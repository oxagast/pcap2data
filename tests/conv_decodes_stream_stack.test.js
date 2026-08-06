// Tests for the per-packet stream decode path in the Conv Decodes subtab.
//
// When the user runs "Follow stream to Conv" with an entire stream loaded
// into the Decodes subtab, the panel should decode each packet separately
// and render the results as a vertical stack (newest first), instead of
// decoding the concatenated stream as a single blob.
//
// We extract the relevant state-management functions from
// src/ui/panels/data-tools-panel.js into a vm context with a minimal DOM
// stub, then assert:
//   1. setDataToolsStreamPackets normalizes entries (drops empties, caps
//      to MAX_DATA_TOOLS_STREAM_PACKETS, assigns orderIndex).
//   2. clearDataToolsStreamPackets resets state to null.
//   3. getDataToolsStreamPackets returns null when no stream is active.
//   4. The new exports exist on module.exports.

const fs = require("fs");
const path = require("path");
const vm = require("vm");

function extractFunctionSource(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    let startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    const lastIndex = sourceText.lastIndexOf(startToken);
    if (lastIndex !== -1 && lastIndex !== startIndex) {
        startIndex = lastIndex;
    }
    const bodyStart = sourceText.indexOf("{", startIndex);
    if (bodyStart === -1) {
        throw new Error(`Could not find body for ${functionName}`);
    }

    let depth = 0;
    let cursor = bodyStart;
    while (cursor < sourceText.length) {
        const char = sourceText[cursor];
        if (char === "{") depth += 1;
        if (char === "}") {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
        cursor += 1;
    }
    throw new Error(`Could not parse function ${functionName}`);
}

function loadStreamStateFunctions() {
    const projectRoot = path.resolve(__dirname, "..");
    const targetFile = path.join(projectRoot, "src/ui/panels/data-tools-panel.js");
    const sourceText = fs.readFileSync(targetFile, "utf8");

    const functionNames = [
        "getDataToolsStreamPackets",
        "setDataToolsStreamPackets",
        "clearDataToolsStreamPackets",
    ];
    const extractedFunctions = functionNames
        .map((name) => extractFunctionSource(sourceText, name))
        .join("\n\n");

    // Build a vm context with the cap constant provided externally (the
    // parser above doesn't try to pull numeric constants out of source —
    // we just inject the same value the panel uses).
    const MAX_DATA_TOOLS_STREAM_PACKETS = 512;
    const context = {
        Uint8Array,
        MAX_DATA_TOOLS_STREAM_PACKETS,
        exports: {},
        module: { exports: {} },
    };
    context.module.exports = context.exports;
    vm.createContext(context);
    vm.runInContext(
        extractedFunctions +
        "\nmodule.exports = { getDataToolsStreamPackets, setDataToolsStreamPackets, clearDataToolsStreamPackets };",
        context,
    );
    return context.module.exports;
}

describe("Conv Decodes per-packet stream state", () => {
    let streamApi;
    beforeAll(() => {
        streamApi = loadStreamStateFunctions();
    });

    beforeEach(() => {
        streamApi.clearDataToolsStreamPackets();
    });

    test("exposes the stream packet accessors", () => {
        expect(typeof streamApi.getDataToolsStreamPackets).toBe("function");
        expect(typeof streamApi.setDataToolsStreamPackets).toBe("function");
        expect(typeof streamApi.clearDataToolsStreamPackets).toBe("function");
    });

    test("returns null when no stream is active", () => {
        expect(streamApi.getDataToolsStreamPackets()).toBeNull();
    });

    test("clears state when called", () => {
        streamApi.setDataToolsStreamPackets([
            { bytes: new Uint8Array([1, 2, 3]) },
        ]);
        expect(Array.isArray(streamApi.getDataToolsStreamPackets())).toBe(true);
        streamApi.clearDataToolsStreamPackets();
        expect(streamApi.getDataToolsStreamPackets()).toBeNull();
    });

    test("setDataToolsStreamPackets normalizes valid entries", () => {
        const entries = [
            { bytes: new Uint8Array([0x47, 0x45, 0x54]) }, // "GET"
            { bytes: new Uint8Array([0x48, 0x54, 0x54, 0x50]) }, // "HTTP"
        ];
        streamApi.setDataToolsStreamPackets(entries);
        const stored = streamApi.getDataToolsStreamPackets();
        expect(stored).not.toBeNull();
        expect(stored).toHaveLength(2);
        expect(stored[0].orderIndex).toBe(0);
        expect(stored[1].orderIndex).toBe(1);
        expect(stored[0].bytes).toBeInstanceOf(Uint8Array);
        expect(stored[0].bytes.length).toBe(3);
        expect(Array.from(stored[1].bytes)).toEqual([0x48, 0x54, 0x54, 0x50]);
    });

    test("filters out entries with empty or missing bytes", () => {
        streamApi.setDataToolsStreamPackets([
            { bytes: new Uint8Array([1, 2]) },
            { bytes: new Uint8Array(0) }, // empty bytes
            { bytes: "not a Uint8Array" }, // wrong type
            null, // null entry
            { /* no bytes field */ },
            { bytes: new Uint8Array([3]) },
        ]);
        const stored = streamApi.getDataToolsStreamPackets();
        expect(stored).not.toBeNull();
        expect(stored).toHaveLength(2);
        expect(Array.from(stored[0].bytes)).toEqual([1, 2]);
        expect(Array.from(stored[1].bytes)).toEqual([3]);
    });

    test("clears state when all entries are invalid", () => {
        streamApi.setDataToolsStreamPackets([
            null,
            { bytes: new Uint8Array(0) },
            { bytes: "wrong" },
        ]);
        expect(streamApi.getDataToolsStreamPackets()).toBeNull();
    });

    test("accepts and stores per-packet info metadata", () => {
        streamApi.setDataToolsStreamPackets([
            {
                bytes: new Uint8Array([1]),
                info: { packetIndex: 42, sourceKey: "tcp:80:1" },
            },
        ]);
        const stored = streamApi.getDataToolsStreamPackets();
        expect(stored).toHaveLength(1);
        expect(stored[0].info.packetIndex).toBe(42);
        expect(stored[0].info.sourceKey).toBe("tcp:80:1");
    });

    test("falls back to empty info object when info is missing or malformed", () => {
        streamApi.setDataToolsStreamPackets([
            { bytes: new Uint8Array([1]), info: null },
            { bytes: new Uint8Array([2]) },
            { bytes: new Uint8Array([3]), info: "not an object" },
        ]);
        const stored = streamApi.getDataToolsStreamPackets();
        expect(stored).toHaveLength(3);
        stored.forEach((entry) => {
            expect(entry.info).toBeDefined();
            expect(typeof entry.info).toBe("object");
        });
    });

    test("caps stored entries to MAX_DATA_TOOLS_STREAM_PACKETS", () => {
        const entries = [];
        for (let i = 0; i < 600; i += 1) {
            entries.push({ bytes: new Uint8Array([i & 0xff]) });
        }
        streamApi.setDataToolsStreamPackets(entries);
        const stored = streamApi.getDataToolsStreamPackets();
        expect(stored).not.toBeNull();
        expect(stored.length).toBe(512);
        // orderIndex reflects the post-cap position so the renderer can
        // label "Packet N of 512" instead of the original count.
        expect(stored[0].orderIndex).toBe(0);
        expect(stored[511].orderIndex).toBe(511);
    });

    test("accepts null and empty array to clear the state", () => {
        streamApi.setDataToolsStreamPackets([
            { bytes: new Uint8Array([1]) },
        ]);
        expect(Array.isArray(streamApi.getDataToolsStreamPackets())).toBe(true);
        streamApi.setDataToolsStreamPackets(null);
        expect(streamApi.getDataToolsStreamPackets()).toBeNull();
        streamApi.setDataToolsStreamPackets([
            { bytes: new Uint8Array([1]) },
        ]);
        streamApi.setDataToolsStreamPackets([]);
        expect(streamApi.getDataToolsStreamPackets()).toBeNull();
    });

    test("preserves original byte order (caller controls ordering)", () => {
        // The newest-first rendering happens inside the renderer; the
        // accessor layer must preserve the order it was given so the
        // renderer's reverse iteration lines up with the capture order.
        const entries = [
            { bytes: new Uint8Array([1]) },
            { bytes: new Uint8Array([2]) },
            { bytes: new Uint8Array([3]) },
        ];
        streamApi.setDataToolsStreamPackets(entries);
        const stored = streamApi.getDataToolsStreamPackets();
        expect(Array.from(stored[0].bytes)).toEqual([1]);
        expect(Array.from(stored[1].bytes)).toEqual([2]);
        expect(Array.from(stored[2].bytes)).toEqual([3]);
    });
});

describe("Conv Decodes panel exports the per-packet decode API", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const panelFile = path.join(projectRoot, "src/ui/panels/data-tools-panel.js");

    test("module.exports includes the stream packet accessors", () => {
        const sourceText = fs.readFileSync(panelFile, "utf8");
        // The module.exports block lists the public surface. We don't
        // require() it (that pulls in the Electron dependencies); we
        // instead inspect the source for the names so any future removal
        // shows up as a failing test.
        const requiredNames = [
            "getDataToolsStreamPackets",
            "setDataToolsStreamPackets",
            "clearDataToolsStreamPackets",
            "runProtoDecoderForStreamPackets",
            "decodeWithSelectedProtocol",
        ];
        requiredNames.forEach((name) => {
            expect(sourceText).toContain(name);
        });
        // And that they appear in the module.exports object literal.
        const exportsMatch = sourceText.match(/module\.exports\s*=\s*\{([\s\S]*?)\};?/);
        expect(exportsMatch).not.toBeNull();
        const exportsBody = exportsMatch[1];
        requiredNames.forEach((name) => {
            expect(exportsBody).toContain(name);
        });
    });

    test("clearProtoDecoderOutput does NOT clear stream state", () => {
        // Decoupling: clearProtoDecoderOutput is also called when the
        // payload is too large AND we're not on the Decodes subtab. In
        // that path we want the visual output cleared but the per-packet
        // stream state to survive so the stacked render shows again when
        // the user switches back to Decodes. Full-reset paths clear the
        // stream state explicitly via clearDataToolsStreamPackets().
        const sourceText = fs.readFileSync(panelFile, "utf8");
        // Locate the body of clearProtoDecoderOutput and assert it does
        // not assign to dataToolsStreamPackets and does not invoke the
        // explicit clearer. We strip line comments first so references
        // inside comments don't trigger the assertion.
        const fnMatch = sourceText.match(
            /function clearProtoDecoderOutput\s*\([^)]*\)\s*\{([\s\S]*?)\n\}/,
        );
        expect(fnMatch).not.toBeNull();
        const strippedBody = fnMatch[1].replace(/\/\/[^\n]*/g, "");
        expect(strippedBody).not.toMatch(/dataToolsStreamPackets\s*=\s*null/);
        expect(strippedBody).not.toMatch(/clearDataToolsStreamPackets\s*\(\s*\)/);
    });
});

describe("Conv file-load entry points clear stream state", () => {
    const projectRoot = path.resolve(__dirname, "..");
    const mainFile = path.join(projectRoot, "src/ui/main-frontend.js");

    // Each of these functions loads fresh, non-stream bytes into the Conv
    // panel. If they did NOT clear dataToolsStreamPackets, a previously
    // loaded stream would leak into a subsequent single-blob decode (e.g.
    // a JPEG) and runProtoDecoder would route those bytes through the
    // per-packet stream path instead of the single-blob decoder.
    const entryPoints = [
        "loadExtractionResultIntoConv",
        "loadExtractionResultIntoHashesSubtab",
        "loadCarvedFileCandidateIntoConvTab",
        "loadRawPayloadIntoDataToolsFromContextMenu",
        "loadRawPacketIntoDataToolsFromContextMenu",
        "loadActiveConvInputDecompressedFromContextMenu",
        "loadHttpBodyIntoConvTabFromContextMenuImpl",
        "loadManualFileIntoConvTabFromContextMenu",
        "resetDataToolsOutputs",
    ];

    test.each(entryPoints)(
        "%s clears the per-packet stream state",
        (functionName) => {
            const sourceText = fs.readFileSync(mainFile, "utf8");
            // Find the function/method body. We accept both `function NAME(` and
            // `NAME: function` shapes so future refactors don't surprise us.
            const functionRegex = new RegExp(
                `(?:function\\s+${functionName}|${functionName}\\s*:\\s*function)\\s*\\(`,
            );
            const match = sourceText.match(functionRegex);
            expect(match).not.toBeNull();
            const startIndex = match.index;
            // Walk forward tracking brace depth to find the end of the body.
            let depth = 0;
            let cursor = startIndex;
            let sawOpenBrace = false;
            while (cursor < sourceText.length) {
                const char = sourceText[cursor];
                if (char === "{") {
                    depth += 1;
                    sawOpenBrace = true;
                }
                if (char === "}") {
                    depth -= 1;
                    if (sawOpenBrace && depth === 0) {
                        break;
                    }
                }
                cursor += 1;
            }
            const body = sourceText.slice(startIndex, cursor + 1);
            expect(body).toMatch(/clearDataToolsStreamPackets\s*\(\s*\)/);
        },
    );
});
