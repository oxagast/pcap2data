// Tests for the new "Load carved file into Decoders" Stats context-menu
// entry, including the file-extension-to-decoder-hint helper and the menu
// markup that the renderer relies on.

const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");

describe("Conv decoders: file-extension hint helper", () => {
    let mimeModule;
    beforeAll(() => {
        mimeModule = require(
            path.join(
                PROJECT_ROOT,
                "src/ui/decoders/conv/mime-maps.js",
            ),
        );
    });

    test("maps common image extensions to the matching decoder key", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("photo.jpg")).toBe("jpeg");
        expect(mimeModule.getProtoDecoderHintForFileName("photo.jpeg")).toBe("jpeg");
        expect(mimeModule.getProtoDecoderHintForFileName("icon.png")).toBe("png");
        expect(mimeModule.getProtoDecoderHintForFileName("anim.gif")).toBe("gif");
        expect(mimeModule.getProtoDecoderHintForFileName("pic.webp")).toBe("webp");
    });

    test("maps markup and structured-data extensions to their decoders", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("page.html")).toBe("html");
        expect(mimeModule.getProtoDecoderHintForFileName("page.htm")).toBe("html");
        expect(mimeModule.getProtoDecoderHintForFileName("data.json")).toBe("json");
        expect(mimeModule.getProtoDecoderHintForFileName("data.xml")).toBe("xml");
        expect(mimeModule.getProtoDecoderHintForFileName("config.yaml")).toBe("yaml");
        expect(mimeModule.getProtoDecoderHintForFileName("config.yml")).toBe("yaml");
    });

    test("maps plain-text extensions to the plaintext decoder", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("notes.txt")).toBe("plaintext");
        expect(mimeModule.getProtoDecoderHintForFileName("trace.log")).toBe("plaintext");
        expect(mimeModule.getProtoDecoderHintForFileName("data.csv")).toBe("plaintext");
        expect(mimeModule.getProtoDecoderHintForFileName("app.env")).toBe("plaintext");
    });

    test("uppercase and mixed-case extensions are normalized", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("PIC.JPG")).toBe("jpeg");
        expect(mimeModule.getProtoDecoderHintForFileName("Pic.JpG")).toBe("jpeg");
        expect(mimeModule.getProtoDecoderHintForFileName("DATA.YAML")).toBe("yaml");
    });

    test("strips directory paths before extracting the extension", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("/tmp/uploads/photo.png")).toBe("png");
        expect(mimeModule.getProtoDecoderHintForFileName("C:\\share\\data.json")).toBe("json");
    });

    test("returns an empty string for unknown / missing extensions", () => {
        expect(mimeModule.getProtoDecoderHintForFileName("payload")).toBe("");
        expect(mimeModule.getProtoDecoderHintForFileName("payload.bin")).toBe("");
        expect(mimeModule.getProtoDecoderHintForFileName("archive.exe")).toBe("");
        expect(mimeModule.getProtoDecoderHintForFileName("")).toBe("");
        expect(mimeModule.getProtoDecoderHintForFileName(null)).toBe("");
    });

    test("ignores dotfiles and trailing-dot files", () => {
        expect(mimeModule.getProtoDecoderHintForFileName(".bashrc")).toBe("");
        expect(mimeModule.getProtoDecoderHintForFileName("file.")).toBe("");
    });

    test("only returns proto keys supported by the decoder dropdown", () => {
        // Sanity check: every entry in the extension map must be in the
        // supported-protos set. This catches typos where someone adds an
        // extension that points at a decoder key the dropdown does not
        // expose.
        const supported = mimeModule.SUPPORTED_DECODER_PROTOS;
        for (const [ext, proto] of Object.entries(mimeModule.FILE_EXTENSION_TO_PROTO)) {
            expect(supported.has(proto)).toBe(true);
            expect(typeof ext).toBe("string");
        }
    });
});

describe("Conv decoders: barrel re-exports include the new helpers", () => {
    let barrel;
    beforeAll(() => {
        barrel = require(
            path.join(PROJECT_ROOT, "src/ui/decoders/conv/index.js"),
        );
    });

    test("exposes getProtoDecoderHintForFileName", () => {
        expect(typeof barrel.getProtoDecoderHintForFileName).toBe("function");
    });

    test("exposes FILE_EXTENSION_TO_PROTO and SUPPORTED_DECODER_PROTOS", () => {
        expect(barrel.FILE_EXTENSION_TO_PROTO).toBeDefined();
        expect(barrel.SUPPORTED_DECODER_PROTOS).toBeDefined();
    });

    test("exposes extractFileExtension", () => {
        expect(typeof barrel.extractFileExtension).toBe("function");
        expect(barrel.extractFileExtension("data.json")).toBe("json");
        expect(barrel.extractFileExtension("archive.bin")).toBe("bin");
        expect(barrel.extractFileExtension("noext")).toBe("");
    });
});

describe("Convert context menu markup", () => {
    let markup;
    beforeAll(() => {
        markup = fs.readFileSync(
            path.join(
                PROJECT_ROOT,
                "src/ui/fragments/convert-context-menu.js",
            ),
            "utf8",
        );
    });

    test("declares the new carved-file decoders button", () => {
        expect(markup).toContain('id="ctx-load-carvable-decoders"');
        expect(markup).toContain("Load carved file into Decoders");
    });

    test("keeps the existing carved-file Extraction and VirusTotal buttons", () => {
        expect(markup).toContain('id="ctx-load-carvable-extraction"');
        expect(markup).toContain('id="ctx-load-carvable-virustotal"');
    });

    test("places the new button between Extraction and VirusTotal", () => {
        const extractionIdx = markup.indexOf('id="ctx-load-carvable-extraction"');
        const decodersIdx = markup.indexOf('id="ctx-load-carvable-decoders"');
        const virusTotalIdx = markup.indexOf('id="ctx-load-carvable-virustotal"');
        expect(extractionIdx).toBeGreaterThan(-1);
        expect(decodersIdx).toBeGreaterThan(extractionIdx);
        expect(virusTotalIdx).toBeGreaterThan(decodersIdx);
    });
});

describe("main-frontend.js: carved-file decoders wiring", () => {
    let mainFrontendSource;
    beforeAll(() => {
        mainFrontendSource = fs.readFileSync(
            path.join(PROJECT_ROOT, "src/ui/main-frontend.js"),
            "utf8",
        );
    });

    test("caches the new button in convertContextButtons", () => {
        // The lookup is created via getCachedElement, mirroring the
        // pattern of the existing extraction/virustotal buttons.
        expect(mainFrontendSource).toMatch(
            /loadCarvableDecoders:\s*getCachedElement\("ctx-load-carvable-decoders"\)/,
        );
    });

    test("toggles the new button's visibility alongside the other carvable entries", () => {
        // We do not pin a specific code shape; we just require that
        // hasStatsCarvableAction drives all three carvable buttons.
        const loadCarvableDecodersVisibility = mainFrontendSource.match(
            /convertContextButtons\.loadCarvableDecoders\.style\.display\s*=\s*hasStatsCarvableAction\s*\?\s*"block"\s*:\s*"none"/,
        );
        expect(loadCarvableDecodersVisibility).not.toBeNull();
    });

    test("wires a click handler that forwards the file hint and forces auto-select", () => {
        // Verify the handler exists, keeps the decoder on auto, and
        // forwards the file name to the decoder hints so the auto-detect
        // path can pick the right protocol from the byte content.
        const handlerBlock = mainFrontendSource.match(
            /convertContextButtons\.loadCarvableDecoders\.addEventListener\([\s\S]*?\n\}\);/,
        );
        expect(handlerBlock).not.toBeNull();
        const source = handlerBlock[0];
        expect(source).toContain("setDataToolsDecoderHints");
        expect(source).toContain("fileNameHint");
        expect(source).toContain('"auto"');
        expect(source).toContain("CONV_DECODES_SUBTAB");
        expect(source).toContain("data-tools-proto-select");
    });

    test("imports the new mime-maps helper", () => {
        expect(mainFrontendSource).toMatch(
            /require\(['"]\.\/decoders\/conv\/mime-maps['"]\)/,
        );
        expect(mainFrontendSource).toContain("getProtoDecoderHintForFileName");
        expect(mainFrontendSource).toContain("SUPPORTED_DECODER_PROTOS");
    });
});

describe("Docs: 'Load carved file into Decoders' is documented", () => {
    test("context-menu.md mentions the new entry", () => {
        const doc = fs.readFileSync(
            path.join(PROJECT_ROOT, "docs/PacketSnitch-Website/docu/context-menu.md"),
            "utf8",
        );
        expect(doc).toContain("Load carved file into Decoders");
    });

    test("RELEASE_NOTES.md mentions the new entry", () => {
        const notes = fs.readFileSync(
            path.join(PROJECT_ROOT, "RELEASE_NOTES.md"),
            "utf8",
        );
        expect(notes).toContain("Load carved file into Decoders");
    });
});

describe("Conv decoders: autoDetectProtoFromBytes filename precedence", () => {
    let autoDetect;
    beforeAll(() => {
        autoDetect = require(
            path.join(PROJECT_ROOT, "src/ui/decoders/conv/auto-detect.js"),
        );
    });

    test("filename hint wins over byte magic for a text file", () => {
        // Bytes that would normally be detected as a PNG by magic-number
        // heuristics, but the caller supplied a .txt filename hint.
        const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
        const result = autoDetect.autoDetectProtoFromBytes(bytes, {
            protocolHint: null,
            portHint: null,
            fileNameHint: "readme.txt",
        });
        expect(result).toBe("plaintext");
    });

    test("filename hint wins over transport protocol/port hints", () => {
        // Even if a packet-derived HTTP hint is supplied, an explicit
        // filename hint for a structured file should take precedence.
        const bytes = new Uint8Array([0x48, 0x54, 0x54, 0x50]); // "HTTP"
        const result = autoDetect.autoDetectProtoFromBytes(bytes, {
            protocolHint: "http",
            portHint: "http",
            fileNameHint: "data.json",
        });
        expect(result).toBe("json");
    });

    test("byte magic is still used when no filename hint is provided", () => {
        const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
        const result = autoDetect.autoDetectProtoFromBytes(bytes, {});
        expect(result).toBe("png");
    });

    test("unknown filename extension falls through to byte heuristics", () => {
        const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
        const result = autoDetect.autoDetectProtoFromBytes(bytes, {
            fileNameHint: "payload.bin",
        });
        expect(result).toBe("png");
    });
});

describe("Conv decoders: isFile load-mode toggle", () => {
    // Files are complete data chunks — never stream packets — so their
    // decode must not take hints from the transport stream they were
    // pulled from. The isFile toggle gates this: file loads use only the
    // filename extension hint + byte heuristics; every non-file load
    // resets it so packet-context stream tracking keeps working.

    let panelSource;
    beforeAll(() => {
        panelSource = fs.readFileSync(
            path.join(PROJECT_ROOT, "src/ui/panels/data-tools-panel.js"),
            "utf8",
        );
    });

    test("panel hint state exposes isFile (not the older fallback flag)", () => {
        expect(panelSource).toMatch(/let dataToolsDecoderHints = \{[^}]*isFile: false,/);
        expect(panelSource).not.toContain("noPacketContextFallback");
    });

    test("setDataToolsDecoderHints stores the isFile flag", () => {
        const vm = require("vm");
        const source = panelSource;
        const fnStart = source.indexOf("function setDataToolsDecoderHints");
        const parenOpen = source.indexOf("(", fnStart);
        const parenClose = source.indexOf(")", parenOpen);
        const bodyStart = source.indexOf("{", parenClose);
        let depth = 0;
        let cursor = bodyStart;
        while (cursor < source.length) {
            if (source[cursor] === "{") depth += 1;
            if (source[cursor] === "}") {
                depth -= 1;
                if (depth === 0) break;
            }
            cursor += 1;
        }
        const fnSource = source.slice(fnStart, cursor + 1);
        const context = { dataToolsDecoderHints: null };
        vm.createContext(context);
        vm.runInContext(fnSource, context);
        vm.runInContext(
            "setDataToolsDecoderHints({ fileNameHint: ' report.csv ', isFile: true, protocolHint: 'http' })",
            context,
        );
        expect(context.dataToolsDecoderHints).toEqual({
            protocolHint: "http",
            portHint: null,
            fileNameHint: "report.csv",
            isFile: true,
        });
        vm.runInContext("setDataToolsDecoderHints({ isFile: false })", context);
        expect(context.dataToolsDecoderHints).toEqual({
            protocolHint: null,
            portHint: null,
            fileNameHint: null,
            isFile: false,
        });
    });

    test("single-blob and stream decode paths honor isFile over packet context", () => {
        // In runProtoDecoder and runProtoDecoderForStreamPackets, when
        // dataToolsDecoderHints.isFile is true the context packet must be
        // ignored and the explicit hints used verbatim.
        const runProtoBlock = panelSource.slice(
            panelSource.indexOf("function runProtoDecoder(bytes)"),
            panelSource.indexOf("function runProtoDecoder(bytes)") + 4000,
        );
        expect(runProtoBlock).toContain("dataToolsDecoderHints.isFile");
        const streamBlock = panelSource.slice(
            panelSource.indexOf("function runProtoDecoderForStreamPackets"),
            panelSource.indexOf("function runProtoDecoderForStreamPackets") + 4000,
        );
        expect(streamBlock).toContain("dataToolsDecoderHints.isFile");
        // clearDataToolsStreamPackets must NOT wipe decoder hints: file
        // loaders call it before setting their hints.
        const clearBlock = panelSource.slice(
            panelSource.indexOf("function clearDataToolsStreamPackets"),
            panelSource.indexOf("function clearDataToolsStreamPackets") + 600,
        );
        expect(clearBlock).not.toContain("dataToolsDecoderHints");
    });

    test("file loaders set isFile: true; stream/non-file loaders reset it", () => {
        const mainSource = fs.readFileSync(
            path.join(PROJECT_ROOT, "src/ui/main-frontend.js"),
            "utf8",
        );
        // File loaders.
        const fileLoaderBlocks = [
            "function loadCarvedFileCandidateIntoConvTab",
            "function loadHttpBodyIntoConvTabFromContextMenuImpl",
            "function loadExtractionResultIntoConv",
            "function loadExtractionResultIntoHashesSubtab",
        ];
        for (const fnName of fileLoaderBlocks) {
            const start = mainSource.indexOf(fnName);
            expect(start).toBeGreaterThan(-1);
            const block = mainSource.slice(start, start + 3000);
            expect(block).toContain("isFile: true");
        }
        // Manual import sets hints inside its try block.
        const manualStart = mainSource.indexOf("function loadManualFileIntoConvTabFromContextMenu");
        const manualBlock = mainSource.slice(manualStart, manualStart + 8000);
        expect(manualBlock).toContain("isFile: true");
        // Stream loader resets file mode.
        const streamHintIdx = mainSource.indexOf("setDataToolsDecoderHints({ ...streamHints, isFile: false })");
        expect(streamHintIdx).toBeGreaterThan(-1);
    });

    test("Stats decode handlers flag the load as a file", () => {
        const mainSource = fs.readFileSync(
            path.join(PROJECT_ROOT, "src/ui/main-frontend.js"),
            "utf8",
        );
        // Both the decode-stats-object handler and the load-carvable-decoders
        // handler set isFile: true with the candidate filename.
        const decodeStatsIdx = mainSource.indexOf("convertContextButtons.decodeStatsObject.addEventListener");
        const decodeStatsBlock = mainSource.slice(decodeStatsIdx, decodeStatsIdx + 6000);
        expect(decodeStatsBlock).toContain("fileNameHint: candidate.fileName");
        expect(decodeStatsBlock).toContain("isFile: true");
        const loadCarvableIdx = mainSource.indexOf("convertContextButtons.loadCarvableDecoders.addEventListener");
        const loadCarvableBlock = mainSource.slice(loadCarvableIdx, loadCarvableIdx + 6000);
        expect(loadCarvableBlock).toContain("fileNameHint: candidate.fileName");
        expect(loadCarvableBlock).toContain("isFile: true");
    });
});
