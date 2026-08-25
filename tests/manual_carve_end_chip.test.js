// Tests for the Manual Carve "End:" cursor chip in the Conv panel.
//
// Background: the data-tools output panes render only the first
// ``DATA_TOOLS_OUTPUT_PAGE_BYTES`` bytes of the conversion stream. The
// "End:" chip is documented as "Bytes from selection end to stream end —
// click to set Manual Carve length". Before the fix, the chip's value was
// computed from the *rendered* byte count
// (``dataToolsSelectionState.bytes.length``) rather than the *full* stream
// length (``dataToolsLastConversionBytes.length``). This meant clicking the
// chip when the stream was larger than the visible page would set the
// Manual Carve Length to the displayed remainder, not the true stream-end
// remainder — so a carve that should have run to the end of the stream was
// silently truncated.
//
// These tests load the relevant functions from ``src/ui/main-frontend.js``
// into a vm context with a minimal DOM stub, simulate the paginated
// output scenario, and assert the chip text and underlying ``rawValue``.
//
// We also assert the same fix in the bundled test mirror
// (``src/ui/main-frontend-test.cjs``) to keep the production and test
// files in lockstep — see tests/extraction_panel.test.js for the same
// "manual import fix" mirror pattern.

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const TARGET_FILE = path.join(PROJECT_ROOT, "src/ui/main-frontend.js");
const MIRROR_FILE = path.join(PROJECT_ROOT, "src/ui/main-frontend-test.cjs");

// Pulls the source of a single function out of a file. The same logic is
// used in tests/conv_decodes_stream_stack.test.js and
// tests/extraction_panel.test.js; this is a focused, regex-aware version
// that handles single/double quotes, template literals, line/block
// comments, and regex literals.
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
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inTemplate = false;
    let inLineComment = false;
    let inBlockComment = false;
    let inRegex = false;
    let inRegexCharClass = false;
    let escaped = false;

    function isRegexStart(idx) {
        let j = idx - 1;
        while (j >= 0 && /\s/.test(sourceText[j])) j -= 1;
        if (j < 0) return true;
        const prev = sourceText[j];
        if (/[=(,:\[{};?!|&]/.test(prev)) return true;
        const back = sourceText.slice(Math.max(0, j - 30), j + 1);
        const match = back.match(
            /\b(return|break|continue|with|if|else|case|while|do|for|switch|throw|catch|await|yield|new|typeof|instanceof|delete|void)$/,
        );
        if (match) return true;
        return false;
    }

    while (cursor < sourceText.length) {
        const char = sourceText[cursor];
        const next = sourceText[cursor + 1];
        if (inLineComment) {
            if (char === "\n") inLineComment = false;
            cursor += 1;
            continue;
        }
        if (inBlockComment) {
            if (char === "*" && next === "/") {
                inBlockComment = false;
                cursor += 2;
                continue;
            }
            cursor += 1;
            continue;
        }
        if (inRegex) {
            if (escaped) {
                escaped = false;
                cursor += 1;
                continue;
            }
            if (char === "\\") {
                escaped = true;
                cursor += 1;
                continue;
            }
            if (char === "[" && !inRegexCharClass) inRegexCharClass = true;
            if (char === "]" && inRegexCharClass) inRegexCharClass = false;
            if (char === "/" && !inRegexCharClass) {
                inRegex = false;
                cursor += 1;
                while (cursor < sourceText.length && /[dgimsuvy]/i.test(sourceText[cursor])) cursor += 1;
                continue;
            }
            cursor += 1;
            continue;
        }
        if (inSingleQuote || inDoubleQuote || inTemplate) {
            if (escaped) {
                escaped = false;
                cursor += 1;
                continue;
            }
            if (char === "\\") {
                escaped = true;
                cursor += 1;
                continue;
            }
            if (inSingleQuote && char === "'") inSingleQuote = false;
            else if (inDoubleQuote && char === '"') inDoubleQuote = false;
            else if (inTemplate && char === "`") inTemplate = false;
            cursor += 1;
            continue;
        }
        if (char === "/" && next === "/") {
            inLineComment = true;
            cursor += 2;
            continue;
        }
        if (char === "/" && next === "*") {
            inBlockComment = true;
            cursor += 2;
            continue;
        }
        if (char === "'") { inSingleQuote = true; cursor += 1; continue; }
        if (char === '"') { inDoubleQuote = true; cursor += 1; continue; }
        if (char === "`") { inTemplate = true; cursor += 1; continue; }
        if (char === "/") {
            if (isRegexStart(cursor)) {
                inRegex = true;
                cursor += 1;
                continue;
            }
        }
        if (char === "{") depth += 1;
        if (char === "}") {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
        cursor += 1;
    }
    throw new Error(`Could not parse function ${functionName} (reached EOF at depth ${depth})`);
}

// Builds a minimal DOM stub with just enough surface for
// ``updateDataToolsCursorReadout`` and its ``setDataToolsCursorValue`` helper.
function createChipElement() {
    const valueEl = {
        dataset: {},
        _chipText: "",
        _text: "",
        querySelector: function (sel) {
            if (sel === ".data-tools-cursor-chip-value") {
                // Return the same chip-value object every time so the
                // production code's ``chipValue.textContent = displayValue``
                // assignment is observable from the test.
                if (!this._chipValue) {
                    this._chipValue = {
                        set textContent(v) { valueEl._chipText = v; },
                        get textContent() { return valueEl._chipText; },
                    };
                }
                return this._chipValue;
            }
            return null;
        },
        set textContent(v) { this._text = v; },
        get textContent() { return this._text; },
    };
    return valueEl;
}

function createCursorReadoutContext() {
    // Capture per-chip state so tests can assert both display and raw value.
    const chips = {};
    function makeChip(id) {
        const chip = createChipElement();
        chips[id] = chip;
        return chip;
    }

    const elements = {
        "data-tools-output-cursor-offset": makeChip("data-tools-output-cursor-offset"),
        "data-tools-output-cursor-line": makeChip("data-tools-output-cursor-line"),
        "data-tools-output-cursor-column": makeChip("data-tools-output-cursor-column"),
        "data-tools-output-cursor-position": makeChip("data-tools-output-cursor-position"),
        "data-tools-output-cursor-sel-len": makeChip("data-tools-output-cursor-sel-len"),
        "data-tools-output-cursor-end-remaining": makeChip("data-tools-output-cursor-end-remaining"),
        "data-tools-input": createChipElement(),
    };

    const document = {
        getElementById: (id) => elements[id] || null,
    };

    return { elements, document, chips };
}

function loadReadoutFunctions(filePath) {
    const sourceText = fs.readFileSync(filePath, "utf8");
    const functionNames = [
        "setDataToolsCursorValue",
        "getDataToolsByteRangeForSelection",
        "updateDataToolsCursorReadout",
    ];
    const extractedSource = functionNames
        .map((name) => extractFunctionSource(sourceText, name))
        .join("\n\n");

    const ctx = createCursorReadoutContext();
    const sandbox = {
        Uint8Array,
        document: ctx.document,
        dataToolsSelectionState: {
            bytes: new Uint8Array(),
            maps: {},
        },
        dataToolsLastConversionBytes: new Uint8Array(),
    };
    vm.createContext(sandbox);
    vm.runInContext(extractedSource, sandbox);
    return { ...ctx, sandbox };
}

// Builds a selection map for an ASCII output where each character maps 1:1
// to a byte index. Mirrors the real `buildInputSelectionMap` shape closely
// enough for the cursor-readout logic to compute the same byte ranges.
function buildAsciiSelectionMap(text, byteCount) {
    const safeText = String(text || "");
    const charToByte = new Array(safeText.length);
    for (let i = 0; i < safeText.length; i++) charToByte[i] = i;
    const byteRanges = Array.from({ length: byteCount }, (_, idx) => ({
        start: idx,
        end: idx + 1,
    }));
    return { text: safeText, charToByte, byteRanges };
}

describe("Manual Carve 'End:' chip in the Conv panel", () => {
    let harness;

    beforeEach(() => {
        harness = loadReadoutFunctions(TARGET_FILE);
    });

    test("'End:' chip shows full stream remainder when only a page is rendered", () => {
        // Simulate a 10,000-byte stream with the first 2,048 bytes rendered
        // into the output panes — the paginated-display case from the bug.
        const fullStream = new Uint8Array(10000);
        const renderedBytes = fullStream.slice(0, 2048);
        harness.sandbox.dataToolsLastConversionBytes = fullStream;
        harness.sandbox.dataToolsSelectionState.bytes = renderedBytes;

        // Build a selection map that aligns the textarea contents to the
        // rendered byte slice; cursor is parked at byte index 1024 (well
        // inside the rendered page, not at the trailing boundary where the
        // cursor clamps to the byte-after-end).
        const asciiText = renderedBytes.toString(); // printable placeholder
        const map = buildAsciiSelectionMap(asciiText, renderedBytes.length);
        harness.sandbox.dataToolsSelectionState.maps = {
            "data-tools-input": map,
        };
        const cursorPos = 1024;
        const inputEl = harness.elements["data-tools-input"];
        inputEl.value = asciiText;
        inputEl.selectionStart = cursorPos;
        inputEl.selectionEnd = cursorPos;

        harness.sandbox.updateDataToolsCursorReadout("data-tools-input");

        // The chip must show 10000 - 1024 = 8976, not 2048 - 1024 = 1024.
        const endChip = harness.chips["data-tools-output-cursor-end-remaining"];
        expect(endChip.dataset.rawValue).toBe(8976);
        // The DOM stub stores the chip-value text under _chipText (the
        // inner span's textContent is the displayValue the user sees).
        expect(endChip._chipText).toBe("8976");
    });

    test("'End:' chip shows the full stream length when no selection is active", () => {
        // Even with no map yet (e.g. the early-return branch), the chip must
        // show the *full* stream length, not 0.
        const fullStream = new Uint8Array(5000);
        harness.sandbox.dataToolsLastConversionBytes = fullStream;
        harness.sandbox.dataToolsSelectionState.bytes = fullStream.slice(0, 1024);
        harness.sandbox.dataToolsSelectionState.maps = {};

        harness.sandbox.updateDataToolsCursorReadout("data-tools-input");

        const endChip = harness.chips["data-tools-output-cursor-end-remaining"];
        expect(endChip.dataset.rawValue).toBe(5000);
        expect(endChip._chipText).toBe("5000");
    });

    test("'End:' chip falls back to 0 when there is no conversion loaded", () => {
        harness.sandbox.dataToolsLastConversionBytes = new Uint8Array();
        harness.sandbox.dataToolsSelectionState.bytes = new Uint8Array();
        harness.sandbox.dataToolsSelectionState.maps = {};

        harness.sandbox.updateDataToolsCursorReadout("data-tools-input");

        const endChip = harness.chips["data-tools-output-cursor-end-remaining"];
        expect(endChip.dataset.rawValue).toBe(0);
        expect(endChip._chipText).toBe("0");
    });

    test("clicking the 'End:' chip sets the Manual Carve length to the full-stream remainder", () => {
        // Wire the chip's rawValue into the carve Length input and verify the
        // math a user would experience end-to-end. We don't run the full
        // performDataToolsManualCarve (which requires the entire data tools
        // input pipeline); we just exercise the click handler shape that
        // ``handleDataToolsCursorCarveClick`` already implements.
        const fullStream = new Uint8Array(10000);
        const renderedBytes = fullStream.slice(0, 2048);
        harness.sandbox.dataToolsLastConversionBytes = fullStream;
        harness.sandbox.dataToolsSelectionState.bytes = renderedBytes;

        const asciiText = renderedBytes.toString();
        const map = buildAsciiSelectionMap(asciiText, renderedBytes.length);
        harness.sandbox.dataToolsSelectionState.maps = {
            "data-tools-input": map,
        };
        const inputEl = harness.elements["data-tools-input"];
        inputEl.value = asciiText;
        // Selected range: bytes 0..1024. With the 1:1 ascii map,
        // getDataToolsByteRangeForSelection returns { start: 0, end: 1024 }
        // so the End chip shows 10000 - 1024 = 8976.
        inputEl.selectionStart = 0;
        inputEl.selectionEnd = 1024;

        harness.sandbox.updateDataToolsCursorReadout("data-tools-input");

        // Simulate the click handler: copy the chip's rawValue into the
        // Length input, then compute the carve end as the codebase does
        // for a carve whose Position field is set to the selection's start
        // byte.
        const endChip = harness.chips["data-tools-output-cursor-end-remaining"];
        const carveLength = Number(endChip.dataset.rawValue);
        const startByte = 0; // the user's selection-start byte
        const endByte = Math.min(startByte + carveLength, fullStream.length);

        // The carve must run from byte 0 to the end of the full stream.
        // Before the fix, carveLength was capped to the displayed page
        // (2048) and would have been 1024 instead of 8976, truncating
        // the carve.
        expect(carveLength).toBe(8976);
        expect(endByte).toBe(8976);
        // And the carve would have missed 7952 bytes that are in the
        // stream but not on the visible page.
        expect(fullStream.length - endByte).toBe(1024);
    });
});

describe("main-frontend-test.cjs mirrors the End chip fix", () => {
    test("the mirror file uses the full-stream length for the End chip", () => {
        // Find the body of updateDataToolsCursorReadout in the mirror file
        // and assert it consults dataToolsLastConversionBytes (the full
        // stream) rather than dataToolsSelectionState.bytes (the rendered
        // page) for the streamLen constant.
        const source = fs.readFileSync(MIRROR_FILE, "utf8");
        expect(source).toMatch(/updateDataToolsCursorReadout/);

        const token = "function updateDataToolsCursorReadout";
        const startIndex = source.lastIndexOf(token);
        expect(startIndex).toBeGreaterThanOrEqual(0);
        const bodyStart = source.indexOf("{", startIndex);
        expect(bodyStart).toBeGreaterThanOrEqual(0);

        // Walk braces to find the matching close.
        let depth = 0;
        let cursor = bodyStart;
        while (cursor < source.length) {
            const ch = source[cursor];
            if (ch === "{") depth += 1;
            if (ch === "}") {
                depth -= 1;
                if (depth === 0) break;
            }
            cursor += 1;
        }
        const body = source.slice(startIndex, cursor + 1);

        // The fix: streamLen must be derived from the full conversion
        // buffer, not the (paginated) selection state buffer.
        expect(body).toMatch(/dataToolsLastConversionBytes/);
        // And the old (buggy) derivation must be gone.
        expect(body).not.toMatch(/const streamLen = dataToolsSelectionState\.bytes\?\.length/);
    });
});
