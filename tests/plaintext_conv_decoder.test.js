// Tests for the plaintext Conv decoder in data-tools-panel.js.
// Mirrors the vm-extraction pattern used by conv_decodes_hide_noop.test.js.

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

function extractConstantSource(sourceText, constName) {
    const startToken = `function ${constName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        // Maybe it's a `const` or `let` declaration.
        const re = new RegExp(`(?:const|let)\\s+${constName}\\s*=`);
        const m = sourceText.match(re);
        if (!m) return "";
        const exprStart = sourceText.indexOf("=", m.index) + 1;
        let depth = 0;
        let i = exprStart;
        while (i < sourceText.length) {
            const c = sourceText[i];
            if (c === "{") depth++;
            else if (c === "}") { depth--; if (depth === 0) return sourceText.slice(m.index, i + 1); }
            i++;
        }
        return "";
    }
    const bodyStart = sourceText.indexOf("{", startIndex);
    if (bodyStart === -1) return "";
    let depth = 0;
    let cursor = bodyStart;
    while (cursor < sourceText.length) {
        const char = sourceText[cursor];
        if (char === "{") depth += 1;
        if (char === "}") { depth -= 1; if (depth === 0) return sourceText.slice(startIndex, cursor + 1); }
        cursor += 1;
    }
    return "";
}

function loadPlaintextDecoder() {
    const projectRoot = path.resolve(__dirname, "..");
    const targetFile = path.join(projectRoot, "src/ui/panels/data-tools-panel.js");
    const sourceText = fs.readFileSync(targetFile, "utf8");
    const extractedFn = extractFunctionSource(sourceText, "decodePlainTextFromBytes");
    const extractedBytesToPrintable = extractFunctionSource(sourceText, "bytesToPrintableAscii");
    const context = {
        Uint8Array,
        TextDecoder,
    };
    vm.createContext(context);
    vm.runInContext(extractedBytesToPrintable, context);
    vm.runInContext(extractedFn, context);
    return { decodePlainTextFromBytes: context.decodePlainTextFromBytes };
}

// ---- Fixtures -----------------------------------------------------------

function buildPlainAscii() {
    // Standard typeable ASCII: letters, digits, punctuation, spaces, newlines.
    return Uint8Array.from("Hello, world!\n\tPassword: secret123\r\n".split("").map((c) => c.charCodeAt(0)));
}

function buildUtf8Valid() {
    // Valid UTF-8: "héllo" (e with acute is 0xc3 0xa9 in UTF-8).
    const text = "café";
    const bytes = [];
    for (let i = 0; i < text.length; i++) {
        const code = text.charCodeAt(i);
        if (code <= 0x7f) bytes.push(code);
        else if (code <= 0x7ff) {
            bytes.push(0xc0 | (code >> 6));
            bytes.push(0x80 | (code & 0x3f));
        } else {
            bytes.push(0xe0 | (code >> 12));
            bytes.push(0x80 | ((code >> 6) & 0x3f));
            bytes.push(0x80 | (code & 0x3f));
        }
    }
    return Uint8Array.from(bytes);
}

function buildMostlyGarbage() {
    // 20% valid "Pass" + 80% binary garbage (0x00-0x1f and 0x80-0xff).
    const bytes = [0x50, 0x61, 0x73, 0x73]; // "Pass"
    for (let i = 0; i < 16; i++) bytes.push(0x00);
    for (let i = 0; i < 16; i++) bytes.push(0x80 | (i & 0x7f));
    return Uint8Array.from(bytes);
}

function buildBinaryAll() {
    // All binary: 0x00-0x1f except CR/LF.
    return Uint8Array.from(Array.from({ length: 20 }, (_, i) => i === 10 || i === 13 ? i : 0x00));
}

// ---- Tests -------------------------------------------------------------

describe("Plaintext decoder validation", () => {
    const { decodePlainTextFromBytes } = loadPlaintextDecoder();

    test("accepts plain ASCII text", () => {
        const bytes = buildPlainAscii();
        const result = decodePlainTextFromBytes(bytes);
        expect(result).not.toBeNull();
        expect(result.protocol).toBe("Plain text");
        expect(result.fields.find((f) => f.name === "Text").value).toContain("Hello");
    });

    test("accepts valid UTF-8 text", () => {
        const bytes = buildUtf8Valid();
        const result = decodePlainTextFromBytes(bytes);
        expect(result).not.toBeNull();
        expect(result.protocol).toBe("Plain text");
    });

    test("rejects mostly garbage binary", () => {
        const bytes = buildMostlyGarbage();
        // 4 valid chars out of 36 = 11% valid, 89% garbage → should be rejected.
        expect(decodePlainTextFromBytes(bytes)).toBeNull();
    });

    test("rejects pure binary (all control characters)", () => {
        const bytes = buildBinaryAll();
        expect(decodePlainTextFromBytes(bytes)).toBeNull();
    });

    test("rejects null input", () => {
        expect(decodePlainTextFromBytes(null)).toBeNull();
    });

    test("rejects empty Uint8Array", () => {
        expect(decodePlainTextFromBytes(new Uint8Array(0))).toBeNull();
    });

    test("rejects UTF-8 invalid sequences", () => {
        // 0xc0 0x80 is an overlong encoding of NUL — invalid UTF-8.
        const bytes = Uint8Array.from([0xc0, 0x80, 0x50, 0x61, 0x73, 0x73]); // [invalid] + "Pass"
        expect(decodePlainTextFromBytes(bytes)).toBeNull();
    });
});
