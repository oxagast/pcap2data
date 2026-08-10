// Tests for the Hash Reverse panel helpers added to
// src/ui/panels/data-tools-panel.js. The two pure helpers
// (`normalizeDataToolsHashForReverseLookup`, `setDataToolsHashReverseInput`)
// are exercised against the actual module source so any future signature
// change breaks this test loudly.

const fs = require("fs");
const path = require("path");
const vm = require("vm");

// We can't ``require()`` the panel directly because it pulls in
// Electron-only modules. Instead we extract the helpers via acorn
// (already a webpack dependency, so it's always available in the
// project) — much safer than brace-counting because template
// literals and inner object literals would otherwise confuse a
// naive counter.
function extractFunctionSource(sourceText, functionName) {
    const acorn = require("acorn");
    const ast = acorn.parse(sourceText, {
        ecmaVersion: 2022,
        sourceType: "script",
        locations: false,
        ranges: true,
        allowReturnOutsideFunction: false,
        allowHashBang: false,
    });
    for (const node of ast.body) {
        if (node.type !== "FunctionDeclaration") continue;
        if (node.id && node.id.name === functionName) {
            const [start, end] = node.range;
            return sourceText.slice(start, end);
        }
    }
    throw new Error(`Could not find function ${functionName}`);
}

function loadPanelExports() {
    const projectRoot = path.resolve(__dirname, "..");
    const targetFile = path.join(projectRoot, "src/ui/panels/data-tools-panel.js");
    const sourceText = fs.readFileSync(targetFile, "utf8");

    const helperSources = [
        "normalizeDataToolsHashForReverseLookup",
        "formatUnmatchedHashLine",
        "buildHashReverseKeystoreEntries",
    ]
        .map((name) => extractFunctionSource(sourceText, name))
        .join("\n\n");

    const context = {
        exports: {},
        module: { exports: {} },
    };
    context.module.exports = context.exports;
    vm.createContext(context);
    vm.runInContext(
        helperSources +
        "\nmodule.exports = { normalizeDataToolsHashForReverseLookup, formatUnmatchedHashLine, buildHashReverseKeystoreEntries };",
        context,
    );
    return context.module.exports;
}

function loadPanelSourceForExports() {
    const projectRoot = path.resolve(__dirname, "..");
    const targetFile = path.join(projectRoot, "src/ui/panels/data-tools-panel.js");
    return fs.readFileSync(targetFile, "utf8");
}

describe("Hash Reverse panel helpers", () => {
    let panelExports;
    let sourceText;
    beforeAll(() => {
        panelExports = loadPanelExports();
        sourceText = loadPanelSourceForExports();
    });

    test("panel exports the new reverse-lookup helpers", () => {
        expect(sourceText).toMatch(/runDataToolsHashReverseLookup[\s\S]*?module\.exports/);
        expect(sourceText).toMatch(/setDataToolsHashReverseInput/);
        expect(sourceText).toMatch(/normalizeDataToolsHashForReverseLookup/);
        // The export block at the bottom of the panel must list each of
        // these three symbols; otherwise the renderer can't import them.
        const exportsBlock = sourceText.split("module.exports = {")[1] || "";
        expect(exportsBlock).toMatch(/runDataToolsHashReverseLookup/);
        expect(exportsBlock).toMatch(/setDataToolsHashReverseInput/);
        expect(exportsBlock).toMatch(/normalizeDataToolsHashForReverseLookup/);
    });

    describe("normalizeDataToolsHashForReverseLookup", () => {
        const normalize = () => panelExports.normalizeDataToolsHashForReverseLookup;

        test("strips leading 0x prefix", () => {
            expect(normalize()("0xDEADBEEF"))
                .toBe("deadbeef");
            expect(normalize()("0X abcdef"))
                .toBe("abcdef");
        });

        test("removes whitespace, commas, colons, dashes, slashes", () => {
            expect(normalize()("aa:bb:cc:dd:ee:ff"))
                .toBe("aabbccddeeff");
            expect(normalize()("aa-bb-cc-dd"))
                .toBe("aabbccdd");
            expect(normalize()("aa bb cc dd"))
                .toBe("aabbccdd");
            expect(normalize()("aa,bb,cc,dd"))
                .toBe("aabbccdd");
            expect(normalize()("aa/bb/cc/dd"))
                .toBe("aabbccdd");
        });

        test("lowercases mixed-case hex", () => {
            expect(normalize()("AaBbCcDdEeFf"))
                .toBe("aabbccddeeff");
        });

        test("drops non-hex characters but keeps embedded hex", () => {
            // The normalizer's contract is "strip non-hex, keep hex" —
            // any non-hex character is dropped, but hex characters
            // embedded in surrounding noise survive (which is what lets
            // ``hello world!`` yield ``ed`` rather than empty). This is
            // intentional: users sometimes paste a hash mixed in with
            // a label, e.g. ``hash: 5d41...402``. The downstream call
            // to hashes.com rejects nonsense anyway, so dropping
            // here just trims garbage.
            expect(normalize()("hello world!")).toBe("ed");
            // After the separator strip, "not-a-hash" becomes
            // "notahash" — only ``a`` survives the hex filter
            // (n, o, t, h, s are all non-hex).
            expect(normalize()("not-a-hash")).toBe("aa");
            // ``greetings-1234`` → ``greetings1234`` →
            // ``ee1234`` (both ``e`` characters in ``grEEtings``
            // are hex; g, r, i, t, n, g, s are non-hex).
            expect(normalize()("greetings-1234")).toBe("ee1234");
        });

        test("accepts common hash lengths (MD5, SHA-1, SHA-256, SHA-512)", () => {
            const md5 = "5d41402abc4b2a76b9719d911017c592";
            expect(normalize()(md5)).toBe(md5);
            const sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
            expect(normalize()(sha1)).toBe(sha1);
            const sha256 =
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
            expect(normalize()(sha256)).toBe(sha256);
            const sha512 =
                "cf83e1357eefb8bdf1542850d66d8007" +
                "d620e4050b5715dc83f4a921d36ce9ce" +
                "47d0d13c5d85f2b0ff8318d2877eec2f" +
                "63b931bd47417a81a538327af927da3e";
            expect(normalize()(sha512)).toBe(sha512);
        });

        test("handles empty / null / undefined input safely", () => {
            expect(normalize()("")).toBe("");
            expect(normalize()(null)).toBe("");
            expect(normalize()(undefined)).toBe("");
            // Numbers get coerced via ``String(rawValue || "")`` so the
            // value ``42`` arrives at the regex as ``"42"``, which is
            // already pure-hex and survives the filter unchanged.
            // Documenting this guards against any future refactor that
            // accidentally switches to a strict numeric-only path.
            expect(normalize()(42)).toBe("42");
        });
    });

    describe("formatUnmatchedHashLine", () => {
        const format = () => panelExports.formatUnmatchedHashLine;

        test("returns hash from object shape", () => {
            expect(format()({ hash: "5d41402a", salt: "", algorithm: "MD5" }))
                .toBe("5d41402a");
            expect(format()({ hash: "abc123" }))
                .toBe("abc123");
        });

        test("returns the string when given a legacy bare-string entry", () => {
            expect(format()("deadbeef")).toBe("deadbeef");
        });

        test("trims whitespace", () => {
            expect(format()({ hash: "  5d41402a  " })).toBe("5d41402a");
            expect(format()("  deadbeef\n")).toBe("deadbeef");
        });

        test("returns empty string for null / undefined / empty input", () => {
            expect(format()(null)).toBe("");
            expect(format()(undefined)).toBe("");
            expect(format()("")).toBe("");
            expect(format()({})).toBe("");
            expect(format()({ hash: "" })).toBe("");
            expect(format()({ hash: null })).toBe("");
        });

        test("never returns the literal string '[object Object]'", () => {
            // Regression: the previous implementation used
            // ``String(entry || "")`` which collapsed objects to
            // ``"[object Object]"``. Lock that out.
            const result = format()({ hash: "abc123", salt: "x" });
            expect(result).not.toBe("[object Object]");
            expect(result).toBe("abc123");
        });
    });

    describe("buildHashReverseKeystoreEntries", () => {
        const build = () => panelExports.buildHashReverseKeystoreEntries;

        const md5OfHello =
            "5d41402abc4b2a76b9719d911017c592";

        test("returns empty list when founds is empty or missing", () => {
            expect(build()({ queryHashes: [], founds: [] })).toEqual([]);
            expect(build()({ queryHashes: [], founds: null })).toEqual([]);
            expect(build()({ queryHashes: [] })).toEqual([]);
        });

        test("skips founds entries that have no plaintext", () => {
            const result = build()({
                queryHashes: [md5OfHello],
                founds: [
                    { hash: md5OfHello, algorithm: "MD5", plaintext: "" },
                    { hash: md5OfHello, algorithm: "MD5", plaintext: "   " },
                    { hash: md5OfHello, algorithm: "MD5" },
                ],
            });
            expect(result).toEqual([]);
        });

        test("builds a keystore-shaped entry per match with the plaintext as content", () => {
            const result = build()({
                queryHashes: [md5OfHello],
                founds: [
                    {
                        hash: md5OfHello,
                        algorithm: "MD5",
                        plaintext: "hello",
                    },
                ],
            });
            expect(result).toHaveLength(1);
            const entry = result[0];
            expect(entry.type).toBe("secret");
            expect(entry.source).toBe("hashes-com-reverse");
            expect(entry.content).toBe("hello");
            expect(entry.summary).toMatch(/MD5/);
            expect(entry.label).toContain("MD5");
        });

        test("includes salt in summary when present", () => {
            const result = build()({
                queryHashes: [md5OfHello],
                founds: [
                    {
                        hash: md5OfHello,
                        algorithm: "MD5",
                        plaintext: "hello",
                        salt: "abcd",
                    },
                ],
            });
            expect(result[0].summary).toMatch(/salt=abcd/);
        });

        test("annotates unverified entries when the resolved hash wasn't requested", () => {
            const result = build()({
                queryHashes: ["requestedhash"],
                founds: [
                    {
                        hash: "differenthash",
                        algorithm: "MD5",
                        plaintext: "leaked",
                    },
                ],
            });
            expect(result).toHaveLength(1);
            expect(result[0].summary).toMatch(/unverified origin/);
        });

        test("emits one entry per plaintext when a single hash has multiple matches", () => {
            const result = build()({
                queryHashes: [md5OfHello],
                founds: [
                    {
                        hash: md5OfHello,
                        algorithm: "MD5",
                        plaintext: "hello",
                    },
                    {
                        hash: md5OfHello,
                        algorithm: "MD5",
                        plaintext: "world",
                    },
                ],
            });
            expect(result).toHaveLength(2);
            expect(result.map((entry) => entry.content)).toEqual([
                "hello",
                "world",
            ]);
        });

        test("label is stable for the same hash so dedupe in addSessionKeystoreEntry works", () => {
            const a = build()({
                queryHashes: [md5OfHello],
                founds: [
                    {
                        hash: md5OfHello,
                        algorithm: "MD5",
                        plaintext: "hello",
                    },
                ],
            });
            const b = build()({
                queryHashes: [md5OfHello],
                founds: [
                    {
                        hash: md5OfHello,
                        algorithm: "MD5",
                        plaintext: "hello",
                    },
                ],
            });
            expect(a[0].label).toBe(b[0].label);
            expect(a[0].content).toBe(b[0].content);
        });
    });
});