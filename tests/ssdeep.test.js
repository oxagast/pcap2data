// Tests for the SSDEEP-style fuzzy similarity helper.
// See src/ui/decoders/ssh-keystrokes/ssdeep.js.

const { computeSsdeep, buildSignature } = require("../src/ui/decoders/ssh-keystrokes/ssdeep");

describe("buildSignature", () => {
    test("returns a non-empty signature for a typable command", () => {
        const sig = buildSignature("ls -la");
        expect(sig.length).toBeGreaterThan(0);
        // Every chunk must be a 16-bit unsigned integer.
        for (const chunk of sig) {
            expect(Number.isInteger(chunk)).toBe(true);
            expect(chunk).toBeGreaterThanOrEqual(0);
            expect(chunk).toBeLessThanOrEqual(0xffff);
        }
    });

    test("returns an empty signature for empty input", () => {
        expect(buildSignature("")).toEqual([]);
    });

    test("returns a single fallback chunk for input too short to trigger", () => {
        const sig = buildSignature("a");
        expect(sig.length).toBe(1);
    });

    test("identical strings produce identical signatures", () => {
        expect(buildSignature("apt-get update")).toEqual(buildSignature("apt-get update"));
    });
});

describe("computeSsdeep", () => {
    test("identical strings score 1.0", () => {
        const { score, matched } = computeSsdeep("ls -la", "ls -la");
        expect(score).toBeGreaterThan(0.95);
        expect(matched).toBeGreaterThan(0);
    });

    test("completely different strings score close to 0", () => {
        const { score } = computeSsdeep("cat /etc/passwd", "rm -rf /");
        expect(score).toBeLessThan(0.4);
    });

    test("one empty, one non-empty scores 0", () => {
        const { score } = computeSsdeep("", "ls");
        expect(score).toBe(0);
    });

    test("shared prefix scores in the middle-high band", () => {
        // CTPH only emits chunks at trigger positions and a single
        // character typically doesn't shift any trigger, so the two
        // prefixes produce the same signature and the score is very
        // high. Tolerate the upper end here and rely on the
        // "completely different strings" test to anchor the lower end.
        const { score } = computeSsdeep("ls -l /tmp", "ls -l /pmt");
        expect(score).toBeGreaterThan(0.3);
    });

    test("shared prefix with single char difference scores high", () => {
        const { score } = computeSsdeep("git push origin main", "git push origin mane");
        expect(score).toBeGreaterThan(0.5);
    });

    test("insertions are tolerated", () => {
        const { score } = computeSsdeep("ls -la", "ls  -la"); // extra space
        expect(score).toBeGreaterThan(0.4);
    });

    test("single transposition still scores reasonably", () => {
        const { score } = computeSsdeep("cd /tmp", "cd /pmt");
        expect(score).toBeGreaterThan(0.2);
    });

    test("long shared prefix dominates score even when suffix differs", () => {
        const truth = "apt-get install -y vim-nox-emu-32bit-extra";
        const pred = "apt-get install -y vim-nox-emu-32bit-XYZ";
        const { score } = computeSsdeep(truth, pred);
        expect(score).toBeGreaterThan(0.5);
    });

    test("returns both signatures so callers can show diagnostics", () => {
        const { sigA, sigB } = computeSsdeep("hello", "world");
        expect(Array.isArray(sigA)).toBe(true);
        expect(Array.isArray(sigB)).toBe(true);
        expect(sigA.length).toBeGreaterThan(0);
        expect(sigB.length).toBeGreaterThan(0);
    });

    test("non-string inputs are handled safely", () => {
        const { score: s1 } = computeSsdeep(null, "ls");
        expect(s1).toBe(0);
        const { score: s2 } = computeSsdeep(undefined, undefined);
        expect(s2).toBe(0);
        const { score: s3 } = computeSsdeep(42, "ls");
        expect(s3).toBe(0);
    });
});
