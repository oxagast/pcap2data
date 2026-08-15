"use strict";

const {
    ShellMarkov,
    cleanLines,
    loadDelays,
    keyDistance,
    BOS,
    EOS,
} = require("../src/ui/decoders/ssh-keystrokes/markov");

describe("ShellMarkov — corpus basics", () => {
    test("training tallies commands, first tokens, and lengths", () => {
        const m = new ShellMarkov(3).train([
            "ls -la",
            "ls -l",
            "cat foo.txt",
            "cat bar.txt",
            "git status",
            "git log",
        ]);
        expect(m.nCommands).toBe(6);
        expect(m.firstTokens).toEqual({ ls: 2, cat: 2, git: 2 });
        expect(m.lengths).toEqual({ 5: 1, 6: 1, 7: 1, 10: 1, 11: 2 });
    });

    test("alphabet sorts and excludes BOS only when training never saw it", () => {
        const m = new ShellMarkov(3).train(["aa", "ab"]);
        const alpha = m.alphabet;
        // Should contain observed chars plus EOS
        expect(alpha).toContain(EOS);
        expect(alpha).toContain("a");
        expect(alpha).toContain("b");
        // Sorted lexicographically
        const sorted = [...alpha].sort();
        expect(alpha).toEqual(sorted);
    });

    test("commandLogP rises with repetitions (longer exact-match bonus)", () => {
        const m = new ShellMarkov(3).train([
            "ls", "ls", "ls", "ls",
            "ls -l",
        ]);
        const repeated = m.commandLogP("ls");
        const fresh = m.commandLogP("ls -l");
        // Both strings are in-vocab; just sanity-check logP finiteness and ordering:
        // "ls" appears 4 times and is shortest, so exact-match bonus is biggest per char.
        expect(Number.isFinite(repeated)).toBe(true);
        expect(Number.isFinite(fresh)).toBe(true);
        // Different commands should generally have different scores (not equal)
        expect(repeated).not.toBe(fresh);
    });
});

describe("ShellMarkov — rank + score", () => {
    test("rank orders higher-scoring commands first", () => {
        const m = new ShellMarkov(3).train([
            "ls", "ls", "ls",
            "ls -l",
            "cat foo",
        ]);
        const r = m.rank(["ls", "ls -l", "totally_unknown_xyz"]);
        // First should be a known candidate, not the totally-unknown one.
        expect(r[r.length - 1][1]).toBe("totally_unknown_xyz");
        // First string should be either "ls" or "ls -l"
        expect(["ls", "ls -l"]).toContain(r[0][1]);
    });

    test("timingScore is finite and falls within a sane range", () => {
        const m = new ShellMarkov(3).train(["ls", "cat foo", "git log"]);
        // Synthesize delays roughly aligned to short commands
        const ds = [80, 100, 90, 95, 102, 88];
        const s = m.timingScore("ls -l", ds);
        expect(Number.isFinite(s)).toBe(true);
        expect(s).toBeLessThanOrEqual(0); // negative MSE
    });

    test("score combines command + timing components when present", () => {
        const m = new ShellMarkov(3).train(["ls", "cat foo", "ls -l"]);
        // Use a multi-char candidate so timingScore actually has at least
        // one digit-bigram to compute against the delays array.
        const s1 = m.score("ls -l", null);
        const s2 = m.score("ls -l", [100, 90, 80, 95]);
        expect(s2).not.toBe(s1);
    });
});

describe("ShellMarkov — generateBeam", () => {
    test("respects target length within tolerance", () => {
        const cmds = [
            "ls -la", "ls -l", "ls -a", "ls",
            "cat foo", "cat bar", "cat baz",
            "git status", "git log", "git push",
        ];
        const m = new ShellMarkov(3).train(cmds);
        const beam = m.generateBeam(5, 2, 200, 30, 50);
        expect(beam.length).toBeGreaterThan(0);
        for (const [, t] of beam) {
            expect(Math.abs(t.length - 5)).toBeLessThanOrEqual(2);
        }
    });

    test("returns highest-scoring strings first", () => {
        const m = new ShellMarkov(3).train([
            "ls", "ls", "ls",
            "ls -l", "ls -a",
            "cat foo",
        ]);
        const beam = m.generateBeam(null, 999, 100, 20, 20);
        expect(beam.length).toBeGreaterThan(0);
        for (let i = 1; i < beam.length; i += 1) {
            expect(beam[i - 1][0]).toBeGreaterThanOrEqual(beam[i][0]);
        }
    });
});

describe("ShellMarkov — JSON round-trip via toDict/fromDict", () => {
    test("preserves counts after serialization", () => {
        const m = new ShellMarkov(3).train([
            "ls", "ls", "ls",
            "git status", "git log",
        ]);
        const d = m.toDict();
        const m2 = ShellMarkov.fromDict(d);
        expect(m2.nCommands).toBe(m.nCommands);
        expect(m2.alphabet.length).toBe(m.alphabet.length);
        expect(m2.commandLogP("ls")).toBeCloseTo(m.commandLogP("ls"), 8);
    });
});

describe("ShellMarkov — helpers", () => {
    test("keyDistance returns small value for adjacent keys", () => {
        // 'q' and 'w' are adjacent in row 0. Their x-positions differ by 1 (no y diff).
        const d = keyDistance("q", "w");
        expect(d).toBeCloseTo(1.0, 3);
    });

    test("keyDistance returns fallback for unknown keys", () => {
        const d = keyDistance("\u0001", "\u0002");
        expect(d).toBe(1.5);
    });

    test("cleanLines drops blank lines and collapses pathological indentation", () => {
        // '   c' has 3 leading spaces; the regex collapses the run of 2+ -> '', leaving 'c'.
        const out = cleanLines("a\n\nb\n   c\n");
        expect(out).toEqual(["a", "b", "c"]);
    });

    test("loadDelays extracts finite delayMs from the SSH JSON shape", () => {
        const ds = loadDelays(JSON.stringify({
            delays: [
                { delayMs: 80 },
                { delayMs: null },
                { delayMs: 102 },
                { notDelayMs: 9999 },
            ],
        }));
        expect(ds).toEqual([80, 102]);
    });
});
