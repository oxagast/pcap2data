// Regression tests for the chunker "max keystroke packet" knob
// (the slider next to the legacy min-gap-floor slider in the
// OpenSSH panel). The knob lets the user filter out large c2s
// SSH packets that look like terminal escape sequences rather
// than real keystrokes. Range 10–150 bytes with a 1-byte step.
// Default 100B matches the historical v2 behaviour (no
// filtering).
//
// Two contracts are pinned here:
//
//   1. The slider is present in src/index.html with the
//      documented range, default, and label companion. This is
//      the "knob is discoverable as a slider" contract — without
//      it the user can't adjust sensitivity at all.
//
//   2. The chunker drops delay-stream entries whose measured
//      packet length exceeds the cap, and leaves entries with
//      null/unknown lengths alone (the metadata might be
//      missing — don't punish the user for that). This is the
//      "knob actually filters" contract.

const fs = require("fs");
const path = require("path");

const HTML_PATH = path.join(__dirname, "..", "src", "index.html");
const PANEL_PATH = path.join(__dirname, "..", "src", "ui", "panels", "crypt-panel.js");

// For HTML we want the entire matched attribute tag (a single
// <input …> line, possibly with continuation lines via the
// long-attribute title that wraps onto the next line). The
// CSS-style ``{}`` brace counting is wrong here — HTML doesn't
// nest braces. We return the matched substring directly; tests
// use it with attribute regexes (e.g. ``\bmin="10"\b``).
function extractRule(html, selectorRe) {
    const match = selectorRe.exec(html);
    return match ? match[0] : null;
}

describe("chunker max-keystroke-packet slider (HTML markup)", () => {
    let html;

    beforeAll(() => {
        html = fs.readFileSync(HTML_PATH, "utf8");
    });

    test("range input + label exist with matching IDs", () => {
        const input = extractRule(html, /<input[^>]+id="crypt-openssh-chunker-max-packet"[^>]*>/);
        expect(input).not.toBeNull();
        expect(input).toMatch(/\bmin="10"/);
        expect(input).toMatch(/\bmax="150"/);
        expect(input).toMatch(/\bstep="1"/);
        expect(input).toMatch(/\bvalue="100"/);
        const label = extractRule(html, /<span[^>]+id="crypt-openssh-chunker-max-packet-label"[^>]*>/);
        expect(label).not.toBeNull();
    });

    test("slider range covers the documented sensitivity band (10–150)", () => {
        // 10B catches the smallest plausible SSH keystroke
        // packet (a single ESC sequence is around 3B, a short
        // arrow-key sequence is 6–10B). 150B catches the largest
        // realistic single-keystroke packet before terminal
        // escape sequences start dominating. Both bounds are
        // documented; if you change them update the comment
        // above and verify the slider's `title` attribute still
        // matches.
        const input = extractRule(html, /<input[^>]+id="crypt-openssh-chunker-max-packet"[^>]*>/);
        expect(input).not.toBeNull();
        const minMatch = /\bmin="(\d+)"/.exec(input);
        const maxMatch = /\bmax="(\d+)"/.exec(input);
        expect(minMatch).not.toBeNull();
        expect(maxMatch).not.toBeNull();
        expect(Number(minMatch[1])).toBe(10);
        expect(Number(maxMatch[1])).toBe(150);
    });

    test("slider lives next to the legacy min-gap-floor slider", () => {
        // The new slider should sit inside the same chunker-row
        // container as the existing min-boundary slider so the
        // two knobs read as a coherent pair (and so the existing
        // per-row layout — flex-wrap, gap, etc. — applies to
        // both without modification).
        const minIdx = html.indexOf('id="crypt-openssh-chunker-min-boundary"');
        const maxIdx = html.indexOf('id="crypt-openssh-chunker-max-packet"');
        expect(minIdx).toBeGreaterThan(-1);
        expect(maxIdx).toBeGreaterThan(-1);
        // They must be within ~10 KB of each other (the entire
        // OpenSSH panel is well under that).
        expect(Math.abs(minIdx - maxIdx)).toBeLessThan(10_000);
    });

    test("default value matches historical v2 behaviour (100B = no filter)", () => {
        // v2 of the decoder had no max-packet filter, so 100B
        // (well above any plausible single-keystroke packet)
        // keeps every entry that used to flow through. If you
        // change this default, downstream tests in
        // chunker_max_packet_filter.test.js need to be re-baselined.
        const input = extractRule(html, /<input[^>]+id="crypt-openssh-chunker-max-packet"[^>]*>/);
        expect(input).not.toBeNull();
        const valueMatch = /\bvalue="(\d+)"/.exec(input);
        expect(valueMatch).not.toBeNull();
        expect(Number(valueMatch[1])).toBe(100);
    });
});

describe("chunker max-keystroke-packet slider (crypt-panel wiring)", () => {
    let panelSrc;

    beforeAll(() => {
        panelSrc = fs.readFileSync(PANEL_PATH, "utf8");
    });

    test("chunkerSettings holds a maxKeystrokePacket field with the v2 default", () => {
        // The chunker reads ``chunkerSettings.maxKeystrokePacket``
        // at the delaysWithIdx push sites. The default 100 keeps
        // every entry that v2 would have processed.
        expect(panelSrc).toMatch(/let\s+chunkerSettings\s*=\s*\{[^}]*maxKeystrokePacket\s*:\s*100/);
    });

    test("slider input event updates chunkerSettings.maxKeystrokePacket", () => {
        // The slider mutates chunkerSettings in real time so
        // the next analysis picks up the new value. We don't
        // re-run analysis on every input tick (same reason as
        // the min-gap slider: page jumps), so this just checks
        // the binding wiring exists.
        expect(panelSrc).toMatch(/chunkerMaxPacketEl[\s\S]*?addEventListener\(\s*["']input["']/);
        expect(panelSrc).toMatch(/chunkerSettings\.maxKeystrokePacket\s*=\s*Math\.round\(/);
    });

    test("delay-stream push sites filter entries exceeding the cap", () => {
        // Two push sites: the chunked async helper (called by
        // the main analysis path) and the synchronous helper
        // (used by the chunker preview). Both must apply the
        // cap; if either regresses, large escape-sequence packets
        // will corrupt the keystroke timing distribution again.
        const pushSites = panelSrc.match(/out\.push\(\s*\{\s*delay\s*:\s*d\s*,\s*index\s*:\s*idx\s*,\s*packetLength\s*:\s*pktLen\s*\}\s*\)\s*;/g) || [];
        // We expect the original two push sites to still exist
        // (we haven't moved the entries, just added an early
        // continue above them).
        expect(pushSites.length).toBe(2);
        // And both push sites should be preceded by a
        // ``continue`` guarded by ``pktLenMax > 0 && pktLen > pktLenMax``
        // — the "filter if too large" branch.
        const continueHits = (panelSrc.match(/pktLenMax\s*>\s*0\s*&&\s*Number\.isFinite\(pktLen\)\s*&&\s*pktLen\s*>\s*pktLenMax/g) || []).length;
        expect(continueHits).toBe(2);
    });
});
