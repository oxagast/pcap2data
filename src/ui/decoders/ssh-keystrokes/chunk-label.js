// Pure helpers for formatting chunker-preview labels.
//
// The chunker preview list (driven by the chunker-min-boundary slider)
// shows one row per chunk with:
//   - chunk index
//   - a human-readable start timestamp (HH:MM:SS.mmm)
//   - keystroke count
//   - a label, either the cached top candidate text or a gap hint
//
// These helpers keep the formatting in one place so the panel can stay
// focused on DOM construction and the format stays unit-testable.

"use strict";

// Format a milliseconds-since-epoch timestamp as "HH:MM:SS.mmm" in UTC.
// Returns the placeholder "—" for non-finite or negative inputs (the
// chunker never produces negative timestamps but a defensively-handled
// helper is easier than chasing a NaN later).
function formatHmsUtc(tsMs) {
    if (!Number.isFinite(tsMs) || tsMs < 0) return "—";
    const d = new Date(tsMs);
    if (Number.isNaN(d.getTime())) return "—";
    const hh = String(d.getUTCHours()).padStart(2, "0");
    const mm = String(d.getUTCMinutes()).padStart(2, "0");
    const ss = String(d.getUTCSeconds()).padStart(2, "0");
    const ms = String(d.getUTCMilliseconds()).padStart(3, "0");
    return `${hh}:${mm}:${ss}.${ms}`;
}

// Pick the most informative non-finite fallback we can given a chunk's
// start-delay-position and the packet positions. Used by the panel
// when the chain flow → delays → packet → timestamp has any missing
// link, so the row still gives the analyst a hint of where to look
// in the raw data.
function formatFallbackLabel(delayPos, packetPos) {
    if (Number.isInteger(packetPos)) return `p#${packetPos}`;
    if (Number.isInteger(delayPos)) return `d#${delayPos}`;
    return "—";
}

// Resolve a chunk's start timestamp. The flow carries an ordered
// `packets` list. The delays-with-idx array is also indexed in packet
// order, so `delaysWithIdx[startDelayPos].index` is the position of
// the first packet in the chunk inside `flow.packets`.
//
// `getFlowPackets` is injected as a function to keep this helper
// decoupled from the panel's flow storage (and trivially mockable in
// tests). It receives the flowKey and returns the array of packets or
// null/undefined when the flow can't be located.
function resolveChunkStartTimestamp({
    flowKey,
    startDelayPos,
    delaysWithIdx,
    getFlowPackets,
}) {
    if (!Number.isInteger(startDelayPos) || startDelayPos < 0) return null;
    if (!Array.isArray(delaysWithIdx) || startDelayPos >= delaysWithIdx.length) return null;
    const row = delaysWithIdx[startDelayPos];
    const pktPos = row && Number.isInteger(row.index) ? row.index : null;
    if (typeof getFlowPackets !== "function") return null;
    const packets = getFlowPackets(flowKey);
    if (!Array.isArray(packets) || pktPos === null || pktPos >= packets.length) {
        return { tsMs: null, delayPos: startDelayPos, packetPos: pktPos };
    }
    const pkt = packets[pktPos];
    const tsMs = pkt && Number.isFinite(pkt.timestamp) ? pkt.timestamp : null;
    return { tsMs, delayPos: startDelayPos, packetPos: pktPos };
}

// Convenience wrapper: returns the formatted label string the panel
// renders. Falls back to delay/packet position labels when the
// timestamp chain is broken.
function formatChunkStartLabel({
    flowKey,
    startDelayPos,
    delaysWithIdx,
    getFlowPackets,
}) {
    const resolved = resolveChunkStartTimestamp({
        flowKey,
        startDelayPos,
        delaysWithIdx,
        getFlowPackets,
    });
    if (!resolved) return "—";
    if (resolved.tsMs !== null) return formatHmsUtc(resolved.tsMs);
    return formatFallbackLabel(resolved.delayPos, resolved.packetPos);
}

// Build the "label cell" content. If a cached top candidate exists
// for this chunk we surface it; otherwise we fall back to a "gap
// Xms" hint that tells the user the chunk ended because of a large
// pause rather than because we have a strong guess.
function formatChunkLabelCell({
    cachedTopText,
    maxGapMs,
}) {
    if (typeof cachedTopText === "string" && cachedTopText.length > 0) {
        return { text: `→ ${cachedTopText}`, title: cachedTopText };
    }
    if (Number.isFinite(maxGapMs)) {
        return { text: `→ gap ${maxGapMs.toFixed(0)}ms`, title: null };
    }
    return { text: "→ (no cached top)", title: null };
}

module.exports = {
    formatHmsUtc,
    formatFallbackLabel,
    resolveChunkStartTimestamp,
    formatChunkStartLabel,
    formatChunkLabelCell,
};