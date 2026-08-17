// Tests for the SSH c2s compression-likelihood heuristic.
//
// We can't decrypt the SSH stream, so these tests pin down the
// observable-signal behavior of the heuristic itself:
//
//   * `analyzeCompressionLikelihood` returns 0 for empty/short flows
//   * uncompressed-looking flows (median ~95 bytes) score low
//   * compressed-looking flows (median ~45 bytes, lots of tiny packets,
//     homogeneous sizes) score high
//   * `compressionInflationFactor` returns 1.0 when likelihood is 0
//   * inflation ramps up with likelihood but is tapered for large packet
//     lengths so we don't double-count obviously-multi-keystroke packets.

"use strict";

const {
    analyzeCompressionLikelihood,
    compressionInflationFactor,
    _internal,
} = require("../src/ui/decoders/ssh-keystrokes/compression-heuristic.js");

// Helper: build a synthetic c2s packet object that mimics the shape
// `calibration.extractDelaysFromFlow` / `summarizeS2cOutput` use.
function makeC2sPacket(wireLen, ts) {
    return {
        direction: "c2s",
        timestamp: ts,
        packet: {
            "packet.info": {
                "packet.length": wireLen,
            },
        },
    };
}

describe("compression-heuristic: analyzeCompressionLikelihood", () => {
    test("returns zero for an empty packet list", () => {
        const r = analyzeCompressionLikelihood([]);
        expect(r.likelihood).toBe(0);
        expect(r.signals.c2sPacketCount).toBe(0);
        expect(r.signals.medianLen).toBeNull();
    });

    test("returns zero for a list with fewer than minC2sPackets", () => {
        const pkts = [makeC2sPacket(80, 0), makeC2sPacket(82, 1)];
        const r = analyzeCompressionLikelihood(pkts, { minC2sPackets: 10 });
        expect(r.likelihood).toBe(0);
        expect(r.signals.c2sPacketCount).toBe(2);
    });

    test("uncompressed-looking flows score low", () => {
        // Median ~95 bytes, mixed sizes — typical uncompressed SSH
        // keystroke stream.
        const pkts = [];
        for (let i = 0; i < 50; i++) {
            const baseLen = 80 + Math.floor(Math.random() * 40); // 80..119
            pkts.push(makeC2sPacket(baseLen, i));
        }
        const r = analyzeCompressionLikelihood(pkts);
        expect(r.signals.c2sPacketCount).toBe(50);
        expect(r.signals.medianLen).toBeGreaterThan(75);
        expect(r.signals.shortFraction).toBe(0);
        expect(r.likelihood).toBeLessThan(0.3);
    });

    test("compressed-looking flows score high", () => {
        // Median ~45 bytes, lots of tiny packets, very homogeneous.
        const pkts = [];
        for (let i = 0; i < 60; i++) {
            const baseLen = 40 + Math.floor(Math.random() * 10); // 40..49
            pkts.push(makeC2sPacket(baseLen, i));
        }
        const r = analyzeCompressionLikelihood(pkts);
        expect(r.signals.medianLen).toBeLessThan(55);
        expect(r.signals.shortFraction).toBeGreaterThan(0.5);
        expect(r.likelihood).toBeGreaterThan(0.7);
    });

    test("ignores non-c2s packets", () => {
        const pkts = [
            // tiny s2c packets should be ignored
            { direction: "s2c", timestamp: 0, packet: { "packet.info": { "packet.length": 20 } } },
            { direction: "s2c", timestamp: 1, packet: { "packet.info": { "packet.length": 25 } } },
        ];
        const r = analyzeCompressionLikelihood(pkts);
        expect(r.signals.c2sPacketCount).toBe(0);
        expect(r.likelihood).toBe(0);
    });

    test("ignores packets with no length signal", () => {
        const pkts = [
            makeC2sPacket(80, 0),
            { direction: "c2s", timestamp: 1, packet: { "packet.info": null } },
            { direction: "c2s", timestamp: 2, packet: null },
            { direction: "c2s", timestamp: 3 }, // no packet field
        ];
        const r = analyzeCompressionLikelihood(pkts);
        expect(r.signals.c2sPacketCount).toBe(1);
    });
});

describe("compression-heuristic: compressionInflationFactor", () => {
    test("returns 1.0 when likelihood is 0", () => {
        expect(compressionInflationFactor(0, 60)).toBe(1);
    });

    test("ramps up with likelihood at small packet sizes", () => {
        const f0 = compressionInflationFactor(0, 30);
        const f50 = compressionInflationFactor(0.5, 30);
        const f100 = compressionInflationFactor(1.0, 30);
        expect(f50).toBeGreaterThan(f0);
        expect(f100).toBeGreaterThan(f50);
    });

    test("tapers to 1.0 for large packets so we don't over-inflate", () => {
        const fSmall = compressionInflationFactor(1.0, 30);
        const fLarge = compressionInflationFactor(1.0, 200);
        expect(fSmall).toBeGreaterThan(1);
        expect(fLarge).toBeLessThanOrEqual(1.001); // ~1.0 at the taper boundary
    });

    test("clamps to a sane maximum", () => {
        const f = compressionInflationFactor(1.0, 1); // extremely small, full likelihood
        expect(f).toBeLessThanOrEqual(_internal.INFLATION_MAX + 0.5);
    });

    test("handles non-finite inputs without throwing", () => {
        expect(compressionInflationFactor(NaN, 60)).toBe(1);
        expect(compressionInflationFactor(0.5, NaN)).toBeGreaterThan(1);
        expect(compressionInflationFactor(0.5, 60)).toBeGreaterThan(1);
    });

    test("non-finite likelihood returns 1.0", () => {
        expect(compressionInflationFactor(undefined, 60)).toBe(1);
        expect(compressionInflationFactor(null, 60)).toBe(1);
        expect(compressionInflationFactor(-0.3, 60)).toBe(1);
        expect(compressionInflationFactor(1.7, 60)).toBeLessThanOrEqual(_internal.INFLATION_MAX + 0.5);
    });
});

describe("compression-heuristic: internals", () => {
    test("median handles empty / single / odd / even lists", () => {
        const { median } = _internal;
        expect(median([])).toBeNull();
        expect(median([42])).toBe(42);
        expect(median([1, 2, 3])).toBe(2);
        expect(median([1, 2, 3, 4])).toBe(2.5);
    });

    test("percentile handles boundary inputs", () => {
        const { percentile } = _internal;
        expect(percentile([], 0.5)).toBeNull();
        expect(percentile([1, 2, 3, 4], 0)).toBe(1);
        expect(percentile([1, 2, 3, 4], 1)).toBe(4);
        expect(percentile([1, 2, 3, 4], 0.5)).toBe(2.5);
    });
});