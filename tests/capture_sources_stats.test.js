const {
  getCaptureSources,
  getPacketsForCaptureSource,
  buildStatsComparison,
  buildSourceComparisonBucketData,
} = require("../src/ui/panels/stats-panel");

function packet(sourceId, sourceName) {
  return {
    "packet.info": {
      "capture.sourceId": sourceId,
      "capture.sourceSession": sourceName,
      "packet.proto": "TCP",
      IP: { "ip.src.addr": "10.0.0.1", "ip.dst.addr": "10.0.0.2" },
    },
  };
}

describe("capture source stats helpers", () => {
  test("uses merged metadata source descriptors", () => {
    const capture = {
      "capture.metadata": {
        sources: [
          { sourceId: "a", sourceName: "left", ordinal: 0, packetCount: 2 },
          { sourceId: "b", sourceName: "right", ordinal: 1, packetCount: 1 },
        ],
      },
      host: { all: [packet("a", "left"), packet("b", "right")] },
    };
    expect(getCaptureSources(capture).map((source) => source.sourceId)).toEqual(["a", "b"]);
    expect(getPacketsForCaptureSource(capture, "a")).toHaveLength(1);
  });

  test("builds signed comparison deltas", () => {
    const comparison = buildStatsComparison(
      { totalPackets: 2, totalStreams: 1 },
      { totalPackets: 5, totalStreams: 3 },
      "left",
      "right",
    );
    expect(comparison.rows.find((row) => row.label === "Packets").delta).toBe(3);
    expect(comparison.rows.find((row) => row.label === "Streams").delta).toBe(2);
  });

  test("builds selectable per-source bucket data", () => {
    global.window = { keystoreCreds: new Set() };
    const capture = { host: { all: [packet("a", "left"), packet("b", "right")] } };
    expect(buildSourceComparisonBucketData(capture, "a", "hosts")).toEqual([
      "10.0.0.1",
      "10.0.0.2",
      "comparison",
    ]);
  });
});