const {
    mergeSessions,
    normalizeOffsetMs,
    parseTimestampMs,
    inferSourceRelationship,
} = require("../src/session-merge");

function packet({
    sourceIp = "10.0.0.1",
    destinationIp = "10.0.0.2",
    sourcePort = 40000,
    destinationPort = 443,
    timestamp = "2026-09-04 12:00:00.000000",
    processed = 0,
    mac = "aa:bb:cc:dd:ee:01",
} = {}) {
    return {
        "packet.info": {
            "packet.processed": processed,
            "packet.timestamp": timestamp,
            "packet.proto": "TCP",
            IP: {
                "ip.src.addr": sourceIp,
                "ip.dst.addr": destinationIp,
                "Source MAC": mac,
            },
            TCP: {
                "tcp.src.port": sourcePort,
                "tcp.dst.port": destinationPort,
            },
        },
        "extra.info": {},
    };
}

function session(name, packets, state = {}) {
    return {
        name,
        sessionPayload: JSON.stringify({
            "capture.data": {
                host: { "10.0.0.2": packets },
                "final.summary": `${name} summary`,
            },
            "session.state": state,
        }),
    };
}

describe("session merge helpers", () => {
    test("parses timestamps with microseconds and normalizes seconds plus milliseconds", () => {
        expect(parseTimestampMs("2026-09-04 12:00:00.123456")).toBe(
            new Date(2026, 8, 4, 12, 0, 0, 123).getTime(),
        );
        expect(normalizeOffsetMs({ offsetSeconds: -2, offsetMilliseconds: 125.5 })).toBe(-1874.5);
    });

    test("reports strong shared MAC evidence as same-machine suggestion", () => {
        const result = inferSourceRelationship(
            { sourceId: "a", evidence: { macs: ["aa"], localIps: [] } },
            { sourceId: "b", evidence: { macs: ["aa"], localIps: ["10.0.0.1"] } },
        );
        expect(result.suggestion).toBe("same");
        expect(result.confidence).toBe("high");
        expect(result.sharedMacs).toEqual(["aa"]);
    });

    test("creates stable, source-qualified packet IDs and deterministic timeline order", () => {
        const result = mergeSessions([
            session("first", [packet({ processed: 0, timestamp: "2026-09-04 12:00:01.000000" })], {
                bookmarkList: ["10.0.0.1$1"],
                notes: [{ id: "note-1", title: "Observation", body: "first" }],
            }),
            session("second", [packet({ processed: 0, timestamp: "2026-09-04 12:00:00.000000" })]),
        ], {
            relationships: [{ sourceA: "source-", sourceB: "source-", mode: "separate" }],
        });

        const packets = Object.values(result.captureData.host).flat();
        expect(packets).toHaveLength(2);
        expect(packets[0]["packet.info"]["capture.mergeOrder"]).toBe(0);
        expect(packets[1]["packet.info"]["capture.mergeOrder"]).toBe(1);
        expect(packets[0]["packet.info"]["capture.packetId"]).not.toBe(
            packets[1]["packet.info"]["capture.packetId"],
        );
        expect(packets.every((entry) => entry.__packetKey === entry["packet.info"]["capture.packetId"])).toBe(true);
        expect(result.sessionState.merged).toBe(true);
        expect(result.metadata.timestampWarning).toMatch(/local wall-clock/i);
    });

    test("keeps sources separate by default and accepts pairwise same-machine override", () => {
        const inputs = [
            session("one", [packet({ sourceIp: "10.0.0.10", destinationIp: "10.0.0.20" })]),
            session("two", [packet({ sourceIp: "10.0.0.10", destinationIp: "10.0.0.20", mac: "aa:bb:cc:dd:ee:02" })]),
        ];
        const separate = mergeSessions(inputs);
        expect(Object.keys(separate.captureData.host)).toHaveLength(2);

        const sourceIds = separate.metadata.sources.map((source) => source.sourceId);
        const same = mergeSessions(inputs, {
            relationships: [{ sourceA: sourceIds[0], sourceB: sourceIds[1], mode: "same" }],
        });
        expect(Object.keys(same.captureData.host)).toHaveLength(1);
        expect(same.metadata.relationships[0].mode).toBe("same");
        expect(same.metadata.relationships[0].override).toBe("same");
    });

    test("applies offsets without rewriting original timestamps", () => {
        const result = mergeSessions([
            session("early", [packet({ timestamp: "2026-09-04 12:00:01.000000" })], {}),
            {
                ...session("adjusted", [packet({ timestamp: "2026-09-04 12:00:02.000000" })]),
                offsetSeconds: -2,
                offsetMilliseconds: 250,
            },
        ]);
        const packets = Object.values(result.captureData.host).flat().sort(
            (left, right) => left["packet.info"]["capture.mergeOrder"] - right["packet.info"]["capture.mergeOrder"],
        );
        expect(packets[0]["packet.info"]["capture.sourceSession"]).toBe("adjusted");
        expect(packets[0]["packet.info"]["capture.originalTimestamp"]).toBe("2026-09-04 12:00:02.000000");
        expect(packets[0]["packet.info"]["capture.offsetMs"]).toBe(-1750);
        expect(packets[0]["packet.info"]["capture.adjustedTimestampMs"]).toBe(
            parseTimestampMs("2026-09-04 12:00:02.000000") - 1750,
        );
    });

    test("remaps bookmarks and adds annotation provenance", () => {
        const annotatedPacket = packet({ processed: 0 });
        const result = mergeSessions([
            session("annotated", [annotatedPacket], {
                bookmarkList: ["10.0.0.1$0"],
                sessionKeychainEntries: [{ type: "secret", value: "abc" }],
                notes: [{ id: "n", title: "Note", body: "body" }],
                fileArtifacts: [{ id: "a", packetKey: "10.0.0.1$0", bytesBase64: "AQI=" }],
            }),
            session("plain", [packet({ processed: 1, timestamp: "2026-09-04 12:00:01.000000" })]),
        ]);
        expect(result.sessionState.bookmarkList).toHaveLength(1);
        expect(result.sessionState.bookmarkList[0]).toMatch(/^source-/);
        expect(result.sessionState.sessionKeychainEntries[0].sourceSession).toBe("annotated");
        expect(result.sessionState.notes[0].title).toBe("[annotated] Note");
        expect(result.sessionState.fileArtifacts[0].packetKey).toMatch(/^source-/);
        expect(result.sessionState.sourcePcap).toBeNull();
    });

    test("rejects fewer than two sessions", () => {
        expect(() => mergeSessions([session("only", [packet()])])).toThrow(/at least two/i);
    });

    test("preserves durable packet IDs when the merged session is merged again", () => {
        const firstMerge = mergeSessions([
            session("left", [packet({ processed: 0 })]),
            session("right", [packet({ processed: 0, timestamp: "2026-09-04 12:00:01.000000" })]),
        ]);
        const secondMerge = mergeSessions([
            {
                name: "merged",
                sessionPayload: firstMerge.json,
            },
            session("third", [packet({ processed: 0, timestamp: "2026-09-04 12:00:02.000000" })]),
        ]);
        const ids = Object.values(secondMerge.captureData.host)
            .flat()
            .map((entry) => entry["packet.info"]["capture.packetId"]);
        expect(new Set(ids).size).toBe(3);
        expect(ids.some((id) => id.includes("source-"))).toBe(true);
    });
});
