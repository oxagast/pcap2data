const { createStreamHelpers } = require('../src/ui/main-frontend/stream-helpers');

function makePacketStub(packetKey, streamKey) {
    return {
        __packetKey: packetKey,
        __packetStub: true,
        'packet.info': {
            streamKey,
            'Raw data': {
                Payload: {},
            },
        },
    };
}

function makeHydratedPacket(packetKey, streamKey, payloadHex) {
    return {
        __packetKey: packetKey,
        __packetStub: false,
        'packet.info': {
            streamKey,
            'Raw data': {
                Payload: {
                    'payload.hex': payloadHex,
                },
            },
        },
    };
}

describe('stream helper hydration lifecycle', () => {
    test('switching active streams dehydrates packets from the previous stream', async () => {
        const hydratedPacketCache = new Map();
        const streamPacketHydrationCache = new Map();
        const streamPayloadHexCache = new Map();
        const stubA1 = makePacketStub('hostA:0', 'stream-a');
        const stubA2 = makePacketStub('hostA:1', 'stream-a');
        const stubB1 = makePacketStub('hostA:2', 'stream-b');
        const hostPackets = [stubA1, stubA2, stubB1];
        const capturedPackets = {
            Host: {
                hostA: hostPackets,
            },
        };
        const filteredPackets = hostPackets.slice();
        const packetStubsByKey = new Map([
            ['hostA:0', stubA1],
            ['hostA:1', stubA2],
            ['hostA:2', stubB1],
        ]);
        const hydratedPacketsByKey = new Map([
            ['hostA:0', makeHydratedPacket('hostA:0', 'stream-a', 'aa')],
            ['hostA:1', makeHydratedPacket('hostA:1', 'stream-a', 'bb')],
            ['hostA:2', makeHydratedPacket('hostA:2', 'stream-b', 'cc')],
        ]);

        let helpers;
        const dehydratePacket = (packetKey, packetStub) => {
            if (!packetKey || !packetStub) return;
            if (typeof packetStub === 'object') {
                packetStub.__packetKey = packetKey;
                packetStub.__packetStub = true;
            }
            hydratedPacketCache.delete(packetKey);
            helpers.updatePacketInCollections(packetKey, packetStub);
        };

        helpers = createStreamHelpers({
            state: {
                hydratedPacketCache,
                streamPacketHydrationCache,
                streamPayloadHexCache,
                streamPayloadHexCacheLimit: 8,
            },
            getPacketKey: (packet) => packet?.__packetKey || '',
            buildBidirectionalStreamKey: (packetInfo) => packetInfo?.streamKey || '',
            yieldToRenderer: async () => { },
            ensureHydratedPacketCached: (packetKey, packet) => {
                hydratedPacketCache.set(packetKey, packet);
            },
            resolvePacketStubByKey: async (packetKey) => packetStubsByKey.get(packetKey) || null,
            dehydratePacket,
            logErrorEntry: () => { },
            getCapturedPackets: () => capturedPackets,
            getFilteredPackets: () => filteredPackets,
            getPacketsForHost: () => hostPackets,
            getCaptureApi: () => ({
                getPacket: async (packetKey) => ({
                    success: true,
                    packet: hydratedPacketsByKey.get(packetKey),
                }),
            }),
        });

        await helpers.warmStreamPacketHydrationCache('stream-a', [
            { packet: stubA1, host: 'hostA', packetIndex: 0 },
            { packet: stubA2, host: 'hostA', packetIndex: 1 },
        ]);
        helpers.setStreamPayloadHexCache('stream-a|2|hostA:0|hostA:1', 'aabb');

        expect(hostPackets[0].__packetStub).toBe(false);
        expect(hostPackets[1].__packetStub).toBe(false);
        expect(streamPacketHydrationCache.has('stream-a')).toBe(true);

        await helpers.warmStreamPacketHydrationCache('stream-b', [
            { packet: stubB1, host: 'hostA', packetIndex: 2 },
        ]);

        expect(hostPackets[0]).toBe(stubA1);
        expect(hostPackets[1]).toBe(stubA2);
        expect(hostPackets[0].__packetStub).toBe(true);
        expect(hostPackets[1].__packetStub).toBe(true);
        expect(hostPackets[2].__packetStub).toBe(false);
        expect(streamPacketHydrationCache.has('stream-a')).toBe(false);
        expect(streamPacketHydrationCache.has('stream-b')).toBe(true);
        expect(streamPayloadHexCache.has('stream-a|2|hostA:0|hostA:1')).toBe(false);
    });
});