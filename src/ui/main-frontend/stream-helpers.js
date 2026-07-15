function createStreamHelpers({
    state,
    getPacketKey,
    buildBidirectionalStreamKey,
    yieldToRenderer,
    ensureHydratedPacketCached,
    logErrorEntry,
    getCapturedPackets,
    getFilteredPackets,
    getPacketsForHost,
    getCaptureApi,
}) {
    function clearStreamPacketHydrationCache() {
        state.streamPacketHydrationCache.clear();
        state.streamPayloadHexCache.clear();
    }

    function buildStreamPayloadHexCacheKey(streamPackets) {
        if (!Array.isArray(streamPackets) || streamPackets.length === 0) {
            return "";
        }
        const firstPacket = streamPackets[0];
        const lastPacket = streamPackets[streamPackets.length - 1];
        const firstPacketKey = getPacketKey(firstPacket, "", 0);
        const lastPacketKey = getPacketKey(lastPacket, "", streamPackets.length - 1);
        const packetInfo = firstPacket?.["packet.info"] || {};
        const streamKey = buildBidirectionalStreamKey(packetInfo) || "unknown-stream";
        return `${streamKey}|${streamPackets.length}|${firstPacketKey}|${lastPacketKey}`;
    }

    function setStreamPayloadHexCache(cacheKey, payloadHex) {
        if (!cacheKey || typeof payloadHex !== "string") {
            return;
        }
        if (state.streamPayloadHexCache.has(cacheKey)) {
            state.streamPayloadHexCache.delete(cacheKey);
        }
        state.streamPayloadHexCache.set(cacheKey, payloadHex);
        while (state.streamPayloadHexCache.size > state.streamPayloadHexCacheLimit) {
            const oldestKey = state.streamPayloadHexCache.keys().next().value;
            if (!oldestKey) break;
            state.streamPayloadHexCache.delete(oldestKey);
        }
    }

    async function warmStreamPacketHydrationCache(streamKey, streamPacketRefs) {
        if (!streamKey || !Array.isArray(streamPacketRefs) || streamPacketRefs.length === 0) {
            return [];
        }

        const cachedStreamPackets = state.streamPacketHydrationCache.get(streamKey);
        if (Array.isArray(cachedStreamPackets)) {
            return cachedStreamPackets;
        }
        if (cachedStreamPackets) {
            return cachedStreamPackets;
        }

        const hydrationPromise = (async () => {
            await yieldToRenderer();
            const hydratedPackets = await Promise.all(
                streamPacketRefs.map(({ packet, host, packetIndex }) =>
                    ensurePacketHydrated(packet, host, packetIndex),
                ),
            );
            const resolvedPackets = hydratedPackets.filter(Boolean);
            state.streamPacketHydrationCache.set(streamKey, resolvedPackets);
            return resolvedPackets;
        })().catch((error) => {
            logErrorEntry("stream-packet-hydration", error);
            state.streamPacketHydrationCache.delete(streamKey);
            return [];
        });

        state.streamPacketHydrationCache.set(streamKey, hydrationPromise);
        return hydrationPromise;
    }

    function updatePacketInCollections(packetKey, packet) {
        if (!packetKey || !packet) return;
        const hosts = getCapturedPackets()?.Host || {};
        for (const host of Object.keys(hosts)) {
            const packetList = hosts[host];
            if (!Array.isArray(packetList)) continue;
            const packetIndex = packetList.findIndex(
                (entry) => getPacketKey(entry, host) === packetKey,
            );
            if (packetIndex >= 0) {
                packetList[packetIndex] = packet;
                break;
            }
        }

        const filteredPackets = getFilteredPackets();
        if (Array.isArray(filteredPackets)) {
            const filteredIndex = filteredPackets.findIndex(
                (entry) => getPacketKey(entry) === packetKey,
            );
            if (filteredIndex >= 0) {
                filteredPackets[filteredIndex] = packet;
            }
        }

        const hostPackets = getPacketsForHost();
        if (Array.isArray(hostPackets)) {
            const packetIndex = hostPackets.findIndex((entry) => getPacketKey(entry) === packetKey);
            if (packetIndex >= 0) {
                hostPackets[packetIndex] = packet;
            }
        }
    }

    async function ensurePacketHydrated(packet, fallbackHost = "", fallbackIndex = 0) {
        if (!packet) return null;
        const packetKey = getPacketKey(packet, fallbackHost, fallbackIndex);
        if (!packetKey) return packet;

        const payloadHex =
            packet?.["packet.info"]?.["Raw data"]?.["Payload"]?.["payload.hex"] ??
            packet?.["packet.info"]?.["Raw data"]?.["Payload"]?.["Hex Encoded"];
        if (typeof payloadHex === "string" && payloadHex.length > 0) {
            ensureHydratedPacketCached(packetKey, packet);
            return packet;
        }

        if (state.hydratedPacketCache.has(packetKey)) {
            return state.hydratedPacketCache.get(packetKey);
        }

        const captureApi = getCaptureApi();
        if (!captureApi) {
            return packet;
        }

        const result = await captureApi.getPacket(packetKey);
        if (!result?.success || !result.packet) {
            return packet;
        }

        const hydrated = {
            ...result.packet,
            __packetKey: packetKey,
            __packetStub: false,
        };
        ensureHydratedPacketCached(packetKey, hydrated);
        updatePacketInCollections(packetKey, hydrated);
        return hydrated;
    }

    return {
        clearStreamPacketHydrationCache,
        buildStreamPayloadHexCacheKey,
        setStreamPayloadHexCache,
        warmStreamPacketHydrationCache,
        updatePacketInCollections,
        ensurePacketHydrated,
    };
}

module.exports = {
    createStreamHelpers,
};