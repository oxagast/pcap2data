// Stages incremental capture packet references off the main thread during ingest.

function getPacketKey(packet, fallbackHost, fallbackIndex) {
    if (packet && typeof packet.__packetKey === "string" && packet.__packetKey) {
        return packet.__packetKey;
    }

    const packetInfo = packet && typeof packet === "object" ? packet["packet.info"] : null;
    const packetIpInfo = packetInfo && typeof packetInfo === "object" ? packetInfo["IP"] : null;
    const sourceIp =
        (packetIpInfo && (packetIpInfo["ip.src.addr"] || packetIpInfo["Source IP"]))
        || fallbackHost
        || "Unknown";
    const packetIndex =
        (packetInfo && (packetInfo["index"] ?? packetInfo["Index"])) ?? fallbackIndex;

    return String(sourceIp) + ":" + String(packetIndex);
}

function stageIncrementalPackets(payload) {
    const nextHostMap = payload && typeof payload.nextHostMap === "object"
        ? payload.nextHostMap
        : {};
    const previousHostPacketCounts =
        payload && typeof payload.previousHostPacketCounts === "object"
            ? payload.previousHostPacketCounts
            : {};
    const previousRealHosts = Array.isArray(payload?.previousRealHosts)
        ? payload.previousRealHosts
        : [];

    const nextHosts = Object.keys(nextHostMap);
    const previousHostSet = new Set(previousRealHosts);
    const hostSetChanged =
        nextHosts.length !== previousRealHosts.length
        || nextHosts.some((host) => !previousHostSet.has(host));

    const newPacketRefs = [];
    nextHosts.forEach((host) => {
        const hostPackets = Array.isArray(nextHostMap[host]) ? nextHostMap[host] : [];
        const previousCount = Number(previousHostPacketCounts[host]) || 0;
        const startIndex = Math.min(previousCount, hostPackets.length);

        for (let packetIndex = startIndex; packetIndex < hostPackets.length; packetIndex += 1) {
            const packet = hostPackets[packetIndex];
            const packetKey = getPacketKey(packet, host, packetIndex);
            newPacketRefs.push({
                host,
                packetIndex,
                packetKey,
            });
        }
    });

    return {
        nextHosts,
        hostSetChanged,
        newPacketRefs,
    };
}

self.onmessage = (event) => {
    const data = event && event.data ? event.data : {};
    const requestId = Number(data.id);
    const action = data.action;

    if (!requestId || !action) {
        return;
    }

    try {
        if (action === "serialize-capture-data") {
            const captureData = data.payload?.captureData;
            const serializedCaptureData = JSON.stringify(captureData || {});
            self.postMessage({
                id: requestId,
                ok: true,
                result: { serializedCaptureData },
            });
            return;
        }

        if (action === "stage-incremental-packets") {
            const result = stageIncrementalPackets(data.payload || {});
            self.postMessage({
                id: requestId,
                ok: true,
                result,
            });
            return;
        }

        self.postMessage({
            id: requestId,
            ok: false,
            error: "Unknown capture ingest worker action",
        });
    } catch (error) {
        self.postMessage({
            id: requestId,
            ok: false,
            error: error && error.message ? error.message : String(error),
        });
    }
};
