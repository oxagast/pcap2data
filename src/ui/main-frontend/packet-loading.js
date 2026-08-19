// Loads backend packet snapshots into renderer state and incremental ingest flows.

function createPacketLoadingHelpers({
    state,
    backendProgressState,
    getBackendPacketChunkSize,
    isFrontendIngestThreadingEnabled,
    getFrontendIngestWorkerThreads,
    getBackendIncrementalRefreshMinPackets,
    getBackendIncrementalRefreshMinIntervalMs,
    createWorker,
}) {
    function normalizeBackendJsonPathPayload(rawPayload) {
        if (typeof rawPayload === "string") {
            return {
                path: rawPayload,
                jobId: "",
                processedPackets: 0,
                totalPackets: 0,
                complete: true,
                chunkSize: getBackendPacketChunkSize(),
            };
        }

        if (!rawPayload || typeof rawPayload !== "object") {
            return null;
        }

        return {
            path: typeof rawPayload.path === "string" ? rawPayload.path : "",
            jobId:
                typeof rawPayload.jobId === "string" && rawPayload.jobId.trim()
                    ? rawPayload.jobId.trim()
                    : "",
            processedPackets: Number(rawPayload.processedPackets) || 0,
            totalPackets: Number(rawPayload.totalPackets) || 0,
            complete: Boolean(rawPayload.complete),
            chunkSize: Number(rawPayload.chunkSize) || getBackendPacketChunkSize(),
        };
    }

    function normalizeBackendJsonDataPayload(rawPayload) {
        if (!rawPayload || typeof rawPayload !== "object") {
            return null;
        }

        const captureData =
            rawPayload.captureData && typeof rawPayload.captureData === "object"
                ? rawPayload.captureData
                : null;
        if (!captureData) {
            return null;
        }

        return {
            captureData,
            jobId:
                typeof rawPayload.jobId === "string" && rawPayload.jobId.trim()
                    ? rawPayload.jobId.trim()
                    : "",
            processedPackets: Number(rawPayload.processedPackets) || 0,
            totalPackets: Number(rawPayload.totalPackets) || 0,
            complete: Boolean(rawPayload.complete),
            chunkSize: Number(rawPayload.chunkSize) || getBackendPacketChunkSize(),
            label:
                typeof rawPayload.label === "string" && rawPayload.label.trim()
                    ? rawPayload.label.trim()
                    : "in-memory-snapshot",
        };
    }

    function createFrontendBackendJobId() {
        return `frontend-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
    }

    function shouldAcceptBackendPayloadForActiveJob(payload) {
        const payloadJobId = String(payload?.jobId || "").trim();
        if (!payloadJobId) {
            return true;
        }
        if (!state.activeBackendJobId) {
            state.activeBackendJobId = payloadJobId;
            return true;
        }
        return payloadJobId === state.activeBackendJobId;
    }

    function countCaptureDataPackets(captureData) {
        if (!captureData || typeof captureData !== "object") return 0;
        const hostMap = captureData["host"];
        if (!hostMap || typeof hostMap !== "object") return 0;
        return Object.values(hostMap).reduce((total, hostPackets) => {
            if (!Array.isArray(hostPackets)) return total;
            return total + hostPackets.length;
        }, 0);
    }

    function hasAnyCaptureDataPackets(captureData) {
        if (!captureData || typeof captureData !== "object") return false;
        const hostMap = captureData["host"];
        if (!hostMap || typeof hostMap !== "object") return false;
        return Object.values(hostMap).some(
            (hostPackets) => Array.isArray(hostPackets) && hostPackets.length > 0,
        );
    }

    function createCaptureIngestWorker() {
        if (typeof Worker !== "function") {
            return null;
        }

        try {
            return createWorker();
        } catch (error) {
            console.warn("Failed to initialize capture ingest worker:", error);
            return null;
        }
    }

    function terminateCaptureIngestWorkers(reason = "disabled") {
        state.pendingCaptureIngestWorkerRequests.forEach(({ reject }) => {
            reject(new Error(`Capture ingest worker stopped: ${reason}`));
        });
        state.pendingCaptureIngestWorkerRequests.clear();

        state.captureIngestWorkers.forEach((worker) => {
            try {
                worker.terminate();
            } catch {
                // no-op
            }
        });
        state.captureIngestWorkers = [];
        state.captureIngestWorkerThreadCount = 0;
        state.captureIngestWorkerCursor = 0;
    }

    function wireCaptureIngestWorker(worker) {
        worker.onmessage = (event) => {
            const payload = event?.data || {};
            const requestId = Number(payload.id);
            if (!requestId || !state.pendingCaptureIngestWorkerRequests.has(requestId)) {
                return;
            }

            const pendingRequest = state.pendingCaptureIngestWorkerRequests.get(requestId);
            state.pendingCaptureIngestWorkerRequests.delete(requestId);

            if (!pendingRequest) {
                return;
            }

            if (payload.ok) {
                pendingRequest.resolve(payload.result || null);
                return;
            }

            pendingRequest.reject(
                new Error(
                    typeof payload.error === "string" && payload.error
                        ? payload.error
                        : "Capture ingest worker failed",
                ),
            );
        };

        worker.onerror = (error) => {
            console.warn("Capture ingest worker crashed, switching to fallback path:", error);
            terminateCaptureIngestWorkers("crash");
        };
    }

    function ensureCaptureIngestWorkers() {
        if (!isFrontendIngestThreadingEnabled()) {
            if (state.captureIngestWorkers.length > 0) {
                terminateCaptureIngestWorkers("threading-disabled");
            }
            return [];
        }

        const targetThreadCount = getFrontendIngestWorkerThreads();
        if (
            state.captureIngestWorkers.length === targetThreadCount
            && state.captureIngestWorkerThreadCount === targetThreadCount
        ) {
            return state.captureIngestWorkers;
        }

        if (state.captureIngestWorkers.length > 0) {
            terminateCaptureIngestWorkers("reconfigure");
        }

        const nextWorkers = [];
        for (let index = 0; index < targetThreadCount; index += 1) {
            const worker = createCaptureIngestWorker();
            if (!worker) {
                terminateCaptureIngestWorkers("create-failed");
                return [];
            }
            wireCaptureIngestWorker(worker);
            nextWorkers.push(worker);
        }

        state.captureIngestWorkers = nextWorkers;
        state.captureIngestWorkerThreadCount = targetThreadCount;
        state.captureIngestWorkerCursor = 0;
        return state.captureIngestWorkers;
    }

    function syncCaptureIngestWorkersFromSettings() {
        ensureCaptureIngestWorkers();
    }

    function requestCaptureIngestWorker(action, payload) {
        const workerPool = ensureCaptureIngestWorkers();
        if (!workerPool.length) {
            return Promise.resolve(null);
        }

        state.captureIngestWorkerCursor =
            (state.captureIngestWorkerCursor + 1) % workerPool.length;
        const worker = workerPool[state.captureIngestWorkerCursor];

        return new Promise((resolve, reject) => {
            state.captureIngestWorkerRequestId += 1;
            const requestId = state.captureIngestWorkerRequestId;
            state.pendingCaptureIngestWorkerRequests.set(requestId, { resolve, reject });

            try {
                worker.postMessage({
                    id: requestId,
                    action,
                    payload,
                });
            } catch (error) {
                state.pendingCaptureIngestWorkerRequests.delete(requestId);
                reject(error);
            }
        });
    }

    async function serializeCaptureDataForBackendLoad(captureData) {
        try {
            const workerResult = await requestCaptureIngestWorker("serialize-capture-data", {
                captureData,
            });
            if (workerResult && typeof workerResult.serializedCaptureData === "string") {
                return workerResult.serializedCaptureData;
            }
        } catch (error) {
            console.warn("Falling back to main-thread capture serialization:", error);
        }

        return JSON.stringify(captureData);
    }

    // Light packet key for incremental staging — mirrors getPacketKey in
    // capture-ingest-worker.js. Only touches __packetKey, ip.src.addr and
    // index so we never need to structured-clone the full packet body.
    function stagePacketKey(packet, fallbackHost, fallbackIndex) {
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

    // Inline equivalent of the worker's stage-incremental-packets action.
    // Runs on the renderer thread but only walks each host once and reads
    // ~3 fields per packet — much cheaper than a postMessage round-trip
    // that structured-clones the entire host map (16k+ nested objects).
    function buildIncrementalPacketPlan(nextHostMap, previousHostMap, previousRealHosts) {
        const previousHostPacketCounts = {};
        Object.keys(previousHostMap || {}).forEach((host) => {
            const previousHostPackets = Array.isArray(previousHostMap[host])
                ? previousHostMap[host]
                : [];
            previousHostPacketCounts[host] = previousHostPackets.length;
        });

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
                const packetKey = stagePacketKey(packet, host, packetIndex);
                newPacketRefs.push({ host, packetIndex, packetKey });
            }
        });

        return { nextHosts, hostSetChanged, newPacketRefs };
    }

    async function stageIncrementalCapturePacketsInWorker(
        nextHostMap,
        previousHostMap,
        previousRealHosts,
    ) {
        // Compute the plan inline. We used to postMessage the full
        // nextHostMap to capture-ingest-worker.js, but the worker returned
        // only packet keys — the structured-clone of the full objects
        // dwarfed the worker's compute. Doing it inline is orders of
        // magnitude cheaper at ingest scales.
        return Promise.resolve(
            buildIncrementalPacketPlan(nextHostMap || {}, previousHostMap || {}, previousRealHosts || []),
        );
    }

    function shouldReplacePendingBackendCaptureUpdate(currentUpdate, nextUpdate) {
        if (!currentUpdate) return true;
        if (!nextUpdate) return false;

        const currentComplete = Boolean(currentUpdate.payload?.complete);
        const nextComplete = Boolean(nextUpdate.payload?.complete);
        if (currentComplete !== nextComplete) {
            return nextComplete;
        }

        const currentProcessed = Number(currentUpdate.payload?.processedPackets) || 0;
        const nextProcessed = Number(nextUpdate.payload?.processedPackets) || 0;
        if (currentProcessed !== nextProcessed) {
            return nextProcessed > currentProcessed;
        }

        const currentTotal = Number(currentUpdate.payload?.totalPackets) || 0;
        const nextTotal = Number(nextUpdate.payload?.totalPackets) || 0;
        if (currentTotal !== nextTotal) {
            return nextTotal > currentTotal;
        }

        return true;
    }

    function shouldApplyIncrementalBackendSnapshot(payload) {
        if (!backendProgressState.firstChunkLoaded || payload?.complete) {
            return true;
        }

        const processedPackets = Number(payload?.processedPackets) || 0;
        const packetThreshold = Math.max(
            (Number(payload?.chunkSize) || getBackendPacketChunkSize()) * 8,
            getBackendIncrementalRefreshMinPackets(),
        );
        const packetDelta = Math.max(
            0,
            processedPackets - state.backendLastAppliedSnapshotProcessedPackets,
        );
        const elapsedMs = Math.max(0, performance.now() - state.backendLastAppliedSnapshotAtMs);

        return (
            packetDelta >= packetThreshold
            || elapsedMs >= getBackendIncrementalRefreshMinIntervalMs()
        );
    }

    function markAppliedBackendSnapshot(payload) {
        state.backendLastAppliedSnapshotProcessedPackets =
            Number(payload?.processedPackets) || 0;
        state.backendLastAppliedSnapshotAtMs = performance.now();
    }

    return {
        normalizeBackendJsonPathPayload,
        normalizeBackendJsonDataPayload,
        createFrontendBackendJobId,
        shouldAcceptBackendPayloadForActiveJob,
        countCaptureDataPackets,
        hasAnyCaptureDataPackets,
        createCaptureIngestWorker,
        terminateCaptureIngestWorkers,
        wireCaptureIngestWorker,
        ensureCaptureIngestWorkers,
        syncCaptureIngestWorkersFromSettings,
        requestCaptureIngestWorker,
        serializeCaptureDataForBackendLoad,
        stageIncrementalCapturePacketsInWorker,
        shouldReplacePendingBackendCaptureUpdate,
        shouldApplyIncrementalBackendSnapshot,
        markAppliedBackendSnapshot,
    };
}

module.exports = {
    createPacketLoadingHelpers,
};