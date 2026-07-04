const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const JSONParse = require("jsonparse");
const { filterPackets, validateFilterSyntax } = require("./filter");

const CAPTURE_STORE_DIR = path.join(os.tmpdir(), "packetsnitch-capture-store");
const PACKET_CACHE_LIMIT = 64;

let activeStore = null;

function isObject(value) {
    return Boolean(value) && typeof value === "object";
}

function ensureStoreDir() {
    fs.mkdirSync(CAPTURE_STORE_DIR, { recursive: true });
}

function getPathKeys(parserContext) {
    return parserContext.stack
        .map((entry) => entry.key)
        .concat(parserContext.key)
        .filter((key) => key !== undefined);
}

function getPacketPathInfo(pathKeys) {
    if (
        pathKeys.length === 3 &&
        pathKeys[0] === "Host" &&
        typeof pathKeys[1] === "string" &&
        typeof pathKeys[2] === "number"
    ) {
        return {
            host: pathKeys[1],
            hostPacketIndex: pathKeys[2],
        };
    }

    if (
        pathKeys.length === 4 &&
        pathKeys[0] === "Capture Data" &&
        pathKeys[1] === "Host" &&
        typeof pathKeys[2] === "string" &&
        typeof pathKeys[3] === "number"
    ) {
        return {
            host: pathKeys[2],
            hostPacketIndex: pathKeys[3],
        };
    }

    return null;
}

function isFinalSummaryPath(pathKeys) {
    return (
        (pathKeys.length === 1 && pathKeys[0] === "Final Summary") ||
        (pathKeys.length === 2 &&
            pathKeys[0] === "Capture Data" &&
            pathKeys[1] === "Final Summary")
    );
}

function isSessionStatePath(pathKeys) {
    return pathKeys.length === 1 && pathKeys[0] === "Session State";
}

function derivePacketKey(packet, host, hostPacketIndex, existingKeys) {
    const packetInfo = packet?.["Packet Info"] || {};
    const sourceIp = packetInfo?.["IP"]?.["Source IP"] || host || "Unknown";
    const packetIndex = packetInfo?.["Index"] ?? hostPacketIndex;
    let candidate = `${sourceIp}:${packetIndex}`;
    if (!existingKeys.has(candidate)) return candidate;

    let dedupCounter = 1;
    while (existingKeys.has(`${candidate}-${dedupCounter}`)) {
        dedupCounter += 1;
    }
    return `${candidate}-${dedupCounter}`;
}

function buildPacketStub(packet, packetKey, host, hostPacketIndex) {
    const packetInfo = isObject(packet?.["Packet Info"])
        ? packet["Packet Info"]
        : {};
    const rawData = isObject(packetInfo["Raw data"]) ? packetInfo["Raw data"] : {};
    const payload = isObject(rawData["Payload"]) ? rawData["Payload"] : {};
    const payloadHex =
        typeof payload["Hex Encoded"] === "string" ? payload["Hex Encoded"] : "";
    const payloadBytes = payloadHex
        ? Math.floor(payloadHex.replace(/\s+/g, "").length / 2)
        : 0;

    return {
        "Packet Info": {
            ...packetInfo,
            "Raw data": {
                ...rawData,
                Payload: {
                    ...payload,
                    "Hex Encoded": "",
                },
                "Payload Length": payloadBytes,
            },
        },
        "Extra Info": isObject(packet?.["Extra Info"]) ? packet["Extra Info"] : {},
        __packetKey: packetKey,
        __host: host,
        __hostPacketIndex: hostPacketIndex,
        __packetStub: true,
    };
}

function derivePacketListSummary(packet, packetKey, host, hostPacketIndex) {
    const packetInfo = isObject(packet?.["Packet Info"]) ? packet["Packet Info"] : {};
    const extraInfo = isObject(packet?.["Extra Info"]) ? packet["Extra Info"] : {};
    const transportName = String(packetInfo?.["Protocol"] || "Unknown").toUpperCase();
    const transportData =
        isObject(packetInfo[transportName]) ? packetInfo[transportName] :
            isObject(packetInfo[transportName.toLowerCase()]) ? packetInfo[transportName.toLowerCase()] :
                {};
    const sourceIp = packetInfo?.["IP"]?.["Source IP"] || host || "Unknown";
    const destinationIp = packetInfo?.["IP"]?.["Destination IP"] || "";
    const sourcePort = transportData?.["Source port"] ?? "";
    const destinationPort = transportData?.["Destination port"] ?? "";
    const hasPorts = sourcePort !== "" && sourcePort !== undefined && sourcePort !== null &&
        destinationPort !== "" && destinationPort !== undefined && destinationPort !== null;
    const endpointA = hasPorts ? `${sourceIp}:${sourcePort}` : sourceIp;
    const endpointB = hasPorts ? `${destinationIp}:${destinationPort}` : destinationIp;
    const [firstEndpoint, secondEndpoint] = [endpointA, endpointB].sort();
    const streamKey = `${transportName}|${firstEndpoint}|${secondEndpoint}`;
    const appProtocol =
        extraInfo?.["Traits"]?.["Network Data"]?.["Port Protocol"] ||
        extraInfo?.["Traits"]?.["Network Data"]?.["Port Protcol"] ||
        packetInfo?.["Decoded Protocols"]?.[0] ||
        transportName ||
        "Unknown";

    return {
        packetKey,
        host,
        pktIdx: hostPacketIndex,
        idx: Number(packetInfo?.["Index"]) || hostPacketIndex,
        srcIp: sourceIp,
        dstIp: destinationIp,
        srcPort: sourcePort,
        dstPort: destinationPort,
        transport: transportName,
        appProto: String(appProtocol),
        payloadLength: Number(packetInfo?.["Raw data"]?.["Payload Length"]) || 0,
        streamKey,
    };
}

function compareListEntries(left, right) {
    const leftIndex = Number(left?.idx);
    const rightIndex = Number(right?.idx);
    if (Number.isFinite(leftIndex) && Number.isFinite(rightIndex) && leftIndex !== rightIndex) {
        return leftIndex - rightIndex;
    }
    if (Number.isFinite(leftIndex) && !Number.isFinite(rightIndex)) return -1;
    if (!Number.isFinite(leftIndex) && Number.isFinite(rightIndex)) return 1;
    return String(left?.packetKey || "").localeCompare(String(right?.packetKey || ""));
}

function addPacketToCache(store, packetKey, packet) {
    if (!store.packetCache.has(packetKey) && store.packetCache.size >= PACKET_CACHE_LIMIT) {
        const oldestKey = store.packetCache.keys().next().value;
        store.packetCache.delete(oldestKey);
    }
    if (store.packetCache.has(packetKey)) {
        store.packetCache.delete(packetKey);
    }
    store.packetCache.set(packetKey, packet);
}

function touchCachedPacket(store, packetKey) {
    const packet = store.packetCache.get(packetKey);
    if (!packet) return null;
    store.packetCache.delete(packetKey);
    store.packetCache.set(packetKey, packet);
    return packet;
}

function writePacketLineSync(packetDataFd, writeOffset, packet) {
    const packetJson = JSON.stringify(packet);
    const line = `${packetJson}\n`;
    const byteLength = Buffer.byteLength(line, "utf8");
    fs.writeSync(packetDataFd, line, writeOffset, "utf8");
    return {
        offset: writeOffset,
        length: byteLength,
    };
}

async function buildStoreFromSource(sourcePath) {
    ensureStoreDir();

    const storeId = `${Date.now()}-${crypto.randomBytes(6).toString("hex")}`;
    const packetDataPath = path.join(CAPTURE_STORE_DIR, `${storeId}.packets.ndjson`);
    const packetDataFd = fs.openSync(packetDataPath, "w+");

    const refsByKey = new Map();
    const hostPackets = new Map();
    const listEntries = [];
    let finalSummary = "";
    let sessionState = null;
    let writeOffset = 0;

    const parser = new JSONParse();
    parser.onValue = function onValue(value) {
        const pathKeys = getPathKeys(this);

        if (isFinalSummaryPath(pathKeys)) {
            finalSummary = typeof value === "string" ? value : "";
            return;
        }

        if (isSessionStatePath(pathKeys) && isObject(value)) {
            sessionState = value;
            return;
        }

        const packetPathInfo = getPacketPathInfo(pathKeys);
        if (!packetPathInfo || !isObject(value) || !isObject(value["Packet Info"])) {
            return;
        }

        const { host, hostPacketIndex } = packetPathInfo;
        const packetKey = derivePacketKey(value, host, hostPacketIndex, refsByKey);
        const packetStub = buildPacketStub(value, packetKey, host, hostPacketIndex);

        hostPackets.set(host, hostPackets.get(host) || []);
        hostPackets.get(host).push(packetStub);

        refsByKey.set(packetKey, {
            packetKey,
            host,
            hostPacketIndex,
            packetListIndex: hostPackets.get(host).length - 1,
            offset: -1,
            length: -1,
        });

        // Serialize packet data for on-demand random-access reads.
        const result = writePacketLineSync(packetDataFd, writeOffset, value);
        writeOffset += result.length;
        const ref = refsByKey.get(packetKey);
        if (ref) {
            ref.offset = result.offset;
            ref.length = result.length;
        }

        listEntries.push(derivePacketListSummary(value, packetKey, host, hostPacketIndex));
    };

    const stream = fs.createReadStream(sourcePath, {
        encoding: "utf8",
        highWaterMark: 1024 * 64,
    });
    await parseJsonChunks(parser, stream);

    fs.fsyncSync(packetDataFd);
    listEntries.sort(compareListEntries);

    const hostObject = {};
    hostPackets.forEach((packetList, host) => {
        hostObject[host] = packetList;
    });

    const store = {
        storeId,
        sourcePath,
        packetDataPath,
        packetDataFd,
        refsByKey,
        hostPackets,
        packetCache: new Map(),
        listEntries,
        captureData: {
            Host: hostObject,
            "Final Summary": finalSummary,
        },
        sessionState,
    };

    return store;
}

async function parseJsonChunks(parser, chunkSource) {
    let parseFailed = false;
    try {
        for await (const chunk of chunkSource) {
            if (parseFailed) break;
            try {
                parser.write(String(chunk));
            } catch (error) {
                parseFailed = true;
                throw error;
            }
        }
    } finally {
        if (chunkSource && typeof chunkSource.destroy === "function") {
            chunkSource.destroy();
        }
    }
}

async function buildStoreFromJsonText(jsonText) {
    ensureStoreDir();

    const storeId = `${Date.now()}-${crypto.randomBytes(6).toString("hex")}`;
    const packetDataPath = path.join(CAPTURE_STORE_DIR, `${storeId}.packets.ndjson`);
    const packetDataFd = fs.openSync(packetDataPath, "w+");

    const refsByKey = new Map();
    const hostPackets = new Map();
    const listEntries = [];
    let finalSummary = "";
    let sessionState = null;
    let writeOffset = 0;

    const parser = new JSONParse();
    parser.onValue = function onValue(value) {
        const pathKeys = getPathKeys(this);

        if (isFinalSummaryPath(pathKeys)) {
            finalSummary = typeof value === "string" ? value : "";
            return;
        }

        if (isSessionStatePath(pathKeys) && isObject(value)) {
            sessionState = value;
            return;
        }

        const packetPathInfo = getPacketPathInfo(pathKeys);
        if (!packetPathInfo || !isObject(value) || !isObject(value["Packet Info"])) {
            return;
        }

        const { host, hostPacketIndex } = packetPathInfo;
        const packetKey = derivePacketKey(value, host, hostPacketIndex, refsByKey);
        const packetStub = buildPacketStub(value, packetKey, host, hostPacketIndex);

        hostPackets.set(host, hostPackets.get(host) || []);
        hostPackets.get(host).push(packetStub);

        refsByKey.set(packetKey, {
            packetKey,
            host,
            hostPacketIndex,
            packetListIndex: hostPackets.get(host).length - 1,
            offset: -1,
            length: -1,
        });

        const result = writePacketLineSync(packetDataFd, writeOffset, value);
        writeOffset += result.length;
        const ref = refsByKey.get(packetKey);
        if (ref) {
            ref.offset = result.offset;
            ref.length = result.length;
        }

        listEntries.push(derivePacketListSummary(value, packetKey, host, hostPacketIndex));
    };

    await parseJsonChunks(parser, [jsonText]);

    fs.fsyncSync(packetDataFd);
    listEntries.sort(compareListEntries);

    const hostObject = {};
    hostPackets.forEach((packetList, host) => {
        hostObject[host] = packetList;
    });

    return {
        storeId,
        sourcePath: "[json-text]",
        packetDataPath,
        packetDataFd,
        refsByKey,
        hostPackets,
        packetCache: new Map(),
        listEntries,
        captureData: {
            Host: hostObject,
            "Final Summary": finalSummary,
        },
        sessionState,
    };
}

async function closeStore(store) {
    if (!store) return;
    try {
        fs.closeSync(store.packetDataFd);
    } catch {
        // Ignore close errors during replacement/cleanup.
    }
    fs.promises.rm(store.packetDataPath, { force: true }).catch(() => { });
}

async function activateStore(nextStore) {
    const previousStore = activeStore;
    activeStore = nextStore;
    await closeStore(previousStore);
}

function getActiveStoreOrThrow() {
    if (!activeStore) {
        throw new Error("No active capture store");
    }
    return activeStore;
}

async function readPacketByKey(packetKey) {
    const store = getActiveStoreOrThrow();
    const ref = store.refsByKey.get(packetKey);
    if (!ref) return null;

    const cached = touchCachedPacket(store, packetKey);
    if (cached) return cached;

    const buffer = Buffer.alloc(ref.length);
    fs.readSync(store.packetDataFd, buffer, 0, ref.length, ref.offset);
    const line = buffer.toString("utf8").trim();
    if (!line) return null;
    const parsed = JSON.parse(line);
    parsed.__packetKey = packetKey;
    addPacketToCache(store, packetKey, parsed);
    return parsed;
}

function getPacketStubByKey(packetKey) {
    const store = getActiveStoreOrThrow();
    const ref = store.refsByKey.get(packetKey);
    if (!ref) return null;
    const packetList = store.hostPackets.get(ref.host);
    if (!packetList || !packetList[ref.packetListIndex]) return null;
    return packetList[ref.packetListIndex];
}

function getListWindow(startIndex = 0, count = 100) {
    const store = getActiveStoreOrThrow();
    const safeStart = Number.isFinite(Number(startIndex)) && Number(startIndex) > 0
        ? Math.floor(Number(startIndex))
        : 0;
    const safeCount = Number.isFinite(Number(count)) && Number(count) > 0
        ? Math.floor(Number(count))
        : 100;
    const endIndex = Math.min(store.listEntries.length, safeStart + safeCount);
    return {
        totalCount: store.listEntries.length,
        startIndex: safeStart,
        rows: store.listEntries.slice(safeStart, endIndex),
    };
}

async function buildMaterializedCaptureData() {
    const store = getActiveStoreOrThrow();
    const hostObject = {};

    for (const [host, packetList] of store.hostPackets.entries()) {
        const materializedPackets = [];
        for (const packetStub of packetList) {
            const packetKey =
                packetStub && typeof packetStub.__packetKey === "string"
                    ? packetStub.__packetKey
                    : "";
            const packet = packetKey ? await readPacketByKey(packetKey) : null;
            materializedPackets.push(packet || packetStub);
        }
        hostObject[host] = materializedPackets;
    }

    return {
        Host: hostObject,
        "Final Summary": store.captureData?.["Final Summary"] || "",
    };
}

async function runFilterQueryAgainstStore(query) {
    const store = getActiveStoreOrThrow();
    const normalizedQuery = typeof query === "string" ? query.trim() : "";
    if (!normalizedQuery) {
        return Array.from(store.refsByKey.keys());
    }

    validateFilterSyntax(normalizedQuery);

    const matchedKeys = [];
    const allKeys = Array.from(store.refsByKey.keys());
    for (const packetKey of allKeys) {
        const ref = store.refsByKey.get(packetKey);
        const packet = await readPacketByKey(packetKey);
        if (!packet || !ref) continue;
        const packetContainer = {
            Host: {
                [ref.host]: [packet],
            },
        };
        const filtered = filterPackets(packetContainer, normalizedQuery);
        if (Array.isArray(filtered) && filtered.length > 0) {
            matchedKeys.push(packetKey);
        }
    }

    return matchedKeys;
}

function registerCaptureStoreHandlers(ipcMain) {
    ipcMain.handle("capture-store-load-file", async (_event, sourcePath) => {
        if (typeof sourcePath !== "string" || !sourcePath.trim()) {
            return { success: false, error: "Invalid source path" };
        }

        try {
            const store = await buildStoreFromSource(sourcePath);
            await activateStore(store);
            return {
                success: true,
                captureData: store.captureData,
                sessionState: store.sessionState,
            };
        } catch (error) {
            return {
                success: false,
                error: error?.message || "Failed to load capture",
            };
        }
    });

    ipcMain.handle("capture-store-load-json", async (_event, jsonData) => {
        if (typeof jsonData !== "string" || !jsonData.trim()) {
            return { success: false, error: "Invalid JSON data" };
        }

        try {
            const store = await buildStoreFromJsonText(jsonData);
            await activateStore(store);
            return {
                success: true,
                captureData: store.captureData,
                sessionState: store.sessionState,
            };
        } catch (error) {
            return {
                success: false,
                error: error?.message || "Failed to load JSON capture",
            };
        }
    });

    ipcMain.handle("capture-store-get-packet", async (_event, packetKey) => {
        if (typeof packetKey !== "string" || !packetKey.trim()) {
            return { success: false, error: "Invalid packet key" };
        }

        try {
            const packet = await readPacketByKey(packetKey);
            return { success: true, packet };
        } catch (error) {
            return {
                success: false,
                error: error?.message || "Unable to read packet",
            };
        }
    });

    ipcMain.handle("capture-store-get-packet-stub", async (_event, packetKey) => {
        if (typeof packetKey !== "string" || !packetKey.trim()) {
            return { success: false, error: "Invalid packet key" };
        }

        try {
            const packet = getPacketStubByKey(packetKey);
            return { success: true, packet };
        } catch (error) {
            return {
                success: false,
                error: error?.message || "Unable to read packet stub",
            };
        }
    });

    ipcMain.handle("capture-store-get-list-window", async (_event, request) => {
        try {
            const startIndex = request && typeof request === "object" ? request.startIndex : 0;
            const count = request && typeof request === "object" ? request.count : 100;
            const windowData = getListWindow(startIndex, count);
            return {
                success: true,
                ...windowData,
            };
        } catch (error) {
            return {
                success: false,
                error: error?.message || "Unable to read packet list window",
                totalCount: 0,
                startIndex: 0,
                rows: [],
            };
        }
    });

    ipcMain.handle("capture-store-export-session-data", async () => {
        try {
            const store = getActiveStoreOrThrow();
            const captureData = await buildMaterializedCaptureData();
            return {
                success: true,
                captureData,
                sessionState: store.sessionState,
            };
        } catch (error) {
            return {
                success: false,
                error: error?.message || "Unable to export session data",
            };
        }
    });

    ipcMain.handle("capture-store-filter", async (_event, query) => {
        try {
            const packetKeys = await runFilterQueryAgainstStore(query);
            return { success: true, packetKeys };
        } catch (error) {
            return {
                success: false,
                error: error?.message || "Filter execution failed",
                packetKeys: [],
            };
        }
    });
}

module.exports = {
    registerCaptureStoreHandlers,
};
