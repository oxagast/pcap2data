// Stores capture packet stubs and serves windowed packet access for large sessions.

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const JSONParse = require("jsonparse");
const { filterPackets, validateFilterSyntax } = require("./filter");

const CAPTURE_STORE_DIR = path.join(os.tmpdir(), "packetsnitch-capture-store");
const PACKET_CACHE_LIMIT = 64;
const PACKET_KEY_SEPARATOR = "$";

let activeStore = null;

function isObject(value) {
    return Boolean(value) && typeof value === "object";
}

function normalizeIpCandidate(value) {
    if (value === null || value === undefined) return "";
    const normalized = String(value).trim();
    if (!normalized) return "";
    if (normalized.toLowerCase() === "n/a") return "";
    return normalized;
}

function extractPacketIpAddress(packetInfo, direction) {
    const normalizedDirection = String(direction || "").toLowerCase() === "dst"
        ? "dst"
        : "src";
    const sourceCandidates = [
        packetInfo?.["IP"]?.["ip.src.addr"],
        packetInfo?.["IP"]?.["network.ip.src.addr"],
        packetInfo?.["IP"]?.["Source IP"],
        packetInfo?.["ip"]?.["ip.src.addr"],
        packetInfo?.["ip"]?.["network.ip.src.addr"],
        packetInfo?.["ip"]?.["source.ip"],
        packetInfo?.["ip.src.addr"],
        packetInfo?.["network.ip.src.addr"],
        packetInfo?.["source.ip"],
        packetInfo?.["Source IP"],
    ];
    const destinationCandidates = [
        packetInfo?.["IP"]?.["ip.dst.addr"],
        packetInfo?.["IP"]?.["network.ip.dst.addr"],
        packetInfo?.["IP"]?.["Destination IP"],
        packetInfo?.["ip"]?.["ip.dst.addr"],
        packetInfo?.["ip"]?.["network.ip.dst.addr"],
        packetInfo?.["ip"]?.["destination.ip"],
        packetInfo?.["ip.dst.addr"],
        packetInfo?.["network.ip.dst.addr"],
        packetInfo?.["destination.ip"],
        packetInfo?.["Destination IP"],
    ];
    const candidates = normalizedDirection === "dst"
        ? destinationCandidates
        : sourceCandidates;
    for (const candidate of candidates) {
        const normalized = normalizeIpCandidate(candidate);
        if (normalized) return normalized;
    }
    return "";
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
        pathKeys[0] === "host" &&
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
        pathKeys[0] === "capture.data" &&
        pathKeys[1] === "host" &&
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
        (pathKeys.length === 1 && pathKeys[0] === "final.summary") ||
        (pathKeys.length === 2 &&
            pathKeys[0] === "capture.data" &&
            pathKeys[1] === "final.summary")
    );
}

function isSessionStatePath(pathKeys) {
    return pathKeys.length === 1 && pathKeys[0] === "session.state";
}

function derivePacketKey(packet, host, hostPacketIndex, existingKeys) {
    const packetInfo = packet?.["packet.info"] || {};
    const sourceIp = extractPacketIpAddress(packetInfo, "src") || host || "Unknown";
    const packetIndex = packetInfo?.["index"] ?? hostPacketIndex;
    let candidate = `${sourceIp}${PACKET_KEY_SEPARATOR}${packetIndex}`;
    if (!existingKeys.has(candidate)) return candidate;

    let dedupCounter = 1;
    while (existingKeys.has(`${candidate}-${dedupCounter}`)) {
        dedupCounter += 1;
    }
    return `${candidate}-${dedupCounter}`;
}

function buildPacketStub(packet, packetKey, host, hostPacketIndex) {
    const packetInfo = isObject(packet?.["packet.info"])
        ? packet["packet.info"]
        : {};
    const rawData = isObject(packetInfo["raw.data"]) ? packetInfo["raw.data"] : {};
    const payload = isObject(rawData["payload"]) ? rawData["payload"] : {};
    const payloadHex =
        typeof rawData["payload.len"] === "number"
            ? null
            : typeof payload["payload.hex"] === "string"
                ? payload["payload.hex"]
                : typeof payload["hex.encoded"] === "string"
                    ? payload["hex.encoded"]
                    : typeof payload["hex"] === "string"
                        ? payload["hex"]
                        : typeof rawData["payload.hex"] === "string"
                            ? rawData["payload.hex"]
                            : typeof rawData["payload.hex.encoded"] === "string"
                                ? rawData["payload.hex.encoded"]
                                : "";
    const payloadBytes = payloadHex
        ? Math.floor(payloadHex.replace(/\s+/g, "").length / 2)
        : Number(rawData["payload.len"]) || 0;

    return {
        "packet.info": {
            ...packetInfo,
            "raw.data": {
                ...rawData,
                payload: {
                    ...payload,
                    "hex.encoded": "",
                },
                "payload.len": payloadBytes,
            },
        },
        "extra.info": isObject(packet?.["extra.info"]) ? packet["extra.info"] : {},
        __packetKey: packetKey,
        __host: host,
        __hostPacketIndex: hostPacketIndex,
        __packetStub: true,
    };
}

function isUnknownLikeProtocol(value) {
    if (value === null || value === undefined) return true;
    const normalized = String(value).trim().toLowerCase();
    return (
        normalized === "" ||
        normalized === "unknown" ||
        normalized === "n/a" ||
        normalized === "na" ||
        normalized === "none" ||
        normalized === "unavailable" ||
        normalized === "null"
    );
}

function collectDecodedProtocolNames(packetInfo) {
    const decodedNames = new Set();
    const packetDecodedValues = [
        packetInfo?.["packet.decoded_protocols"],
        packetInfo?.["decoded.protocols"],
        packetInfo?.["Decoded Protocols"],
    ];

    packetDecodedValues.forEach((packetDecoded) => {
        if (Array.isArray(packetDecoded)) {
            packetDecoded.forEach((name) => {
                if (typeof name === "string" && name.trim()) {
                    decodedNames.add(name.trim());
                }
            });
            return;
        }
        if (typeof packetDecoded === "string" && packetDecoded.trim()) {
            decodedNames.add(packetDecoded.trim());
        }
    });

    return [...decodedNames];
}

function formatLayerOnlyLabel(baseLabel, layerName) {
    const normalizedBase = String(baseLabel ?? "").trim();
    const normalizedLayer = String(layerName ?? "").trim();
    if (!normalizedBase) return "";
    if (!normalizedLayer) return normalizedBase;
    return `${normalizedBase} (${normalizedLayer} Only)`;
}

function normalizeGenericApplicationProtocolLabel(label, transportName) {
    const normalizedLabel = String(label ?? "").trim();
    const normalizedTransport = String(transportName ?? "").trim().toUpperCase();
    if (!normalizedLabel) return "";

    if (normalizedLabel.toUpperCase() === "TCP" || normalizedTransport === "TCP" && normalizedLabel.toUpperCase() === normalizedTransport) {
        return formatLayerOnlyLabel("TCP", "Transport");
    }
    if (normalizedLabel.toUpperCase() === "UDP" || normalizedTransport === "UDP" && normalizedLabel.toUpperCase() === normalizedTransport) {
        return formatLayerOnlyLabel("UDP", "Transport");
    }
    if (normalizedLabel.toUpperCase() === "SCTP" || normalizedTransport === "SCTP" && normalizedLabel.toUpperCase() === normalizedTransport) {
        return formatLayerOnlyLabel("SCTP", "Transport");
    }
    if (normalizedLabel.toUpperCase() === "ICMP" || normalizedTransport === "ICMP" && normalizedLabel.toUpperCase() === normalizedTransport) {
        return formatLayerOnlyLabel("ICMP", "Network");
    }
    if (normalizedLabel.toUpperCase() === "IGMP" || normalizedTransport === "IGMP" && normalizedLabel.toUpperCase() === normalizedTransport) {
        return formatLayerOnlyLabel("IGMP", "Network");
    }
    if (normalizedLabel.toUpperCase() === "LINK") {
        return formatLayerOnlyLabel("LINK", "Link");
    }
    if (normalizedLabel.toUpperCase() === "FRAME") {
        return formatLayerOnlyLabel("FRAME", "Link");
    }
    if (normalizedLabel.toUpperCase() === "IP" || normalizedLabel.toUpperCase() === "UNDECODABLE") {
        return formatLayerOnlyLabel("IP", "Network");
    }

    return normalizedLabel;
}

function getPacketPayloadLength(packetInfo) {
    const payloadLength = Number(
        packetInfo?.["raw.data"]?.["payload.len"] ??
        packetInfo?.["Raw data"]?.["payload.len"] ??
        packetInfo?.["Raw data"]?.["Payload Length"]
    );
    if (!Number.isFinite(payloadLength) || payloadLength < 0) return 0;
    return Math.floor(payloadLength);
}

function getPacketPayloadHex(packetInfo) {
    const payloadHexCandidates = [
        packetInfo?.["raw.data"]?.["payload"]?.["payload.hex"],
        packetInfo?.["raw.data"]?.["payload"]?.["hex.encoded"],
        packetInfo?.["raw.data"]?.["payload.hex"],
        packetInfo?.["raw.data"]?.["payload.hex.encoded"],
        packetInfo?.["Raw data"]?.["Payload"]?.["payload.hex"],
        packetInfo?.["Raw data"]?.["Payload"]?.["Hex Encoded"],
        packetInfo?.["Raw data"]?.["Payload"]?.["hex.encoded"],
        packetInfo?.["Raw data"]?.["payload.hex"],
        packetInfo?.["Raw data"]?.["payload.hex.encoded"],
    ];

    for (const candidate of payloadHexCandidates) {
        if (typeof candidate === "string" && candidate.replace(/\s+/g, "").length > 0) {
            return candidate;
        }
    }
    return "";
}

function inferZeroPayloadProtocolLabel(packetInfo, transportName, transportData) {
    if (transportName === "TCP") {
        const tcpFlags = String(
            transportData?.["tcp.flags"] ??
            transportData?.["transport.tcp.flags"] ??
            transportData?.["TCP Flag Data"]?.["Flags"] ??
            ""
        ).trim();
        if (tcpFlags && tcpFlags.toLowerCase() !== "none") {
            return formatLayerOnlyLabel(
                `TCP ${tcpFlags.replace(/\|+/g, "-")}`,
                "Transport"
            );
        }
        return formatLayerOnlyLabel("TCP control", "Transport");
    }

    if (transportName === "UDP") return formatLayerOnlyLabel("UDP datagram", "Transport");
    if (transportName === "SCTP") return formatLayerOnlyLabel("SCTP packet", "Transport");
    if (transportName === "IGMP") return formatLayerOnlyLabel("IGMP control", "Network");
    if (transportName === "LINK") return formatLayerOnlyLabel("Link-layer frame", "Link");
    if (transportName === "FRAME") return formatLayerOnlyLabel("Frame", "Link");
    if (transportName === "UNDECODABLE") return formatLayerOnlyLabel("IP packet", "Network");

    return "";
}

function inferApplicationProtocol(packetInfo, extraInfo, transportName, transportData) {
    const netData =
        extraInfo?.["traits"]?.["network.data"] ||
        extraInfo?.["Traits"]?.["Network Data"] ||
        {};
    const fromTraitsRaw =
        netData?.["port.protocol"] ??
        netData?.["Port Protocol"] ??
        netData?.["Port Protcol"] ??
        "";
    const fromTraits = typeof fromTraitsRaw === "string" ? fromTraitsRaw.trim() : "";

    const decodedNames = collectDecodedProtocolNames(packetInfo);
    const preferred = [
        "SSH",
        "HTTP2",
        "HTTP",
        "WebSocket",
        "DNS",
        "TLS",
        "Kerberos",
        "NFS",
        "RADIUS",
    ];
    const decodedByLower = new Map(
        decodedNames.map((name) => [String(name).toLowerCase(), name])
    );

    for (const name of preferred) {
        const matched = decodedByLower.get(name.toLowerCase());
        if (matched) return matched;
    }

    if (decodedNames.length > 0) return normalizeGenericApplicationProtocolLabel(decodedNames[0], transportName);
    if (!isUnknownLikeProtocol(fromTraits)) return normalizeGenericApplicationProtocolLabel(fromTraits, transportName);
    if (getPacketPayloadLength(packetInfo) === 0 && getPacketPayloadHex(packetInfo) !== "") return "Undecodable";
    if (getPacketPayloadLength(packetInfo) === 0) {
        const zeroPayloadLabel = inferZeroPayloadProtocolLabel(packetInfo, transportName, transportData);
        if (zeroPayloadLabel) return zeroPayloadLabel;
    }
    return normalizeGenericApplicationProtocolLabel(transportName || "Unknown", transportName);
}

function derivePacketListSummary(packet, packetKey, host, hostPacketIndex) {
    const packetInfo = isObject(packet?.["packet.info"]) ? packet["packet.info"] : {};
    const extraInfo = isObject(packet?.["extra.info"]) ? packet["extra.info"] : {};
    const transportName = String(
        packetInfo?.["packet.proto"] ||
        packetInfo?.["protocol"] ||
        packetInfo?.["Protocol"] ||
        "unknown"
    ).toUpperCase();
    const transportData =
        isObject(packetInfo[transportName]) ? packetInfo[transportName] :
            isObject(packetInfo[transportName.toLowerCase()]) ? packetInfo[transportName.toLowerCase()] :
                {};
    const sourceIp = extractPacketIpAddress(packetInfo, "src") || host || "Unknown";
    const destinationIp = extractPacketIpAddress(packetInfo, "dst") || "";
    const sourcePort =
        transportData?.["tcp.src.port"] ??
        transportData?.["udp.src.port"] ??
        transportData?.["sctp.src.port"] ??
        transportData?.["source.port"] ??
        "";
    const destinationPort =
        transportData?.["tcp.dst.port"] ??
        transportData?.["udp.dst.port"] ??
        transportData?.["sctp.dst.port"] ??
        transportData?.["destination.port"] ??
        "";
    const hasPorts = sourcePort !== "" && sourcePort !== undefined && sourcePort !== null &&
        destinationPort !== "" && destinationPort !== undefined && destinationPort !== null;
    const endpointA = hasPorts ? `${sourceIp}:${sourcePort}` : sourceIp;
    const endpointB = hasPorts ? `${destinationIp}:${destinationPort}` : destinationIp;
    const [firstEndpoint, secondEndpoint] = [endpointA, endpointB].sort();
    const streamKey = `${transportName}|${firstEndpoint}|${secondEndpoint}`;
    const appProtocol = inferApplicationProtocol(packetInfo, extraInfo, transportName, transportData);
    const packetProcessed = Number(packetInfo?.["packet.processed"]);

    return {
        packetKey,
        host,
        pktIdx: hostPacketIndex,
        idx: Number(packetInfo?.["index"]) || hostPacketIndex,
        pcapOrder: Number.isFinite(packetProcessed) ? packetProcessed + 1 : Number(packetInfo?.["index"]) || hostPacketIndex,
        srcIp: sourceIp,
        dstIp: destinationIp,
        srcPort: sourcePort,
        dstPort: destinationPort,
        transport: transportName,
        appProto: String(appProtocol),
        payloadLength: Number(packetInfo?.["raw.data"]?.["payload.len"] ?? packetInfo?.["Raw data"]?.["payload.len"] ?? packetInfo?.["Raw data"]?.["Payload Length"]) || 0,
        streamKey,
    };
}

function compareListEntries(left, right) {
    const leftPcapOrder = Number(left?.pcapOrder);
    const rightPcapOrder = Number(right?.pcapOrder);
    if (Number.isFinite(leftPcapOrder) && Number.isFinite(rightPcapOrder) && leftPcapOrder !== rightPcapOrder) {
        return leftPcapOrder - rightPcapOrder;
    }
    if (Number.isFinite(leftPcapOrder) && !Number.isFinite(rightPcapOrder)) return -1;
    if (!Number.isFinite(leftPcapOrder) && Number.isFinite(rightPcapOrder)) return 1;

    const leftIndex = Number(left?.idx);
    const rightIndex = Number(right?.idx);
    if (Number.isFinite(leftIndex) && Number.isFinite(rightIndex) && leftIndex !== rightIndex) {
        return leftIndex - rightIndex;
    }
    if (Number.isFinite(leftIndex) && !Number.isFinite(rightIndex)) return -1;
    if (!Number.isFinite(leftIndex) && Number.isFinite(rightIndex)) return 1;
    return String(left?.packetKey || "").localeCompare(String(right?.packetKey || ""));
}

function applyStreamOrdering(listEntries) {
    const streamOrderByKey = new Map();
    let nextStreamOrder = 1;

    listEntries.forEach((entry) => {
        const streamKey = String(entry?.streamKey || "");
        if (!streamOrderByKey.has(streamKey)) {
            streamOrderByKey.set(streamKey, nextStreamOrder);
            nextStreamOrder += 1;
        }

        const streamOrder = streamOrderByKey.get(streamKey) || 0;
        entry.streamOrder = streamOrder;
        entry.streamLabel = `S${streamOrder}`;
    });
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

async function buildStoreFromCaptureData(captureDataInput, sessionStateInput = null) {
    const normalizedCaptureData = isObject(captureDataInput)
        ? isObject(captureDataInput["capture.data"])
            ? captureDataInput["capture.data"]
            : captureDataInput
        : null;
    if (!normalizedCaptureData || !isObject(normalizedCaptureData)) {
        throw new Error("Invalid capture data payload");
    }

    const hostMap = isObject(normalizedCaptureData["host"])
        ? normalizedCaptureData["host"]
        : isObject(normalizedCaptureData["Host"])
            ? normalizedCaptureData["Host"]
            : null;
    if (!hostMap) {
        throw new Error("Invalid capture data payload");
    }

    const finalSummary = typeof normalizedCaptureData["final.summary"] === "string"
        ? normalizedCaptureData["final.summary"]
        : "";
    const sessionState = isObject(sessionStateInput)
        ? sessionStateInput
        : isObject(captureDataInput?.["session.state"])
            ? captureDataInput["session.state"]
            : null;

    const refsByKey = new Map();
    const hostPackets = new Map();
    const listEntries = [];

    Object.keys(hostMap).forEach((host) => {
        const sourcePackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
        const packetStubs = [];
        hostPackets.set(host, packetStubs);

        sourcePackets.forEach((value, hostPacketIndex) => {
            if (!isObject(value) || !isObject(value["packet.info"])) {
                return;
            }

            const packetKey = derivePacketKey(value, host, hostPacketIndex, refsByKey);
            const packetStub = buildPacketStub(value, packetKey, host, hostPacketIndex);
            packetStubs.push(packetStub);

            refsByKey.set(packetKey, {
                packetKey,
                host,
                hostPacketIndex,
                packetListIndex: packetStubs.length - 1,
                offset: -1,
                length: -1,
            });

            listEntries.push(derivePacketListSummary(value, packetKey, host, hostPacketIndex));
        });
    });

    listEntries.sort(compareListEntries);
    applyStreamOrdering(listEntries);

    const hostObject = {};
    hostPackets.forEach((packetList, host) => {
        hostObject[host] = packetList;
    });

    return {
        storeId: `mem-${Date.now()}-${crypto.randomBytes(6).toString("hex")}`,
        sourcePath: "[capture-data]",
        packetDataPath: null,
        packetDataFd: null,
        refsByKey,
        hostPackets,
        packetCache: new Map(),
        listEntries,
        captureData: {
            host: hostObject,
            listEntries,
            "final.summary": finalSummary,
        },
        sessionState,
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
        if (!packetPathInfo || !isObject(value) || !isObject(value["packet.info"])) {
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
    applyStreamOrdering(listEntries);

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
            host: hostObject,
            listEntries,
            "final.summary": finalSummary,
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
        if (!packetPathInfo || !isObject(value) || !isObject(value["packet.info"])) {
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
    applyStreamOrdering(listEntries);

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
            host: hostObject,
            listEntries,
            "final.summary": finalSummary,
        },
        sessionState,
    };
}

async function closeStore(store) {
    if (!store) return;
    if (store.packetDataFd) {
        try {
            fs.closeSync(store.packetDataFd);
        } catch {
            // Ignore close errors during replacement/cleanup.
        }
        fs.promises.rm(store.packetDataPath, { force: true }).catch(() => { });
    }
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

    // In-memory store: no disk file, return the stub directly.
    // The stub has all metadata; payload hex is not available (stripped at build time).
    if (!store.packetDataFd) {
        const packetList = store.hostPackets.get(ref.host);
        if (!packetList || !packetList[ref.packetListIndex]) return null;
        const stub = packetList[ref.packetListIndex];
        addPacketToCache(store, packetKey, stub);
        return stub;
    }

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
            // In-memory store: no disk file, use the stub directly.
            const packet = packetKey ? await readPacketByKey(packetKey) : null;
            materializedPackets.push(packet || packetStub);
        }
        hostObject[host] = materializedPackets;
    }

    return {
        host: hostObject,
        "final.summary": store.captureData?.["final.summary"] || "",
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

    ipcMain.handle("capture-store-load-data", async (_event, payload) => {
        const captureData = isObject(payload) ? payload.captureData : null;
        const sessionState = isObject(payload) ? payload.sessionState : null;
        if (!captureData || !isObject(captureData)) {
            return { success: false, error: "Invalid capture data payload" };
        }

        try {
            const store = await buildStoreFromCaptureData(captureData, sessionState);
            await activateStore(store);
            return {
                success: true,
                captureData: store.captureData,
                sessionState: store.sessionState,
            };
        } catch (error) {
            return {
                success: false,
                error: error?.message || "Failed to load in-memory capture",
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
