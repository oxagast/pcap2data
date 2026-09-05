"use strict";

// Pure session composition helpers. This module intentionally has no Electron,
// DOM, or renderer dependencies so the merge model can be tested independently
// and reused by the main-process session IPC layer.

// This module is shared by the Electron main process and the renderer. Use
// crypto-js instead of Node's `crypto` module so webpack can bundle the
// renderer-side machine-correlation helper without requiring a core-module
// polyfill.
const CryptoJS = require("crypto-js");
const {
    normalizeSessionPayload,
    validateSessionPayload,
} = require("./session-format");

const MERGED_SESSION_SCHEMA_VERSION = 1;
const MERGED_HOST_SEPARATOR = "::";
const MERGED_PACKET_SEPARATOR = ":";
const MAX_EVIDENCE_SCAN_DEPTH = 8;

function isObject(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function deepClone(value) {
    if (Array.isArray(value)) return value.map((entry) => deepClone(entry));
    if (!isObject(value)) return value;
    const result = {};
    Object.keys(value).forEach((key) => {
        result[key] = deepClone(value[key]);
    });
    return result;
}

function stableStringify(value) {
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return `[${value.map((entry) => stableStringify(entry)).join(",")}]`;
    }
    return `{${Object.keys(value).sort().map((key) => (
        `${JSON.stringify(key)}:${stableStringify(value[key])}`
    )).join(",")}}`;
}

function hashText(value, length = 16) {
    return CryptoJS.SHA256(String(value)).toString(CryptoJS.enc.Hex).slice(0, length);
}

function normalizeName(value, fallback) {
    const name = typeof value === "string" ? value.trim() : "";
    return name || fallback;
}

function getPacketInfo(packet) {
    return isObject(packet?.["packet.info"]) ? packet["packet.info"] : {};
}

function firstString(values) {
    for (const value of values) {
        if (typeof value === "string" && value.trim()) return value.trim();
        if (typeof value === "number" && Number.isFinite(value)) return String(value);
    }
    return "";
}

function getSourceIp(packetInfo, direction = "src") {
    const isDestination = direction === "dst";
    const candidates = isDestination
        ? [
            packetInfo?.IP?.["ip.dst.addr"],
            packetInfo?.IP?.["network.ip.dst.addr"],
            packetInfo?.IP?.["Destination IP"],
            packetInfo?.ip?.["ip.dst.addr"],
            packetInfo?.ip?.["network.ip.dst.addr"],
            packetInfo?.ip?.["destination.ip"],
            packetInfo?.["ip.dst.addr"],
            packetInfo?.["network.ip.dst.addr"],
            packetInfo?.["destination.ip"],
            packetInfo?.["Destination IP"],
        ]
        : [
            packetInfo?.IP?.["ip.src.addr"],
            packetInfo?.IP?.["network.ip.src.addr"],
            packetInfo?.IP?.["Source IP"],
            packetInfo?.ip?.["ip.src.addr"],
            packetInfo?.ip?.["network.ip.src.addr"],
            packetInfo?.ip?.["source.ip"],
            packetInfo?.["ip.src.addr"],
            packetInfo?.["network.ip.src.addr"],
            packetInfo?.["source.ip"],
            packetInfo?.["Source IP"],
        ];
    return firstString(candidates);
}

function getPort(packetInfo, direction = "src") {
    const isDestination = direction === "dst";
    const candidates = isDestination
        ? [
            packetInfo?.TCP?.["tcp.dst.port"],
            packetInfo?.TCP?.["Destination Port"],
            packetInfo?.UDP?.["udp.dst.port"],
            packetInfo?.UDP?.["Destination Port"],
            packetInfo?.SCTP?.["sctp.dst.port"],
            packetInfo?.["tcp.dst.port"],
            packetInfo?.["udp.dst.port"],
            packetInfo?.["sctp.dst.port"],
            packetInfo?.["Destination Port"],
        ]
        : [
            packetInfo?.TCP?.["tcp.src.port"],
            packetInfo?.TCP?.["Source Port"],
            packetInfo?.UDP?.["udp.src.port"],
            packetInfo?.UDP?.["Source Port"],
            packetInfo?.SCTP?.["sctp.src.port"],
            packetInfo?.["tcp.src.port"],
            packetInfo?.["udp.src.port"],
            packetInfo?.["sctp.src.port"],
            packetInfo?.["Source Port"],
        ];
    return firstString(candidates);
}

function getTransport(packetInfo) {
    const value = firstString([
        packetInfo?.["packet.proto"],
        packetInfo?.Protocol,
        packetInfo?.protocol,
        packetInfo?.["Port Protocol"],
        packetInfo?.["Port Protcol"],
        packetInfo?.TCP ? "TCP" : "",
        packetInfo?.UDP ? "UDP" : "",
        packetInfo?.SCTP ? "SCTP" : "",
    ]);
    return value.toUpperCase();
}

function getStreamIdentity(packetInfo, sourceId) {
    const transport = getTransport(packetInfo);
    const srcIp = getSourceIp(packetInfo, "src");
    const dstIp = getSourceIp(packetInfo, "dst");
    const srcPort = getPort(packetInfo, "src");
    const dstPort = getPort(packetInfo, "dst");
    if (!transport || !srcIp || !dstIp) return `${sourceId}|packet`;
    const endpoints = [
        `${srcIp}:${srcPort}`,
        `${dstIp}:${dstPort}`,
    ].sort();
    return `${sourceId}|${transport}|${endpoints.join("|")}`;
}

function getPacketTimestamp(packetInfo) {
    return firstString([
        packetInfo?.["capture.originalTimestamp"],
        packetInfo?.["packet.timestamp"],
        packetInfo?.["Packet Timestamp"],
        packetInfo?.timestamp,
    ]);
}

function parseTimestampMs(value) {
    if (typeof value !== "string" || !value.trim()) return null;
    const text = value.trim();
    const match = text.match(
        /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:\s*(Z|[+-]\d{2}:?\d{2}))?$/,
    );
    if (match) {
        const [, year, month, day, hour, minute, second, fraction = "", zone] = match;
        const fractionMs = Number(`0.${fraction.slice(0, 3).padEnd(3, "0")}`) * 1000;
        const base = zone
            ? Date.parse(`${year}-${month}-${day}T${hour}:${minute}:${second}${zone === "Z" ? "Z" : zone}`)
            : new Date(
                Number(year),
                Number(month) - 1,
                Number(day),
                Number(hour),
                Number(minute),
                Number(second),
                0,
            ).getTime();
        return Number.isFinite(base) ? base + fractionMs : null;
    }
    const parsed = Date.parse(text);
    return Number.isFinite(parsed) ? parsed : null;
}

function normalizeOffsetMs(value) {
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (!isObject(value)) return 0;
    const explicit = Number(value.offsetMs);
    if (Number.isFinite(explicit)) return explicit;
    const seconds = Number(value.offsetSeconds ?? value.seconds ?? 0);
    const milliseconds = Number(value.offsetMilliseconds ?? value.milliseconds ?? 0);
    return (Number.isFinite(seconds) ? seconds * 1000 : 0)
        + (Number.isFinite(milliseconds) ? milliseconds : 0);
}

function collectValuesByKey(value, matcher, output, depth = 0) {
    if (depth > MAX_EVIDENCE_SCAN_DEPTH || !value || typeof value !== "object") return;
    if (Array.isArray(value)) {
        value.slice(0, 1000).forEach((entry) => collectValuesByKey(entry, matcher, output, depth + 1));
        return;
    }
    Object.keys(value).forEach((key) => {
        const child = value[key];
        if (matcher(key, child)) {
            if (typeof child === "string" && child.trim()) output.add(child.trim().toLowerCase());
            if (Array.isArray(child)) {
                child.forEach((entry) => {
                    if (typeof entry === "string" && entry.trim()) output.add(entry.trim().toLowerCase());
                });
            }
        }
        collectValuesByKey(child, matcher, output, depth + 1);
    });
}

function collectSourceEvidence(captureData) {
    const macs = new Set();
    const localIps = new Set();
    const hostMap = isObject(captureData?.host) ? captureData.host : {};
    Object.values(hostMap).forEach((packets) => {
        if (!Array.isArray(packets)) return;
        packets.slice(0, 5000).forEach((packet) => {
            collectValuesByKey(
                packet,
                (key) => /mac|ether|hardware.?address/i.test(key),
                macs,
            );
            const info = getPacketInfo(packet);
            [getSourceIp(info, "src"), getSourceIp(info, "dst")].forEach((ip) => {
                if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|169\.254\.)/.test(ip)) {
                    localIps.add(ip.toLowerCase());
                }
            });
        });
    });
    return { macs: [...macs].sort(), localIps: [...localIps].sort() };
}

function intersect(left, right) {
    const rightSet = new Set(right);
    return left.filter((entry) => rightSet.has(entry));
}

function inferSourceRelationship(left, right) {
    const sharedMacs = intersect(left?.evidence?.macs || [], right?.evidence?.macs || []);
    const sharedLocalIps = intersect(left?.evidence?.localIps || [], right?.evidence?.localIps || []);
    const sameMachine = sharedMacs.length > 0;
    return {
        sourceA: left.sourceId,
        sourceB: right.sourceId,
        suggestion: sameMachine ? "same" : "separate",
        confidence: sameMachine ? "high" : "low",
        sharedMacs,
        sharedLocalIps,
        reason: sameMachine
            ? "The sources share an exact hardware/MAC address."
            : sharedLocalIps.length > 0
                ? "The sources share local IPs, but no strong hardware evidence was found."
                : "No strong shared-device evidence was found.",
    };
}

function relationshipKey(left, right) {
    return [String(left), String(right)].sort().join("|", "");
}

function getSourceRelationshipValues(source) {
    if (isObject(source)) {
        return [source.sourceId, source.sourceName]
            .filter((value) => typeof value === "string" && value.trim())
            .map((value) => value.trim());
    }
    return typeof source === "string" && source.trim() ? [source.trim()] : [];
}

function getRelationshipOverride(overrides, left, right) {
    if (Array.isArray(overrides)) {
        const leftValues = getSourceRelationshipValues(left);
        const rightValues = getSourceRelationshipValues(right);
        const match = overrides.find((entry) => {
            const entryA = String(entry?.sourceA || entry?.a || "").trim();
            const entryB = String(entry?.sourceB || entry?.b || "").trim();
            return (
                (leftValues.includes(entryA) && rightValues.includes(entryB))
                || (leftValues.includes(entryB) && rightValues.includes(entryA))
            );
        });
        return match?.mode || match?.relationship || "auto";
    }
    if (isObject(overrides)) {
        const leftValues = getSourceRelationshipValues(left);
        const rightValues = getSourceRelationshipValues(right);
        for (const leftValue of leftValues) {
            for (const rightValue of rightValues) {
                const value = overrides[relationshipKey(leftValue, rightValue)]
                    || overrides[`${leftValue}|${rightValue}`]
                    || overrides[`${rightValue}|${leftValue}`];
                if (value) return value;
            }
        }
    }
    return "auto";
}

function getSourceOptionValue(values, source) {
    if (!isObject(values)) return null;
    const candidates = [source.sourceId, source.sourceName].filter(
        (value) => typeof value === "string" && value.trim(),
    );
    for (const candidate of candidates) {
        if (Object.prototype.hasOwnProperty.call(values, candidate)) {
            return values[candidate];
        }
    }
    return null;
}

function buildSourceId(source, captureData, index) {
    const existing = source?.sourceId || captureData?.["capture.metadata"]?.sourceId;
    if (typeof existing === "string" && existing.trim()) return existing.trim();
    const identity = stableStringify({
        name: normalizeName(source?.name, `source-${index + 1}`),
        captureData,
    });
    return `source-${hashText(identity, 12)}`;
}

function parseSource(source, index) {
    const sourceName = normalizeName(source?.name, `Source ${index + 1}`);
    let payload = source?.sessionPayload || source?.payload || source?.data;
    if (typeof payload === "string") {
        try {
            payload = JSON.parse(payload);
        } catch (error) {
            throw new Error(`Source "${sourceName}" is not valid JSON: ${error.message}`);
        }
    }
    if (!payload && source?.captureData) {
        payload = {
            "capture.data": source.captureData,
            "session.state": source.sessionState || null,
        };
    }
    const normalized = normalizeSessionPayload(payload);
    if (!normalized) {
        throw new Error(`Source "${sourceName}" is not a valid PacketSnitch session`);
    }
    const validation = validateSessionPayload(payload);
    if (!validation.valid) {
        throw new Error(`Source "${sourceName}" is invalid: ${validation.error}`);
    }
    const sourceId = buildSourceId(source, normalized.captureData, index);
    return {
        sourceId,
        sourceName,
        captureData: normalized.captureData,
        sessionState: normalized.sessionState || {},
        evidence: collectSourceEvidence(normalized.captureData),
        offsetMs: normalizeOffsetMs(source),
        ordinal: index,
    };
}

function getExistingPacketKey(packet, host, hostIndex) {
    const info = getPacketInfo(packet);
    const sourceIp = getSourceIp(info, "src") || host || "Unknown";
    const index = info.index ?? info.Index ?? info["packet.processed"] ?? hostIndex;
    return firstString([
        packet?.__packetKey,
        info["capture.packetId"],
        `${sourceIp}$${index}`,
        `${sourceIp}:${index}`,
    ]);
}

function getSourcePacketIndex(packet, fallback) {
    const processed = Number(
        getPacketInfo(packet)["packet.processed"]
        ?? getPacketInfo(packet)["Packet Processed"],
    );
    return Number.isFinite(processed) ? processed : fallback;
}

function buildHostGroups(sources, relationshipOverrides, relationships) {
    const parent = new Map(sources.map((source) => [source.sourceId, source.sourceId]));
    const find = (id) => {
        let value = id;
        while (parent.get(value) !== value) {
            value = parent.get(value);
        }
        let current = id;
        while (parent.get(current) !== current) {
            const next = parent.get(current);
            parent.set(current, value);
            current = next;
        }
        return value;
    };
    const union = (left, right) => {
        const leftRoot = find(left);
        const rightRoot = find(right);
        if (leftRoot !== rightRoot) parent.set(rightRoot, leftRoot);
    };

    for (let leftIndex = 0; leftIndex < sources.length; leftIndex += 1) {
        for (let rightIndex = leftIndex + 1; rightIndex < sources.length; rightIndex += 1) {
            const left = sources[leftIndex];
            const right = sources[rightIndex];
            const evidence = inferSourceRelationship(left, right);
            const override = String(getRelationshipOverride(relationshipOverrides, left, right)).toLowerCase();
            const mode = ["same", "same-machine", "same_machine"].includes(override)
                ? "same"
                : ["separate", "different", "different-machine", "different_machine"].includes(override)
                    ? "separate"
                    : evidence.suggestion;
            relationships.push({ ...evidence, mode, override: override === "auto" ? null : override });
            if (mode === "same") union(left.sourceId, right.sourceId);
        }
    }

    const normalizedGroups = new Map();
    sources.forEach((source) => {
        const root = find(source.sourceId);
        if (!normalizedGroups.has(root)) normalizedGroups.set(root, []);
        normalizedGroups.get(root).push(source.sourceId);
    });
    return { find, groups: normalizedGroups };
}

function getCorrelationSourceId(packetInfo, host, fallbackSourceId) {
    const sourceId = firstString([
        packetInfo?.["capture.sourceId"],
        packetInfo?.["capture.sourceSession"],
    ]);
    return sourceId || fallbackSourceId || `capture:${host || "unknown"}`;
}

function getPacketCorrelationSignature(packetInfo) {
    const transport = getTransport(packetInfo) || firstString([
        packetInfo?.["packet.proto"],
        packetInfo?.Protocol,
    ]) || "packet";
    const sourceIp = getSourceIp(packetInfo, "src");
    const destinationIp = getSourceIp(packetInfo, "dst");
    const sourcePort = getPort(packetInfo, "src");
    const destinationPort = getPort(packetInfo, "dst");
    const endpoints = [
        `${sourceIp}:${sourcePort}`,
        `${destinationIp}:${destinationPort}`,
    ].sort();
    const payloadLength = firstString([
        packetInfo?.["packet.length"],
        packetInfo?.["frame.len"],
        packetInfo?.["payload.length"],
    ]);
    return [transport.toUpperCase(), ...endpoints, payloadLength].join("|");
}

function getCorrelationPackets(captureData) {
    const packets = [];
    const hostMap = isObject(captureData?.host) ? captureData.host : {};
    const metadata = isObject(captureData?.["capture.metadata"])
        ? captureData["capture.metadata"]
        : {};
    const fallbackSourceId = firstString([
        metadata.sourceId,
        metadata.sourceName,
        "current-capture",
    ]);
    Object.entries(hostMap).forEach(([host, hostPackets]) => {
        if (!Array.isArray(hostPackets)) return;
        hostPackets.forEach((packet, packetIndex) => {
            const packetInfo = getPacketInfo(packet);
            const timestampMs = parseTimestampMs(getPacketTimestamp(packetInfo));
            packets.push({
                packet,
                packetInfo,
                host,
                packetIndex,
                sourceId: getCorrelationSourceId(packetInfo, host, fallbackSourceId),
                sourceName: firstString([
                    packetInfo?.["capture.sourceSession"],
                    packetInfo?.["capture.sourceId"],
                    fallbackSourceId,
                ]),
                timestampMs,
                signature: getPacketCorrelationSignature(packetInfo),
            });
        });
    });
    return packets;
}

function inferCorrelationThresholdMs(packets) {
    const timestamps = packets
        .map((entry) => entry.timestampMs)
        .filter((value) => Number.isFinite(value))
        .sort((left, right) => left - right);
    const deltas = [];
    for (let index = 1; index < timestamps.length; index += 1) {
        const delta = timestamps[index] - timestamps[index - 1];
        if (delta > 0 && delta <= 5000) deltas.push(delta);
    }
    if (!deltas.length) return 100;
    deltas.sort((left, right) => left - right);
    const median = deltas[Math.floor(deltas.length / 2)];
    return Math.max(10, Math.min(1000, Math.round(median / 2)));
}

function median(values) {
    const sorted = values.filter(Number.isFinite).sort((left, right) => left - right);
    if (!sorted.length) return null;
    return sorted[Math.floor(sorted.length / 2)];
}

/**
 * Derive a non-destructive machine-correlation layer for an already loaded
 * capture. Packet timestamps are never rewritten; `packetMatches` contains
 * the proposed snapped timestamp and verification count instead.
 */
function computeMachineCorrelation(captureData, options = {}) {
    const packets = getCorrelationPackets(captureData);
    const sourcePackets = new Map();
    packets.forEach((entry) => {
        if (!sourcePackets.has(entry.sourceId)) sourcePackets.set(entry.sourceId, []);
        sourcePackets.get(entry.sourceId).push(entry);
    });

    const sources = [...sourcePackets.entries()].map(([sourceId, entries], ordinal) => ({
        sourceId,
        sourceName: entries.find((entry) => entry.sourceName)?.sourceName || sourceId,
        ordinal,
        captureData: {
            host: Object.fromEntries(
                [...new Set(entries.map((entry) => entry.host))].map((host) => [host, []]),
            )
        },
        evidence: collectSourceEvidence({
            host: Object.fromEntries(
                [...new Set(entries.map((entry) => entry.host))].map((host) => [
                    host,
                    entries.filter((entry) => entry.host === host).map((entry) => entry.packet),
                ]),
            ),
        }),
        entries,
    }));

    const relationships = [];
    const parent = new Map(sources.map((source) => [source.sourceId, source.sourceId]));
    const find = (sourceId) => {
        let root = sourceId;
        while (parent.get(root) !== root) root = parent.get(root);
        return root;
    };
    const union = (left, right) => {
        const leftRoot = find(left);
        const rightRoot = find(right);
        if (leftRoot !== rightRoot) parent.set(rightRoot, leftRoot);
    };
    for (let leftIndex = 0; leftIndex < sources.length; leftIndex += 1) {
        for (let rightIndex = leftIndex + 1; rightIndex < sources.length; rightIndex += 1) {
            const left = sources[leftIndex];
            const right = sources[rightIndex];
            const evidence = inferSourceRelationship(left, right);
            const sameMachine = evidence.sharedMacs.length > 0 || evidence.sharedLocalIps.length > 0;
            relationships.push({
                ...evidence,
                suggestion: sameMachine ? "same" : "separate",
                confidence: evidence.sharedMacs.length ? "high" : evidence.sharedLocalIps.length ? "medium" : "low",
                mode: sameMachine ? "same" : "separate",
            });
            if (sameMachine) union(left.sourceId, right.sourceId);
        }
    }

    const groupedSources = new Map();
    sources.forEach((source) => {
        const root = find(source.sourceId);
        if (!groupedSources.has(root)) groupedSources.set(root, []);
        groupedSources.get(root).push(source);
    });

    const packetMatches = {};
    const groups = [];
    let groupIndex = 0;
    groupedSources.forEach((groupSources) => {
        groupIndex += 1;
        const sourceIds = groupSources.map((source) => source.sourceId);
        const groupEntries = groupSources.flatMap((source) => source.entries);
        const macs = [...new Set(groupSources.flatMap((source) => source.evidence.macs))].sort();
        const localIps = [...new Set(groupSources.flatMap((source) => source.evidence.localIps))].sort();
        const hostKeys = [...new Set(groupEntries.map((entry) => entry.host))].sort();
        const signatureSources = new Map();
        groupEntries.forEach((entry) => {
            if (!signatureSources.has(entry.signature)) signatureSources.set(entry.signature, new Map());
            if (!signatureSources.get(entry.signature).has(entry.sourceId)) {
                signatureSources.get(entry.signature).set(entry.sourceId, []);
            }
            signatureSources.get(entry.signature).get(entry.sourceId).push(entry);
        });

        const sourceOffsets = new Map(sourceIds.map((sourceId) => [sourceId, []]));
        signatureSources.forEach((bySource) => {
            if (bySource.size < 2) return;
            const sourceTimes = [...bySource.entries()].map(([sourceId, entries]) => [
                sourceId,
                median(entries.map((entry) => entry.timestampMs)),
            ]).filter(([, time]) => time !== null);
            sourceTimes.forEach(([sourceId, time]) => {
                sourceTimes.forEach(([otherSourceId, otherTime]) => {
                    if (sourceId !== otherSourceId) sourceOffsets.get(sourceId).push(otherTime - time);
                });
            });
        });

        const offsets = new Map([...sourceOffsets.entries()].map(([sourceId, values]) => [
            sourceId,
            median(values) || 0,
        ]));
        const thresholdOption = Number(options.thresholdMs);
        const thresholdMs = Number.isFinite(thresholdOption) && thresholdOption > 0
            ? thresholdOption
            : inferCorrelationThresholdMs(groupEntries);
        const verifiedSignatures = new Map(
            [...signatureSources.entries()].map(([signature, bySource]) => [signature, bySource.size]),
        );

        groupEntries.forEach((entry) => {
            const packetKey = firstString([
                entry.packet?.__packetKey,
                entry.packetInfo?.["capture.packetId"],
                `${entry.host}$${entry.packetIndex}`,
            ]);
            const sourceIp = getSourceIp(entry.packetInfo, "src") || entry.host || "Unknown";
            const sourcePacketKey = `${sourceIp}$${entry.packetInfo?.index ?? entry.packetInfo?.Index ?? entry.packetIndex}`;
            const adjustedTimestampMs = Number.isFinite(entry.timestampMs)
                ? entry.timestampMs + (offsets.get(entry.sourceId) || 0)
                : null;
            const signatureCount = verifiedSignatures.get(entry.signature) || 1;
            const matchingSourceIds = [...(signatureSources.get(entry.signature)?.keys() || [])];
            const matchingSourceNames = matchingSourceIds.map((sourceId) => ({
                sourceId,
                sourceName: groupSources.find((source) => source.sourceId === sourceId)?.sourceName || sourceId,
            }));
            const correlationKey = Number.isFinite(adjustedTimestampMs)
                ? `${entry.signature}|${Math.round(adjustedTimestampMs / Math.max(1, thresholdMs))}`
                : "";
            const match = {
                sourceId: entry.sourceId,
                host: entry.host,
                signature: entry.signature,
                correlationKey,
                verifiedSources: matchingSourceNames,
                originalTimestampMs: entry.timestampMs,
                snappedTimestampMs: adjustedTimestampMs,
                snapDeltaMs: Number.isFinite(adjustedTimestampMs) && Number.isFinite(entry.timestampMs)
                    ? adjustedTimestampMs - entry.timestampMs
                    : 0,
                thresholdMs,
                verifiedAcrossPcaps: signatureCount,
                snapped: Math.abs((adjustedTimestampMs || 0) - (entry.timestampMs || 0)) <= thresholdMs,
            };
            packetMatches[packetKey] = match;
            // Renderer list rows use source-IP + packet-index keys when a
            // durable capture packet ID is unavailable. Keep both aliases
            // pointing at the same presentation metadata.
            packetMatches[sourcePacketKey] = match;
        });

        groups.push({
            groupId: `machine-${groupIndex}`,
            macs,
            localIps,
            sources: sourceIds,
            hostKeys,
            sourceOffsets: Object.fromEntries(offsets),
            thresholdMs,
            verifiedAcrossPcaps: sourceIds.length,
        });
    });

    const hostToGroup = {};
    groups.forEach((group) => group.hostKeys.forEach((host) => {
        hostToGroup[host] = group.groupId;
    }));

    const anomalies = [];
    groups.filter((group) => group.sources.length > 1).forEach((group) => {
        const entries = group.sources.flatMap((sourceId) => sourcePackets.get(sourceId) || []);
        const bySignature = new Map();
        entries.forEach((entry) => {
            if (!bySignature.has(entry.signature)) bySignature.set(entry.signature, new Set());
            bySignature.get(entry.signature).add(entry.sourceId);
        });
        bySignature.forEach((presentSet, signature) => {
            if (presentSet.size === group.sources.length) return;
            const absentFrom = group.sources.filter((sourceId) => !presentSet.has(sourceId));
            anomalies.push({
                kind: "cross_capture_missing",
                label: "Missing from correlated capture",
                detail: `${signature} appears in ${[...presentSet].join(", ")} but not ${absentFrom.join(", ")}`,
                query: "",
                groupId: group.groupId,
                signature,
                presentIn: [...presentSet],
                absentFrom,
            });
        });
    });

    return {
        version: 1,
        enabled: false,
        collapseEnabled: false,
        thresholdMs: groups.length ? Math.max(...groups.map((group) => group.thresholdMs)) : null,
        groups,
        hostToGroup,
        packetMatches,
        anomalies,
        relationships,
    };
}

function hostKeyFor(source, host, hostGroups) {
    const group = hostGroups.groups.get(hostGroups.find(source.sourceId)) || [];
    if (group.length > 1) return host;
    return `${source.sourceId}${MERGED_HOST_SEPARATOR}${host}`;
}

function buildAnnotationState(sources, packetKeyMap, sourceDescriptors, metadata) {
    const bookmarkList = [];
    const filterHistory = [];
    const convInputHistory = [];
    const sessionKeychainEntries = [];
    const notes = [];
    const fileArtifacts = [];
    const summaries = [];
    const sourcePcaps = [];
    const addUnique = (array, value) => {
        const serialized = stableStringify(value);
        if (!array.some((entry) => stableStringify(entry) === serialized)) array.push(value);
    };

    sources.forEach((source) => {
        const state = isObject(source.sessionState) ? source.sessionState : {};
        const sourceLabel = source.sourceName;
        (Array.isArray(state.bookmarkList) ? state.bookmarkList : []).forEach((key) => {
            const mapped = packetKeyMap.get(`${source.sourceId}|${key}`);
            if (mapped) addUnique(bookmarkList, mapped);
        });
        (Array.isArray(state.filterHistory) ? state.filterHistory : []).forEach((entry) => addUnique(filterHistory, entry));
        (Array.isArray(state.convInputHistory) ? state.convInputHistory : []).forEach((entry) => addUnique(convInputHistory, entry));
        (Array.isArray(state.sessionKeychainEntries) ? state.sessionKeychainEntries : []).forEach((entry) => {
            const clone = deepClone(entry);
            if (isObject(clone)) clone.sourceSession = clone.sourceSession || sourceLabel;
            addUnique(sessionKeychainEntries, clone);
        });
        (Array.isArray(state.notes) ? state.notes : []).forEach((entry, index) => {
            const clone = deepClone(entry);
            if (isObject(clone)) {
                clone.id = `${source.sourceId}-note-${index + 1}-${hashText(stableStringify(clone), 8)}`;
                clone.sourceSession = clone.sourceSession || sourceLabel;
                if (typeof clone.title === "string" && clone.title.trim()) clone.title = `[${sourceLabel}] ${clone.title}`;
            }
            addUnique(notes, clone);
        });
        (Array.isArray(state.fileArtifacts) ? state.fileArtifacts : []).forEach((entry, index) => {
            const clone = deepClone(entry);
            if (isObject(clone)) {
                clone.id = `${source.sourceId}-artifact-${index + 1}-${hashText(stableStringify(clone), 8)}`;
                clone.sourceSession = clone.sourceSession || sourceLabel;
                if (typeof clone.packetKey === "string") {
                    clone.packetKey = packetKeyMap.get(`${source.sourceId}|${clone.packetKey}`) || clone.packetKey;
                }
            }
            addUnique(fileArtifacts, clone);
        });
        const summary = state.currentSummary || source.captureData?.["final.summary"];
        if (typeof summary === "string" && summary.trim()) summaries.push({ sourceSession: sourceLabel, summary });
        if (state.sourcePcap && isObject(state.sourcePcap)) {
            addUnique(sourcePcaps, {
                sourceId: source.sourceId,
                sourceSession: sourceLabel,
                ...deepClone(state.sourcePcap),
            });
        }
        if (Array.isArray(state.sourcePcaps)) {
            state.sourcePcaps.forEach((entry) => addUnique(sourcePcaps, {
                sourceId: source.sourceId,
                sourceSession: sourceLabel,
                ...deepClone(entry),
            }));
        }
    });

    return {
        schemaVersion: 3,
        merged: true,
        mergedAt: new Date().toISOString(),
        currentFilterQuery: "",
        filterHistory,
        currentPacketKey: null,
        activePacketCursor: 0,
        packetViewMode: "host",
        selectedHost: "",
        bookmarkList,
        convInputHistory,
        sessionKeychainEntries,
        notes,
        fileArtifacts,
        sourcePcap: null,
        sourcePcaps,
        sourceSummaries: summaries,
        mergeMetadata: metadata,
        tabs: { main: "stats", conv: "", crypt: "", listSearch: "", listGroupStreams: false },
        sourceDescriptors,
    };
}

function mergeSessions(inputSources, options = {}) {
    if (!Array.isArray(inputSources) || inputSources.length < 2) {
        throw new Error("At least two saved sessions are required to merge");
    }

    const sources = inputSources.map((source, index) => parseSource(source, index));
    const offsetOptions = isObject(options.offsets) ? options.offsets : {};
    sources.forEach((source) => {
        const configuredOffset = getSourceOptionValue(offsetOptions, source);
        if (configuredOffset !== null) {
            source.offsetMs = normalizeOffsetMs(configuredOffset);
        }
    });
    const sourceIds = new Set();
    sources.forEach((source) => {
        if (sourceIds.has(source.sourceId)) {
            throw new Error(`Duplicate source identity detected for "${source.sourceName}"`);
        }
        sourceIds.add(source.sourceId);
    });

    const relationships = [];
    const hostGroupResult = buildHostGroups(
        sources,
        options.relationships || options.relationshipOverrides,
        relationships,
    );
    const mergedHost = {};
    const packetKeyMap = new Map();
    const usedPacketIds = new Set();
    const decoratedPackets = [];

    sources.forEach((source) => {
        const hostMap = isObject(source.captureData.host) ? source.captureData.host : {};
        let fallbackSourceIndex = 0;
        Object.keys(hostMap).forEach((host) => {
            const packets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
            packets.forEach((packet, hostIndex) => {
                if (!isObject(packet)) return;
                const cloned = deepClone(packet);
                const info = getPacketInfo(cloned);
                const sourcePacketIndex = getSourcePacketIndex(cloned, fallbackSourceIndex);
                fallbackSourceIndex += 1;
                const originalTimestamp = getPacketTimestamp(info);
                const timestampMs = parseTimestampMs(originalTimestamp);
                const adjustedTimestampMs = timestampMs === null
                    ? null
                    : timestampMs + source.offsetMs;
                const oldKey = getExistingPacketKey(cloned, host, hostIndex);
                const digest = hashText(stableStringify(cloned), 12);
                const basePacketId = [source.sourceId, sourcePacketIndex, digest].join(MERGED_PACKET_SEPARATOR);
                let packetId = basePacketId;
                let collisionIndex = 1;
                while (usedPacketIds.has(packetId)) {
                    packetId = `${basePacketId}-${collisionIndex}`;
                    collisionIndex += 1;
                }
                usedPacketIds.add(packetId);
                const mergedHostKey = hostKeyFor(source, host, hostGroupResult);
                const sourceQualifiedStreamId = getStreamIdentity(info, source.sourceId);
                info["capture.sourceId"] = source.sourceId;
                info["capture.sourceSession"] = source.sourceName;
                info["capture.sourceHost"] = host;
                info["capture.sourcePacketIndex"] = sourcePacketIndex;
                info["capture.originalPacketProcessed"] = info["packet.processed"] ?? info["Packet Processed"] ?? null;
                info["capture.originalTimestamp"] = originalTimestamp;
                info["capture.offsetMs"] = source.offsetMs;
                info["capture.adjustedTimestampMs"] = adjustedTimestampMs;
                info["capture.packetId"] = packetId;
                info["capture.streamId"] = sourceQualifiedStreamId;
                info["capture.sourceStreamId"] = sourceQualifiedStreamId;
                info["capture.mergeOrder"] = -1;
                cloned["packet.info"] = info;
                cloned.__packetKey = packetId;
                packetKeyMap.set(`${source.sourceId}|${oldKey}`, packetId);
                packetKeyMap.set(`${source.sourceId}|${packetId}`, packetId);
                decoratedPackets.push({
                    packet: cloned,
                    source,
                    host,
                    mergedHostKey,
                    hostIndex,
                    sourcePacketIndex,
                    timestampMs: adjustedTimestampMs,
                    digest,
                });
            });
        });
    });

    decoratedPackets.sort((left, right) => {
        const leftTime = left.timestampMs === null ? Number.POSITIVE_INFINITY : left.timestampMs;
        const rightTime = right.timestampMs === null ? Number.POSITIVE_INFINITY : right.timestampMs;
        return leftTime - rightTime
            || left.source.ordinal - right.source.ordinal
            || left.sourcePacketIndex - right.sourcePacketIndex
            || left.digest.localeCompare(right.digest);
    });

    const hostIndexes = new Map();
    decoratedPackets.forEach((entry, mergeOrder) => {
        const info = entry.packet["packet.info"];
        const nextHostIndex = (hostIndexes.get(entry.mergedHostKey) || 0) + 1;
        hostIndexes.set(entry.mergedHostKey, nextHostIndex);
        info["capture.mergeOrder"] = mergeOrder;
        info.index = nextHostIndex;
        info.Index = nextHostIndex;
        if (!mergedHost[entry.mergedHostKey]) mergedHost[entry.mergedHostKey] = [];
        mergedHost[entry.mergedHostKey].push(entry.packet);
    });

    const sourceDescriptors = sources.map((source) => ({
        sourceId: source.sourceId,
        sourceName: source.sourceName,
        ordinal: source.ordinal,
        offsetMs: source.offsetMs,
        packetCount: decoratedPackets.filter((entry) => entry.source.sourceId === source.sourceId).length,
        evidence: deepClone(source.evidence),
    }));
    const metadata = {
        merged: true,
        schemaVersion: MERGED_SESSION_SCHEMA_VERSION,
        timelinePolicy: "adjusted-timestamp-source-order-source-index-digest",
        timestampWarning: "Stored PacketSnitch timestamps are local wall-clock values without timezone metadata; offsets are for timeline alignment only.",
        sources: sourceDescriptors,
        relationships,
        hostGroups: [...hostGroupResult.groups.values()].map((group) => [...group]),
    };
    const sessionState = buildAnnotationState(sources, packetKeyMap, sourceDescriptors, metadata);
    const captureData = {
        host: mergedHost,
        "final.summary": sourceDescriptors.length
            ? sourceDescriptors.map((source) => `${source.sourceName}: ${sources.find((entry) => entry.sourceId === source.sourceId)?.captureData?.["final.summary"] || ""}`).filter((entry) => !entry.endsWith(": ")).join("\n\n")
            : "",
        "capture.metadata": metadata,
    };

    return {
        captureData,
        sessionState,
        metadata,
        json: JSON.stringify({ "capture.data": captureData, "session.state": sessionState }, null, 2),
    };
}

module.exports = {
    MERGED_SESSION_SCHEMA_VERSION,
    deepClone,
    stableStringify,
    parseTimestampMs,
    normalizeOffsetMs,
    collectSourceEvidence,
    inferSourceRelationship,
    computeMachineCorrelation,
    mergeSessions,
};
