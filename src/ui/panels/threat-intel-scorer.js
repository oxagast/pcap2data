// Aggregates threat indicators across the entire capture/session and computes
// a deterministic Session Threat Score (0-100). Used by the Threat Intel
// sub-tab to summarize how risky the analyzed capture looks overall.
//
// Inputs (all optional, gracefully ignored when missing):
//   * capturedPackets  - { [host]: Array<packet> } captured packet structure
//   * threatIntelState - { ipsum, tor, virustotal, ... } per-target lookups
//   * sessionThreatIntel - additional per-target lookups accumulated across
//     the whole session (populated by the panel whenever a user kicks off a
//     lookup).
//   * carvableFiles   - extracted/carved files with their hashes + bytes
//   * inputBytes      - current Conv input Uint8Array (for Shannon entropy)
//
// The module exposes pure helpers so it can be unit-tested without a DOM:
//
//   computeSessionThreatScore(...)
//   collectSessionThreatIndicators(...)
//   detectProtocolAnomalies(...)
//   buildSessionThreatScoreBreakdown(...)
//   buildSessionThreatLlmPrompt(...)

const IPV4_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_REGEX = /^(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}$/;
const DNS_NAME_REGEX = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$/;
const URL_REGEX = /\bhttps?:\/\/[^\s<>"'`()]+/gi;
const DOMAIN_HINT_REGEX = /\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b/g;

const HEURISTIC_SCORE_VERSION = 1;
const MAX_SCORE = 100;

const SCORE_BANDS = [
    { name: "Clean", min: 0, max: 0, color: "#2e7d32", description: "No indicators of compromise were detected." },
    { name: "Low", min: 1, max: 19, color: "#558b2f", description: "A small number of weak indicators were found; review at your leisure." },
    { name: "Medium", min: 20, max: 49, color: "#f9a825", description: "Multiple moderate indicators were found; investigate before treating the capture as benign." },
    { name: "High", min: 50, max: 79, color: "#ef6c00", description: "Many strong indicators were found; this capture warrants immediate analyst attention." },
    { name: "Critical", min: 80, max: 100, color: "#c62828", description: "Severe indicators (e.g. known-malicious file hashes, repeated hits on high-risk reputation lists) were found." },
];

// Per-indicator weights for the deterministic score. Values are tuned so
// that even one well-attested hit (e.g. a malicious VT file hash) lifts the
// score into the High band, and the typical noiseless capture sits at 0.
const WEIGHTS = Object.freeze({
    // Per-target reputation lookups
    ipsumListedHit: 4,
    ipsumListedWithManyHits: 8,
    torExitNode: 6,
    virustotalMaliciousVerdict: 18,
    virustotalSuspiciousVerdict: 6,
    virustotalHarmlessModifier: -2,
    virustotalUndetectedModifier: 0,
    virustotalNegativeReputation: 8,

    // Session-wide (file) reputation
    fileHashMalicious: 22,
    fileHashSuspicious: 8,

    // Frequency multipliers (per indicator key, applied as
    // 1 + log10(occurrences) when occurrences > 1)
    repeatedIndicatorMultiplier: 0.6,

    // Embedded / obfuscated data
    embeddedEntropyHigh: 22, // >= 7.5
    embeddedEntropyMedium: 10, // >= 6.0

    // Protocol anomalies (per detected anomaly)
    protocolAnomaly: 5,
    protocolAnomalyBeaconing: 8,
    protocolAnomalyDnsTunneling: 12,
    protocolAnomalyNonStandardPort: 4,
});

const HIGH_ENTROPY_THRESHOLD = 7.5;
const MEDIUM_ENTROPY_THRESHOLD = 6.0;

const DNS_TUNNEL_LABEL_LENGTH_THRESHOLD = 50;
const BEACONING_MIN_OCCURRENCES = 6;
const BEACONING_MIN_UNIQUE_SIZES = 3;
const BEACONING_MAX_SIZE_VARIANCE = 32;

const NON_STANDARD_TCP_PORTS = new Set([
    22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]);

function clampScore(score) {
    if (!Number.isFinite(score)) return 0;
    if (score < 0) return 0;
    if (score > MAX_SCORE) return MAX_SCORE;
    return Math.round(score);
}

function isIpv4(value) {
    if (!value || typeof value !== "string") return false;
    if (!IPV4_REGEX.test(value)) return false;
    const parts = value.split(".").map((p) => Number(p));
    return parts.every((p) => Number.isInteger(p) && p >= 0 && p <= 255);
}

function isIpv6(value) {
    if (!value || typeof value !== "string") return false;
    return value.includes(":") && IPV6_REGEX.test(value);
}

function isPublicIpv4(value) {
    if (!isIpv4(value)) return false;
    const parts = value.split(".").map((p) => Number(p));
    const [a, b] = parts;
    if (a === 10) return false;
    if (a === 127) return false;
    if (a === 0) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
    if (a >= 224) return false; // multicast / reserved
    return true;
}

function isLikelyDomain(value) {
    if (!value || typeof value !== "string") return false;
    const trimmed = value.trim().toLowerCase().replace(/\.+$/, "");
    if (trimmed.length < 4) return false;
    if (trimmed.startsWith(".") || trimmed.endsWith(".")) return false;
    if (trimmed.includes(" ")) return false;
    // Skip pure-numeric and pure-IPv4 noise
    if (/^\d+(\.\d+)*$/.test(trimmed)) return false;
    if (isIpv4(trimmed)) return false;
    return DNS_NAME_REGEX.test(trimmed);
}

function normalizeDomain(value) {
    return String(value || "").trim().toLowerCase().replace(/\.+$/, "");
}

function safeString(value) {
    if (value === null || value === undefined) return "";
    return String(value);
}

function getPacketInfo(packet) {
    if (!packet || typeof packet !== "object") return null;
    return packet["packet.info"] || null;
}

function getPacketProto(packetInfo) {
    if (!packetInfo || typeof packetInfo !== "object") return "";
    return safeString(packetInfo["packet.proto"] ?? packetInfo["Protocol"] ?? "").toUpperCase();
}

function getPacketSourceIp(packetInfo) {
    if (!packetInfo || typeof packetInfo !== "object") return "";
    return safeString(packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"] ?? "").trim();
}

function getPacketDestinationIp(packetInfo) {
    if (!packetInfo || typeof packetInfo !== "object") return "";
    return safeString(packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"] ?? "").trim();
}

function getPacketSourcePort(packetInfo, protocol) {
    if (!packetInfo || typeof packetInfo !== "object") return null;
    const proto = protocol || getPacketProto(packetInfo);
    // Read TCP/UDP port fields regardless of whether the application-layer
    // protocol is set (HTTP/TLS packets still carry a TCP header with ports).
    if (proto === "TCP" || packetInfo?.["TCP"]) {
        const raw = packetInfo?.["TCP"]?.["tcp.src.port"] ?? packetInfo?.["TCP"]?.["Source port"];
        if (raw !== undefined && raw !== null) {
            const num = Number(raw);
            if (Number.isFinite(num)) return num;
        }
    }
    if (proto === "UDP" || packetInfo?.["UDP"]) {
        const raw = packetInfo?.["UDP"]?.["udp.srcport"] ?? packetInfo?.["UDP"]?.["Source port"];
        if (raw !== undefined && raw !== null) {
            const num = Number(raw);
            if (Number.isFinite(num)) return num;
        }
    }
    return NaN;
}

function getPacketDestinationPort(packetInfo, protocol) {
    if (!packetInfo || typeof packetInfo !== "object") return null;
    const proto = protocol || getPacketProto(packetInfo);
    // Read TCP/UDP port fields regardless of whether the application-layer
    // protocol is set (HTTP/TLS packets still carry a TCP header with ports).
    if (proto === "TCP" || packetInfo?.["TCP"]) {
        const raw = packetInfo?.["TCP"]?.["tcp.dst.port"] ?? packetInfo?.["TCP"]?.["Destination port"];
        if (raw !== undefined && raw !== null) {
            const num = Number(raw);
            if (Number.isFinite(num)) return num;
        }
    }
    if (proto === "UDP" || packetInfo?.["UDP"]) {
        const raw = packetInfo?.["UDP"]?.["udp.dstport"] ?? packetInfo?.["UDP"]?.["Destination port"];
        if (raw !== undefined && raw !== null) {
            const num = Number(raw);
            if (Number.isFinite(num)) return num;
        }
    }
    return NaN;
}

function getPacketTimestamp(packetInfo) {
    if (!packetInfo || typeof packetInfo !== "object") return null;
    const raw = packetInfo["packet.timestamp"] ?? packetInfo["Packet Timestamp"];
    if (raw === undefined || raw === null) return null;
    const num = Number(raw);
    if (!Number.isFinite(num)) return null;
    return num > 1e12 ? num : num * 1000;
}

function getDnsQueryName(packetInfo) {
    if (!packetInfo || typeof packetInfo !== "object") return null;
    const dns = packetInfo["DNS"];
    if (!dns || typeof dns !== "object") return null;
    const name = dns["dns.qry.name"] ?? dns["dns.qry.name.len"] ?? dns["Query Name"] ?? null;
    if (!name) return null;
    return normalizeDomain(name);
}

function getHttpHost(packetInfo) {
    if (!packetInfo || typeof packetInfo !== "object") return null;
    const http = packetInfo["HTTP"] || packetInfo["http"];
    if (!http || typeof http !== "object") return null;
    const host = http["http.host"] ?? http["Host"] ?? null;
    if (!host) return null;
    return normalizeDomain(host);
}

function getHttpRequestUri(packetInfo) {
    if (!packetInfo || typeof packetInfo !== "object") return null;
    const http = packetInfo["HTTP"] || packetInfo["http"];
    if (!http || typeof http !== "object") return null;
    return http["http.request.uri"] ?? http["Request URI"] ?? null;
}

function getPacketLength(packetInfo) {
    if (!packetInfo || typeof packetInfo !== "object") return null;
    const raw = packetInfo["packet.len"] ?? packetInfo["Packet Length"] ?? packetInfo?.["Raw data"]?.["Frame Length"];
    const num = Number(raw);
    return Number.isFinite(num) ? num : null;
}

// Iterates over every packet in the capturedPackets structure. Yields
// { host, packetInfo, packet }. Skips host buckets that are not arrays.
function* iterateCapturedPackets(capturedPackets) {
    if (!capturedPackets || typeof capturedPackets !== "object") return;
    const hosts = capturedPackets["host"];
    if (!hosts || typeof hosts !== "object") return;
    for (const host of Object.keys(hosts)) {
        const list = hosts[host];
        if (!Array.isArray(list)) continue;
        for (const packet of list) {
            const packetInfo = getPacketInfo(packet);
            if (!packetInfo) continue;
            yield { host, packet, packetInfo };
        }
    }
}

// Collects every unique IP seen as either source or destination across the
// capture, with a per-IP packet count. Public IPs are tracked separately so
// that private/loopback/link-local noise does not dominate the score.
function collectIpIndicators(capturedPackets) {
    const allByIp = new Map();
    const publicByIp = new Map();
    for (const { packetInfo } of iterateCapturedPackets(capturedPackets)) {
        const src = getPacketSourceIp(packetInfo);
        const dst = getPacketDestinationIp(packetInfo);
        for (const ip of [src, dst]) {
            if (!ip) continue;
            if (!isIpv4(ip) && !isIpv6(ip)) continue;
            const isPublic = isPublicIpv4(ip);
            const counter = isPublic ? publicByIp : allByIp;
            counter.set(ip, (counter.get(ip) || 0) + 1);
        }
    }
    const all = Array.from(allByIp.entries())
        .map(([ip, count]) => ({ ip, count, isPublic: false }))
        .sort((a, b) => b.count - a.count);
    const publicIps = Array.from(publicByIp.entries())
        .map(([ip, count]) => ({ ip, count, isPublic: true }))
        .sort((a, b) => b.count - a.count);
    return { all, publicIps };
}

// Collects every unique domain/URL seen in the capture. DNS query names
// and HTTP Host fields are the dominant sources; we also scan any string
// fields that look like domain names.
function collectDomainIndicators(capturedPackets) {
    const domainsByName = new Map();
    const urlsByValue = new Map();

    function bump(map, key, count = 1) {
        map.set(key, (map.get(key) || 0) + count);
    }

    for (const { packetInfo } of iterateCapturedPackets(capturedPackets)) {
        const dnsName = getDnsQueryName(packetInfo);
        if (dnsName && isLikelyDomain(dnsName)) {
            bump(domainsByName, dnsName);
        }
        const httpHost = getHttpHost(packetInfo);
        if (httpHost && isLikelyDomain(httpHost)) {
            bump(domainsByName, httpHost);
        }
        const requestUri = getHttpRequestUri(packetInfo);
        if (requestUri) {
            const matches = String(requestUri).match(URL_REGEX) || [];
            for (const url of matches) {
                bump(urlsByValue, url);
            }
        }
    }

    return {
        domains: Array.from(domainsByName.entries())
            .map(([domain, count]) => ({ domain, count }))
            .sort((a, b) => b.count - a.count),
        urls: Array.from(urlsByValue.entries())
            .map(([url, count]) => ({ url, count }))
            .sort((a, b) => b.count - a.count),
    };
}

// Collects hash indicators from carvable files (extracted or carved). Each
// entry should expose a sha256/md5/sha1 and the source file name. Unknown
// hashes are skipped.
function collectHashIndicators(carvableFiles) {
    if (!Array.isArray(carvableFiles)) return [];
    const byHash = new Map();
    for (const entry of carvableFiles) {
        if (!entry || typeof entry !== "object") continue;
        const hashValues = {
            sha256: safeString(entry.sha256 || entry["sha256"] || "").trim().toLowerCase(),
            sha1: safeString(entry.sha1 || entry["sha1"] || "").trim().toLowerCase(),
            md5: safeString(entry.md5 || entry["md5"] || "").trim().toLowerCase(),
        };
        const label = safeString(entry.fileName || entry.label || entry.name || "extracted").trim() || "extracted";
        for (const [algo, hash] of Object.entries(hashValues)) {
            if (!hash) continue;
            if (!/^[a-f0-9]{16,128}$/.test(hash)) continue;
            const key = `${algo}:${hash}`;
            const existing = byHash.get(key);
            if (existing) {
                existing.sources.push(label);
            } else {
                byHash.set(key, {
                    algorithm: algo,
                    hash,
                    sources: [label],
                    bytes: Number.isFinite(Number(entry.byteLength)) ? Number(entry.byteLength) : null,
                });
            }
        }
    }
    return Array.from(byHash.values());
}

// Iterates over all per-target threat intel lookups (current state + any
// accumulated across the session). Exposes a normalized array of records.
function collectReputationIndicators(threatIntelState, sessionThreatIntel) {
    const records = [];
    const seenTargets = new Set();

    function pushRecord(source, target, type, payload) {
        if (!target) return;
        const key = `${type}:${target.toLowerCase()}`;
        if (seenTargets.has(key)) return;
        seenTargets.add(key);
        records.push({ source, target, type, payload });
    }

    if (threatIntelState && typeof threatIntelState === "object") {
        const { ipsum, tor, virustotal } = threatIntelState;
        if (ipsum && ipsum.success !== false) {
            pushRecord("ipsum", ipsum.ip, "ip", ipsum);
        }
        if (tor && tor.success !== false) {
            pushRecord("tor", tor.ip, "ip", tor);
        }
        if (virustotal && virustotal.success !== false) {
            const target = virustotal.lookupValue || virustotal.ip || "";
            const type = virustotal.lookupType || "ip";
            pushRecord("virustotal", target, type, virustotal);
        }
    }

    if (Array.isArray(sessionThreatIntel)) {
        for (const entry of sessionThreatIntel) {
            if (!entry || typeof entry !== "object") continue;
            const { source, target, type, payload } = entry;
            if (!source || !target) continue;
            pushRecord(source, target, type || "ip", payload || entry);
        }
    }

    return records;
}

// Computes a Shannon entropy (bits per byte) over a Uint8Array. Mirrors
// the heuristic used by data-tools; defensive against non-Uint8Array input.
function calculateShannonEntropy(bytes) {
    if (!bytes || typeof bytes.length !== "number" || bytes.length === 0) return 0;
    const length = bytes.length;
    const counts = new Array(256).fill(0);
    // The input may be a Uint8Array OR an array-like with byte values; both
    // are addressable by index.
    for (let i = 0; i < length; i += 1) {
        const value = bytes[i];
        const idx = typeof value === "number" ? value : Number(value);
        if (!Number.isFinite(idx) || idx < 0 || idx > 255) continue;
        counts[idx] += 1;
    }
    let entropy = 0;
    for (let i = 0; i < 256; i += 1) {
        if (counts[i] === 0) continue;
        const p = counts[i] / length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

// Detects protocol-level anomalies from the captured packet stream. Each
// anomaly is returned as a structured object so the UI can render it and
// the scoring function can apply weights.
function detectProtocolAnomalies(capturedPackets) {
    const anomalies = [];
    if (!capturedPackets || typeof capturedPackets !== "object") return anomalies;

    let dnsLongNameCount = 0;
    let nonStandardPortCount = 0;
    let highDstConcentrationCount = 0;
    let beaconingFlows = 0;
    let unencryptedSensitiveOnPublicCount = 0;

    // Track per-(dst) packet sizes and counts for beaconing detection.
    const sizesByFlow = new Map();
    // Track per-(dst) destination IP packet counts.
    const countsByDst = new Map();
    let totalPackets = 0;
    let dstPortTotals = 0;

    for (const { packetInfo } of iterateCapturedPackets(capturedPackets)) {
        totalPackets += 1;
        const proto = getPacketProto(packetInfo);
        const dstIp = getPacketDestinationIp(packetInfo);
        const srcIp = getPacketSourceIp(packetInfo);
        const length = getPacketLength(packetInfo);
        const dstPort = getPacketDestinationPort(packetInfo, proto);
        const srcPort = getPacketSourcePort(packetInfo, proto);

        if (dstIp) {
            countsByDst.set(dstIp, (countsByDst.get(dstIp) || 0) + 1);
        }
        if (Number.isFinite(dstPort)) {
            dstPortTotals += 1;
            // Detect HTTP/SMTP/IMAP/etc on unusual ports.
            if ((proto === "HTTP" || proto === "TLS" || proto === "SMTP" || proto === "IMAP")
                && !NON_STANDARD_TCP_PORTS.has(dstPort)) {
                nonStandardPortCount += 1;
            }
            // Detect cleartext telnet/SSH on high ports (commonly tunneling
            // or scanner traffic).
            if ((proto === "TELNET" || proto === "SSH") && dstPort > 1024) {
                nonStandardPortCount += 1;
            }
        }

        if (proto === "DNS") {
            const name = getDnsQueryName(packetInfo);
            if (name && name.length > DNS_TUNNEL_LABEL_LENGTH_THRESHOLD) {
                dnsLongNameCount += 1;
            }
        }

        if (proto === "TELNET" || proto === "FTP" || proto === "HTTP") {
            if (dstIp && isPublicIpv4(dstIp)) {
                unencryptedSensitiveOnPublicCount += 1;
            }
        }

        if (Number.isFinite(dstPort) && length && length > 0) {
            const flowKey = `${srcIp || "?"}->${dstIp || "?"}:${dstPort}`;
            let entry = sizesByFlow.get(flowKey);
            if (!entry) {
                entry = { sizes: [], firstTs: null, lastTs: null };
                sizesByFlow.set(flowKey, entry);
            }
            entry.sizes.push(length);
            const ts = getPacketTimestamp(packetInfo);
            if (ts) {
                if (entry.firstTs === null) entry.firstTs = ts;
                entry.lastTs = ts;
            }
        }
    }

    if (dnsLongNameCount > 0) {
        anomalies.push({
            kind: "dns-tunneling-suspect",
            label: "Possible DNS tunneling",
            detail: `${dnsLongNameCount} DNS query name(s) exceeded ${DNS_TUNNEL_LABEL_LENGTH_THRESHOLD} characters.`,
            weight: WEIGHTS.protocolAnomalyDnsTunneling,
            occurrences: dnsLongNameCount,
        });
    }

    if (nonStandardPortCount > 0) {
        anomalies.push({
            kind: "non-standard-port",
            label: "Service on unusual port",
            detail: `${nonStandardPortCount} packet(s) used a non-standard port for their protocol.`,
            weight: WEIGHTS.protocolAnomalyNonStandardPort,
            occurrences: nonStandardPortCount,
        });
    }

    if (unencryptedSensitiveOnPublicCount > 0) {
        anomalies.push({
            kind: "cleartext-to-public",
            label: "Cleartext traffic to public host",
            detail: `${unencryptedSensitiveOnPublicCount} unencrypted packet(s) (Telnet/FTP/HTTP) targeted a public IP.`,
            weight: WEIGHTS.protocolAnomaly,
            occurrences: unencryptedSensitiveOnPublicCount,
        });
    }

    // Beaconing detection: a flow with many packets of similar size.
    for (const [flowKey, entry] of sizesByFlow.entries()) {
        if (entry.sizes.length < BEACONING_MIN_OCCURRENCES) continue;
        const uniqueSizes = new Set(entry.sizes);
        if (uniqueSizes.size < BEACONING_MIN_UNIQUE_SIZES) continue;
        const min = Math.min(...entry.sizes);
        const max = Math.max(...entry.sizes);
        if (max - min <= BEACONING_MAX_SIZE_VARIANCE) {
            beaconingFlows += 1;
        }
    }
    if (beaconingFlows > 0) {
        anomalies.push({
            kind: "beaconing-flow",
            label: "Possible beaconing",
            detail: `${beaconingFlows} flow(s) showed repeated similar-sized packets (potential C2 beaconing).`,
            weight: WEIGHTS.protocolAnomalyBeaconing,
            occurrences: beaconingFlows,
        });
    }

    // High destination concentration: a single dst IP that received a
    // disproportionate share of the traffic. Threshold: >50% of packets
    // going to a single public IP, with at least 50 packets observed.
    if (totalPackets > 0 && countsByDst.size > 0) {
        const top = Array.from(countsByDst.entries()).sort((a, b) => b[1] - a[1])[0];
        if (top && top[1] >= 50) {
            const share = top[1] / totalPackets;
            if (share > 0.5 && isPublicIpv4(top[0])) {
                anomalies.push({
                    kind: "single-destination-flood",
                    label: "Single-destination flood",
                    detail: `${top[1]}/${totalPackets} packets (${(share * 100).toFixed(1)}%) targeted ${top[0]}.`,
                    weight: WEIGHTS.protocolAnomaly,
                    occurrences: top[1],
                });
                highDstConcentrationCount = top[1];
            }
        }
    }

    return anomalies;
}

// Counts the "weight multiplier" applied when an indicator appears more
// than once. Returns 1 for single occurrences.
function repetitionMultiplier(occurrences) {
    if (!Number.isFinite(occurrences) || occurrences <= 1) return 1;
    return 1 + WEIGHTS.repeatedIndicatorMultiplier * Math.log10(occurrences);
}

// Aggregates everything into a single Session Threat Score. Returns a
// structured result that the UI can render in full.
function computeSessionThreatScore({
    capturedPackets = null,
    threatIntelState = null,
    sessionThreatIntel = null,
    carvableFiles = null,
    inputBytes = null,
} = {}) {
    const ipIndicators = collectIpIndicators(capturedPackets);
    const domainIndicators = collectDomainIndicators(capturedPackets);
    const hashIndicators = collectHashIndicators(carvableFiles);
    const reputationIndicators = collectReputationIndicators(threatIntelState, sessionThreatIntel);
    const anomalies = detectProtocolAnomalies(capturedPackets);

    const components = [];
    let rawScore = 0;

    // Reputation: per-target lookups (current + session)
    for (const record of reputationIndicators) {
        if (record.source === "ipsum") {
            const hitCount = Number(record.payload?.hitCount) || 0;
            const listed = Boolean(record.payload?.listed);
            if (listed) {
                const w = hitCount >= 5
                    ? WEIGHTS.ipsumListedWithManyHits
                    : WEIGHTS.ipsumListedHit;
                rawScore += w;
                components.push({
                    kind: "ip-reputation",
                    label: `IPSum listed ${record.target}`,
                    detail: hitCount > 0
                        ? `IP appears on ${hitCount} blocklist(s).`
                        : "IP appears on the IPSum blocklist.",
                    weight: w,
                });
            }
        } else if (record.source === "tor") {
            if (record.payload?.isExitNode) {
                const w = WEIGHTS.torExitNode;
                rawScore += w;
                components.push({
                    kind: "tor-exit",
                    label: `Tor exit node ${record.target}`,
                    detail: "Target is a known Tor exit relay.",
                    weight: w,
                });
            }
        } else if (record.source === "virustotal") {
            // Skip hash records here — file-hash hits are scored in the
            // dedicated file-hash loop below with their own (heavier) weight.
            if (record.type !== "hash") {
                const analysis = record.payload?.analysis || {};
                const malicious = Number(analysis.malicious) || 0;
                const suspicious = Number(analysis.suspicious) || 0;
                const harmless = Number(analysis.harmless) || 0;
                if (malicious > 0) {
                    const w = WEIGHTS.virustotalMaliciousVerdict;
                    rawScore += w;
                    components.push({
                        kind: "vt-malicious",
                        label: `VirusTotal malicious (${record.target})`,
                        detail: `${malicious} engine(s) flagged the target as malicious${suspicious > 0 ? ` (${suspicious} suspicious)` : ""}.`,
                        weight: w,
                    });
                }
                if (suspicious > 0 && malicious === 0) {
                    const w = WEIGHTS.virustotalSuspiciousVerdict;
                    rawScore += w;
                    components.push({
                        kind: "vt-suspicious",
                        label: `VirusTotal suspicious (${record.target})`,
                        detail: `${suspicious} engine(s) flagged the target as suspicious.`,
                        weight: w,
                    });
                }
                if (harmless > 0 && malicious === 0 && suspicious === 0) {
                    rawScore += WEIGHTS.virustotalHarmlessModifier;
                    components.push({
                        kind: "vt-harmless",
                        label: `VirusTotal harmless (${record.target})`,
                        detail: `${harmless} engine(s) considered the target harmless.`,
                        weight: WEIGHTS.virustotalHarmlessModifier,
                    });
                }
                const reputation = Number(record.payload?.reputation);
                if (Number.isFinite(reputation) && reputation < 0) {
                    const w = WEIGHTS.virustotalNegativeReputation;
                    rawScore += w;
                    components.push({
                        kind: "vt-negative-reputation",
                        label: `VirusTotal negative reputation (${record.target})`,
                        detail: `Reputation score ${reputation} (community-downvoted).`,
                        weight: w,
                    });
                }
            }
        }
    }

    // File-hash reputation (when the user has registered a carve or a
    // VirusTotal record surfaces malicious verdicts on a hash).
    const fileHashScore = new Map();
    for (const entry of hashIndicators) {
        const key = `${entry.algorithm}:${entry.hash}`;
        fileHashScore.set(key, entry);
    }
    for (const record of reputationIndicators) {
        if (record.source !== "virustotal") continue;
        if (record.type !== "hash") continue;
        const hash = String(record.payload?.lookupValue || record.target || "").trim().toLowerCase();
        if (!hash) continue;
        const analysis = record.payload?.analysis || {};
        const malicious = Number(analysis.malicious) || 0;
        const suspicious = Number(analysis.suspicious) || 0;
        if (malicious > 0) {
            const w = WEIGHTS.fileHashMalicious;
            rawScore += w;
            components.push({
                kind: "file-hash-malicious",
                label: `File hash flagged malicious (${hash.slice(0, 12)}...)`,
                detail: `${malicious} engine(s) flagged this hash.`,
                weight: w,
            });
        } else if (suspicious > 0) {
            const w = WEIGHTS.fileHashSuspicious;
            rawScore += w;
            components.push({
                kind: "file-hash-suspicious",
                label: `File hash flagged suspicious (${hash.slice(0, 12)}...)`,
                detail: `${suspicious} engine(s) flagged this hash.`,
                weight: w,
            });
        }
    }

    // Indicator frequency: public IPs and domains that appear many times
    // weigh more than one-shot hits. This is purely about repetition within
    // the capture (a single DNS query is normal; 200 of the same name is
    // suspect).
    const topPublicIps = ipIndicators.publicIps.slice(0, 5);
    for (const entry of topPublicIps) {
        if (entry.count < 25) continue; // ignore short-lived chatter
        const mult = repetitionMultiplier(entry.count);
        const w = Math.round(2 * mult);
        if (w <= 0) continue;
        rawScore += w;
        components.push({
            kind: "frequent-public-ip",
            label: `Frequent public IP ${entry.ip}`,
            detail: `Appears in ${entry.count} packet(s).`,
            weight: w,
        });
    }
    const topDomains = domainIndicators.domains.slice(0, 5);
    for (const entry of topDomains) {
        if (entry.count < 25) continue;
        const mult = repetitionMultiplier(entry.count);
        const w = Math.round(2 * mult);
        if (w <= 0) continue;
        rawScore += w;
        components.push({
            kind: "frequent-domain",
            label: `Frequent domain ${entry.domain}`,
            detail: `Appears in ${entry.count} packet(s).`,
            weight: w,
        });
    }

    // Embedded / obfuscated data via Shannon entropy of the current Conv
    // input. If the input is small (< 32 bytes) we do not penalize.
    let entropy = 0;
    let entropyLabel = "Unknown";
    if (inputBytes && typeof inputBytes.length === "number" && inputBytes.length >= 32) {
        entropy = calculateShannonEntropy(inputBytes);
        if (entropy >= HIGH_ENTROPY_THRESHOLD) {
            const w = WEIGHTS.embeddedEntropyHigh;
            rawScore += w;
            components.push({
                kind: "embedded-entropy-high",
                label: "Heavily embedded/obfuscated data",
                detail: `Shannon entropy ${entropy.toFixed(2)} bits/byte (>= ${HIGH_ENTROPY_THRESHOLD}).`,
                weight: w,
            });
            entropyLabel = "High";
        } else if (entropy >= MEDIUM_ENTROPY_THRESHOLD) {
            const w = WEIGHTS.embeddedEntropyMedium;
            rawScore += w;
            components.push({
                kind: "embedded-entropy-medium",
                label: "Possibly obfuscated data",
                detail: `Shannon entropy ${entropy.toFixed(2)} bits/byte (>= ${MEDIUM_ENTROPY_THRESHOLD}).`,
                weight: w,
            });
            entropyLabel = "Medium";
        } else {
            entropyLabel = entropy > 0 ? "Low" : "Unknown";
        }
    }

    // Protocol anomalies
    for (const anomaly of anomalies) {
        rawScore += anomaly.weight;
        components.push({
            kind: anomaly.kind,
            label: anomaly.label,
            detail: anomaly.detail,
            weight: anomaly.weight,
        });
    }

    const finalScore = clampScore(rawScore);
    const band = SCORE_BANDS.find((b) => finalScore >= b.min && finalScore <= b.max) || SCORE_BANDS[0];

    return {
        version: HEURISTIC_SCORE_VERSION,
        generatedAt: new Date().toISOString(),
        score: finalScore,
        maxScore: MAX_SCORE,
        band: band.name,
        bandColor: band.color,
        bandDescription: band.description,
        components: components.sort((a, b) => b.weight - a.weight),
        indicators: {
            ips: {
                total: ipIndicators.all.length,
                publicCount: ipIndicators.publicIps.length,
                topPublic: ipIndicators.publicIps.slice(0, 10),
            },
            domains: {
                total: domainIndicators.domains.length,
                top: domainIndicators.domains.slice(0, 10),
            },
            urls: {
                total: domainIndicators.urls.length,
                top: domainIndicators.urls.slice(0, 10),
            },
            hashes: {
                total: hashIndicators.length,
                entries: hashIndicators,
            },
            reputationLookups: reputationIndicators.length,
            anomalies: anomalies.length,
        },
        entropy: {
            value: Number(entropy.toFixed(2)),
            label: entropyLabel,
            highThreshold: HIGH_ENTROPY_THRESHOLD,
            mediumThreshold: MEDIUM_ENTROPY_THRESHOLD,
        },
    };
}

// Builds a compact Markdown report summarizing the session threat score and
// its components. Designed to be readable as a one-page brief.
function buildSessionThreatScoreBreakdown(scoreResult) {
    if (!scoreResult || typeof scoreResult !== "object") return "";
    const lines = [];
    lines.push(`# Session Threat Score: ${scoreResult.score} / ${scoreResult.maxScore} (${scoreResult.band})`);
    lines.push("");
    lines.push(scoreResult.bandDescription || "");
    lines.push("");
    if (Array.isArray(scoreResult.components) && scoreResult.components.length > 0) {
        lines.push("## Top contributing indicators");
        for (const c of scoreResult.components.slice(0, 10)) {
            const w = c.weight > 0 ? `+${c.weight}` : `${c.weight}`;
            lines.push(`- [${w}] **${c.label}** — ${c.detail}`);
        }
        lines.push("");
    } else {
        lines.push("## No risk indicators triggered");
        lines.push("- All reputation lookups, repeated indicators, and protocol heuristics came back clean.");
        lines.push("");
    }
    const ind = scoreResult.indicators || {};
    lines.push("## Capture footprint");
    lines.push(`- Public IPs observed: ${ind?.ips?.publicCount ?? 0} (top: ${(ind?.ips?.topPublic || []).slice(0, 3).map((p) => p.ip).join(", ") || "none"})`);
    lines.push(`- Unique domains observed: ${ind?.domains?.total ?? 0}`);
    lines.push(`- URLs observed: ${ind?.urls?.total ?? 0}`);
    lines.push(`- File hashes registered: ${ind?.hashes?.total ?? 0}`);
    lines.push(`- Reputation lookups completed: ${ind?.reputationLookups ?? 0}`);
    lines.push(`- Protocol anomalies: ${ind?.anomalies ?? 0}`);
    lines.push(`- Current Conv input entropy: ${scoreResult.entropy?.value ?? "?"} bits/byte (${scoreResult.entropy?.label ?? "Unknown"})`);
    return lines.join("\n");
}

// Builds a concise Ollama prompt. The LLM is offered as an *advisory*
// narrative on top of the deterministic score; the prompt asks for a short
// paragraph plus a list of up to 5 concrete next actions.
function buildSessionThreatLlmPrompt(scoreResult) {
    if (!scoreResult || typeof scoreResult !== "object") return "";
    const compact = {
        score: scoreResult.score,
        band: scoreResult.band,
        indicators: scoreResult.indicators,
        entropy: scoreResult.entropy,
        // Cap the components to top 10 so the prompt fits in the model's
        // context window.
        topComponents: (scoreResult.components || []).slice(0, 10).map((c) => ({
            kind: c.kind,
            label: c.label,
            detail: c.detail,
            weight: c.weight,
        })),
    };
    return [
        "You are PacketSnitch, a network-forensics assistant.",
        "Given the deterministic Session Threat Score breakdown below, write a SHORT analyst narrative (max ~400 chars) and a list of up to 5 concrete next actions.",
        "Do not invent data; only use the JSON provided. Do not change the numeric score. If everything is clean, say so plainly.",
        "",
        "Session Threat Score (JSON):",
        JSON.stringify(compact, null, 2),
    ].join("\n");
}

// Public API. Helpers used by the unit tests are exported as well.
const api = {
    HEURISTIC_SCORE_VERSION,
    MAX_SCORE,
    SCORE_BANDS,
    WEIGHTS,
    HIGH_ENTROPY_THRESHOLD,
    MEDIUM_ENTROPY_THRESHOLD,
    calculateShannonEntropy,
    collectIpIndicators,
    collectDomainIndicators,
    collectHashIndicators,
    collectReputationIndicators,
    detectProtocolAnomalies,
    computeSessionThreatScore,
    buildSessionThreatScoreBreakdown,
    buildSessionThreatLlmPrompt,
    isPublicIpv4,
    isLikelyDomain,
    normalizeDomain,
};

if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
}

if (typeof globalThis !== "undefined") {
    // Expose to the renderer's `window` scope when loaded as a plain script.
    globalThis.PacketSnitchThreatIntel = api;
}
