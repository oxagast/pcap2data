// Tests for the Threat Intel scorer module.
//
// Verifies the deterministic Session Threat Score aggregation:
//   * Empty capture => score 0, Clean band.
//   * Each reputation lookup (IPSum, Tor, VirusTotal) adds the documented
//     weight and surfaces a component for the UI to render.
//   * File-hash hits (carved/extracted file with a malicious VT verdict)
//     are weighted heavily.
//   * Frequency weighting scales with `log10(occurrences)`.
//   * High-entropy Conv input lifts the score into the High band.
//   * Protocol anomalies (DNS tunneling, beaconing, non-standard ports,
//     single-destination flood) contribute to the score.
//   * Score is clamped to [0, 100] and bands are exclusive.

const path = require("path");

const MODULE_PATH = path.join(
    __dirname,
    "..",
    "src",
    "ui",
    "panels",
    "threat-intel-scorer.js",
);

const scorer = require(MODULE_PATH);

const {
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
} = scorer;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makePacket(packetInfo, host = "host-a") {
    return {
        "packet.info": packetInfo,
        "host": host,
    };
}

function ipv4Packet({ src, dst, proto = "IP", srcPort, dstPort, length = 64, dnsName, httpHost, requestUri, ts = 1 } = {}) {
    const info = {
        "packet.proto": proto,
        "packet.timestamp": ts,
        "packet.len": length,
    };
    if (src || dst) {
        info["IP"] = {};
        if (src) info["IP"]["ip.src.addr"] = src;
        if (dst) info["IP"]["ip.dst.addr"] = dst;
    }
    if (proto === "TCP" || proto === "UDP") {
        info[proto] = {};
        if (srcPort !== undefined) info[proto][proto === "TCP" ? "tcp.src.port" : "udp.srcport"] = srcPort;
        if (dstPort !== undefined) info[proto][proto === "TCP" ? "tcp.dst.port" : "udp.dstport"] = dstPort;
    }
    if (dnsName) info["DNS"] = { "dns.qry.name": dnsName };
    if (httpHost) info["HTTP"] = { "http.host": httpHost };
    if (requestUri) info["HTTP"] = { "http.host": httpHost || "example.com", "http.request.uri": requestUri };
    return makePacket(info);
}

function capturedPacketsFromList(list) {
    return { host: { "host-a": list } };
}

// Builds an array of `count` IPv4 packets going from a unique source to a
// single destination. Used for repetition-based scoring tests.
function makeRepeatedIpTraffic(dstIp, count, { srcPrefix = "10.0.0." } = {}) {
    const packets = [];
    for (let i = 0; i < count; i += 1) {
        packets.push(ipv4Packet({ src: `${srcPrefix}${i % 255}`, dst: dstIp, length: 100 }));
    }
    return packets;
}

// ---------------------------------------------------------------------------
// Score-band math
// ---------------------------------------------------------------------------

describe("score-band math", () => {
    test("MAX_SCORE is 100 and bands are sorted ascending", () => {
        expect(MAX_SCORE).toBe(100);
        expect(SCORE_BANDS.length).toBe(5);
        for (let i = 1; i < SCORE_BANDS.length; i += 1) {
            const prev = SCORE_BANDS[i - 1];
            const next = SCORE_BANDS[i];
            expect(next.min).toBeGreaterThan(prev.max);
        }
    });

    test("empty capture => score 0 / Clean", () => {
        const result = computeSessionThreatScore({});
        expect(result.score).toBe(0);
        expect(result.band).toBe("Clean");
        expect(result.components).toEqual([]);
    });

    test("score clamps to MAX_SCORE for absurd inputs", () => {
        // Forge a session where many components would push the score past 100.
        const reputation = [];
        for (let i = 0; i < 20; i += 1) {
            reputation.push({
                source: "virustotal",
                target: `file-${i}.bin`,
                type: "hash",
                payload: {
                    lookupValue: `${i.toString(16).padStart(64, "0")}`,
                    analysis: { malicious: 10, suspicious: 5 },
                },
            });
        }
        const result = computeSessionThreatScore({ sessionThreatIntel: reputation });
        expect(result.score).toBeLessThanOrEqual(MAX_SCORE);
    });

    test("score never goes negative even with VirusTotal harmless pulls", () => {
        const state = {
            virustotal: {
                ip: "8.8.8.8",
                lookupType: "ip",
                lookupValue: "8.8.8.8",
                success: true,
                analysis: { malicious: 0, suspicious: 0, harmless: 50 },
            },
        };
        const result = computeSessionThreatScore({ threatIntelState: state });
        expect(result.score).toBeGreaterThanOrEqual(0);
    });
});

// ---------------------------------------------------------------------------
// Reputation indicators
// ---------------------------------------------------------------------------

describe("reputation indicators", () => {
    test("IPSum listed IP adds the documented weight", () => {
        const result = computeSessionThreatScore({
            threatIntelState: {
                ipsum: { ip: "203.0.113.45", success: true, listed: true, hitCount: 1 },
            },
        });
        expect(result.score).toBe(WEIGHTS.ipsumListedHit);
        const comp = result.components.find((c) => c.kind === "ip-reputation");
        expect(comp).toBeDefined();
        expect(comp.weight).toBe(WEIGHTS.ipsumListedHit);
    });

    test("IPSum listed IP with >=5 blocklists adds the higher weight", () => {
        const result = computeSessionThreatScore({
            threatIntelState: {
                ipsum: { ip: "203.0.113.45", success: true, listed: true, hitCount: 8 },
            },
        });
        expect(result.score).toBe(WEIGHTS.ipsumListedWithManyHits);
    });

    test("Tor exit node adds the Tor weight", () => {
        const result = computeSessionThreatScore({
            threatIntelState: {
                tor: { ip: "185.220.101.1", success: true, isExitNode: true },
            },
        });
        expect(result.score).toBe(WEIGHTS.torExitNode);
        expect(result.components.some((c) => c.kind === "tor-exit")).toBe(true);
    });

    test("VirusTotal malicious verdict for an IP adds the documented weight (Low band)", () => {
        const result = computeSessionThreatScore({
            threatIntelState: {
                virustotal: {
                    ip: "203.0.113.99",
                    lookupType: "ip",
                    lookupValue: "203.0.113.99",
                    success: true,
                    analysis: { malicious: 12, suspicious: 0, harmless: 0 },
                },
            },
        });
        expect(result.score).toBe(WEIGHTS.virustotalMaliciousVerdict);
        // The IP-malicious weight alone lives in the Low band.
        expect(result.band).toBe("Low");
    });

    test("VirusTotal suspicious-only verdict adds the lower weight (harmless is suppressed)", () => {
        const result = computeSessionThreatScore({
            threatIntelState: {
                virustotal: {
                    ip: "203.0.113.99",
                    lookupType: "ip",
                    lookupValue: "203.0.113.99",
                    success: true,
                    analysis: { malicious: 0, suspicious: 4, harmless: 30 },
                },
            },
        });
        // With suspicious > 0 the harmless modifier is NOT applied; only the
        // suspicious weight is added.
        expect(result.score).toBe(WEIGHTS.virustotalSuspiciousVerdict);
    });

    test("VirusTotal only-harmless verdict does not lift the score", () => {
        // The harmless modifier is negative, but the score is clamped to 0
        // (so the user never sees a "negative threat").
        const result = computeSessionThreatScore({
            threatIntelState: {
                virustotal: {
                    ip: "203.0.113.99",
                    lookupType: "ip",
                    lookupValue: "203.0.113.99",
                    success: true,
                    analysis: { malicious: 0, suspicious: 0, harmless: 50 },
                },
            },
        });
        expect(result.score).toBe(0);
        expect(result.band).toBe("Clean");
        expect(result.components.some((c) => c.kind === "vt-harmless")).toBe(true);
    });

    test("VirusTotal negative reputation adds its own component", () => {
        const result = computeSessionThreatScore({
            threatIntelState: {
                virustotal: {
                    ip: "203.0.113.99",
                    lookupType: "ip",
                    lookupValue: "203.0.113.99",
                    success: true,
                    analysis: { malicious: 0, suspicious: 0, harmless: 0 },
                    reputation: -25,
                },
            },
        });
        expect(result.score).toBe(WEIGHTS.virustotalNegativeReputation);
    });

    test("file-hash malicious verdict is weighted heavier than IP-malicous", () => {
        const ipResult = computeSessionThreatScore({
            threatIntelState: {
                virustotal: {
                    ip: "203.0.113.99",
                    lookupType: "ip",
                    lookupValue: "203.0.113.99",
                    success: true,
                    analysis: { malicious: 10, suspicious: 0 },
                },
            },
        });
        const hashResult = computeSessionThreatScore({
            sessionThreatIntel: [
                {
                    source: "virustotal",
                    target: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    type: "hash",
                    payload: {
                        lookupValue: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                        analysis: { malicious: 10, suspicious: 0 },
                    },
                },
            ],
        });
        expect(WEIGHTS.fileHashMalicious).toBeGreaterThan(WEIGHTS.virustotalMaliciousVerdict);
        expect(hashResult.score).toBe(WEIGHTS.fileHashMalicious);
        expect(hashResult.score).toBeGreaterThan(ipResult.score);
    });

    test("session-wide records are deduplicated by target", () => {
        const records = [
            {
                source: "ipsum",
                target: "203.0.113.50",
                type: "ip",
                payload: { listed: true, hitCount: 2 },
            },
            {
                source: "ipsum",
                target: "203.0.113.50",
                type: "ip",
                payload: { listed: true, hitCount: 99 },
            },
        ];
        const indicators = collectReputationIndicators({}, records);
        // De-duplicated by `type:target`
        expect(indicators.length).toBe(1);
    });
});

// ---------------------------------------------------------------------------
// IP / domain / hash collection
// ---------------------------------------------------------------------------

describe("indicator collection", () => {
    test("collectIpIndicators separates public from private IPs", () => {
        const packets = [
            ipv4Packet({ src: "192.168.1.10", dst: "8.8.8.8" }),
            ipv4Packet({ src: "192.168.1.10", dst: "8.8.8.8" }),
            ipv4Packet({ src: "192.168.1.10", dst: "10.0.0.5" }),
            ipv4Packet({ src: "192.168.1.10", dst: "172.16.5.5" }),
        ];
        const result = collectIpIndicators(capturedPacketsFromList(packets));
        expect(result.publicIps.find((e) => e.ip === "8.8.8.8")).toBeDefined();
        expect(result.publicIps.find((e) => e.ip === "10.0.0.5")).toBeUndefined();
        expect(result.publicIps.find((e) => e.ip === "172.16.5.5")).toBeUndefined();
        expect(result.publicIps.find((e) => e.ip === "192.168.1.10")).toBeUndefined();
    });

    test("collectDomainIndicators pulls DNS query names and HTTP hosts", () => {
        const packets = [
            ipv4Packet({ dst: "8.8.8.8", proto: "DNS", dnsName: "example.com" }),
            ipv4Packet({ dst: "8.8.8.8", proto: "DNS", dnsName: "EXAMPLE.com" }),
            ipv4Packet({ dst: "8.8.8.8", proto: "HTTP", httpHost: "example.org" }),
            ipv4Packet({ dst: "8.8.8.8", proto: "HTTP", httpHost: "example.org", requestUri: "https://example.org/path?q=1" }),
        ];
        const result = collectDomainIndicators(capturedPacketsFromList(packets));
        const domains = result.domains.map((d) => d.domain);
        expect(domains).toContain("example.com");
        expect(domains).toContain("example.org");
        expect(result.urls.some((u) => u.url.startsWith("https://example.org"))).toBe(true);
        // example.com appears twice -> count >= 2
        const exampleCom = result.domains.find((d) => d.domain === "example.com");
        expect(exampleCom.count).toBe(2);
    });

    test("collectHashIndicators normalizes hashes and tracks sources", () => {
        const carvable = [
            {
                fileName: "doc.pdf",
                sha256: "AbCdEf1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890",
                byteLength: 12345,
            },
            {
                fileName: "img.png",
                md5: "DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            },
        ];
        const result = collectHashIndicators(carvable);
        expect(result.length).toBe(2);
        const sha = result.find((h) => h.algorithm === "sha256");
        expect(sha.hash).toBe(sha.hash.toLowerCase());
        expect(sha.sources).toContain("doc.pdf");
    });

    test("isPublicIpv4 rejects RFC1918, loopback, link-local, and CGNAT ranges", () => {
        expect(isPublicIpv4("8.8.8.8")).toBe(true);
        expect(isPublicIpv4("1.1.1.1")).toBe(true);
        expect(isPublicIpv4("192.168.1.1")).toBe(false);
        expect(isPublicIpv4("10.0.0.1")).toBe(false);
        expect(isPublicIpv4("172.16.5.5")).toBe(false);
        expect(isPublicIpv4("172.31.255.255")).toBe(false);
        expect(isPublicIpv4("172.32.0.0")).toBe(true);
        expect(isPublicIpv4("127.0.0.1")).toBe(false);
        expect(isPublicIpv4("169.254.0.1")).toBe(false);
        expect(isPublicIpv4("100.64.0.1")).toBe(false); // CGNAT
        expect(isPublicIpv4("224.0.0.1")).toBe(false); // multicast
        expect(isPublicIpv4("not-an-ip")).toBe(false);
    });

    test("isLikelyDomain accepts normal domains and rejects junk", () => {
        expect(isLikelyDomain("example.com")).toBe(true);
        expect(isLikelyDomain("a.b.c.example.com")).toBe(true);
        expect(isLikelyDomain("EXAMPLE.com")).toBe(true);
        expect(isLikelyDomain("123")).toBe(false);
        expect(isLikelyDomain("192.168.1.1")).toBe(false);
        expect(isLikelyDomain("no spaces here")).toBe(false);
        expect(isLikelyDomain("no-tld")).toBe(false);
    });

    test("normalizeDomain lowercases and trims trailing dots", () => {
        expect(normalizeDomain("  Example.COM.  ")).toBe("example.com");
        expect(normalizeDomain("foo.BAR")).toBe("foo.bar");
        expect(normalizeDomain(null)).toBe("");
    });
});

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------

describe("calculateShannonEntropy", () => {
    test("returns 0 for empty input", () => {
        expect(calculateShannonEntropy(new Uint8Array(0))).toBe(0);
        expect(calculateShannonEntropy(null)).toBe(0);
    });

    test("returns 0 for uniform single-byte input", () => {
        const buf = new Uint8Array(64).fill(0);
        expect(calculateShannonEntropy(buf)).toBe(0);
    });

    test("returns ~8 for uniformly random bytes", () => {
        // Deterministic LCG so the test is reproducible without a RNG.
        const buf = new Uint8Array(8192);
        let state = 12345;
        for (let i = 0; i < buf.length; i += 1) {
            // Numerical Recipes LCG: good enough distribution for an entropy test.
            state = (state * 1664525 + 1013904223) >>> 0;
            buf[i] = state & 0xff;
        }
        const entropy = calculateShannonEntropy(buf);
        expect(entropy).toBeGreaterThan(7.5);
        expect(entropy).toBeLessThanOrEqual(8);
    });

    test("entropy above HIGH threshold triggers High band scoring", () => {
        const buf = new Uint8Array(2048);
        for (let i = 0; i < buf.length; i += 1) {
            buf[i] = (i * 37) & 0xff;
        }
        const entropy = calculateShannonEntropy(buf);
        const result = computeSessionThreatScore({ inputBytes: buf });
        if (entropy >= HIGH_ENTROPY_THRESHOLD) {
            expect(result.entropy.label).toBe("High");
            expect(result.components.some((c) => c.kind === "embedded-entropy-high")).toBe(true);
        }
    });

    test("small input (< 32 bytes) is ignored even if uniformly random", () => {
        const buf = new Uint8Array(16);
        for (let i = 0; i < buf.length; i += 1) {
            buf[i] = i;
        }
        const result = computeSessionThreatScore({ inputBytes: buf });
        expect(result.entropy.label).toBe("Unknown");
        expect(result.components.some((c) => c.kind === "embedded-entropy-high")).toBe(false);
        expect(result.components.some((c) => c.kind === "embedded-entropy-medium")).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// Protocol anomalies
// ---------------------------------------------------------------------------

describe("detectProtocolAnomalies", () => {
    test("returns an empty array for no captured packets", () => {
        expect(detectProtocolAnomalies(null)).toEqual([]);
        expect(detectProtocolAnomalies({})).toEqual([]);
    });

    test("flags DNS tunneling when query name exceeds threshold", () => {
        const longName = "a".repeat(120) + ".example.com";
        const packets = [
            ipv4Packet({ dst: "8.8.8.8", proto: "DNS", dnsName: longName, length: 80 }),
            ipv4Packet({ dst: "8.8.8.8", proto: "DNS", dnsName: longName, length: 80 }),
        ];
        const result = detectProtocolAnomalies(capturedPacketsFromList(packets));
        expect(result.some((a) => a.kind === "dns-tunneling-suspect")).toBe(true);
    });

    test("flags beaconing when one flow has many similar-sized packets", () => {
        const packets = [];
        // 12 packets, sizes {100, 110, 120, 130} -> 4 unique sizes, max-min=30 <= 32
        const sizes = [100, 110, 120, 130];
        for (let i = 0; i < 12; i += 1) {
            packets.push(
                ipv4Packet({
                    src: "10.0.0.5",
                    dst: "203.0.113.7",
                    proto: "TCP",
                    srcPort: 40000,
                    dstPort: 443,
                    length: sizes[i % sizes.length],
                    ts: 1000 + i,
                }),
            );
        }
        const result = detectProtocolAnomalies(capturedPacketsFromList(packets));
        expect(result.some((a) => a.kind === "beaconing-flow")).toBe(true);
    });

    test("flags single-destination flood when 1 IP gets >50% of packets", () => {
        const packets = [];
        for (let i = 0; i < 80; i += 1) {
            packets.push(
                ipv4Packet({ src: `10.0.0.${i % 10}`, dst: "203.0.113.10", length: 64 }),
            );
        }
        const result = detectProtocolThreatHelper(packets);
        expect(result.some((a) => a.kind === "single-destination-flood")).toBe(true);
    });

    test("flags cleartext traffic to public IPs", () => {
        const packets = [
            ipv4Packet({ src: "10.0.0.5", dst: "203.0.113.20", proto: "TELNET", srcPort: 50000, dstPort: 23, length: 80 }),
        ];
        const result = detectProtocolAnomalies(capturedPacketsFromList(packets));
        expect(result.some((a) => a.kind === "cleartext-to-public")).toBe(true);
    });

    test("flags non-standard ports for HTTP/TLS/SMTP/IMAP", () => {
        // Real packets carry BOTH an L4 protocol (TCP/UDP) and an application
        // protocol (HTTP/TLS/SMTP/IMAP). For the scorer, the application
        // protocol drives the anomaly decision and the L4 protocol decides
        // where to look up ports.
        const packets = [
            {
                "packet.info": {
                    "packet.proto": "HTTP",
                    "packet.timestamp": 1,
                    "packet.len": 200,
                    "IP": { "ip.src.addr": "10.0.0.5", "ip.dst.addr": "203.0.113.30" },
                    "TCP": { "tcp.src.port": 50000, "tcp.dst.port": 8081 },
                },
            },
        ];
        const result = detectProtocolAnomalies(capturedPacketsFromList(packets));
        expect(result.some((a) => a.kind === "non-standard-port")).toBe(true);
    });
});

// Tiny helper used by the single-destination flood test to keep the describe
// block above readable.
function detectProtocolThreatHelper(packets) {
    return detectProtocolAnomalies(capturedPacketsFromList(packets));
}

// ---------------------------------------------------------------------------
// Frequency weighting
// ---------------------------------------------------------------------------

describe("frequency weighting", () => {
    test("public IP appearing >=25 times contributes a frequent-IP component", () => {
        const packets = makeRepeatedIpTraffic("203.0.113.50", 50);
        const result = computeSessionThreatScore({ capturedPackets: capturedPacketsFromList(packets) });
        expect(result.components.some((c) => c.kind === "frequent-public-ip")).toBe(true);
        const comp = result.components.find((c) => c.kind === "frequent-public-ip");
        expect(comp.weight).toBeGreaterThanOrEqual(2);
        expect(comp.detail).toContain("50 packet");
    });

    test("repetition multiplier grows with log10(occurrences)", () => {
        const packets30 = makeRepeatedIpTraffic("203.0.113.60", 30);
        const packets300 = makeRepeatedIpTraffic("203.0.113.61", 300);
        const result30 = computeSessionThreatScore({ capturedPackets: capturedPacketsFromList(packets30) });
        const result300 = computeSessionThreatScore({ capturedPackets: capturedPacketsFromList(packets300) });
        const c30 = result30.components.find((c) => c.kind === "frequent-public-ip");
        const c300 = result300.components.find((c) => c.kind === "frequent-public-ip");
        expect(c30).toBeDefined();
        expect(c300).toBeDefined();
        expect(c300.weight).toBeGreaterThan(c30.weight);
    });
});

// ---------------------------------------------------------------------------
// End-to-end score aggregation
// ---------------------------------------------------------------------------

describe("end-to-end score", () => {
    test("a single malicious file hash lifts the capture into Medium or higher", () => {
        const result = computeSessionThreatScore({
            carvableFiles: [
                {
                    fileName: "evil.bin",
                    sha256: "deadbeef".repeat(8),
                },
            ],
            sessionThreatIntel: [
                {
                    source: "virustotal",
                    target: "deadbeef".repeat(8),
                    type: "hash",
                    payload: {
                        lookupValue: "deadbeef".repeat(8),
                        analysis: { malicious: 8, suspicious: 0 },
                    },
                },
            ],
        });
        // File-hash-malicous weight alone (22) lands in the Medium band.
        expect(result.score).toBeGreaterThanOrEqual(WEIGHTS.fileHashMalicious);
        expect(["Medium", "High", "Critical"]).toContain(result.band);
    });

    test("a malicious file hash combined with high-entropy input lands in High/Critical", () => {
        // High-entropy input bumps the score into High band on top of the
        // file-hash-malicous component.
        const highEntropy = new Uint8Array(4096);
        let state = 99;
        for (let i = 0; i < highEntropy.length; i += 1) {
            state = (state * 1664525 + 1013904223) >>> 0;
            highEntropy[i] = state & 0xff;
        }
        const result = computeSessionThreatScore({
            inputBytes: highEntropy,
            carvableFiles: [{ fileName: "evil.bin", sha256: "deadbeef".repeat(8) }],
            sessionThreatIntel: [
                {
                    source: "virustotal",
                    target: "deadbeef".repeat(8),
                    type: "hash",
                    payload: {
                        lookupValue: "deadbeef".repeat(8),
                        analysis: { malicious: 8, suspicious: 0 },
                    },
                },
                {
                    source: "ipsum",
                    target: "203.0.113.50",
                    type: "ip",
                    payload: { listed: true, hitCount: 8 },
                },
            ],
        });
        expect(result.score).toBeGreaterThanOrEqual(50);
        expect(["High", "Critical"]).toContain(result.band);
    });

    test("combined reputation + anomaly + entropy yields higher score than any single signal", () => {
        // Capture with a few reputation hits, an obvious DNS-tunneling packet,
        // and a high-entropy Conv input.
        const longDns = "b".repeat(80) + ".example.com";
        const packets = [
            ipv4Packet({ dst: "8.8.8.8", proto: "DNS", dnsName: longDns, length: 80 }),
            ipv4Packet({ dst: "203.0.113.5", proto: "TELNET", srcPort: 50000, dstPort: 23, length: 80 }),
        ];
        const highEntropy = new Uint8Array(2048);
        let state = 7;
        for (let i = 0; i < highEntropy.length; i += 1) {
            state = (state * 1664525 + 1013904223) >>> 0;
            highEntropy[i] = state & 0xff;
        }
        const onlyAnomalies = computeSessionThreatScore({
            capturedPackets: capturedPacketsFromList(packets),
            inputBytes: highEntropy,
        });
        const onlyReputation = computeSessionThreatScore({
            threatIntelState: {
                ipsum: { ip: "203.0.113.5", success: true, listed: true, hitCount: 6 },
                tor: { ip: "203.0.113.5", success: true, isExitNode: true },
                virustotal: {
                    ip: "203.0.113.5",
                    lookupType: "ip",
                    lookupValue: "203.0.113.5",
                    success: true,
                    analysis: { malicious: 6, suspicious: 0 },
                },
            },
        });
        const combined = computeSessionThreatScore({
            capturedPackets: capturedPacketsFromList(packets),
            inputBytes: highEntropy,
            threatIntelState: {
                ipsum: { ip: "203.0.113.5", success: true, listed: true, hitCount: 6 },
                tor: { ip: "203.0.113.5", success: true, isExitNode: true },
                virustotal: {
                    ip: "203.0.113.5",
                    lookupType: "ip",
                    lookupValue: "203.0.113.5",
                    success: true,
                    analysis: { malicious: 6, suspicious: 0 },
                },
            },
        });
        expect(combined.score).toBeGreaterThanOrEqual(onlyAnomalies.score);
        expect(combined.score).toBeGreaterThanOrEqual(onlyReputation.score);
        expect(combined.band).toBe(SCORE_BANDS.find((b) => combined.score >= b.min && combined.score <= b.max).name);
    });

    test("result includes a stable version, generatedAt, and entropy metadata", () => {
        const result = computeSessionThreatScore({});
        expect(result.version).toBe(HEURISTIC_SCORE_VERSION);
        expect(result.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
        expect(result.maxScore).toBe(MAX_SCORE);
        expect(result.entropy.highThreshold).toBe(HIGH_ENTROPY_THRESHOLD);
        expect(result.entropy.mediumThreshold).toBe(MEDIUM_ENTROPY_THRESHOLD);
        expect(result.indicators).toBeDefined();
    });
});

// ---------------------------------------------------------------------------
// Breakdown + LLM prompt builders
// ---------------------------------------------------------------------------

describe("report builders", () => {
    test("buildSessionThreatScoreBreakdown returns empty string for null input", () => {
        expect(buildSessionThreatScoreBreakdown(null)).toBe("");
        expect(buildSessionThreatScoreBreakdown(undefined)).toBe("");
    });

    test("breakdown mentions score, band, and component details", () => {
        const result = computeSessionThreatScore({
            threatIntelState: {
                virustotal: {
                    ip: "203.0.113.99",
                    lookupType: "ip",
                    lookupValue: "203.0.113.99",
                    success: true,
                    analysis: { malicious: 4, suspicious: 0 },
                },
            },
        });
        const md = buildSessionThreatScoreBreakdown(result);
        expect(md).toContain(`Session Threat Score: ${result.score}`);
        expect(md).toContain(result.band);
        expect(md).toContain("VirusTotal malicious");
        expect(md).toContain("Capture footprint");
    });

    test("buildSessionThreatLlmPrompt embeds JSON and stays human-readable", () => {
        const result = computeSessionThreatScore({
            threatIntelState: {
                ipsum: { ip: "203.0.113.5", success: true, listed: true, hitCount: 2 },
            },
        });
        const prompt = buildSessionThreatLlmPrompt(result);
        expect(prompt).toContain("PacketSnitch");
        expect(prompt).toContain("Session Threat Score");
        expect(prompt).toContain(JSON.stringify(result.score));
    });

    test("breakdown for an empty capture is short and says 'No risk indicators triggered'", () => {
        const result = computeSessionThreatScore({});
        const md = buildSessionThreatScoreBreakdown(result);
        expect(md).toContain("No risk indicators triggered");
    });
});
