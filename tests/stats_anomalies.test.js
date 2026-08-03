// Tests for the Stats → Anomalies subtab detectors.
//
// The Stats panel's Anomalies subtab reuses the protocol-anomaly
// detector from src/ui/panels/threat-intel-scorer.js and adds four
// additional pure detectors:
//
//   detectStatsAnomaliesPortscan
//   detectStatsAnomaliesBruteForce
//   detectStatsAnomaliesBaselineOutliers
//   detectStatsAnomaliesEmbeddedContent
//
// These tests build synthetic captured-packets trees in the same
// shape the panel consumes, run the detectors, and assert the
// structured findings. They intentionally avoid DOM access — the
// detectors are pure functions of the packet tree.

const path = require("path");

const STATS_PANEL_PATH = path.join(
  __dirname,
  "..",
  "src",
  "ui",
  "panels",
  "stats-panel.js",
);
const SETTINGS_PATH = path.join(__dirname, "..", "src", "settings.js");

function freshRequireStatsPanel() {
  delete require.cache[require.resolve(SETTINGS_PATH)];
  delete require.cache[require.resolve(STATS_PANEL_PATH)];
  return require(STATS_PANEL_PATH);
}

function makePacket({
  proto,
  src,
  dst,
  srcPort = 40000,
  dstPort = 80,
  length = 200,
  flags = null,
  timestamp = 1_700_000_000,
  dnsName = null,
  httpUri = null,
  httpAuth = null,
  kerberosRealm = null,
  decodedSection = null,
}) {
  // The brute-force detector ports auth protocols (SSH, FTP, etc.) by
  // looking up tcp.dst.port on the TCP transport section. In the real
  // wire shape those protocols still expose their TCP ports, so the
  // helper always attaches a TCP/UDP section unless the caller
  // explicitly named UDP.
  //
  // When `decodedSection` is set, the packet mimics the Python
  // backend's wire shape: packet.proto stays as "TCP" and the decoded
  // application protocol (e.g. "FTP") is mounted under the transport
  // section. This is the shape produced for real FTP/SMTP/IMAP/POP3/
  // Kerberos/Telnet packets.
  const isUdp = proto === "UDP";
  const pi = {
    "packet.proto": proto,
    IP: { "ip.src.addr": src, "ip.dst.addr": dst },
    ...(isUdp
      ? { UDP: { "udp.srcport": srcPort, "udp.dstport": dstPort } }
      : {
          TCP: {
            "tcp.src.port": srcPort,
            "tcp.dst.port": dstPort,
            ...(flags ? { "tcp.flags": flags } : {}),
            ...(decodedSection && typeof decodedSection === "object"
              ? { [decodedSection.name]: decodedSection.payload || {} }
              : {}),
          },
        }),
  };
  if (Number.isFinite(length)) pi["packet.len"] = length;
  // Accept numeric or string timestamps — the Python backend writes
  // timestamps as space-separated UTC strings ("2002-06-18 02:12:11.010076").
  if (timestamp !== null && timestamp !== undefined && timestamp !== "") {
    pi["packet.timestamp"] = timestamp;
  }
  if (dnsName) {
    pi.DNS = { "dns.qry.name": dnsName };
    pi["packet.proto"] = "DNS";
  }
  if (httpUri || httpAuth) {
    const http = {};
    if (httpUri) http["http.request.uri"] = httpUri;
    if (httpAuth) http["http.authorization"] = httpAuth;
    pi.HTTP = http;
    pi["packet.proto"] = "HTTP";
  }
  if (kerberosRealm) {
    pi.Kerberos = { "kerberos.realm": kerberosRealm };
    pi["packet.proto"] = "KERBEROS";
  }
  return { "packet.info": pi };
}

function wrapPackets(packets) {
  return { host: { "test-host": packets } };
}

describe("stats anomalies subtab detectors", () => {
  let panel;
  beforeAll(() => {
    panel = freshRequireStatsPanel();
  });

  test("exports the new detectors and aggregate collector", () => {
    expect(typeof panel.collectStatsAnomalies).toBe("function");
    expect(typeof panel.detectStatsAnomaliesPortscan).toBe("function");
    expect(typeof panel.detectStatsAnomaliesBruteForce).toBe("function");
    expect(typeof panel.detectStatsAnomaliesBaselineOutliers).toBe("function");
    expect(typeof panel.detectStatsAnomaliesEmbeddedContent).toBe("function");
  });

  test("portscan detector flags a single source sweeping many ports", () => {
    const packets = [];
    for (let port = 1; port <= 40; port += 1) {
      packets.push(
        makePacket({
          proto: "TCP",
          src: "10.0.0.5",
          dst: "10.0.0.99",
          srcPort: 51000 + port,
          dstPort: port,
          length: 60,
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesPortscan(wrapPackets(packets));
    expect(findings.length).toBe(1);
    const finding = findings[0];
    expect(finding.kind).toMatch(/^portscan-/);
    expect(finding.target).toBe("10.0.0.5");
    expect(finding.occurrences).toBeGreaterThanOrEqual(30);
    expect(finding.query).toContain("ip.src.addr: 10.0.0.5");
  });

  test("portscan detector flags a SYN-heavy scan separately", () => {
    const packets = [];
    for (let port = 1; port <= 60; port += 1) {
      packets.push(
        makePacket({
          proto: "TCP",
          src: "10.0.0.5",
          dst: "10.0.0.99",
          srcPort: 51000,
          dstPort: port,
          length: 60,
          flags: "S",
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesPortscan(wrapPackets(packets));
    expect(findings.length).toBe(1);
    expect(findings[0].kind).toBe("portscan-syn");
    expect(findings[0].weight).toBeGreaterThanOrEqual(7);
  });

  test("portscan detector ignores short port flurries", () => {
    const packets = [];
    for (let port = 1; port <= 10; port += 1) {
      packets.push(
        makePacket({
          proto: "TCP",
          src: "10.0.0.5",
          dst: "10.0.0.99",
          srcPort: 51000,
          dstPort: port,
          length: 60,
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesPortscan(wrapPackets(packets));
    expect(findings).toEqual([]);
  });

  test("portscan detector flags a 29-port scan below the old 30-packet threshold", () => {
    // Regression test: a real nmap-style scan of 29 distinct ports
    // should still fire. The previous MIN_PACKETS=30 threshold
    // missed scans of 29 ports/packets, leaving small but real
    // recon invisible in the Anomalies panel.
    const packets = [];
    for (let port = 1; port <= 29; port += 1) {
      packets.push(
        makePacket({
          proto: "TCP",
          src: "10.100.25.14",
          dst: "10.100.18.12",
          srcPort: 51000,
          dstPort: port,
          length: 60,
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesPortscan(wrapPackets(packets));
    expect(findings.length).toBe(1);
    expect(findings[0].target).toBe("10.100.25.14");
    expect(findings[0].kind).toMatch(/^portscan-/);
  });

  test("brute-force detector flags an SSH password-guessing burst", () => {
    const packets = [];
    // The detector treats numeric timestamps as UNIX-seconds unless
    // they are > 1e12 (assumed to be UNIX-ms). We use UNIX-ms here so
    // 12 attempts spaced 1s apart clearly fit inside the 60s window.
    const baseMs = 1_700_000_000_000;
    for (let i = 0; i < 12; i += 1) {
      packets.push(
        makePacket({
          proto: "SSH",
          src: "10.0.0.5",
          dst: "10.0.0.99",
          srcPort: 51000 + i,
          dstPort: 22,
          timestamp: baseMs + i * 1_000,
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
    expect(findings.length).toBe(1);
    expect(findings[0].kind).toBe("brute-force-login");
    expect(findings[0].target).toBe("10.0.0.99");
    expect(findings[0].query).toContain("ip.dst.addr: 10.0.0.99");
  });

  test("brute-force detector does not flag low-volume auth traffic", () => {
    const packets = [];
    for (let i = 0; i < 3; i += 1) {
      packets.push(
        makePacket({
          proto: "SSH",
          src: "10.0.0.5",
          dst: "10.0.0.99",
          srcPort: 51000 + i,
          dstPort: 22,
          timestamp: 1_700_000_000 + i * 1_000,
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
    expect(findings).toEqual([]);
  });

  test("brute-force detector flags an FTP password-cracking burst", () => {
    const packets = [];
    // FTP password guessing: 10 USER/PASS attempts to a single FTP
    // server inside the 60s window. The detector should bucket these
    // by (proto, dst, dstPort) and emit a brute-force-login finding.
    const baseMs = 1_700_000_000_000;
    for (let i = 0; i < 10; i += 1) {
      packets.push(
        makePacket({
          proto: "FTP",
          src: "203.0.113.7",
          dst: "10.0.0.42",
          srcPort: 51000 + i,
          dstPort: 21,
          timestamp: baseMs + i * 1_500,
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
    expect(findings.length).toBe(1);
    const finding = findings[0];
    expect(finding.kind).toBe("brute-force-login");
    expect(finding.target).toBe("10.0.0.42");
    expect(finding.label).toContain("FTP");
    expect(finding.query).toContain("ip.dst.addr: 10.0.0.42");
    expect(finding.query).toContain("packet.proto: FTP");
    expect(finding.occurrences).toBeGreaterThanOrEqual(6);
  });

  test("brute-force detector flags an FTP crack in real wire shape (TCP + nested FTP section)", () => {
    // The Python backend decodes FTP into packetInfo["TCP"]["FTP"]
    // and leaves packet.proto as "TCP". This regression test guards
    // against the detector missing FTP brute-force in real captures.
    const packets = [];
    const baseMs = 1_700_000_000_000;
    for (let i = 0; i < 10; i += 1) {
      packets.push(
        makePacket({
          proto: "TCP",
          src: "203.0.113.7",
          dst: "10.0.0.42",
          srcPort: 51000 + i,
          dstPort: 21,
          timestamp: baseMs + i * 1_500,
          decodedSection: { name: "FTP", payload: { "ftp.request.command": "PASS" } },
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
    expect(findings.length).toBe(1);
    const finding = findings[0];
    expect(finding.kind).toBe("brute-force-login");
    expect(finding.target).toBe("10.0.0.42");
    expect(finding.label).toContain("FTP");
    expect(finding.query).toContain("packet.proto: FTP");
  });

  test("brute-force detector surfaces distinct FTP vs SSH attempts separately", () => {
    // An FTP crack and an SSH crack to different targets should each
    // become their own finding (not collapse into one).
    const packets = [];
    const baseMs = 1_700_000_000_000;
    for (let i = 0; i < 8; i += 1) {
      packets.push(
        makePacket({
          proto: "FTP",
          src: "203.0.113.7",
          dst: "10.0.0.42",
          srcPort: 51000 + i,
          dstPort: 21,
          timestamp: baseMs + i * 1_000,
        }),
      );
      packets.push(
        makePacket({
          proto: "SSH",
          src: "203.0.113.7",
          dst: "10.0.0.77",
          srcPort: 52000 + i,
          dstPort: 22,
          timestamp: baseMs + i * 1_000,
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
    expect(findings.length).toBe(2);
    const protos = findings.map((f) => f.query.match(/packet\.proto: (\w+)/)[1]).sort();
    expect(protos).toEqual(["FTP", "SSH"]);
  });

  test.each([
    ["SMTP", 25],
    ["IMAP", 143],
    ["POP3", 110],
  ])(
    "brute-force detector flags %s password-cracking bursts",
    (proto, dstPort) => {
      const packets = [];
      const baseMs = 1_700_000_000_000;
      for (let i = 0; i < 8; i += 1) {
        packets.push(
          makePacket({
            proto,
            src: "203.0.113.7",
            dst: "10.0.0.42",
            srcPort: 51000 + i,
            dstPort,
            timestamp: baseMs + i * 1_500,
          }),
        );
      }
      const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
      expect(findings.length).toBe(1);
      const finding = findings[0];
      expect(finding.kind).toBe("brute-force-login");
      expect(finding.target).toBe("10.0.0.42");
      expect(finding.label).toContain(proto);
      expect(finding.query).toContain(`packet.proto: ${proto}`);
      expect(finding.occurrences).toBeGreaterThanOrEqual(6);
    },
  );

  test("brute-force detector flags HTTP basic-auth password cracking", () => {
    // HTTP packets carrying an Authorization header should be treated
    // as an auth-bearing flow even when the transport section reports
    // a plain TCP packet. The detector pulls the header from
    // packetInfo.HTTP["http.authorization"].
    const packets = [];
    const baseMs = 1_700_000_000_000;
    for (let i = 0; i < 9; i += 1) {
      packets.push(
        makePacket({
          proto: "TCP",
          src: "203.0.113.7",
          dst: "10.0.0.42",
          srcPort: 51000 + i,
          dstPort: 80,
          timestamp: baseMs + i * 1_000,
          httpAuth: `Basic dXNlcg${i}OnR5cGU=`,
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
    expect(findings.length).toBe(1);
    const finding = findings[0];
    expect(finding.kind).toBe("brute-force-login");
    expect(finding.target).toBe("10.0.0.42");
    expect(findings[0].query).toContain("ip.dst.addr: 10.0.0.42");
    expect(finding.occurrences).toBeGreaterThanOrEqual(6);
  });

  test("brute-force detector does not flag low-volume auth traffic across auth protocols", () => {
    // 3 attempts of each auth-bearing protocol is well below the 6-attempt
    // threshold, so nothing should fire — even if every protocol is
    // represented.
    const packets = [];
    const baseMs = 1_700_000_000_000;
    const scenarios = [
      { proto: "SSH", port: 22 },
      { proto: "FTP", port: 21 },
      { proto: "TELNET", port: 23 },
      { proto: "SMTP", port: 25 },
      { proto: "IMAP", port: 143 },
      { proto: "POP3", port: 110 },
    ];
    for (const s of scenarios) {
      for (let i = 0; i < 3; i += 1) {
        packets.push(
          makePacket({
            proto: s.proto,
            src: "203.0.113.7",
            dst: "10.0.0.42",
            srcPort: 51000 + i,
            dstPort: s.port,
            timestamp: baseMs + i * 1_000,
          }),
        );
      }
    }
    const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
    expect(findings).toEqual([]);
  });

  test("brute-force detector flags Kerberos AS-REQ password bursts", () => {
    const packets = [];
    const baseMs = 1_700_000_000_000;
    for (let i = 0; i < 7; i += 1) {
      packets.push(
        makePacket({
          proto: "KERBEROS",
          src: "203.0.113.7",
          dst: "10.0.0.42",
          srcPort: 51000 + i,
          dstPort: 88,
          timestamp: baseMs + i * 1_500,
          kerberosRealm: "EXAMPLE.COM",
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
    expect(findings.length).toBe(1);
    const finding = findings[0];
    expect(finding.kind).toBe("brute-force-login");
    expect(finding.label).toContain("KERBEROS");
  });

  test.each([
    ["SMTP", "smtp.req.command", 25],
    ["IMAP", "imap.request.command", 143],
    ["POP3", "pop3.request.command", 110],
    ["Kerberos", "kerberos.realm", 88],
  ])(
    "brute-force detector flags %s password-cracking in real wire shape (TCP + nested section)",
    (sectionName, fieldKey, dstPort) => {
      // Real wire shape: packet.proto = "TCP", decoded protocol
      // nested under TCP[sectionName].
      const packets = [];
      const baseMs = 1_700_000_000_000;
      const payload = {};
      payload[fieldKey] = "AUTH payload";
      for (let i = 0; i < 8; i += 1) {
        packets.push(
          makePacket({
            proto: "TCP",
            src: "203.0.113.7",
            dst: "10.0.0.42",
            srcPort: 51000 + i,
            dstPort,
            timestamp: baseMs + i * 1_500,
            decodedSection: { name: sectionName, payload },
          }),
        );
      }
      const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
      expect(findings.length).toBe(1);
      const finding = findings[0];
      expect(finding.kind).toBe("brute-force-login");
      expect(finding.target).toBe("10.0.0.42");
      // The label should advertise the decoded application protocol
      // (FTP, SMTP, IMAP, POP3, KERBEROS) — not the transport "TCP".
      expect(finding.label).not.toMatch(/\(TCP\)/);
      expect(finding.label).toContain("10.0.0.42");
    },
  );

  test("brute-force detector parses Python backend ISO-string timestamps", () => {
    // The Python backend writes packet.timestamp as a
    // space-separated UTC string (e.g. "2002-06-18 02:12:11.010076"),
    // not a UNIX number. Without string-aware parsing, every
    // timestamp resolves to null and no bucket ever trips the
    // minimum-attempts threshold.
    const packets = [];
    // 8 attempts spaced 1.5s apart, ISO-string timestamps.
    const base = new Date("2002-06-18T02:12:11Z").getTime();
    for (let i = 0; i < 8; i += 1) {
      const isoTs = new Date(base + i * 1_500).toISOString().replace("T", " ").replace("Z", "");
      packets.push(
        makePacket({
          proto: "FTP",
          src: "203.0.113.7",
          dst: "10.0.0.42",
          srcPort: 51000 + i,
          dstPort: 21,
          timestamp: isoTs,
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
    expect(findings.length).toBe(1);
    const finding = findings[0];
    expect(finding.kind).toBe("brute-force-login");
    expect(finding.occurrences).toBeGreaterThanOrEqual(6);
  });

  test("brute-force detector collapses ephemeral-port noise into one bucket", () => {
    // An attacker using a new ephemeral source port for every
    // attempt should produce ONE finding, not one per ephemeral
    // port. Server→client response packets on random ephemeral
    // ports should not add their own buckets either.
    const packets = [];
    const baseMs = 1_700_000_000_000;
    for (let i = 0; i < 12; i += 1) {
      packets.push(
        makePacket({
          proto: "FTP",
          src: "203.0.113.7",
          dst: "10.0.0.42",
          srcPort: 40000 + i, // distinct ephemeral port per attempt
          dstPort: 21,
          timestamp: baseMs + i * 1_500,
        }),
      );
      // Server-side response on the same ephemeral port
      packets.push(
        makePacket({
          proto: "FTP",
          src: "10.0.0.42",
          dst: "203.0.113.7",
          srcPort: 21,
          dstPort: 40000 + i,
          timestamp: baseMs + i * 1_500 + 50,
        }),
      );
    }
    const findings = panel.detectStatsAnomaliesBruteForce(wrapPackets(packets));
    // Only the attacker→server flow should produce a finding; the
    // server→client responses are not "attempts" so they should
    // not create their own (smaller) buckets.
    expect(findings.length).toBe(1);
    expect(findings[0].target).toBe("10.0.0.42");
    expect(findings[0].label).toContain("10.0.0.42:21");
  });

  test("baseline outlier detector flags a single oversized packet for a protocol", () => {
    const packets = [];
    // 30 normal HTTP packets around 200 bytes, then one 4KB outlier.
    for (let i = 0; i < 30; i += 1) {
      packets.push(
        makePacket({
          proto: "HTTP",
          src: "10.0.0.5",
          dst: "10.0.0.99",
          length: 200,
        }),
      );
    }
    packets.push(
      makePacket({
        proto: "HTTP",
        src: "10.0.0.5",
        dst: "10.0.0.99",
        length: 4000,
      }),
    );
    const findings = panel.detectStatsAnomaliesBaselineOutliers(wrapPackets(packets));
    expect(findings.length).toBeGreaterThan(0);
    const labelFinding = findings.find((f) =>
      f.kind === "baseline-packet-length-outlier",
    );
    expect(labelFinding).toBeDefined();
    expect(labelFinding.label).toContain("HTTP");
  });

  test("embedded content detector flags high-entropy cleartext payloads", () => {
    // 64 bytes of pseudo-random-ish characters; entropy should be high.
    const random = "aZ7gP0eHqXcVmY2lKbR9uTn8WfDhJxSvC3pLrQ5yMtBnF4sUv";
    const packets = [
      makePacket({
        proto: "DNS",
        src: "10.0.0.5",
        dst: "10.0.0.99",
        dnsName: random,
      }),
    ];
    const findings = panel.detectStatsAnomaliesEmbeddedContent(wrapPackets(packets));
    expect(findings.length).toBe(1);
    expect(findings[0].kind).toBe("cleartext-high-entropy");
  });

  test("embedded content detector ignores low-entropy cleartext payloads", () => {
    const packets = [
      makePacket({
        proto: "DNS",
        src: "10.0.0.5",
        dst: "10.0.0.99",
        dnsName: "example.com",
      }),
    ];
    const findings = panel.detectStatsAnomaliesEmbeddedContent(wrapPackets(packets));
    expect(findings).toEqual([]);
  });

  test("collectStatsAnomalies returns the expected aggregate shape", () => {
    const aggregated = panel.collectStatsAnomalies(wrapPackets([]));
    expect(aggregated).toEqual({
      protocolAnomalies: [],
      portscans: [],
      bruteForce: [],
      baselineOutliers: [],
      embeddedContent: [],
      totalCount: 0,
    });
  });

  test("collectStatsAnomalies survives an undefined input", () => {
    const aggregated = panel.collectStatsAnomalies(undefined);
    expect(aggregated.totalCount).toBe(0);
    expect(aggregated.protocolAnomalies).toEqual([]);
  });
});
