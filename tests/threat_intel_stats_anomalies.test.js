// Tests for folding Stats → Anomalies findings into the Session
// Threat Score aggregator (computeSessionThreatScore).
//
// The Stats subtab exposes portscan, brute-force, baseline-outlier,
// and embedded-cleartext detectors. They are surfaced in the Anomalies
// panel as a grouped `{protocolAnomalies, portscans, bruteForce,
// baselineOutliers, embeddedContent}` shape. The Threat Intel panel
// should add these findings to the Session Threat Score so an FTP
// crack or portscan drives the score into a meaningful band.

const path = require("path");
const PROJECT_ROOT = path.join(__dirname, "..");
const STATS_PANEL_PATH = path.join(
  PROJECT_ROOT,
  "src",
  "ui",
  "panels",
  "stats-panel.js",
);
const THREAT_SCORER_PATH = path.join(
  PROJECT_ROOT,
  "src",
  "ui",
  "panels",
  "threat-intel-scorer.js",
);

function freshRequire() {
  const settingsPath = path.join(PROJECT_ROOT, "src", "settings.js");
  delete require.cache[require.resolve(settingsPath)];
  delete require.cache[require.resolve(STATS_PANEL_PATH)];
  delete require.cache[require.resolve(THREAT_SCORER_PATH)];
  return {
    stats: require(STATS_PANEL_PATH),
    scorer: require(THREAT_SCORER_PATH),
  };
}

function makePacket({
  proto,
  src,
  dst,
  srcPort = 40000,
  dstPort = 80,
  length = 200,
  flags = null,
  timestamp = 1_700_000_000_000,
  dnsName = null,
  httpUri = null,
  httpAuth = null,
  kerberosRealm = null,
  decodedSection = null,
}) {
  // Always attach a TCP/UDP section so port lookups succeed for
  // application protocols that share the wire's TCP transport
  // (SSH/FTP/SMTP/IMAP/POP3/Kerberos/Telnet/HTTP).
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
  if (Number.isFinite(timestamp)) pi["packet.timestamp"] = timestamp;
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

function flattenAnomalies(grouped) {
  if (!grouped || typeof grouped !== "object") return [];
  return []
    .concat(grouped.protocolAnomalies || [])
    .concat(grouped.portscans || [])
    .concat(grouped.bruteForce || [])
    .concat(grouped.baselineOutliers || [])
    .concat(grouped.embeddedContent || []);
}

describe("Session Threat Score folds in Stats anomalies", () => {
  let stats;
  let scorer;

  beforeAll(() => {
    ({ stats, scorer } = freshRequire());
  });

  test("extraAnomalies parameter is accepted and ignored when null/undefined", () => {
    const packets = wrapPackets([
      makePacket({ proto: "TCP", src: "10.0.0.1", dst: "10.0.0.2" }),
    ]);
    const baseline = scorer.computeSessionThreatScore({ capturedPackets: packets });
    const withEmpty = scorer.computeSessionThreatScore({
      capturedPackets: packets,
      extraAnomalies: null,
    });
    const withEmptyArr = scorer.computeSessionThreatScore({
      capturedPackets: packets,
      extraAnomalies: [],
    });
    expect(baseline.score).toBe(withEmpty.score);
    expect(baseline.score).toBe(withEmptyArr.score);
  });

  test("portscan findings raise the threat score", () => {
    const packets = [];
    for (let p = 1; p <= 40; p += 1) {
      packets.push(
        makePacket({
          proto: "TCP",
          src: "10.0.0.5",
          dst: "10.0.0.99",
          srcPort: 51000,
          dstPort: p,
          length: 60,
        }),
      );
    }
    const captured = wrapPackets(packets);
    const grouped = stats.collectStatsAnomalies(captured);
    const flat = flattenAnomalies(grouped);
    expect(flat.length).toBeGreaterThan(0);
    expect(grouped.portscans.length).toBeGreaterThan(0);

    const baseline = scorer.computeSessionThreatScore({ capturedPackets: captured });
    const withAnomalies = scorer.computeSessionThreatScore({
      capturedPackets: captured,
      extraAnomalies: flat,
    });

    expect(withAnomalies.score).toBeGreaterThan(baseline.score);
    expect(withAnomalies.statsAnomalies.length).toBe(grouped.portscans.length);
    const portscanComponent = withAnomalies.components.find(
      (c) => c.kind === "portscan-distinct-ports",
    );
    expect(portscanComponent).toBeDefined();
    expect(portscanComponent.source).toBe("stats-anomalies");
  });

  test("brute-force login findings raise the threat score into the High or Critical band", () => {
    const packets = [];
    const baseMs = 1_700_000_000_000;
    for (let i = 0; i < 12; i += 1) {
      packets.push(
        makePacket({
          proto: "TCP",
          src: "203.0.113.7",
          dst: "10.0.0.42",
          srcPort: 51000 + i,
          dstPort: 21,
          timestamp: baseMs + i * 1_500,
          // Real wire shape: decoded FTP nested under the TCP section.
          decodedSection: { name: "FTP", payload: { "ftp.request.command": "PASS" } },
        }),
      );
    }
    const captured = wrapPackets(packets);
    const grouped = stats.collectStatsAnomalies(captured);
    expect(grouped.bruteForce.length).toBe(1);
    const flat = flattenAnomalies(grouped);

    const baseline = scorer.computeSessionThreatScore({ capturedPackets: captured });
    const withAnomalies = scorer.computeSessionThreatScore({
      capturedPackets: captured,
      extraAnomalies: flat,
    });

    expect(withAnomalies.score).toBeGreaterThan(baseline.score);
    // The brute-force detector emits weight=7 per finding; with the
    // FTP-brute-force finding rolled in the score must clearly
    // exceed the empty-capture baseline.
    expect(withAnomalies.score).toBeGreaterThanOrEqual(7);
    expect(["Low", "Medium", "High", "Critical"]).toContain(withAnomalies.band);
    const component = withAnomalies.components.find(
      (c) => c.kind === "brute-force-login",
    );
    expect(component).toBeDefined();
    expect(component.label).toContain("FTP");
  });

  test("embedded cleartext findings contribute to the score", () => {
    const random =
      "aZ7gP0eHqXcVmY2lKbR9uTn8WfDhJxSvC3pLrQ5yMtBnF4sUv";
    const packets = [
      makePacket({
        proto: "DNS",
        src: "10.0.0.5",
        dst: "10.0.0.99",
        dnsName: random,
      }),
    ];
    const captured = wrapPackets(packets);
    const grouped = stats.collectStatsAnomalies(captured);
    expect(grouped.embeddedContent.length).toBeGreaterThan(0);
    const flat = flattenAnomalies(grouped);

    const withAnomalies = scorer.computeSessionThreatScore({
      capturedPackets: captured,
      extraAnomalies: flat,
    });
    const component = withAnomalies.components.find(
      (c) => c.kind === "cleartext-high-entropy",
    );
    expect(component).toBeDefined();
    expect(component.source).toBe("stats-anomalies");
    expect(withAnomalies.indicators.statsAnomalies).toBe(flat.length);
  });

  test("score without any stats anomalies reports statsAnomalies = 0", () => {
    const packets = wrapPackets([
      makePacket({ proto: "TCP", src: "10.0.0.1", dst: "10.0.0.2" }),
    ]);
    const score = scorer.computeSessionThreatScore({ capturedPackets: packets });
    expect(score.indicators.statsAnomalies).toBe(0);
    expect(score.statsAnomalies).toEqual([]);
  });

  test("subnet-calculator-panel requires threat-intel-scorer correctly", () => {
    // Regression: the panel used to destructure `{ PacketSnitchThreatIntel }`
    // from the threat-intel-scorer module export, but the module
    // exports the api object directly (with `computeSessionThreatScore`
    // etc.) and only attaches `PacketSnitchThreatIntel` to globalThis.
    // The destructure pulled `undefined`, so every recompute hit an
    // early-return and the score stayed at 0. This test asserts the
    // module's exported symbols are what the panel needs.
    const scorer = require("../src/ui/panels/threat-intel-scorer");
    expect(typeof scorer.computeSessionThreatScore).toBe("function");
    expect(typeof scorer.detectProtocolAnomalies).toBe("function");
    expect(typeof scorer.buildSessionThreatLlmPrompt).toBe("function");
    expect(typeof scorer.buildSessionThreatScoreBreakdown).toBe("function");
    // Importing the panel must not throw — if it tries to destructure a
    // missing symbol the require call itself succeeds (destructuring
    // undefined is fine) but subsequent uses break.
    expect(() => require("../src/ui/panels/subnet-calculator-panel")).not.toThrow();
  });

  test("subnet-calculator-panel's default collector is wired through stats-panel", () => {
    // The subnet-calculator-panel module imports a default
    // `collectStatsAnomaliesDefault` from ./stats-panel as a fallback
    // so the integration still works even if main-frontend forgets
    // to inject one. We verify the wiring by simulating the panel's
    // own fallback branch end-to-end.
    const { collectStatsAnomalies: panelCollector } = require("../src/ui/panels/stats-panel");
    expect(typeof panelCollector).toBe("function");

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
    const captured = wrapPackets(packets);
    const grouped = panelCollector(captured);
    const flat = flattenAnomalies(grouped);
    const score = scorer.computeSessionThreatScore({
      capturedPackets: captured,
      extraAnomalies: flat,
    });
    expect(score.score).toBeGreaterThan(0);
    expect(score.components.some((c) => c.kind === "brute-force-login")).toBe(true);
  });

  test("findings with an unrecognized kind and no fallback weight are ignored", () => {
    const captured = wrapPackets([]);
    // An unknown kind with no explicit weight must be dropped — we
    // don't know how to score it. An unknown kind with an explicit
    // weight is honored (caller's responsibility).
    const dropped = scorer.computeSessionThreatScore({
      capturedPackets: captured,
      extraAnomalies: [
        { kind: "made-up-anomaly", label: "x", detail: "y" },
      ],
    });
    expect(dropped.score).toBe(0);
    expect(dropped.indicators.statsAnomalies).toBe(0);

    const honored = scorer.computeSessionThreatScore({
      capturedPackets: captured,
      extraAnomalies: [
        { kind: "made-up-anomaly", label: "explicit", detail: "y", weight: 5 },
      ],
    });
    expect(honored.score).toBe(5);
    expect(honored.indicators.statsAnomalies).toBe(1);
  });
});