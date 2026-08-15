// Controls the Crypt workspace UI for decryption, TLS, and PGP workflows.


const crypto = require("crypto-browserify");
const openpgp = require("openpgp");

// Use Node's native crypto in Electron renderer contexts so that TLS
// certificate validation, RSA-OAEP-SHA256 decryption, and key-log-based
// symmetric decryption work correctly. crypto-browserify (via public-encrypt)
// hard-codes OAEP to SHA-1 and lacks X509Certificate/createPublicKey, so it
// cannot perform any of these operations.
function getNativeCryptoApi() {
  return window.cryptoapi && typeof window.cryptoapi.privateDecrypt === "function"
    ? window.cryptoapi
    : null;
}

function logCryptoApiVersion() {
  const api = getNativeCryptoApi();
  if (api && api.__version) {
    writeLogEntry(`[Crypt] native crypto bridge version="${api.__version}"`);
  }
}

// Expose a safe key-object type probe to help diagnose mismatched PEMs.
function getKeyObjectKind(pem) {
  const api = getNativeCryptoApi();
  if (!api) return "unknown";
  try {
    api.getPublicKeyFromCertificatePem(pem);
    return "certificate";
  } catch (_) { }
  try {
    api.getPublicKeyFromPrivateKeyPem(pem);
    return "key";
  } catch (err) {
    return `unparseable (${err.message})`;
  }
}

const TLS_CONTENT_TYPE_MIN = 20;
const TLS_CONTENT_TYPE_MAX = 23;
const TLS_RECORD_TYPE_HANDSHAKE = 22;
const TLS_RECORD_TYPE_ALERT = 21;
const TLS_RECORD_TYPE_APPLICATION_DATA = 23;
const TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC = 20;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 1;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO = 2;
const TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16;
const TLS_HANDSHAKE_TYPE_FINISHED = 20;
const TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8;
const TLS_HANDSHAKE_TYPE_CERTIFICATE = 11;
const TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15;
const TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4;
const TLS_VERSION_1_2 = 0x0303;
const TLS_VERSION_1_3 = 0x0304;
const TLS_CIPHER_SUITES = {
  // TLS 1.3 suites (key length 32, iv length 12)
  'TLS_AES_128_GCM_SHA256': { keyLen: 16, ivLen: 12, aead: 'aes-128-gcm', hash: 'sha256', isTls13: true },
  'TLS_AES_256_GCM_SHA384': { keyLen: 32, ivLen: 12, aead: 'aes-256-gcm', hash: 'sha384', isTls13: true },
  'TLS_CHACHA20_POLY1305_SHA256': { keyLen: 32, ivLen: 12, aead: 'chacha20-poly1305', hash: 'sha256', isTls13: true },
  // TLS 1.2 suites
  'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256': { keyLen: 16, ivLen: 4, aead: 'aes-128-gcm', hash: 'sha256', isTls13: false },
  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256': { keyLen: 16, ivLen: 4, aead: 'aes-128-gcm', hash: 'sha256', isTls13: false },
  'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384': { keyLen: 32, ivLen: 4, aead: 'aes-256-gcm', hash: 'sha384', isTls13: false },
  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384': { keyLen: 32, ivLen: 4, aead: 'aes-256-gcm', hash: 'sha384', isTls13: false },
  'TLS_RSA_WITH_AES_128_CBC_SHA256': { keyLen: 16, ivLen: 16, aead: 'aes-128-cbc-hmac-sha256', hash: 'sha256', isTls13: false },
  'TLS_RSA_WITH_AES_256_CBC_SHA256': { keyLen: 32, ivLen: 16, aead: 'aes-256-cbc-hmac-sha256', hash: 'sha256', isTls13: false },
  'TLS_RSA_WITH_AES_128_CBC_SHA': { keyLen: 16, ivLen: 16, aead: 'aes-128-cbc-hmac-sha1', hash: 'sha1', isTls13: false },
  'TLS_RSA_WITH_AES_256_CBC_SHA': { keyLen: 32, ivLen: 16, aead: 'aes-256-cbc-hmac-sha1', hash: 'sha1', isTls13: false },
};
const NSS_KEY_LOG_LABEL_CLIENT_RANDOM = 'CLIENT_RANDOM';
const NSS_KEY_LOG_LABELS_TLS13 = [
  'CLIENT_EARLY_TRAFFIC_SECRET',
  'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
  'SERVER_HANDSHAKE_TRAFFIC_SECRET',
  'CLIENT_TRAFFIC_SECRET_0',
  'SERVER_TRAFFIC_SECRET_0',
  'CLIENT_TRAFFIC_SECRET_1',
  'SERVER_TRAFFIC_SECRET_1',
  'CLIENT_TRAFFIC_SECRET_2',
  'SERVER_TRAFFIC_SECRET_2',
  'CLIENT_TRAFFIC_SECRET_3',
  'SERVER_TRAFFIC_SECRET_3',
  'EARLY_EXPORTER_SECRET',
  'EXPORTER_SECRET',
];
const PRINTABLE_UTF8_PREVIEW_REGEX = /^[\x09\x0A\x0D\x20-\x7E]*$/;
const MAX_ASCII_PREVIEW_LENGTH = 1024;
const PGP_ARMOR_BLOCK_REGEX =
  /-----BEGIN PGP [A-Z0-9 ]+-----[\s\S]*?-----END PGP [A-Z0-9 ]+-----/g;
const PGP_BEGIN_LINE_REGEX = /-----BEGIN (PGP [^-]+)-----/;
const PGP_END_LINE_REGEX = /-----END (PGP [^-]+)-----/;
const PGP_PRIVATE_KEY_BLOCK_REGEX =
  /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/i;
const MAX_PGP_PREVIEW_LENGTH = 400;
const threadName = "Crypt";
const MAX_DECRYPT_FAILURE_MESSAGES = 8;

// Creates crypt panel.
function createCryptPanel({
  constants,
  getCapturedPackets,
  getJsonCapture,
  setActiveMainTab,
  setActiveCryptSubtab,
  statusUpdate,
  writeLogEntry,
  doError,
  logErrorEntry,
  filterInputEl,
  syncFilterHighlight,
  runFilterQuery,
  addSessionKeystoreEntry,
  getSessionKeychainEntries,
  getFirstLineOrFallback,
  sendDecryptedToConv,
  rerunBackendWithWifiKeys,
}) {
  const {
    MAIN_TAB_CRYPT,
    CRYPT_HASHES_SUBTAB,
    CRYPT_SSL_SUBTAB,
    CRYPT_PGP_SUBTAB,
    CRYPT_OPENSSH_SUBTAB,
    CRYPT_WIFI_SUBTAB,
    SESSION_KEYCHAIN_LABEL,
    isLikelyIpAddress,
    extractIpv6EndpointParts,
    formatNetworkEndpointDisplay,
  } = constants;

  function normalizeCryptEndpointIp(value) {
    const endpoint =
      typeof extractIpv6EndpointParts === "function"
        ? extractIpv6EndpointParts(value)
        : null;
    return String(endpoint?.host || value || "").trim();
  }

  function formatCryptEndpoint(ip, port) {
    if (typeof formatNetworkEndpointDisplay === "function") {
      return formatNetworkEndpointDisplay(ip, port);
    }
    const normalizedIp = String(ip || "").trim();
    const normalizedPort = String(port ?? "").trim();
    if (!normalizedPort) return normalizedIp;
    if (normalizedIp.includes(":") && !/^\[[^\]]+\]$/.test(normalizedIp)) {
      return `[${normalizedIp}]:${normalizedPort}`;
    }
    return `${normalizedIp}:${normalizedPort}`;
  }

  let cryptEncounteredEntries = [];
  let cryptSessionEncounteredEntries = [];
  let cryptActiveEntryIndex = -1;
  let cryptLastDecryptedPayload = null;
  let cryptKeyLogEntries = [];
  let pgpEncounteredEntries = [];
  let pgpActiveEntryIndex = -1;
  let pgpLastOutputPayload = null;
  let pgpPrivateKeyCandidates = [];
  let pgpPassphraseCandidates = [];
  let wifiEncounteredEntries = [];
  let wifiAllEncounteredEntries = [];
  let wifiActiveEntryIndex = -1;
  let wifiKeystoreKeys = [];
  let wifiBackendKeysAccepted = 0;
  let wifiBackendKeysLastSentAt = null;
  // Snapshot of the keys last handed to setBackendWifiKeys. We keep this
  // around so the auto-rerun triggered after a successful send can reuse
  // the exact same keys even if the session keychain is mutated (e.g. by
  // a debounced keystore-LLM rebuild) before the rerun callback fires.
  let wifiBackendKeysLastSent = [];
  const wifiFilterState = {
    ssid: "",
    bssid: "",
    decryptableOnly: false,
    sort: "index",
  };

  function getHostPacketMap(capturedPackets) {
    if (!capturedPackets || typeof capturedPackets !== "object") return null;
    const map = capturedPackets["host"] || capturedPackets["Host"];
    return map && typeof map === "object" ? map : null;
  }

  function getPacketInfo(packet) {
    const info = packet?.["packet.info"] || packet?.["Packet Info"];
    return info && typeof info === "object" ? info : {};
  }

  function getExtraInfo(packet) {
    const info = packet?.["extra.info"] || packet?.["Extra Info"];
    return info && typeof info === "object" ? info : {};
  }

  function getTransportData(packetInfo, protocol) {
    if (!packetInfo || typeof packetInfo !== "object") return {};
    const protocolName = String(protocol || "").trim();
    if (!protocolName) return {};
    const direct = packetInfo[protocolName];
    if (direct && typeof direct === "object") return direct;
    const lower = packetInfo[protocolName.toLowerCase()];
    if (lower && typeof lower === "object") return lower;
    const upper = packetInfo[protocolName.toUpperCase()];
    if (upper && typeof upper === "object") return upper;
    return {};
  }

  function getServerInfo(extraInfo) {
    const traits =
      extraInfo?.["Traits"] ||
      extraInfo?.["traits"] ||
      extraInfo?.["traits.server.info"] ||
      {};
    return (
      traits?.["Server Info"] ||
      traits?.["server.info"] ||
      extraInfo?.["server.info"] ||
      {}
    );
  }

  function getEncryptionData(serverInfo) {
    return (
      serverInfo?.["Encryption Data"] ||
      serverInfo?.["encryption.data"] ||
      serverInfo?.["encryption"] ||
      null
    );
  }

  // ── OpenSSH keystroke-timing subtab ───────────────────────────────────
  //
  // Detects TCP flows on port 22 / 2222, computes inter-packet delays,
  // then runs the QWERTY digraph decoder in src/ui/decoders/ssh-keystrokes
  // to produce top-N decoded keystroke hypotheses plus a Plotly chart.

  const SSH_DEFAULT_PORTS = [22, 2222];

  function parseSshPacketTimestampMs(packet) {
    const ts =
      packet?.["packet.info"]?.["packet.timestamp"] ??
      packet?.["packet.info"]?.["Packet Timestamp"];
    if (typeof ts !== "string" || !ts.trim()) return null;
    const parsed = Date.parse(ts);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function isSshPort(transportData) {
    const candidates = [
      transportData?.["tcp.src.port"],
      transportData?.["tcp.dst.port"],
      transportData?.["Source port"],
      transportData?.["source.port"],
      transportData?.["Destination port"],
      transportData?.["destination.port"],
    ];
    for (const value of candidates) {
      const n = Number(value);
      if (SSH_DEFAULT_PORTS.includes(n)) return true;
    }
    return false;
  }

  // Default chunk size — process 100 packets at a time so the UI thread
  // can keep painting between chunks.
  const SSH_PACKET_CHUNK_SIZE = 100;

  function getSshEncounteredFlows() {
    const flows = [];
    const hostMap = getHostPacketMap(getCapturedPackets());
    if (!hostMap) return flows;
    const flowKeyByEndpoint = (srcIp, srcPort, dstIp, dstPort) => {
      const a = `${srcIp}:${srcPort}`;
      const b = `${dstIp}:${dstPort}`;
      const [first, second] = [a, b].sort();
      return `tcp|${first}|${second}`;
    };
    for (const host of Object.keys(hostMap)) {
      const packets = hostMap[host];
      if (!Array.isArray(packets)) continue;
      packets.forEach((packet) => {
        const packetInfo = getPacketInfo(packet);
        const transportData = getTransportData(packetInfo, "TCP");
        if (!isSshPort(transportData)) return;
        const srcIp =
          packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"] ?? "?";
        const dstIp =
          packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"] ?? "?";
        const srcPort = Number(transportData?.["tcp.src.port"] ?? "?");
        const dstPort = Number(transportData?.["tcp.dst.port"] ?? "?");
        const timestamp = parseSshPacketTimestampMs(packet);
        const packetIndex =
          packetInfo?.["Index"] ?? packetInfo?.["packet.processed"] ?? null;
        const direction =
          srcPort === 22 || srcPort === 2222
            ? "s2c"
            : dstPort === 22 || dstPort === 2222
              ? "c2s"
              : "?";
        flows.push({
          host,
          packet,
          srcIp,
          srcPort,
          dstIp,
          dstPort,
          timestamp,
          packetIndex,
          direction,
          flowKey: flowKeyByEndpoint(srcIp, srcPort, dstIp, dstPort),
        });
      });
    }
    return flows;
  }

  // Async variant of `getSshEncounteredFlows`. Walks every packet in
  // chunks of `SSH_PACKET_CHUNK_SIZE` and yields to the event loop between
  // chunks so the renderer can paint progress and stay responsive on
  // very large captures. `onProgress` (optional) is invoked with
  // `{ processed, total }` after each chunk.
  async function collectSshEncounteredFlows(onProgress) {
    const flows = [];
    const hostMap = getHostPacketMap(getCapturedPackets());
    if (!hostMap) return flows;
    const flowKeyByEndpoint = (srcIp, srcPort, dstIp, dstPort) => {
      const a = `${srcIp}:${srcPort}`;
      const b = `${dstIp}:${dstPort}`;
      const [first, second] = [a, b].sort();
      return `tcp|${first}|${second}`;
    };
    // Get session artifact store for collecting IPs/hosts seen in this capture.
    // These artifacts can later be used for Markov template slot matching.
    let artifactStore = null;
    if (sshMarkovModule && typeof sshMarkovModule.getSessionArtifactStore === "function") {
      try {
        artifactStore = sshMarkovModule.getSessionArtifactStore();
      } catch (e) {
        console.warn("[Crypt/OpenSSH] artifact store unavailable:", e);
        artifactStore = null;
      }
    }
    // Track seen IPs/hosts to avoid spamming the artifact store with duplicates
    const seenFlowKeys = new Set();
    const seenHosts = new Set();
    let total = 0;
    for (const host of Object.keys(hostMap)) {
      const packets = hostMap[host];
      if (Array.isArray(packets)) total += packets.length;
    }
    let processed = 0;
    for (const host of Object.keys(hostMap)) {
      const packets = hostMap[host];
      if (!Array.isArray(packets)) continue;
      for (let i = 0; i < packets.length; i += 1) {
        const packet = packets[i];
        const packetInfo = getPacketInfo(packet);
        const transportData = getTransportData(packetInfo, "TCP");
        if (isSshPort(transportData)) {
          const srcIp =
            packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"] ?? "?";
          const dstIp =
            packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"] ?? "?";
          const srcPort = Number(transportData?.["tcp.src.port"] ?? "?");
          const dstPort = Number(transportData?.["tcp.dst.port"] ?? "?");
          const timestamp = parseSshPacketTimestampMs(packet);
          const packetIndex =
            packetInfo?.["Index"] ?? packetInfo?.["packet.processed"] ?? null;
          const direction =
            srcPort === 22 || srcPort === 2222
              ? "s2c"
              : dstPort === 22 || dstPort === 2222
                ? "c2s"
                : "?";
          const flowKey = flowKeyByEndpoint(srcIp, srcPort, dstIp, dstPort);
          flows.push({
            host,
            packet,
            srcIp,
            srcPort,
            dstIp,
            dstPort,
            timestamp,
            packetIndex,
            direction,
            flowKey,
          });
          // Collect artifacts for slot matching: IPs, hosts from SSH flows
          if (artifactStore && !seenFlowKeys.has(flowKey)) {
            seenFlowKeys.add(flowKey);
            // Add source and destination IPs as artifacts
            if (srcIp && srcIp !== "?") {
              artifactStore.addIpAddress(srcIp, {
                flowKey,
                source: "capture",
                confidence: 1.0,
                category: direction === "s2c" ? "server_ip" : "client_ip",
                timestampMs: timestamp,
              });
            }
            if (dstIp && dstIp !== "?") {
              artifactStore.addIpAddress(dstIp, {
                flowKey,
                source: "capture",
                confidence: 1.0,
                category: direction === "c2s" ? "server_ip" : "client_ip",
                timestampMs: timestamp,
              });
            }
            // Add host from the capture's host map (could be a hostname)
            if (host && !seenHosts.has(host)) {
              seenHosts.add(host);
              // Check if host looks like an IP or a hostname
              const looksLikeIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) || host.includes(":");
              if (looksLikeIp) {
                artifactStore.addIpAddress(host, {
                  flowKey,
                  source: "capture",
                  confidence: 1.0,
                  category: "flow_host",
                });
              } else {
                // Could be a hostname - add as both hostname and domain
                artifactStore.addHostname(host, {
                  flowKey,
                  source: "capture",
                  confidence: 0.9,
                });
                // Also extract eTLD+1 if it looks like a domain
                if (host.includes(".")) {
                  const domainParts = host.split(".");
                  if (domainParts.length >= 2) {
                    const domain = domainParts.slice(-2).join(".");
                    artifactStore.addDomain(domain, {
                      flowKey,
                      source: "capture",
                      confidence: 0.7,
                    });
                  }
                }
              }
            }
          }
        }
        processed += 1;
        if (processed % SSH_PACKET_CHUNK_SIZE === 0) {
          if (typeof onProgress === "function") {
            try { onProgress({ processed, total }); } catch (_e) { /* ignore */ }
          }
          // Yield to the event loop so the renderer can paint.
          // eslint-disable-next-line no-await-in-loop
          await yieldToUi();
        }
      }
    }
    if (typeof onProgress === "function") {
      try { onProgress({ processed, total }); } catch (_e) { /* ignore */ }
    }
    return flows;
  }

  // Async variant of `aggregateSshFlows`. Sorts each bucket in chunks and
  // yields so the UI thread stays responsive.
  async function aggregateSshFlowsAsync(flows) {
    const byKey = new Map();
    for (const entry of flows) {
      const bucket = byKey.get(entry.flowKey) || {
        flowKey: entry.flowKey,
        host: entry.host,
        srcIp: entry.srcIp,
        srcPort: entry.srcPort,
        dstIp: entry.dstIp,
        dstPort: entry.dstPort,
        packets: [],
      };
      bucket.packets.push(entry);
      byKey.set(entry.flowKey, bucket);
    }
    const buckets = Array.from(byKey.values());
    for (let bi = 0; bi < buckets.length; bi += 1) {
      const bucket = buckets[bi];
      bucket.packets.sort((a, b) => {
        const ta = a.timestamp || 0;
        const tb = b.timestamp || 0;
        if (ta !== tb) return ta - tb;
        return (a.packetIndex || 0) - (b.packetIndex || 0);
      });
      bucket.c2sPacketCount = bucket.packets.filter((p) => p.direction === "c2s").length;
      bucket.s2cPacketCount = bucket.packets.filter((p) => p.direction === "s2c").length;
      bucket.firstTimestamp = bucket.packets[0]?.timestamp ?? null;
      bucket.lastTimestamp = bucket.packets[bucket.packets.length - 1]?.timestamp ?? null;
      if (bi % SSH_PACKET_CHUNK_SIZE === 0) {
        // eslint-disable-next-line no-await-in-loop
        await yieldToUi();
      }
    }
    buckets.sort((a, b) => {
      const ta = a.firstTimestamp || 0;
      const tb = b.firstTimestamp || 0;
      return ta - tb;
    });
    return buckets;
  }

  // Yield to the event loop so the renderer can paint. Uses
  // requestAnimationFrame when available (smoother progress repainting)
  // and falls back to setTimeout(0) otherwise.
  function yieldToUi() {
    return new Promise((resolve) => {
      if (typeof window !== "undefined" && typeof window.requestAnimationFrame === "function") {
        window.requestAnimationFrame(() => resolve());
      } else {
        setTimeout(resolve, 0);
      }
    });
  }

  // Async variant of `computeInterPacketDelaysWithIndexes`. Yields after
  // every `SSH_PACKET_CHUNK_SIZE` packets so the UI stays responsive even
  // on very long captures. The direction filter (when set) is also chunked
  // so it does not block on very large packet arrays.
  async function computeInterPacketDelaysWithIndexesAsync(packets, directionFilter, onProgress) {
    // Chunked filter so the direction filter itself doesn't block on huge
    // packet arrays. For "both" we skip the filter and use the source array.
    let filtered = packets;
    const total = packets.length;
    if (directionFilter === "c2s" || directionFilter === "s2c") {
      filtered = [];
      for (let i = 0; i < packets.length; i += 1) {
        if (packets[i].direction === directionFilter) filtered.push(packets[i]);
        if (i % SSH_PACKET_CHUNK_SIZE === 0 && i !== 0) {
          // eslint-disable-next-line no-await-in-loop
          await yieldToUi();
        }
      }
    }
    const out = [];
    let prevTs = null;
    let idx = 0;
    for (let i = 0; i < filtered.length; i += 1) {
      const pkt = filtered[i];
      if (pkt.timestamp === null || pkt.timestamp === undefined) {
        idx += 1;
      } else {
        if (prevTs !== null) {
          const d = pkt.timestamp - prevTs;
          if (Number.isFinite(d) && d > 0 && d < 60_000) {
            let pktLen = null;
            try {
              const pinfo = getPacketInfo(pkt.packet);
              pktLen = Number(pinfo?.["packet.length"] ?? pinfo?.["Packet Length"] ?? pinfo?.["Length"] ?? null);
              if (!Number.isFinite(pktLen)) pktLen = null;
            } catch (_e) {
              pktLen = null;
            }
            out.push({ delay: d, index: idx, packetLength: pktLen });
          }
        }
        prevTs = pkt.timestamp;
        idx += 1;
      }
      // Yield every SSH_PACKET_CHUNK_SIZE packets and report progress.
      if (i % SSH_PACKET_CHUNK_SIZE === 0) {
        if (typeof onProgress === "function") {
          try { onProgress({ processed: i + 1, total: filtered.length }); } catch (_e) { /* ignore */ }
        }
        // eslint-disable-next-line no-await-in-loop
        await yieldToUi();
      }
    }
    if (typeof onProgress === "function") {
      try { onProgress({ processed: filtered.length, total: filtered.length }); } catch (_e) { /* ignore */ }
    }
    return out;
  }

  function aggregateSshFlows(flows) {
    const byKey = new Map();
    for (const entry of flows) {
      const bucket = byKey.get(entry.flowKey) || {
        flowKey: entry.flowKey,
        host: entry.host,
        srcIp: entry.srcIp,
        srcPort: entry.srcPort,
        dstIp: entry.dstIp,
        dstPort: entry.dstPort,
        packets: [],
      };
      bucket.packets.push(entry);
      byKey.set(entry.flowKey, bucket);
    }
    const buckets = Array.from(byKey.values());
    for (const bucket of buckets) {
      bucket.packets.sort((a, b) => {
        const ta = a.timestamp || 0;
        const tb = b.timestamp || 0;
        if (ta !== tb) return ta - tb;
        return (a.packetIndex || 0) - (b.packetIndex || 0);
      });
      bucket.c2sPacketCount = bucket.packets.filter((p) => p.direction === "c2s").length;
      bucket.s2cPacketCount = bucket.packets.filter((p) => p.direction === "s2c").length;
      bucket.firstTimestamp = bucket.packets[0]?.timestamp ?? null;
      bucket.lastTimestamp = bucket.packets[bucket.packets.length - 1]?.timestamp ?? null;
    }
    buckets.sort((a, b) => {
      const ta = a.firstTimestamp || 0;
      const tb = b.firstTimestamp || 0;
      return ta - tb;
    });
    return buckets;
  }

  function computeInterPacketDelays(packets, directionFilter) {
    if (directionFilter === "c2s" || directionFilter === "s2c") {
      packets = packets.filter((p) => p.direction === directionFilter);
    }
    const delays = [];
    let prevTs = null;
    for (const pkt of packets) {
      if (pkt.timestamp === null || pkt.timestamp === undefined) continue;
      if (prevTs !== null) {
        const d = pkt.timestamp - prevTs;
        if (Number.isFinite(d) && d > 0 && d < 60_000) {
          delays.push(d);
        }
      }
      prevTs = pkt.timestamp;
    }
    return delays;
  }

  // Compute inter-packet delays but preserve the packet index of the later
  // packet for mapping delays back to keystroke positions. Returns an array
  // of { delay, index } objects where index is the 0-based index within the
  // filtered packet list of the packet that ended the interval.
  function computeInterPacketDelaysWithIndexes(packets, directionFilter) {
    if (directionFilter === "c2s" || directionFilter === "s2c") {
      packets = packets.filter((p) => p.direction === directionFilter);
    }
    const out = [];
    let prevTs = null;
    let idx = 0;
    for (const pkt of packets) {
      if (pkt.timestamp === null || pkt.timestamp === undefined) {
        idx += 1;
        continue;
      }
      if (prevTs !== null) {
        const d = pkt.timestamp - prevTs;
        if (Number.isFinite(d) && d > 0 && d < 60_000) {
          // Try to extract a packet length if available in the packet.info
          let pktLen = null;
          try {
            const pinfo = getPacketInfo(pkt.packet);
            pktLen = Number(pinfo?.["packet.length"] ?? pinfo?.["Packet Length"] ?? pinfo?.["Length"] ?? null);
            if (!Number.isFinite(pktLen)) pktLen = null;
          } catch (_e) {
            pktLen = null;
          }
          out.push({ delay: d, index: idx, packetLength: pktLen });
        }
      }
      prevTs = pkt.timestamp;
      idx += 1;
    }
    return out;
  }

  // Pure helper: split an inter-key-delay stream into per-Return
  // chunks. Each returned chunk has its own start/end packet indices
  // and a ``keystrokeCount`` derived from the small-packet heuristic
  // below. Returns an empty array when no Return-shaped gap exists.
  //
  // The "Return-shaped gap" is the same statistical test as
  // ``estimateCommandLengthFromDelaysWithIdx`` below: median + N*MAD
  // with an absolute floor of 400 ms. We prefer to detect *every*
  // candidate gap (not just the end-of-session one) so callers can
  // either pick the last chunk (existing behaviour) or render all
  // chunks (per-command guesses).
  //
  // Helper: convert a plain number array (e.g. `keystrokeDelaysMs`
  // from the padding detector, which has no packetLength / index
  // metadata) into the `{ delay, index, packetLength }` shape that
  // ``findReturnChunks`` expects. Used by the markov background
  // pass to re-chunk the PEELED stream.
  function buildIndexedDelaysFromPeeled(peeledDelays) {
    if (!Array.isArray(peeledDelays)) return [];
    const out = [];
    for (let i = 0; i < peeledDelays.length; i += 1) {
      const d = peeledDelays[i];
      if (!Number.isFinite(d)) continue;
      out.push({ delay: d, index: i, packetLength: null });
    }
    return out;
  }
  function findReturnChunks(delaysWithIdx) {
    if (!Array.isArray(delaysWithIdx) || delaysWithIdx.length === 0) return [];
    const vals = delaysWithIdx.map((d) => d.delay).filter((v) => Number.isFinite(v));
    if (!vals.length) return [];
    const sorted = vals.slice().sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    const median = sorted.length % 2 === 1
      ? sorted[mid]
      : (sorted[mid - 1] + sorted[mid]) / 2;
    const absDevs = sorted.map((v) => Math.abs(v - median));
    const mad = absDevs.slice().sort((a, b) => a - b)[Math.floor(absDevs.length / 2)] || 0;
    const approxStd = mad * 1.4826 || 0;
    const dynamicThresh = median + Math.max(3 * approxStd, 150);
    const threshold = Math.max(dynamicThresh, 400);

    // Walk delays once. Each time we cross the threshold, the gap
    // ends the *current* chunk and starts a new one. The very last
    // (unbounded) chunk is captured too because the user's most
    // recent command may not yet have hit Enter.
    const chunks = [];
    let curStart = 0;
    for (let i = 0; i < delaysWithIdx.length; i += 1) {
      const d = delaysWithIdx[i];
      if (!d || !Number.isFinite(d.delay)) continue;
      if (d.delay >= threshold) {
        chunks.push({
          startIdx: curStart,
          endIdx: i,
          // Filled in below: small-packet count for this chunk.
          keystrokeCount: 0,
        });
        curStart = i + 1;
      }
    }
    if (curStart <= delaysWithIdx.length - 1) {
      chunks.push({
        startIdx: curStart,
        endIdx: delaysWithIdx.length - 1,
        keystrokeCount: 0,
      });
    }

    // Convert each chunk's packet range into a keystroke count.
    // Three sources of truth, in priority order:
    //   1. ``entry.keystrokeCount`` — explicitly-set count (used by
    //      ``markovChunks`` to feed back per-chunk beam results)
    //   2. ``packetLength`` known and small (<=100 B) — typical
    //      single-keystroke SSH c2s payload
    //   3. ``packetLength`` null (peeled stream) — every entry is a
    //      keystroke, because the peeling already removed filler
    const SMALL_PACKET_BYTES = 100;
    for (const chunk of chunks) {
      let count = 0;
      let sawEntry = false;
      for (let i = chunk.startIdx; i <= chunk.endIdx; i += 1) {
        const entry = delaysWithIdx[i];
        if (!entry) continue;
        sawEntry = true;
        if (Number.isFinite(entry.keystrokeCount) && entry.keystrokeCount > 0) {
          count += entry.keystrokeCount;
          continue;
        }
        // Peeled stream entries have `packetLength: null` (set by
        // ``buildIndexedDelaysFromPeeled``). Each one represents a
        // real keystroke — the peeling already filtered out filler.
        // NOTE: check the raw field, not Number(null), which is 0.
        if (entry.packetLength === null || entry.packetLength === undefined) {
          count += 1;
          continue;
        }
        const len = Number(entry.packetLength);
        if (Number.isFinite(len) && len > 0 && len <= SMALL_PACKET_BYTES) {
          count += 1;
        }
      }
      // Always at least 1 — a chunk with no small packets is
      // counted as "one composite action" rather than zero, so the
      // markov beam never receives targetLen=0.
      chunk.keystrokeCount = Math.max(1, count || (sawEntry ? 1 : 0));
    }
    return chunks;
  }

  // Heuristic to estimate where an Enter/Return keypress likely
  // occurred. Uses robust statistics (median, MAD-like) and absolute
  // thresholds to find a large inter-key gap that plausibly
  // corresponds to the end of a typed command. Returns the estimated
  // command length (number of characters typed before the gap) or
  // null if no clear boundary is detected.
  //
  // Implementation notes:
  //   * ``delaysWithIdx[i].index`` is the *position of the packet
  //     that ended the interval* within the filtered (typically
  //     c2s-only) packet list, NOT a keystroke count. Reporting
  //     it as "command length" produces wildly inflated numbers on
  //     long sessions with substantial padding/control traffic.
  //   * One SSH keystroke generally produces a small c2s payload
  //     (~32-100 bytes is the empirically observed band; SSH
  //     protocol minimum is 32 bytes for a typed frame, but
  //     channels like vim emit longer frames mid-edit). We treat
  //     "small c2s packets" as keystrokes and count them up to
  //     and including the candidate gap's ending packet.
  //   * We cap the answer against the small-packet total so a
  //     bogus gap inside the stream can never report "longer than
  //     the entire session".
  function estimateCommandLengthFromDelaysWithIdx(delaysWithIdx) {
    if (!Array.isArray(delaysWithIdx) || delaysWithIdx.length === 0) return null;
    const chunks = findReturnChunks(delaysWithIdx);
    if (!chunks.length) return null;
    // Preserve legacy semantics: return the keystroke count of
    // the *last* chunk (i.e., the most recent command).
    return chunks[chunks.length - 1].keystrokeCount;
  }

  // Backspace/delete detection is implemented as a pure helper in
  // src/ui/decoders/ssh-keystrokes/backspace-detect.js so it can be
  // unit-tested without instantiating the panel. The local
  // `detectBackspaceHintsAsync` is a thin yield-aware wrapper that
  // delegates to the module — this keeps one canonical implementation.
  async function detectBackspaceHintsAsync(delaysWithIdx, opts) {
    const fn = getDetectBackspaceHints();
    if (!fn) return { indices: [], count: 0 };
    if (!Array.isArray(delaysWithIdx) || delaysWithIdx.length === 0) {
      return { indices: [], count: 0 };
    }
    // Yield once before classification so the renderer can paint a
    // "Detecting backspaces…" progress state if it wants to. The
    // detector itself is O(N) and finishes in milliseconds on
    // realistic-sized inputs, so additional yields are unnecessary.
    if (typeof yieldToUi === "function") {
      await yieldToUi();
    }
    return fn(delaysWithIdx, opts);
  }

  let sshAllFlows = [];
  let sshFlows = [];
  let sshSelectedFlowKey = null;
  let sshDecoder = null;
  let sshModel = null;
  let sshModelLoadPromise = null;
  // Per-flow analysis cache. Keyed by `flow.flowKey` so re-selecting a
  // previously-analyzed flow retains its timing trace and decoder
  // candidates; this is what powers the "Export keystrokes" button.
  // Shape: { flow, model, delays, delaysWithIdx, candidates, primary,
  //         insight, renderMode, estimatedCommandLength, backspaceHints,
  //         analyzedAt }.
  const sshLastAnalysisByFlowKey = new Map();

  function getSshDecoderModule() {
    if (sshDecoder) return sshDecoder;
    try {
      // eslint-disable-next-line global-require
      sshDecoder = require("../decoders/ssh-keystrokes");
    } catch (err) {
      console.warn("[Crypt/OpenSSH] decoder unavailable:", err);
      sshDecoder = null;
    }
    return sshDecoder;
  }

  // Pure helpers (text builder + stats) live in their own module so
  // they can be unit-tested without instantiating the panel. Loading is
  // best-effort: a missing module leaves `sshExportModule` null and the
  // button falls through to a graceful console-warning path.
  let sshExportModule = null;
  try {
    // eslint-disable-next-line global-require
    sshExportModule = require("../decoders/ssh-keystrokes/export");
  } catch (err) {
    console.warn("[Crypt/OpenSSH] export module unavailable:", err);
    sshExportModule = null;
  }
  // Backspace/delete detector — same pattern: pure helper in its own
  // module, required lazily so a missing module doesn't crash the panel.
  let sshBackspaceModule = null;
  try {
    // eslint-disable-next-line global-require
    sshBackspaceModule = require("../decoders/ssh-keystrokes/backspace-detect");
  } catch (err) {
    console.warn("[Crypt/OpenSSH] backspace-detect module unavailable:", err);
    sshBackspaceModule = null;
  }
  // Shell-Markov module (pure-JS model, no node-core imports).
  // The renderer fetches the trained model via window.markovapi.
  let sshMarkovModule = null;
  try {
    // eslint-disable-next-line global-require
    sshMarkovModule = require("../decoders/ssh-keystrokes/markov");
  } catch (err) {
    console.warn("[Crypt/OpenSSH] markov module unavailable:", err);
    sshMarkovModule = null;
  }
  // `sshMarkovModel` is the loaded/trained ShellMarkov instance, once
  // ready. `sshMarkovTrainPromise` deduplicates concurrent model-fetch
  // requests (first OpenSSH tab open, then again at next open).
  let sshMarkovModel = null;
  let sshMarkovTrainPromise = null;
  function getUserDataDirForMarkov() {
    // Renderer-side userData isn't directly available; ask the main
    // process via `window.markovapi.getUserDataDir()` (defined in
    // preload.js) and fall back to a deterministic temp path if the
    // bridge isn't there yet.
    if (typeof window !== "undefined"
      && window.markovapi
      && typeof window.markovapi.getUserDataDir === "function") {
      try {
        const p = window.markovapi.getUserDataDir();
        if (p) return p;
      } catch (_e) { /* ignore */ }
    }
    return null;
  }
  function ensureShellMarkovReady() {
    if (sshMarkovModel) return Promise.resolve(sshMarkovModel);
    if (sshMarkovTrainPromise) return sshMarkovTrainPromise;
    if (!sshMarkovModule
      || typeof sshMarkovModule.ShellMarkov !== "function") {
      return Promise.resolve(null);
    }
    const api = (typeof window !== "undefined") ? window.markovapi : null;
    if (!api || typeof api.getModel !== "function") {
      return Promise.resolve(null);
    }
    sshMarkovTrainPromise = (async () => {
      // Yield once so the renderer's main thread can paint if the
      // bridge is slow. ``setImmediate`` isn't a browser global —
      // webpack's ProvidePlugin maps ``setimmediate`` for us, but a
      // belt-and-braces fallback to setTimeout(0) keeps the call
      // safe on any environment that didn't wire the polyfill.
      await new Promise((r) => {
        if (typeof setImmediate === "function") setImmediate(r);
        else setTimeout(r, 0);
      });
      // Try the cache first (warm path).
      let dict = await api.getModel();
      if (!dict && typeof api.train === "function") {
        // Cold path — main process hasn't precomputed yet (or
        // user opened the OpenSSH tab before app.whenReady's
        // setImmediate fired). Train now in the main process,
        // which has node core available; the renderer just
        // forwards and waits.
        dict = await api.train();
      }
      if (!dict) return null;
      const model = sshMarkovModule.ShellMarkov.fromDict(dict);
      sshMarkovModel = model;
      return model;
    })();
    sshMarkovTrainPromise.finally(() => { sshMarkovTrainPromise = null; });
    return sshMarkovTrainPromise;
  }
  // Kick the training chain off as soon as the panel loads so the
  // user's first OpenSSH analysis hits a warm cache. The main
  // process also runs ``scheduleShellMarkovPrecompute`` in
  // ``app.whenReady``; whichever finishes first wins, the other
  // side just observes the cache file.
  try { void ensureShellMarkovReady(); } catch (_e) { /* ignore */ }
  function getDetectBackspaceHints() {
    return (sshBackspaceModule
      && typeof sshBackspaceModule.detectBackspaceHints === "function")
      ? sshBackspaceModule.detectBackspaceHints
      : null;
  }

  function ensureSshModelLoaded() {
    if (sshModel) return Promise.resolve(sshModel);
    if (sshModelLoadPromise) return sshModelLoadPromise;
    const decoder = getSshDecoderModule();
    if (!decoder) {
      return Promise.reject(new Error("Decoder module failed to load"));
    }
    const api =
      typeof window !== "undefined" && window.opensshapi
        ? window.opensshapi
        : null;
    if (!api || typeof api.loadQwertyModel !== "function") {
      // No IPC bridge — fall back to the heuristic-only model so the
      // decoder still works (just without empirical priors).
      sshModel = decoder.loadQwertyModel({});
      return Promise.resolve(sshModel);
    }
    sshModelLoadPromise = api
      .loadQwertyModel()
      .then((response) => {
        sshModelLoadPromise = null;
        if (response && response.success && response.model) {
          sshModel = decoder.loadQwertyModel(response.model);
        } else {
          console.warn(
            "[Crypt/OpenSSH] qwerty model load returned:",
            response && response.error,
          );
          sshModel = decoder.loadQwertyModel({});
        }
        return sshModel;
      })
      .catch((err) => {
        sshModelLoadPromise = null;
        console.warn("[Crypt/OpenSSH] qwerty model load failed:", err);
        sshModel = decoder.loadQwertyModel({});
        return sshModel;
      });
    return sshModelLoadPromise;
  }

  async function refreshSshEncounteredFlows() {
    const detailsEl = document.getElementById("crypt-openssh-flow-details");
    const listEl = document.getElementById("crypt-openssh-flows");
    if (detailsEl) {
      detailsEl.textContent = "Scanning packets for SSH flows (chunked 100/chunk)...";
    }
    if (listEl) {
      listEl.replaceChildren();
      const opt = document.createElement("option");
      opt.textContent = "Scanning...";
      opt.disabled = true;
      listEl.appendChild(opt);
    }
    // Drop any cached analysis from a prior capture — flowKey() values
    // may be reused after the user loads a different pcap, and stale
    // timing traces for the wrong capture would corrupt the export.
    sshLastAnalysisByFlowKey.clear();
    // Clear the visible OpenSSH outputs (chart, candidates, summary,
    // primary, insight) so the user immediately sees a clean state
    // when they load a new capture, instead of stale results from
    // the previous pcap.
    clearSshOutputPanels();
    // Reset the session artifact store when starting a fresh flow analysis
    // on a potentially new capture. This ensures artifacts from different
    // captures don't bleed into each other.
    if (sshMarkovModule && typeof sshMarkovModule.resetSessionArtifactStore === "function") {
      try {
        sshMarkovModule.resetSessionArtifactStore();
      } catch (e) {
        console.warn("[Crypt/OpenSSH] failed to reset artifact store:", e);
      }
    }
    try {
      const flows = await collectSshEncounteredFlows();
      sshAllFlows = await aggregateSshFlowsAsync(flows);
      sshFlows = sshAllFlows;
    } catch (err) {
      console.warn("[Crypt/OpenSSH] chunked refresh failed, falling back:", err);
      sshAllFlows = aggregateSshFlows(getSshEncounteredFlows());
      sshFlows = sshAllFlows;
    }
    renderSshFlowOptions();
  }

  function renderSshFlowOptions() {
    const listEl = document.getElementById("crypt-openssh-flows");
    const detailsEl = document.getElementById("crypt-openssh-flow-details");
    const analyzeBtn = document.getElementById("crypt-openssh-analyze-btn");
    if (!listEl) return;
    listEl.replaceChildren();

    if (sshFlows.length === 0) {
      const option = document.createElement("option");
      option.textContent = "No SSH flows detected in the loaded capture.";
      option.disabled = true;
      listEl.appendChild(option);
      if (analyzeBtn) analyzeBtn.disabled = true;
      if (detailsEl) {
        detailsEl.textContent =
          "Load a capture that contains port 22 or 2222 TCP traffic.";
      }
      return;
    }
    if (analyzeBtn) analyzeBtn.disabled = false;
    sshFlows.forEach((flow, idx) => {
      const option = document.createElement("option");
      option.value = String(idx);
      const span =
        flow.lastTimestamp && flow.firstTimestamp
          ? Math.max(0, flow.lastTimestamp - flow.firstTimestamp)
          : 0;
      option.textContent =
        `#${idx + 1} ${flow.srcIp}:${flow.srcPort} ↔ ${flow.dstIp}:${flow.dstPort} ` +
        `(${flow.packets.length} pkts, c2s=${flow.c2sPacketCount}, s2c=${flow.s2cPacketCount}, ~${(span / 1000).toFixed(1)}s)`;
      listEl.appendChild(option);
    });
    listEl.selectedIndex = 0;
    sshSelectedFlowKey = sshFlows[0]?.flowKey || null;
    renderSshFlowDetails(sshFlows[0]);
  }

  function renderSshFlowDetails(flow) {
    const detailsEl = document.getElementById("crypt-openssh-flow-details");
    if (!detailsEl) return;
    if (!flow) {
      detailsEl.textContent = "Select a flow to inspect.";
      return;
    }
    const span =
      flow.lastTimestamp && flow.firstTimestamp
        ? Math.max(0, flow.lastTimestamp - flow.firstTimestamp)
        : 0;
    detailsEl.textContent = [
      `Host: ${flow.host}`,
      `5-tuple: ${flow.srcIp}:${flow.srcPort} ↔ ${flow.dstIp}:${flow.dstPort}`,
      `Packets: ${flow.packets.length} (c2s=${flow.c2sPacketCount}, s2c=${flow.s2cPacketCount})`,
      `Span: ${(span / 1000).toFixed(3)} s`,
    ].join("\n");
    // Refresh the export button — it should be enabled only when the
    // currently-selected flow has a cached analysis result.
    refreshSshExportButton();
  }

  // Enable the "Export keystrokes" button only when the user has analyzed
  // the currently-selected flow. Cheap to call (single DOM lookup); safe
  // to fire from anywhere flow state changes.
  function refreshSshExportButton() {
    const exportBtn = document.getElementById("crypt-openssh-export-btn");
    if (!exportBtn) return;
    const hasResult = !!(sshSelectedFlowKey && sshLastAnalysisByFlowKey.get(sshSelectedFlowKey));
    exportBtn.disabled = !hasResult;
    if (hasResult) {
      exportBtn.title = "Save the keystroke timing trace for this flow as a text file";
    } else {
      exportBtn.title = "Run 'Analyze selected' first — the export needs the timing trace";
    }
  }

  // ── Panel reset ─────────────────────────────────────────────────────
  //
  // Wipe the visible OpenSSH outputs to a clean state. Used both at
  // "Analyze selected" start (so the previous run's chart / candidates
  // / insight don't linger while the new one is computing) and on
  // every flow selection change (so switching flows doesn't show
  // stale text from the previously-analyzed flow).
  //
  // Inputs (direction selector, topN, deobf controls) are left alone
  // — those are user choices that persist between runs.
  function clearSshOutputPanels() {
    if (typeof document === "undefined") return;
    // NOTE: Only include LEAF elements in this list (elements that contain
    // only text/content, not other elements). Container elements like
    // crypt-openssh-primary, crypt-openssh-insight, crypt-openssh-markov-section
    // must NOT be included here because calling replaceChildren() on them
    // would DESTROY their child elements (like #crypt-openssh-primary-text),
    // which the render functions later need to populate.
    const idList = [
      "crypt-openssh-summary",
      "crypt-openssh-candidates",
      "crypt-openssh-chart",
      "crypt-openssh-chart-legend",
      "crypt-openssh-primary-text",
      "crypt-openssh-primary-confidence",
      "crypt-openssh-primary-kind",
      "crypt-openssh-primary-source",
      "crypt-openssh-primary-rationale",
      "crypt-openssh-insight-text",
      "crypt-openssh-insight-source",
      "crypt-openssh-markov-text",
      "crypt-openssh-markov-confidence",
      "crypt-openssh-markov-target",
      "crypt-openssh-markov-source",
      // Enhanced confidence elements
      "crypt-openssh-session-confidence-value",
      "crypt-openssh-session-confidence-interpretation",
      "crypt-openssh-markov-candidates-list",
      // Timeline elements
      "crypt-openssh-markov-timeline",
    ];
    for (const id of idList) {
      const el = document.getElementById(id);
      if (!el) continue;
      // Replace all children — preserves any nested <span>/<details>
      // markup the panel uses for indentation; ``textContent = ""``
      // would strip that. We keep a single placeholder line so the
      // layout doesn't collapse.
      el.replaceChildren();
    }
    // Hide progress + reset label
    const progressEl = document.getElementById("crypt-openssh-progress");
    const progressTextEl = document.getElementById("crypt-openssh-progress-text");
    if (progressEl) progressEl.hidden = true;
    if (progressTextEl) progressTextEl.textContent = "Working";
    // Hide the primary and Markov sections
    const primaryEl = document.getElementById("crypt-openssh-primary");
    const markovSectionEl = document.getElementById("crypt-openssh-markov-section");
    const sessionConfEl = document.getElementById("crypt-openssh-markov-session-confidence");
    const candidatesListTitleEl = document.getElementById("crypt-openssh-markov-list-title");
    const candidatesListEl = document.getElementById("crypt-openssh-markov-candidates-list");
    const timelineTitleEl = document.getElementById("crypt-openssh-markov-timeline-title");
    const timelineEl = document.getElementById("crypt-openssh-markov-timeline");
    const markovOutputEl = document.getElementById("crypt-openssh-markov-output");
    if (primaryEl) primaryEl.hidden = true;
    if (markovSectionEl) markovSectionEl.hidden = true;
    if (sessionConfEl) sessionConfEl.hidden = true;
    if (candidatesListTitleEl) candidatesListTitleEl.hidden = true;
    if (candidatesListEl) candidatesListEl.hidden = true;
    if (timelineTitleEl) timelineTitleEl.hidden = true;
    if (timelineEl) timelineEl.hidden = true;
    if (markovOutputEl) markovOutputEl.hidden = true;
    // Drop the analysis cache so the export button reflects "needs analyze"
    sshLastAnalysisByFlowKey.clear();
    // Re-disable the export button (it'll be re-enabled after analyze completes)
    const exportBtn = document.getElementById("crypt-openssh-export-btn");
    if (exportBtn) exportBtn.disabled = true;
  }

  // ── Keystroke-timing export ─────────────────────────────────────────
  //
  // Click handler for the "Export keystrokes" button. The text builder
  // itself lives in src/ui/decoders/ssh-keystrokes/export so it's pure
  // and unit-testable; this wrapper just glues it to the cached
  // analysis and the OS save dialog.
  async function exportSshKeystrokes() {
    const exportBtn = document.getElementById("crypt-openssh-export-btn");
    if (exportBtn) exportBtn.disabled = true;
    try {
      const cached = sshSelectedFlowKey
        ? sshLastAnalysisByFlowKey.get(sshSelectedFlowKey)
        : null;
      if (!cached) {
        if (typeof appendActivityLogLine === "function") {
          appendActivityLogLine("[Crypt/OpenSSH] export requested with no cached analysis");
        }
        return;
      }
      if (!sshExportModule || typeof sshExportModule.buildSshKeystrokeExport !== "function") {
        console.warn("[Crypt/OpenSSH] export module missing; cannot build text");
        return;
      }
      const text = sshExportModule.buildSshKeystrokeExport(cached);
      const flow = cached.flow || {};
      const defaultName = `packetsnitch-ssh-${(flow.srcIp || "client").replace(/[^a-zA-Z0-9_.-]/g, "_")}-to-${(flow.dstIp || "server").replace(/[^a-zA-Z0-9_.-]/g, "_")}-${Date.now()}.txt`;
      const saveText =
        typeof window !== "undefined" &&
          window.saveapi &&
          typeof window.saveapi.saveText === "function"
          ? window.saveapi.saveText
          : null;
      if (!saveText) {
        console.warn("[Crypt/OpenSSH] window.saveapi.saveText unavailable; cannot save export");
        return;
      }
      const result = await saveText({
        text,
        title: "Export SSH keystroke timing trace",
        defaultName,
        defaultExtension: "txt",
        filters: [
          { name: "Text", extensions: ["txt"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });
      if (result && result.success) {
        if (typeof appendActivityLogLine === "function" && result.filePath) {
          appendActivityLogLine(`[Crypt/OpenSSH] exported keystrokes to ${result.filePath}`);
        }
        // Offer to also save a structured JSON export (user can cancel)
        try {
          const wantJson = (typeof window !== "undefined" && typeof window.confirm === "function")
            ? window.confirm("Also save structured JSON export for this trace?")
            : false;
          if (wantJson && sshExportModule && typeof sshExportModule.buildSshKeystrokeExportJson === "function") {
            const jsonObj = sshExportModule.buildSshKeystrokeExportJson(cached);
            const jsonText = JSON.stringify(jsonObj, null, 2);
            const jsonName = defaultName.replace(/\.txt$/, ".json");
            const jsonResult = await saveText({
              text: jsonText,
              title: "Export SSH keystroke timing trace (JSON)",
              defaultName: jsonName,
              defaultExtension: "json",
              filters: [
                { name: "JSON", extensions: ["json"] },
                { name: "All Files", extensions: ["*"] },
              ],
            });
            if (jsonResult && jsonResult.success && typeof appendActivityLogLine === "function" && jsonResult.filePath) {
              appendActivityLogLine(`[Crypt/OpenSSH] exported keystrokes (JSON) to ${jsonResult.filePath}`);
            }
          }
        } catch (err) {
          console.warn("[Crypt/OpenSSH] JSON save failed", err);
        }
      } else if (result && result.canceled) {
        // user cancelled the save dialog — no log entry
      } else if (result && result.error) {
        console.warn("[Crypt/OpenSSH] saveText error:", result.error);
      }
    } finally {
      // Always re-evaluate the button state from the cache so the
      // disabled state matches whether data is still available.
      refreshSshExportButton();
    }
  }

  // Synchronous chart series builder (kept for the decoder's own tests).
  // For very large delay arrays the renderer uses `buildChartSeriesAsync`
  // instead so the histogram loop and `Math.max(...delays)` don't block.
  function buildChartSeries(delays, decoder) {
    return decoder.buildChartSeries(delays);
  }

  // Async chart-series builder that yields to the event loop every
  // SSH_PACKET_CHUNK_SIZE delays. Avoids the `Math.max(...arr)` spread
  // (which can stack-overflow on huge arrays) and keeps the histogram
  // loop off the main thread for the full duration.
  async function buildChartSeriesAsync(delays, decoder) {
    const binSize = Math.max(10, Math.floor(decoder.DEFAULT_DIGRAPH_PARAMS.binSize || 25));
    const chunkSize = SSH_PACKET_CHUNK_SIZE;
    let maxDelay = 500;
    const valid = [];
    for (let i = 0; i < delays.length; i += 1) {
      const d = delays[i];
      if (Number.isFinite(d) && d > 0) {
        valid.push(d);
        if (d > maxDelay) maxDelay = d;
      }
      if (i % chunkSize === 0 && i !== 0) {
        // eslint-disable-next-line no-await-in-loop
        await yieldToUi();
      }
    }
    const bins = [];
    for (let edge = 0; edge <= maxDelay; edge += decoder.DEFAULT_DIGRAPH_PARAMS.binSize || 25) {
      bins.push({ x0: edge, x1: edge + (decoder.DEFAULT_DIGRAPH_PARAMS.binSize || 25), count: 0 });
    }
    for (let i = 0; i < valid.length; i += 1) {
      const idx = Math.min(bins.length - 1, Math.floor(valid[i] / (decoder.DEFAULT_DIGRAPH_PARAMS.binSize || 25)));
      bins[idx].count += 1;
      if (i % chunkSize === 0 && i !== 0) {
        // eslint-disable-next-line no-await-in-loop
        await yieldToUi();
      }
    }
    const bin = decoder.DEFAULT_DIGRAPH_PARAMS.binSize || 25;
    const histogram = {
      x: bins.map((b) => b.x0 + bin / 2),
      y: bins.map((b) => b.count),
      type: "bar",
      name: "Observed inter-key delays",
      marker: { color: "rgba(99, 110, 250, 0.55)" },
    };
    const mean = decoder.DEFAULT_DIGRAPH_PARAMS.mean;
    const std = decoder.DEFAULT_DIGRAPH_PARAMS.std;
    const totalCount = valid.length || 1;
    const refX = [];
    const refY = [];
    for (let edge = 0; edge <= maxDelay; edge += bin) {
      const center = edge + bin / 2;
      refX.push(center);
      const density = Math.exp(decoder.gaussianLogProbability(center, mean, std)) * bin * totalCount;
      refY.push(density);
    }
    const reference = {
      x: refX,
      y: refY,
      type: "scatter",
      mode: "lines",
      name: `Neutral Gaussian (μ=${mean} ms, σ=${std} ms)`,
      line: { color: "rgba(220, 71, 71, 0.9)", width: 2 },
    };
    return { histogram, reference, binSize: bin };
  }

  async function estimateCommandLengthFromDelaysWithIdxAsync(delaysWithIdx) {
    // Same semantics as the sync variant. We push the per-element
    // loop into a setImmediate tick so we never block the renderer
    // on a 10k-delay session. The chunk-finder itself is pure so it
    // returns immediately; yielding only matters on the wrapper.
    if (!Array.isArray(delaysWithIdx) || delaysWithIdx.length === 0) return null;
    for (let i = 0; i < delaysWithIdx.length; i += SSH_PACKET_CHUNK_SIZE) {
      // Touch the array lazily to keep the chunked-yield contract
      // (no real work happens here because findReturnChunks is
      // O(n) anyway and the analyzer already yielded while building
      // ``delaysWithIdx``).
      if (delaysWithIdx[i] && i !== 0) {
        // eslint-disable-next-line no-await-in-loop
        await yieldToUi();
      }
    }
    const chunks = findReturnChunks(delaysWithIdx);
    if (!chunks.length) return null;
    // Use the median chunk length across all chunks as the command
    // length estimate, rather than just the last chunk. This is more
    // robust because the last chunk may contain only a single
    // keystroke (e.g. a trailing Return or partial command), while the
    // median captures the typical command shape.
    const lengths = chunks.map((c) => c.keystrokeCount).sort((a, b) => a - b);
    const medianIdx = Math.floor(lengths.length / 2);
    return lengths[medianIdx];
  }

  // Check the threshold of 100 packets at a time so that the rest of the
  // pipeline (chart, summary, candidates) doesn't block the UI thread.
  function selectSshEncounteredFlow(flowIndex) {
    const flow = sshFlows[flowIndex];
    const newKey = flow ? flow.flowKey : null;
    const keyChanged = newKey !== sshSelectedFlowKey;
    sshSelectedFlowKey = newKey;
    renderSshFlowDetails(flow);
    // Switched to a different flow? Drop the visible outputs so the
    // user doesn't see stale chart/candidates/insight from the
    // previously-analyzed flow. The flow-details pane is repopulated
    // by renderSshFlowDetails() above.
    if (keyChanged && newKey) clearSshOutputPanels();
  }

  function analyzeSelectedSshFlow() {
    const decoder = getSshDecoderModule();
    if (!decoder) {
      const summaryEl = document.getElementById("crypt-openssh-summary");
      if (summaryEl) {
        summaryEl.textContent =
          "Decoder module failed to load — see devtools for details.";
      }
      return;
    }
    const flow = sshFlows.find((f) => f.flowKey === sshSelectedFlowKey);
    if (!flow) return;
    const directionEl = document.getElementById("crypt-openssh-direction");
    const topNEl = document.getElementById("crypt-openssh-topn");
    const progressEl = document.getElementById("crypt-openssh-progress");
    const progressTextEl = document.getElementById("crypt-openssh-progress-text");
    const analyzeBtn = document.getElementById("crypt-openssh-analyze-btn");
    // Deobfuscator controls. Defaults match the HTML so a missing
    // element (e.g. older DOM) doesn't break the analysis.
    const deobfEnableEl = document.getElementById("crypt-openssh-deobf-enable");
    const deobfModeEl = document.getElementById("crypt-openssh-deobf-mode");
    const deobfCoverageEl = document.getElementById("crypt-openssh-deobf-coverage");
    const deobfCoverageLabelEl = document.getElementById("crypt-openssh-deobf-coverage-label");
    const deobfSettings = {
      enabled: deobfEnableEl ? !!deobfEnableEl.checked : true,
      mode: deobfModeEl ? deobfModeEl.value : "auto",
      minCoverage: deobfCoverageEl ? Number(deobfCoverageEl.value) : 0.5,
    };
    if (deobfCoverageEl && deobfCoverageLabelEl) {
      deobfCoverageLabelEl.textContent = Number(deobfCoverageEl.value).toFixed(2);
    }
    // Live-update the coverage label as the user drags the slider.
    if (deobfCoverageEl && deobfCoverageLabelEl) {
      deobfCoverageEl.addEventListener("input", () => {
        deobfCoverageLabelEl.textContent = Number(deobfCoverageEl.value).toFixed(2);
        deobfSettings.minCoverage = Number(deobfCoverageEl.value);
      });
    }
    // Enable/disable the rest of the controls when the master toggle
    // flips so the user gets clear feedback that the deobfuscator is off.
    function syncDeobfDisabledState() {
      const enabled = deobfEnableEl ? deobfEnableEl.checked : true;
      if (deobfModeEl) deobfModeEl.disabled = !enabled;
      if (deobfCoverageEl) deobfCoverageEl.disabled = !enabled;
      if (deobfCoverageLabelEl) deobfCoverageLabelEl.style.opacity = enabled ? "1" : "0.5";
      deobfSettings.enabled = enabled;
    }
    if (deobfEnableEl) deobfEnableEl.addEventListener("change", syncDeobfDisabledState);
    syncDeobfDisabledState();
    function setProgress(label) {
      if (progressEl) progressEl.hidden = false;
      // The progress span already has an animated loading-dots
      // pseudo-element (`.loading::after`), so the text shouldn't end
      // with its own ellipsis — that would render as double dots
      // ("Decoding keystrokes (3792 intervals)……" → looks like
      // "Decoding...  ...").
      let text = label || "Working";
      text = String(text).replace(/\.+\s*$/, "").replace(/…\s*$/, "");
      if (!text) text = "Working";
      if (progressTextEl) progressTextEl.textContent = text;
    }
    function clearProgress() {
      if (progressEl) progressEl.hidden = true;
      if (progressTextEl) progressTextEl.textContent = "Working";
      // Reveal + reset the staged indicators so the next Analyze
      // run starts from a clean slate.
      const stagesEl = document.getElementById("crypt-openssh-progress-stages");
      if (stagesEl) stagesEl.hidden = false;
      ["scanning", "decoding", "markov"].forEach((s) => {
        const stageEl = document.querySelector(
          `#crypt-openssh-progress-stages .crypt-openssh-stage[data-stage="${s}"]`,
        );
        if (stageEl) {
          stageEl.classList.remove("is-running", "is-done", "is-error");
        }
        const statusEl = document.querySelector(
          `#crypt-openssh-progress-stages [data-stage-status="${s}"]`,
        );
        if (statusEl) statusEl.textContent = "";
      });
    }
    // Update one stage's visual state. ``state`` is one of:
    //   ``"running"`` (the spinner dotted bullet lights up),
    //   ``"done"``    (a checkmark-equivalent suffix),
    //   ``"error"``   (an error marker).
    function markStage(stage, state, note) {
      if (typeof document === "undefined") return;
      const stageEl = document.querySelector(
        `#crypt-openssh-progress-stages .crypt-openssh-stage[data-stage="${stage}"]`,
      );
      if (stageEl) {
        stageEl.classList.remove("is-running", "is-done", "is-error");
        if (state) stageEl.classList.add(`is-${state}`);
      }
      const statusEl = document.querySelector(
        `#crypt-openssh-progress-stages [data-stage-status="${stage}"]`,
      );
      if (statusEl) statusEl.textContent = note ? ` — ${note}` : "";
    }
    if (analyzeBtn) analyzeBtn.disabled = true;
    // Wipe the visible outputs immediately so the user doesn't see
    // stale chart / candidates / insight from a previous Analyze run
    // (or from a different flow) while the new analysis is in
    // flight. The cache is also cleared so the export button
    // reverts to "needs analyze" while we work.
    clearSshOutputPanels();
    setProgress("Scanning packets…");
    markStage("scanning", "running", null);
    markStage("decoding", null);
    markStage("markov", null);
    // Disable export until this new analysis completes; the cache will
    // be refreshed (and the button re-enabled) at the end of the run.
    const exportBtn = document.getElementById("crypt-openssh-export-btn");
    if (exportBtn) exportBtn.disabled = true;
    const direction = directionEl?.value || "both";
    const topN = Math.max(1, Number(topNEl?.value || 32));
    // The LLM needs more evidence than the UI table shows. ``llmTopN`` is
    // the working set we send to the language model for reranking and
    // best-guess assembling — larger than the on-screen candidate list so
    // the LLM can pick up commands/filenames that the Viterbi beam pruned.
    const llmTopN = Math.max(topN, 32);
    const summaryEl = document.getElementById("crypt-openssh-summary");
    ensureSshModelLoaded()
      .then(async (model) => {
        // Use the indexed delays so we can map large pauses back to a
        // keystroke position and estimate the command length (Enter/Return).
        // Build the delays in chunks of 100 packets to keep the UI thread
        // responsive on very long sessions.
        const delaysWithIdx = await computeInterPacketDelaysWithIndexesAsync(flow.packets, direction, ({ processed, total }) => {
          if (summaryEl) {
            summaryEl.textContent = `Building inter-key delays (${processed}/${total})...`;
          }
          setProgress(`Building inter-key delays (${processed}/${total})…`);
        });
        markStage("scanning", "done", `${delaysWithIdx.length} intervals`);
        const delays = delaysWithIdx.map((d) => d.delay);
        // Detect obfuscation-packet padding before the histogram/decoder
        // stage. SSH servers sometimes insert filler packets on a fixed
        // cadence to defeat keystroke-side analysis. The detector now
        // finds the cadence on its own (via a first-difference
        // histogram scan + refine), and returns three artefacts:
        //   - snappedDelaysMs      : each delay with the nearest integer
        //                            multiple of the cadence subtracted
        //                            (preserves interval count)
        //   - keystrokeDelaysMs    : same as above but with the filler
        //                            intervals REMOVED so the decoder
        //                            sees one delay per real keystroke
        //   - paddedIntervals      : indices into the input array that
        //                            were classified as filler (for
        //                            diagnostics + the LLM brief)
        // Auto-tune the coverage threshold when the deobfuscator is
        // set to its default "auto" mode. The tuner sweeps a range
        // of minCoverage values, runs the detector at each, and
        // picks the value whose peeled keystroke stream yields
        // chunks whose lengths cluster in the 5–50 range (typical
        // shell command length). The user's slider value is honored
        // when mode is "force" or when "auto" produces no detection.
        const useAutoTune = deobfSettings.enabled
          && deobfSettings.mode === "auto"
          && typeof decoder.autoTunePaddingThreshold === "function";
        const paddingResult = useAutoTune
          ? decoder.autoTunePaddingThreshold(delays, {
            minCoverage: deobfSettings.minCoverage,
          })
          : (typeof decoder.detect20msPadding === "function"
            ? decoder.detect20msPadding(delays, {
              // User-controlled deobfuscator settings. The detector
              // honours `minCoverage` directly; `enabled` and `mode`
              // are post-processed below via applyDeobfuscatorMode.
              minCoverage: deobfSettings.minCoverage,
            })
            : { detected: false, candidateScores: [] });
        // When auto-tune ran, surface the chosen threshold so the
        // user can see what the algorithm picked.
        if (useAutoTune && paddingResult.autotuneSelected != null) {
          paddingResult.selectedMinCoverage = paddingResult.autotuneSelected;
        }
        // Apply user-selected mode (off/auto/force) on top of the
        // detector's verdict. The helper is shared with the export
        // tests so the off/force semantics stay in sync.
        const deobfHelper = (sshExportModule && typeof sshExportModule.applyDeobfuscatorMode === "function")
          ? sshExportModule.applyDeobfuscatorMode
          : null;
        const appliedPadding = deobfHelper
          ? deobfHelper(paddingResult, delays, deobfSettings)
          : paddingResult;
        let effectiveDelays = delays;
        if (appliedPadding.detected) {
          // Prefer keystrokeDelaysMs (filler intervals removed) so the
          // decoder's Viterbi beam isn't polluted by extra low-delay
          // samples. Fall back to snappedDelaysMs if the refined pass
          // didn't produce keystroke delays (e.g. snap:false was set).
          if (Array.isArray(appliedPadding.keystrokeDelaysMs)) {
            effectiveDelays = appliedPadding.keystrokeDelaysMs;
          } else if (Array.isArray(appliedPadding.snappedDelaysMs)) {
            effectiveDelays = appliedPadding.snappedDelaysMs;
          }
          const modeLabel = deobfSettings.mode === "force" ? " (forced)" : "";
          const tuneLabel = (appliedPadding.selectedMinCoverage != null)
            ? ` (auto-tuned coverage ${(appliedPadding.selectedMinCoverage * 100).toFixed(0)}%, ${appliedPadding.autotuneChunkCount || 0} chunks)`
            : "";
          setProgress(
            `Detected${modeLabel} ${appliedPadding.periodMs}ms padding cadence ` +
            `(coverage ${(appliedPadding.coverage * 100).toFixed(0)}%, ` +
            `${appliedPadding.paddedIntervals ? appliedPadding.paddedIntervals.length : 0} filler intervals)${tuneLabel}; peeling off…`,
          );
          await yieldToUi();
        } else if (
          deobfSettings.enabled
          && deobfSettings.mode === "auto"
          && appliedPadding.candidateScores
          && appliedPadding.candidateScores.length > 0
        ) {
          // No confident detection this time — show the best candidate
          // so the user can see why and lower the coverage threshold
          // if they want to peel more aggressively.
          const best = appliedPadding.candidateScores
            .slice()
            .sort((a, b) => {
              if (b.coverage !== a.coverage) return b.coverage - a.coverage;
              return a.residualStdMs - b.residualStdMs;
            })[0];
          if (best && Number.isFinite(best.periodMs)) {
            setProgress(
              `No confident cadence (best candidate ${best.periodMs}ms at ` +
              `${(best.coverage * 100).toFixed(0)}% coverage — below threshold ${(deobfSettings.minCoverage * 100).toFixed(0)}%).`,
            );
            await yieldToUi();
          }
        }
        if (summaryEl) {
          summaryEl.textContent = `Building histogram (${effectiveDelays.length} intervals)...`;
        }
        setProgress(`Building histogram (${effectiveDelays.length} intervals)…`);
        await yieldToUi();
        const series = await buildChartSeriesAsync(effectiveDelays, decoder);
        renderSshChartWithSeries(series, effectiveDelays, decoder);
        if (summaryEl) {
          summaryEl.textContent = `Decoding keystrokes (${effectiveDelays.length} intervals)...`;
        }
        setProgress(`Decoding keystrokes (${effectiveDelays.length} intervals)…`);
        markStage("decoding", "running", `${effectiveDelays.length} intervals`);
        await yieldToUi();
        let candidates;
        try {
          // Prefer the worker-thread decoder when the preload bridge is
          // available — it runs the synchronous Viterbi on a worker so
          // the renderer never blocks, even on very long sessions. Speed
          // is prioritized over progress reporting here: the worker
          // decode is opaque (no per-interval count), which is an
          // accepted trade-off because it's the fastest path.
          const api =
            typeof window !== "undefined" && window.opensshapi
              ? window.opensshapi
              : null;
          if (api && typeof api.decode === "function") {
            const resp = await api.decode({ delays: effectiveDelays, topN, model });
            if (resp && resp.success && Array.isArray(resp.candidates)) {
              candidates = resp.candidates;
            } else {
              console.warn("[Crypt/OpenSSH] worker decode failed:", resp && resp.error);
              candidates = decoder.decodeKeystrokes(effectiveDelays, { topN, model });
            }
          } else if (typeof decoder.decodeKeystrokesBatched === "function") {
            // Fallback: batched decoder runs on the main thread but yields.
            candidates = await decoder.decodeKeystrokesBatched(effectiveDelays, { topN, model, batchSize: 100 });
          } else {
            candidates = decoder.decodeKeystrokes(effectiveDelays, { topN, model });
          }
        } catch (err) {
          console.warn("[Crypt/OpenSSH] decode failed, falling back:", err);
          candidates = decoder.decodeKeystrokes(effectiveDelays, { topN, model });
        }
        if (summaryEl) {
          summaryEl.textContent = `Estimating command length (${delaysWithIdx.length} samples)...`;
        }
        setProgress(`Estimating command length (${delaysWithIdx.length} samples)…`);
        await yieldToUi();
        // Compute command length from the PEELED stream when the
        // padding detector identified filler packets. With a
        // heavily obfuscated session (median delay ~11ms) the raw
        // stream's "small c2s packet" heuristic sees filler as
        // keystrokes and reports 1 keystroke per Return; the peeled
        // stream gives a real per-command length.
        let estimatedCommandLength = null;
        if (appliedPadding.detected && Array.isArray(appliedPadding.keystrokeDelaysMs)) {
          const peeledIndexed = buildIndexedDelaysFromPeeled(appliedPadding.keystrokeDelaysMs);
          estimatedCommandLength = await estimateCommandLengthFromDelaysWithIdxAsync(peeledIndexed);
        }
        if (!Number.isFinite(estimatedCommandLength)) {
          estimatedCommandLength = await estimateCommandLengthFromDelaysWithIdxAsync(delaysWithIdx);
        }
        const backspaceHints = await detectBackspaceHintsAsync(delaysWithIdx);

        // Run the LLM as the primary result builder. The decoder provides
        // a working set of timing-derived candidate strings; the language
        // model assembles them with shell/file language priors and returns
        // a single best-guess text, probability, kind, and a short
        // rationale. The decoder candidates remain visible as supporting
        // evidence below the primary result.
        (async () => {
          setProgress("Asking LLM to assemble best guess…");
          let finalCandidates = candidates.slice();
          let primaryResult = null;
          let insightResult = null;
          // mode drives the placeholder text inside the LLM cards when
          // the prompt ran but didn't yield a usable result.
          let renderMode = "no-llm";
          try {
            if (typeof window !== "undefined" && window.llmapi && typeof window.llmapi.generate === "function") {
              renderMode = "no-result";
              try {
                let s2cSummary = null;
                if (
                  sshExportModule &&
                  typeof sshExportModule.summarizeS2cOutput === "function" &&
                  flow && Array.isArray(flow.packets) && flow.packets.length > 0
                ) {
                  try {
                    s2cSummary = sshExportModule.summarizeS2cOutput(flow.packets);
                  } catch (err) {
                    console.warn("[Crypt/OpenSSH] summarizeS2cOutput failed:", err);
                    s2cSummary = { ok: false, reason: "exception" };
                  }
                }
                // Pass the *peeled* delays (post-padding-removal) to the
                // LLM brief. The raw delays still carry the 20 ms server
                // obfuscation blip, which floods the brief's aggregate
                // timing stats with artificial jitter and degrades
                // decoder accuracy downstream. The padding detector
                // Pass the *peeled* delays (post-padding-removal) to the
                // LLM brief. The raw delays still carry the 20 ms server
                // obfuscation blip, which floods the brief's aggregate
                // timing stats with artificial jitter and degrades
                // decoder accuracy downstream. The padding detector
                // already removed the cadence when ``detected`` is true.
                let shellCorpus = null;
                if (window.opensshapi && typeof window.opensshapi.loadShellCorpus === "function") {
                  try {
                    const corpusResult = await window.opensshapi.loadShellCorpus();
                    if (corpusResult && corpusResult.success && typeof corpusResult.corpus === "string") {
                      shellCorpus = corpusResult.corpus;
                    }
                  } catch (corpusErr) {
                    console.warn("[Crypt/OpenSSH] shell corpus load failed:", corpusErr);
                  }
                }
                // Ask the LLM to assemble a single best-guess primary
                // result and a short insight paragraph, and to rerank the
                // decoder candidates so the evidence table below the
                // primary card reflects the same confidence order. When
                // the LLM is unavailable ``assembleLlmPrimaryResult``
                // returns only ``rankedCandidates`` (the decoder's own
                // order), so the timing evidence still renders.
                const llmBundle = await assembleLlmPrimaryResult(effectiveDelays, candidates, model, {
                  estimatedCommandLength,
                  delaysWithIdx,
                  backspaceHints,
                  flow,
                  direction,
                  paddingDetection: paddingResult,
                  s2cSummary,
                  shellCorpus,
                });
                if (llmBundle && llmBundle.primary) {
                  primaryResult = llmBundle.primary;
                }
                if (llmBundle && llmBundle.insight) {
                  insightResult = llmBundle.insight;
                }
                if (Array.isArray(llmBundle && llmBundle.rankedCandidates) && llmBundle.rankedCandidates.length > 0) {
                  finalCandidates = llmBundle.rankedCandidates;
                }
                if (primaryResult || insightResult) renderMode = "ok";
              } catch (innerErr) {
                console.warn("[Crypt/OpenSSH] LLM primary result failed:", innerErr);
                renderMode = "error";
              }
            }
          } catch (outerErr) {
            // Defensive guard around the feature-detect block above.
            console.warn("[Crypt/OpenSSH] LLM primary result path failed:", outerErr);
            renderMode = "error";
          }
          // Render the primary/insight cards, the keystroke-timing
          // evidence table (with the per-candidate Avg Δ column), and
          // the summary line. These calls were dropped in a prior
          // refactor which is why the timing results below the stats
          // stopped appearing — and, because the analysis was never
          // cached, the Markov stage bailed on ``!cached`` and never
          // generated. Restored here.
          renderSshPrimary(primaryResult, insightResult, { mode: renderMode });
          renderSshCandidates(finalCandidates, delays, decoder);
          renderSshSummary(flow, delays, finalCandidates, estimatedCommandLength, backspaceHints);
          // Cache the analysis so the Markov stage (below) can pick it
          // up, and so the user can export the keystroke-timing trace
          // and re-pick a different flow without losing the prior
          // flow's data. Keyed by flowKey.
          if (delays && delays.length > 0 && flow && flow.flowKey) {
            sshLastAnalysisByFlowKey.set(flow.flowKey, {
              flow,
              model,
              direction,
              delays,
              delaysWithIdx,
              candidates: finalCandidates,
              primary: primaryResult,
              insight: insightResult,
              renderMode,
              estimatedCommandLength,
              backspaceHints,
              paddingDetection: paddingResult,
              analyzedAt: new Date().toISOString(),
            });
          }
          // Kick off the Markov beam search in the background. We're
          // not awaiting it because the user's analysis result is
          // already on screen; we just attach the candidates when
          // they arrive so the JSON export ends up with them.
          if (sshMarkovModule && typeof window !== "undefined" && window.markovapi) {
            // Mark the markov stage as running up front so the user
            // sees the chain is in flight, not silently failing.
            markStage("markov", "running", "loading model…");
            ensureShellMarkovReady().then(async (model) => {
              if (!model) {
                markStage("markov", "error", "model unavailable");
                return;
              }
              markStage("markov", "running", "generating…");
              const cached = sshLastAnalysisByFlowKey.get(flow.flowKey);
              if (!cached) return;
              // The cache stores the RAW delays (needed for the
              // markov export's "rawDelays" field). But the beam
              // search and the chunk splitter should both see the
              // PEELED stream — otherwise an obfuscated session
              // (median delay ~11ms) makes the ranker fit timing
              // to filler packets and the chunk splitter sees
              // hundreds of "keystrokes" per "command". Pull the
              // peeled delays out of the padding-detection cache
              // when present, and use them as the primary input.
              const pad = cached.paddingDetection;
              const peeledDelays = (pad && Array.isArray(pad.keystrokeDelaysMs))
                ? pad.keystrokeDelaysMs
                : null;
              const delaysForMarkov = (peeledDelays && peeledDelays.length > 0)
                ? peeledDelays
                : (cached.delaysWithIdx || []).map((d) => Number(d.delay)).filter(Number.isFinite);
              // The estimated command length is computed from the
              // RAW delay stream by findReturnChunks() — but with a
              // heavily obfuscated session the chunk splitter sees
              // filler as keystrokes and reports "1 keystroke per
              // Return" which makes the beam target 1-char strings.
              // Recompute the command length on the peeled stream
              // for the beam target. Fall back to the cached value
              // when peeling didn't run.
              let targetLen = Number.isFinite(cached.estimatedCommandLength)
                ? Math.max(1, Math.round(cached.estimatedCommandLength))
                : null;
              if (peeledDelays && peeledDelays.length > 1) {
                const rebuilt = buildIndexedDelaysFromPeeled(peeledDelays);
                const chunks = (typeof findReturnChunks === "function")
                  ? findReturnChunks(rebuilt)
                  : [];
                if (chunks.length > 0) {
                  // Use the median chunk length as the beam
                  // target — this is the typical-command shape the
                  // auto-tuner is also trying to recover. Falls
                  // back to the last chunk (most recent command).
                  const lengths = chunks.map((c) => c.keystrokeCount).sort((a, b) => a - b);
                  const medianChunk = lengths[Math.floor(lengths.length / 2)];
                  targetLen = Math.max(3, medianChunk || 1);
                }
              }
              if (!targetLen) targetLen = 8;
              // Merge ciphertext-aware signals into the prior the
              // ranker sees. The JSON export we now produce carries
              // per-packet fields (ciphertextLength, seq) and the
              // delays[] table (delayMs, packetIndex); we read
              // those signals from the cached analysis and feed
              // them into the rerank so the chain's top-1 lines up
              // with the user's actual typing rhythm.
              const packetLengths = (cached.delaysWithIdx || [])
                .map((d) => Number(d.packetLength))
                .filter((n) => Number.isFinite(n));

              // Use rankCorpus instead of generateBeam:
              // - Returns actual corpus lines, not generated garbage
              // - Already sorted by frequency + Markov probability
              // - Length-aware filtering with slot flexibility
              const beam = model.rankCorpus(targetLen, 5, 100);

              // Re-rank with timing for the top-N using the
              // peeled delays so candidates that match the user's
              // typing rhythm bubble up.
              const reranked = model.rankWithTiming(
                beam,
                delaysForMarkov,
                0.22,
              ).slice(0, 30);

              // Per-Return chunk: split the PEELED stream into
              // Return-shaped chunks and run one beam per chunk.
              // Using peeled delays here is the difference between
              // "9 chunks × 8 keystrokes" (a usable guess) and
              // "hundreds of chunks × 1 keystroke" (gibberish).
              const chunkSourceDelays = peeledDelays || delaysForMarkov;
              const rebuiltIndexed = buildIndexedDelaysFromPeeled(chunkSourceDelays);
              const chunkList = (typeof findReturnChunks === "function")
                ? findReturnChunks(rebuiltIndexed)
                : [];
              // Process the per-Return chunks one at a time so we can
              // surface a live "N/M chunks" counter in the markov stage
              // note (letting the user estimate completion), and yield to
              // the UI between chunks so the count actually paints.
              const totalMarkovChunks = chunkList.length;
              const markovChunks = [];
              for (let ci = 0; ci < totalMarkovChunks; ci += 1) {
                const ch = chunkList[ci];
                markStage(
                  "markov",
                  "running",
                  `generating… ${ci + 1}/${totalMarkovChunks} chunk(s)`,
                );
                const segDelays = rebuiltIndexed
                  .slice(ch.startIdx, ch.endIdx + 1)
                  .map((d) => Number(d.delay))
                  .filter(Number.isFinite);

                // Use rankCorpus for per-chunk candidates too
                const segBeam = model.rankCorpus(
                  Math.max(3, ch.keystrokeCount),
                  3,  // tolerance
                  20,  // top N
                );
                const segRanked = model
                  .rankWithTiming(segBeam, segDelays, 0.22)
                  .slice(0, 3);
                markovChunks.push({
                  keystrokeCount: ch.keystrokeCount,
                  startIdx: ch.startIdx,
                  endIdx: ch.endIdx,
                  top: segRanked.map(([score, text]) => ({ score, text })),
                });
                // Yield so the stage-note repaint is visible mid-run.
                await yieldToUi();
              }

              sshLastAnalysisByFlowKey.set(flow.flowKey, {
                ...cached,
                markovCandidates: reranked,
                markovChunks,
                // Echo the merged features so the JSON export
                // includes the same context the UI shows.
                markovFeatures: {
                  targetLen,
                  delayCount: delaysForMarkov.length,
                  peeledDelayCount: peeledDelays ? peeledDelays.length : null,
                  packetLengthMean: packetLengths.length
                    ? packetLengths.reduce((s, n) => s + n, 0) / packetLengths.length
                    : null,
                  chunkCount: markovChunks.length,
                },
              });
              // Type-out UI: keep the existing Viterbi primary on
              // screen until this point (per spec), then overwrite
              // with the chain's per-chunk results so the user
              // sees "one guess per Return-shaped gap".
              renderSshPrimaryFromMarkov(
                {
                  ...cached,
                  markovFeatures: {
                    targetLen,
                    chunkCount: markovChunks.length,
                  },
                },
                reranked,
                { nCommands: model.nCommands, chunks: markovChunks },
              );
              // Console-shape diagnostic. If the user reports the
              // markov data is missing on screen, this prints the
              // chunk / candidate sizes so we can verify the data
              // reached the renderer.
              try {
                console.log(
                  "[Crypt/OpenSSH] markov: rendered",
                  markovChunks.length, "chunk(s);",
                  "reranked top-1:", reranked[0] && reranked[0][1],
                  "score:",
                  reranked[0] && reranked[0][0],
                );
              } catch (_e) { /* ignore */ }
              // Surface the peeled-stream command length in the
              // summary so the user can see whether peeling
              // succeeded. With heavy obfuscation this number can
              // be wildly different from the raw-stream estimate
              // the analyzer pane shows.
              try {
                if (peeledDelays && peeledDelays.length > 1) {
                  const chunkStats = computeChunkShapeStats(delaysForMarkov);
                  console.log(
                    "[Crypt/OpenSSH] markov: peeled chunks=",
                    chunkStats.chunkCount,
                    "median keystrokes=",
                    chunkStats.median,
                    "targetLen=", targetLen,
                  );
                }
              } catch (_e) { /* ignore */ }
              markStage(
                "markov",
                "done",
                `${markovChunks.length || 0} chunk(s) · ${model.nCommands} commands`,
              );
            }).catch((err) => {
              markStage("markov", "error", err?.message ? String(err.message) : "failed");
            });
          } else {
            // No markovapi bridge — surface that so the user knows
            // the markov stage was skipped, not silently no-op'd.
            markStage("markov", "error", "markovapi unavailable");
          }
          refreshSshExportButton();
          clearProgress();
          if (analyzeBtn) analyzeBtn.disabled = false;
        })();
      })
      .catch((err) => {
        if (summaryEl) {
          summaryEl.textContent =
            "Failed to load QWERTY model: " + (err?.message || err);
        }
        clearProgress();
        if (analyzeBtn) analyzeBtn.disabled = false;
        // Restore the export button to whatever the cache allows. A prior
        // successful analysis for this flow may still be exportable.
        refreshSshExportButton();
      });
  }

  function renderSshChartWithSeries(series, delays, decoder) {
    const chartEl = document.getElementById("crypt-openssh-chart");
    const legendEl = document.getElementById("crypt-openssh-chart-legend");
    if (!chartEl) return;
    if (!delays.length) {
      chartEl.replaceChildren();
      if (legendEl) {
        legendEl.textContent =
          "Not enough packets in this direction to plot a distribution.";
      }
      return;
    }
    const layout = {
      margin: { t: 20, r: 12, l: 40, b: 36 },
      bargap: 0.05,
      xaxis: {
        title: { text: "Inter-key delay (ms)" },
        range: [0, Math.max(...series.histogram.x) + series.binSize],
      },
      yaxis: { title: { text: "Count" } },
      legend: { orientation: "h", y: -0.2 },
      paper_bgcolor: "rgba(0,0,0,0)",
      plot_bgcolor: "rgba(0,0,0,0)",
    };
    if (typeof window.Plotly !== "undefined") {
      window.Plotly.newPlot(
        chartEl,
        [series.histogram, series.reference],
        layout,
        { displayModeBar: false, responsive: true },
      );
    } else if (legendEl) {
      legendEl.textContent =
        "Plotly unavailable — chart skipped. Histogram: " +
        JSON.stringify(series.histogram.y);
    }
    if (legendEl) {
      legendEl.textContent =
        `${delays.length} inter-key delays. ${series.binSize} ms bins. ` +
        `Reference Gaussian (μ=${decoder.DEFAULT_DIGRAPH_PARAMS.mean} ms, σ=${decoder.DEFAULT_DIGRAPH_PARAMS.std} ms).`;
    }
  }

  function renderSshChart(delays, decoder) {
    const chartEl = document.getElementById("crypt-openssh-chart");
    const legendEl = document.getElementById("crypt-openssh-chart-legend");
    if (!chartEl) return;
    if (!delays.length) {
      chartEl.replaceChildren();
      if (legendEl) {
        legendEl.textContent =
          "Not enough packets in this direction to plot a distribution.";
      }
      return;
    }
    const series = decoder.buildChartSeries(delays);
    const layout = {
      margin: { t: 20, r: 12, l: 40, b: 36 },
      bargap: 0.05,
      xaxis: {
        title: { text: "Inter-key delay (ms)" },
        range: [0, Math.max(...series.histogram.x) + series.binSize],
      },
      yaxis: { title: { text: "Count" } },
      legend: { orientation: "h", y: -0.2 },
      paper_bgcolor: "rgba(0,0,0,0)",
      plot_bgcolor: "rgba(0,0,0,0)",
    };
    if (typeof window.Plotly !== "undefined") {
      window.Plotly.newPlot(
        chartEl,
        [series.histogram, series.reference],
        layout,
        { displayModeBar: false, responsive: true },
      );
    } else if (legendEl) {
      legendEl.textContent =
        "Plotly unavailable — chart skipped. Histogram: " +
        JSON.stringify(series.histogram.y);
    }
    if (legendEl) {
      legendEl.textContent =
        `${delays.length} inter-key delays. ${series.binSize} ms bins. ` +
        `Reference Gaussian (μ=${decoder.DEFAULT_DIGRAPH_PARAMS.mean} ms, σ=${decoder.DEFAULT_DIGRAPH_PARAMS.std} ms).`;
    }
  }

  /**
   * Render the LLM-derived insight + primary result cards.
   * ``insight`` is shown at the top of the Top-N full-width section
   * (just under the dropdowns and above the top-guess); ``primary``
   * follows directly underneath. Both are ``null`` when the LLM
   * is unavailable — in that case we keep the cards visible with a
   * diagnostic message so the user can see that the LLM prompt path
   * exists, even when no LLM is configured or the model call failed.
   *
   * ``mode`` is one of:
   *   - "ok"        — primary and/or insight came back from the LLM
   *   - "no-llm"    — ``window.llmapi.generate`` is unavailable
   *   - "no-result" — LLM call returned an empty/unparseable result
   *   - "error"     — LLM call threw an exception
   */
  // Type out a string element-by-element into ``el`` over roughly
  // ``charMs`` per character. Honors ``AbortSignal`` (so the next
  // pass can interrupt mid-typewriter when more data arrives or
  // the user clicks Analyze again).
  function typewriteIntoEl(el, text, opts) {
    if (!el) return Promise.resolve();
    if (typeof text !== "string") text = String(text || "");
    const charMs = (opts && Number.isFinite(opts.charMs)) ? opts.charMs : 6;
    const signal = opts && opts.signal;
    el.replaceChildren();
    if (!text) return Promise.resolve();
    return new Promise((resolve) => {
      let i = 0;
      const tick = () => {
        if (signal && signal.aborted) { resolve(); return; }
        if (i >= text.length) { resolve(); return; }
        // Append a single character; preserves any rich-text styling
        // we may add later (e.g., a span-per-character cursor).
        el.appendChild(document.createTextNode(text[i]));
        i += 1;
        const wait = charMs + Math.floor(Math.random() * 3);
        setTimeout(tick, wait);
      };
      tick();
    });
  }

  // ── Enhanced confidence-scored Markov rendering ─────────────────────
  //
  // Helper: get color class for confidence value
  function _confidenceColorClass(conf) {
    if (conf >= 0.7) return "high";
    if (conf >= 0.4) return "medium";
    return "low";
  }

  // Render the Markov-chain result into the primary card. Enhanced with:
  // - Session confidence score (overall signal quality)
  // - Line confidence scores (per-candidate with all factors)
  // - Multi-candidate list display with confidence on the left
  // Helper: enhance a chunk's candidates with line confidence
  function _enhanceChunkCandidates(chunk, chunkIdx, lineOptsBase, haveLineConf, sshMarkovModule) {
    const enhanced = [];
    const alternatives = (chunk && chunk.top) || [];

    for (let i = 0; i < alternatives.length; i += 1) {
      const alt = alternatives[i];
      const text = alt && alt.text ? String(alt.text) : "";
      const markovScore = Number.isFinite(alt.score) ? alt.score : null;

      const entry = {
        rank: i + 1,
        markovScore: markovScore,
        text: text,
        lineConfidence: null,
      };

      if (haveLineConf && text && sshMarkovModule) {
        const lineOpts = { ...lineOptsBase };
        // If this chunk has its own keystroke count, use that for length
        if (Number.isFinite(chunk.keystrokeCount)) {
          lineOpts.estimatedLength = chunk.keystrokeCount;
        }
        entry.lineConfidence = sshMarkovModule.computeLineConfidence(text, lineOpts);
      }

      entry.sortKey = Number.isFinite(entry.lineConfidence)
        ? entry.lineConfidence
        : (Number.isFinite(markovScore) ? markovScore : -100);

      enhanced.push(entry);
    }

    // Re-rank by line confidence if available
    if (enhanced.some((c) => Number.isFinite(c.lineConfidence))) {
      enhanced.sort((a, b) => b.sortKey - a.sortKey);
      enhanced.forEach((c, idx) => { c.rank = idx + 1; });
    }

    return enhanced;
  }

  function renderSshPrimaryFromMarkov(cached, reranked, modelInfo) {
    const primaryEl = document.getElementById("crypt-openssh-primary");
    const textEl = document.getElementById("crypt-openssh-primary-text");
    const confEl = document.getElementById("crypt-openssh-primary-confidence");
    const kindEl = document.getElementById("crypt-openssh-primary-kind");
    const sourceEl = document.getElementById("crypt-openssh-primary-source");
    const rationaleEl = document.getElementById("crypt-openssh-primary-rationale");
    // Markov output panel elements
    const markovSectionEl = document.getElementById("crypt-openssh-markov-section");
    const markovTextEl = document.getElementById("crypt-openssh-markov-text");
    const markovConfEl = document.getElementById("crypt-openssh-markov-confidence");
    const markovTargetEl = document.getElementById("crypt-openssh-markov-target");
    const markovSourceEl = document.getElementById("crypt-openssh-markov-source");
    // Session confidence elements
    const sessionConfEl = document.getElementById("crypt-openssh-markov-session-confidence");
    const sessionConfValueEl = document.getElementById("crypt-openssh-session-confidence-value");
    const sessionConfInterpEl = document.getElementById("crypt-openssh-session-confidence-interpretation");
    // Timeline elements
    const timelineTitleEl = document.getElementById("crypt-openssh-markov-timeline-title");
    const timelineEl = document.getElementById("crypt-openssh-markov-timeline");
    // Fallback: candidates list elements (for single-chunk or legacy mode)
    const candidatesListTitleEl = document.getElementById("crypt-openssh-markov-list-title");
    const candidatesListEl = document.getElementById("crypt-openssh-markov-candidates-list");

    if (!textEl) return;
    // Make panels visible
    if (primaryEl) primaryEl.hidden = false;
    if (markovSectionEl) markovSectionEl.hidden = false;

    const chunks = (modelInfo && Array.isArray(modelInfo.chunks))
      ? modelInfo.chunks
      : null;

    // Get top candidate for the primary card
    let top = "";
    if (chunks && chunks.length > 0) {
      const first = chunks[0];
      top = (first && first.top && first.top[0] && first.top[0].text) || "";
    }
    if (!top && reranked && reranked[0] && reranked[0][1]) {
      top = reranked[0][1];
    }
    const body = top ? `Top candidate: ${top}` : "Top candidate: (none)";

    // Diagnostic log
    try {
      console.log(
        "[Crypt/OpenSSH] renderSshPrimaryFromMarkov:",
        "chunks=", chunks && chunks.length,
        "chunk0.top[0]=", chunks && chunks[0] && chunks[0].top && chunks[0].top[0],
        "reranked[0]=", reranked && reranked[0],
        "top=", JSON.stringify(top),
      );
    } catch (_e) { /* ignore */ }

    // Immediate write + typewriter
    if (textEl) textEl.textContent = body;
    if (markovTextEl) markovTextEl.textContent = top || "(none)";
    if (body) void typewriteIntoEl(textEl, body, { charMs: 6 });

    // ── Session confidence ──────────────────────────────────────────

    let sessionConfidence = null;
    const haveConfFunctions = sshMarkovModule
      && typeof sshMarkovModule.computeSessionConfidence === "function"
      && typeof sshMarkovModule.computeDelayStats === "function";

    if (haveConfFunctions && cached) {
      const pad = cached.paddingDetection;
      const markovFeats = cached.markovFeatures || {};
      const delaysForMarkov = (pad && Array.isArray(pad.keystrokeDelaysMs))
        ? pad.keystrokeDelaysMs
        : (cached.delaysWithIdx || []).map((d) => Number(d.delay)).filter(Number.isFinite);

      const sessionOpts = {};

      // Chunk count
      if (Number.isFinite(markovFeats.chunkCount)) {
        sessionOpts.chunkCount = markovFeats.chunkCount;
      } else if (chunks && chunks.length > 0) {
        sessionOpts.chunkCount = chunks.length;
      }

      // Clear gap count (chunk count is our proxy)
      if (sessionOpts.chunkCount) {
        sessionOpts.clearGapCount = sessionOpts.chunkCount;
      }

      // Delay stats
      if (delaysForMarkov && delaysForMarkov.length >= 2) {
        const stats = sshMarkovModule.computeDelayStats(delaysForMarkov);
        if (stats.count >= 2) {
          sessionOpts.delayMean = stats.mean;
          sessionOpts.delayStd = stats.std;
          sessionOpts.medianDelayMs = stats.median;
        }
      }

      // Obfuscation
      if (pad && pad.detected) {
        sessionOpts.obfuscationDetected = true;
        sessionOpts.obfuscationCoverage = Number.isFinite(pad.coverage)
          ? pad.coverage
          : 0.5;
      }

      sessionConfidence = sshMarkovModule.computeSessionConfidence(sessionOpts);
    }

    // Render session confidence
    if (sessionConfEl) {
      if (sessionConfidence) {
        sessionConfEl.hidden = false;
        if (sessionConfValueEl) {
          sessionConfValueEl.textContent = sessionConfidence.label;
        }
        if (sessionConfInterpEl) {
          sessionConfInterpEl.textContent = sessionConfidence.interpretation;
        }
        console.log("[Crypt/OpenSSH] session confidence:", sessionConfidence);
      } else {
        sessionConfEl.hidden = true;
      }
    }

    // ── Line confidence + Chronological Timeline ────────────────────

    const haveLineConf = sshMarkovModule
      && typeof sshMarkovModule.computeLineConfidence === "function";

    const pad = cached && cached.paddingDetection;
    const targetLen = cached && Number.isFinite(cached.estimatedCommandLength)
      ? Math.max(1, Math.round(cached.estimatedCommandLength))
      : null;
    const delaysForMarkov = (pad && Array.isArray(pad.keystrokeDelaysMs))
      ? pad.keystrokeDelaysMs
      : (cached && cached.delaysWithIdx || []).map((d) => Number(d.delay)).filter(Number.isFinite);

    // Base line options for confidence calculation
    const lineOptsBase = {
      estimatedLength: targetLen,
      lengthTolerance: 2,
    };
    if (delaysForMarkov && delaysForMarkov.length >= 2) {
      lineOptsBase.delaysMs = delaysForMarkov;
    }
    if (pad && pad.detected) {
      lineOptsBase.obfuscationDetected = true;
      lineOptsBase.obfuscationCoverage = Number.isFinite(pad.coverage)
        ? pad.coverage
        : 0.5;
    }

    // Kind/target length
    if (kindEl) {
      const chunkCount = cached && cached.markovFeatures
        && Number.isFinite(cached.markovFeatures.chunkCount)
        ? cached.markovFeatures.chunkCount
        : (chunks && chunks.length ? chunks.length : null);
      const tail = chunkCount != null ? ` across ${chunkCount} Return(s)` : "";
      kindEl.textContent = targetLen
        ? `Target length: ${targetLen}${tail}`
        : `Target length: auto${tail}`;
    }
    if (markovTargetEl) {
      const chunkCount = cached && cached.markovFeatures
        && Number.isFinite(cached.markovFeatures.chunkCount)
        ? cached.markovFeatures.chunkCount
        : (chunks && chunks.length ? chunks.length : null);
      const tail = chunkCount != null ? ` across ${chunkCount} Return(s)` : "";
      markovTargetEl.textContent = targetLen
        ? `Target length: ${targetLen}${tail}`
        : `Target length: auto${tail}`;
    }

    // Source
    if (sourceEl) {
      const n = modelInfo && Number.isFinite(modelInfo.nCommands)
        ? `${modelInfo.nCommands}-cmd corpus`
        : "shell_corpus corpus";
      sourceEl.textContent = `Markov chain (${n})`;
    }
    if (markovSourceEl) {
      const n = modelInfo && Number.isFinite(modelInfo.nCommands)
        ? `${modelInfo.nCommands}-cmd corpus`
        : "shell_corpus corpus";
      markovSourceEl.textContent = `Markov chain (${n})`;
    }

    // Rationale
    if (rationaleEl) {
      const notes = [
        "Chronological timeline: one row per detected Return-shaped gap (small c2s packet heuristic, ≤100 B).",
        "Click any row to expand alternative candidates for that command.",
        "Confidence factors: QWERTY timing match, length similarity, first-token validity, obfuscation level.",
      ];
      rationaleEl.textContent = notes.join("\n");
    }

    // ── Render Chronological Timeline ──────────────────────────────
    //
    // If we have chunks (multiple commands detected), render them in
    // chronological order with click-to-expand alternatives.

    if (timelineEl) {
      timelineEl.innerHTML = "";

      // Check if we have multiple chunks (timeline mode)
      const haveMultipleChunks = chunks && chunks.length > 0;

      if (haveMultipleChunks) {
        // Show timeline view
        timelineEl.hidden = false;
        if (timelineTitleEl) timelineTitleEl.hidden = false;

        // Hide legacy candidates list
        if (candidatesListEl) candidatesListEl.hidden = true;
        if (candidatesListTitleEl) candidatesListTitleEl.hidden = true;

        // Update primary confidence from first chunk's top candidate
        const firstChunk = chunks[0];
        const firstEnhanced = _enhanceChunkCandidates(
          firstChunk, 0, lineOptsBase, haveLineConf, sshMarkovModule
        );
        const firstTop = firstEnhanced[0];

        if (confEl) {
          if (firstTop && Number.isFinite(firstTop.lineConfidence)) {
            confEl.textContent = `Confidence: ${(firstTop.lineConfidence * 100).toFixed(1)}%`;
          } else if (firstTop && Number.isFinite(firstTop.markovScore)) {
            confEl.textContent = `Markov score: ${firstTop.markovScore.toFixed(3)}`;
          } else {
            confEl.textContent = "Markov score: —";
          }
        }
        if (markovConfEl) {
          if (firstTop && Number.isFinite(firstTop.lineConfidence)) {
            markovConfEl.textContent = `Confidence: ${(firstTop.lineConfidence * 100).toFixed(1)}%`;
          } else if (firstTop && Number.isFinite(firstTop.markovScore)) {
            markovConfEl.textContent = `Markov score: ${firstTop.markovScore.toFixed(3)}`;
          } else {
            markovConfEl.textContent = "Confidence: —";
          }
        }

        // Render each chunk in chronological order
        for (let ci = 0; ci < chunks.length; ci += 1) {
          const chunk = chunks[ci];
          const enhanced = _enhanceChunkCandidates(
            chunk, ci, lineOptsBase, haveLineConf, sshMarkovModule
          );
          const topCand = enhanced[0];

          // Timeline item container
          const itemEl = document.createElement("div");
          itemEl.className = "crypt-openssh-markov-timeline-item";
          itemEl.setAttribute("data-chunk-index", String(ci));
          itemEl.setAttribute("data-expanded", "false");

          // Timeline connector (left side)
          const connectorEl = document.createElement("div");
          connectorEl.className = "crypt-openssh-markov-timeline-connector";

          // Command index badge
          const indexBadge = document.createElement("div");
          indexBadge.className = "crypt-openssh-markov-timeline-index";
          indexBadge.textContent = String(ci + 1);
          connectorEl.appendChild(indexBadge);

          // Timeline dot and line
          const dotEl = document.createElement("div");
          dotEl.className = "crypt-openssh-markov-timeline-dot";
          if (topCand && Number.isFinite(topCand.lineConfidence)) {
            dotEl.setAttribute("data-confidence", _confidenceColorClass(topCand.lineConfidence));
          }
          connectorEl.appendChild(dotEl);

          const lineEl = document.createElement("div");
          lineEl.className = "crypt-openssh-markov-timeline-line";
          // Don't draw line after last item
          if (ci < chunks.length - 1) {
            lineEl.style.height = "100%";
          }
          connectorEl.appendChild(lineEl);

          itemEl.appendChild(connectorEl);

          // Content area (header + alternatives)
          const contentEl = document.createElement("div");
          contentEl.className = "crypt-openssh-markov-timeline-content";

          // Header row (clickable to expand)
          const headerEl = document.createElement("div");
          headerEl.className = "crypt-openssh-markov-timeline-header";

          // Confidence/info on left
          const infoEl = document.createElement("div");
          infoEl.className = "crypt-openssh-markov-timeline-info";

          if (topCand) {
            if (Number.isFinite(topCand.lineConfidence)) {
              const confPct = (topCand.lineConfidence * 100).toFixed(0);
              const confLabel = document.createElement("span");
              confLabel.className = "crypt-openssh-markov-timeline-confidence";
              confLabel.setAttribute("data-confidence", _confidenceColorClass(topCand.lineConfidence));
              confLabel.textContent = `${confPct}%`;
              infoEl.appendChild(confLabel);
            }
            if (Number.isFinite(topCand.markovScore)) {
              const scoreLabel = document.createElement("span");
              scoreLabel.className = "crypt-openssh-markov-timeline-score";
              scoreLabel.textContent = `Markov: ${topCand.markovScore.toFixed(2)}`;
              infoEl.appendChild(scoreLabel);
            }
          }

          // Keystroke count
          if (Number.isFinite(chunk.keystrokeCount)) {
            const ksLabel = document.createElement("span");
            ksLabel.className = "crypt-openssh-markov-timeline-keystrokes";
            ksLabel.textContent = `${chunk.keystrokeCount} chars`;
            infoEl.appendChild(ksLabel);
          }

          headerEl.appendChild(infoEl);

          // Chevron (right side, rotates on expand)
          const chevronEl = document.createElement("div");
          chevronEl.className = "crypt-openssh-markov-timeline-chevron";
          if (enhanced.length > 1) {
            // Only show chevron if there are alternatives
            chevronEl.innerHTML = "▼";
          }
          headerEl.appendChild(chevronEl);

          // Top command text (spans width below header info)
          const cmdEl = document.createElement("div");
          cmdEl.className = "crypt-openssh-markov-timeline-command";
          cmdEl.textContent = (topCand && topCand.text) || "(no candidates)";
          headerEl.appendChild(cmdEl);

          contentEl.appendChild(headerEl);

          // Alternatives dropdown (hidden by default)
          if (enhanced.length > 1) {
            const altsEl = document.createElement("div");
            altsEl.className = "crypt-openssh-markov-timeline-alternatives";
            altsEl.setAttribute("hidden", "");

            // Alternatives header
            const altsHeader = document.createElement("div");
            altsHeader.className = "crypt-openssh-markov-timeline-alts-header";
            altsHeader.textContent = `Alternative candidates (${enhanced.length - 1} more):`;
            altsEl.appendChild(altsHeader);

            // Alternative rows (skip #1 since it's the top)
            for (let ai = 1; ai < enhanced.length; ai += 1) {
              const alt = enhanced[ai];
              const altRow = document.createElement("div");
              altRow.className = "crypt-openssh-markov-timeline-alt-row";

              const altInfo = document.createElement("div");
              altInfo.className = "crypt-openssh-markov-timeline-alt-info";

              if (Number.isFinite(alt.lineConfidence)) {
                const altConf = document.createElement("span");
                altConf.className = "crypt-openssh-markov-timeline-alt-confidence";
                altConf.setAttribute("data-confidence", _confidenceColorClass(alt.lineConfidence));
                altConf.textContent = `#${alt.rank} ${(alt.lineConfidence * 100).toFixed(0)}%`;
                altInfo.appendChild(altConf);
              } else {
                const altRank = document.createElement("span");
                altRank.className = "crypt-openssh-markov-timeline-alt-rank";
                altRank.textContent = `#${alt.rank}`;
                altInfo.appendChild(altRank);
              }

              if (Number.isFinite(alt.markovScore)) {
                const altScore = document.createElement("span");
                altScore.className = "crypt-openssh-markov-timeline-alt-score";
                altScore.textContent = `Markov: ${alt.markovScore.toFixed(2)}`;
                altInfo.appendChild(altScore);
              }

              altRow.appendChild(altInfo);

              const altCmd = document.createElement("div");
              altCmd.className = "crypt-openssh-markov-timeline-alt-command";
              altCmd.textContent = alt.text || "(empty)";
              altRow.appendChild(altCmd);

              altsEl.appendChild(altRow);
            }

            contentEl.appendChild(altsEl);

            // Click handler to toggle expansion
            headerEl.style.cursor = "pointer";
            headerEl.addEventListener("click", () => {
              const isExpanded = itemEl.getAttribute("data-expanded") === "true";
              const newState = isExpanded ? "false" : "true";
              itemEl.setAttribute("data-expanded", newState);
              if (isExpanded) {
                altsEl.setAttribute("hidden", "");
                chevronEl.innerHTML = "▼";
              } else {
                altsEl.removeAttribute("hidden");
                chevronEl.innerHTML = "▲";
              }
            });
          }

          itemEl.appendChild(contentEl);
          timelineEl.appendChild(itemEl);
        }

        console.log(
          "[Crypt/OpenSSH] rendered chronological timeline:",
          chunks.length, "chunk(s), line confidence available:",
          haveLineConf
        );
      } else {
        // No chunks: fall back to legacy candidates list from reranked
        timelineEl.hidden = true;
        if (timelineTitleEl) timelineTitleEl.hidden = true;

        // Build legacy enhanced candidates list from reranked
        let enhancedCandidates = [];
        if (reranked && reranked.length > 0) {
          for (let i = 0; i < reranked.length; i += 1) {
            const [markovScore, text] = reranked[i];
            const entry = {
              source: "session",
              rank: i + 1,
              markovScore: markovScore,
              text: text || "",
              lineConfidence: null,
            };

            if (haveLineConf && text) {
              const lineOpts = {
                ...lineOptsBase,
                markovScore: markovScore,
              };
              entry.lineConfidence = sshMarkovModule.computeLineConfidence(text, lineOpts);
            }

            entry.sortKey = Number.isFinite(entry.lineConfidence)
              ? entry.lineConfidence
              : (Number.isFinite(markovScore) ? markovScore : -100);

            enhancedCandidates.push(entry);
          }
        }

        // Re-rank by line confidence if we have it
        if (enhancedCandidates.some((c) => Number.isFinite(c.lineConfidence))) {
          enhancedCandidates.sort((a, b) => b.sortKey - a.sortKey);
          enhancedCandidates.forEach((c, idx) => { c.rank = idx + 1; });
        }

        // Update confidence displays
        const topEnhanced = enhancedCandidates[0];
        if (confEl) {
          if (topEnhanced && Number.isFinite(topEnhanced.lineConfidence)) {
            confEl.textContent = `Confidence: ${(topEnhanced.lineConfidence * 100).toFixed(1)}%`;
          } else {
            const score = reranked && reranked[0] && reranked[0][0];
            confEl.textContent = Number.isFinite(score)
              ? `Markov score: ${score.toFixed(3)}`
              : "Markov score: —";
          }
        }
        if (markovConfEl) {
          if (topEnhanced && Number.isFinite(topEnhanced.lineConfidence)) {
            markovConfEl.textContent = `Confidence: ${(topEnhanced.lineConfidence * 100).toFixed(1)}%`;
          } else {
            const score = reranked && reranked[0] && reranked[0][0];
            markovConfEl.textContent = Number.isFinite(score)
              ? `Confidence: ${score.toFixed(3)}`
              : "Confidence: —";
          }
        }

        // Render legacy candidates list
        if (candidatesListEl) {
          candidatesListEl.innerHTML = "";
          if (enhancedCandidates.length > 0) {
            candidatesListEl.hidden = false;
            if (candidatesListTitleEl) candidatesListTitleEl.hidden = false;

            const toShow = enhancedCandidates.slice(0, 12);
            for (const cand of toShow) {
              const row = document.createElement("div");
              row.className = "crypt-openssh-markov-candidate";
              row.setAttribute("data-rank", String(cand.rank));

              const rankDiv = document.createElement("div");
              rankDiv.className = "crypt-openssh-markov-candidate-rank";

              const confSpan = document.createElement("div");
              confSpan.className = "crypt-openssh-markov-candidate-confidence";
              if (Number.isFinite(cand.lineConfidence)) {
                confSpan.textContent = `#${cand.rank}  ${(cand.lineConfidence * 100).toFixed(0)}%`;
                confSpan.setAttribute("data-confidence", _confidenceColorClass(cand.lineConfidence));
              } else {
                confSpan.textContent = `#${cand.rank}`;
              }

              const markovSpan = document.createElement("div");
              markovSpan.className = "crypt-openssh-markov-candidate-markov-score";
              if (Number.isFinite(cand.markovScore)) {
                markovSpan.textContent = `Markov: ${cand.markovScore.toFixed(2)}`;
              }

              rankDiv.appendChild(confSpan);
              if (markovSpan.textContent) rankDiv.appendChild(markovSpan);

              const cmdDiv = document.createElement("div");
              cmdDiv.className = "crypt-openssh-markov-candidate-command";
              cmdDiv.textContent = cand.text || "(empty)";

              row.appendChild(rankDiv);
              row.appendChild(cmdDiv);
              candidatesListEl.appendChild(row);
            }

            console.log(
              "[Crypt/OpenSSH] rendered",
              toShow.length,
              "legacy Markov candidates (line confidence:",
              haveLineConf,
              ")"
            );
          } else {
            candidatesListEl.hidden = true;
            if (candidatesListTitleEl) candidatesListTitleEl.hidden = true;
          }
        }
      }
    }
  }

  // ── LLM primary result pane ──────────────────────────────────────────
  //
  // Renders the Viterbi-decoder + LLM primary guess into the
  // ``crypt-openssh-primary`` / ``crypt-openssh-insight`` cards. When
  // ``window.llmapi.generate`` isn't configured, ``mode`` is "no-llm"
  // and we surface a diagnostic instead — the card is always visible
  // (it's the user's first stop for "did the prompt work?"). When
  // the chain result arrives a beat later, ``renderSshPrimaryFromMarkov``
  // overwrites the Viterbi text via a per-character typewriter effect.
  //
  function renderSshPrimary(primary, insight, opts) {
    const mode = (opts && opts.mode) || (primary || insight ? "ok" : "no-llm");
    const textEl = document.getElementById("crypt-openssh-primary-text");
    const confEl = document.getElementById("crypt-openssh-primary-confidence");
    const kindEl = document.getElementById("crypt-openssh-primary-kind");
    const sourceEl = document.getElementById("crypt-openssh-primary-source");
    const rationaleEl = document.getElementById("crypt-openssh-primary-rationale");
    const primaryEl = document.getElementById("crypt-openssh-primary");
    const insightEl = document.getElementById("crypt-openssh-insight");
    const insightTextEl = document.getElementById("crypt-openssh-insight-text");
    const insightSourceEl = document.getElementById("crypt-openssh-insight-source");

    // Primary card is always visible (non-hidden) once analysis has run —
    // its content communicates either the LLM's best-guess, or a "LLM
    // unavailable" diagnostic so the user understands the prompt ran but
    // no model is wired up.
    if (primaryEl) primaryEl.hidden = false;

    if (primary && primary.text) {
      if (textEl) textEl.textContent = primary.text;
      if (confEl) {
        confEl.textContent = Number.isFinite(primary.confidence)
          ? `Confidence: ${(primary.confidence * 100).toFixed(1)}%`
          : "Confidence: —";
      }
      if (kindEl) {
        kindEl.textContent = primary.kind ? `Type: ${primary.kind}` : "Type: —";
      }
      if (sourceEl) {
        sourceEl.textContent = primary.source || "decoder + LLM";
      }
      // When the LLM couldn't recover exact characters but did produce
      // a session-level interpretation, surface the sessionActivity in
      // the rationale so the user sees the analysis even when the
      // primary text is a label.
      let rationale = primary.rationale || "";
      if (!rationale && primary.sessionActivity) {
        rationale = primary.sessionActivity;
      }
      if (rationaleEl) rationaleEl.textContent = rationale;
    } else {
      // No primary result from the LLM. Show a diagnostic in the same
      // card so the user knows the prompt path was exercised.
      const label =
        mode === "error"
          ? "LLM call failed."
          : mode === "no-result"
            ? "LLM returned no usable result."
            : "LLM not configured. Showing decoder candidates only.";
      if (textEl) textEl.textContent = label;
      if (confEl) confEl.textContent = "Confidence: —";
      if (kindEl) kindEl.textContent = "Type: —";
      if (sourceEl) sourceEl.textContent = "decoder only";
      if (rationaleEl) {
        rationaleEl.textContent =
          "The decoder still provides the best per-character hypotheses in the table below.";
      }
    }

    // Insight card sits above the primary card. Always visible after
    // analysis completes — content varies by mode:
    //   - "ok"        → LLM-authored analyst paragraph
    //   - "no-llm"    → "LLM unavailable; primary result was produced by the decoder alone."
    //   - "no-result" → "LLM did not return an insight string."
    //   - "error"     → "LLM call failed before an insight could be produced."
    if (insightEl) insightEl.hidden = false;
    if (insight && insight.text) {
      if (insightTextEl) insightTextEl.textContent = insight.text;
      if (insightSourceEl) {
        insightSourceEl.textContent = insight.source || "decoder + LLM";
      }
    } else {
      const fallback =
        mode === "error"
          ? "The LLM call failed before an analyst note could be produced. Check the activity log for diagnostics."
          : mode === "no-result"
            ? "The LLM did not return an insight string for this session."
            : "The LLM is not configured or unavailable. To enable insight, install Ollama and select a model in Settings.";
      if (insightTextEl) insightTextEl.textContent = fallback;
      if (insightSourceEl) insightSourceEl.textContent = "decoder only";
    }
  }

  function renderSshCandidates(candidates, delays, decoder) {
    const tbodyEl = document.querySelector("#crypt-openssh-candidates tbody");
    if (!tbodyEl) return;
    tbodyEl.replaceChildren();
    if (!candidates.length) {
      const row = document.createElement("tr");
      row.className = "crypt-table-empty";
      const cell = document.createElement("td");
      cell.colSpan = 5;
      cell.textContent = "No candidates produced (insufficient or non-positive delays).";
      row.appendChild(cell);
      tbodyEl.appendChild(row);
      return;
    }
    const avgDelta =
      delays.reduce((s, v) => s + v, 0) / Math.max(1, delays.length);

    // Choose ranking/probability source: prefer LLM-combined score when
    // available (candidate.combinedScore in [0,1]), otherwise fall back to
    // the decoder's log-prob (convert to probability with exp).
    const scores = candidates.map((c) => {
      const decoderProb = Number.isFinite(c.logProb) ? Math.exp(c.logProb) : 0;
      const combined = Number.isFinite(c.combinedScore) ? c.combinedScore : decoderProb;
      return combined;
    });
    const bestScore = Math.max(...scores, 1e-12);

    // Show an LLM indicator in the chart legend if LLM scores are present.
    try {
      const legendEl = document.getElementById("crypt-openssh-chart-legend");
      if (legendEl) {
        const anyLlm = candidates.some((c) => Number.isFinite(c.llmScore) || Number.isFinite(c.combinedScore));
        if (anyLlm) {
          // Append a short badge; keep existing text and only add if not present.
          if (!/LLM re-?ranked/.test(legendEl.textContent || "")) {
            legendEl.textContent = (legendEl.textContent || "").trim() + " • LLM re-ranked";
          }
        }
      }
    } catch (_err) {
      // ignore DOM indicator failures
    }

    // Surface padding-packet detection (when present in the cache) so
    // the analyst can see the decoder was compensating for obfuscation.
    try {
      const cached = sshSelectedFlowKey
        ? sshLastAnalysisByFlowKey.get(sshSelectedFlowKey)
        : null;
      const pad = cached && cached.paddingDetection;
      if (pad && pad.detected) {
        const legendEl = document.getElementById("crypt-openssh-chart-legend");
        if (legendEl && !new RegExp(`${pad.periodMs}ms padding`).test(legendEl.textContent || "")) {
          const pct = Number.isFinite(pad.coverage) ? `${(pad.coverage * 100).toFixed(0)}%` : "—";
          legendEl.textContent = (legendEl.textContent || "").trim() +
            ` • ${pad.periodMs}ms padding detected (coverage ${pct}, peeled)`;
        }
      }
    } catch (_err) {
      // ignore DOM indicator failures
    }

    candidates.forEach((cand, idx) => {
      const row = document.createElement("tr");
      if (idx === 0) row.className = "crypt-table-top";
      const rankCell = document.createElement("td");
      rankCell.textContent = String(idx + 1);
      const textCell = document.createElement("td");
      textCell.textContent = cand.text || "(empty)";
      const logPCell = document.createElement("td");
      logPCell.textContent = Number.isFinite(cand.logProb) ? cand.logProb.toFixed(2) : "n/a";
      const avgCell = document.createElement("td");
      avgCell.textContent = avgDelta.toFixed(1);
      const scoreCell = document.createElement("td");
      const decoderProb = Number.isFinite(cand.logProb) ? Math.exp(cand.logProb) : 0;
      const displayScore = Number.isFinite(cand.combinedScore) ? cand.combinedScore : decoderProb;
      const relative = displayScore / bestScore;
      scoreCell.textContent = `${(relative * 100).toFixed(1)}%`;
      row.appendChild(rankCell);
      row.appendChild(textCell);
      row.appendChild(logPCell);
      row.appendChild(avgCell);
      row.appendChild(scoreCell);
      tbodyEl.appendChild(row);
    });
  }

  // ── LLM-driven primary result assembly ─────────────────────────────────
  //
  // Combines the decoder's Viterbi candidates with shell/file language
  // priors to produce a single best-guess command/filename/text plus a
  // short LLM-authored insight paragraph that interprets the guess in
  // context. The function also reranks the decoder candidates so the
  // evidence table below the primary card reflects the same LLM
  // confidence order.
  //
  // Returns:
  //   { primary, insight, rankedCandidates }
  // or
  //   { rankedCandidates }   (when the LLM is unavailable).
  async function assembleLlmPrimaryResult(delays, candidates, model, opts) {
    if (!Array.isArray(candidates) || candidates.length === 0) {
      return { rankedCandidates: [] };
    }
    const result = { rankedCandidates: candidates.slice() };
    if (typeof window === "undefined" || !window.llmapi || typeof window.llmapi.generate !== "function") {
      return result;
    }
    // Compute shell command priors from the seed corpus (e.g.
    // src/data/shell_corpus.txt). The corpus is a slice of the user's real
    // shell history; the priors give the LLM frequency-weighted
    // knowledge of which commands the user actually runs, so it can
    // boost decoder candidates whose shape matches prior usage.
    const o = opts || {};
    let shellPriors = null;
    const corpus =
      typeof o.shellCorpus === "string" ? o.shellCorpus :
        Array.isArray(o.shellCorpusLines) ? o.shellCorpusLines.join("\n") :
          null;
    if (
      corpus &&
      sshExportModule &&
      typeof sshExportModule.buildShellCommandPriors === "function"
    ) {
      try {
        shellPriors = sshExportModule.buildShellCommandPriors(corpus, o.shellPriorsOpts);
      } catch (err) {
        console.warn("[Crypt/OpenSSH] shell priors parse failed:", err);
        shellPriors = { ok: false };
      }
    }
    const evidence = buildLlmEvidence(delays, candidates, model, {
      ...o,
      shellPriors,
    });
    // Brief refused — sample too small for a meaningful guess. Skip the
    // LLM round-trip entirely and let the decoder's logProb order the
    // evidence table.
    if (evidence && evidence.kind === "openssh-timing-too-small") {
      result.llmSkippedReason = evidence.reason || "too_few_samples";
      result.llmSampleCount = evidence.sampleCount;
      result.llmMinSamples = evidence.minSamples;
      return result;
    }

    // ── Step 1: assemble the primary best-guess.
    let primary = null;
    try {
      primary = await requestLlmPrimary(evidence);
    } catch (err) {
      console.warn("[Crypt/OpenSSH] LLM primary assembly failed:", err);
    }
    if (primary) result.primary = primary;

    // ── Step 2: insight paragraph that interprets the primary guess in
    // context (commands, filenames, intent, security implications).
    if (primary && primary.text) {
      try {
        const insight = await requestLlmInsight(evidence, primary);
        if (insight) result.insight = insight;
      } catch (err) {
        console.warn("[Crypt/OpenSSH] LLM insight failed:", err);
      }
    }

    // ── Step 3: rerank the decoder candidates so the evidence table
    // matches the LLM's preferred order. Falls back to the decoder's own
    // scores if the LLM call fails.
    try {
      const ranked = await requestLlmRerank(evidence, candidates);
      if (Array.isArray(ranked) && ranked.length > 0) {
        result.rankedCandidates = ranked;
      }
    } catch (err) {
      console.warn("[Crypt/OpenSSH] LLM rerank failed:", err);
    }

    return result;
  }

  // Build the JSON evidence packet the LLM sees. Keeps the payload
  // compact enough for a single Ollama call while still carrying the
  // decoder's top candidates, digraph priors, command-length estimate,
  // and backspace hints.
  // Build the LLM-facing evidence packet from the cached analysis
  // state. Prefers the same plain-text brief produced for the "Export
  // keystrokes" file, but falls back to a compact JSON bag when:
  //   * the export module isn't available (e.g. mid-load)
  //   * the sample is too small for the brief (defaults: < 30 delays)
  //   * the caller explicitly passed `format: "json"`
  //
  // The brief gives the LLM aggregate timing stats, burst/pause lists,
  // a sampled delay head/tail, padding-detection summary, the top 12
  // decoder candidates, and (optionally) any previous round-tripped
  // primary guess — exactly what a human analyst would read.
  function buildLlmEvidence(delays, candidates, model, opts) {
    const o = opts || {};
    const alphabet =
      (model && model.alphabet) ||
      "abcdefghijklmnopqrstuvwxyz0123456789 .,-_/:;=?!@#$%^&*()[]{}<>'\"|\\~`+";
    const presetSetting =
      typeof document !== "undefined" && document.getElementById("settings-llm-preset")
        ? document.getElementById("settings-llm-preset").value
        : "english";

    // If the export module is loaded, build the brief and let it decide
    // whether the sample is large enough.
    if (
      o.format !== "json" &&
      sshExportModule &&
      typeof sshExportModule.buildSshTimingAnalysisBrief === "function"
    ) {
      const briefState = {
        flow: o.flow,
        model,
        direction: o.direction,
        delays,
        delaysWithIdx: o.delaysWithIdx,
        candidates,
        primary: o.previousPrimary,
        paddingDetection: o.paddingDetection,
        s2cSummary: o.s2cSummary,
        backspaceHints: o.backspaceHints,
        shellPriors: o.shellPriors,
      };
      const brief = sshExportModule.buildSshTimingAnalysisBrief(briefState, {
        minSamples: Number.isFinite(o.minSamples) ? o.minSamples : undefined,
        maxSamples: Number.isFinite(o.maxSamples) ? o.maxSamples : undefined,
      });
      if (brief && brief.ok) {
        return {
          kind: "openssh-timing-brief",
          source: "export-module",
          brief: brief.text,
          sampleCount: brief.sampleCount,
          truncated: !!brief.truncated,
          allowedAlphabet: alphabet,
          languagePreset: presetSetting || "english",
          estimatedCommandLength:
            Number.isFinite(o.estimatedCommandLength) ? o.estimatedCommandLength : undefined,
          backspaceHints: o.backspaceHints || undefined,
        };
      }
      // Brief refused (too few samples). Bubble up a clear signal so
      // the caller skips the LLM and returns a deterministic result.
      if (brief && brief.ok === false && brief.reason === "too_few_samples") {
        return {
          kind: "openssh-timing-too-small",
          source: "export-module",
          sampleCount: brief.sampleCount,
          minSamples: brief.minSamples,
          reason: brief.reason,
          allowedAlphabet: alphabet,
          languagePreset: presetSetting || "english",
        };
      }
    }

    // JSON fallback (used when the export module isn't loaded yet, or
    // the caller explicitly requested JSON).
    const delaysWithIdx = Array.isArray(o.delaysWithIdx)
      ? o.delaysWithIdx.slice(0, 200)
      : null;
    return {
      kind: "openssh-keystroke-timing",
      source: "json-fallback",
      languagePreset: presetSetting || "english",
      allowedAlphabet: alphabet,
      delays: delays.slice(0, 200),
      delaysWithIdx: delaysWithIdx || undefined,
      estimatedCommandLength:
        Number.isFinite(o.estimatedCommandLength) ? o.estimatedCommandLength : undefined,
      backspaceHints: o.backspaceHints || undefined,
      candidates: candidates.map((c) => ({ text: c.text || "", logProb: c.logProb })),
    };
  }

  // Ask the LLM to take a best-guess at what was typed *and* what was
  // happening in the session. Encourages interpretation rather than a
  // mechanical transcription, with explicit confidence.
  async function requestLlmPrimary(evidence) {
    // Brief refused to produce a summary — tell the caller no.
    if (evidence && evidence.kind === "openssh-timing-too-small") {
      return null;
    }
    const prompt = `You are a behavioural analyst interpreting a recovered SSH session. The user has provided an analysis brief (the same plain-text data that can be exported with the "Export keystrokes" button) covering BOTH sides of the conversation:

- the client\u2192server timing of the keystrokes the user typed
- the server\u2192client timing and byte sizes of the server's response packets

Your job is to take a best-guess at:
1. what the user typed (the candidate commands)
2. which typed commands produced which server-output chunks
3. what was logically happening in this session overall

Analysis brief (same content as the export file):
\`\`\`
${evidence && evidence.brief ? evidence.brief : ""}
\`\`\`

Hints:
- allowedAlphabet: ${evidence && evidence.allowedAlphabet ? evidence.allowedAlphabet : ""}
- languagePreset: ${evidence && evidence.languagePreset ? evidence.languagePreset : "english"}
- estimatedCommandLength: ${evidence && Number.isFinite(evidence.estimatedCommandLength) ? evidence.estimatedCommandLength : "unknown"}
- backspaceHints: ${evidence && evidence.backspaceHints ? JSON.stringify(evidence.backspaceHints) : "none"}

Interpretation tips:
- YOUR JOB: infer the SSH session keys from the SHAPE/HEURISTIC SIGNATURE ALONE, not from the literal candidate "text" fields. The candidate strings are LITERALLY timing-decoder guesses — each one is the most-plausible-string-for-this-delay-sequence, NOT a transcription of what was typed. Treat them as a noisy prior, never as ground truth. Your reconstruction comes from cross-correlating: (a) the timing shape (bursts/pauses/std-dev/coefficient-of-variation), (b) the server response shape (s2c bytes / kind / char-distribution), (c) the session-turn-pair constraints, (d) the shell command priors, and (e) the obfuscation residue. Any candidate whose text is plausible-sounding but inconsistent with the timing shape + s2c shape + priors should be scored DOWN. A candidate whose text is awkward-sounding but a perfect fit for ALL the shape signals should be scored UP.
- Long pauses (>500 ms) in the c2s stream usually delimit commands or mark "thinking" gaps between steps.
- Bursts (<30 ms) cluster within a single word or token; use them to guess word boundaries.
- Multiple long pauses in close succession may mean a command was being composed in pieces or that the user copy-pasted across multiple lines.
- Heavy backspacing implies typos and may shift confidence toward a shorter, common command.
- The decoder's top candidates are an excellent language-model prior — but they're decoded from timing only, so they often get short tokens wrong. They are a TIMING guess, not a transcript.
- CRITICAL: The s2c data in the brief is RETURNED OUTPUT FROM PROGRAMS THE USER RAN, NOT KEYS. Every byte in the s2c chunks is part of the server's response (a shell prompt echo, the contents of a file the user cat'd, the output of systemctl status, etc.). NEVER treat s2c bytes as candidate keystrokes. NEVER include s2c content in your candidate "text" field. The s2c side is a CLASSIFIER INPUT — it tells you what kind of command produced the output, not the command itself.
- The s2c output is FAR more informative than the c2s keystrokes when an obfuscator is running. A flat ~50 char/s over ~1 s is characteristic of \`cat\` of a small config file; a fast burst followed by silence is typical of \`systemctl status\` / \`ps aux | head\` / \`ip a\`. Pair each typed command to its output by timing + size.
- Per-chunk character distribution: when the brief's s2c section reports per-chunk char categories (letters / digits / paths / punct / ctrl / hi-bit percentages), use them as a strong prior on the command CLASS that produced the chunk. A chunk that is dominated by 'paths /' (slash + dot + dash + underscore) almost certainly came from \`cat\`/\`ls\`/\`grep\` of a path; one dominated by 'letters lo' with few digits is prose (a help-text dump); one dominated by 'digits punct' is JSON / numeric data.
- Session turn pairs: when the brief's "Session turn pairs" section is present, it pairs each c2s keystroke run with the s2c chunk that followed it. Use these pairs as your primary reconstruction key:
    * \`typed-length\` (number of c2s keystroke gaps in the turn) ≈ number of typed characters ± 2
    * \`typed-duration\` (sum of inter-key delays in the turn) tells you roughly how long the user spent composing the command — long turns (>5 s) usually mean a multi-word / multi-argument command like \`systemctl restart something\`; short turns (<500 ms) usually mean a familiar command like \`ls\` or \`pwd\`.
    * \`s2c bytes\` × \`s2c duration\` × \`s2c kind\` together constrain the command CLASS — e.g. a "paged-file-content" chunk of ~5 kB in 100 s is almost certainly \`cat\` of a multi-kB file.
    * When chunk-based and turn-based pairings AGREE, the reconstruction is solid. When they DISAGREE (e.g. one chunk attributes to turn N, the other attributes to turn N+1), the c2s timing is ambiguous — defer to whichever pair has stronger s2c evidence.
- Shell command priors: when the brief contains a "Shell command priors" section, BOOST candidates whose verb + argument shape match a prior the user actually runs. For example, if "git push" appears 12 times in the priors and a candidate is "git push origin main", it should outrank a candidate that the LLM likes but the user has never typed. Conversely, DOWNWEIGHT candidates whose command shape has zero prior support AND no s2c backing — they are unlikely.
- Treat the priors as a frequency-weighted prior, not a hard filter: an unsuported candidate with strong timing or s2c evidence still survives, but it should rank below a prior-supported candidate of similar evidence strength.
- Redactions in the priors: any run of 4+ consecutive 'A' characters (e.g. "AAAA", "AAAAAAAAAAAAA") in a priors example is a REDACTION PLACEHOLDER — the real username/hostname/IP/path/JSON-key was scrubbed from the corpus for privacy. When you see such a placeholder, treat it as an arbitrary string of length (placeholder-length ± 4 chars) — the ±4 tolerance absorbs minor mismatches between the scrubbed length and the original token length. Substitute any plausible value when reconstructing the command. The position and length of the placeholder still tells you WHERE the user typically embeds usernames, hostnames, paths, and keys; the specific letters are not informative.
- When the c2s timing is heavily obfuscated (e.g. a 20 ms padding cadence), you CANNOT recover filenames or exact characters from typing alone — but you CAN often recover command *class* (cat/ls/ps/systemctl) and approximate output size from the s2c side. In that case lean on the session-turn-pair section: the typed-duration and s2c-kind together pin down the command class even when the decoder's candidates are unreliable.
- Server-side SSH timing obfuscation: if the brief's "Padding detection" section reports a 20 ms / 40 ms cadence (or similar), the c2s delays you see have ALREADY been peeled by the local detector. Treat any residual sub-cadence jitter as noise from imperfect peeling — do NOT interpret it as an extra sub-keystroke clock or as bursts within a word. The remaining spread in inter-key delays reflects natural typing cadence, not the obfuscation period.
- How the padding detector works (two-pass, no hard-coded cadence) — this is important context for interpreting the raw-vs-peeled comparison:
    * PASS 1 — first-difference histogram scan: for every adjacent pair of delays in the raw stream, compute |delays[i+1] - delays[i]|, build a histogram of those differences in the [5 ms, 80 ms] range, and pick the bin with the highest count relative to the median bin (peak-to-noise > 1.6). That bin IS the candidate cadence P. If no bin clears the threshold, the stream has no detectable fixed cadence — don't invent one.
    * PASS 2 — sub-millisecond refine + classify: sweep periods in [P-3 ms, P+3 ms] at 0.5 ms resolution; for each candidate p, compute each IID's residue r = IID - round(IID/p)*p; classify the IID as 'padding' if |r| <= max(2 ms, 0.15·p); pick the period with highest coverage AND lowest residual std; confirm only if coverage >= 50% AND residual std < 0.55 * (p / sqrt(12)).
    * The detector emits THREE views — snappedDelaysMs (every IID replaced by its residue, interval count preserved), keystrokeDelaysMs (residues of NON-padding intervals only, one entry per real keystroke, filler dropped), and paddedIntervals (indices classified as filler). The brief's aggregate statistics and decoder candidates use keystrokeDelaysMs; the raw-vs-peeled comparison surfaces both for cross-validation.
    * When interpreting the "Raw vs peeled IID" table: the cadence fingerprint strength (% of raw IIDs within ±P·0.15 of an integer multiple of P) is the most reliable evidence the obfuscator was active. If that strength is high AND the median ratio (raw/peeled) is > 2×, the peeled view is trustworthy; if the strength is moderate (40-60%) the obfuscator may have been intermittent, and you should weight the peeled view less.
- Decoder alphabet: when \`allowedAlphabet\` is non-empty, only characters in that set can appear in candidate text fields. Do NOT propose characters outside the alphabet — the local decoder could not have produced them. However, the alphabet is LOOSE for case (the timing channel usually cannot distinguish uppercase from lowercase unless the model.layout specifies capslock), so equivalent-case substitutions are usually safe.
- Wire-level packet profile (frame length / ciphertext / flags): the brief also surfaces a per-direction packet-profile section that gives you additional priors BEYOND timing. Use it to:
    * Distinguish chunked file transfers (median s2c frame > 1000 B, low variance) from interactive one-liners (median s2c frame < 200 B, high variance). The former implies cat/less of a multi-kB file or scp/rsync push — a "show me this file" command; the latter implies systemctl status / ps aux / ip a style outputs.
    * Treat ACK-only frames between s2c and c2s as quiet thinking time. If a > 500 ms c2s pause coincides with a run of ACK-only frames, that pause is almost certainly a "user read the output before typing the next command" boundary.
    * Treat retransmit / out-of-order segments as network jitter — any timing outlier near these should be de-weighted when ranking candidates.
    * Use the direction-change count (c2s↔s2c hand-offs) as a sanity check on the decoder's per-turn count. If the decoder sees 12 turns but the wire shows 50 hand-offs, the turn splitter is splitting too aggressively; if 50 turns but 12 hand-offs, it's not splitting enough.
    * Use the max ciphertext segment size as a "real bytes seen by the server" upper bound on what could have been typed. SSH framing adds ~16 bytes overhead per packet, so max_ciphertext_c2s ≈ typed-command-bytes + 16 × (number-of-typed-packets); a command whose typed-length estimate exceeds this bound is impossible.
    * The PSH flag mix tells you whether the c2s stream is data-carrying (mostly PSH) or control-heavy (mostly ACK); if PSH counts are low, the c2s traffic is suspiciously quiet and the decoder is probably under-counting typed characters.
- Return-key detection (turn terminators) — CRITICAL for command-length validation. Each pause boundary (>500 ms gap) is classified as either a Return keypress or a thinking pause. Detection combines four signals: (a) positional anchoring at the pause (the Return is always the last keystroke), (b) packet size (the c2s packet carrying a Return is small — ≤ 1 keystroke worth of ciphertext, on-wire size below 70% of the median c2s packet size), (c) pre-key gap (the gap BEFORE the Return is in the upper half of gaps within the same command — the user pauses briefly to "compose" before committing), and (d) post-key gap ratio (the gap AFTER the Return is ≥ 3× the command's median gap — the shell is now executing and the user is reading output).
    * The detected Return positions are CANONICAL turn terminators. typed-length per command = next-Return-pos minus previous-Return-pos minus 1 (excluding the Return itself).
    * When ranking candidates: STRONGLY prefer candidates whose text length matches the typed-length from Return detection. The wire-level keystroke count is HARD EVIDENCE — a candidate whose text is 12 chars long but the typed-length is 6 chars is physically impossible; a candidate whose text is 6 chars but typed-length is 12 chars is missing ~6 chars of argument content.
    * When Return detection finds N turns but the turn-pair section shows N+M s2c chunks, M chunks came from previous commands (the user typed Return but the s2c response was still arriving) or from output that lagged by a turn — both are normal.
    * When Return detection finds FEWER turns than the wire-level direction-change count suggests, the user probably typed multi-line input (a heredoc or a continuation line) before pressing Return — the typed-length estimate still applies, just to the multi-line block as a whole.

Instructions:
- Return a SINGLE valid JSON object, no other commentary. Schema:
  {
    "text": string,                                 // your best-guess at the most recent / central typed command (use allowedAlphabet)
    "confidence": number in [0,1],                  // how likely this exact string was typed
    "kind": "command" | "filename" | "path" | "argument" | "phrase" | "unknown",
    "isCommand": boolean,
    "rationale": string,                            // 1-2 sentence explanation grounded in the timing AND the s2c output
    "sessionActivity": string,                      // 1-2 sentence narrative: what the user was likely doing across the WHOLE session, e.g. "inspected two config files then ran a status check"
    "sessionCommands": [                             // ordered list pairing typed commands to their output chunks
      {
        "command": string,                          // best-guess at the typed command (use allowedAlphabet; "" if uncertain)
        "commandConfidence": number in [0,1],       // confidence in this command
        "producedChunk": number | null,             // 1-based index into the output chunks; null if no matching chunk
        "producedKind": string,                     // e.g. "cat of small config", "systemctl status", "ps aux | head"
        "rationale": string                         // 1 sentence explaining why this chunk matches
      }
    ],
    "alternateInterpretations": [                   // optional; 0-2 alternatives for the primary 'text'
      { "text": string, "confidence": number in [0,1], "reason": string }
    ]
  }
- If the brief is too thin to guess, return {"text": "", "confidence": 0, "kind": "unknown", "isCommand": false, "rationale": "insufficient evidence", "sessionActivity": "unknown", "sessionCommands": [], "alternateInterpretations": []}.
- Be honest about uncertainty. Confidence <= 0.5 is fine if the timing evidence is ambiguous. If the c2s timing is obfuscated but the s2c output is clean, you may still produce high-confidence command-class guesses for each chunk.
- Output ONLY the JSON object.`;

    const raw = await window.llmapi.generate(prompt, {
      // Bump the response budget so the JSON schema (text + rationale +
      // sessionActivity + sessionCommands + alternates) fits. The default
      // 1024 tokens is too low for the s2c-aware brief — and the
      // minimax-m3:cloud model is a thinking model that burns many
      // tokens on internal reasoning before producing the JSON, so
      // 4096 gives it headroom for both thinking AND response.
      maxTokens: 4096,
      temperature: 0.4,
      // Disable thinking mode for structured-output prompts — Ollama
      // cloud models emit `thinking` instead of `response` when
      // thinking is enabled, leaving us nothing to parse.
      think: false,
    });
    const text = extractLlmText(raw);
    if (!text) {
      console.warn("[Crypt/OpenSSH] LLM primary returned empty text. raw keys=",
        raw && typeof raw === "object" ? Object.keys(raw).join(",") : "(non-object)");
      return null;
    }
    const obj = parseLlmJsonObject(text);
    if (!obj || typeof obj !== "object") {
      // Special-case: when the model emitted only thinking (no JSON
      // response), surface that explicitly in the diagnostic so the
      // user knows to bump maxTokens / try a non-thinking model.
      const thinkingOnly = text.startsWith("[thinking-only");
      console.warn(
        "[Crypt/OpenSSH] LLM primary JSON parse failed. textLen=",
        text.length,
        "thinkingOnly=",
        thinkingOnly,
        "first300=",
        text.slice(0, 300),
      );
      // When the model emitted thinking-only output, attempt to extract
      // session commands from the raw text as a fallback. The LLM may
      // have produced useful command interpretations during its thinking
      // process even though it didn't emit a structured JSON response.
      let sessionCommands = [];
      if (thinkingOnly) {
        // Try to find sessionCommands-like entries in the raw thinking text.
        // The thinking output may contain command references; extract any
        // quoted command strings that look like shell commands.
        const cmdMatches = text.match(/["']([^"']{3,64})["']/g);
        if (Array.isArray(cmdMatches) && cmdMatches.length > 0) {
          sessionCommands = cmdMatches.map((m) => m.replace(/["']/g, "")).slice(0, 32);
        }
      }
      // If we extracted any session commands, synthesize a primary result
      // from the highest-confidence one so the UI still shows something
      // useful rather than "LLM returned no usable result".
      if (sessionCommands.length > 0) {
        const bestCmd = sessionCommands
          .slice()
          .sort((a, b) => (b.length - a.length))[0]; // simple heuristic: longer = more specific
        const cleaned = sanitizeTextForAlphabetShared(bestCmd).trim();
        const confidence = 0.3; // low confidence for thinking-only fallback
        const kind = "command";
        const rationale = "Recovered from LLM thinking output (no structured JSON)";
        const sessionActivity = "LLM thinking session";
        // Build a primary result object that the UI can render
        const primaryResult = {
          text: cleaned || "",
          confidence: confidence,
          kind: kind,
          rationale: rationale,
          sessionActivity: sessionActivity,
          sessionCommands: sessionCommands.map((c) => ({ command: c, commandConfidence: confidence })),
        };
        return { primary: primaryResult, rankedCandidates: [] };
      }
      return null;
    }
    let cleaned = sanitizeTextForAlphabetShared(String(obj.text || "")).trim();
    const confidence = clamp01(obj.confidence);
    const kind = String(obj.kind || "command").toLowerCase();
    const rationale = String(obj.rationale || "").trim();
    const sessionActivity = String(obj.sessionActivity || "").trim();
    let sessionCommands = [];
    if (Array.isArray(obj.sessionCommands)) {
      sessionCommands = obj.sessionCommands
        .slice(0, 32)
        .map((entry) => {
          const cmdText = sanitizeTextForAlphabetShared(String((entry && entry.command) || "")).trim();
          const cmdConf = clamp01(entry && entry.commandConfidence);
          return {
            command: cmdText,
            commandConfidence: Number.isFinite(cmdConf) ? cmdConf : 0,
            producedChunk: Number.isFinite(entry && entry.producedChunk) ? entry.producedChunk : null,
            producedKind: String((entry && entry.producedKind) || "").trim(),
            rationale: String((entry && entry.rationale) || "").trim(),
          };
        })
        .filter((entry) => entry.command || entry.producedKind);
    }
    let alternates = [];
    if (Array.isArray(obj.alternateInterpretations)) {
      alternates = obj.alternateInterpretations
        .slice(0, 2)
        .map((alt) => ({
          text: sanitizeTextForAlphabetShared(String((alt && alt.text) || "")).trim(),
          confidence: clamp01(alt && alt.confidence),
          reason: String((alt && alt.reason) || "").trim(),
        }))
        .filter((alt) => alt.text && Number.isFinite(alt.confidence));
    }

    // When the LLM doesn't supply a top-level `text` (because the timing
    // is heavily obfuscated and exact characters can't be recovered),
    // but it DID provide session-level context (sessionCommands /
    // sessionActivity), synthesize a "best guess" from the highest-
    // confidence sessionCommands entry so the primary card still shows
    // something useful. Confidence is capped at 0.5 to reflect the
    // uncertainty. Without this fallback, the primary card would
    // silently fall back to the "no usable result" diagnostic even
    // though the LLM produced a meaningful session interpretation.
    let synthesizedFromSession = false;
    if (!cleaned && sessionCommands.length > 0) {
      const bestCmd = sessionCommands
        .slice()
        .sort((a, b) => (b.commandConfidence || 0) - (a.commandConfidence || 0))[0];
      if (bestCmd && bestCmd.command) {
        cleaned = bestCmd.command;
        synthesizedFromSession = true;
      } else if (bestCmd && bestCmd.producedKind) {
        cleaned = `[${bestCmd.producedKind}]`;
        synthesizedFromSession = true;
      }
    }
    if (!cleaned && sessionActivity) {
      cleaned = `[session-only] ${sessionActivity}`;
      synthesizedFromSession = true;
    }
    if (!cleaned) {
      // Diagnostic: surface what the LLM actually returned so we can
      // diagnose "no usable result" without spelunking in DevTools.
      try {
        const keys = obj && typeof obj === "object" ? Object.keys(obj).slice(0, 12) : [];
        const textLen = (obj && obj.text && String(obj.text).length) || 0;
        const snippet = JSON.stringify(obj).slice(0, 300);
        console.warn(
          "[Crypt/OpenSSH] LLM primary produced no usable text. Keys=",
          keys,
          "textLen=",
          textLen,
          "sessionActivityLen=",
          sessionActivity.length,
          "sessionCommandsCount=",
          sessionCommands.length,
          "snippet=",
          snippet,
        );
      } catch (_e) { /* ignore */ }
      return null;
    }

    const isCommand = obj.isCommand === true || looksLikeShellCommandShared(cleaned);
    return {
      text: cleaned,
      confidence: synthesizedFromSession
        ? Math.min(0.5, Number.isFinite(confidence) ? confidence : 0)
        : Number.isFinite(confidence) ? confidence : 0,
      kind,
      rationale,
      sessionActivity,
      synthesizedFromSession,
      sessionCommands,
      alternateInterpretations: alternates,
      isCommand,
      source: "decoder + LLM (timing-analysis brief)",
    };
  }

  // Ask the LLM to author a 4-bullet analyst note that interprets the
  // primary guess in context — what was typed, what was happening, what
  // each server-output chunk was, and any security-relevant observations.
  async function requestLlmInsight(evidence, primary) {
    const prompt = `You are a security-aware behavioural analyst. A decoder + LLM just produced a session-level interpretation from a recovered SSH keystroke-timing trace that includes BOTH the client\u2192server typing cadence and the server\u2192client output packets. Your job is to write a concise, security-aware analyst note that interprets the session as a whole, using the same analysis brief the primary was based on.

Primary guess JSON:
${JSON.stringify({
      text: primary.text,
      kind: primary.kind,
      isCommand: primary.isCommand,
      confidence: primary.confidence,
      rationale: primary.rationale,
      sessionActivity: primary.sessionActivity,
      sessionCommands: primary.sessionCommands,
      alternateInterpretations: primary.alternateInterpretations,
    })}

Analysis brief (same content as the export file):
\`\`\`
${evidence && evidence.brief ? evidence.brief : ""}
\`\`\`

Instructions:
- Write exactly 4 short bullets (one sentence each is fine):
    1. "What was likely typed" — restate or refine the primary guess and what it does.
    2. "Session shape" — how the typed commands map to the server-output chunks; which typed command likely produced which chunk (by size + rate); what the user was probably doing across the whole session.
    3. "What each output chunk was" — for each numbered chunk in the brief, name the most likely command class that produced it (e.g. \`cat\` of a config file, \`systemctl status\`, \`ps aux | grep\`, shell prompt echo). If a chunk is unidentified, say so explicitly.
    4. "Security observations" — anything security-relevant (file paths, credentials, hostnames, dangerous commands, suspicious network endpoints, data exfil patterns, obfuscated-timing artefacts). If nothing stands out, say so explicitly.
- If the c2s stream is heavily obfuscated (e.g. a 20 ms padding cadence) acknowledge that filenames/flags aren't recoverable from typing alone, but the s2c output rate is still highly informative.
- If the evidence is too weak, say so in bullet 1 and avoid speculation.
- Return ONLY a JSON object: {"text": "<the four bullets joined by '\\n\\n' (blank line between bullets)>"}.

- Output ONLY the JSON object.`;

    const raw = await window.llmapi.generate(prompt, {
      maxTokens: 4096,
      temperature: 0.5,
      think: false,
    });
    const text = extractLlmText(raw);
    if (!text) {
      console.warn("[Crypt/OpenSSH] LLM insight returned empty text.");
      return null;
    }
    const obj = parseLlmJsonObject(text);
    if (!obj || typeof obj !== "object") {
      console.warn(
        "[Crypt/OpenSSH] LLM insight JSON parse failed. textLen=",
        text.length,
        "first200=",
        text.slice(0, 200),
      );
      return null;
    }
    let insightText = String(obj.text || "").trim();
    // Fallback: if the LLM didn't return a `text` field but the primary
    // had session-level context, surface that as a synthetic insight so
    // the analyst card isn't blank.
    if (!insightText && primary) {
      const sessionActivity = String(primary.sessionActivity || "").trim();
      const sessionCommands = Array.isArray(primary.sessionCommands) ? primary.sessionCommands : [];
      if (sessionActivity || sessionCommands.length > 0) {
        const lines = [];
        if (sessionActivity) {
          lines.push(`- Session activity: ${sessionActivity}`);
        }
        if (sessionCommands.length > 0) {
          lines.push("- Best-guess command(s):");
          for (const cmd of sessionCommands.slice(0, 4)) {
            const text = cmd.command || `[${cmd.producedKind || "unknown"}]`;
            const conf = Number.isFinite(cmd.commandConfidence)
              ? ` (conf ${(cmd.commandConfidence * 100).toFixed(0)}%)`
              : "";
            const kind = cmd.producedKind ? ` — ${cmd.producedKind}` : "";
            lines.push(`    - ${text}${conf}${kind}`);
          }
        }
        if (lines.length > 0) {
          insightText = lines.join("\n") + "\n- Security observations: see primary result rationale.";
        }
      }
    }
    if (!insightText) return null;
    return { text: insightText, source: "decoder + LLM", synthesized: !obj.text };
  }

  // Ask the LLM to rerank the decoder candidates. Returns the same
  // candidate objects, decorated with llmScore/combinedScore, sorted
  // descending by combinedScore. Falls back to the decoder's own
  // logProb on any failure.
  async function requestLlmRerank(evidence, candidates) {
    if (!Array.isArray(candidates) || candidates.length === 0) return candidates;
    // No brief produced (too few samples) — the decoder's own logProb
    // is the only signal we have. Skip the LLM round-trip.
    if (evidence && evidence.kind === "openssh-timing-too-small") return candidates;

    const prompt = `You are re-ranking SSH keystroke-timing candidates using shell/file language priors. Each candidate is a string the decoder thinks the user may have typed, with a timing log-probability. Re-score them and return a JSON array of objects. Use the analysis brief for context on session activity and cadence.

Analysis brief (same content as the export file):
\`\`\`
${evidence && evidence.brief ? evidence.brief : ""}
\`\`\`

Candidates (in input order):
${JSON.stringify({
      candidates: evidence.candidates || [],
      languagePreset: evidence.languagePreset,
      estimatedCommandLength: evidence.estimatedCommandLength,
    })}

Instructions:
- Output a JSON array of objects in the same order as the input candidates: [{"text": string, "score": number in [0,1], "isCommand": boolean}].
- "score" is a combined probability in [0,1] that the text was typed in this session.
- "isCommand" is true if the candidate is a shell command.
- YOUR JOB: score each candidate based on whether it fits the SHAPE/HEURISTIC SIGNATURE, NOT on whether the text string looks plausible in isolation. The candidate "text" fields are timing-decoder guesses (the most-likely-string-for-this-delay-sequence) — they are NOT a transcript of what was typed. A candidate that looks ugly but matches every shape signal should score high; a candidate that reads beautifully but contradicts the timing/s2c/priors shape should score low.
- CRITICAL: the s2c data in the brief is RETURNED OUTPUT FROM PROGRAMS, NOT candidate keystrokes. Never include s2c content in any candidate "text" field. Use s2c shape (bytes / kind / char-distribution) and the session-turn-pair section only as a CLASSIFIER — they constrain which command CLASS produced each output, not the literal characters typed.
- Session turn pairs: if the brief's "Session turn pairs" section is non-empty, use typed-length, typed-duration, and the paired s2c kind/char-distribution to score candidates. A candidate whose length matches the typed-length of a turn (within ±2 chars) and whose command class matches the paired s2c chunk kind scores higher than one that fits only the c2s timing.
- Shell command priors: if the brief's "Shell command priors" section is non-empty, use it as a frequency-weighted prior — boost candidates whose verb + argument shape matches a prior the user actually runs, and downweight candidates whose shape has zero prior support unless their timing is unusually strong. The priors reflect REAL usage, not generic shell knowledge; they should win ties.
- Redactions in the priors: any run of 4+ consecutive 'A' characters in a priors example is a REDACTION PLACEHOLDER — the real username/hostname/IP/path/key was scrubbed from the corpus. Treat it as an arbitrary string of length (placeholder-length ± 4 chars) when scoring candidates. Position and length still indicate WHERE such tokens typically appear.
- Return ONLY the JSON array, no other commentary.`;

    let raw;
    try {
      raw = await window.llmapi.generate(prompt, {
        maxTokens: 4096,
        temperature: 0.3,
        think: false,
      });
    } catch (err) {
      console.warn("LLM rerank generate error:", err);
      return candidates;
    }
    const text = extractLlmText(raw);
    if (!text) return candidates;
    const arr = parseLlmJsonArray(text);
    if (!arr) return candidates;
    return mergeLlmScoresIntoCandidates(arr, candidates);
  }

  // ── LLM response helpers ──────────────────────────────────────────────
  // Walk a string to find the first balanced JSON object/array — used
  // to recover a clean JSON payload when the LLM response includes
  // surrounding prose or trailing truncation. Tracks nested braces /
  // brackets and respects escaped quotes inside string literals.
  function extractFirstBalancedJson(text) {
    if (!text || typeof text !== "string") return null;
    const start = text.search(/[\[{]/);
    if (start < 0) return null;
    const open = text[start];
    const close = open === "{" ? "}" : "]";
    let depth = 0;
    let inString = false;
    let escape = false;
    for (let i = start; i < text.length; i += 1) {
      const ch = text[i];
      if (escape) { escape = false; continue; }
      if (inString) {
        if (ch === "\\") { escape = true; continue; }
        if (ch === '"') inString = false;
        continue;
      }
      if (ch === '"') { inString = true; continue; }
      if (ch === open) depth += 1;
      else if (ch === close) {
        depth -= 1;
        if (depth === 0) return text.slice(start, i + 1);
      }
    }
    // Unbalanced (truncated response). Return whatever we have so the
    // JSON parser can attempt a partial repair, but only if the depth
    // is still positive — otherwise we never opened a structure.
    if (depth > 0) return text.slice(start);
    return null;
  }

  // When a thinking-mode model exhausts its response budget on internal
  // reasoning, the final answer is often drafted inside the ``thinking``
  // field but never emitted as ``response``. Walk the thinking text and
  // pull out the last balanced JSON object — that's almost always the
  // intended final answer.
  function extractJsonFromThinking(text) {
    if (!text || typeof text !== "string") return null;
    // Try the standard balanced-walker from end-to-start, so we prefer
    // the LAST JSON object (the model's most recent/final attempt).
    let i = text.length;
    while (i > 0) {
      // Find the start of a balanced object ending at position i.
      // Walk backwards from a closing brace to its matching opener.
      const closeIdx = text.lastIndexOf("}", i - 1);
      if (closeIdx < 0) return null;
      const candidate = extractFirstBalancedJson(text.slice(0, closeIdx + 1));
      if (candidate) {
        try {
          JSON.parse(candidate);
          return candidate;
        } catch (_e) {
          // Try the next-backwards closing brace.
          i = closeIdx;
          continue;
        }
      }
      i = closeIdx;
    }
    return null;
  }

  function extractLlmText(raw) {
    if (typeof raw === "string") return raw;
    if (!raw || typeof raw !== "object") return "";
    try {
      // Ollama cloud / ollama.js response shape: { response: "...", thinking: "..." }
      // When ``response`` is non-empty, that's the model's final answer.
      if (typeof raw.response === "string" && raw.response.length > 0) {
        return raw.response;
      }
      // Thinking-only response: the model burned the entire num_predict
      // budget on internal reasoning and emitted no final answer.
      // Try to extract the final JSON from the thinking text — many
      // models draft the answer in their reasoning and would have
      // emitted it as ``response`` if there were room.
      if (typeof raw.thinking === "string" && raw.thinking.length > 0) {
        const extracted = extractJsonFromThinking(raw.thinking);
        if (extracted) return extracted;
        return `[thinking-only, no response emitted] ${raw.thinking}`;
      }
      if (Array.isArray(raw.output) && raw.output.length > 0) {
        return raw.output.map((o) => o.content || "").join("\n");
      }
      if (Array.isArray(raw)) {
        return raw.map((r) => (r && r.content) || JSON.stringify(r)).join("\n");
      }
      if (raw[0] && raw[0].content) return raw[0].content;
      if (raw.content) return raw.content;
      return JSON.stringify(raw);
    } catch (_e) {
      return "";
    }
  }

  function stripLlmCodeFences(text) {
    if (!text || typeof text !== "string") return "";
    let cleaned = String(text);
    // Strip a leading markdown fence (``` or ```json) followed by
    // any whitespace (including \r\n). The previous pattern required
    // a literal \n after the fence; some LLM outputs use \r\n or no
    // newline at all between the fence and the JSON. We tolerate all
    // three.
    cleaned = cleaned.replace(/^\s*```(?:json|JSON)?\s*\r?\n?/, "");
    // Strip a trailing fence: newline + ``` + optional whitespace.
    // Some LLM outputs trim the closing \n, so we also accept ``` at
    // end-of-string.
    cleaned = cleaned.replace(/\r?\n```\s*$/, "");
    cleaned = cleaned.replace(/```\s*$/, "");
    return cleaned.trim();
  }

  // Strip raw control characters (LF, CR, TAB) that the LLM emitted
  // inside JSON string literals instead of the JSON-escaped
  // sequences. JSON.parse refuses raw newlines inside strings, so a
  // truncated rationale containing a literal newline kills the parse.
  // We walk character-by-character, tracking whether we're inside a
  // string literal (handling escapes), and replace raw control bytes
  // with a single space inside strings. Outside strings, we leave the
  // text alone — JSON whitespace outside string values is fine.
  //
  // LF specifically is treated as a string terminator: the LLM was
  // probably trying to end the string there but emitted a literal
  // newline. CRLF together is replaced with a single space (we keep
  // the string alive across the line break).
  function repairLlmJsonStrings(text) {
    if (!text || typeof text !== "string") return text;
    let out = "";
    let inString = false;
    let escape = false;
    for (let i = 0; i < text.length; i += 1) {
      const ch = text[i];
      if (escape) {
        out += ch;
        escape = false;
        continue;
      }
      if (inString) {
        if (ch === "\\") {
          out += ch;
          escape = true;
          continue;
        }
        if (ch === '"') {
          out += ch;
          inString = false;
          continue;
        }
        // CRLF: replace with a single space but keep the string open.
        if (ch === "\r" && text[i + 1] === "\n") {
          out += " ";
          i += 1;
          continue;
        }
        // LF alone: close the string and drop the newline. The LLM
        // likely intended the LF as a string terminator.
        if (ch === "\n") {
          if (inString) {
            out += '"';
            inString = false;
          }
          continue;
        }
        // Other control characters: replace with space.
        const code = ch.charCodeAt(0);
        if (ch === "\r" || ch === "\t" || code < 0x20) {
          out += " ";
          continue;
        }
        out += ch;
        continue;
      }
      // Outside a string: track state and copy.
      if (ch === '"') {
        inString = true;
        out += ch;
        continue;
      }
      out += ch;
    }
    // Close any string still open at EOF.
    if (inString) out += '"';
    return out;
  }

  // If the LLM response is truncated mid-object, close any open
  // braces so JSON.parse can finish. Tracks string state to avoid
  // miscounting braces inside string values.
  function closeOpenJsonBraces(text) {
    if (!text || typeof text !== "string") return text;
    let depth = 0;
    let inString = false;
    let escape = false;
    for (let i = 0; i < text.length; i += 1) {
      const ch = text[i];
      if (escape) { escape = false; continue; }
      if (inString) {
        if (ch === "\\") { escape = true; continue; }
        if (ch === '"') inString = false;
        continue;
      }
      if (ch === '"') inString = true;
      else if (ch === "{") depth += 1;
      else if (ch === "}") depth -= 1;
    }
    return depth > 0 ? text + "}".repeat(depth) : text;
  }

  function parseLlmJsonObject(text) {
    if (!text || typeof text !== "string") return null;
    // Strip markdown code fences the LLM often wraps JSON in.
    let cleaned = stripLlmCodeFences(text);
    try {
      return JSON.parse(cleaned);
    } catch (_e) { /* fall through */ }
    // Try direct parse on the original text too (covers simple cases).
    try {
      return JSON.parse(text);
    } catch (_e) { /* fall through to regex */ }
    // LLMs sometimes emit raw newlines / tabs inside JSON string
    // values instead of the JSON-escaped sequences (`\n`, `\t`).
    // That's invalid JSON per the spec. Strip those control characters
    // so the parser can finish the string and produce a usable
    // object. Without this, the user's reported 4405-char responses
    // with truncated rationales fail to parse with "Bad control
    // character in string literal".
    const cleaned2 = repairLlmJsonStrings(cleaned);
    // If the LLM response was truncated mid-object (e.g. token-limit
    // cut), close any unclosed braces so JSON.parse can finish.
    const cleaned3 = closeOpenJsonBraces(cleaned2);
    try {
      return JSON.parse(cleaned3);
    } catch (_e) { /* fall through */ }
    // Extract the first balanced JSON object from the text. Walk
    // braces to handle nested objects without grabbing trailing
    // prose after a truncated response.
    const m = extractFirstBalancedJson(text);
    if (!m) return null;
    try {
      return JSON.parse(m);
    } catch (_e) {
      return null;
    }
  }

  function parseLlmJsonArray(text) {
    if (!text || typeof text !== "string") return null;
    let cleaned = stripLlmCodeFences(text);
    try {
      const parsed = JSON.parse(cleaned);
      if (Array.isArray(parsed)) return parsed;
    } catch (_e) { /* fall through */ }
    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) return parsed;
    } catch (_e) { /* fall through */ }
    // Strip raw control chars inside JSON string values (LLM emits
    // literal newlines inside strings instead of `\n` sequences).
    const cleaned2 = repairLlmJsonStrings(cleaned);
    const cleaned3 = closeOpenJsonBraces(cleaned2);
    try {
      const parsed = JSON.parse(cleaned3);
      if (Array.isArray(parsed)) return parsed;
    } catch (_e) { /* fall through */ }
    const m = extractFirstBalancedJson(text);
    if (!m) return null;
    try {
      const parsed = JSON.parse(m);
      if (Array.isArray(parsed)) return parsed;
    } catch (_e) {
      return null;
    }
    return null;
  }

  function clamp01(n) {
    const x = Number(n);
    if (!Number.isFinite(x)) return NaN;
    if (x < 0) return 0;
    if (x > 1) return 1;
    return x;
  }

  // Ask Ollama to re-score the decoder candidates. Returns a new array of
  // candidate objects sorted by combinedScore (descending) when successful.
  // The function is best-effort and will return the original candidates on
  // any parse/error failure.
  async function rerankCandidatesWithLlm(delays, candidates, model, opts = {}) {
    if (!Array.isArray(candidates) || candidates.length === 0) return candidates;

    // Pull small priors from model to aid the LLM: baselines and a small
    // list of empirical digraphs (if present). Keep the payload compact.
    const baselines = (model && model.baselines) || null;
    const empirical = (model && model.empirical) || null;
    const allowedAlphabet = (model && model.alphabet) || "abcdefghijklmnopqrstuvwxyz0123456789 .,-_/:;=?!@#$%^&*()[]{}<>'\"|\\~`+";

    // Include any estimated command length / Enter detection hints discovered
    // by local heuristics so the LLM can respect likely command boundaries.
    const estimatedCommandLength = Number.isFinite(opts.estimatedCommandLength) ? opts.estimatedCommandLength : null;
    const delaysWithIdx = Array.isArray(opts.delaysWithIdx) ? opts.delaysWithIdx.slice(0, 200) : null;

    // Read user tuning: preset and LLM weight slider (persisted in Settings).
    const presetSetting = (typeof document !== 'undefined' && document.getElementById('settings-llm-preset')) ? document.getElementById('settings-llm-preset').value : 'english';
    let llmWeightPercent = 40;
    try {
      if (typeof document !== 'undefined' && document.getElementById('settings-llm-weight-percent')) {
        const v = Number(document.getElementById('settings-llm-weight-percent').value);
        if (Number.isFinite(v)) llmWeightPercent = Math.max(0, Math.min(100, v));
      }
    } catch (_e) {
      llmWeightPercent = 40;
    }
    // decoder weight alpha = 1 - llmWeightFraction
    const computedAlpha = Math.max(0, Math.min(1, 1 - llmWeightPercent / 100));

    // Build a concise, machine-friendly prompt that asks the LLM to return
    // a strict JSON array of objects. Instruct the model to score both
    // timing-likelihood (using QWERTY/digraph priors) and language-model
    // plausibility for shell/ssh commands, and to combine them into a
    // single score between 0 and 1. Responses must be commands suitable
    // for an interactive ssh shell and must use only allowed characters.
    const payload = {
      delays: delays.slice(0, 200), // avoid extremely long prompts
      delaysWithIdx: delaysWithIdx || undefined,
      estimatedCommandLength: estimatedCommandLength !== null ? estimatedCommandLength : undefined,
      backspaceHints: opts.backspaceHints || undefined,
      candidates: candidates.map((c) => ({ text: c.text || "", logProb: c.logProb })),
      baselines: baselines || {},
      empiricalDigraphsSample: Object.keys(empirical || {}).slice(0, 40),
      allowedAlphabet,
      languagePreset: presetSetting || 'english',
      llmWeightPercent: llmWeightPercent,
      note:
        "Return strictly a JSON array of objects [{\"text\": string, \"score\": number, \"isCommand\": boolean}]. 'score' is a combined probability in [0,1] that the text was typed in this SSH session given the timing data and language priors. If an estimatedCommandLength is provided, prefer candidates whose length best matches that estimate (within ±2 chars). If backspaceHints are provided, consider that deletions may have occurred at those positions and prefer candidate texts that can explain those corrections. Keep the output valid JSON with no additional commentary."
    };

    let prompt = `You are a specialist assistant that combines keystroke-timing likelihoods with shell-language priors to judge which candidate strings are most likely to have been typed in an interactive SSH session. Use the language preset: ${String(presetSetting || 'english')}.

Context JSON:
${JSON.stringify(payload)}

Instructions:
- Use QWERTY and digraph timing priors to approximate timing-likelihoods. If delaysWithIdx and estimatedCommandLength are provided, use them to prefer candidates that align with the detected Enter/Return boundary. If backspaceHints are present, assume those positions likely correspond to deletion keypresses (Backspace/Delete) and allow candidate texts that are shorter or contain corrections at those positions.
- Use your language model knowledge to score how plausible each candidate is as an SSH shell command (examples: ls, cd, sudo, git status, cat /etc/passwd, ./run.sh). If the preset is 'command-line' prefer typical shell invocations; if 'vim', increase tolerance for editor-like fragments and keypress patterns.
- Prefer outputs that are valid commands for an interactive shell and follow POSIX-style command patterns where appropriate.
- Output JSON array only, with objects: {\"text\": string, \"score\": number in [0,1], \"isCommand\": boolean}.`;
    let rawResp;
    try {
      rawResp = await window.llmapi.generate(prompt, {
        maxTokens: 4096,
        temperature: 0.3,
        think: false,
      });
    } catch (err) {
      console.warn("LLM generate error:", err);
      return candidates;
    }

    // Extract textual content from the known Ollama response shapes.
    let textResp = "";
    try {
      if (typeof rawResp === "string") {
        textResp = rawResp;
      } else if (rawResp && typeof rawResp === "object") {
        if (Array.isArray(rawResp.output) && rawResp.output.length > 0) {
          textResp = rawResp.output.map((o) => o.content || "").join("\n");
        } else if (Array.isArray(rawResp)) {
          textResp = rawResp.map((r) => (r && r.content) || JSON.stringify(r)).join("\n");
        } else if (rawResp?.[0]?.content) {
          textResp = rawResp[0].content;
        } else if (rawResp?.content) {
          textResp = rawResp.content;
        } else {
          textResp = JSON.stringify(rawResp);
        }
      }
    } catch (err) {
      console.warn("Failed to normalize LLM response:", err, rawResp);
      return candidates;
    }

    // Try to find a JSON array in the response.
    const jsonMatch = textResp.match(/\[\s*\{[\s\S]*\}\s*\]/m);
    if (!jsonMatch) {
      try {
        const parsedAll = JSON.parse(textResp);
        if (Array.isArray(parsedAll)) {
          let merged = mergeLlmScoresIntoCandidates(parsedAll, candidates);
          // Attempt to get a single best-guess from the LLM to further bias
          // by language plausibility. Best-guess is optional; failures are
          // non-fatal.
          try {
            const bestPrompt = `Given the same context and the candidate list, return a strict JSON object with the single most probable SSH command string that could have been typed and a confidence in [0,1]. Example: {"text":"ls -la","confidence":0.82}. Return ONLY the object.`;
            const bestResp = await window.llmapi.generate(bestPrompt);
            let bestText = "";
            let bestConf = null;
            if (typeof bestResp === "string") {
              try {
                const b = JSON.parse(bestResp);
                bestText = b.text || "";
                bestConf = Number.isFinite(b.confidence) ? b.confidence : null;
              } catch (_e) {
                // try to extract object from text
                const m = bestResp.match(/\{[\s\S]*\}/m);
                if (m) {
                  try {
                    const b2 = JSON.parse(m[0]);
                    bestText = b2.text || "";
                    bestConf = Number.isFinite(b2.confidence) ? b2.confidence : null;
                  } catch (_e2) { }
                }
              }
            } else if (bestResp && typeof bestResp === "object") {
              if (bestResp?.text) {
                bestText = bestResp.text;
                bestConf = Number.isFinite(bestResp.confidence) ? bestResp.confidence : null;
              } else if (bestResp?.content) {
                try {
                  const b3 = JSON.parse(bestResp.content);
                  bestText = b3.text || "";
                  bestConf = Number.isFinite(b3.confidence) ? b3.confidence : null;
                } catch (_e) { }
              }
            }

            if (bestText && bestText.trim()) {
              bestText = sanitizeTextForAlphabetShared(bestText).trim();
              if (bestText) {
                // Find best matching candidate or insert as synthetic.
                const lcBest = bestText.toLowerCase();
                let matched = null;
                for (const mc of merged) {
                  if ((mc.text || "").toLowerCase() === lcBest) {
                    matched = mc;
                    break;
                  }
                }
                if (!matched) {
                  for (const mc of merged) {
                    const t = (mc.text || "").toLowerCase();
                    if (t && (t.includes(lcBest) || lcBest.includes(t))) {
                      matched = mc;
                      break;
                    }
                  }
                }
                if (matched) {
                  // Boost matched candidate's llmScore toward bestConf
                  if (Number.isFinite(bestConf)) {
                    matched.llmScore = Math.max(matched.llmScore || 0, bestConf);
                  } else {
                    matched.llmScore = Math.max(matched.llmScore || 0, 0.5);
                  }
                  matched.llmBestGuess = true;
                } else {
                  // Insert synthetic candidate at the top
                  const synth = {
                    text: bestText,
                    logProb: Number.NEGATIVE_INFINITY,
                    decoderProb: 0.0001,
                    llmScore: Number.isFinite(bestConf) ? bestConf : 0.5,
                    llmIsCommand: looksLikeShellCommandShared(bestText),
                    combinedScore: 0,
                    synthetic: true,
                  };
                  merged.unshift(synth);
                }

                // Re-normalize LLM scores and re-compute combined scores with
                // a bias toward the LLM (more language-driven ranking).
                // Reduce decoder weight slightly when a best-guess is present so
                // language plausibility has more pull. computedAlpha is the
                // decoder-weight baseline derived from the UI slider; scale it
                // toward language for the best-guess path.
                const alpha = Math.max(0, computedAlpha * 0.6);
                const decoderProbs = merged.map((c) => c.decoderProb || (Number.isFinite(c.logProb) ? Math.exp(c.logProb) : 0));
                const sumDecoder = decoderProbs.reduce((s, v) => s + v, 0) || 1e-12;
                const decoderNorm = decoderProbs.map((v) => v / sumDecoder);
                const llmScores = merged.map((c) => Number.isFinite(c.llmScore) ? c.llmScore : 0.01);
                const sumLlm = llmScores.reduce((s, v) => s + v, 0) || 1e-12;
                const llmNorm = llmScores.map((v) => v / sumLlm);
                for (let i = 0; i < merged.length; i++) {
                  const cmdBoost = merged[i].llmIsCommand ? 1.12 : 1.0;
                  merged[i].combinedScore = (alpha * decoderNorm[i] + (1 - alpha) * llmNorm[i]) * cmdBoost;
                }
                const sumC = merged.reduce((s, v) => s + (v.combinedScore || 0), 0) || 1e-12;
                for (const m of merged) m.combinedScore = m.combinedScore / sumC;

                merged.sort((a, b) => b.combinedScore - a.combinedScore);
              }
            }
          } catch (_bgErr) {
            // ignore best-guess failures
          }
          return merged;
        }
      } catch (_e) {
        console.warn("LLM response did not contain JSON array");
        return candidates;
      }
    }

    try {
      if (!jsonMatch || !jsonMatch[0]) {
        // Defensive fallback: try parsing the full textResp as JSON array.
        try {
          const parsedAll2 = JSON.parse(textResp);
          if (Array.isArray(parsedAll2)) return mergeLlmScoresIntoCandidates(parsedAll2, candidates);
        } catch (_e) {
          console.warn("LLM response matched but had no capture group; falling back to original candidates");
          return candidates;
        }
      }
      const parsed = JSON.parse(jsonMatch[0]);
      if (!Array.isArray(parsed)) return candidates;
      return mergeLlmScoresIntoCandidates(parsed, candidates);
    } catch (err) {
      console.warn("Failed to parse JSON from LLM response:", err);
      return candidates;
    }

    function sanitizeTextForAlphabetLocal(text, allowedAlphabet) {
      if (!text || typeof text !== "string") return "";
      const allowed = new Set(String(allowedAlphabet || "").split(""));
      let out = "";
      for (const ch of text) {
        if (allowed.has(ch) || ch === '\n' || ch === '\t') out += ch;
      }
      return out.trim();
    }

    function mergeLlmScoresIntoCandidatesLocal(parsedArray, originalCandidates, allowedAlphabet, computedAlphaLocal) {
      // Map texts to scores; allow case-insensitive matching and simple
      // substring fallback.
      const scoreMap = new Map();
      for (const item of parsedArray) {
        if (!item || typeof item !== "object") continue;
        const t = sanitizeTextForAlphabetLocal(String(item.text || ""), allowedAlphabet).trim();
        let s = Number(item.score ?? item.score?.value ?? item.prob ?? item.confidence);
        if (!Number.isFinite(s)) s = Number(item.score) || 0;
        if (!Number.isFinite(s) || s < 0) s = 0;
        if (s > 1) s = 1;
        const isCommand = !!item.isCommand || looksLikeShellCommandShared(t);
        scoreMap.set(t, { s, isCommand });
      }

      // Build arrays for normalization.
      const llmScores = originalCandidates.map((c) => {
        const text = sanitizeTextForAlphabetLocal(String(c.text || ""), allowedAlphabet).trim();
        if (scoreMap.has(text)) return scoreMap.get(text).s;
        for (const [k, v] of scoreMap.entries()) {
          if (k.toLowerCase() === text.toLowerCase()) return v.s;
        }
        for (const [k, v] of scoreMap.entries()) {
          if (text && k && (text.includes(k) || k.includes(text))) return v.s;
        }
        return 0.01; // small default
      });

      const llmIsCommand = originalCandidates.map((c) => {
        const text = sanitizeTextForAlphabetLocal(String(c.text || ""), allowedAlphabet).trim();
        if (scoreMap.has(text)) return !!scoreMap.get(text).isCommand;
        for (const [k, v] of scoreMap.entries()) {
          if (k.toLowerCase() === text.toLowerCase()) return !!v.isCommand;
        }
        return false;
      });

      // Normalize decoder probabilities and LLM scores, then combine.
      const decoderProbs = originalCandidates.map((c) => (Number.isFinite(c.logProb) ? Math.exp(c.logProb) : 0));
      const sumDecoder = decoderProbs.reduce((s, v) => s + v, 0) || 1e-12;
      const sumLlm = llmScores.reduce((s, v) => s + v, 0) || 1e-12;
      const decoderNorm = decoderProbs.map((v) => v / sumDecoder);
      const llmNorm = llmScores.map((v) => v / sumLlm);

      // Combine using the UI-configured weighting: computedAlpha is the
      // decoder-weight baseline (1 - llmWeightFraction). Slightly boost
      // candidates that look like commands.
      const alpha = typeof computedAlphaLocal === 'number' ? computedAlphaLocal : 0.6;
      const merged = originalCandidates.map((c, i) => {
        const baseCombined = alpha * decoderNorm[i] + (1 - alpha) * llmNorm[i];
        const commandBoost = llmIsCommand[i] ? 1.12 : 1.0; // slight boost
        return {
          ...c,
          combinedScore: baseCombined * commandBoost,
          llmScore: llmScores[i],
          decoderProb: decoderProbs[i],
          llmIsCommand: !!llmIsCommand[i],
        };
      });

      // Normalize combined scores to [0,1]
      const sumCombined = merged.reduce((s, v) => s + (v.combinedScore || 0), 0) || 1e-12;
      for (const m of merged) {
        m.combinedScore = m.combinedScore / sumCombined;
      }

      merged.sort((a, b) => b.combinedScore - a.combinedScore);
      return merged;
    }
  }

  function sanitizeTextForAlphabetShared(text, allowedAlphabet) {
    if (!text || typeof text !== "string") return "";
    const allowed = new Set(String(allowedAlphabet || "").split(""));
    let out = "";
    for (const ch of text) {
      if (allowed.has(ch) || ch === '\n' || ch === '\t') out += ch;
    }
    return out.trim();
  }

  function looksLikeShellCommandShared(t) {
    if (!t || typeof t !== "string") return false;
    const trimmed = t.trim();
    if (!trimmed) return false;
    return /^([a-zA-Z0-9_./-]|\.|\s)/.test(trimmed) && /[a-zA-Z0-9/._-]/.test(trimmed);
  }

  function mergeLlmScoresIntoCandidatesShared(parsedArray, originalCandidates, allowedAlphabet, computedAlpha) {
    const scoreMap = new Map();
    for (const item of parsedArray) {
      if (!item || typeof item !== "object") continue;
      const t = sanitizeTextForAlphabetShared(String(item.text || ""), allowedAlphabet).trim();
      let s = Number(item.score ?? item.score?.value ?? item.prob ?? item.confidence);
      if (!Number.isFinite(s)) s = Number(item.score) || 0;
      if (!Number.isFinite(s) || s < 0) s = 0;
      if (s > 1) s = 1;
      const isCommand = !!item.isCommand || looksLikeShellCommandShared(t);
      scoreMap.set(t, { s, isCommand });
    }

    const llmScores = originalCandidates.map((c) => {
      const text = sanitizeTextForAlphabetShared(String(c.text || ""), allowedAlphabet).trim();
      if (scoreMap.has(text)) return scoreMap.get(text).s;
      for (const [k, v] of scoreMap.entries()) {
        if (k.toLowerCase() === text.toLowerCase()) return v.s;
      }
      for (const [k, v] of scoreMap.entries()) {
        if (text && k && (text.includes(k) || k.includes(text))) return v.s;
      }
      return 0.01;
    });

    const llmIsCommand = originalCandidates.map((c) => {
      const text = sanitizeTextForAlphabetShared(String(c.text || ""), allowedAlphabet).trim();
      if (scoreMap.has(text)) return !!scoreMap.get(text).isCommand;
      for (const [k, v] of scoreMap.entries()) {
        if (k.toLowerCase() === text.toLowerCase()) return !!v.isCommand;
      }
      return false;
    });

    const decoderProbs = originalCandidates.map((c) => (Number.isFinite(c.logProb) ? Math.exp(c.logProb) : 0));
    const sumDecoder = decoderProbs.reduce((s, v) => s + v, 0) || 1e-12;
    const sumLlm = llmScores.reduce((s, v) => s + v, 0) || 1e-12;
    const decoderNorm = decoderProbs.map((v) => v / sumDecoder);
    const llmNorm = llmScores.map((v) => v / sumLlm);

    const alpha = typeof computedAlpha === "number" ? computedAlpha : 0.6;
    const merged = originalCandidates.map((c, i) => {
      const baseCombined = alpha * decoderNorm[i] + (1 - alpha) * llmNorm[i];
      const commandBoost = llmIsCommand[i] ? 1.12 : 1.0;
      return {
        ...c,
        combinedScore: baseCombined * commandBoost,
        llmScore: llmScores[i],
        decoderProb: decoderProbs[i],
        llmIsCommand: !!llmIsCommand[i],
      };
    });
    const sumCombined = merged.reduce((s, v) => s + (v.combinedScore || 0), 0) || 1e-12;
    for (const m of merged) {
      m.combinedScore = m.combinedScore / sumCombined;
    }
    merged.sort((a, b) => b.combinedScore - a.combinedScore);
    return merged;
  }

  // Compat alias: the inner-block ``mergeLlmScoresIntoCandidatesLocal``
  // and the outer-scope ``mergeLlmScoresIntoCandidatesShared`` exist
  // for refactor-safe access, but four call sites in this file still
  // reference the original signature ``mergeLlmScoresIntoCandidates(arr, candidates)``.
  // Aliasing to the shared variant keeps those call sites working
  // without changing their expected argument shape — neither variant
  // uses ``allowedAlphabet``/``computedAlpha`` differently from the
  // other, so the call sites can stay as-is. (This same logic lives
  // in the local-nested copy as a fallback path for any older call
  // shape that may reference it explicitly.)
  function mergeLlmScoresIntoCandidatesLocal(arr, candidates) {
    return mergeLlmScoresIntoCandidatesShared(arr, candidates, "", undefined);
  }
  // Captured at call sites that haven't migrated — keep them routed
  // through the shared implementation so any later tweak applies
  // uniformly.
  function mergeLlmScoresIntoCandidates(arr, candidates) {
    return mergeLlmScoresIntoCandidatesShared(arr, candidates, "", undefined);
  }

  function renderSshSummary(flow, delays, candidates, estimatedCommandLength, backspaceHints) {
    const summaryEl = document.getElementById("crypt-openssh-summary");
    if (!summaryEl) return;
    if (!delays.length) {
      summaryEl.textContent = `Flow ${flow.flowKey}: 0 delays available.`;
      return;
    }
    const sorted = delays.slice().sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    const min = sorted[0];
    const max = sorted[sorted.length - 1];
    const topText = candidates[0]?.text || "(none)";
    const topLogP = candidates[0]?.logProb?.toFixed(2) ?? "n/a";

    const lines = [
      `Flow: ${flow.srcIp}:${flow.srcPort} ↔ ${flow.dstIp}:${flow.dstPort}`,
      `Delays: ${delays.length} | min=${min.toFixed(1)} ms | median=${median.toFixed(1)} ms | max=${max.toFixed(1)} ms`,
      `Top hypothesis: "${topText}"  (logP=${topLogP})`,
    ];
    if (Number.isFinite(estimatedCommandLength)) {
      lines.push(`Estimated command length (chars): ${Number(estimatedCommandLength)}`);
    }
    if (backspaceHints && typeof backspaceHints.count === 'number' && backspaceHints.count > 0) {
      lines.push(`Detected possible deletions (Backspace/Delete): ${backspaceHints.count}`);
    }
    summaryEl.textContent = lines.join("\n");
  }

  function formatCryptSummary(rawText, label, sourceLabel, expectedRegex) {
    const normalized = (rawText || "").trim();
    if (!normalized) {
      return `No ${label.toLowerCase()} loaded.`;
    }

    const lines = normalized.split(/\r?\n/);
    const beginMatch = normalized.match(/-----BEGIN ([^-]+)-----/);
    const endMatch = normalized.match(/-----END ([^-]+)-----/);
    const blockType = beginMatch ? beginMatch[1] : "Plain text";
    const looksExpected =
      !expectedRegex || (beginMatch && expectedRegex.test(blockType));

    return [
      `${label} loaded from ${sourceLabel}.`,
      `Bytes: ${new TextEncoder().encode(normalized).length}`,
      `Lines: ${lines.length}`,
      `Detected block type: ${blockType}`,
      beginMatch && endMatch
        ? `PEM boundaries: ${beginMatch[1]} ... ${endMatch[1]}`
        : "PEM boundaries not detected",
      looksExpected
        ? "Format check: looks valid for this input type"
        : "Format check: unexpected block type for this input",
    ].join("\n");
  }

  function getCryptEncounteredEntries() {
    const entries = [];
    const capturedPackets = getCapturedPackets();
    const hostMap = getHostPacketMap(capturedPackets);
    if (!hostMap) {
      return entries;
    }

    for (const host of Object.keys(hostMap)) {
      const packets = hostMap[host];
      if (!Array.isArray(packets)) continue;

      packets.forEach((packet) => {
        const packetInfo = getPacketInfo(packet);
        const extraInfo = getExtraInfo(packet);
        const serverInfo = getServerInfo(extraInfo);
        const encryptionData = getEncryptionData(serverInfo);
        if (
          Object.keys(packetInfo).length === 0 ||
          Object.keys(serverInfo).length === 0 ||
          !encryptionData ||
          encryptionData === "N/A"
        )
          return;

        const protocol =
          packetInfo["Protocol"] ||
          packetInfo["packet.proto"] ||
          "Unknown";
        const transportData = getTransportData(packetInfo, protocol);
        const encryptedWithRaw =
          encryptionData["Encrypted With"] || encryptionData["encrypted.with"];
        const encryptedWith = Array.isArray(encryptedWithRaw)
          ? encryptedWithRaw.filter(Boolean)
          : encryptedWithRaw
            ? [String(encryptedWithRaw)]
            : [];
        entries.push({
          host,
          packetIndex: packetInfo["Index"] ?? packetInfo["packet.processed"] ?? "?",
          protocol,
          srcIp: packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"] ?? "N/A",
          dstIp: packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"] ?? "N/A",
          srcPort: transportData?.["Source port"] ?? transportData?.["source.port"] ?? "N/A",
          dstPort: transportData?.["Destination port"] ?? transportData?.["destination.port"] ?? "N/A",
          encrypted: serverInfo["Encrypted"] ?? serverInfo["encrypted"] ?? "Unknown",
          sslVersion: encryptionData["SSL Version"] ?? encryptionData["ssl.version"] ?? "Unknown",
          sslCert: encryptionData["SSL Cert"] ?? encryptionData["ssl.cert"] ?? "",
          encryptedWith,
        });
      });
    }

    return entries.sort((a, b) => {
      const aIdx = Number(a.packetIndex);
      const bIdx = Number(b.packetIndex);
      if (Number.isFinite(aIdx) && Number.isFinite(bIdx)) return aIdx - bIdx;
      return String(a.packetIndex).localeCompare(String(b.packetIndex));
    });
  }

  function renderCryptEncounteredDetails(entry) {
    const detailsEl = document.getElementById("crypt-encountered-details");
    if (!entry) {
      detailsEl.textContent = "Select an encountered SSL/TLS item to inspect.";
      return;
    }
    const algoText = entry.encryptedWith.length
      ? entry.encryptedWith.join(", ")
      : "Unavailable";
    const sourceEndpoint = formatCryptEndpoint(entry.srcIp, entry.srcPort);
    const destinationEndpoint = formatCryptEndpoint(entry.dstIp, entry.dstPort);
    detailsEl.textContent = [
      `Host: ${entry.host}`,
      `Packet: ${entry.packetIndex}`,
      `Protocol: ${entry.protocol}`,
      `Path: ${sourceEndpoint} -> ${destinationEndpoint}`,
      `Encrypted: ${entry.encrypted}`,
      `SSL/TLS Version: ${entry.sslVersion}`,
      `Algorithms: ${algoText}`,
      entry.streamHeaderSummary ? `Stream header: ${entry.streamHeaderSummary}` : null,
      entry.streamConnectSummary ? `Proxy tunnel: ${entry.streamConnectSummary}` : null,
    ].join("\n");
  }

  function renderCurrentCryptEncounteredEntries() {
    const listEl = document.getElementById("crypt-encountered-list");
    listEl.replaceChildren();
    cryptActiveEntryIndex = -1;

    if (cryptEncounteredEntries.length === 0) {
      const option = document.createElement("option");
      option.textContent =
        "No SSL/TLS encryption encountered in loaded capture.";
      option.disabled = true;
      listEl.appendChild(option);
      renderCryptEncounteredDetails(null);
      clearCryptDecryptionOutput();
      return;
    }

    cryptEncounteredEntries.forEach((entry, entryIndex) => {
      const option = document.createElement("option");
      option.value = String(entryIndex);
      const algoPreview = entry.encryptedWith.length
        ? entry.encryptedWith[0]
        : "Unknown cipher";
      const sourceEndpoint = formatCryptEndpoint(entry.srcIp, entry.srcPort);
      const destinationEndpoint = formatCryptEndpoint(entry.dstIp, entry.dstPort);
      option.textContent = `#${entry.packetIndex} ${entry.sslVersion} ${sourceEndpoint} -> ${destinationEndpoint} (${algoPreview})`;
      listEl.appendChild(option);
    });

    listEl.selectedIndex = 0;
    cryptActiveEntryIndex = 0;
    renderCryptEncounteredDetails(cryptEncounteredEntries[0]);
    clearCryptDecryptionOutput();
  }

  function mergeWithSessionCryptEntries(baseEntries) {
    const merged = [];
    const seenKeys = new Set();

    const pushUnique = (entry) => {
      if (!entry || typeof entry !== "object") return;
      const uniqueKey =
        entry.sessionEntryId ||
        [
          String(entry.host || ""),
          String(entry.packetIndex || ""),
          String(entry.srcIp || ""),
          String(entry.srcPort || ""),
          String(entry.dstIp || ""),
          String(entry.dstPort || ""),
          String(entry.payloadHex || "").slice(0, 64),
        ].join("|");
      if (seenKeys.has(uniqueKey)) return;
      seenKeys.add(uniqueKey);
      merged.push(entry);
    };

    (Array.isArray(baseEntries) ? baseEntries : []).forEach(pushUnique);
    cryptSessionEncounteredEntries.forEach(pushUnique);

    return merged.sort((a, b) => {
      const aIdx = Number.parseInt(String(a.packetIndex || ""), 10);
      const bIdx = Number.parseInt(String(b.packetIndex || ""), 10);
      if (Number.isFinite(aIdx) && Number.isFinite(bIdx)) return aIdx - bIdx;
      return String(a.packetIndex || "").localeCompare(
        String(b.packetIndex || ""),
      );
    });
  }

  function refreshCryptEncounteredEntries() {
    const detectedEntries = getCryptEncounteredEntries();
    cryptEncounteredEntries = mergeWithSessionCryptEntries(detectedEntries);
    renderCurrentCryptEncounteredEntries();
  }

  function setDecryptSendEnabled(isEnabled) {
    const sendBtnEl = document.getElementById("crypt-send-decrypted-conv-btn");
    if (sendBtnEl) {
      sendBtnEl.disabled = !isEnabled;
    }
  }

  function clearCryptDecryptionOutput() {
    const decryptPreviewEl = document.getElementById("crypt-decrypt-preview");
    if (decryptPreviewEl) {
      decryptPreviewEl.textContent = "No decrypted TLS/SSL output yet.";
    }
    cryptLastDecryptedPayload = null;
    setDecryptSendEnabled(false);
  }

  function setPgpSendEnabled(isEnabled) {
    const sendBtnEl = document.getElementById("crypt-pgp-send-conv-btn");
    if (sendBtnEl) {
      sendBtnEl.disabled = !isEnabled;
    }
  }

  function clearPgpOutput() {
    const outputEl = document.getElementById("crypt-pgp-output-preview");
    if (outputEl) {
      outputEl.textContent = "No PGP output yet.";
    }
    pgpLastOutputPayload = null;
    setPgpSendEnabled(false);
  }

  function clearPgpInput() {
    const inputEl = document.getElementById("crypt-pgp-input");
    const analysisEl = document.getElementById("crypt-pgp-analysis-preview");
    if (inputEl) inputEl.value = "";
    if (analysisEl) analysisEl.textContent = "No PGP input analyzed yet.";
  }

  function normalizePgpPrivateKeyCandidate(value) {
    const normalized = String(value || "")
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
      .trim();
    if (!normalized) return "";
    if (!PGP_PRIVATE_KEY_BLOCK_REGEX.test(normalized)) return "";
    return normalized;
  }

  function normalizePgpPassphraseCandidate(value) {
    const normalized = String(value || "")
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
      .trim();
    if (!normalized) return "";
    if (normalized.length < 3 || normalized.length > 160) return "";
    return normalized;
  }

  function truncatePgpKeyPreview(value, maxLen = 72) {
    const normalized = String(value || "").replace(/\r?\n/g, " ").trim();
    if (!normalized) return "";
    if (normalized.length <= maxLen) return normalized;
    return `${normalized.slice(0, maxLen - 3)}...`;
  }

  function renderPgpPrivateKeyCandidates() {
    const selectEl = document.getElementById("crypt-pgp-private-key-candidates");
    if (!selectEl) return;
    selectEl.replaceChildren();

    if (pgpPrivateKeyCandidates.length === 0) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No PGP private keys in session keychain";
      option.selected = true;
      selectEl.appendChild(option);
      return;
    }

    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Select PGP private key from session keychain";
    placeholder.selected = true;
    selectEl.appendChild(placeholder);

    pgpPrivateKeyCandidates.forEach((candidate, candidateIndex) => {
      const option = document.createElement("option");
      option.value = String(candidateIndex);
      option.textContent = candidate.label;
      selectEl.appendChild(option);
    });
  }

  function renderPgpPassphraseCandidates() {
    const selectEl = document.getElementById("crypt-pgp-passphrase-candidates");
    if (!selectEl) return;
    selectEl.replaceChildren();

    if (pgpPassphraseCandidates.length === 0) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No passphrases in session keychain";
      option.selected = true;
      selectEl.appendChild(option);
      return;
    }

    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Select passphrase from session keychain";
    placeholder.selected = true;
    selectEl.appendChild(placeholder);

    pgpPassphraseCandidates.forEach((candidate, candidateIndex) => {
      const option = document.createElement("option");
      option.value = String(candidateIndex);
      option.textContent = candidate.label;
      selectEl.appendChild(option);
    });
  }

  function refreshPgpPrivateKeyCandidates() {
    const entries =
      typeof getSessionKeychainEntries === "function"
        ? getSessionKeychainEntries()
        : [];
    const candidateMap = new Map();
    if (!Array.isArray(entries)) {
      pgpPrivateKeyCandidates = [];
      renderPgpPrivateKeyCandidates();
      return;
    }

    entries.forEach((entry) => {
      if (!entry || entry.type !== "private-key") return;
      const normalizedContent = normalizePgpPrivateKeyCandidate(entry.content);
      if (!normalizedContent || candidateMap.has(normalizedContent)) return;
      const labelPrefix = String(entry.label || "PGP Private Key").trim();
      candidateMap.set(normalizedContent, {
        content: normalizedContent,
        label: `${labelPrefix} - ${truncatePgpKeyPreview(normalizedContent)}`,
      });
    });

    pgpPrivateKeyCandidates = Array.from(candidateMap.values());
    renderPgpPrivateKeyCandidates();
  }

  function refreshPgpPassphraseCandidates() {
    const entries =
      typeof getSessionKeychainEntries === "function"
        ? getSessionKeychainEntries()
        : [];
    const candidateMap = new Map();
    if (!Array.isArray(entries)) {
      pgpPassphraseCandidates = [];
      renderPgpPassphraseCandidates();
      return;
    }

    entries.forEach((entry) => {
      if (!entry || entry.type !== "secret") return;
      const normalizedContent = normalizePgpPassphraseCandidate(entry.content);
      if (!normalizedContent || candidateMap.has(normalizedContent)) return;
      const labelPrefix = String(entry.label || "Secret").trim();
      candidateMap.set(normalizedContent, {
        content: normalizedContent,
        label: `${labelPrefix} - ${"*".repeat(Math.min(normalizedContent.length, 8))}`,
      });
    });

    pgpPassphraseCandidates = Array.from(candidateMap.values());
    renderPgpPassphraseCandidates();
  }

  function useSelectedPgpPrivateKeyCandidate() {
    const selectEl = document.getElementById("crypt-pgp-private-key-candidates");
    const inputEl = document.getElementById("crypt-pgp-private-key-input");
    const selectedIndex = Number.parseInt(String(selectEl?.value || ""), 10);
    const selectedCandidate =
      Number.isInteger(selectedIndex) && selectedIndex >= 0
        ? pgpPrivateKeyCandidates[selectedIndex]
        : null;
    if (!selectedCandidate) {
      statusUpdate("Status: Select a PGP private key first");
      return;
    }
    if (inputEl) {
      inputEl.value = selectedCandidate.content;
    }
    statusUpdate("Status: PGP private key loaded from session keychain");
  }

  function useSelectedPgpPasswordCandidate() {
    const selectEl = document.getElementById("crypt-pgp-passphrase-candidates");
    const inputEl = document.getElementById("crypt-pgp-passphrase-input");
    const selectedIndex = Number.parseInt(String(selectEl?.value || ""), 10);
    const selectedCandidate =
      Number.isInteger(selectedIndex) && selectedIndex >= 0
        ? pgpPassphraseCandidates[selectedIndex]
        : null;
    if (!selectedCandidate) {
      statusUpdate("Status: Select a passphrase first");
      return;
    }
    if (inputEl) {
      inputEl.value = selectedCandidate.content;
    }
    statusUpdate("Status: Passphrase loaded from session keychain");
  }

  async function saveSuccessfulPgpKeyMaterial({
    privateKeyText,
    passphrase,
  }) {
    const extractPrivateKeyBlock = (rawValue) => {
      const text = String(rawValue || "").trim();
      if (!text) return "";
      const blockMatch = text.match(PGP_PRIVATE_KEY_BLOCK_REGEX);
      if (blockMatch?.[0]) {
        return String(blockMatch[0]).trim();
      }
      return text;
    };

    // Persist the exact private key material the user pasted into the PGP private key input.
    // This avoids saving any transformed/internal representation.
    const normalizedPrivateKey = extractPrivateKeyBlock(privateKeyText);
    const normalizedPassphrase = String(passphrase || "").trim();

    if (normalizedPassphrase) {
      addSessionKeystoreEntry({
        type: "secret",
        label: "PGP Password",
        source: "pgp-decrypt-success",
        content: normalizedPassphrase,
        summary: "Validated by successful PGP decrypt",
      });
      refreshPgpPassphraseCandidates();
    }

    if (normalizedPrivateKey) {
      addSessionKeystoreEntry({
        type: "private-key",
        label: "PGP Private Key",
        source: "pgp-decrypt-success",
        content: normalizedPrivateKey,
        summary: "Validated by successful PGP decrypt",
      });
      refreshPgpPrivateKeyCandidates();
    }
  }

  function normalizeHexString(value) {
    return String(value || "").replace(/[^0-9A-Fa-f]/g, "");
  }

  function parseHexToBuffer(value) {
    const normalized = normalizeHexString(value);
    if (!normalized) {
      throw new Error("No binary hex data provided.");
    }
    if (normalized.length % 2 !== 0) {
      throw new Error("Hex payload has an odd length and is invalid.");
    }
    return Buffer.from(normalized, "hex");
  }

  function getPacketPayloadHex(packet) {
    const packetInfo = getPacketInfo(packet);
    return String(
      (packetInfo?.["Raw data"]?.["Payload"]?.["payload.hex"] ??
        packetInfo?.["Raw data"]?.["Payload"]?.["Hex Encoded"] ??
        packetInfo?.["raw.data"]?.["payload"]?.["payload.hex"] ??
        packetInfo?.["raw.data"]?.["payload"]?.["hex.encoded"]) ||
      "",
    );
  }

  function findPayloadHexForEncounteredEntry(entry) {
    if (entry?.payloadHex) {
      return String(entry.payloadHex || "");
    }
    const packets = getHostPacketMap(getCapturedPackets())?.[entry.host];
    if (!Array.isArray(packets)) return "";
    const matchedPacket = packets.find((packet) => {
      const packetInfo = getPacketInfo(packet);
      const packetIndex =
        packetInfo?.["Index"] ?? packetInfo?.["packet.processed"];
      return String(packetIndex) === String(entry.packetIndex);
    });
    return getPacketPayloadHex(matchedPacket);
  }

  function findTlsRecordOffsetBytes(payloadBytes) {
    if (!payloadBytes || payloadBytes.length < 5) return -1;
    for (let offset = 0; offset <= payloadBytes.length - 5; offset += 1) {
      const contentType = payloadBytes[offset];
      if (contentType < TLS_CONTENT_TYPE_MIN || contentType > TLS_CONTENT_TYPE_MAX) {
        continue;
      }
      const major = payloadBytes[offset + 1];
      const minor = payloadBytes[offset + 2];
      if (major !== 0x03 || minor > 0x04) continue;
      const recordLength = (payloadBytes[offset + 3] << 8) | payloadBytes[offset + 4];
      if (recordLength <= 0) continue;
      const recordEnd = offset + 5 + recordLength;
      if (recordEnd <= payloadBytes.length) {
        return offset;
      }
    }
    return -1;
  }

  function getTlsStreamHexParts(combinedHex) {
    const normalizedHex = normalizeHexString(combinedHex);
    if (!normalizedHex || normalizedHex.length % 2 !== 0) {
      return {
        payloadHex: normalizedHex,
        decryptPayloadHex: normalizedHex,
        headerSummary: "none",
      };
    }
    const payloadBytes = Buffer.from(normalizedHex, "hex");
    const tlsOffset = findTlsRecordOffsetBytes(payloadBytes);
    if (tlsOffset <= 0) {
      return {
        payloadHex: normalizedHex,
        decryptPayloadHex: normalizedHex,
        headerSummary: tlsOffset === 0 ? "none" : "unrecognized",
      };
    }
    const headerBytes = payloadBytes.subarray(0, tlsOffset);
    const decryptBytes = payloadBytes.subarray(tlsOffset);
    return {
      payloadHex: normalizedHex,
      decryptPayloadHex: decryptBytes.toString("hex"),
      headerSummary: `${headerBytes.length} bytes skipped`,
    };
  }

  function parseSquidConnectHeaderSummary(combinedHex, skippedHeaderBytes = 0) {
    const normalizedHex = normalizeHexString(combinedHex);
    if (!normalizedHex || normalizedHex.length % 2 !== 0 || skippedHeaderBytes <= 0) {
      return "";
    }
    const payloadBytes = Buffer.from(normalizedHex, "hex");
    const headerBytes = payloadBytes.subarray(0, Math.min(skippedHeaderBytes, payloadBytes.length));
    const headerText = headerBytes.toString("utf8");
    const lines = headerText
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    if (!lines.length) return "";

    const connectLine = lines.find((line) => /^CONNECT\s+/i.test(line));
    if (!connectLine) return "";
    const connectMatch = connectLine.match(/^CONNECT\s+([^\s]+)\s+HTTP\//i);
    const target = connectMatch?.[1] || "unknown-target";
    const proxyStatusLine = lines.find((line) => /^HTTP\/\d\.\d\s+200\b/i.test(line));
    return proxyStatusLine
      ? `Squid CONNECT tunnel ${target} (${proxyStatusLine})`
      : `Squid CONNECT tunnel ${target}`;
  }

  function loadStreamIntoCryptEncountered(streamPackets, combinedHex) {
    const packets = Array.isArray(streamPackets) ? streamPackets : [];
    if (!packets.length) {
      refreshCryptEncounteredEntries();
      return;
    }

    const firstPacketInfo = getPacketInfo(packets[0]);
    const lastPacketInfo = getPacketInfo(packets[packets.length - 1]);
    const protocol =
      firstPacketInfo["Protocol"] ||
      firstPacketInfo["packet.proto"] ||
      "Unknown";
    const transportData = getTransportData(firstPacketInfo, protocol);
    const firstExtraInfo = getExtraInfo(packets[0]);
    const firstServerInfo = getServerInfo(firstExtraInfo);
    const firstEncryptionData = getEncryptionData(firstServerInfo) || {};
    const encryptedWithRaw =
      firstEncryptionData["Encrypted With"] || firstEncryptionData["encrypted.with"];
    const encryptedWith = Array.isArray(encryptedWithRaw)
      ? encryptedWithRaw.filter(Boolean)
      : encryptedWithRaw
        ? [String(encryptedWithRaw)]
        : [];
    const streamHexParts = getTlsStreamHexParts(combinedHex);
    const skippedMatch = String(streamHexParts.headerSummary || "").match(/^(\d+)\s+bytes skipped$/i);
    const skippedHeaderBytes = skippedMatch
      ? Number.parseInt(skippedMatch[1], 10)
      : 0;
    const squidConnectSummary = parseSquidConnectHeaderSummary(
      streamHexParts.payloadHex,
      Number.isFinite(skippedHeaderBytes) ? skippedHeaderBytes : 0,
    );
    const sourceStart = firstPacketInfo["Index"] ?? firstPacketInfo["packet.processed"] ?? "?";
    const sourceEnd = lastPacketInfo["Index"] ?? lastPacketInfo["packet.processed"] ?? sourceStart;

    const newSessionEntries = [];
    packets.forEach((packet, packetOffset) => {
      const packetInfo = getPacketInfo(packet);
      if (Object.keys(packetInfo).length === 0) return;
      const packetProtocol =
        packetInfo["Protocol"] || packetInfo["packet.proto"] || protocol;
      const packetTransport = getTransportData(packetInfo, packetProtocol);
      const packetExtraInfo = getExtraInfo(packet);
      const packetServerInfo = getServerInfo(packetExtraInfo);
      const packetEncryptionData = getEncryptionData(packetServerInfo) || {};
      const packetEncryptedWithRaw =
        packetEncryptionData["Encrypted With"] ||
        packetEncryptionData["encrypted.with"] ||
        encryptedWithRaw;
      const packetEncryptedWith = Array.isArray(packetEncryptedWithRaw)
        ? packetEncryptedWithRaw.filter(Boolean)
        : packetEncryptedWithRaw
          ? [String(packetEncryptedWithRaw)]
          : [];

      const packetPayloadHex = normalizeHexString(getPacketPayloadHex(packet));
      const packetHexParts = getTlsStreamHexParts(packetPayloadHex);
      const packetIndexValue =
        packetInfo["Index"] ??
        packetInfo["packet.processed"] ??
        `${sourceStart}-${packetOffset + 1}`;
      const sessionEntryId = [
        "stream",
        String(packetIndexValue),
        String(
          packetInfo?.["IP"]?.["ip.src.addr"] ??
          packetInfo?.["IP"]?.["Source IP"] ??
          "N/A",
        ),
        String(
          packetInfo?.["IP"]?.["ip.dst.addr"] ??
          packetInfo?.["IP"]?.["Destination IP"] ??
          "N/A",
        ),
      ].join("|");

      newSessionEntries.push({
        sessionEntryId,
        host: "stream",
        packetIndex: packetIndexValue,
        protocol: packetProtocol,
        srcIp:
          packetInfo?.["IP"]?.["ip.src.addr"] ??
          packetInfo?.["IP"]?.["Source IP"] ??
          "N/A",
        dstIp:
          packetInfo?.["IP"]?.["ip.dst.addr"] ??
          packetInfo?.["IP"]?.["Destination IP"] ??
          "N/A",
        srcPort:
          packetTransport?.["Source port"] ??
          packetTransport?.["source.port"] ??
          transportData?.["Source port"] ??
          transportData?.["source.port"] ??
          "N/A",
        dstPort:
          packetTransport?.["Destination port"] ??
          packetTransport?.["destination.port"] ??
          transportData?.["Destination port"] ??
          transportData?.["destination.port"] ??
          "N/A",
        encrypted:
          packetServerInfo["Encrypted"] ||
          packetServerInfo["encrypted"] ||
          firstServerInfo["Encrypted"] ||
          firstServerInfo["encrypted"] ||
          "Unknown",
        sslVersion:
          packetEncryptionData["SSL Version"] ||
          packetEncryptionData["ssl.version"] ||
          firstEncryptionData["SSL Version"] ||
          firstEncryptionData["ssl.version"] ||
          "Unknown",
        sslCert:
          packetEncryptionData["SSL Cert"] ||
          packetEncryptionData["ssl.cert"] ||
          firstEncryptionData["SSL Cert"] ||
          firstEncryptionData["ssl.cert"] ||
          "",
        encryptedWith: packetEncryptedWith,
        payloadHex: packetHexParts.payloadHex,
        decryptPayloadHex: packetHexParts.decryptPayloadHex,
        streamHeaderSummary:
          packetOffset === 0
            ? `${streamHexParts.headerSummary} across stream ${sourceStart}-${sourceEnd}`
            : packetHexParts.headerSummary,
        streamConnectSummary: packetOffset === 0 ? squidConnectSummary : "",
      });
    });

    cryptSessionEncounteredEntries = mergeWithSessionCryptEntries(
      newSessionEntries,
    );
    refreshCryptEncounteredEntries();
  }

  function extractPgpArmorBlocksFromText(textValue) {
    const text = String(textValue || "");
    if (!text) return [];
    const matches = text.match(PGP_ARMOR_BLOCK_REGEX);
    return Array.isArray(matches) ? matches : [];
  }

  function getPgpEncounteredEntries() {
    const entries = [];
    const capturedPackets = getCapturedPackets();
    const hostMap = getHostPacketMap(capturedPackets);
    if (!hostMap) {
      return entries;
    }

    for (const host of Object.keys(hostMap)) {
      const packets = hostMap[host];
      if (!Array.isArray(packets)) continue;
      packets.forEach((packet) => {
        const packetInfo = getPacketInfo(packet);
        if (Object.keys(packetInfo).length === 0) return;
        const payloadHex = normalizeHexString(getPacketPayloadHex(packet));
        if (!payloadHex) return;
        const payloadBytes = Buffer.from(payloadHex, "hex");
        const payloadText = payloadBytes.toString("utf8");
        const armoredBlocks = extractPgpArmorBlocksFromText(payloadText);
        if (armoredBlocks.length === 0) return;

        const protocol =
          packetInfo["Protocol"] ||
          packetInfo["packet.proto"] ||
          "Unknown";
        const transportData = getTransportData(packetInfo, protocol);
        armoredBlocks.forEach((blockText, blockIndex) => {
          const beginMatch = blockText.match(PGP_BEGIN_LINE_REGEX);
          const endMatch = blockText.match(PGP_END_LINE_REGEX);
          const blockType = beginMatch?.[1] || "PGP data";
          entries.push({
            host,
            packetIndex: packetInfo["Index"] ?? packetInfo["packet.processed"] ?? "?",
            protocol,
            srcIp: packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"] ?? "N/A",
            dstIp: packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"] ?? "N/A",
            srcPort: transportData?.["Source port"] ?? transportData?.["source.port"] ?? "N/A",
            dstPort: transportData?.["Destination port"] ?? transportData?.["destination.port"] ?? "N/A",
            blockType,
            blockIndex,
            armoredText: String(blockText || "").trim(),
            boundariesDetected: Boolean(beginMatch && endMatch),
          });
        });
      });
    }

    return entries.sort((a, b) => {
      const aIdx = Number(a.packetIndex);
      const bIdx = Number(b.packetIndex);
      if (Number.isFinite(aIdx) && Number.isFinite(bIdx)) return aIdx - bIdx;
      return String(a.packetIndex).localeCompare(String(b.packetIndex));
    });
  }

  function renderPgpEncounteredDetails(entry) {
    const detailsEl = document.getElementById("crypt-pgp-encountered-details");
    if (!detailsEl) return;
    if (!entry) {
      detailsEl.textContent = "No PGP messages detected in packet payloads.";
      return;
    }
    const preview = String(entry.armoredText || "")
      .replace(/\r?\n/g, " ")
      .slice(0, MAX_PGP_PREVIEW_LENGTH);
    const sourceEndpoint = formatCryptEndpoint(entry.srcIp, entry.srcPort);
    const destinationEndpoint = formatCryptEndpoint(entry.dstIp, entry.dstPort);
    detailsEl.textContent = [
      `Packet: ${entry.packetIndex}`,
      `Host: ${entry.host}`,
      `Path: ${sourceEndpoint} -> ${destinationEndpoint}`,
      `Protocol: ${entry.protocol}`,
      `Armor type: ${entry.blockType}`,
      `Armor boundaries: ${entry.boundariesDetected ? "detected" : "not detected"}`,
      `Block in payload: ${entry.blockIndex + 1}`,
      "",
      `Preview: ${preview || "(empty)"}`,
    ].join("\n");
  }

  function refreshPgpEncounteredEntries() {
    const listEl = document.getElementById("crypt-pgp-encountered-list");
    if (!listEl) return;
    pgpEncounteredEntries = getPgpEncounteredEntries();
    listEl.replaceChildren();
    pgpActiveEntryIndex = -1;

    if (pgpEncounteredEntries.length === 0) {
      const option = document.createElement("option");
      option.textContent = "No PGP ASCII-armored messages in loaded capture.";
      option.disabled = true;
      listEl.appendChild(option);
      renderPgpEncounteredDetails(null);
      clearPgpOutput();
      return;
    }

    pgpEncounteredEntries.forEach((entry, entryIndex) => {
      const option = document.createElement("option");
      option.value = String(entryIndex);
      const sourceEndpoint = formatCryptEndpoint(entry.srcIp, entry.srcPort);
      const destinationEndpoint = formatCryptEndpoint(entry.dstIp, entry.dstPort);
      option.textContent = `#${entry.packetIndex} ${entry.blockType} ${sourceEndpoint} -> ${destinationEndpoint}`;
      listEl.appendChild(option);
    });

    listEl.selectedIndex = 0;
    pgpActiveEntryIndex = 0;
    renderPgpEncounteredDetails(pgpEncounteredEntries[0]);
    clearPgpOutput();
    refreshPgpPrivateKeyCandidates();
    refreshPgpPassphraseCandidates();
  }

  function selectPgpEncounteredEntry(selectedIndex) {
    if (
      !Number.isFinite(selectedIndex) ||
      !pgpEncounteredEntries[selectedIndex]
    ) {
      return;
    }
    pgpActiveEntryIndex = selectedIndex;
    renderPgpEncounteredDetails(pgpEncounteredEntries[selectedIndex]);
  }

  function resolvePgpEncounteredLoadTarget(blockType) {
    const normalized = String(blockType || "").trim().toUpperCase();
    if (normalized === "PGP PRIVATE KEY BLOCK") {
      return {
        elementId: "crypt-pgp-private-key-input",
        destination: "PGP private key input",
      };
    }
    if (normalized === "PGP PUBLIC KEY BLOCK") {
      return {
        elementId: "crypt-pgp-public-key-input",
        destination: "PGP public key input",
      };
    }
    return {
      elementId: "crypt-pgp-input",
      destination: "PGP input",
    };
  }

  function loadSelectedPgpEncounteredInput() {
    if (pgpActiveEntryIndex < 0 || !pgpEncounteredEntries[pgpActiveEntryIndex]) {
      statusUpdate("Status: Select an encountered PGP entry first");
      return;
    }
    const entry = pgpEncounteredEntries[pgpActiveEntryIndex];
    const target = resolvePgpEncounteredLoadTarget(entry.blockType);
    const inputEl = document.getElementById(target.elementId);
    if (inputEl) {
      inputEl.value = entry.armoredText;
    }
    statusUpdate(
      `Status: Loaded PGP ${entry.blockType} block from packet #${entry.packetIndex} into ${target.destination}`,
    );
    writeLogEntry(
      `[${threadName}] PGP encountered payload loaded packet_index=${entry.packetIndex} block_index=${entry.blockIndex} block_type="${entry.blockType}" destination="${target.elementId}"`,
    );
  }

  async function tryReadPgpStructure(inputText, binaryBytes) {
    if (inputText) {
      if (/^-----BEGIN PGP SIGNED MESSAGE-----/m.test(inputText)) {
        const cleartextMessage = await openpgp.readCleartextMessage({
          cleartextMessage: inputText,
        });
        return {
          kind: "cleartext",
          entity: cleartextMessage,
          format: "ascii-armor",
        };
      }
      try {
        const message = await openpgp.readMessage({ armoredMessage: inputText });
        return { kind: "message", entity: message, format: "ascii-armor" };
      } catch (_) {
        // Try other OpenPGP object readers below.
      }
      try {
        const signature = await openpgp.readSignature({
          armoredSignature: inputText,
        });
        return { kind: "signature", entity: signature, format: "ascii-armor" };
      } catch (_) {
        // Try key readers below.
      }
      try {
        const publicKey = await openpgp.readKey({ armoredKey: inputText });
        return { kind: "public-key", entity: publicKey, format: "ascii-armor" };
      } catch (_) {
        // Try private key reader below.
      }
      try {
        const privateKey = await openpgp.readPrivateKey({ armoredKey: inputText });
        return { kind: "private-key", entity: privateKey, format: "ascii-armor" };
      } catch (_) {
        // Fall through to invalid input error below.
      }
    }

    if (binaryBytes && binaryBytes.length > 0) {
      const binaryMessage = new Uint8Array(binaryBytes);
      try {
        const message = await openpgp.readMessage({ binaryMessage });
        return { kind: "message", entity: message, format: "binary" };
      } catch (_) {
        // Continue through alternative readers.
      }
      try {
        const signature = await openpgp.readSignature({ binarySignature: binaryMessage });
        return { kind: "signature", entity: signature, format: "binary" };
      } catch (_) {
        // Continue through alternative readers.
      }
      try {
        const publicKey = await openpgp.readKey({ binaryKey: binaryMessage });
        return { kind: "public-key", entity: publicKey, format: "binary" };
      } catch (_) {
        // Continue through alternative readers.
      }
      try {
        const privateKey = await openpgp.readPrivateKey({ binaryKey: binaryMessage });
        return { kind: "private-key", entity: privateKey, format: "binary" };
      } catch (_) {
        // Fall through to invalid input error below.
      }
    }

    throw new Error("Input is not recognized as valid OpenPGP data.");
  }

  async function parseCurrentPgpInput() {
    const inputEl = document.getElementById("crypt-pgp-input");
    const rawValue = String(inputEl?.value || "").trim();
    if (!rawValue) {
      throw new Error("No PGP input provided.");
    }
    const looksArmored = /^-----BEGIN PGP /m.test(rawValue);
    const binaryBytes = looksArmored ? null : parseHexToBuffer(rawValue);
    const structure = await tryReadPgpStructure(
      looksArmored ? rawValue : "",
      binaryBytes,
    );
    return {
      rawValue,
      looksArmored,
      binaryBytes,
      structure,
    };
  }

  function getPgpArmorType(textValue) {
    const beginMatch = String(textValue || "").match(PGP_BEGIN_LINE_REGEX);
    return beginMatch?.[1] || "Unknown";
  }

  function getPgpErrorMessage(error, operationLabel) {
    const rawMessage = String(error?.message || "").trim();
    const lowerMessage = rawMessage.toLowerCase();

    const isBadPassphrase =
      lowerMessage.includes("incorrect key passphrase") ||
      lowerMessage.includes("wrong passphrase") ||
      lowerMessage.includes("bad passphrase") ||
      lowerMessage.includes("private key is not decrypted") ||
      lowerMessage.includes("cannot decrypt private key") ||
      lowerMessage.includes("error decrypting private key");

    if (isBadPassphrase) {
      return "PGP key unlock failed: the passphrase appears to be incorrect.";
    }

    const isCorruptedInput =
      lowerMessage.includes("no pgp input provided") ||
      lowerMessage.includes("not recognized as valid openpgp data") ||
      lowerMessage.includes("invalid") ||
      lowerMessage.includes("malformed") ||
      lowerMessage.includes("parse") ||
      lowerMessage.includes("parsing") ||
      lowerMessage.includes("armored") ||
      lowerMessage.includes("armor") ||
      lowerMessage.includes("checksum") ||
      lowerMessage.includes("crc") ||
      lowerMessage.includes("truncated") ||
      lowerMessage.includes("unexpected end") ||
      lowerMessage.includes("odd length") ||
      lowerMessage.includes("binary hex data provided") ||
      lowerMessage.includes("hex payload");

    if (isCorruptedInput) {
      return "PGP input appears corrupted or in the wrong format. Verify armor/hex data and try again.";
    }

    return `PGP ${operationLabel} failed due to an internal app/runtime issue. Try again or restart PacketSnitch. Details: ${rawMessage || "unknown error"}`;
  }

  function formatOpenPgpKeyId(keyId) {
    if (!keyId) return "unknown";
    if (typeof keyId.toHex === "function") return keyId.toHex();
    return String(keyId);
  }

  function buildPgpStructureSummaryLines(parsed) {
    const { rawValue, looksArmored, binaryBytes, structure } = parsed;
    const lines = [];
    lines.push(`Input format: ${looksArmored ? "ASCII armor" : "Binary hex"}`);
    lines.push(`Detected OpenPGP structure: ${structure.kind}`);
    lines.push(`Input bytes: ${looksArmored ? Buffer.byteLength(rawValue, "utf8") : binaryBytes.length}`);
    if (looksArmored) {
      lines.push(`Armor type: ${getPgpArmorType(rawValue)}`);
    }

    if (structure.kind === "message") {
      if (typeof structure.entity.getEncryptionKeyIDs === "function") {
        const ids = structure.entity.getEncryptionKeyIDs();
        const formatted = Array.isArray(ids)
          ? ids.map(formatOpenPgpKeyId).join(", ")
          : "none";
        lines.push(`Encryption key IDs: ${formatted || "none"}`);
      }
      if (typeof structure.entity.getSigningKeyIDs === "function") {
        const ids = structure.entity.getSigningKeyIDs();
        const formatted = Array.isArray(ids)
          ? ids.map(formatOpenPgpKeyId).join(", ")
          : "none";
        lines.push(`Signing key IDs: ${formatted || "none"}`);
      }
    }

    return lines;
  }

  async function analyzePgpInput() {
    const analysisEl = document.getElementById("crypt-pgp-analysis-preview");
    try {
      const parsed = await parseCurrentPgpInput();
      const lines = buildPgpStructureSummaryLines(parsed);
      if (analysisEl) {
        analysisEl.textContent = lines.join("\n");
      }
      statusUpdate("Status: PGP input analyzed");
      writeLogEntry(`[${threadName}] PGP input analyzed kind=${parsed.structure.kind}`);
    } catch (error) {
      if (analysisEl) {
        analysisEl.textContent = `PGP analysis failed: ${error.message}`;
      }
      logErrorEntry("crypt-pgp-analyze", error);
      doError(getPgpErrorMessage(error, "analysis"));
    }
  }

  async function convertPgpInputToBinaryHex() {
    const analysisEl = document.getElementById("crypt-pgp-analysis-preview");
    const inputEl = document.getElementById("crypt-pgp-input");
    try {
      const parsed = await parseCurrentPgpInput();
      if (!parsed.looksArmored) {
        statusUpdate("Status: PGP input is already binary hex");
        return;
      }

      let binaryBytes = null;
      if (typeof openpgp.unarmor === "function") {
        const unarmored = await openpgp.unarmor(parsed.rawValue);
        if (unarmored?.data) {
          binaryBytes = Buffer.from(unarmored.data);
        }
      }
      if (!binaryBytes && typeof parsed.structure.entity.write === "function") {
        binaryBytes = Buffer.from(await parsed.structure.entity.write());
      }
      if (!binaryBytes) {
        throw new Error("Unable to convert armored PGP input to binary bytes.");
      }

      const binaryHex = binaryBytes.toString("hex");
      if (inputEl) inputEl.value = binaryHex;
      if (analysisEl) {
        analysisEl.textContent = [
          "Converted to binary hex.",
          `Bytes: ${binaryBytes.length}`,
          `Hex chars: ${binaryHex.length}`,
        ].join("\n");
      }
      statusUpdate("Status: Converted PGP ASCII armor to binary hex");
    } catch (error) {
      logErrorEntry("crypt-pgp-convert-to-binary", error);
      doError(getPgpErrorMessage(error, "conversion to binary"));
    }
  }

  function getArmorEnumForKind(kind) {
    if (!openpgp.enums?.armor) return null;
    if (kind === "message") return openpgp.enums.armor.message;
    if (kind === "signature") return openpgp.enums.armor.signature;
    if (kind === "public-key") return openpgp.enums.armor.publicKey;
    if (kind === "private-key") return openpgp.enums.armor.privateKey;
    return null;
  }

  async function convertPgpInputToArmor() {
    const analysisEl = document.getElementById("crypt-pgp-analysis-preview");
    const inputEl = document.getElementById("crypt-pgp-input");
    try {
      const parsed = await parseCurrentPgpInput();
      if (parsed.looksArmored) {
        statusUpdate("Status: PGP input is already ASCII armored");
        return;
      }

      let armoredText = "";
      if (typeof parsed.structure.entity.armor === "function") {
        armoredText = await parsed.structure.entity.armor();
      }
      if (!armoredText && typeof openpgp.armor === "function") {
        const armorType = getArmorEnumForKind(parsed.structure.kind);
        if (armorType !== null) {
          armoredText = await openpgp.armor(
            armorType,
            new Uint8Array(parsed.binaryBytes),
          );
        }
      }
      if (!armoredText) {
        throw new Error("Unable to convert binary PGP data to ASCII armor.");
      }

      if (inputEl) inputEl.value = armoredText;
      if (analysisEl) {
        analysisEl.textContent = [
          "Converted to ASCII armor.",
          `Armor type: ${getPgpArmorType(armoredText)}`,
          `Bytes: ${Buffer.byteLength(armoredText, "utf8")}`,
        ].join("\n");
      }
      statusUpdate("Status: Converted PGP binary hex to ASCII armor");
    } catch (error) {
      logErrorEntry("crypt-pgp-convert-to-armor", error);
      doError(getPgpErrorMessage(error, "conversion to ASCII armor"));
    }
  }

  async function summarizePgpSignatures(signatures) {
    if (!Array.isArray(signatures) || signatures.length === 0) {
      return ["Signature status: no signatures present."];
    }

    const lines = [];
    for (let index = 0; index < signatures.length; index += 1) {
      const signatureEntry = signatures[index];
      let verifiedStatus = "not checked";
      try {
        if (signatureEntry && signatureEntry.verified) {
          await signatureEntry.verified;
          verifiedStatus = "verified";
        }
      } catch (error) {
        verifiedStatus = `failed (${error.message})`;
      }
      const signingKey = signatureEntry?.keyID
        ? formatOpenPgpKeyId(signatureEntry.keyID)
        : "unknown";
      lines.push(
        `Signature ${index + 1}: ${verifiedStatus}; signer key ID: ${signingKey}`,
      );
    }
    return lines;
  }

  function renderPgpOutput(sourceLabel, plainText, detailsLines) {
    const outputEl = document.getElementById("crypt-pgp-output-preview");
    const utf8Value = String(plainText || "");
    const hexValue = Buffer.from(utf8Value, "utf8").toString("hex");
    const printablePreview = utf8Value
      .slice(0, MAX_ASCII_PREVIEW_LENGTH)
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, ".");
    if (outputEl) {
      outputEl.textContent = [
        `Source: ${sourceLabel}`,
        `Bytes: ${Buffer.byteLength(utf8Value, "utf8")}`,
        ...detailsLines,
        "",
        "Decrypted / verified text:",
        printablePreview || "(empty)",
      ].join("\n");
    }
    pgpLastOutputPayload = {
      sourceLabel,
      utf8Value,
      hexValue,
    };
    setPgpSendEnabled(true);
  }

  async function decryptVerifyPgpInput() {
    const privateKeyText = String(
      document.getElementById("crypt-pgp-private-key-input")?.value || "",
    ).trim();
    const publicKeyText = String(
      document.getElementById("crypt-pgp-public-key-input")?.value || "",
    ).trim();
    const passphrase = String(
      document.getElementById("crypt-pgp-passphrase-input")?.value || "",
    );

    try {
      const parsed = await parseCurrentPgpInput();
      const details = [
        `Input format: ${parsed.looksArmored ? "ASCII armor" : "Binary hex"}`,
        `PGP structure: ${parsed.structure.kind}`,
      ];

      if (parsed.structure.kind === "cleartext") {
        const verifyArgs = {
          message: parsed.structure.entity,
        };
        if (publicKeyText) {
          verifyArgs.verificationKeys = [
            await openpgp.readKey({ armoredKey: publicKeyText }),
          ];
        }
        const verifyResult = await openpgp.verify(verifyArgs);
        const signatureLines = await summarizePgpSignatures(
          verifyResult.signatures,
        );
        renderPgpOutput(
          "PGP signed message",
          verifyResult.data,
          [...details, ...signatureLines],
        );
        statusUpdate("Status: Verified PGP signed message");
        return;
      }

      if (parsed.structure.kind !== "message") {
        throw new Error(
          "Decrypt/verify currently supports PGP messages and cleartext signed messages.",
        );
      }

      const decryptArgs = {
        message: parsed.structure.entity,
        format: "utf8",
      };

      if (privateKeyText) {
        let privateKey = await openpgp.readPrivateKey({
          armoredKey: privateKeyText,
        });
        if (passphrase) {
          privateKey = await openpgp.decryptKey({
            privateKey,
            passphrase,
          });
        }
        decryptArgs.decryptionKeys = [privateKey];
      }

      if (publicKeyText) {
        decryptArgs.verificationKeys = [
          await openpgp.readKey({ armoredKey: publicKeyText }),
        ];
      }

      const decryptResult = await openpgp.decrypt(decryptArgs);
      const signatureLines = await summarizePgpSignatures(
        decryptResult.signatures,
      );
      const decryptedText =
        typeof decryptResult.data === "string"
          ? decryptResult.data
          : Buffer.from(decryptResult.data || []).toString("utf8");

      renderPgpOutput(
        "PGP decrypt/verify",
        decryptedText,
        [...details, ...signatureLines],
      );
      if (privateKeyText) {
        await saveSuccessfulPgpKeyMaterial({
          privateKeyText,
          passphrase,
        });
      }
      statusUpdate("Status: PGP decrypt/verify completed");
      writeLogEntry("[Crypt] PGP decrypt/verify completed");
    } catch (error) {
      clearPgpOutput();
      logErrorEntry("crypt-pgp-decrypt-verify", error);
      doError(getPgpErrorMessage(error, "decrypt/verify"));
    }
  }

  function sendPgpOutputToConvTab() {
    if (!pgpLastOutputPayload) {
      statusUpdate("Status: Decrypt/verify output first before sending to Conv");
      return;
    }
    sendDecryptedToConv(pgpLastOutputPayload);
    statusUpdate(
      `Status: Sent PGP output from ${pgpLastOutputPayload.sourceLabel} to Conv`,
    );
    writeLogEntry(
      `[${threadName}] PGP output sent to Conv source="${pgpLastOutputPayload.sourceLabel}"`,
    );
  }

  function getPrivateKeyModulusByteLength(privateKeyPem) {
    try {
      const nativeCryptoApi = getNativeCryptoApi();
      return nativeCryptoApi
        ? nativeCryptoApi.getPrivateKeyModulusByteLength(privateKeyPem)
        : 0;
    } catch (error) {
      logErrorEntry("crypt-key-modulus", error);
      return 0;
    }
  }

  function summarizeHandshakeTypes(payloadBytes) {
    const types = [];
    if (!payloadBytes || payloadBytes.length < 4) return types;
    // Walk the raw payload looking for plausible handshake headers.
    for (let offset = 0; offset + 4 <= payloadBytes.length; offset += 1) {
      const msgType = payloadBytes[offset];
      const msgLength =
        (payloadBytes[offset + 1] << 16) |
        (payloadBytes[offset + 2] << 8) |
        payloadBytes[offset + 3];
      if (msgLength > 0 && msgLength <= payloadBytes.length - offset - 4) {
        if (msgType >= 1 && msgType <= 24) {
          types.push(`${msgType}(${msgLength})`);
          offset += 3 + msgLength;
        }
      }
    }
    return types;
  }

  function extractDecryptCandidates(cipherBytes, privateKeyPem) {
    const candidates = [];
    const seenHex = new Set();
    const modulusLen = getPrivateKeyModulusByteLength(privateKeyPem);
    const knownRsaSizes = [64, 128, 256, 384, 512];
    const rsaSizeCandidates = modulusLen > 0
      ? [...new Set([modulusLen, ...knownRsaSizes])].sort((a, b) => a - b)
      : [...knownRsaSizes];

    const addCandidate = (value) => {
      if (!value || value.length === 0) return;
      const key = Buffer.from(value).toString("hex");
      if (seenHex.has(key)) return;
      seenHex.add(key);
      candidates.push(value);
    };

    // Add exact-modulus slices from a larger buffer. For each known RSA key size,
    // try both the leading block (TLS 1.0/1.1 CKX layout) and trailing block.
    const addModulusAlignedSlices = (buffer) => {
      if (!buffer || buffer.length === 0) return;
      for (const size of rsaSizeCandidates) {
        if (buffer.length < size) continue;
        addCandidate(buffer.subarray(0, size));
        addCandidate(buffer.subarray(buffer.length - size));
      }
    };

    // Scan the whole byte stream for any contiguous block that looks like a
    // PKCS#1 v1.5 or OAEP ciphertext: exactly modulusLen bytes and leading with 0x00.
    const scanRsaBlocks = (buffer) => {
      if (!buffer || buffer.length === 0) return;
      for (const size of rsaSizeCandidates) {
        if (buffer.length < size) continue;
        for (let i = 0; i <= buffer.length - size; i += 1) {
          const block = buffer.subarray(i, i + size);
          if (block[0] === 0x00) {
            addCandidate(block);
          }
        }
      }
    };

    const collectClientKeyExchangeCandidates = (handshakeBytes) => {
      if (!handshakeBytes || handshakeBytes.length < 4) return;
      let offset = 0;
      while (offset + 4 <= handshakeBytes.length) {
        const handshakeType = handshakeBytes[offset];
        const bodyLength =
          (handshakeBytes[offset + 1] << 16) |
          (handshakeBytes[offset + 2] << 8) |
          handshakeBytes[offset + 3];
        const bodyStart = offset + 4;
        const bodyEnd = bodyStart + bodyLength;
        if (bodyLength <= 0 || bodyEnd > handshakeBytes.length) break;
        if (handshakeType === TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE) {
          const handshakeBody = handshakeBytes.subarray(bodyStart, bodyEnd);
          addModulusAlignedSlices(handshakeBody);
          // Some captures include a 1- or 2-byte length prefix before the RSA block.
          if (handshakeBody.length > 2) {
            const encryptedLen = (handshakeBody[0] << 8) | handshakeBody[1];
            if (encryptedLen > 0 && encryptedLen + 2 <= handshakeBody.length) {
              addCandidate(handshakeBody.subarray(2, 2 + encryptedLen));
              addModulusAlignedSlices(handshakeBody.subarray(2, 2 + encryptedLen));
            }
          }
          if (handshakeBody.length > 0) {
            addCandidate(handshakeBody.subarray(1));
            addModulusAlignedSlices(handshakeBody.subarray(1));
          }
        }
        offset = bodyEnd;
        if (handshakeType === TLS_HANDSHAKE_TYPE_FINISHED) {
          break;
        }
      }
    };

    addCandidate(cipherBytes);
    addModulusAlignedSlices(cipherBytes);
    scanRsaBlocks(cipherBytes);

    // Walk raw handshake message framing in the full payload in case the TLS
    // record layer is missing or fragmented.
    if (cipherBytes.length >= 4) {
      let offset = 0;
      while (offset + 4 <= cipherBytes.length) {
        const msgType = cipherBytes[offset];
        const msgLength =
          (cipherBytes[offset + 1] << 16) |
          (cipherBytes[offset + 2] << 8) |
          cipherBytes[offset + 3];
        const msgEnd = offset + 4 + msgLength;
        if (
          msgLength > 0 &&
          msgEnd <= cipherBytes.length &&
          msgType === TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE
        ) {
          const body = cipherBytes.subarray(offset + 4, msgEnd);
          addCandidate(body);
          addModulusAlignedSlices(body);
          scanRsaBlocks(body);
        }
        if (msgEnd <= cipherBytes.length) {
          offset = msgEnd;
        } else {
          break;
        }
      }
    }

    if (cipherBytes.length < 5) {
      return candidates;
    }

    let offset = 0;
    let recordCount = 0;
    while (offset + 5 <= cipherBytes.length && recordCount < 256) {
      const contentType = cipherBytes[offset];
      if (contentType < TLS_CONTENT_TYPE_MIN || contentType > TLS_CONTENT_TYPE_MAX) {
        break;
      }
      const major = cipherBytes[offset + 1];
      const minor = cipherBytes[offset + 2];
      if (major !== 0x03 || minor > 0x04) {
        break;
      }

      const recordLength = (cipherBytes[offset + 3] << 8) | cipherBytes[offset + 4];
      const recordStart = offset + 5;
      const recordEnd = recordStart + recordLength;
      if (recordLength <= 0 || recordEnd > cipherBytes.length) {
        break;
      }

      const recordPayload = cipherBytes.subarray(recordStart, recordEnd);
      addCandidate(recordPayload);
      addModulusAlignedSlices(recordPayload);
      scanRsaBlocks(recordPayload);
      if (contentType === TLS_RECORD_TYPE_HANDSHAKE) {
        collectClientKeyExchangeCandidates(recordPayload);
      }

      offset = recordEnd;
      recordCount += 1;
    }

    return candidates;
  }

  function getNativeCryptoApi() {
    if (
      typeof window === "undefined" ||
      !window.cryptoapi ||
      typeof window.cryptoapi.privateDecrypt !== "function"
    ) {
      return null;
    }
    return window.cryptoapi;
  }

  function getNativeCryptoApiOrThrow(operation) {
    const api = getNativeCryptoApi();
    if (!api) {
      throw new Error(
        `Native crypto bridge required for ${operation} but unavailable.`,
      );
    }
    return api;
  }

  function extractClientRandomFromPayloadBytes(payloadBytes) {
    if (!payloadBytes || payloadBytes.length < 43) return null;

    // First try to locate the start of actual TLS record framing, skipping
    // non-TLS prefixes such as Squid CONNECT headers or other transport bytes.
    const tlsOffset = findTlsRecordOffsetBytes(payloadBytes);
    const scanStart = tlsOffset >= 0 ? tlsOffset : 0;

    // Walk raw handshake framing (no record layer) from the TLS offset.
    let offset = scanStart;
    while (offset + 4 <= payloadBytes.length) {
      const msgType = payloadBytes[offset];
      const msgLength =
        (payloadBytes[offset + 1] << 16) |
        (payloadBytes[offset + 2] << 8) |
        payloadBytes[offset + 3];
      const msgEnd = offset + 4 + msgLength;
      if (
        msgLength > 0 &&
        msgEnd <= payloadBytes.length &&
        msgType === TLS_HANDSHAKE_TYPE_CLIENT_HELLO
      ) {
        const body = payloadBytes.subarray(offset + 4, msgEnd);
        if (body.length >= 39) {
          // client_version(2) + random(32) + session_id_len(1)...
          return body.subarray(2, 34).toString("hex");
        }
      }
      if (msgEnd <= payloadBytes.length) {
        offset = msgEnd;
      } else {
        break;
      }
    }

    // Walk TLS record layer from the located TLS offset.
    offset = scanStart;
    let recordCount = 0;
    while (offset + 5 <= payloadBytes.length && recordCount < 256) {
      const contentType = payloadBytes[offset];
      if (
        contentType < TLS_CONTENT_TYPE_MIN ||
        contentType > TLS_CONTENT_TYPE_MAX
      ) {
        break;
      }
      const major = payloadBytes[offset + 1];
      const minor = payloadBytes[offset + 2];
      if (major !== 0x03 || minor > 0x04) {
        break;
      }
      const recordLength =
        (payloadBytes[offset + 3] << 8) | payloadBytes[offset + 4];
      const recordEnd = offset + 5 + recordLength;
      if (recordLength <= 0 || recordEnd > payloadBytes.length) break;
      const recordPayload = payloadBytes.subarray(offset + 5, recordEnd);
      if (contentType === TLS_RECORD_TYPE_HANDSHAKE) {
        // A handshake record can contain multiple handshake messages.
        let innerOffset = 0;
        while (innerOffset + 4 <= recordPayload.length) {
          const innerType = recordPayload[innerOffset];
          const innerLength =
            (recordPayload[innerOffset + 1] << 16) |
            (recordPayload[innerOffset + 2] << 8) |
            recordPayload[innerOffset + 3];
          const innerEnd = innerOffset + 4 + innerLength;
          if (
            innerLength > 0 &&
            innerEnd <= recordPayload.length &&
            innerType === TLS_HANDSHAKE_TYPE_CLIENT_HELLO
          ) {
            const body = recordPayload.subarray(innerOffset + 4, innerEnd);
            if (body.length >= 38) {
              return body.subarray(2, 34).toString("hex");
            }
          }
          if (innerEnd <= recordPayload.length) {
            innerOffset = innerEnd;
          } else {
            break;
          }
        }
      }
      offset = recordEnd;
      recordCount += 1;
    }

    return null;
  }

  function findCipherSuiteNameFromClientHello(payloadBytes) {
    // Heuristic scan: search ClientHello bytes for a TLS cipher suite
    // then look up its name by known 2-byte identifiers. Returns the
    // first supported suite we recognize, or null.
    if (!payloadBytes || payloadBytes.length < 64) return null;
    const wellKnown = {
      '0x1301': 'TLS_AES_128_GCM_SHA256',
      '0x1302': 'TLS_AES_256_GCM_SHA384',
      '0x1303': 'TLS_CHACHA20_POLY1305_SHA256',
      '0x002f': 'TLS_RSA_WITH_AES_128_CBC_SHA',
      '0x0035': 'TLS_RSA_WITH_AES_256_CBC_SHA',
      '0x003c': 'TLS_RSA_WITH_AES_128_CBC_SHA256',
      '0x003d': 'TLS_RSA_WITH_AES_256_CBC_SHA256',
      '0xc02f': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
      '0xc02b': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
      '0xc030': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
      '0xc02c': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    };
    for (let i = 0; i + 1 < payloadBytes.length; i += 1) {
      const key = `0x${payloadBytes[i].toString(16).padStart(2, '0')}${payloadBytes[i + 1].toString(16).padStart(2, '0')}`;
      const name = wellKnown[key.toLowerCase()];
      if (name) return name;
    }
    return null;
  }

  function findFirstServerHelloRecordBytes(payloadBytes) {
    if (!payloadBytes || payloadBytes.length < 5) return null;
    let offset = 0;
    let recordCount = 0;
    while (offset + 5 <= payloadBytes.length && recordCount < 256) {
      const contentType = payloadBytes[offset];
      if (contentType < TLS_CONTENT_TYPE_MIN || contentType > TLS_CONTENT_TYPE_MAX) {
        break;
      }
      const major = payloadBytes[offset + 1];
      const minor = payloadBytes[offset + 2];
      if (major !== 0x03 || minor > 0x04) break;
      const recordLength = (payloadBytes[offset + 3] << 8) | payloadBytes[offset + 4];
      const recordEnd = offset + 5 + recordLength;
      if (recordLength <= 0 || recordEnd > payloadBytes.length) break;
      const recordPayload = payloadBytes.subarray(offset + 5, recordEnd);
      if (contentType === TLS_RECORD_TYPE_HANDSHAKE &&
        recordPayload.length > 0 &&
        recordPayload[0] === TLS_HANDSHAKE_TYPE_SERVER_HELLO) {
        return { recordPayload, offset };
      }
      offset = recordEnd;
      recordCount += 1;
    }
    return null;
  }

  function parseServerHelloCipherSuite(serverHelloBytes) {
    if (!serverHelloBytes || serverHelloBytes.length < 38) return null;
    let offset = 0; // handshake_type already stripped by caller
    if (serverHelloBytes[offset] === TLS_HANDSHAKE_TYPE_SERVER_HELLO) {
      offset += 1; // skip handshake type
    }
    offset += 3; // skip handshake length
    offset += 2; // server_version
    offset += 32; // server_random
    const sessionIdLen = serverHelloBytes[offset] ?? 0;
    offset += 1 + sessionIdLen;
    if (offset + 2 > serverHelloBytes.length) return null;
    const suiteId = serverHelloBytes.subarray(offset, offset + 2);
    const key = `0x${suiteId[0].toString(16).padStart(2, '0')}${suiteId[1].toString(16).padStart(2, '0')}`;
    const wellKnown = {
      '0x1301': 'TLS_AES_128_GCM_SHA256',
      '0x1302': 'TLS_AES_256_GCM_SHA384',
      '0x1303': 'TLS_CHACHA20_POLY1305_SHA256',
      '0x002f': 'TLS_RSA_WITH_AES_128_CBC_SHA',
      '0x0035': 'TLS_RSA_WITH_AES_256_CBC_SHA',
      '0x003c': 'TLS_RSA_WITH_AES_128_CBC_SHA256',
      '0x003d': 'TLS_RSA_WITH_AES_256_CBC_SHA256',
      '0xc02f': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
      '0xc02b': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
      '0xc030': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
      '0xc02c': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    };
    return wellKnown[key.toLowerCase()] || null;
  }

  function deriveKeysTls12(
    masterSecretHex,
    cipherSuite,
    serverRandomHex,
    clientRandomHex,
  ) {
    const api = getNativeCryptoApiOrThrow("TLS 1.2 key derivation");
    const suite = TLS_CIPHER_SUITES[cipherSuite];
    if (!suite) {
      throw new Error(`Unsupported TLS 1.2 cipher suite: ${cipherSuite}`);
    }
    if (cipherSuite.includes("_EXPORT")) {
      throw new Error(
        `Export TLS 1.2 cipher suites are not supported: ${cipherSuite}`,
      );
    }
    const macLen =
      suite.hash === "sha384" ? 48 : suite.hash === "sha256" ? 32 : 20;
    const seed = `${clientRandomHex}${serverRandomHex}`;
    const keyBlockLen = 2 * macLen + 2 * suite.keyLen + 2 * suite.ivLen;
    const prfHash = suite.hash === "sha384" ? "sha384" : "sha256";
    const keyBlockHex = api.tlsPrf(masterSecretHex, "key expansion", seed, keyBlockLen);
    const keyBlock = Buffer.from(keyBlockHex, "hex");
    let pos = 0;
    const clientMacKey = keyBlock.subarray(pos, pos + macLen).toString("hex");
    pos += macLen;
    const serverMacKey = keyBlock.subarray(pos, pos + macLen).toString("hex");
    pos += macLen;
    const clientKey = keyBlock
      .subarray(pos, pos + suite.keyLen)
      .toString("hex");
    pos += suite.keyLen;
    const serverKey = keyBlock.subarray(pos, pos + suite.keyLen).toString("hex");
    pos += suite.keyLen;
    const clientIv = keyBlock.subarray(pos, pos + suite.ivLen).toString("hex");
    pos += suite.ivLen;
    const serverIv = keyBlock.subarray(pos, pos + suite.ivLen).toString("hex");
    return {
      clientMacKey,
      serverMacKey,
      clientKey,
      serverKey,
      clientIv,
      serverIv,
      aead: suite.aead,
      keyLen: suite.keyLen,
      ivLen: suite.ivLen,
      macLen,
      hash: suite.hash,
    };
  }

  function deriveKeysTls13(secretHex, cipherSuite, isServer) {
    const api = getNativeCryptoApiOrThrow("TLS 1.3 key derivation");
    const suite = TLS_CIPHER_SUITES[cipherSuite];
    if (!suite || !suite.isTls13) {
      throw new Error(`Unsupported TLS 1.3 cipher suite: ${cipherSuite}`);
    }
    const hkdf =
      suite.hash === "sha384"
        ? (secret, salt, info, len) =>
          api.hkdfSha384(
            secret,
            salt,
            buildTls13HkdfInfo(info, len),
            len,
          )
        : (secret, salt, info, len) =>
          api.hkdfSha256(
            secret,
            salt,
            buildTls13HkdfInfo(info, len),
            len,
          );
    const key = hkdf(secretHex, "", "tls13 key", suite.keyLen);
    const iv = hkdf(secretHex, "", "tls13 iv", suite.ivLen);
    return { key, iv, aead: suite.aead, keyLen: suite.keyLen, ivLen: suite.ivLen };
  }

  function buildTls13HkdfInfo(label, length) {
    const labelBytes = Buffer.from(label, "ascii");
    const info = Buffer.alloc(2 + 1 + labelBytes.length + 1);
    info.writeUInt16BE(length, 0);
    info[2] = labelBytes.length;
    labelBytes.copy(info, 3);
    info[3 + labelBytes.length] = 0;
    return info.toString("hex");
  }

  function decryptTls12ApplicationDataRecord(payloadBytes, offset, keys) {
    const api = getNativeCryptoApiOrThrow("TLS 1.2 record decryption");
    const contentType = payloadBytes[offset];
    const recordLength = (payloadBytes[offset + 3] << 8) | payloadBytes[offset + 4];
    const recordStart = offset + 5;
    const recordEnd = recordStart + recordLength;
    if (recordEnd > payloadBytes.length) {
      throw new Error("TLS 1.2 record extends past payload");
    }
    const ivLen = keys.aead.includes('gcm') ? 0 : (keys.ivLen || 16);
    const explicitNonceLength = keys.aead.includes('gcm') ? 8 : 0;
    const iv = keys.aead.includes('gcm')
      ? Buffer.concat([
        Buffer.from(keys.serverIv, 'hex'),
        payloadBytes.subarray(recordStart, recordStart + explicitNonceLength),
      ]).toString('hex')
      : payloadBytes.subarray(recordStart, recordStart + ivLen).toString('hex');
    const cipherStart = recordStart + explicitNonceLength + ivLen;
    const authTagLength = keys.aead.includes('gcm') ? 16 : 0;
    if (keys.aead.includes('gcm') && recordEnd - cipherStart < authTagLength) {
      throw new Error("TLS 1.2 AEAD record too short for auth tag");
    }
    const cipherEnd = keys.aead.includes('gcm')
      ? recordEnd - authTagLength
      : recordEnd;
    const aadHex = payloadBytes.subarray(offset, recordStart).toString('hex');
    const cipherHex = payloadBytes.subarray(cipherStart, cipherEnd).toString('hex');
    const tagHex = keys.aead.includes('gcm')
      ? payloadBytes.subarray(cipherEnd, recordEnd).toString('hex')
      : '';
    if (keys.aead.includes('gcm')) {
      const plaintextHex = api.decryptAesGcm(
        keys.serverKey,
        iv,
        aadHex,
        cipherHex,
        tagHex,
      );
      const plaintext = Buffer.from(plaintextHex, 'hex');
      // TLS 1.2 AEAD plaintext is content || content_type || padding.
      let padIndex = plaintext.length - 1;
      while (padIndex >= 0 && plaintext[padIndex] === 0) {
        padIndex -= 1;
      }
      const data = padIndex > 0 ? plaintext.subarray(0, padIndex) : Buffer.alloc(0);
      return { plaintext: data, offset: recordEnd, contentType };
    }
    // CBC: remove both MAC and padding; MAC verification is skipped for offline preview.
    const plaintextHex = api.decryptAesCbc(keys.serverKey, iv, cipherHex);
    const plaintext = Buffer.from(plaintextHex, 'hex');
    const macLen = keys.macLen || (keys.hash === 'sha256' ? 32 : keys.hash === 'sha384' ? 48 : 20);
    let padLen = 0;
    if (plaintext.length > 0) {
      padLen = plaintext[plaintext.length - 1];
    }
    const contentEnd =
      padLen > 0 && padLen <= plaintext.length
        ? plaintext.length - 1 - padLen - macLen
        : plaintext.length - macLen;
    const inner =
      contentEnd > 0 ? plaintext.subarray(0, contentEnd) : Buffer.alloc(0);
    return { plaintext: inner, offset: recordEnd, contentType };
  }

  function tryDecryptTlsWithKeyLog(payloadBytes, privateKeyPem, activeEntry) {
    const api = getNativeCryptoApiOrThrow("TLS key-log decryption");
    if (!cryptKeyLogEntries.length) {
      return null;
    }

    const tlsOffset = findTlsRecordOffsetBytes(payloadBytes);
    const scanBytes = tlsOffset > 0 ? payloadBytes.subarray(tlsOffset) : payloadBytes;
    let clientRandom = extractClientRandomFromPayloadBytes(scanBytes);
    writeLogEntry(
      `[Crypt] key-log scan tlsOffset=${tlsOffset} payloadLen=${payloadBytes.length} scanLen=${scanBytes.length} clientRandom=${clientRandom ? `${clientRandom.slice(0, 16)}...` : "not-found"}`,
    );

    // If the selected packet is just Application Data, try to find the
    // ClientHello in other packets for the same host and infer client_random.
    if (!clientRandom && activeEntry?.host) {
      clientRandom = findClientRandomFromHostPackets(activeEntry);
      if (clientRandom) {
        writeLogEntry(
          `[Crypt] Resolved client_random=${clientRandom.slice(0, 16)}... from another packet on the same host.`,
        );
      }
    }

    if (!clientRandom) {
      writeLogEntry(
        "[Crypt] Could not locate ClientHello client_random in selected payload; key-log decryption cannot proceed.",
      );
      return null;
    }
    writeLogEntry(
      `[Crypt] Extracted client_random=${clientRandom.slice(0, 16)}... from payload; searching key log.`,
    );

    // For TLS 1.3, try traffic secrets first.
    const tls13TrafficLabels = [
      'SERVER_TRAFFIC_SECRET_0',
      'CLIENT_TRAFFIC_SECRET_0',
      'SERVER_HANDSHAKE_TRAFFIC_SECRET',
      'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
    ];
    for (const label of tls13TrafficLabels) {
      const match = cryptKeyLogEntries.find(
        (e) => e.label === label && e.clientRandom === clientRandom,
      );
      if (!match) continue;
      let cipherSuite = parseServerHelloCipherSuite(
        findFirstServerHelloRecordBytes(scanBytes)?.recordPayload,
      );
      if (!cipherSuite) {
        cipherSuite = findCipherSuiteNameFromClientHello(scanBytes);
      }
      if (!cipherSuite || !TLS_CIPHER_SUITES[cipherSuite]?.isTls13) {
        writeLogEntry(`[Crypt] TLS 1.3 traffic secret found but cipher suite not recognized; skipped ${label}.`);
        continue;
      }
      const isServer = label.startsWith('SERVER_');
      const keys = deriveKeysTls13(match.secretHex, cipherSuite, isServer);
      const decrypted = tryDecryptApplicationRecordsTls13(scanBytes, keys);
      if (decrypted && decrypted.length) {
        writeLogEntry(`[Crypt] Decrypted TLS 1.3 application data with ${label} (${cipherSuite}).`);
        return decrypted;
      }
    }

    // TLS 1.2: look up CLIENT_RANDOM master secret.
    const clientRandomMatch = cryptKeyLogEntries.find(
      (e) => e.label === NSS_KEY_LOG_LABEL_CLIENT_RANDOM && e.clientRandom === clientRandom,
    );
    if (!clientRandomMatch) {
      writeLogEntry(`[Crypt] No CLIENT_RANDOM master secret found in key log for this session.`);
      return null;
    }
    const serverHelloInfo = findFirstServerHelloRecordBytes(scanBytes);
    let cipherSuite = parseServerHelloCipherSuite(serverHelloInfo?.recordPayload);
    if (!cipherSuite) {
      cipherSuite = findCipherSuiteNameFromClientHello(scanBytes);
    }
    if (!cipherSuite) {
      writeLogEntry('[Crypt] Could not determine cipher suite for TLS 1.2 key-log decryption.');
      return null;
    }
    if (TLS_CIPHER_SUITES[cipherSuite]?.isTls13) {
      writeLogEntry('[Crypt] Selected cipher suite appears to be TLS 1.3, but no TLS 1.3 traffic secret found for this session.');
      return null;
    }
    const serverRandom = serverHelloInfo?.recordPayload
      ? extractServerRandomFromServerHello(serverHelloInfo.recordPayload)
      : null;
    const clientRandomHex = clientRandom;
    const serverRandomHex = serverRandom || '';
    const keys = deriveKeysTls12(
      clientRandomMatch.secretHex,
      cipherSuite,
      serverRandomHex,
      clientRandomHex,
    );
    const decrypted = tryDecryptApplicationRecordsTls12(scanBytes, keys);
    if (decrypted && decrypted.length) {
      writeLogEntry(`[Crypt] Decrypted TLS 1.2 application data with CLIENT_RANDOM (${cipherSuite}).`);
      return decrypted;
    }
    return null;
  }

  function findClientRandomFromHostPackets(entry) {
    const hostMap = getHostPacketMap(getCapturedPackets());
    if (!hostMap || typeof hostMap !== "object") return null;

    // The selected packet may not carry the ClientHello (e.g. a tiny TLS
    // alert/ACK). Build a list of candidate packet arrays to search, starting
    // with the same host, then any host that shares this endpoint IP.
    const candidateArrays = [];
    const hostsTried = [];
    if (entry?.host && Array.isArray(hostMap[entry.host])) {
      candidateArrays.push(hostMap[entry.host]);
      hostsTried.push(entry.host);
    }
    const endpointIps = new Set([
      entry?.srcIp,
      entry?.dstIp,
    ].filter(Boolean));
    for (const host of Object.keys(hostMap)) {
      if (hostsTried.includes(host)) continue;
      if (endpointIps.has(host) || host.split(/[:\s]/).some((part) => endpointIps.has(part))) {
        candidateArrays.push(hostMap[host]);
        hostsTried.push(host);
      }
    }
    if (candidateArrays.length === 0) return null;

    const normalizeIp = (ip) => String(ip || "").trim().toLowerCase();
    const normalizePort = (port) => String(port || "").trim();
    const entrySrcIp = normalizeIp(entry?.srcIp);
    const entryDstIp = normalizeIp(entry?.dstIp);
    const entrySrcPort = normalizePort(entry?.srcPort);
    const entryDstPort = normalizePort(entry?.dstPort);

    // First pass: only consider packets on the exact same 5-tuple stream.
    let scanned = 0;
    for (const packets of candidateArrays) {
      for (const packet of packets) {
        const packetInfo = getPacketInfo(packet);
        if (!packetInfo) continue;
        const protocol = packetInfo["Protocol"] || packetInfo["packet.proto"] || "Unknown";
        const transportData = getTransportData(packetInfo, protocol);
        const srcPort = normalizePort(transportData?.["Source port"] ?? transportData?.["source.port"]);
        const dstPort = normalizePort(transportData?.["Destination port"] ?? transportData?.["destination.port"]);
        const srcIp = normalizeIp(packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"]);
        const dstIp = normalizeIp(packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"]);
        const sameStream =
          (srcIp === entrySrcIp && dstIp === entryDstIp && srcPort === entrySrcPort && dstPort === entryDstPort) ||
          (srcIp === entryDstIp && dstIp === entrySrcIp && srcPort === entryDstPort && dstPort === entrySrcPort);
        if (!sameStream) continue;
        const payloadHex = getPacketPayloadHex(packet);
        if (!payloadHex) continue;
        const payloadBytes = Buffer.from(normalizeHexString(payloadHex), "hex");
        scanned += 1;
        const tlsOffset = findTlsRecordOffsetBytes(payloadBytes);
        const scanBytes = tlsOffset > 0 ? payloadBytes.subarray(tlsOffset) : payloadBytes;
        const clientRandom = extractClientRandomFromPayloadBytes(scanBytes);
        if (clientRandom) {
          writeLogEntry(`[Crypt] Resolved client_random=${clientRandom.slice(0, 16)}... from same-stream packet #${packetInfo?.["Index"] ?? packetInfo?.["packet.processed"] ?? "?"} (scanned ${scanned}).`);
          return clientRandom;
        }
      }
    }

    // Second pass: relax stream matching and search every packet on the
    // candidate hosts for any ClientHello. This handles captures where the
    // host map key or endpoint metadata differs from the selected entry.
    scanned = 0;
    for (const packets of candidateArrays) {
      for (const packet of packets) {
        const packetInfo = getPacketInfo(packet);
        if (!packetInfo) continue;
        const payloadHex = getPacketPayloadHex(packet);
        if (!payloadHex) continue;
        const payloadBytes = Buffer.from(normalizeHexString(payloadHex), "hex");
        scanned += 1;
        const tlsOffset = findTlsRecordOffsetBytes(payloadBytes);
        const scanBytes = tlsOffset > 0 ? payloadBytes.subarray(tlsOffset) : payloadBytes;
        const clientRandom = extractClientRandomFromPayloadBytes(scanBytes);
        if (clientRandom) {
          writeLogEntry(`[Crypt] Resolved client_random=${clientRandom.slice(0, 16)}... from relaxed host search packet #${packetInfo?.["Index"] ?? packetInfo?.["packet.processed"] ?? "?"} (scanned ${scanned}).`);
          return clientRandom;
        }
      }
    }

    writeLogEntry(`[Crypt] ClientHello not found in ${scanned} candidate packets across ${candidateArrays.length} host(s).`);
    return null;
  }

  function extractServerRandomFromServerHello(serverHelloBytes) {
    if (!serverHelloBytes || serverHelloBytes.length < 38) return null;
    let offset = 0;
    if (serverHelloBytes[offset] === TLS_HANDSHAKE_TYPE_SERVER_HELLO) offset += 1;
    offset += 3; // handshake length
    offset += 2; // server_version
    if (serverHelloBytes.length < offset + 32) return null;
    return serverHelloBytes.subarray(offset, offset + 32).toString('hex');
  }

  function tryDecryptApplicationRecordsTls12(payloadBytes, keys) {
    const records = [];
    let offset = 0;
    let recordCount = 0;
    while (offset + 5 <= payloadBytes.length && recordCount < 512) {
      const contentType = payloadBytes[offset];
      if (contentType < TLS_CONTENT_TYPE_MIN || contentType > TLS_CONTENT_TYPE_MAX) {
        break;
      }
      const major = payloadBytes[offset + 1];
      const minor = payloadBytes[offset + 2];
      if (major !== 0x03 || minor > 0x04) break;
      const recordLength = (payloadBytes[offset + 3] << 8) | payloadBytes[offset + 4];
      const recordEnd = offset + 5 + recordLength;
      if (recordLength <= 0 || recordEnd > payloadBytes.length) break;
      if (contentType === TLS_RECORD_TYPE_APPLICATION_DATA) {
        try {
          const result = decryptTls12ApplicationDataRecord(payloadBytes, offset, keys);
          if (result.plaintext && result.plaintext.length) {
            records.push(result.plaintext);
          }
        } catch (_) {
          // ignore record failures and keep scanning
        }
      }
      offset = recordEnd;
      recordCount += 1;
    }
    if (records.length === 0) return null;
    return Buffer.concat(records);
  }

  function tryDecryptApplicationRecordsTls13(payloadBytes, keys) {
    const api = getNativeCryptoApiOrThrow("TLS 1.3 record decryption");
    const records = [];
    let offset = 0;
    let recordCount = 0;
    let seq = 0;
    const MAX_SEQ_TRIES = 64;
    while (offset + 5 <= payloadBytes.length && recordCount < 512) {
      const contentType = payloadBytes[offset];
      if (contentType < TLS_CONTENT_TYPE_MIN || contentType > TLS_CONTENT_TYPE_MAX) {
        break;
      }
      const major = payloadBytes[offset + 1];
      const minor = payloadBytes[offset + 2];
      if (major !== 0x03 || minor > 0x04) {
        break;
      }
      const recordLength = (payloadBytes[offset + 3] << 8) | payloadBytes[offset + 4];
      const recordEnd = offset + 5 + recordLength;
      if (recordLength <= 0 || recordEnd > payloadBytes.length) break;
      if (contentType === TLS_RECORD_TYPE_APPLICATION_DATA) {
        let decryptedRecord = null;
        let successSeq = null;
        const tagLen = 16;
        if (recordEnd - (offset + 5) >= tagLen) {
          const cipherStart = offset + 5;
          const cipherEnd = recordEnd - tagLen;
          const aadHex = payloadBytes.subarray(offset, cipherStart).toString('hex');
          const cipherHex = payloadBytes.subarray(cipherStart, cipherEnd).toString('hex');
          const tagHex = payloadBytes.subarray(cipherEnd, recordEnd).toString('hex');
          for (let seqTry = seq; seqTry < seq + MAX_SEQ_TRIES; seqTry += 1) {
            try {
              const nonce = Buffer.from(keys.iv, 'hex');
              const seqBytes = Buffer.alloc(8);
              seqBytes.writeBigUInt64BE(BigInt(seqTry), 0);
              for (let i = 0; i < 8; i += 1) {
                nonce[nonce.length - 8 + i] ^= seqBytes[i];
              }
              const plaintextHex = api.decryptAesGcm(
                keys.key,
                nonce.toString('hex'),
                aadHex,
                cipherHex,
                tagHex,
              );
              const inner = Buffer.from(plaintextHex, 'hex');
              let padIndex = inner.length - 1;
              while (padIndex >= 0 && inner[padIndex] === 0) {
                padIndex -= 1;
              }
              const innerType = padIndex >= 0 ? inner[padIndex] : 0;
              const data = padIndex > 0 ? inner.subarray(0, padIndex) : Buffer.alloc(0);
              if (
                (innerType === TLS_RECORD_TYPE_APPLICATION_DATA ||
                  innerType === TLS_RECORD_TYPE_HANDSHAKE) &&
                data.length > 0
              ) {
                decryptedRecord = data;
                successSeq = seqTry;
                break;
              }
            } catch (_) {
              // try next sequence number
            }
          }
        }
        if (decryptedRecord) {
          records.push(decryptedRecord);
          seq = successSeq + 1;
        } else {
          seq += 1;
        }
        offset = recordEnd;
        recordCount += 1;
        continue;
      }
      offset = recordEnd;
      recordCount += 1;
    }
    if (records.length === 0) return null;
    return Buffer.concat(records);
  }

  function decryptTlsCipherBytes(cipherBytes, privateKeyPem, activeEntry) {
    // Prefer NSS/SSL key log decryption whenever a key log has been loaded.
    const keyLogResult = tryDecryptTlsWithKeyLog(
      cipherBytes,
      privateKeyPem,
      activeEntry,
    );
    if (keyLogResult) {
      return keyLogResult;
    }

    const normalizedKey = String(privateKeyPem || "").trim();
    if (!normalizedKey) {
      // No private key loaded; if a key log was loaded we already tried it above.
      if (cryptKeyLogEntries.length) {
        throw new Error(
          "No TLS decrypt attempt succeeded with the loaded key log for this session.",
        );
      }
      throw new Error("No private key or TLS key log loaded.");
    }

    const candidates = extractDecryptCandidates(cipherBytes, normalizedKey);
    const modulusLen = getPrivateKeyModulusByteLength(privateKeyPem);
    const candidateLengths = candidates.map((c) => c.length);
    const handshakeTypes = summarizeHandshakeTypes(cipherBytes);
    const hasClientKeyExchange = handshakeTypes.some((s) =>
      s.startsWith(`${TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE}(`),
    );
    writeLogEntry(
      `[Crypt] decryptTlsCipherBytes keyLogTried modulusLen=${modulusLen} candidates=${candidates.length} lengths=${candidateLengths.slice(0, 20).join(",")}${candidateLengths.length > 20 ? "..." : ""} handshakes=${handshakeTypes.slice(0, 10).join(",")} clientKeyExchange=${hasClientKeyExchange ? "yes" : "no"}`,
    );
    if (!hasClientKeyExchange && handshakeTypes.length > 0) {
      writeLogEntry(
        `[Crypt] No ClientKeyExchange (type ${TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE}) found in selected payload; this handshake likely uses ECDHE/DHE, which cannot be decrypted with an RSA private key.`,
      );
    }
    const nativeCryptoApi = getNativeCryptoApi();

    if (nativeCryptoApi) {
      const constants = nativeCryptoApi.getRsaConstants();
      const decryptVariants = [
        {
          name: "RSA-OAEP-SHA256",
          options: {
            padding: constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
          },
        },
        {
          name: "RSA-PKCS1-v1_5",
          options: { padding: constants.RSA_PKCS1_PADDING },
        },
      ];
      const failures = [];
      for (const candidate of candidates) {
        for (const variant of decryptVariants) {
          try {
            const decryptedHex = nativeCryptoApi.privateDecrypt(
              normalizedKey,
              candidate.toString("hex"),
              variant.options,
            );
            return Buffer.from(decryptedHex, "hex");
          } catch (error) {
            failures.push(`${variant.name} (${candidate.length} bytes): ${error.message}`);
          }
        }
      }
      const failurePreview = [...new Set(failures)]
        .slice(0, MAX_DECRYPT_FAILURE_MESSAGES)
        .join("; ");
      throw new Error(
        `No TLS decrypt attempt succeeded with the loaded key (${failurePreview})`,
      );
    }

    // Fallback for non-Electron browser contexts where the native bridge is unavailable.
    const decryptVariants = [
      {
        name: "RSA-OAEP-SHA256",
        options: {
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256",
        },
      },
      {
        name: "RSA-PKCS1-v1_5",
        options: { padding: crypto.constants.RSA_PKCS1_PADDING },
      },
    ];
    const failures = [];
    for (const candidate of candidates) {
      for (const variant of decryptVariants) {
        try {
          const decrypted = crypto.privateDecrypt(
            {
              key: normalizedKey,
              ...variant.options,
            },
            candidate,
          );
          return decrypted;
        } catch (error) {
          failures.push(`${variant.name}: ${error.message}`);
        }
      }
    }
    const failurePreview = [...new Set(failures)]
      .slice(0, MAX_DECRYPT_FAILURE_MESSAGES)
      .join("; ");
    throw new Error(
      `No TLS decrypt attempt succeeded with the loaded key (${failurePreview})`,
    );
  }

  function certMatchesPrivateKey(certificatePem, privateKeyPem) {
    const normalizedCert = String(certificatePem || "").trim();
    if (!normalizedCert) return { matched: true };

    const certKind = getKeyObjectKind(normalizedCert);
    const keyKind = getKeyObjectKind(privateKeyPem);
    writeLogEntry(
      `[Crypt] cert/key kind check certKind="${certKind}" keyKind="${keyKind}"`,
    );

    const nativeCryptoApi = getNativeCryptoApi();
    if (nativeCryptoApi) {
      try {
        const certPublicKeyPem =
          nativeCryptoApi.getPublicKeyFromCertificatePem(normalizedCert);
        let privateKeyPublicPem = null;
        try {
          privateKeyPublicPem =
            nativeCryptoApi.getPublicKeyFromPrivateKeyPem(privateKeyPem);
        } catch (keyError) {
          // If the loaded key cannot yield a public key (e.g. encrypted/malformed),
          // skip the comparison rather than failing decryption later.
          logErrorEntry(
            "crypt-cert-key-check",
            new Error(
              `Private key parse failed; PEM kind=${keyKind}, original=${keyError.message}`,
            ),
          );
          return {
            matched: null,
            reason: `Key parse failed (kind=${keyKind}); certificate/key validation skipped.`,
          };
        }
        return { matched: certPublicKeyPem === privateKeyPublicPem };
      } catch (error) {
        logErrorEntry("crypt-cert-key-check", error);
        return {
          matched: null,
          reason: "Certificate/key pair validation failed and was skipped.",
        };
      }
    }

    if (
      typeof crypto.X509Certificate !== "function" ||
      typeof crypto.createPublicKey !== "function"
    ) {
      return {
        matched: null,
        reason:
          "Certificate/key pair validation is unavailable in this runtime.",
      };
    }
    try {
      const certPublicKeyPem = crypto
        .createPublicKey(new crypto.X509Certificate(normalizedCert).publicKey)
        .export({ type: "spki", format: "pem" })
        .toString();
      const privateKeyPublicPem = crypto
        .createPublicKey(privateKeyPem)
        .export({ type: "spki", format: "pem" })
        .toString();
      return { matched: certPublicKeyPem === privateKeyPublicPem };
    } catch (error) {
      logErrorEntry("crypt-cert-key-check", error);
      return {
        matched: null,
        reason: "Certificate/key pair validation failed and was skipped.",
      };
    }
  }

  function renderDecryptedPayload(entry, decryptedBytes) {
    const decryptPreviewEl = document.getElementById("crypt-decrypt-preview");
    const decryptedHex = decryptedBytes.toString("hex");
    const decryptedUtf8 = decryptedBytes.toString("utf8");
    const looksPrintable = PRINTABLE_UTF8_PREVIEW_REGEX.test(decryptedUtf8);
    const asciiSummary = looksPrintable
      ? decryptedUtf8.slice(0, MAX_ASCII_PREVIEW_LENGTH)
      : decryptedUtf8
        .slice(0, MAX_ASCII_PREVIEW_LENGTH)
        .replace(/[^\x09\x0A\x0D\x20-\x7E]/g, ".");
    decryptPreviewEl.textContent = [
      `Decrypted payload for packet #${entry.packetIndex}`,
      `Bytes: ${decryptedBytes.length}`,
      "",
      "ASCII / UTF-8 preview:",
      asciiSummary || "(no printable output)",
      "",
      "Hex:",
      decryptedHex || "(empty)",
    ].join("\n");
    cryptLastDecryptedPayload = {
      sourceLabel: `packet #${entry.packetIndex}`,
      hexValue: decryptedHex,
      utf8Value: decryptedUtf8,
    };
    setDecryptSendEnabled(true);
  }

  function setCryptSubtab(tabName) {
    setActiveCryptSubtab(tabName);
    const hashesActive = tabName === CRYPT_HASHES_SUBTAB;
    const sslActive = tabName === CRYPT_SSL_SUBTAB;
    const pgpActive = tabName === CRYPT_PGP_SUBTAB;
    const opensshActive = tabName === CRYPT_OPENSSH_SUBTAB;
    const wifiActive = tabName === CRYPT_WIFI_SUBTAB;
    document
      .getElementById("crypt-subtab-hashes")
      .classList.toggle("active", hashesActive);
    document
      .getElementById("crypt-subtab-ssl")
      .classList.toggle("active", sslActive);
    document
      .getElementById("crypt-subtab-pgp")
      .classList.toggle("active", pgpActive);
    document
      .getElementById("crypt-subtab-openssh")
      .classList.toggle("active", opensshActive);
    document
      .getElementById("crypt-subtab-wifi")
      .classList.toggle("active", wifiActive);
    document.getElementById("crypt-hashes-panel").hidden = !hashesActive;
    document.getElementById("crypt-ssl-panel").hidden = !sslActive;
    document.getElementById("crypt-pgp-panel").hidden = !pgpActive;
    document.getElementById("crypt-openssh-panel").hidden = !opensshActive;
    document.getElementById("crypt-wifi-panel").hidden = !wifiActive;
    if (pgpActive) {
      refreshPgpEncounteredEntries();
      refreshPgpPrivateKeyCandidates();
      refreshPgpPassphraseCandidates();
    }
    if (wifiActive) {
      refreshWifiEncounteredEntries();
      refreshWifiKeystoreEntries();
    }
    if (opensshActive) {
      refreshSshEncounteredFlows();
    }
  }

  // ---------------------------------------------------------------------------
  // Wireless (IEEE 802.11) subtab
  // ---------------------------------------------------------------------------

  function normalizeWifiBssidString(value) {
    if (!value) return "";
    const cleaned = String(value)
      .trim()
      .toLowerCase()
      .replace(/[^0-9a-f]/g, "");
    if (cleaned.length !== 12) return "";
    const pairs = [];
    for (let i = 0; i < 12; i += 2) {
      pairs.push(cleaned.slice(i, i + 2));
    }
    return pairs.join(":");
  }

  function getWifiSection(packetInfo) {
    if (!packetInfo || typeof packetInfo !== "object") return null;
    const direct = packetInfo["Wireless"] || packetInfo["wireless"];
    return direct && typeof direct === "object" ? direct : null;
  }

  function isWifiPacket(packetInfo) {
    if (!packetInfo || typeof packetInfo !== "object") return false;
    const proto = packetInfo["packet.proto"] || packetInfo["Protocol"];
    if (typeof proto === "string" && proto.toUpperCase() === "WIFI") return true;
    if (
      typeof packetInfo["link.proto"] === "string" &&
      packetInfo["link.proto"].toLowerCase().includes("802.11")
    ) {
      return true;
    }
    return getWifiSection(packetInfo) !== null;
  }

  function getWifiEncounteredEntries() {
    const entries = [];
    const capturedPackets = getCapturedPackets();
    const hostMap = getHostPacketMap(capturedPackets);
    if (!hostMap) return entries;

    for (const host of Object.keys(hostMap)) {
      const packets = hostMap[host];
      if (!Array.isArray(packets)) continue;
      packets.forEach((packet, packetOffset) => {
        const packetInfo = getPacketInfo(packet);
        if (!isWifiPacket(packetInfo)) return;
        const wifi = getWifiSection(packetInfo) || {};
        const packetIndex =
          packetInfo["Index"] ?? packetInfo["packet.processed"] ?? packetOffset;
        entries.push({
          host,
          packetIndex,
          packet,
          ssid: wifi["wifi.ssid"] ?? wifi["ssid"] ?? "",
          bssid: wifi["wifi.bssid"] ?? wifi["bssid"] ?? "",
          channel: wifi["wifi.channel"] ?? wifi["channel"] ?? "",
          type: wifi["wifi.type"] ?? wifi["type"] ?? "",
          subtype: wifi["wifi.subtype"] ?? wifi["subtype"] ?? "",
          cipher: wifi["wifi.cipher"] ?? wifi["cipher"] ?? "",
          crypto: wifi["wifi.crypto"] ?? wifi["crypto"] ?? "",
          decryptOk: wifi["wifi.decrypt.ok"] === true,
          decryptAlgorithm: wifi["wifi.decrypt.algorithm"] || "",
          linkProto: packetInfo["link.proto"] || "IEEE 802.11",
        });
      });
    }

    return entries.sort((a, b) => {
      const aIdx = Number(a.packetIndex);
      const bIdx = Number(b.packetIndex);
      if (Number.isFinite(aIdx) && Number.isFinite(bIdx)) return aIdx - bIdx;
      return String(a.packetIndex).localeCompare(String(b.packetIndex));
    });
  }

  function classifyWifiEntryDecryptability(entry) {
    if (!entry) return "unknown";
    if (entry.decryptOk) return "decrypted";
    const ssid = String(entry.ssid || "").trim();
    const bssid = String(entry.bssid || "").trim().toLowerCase();
    const cipher = String(entry.cipher || "").toUpperCase();
    const crypto = String(entry.crypto || "").toUpperCase();
    if (!wifiKeystoreKeys.length) return "no-keys";
    const matchingBssid = wifiKeystoreKeys.filter((k) => {
      const summary = readWifiEntrySummary(k);
      const keyBssid = normalizeWifiBssidString(summary.bssid || k.bssid || "");
      if (!keyBssid) return true;
      if (!bssid) return true;
      return keyBssid === bssid;
    });
    if (!matchingBssid.length) return "no-key-for-bssid";
    const supportsCipher = (() => {
      if (cipher.includes("WEP") || cipher.includes("WEP40") || cipher.includes("WEP104")) {
        return matchingBssid.some((k) => {
          const type = String(k.type || "").toLowerCase();
          const content = String(k.content || "").trim();
          return (
            type === "wifi-wep" ||
            type === "wep" ||
            /^[0-9a-fA-F]{10,32}$/.test(content)
          );
        });
      }
      if (
        cipher.includes("CCMP") ||
        cipher.includes("WPA") ||
        cipher.includes("TKIP") ||
        crypto.includes("WPA") ||
        crypto.includes("WPA2") ||
        crypto.includes("WPA3")
      ) {
        return matchingBssid.some((k) => {
          const type = String(k.type || "").toLowerCase();
          const content = String(k.content || "").trim();
          return (
            type === "wifi-wpa-psk" ||
            type === "wifi-pmk" ||
            type === "wpa-psk" ||
            type === "wpa-pmk" ||
            /^[0-9a-fA-F]{64}$/.test(content) ||
            (/\s/.test(content) && content.length >= 8 && content.length <= 63)
          );
        });
      }
      return false;
    })();
    return supportsCipher ? "decryptable" : "no-match";
  }

  function applyWifiFilters(rawEntries) {
    const base = Array.isArray(rawEntries) ? rawEntries.slice() : [];
    const ssidNeedle = String(wifiFilterState.ssid || "").trim().toLowerCase();
    const bssidNeedle = String(wifiFilterState.bssid || "").trim().toLowerCase();
    const wantDecryptable = Boolean(wifiFilterState.decryptableOnly);
    const filtered = base.filter((entry) => {
      if (ssidNeedle) {
        const ssid = String(entry.ssid || "").toLowerCase();
        if (!ssid.includes(ssidNeedle)) return false;
      }
      if (bssidNeedle) {
        const bssid = String(entry.bssid || "").toLowerCase();
        const cleanedBssid = bssid.replace(/[^0-9a-f]/g, "");
        const cleanedNeedle = bssidNeedle.replace(/[^0-9a-f]/g, "");
        if (!bssid) return false;
        if (cleanedBssid && cleanedNeedle) {
          if (!cleanedBssid.includes(cleanedNeedle)) return false;
        } else if (!bssid.includes(bssidNeedle)) {
          return false;
        }
      }
      if (wantDecryptable) {
        const cls = classifyWifiEntryDecryptability(entry);
        if (cls !== "decrypted" && cls !== "decryptable") return false;
      }
      return true;
    });
    const sortKey = String(wifiFilterState.sort || "index");
    if (sortKey === "decryptable-first") {
      const rank = (cls) => {
        if (cls === "decrypted") return 0;
        if (cls === "decryptable") return 1;
        if (cls === "no-key-for-bssid") return 3;
        if (cls === "no-keys") return 4;
        if (cls === "no-match") return 5;
        return 2;
      };
      filtered.sort((a, b) => {
        const ra = rank(classifyWifiEntryDecryptability(a));
        const rb = rank(classifyWifiEntryDecryptability(b));
        if (ra !== rb) return ra - rb;
        const aIdx = Number(a.packetIndex);
        const bIdx = Number(b.packetIndex);
        if (Number.isFinite(aIdx) && Number.isFinite(bIdx)) return aIdx - bIdx;
        return String(a.packetIndex).localeCompare(String(b.packetIndex));
      });
    } else if (sortKey === "ssid") {
      filtered.sort((a, b) => {
        const ssidCompare = String(a.ssid || "").localeCompare(
          String(b.ssid || ""),
        );
        if (ssidCompare !== 0) return ssidCompare;
        const aIdx = Number(a.packetIndex);
        const bIdx = Number(b.packetIndex);
        if (Number.isFinite(aIdx) && Number.isFinite(bIdx)) return aIdx - bIdx;
        return 0;
      });
    } else if (sortKey === "bssid") {
      filtered.sort((a, b) => {
        const bssidCompare = String(a.bssid || "").localeCompare(
          String(b.bssid || ""),
        );
        if (bssidCompare !== 0) return bssidCompare;
        const aIdx = Number(a.packetIndex);
        const bIdx = Number(b.packetIndex);
        if (Number.isFinite(aIdx) && Number.isFinite(bIdx)) return aIdx - bIdx;
        return 0;
      });
    } else {
      filtered.sort((a, b) => {
        const aIdx = Number(a.packetIndex);
        const bIdx = Number(b.packetIndex);
        if (Number.isFinite(aIdx) && Number.isFinite(bIdx)) return aIdx - bIdx;
        return String(a.packetIndex).localeCompare(String(b.packetIndex));
      });
    }
    return filtered;
  }

  function updateWifiFilterStatus() {
    const statusEl = document.getElementById("crypt-wifi-filter-status");
    if (!statusEl) return;
    const totalRaw = wifiAllEncounteredEntries.length;
    const totalShown = wifiEncounteredEntries.length;
    const parts = [];
    if (wifiFilterState.ssid) parts.push(`SSID~="${wifiFilterState.ssid}"`);
    if (wifiFilterState.bssid) parts.push(`BSSID~="${wifiFilterState.bssid}"`);
    if (wifiFilterState.decryptableOnly) parts.push("decryptable-only");
    const sortLabel = {
      "index": "by index",
      "decryptable-first": "decryptable first",
      "ssid": "by SSID",
      "bssid": "by BSSID",
    }[wifiFilterState.sort] || "by index";
    const filterClause = parts.length ? ` [${parts.join(", ")}]` : "";
    statusEl.textContent = `Showing ${totalShown} of ${totalRaw} 802.11 frames (sorted ${sortLabel})${filterClause}`;
  }

  function renderWifiEncounteredDetails(entry) {
    const detailsEl = document.getElementById("crypt-wifi-encountered-details");
    if (!entry) {
      detailsEl.textContent =
        "No 802.11 frames detected in the loaded capture.";
      return;
    }
    const cls = classifyWifiEntryDecryptability(entry);
    const keyParts = [
      `Host: ${entry.host}`,
      `Packet: ${entry.packetIndex}`,
      `Link: ${entry.linkProto}`,
      `Type: ${entry.type || "Unknown"}${entry.subtype ? ` / ${entry.subtype}` : ""}`,
      `SSID: ${entry.ssid || "(probe/none)"}`,
      `BSSID: ${entry.bssid || "N/A"}`,
      `Channel: ${entry.channel || "Unknown"}`,
      `Cipher: ${entry.cipher || "Unknown"}`,
      `Crypto: ${entry.crypto || "Unknown"}`,
      `Decrypt: ${entry.decryptOk ? `Yes (${entry.decryptAlgorithm || "OK"})` : "Not yet"}`,
      `Status: ${describeWifiClass(cls)}`,
    ];
    if (entry.bssid) {
      const matching = wifiKeystoreKeys.filter((k) => {
        const summary = readWifiEntrySummary(k);
        const keyBssid = normalizeWifiBssidString(summary.bssid || k.bssid || "");
        if (!keyBssid) return true;
        return keyBssid === entry.bssid;
      });
      keyParts.push(`Keystore keys for BSSID: ${matching.length}`);
    }
    detailsEl.textContent = keyParts.join("\n");
  }

  function renderCurrentWifiEncounteredEntries() {
    const listEl = document.getElementById("crypt-wifi-encountered-list");
    listEl.replaceChildren();
    wifiActiveEntryIndex = -1;

    if (wifiEncounteredEntries.length === 0) {
      const option = document.createElement("option");
      const totalRaw = wifiAllEncounteredEntries.length;
      if (totalRaw === 0) {
        option.textContent = "No 802.11 frames detected in loaded capture.";
      } else {
        option.textContent = `No 802.11 frames match the current filter (0 of ${totalRaw}).`;
      }
      option.disabled = true;
      listEl.appendChild(option);
      renderWifiEncounteredDetails(null);
      updateWifiFilterStatus();
      return;
    }

    wifiEncounteredEntries.forEach((entry, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      const ssid = entry.ssid || "(no SSID)";
      const bssid = entry.bssid || "ff:ff:ff:ff:ff:ff";
      const cipher = entry.cipher || "Unknown";
      const cls = classifyWifiEntryDecryptability(entry);
      let marker = "";
      if (entry.decryptOk) marker = " ✔";
      else if (cls === "decryptable") marker = " ★";
      else if (cls === "no-key-for-bssid") marker = " ✗";
      option.textContent = `#${entry.packetIndex} ${ssid} [${bssid}] ${cipher}${marker}`;
      option.title = describeWifiClass(cls);
      listEl.appendChild(option);
    });

    listEl.selectedIndex = 0;
    wifiActiveEntryIndex = 0;
    renderWifiEncounteredDetails(wifiEncounteredEntries[0]);
    updateWifiFilterStatus();
  }

  function describeWifiClass(cls) {
    switch (cls) {
      case "decrypted":
        return "Decrypted by backend";
      case "decryptable":
        return "Decryptable with current keystore keys";
      case "no-keys":
        return "No Wi-Fi keys in the keystore";
      case "no-key-for-bssid":
        return "No keystore key for this BSSID";
      case "no-match":
        return "Keystore key does not match cipher";
      default:
        return "Unknown decryptability";
    }
  }

  function refreshWifiEncounteredEntries() {
    wifiAllEncounteredEntries = getWifiEncounteredEntries();
    wifiEncounteredEntries = applyWifiFilters(wifiAllEncounteredEntries);
    renderCurrentWifiEncounteredEntries();
  }

  function applyWifiFiltersAndRender() {
    wifiEncounteredEntries = applyWifiFilters(wifiAllEncounteredEntries);
    renderCurrentWifiEncounteredEntries();
  }

  function readWifiFilterInputs() {
    const ssidEl = document.getElementById("crypt-wifi-filter-ssid");
    const bssidEl = document.getElementById("crypt-wifi-filter-bssid");
    const decryptableEl = document.getElementById(
      "crypt-wifi-filter-decryptable",
    );
    const sortEl = document.getElementById("crypt-wifi-filter-sort");
    wifiFilterState.ssid = (ssidEl?.value || "").trim();
    wifiFilterState.bssid = (bssidEl?.value || "").trim();
    wifiFilterState.decryptableOnly = Boolean(decryptableEl?.checked);
    wifiFilterState.sort = sortEl?.value || "index";
  }

  function applyWifiFilterFromInputs() {
    readWifiFilterInputs();
    applyWifiFiltersAndRender();
    const ssidPart = wifiFilterState.ssid ? ` SSID~="${wifiFilterState.ssid}"` : "";
    const bssidPart = wifiFilterState.bssid ? ` BSSID~="${wifiFilterState.bssid}"` : "";
    const decryptPart = wifiFilterState.decryptableOnly ? " decryptable-only" : "";
    statusUpdate(
      `Status: Wi-Fi filter applied — ${wifiEncounteredEntries.length} frame(s) match${ssidPart}${bssidPart}${decryptPart}`,
    );
    writeLogEntry(
      `[${threadName}] Wi-Fi encountered filter applied: ssid=${JSON.stringify(wifiFilterState.ssid)} bssid=${JSON.stringify(wifiFilterState.bssid)} decryptableOnly=${wifiFilterState.decryptableOnly} sort=${wifiFilterState.sort} -> ${wifiEncounteredEntries.length} frame(s)`,
    );
  }

  function clearWifiFilter() {
    const ssidEl = document.getElementById("crypt-wifi-filter-ssid");
    const bssidEl = document.getElementById("crypt-wifi-filter-bssid");
    const decryptableEl = document.getElementById(
      "crypt-wifi-filter-decryptable",
    );
    const sortEl = document.getElementById("crypt-wifi-filter-sort");
    if (ssidEl) ssidEl.value = "";
    if (bssidEl) bssidEl.value = "";
    if (decryptableEl) decryptableEl.checked = false;
    if (sortEl) sortEl.value = "index";
    wifiFilterState.ssid = "";
    wifiFilterState.bssid = "";
    wifiFilterState.decryptableOnly = false;
    wifiFilterState.sort = "index";
    applyWifiFiltersAndRender();
    statusUpdate("Status: Cleared Wi-Fi filter");
  }

  function selectWifiEncounteredEntry(index) {
    if (
      !Number.isFinite(index) ||
      index < 0 ||
      index >= wifiEncounteredEntries.length
    ) {
      wifiActiveEntryIndex = -1;
      renderWifiEncounteredDetails(null);
      return;
    }
    wifiActiveEntryIndex = index;
    renderWifiEncounteredDetails(wifiEncounteredEntries[index]);
  }

  function loadSelectedWifiEntry() {
    const entry = wifiEncounteredEntries[wifiActiveEntryIndex];
    if (!entry) {
      statusUpdate("Status: Select an 802.11 frame first");
      return;
    }
    const packet = entry.packet;
    const packetInfo = getPacketInfo(packet);
    const index = packetInfo["Index"] ?? packetInfo["packet.processed"] ?? entry.packetIndex;
    statusUpdate(`Status: Loaded 802.11 frame #${index} (${entry.ssid || "(no SSID)"})`);
    writeLogEntry(`[${threadName}] Loaded 802.11 frame #${index} from crypt:wireless`);
  }

  function applyWifiFilterForActiveEntry() {
    const entry = wifiEncounteredEntries[wifiActiveEntryIndex];
    if (!entry) {
      statusUpdate("Status: Select an 802.11 frame to filter on");
      return;
    }
    const filters = [];
    if (entry.bssid) {
      filters.push(`wifi.bssid == "${entry.bssid}"`);
    }
    if (entry.ssid && entry.ssid !== "(probe/none)") {
      filters.push(`wifi.ssid == "${entry.ssid}"`);
    }
    if (wifiFilterState.decryptableOnly) {
      filters.push('wifi.decrypt.ok == "true"');
    }
    if (!filters.length) {
      filters.push(`packet.proto == "WIFI"`);
    }
    const query = filters.join(" || ");
    filterInputEl.value = query;
    syncFilterHighlight();
    runFilterQuery();
    statusUpdate(`Status: Applied Wi-Fi filter "${query}"`);
    writeLogEntry(`[${threadName}] Applied Wi-Fi filter from crypt:wireless: ${query}`);
  }

  function getWifiKeychainEntries() {
    if (typeof getSessionKeychainEntries !== "function") return [];
    const entries = getSessionKeychainEntries();
    return Array.isArray(entries) ? entries : [];
  }

  function readWifiEntrySummary(entry) {
    if (!entry || typeof entry !== "object") return {};
    const summary = entry.summary;
    if (typeof summary === "string") {
      try {
        const parsed = JSON.parse(summary);
        if (parsed && typeof parsed === "object") return parsed;
      } catch (_err) {
        // fall through to label parsing
      }
    }
    const label = String(entry.label || "");
    const out = {};
    const ssidMatch = label.match(/ssid=([^ ]+)/);
    if (ssidMatch) out.ssid = ssidMatch[1];
    const bssidMatch = label.match(/bssid=([0-9a-f:]{17})/i);
    if (bssidMatch) out.bssid = bssidMatch[1].toLowerCase();
    return out;
  }

  function isWifiKeystoreEntry(entry) {
    if (!entry || typeof entry !== "object") return false;
    const type = String(entry.type || "").toLowerCase();
    if (type.startsWith("wifi")) return true;
    if (type === "wep" || type === "wpa-psk" || type === "wpa-pmk") return true;
    return false;
  }

  function wifiEntryToBackendKey(entry) {
    if (!entry || typeof entry !== "object") return null;
    const summary = readWifiEntrySummary(entry);
    const ssid = String(summary.ssid || "").trim();
    const bssid = normalizeWifiBssidString(summary.bssid || entry.bssid || "");
    const raw = String(entry.content || "").trim();
    const type = String(entry.type || "").toLowerCase();
    const out = {};
    if (ssid) out.ssid = ssid;
    if (bssid) out.bssid = bssid;
    if (type === "wifi-wep" || type === "wep" || /^[0-9a-fA-F]{10,32}$/.test(raw)) {
      out.wepKeyHex = raw.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
    } else if (type === "wifi-pmk" || type === "wpa-pmk" || /^[0-9a-fA-F]{64}$/.test(raw)) {
      out.pmkHex = raw.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
    } else {
      out.psk = raw;
    }
    return out;
  }

  function refreshWifiKeystoreEntries() {
    const entries = getWifiKeychainEntries().filter(isWifiKeystoreEntry);
    wifiKeystoreKeys = entries;
    const listEl = document.getElementById("crypt-wifi-keystore-list");
    listEl.replaceChildren();
    if (!entries.length) {
      const option = document.createElement("option");
      option.textContent = "No Wi-Fi keys saved in the session keychain.";
      option.disabled = true;
      listEl.appendChild(option);
    } else {
      entries.forEach((entry, index) => {
        const option = document.createElement("option");
        option.value = String(index);
        const summary = readWifiEntrySummary(entry);
        const type = entry.type || "unknown";
        const ssid = summary.ssid || entry.label || "(no SSID)";
        const bssid = summary.bssid || "any";
        const preview = String(entry.content || "")
          .replace(/\s+/g, " ")
          .slice(0, 32);
        option.textContent = `${type} ${ssid} [${bssid}] ${preview}`;
        listEl.appendChild(option);
      });
      listEl.selectedIndex = 0;
    }
    // Re-render the encountered list so the decryptability markers and the
    // 'decryptable-only' filter pick up the freshly-loaded keys.
    if (wifiAllEncounteredEntries.length) {
      applyWifiFiltersAndRender();
    }
  }

  function addWifiKeyFromForm() {
    const typeEl = document.getElementById("crypt-wifi-key-type");
    const ssidEl = document.getElementById("crypt-wifi-ssid-input");
    const bssidEl = document.getElementById("crypt-wifi-bssid-input");
    const keyEl = document.getElementById("crypt-wifi-key-input");
    const keyType = typeEl?.value || "wpa-psk";
    const ssid = (ssidEl?.value || "").trim();
    const bssid = normalizeWifiBssidString(bssidEl?.value || "");
    const value = (keyEl?.value || "").trim();
    if (!value) {
      statusUpdate("Status: Wi-Fi key material is empty");
      return;
    }
    if (typeof addSessionKeystoreEntry !== "function") {
      doError("Session keychain is not available in this build.");
      return;
    }
    const label = [
      `Wi-Fi ${keyType}`,
      ssid ? `ssid=${ssid}` : null,
      bssid ? `bssid=${bssid}` : null,
    ]
      .filter(Boolean)
      .join(" ");
    const summary = JSON.stringify({ ssid, bssid, type: keyType });
    const entry = {
      type: `wifi-${keyType}`,
      label,
      source: "crypt-wireless",
      content: value,
      summary,
    };
    try {
      addSessionKeystoreEntry(entry);
      if (keyEl) keyEl.value = "";
      statusUpdate(`Status: Saved Wi-Fi key (${keyType}) to session keychain`);
      refreshWifiKeystoreEntries();
    } catch (err) {
      doError(`Could not save Wi-Fi key: ${err.message || err}`);
    }
  }

  function removeSelectedWifiKeystoreKey() {
    const listEl = document.getElementById("crypt-wifi-keystore-list");
    const idx = Number(listEl.value);
    if (!Number.isFinite(idx) || idx < 0 || idx >= wifiKeystoreKeys.length) {
      statusUpdate("Status: Select a Wi-Fi key to remove");
      return;
    }
    const entry = wifiKeystoreKeys[idx];
    if (entry?.delete) {
      try {
        entry.delete();
      } catch (_err) {
        // ignore
      }
    }
    refreshWifiKeystoreEntries();
  }

  function collectBackendWifiKeys() {
    const keys = wifiKeystoreKeys
      .map(wifiEntryToBackendKey)
      .filter((k) => k && typeof k === "object");
    return keys;
  }

  function getBackendWifiIpc() {
    if (typeof window === "undefined") return null;
    const candidates = [window.snitchapi, window.backend, window.getfileapi];
    for (const candidate of candidates) {
      if (candidate && typeof candidate.setBackendWifiKeys === "function") {
        return candidate;
      }
    }
    return null;
  }

  function updateWifiBackendStatus(message) {
    wifiBackendKeysLastSentAt = new Date().toISOString();
    const statusEl = document.getElementById("crypt-wifi-backend-status");
    if (statusEl) {
      statusEl.textContent = `Last sent ${wifiBackendKeysLastSentAt}: ${message}`;
    }
  }

  async function sendWifiKeysToBackend() {
    const keys = collectBackendWifiKeys();
    if (!keys.length) {
      statusUpdate("Status: No Wi-Fi keys to send to backend");
      updateWifiBackendStatus("No keys sent (keychain empty)");
      return;
    }
    const api = getBackendWifiIpc();
    if (!api || typeof api.setBackendWifiKeys !== "function") {
      doError("Wi-Fi bridge is not available; the backend cannot decrypt 802.11 payloads.");
      return;
    }
    // Snapshot the keys BEFORE the IPC so the auto-rerun callback below
    // can reuse them even if the session keychain is rebuilt/emptied
    // between the IPC round-trip and the rerun dispatch (a real race we
    // observed: the keystore-LLM debounce rebuild wiped the user-added
    // key by the time triggerWifiKeysRerun re-read collectBackendWifiKeys).
    wifiBackendKeysLastSent = Array.isArray(keys)
      ? keys.map((entry) => (entry && typeof entry === "object" ? { ...entry } : entry))
      : [];
    try {
      const result = await api.setBackendWifiKeys(keys);
      if (result && result.success) {
        wifiBackendKeysAccepted = Number(result.accepted || keys.length);
        statusUpdate(
          `Status: Backend accepted ${wifiBackendKeysAccepted} Wi-Fi key(s); re-running capture to decrypt 802.11 frames...`,
        );
        updateWifiBackendStatus(
          `Sent ${keys.length} key(s); backend accepted ${wifiBackendKeysAccepted}; rerun queued`,
        );
        writeLogEntry(
          `[${threadName}] Sent ${keys.length} Wi-Fi key(s) to backend for decryption`,
        );
        // Automatically kick off a background rerun so the freshly
        // decrypted 802.11 frames merge into the live session data
        // without the user needing to click "Reprocess Session PCAP".
        if (typeof rerunBackendWithWifiKeys === "function") {
          try {
            const didRerun = rerunBackendWithWifiKeys({
              keys: wifiBackendKeysLastSent,
            });
            if (!didRerun) {
              statusUpdate(
                "Status: Backend accepted Wi-Fi keys; click 'Reprocess Session PCAP' to apply them",
              );
            }
          } catch (rerunError) {
            logErrorEntry("crypt-wifi-auto-rerun", rerunError);
          }
        }
      } else {
        doError(`Backend rejected Wi-Fi keys: ${result?.error || "unknown error"}`);
      }
    } catch (err) {
      doError(`Failed to send Wi-Fi keys to backend: ${err.message || err}`);
    }
  }

  function hexToAsciiPreview(hexString) {
    if (typeof hexString !== "string" || !hexString) return "";
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
      const byte = parseInt(hexString.slice(i, i + 2), 16);
      if (Number.isNaN(byte)) return "";
      bytes.push(byte);
    }
    const decoded = Buffer.from(bytes).toString("utf8");
    return PRINTABLE_UTF8_PREVIEW_REGEX.test(decoded)
      ? decoded
      : decoded
        .slice(0, MAX_ASCII_PREVIEW_LENGTH)
        .replace(/[^\x09\x0A\x0D\x20-\x7E]/g, ".");
  }

  function applyCryptCertificateText(rawText, sourceLabel) {
    const certInputEl = document.getElementById("crypt-cert-input");
    const certPreviewEl = document.getElementById("crypt-cert-preview");
    const normalized = (rawText || "").trim();
    certInputEl.value = normalized;
    certPreviewEl.textContent = formatCryptSummary(
      normalized,
      "Certificate",
      sourceLabel,
      /CERTIFICATE/i,
    );
    if (normalized) {
      statusUpdate(`Status: Certificate loaded from ${sourceLabel}`);
      writeLogEntry(`[${threadName}] Crypt certificate loaded source="${sourceLabel}"`);
      if (sourceLabel !== SESSION_KEYCHAIN_LABEL) {
        addSessionKeystoreEntry({
          type: "certificate",
          label: getFirstLineOrFallback(
            "crypt-cert-preview",
            `Certificate-${new Date().toISOString()}`,
          ),
          source: `cert-tab ${sourceLabel}`,
          content: normalized,
          summary: "Imported into cert tab",
        });
      }
    }
  }

  function applyCryptPrivateKeyText(rawText, sourceLabel) {
    const keyInputEl = document.getElementById("crypt-key-input");
    const keyPreviewEl = document.getElementById("crypt-key-preview");
    const pgpPrivateKeyInputEl = document.getElementById(
      "crypt-pgp-private-key-input",
    );
    const normalized = (rawText || "").trim();
    keyInputEl.value = normalized;
    if (
      pgpPrivateKeyInputEl &&
      /-----BEGIN PGP PRIVATE KEY BLOCK-----/i.test(normalized)
    ) {
      pgpPrivateKeyInputEl.value = normalized;
      refreshPgpPrivateKeyCandidates();
    }
    keyPreviewEl.textContent = formatCryptSummary(
      normalized,
      "Private key",
      sourceLabel,
      /(PRIVATE KEY|OPENSSH)/i,
    );
    if (normalized) {
      statusUpdate(`Status: Private key loaded from ${sourceLabel}`);
      writeLogEntry(`[${threadName}] Crypt private key loaded source="${sourceLabel}"`);
      if (sourceLabel !== SESSION_KEYCHAIN_LABEL) {
        addSessionKeystoreEntry({
          type: "private-key",
          label: getFirstLineOrFallback(
            "crypt-key-preview",
            `Private-key-${new Date().toISOString()}`,
          ),
          source: `cert-tab ${sourceLabel}`,
          content: normalized,
          summary: "Imported into cert tab",
        });
      }
    }
  }

  function parseNssKeyLog(text) {
    const normalized = String(text || "").trim();
    const entries = [];
    if (!normalized) return entries;
    const lines = normalized.split(/\r?\n/);
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 3) continue;
      const [label, clientRandomHex, secretHex, ...rest] = parts;
      if (
        !/^(CLIENT_RANDOM|CLIENT_EARLY_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_\d+|SERVER_TRAFFIC_SECRET_\d+|EARLY_EXPORTER_SECRET|EXPORTER_SECRET)$/.test(
          label,
        )
      ) {
        continue;
      }
      const clientRandom = normalizeHexString(clientRandomHex).toLowerCase();
      if (!clientRandom || clientRandom.length !== 64) continue;
      const normalizedSecret = normalizeHexString(secretHex).toLowerCase();
      if (!normalizedSecret) continue;
      entries.push({
        label,
        clientRandom,
        secretHex: normalizedSecret,
        originalLine: line.trim(),
      });
    }
    return entries;
  }

  function applyCryptKeyLogText(rawText, sourceLabel) {
    const keyLogInputEl = document.getElementById("crypt-key-log-input");
    const keyLogPreviewEl = document.getElementById("crypt-key-log-preview");
    const normalized = String(rawText || "").trim();
    keyLogInputEl.value = normalized;
    if (normalized) {
      const entries = parseNssKeyLog(normalized);
      cryptKeyLogEntries = entries;
      const clientRandoms = entries
        .filter((e) => e.label === NSS_KEY_LOG_LABEL_CLIENT_RANDOM)
        .map((e) => e.clientRandom.slice(0, 16))
        .filter((v, i, a) => a.indexOf(v) === i);
      const tls13Secrets = entries.some((e) =>
        NSS_KEY_LOG_LABELS_TLS13.includes(e.label),
      );
      keyLogPreviewEl.textContent = [
        `Loaded ${entries.length} key log line(s) from ${sourceLabel}.`,
        clientRandoms.length
          ? `CLIENT_RANDOM entries: ${clientRandoms.length} session(s) preview ${clientRandoms.join(", ")}`
          : null,
        tls13Secrets ? "TLS 1.3 traffic secrets present." : null,
      ]
        .filter(Boolean)
        .join("\n");
      statusUpdate(`Status: TLS key log loaded from ${sourceLabel}`);
      writeLogEntry(
        `[${threadName}] Crypt key log loaded source="${sourceLabel}" entries=${entries.length} clientRandomSessions=${clientRandoms.length} tls13=${tls13Secrets}`,
      );
      if (sourceLabel !== SESSION_KEYCHAIN_LABEL) {
        addSessionKeystoreEntry({
          type: "tls-session-secret",
          label: getFirstLineOrFallback(
            "crypt-key-log-preview",
            `TLS-Key-Log-${new Date().toISOString()}`,
          ),
          source: `key-log-tab ${sourceLabel}`,
          content: normalized,
          summary: `Imported ${entries.length} NSS key log line(s)`,
        });
      }
    } else {
      cryptKeyLogEntries = [];
      keyLogPreviewEl.textContent = "No TLS key log loaded.";
      statusUpdate("Status: TLS key log cleared");
    }
  }

  function readCryptTextFile(fileInputEl, onLoad) {
    const file = fileInputEl.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () =>
      onLoad(String(reader.result || ""), `file ${file.name}`);
    reader.onerror = (error) => {
      logErrorEntry("crypt-file-read", error);
      doError("Could not read selected crypt file.");
    };
    reader.readAsText(file);
  }

  function applyCryptFilterForActiveEntry() {
    if (
      cryptActiveEntryIndex < 0 ||
      !cryptEncounteredEntries[cryptActiveEntryIndex]
    ) {
      statusUpdate("Status: Select an encountered SSL/TLS entry first");
      return;
    }
    const activeEntry = cryptEncounteredEntries[cryptActiveEntryIndex];
    const sourceIp = normalizeCryptEndpointIp(activeEntry.srcIp);
    const destinationIp = normalizeCryptEndpointIp(activeEntry.dstIp);
    if (
      !isLikelyIpAddress(sourceIp) ||
      !isLikelyIpAddress(destinationIp)
    ) {
      statusUpdate(
        "Status: Cannot build filter query for non-IP packet endpoints",
      );
      return;
    }
    const query = `ip.src.addr: ${sourceIp} && ip.dst.addr: ${destinationIp}`;
    filterInputEl.value = query;
    syncFilterHighlight();
    runFilterQuery(query);
    writeLogEntry(`[${threadName}] Crypt filter applied query="${query}"`);
  }

  function loadEncounteredCertificateIntoCrypt() {
    if (
      cryptActiveEntryIndex < 0 ||
      !cryptEncounteredEntries[cryptActiveEntryIndex]
    ) {
      statusUpdate("Status: Select an encountered SSL/TLS entry first");
      return;
    }
    const activeEntry = cryptEncounteredEntries[cryptActiveEntryIndex];
    if (!activeEntry.sslCert || activeEntry.sslCert === "Not available") {
      statusUpdate("Status: No certificate text available for selected entry");
      return;
    }
    applyCryptCertificateText(
      String(activeEntry.sslCert),
      `encountered packet #${activeEntry.packetIndex}`,
    );
  }

  function selectEncounteredEntry(selectedIndex) {
    if (
      !Number.isFinite(selectedIndex) ||
      !cryptEncounteredEntries[selectedIndex]
    ) {
      return;
    }
    cryptActiveEntryIndex = selectedIndex;
    renderCryptEncounteredDetails(cryptEncounteredEntries[selectedIndex]);
    clearCryptDecryptionOutput();
  }

  function decryptActiveEntryWithLoadedKey() {
    if (
      cryptActiveEntryIndex < 0 ||
      !cryptEncounteredEntries[cryptActiveEntryIndex]
    ) {
      statusUpdate("Status: Select an encountered SSL/TLS entry first");
      return;
    }
    const privateKeyPem = String(
      document.getElementById("crypt-key-input")?.value || "",
    ).trim();
    const certificatePem = String(
      document.getElementById("crypt-cert-input")?.value || "",
    ).trim();
    const keyLogText = String(
      document.getElementById("crypt-key-log-input")?.value || "",
    ).trim();
    if (!privateKeyPem && !keyLogText) {
      statusUpdate(
        "Status: Load a private key or an SSL key log from keychain/file first",
      );
      return;
    }
    if (certificatePem && privateKeyPem) {
      const certKeyCheck = certMatchesPrivateKey(certificatePem, privateKeyPem);
      if (certKeyCheck.matched === false) {
        statusUpdate(
          "Status: Loaded certificate does not match private key (continuing with key)",
        );
      }
      if (certKeyCheck.matched === null && certKeyCheck.reason) {
        writeLogEntry(`Crypt cert/key check skipped: ${certKeyCheck.reason}`);
      }
    }
    const activeEntry = cryptEncounteredEntries[cryptActiveEntryIndex];
    const payloadHex = String(
      activeEntry?.decryptPayloadHex || findPayloadHexForEncounteredEntry(activeEntry),
    ).replace(/[^0-9A-Fa-f]/g, "");
    if (!payloadHex) {
      statusUpdate("Status: Selected packet has no payload to decrypt");
      return;
    }
    if (payloadHex.length % 2 !== 0) {
      doError("Selected payload is not valid hex data.");
      return;
    }
    try {
      const decryptedBytes = decryptTlsCipherBytes(
        Buffer.from(payloadHex, "hex"),
        privateKeyPem,
        activeEntry,
      );
      renderDecryptedPayload(activeEntry, decryptedBytes);
      if (keyLogText) {
        addSessionKeystoreEntry({
          type: "tls-session-secret",
          label: getFirstLineOrFallback(
            "crypt-key-log-preview",
            `TLS-Key-Log-Success-${new Date().toISOString()}`,
          ),
          source: "tls-decrypt-success",
          content: keyLogText,
          summary: `Decrypted packet #${activeEntry.packetIndex} with key log`,
        });
      }
      if (privateKeyPem) {
        addSessionKeystoreEntry({
          type: "private-key",
          label: getFirstLineOrFallback(
            "crypt-key-preview",
            `TLS-Private-Key-${new Date().toISOString()}`,
          ),
          source: "tls-decrypt-success",
          content: privateKeyPem,
          summary: "Validated by successful TLS decrypt",
        });
      }
      statusUpdate(
        `Status: Decrypted TLS/SSL payload for packet #${activeEntry.packetIndex}`,
      );
      writeLogEntry(
        `[${threadName}] Crypt decrypted payload packet_index=${activeEntry.packetIndex}`,
      );
    } catch (error) {
      clearCryptDecryptionOutput();
      logErrorEntry(`[${threadName}] crypt-tls-decrypt`, error);
      doError(
        "Could not decrypt selected TLS/SSL payload with the loaded key or key log.",
      );
    }
  }

  function sendDecryptedPayloadToConvTab() {
    if (!cryptLastDecryptedPayload) {
      statusUpdate("Status: Decrypt data first before sending to Conv");
      return;
    }
    sendDecryptedToConv(cryptLastDecryptedPayload);
    statusUpdate(
      `Status: Sent decrypted payload from ${cryptLastDecryptedPayload.sourceLabel} to Conv`,
    );
    writeLogEntry(
      `[${threadName}] Crypt decrypted payload sent to Conv source="${cryptLastDecryptedPayload.sourceLabel}"`,
    );
  }

  function getLastTlsDecryptedPayload() {
    if (!cryptLastDecryptedPayload) return null;
    return { ...cryptLastDecryptedPayload };
  }

  function getLastPgpOutputPayload() {
    if (!pgpLastOutputPayload) return null;
    return { ...pgpLastOutputPayload };
  }

  function showCryptWorkspace(tabName = CRYPT_HASHES_SUBTAB) {
    setActiveMainTab(MAIN_TAB_CRYPT);
    if (getJsonCapture() === "") {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      writeLogEntry(`[${threadName}] No JSON file loaded when attempting to access crypt workspace`);
      doError("Please upload a JSON file before accessing crypt tools.");
      return;
    }

    statusUpdate("Status: Displaying crypt workspace");
    writeLogEntry(`[${threadName}] User opened crypt workspace view`);
    document.getElementById("prev-btn").style.display = "none";
    document.getElementById("next-btn").style.display = "none";
    document.getElementById("packetInfoPane").style.display = "none";
    document.getElementById("packetPayloadPane").style.display = "none";
    document.getElementById("summary_box").style.display = "none";
    document.getElementById("stats_box").style.display = "none";
    document.getElementById("data_tools_box").style.display = "none";
    document.getElementById("list_box").style.display = "none";
    document.getElementById("notes_box").style.display = "none";
    document.getElementById("keystore_box").style.display = "none";
    document.getElementById("settings_box").style.display = "none";
    document.getElementById("rightside").style.display = "none";
    const cryptBoxEl = document.getElementById("crypt_box");
    cryptBoxEl.style.display = "flex";
    setCryptSubtab(tabName);
    refreshCryptEncounteredEntries();
    refreshPgpEncounteredEntries();
    refreshPgpPrivateKeyCandidates();
    refreshPgpPassphraseCandidates();
    if (tabName === CRYPT_WIFI_SUBTAB) {
      refreshWifiEncounteredEntries();
      refreshWifiKeystoreEntries();
    }
    if (tabName === CRYPT_OPENSSH_SUBTAB) {
      refreshSshEncounteredFlows();
    }
  }

  return {
    setCryptSubtab,
    showCryptWorkspace,
    refreshCryptEncounteredEntries,
    loadStreamIntoCryptEncountered,
    refreshPgpEncounteredEntries,
    refreshPgpPrivateKeyCandidates,
    refreshPgpPassphraseCandidates,
    readCryptTextFile,
    applyCryptCertificateText,
    applyCryptPrivateKeyText,
    applyCryptKeyLogText,
    applyCryptFilterForActiveEntry,
    loadEncounteredCertificateIntoCrypt,
    selectEncounteredEntry,
    decryptActiveEntryWithLoadedKey,
    sendDecryptedPayloadToConvTab,
    clearCryptDecryptionOutput,
    selectPgpEncounteredEntry,
    loadSelectedPgpEncounteredInput,
    analyzePgpInput,
    convertPgpInputToBinaryHex,
    convertPgpInputToArmor,
    decryptVerifyPgpInput,
    sendPgpOutputToConvTab,
    clearPgpOutput,
    clearPgpInput,
    useSelectedPgpPrivateKeyCandidate,
    useSelectedPgpPasswordCandidate,
    getLastTlsDecryptedPayload,
    getLastPgpOutputPayload,
    refreshWifiEncounteredEntries,
    selectWifiEncounteredEntry,
    loadSelectedWifiEntry,
    applyWifiFilterForActiveEntry,
    applyWifiFilterFromInputs,
    clearWifiFilter,
    refreshWifiKeystoreEntries,
    addWifiKeyFromForm,
    removeSelectedWifiKeystoreKey,
    sendWifiKeysToBackend,
    getLastSentWifiKeys: () =>
      Array.isArray(wifiBackendKeysLastSent) ? wifiBackendKeysLastSent.slice() : [],
    classifyWifiEntryDecryptability,
    describeWifiClass,
    refreshSshEncounteredFlows,
    selectSshEncounteredFlow,
    analyzeSelectedSshFlow,
    // Keystroke-timing export — click handler is in scope; the pure
    // text builder + stats helpers live in
    // src/ui/decoders/ssh-keystrokes/export/index.js so they can be
    // unit-tested without the DOM or IPC. Re-export them here as a
    // convenience for callers / tests.
    exportSshKeystrokes,
    buildSshKeystrokeExport: (state, opts) =>
      sshExportModule && typeof sshExportModule.buildSshKeystrokeExport === "function"
        ? sshExportModule.buildSshKeystrokeExport(state, opts)
        : "",
    computeDelayStats: (delays) =>
      sshExportModule && typeof sshExportModule.computeDelayStats === "function"
        ? sshExportModule.computeDelayStats(delays)
        : null,
    formatNumber: (n) =>
      sshExportModule && typeof sshExportModule.formatNumber === "function"
        ? sshExportModule.formatNumber(n)
        : "—",
    wrapText: (text, width) =>
      sshExportModule && typeof sshExportModule.wrapText === "function"
        ? sshExportModule.wrapText(text, width)
        : (typeof text === "string" ? text : ""),
    directionLabel: (direction) =>
      sshExportModule && typeof sshExportModule.directionLabel === "function"
        ? sshExportModule.directionLabel(direction)
        : "client \u2192 server",
    refreshSshExportButton,
  };
}

module.exports = {
  id: "crypt",
  createCryptPanel,
};
