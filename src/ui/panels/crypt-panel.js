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
}) {
  const {
    MAIN_TAB_CRYPT,
    CRYPT_SSL_SUBTAB,
    CRYPT_PGP_SUBTAB,
    CRYPT_OPENSSH_SUBTAB,
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

  function loadSelectedPgpEncounteredInput() {
    if (pgpActiveEntryIndex < 0 || !pgpEncounteredEntries[pgpActiveEntryIndex]) {
      statusUpdate("Status: Select an encountered PGP entry first");
      return;
    }
    const entry = pgpEncounteredEntries[pgpActiveEntryIndex];
    const inputEl = document.getElementById("crypt-pgp-input");
    if (inputEl) {
      inputEl.value = entry.armoredText;
    }
    statusUpdate(`Status: Loaded PGP block from packet #${entry.packetIndex}`);
    writeLogEntry(
      `[${threadName}] PGP encountered payload loaded packet_index=${entry.packetIndex} block_index=${entry.blockIndex}`,
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
    const sslActive = tabName === CRYPT_SSL_SUBTAB;
    const pgpActive = tabName === CRYPT_PGP_SUBTAB;
    const opensshActive = tabName === CRYPT_OPENSSH_SUBTAB;
    document
      .getElementById("crypt-subtab-ssl")
      .classList.toggle("active", sslActive);
    document
      .getElementById("crypt-subtab-pgp")
      .classList.toggle("active", pgpActive);
    document
      .getElementById("crypt-subtab-openssh")
      .classList.toggle("active", opensshActive);
    document.getElementById("crypt-ssl-panel").hidden = !sslActive;
    document.getElementById("crypt-pgp-panel").hidden = !pgpActive;
    document.getElementById("crypt-openssh-panel").hidden = !opensshActive;
    if (pgpActive) {
      refreshPgpEncounteredEntries();
      refreshPgpPrivateKeyCandidates();
      refreshPgpPassphraseCandidates();
    }
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

  function showCryptWorkspace(tabName = CRYPT_SSL_SUBTAB) {
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
  };
}

module.exports = {
  id: "crypt",
  createCryptPanel,
};
