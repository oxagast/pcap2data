
const crypto = require("crypto-browserify");
const openpgp = require("openpgp");
const TLS_CONTENT_TYPE_MIN = 20;
const TLS_CONTENT_TYPE_MAX = 23;
const TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16;
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
    STRICT_IPV4_REGEX,
  } = constants;

  let cryptEncounteredEntries = [];
  let cryptActiveEntryIndex = -1;
  let cryptLastDecryptedPayload = null;
  let pgpEncounteredEntries = [];
  let pgpActiveEntryIndex = -1;
  let pgpLastOutputPayload = null;
  let pgpPrivateKeyCandidates = [];
  let pgpPassphraseCandidates = [];

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
    if (
      !capturedPackets ||
      typeof capturedPackets !== "object" ||
      !capturedPackets["Host"]
    ) {
      return entries;
    }

    for (const host of Object.keys(capturedPackets["Host"])) {
      const packets = capturedPackets["Host"][host];
      if (!Array.isArray(packets)) continue;

      packets.forEach((packet) => {
        const packetInfo = packet?.["Packet Info"];
        const extraInfo = packet?.["Extra Info"];
        const serverInfo = extraInfo?.["Traits"]?.["Server Info"];
        const encryptionData = serverInfo?.["Encryption Data"];
        if (
          !packetInfo ||
          !serverInfo ||
          !encryptionData ||
          encryptionData === "N/A"
        )
          return;

        const protocol = packetInfo["Protocol"] || "Unknown";
        const transportData = packetInfo[protocol] || {};
        const encryptedWithRaw = encryptionData["Encrypted With"];
        const encryptedWith = Array.isArray(encryptedWithRaw)
          ? encryptedWithRaw.filter(Boolean)
          : encryptedWithRaw
            ? [String(encryptedWithRaw)]
            : [];
        entries.push({
          host,
          packetIndex: packetInfo["Index"] ?? "?",
          protocol,
          srcIp: packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"] ?? "N/A",
          dstIp: packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"] ?? "N/A",
          srcPort: transportData?.["Source port"] ?? "N/A",
          dstPort: transportData?.["Destination port"] ?? "N/A",
          encrypted: serverInfo["Encrypted"] ?? "Unknown",
          sslVersion: encryptionData["SSL Version"] ?? "Unknown",
          sslCert: encryptionData["SSL Cert"] ?? "",
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
    detailsEl.textContent = [
      `Host: ${entry.host}`,
      `Packet: ${entry.packetIndex}`,
      `Protocol: ${entry.protocol}`,
      `Path: ${entry.srcIp}:${entry.srcPort} -> ${entry.dstIp}:${entry.dstPort}`,
      `Encrypted: ${entry.encrypted}`,
      `SSL/TLS Version: ${entry.sslVersion}`,
      `Algorithms: ${algoText}`,
    ].join("\n");
  }

  function refreshCryptEncounteredEntries() {
    const listEl = document.getElementById("crypt-encountered-list");
    cryptEncounteredEntries = getCryptEncounteredEntries();
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
      option.textContent = `#${entry.packetIndex} ${entry.sslVersion} ${entry.srcIp}:${entry.srcPort} -> ${entry.dstIp}:${entry.dstPort} (${algoPreview})`;
      listEl.appendChild(option);
    });

    listEl.selectedIndex = 0;
    cryptActiveEntryIndex = 0;
    renderCryptEncounteredDetails(cryptEncounteredEntries[0]);
    clearCryptDecryptionOutput();
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
    return String(
      (packet?.["Packet Info"]?.["Raw data"]?.["Payload"]?.["payload.hex"] ??
        packet?.["Packet Info"]?.["Raw data"]?.["Payload"]?.["Hex Encoded"]) ||
      "",
    );
  }

  function findPayloadHexForEncounteredEntry(entry) {
    const packets = getCapturedPackets()?.["Host"]?.[entry.host];
    if (!Array.isArray(packets)) return "";
    const matchedPacket = packets.find((packet) => {
      const packetIndex = packet?.["Packet Info"]?.["Index"];
      return String(packetIndex) === String(entry.packetIndex);
    });
    return getPacketPayloadHex(matchedPacket);
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
    if (
      !capturedPackets ||
      typeof capturedPackets !== "object" ||
      !capturedPackets["Host"]
    ) {
      return entries;
    }

    for (const host of Object.keys(capturedPackets["Host"])) {
      const packets = capturedPackets["Host"][host];
      if (!Array.isArray(packets)) continue;
      packets.forEach((packet) => {
        const packetInfo = packet?.["Packet Info"];
        if (!packetInfo) return;
        const payloadHex = normalizeHexString(getPacketPayloadHex(packet));
        if (!payloadHex) return;
        const payloadBytes = Buffer.from(payloadHex, "hex");
        const payloadText = payloadBytes.toString("utf8");
        const armoredBlocks = extractPgpArmorBlocksFromText(payloadText);
        if (armoredBlocks.length === 0) return;

        const protocol = packetInfo["Protocol"] || "Unknown";
        const transportData = packetInfo[protocol] || {};
        armoredBlocks.forEach((blockText, blockIndex) => {
          const beginMatch = blockText.match(PGP_BEGIN_LINE_REGEX);
          const endMatch = blockText.match(PGP_END_LINE_REGEX);
          const blockType = beginMatch?.[1] || "PGP data";
          entries.push({
            host,
            packetIndex: packetInfo["Index"] ?? "?",
            protocol,
            srcIp: packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"] ?? "N/A",
            dstIp: packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"] ?? "N/A",
            srcPort: transportData?.["Source port"] ?? "N/A",
            dstPort: transportData?.["Destination port"] ?? "N/A",
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
    detailsEl.textContent = [
      `Packet: ${entry.packetIndex}`,
      `Host: ${entry.host}`,
      `Path: ${entry.srcIp}:${entry.srcPort} -> ${entry.dstIp}:${entry.dstPort}`,
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
      option.textContent = `#${entry.packetIndex} ${entry.blockType} ${entry.srcIp}:${entry.srcPort} -> ${entry.dstIp}:${entry.dstPort}`;
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

  function extractDecryptCandidates(cipherBytes) {
    const candidates = [cipherBytes];
    if (
      cipherBytes.length > 5 &&
      cipherBytes[0] >= TLS_CONTENT_TYPE_MIN &&
      cipherBytes[0] <= TLS_CONTENT_TYPE_MAX
    ) {
      const recordLength = (cipherBytes[3] << 8) | cipherBytes[4];
      const recordEnd = 5 + recordLength;
      if (recordLength > 0 && recordEnd <= cipherBytes.length) {
        const recordPayload = cipherBytes.subarray(5, recordEnd);
        candidates.push(recordPayload);
        if (
          recordPayload.length > 6 &&
          recordPayload[0] === TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE
        ) {
          const handshakeBody = recordPayload.subarray(4);
          candidates.push(handshakeBody);
          if (handshakeBody.length > 2) {
            const encryptedLen = (handshakeBody[0] << 8) | handshakeBody[1];
            if (encryptedLen > 0 && encryptedLen + 2 <= handshakeBody.length) {
              candidates.push(handshakeBody.subarray(2, 2 + encryptedLen));
            }
          }
        }
      }
    }
    return candidates;
  }

  function decryptTlsCipherBytes(cipherBytes, privateKeyPem) {
    const candidates = extractDecryptCandidates(cipherBytes);
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
              key: privateKeyPem,
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
    if (
      !STRICT_IPV4_REGEX.test(String(activeEntry.srcIp || "")) ||
      !STRICT_IPV4_REGEX.test(String(activeEntry.dstIp || ""))
    ) {
      statusUpdate(
        "Status: Cannot build filter query for non-IPv4 packet endpoints",
      );
      return;
    }
    const query = `ip.src.addr: ${activeEntry.srcIp} && ip.dst.addr: ${activeEntry.dstIp}`;
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
    if (!privateKeyPem) {
      statusUpdate("Status: Load a private key from keychain or file first");
      return;
    }
    const certificatePem = String(
      document.getElementById("crypt-cert-input")?.value || "",
    ).trim();
    const certKeyCheck = certMatchesPrivateKey(certificatePem, privateKeyPem);
    if (certificatePem && certKeyCheck.matched === false) {
      statusUpdate(
        "Status: Loaded certificate does not match private key (continuing with key)",
      );
    }
    if (
      certificatePem &&
      certKeyCheck.matched === null &&
      certKeyCheck.reason
    ) {
      writeLogEntry(`Crypt cert/key check skipped: ${certKeyCheck.reason}`);
    }
    const activeEntry = cryptEncounteredEntries[cryptActiveEntryIndex];
    const payloadHex = findPayloadHexForEncounteredEntry(activeEntry).replace(
      /[^0-9A-Fa-f]/g,
      "",
    );
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
      );
      renderDecryptedPayload(activeEntry, decryptedBytes);
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
        "Could not decrypt selected TLS/SSL payload with the loaded private key.",
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
    refreshPgpEncounteredEntries,
    refreshPgpPrivateKeyCandidates,
    refreshPgpPassphraseCandidates,
    readCryptTextFile,
    applyCryptCertificateText,
    applyCryptPrivateKeyText,
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
