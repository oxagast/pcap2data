// Controls the keystore workspace UI and session-secret extraction workflows.

const CRYPT_KEYSTORE_DB_NAME = "packetsnitch-crypt-keystore";
const CRYPT_KEYSTORE_DB_VERSION = 1;
const CRYPT_KEYSTORE_STORE_NAME = "entries";
const CRYPT_KEYSTORE_RECORD_KEY = "default";
const CRYPT_KEYSTORE_SCHEMA_VERSION = 2;
const CRYPT_KEYSTORE_MIN_PASSWORD_LENGTH = 8;
const threadName = "Keystore";
const CRYPT_KEYSTORE_RESET_CONFIRMATION_MESSAGE =
  "Resetting the keychain password will wipe your current persistent keychain entries. Continue?";
const CRYPT_KEYSTORE_MODE_SESSION = "session";
const CRYPT_KEYSTORE_MODE_PERSISTENT = "persistent";
const SESSION_KEYCHAIN_LABEL = "session keychain";
const SESSION_SECRET_KEY_HINTS = [
  "password",
  "passwd",
  "passphrase",
  "secret",
  "credential",
  "token",
  "authorization",
  "auth",
  "username",
  "user",
  "login",
  "apikey",
  "api_key",
  "api-key",
  "cookie",
  "session",
  "sessionid",
  "set_cookie",
  "set-cookie",
];
const SESSION_SECRET_IGNORE_KEY_HINTS = [
  "encrypted",
  "length",
  "checksum",
  "version",
  "port",
  "ip",
  "mac",
  "ttl",
  "window",
  "sequence",
  "ack",
  "timestamp",
  "frame",
  "packet",
];
const SESSION_AUTO_BUILD_CHUNK_SIZE = 50;
const SESSION_TOKEN_SCAN_WORKER_CHUNK_SIZE = 120;
const SESSION_SCAN_HYDRATED_PACKET_CACHE_LIMIT = 4096;

let goodiesStash = null;

// Creates keystore panel.
function createKeystorePanel({
  statusUpdate,
  writeLogEntry,
  doError,
  logErrorEntry,
  getCapturedPackets,
  getJsonCapture,
  setActiveMainTab,
  MAIN_TAB_KEYSTORE,
  parseDataToolsInput,
  decodeHttpFromBytes,
  extractCookieJarEntriesFromHttpFields,
  getTrimmedSelectionText,
  hideConvertContextMenu,
  getActiveContextConversionText,
  getApplyCryptCertificateText,
  getApplyCryptPrivateKeyText,
  openExternalUrl,
}) {
  let cryptPersistentKeystoreEntries = [];
  let cryptSessionKeystoreEntries = [];
  let cryptActiveKeystoreMode = CRYPT_KEYSTORE_MODE_SESSION;
  let cryptKeystoreUnlockKeyMaterial = null;
  let cryptKeystoreUnlockDialogResolver = null;
  let cryptKeystoreUnlockDialogMode = "unlock";
  let cryptManualUriDialogResolver = null;
  let cryptManualUriDialogMode = CRYPT_KEYSTORE_MODE_SESSION;
  let sessionRebuildGeneration = 0;
  const sessionScanHydratedPacketCache = new Map();

  function setBoundedCacheEntry(cacheMap, key, value, limit) {
    if (!cacheMap || !key) return;
    if (cacheMap.has(key)) {
      cacheMap.delete(key);
    }
    cacheMap.set(key, value);
    while (cacheMap.size > limit) {
      const oldestKey = cacheMap.keys().next().value;
      if (!oldestKey) break;
      cacheMap.delete(oldestKey);
    }
  }

  function clearSessionScanCaches() {
    sessionScanHydratedPacketCache.clear();
  }

  function generateCryptEntryId() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      return window.crypto.randomUUID();
    }
    if (window.crypto && typeof window.crypto.getRandomValues === "function") {
      const bytes = window.crypto.getRandomValues(new Uint8Array(16));
      const hex = Array.from(bytes, (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join("");
      return `${Date.now()}-${hex}`;
    }
    return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  }

  function toBase64(bytes) {
    return window.btoa(
      Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""),
    );
  }

  function fromBase64(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }



  async function isItAGoodie(string) {
    // this function loads a file full of goodies (one per line) and returns it as an array of strings, filtering out empty lines and comments
    // then it checks to see if string is one of the goodies, if so, it returns the input string, else it returns an empty string
    const chunkSize = 25;
    if (!goodiesStash) {
      goodiesStash = await window.goodiesapi.getGoodies();
    }
    // this probably should be done in parallel because the list is long
    function listInChunks(array, chunkSize) {
      const chunks = [];
      for (let i = 0; i < array.length; i += chunkSize) {
        chunks.push(array.slice(i, i + chunkSize));
      }
      return chunks;
    }
    const goodiesChunks = listInChunks(goodiesStash, chunkSize);
    const promises = goodiesChunks.map((chunk) => {
      return new Promise((resolve) => {
        const worker = new Worker(new URL("./goodies-worker.js", import.meta.url));
        worker.onmessage = (event) => {
          const { goodie } = event.data;
          if (goodie) {
            resolve(true);
          } else {
            resolve(false);
          }
          worker.terminate();
        };
        worker.postMessage({ input: string, goodies: chunk });
        if (chunk.length === 0) {
          resolve(false);
          worker.terminate();
        }
      });
    });
    return Promise.all(promises).then((results) => results.some((result) => result));
  }

  async function importCryptKeyMaterial(passphrase) {
    return window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(passphrase),
      { name: "PBKDF2" },
      false,
      ["deriveKey"],
    );
  }

  async function deriveCryptKey(passphraseOrKeyMaterial, saltBytes, usage) {
    const keyMaterial =
      typeof passphraseOrKeyMaterial === "string"
        ? await importCryptKeyMaterial(passphraseOrKeyMaterial)
        : passphraseOrKeyMaterial;
    return window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: 600000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      [usage],
    );
  }

  async function encryptCryptContent(content, passphrase) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveCryptKey(passphrase, salt, "encrypt");
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(content),
    );
    return {
      encryptedContent: toBase64(new Uint8Array(ciphertext)),
      salt: toBase64(salt),
      iv: toBase64(iv),
    };
  }

  async function decryptCryptContent(entry, passphrase) {
    const key = await deriveCryptKey(
      passphrase,
      fromBase64(entry.salt),
      "decrypt",
    );
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(entry.iv) },
      key,
      fromBase64(entry.encryptedContent),
    );
    return new TextDecoder().decode(new Uint8Array(decrypted));
  }

  function openCryptKeystoreDb() {
    return new Promise((resolve, reject) => {
      const request = window.indexedDB.open(
        CRYPT_KEYSTORE_DB_NAME,
        CRYPT_KEYSTORE_DB_VERSION,
      );
      request.onerror = () => reject(request.error);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(CRYPT_KEYSTORE_STORE_NAME)) {
          db.createObjectStore(CRYPT_KEYSTORE_STORE_NAME);
        }
      };
      request.onsuccess = () => resolve(request.result);
    });
  }

  function runIdbRequest(request) {
    return new Promise((resolve, reject) => {
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
    });
  }

  function waitForIdbTransaction(transaction) {
    return new Promise((resolve, reject) => {
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  }

  async function loadCryptKeystore() {
    try {
      const db = await openCryptKeystoreDb();
      const transaction = db.transaction(CRYPT_KEYSTORE_STORE_NAME, "readonly");
      const store = transaction.objectStore(CRYPT_KEYSTORE_STORE_NAME);
      const storedRecord = await runIdbRequest(
        store.get(CRYPT_KEYSTORE_RECORD_KEY),
      );
      db.close();
      return storedRecord || null;
    } catch (error) {
      logErrorEntry("crypt-keystore-load", error);
      return null;
    }
  }

  async function saveCryptKeystoreRecord(storedRecord) {
    try {
      const db = await openCryptKeystoreDb();
      const transaction = db.transaction(
        CRYPT_KEYSTORE_STORE_NAME,
        "readwrite",
      );
      const store = transaction.objectStore(CRYPT_KEYSTORE_STORE_NAME);
      store.put(storedRecord, CRYPT_KEYSTORE_RECORD_KEY);
      await waitForIdbTransaction(transaction);
      db.close();
    } catch (error) {
      logErrorEntry("crypt-keystore-save", error);
      doError("Could not save the persistent local keystore.");
    }
  }

  function sanitizePersistentEntry(entry) {
    if (!entry || typeof entry !== "object") return null;
    const content =
      typeof entry.content === "string"
        ? entry.content
        : entry.encryptedContent && entry.salt && entry.iv
          ? null
          : "";
    return {
      id: entry.id || generateCryptEntryId(),
      type: String(entry.type || "secret"),
      label: String(entry.label || "Untitled"),
      source: String(entry.source || "manual"),
      content,
      encryptedContent: entry.encryptedContent
        ? String(entry.encryptedContent)
        : "",
      salt: entry.salt ? String(entry.salt) : "",
      iv: entry.iv ? String(entry.iv) : "",
      summary: String(entry.summary || ""),
      createdAt: String(entry.createdAt || new Date().toISOString()),
    };
  }

  async function loadPersistentCryptKeystoreEntries(
    passphrase,
    existingRecord,
  ) {
    const storedRecord =
      existingRecord === undefined ? await loadCryptKeystore() : existingRecord;
    if (!storedRecord) return [];

    if (
      storedRecord?.schemaVersion === CRYPT_KEYSTORE_SCHEMA_VERSION &&
      storedRecord?.encryptedPayload &&
      storedRecord?.salt &&
      storedRecord?.iv
    ) {
      const decryptedJson = await decryptCryptContent(
        {
          encryptedContent: String(storedRecord.encryptedPayload),
          salt: String(storedRecord.salt),
          iv: String(storedRecord.iv),
        },
        passphrase,
      );
      const parsed = JSON.parse(decryptedJson);
      if (!Array.isArray(parsed)) return [];
      return parsed.map(sanitizePersistentEntry).filter(Boolean);
    }

    const legacyEntries = Array.isArray(storedRecord?.entries)
      ? storedRecord.entries.map(sanitizePersistentEntry).filter(Boolean)
      : [];
    await savePersistentCryptKeystoreEntries(legacyEntries, passphrase);
    return legacyEntries;
  }

  async function savePersistentCryptKeystoreEntries(entries, passphrase) {
    const encryptedPayload = await encryptCryptContent(
      JSON.stringify(entries),
      passphrase,
    );
    await saveCryptKeystoreRecord({
      schemaVersion: CRYPT_KEYSTORE_SCHEMA_VERSION,
      encryptedPayload: encryptedPayload.encryptedContent,
      salt: encryptedPayload.salt,
      iv: encryptedPayload.iv,
      updatedAt: new Date().toISOString(),
    });
  }

  function getActiveCryptKeystoreEntries() {
    return cryptActiveKeystoreMode === CRYPT_KEYSTORE_MODE_SESSION
      ? cryptSessionKeystoreEntries
      : cryptPersistentKeystoreEntries;
  }

  function getActiveKeystoreLabel() {
    return cryptActiveKeystoreMode === CRYPT_KEYSTORE_MODE_SESSION
      ? SESSION_KEYCHAIN_LABEL
      : "persistent keychain";
  }

  function normalizeOpenableLink(value) {
    const normalized = normalizeSessionSecretValue(value);
    if (!normalized) return "";
    try {
      const parsed = new URL(normalized);
      if (parsed.protocol === "http:" || parsed.protocol === "https:") {
        return parsed.href;
      }
    } catch {
      return "";
    }
    return "";
  }

  function canEntryOpenInBrowser(entry) {
    return !!normalizeOpenableLink(entry?.content);
  }

  function updateCryptKeystoreWorkspaceState(activeEntry = null) {
    const isPersistentMode =
      cryptActiveKeystoreMode === CRYPT_KEYSTORE_MODE_PERSISTENT;
    const saveCertBtn = document.getElementById("crypt-save-cert-keystore-btn");
    const saveKeyBtn = document.getElementById("crypt-save-key-keystore-btn");
    const saveSecretBtn = document.getElementById(
      "crypt-save-secret-keystore-btn",
    );
    const sendToPersistentBtn = document.getElementById(
      "crypt-send-to-persistent-btn",
    );
    const deleteBtn = document.getElementById(
      "crypt-delete-keystore-entry-btn",
    );
    if (cryptActiveKeystoreMode === CRYPT_KEYSTORE_MODE_SESSION) {
      document.getElementById("keystore-filter-block").style.display = "block";
    } else {
      document.getElementById("keystore-filter-block").style.display = "none";
    }
    const openLinkBtn = document.getElementById("crypt-open-link-btn");
    saveCertBtn.disabled = !isPersistentMode;
    saveKeyBtn.disabled = !isPersistentMode;
    saveSecretBtn.disabled = !isPersistentMode;
    sendToPersistentBtn.disabled = isPersistentMode;
    deleteBtn.disabled = !isPersistentMode;
    if (openLinkBtn) {
      openLinkBtn.disabled = !canEntryOpenInBrowser(activeEntry);
    }
    const unlockStatusEl = document.getElementById(
      "crypt-keystore-unlock-status",
    );
    unlockStatusEl.textContent = isPersistentMode
      ? "Persistent keychain is unlocked for this app session."
      : "Session keychain is auto-populated from decodable packet secrets and cert-tab imports.";
  }

  function renderCryptKeystoreDetails(entry) {
    const detailsEl = document.getElementById("crypt-keystore-details");
    if (!entry) {
      detailsEl.textContent = `No entries available in ${getActiveKeystoreLabel()}.`;
      updateCryptKeystoreWorkspaceState(null);
      return;
    }
    const normalizedContent = normalizeSessionSecretValue(entry.content);
    const contentPreview = normalizedContent
      ? normalizedContent.replace(/\r?\n/g, " ").slice(0, 140)
      : "";
    detailsEl.textContent = [
      `Keychain: ${getActiveKeystoreLabel()}`,
      `Type: ${entry.type}`,
      `Label: ${entry.label}`,
      `Source: ${entry.source}`,
      entry.packetIndex !== undefined ? `Packet: ${entry.packetIndex}` : null,
      `Saved: ${entry.createdAt}`,
      entry.summary ? `Summary: ${entry.summary}` : "Summary: n/a",
      normalizedContent
        ? `Content bytes: ${new TextEncoder().encode(normalizedContent).length}`
        : "Content bytes: 0",
      contentPreview ? `Content preview: ${contentPreview}` : "Content preview: (empty)",
    ]
      .filter(Boolean)
      .join("\n");
    updateCryptKeystoreWorkspaceState(entry);
  }

  function renderCryptKeystoreList(listEntries = null) {
    const listEl = document.getElementById("crypt-keystore-list");
    const activeEntries = listEntries || getActiveCryptKeystoreEntries();
    listEl.replaceChildren();
    if (!activeEntries.length) {
      const option = document.createElement("option");
      option.textContent = `No entries in ${getActiveKeystoreLabel()}.`;
      option.disabled = true;
      listEl.appendChild(option);
      renderCryptKeystoreDetails(null);
      return;
    }

    activeEntries.forEach((entry, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = `[${entry.type}] ${entry.label}`;
      listEl.appendChild(option);
    });
    listEl.selectedIndex = 0;
    renderCryptKeystoreDetails(activeEntries[0]);
  }

  function normalizeSessionSecretValue(value) {
    if (value === null || value === undefined) return "";
    const normalized =
      typeof value === "string"
        ? value
        : typeof value === "number"
          ? String(value)
          : "";
    return normalized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
  }

  function decodeHttpBasicAuth(rawValue) {
    if (!rawValue || !/^basic\s+/i.test(rawValue)) return "";
    const encoded = rawValue.replace(/^basic\s+/i, "").trim();
    if (!encoded) return "";
    try {
      const decoded = window.atob(encoded);
      return decoded.includes(":") ? decoded.trim() : "";
    } catch (error) {
      logErrorEntry("crypt-keystore-basic-auth-decode", error);
      return "";
    }
  }

  function extractTransportPorts(transportData, packetInfo) {
    const rawPorts = [
      transportData?.["tcp.src.port"] ?? null,
      transportData?.["tcp.dst.port"],
      transportData?.["udp.src.port"],
      transportData?.["udp.dst.port"],
      transportData?.["sctp.src.port"],
      transportData?.["sctp.dst.port"],
      transportData?.["Source port"],
      transportData?.["Destination port"],
      transportData?.tcp?.["Source port"],
      transportData?.tcp?.["Destination port"],
      transportData?.udp?.["Source port"],
      transportData?.udp?.["Destination port"],
      packetInfo?.["Transport Layer"]?.["tcp.src.port"],
      packetInfo?.["Transport Layer"]?.["tcp.dst.port"],
      packetInfo?.["Transport Layer"]?.["udp.src.port"],
      packetInfo?.["Transport Layer"]?.["udp.dst.port"],
      packetInfo?.["Transport Layer"]?.["sctp.src.port"],
      packetInfo?.["Transport Layer"]?.["sctp.dst.port"],
      packetInfo?.["Transport Layer"]?.["Source port"],
      packetInfo?.["Transport Layer"]?.["Destination port"],
      packetInfo?.["TCP"]?.["tcp.src.port"],
      packetInfo?.["TCP"]?.["tcp.dst.port"],
      packetInfo?.["UDP"]?.["udp.src.port"],
      packetInfo?.["UDP"]?.["udp.dst.port"],
      packetInfo?.["SCTP"]?.["sctp.src.port"],
      packetInfo?.["SCTP"]?.["sctp.dst.port"],
      packetInfo?.["TCP"]?.["Source port"],
      packetInfo?.["TCP"]?.["Destination port"],
      packetInfo?.["tcp"]?.["Source port"],
      packetInfo?.["tcp"]?.["Destination port"],
      packetInfo?.["UDP"]?.["Source port"],
      packetInfo?.["UDP"]?.["Destination port"],
      packetInfo?.["udp"]?.["Source port"],
      packetInfo?.["udp"]?.["Destination port"],
    ];

    const uniquePorts = new Set();
    rawPorts.forEach((value) => {
      const port = Number(value);
      if (Number.isFinite(port) && port > 0) {
        uniquePorts.add(port);
      }
    });

    return Array.from(uniquePorts);
  }

  function isRelevantProtocolPort(protocol, port) {
    const candidatePorts = Array.isArray(port) ? port : [port];
    if (!candidatePorts.length) return false;
    const lowerProtocol = String(protocol || "").toLowerCase();

    const hasPort = (expectedPort) =>
      candidatePorts.some((candidatePort) => Number(candidatePort) === expectedPort);

    if (lowerProtocol.includes("ftp")) {
      return hasPort(21);
    }
    if (lowerProtocol.includes("smtp")) {
      return hasPort(25) || hasPort(465) || hasPort(587);
    }
    if (lowerProtocol.includes("imap")) {
      return hasPort(143) || hasPort(993);
    }
    if (lowerProtocol.includes("rdp")) {
      return hasPort(3389);
    }
    if (lowerProtocol.includes("sip")) {
      return hasPort(5060) || hasPort(5061);
    }

    return false;
  }

  function isLikelyEmailAddress(value) {
    return /^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/.test(
      normalizeSessionSecretValue(value),
    );
  }

  function normalizeCredentialToken(token) {
    const trimmed = normalizeSessionSecretValue(token);
    if (!trimmed) return "";
    return trimmed
      .replace(/^<(.+)>$/, "$1")
      .replace(/^"(.+)"$/, "$1")
      .trim();
  }

  function splitCredentialArguments(argumentText) {
    const source = normalizeSessionSecretValue(argumentText);
    if (!source) return [];
    const tokens = [];
    const tokenPattern = /"([^"\\]*(?:\\.[^"\\]*)*)"|(\S+)/g;
    let match;
    while ((match = tokenPattern.exec(source)) !== null) {
      const rawToken =
        match[1] !== undefined
          ? match[1].replace(/\\"/g, '"')
          : match[2] || "";
      const normalized = normalizeCredentialToken(rawToken);
      if (normalized) tokens.push(normalized);
    }
    return tokens;
  }

  function extractHttpBasicCredentialEntries(rawAuthValue) {
    const decoded = decodeHttpBasicAuth(rawAuthValue);
    if (!decoded) return [];
    const separatorIndex = decoded.indexOf(":");
    if (separatorIndex < 0) return [];
    const username = normalizeCredentialToken(decoded.slice(0, separatorIndex));
    const password = normalizeCredentialToken(decoded.slice(separatorIndex + 1));
    const entries = [];
    if (username) {
      entries.push({
        type: isLikelyEmailAddress(username) ? "email" : "secret",
        label: "HTTP Basic Username",
        source: "session-auto-http-basic-user",
        content: username,
        protocol: "HTTP",
      });
    }
    if (password) {
      entries.push({
        type: "secret",
        label: "HTTP Basic Password",
        source: "session-auto-http-basic-password",
        content: password,
        protocol: "HTTP",
      });
    }
    return entries;
  }

  function extractStructuredFtpCredentialEntries(packetInfo) {
    const ftpCandidates = [
      packetInfo?.["Transport Layer"]?.FTP,
      packetInfo?.["Transport Layer"]?.ftp,
      packetInfo?.FTP,
      packetInfo?.ftp,
      packetInfo?.TCP?.FTP,
      packetInfo?.TCP?.ftp,
      packetInfo?.tcp?.FTP,
      packetInfo?.tcp?.ftp,
    ].filter((candidate) => candidate && typeof candidate === "object");

    for (const ftpData of ftpCandidates) {
      const ftpCredentials =
        ftpData?.Credentials && typeof ftpData.Credentials === "object"
          ? ftpData.Credentials
          : null;
      const credentialUser = normalizeCredentialToken(ftpCredentials?.username);
      const credentialPassword = normalizeCredentialToken(
        ftpCredentials?.password,
      );
      if (credentialUser || credentialPassword) {
        return {
          username: credentialUser || "",
          password: credentialPassword || "",
        };
      }

      const command = normalizeSessionSecretValue(
        ftpData?.Command || ftpData?.command || ftpData?.["ftp.command"],
      ).toUpperCase();
      const argument = normalizeCredentialToken(
        ftpData?.Argument || ftpData?.argument || ftpData?.["ftp.argument"],
      );
      if (!command || !argument) continue;
      if (command === "USER") {
        return { username: argument, password: "" };
      }
      if (command === "PASS") {
        return { username: "", password: argument };
      }
    }

    return null;
  }

  function extractPlaintextProtocolCredentialEntries({
    protocol,
    pathKey,
    rawText,
    port,
    packetInfo,
  }) {
    const text = normalizeSessionSecretValue(rawText);
    if (!text) return [];

    const lowerProtocol = String(protocol || "").toLowerCase();
    const upperProtocol = String(protocol || "").toUpperCase() || "Unknown";
    const lowerPath = String(pathKey || "").toLowerCase();
    const entries = [];
    const discovered = new Set();
    const structuredFtpCredentials = extractStructuredFtpCredentialEntries(
      packetInfo,
    );

    const addEntry = ({ type = "secret", label, source, content, protocolName }) => {
      const normalizedContent = normalizeCredentialToken(content);
      const normalizedLabel = normalizeSessionSecretValue(label);
      if (!normalizedContent || !normalizedLabel) return;
      const fingerprint = `${normalizedLabel}|${normalizedContent}`;
      if (discovered.has(fingerprint)) return;
      discovered.add(fingerprint);
      entries.push({
        type,
        label: normalizedLabel,
        source: source || "session-auto-protocol-credential",
        content: normalizedContent,
        protocol: protocolName || upperProtocol,
      });
    };

    const addUserPasswordEntries = (serviceLabel, username, password, protocolName) => {
      const normalizedUser = normalizeCredentialToken(username);
      const normalizedPassword = normalizeCredentialToken(password);
      if (normalizedUser) {
        addEntry({
          type: isLikelyEmailAddress(normalizedUser) ? "email" : "secret",
          label: `${serviceLabel} Username`,
          source: `session-auto-${serviceLabel.toLowerCase()}-username`,
          content: normalizedUser,
          protocolName,
        });
      }
      if (normalizedPassword) {
        addEntry({
          type: "secret",
          label: `${serviceLabel} Password`,
          source: `session-auto-${serviceLabel.toLowerCase()}-password`,
          content: normalizedPassword,
          protocolName,
        });
      }
    };

    if (
      lowerProtocol.includes("http") ||
      lowerPath.includes("authorization") ||
      lowerPath.includes("basic")
    ) {
      extractHttpBasicCredentialEntries(text).forEach((entry) => {
        addEntry({
          type: entry.type,
          label: entry.label,
          source: entry.source,
          content: entry.content,
          protocolName: entry.protocol,
        });
      });
    }

    if (
      !!structuredFtpCredentials ||
      /^\s*(USER|PASS)\s+.+$/im.test(text) ||
      lowerProtocol.includes("ftp") ||
      (lowerPath.includes("ftp") && isRelevantProtocolPort("ftp", port))
    ) {
      if (structuredFtpCredentials) {
        addUserPasswordEntries(
          "TCP FTP.credentials.username",
          structuredFtpCredentials.username,
          structuredFtpCredentials.password,
          "TCP FTP.credentials.password",
        );
      }

      const ftpUserMatch = text.match(/^\s*USER\s+(.+)$/im);
      const ftpPassMatch = text.match(/^\s*PASS\s+(.+)$/im);
      if (ftpUserMatch || ftpPassMatch) {
        addUserPasswordEntries(
          "TCP FTP.credentials.username",
          ftpUserMatch?.[1] || "",
          ftpPassMatch?.[1] || "",
          "TCP FTP.credentials.password",
        );
      }
      if (isRelevantProtocolPort("ftp", port)) {
        if (
          lowerPath.includes("user") ||
          lowerPath.includes("username") ||
          lowerPath.includes("login")
        ) {
          addUserPasswordEntries("TCP FTP.credentials.username", text, "", "TCP FTP.credentials.password");
        }
        if (lowerPath.includes("pass") || lowerPath.includes("password")) {
          addUserPasswordEntries("TCP FTP.credentials.username", "", text, "TCP FTP.credentials.password");
        }
      }
    }

    if (
      lowerProtocol.includes("rdp") ||
      (lowerPath.includes("rdp") && isRelevantProtocolPort("rdp", port))
    ) {
      const rdpUserMatch = text.match(/\b(?:user(?:name)?|login)\s*[:=]\s*(\S+)/i);
      const rdpPassMatch = text.match(/\b(?:pass(?:word)?|pwd)\s*[:=]\s*(\S+)/i);
      if ((rdpUserMatch || rdpPassMatch) && isRelevantProtocolPort("rdp", port)) {
        addUserPasswordEntries(
          "TCP RDP.credentials.username",
          rdpUserMatch?.[1] || "",
          rdpPassMatch?.[1] || "",
          "TCP RDP.credentials.password",
        );
      }
      if (isRelevantProtocolPort("rdp", port)) {
        if (
          lowerPath.includes("user") ||
          lowerPath.includes("username") ||
          lowerPath.includes("login")
        ) {
          addUserPasswordEntries("TCP RDP.credentials.username", text, "", "TCP RDP.credentials.password");
        }
        if (lowerPath.includes("pass") || lowerPath.includes("password")) {
          addUserPasswordEntries("TCP RDP.credentials.username", "", text, "TCP RDP.credentials.password");
        }
      }
    }

    if (
      lowerProtocol.includes("imap") ||
      (lowerPath.includes("imap") && isRelevantProtocolPort("imap", port))
    ) {
      const imapLoginMatch = text.match(/^\s*\S+\s+LOGIN\s+(.+)$/im);
      if (imapLoginMatch?.[1] && isRelevantProtocolPort("imap", port)) {
        const imapTokens = splitCredentialArguments(imapLoginMatch[1]);
        if (imapTokens.length >= 2) {
          addUserPasswordEntries(
            "IMAP",
            imapTokens[0],
            imapTokens[1],
            "IMAP",
          );
        }
      }
      if (isRelevantProtocolPort("imap", port)) {
        if (lowerPath.includes("email") || lowerPath.includes("user")) {
          addEntry({
            type: isLikelyEmailAddress(text) ? "email" : "secret",
            label: "IMAP Username",
            source: "session-auto-imap-username",
            content: text,
            protocolName: "IMAP",
          });
        }
        if (lowerPath.includes("pass") || lowerPath.includes("password")) {
          addEntry({
            type: "secret",
            label: "IMAP Password",
            source: "session-auto-imap-password",
            content: text,
            protocolName: "IMAP",
          });
        }
      }
    }

    if (
      lowerProtocol.includes("smtp") ||
      (lowerPath.includes("smtp") && isRelevantProtocolPort("smtp", port))
    ) {
      const smtpAuthMatch = text.match(
        /^\s*AUTH\s+(?:LOGIN|PLAIN)\s+(.+)$/im,
      );
      if (smtpAuthMatch?.[1] && isRelevantProtocolPort("smtp", port)) {
        const smtpTokens = splitCredentialArguments(smtpAuthMatch[1]);
        if (smtpTokens.length >= 2) {
          addUserPasswordEntries(
            "TCP SMTP.credentials.username",
            smtpTokens[0],
            smtpTokens[1],
            "TCP SMTP.credentials.password",
          );
        }
      }
      if (isRelevantProtocolPort("smtp", port)) {
        if (lowerPath.includes("email") || lowerPath.includes("user")) {
          addEntry({
            type: isLikelyEmailAddress(text) ? "email" : "secret",
            label: "SMTP Username",
            source: "session-auto-smtp-username",
            content: text,
            protocolName: "SMTP",
          });
        }
        if (lowerPath.includes("pass") || lowerPath.includes("password")) {
          addEntry({
            type: "secret",
            label: "SMTP Password",
            source: "session-auto-smtp-password",
            content: text,
            protocolName: "SMTP",
          });
        }
      }
    }

    if (
      lowerProtocol.includes("sip") ||
      (lowerPath.includes("sip") && isRelevantProtocolPort("sip", port))
    ) {
      // Extract SIP Authorization header credentials
      const authMatch = text.match(
        /^\s*(?:Authorization|Proxy-Authorization)\s*[:=]\s*(.+)$/im,
      );
      if (authMatch?.[1] && isRelevantProtocolPort("sip", port)) {
        const authValue = authMatch[1].trim();
        // Extract username from digest auth (username="username_value")
        const usernameMatch = authValue.match(/username\s*=\s*"?([^",\s]+)"?/i);
        if (usernameMatch?.[1]) {
          addEntry({
            type: isLikelyEmailAddress(usernameMatch[1]) ? "email" : "secret",
            label: "SIP Username",
            source: "session-auto-sip-username",
            content: usernameMatch[1],
            protocolName: "SIP",
          });
        }
        // Extract password/response from digest auth (response="...")
        const responseMatch = authValue.match(/response\s*=\s*"([^"]+)"/i);
        if (responseMatch?.[1]) {
          addEntry({
            type: "secret",
            label: "SIP Digest Response (hashed)",
            source: "session-auto-sip-password",
            content: responseMatch[1],
            protocolName: "SIP",
          });
        }
        // For basic auth in SIP (rare but possible)
        if (authValue.toLowerCase().includes("basic")) {
          const basicMatch = authValue.match(/basic\s+([A-Za-z0-9+/=]+)/i);
          if (basicMatch?.[1]) {
            try {
              const decodedBasic = atob(basicMatch[1]);
              const [basicUser, basicPass] = decodedBasic.split(":");
              if (basicUser) {
                addEntry({
                  type: isLikelyEmailAddress(basicUser) ? "email" : "secret",
                  label: "SIP Basic Auth Username",
                  source: "session-auto-sip-basic-username",
                  content: basicUser,
                  protocolName: "SIP",
                });
              }
              if (basicPass) {
                addEntry({
                  type: "secret",
                  label: "SIP Basic Auth Password",
                  source: "session-auto-sip-basic-password",
                  content: basicPass,
                  protocolName: "SIP",
                });
              }
            } catch (e) {
              // Ignore if base64 decode fails
            }
          }
        }
      }
      // Check for Authorization/Proxy-Authorization header in pathKey
      if (isRelevantProtocolPort("sip", port)) {
        if (lowerPath.includes("authorization")) {
          // Extract credentials from Authorization header value in path
          const usernameMatch = text.match(/username\s*=\s*"?([^",\s]+)"?/i);
          if (usernameMatch?.[1]) {
            addEntry({
              type: isLikelyEmailAddress(usernameMatch[1]) ? "email" : "secret",
              label: "SIP Username",
              source: "session-auto-sip-username",
              content: usernameMatch[1],
              protocolName: "SIP",
            });
          }
          const responseMatch = text.match(/response\s*=\s*"([^"]+)"/i);
          if (responseMatch?.[1]) {
            addEntry({
              type: "secret",
              label: "SIP Digest Response (hashed)",
              source: "session-auto-sip-password",
              content: responseMatch[1],
              protocolName: "SIP",
            });
          }
        }
      }
    }

    return entries;
  }

  function hashContentForDeduplication(content) {
    let hash = 2166136261;
    for (let index = 0; index < content.length; index++) {
      hash ^= content.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16);
  }

  function detectSessionTokenMatches(rawText, pathKey = "") {
    const matches = [];
    const text = normalizeSessionSecretValue(rawText);
    if (!text) return matches;
    const lowerPath = String(pathKey || "").toLowerCase();

    const addMatch = (type, token) => {
      const normalizedToken = normalizeSessionSecretValue(token);
      if (!normalizedToken) return;
      matches.push({ type, content: normalizedToken });
    };

    const regexExtract = (regex, type) => {
      regex.lastIndex = 0;
      let regexMatch;
      while ((regexMatch = regex.exec(text)) !== null) {
        addMatch(type, regexMatch[0]);
      }
    };

    regexExtract(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "aws-access-key");
    regexExtract(/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, "github-token");
    regexExtract(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, "github-token");
    regexExtract(/\bmfa\.[A-Za-z0-9_-]{80,}\b/g, "discord-token");
    regexExtract(
      /\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{20,}\b/g,
      "discord-token",
    );
    regexExtract(
      /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
      "jwt-token",
    );
    regexExtract(/\bya29\.[A-Za-z0-9._-]{20,}\b/g, "oauth-token");

    if (/\bBearer\s+[A-Za-z0-9._~-]{20,}\b/i.test(text)) {
      const bearerToken = text.replace(/^.*?\bBearer\s+/i, "").trim();
      addMatch("oauth-token", bearerToken);
    }

    const hasLikelySecretKeyName =
      lowerPath.includes("token") ||
      lowerPath.includes("apikey") ||
      lowerPath.includes("api_key") ||
      lowerPath.includes("api-key") ||
      lowerPath.includes("oauth") ||
      lowerPath.includes("authorization") ||
      lowerPath.includes("auth") ||
      lowerPath.includes("discord") ||
      lowerPath.includes("github") ||
      lowerPath.includes("azure") ||
      lowerPath.includes("aws") ||
      lowerPath.includes("secret") ||
      lowerPath.includes("accountkey");

    if (hasLikelySecretKeyName) {
      const normalizedCandidate = text.replace(/^bearer\s+/i, "").trim();
      if (normalizedCandidate.length >= 20) {
        let inferredType = "api-token";
        if (lowerPath.includes("oauth")) inferredType = "oauth-token";
        else if (lowerPath.includes("discord")) inferredType = "discord-token";
        else if (lowerPath.includes("github")) inferredType = "github-token";
        else if (lowerPath.includes("aws")) inferredType = "aws-secret-key";
        else if (lowerPath.includes("azure") || lowerPath.includes("accountkey")) {
          inferredType = "azure-key";
        }
        addMatch(inferredType, normalizedCandidate);
      }
    }

    const accountKeyMatch = text.match(/AccountKey=([^;\s]+)/i);
    if (accountKeyMatch?.[1]) {
      addMatch("azure-key", accountKeyMatch[1]);
    }

    if (/^[A-Za-z0-9+/]{43}=$/.test(text) || /^[A-Za-z0-9+/]{86}==$/.test(text)) {
      if (lowerPath.includes("azure") || lowerPath.includes("accountkey")) {
        addMatch("azure-key", text);
      }
    }

    if (/^[A-Za-z0-9/+=]{40}$/.test(text) && lowerPath.includes("aws")) {
      addMatch("aws-secret-key", text);
    }
    if (shouldIncludeSessionSecretValue(text)) {
      addMatch("goodie", text);
    }
    return matches;
  }

  function normalizeUriCandidate(uri) {
    if (uri === null || uri === undefined) return "";
    // try to filter out CSS and HTML crap
    if (typeof uri === "string") {
      uri = uri.trim();
      if (
        uri.startsWith("url(") ||
        uri.startsWith("URL(") ||
        uri.startsWith("href=") ||
        uri.startsWith("src=")
      ) {
        const match = uri.match(/["']?([^"')]+)["']?/);
        if (match?.[1]) {
          uri = match[1].trim();
        }
      }
    }
    // strip out anything with trailinling punctuation thats not uri related
    if (uri.startsWith("data:") || uri.startsWith("blob:") || uri.startsWith("file:")) {
      return uri;
    }
    if (uri.startsWith("http://") || uri.startsWith("https://")) {
      try {
        const parsed = new URL(uri);
        return parsed.href;
      } catch {
        return "";
      }
    }
    else if (uri.startsWith("ftp://")) {
      try {
        const parsed = new URL(uri);
        return parsed.href;
      } catch {
        return "";
      }
    }
    else if (uri.startsWith("mailto:")) {
      try {
        const parsed = new URL(uri);
        return parsed.href;
      } catch {
        return "";
      }
    }
    if (uri.startsWith("sip:")) {
      try {
        const parsed = new URL(uri);
        return parsed.href;
      } catch {
        return "";
      }
    }
    if (uri.startsWith("tel:")) {
      try {
        const parsed = new URL(uri);
        return parsed.href;
      } catch {
        return "";
      }
    }
    else if (/^[a-z][a-z0-9+.-]*:\/\//.test(uri)) {
      try {
        const parsed = new URL(uri);
        return parsed.href;
      } catch {
        return "";
      }
    }
    return "";
  }

  function extractUriCandidatesFromText(rawText) {
    const sourceText = normalizeSessionSecretValue(rawText);
    if (!sourceText) return [];
    const candidatePattern = /\b[a-z][a-z0-9+.-]*:[^\s<>"']+/gi;
    const discovered = new Set();
    let match;
    while ((match = candidatePattern.exec(sourceText)) !== null) {
      const normalized = normalizeUriCandidate(match[0]);
      if (!normalized) continue;
      try {
        const parsed = new URL(normalized);
        if (parsed.protocol) {
          discovered.add(parsed.href);
        }
      } catch {
        continue;
      }
    }
    return Array.from(discovered);
  }

  function extractEmailCandidatesFromText(rawText) {
    const sourceText = normalizeSessionSecretValue(rawText);
    if (!sourceText) return [];
    const emailPattern = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
    const discovered = new Set();
    let match;
    while ((match = emailPattern.exec(sourceText)) !== null) {
      discovered.add(match[0].toLowerCase());
    }
    return Array.from(discovered);
  }

  function getHttpFieldValue(fields, fieldName) {
    if (!Array.isArray(fields) || !fieldName) return "";
    const match = fields.find(
      (field) =>
        field &&
        typeof field === "object" &&
        String(field.name || "").toLowerCase() === fieldName.toLowerCase(),
    );
    return normalizeSessionSecretValue(match?.value);
  }

  function inferHttpSchemeForPacket(packetInfo) {
    const destinationPort = Number(
      packetInfo?.["Transport Layer"]?.["tcp.dst.port"] ||
      packetInfo?.["Transport Layer"]?.["udp.dst.port"] ||
      packetInfo?.["Transport Layer"]?.["sctp.dst.port"] ||
      packetInfo?.["Transport Layer"]?.["Destination port"] ||
      packetInfo?.["TCP"]?.["tcp.dst.port"] ||
      packetInfo?.["tcp"]?.["tcp.dst.port"] ||
      packetInfo?.["TCP"]?.["Destination port"] ||
      packetInfo?.["tcp"]?.["Destination port"] ||
      0,
    );
    return destinationPort === 443 || destinationPort === 8443
      ? "https"
      : "http";
  }

  function normalizeHttpAuthority(authorityRaw) {
    const trimmed = normalizeSessionSecretValue(authorityRaw)
      .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "")
      .split("/")[0]
      .trim();
    if (!trimmed) return "";
    if (trimmed.startsWith("[")) return trimmed;
    const colonCount = (trimmed.match(/:/g) || []).length;
    if (colonCount > 1) {
      return `[${trimmed}]`;
    }
    return trimmed;
  }

  function extractHttpRequestLocationInput(httpCandidate) {
    if (!httpCandidate || typeof httpCandidate !== "object") {
      return null;
    }

    if (httpCandidate?.protocol === "HTTP" && Array.isArray(httpCandidate?.fields)) {
      const requestType = getHttpFieldValue(httpCandidate.fields, "Type");
      const requestTarget = getHttpFieldValue(httpCandidate.fields, "URL");
      const hostHeader = getHttpFieldValue(httpCandidate.fields, "Host");
      return {
        requestType,
        requestTarget,
        hostHeader,
      };
    }

    const requestType = normalizeSessionSecretValue(
      httpCandidate.Type || httpCandidate["http.type"],
    );
    const requestTarget = normalizeSessionSecretValue(
      httpCandidate.URL ||
      httpCandidate["http.url"] ||
      httpCandidate["Request URI"] ||
      httpCandidate["request.uri"],
    );
    const hostHeader = normalizeSessionSecretValue(
      httpCandidate.Host || httpCandidate["http.host"],
    );
    return {
      requestType,
      requestTarget,
      hostHeader,
    };
  }

  function buildHttpRequestLocationCandidates(httpCandidate, packetInfo, host) {
    const locationInput = extractHttpRequestLocationInput(httpCandidate);
    if (!locationInput) {
      return [];
    }

    const requestType = locationInput.requestType;
    const requestTarget = locationInput.requestTarget;
    const hostHeader = locationInput.hostHeader;
    if (requestType.toLowerCase() !== "request") {
      return [];
    }

    if (!requestTarget || requestTarget === "*") {
      return [];
    }

    const destinationIp = normalizeSessionSecretValue(
      packetInfo?.["IP"]?.["ip.dst.addr"],
      packetInfo?.["IP"]?.["Destination IP"],
    );
    const sourceIp = normalizeSessionSecretValue(packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"]);
    const fallbackHost = normalizeSessionSecretValue(host);
    const authority =
      normalizeHttpAuthority(hostHeader) ||
      normalizeHttpAuthority(destinationIp) ||
      normalizeHttpAuthority(sourceIp) ||
      normalizeHttpAuthority(fallbackHost);
    const scheme = inferHttpSchemeForPacket(packetInfo);

    const discovered = new Set();
    const candidates = [];
    const pushCandidate = (value, preferredType = "url") => {
      const normalizedValue = normalizeSessionSecretValue(value);
      if (!normalizedValue || discovered.has(normalizedValue)) return;
      discovered.add(normalizedValue);
      const candidateType = /^https?:\/\//i.test(normalizedValue)
        ? "url"
        : preferredType;
      candidates.push({
        type: candidateType,
        label: `${candidateType.toUpperCase()} ${normalizedValue}`,
        content: normalizedValue,
      });
    };

    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(requestTarget)) {
      try {
        pushCandidate(new URL(requestTarget).href, "url");
      } catch {
        pushCandidate(requestTarget, "uri");
      }
      return candidates;
    }

    pushCandidate(requestTarget, "uri");

    if (authority) {
      const base = `${scheme}://${authority}`;
      try {
        if (
          requestTarget.startsWith("/") ||
          requestTarget.startsWith("?") ||
          requestTarget.startsWith("#")
        ) {
          pushCandidate(new URL(requestTarget, base).href, "url");
        } else {
          pushCandidate(new URL(`/${requestTarget}`, base).href, "url");
        }
      } catch {
        const separator = requestTarget.startsWith("/") ? "" : "/";
        pushCandidate(`${base}${separator}${requestTarget}`, "url");
      }
    }

    return candidates;
  }

  function splitCookieHeaderCandidates(cookieHeader) {
    const normalizedHeader = normalizeSessionSecretValue(cookieHeader);
    if (!normalizedHeader) return [];
    return normalizedHeader
      .split(";")
      .map((part) => normalizeSessionSecretValue(part))
      .filter((part) => part.includes("="));
  }

  function extractCookieEntriesFromHttpMetadata(httpCandidate) {
    const discovered = new Set();
    const cookieEntries = [];
    const addCookieEntry = (entry) => {
      const normalizedEntry = normalizeSessionSecretValue(entry);
      if (!normalizedEntry || !normalizedEntry.includes("=")) return;
      if (discovered.has(normalizedEntry)) return;
      discovered.add(normalizedEntry);
      cookieEntries.push(normalizedEntry);
    };

    if (!httpCandidate || typeof httpCandidate !== "object") {
      return cookieEntries;
    }

    if (httpCandidate?.protocol === "HTTP" && Array.isArray(httpCandidate?.fields)) {
      extractCookieJarEntriesFromHttpFields(httpCandidate.fields).forEach(addCookieEntry);
      return cookieEntries;
    }

    const directCookieHeader = normalizeSessionSecretValue(
      httpCandidate.Cookie || httpCandidate["http.cookie"],
    );
    splitCookieHeaderCandidates(directCookieHeader).forEach(addCookieEntry);

    const directSetCookieHeader = normalizeSessionSecretValue(
      httpCandidate["Set-Cookie"] ||
      httpCandidate["set-cookie"] ||
      httpCandidate["http.set_cookie"],
    );
    if (directSetCookieHeader) {
      const firstPair = directSetCookieHeader.split(";")[0] || "";
      addCookieEntry(firstPair);
    }

    const credentials =
      httpCandidate.Credentials && typeof httpCandidate.Credentials === "object"
        ? httpCandidate.Credentials
        : null;
    if (!credentials) {
      return cookieEntries;
    }

    Object.entries(credentials).forEach(([key, value]) => {
      const normalizedKey = String(key || "").toLowerCase().trim();
      const normalizedValue = normalizeSessionSecretValue(value);
      if (!normalizedValue) return;
      if (normalizedKey === "cookie_raw") {
        splitCookieHeaderCandidates(normalizedValue).forEach(addCookieEntry);
        return;
      }
      if (normalizedKey === "set_cookie_raw") {
        const firstPair = normalizedValue.split(";")[0] || "";
        addCookieEntry(firstPair);
        return;
      }
      if (normalizedKey.startsWith("cookie.")) {
        const cookieName = normalizedKey.slice("cookie.".length).trim();
        if (!cookieName) return;
        addCookieEntry(`${cookieName}=${normalizedValue}`);
      }
    });

    return cookieEntries;
  }

  function extractSmbCredentialEntriesFromMetadata(smbCandidate) {
    if (!smbCandidate || typeof smbCandidate !== "object") {
      return [];
    }

    const entries = [];
    const discovered = new Set();
    const pushEntry = ({ type = "secret", label, source, content, protocol = "SMB" }) => {
      const normalizedContent = normalizeSessionSecretValue(content);
      const normalizedLabel = normalizeSessionSecretValue(label);
      if (!normalizedContent || !normalizedLabel) return;
      const fingerprint = `${type}|${normalizedLabel}|${normalizedContent}`;
      if (discovered.has(fingerprint)) return;
      discovered.add(fingerprint);
      entries.push({
        type,
        label: normalizedLabel,
        source,
        content: normalizedContent,
        protocol,
      });
    };

    const username = normalizeSessionSecretValue(
      smbCandidate.Username || smbCandidate["smb.auth.username"],
    );
    const domain = normalizeSessionSecretValue(
      smbCandidate.Domain || smbCandidate["smb.auth.domain"],
    );
    const workstation = normalizeSessionSecretValue(
      smbCandidate.Workstation || smbCandidate["smb.auth.workstation"],
    );
    const ntlmResponse = normalizeSessionSecretValue(
      smbCandidate["NTLM Response"] || smbCandidate["smb.auth.ntlm_response"],
    );
    const lmResponse = normalizeSessionSecretValue(
      smbCandidate["LM Response"] || smbCandidate["smb.auth.lm_response"],
    );
    const ntlmType = normalizeSessionSecretValue(
      smbCandidate.NTLMSSP || smbCandidate["smb.ntlm.type"],
    );

    if (username) {
      pushEntry({
        type: isLikelyEmailAddress(username) ? "email" : "secret",
        label: "SMB Username",
        source: "session-auto-smb-username",
        content: username,
      });
    }
    if (domain) {
      pushEntry({
        type: "secret",
        label: "SMB Domain",
        source: "session-auto-smb-domain",
        content: domain,
      });
    }
    if (workstation) {
      pushEntry({
        type: "secret",
        label: "SMB Workstation",
        source: "session-auto-smb-workstation",
        content: workstation,
      });
    }
    if (lmResponse) {
      pushEntry({
        type: "secret",
        label: `SMB LM Response${ntlmType ? ` (${ntlmType})` : ""}`,
        source: "session-auto-smb-lm-response",
        content: lmResponse,
      });
    }
    if (ntlmResponse) {
      pushEntry({
        type: "secret",
        label: `SMB NTLM Response${ntlmType ? ` (${ntlmType})` : ""}`,
        source: "session-auto-smb-ntlm-response",
        content: ntlmResponse,
      });
    }

    return entries;
  }

  function normalizeSmbPayloadBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4) return bytes;
    for (let offset = 0; offset <= Math.min(bytes.length - 4, 16); offset += 1) {
      const firstByte = bytes[offset];
      if (
        (firstByte === 0xff || firstByte === 0xfe) &&
        bytes[offset + 1] === 0x53 &&
        bytes[offset + 2] === 0x4d &&
        bytes[offset + 3] === 0x42
      ) {
        return bytes.slice(offset);
      }
    }
    return bytes;
  }

  function readUint32LeFromBytes(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset < 0 || offset + 4 > bytes.length) return null;
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
  }

  function readSmbSecurityBuffer(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset < 0 || offset + 8 > bytes.length) {
      return new Uint8Array();
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const valueLength = view.getUint16(offset, true);
    const bufferOffset = view.getUint32(offset + 4, true);
    if (valueLength <= 0 || bufferOffset < 0 || bufferOffset + valueLength > bytes.length) {
      return new Uint8Array();
    }
    return bytes.slice(bufferOffset, bufferOffset + valueLength);
  }

  function decodeSmbUtf16Text(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return "";
    try {
      return new TextDecoder("utf-16le", { fatal: false })
        .decode(bytes)
        .replace(/\u0000+$/g, "")
        .trim();
    } catch {
      return "";
    }
  }

  function findBytesPatternIndex(bytes, pattern) {
    if (!(bytes instanceof Uint8Array) || !(pattern instanceof Uint8Array)) return -1;
    if (!pattern.length || pattern.length > bytes.length) return -1;
    for (let index = 0; index <= bytes.length - pattern.length; index += 1) {
      let matched = true;
      for (let offset = 0; offset < pattern.length; offset += 1) {
        if (bytes[index + offset] !== pattern[offset]) {
          matched = false;
          break;
        }
      }
      if (matched) return index;
    }
    return -1;
  }

  function bytesToHexStringLower(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return "";
    return Array.from(bytes, (byteValue) => byteValue.toString(16).padStart(2, "0")).join("");
  }

  function extractSmbCredentialEntriesFromPayloadHex(payloadHex) {
    const normalizedHex = typeof payloadHex === "string" ? payloadHex.trim() : "";
    if (!normalizedHex) return [];

    let payloadBytes;
    try {
      payloadBytes = parseDataToolsInput("hex", normalizedHex);
    } catch {
      return [];
    }

    const smbBytes = normalizeSmbPayloadBytes(payloadBytes);
    if (!(smbBytes instanceof Uint8Array) || smbBytes.length < 72) return [];
    if (!((smbBytes[0] === 0xff || smbBytes[0] === 0xfe) && smbBytes[1] === 0x53 && smbBytes[2] === 0x4d && smbBytes[3] === 0x42)) {
      return [];
    }

    const ntlmMarkerIndex = findBytesPatternIndex(
      smbBytes,
      new Uint8Array([0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00]),
    );
    if (ntlmMarkerIndex === -1) return [];
    const ntlmBytes = smbBytes.slice(ntlmMarkerIndex);
    if (ntlmBytes.length < 64) return [];

    const messageType = readUint32LeFromBytes(ntlmBytes, 8);
    if (messageType !== 3) return [];
    const flags = readUint32LeFromBytes(ntlmBytes, 60) || 0;
    const useUnicode = Boolean(flags & 0x00000001);

    const domainBytes = readSmbSecurityBuffer(ntlmBytes, 28);
    const usernameBytes = readSmbSecurityBuffer(ntlmBytes, 36);
    const workstationBytes = readSmbSecurityBuffer(ntlmBytes, 44);
    const lmResponseBytes = readSmbSecurityBuffer(ntlmBytes, 12);
    const ntlmResponseBytes = readSmbSecurityBuffer(ntlmBytes, 20);

    const entries = [];
    const pushEntry = (entry) => {
      if (!entry?.content) return;
      entries.push(entry);
    };

    const decodeText = (bytes) => {
      if (useUnicode) return decodeSmbUtf16Text(bytes);
      return normalizeSessionSecretValue(new TextDecoder("utf-8", { fatal: false }).decode(bytes));
    };

    const username = decodeText(usernameBytes);
    const domain = decodeText(domainBytes);
    const workstation = decodeText(workstationBytes);
    const lmResponse = bytesToHexStringLower(lmResponseBytes);
    const ntlmResponse = bytesToHexStringLower(ntlmResponseBytes);

    if (username) {
      pushEntry({
        type: isLikelyEmailAddress(username) ? "email" : "secret",
        label: "SMB Username",
        source: "session-auto-smb-username",
        content: username,
        protocol: "SMB",
      });
    }
    if (domain) {
      pushEntry({
        type: "secret",
        label: "SMB Domain",
        source: "session-auto-smb-domain",
        content: domain,
        protocol: "SMB",
      });
    }
    if (workstation) {
      pushEntry({
        type: "secret",
        label: "SMB Workstation",
        source: "session-auto-smb-workstation",
        content: workstation,
        protocol: "SMB",
      });
    }
    if (lmResponse) {
      pushEntry({
        type: "secret",
        label: "SMB LM Response (AUTHENTICATE)",
        source: "session-auto-smb-lm-response",
        content: lmResponse,
        protocol: "SMB",
      });
    }
    if (ntlmResponse) {
      pushEntry({
        type: "secret",
        label: "SMB NTLM Response (AUTHENTICATE)",
        source: "session-auto-smb-ntlm-response",
        content: ntlmResponse,
        protocol: "SMB",
      });
    }

    return entries;
  }

  function shouldIncludeSessionSecretKey(pathKey) {
    if (!pathKey) return false;
    const lower = pathKey.toLowerCase();
    if (SESSION_SECRET_IGNORE_KEY_HINTS.some((hint) => lower.includes(hint))) {
      return false;
    }
    return SESSION_SECRET_KEY_HINTS.some((hint) => lower.includes(hint));
  }



  function shouldIncludeSessionSecretValue(value) {
    if (!value) return false;
    const normalized = normalizeSessionSecretValue(value);
    if (!normalized) return false;
    if (normalized.length < 3) return false;
    if (normalized.length > 400) return false;
    if (SESSION_SECRET_IGNORE_KEY_HINTS.some((hint) => normalized.includes(hint))) {
      return false;
    }
    if (isItAGoodie(normalized)) {
      return true;
    }
  }

  function inferSessionEntryType(pathKey) {
    const lower = String(pathKey || "").toLowerCase();
    if (lower.includes("cert")) return "certificate";
    if (lower.includes("private") && lower.includes("key"))
      return "private-key";
    if (lower.includes("key")) return "private-key";
    return "secret";
  }

  function collectSessionSecretCandidates(source, visit, parentPath = "") {
    if (!source || typeof source !== "object") return;
    for (const [key, value] of Object.entries(source)) {
      const nextPath = parentPath ? `${parentPath}.${key}` : key;
      if (value && typeof value === "object") {
        collectSessionSecretCandidates(value, visit, nextPath);
        continue;
      }
      visit(nextPath, value);
    }
  }

  function yieldToBrowserThread() {
    return new Promise((resolve) => {
      window.setTimeout(resolve, 0);
    });
  }

  function keystoreTokenWorkerThread() {
    const DEFAULT_CHUNK_SIZE = 120;
    const SESSION_SECRET_IGNORE_HINTS = [
      "encrypted",
      "length",
      "checksum",
      "version",
      "port",
      "ip",
      "mac",
      "ttl",
      "window",
      "sequence",
      "ack",
      "timestamp",
      "frame",
      "packet",
    ];

    function normalizeValue(value) {
      if (value === null || value === undefined) return "";
      const normalized =
        typeof value === "string"
          ? value
          : typeof value === "number"
            ? String(value)
            : "";
      return normalized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
    }

    function hashForDedupe(content) {
      let hash = 2166136261;
      for (let index = 0; index < content.length; index++) {
        hash ^= content.charCodeAt(index);
        hash = Math.imul(hash, 16777619);
      }
      return (hash >>> 0).toString(16);
    }

    function shouldIncludeSessionSecretValue(value) {
      const normalized = normalizeValue(value);
      if (!normalized) return false;
      if (normalized.length < 3) return false;
      if (normalized.length > 400) return false;
      if (
        SESSION_SECRET_IGNORE_HINTS.some((hint) => normalized.includes(hint))
      ) {
        return false;
      }
      return true;
    }

    function collectLeafValues(source, visit, parentPath = "") {
      if (!source || typeof source !== "object") return;
      for (const [key, value] of Object.entries(source)) {
        const nextPath = parentPath ? `${parentPath}.${key}` : key;
        if (value && typeof value === "object") {
          collectLeafValues(value, visit, nextPath);
          continue;
        }
        visit(nextPath, value);
      }
    }

    async function detectTokenMatches(rawText, pathKey) {
      const matches = [];
      const text = normalizeValue(rawText);
      if (!text) return matches;
      const lowerPath = String(pathKey || "").toLowerCase();

      const addMatch = (type, token) => {
        const normalizedToken = normalizeValue(token);
        if (!normalizedToken) return;
        matches.push({ type, content: normalizedToken });
      };

      const regexExtract = (regex, type) => {
        regex.lastIndex = 0;
        let regexMatch;
        while ((regexMatch = regex.exec(text)) !== null) {
          addMatch(type, regexMatch[0]);
        }
      };

      regexExtract(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "aws-access-key");
      regexExtract(/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, "github-token");
      regexExtract(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, "github-token");
      regexExtract(/\bmfa\.[A-Za-z0-9_-]{80,}\b/g, "discord-token");
      regexExtract(
        /\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{20,}\b/g,
        "discord-token",
      );
      regexExtract(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "jwt-token");
      regexExtract(/\bya29\.[A-Za-z0-9._-]{20,}\b/g, "oauth-token");

      if (/\bBearer\s+[A-Za-z0-9._~-]{20,}\b/i.test(text)) {
        const bearerToken = text.replace(/^.*?\bBearer\s+/i, "").trim();
        addMatch("oauth-token", bearerToken);
      }

      const hasLikelySecretKeyName =
        lowerPath.includes("token") ||
        lowerPath.includes("apikey") ||
        lowerPath.includes("api_key") ||
        lowerPath.includes("api-key") ||
        lowerPath.includes("oauth") ||
        lowerPath.includes("authorization") ||
        lowerPath.includes("auth") ||
        lowerPath.includes("discord") ||
        lowerPath.includes("github") ||
        lowerPath.includes("azure") ||
        lowerPath.includes("aws") ||
        lowerPath.includes("secret") ||
        lowerPath.includes("accountkey");

      if (hasLikelySecretKeyName) {
        const normalizedCandidate = text.replace(/^bearer\s+/i, "").trim();
        if (normalizedCandidate.length >= 20) {
          let inferredType = "api-token";
          if (lowerPath.includes("oauth")) inferredType = "oauth-token";
          else if (lowerPath.includes("discord")) inferredType = "discord-token";
          else if (lowerPath.includes("github")) inferredType = "github-token";
          else if (lowerPath.includes("aws")) inferredType = "aws-secret-key";
          else if (lowerPath.includes("azure") || lowerPath.includes("accountkey")) {
            inferredType = "azure-key";
          }
          addMatch(inferredType, normalizedCandidate);
        }
      }

      const accountKeyMatch = text.match(/AccountKey=([^;\s]+)/i);
      if (accountKeyMatch?.[1]) {
        addMatch("azure-key", accountKeyMatch[1]);
      }

      if (/^[A-Za-z0-9+/]{43}=$/.test(text) || /^[A-Za-z0-9+/]{86}==$/.test(text)) {
        if (lowerPath.includes("azure") || lowerPath.includes("accountkey")) {
          addMatch("azure-key", text);
        }
      }

      if (/^[A-Za-z0-9/+=]{40}$/.test(text) && lowerPath.includes("aws")) {
        addMatch("aws-secret-key", text);
      }
      if (shouldIncludeSessionSecretValue(text)) {
        addMatch("goodie", text);
      }
      return matches;
    }

    self.onmessage = (event) => {
      const payload = event?.data || {};
      if (payload.type !== "scan") return;
      const packets = Array.isArray(payload.packets) ? payload.packets : [];
      const chunkSize =
        Number.isInteger(payload.chunkSize) && payload.chunkSize > 0
          ? payload.chunkSize
          : DEFAULT_CHUNK_SIZE;
      const dedupe = new Set();
      const discoveredEntries = [];

      const pushEntry = ({
        type,
        content,
        host,
        pathKey,
        packetIndex,
        protocol,
      }) => {
        const normalizedContent = normalizeValue(content);
        if (!normalizedContent) return;
        const fingerprint = `${type}|${hashForDedupe(normalizedContent)}`;
        if (dedupe.has(fingerprint)) return;
        dedupe.add(fingerprint);
        discoveredEntries.push({
          type,
          label: `${type.toUpperCase()} ${normalizedContent.slice(0, 64)}`,
          source: "session-auto-token",
          content: normalizedContent,
          summary: `Host ${host} packet #${packetIndex} ${pathKey}`,
          packetIndex,
          protocol,
          createdAt: new Date().toISOString(),
        });
      };

      function scanPacket(packetRecord) {
        const host = packetRecord?.host || "Unknown";
        const packet = packetRecord?.packet || {};
        const packetInfo = packet?.["packet.info"] || {};
        const protocol = packetInfo?.["packet.proto"] ?? packetInfo?.["Protocol"] ?? "Unknown";
        const packetIndex = packetInfo?.["index"] ?? packetInfo?.["Index"] ?? "?";
        const transportData =
          packetInfo?.["Transport Layer"] || packetInfo?.[protocol] || {};
        const extraInfo = packet?.["extra.info"] || {};
        const roots = [transportData, extraInfo];
        // check type before going over roots
        if (!Array.isArray(roots) || roots.length === 0) return;
        roots.forEach((root) => {
          collectLeafValues(root, (pathKey, rawValue) => {
            const tokenMatches = detectTokenMatches(rawValue, pathKey);
            // check type before going over tokenMatches
            if (!Array.isArray(tokenMatches) || tokenMatches.length === 0) return;
            tokenMatches.forEach(({ type, content }) => {
              pushEntry({
                type,
                content,
                host,
                pathKey,
                packetIndex,
                protocol,
              });
            });
          });
        });
      }

      function processChunk(startIndex) {
        const endIndex = Math.min(startIndex + chunkSize, packets.length);
        for (let index = startIndex; index < endIndex; index++) {
          scanPacket(packets[index]);
        }
        if (endIndex < packets.length) {
          setTimeout(() => processChunk(endIndex), 0);
          return;
        }
        self.postMessage({
          type: "done",
          entries: discoveredEntries,
        });
      }

      processChunk(0);
    };
  }

  function createSessionTokenWorker() {
    if (
      typeof Worker !== "function" ||
      typeof Blob !== "function" ||
      !window.URL ||
      typeof window.URL.createObjectURL !== "function"
    ) {
      return null;
    }
    const source = `(${keystoreTokenWorkerThread.toString()})();`;
    const workerBlob = new Blob([source], {
      type: "application/javascript",
    });
    const workerUrl = window.URL.createObjectURL(workerBlob);
    const worker = new Worker(workerUrl);
    window.URL.revokeObjectURL(workerUrl);
    return worker;
  }

  document.getElementById("crypt-keystore-filter").addEventListener("input", (event) => {
    const filterValue = event.target.value.trim();
    let typeEntriesGrep = grepSessionKeystoreEntriesByType(filterValue);
    let contentEntriesGrep = grepSessionKeystoreEntriesByContent(filterValue);
    let labelEntriesGrep = grepSessionKeystoreEntriesByLabel(filterValue);
    //let typeEntriesGrep = [];
    //let contentEntriesGrep = [];
    //if (filterValue) {
    //  typeEntriesGrep = grepSessionKeystoreEntries(filterValue, "type");
    //  contentEntriesGrep = grepSessionKeystoreEntries(filterValue, "content");
    //}
    let newEntries = [];
    if (filterValue) {
      newEntries = [...typeEntriesGrep, ...contentEntriesGrep, ...labelEntriesGrep];
    } else {
      newEntries = cryptSessionKeystoreEntries.slice();
    }

    // now to make sure we dont have dupes in newEntries, we can use a Set to track unique IDs
    const uniqueIds = new Set();
    newEntries = newEntries.filter((entry) => {
      if (uniqueIds.has(entry.id)) {
        return false;
      }
      uniqueIds.add(entry.id);
      return true;
    });
    renderCryptKeystoreList(newEntries);
  });

  async function hydratePacketForSessionScan(
    packet,
    hydrationCache = sessionScanHydratedPacketCache,
  ) {
    if (!packet || typeof packet !== "object") return packet;
    if (!packet.__packetStub) return packet;

    const packetKey =
      typeof packet.__packetKey === "string" ? packet.__packetKey : "";
    if (!packetKey) return packet;

    if (hydrationCache && hydrationCache.has(packetKey)) {
      return hydrationCache.get(packetKey);
    }

    if (!window.captureapi || typeof window.captureapi.getPacket !== "function") {
      return packet;
    }

    try {
      const hydrationResult = await window.captureapi.getPacket(packetKey);
      const hydratedPacket = hydrationResult?.packet;
      if (!hydratedPacket || typeof hydratedPacket !== "object") {
        if (hydrationCache) {
          setBoundedCacheEntry(
            hydrationCache,
            packetKey,
            packet,
            SESSION_SCAN_HYDRATED_PACKET_CACHE_LIMIT,
          );
        }
        return packet;
      }

      const mergedPacket = {
        ...packet,
        ...hydratedPacket,
        __packetKey: packetKey,
        __packetStub: false,
      };
      if (hydrationCache) {
        setBoundedCacheEntry(
          hydrationCache,
          packetKey,
          mergedPacket,
          SESSION_SCAN_HYDRATED_PACKET_CACHE_LIMIT,
        );
      }
      return mergedPacket;
    } catch (error) {
      logErrorEntry("crypt-keystore-packet-hydration", error);
      if (hydrationCache) {
        setBoundedCacheEntry(
          hydrationCache,
          packetKey,
          packet,
          SESSION_SCAN_HYDRATED_PACKET_CACHE_LIMIT,
        );
      }
      return packet;
    }
  }

  function scanSessionTokensInWorker(packetRecords) {
    const worker = createSessionTokenWorker();
    if (!worker || !Array.isArray(packetRecords) || packetRecords.length === 0) {
      return Promise.resolve([]);
    }

    return new Promise((resolve) => {
      let didResolve = false;
      const resolveOnce = (entries) => {
        if (didResolve) return;
        didResolve = true;
        worker.terminate();
        resolve(Array.isArray(entries) ? entries : []);
      };

      worker.onerror = (error) => {
        logErrorEntry("crypt-keystore-token-worker", error);
        resolveOnce([]);
      };

      worker.onmessage = (event) => {
        const payload = event?.data || {};
        if (payload.type === "done") {
          resolveOnce(payload.entries);
        }
      };

      worker.postMessage({
        type: "scan",
        packets: packetRecords,
        chunkSize: SESSION_TOKEN_SCAN_WORKER_CHUNK_SIZE,
      });
    });
  }

  async function buildSessionAutoKeystoreEntries() {
    const generatedEntries = [];
    const dedupe = new Set();
    const hosts = getCapturedPackets()?.host ?? getCapturedPackets()?.Host;
    if (!hosts || typeof hosts !== "object") return generatedEntries;

    const packetRecords = [];
    Object.entries(hosts).forEach(([host, packets]) => {
      if (!Array.isArray(packets)) return;
      packets.forEach((packet) => {
        packetRecords.push({
          host,
          packet,
        });
      });
    });

    const tokenScanPromise = scanSessionTokensInWorker(packetRecords);

    const pushSessionEntry = ({
      type = "secret",
      label,
      source,
      content,
      summary,
      packetIndex,
      protocol,
    }) => {
      const normalizedContent = normalizeSessionSecretValue(content);
      if (!normalizedContent) return;
      const fingerprint = `${type}|${label}|${hashContentForDeduplication(normalizedContent)}`;
      if (dedupe.has(fingerprint)) return;
      dedupe.add(fingerprint);
      generatedEntries.push({
        id: generateCryptEntryId(),
        type,
        label: label || `${type}-${new Date().toISOString()}`,
        source: source || "session-auto",
        content: normalizedContent,
        summary: summary || "",
        packetIndex: packetIndex ?? "?",
        protocol: protocol || "Unknown",
        createdAt: new Date().toISOString(),
      });
    };

    for (
      let recordIndex = 0;
      recordIndex < packetRecords.length;
      recordIndex += SESSION_AUTO_BUILD_CHUNK_SIZE
    ) {
      const chunk = packetRecords.slice(
        recordIndex,
        recordIndex + SESSION_AUTO_BUILD_CHUNK_SIZE,
      );
      for (const { host, packet } of chunk) {
        const hydratedPacket = await hydratePacketForSessionScan(
          packet,
          sessionScanHydratedPacketCache,
        );
        const packetInfo = hydratedPacket?.["packet.info"] || {};
        const protocol = packetInfo?.["packet.proto"] ?? packetInfo?.["Protocol"] ?? "Unknown";
        const transportData =
          packetInfo?.["Transport Layer"] || packetInfo?.[protocol] || {};
        const extraInfo = hydratedPacket?.["extra.info"] || {};
        const packetIndex = packetInfo?.["index"] ?? packetInfo?.["Index"] ?? "?";
        const transportPorts = extractTransportPorts(transportData, packetInfo);
        [transportData, extraInfo].forEach((candidateRoot) => {
          collectSessionSecretCandidates(candidateRoot, (pathKey, rawValue) => {
            const rawText = normalizeSessionSecretValue(rawValue);
            if (rawText) {
              extractUriCandidatesFromText(rawText).forEach((uriValue) => {
                const uriType = /^https?:\/\//i.test(uriValue) ? "url" : "uri";
                pushSessionEntry({
                  type: uriType,
                  label: `${uriType.toUpperCase()} ${uriValue}`,
                  source: "session-auto-uri",
                  content: uriValue,
                  summary: `Host ${host} packet #${packetIndex} ${pathKey}`,
                  packetIndex,
                  protocol,
                });
              });
              extractEmailCandidatesFromText(rawText).forEach((emailValue) => {
                pushSessionEntry({
                  type: "email",
                  label: `Email ${emailValue}`,
                  source: "session-auto-email",
                  content: emailValue,
                  summary: `Host ${host} packet #${packetIndex} ${pathKey}`,
                  packetIndex,
                  protocol,
                });
              });
              extractPlaintextProtocolCredentialEntries({
                protocol,
                pathKey,
                rawText,
                port: transportPorts,
                packetInfo,
              }).forEach((credentialEntry) => {
                pushSessionEntry({
                  type: credentialEntry.type,
                  label: credentialEntry.label,
                  source: credentialEntry.source,
                  content: credentialEntry.content,
                  summary: `Host ${host} packet #${packetIndex} ${pathKey}`,
                  packetIndex,
                  protocol: credentialEntry.protocol || protocol,
                });
              });
            }
            if (!shouldIncludeSessionSecretKey(pathKey)) return;
            if (!shouldIncludeSessionSecretValue(rawText)) return;
            if (!rawText) return;
            const decodedBasic = decodeHttpBasicAuth(rawText);
            const contentToSave = decodedBasic || rawText;
            pushSessionEntry({
              type: inferSessionEntryType(pathKey),
              label: `${protocol} ${pathKey}`,
              source: "session-auto-decoded",
              content: contentToSave,
              summary: `Host ${host} packet #${packetIndex}`,
              packetIndex,
              protocol,
            });
          });
        });

        const payloadHex =
          packetInfo?.["Raw data"]?.["Payload"]?.["payload.hex"] ??
          packetInfo?.["Raw data"]?.["Payload"]?.["Hex Encoded"];
        const structuredHttpSection = transportData?.HTTP;
        const structuredHttpLocationEntries = buildHttpRequestLocationCandidates(
          structuredHttpSection,
          packetInfo,
          host,
        );
        structuredHttpLocationEntries.forEach((locationEntry) => {
          pushSessionEntry({
            type: locationEntry.type,
            label: locationEntry.label,
            source: "session-auto-http-location",
            content: locationEntry.content,
            summary: `Host ${host} packet #${packetIndex} HTTP request target`,
            packetIndex,
            protocol: "HTTP",
          });
        });

        const structuredCookieEntries = extractCookieEntriesFromHttpMetadata(
          structuredHttpSection,
        );
        structuredCookieEntries.forEach((cookieEntry) => {
          const separatorIndex = cookieEntry.indexOf("=");
          const cookieName =
            separatorIndex >= 0
              ? cookieEntry.slice(0, separatorIndex).trim()
              : "";
          const cookieLabelSuffix =
            cookieName ||
            `packet-${packetIndex}-${hashContentForDeduplication(cookieEntry)}`;
          pushSessionEntry({
            type: "cookie",
            label: `HTTP Cookie ${cookieLabelSuffix}`,
            source: "session-auto-cookie-jar",
            content: cookieEntry,
            summary: `Host ${host} packet #${packetIndex}`,
            packetIndex,
            protocol: "HTTP",
          });
        });

        const structuredSmbSection = transportData?.SMB;
        const structuredSmbEntries = extractSmbCredentialEntriesFromMetadata(
          structuredSmbSection,
        );
        structuredSmbEntries.forEach((smbEntry) => {
          pushSessionEntry({
            type: smbEntry.type,
            label: smbEntry.label,
            source: smbEntry.source,
            content: smbEntry.content,
            summary: `Host ${host} packet #${packetIndex} SMB authentication`,
            packetIndex,
            protocol: smbEntry.protocol || "SMB",
          });
        });

        if (typeof payloadHex === "string" && payloadHex.trim()) {
          const payloadSmbEntries = extractSmbCredentialEntriesFromPayloadHex(
            payloadHex,
          );
          payloadSmbEntries.forEach((smbEntry) => {
            pushSessionEntry({
              type: smbEntry.type,
              label: smbEntry.label,
              source: smbEntry.source,
              content: smbEntry.content,
              summary: `Host ${host} packet #${packetIndex} SMB authentication payload`,
              packetIndex,
              protocol: smbEntry.protocol || "SMB",
            });
          });
          try {
            const payloadBytes = parseDataToolsInput("hex", payloadHex);
            const payloadText = new TextDecoder("utf-8", {
              fatal: false,
            }).decode(payloadBytes);
            extractPlaintextProtocolCredentialEntries({
              protocol,
              pathKey: "payload.text",
              rawText: payloadText,
              port: transportPorts,
              packetInfo,
            }).forEach((credentialEntry) => {
              pushSessionEntry({
                type: credentialEntry.type,
                label: credentialEntry.label,
                source: credentialEntry.source,
                content: credentialEntry.content,
                summary: `Host ${host} packet #${packetIndex} payload plaintext`,
                packetIndex,
                protocol: credentialEntry.protocol || protocol,
              });
            });

            const decodedHttp = decodeHttpFromBytes(payloadBytes);
            if (decodedHttp?.protocol === "HTTP") {
              const decodedHttpAuthHeader = getHttpFieldValue(
                decodedHttp.fields,
                "Authorization",
              );
              extractHttpBasicCredentialEntries(decodedHttpAuthHeader).forEach(
                (basicEntry) => {
                  pushSessionEntry({
                    type: basicEntry.type,
                    label: basicEntry.label,
                    source: basicEntry.source,
                    content: basicEntry.content,
                    summary: `Host ${host} packet #${packetIndex} HTTP Authorization`,
                    packetIndex,
                    protocol: "HTTP",
                  });
                },
              );

              const httpLocationEntries = buildHttpRequestLocationCandidates(
                decodedHttp,
                packetInfo,
                host,
              );
              httpLocationEntries.forEach((locationEntry) => {
                pushSessionEntry({
                  type: locationEntry.type,
                  label: locationEntry.label,
                  source: "session-auto-http-location",
                  content: locationEntry.content,
                  summary: `Host ${host} packet #${packetIndex} HTTP request target`,
                  packetIndex,
                  protocol: "HTTP",
                });
              });

              const cookieEntries = extractCookieJarEntriesFromHttpFields(
                decodedHttp.fields,
              );
              cookieEntries.forEach((cookieEntry) => {
                const separatorIndex = cookieEntry.indexOf("=");
                const cookieName =
                  separatorIndex >= 0
                    ? cookieEntry.slice(0, separatorIndex).trim()
                    : "";
                const cookieLabelSuffix =
                  cookieName ||
                  `packet-${packetIndex}-${hashContentForDeduplication(cookieEntry)}`;
                pushSessionEntry({
                  type: "cookie",
                  label: `HTTP Cookie ${cookieLabelSuffix}`,
                  source: "session-auto-cookie-jar",
                  content: cookieEntry,
                  summary: `Host ${host} packet #${packetIndex}`,
                  packetIndex,
                  protocol: "HTTP",
                });
              });
            }
          } catch (error) {
            logErrorEntry("crypt-keystore-cookie-auto", error);
          }
        }
      }

      await yieldToBrowserThread();
    }

    const tokenEntries = await tokenScanPromise;
    tokenEntries.forEach((tokenEntry) => {
      pushSessionEntry(tokenEntry);
    });

    return generatedEntries.sort((a, b) => {
      const aPacketNumber = Number(a.packetIndex);
      const bPacketNumber = Number(b.packetIndex);
      if (Number.isFinite(aPacketNumber) && Number.isFinite(bPacketNumber)) {
        return aPacketNumber - bPacketNumber;
      }
      return String(a.packetIndex).localeCompare(String(b.packetIndex));
    });
  }

  function buildManualDataKeystoreEntries({
    bytes = null,
    text = "",
    fileName = "",
    source = "manual-conv-import",
  } = {}) {
    const generatedEntries = [];
    const dedupe = new Set();
    const normalizedText = normalizeSessionSecretValue(text);
    const summaryBase = fileName
      ? `Manual Conv import file=${fileName}`
      : "Manual Conv import";

    const pushManualEntry = ({
      type = "secret",
      label,
      content,
      entrySource = source,
      summary = summaryBase,
      packetIndex = "manual",
    }) => {
      const normalizedContent = normalizeSessionSecretValue(content);
      if (!normalizedContent) return;
      const fingerprint = `${type}|${label}|${hashContentForDeduplication(normalizedContent)}`;
      if (dedupe.has(fingerprint)) return;
      dedupe.add(fingerprint);
      generatedEntries.push({
        type,
        label: label || `${type}-${new Date().toISOString()}`,
        source: entrySource,
        content: normalizedContent,
        summary,
        packetIndex,
      });
    };

    const scanTextValue = (rawValue, pathKey = "body") => {
      const rawText = normalizeSessionSecretValue(rawValue);
      if (!rawText) return;

      extractUriCandidatesFromText(rawText).forEach((uriValue) => {
        const uriType = /^https?:\/\//i.test(uriValue) ? "url" : "uri";
        pushManualEntry({
          type: uriType,
          label: `${uriType.toUpperCase()} ${uriValue}`,
          content: uriValue,
          entrySource: `${source}-uri`,
          summary: `${summaryBase} ${pathKey}`,
        });
      });

      extractEmailCandidatesFromText(rawText).forEach((emailValue) => {
        pushManualEntry({
          type: "email",
          label: `Email ${emailValue}`,
          content: emailValue,
          entrySource: `${source}-email`,
          summary: `${summaryBase} ${pathKey}`,
        });
      });

      extractPlaintextProtocolCredentialEntries({
        protocol: "FILE",
        pathKey,
        rawText,
        port: [21, 25, 80, 143, 443, 465, 5060, 5061, 587, 993, 3389],
        packetInfo: {},
      }).forEach((credentialEntry) => {
        pushManualEntry({
          type: credentialEntry.type,
          label: credentialEntry.label,
          content: credentialEntry.content,
          entrySource: credentialEntry.source || `${source}-credential`,
          summary: `${summaryBase} ${pathKey}`,
        });
      });

      detectSessionTokenMatches(rawText, pathKey).forEach((tokenMatch) => {
        pushManualEntry({
          type: tokenMatch.type,
          label: `${tokenMatch.type.toUpperCase()} ${tokenMatch.content.slice(0, 64)}`,
          content: tokenMatch.content,
          entrySource: `${source}-token`,
          summary: `${summaryBase} ${pathKey}`,
        });
      });

      if (shouldIncludeSessionSecretKey(pathKey) && shouldIncludeSessionSecretValue(rawText)) {
        const decodedBasic = decodeHttpBasicAuth(rawText);
        pushManualEntry({
          type: inferSessionEntryType(pathKey),
          label: `FILE ${pathKey}`,
          content: decodedBasic || rawText,
          entrySource: `${source}-decoded`,
          summary: `${summaryBase} ${pathKey}`,
        });
      }
    };

    if (normalizedText) {
      scanTextValue(normalizedText, "body");
      normalizedText.split(/\r?\n/).forEach((line, lineIndex) => {
        const normalizedLine = normalizeSessionSecretValue(line);
        if (!normalizedLine) return;
        const keyValueMatch = normalizedLine.match(/^([A-Za-z0-9_.\-\[\] ]{2,80})\s*[:=]\s*(.+)$/);
        if (keyValueMatch) {
          const derivedPathKey = keyValueMatch[1]
            .trim()
            .toLowerCase()
            .replace(/\s+/g, ".");
          scanTextValue(keyValueMatch[2], derivedPathKey);
        }
        scanTextValue(normalizedLine, `line.${lineIndex + 1}`);
      });
    }

    if (bytes instanceof Uint8Array && bytes.length > 0) {
      const decodedHttp = decodeHttpFromBytes(bytes);
      if (decodedHttp?.protocol === "HTTP") {
        decodedHttp.fields.forEach((field) => {
          const fieldName = String(field?.name || "field")
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, ".");
          scanTextValue(field?.value, `http.${fieldName}`);
        });
        extractCookieJarEntriesFromHttpFields(decodedHttp.fields).forEach((cookieValue) => {
          const cookieName = cookieValue.split("=")[0] || cookieValue;
          pushManualEntry({
            type: "cookie",
            label: `COOKIE ${cookieName}`,
            content: cookieValue,
            entrySource: `${source}-cookie`,
            summary: `${summaryBase} http.cookie`,
          });
        });
      }
    }

    return generatedEntries;
  }

  function importManualDataIntoSessionKeystore(options = {}) {
    const generatedEntries = buildManualDataKeystoreEntries(options);
    let addedCount = 0;
    generatedEntries.forEach((entry) => {
      const previousLength = cryptSessionKeystoreEntries.length;
      addSessionKeystoreEntry(entry);
      if (cryptSessionKeystoreEntries.length > previousLength) {
        addedCount += 1;
      }
    });
    return addedCount;
  }

  function addSessionKeystoreEntry({
    type,
    label,
    source,
    content,
    summary,
    packetIndex,
  }) {
    const normalizedContent = normalizeSessionSecretValue(content);
    if (!normalizedContent) return;
    const exists = cryptSessionKeystoreEntries.some(
      (entry) =>
        entry.type === type &&
        entry.label === label &&
        normalizeSessionSecretValue(entry.content) === normalizedContent,
    );
    if (exists) return;
    cryptSessionKeystoreEntries.unshift({
      id: generateCryptEntryId(),
      type,
      label: label?.trim()
        ? label.trim()
        : `${type}-${new Date().toISOString()}`,
      source: source || "session-auto",
      content: normalizedContent,
      summary: summary || "",
      packetIndex: packetIndex ?? "?",
      createdAt: new Date().toISOString(),
    });
    if (cryptActiveKeystoreMode === CRYPT_KEYSTORE_MODE_SESSION) {
      renderCryptKeystoreList();
    }
  }

  async function addCryptKeystoreEntry(
    { type, label, source, content, summary },
    { force = false } = {},
  ) {
    if (!force && cryptActiveKeystoreMode !== CRYPT_KEYSTORE_MODE_PERSISTENT) {
      statusUpdate("Status: Switch to persistent keychain to save entries");
      return;
    }
    if (!cryptKeystoreUnlockKeyMaterial) {
      doError(
        "Persistent keychain is locked. Reopen the keychain tab with password.",
      );
      return;
    }
    const normalizedContent = (content || "").trim();
    if (!normalizedContent) {
      statusUpdate("Status: No content available to save");
      return;
    }

    const entry = {
      id: generateCryptEntryId(),
      type,
      label: label?.trim()
        ? label.trim()
        : `${type}-${new Date().toISOString()}`,
      source,
      content: normalizedContent,
      summary: summary || "",
      createdAt: new Date().toISOString(),
    };
    cryptPersistentKeystoreEntries.unshift(entry);
    try {
      await savePersistentCryptKeystoreEntries(
        cryptPersistentKeystoreEntries,
        cryptKeystoreUnlockKeyMaterial,
      );
    } catch (error) {
      logErrorEntry("crypt-keystore-save", error);
      doError("Could not save the persistent keychain.");
      return;
    }
    renderCryptKeystoreList();
    statusUpdate(`Status: Saved ${type} in persistent keychain`);
    writeLogEntry(
      `[${threadName}] Crypt keystore entry added type=${type} label="${entry.label}"`,
    );
  }

  async function loadSelectedCryptKeystoreEntry() {
    const listEl = document.getElementById("crypt-keystore-list");
    const selectedIndex = Number(listEl.value);
    const activeEntries = getActiveCryptKeystoreEntries();
    if (!Number.isFinite(selectedIndex) || !activeEntries[selectedIndex]) {
      statusUpdate("Status: Select a keystore entry first");
      return;
    }

    const selectedEntry = activeEntries[selectedIndex];
    let loadedContent = normalizeSessionSecretValue(selectedEntry.content);
    if (
      !loadedContent &&
      selectedEntry.encryptedContent &&
      selectedEntry.salt &&
      selectedEntry.iv
    ) {
      if (!cryptKeystoreUnlockKeyMaterial) {
        doError(
          "Persistent keychain is locked. Reopen keychain with password.",
        );
        return;
      }
      try {
        loadedContent = await decryptCryptContent(
          selectedEntry,
          cryptKeystoreUnlockKeyMaterial,
        );
      } catch (error) {
        logErrorEntry("crypt-keystore-decrypt", error);
        doError("Could not decrypt keystore entry with current password.");
        return;
      }
    }
    if (!loadedContent) {
      statusUpdate("Status: Selected entry has no decodable content");
      return;
    }
    renderCryptKeystoreDetails(selectedEntry);
    document.getElementById("crypt-keystore-label").value = selectedEntry.label;
    document.getElementById("crypt-credential-input").value = loadedContent;
    if (selectedEntry.type === "certificate") {
      getApplyCryptCertificateText()(loadedContent, getActiveKeystoreLabel());
    } else if (selectedEntry.type === "private-key") {
      getApplyCryptPrivateKeyText()(loadedContent, getActiveKeystoreLabel());
    }
    statusUpdate(`Status: Loaded keystore entry "${selectedEntry.label}"`);
  }

  async function deleteSelectedCryptKeystoreEntry() {
    if (cryptActiveKeystoreMode !== CRYPT_KEYSTORE_MODE_PERSISTENT) {
      statusUpdate("Status: Session keychain entries are auto-managed");
      return;
    }
    const listEl = document.getElementById("crypt-keystore-list");
    const selectedIndex = Number(listEl.value);
    if (
      !Number.isFinite(selectedIndex) ||
      !cryptPersistentKeystoreEntries[selectedIndex]
    ) {
      statusUpdate("Status: Select a keystore entry first");
      return;
    }
    if (!cryptKeystoreUnlockKeyMaterial) {
      doError("Persistent keychain is locked. Reopen keychain with password.");
      return;
    }
    const [removedEntry] = cryptPersistentKeystoreEntries.splice(
      selectedIndex,
      1,
    );
    try {
      await savePersistentCryptKeystoreEntries(
        cryptPersistentKeystoreEntries,
        cryptKeystoreUnlockKeyMaterial,
      );
    } catch (error) {
      logErrorEntry("crypt-keystore-save", error);
      doError("Could not save the persistent keychain.");
      return;
    }
    renderCryptKeystoreList();
    statusUpdate(`Status: Deleted keystore entry "${removedEntry.label}"`);
    writeLogEntry(
      `[${threadName}] Crypt keystore entry deleted type=${removedEntry.type} label="${removedEntry.label}"`,
    );
  }

  async function sendSelectedSessionEntryToPersistent() {
    if (cryptActiveKeystoreMode !== CRYPT_KEYSTORE_MODE_SESSION) {
      statusUpdate(
        "Status: Switch to session keychain to send temporary entries",
      );
      return;
    }
    if (!cryptKeystoreUnlockKeyMaterial) {
      doError("Persistent keychain is locked. Reopen keychain with password.");
      return;
    }
    const listEl = document.getElementById("crypt-keystore-list");
    const selectedIndex = Number(listEl.value);
    if (
      !Number.isFinite(selectedIndex) ||
      !cryptSessionKeystoreEntries[selectedIndex]
    ) {
      statusUpdate("Status: Select a session keychain entry first");
      return;
    }

    const selectedEntry = cryptSessionKeystoreEntries[selectedIndex];
    const normalizedContent = normalizeSessionSecretValue(
      selectedEntry.content,
    );
    if (!normalizedContent) {
      statusUpdate("Status: Selected session entry has no content to persist");
      return;
    }

    const alreadyStored = cryptPersistentKeystoreEntries.some(
      (entry) =>
        entry.type === selectedEntry.type &&
        entry.label === selectedEntry.label &&
        normalizeSessionSecretValue(entry.content) === normalizedContent,
    );
    if (alreadyStored) {
      statusUpdate("Status: Entry is already stored in persistent keychain");
      return;
    }

    cryptPersistentKeystoreEntries.unshift({
      id: generateCryptEntryId(),
      type: selectedEntry.type,
      label: selectedEntry.label,
      source: `bookmarked from ${selectedEntry.source || "session-auto"}`,
      content: normalizedContent,
      summary: selectedEntry.summary || "Bookmarked from session keychain",
      createdAt: new Date().toISOString(),
    });
    try {
      await savePersistentCryptKeystoreEntries(
        cryptPersistentKeystoreEntries,
        cryptKeystoreUnlockKeyMaterial,
      );
    } catch (error) {
      logErrorEntry("crypt-keystore-save", error);
      doError("Could not save selected entry to persistent keychain.");
      return;
    }
    statusUpdate(
      `Status: Sent "${selectedEntry.label}" to persistent keychain`,
    );
    writeLogEntry(
      `[${threadName}] Session keychain entry persisted label="${selectedEntry.label}"`,
    );
  }

  function grepSessionKeystoreEntriesByContent(content) {
    const normalizedContent = content.trim().toLowerCase();
    // get the session keystore entries from from the keystore-panel.js aray
    // getActiveCryptKeystoreEntries() is not available in this context, so we access the global variable directly
    const keystoreEntries = cryptSessionKeystoreEntries;
    if (!normalizedContent) return keystoreEntries;
    return keystoreEntries.filter((entry) => {
      const entryContent = entry.content || "";
      return entryContent.toLowerCase().includes(normalizedContent);
    });
  }

  function grepSessionKeystoreEntriesByType(type) {
    const normalizedType = type.trim().toLowerCase();
    // get the session keystore entries from from the keystore-panel.js aray
    // getActiveCryptKeystoreEntries() is not available in this context, so we access the global variable directly
    const keystoreEntries = cryptSessionKeystoreEntries;
    if (!normalizedType) return keystoreEntries;
    return keystoreEntries.filter((entry) => {
      const entryType = entry.type || "";
      return entryType.toLowerCase().includes(normalizedType);
    });
  }

  function grepSessionKeystoreEntriesByLabel(label) {
    const normalizedLabel = label.trim().toLowerCase();
    // get the session keystore entries from from the keystore-panel.js aray
    // getActiveCryptKeystoreEntries() is not available in this context, so we access the global variable directly
    const keystoreEntries = cryptSessionKeystoreEntries;
    if (!normalizedLabel) return keystoreEntries;
    return keystoreEntries.filter((entry) => {
      const entryLabel = entry.label || "";
      return entryLabel.toLowerCase().includes(normalizedLabel);
    });
  }

  function configureKeystoreUnlockDialog(mode) {
    cryptKeystoreUnlockDialogMode = mode === "setup" ? "setup" : "unlock";
    const isSetup = cryptKeystoreUnlockDialogMode === "setup";
    const titleEl = document.getElementById("crypt-keystore-unlock-title");
    const descriptionEl = document.getElementById(
      "crypt-keystore-unlock-description",
    );
    const passwordEl = document.getElementById(
      "crypt-keystore-unlock-password",
    );
    const confirmEl = document.getElementById(
      "crypt-keystore-unlock-password-confirm",
    );
    const confirmBtn = document.getElementById(
      "crypt-keystore-unlock-confirm-btn",
    );
    const resetBtn = document.getElementById("crypt-keystore-unlock-reset-btn");
    if (titleEl) {
      titleEl.textContent = isSetup
        ? "Set Keychain Password"
        : "Unlock Keychain";
    }
    if (descriptionEl) {
      descriptionEl.textContent = isSetup
        ? `Create the initial password for the persistent keychain (minimum ${CRYPT_KEYSTORE_MIN_PASSWORD_LENGTH} characters). You will only be asked when selecting the keychain tab.`
        : "Enter password to unlock the persistent keychain.";
    }
    if (passwordEl) {
      passwordEl.placeholder = isSetup
        ? "Create keychain password"
        : "Enter keychain password";
    }
    if (confirmEl) {
      confirmEl.hidden = !isSetup;
      confirmEl.placeholder = "Confirm keychain password";
    }
    if (confirmBtn) {
      confirmBtn.textContent = isSetup ? "Set password" : "Unlock";
    }
    if (resetBtn) {
      resetBtn.hidden = isSetup;
    }
  }

  function requestKeystoreUnlockPassword(mode = "unlock") {
    const dialogEl = document.getElementById("crypt-keystore-unlock-dialog");
    const inputEl = document.getElementById("crypt-keystore-unlock-password");
    const confirmEl = document.getElementById(
      "crypt-keystore-unlock-password-confirm",
    );
    if (!dialogEl || !inputEl || !confirmEl) return Promise.resolve(null);
    configureKeystoreUnlockDialog(mode);
    dialogEl.hidden = false;
    inputEl.value = "";
    confirmEl.value = "";
    inputEl.focus();
    return new Promise((resolve) => {
      cryptKeystoreUnlockDialogResolver = resolve;
    });
  }

  function resolveKeystoreUnlockPassword(value) {
    const dialogEl = document.getElementById("crypt-keystore-unlock-dialog");
    const inputEl = document.getElementById("crypt-keystore-unlock-password");
    const confirmEl = document.getElementById(
      "crypt-keystore-unlock-password-confirm",
    );
    if (dialogEl) dialogEl.hidden = true;
    if (inputEl) inputEl.value = "";
    if (confirmEl) confirmEl.value = "";
    if (!cryptKeystoreUnlockDialogResolver) return;
    const resolve = cryptKeystoreUnlockDialogResolver;
    cryptKeystoreUnlockDialogResolver = null;
    resolve(value);
  }

  function submitKeystoreUnlockDialog() {
    const inputEl = document.getElementById("crypt-keystore-unlock-password");
    const confirmEl = document.getElementById(
      "crypt-keystore-unlock-password-confirm",
    );
    resolveKeystoreUnlockPassword({
      password: inputEl?.value || "",
      confirmPassword: confirmEl?.value || "",
      mode: cryptKeystoreUnlockDialogMode,
    });
  }

  function requestPersistentKeystoreReset() {
    if (cryptKeystoreUnlockDialogMode !== "unlock") {
      return;
    }
    resolveKeystoreUnlockPassword({
      action: "reset",
    });
  }

  function requestManualUriFromContextMenuDialog(keystoreMode) {
    const dialogEl = document.getElementById("crypt-keystore-manual-uri-dialog");
    const descriptionEl = document.getElementById(
      "crypt-keystore-manual-uri-description",
    );
    const inputEl = document.getElementById("crypt-keystore-manual-uri-input");
    if (!dialogEl || !descriptionEl || !inputEl) return Promise.resolve(null);
    if (cryptManualUriDialogResolver) {
      const resolve = cryptManualUriDialogResolver;
      cryptManualUriDialogResolver = null;
      resolve(null);
    }
    cryptManualUriDialogMode =
      keystoreMode === CRYPT_KEYSTORE_MODE_PERSISTENT
        ? CRYPT_KEYSTORE_MODE_PERSISTENT
        : CRYPT_KEYSTORE_MODE_SESSION;
    const modeLabel =
      cryptManualUriDialogMode === CRYPT_KEYSTORE_MODE_PERSISTENT
        ? "persistent keychain"
        : "session keychain";
    descriptionEl.textContent = `Enter URI/URL to add to the ${modeLabel}.`;
    dialogEl.hidden = false;
    inputEl.value = "";
    inputEl.focus();
    return new Promise((resolve) => {
      cryptManualUriDialogResolver = resolve;
    });
  }

  function resolveManualUriFromContextMenuDialog(value) {
    const dialogEl = document.getElementById("crypt-keystore-manual-uri-dialog");
    const inputEl = document.getElementById("crypt-keystore-manual-uri-input");
    if (dialogEl) dialogEl.hidden = true;
    if (inputEl) inputEl.value = "";
    if (!cryptManualUriDialogResolver) return;
    const resolve = cryptManualUriDialogResolver;
    cryptManualUriDialogResolver = null;
    resolve({
      value,
      mode: cryptManualUriDialogMode,
    });
  }

  function submitManualUriFromContextMenuDialog() {
    const inputEl = document.getElementById("crypt-keystore-manual-uri-input");
    resolveManualUriFromContextMenuDialog(inputEl?.value || "");
  }

  async function resetPersistentKeystorePassword() {
    if (!(window.crypto && window.crypto.subtle)) {
      doError("WebCrypto API is unavailable; cannot reset keychain password.");
      return false;
    }

    const shouldReset = window.confirm(CRYPT_KEYSTORE_RESET_CONFIRMATION_MESSAGE);
    if (!shouldReset) {
      statusUpdate("Status: Keychain password reset cancelled");
      return false;
    }

    const dialogResult = await requestKeystoreUnlockPassword("setup");
    if (dialogResult?.action === "reset") {
      statusUpdate("Status: Keychain password reset cancelled");
      return false;
    }
    const normalizedPassword = (dialogResult?.password || "").trim();
    if (!normalizedPassword) {
      statusUpdate("Status: Keychain password reset cancelled");
      return false;
    }
    if (normalizedPassword.length < CRYPT_KEYSTORE_MIN_PASSWORD_LENGTH) {
      doError(
        `Keychain password must be at least ${CRYPT_KEYSTORE_MIN_PASSWORD_LENGTH} characters.`,
      );
      return false;
    }
    const normalizedConfirmPassword = String(
      dialogResult?.confirmPassword || "",
    ).trim();
    if (normalizedPassword !== normalizedConfirmPassword) {
      doError("Keychain password confirmation does not match.");
      return false;
    }

    try {
      const keyMaterial = await importCryptKeyMaterial(normalizedPassword);
      await savePersistentCryptKeystoreEntries([], keyMaterial);
      cryptPersistentKeystoreEntries = [];
      cryptKeystoreUnlockKeyMaterial = keyMaterial;
      renderCryptKeystoreList();
      statusUpdate("Status: Keychain password reset and persistent keychain wiped");
      writeLogEntry(`[${threadName}] Persistent keychain password reset; entries wiped`);
      return true;
    } catch (error) {
      logErrorEntry("crypt-keystore-reset-password", error);
      doError("Could not reset persistent keychain password.");
      return false;
    }
  }

  async function unlockPersistentKeystoreAndLoad() {
    if (!(window.crypto && window.crypto.subtle)) {
      doError("WebCrypto API is unavailable; cannot unlock keychain.");
      return false;
    }
    if (cryptKeystoreUnlockKeyMaterial) return true;

    const storedRecord = await loadCryptKeystore();
    const isInitialSetup = !storedRecord;
    const dialogResult = await requestKeystoreUnlockPassword(
      isInitialSetup ? "setup" : "unlock",
    );
    if (dialogResult?.action === "reset") {
      return resetPersistentKeystorePassword();
    }
    const normalizedPassword = (dialogResult?.password || "").trim();
    if (!normalizedPassword) {
      statusUpdate("Status: Keychain remains locked");
      return false;
    }
    if (normalizedPassword.length < CRYPT_KEYSTORE_MIN_PASSWORD_LENGTH) {
      doError(
        `Keychain password must be at least ${CRYPT_KEYSTORE_MIN_PASSWORD_LENGTH} characters.`,
      );
      return false;
    }
    if (
      isInitialSetup &&
      normalizedPassword !== String(dialogResult?.confirmPassword || "").trim()
    ) {
      doError("Keychain password confirmation does not match.");
      return false;
    }
    try {
      const keyMaterial = await importCryptKeyMaterial(normalizedPassword);
      if (isInitialSetup) {
        cryptPersistentKeystoreEntries = [];
        await savePersistentCryptKeystoreEntries([], keyMaterial);
        statusUpdate("Status: Keychain password set");
        writeLogEntry(`[${threadName}] Persistent keychain password initialized`);
      } else {
        cryptPersistentKeystoreEntries =
          await loadPersistentCryptKeystoreEntries(keyMaterial, storedRecord);
        statusUpdate("Status: Keychain unlocked");
        writeLogEntry(`[${threadName}] Persistent keychain unlocked`);
      }
      cryptKeystoreUnlockKeyMaterial = keyMaterial;
      return true;
    } catch (error) {
      logErrorEntry("crypt-keystore-unlock", error);
      doError(
        isInitialSetup
          ? "Could not initialize persistent keychain."
          : "Could not unlock persistent keychain. Verify password.",
      );
      return false;
    }
  }

  function showKeystoreWorkspace() {
    setActiveMainTab(MAIN_TAB_KEYSTORE);
    if (getJsonCapture() === "") {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      doError("Please upload a JSON file before accessing the keystore.");
      return;
    }

    if (
      cryptActiveKeystoreMode === CRYPT_KEYSTORE_MODE_PERSISTENT &&
      !cryptKeystoreUnlockKeyMaterial
    ) {
      doError("Please unlock the keychain with password first.");
      return;
    }
    statusUpdate("Status: Displaying keychain manager");
    writeLogEntry(`[${threadName}] User opened keystore workspace view`);
    document.getElementById("prev-btn").style.display = "none";
    document.getElementById("next-btn").style.display = "none";
    document.getElementById("packetInfoPane").style.display = "none";
    document.getElementById("packetPayloadPane").style.display = "none";
    document.getElementById("summary_box").style.display = "none";
    document.getElementById("stats_box").style.display = "none";
    document.getElementById("data_tools_box").style.display = "none";
    document.getElementById("list_box").style.display = "none";
    document.getElementById("notes_box").style.display = "none";
    document.getElementById("settings_box").style.display = "none";
    document.getElementById("crypt_box").style.display = "none";
    document.getElementById("rightside").style.display = "none";
    const keystoreBoxEl = document.getElementById("keystore_box");
    keystoreBoxEl.style.display = "flex";
    const modeEl = document.getElementById("crypt-keystore-mode");
    modeEl.value = cryptActiveKeystoreMode;

    renderCryptKeystoreList();
  }

  async function addToKeystoreFromContextMenu(type, keystoreMode) {
    const text = (
      getTrimmedSelectionText() || getActiveContextConversionText()
    ).trim();
    hideConvertContextMenu();
    if (!text) {
      statusUpdate("Status: No text to add to keystore");
      return;
    }
    if (keystoreMode === CRYPT_KEYSTORE_MODE_SESSION) {
      addSessionKeystoreEntry({
        type,
        label: "",
        source: "context-menu",
        content: text,
        summary: "",
      });
      statusUpdate(`Status: Saved ${type} in session keychain`);
      writeLogEntry(
        `[${threadName}] Context menu keystore entry added type=${type} mode=session`,
      );
    } else {
      await addCryptKeystoreEntry(
        { type, label: "", source: "context-menu", content: text, summary: "" },
        { force: true },
      );
    }
  }

  async function addManualUriToKeystoreFromContextMenu(keystoreMode) {
    hideConvertContextMenu();
    const dialogResult = await requestManualUriFromContextMenuDialog(
      keystoreMode,
    );
    if (!dialogResult) return;
    const normalized = normalizeUriCandidate(dialogResult.value);
    // make sure its actually a URI in format, otherwise we don't want to add it to the keystore
    if (!normalized) {
      statusUpdate("Status: No URI/URL provided");
      return;
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(normalized);
    } catch {
      statusUpdate("Status: Invalid URI/URL");
      return;
    }

    const normalizedUri = parsedUrl.href;
    const uriType = /^https?:$/i.test(parsedUrl.protocol) ? "url" : "uri";
    const entry = {
      type: uriType,
      label: `${uriType.toUpperCase()} ${normalizedUri}`,
      source: "context-menu-manual-uri",
      content: normalizedUri,
      summary: "Manual URI/URL entry from context menu",
    };

    if (dialogResult.mode === CRYPT_KEYSTORE_MODE_SESSION) {
      addSessionKeystoreEntry(entry);
      statusUpdate(`Status: Saved ${uriType} in session keychain`);
      writeLogEntry(`[${threadName}] Manual context URI saved mode=session type=${uriType}`);
      return;
    }

    await addCryptKeystoreEntry(entry, { force: true });
  }

  async function openSelectedKeystoreLinkInBrowser() {
    const listEl = document.getElementById("crypt-keystore-list");
    const selectedIndex = Number(listEl.value);
    const activeEntries = getActiveCryptKeystoreEntries();
    if (!Number.isFinite(selectedIndex) || !activeEntries[selectedIndex]) {
      statusUpdate("Status: Select a keystore entry first");
      return;
    }

    const selectedEntry = activeEntries[selectedIndex];
    const openableLink = normalizeOpenableLink(selectedEntry.content);
    if (!openableLink) {
      statusUpdate("Status: Selected entry is not an openable web link");
      return;
    }
    if (typeof openExternalUrl !== "function") {
      doError("External browser opening is unavailable in this environment.");
      return;
    }

    const result = await openExternalUrl(openableLink);
    if (result?.success) {
      statusUpdate("Status: Opened link in external browser");
      writeLogEntry(
        `[${threadName}] Keystore link opened in browser label="${selectedEntry.label}"`,
      );
      return;
    }

    const errorMessage =
      result && typeof result === "object" && "error" in result
        ? result.error
        : "unknown";
    doError("Could not open the selected link in browser.");
    logErrorEntry(`[${threadName}] crypt-keystore-open-link`, errorMessage || "unknown");
    statusUpdate(
      "Status: Could not open selected link – " + (errorMessage || "unknown"),
    );
  }

  return {
    addSessionKeystoreEntry,
    addCryptKeystoreEntry,
    loadSelectedCryptKeystoreEntry,
    deleteSelectedCryptKeystoreEntry,
    sendSelectedSessionEntryToPersistent,
    showKeystoreWorkspace,
    renderCryptKeystoreList,
    renderCryptKeystoreDetails,
    addToKeystoreFromContextMenu,
    addManualUriToKeystoreFromContextMenu,
    openSelectedKeystoreLinkInBrowser,
    unlockPersistentKeystoreAndLoad,
    resetPersistentKeystorePassword,
    submitKeystoreUnlockDialog,
    requestPersistentKeystoreReset,
    resolveKeystoreUnlockPassword,
    submitManualUriFromContextMenuDialog,
    resolveManualUriFromContextMenuDialog,
    importManualDataIntoSessionKeystore,
    getActiveCryptKeystoreEntries,
    setActiveMode(mode) {
      cryptActiveKeystoreMode = mode;
      renderCryptKeystoreList();
    },
    getSessionKeychainEntries() {
      return cryptSessionKeystoreEntries;
    },
    getKeystoreMode() {
      return cryptActiveKeystoreMode;
    },
    isUnlocked() {
      return !!cryptKeystoreUnlockKeyMaterial;
    },
    restoreSessionState(sessionKeychainEntries, keystoreMode) {
      sessionRebuildGeneration += 1;
      clearSessionScanCaches();
      cryptSessionKeystoreEntries = sessionKeychainEntries;
      if (
        keystoreMode === CRYPT_KEYSTORE_MODE_SESSION ||
        keystoreMode === CRYPT_KEYSTORE_MODE_PERSISTENT
      ) {
        cryptActiveKeystoreMode = keystoreMode;
      }
    },
    async rebuildSessionEntries() {
      const rebuildGeneration = ++sessionRebuildGeneration;
      const generatedEntries = await buildSessionAutoKeystoreEntries();
      if (rebuildGeneration !== sessionRebuildGeneration) {
        return cryptSessionKeystoreEntries.length;
      }
      cryptSessionKeystoreEntries = generatedEntries;
      if (cryptActiveKeystoreMode === CRYPT_KEYSTORE_MODE_SESSION) {
        renderCryptKeystoreList();
      }
      return cryptSessionKeystoreEntries.length;
    },
    resetKeystoreState() {
      sessionRebuildGeneration += 1;
      clearSessionScanCaches();
      cryptActiveKeystoreMode = CRYPT_KEYSTORE_MODE_SESSION;
      cryptSessionKeystoreEntries = [];
      cryptPersistentKeystoreEntries = [];
      cryptKeystoreUnlockKeyMaterial = null;
      cryptKeystoreUnlockDialogResolver = null;
      cryptKeystoreUnlockDialogMode = "unlock";
      cryptManualUriDialogResolver = null;
      cryptManualUriDialogMode = CRYPT_KEYSTORE_MODE_SESSION;
      renderCryptKeystoreList();
    },
    clearSessionScanCaches,
  };
}




module.exports = {
  id: "keystore",
  createKeystorePanel,
  CRYPT_KEYSTORE_MODE_SESSION,
  CRYPT_KEYSTORE_MODE_PERSISTENT,
  SESSION_KEYCHAIN_LABEL,
};
