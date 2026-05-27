const CRYPT_KEYSTORE_DB_NAME = "packetsnitch-crypt-keystore";
const CRYPT_KEYSTORE_DB_VERSION = 1;
const CRYPT_KEYSTORE_STORE_NAME = "entries";
const CRYPT_KEYSTORE_RECORD_KEY = "default";
const CRYPT_KEYSTORE_SCHEMA_VERSION = 2;
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
    detailsEl.textContent = [
      `Keychain: ${getActiveKeystoreLabel()}`,
      `Type: ${entry.type}`,
      `Label: ${entry.label}`,
      `Source: ${entry.source}`,
      entry.packetIndex !== undefined ? `Packet: ${entry.packetIndex}` : null,
      `Saved: ${entry.createdAt}`,
      entry.summary ? `Summary: ${entry.summary}` : "Summary: n/a",
    ]
      .filter(Boolean)
      .join("\n");
    updateCryptKeystoreWorkspaceState(entry);
  }

  function renderCryptKeystoreList() {
    const listEl = document.getElementById("crypt-keystore-list");
    const activeEntries = getActiveCryptKeystoreEntries();
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

  function hashContentForDeduplication(content) {
    let hash = 2166136261;
    for (let index = 0; index < content.length; index++) {
      hash ^= content.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return (hash >>> 0).toString(16);
  }

  function normalizeUriCandidate(uri) {
    return String(uri || "")
      .trim()
      .replace(/[),.;!?]+$/g, "");
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

  function shouldIncludeSessionSecretKey(pathKey) {
    if (!pathKey) return false;
    const lower = pathKey.toLowerCase();
    if (SESSION_SECRET_IGNORE_KEY_HINTS.some((hint) => lower.includes(hint))) {
      return false;
    }
    return SESSION_SECRET_KEY_HINTS.some((hint) => lower.includes(hint));
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

  function buildSessionAutoKeystoreEntries() {
    const generatedEntries = [];
    const dedupe = new Set();
    const hosts = getCapturedPackets()?.Host;
    if (!hosts || typeof hosts !== "object") return generatedEntries;

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

    Object.entries(hosts).forEach(([host, packets]) => {
      if (!Array.isArray(packets)) return;
      packets.forEach((packet) => {
        const packetInfo = packet?.["Packet Info"] || {};
        const protocol = packetInfo?.["Protocol"] ?? "Unknown";
        const transportData =
          packetInfo?.["Transport Layer"] || packetInfo?.[protocol] || {};
        const extraInfo = packet?.["Extra Info"] || {};
        const packetIndex = packetInfo?.["Index"] ?? "?";
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
            }
            if (!shouldIncludeSessionSecretKey(pathKey)) return;
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
          packetInfo?.["Raw data"]?.["Payload"]?.["Hex Encoded"];
        if (typeof payloadHex === "string" && payloadHex.trim()) {
          try {
            const payloadBytes = parseDataToolsInput("hex", payloadHex);
            const decodedHttp = decodeHttpFromBytes(payloadBytes);
            if (decodedHttp?.protocol === "HTTP") {
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
      });
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
      `Crypt keystore entry added type=${type} label="${entry.label}"`,
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
    if (selectedEntry.type === "certificate") {
      getApplyCryptCertificateText()(loadedContent, getActiveKeystoreLabel());
    } else if (selectedEntry.type === "private-key") {
      getApplyCryptPrivateKeyText()(loadedContent, getActiveKeystoreLabel());
    } else {
      document.getElementById("crypt-credential-input").value = loadedContent;
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
      `Crypt keystore entry deleted type=${removedEntry.type} label="${removedEntry.label}"`,
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
      `Session keychain entry persisted label="${selectedEntry.label}"`,
    );
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
    if (titleEl) {
      titleEl.textContent = isSetup
        ? "Set Keychain Password"
        : "Unlock Keychain";
    }
    if (descriptionEl) {
      descriptionEl.textContent = isSetup
        ? "Create the initial password for the persistent keychain (minimum 8 characters). You will only be asked when selecting the keychain tab."
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
    const normalizedPassword = (dialogResult?.password || "").trim();
    if (!normalizedPassword) {
      statusUpdate("Status: Keychain remains locked");
      return false;
    }
    if (normalizedPassword.length < 8) {
      doError("Keychain password must be at least 8 characters.");
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
        writeLogEntry("Persistent keychain password initialized");
      } else {
        cryptPersistentKeystoreEntries =
          await loadPersistentCryptKeystoreEntries(keyMaterial, storedRecord);
        statusUpdate("Status: Keychain unlocked");
        writeLogEntry("Persistent keychain unlocked");
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

    if (!cryptKeystoreUnlockKeyMaterial) {
      doError("Please unlock the keychain with password first.");
      return;
    }
    statusUpdate("Status: Displaying keychain manager");
    writeLogEntry("User opened keystore workspace");
    document.getElementById("prev-btn").style.display = "none";
    document.getElementById("next-btn").style.display = "none";
    document.getElementById("packetInfoPane").style.display = "none";
    document.getElementById("packetPayloadPane").style.display = "none";
    document.getElementById("summary_box").style.display = "none";
    document.getElementById("stats_box").style.display = "none";
    document.getElementById("data_tools_box").style.display = "none";
    document.getElementById("list_box").style.display = "none";
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
        `Context menu keystore entry added type=${type} mode=session`,
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
    const manualInput = window.prompt(
      "Enter URI/URL to add to the keystore:",
      "",
    );
    if (manualInput === null) return;
    const normalized = normalizeUriCandidate(manualInput);
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

    if (keystoreMode === CRYPT_KEYSTORE_MODE_SESSION) {
      addSessionKeystoreEntry(entry);
      statusUpdate(`Status: Saved ${uriType} in session keychain`);
      writeLogEntry(`Manual context URI saved mode=session type=${uriType}`);
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
        `Keystore link opened in browser label="${selectedEntry.label}"`,
      );
      return;
    }

    const errorMessage =
      result && typeof result === "object" && "error" in result
        ? result.error
        : "unknown";
    doError("Could not open the selected link in browser.");
    logErrorEntry("crypt-keystore-open-link", errorMessage || "unknown");
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
    submitKeystoreUnlockDialog,
    resolveKeystoreUnlockPassword,
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
      cryptSessionKeystoreEntries = sessionKeychainEntries;
      if (
        keystoreMode === CRYPT_KEYSTORE_MODE_SESSION ||
        keystoreMode === CRYPT_KEYSTORE_MODE_PERSISTENT
      ) {
        cryptActiveKeystoreMode = keystoreMode;
      }
    },
    rebuildSessionEntries() {
      cryptSessionKeystoreEntries = buildSessionAutoKeystoreEntries();
      return cryptSessionKeystoreEntries.length;
    },
    resetKeystoreState() {
      cryptActiveKeystoreMode = CRYPT_KEYSTORE_MODE_SESSION;
      cryptSessionKeystoreEntries = [];
      cryptPersistentKeystoreEntries = [];
      cryptKeystoreUnlockKeyMaterial = null;
      cryptKeystoreUnlockDialogResolver = null;
      cryptKeystoreUnlockDialogMode = "unlock";
      renderCryptKeystoreList();
    },
  };
}

module.exports = {
  id: "keystore",
  createKeystorePanel,
  CRYPT_KEYSTORE_MODE_SESSION,
  CRYPT_KEYSTORE_MODE_PERSISTENT,
  SESSION_KEYCHAIN_LABEL,
};
