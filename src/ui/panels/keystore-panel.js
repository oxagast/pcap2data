// Controls the keystore workspace UI and session-secret extraction workflows.

const CRYPT_KEYSTORE_DB_NAME = "packetsnitch-crypt-keystore";
const CRYPT_KEYSTORE_DB_VERSION = 2;
const CRYPT_KEYSTORE_STORE_NAME = "entries";
const CRYPT_KEYSTORE_FILES_STORE_NAME = "files";
const CRYPT_KEYSTORE_RECORD_KEY = "default";
const CRYPT_KEYSTORE_SCHEMA_VERSION = 2;
const threadName = "Keystore";
// The persistent keychain is encrypted at rest in IndexedDB with a fixed
// app-wide passphrase. The keystore only holds secrets that were already
// present in the loaded pcap, so there is no real security boundary being
// enforced by a user-chosen password — the encryption merely avoids
// writing plaintext credentials to disk. Keeping it automatic removes
// the unlock friction without changing the storage format.
const CRYPT_KEYSTORE_FIXED_PASSPHRASE =
  "packetsnitch-persistent-keystore-v2-fixed-passphrase";
const CRYPT_KEYSTORE_MODE_SESSION = "session";
const CRYPT_KEYSTORE_MODE_PERSISTENT = "persistent";
const SESSION_KEYCHAIN_LABEL = "session keychain";

// ── Artifact Store categories ─────────────────────────────────────────
// The user-facing tab is labeled "Artifact Store" but all internal
// naming (keystore, keystorePanel, DOM IDs, CSS classes, plugin
// capabilities, IndexedDB db name) stays unchanged.  Categories are a
// pure UI filter dimension layered on top of the existing flat ``type``
// field — legacy sessions without a category still render under "all".
const ARTIFACT_CATEGORY_ALL = "all";
const ARTIFACT_CATEGORY_SECRETS = "secrets";
const ARTIFACT_CATEGORY_ITEMS = "items";
const ARTIFACT_CATEGORY_FILES = "files";
const ARTIFACT_CATEGORY_MISC = "misc";
const ARTIFACT_CATEGORIES = [
  ARTIFACT_CATEGORY_ALL,
  ARTIFACT_CATEGORY_SECRETS,
  ARTIFACT_CATEGORY_ITEMS,
  ARTIFACT_CATEGORY_FILES,
  ARTIFACT_CATEGORY_MISC,
];

// Map a flat entry ``type`` string to one of the major categories.
// Unrecognized types fall back to ``misc`` so legacy/unknown entries are
// always visible somewhere.
const ARTIFACT_TYPE_TO_CATEGORY = {
  secret: ARTIFACT_CATEGORY_SECRETS,
  password: ARTIFACT_CATEGORY_SECRETS,
  "private-key": ARTIFACT_CATEGORY_SECRETS,
  cookie: ARTIFACT_CATEGORY_SECRETS,
  "aws-access-key": ARTIFACT_CATEGORY_SECRETS,
  "aws-secret-key": ARTIFACT_CATEGORY_SECRETS,
  "github-token": ARTIFACT_CATEGORY_SECRETS,
  "discord-token": ARTIFACT_CATEGORY_SECRETS,
  "jwt-token": ARTIFACT_CATEGORY_SECRETS,
  "oauth-token": ARTIFACT_CATEGORY_SECRETS,
  "api-token": ARTIFACT_CATEGORY_SECRETS,
  "azure-key": ARTIFACT_CATEGORY_SECRETS,
  "gcp-key": ARTIFACT_CATEGORY_SECRETS,
  "gcp-service-account-key": ARTIFACT_CATEGORY_SECRETS,
  "gcp-oauth-token": ARTIFACT_CATEGORY_SECRETS,
  certificate: ARTIFACT_CATEGORY_ITEMS,
  email: ARTIFACT_CATEGORY_ITEMS,
  url: ARTIFACT_CATEGORY_ITEMS,
  uri: ARTIFACT_CATEGORY_ITEMS,
  file: ARTIFACT_CATEGORY_FILES,
  goodie: ARTIFACT_CATEGORY_MISC,
};

function categoryForType(type) {
  const normalized = String(type || "").toLowerCase().trim();
  return ARTIFACT_TYPE_TO_CATEGORY[normalized] || ARTIFACT_CATEGORY_MISC;
}

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

// ── Token / secret regex patterns ───────────────────────────────────
// Module-level so both the Web Worker source string and the main-thread
// file-rescan path share the same detection set.  Each entry is
// { regex, type } — the regex must be global (used with .exec in a loop).
const TOKEN_REGEX_PATTERNS = [
  // AWS access keys (AKIA = standard, ASIA = temporary/sts)
  { regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, type: "aws-access-key" },
  // AWS secret keys — 40-char base64-ish when the path/key hints "aws"
  // (handled separately via path-key inference below, not pure regex)
  // GitHub tokens: ghp_ (PAT), gho_ (OAuth), ghs_ (server), ghu_ (user),
  // ghr_ (refresh), github_pat_ (fine-grained PAT)
  { regex: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, type: "github-token" },
  { regex: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, type: "github-token" },
  // Discord tokens: mfa.<long> or <24>.<6>.<20+>
  { regex: /\bmfa\.[A-Za-z0-9_-]{80,}\b/g, type: "discord-token" },
  { regex: /\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{20,}\b/g, type: "discord-token" },
  // JWT tokens: eyJ<header>.<payload>.<signature>
  { regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, type: "jwt-token" },
  // Google OAuth access tokens: ya29.<token>
  { regex: /\bya29\.[A-Za-z0-9._-]{20,}\b/g, type: "gcp-oauth-token" },
  // Google API keys: AIza<35 chars> (AIzaSy is common prefix)
  { regex: /\bAIza[0-9A-Za-z_-]{35}\b/g, type: "gcp-key" },
];

// Path-key inference: when the field/path name contains a secret-related
// keyword, infer the token type from the keyword.  Used when the value
// itself doesn't match a known pattern but the key name suggests a secret.
const TOKEN_PATH_KEY_HINTS = [
  "token", "apikey", "api_key", "api-key", "oauth", "authorization",
  "auth", "discord", "github", "azure", "aws", "gcp", "google",
  "secret", "accountkey", "service_account", "private_key_id",
];

// Infer a token type from a path key name.  Returns null if no inference.
function inferTypeFromPathKey(lowerPath) {
  if (lowerPath.includes("oauth") || lowerPath.includes("bearer"))
    return "oauth-token";
  if (lowerPath.includes("discord")) return "discord-token";
  if (lowerPath.includes("github")) return "github-token";
  if (lowerPath.includes("gcp") || lowerPath.includes("google"))
    return "gcp-key";
  if (lowerPath.includes("azure") || lowerPath.includes("accountkey"))
    return "azure-key";
  if (lowerPath.includes("aws")) return "aws-secret-key";
  return "api-token";
}

let goodiesStash = null;

const {
  initKeystoreLlmSummarizer,
  requestKeystoreReviewNow,
  clearKeystoreSummary,
  stopKeystoreReview,
  stopKeystoreReviewTimer,
} = require("./keystore-llm-summarizer");

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
  callLargeLanguageModel,
  isLlmRuntimeEnabled,
  isBackgroundSummaryGenerationEnabled,
  listCarvableFilesForStats,
  listDownloadedFilesForStats,
  openCarvedFileInConv,
}) {
  let cryptPersistentKeystoreEntries = [];
  let cryptSessionKeystoreEntries = [];
  let cryptActiveKeystoreMode = CRYPT_KEYSTORE_MODE_SESSION;
  let cryptActiveCategory = ARTIFACT_CATEGORY_ALL;
  let cryptKeystoreUnlockKeyMaterial = null;
  let cryptManualUriDialogResolver = null;
  let cryptManualUriDialogMode = CRYPT_KEYSTORE_MODE_SESSION;
  let sessionRebuildGeneration = 0;
  const sessionScanHydratedPacketCache = new Map();
  let cryptRenderedKeystoreEntries = [];
  // In-memory mirror of persisted file artifacts, kept in sync on every
  // persistFileArtifact call so getFileArtifactSnapshot() stays synchronous
  // (buildSessionStateSnapshot is sync — making it async would require
  // auditing all 3 call sites). Each entry: {id, protocol, fileName,
  // bytesBase64, byteLength, label, sourceDetail}.
  let cryptFileArtifactMirror = [];
  // The public API surface of this panel. It must be assigned before the
  // panel returns so that the keystore-llm-summarizer callback (registered
  // above) can resolve the panel methods lazily without triggering a
  // ReferenceError when the methods are still being defined.
  let panelApi = null;

  initKeystoreLlmSummarizer({
    callLargeLanguageModel,
    isLlmRuntimeEnabled,
    isBackgroundSummaryGenerationEnabled,
    statusUpdate,
    writeLogEntry,
    getKeystorePanelApi: () => panelApi,
  });

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
        // v2: add the files store for persisted file artifacts. The
        // existing entries store (persistent secrets) is left intact.
        if (!db.objectStoreNames.contains(CRYPT_KEYSTORE_FILES_STORE_NAME)) {
          db.createObjectStore(CRYPT_KEYSTORE_FILES_STORE_NAME);
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
      doError("Could not save the persistent local store.");
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

  // ── File artifact persistence (IndexedDB files store) ───────────────
  // File artifacts are persisted to a dedicated IndexedDB object store
  // (``files``, keyed by candidate.id) and also serialized into
  // ``session.state.fileArtifacts`` as ``bytesBase64`` strings so they
  // survive session save/load AND cross-machine moves.

  function toBase64Local(bytes) {
    return window.btoa(
      Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""),
    );
  }

  function fromBase64Local(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }

  async function persistFileArtifact(candidate) {
    if (!candidate || typeof candidate !== "object") return;
    const bytes = candidate.bytes;
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return;
    const fileId = candidate.id || `${candidate.protocol}|${candidate.fileName}|${bytes.length}`;
    const bytesBase64 = toBase64Local(bytes);
    const record = {
      id: fileId,
      protocol: candidate.protocol || "FILE",
      fileName: candidate.fileName || "",
      bytesBase64,
      byteLength: bytes.length,
      label: candidate.label || "",
      sourceDetail: candidate.sourceDetail || "",
      savedAt: new Date().toISOString(),
    };
    // Update the in-memory mirror synchronously.
    const mirrorIndex = cryptFileArtifactMirror.findIndex(
      (entry) => entry.id === fileId,
    );
    if (mirrorIndex >= 0) {
      cryptFileArtifactMirror[mirrorIndex] = record;
    } else {
      cryptFileArtifactMirror.push(record);
    }
    // Best-effort IndexedDB write.
    try {
      const db = await openCryptKeystoreDb();
      const transaction = db.transaction(
        CRYPT_KEYSTORE_FILES_STORE_NAME,
        "readwrite",
      );
      const store = transaction.objectStore(CRYPT_KEYSTORE_FILES_STORE_NAME);
      store.put(record, fileId);
      await waitForIdbTransaction(transaction);
      db.close();
    } catch (error) {
      logErrorEntry("artifact-store-file-persist", error);
    }
  }

  function getFileArtifactSnapshot() {
    return cryptFileArtifactMirror.map((entry) => ({
      id: entry.id,
      protocol: entry.protocol,
      fileName: entry.fileName,
      bytesBase64: entry.bytesBase64,
      byteLength: entry.byteLength,
      label: entry.label,
      sourceDetail: entry.sourceDetail,
    }));
  }

  async function restoreFileArtifacts(entries) {
    if (!Array.isArray(entries)) return [];
    const restored = [];
    for (const entry of entries) {
      if (!entry || typeof entry !== "object" || !entry.id) continue;
      let bytes = null;
      if (entry.bytesBase64) {
        try {
          bytes = fromBase64Local(entry.bytesBase64);
        } catch (error) {
          logErrorEntry("artifact-store-file-restore-decode", error);
        }
      }
      const record = {
        id: entry.id,
        protocol: entry.protocol || "FILE",
        fileName: entry.fileName || "",
        bytesBase64: entry.bytesBase64 || "",
        byteLength: entry.byteLength || (bytes ? bytes.length : 0),
        label: entry.label || "",
        sourceDetail: entry.sourceDetail || "",
        savedAt: entry.savedAt || new Date().toISOString(),
      };
      restored.push(record);
      // Write back to IndexedDB so the live session is consistent.
      if (bytes) {
        try {
          const db = await openCryptKeystoreDb();
          const transaction = db.transaction(
            CRYPT_KEYSTORE_FILES_STORE_NAME,
            "readwrite",
          );
          const store = transaction.objectStore(CRYPT_KEYSTORE_FILES_STORE_NAME);
          store.put(record, record.id);
          await waitForIdbTransaction(transaction);
          db.close();
        } catch (error) {
          logErrorEntry("artifact-store-file-restore-idb", error);
        }
      }
    }
    cryptFileArtifactMirror = restored;
    return restored;
  }

  async function clearFileArtifactStore() {
    cryptFileArtifactMirror = [];
    try {
      const db = await openCryptKeystoreDb();
      const transaction = db.transaction(
        CRYPT_KEYSTORE_FILES_STORE_NAME,
        "readwrite",
      );
      const store = transaction.objectStore(CRYPT_KEYSTORE_FILES_STORE_NAME);
      store.clear();
      await waitForIdbTransaction(transaction);
      db.close();
    } catch (error) {
      logErrorEntry("artifact-store-file-clear", error);
    }
  }

  function getActiveCryptKeystoreEntries() {
    return cryptActiveKeystoreMode === CRYPT_KEYSTORE_MODE_SESSION
      ? cryptSessionKeystoreEntries
      : cryptPersistentKeystoreEntries;
  }

  function getRenderedCryptKeystoreEntries() {
    return cryptRenderedKeystoreEntries;
  }

  function getActiveKeystoreLabel() {
    return cryptActiveKeystoreMode === CRYPT_KEYSTORE_MODE_SESSION
      ? SESSION_KEYCHAIN_LABEL
      : "persistent store";
  }

  // Filter an entries array by the active category.  ``"all"`` returns
  // the array unchanged.  Used by ``renderCryptKeystoreList`` and the
  // text-filter handler so category + search compose correctly.
  function filterEntriesByCategory(entries, category) {
    if (!Array.isArray(entries)) return [];
    if (!category || category === ARTIFACT_CATEGORY_ALL) return entries;
    return entries.filter(
      (entry) => categoryForType(entry?.type) === category,
    );
  }

  function getActiveCategoryEntries() {
    return filterEntriesByCategory(
      getActiveCryptKeystoreEntries(),
      cryptActiveCategory,
    );
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
    const isFilesCategory = cryptActiveCategory === ARTIFACT_CATEGORY_FILES;
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
    // When the Files category is active, disable the secret/cert/key save
    // buttons and send-to-persistent — file entries are session-only mirrors.
    saveCertBtn.disabled = !isPersistentMode || isFilesCategory;
    saveKeyBtn.disabled = !isPersistentMode || isFilesCategory;
    saveSecretBtn.disabled = !isPersistentMode || isFilesCategory;
    sendToPersistentBtn.disabled = isPersistentMode || isFilesCategory;
    deleteBtn.disabled = !isPersistentMode;
    if (openLinkBtn) {
      openLinkBtn.disabled = !canEntryOpenInBrowser(activeEntry);
    }
    const unlockStatusEl = document.getElementById(
      "crypt-keystore-unlock-status",
    );
    unlockStatusEl.textContent = isPersistentMode
      ? "Persistent store is auto-unlocked for this app session."
      : "Session artifacts are auto-populated from decodable packet secrets and cert-tab imports.";
  }

  function renderCryptKeystoreDetails(entry) {
    const detailsEl = document.getElementById("crypt-keystore-details");
    if (!entry) {
      detailsEl.textContent = `No entries available in ${getActiveKeystoreLabel()}.`;
      updateCryptKeystoreWorkspaceState(null);
      return;
    }

    // File-type entries show file-specific metadata instead of content.
    if (entry.type === "file" && entry.__fileArtifact) {
      const fa = entry.__fileArtifact;
      detailsEl.textContent = [
        `Store: ${getActiveKeystoreLabel()}`,
        `Type: ${entry.type}`,
        `Label: ${entry.label}`,
        `Source: ${entry.source}`,
        `Protocol: ${fa.protocol}`,
        `File name: ${fa.fileName}`,
        `File size: ${fa.byteLength} bytes`,
        entry.summary ? `Summary: ${entry.summary}` : "Summary: n/a",
        `Saved: ${entry.createdAt}`,
      ]
        .filter(Boolean)
        .join("\n");
      updateCryptKeystoreWorkspaceState(entry);
      return;
    }

    const normalizedContent = normalizeSessionSecretValue(entry.content);
    const contentPreview = normalizedContent
      ? normalizedContent.replace(/\r?\n/g, " ").slice(0, 140)
      : "";
    detailsEl.textContent = [
      `Store: ${getActiveKeystoreLabel()}`,
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

  // Tracks the selected keystore list index for the <div> renderer.
  let cryptKeystoreSelectedIndex = 0;

  function renderCryptKeystoreList(listEntries = null) {
    const listEl = document.getElementById("crypt-keystore-list");
    // When the caller passes an explicit filtered array (e.g. from the
    // text-filter handler), use it as-is.  Otherwise apply the active
    // category filter on top of the mode's entries.
    const activeEntries = listEntries || getActiveCategoryEntries();
    // Deduplicate by content value — each secret/token value only shows
    // up once in the list.  File-type entries are exempt: the same file
    // extracted at different times should appear separately (different
    // timestamps).  Non-secret entries with empty content (e.g. file
    // entries) also pass through without dedup.
    const seenContent = new Set();
    const dedupedEntries = [];
    for (const entry of activeEntries) {
      if (entry.type === "file") {
        dedupedEntries.push(entry);
        continue;
      }
      const contentKey = String(entry.content || "").trim();
      if (!contentKey) {
        dedupedEntries.push(entry);
        continue;
      }
      if (seenContent.has(contentKey)) continue;
      seenContent.add(contentKey);
      dedupedEntries.push(entry);
    }
    cryptRenderedKeystoreEntries = dedupedEntries;
    cryptKeystoreSelectedIndex = 0;
    listEl.replaceChildren();

    if (!dedupedEntries.length) {
      const emptyEl = document.createElement("div");
      emptyEl.className = "keystore-list-empty";
      emptyEl.textContent = `No entries in ${getActiveKeystoreLabel()}.`;
      listEl.appendChild(emptyEl);
      renderCryptKeystoreDetails(null);
      return;
    }

    dedupedEntries.forEach((entry, index) => {
      const itemEl = document.createElement("div");
      itemEl.className = "keystore-list-item";
      itemEl.dataset.index = String(index);
      itemEl.textContent = `[${entry.type}] ${entry.label}`;
      if (index === 0) itemEl.classList.add("keystore-list-selected");

      itemEl.addEventListener("click", () => {
        listEl.querySelectorAll(".keystore-list-item")
          .forEach((el) => el.classList.remove("keystore-list-selected"));
        itemEl.classList.add("keystore-list-selected");
        cryptKeystoreSelectedIndex = index;
        renderCryptKeystoreDetails(dedupedEntries[index]);
      });

      listEl.appendChild(itemEl);
    });

    renderCryptKeystoreDetails(dedupedEntries[0]);
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
      regexExtract(/\bya29\.[A-Za-z0-9._-]{20,}\b/g, "gcp-oauth-token");
      regexExtract(/\bAIza[0-9A-Za-z_-]{35}\b/g, "gcp-key");

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
        lowerPath.includes("gcp") ||
        lowerPath.includes("google") ||
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
          else if (lowerPath.includes("gcp") || lowerPath.includes("google")) {
            inferredType = "gcp-key";
          }
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

      // GCP service account private_key_id (hex, 20+ chars)
      const gcpSaKeyMatch = text.match(
        /"private_key_id"\s*:\s*"([a-f0-9]{20,})"/i,
      );
      if (gcpSaKeyMatch?.[1]) {
        addMatch("gcp-service-account-key", gcpSaKeyMatch[1]);
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
    // Apply the category filter first, then run the text grep over the
    // category-filtered set so category + search compose correctly.
    const categoryFilteredEntries = getActiveCategoryEntries();
    let typeEntriesGrep = grepSessionKeystoreEntriesByType(filterValue, categoryFilteredEntries);
    let contentEntriesGrep = grepSessionKeystoreEntriesByContent(filterValue, categoryFilteredEntries);
    let labelEntriesGrep = grepSessionKeystoreEntriesByLabel(filterValue, categoryFilteredEntries);
    let newEntries = [];
    if (filterValue) {
      newEntries = [...typeEntriesGrep, ...contentEntriesGrep, ...labelEntriesGrep];
    } else {
      newEntries = categoryFilteredEntries.slice();
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

  // The "Rescan for Artifacts" button lives in the left sidebar
  // (#rescan-files-btn) and is wired in main-frontend.js, not here —
  // it calls keystorePanel.rescanFileArtifactsForSecrets() via the
  // panel API.

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

  // Build file-type entries from the carved/downloaded file registries.
  // These are "mirror" entries — the Stats tab keeps its own inline
  // Carvable/Downloaded Files sections; the Artifact Store Files category
  // is an additional surface fed from the same registries.  File entries
  // carry ``__fileArtifact`` metadata so ``loadSelectedCryptKeystoreEntry``
  // can open them in Conv via the injected ``openCarvedFileInConv`` callback.
  async function buildFileArtifactEntries() {
    const fileEntries = [];
    const seenIds = new Set();
    const addCandidate = (candidate) => {
      if (!candidate || typeof candidate !== "object") return;
      const fileId = candidate.id || `${candidate.protocol}|${candidate.fileName}|${candidate.byteLength}`;
      if (seenIds.has(fileId)) return;
      seenIds.add(fileId);
      fileEntries.push({
        id: generateCryptEntryId(),
        type: "file",
        label: candidate.label || `${candidate.protocol || "FILE"}: ${candidate.fileName || "unknown"}`,
        source: `session-auto-file-${String(candidate.protocol || "file").toLowerCase()}`,
        content: "",
        summary: candidate.sourceDetail || "",
        packetIndex: "?",
        protocol: candidate.protocol || "FILE",
        createdAt: new Date().toISOString(),
        __fileArtifact: {
          id: fileId,
          protocol: candidate.protocol || "FILE",
          fileName: candidate.fileName || "",
          byteLength: candidate.byteLength || (candidate.bytes ? candidate.bytes.length : 0),
          bytes: candidate.bytes || null,
        },
      });
    };
    if (typeof listCarvableFilesForStats === "function") {
      try {
        const carvables = await listCarvableFilesForStats();
        if (Array.isArray(carvables)) {
          carvables.forEach(addCandidate);
        }
      } catch (error) {
        logErrorEntry("artifact-store-carvable-mirror", error);
      }
    }
    if (typeof listDownloadedFilesForStats === "function") {
      try {
        const downloaded = listDownloadedFilesForStats();
        if (Array.isArray(downloaded)) {
          downloaded.forEach(addCandidate);
        }
      } catch (error) {
        logErrorEntry("artifact-store-downloaded-mirror", error);
      }
    }
    // Also include file artifacts restored from a saved session (the
    // in-memory mirror).  These may overlap with live-registry entries
    // (deduped by file id) or be the only source of file bytes when the
    // live registries have been cleared (e.g. after a session reload).
    cryptFileArtifactMirror.forEach((record) => {
      let bytes = null;
      if (record.bytesBase64) {
        try {
          bytes = fromBase64Local(record.bytesBase64);
        } catch {
          // ignore decode errors — bytes stay null
        }
      }
      addCandidate({
        id: record.id,
        protocol: record.protocol,
        fileName: record.fileName,
        bytes,
        byteLength: record.byteLength,
        label: record.label,
        sourceDetail: record.sourceDetail,
      });
    });
    return fileEntries;
  }

  // Lightweight refresh that only re-derives file entries from the live
  // registries and merges them into the existing session keystore —
  // without re-scanning all packets for secrets (which
  // ``rebuildSessionEntries`` does).  Called after a carve/download
  // so newly registered files appear immediately in the Files category.
  async function refreshFileArtifacts() {
    const fileEntries = await buildFileArtifactEntries();
    const newFileIds = new Set(fileEntries.map((e) => e.__fileArtifact.id));
    // Remove existing file entries that are stale (no bytes or no longer
    // in the registries) and merge in fresh ones with bytes from the
    // live registries + the restored mirror.
    const nonFileEntries = cryptSessionKeystoreEntries.filter(
      (entry) => entry.type !== "file",
    );
    const existingFileEntries = cryptSessionKeystoreEntries.filter(
      (entry) => entry.type === "file" && entry.__fileArtifact,
    );
    // Keep existing file entries that aren't in the new set (they may
    // have been restored from a saved session with bytes).
    const keptFileEntries = existingFileEntries.filter(
      (entry) => !newFileIds.has(entry.__fileArtifact.id),
    );
    let added = 0;
    fileEntries.forEach((fileEntry) => {
      // Skip if the new entry has no bytes AND an existing one already
      // has bytes for the same id — prefer the one with bytes.
      const existing = existingFileEntries.find(
        (e) => e.__fileArtifact.id === fileEntry.__fileArtifact.id,
      );
      if (existing && existing.__fileArtifact.bytes && !fileEntry.__fileArtifact.bytes) {
        return; // keep the existing one with bytes
      }
      added += 1;
    });
    cryptSessionKeystoreEntries = [...fileEntries, ...keptFileEntries, ...nonFileEntries];
    if (cryptActiveKeystoreMode === CRYPT_KEYSTORE_MODE_SESSION) {
      renderCryptKeystoreList();
    }
    return added;
  }

  // ── File content secret scanner ───────────────────────────────────
  // Main-thread token detection over extracted/carved file bytes.  Uses
  // the same regex patterns as the Web Worker detector (TOKEN_REGEX_PATTERNS)
  // so results are consistent.  Returns an array of keystore entries.
  function detectTokensInText(text, pathKey) {
    const matches = [];
    if (!text) return matches;
    const lowerPath = String(pathKey || "").toLowerCase();
    const addMatch = (type, token) => {
      const trimmed = String(token || "").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
      if (!trimmed) return;
      matches.push({ type, content: trimmed });
    };
    const regexExtract = (regex, type) => {
      regex.lastIndex = 0;
      let m;
      while ((m = regex.exec(text)) !== null) {
        addMatch(type, m[0]);
      }
    };
    TOKEN_REGEX_PATTERNS.forEach(({ regex, type }) => regexExtract(regex, type));
    // Bearer token
    if (/\bBearer\s+[A-Za-z0-9._~-]{20,}\b/i.test(text)) {
      addMatch("oauth-token", text.replace(/^.*?\bBearer\s+/i, "").trim());
    }
    // Path-key inference
    const hasSecretKey = TOKEN_PATH_KEY_HINTS.some((h) => lowerPath.includes(h));
    if (hasSecretKey) {
      const candidate = text.replace(/^bearer\s+/i, "").trim();
      if (candidate.length >= 20) {
        addMatch(inferTypeFromPathKey(lowerPath), candidate);
      }
    }
    // Azure AccountKey=
    const akMatch = text.match(/AccountKey=([^;\s]+)/i);
    if (akMatch?.[1]) addMatch("azure-key", akMatch[1]);
    // Azure base64 keys
    if (/^[A-Za-z0-9+/]{43}=$/.test(text) || /^[A-Za-z0-9+/]{86}==$/.test(text)) {
      if (lowerPath.includes("azure") || lowerPath.includes("accountkey")) {
        addMatch("azure-key", text);
      }
    }
    // AWS secret key (40-char base64)
    if (/^[A-Za-z0-9/+=]{40}$/.test(text) && lowerPath.includes("aws")) {
      addMatch("aws-secret-key", text);
    }
    // GCP service account private_key_id
    const gcpMatch = text.match(/"private_key_id"\s*:\s*"([a-f0-9]{20,})"/i);
    if (gcpMatch?.[1]) addMatch("gcp-service-account-key", gcpMatch[1]);
    // Goodies (PEM blocks, connection strings, etc.)
    const GOODIE_PATTERNS = [
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
      /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
      /\b(?:mysql|postgres|mongodb(?:\+srv)?|redis|amqp|ldap|ftp|sftp|smb):\/\/[^\s"'<>]{10,}/gi,
    ];
    GOODIE_PATTERNS.forEach((regex) => regexExtract(regex, "goodie"));
    return matches;
  }

  // Scan extracted/carved file bytes for embedded secrets.  Called when
  // the user clicks "Rescan Files" or automatically after archive
  // extraction / decompression.  Decodes file bytes as UTF-8 (lenient)
  // and runs the same token + credential detection used for packet
  // payloads.  Discovered secrets are merged into the session keystore.
  async function rescanFileArtifactsForSecrets() {
    const fileEntries = await buildFileArtifactEntries();
    const discovered = [];
    const dedupe = new Set();

    const addDiscovery = ({ type, content, label, summary, protocol }) => {
      const normalized = normalizeSessionSecretValue(content);
      if (!normalized) return;
      const fingerprint = `${type}|${hashContentForDeduplication(normalized)}`;
      if (dedupe.has(fingerprint)) return;
      dedupe.add(fingerprint);
      discovered.push({
        id: generateCryptEntryID(),
        type,
        label: label || `${type.toUpperCase()} ${normalized.slice(0, 64)}`,
        source: "session-auto-file-scan",
        content: normalized,
        summary: summary || "",
        packetIndex: "?",
        protocol: protocol || "FILE",
        createdAt: new Date().toISOString(),
      });
    };

    for (const fileEntry of fileEntries) {
      const fa = fileEntry.__fileArtifact;
      if (!fa) continue;
      const bytes = fa.bytes;
      if (!bytes || (bytes.length ?? 0) === 0) continue;

      // Decode as UTF-8 lenient (binary files will produce garbage but
      // regex patterns are specific enough to avoid false positives).
      let decodedText;
      try {
        decodedText = new TextDecoder("utf-8", { fatal: false }).decode(
          bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes),
        );
      } catch {
        continue;
      }
      if (!decodedText) continue;

      const fileLabel = fileEntry.label || fa.fileName || "extracted file";
      const fileProtocol = fa.protocol || "FILE";
      const summaryPrefix = `File: ${fileLabel}`;

      // Run token detection on file content
      const tokenMatches = detectTokensInText(decodedText, "file-content");
      for (const { type, content } of tokenMatches) {
        addDiscovery({
          type,
          content,
          label: `${type.toUpperCase()} from ${fa.fileName || "file"}`,
          summary: `${summaryPrefix} (${content.slice(0, 40)}…)`,
          protocol: fileProtocol,
        });
      }

      // Also scan for credential key=value patterns in text
      const credPattern =
        /(?:^|[\s,;&])((?:password|passwd|pwd|secret|api[_-]?key|apikey|token|access_token|refresh_token|client_secret|auth_token|private_key)\s*[=:]\s*)([^\s&"'<>,;]{3,512})/gi;
      let credMatch;
      while ((credMatch = credPattern.exec(decodedText)) !== null) {
        const credValue = credMatch[2];
        addDiscovery({
          type: "secret",
          content: credValue,
          label: `Credential from ${fa.fileName || "file"}`,
          summary: `${summaryPrefix} key=${credMatch[1].trim()}`,
          protocol: fileProtocol,
        });
      }

      // JSON credential extraction: "key": "value" where key looks like a
      // credential field.  Uses a simpler keyword alternation than the
      // packet-level scanner to stay webpack-parse-friendly.
      const jsonCredPattern =
        /"(?:[a-z0-9_\-.]*)?(?:pass|pw|secret|auth|credential|api[_\-.]?key|token|user|login|email|private_key|client_secret)(?:[a-z0-9_\-.]*)?"\s*:\s*"([^"]{3,512})"/gi;
      let jsonMatch;
      while ((jsonMatch = jsonCredPattern.exec(decodedText)) !== null) {
        const jsonValue = jsonMatch[1];
        addDiscovery({
          type: "secret",
          content: jsonValue,
          label: `JSON credential from ${fa.fileName || "file"}`,
          summary: `${summaryPrefix} key=${jsonMatch[0].split(":")[0].trim()}`,
          protocol: fileProtocol,
        });
      }
    }

    // Merge discovered secrets into session keystore (deduped against
    // existing entries by type+content hash)
    let added = 0;
    const existingFingerprints = new Set(
      cryptSessionKeystoreEntries.map(
        (e) => `${e.type}|${hashContentForDeduplication(e.content)}`,
      ),
    );
    for (const entry of discovered) {
      const fp = `${entry.type}|${hashContentForDeduplication(entry.content)}`;
      if (existingFingerprints.has(fp)) continue;
      existingFingerprints.add(fp);
      cryptSessionKeystoreEntries.push(entry);
      added += 1;
    }

    if (added > 0 && cryptActiveKeystoreMode === CRYPT_KEYSTORE_MODE_SESSION) {
      renderCryptKeystoreList();
    }

    if (typeof statusUpdate === "function") {
      statusUpdate(
        added > 0
          ? `File rescan: ${added} secret${added === 1 ? "" : "s"} found in extracted files`
          : "File rescan complete — no new secrets found in extracted files",
      );
    }
    return added;
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

    // Surface carved + downloaded files as file-type entries in the Files
    // category.  These are mirrors of the Stats-tab inline sections.
    const fileEntries = await buildFileArtifactEntries();
    fileEntries.forEach((fileEntry) => {
      const fingerprint = `file|${fileEntry.__fileArtifact.id}`;
      if (dedupe.has(fingerprint)) return;
      dedupe.add(fingerprint);
      generatedEntries.push(fileEntry);
    });

    // Scan extracted/carved file bytes for embedded secrets.  Files may
    // contain secrets that weren't visible in the packet-level scan
    // (e.g. extracted from ZIP archives, decompressed from gzip, or
    // decrypted from PGP).  This ensures their contents are scanned.
    for (const fileEntry of fileEntries) {
      const fa = fileEntry.__fileArtifact;
      if (!fa) continue;
      const bytes = fa.bytes;
      if (!bytes || (bytes.length ?? 0) === 0) continue;
      let decodedText;
      try {
        decodedText = new TextDecoder("utf-8", { fatal: false }).decode(
          bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes),
        );
      } catch {
        continue;
      }
      if (!decodedText) continue;
      const tokenMatches = detectTokensInText(decodedText, "file-content");
      for (const { type, content } of tokenMatches) {
        pushSessionEntry({
          type,
          label: `${type.toUpperCase()} from ${fa.fileName || "file"}`,
          source: "session-auto-file-scan",
          content,
          summary: `File: ${fileEntry.label}`,
          packetIndex: "?",
          protocol: fa.protocol || "FILE",
        });
      }
    }

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
    requestKeystoreReviewNow();
  }

  async function addCryptKeystoreEntry(
    { type, label, source, content, summary },
    { force = false } = {},
  ) {
    // File-type entries are session-only mirrors of the carved/downloaded
    // file registries — they are never persisted to the persistent store.
    if (type === "file") {
      statusUpdate("Status: File artifacts are session-only and cannot be saved to the persistent store");
      return;
    }
    if (!force && cryptActiveKeystoreMode !== CRYPT_KEYSTORE_MODE_PERSISTENT) {
      statusUpdate("Status: Switch to persistent store to save entries");
      return;
    }
    if (!cryptKeystoreUnlockKeyMaterial) {
      cryptKeystoreUnlockKeyMaterial = await importCryptKeyMaterial(
        CRYPT_KEYSTORE_FIXED_PASSPHRASE,
      );
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
      doError("Could not save the persistent store.");
      return;
    }
    renderCryptKeystoreList();
    statusUpdate(`Status: Saved ${type} in persistent store`);
    writeLogEntry(
      `[${threadName}] Crypt keystore entry added type=${type} label="${entry.label}"`,
    );
    requestKeystoreReviewNow();
  }

  async function loadSelectedCryptKeystoreEntry() {
    const activeEntries = cryptRenderedKeystoreEntries;
    const selectedIndex = cryptKeystoreSelectedIndex;
    if (!Number.isFinite(selectedIndex) || !activeEntries[selectedIndex]) {
      statusUpdate("Status: Select an artifact entry first");
      return;
    }

    const selectedEntry = activeEntries[selectedIndex];

    // File-type entries open in Conv via the injected callback instead
    // of loading text into the credential textarea.
    if (selectedEntry.type === "file" && selectedEntry.__fileArtifact) {
      const fileArtifact = selectedEntry.__fileArtifact;
      if (typeof openCarvedFileInConv === "function") {
        const candidate = {
          id: fileArtifact.id,
          protocol: fileArtifact.protocol,
          fileName: fileArtifact.fileName,
          bytes: fileArtifact.bytes instanceof Uint8Array
            ? fileArtifact.bytes
            : null,
          byteLength: fileArtifact.byteLength,
          label: selectedEntry.label,
          sourceDetail: selectedEntry.summary,
        };
        if (candidate.bytes) {
          openCarvedFileInConv(candidate);
          statusUpdate(`Status: Opened file "${selectedEntry.label}" in Conv`);
        } else {
          statusUpdate("Status: File bytes are unavailable (re-carve to restore)");
        }
      } else {
        statusUpdate("Status: File opening is unavailable in this environment");
      }
      renderCryptKeystoreDetails(selectedEntry);
      return;
    }

    let loadedContent = normalizeSessionSecretValue(selectedEntry.content);
    if (
      !loadedContent &&
      selectedEntry.encryptedContent &&
      selectedEntry.salt &&
      selectedEntry.iv
    ) {
      try {
        const keyMaterial =
          cryptKeystoreUnlockKeyMaterial ||
          (await importCryptKeyMaterial(CRYPT_KEYSTORE_FIXED_PASSPHRASE));
        cryptKeystoreUnlockKeyMaterial = keyMaterial;
        loadedContent = await decryptCryptContent(
          selectedEntry,
          keyMaterial,
        );
      } catch (error) {
        logErrorEntry("crypt-keystore-decrypt", error);
        doError("Could not decrypt artifact entry.");
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
    statusUpdate(`Status: Loaded artifact entry "${selectedEntry.label}"`);
  }

  async function deleteSelectedCryptKeystoreEntry() {
    if (cryptActiveKeystoreMode !== CRYPT_KEYSTORE_MODE_PERSISTENT) {
      statusUpdate("Status: Session artifacts are auto-managed");
      return;
    }
    const selectedIndex = cryptKeystoreSelectedIndex;
    if (
      !Number.isFinite(selectedIndex) ||
      !cryptRenderedKeystoreEntries[selectedIndex]
    ) {
      statusUpdate("Status: Select an artifact entry first");
      return;
    }
    const selectedEntry = cryptRenderedKeystoreEntries[selectedIndex];
    const persistentIndex = cryptPersistentKeystoreEntries.findIndex(
      (entry) => entry.id === selectedEntry.id,
    );
    if (persistentIndex < 0) {
      statusUpdate("Status: Select a keystore entry first");
      return;
    }
    if (!cryptKeystoreUnlockKeyMaterial) {
      cryptKeystoreUnlockKeyMaterial = await importCryptKeyMaterial(
        CRYPT_KEYSTORE_FIXED_PASSPHRASE,
      );
    }
    const [removedEntry] = cryptPersistentKeystoreEntries.splice(
      persistentIndex,
      1,
    );
    try {
      await savePersistentCryptKeystoreEntries(
        cryptPersistentKeystoreEntries,
        cryptKeystoreUnlockKeyMaterial,
      );
    } catch (error) {
      logErrorEntry("crypt-keystore-save", error);
      doError("Could not save the persistent store.");
      return;
    }
    renderCryptKeystoreList();
    statusUpdate(`Status: Deleted artifact entry "${removedEntry.label}"`);
    writeLogEntry(
      `[${threadName}] Crypt keystore entry deleted type=${removedEntry.type} label="${removedEntry.label}"`,
    );
  }

  async function sendSelectedSessionEntryToPersistent() {
    if (cryptActiveKeystoreMode !== CRYPT_KEYSTORE_MODE_SESSION) {
      statusUpdate(
        "Status: Switch to session artifacts to send temporary entries",
      );
      return;
    }
    if (!cryptKeystoreUnlockKeyMaterial) {
      cryptKeystoreUnlockKeyMaterial = await importCryptKeyMaterial(
        CRYPT_KEYSTORE_FIXED_PASSPHRASE,
      );
    }
    const selectedIndex = cryptKeystoreSelectedIndex;
    if (
      !Number.isFinite(selectedIndex) ||
      !cryptRenderedKeystoreEntries[selectedIndex]
    ) {
      statusUpdate("Status: Select a session artifact entry first");
      return;
    }

    const selectedEntry = cryptRenderedKeystoreEntries[selectedIndex];

    // File-type entries are session-only mirrors — they can't be sent to
    // the persistent store.
    if (selectedEntry.type === "file") {
      statusUpdate("Status: File artifacts are session-only and cannot be persisted");
      return;
    }

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
      statusUpdate("Status: Entry is already stored in persistent store");
      return;
    }

    cryptPersistentKeystoreEntries.unshift({
      id: generateCryptEntryId(),
      type: selectedEntry.type,
      label: selectedEntry.label,
      source: `bookmarked from ${selectedEntry.source || "session-auto"}`,
      content: normalizedContent,
      summary: selectedEntry.summary || "Bookmarked from session artifacts",
      createdAt: new Date().toISOString(),
    });
    try {
      await savePersistentCryptKeystoreEntries(
        cryptPersistentKeystoreEntries,
        cryptKeystoreUnlockKeyMaterial,
      );
    } catch (error) {
      logErrorEntry("crypt-keystore-save", error);
      doError("Could not save selected entry to persistent store.");
      return;
    }
    statusUpdate(
      `Status: Sent "${selectedEntry.label}" to persistent store`,
    );
    writeLogEntry(
      `[${threadName}] Session keychain entry persisted label="${selectedEntry.label}"`,
    );
    requestKeystoreReviewNow();
  }

  // Read-only access to the currently selected entry. Returns
  // ``{ label, type, source, content, summary, normalizedContent }`` or
  // ``null`` if nothing is selected. The Conv "Send to Hashes" handler
  // in main-frontend.js calls this and forwards ``content`` to the
  // Hash Reverse panel — keeping the keystore panel agnostic about
  // Conv subtab routing avoids a circular import (data-tools-panel
  // would otherwise need to know about keystore-panel just to switch
  // tabs).
  function getSelectedSessionEntryForHashes() {
    const selectedIndex = cryptKeystoreSelectedIndex;
    if (
      !Number.isFinite(selectedIndex) ||
      !cryptRenderedKeystoreEntries[selectedIndex]
    ) {
      return null;
    }
    const selectedEntry = cryptRenderedKeystoreEntries[selectedIndex];
    // For file-type entries, ``content`` is empty by design (bytes are in
    // ``__fileArtifact``).  Return the file bytes as a hex string so the
    // "Send to Hashes" handler can compute a hash from the file content.
    if (selectedEntry.type === "file" && selectedEntry.__fileArtifact) {
      const bytes = selectedEntry.__fileArtifact.bytes;
      let hexContent = "";
      if (bytes instanceof Uint8Array && bytes.length > 0) {
        hexContent = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
      }
      return {
        label: String(selectedEntry.label || ""),
        type: String(selectedEntry.type || ""),
        source: String(selectedEntry.source || ""),
        content: hexContent,
        normalizedContent: hexContent,
        summary: String(selectedEntry.summary || ""),
      };
    }
    return {
      label: String(selectedEntry.label || ""),
      type: String(selectedEntry.type || ""),
      source: String(selectedEntry.source || ""),
      content: String(selectedEntry.content || ""),
      normalizedContent: normalizeSessionSecretValue(selectedEntry.content),
      summary: String(selectedEntry.summary || ""),
    };
  }

  function grepSessionKeystoreEntriesByContent(content, entries) {
    const normalizedContent = content.trim().toLowerCase();
    const keystoreEntries = entries || cryptSessionKeystoreEntries;
    if (!normalizedContent) return keystoreEntries;
    return keystoreEntries.filter((entry) => {
      const entryContent = entry.content || "";
      return entryContent.toLowerCase().includes(normalizedContent);
    });
  }

  function grepSessionKeystoreEntriesByType(type, entries) {
    const normalizedType = type.trim().toLowerCase();
    const keystoreEntries = entries || cryptSessionKeystoreEntries;
    if (!normalizedType) return keystoreEntries;
    return keystoreEntries.filter((entry) => {
      const entryType = entry.type || "";
      return entryType.toLowerCase().includes(normalizedType);
    });
  }

  function grepSessionKeystoreEntriesByLabel(label, entries) {
    const normalizedLabel = label.trim().toLowerCase();
    const keystoreEntries = entries || cryptSessionKeystoreEntries;
    if (!normalizedLabel) return keystoreEntries;
    return keystoreEntries.filter((entry) => {
      const entryLabel = entry.label || "";
      return entryLabel.toLowerCase().includes(normalizedLabel);
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
        ? "persistent store"
        : "session artifacts";
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

  async function resetPersistentKeystoreEntries() {
    if (!(window.crypto && window.crypto.subtle)) {
      doError("WebCrypto API is unavailable; cannot reset persistent store.");
      return false;
    }
    try {
      const keyMaterial = await importCryptKeyMaterial(
        CRYPT_KEYSTORE_FIXED_PASSPHRASE,
      );
      await savePersistentCryptKeystoreEntries([], keyMaterial);
      cryptPersistentKeystoreEntries = [];
      cryptKeystoreUnlockKeyMaterial = keyMaterial;
      renderCryptKeystoreList();
      statusUpdate("Status: Persistent store wiped");
      writeLogEntry(`[${threadName}] Persistent keychain wiped`);
      return true;
    } catch (error) {
      logErrorEntry("crypt-keystore-reset", error);
      doError("Could not reset the persistent store.");
      return false;
    }
  }

  async function unlockPersistentKeystoreAndLoad() {
    if (!(window.crypto && window.crypto.subtle)) {
      doError("WebCrypto API is unavailable; cannot unlock store.");
      return false;
    }
    if (cryptKeystoreUnlockKeyMaterial) return true;
    try {
      const keyMaterial = await importCryptKeyMaterial(
        CRYPT_KEYSTORE_FIXED_PASSPHRASE,
      );
      const storedRecord = await loadCryptKeystore();
      if (!storedRecord) {
        cryptPersistentKeystoreEntries = [];
        await savePersistentCryptKeystoreEntries([], keyMaterial);
        statusUpdate("Status: Persistent store initialized");
        writeLogEntry(`[${threadName}] Persistent keychain initialized`);
      } else {
        try {
          cryptPersistentKeystoreEntries =
            await loadPersistentCryptKeystoreEntries(keyMaterial, storedRecord);
          statusUpdate("Status: Store unlocked");
          writeLogEntry(`[${threadName}] Persistent keychain unlocked`);
        } catch (loadError) {
          // The stored record was encrypted with an older user-chosen
          // password that the fixed passphrase cannot decrypt. Since the
          // keystore now runs password-free, wipe the stale record and
          // start fresh rather than locking the user out of the tab.
          logErrorEntry("crypt-keystore-legacy-decrypt", loadError);
          cryptPersistentKeystoreEntries = [];
          await savePersistentCryptKeystoreEntries([], keyMaterial);
          statusUpdate(
            "Status: Persistent store reinitialized (old entries could not be decrypted and were wiped)",
          );
          writeLogEntry(
            `[${threadName}] Persistent keychain reinitialized; undecryptable legacy entries wiped`,
          );
        }
      }
      cryptKeystoreUnlockKeyMaterial = keyMaterial;
      requestKeystoreReviewNow();
      return true;
    } catch (error) {
      logErrorEntry("crypt-keystore-unlock", error);
      doError("Could not unlock persistent store.");
      return false;
    }
  }

  function showKeystoreWorkspace() {
    setActiveMainTab(MAIN_TAB_KEYSTORE);
    if (getJsonCapture() === "") {
      statusUpdate("Status: No JSON file loaded, please upload a file first");
      doError("Please upload a JSON file before accessing the artifact store.");
      return;
    }

    statusUpdate("Status: Displaying artifact store");
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
      statusUpdate("Status: No text to add to artifact store");
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
      statusUpdate(`Status: Saved ${type} in session artifacts`);
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
      statusUpdate(`Status: Saved ${uriType} in session artifacts`);
      writeLogEntry(`[${threadName}] Manual context URI saved mode=session type=${uriType}`);
      return;
    }

    await addCryptKeystoreEntry(entry, { force: true });
  }

  async function openSelectedKeystoreLinkInBrowser() {
    const activeEntries = cryptRenderedKeystoreEntries;
    const selectedIndex = cryptKeystoreSelectedIndex;
    if (!Number.isFinite(selectedIndex) || !activeEntries[selectedIndex]) {
      statusUpdate("Status: Select an artifact entry first");
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

  panelApi = {
    addSessionKeystoreEntry,
    addCryptKeystoreEntry,
    loadSelectedCryptKeystoreEntry,
    deleteSelectedCryptKeystoreEntry,
    sendSelectedSessionEntryToPersistent,
    getSelectedSessionEntryForHashes,
    showKeystoreWorkspace,
    renderCryptKeystoreList,
    renderCryptKeystoreDetails,
    addToKeystoreFromContextMenu,
    addManualUriToKeystoreFromContextMenu,
    openSelectedKeystoreLinkInBrowser,
    unlockPersistentKeystoreAndLoad,
    resetPersistentKeystoreEntries,
    submitManualUriFromContextMenuDialog,
    resolveManualUriFromContextMenuDialog,
    importManualDataIntoSessionKeystore,
    getActiveCryptKeystoreEntries,
    getRenderedCryptKeystoreEntries,
    setActiveMode(mode) {
      cryptActiveKeystoreMode = mode;
      renderCryptKeystoreList();
    },
    setActiveCategory(category) {
      if (ARTIFACT_CATEGORIES.includes(category)) {
        cryptActiveCategory = category;
      }
      renderCryptKeystoreList();
    },
    getActiveCategory() {
      return cryptActiveCategory;
    },
    getCategories() {
      return ARTIFACT_CATEGORIES.slice();
    },
    getSessionKeychainEntries() {
      return cryptSessionKeystoreEntries;
    },
    getKeystoreMode() {
      return cryptActiveKeystoreMode;
    },
    isUnlocked() {
      // The persistent keychain no longer requires a user password; it
      // auto-unlocks with the fixed app-wide passphrase. This stays true
      // so callers that gate on "is the keychain ready" keep working.
      return true;
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
    restoreArtifactCategory(category) {
      if (ARTIFACT_CATEGORIES.includes(category)) {
        cryptActiveCategory = category;
      } else {
        cryptActiveCategory = ARTIFACT_CATEGORY_ALL;
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
      cryptActiveCategory = ARTIFACT_CATEGORY_ALL;
      cryptSessionKeystoreEntries = [];
      cryptPersistentKeystoreEntries = [];
      cryptKeystoreUnlockKeyMaterial = null;
      cryptManualUriDialogResolver = null;
      cryptManualUriDialogMode = CRYPT_KEYSTORE_MODE_SESSION;
      renderCryptKeystoreList();
      clearKeystoreSummary();
      stopKeystoreReviewTimer();
      clearFileArtifactStore();
    },
    clearSessionScanCaches,
    persistFileArtifact,
    getFileArtifactSnapshot,
    restoreFileArtifacts,
    clearFileArtifactStore,
    refreshFileArtifacts,
    rescanFileArtifactsForSecrets,
  };

  return panelApi;
}




module.exports = {
  id: "keystore",
  createKeystorePanel,
  CRYPT_KEYSTORE_MODE_SESSION,
  CRYPT_KEYSTORE_MODE_PERSISTENT,
  SESSION_KEYCHAIN_LABEL,
  ARTIFACT_CATEGORIES,
  ARTIFACT_CATEGORY_ALL,
  ARTIFACT_CATEGORY_SECRETS,
  ARTIFACT_CATEGORY_ITEMS,
  ARTIFACT_CATEGORY_FILES,
  ARTIFACT_CATEGORY_MISC,
  categoryForType,
};
