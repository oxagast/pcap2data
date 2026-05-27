import "../assets/css/style.css";
const { filterPackets, validateFilterSyntax } = require("../filter");
const { initializeLogging } = require("../logging");
const { initializeContextMenu } = require("./context-menu");
const {
  createTable,
  renderDnsTable,
  renderIcmpTable,
  renderSnmpTable,
  renderDhcpTable,
  renderNtpTable,
  renderSipTable,
  renderHttpTable,
  renderFtpTable,
  renderSmtpTable,
  renderPop3Table,
  renderImapTable,
  renderTelnetTable,
  renderIrcTable,
  renderMtpTable,
  renderLdapTable,
  renderMysqlTable,
  renderPostgresqlTable,
  renderXmppTable,
  renderSmbTable,
  renderMqttTable,
  renderRtspTable,
  renderTftpTable,
  renderBgpTable,
  renderHttp2Table,
  renderNntpTable,
  renderRadiusTable,
} = require("./decoders");
const { createCryptPanel } = require("./panels/crypt-panel");
const {
  createKeystorePanel,
  CRYPT_KEYSTORE_MODE_SESSION,
  CRYPT_KEYSTORE_MODE_PERSISTENT,
  SESSION_KEYCHAIN_LABEL,
} = require("./panels/keystore-panel");
const psVer = require("../../package.json").version;
const CryptoJS = require("crypto-js");
const { sha3_256, sha3_512 } = require("js-sha3");
const whirlpool = require("whirlpool-js");

// Cache frequently accessed DOM elements to avoid repeated lookups
const domCache = {};
function getCachedElement(id) {
  if (!domCache[id]) {
    domCache[id] = document.getElementById(id);
  }
  return domCache[id];
}

const SESSION_FILE_SCHEMA_VERSION = 1;
const SESSION_CAPTURE_KEY = "Capture Data";
const SESSION_STATE_KEY = "Session State";
const MAIN_TAB_SUMMARY = "summary";
const MAIN_TAB_DATA = "data";
const MAIN_TAB_STATS = "stats";
const MAIN_TAB_LIST = "list";
const MAIN_TAB_DATA_TOOLS = "data-tools";
const MAIN_TAB_CRYPT = "crypt";
const MAIN_TAB_KEYSTORE = "keystore";

// Global variables for DOM elements and state
let capturedPackets = {}; // Stores parsed packet data from JSON
let jsonCapture = ""; // Stringified JSON capture for pretty display
let currentIp;
let finalSummary = ""; // Stores the summary section from JSON
const status = getCachedElement("status"); // Status bar element
let hostsList = ["0.0.0.0"]; // List of hosts found in capture
const hostFilterEl = getCachedElement("host_filter"); // Host filter dropdown
let packetsForHost = []; // Packets for the currently selected host
let index = 0; // Navigation index for packets
let activePacketCursor = 0;
let bookmarkList = []; // List of bookmarks (host:packet index)
let activeBookmark = {}; // Current bookmark object
let isFileLoaded = false;
let jsonOfPackets;
let filteredPackets;
let currentPacketKey;
let startTime;
const filterInputEl = getCachedElement("filterStr");
const filterHighlightEl = getCachedElement("filterStr-highlight");
const filterClearButtonEl = getCachedElement("filterStr-clear");
const filterHistorySelectEl = getCachedElement("filter-history-select");
const filterHistory = [];
const DATA_TOOLS_TEXT_MIME_PRINTABLE_THRESHOLD = 0.9;
const DATA_TOOLS_ENTROPY_HIGH_THRESHOLD = 6.8;
const DATA_TOOLS_ENTROPY_MEDIUM_THRESHOLD = 4.5;
const DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES = 4096;
const DATA_TOOLS_CONTEXT_BASE64_MIN_LENGTH = 12;
const CONTEXT_IPV4_REGEX =
  /\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/;
const STRICT_IPV4_REGEX =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const CONTEXT_MAC_REGEX = /\b([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}\b/;
const CONTEXT_MIME_REGEX = /^[\w.+-]+\/[\w.+-]+$/;
const CONV_CONVERSIONS_SUBTAB = "conversions";
const CONV_HASHES_SUBTAB = "hashes";
const CONV_DECODES_SUBTAB = "decodes";
const CRYPT_SSL_SUBTAB = "ssl";
const CRYPT_PGP_SUBTAB = "pgp";
const CRYPT_OPENSSH_SUBTAB = "openssh";
const VALID_MAIN_TABS = [
  MAIN_TAB_SUMMARY,
  MAIN_TAB_DATA,
  MAIN_TAB_STATS,
  MAIN_TAB_LIST,
  MAIN_TAB_DATA_TOOLS,
  MAIN_TAB_CRYPT,
  MAIN_TAB_KEYSTORE,
];
const VALID_CONV_SUBTABS = [
  CONV_CONVERSIONS_SUBTAB,
  CONV_HASHES_SUBTAB,
  CONV_DECODES_SUBTAB,
];
const VALID_CRYPT_SUBTABS = [CRYPT_SSL_SUBTAB, CRYPT_PGP_SUBTAB, CRYPT_OPENSSH_SUBTAB];
let activeMainTab = MAIN_TAB_SUMMARY;
let activeConvSubtab = CONV_CONVERSIONS_SUBTAB;
let activeCryptSubtab = CRYPT_SSL_SUBTAB;
let keystorePanel;

// Check for first run after new version install and show install screen if needed
if (window.installapi) {
  window.installapi.checkFirstRun().then((installInfo) => {
    if (installInfo && installInfo.isFirstRun) {
      showInstallScreen(installInfo);
    }
  });
}

function showInstallScreen(installInfo) {
  const screen = document.getElementById("install-screen");
  if (!screen) return;

  document.getElementById("install-version").textContent =
    "Version " + installInfo.version;

  const fileList = document.getElementById("install-file-list");
  fileList.innerHTML = "";
  installInfo.installedFiles.forEach((file) => {
    const item = document.createElement("li");
    item.className = file.exists ? "install-file-ok" : "install-file-missing";
    item.textContent = (file.exists ? "\u2713 " : "\u2717 ") + file.name;
    if (!file.exists) {
      item.title = "Not found at: " + file.path;
    }
    fileList.appendChild(item);
  });

  const ollamaStatus = document.getElementById("install-ollama-status");
  if (!installInfo.ollamaInstalled) {
    ollamaStatus.textContent =
      "\u26a0 Ollama is not installed. LLM packet summarisation will be unavailable. Install Ollama from https://ollama.com to enable this feature.";
    ollamaStatus.className = "install-warning";
  } else {
    ollamaStatus.textContent =
      "\u2713 Ollama is installed. LLM summarisation is available.";
    ollamaStatus.className = "install-ok";
  }

  screen.style.display = "flex";
}

const installContinueBtn = document.getElementById("install-continue-btn");
if (installContinueBtn) {
  installContinueBtn.addEventListener("click", () => {
    if (window.installapi) {
      window.installapi.dismissFirstRun().then(() => {
        document.getElementById("install-screen").style.display = "none";
      });
    } else {
      document.getElementById("install-screen").style.display = "none";
    }
  });
}

const {
  initializeActivityLog,
  writeLogEntry,
  writeBackendErrorLogEntry,
  logErrorEntry,
} = initializeLogging({
  logapi: window.logapi,
  documentRef: document,
  consoleRef: console,
});

function getPacketTimeframe() {
  if (!capturedPackets || typeof capturedPackets !== "object") return null;
  const packetTimes = [];
  if (!capturedPackets["Host"]) return null;
  for (const host of Object.keys(capturedPackets["Host"])) {
    const hostPackets = capturedPackets["Host"][host];
    if (!Array.isArray(hostPackets)) continue;
    hostPackets.forEach((packet) => {
      const packetTime = packet?.["Packet Info"]?.["Packet Timestamp"];
      if (packetTime) {
        packetTimes.push(packetTime);
      }
    });
  }
  if (packetTimes.length === 0) return null;
  const parsedTimes = packetTimes
    .map((time) => ({
      raw: time,
      value: Date.parse(time),
    }))
    .filter((item) => !Number.isNaN(item.value))
    .sort((a, b) => a.value - b.value);
  if (parsedTimes.length < 1) return null;
  return {
    first: parsedTimes[0].raw,
    last: parsedTimes[parsedTimes.length - 1].raw,
  };
}

function logCurrentPacketDisplay(action) {
  if (!packetsForHost || !packetsForHost[index]) return;
  const packetInfo = packetsForHost[index]["Packet Info"];
  const selectedHost = getCachedElement("host_filter").value || "Unknown host";
  const sourceIp = packetInfo?.["IP"]?.["Source IP"] || "Unknown source";
  const destinationIp =
    packetInfo?.["IP"]?.["Destination IP"] || "Unknown destination";
  const packetIndex = packetInfo?.["Index"] ?? index;
  const packetTimestamp = packetInfo?.["Packet Timestamp"] || "Unknown time";
  writeLogEntry(
    `Displayed packet action=${action} host=${selectedHost} packet=${packetIndex} source=${sourceIp} destination=${destinationIp} timeframe=${packetTimestamp}`,
  );
}

void initializeActivityLog();

popHexGrid("00".repeat(256));
// Set up file upload handler for JSON capture
document
  .getElementById("json-upload")
  .addEventListener("change", function (event) {
    const file = event.target.files[0];
    if (file) {
      startTime = performance.now();
      statusUpdate("Processing file: " + file.name);
      writeLogEntry(
        `User selected JSON file name=${file.name} size_bytes=${file.size}`,
      );
      processFile(file);
      isFileLoaded = true;
      event.target.value = ""; // Reset so the same file can be loaded again
    }
  });

document
  .getElementById("pcap-filename")
  .addEventListener("click", function (event) {
    window.getfileapi
      .selectFile()
      .then((filePath) => {
        if (filePath) {
          writeLogEntry(`User selected PCAP file path=${filePath}`);
          window.fsize
            .getFSize()
            .then((fileSize) => {
              // Update the UI with the file size
              const fileSizeKb = (fileSize / 1024).toFixed(2);
              document.getElementById("pcap-size").textContent =
                `PCAP size: ${fileSizeKb}kb`;
              writeLogEntry(
                `Capture size recorded bytes=${fileSize} kilobytes=${fileSizeKb}`,
              );
            })
            .catch((error) => {
              // Handle any errors (e.g., file not found)
              console.error("Error fetching file size:", error);
              logErrorEntry("file-size-fetch", error);
            });

          runSnitch(filePath);
        }
      })
      .catch((error) => {
        doError("Error selecting PCAP file!");
        logErrorEntry("pcap-select", error);
      });
  });

function isValidJson(str) {
  try {
    JSON.parse(str);
    return true;
  } catch (e) {
    return false;
  }
}

// Chunked JSON parsing for large files to avoid blocking the UI
function parseJsonChunked(jsonString, chunkSize = 65536) {
  return new Promise((resolve, reject) => {
    try {
      // For smaller files, parse directly
      if (jsonString.length < chunkSize * 2) {
        resolve(JSON.parse(jsonString));
        return;
      }

      // For large files, use setTimeout to yield to the main thread
      let position = 0;
      const length = jsonString.length;
      let result = "";
      const stack = [];
      let inString = false;
      let escape = false;

      function processChunk() {
        const end = Math.min(position + chunkSize, length);

        for (; position < end; position++) {
          const char = jsonString[position];
          if (escape) {
            escape = false;
          } else if (char === "\\") {
            escape = true;
          } else if (char === '"') {
            inString = !inString;
          } else if (!inString) {
            if (char === "{" || char === "[") {
              stack.push(char);
            } else if (char === "}" || char === "]") {
              stack.pop();
            }
          }
          result += char;
        }

        if (position < length) {
          // Yield to main thread and continue
          setTimeout(processChunk, 0);
        } else {
          resolve(JSON.parse(result));
        }
      }

      setTimeout(processChunk, 0);
    } catch (e) {
      reject(e);
    }
  });
}

function fileLoaded(isLoaded) {
  isFileLoaded = isLoaded;
  if (isLoaded) {
    const loadEndTime = performance.now();
    document.getElementById("load-time").textContent =
      "Load time: " +
      ((loadEndTime - startTime) / 1000).toFixed(2) +
      " seconds";
    filterInputEl.disabled = false;
    filterHistorySelectEl.disabled = false;
    document.getElementById("summary-btn").style.opacity = "1";
    document.getElementById("data-btn").style.opacity = "1";
    document.getElementById("data-tools-btn").style.opacity = "1";
    document.getElementById("crypt-btn").style.opacity = "1";
    document.getElementById("keystore-btn").style.opacity = "1";
    document.getElementById("tab-btns").style.opacity = "1";
    document.getElementById("prev-btn").style.opacity = "1";
    document.getElementById("next-btn").style.opacity = "1";
    document.getElementById("log-btn").style.opacity = "1";
    document.getElementById("stats-btn").style.opacity = "1";
    document.getElementById("list-btn").style.opacity = "1";
    document.getElementById("json-lab").style.display = "none";
    document.getElementById("pcap-lab").style.display = "none";
    document.getElementById("llm-toggle").style.display = "none";
    writeLogEntry(
      `Initial file load completed seconds=${((loadEndTime - startTime) / 1000).toFixed(2)}`,
    );
  } else {
    filterInputEl.disabled = true;
    filterHistorySelectEl.disabled = true;
    document.getElementById("json-lab").style.display = "block";
    document.getElementById("pcap-lab").style.display = "block";
    document.getElementById("log-btn").style.opacity = "0";
    document.getElementById("stats-btn").style.opacity = "0";
    document.getElementById("list-btn").style.opacity = "0";
    document.getElementById("crypt-btn").style.opacity = "0";
    document.getElementById("keystore-btn").style.opacity = "0";
  }
  updateFilterClearButtonState();
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function decorateExpressionSegment(segmentText) {
  if (!segmentText) return "";

  const colonIndex = segmentText.indexOf(":");
  if (colonIndex === -1) {
    return `<span class="query-token-value">${escapeHtml(segmentText)}</span>`;
  }

  const keyText = segmentText.slice(0, colonIndex);
  const valueText = segmentText.slice(colonIndex + 1);
  const cmpMatch = valueText.match(/^(\s*)(>=|<=|==|!=|>|<)(\s*)(.*)$/);

  let valueHtml = "";
  if (cmpMatch) {
    valueHtml =
      escapeHtml(cmpMatch[1]) +
      `<span class="query-token-operator">${escapeHtml(cmpMatch[2])}</span>` +
      escapeHtml(cmpMatch[3]) +
      `<span class="query-token-value">${escapeHtml(cmpMatch[4])}</span>`;
  } else {
    valueHtml = `<span class="query-token-value">${escapeHtml(valueText)}</span>`;
  }

  return (
    `<span class="query-token-key">${escapeHtml(keyText)}</span>` +
    '<span class="query-token-colon">:</span>' +
    valueHtml
  );
}

function renderHighlightedQuery(query) {
  const source = query || "";
  if (!source) return "&nbsp;";

  // Query grammar tokens: logical OR/AND operators and grouping parentheses.
  const tokenRegex = /(\|\||&&|\(|\)|!(?!=))/g;
  let cursor = 0;
  let html = "";
  let tokenMatch = tokenRegex.exec(source);

  while (tokenMatch !== null) {
    const segmentText = source.slice(cursor, tokenMatch.index);
    html += decorateExpressionSegment(segmentText);

    const tokenText = tokenMatch[0];
    const tokenClass =
      tokenText === "(" || tokenText === ")" ? "paren" : "logic";
    html += `<span class="query-token-${tokenClass}">${escapeHtml(tokenText)}</span>`;
    cursor = tokenRegex.lastIndex;
    tokenMatch = tokenRegex.exec(source);
  }

  html += decorateExpressionSegment(source.slice(cursor));
  return html;
}

function syncFilterHighlight() {
  filterHighlightEl.innerHTML = renderHighlightedQuery(filterInputEl.value);
  syncFilterHighlightScroll();
  updateFilterClearButtonState();
}

function syncFilterHighlightScroll() {
  filterHighlightEl.scrollLeft = filterInputEl.scrollLeft;
}

function updateFilterClearButtonState() {
  filterClearButtonEl.disabled = !canClearFilterQuery();
}

function canClearFilterQuery() {
  return !filterInputEl.disabled && filterInputEl.value.trim() !== "";
}

function renderFilterHistory() {
  filterHistorySelectEl.replaceChildren();

  const placeholderOption = document.createElement("option");
  placeholderOption.value = "";
  placeholderOption.textContent = filterHistory.length
    ? "Previous queries"
    : "No previous queries";
  placeholderOption.selected = true;
  filterHistorySelectEl.appendChild(placeholderOption);

  filterHistory.forEach((query) => {
    const queryOption = document.createElement("option");
    queryOption.value = query;
    queryOption.textContent = query;
    queryOption.title = query;
    filterHistorySelectEl.appendChild(queryOption);
  });
  filterHistorySelectEl.value = "";
  filterHistorySelectEl.disabled = !isFileLoaded;
}

function addFilterHistory(query) {
  const normalizedQuery = query.trim();
  if (!normalizedQuery) return;
  const existingIndex = filterHistory.indexOf(normalizedQuery);
  if (existingIndex !== -1) {
    filterHistory.splice(existingIndex, 1);
  }
  filterHistory.unshift(normalizedQuery);
  renderFilterHistory();
}

function runFilterQuery(filterQuery, options = {}) {
  const { trackHistory = true } = options;
  try {
    validateFilterSyntax(filterQuery);
  } catch (error) {
    logErrorEntry("filter-syntax", error);
    writeLogEntry(`User query rejected query="${filterQuery}"`);
    doError(`Invalid filter syntax: ${error.message}`);
    statusUpdate("Status: Invalid filter syntax");
    return;
  }

  if (trackHistory) {
    addFilterHistory(filterQuery);
  }
  filteredPackets = filterPackets(capturedPackets, filterQuery);
  writeLogEntry(`User executed query="${filterQuery}"`);

  if (filteredPackets === undefined || filteredPackets.length === 0) {
    hideAllData();
    statusUpdate("Status: No packets match the filter criteria");
    writeLogEntry("User query returned 0 packets");
  } else {
    statusUpdate(
      "Status: Displaying " +
        filteredPackets.length +
        " packets matching filter",
    );
    writeLogEntry(`User query returned packets=${filteredPackets.length}`);
    handlePacketNavigation("filtered", null);
  }
}

function clearFilterQuery() {
  if (!canClearFilterQuery()) {
    return;
  }
  filterInputEl.value = "";
  syncFilterHighlight();
  filterHistorySelectEl.value = "";
  filterInputEl.focus();
  runFilterQuery("");
}

function deepCloneSessionData(value, fallback) {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return fallback;
  }
}

function normalizeLoadedSessionPayload(parsedPayload) {
  if (!parsedPayload || typeof parsedPayload !== "object") {
    return null;
  }

  const hasWrappedCapture =
    parsedPayload[SESSION_CAPTURE_KEY] &&
    typeof parsedPayload[SESSION_CAPTURE_KEY] === "object";
  const captureData = hasWrappedCapture
    ? parsedPayload[SESSION_CAPTURE_KEY]
    : parsedPayload;
  const sessionState =
    hasWrappedCapture && parsedPayload[SESSION_STATE_KEY]
      ? parsedPayload[SESSION_STATE_KEY]
      : null;

  if (
    !captureData ||
    typeof captureData !== "object" ||
    !captureData["Host"] ||
    typeof captureData["Host"] !== "object"
  ) {
    return null;
  }

  return {
    captureData,
    sessionState:
      sessionState && typeof sessionState === "object" ? sessionState : null,
  };
}

function rebuildBookmarkDropdown() {
  const selectBookmarkEl = document.getElementById("selectBookmark");
  while (selectBookmarkEl.options.length > 1) {
    selectBookmarkEl.remove(1);
  }
  bookmarkList.forEach((bookmarkKey) => {
    selectBookmarkEl.appendChild(new Option(bookmarkKey, bookmarkKey));
  });
}

function getSessionPacketViewMode() {
  if (
    Array.isArray(filteredPackets) &&
    filteredPackets.length > 0 &&
    packetsForHost === filteredPackets
  ) {
    return "filtered";
  }
  return "host";
}

function buildSessionStateSnapshot() {
  const listSearchEl = document.getElementById("list-search");
  const listGroupStreamsEl = document.getElementById("list-group-streams");
  return {
    schemaVersion: SESSION_FILE_SCHEMA_VERSION,
    savedAt: new Date().toISOString(),
    currentFilterQuery: filterInputEl.value || "",
    filterHistory: [...filterHistory],
    currentPacketKey: currentPacketKey || null,
    activePacketCursor: getActivePacketCursor(),
    packetViewMode: getSessionPacketViewMode(),
    selectedHost:
      document.getElementById("target_hosts")?.value || hostFilterEl.value || "",
    bookmarkList: [...bookmarkList],
    sessionKeychainEntries: deepCloneSessionData(
      keystorePanel.getSessionKeychainEntries(),
      [],
    ),
    keystoreMode: keystorePanel.getKeystoreMode(),
    tabs: {
      main: activeMainTab,
      conv: activeConvSubtab,
      crypt: activeCryptSubtab,
      listSearch: listSearchEl ? listSearchEl.value : "",
      listGroupStreams: listGroupStreamsEl ? Boolean(listGroupStreamsEl.checked) : false,
    },
  };
}

function buildSessionFilePayload() {
  return JSON.stringify(
    {
      [SESSION_CAPTURE_KEY]: capturedPackets,
      [SESSION_STATE_KEY]: buildSessionStateSnapshot(),
    },
    null,
    2,
  );
}

async function persistSessionToDisk(sourceLabel = "manual-save") {
  if (
    !capturedPackets ||
    !capturedPackets["Host"] ||
    typeof capturedPackets["Host"] !== "object"
  ) {
    statusUpdate("Status: No data loaded to save");
    return { success: false, error: "No loaded capture" };
  }
  const sessionJsonData = buildSessionFilePayload();
  const result = await window.saveapi.saveJson(sessionJsonData);
  if (result.canceled) {
    statusUpdate("Status: Save cancelled");
  } else if (result.success) {
    statusUpdate("Status: Session saved successfully");
    writeLogEntry(`Session saved source=${sourceLabel}`);
  } else {
    const errorMessage =
      result && typeof result === "object" && "error" in result
        ? result.error
        : "unknown";
    doError("Save failed");
    logErrorEntry("save-session", errorMessage || "unknown");
    statusUpdate("Status: Save failed – " + (errorMessage || "unknown error"));
    console.error("Save failed:", errorMessage);
  }
  return result;
}

async function maybePromptSaveSessionOnExit() {
  if (!isFileLoaded || !capturedPackets || !capturedPackets["Host"]) {
    return "discard";
  }
  const dialogEl = document.getElementById("save-session-dialog");
  if (!dialogEl) {
    return window.confirm("Save session before exit?") ? "save" : "cancel";
  }
  dialogEl.hidden = false;
  return new Promise((resolve) => {
    function cleanup(result) {
      dialogEl.hidden = true;
      document
        .getElementById("save-session-save-btn")
        .removeEventListener("click", onSave);
      document
        .getElementById("save-session-discard-btn")
        .removeEventListener("click", onDiscard);
      document
        .getElementById("save-session-cancel-btn")
        .removeEventListener("click", onCancel);
      resolve(result);
    }
    function onSave() { cleanup("save"); }
    function onDiscard() { cleanup("discard"); }
    function onCancel() { cleanup("cancel"); }
    document.getElementById("save-session-save-btn").addEventListener("click", onSave);
    document.getElementById("save-session-discard-btn").addEventListener("click", onDiscard);
    document.getElementById("save-session-cancel-btn").addEventListener("click", onCancel);
  });
}

async function requestApplicationClose() {
  const exitAction = await maybePromptSaveSessionOnExit();
  if (exitAction === "cancel") {
    statusUpdate("Status: Exit cancelled");
    return;
  }
  if (exitAction === "save") {
    const saveResult = await persistSessionToDisk("exit-prompt");
    if (!saveResult?.success) {
      if (saveResult?.canceled) {
        statusUpdate("Status: Exit cancelled");
      } else {
        statusUpdate("Status: Exit cancelled due to save failure");
      }
      return;
    }
  }
  window.quitapi.quitApp();
}

function restoreSessionState(sessionState) {
  if (!sessionState || typeof sessionState !== "object") return;

  const loadedHistory = Array.isArray(sessionState.filterHistory)
    ? sessionState.filterHistory
        .filter((query) => typeof query === "string")
        .map((query) => query.trim())
        .filter(Boolean)
    : [];
  filterHistory.splice(0, filterHistory.length, ...loadedHistory);
  renderFilterHistory();

  const loadedBookmarks = Array.isArray(sessionState.bookmarkList)
    ? sessionState.bookmarkList.filter(
        (bookmark) => typeof bookmark === "string" && bookmark.trim() !== "",
      )
    : [];
  bookmarkList = loadedBookmarks;
  rebuildBookmarkDropdown();

  const loadedSessionEntries = Array.isArray(sessionState.sessionKeychainEntries)
    ? sessionState.sessionKeychainEntries.filter(
        (entry) => entry && typeof entry === "object",
      )
    : [];
  keystorePanel.restoreSessionState(
    deepCloneSessionData(loadedSessionEntries, []),
    sessionState.keystoreMode,
  );

  const selectedHost = String(sessionState.selectedHost || "").trim();
  if (selectedHost && capturedPackets?.["Host"]?.[selectedHost]) {
    const targetHostsEl = document.getElementById("target_hosts");
    if (targetHostsEl) {
      targetHostsEl.value = selectedHost;
    }
    hostFilterEl.value = selectedHost;
  }

  const restoredFilterQuery =
    typeof sessionState.currentFilterQuery === "string"
      ? sessionState.currentFilterQuery
      : "";
  filterInputEl.value = restoredFilterQuery;
  syncFilterHighlight();
  if (restoredFilterQuery.trim()) {
    runFilterQuery(restoredFilterQuery, { trackHistory: false });
  } else {
    filteredPackets = [];
    document.getElementById("filter-returned").textContent = "Filtered Packets: 0";
  }

  currentPacketKey =
    typeof sessionState.currentPacketKey === "string"
      ? sessionState.currentPacketKey
      : null;
  setActivePacketCursor(sessionState.activePacketCursor);

  const navAction =
    sessionState.packetViewMode === "filtered" &&
    Array.isArray(filteredPackets) &&
    filteredPackets.length > 0
      ? "filtered"
      : "first-load";
  handlePacketNavigation(navAction);

  const tabState = sessionState.tabs && typeof sessionState.tabs === "object"
    ? sessionState.tabs
    : {};
  const savedMainTab =
    typeof tabState.main === "string" && VALID_MAIN_TABS.includes(tabState.main)
      ? tabState.main
      : MAIN_TAB_DATA;
  const savedConvTab = VALID_CONV_SUBTABS.includes(tabState.conv)
    ? tabState.conv
    : CONV_CONVERSIONS_SUBTAB;
  const savedCryptTab = VALID_CRYPT_SUBTABS.includes(tabState.crypt)
    ? tabState.crypt
    : CRYPT_SSL_SUBTAB;

  if (savedMainTab === MAIN_TAB_SUMMARY) {
    writeSummary();
  } else if (savedMainTab === MAIN_TAB_STATS) {
    showStats();
  } else if (savedMainTab === MAIN_TAB_LIST) {
    showPacketList();
    const listSearchEl = document.getElementById("list-search");
    const listGroupStreamsEl = document.getElementById("list-group-streams");
    if (listSearchEl && typeof tabState.listSearch === "string") {
      listSearchEl.value = tabState.listSearch;
      listSearchEl.dispatchEvent(new Event("input"));
    }
    if (listGroupStreamsEl && typeof tabState.listGroupStreams === "boolean") {
      listGroupStreamsEl.checked = tabState.listGroupStreams;
      listGroupStreamsEl.dispatchEvent(new Event("change"));
    }
  } else if (savedMainTab === MAIN_TAB_DATA_TOOLS) {
    showDataTools(savedConvTab);
  } else if (savedMainTab === MAIN_TAB_CRYPT) {
    showCryptWorkspace(savedCryptTab);
  } else if (savedMainTab === MAIN_TAB_KEYSTORE && keystorePanel.isUnlocked()) {
    keystorePanel.showKeystoreWorkspace();
  } else {
    initializeDataView();
  }

  if (savedMainTab !== MAIN_TAB_DATA_TOOLS) {
    setConvSubtab(savedConvTab);
  }
  if (savedMainTab !== MAIN_TAB_CRYPT) {
    setCryptSubtab(savedCryptTab);
  }

  writeLogEntry("Session state restored from JSON");
  statusUpdate("Status: Session restored");
}

/**
 * Reads and parses the JSON file, updates UI and state.
 * Uses chunked parsing for large files to avoid UI blocking.
 */
function processFile(file) {
  let loadedSessionState = null;
  const reader = new FileReader();
  reader.onload = (event) => {
    const mainPanel = getCachedElement("main");
    if (isValidJson(event.target.result) == false) {
      console.log("Invalid JSON file");
      doError("Invalid JSON file, please upload a valid JSON capture!");
      fileLoaded(false);
      return;
    }
    fileLoaded(true);
    jsonOfPackets = event.target.result;
    getCachedElement("error-container").style.display = "none";

    // Use chunked parsing for large files (>1MB)
    const fileSize = event.target.result.length;
    if (fileSize > 1024 * 1024) {
      statusUpdate(
        "Status: Parsing large file (" +
          (fileSize / 1024 / 1024).toFixed(2) +
          "MB)...",
      );
      parseJsonChunked(event.target.result)
        .then((parsed) => {
          const normalizedPayload = normalizeLoadedSessionPayload(parsed);
          if (!normalizedPayload) {
            doError("Invalid JSON file, please upload a valid capture/session file!");
            fileLoaded(false);
            return;
          }
          capturedPackets = normalizedPayload.captureData;
          loadedSessionState = normalizedPayload.sessionState;
          jsonCapture = JSON.stringify(capturedPackets, null, 2);
          finalSummary = capturedPackets["Final Summary"] ?? "";
          finishProcessingFile();
        })
        .catch((e) => {
          console.error("JSON parse error:", e);
          logErrorEntry("json-parse", e);
          doError("Error parsing JSON file!");
        });
    } else {
      const normalizedPayload = normalizeLoadedSessionPayload(
        JSON.parse(event.target.result),
      );
      if (!normalizedPayload) {
        doError("Invalid JSON file, please upload a valid capture/session file!");
        fileLoaded(false);
        return;
      }
      capturedPackets = normalizedPayload.captureData;
      loadedSessionState = normalizedPayload.sessionState;
      jsonCapture = JSON.stringify(capturedPackets, null, 2);
      finalSummary = capturedPackets["Final Summary"] ?? "";
      finishProcessingFile();
    }
  };

  function finishProcessingFile() {
    getCachedElement("target_hosts").hidden = false;
    getCachedElement("summary-btn").style.display = "block";
    // Reset host list and dropdowns for the new file
    hostsList = ["0.0.0.0"];
    const targetHostsDropdown = getCachedElement("target_hosts");
    while (targetHostsDropdown.options.length > 0) {
      targetHostsDropdown.remove(0);
    }
    bookmarkList = [];
    const selectBookmarkEl = document.getElementById("selectBookmark");
    while (selectBookmarkEl.options.length > 1) {
      selectBookmarkEl.remove(1);
    }
    // Populate host dropdown with hosts from JSON
    for (const host in capturedPackets["Host"]) {
      hostsList.push(host);
      const newhost = document.createElement("option");
      newhost.textContent = host;
      newhost.value = host;
      targetHostsDropdown.appendChild(newhost);
      isFileLoaded = true;
    }
    writeLogEntry(`Hosts targeted discovered count=${hostsList.length - 1}`);
    const keystoreEntryCount = keystorePanel.rebuildSessionEntries();
    writeLogEntry(
      `Session keychain auto-populated entries=${keystoreEntryCount}`,
    );
    const timeframe = getPacketTimeframe();
    if (timeframe) {
      writeLogEntry(
        `Packet timeframe start="${timeframe.first}" end="${timeframe.last}"`,
      );
    }
    writeLogEntry(`Total packet count=${totalPacketCount()}`);
    writeSummary();
    initializeDataView();
    if (loadedSessionState) {
      restoreSessionState(loadedSessionState);
    }
  }
  reader.onerror = (error) => {
    status.textContent = "Status: Error reading file: " + error;
    logErrorEntry("file-read", error);
    doError("Error reading file!");
  };
  reader.readAsText(file);
}

/**
 * Updates the status bar with a message, then resets after 6 seconds.
 */
function statusUpdate(message) {
  status.textContent = message;
  setTimeout(() => {
    status.textContent = "PacketSnitch " + psVer + ": Ready";
  }, 6000);
}

/**
 * Loads all capturedPackets for a given host IP into packetsForHost.
 */
function hostPacketInfo(currentIp) {
  const selected = currentIp;
  packetsForHost = [];
  const hostPackets = capturedPackets["Host"][selected];
  for (const packet in hostPackets) {
    packetsForHost.push(hostPackets[packet]);
  }
}

// Use event delegation for dynamically created elements
// and cache static elements at module load
const navButtons = {
  prev: getCachedElement("prev-btn"),
  next: getCachedElement("next-btn"),
  summary: getCachedElement("summary-btn"),
  data: getCachedElement("data-btn"),
  setBookmark: getCachedElement("setBookmark"),
};

// Update host filter when a new host is selected from dropdown
getCachedElement("target_hosts").addEventListener("change", function () {
  const selected = getCachedElement("target_hosts").value;
  let hostFilterEl = getCachedElement("host_filter");
  filteredPackets = []; // reset filter when host changes
  writeLogEntry(`Host target changed host=${selected}`);
  if (hostFilterEl.value !== selected) {
    hostFilterEl.value = selected;
  }
});

getCachedElement("target_hosts").addEventListener("click", function () {
  const selected = getCachedElement("target_hosts").value;
  filteredPackets = filterPackets(
    capturedPackets,
    "ip.src.addr: " + selected + "|| ip.dst.addr: " + selected,
  );
  writeLogEntry(
    `Host target clicked host=${selected} packets_returned=${filteredPackets.length}`,
  );
  handlePacketNavigation("filtered", null);
});

// Show summary when summary button is clicked
getCachedElement("summary-btn").addEventListener("click", function () {
  writeSummary();
});

// Displays the summary section from the loaded JSON.

function writeSummary() {
  activeMainTab = MAIN_TAB_SUMMARY;
  statusUpdate("Status: Displaying capture analysis summary");
  //highlightTab("summary-navAction");
  if (jsonCapture == "") {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
  } else {
    document.getElementById("packetInfoPane").style.display = "none";
    document.getElementById("packetPayloadPane").style.display = "none";
    document.getElementById("stats_box").style.display = "none";
    document.getElementById("data_tools_box").style.display = "none";
    document.getElementById("crypt_box").style.display = "none";
    document.getElementById("keystore_box").style.display = "none";
    document.getElementById("list_box").style.display = "none";
    document.getElementById("summary_content").textContent =
      finalSummary || "No LLM summary available.";
    document.getElementById("summary_box").style.display = "block";
    fileLoaded(true);
  }
}

function normalizeStatsTextValue(value, options = {}) {
  if (value === null || value === undefined) return null;

  const { stripNonPrintable = false } = options;
  let normalized = typeof value === "string" ? value : String(value);

  if (stripNonPrintable) {
    normalized = normalized.replace(/[\x00-\x1F\x7F]/g, "");
  }

  normalized = normalized.trim();
  return normalized ? normalized : null;
}

function normalizeStatsPortValue(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  const normalizedText = normalizeStatsTextValue(value);
  if (!normalizedText || !/^\d+$/.test(normalizedText)) return null;
  return Number(normalizedText);
}

/**
 * Iterates all packets in capturedPackets and returns aggregate statistics
 * useful for understanding what is in the capture at a glance.
 */
function buildCaptureStats() {
  const protocols = new Set();
  const transportProtocols = new Set();
  const hosts = new Set();
  const ports = new Set();
  const macVendors = new Set();
  const mimeTypes = new Set();
  const locations = new Map(); // "City, Country" -> count
  const hostnames = new Set();
  const dataTypes = new Set();
  let encryptedCount = 0;
  let unencryptedCount = 0;
  let totalPackets = 0;

  if (!capturedPackets || !capturedPackets["Host"]) return null;

  for (const host of Object.keys(capturedPackets["Host"])) {
    const normalizedHostKey = normalizeStatsTextValue(host);
    if (normalizedHostKey) hosts.add(normalizedHostKey);
    const packets = capturedPackets["Host"][host];
    if (!Array.isArray(packets)) continue;

    for (const pkt of packets) {
      totalPackets++;
      const pi = pkt?.["Packet Info"];
      const ei = pkt?.["Extra Info"];
      if (!pi || !ei) continue;

      // Transport protocol (TCP/UDP/ICMP)
      const tp = normalizeStatsTextValue(pi["Protocol"]);
      if (tp) transportProtocols.add(tp);

      // Source/destination IPs
      const srcIp = normalizeStatsTextValue(pi?.["IP"]?.["Source IP"]);
      const dstIp = normalizeStatsTextValue(pi?.["IP"]?.["Destination IP"]);
      if (srcIp) hosts.add(srcIp);
      if (dstIp) hosts.add(dstIp);

      // MAC vendors
      const ef = pi?.["Ethernet Frame"];
      if (ef) {
        const srcVendor = normalizeStatsTextValue(ef["MAC Source Vendor"]);
        const dstVendor = normalizeStatsTextValue(ef["MAC Destination Vendor"]);
        if (srcVendor) macVendors.add(srcVendor);
        if (dstVendor) macVendors.add(dstVendor);
      }

      // Port-level protocol name and ports
      const netData = ei?.["Traits"]?.["Network Data"];
      if (netData) {
        const protoName = normalizeStatsTextValue(netData["Port Protcol"]);
        if (protoName && protoName !== "Unknown") protocols.add(protoName);

        // Source/dest ports
        const tpData = tp ? pi[tp] : null;
        if (tpData) {
          const srcPort = normalizeStatsPortValue(tpData["Source port"]);
          const dstPort = normalizeStatsPortValue(tpData["Destination port"]);
          if (srcPort !== null) ports.add(srcPort);
          if (dstPort !== null) ports.add(dstPort);
        }

        // Hostnames
        const hn = netData?.["Hostnames"]?.["Hostnames"];
        if (Array.isArray(hn)) {
          hn.forEach((h) => {
            const normalizedHostname = normalizeStatsTextValue(h);
            if (normalizedHostname) hostnames.add(normalizedHostname);
          });
        }

        // Locations
        for (const side of ["Source IP", "Destination IP"]) {
          const loc = netData?.[side]?.["Location"];
          const city = normalizeStatsTextValue(loc?.["City"]);
          const country = normalizeStatsTextValue(loc?.["Country"]);
          if (city && country) {
            const key = `${city}, ${country}`;
            locations.set(key, (locations.get(key) || 0) + 1);
          }
        }
      }

      // MIME types
      const mimeType = normalizeStatsTextValue(ei?.["MIME Type"]);
      if (mimeType) mimeTypes.add(mimeType);

      // Data types
      const dt = ei?.["Data Types"];
      if (Array.isArray(dt)) {
        dt.forEach((d) => {
          const normalizedDataType = normalizeStatsTextValue(d, {
            stripNonPrintable: true,
          });
          if (normalizedDataType) dataTypes.add(normalizedDataType);
        });
      }

      // Encryption
      const encData = ei?.["Traits"]?.["Server Info"]?.["Encryption Data"];
      if (!encData || encData === "N/A") {
        unencryptedCount++;
      } else {
        encryptedCount++;
      }
    }
  }

  return {
    protocols: [...protocols].sort(),
    transportProtocols: [...transportProtocols].sort(),
    hosts: [...hosts].sort(),
    ports: [...ports].sort((a, b) => a - b),
    macVendors: [...macVendors].filter((v) => v !== "N/A").sort(),
    mimeTypes: [...mimeTypes].sort(),
    locations: [...locations.entries()].sort((a, b) => b[1] - a[1]),
    hostnames: [...hostnames].sort(),
    dataTypes: [...dataTypes].sort(),
    encryptedCount,
    unencryptedCount,
    totalPackets,
  };
}

/**
 * Renders a section of tags that, when clicked, populate the filter bar
 * with a suggested query for that value.
 */
function makeStatsSection(title, items, queryBuilder) {
  if (!items || items.length === 0) return null;
  const normalizedItems = Array.from(
    new Set(
      items.filter((item) => {
        if (item === null || item === undefined) return false;
        if (typeof item !== "string") return true;
        return normalizeStatsTextValue(item) !== null;
      }),
    ),
  );
  if (normalizedItems.length === 0) return null;

  const section = document.createElement("div");
  section.className = "stats-section";

  const heading = document.createElement("div");
  heading.className = "stats-section-title";
  heading.textContent = title;
  section.appendChild(heading);

  const tagList = document.createElement("div");
  tagList.className = "stats-tag-list";

  normalizedItems.forEach((item) => {
    const tag = document.createElement("span");
    tag.className = "stats-tag";
    tag.textContent = item;
    tag.title = "Click to filter packets by this value";
    if (queryBuilder) {
      tag.addEventListener("click", () => {
        const query = queryBuilder(item);
        if (query) {
          filterInputEl.value = query;
          syncFilterHighlight();
          writeLogEntry(`Stats tag clicked query="${query}"`);
          runFilterQuery(query);
          // Keep packetsForHost in sync so prev/next navigation works within the result
          if (filteredPackets && filteredPackets.length > 0) {
            packetsForHost = filteredPackets;
          }
        }
      });
    }
    tagList.appendChild(tag);
  });

  section.appendChild(tagList);
  return section;
}

/**
 * Shows the capture stats panel with aggregated data from the loaded capture.
 */
function showStats() {
  activeMainTab = MAIN_TAB_STATS;
  if (jsonCapture === "") {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
    return;
  }
  statusUpdate("Status: Displaying capture statistics");
  writeLogEntry("User opened capture stats view");

  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("list_box").style.display = "none";
  document.getElementById("data_tools_box").style.display = "none";
  document.getElementById("crypt_box").style.display = "none";
  document.getElementById("keystore_box").style.display = "none";
  document.getElementById("stats_box").style.display = "block";
  document.getElementById("rightside").style.display = "none";

  const content = document.getElementById("stats_content");
  content.replaceChildren();

  const stats = buildCaptureStats();
  if (!stats) {
    content.textContent = "No packet data available.";
    return;
  }

  // Overview row
  const overview = document.createElement("div");
  overview.className = "stats-section";
  const ovHead = document.createElement("div");
  ovHead.className = "stats-section-title";
  ovHead.textContent = "Capture Overview";
  overview.appendChild(ovHead);
  [
    `Total Packets: ${stats.totalPackets}`,
    `Unique Hosts Targeted: ${stats.hosts.length}`,
    `Encrypted Packets: ${stats.encryptedCount}`,
    `Unencrypted Packets: ${stats.unencryptedCount}`,
    `Unique Protocols: ${stats.protocols.length}`,
    `Unique Locations: ${stats.locations.length}`,
  ].forEach((line) => {
    const kv = document.createElement("div");
    kv.className = "stats-kv";
    kv.textContent = line;
    overview.appendChild(kv);
  });
  content.appendChild(overview);

  // Application protocols
  const protoSec = makeStatsSection(
    "Application Protocols",
    stats.protocols,
    (v) => `tcp.proto: ${v.toLowerCase()}`,
  );
  if (protoSec) content.appendChild(protoSec);

  // Transport protocols
  const tpSec = makeStatsSection(
    "Transport Protocols",
    stats.transportProtocols,
    (v) => `wire.proto: ${v.toLowerCase()}`,
  );
  if (tpSec) content.appendChild(tpSec);

  // All hosts
  const hostSec = makeStatsSection(
    "All Hosts Addressed",
    stats.hosts,
    (v) => `ip.src.addr: ${v} || ip.dst.addr: ${v}`,
  );
  if (hostSec) content.appendChild(hostSec);

  // Hostnames / DNS
  const hnSec = makeStatsSection(
    "Hostnames (DNS)",
    stats.hostnames,
    (v) => `dns.qname: ${v}`,
  );
  if (hnSec) content.appendChild(hnSec);

  // Physical locations
  if (stats.locations.length > 0) {
    const locItems = stats.locations.map(
      ([place, count]) => `${place} (${count})`,
    );
    const locSec = makeStatsSection("Physical Locations", locItems, null);
    if (locSec) content.appendChild(locSec);
  }

  // Ports
  const portSec = makeStatsSection(
    "Ports Seen",
    stats.ports.map(String),
    (v) => `tcp.src.port: ${v} || tcp.dst.port: ${v}`,
  );
  if (portSec) content.appendChild(portSec);

  // MAC vendors
  const macSec = makeStatsSection(
    "MAC Vendors",
    stats.macVendors,
    (v) => `eth.src.vendor: ${v}`,
  );
  if (macSec) content.appendChild(macSec);

  // MIME types
  const mimeSec = makeStatsSection(
    "MIME Types",
    stats.mimeTypes,
    (v) => `mime.type: ${v}`,
  );
  if (mimeSec) content.appendChild(mimeSec);

  // Data types
  const dtSec = makeStatsSection("Data Types", stats.dataTypes, null);
  if (dtSec) content.appendChild(dtSec);
}

function parseDataToolsInput(format, rawInput) {
  if (!rawInput || rawInput.trim() === "") {
    throw new Error("Enter input data first.");
  }

  if (format === "hex") {
    const normalized = rawInput
      .replace(/0x/gi, "")
      .replace(/[\s,:;-]+/g, "")
      .trim();
    if (!normalized) throw new Error("No hex bytes were found.");
    if (!/^[0-9a-fA-F]+$/.test(normalized)) {
      throw new Error("Hex input can only contain 0-9 and A-F.");
    }
    if (normalized.length % 2 !== 0) {
      throw new Error("Hex input must contain an even number of characters.");
    }
    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < normalized.length; i += 2) {
      bytes[i / 2] = parseInt(normalized.slice(i, i + 2), 16);
    }
    return bytes;
  }

  if (format === "binary") {
    const normalized = rawInput.replace(/\s+/g, "");
    if (!normalized) throw new Error("No binary bits were found.");
    if (!/^[01]+$/.test(normalized)) {
      throw new Error("Binary input can only contain 0 and 1.");
    }
    if (normalized.length % 8 !== 0) {
      throw new Error("Binary input must be grouped into full 8-bit bytes.");
    }
    const bytes = new Uint8Array(normalized.length / 8);
    for (let i = 0; i < normalized.length; i += 8) {
      bytes[i / 8] = parseInt(normalized.slice(i, i + 8), 2);
    }
    return bytes;
  }

  if (format === "base64") {
    const normalized = rawInput
      .trim()
      .replace(/^data:[^;]+;base64,/i, "")
      .replace(/\s+/g, "");
    if (!normalized) throw new Error("No base64 content was found.");
    let decoded = "";
    try {
      decoded = atob(normalized);
    } catch {
      throw new Error("Invalid base64 input.");
    }
    const bytes = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i++) {
      bytes[i] = decoded.charCodeAt(i);
    }
    return bytes;
  }

  if (format === "decimal") {
    const tokens = rawInput.split(/[\s,]+/).filter(Boolean);
    if (!tokens.length) throw new Error("No decimal byte values were found.");
    const values = tokens.map((token) => {
      const parsed = Number(token);
      if (!/^\d+$/.test(token) || parsed > 255) {
        throw new Error(
          "Each decimal value must be a non-negative integer between 0 and 255.",
        );
      }
      return parsed;
    });
    return Uint8Array.from(values);
  }

  // ascii / utf-8 fallback
  return new TextEncoder().encode(rawInput);
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function bytesToPrintableAscii(bytes) {
  return [...bytes]
    .map((byte) =>
      byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".",
    )
    .join("");
}

function bytesToBigIntDecimal(bytes) {
  let total = 0n;
  bytes.forEach((byte) => {
    total = (total << 8n) + BigInt(byte);
  });
  return total.toString(10);
}

function calculateShannonEntropy(bytes) {
  if (!bytes.length) return 0;
  const counts = new Array(256).fill(0);
  bytes.forEach((byte) => {
    counts[byte] += 1;
  });
  let entropy = 0;
  counts.forEach((count) => {
    if (!count) return;
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  });
  return entropy;
}

function inferMimeType(bytes) {
  if (!bytes || !bytes.length) return "application/octet-stream";

  const startsWith = (signature) =>
    signature.every((value, index) => bytes[index] === value);
  if (startsWith([0x89, 0x50, 0x4e, 0x47])) return "image/png";
  if (startsWith([0xff, 0xd8, 0xff])) return "image/jpeg";
  if (startsWith([0x47, 0x49, 0x46, 0x38])) return "image/gif";
  if (startsWith([0x25, 0x50, 0x44, 0x46])) return "application/pdf";
  if (startsWith([0x50, 0x4b, 0x03, 0x04])) return "application/zip";
  if (startsWith([0x1f, 0x8b])) return "application/gzip";
  if (startsWith([0x7f, 0x45, 0x4c, 0x46])) return "application/x-elf";

  const utf8Text = new TextDecoder().decode(bytes);
  const trimmed = utf8Text.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      JSON.parse(trimmed);
      return "application/json";
    } catch {
      // Keep evaluating as plain text/binary.
    }
  }

  const printableChars = [...utf8Text].filter((ch) => {
    const code = ch.charCodeAt(0);
    return (
      (code >= 32 && code <= 126) || ch === "\n" || ch === "\r" || ch === "\t"
    );
  }).length;
  if (
    utf8Text.length > 0 &&
    printableChars / utf8Text.length > DATA_TOOLS_TEXT_MIME_PRINTABLE_THRESHOLD
  ) {
    return "text/plain; charset=utf-8";
  }

  return "application/octet-stream";
}

function getEntropyLabel(entropy) {
  if (entropy >= DATA_TOOLS_ENTROPY_HIGH_THRESHOLD) return "High";
  if (entropy >= DATA_TOOLS_ENTROPY_MEDIUM_THRESHOLD) return "Medium";
  return "Low";
}

function resetDataToolsOutputs() {
  document.getElementById("data-tools-hex-output").value = "";
  document.getElementById("data-tools-binary-output").value = "";
  document.getElementById("data-tools-decimal-output").value = "";
  document.getElementById("data-tools-decimal-integer-output").value = "";
  document.getElementById("data-tools-ascii-output").value = "";
  document.getElementById("data-tools-base64-output").value = "";
  document.getElementById("data-tools-byte-length").textContent =
    "Byte Length: 0";
  document.getElementById("data-tools-mime-type").textContent =
    "MIME Type: Unknown";
  document.getElementById("data-tools-entropy").textContent =
    "Shannon Entropy: 0.00 (Low)";
  resetHashOutputs();
  clearProtoDecoderOutput();
}

const HASH_IDS = [
  "data-tools-md5-output",
  "data-tools-sha1-output",
  "data-tools-sha256-output",
  "data-tools-sha384-output",
  "data-tools-sha512-output",
  "data-tools-sha3-256-output",
  "data-tools-sha3-512-output",
  "data-tools-ripemd160-output",
  "data-tools-whirlpool-output",
];

function resetHashOutputs() {
  for (const id of HASH_IDS) {
    document.getElementById(id).value = "";
  }
}

function bytesToCharString(bytes) {
  const CHUNK_SIZE = 0x8000;
  let result = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, i + CHUNK_SIZE);
    result += String.fromCharCode(...chunk);
  }
  return result;
}

function computeDataToolsHashes(bytes) {
  const wordArray = CryptoJS.lib.WordArray.create(bytes);
  const byteString = bytesToCharString(bytes);

  document.getElementById("data-tools-md5-output").value =
    CryptoJS.MD5(wordArray).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha1-output").value =
    CryptoJS.SHA1(wordArray).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha256-output").value =
    CryptoJS.SHA256(wordArray).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha384-output").value =
    CryptoJS.SHA384(wordArray).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha512-output").value =
    CryptoJS.SHA512(wordArray).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha3-256-output").value = sha3_256(bytes);
  document.getElementById("data-tools-sha3-512-output").value = sha3_512(bytes);
  document.getElementById("data-tools-ripemd160-output").value =
    CryptoJS.RIPEMD160(wordArray).toString(CryptoJS.enc.Hex);
  const whirlpoolHash =
    bytes.length > 0 ? whirlpool.encSync(byteString, "hex") : "";
  document.getElementById("data-tools-whirlpool-output").value = whirlpoolHash;
}

function runDataToolsConversion() {
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  const errorEl = document.getElementById("data-tools-error");

  try {
    const bytes = parseDataToolsInput(formatEl.value, inputEl.value);
    const hexSpaced = [...bytes]
      .map((byte) => byte.toString(16).padStart(2, "0").toUpperCase())
      .join(" ");
    const binarySpaced = [...bytes]
      .map((byte) => byte.toString(2).padStart(8, "0"))
      .join(" ");
    const decimalBytes = [...bytes].join(" ");
    const asciiPreview = bytesToPrintableAscii(bytes);
    const base64Value = bytesToBase64(bytes);
    const entropy = calculateShannonEntropy(bytes);
    const entropyLabel = getEntropyLabel(entropy);
    const decimalInteger =
      bytes.length > DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES
        ? `Input exceeds ${DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES} bytes for decimal integer display`
        : bytesToBigIntDecimal(bytes);

    document.getElementById("data-tools-hex-output").value = hexSpaced;
    document.getElementById("data-tools-binary-output").value = binarySpaced;
    document.getElementById("data-tools-decimal-output").value = decimalBytes;
    document.getElementById("data-tools-decimal-integer-output").value =
      decimalInteger;
    document.getElementById("data-tools-ascii-output").value = asciiPreview;
    document.getElementById("data-tools-base64-output").value = base64Value;
    document.getElementById("data-tools-byte-length").textContent =
      `Byte Length: ${bytes.length}`;
    document.getElementById("data-tools-mime-type").textContent =
      `MIME Type: ${inferMimeType(bytes)}`;
    document.getElementById("data-tools-entropy").textContent =
      `Shannon Entropy: ${entropy.toFixed(2)} (${entropyLabel})`;
    errorEl.textContent = "";
    computeDataToolsHashes(bytes);
    runProtoDecoder(bytes);
  } catch (error) {
    resetDataToolsOutputs();
    errorEl.textContent =
      error && typeof error === "object" && "message" in error
        ? error.message
        : String(error);
  }
}

// ── Protocol decoders for the Conv tab ───────────────────────────────────────

function decodeHttpFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/);
  if (!lines.length) return null;
  const firstLine = lines[0].trim();
  const requestMatch = firstLine.match(
    /^([A-Z]+)\s+(\S+)\s+(HTTP\/[\d.]+)$/,
  );
  const responseMatch = firstLine.match(/^(HTTP\/[\d.]+)\s+(\d{3})\s*(.*)/);
  if (!requestMatch && !responseMatch) return null;

  const emptyLineIdx = lines.findIndex((l, i) => i > 0 && l.trim() === "");
  const headerLines = lines.slice(
    1,
    emptyLineIdx > 0 ? emptyLineIdx : lines.length,
  );
  const headers = {};
  headerLines.forEach((hl) => {
    const idx = hl.indexOf(":");
    if (idx > 0) {
      headers[hl.slice(0, idx).trim()] = hl.slice(idx + 1).trim();
    }
  });

  const fields = [];
  if (requestMatch) {
    fields.push(
      { name: "Type", value: "Request" },
      { name: "Method", value: requestMatch[1] },
      { name: "URL", value: requestMatch[2] },
      { name: "Version", value: requestMatch[3] },
    );
    [
      "Host",
      "User-Agent",
      "Content-Type",
      "Content-Length",
      "Accept",
      "Accept-Encoding",
      "Connection",
      "Authorization",
      "Referer",
      "Cookie",
    ].forEach((h) => {
      if (headers[h]) fields.push({ name: h, value: headers[h] });
    });
  } else {
    fields.push(
      { name: "Type", value: "Response" },
      { name: "Version", value: responseMatch[1] },
      { name: "Status Code", value: responseMatch[2] },
      { name: "Status Message", value: responseMatch[3] || "—" },
    );
    [
      "Server",
      "Content-Type",
      "Content-Length",
      "Content-Encoding",
      "Transfer-Encoding",
      "Connection",
      "Location",
      "Set-Cookie",
      "Cache-Control",
      "Date",
    ].forEach((h) => {
      if (headers[h]) fields.push({ name: h, value: headers[h] });
    });
  }
  if (emptyLineIdx > 0 && emptyLineIdx < lines.length - 1) {
    const body = lines
      .slice(emptyLineIdx + 1)
      .join("\n")
      .trim();
    if (body) {
      fields.push({
        name: "Body (preview)",
        value: body.length > 200 ? body.slice(0, 200) + "…" : body,
      });
    }
  }
  return { protocol: "HTTP", fields };
}

function decodeTelnetFromBytes(bytes) {
  const IAC = 0xff;
  const WILL = 0xfb,
    WONT = 0xfc,
    DO = 0xfd,
    DONT = 0xfe;
  const SB = 0xfa,
    SE = 0xf0;
  const optionNames = {
    0: "Binary",
    1: "Echo",
    3: "Suppress Go Ahead",
    5: "Status",
    24: "Terminal Type",
    31: "Window Size",
    32: "Terminal Speed",
    34: "Linemode",
    39: "New Environment",
  };
  const negotiations = [];
  let text = "";
  let i = 0;
  let hasIac = false;
  while (i < bytes.length) {
    if (bytes[i] === IAC) {
      hasIac = true;
      i++;
      if (i >= bytes.length) break;
      const cmd = bytes[i++];
      if (cmd === WILL || cmd === WONT || cmd === DO || cmd === DONT) {
        if (i < bytes.length) {
          const opt = bytes[i++];
          const cmdName =
            cmd === WILL
              ? "WILL"
              : cmd === WONT
                ? "WONT"
                : cmd === DO
                  ? "DO"
                  : "DONT";
          negotiations.push(`${cmdName} ${optionNames[opt] ?? `Option ${opt}`}`);
        }
      } else if (cmd === SB) {
        while (i < bytes.length) {
          if (bytes[i] === IAC && i + 1 < bytes.length && bytes[i + 1] === SE) {
            i += 2;
            break;
          }
          i++;
        }
      }
    } else {
      const b = bytes[i++];
      if (b >= 32 && b < 127) text += String.fromCharCode(b);
      else if (b === 10) text += "\n";
      else if (b === 13) text += "\r";
    }
  }
  if (!hasIac && !text.trim()) return null;
  const fields = [];
  if (negotiations.length) {
    fields.push({ name: "Negotiations", value: negotiations.join(", ") });
  }
  if (text.trim()) {
    const t = text.trim();
    fields.push({
      name: "Text",
      value: t.length > 500 ? t.slice(0, 500) + "…" : t,
    });
  }
  if (!fields.length) return null;
  return { protocol: "Telnet", fields };
}

function decodeSshFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(
    bytes.slice(0, 512),
  );
  const bannerMatch = text.match(/^SSH-([\S]+)\r?\n/);
  if (!bannerMatch) return null;
  const versionStr = bannerMatch[1];
  const dashIdx = versionStr.indexOf("-");
  const protocolVersion =
    dashIdx >= 0 ? versionStr.slice(0, dashIdx) : versionStr;
  const softwareVersion = dashIdx >= 0 ? versionStr.slice(dashIdx + 1) : "—";
  const fields = [
    { name: "Protocol Version", value: protocolVersion },
    { name: "Software Version", value: softwareVersion },
  ];
  const bannerEnd = text.indexOf("\n");
  if (bannerEnd > 0 && bytes.length > bannerEnd + 1) {
    fields.push({
      name: "Additional Data",
      value: `${bytes.length - bannerEnd - 1} bytes (key exchange)`,
    });
  }
  return { protocol: "SSH / OpenSSH", fields };
}

function decodePop3FromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) return null;
  const POP3_COMMANDS = new Set([
    "USER",
    "PASS",
    "STAT",
    "LIST",
    "RETR",
    "DELE",
    "NOOP",
    "RSET",
    "QUIT",
    "APOP",
    "TOP",
    "UIDL",
  ]);
  const fields = [];
  let detected = false;
  for (const line of lines) {
    if (line.startsWith("+OK")) {
      fields.push({ name: "Response", value: "+OK" });
      const msg = line.slice(3).trim();
      if (msg) fields.push({ name: "Message", value: msg });
      detected = true;
    } else if (line.startsWith("-ERR")) {
      fields.push({ name: "Response", value: "-ERR" });
      const msg = line.slice(4).trim();
      if (msg) fields.push({ name: "Error", value: msg });
      detected = true;
    } else {
      const parts = line.split(/\s+/);
      const cmd = parts[0].toUpperCase();
      if (POP3_COMMANDS.has(cmd)) {
        fields.push({ name: "Command", value: cmd });
        if (parts.length > 1) {
          fields.push({ name: "Argument", value: parts.slice(1).join(" ") });
        }
        detected = true;
      }
    }
    if (fields.length >= 10) break;
  }
  if (!detected) return null;
  return { protocol: "POP3", fields };
}

function decodeImapFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) return null;
  const IMAP_STATUSES = new Set(["OK", "NO", "BAD", "PREAUTH", "BYE"]);
  const IMAP_COMMANDS = new Set([
    "CAPABILITY",
    "NOOP",
    "LOGOUT",
    "AUTHENTICATE",
    "LOGIN",
    "SELECT",
    "EXAMINE",
    "CREATE",
    "DELETE",
    "RENAME",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "LIST",
    "LSUB",
    "STATUS",
    "APPEND",
    "CHECK",
    "CLOSE",
    "EXPUNGE",
    "SEARCH",
    "FETCH",
    "STORE",
    "COPY",
    "UID",
    "IDLE",
  ]);
  const fields = [];
  let detected = false;
  for (const line of lines) {
    if (line.startsWith("* ")) {
      const val = line.slice(2).trim();
      fields.push({
        name: "Untagged",
        value: val.length > 100 ? val.slice(0, 100) + "…" : val,
      });
      detected = true;
    } else if (line.startsWith("+ ")) {
      fields.push({ name: "Continuation", value: line.slice(2).trim() });
      detected = true;
    } else {
      const m = line.match(/^(\S+)\s+(\S+)\s*(.*)/);
      if (m) {
        const tag = m[1];
        const word = m[2].toUpperCase();
        const rest = m[3];
        if (IMAP_STATUSES.has(word)) {
          const val = `${word} ${rest}`.trim();
          fields.push({
            name: `[${tag}] Status`,
            value: val.length > 100 ? val.slice(0, 100) + "…" : val,
          });
          detected = true;
        } else if (IMAP_COMMANDS.has(word)) {
          fields.push({ name: `[${tag}] Command`, value: word });
          if (rest) {
            fields.push({
              name: "Arguments",
              value: rest.length > 100 ? rest.slice(0, 100) + "…" : rest,
            });
          }
          detected = true;
        }
      }
    }
    if (fields.length >= 12) break;
  }
  if (!detected) return null;
  return { protocol: "IMAP", fields };
}

function decodeSmtpFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) return null;
  const SMTP_COMMANDS = new Set([
    "HELO",
    "EHLO",
    "MAIL",
    "RCPT",
    "DATA",
    "RSET",
    "VRFY",
    "EXPN",
    "NOOP",
    "QUIT",
    "AUTH",
    "STARTTLS",
  ]);
  const fields = [];
  let detected = false;
  for (const line of lines) {
    const rm = line.match(/^(\d{3})([\s-])(.*)/);
    if (rm) {
      const label = `Response ${rm[1]}${rm[2] === "-" ? " (cont.)" : ""}`;
      fields.push({ name: label, value: rm[3] });
      detected = true;
    } else {
      const parts = line.split(/\s+/);
      const cmd = parts[0].toUpperCase();
      if (SMTP_COMMANDS.has(cmd)) {
        fields.push({ name: "Command", value: cmd });
        if (parts.length > 1) {
          const arg = parts.slice(1).join(" ");
          fields.push({
            name: "Argument",
            value: arg.length > 100 ? arg.slice(0, 100) + "…" : arg,
          });
        }
        detected = true;
      }
    }
    if (fields.length >= 12) break;
  }
  if (!detected) return null;
  return { protocol: "SMTP", fields };
}

function autoDetectProtoFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(
    bytes.slice(0, 256),
  );
  if (/^SSH-/.test(text)) return "ssh";
  if (
    /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s/.test(text) ||
    /^HTTP\/[\d.]+ \d{3}/.test(text)
  )
    return "http";
  if (
    /^(HELO|EHLO|MAIL FROM|RCPT TO|DATA|QUIT)\b/i.test(text) ||
    /^\d{3}[\s-]/.test(text)
  )
    return "smtp";
  if (
    /^\+OK/.test(text) ||
    /^-ERR/.test(text) ||
    /^(USER|PASS|STAT|LIST|RETR|DELE|QUIT)\b/i.test(text)
  )
    return "pop3";
  if (
    /^\* /.test(text) ||
    /^\+ /.test(text) ||
    /^\S+ (OK|NO|BAD|PREAUTH|BYE)\b/i.test(text) ||
    /^\S+ (SELECT|LOGIN|FETCH|AUTHENTICATE)\b/i.test(text)
  )
    return "imap";
  // Telnet: require IAC (0xFF) followed by a valid command byte (0xF0–0xFF)
  const TELNET_COMMANDS = new Set([
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff,
  ]);
  for (let i = 0; i + 1 < bytes.length; i++) {
    if (bytes[i] === 0xff && TELNET_COMMANDS.has(bytes[i + 1])) return "telnet";
  }
  return null;
}

function renderProtoDecoderOutput(result, selectedProtocol, protocol) {
  const protoOutput = document.getElementById("data-tools-proto-output");
  if (!protoOutput) return;
  activeDataToolsProtoResult = result || null;
  protoOutput.innerHTML = "";
  if (!result) {
    const span = document.createElement("span");
    span.className = "data-tools-proto-none";
    span.textContent =
      selectedProtocol === "auto"
        ? "No known protocol detected"
        : `Could not decode as ${(protocol || selectedProtocol).toUpperCase()}`;
    protoOutput.appendChild(span);
    return;
  }
  const table = document.createElement("table");
  table.className = "data-tools-proto-table";
  const headerRow = document.createElement("tr");
  const th1 = document.createElement("th");
  th1.textContent = `${result.protocol} Field`;
  const th2 = document.createElement("th");
  th2.textContent = "Value";
  headerRow.appendChild(th1);
  headerRow.appendChild(th2);
  table.appendChild(headerRow);
  result.fields.forEach((field) => {
    const tr = document.createElement("tr");
    const tdName = document.createElement("td");
    tdName.textContent = field.name;
    const tdVal = document.createElement("td");
    tdVal.textContent = field.value;
    tr.appendChild(tdName);
    tr.appendChild(tdVal);
    table.appendChild(tr);
  });
  protoOutput.appendChild(table);
}

function runProtoDecoder(bytes) {
  const selectEl = document.getElementById("data-tools-proto-select");
  const selectedProtocol = selectEl ? selectEl.value : "auto";
  let protocol = selectedProtocol;
  if (protocol === "auto") {
    protocol = autoDetectProtoFromBytes(bytes);
  }
  let result = null;
  switch (protocol) {
    case "http":
      result = decodeHttpFromBytes(bytes);
      break;
    case "telnet":
      result = decodeTelnetFromBytes(bytes);
      break;
    case "ssh":
      result = decodeSshFromBytes(bytes);
      break;
    case "pop3":
      result = decodePop3FromBytes(bytes);
      break;
    case "imap":
      result = decodeImapFromBytes(bytes);
      break;
    case "smtp":
      result = decodeSmtpFromBytes(bytes);
      break;
    default:
      protocol = null;
  }
  renderProtoDecoderOutput(result, selectedProtocol, protocol);
}

function clearProtoDecoderOutput() {
  const protoOutput = document.getElementById("data-tools-proto-output");
  if (protoOutput) protoOutput.innerHTML = "";
}

// ─────────────────────────────────────────────────────────────────────────────

function showDataTools(tabName = CONV_CONVERSIONS_SUBTAB) {
  activeMainTab = MAIN_TAB_DATA_TOOLS;
  statusUpdate("Status: Displaying data conversion tools");
  writeLogEntry("User opened data conversion tools view");
  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("stats_box").style.display = "none";
  document.getElementById("list_box").style.display = "none";
  document.getElementById("crypt_box").style.display = "none";
  document.getElementById("keystore_box").style.display = "none";
  document.getElementById("rightside").style.display = "none";
  document.getElementById("data_tools_box").style.display = "flex";
  setConvSubtab(tabName);
}

function getFirstLineOrFallback(elementId, fallback = "") {
  const text = document.getElementById(elementId)?.textContent || "";
  const firstLine = text.split("\n")[0]?.trim();
  return firstLine || fallback;
}

function setConvSubtab(tabName) {
  activeConvSubtab = tabName;
  const conversionsActive = tabName === CONV_CONVERSIONS_SUBTAB;
  const hashesActive = tabName === CONV_HASHES_SUBTAB;
  const decodesActive = tabName === CONV_DECODES_SUBTAB;
  document
    .getElementById("conv-subtab-conversions")
    .classList.toggle("active", conversionsActive);
  document
    .getElementById("conv-subtab-hashes")
    .classList.toggle("active", hashesActive);
  document
    .getElementById("conv-subtab-decodes")
    .classList.toggle("active", decodesActive);
  document.getElementById("conv-conversions-panel").hidden = !conversionsActive;
  document.getElementById("conv-hashes-panel").hidden = !hashesActive;
  document.getElementById("conv-decodes-panel").hidden = !decodesActive;
}

const cryptPanel = createCryptPanel({
  constants: {
    MAIN_TAB_CRYPT,
    CRYPT_SSL_SUBTAB,
    CRYPT_PGP_SUBTAB,
    CRYPT_OPENSSH_SUBTAB,
    SESSION_KEYCHAIN_LABEL,
    STRICT_IPV4_REGEX,
  },
  getCapturedPackets: () => capturedPackets,
  getJsonCapture: () => jsonCapture,
  setActiveMainTab: (tabName) => {
    activeMainTab = tabName;
  },
  setActiveCryptSubtab: (tabName) => {
    activeCryptSubtab = tabName;
  },
  statusUpdate,
  writeLogEntry,
  doError,
  logErrorEntry,
  filterInputEl,
  syncFilterHighlight,
  runFilterQuery,
  addSessionKeystoreEntry: (...args) => keystorePanel.addSessionKeystoreEntry(...args),
  getFirstLineOrFallback,
});

const {
  setCryptSubtab,
  applyCryptCertificateText,
  applyCryptPrivateKeyText,
  readCryptTextFile,
  applyCryptFilterForActiveEntry,
  loadEncounteredCertificateIntoCrypt,
  refreshCryptEncounteredEntries,
  showCryptWorkspace,
} = cryptPanel;

let activeContextConversionText = "";
let activeContextTarget = null;
let activeContextPasteTarget = null;
let activeContextFilterQueries = {};
let activeContextCookieJarText = "";
let activeDataToolsProtoResult = null;
const convertContextMenuEl = getCachedElement("convert-context-menu");
const convertContextButtons = {
  copy: getCachedElement("ctx-copy"),
  paste: getCachedElement("ctx-paste"),
  saveJson: getCachedElement("ctx-save-json"),
  exportPacket: getCachedElement("ctx-export-packet"),
  exportPayload: getCachedElement("ctx-export-payload"),
  hex: getCachedElement("convert-context-hex"),
  binary: getCachedElement("convert-context-binary"),
  base64: getCachedElement("convert-context-base64"),
  decimal: getCachedElement("convert-context-decimal"),
  ascii: getCachedElement("convert-context-ascii"),
  loadPayload: getCachedElement("convert-context-load-payload"),
  copyHex: getCachedElement("convert-context-copy-hex"),
  copyAscii: getCachedElement("convert-context-copy-ascii"),
  copyRaw: getCachedElement("convert-context-copy-raw"),
  filterIp: getCachedElement("ctx-filter-ip"),
  filterPort: getCachedElement("ctx-filter-port"),
  filterMac: getCachedElement("ctx-filter-mac"),
  filterProtocol: getCachedElement("ctx-filter-protocol"),
  filterMime: getCachedElement("ctx-filter-mime"),
  filterOrIp: getCachedElement("ctx-filter-or-ip"),
  filterOrPort: getCachedElement("ctx-filter-or-port"),
  filterOrMac: getCachedElement("ctx-filter-or-mac"),
  filterOrProtocol: getCachedElement("ctx-filter-or-protocol"),
  filterOrMime: getCachedElement("ctx-filter-or-mime"),
  filterNotIp: getCachedElement("ctx-filter-not-ip"),
  filterNotPort: getCachedElement("ctx-filter-not-port"),
  filterNotMac: getCachedElement("ctx-filter-not-mac"),
  filterNotProtocol: getCachedElement("ctx-filter-not-protocol"),
  filterNotMime: getCachedElement("ctx-filter-not-mime"),
  filterParenOpen: getCachedElement("ctx-filter-paren-open"),
  filterParenClose: getCachedElement("ctx-filter-paren-close"),
  filterParenWrap: getCachedElement("ctx-filter-paren-wrap"),
  filterClearIp: getCachedElement("ctx-filter-clear-ip"),
  filterClearPort: getCachedElement("ctx-filter-clear-port"),
  filterClearMac: getCachedElement("ctx-filter-clear-mac"),
  filterClearProtocol: getCachedElement("ctx-filter-clear-protocol"),
  filterClearMime: getCachedElement("ctx-filter-clear-mime"),
  keystorePasswordSession: getCachedElement("ctx-keystore-password-session"),
  keystorePasswordPersistent: getCachedElement("ctx-keystore-password-persistent"),
  keystoreKeySession: getCachedElement("ctx-keystore-key-session"),
  keystoreKeyPersistent: getCachedElement("ctx-keystore-key-persistent"),
  keystoreCertSession: getCachedElement("ctx-keystore-cert-session"),
  keystoreCertPersistent: getCachedElement("ctx-keystore-cert-persistent"),
  keystoreCookieSession: getCachedElement("ctx-keystore-cookie-session"),
  keystoreCookiePersistent: getCachedElement("ctx-keystore-cookie-persistent"),
  copyCookieJar: getCachedElement("ctx-copy-cookie-jar"),
  saveCookieJar: getCachedElement("ctx-save-cookie-jar"),
  httpFileSave: getCachedElement("ctx-http-file-save"),
  httpFileLoad: getCachedElement("ctx-http-file-load"),
  httpFilePreview: getCachedElement("ctx-http-file-preview"),
};
const convertContextSubmenus = {
  copy: getCachedElement("ctx-copy-submenu"),
  convert: getCachedElement("ctx-convert-submenu"),
  filter: getCachedElement("ctx-filter-submenu"),
  filterAnd: getCachedElement("ctx-filter-and-submenu"),
  filterOr: getCachedElement("ctx-filter-or-submenu"),
  filterNot: getCachedElement("ctx-filter-not-submenu"),
  filterParentheses: getCachedElement("ctx-filter-parentheses-submenu"),
  filterClear: getCachedElement("ctx-filter-clear-submenu"),
  export: getCachedElement("ctx-export-submenu"),
  keystore: getCachedElement("ctx-keystore-submenu"),
  keystorePassword: getCachedElement("ctx-keystore-password-submenu"),
  keystoreKey: getCachedElement("ctx-keystore-key-submenu"),
  keystoreCert: getCachedElement("ctx-keystore-cert-submenu"),
  keystoreCookie: getCachedElement("ctx-keystore-cookie-submenu"),
  httpFile: getCachedElement("ctx-http-file-submenu"),
};
const convertContextDividerEl = getCachedElement("convert-context-divider");
const convertContextSaveDividerEl = getCachedElement(
  "convert-context-save-divider",
);
const convertContextSubmenuEls = Array.from(
  convertContextMenuEl.querySelectorAll(".ctx-submenu"),
);

function resetConvertContextSubmenuPositions() {
  convertContextSubmenuEls.forEach((submenuEl) => {
    submenuEl.classList.remove("ctx-submenu-flip-x", "ctx-submenu-flip-y");
  });
}

function updateConvertContextSubmenuPositions() {
  const viewportPadding = 8;
  resetConvertContextSubmenuPositions();

  convertContextSubmenuEls.forEach((submenuEl) => {
    if (submenuEl.style.display === "none") return;
    // Use :scope > to get only the direct child panel, not a grandchild's.
    const submenuPanelEl = submenuEl.querySelector(":scope > .ctx-submenu-panel");
    if (!submenuPanelEl) return;

    // Temporarily reveal every ancestor .ctx-submenu-panel so that this
    // element has a real viewport position when getBoundingClientRect() is
    // called.  Without this, panels at depth > 1 are inside a hidden
    // ancestor and always return zero-area rects, making the overflow
    // calculations completely wrong for those levels.
    const revealedAncestors = [];
    let node = submenuEl.parentElement;
    while (node && node !== convertContextMenuEl) {
      if (
        node.classList.contains("ctx-submenu-panel") &&
        node.style.display !== "block"
      ) {
        revealedAncestors.push({
          el: node,
          previousDisplay: node.style.display,
          previousVisibility: node.style.visibility,
          previousPointerEvents: node.style.pointerEvents,
        });
        node.style.display = "block";
        node.style.visibility = "hidden";
        node.style.pointerEvents = "none";
      }
      node = node.parentElement;
    }

    const previousDisplay = submenuPanelEl.style.display;
    const previousVisibility = submenuPanelEl.style.visibility;
    const previousPointerEvents = submenuPanelEl.style.pointerEvents;
    submenuPanelEl.style.display = "block";
    submenuPanelEl.style.visibility = "hidden";
    submenuPanelEl.style.pointerEvents = "none";

    const submenuRect = submenuEl.getBoundingClientRect();
    const panelRect = submenuPanelEl.getBoundingClientRect();
    const wouldOverflowRight =
      submenuRect.right + panelRect.width > window.innerWidth - viewportPadding;
    const wouldOverflowBottom =
      submenuRect.top + panelRect.height > window.innerHeight - viewportPadding;
    const hasRoomAbove =
      submenuRect.bottom - panelRect.height >= viewportPadding;

    if (wouldOverflowRight) {
      submenuEl.classList.add("ctx-submenu-flip-x");
    }
    if (wouldOverflowBottom && hasRoomAbove) {
      submenuEl.classList.add("ctx-submenu-flip-y");
    }

    submenuPanelEl.style.display = previousDisplay;
    submenuPanelEl.style.visibility = previousVisibility;
    submenuPanelEl.style.pointerEvents = previousPointerEvents;

    // Restore ancestor panels in reverse order (innermost first).
    for (let i = revealedAncestors.length - 1; i >= 0; i--) {
      const ancestor = revealedAncestors[i];
      ancestor.el.style.display = ancestor.previousDisplay;
      ancestor.el.style.visibility = ancestor.previousVisibility;
      ancestor.el.style.pointerEvents = ancestor.previousPointerEvents;
    }
  });
}

function hideConvertContextMenu() {
  activeContextConversionText = "";
  activeContextTarget = null;
  activeContextPasteTarget = null;
  activeContextFilterQueries = {};
  activeContextCookieJarText = "";
  resetConvertContextSubmenuPositions();
  convertContextMenuEl.hidden = true;
}

function normalizeContextToken(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/\s+/g, " ").trim();
}

function extractContextIp(value) {
  const normalized = normalizeContextToken(value);
  const match = normalized.match(CONTEXT_IPV4_REGEX);
  return match ? match[0] : "";
}

function extractContextPort(value, allowStandaloneNumber = false) {
  const normalized = normalizeContextToken(value);
  const ipPortMatch = normalized.match(
    /\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}:(\d{1,5})\b/,
  );
  if (ipPortMatch) {
    const ipPortValue = Number.parseInt(ipPortMatch[4], 10);
    return ipPortValue >= 0 && ipPortValue <= 65535 ? String(ipPortValue) : "";
  }
  if (!allowStandaloneNumber) return "";
  const portMatch = normalized.match(/^\d{1,5}$/);
  if (!portMatch) return "";
  const portValue = Number.parseInt(normalized, 10);
  return portValue >= 0 && portValue <= 65535 ? String(portValue) : "";
}

function extractContextMac(value) {
  const normalized = normalizeContextToken(value);
  const match = normalized.match(CONTEXT_MAC_REGEX);
  return match ? match[0].toLowerCase() : "";
}

function extractContextMimeType(value) {
  const normalized = normalizeContextToken(value);
  const labelStripped = normalized
    .replace(/^mime(?:\s+type)?\s*:\s*/i, "")
    .trim();
  if (!labelStripped) return "";
  const mimeBase = labelStripped.split(";")[0].trim();
  return CONTEXT_MIME_REGEX.test(mimeBase) ? mimeBase.toLowerCase() : "";
}

function extractContextProtocol(value) {
  const normalized = normalizeContextToken(value);
  const labelStripped = normalized
    .replace(/^protocol(?:\s+name)?\s*:\s*/i, "")
    .replace(/^app(?:lication)?\s+protocol\s*:\s*/i, "")
    .replace(/^transport\s+protocol\s*:\s*/i, "")
    .trim();
  if (!labelStripped) return "";
  const protocolMatch = labelStripped.match(/^[a-z][a-z0-9+_-]*$/i);
  return protocolMatch ? labelStripped.toLowerCase() : "";
}

function sanitizeFilterTerm(value) {
  return normalizeContextToken(value)
    .replace(/[^a-zA-Z0-9:./+-]/g, "")
    .trim();
}

function buildContextFilterQueries(target, selectedText, conversionText) {
  const candidates = [];
  const addCandidate = (value) => {
    const normalized = normalizeContextToken(value);
    if (!normalized) return;
    if (!candidates.includes(normalized)) candidates.push(normalized);
  };

  addCandidate(selectedText);
  addCandidate(conversionText);

  let rowName = "";
  let rowPortEligible = false;
  const row = target?.closest?.("tr");
  if (row) {
    const cells = row.querySelectorAll("td");
    rowName = normalizeContextToken(cells[0]?.textContent);
    const rowValue = normalizeContextToken(cells[1]?.textContent);
    addCandidate(rowValue);
    rowPortEligible = /\bport\b/i.test(rowName);
    if (/^ip\s*:?\s*port$/i.test(rowName) && rowValue) {
      const bracketedIpv6Match = rowValue.match(/^\[([^\]]+)\]:(\d{1,5})$/);
      if (bracketedIpv6Match) {
        addCandidate(bracketedIpv6Match[1]);
        addCandidate(bracketedIpv6Match[2]);
      } else {
        const ipv4PortMatch = rowValue.match(
          /^((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}):(\d{1,5})$/,
        );
        if (ipv4PortMatch) {
          addCandidate(ipv4PortMatch[1]);
          addCandidate(ipv4PortMatch[2]);
        } else {
          const lastColonIndex = rowValue.lastIndexOf(":");
          if (lastColonIndex > 0) {
            const maybePort = rowValue.slice(lastColonIndex + 1).trim();
            if (/^\d{1,5}$/.test(maybePort)) {
              addCandidate(maybePort);
            }
          }
        }
      }
    }
  }

  const filterQueries = {};
  const skipProtocol = /^network\s+class$/i.test(rowName);
  for (const candidate of candidates) {
    if (!filterQueries.ip) {
      const ip = extractContextIp(candidate);
      if (ip) {
        const safeIp = sanitizeFilterTerm(ip);
        filterQueries.ip = `ip.src.addr: ${safeIp} || ip.dst.addr: ${safeIp}`;
      }
    }
    if (!filterQueries.port) {
      const port = extractContextPort(candidate, rowPortEligible);
      if (port) {
        const safePort = sanitizeFilterTerm(port);
        filterQueries.port =
          `tcp.src.port: ${safePort} || tcp.dst.port: ${safePort}` +
          ` || udp.src.port: ${safePort} || udp.dst.port: ${safePort}`;
      }
    }
    if (!filterQueries.mac) {
      const mac = extractContextMac(candidate);
      if (mac) {
        const safeMac = sanitizeFilterTerm(mac);
        filterQueries.mac = `ether.src.mac.addr: ${safeMac} || ether.dst.mac.addr: ${safeMac}`;
      }
    }
    if (!filterQueries.protocol && !skipProtocol) {
      const protocol = extractContextProtocol(candidate);
      if (protocol) {
        const safeProtocol = sanitizeFilterTerm(protocol);
        filterQueries.protocol = `wire.proto: ${safeProtocol} || tcp.proto: ${safeProtocol}`;
      }
    }
    if (!filterQueries.mime) {
      const mimeType = extractContextMimeType(candidate);
      if (mimeType) {
        const safeMimeType = sanitizeFilterTerm(mimeType);
        filterQueries.mime = `mime.type: ${safeMimeType}`;
      }
    }
  }

  return filterQueries;
}

function getTrimmedSelectionText() {
  return window.getSelection()?.toString().trim() || "";
}

function looksLikeBase64(text) {
  const normalized = text.replace(/\s+/g, "");
  return (
    normalized.length >= DATA_TOOLS_CONTEXT_BASE64_MIN_LENGTH &&
    normalized.length % 4 === 0 &&
    /^[A-Za-z0-9+/]*={0,2}$/.test(normalized) &&
    normalized.replace(/=/g, "").length > 0
  );
}

function detectConvertibleFormats(text) {
  const formats = [];
  const value = text.trim();
  if (!value) return formats;

  const canParse = (format) => {
    try {
      parseDataToolsInput(format, value);
      return true;
    } catch {
      return false;
    }
  };

  if (canParse("hex")) formats.push("hex");
  if (canParse("binary")) formats.push("binary");
  if (canParse("decimal")) formats.push("decimal");
  if (looksLikeBase64(value) && canParse("base64")) formats.push("base64");
  if (formats.length > 0) formats.push("ascii");

  return formats;
}

function splitCookieHeaderEntries(headerValue) {
  if (typeof headerValue !== "string" || !headerValue.trim()) return [];
  const entries = [];
  let currentEntry = "";
  let inQuotes = false;
  let isEscaped = false;

  for (const character of headerValue) {
    if (isEscaped) {
      currentEntry += character;
      isEscaped = false;
      continue;
    }
    if (character === "\\" && inQuotes) {
      currentEntry += character;
      isEscaped = true;
      continue;
    }
    if (character === '"') {
      inQuotes = !inQuotes;
      currentEntry += character;
      continue;
    }
    if (character === ";" && !inQuotes) {
      const trimmedEntry = currentEntry.trim();
      if (trimmedEntry) entries.push(trimmedEntry);
      currentEntry = "";
      continue;
    }
    currentEntry += character;
  }

  const trimmedEntry = currentEntry.trim();
  if (trimmedEntry) entries.push(trimmedEntry);
  return entries;
}

function extractCookieJarEntriesFromHttpFields(fields) {
  if (!Array.isArray(fields)) return [];
  const cookieEntries = [];
  const addCookieEntry = (entry) => {
    const normalizedEntry =
      typeof entry === "string" ? entry.trim() : String(entry || "").trim();
    if (!normalizedEntry || !normalizedEntry.includes("=")) return;
    if (!cookieEntries.includes(normalizedEntry)) {
      cookieEntries.push(normalizedEntry);
    }
  };

  fields.forEach((field) => {
    const fieldName = String(field?.name || "").trim().toLowerCase();
    const fieldValue = typeof field?.value === "string" ? field.value.trim() : "";
    if (!fieldValue) return;
    if (fieldName === "cookie") {
      splitCookieHeaderEntries(fieldValue).forEach((cookieEntry) => {
        addCookieEntry(cookieEntry);
      });
      return;
    }
    if (fieldName === "set-cookie") {
      addCookieEntry(fieldValue);
    }
  });

  return cookieEntries;
}

keystorePanel = createKeystorePanel({
  statusUpdate,
  writeLogEntry,
  doError,
  logErrorEntry,
  getCapturedPackets: () => capturedPackets,
  getJsonCapture: () => jsonCapture,
  setActiveMainTab: (tabName) => {
    activeMainTab = tabName;
  },
  MAIN_TAB_KEYSTORE,
  parseDataToolsInput,
  decodeHttpFromBytes,
  extractCookieJarEntriesFromHttpFields,
  getTrimmedSelectionText,
  hideConvertContextMenu,
  getActiveContextConversionText: () => activeContextConversionText,
  getApplyCryptCertificateText: () => applyCryptCertificateText,
  getApplyCryptPrivateKeyText: () => applyCryptPrivateKeyText,
});

function buildCookieJarTextFromHttpFields(fields) {
  return extractCookieJarEntriesFromHttpFields(fields).join("\n");
}

function getCookieJarTextForCurrentPacket() {
  const payloadHex = getCurrentRawPayloadHex();
  if (!payloadHex) return "";
  try {
    const bytes = parseDataToolsInput("hex", payloadHex);
    const decodedHttp = decodeHttpFromBytes(bytes);
    return decodedHttp?.protocol === "HTTP"
      ? buildCookieJarTextFromHttpFields(decodedHttp.fields)
      : "";
  } catch {
    // Context-menu cookie actions are best-effort for the active packet.
    // Fallback to no cookie jar when payload decode fails.
    return "";
  }
}

function getCookieJarTextForContextTarget(target) {
  if (target?.closest?.("#data-tools-proto-output")) {
    const dataToolsCookieJarText =
      activeDataToolsProtoResult?.protocol === "HTTP"
        ? buildCookieJarTextFromHttpFields(activeDataToolsProtoResult.fields)
        : "";
    if (dataToolsCookieJarText) return dataToolsCookieJarText;
  }
  return getCookieJarTextForCurrentPacket();
}

function getConversionTextFromTarget(target) {
  const selectedText = window.getSelection()?.toString().trim();
  if (selectedText) return selectedText;

  const directValue =
    target && "value" in target && typeof target.value === "string"
      ? target.value.trim()
      : "";
  if (directValue) return directValue;

  if (target?.classList?.contains("griditem")) {
    return target.textContent.trim();
  }

  const textContent = target?.textContent ? target.textContent.trim() : "";
  if (!textContent) return "";

  if (textContent.includes(":")) {
    const prefix = textContent.split(":")[0]?.trim();
    const looksLikeLabel = /^[A-Za-z][\w\s-]*$/.test(prefix);
    // Keep full suffix so values containing additional colons (IPv6/timestamps)
    // are preserved, e.g. "Label: fe80::1" or "Time: 12:34:56".
    if (looksLikeLabel) {
      const suffix = textContent.split(":").slice(1).join(":").trim();
      if (suffix) return suffix;
    }
  }

  return textContent;
}

function getPasteTargetFromContextTarget(target) {
  if (!(target instanceof Element)) return null;
  const editableTarget = target.closest(
    'input, textarea, [contenteditable="true"], [contenteditable=""]',
  );
  if (!editableTarget) return null;

  if ("readOnly" in editableTarget && editableTarget.readOnly) return null;
  if ("disabled" in editableTarget && editableTarget.disabled) return null;

  if (editableTarget.tagName === "INPUT") {
    const disallowedInputTypes = new Set([
      "button",
      "checkbox",
      "color",
      "file",
      "hidden",
      "image",
      "radio",
      "range",
      "reset",
      "submit",
    ]);
    const inputType = (editableTarget.type || "text").toLowerCase();
    if (disallowedInputTypes.has(inputType)) return null;
  }

  return editableTarget;
}

function showConvertContextMenu(
  x,
  y,
  sourceText,
  formats,
  {
    isHexViewTarget = false,
    target = null,
    pasteTarget = null,
    showCopySelection = false,
    showPaste = true,
    showSaveJson = true,
    filterQueries = {},
    cookieJarText = "",
  } = {},
) {
  activeContextConversionText = sourceText;
  activeContextTarget = target;
  activeContextPasteTarget = pasteTarget;
  activeContextFilterQueries = filterQueries;
  activeContextCookieJarText = cookieJarText;

  convertContextButtons.copy.style.display = showCopySelection
    ? "block"
    : "none";
  convertContextButtons.paste.style.display = showPaste ? "block" : "none";
  convertContextButtons.saveJson.style.display = showSaveJson
    ? "block"
    : "none";
  const hasPacketToExport = Boolean(
    getCurrentPacketForExport(packetsForHost, getActivePacketCursor()),
  );
  const hasPayloadToExport = Boolean(getCurrentRawPayloadHex());
  const hasHttpBody = Boolean(getCurrentHttpBodyHex());
  convertContextButtons.exportPacket.style.display = hasPacketToExport
    ? "block"
    : "none";
  convertContextButtons.exportPayload.style.display = hasPayloadToExport
    ? "block"
    : "none";
  convertContextButtons.httpFileSave.style.display = hasHttpBody
    ? "block"
    : "none";
  convertContextButtons.httpFileLoad.style.display = hasHttpBody
    ? "block"
    : "none";
  convertContextButtons.httpFilePreview.style.display = hasHttpBody
    ? "block"
    : "none";

  ["hex", "binary", "base64", "decimal", "ascii"].forEach((format) => {
    convertContextButtons[format].style.display = formats.includes(format)
      ? "block"
      : "none";
  });
  convertContextButtons.copyHex.style.display = isHexViewTarget
    ? "block"
    : "none";
  convertContextButtons.copyAscii.style.display = isHexViewTarget
    ? "block"
    : "none";
  convertContextButtons.copyRaw.style.display = isHexViewTarget
    ? "block"
    : "none";
  convertContextButtons.copyCookieJar.style.display = cookieJarText
    ? "block"
    : "none";
  convertContextButtons.saveCookieJar.style.display = cookieJarText
    ? "block"
    : "none";
  convertContextButtons.loadPayload.style.display = hasPayloadToExport
    ? "block"
    : "none";
  convertContextButtons.filterIp.style.display = filterQueries.ip
    ? "block"
    : "none";
  convertContextButtons.filterPort.style.display = filterQueries.port
    ? "block"
    : "none";
  convertContextButtons.filterMac.style.display = filterQueries.mac
    ? "block"
    : "none";
  convertContextButtons.filterProtocol.style.display = filterQueries.protocol
    ? "block"
    : "none";
  convertContextButtons.filterMime.style.display = filterQueries.mime
    ? "block"
    : "none";
  convertContextButtons.filterOrIp.style.display = filterQueries.ip
    ? "block"
    : "none";
  convertContextButtons.filterOrPort.style.display = filterQueries.port
    ? "block"
    : "none";
  convertContextButtons.filterOrMac.style.display = filterQueries.mac
    ? "block"
    : "none";
  convertContextButtons.filterOrProtocol.style.display = filterQueries.protocol
    ? "block"
    : "none";
  convertContextButtons.filterOrMime.style.display = filterQueries.mime
    ? "block"
    : "none";
  convertContextButtons.filterNotIp.style.display = filterQueries.ip
    ? "block"
    : "none";
  convertContextButtons.filterNotPort.style.display = filterQueries.port
    ? "block"
    : "none";
  convertContextButtons.filterNotMac.style.display = filterQueries.mac
    ? "block"
    : "none";
  convertContextButtons.filterNotProtocol.style.display = filterQueries.protocol
    ? "block"
    : "none";
  convertContextButtons.filterNotMime.style.display = filterQueries.mime
    ? "block"
    : "none";
  convertContextButtons.filterParenOpen.style.display = "block";
  convertContextButtons.filterParenClose.style.display = "block";
  convertContextButtons.filterParenWrap.style.display = "block";
  convertContextButtons.filterClearIp.style.display = filterQueries.ip
    ? "block"
    : "none";
  convertContextButtons.filterClearPort.style.display = filterQueries.port
    ? "block"
    : "none";
  convertContextButtons.filterClearMac.style.display = filterQueries.mac
    ? "block"
    : "none";
  convertContextButtons.filterClearProtocol.style.display =
    filterQueries.protocol ? "block" : "none";
  convertContextButtons.filterClearMime.style.display = filterQueries.mime
    ? "block"
    : "none";
  const hasCookieActions = Boolean(cookieJarText);
  const hasCopyActions = showCopySelection || isHexViewTarget || hasCookieActions;
  const hasClipboardActions = hasCopyActions || showPaste;
  const hasGeneralActions = hasClipboardActions;
  const hasDataTypeActions = formats.length > 0 || hasPayloadToExport;
  const hasFilterActions = Object.values(filterQueries).some(Boolean);
  const hasKeystoreActions = showCopySelection || Boolean(sourceText);
  const hasExportActions =
    showSaveJson || hasPacketToExport || hasPayloadToExport || hasCookieActions;
  convertContextSubmenus.copy.style.display = hasCopyActions ? "block" : "none";
  convertContextSubmenus.convert.style.display = hasDataTypeActions
    ? "block"
    : "none";
  convertContextSubmenus.filter.style.display = hasFilterActions
    ? "block"
    : "none";
  convertContextSubmenus.filterAnd.style.display = hasFilterActions
    ? "block"
    : "none";
  convertContextSubmenus.filterOr.style.display = hasFilterActions
    ? "block"
    : "none";
  convertContextSubmenus.filterNot.style.display = hasFilterActions
    ? "block"
    : "none";
  convertContextSubmenus.filterParentheses.style.display = hasFilterActions
    ? "block"
    : "none";
  convertContextSubmenus.filterClear.style.display = hasFilterActions
    ? "block"
    : "none";
  convertContextSubmenus.keystore.style.display = hasKeystoreActions
    ? "block"
    : "none";
  convertContextSubmenus.keystorePassword.style.display = hasKeystoreActions
    ? "block"
    : "none";
  convertContextSubmenus.keystoreKey.style.display = hasKeystoreActions
    ? "block"
    : "none";
  convertContextSubmenus.keystoreCert.style.display = hasKeystoreActions
    ? "block"
    : "none";
  convertContextSubmenus.keystoreCookie.style.display = hasKeystoreActions
    ? "block"
    : "none";
  convertContextSubmenus.export.style.display = hasExportActions
    ? "block"
    : "none";
  convertContextSubmenus.httpFile.style.display = hasHttpBody ? "block" : "none";
  if (
    !hasGeneralActions &&
    !hasDataTypeActions &&
    !isHexViewTarget &&
    !hasFilterActions &&
    !hasCookieActions &&
    !hasKeystoreActions &&
    !hasExportActions &&
    !hasHttpBody
  ) {
    hideConvertContextMenu();
    return;
  }
  convertContextDividerEl.style.display =
    hasClipboardActions &&
    (hasDataTypeActions ||
      isHexViewTarget ||
      hasFilterActions ||
      hasExportActions ||
      hasHttpBody)
      ? "block"
      : "none";
  convertContextSaveDividerEl.style.display =
    (hasExportActions || hasHttpBody) &&
    (hasClipboardActions ||
      hasDataTypeActions ||
      isHexViewTarget ||
      hasFilterActions ||
      hasCookieActions ||
      hasKeystoreActions)
      ? "block"
      : "none";

  convertContextMenuEl.hidden = false;
  const menuWidth = convertContextMenuEl.offsetWidth;
  const menuHeight = convertContextMenuEl.offsetHeight;
  const boundedX = Math.max(8, Math.min(x, window.innerWidth - menuWidth - 8));
  const boundedY = Math.max(
    8,
    Math.min(y, window.innerHeight - menuHeight - 8),
  );
  convertContextMenuEl.style.left = `${boundedX}px`;
  convertContextMenuEl.style.top = `${boundedY}px`;
  updateConvertContextSubmenuPositions();
}

function loadContextValueIntoDataTools(format) {
  if (!activeContextConversionText) return;
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  inputEl.value = activeContextConversionText;
  formatEl.value = format;
  showDataTools();
  runDataToolsConversion();
  hideConvertContextMenu();
  writeLogEntry(`Context conversion loaded format=${format}`);
}

function loadRawPayloadIntoDataToolsFromContextMenu() {
  const payloadHex = getCurrentRawPayloadHex();
  hideConvertContextMenu();
  if (!payloadHex) {
    statusUpdate("Status: No raw payload available to load");
    return;
  }
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  inputEl.value = payloadHex;
  formatEl.value = "hex";
  showDataTools();
  runDataToolsConversion();
  writeLogEntry("Context conversion loaded raw payload into Conv tab");
}

function getActivePacketCursor() {
  return Number.isInteger(activePacketCursor) && activePacketCursor >= 0
    ? activePacketCursor
    : null;
}

function setActivePacketCursor(nextIndex) {
  const parsedIndex = Number.parseInt(nextIndex, 10);
  activePacketCursor =
    Number.isNaN(parsedIndex) || parsedIndex < 0 ? null : parsedIndex;
  return activePacketCursor;
}

function getCurrentRawPayloadHex() {
  const packetCursor = getActivePacketCursor();
  const payloadHex =
    packetsForHost?.[packetCursor]?.["Packet Info"]?.["Raw data"]?.[
      "Payload"
    ]?.["Hex Encoded"];
  return typeof payloadHex === "string" ? payloadHex : "";
}

function getCurrentHttpData() {
  const cursor = getActivePacketCursor();
  if (cursor === null) return null;
  const packetInfo = packetsForHost?.[cursor]?.["Packet Info"];
  if (!packetInfo) return null;
  const protocol = packetInfo["Protocol"] || "TCP";
  return packetInfo[protocol]?.["HTTP"] || null;
}

function extractHttpBodyHex(payloadHex) {
  if (!payloadHex) return "";
  // Locate the HTTP header/body separator in hex space.
  // RFC 7230 mandates \r\n\r\n which encodes as "0d0a0d0a".
  const lower = payloadHex.toLowerCase();
  const sepIdx = lower.indexOf("0d0a0d0a");
  if (sepIdx === -1) return "";
  const bodyStart = sepIdx + 8; // skip past the 4-byte CRLFCRLF separator
  if (bodyStart >= payloadHex.length) return "";
  return payloadHex.slice(bodyStart);
}

function getCurrentHttpBodyHex() {
  return extractHttpBodyHex(getCurrentRawPayloadHex());
}

function getCurrentPacketForExport(packetSet, packetIndex) {
  if (!Number.isInteger(packetIndex) || packetIndex < 0) {
    return null;
  }
  return packetSet?.[packetIndex] || null;
}

async function copyTextToClipboard(text, label) {
  if (!text) {
    statusUpdate(`Status: No ${label.toLowerCase()} available to copy`);
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const fallbackInput = document.createElement("textarea");
    fallbackInput.value = text;
    fallbackInput.style.position = "fixed";
    fallbackInput.style.left = "-9999px";
    document.body.appendChild(fallbackInput);
    fallbackInput.focus();
    fallbackInput.select();
    document.execCommand("copy");
    document.body.removeChild(fallbackInput);
  }

  statusUpdate(`Status: Copied ${label} to clipboard`);
  writeLogEntry(`Copied ${label} length=${text.length}`);
}

function getAsciiPreviewForHexOffset(payloadHex, byteIndex) {
  if (byteIndex < 0) return "";
  const decodedAscii = hexToAscii(payloadHex);
  let printableSequence = "";
  for (let i = byteIndex; i < decodedAscii.length; i++) {
    const charCode = decodedAscii.charCodeAt(i);
    if (!isPrintable(charCode)) break;
    printableSequence += decodedAscii[i];
  }
  if (printableSequence.length > 0) return printableSequence;
  const fallbackCode = decodedAscii.charCodeAt(byteIndex);
  if (Number.isNaN(fallbackCode)) return "";
  return isPrintable(fallbackCode) ? decodedAscii[byteIndex] : ".";
}

async function copyHexFromContext() {
  const payloadHex = getCurrentRawPayloadHex();
  const hexValue = activeContextTarget?.classList?.contains("griditem")
    ? activeContextTarget.textContent.trim()
    : payloadHex;
  await copyTextToClipboard(hexValue, "Hex");
  hideConvertContextMenu();
}

async function copyAsciiFromContext() {
  const payloadHex = getCurrentRawPayloadHex();
  const byteIndex = Number.parseInt(
    activeContextTarget?.dataset?.byteIndex ?? "-1",
    10,
  );
  const fullPayloadAscii = payloadHex
    ? bytesToPrintableAscii(parseDataToolsInput("hex", payloadHex))
    : "";
  const asciiValue = activeContextTarget?.classList?.contains("griditem")
    ? getAsciiPreviewForHexOffset(payloadHex, byteIndex)
    : fullPayloadAscii;
  await copyTextToClipboard(asciiValue, "ASCII");
  hideConvertContextMenu();
}

async function copyRawPayloadFromContext() {
  await copyTextToClipboard(getCurrentRawPayloadHex(), "Raw payload");
  hideConvertContextMenu();
}

function copySelectedTextFromContextMenu() {
  const selectedText = getTrimmedSelectionText();
  hideConvertContextMenu();
  if (!selectedText) {
    statusUpdate("Status: No text selected to copy");
    return;
  }
  navigator.clipboard
    .writeText(selectedText)
    .then(() => {
      statusUpdate("Status: Copied selected text to clipboard");
      writeLogEntry(`Copied selected text length=${selectedText.length}`);
    })
    .catch((error) => {
      console.error("Copy failed:", error);
      statusUpdate("Status: Copy failed – clipboard access denied");
    });
}

async function copyCookieJarFromContextMenu() {
  const cookieJarText = activeContextCookieJarText;
  hideConvertContextMenu();
  await copyTextToClipboard(cookieJarText, "Cookie Jar");
}

function pasteTextFromContextMenu() {
  const pasteTarget = activeContextPasteTarget;
  hideConvertContextMenu();
  if (!pasteTarget) {
    statusUpdate("Status: Paste unavailable for this target");
    return;
  }
  navigator.clipboard
    .readText()
    .then((text) => {
      if (
        pasteTarget.tagName === "INPUT" ||
        pasteTarget.tagName === "TEXTAREA"
      ) {
        const hasSelectionRange =
          typeof pasteTarget.selectionStart === "number" &&
          typeof pasteTarget.selectionEnd === "number";
        const start = hasSelectionRange
          ? pasteTarget.selectionStart
          : pasteTarget.value.length;
        const end = hasSelectionRange
          ? pasteTarget.selectionEnd
          : pasteTarget.value.length;
        const current = pasteTarget.value;
        pasteTarget.value =
          current.substring(0, start) + text + current.substring(end);
        if (hasSelectionRange) {
          pasteTarget.selectionStart = pasteTarget.selectionEnd =
            start + text.length;
        }
        pasteTarget.dispatchEvent(new Event("input", { bubbles: true }));
        return;
      }

      if (pasteTarget.isContentEditable) {
        pasteTarget.focus();
        const selection = window.getSelection();
        if (selection && selection.rangeCount > 0) {
          const range = selection.getRangeAt(0);
          range.deleteContents();
          const textNode = document.createTextNode(text);
          range.insertNode(textNode);
          range.setStartAfter(textNode);
          range.setEndAfter(textNode);
          selection.removeAllRanges();
          selection.addRange(range);
        } else {
          pasteTarget.textContent = (pasteTarget.textContent || "") + text;
        }
        pasteTarget.dispatchEvent(new Event("input", { bubbles: true }));
      }
    })
    .catch((error) => {
      console.error("Paste failed:", error);
      statusUpdate("Status: Paste failed – clipboard access denied");
    });
}

function saveJsonFromContextMenu() {
  hideConvertContextMenu();
  void persistSessionToDisk("context-menu");
}

function exportCurrentPacketFromContextMenu() {
  hideConvertContextMenu();
  const currentPacket = getCurrentPacketForExport(
    packetsForHost,
    getActivePacketCursor(),
  );
  if (!currentPacket) {
    statusUpdate("Status: No packet selected to export");
    return;
  }
  window.saveapi.savePacket(currentPacket).then((result) => {
    if (result.canceled) {
      statusUpdate("Status: Export cancelled");
    } else if (result.success) {
      statusUpdate("Status: Packet exported successfully");
      writeLogEntry("Context menu packet export completed");
    } else {
      const errorMessage =
        result && typeof result === "object" && "error" in result
          ? result.error
          : "unknown";
      doError("Packet export failed");
      logErrorEntry("export-packet", errorMessage || "unknown");
      statusUpdate(
        "Status: Packet export failed – " + (errorMessage || "unknown error"),
      );
      console.error("Packet export failed:", errorMessage);
    }
  });
}

function exportCurrentPayloadFromContextMenu() {
  hideConvertContextMenu();
  const payloadHex = getCurrentRawPayloadHex();
  if (!payloadHex) {
    statusUpdate("Status: No payload available to export");
    return;
  }
  window.saveapi.savePayload(payloadHex).then((result) => {
    if (result.canceled) {
      statusUpdate("Status: Export cancelled");
    } else if (result.success) {
      statusUpdate("Status: Payload exported successfully");
      writeLogEntry("Context menu payload export completed");
    } else {
      const errorMessage =
        result && typeof result === "object" && "error" in result
          ? result.error
          : "unknown";
      doError("Payload export failed");
      logErrorEntry("export-payload", errorMessage || "unknown");
      statusUpdate(
        "Status: Payload export failed – " + (errorMessage || "unknown error"),
      );
      console.error("Payload export failed:", errorMessage);
    }
  });
}

function saveCookieJarFromContextMenu() {
  const cookieJarText = activeContextCookieJarText;
  hideConvertContextMenu();
  if (!cookieJarText) {
    statusUpdate("Status: No cookie jar available to save");
    return;
  }
  window.saveapi.saveCookieJar(cookieJarText).then((result) => {
    if (result.canceled) {
      statusUpdate("Status: Save cancelled");
    } else if (result.success) {
      statusUpdate("Status: Cookie jar saved successfully");
      writeLogEntry("Context menu cookie jar save completed");
    } else {
      const errorMessage =
        result && typeof result === "object" && "error" in result
          ? result.error
          : "unknown";
      doError("Cookie jar save failed");
      logErrorEntry("save-cookie-jar", errorMessage || "unknown");
      statusUpdate(
        "Status: Cookie jar save failed – " + (errorMessage || "unknown error"),
      );
      console.error("Cookie jar save failed:", errorMessage);
    }
  });
}

function getHttpContentTypeForCurrentPacket() {
  const httpData = getCurrentHttpData();
  return (httpData && httpData["Content-Type"]) || "application/octet-stream";
}

function saveHttpBodyFromContextMenu() {
  hideConvertContextMenu();
  const bodyHex = getCurrentHttpBodyHex();
  if (!bodyHex) {
    statusUpdate("Status: No HTTP body available to save");
    return;
  }
  const contentType = getHttpContentTypeForCurrentPacket();
  window.saveapi.saveHttpBody(bodyHex, contentType).then((result) => {
    if (result.canceled) {
      statusUpdate("Status: Save cancelled");
    } else if (result.success) {
      statusUpdate("Status: HTTP body saved successfully");
      writeLogEntry("Context menu HTTP body save completed");
    } else {
      const errorMessage =
        result && typeof result === "object" && "error" in result
          ? result.error
          : "unknown";
      doError("HTTP body save failed");
      logErrorEntry("http-body-save", errorMessage || "unknown");
      statusUpdate(
        "Status: HTTP body save failed – " + (errorMessage || "unknown error"),
      );
      console.error("HTTP body save failed:", errorMessage);
    }
  });
}

function loadHttpBodyIntoConvTabFromContextMenu() {
  const bodyHex = getCurrentHttpBodyHex();
  hideConvertContextMenu();
  if (!bodyHex) {
    statusUpdate("Status: No HTTP body available to load");
    return;
  }
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  inputEl.value = bodyHex;
  formatEl.value = "hex";
  showDataTools();
  runDataToolsConversion();
  writeLogEntry("Context menu loaded HTTP body into Conv tab");
}

function previewHttpBodyInBrowserFromContextMenu() {
  hideConvertContextMenu();
  const bodyHex = getCurrentHttpBodyHex();
  if (!bodyHex) {
    statusUpdate("Status: No HTTP body available to preview");
    return;
  }
  const contentType = getHttpContentTypeForCurrentPacket();
  window.previewapi.previewHttpBody(bodyHex, contentType).then((result) => {
    if (result.success) {
      statusUpdate("Status: HTTP body opened in browser");
      writeLogEntry("Context menu HTTP body browser preview launched");
    } else {
      const errorMessage =
        result && typeof result === "object" && "error" in result
          ? result.error
          : "unknown";
      doError("HTTP body preview failed");
      logErrorEntry("http-body-preview", errorMessage || "unknown");
      statusUpdate(
        "Status: HTTP body preview failed – " + (errorMessage || "unknown error"),
      );
      console.error("HTTP body preview failed:", errorMessage);
    }
  });
}

function appendFilterQueryFromContextMenu(
  type,
  joinOperator = "&&",
  negate = false,
) {
  const query = activeContextFilterQueries[type];
  hideConvertContextMenu();
  if (!query) {
    statusUpdate("Status: No matching filter value found for this selection");
    return;
  }
  if (joinOperator !== "&&" && joinOperator !== "||") {
    statusUpdate("Status: Could not add filter query — please try again");
    return;
  }
  const queryToInsert = negate ? `!(${query})` : query;
  const existingQuery = filterInputEl.value.trim();
  const wrappedQuery = negate
    ? queryToInsert
    : queryToInsert.includes("||") || queryToInsert.includes("&&")
      ? `(${queryToInsert})`
      : queryToInsert;
  if (!existingQuery) {
    filterInputEl.value = queryToInsert;
  } else if (/(?:\|\||&&)\s*$/.test(existingQuery)) {
    filterInputEl.value = `${existingQuery} ${wrappedQuery}`;
  } else {
    filterInputEl.value = `${existingQuery} ${joinOperator} ${wrappedQuery}`;
  }
  syncFilterHighlight();
  filterInputEl.focus();
  statusUpdate("Status: Filter query populated — press Enter to apply");
  writeLogEntry(
    `Context menu filter populated type=${type} negated=${negate} query="${filterInputEl.value}"`,
  );
}

function clearAndFilterQueryFromContextMenu(type) {
  const query = activeContextFilterQueries[type];
  hideConvertContextMenu();
  if (!query) {
    statusUpdate("Status: No matching filter value found for this selection");
    return;
  }
  filterInputEl.value = query;
  syncFilterHighlight();
  filterInputEl.focus();
  statusUpdate("Status: Filter query populated — press Enter to apply");
  writeLogEntry(
    `Context menu filter cleared and populated type=${type} query="${filterInputEl.value}"`,
  );
}

function appendParenthesisTokenFromContextMenu(token) {
  hideConvertContextMenu();
  if (token !== "(" && token !== ")") {
    statusUpdate("Status: Could not append parenthesis — please try again");
    return;
  }
  filterInputEl.value = `${filterInputEl.value}${token}`;
  syncFilterHighlight();
  filterInputEl.focus();
  statusUpdate("Status: Filter query updated — press Enter to apply");
  writeLogEntry(
    `Context menu filter appended token="${token}" query="${filterInputEl.value}"`,
  );
}

function wrapCurrentFilterWithParenthesesFromContextMenu() {
  hideConvertContextMenu();
  const existingQuery = filterInputEl.value.trim();
  if (!existingQuery) {
    statusUpdate("Status: No filter query available to wrap");
    return;
  }
  filterInputEl.value = `(${existingQuery})`;
  syncFilterHighlight();
  filterInputEl.focus();
  statusUpdate("Status: Filter query updated — press Enter to apply");
  writeLogEntry(`Context menu filter wrapped query="${filterInputEl.value}"`);
}

document.getElementById("close-btn").addEventListener("click", () => {
  void requestApplicationClose();
});

// Show host data when data button is clicked
document.getElementById("data-btn").addEventListener("click", function () {
  if (!isFileLoaded) {
    doError("Please upload a JSON file before accessing host data.");
    return;
  }
  initializeDataView();
});

// Show capture stats when stats button is clicked
document.getElementById("stats-btn").addEventListener("click", function () {
  if (!isFileLoaded) {
    doError("Please upload a JSON file before accessing packet statistics.");
    return;
  }
  showStats();
});

// Show data conversion tools when data tools button is clicked
document
  .getElementById("data-tools-btn")
  .addEventListener("click", function () {
    showDataTools();
  });

document.getElementById("crypt-btn").addEventListener("click", function () {
  if (!isFileLoaded) {
    doError("Please upload a JSON file before accessing crypt tools.");
    return;
  }
  showCryptWorkspace();
});

document.getElementById("keystore-btn").addEventListener("click", async function () {
  if (!isFileLoaded) {
    doError("Please upload a JSON file before accessing the keystore.");
    return;
  }
  const unlocked = await keystorePanel.unlockPersistentKeystoreAndLoad();
  if (!unlocked) return;
  keystorePanel.showKeystoreWorkspace();
});
document
  .getElementById("crypt-keystore-unlock-confirm-btn")
  .addEventListener("click", keystorePanel.submitKeystoreUnlockDialog);
document
  .getElementById("crypt-keystore-unlock-cancel-btn")
  .addEventListener("click", () => keystorePanel.resolveKeystoreUnlockPassword(null));
document
  .getElementById("crypt-keystore-unlock-password")
  .addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    keystorePanel.submitKeystoreUnlockDialog();
  });
document
  .getElementById("crypt-keystore-unlock-password-confirm")
  .addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    keystorePanel.submitKeystoreUnlockDialog();
  });

// Show packet list when list button is clicked
document.getElementById("list-btn").addEventListener("click", function () {
  if (!isFileLoaded) {
    doError("Please upload a JSON file before accessing the packet list.");
    return;
  }
  showPacketList();
});

document
  .getElementById("conv-subtab-conversions")
  .addEventListener("click", () => setConvSubtab(CONV_CONVERSIONS_SUBTAB));
document
  .getElementById("conv-subtab-hashes")
  .addEventListener("click", () => setConvSubtab(CONV_HASHES_SUBTAB));
document
  .getElementById("conv-subtab-decodes")
  .addEventListener("click", () => setConvSubtab(CONV_DECODES_SUBTAB));

document
  .getElementById("crypt-subtab-ssl")
  .addEventListener("click", () => setCryptSubtab(CRYPT_SSL_SUBTAB));
document
  .getElementById("crypt-subtab-pgp")
  .addEventListener("click", () => setCryptSubtab(CRYPT_PGP_SUBTAB));
document
  .getElementById("crypt-subtab-openssh")
  .addEventListener("click", () => setCryptSubtab(CRYPT_OPENSSH_SUBTAB));
document.getElementById("crypt-refresh-btn").addEventListener("click", () => {
  refreshCryptEncounteredEntries();
});
document
  .getElementById("crypt-encountered-list")
  .addEventListener("change", function () {
    const selectedIndex = Number(this.value);
    cryptPanel.selectEncounteredEntry(selectedIndex);
  });
document
  .getElementById("crypt-apply-filter-btn")
  .addEventListener("click", applyCryptFilterForActiveEntry);
document
  .getElementById("crypt-load-encountered-cert-btn")
  .addEventListener("click", loadEncounteredCertificateIntoCrypt);

document
  .getElementById("crypt-load-cert-file-btn")
  .addEventListener("click", () =>
    document.getElementById("crypt-cert-file-input").click(),
  );
document
  .getElementById("crypt-cert-file-input")
  .addEventListener("change", function () {
    readCryptTextFile(this, applyCryptCertificateText);
    this.value = "";
  });
document
  .getElementById("crypt-use-cert-input-btn")
  .addEventListener("click", () =>
    applyCryptCertificateText(
      document.getElementById("crypt-cert-input").value,
      "pasted text",
    ),
  );
document.getElementById("crypt-clear-cert-btn").addEventListener("click", () => {
  applyCryptCertificateText("", "cleared");
});

document
  .getElementById("crypt-load-key-file-btn")
  .addEventListener("click", () =>
    document.getElementById("crypt-key-file-input").click(),
  );
document
  .getElementById("crypt-key-file-input")
  .addEventListener("change", function () {
    readCryptTextFile(this, applyCryptPrivateKeyText);
    this.value = "";
  });
document
  .getElementById("crypt-use-key-input-btn")
  .addEventListener("click", () =>
    applyCryptPrivateKeyText(
      document.getElementById("crypt-key-input").value,
      "pasted text",
    ),
  );
document.getElementById("crypt-clear-key-btn").addEventListener("click", () => {
  applyCryptPrivateKeyText("", "cleared");
});

document
  .getElementById("crypt-save-cert-keystore-btn")
  .addEventListener("click", () => {
    void keystorePanel.addCryptKeystoreEntry({
      type: "certificate",
      label: document.getElementById("crypt-keystore-label").value,
      source: "crypt-certificate-loader",
      content: document.getElementById("crypt-cert-input").value,
      summary: getFirstLineOrFallback(
        "crypt-cert-preview",
        "Certificate from loader",
      ),
    });
  });
document
  .getElementById("crypt-save-key-keystore-btn")
  .addEventListener("click", () => {
    void keystorePanel.addCryptKeystoreEntry({
      type: "private-key",
      label: document.getElementById("crypt-keystore-label").value,
      source: "crypt-private-key-loader",
      content: document.getElementById("crypt-key-input").value,
      summary: getFirstLineOrFallback(
        "crypt-key-preview",
        "Private key from loader",
      ),
    });
  });
document
  .getElementById("crypt-save-secret-keystore-btn")
  .addEventListener("click", () => {
    void keystorePanel.addCryptKeystoreEntry({
      type: "secret",
      label: document.getElementById("crypt-keystore-label").value,
      source: "crypt-secret-input",
      content: document.getElementById("crypt-credential-input").value,
      summary: "Manual secret/credential entry",
    });
  });
document
  .getElementById("crypt-keystore-mode")
  .addEventListener("change", function () {
    const selectedMode = String(this.value || CRYPT_KEYSTORE_MODE_SESSION);
    keystorePanel.setActiveMode(
      selectedMode === CRYPT_KEYSTORE_MODE_PERSISTENT
        ? CRYPT_KEYSTORE_MODE_PERSISTENT
        : CRYPT_KEYSTORE_MODE_SESSION,
    );
  });
document
  .getElementById("crypt-keystore-list")
  .addEventListener("change", function () {
    const activeEntries = keystorePanel.getActiveCryptKeystoreEntries();
    const selectedIndex = Number(this.value);
    if (!Number.isFinite(selectedIndex) || !activeEntries[selectedIndex]) {
      return;
    }
    keystorePanel.renderCryptKeystoreDetails(activeEntries[selectedIndex]);
  });
document
  .getElementById("crypt-load-keystore-entry-btn")
  .addEventListener("click", () => {
    void keystorePanel.loadSelectedCryptKeystoreEntry();
  });
document
  .getElementById("crypt-send-to-persistent-btn")
  .addEventListener("click", () => {
    void keystorePanel.sendSelectedSessionEntryToPersistent();
  });
document
  .getElementById("crypt-delete-keystore-entry-btn")
  .addEventListener("click", () => {
    void keystorePanel.deleteSelectedCryptKeystoreEntry();
  });

document
  .getElementById("data-tools-convert-btn")
  .addEventListener("click", runDataToolsConversion);
document
  .getElementById("data-tools-clear-btn")
  .addEventListener("click", () => {
    document.getElementById("data-tools-input").value = "";
    document.getElementById("data-tools-error").textContent = "";
    resetDataToolsOutputs();
  });
document
  .getElementById("data-tools-proto-select")
  .addEventListener("change", () => {
    const inputEl = document.getElementById("data-tools-input");
    const formatEl = document.getElementById("data-tools-format");
    if (!inputEl.value.trim()) return;
    try {
      const bytes = parseDataToolsInput(formatEl.value, inputEl.value);
      runProtoDecoder(bytes);
    } catch {
      // ignore parse errors; the error will have been shown on convert
    }
  });
convertContextButtons.hex.addEventListener("click", () =>
  loadContextValueIntoDataTools("hex"),
);
convertContextButtons.binary.addEventListener("click", () =>
  loadContextValueIntoDataTools("binary"),
);
convertContextButtons.base64.addEventListener("click", () =>
  loadContextValueIntoDataTools("base64"),
);
convertContextButtons.decimal.addEventListener("click", () =>
  loadContextValueIntoDataTools("decimal"),
);
convertContextButtons.ascii.addEventListener("click", () =>
  loadContextValueIntoDataTools("ascii"),
);
convertContextButtons.loadPayload.addEventListener("click", () => {
  loadRawPayloadIntoDataToolsFromContextMenu();
});
convertContextButtons.copyHex.addEventListener("click", () => {
  copyHexFromContext();
});
convertContextButtons.copyAscii.addEventListener("click", () => {
  copyAsciiFromContext();
});
convertContextButtons.copyRaw.addEventListener("click", () => {
  copyRawPayloadFromContext();
});
convertContextButtons.filterIp.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("ip", "&&");
});
convertContextButtons.filterPort.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("port", "&&");
});
convertContextButtons.filterMac.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("mac", "&&");
});
convertContextButtons.filterProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("protocol", "&&");
});
convertContextButtons.filterMime.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("mime", "&&");
});
convertContextButtons.filterOrIp.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("ip", "||");
});
convertContextButtons.filterOrPort.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("port", "||");
});
convertContextButtons.filterOrMac.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("mac", "||");
});
convertContextButtons.filterOrProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("protocol", "||");
});
convertContextButtons.filterOrMime.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("mime", "||");
});
convertContextButtons.filterNotIp.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("ip", "&&", true);
});
convertContextButtons.filterNotPort.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("port", "&&", true);
});
convertContextButtons.filterNotMac.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("mac", "&&", true);
});
convertContextButtons.filterNotProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("protocol", "&&", true);
});
convertContextButtons.filterNotMime.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("mime", "&&", true);
});
convertContextButtons.filterParenOpen.addEventListener("click", () => {
  appendParenthesisTokenFromContextMenu("(");
});
convertContextButtons.filterParenClose.addEventListener("click", () => {
  appendParenthesisTokenFromContextMenu(")");
});
convertContextButtons.filterParenWrap.addEventListener("click", () => {
  wrapCurrentFilterWithParenthesesFromContextMenu();
});
convertContextButtons.filterClearIp.addEventListener("click", () => {
  clearAndFilterQueryFromContextMenu("ip");
});
convertContextButtons.filterClearPort.addEventListener("click", () => {
  clearAndFilterQueryFromContextMenu("port");
});
convertContextButtons.filterClearMac.addEventListener("click", () => {
  clearAndFilterQueryFromContextMenu("mac");
});
convertContextButtons.filterClearProtocol.addEventListener("click", () => {
  clearAndFilterQueryFromContextMenu("protocol");
});
convertContextButtons.filterClearMime.addEventListener("click", () => {
  clearAndFilterQueryFromContextMenu("mime");
});
convertContextButtons.copy.addEventListener(
  "click",
  copySelectedTextFromContextMenu,
);
convertContextButtons.copyCookieJar.addEventListener(
  "click",
  copyCookieJarFromContextMenu,
);
convertContextButtons.paste.addEventListener("click", pasteTextFromContextMenu);
convertContextButtons.keystorePasswordSession.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu("password", CRYPT_KEYSTORE_MODE_SESSION);
});
convertContextButtons.keystorePasswordPersistent.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu("password", CRYPT_KEYSTORE_MODE_PERSISTENT);
});
convertContextButtons.keystoreKeySession.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu("key", CRYPT_KEYSTORE_MODE_SESSION);
});
convertContextButtons.keystoreKeyPersistent.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu("key", CRYPT_KEYSTORE_MODE_PERSISTENT);
});
convertContextButtons.keystoreCertSession.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu("cert", CRYPT_KEYSTORE_MODE_SESSION);
});
convertContextButtons.keystoreCertPersistent.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu("cert", CRYPT_KEYSTORE_MODE_PERSISTENT);
});
convertContextButtons.keystoreCookieSession.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu("cookie", CRYPT_KEYSTORE_MODE_SESSION);
});
convertContextButtons.keystoreCookiePersistent.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu("cookie", CRYPT_KEYSTORE_MODE_PERSISTENT);
});
convertContextButtons.saveJson.addEventListener(
  "click",
  saveJsonFromContextMenu,
);
convertContextButtons.exportPacket.addEventListener(
  "click",
  exportCurrentPacketFromContextMenu,
);
convertContextButtons.exportPayload.addEventListener(
  "click",
  exportCurrentPayloadFromContextMenu,
);
convertContextButtons.saveCookieJar.addEventListener(
  "click",
  saveCookieJarFromContextMenu,
);
convertContextButtons.httpFileSave.addEventListener(
  "click",
  saveHttpBodyFromContextMenu,
);
convertContextButtons.httpFileLoad.addEventListener(
  "click",
  loadHttpBodyIntoConvTabFromContextMenu,
);
convertContextButtons.httpFilePreview.addEventListener(
  "click",
  previewHttpBodyInBrowserFromContextMenu,
);

/**
 * Builds a bidirectional stream filter query for a packet's 4-tuple.
 * Returns a filter string matching packets flowing in either direction
 * between the same endpoints, or an IP-only filter for protocols without ports.
 */
function buildStreamFilterQuery(transport, srcIp, dstIp, srcPort, dstPort) {
  if (!srcIp || !dstIp) return null;
  const tp = (transport || "").toLowerCase();
  const hasPorts =
    (srcPort !== "" && srcPort !== undefined && srcPort !== null) &&
    (dstPort !== "" && dstPort !== undefined && dstPort !== null);
  if (hasPorts && (tp === "tcp" || tp === "udp")) {
    return (
      `(ip.src.addr: ${srcIp} && ip.dst.addr: ${dstIp} && ${tp}.src.port: ${srcPort} && ${tp}.dst.port: ${dstPort})` +
      ` || ` +
      `(ip.src.addr: ${dstIp} && ip.dst.addr: ${srcIp} && ${tp}.src.port: ${dstPort} && ${tp}.dst.port: ${srcPort})`
    );
  }
  return `(ip.src.addr: ${srcIp} && ip.dst.addr: ${dstIp}) || (ip.src.addr: ${dstIp} && ip.dst.addr: ${srcIp})`;
}

/**
 * Builds and shows the packet list tab, displaying all packets grouped by host
 * in a scrollable, selectable table.
 */
function showPacketList() {
  activeMainTab = MAIN_TAB_LIST;
  if (jsonCapture === "") {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
    return;
  }
  statusUpdate("Status: Displaying packet list");
  writeLogEntry("User opened packet list view");

  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("stats_box").style.display = "none";
  document.getElementById("data_tools_box").style.display = "none";
  document.getElementById("crypt_box").style.display = "none";
  document.getElementById("keystore_box").style.display = "none";
  document.getElementById("rightside").style.display = "none";
  const listBox = document.getElementById("list_box");
  listBox.style.display = "flex";

  const content = document.getElementById("list_content");
  const searchEl = document.getElementById("list-search");
  const groupByStreamEl = document.getElementById("list-group-streams");
  const columnDefinitions = [
    { label: "#", key: "idx" },
    { label: "★", key: "isBookmarked" },
    { label: "Stream", key: "streamOrder" },
    { label: "Host", key: "host" },
    { label: "Src IP", key: "srcIp" },
    { label: "Dst IP", key: "dstIp" },
    { label: "Src Port", key: "srcPort" },
    { label: "Dst Port", key: "dstPort" },
    { label: "Transport", key: "transport" },
    { label: "App Protocol", key: "appProto" },
  ];
  const sortState = { key: "idx", direction: "asc" };

  function buildTable(filterText) {
    content.replaceChildren();
    if (!capturedPackets || !capturedPackets["Host"]) {
      content.textContent = "No packet data available.";
      return;
    }

    const hosts = Object.keys(capturedPackets["Host"]).sort();
    const lc = filterText ? filterText.toLowerCase() : "";

    const rows = [];

    const getStreamKey = (packetInfo) => {
      const transportName = packetInfo?.["Protocol"] || "Unknown";
      const transportData = packetInfo?.[transportName] || {};
      const sourceIp = packetInfo?.["IP"]?.["Source IP"] ?? "";
      const destinationIp = packetInfo?.["IP"]?.["Destination IP"] ?? "";
      const sourcePort = transportData?.["Source port"] ?? "";
      const destinationPort = transportData?.["Destination port"] ?? "";

      const endpointA = `${sourceIp}:${sourcePort}`;
      const endpointB = `${destinationIp}:${destinationPort}`;
      const [firstEndpoint, secondEndpoint] = [endpointA, endpointB].sort();
      return `${transportName}|${firstEndpoint}|${secondEndpoint}`;
    };

    for (const host of hosts) {
      const packets = capturedPackets["Host"][host];
      if (!Array.isArray(packets)) continue;

      packets.forEach((pkt, pktIdx) => {
        const pi = pkt?.["Packet Info"];
        const ei = pkt?.["Extra Info"];
        if (!pi) return;

        const idx = pi["Index"] ?? pktIdx + 1;
        const srcIp = pi?.["IP"]?.["Source IP"] ?? "";
        const dstIp = pi?.["IP"]?.["Destination IP"] ?? "";
        const transport = pi["Protocol"] || "TCP";
        const tpData = pi[transport] || null;
        const srcPort = tpData?.["Source port"] ?? "";
        const dstPort = tpData?.["Destination port"] ?? "";
        const netData = ei?.["Traits"]?.["Network Data"];
        const appProto =
          netData?.["Port Protocol"] ?? netData?.["Port Protcol"] ?? "";
        const packetKey = srcIp + ":" + pi["Index"];
        const isBookmarked = bookmarkList.includes(packetKey);
        const streamKey = getStreamKey(pi);

        if (lc) {
          const rowText = [
            host,
            srcIp,
            dstIp,
            String(srcPort),
            String(dstPort),
            transport,
            appProto,
          ]
            .join(" ")
            .toLowerCase();
          if (!rowText.includes(lc)) return;
        }

        rows.push({
          idx,
          host,
          srcIp,
          dstIp,
          srcPort,
          dstPort,
          transport,
          appProto,
          pktIdx,
          pi,
          streamKey,
          isBookmarked,
        });
      });
    }

    const streamOrderMap = new Map();
    let nextStreamOrder = 1;
    rows.forEach((row) => {
      if (!streamOrderMap.has(row.streamKey)) {
        streamOrderMap.set(row.streamKey, nextStreamOrder++);
      }
      row.streamOrder = streamOrderMap.get(row.streamKey);
      row.streamLabel = `S${row.streamOrder}`;
    });

    const activeGroupByStream =
      document.getElementById("list-group-streams")?.checked;
    const sortDirection = sortState.direction === "asc" ? 1 : -1;
    const compareText = (left, right) =>
      String(left ?? "").localeCompare(String(right ?? ""));
    const comparePortValue = (left, right) => {
      const leftNum = Number(left);
      const rightNum = Number(right);
      const leftIsNumber = Number.isFinite(leftNum);
      const rightIsNumber = Number.isFinite(rightNum);
      if (leftIsNumber && rightIsNumber) return leftNum - rightNum;
      return compareText(left, right);
    };

    const compareByColumn = (left, right, columnKey) => {
      switch (columnKey) {
        case "idx":
        case "streamOrder":
          return Number(left[columnKey]) - Number(right[columnKey]);
        case "isBookmarked":
          return Number(left.isBookmarked) - Number(right.isBookmarked);
        case "srcPort":
        case "dstPort":
          return comparePortValue(left[columnKey], right[columnKey]);
        default:
          return compareText(left[columnKey], right[columnKey]);
      }
    };

    rows.sort((left, right) => {
      if (activeGroupByStream && sortState.key !== "streamOrder") {
        const streamDiff = left.streamOrder - right.streamOrder;
        if (streamDiff !== 0) return streamDiff;
      }

      const sortedDiff = compareByColumn(left, right, sortState.key);
      if (sortedDiff !== 0) return sortedDiff * sortDirection;
      return Number(left.idx) - Number(right.idx);
    });

    const table = document.createElement("table");
    table.className = "packet-list-table";

    const thead = document.createElement("thead");
    const headerRow = document.createElement("tr");
    columnDefinitions.forEach((column) => {
      const th = document.createElement("th");
      const isActiveSort = sortState.key === column.key;
      const sortArrow = isActiveSort
        ? sortState.direction === "asc"
          ? " ▲"
          : " ▼"
        : "";
      th.textContent = column.label + sortArrow;
      th.classList.add("packet-list-sortable-header");
      th.tabIndex = 0;
      th.title = `Sort by ${column.label}`;
      th.setAttribute(
        "aria-sort",
        isActiveSort
          ? sortState.direction === "asc"
            ? "ascending"
            : "descending"
          : "none",
      );
      const sortByColumn = () => {
        if (sortState.key === column.key) {
          sortState.direction = sortState.direction === "asc" ? "desc" : "asc";
        } else {
          sortState.key = column.key;
          sortState.direction = "asc";
        }
        buildTable(document.getElementById("list-search")?.value || "");
      };
      th.addEventListener("click", sortByColumn);
      th.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          sortByColumn();
        }
      });
      headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");

    if (rows.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = columnDefinitions.length;
      td.textContent = filterText
        ? "No packets match the filter."
        : "No packets available.";
      td.style.textAlign = "center";
      td.style.padding = "12px";
      tr.appendChild(td);
      tbody.appendChild(tr);
    } else {
      let previousStreamLabel = "";
      rows.forEach((row) => {
        const tr = document.createElement("tr");
        tr.dataset.host = row.host;
        tr.dataset.pktIdx = row.pktIdx;
        tr.dataset.stream = row.streamLabel;

        if (
          activeGroupByStream &&
          previousStreamLabel !== "" &&
          previousStreamLabel !== row.streamLabel
        ) {
          tr.classList.add("packet-list-stream-break");
        }
        previousStreamLabel = row.streamLabel;

        [
          row.idx,
          row.isBookmarked ? "★" : "",
          row.streamLabel,
          row.host,
          row.srcIp,
          row.dstIp,
          row.srcPort,
          row.dstPort,
          row.transport,
          row.appProto,
        ].forEach((val) => {
          const td = document.createElement("td");
          td.textContent = val ?? "";
          tr.appendChild(td);
        });

        tr.addEventListener("mouseenter", () => {
          tr.classList.add("packet-list-hovered");
        });
        tr.addEventListener("mouseleave", () => {
          tr.classList.remove("packet-list-hovered");
        });

        tr.addEventListener("click", () => {
          // Remove previous selection
          tbody
            .querySelectorAll(".packet-list-selected")
            .forEach((r) => r.classList.remove("packet-list-selected"));
          tr.classList.add("packet-list-selected");

          // Set packet context so handlePacketNavigation can locate it in the filtered set
          hostFilterEl.value = row.host;
          document.getElementById("target_hosts").value = row.host;
          currentIp = row.srcIp;
          currentPacketKey = row.srcIp + ":" + row.pi["Index"];
          syncBookmarkDropdown(currentPacketKey);
          writeLogEntry(
            `Packet list row selected host=${row.host} index=${row.pi["Index"]}`,
          );

          // Build a bidirectional stream filter and apply it so only packets
          // from the same stream are loaded into the interface
          const streamFilter = buildStreamFilterQuery(
            row.transport, row.srcIp, row.dstIp, row.srcPort, row.dstPort,
          );
          if (streamFilter) {
            filterInputEl.value = streamFilter;
            syncFilterHighlight();
            runFilterQuery(streamFilter);
            // Keep packetsForHost in sync with the filtered stream so that
            // prev/next navigation and payload access stay within the stream
            packetsForHost = filteredPackets;
          } else {
            // Fallback: load all host packets when a stream filter cannot be built
            packetsForHost = capturedPackets["Host"][row.host];
            index = row.pktIdx;
            setActivePacketCursor(index);
            document.getElementById("list_box").style.display = "none";
            document.getElementById("data_tools_box").style.display = "none";
            document.getElementById("crypt_box").style.display = "none";
            document.getElementById("keystore_box").style.display = "none";
            document.getElementById("packetInfoPane").style.display = "block";
            document.getElementById("packetPayloadPane").style.display = "block";
            document.getElementById("prev-btn").style.display = "block";
            document.getElementById("next-btn").style.display = "block";
            showAllData();
            infoPanel(packetsForHost);
            const hexPayload =
              packetsForHost[index]?.["Packet Info"]?.["Raw data"]?.["Payload"]?.[
                "Hex Encoded"
              ];
            if (hexPayload) popHexGrid(hexPayload);
            populateDataTypes(packetsForHost);
          }

          statusUpdate(
            "Status: Displaying packet " +
              row.pi["Index"] +
              " for host " +
              row.host,
          );
        });

        tbody.appendChild(tr);
      });
    }

    table.appendChild(tbody);
    content.appendChild(table);
  }

  buildTable(searchEl.value);

  // Re-register search listener (replace old one)
  const newSearch = searchEl.cloneNode(true);
  searchEl.parentNode.replaceChild(newSearch, searchEl);
  newSearch.addEventListener("input", () => buildTable(newSearch.value));
  if (groupByStreamEl) {
    const newGroupByStream = groupByStreamEl.cloneNode(true);
    groupByStreamEl.parentNode.replaceChild(newGroupByStream, groupByStreamEl);
    newGroupByStream.addEventListener("change", () =>
      buildTable(newSearch.value),
    );
  }
}

function initializeDataView() {
  activeMainTab = MAIN_TAB_DATA;
  statusUpdate(
    "Status: Displaying packet information for " + hostFilterEl.value,
  );
  if (jsonCapture == "") {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
    doError("No file loaded! Upload one of JSON or PCAP first!");
  } else {
    document.getElementById("prev-btn").style.display = "block";
    document.getElementById("next-btn").style.display = "block";
    document.getElementById("welcome").style.display = "none";
    //hostPacketInfostPacketInfo(hostFilterEl.value);
    if (document.getElementById("host_filter").value == "") {
      document.getElementById("host_filter").value = hostsList[1];
    }

    const hasActiveFilterQuery = filterInputEl.value.trim() !== "";
    const shouldReuseFilteredPackets =
      Array.isArray(filteredPackets) &&
      (hasActiveFilterQuery || packetsForHost === filteredPackets);
    handlePacketNavigation(
      shouldReuseFilteredPackets ? "filtered" : "first-load",
    );
  }
}

// Navigation for previous packet
document.getElementById("prev-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  if (!isFileLoaded) {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
    doError("No file loaded! Upload one of JSON or PCAP first!");
    return;
  }
  if (index > 0) {
    index--;
    setActivePacketCursor(index);

    currentIp = packetsForHost[index]["Packet Info"]["IP"]["Source IP"];
    currentPacketKey =
      currentIp + ":" + packetsForHost[index]["Packet Info"]["Index"];
    syncBookmarkDropdown(currentPacketKey);
    infoPanel(packetsForHost);
    popHexGrid(
      packetsForHost[index]["Packet Info"]["Raw data"]["Payload"][
        "Hex Encoded"
      ],
    );
    populateDataTypes(packetsForHost);
    logCurrentPacketDisplay("prev");
  }
});

// Navigation for next packet
document.getElementById("next-btn").addEventListener("click", function () {
  statusUpdate("Status: Displaying capture analysis summary");
  if (!isFileLoaded) {
    statusUpdate("Status: No JSON file loaded, please upload a file first");
    doError("No file loaded! Upload one of JSON or PCAP first!");
    return;
  }
  if (index < packetsForHost.length - 1) {
    index++;
    setActivePacketCursor(index);
    currentIp = packetsForHost[index]["Packet Info"]["IP"]["Source IP"];
    currentPacketKey =
      currentIp + ":" + packetsForHost[index]["Packet Info"]["Index"];
  }
  syncBookmarkDropdown(currentPacketKey);
  infoPanel(packetsForHost);
  popHexGrid(
    packetsForHost[index]["Packet Info"]["Raw data"]["Payload"]["Hex Encoded"],
  );
  populateDataTypes(packetsForHost);
  logCurrentPacketDisplay("next");
});

// Handle bookmark selection from dropdown
document
  .getElementById("selectBookmark")
  .addEventListener("change", function () {
    const bookmarkHost = document
      .getElementById("selectBookmark")
      .value.split(":")[0];
    index = document.getElementById("selectBookmark").value.split(":")[1];
    setActivePacketCursor(index);
    packetsForHost = capturedPackets["Host"][bookmarkHost];
    activeBookmark["Host"] = bookmarkHost;
    activeBookmark["Packet"] = index;
    hostFilterEl.value = bookmarkHost;
    if (bookmarkHost == undefined || index == undefined) {
      statusUpdate("Invalid bookmark selection, missing host or packet index");
      doError("Invalid bookmark selection, missing host or packet index!");
    } else {
      document.getElementById("target_hosts").value = bookmarkHost;
    }
    handlePacketNavigation("bookmark", activeBookmark);
  });

// Add current packet as a bookmark
document.getElementById("setBookmark").addEventListener("click", function () {
  if (!bookmarkList.includes(currentPacketKey)) {
    if (currentPacketKey != undefined) {
      bookmarkList.push(currentPacketKey);
      document
        .getElementById("selectBookmark")
        .appendChild(new Option(currentPacketKey, currentPacketKey));
      writeLogEntry(`Bookmark added key=${currentPacketKey}`);
    }
  }
});

// Syncs the bookmark dropdown to reflect whether the given packet key is bookmarked
function syncBookmarkDropdown(packetKey) {
  document.getElementById("selectBookmark").value = bookmarkList.includes(
    packetKey,
  )
    ? packetKey
    : "";
}

// function that returns the total number of packets in the entire capture
function totalPacketCount() {
  let totalCount = 0;
  if (capturedPackets["Host"] != undefined) {
    for (const host in capturedPackets["Host"]) {
      totalCount += capturedPackets["Host"][host].length;
    }
  } else {
    return 0;
  }
  return totalCount;
}

/**
 * Returns the packet array index matching a `sourceIp:packetIndex` key.
 */
function findPacketIndexByKey(packetSet, packetKey) {
  if (!Array.isArray(packetSet) || !packetKey || typeof packetKey !== "string") {
    return -1;
  }

  const separatorIndex = packetKey.lastIndexOf(":");
  if (separatorIndex < 0) return -1;

  const sourceIp = packetKey.slice(0, separatorIndex);
  const packetIndexValue = packetKey.slice(separatorIndex + 1);
  return packetSet.findIndex((packet) => {
    const packetInfo = packet?.["Packet Info"];
    if (!packetInfo) return false;
    const candidateSourceIp = packetInfo?.["IP"]?.["Source IP"];
    const candidatePacketIndex = packetInfo?.["Index"];
    return (
      String(candidateSourceIp) === sourceIp &&
      String(candidatePacketIndex) === packetIndexValue
    );
  });
}

/**
 * Handles navigation between capturedPackets (next, prev, activeBookmark, first-load).
 * Updates UI and packet info accordingly.
 */
function handlePacketNavigation(navAction, navBookmark) {
  activeMainTab = MAIN_TAB_DATA;
  const previousPacketKey = currentPacketKey;
  const previousCursor = getActivePacketCursor();
  document.getElementById("loading-container").style.display = "none";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("stats_box").style.display = "none";
  document.getElementById("list_box").style.display = "none";
  document.getElementById("data_tools_box").style.display = "none";
  document.getElementById("crypt_box").style.display = "none";
  document.getElementById("keystore_box").style.display = "none";
  document.getElementById("packetInfoPane").style.display = "block";
  document.getElementById("packetPayloadPane").style.display = "block";
  document.getElementById("welcome").style.display = "none";
  showAllData();

  document.getElementById("total-packets").innerHTML =
    "Total Packets: " + totalPacketCount();
  if (navAction === undefined) {
    handlePacketNavigation("first-load");
  }
  let packetSet = capturedPackets["Host"][hostFilterEl.value];
  if (navAction === "filtered") {
    packetSet = [];
    document.getElementById("filter-returned").textContent =
      "Filtered Packets: " + filteredPackets.length;
    packetSet = filteredPackets;
    writeLogEntry(
      `Filtered packet navigation packets_returned=${packetSet.length}`,
    );
  }

  if (navAction === "bookmark") {
    if (
      navBookmark["Host"] == undefined ||
      navBookmark["Packet"] == undefined
    ) {
      statusUpdate("Status: Invalid bookmark data, reverting to first packet");
      doError("Invalid bookmark data, missing host or packet index!");
      handlePacketNavigation("first-load");
    } else {
      index = navBookmark["Packet"] - 1;
      setActivePacketCursor(index);

      statusUpdate(
        "Navigating to bookmark: " +
          navBookmark["Host"] +
          " packet " +
          navBookmark["Packet"],
      );
      writeLogEntry(
        `Navigating bookmark host=${navBookmark["Host"]} packet=${navBookmark["Packet"]}`,
      );
    }
  } else {
    const packetIndexFromKey = findPacketIndexByKey(packetSet, previousPacketKey);
    if (packetIndexFromKey >= 0) {
      index = packetIndexFromKey;
    } else if (
      Number.isInteger(previousCursor) &&
      previousCursor >= 0 &&
      previousCursor < packetSet?.length
    ) {
      index = previousCursor;
    } else {
      index = 0;
    }
    setActivePacketCursor(index);
  }
  if (!packetSet || packetSet.length === 0) {
    statusUpdate("Status: No packets");
    return;
  }
  if (
    packetSet != undefined &&
    (packetSet.length == 0 || packetSet[0] == undefined)
  ) {
    statusUpdate("Status: No packet information found for this host");
    document.getElementById("main").innerHTML = "Please select a json file!";
  }
  // in the data main secton, this is where we would
  // add the packet info for each packet, for now we just
  // dump the json, we'll format later
  // packetsForHost[index] is an array of all packet info
  // for the current host, we want to be able to navigate
  // through it with next and prev buttons
  if (packetSet == undefined || packetSet[index] == undefined) {
    statusUpdate("Status: No packet information found for this host");
    doError("No packet information found for this host!");
    return;
  } else {
    currentIp = packetSet[index]["Packet Info"]["IP"]["Source IP"];
    currentPacketKey =
      currentIp + ":" + packetSet[index]["Packet Info"]["Index"];
    syncBookmarkDropdown(currentPacketKey);
    console.log(packetSet[index]);
    const hexPayload =
      packetSet[index]["Packet Info"]["Raw data"]["Payload"]["Hex Encoded"];
    infoPanel(packetSet);
    popHexGrid(hexPayload);
    populateDataTypes(packetSet);
    logCurrentPacketDisplay(navAction || "first-load");
  }
}
function populateDataTypes(p) {
  const typesListEl = document.getElementById("types-list");
  typesListEl.textContent = "";
  const mimeTypeEl = document.getElementById("mime-type");
  const charsetEl = document.getElementById("charset");
  const encodingEl = document.getElementById("encoding");
  const languageEl = document.getElementById("language");
  encodingEl.textContent = "";
  languageEl.textContent = "";
  let encodingText = "";
  let languageText = "";
  // packetsForHost = capturedPackets["Host"][hostFilterEl.value];
  packetsForHost = p;
  let charsetText = JSON.parse(
    JSON.stringify(
      packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Charset"],
    ),
  );
  if (
    packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Encoding"] ==
    "Unavailable for high entropy data"
  ) {
    encodingText = JSON.parse(
      JSON.stringify(
        packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Encoding"],
      ),
    );
  } else {
    encodingText = JSON.stringify(
      packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Encoding"][
        "encoding"
      ],
    );
    languageText = JSON.stringify(
      packetsForHost[index]["Extra Info"]["Traits"]["Characters"]["Encoding"][
        "language"
      ],
    );
  }

  const mimeTypeText = JSON.parse(
    JSON.stringify(packetsForHost[index]["Extra Info"]["MIME Type"]),
  );
  let dataItems = JSON.parse(
    JSON.stringify(packetsForHost[index]["Extra Info"]["Data Types"]),
  );
  let sslDetails = "";
  if (
    packetsForHost[index]["Extra Info"]["Traits"]["Server Info"][
      "Encryption Data"
    ] != "N/A" &&
    packetsForHost[index]["Extra Info"]["Traits"]["Server Info"][
      "Encryption Data"
    ] != undefined
  ) {
    sslDetails =
      packetsForHost[index]["Extra Info"]["Traits"]["Server Info"][
        "Encryption Data"
      ]["SSL Version"];
    const protoName =
      packetsForHost[index]["Extra Info"]["Traits"]["Network Data"][
        "Port Protcol"
      ];
    dataItems = [];
    dataItems.push(sslDetails + " encrypted stream");
    dataItems.push(protoName + " protocol data");
  }

  mimeTypeEl.textContent = "MIME type: " + mimeTypeText;
  charsetText = charsetText == "" ? "Unknown" : charsetText;
  encodingText = encodingText == "" ? "Unknown" : encodingText;
  if (encodingText !== undefined) {
    encodingEl.textContent =
      "Payload Encoding: " + encodingText.replace(/"/g, "");
  }
  if (languageText !== undefined) {
    languageEl.textContent =
      "Payload Language: " + languageText.replace(/"/g, "");
  }
  dataItems.forEach((item) => {
    const listItem = document.createElement("li");
    listItem.textContent = item;
    typesListEl.appendChild(listItem);
  });
}
// this takes a char code and returns true if it's
// a printable ASCII character, false otherwise
function isPrintable(charCode) {
  // ASCII printable: 32 (space) to 126 (~)
  return charCode >= 32 && charCode <= 126;
}

// this changes hex to ASCII
function hexToAscii(hex) {
  let decodedAscii = "";
  for (let i = 0; i < hex.length; i += 2) {
    decodedAscii += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return decodedAscii;
}

// trunactes a string to a max length
function truncate(str, maxLength) {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength);
}

// returns a 0 padded hex string of a number with a given length
function decToHex(num, pad) {
  return num.toString(16).padStart(pad, "0");
}

// clears the higlights (its called after the moouse leaves grid)
function clearGridHighlights() {
  document
    .querySelectorAll(".griditem")
    .forEach((el) => el.classList.remove("highlight"));
}

/**
 * Populates the hex grid display with the given hex string.
 */
function popHexGrid(hex) {
  // swap it back to ASCII for the fade box
  const payloadAsciiBox = document.getElementById("payloadascii");
  const decodedAscii = hexToAscii(hex);
  document.getElementById("hexg").textContent = "";
  const hexGridContainer = document.getElementById("hexg");
  const hexPairs = hex.toUpperCase().match(/.{1,2}/g) || [];
  // this block populates the grid with boxes for hex codes
  hexPairs.forEach((hexPair, byteIndex) => {
    const item = document.createElement("div");
    item.classList.add("griditem");
    item.textContent = hexPair;
    item.dataset.byteIndex = String(byteIndex);
    hexGridContainer.appendChild(item);
  });
  function getPrintableSequence(startIndex) {
    let result = "";
    for (let i = startIndex; i < decodedAscii.length; i++) {
      if (!isPrintable(decodedAscii.charCodeAt(i))) break;
      result += String.fromCharCode(decodedAscii.charCodeAt(i));
    }
    return result;
  }
  // Attach event listeners to each grid item
  document.querySelectorAll(".griditem").forEach((item, idx) => {
    item.addEventListener("mouseenter", (e) => {
      //box fade in
      const hexOffsetDisplay = document.getElementById("asciiOffset");
      const asciiTextBox = document.getElementById("asciiText");
      payloadAsciiBox.style.top = e.clientY + 18 + "px";
      payloadAsciiBox.style.left = e.clientX + 18 + "px";
      payloadAsciiBox.classList.add("visible");
      asciiTextBox.innerHTML = "";
      const printable = getPrintableSequence(idx);
      window.currentPrintableSequence = printable;
      // adds only consecutive printable characters to the decodedAscii box
      asciiTextBox.textContent += truncate(printable, 32);
      for (let i = 0; i < truncate(printable, 32).length; i++) {
        const highlightedCell = document.querySelectorAll(".griditem")[idx + i];
        highlightedCell.classList.add("highlight");
      }
      const hexLen = parseInt(truncate(printable, 32).length, 10)
        .toString(16)
        .padStart(2, "0")
        .toUpperCase();
      const hexOffset = idx.toString(16).padStart(4, "0").toUpperCase();
      if (printable.length == 0) {
        asciiTextBox.textContent = "0x" + item.textContent;
      }
      hexOffsetDisplay.textContent = "0x" + hexOffset + ":" + hexLen;
    });
  });
  // this fades the box back out and calls the grid clear func
  document.querySelectorAll(".griditem").forEach((item) => {
    item.addEventListener("mouseleave", () => {
      payloadAsciiBox.classList.remove("visible");
      clearGridHighlights();
    });
  });
}

/**
 * Utility to create a table from data and headers, and append to a container.
 */
// probably should break this function up into smaller pieces,
// but it works for now, it takes the current packet info and
// populates the info panel with it, including the side tables
// and the main info table, also updates the timestamp and
// currentIp:port info at the top
function infoPanel(pk) {
  const infoPaneEl = document.getElementById("packetInfoPane");
  document.getElementById("rightside").style.display = "block";
  document.getElementById("leftside").style.display = "block";
  const infoPaneOrigHtml = infoPaneEl.innerHTML;
  infoPaneEl.style.display = "block";
  const p = pk[index];
  let packetInfoData = p["Packet Info"];
  let extraInfoData = p["Extra Info"];
  let packetTimestamp = packetInfoData["Packet Timestamp"];
  let ipChecksum = packetInfoData["IP"]["IP Checksum"];

  // Determine transport protocol (TCP or UDP); fall back to TCP for older captures
  const protocol = packetInfoData["Protocol"] || "TCP";
  const transportData = packetInfoData[protocol] || {};

  const transportChecksum =
    protocol === "TCP"
      ? transportData["TCP checksum"]
      : protocol === "UDP"
        ? transportData["UDP checksum"]
        : protocol === "ICMP"
          ? transportData["ICMP Checksum"]
          : "N/A";
  const transportLayerLen =
    protocol === "TCP"
      ? transportData["TCP layer length"]
      : protocol === "UDP"
        ? transportData["UDP length"]
        : protocol === "ICMP"
          ? transportData["Wire length"]
          : "N/A";
  const tcpFlags =
    protocol === "TCP" && transportData["TCP Flag Data"]
      ? transportData["TCP Flag Data"]["Flags"]
      : "N/A";

  const sourceIpPort =
    packetInfoData["IP"]["Source IP"] +
    ":" +
    (transportData["Source port"] ?? "?");
  const destIpPort =
    packetInfoData["IP"]["Destination IP"] +
    ":" +
    (transportData["Destination port"] ?? "?");
  const etherFrame =
    typeof packetInfoData["Ethernet Frame"] === "object" &&
    packetInfoData["Ethernet Frame"] !== null
      ? packetInfoData["Ethernet Frame"]
      : {};
  const srcMac = etherFrame["MAC Source"] ?? "N/A";
  const dstMac = etherFrame["MAC Destination"] ?? "N/A";
  const srcMacVendor = etherFrame["MAC Source Vendor"] ?? "N/A";
  const dstMacVendor = etherFrame["MAC Destination Vendor"] ?? "N/A";
  const ipLayerLen = packetInfoData["IP"]["IP layer length"];
  const wireLen = transportData["Wire length"];
  const payloadLen = packetInfoData["Raw data"]["Payload Length"];
  let sslCert = "";
  let sslVersion = "";
  let sslAlgos = "";
  if (
    extraInfoData["Traits"]["Server Info"]["Encryption Data"] == "N/A" ||
    extraInfoData["Traits"]["Server Info"].hasOwnProperty("Encryption Data") ==
      false
  ) {
    sslCert = "Not encrypted";
    sslVersion = "Not encrypted";
    sslAlgos = "";
  } else {
    sslCert =
      extraInfoData["Traits"]["Server Info"]["Encryption Data"]["SSL Cert"] ??
      "Not available";
    sslVersion =
      extraInfoData["Traits"]["Server Info"]["Encryption Data"][
        "SSL Version"
      ] ?? "Not available";
    sslAlgos =
      extraInfoData["Traits"]["Server Info"]["Encryption Data"][
        "Encrypted With"
      ].join("<br>Extra algo info: ") ?? "No algorithm information available";
  }
  const isDecompressed = extraInfoData["Decompressed"]["Decompressed"];
  function removeIps(ipList) {
    const ipRegex =
      /\b((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/;
    return ipList.filter((item) => !ipRegex.test(item));
  }

  let dnsHostsHtml;
  if (
    extraInfoData["Traits"]["Network Data"]["Hostnames"]["Hostnames"] ==
    undefined
  ) {
    dnsHostsHtml = "localhost";
  } else {
    dnsHostsHtml =
      "localhost<br>" +
      extraInfoData["Traits"]["Network Data"]["Hostnames"]["Hostnames"].join(
        "<br>",
      );
  }
  const filteredDnsHosts = removeIps(dnsHostsHtml.split("<br>")).join("<br>");
  dnsHostsHtml = filteredDnsHosts == "" ? "localhost" : filteredDnsHosts;

  const pageTitle = extraInfoData["Traits"]["Server Info"]["Page Title"];
  const isEncrypted = extraInfoData["Traits"]["Server Info"]["Encrypted"];
  const protoName = extraInfoData["Traits"]["Network Data"]["Port Protcol"];
  const protoDescription =
    extraInfoData["Traits"]["Network Data"]["Port Description"];
  const srcNetClass =
    extraInfoData["Traits"]["Network Data"]["Source IP"]["Class"];
  const dstNetClass =
    extraInfoData["Traits"]["Network Data"]["Destination IP"]["Class"];
  document.getElementById("sidedatatable").textContent = "";
  document.getElementById("protoInfoSrc").textContent = "Source";
  document.getElementById("protoInfoDest").textContent = "Destination";
  document.getElementById("comp").textContent = "Unknown";
  if (isDecompressed == false || isDecompressed == undefined) {
    const types = extraInfoData["Data Types"];

    types.forEach((type) => {
      if (type.includes("Zlib") || type.includes("zlib")) {
        document.getElementById("comp").textContent = "Compressed with zlib";

        console.log("Data type identified: " + type);
      }
      if (type.includes("Gzip") || type.includes("gzip")) {
        document.getElementById("comp").textContent = "Compressed with gzip";
      }
      if (type.includes("Zip")) {
        document.getElementById("comp").textContent = "Compressed with zip";
      }
    });
  }
  if (isDecompressed == true) {
    document.getElementById("comp").textContent =
      "Not regonized as compressed data";
  }
  //  wireLen
  if (pageTitle == undefined || pageTitle == "N/A") {
    document.getElementById("website").textContent =
      "Not available for this server";
  } else {
    document.getElementById("website").textContent = pageTitle;
  }
  //document.getElementById("crypt").textContent = isEncrypted;
  const dnsCollapsedList = dnsHostsHtml.replace(/(<br\s*\/?>\s*)+/gi, "<br>");
  document.getElementById("dns").innerHTML = dnsCollapsedList;
  if (sslAlgos == undefined || sslAlgos == "") {
    //document.getElementById("crypt").innerHTML = sslCert
    //  ? "Encrypted with: " + sslVersion + "<br>" + sslAlgos
    //  : "Not Encrypted";
    document.getElementById("crypt").innerHTML = "Not encrypted";
  } else {
    document.getElementById("crypt").innerHTML =
      "Encrypted with: " + sslVersion + "<br>" + sslAlgos;
  }

  if (protoName == "Unknown") {
    document.getElementById("protocols").innerHTML = "Unknown";
  } else {
    document.getElementById("protocols").innerHTML =
      "Protocol Name: " +
      protoName +
      "<br>Protocol Description: " +
      protoDescription;
  }
  const checksumData = [
    { name: "IP Checksum", value: ipChecksum },
    { name: protocol + " Checksum", value: transportChecksum },
    { name: "Flags", value: tcpFlags },
    { name: "IP Length", value: ipLayerLen },
    { name: protocol + " Length", value: transportLayerLen },
    { name: "Wire Length", value: wireLen },
    { name: "Payload Length", value: payloadLen },
  ];
  const checksumHeaders = ["Protocol data", "Details"];
  createTable(checksumData, checksumHeaders, "sidedatatable");

  // DNS info table (shown for UDP/DNS packets)
  renderDnsTable(transportData);

  // ICMP info table (shown for ICMP packets)
  renderIcmpTable(protocol, transportData);

  // SNMP info table (shown for SNMP packets on port 161/162)
  renderSnmpTable(transportData);

  // DHCP info table (shown for DHCP packets on port 67/68)
  renderDhcpTable(transportData);

  // NTP info table (shown for NTP packets on port 123)
  renderNtpTable(transportData);

  // SIP info table (shown for SIP packets on port 5060/5061)
  renderSipTable(transportData);

  // HTTP info table (shown for HTTP request/response packets)
  renderHttpTable(transportData);

  // HTTP/2 info table (shown for HTTP/2 frames on any TCP port)
  renderHttp2Table(transportData);

  // FTP info table (shown for FTP packets on port 20/21)
  renderFtpTable(transportData);

  // SMTP info table (shown for SMTP packets on port 25/587/465)
  renderSmtpTable(transportData);

  // POP3 info table (shown for POP3 packets on port 110/995)
  renderPop3Table(transportData);

  // IMAP info table (shown for IMAP packets on port 143/993)
  renderImapTable(transportData);

  // Telnet info table (shown for Telnet packets on port 23)
  renderTelnetTable(transportData);

  // IRC info table (shown for IRC packets on port 6667/6668/6669)
  renderIrcTable(transportData);

  // MTP info table (shown for MTP/MMS packets on port 1755)
  renderMtpTable(transportData);

  // LDAP info table (shown for LDAP packets on port 389/636)
  renderLdapTable(transportData);

  // MySQL info table (shown for MySQL packets on port 3306)
  renderMysqlTable(transportData);

  // PostgreSQL info table (shown for PostgreSQL packets on port 5432)
  renderPostgresqlTable(transportData);

  // XMPP info table (shown for XMPP packets on port 5222/5223)
  renderXmppTable(transportData);

  // SMB info table (shown for SMB packets on port 139/445)
  renderSmbTable(transportData);

  // MQTT info table (shown for MQTT packets on port 1883/8883)
  renderMqttTable(transportData);

  // RTSP info table (shown for RTSP packets on port 554)
  renderRtspTable(transportData);

  // TFTP info table (shown for TFTP packets on UDP port 69)
  renderTftpTable(transportData);

  // BGP info table (shown for BGP packets on port 179)
  renderBgpTable(transportData);

  // NNTP info table (shown for NNTP packets on port 119)
  renderNntpTable(transportData);

  // RADIUS info table (shown for RADIUS packets on port 1812/1813/1645/1646)
  renderRadiusTable(transportData);

  const ipTableHeaders = ["Packet", "Data"];
  const srcIpData = [
    { name: "IP:Port", value: sourceIpPort },
    { name: "MAC", value: srcMac },
    { name: "MAC Vendor", value: srcMacVendor },
    { name: "Network Class", value: srcNetClass },
  ];
  createTable(srcIpData, ipTableHeaders, "protoInfoSrc");
  const dstIpData = [
    { name: "IP:Port", value: destIpPort },
    { name: "MAC", value: dstMac },
    { name: "MAC Vendor", value: dstMacVendor },
    { name: "Network Class", value: dstNetClass },
  ];
  createTable(dstIpData, ipTableHeaders, "protoInfoDest");
  const entropyValue = extraInfoData["Traits"]["Shannon Entropy"];
  document.getElementById("timestamp").textContent =
    "Timestamp " + packetTimestamp;
  //document.getElementById("ip2ip").textContent = sourceIpPort + " ~ " + destIpPort;
  document.getElementById("sideloctable").textContent = "";
  document.getElementById("entropybox").textContent =
    "\u096F " + entropyValue.toFixed(2);
  const entropyBoxEl = document.getElementById("entropybox");
  if (entropyValue >= 6.8) {
    entropyBoxEl.className = "high";
  } else if (entropyValue >= 4.5) {
    entropyBoxEl.className = "med";
  } else {
    entropyBoxEl.className = "low";
  }
  const secondColumnCells = document.querySelectorAll(
    "table tr td:nth-child(1), table tr th:nth-child(1)",
  );
  secondColumnCells.forEach((cell) => {
    cell.style.width = "23%";
  });
  if (
    extraInfoData["Traits"]["Network Data"]["Source IP"]["Location"]["City"] ==
    undefined
  ) {
    const localnetData = [{ name: "Location", value: "Localnet" }];
    const localnetHeaders = ["Source Host", "Location"];
    createTable(localnetData, localnetHeaders, "sideloctable");
  } else {
    const srcLocData = [
      {
        name: "Country",
        value:
          extraInfoData["Traits"]["Network Data"]["Source IP"]["Location"][
            "Country"
          ],
      },
      {
        name: "City",
        value:
          extraInfoData["Traits"]["Network Data"]["Source IP"]["Location"][
            "City"
          ],
      },
      {
        name: "Timezone",
        value:
          extraInfoData["Traits"]["Network Data"]["Source IP"]["Location"][
            "Time Zone"
          ],
      },
    ];
    const srcLocHeaders = ["Source Host", "Location"];
    createTable(srcLocData, srcLocHeaders, "sideloctable");
  }
  if (
    extraInfoData["Traits"]["Network Data"]["Destination IP"]["Location"][
      "City"
    ] == undefined
  ) {
    const localnetData = [{ name: "Location", value: "Localnet" }];
    const localnetHeaders = ["Destination Host", "Location"];
    createTable(localnetData, localnetHeaders, "sideloctable");
  } else {
    const dstLocData = [
      {
        name: "Country",
        value:
          extraInfoData["Traits"]["Network Data"]["Destination IP"]["Location"][
            "Country"
          ],
      },
      {
        name: "City",
        value:
          extraInfoData["Traits"]["Network Data"]["Destination IP"]["Location"][
            "City"
          ],
      },
      {
        name: "Timezone",

        value:
          extraInfoData["Traits"]["Network Data"]["Destination IP"]["Location"][
            "Time Zone"
          ],
      },
    ];
    const dstLocHeaders = ["Destination Host", "Location"];
    createTable(dstLocData, dstLocHeaders, "sideloctable");
  }
}

// Save the currently loaded capture plus session state to disk
document.getElementById("save-json-btn").addEventListener("click", function () {
  void persistSessionToDisk("sidebar-button");
});

// the next two have hooks into IPC handlers for main.js
// data transactions

// when the main.js returns our json data from snitch.py
window.jsonapi.onJsonData((jsonData) => {
  document.getElementById("loading-container").style.display = "block";
  document.getElementById("error-container").style.display = "none";
  statusUpdate("Loaded data from backend, processing...");
  writeLogEntry("Backend JSON payload received for processing");
  processFile(
    new File([jsonData], "capture.json", { type: "application/json" }),
  );
  document.getElementById("loading-container").style.display = "none";
  const loadEndTime = performance.now();
  document.getElementById("load-time").textContent =
    "Load time: " + ((loadEndTime - startTime) / 1000).toFixed(2) + " seconds";
});

// here we create the backend process and hook it to the handler
function runSnitch(file) {
  document.getElementById("loading-container").style.display = "block";
  document.getElementById("summary_content").innerHTML =
    '<span id="loaderdots" class="loading">Loading</span>';
  document.getElementById("status").textContent =
    "Status: Running snitch backend, this may take a few minutes...";
  document.getElementById("error-container").style.display = "none";
  startTime = performance.now();
  const useLLM = document.getElementById("use-llm").checked;
  const fileLabel = typeof file === "string" ? file : file?.name || "unknown";
  writeLogEntry(
    `Backend analysis started file=${fileLabel} llm_enabled=${useLLM}`,
  );
  window.snitchapi
    .runBackendCommand(file, useLLM)
    .then((output) => {})
    .catch((error) => {
      doError("Backend run error!", { backend: true });
      logErrorEntry("backend-run", error);
    });
}

function doError(message, { backend = false } = {}) {
  console.error("Error from backend:", message);
  if (backend) {
    writeBackendErrorLogEntry(`Error shown message="${message}"`);
  } else {
    writeLogEntry(`Error shown message="${message}"`);
  }
  const loadingContainerEl = document.getElementById("loading-container");
  const errorContainerEl = document.getElementById("error-container");
  document.getElementById("summary_content").textContent = "";
  loadingContainerEl.style.display = "none";
  errorContainerEl.style.display = "block";
  errorContainerEl.textContent = message;
  errorContainerEl.addEventListener("click", () => {
    errorContainerEl.style.display = "none";
    loadingContainerEl.style.display = "none";
  });
}

function hideAllData() {
  //  document.getElementById("packetInfoPane").textContent =
  //    "No matching packets found.";
  doError("No packets match the filter criteria!");
  statusUpdate("Status: No packets match the filter criteria");
  document.getElementById("data-types").style.display = "none";
  document.getElementById("protoInfo").style.display = "none";
  document.getElementById("timestamp").style.display = "none";
  document.getElementById("rightside").style.display = "none";
  document.getElementById("active-recon").style.display = "none";
  document.getElementById("prev-btn").style.opacity = "0";
  document.getElementById("next-btn").style.opacity = "0";
  popHexGrid("00".repeat(1));
}
function showAllData() {
  document.getElementById("prev-btn").style.opacity = "1";
  document.getElementById("next-btn").style.opacity = "1";
  document.getElementById("data-types").style.display = "block";
  document.getElementById("protoInfo").style.display = "block";
  document.getElementById("timestamp").style.display = "block";
  document.getElementById("rightside").style.display = "block";
  document.getElementById("active-recon").style.display = "block";
  document.getElementById("hexg").hidden = false;
  document.getElementById("error-container").style.display = "none";
}

document
  .getElementById("filterStr")
  .addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
      const filterQuery = filterInputEl.value;
      runFilterQuery(filterQuery);
      filterHistorySelectEl.value = "";
    }
  });

filterClearButtonEl.addEventListener("click", clearFilterQuery);

initializeContextMenu({
  documentRef: document,
  windowRef: window,
  convertContextMenuEl,
  getPasteTargetFromContextTarget,
  getTrimmedSelectionText,
  getConversionTextFromTarget,
  detectConvertibleFormats,
  buildContextFilterQueries,
  getCookieJarTextForContextTarget,
  showConvertContextMenu,
  hideConvertContextMenu,
});

filterInputEl.addEventListener("input", syncFilterHighlight);
filterInputEl.addEventListener("scroll", syncFilterHighlightScroll);

filterHistorySelectEl.addEventListener("change", () => {
  const selectedQuery = filterHistorySelectEl.value;
  if (!selectedQuery) return;
  filterInputEl.value = selectedQuery;
  syncFilterHighlight();
  runFilterQuery(selectedQuery);
  filterHistorySelectEl.value = "";
});

renderFilterHistory();
syncFilterHighlight();

window.onerror = (message, source, lineno, colno, error) => {
  doError(message + " at " + source + ":" + lineno + ":" + colno);
};

window.onunhandledrejection = (event) => {
  doError("Unhandled promise error! " + event.reason);
};

window.api.onError((msg) => {
  console.error("Error from backend:", msg);
  // Show alert or UI message
  doError(msg, { backend: true });
});

// On page load, hide packet info and payload panes
onload = function () {
  // document.getElementById("selectBookmark").style.display = "none";
  hideConvertContextMenu();
  keystorePanel.resetKeystoreState();
  setCryptSubtab(CRYPT_SSL_SUBTAB);
  setConvSubtab(CONV_CONVERSIONS_SUBTAB);
  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  document.getElementById("rightside").style.display = "none";
  document.getElementById("leftside").style.display = "none";
  document.getElementById("loading-container").style.display = "none";
};
