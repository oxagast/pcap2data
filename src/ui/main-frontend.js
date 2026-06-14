import "../assets/css/style.css";
const CryptoJS = require("crypto-js");
const { sha3_256, sha3_512 } = require("js-sha3");
const whirlpool = require("whirlpool-js");
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
const { createStatsPanel } = require("./panels/stats-panel");
const { createListPanel } = require("./panels/list-panel");
const { createSummaryPanel } = require("./panels/summary-panel");
const { initializeInstallScreen } = require("./panels/install-screen");
const { initializeSessionPicker } = require("./panels/session-picker");
const { createDataPanel } = require("./panels/data-panel");
const psVer = require("../../package.json").version;
const {
  initConvPanel,
  CONV_CONVERSIONS_SUBTAB,
  CONV_HASHES_SUBTAB,
  CONV_DECODES_SUBTAB,
  VALID_CONV_SUBTABS,
  DATA_TOOLS_CONTEXT_BASE64_MIN_LENGTH,
  DATA_TOOLS_TEXT_MIME_PRINTABLE_THRESHOLD,
  DATA_TOOLS_ENTROPY_HIGH_THRESHOLD,
  DATA_TOOLS_ENTROPY_MEDIUM_THRESHOLD,
  DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES,
  getActiveConvSubtab,
  getActiveDataToolsProtoResult,
  setConvSubtab,
  runDataToolsHashesFromInput,
} = require("./panels/data-tools-panel");

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
const MAIN_TAB_NOTES = "notes";
const MAIN_TAB_DATA_TOOLS = "data-tools";
const MAIN_TAB_CRYPT = "crypt";
const MAIN_TAB_KEYSTORE = "keystore";
const NOTE_DEFAULT_COLOR = "#4caf50";
const NOTE_FALLBACK_COLORS = [
  "#4caf50",
  "#ff9800",
  "#2196f3",
  "#9c27b0",
  "#e91e63",
  "#ffc107",
];
const DEFAULT_DATA_TOOLS_FORMAT = "hex";
const DATA_TOOLS_CONVERTED_OUTPUT_IDS = [
  "data-tools-hex-output",
  "data-tools-binary-output",
  "data-tools-decimal-output",
  "data-tools-decimal-integer-output",
  "data-tools-ascii-output",
  "data-tools-base64-output",
];
const DATA_TOOLS_OUTPUT_FORMAT_DETAILS = {
  hex: {
    labelSelector: ".data-tools-output-label-hex",
    outputSelector: "#data-tools-hex-output",
  },
  binary: {
    labelSelector: ".data-tools-output-label-binary",
    outputSelector: "#data-tools-binary-output",
  },
  decimal: {
    labelSelector: ".data-tools-output-label-decimal",
    outputSelector: "#data-tools-decimal-output",
  },
  "decimal-integer": {
    labelSelector: ".data-tools-output-label-decimal-integer",
    outputSelector: "#data-tools-decimal-integer-output",
  },
  ascii: {
    labelSelector: ".data-tools-output-label-ascii",
    outputSelector: "#data-tools-ascii-output",
  },
  base64: {
    labelSelector: ".data-tools-output-label-base64",
    outputSelector: "#data-tools-base64-output",
  },
};

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
const dataToolsHistorySelectEl = getCachedElement("data-tools-history-select");
const dataToolsInputHistory = [];
const DATA_TOOLS_INPUT_HISTORY_LIMIT = 10;
const CONTEXT_IPV4_REGEX =
  /\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/;
const STRICT_IPV4_REGEX =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const CONTEXT_MAC_REGEX = /\b([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}\b/;
const CONTEXT_MIME_REGEX = /^[\w.+-]+\/[\w.+-]+$/;
const CRYPT_SSL_SUBTAB = "ssl";
const CRYPT_PGP_SUBTAB = "pgp";
const CRYPT_OPENSSH_SUBTAB = "openssh";
const VALID_MAIN_TABS = [
  MAIN_TAB_SUMMARY,
  MAIN_TAB_DATA,
  MAIN_TAB_STATS,
  MAIN_TAB_LIST,
  MAIN_TAB_NOTES,
  MAIN_TAB_DATA_TOOLS,
  MAIN_TAB_CRYPT,
  MAIN_TAB_KEYSTORE,
];
const VALID_CRYPT_SUBTABS = [
  CRYPT_SSL_SUBTAB,
  CRYPT_PGP_SUBTAB,
  CRYPT_OPENSSH_SUBTAB,
];
let activeMainTab = MAIN_TAB_SUMMARY;
let activeCryptSubtab = CRYPT_SSL_SUBTAB;
let activeDataToolsProtoResult = null;
let keystorePanel;
let notesList = [];
let selectedNoteId = null;
let noteIdCounter = 0;
// Name of the session in the library (userData/sessions/). Null if unsaved.
let currentSessionName = null;
let sessionPickerPanel = null;

initializeInstallScreen({
  installapi: window.installapi,
  documentRef: document,
});



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

const { showStats } = createStatsPanel({
  documentRef: document,
  statusUpdate,
  writeLogEntry,
  setActiveMainTab: (tab) => {
    activeMainTab = tab;
  },
  mainTabStats: MAIN_TAB_STATS,
  getJsonCapture: () => jsonCapture,
  getCapturedPackets: () => capturedPackets,
  filterInputEl,
  syncFilterHighlight,
  runFilterQuery,
  getFilteredPackets: () => filteredPackets,
  setPacketsForHost: (packets) => {
    packetsForHost = packets;
  },
});

const summaryPanel = createSummaryPanel({
  documentRef: document,
  getJsonCapture: () => jsonCapture,
  getFinalSummary: () => finalSummary,
  setActiveMainTab: (tab) => {
    activeMainTab = tab;
  },
  mainTabSummary: MAIN_TAB_SUMMARY,
  statusUpdate,
  fileLoaded,
});

const { showSummary, showSummaryLoading, clearSummaryContent } = summaryPanel;
const { initializeDataView, bindDataPanelEvents, logCurrentPacketDisplay } =
  createDataPanel({
    constants: {
      MAIN_TAB_DATA,
    },
    documentRef: document,
    statusUpdate,
    writeLogEntry,
    doError,
    getIsFileLoaded: () => isFileLoaded,
    getJsonCapture: () => jsonCapture,
    getHostFilterValue: () => hostFilterEl.value,
    getHostsList: () => hostsList,
    getFilterInputValue: () => filterInputEl.value,
    getFilteredPackets: () => filteredPackets,
    getPacketsForHost: () => packetsForHost,
    setActiveMainTab: (tab) => {
      activeMainTab = tab;
    },
    handlePacketNavigation: (navAction, navBookmark) =>
      handlePacketNavigation(navAction, navBookmark),
    getIndex: () => index,
    setIndex: (nextIndex) => {
      index = nextIndex;
    },
    setActivePacketCursor,
    setCurrentIp: (nextIp) => {
      currentIp = nextIp;
    },
    setCurrentPacketKey: (nextPacketKey) => {
      currentPacketKey = nextPacketKey;
    },
    getCurrentPacketKey: () => currentPacketKey,
    syncBookmarkDropdown,
    infoPanel,
    popHexGrid,
    populateDataTypes,
  });
bindDataPanelEvents();


sessionPickerPanel = initializeSessionPicker({
  sessionsapi: window.sessionsapi,
  documentRef: document,
  onSessionSelected: (name, jsonData) => {
    currentSessionName = name;
    startTime = performance.now();
    statusUpdate("Loading session: " + name);
    processFile(
      new File([jsonData], name + ".json", { type: "application/json" }),
    );
  },
  onNewSession: async () => {
    // User dismissed the picker – stay on the blank/new session state
    // on new session, we should clear any existing data and reset the UI to the initial state
    document.getElementById("loading-screen").style.display = "flex";
    await clearCurrentSession();
    window.getfileapi
      .selectFile()
      .then((filePath) => {
        if (filePath) {
          window.fsize
            .getFSize()
            .then((fileSize) => {
              // Update the UI with the file size
              const fileSizeKb = (fileSize / 1024).toFixed(2);
              document.getElementById("pcap-size").textContent =
                `PCAP size: ${fileSizeKb}kb`;
              writeLogEntry(`Capture size=${fileSizeKb}kb`);
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
  },
});

async function clearCurrentSession() {
  statusUpdate("Clearing current session data for new session...");
  writeLogEntry("User initiated new session: clearing existing session data");
  currentSessionName = null;
  packetsForHost = [];
  capturedPackets = {};
  activePacketCursor = 0;
  index = 0;
  currentIp = null;
  currentPacketKey = null;
  jsonCapture = "";
  finalSummary = "";
  finalSummary = ""; // Clear the default summary from the template
  filterHistory.length = 0;
  hostFilterEl.value = "";
  filterHistorySelectEl.innerHTML = '<option value="" selected>Filter History</option>';
  filterInputEl.value = "";
  dataToolsInputHistory.length = 0;
  dataToolsHistorySelectEl.innerHTML = '<option value="" disabled selected>Data Tools History</option>';
  updateFilterClearButtonState();
  clearFilterQuery();
  syncFilterHighlight();
  clearSummaryContent();
  renderFilterHistory();

  // Load the baseline session template through the preload bridge.
  // this basically zeroed/nulls everything out but keeps the overall structure
  // of the JSON intact.
  try {
    const templateResult = await window.templateapi.getNewSessionTemplate();
    if (!templateResult || !templateResult.success || !templateResult.data) {
      doError(
        "Unable to load new session template" +
        (templateResult && templateResult.error
          ? ": " + templateResult.error
          : "."),
      );
      return;
    }
    processFile(
      new File([templateResult.data], "new_session.json", {
        type: "application/json",
      }),
    );


  } catch (err) {
    doError(
      "Unable to load new session template: " +
      (err && err.message ? err.message : String(err)),
    );
  }
}



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
      const fileSizeKb = (file.size / 1024).toFixed(2);
      writeLogEntry(
        `User selected JSON file name=${file.name} size=${fileSizeKb}kb`,
      );
      // Clear library session name – this is a manual file load, not from the library
      currentSessionName = null;
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
          window.fsize
            .getFSize()
            .then((fileSize) => {
              // Update the UI with the file size
              const fileSizeKb = (fileSize / 1024).toFixed(2);
              document.getElementById("pcap-size").textContent =
                `PCAP size: ${fileSizeKb}kb`;
              writeLogEntry(`Capture size=${fileSizeKb}kb`);
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
    document.getElementById("notes-btn").style.opacity = "1";
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
    document.getElementById("notes-btn").style.opacity = "0";
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

function buildDataToolsHistoryLabel(entry) {
  const preview = entry.input.replace(/\s+/g, " ").trim();
  const truncatedPreview =
    preview.length > 80 ? `${preview.slice(0, 77)}…` : preview;
  return `${entry.format.toUpperCase()}: ${truncatedPreview}`;
}

function renderDataToolsInputHistory() {
  dataToolsHistorySelectEl.replaceChildren();

  const placeholderOption = document.createElement("option");
  placeholderOption.value = "";
  placeholderOption.textContent = dataToolsInputHistory.length
    ? "Previous inputs"
    : "No previous inputs";
  placeholderOption.selected = true;
  dataToolsHistorySelectEl.appendChild(placeholderOption);

  dataToolsInputHistory.forEach((entry, index) => {
    const entryOption = document.createElement("option");
    entryOption.value = String(index);
    entryOption.textContent = buildDataToolsHistoryLabel(entry);
    entryOption.title = buildDataToolsHistoryLabel(entry);
    dataToolsHistorySelectEl.appendChild(entryOption);
  });

  dataToolsHistorySelectEl.value = "";
  dataToolsHistorySelectEl.disabled = dataToolsInputHistory.length === 0;
}

function addDataToolsInputHistory(format, input) {
  const normalizedFormat =
    typeof format === "string" && format.trim()
      ? format.trim().toLowerCase()
      : "hex";
  const normalizedInput = String(input ?? "");
  if (!normalizedInput.trim()) return;

  const existingIndex = dataToolsInputHistory.findIndex(
    (entry) =>
      entry.format === normalizedFormat && entry.input === normalizedInput,
  );
  if (existingIndex !== -1) {
    dataToolsInputHistory.splice(existingIndex, 1);
  }

  dataToolsInputHistory.unshift({
    format: normalizedFormat,
    input: normalizedInput,
  });
  if (dataToolsInputHistory.length > DATA_TOOLS_INPUT_HISTORY_LIMIT) {
    dataToolsInputHistory.length = DATA_TOOLS_INPUT_HISTORY_LIMIT;
  }
  renderDataToolsInputHistory();
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

function normalizeNoteColor(colorValue) {
  const normalized =
    typeof colorValue === "string" ? colorValue.trim().toLowerCase() : "";
  if (/^#[0-9a-f]{6}$/.test(normalized)) return normalized;
  return NOTE_DEFAULT_COLOR;
}

function generateNoteId() {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  noteIdCounter += 1;
  return `note-${Date.now()}-${noteIdCounter}`;
}

function createNoteEntry(text = "", color = NOTE_DEFAULT_COLOR) {
  return {
    id: generateNoteId(),
    text: typeof text === "string" ? text : String(text || ""),
    color: normalizeNoteColor(color),
  };
}

function getSelectedNoteEntry() {
  return notesList.find((entry) => entry.id === selectedNoteId) || null;
}

function renderNotesList() {
  const notesSelectEl = document.getElementById("notes-select");
  const notesEditorEl = document.getElementById("notes-editor");
  const newNoteColorEl = document.getElementById("notes-new-color");
  if (!notesSelectEl || !notesEditorEl || !newNoteColorEl) return;

  notesSelectEl.replaceChildren();
  if (!notesList.length) {
    selectedNoteId = null;
    notesEditorEl.value = "";
    notesEditorEl.disabled = true;
    return;
  }

  if (!getSelectedNoteEntry()) {
    selectedNoteId = notesList[0].id;
  }

  notesList.forEach((noteEntry, noteIndex) => {
    const optionEl = document.createElement("option");
    const previewText = String(noteEntry.text || "")
      .replace(/\s+/g, " ")
      .trim();
    optionEl.value = noteEntry.id;
    optionEl.textContent = `${noteIndex + 1}. ${previewText || "(empty note)"}`;
    optionEl.style.borderLeft = `8px solid ${normalizeNoteColor(noteEntry.color)}`;
    notesSelectEl.appendChild(optionEl);
  });

  notesSelectEl.value = selectedNoteId;
  const selectedNoteEntry = getSelectedNoteEntry();
  notesEditorEl.disabled = !selectedNoteEntry;
  notesEditorEl.value = selectedNoteEntry ? selectedNoteEntry.text : "";
  newNoteColorEl.value = selectedNoteEntry
    ? normalizeNoteColor(selectedNoteEntry.color)
    : NOTE_DEFAULT_COLOR;
}

function addNote(text, color = NOTE_DEFAULT_COLOR, sourceLabel = "manual") {
  const normalizedText =
    typeof text === "string" ? text.trim() : String(text || "").trim();
  if (!normalizedText) {
    statusUpdate("Status: No note text to add");
    return false;
  }
  const noteEntry = createNoteEntry(normalizedText, color);
  notesList.unshift(noteEntry);
  selectedNoteId = noteEntry.id;
  renderNotesList();
  statusUpdate("Status: Note added");
  writeLogEntry(
    `Note added source=${sourceLabel} length=${normalizedText.length}`,
  );
  return true;
}

function removeSelectedNote() {
  const selectedNoteEntry = getSelectedNoteEntry();
  if (!selectedNoteEntry) {
    statusUpdate("Status: No note selected to remove");
    return;
  }
  const selectedIndex = notesList.findIndex(
    (entry) => entry.id === selectedNoteEntry.id,
  );
  notesList = notesList.filter((entry) => entry.id !== selectedNoteEntry.id);
  if (notesList.length === 0) {
    selectedNoteId = null;
  } else if (selectedIndex >= notesList.length) {
    selectedNoteId = notesList[notesList.length - 1].id;
  } else {
    selectedNoteId = notesList[Math.max(0, selectedIndex)].id;
  }
  renderNotesList();
  statusUpdate("Status: Note removed");
  writeLogEntry(`Note removed id=${selectedNoteEntry.id}`);
}

function formatNotesForExport() {
  if (!Array.isArray(notesList) || notesList.length === 0) return "";
  return notesList
    .map((noteEntry, noteIndex) => {
      const noteText = String(noteEntry.text || "").trim();
      return [
        `Note ${noteIndex + 1}`,
        `Color: ${normalizeNoteColor(noteEntry.color)}`,
        noteText,
      ].join("\n");
    })
    .join("\n\n---\n\n");
}

async function saveNotesToDisk() {
  const notesExportText = formatNotesForExport();
  if (!notesExportText) {
    statusUpdate("Status: No notes available to save");
    return;
  }
  const result = await window.saveapi.saveNotes(notesExportText);
  if (result?.canceled) {
    statusUpdate("Status: Save cancelled");
  } else if (result?.success) {
    statusUpdate("Status: Notes saved successfully");
    writeLogEntry(`Notes saved entries=${notesList.length}`);
  } else {
    const errorMessage =
      result && typeof result === "object" && "error" in result
        ? result.error
        : "unknown";
    doError("Notes save failed");
    logErrorEntry("save-notes", errorMessage || "unknown");
    statusUpdate(
      "Status: Notes save failed – " + (errorMessage || "unknown error"),
    );
  }
}

function buildConvConvertedOutputNoteText() {
  const outputFields = [
    ["Hex", "data-tools-hex-output"],
    ["Binary", "data-tools-binary-output"],
    ["Decimal bytes", "data-tools-decimal-output"],
    ["Decimal integer", "data-tools-decimal-integer-output"],
    ["ASCII", "data-tools-ascii-output"],
    ["Base64", "data-tools-base64-output"],
  ];
  const lines = outputFields
    .map(([label, id]) => {
      const value = document.getElementById(id)?.value?.trim() || "";
      return value ? `${label}: ${value}` : "";
    })
    .filter(Boolean);
  return lines.length > 0 ? lines.join("\n") : "";
}

function buildConvHashesNoteText() {
  const hashFields = [
    ["Input", "data-tools-hash-input-reading"],
    ["MD5", "data-tools-md5-output"],
    ["SHA-1", "data-tools-sha1-output"],
    ["SHA-256", "data-tools-sha256-output"],
    ["SHA-384", "data-tools-sha384-output"],
    ["SHA-512", "data-tools-sha512-output"],
    ["SHA3-256", "data-tools-sha3-256-output"],
    ["SHA3-512", "data-tools-sha3-512-output"],
    ["RIPEMD-160", "data-tools-ripemd160-output"],
    ["Whirlpool", "data-tools-whirlpool-output"],
  ];
  const lines = hashFields
    .map(([label, id]) => {
      const value = document.getElementById(id)?.value?.trim() || "";
      return value ? `${label}: ${value}` : "";
    })
    .filter(Boolean);
  return lines.length > 0 ? lines.join("\n") : "";
}

function sendTextToNotesFromContextMenu(text, sourceLabel) {
  hideConvertContextMenu();
  const didAdd = addNote(text, NOTE_DEFAULT_COLOR, sourceLabel);
  if (!didAdd) return;
  showNotesWorkspace();
}

function initializeNotesPanel() {
  const addButtonEl = document.getElementById("notes-add-btn");
  const removeButtonEl = document.getElementById("notes-remove-btn");
  const saveButtonEl = document.getElementById("notes-save-btn");
  const newNoteInputEl = document.getElementById("notes-new-input");
  const newNoteColorEl = document.getElementById("notes-new-color");
  const notesSelectEl = document.getElementById("notes-select");
  const notesEditorEl = document.getElementById("notes-editor");
  if (
    !addButtonEl ||
    !removeButtonEl ||
    !saveButtonEl ||
    !newNoteInputEl ||
    !newNoteColorEl ||
    !notesSelectEl ||
    !notesEditorEl
  ) {
    return;
  }
  newNoteColorEl.value = NOTE_DEFAULT_COLOR;

  addButtonEl.addEventListener("click", () => {
    const didAdd = addNote(
      newNoteInputEl.value,
      newNoteColorEl.value,
      "notes-panel",
    );
    if (didAdd) {
      newNoteInputEl.value = "";
      newNoteInputEl.focus();
    }
  });
  saveButtonEl.addEventListener("click", () => {
    void saveNotesToDisk();
  });
  removeButtonEl.addEventListener("click", removeSelectedNote);
  newNoteInputEl.addEventListener("keydown", (event) => {
    if (!(event.ctrlKey || event.metaKey) || event.key !== "Enter") return;
    event.preventDefault();
    const didAdd = addNote(
      newNoteInputEl.value,
      newNoteColorEl.value,
      "notes-panel",
    );
    if (didAdd) {
      newNoteInputEl.value = "";
      newNoteInputEl.focus();
    }
  });
  notesSelectEl.addEventListener("change", () => {
    selectedNoteId = notesSelectEl.value || null;
    renderNotesList();
  });
  notesEditorEl.addEventListener("input", () => {
    const selectedNoteEntry = getSelectedNoteEntry();
    if (!selectedNoteEntry) return;
    selectedNoteEntry.text = notesEditorEl.value;
    const selectedOptionEl =
      notesSelectEl.options[notesSelectEl.selectedIndex] || null;
    if (selectedOptionEl) {
      const previewText = String(selectedNoteEntry.text || "")
        .replace(/\s+/g, " ")
        .trim();
      selectedOptionEl.textContent = `${notesSelectEl.selectedIndex + 1}. ${previewText || "(empty note)"}`;
    }
  });
  newNoteColorEl.addEventListener("input", () => {
    const selectedNoteEntry = getSelectedNoteEntry();
    if (!selectedNoteEntry) return;
    selectedNoteEntry.color = normalizeNoteColor(newNoteColorEl.value);
    const selectedOptionEl =
      notesSelectEl.options[notesSelectEl.selectedIndex] || null;
    if (selectedOptionEl) {
      selectedOptionEl.style.borderLeft = `8px solid ${selectedNoteEntry.color}`;
    }
  });

  renderNotesList();
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
      document.getElementById("target_hosts")?.value ||
      hostFilterEl.value ||
      "",
    bookmarkList: [...bookmarkList],
    convInputHistory: deepCloneSessionData(dataToolsInputHistory, []),
    sessionKeychainEntries: deepCloneSessionData(
      keystorePanel.getSessionKeychainEntries(),
      [],
    ),
    keystoreMode: keystorePanel.getKeystoreMode(),
    notes: deepCloneSessionData(notesList, []),
    tabs: {
      main: activeMainTab,
      conv: getActiveConvSubtab(),
      crypt: activeCryptSubtab,
      listSearch: listSearchEl ? listSearchEl.value : "",
      listGroupStreams: listGroupStreamsEl
        ? Boolean(listGroupStreamsEl.checked)
        : false,
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

  // If no session library is available fall back to the file-dialog export
  if (!window.sessionsapi) {
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

  // Prompt for a session name if one has not been set yet
  if (!currentSessionName) {
    const promptedName =
      sessionPickerPanel
        ? await sessionPickerPanel.promptSessionName("Save Session to Library", "")
        : window.prompt("Enter a session name:", "");
    if (!promptedName || !promptedName.trim()) {
      statusUpdate("Status: Save cancelled");
      return { success: false, canceled: true };
    }
    currentSessionName = promptedName.trim();
  }

  const sessionJsonData = buildSessionFilePayload();
  const result = await window.sessionsapi.save(currentSessionName, sessionJsonData);
  if (result.success) {
    // Keep the canonical name returned by the backend (post-sanitization)
    if (result.name) currentSessionName = result.name;
    statusUpdate('Status: Session saved to library as "' + currentSessionName + '"');
    writeLogEntry(
      `Session saved to library name="${currentSessionName}" source=${sourceLabel}`,
    );
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

async function exportSessionToFile() {
  if (
    !capturedPackets ||
    !capturedPackets["Host"] ||
    typeof capturedPackets["Host"] !== "object"
  ) {
    statusUpdate("Status: No data loaded to export");
    return { success: false, error: "No loaded capture" };
  }
  const sessionJsonData = buildSessionFilePayload();
  if (window.sessionsapi) {
    const result = await window.sessionsapi.exportToFile(
      currentSessionName || "",
      sessionJsonData,
    );
    if (result.canceled) {
      statusUpdate("Status: Export cancelled");
    } else if (result.success) {
      statusUpdate("Status: Session exported successfully");
      writeLogEntry(`Session exported to file name="${currentSessionName || "unnamed"}"`);
    } else {
      const errorMessage =
        result && typeof result === "object" && "error" in result
          ? result.error
          : "unknown";
      doError("Export failed");
      logErrorEntry("export-session", errorMessage || "unknown");
      statusUpdate("Status: Export failed – " + (errorMessage || "unknown error"));
    }
    return result;
  }
  // Fallback: use the legacy save dialog
  const result = await window.saveapi.saveJson(sessionJsonData);
  if (result.canceled) {
    statusUpdate("Status: Export cancelled");
  } else if (result.success) {
    statusUpdate("Status: Session exported successfully");
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
    function onSave() {
      cleanup("save");
    }
    function onDiscard() {
      cleanup("discard");
    }
    function onCancel() {
      cleanup("cancel");
    }
    document
      .getElementById("save-session-save-btn")
      .addEventListener("click", onSave);
    document
      .getElementById("save-session-discard-btn")
      .addEventListener("click", onDiscard);
    document
      .getElementById("save-session-cancel-btn")
      .addEventListener("click", onCancel);
  });
}

async function requestApplicationClose() {
  if (packetsForHost && packetsForHost.length > 1) {
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

  const loadedDataToolsHistory = Array.isArray(sessionState.convInputHistory)
    ? sessionState.convInputHistory
      .filter((entry) => entry && typeof entry === "object")
      .flatMap((entry) => {
        const normalizedInput =
          typeof entry.input === "string"
            ? entry.input
            : String(entry.input ?? "");
        if (!normalizedInput.trim()) return [];
        return [
          {
            format:
              typeof entry.format === "string" && entry.format.trim()
                ? entry.format.trim().toLowerCase()
                : "hex",
            input: normalizedInput,
          },
        ];
      })
      .slice(0, DATA_TOOLS_INPUT_HISTORY_LIMIT)
    : [];
  dataToolsInputHistory.splice(
    0,
    dataToolsInputHistory.length,
    ...loadedDataToolsHistory,
  );
  renderDataToolsInputHistory();

  const loadedSessionEntries = Array.isArray(
    sessionState.sessionKeychainEntries,
  )
    ? sessionState.sessionKeychainEntries.filter(
      (entry) => entry && typeof entry === "object",
    )
    : [];
  keystorePanel.restoreSessionState(
    deepCloneSessionData(loadedSessionEntries, []),
    sessionState.keystoreMode,
  );

  const loadedNotes = Array.isArray(sessionState.notes)
    ? sessionState.notes
      .filter((note) => note && typeof note === "object")
      .map((note) => ({
        id:
          typeof note.id === "string" && note.id.trim()
            ? note.id
            : generateNoteId(),
        text:
          typeof note.text === "string" ? note.text : String(note.text || ""),
        color: normalizeNoteColor(note.color),
      }))
    : [];
  notesList = loadedNotes;
  selectedNoteId = notesList.length > 0 ? notesList[0].id : null;
  renderNotesList();

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
    document.getElementById("filter-returned").textContent =
      "Filtered Packets: 0";
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

  const tabState =
    sessionState.tabs && typeof sessionState.tabs === "object"
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
    showSummary();
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
  } else if (savedMainTab === MAIN_TAB_NOTES) {
    showNotesWorkspace();
  } else if (savedMainTab === MAIN_TAB_DATA_TOOLS) {
    showDataTools(savedConvTab);
  } else if (savedMainTab === MAIN_TAB_CRYPT) {
    showCryptWorkspace(savedCryptTab);
  } else if (savedMainTab === MAIN_TAB_KEYSTORE && keystorePanel.isUnlocked()) {
    keystorePanel.showKeystoreWorkspace();
  }

  if (savedMainTab !== MAIN_TAB_DATA_TOOLS) {
    setConvSubtab(savedConvTab);
  }
  if (savedMainTab !== MAIN_TAB_CRYPT) {
    setCryptSubtab(savedCryptTab);
  }
  else {
    isFileLoaded = true;
  }
  writeLogEntry("Session state restored from JSON");
  statusUpdate("Status: Session restored");
}

/**
 * Reads and parses the JSON file, updates UI and state.
 * Uses chunked parsing for large files to avoid UI blocking.
 */
function processFile(file) {
  document.getElementById("loading-screen").style.display = "flex";
  document.getElementById("loading-container").style.display = "block";
  document.getElementById("loading-text").textContent = "Loading packets...";
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
            doError(
              "Invalid JSON file, please upload a valid capture/session file!",
            );
            fileLoaded(false);
            return;
          }
          document.getElementById("loading-text").textContent =
            "Initializing session...";
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
        doError(
          "Invalid JSON file, please upload a valid capture/session file!",
        );
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
    notesList = [];
    selectedNoteId = null;
    renderNotesList();
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
    clearFilterQuery();
    syncFilterHighlight();
    isFileLoaded = true;
    if (loadedSessionState) {
      restoreSessionState(loadedSessionState);
    }
    else {
      statusUpdate("Status: File loaded successfully");
      writeLogEntry("New session initialized: created new session state");
      document.getElementById("total-packets").textContent = "Total Packets: " + totalPacketCount();
      showPacketList();
    }
    document.getElementById("loading-screen").style.display = "none";
    document.getElementById("loading-container").style.display = "none";


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

function buildHostTargetFilterQuery(selectedHost) {
  const safeHost = sanitizeFilterTerm(selectedHost);
  if (!safeHost) return "";
  return `ip.src.addr: ${safeHost} || ip.dst.addr: ${safeHost}`;
}

// Update host and apply associated filter when a new host is selected from dropdown
getCachedElement("target_hosts").addEventListener("change", function () {
  const selected = getCachedElement("target_hosts").value;
  writeLogEntry(`Host target changed host=${selected}`);
  if (hostFilterEl.value !== selected) {
    hostFilterEl.value = selected;
  }
  const hostFilterQuery = buildHostTargetFilterQuery(selected);
  filterInputEl.value = hostFilterQuery;
  syncFilterHighlight();
  runFilterQuery(hostFilterQuery, { trackHistory: false });
});

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

const DATA_TOOLS_TEXT_ENCODER = new TextEncoder();
const DATA_TOOLS_SELECTION_FIELD_IDS = [
  "data-tools-input",
  "data-tools-hex-output",
  "data-tools-binary-output",
  "data-tools-decimal-output",
  "data-tools-ascii-output",
  "data-tools-base64-output",
];
const DATA_TOOLS_HEX_BREAK_BYTES = new Set([
  0x00, 0x09, 0x0a, 0x0d, 0x20, 0x2c, 0x3a, 0x3b, 0x7c,
]);
const dataToolsSelectionState = {
  bytes: new Uint8Array(),
  maps: {},
  selectedByteRange: null,
  syncingSelection: false,
  lastSelectionSignature: "",
};

function escapeDataToolsHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function classifyDataToolsHexByte(byteValue) {
  if (DATA_TOOLS_HEX_BREAK_BYTES.has(byteValue)) return "data-tools-hex-break";
  if (
    (byteValue >= 0x30 && byteValue <= 0x39) ||
    (byteValue >= 0x41 && byteValue <= 0x5a) ||
    (byteValue >= 0x61 && byteValue <= 0x7a)
  ) {
    return "data-tools-hex-alpha";
  }
  return "data-tools-hex-binary";
}

function buildInputSelectionMap(rawInput, format, bytes) {
  const text = String(rawInput || "");
  const charToByte = new Array(text.length).fill(null);
  const byteRanges = Array.from({ length: bytes.length }, () => ({
    start: null,
    end: null,
  }));
  const markByteRange = (byteIndex, charIndex) => {
    if (byteIndex == null || byteIndex < 0 || byteIndex >= byteRanges.length) {
      return;
    }
    if (byteRanges[byteIndex].start == null)
      byteRanges[byteIndex].start = charIndex;
    byteRanges[byteIndex].end = charIndex + 1;
  };

  if (format === "hex") {
    let hexNibbleIndex = 0;
    for (let i = 0; i < text.length; i++) {
      if (!/[0-9a-fA-F]/.test(text[i])) continue;
      const byteIndex = Math.floor(hexNibbleIndex / 2);
      charToByte[i] = byteIndex;
      markByteRange(byteIndex, i);
      hexNibbleIndex += 1;
    }
    return { charToByte, byteRanges };
  }

  if (format === "binary") {
    let bitIndex = 0;
    for (let i = 0; i < text.length; i++) {
      if (text[i] !== "0" && text[i] !== "1") continue;
      const byteIndex = Math.floor(bitIndex / 8);
      charToByte[i] = byteIndex;
      markByteRange(byteIndex, i);
      bitIndex += 1;
    }
    return { charToByte, byteRanges };
  }

  if (format === "decimal") {
    const tokens = text.matchAll(/\d+/g);
    let byteIndex = 0;
    for (const token of tokens) {
      const start = token.index ?? 0;
      const end = start + token[0].length;
      for (let i = start; i < end; i++) {
        charToByte[i] = byteIndex;
        markByteRange(byteIndex, i);
      }
      byteIndex += 1;
      if (byteIndex >= bytes.length) break;
    }
    return { charToByte, byteRanges };
  }

  if (format === "base64") {
    const prefixMatch = text.match(/^\s*data:[^;]+;base64,/i);
    const startOffset = prefixMatch ? prefixMatch[0].length : 0;
    const indices = [];
    for (let i = startOffset; i < text.length; i++) {
      if (!/\s/.test(text[i])) indices.push(i);
    }
    let byteCursor = 0;
    for (let i = 0; i + 3 < indices.length; i += 4) {
      const c1 = text[indices[i]];
      const c2 = text[indices[i + 1]];
      const c3 = text[indices[i + 2]];
      const c4 = text[indices[i + 3]];
      const byteCount = c3 === "=" ? 1 : c4 === "=" ? 2 : 3;
      const quartetTargets = [
        byteCursor,
        byteCursor,
        byteCount > 1 ? byteCursor + 1 : byteCursor,
        byteCount > 2 ? byteCursor + 2 : byteCursor + byteCount - 1,
      ];
      for (let j = 0; j < 4; j++) {
        const byteIndex = quartetTargets[j];
        if (!Number.isFinite(byteIndex) || byteIndex >= bytes.length) continue;
        const charIndex = indices[i + j];
        charToByte[charIndex] = byteIndex;
        markByteRange(byteIndex, charIndex);
      }
      byteCursor += byteCount;
      if (byteCursor >= bytes.length) break;
    }
    return { charToByte, byteRanges };
  }

  let byteOffset = 0;
  for (let i = 0; i < text.length; i++) {
    const encoded = DATA_TOOLS_TEXT_ENCODER.encode(text[i]);
    const start = byteOffset;
    const end = Math.min(byteRanges.length, start + encoded.length);
    for (let byteIndex = start; byteIndex < end; byteIndex++) {
      if (charToByte[i] == null) {
        charToByte[i] = byteIndex;
      }
      markByteRange(byteIndex, i);
    }
    byteOffset += encoded.length;
    if (byteOffset >= byteRanges.length) break;
  }
  return { charToByte, byteRanges };
}

function buildRenderedSelectionMap(values) {
  const text = values.join(" ");
  const charToByte = [];
  const byteRanges = Array.from({ length: values.length }, () => ({
    start: null,
    end: null,
  }));
  let cursor = 0;
  values.forEach((value, byteIndex) => {
    for (let i = 0; i < value.length; i++) {
      charToByte[cursor + i] = byteIndex;
    }
    byteRanges[byteIndex] = { start: cursor, end: cursor + value.length };
    cursor += value.length;
    if (byteIndex < values.length - 1) {
      charToByte[cursor] = null;
      cursor += 1;
    }
  });
  return { text, charToByte, byteRanges };
}

function buildBase64SelectionMap(base64Text, bytes) {
  const charToByte = new Array(base64Text.length).fill(null);
  const byteRanges = Array.from({ length: bytes.length }, () => ({
    start: null,
    end: null,
  }));
  const markByteRange = (byteIndex, charIndex) => {
    if (byteIndex < 0 || byteIndex >= byteRanges.length) return;
    if (byteRanges[byteIndex].start == null)
      byteRanges[byteIndex].start = charIndex;
    byteRanges[byteIndex].end = charIndex + 1;
  };
  let byteCursor = 0;
  for (let i = 0; i + 3 < base64Text.length; i += 4) {
    const c3 = base64Text[i + 2];
    const c4 = base64Text[i + 3];
    const byteCount = c3 === "=" ? 1 : c4 === "=" ? 2 : 3;
    const targets = [
      byteCursor,
      byteCursor,
      byteCount > 1 ? byteCursor + 1 : byteCursor,
      byteCount > 2 ? byteCursor + 2 : byteCursor + byteCount - 1,
    ];
    for (let j = 0; j < 4; j++) {
      const byteIndex = targets[j];
      if (!Number.isFinite(byteIndex) || byteIndex >= bytes.length) continue;
      charToByte[i + j] = byteIndex;
      markByteRange(byteIndex, i + j);
    }
    byteCursor += byteCount;
    if (byteCursor >= bytes.length) break;
  }
  return { text: base64Text, charToByte, byteRanges };
}

function getDataToolsByteRangeForSelection(selectionMap, start, end) {
  if (!selectionMap) return null;
  const max = selectionMap.charToByte.length;
  const left = Math.max(0, Math.min(start ?? 0, max));
  const right = Math.max(0, Math.min(end ?? left, max));
  let minByte = Number.POSITIVE_INFINITY;
  let maxByte = -1;

  for (let i = left; i < right; i++) {
    const byteIndex = selectionMap.charToByte[i];
    if (byteIndex == null) continue;
    minByte = Math.min(minByte, byteIndex);
    maxByte = Math.max(maxByte, byteIndex);
  }

  if (maxByte >= 0) {
    return { start: minByte, end: maxByte + 1 };
  }

  const probeIndexes = [left, left - 1, right, right - 1];
  for (const probeIndex of probeIndexes) {
    if (probeIndex < 0 || probeIndex >= max) continue;
    const byteIndex = selectionMap.charToByte[probeIndex];
    if (byteIndex == null) continue;
    return { start: byteIndex, end: byteIndex + 1 };
  }

  return null;
}

function getDataToolsSelectionForByteRange(selectionMap, byteRange) {
  if (!selectionMap || !byteRange) return null;
  const startByte = Math.max(0, byteRange.start);
  const endByte = Math.max(startByte + 1, byteRange.end);
  const startRange = selectionMap.byteRanges[startByte];
  const endRange = selectionMap.byteRanges[endByte - 1];
  if (!startRange || !endRange) return null;
  if (startRange.start == null || endRange.end == null) return null;
  return { start: startRange.start, end: endRange.end };
}

function buildColorizedHexHtml(rawText, selectionMap, bytes, byteRange) {
  const text = String(rawText || "");
  const hasSelection = Boolean(byteRange);
  const inSelectedRange = (byteIndex) =>
    hasSelection &&
    byteIndex != null &&
    byteIndex >= byteRange.start &&
    byteIndex < byteRange.end;
  let html = "";
  for (let i = 0; i < text.length; i++) {
    const byteIndex = selectionMap?.charToByte?.[i] ?? null;
    let className = "data-tools-hex-separator";
    if (byteIndex != null && byteIndex < bytes.length) {
      className = classifyDataToolsHexByte(bytes[byteIndex]);
    } else if (/[\s,;:-]/.test(text[i])) {
      className = "data-tools-hex-separator";
    }
    if (inSelectedRange(byteIndex)) {
      className += " data-tools-sync-highlight";
    }
    html += `<span class="${className}">${escapeDataToolsHtml(text[i])}</span>`;
  }
  return html;
}

function updateDataToolsHexHighlights() {
  const inputHighlightEl = document.getElementById(
    "data-tools-input-highlight",
  );
  const outputHighlightEl = document.getElementById(
    "data-tools-hex-output-highlight",
  );
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  const outputEl = document.getElementById("data-tools-hex-output");
  if (
    !inputHighlightEl ||
    !outputHighlightEl ||
    !inputEl ||
    !formatEl ||
    !outputEl
  ) {
    return;
  }
  const inputMap = dataToolsSelectionState.maps["data-tools-input"] || {
    charToByte: [],
    byteRanges: [],
  };
  const outputMap = dataToolsSelectionState.maps["data-tools-hex-output"] || {
    charToByte: [],
    byteRanges: [],
  };
  const bytes = dataToolsSelectionState.bytes || new Uint8Array();
  if (formatEl.value === "hex") {
    inputHighlightEl.innerHTML = buildColorizedHexHtml(
      inputEl.value,
      inputMap,
      bytes,
      dataToolsSelectionState.selectedByteRange,
    );
  } else {
    inputHighlightEl.innerHTML = escapeDataToolsHtml(inputEl.value);
  }
  outputHighlightEl.innerHTML = buildColorizedHexHtml(
    outputEl.value,
    outputMap,
    bytes,
    dataToolsSelectionState.selectedByteRange,
  );
}

function syncDataToolsHighlightScroll(textareaId, layerId) {
  const textarea = document.getElementById(textareaId);
  const layer = document.getElementById(layerId);
  if (!textarea || !layer) return;
  layer.style.transform = `translate(${-textarea.scrollLeft}px, ${-textarea.scrollTop}px)`;
}

function clearDataToolsSelectionState() {
  dataToolsSelectionState.bytes = new Uint8Array();
  dataToolsSelectionState.maps = {};
  dataToolsSelectionState.selectedByteRange = null;
  dataToolsSelectionState.lastSelectionSignature = "";
  updateDataToolsHexHighlights();
  syncDataToolsHighlightScroll(
    "data-tools-input",
    "data-tools-input-highlight",
  );
  syncDataToolsHighlightScroll(
    "data-tools-hex-output",
    "data-tools-hex-output-highlight",
  );
}

function updateDataToolsSelectionMaps(format, rawInput, bytes, outputs) {
  dataToolsSelectionState.bytes = bytes;
  dataToolsSelectionState.lastSelectionSignature = "";
  dataToolsSelectionState.maps = {
    "data-tools-input": buildInputSelectionMap(rawInput, format, bytes),
    "data-tools-hex-output": buildRenderedSelectionMap(outputs.hexValues),
    "data-tools-binary-output": buildRenderedSelectionMap(outputs.binaryValues),
    "data-tools-decimal-output": buildRenderedSelectionMap(
      outputs.decimalValues,
    ),
    "data-tools-ascii-output": {
      text: outputs.asciiText,
      charToByte: Array.from(
        { length: outputs.asciiText.length },
        (_, idx) => idx,
      ),
      byteRanges: Array.from({ length: bytes.length }, (_, idx) => ({
        start: idx,
        end: idx + 1,
      })),
    },
    "data-tools-base64-output": buildBase64SelectionMap(
      outputs.base64Text,
      bytes,
    ),
  };
}

function syncDataToolsSelectionFromField(sourceFieldId) {
  if (dataToolsSelectionState.syncingSelection) return;
  const sourceEl = document.getElementById(sourceFieldId);
  const sourceMap = dataToolsSelectionState.maps[sourceFieldId];
  if (!sourceEl || !sourceMap) return;
  const signature = `${sourceFieldId}:${sourceEl.selectionStart}:${sourceEl.selectionEnd}`;
  if (signature === dataToolsSelectionState.lastSelectionSignature) {
    return;
  }
  dataToolsSelectionState.lastSelectionSignature = signature;

  const byteRange = getDataToolsByteRangeForSelection(
    sourceMap,
    sourceEl.selectionStart,
    sourceEl.selectionEnd,
  );
  dataToolsSelectionState.selectedByteRange = byteRange;

  dataToolsSelectionState.syncingSelection = true;
  try {
    for (const fieldId of DATA_TOOLS_SELECTION_FIELD_IDS) {
      if (fieldId === sourceFieldId) continue;
      const targetEl = document.getElementById(fieldId);
      const targetMap = dataToolsSelectionState.maps[fieldId];
      if (!targetEl || !targetMap) continue;
      if (!byteRange) {
        targetEl.setSelectionRange(0, 0);
        continue;
      }
      const selection = getDataToolsSelectionForByteRange(targetMap, byteRange);
      if (!selection) continue;
      targetEl.setSelectionRange(selection.start, selection.end);
    }
  } finally {
    dataToolsSelectionState.syncingSelection = false;
  }
  updateDataToolsHexHighlights();
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

  const inspectedText = decodeBytesForTextInspection(bytes);
  const trimmed = inspectedText.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      JSON.parse(trimmed);
      return "application/json";
    } catch {
      // Keep evaluating as plain text/binary.
    }
  }

  if (looksLikeHtmlSource(trimmed)) return "text/html; charset=utf-8";
  if (looksLikeCssSource(trimmed)) return "text/css; charset=utf-8";
  if (looksLikeJavaScriptSource(trimmed)) {
    return "application/javascript; charset=utf-8";
  }
  if (looksLikeXmlSource(trimmed)) {
    return trimmed.startsWith("<svg") ? "image/svg+xml" : "application/xml";
  }
  if (looksLikeYamlSource(trimmed)) return "application/yaml";
  if (isLikelyReadableText(inspectedText, bytes)) {
    return "text/plain; charset=utf-8";
  }

  return "application/octet-stream";
}

function getEntropyLabel(entropy) {
  if (entropy >= DATA_TOOLS_ENTROPY_HIGH_THRESHOLD) return "High";
  if (entropy >= DATA_TOOLS_ENTROPY_MEDIUM_THRESHOLD) return "Medium";
  return "Low";
}

const DATA_TYPE_GUESS_SCAN_CHUNK_SIZE = 2048;
const DATA_TYPE_GUESS_SCAN_OVERLAP = 256;
const DATA_TYPE_GUESS_TOKEN_RE = /[A-Za-z0-9+/_=:$.-]{8,}/g;
const DATA_TOOLS_UTF8_DECODER = new TextDecoder("utf-8", { fatal: false });
const DATA_TOOLS_UTF16LE_DECODER = new TextDecoder("utf-16le", {
  fatal: false,
});
const DATA_TOOLS_UTF16BE_DECODER = new TextDecoder("utf-16be", {
  fatal: false,
});
const DATA_TYPE_GUESS_UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DATA_TYPE_GUESS_JWT_RE =
  /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/;
const DATA_TYPE_GUESS_URL_RE =
  /\b(?:(?:https?|ftp|file|ws|wss):\/\/|mailto:)[^\s<>"']+/i;
const DATA_TYPE_GUESS_URI_RE = /\b[a-z][a-z0-9+.-]{1,31}:[^\s<>"']+/i;
const DATA_TYPE_GUESS_FILENAME_EXTENSIONS = [
  "txt",
  "log",
  "cfg",
  "conf",
  "ini",
  "json",
  "xml",
  "htm",
  "html",
  "js",
  "jsx",
  "mjs",
  "cjs",
  "ts",
  "tsx",
  "css",
  "scss",
  "less",
  "py",
  "rb",
  "php",
  "pl",
  "sh",
  "bash",
  "zsh",
  "fish",
  "ps1",
  "sql",
  "c",
  "cc",
  "cpp",
  "h",
  "hpp",
  "java",
  "go",
  "rs",
  "swift",
  "kt",
  "m",
  "mm",
  "cs",
  "yaml",
  "yml",
  "toml",
  "md",
  "pdf",
  "doc",
  "docx",
  "xls",
  "xlsx",
  "ppt",
  "pptx",
  "csv",
  "tsv",
  "zip",
  "tar",
  "gz",
  "bz2",
  "xz",
  "7z",
  "rar",
  "png",
  "jpg",
  "jpeg",
  "gif",
  "svg",
  "pcap",
  "pcapng",
  "bin",
];
const DATA_TYPE_GUESS_FILENAME_EXTENSION_PATTERN =
  DATA_TYPE_GUESS_FILENAME_EXTENSIONS.map((extension) =>
    extension.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
  ).join("|");
const DATA_TYPE_GUESS_FILENAME_RE = new RegExp(
  String.raw`(?:^|[\s"'([{])(?:[A-Za-z]:[\\/]|\.{0,2}[\\/])?(?:[\w @()+,\-]+[\\/])*[\w @()+,\-]+\.(?:${DATA_TYPE_GUESS_FILENAME_EXTENSION_PATTERN})(?=$|[\s"')\]}:,;.!?])`,
  "i",
);
const DATA_TYPE_GUESS_CSS_BLOCK_MAX_CHARS = 600;
const DATA_TOOLS_LANGUAGE_MIN_LETTERS = 24;
const DATA_TOOLS_LANGUAGE_MIN_STOPWORD_MATCHES = 3;
const DATA_TOOLS_LANGUAGE_HIGH_CONFIDENCE_STOPWORD_MATCHES = 6;
const DATA_TOOLS_LANGUAGE_STOPWORDS = {
  English: ["the", "and", "with", "that", "this", "from", "have"],
  Spanish: ["que", "para", "una", "por", "como", "los", "las", "del", "con"],
  French: ["une", "pour", "avec", "dans", "des", "est", "pas", "sur", "les"],
  German: ["und", "der", "die", "das", "nicht", "mit", "ist", "ein", "den"],
  Portuguese: ["que", "para", "com", "uma", "não", "por", "dos", "das", "está"],
  Italian: ["che", "per", "con", "una", "non", "della", "sono", "degli"],
};

function decodeBytesForTextInspection(bytes) {
  if (!bytes || !bytes.length) return "";
  if (
    bytes.length >= 3 &&
    bytes[0] === 0xef &&
    bytes[1] === 0xbb &&
    bytes[2] === 0xbf
  ) {
    return DATA_TOOLS_UTF8_DECODER.decode(bytes);
  }
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return DATA_TOOLS_UTF16LE_DECODER.decode(bytes);
  }
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    return DATA_TOOLS_UTF16BE_DECODER.decode(bytes);
  }
  return DATA_TOOLS_UTF8_DECODER.decode(bytes);
}

function isLikelyReadableText(text, bytes = null) {
  const normalized = String(text || "");
  if (!normalized.trim()) return false;
  const replacementCount = (normalized.match(/\uFFFD/g) || []).length;
  if (replacementCount > Math.max(2, normalized.length * 0.05)) return false;
  const hasUtf16Bom =
    bytes &&
    bytes.length >= 2 &&
    ((bytes[0] === 0xff && bytes[1] === 0xfe) ||
      (bytes[0] === 0xfe && bytes[1] === 0xff));
  if (bytes && !hasUtf16Bom && bytes.includes(0x00)) return false;
  let readableChars = 0;
  for (const ch of normalized) {
    const code = ch.codePointAt(0);
    if (
      ch === "\n" ||
      ch === "\r" ||
      ch === "\t" ||
      (code >= 32 && code <= 126) ||
      (code >= 0xa0 && code !== 0xfffd)
    ) {
      readableChars += 1;
    }
  }
  return (
    readableChars / normalized.length >=
    DATA_TOOLS_TEXT_MIME_PRINTABLE_THRESHOLD
  );
}

function looksLikeHtmlSource(text) {
  return (
    /<!doctype\s+html/i.test(text) ||
    /<html\b/i.test(text) ||
    /<(?:head|body|title|script|style|div|span|p|a|form|table)\b/i.test(text)
  );
}

function looksLikeXmlSource(text) {
  return (
    /^<\?xml\b/i.test(text) ||
    (/^<[\w:-]+(?:\s+[^>]*)?>/.test(text) && /<\/[\w:-]+>\s*$/.test(text))
  );
}

function looksLikeCssSource(text) {
  if (
    /@(?:media|import|supports|font-face)\b/i.test(text) ||
    /--[\w-]+\s*:/.test(text)
  ) {
    return true;
  }
  const blockStart = text.indexOf("{");
  const blockEnd = blockStart >= 0 ? text.indexOf("}", blockStart + 1) : -1;
  if (
    blockStart < 0 ||
    blockEnd < 0 ||
    blockEnd - blockStart > DATA_TYPE_GUESS_CSS_BLOCK_MAX_CHARS
  ) {
    return false;
  }
  const selector = text.slice(0, blockStart).trim();
  const blockBody = text.slice(blockStart + 1, blockEnd);
  return (
    /[#.]?[A-Za-z][\w-]*(?:\s*[>+~]\s*[#.]?[A-Za-z][\w-]*)*$/.test(selector) &&
    /(?:^|[;\s])[\w-]+\s*:\s*[^;{}]+;?/.test(blockBody)
  );
}

function looksLikeJavaScriptSource(text) {
  return (
    /\b(?:const|let|var|function|export|import|async|await|document|window|console)\b/.test(
      text,
    ) || /=>/.test(text)
  );
}

function looksLikePythonSource(text) {
  return (
    /^\s*#!\/(?:usr\/bin\/env\s+)?python\d*\b/m.test(text) ||
    /\bdef\s+\w+\s*\(/.test(text) ||
    /\bclass\s+\w+\s*[:(]/.test(text) ||
    /\bimport\s+\w+/.test(text)
  );
}

function looksLikeShellSource(text) {
  return (
    /^\s*#!\/(?:usr\/bin\/env\s+)?(?:bash|sh|zsh|fish)\b/m.test(text) ||
    (/\b(?:echo|export|grep|awk|sed|fi|done|then)\b/.test(text) &&
      /\$\w+/.test(text))
  );
}

function looksLikePowerShellSource(text) {
  return /\b(?:Get-|Set-|Write-Host|New-Object|Param\s*\(|\$env:)\b/i.test(
    text,
  );
}

function looksLikeSqlSource(text) {
  return /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE)\b/i.test(
    text,
  );
}

function looksLikePhpSource(text) {
  return /<\?php\b/i.test(text);
}

function looksLikeGoSource(text) {
  return /\bpackage\s+\w+\b/.test(text) && /\bfunc\s+\w+\s*\(/.test(text);
}

function looksLikeRustSource(text) {
  return (
    /\bfn\s+\w+\s*\(/.test(text) && /\b(?:let\s+mut|impl|use\s+\w)/.test(text)
  );
}

function looksLikeJavaOrCSharpSource(text) {
  return (
    /\b(?:public|private|protected)\s+(?:class|static|void)\b/.test(text) ||
    /\bSystem\.out\.println\b/.test(text) ||
    /\busing\s+System\b/.test(text)
  );
}

function looksLikeYamlSource(text) {
  return (
    /^\s*[A-Za-z0-9_.-]+\s*:\s+\S+/m.test(text) &&
    !/[{};]/.test(text) &&
    !/<[A-Za-z]/.test(text)
  );
}

function looksLikeAnySourceCode(text) {
  return (
    looksLikeHtmlSource(text) ||
    looksLikeXmlSource(text) ||
    looksLikeCssSource(text) ||
    looksLikeJavaScriptSource(text) ||
    looksLikePythonSource(text) ||
    looksLikeShellSource(text) ||
    looksLikePowerShellSource(text) ||
    looksLikeSqlSource(text) ||
    looksLikePhpSource(text) ||
    looksLikeGoSource(text) ||
    looksLikeRustSource(text) ||
    looksLikeJavaOrCSharpSource(text) ||
    looksLikeYamlSource(text)
  );
}

function addStructuredTextTypeGuesses(inputText, candidateScores) {
  const text = String(inputText || "");
  const trimmed = text.trim();
  if (!trimmed) return;

  if (DATA_TYPE_GUESS_URL_RE.test(text) || DATA_TYPE_GUESS_URI_RE.test(text)) {
    addDataTypeGuessCandidate(candidateScores, "URL / Link", 92);
  }
  if (DATA_TYPE_GUESS_FILENAME_RE.test(text)) {
    addDataTypeGuessCandidate(candidateScores, "Filename / File Path", 88);
  }
  if (looksLikeHtmlSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "HTML Source Code", 94);
  }
  if (looksLikeCssSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "CSS Stylesheet", 91);
  }
  if (looksLikeJavaScriptSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "JavaScript Source Code", 90);
  }
  if (looksLikeXmlSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "XML / Markup Source Code", 86);
  }
  if (looksLikePythonSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "Python Source Code", 88);
  }
  if (looksLikeShellSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "Shell Script", 85);
  }
  if (looksLikePowerShellSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "PowerShell Script", 86);
  }
  if (looksLikeSqlSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "SQL Source Code", 87);
  }
  if (looksLikePhpSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "PHP Source Code", 86);
  }
  if (looksLikeGoSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "Go Source Code", 86);
  }
  if (looksLikeRustSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "Rust Source Code", 84);
  }
  if (looksLikeJavaOrCSharpSource(trimmed)) {
    addDataTypeGuessCandidate(candidateScores, "Java / C# Source Code", 82);
  }
  if (
    !looksLikeAnySourceCode(trimmed) &&
    /[{}();<>]/.test(trimmed) &&
    /\b(?:if|for|while|return|class|function|const|let|var|def|fn|SELECT|echo)\b/.test(
      trimmed,
    )
  ) {
    addDataTypeGuessCandidate(candidateScores, "Programming Source Code", 72);
  }
}

function guessReadableTextLanguage(text, bytes = null) {
  const normalized = String(text || "").trim();
  if (!isLikelyReadableText(normalized, bytes)) return null;
  if (looksLikeAnySourceCode(normalized)) {
    return null;
  }

  if (/[\u3040-\u30ff]/.test(normalized)) {
    return { label: "Japanese", confidence: "High" };
  }
  if (/[\uac00-\ud7af]/.test(normalized)) {
    return { label: "Korean", confidence: "High" };
  }
  if (/[\u0600-\u06ff]/.test(normalized)) {
    return { label: "Arabic", confidence: "High" };
  }
  if (/[\u0590-\u05ff]/.test(normalized)) {
    return { label: "Hebrew", confidence: "High" };
  }
  if (/[\u0370-\u03ff]/.test(normalized)) {
    return { label: "Greek", confidence: "High" };
  }
  if (/[\u4e00-\u9fff]/.test(normalized)) {
    const hasJapaneseKana = /[\u3040-\u30ff]/.test(normalized);
    return { label: "Chinese", confidence: hasJapaneseKana ? "Low" : "Medium" };
  }

  const letterTokens = normalized.toLowerCase().match(/\p{L}+/gu) || [];
  const joinedLetters = letterTokens.join("");
  if (joinedLetters.length < DATA_TOOLS_LANGUAGE_MIN_LETTERS) return null;

  const cyrillicCount = (joinedLetters.match(/[\u0400-\u04ff]/g) || []).length;
  if (cyrillicCount / joinedLetters.length >= 0.4) {
    return {
      label: "Russian",
      confidence:
        cyrillicCount / joinedLetters.length >= 0.8 ? "High" : "Medium",
    };
  }

  let bestLabel = "";
  let bestScore = 0;
  Object.entries(DATA_TOOLS_LANGUAGE_STOPWORDS).forEach(
    ([label, stopwords]) => {
      const stopwordSet = new Set(stopwords);
      const score = letterTokens.reduce(
        (total, token) => total + (stopwordSet.has(token) ? 1 : 0),
        0,
      );
      if (score > bestScore) {
        bestLabel = label;
        bestScore = score;
      }
    },
  );

  if (bestScore >= DATA_TOOLS_LANGUAGE_MIN_STOPWORD_MATCHES) {
    return {
      label: bestLabel,
      confidence:
        bestScore >= DATA_TOOLS_LANGUAGE_HIGH_CONFIDENCE_STOPWORD_MATCHES
          ? "High"
          : "Medium",
    };
  }

  return null;
}

function addDataTypeGuessCandidate(candidateScores, label, score) {
  const currentScore = candidateScores.get(label) || 0;
  if (score > currentScore) {
    candidateScores.set(label, score);
  }
}

function detectDataTypeGuessFromToken(token, candidateScores) {
  const normalizedToken = String(token || "").trim();
  if (!normalizedToken) return;

  if (/^\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}$/.test(normalizedToken)) {
    addDataTypeGuessCandidate(candidateScores, "bcrypt Hash", 99);
  }

  if (DATA_TYPE_GUESS_UUID_RE.test(normalizedToken)) {
    addDataTypeGuessCandidate(candidateScores, "UUID / GUID", 98);
  }

  if (DATA_TYPE_GUESS_JWT_RE.test(normalizedToken)) {
    addDataTypeGuessCandidate(candidateScores, "JWT Token", 95);
  }

  const cleanHex = normalizedToken
    .toLowerCase()
    .replace(/^0x/i, "")
    .replace(/[\s:]/g, "");
  const isLikelyHex = /^[0-9a-f]+$/.test(cleanHex);
  if (isLikelyHex) {
    switch (cleanHex.length) {
      case 32:
        addDataTypeGuessCandidate(candidateScores, "MD5 / NTLM Hash", 90);
        break;
      case 40:
        addDataTypeGuessCandidate(
          candidateScores,
          "SHA-1 / RIPEMD-160 Hash",
          90,
        );
        break;
      case 56:
        addDataTypeGuessCandidate(
          candidateScores,
          "SHA-224 / SHA3-224 Hash",
          90,
        );
        break;
      case 64:
        addDataTypeGuessCandidate(
          candidateScores,
          "SHA-256 / SHA3-256 Hash",
          90,
        );
        break;
      case 96:
        addDataTypeGuessCandidate(
          candidateScores,
          "SHA-384 / SHA3-384 Hash",
          90,
        );
        break;
      case 128:
        addDataTypeGuessCandidate(
          candidateScores,
          "SHA-512 / Whirlpool Hash",
          90,
        );
        break;
      default:
        if (cleanHex.length >= 8) {
          addDataTypeGuessCandidate(candidateScores, "Hexadecimal Data", 55);
        }
        break;
    }
  }

  const noWhitespace = normalizedToken.replace(/\s+/g, "");
  const alreadySpecific =
    isLikelyHex ||
    DATA_TYPE_GUESS_UUID_RE.test(normalizedToken) ||
    DATA_TYPE_GUESS_JWT_RE.test(normalizedToken);
  if (noWhitespace.length >= 4 && !alreadySpecific) {
    const hasBase64UrlChars = /[-_]/.test(noWhitespace);
    if (hasBase64UrlChars && /^[A-Za-z0-9_-]+$/.test(noWhitespace)) {
      addDataTypeGuessCandidate(candidateScores, "Base64URL Encoded Data", 80);
    } else if (/^[A-Za-z0-9+/]+=*$/.test(noWhitespace)) {
      addDataTypeGuessCandidate(
        candidateScores,
        "Base64 Encoded Data",
        noWhitespace.length % 4 === 0 ? 80 : 50,
      );
    }
  }
}

function scanAsciiTextForDataTypeGuesses(inputText, candidateScores) {
  const sourceText = String(inputText || "");
  if (!sourceText.trim()) return;
  addStructuredTextTypeGuesses(sourceText, candidateScores);

  const stepSize = Math.max(
    1,
    DATA_TYPE_GUESS_SCAN_CHUNK_SIZE - DATA_TYPE_GUESS_SCAN_OVERLAP,
  );
  for (let offset = 0; offset < sourceText.length; offset += stepSize) {
    const chunk = sourceText.slice(
      offset,
      offset + DATA_TYPE_GUESS_SCAN_CHUNK_SIZE,
    );
    if (/-----BEGIN PGP/.test(chunk)) {
      addDataTypeGuessCandidate(candidateScores, "PGP ASCII Armored Data", 100);
    }

    const chunkTokens = chunk.match(DATA_TYPE_GUESS_TOKEN_RE) || [];
    chunkTokens.forEach((token) => {
      detectDataTypeGuessFromToken(token, candidateScores);
    });
  }
}

function deriveDataTypeGuesses(rawInput, decodedAsciiInput = "") {
  const candidateScores = new Map();
  scanAsciiTextForDataTypeGuesses(rawInput, candidateScores);
  const normalizedRaw = String(rawInput || "");
  const normalizedDecoded = String(decodedAsciiInput || "");
  if (normalizedDecoded && normalizedDecoded !== normalizedRaw) {
    scanAsciiTextForDataTypeGuesses(normalizedDecoded, candidateScores);
  }
  return [...candidateScores.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([label, score]) => ({
      label,
      confidence: score >= 85 ? "High" : score >= 60 ? "Medium" : "Low",
    }));
}

function renderDataTypeGuesses(guesses) {
  const guessesEl = document.getElementById("data-tools-data-type-guesses");
  if (!guessesEl) return;
  guessesEl.innerHTML = "";
  const headerEl = document.createElement("span");
  headerEl.textContent = "Data Type Guesses:";
  guessesEl.appendChild(headerEl);
  if (!guesses || guesses.length === 0) {
    const noneEl = document.createElement("span");
    noneEl.textContent = " None";
    guessesEl.appendChild(noneEl);
    return;
  }
  guesses.forEach((guess, idx) => {
    const rowEl = document.createElement("div");
    rowEl.className = "data-tools-guess-item";
    rowEl.textContent = `${idx + 1}. ${guess.label} (${guess.confidence})`;
    guessesEl.appendChild(rowEl);
  });
}

function renderDataToolsLanguageGuess(languageGuess) {
  const languageEl = document.getElementById("data-tools-language-guess");
  if (!languageEl) return;
  languageEl.textContent = languageGuess
    ? `Text Language: ${languageGuess.label} (${languageGuess.confidence})`
    : "Text Language: Unknown";
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
  renderDataToolsLanguageGuess(null);
  renderDataTypeGuesses([]);
  document.getElementById("data-tools-entropy").textContent =
    "Shannon Entropy: 0.00 (Low)";
  resetHashOutputs();
  clearProtoDecoderOutput();
  clearDataToolsSelectionState();
  setExpandedConvertedOutput(null);
  updateDataToolsConvertedOutputVisibility();
}

function setExpandedConvertedOutput(expandedOutputId) {
  DATA_TOOLS_CONVERTED_OUTPUT_IDS.forEach((outputId) => {
    const outputEl = document.getElementById(outputId);
    if (!outputEl) return;
    const isExpanded = expandedOutputId === outputId;
    outputEl.classList.toggle("data-tools-output-expanded", isExpanded);
    outputEl.classList.toggle(
      "data-tools-output-collapsed",
      Boolean(expandedOutputId) && !isExpanded,
    );
  });
}

function bindConvertedOutputExpandHandlers() {
  DATA_TOOLS_CONVERTED_OUTPUT_IDS.forEach((outputId) => {
    const outputEl = document.getElementById(outputId);
    if (!outputEl || outputEl.dataset.expandBinding === "1") return;
    outputEl.dataset.expandBinding = "1";
    outputEl.addEventListener("click", () => {
      setExpandedConvertedOutput(outputId);
    });
  });
}

function updateDataToolsConvertedOutputVisibility() {
  const formatEl = document.getElementById("data-tools-format");
  const activeFormat = String(formatEl?.value || DEFAULT_DATA_TOOLS_FORMAT);

  Object.entries(DATA_TOOLS_OUTPUT_FORMAT_DETAILS).forEach(
    ([outputFormat, details]) => {
      const labelEl = document.querySelector(details.labelSelector);
      const outputEl = document.querySelector(details.outputSelector);
      const outputContainerEl =
        outputEl?.closest(".data-tools-highlight-wrap") || outputEl;
      const shouldShow = outputFormat !== activeFormat;

      if (labelEl) labelEl.hidden = !shouldShow;
      if (outputContainerEl) outputContainerEl.hidden = !shouldShow;
    },
  );
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

  document.getElementById("data-tools-md5-output").value = CryptoJS.MD5(
    wordArray,
  ).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha1-output").value = CryptoJS.SHA1(
    wordArray,
  ).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha256-output").value = CryptoJS.SHA256(
    wordArray,
  ).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha384-output").value = CryptoJS.SHA384(
    wordArray,
  ).toString(CryptoJS.enc.Hex);
  document.getElementById("data-tools-sha512-output").value = CryptoJS.SHA512(
    wordArray,
  ).toString(CryptoJS.enc.Hex);
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
  updateDataToolsConvertedOutputVisibility();

  try {
    const bytes = parseDataToolsInput(formatEl.value, inputEl.value);
    addDataToolsInputHistory(formatEl.value, inputEl.value);
    const hexValues = [...bytes].map((byte) =>
      byte.toString(16).padStart(2, "0").toUpperCase(),
    );
    const binaryValues = [...bytes].map((byte) =>
      byte.toString(2).padStart(8, "0"),
    );
    const decimalValues = [...bytes].map((byte) => String(byte));
    const hexSpaced = hexValues.join(" ");
    const binarySpaced = binaryValues.join(" ");
    const decimalBytes = decimalValues.join(" ");
    const asciiPreview = bytesToPrintableAscii(bytes);
    const inspectedText = decodeBytesForTextInspection(bytes);
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
    renderDataToolsLanguageGuess(
      guessReadableTextLanguage(
        formatEl.value === "ascii" ? inputEl.value : inspectedText,
        bytes,
      ),
    );
    // ASCII input has already been scanned as raw text; skip duplicate decoded scan.
    renderDataTypeGuesses(
      deriveDataTypeGuesses(
        inputEl.value,
        formatEl.value === "ascii" ? "" : inspectedText,
      ),
    );
    updateDataToolsSelectionMaps(formatEl.value, inputEl.value, bytes, {
      hexValues,
      binaryValues,
      decimalValues,
      asciiText: asciiPreview,
      base64Text: base64Value,
    });
    syncDataToolsSelectionFromField(
      document.activeElement &&
        DATA_TOOLS_SELECTION_FIELD_IDS.includes(document.activeElement.id)
        ? document.activeElement.id
        : "data-tools-input",
    );
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
  const requestMatch = firstLine.match(/^([A-Z]+)\s+(\S+)\s+(HTTP\/[\d.]+)$/);
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
          negotiations.push(
            `${cmdName} ${optionNames[opt] ?? `Option ${opt}`}`,
          );
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
  document.getElementById("prev-btn").style.display = "none";
  document.getElementById("next-btn").style.display = "none";
  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("stats_box").style.display = "none";
  document.getElementById("list_box").style.display = "none";
  document.getElementById("notes_box").style.display = "none";
  document.getElementById("crypt_box").style.display = "none";
  document.getElementById("keystore_box").style.display = "none";
  document.getElementById("rightside").style.display = "none";
  document.getElementById("data_tools_box").style.display = "flex";
  setConvSubtab(tabName);
}

function showNotesWorkspace() {
  activeMainTab = MAIN_TAB_NOTES;
  statusUpdate("Status: Displaying session notes");
  writeLogEntry("User opened notes workspace");
  document.getElementById("prev-btn").style.display = "none";
  document.getElementById("next-btn").style.display = "none";
  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("stats_box").style.display = "none";
  document.getElementById("list_box").style.display = "none";
  document.getElementById("data_tools_box").style.display = "none";
  document.getElementById("crypt_box").style.display = "none";
  document.getElementById("keystore_box").style.display = "none";
  document.getElementById("notes_box").style.display = "flex";
  document.getElementById("rightside").style.display = "block";
  const rightsideDataEl = document.getElementById("rightside-data");
  const rightsideNotesEl = document.getElementById("rightside-notes");
  if (rightsideDataEl) rightsideDataEl.hidden = true;
  if (rightsideNotesEl) rightsideNotesEl.hidden = false;
  renderNotesList();
}

function getFirstLineOrFallback(elementId, fallback = "") {
  const text = document.getElementById(elementId)?.textContent || "";
  const firstLine = text.split("\n")[0]?.trim();
  return firstLine || fallback;
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
  addSessionKeystoreEntry: (...args) =>
    keystorePanel.addSessionKeystoreEntry(...args),
  getFirstLineOrFallback,
  sendDecryptedToConv: ({ hexValue, utf8Value, sourceLabel }) => {
    const inputEl = document.getElementById("data-tools-input");
    const formatEl = document.getElementById("data-tools-format");
    const normalizedHex = String(hexValue || "").trim();
    const normalizedUtf8 = String(utf8Value || "");
    if (normalizedHex) {
      inputEl.value = normalizedHex;
      formatEl.value = "hex";
    } else {
      inputEl.value = normalizedUtf8;
      formatEl.value = "ascii";
    }
    showDataTools(CONV_CONVERSIONS_SUBTAB);
    runDataToolsConversion();
  },
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
  decryptActiveEntryWithLoadedKey,
  sendDecryptedPayloadToConvTab,
  clearCryptDecryptionOutput,
} = cryptPanel;

const listPanel = createListPanel({
  constants: {
    MAIN_TAB_LIST,
  },
  getJsonCapture: () => jsonCapture,
  getCapturedPackets: () => capturedPackets,
  getBookmarkList: () => bookmarkList,
  setActiveMainTab: (tabName) => {
    activeMainTab = tabName;
  },
  statusUpdate,
  writeLogEntry,
  hostFilterEl,
  filterInputEl,
  syncFilterHighlight,
  runFilterQuery,
  getFilteredPackets: () => filteredPackets,
  setPacketsForHost: (packets) => {
    packetsForHost = packets;
  },
  setIndex: (nextIndex) => {
    index = nextIndex;
  },
  setCurrentIp: (nextCurrentIp) => {
    currentIp = nextCurrentIp;
  },
  setCurrentPacketKey: (packetKey) => {
    currentPacketKey = packetKey;
  },
  syncBookmarkDropdown,
  setActivePacketCursor,
  showAllData,
  infoPanel,
  popHexGrid,
  populateDataTypes,
});

const { showPacketList } = listPanel;
let activeContextConversionText = "";
let activeContextTarget = null;
let activeContextPasteTarget = null;
let activeContextFilterQueries = {};
let activeContextCookieJarText = "";
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
  deriveGuess: getCachedElement("convert-context-derive-guess"),
  loadCursorAscii: getCachedElement("convert-context-load-cursor-ascii"),
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
  keystorePasswordPersistent: getCachedElement(
    "ctx-keystore-password-persistent",
  ),
  keystoreKeySession: getCachedElement("ctx-keystore-key-session"),
  keystoreKeyPersistent: getCachedElement("ctx-keystore-key-persistent"),
  keystoreCertSession: getCachedElement("ctx-keystore-cert-session"),
  keystoreCertPersistent: getCachedElement("ctx-keystore-cert-persistent"),
  keystoreCookieSession: getCachedElement("ctx-keystore-cookie-session"),
  keystoreCookiePersistent: getCachedElement("ctx-keystore-cookie-persistent"),
  keystoreUriSession: getCachedElement("ctx-keystore-uri-session"),
  keystoreUriPersistent: getCachedElement("ctx-keystore-uri-persistent"),
  copyCookieJar: getCachedElement("ctx-copy-cookie-jar"),
  saveCookieJar: getCachedElement("ctx-save-cookie-jar"),
  notesSendData: getCachedElement("ctx-notes-send-data"),
  notesSendConvOutput: getCachedElement("ctx-notes-send-conv-output"),
  notesSendConvHashes: getCachedElement("ctx-notes-send-conv-hashes"),
  httpFileSave: getCachedElement("ctx-http-file-save"),
  httpFileLoad: getCachedElement("ctx-http-file-load"),
  httpFilePreview: getCachedElement("ctx-http-file-preview"),
  followStreamConv: getCachedElement("ctx-follow-stream-conv"),
  followStreamCrypt: getCachedElement("ctx-follow-stream-crypt"),
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
  notes: getCachedElement("ctx-notes-submenu"),
  export: getCachedElement("ctx-export-submenu"),
  keystore: getCachedElement("ctx-keystore-submenu"),
  keystorePassword: getCachedElement("ctx-keystore-password-submenu"),
  keystoreKey: getCachedElement("ctx-keystore-key-submenu"),
  keystoreCert: getCachedElement("ctx-keystore-cert-submenu"),
  keystoreCookie: getCachedElement("ctx-keystore-cookie-submenu"),
  keystoreUri: getCachedElement("ctx-keystore-uri-submenu"),
  httpFile: getCachedElement("ctx-http-file-submenu"),
  followStream: getCachedElement("ctx-follow-stream-submenu"),
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
    const submenuPanelEl = submenuEl.querySelector(
      ":scope > .ctx-submenu-panel",
    );
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
    const fieldName = String(field?.name || "")
      .trim()
      .toLowerCase();
    const fieldValue =
      typeof field?.value === "string" ? field.value.trim() : "";
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
  openExternalUrl: (url) => window.browserapi.openExternalUrl(url),
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
      getActiveDataToolsProtoResult()?.protocol === "HTTP"
        ? buildCookieJarTextFromHttpFields(
          getActiveDataToolsProtoResult().fields,
        )
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
    showManualKeystoreUri = false,
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
  const currentPayloadHex = getCurrentRawPayloadHex();
  const hasPayloadToExport = Boolean(currentPayloadHex);
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
  const hasDeriveGuessInput = Boolean(
    (sourceText || "").trim() || getTrimmedSelectionText(),
  );
  convertContextButtons.deriveGuess.style.display = hasDeriveGuessInput
    ? "block"
    : "none";
  const cursorByteIndex = Number.parseInt(
    target?.dataset?.byteIndex ?? "-1",
    10,
  );
  const hasCursorAsciiValue = Boolean(
    target?.classList?.contains("griditem") &&
    getCursorAsciiContextLoadData(currentPayloadHex, cursorByteIndex),
  );
  convertContextButtons.loadCursorAscii.style.display = hasCursorAsciiValue
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
  const hasContextDataForNotes = Boolean(
    (sourceText && sourceText.trim()) || getTrimmedSelectionText(),
  );
  const hasConvOutputForNotes = Boolean(buildConvConvertedOutputNoteText());
  const hasConvHashesForNotes = Boolean(buildConvHashesNoteText());
  convertContextButtons.notesSendData.style.display = hasContextDataForNotes
    ? "block"
    : "none";
  convertContextButtons.notesSendConvOutput.style.display =
    hasConvOutputForNotes ? "block" : "none";
  convertContextButtons.notesSendConvHashes.style.display =
    hasConvHashesForNotes ? "block" : "none";
  const hasNotesActions =
    hasContextDataForNotes || hasConvOutputForNotes || hasConvHashesForNotes;
  const hasCopyActions =
    showCopySelection || isHexViewTarget || hasCookieActions;
  const hasClipboardActions = hasCopyActions || showPaste;
  const hasGeneralActions = hasClipboardActions;
  const hasDataTypeActions =
    formats.length > 0 ||
    hasPayloadToExport ||
    hasCursorAsciiValue ||
    hasDeriveGuessInput;
  const hasFilterActions = Object.values(filterQueries).some(Boolean);
  const hasContextTextKeystoreActions =
    showCopySelection || Boolean(sourceText);
  const hasKeystoreActions =
    hasContextTextKeystoreActions || showManualKeystoreUri;
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
  convertContextSubmenus.notes.style.display = hasNotesActions
    ? "block"
    : "none";
  convertContextSubmenus.keystore.style.display = hasKeystoreActions
    ? "block"
    : "none";
  convertContextSubmenus.keystorePassword.style.display =
    hasContextTextKeystoreActions ? "block" : "none";
  convertContextSubmenus.keystoreKey.style.display =
    hasContextTextKeystoreActions ? "block" : "none";
  convertContextSubmenus.keystoreCert.style.display =
    hasContextTextKeystoreActions ? "block" : "none";
  convertContextSubmenus.keystoreCookie.style.display =
    hasContextTextKeystoreActions ? "block" : "none";
  convertContextSubmenus.keystoreUri.style.display = showManualKeystoreUri
    ? "block"
    : "none";
  convertContextSubmenus.export.style.display = hasExportActions
    ? "block"
    : "none";
  convertContextSubmenus.httpFile.style.display = hasHttpBody
    ? "block"
    : "none";
  const hasFollowStreamActions = Boolean(getCurrentStreamTuple());
  convertContextSubmenus.followStream.style.display = hasFollowStreamActions
    ? "block"
    : "none";
  if (
    !hasGeneralActions &&
    !hasDataTypeActions &&
    !isHexViewTarget &&
    !hasFilterActions &&
    !hasCookieActions &&
    !hasNotesActions &&
    !hasKeystoreActions &&
    !hasExportActions &&
    !hasHttpBody &&
    !hasFollowStreamActions
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

function deriveContextSelectionGuessFromContextMenu() {
  const selectedText =
    getTrimmedSelectionText() || (activeContextConversionText || "").trim();
  hideConvertContextMenu();
  if (!selectedText) {
    statusUpdate("Status: No selected/context text available to derive guess");
    return;
  }
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  inputEl.value = selectedText;
  formatEl.value = "ascii";
  showDataTools();
  runDataToolsConversion();
  writeLogEntry("Derived data type guess from selected/context data");
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

function getCursorAsciiContextLoadData(payloadHex, byteIndex) {
  if (byteIndex < 0 || !payloadHex) return null;
  const decodedAscii = hexToAscii(payloadHex);
  let printableSequence = "";
  for (let i = byteIndex; i < decodedAscii.length; i++) {
    const charCode = decodedAscii.charCodeAt(i);
    if (!isPrintable(charCode)) break;
    printableSequence += decodedAscii[i];
  }
  if (printableSequence) {
    return { value: printableSequence, format: "ascii" };
  }
  const hexOffset = byteIndex * 2;
  const hexPair = payloadHex.slice(hexOffset, hexOffset + 2);
  if (hexPair.length !== 2 || !/^[0-9A-Fa-f]{2}$/.test(hexPair)) return null;
  return { value: hexPair.toUpperCase(), format: "hex" };
}

function loadCursorAsciiIntoDataToolsFromContextMenu() {
  const payloadHex = getCurrentRawPayloadHex();
  const byteIndex = Number.parseInt(
    activeContextTarget?.dataset?.byteIndex ?? "-1",
    10,
  );
  const cursorAsciiLoadData = getCursorAsciiContextLoadData(
    payloadHex,
    byteIndex,
  );
  hideConvertContextMenu();
  if (!cursorAsciiLoadData) {
    statusUpdate("Status: No cursor ASCII value available to load");
    return;
  }
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  inputEl.value = cursorAsciiLoadData.value;
  formatEl.value = cursorAsciiLoadData.format;
  showDataTools();
  runDataToolsConversion();
  writeLogEntry(
    `Context conversion loaded cursor ASCII into Conv tab format=${cursorAsciiLoadData.format}`,
  );
}

function getActivePacketCursor() {
  return Number.isInteger(activePacketCursor) && activePacketCursor >= 0
    ? activePacketCursor
    : null;
}

/**
 * Returns the total number of packets across all hosts in capturedPackets.
 * Used to decide whether to show the stream-loading overlay.
 */
function getTotalPacketCount() {
  const hosts = capturedPackets?.["Host"];
  if (!hosts || typeof hosts !== "object") return 0;
  return Object.values(hosts).reduce(
    (sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0),
    0,
  );
}

// Minimum total-packet count that triggers the stream-loading overlay.
// getFollowStreamPackets() iterates every packet across all hosts, so captures
// with ~500+ packets produce a noticeable pause without the overlay.
const STREAM_LOADING_THRESHOLD = 50;

/**
 * Shows the loading-container overlay with a stream-specific message.
 * The caller is responsible for hiding it with hideStreamLoadingOverlay().
 */
function showStreamLoadingOverlay() {
  const loadingTextEl = document.getElementById("loading-text");
  const loadingContainerEl = document.getElementById("loading-container");
  if (loadingTextEl) loadingTextEl.textContent = "Preparing stream...";
  if (loadingContainerEl) loadingContainerEl.style.display = "block";
}

/** Hides the loading-container overlay shown by showStreamLoadingOverlay(). */
function hideStreamLoadingOverlay() {
  const loadingContainerEl = document.getElementById("loading-container");
  if (loadingContainerEl) loadingContainerEl.style.display = "none";
}

/**
 * Returns metadata about the current packet's stream (4-tuple: srcIp, srcPort,
 * dstIp, dstPort, protocol), or null if no current packet is loaded.
 */
function getCurrentStreamTuple() {
  const cursor = getActivePacketCursor();
  if (cursor === null) return null;
  const packetInfo = packetsForHost?.[cursor]?.["Packet Info"];
  if (!packetInfo) return null;
  const srcIp = packetInfo["IP"]?.["Source IP"];
  const dstIp = packetInfo["IP"]?.["Destination IP"];
  const protocol = packetInfo["Protocol"] || "TCP";
  const transportData = packetInfo[protocol] || {};
  const srcPort = transportData["Source port"] ?? null;
  const dstPort = transportData["Destination port"] ?? null;
  if (!srcIp || !dstIp) return null;
  return { srcIp, srcPort, dstIp, dstPort, protocol };
}

/**
 * Collects all packets across all hosts in capturedPackets that belong to the
 * same bidirectional conversation as the current packet, sorted by timestamp.
 * Returns an array of packet objects, or [] when no stream can be determined.
 */
function getFollowStreamPackets() {
  const tuple = getCurrentStreamTuple();
  if (!tuple) return [];
  const { srcIp, srcPort, dstIp, dstPort, protocol } = tuple;
  const hasPorts = srcPort !== null && dstPort !== null;
  const matches = [];
  const hosts = capturedPackets?.["Host"];
  if (!hosts || typeof hosts !== "object") return [];
  for (const host of Object.values(hosts)) {
    if (!Array.isArray(host)) continue;
    for (const pkt of host) {
      const pi = pkt?.["Packet Info"];
      if (!pi) continue;
      const pProto = pi["Protocol"] || "TCP";
      if (pProto !== protocol) continue;
      const pSrcIp = pi["IP"]?.["Source IP"];
      const pDstIp = pi["IP"]?.["Destination IP"];
      if (!pSrcIp || !pDstIp) continue;
      const pTransport = pi[pProto] || {};
      const pSrcPort = pTransport["Source port"] ?? null;
      const pDstPort = pTransport["Destination port"] ?? null;
      const forwardMatch =
        pSrcIp === srcIp &&
        pDstIp === dstIp &&
        (!hasPorts || (pSrcPort === srcPort && pDstPort === dstPort));
      const reverseMatch =
        pSrcIp === dstIp &&
        pDstIp === srcIp &&
        (!hasPorts || (pSrcPort === dstPort && pDstPort === srcPort));
      if (forwardMatch || reverseMatch) {
        matches.push(pkt);
      }
    }
  }
  // Sort by packet timestamp, falling back to Index for stable ordering.
  matches.sort((a, b) => {
    const tsA = a?.["Packet Info"]?.["Packet Timestamp"] ?? "";
    const tsB = b?.["Packet Info"]?.["Packet Timestamp"] ?? "";
    if (tsA < tsB) return -1;
    if (tsA > tsB) return 1;
    const idxA = Number(a?.["Packet Info"]?.["Index"] ?? 0);
    const idxB = Number(b?.["Packet Info"]?.["Index"] ?? 0);
    return idxA - idxB;
  });
  return matches;
}

/**
 * Returns a hex string with all payloads from the stream concatenated, and a
 * summary label for logging.  Returns null when no payload data is found.
 */
function buildStreamHex(streamPackets) {
  if (!streamPackets.length) return null;
  let combined = "";
  for (const pkt of streamPackets) {
    const payloadHex =
      pkt?.["Packet Info"]?.["Raw data"]?.["Payload"]?.["Hex Encoded"];
    if (typeof payloadHex === "string" && payloadHex.length > 0) {
      combined += payloadHex;
    }
  }
  return combined || null;
}

function followStreamToConv() {
  hideConvertContextMenu();
  const isLarge = getTotalPacketCount() >= STREAM_LOADING_THRESHOLD;
  if (isLarge) {
    showStreamLoadingOverlay();
    setTimeout(() => {
      try {
        _doFollowStreamToConv();
      } finally {
        hideStreamLoadingOverlay();
      }
    }, 0);
  } else {
    _doFollowStreamToConv();
  }
}

function _doFollowStreamToConv() {
  const streamPackets = getFollowStreamPackets();
  if (!streamPackets.length) {
    statusUpdate("Status: No stream packets found for current packet");
    return;
  }
  const combinedHex = buildStreamHex(streamPackets);
  if (!combinedHex) {
    statusUpdate("Status: Stream packets have no payload data");
    return;
  }
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  inputEl.value = combinedHex;
  formatEl.value = "hex";
  showDataTools();
  runDataToolsConversion();
  writeLogEntry(
    `Follow stream loaded ${streamPackets.length} packets into Conv tab`,
  );
}

function followStreamToCrypt() {
  hideConvertContextMenu();
  const isLarge = getTotalPacketCount() >= STREAM_LOADING_THRESHOLD;
  if (isLarge) {
    showStreamLoadingOverlay();
    setTimeout(() => {
      try {
        _doFollowStreamToCrypt();
      } finally {
        hideStreamLoadingOverlay();
      }
    }, 0);
  } else {
    _doFollowStreamToCrypt();
  }
}

function _doFollowStreamToCrypt() {
  const streamPackets = getFollowStreamPackets();
  if (!streamPackets.length) {
    statusUpdate("Status: No stream packets found for current packet");
    return;
  }
  const combinedHex = buildStreamHex(streamPackets);
  if (!combinedHex) {
    statusUpdate("Status: Stream packets have no payload data");
    return;
  }
  let asciiContent;
  try {
    asciiContent = hexToAscii(combinedHex);
  } catch {
    statusUpdate("Status: Could not convert stream payload to ASCII");
    return;
  }
  const certInputEl = document.getElementById("crypt-cert-input");
  const certPreviewEl = document.getElementById("crypt-cert-preview");
  if (certInputEl) certInputEl.value = asciiContent;
  if (certPreviewEl) {
    certPreviewEl.textContent = `Stream data: ${streamPackets.length} packets, ${Math.round(combinedHex.length / 2)} bytes`;
  }
  showCryptWorkspace();
  writeLogEntry(
    `Follow stream loaded ${streamPackets.length} packets into Crypt tab`,
  );
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
        "Status: HTTP body preview failed – " +
        (errorMessage || "unknown error"),
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

initConvPanel({
  writeLogEntry,
  statusUpdate,
  setActiveMainTab: (tab) => {
    activeMainTab = tab;
  },
});
initializeNotesPanel();
document.getElementById("close-btn").addEventListener("click", () => {
  void requestApplicationClose();
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

document
  .getElementById("keystore-btn")
  .addEventListener("click", async function () {
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
  .getElementById("crypt-keystore-unlock-reset-btn")
  .addEventListener("click", keystorePanel.requestPersistentKeystoreReset);
document
  .getElementById("crypt-keystore-unlock-cancel-btn")
  .addEventListener("click", () =>
    keystorePanel.resolveKeystoreUnlockPassword(null),
  );
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
document
  .getElementById("crypt-keystore-manual-uri-confirm-btn")
  .addEventListener(
    "click",
    keystorePanel.submitManualUriFromContextMenuDialog,
  );
document
  .getElementById("crypt-keystore-manual-uri-cancel-btn")
  .addEventListener("click", () =>
    keystorePanel.resolveManualUriFromContextMenuDialog(null),
  );
document
  .getElementById("crypt-keystore-manual-uri-input")
  .addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    keystorePanel.submitManualUriFromContextMenuDialog();
  });

// Show packet list when list button is clicked
document.getElementById("list-btn").addEventListener("click", function () {
  if (!isFileLoaded) {
    doError("Please upload a JSON file before accessing the packet list.");
    return;
  }
  showPacketList();
});
document.getElementById("notes-btn").addEventListener("click", function () {
  if (!isFileLoaded) {
    doError("Please upload a JSON file before accessing notes.");
    return;
  }
  showNotesWorkspace();
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
document
  .getElementById("crypt-clear-cert-btn")
  .addEventListener("click", () => {
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
  .getElementById("crypt-decrypt-entry-btn")
  .addEventListener("click", decryptActiveEntryWithLoadedKey);
document
  .getElementById("crypt-send-decrypted-conv-btn")
  .addEventListener("click", sendDecryptedPayloadToConvTab);
document
  .getElementById("crypt-clear-decrypted-btn")
  .addEventListener("click", clearCryptDecryptionOutput);

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
document.getElementById("crypt-open-link-btn").addEventListener("click", () => {
  void keystorePanel.openSelectedKeystoreLinkInBrowser();
});
document
  .getElementById("crypt-reset-keystore-password-btn")
  .addEventListener("click", () => {
    void keystorePanel.resetPersistentKeystorePassword();
  });

document
  .getElementById("data-tools-convert-btn")
  .addEventListener("click", runDataToolsConversion);
bindConvertedOutputExpandHandlers();
updateDataToolsConvertedOutputVisibility();
document.getElementById("data-tools-input").addEventListener("input", () => {
  dataToolsHistorySelectEl.value = "";
  updateDataToolsHexHighlights();
  syncDataToolsHighlightScroll(
    "data-tools-input",
    "data-tools-input-highlight",
  );
});
document.getElementById("data-tools-format").addEventListener("change", () => {
  dataToolsHistorySelectEl.value = "";
  updateDataToolsConvertedOutputVisibility();
  updateDataToolsHexHighlights();
});
document.getElementById("data-tools-input").addEventListener("scroll", () => {
  syncDataToolsHighlightScroll(
    "data-tools-input",
    "data-tools-input-highlight",
  );
});
// Prevent drag-and-drop from editing the Conv input; keyboard editing remains unaffected.
document
  .getElementById("data-tools-input")
  .addEventListener("dragstart", (event) => {
    event.preventDefault();
  });
document
  .getElementById("data-tools-input")
  .addEventListener("drop", (event) => {
    event.preventDefault();
  });
document
  .getElementById("data-tools-hex-output")
  .addEventListener("scroll", () => {
    syncDataToolsHighlightScroll(
      "data-tools-hex-output",
      "data-tools-hex-output-highlight",
    );
  });
document
  .getElementById("data-tools-hex-output")
  .addEventListener("dragstart", (event) => {
    event.preventDefault();
  });
for (const fieldId of DATA_TOOLS_SELECTION_FIELD_IDS) {
  const el = document.getElementById(fieldId);
  if (!el) continue;
  const syncFromField = () => syncDataToolsSelectionFromField(fieldId);
  el.addEventListener("select", syncFromField);
  el.addEventListener("mouseup", syncFromField);
  el.addEventListener("keyup", syncFromField);
}
document
  .getElementById("data-tools-hash-input-reading")
  .addEventListener("input", runDataToolsHashesFromInput);
document
  .getElementById("data-tools-clear-btn")
  .addEventListener("click", () => {
    dataToolsHistorySelectEl.value = "";
    document.getElementById("data-tools-input").value = "";
    document.getElementById("data-tools-error").textContent = "";
    resetDataToolsOutputs();
    updateDataToolsHexHighlights();
  });
dataToolsHistorySelectEl.addEventListener("change", () => {
  const selectedIndex = Number(dataToolsHistorySelectEl.value);
  if (!Number.isInteger(selectedIndex) || selectedIndex < 0) return;
  const selectedEntry = dataToolsInputHistory[selectedIndex];
  if (!selectedEntry) return;
  document.getElementById("data-tools-format").value = selectedEntry.format;
  document.getElementById("data-tools-input").value = selectedEntry.input;
  updateDataToolsHexHighlights();
  syncDataToolsHighlightScroll(
    "data-tools-input",
    "data-tools-input-highlight",
  );
  runDataToolsConversion();
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
convertContextButtons.deriveGuess.addEventListener("click", () => {
  deriveContextSelectionGuessFromContextMenu();
});
convertContextButtons.loadPayload.addEventListener("click", () => {
  loadRawPayloadIntoDataToolsFromContextMenu();
});
convertContextButtons.loadCursorAscii.addEventListener("click", () => {
  loadCursorAsciiIntoDataToolsFromContextMenu();
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
convertContextButtons.notesSendData.addEventListener("click", () => {
  const selectedText = getTrimmedSelectionText();
  sendTextToNotesFromContextMenu(
    selectedText || activeContextConversionText,
    "context-data",
  );
});
convertContextButtons.notesSendConvOutput.addEventListener("click", () => {
  sendTextToNotesFromContextMenu(
    buildConvConvertedOutputNoteText(),
    "context-conv-output",
  );
});
convertContextButtons.notesSendConvHashes.addEventListener("click", () => {
  sendTextToNotesFromContextMenu(
    buildConvHashesNoteText(),
    "context-conv-hashes",
  );
});
convertContextButtons.keystorePasswordSession.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu(
    "password",
    CRYPT_KEYSTORE_MODE_SESSION,
  );
});
convertContextButtons.keystorePasswordPersistent.addEventListener(
  "click",
  () => {
    keystorePanel.addToKeystoreFromContextMenu(
      "password",
      CRYPT_KEYSTORE_MODE_PERSISTENT,
    );
  },
);
convertContextButtons.keystoreKeySession.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu(
    "key",
    CRYPT_KEYSTORE_MODE_SESSION,
  );
});
convertContextButtons.keystoreKeyPersistent.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu(
    "key",
    CRYPT_KEYSTORE_MODE_PERSISTENT,
  );
});
convertContextButtons.keystoreCertSession.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu(
    "cert",
    CRYPT_KEYSTORE_MODE_SESSION,
  );
});
convertContextButtons.keystoreCertPersistent.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu(
    "cert",
    CRYPT_KEYSTORE_MODE_PERSISTENT,
  );
});
convertContextButtons.keystoreCookieSession.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu(
    "cookie",
    CRYPT_KEYSTORE_MODE_SESSION,
  );
});
convertContextButtons.keystoreCookiePersistent.addEventListener("click", () => {
  keystorePanel.addToKeystoreFromContextMenu(
    "cookie",
    CRYPT_KEYSTORE_MODE_PERSISTENT,
  );
});
convertContextButtons.keystoreUriSession.addEventListener("click", () => {
  void keystorePanel.addManualUriToKeystoreFromContextMenu(
    CRYPT_KEYSTORE_MODE_SESSION,
  );
});
convertContextButtons.keystoreUriPersistent.addEventListener("click", () => {
  void keystorePanel.addManualUriToKeystoreFromContextMenu(
    CRYPT_KEYSTORE_MODE_PERSISTENT,
  );
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
convertContextButtons.followStreamConv.addEventListener(
  "click",
  followStreamToConv,
);
convertContextButtons.followStreamCrypt.addEventListener(
  "click",
  followStreamToCrypt,
);

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
  if (
    !Array.isArray(packetSet) ||
    !packetKey ||
    typeof packetKey !== "string"
  ) {
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
  document.getElementById("prev-btn").style.display = "block";
  document.getElementById("next-btn").style.display = "block";
  document.getElementById("loading-container").style.display = "none";
  document.getElementById("summary_box").style.display = "none";
  document.getElementById("stats_box").style.display = "none";
  document.getElementById("list_box").style.display = "none";
  document.getElementById("notes_box").style.display = "none";
  document.getElementById("data_tools_box").style.display = "none";
  document.getElementById("crypt_box").style.display = "none";
  document.getElementById("keystore_box").style.display = "none";
  document.getElementById("packetInfoPane").style.display = "block";
  document.getElementById("packetPayloadPane").style.display = "block";
  document.getElementById("welcome").style.display = "none";
  showAllData();
  const rightsideDataEl = document.getElementById("rightside-data");
  const rightsideNotesEl = document.getElementById("rightside-notes");
  if (rightsideDataEl) rightsideDataEl.hidden = false;
  if (rightsideNotesEl) rightsideNotesEl.hidden = true;

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
    const packetIndexFromKey = findPacketIndexByKey(
      packetSet,
      previousPacketKey,
    );
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

// Export session to a user-chosen file location
document.getElementById("export-session-btn").addEventListener("click", function () {
  void exportSessionToFile();
});

// Open the session library picker
const sessionsLibraryBtn = document.getElementById("sessions-library-btn");
if (sessionsLibraryBtn) {
  sessionsLibraryBtn.addEventListener("click", () => {
    if (sessionPickerPanel) sessionPickerPanel.show();
  });
}

// the next two have hooks into IPC handlers for main.js
// data transactions

// when the main.js returns our json data from snitch.py
window.jsonapi.onJsonData((jsonData) => {
  document.getElementById("loading-container").style.display = "block";
  document.getElementById("error-container").style.display = "none";
  statusUpdate("Loaded data from backend, processing...");
  writeLogEntry("Backend JSON payload received for processing");
  // Clear library session name – this is a new PCAP capture, not a library session
  currentSessionName = null;
  processFile(
    new File([jsonData], "capture.json", { type: "application/json" }),
  );
  const loadEndTime = performance.now();
  document.getElementById("load-time").textContent =
    "Load time: " + ((loadEndTime - startTime) / 1000).toFixed(2) + " seconds";
  document.getElementById("total-packets").textContent =
    "Total Packets: " + totalPacketCount();
  writeLogEntry(
    `Completed processing backend data total_packets=${totalPacketCount()} load_time_sec=${(
      (loadEndTime - startTime) /
      1000
    ).toFixed(2)}`,
  );
  filterInputEl.value = "";
  updateFilterClearButtonState();
  clearFilterQuery();
  syncFilterHighlight();
  if (capturedPackets && capturedPackets["Host"] && capturedPackets["Host"][hostFilterEl.value] !== "0.0.0.0") {
    runFilterQuery("");
  }
  statusUpdate("Status: Ready");
});

// here we create the backend process and hook it to the handler
function runSnitch(file) {
  document.getElementById("loading-screen").style.display = "block";
  document.getElementById("loading-container").style.display = "block";
  showSummaryLoading();
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
    .then((output) => { })
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
  clearSummaryContent();
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
  // check if packets were returned
  if (!filteredPackets || filteredPackets.length === 0) {
    doError("No packets match the filter criteria!");
    statusUpdate("Status: No packets match the filter criteria");
  }
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
renderDataToolsInputHistory();
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
  updateDataToolsHexHighlights();
  syncDataToolsHighlightScroll(
    "data-tools-input",
    "data-tools-input-highlight",
  );
  syncDataToolsHighlightScroll(
    "data-tools-hex-output",
    "data-tools-hex-output-highlight",
  );
  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  document.getElementById("rightside").style.display = "none";
  const rightsideDataEl = document.getElementById("rightside-data");
  const rightsideNotesEl = document.getElementById("rightside-notes");
  if (rightsideDataEl) rightsideDataEl.hidden = false;
  if (rightsideNotesEl) rightsideNotesEl.hidden = true;
  document.getElementById("leftside").style.display = "none";
  document.getElementById("loading-container").style.display = "none";
};
