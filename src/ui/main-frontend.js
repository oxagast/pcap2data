const threadName = "MainFrontend";
import { bookmarkList } from '../state';
import "../assets/css/style.css";
const CryptoJS = require("crypto-js");
const { sha3_256, sha3_512 } = require("js-sha3");
const whirlpool = require("whirlpool-js");
const { validateFilterSyntax } = require("../filter");
const { initializeLogging } = require("../logging");
const { initializeContextMenu } = require("./context-menu");
const {
  createTable,
  renderDnsTable,
  renderIcmpTable,
  renderIgmpTable,
  renderArpTable,
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
  renderWebSocketTable,
  renderNfsTable,
  renderKerberosTable,
  renderSshTable,
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
  CONV_PACKET_JSON_SUBTAB,
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
const goodiesArray = window.goodiesapi.getGoodies().then((goodies) => {
  console.log(`Loaded ${goodies.length} goodies from preload API`);
});

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
const DATA_TYPES_DEFAULT_HIDDEN_PROTOCOLS = new Set([
  "ARP",
  "RARP",
  "IGMP",
  "ICMP",
  "DHCP",
  "DNS",
  "NTP",
  "BOOTPC",
  "BOOTPS",
  "FRAME",
  "ATM",
  "PPP",
  "BGP",
]);
const DATA_TYPES_DEFAULT_HIDDEN_PROTOCOL_PREFIXES = [
  "BOOTP",
  "DHCP",
  "DNS",
  "NTP",
  "ICMP",
  "IGMP",
  "ARP",
  "RARP",
  "ATM",
  "PPP",
  "FRAME",
  "BGP",
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
const DUMMY_ALL_HOST = "0.0.0.0";
const DUMMY_ALL_HOST_ALIAS = "All Hosts";
const DUMMY_BOOKMARKED_HOST = "__BOOKMARKED__";
const DUMMY_BOOKMARKED_HOST_ALIAS = "Bookmarked";
const BOOKMARK_FILTER_QUERY = "bookmark: true";

// Global variables for DOM elements and state
let capturedPackets = {}; // Stores parsed packet data from JSON
let jsonCapture = ""; // Stringified JSON capture for pretty display
let currentIp;
let finalSummary = ""; // Stores the summary section from JSON
const status = getCachedElement("status"); // Status bar element
let hostsList = [DUMMY_ALL_HOST]; // List of hosts found in capture
const hostFilterEl = getCachedElement("host_filter"); // Host filter dropdown
let p = []; // Packets for the currently selected host
let index = 0; // Navigation index for packets
let activePacketCursor = 0;
//let bookmarkList = []; // List of bookmarks (host:packet index)
let retransmissionList = []; // List of packets marked as retransmissions
let outOfOrderList = []; // List of packets marked as out-of-order
let activeBookmark = {}; // Current bookmark object
let isFileLoaded = false;
let jsonOfPackets;
let streamProtocol = null;
let filteredPackets;
let currentPacketKey;
let lastFilteredNavigationLogMessage = "";
let startTime;
let helpOpen = false;
let helpWin = null;
const packetStubByKey = new Map();
const hydratedPacketCache = new Map();
const HYDRATED_PACKET_CACHE_LIMIT = 8;
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
const BACKEND_PACKET_CHUNK_SIZE = 250;
const SESSION_AUTOSAVE_INTERVAL_MS = 5 * 60 * 1000;
let backendCaptureUpdateQueue = Promise.resolve();
let sessionAutosaveInFlight = false;
let keystoreAutoPopulateGeneration = 0;
let dataTypesOverridePacketKey = null;
const backendProgressState = {
  firstChunkLoaded: false,
  processing: false,
  processedPackets: 0,
  totalPackets: 0,
};
let sessionPcapSource = null;

function scheduleSessionKeychainAutoPopulate(reason = "startup") {
  const generation = ++keystoreAutoPopulateGeneration;
  const runAutoPopulate = async () => {
    try {
      statusUpdate("Status: Auto-populating keychain from packet data...");
      const keystoreEntryCount = await keystorePanel.rebuildSessionEntries();
      if (generation !== keystoreAutoPopulateGeneration) return;
      writeLogEntry(
        `Session keychain auto-populated entries=${keystoreEntryCount} reason=${reason}`,
      );
      statusUpdate("Status: Session keychain auto-populated");
    } catch (error) {
      if (generation !== keystoreAutoPopulateGeneration) return;
      logErrorEntry("session-keystore-autopopulate", error);
      statusUpdate("Status: Session keychain auto-populate failed");
    }
  };

  if (typeof window.requestIdleCallback === "function") {
    window.requestIdleCallback(() => {
      void runAutoPopulate();
    }, { timeout: 1000 });
    return;
  }

  window.setTimeout(() => {
    void runAutoPopulate();
  }, 0);
}

function estimateBase64DecodedByteLength(base64Data) {
  const normalized = typeof base64Data === "string"
    ? base64Data.replace(/\s+/g, "")
    : "";
  if (!normalized) return 0;
  const paddingMatch = normalized.match(/=+$/);
  const paddingLength = paddingMatch ? paddingMatch[0].length : 0;
  return Math.max(0, Math.floor((normalized.length * 3) / 4) - paddingLength);
}

function normalizeSessionPcapSource(source) {
  if (!source || typeof source !== "object") return null;
  const normalizedBase64 =
    typeof source.data === "string" ? source.data.replace(/\s+/g, "").trim() : "";
  if (!normalizedBase64) return null;
  const explicitByteLength = Number(source.byteLength);
  const byteLength =
    Number.isFinite(explicitByteLength) && explicitByteLength > 0
      ? Math.floor(explicitByteLength)
      : estimateBase64DecodedByteLength(normalizedBase64);
  const fileName =
    typeof source.fileName === "string" && source.fileName.trim()
      ? source.fileName.trim()
      : "capture.pcap";
  return {
    fileName,
    encoding: "base64",
    data: normalizedBase64,
    byteLength,
  };
}

function updatePcapSizeDisplayFromSource() {
  const pcapSizeEl = document.getElementById("pcap-size");
  const pcapFileNameEl = document.getElementById("file-name");
  if (!pcapSizeEl || !pcapFileNameEl) return;
  const sourceSize = sessionPcapSource && Number.isFinite(sessionPcapSource.byteLength)
    ? sessionPcapSource.byteLength
    : 0;
  const fileSizeKb = (sourceSize / 1024).toFixed(2);
  pcapFileNameEl.textContent = `PCAP file: ${sessionPcapSource?.fileName || "unknown"}`;
  pcapSizeEl.textContent = `PCAP size: ${fileSizeKb}kb`;
}

function updateReprocessButtonState() {
  const reprocessBtn = document.getElementById("reprocess-session-pcap-btn");
  if (!reprocessBtn) return;
  const hasSessionPcapData = Boolean(sessionPcapSource && sessionPcapSource.data);
  const canReprocessNow = hasSessionPcapData && !backendProgressState.processing;
  reprocessBtn.disabled = !canReprocessNow;
  reprocessBtn.title = !hasSessionPcapData
    ? "No stored source PCAP in the current session"
    : backendProgressState.processing
      ? "Wait until backend preprocessing completes before reprocessing"
      : "Reprocess stored source PCAP through backend";
}

function canPersistSessionNow() {
  if (!isFileLoaded) return false;
  if (backendProgressState.processing) return false;
  if (!capturedPackets || typeof capturedPackets !== "object") return false;
  const hosts = capturedPackets["Host"];
  if (!hosts || typeof hosts !== "object") return false;
  return Object.keys(hosts).some((host) => {
    const hostPackets = hosts[host];
    return Array.isArray(hostPackets) && hostPackets.length > 0;
  });
}

function updateSessionSaveControls() {
  // Keep save controls enabled so an early click can surface the warning.
}

function warnReprocessAttemptBeforeReady() {
  const message =
    "Status: Backend preprocessing is still running. Wait until processing completes before reprocessing the session PCAP.";
  statusUpdate(message);
  writeLogEntry(
    "Warning: blocked reprocess session PCAP while backend preprocessing was still in progress",
  );
  return {
    success: false,
    error: "Backend preprocessing still in progress",
  };
}

function warnSessionSaveAttemptBeforeReady(actionLabel) {
  const message =
    "Status: Backend preprocessing is still running. Wait until processing completes before " +
    actionLabel + ".";
  statusUpdate(message);
  writeLogEntry(
    `Warning: blocked ${actionLabel} while backend preprocessing was still in progress`,
  );
  return {
    success: false,
    error: "Backend preprocessing still in progress",
  };
}

function setSessionPcapSource(source, options = {}) {
  const { skipLog = false, logLabel = "session" } = options;
  sessionPcapSource = normalizeSessionPcapSource(source);
  updatePcapSizeDisplayFromSource();
  updateReprocessButtonState();
  if (!skipLog && sessionPcapSource) {
    writeLogEntry(
      `PCAP source cached label=${logLabel} name=${sessionPcapSource.fileName} bytes=${sessionPcapSource.byteLength}`,
    );
  }
}

function resetBackendProgressState() {
  backendProgressState.firstChunkLoaded = false;
  backendProgressState.processing = false;
  backendProgressState.processedPackets = 0;
  backendProgressState.totalPackets = 0;
  updateBackendProcessingWarning();
}

function updateBackendProcessingWarning() {
  updateSessionSaveControls();
  updateReprocessButtonState();
  const warningEl = document.getElementById("backend-processing-warning");
  if (!warningEl) return;

  if (!backendProgressState.firstChunkLoaded || !backendProgressState.processing) {
    warningEl.style.display = "none";
    warningEl.textContent = "";
    return;
  }

  const processedText = backendProgressState.processedPackets > 0
    ? String(backendProgressState.processedPackets)
    : "0";
  const totalText = backendProgressState.totalPackets > 0
    ? String(backendProgressState.totalPackets)
    : "?";
  warningEl.textContent =
    "Warning: packets are still being processed (" +
    processedText +
    " / " +
    totalText +
    "). Data is partial until backend processing completes.";
  warningEl.style.display = "block";
}

function normalizeBackendJsonPathPayload(rawPayload) {
  if (typeof rawPayload === "string") {
    return {
      path: rawPayload,
      processedPackets: 0,
      totalPackets: 0,
      complete: true,
      chunkSize: BACKEND_PACKET_CHUNK_SIZE,
    };
  }

  if (!rawPayload || typeof rawPayload !== "object") {
    return null;
  }

  return {
    path: typeof rawPayload.path === "string" ? rawPayload.path : "",
    processedPackets: Number(rawPayload.processedPackets) || 0,
    totalPackets: Number(rawPayload.totalPackets) || 0,
    complete: Boolean(rawPayload.complete),
    chunkSize: Number(rawPayload.chunkSize) || BACKEND_PACKET_CHUNK_SIZE,
  };
}

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
  syncTargetHostFromPackets: (packets) =>
    syncTargetHostFromFilteredPackets(packets, "Stats filter"),
  setPacketsForHost: (packets) => {
    p = packets;
  },
  getBookmarkCount: () => bookmarkList.length,
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
    getPacketsForHost: () => p,
    setActiveMainTab: (tab) => {
      activeMainTab = tab;
    },
    handlePacketNavigation: (navAction, navBookmark) =>
      void handlePacketNavigation(navAction, navBookmark),
    getIndex: () => index,
    setIndex: (nextIndex) => {
      const normalizedIndex = setActivePacketCursor(nextIndex);
      index = Number.isInteger(normalizedIndex) ? normalizedIndex : 0;
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
  buildSessionFilePayload,
  onSessionSelected: async (name, jsonData) => {
    currentSessionName = name;
    startTime = performance.now();
    statusUpdate("Loading session: " + name);
    resetBackendProgressState();
    window.snitchapi.shutdownBackend().catch((error) => {
      logErrorEntry("shutdown-backend", error);
    });
    setSessionPcapSource(null, { skipLog: true });
    if (window.captureapi) {
      const loadResult = await window.captureapi.loadJson(jsonData);
      if (!loadResult?.success) {
        doError(`Failed to load session: ${loadResult?.error || "unknown error"}`);
        return;
      }
      const syntheticPayload = {
        [SESSION_CAPTURE_KEY]: loadResult.captureData,
      };
      if (loadResult.sessionState) {
        syntheticPayload[SESSION_STATE_KEY] = loadResult.sessionState;
      }
      processFile(
        new File([JSON.stringify(syntheticPayload)], name + ".json", {
          type: "application/json",
        }),
      );
      return;
    }

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
          setSessionPcapSource(null, { skipLog: true });
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
  resetBackendProgressState();
  currentSessionName = null;
  p = [];
  capturedPackets = {};
  activePacketCursor = 0;
  index = 0;
  currentIp = null;
  currentPacketKey = null;
  jsonCapture = "";
  finalSummary = "";
  finalSummary = ""; // Clear the default summary from the template
  setSessionPcapSource(null, { skipLog: true });
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
startSessionAutosaveTimer();

popHexGrid("00".repeat(256));
// Set up the unified capture/session loader.
document
  .getElementById("capture-file-btn")
  .addEventListener("click", function () {
    window.getfileapi
      .selectFile()
      .then((filePath) => {
        if (!filePath) return;
        startTime = performance.now();
        statusUpdate("Processing file: " + filePath);
        setSessionPcapSource(null, { skipLog: true });
        writeLogEntry(`User selected capture/session file path=${filePath}`);
        // Clear library session name – this is a manual file load, not from the library
        currentSessionName = null;
        runSnitch(filePath);
      })
      .catch((error) => {
        doError("Error selecting capture/session file!");
        logErrorEntry("capture-select", error);
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
    document.getElementById("capture-file-lab").style.display = "none";
    document.getElementById("llm-toggle").style.display = "none";
    writeLogEntry(
      `[${threadName}] User opened AI Summary view`,
    );
  } else {
    filterInputEl.disabled = true;
    filterHistorySelectEl.disabled = true;
    document.getElementById("capture-file-lab").style.display = "block";
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

function getPacketKey(packet, fallbackHost = "", fallbackIndex = 0) {
  if (packet && typeof packet.__packetKey === "string" && packet.__packetKey) {
    return packet.__packetKey;
  }
  const packetInfo = packet?.["Packet Info"];
  const sourceIp =
    packetInfo?.["IP"]?.["Source IP"] || fallbackHost || "Unknown";
  const packetIndex = packetInfo?.["Index"] ?? fallbackIndex;
  return sourceIp + ":" + packetIndex;
}

function cachePacketStub(packetKey, packetStub) {
  if (!packetKey || !packetStub) return;
  if (!packetStubByKey.has(packetKey)) {
    packetStubByKey.set(packetKey, packetStub);
  }
}

function cacheHydratedPacket(packetKey, packet) {
  if (!packetKey || !packet) return;
  if (hydratedPacketCache.has(packetKey)) {
    hydratedPacketCache.delete(packetKey);
  }
  hydratedPacketCache.set(packetKey, packet);
  while (hydratedPacketCache.size > HYDRATED_PACKET_CACHE_LIMIT) {
    const oldestKey = hydratedPacketCache.keys().next().value;
    if (!oldestKey) break;
    hydratedPacketCache.delete(oldestKey);
  }
}

function updatePacketInCollections(packetKey, packet) {
  if (!packetKey || !packet) return;
  const hosts = capturedPackets?.Host || {};
  for (const host of Object.keys(hosts)) {
    const packetList = hosts[host];
    if (!Array.isArray(packetList)) continue;
    const packetIndex = packetList.findIndex(
      (entry) => getPacketKey(entry, host) === packetKey,
    );
    if (packetIndex >= 0) {
      packetList[packetIndex] = packet;
      break;
    }
  }

  if (Array.isArray(filteredPackets)) {
    const filteredIndex = filteredPackets.findIndex(
      (entry) => getPacketKey(entry) === packetKey,
    );
    if (filteredIndex >= 0) {
      filteredPackets[filteredIndex] = packet;
    }
  }

  if (Array.isArray(p)) {
    const packetIndex = p.findIndex((entry) => getPacketKey(entry) === packetKey);
    if (packetIndex >= 0) {
      p[packetIndex] = packet;
    }
  }
}

async function ensurePacketHydrated(packet, fallbackHost = "", fallbackIndex = 0) {
  if (!packet) return null;
  const packetKey = getPacketKey(packet, fallbackHost, fallbackIndex);
  if (!packetKey) return packet;

  const payloadHex =
    packet?.["Packet Info"]?.["Raw data"]?.["Payload"]?.["Hex Encoded"];
  if (typeof payloadHex === "string" && payloadHex.length > 0) {
    cacheHydratedPacket(packetKey, packet);
    return packet;
  }

  if (hydratedPacketCache.has(packetKey)) {
    return hydratedPacketCache.get(packetKey);
  }

  if (!window.captureapi) {
    return packet;
  }

  const result = await window.captureapi.getPacket(packetKey);
  if (!result?.success || !result.packet) {
    return packet;
  }

  const hydrated = {
    ...result.packet,
    __packetKey: packetKey,
    __packetStub: false,
  };
  cacheHydratedPacket(packetKey, hydrated);
  updatePacketInCollections(packetKey, hydrated);
  return hydrated;
}

function isLocationFilterQuery(filterQuery) {
  if (typeof filterQuery !== "string") return false;
  return /\bloc\.(src|dst)\.(city|country|postal|tz|timezone)\s*:/i.test(
    filterQuery,
  );
}

function chooseTargetHostFromPacketMatches(matches) {
  if (!Array.isArray(matches) || matches.length === 0) return "";

  const targetHostsEl = getCachedElement("target_hosts");
  const availableHosts = new Set(
    Array.from(targetHostsEl.options || [])
      .map((option) => String(option.value || "").trim())
      .filter(Boolean),
  );
  const ipHitCounts = new Map();

  matches.forEach((packet) => {
    const sourceIp = packet?.["Packet Info"]?.["IP"]?.["Source IP"];
    const destinationIp = packet?.["Packet Info"]?.["IP"]?.["Destination IP"];
    [sourceIp, destinationIp].forEach((ipValue) => {
      if (typeof ipValue !== "string") return;
      const normalizedIp = ipValue.trim();
      if (!normalizedIp) return;
      if (!STRICT_IPV4_REGEX.test(normalizedIp)) return;
      if (availableHosts.size > 0 && !availableHosts.has(normalizedIp)) return;
      ipHitCounts.set(normalizedIp, (ipHitCounts.get(normalizedIp) || 0) + 1);
    });
  });

  let selectedIp = "";
  let highestHitCount = -1;
  ipHitCounts.forEach((hitCount, ipValue) => {
    if (hitCount > highestHitCount) {
      highestHitCount = hitCount;
      selectedIp = ipValue;
    }
  });
  return selectedIp;
}

function syncTargetHostFromFilteredPackets(matches, sourceLabel = "filter") {
  const selectedHost = chooseTargetHostFromPacketMatches(matches);
  if (!syncTargetHostSelection(selectedHost)) {
    return "";
  }
  writeLogEntry(`${sourceLabel} auto-selected target host=${selectedHost}`);
  return selectedHost;
}

function syncTargetHostSelection(selectedHost) {
  const normalizedHost =
    typeof selectedHost === "string" ? selectedHost.trim() : "";
  if (!normalizedHost) return false;

  const targetHostsEl = getCachedElement("target_hosts");
  const hostExists = Array.from(targetHostsEl.options || []).some(
    (option) => option.value === normalizedHost,
  );
  if (!hostExists) return false;

  if (targetHostsEl.value !== normalizedHost) {
    targetHostsEl.value = normalizedHost;
  }
  if (hostFilterEl.value !== normalizedHost) {
    hostFilterEl.value = normalizedHost;
  }
  return true;
}

function isAllHostsSelection(selectedHost) {
  return String(selectedHost || "").trim() === DUMMY_ALL_HOST;
}

function isBookmarkedSelection(selectedHost) {
  return String(selectedHost || "").trim() === DUMMY_BOOKMARKED_HOST;
}

function appendAllHostsOption(targetHostsDropdown) {
  const optionEl = document.createElement("option");
  optionEl.value = DUMMY_ALL_HOST;
  optionEl.textContent = `${DUMMY_ALL_HOST_ALIAS} (${DUMMY_ALL_HOST})`;
  targetHostsDropdown.appendChild(optionEl);
}

function appendBookmarkedOption(targetHostsDropdown) {
  const optionEl = document.createElement("option");
  optionEl.value = DUMMY_BOOKMARKED_HOST;
  optionEl.textContent = DUMMY_BOOKMARKED_HOST_ALIAS;
  targetHostsDropdown.appendChild(optionEl);
}

function getAllPacketKeysForFiltering() {
  if (packetStubByKey.size > 0) {
    return Array.from(packetStubByKey.keys());
  }

  const hostMap =
    capturedPackets && typeof capturedPackets["Host"] === "object"
      ? capturedPackets["Host"]
      : {};
  const packetKeys = [];
  Object.keys(hostMap).forEach((host) => {
    const hostPackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
    hostPackets.forEach((packet, packetIndex) => {
      packetKeys.push(getPacketKey(packet, host, packetIndex));
    });
  });
  return packetKeys;
}

function getBookmarkedPacketsForHostNavigation() {
  const seenPacketKeys = new Set();
  const packets = [];
  const allPackets = getAllPacketsForHostNavigation();
  bookmarkList.forEach((packetKey) => {
    if (seenPacketKeys.has(packetKey)) return;
    seenPacketKeys.add(packetKey);

    const packetStub = packetStubByKey.get(packetKey);
    if (packetStub) {
      packets.push(packetStub);
      return;
    }

    const packetIndex = findPacketIndexByKey(allPackets, packetKey);
    if (packetIndex >= 0) {
      packets.push(allPackets[packetIndex]);
    }
  });
  return sortPacketsByOwnStreamOrder(packets);
}

function parseFilterExpressionParts(expression) {
  if (typeof expression !== "string") {
    return null;
  }
  const separatorIndex = expression.indexOf(":");
  if (separatorIndex === -1) {
    return null;
  }
  const filterKey = expression.slice(0, separatorIndex).trim();
  const filterValue = expression.slice(separatorIndex + 1).trim();
  return {
    filterKey,
    filterValue,
  };
}

function normalizeLocalFilterKey(filterKey) {
  return String(filterKey || "")
    .toLowerCase()
    .replace(/[._\s-]+/g, "-");
}

function isBookmarkFilterExpression(expression) {
  const parts = parseFilterExpressionParts(expression);
  if (!parts?.filterKey) return false;
  return normalizeLocalFilterKey(parts.filterKey) === "bookmark";
}

function isRetransmissionFilterExpression(expression) {
  const parts = parseFilterExpressionParts(expression);
  if (!parts?.filterKey) return false;
  const normalizedFilterKey = normalizeLocalFilterKey(parts.filterKey);
  return (
    normalizedFilterKey === "tcp-retransmission" ||
    normalizedFilterKey === "tcp-stream-retransmission"
  );
}

function isOutOfOrderFilterExpression(expression) {
  const parts = parseFilterExpressionParts(expression);
  if (!parts?.filterKey) return false;
  const normalizedFilterKey = normalizeLocalFilterKey(parts.filterKey);
  return (
    normalizedFilterKey === "tcp-badorder" ||
    normalizedFilterKey === "tcp-stream-badorder"
  );
}

function parseBookmarkFilterBool(rawValue) {
  const normalized = String(rawValue || "").trim().toLowerCase();
  if (["true", "1", "yes", "y"].includes(normalized)) return true;
  if (["false", "0", "no", "n"].includes(normalized)) return false;
  return null;
}

function parseRetransmissionFilterBool(rawValue) {
  const normalized = String(rawValue || "").trim().toLowerCase();
  if (["true", "1", "yes", "y"].includes(normalized)) return true;
  if (["false", "0", "no", "n"].includes(normalized)) return false;
  return null;
}

function rebuildTcpStreamFilterIndexes() {
  retransmissionList = [];
  outOfOrderList = [];

  const hostMap =
    capturedPackets && typeof capturedPackets["Host"] === "object"
      ? capturedPackets["Host"]
      : {};
  const streamPacketsByKey = new Map();

  Object.keys(hostMap).forEach((host) => {
    const hostPackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
    hostPackets.forEach((packet) => {
      const packetInfo = packet?.["Packet Info"];
      const protocol = String(packetInfo?.["Protocol"] || "").toUpperCase();
      if (protocol !== "TCP") return;

      const streamKey = buildBidirectionalStreamKey(packetInfo);
      if (!streamKey) return;

      if (!streamPacketsByKey.has(streamKey)) {
        streamPacketsByKey.set(streamKey, []);
      }
      streamPacketsByKey.get(streamKey).push(packet);
    });
  });

  streamPacketsByKey.forEach((streamPackets) => {
    const sortedStreamPackets = sortPacketsByOwnStreamOrder([...streamPackets]);
    getTcpStreamArrivalStatusByPacketKey(sortedStreamPackets);
  });
}

function evaluateBookmarkFilterExpression(expression) {
  const parts = parseFilterExpressionParts(expression);
  if (!parts) return [];

  const comparisonOps = [">=", "<=", ">", "<", "==", "!="];
  const filterModifier = comparisonOps.find((modifier) =>
    parts.filterValue.includes(modifier),
  );
  const rawFilterValue = filterModifier
    ? parts.filterValue.replace(filterModifier, "").trim()
    : parts.filterValue;
  const expectedBookmarked = parseBookmarkFilterBool(rawFilterValue);
  if (expectedBookmarked === null) {
    return [];
  }

  const bookmarkSet = new Set(bookmarkList);
  const allPacketKeys = getAllPacketKeysForFiltering();
  return allPacketKeys.filter((packetKey) => {
    const isBookmarked = bookmarkSet.has(packetKey);
    if (filterModifier === "!=") {
      return isBookmarked !== expectedBookmarked;
    }
    return isBookmarked === expectedBookmarked;
  });
}

function evaluateRetransmissionFilterExpression(expression) {
  const parts = parseFilterExpressionParts(expression);
  if (!parts) return [];
  const comparisonOps = [">=", "<=", ">", "<", "==", "!="];
  const filterModifier = comparisonOps.find((modifier) =>
    parts.filterValue.includes(modifier),
  );
  const rawFilterValue = filterModifier
    ? parts.filterValue.replace(filterModifier, "").trim()
    : parts.filterValue;
  const expectedRetransmission = parseRetransmissionFilterBool(rawFilterValue);
  if (expectedRetransmission === null) {
    return [];
  }

  rebuildTcpStreamFilterIndexes();
  const retransmissionSet = new Set(retransmissionList);
  const allPacketKeys = getAllPacketKeysForFiltering();
  return allPacketKeys.filter((packetKey) => {
    const isRetransmission = retransmissionSet.has(packetKey);
    if (filterModifier === "!=") {
      return isRetransmission !== expectedRetransmission;
    }
    return isRetransmission === expectedRetransmission;
  });
}

function evaluateOutOfOrderFilterExpression(expression) {
  const parts = parseFilterExpressionParts(expression);
  if (!parts) return [];
  const comparisonOps = [">=", "<=", ">", "<", "==", "!="];
  const filterModifier = comparisonOps.find((modifier) =>
    parts.filterValue.includes(modifier),
  );
  const rawFilterValue = filterModifier
    ? parts.filterValue.replace(filterModifier, "").trim()
    : parts.filterValue;
  const expectedOutOfOrder = parseRetransmissionFilterBool(rawFilterValue);
  if (expectedOutOfOrder === null) {
    return [];
  }

  rebuildTcpStreamFilterIndexes();
  const outOfOrderSet = new Set(outOfOrderList);
  const allPacketKeys = getAllPacketKeysForFiltering();
  return allPacketKeys.filter((packetKey) => {
    const isOutOfOrder = outOfOrderSet.has(packetKey);
    if (filterModifier === "!=") {
      return isOutOfOrder !== expectedOutOfOrder;
    }
    return isOutOfOrder === expectedOutOfOrder;
  });
}

function getAllPacketsForHostNavigation() {
  const hostMap =
    capturedPackets && typeof capturedPackets["Host"] === "object"
      ? capturedPackets["Host"]
      : {};
  const allPackets = [];
  Object.keys(hostMap).forEach((host) => {
    const hostPackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
    allPackets.push(...hostPackets);
  });
  return sortPacketsByOwnStreamOrder(allPackets);
}

function getPacketsForSelectedHost(selectedHost) {
  if (isAllHostsSelection(selectedHost)) {
    return getAllPacketsForHostNavigation();
  }
  if (isBookmarkedSelection(selectedHost)) {
    return getBookmarkedPacketsForHostNavigation();
  }
  const hostPackets = Array.isArray(capturedPackets?.["Host"]?.[selectedHost])
    ? capturedPackets["Host"][selectedHost]
    : [];
  return sortPacketsByOwnStreamOrder([...hostPackets]);
}

function parsePacketTimestampMs(packet) {
  const packetTimestamp = packet?.["Packet Info"]?.["Packet Timestamp"];
  if (typeof packetTimestamp !== "string" || !packetTimestamp.trim()) {
    return null;
  }
  const parsedTimestamp = Date.parse(packetTimestamp);
  return Number.isFinite(parsedTimestamp) ? parsedTimestamp : null;
}

function parsePacketProcessedNumber(packet) {
  const processedRaw = Number(packet?.["Packet Info"]?.["Packet Processed"]);
  return Number.isFinite(processedRaw) ? processedRaw : null;
}

function parsePacketIndexNumber(packet) {
  const packetIndexRaw = Number(packet?.["Packet Info"]?.["Index"]);
  return Number.isFinite(packetIndexRaw) ? packetIndexRaw : null;
}

function comparePacketsChronologically(
  leftPacket,
  rightPacket,
  leftFallbackOrder = 0,
  rightFallbackOrder = 0,
) {
  const leftTimestamp = parsePacketTimestampMs(leftPacket);
  const rightTimestamp = parsePacketTimestampMs(rightPacket);
  if (leftTimestamp !== null && rightTimestamp !== null && leftTimestamp !== rightTimestamp) {
    return leftTimestamp - rightTimestamp;
  }
  if (leftTimestamp !== null && rightTimestamp === null) return -1;
  if (leftTimestamp === null && rightTimestamp !== null) return 1;

  const leftProcessed = parsePacketProcessedNumber(leftPacket);
  const rightProcessed = parsePacketProcessedNumber(rightPacket);
  if (leftProcessed !== null && rightProcessed !== null && leftProcessed !== rightProcessed) {
    return leftProcessed - rightProcessed;
  }
  if (leftProcessed !== null && rightProcessed === null) return -1;
  if (leftProcessed === null && rightProcessed !== null) return 1;

  const leftIndex = parsePacketIndexNumber(leftPacket);
  const rightIndex = parsePacketIndexNumber(rightPacket);
  if (leftIndex !== null && rightIndex !== null && leftIndex !== rightIndex) {
    return leftIndex - rightIndex;
  }
  if (leftIndex !== null && rightIndex === null) return -1;
  if (leftIndex === null && rightIndex !== null) return 1;

  return leftFallbackOrder - rightFallbackOrder;
}

function getPacketStreamSortInfo(packet, fallbackOrder = 0) {
  const packetInfo = packet?.["Packet Info"] || {};
  const protocol = String(packetInfo["Protocol"] || "").toUpperCase();
  const sourceIp = packetInfo?.["IP"]?.["Source IP"] || "";
  const destinationIp = packetInfo?.["IP"]?.["Destination IP"] || "";
  const transport = packetInfo[protocol] || packetInfo[protocol.toLowerCase()] || {};
  const sourcePort = transport?.["Source port"];
  const destinationPort = transport?.["Destination port"];
  const hasPorts =
    sourcePort !== undefined &&
    sourcePort !== null &&
    destinationPort !== undefined &&
    destinationPort !== null;

  const endpointA = hasPorts ? `${sourceIp}:${sourcePort}` : sourceIp;
  const endpointB = hasPorts ? `${destinationIp}:${destinationPort}` : destinationIp;
  const [firstEndpoint, secondEndpoint] = [endpointA, endpointB].sort();
  const streamKey = `${protocol}|${firstEndpoint}|${secondEndpoint}`;

  const packetIndexRaw = Number(packetInfo?.["Index"]);
  const packetIndex = Number.isFinite(packetIndexRaw)
    ? packetIndexRaw
    : fallbackOrder;

  return {
    streamKey,
    packetIndex,
    protocol,
  };
}

function sortPacketsByOwnStreamOrder(packetList) {
  if (!Array.isArray(packetList) || packetList.length < 2) {
    return Array.isArray(packetList) ? packetList : [];
  }

  const decorated = packetList.map((packet, originalOrder) => {
    return {
      packet,
      originalOrder,
    };
  });

  decorated.sort((left, right) => {
    return comparePacketsChronologically(
      left.packet,
      right.packet,
      left.originalOrder,
      right.originalOrder,
    );
  });

  return decorated.map((entry) => entry.packet);
}

function tokenizeLocalFilterQuery(query) {
  const tokenList = [];
  let cursor = 0;

  while (cursor < query.length) {
    if (/\s/.test(query[cursor])) {
      cursor += 1;
      continue;
    }
    if (query[cursor] === "(") {
      tokenList.push({ type: "LPAREN" });
      cursor += 1;
      continue;
    }
    if (query[cursor] === ")") {
      tokenList.push({ type: "RPAREN" });
      cursor += 1;
      continue;
    }
    if (query.startsWith("||", cursor)) {
      tokenList.push({ type: "OR" });
      cursor += 2;
      continue;
    }
    if (query.startsWith("&&", cursor)) {
      tokenList.push({ type: "AND" });
      cursor += 2;
      continue;
    }
    if (query[cursor] === "!" && query[cursor + 1] !== "=") {
      tokenList.push({ type: "NOT" });
      cursor += 1;
      continue;
    }

    let expressionEnd = cursor;
    while (
      expressionEnd < query.length &&
      !query.startsWith("||", expressionEnd) &&
      !query.startsWith("&&", expressionEnd) &&
      !(query[expressionEnd] === "!" && query[expressionEnd + 1] !== "=") &&
      query[expressionEnd] !== "(" &&
      query[expressionEnd] !== ")"
    ) {
      expressionEnd += 1;
    }

    const expressionText = query.slice(cursor, expressionEnd).trim();
    if (expressionText) {
      tokenList.push({ type: "EXPR", value: expressionText });
    }
    cursor = expressionEnd;
  }
  return tokenList;
}

function unionPacketKeys(leftKeys, rightKeys) {
  return Array.from(new Set([...leftKeys, ...rightKeys]));
}

function intersectPacketKeys(leftKeys, rightKeys) {
  const rightSet = new Set(rightKeys);
  return leftKeys.filter((packetKey) => rightSet.has(packetKey));
}

function subtractPacketKeys(allKeys, excludedKeys) {
  const excludedSet = new Set(excludedKeys);
  return allKeys.filter((packetKey) => !excludedSet.has(packetKey));
}

async function evaluateFilterExpressionToPacketKeys(expression) {
  if (isBookmarkFilterExpression(expression)) {
    return evaluateBookmarkFilterExpression(expression);
  }
  if (isRetransmissionFilterExpression(expression)) {
    return evaluateRetransmissionFilterExpression(expression);
  }
  if (isOutOfOrderFilterExpression(expression)) {
    return evaluateOutOfOrderFilterExpression(expression);
  }
  if (!window.captureapi) {
    return [];
  }
  const filterResult = await window.captureapi.filter(expression);
  if (!filterResult?.success) {
    const errorText =
      typeof filterResult?.error === "string"
        ? filterResult.error
        : "Filter failed";
    throw new Error(errorText);
  }
  return Array.isArray(filterResult.packetKeys) ? filterResult.packetKeys : [];
}

async function evaluateFilterQueryToPacketKeys(query) {
  const normalizedQuery = String(query || "").trim();
  if (!normalizedQuery) {
    return getAllPacketKeysForFiltering();
  }

  const tokenList = tokenizeLocalFilterQuery(normalizedQuery);
  const allPacketKeys = getAllPacketKeysForFiltering();
  let tokenIndex = 0;

  const peek = () => tokenList[tokenIndex];
  const consume = (expectedType) => {
    const currentToken = tokenList[tokenIndex];
    if (expectedType && (!currentToken || currentToken.type !== expectedType)) {
      throw new Error(
        `Expected ${expectedType} but got ${currentToken ? currentToken.type : "EOF"}`,
      );
    }
    tokenIndex += 1;
    return currentToken;
  };

  const parseOr = async () => {
    let result = await parseAnd();
    while (peek() && peek().type === "OR") {
      consume("OR");
      const rightResult = await parseAnd();
      result = unionPacketKeys(result, rightResult);
    }
    return result;
  };

  const parseAnd = async () => {
    let result = await parseTerm();
    while (peek() && peek().type === "AND") {
      consume("AND");
      const rightResult = await parseTerm();
      result = intersectPacketKeys(result, rightResult);
    }
    return result;
  };

  const parseTerm = async () => {
    const currentToken = peek();
    if (!currentToken) {
      return [];
    }
    if (currentToken.type === "NOT") {
      consume("NOT");
      const negatedResult = await parseTerm();
      return subtractPacketKeys(allPacketKeys, negatedResult);
    }
    if (currentToken.type === "LPAREN") {
      consume("LPAREN");
      const groupedResult = await parseOr();
      consume("RPAREN");
      return groupedResult;
    }
    if (currentToken.type === "EXPR") {
      consume("EXPR");
      return evaluateFilterExpressionToPacketKeys(currentToken.value);
    }
    return [];
  };

  const resolvedPacketKeys = await parseOr();
  return Array.isArray(resolvedPacketKeys) ? resolvedPacketKeys : [];
}

async function runFilterQuery(filterQuery, options = {}) {
  const {
    trackHistory = true,
    updateUi = true,
    logQueryOutcome = trackHistory,
  } = options;
  const normalizedFilterQuery =
    typeof filterQuery === "string" ? filterQuery.trim() : "";

  if (normalizedFilterQuery === "") {
    filteredPackets = getAllPacketsForHostNavigation();
    if (!updateUi) {
      return;
    }

    syncTargetHostSelection(DUMMY_ALL_HOST);
    writeLogEntry("User cleared filter query");
    statusUpdate("Status: Filter cleared, displaying all packets");
    await handlePacketNavigation("first-load", null);
    return;
  }

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

  try {
    const matchedPacketKeys = await evaluateFilterQueryToPacketKeys(filterQuery);
    filteredPackets = matchedPacketKeys
      .map((packetKey) => packetStubByKey.get(packetKey))
      .filter(Boolean);
    filteredPackets = sortPacketsByOwnStreamOrder(filteredPackets);
  } catch (error) {
    const errorText =
      typeof error?.message === "string" && error.message.trim()
        ? error.message
        : "Filter failed";
    doError(`Filter execution failed: ${errorText}`);
    statusUpdate("Status: Filter execution failed");
    return;
  }

  if (isLocationFilterQuery(filterQuery) && filteredPackets.length > 0) {
    syncTargetHostFromFilteredPackets(filteredPackets, "Location filter");
  }

  if (!updateUi) {
    return;
  }

  if (logQueryOutcome) {
    writeLogEntry(`User executed query="${filterQuery}"`);
  }
  statusUpdate("Status: Filtering packets...");

  if (filteredPackets === undefined || filteredPackets.length === 0) {
    hideAllData();
    statusUpdate("Status: No packets match the filter criteria");
    if (logQueryOutcome) {
      writeLogEntry("User query returned 0 packets");
    }
  } else {
    statusUpdate(
      "Status: Displaying " +
      filteredPackets.length +
      " packets matching filter",
    );
    if (logQueryOutcome) {
      writeLogEntry(`User query returned packets=${filteredPackets.length}`);
    }
    await handlePacketNavigation("filtered", null);
  }
}

function clearFilterQuery() {
  syncTargetHostSelection(DUMMY_ALL_HOST);
  if (!canClearFilterQuery()) {
    return;
  }
  filterInputEl.value = "";
  syncFilterHighlight();
  filterHistorySelectEl.value = "";
  filterInputEl.focus();
  void runFilterQuery("");
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

function getConvDecodedOutputText() {
  const decodedOutputEl = document.getElementById("data-tools-proto-output");
  if (!decodedOutputEl) return "";
  return String(decodedOutputEl.innerText || "").trim();
}

function getConvContextExportText(exportType) {
  switch (exportType) {
    case "input":
      return document.getElementById("data-tools-input")?.value?.trim() || "";
    case "hex":
      return document.getElementById("data-tools-hex-output")?.value?.trim() || "";
    case "binary":
      return document.getElementById("data-tools-binary-output")?.value?.trim() || "";
    case "decimal":
      return document.getElementById("data-tools-decimal-output")?.value?.trim() || "";
    case "decimal-integer":
      return (
        document.getElementById("data-tools-decimal-integer-output")?.value?.trim() ||
        ""
      );
    case "ascii":
      return document.getElementById("data-tools-ascii-output")?.value?.trim() || "";
    case "base64":
      return document.getElementById("data-tools-base64-output")?.value?.trim() || "";
    case "hashes":
      return buildConvHashesNoteText();
    case "decodes":
      return getConvDecodedOutputText();
    default:
      return "";
  }
}

function getConvContextExportMeta(exportType) {
  switch (exportType) {
    case "input":
      return {
        title: "Export Conv Input",
        defaultName: "conv-input.txt",
        statusLabel: "Conv input",
        logKey: "input",
      };
    case "hex":
      return {
        title: "Export Conv Output (Hex)",
        defaultName: "conv-output-hex.txt",
        statusLabel: "Conv hex output",
        logKey: "hex",
      };
    case "binary":
      return {
        title: "Export Conv Output (Binary)",
        defaultName: "conv-output-binary.txt",
        statusLabel: "Conv binary output",
        logKey: "binary",
      };
    case "decimal":
      return {
        title: "Export Conv Output (Decimal Bytes)",
        defaultName: "conv-output-decimal-bytes.txt",
        statusLabel: "Conv decimal bytes output",
        logKey: "decimal-bytes",
      };
    case "decimal-integer":
      return {
        title: "Export Conv Output (Decimal Integer)",
        defaultName: "conv-output-decimal-integer.txt",
        statusLabel: "Conv decimal integer output",
        logKey: "decimal-integer",
      };
    case "ascii":
      return {
        title: "Export Conv Output (ASCII)",
        defaultName: "conv-output-ascii.txt",
        statusLabel: "Conv ASCII output",
        logKey: "ascii",
      };
    case "base64":
      return {
        title: "Export Conv Output (Base64)",
        defaultName: "conv-output-base64.txt",
        statusLabel: "Conv base64 output",
        logKey: "base64",
      };
    case "hashes":
      return {
        title: "Export Conv Hashes",
        defaultName: "conv-hashes.txt",
        statusLabel: "Conv hashes",
        logKey: "hashes",
      };
    case "decodes":
      return {
        title: "Export Conv Decode Output",
        defaultName: "conv-decode-output.txt",
        statusLabel: "Conv decode output",
        logKey: "decode-output",
      };
    default:
      return {
        title: "Export Conv Data",
        defaultName: "conv-export.txt",
        statusLabel: "Conv data",
        logKey: "unknown",
      };
  }
}

function exportConvContextTextFromContextMenu(exportType) {
  const exportText = getConvContextExportText(exportType);
  const exportMeta = getConvContextExportMeta(exportType);
  hideConvertContextMenu();
  if (!exportText) {
    statusUpdate(`Status: No ${exportMeta.statusLabel} available to export`);
    return;
  }
  window.saveapi
    .saveText({
      text: exportText,
      title: exportMeta.title,
      defaultName: exportMeta.defaultName,
    })
    .then((result) => {
      if (result.canceled) {
        statusUpdate("Status: Export cancelled");
      } else if (result.success) {
        statusUpdate(`Status: ${exportMeta.statusLabel} exported successfully`);
        writeLogEntry(
          `Context menu conv export completed type=${exportMeta.logKey}`,
        );
      } else {
        const errorMessage =
          result && typeof result === "object" && "error" in result
            ? result.error
            : "unknown";
        doError(`${exportMeta.statusLabel} export failed`);
        logErrorEntry(
          `export-conv-${exportMeta.logKey}`,
          errorMessage || "unknown",
        );
        statusUpdate(
          `Status: ${exportMeta.statusLabel} export failed – ${errorMessage || "unknown error"}`,
        );
        console.error(`${exportMeta.statusLabel} export failed:`, errorMessage);
      }
    });
}

function exportConvRawFromContextMenu() {
  const payloadHex =
    document.getElementById("data-tools-hex-output")?.value?.trim() || "";
  hideConvertContextMenu();
  if (!payloadHex) {
    statusUpdate("Status: No Conv raw data available to export");
    return;
  }
  window.saveapi.savePayload(payloadHex).then((result) => {
    if (result.canceled) {
      statusUpdate("Status: Export cancelled");
    } else if (result.success) {
      statusUpdate("Status: Conv raw data exported successfully");
      writeLogEntry("Context menu conv export completed type=raw");
    } else {
      const errorMessage =
        result && typeof result === "object" && "error" in result
          ? result.error
          : "unknown";
      doError("Conv raw export failed");
      logErrorEntry("export-conv-raw", errorMessage || "unknown");
      statusUpdate(
        `Status: Conv raw export failed – ${errorMessage || "unknown error"}`,
      );
      console.error("Conv raw export failed:", errorMessage);
    }
  });
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

function buildListVisibleDataNoteText(target = activeContextTarget) {
  const row = target?.closest?.("tr[data-host][data-pkt-idx]");
  if (!row) return "";

  const headers = Array.from(
    row.closest("table")?.querySelectorAll("thead th") || [],
  ).map((headerEl) =>
    String(headerEl?.textContent || "")
      .replace(/[▲▼]/g, "")
      .trim(),
  );
  const values = Array.from(row.querySelectorAll("td")).map((cellEl) =>
    String(cellEl?.textContent || "").trim(),
  );
  if (!values.length) return "";

  const lines = ["List Tab Visible Row Data:"];
  values.forEach((value, index) => {
    const header = headers[index] || `Column ${index + 1}`;
    const normalizedHeader = header === "★" ? "Bookmarked" : header;
    const normalizedValue = header === "★"
      ? value === "★"
        ? "Yes"
        : "No"
      : value || "(empty)";
    lines.push(`${normalizedHeader}: ${normalizedValue}`);
  });
  return lines.join("\n");
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
    p === filteredPackets
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
    sourcePcap: sessionPcapSource
      ? {
        fileName: sessionPcapSource.fileName,
        encoding: sessionPcapSource.encoding,
        data: sessionPcapSource.data,
        byteLength: sessionPcapSource.byteLength,
      }
      : null,
    tabs: {
      main: activeMainTab,
      conv: getActiveConvSubtab(),
      convCurrentInput: document.getElementById("data-tools-input")?.value || "",
      convCurrentFormat: document.getElementById("data-tools-format")?.value || "",
      crypt: activeCryptSubtab,
      listSearch: listSearchEl ? listSearchEl.value : "",
      listGroupStreams: listGroupStreamsEl
        ? Boolean(listGroupStreamsEl.checked)
        : false,
    },
  };
}

async function buildSessionFilePayload() {
  let captureDataForSave = capturedPackets;

  if (window.captureapi?.exportSessionData) {
    try {
      const exportResult = await window.captureapi.exportSessionData();
      if (exportResult?.success && exportResult.captureData) {
        captureDataForSave = exportResult.captureData;
      }
    } catch (error) {
      logErrorEntry("session-export-materialize", error);
    }
  }

  return JSON.stringify(
    {
      [SESSION_CAPTURE_KEY]: captureDataForSave,
      [SESSION_STATE_KEY]: buildSessionStateSnapshot(),
    },
    null,
    2,
  );
}

function canAutosaveCurrentSession() {
  return canPersistSessionNow();
}

async function autosaveSessionToDisk() {
  const sessionsApiRef = window.sessionsapi;
  if (!sessionsApiRef || typeof sessionsApiRef.save !== "function") return;
  if (!canAutosaveCurrentSession()) return;
  if (sessionAutosaveInFlight) return;

  sessionAutosaveInFlight = true;
  try {
    const sessionJsonData = await buildSessionFilePayload();
    if (!sessionJsonData || sessionJsonData.length <= 5000) return;

    const autosaveTargetName =
      typeof currentSessionName === "string" && currentSessionName.trim()
        ? currentSessionName.trim()
        : "autosave";
    const result = await sessionsApiRef.save(autosaveTargetName, sessionJsonData);

    if (result?.success && autosaveTargetName !== "autosave" && result.name) {
      currentSessionName = result.name;
    }
    if (result?.success) {
      writeLogEntry(
        `Session autosaved target="${autosaveTargetName}" source=timer-5m`,
      );
    } else if (result && !result.canceled) {
      logErrorEntry("session-autosave", result.error || "unknown");
    }
  } catch (error) {
    logErrorEntry("session-autosave", error);
  } finally {
    sessionAutosaveInFlight = false;
  }
}

function startSessionAutosaveTimer() {
  window.setInterval(() => {
    void autosaveSessionToDisk();
  }, SESSION_AUTOSAVE_INTERVAL_MS);
}

async function persistSessionToDisk(sourceLabel = "manual-save") {
  if (!canPersistSessionNow()) {
    if (backendProgressState.processing) {
      return warnSessionSaveAttemptBeforeReady("saving");
    }
    statusUpdate("Status: No data loaded to save");
    return { success: false, error: "No loaded capture" };
  }

  // If no session library is available fall back to the file-dialog export
  if (!window.sessionsapi) {
    // get the sessions name from the json payload

    const sessionJsonData = await buildSessionFilePayload();
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

  if (currentSessionName && currentSessionName === "autosave") {
    // For autosave, we want to overwrite the existing session without creating a new entry in the library or log
    currentSessionName = null; // Clear the session name after autosave so that the next save will prompt for a name again
    await persistSessionToDisk(sourceLabel = "manual-save");
    return { success: true, name: "autosave" };
  }
  const sessionJsonData = await buildSessionFilePayload();
  // if the user picks save, we should also ask them what the new name 
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
  if (!canPersistSessionNow()) {
    if (backendProgressState.processing) {
      return warnSessionSaveAttemptBeforeReady("exporting");
    }
    statusUpdate("Status: No data loaded to export");
    return { success: false, error: "No loaded capture" };
  }
  const sessionJsonData = await buildSessionFilePayload();
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
  if (p && p.length > 1) {
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

  setSessionPcapSource(sessionState.sourcePcap, {
    skipLog: true,
  });

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
  bookmarkList.splice(0, bookmarkList.length, ...loadedBookmarks);
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
  if (
    selectedHost &&
    (
      isAllHostsSelection(selectedHost) ||
      isBookmarkedSelection(selectedHost) ||
      capturedPackets?.["Host"]?.[selectedHost]
    )
  ) {
    const targetHostsEl = document.getElementById("target_hosts");
    if (targetHostsEl) {
      targetHostsEl.value = selectedHost;
    }
    hostFilterEl.value = selectedHost;
  } else {
    const fallbackHost = DUMMY_ALL_HOST;
    if (fallbackHost) {
      const targetHostsEl = document.getElementById("target_hosts");
      if (targetHostsEl) {
        targetHostsEl.value = fallbackHost;
      }
      hostFilterEl.value = fallbackHost;
    }
  }

  const restoredFilterQuery =
    typeof sessionState.currentFilterQuery === "string"
      ? sessionState.currentFilterQuery
      : "";
  filterInputEl.value = restoredFilterQuery;
  syncFilterHighlight();
  if (restoredFilterQuery.trim()) {
    void runFilterQuery(restoredFilterQuery, { trackHistory: false });
  } else {
    filteredPackets = [];
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
  void handlePacketNavigation(navAction);

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

  const savedConvCurrentInput = typeof tabState.convCurrentInput === "string"
    ? tabState.convCurrentInput
    : "";
  const savedConvCurrentFormat = typeof tabState.convCurrentFormat === "string"
    ? tabState.convCurrentFormat
    : "";
  if (savedConvCurrentInput.trim()) {
    const dataToolsInputEl = document.getElementById("data-tools-input");
    const dataToolsFormatEl = document.getElementById("data-tools-format");
    if (dataToolsInputEl && dataToolsFormatEl) {
      dataToolsInputEl.value = savedConvCurrentInput;
      dataToolsFormatEl.value = savedConvCurrentFormat;
      runDataToolsConversion();
    }
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

async function processCapturePath(capturePath, options = {}) {
  const { suppressLoadingOverlay = false, incrementalUpdate = false } = options;
  if (!suppressLoadingOverlay) {
    document.getElementById("loading-screen").style.display = "flex";
    document.getElementById("loading-container").style.display = "block";
    document.getElementById("loading-text").textContent = "Indexing capture...";
  }

  if (!window.captureapi) {
    doError("Capture API is unavailable in this build");
    return;
  }

  const loadResult = await window.captureapi.loadFile(capturePath);
  if (!loadResult?.success) {
    doError(`Failed to load capture: ${loadResult?.error || "unknown error"}`);
    fileLoaded(false);
    return;
  }

  if (incrementalUpdate && isFileLoaded) {
    capturedPackets = loadResult.captureData || { Host: {}, "Final Summary": "" };
    finalSummary = capturedPackets["Final Summary"] || "";
    jsonCapture = "[lazy-capture-store]";

    const targetHostsDropdown = getCachedElement("target_hosts");
    const previousHost = targetHostsDropdown?.value || hostFilterEl.value || "";
    const hostMap =
      capturedPackets && typeof capturedPackets["Host"] === "object"
        ? capturedPackets["Host"]
        : {};

    hostsList = [DUMMY_ALL_HOST, DUMMY_BOOKMARKED_HOST];
    while (targetHostsDropdown.options.length > 0) {
      targetHostsDropdown.remove(0);
    }
    appendAllHostsOption(targetHostsDropdown);
    appendBookmarkedOption(targetHostsDropdown);

    packetStubByKey.clear();
    hydratedPacketCache.clear();

    Object.keys(hostMap).forEach((host) => {
      hostsList.push(host);
      const optionEl = document.createElement("option");
      optionEl.textContent = host;
      optionEl.value = host;
      targetHostsDropdown.appendChild(optionEl);
      const hostPackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
      hostPackets.forEach((packet, packetIndex) => {
        const packetKey = getPacketKey(packet, host, packetIndex);
        if (packet && typeof packet === "object") {
          packet.__packetKey = packetKey;
        }
        cachePacketStub(packetKey, packet);
      });
    });

    const availableHosts = hostsList.slice();
    const selectedHost =
      previousHost && availableHosts.includes(previousHost)
        ? previousHost
        : DUMMY_ALL_HOST;
    if (selectedHost) {
      targetHostsDropdown.value = selectedHost;
      hostFilterEl.value = selectedHost;
      p = getPacketsForSelectedHost(selectedHost);
    }

    document.getElementById("total-packets").textContent =
      "Total Packets: " + totalPacketCount();

    if (typeof filterInputEl.value === "string" && filterInputEl.value.trim()) {
      const shouldRefreshFilterUi = activeMainTab === MAIN_TAB_DATA;
      await runFilterQuery(filterInputEl.value, {
        trackHistory: false,
        updateUi: shouldRefreshFilterUi,
      });
      if (activeMainTab === MAIN_TAB_LIST) {
        showPacketList();
      }
    } else {
      filteredPackets = undefined;
      if (activeMainTab === MAIN_TAB_LIST) {
        showPacketList();
      }
      if (activeMainTab === MAIN_TAB_DATA && p.length > 0) {
        await handlePacketNavigation(undefined, null);
      }
      if (activeMainTab === MAIN_TAB_SUMMARY) {
        showSummary();
      }
    }

    return;
  }

  capturedPackets = loadResult.captureData || { Host: {}, "Final Summary": "" };
  finalSummary = capturedPackets["Final Summary"] || "";
  jsonCapture = "[lazy-capture-store]";
  fileLoaded(true);

  let loadedSessionState =
    loadResult.sessionState && typeof loadResult.sessionState === "object"
      ? loadResult.sessionState
      : null;

  // Reuse the existing session flow by processing a tiny synthetic payload.
  // processFile() rebuilds the host dropdown, bookmarks, notes, and panel state.
  const syntheticPayload = {
    [SESSION_CAPTURE_KEY]: capturedPackets,
  };
  if (loadedSessionState) {
    syntheticPayload[SESSION_STATE_KEY] = loadedSessionState;
  }
  processFile(
    new File([JSON.stringify(syntheticPayload)], "lazy-capture.json", {
      type: "application/json",
    }),
  );
}

/**
 * Reads and parses the JSON file, updates UI and state.
 * Uses chunked parsing for large files to avoid UI blocking.
 */
function processFile(file) {
  if (
    window.captureapi &&
    file &&
    typeof file.path === "string" &&
    file.path.trim()
  ) {
    void processCapturePath(file.path);
    return;
  }

  document.getElementById("loading-screen").style.display = "flex";
  document.getElementById("loading-container").style.display = "block";
  document.getElementById("loading-text").textContent = "Loading packets...";
  let loadedSessionState = null;
  const reader = new FileReader();
  reader.onload = async (event) => {
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
        .then(async (parsed) => {
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
          await finishProcessingFile();
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
      await finishProcessingFile();
    }
  };

  async function finishProcessingFile() {
    getCachedElement("target_hosts").hidden = false;
    getCachedElement("summary-btn").style.display = "block";
    // Reset host list and dropdowns for the new file
    hostsList = [DUMMY_ALL_HOST, DUMMY_BOOKMARKED_HOST];
    const targetHostsDropdown = getCachedElement("target_hosts");
    while (targetHostsDropdown.options.length > 0) {
      targetHostsDropdown.remove(0);
    }
    appendAllHostsOption(targetHostsDropdown);
    appendBookmarkedOption(targetHostsDropdown);
    bookmarkList.splice(0, bookmarkList.length);
    notesList = [];
    selectedNoteId = null;
    renderNotesList();
    const selectBookmarkEl = document.getElementById("selectBookmark");
    while (selectBookmarkEl.options.length > 1) {
      selectBookmarkEl.remove(1);
    }
    // Populate host dropdown with hosts from JSON
    packetStubByKey.clear();
    hydratedPacketCache.clear();
    for (const host in capturedPackets["Host"]) {
      hostsList.push(host);
      const newhost = document.createElement("option");
      newhost.textContent = host;
      newhost.value = host;
      targetHostsDropdown.appendChild(newhost);
      const hostPackets = Array.isArray(capturedPackets["Host"][host])
        ? capturedPackets["Host"][host]
        : [];
      hostPackets.forEach((packet, packetIndex) => {
        const packetKey = getPacketKey(packet, host, packetIndex);
        if (packet && typeof packet === "object") {
          packet.__packetKey = packetKey;
        }
        cachePacketStub(packetKey, packet);
      });
      isFileLoaded = true;
    }
    if (hostsList.length > 1) {
      writeLogEntry(`Hosts targeted discovered count=${hostsList.length - 1}`);
    }
    const timeframe = getPacketTimeframe();
    if (timeframe) {
      writeLogEntry(
        `Packet timeframe start="${timeframe.first}" end="${timeframe.last}"`,
      );
    }
    if (totalPacketCount() > 1) {
      writeLogEntry(`Total packet count=${totalPacketCount()}`);
    }
    clearFilterQuery();
    syncFilterHighlight();
    isFileLoaded = true;
    if (loadedSessionState) {
      restoreSessionState(loadedSessionState);
    }
    else {
      scheduleSessionKeychainAutoPopulate("file-load");
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
 * Updates the status bar with a message, then resets after 8 seconds.
 */
function statusUpdate(message) {
  status.textContent = message;
  setTimeout(() => {
    status.textContent = "PacketSnitch " + psVer + ": Ready";
  }, 10000);
}

/**
 * Loads all capturedPackets for a given host IP into packetsForHost.
 */
function hostPacketInfo(currentIp) {
  p = getPacketsForSelectedHost(currentIp);
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
  if (isAllHostsSelection(selectedHost)) return "";
  if (isBookmarkedSelection(selectedHost)) return BOOKMARK_FILTER_QUERY;
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
  void runFilterQuery(hostFilterQuery, { trackHistory: false });
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
const DATA_TOOLS_SELECTION_FIELD_SELECTOR =
  DATA_TOOLS_SELECTION_FIELD_IDS.map((fieldId) => `#${fieldId}`).join(", ");
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

function getCompressionAlgorithmsByPriority(preferredAlgorithm = "") {
  const normalizedPreferred = String(preferredAlgorithm || "").toLowerCase();
  const allAlgorithms = ["gzip", "deflate", "brotli"];
  if (!normalizedPreferred || !allAlgorithms.includes(normalizedPreferred)) {
    return allAlgorithms;
  }
  return [normalizedPreferred, ...allAlgorithms.filter((a) => a !== normalizedPreferred)];
}

function inferCompressionFromBytes(bytes) {
  if (!bytes || bytes.length < 2) return "";
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) return "gzip";
  if (bytes[0] === 0x78) return "deflate";
  return "";
}

async function decompressBytes(bytes, algorithm) {
  if (!bytes || !bytes.length) {
    throw new Error("No input bytes available for decompression");
  }
  if (typeof DecompressionStream !== "function") {
    throw new Error("DecompressionStream is unavailable");
  }
  const streamFormat =
    algorithm === "brotli"
      ? "br"
      : algorithm === "gzip"
        ? "gzip"
        : algorithm === "deflate"
          ? "deflate"
          : "";
  if (!streamFormat) {
    throw new Error(`Unsupported compression algorithm: ${algorithm}`);
  }

  const compressedBlob = new Blob([bytes]);
  const decompressedStream = compressedBlob
    .stream()
    .pipeThrough(new DecompressionStream(streamFormat));
  const decompressedArrayBuffer = await new Response(decompressedStream).arrayBuffer();
  return new Uint8Array(decompressedArrayBuffer);
}

async function tryDecompressBytes(bytes, preferredAlgorithm = "") {
  if (!bytes || !bytes.length) return null;
  const byMagic = inferCompressionFromBytes(bytes);
  const algorithmOrder = getCompressionAlgorithmsByPriority(
    preferredAlgorithm || byMagic,
  );

  for (const algorithm of algorithmOrder) {
    try {
      const decompressedBytes = await decompressBytes(bytes, algorithm);
      if (!decompressedBytes || decompressedBytes.length === 0) continue;
      if (decompressedBytes.length === bytes.length) continue;
      return {
        algorithm,
        bytes: decompressedBytes,
      };
    } catch {
      // Try next algorithm.
    }
  }

  return null;
}


async function getCurrentPacketCompressionHint() {
  const contextPacket = getCurrentContextPacket();
  const httpData = getCurrentHttpData(contextPacket);
  // packet payload hex is for brotli and it has to be the next packet in the stream
  // get the packet num in the current stream

  //const packetPayloadHex = contextPacket?.["Packet Info"]?.["Raw data"]?.["Payload"]["Hex Encoded"];
  const encoding = String(httpData?.["Content-Encoding"] || "").toLowerCase();
  if (encoding.includes("br") || encoding.includes("brotli")) return "brotli";
  if (encoding.includes("gzip") || encoding.includes("gz")) return "gzip";
  if (encoding.includes("deflate") || encoding.includes("zlib")) return "deflate";

  const extraInfoData = contextPacket?.["Extra Info"];
  const dataTypes = Array.isArray(extraInfoData?.["Data Types"])
    ? extraInfoData["Data Types"]
    : [];
  const dataTypeText = dataTypes.join(" ").toLowerCase();
  // for brotli we need to grab the payload from the packet after the HTTP header that reads br
  const packetPayload = getPacketPayloadBytes(getCurrentContextPacket(contextPacket, 1));
  const tryBrotli = await tryDecompressBytes(packetPayload, "brotli");
  if (tryBrotli) return "brotli";
  if (dataTypeText.includes("gzip") || dataTypeText.includes(" gz")) return "gzip";
  if (dataTypeText.includes("zlib") || dataTypeText.includes("deflate")) return "deflate";


  const payloadHex = getCurrentRawPayloadHex();
  if (!payloadHex) return "";
  try {
    return inferCompressionFromBytes(parseDataToolsInput("hex", payloadHex));
  } catch {
    return "";
  }
}

function getActiveConvDecompressionCandidate() {
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  if (!inputEl || !formatEl || !inputEl.value.trim()) return null;
  try {
    const bytes = parseDataToolsInput(formatEl.value, inputEl.value);
    const inferredAlgorithm = inferCompressionFromBytes(bytes);
    if (!inferredAlgorithm) return null;
    return {
      bytes,
      algorithm: inferredAlgorithm,
    };
  } catch {
    return null;
  }
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
  if (normalizedToken.length >= 3 && /.*\S[\s\S]*\S\r?\n$/.test(normalizedToken)) {
    addDataTypeGuessCandidate(candidateScores, "Protocol Token", 75);
  }
  if (normalizedToken.length >= 8) {
    addDataTypeGuessCandidate(candidateScores, "Alphanumeric Identifier", 50);
  }
  // recognize an ip address pattern with  optional port, but only if it doesn't contain letters to avoid false positives on hex strings
  if (/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b/.test(normalizedToken) && !/[A-Za-z]/.test(normalizedToken)) {
    addDataTypeGuessCandidate(candidateScores, "Network Endpoint", 85);
  }
  // reconize a mac address pattern with option delimaters and make sure its wihtin a reasonable length range to avoid false positives on hex strings
  if (/\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b/.test(normalizedToken) && normalizedToken.length <= 20) {
    addDataTypeGuessCandidate(candidateScores, "MAC Address", 85);
  }
  if (normalizedToken.length === 4 && /\p{Emoji}/u.test(normalizedToken)) {
    addDataTypeGuessCandidate(candidateScores, "Emoji", 60);
  }
  if (/\d+\.\d+/.test(normalizedToken) && !/\D/.test(normalizedToken)) {
    addDataTypeGuessCandidate(candidateScores, "Floating Point", 40);
  }
  else if (/\d+/.test(normalizedToken)) {
    addDataTypeGuessCandidate(candidateScores, "Integer", 35);
  }
  if (/\d{4}(-|\/)\d{2}(-|\/)\d{2}/.test(normalizedToken)) {
    addDataTypeGuessCandidate(candidateScores, "Date", 85);
  }
  if (/\d{2}:\d{2}:\d{2}/.test(normalizedToken)) {
    addDataTypeGuessCandidate(candidateScores, "Time", 85);
  }
  if (normalizedToken.length === 1) {
    if (/\x00/.test(normalizedToken)) {
      addDataTypeGuessCandidate(candidateScores, "Null Byte", 95);
      addDataTypeGuessCandidate(candidateScores, "Control Character", 90);
      addDataTypeGuessCandidate(candidateScores, "Delimiter", 95);
    }
    if (/\p{P}/u.test(normalizedToken)) {
      addDataTypeGuessCandidate(candidateScores, "Punctuation Character", 70);
      addDataTypeGuessCandidate(candidateScores, "Delimiter", 40);
    }
    if (/\p{S}/u.test(normalizedToken)) {
      addDataTypeGuessCandidate(candidateScores, "Symbol Character", 65);
    }
    if (/\p{C}/u.test(normalizedToken)) {
      addDataTypeGuessCandidate(candidateScores, "Control Character", 90);
    }
    if (/\p{Z}/u.test(normalizedToken)) {
      addDataTypeGuessCandidate(candidateScores, "Whitespace Character", 90);
    }
    if (/\p{M}/u.test(normalizedToken)) {
      addDataTypeGuessCandidate(candidateScores, "Combining Mark Character", 50);
    }
    if (/[A-Za-z]/.test(normalizedToken)) {
      if (/[aeiouAEIOU]/.test(normalizedToken)) {
        addDataTypeGuessCandidate(candidateScores, "Vowel", 85);
      } else {
        addDataTypeGuessCandidate(candidateScores, "Consonant", 85);
      }
      if (/[A-Z]/.test(normalizedToken)) {
        addDataTypeGuessCandidate(candidateScores, "Uppercase Letter", 85);
      } else {
        addDataTypeGuessCandidate(candidateScores, "Lowercase Letter", 85);
      }
    } else if (/\d/.test(normalizedToken)) {
      addDataTypeGuessCandidate(candidateScores, "Digit", 75);
    }
    // add detection for common delimeter characters
    if (/[:;.,\-_=+\/\\|?<>]/.test(normalizedToken)) {
      addDataTypeGuessCandidate(candidateScores, "Delimiter", 40);
    }
    addDataTypeGuessCandidate(candidateScores, "Byte", 90);
    return;
  }

}

function scanAsciiTextForDataTypeGuesses(inputText, candidateScores) {
  const sourceText = String(inputText || "");
  if (!sourceText.trim()) return;
  addStructuredTextTypeGuesses(sourceText, candidateScores);

  const trimmedSourceText = sourceText.trim();
  // Short standalone values never match the 8+ token scanner below, so
  // classify them directly instead of returning no guesses.
  if (trimmedSourceText.length <= 7 && !/\s/.test(trimmedSourceText)) {
    detectDataTypeGuessFromToken(trimmedSourceText, candidateScores);
    return;
  }

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
  if (candidateScores.size === 0) {
    const fallbackToken = normalizedDecoded.trim() || normalizedRaw.trim();
    if (fallbackToken.length === 1) {
      detectDataTypeGuessFromToken(fallbackToken, candidateScores);
    }
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

function decodeFtpFromBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const lines = text.split(/\r?\n/).filter((line) => line.trim());
  if (!lines.length) return null;

  const FTP_COMMANDS = new Set([
    "USER",
    "PASS",
    "ACCT",
    "CWD",
    "CDUP",
    "PWD",
    "TYPE",
    "PASV",
    "EPSV",
    "PORT",
    "EPRT",
    "LIST",
    "NLST",
    "RETR",
    "STOR",
    "DELE",
    "RNFR",
    "RNTO",
    "MKD",
    "RMD",
    "SYST",
    "STAT",
    "FEAT",
    "AUTH",
    "QUIT",
    "NOOP",
  ]);

  const fields = [];
  let detected = false;
  for (const line of lines) {
    const responseMatch = line.match(/^(\d{3})([\s-])(.*)/);
    if (responseMatch) {
      const code = responseMatch[1];
      const suffix = responseMatch[2] === "-" ? " (cont.)" : "";
      fields.push({
        name: `Response ${code}${suffix}`,
        value: responseMatch[3] || "—",
      });
      detected = true;
    } else {
      const parts = line.trim().split(/\s+/);
      const command = (parts[0] || "").toUpperCase();
      if (FTP_COMMANDS.has(command)) {
        fields.push({ name: "Command", value: command });
        if (parts.length > 1) {
          const argument = parts.slice(1).join(" ");
          fields.push({
            name: "Argument",
            value: argument.length > 160 ? argument.slice(0, 160) + "…" : argument,
          });
        }
        detected = true;
      }
    }

    if (fields.length >= 12) break;
  }

  if (!detected) return null;
  return { protocol: "FTP", fields };
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
    /^(USER|PASS|ACCT|CWD|CDUP|PWD|TYPE|PASV|EPSV|PORT|EPRT|LIST|NLST|RETR|STOR|DELE|RNFR|RNTO|MKD|RMD|SYST|STAT|FEAT|AUTH|NOOP|QUIT)\b/i.test(
      text,
    ) ||
    /^220[\s-].*ftp/i.test(text)
  )
    return "ftp";
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
    case "ftp":
      result = decodeFtpFromBytes(bytes);
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
  writeLogEntry(`[${threadName}] User opened data conversion tools view`);
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
  writeLogEntry(`[${threadName}] User opened notes workspace view`);
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
    p = packets;
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
let activeContextConvDecompression = null;
let activeContextHttpBodyDecompressionHint = "";
let activeContextStreamCompressionHint = "";
let activeContextPacket = null;
const convertContextMenuEl = getCachedElement("convert-context-menu");
const convertContextButtons = {
  copy: getCachedElement("ctx-copy"),
  paste: getCachedElement("ctx-paste"),
  saveJson: getCachedElement("ctx-save-json"),
  exportPacket: getCachedElement("ctx-export-packet"),
  exportPayload: getCachedElement("ctx-export-payload"),
  exportConvInput: getCachedElement("ctx-export-conv-input"),
  exportConvRaw: getCachedElement("ctx-export-conv-raw"),
  exportConvHex: getCachedElement("ctx-export-conv-hex"),
  exportConvBinary: getCachedElement("ctx-export-conv-binary"),
  exportConvDecimal: getCachedElement("ctx-export-conv-decimal"),
  exportConvDecimalInteger: getCachedElement("ctx-export-conv-decimal-integer"),
  exportConvAscii: getCachedElement("ctx-export-conv-ascii"),
  exportConvBase64: getCachedElement("ctx-export-conv-base64"),
  exportConvHashes: getCachedElement("ctx-export-conv-hashes"),
  exportConvDecodes: getCachedElement("ctx-export-conv-decodes"),
  hex: getCachedElement("convert-context-hex"),
  binary: getCachedElement("convert-context-binary"),
  base64: getCachedElement("convert-context-base64"),
  decimal: getCachedElement("convert-context-decimal"),
  ascii: getCachedElement("convert-context-ascii"),
  deriveGuess: getCachedElement("convert-context-derive-guess"),
  loadCursorAscii: getCachedElement("convert-context-load-cursor-ascii"),
  loadPayload: getCachedElement("convert-context-load-payload"),
  decompressConv: getCachedElement("convert-context-decompress-conv"),
  copyHex: getCachedElement("convert-context-copy-hex"),
  copyAscii: getCachedElement("convert-context-copy-ascii"),
  copyRaw: getCachedElement("convert-context-copy-raw"),
  filterIp: getCachedElement("ctx-filter-ip"),
  filterPort: getCachedElement("ctx-filter-port"),
  filterMac: getCachedElement("ctx-filter-mac"),
  filterLinkProtocol: getCachedElement("ctx-filter-link-protocol"),
  filterWireProtocol: getCachedElement("ctx-filter-wire-protocol"),
  filterAppProtocol: getCachedElement("ctx-filter-app-protocol"),
  filterProtocol: getCachedElement("ctx-filter-protocol"),
  filterMime: getCachedElement("ctx-filter-mime"),
  filterOrIp: getCachedElement("ctx-filter-or-ip"),
  filterOrPort: getCachedElement("ctx-filter-or-port"),
  filterOrMac: getCachedElement("ctx-filter-or-mac"),
  filterOrLinkProtocol: getCachedElement("ctx-filter-or-link-protocol"),
  filterOrWireProtocol: getCachedElement("ctx-filter-or-wire-protocol"),
  filterOrAppProtocol: getCachedElement("ctx-filter-or-app-protocol"),
  filterOrProtocol: getCachedElement("ctx-filter-or-protocol"),
  filterOrMime: getCachedElement("ctx-filter-or-mime"),
  filterNotIp: getCachedElement("ctx-filter-not-ip"),
  filterNotPort: getCachedElement("ctx-filter-not-port"),
  filterNotMac: getCachedElement("ctx-filter-not-mac"),
  filterNotLinkProtocol: getCachedElement("ctx-filter-not-link-protocol"),
  filterNotWireProtocol: getCachedElement("ctx-filter-not-wire-protocol"),
  filterNotAppProtocol: getCachedElement("ctx-filter-not-app-protocol"),
  filterNotProtocol: getCachedElement("ctx-filter-not-protocol"),
  filterNotMime: getCachedElement("ctx-filter-not-mime"),
  filterParenOpen: getCachedElement("ctx-filter-paren-open"),
  filterParenClose: getCachedElement("ctx-filter-paren-close"),
  filterParenWrap: getCachedElement("ctx-filter-paren-wrap"),
  filterClearIp: getCachedElement("ctx-filter-clear-ip"),
  filterClearPort: getCachedElement("ctx-filter-clear-port"),
  filterClearMac: getCachedElement("ctx-filter-clear-mac"),
  filterClearLinkProtocol: getCachedElement("ctx-filter-clear-link-protocol"),
  filterClearWireProtocol: getCachedElement("ctx-filter-clear-wire-protocol"),
  filterClearAppProtocol: getCachedElement("ctx-filter-clear-app-protocol"),
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
  notesSendListPacket: getCachedElement("ctx-notes-send-list-packet"),
  notesSendConvOutput: getCachedElement("ctx-notes-send-conv-output"),
  notesSendConvHashes: getCachedElement("ctx-notes-send-conv-hashes"),
  httpFileSave: getCachedElement("ctx-http-file-save"),
  httpFileSaveDecompressed: getCachedElement(
    "ctx-http-file-save-decompressed",
  ),
  httpFileLoad: getCachedElement("ctx-http-file-load"),
  httpFileLoadDecompressed: getCachedElement(
    "ctx-http-file-load-decompressed",
  ),
  httpFilePreview: getCachedElement("ctx-http-file-preview"),
  httpFilePreviewDecompressed: getCachedElement(
    "ctx-http-file-preview-decompressed",
  ),
  fileCarveSmb: getCachedElement("ctx-file-carve-smb"),
  fileCarveNfs: getCachedElement("ctx-file-carve-nfs"),
  fileCarveFtp: getCachedElement("ctx-file-carve-ftp"),
  followStreamConv: getCachedElement("ctx-follow-stream-conv"),
  followStreamConvDecompress: getCachedElement("ctx-follow-stream-conv-decompress"),
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
  fileCarve: getCachedElement("ctx-file-carve-submenu"),
  followStream: getCachedElement("ctx-follow-stream-submenu"),
};
const convertContextDividerEl = getCachedElement("convert-context-divider");
const convertContextSaveDividerEl = getCachedElement(
  "convert-context-bottom-divider",
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
  activeContextHttpBodyDecompressionHint = "";
  activeContextPacket = null;
  resetConvertContextSubmenuPositions();
  convertContextMenuEl.hidden = true;
}

function getPacketFromListContextTarget(target, offset = 0) {
  const row = target?.closest?.("tr[data-host][data-pkt-idx]");
  if (!row) return null;
  const host = String(row.dataset.host || "").trim();
  const packetIndex = Number.parseInt(row.dataset.pktIdx ?? "-1", 10) + offset;
  if (!host || !Number.isInteger(packetIndex) || packetIndex < 0) return null;
  const hostPackets = capturedPackets?.["Host"]?.[host];
  if (!Array.isArray(hostPackets)) return null;
  return hostPackets[packetIndex] || null;
}

function getCurrentContextPacket(target = null, offset = 0) {
  if (activeMainTab === MAIN_TAB_LIST) {
    const listPacket = getPacketFromListContextTarget(target || activeContextTarget, offset);
    if (listPacket) return listPacket;
  }
  if (activeContextPacket) return activeContextPacket;
  const packetCursor = getActivePacketCursor() + offset;
  if (packetCursor === null) return null;
  return p?.[packetCursor] || null;
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
    if (!filterQueries.mime) {
      const mimeType = extractContextMimeType(candidate);
      if (mimeType) {
        const safeMimeType = sanitizeFilterTerm(mimeType);
        filterQueries.mime = `mime.type: ${safeMimeType}`;
      }
    }
  }

  const currentPkt = p?.[index];
  if (currentPkt) {
    const wireProto = String(currentPkt?.["Packet Info"]?.["Protocol"] ?? "").toLowerCase().trim();
    const appProto = String(currentPkt?.["Extra Info"]?.["Traits"]?.["Network Data"]?.["Port Protcol"] ?? "").toLowerCase().trim();
    const safeWire = wireProto ? sanitizeFilterTerm(wireProto) : "";
    const safeApp = appProto && appProto !== "unknown" ? sanitizeFilterTerm(appProto) : "";
    const safeLink = String(currentPkt?.["Packet Info"]?.["link.proto"] ?? "").toLowerCase().trim();
    if (safeLink) {
      filterQueries.linkProtocol = `link.proto: ${safeLink}`;
    }
    if (safeWire) {
      filterQueries.wireProtocol = `transport.proto: ${safeWire}`;
    }
    if (safeApp) {
      filterQueries.appProtocol = `application.proto: ${safeApp}`;
    }
    if (safeWire && safeApp && safeLink) {
      filterQueries.protocol = `transport.proto: ${safeWire} && application.proto: ${safeApp} && link.proto: ${safeLink}`;
    } else if (safeWire) {
      filterQueries.protocol = `transport.proto: ${safeWire}`;
    } else if (safeApp) {
      filterQueries.protocol = `application.proto: ${safeApp}`;
    }
  }

  return filterQueries;
}

function getTrimmedSelectionText() {
  return window.getSelection()?.toString().trim() || "";
}

function getUtf8ByteLength(value) {
  const normalized = typeof value === "string" ? value : String(value || "");
  return DATA_TOOLS_TEXT_ENCODER.encode(normalized).length;
}

function getContextSelectionByteLength(target = activeContextTarget) {
  if (
    activeMainTab === MAIN_TAB_DATA_TOOLS &&
    target?.closest?.(DATA_TOOLS_SELECTION_FIELD_SELECTOR)
  ) {
    const byteRange = dataToolsSelectionState.selectedByteRange;
    if (
      byteRange &&
      Number.isFinite(byteRange.start) &&
      Number.isFinite(byteRange.end)
    ) {
      return Math.max(0, byteRange.end - byteRange.start);
    }
  }
  return getUtf8ByteLength(getTrimmedSelectionText());
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
  activeContextPacket = getCurrentContextPacket(target, 0);
  activeContextHttpBodyDecompressionHint = getCurrentHttpBodyCompressionHint(
    activeContextPacket,
  );

  const isHostDataTabActive = activeMainTab === MAIN_TAB_DATA;
  const allowFollowStreamActions =
    activeMainTab === MAIN_TAB_DATA || activeMainTab === MAIN_TAB_LIST;

  const hasSelectionContext = getContextSelectionByteLength(target) > 1;
  const hasContextSourceText = getUtf8ByteLength(sourceText || "") > 1;

  convertContextButtons.copy.style.display = hasSelectionContext
    ? "block"
    : "none";
  convertContextButtons.paste.style.display = showPaste ? "block" : "none";
  convertContextButtons.saveJson.style.display = showSaveJson
    ? "block"
    : "none";
  const hasPacketToExport = Boolean(getCurrentPacketForExport());
  const currentPayloadHex = getCurrentRawPayloadHex();
  const hasPayloadToExport = Boolean(currentPayloadHex);
  const isConvTabActive = activeMainTab === MAIN_TAB_DATA_TOOLS;
  const hasConvInputToExport =
    isConvTabActive && Boolean(getConvContextExportText("input"));
  const hasConvRawToExport =
    isConvTabActive && Boolean(getConvContextExportText("hex"));
  const hasConvHexToExport =
    isConvTabActive && Boolean(getConvContextExportText("hex"));
  const hasConvBinaryToExport =
    isConvTabActive && Boolean(getConvContextExportText("binary"));
  const hasConvDecimalToExport =
    isConvTabActive && Boolean(getConvContextExportText("decimal"));
  const hasConvDecimalIntegerToExport =
    isConvTabActive && Boolean(getConvContextExportText("decimal-integer"));
  const hasConvAsciiToExport =
    isConvTabActive && Boolean(getConvContextExportText("ascii"));
  const hasConvBase64ToExport =
    isConvTabActive && Boolean(getConvContextExportText("base64"));
  const hasConvHashesToExport =
    isConvTabActive && Boolean(getConvContextExportText("hashes"));
  const hasConvDecodesToExport =
    isConvTabActive && Boolean(getConvContextExportText("decodes"));
  const hasConvExportActions =
    hasConvInputToExport ||
    hasConvRawToExport ||
    hasConvHexToExport ||
    hasConvBinaryToExport ||
    hasConvDecimalToExport ||
    hasConvDecimalIntegerToExport ||
    hasConvAsciiToExport ||
    hasConvBase64ToExport ||
    hasConvHashesToExport ||
    hasConvDecodesToExport;
  const hasHttpBody = Boolean(extractHttpBodyHex(getCurrentRawPayloadHex()));
  const canCarveSmbStream = canCarveCurrentStreamForProtocol(
    "smb",
    activeContextPacket,
  );
  const canCarveNfsStream = canCarveCurrentStreamForProtocol(
    "nfs",
    activeContextPacket,
  );
  const canCarveFtpStream = canCarveCurrentStreamForProtocol(
    "ftp",
    activeContextPacket,
  );
  const hasFileCarveActions =
    hasHttpBody || canCarveSmbStream || canCarveNfsStream || canCarveFtpStream;
  convertContextButtons.exportPacket.style.display = hasPacketToExport
    ? "block"
    : "none";
  convertContextButtons.exportPayload.style.display = hasPayloadToExport
    ? "block"
    : "none";
  convertContextButtons.exportConvInput.style.display = hasConvInputToExport
    ? "block"
    : "none";
  convertContextButtons.exportConvRaw.style.display = hasConvRawToExport
    ? "block"
    : "none";
  convertContextButtons.exportConvHex.style.display = hasConvHexToExport
    ? "block"
    : "none";
  convertContextButtons.exportConvBinary.style.display = hasConvBinaryToExport
    ? "block"
    : "none";
  convertContextButtons.exportConvDecimal.style.display = hasConvDecimalToExport
    ? "block"
    : "none";
  convertContextButtons.exportConvDecimalInteger.style.display =
    hasConvDecimalIntegerToExport ? "block" : "none";
  convertContextButtons.exportConvAscii.style.display = hasConvAsciiToExport
    ? "block"
    : "none";
  convertContextButtons.exportConvBase64.style.display = hasConvBase64ToExport
    ? "block"
    : "none";
  convertContextButtons.exportConvHashes.style.display = hasConvHashesToExport
    ? "block"
    : "none";
  convertContextButtons.exportConvDecodes.style.display = hasConvDecodesToExport
    ? "block"
    : "none";
  convertContextButtons.httpFileSave.style.display = hasHttpBody
    ? "block"
    : "none";
  convertContextButtons.httpFileSaveDecompressed.style.display =
    hasHttpBody && activeContextHttpBodyDecompressionHint
      ? "block"
      : "none";
  convertContextButtons.httpFileLoad.style.display = hasHttpBody
    ? "block"
    : "none";
  convertContextButtons.httpFileLoadDecompressed.style.display =
    hasHttpBody && activeContextHttpBodyDecompressionHint
      ? "block"
      : "none";
  convertContextButtons.httpFilePreview.style.display = hasHttpBody
    ? "block"
    : "none";
  convertContextButtons.httpFilePreviewDecompressed.style.display =
    hasHttpBody && activeContextHttpBodyDecompressionHint
      ? "block"
      : "none";
  convertContextButtons.fileCarveSmb.style.display = canCarveSmbStream
    ? "block"
    : "none";
  convertContextButtons.fileCarveNfs.style.display = canCarveNfsStream
    ? "block"
    : "none";
  convertContextButtons.fileCarveFtp.style.display = canCarveFtpStream
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
  activeContextConvDecompression = getActiveConvDecompressionCandidate();
  convertContextButtons.decompressConv.style.display = activeContextConvDecompression
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
  convertContextButtons.filterIp.style.display = isHostDataTabActive && filterQueries.ip
    ? "block"
    : "none";
  convertContextButtons.filterPort.style.display =
    isHostDataTabActive && filterQueries.port
      ? "block"
      : "none";
  convertContextButtons.filterMac.style.display = isHostDataTabActive && filterQueries.mac
    ? "block"
    : "none";
  convertContextButtons.filterLinkProtocol.style.display = isHostDataTabActive
    ? "block"
    : "none";
  convertContextButtons.filterWireProtocol.style.display =
    isHostDataTabActive && filterQueries.wireProtocol
      ? "block"
      : "none";
  convertContextButtons.filterAppProtocol.style.display =
    isHostDataTabActive && filterQueries.appProtocol
      ? "block"
      : "none";
  convertContextButtons.filterProtocol.style.display =
    isHostDataTabActive && filterQueries.protocol
      ? "block"
      : "none";
  convertContextButtons.filterMime.style.display = isHostDataTabActive && filterQueries.mime
    ? "block"
    : "none";
  convertContextButtons.filterOrIp.style.display = isHostDataTabActive && filterQueries.ip
    ? "block"
    : "none";
  convertContextButtons.filterOrPort.style.display =
    isHostDataTabActive && filterQueries.port
      ? "block"
      : "none";
  convertContextButtons.filterOrMac.style.display = isHostDataTabActive && filterQueries.mac
    ? "block"
    : "none";
  convertContextButtons.filterOrLinkProtocol.style.display = isHostDataTabActive
    ? "block"
    : "none";
  convertContextButtons.filterOrWireProtocol.style.display =
    isHostDataTabActive && filterQueries.wireProtocol
      ? "block"
      : "none";
  convertContextButtons.filterOrAppProtocol.style.display =
    isHostDataTabActive && filterQueries.appProtocol
      ? "block"
      : "none";
  convertContextButtons.filterOrProtocol.style.display =
    isHostDataTabActive && filterQueries.protocol
      ? "block"
      : "none";
  convertContextButtons.filterOrMime.style.display = isHostDataTabActive && filterQueries.mime
    ? "block"
    : "none";
  convertContextButtons.filterNotIp.style.display = isHostDataTabActive && filterQueries.ip
    ? "block"
    : "none";
  convertContextButtons.filterNotPort.style.display =
    isHostDataTabActive && filterQueries.port
      ? "block"
      : "none";
  convertContextButtons.filterNotMac.style.display =
    isHostDataTabActive && filterQueries.mac
      ? "block"
      : "none";
  convertContextButtons.filterNotLinkProtocol.style.display = isHostDataTabActive
    ? "block"
    : "none";
  convertContextButtons.filterNotWireProtocol.style.display =
    isHostDataTabActive && filterQueries.wireProtocol
      ? "block"
      : "none";
  convertContextButtons.filterNotAppProtocol.style.display =
    isHostDataTabActive && filterQueries.appProtocol
      ? "block"
      : "none";
  convertContextButtons.filterNotProtocol.style.display =
    isHostDataTabActive && filterQueries.protocol
      ? "block"
      : "none";
  convertContextButtons.filterNotMime.style.display =
    isHostDataTabActive && filterQueries.mime
      ? "block"
      : "none";
  convertContextButtons.filterParenOpen.style.display = isHostDataTabActive
    ? "block"
    : "none";
  convertContextButtons.filterParenClose.style.display = isHostDataTabActive
    ? "block"
    : "none";
  convertContextButtons.filterParenWrap.style.display = isHostDataTabActive
    ? "block"
    : "none";
  convertContextButtons.filterClearIp.style.display = isHostDataTabActive && filterQueries.ip
    ? "block"
    : "none";
  convertContextButtons.filterClearPort.style.display =
    isHostDataTabActive && filterQueries.port
      ? "block"
      : "none";
  convertContextButtons.filterClearMac.style.display =
    isHostDataTabActive && filterQueries.mac
      ? "block"
      : "none";
  convertContextButtons.filterClearLinkProtocol.style.display =
    isHostDataTabActive ? "block" : "none";
  convertContextButtons.filterClearWireProtocol.style.display =
    isHostDataTabActive && filterQueries.wireProtocol ? "block" : "none";
  convertContextButtons.filterClearAppProtocol.style.display =
    isHostDataTabActive && filterQueries.appProtocol ? "block" : "none";
  convertContextButtons.filterClearProtocol.style.display =
    isHostDataTabActive && filterQueries.protocol ? "block" : "none";
  convertContextButtons.filterClearMime.style.display =
    isHostDataTabActive && filterQueries.mime
      ? "block"
      : "none";
  const allowNotesDataFromContext =
    activeMainTab === MAIN_TAB_DATA ||
    activeMainTab === MAIN_TAB_STATS ||
    activeMainTab === MAIN_TAB_LIST ||
    activeMainTab === MAIN_TAB_DATA_TOOLS ||
    activeMainTab === MAIN_TAB_CRYPT;
  const allowConvNotesActions = activeMainTab === MAIN_TAB_DATA_TOOLS;
  const allowKeystoreContextActions =
    activeMainTab === MAIN_TAB_DATA ||
    activeMainTab === MAIN_TAB_DATA_TOOLS ||
    activeMainTab === MAIN_TAB_CRYPT ||
    activeMainTab === MAIN_TAB_KEYSTORE;
  const hasCookieActions = Boolean(cookieJarText);
  const hasContextDataForNotes =
    allowNotesDataFromContext &&
    (hasContextSourceText || hasSelectionContext);
  const hasListVisibleDataForNotes =
    activeMainTab === MAIN_TAB_LIST &&
    Boolean(buildListVisibleDataNoteText(target));
  const hasConvOutputForNotes =
    allowConvNotesActions && Boolean(buildConvConvertedOutputNoteText());
  const hasConvHashesForNotes =
    allowConvNotesActions && Boolean(buildConvHashesNoteText());
  convertContextButtons.notesSendData.style.display = hasContextDataForNotes
    ? "block"
    : "none";
  convertContextButtons.notesSendListPacket.style.display =
    hasListVisibleDataForNotes ? "block" : "none";
  convertContextButtons.notesSendConvOutput.style.display =
    hasConvOutputForNotes ? "block" : "none";
  convertContextButtons.notesSendConvHashes.style.display =
    hasConvHashesForNotes ? "block" : "none";
  const hasNotesActions =
    hasContextDataForNotes ||
    hasListVisibleDataForNotes ||
    hasConvOutputForNotes ||
    hasConvHashesForNotes;
  const hasCopyActions =
    hasSelectionContext || isHexViewTarget || hasCookieActions;
  const hasClipboardActions = hasCopyActions || showPaste;
  const hasGeneralActions = hasClipboardActions;
  const hasDataTypeActions =
    formats.length > 0 ||
    hasPayloadToExport ||
    Boolean(activeContextConvDecompression) ||
    hasCursorAsciiValue ||
    hasDeriveGuessInput;
  const hasFilterActions =
    isHostDataTabActive && Object.values(filterQueries).some(Boolean);
  const hasContextTextKeystoreActions =
    allowKeystoreContextActions && (hasSelectionContext || hasContextSourceText);
  const hasManualKeystoreUriAction =
    allowKeystoreContextActions && showManualKeystoreUri;
  const hasKeystoreActions =
    hasContextTextKeystoreActions || hasManualKeystoreUriAction;
  const hasExportActions =
    showSaveJson ||
    hasPacketToExport ||
    hasPayloadToExport ||
    hasCookieActions ||
    hasConvExportActions;
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
  convertContextSubmenus.keystoreUri.style.display = hasManualKeystoreUriAction
    ? "block"
    : "none";
  convertContextSubmenus.export.style.display = hasExportActions
    ? "block"
    : "none";
  convertContextSubmenus.httpFile.style.display = hasHttpBody
    ? "block"
    : "none";
  convertContextSubmenus.fileCarve.style.display = hasFileCarveActions
    ? "block"
    : "none";
  const hasFollowStreamActions =
    allowFollowStreamActions && Boolean(getCurrentStreamTuple());
  activeContextStreamCompressionHint = hasFollowStreamActions
    ? getCurrentPacketCompressionHint()
    : "";
  convertContextButtons.followStreamConvDecompress.style.display =
    hasFollowStreamActions && activeContextStreamCompressionHint
      ? "block"
      : "none";
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
    !hasFileCarveActions &&
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
        hasHttpBody ||
        hasFileCarveActions)
      ? "block"
      : "none";
  convertContextSaveDividerEl.style.display =
    (hasExportActions || hasHttpBody || hasFileCarveActions) &&
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

async function loadActiveConvInputDecompressedFromContextMenu() {
  const decompressionCandidate = activeContextConvDecompression;
  hideConvertContextMenu();
  if (!decompressionCandidate?.bytes) {
    statusUpdate("Status: No compressed Conv data detected");
    return;
  }

  const decompressedCandidate = await tryDecompressBytes(
    decompressionCandidate.bytes,
    decompressionCandidate.algorithm,
  );
  if (!decompressedCandidate?.bytes) {
    statusUpdate("Status: Failed to decompress Conv data");
    return;
  }

  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  inputEl.value = bytesToHexString(decompressedCandidate.bytes);
  formatEl.value = "hex";
  showDataTools();
  runDataToolsConversion();
  writeLogEntry(
    `Context conversion decompressed Conv input algorithm=${decompressedCandidate.algorithm}`,
  );
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
const STREAM_LOADING_THRESHOLD = 10;
const STREAM_CONTEXT_WARN_PACKET_THRESHOLD = 100;
const STREAM_ASYNC_PACKET_YIELD_INTERVAL = 2000;
const STREAM_ASYNC_HEX_YIELD_INTERVAL = 200;

function yieldToRenderer() {
  if (typeof window !== "undefined" && typeof window.requestAnimationFrame === "function") {
    return new Promise((resolve) => {
      window.requestAnimationFrame(() => resolve());
    });
  }
  return new Promise((resolve) => setTimeout(resolve, 0));
}

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

function confirmFollowStreamContextMenuLoad(tabLabel, packetCount) {
  if (packetCount <= STREAM_CONTEXT_WARN_PACKET_THRESHOLD) return true;
  return window.confirm(
    `This stream contains ${packetCount} packets. Loading it into the ${tabLabel} tab can consume significant memory and may bog down the UI.\n\nContinue?`,
  );
}

function getStreamTupleForPacket(packet) {
  const packetInfo = packet?.["Packet Info"];
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
 * Returns metadata about the current packet's stream (4-tuple: srcIp, srcPort,
 * dstIp, dstPort, protocol), or null if no current packet is loaded.
 */
function getCurrentStreamTuple() {
  return getStreamTupleForPacket(getCurrentContextPacket());
}

/**
 * Collects all packets across all hosts in capturedPackets that belong to the
 * same bidirectional conversation as the current packet, sorted by timestamp.
 * Returns an array of packet objects, or [] when no stream can be determined.
 */
function getFollowStreamPackets(packet = null) {
  const tuple = packet
    ? getStreamTupleForPacket(packet)
    : getCurrentStreamTuple();
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
  // Sort by packet chronology using timestamp, then Packet Processed and Index.
  matches.sort((a, b) => {
    return comparePacketsChronologically(a, b);
  });
  return matches;
}

async function getFollowStreamPacketsAsync(packet = null) {
  const tuple = packet
    ? getStreamTupleForPacket(packet)
    : getCurrentStreamTuple();
  if (!tuple) return [];
  const { srcIp, srcPort, dstIp, dstPort, protocol } = tuple;
  const hasPorts = srcPort !== null && dstPort !== null;
  const matches = [];
  const hosts = capturedPackets?.["Host"];
  if (!hosts || typeof hosts !== "object") return [];

  let scannedPacketCount = 0;
  for (const host of Object.values(hosts)) {
    if (!Array.isArray(host)) continue;
    for (const pkt of host) {
      const pi = pkt?.["Packet Info"];
      if (!pi) {
        scannedPacketCount += 1;
        if (scannedPacketCount % STREAM_ASYNC_PACKET_YIELD_INTERVAL === 0) {
          await yieldToRenderer();
        }
        continue;
      }

      const pProto = pi["Protocol"] || "TCP";
      if (pProto === protocol) {
        const pSrcIp = pi["IP"]?.["Source IP"];
        const pDstIp = pi["IP"]?.["Destination IP"];
        if (pSrcIp && pDstIp) {
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

      scannedPacketCount += 1;
      if (scannedPacketCount % STREAM_ASYNC_PACKET_YIELD_INTERVAL === 0) {
        await yieldToRenderer();
      }
    }
  }

  await yieldToRenderer();
  matches.sort((a, b) => {
    return comparePacketsChronologically(a, b);
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

async function buildStreamHexAsync(streamPackets) {
  if (!streamPackets.length) return null;
  const parts = [];
  let scanned = 0;
  for (const pkt of streamPackets) {
    const payloadHex =
      pkt?.["Packet Info"]?.["Raw data"]?.["Payload"]?.["Hex Encoded"];
    if (typeof payloadHex === "string" && payloadHex.length > 0) {
      parts.push(payloadHex);
    }
    scanned += 1;
    if (scanned % STREAM_ASYNC_HEX_YIELD_INTERVAL === 0) {
      await yieldToRenderer();
    }
  }
  return parts.length ? parts.join("") : null;
}

function alignTo4(value) {
  return (value + 3) & ~3;
}

function bytesToHexString(bytes) {
  return Array.from(bytes || [])
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getPacketPayloadHex(packet) {
  const payloadHex =
    packet?.["Packet Info"]?.["Raw data"]?.["Payload"]?.["Hex Encoded"];
  return typeof payloadHex === "string" ? payloadHex : "";
}

function getPacketPayloadBytes(packet) {
  const payloadHex = getPacketPayloadHex(packet);
  if (!payloadHex) return null;
  try {
    return parseDataToolsInput("hex", payloadHex);
  } catch {
    return null;
  }
}

function getPacketTransportData(packet) {
  const packetInfo = packet?.["Packet Info"];
  if (!packetInfo) return null;
  const protocol = packetInfo["Protocol"] || "TCP";
  return packetInfo[protocol] || null;
}

function buildBidirectionalStreamKey(packetInfo) {
  if (!packetInfo || typeof packetInfo !== "object") return "";
  const transportName = String(packetInfo["Protocol"] || "Unknown");
  const transportData = packetInfo[transportName] || {};
  const sourceIp = packetInfo?.["IP"]?.["Source IP"] ?? "";
  const destinationIp = packetInfo?.["IP"]?.["Destination IP"] ?? "";
  const sourcePort = transportData?.["Source port"] ?? "";
  const destinationPort = transportData?.["Destination port"] ?? "";

  const endpointA = `${sourceIp}:${sourcePort}`;
  const endpointB = `${destinationIp}:${destinationPort}`;
  const [firstEndpoint, secondEndpoint] = [endpointA, endpointB].sort();
  return `${transportName}|${firstEndpoint}|${secondEndpoint}`;
}

function parseTcpSequenceNumber(transportData) {
  const sequenceCandidates = [
    transportData?.["TCP Sequence Number"],
    transportData?.["tcp.seq"],
    transportData?.["Sequence Number"],
    transportData?.["Sequence"],
  ];
  for (const candidate of sequenceCandidates) {
    const parsed = Number(candidate);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function getTcpSegmentLength(packetInfo, transportData) {
  const payloadLenRaw = Number(packetInfo?.["Raw data"]?.["Payload Length"]);
  const payloadLen = Number.isFinite(payloadLenRaw) && payloadLenRaw > 0
    ? payloadLenRaw
    : 0;

  const flagsText = String(transportData?.["TCP Flag Data"]?.["Flags"] || "").toUpperCase();
  const controlByteLength =
    (flagsText.includes("SYN") ? 1 : 0) + (flagsText.includes("FIN") ? 1 : 0);
  return payloadLen + controlByteLength;
}

function mergeSequenceRange(ranges, start, end) {
  if (!Array.isArray(ranges) || !Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
    return;
  }

  ranges.push({ start, end });
  ranges.sort((left, right) => left.start - right.start);

  const merged = [];
  for (const currentRange of ranges) {
    if (!merged.length) {
      merged.push({ ...currentRange });
      continue;
    }
    const lastRange = merged[merged.length - 1];
    if (currentRange.start <= lastRange.end) {
      lastRange.end = Math.max(lastRange.end, currentRange.end);
      continue;
    }
    merged.push({ ...currentRange });
  }

  ranges.length = 0;
  ranges.push(...merged);
}

function getSequenceRangeOverlapLength(ranges, start, end) {
  if (!Array.isArray(ranges) || end <= start) return 0;
  let overlapLength = 0;
  for (const range of ranges) {
    if (range.end <= start) continue;
    if (range.start >= end) break;
    const overlapStart = Math.max(start, range.start);
    const overlapEnd = Math.min(end, range.end);
    if (overlapEnd > overlapStart) {
      overlapLength += overlapEnd - overlapStart;
    }
  }
  return overlapLength;
}

function getTcpStreamArrivalStatusByPacketKey(streamPackets) {
  const statusByPacketKey = new Map();
  if (!Array.isArray(streamPackets) || streamPackets.length === 0) {
    return statusByPacketKey;
  }

  const streamStateByDirection = new Map();
  streamPackets.forEach((packet) => {
    const packetInfo = packet?.["Packet Info"] || {};
    const protocol = String(packetInfo["Protocol"] || "").toUpperCase();
    const packetKey = getPacketKey(packet);
    if (!packetKey || protocol !== "TCP") return;

    const transportData = packetInfo["TCP"] || {};
    const sourceIp = packetInfo?.["IP"]?.["Source IP"] || "";
    const destinationIp = packetInfo?.["IP"]?.["Destination IP"] || "";
    const sourcePort = transportData?.["Source port"] ?? "";
    const destinationPort = transportData?.["Destination port"] ?? "";
    const directionKey = `${sourceIp}:${sourcePort}>${destinationIp}:${destinationPort}`;
    const sequenceNumber = parseTcpSequenceNumber(transportData);
    const segmentLength = getTcpSegmentLength(packetInfo, transportData);

    const state = streamStateByDirection.get(directionKey) || {
      seenRanges: [],
      maxStartObserved: null,
    };

    if (sequenceNumber === null || segmentLength <= 0) {
      statusByPacketKey.set(packetKey, {
        label: "In-order TCP segment",
        isRetransmission: false,
        isOutOfOrder: false,
      });
      streamStateByDirection.set(directionKey, state);
      return;
    }

    const sequenceEnd = sequenceNumber + segmentLength;
    const overlapLength = getSequenceRangeOverlapLength(
      state.seenRanges,
      sequenceNumber,
      sequenceEnd,
    );
    const isRetransmission = overlapLength > 0;
    const isOutOfOrder =
      Number.isFinite(state.maxStartObserved) && sequenceNumber < state.maxStartObserved;

    let label = "In-order TCP segment";
    if (isRetransmission && isOutOfOrder) {
      label = "Retransmission (out-of-order arrival)";
      retransmissionList.push(packetKey);
      outOfOrderList.push(packetKey);
    } else if (isRetransmission) {
      label = "Retransmission";
      retransmissionList.push(packetKey);
    } else if (isOutOfOrder) {
      label = "Out-of-order arrival";
      outOfOrderList.push(packetKey);
    }
    statusByPacketKey.set(packetKey, {
      label,
      isRetransmission,
      isOutOfOrder,
    });

    mergeSequenceRange(state.seenRanges, sequenceNumber, sequenceEnd);
    state.maxStartObserved = Number.isFinite(state.maxStartObserved)
      ? Math.max(state.maxStartObserved, sequenceNumber)
      : sequenceNumber;
    streamStateByDirection.set(directionKey, state);
  });

  return statusByPacketKey;
}

function readUint32Le(bytes, offset) {
  if (!bytes || offset < 0 || offset + 4 > bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(offset, true);
}

function readUint16Le(bytes, offset) {
  if (!bytes || offset < 0 || offset + 2 > bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint16(offset, true);
}

function readUint32Be(bytes, offset) {
  if (!bytes || offset < 0 || offset + 4 > bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(offset, false);
}

function readUint64LeNumber(bytes, offset) {
  if (!bytes || offset < 0 || offset + 8 > bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (typeof view.getBigUint64 === "function") {
    const value = view.getBigUint64(offset, true);
    const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
    if (value > maxSafe) return null;
    return Number(value);
  }
  const low = view.getUint32(offset, true);
  const high = view.getUint32(offset + 4, true);
  if (high > 0x1fffff) return null;
  return high * 0x100000000 + low;
}

function readUint64BeNumber(bytes, offset) {
  if (!bytes || offset < 0 || offset + 8 > bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (typeof view.getBigUint64 === "function") {
    const value = view.getBigUint64(offset, false);
    const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
    if (value > maxSafe) return null;
    return Number(value);
  }
  const high = view.getUint32(offset, false);
  const low = view.getUint32(offset + 4, false);
  if (high > 0x1fffff) return null;
  return high * 0x100000000 + low;
}

function readUint64LeHex(bytes, offset) {
  if (!bytes || offset < 0 || offset + 8 > bytes.length) return "";
  return bytesToHexString(bytes.slice(offset, offset + 8).reverse());
}

function decodeUtf16Le(bytes) {
  if (!bytes || bytes.length === 0) return "";
  const maxLen = bytes.length - (bytes.length % 2);
  const evenBytes = bytes.slice(0, maxLen);
  try {
    return new TextDecoder("utf-16le").decode(evenBytes).replace(/\u0000/g, "");
  } catch {
    return "";
  }
}

function sanitizeCarveFilename(name) {
  const raw = String(name || "").trim();
  if (!raw) return "";
  const parts = raw.split(/[\\/]/).filter(Boolean);
  const leaf = parts.length ? parts[parts.length - 1] : raw;
  return leaf.replace(/[\u0000-\u001f<>:"|?*]/g, "_").trim();
}

function addSegmentToEntry(entry, offset, bytes) {
  if (!entry || !Number.isInteger(offset) || offset < 0) return;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return;
  entry.segments.push({ offset, bytes });
}

function assembleSegments(segments) {
  if (!Array.isArray(segments) || segments.length === 0) return null;
  const ordered = segments
    .filter(
      (segment) =>
        segment &&
        Number.isInteger(segment.offset) &&
        segment.offset >= 0 &&
        segment.bytes instanceof Uint8Array &&
        segment.bytes.length > 0,
    )
    .sort((a, b) => a.offset - b.offset);
  if (!ordered.length) return null;
  const totalLength = ordered.reduce(
    (maxLength, segment) =>
      Math.max(maxLength, segment.offset + segment.bytes.length),
    0,
  );
  if (!Number.isFinite(totalLength) || totalLength <= 0) return null;
  const output = new Uint8Array(totalLength);
  ordered.forEach((segment) => {
    output.set(segment.bytes, segment.offset);
  });
  return output;
}

function extractSmbFileCandidates(streamPackets) {
  const fileEntries = new Map();
  const createRequestByMessageId = new Map();
  const readRequestByMessageId = new Map();
  const fileIdToName = new Map();

  const getOrCreateFileEntry = (fileId) => {
    if (!fileEntries.has(fileId)) {
      fileEntries.set(fileId, {
        fileId,
        name: "",
        segments: [],
      });
    }
    return fileEntries.get(fileId);
  };

  streamPackets.forEach((packet) => {
    const transportData = getPacketTransportData(packet);
    if (!transportData?.["SMB"]) return;
    const payload = getPacketPayloadBytes(packet);
    if (!payload || payload.length < 64) return;
    if (
      payload[0] !== 0xfe ||
      payload[1] !== 0x53 ||
      payload[2] !== 0x4d ||
      payload[3] !== 0x42
    ) {
      return;
    }

    const command = readUint16Le(payload, 12);
    const flags = readUint32Le(payload, 16);
    const messageId = readUint64LeHex(payload, 24);
    if (command === null || flags === null || !messageId) return;
    const isResponse = Boolean(flags & 0x00000001);

    if (command === 0x0005) {
      if (!isResponse) {
        const nameOffset = readUint16Le(payload, 108);
        const nameLength = readUint16Le(payload, 110);
        if (
          nameOffset !== null &&
          nameLength !== null &&
          nameLength > 0 &&
          nameOffset + nameLength <= payload.length
        ) {
          const rawName = decodeUtf16Le(
            payload.slice(nameOffset, nameOffset + nameLength),
          );
          const cleanedName = rawName.trim();
          if (cleanedName) {
            createRequestByMessageId.set(messageId, cleanedName);
          }
        }
      } else {
        if (payload.length < 144) return;
        const fileId = bytesToHexString(payload.slice(128, 144));
        if (!fileId) return;
        const fileName = createRequestByMessageId.get(messageId) || "";
        if (fileName) fileIdToName.set(fileId, fileName);
        const entry = getOrCreateFileEntry(fileId);
        if (fileName) entry.name = fileName;
      }
      return;
    }

    if (command === 0x0009 && !isResponse) {
      const dataOffset = readUint16Le(payload, 66);
      const dataLength = readUint32Le(payload, 68);
      const fileOffset = readUint64LeNumber(payload, 72);
      if (
        dataOffset === null ||
        dataLength === null ||
        fileOffset === null ||
        payload.length < 96
      ) {
        return;
      }
      const fileId = bytesToHexString(payload.slice(80, 96));
      if (!fileId || dataLength === 0) return;
      const dataEnd = dataOffset + dataLength;
      if (dataOffset < 0 || dataEnd > payload.length) return;
      const chunk = payload.slice(dataOffset, dataEnd);
      const entry = getOrCreateFileEntry(fileId);
      if (!entry.name && fileIdToName.has(fileId)) {
        entry.name = fileIdToName.get(fileId);
      }
      addSegmentToEntry(entry, fileOffset, chunk);
      return;
    }

    if (command === 0x0008) {
      if (!isResponse) {
        const fileOffset = readUint64LeNumber(payload, 72);
        if (fileOffset === null || payload.length < 96) return;
        const fileId = bytesToHexString(payload.slice(80, 96));
        if (!fileId) return;
        readRequestByMessageId.set(messageId, {
          fileId,
          fileOffset,
        });
        return;
      }

      const readRequest = readRequestByMessageId.get(messageId);
      if (!readRequest) return;
      const dataOffset = payload[66];
      const dataLength = readUint32Le(payload, 68);
      if (dataLength === null || dataLength === 0) return;
      const dataEnd = dataOffset + dataLength;
      if (dataOffset < 0 || dataEnd > payload.length) return;
      const chunk = payload.slice(dataOffset, dataEnd);
      const entry = getOrCreateFileEntry(readRequest.fileId);
      if (!entry.name && fileIdToName.has(readRequest.fileId)) {
        entry.name = fileIdToName.get(readRequest.fileId);
      }
      addSegmentToEntry(entry, readRequest.fileOffset, chunk);
    }
  });

  const candidates = [];
  for (const entry of fileEntries.values()) {
    const bytes = assembleSegments(entry.segments);
    if (!bytes || bytes.length === 0) continue;
    const cleanName = sanitizeCarveFilename(entry.name);
    const fallbackId = entry.fileId.slice(0, 12) || "unknown";
    const label = cleanName
      ? `${cleanName} (${bytes.length} bytes)`
      : `SMB file ${fallbackId} (${bytes.length} bytes)`;
    candidates.push({
      label,
      fileName: cleanName || `smb-file-${fallbackId}.bin`,
      bytes,
    });
  }
  return candidates;
}

async function hydratePacketCollection(packetList) {
  if (!Array.isArray(packetList) || packetList.length === 0) return [];
  const hydratedPackets = [];
  for (let packetIndex = 0; packetIndex < packetList.length; packetIndex += 1) {
    const hydratedPacket = await ensurePacketHydrated(packetList[packetIndex]);
    hydratedPackets.push(hydratedPacket || packetList[packetIndex]);
  }
  return hydratedPackets;
}

function parseRpcBaseOffset(payload) {
  if (!payload || payload.length < 8) return 0;
  const recordMark = readUint32Be(payload, 0);
  if (recordMark === null) return 0;
  if ((recordMark & 0x80000000) !== 0) {
    const fragmentLength = recordMark & 0x7fffffff;
    if (fragmentLength > 0 && fragmentLength + 4 <= payload.length) {
      return 4;
    }
  }
  return 0;
}

function parseRpcCallArgsOffset(payload, baseOffset) {
  let cursor = baseOffset + 24;
  if (cursor + 8 > payload.length) return null;
  const credentialLength = readUint32Be(payload, cursor + 4);
  if (credentialLength === null) return null;
  cursor = alignTo4(cursor + 8 + credentialLength);
  if (cursor + 8 > payload.length) return null;
  const verifierLength = readUint32Be(payload, cursor + 4);
  if (verifierLength === null) return null;
  cursor = alignTo4(cursor + 8 + verifierLength);
  if (cursor > payload.length) return null;
  return cursor;
}

function parseRpcReplyResultsOffset(payload, baseOffset) {
  let cursor = baseOffset + 8;
  if (cursor + 4 > payload.length) return null;
  const replyStatus = readUint32Be(payload, cursor);
  if (replyStatus !== 0) return null;
  cursor += 4;
  if (cursor + 8 > payload.length) return null;
  const verifierLength = readUint32Be(payload, cursor + 4);
  if (verifierLength === null) return null;
  cursor = alignTo4(cursor + 8 + verifierLength);
  if (cursor + 4 > payload.length) return null;
  const acceptStatus = readUint32Be(payload, cursor);
  if (acceptStatus !== 0) return null;
  cursor += 4;
  return cursor <= payload.length ? cursor : null;
}

function parseRpcOpaque(payload, offset) {
  if (!payload || offset < 0 || offset + 4 > payload.length) return null;
  const length = readUint32Be(payload, offset);
  if (length === null) return null;
  const dataStart = offset + 4;
  const dataEnd = dataStart + length;
  if (dataEnd > payload.length) return null;
  const nextOffset = alignTo4(dataEnd);
  if (nextOffset > payload.length) return null;
  return {
    data: payload.slice(dataStart, dataEnd),
    nextOffset,
  };
}

function extractNfsFileCandidates(streamPackets) {
  const fileEntries = new Map();
  const readRequestByXid = new Map();

  const getOrCreateFileEntry = (handleHex) => {
    if (!fileEntries.has(handleHex)) {
      fileEntries.set(handleHex, {
        handleHex,
        segments: [],
      });
    }
    return fileEntries.get(handleHex);
  };

  streamPackets.forEach((packet) => {
    const transportData = getPacketTransportData(packet);
    if (!transportData?.["NFS"]) return;
    const payload = getPacketPayloadBytes(packet);
    if (!payload || payload.length < 24) return;

    const baseOffset = parseRpcBaseOffset(payload);
    const xidValue = readUint32Be(payload, baseOffset);
    const msgType = readUint32Be(payload, baseOffset + 4);
    if (xidValue === null || msgType === null) return;
    const xid = xidValue.toString(16).padStart(8, "0");

    if (msgType === 0) {
      const program = readUint32Be(payload, baseOffset + 12);
      const procedure = readUint32Be(payload, baseOffset + 20);
      if (program !== 100003 || procedure === null) return;
      const argsOffset = parseRpcCallArgsOffset(payload, baseOffset);
      if (argsOffset === null) return;
      const fileHandleOpaque = parseRpcOpaque(payload, argsOffset);
      if (!fileHandleOpaque) return;
      const handleHex = bytesToHexString(fileHandleOpaque.data);
      if (!handleHex) return;

      if (procedure === 6) {
        const readOffset = readUint64BeNumber(payload, fileHandleOpaque.nextOffset);
        if (readOffset === null) return;
        readRequestByXid.set(xid, {
          handleHex,
          readOffset,
        });
        return;
      }

      if (procedure === 7) {
        const writeOffset = readUint64BeNumber(payload, fileHandleOpaque.nextOffset);
        if (writeOffset === null) return;
        const dataOpaque = parseRpcOpaque(payload, fileHandleOpaque.nextOffset + 16);
        if (!dataOpaque || dataOpaque.data.length === 0) return;
        const entry = getOrCreateFileEntry(handleHex);
        addSegmentToEntry(entry, writeOffset, dataOpaque.data);
      }
      return;
    }

    if (msgType !== 1) return;
    const readRequest = readRequestByXid.get(xid);
    if (!readRequest) return;
    const resultOffset = parseRpcReplyResultsOffset(payload, baseOffset);
    if (resultOffset === null) return;
    const nfsStatus = readUint32Be(payload, resultOffset);
    if (nfsStatus !== 0) return;

    let cursor = resultOffset + 4;
    const hasAttributes = readUint32Be(payload, cursor);
    if (hasAttributes === null) return;
    cursor += 4;
    if (hasAttributes !== 0) {
      if (cursor + 84 > payload.length) return;
      cursor += 84;
    }
    const dataLength = readUint32Be(payload, cursor + 8);
    if (dataLength === null || dataLength === 0) return;
    const dataStart = cursor + 12;
    const dataEnd = dataStart + dataLength;
    if (dataEnd > payload.length) return;
    const chunk = payload.slice(dataStart, dataEnd);
    const entry = getOrCreateFileEntry(readRequest.handleHex);
    addSegmentToEntry(entry, readRequest.readOffset, chunk);
  });

  const candidates = [];
  for (const entry of fileEntries.values()) {
    const bytes = assembleSegments(entry.segments);
    if (!bytes || bytes.length === 0) continue;
    const handlePreview = entry.handleHex.slice(0, 12) || "unknown";
    candidates.push({
      label: `NFS handle ${handlePreview} (${bytes.length} bytes)`,
      fileName: `nfs-file-${handlePreview}.bin`,
      bytes,
    });
  }
  return candidates;
}

function parseFtpActiveModeDataPort(argument) {
  const value = String(argument || "").trim();
  if (!value) return null;

  const commaMatch = value.match(
    /^(\d{1,3})(?:,(\d{1,3})){5}$/,
  );
  if (commaMatch) {
    const parts = value.split(",").map((part) => Number.parseInt(part, 10));
    if (parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) {
      const port = parts[4] * 256 + parts[5];
      if (port >= 1 && port <= 65535) return port;
    }
  }

  // EPRT usually looks like: |1|192.168.1.10|59231|
  const eprtMatch = value.match(/^\|[^|]*\|[^|]*\|(\d{1,5})\|$/);
  if (eprtMatch) {
    const port = Number.parseInt(eprtMatch[1], 10);
    if (Number.isInteger(port) && port >= 1 && port <= 65535) return port;
  }

  return null;
}

function parseFtpPassiveModeDataPort(message) {
  const text = String(message || "").trim();
  if (!text) return null;

  // 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
  const passiveMatch = text.match(/\((\d{1,3}(?:,\d{1,3}){5})\)/);
  if (passiveMatch) {
    const parts = passiveMatch[1]
      .split(",")
      .map((part) => Number.parseInt(part, 10));
    if (parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) {
      const port = parts[4] * 256 + parts[5];
      if (port >= 1 && port <= 65535) return port;
    }
  }

  // 229 Entering Extended Passive Mode (|||6446|)
  const epsvMatch = text.match(/\(\|\|\|(\d{1,5})\|\)/);
  if (epsvMatch) {
    const port = Number.parseInt(epsvMatch[1], 10);
    if (Number.isInteger(port) && port >= 1 && port <= 65535) return port;
  }

  return null;
}

function getFtpControlRolesFromStreamTuple(streamTuple) {
  if (!streamTuple) return { clientIp: "", serverIp: "" };
  const srcPort = Number(streamTuple.srcPort);
  const dstPort = Number(streamTuple.dstPort);
  if (dstPort === 21 || dstPort === 20) {
    return { clientIp: streamTuple.srcIp, serverIp: streamTuple.dstIp };
  }
  if (srcPort === 21 || srcPort === 20) {
    return { clientIp: streamTuple.dstIp, serverIp: streamTuple.srcIp };
  }
  return { clientIp: "", serverIp: "" };
}

function buildFtpCandidateFromDataStream(
  streamPackets,
  {
    transferCommand = "",
    transferName = "",
    clientIp = "",
    serverIp = "",
  } = {},
) {
  if (!Array.isArray(streamPackets) || streamPackets.length === 0) return null;

  const wantsServerToClient = ["RETR", "LIST", "NLST"].includes(transferCommand);
  const wantsClientToServer = ["STOR", "APPE"].includes(transferCommand);
  let preferredDirection = "";
  if (wantsServerToClient && clientIp && serverIp) {
    preferredDirection = `${serverIp}->${clientIp}`;
  } else if (wantsClientToServer && clientIp && serverIp) {
    preferredDirection = `${clientIp}->${serverIp}`;
  }

  let forwardHex = "";
  let reverseHex = "";
  let forwardBytes = 0;
  let reverseBytes = 0;

  const baseTuple = getStreamTupleForPacket(streamPackets[0]);
  if (!baseTuple) return null;
  const forwardDirection = `${baseTuple.srcIp}->${baseTuple.dstIp}`;
  const reverseDirection = `${baseTuple.dstIp}->${baseTuple.srcIp}`;

  streamPackets.forEach((packet) => {
    const payloadHex = getPacketPayloadHex(packet);
    if (!payloadHex) return;
    const tuple = getStreamTupleForPacket(packet);
    if (!tuple) return;
    const packetDirection = `${tuple.srcIp}->${tuple.dstIp}`;
    if (packetDirection === forwardDirection) {
      forwardHex += payloadHex;
      forwardBytes += payloadHex.length / 2;
      return;
    }
    if (packetDirection === reverseDirection) {
      reverseHex += payloadHex;
      reverseBytes += payloadHex.length / 2;
    }
  });

  if (!forwardHex && !reverseHex) return null;

  let selectedHex = "";
  if (preferredDirection && preferredDirection === forwardDirection && forwardHex) {
    selectedHex = forwardHex;
  } else if (
    preferredDirection &&
    preferredDirection === reverseDirection &&
    reverseHex
  ) {
    selectedHex = reverseHex;
  } else {
    selectedHex = forwardBytes >= reverseBytes ? forwardHex : reverseHex;
  }
  if (!selectedHex) return null;

  let bytes;
  try {
    bytes = parseDataToolsInput("hex", selectedHex);
  } catch {
    return null;
  }
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

  const safeName = sanitizeCarveFilename(transferName);
  const transferPrefix = transferCommand
    ? `ftp-${transferCommand.toLowerCase()}`
    : "ftp-transfer";
  const fileName = safeName || `${transferPrefix}.bin`;
  return {
    label: `${fileName} (${bytes.length} bytes)`,
    fileName,
    bytes,
  };
}

function extractFtpFileCandidates(streamPackets, contextPacket = null) {
  if (!Array.isArray(streamPackets) || streamPackets.length === 0) return [];

  let hasControlMetadata = false;
  let transferCommand = "";
  let transferName = "";
  let transferTimestamp = null;
  const candidateDataPorts = new Set();

  streamPackets.forEach((packet) => {
    const transportData = getPacketTransportData(packet);
    const ftpData = transportData?.["FTP"];
    if (!ftpData || typeof ftpData !== "object") return;
    hasControlMetadata = true;

    const ftpType = String(ftpData["Type"] || "").trim().toLowerCase();
    if (ftpType === "command") {
      const command = String(ftpData["Command"] || "")
        .trim()
        .toUpperCase();
      const argument = String(ftpData["Argument"] || "").trim();

      if (command === "PORT" || command === "EPRT") {
        const activePort = parseFtpActiveModeDataPort(argument);
        if (activePort) candidateDataPorts.add(activePort);
      }

      if (["RETR", "STOR", "APPE", "LIST", "NLST"].includes(command)) {
        transferCommand = command;
        transferName = command === "LIST" || command === "NLST" ? "" : argument;
        const packetTs = parsePacketTimestampMs(packet);
        transferTimestamp = Number.isFinite(packetTs) ? packetTs : transferTimestamp;
      }
      return;
    }

    if (ftpType === "response") {
      const statusCode = String(ftpData["Status Code"] || "").trim();
      if (statusCode === "227" || statusCode === "229") {
        const passivePort = parseFtpPassiveModeDataPort(ftpData["Message"]);
        if (passivePort) candidateDataPorts.add(passivePort);
      }
    }
  });

  if (!hasControlMetadata) {
    const tuple = getStreamTupleForPacket(contextPacket || streamPackets[0]);
    const srcPort = Number(tuple?.srcPort);
    const dstPort = Number(tuple?.dstPort);
    const streamLooksFtpData =
      srcPort === 20 ||
      dstPort === 20 ||
      streamPackets.some((packet) => {
        const protocolTokens = collectPacketProtocolTokens(packet);
        return protocolTokens.includes("FTP") || protocolTokens.includes("FTPDATA");
      });
    if (!streamLooksFtpData) return [];
    const directCandidate = buildFtpCandidateFromDataStream(streamPackets);
    return directCandidate ? [directCandidate] : [];
  }

  if (!transferCommand) return [];

  const controlTuple = getStreamTupleForPacket(contextPacket || streamPackets[0]);
  const { clientIp, serverIp } = getFtpControlRolesFromStreamTuple(controlTuple);
  if (!clientIp || !serverIp) return [];

  const controlStreamKey = buildBidirectionalStreamKey(
    (contextPacket || streamPackets[0])?.["Packet Info"] || {},
  );
  const allPackets = getAllPacketsForHostNavigation();
  const streamMap = new Map();

  allPackets.forEach((packet) => {
    const packetInfo = packet?.["Packet Info"];
    const tuple = getStreamTupleForPacket(packet);
    if (!packetInfo || !tuple) return;
    if (String(packetInfo["Protocol"] || "").toUpperCase() !== "TCP") return;

    const hasSameEndpoints =
      (tuple.srcIp === clientIp && tuple.dstIp === serverIp) ||
      (tuple.srcIp === serverIp && tuple.dstIp === clientIp);
    if (!hasSameEndpoints) return;

    const streamKey = buildBidirectionalStreamKey(packetInfo);
    if (!streamKey || streamKey === controlStreamKey) return;

    if (!streamMap.has(streamKey)) {
      streamMap.set(streamKey, []);
    }
    streamMap.get(streamKey).push(packet);
  });

  let bestStreamPackets = [];
  let bestScore = -1;
  streamMap.forEach((packets) => {
    if (!Array.isArray(packets) || packets.length === 0) return;
    packets.sort((left, right) => comparePacketsChronologically(left, right));

    const firstTs = parsePacketTimestampMs(packets[0]);
    if (
      Number.isFinite(transferTimestamp) &&
      Number.isFinite(firstTs) &&
      firstTs < transferTimestamp - 2000
    ) {
      return;
    }

    let hasControlPort = false;
    const observedPorts = new Set();
    let totalPayloadBytes = 0;
    packets.forEach((packet) => {
      const tuple = getStreamTupleForPacket(packet);
      const payloadHex = getPacketPayloadHex(packet);
      if (tuple) {
        const srcPort = Number(tuple.srcPort);
        const dstPort = Number(tuple.dstPort);
        if (Number.isInteger(srcPort)) observedPorts.add(srcPort);
        if (Number.isInteger(dstPort)) observedPorts.add(dstPort);
        if (srcPort === 21 || dstPort === 21) hasControlPort = true;
      }
      if (payloadHex) totalPayloadBytes += payloadHex.length / 2;
    });

    if (hasControlPort || totalPayloadBytes <= 0) return;
    if (candidateDataPorts.size > 0) {
      const matchedPort = Array.from(observedPorts).some((port) =>
        candidateDataPorts.has(port),
      );
      if (!matchedPort) return;
    }

    const score = totalPayloadBytes;
    if (score > bestScore) {
      bestScore = score;
      bestStreamPackets = packets;
    }
  });

  if (!bestStreamPackets.length) return [];
  const carvedCandidate = buildFtpCandidateFromDataStream(bestStreamPackets, {
    transferCommand,
    transferName,
    clientIp,
    serverIp,
  });
  return carvedCandidate ? [carvedCandidate] : [];
}

function buildFileCarveCandidatesForProtocol(
  protocolName,
  streamPackets,
  packet = null,
) {
  const normalized = String(protocolName || "").toLowerCase().trim();
  if (normalized === "smb") return extractSmbFileCandidates(streamPackets);
  if (normalized === "nfs") return extractNfsFileCandidates(streamPackets);
  if (normalized === "ftp") {
    return extractFtpFileCandidates(streamPackets, packet);
  }
  return [];
}

function canCarveCurrentStreamForProtocol(protocolName, packet = null) {
  const normalized = String(protocolName || "").toLowerCase().trim();
  if (!normalized) return false;
  const streamPackets = getFollowStreamPackets(packet);
  if (!streamPackets.length) return false;
  const candidates = buildFileCarveCandidatesForProtocol(
    normalized,
    streamPackets,
    packet,
  );
  return candidates.length > 0;
}

function selectCarveCandidate(candidates, protocolLabel) {
  if (!Array.isArray(candidates) || candidates.length === 0) return null;
  if (candidates.length === 1) return candidates[0];

  const visibleOptions = candidates.slice(0, 20);
  const optionsText = visibleOptions
    .map((candidate, optionIndex) => `${optionIndex + 1}. ${candidate.label}`)
    .join("\n");
  const promptText =
    `Select ${protocolLabel} file to carve:` +
    `\n${optionsText}` +
    (candidates.length > visibleOptions.length
      ? `\n... ${candidates.length - visibleOptions.length} more omitted`
      : "") +
    "\nEnter number:";
  const userChoice = window.prompt(promptText, "1");
  if (userChoice === null) return null;
  const parsedChoice = Number.parseInt(userChoice.trim(), 10);
  if (
    !Number.isInteger(parsedChoice) ||
    parsedChoice < 1 ||
    parsedChoice > visibleOptions.length
  ) {
    statusUpdate("Status: Invalid file selection for carving");
    return null;
  }
  return visibleOptions[parsedChoice - 1];
}

async function carveCurrentStreamToFileFromContextMenu(protocolName) {
  const contextPacket = getCurrentContextPacket();
  hideConvertContextMenu();
  const normalized = String(protocolName || "").toLowerCase().trim();
  const protocolLabel = normalized.toUpperCase();
  if (!normalized) {
    statusUpdate("Status: Unsupported carve protocol");
    return;
  }

  const streamPackets = getFollowStreamPackets(contextPacket);
  if (!streamPackets.length) {
    statusUpdate("Status: No stream packets found for current packet");
    return;
  }

  const hydratedStreamPackets = await hydratePacketCollection(streamPackets);

  const candidates = buildFileCarveCandidatesForProtocol(
    normalized,
    hydratedStreamPackets,
    contextPacket,
  );
  if (!candidates.length) {
    statusUpdate(`Status: No ${protocolLabel} file data found in this stream`);
    return;
  }

  const selectedCandidate = selectCarveCandidate(candidates, protocolLabel);
  if (!selectedCandidate) {
    statusUpdate("Status: File carving cancelled");
    return;
  }

  const payloadHex = bytesToHexString(selectedCandidate.bytes);
  if (!payloadHex) {
    statusUpdate("Status: Selected file has no bytes to export");
    return;
  }

  window.saveapi.savePayload(payloadHex).then((result) => {
    if (result.canceled) {
      statusUpdate("Status: Export cancelled");
    } else if (result.success) {
      statusUpdate(`Status: ${protocolLabel} file carved successfully`);
      writeLogEntry(
        `${protocolLabel} file carve exported label="${selectedCandidate.label}" bytes=${selectedCandidate.bytes.length}`,
      );
    } else {
      const errorMessage =
        result && typeof result === "object" && "error" in result
          ? result.error
          : "unknown";
      doError(`${protocolLabel} file carve failed`);
      logErrorEntry(`file-carve-${normalized}`, errorMessage || "unknown");
      statusUpdate(
        `Status: ${protocolLabel} file carve failed - ${errorMessage || "unknown error"}`,
      );
      console.error(`${protocolLabel} file carve failed:`, errorMessage);
    }
  });
}

function followStreamToConv() {
  const contextPacket = getCurrentContextPacket();
  hideConvertContextMenu();
  void _runFollowStreamToConvAction({ contextPacket });
}

function followStreamToConvDecompressed() {
  const contextPacket = getCurrentContextPacket();
  hideConvertContextMenu();
  void _runFollowStreamToConvAction({ contextPacket, decompress: true });
}

async function _runFollowStreamToConvAction(options = {}) {
  const { contextPacket = null, decompress = false } = options;
  showStreamLoadingOverlay();
  await yieldToRenderer();
  try {
    const streamPackets = await getFollowStreamPacketsAsync(contextPacket);
    if (!streamPackets.length) {
      statusUpdate("Status: No stream packets found for current packet");
      return;
    }
    if (!confirmFollowStreamContextMenuLoad("Conv", streamPackets.length)) {
      statusUpdate("Status: Follow stream to Conv cancelled");
      return;
    }
    await _doFollowStreamToConv(streamPackets, { decompress });
  } finally {
    hideStreamLoadingOverlay();
  }
}

async function _doFollowStreamToConv(
  streamPackets = getFollowStreamPackets(),
  options = {},
) {
  const { decompress = false } = options;
  if (!streamPackets.length) {
    statusUpdate("Status: No stream packets found for current packet");
    return;
  }
  const hydratedStreamPackets = await hydratePacketCollection(streamPackets);
  const combinedHex = await buildStreamHexAsync(hydratedStreamPackets);
  if (!combinedHex) {
    statusUpdate("Status: Stream packets have no payload data");
    return;
  }

  let outputHex = combinedHex;
  let decompressionAlgorithm = "";
  if (decompress) {
    let compressedBytes;
    try {
      compressedBytes = parseDataToolsInput("hex", combinedHex);
    } catch {
      statusUpdate("Status: Stream payload is not valid hex data");
      return;
    }
    const decompressionCandidate = await tryDecompressBytes(
      compressedBytes,
      activeContextStreamCompressionHint,
    );
    if (!decompressionCandidate) {
      statusUpdate(
        "Status: Stream does not appear to be gzip/deflate/brotli compressed",
      );
      return;
    }
    outputHex = bytesToHexString(decompressionCandidate.bytes);
    decompressionAlgorithm = decompressionCandidate.algorithm;
  }

  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  inputEl.value = outputHex;
  formatEl.value = "hex";
  showDataTools();
  await yieldToRenderer();
  runDataToolsConversion();
  if (decompress) {
    writeLogEntry(
      `Follow stream loaded ${streamPackets.length} packets into Conv tab decompressed algorithm=${decompressionAlgorithm}`,
    );
    return;
  }
  writeLogEntry(`Follow stream loaded ${streamPackets.length} packets into Conv tab`);
}

function followStreamToCrypt() {
  const contextPacket = getCurrentContextPacket();
  hideConvertContextMenu();
  const streamPackets = getFollowStreamPackets(contextPacket);
  if (!streamPackets.length) {
    statusUpdate("Status: No stream packets found for current packet");
    return;
  }
  if (!confirmFollowStreamContextMenuLoad("Crypt", streamPackets.length)) {
    statusUpdate("Status: Follow stream to Crypt cancelled");
    return;
  }
  const isLarge = getTotalPacketCount() >= STREAM_LOADING_THRESHOLD;
  if (isLarge) {
    showStreamLoadingOverlay();
    setTimeout(() => {
      void _doFollowStreamToCrypt(streamPackets).finally(() => {
        hideStreamLoadingOverlay();
      });
    }, 0);
  } else {
    void _doFollowStreamToCrypt(streamPackets);
  }
}

async function _doFollowStreamToCrypt(streamPackets = getFollowStreamPackets()) {
  if (!streamPackets.length) {
    statusUpdate("Status: No stream packets found for current packet");
    return;
  }
  const hydratedStreamPackets = await hydratePacketCollection(streamPackets);
  const combinedHex = buildStreamHex(hydratedStreamPackets);
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

function getCurrentRawPayloadHex(packet = null) {
  const contextPacket = packet || getCurrentContextPacket();
  const payloadHex =
    contextPacket?.["Packet Info"]?.["Raw data"]?.["Payload"]?.[
    "Hex Encoded"
    ];
  return typeof payloadHex === "string" ? payloadHex : "";
}

function getCurrentHttpData(packet = null) {
  const contextPacket = packet || getCurrentContextPacket();
  const packetInfo = contextPacket?.["Packet Info"];
  if (!packetInfo) return null;
  const protocol = packetInfo["Protocol"] || "TCP";
  return packetInfo[protocol]?.["HTTP"] || null;
}

function extractHttpBodyHex(payloadHex) {
  if (!payloadHex) return "";
  // Locate the HTTP header/body separator in hex space.
  // RFC 7230 mandates \r\n\r\n which encodes as "0d0a0d0a".
  const normalized = payloadHex.replace(/\s+/g, "");
  const lower = normalized.toLowerCase();
  const sepIdx = lower.indexOf("0d0a0d0a");
  if (sepIdx === -1) return "";
  const bodyStart = sepIdx + 8; // skip past the 4-byte CRLFCRLF separator
  if (bodyStart >= normalized.length) return "";
  return normalized.slice(bodyStart);
}

function parseHttpContentLength(packet = null) {
  const httpData = getCurrentHttpData(packet);
  const rawLength = String(httpData?.["Content-Length"] || "").trim();
  if (!/^\d+$/.test(rawLength)) return null;
  const contentLength = Number.parseInt(rawLength, 10);
  return Number.isFinite(contentLength) && contentLength >= 0
    ? contentLength
    : null;
}

function isChunkedHttpTransfer(packet = null) {
  const httpData = getCurrentHttpData(packet);
  return String(httpData?.["Transfer-Encoding"] || "")
    .toLowerCase()
    .includes("chunked");
}

function hexToAsciiString(hex) {
  const normalized = typeof hex === "string" ? hex.replace(/\s+/g, "") : "";
  let result = "";
  for (let idx = 0; idx + 1 < normalized.length; idx += 2) {
    result += String.fromCharCode(Number.parseInt(normalized.slice(idx, idx + 2), 16));
  }
  return result;
}

function sliceCompleteChunkedHttpBodyHex(bodyHex) {
  const normalized = typeof bodyHex === "string" ? bodyHex.replace(/\s+/g, "") : "";
  let cursor = 0;
  while (cursor < normalized.length) {
    const lineEnd = normalized.indexOf("0d0a", cursor);
    if (lineEnd === -1) return null;
    const chunkSizeLine = hexToAsciiString(normalized.slice(cursor, lineEnd)).trim();
    const chunkSizeToken = chunkSizeLine.split(";", 1)[0].trim();
    if (!/^[0-9a-fA-F]+$/.test(chunkSizeToken)) return null;
    const chunkSize = Number.parseInt(chunkSizeToken, 16);
    if (!Number.isFinite(chunkSize) || chunkSize < 0) return null;
    cursor = lineEnd + 4;
    const chunkDataEnd = cursor + chunkSize * 2;
    if (chunkDataEnd > normalized.length) return null;
    cursor = chunkDataEnd;
    if (normalized.slice(cursor, cursor + 4).toLowerCase() !== "0d0a") return null;
    cursor += 4;
    if (chunkSize === 0) {
      let trailerCursor = cursor;
      while (trailerCursor <= normalized.length) {
        const trailerEnd = normalized.indexOf("0d0a", trailerCursor);
        if (trailerEnd === -1) return null;
        if (trailerEnd === trailerCursor) {
          return normalized.slice(0, trailerEnd + 4);
        }
        trailerCursor = trailerEnd + 4;
      }
      return null;
    }
  }
  return null;
}

function getPacketIdentity(packet) {
  return (
    packet?.__packetKey ||
    packet?.["Packet Info"]?.["Index"] ||
    null
  );
}

function isSameDirectionalStreamPacket(packet, referencePacket) {
  const packetTuple = getStreamTupleForPacket(packet);
  const referenceTuple = getStreamTupleForPacket(referencePacket);
  if (!packetTuple || !referenceTuple) return false;
  return (
    packetTuple.protocol === referenceTuple.protocol &&
    packetTuple.srcIp === referenceTuple.srcIp &&
    packetTuple.dstIp === referenceTuple.dstIp &&
    packetTuple.srcPort === referenceTuple.srcPort &&
    packetTuple.dstPort === referenceTuple.dstPort
  );
}

function collectHttpBodyHexFromStream(streamPackets, referencePacket) {
  if (!Array.isArray(streamPackets) || !streamPackets.length || !referencePacket) {
    return "";
  }
  const referenceIdentity = getPacketIdentity(referencePacket);
  const referenceIndex = streamPackets.findIndex((packet) => {
    return getPacketIdentity(packet) === referenceIdentity;
  });
  if (referenceIndex === -1) return "";

  const firstPacket = streamPackets[referenceIndex];
  const firstBodyHex = extractHttpBodyHex(getCurrentRawPayloadHex(firstPacket));
  if (!firstBodyHex) return "";

  let combinedBodyHex = firstBodyHex;
  for (let packetIndex = referenceIndex + 1; packetIndex < streamPackets.length; packetIndex += 1) {
    const packet = streamPackets[packetIndex];
    if (!isSameDirectionalStreamPacket(packet, firstPacket)) continue;
    const payloadHex = getCurrentRawPayloadHex(packet).replace(/\s+/g, "");
    if (payloadHex) combinedBodyHex += payloadHex;
  }

  const contentLength = parseHttpContentLength(firstPacket);
  if (contentLength !== null) {
    return combinedBodyHex.slice(0, contentLength * 2);
  }
  if (isChunkedHttpTransfer(firstPacket)) {
    return sliceCompleteChunkedHttpBodyHex(combinedBodyHex) || combinedBodyHex;
  }
  return combinedBodyHex;
}

async function getCurrentHttpBodyHex(packet = null) {
  const contextPacket = packet || getCurrentContextPacket();
  if (!contextPacket) return "";
  const localBodyHex = extractHttpBodyHex(getCurrentRawPayloadHex(contextPacket));
  if (!localBodyHex) return "";

  const streamPackets = await getFollowStreamPacketsAsync(contextPacket);
  if (!streamPackets.length) return localBodyHex;
  const hydratedStreamPackets = await hydratePacketCollection(streamPackets);
  return collectHttpBodyHexFromStream(hydratedStreamPackets, contextPacket) || localBodyHex;
}

function getCurrentHttpBodyCompressionHint(packet = null, bodyHexOverride = "") {
  const contextPacket = packet || getCurrentContextPacket();
  const httpData = getCurrentHttpData(contextPacket);
  const encoding = String(httpData?.["Content-Encoding"] || "").toLowerCase();
  if (encoding.includes("br") || encoding.includes("brotli")) return "brotli";
  if (encoding.includes("gzip") || encoding.includes("gz")) return "gzip";
  if (encoding.includes("deflate") || encoding.includes("zlib")) return "deflate";

  const bodyHex =
    bodyHexOverride || extractHttpBodyHex(getCurrentRawPayloadHex(contextPacket));
  if (!bodyHex) return "";
  try {
    return inferCompressionFromBytes(parseDataToolsInput("hex", bodyHex));
  } catch {
    return "";
  }
}

async function getCurrentHttpBodyDecompressionCandidate(packet = null) {
  const bodyHex = await getCurrentHttpBodyHex(packet);
  if (!bodyHex) return null;
  try {
    const bodyBytes = parseDataToolsInput("hex", bodyHex);
    return await tryDecompressBytes(
      bodyBytes,
      getCurrentHttpBodyCompressionHint(packet, bodyHex),
    );
  } catch {
    return null;
  }
}

function getCurrentPacketForExport() {
  return getCurrentContextPacket();
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

function currentPacketToConvJson() {
  const contextPacket = getCurrentContextPacket();
  // turn it into json object
  const packetJson = contextPacket || {};
  const jsonString = JSON.stringify(packetJson, null, 4);
  const outputEl = document.getElementById("data-tools-packet-json-pre");
  outputEl.textContent = jsonString;
}


function exportCurrentPacketFromContextMenu() {
  const contextPacket = getCurrentPacketForExport();
  hideConvertContextMenu();
  const currentPacket = contextPacket;
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
  const contextPacket = getCurrentContextPacket();
  hideConvertContextMenu();
  const payloadHex = getCurrentRawPayloadHex(contextPacket);
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

function getHttpContentTypeForCurrentPacket(packet = null) {
  const httpData = getCurrentHttpData(packet);
  return (httpData && httpData["Content-Type"]) || "application/octet-stream";
}

function saveHttpBodyFromContextMenu() {
  void saveHttpBodyFromContextMenuImpl(false);
}

async function saveHttpBodyFromContextMenuImpl(decompress = false) {
  const contextPacket = getCurrentContextPacket();
  hideConvertContextMenu();
  const bodyHex = await getCurrentHttpBodyHex(contextPacket);
  if (!bodyHex) {
    statusUpdate("Status: No HTTP body available to save");
    return;
  }
  let outputHex = bodyHex;
  let decompressLabel = "";
  if (decompress) {
    const decompressionCandidate = await getCurrentHttpBodyDecompressionCandidate(
      contextPacket,
    );
    if (!decompressionCandidate) {
      statusUpdate("Status: HTTP body does not appear to be compressed");
      return;
    }
    outputHex = bytesToHexString(decompressionCandidate.bytes);
    decompressLabel = ` decompressed algorithm=${decompressionCandidate.algorithm}`;
  }
  window.saveapi.savePayload(outputHex).then((result) => {
    if (result.canceled) {
      statusUpdate("Status: Save cancelled");
    } else if (result.success) {
      statusUpdate(
        decompress
          ? "Status: Decompressed HTTP body saved successfully"
          : "Status: HTTP body saved successfully",
      );
      writeLogEntry(
        `Context menu HTTP body save completed${decompressLabel}`,
      );
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
  void loadHttpBodyIntoConvTabFromContextMenuImpl(false);
}

async function loadHttpBodyIntoConvTabFromContextMenuImpl(decompress = false) {
  const contextPacket = getCurrentContextPacket();
  const bodyHex = await getCurrentHttpBodyHex(contextPacket);
  hideConvertContextMenu();
  if (!bodyHex) {
    statusUpdate("Status: No HTTP body available to load");
    return;
  }
  let outputHex = bodyHex;
  let decompressLabel = "";
  if (decompress) {
    const decompressionCandidate = await getCurrentHttpBodyDecompressionCandidate(
      contextPacket,
    );
    if (!decompressionCandidate) {
      statusUpdate("Status: HTTP body does not appear to be compressed");
      return;
    }
    outputHex = bytesToHexString(decompressionCandidate.bytes);
    decompressLabel = ` decompressed algorithm=${decompressionCandidate.algorithm}`;
  }
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  inputEl.value = outputHex;
  formatEl.value = "hex";
  showDataTools();
  runDataToolsConversion();
  writeLogEntry(
    `Context menu loaded HTTP body into Conv tab${decompressLabel}`,
  );
}

function previewHttpBodyInBrowserFromContextMenu() {
  void previewHttpBodyInBrowserFromContextMenuImpl(false);
}

async function previewHttpBodyInBrowserFromContextMenuImpl(
  decompress = false,
) {
  const contextPacket = getCurrentContextPacket();
  hideConvertContextMenu();
  const bodyHex = await getCurrentHttpBodyHex(contextPacket);
  if (!bodyHex) {
    statusUpdate("Status: No HTTP body available to preview");
    return;
  }
  let outputHex = bodyHex;
  let contentType = getHttpContentTypeForCurrentPacket(contextPacket);
  let decompressLabel = "";
  if (decompress) {
    const decompressionCandidate = await getCurrentHttpBodyDecompressionCandidate(
      contextPacket,
    );
    if (!decompressionCandidate) {
      statusUpdate("Status: HTTP body does not appear to be compressed");
      return;
    }
    outputHex = bytesToHexString(decompressionCandidate.bytes);
    contentType = inferMimeType(decompressionCandidate.bytes);
    decompressLabel = ` decompressed algorithm=${decompressionCandidate.algorithm}`;
  }
  window.previewapi.previewHttpBody(outputHex, contentType).then((result) => {
    if (result.success) {
      statusUpdate(
        decompress
          ? "Status: Decompressed HTTP body opened in browser"
          : "Status: HTTP body opened in browser",
      );
      writeLogEntry(
        `Context menu HTTP body browser preview launched${decompressLabel}`,
      );
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

document.getElementById("help-btn").addEventListener("click", function () {
  // if the window is already open, make sure it doesn't get opened again, just focus it
  if (helpWin != null && !helpWin.closed) {
    // bring the help window back in front of the main window
    helpWin.blur();
    window.focus();
    return;
  }
  // open the help page in a new window
  writeLogEntry("Calling help page in new window");
  helpWin = window.open("https://packetsnitch.oxasploits.com/", "_blank");
  // if the window is closed, set helpWin to null
  helpWin.addEventListener("beforeunload", () => {
    helpWin = null;
  });
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
document.getElementById("conv-subtab-packet-json").addEventListener("click", () => {
  currentPacketToConvJson();
  setConvSubtab(CONV_PACKET_JSON_SUBTAB);
});

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
convertContextButtons.decompressConv.addEventListener("click", () => {
  loadActiveConvInputDecompressedFromContextMenu();
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
convertContextButtons.filterLinkProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("linkProtocol", "&&");
});
convertContextButtons.filterWireProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("wireProtocol", "&&");
});
convertContextButtons.filterAppProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("appProtocol", "&&");
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
convertContextButtons.filterOrLinkProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("linkProtocol", "||");
});
convertContextButtons.filterOrWireProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("wireProtocol", "||");
});
convertContextButtons.filterOrAppProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("appProtocol", "||");
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
convertContextButtons.filterNotLinkProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("linkProtocol", "&&", true);
});
convertContextButtons.filterNotWireProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("wireProtocol", "&&", true);
});
convertContextButtons.filterNotAppProtocol.addEventListener("click", () => {
  appendFilterQueryFromContextMenu("appProtocol", "&&", true);
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
convertContextButtons.filterClearLinkProtocol.addEventListener("click", () => {
  clearAndFilterQueryFromContextMenu("linkProtocol");
});
convertContextButtons.filterClearWireProtocol.addEventListener("click", () => {
  clearAndFilterQueryFromContextMenu("wireProtocol");
});
convertContextButtons.filterClearAppProtocol.addEventListener("click", () => {
  clearAndFilterQueryFromContextMenu("appProtocol");
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
convertContextButtons.notesSendListPacket.addEventListener("click", () => {
  sendTextToNotesFromContextMenu(
    buildListVisibleDataNoteText(),
    "context-list-row-visible-data",
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
convertContextButtons.exportConvInput.addEventListener("click", () => {
  exportConvContextTextFromContextMenu("input");
});
convertContextButtons.exportConvRaw.addEventListener(
  "click",
  exportConvRawFromContextMenu,
);
convertContextButtons.exportConvHex.addEventListener("click", () => {
  exportConvContextTextFromContextMenu("hex");
});
convertContextButtons.exportConvBinary.addEventListener("click", () => {
  exportConvContextTextFromContextMenu("binary");
});
convertContextButtons.exportConvDecimal.addEventListener("click", () => {
  exportConvContextTextFromContextMenu("decimal");
});
convertContextButtons.exportConvDecimalInteger.addEventListener("click", () => {
  exportConvContextTextFromContextMenu("decimal-integer");
});
convertContextButtons.exportConvAscii.addEventListener("click", () => {
  exportConvContextTextFromContextMenu("ascii");
});
convertContextButtons.exportConvBase64.addEventListener("click", () => {
  exportConvContextTextFromContextMenu("base64");
});
convertContextButtons.exportConvHashes.addEventListener("click", () => {
  exportConvContextTextFromContextMenu("hashes");
});
convertContextButtons.exportConvDecodes.addEventListener("click", () => {
  exportConvContextTextFromContextMenu("decodes");
});
convertContextButtons.saveCookieJar.addEventListener(
  "click",
  saveCookieJarFromContextMenu,
);
convertContextButtons.httpFileSave.addEventListener(
  "click",
  saveHttpBodyFromContextMenu,
);
convertContextButtons.httpFileSaveDecompressed.addEventListener("click", () => {
  void saveHttpBodyFromContextMenuImpl(true);
});
convertContextButtons.httpFileLoad.addEventListener(
  "click",
  loadHttpBodyIntoConvTabFromContextMenu,
);
convertContextButtons.httpFileLoadDecompressed.addEventListener("click", () => {
  void loadHttpBodyIntoConvTabFromContextMenuImpl(true);
});
convertContextButtons.httpFilePreview.addEventListener(
  "click",
  previewHttpBodyInBrowserFromContextMenu,
);
convertContextButtons.httpFilePreviewDecompressed.addEventListener(
  "click",
  () => {
    void previewHttpBodyInBrowserFromContextMenuImpl(true);
  },
);
convertContextButtons.fileCarveSmb.addEventListener("click", () =>
  carveCurrentStreamToFileFromContextMenu("smb"),
);
convertContextButtons.fileCarveNfs.addEventListener("click", () =>
  carveCurrentStreamToFileFromContextMenu("nfs"),
);
convertContextButtons.fileCarveFtp.addEventListener("click", () =>
  carveCurrentStreamToFileFromContextMenu("ftp"),
);
convertContextButtons.followStreamConv.addEventListener(
  "click",
  followStreamToConv,
);
convertContextButtons.followStreamConvDecompress.addEventListener(
  "click",
  followStreamToConvDecompressed,
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
    const bookmarkPacketIndex = Number.parseInt(
      document.getElementById("selectBookmark").value.split(":")[1],
      10,
    );
    if (!Number.isInteger(bookmarkPacketIndex) || bookmarkPacketIndex < 0) {
      statusUpdate("Invalid bookmark selection, missing host or packet index");
      doError("Invalid bookmark selection, missing host or packet index!");
      return;
    }
    index = bookmarkPacketIndex;
    setActivePacketCursor(index);
    p = capturedPackets["Host"][bookmarkHost];
    activeBookmark["Host"] = bookmarkHost;
    activeBookmark["Packet"] = index;
    hostFilterEl.value = bookmarkHost;
    if (bookmarkHost == undefined || index == undefined) {
      statusUpdate("Invalid bookmark selection, missing host or packet index");
      doError("Invalid bookmark selection, missing host or packet index!");
    } else {
      document.getElementById("target_hosts").value = bookmarkHost;
    }
    void handlePacketNavigation("bookmark", activeBookmark);
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

function updateCurrentPacketCounters(packetSet, options = {}) {
  const { isFilteredView = false } = options;
  const currentStreamPacketEl = document.getElementById("current-stream-packet");
  const currentFilteredPacketEl = document.getElementById(
    "current-filtered-packet",
  );
  if (!currentStreamPacketEl || !currentFilteredPacketEl) {
    return;
  }

  const packetCursor = Number.isInteger(index) && index >= 0 ? index : null;
  const packetKeyForPacket = (packet, fallbackIndex = 0) => {
    const packetInfo = packet?.["Packet Info"];
    if (!packetInfo) return null;
    const sourceIp = packetInfo?.["IP"]?.["Source IP"] || "Unknown";
    const packetIndex = packetInfo?.["Index"] ?? fallbackIndex;
    return sourceIp + ":" + packetIndex;
  };

  const streamPackets = getFollowStreamPackets();
  const streamPacketTotal = streamPackets.length;
  let streamPacketPosition = 0;
  if (streamPacketTotal > 0 && typeof currentPacketKey === "string") {
    const streamPacketIndex = streamPackets.findIndex((packet, idx) => {
      return packetKeyForPacket(packet, idx) === currentPacketKey;
    });
    streamPacketPosition = streamPacketIndex >= 0 ? streamPacketIndex + 1 : 0;
  }

  currentStreamPacketEl.textContent =
    "Current Stream Packet: " +
    streamPacketPosition +
    " / " +
    streamPacketTotal;

  const hasActiveFilterQuery =
    typeof filterInputEl?.value === "string" && filterInputEl.value.trim() !== "";
  const filteredPacketTotal = Array.isArray(filteredPackets)
    ? filteredPackets.length
    : 0;
  let filteredPacketPosition = 0;

  if (hasActiveFilterQuery && filteredPacketTotal > 0) {
    let filteredPacketIndex =
      typeof currentPacketKey === "string" && currentPacketKey
        ? findPacketIndexByKey(filteredPackets, currentPacketKey)
        : -1;
    if (
      filteredPacketIndex < 0 &&
      isFilteredView &&
      packetCursor !== null &&
      packetCursor < filteredPacketTotal
    ) {
      filteredPacketIndex = packetCursor;
    }
    filteredPacketPosition = filteredPacketIndex >= 0 ? filteredPacketIndex + 1 : 0;
  }

  currentFilteredPacketEl.textContent =
    "Current Filtered Packet: " +
    filteredPacketPosition +
    " / " +
    (hasActiveFilterQuery ? filteredPacketTotal : 0);
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

  const directIndex = packetSet.findIndex(
    (packet) => packet?.__packetKey === packetKey,
  );
  if (directIndex >= 0) return directIndex;

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

function setPrevNextButtonVisibility(packetSet, index) {
  document.getElementById("prev-btn").style.display = "block";
  document.getElementById("next-btn").style.display = "block";
  document.getElementById("prev-btn").style.opacity = "1";
  document.getElementById("next-btn").style.opacity = "1";
  if (!packetSet || packetSet.length === 0) {
    document.getElementById("prev-btn").style.opacity = "0";
    document.getElementById("next-btn").style.opacity = "0";
    return;
  }
  document.getElementById("prev-btn").style.opacity =
    index > 0 ? "1" : "0";
  document.getElementById("next-btn").style.opacity =
    index < packetSet.length - 1 ? "1" : "0";
}


/**
 * Handles navigation between capturedPackets (next, prev, activeBookmark, first-load).
 * Updates UI and packet info accordingly.
 */
async function handlePacketNavigation(navAction, navBookmark) {
  activeMainTab = MAIN_TAB_DATA;
  const previousPacketKey = currentPacketKey;
  const previousCursor = getActivePacketCursor();
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
  document.getElementById("total-packets").textContent =
    "Total Packets: " + totalPacketCount();
  if (navAction === undefined) {
    await handlePacketNavigation("first-load");
    return;
  }
  const hasActiveFilterQuery =
    typeof filterInputEl?.value === "string" && filterInputEl.value.trim() !== "";
  const shouldUseFilteredPacketSet =
    navAction === "filtered" ||
    (navAction !== "bookmark" &&
      hasActiveFilterQuery &&
      Array.isArray(filteredPackets));

  let packetSet = shouldUseFilteredPacketSet
    ? filteredPackets
    : getPacketsForSelectedHost(hostFilterEl.value);
  if (shouldUseFilteredPacketSet) {
    const filteredNavigationLogMessage =
      `Filtered packet navigation packets_returned=${packetSet.length}`;
    if (filteredNavigationLogMessage !== lastFilteredNavigationLogMessage) {
      writeLogEntry(filteredNavigationLogMessage);
      lastFilteredNavigationLogMessage = filteredNavigationLogMessage;
    }
  } else {
    lastFilteredNavigationLogMessage = "";
  }
  p = Array.isArray(packetSet) ? packetSet : [];
  if (navAction === "bookmark") {
    if (
      navBookmark["Host"] == undefined ||
      navBookmark["Packet"] == undefined
    ) {
      statusUpdate("Status: Invalid bookmark data, reverting to first packet");
      doError("Invalid bookmark data, missing host or packet index!");
      await handlePacketNavigation("first-load");
      return;
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
  } else if (navAction === "next") {
    if (Array.isArray(packetSet) && index < packetSet.length - 1) {
      index += 1;
      setActivePacketCursor(index);
    }
  } else if (navAction === "prev") {
    if (Array.isArray(packetSet) && index > 0) {
      index -= 1;
      setActivePacketCursor(index);
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
    updateCurrentPacketCounters([], {
      isFilteredView: navAction === "filtered",
    });
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
    const activePacket = await ensurePacketHydrated(
      packetSet[index],
      hostFilterEl.value,
      index,
    );
    packetSet[index] = activePacket;
    const packetInfo = activePacket?.["Packet Info"];
    if (!packetInfo) {
      statusUpdate("Status: Packet data is unavailable for this entry");
      doError("Packet data is unavailable for this entry!");
      return;
    }
    currentIp = packetInfo?.["IP"]?.["Source IP"] || hostFilterEl.value || "Unknown";
    currentPacketKey =
      currentIp + ":" + (packetInfo?.["Index"] ?? index);
    syncBookmarkDropdown(currentPacketKey);
    updateCurrentPacketCounters(packetSet, {
      isFilteredView: navAction === "filtered",
    });
    console.log(activePacket);
    const hexPayload =
      packetInfo?.["Raw data"]?.["Payload"]?.["Hex Encoded"] || "";
    infoPanel(packetSet);
    popHexGrid(hexPayload);
    populateDataTypes(packetSet);
    logCurrentPacketDisplay(navAction || "first-load");
  }
}

function getPacketDataTypeItems(packetEntry) {
  const extraInfo = packetEntry?.["Extra Info"] || {};
  const traits = extraInfo["Traits"] || {};
  const serverInfo = traits["Server Info"] || {};
  const networkData = traits["Network Data"] || {};
  let dataItems = Array.isArray(extraInfo["Data Types"])
    ? [...extraInfo["Data Types"]]
    : [];

  if (
    serverInfo["Encryption Data"] != "N/A" &&
    serverInfo["Encryption Data"] != undefined
  ) {
    const sslDetails = serverInfo["Encryption Data"]?.["SSL Version"] ?? "Unknown";
    const protoName =
      networkData["Port Protocol"] ?? networkData["Port Protcol"] ?? "Unknown";
    dataItems = [];
    dataItems.push(sslDetails + " encrypted stream");
    dataItems.push(protoName + " protocol data");
  }

  return dataItems;
}

function normalizeProtocolToken(value) {
  return String(value ?? "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");
}

function collectPacketProtocolTokens(packetEntry) {
  const packetInfo = packetEntry?.["Packet Info"] || {};
  const extraInfo = packetEntry?.["Extra Info"] || {};
  const traits = extraInfo["Traits"] || {};
  const networkData = traits["Network Data"] || {};
  const tokens = new Set();

  const pushToken = (value) => {
    if (value == null) return;
    if (Array.isArray(value)) {
      value.forEach((item) => pushToken(item));
      return;
    }
    const text = String(value).trim();
    if (!text) return;
    const normalizedWhole = normalizeProtocolToken(text);
    if (normalizedWhole) tokens.add(normalizedWhole);
    text.split(/[^A-Za-z0-9]+/).forEach((segment) => {
      const normalized = normalizeProtocolToken(segment);
      if (normalized) tokens.add(normalized);
    });
  };

  pushToken(packetInfo["Protocol"]);
  pushToken(packetInfo["Decoded Protocols"]);
  pushToken(packetInfo["Link Control"]);
  pushToken(networkData["Port Protocol"]);
  pushToken(networkData["Port Protcol"]);
  pushToken(networkData["Port Description"]);

  return [...tokens];
}

function getMatchedHiddenDataTypeProtocol(packetEntry) {
  const protocolTokens = collectPacketProtocolTokens(packetEntry);
  for (const token of protocolTokens) {
    if (DATA_TYPES_DEFAULT_HIDDEN_PROTOCOLS.has(token)) {
      return token;
    }
    if (
      DATA_TYPES_DEFAULT_HIDDEN_PROTOCOL_PREFIXES.some((prefix) =>
        token.startsWith(prefix),
      )
    ) {
      return token;
    }
  }
  return "";
}

function hasLikelyFileLikeDataTypes(packetEntry, dataItems) {
  const extraInfo = packetEntry?.["Extra Info"] || {};
  const traits = extraInfo["Traits"] || {};
  const characters = traits["Characters"] || {};
  const packetInfo = packetEntry?.["Packet Info"] || {};
  const payloadLenRaw = packetInfo?.["Raw data"]?.["Payload Length"];
  const payloadLength = Number(payloadLenRaw);

  if (Number.isFinite(payloadLength) && payloadLength <= 0) {
    return false;
  }

  const charset = String(characters["Charset"] ?? "").trim().toLowerCase();
  if (charset && charset !== "unknown" && charset !== "n/a") {
    return true;
  }

  const mimeType = String(extraInfo["MIME Type"] ?? "")
    .trim()
    .toLowerCase();
  const usefulMimeHints = [
    "text/",
    "image/",
    "audio/",
    "video/",
    "application/json",
    "application/xml",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-",
  ];
  if (usefulMimeHints.some((hint) => mimeType.startsWith(hint))) {
    return true;
  }

  const nonUsefulDataTypePatterns = [
    /^unknown\s*data\s*type$/i,
    /encrypted\s+stream/i,
    /protocol\s+data/i,
    /^unknown$/i,
    /^n\/a$/i,
  ];
  const hasUsefulDataType = dataItems.some((item) => {
    const normalized = String(item ?? "").trim();
    if (!normalized) return false;
    return !nonUsefulDataTypePatterns.some((pattern) => pattern.test(normalized));
  });

  return hasUsefulDataType;
}

function getDataTypesVisibilityState(packetEntry) {
  const dataItems = getPacketDataTypeItems(packetEntry);
  const hiddenProtocolToken = getMatchedHiddenDataTypeProtocol(packetEntry);
  const hiddenByProtocol = hiddenProtocolToken !== "";
  const likelyFileLikeData = hasLikelyFileLikeDataTypes(packetEntry, dataItems);
  const hiddenByHeuristic = !hiddenByProtocol && !likelyFileLikeData;
  const isOverridden = currentPacketKey != null && dataTypesOverridePacketKey === currentPacketKey;

  return {
    showPane: isOverridden || (!hiddenByProtocol && !hiddenByHeuristic ? true : false),
    reason: hiddenByProtocol
      ? `Hidden by default for ${hiddenProtocolToken} control/management traffic. Show it anyway to inspect encapsulated or tunneled payload guesses.`
      : hiddenByHeuristic
        ? "Hidden by default because this packet has no strong file-like payload indicators. Show it anyway to inspect encapsulated or tunneled payload guesses."
        : "",
  };
}

function applyDataTypesVisibility(visibilityState) {
  const dataTypesEl = document.getElementById("data-types");
  const dataTypesPaneEl = document.getElementById("dataTypesPane");
  const overrideWrapEl = document.getElementById("data-types-override-wrap");
  const overrideTextEl = document.getElementById("data-types-override-text");
  const overrideButtonEl = document.getElementById("data-types-override-btn");

  if (
    !dataTypesEl ||
    !dataTypesPaneEl ||
    !overrideWrapEl ||
    !overrideTextEl ||
    !overrideButtonEl
  ) {
    return;
  }

  dataTypesPaneEl.hidden = !visibilityState.showPane;
  overrideWrapEl.hidden = visibilityState.showPane;
  overrideButtonEl.hidden = visibilityState.showPane;
  overrideTextEl.textContent = visibilityState.reason;
  dataTypesEl.classList.toggle("data-types-collapsed", !visibilityState.showPane);
}

function populateDataTypes(p) {
  setPrevNextButtonVisibility(p, index);
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
  const packetEntry = p?.[index] || {};
  const visibilityState = getDataTypesVisibilityState(packetEntry);
  applyDataTypesVisibility(visibilityState);
  const extraInfo = packetEntry["Extra Info"] || {};
  const traits = extraInfo["Traits"] || {};
  const characters = traits["Characters"] || {};

  let charsetText = String(characters["Charset"] ?? "Unknown");
  const encodingData = characters["Encoding"];
  if (encodingData === "Unavailable for high entropy data") {
    encodingText = "Unavailable for high entropy data";
  } else if (encodingData && typeof encodingData === "object") {
    encodingText = JSON.stringify(encodingData["encoding"] ?? "Unknown");
    languageText = JSON.stringify(encodingData["language"] ?? "Unknown");
  } else {
    encodingText = "Unknown";
    languageText = "Unknown";
  }

  const mimeTypeText = String(extraInfo["MIME Type"] ?? "Unknown");
  const dataItems = getPacketDataTypeItems(packetEntry);

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
    listItem.textContent = String(item ?? "Unknown");
    typesListEl.appendChild(listItem);
  });
}

const dataTypesOverrideButtonEl = document.getElementById("data-types-override-btn");
if (dataTypesOverrideButtonEl) {
  dataTypesOverrideButtonEl.addEventListener("click", () => {
    if (currentPacketKey == null || !Array.isArray(p) || !p[index]) {
      return;
    }
    dataTypesOverridePacketKey = currentPacketKey;
    populateDataTypes(p);
    statusUpdate("Status: Showing data types for current packet");
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
  if (!Array.isArray(pk) || pk.length === 0) {
    statusUpdate("Status: No packet information found for this host");
    doError("No packet information found for this host!");
    return;
  }
  const p = pk[index];
  if (!p || !p["Packet Info"]) {
    statusUpdate("Status: Packet data is unavailable for this entry");
    doError("Packet data is unavailable for this entry!");
    return;
  }
  updateCurrentPacketCounters(pk, {
    isFilteredView: Array.isArray(filteredPackets) && pk === filteredPackets,
  });
  let packetInfoData = p["Packet Info"] || {};
  let extraInfoData = p["Extra Info"] || {};
  const ipData = packetInfoData["IP"] || {};
  const traitsData = extraInfoData["Traits"] || {};
  const networkData = traitsData["Network Data"] || {};
  const serverInfo = traitsData["Server Info"] || {};
  const srcLocation = networkData?.["Source IP"]?.["Location"] || {};
  const dstLocation = networkData?.["Destination IP"]?.["Location"] || {};
  let packetTimestamp = packetInfoData["Packet Timestamp"] || "N/A";
  let ipChecksum = ipData["IP Checksum"] ?? "N/A";

  // Determine transport protocol (TCP or UDP); fall back to TCP for older captures
  const protocol = packetInfoData["Protocol"] || "Unknown";
  const transportData = packetInfoData[protocol] || {};

  const transportChecksum =
    protocol === "TCP"
      ? transportData["TCP checksum"]
      : protocol === "UDP"
        ? transportData["UDP checksum"]
        : protocol === "IGMP"
          ? transportData["IGMP Checksum"]
          : protocol === "ICMP"
            ? transportData["ICMP Checksum"]
            : "N/A";
  const transportLayerLen =
    protocol === "TCP"
      ? transportData["TCP layer length"]
      : protocol === "UDP"
        ? transportData["UDP length"]
        : protocol === "IGMP"
          ? transportData["Wire length"]
          : protocol === "ICMP"
            ? transportData["Wire length"]
            : "N/A";
  const tcpFlags =
    protocol === "TCP" && transportData["TCP Flag Data"]
      ? transportData["TCP Flag Data"]["Flags"]
      : "N/A";

  const sourceIpPort =
    (ipData["Source IP"] ?? hostFilterEl.value ?? "Unknown") +
    ":" +
    (transportData["Source port"] ?? "?");
  const destIpPort =
    (ipData["Destination IP"] ?? hostFilterEl.value ?? "Unknown") +
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
  const ipLayerLen = ipData["IP layer length"] ?? "N/A";
  const wireLen = transportData["Wire length"] ?? "N/A";
  const payloadLen = packetInfoData?.["Raw data"]?.["Payload Length"] ?? "N/A";
  let sslCert = "";
  let sslVersion = "";
  let sslAlgos = "";
  if (
    serverInfo["Encryption Data"] == "N/A" ||
    serverInfo.hasOwnProperty("Encryption Data") == false
  ) {
    sslCert = "Not encrypted";
    sslVersion = "Not encrypted";
    sslAlgos = "";
  } else {
    sslCert = serverInfo["Encryption Data"]?.["SSL Cert"] ?? "Not available";
    sslVersion = serverInfo["Encryption Data"]?.["SSL Version"] ?? "Not available";
    sslAlgos =
      serverInfo["Encryption Data"]?.["Encrypted With"]?.join(
        "<br>Extra algo info: ",
      ) ?? "No algorithm information available";
  }
  const isDecompressed = extraInfoData?.["Decompressed"]?.["Decompressed"];
  function removeIps(ipList) {
    const ipRegex =
      /\b((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/;
    return ipList.filter((item) => !ipRegex.test(item));
  }

  let dnsHostsHtml;
  if (
    networkData?.["Hostnames"]?.["Hostnames"] == undefined
  ) {
    dnsHostsHtml = "localhost";
  } else {
    dnsHostsHtml =
      "localhost<br>" +
      networkData["Hostnames"]["Hostnames"].join(
        "<br>",
      );
  }
  const filteredDnsHosts = removeIps(dnsHostsHtml.split("<br>")).join("<br>");
  dnsHostsHtml = filteredDnsHosts == "" ? "localhost" : filteredDnsHosts;

  const pageTitle = serverInfo["Page Title"];
  const isEncrypted = serverInfo["Encrypted"];
  const protoName = networkData["app.proto"] ?? "Unknown";
  const protoDescription = networkData["Port Description"];
  const srcNetClass = networkData?.["Source IP"]?.["Class"] ?? "N/A";
  const dstNetClass = networkData?.["Destination IP"]?.["Class"] ?? "N/A";
  document.getElementById("sidedatatable").textContent = "";
  document.getElementById("protoInfoSrc").textContent = "Source";
  document.getElementById("protoInfoDest").textContent = "Destination";
  document.getElementById("comp").textContent = "Unknown";
  if (isDecompressed == false || isDecompressed == undefined) {
    const types = Array.isArray(extraInfoData["Data Types"])
      ? extraInfoData["Data Types"]
      : [];

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

  const protocolsUsed = [];
  const seenProtocolKeys = new Set();
  const normalizeProtocolLabel = (value) => {
    const text = String(value ?? "").trim();
    if (!text) return "";
    const lowered = text.toLowerCase();
    if (lowered === "unknown" || lowered === "n/a" || lowered === "null") {
      return "";
    }
    return text;
  };
  const addProtocolUsed = (layer, protocolLabel, details = "") => {
    const normalizedLabel = normalizeProtocolLabel(protocolLabel);
    if (!normalizedLabel) return;
    const normalizedLayer = String(layer ?? "").trim();
    const dedupeKey = `${normalizedLayer.toLowerCase()}|${normalizedLabel.toLowerCase()}`;
    if (seenProtocolKeys.has(dedupeKey)) return;
    seenProtocolKeys.add(dedupeKey);
    protocolsUsed.push({
      layer: normalizedLayer,
      protocol: normalizedLabel,
      details: normalizeProtocolLabel(details),
    });
  };

  if (packetInfoData["Ethernet Frame"]) {
    addProtocolUsed("Link", "Ethernet");
  }
  if (protocol === "ARP" || protocol === "RARP") {
    addProtocolUsed("Network", protocol, transportData?.["Operation"]);
  } else if (protocol === "IGMP") {
    if (packetInfoData["IP"]) {
      addProtocolUsed("Network", "IP");
    }
    addProtocolUsed("Network", "IGMP", transportData?.["Type"]);
  } else {
    if (packetInfoData["IP"]) {
      addProtocolUsed("Network", "IP");
    }
    addProtocolUsed("Transport", protocol);
    addProtocolUsed("Application", protoName, protoDescription);
  }

  const sslVersionLabel =
    extraInfoData?.["Traits"]?.["Server Info"]?.["Encryption Data"]?.[
    "SSL Version"
    ];
  addProtocolUsed("Encryption", sslVersionLabel);
  if (isEncrypted === true) {
    addProtocolUsed("Encryption", "TLS");
  }

  const protocolsEl = document.getElementById("protocols");
  if (protocolsUsed.length === 0) {
    protocolsEl.innerHTML = "Unknown";
  } else {
    protocolsEl.innerHTML = protocolsUsed
      .map((entry) => {
        const detailText = entry.details
          ? ` (${escapeHtml(String(entry.details))})`
          : "";
        if (!entry.layer) {
          return `${escapeHtml(String(entry.protocol))}${detailText}`;
        }
        return `${escapeHtml(String(entry.layer))}: ${escapeHtml(String(entry.protocol))}${detailText}`;
      })
      .join("<br>");
  }

  const currentStreamKey = buildBidirectionalStreamKey(packetInfoData);
  const streamPackets = [];

  // ensure that all the packets in the stream all report the same application protocol, for consistency
  if (capturedPackets && capturedPackets["Host"]) {
    for (const host of Object.keys(capturedPackets["Host"])) {
      const hostPackets = capturedPackets["Host"][host];
      if (!Array.isArray(hostPackets)) continue;
      for (const pkt of hostPackets) {
        const pi = pkt?.["Packet Info"];
        if (pi && buildBidirectionalStreamKey(pi) === currentStreamKey) {
          streamPackets.push(pkt);
          // check and see if they all have the same application protocol,
          // if not, we will use the first packet's application protocol
          //  for the stream, for consistency
          const pktProtoName =
            pi?.["Extra Info"]?.["Traits"]?.["Network Data"]?.["tcp.proto"] ||
            "Unknown";
          if (streamPackets.length === 1) {
            // first packet in the stream, set the stream protocol
            streamProtocol = pktProtoName;
          } else if (pktProtoName !== streamProtocol) {
            // different protocol found, log a warning and continue using the first packet's protocol
            console.warn(`Inconsistent application protocol in stream: expected ${streamProtocol}, but found ${pktProtoName}`);
          }
        }
      }
    }
  }

  const sortedStreamPackets = sortPacketsByOwnStreamOrder(streamPackets);
  const tcpArrivalStatusByPacketKey = getTcpStreamArrivalStatusByPacketKey(
    sortedStreamPackets,
  );
  const currentTcpArrivalStatus = tcpArrivalStatusByPacketKey.get(getPacketKey(p));
  const tcpStreamStatusText =
    protocol === "TCP"
      ? currentTcpArrivalStatus?.label || "In-order TCP segment"
      : "N/A";

  const checksumData = [
    { name: "IP Checksum", value: ipChecksum },
    { name: protocol + " Checksum", value: transportChecksum },
    { name: "Flags", value: tcpFlags },
    { name: "TCP Stream Status", value: tcpStreamStatusText },
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

  // IGMP info table (shown for IGMP packets)
  renderIgmpTable(protocol, transportData);

  // ARP/RARP info table (shown for ARP and RARP packets)
  renderArpTable(protocol, transportData);

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

  // WebSocket info table (shown for WebSocket frames/upgrades on port 80/443/8080/8443/8765)
  renderWebSocketTable(transportData);

  // NFS/RPC info table (shown for NFS/RPC packets on port 2049/111)
  renderNfsTable(transportData);

  // Kerberos info table (shown for Kerberos packets on port 88)
  renderKerberosTable(transportData);

  // SSH info table (shown for SSH packets on port 22/2222)
  renderSshTable(transportData);

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
  const entropyValue = Number(traitsData["Shannon Entropy"] ?? 0);
  const tcpTimestampSuffix =
    protocol === "TCP" && tcpStreamStatusText !== "N/A"
      ? ` ${tcpStreamStatusText}`
      : "";
  document.getElementById("timestamp").innerHTML =
    "Timestamp " + packetTimestamp + "<br>" + tcpTimestampSuffix;

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
    srcLocation["City"] == undefined
  ) {
    const localnetData = [{ name: "Location", value: "Localnet" }];
    const localnetHeaders = ["Source Host", "Location"];
    createTable(localnetData, localnetHeaders, "sideloctable");
  } else {
    const srcLocData = [
      {
        name: "Country",
        value:
          srcLocation["Country"] ?? "N/A",
      },
      {
        name: "City",
        value: srcLocation["City"] ?? "N/A",
      },
      {
        name: "Timezone",
        value: srcLocation["Time Zone"] ?? "N/A",
      },
    ];
    const srcLocHeaders = ["Source Host", "Location"];
    createTable(srcLocData, srcLocHeaders, "sideloctable");
  }
  if (
    dstLocation["City"] == undefined
  ) {
    const localnetData = [{ name: "Location", value: "Localnet" }];
    const localnetHeaders = ["Destination Host", "Location"];
    createTable(localnetData, localnetHeaders, "sideloctable");
  } else {
    const dstLocData = [
      {
        name: "Country",
        value:
          dstLocation["Country"] ?? "N/A",
      },
      {
        name: "City",
        value: dstLocation["City"] ?? "N/A",
      },
      {
        name: "Timezone",

        value: dstLocation["Time Zone"] ?? "N/A",
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

const reprocessSessionPcapBtn = document.getElementById("reprocess-session-pcap-btn");
if (reprocessSessionPcapBtn) {
  reprocessSessionPcapBtn.addEventListener("click", () => {
    if (!sessionPcapSource || !sessionPcapSource.data) {
      statusUpdate("Status: No stored session PCAP to reprocess");
      return;
    }
    if (backendProgressState.processing) {
      warnReprocessAttemptBeforeReady();
      return;
    }
    runSnitch(sessionPcapSource, { fromSessionSource: true });
  });
}

if (window.snitchapi && typeof window.snitchapi.onPcapSource === "function") {
  window.snitchapi.onPcapSource((pcapSource) => {
    setSessionPcapSource(pcapSource, {
      logLabel: "backend-source",
    });
  });
}

// Open the session library picker
const sessionsLibraryBtn = document.getElementById("sessions-library-btn");
if (sessionsLibraryBtn) {
  sessionsLibraryBtn.addEventListener("click", () => {
    if (sessionPickerPanel) sessionPickerPanel.show();
  });
}

// the next two have hooks into IPC handlers for main.js
// data transactions

// when the main.js returns the capture path from snitch.py
window.jsonapi.onJsonPath((rawPayload) => {
  const payload = normalizeBackendJsonPathPayload(rawPayload);
  if (!payload || !payload.path) return;

  backendCaptureUpdateQueue = backendCaptureUpdateQueue
    .then(async () => {
      document.getElementById("error-container").style.display = "none";
      // Clear library session name – this is a new PCAP capture, not a library session
      currentSessionName = null;

      backendProgressState.processedPackets = Math.max(
        backendProgressState.processedPackets,
        payload.processedPackets,
      );
      backendProgressState.totalPackets = Math.max(
        backendProgressState.totalPackets,
        payload.totalPackets,
      );
      backendProgressState.processing = !payload.complete;

      const minimumChunkSize = payload.chunkSize || BACKEND_PACKET_CHUNK_SIZE;
      const hasUsableChunk =
        payload.complete || payload.processedPackets >= minimumChunkSize;

      if (!backendProgressState.firstChunkLoaded) {
        if (!hasUsableChunk) {
          document.getElementById("loading-screen").style.display = "flex";
          document.getElementById("loading-container").style.display = "block";
          document.getElementById("loading-text").textContent = "Loading packets...";
          statusUpdate("Status: Waiting for initial packet batch...");
          updateBackendProcessingWarning();
          return;
        }

        document.getElementById("loading-screen").style.display = "flex";
        document.getElementById("loading-container").style.display = "block";
        document.getElementById("loading-text").textContent = "Loading packets...";
        statusUpdate("Status: Initial packet batch ready, loading...");
        writeLogEntry(
          `Backend snapshot received path="${payload.path}" processed=${payload.processedPackets} total=${payload.totalPackets} complete=${payload.complete}`,
        );
        await processCapturePath(payload.path, {
          suppressLoadingOverlay: false,
          incrementalUpdate: false,
        });
        backendProgressState.firstChunkLoaded = true;
        filterInputEl.value = "";
        updateFilterClearButtonState();
        clearFilterQuery();
        syncFilterHighlight();
      } else {
        statusUpdate("Status: Updating packet data as backend processes capture...");
        await processCapturePath(payload.path, {
          suppressLoadingOverlay: true,
          incrementalUpdate: true,
        });
        writeLogEntry(
          `Backend incremental update processed=${payload.processedPackets} total=${payload.totalPackets} complete=${payload.complete}`,
        );
      }

      if (payload.complete) {
        backendProgressState.processing = false;
        const loadEndTime = performance.now();
        document.getElementById("load-time").textContent =
          "Load time: " + ((loadEndTime - startTime) / 1000).toFixed(2) + " seconds";
        document.getElementById("total-packets").textContent =
          "Total Packets: " + totalPacketCount();
        scheduleSessionKeychainAutoPopulate("backend-complete");
        writeLogEntry(
          `Completed processing backend data total_packets=${totalPacketCount()} load_time_sec=${(
            (loadEndTime - startTime) /
            1000
          ).toFixed(2)}`,
        );
        statusUpdate("Status: Ready");
      }

      updateBackendProcessingWarning();
    })
    .catch((error) => {
      logErrorEntry("backend-progress", error);
      doError("Failed to process backend update", { backend: true });
    });
});

// here we create the backend process and hook it to the handler
function runSnitch(file, options = {}) {
  const { fromSessionSource = false } = options;
  resetBackendProgressState();
  backendProgressState.processing = true;
  document.getElementById("loading-screen").style.display = "block";
  document.getElementById("loading-container").style.display = "block";
  document.getElementById("loading-text").textContent = "Loading packets...";
  showSummaryLoading();
  document.getElementById("status").textContent =
    "Status: Running snitch backend, this may take a few minutes...";
  document.getElementById("error-container").style.display = "none";
  startTime = performance.now();
  const useLLM = document.getElementById("use-llm").checked;
  const fileLabel = fromSessionSource
    ? file?.fileName || "session-stored-pcap"
    : typeof file === "string"
      ? file
      : file?.name || "unknown";
  writeLogEntry(
    `Backend analysis started file=${fileLabel} llm_enabled=${useLLM}`,
  );
  const backendPromise = fromSessionSource
    ? window.snitchapi && typeof window.snitchapi.runBackendCommandFromSession === "function"
      ? window.snitchapi.runBackendCommandFromSession(file, useLLM)
      : Promise.reject(new Error("Session PCAP reprocess API is unavailable"))
    : window.snitchapi.runBackendCommand(file, useLLM);
  backendPromise
    .then((result) => {
      if (result && result.pcapSource) {
        setSessionPcapSource(result.pcapSource, {
          logLabel: fromSessionSource ? "session-reprocess" : "backend-file",
        });
      }
    })
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
  updateCurrentPacketCounters([], {
    isFilteredView: true,
  });
  popHexGrid("");
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
      void runFilterQuery(filterQuery);
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

filterInputEl.addEventListener("input", () => {
  syncFilterHighlight();
  if (filterInputEl.value.trim() === "") {
    syncTargetHostSelection(DUMMY_ALL_HOST);
  }
});
filterInputEl.addEventListener("scroll", syncFilterHighlightScroll);

filterHistorySelectEl.addEventListener("change", () => {
  const selectedQuery = filterHistorySelectEl.value;
  if (!selectedQuery) return;
  filterInputEl.value = selectedQuery;
  syncFilterHighlight();
  void runFilterQuery(selectedQuery);
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
  document.getElementById("help-btn").style.opacity = "1";
  document.getElementById("log-btn").style.opacity = "1";
  const rightsideDataEl = document.getElementById("rightside-data");
  const rightsideNotesEl = document.getElementById("rightside-notes");
  if (rightsideDataEl) rightsideDataEl.hidden = false;
  if (rightsideNotesEl) rightsideNotesEl.hidden = true;
  updatePcapSizeDisplayFromSource();
  updateReprocessButtonState();
  document.getElementById("leftside").style.display = "none";
  document.getElementById("loading-container").style.display = "none";
};
