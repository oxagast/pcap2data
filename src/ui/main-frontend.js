// Orchestrates the main renderer UI, capture workflows, and cross-panel behavior.

const threadName = "MainFrontend";
window.__PACKETSNITCH_MAIN_FRONTEND_LOADED__ = true;

// ============================================================================
// Imports and module dependencies
// ============================================================================
import { bookmarkList } from '../state';
import "../assets/css/style.css";
const CryptoJS = require("crypto-js");
const { marked } = require("marked");
const { sha3_256, sha3_512 } = require("js-sha3");
const whirlpool = require("whirlpool-js");
const { activityLogPanelMarkup } = require("./fragments/activity-log-panel");
const { convertContextMenuMarkup } = require("./fragments/convert-context-menu");
const { validateFilterSyntax } = require("../filter");
const { initializeLogging } = require("../logging");
const { initializeContextMenu } = require("./context-menu");
const metrics = require("../metrics");
// Expose the metrics module on the window so first-run UI (the
// consent overlay) and other panels can call into it without having
// to thread the require through every call site. The metrics object
// is the same singleton the rest of the renderer uses.
window.__PACKETSNITCH_METRICS__ = metrics;
// Metrics is always loaded so that call sites can use it unconditionally.
// The queue is a no-op until the user opts in via the Privacy settings subtab.
if (metrics && typeof metrics.init === "function") {
  metrics.init();
}
// Wire the main process's flush-request signal to the renderer's queue
// drain. Without this listener the timer in main.js fires
// ``metrics:flush-request`` every interval but no one ever reads it,
// so events pile up in the renderer queue and never reach the network.
// We also kick a flush on window unload so a graceful shutdown ships
// the last few events.
if (
  typeof window !== "undefined"
  && window.metricsapi
  && typeof window.metricsapi.onFlushRequest === "function"
  && typeof metrics.flush === "function"
) {
  window.metricsapi.onFlushRequest(() => {
    metrics.flush().catch((error) => {
      // The flush promise itself never throws (errors land in
      // ``metrics.retryQueue``) but be defensive in case a future
      // refactor does. ``logErrorEntry`` is declared further down
      // in this file (inside the panel-composition section), so
      // we go through ``writeLogEntry`` here to avoid a temporal
      // dead zone on first call.
      const message =
        error && typeof error === "object" && "message" in error
          ? error.message
          : String(error);
      writeLogEntry(`Error context=metrics-flush details="${message}"`);
    });
  });
  window.addEventListener("beforeunload", () => {
    try {
      void metrics.flush();
    } catch (_error) {
      // ignore: we are tearing down
    }
  });
}

// Settings changes that originate outside the privacy tab form
// (e.g. the first-run consent overlay, the metrics service writing
// back a fresh install id) only round-trip to the renderer's
// in-memory ``appSettings`` and the privacy form if the renderer is
// told about them. ``metrics.js`` dispatches a
// ``packetsnitch:settings-updated`` CustomEvent whenever it calls
// ``settingsapi.update``; we listen for it here and re-sync the
// in-memory state and the visible form.  Without this listener the
// privacy tab checkbox would stay unselected after the user clicks
// "Yes" on the consent overlay because the renderer's
// ``appSettings`` is not refreshed by the IPC call alone.
if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
  window.addEventListener("packetsnitch:settings-updated", (event) => {
    const detail = event && event.detail;
    if (!detail || typeof detail !== "object") {
      return;
    }
    try {
      setCurrentSettings(detail);
    } catch (_error) {
      // ignore: setCurrentSettings is best-effort
    }
    try {
      syncSettingsFormFromState();
    } catch (_error) {
      // ignore: re-syncing the form is best-effort
    }
  });
}

// One-shot tab and subtab tracking.
//
// Each main tab (Analysis, Host Data, Conv, Crypt, Keystore, Stats,
// List, Notes, Settings) and every subtab inside those workspaces
// is wired to its own click handler in a different file.  Rather
// than touch every panel we listen for clicks here at the document
// level and look up the right tab/subtab names by the button's
// ``id``.  This keeps the metrics tracking completely decoupled
// from the per-panel wiring (a new tab added to the toolbar will
// only need an entry in the lookup tables below to be tracked).
//
// ``tab.switch`` fires for top-level tabs; ``subtab.switch`` fires
// when a subtab is opened inside a known parent tab.  Both events
// are no-ops when the user has not opted in to diagnostics.
const MAIN_TAB_BUTTON_TO_TAB = {
  "summary-btn": "summary",
  "data-btn": "data",
  "data-tools-btn": "data-tools",
  "crypt-btn": "crypt",
  "keystore-btn": "keystore",
  "stats-btn": "stats",
  "list-btn": "list",
  "notes-btn": "notes",
  "settings-btn": "settings",
};
// ``conv-subtab-*`` and ``crypt-subtab-*`` buttons live inside
// the Conv and Crypt workspaces respectively; we tag the event
// with the parent tab so the dashboard can answer questions like
// "which Conv subtab is most used?".
const CONV_SUBTAB_PREFIX = "conv-subtab-";
const CRYPT_SUBTAB_PREFIX = "crypt-subtab-";

if (typeof document !== "undefined" && typeof document.addEventListener === "function") {
  document.addEventListener("click", (event) => {
    if (!metrics || typeof metrics.trackTabSwitch !== "function") {
      return;
    }
    const target = event.target;
    if (!target || typeof target !== "object" || typeof target.id !== "string") {
      return;
    }
    const buttonId = target.id;
    if (!buttonId) {
      return;
    }
    const mainTab = MAIN_TAB_BUTTON_TO_TAB[buttonId];
    if (mainTab) {
      metrics.trackTabSwitch({ tab: mainTab });
      return;
    }
    if (buttonId.startsWith(CONV_SUBTAB_PREFIX)) {
      metrics.trackTabSwitch({
        tab: "data-tools",
        subtab: buttonId.slice(CONV_SUBTAB_PREFIX.length),
      });
      return;
    }
    if (buttonId.startsWith(CRYPT_SUBTAB_PREFIX)) {
      metrics.trackTabSwitch({
        tab: "crypt",
        subtab: buttonId.slice(CRYPT_SUBTAB_PREFIX.length),
      });
      return;
    }
  });
}
const {
  createTable,
  renderDnsTable,
  renderIcmpTable,
  renderIgmpTable,
  renderArpTable,
  renderLinkControlTable,
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
  renderSmppTable,
  renderSoulseekTable,
  renderBitTorrentTable,
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
  renderSctpTable,
} = require("./decoders/main");
const { createCryptPanel } = require("./panels/crypt-panel");
const {
  createKeystorePanel,
  CRYPT_KEYSTORE_MODE_SESSION,
  CRYPT_KEYSTORE_MODE_PERSISTENT,
  SESSION_KEYCHAIN_LABEL,
} = require("./panels/keystore-panel");
const {
  getLatestKeystoreSummary,
} = require("./panels/keystore-llm-summarizer");
const { createStatsPanel, buildCaptureStats } = require("./panels/stats-panel");
const { createListPanel } = require("./panels/list-panel");
const { createSummaryPanel } = require("./panels/summary-panel");
const { createSubnetCalculatorPanel } = require("./panels/subnet-calculator-panel");
const { initializeInstallScreen } = require("./panels/install-screen");
const { initializeSessionPicker } = require("./panels/session-picker");
const { createDataPanel } = require("./panels/data-panel");
const {
  createPacketLoadingHelpers,
} = require("./main-frontend/packet-loading");
const { createStreamHelpers } = require("./main-frontend/stream-helpers");
const { createDataTypeHelpers } = require("./main-frontend/data-types");
const { createWorkspaceTabController } = require("./main-frontend/workspace-tabs");
const {
  createProtocolDecodingHelpers,
} = require("./main-frontend/protocol-decoding");
const psVer = require("../../package.json").version;
const {
  DEFAULT_SETTINGS,
  cloneDefaultSettings,
  normalizeSettings,
} = require("../settings");
const {
  initConvPanel,
  CONV_CONVERSIONS_SUBTAB,
  CONV_HASHES_SUBTAB,
  CONV_EXTRACTION_SUBTAB,
  CONV_DECODES_SUBTAB,
  CONV_SUBNET_SUBTAB,
  CONV_THREAT_INTEL_SUBTAB,
  CONV_PACKET_JSON_SUBTAB,
  VALID_CONV_SUBTABS,
  DATA_TOOLS_CONTEXT_BASE64_MIN_LENGTH,
  DATA_TOOLS_TEXT_MIME_PRINTABLE_THRESHOLD,
  DATA_TOOLS_ENTROPY_HIGH_THRESHOLD,
  DATA_TOOLS_ENTROPY_MEDIUM_THRESHOLD,
  DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES,
  getActiveConvSubtab,
  getActiveDataToolsProtoResult,
  getDecodedImageRegistry,
  clearDecodedImageRegistry,
  getPacketProtocolDecoderHint,
  formatHexInputBytes,
  setConvSubtab,
  runDataToolsHashesFromInput,
  crossReferenceCurrentHash,
  decodeHttpFromBytes,
  decodeJpegFromBytes,
  decodePngFromBytes,
  decodeGifFromBytes,
  decodeWebpFromBytes,
  renderProtoDecoderOutput,
  runProtoDecoder,
  runProtoDecoderForStreamPackets,
  decodeWithSelectedProtocol,
  clearProtoDecoderOutput,
  setDataToolsStreamPackets,
  getDataToolsStreamPackets,
  clearDataToolsStreamPackets,
  EXIF_FILE_TYPE_TO_PROTO,
  getImageTypeFromExifReader,
  clearDataToolsSummary,
  requestDataToolsBackgroundSummary,
} = require("./panels/data-tools-panel");
const {
  getCurrentSummaryContext,
  getCurrentSummaryContextHash,
} = require("./panels/data-tools-llm-summarizer");
const { normalizeSmbDecoderBytes } = require('./decoders/conv/smb-helpers');
const {
  getProtoDecoderHintForFileName,
  SUPPORTED_DECODER_PROTOS,
} = require('./decoders/conv/mime-maps');
function mountStartupFragments() {
  const activityLogPanelEl = document.getElementById("activity-log-panel");
  if (activityLogPanelEl && !activityLogPanelEl.dataset.fragmentMounted) {
    activityLogPanelEl.innerHTML = activityLogPanelMarkup;
    activityLogPanelEl.dataset.fragmentMounted = "true";
  }

  const convertContextMenuEl = document.getElementById("convert-context-menu");
  if (convertContextMenuEl && !convertContextMenuEl.dataset.fragmentMounted) {
    convertContextMenuEl.innerHTML = convertContextMenuMarkup;
    convertContextMenuEl.dataset.fragmentMounted = "true";
  }
}

mountStartupFragments();

const domCache = {};
function getCachedElement(id) {
  if (!domCache[id]) {
    domCache[id] = document.getElementById(id);
  }
  return domCache[id];
}

const validKeysCache = [];
const validKeyByLower = new Map();
const filterKeyUsageCounts = new Map();
const filterValueUsageCacheByKey = new Map();
const filterValueUsageInFlightByKey = new Map();
const FILTER_AUTOCOMPLETE_MAX_SUGGESTIONS = 8;
let filterAutocompleteCacheVersion = -1;
if (window.validkeysapi && typeof window.validkeysapi.getValidKeys === "function") {
  window.validkeysapi.getValidKeys().then((keys) => {
    const normalizedKeys = Array.isArray(keys)
      ? keys
        .map((key) => String(key || "").trim())
        .filter(Boolean)
      : [];
    normalizedKeys.sort((a, b) => a.localeCompare(b));
    validKeysCache.splice(0, validKeysCache.length, ...new Set(normalizedKeys));
    validKeyByLower.clear();
    validKeysCache.forEach((key) => {
      validKeyByLower.set(key.toLowerCase(), key);
    });
    void refreshFilterAutocompleteOptions();
  });
} else {
  console.warn("validkeysapi is unavailable. Key validation helpers will be disabled.");
}

function ensureFilterAutocompleteCachesFresh() {
  if (filterAutocompleteCacheVersion === packetNavigationCacheVersion) {
    return;
  }
  filterValueUsageCacheByKey.clear();
  filterValueUsageInFlightByKey.clear();
  filterAutocompleteCacheVersion = packetNavigationCacheVersion;
}

function canonicalFilterKey(filterKey) {
  const normalized = String(filterKey || "").trim().toLowerCase();
  if (!normalized) return null;
  return validKeyByLower.get(normalized) || null;
}

function extractFilterKeysFromQuery(rawQuery) {
  const query = String(rawQuery || "");
  const filterKeys = [];
  const keyPattern = /(^|[\s!()&|])([a-zA-Z0-9._-]+)\s*:/g;
  let match;
  while ((match = keyPattern.exec(query)) !== null) {
    const key = canonicalFilterKey(match[2]);
    if (key) {
      filterKeys.push(key);
    }
  }
  return filterKeys;
}

function trackFilterKeyUsage(rawQuery) {
  const keys = extractFilterKeysFromQuery(rawQuery);
  keys.forEach((key) => {
    const nextCount = (filterKeyUsageCounts.get(key) || 0) + 1;
    filterKeyUsageCounts.set(key, nextCount);
  });
}

function collectDotKeyValuesFromObject(value, dotKey, outValues, visited) {
  if (!value || typeof value !== "object") {
    return;
  }
  if (visited.has(value)) {
    return;
  }
  visited.add(value);

  if (Object.prototype.hasOwnProperty.call(value, dotKey)) {
    outValues.push(value[dotKey]);
  }

  if (Array.isArray(value)) {
    value.forEach((item) => {
      if (item && typeof item === "object") {
        collectDotKeyValuesFromObject(item, dotKey, outValues, visited);
      }
    });
    return;
  }

  Object.values(value).forEach((child) => {
    if (child && typeof child === "object") {
      collectDotKeyValuesFromObject(child, dotKey, outValues, visited);
    }
  });
}

function normalizeAutocompleteValue(rawValue) {
  if (rawValue === null || rawValue === undefined) {
    return "";
  }
  if (typeof rawValue === "string") {
    const normalized = rawValue.trim();
    if (!normalized) return "";
    return normalized.length > 120 ? `${normalized.slice(0, 117)}...` : normalized;
  }
  if (typeof rawValue === "number" || typeof rawValue === "boolean") {
    return String(rawValue);
  }
  return "";
}

async function buildValueUsageCacheForFilterKey(canonicalKey) {
  const valueCounts = new Map();
  const hydratedAutocompletePackets = new Map();

  try {
    if (window.captureapi && typeof window.captureapi.filter === "function") {
      let matchedPacketKeys = [];
      try {
        const filterResult = await window.captureapi.filter(`${canonicalKey}:*`);
        matchedPacketKeys = Array.isArray(filterResult)
          ? filterResult
            .map((packetKey) => normalizePacketKey(packetKey))
            .filter((packetKey) => typeof packetKey === "string" && packetKey.trim())
          : [];
      } catch (error) {
        matchedPacketKeys = [];
      }

      const matchedPackets = await resolvePacketStubsByKeys(matchedPacketKeys);
      for (let packetIndex = 0; packetIndex < matchedPackets.length; packetIndex += 1) {
        const packetStub = matchedPackets[packetIndex];
        const packetKey = getPacketKey(packetStub, "", packetIndex);
        const hadPayloadHex = Boolean(
          packetStub?.["packet.info"]?.["Raw data"]?.["Payload"]?.["payload.hex"]
          ?? packetStub?.["packet.info"]?.["Raw data"]?.["Payload"]?.["Hex Encoded"],
        );
        const hydratedPacket = await ensurePacketHydrated(packetStub);
        if (!hadPayloadHex && hydratedPacket && hydratedPacket !== packetStub && packetKey) {
          hydratedAutocompletePackets.set(packetKey, packetStub);
        }
        const packetInfo = hydratedPacket?.["packet.info"];
        if (!packetInfo || typeof packetInfo !== "object") {
          continue;
        }
        const rawValues = [];
        collectDotKeyValuesFromObject(packetInfo, canonicalKey, rawValues, new WeakSet());
        rawValues.forEach((rawValue) => {
          const normalized = normalizeAutocompleteValue(rawValue);
          if (!normalized) return;
          valueCounts.set(normalized, (valueCounts.get(normalized) || 0) + 1);
        });
      }
    }

    // Fallback path for non-captureapi contexts.
    if (!valueCounts.size) {
      const allPackets = getAllPacketsForHostNavigation();
      allPackets.forEach((packet) => {
        const packetInfo = packet?.["packet.info"];
        if (!packetInfo || typeof packetInfo !== "object") {
          return;
        }
        const rawValues = [];
        collectDotKeyValuesFromObject(packetInfo, canonicalKey, rawValues, new WeakSet());
        rawValues.forEach((rawValue) => {
          const normalized = normalizeAutocompleteValue(rawValue);
          if (!normalized) return;
          valueCounts.set(normalized, (valueCounts.get(normalized) || 0) + 1);
        });
      });
    }

    return Array.from(valueCounts.entries())
      .sort((a, b) => {
        if (b[1] !== a[1]) {
          return b[1] - a[1];
        }
        return a[0].localeCompare(b[0]);
      })
      .map(([value]) => value);
  } finally {
    hydratedAutocompletePackets.forEach((packetStub, packetKey) => {
      dehydratePacket(packetKey, packetStub);
    });
  }
}

function dehydratePacket(packetKey, packetStub) {
  if (!packetKey || !packetStub) return;
  if (typeof packetStub === "object") {
    packetStub.__packetKey = packetKey;
    packetStub.__packetStub = true;
  }
  hydratedPacketCache.delete(packetKey);
  updatePacketInCollections(packetKey, packetStub);
}

async function getTopValueSuggestionsForFilterKey(filterKey, valuePrefix = "") {
  ensureFilterAutocompleteCachesFresh();

  const canonicalKey = canonicalFilterKey(filterKey);
  if (!canonicalKey) {
    return [];
  }

  if (!filterValueUsageCacheByKey.has(canonicalKey)) {
    if (!filterValueUsageInFlightByKey.has(canonicalKey)) {
      filterValueUsageInFlightByKey.set(
        canonicalKey,
        buildValueUsageCacheForFilterKey(canonicalKey),
      );
    }
    try {
      const rankedValues = await filterValueUsageInFlightByKey.get(canonicalKey);
      filterValueUsageCacheByKey.set(canonicalKey, rankedValues);
    } finally {
      filterValueUsageInFlightByKey.delete(canonicalKey);
    }
  }

  const normalizedPrefix = String(valuePrefix || "").trim().toLowerCase();
  const ranked = filterValueUsageCacheByKey.get(canonicalKey) || [];
  const filtered = normalizedPrefix
    ? ranked.filter((value) => value.toLowerCase().startsWith(normalizedPrefix))
    : ranked;
  return filtered.slice(0, FILTER_AUTOCOMPLETE_MAX_SUGGESTIONS);
}

function getFilterAutocompleteContext(rawQuery, cursorIndex) {
  const query = String(rawQuery || "");
  const cursor = Number.isInteger(cursorIndex)
    ? Math.max(0, Math.min(cursorIndex, query.length))
    : query.length;
  const separators = new Set([" ", "\t", "\n", "\r", "&", "|", "(", ")"]);
  const valueStopCharacters = new Set(["&", "|", "(", ")", "\n", "\r"]);

  let tokenStart = cursor;
  while (tokenStart > 0 && !separators.has(query[tokenStart - 1])) {
    tokenStart -= 1;
  }

  const token = query.slice(tokenStart, cursor);
  const separatorIndex = token.indexOf(":");
  if (separatorIndex >= 0) {
    const colonIndex = tokenStart + separatorIndex;
    const rawKey = token.slice(0, separatorIndex).replace(/^!+/, "").trim();
    if (!rawKey || /[^a-zA-Z0-9._-]/.test(rawKey)) {
      return null;
    }

    let valueStart = colonIndex + 1;
    while (valueStart < query.length && /\s/.test(query[valueStart])) {
      valueStart += 1;
    }

    let valueEnd = valueStart;
    while (valueEnd < query.length && !valueStopCharacters.has(query[valueEnd])) {
      valueEnd += 1;
    }

    const typedPrefix = query.slice(valueStart, cursor).trim();
    return {
      mode: "value",
      query,
      filterKey: rawKey,
      canonicalKey: canonicalFilterKey(rawKey),
      valueStart,
      valueEnd,
      typedPrefix,
      typedPrefixLower: typedPrefix.toLowerCase(),
    };
  }

  let keyStart = tokenStart;
  while (query[keyStart] === "!") {
    keyStart += 1;
  }
  if (keyStart >= cursor) {
    return null;
  }

  let keyEnd = keyStart;
  while (keyEnd < query.length) {
    const char = query[keyEnd];
    if (char === ":" || separators.has(char)) {
      break;
    }
    keyEnd += 1;
  }

  const typedPrefix = query.slice(keyStart, cursor).trim();
  if (!typedPrefix || /[^a-zA-Z0-9._-]/.test(typedPrefix)) {
    return null;
  }

  return {
    mode: "key",
    query,
    keyStart,
    keyEnd,
    typedPrefix,
    typedPrefixLower: typedPrefix.toLowerCase(),
    hasColon: query[keyEnd] === ":",
  };
}

function rankFilterKeysByUsage(candidateKeys) {
  const keys = Array.isArray(candidateKeys) ? candidateKeys : [];
  return [...keys].sort((left, right) => {
    const rightCount = filterKeyUsageCounts.get(right) || 0;
    const leftCount = filterKeyUsageCounts.get(left) || 0;
    if (rightCount !== leftCount) {
      return rightCount - leftCount;
    }
    return left.localeCompare(right);
  });
}

async function refreshFilterAutocompleteOptions() {
  const autocompleteListEl = getCachedElement("filterStr-autocomplete");
  if (!autocompleteListEl) return;

  autocompleteListEl.replaceChildren();
  if (!validKeysCache.length) return;

  const cursor = typeof filterInputEl.selectionStart === "number"
    ? filterInputEl.selectionStart
    : filterInputEl.value.length;
  const autocompleteContext = getFilterAutocompleteContext(filterInputEl.value, cursor);
  if (!autocompleteContext) {
    return;
  }

  if (autocompleteContext.mode === "key") {
    const matchingKeys = autocompleteContext.typedPrefixLower
      ? validKeysCache.filter((key) =>
        key.toLowerCase().startsWith(autocompleteContext.typedPrefixLower),
      )
      : [...validKeysCache];
    const candidates = rankFilterKeysByUsage(matchingKeys)
      .slice(0, FILTER_AUTOCOMPLETE_MAX_SUGGESTIONS);

    candidates.forEach((key) => {
      const optionEl = document.createElement("option");
      optionEl.value = `${key}:`;
      autocompleteListEl.appendChild(optionEl);
    });
    return;
  }

  const valueCandidates = await getTopValueSuggestionsForFilterKey(
    autocompleteContext.filterKey,
    autocompleteContext.typedPrefix,
  );
  const prefix = autocompleteContext.query.slice(0, autocompleteContext.valueStart);
  const suffix = autocompleteContext.query.slice(autocompleteContext.valueEnd);
  valueCandidates.forEach((value) => {
    const optionEl = document.createElement("option");
    optionEl.value = `${prefix}${value}${suffix}`;
    autocompleteListEl.appendChild(optionEl);
  });
}

async function applyTabFilterKeyAutocomplete() {
  if (!validKeysCache.length) return false;

  const cursor = typeof filterInputEl.selectionStart === "number"
    ? filterInputEl.selectionStart
    : filterInputEl.value.length;
  const autocompleteContext = getFilterAutocompleteContext(filterInputEl.value, cursor);
  if (!autocompleteContext) return false;

  let updatedQuery = filterInputEl.value;
  let caretPosition = cursor;

  if (autocompleteContext.mode === "key") {
    const matchingKeys = rankFilterKeysByUsage(
      validKeysCache.filter((key) =>
        key.toLowerCase().startsWith(autocompleteContext.typedPrefixLower),
      ),
    );
    if (!matchingKeys.length) return false;

    const exactMatch = matchingKeys.find(
      (key) => key.toLowerCase() === autocompleteContext.typedPrefixLower,
    );
    const selectedKey = exactMatch || matchingKeys[0];
    const replacement = autocompleteContext.hasColon ? selectedKey : `${selectedKey}:`;
    updatedQuery =
      autocompleteContext.query.slice(0, autocompleteContext.keyStart) +
      replacement +
      autocompleteContext.query.slice(autocompleteContext.keyEnd);
    caretPosition = autocompleteContext.keyStart + replacement.length;
  } else {
    const valueCandidates = await getTopValueSuggestionsForFilterKey(
      autocompleteContext.filterKey,
      autocompleteContext.typedPrefix,
    );
    if (!valueCandidates.length) return false;

    const exactValue = valueCandidates.find(
      (value) => value.toLowerCase() === autocompleteContext.typedPrefixLower,
    );
    const selectedValue = exactValue || valueCandidates[0];
    updatedQuery =
      autocompleteContext.query.slice(0, autocompleteContext.valueStart) +
      selectedValue +
      autocompleteContext.query.slice(autocompleteContext.valueEnd);
    caretPosition = autocompleteContext.valueStart + selectedValue.length;
  }

  filterInputEl.value = updatedQuery;
  filterInputEl.setSelectionRange(caretPosition, caretPosition);
  syncFilterHighlight();
  void refreshFilterAutocompleteOptions();
  return true;
}

const SESSION_FILE_SCHEMA_VERSION = 1;
const PACKETSNITCH_VERSION = String(psVer || "").trim() || "unknown";
const SESSION_CAPTURE_KEY = "capture.data";
const SESSION_STATE_KEY = "session.state";
const MAIN_TAB_SUMMARY = "summary";
const MAIN_TAB_DATA = "data";
const MAIN_TAB_STATS = "stats";
const MAIN_TAB_LIST = "list";
const MAIN_TAB_NOTES = "notes";
const MAIN_TAB_SETTINGS = "settings";
const MAIN_TAB_DATA_TOOLS = "data-tools";
const MAIN_TAB_CRYPT = "crypt";
const MAIN_TAB_KEYSTORE = "keystore";
const NOTE_DEFAULT_COLOR = "#4caf50";
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
const PACKET_KEY_SEPARATOR = "$";

let capturedPackets = {};
let jsonCapture = "";
let currentIp;
const status = getCachedElement("status");
let hostsList = [DUMMY_ALL_HOST];
const hostFilterEl = getCachedElement("host_filter");
let p = [];
let index = 0;
let activePacketCursor = 0;
let retransmissionList = [];
let outOfOrderList = [];
let activeBookmark = {};
let isFileLoaded = false;
let isCaptureStoreBackedCapture = false;
let streamProtocol = null;
let filteredPackets;
let currentPacketKey;
let dataTypesOverridePacketKey = null;
let summaryFromSavedSession = false;
let lastFilteredNavigationLogMessage = "";
let startTime;
let helpWin = null;
let llmSummaryTimeout = null;
let summary = "";
let analysisBlubHistory = [];
// Context-scoped compacted analysis summaries. Each entry represents a distinct
// analysis context (e.g. a packet stream or Data Tools workspace) so the summary
// panel can show multiple, additive, in-depth summaries in chronological order.
let compactedAnalysisSummaries = [];
let analysisCompactionInProgress = false;
const packetStubByKey = new Map();
const hydratedPacketCache = new Map();
const streamPacketHydrationCache = new Map();
const streamPayloadHexCache = new Map();
let packetNavigationCacheVersion = 0;
let allHostsNavigationPacketsCache = null;
const hostNavigationPacketsCache = new Map();
let bookmarkedNavigationPacketsCache = null;
let totalPacketCountCache = null;
const HYDRATED_PACKET_CACHE_LIMIT = 8;
const STREAM_PAYLOAD_HEX_CACHE_LIMIT = 64;
const PACKET_STUB_INDEX_MAX = 200000;
let notesPanelInitialized = false;
let notesWorkspaceFragmentPromise = null;
const filterInputEl = getCachedElement("filterStr");
const filterHighlightEl = getCachedElement("filterStr-highlight");
const filterClearButtonEl = getCachedElement("filterStr-clear");
const filterHistorySelectEl = getCachedElement("filter-history-select");
const FILTER_DROPDOWN_OPTION_PREFIX_SAVED = "saved:";
const FILTER_DROPDOWN_OPTION_PREFIX_SESSION = "session:";
const filterHistory = [];
const savedFilterLibrary = [];
const dataToolsHistorySelectEl = getCachedElement("data-tools-history-select");
const dataToolsInputHistory = [];
const DATA_TOOLS_INPUT_HISTORY_LIMIT = 10;
const DATA_TOOLS_OUTPUT_PAGE_BYTES = 8192;
const DATA_TOOLS_INPUT_DISPLAY_MAX_BYTES = 8192;
const DATA_TOOLS_HEAVY_ANALYSIS_DEFER_BYTES = 262144;
const DATA_TOOLS_TEXT_INSPECTION_MAX_BYTES = 65536;
const DATA_TOOLS_INPUT_TEXT_SAMPLE_MAX_CHARS = 65536;
const DATA_TOOLS_CONVERTED_OUTPUT_IDS = [
  "data-tools-hex-output",
  "data-tools-binary-output",
  "data-tools-decimal-output",
  "data-tools-decimal-integer-output",
  "data-tools-ascii-output",
  "data-tools-base64-output",
];
let dataToolsCommittedInputValue = "";
let dataToolsCommittedInputFormat = "hex";
let dataToolsLastConversionBytes = new Uint8Array();
let dataToolsOriginalInputBytes = null;
let dataToolsInputEditedFlag = false;
let dataToolsContextPacket = null;
let dataToolsDecodeUseRawConvInputOverride = false;
let dataToolsLastRenderedOutputBytes = 0;
let dataToolsLastConversionDisplay = {
  decimalInteger: "",
};
let dataToolsManualCarveResult = null;
// Tracks which converted output panes have already had their expensive text built.
const dataToolsRenderedOutputPanes = new Set();
const CONTEXT_IPV4_REGEX =
  /\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/;
const STRICT_IPV4_REGEX =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const CONTEXT_MAC_REGEX = /\b([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}\b/;
const CONTEXT_MIME_REGEX =
  /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i;
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

function isLikelyIpAddress(value) {
  const rawValue = String(value || "").trim();
  if (!rawValue) return false;
  if (rawValue.includes(":")) {
    return /^[0-9a-fA-F:]+$/.test(rawValue);
  }
  return STRICT_IPV4_REGEX.test(rawValue);
}

function extractIpv6EndpointParts(value) {
  const rawValue = String(value || "").trim();
  if (!rawValue) return null;

  const bracketedMatch = rawValue.match(/^\[([^\]]+)\]:(\d{1,5})$/);
  if (bracketedMatch && isLikelyIpAddress(bracketedMatch[1])) {
    return {
      host: bracketedMatch[1],
      port: bracketedMatch[2],
    };
  }

  const compressedMatch = rawValue.match(/^(.*::[0-9A-Fa-f]+):(\d{1,5})$/);
  if (
    compressedMatch &&
    !compressedMatch[1].endsWith(":") &&
    isLikelyIpAddress(compressedMatch[1])
  ) {
    return {
      host: compressedMatch[1],
      port: compressedMatch[2],
    };
  }

  return null;
}

function formatNetworkEndpointDisplay(ip, port) {
  const normalizedIp = String(ip || "").trim();
  const normalizedPort = String(port ?? "").trim();
  if (!normalizedPort) return normalizedIp;
  if (normalizedIp.includes(":") && !/^\[[^\]]+\]$/.test(normalizedIp)) {
    return `[${normalizedIp}]:${normalizedPort}`;
  }
  return `${normalizedIp}:${normalizedPort}`;
}

const SETTINGS_SUBTAB_GENERAL = "general";
const SETTINGS_SUBTAB_LLM = "llm";
const SETTINGS_SUBTAB_API_KEYS = "api-keys";
const SETTINGS_SUBTAB_BACKEND = "backend";
const SETTINGS_SUBTAB_DEBUG = "debug";
const SETTINGS_SUBTAB_PLUGINS = "plugins";
const SETTINGS_SUBTAB_THEMES = "themes";
const SETTINGS_SUBTAB_PRIVACY = "privacy";
const SETTINGS_SUBTAB_ABOUT = "about";
const PACKETSNITCH_RELEASES_PAGE_URL =
  "https://github.com/oxasploits/PacketSnitch/releases";
const PACKETSNITCH_RELEASES_LATEST_API_URL =
  "https://api.github.com/repos/oxasploits/PacketSnitch/releases/latest";
let notesEditorVisible = false;
let currentSessionName = null;
let sessionPickerPanel = null;
let lastBackendLoadRequest = null;
let notesList = [];
let selectedNoteId = null;
let noteIdCounter = 0;
const LLM_MAX_CONTENT_LENGTH = 180000;
const SESSION_AUTOSAVE_INTERVAL_MS = 5 * 60 * 1000;
let backendCaptureUpdateQueue = Promise.resolve();
let pendingBackendCaptureUpdate = null;
let backendCaptureUpdateDrainActive = false;
let backendLastAppliedSnapshotProcessedPackets = 0;
let backendLastAppliedSnapshotAtMs = 0;
const ingestionChunkLogState = new Map();
const deferredIngestionBacklogState = {
  active: false,
  deferredCount: 0,
  lastDeferredAtMs: 0,
};
let captureIngestWorkers = [];
let captureIngestWorkerThreadCount = 0;
let captureIngestWorkerCursor = 0;
let captureIngestWorkerRequestId = 0;
const pendingCaptureIngestWorkerRequests = new Map();
let sessionAutosaveInFlight = false;
let appSettings = cloneDefaultSettings();
let statusResetTimeoutId = null;
let keystorePanel = null;
const PACKETSNITCH_AUTHOR_NAME = "Marshall Whittaker / oxagast";
const PACKETSNITCH_TERMINAL_IDENTITY = "marshall@oxasploits";
let activeSettingsSubtab = SETTINGS_SUBTAB_GENERAL;
const FALLBACK_THEME_ID = "snitchbitch";
let availableThemes = [];
let availableOllamaModels = [];
let defaultThemeLogoSrc = null;
let appliedThemeVariableNames = new Set();
let keystoreAutoPopulateGeneration = 0;
let lastLLMSummaryPacketKey = null;
let alreadySummarizedPacketKeys = new Set();
let ollamaVersionCheckPassed = false;
let cachedLlmDiagnostics = null;
let startupWindowLoaded = false;
let startupSettingsInitialized = false;
let startupPreloadHidden = false;
let startupPreloadShownAtMs = Date.now();
let startupPreloadHideStartTimeoutId = null;
let cachedBackendDiagnostics = null;
let cachedVirusTotalDiagnostics = null;
let virusTotalDiagnosticsInFlight = null;
let virusTotalDiagnosticsLastSuccessAt = 0;
const VIRUS_TOTAL_DIAGNOSTICS_DEDUPE_MS = 30_000;
let cachedMetricsDiagnostics = null;
let metricsDiagnosticsInFlight = null;
let metricsDiagnosticsLastSuccessAt = 0;
const METRICS_DIAGNOSTICS_DEDUPE_MS = 30_000;
let cachedSettingsAboutReleaseInfo = null;
let settingsAboutReleaseInfoLoadPromise = null;
let settingsAboutTypewriterToken = 0;
let settingsAboutTypewriterTimeoutId = null;
let settingsAboutDownloadButtonUrl = "";
let cachedPluginRegistry = [];
let pluginErrorEntries = [];
const loadedPluginIds = new Set();
let selectedPluginId = "";
let activePluginInstallCapabilityDialogResolver = null;
let cachedLinuxReleasePackageFamily = null;
let cachedRuntimePlatform = "";
let startupReleaseCheckHandled = false;
let resolveStartupReleaseCheckPromise = null;
let startupReleaseCheckPromise = new Promise((resolve) => {
  resolveStartupReleaseCheckPromise = resolve;
});
window.__PACKETSNITCH_STARTUP_RELEASE_CHECK_PROMISE__ = startupReleaseCheckPromise;
const backendProgressState = {
  firstChunkLoaded: false,
  processing: false,
  processedPackets: 0,
  totalPackets: 0,
  lastReportedPercent: -1,
  etaLastSampleAtMs: 0,
  etaLastSampleProcessedPackets: 0,
  etaPacketsPerSecond: 0,
};
let activeBackendJobId = "";
let sessionPcapSource = null;

// ============================================================================
// Settings, diagnostics, and backend option helpers
// ============================================================================

// Returns current settings.
function getCurrentSettings() {
  return appSettings;
}

// Invalidates packet-navigation derived caches.
function invalidatePacketNavigationCaches() {
  allHostsNavigationPacketsCache = null;
  hostNavigationPacketsCache.clear();
  bookmarkedNavigationPacketsCache = null;
  totalPacketCountCache = null;
}

// Bumps navigation cache version after capture mutations.
function bumpPacketNavigationCacheVersion() {
  packetNavigationCacheVersion += 1;
  invalidatePacketNavigationCaches();
}

// Sets current settings.
function setCurrentSettings(nextSettings) {
  appSettings = normalizeSettings(nextSettings);
  // Push a synchronous snapshot of the settings into the metrics
  // service. ``window.settingsapi.get`` is async, but ``metrics.track``
  // and friends have to gate on the privacy block synchronously,
  // so we keep a local copy. Centralising the push here means
  // every code path that mutates the in-memory state also keeps
  // the metrics layer in lockstep.
  if (metrics && typeof metrics.setSettingsSnapshot === "function") {
    try {
      metrics.setSettingsSnapshot(appSettings);
    } catch (_error) {
      // ignore: metrics is a best-effort, non-essential service
    }
  }
  return appSettings;
}

// Returns whether llm enabled in settings.
function isLlmEnabledInSettings() {
  return Boolean(getCurrentSettings()?.llm?.activeByDefault);
}

// Returns whether background summary generation enabled.
function isBackgroundSummaryGenerationEnabled() {
  const llmSettings = getCurrentSettings()?.llm || {};
  return llmSettings.backgroundSummaryGenerationEnabled !== false;
}

// Returns the configured number of analysis blurbs before the LLM compacts them.
function getAnalysisCompactionThresholdBlubs() {
  const llmSettings = getCurrentSettings()?.llm || {};
  const threshold = Number(llmSettings.analysisCompactionThresholdBlubs);
  if (!Number.isFinite(threshold) || threshold < 1) {
    return DEFAULT_SETTINGS.llm.analysisCompactionThresholdBlubs;
  }
  return Math.floor(threshold);
}

// Returns whether llm runtime enabled.
function isLlmRuntimeEnabled() {
  return isLlmEnabledInSettings() && ollamaVersionCheckPassed;
}

async function refreshOllamaStartupAvailability() {
  if (!window.installapi || typeof window.installapi.getLlmDiagnostics !== "function") {
    ollamaVersionCheckPassed = false;
    cachedLlmDiagnostics = null;
    return ollamaVersionCheckPassed;
  }
  try {
    const diagnostics = await window.installapi.getLlmDiagnostics();
    cachedLlmDiagnostics = diagnostics || null;
    ollamaVersionCheckPassed = Boolean(
      diagnostics?.ollamaInstalled && diagnostics?.ollamaServerListening,
    );
    syncLlmDiagnosticsIndicators();
  } catch (error) {
    console.warn("Unable to resolve Ollama startup availability:", error);
    ollamaVersionCheckPassed = false;
    cachedLlmDiagnostics = null;
    syncLlmDiagnosticsIndicators();
  }
  // Re-render the Session Threat Score card so the LLM "Get Assessment"
  // button enables/disables to track Ollama availability.
  if (typeof subnetCalculatorPanel?.recomputeSessionThreatScore === "function") {
    subnetCalculatorPanel.recomputeSessionThreatScore({ silent: true });
  }
  return ollamaVersionCheckPassed;
}

// Returns llm diagnostic element.
function getLlmDiagnosticElement(id) {
  return document.getElementById(id);
}

// Renders llm diagnostic indicator.
function renderLlmDiagnosticIndicator(elementId, label, value, stateClass) {
  const element = getLlmDiagnosticElement(elementId);
  if (!element) return;
  element.textContent = `${label}: ${value}`;
  element.className = `settings-status-pill ${stateClass}`;
}

// Syncs llm diagnostics indicators.
function syncLlmDiagnosticsIndicators() {
  const diagnostics = cachedLlmDiagnostics;
  renderLlmDiagnosticIndicator(
    "settings-llm-installed-status",
    "Installed",
    diagnostics?.ollamaInstalled ? "Yes" : "No",
    diagnostics?.ollamaInstalled ? "status-ok" : "status-error",
  );
  renderLlmDiagnosticIndicator(
    "settings-llm-online-status",
    "Online",
    diagnostics?.ollamaServerListening ? "Yes" : "No",
    diagnostics?.ollamaServerListening ? "status-ok" : "status-error",
  );

  const cloudResultCode = diagnostics?.cloudApiResultCode;
  renderLlmDiagnosticIndicator(
    "settings-llm-cloud-status",
    "Cloud API",
    cloudResultCode === null || typeof cloudResultCode === "undefined"
      ? "—"
      : String(cloudResultCode),
    cloudResultCode === 0
      ? "status-ok"
      : cloudResultCode === null || typeof cloudResultCode === "undefined"
        ? "status-neutral"
        : "status-warn",
  );

  const lastResultCode = diagnostics?.lastCallResultCode;
  renderLlmDiagnosticIndicator(
    "settings-llm-last-result-status",
    "Last call result",
    lastResultCode === null || typeof lastResultCode === "undefined" ? "—" : String(lastResultCode),
    lastResultCode === 0 ? "status-ok" : lastResultCode === null || typeof lastResultCode === "undefined" ? "status-neutral" : "status-warn",
  );

  // Mirror the same indicators in the API Keys panel so the pills light up
  // regardless of which subtab the user is currently looking at.
  renderLlmDiagnosticIndicator(
    "settings-api-keys-llm-installed-status",
    "Installed",
    diagnostics?.ollamaInstalled ? "Yes" : "No",
    diagnostics?.ollamaInstalled ? "status-ok" : "status-error",
  );
  renderLlmDiagnosticIndicator(
    "settings-api-keys-llm-online-status",
    "Online",
    diagnostics?.ollamaServerListening ? "Yes" : "No",
    diagnostics?.ollamaServerListening ? "status-ok" : "status-error",
  );
  renderLlmDiagnosticIndicator(
    "settings-api-keys-llm-cloud-status",
    "Cloud API",
    cloudResultCode === null || typeof cloudResultCode === "undefined"
      ? "—"
      : String(cloudResultCode),
    cloudResultCode === 0
      ? "status-ok"
      : cloudResultCode === null || typeof cloudResultCode === "undefined"
        ? "status-neutral"
        : "status-warn",
  );
  renderLlmDiagnosticIndicator(
    "settings-api-keys-llm-last-result-status",
    "Last call result",
    lastResultCode === null || typeof lastResultCode === "undefined" ? "—" : String(lastResultCode),
    lastResultCode === 0 ? "status-ok" : lastResultCode === null || typeof lastResultCode === "undefined" ? "status-neutral" : "status-warn",
  );
}

// Returns metrics diagnostic element.
function getMetricsDiagnosticElement(id) {
  return document.getElementById(id);
}

// Renders metrics diagnostic indicator.
function renderMetricsDiagnosticIndicator(elementId, label, value, stateClass) {
  const element = getMetricsDiagnosticElement(elementId);
  if (!element) return;
  element.textContent = `${label}: ${value}`;
  element.className = `settings-status-pill ${stateClass}`;
}

// Syncs metrics diagnostics indicators.
function syncMetricsDiagnosticsIndicators() {
  const diagnostics = cachedMetricsDiagnostics || {};
  const privacySettings = getCurrentSettings()?.privacy || {};
  const endpointConfigured = Boolean(
    String(privacySettings.metricsEndpointUrl || "").trim(),
  );
  const endpointReachable = diagnostics.endpointReachable;

  let endpointValue = "—";
  let endpointClass = "status-neutral";
  if (!endpointConfigured) {
    endpointValue = "Not configured";
    endpointClass = "status-warn";
  } else if (endpointReachable === true) {
    endpointValue = "Up";
    endpointClass = "status-ok";
  } else if (endpointReachable === false) {
    endpointValue = "Down";
    endpointClass = "status-error";
  } else {
    endpointValue = "Unknown";
    endpointClass = "status-neutral";
  }
  renderMetricsDiagnosticIndicator(
    "settings-api-keys-metrics-endpoint-status",
    "Endpoint",
    endpointValue,
    endpointClass,
  );

  let consentValue = "—";
  let consentClass = "status-neutral";
  if (typeof diagnostics.consentStatus === "string" && diagnostics.consentStatus) {
    if (diagnostics.consentStatus === "first-run") {
      consentValue = "Not asked";
      consentClass = "status-warn";
    } else if (diagnostics.consentStatus === "enabled") {
      consentValue = "Granted";
      consentClass = "status-ok";
    } else if (diagnostics.consentStatus === "disabled") {
      consentValue = "Declined";
      consentClass = "status-neutral";
    } else {
      consentValue = diagnostics.consentStatus;
    }
  }
  renderMetricsDiagnosticIndicator(
    "settings-api-keys-metrics-consent-status",
    "Consent",
    consentValue,
    consentClass,
  );

  // TLS pill: shows whether the metrics transport will skip cert
  // verification for HTTPS endpoints (the production catalog server
  // uses a self-signed cert). Mirrors the ``allowInsecureTlsEndpoints``
  // flag in src/settings.js which is locked to true.
  let tlsValue = "—";
  let tlsClass = "status-neutral";
  const endpointProtocol = String(diagnostics.endpointProtocol || "").trim();
  if (!endpointConfigured) {
    tlsValue = "n/a";
    tlsClass = "status-neutral";
  } else if (endpointProtocol === "https:") {
    if (diagnostics.insecureTls) {
      tlsValue = "Self-signed allowed";
      tlsClass = "status-ok";
    } else if (diagnostics.allowInsecureTls === false) {
      tlsValue = "Strict";
      tlsClass = "status-warn";
    } else {
      tlsValue = "Unknown";
      tlsClass = "status-neutral";
    }
  } else if (endpointProtocol === "http:") {
    tlsValue = "Plain HTTP";
    tlsClass = "status-neutral";
  }
  renderMetricsDiagnosticIndicator(
    "settings-api-keys-metrics-tls-status",
    "TLS",
    tlsValue,
    tlsClass,
  );

  const lastFlush = diagnostics.lastFlush;
  let lastFlushValue = "—";
  let lastFlushClass = "status-neutral";
  if (lastFlush && typeof lastFlush === "object") {
    if (lastFlush.ok === true) {
      lastFlushValue = `OK (${lastFlush.sent || 0})`;
      lastFlushClass = "status-ok";
    } else if (lastFlush.ok === false) {
      lastFlushValue = lastFlush.reason
        ? `Failed (${lastFlush.reason})`
        : "Failed";
      lastFlushClass = "status-error";
    } else if (lastFlush.checkedAt) {
      lastFlushValue = `Checked ${formatRelativeTimestamp(lastFlush.checkedAt)}`;
      lastFlushClass = "status-neutral";
    }
  } else if (typeof lastFlush === "string") {
    lastFlushValue = lastFlush;
  }
  renderMetricsDiagnosticIndicator(
    "settings-api-keys-metrics-last-flush-status",
    "Last flush",
    lastFlushValue,
    lastFlushClass,
  );
}

function formatRelativeTimestamp(isoString) {
  if (!isoString) return "";
  const ts = Date.parse(isoString);
  if (Number.isNaN(ts)) return isoString;
  const deltaSec = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (deltaSec < 60) return `${deltaSec}s ago`;
  if (deltaSec < 3600) return `${Math.round(deltaSec / 60)}m ago`;
  if (deltaSec < 86400) return `${Math.round(deltaSec / 3600)}h ago`;
  return `${Math.round(deltaSec / 86400)}d ago`;
}

// Refreshes metrics diagnostics by probing the configured endpoint.
async function refreshMetricsDiagnostics({ force = false } = {}) {
  if (!window.metricsapi || typeof window.metricsapi.getStatus !== "function") {
    cachedMetricsDiagnostics = null;
    syncMetricsDiagnosticsIndicators();
    return null;
  }
  if (!force && metricsDiagnosticsInFlight) {
    return metricsDiagnosticsInFlight;
  }
  if (
    !force
    && cachedMetricsDiagnostics
    && Date.now() - metricsDiagnosticsLastSuccessAt < METRICS_DIAGNOSTICS_DEDUPE_MS
  ) {
    return cachedMetricsDiagnostics;
  }
  metricsDiagnosticsInFlight = (async () => {
    try {
      const status = await window.metricsapi.getStatus();
      const privacySettings = getCurrentSettings()?.privacy || {};
      const consentStatus = window.__PACKETSNITCH_METRICS__
        && typeof window.__PACKETSNITCH_METRICS__.getConsentStatus === "function"
        ? window.__PACKETSNITCH_METRICS__.getConsentStatus()
        : null;
      let endpointReachable = null;
      const endpoint = String(privacySettings.metricsEndpointUrl || status?.endpoint || "").trim();
      if (endpoint && privacySettings.metricsEnabled) {
        try {
          const flushResult = await window.metricsapi.flush({
            installId: status?.installId || privacySettings.metricsInstallId || "",
            appVersion: status?.appVersion || "",
            sentAt: new Date().toISOString(),
            events: [],
          });
          endpointReachable = Boolean(
            flushResult && flushResult.ok === true && flushResult.reason !== "no-events",
          );
          // Treat an empty-events successful response as a connectivity OK.
          if (flushResult && flushResult.ok === true) {
            endpointReachable = true;
          }
        } catch (_error) {
          endpointReachable = false;
        }
      }
      cachedMetricsDiagnostics = {
        consentStatus,
        endpointReachable,
        endpointProtocol: String(status?.endpointProtocol || "").trim(),
        insecureTls: Boolean(status?.insecureTls),
        allowInsecureTls: Boolean(status?.allowInsecureTls),
        lastFlush: {
          checkedAt: new Date().toISOString(),
          ok: endpointReachable === true,
          reason: endpointReachable === false ? "probe-failed" : null,
          sent: 0,
        },
      };
      metricsDiagnosticsLastSuccessAt = Date.now();
    } catch (error) {
      console.warn("Unable to resolve Metrics diagnostics:", error);
      cachedMetricsDiagnostics = {
        consentStatus: null,
        endpointReachable: false,
        lastFlush: {
          checkedAt: new Date().toISOString(),
          ok: false,
          reason: "probe-failed",
        },
      };
    } finally {
      metricsDiagnosticsInFlight = null;
    }
    syncMetricsDiagnosticsIndicators();
    return cachedMetricsDiagnostics;
  })();
  return metricsDiagnosticsInFlight;
}

// Returns backend diagnostic element.
function getBackendDiagnosticElement(id) {
  return document.getElementById(id);
}

// Renders backend diagnostic indicator.
function renderBackendDiagnosticIndicator(elementId, label, value, stateClass) {
  const element = getBackendDiagnosticElement(elementId);
  if (!element) return;
  element.textContent = `${label}: ${value}`;
  element.className = `settings-status-pill ${stateClass}`;
}

function getBackendVirusTotalApiKey(settings = getCurrentSettings()) {
  return String(settings?.apiKeys?.virusTotalApiKey || "").trim();
}

function syncVirusTotalDiagnosticsIndicators() {
  const diagnostics = cachedVirusTotalDiagnostics;
  const hasStoredKey = Boolean(getBackendVirusTotalApiKey());
  const endpointReachable = diagnostics?.endpointReachable;
  const keyConfigured = hasStoredKey || Boolean(diagnostics?.keyConfigured);
  const keyValid = diagnostics?.keyValid;

  const endpointValue =
    endpointReachable === true ? "Up" : endpointReachable === false ? "Down" : "—";
  const endpointClass =
    endpointReachable === true
      ? "status-ok"
      : endpointReachable === false
        ? "status-error"
        : "status-neutral";

  const keyValue =
    !keyConfigured
      ? "Missing"
      : keyValid === true
        ? "Valid"
        : keyValid === false
          ? "Invalid"
          : "Configured";
  const keyClass =
    !keyConfigured
      ? "status-warn"
      : keyValid === true
        ? "status-ok"
        : keyValid === false
          ? "status-error"
          : "status-neutral";

  renderBackendDiagnosticIndicator(
    "settings-backend-virustotal-endpoint-status",
    "VirusTotal Endpoint",
    endpointValue,
    endpointClass,
  );
  renderBackendDiagnosticIndicator(
    "settings-backend-virustotal-key-status",
    "VirusTotal Key",
    keyValue,
    keyClass,
  );
}

// Syncs backend diagnostics indicators.
function syncBackendDiagnosticsIndicators() {
  const diagnostics = cachedBackendDiagnostics;
  const forceLegacySpawn = Boolean(diagnostics?.forceLegacySpawn);
  const processRunning = Boolean(diagnostics?.backendProcessRunning);
  const webserverUp = Boolean(diagnostics?.backendWebserverUp);
  const backendVersion =
    typeof diagnostics?.backendVersion === "string" && diagnostics.backendVersion.trim()
      ? diagnostics.backendVersion.trim()
      : "—";

  renderBackendDiagnosticIndicator(
    "settings-backend-process-status",
    "Process",
    processRunning ? "Running" : "Down",
    processRunning ? "status-ok" : "status-error",
  );
  renderBackendDiagnosticIndicator(
    "settings-backend-webserver-status",
    "Webserver",
    forceLegacySpawn ? "Legacy mode" : webserverUp ? "Up" : "Down",
    forceLegacySpawn ? "status-warn" : webserverUp ? "status-ok" : "status-error",
  );
  renderBackendDiagnosticIndicator(
    "settings-backend-version-status",
    "Version",
    backendVersion,
    backendVersion !== "—" ? "status-ok" : forceLegacySpawn ? "status-warn" : "status-error",
  );
  renderBackendDiagnosticIndicator(
    "settings-backend-mode-status",
    "Mode",
    forceLegacySpawn ? "Legacy spawn" : "HTTP service",
    forceLegacySpawn ? "status-warn" : "status-ok",
  );
  syncVirusTotalDiagnosticsIndicators();
}

async function refreshVirusTotalDiagnostics({ force = false } = {}) {
  if (!window.snitchapi || typeof window.snitchapi.lookupVirusTotal !== "function") {
    cachedVirusTotalDiagnostics = null;
    syncVirusTotalDiagnosticsIndicators();
    return null;
  }

  // Coalesce concurrent callers so a startup burst (eager + loadPersistedSettings
  // + backend-service-ready) only hits the VirusTotal API once. Also skip the
  // probe entirely when a recent successful diagnostic is still fresh.
  if (!force) {
    if (virusTotalDiagnosticsInFlight) {
      return virusTotalDiagnosticsInFlight;
    }
    if (
      cachedVirusTotalDiagnostics &&
      cachedVirusTotalDiagnostics.endpointReachable !== false &&
      Date.now() - virusTotalDiagnosticsLastSuccessAt < VIRUS_TOTAL_DIAGNOSTICS_DEDUPE_MS
    ) {
      return cachedVirusTotalDiagnostics;
    }
  }

  const apiKey = getBackendVirusTotalApiKey();
  virusTotalDiagnosticsInFlight = (async () => {
    try {
      const diagnostics = await window.snitchapi.lookupVirusTotal("8.8.8.8", {
        lookupType: "ip",
        apiKey,
        diagnosticOnly: true,
        backendOptions: getBackendTransportOptionsFromSettings(),
      });
      cachedVirusTotalDiagnostics = diagnostics || null;
      if (cachedVirusTotalDiagnostics) {
        virusTotalDiagnosticsLastSuccessAt = Date.now();
      }
    } catch (error) {
      console.warn("Unable to resolve VirusTotal diagnostics:", error);
      cachedVirusTotalDiagnostics = {
        endpointReachable: false,
        keyConfigured: Boolean(apiKey),
        keyValid: false,
        error: error?.message || String(error),
      };
    } finally {
      virusTotalDiagnosticsInFlight = null;
    }
    syncVirusTotalDiagnosticsIndicators();
    return cachedVirusTotalDiagnostics;
  })();

  return virusTotalDiagnosticsInFlight;
}

// Clears the cached VirusTotal diagnostics so the next refresh re-probes the
// API. Used when settings (e.g. API key) change and a stale result must not
// mask the new configuration.
function invalidateVirusTotalDiagnosticsCache() {
  virusTotalDiagnosticsLastSuccessAt = 0;
  cachedVirusTotalDiagnostics = null;
  syncVirusTotalDiagnosticsIndicators();
}

async function refreshBackendDiagnostics({ ensureReady = false } = {}) {
  if (!window.snitchapi || typeof window.snitchapi.getBackendDiagnostics !== "function") {
    cachedBackendDiagnostics = null;
    syncBackendDiagnosticsIndicators();
    return null;
  }

  try {
    const diagnostics = await window.snitchapi.getBackendDiagnostics({
      ensureReady: Boolean(ensureReady),
      backendOptions: getBackendTransportOptionsFromSettings(),
    });
    cachedBackendDiagnostics = diagnostics || null;
  } catch (error) {
    console.warn("Unable to resolve backend diagnostics:", error);
    cachedBackendDiagnostics = null;
  }
  syncBackendDiagnosticsIndicators();
  await refreshVirusTotalDiagnostics();
  return cachedBackendDiagnostics;
}

function normalizeReleaseVersionToken(value) {
  if (typeof value !== "string") return "";
  return value
    .trim()
    .toLowerCase()
    .replace(/^v+/, "")
    .replace(/^packetsnitch[-_\s]*/i, "");
}

function getReleaseVersionToken(release) {
  if (!release || typeof release !== "object") return "";
  const candidateValues = [release.tag_name, release.name];
  for (const candidate of candidateValues) {
    if (typeof candidate === "string" && candidate.trim()) {
      const normalized = normalizeReleaseVersionToken(candidate);
      if (normalized) return normalized;
    }
  }
  return "";
}

function compareReleaseVersionTokens(leftValue, rightValue) {
  const leftToken = normalizeReleaseVersionToken(leftValue);
  const rightToken = normalizeReleaseVersionToken(rightValue);
  const leftParts = leftToken.match(/\d+|[a-z]+/g) || [];
  const rightParts = rightToken.match(/\d+|[a-z]+/g) || [];
  const maxLength = Math.max(leftParts.length, rightParts.length);

  for (let index = 0; index < maxLength; index += 1) {
    const leftPart = leftParts[index];
    const rightPart = rightParts[index];
    if (typeof leftPart === "undefined" && typeof rightPart === "undefined") {
      return 0;
    }
    if (typeof leftPart === "undefined") {
      return -1;
    }
    if (typeof rightPart === "undefined") {
      return 1;
    }

    const leftIsNumber = /^\d+$/.test(leftPart);
    const rightIsNumber = /^\d+$/.test(rightPart);
    if (leftIsNumber && rightIsNumber) {
      const numericDiff = Number.parseInt(leftPart, 10) - Number.parseInt(rightPart, 10);
      if (numericDiff !== 0) {
        return numericDiff;
      }
      continue;
    }
    if (leftIsNumber !== rightIsNumber) {
      return leftIsNumber ? 1 : -1;
    }

    const lexicalDiff = leftPart.localeCompare(rightPart);
    if (lexicalDiff !== 0) {
      return lexicalDiff;
    }
  }

  return 0;
}

async function detectLinuxReleasePackageFamily(runtimePlatform = "") {
  const normalizedRuntimePlatform = String(runtimePlatform || "").trim().toLowerCase();
  const platformName = normalizedRuntimePlatform || await detectRuntimePlatform();
  if (platformName !== "linux") {
    return "";
  }
  if (cachedLinuxReleasePackageFamily !== null) {
    return cachedLinuxReleasePackageFamily;
  }

  if (!window.browserapi || typeof window.browserapi.getLinuxReleasePackageFamily !== "function") {
    cachedLinuxReleasePackageFamily = "";
    return cachedLinuxReleasePackageFamily;
  }

  try {
    const response = await window.browserapi.getLinuxReleasePackageFamily();
    const family = typeof response?.family === "string" ? response.family.trim().toLowerCase() : "";
    cachedLinuxReleasePackageFamily = family === "debian" || family === "redhat" ? family : "";
  } catch (_error) {
    cachedLinuxReleasePackageFamily = "";
  }
  return cachedLinuxReleasePackageFamily;
}

async function detectRuntimePlatform() {
  if (cachedRuntimePlatform) {
    return cachedRuntimePlatform;
  }

  if (window.browserapi && typeof window.browserapi.getRuntimePlatform === "function") {
    try {
      const response = await window.browserapi.getRuntimePlatform();
      const runtimePlatform = typeof response?.platform === "string"
        ? response.platform.trim().toLowerCase()
        : "";
      if (runtimePlatform) {
        cachedRuntimePlatform = runtimePlatform;
        return cachedRuntimePlatform;
      }
    } catch (_error) {
      // Fall back to local process metadata below.
    }
  }

  cachedRuntimePlatform = typeof process !== "undefined" && typeof process.platform === "string"
    ? process.platform
    : "";
  return cachedRuntimePlatform;
}

function getReleaseDownloadAssetPreferences(
  platformName = (typeof process !== "undefined" ? process.platform : ""),
  linuxPackageFamily = "",
) {
  switch (platformName) {
    case "win32":
      return [".exe"];
    case "darwin":
      return [".dmg", ".pkg", ".zip"];
    case "linux": {
      if (linuxPackageFamily === "debian") {
        return [".deb", ".rpm", ".appimage", ".tar.gz", ".tgz", ".zip"];
      }
      if (linuxPackageFamily === "redhat") {
        return [".rpm", ".deb", ".appimage", ".tar.gz", ".tgz", ".zip"];
      }
      return [".deb", ".rpm", ".appimage", ".tar.gz", ".tgz", ".zip"];
    }
    default:
      return [".zip", ".tar.gz", ".tgz"];
  }
}

function selectReleaseDownloadAsset(release, { linuxPackageFamily = "", runtimePlatform = "" } = {}) {
  if (!release || typeof release !== "object") return null;
  const assets = Array.isArray(release.assets) ? release.assets : [];
  if (assets.length === 0) return null;
  const platformName = runtimePlatform
    || (typeof process !== "undefined" ? process.platform : "");
  const preferences = getReleaseDownloadAssetPreferences(platformName, linuxPackageFamily);
  const normalizedAssets = assets.filter((asset) => asset && typeof asset === "object");

  const assetMatchesSuffix = (asset, suffix) => {
    const suffixLower = String(suffix || "").toLowerCase();
    const suffixRegex = new RegExp(`${suffixLower.replace(/\./g, "\\.")}(?:$|[?#])`, "i");
    const assetName = String(asset?.name || "").trim().toLowerCase();
    const assetUrl = String(asset?.browser_download_url || "").trim().toLowerCase();
    return suffixRegex.test(assetName) || suffixRegex.test(assetUrl);
  };

  for (const preferredSuffix of preferences) {
    const matchedAsset = normalizedAssets.find((asset) => {
      return assetMatchesSuffix(asset, preferredSuffix);
    });
    if (matchedAsset?.browser_download_url) {
      return matchedAsset;
    }
  }

  // For Windows we should only offer the executable package.
  if (platformName === "win32") {
    return null;
  }

  if (platformName === "linux" && linuxPackageFamily === "redhat") {
    const bestNonDebAsset = normalizedAssets.find(
      (asset) => typeof asset.browser_download_url === "string"
        && asset.browser_download_url.trim()
        && !assetMatchesSuffix(asset, ".deb"),
    );
    if (bestNonDebAsset) {
      return bestNonDebAsset;
    }
  }

  if (platformName === "linux" && linuxPackageFamily === "debian") {
    const bestNonRpmAsset = normalizedAssets.find(
      (asset) => typeof asset.browser_download_url === "string"
        && asset.browser_download_url.trim()
        && !assetMatchesSuffix(asset, ".rpm"),
    );
    if (bestNonRpmAsset) {
      return bestNonRpmAsset;
    }
  }

  return normalizedAssets.find((asset) => typeof asset.browser_download_url === "string" && asset.browser_download_url.trim()) || null;
}

function buildReleaseDownloadInfo(
  release,
  runningVersion,
  { linuxPackageFamily = "", runtimePlatform = "" } = {},
) {
  const latestReleaseVersion = getReleaseVersionToken(release);
  const newVersionAvailable = compareReleaseVersionTokens(latestReleaseVersion, runningVersion) > 0;
  if (!newVersionAvailable) {
    return {
      newVersionAvailable: false,
      downloadUrl: "",
      downloadAssetName: "",
    };
  }

  const selectedAsset = selectReleaseDownloadAsset(release, {
    linuxPackageFamily,
    runtimePlatform,
  });
  return {
    newVersionAvailable: Boolean(selectedAsset?.browser_download_url),
    downloadUrl: typeof selectedAsset?.browser_download_url === "string"
      ? selectedAsset.browser_download_url.trim()
      : "",
    downloadAssetName: typeof selectedAsset?.name === "string" ? selectedAsset.name.trim() : "",
  };
}

function shouldCheckForNewReleasesOnStartup() {
  return Boolean(getCurrentSettings()?.general?.checkForNewReleasesOnStartup);
}

async function maybeShowSettingsAboutForNewRelease() {
  startupReleaseCheckHandled = true;
  if (!shouldCheckForNewReleasesOnStartup()) {
    if (resolveStartupReleaseCheckPromise) {
      resolveStartupReleaseCheckPromise(false);
      resolveStartupReleaseCheckPromise = null;
    }
    return false;
  }

  const releaseInfo = await loadSettingsAboutReleaseInfo({ forceRefresh: true });
  const newVersionAvailable = Boolean(releaseInfo?.downloadInfo?.newVersionAvailable);
  if (!newVersionAvailable) {
    if (resolveStartupReleaseCheckPromise) {
      resolveStartupReleaseCheckPromise(false);
      resolveStartupReleaseCheckPromise = null;
    }
    return false;
  }

  showSettingsWorkspace();
  setSettingsSubtab(SETTINGS_SUBTAB_ABOUT);
  if (resolveStartupReleaseCheckPromise) {
    resolveStartupReleaseCheckPromise(true);
    resolveStartupReleaseCheckPromise = null;
  }
  return true;
}

function syncSettingsAboutDownloadButton() {
  const downloadButtonEl = document.getElementById("settings-about-download-btn");
  if (!downloadButtonEl) return;

  const downloadUrl = settingsAboutDownloadButtonUrl || "";
  const visible = Boolean(downloadUrl);
  downloadButtonEl.hidden = !visible;
  downloadButtonEl.disabled = !visible;
  downloadButtonEl.setAttribute("aria-hidden", visible ? "false" : "true");
  downloadButtonEl.dataset.downloadUrl = downloadUrl;
  downloadButtonEl.title = visible ? "Download the latest PacketSnitch release for this OS" : "";
}

function setSettingsAboutDownloadButtonState(downloadInfo = {}) {
  settingsAboutDownloadButtonUrl =
    typeof downloadInfo.downloadUrl === "string" && downloadInfo.downloadUrl.trim()
      ? downloadInfo.downloadUrl.trim()
      : "";
  syncSettingsAboutDownloadButton();
}

async function openSettingsAboutDownloadUrl() {
  const downloadUrl = settingsAboutDownloadButtonUrl;
  if (!downloadUrl || !window.browserapi || typeof window.browserapi.openExternalUrl !== "function") {
    return;
  }

  try {
    await window.browserapi.openExternalUrl(downloadUrl);
  } catch (error) {
    console.warn("Unable to open PacketSnitch release download URL:", error);
  }
}

function normalizeReleaseNotesForTerminal(bodyText) {
  if (typeof bodyText !== "string" || !bodyText.trim()) {
    return "No release notes were provided for this release.";
  }
  const normalizedNewlines = bodyText.replace(/\r\n/g, "\n");

  // Strip HTML tags/content wrappers (e.g. <img ...>, <a ...>, <br>) from release text.
  let plainText = normalizedNewlines.replace(/<[^>]*>/g, " ");

  // Remove fenced code blocks and inline code markers.
  plainText = plainText.replace(/```[\s\S]*?```/g, " ");
  plainText = plainText.replace(/`([^`]+)`/g, "$1");

  // Convert common markdown links/images to plain text.
  plainText = plainText.replace(/!\[[^\]]*\]\([^\)]*\)/g, " ");
  plainText = plainText.replace(/\[([^\]]+)\]\(([^\)]+)\)/g, "$1");

  // Remove markdown heading/quote/list markers and emphasis syntax.
  plainText = plainText.replace(/^\s{0,3}#{1,6}\s*/gm, "");
  plainText = plainText.replace(/^\s{0,3}>\s?/gm, "");
  plainText = plainText.replace(/^\s*[-*+]\s+/gm, "");
  plainText = plainText.replace(/^\s*\d+\.\s+/gm, "");
  plainText = plainText.replace(/\*\*([^*]+)\*\*/g, "$1");
  plainText = plainText.replace(/__([^_]+)__/g, "$1");
  plainText = plainText.replace(/\*([^*]+)\*/g, "$1");
  plainText = plainText.replace(/_([^_]+)_/g, "$1");
  plainText = plainText.replace(/~~([^~]+)~~/g, "$1");
  plainText = plainText.replace(/^\s*[-*_]{3,}\s*$/gm, "");

  // Normalize whitespace for terminal display.
  plainText = plainText
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim();

  return plainText || "No release notes were provided for this release.";
}

function buildSettingsAboutTerminalReadout({
  runningVersion,
  latestReleaseVersion,
  latestReleaseNotes,
  latestReleaseUrl,
  fetchError = "",
}) {
  const lines = [];
  lines.push("                          _       _ _");
  lines.push("  _____  ____ _ ___ _ __ | | ___ (_) |_ ___   ___ ___  _ __ ___");
  lines.push(" / _ \\\\ \/ / _` / __| '_ \\| |/ _ \\| | __/ __| / __/ _ \\| '_ ` _ \\");
  lines.push("| (_) >  < (_| \\__ \\ |_) | | (_) | | |_\\__ \\| (_| (_) | | | | | |");
  lines.push(" \\___/_/\\_\\__,_|___/ .__/|_|\\___/|_|\\__|___(_)___\\___/|_| |_| |_|");
  lines.push("                   |_|          Welcome to the oxsploits network.");
  lines.push("");
  lines.push(`${PACKETSNITCH_TERMINAL_IDENTITY}:~$ cat packetsnitch.txt`);
  lines.push("PacketSnitch: A feature rich network packet capture and analysis tool built in Python and NodeJS/Electron.");
  lines.push(`Author: ${PACKETSNITCH_AUTHOR_NAME}`);
  lines.push(`Running PacketSnitch version: ${runningVersion || "Unknown"}`);
  lines.push(`Latest release version: ${latestReleaseVersion || "Unavailable"}`);
  lines.push(`Release source: ${PACKETSNITCH_RELEASES_PAGE_URL}`);
  lines.push("");
  lines.push("=== Latest Release Notes ===");

  if (fetchError) {
    lines.push(`Unable to fetch releases: ${fetchError}`);
    lines.push("Showing local app metadata only.");
  } else {
    lines.push(`Release URL: ${latestReleaseUrl || PACKETSNITCH_RELEASES_PAGE_URL}`);
    lines.push("");
    lines.push(latestReleaseNotes || "No release notes available.");
  }

  return `${lines.join("\n")}\n`;
}

function clearSettingsAboutTypewriterTimeout() {
  if (settingsAboutTypewriterTimeoutId !== null) {
    clearTimeout(settingsAboutTypewriterTimeoutId);
    settingsAboutTypewriterTimeoutId = null;
  }
}

function renderSettingsAboutTerminalReadout(readoutText, { animateCommand = false } = {}) {
  const outputEl = document.getElementById("settings-about-terminal-output");
  if (!outputEl) return;

  const fullText = String(readoutText || "");
  settingsAboutTypewriterToken += 1;
  const activeToken = settingsAboutTypewriterToken;
  clearSettingsAboutTypewriterTimeout();

  if (!animateCommand) {
    outputEl.textContent = fullText;
    return;
  }

  const allLines = fullText.split("\n");
  const commandLineIndex = allLines.findIndex((line) => line.includes(":~$ "));
  if (commandLineIndex === -1) {
    outputEl.textContent = fullText;
    return;
  }

  const commandLine = allLines[commandLineIndex] || "";
  const preCommandOutput = allLines.slice(0, commandLineIndex).join("\n");
  const postCommandOutput = allLines.slice(commandLineIndex + 1).join("\n");
  const preCommandText = preCommandOutput ? `${preCommandOutput}\n` : "";
  const trailingText = postCommandOutput ? `\n${postCommandOutput}` : "";

  if (!commandLine) {
    outputEl.textContent = fullText;
    return;
  }

  const promptMarker = "$ ";
  const promptIndex = commandLine.indexOf(promptMarker);
  const hasPrompt = promptIndex !== -1;
  const promptText = hasPrompt
    ? commandLine.slice(0, promptIndex + promptMarker.length)
    : "";
  const typedCommandText = hasPrompt
    ? commandLine.slice(promptIndex + promptMarker.length)
    : commandLine;

  outputEl.textContent = `${preCommandText}${promptText}`;
  let cursor = 0;
  const charDelayMs = 30;
  const preTypeDelayMs = 1000;
  const preReturnDelayMs = 500;

  const typeNextCharacter = () => {
    if (activeToken !== settingsAboutTypewriterToken) return;

    if (cursor < typedCommandText.length) {
      outputEl.textContent += typedCommandText[cursor];
      cursor += 1;
      settingsAboutTypewriterTimeoutId = setTimeout(typeNextCharacter, charDelayMs);
      return;
    }

    settingsAboutTypewriterTimeoutId = setTimeout(() => {
      if (activeToken !== settingsAboutTypewriterToken) return;
      outputEl.textContent = `${preCommandText}${commandLine}${trailingText}`;
      settingsAboutTypewriterTimeoutId = null;
    }, preReturnDelayMs);
  };

  settingsAboutTypewriterTimeoutId = setTimeout(typeNextCharacter, preTypeDelayMs);
}

async function loadSettingsAboutReleaseInfo({ forceRefresh = false } = {}) {
  const runningVersion = String(psVer || "").trim() || "Unknown";
  if (!forceRefresh && cachedSettingsAboutReleaseInfo) {
    setSettingsAboutDownloadButtonState(cachedSettingsAboutReleaseInfo.downloadInfo || {});
    renderSettingsAboutTerminalReadout(
      buildSettingsAboutTerminalReadout(cachedSettingsAboutReleaseInfo),
      { animateCommand: true },
    );
    return cachedSettingsAboutReleaseInfo;
  }

  if (settingsAboutReleaseInfoLoadPromise && !forceRefresh) {
    await settingsAboutReleaseInfoLoadPromise;
    if (cachedSettingsAboutReleaseInfo) {
      setSettingsAboutDownloadButtonState(cachedSettingsAboutReleaseInfo.downloadInfo || {});
      renderSettingsAboutTerminalReadout(
        buildSettingsAboutTerminalReadout(cachedSettingsAboutReleaseInfo),
        { animateCommand: true },
      );
    }
    return cachedSettingsAboutReleaseInfo;
  }

  renderSettingsAboutTerminalReadout(
    buildSettingsAboutTerminalReadout({
      runningVersion,
      latestReleaseVersion: "Loading...",
      latestReleaseNotes: "Fetching latest release metadata from GitHub...",
      latestReleaseUrl: PACKETSNITCH_RELEASES_PAGE_URL,
    }),
    { animateCommand: false },
  );

  const loadPromise = (async () => {
    try {
      const githubHeaders = {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      };

      let latestRelease = null;

      // Prefer the dedicated latest-release endpoint for reliability.
      try {
        const latestResponse = await fetch(PACKETSNITCH_RELEASES_LATEST_API_URL, {
          headers: githubHeaders,
        });
        if (!latestResponse.ok) {
          throw new Error(`GitHub latest endpoint returned HTTP ${latestResponse.status}`);
        }
        const latestPayload = await latestResponse.json();
        if (latestPayload && typeof latestPayload === "object" && !latestPayload.draft) {
          latestRelease = latestPayload;
        }
      } catch (latestEndpointError) {
        // Fall through to releases list endpoint.
      }

      if (!latestRelease) {
        const releasesResponse = await fetch(PACKETSNITCH_RELEASES_API_URL, {
          headers: githubHeaders,
        });
        if (!releasesResponse.ok) {
          throw new Error(`GitHub releases endpoint returned HTTP ${releasesResponse.status}`);
        }
        const payload = await releasesResponse.json();
        const releases = Array.isArray(payload)
          ? payload.filter((release) => release && typeof release === "object" && !release.draft)
          : [];
        latestRelease = releases.find((release) => !release.prerelease) || releases[0] || null;
      }

      if (!latestRelease) {
        throw new Error("No releases returned by GitHub API");
      }

      const runtimePlatform = await detectRuntimePlatform();
      const linuxPackageFamily = runtimePlatform === "linux"
        ? await detectLinuxReleasePackageFamily(runtimePlatform)
        : "";

      cachedSettingsAboutReleaseInfo = {
        runningVersion,
        latestReleaseVersion: getReleaseVersionToken(latestRelease) || "Unavailable",
        latestReleaseNotes: normalizeReleaseNotesForTerminal(latestRelease?.body),
        latestReleaseUrl:
          typeof latestRelease?.html_url === "string" && latestRelease.html_url.trim()
            ? latestRelease.html_url.trim()
            : PACKETSNITCH_RELEASES_PAGE_URL,
        downloadInfo: buildReleaseDownloadInfo(latestRelease, runningVersion, {
          linuxPackageFamily,
          runtimePlatform,
        }),
        fetchError: "",
      };
    } catch (error) {
      const errorMessage =
        error && typeof error.message === "string" && error.message.trim()
          ? error.message.trim()
          : String(error || "Unknown error");
      cachedSettingsAboutReleaseInfo = {
        runningVersion,
        latestReleaseVersion: "Lookup failed",
        latestReleaseNotes:
          "Unable to retrieve release notes from GitHub right now.\n"
          + "Use the Refresh release notes button to retry.",
        latestReleaseUrl: PACKETSNITCH_RELEASES_PAGE_URL,
        downloadInfo: {
          newVersionAvailable: false,
          downloadUrl: "",
          downloadAssetName: "",
        },
        fetchError: errorMessage,
      };
      console.warn("Unable to load PacketSnitch release metadata:", error);
    }
    setSettingsAboutDownloadButtonState(cachedSettingsAboutReleaseInfo.downloadInfo || {});
    renderSettingsAboutTerminalReadout(
      buildSettingsAboutTerminalReadout(cachedSettingsAboutReleaseInfo),
      { animateCommand: true },
    );
    return cachedSettingsAboutReleaseInfo;
  })();

  settingsAboutReleaseInfoLoadPromise = loadPromise;
  try {
    return await loadPromise;
  } finally {
    if (settingsAboutReleaseInfoLoadPromise === loadPromise) {
      settingsAboutReleaseInfoLoadPromise = null;
    }
  }
}

// Syncs runtime llm toggle from settings.
function syncRuntimeLlmToggleFromSettings() {
  const useLlmEl = document.getElementById("use-llm");
  if (useLlmEl) {
    useLlmEl.checked = isLlmEnabledInSettings();
  }
}

// Handles sanitize theme id.
function sanitizeThemeId(value, fallback = FALLBACK_THEME_ID) {
  if (typeof value !== "string") return fallback;
  const normalized = value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
  return normalized || fallback;
}

// Returns theme select element.
function getThemeSelectElement() {
  return document.getElementById("settings-themes-select");
}

// Returns llm model select element.
function getLlmModelSelectElement() {
  return document.getElementById("settings-llm-model");
}

// Returns configured ollama models.
function getConfiguredOllamaModels() {
  if (Array.isArray(availableOllamaModels) && availableOllamaModels.length > 0) {
    return availableOllamaModels.map((entry) => ({ ...entry }));
  }
  return [{
    value: DEFAULT_SETTINGS.llm.ollamaModel,
    label: DEFAULT_SETTINGS.llm.ollamaModel,
  }];
}

// Normalizes ollama model entry.
function normalizeOllamaModelEntry(rawValue) {
  if (typeof rawValue === "string") {
    const normalized = rawValue.trim();
    if (!normalized || normalized.startsWith("#")) return null;
    return {
      value: normalized,
      label: normalized,
    };
  }

  if (!rawValue || typeof rawValue !== "object") return null;

  const value =
    typeof rawValue.value === "string" && rawValue.value.trim()
      ? rawValue.value.trim()
      : typeof rawValue.name === "string" && rawValue.name.trim()
        ? rawValue.name.trim()
        : typeof rawValue.model === "string" && rawValue.model.trim()
          ? rawValue.model.trim()
          : "";
  if (!value || value.startsWith("#")) return null;

  const label =
    typeof rawValue.label === "string" && rawValue.label.trim()
      ? rawValue.label.trim()
      : value;

  return { value, label };
}

async function loadAvailableOllamaModels() {
  if (!window.modelsapi || typeof window.modelsapi.getOllamaModels !== "function") {
    availableOllamaModels = [{
      value: DEFAULT_SETTINGS.llm.ollamaModel,
      label: DEFAULT_SETTINGS.llm.ollamaModel,
    }];
    renderLlmModelOptions(getCurrentSettings()?.llm?.ollamaModel || DEFAULT_SETTINGS.llm.ollamaModel);
    return availableOllamaModels;
  }

  try {
    const models = await window.modelsapi.getOllamaModels();
    availableOllamaModels = Array.isArray(models)
      ? models
        .map((entry) => normalizeOllamaModelEntry(entry))
        .filter(Boolean)
      : [];
  } catch (error) {
    console.warn("Unable to load available Ollama models:", error);
    availableOllamaModels = [];
  }

  if (availableOllamaModels.length === 0) {
    availableOllamaModels = [{
      value: DEFAULT_SETTINGS.llm.ollamaModel,
      label: DEFAULT_SETTINGS.llm.ollamaModel,
    }];
  }

  renderLlmModelOptions(getCurrentSettings()?.llm?.ollamaModel || DEFAULT_SETTINGS.llm.ollamaModel);
  return [...availableOllamaModels];
}

// Returns ollama model dropdown options.
function getOllamaModelDropdownOptions() {
  return getConfiguredOllamaModels().map((modelEntry) => ({
    value: modelEntry.value,
    label: modelEntry.label,
  }));
}

// Renders llm model options.
function renderLlmModelOptions(selectedModelValue = "") {
  const modelSelectEl = getLlmModelSelectElement();
  if (!modelSelectEl) return;

  const normalizedSelectedValue =
    typeof selectedModelValue === "string" && selectedModelValue.trim()
      ? selectedModelValue.trim()
      : DEFAULT_SETTINGS.llm.ollamaModel;
  const optionDefinitions = getOllamaModelDropdownOptions();
  const hasSelectedValue = optionDefinitions.some(
    (option) => option.value === normalizedSelectedValue,
  );

  if (!hasSelectedValue) {
    optionDefinitions.unshift({
      value: normalizedSelectedValue,
      label: `${normalizedSelectedValue} (Custom)`,
    });
  }

  modelSelectEl.innerHTML = "";
  optionDefinitions.forEach((optionDefinition) => {
    const optionEl = document.createElement("option");
    optionEl.value = optionDefinition.value;
    optionEl.textContent = optionDefinition.label;
    modelSelectEl.appendChild(optionEl);
  });

  modelSelectEl.value = normalizedSelectedValue;
}

// Returns theme by id from list.
function getThemeByIdFromList(themeId) {
  const normalizedId = sanitizeThemeId(themeId, FALLBACK_THEME_ID);
  return availableThemes.find((theme) => sanitizeThemeId(theme.id, "") === normalizedId) || null;
}

// Returns theme source suffix.
function getThemeSourceSuffix(theme) {
  if (!theme || !theme.hasUserBundledDiff) return "";
  return theme.sourceKind === "user" ? " [User Modified]" : " [Bundled]";
}

// Handles update selected theme source note.
function updateSelectedThemeSourceNote(themeId) {
  const noteEl = document.getElementById("settings-themes-source-note");
  if (!noteEl) return;
  const theme = getThemeByIdFromList(themeId);
  if (!theme || !theme.hasUserBundledDiff) {
    noteEl.textContent = "";
    noteEl.hidden = true;
    return;
  }

  const sourceLabel = theme.sourceKind === "user" ? "User Modified" : "Bundled";
  noteEl.textContent = `Selected source for this theme ID: ${sourceLabel}.`;
  noteEl.hidden = false;
}

// Renders theme options.
function renderThemeOptions() {
  const themeSelectEl = getThemeSelectElement();
  if (!themeSelectEl) return;
  const currentValue = sanitizeThemeId(themeSelectEl.value, FALLBACK_THEME_ID);
  const settingsThemeId = sanitizeThemeId(
    getCurrentSettings()?.general?.themeId,
    FALLBACK_THEME_ID,
  );
  const selectedThemeId = availableThemes.some((theme) => theme.id === settingsThemeId)
    ? settingsThemeId
    : currentValue;

  themeSelectEl.innerHTML = "";
  availableThemes.forEach((theme) => {
    const option = document.createElement("option");
    option.value = theme.id;
    option.textContent = `${theme.name}${getThemeSourceSuffix(theme)}`;
    themeSelectEl.appendChild(option);
  });

  if (themeSelectEl.options.length > 0) {
    themeSelectEl.value = selectedThemeId || FALLBACK_THEME_ID;
  }
  updateSelectedThemeSourceNote(themeSelectEl.value);
}

function parseHexColorToRgb(colorValue) {
  if (typeof colorValue !== "string") return null;
  const normalized = colorValue.trim().toLowerCase();
  const hexMatch = normalized.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (!hexMatch) return null;
  const hexBody = hexMatch[1];
  const expanded = hexBody.length === 3
    ? hexBody.split("").map((part) => `${part}${part}`).join("")
    : hexBody;
  const red = parseInt(expanded.slice(0, 2), 16);
  const green = parseInt(expanded.slice(2, 4), 16);
  const blue = parseInt(expanded.slice(4, 6), 16);
  if ([red, green, blue].some((value) => Number.isNaN(value))) return null;
  return { red, green, blue };
}

function toLinearSrgb(value) {
  const normalized = value / 255;
  if (normalized <= 0.04045) {
    return normalized / 12.92;
  }
  return ((normalized + 0.055) / 1.055) ** 2.4;
}

function getRelativeLuminanceFromRgb({ red, green, blue }) {
  const linearRed = toLinearSrgb(red);
  const linearGreen = toLinearSrgb(green);
  const linearBlue = toLinearSrgb(blue);
  return (0.2126 * linearRed) + (0.7152 * linearGreen) + (0.0722 * linearBlue);
}

function resolveSettingsAboutTerminalColorToken(themeVariables, tokenName, fallbackValue = "") {
  if (!themeVariables || typeof themeVariables !== "object") return fallbackValue;
  const raw = themeVariables[tokenName];
  if (typeof raw !== "string" || !raw.trim()) return fallbackValue;
  return raw.trim();
}

function resolveThemeBgColorToken(themeVariables) {
  if (!themeVariables || typeof themeVariables !== "object") return "";
  const candidateTokens = ["--app-bg", "--surface-0", "--surface-1", "--input-bg-color"];
  for (const tokenName of candidateTokens) {
    const tokenValue = resolveSettingsAboutTerminalColorToken(themeVariables, tokenName, "");
    if (tokenValue) return tokenValue;
  }
  return "";
}

function isThemeLight(themeVariables) {
  const backgroundToken = resolveThemeBgColorToken(themeVariables);
  const parsedBackground = parseHexColorToRgb(backgroundToken);
  if (!parsedBackground) return false;
  return getRelativeLuminanceFromRgb(parsedBackground) >= 0.5;
}

function applyThemeDropdownColors(theme) {
  const rootStyle = document.documentElement.style;
  const themeVariables = theme && typeof theme === "object" ? theme.variables : null;
  const lightTheme = isThemeLight(themeVariables);
  const dropdownBackgroundColor = lightTheme ? "#ffffff" : "#000000";
  const dropdownTextColor = lightTheme ? "#000000" : "#ffffff";

  rootStyle.setProperty("--dropdown-bg-color", dropdownBackgroundColor);
  rootStyle.setProperty("--dropdown-text-color", dropdownTextColor);
}

function applySettingsAboutTerminalTheme(theme) {
  const rootStyle = document.documentElement.style;
  const themeVariables = theme && typeof theme === "object" ? theme.variables : null;
  const fallbackTextColor = "#e6e6e6";

  const borderAndTextColor =
    resolveSettingsAboutTerminalColorToken(themeVariables, "--color-5", "")
    || resolveSettingsAboutTerminalColorToken(themeVariables, "--header-text-color", "")
    || fallbackTextColor;

  const parsedTextColor = parseHexColorToRgb(borderAndTextColor);
  const textLuminance = parsedTextColor
    ? getRelativeLuminanceFromRgb(parsedTextColor)
    : 0.8;

  // Keep terminal background strictly black/white while maximizing contrast.
  const terminalBackgroundColor = textLuminance >= 0.5 ? "#000000" : "#ffffff";

  rootStyle.setProperty("--settings-about-terminal-bg", terminalBackgroundColor);
  rootStyle.setProperty("--settings-about-terminal-fg", borderAndTextColor);
  rootStyle.setProperty("--settings-about-terminal-border", borderAndTextColor);
}

// Applies theme variables.
function applyThemeVariables(theme) {
  const rootStyle = document.documentElement.style;
  if (appliedThemeVariableNames.size > 0) {
    appliedThemeVariableNames.forEach((variableName) => {
      rootStyle.removeProperty(variableName);
    });
    appliedThemeVariableNames = new Set();
  }
  if (!theme || !theme.variables || typeof theme.variables !== "object") return;

  Object.entries(theme.variables).forEach(([variableName, variableValue]) => {
    if (!String(variableName).startsWith("--")) return;
    if (typeof variableValue !== "string" || !variableValue.trim()) return;
    rootStyle.setProperty(variableName, String(variableValue));
    appliedThemeVariableNames.add(String(variableName));
  });

  applyThemeDropdownColors(theme);
  applySettingsAboutTerminalTheme(theme);
}

// Applies theme quit button character.
function applyThemeQuitButtonCharacter(theme) {
  const closeBtn = document.getElementById("close-btn");
  if (!closeBtn) return;
  const configuredCharacter =
    theme && typeof theme.quitButtonCharacter === "string"
      ? theme.quitButtonCharacter.trim()
      : "";
  closeBtn.textContent = configuredCharacter || "\u00D7";
}

// Returns app logo element.
function getAppLogoElement() {
  return document.getElementById("app-logo") || document.querySelector(".logo-cont img");
}

// Returns theme backdrop element.
function getThemeBackdropElement() {
  return document.getElementById("theme-backdrop");
}

// Builds theme embedded image data uri.
function buildThemeEmbeddedImageDataUri(imageConfig) {
  if (!imageConfig || typeof imageConfig !== "object") return null;
  const formatRaw = typeof imageConfig.format === "string"
    ? imageConfig.format.trim().toLowerCase()
    : "";
  const format = formatRaw === "jpeg" ? "jpg" : formatRaw;
  const normalizedBase64 = typeof imageConfig.base64 === "string"
    ? imageConfig.base64.replace(/^data:image\/(png|jpeg|jpg);base64,/i, "").replace(/\s+/g, "")
    : "";
  if ((format !== "png" && format !== "jpg") || !normalizedBase64) {
    return null;
  }

  const mime = format === "png" ? "image/png" : "image/jpeg";
  return `data:${mime};base64,${normalizedBase64}`;
}

// Applies theme logo.
function applyThemeLogo(theme) {
  const logoEl = getAppLogoElement();
  if (!logoEl) return;

  if (!defaultThemeLogoSrc) {
    defaultThemeLogoSrc = logoEl.getAttribute("src") || "../assets/images/logo.webp";
  }

  const logoImage = theme && typeof theme === "object" ? theme.logoImage : null;
  const logoDataUri = buildThemeEmbeddedImageDataUri(logoImage);
  if (!logoDataUri) {
    logoEl.src = defaultThemeLogoSrc;
    return;
  }

  logoEl.src = logoDataUri;
}

// Applies theme backdrop image.
function applyThemeBackdropImage(theme) {
  const backdropEl = getThemeBackdropElement();
  if (!backdropEl) return;

  const backdropImage = theme && typeof theme === "object" ? theme.backdropImage : null;
  const backdropDataUri = buildThemeEmbeddedImageDataUri(backdropImage);
  if (!backdropDataUri) {
    backdropEl.style.removeProperty("background-image");
    backdropEl.classList.remove("has-image");
    return;
  }

  backdropEl.style.setProperty("background-image", `url(${backdropDataUri})`);
  backdropEl.classList.add("has-image");
}

async function applyThemeById(themeId) {
  const normalizedThemeId = sanitizeThemeId(themeId, FALLBACK_THEME_ID);
  if (!window.themeapi || typeof window.themeapi.get !== "function") {
    applyThemeVariables(null);
    applyThemeLogo(null);
    applyThemeBackdropImage(null);
    applyThemeQuitButtonCharacter(null);
    document.documentElement.dataset.themeId = normalizedThemeId;
    return normalizedThemeId;
  }
  try {
    const theme = await window.themeapi.get(normalizedThemeId);
    if (!theme) return normalizedThemeId;
    applyThemeVariables(theme);
    applyThemeLogo(theme);
    applyThemeBackdropImage(theme);
    applyThemeQuitButtonCharacter(theme);
    document.documentElement.dataset.themeId = theme.id;
    return theme.id;
  } catch (error) {
    console.warn("Unable to apply selected theme:", error);
    return normalizedThemeId;
  }
}

async function loadAvailableThemes() {
  if (!window.themeapi || typeof window.themeapi.list !== "function") {
    availableThemes = [{ id: FALLBACK_THEME_ID, name: "SnitchBitch" }];
    renderThemeOptions();
    return availableThemes;
  }

  try {
    const themeList = await window.themeapi.list();
    availableThemes = Array.isArray(themeList) && themeList.length > 0
      ? themeList
      : [{ id: FALLBACK_THEME_ID, name: "SnitchBitch" }];
  } catch (error) {
    console.warn("Unable to load available themes:", error);
    availableThemes = [{ id: FALLBACK_THEME_ID, name: "SnitchBitch" }];
  }
  renderThemeOptions();
  return availableThemes;
}

// Updates theme directory hint.
async function updateThemeDirectoryHint() {
  const hintEl = document.getElementById("settings-themes-directory-hint");
  if (!hintEl || !window.themeapi || typeof window.themeapi.getThemesDirectory !== "function") {
    return;
  }
  try {
    const themesDir = await window.themeapi.getThemesDirectory();
    if (themesDir) {
      hintEl.textContent = `Add custom theme JSON files in ${themesDir} and restart or reopen Settings.`;
    }
  } catch (error) {
    console.warn("Unable to resolve themes directory:", error);
  }
}

// Theme preview and catalog state for the Settings → Themes subtab.
let themesCatalogEntries = [];
let themesCatalogIsSandbox = false;
let themesCatalogPaddleEnv = null;
let themesCatalogLoading = false;
let themesPreviewObjectUrl = null;
let themesPreviewInFlight = 0;
const themesEmbeddedPreviewCache = new Map();

function getThemesPreviewElement() {
  return document.getElementById("settings-themes-preview");
}

function getThemesPreviewFallbackElement() {
  return document.getElementById("settings-themes-preview-fallback");
}

function getThemesCatalogListElement() {
  return document.getElementById("settings-themes-catalog-list");
}

function getThemesCatalogStatusElement() {
  return document.getElementById("settings-themes-catalog-status");
}

function setThemesCatalogStatus(message, { isError = false } = {}) {
  const statusEl = getThemesCatalogStatusElement();
  if (!statusEl) return;
  statusEl.textContent = String(message || "");
  statusEl.style.color = isError ? "#ff9090" : "";
}

function getThemesCatalogSandboxBannerElement() {
  return document.getElementById("settings-themes-catalog-sandbox-banner");
}

// Show or hide the sandbox warning banner above the catalog list. The
// catalog server signals sandbox mode via either ``paddleEnv: "sandbox"``
// (preferred) or the legacy ``sandbox: true`` boolean; either is enough.
// Unknown / production responses hide the banner.
function setThemesCatalogSandboxBanner({ paddleEnv, sandbox } = {}) {
  const bannerEl = getThemesCatalogSandboxBannerElement();
  if (!bannerEl) return;
  const isSandboxEnv = typeof paddleEnv === "string" && paddleEnv.trim().toLowerCase() === "sandbox";
  const isSandboxBool = sandbox === true;
  const isSandbox = isSandboxEnv || isSandboxBool;
  themesCatalogIsSandbox = isSandbox;
  themesCatalogPaddleEnv = typeof paddleEnv === "string" && paddleEnv.trim()
    ? paddleEnv.trim().toLowerCase()
    : (isSandbox ? "sandbox" : null);
  if (!isSandbox) {
    bannerEl.hidden = true;
    bannerEl.textContent = "";
    return;
  }
  bannerEl.hidden = false;
  bannerEl.textContent =
    "Sandbox mode: the theme catalog is connected to Paddle's sandbox "
    + "environment. Purchases will not be charged and no real licenses "
    + "will be issued.";
}

function clearThemesPreviewObjectUrl() {
  if (themesPreviewObjectUrl) {
    try {
      URL.revokeObjectURL(themesPreviewObjectUrl);
    } catch (_error) {
      // ignore
    }
    themesPreviewObjectUrl = null;
  }
}

function resetThemesPreview() {
  clearThemesPreviewObjectUrl();
  const previewEl = getThemesPreviewElement();
  const fallbackEl = getThemesPreviewFallbackElement();
  if (previewEl) {
    previewEl.style.removeProperty("background-image");
    previewEl.hidden = true;
  }
  if (fallbackEl) {
    fallbackEl.hidden = false;
  }
}

function showThemesPreviewFromDataUri(dataUri) {
  const previewEl = getThemesPreviewElement();
  const fallbackEl = getThemesPreviewFallbackElement();
  if (!previewEl || !fallbackEl) return;
  if (!dataUri) {
    resetThemesPreview();
    return;
  }
  previewEl.style.setProperty("background-image", `url(${dataUri})`);
  previewEl.hidden = false;
  fallbackEl.hidden = true;
}

function buildThemesPreviewDataUri(themeConfig) {
  if (!themeConfig) return null;
  // --- catalog-side shape: a raw "data:image/...;base64,..." string ---
  if (typeof themeConfig === "string") {
    if (/^data:image\/(png|jpeg|jpg);base64,[A-Za-z0-9+/=]+$/i.test(themeConfig)) {
      return themeConfig;
    }
    return null;
  }
  if (typeof themeConfig !== "object") return null;
  // --- new shape: a "data:image/...;base64,..." string in `.dataUri` ---
  if (typeof themeConfig.dataUri === "string" && themeConfig.dataUri) {
    if (/^data:image\/(png|jpeg|jpg);base64,[A-Za-z0-9+/=]+$/i.test(themeConfig.dataUri)) {
      return themeConfig.dataUri;
    }
  }
  // --- legacy shape: {format, base64} object ---
  const formatRaw = typeof themeConfig.format === "string"
    ? themeConfig.format.trim().toLowerCase()
    : "";
  const format = formatRaw === "jpeg" ? "jpg" : formatRaw;
  if (format !== "png" && format !== "jpg") return null;
  const rawBase64 = typeof themeConfig.base64 === "string"
    ? themeConfig.base64
    : typeof themeConfig.data === "string"
      ? themeConfig.data
      : "";
  if (!rawBase64) return null;
  const mime = format === "png" ? "image/png" : "image/jpeg";
  const base64 = rawBase64
    .replace(/^data:image\/(png|jpeg|jpg);base64,/i, "")
    .replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/=]+$/.test(base64)) return null;
  return `data:${mime};base64,${base64}`;
}

function getThemeEmbeddedPreviewDataUri(theme) {
  if (!theme || typeof theme !== "object") return null;
  if (themesEmbeddedPreviewCache.has(theme.id)) {
    return themesEmbeddedPreviewCache.get(theme.id) || null;
  }
  const dataUri = buildThemesPreviewDataUri(theme.previewImage);
  themesEmbeddedPreviewCache.set(theme.id, dataUri || "");
  return dataUri;
}

async function fetchThemesPreviewFromUrl(previewUrl) {
  if (!window.themeapi || typeof window.themeapi.fetchPreview !== "function") {
    return null;
  }
  const requestToken = ++themesPreviewInFlight;
  try {
    const result = await window.themeapi.fetchPreview({ url: previewUrl });
    if (requestToken !== themesPreviewInFlight) {
      // A newer request superseded us; discard this one to avoid races.
      if (result && result.dataUri && result.dataUri.startsWith("blob:")) {
        try {
          URL.revokeObjectURL(result.dataUri);
        } catch (_e) {
          // ignore
        }
      }
      return null;
    }
    if (result && typeof result.dataUri === "string" && result.dataUri) {
      // Revoke any prior blob URL before adopting the new one.
      if (themesPreviewObjectUrl) {
        try {
          URL.revokeObjectURL(themesPreviewObjectUrl);
        } catch (_e) {
          // ignore
        }
      }
      if (result.dataUri.startsWith("blob:")) {
        themesPreviewObjectUrl = result.dataUri;
      }
      return result.dataUri;
    }
    return null;
  } catch (error) {
    console.warn("Unable to fetch theme preview:", error);
    return null;
  }
}

async function refreshThemesPreviewForSelected() {
  const themeSelectEl = getThemeSelectElement();
  if (!themeSelectEl) return;
  const selectedId = sanitizeThemeId(themeSelectEl.value, FALLBACK_THEME_ID);
  const theme = getThemeByIdFromList(selectedId);
  if (!theme) {
    resetThemesPreview();
    return;
  }
  const embeddedDataUri = getThemeEmbeddedPreviewDataUri(theme);
  if (embeddedDataUri) {
    showThemesPreviewFromDataUri(embeddedDataUri);
    return;
  }
  const previewUrl = typeof theme.previewUrl === "string" ? theme.previewUrl.trim() : "";
  if (previewUrl) {
    resetThemesPreview();
    const dataUri = await fetchThemesPreviewFromUrl(previewUrl);
    if (dataUri) {
      showThemesPreviewFromDataUri(dataUri);
    } else {
      resetThemesPreview();
    }
    return;
  }
  resetThemesPreview();
}

function renderThemesCatalog() {
  const listEl = getThemesCatalogListElement();
  if (!listEl) return;
  listEl.innerHTML = "";
  if (!Array.isArray(themesCatalogEntries) || themesCatalogEntries.length === 0) {
    return;
  }
  themesCatalogEntries.forEach((entry) => {
    if (!entry || typeof entry !== "object") return;
    const cardEl = document.createElement("div");
    cardEl.className = "settings-themes-catalog-card";
    cardEl.setAttribute("role", "listitem");

    const nameEl = document.createElement("div");
    nameEl.className = "settings-themes-catalog-name";
    nameEl.textContent = String(entry.name || entry.id || "Theme");
    cardEl.appendChild(nameEl);

    if (entry.description) {
      const descEl = document.createElement("div");
      descEl.className = "settings-themes-catalog-desc";
      descEl.textContent = String(entry.description);
      cardEl.appendChild(descEl);
    }

    const priceEl = document.createElement("div");
    priceEl.className = "settings-themes-catalog-price";
    const priceLabel = typeof entry.priceLabel === "string" && entry.priceLabel.trim()
      ? entry.priceLabel.trim()
      : (typeof entry.priceCents === "number" && entry.priceCents > 0
        ? `$${(entry.priceCents / 100).toFixed(2)}`
        : "Free / included");
    priceEl.textContent = priceLabel;
    cardEl.appendChild(priceEl);

    const statusEl = document.createElement("div");
    statusEl.className = "settings-themes-catalog-status";
    if (entry.owned) {
      statusEl.textContent = "Owned";
      statusEl.style.color = "#7be58a";
    } else if (entry.installed) {
      statusEl.textContent = "Installed (not licensed)";
      statusEl.style.color = "#ffcf6b";
    } else {
      statusEl.textContent = "Available for purchase";
      statusEl.style.color = "";
    }
    cardEl.appendChild(statusEl);

    const actionsEl = document.createElement("div");
    actionsEl.className = "settings-actions-row";
    actionsEl.style.marginTop = "0.4rem";

    const previewBtn = document.createElement("button");
    previewBtn.type = "button";
    previewBtn.textContent = "Preview";
    previewBtn.addEventListener("click", () => {
      showThemesPreviewFromDataUri(buildThemesPreviewDataUri(entry.previewImage));
    });
    actionsEl.appendChild(previewBtn);

    const buyBtn = document.createElement("button");
    buyBtn.type = "button";
    buyBtn.textContent = entry.owned ? "Open in Browser" : "Buy";
    buyBtn.disabled = !entry.owned && !entry.checkoutUrl;
    buyBtn.addEventListener("click", () => {
      void startThemeCheckout(entry);
    });
    actionsEl.appendChild(buyBtn);

    cardEl.appendChild(actionsEl);
    listEl.appendChild(cardEl);
  });
}

async function refreshThemesCatalog({ force = false } = {}) {
  if (!window.themeapi || typeof window.themeapi.listCatalog !== "function") {
    setThemesCatalogStatus("Online theme catalog is not available in this build.", { isError: true });
    return;
  }
  if (themesCatalogLoading && !force) return;
  themesCatalogLoading = true;
  setThemesCatalogStatus("Loading catalog...");
  try {
    const result = await window.themeapi.listCatalog({ force });
    themesCatalogEntries = Array.isArray(result?.entries) ? result.entries : [];
    // Update the sandbox banner whenever we get a fresh catalog response.
    // We read both signals (paddleEnv string and sandbox boolean) so we
    // don't break if the server only emits one.
    setThemesCatalogSandboxBanner({
      paddleEnv: result?.paddleEnv,
      sandbox: result?.sandbox,
    });
    if (result && result.success === false) {
      // The main process already produced a human-readable error
      // message (e.g. "Could not reach theme server… change to https://…
      // and try again"). Surface it verbatim instead of the generic
      // "no themes" line, which was hiding protocol-mismatch bugs.
      setThemesCatalogStatus(
        result.error
          ? `Unable to load theme catalog: ${result.error}`
          : "Unable to load theme catalog.",
        { isError: true },
      );
    } else {
      setThemesCatalogStatus(
        themesCatalogEntries.length === 0
          ? "No themes are available for purchase right now."
          : `Loaded ${themesCatalogEntries.length} theme(s).`,
      );
    }
    renderThemesCatalog();
  } catch (error) {
    console.warn("Unable to load theme catalog:", error);
    setThemesCatalogStatus(
      `Unable to load theme catalog: ${error?.message || error || "unknown error"}`,
      { isError: true },
    );
  } finally {
    themesCatalogLoading = false;
  }
}

// Subscribe once to the main-process deeplink channel so a
// ``packetsnitch://checkout-success?...`` click in the user's browser
// automatically reconciles licenses and refreshes the catalog without
// the user having to manually click "Check License".
if (window.themeapi && typeof window.themeapi.onCheckoutSuccessDeeplink === "function") {
  window.themeapi.onCheckoutSuccessDeeplink(async (payload) => {
    try {
      const themeId = String(payload?.themeId || "").trim();
      const unlocked = Array.isArray(payload?.unlockedThemeIds)
        ? payload.unlockedThemeIds
        : [];
      const errorText = payload?.error ? String(payload.error) : "";
      if (errorText) {
        setThemesCatalogStatus(
          `Deeplink received, but license reconcile failed: ${errorText}. You can click "Check License" to retry.`,
          { isError: true },
        );
      } else if (unlocked.length > 0) {
        const unlockedList = unlocked.join(", ");
        setThemesCatalogStatus(
          themeId && unlocked.includes(themeId)
            ? `Theme "${themeId}" unlocked via deeplink. Reloading...`
            : `Unlocked ${unlocked.length} theme(s) via deeplink: ${unlockedList}. Reloading...`,
        );
        await loadAvailableThemes();
        await refreshThemesPreviewForSelected();
        // Re-fetch the catalog so newly-licensed themes show as "owned".
        try {
          await refreshThemesCatalog({ force: false });
        } catch (_e) {
          // ignore — the catalog is a best-effort refresh
        }
      } else {
        setThemesCatalogStatus(
          "Deeplink received, but no new licenses were granted yet. Paddle may still be processing the payment. You can click \"Check License\" to retry.",
        );
      }
    } catch (error) {
      console.warn("Deeplink handler failed:", error);
      setThemesCatalogStatus(
        `Deeplink handler failed: ${error?.message || error || "unknown error"}`,
        { isError: true },
      );
    }
  });
}

async function startThemeCheckout(catalogEntry) {
  if (!catalogEntry || typeof catalogEntry !== "object") return;
  if (!window.themeapi || typeof window.themeapi.startCheckout !== "function") {
    setThemesCatalogStatus("Checkout is not available in this build.", { isError: true });
    return;
  }
  if (catalogEntry.owned && catalogEntry.licenseUrl) {
    try {
      await window.themeapi.openExternalUrl(catalogEntry.licenseUrl);
    } catch (_e) {
      // ignore
    }
    return;
  }
  setThemesCatalogStatus(
    themesCatalogIsSandbox
      ? "Opening checkout in your default browser. Sandbox mode is active — no real payment will be taken."
      : "Opening checkout in your default browser...",
  );
  try {
    const result = await window.themeapi.startCheckout({
      themeId: catalogEntry.id,
      checkoutUrl: catalogEntry.checkoutUrl || "",
    });
    if (result?.success) {
      setThemesCatalogStatus(
        result.openedExternally
          ? "Checkout opened in your default browser. After completing payment, click Check License to refresh."
          : "Checkout is ready. After completing payment, click Check License to refresh.",
      );
    } else {
      setThemesCatalogStatus(
        `Unable to start checkout: ${result?.error || "unknown error"}`,
        { isError: true },
      );
    }
  } catch (error) {
    setThemesCatalogStatus(
      `Unable to start checkout: ${error?.message || error || "unknown error"}`,
      { isError: true },
    );
  }
}

async function checkThemesLicense() {
  if (!window.themeapi || typeof window.themeapi.refreshLicenses !== "function") {
    setThemesCatalogStatus("License check is not available in this build.", { isError: true });
    return;
  }
  setThemesCatalogStatus("Checking license for this install...");
  try {
    const result = await window.themeapi.refreshLicenses();
    const unlocked = Array.isArray(result?.unlockedThemeIds)
      ? result.unlockedThemeIds
      : [];
    // License reconcile also surfaces the server's Paddle environment,
    // so refresh the sandbox banner in case the catalog fetch has been
    // delayed or the user clicked Check License first.
    setThemesCatalogSandboxBanner({
      paddleEnv: result?.paddleEnv,
      sandbox: result?.sandbox,
    });
    setThemesCatalogStatus(
      unlocked.length === 0
        ? "No new themes unlocked for this install yet."
        : `Unlocked ${unlocked.length} theme(s): ${unlocked.join(", ")}. Reloading...`,
    );
    if (unlocked.length > 0) {
      await loadAvailableThemes();
      await refreshThemesPreviewForSelected();
      await refreshThemesCatalog({ force: true });
    }
  } catch (error) {
    setThemesCatalogStatus(
      `Unable to check license: ${error?.message || error || "unknown error"}`,
      { isError: true },
    );
  }
}

function bindThemesSubtabEvents() {
  const refreshBtn = document.getElementById("settings-themes-refresh-catalog-btn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      void refreshThemesCatalog({ force: true });
    });
  }
  const checkLicenseBtn = document.getElementById("settings-themes-check-license-btn");
  if (checkLicenseBtn) {
    checkLicenseBtn.addEventListener("click", () => {
      void checkThemesLicense();
    });
  }
  const selectEl = getThemeSelectElement();
  if (selectEl) {
    selectEl.addEventListener("change", () => {
      void refreshThemesPreviewForSelected();
    });
  }
}

// Syncs settings form from state.
function syncSettingsFormFromState() {
  const settings = getCurrentSettings();
  const themeSelectEl = getThemeSelectElement();
  const convJsonIndentEl = document.getElementById("settings-general-conv-json-indent");
  const statusResetSecondsEl = document.getElementById("settings-general-status-reset-seconds");
  const backendChunkSizeEl = document.getElementById("settings-backend-chunk-size");
  const backendWorkerThreadsEl = document.getElementById(
    "settings-backend-worker-threads",
  );
  const streamWarnThresholdEl = document.getElementById(
    "settings-general-stream-warn-packet-threshold",
  );
  const manualConvImportMaxBytesEl = document.getElementById(
    "settings-general-manual-conv-import-max-bytes",
  );
  const nmapServiceScanEnabledEl = document.getElementById(
    "settings-general-nmap-service-scan-enabled",
  );
  const checkForNewReleasesOnStartupEl = document.getElementById(
    "settings-general-check-for-new-releases-on-startup",
  );
  const backendTcpHostEl = document.getElementById("settings-backend-tcp-host");
  const backendTcpPortEl = document.getElementById("settings-backend-tcp-port");
  const backendVirusTotalApiKeyEl = document.getElementById(
    "settings-backend-virustotal-api-key",
  );
  const apiKeysMetricsInstallIdEl = document.getElementById(
    "settings-api-keys-metrics-install-id",
  );
  const backendForceLegacySpawnEl = document.getElementById(
    "settings-backend-force-legacy-spawn",
  );
  const bsonGzipSessionEnabledEl = document.getElementById(
    "settings-debug-bson-gzip-session-enabled",
  );
  const ungroupedListVirtualizationEnabledEl = document.getElementById(
    "settings-debug-ungrouped-list-virtualization-enabled",
  );
  const backendHttpDataModeEnabledEl = document.getElementById(
    "settings-backend-http-data-mode-enabled",
  );
  const backendRefreshIntervalMsEl = document.getElementById(
    "settings-debug-backend-refresh-interval-ms",
  );
  const backendRefreshMinPacketsEl = document.getElementById(
    "settings-debug-backend-refresh-min-packets",
  );
  const backendJsonDataEmitIntervalMsEl = document.getElementById(
    "settings-debug-backend-json-data-emit-interval-ms",
  );
  const frontendIngestThreadingEnabledEl = document.getElementById(
    "settings-debug-frontend-ingest-threading-enabled",
  );
  const frontendIngestWorkerThreadsEl = document.getElementById(
    "settings-debug-frontend-ingest-worker-threads",
  );
  const mapProjectionZoomXEl = document.getElementById("settings-debug-map-projection-zoom-x");
  const mapProjectionZoomYEl = document.getElementById("settings-debug-map-projection-zoom-y");
  const mapProjectionOffsetXEl = document.getElementById("settings-debug-map-projection-offset-x");
  const mapProjectionOffsetYEl = document.getElementById("settings-debug-map-projection-offset-y");
  const modelEl = document.getElementById("settings-llm-model");
  const apiKeyEl = document.getElementById("settings-llm-api-key");
  const activeByDefaultEl = document.getElementById("settings-llm-active-by-default");
  const backgroundSummaryGenerationEnabledEl = document.getElementById(
    "settings-llm-background-summary-generation-enabled",
  );
  const delayEl = document.getElementById("settings-llm-delay-seconds");
  const maxTokensEl = document.getElementById("settings-llm-max-tokens");
  const timeoutSecondsEl = document.getElementById("settings-llm-timeout-seconds");
  const retryCountEl = document.getElementById("settings-llm-retry-count");
  const analysisCompactionThresholdBlubsEl = document.getElementById(
    "settings-llm-analysis-compaction-threshold-blubs",
  );
  const pluginFailureThresholdEl = document.getElementById(
    "settings-plugins-auto-disable-failure-threshold",
  );
  const privacyMetricsEnabledEl = document.getElementById(
    "settings-privacy-metrics-enabled",
  );
  const privacyEndpointUrlEl = document.getElementById(
    "settings-privacy-metrics-endpoint-url",
  );
  const privacyFlushIntervalEl = document.getElementById(
    "settings-privacy-metrics-flush-interval-seconds",
  );
  const privacyMaxQueueSizeEl = document.getElementById(
    "settings-privacy-metrics-max-queue-size",
  );
  const privacyInstallIdEl = document.getElementById(
    "settings-privacy-metrics-install-id",
  );
  const privacyConsentStatusEl = document.getElementById(
    "settings-privacy-consent-status",
  );
  if (themeSelectEl) {
    renderThemeOptions();
    themeSelectEl.value = sanitizeThemeId(settings.general.themeId, FALLBACK_THEME_ID);
  }
  if (convJsonIndentEl) {
    convJsonIndentEl.value = String(settings.general.convJsonIndentSpaces);
  }
  if (statusResetSecondsEl) {
    statusResetSecondsEl.value = String(settings.general.statusResetSeconds);
  }
  if (backendChunkSizeEl) {
    backendChunkSizeEl.value = String(settings.general.backendPacketChunkSize);
  }
  if (backendWorkerThreadsEl) {
    backendWorkerThreadsEl.value = String(settings.general.backendWorkerThreads);
  }
  if (streamWarnThresholdEl) {
    streamWarnThresholdEl.value = String(settings.general.streamContextWarnPacketThreshold);
  }
  if (manualConvImportMaxBytesEl) {
    manualConvImportMaxBytesEl.value = formatManualConvImportLimitMb(
      settings.general.manualConvImportMaxBytes,
    );
  }
  if (nmapServiceScanEnabledEl) {
    nmapServiceScanEnabledEl.checked = Boolean(settings.general.nmapServiceScanEnabled);
  }
  if (checkForNewReleasesOnStartupEl) {
    checkForNewReleasesOnStartupEl.checked = Boolean(
      settings?.general?.checkForNewReleasesOnStartup,
    );
  }
  // Theme catalog base URL, self-signed-cert allowance, and recache
  // interval are hard-coded — there are no UI controls for them any
  // more. The defensive lookups below tolerate older bundles that may
  // still expose the (now ignored) inputs.
  const themeServerBaseUrlEl = document.getElementById("settings-themes-server-base-url");
  if (themeServerBaseUrlEl) {
    themeServerBaseUrlEl.value = String(
      DEFAULT_SETTINGS.general.themeServerBaseUrl || "",
    );
  }
  const themeRefreshIntervalHoursEl = document.getElementById(
    "settings-themes-refresh-interval-hours",
  );
  if (themeRefreshIntervalHoursEl) {
    themeRefreshIntervalHoursEl.value = String(
      DEFAULT_SETTINGS.general.themeRefreshIntervalHours,
    );
  }
  const themeAllowInsecureTlsEl = document.getElementById(
    "settings-themes-allow-insecure-tls",
  );
  if (themeAllowInsecureTlsEl) {
    themeAllowInsecureTlsEl.checked = Boolean(
      DEFAULT_SETTINGS.general.allowInsecureTlsEndpoints,
    );
  }
  if (backendTcpHostEl) {
    backendTcpHostEl.value = String(settings.backend.tcpHost || DEFAULT_SETTINGS.backend.tcpHost);
  }
  if (backendTcpPortEl) {
    backendTcpPortEl.value = String(settings.backend.tcpPort || DEFAULT_SETTINGS.backend.tcpPort);
  }
  if (backendVirusTotalApiKeyEl) {
    backendVirusTotalApiKeyEl.value = "";
    backendVirusTotalApiKeyEl.placeholder = settings.apiKeys?.virusTotalApiKey
      ? "Stored key present; leave blank to keep it"
      : "Leave blank to keep the stored key";
  }
  if (apiKeysMetricsInstallIdEl) {
    apiKeysMetricsInstallIdEl.value = String(
      settings.privacy?.metricsInstallId || "",
    );
  }
  if (backendForceLegacySpawnEl) {
    backendForceLegacySpawnEl.checked = Boolean(settings.backend.forceLegacySpawn);
  }
  if (bsonGzipSessionEnabledEl) {
    bsonGzipSessionEnabledEl.checked = Boolean(settings.debug.bsonGzipSessionEnabled);
  }
  if (ungroupedListVirtualizationEnabledEl) {
    ungroupedListVirtualizationEnabledEl.checked = Boolean(
      settings.debug.ungroupedListVirtualizationEnabled,
    );
  }
  if (backendHttpDataModeEnabledEl) {
    backendHttpDataModeEnabledEl.checked = Boolean(
      settings.debug.backendHttpDataModeEnabled,
    );
  }
  if (backendRefreshIntervalMsEl) {
    backendRefreshIntervalMsEl.value = String(
      settings.debug.backendIncrementalRefreshMinIntervalMs,
    );
  }
  if (backendRefreshMinPacketsEl) {
    backendRefreshMinPacketsEl.value = String(
      settings.debug.backendIncrementalRefreshMinPackets,
    );
  }
  if (backendJsonDataEmitIntervalMsEl) {
    backendJsonDataEmitIntervalMsEl.value = String(
      settings.debug.backendJsonDataEmitMinIntervalMs,
    );
  }
  if (frontendIngestThreadingEnabledEl) {
    frontendIngestThreadingEnabledEl.checked = Boolean(
      settings.debug.frontendIngestThreadingEnabled,
    );
  }
  if (frontendIngestWorkerThreadsEl) {
    frontendIngestWorkerThreadsEl.value = String(
      settings.debug.frontendIngestWorkerThreads,
    );
    frontendIngestWorkerThreadsEl.disabled = !Boolean(
      settings.debug.frontendIngestThreadingEnabled,
    );
  }
  if (mapProjectionZoomXEl) {
    mapProjectionZoomXEl.value = String(settings.debug.mapProjectionZoomX);
  }
  if (mapProjectionZoomYEl) {
    mapProjectionZoomYEl.value = String(settings.debug.mapProjectionZoomY);
  }
  if (mapProjectionOffsetXEl) {
    mapProjectionOffsetXEl.value = String(settings.debug.mapProjectionOffsetX);
  }
  if (mapProjectionOffsetYEl) {
    mapProjectionOffsetYEl.value = String(settings.debug.mapProjectionOffsetY);
  }
  if (modelEl) {
    renderLlmModelOptions(settings.llm.ollamaModel);
  }
  if (apiKeyEl) {
    apiKeyEl.value = "";
    apiKeyEl.placeholder = settings.apiKeys?.ollamaApiKey
      ? "Stored key present; leave blank to keep it"
      : "Leave blank to keep the stored key";
  }
  if (activeByDefaultEl) activeByDefaultEl.checked = Boolean(settings.llm.activeByDefault);
  if (backgroundSummaryGenerationEnabledEl) {
    backgroundSummaryGenerationEnabledEl.checked = Boolean(
      settings.llm.backgroundSummaryGenerationEnabled,
    );
  }
  if (delayEl) delayEl.value = String(settings.llm.triggerDelaySeconds);
  if (maxTokensEl) maxTokensEl.value = String(settings.llm.maxSummaryTokens);
  if (timeoutSecondsEl) timeoutSecondsEl.value = String(settings.llm.ollamaRequestTimeoutSeconds);
  if (retryCountEl) retryCountEl.value = String(settings.llm.retryCount);
  if (analysisCompactionThresholdBlubsEl) {
    analysisCompactionThresholdBlubsEl.value = String(
      settings.llm.analysisCompactionThresholdBlubs,
    );
  }
  if (pluginFailureThresholdEl) {
    pluginFailureThresholdEl.value = String(
      settings.plugins?.autoDisableFailureThreshold
      || DEFAULT_SETTINGS.plugins.autoDisableFailureThreshold,
    );
  }
  if (privacyMetricsEnabledEl) {
    privacyMetricsEnabledEl.checked = Boolean(settings.privacy?.metricsEnabled);
  }
  if (privacyEndpointUrlEl) {
    privacyEndpointUrlEl.value = String(
      settings.privacy?.metricsEndpointUrl
      || DEFAULT_SETTINGS.privacy.metricsEndpointUrl,
    );
  }
  if (privacyFlushIntervalEl) {
    privacyFlushIntervalEl.value = String(
      settings.privacy?.metricsFlushIntervalSeconds
      || DEFAULT_SETTINGS.privacy.metricsFlushIntervalSeconds,
    );
  }
  if (privacyMaxQueueSizeEl) {
    privacyMaxQueueSizeEl.value = String(
      settings.privacy?.metricsMaxQueueSize
      || DEFAULT_SETTINGS.privacy.metricsMaxQueueSize,
    );
  }
  if (privacyInstallIdEl) {
    privacyInstallIdEl.value = String(
      settings.privacy?.metricsInstallId || "",
    );
  }
  if (privacyConsentStatusEl) {
    const consentStatus = window.__PACKETSNITCH_METRICS__
      && typeof window.__PACKETSNITCH_METRICS__.getConsentStatus === "function"
      ? window.__PACKETSNITCH_METRICS__.getConsentStatus()
      : null;
    if (consentStatus === "first-run") {
      privacyConsentStatusEl.textContent =
        "PacketSnitch has not yet asked whether to send anonymous diagnostics. "
        + "You can decide at any time from this panel.";
    } else if (settings.privacy?.metricsEnabled) {
      privacyConsentStatusEl.textContent =
        "Metrics are enabled. Only anonymous, allow-listed events are sent.";
    } else {
      privacyConsentStatusEl.textContent =
        "Metrics are disabled. PacketSnitch does not phone home.";
    }
  }
  syncLlmDiagnosticsIndicators();
  syncBackendDiagnosticsIndicators();
  syncMetricsDiagnosticsIndicators();
}

// Handles read settings form state.
function readSettingsFormState() {
  const themeSelectEl = getThemeSelectElement();
  const convJsonIndentEl = document.getElementById("settings-general-conv-json-indent");
  const statusResetSecondsEl = document.getElementById("settings-general-status-reset-seconds");
  const backendChunkSizeEl = document.getElementById("settings-backend-chunk-size");
  const backendWorkerThreadsEl = document.getElementById(
    "settings-backend-worker-threads",
  );
  const streamWarnThresholdEl = document.getElementById(
    "settings-general-stream-warn-packet-threshold",
  );
  const manualConvImportMaxBytesEl = document.getElementById(
    "settings-general-manual-conv-import-max-bytes",
  );
  const nmapServiceScanEnabledEl = document.getElementById(
    "settings-general-nmap-service-scan-enabled",
  );
  const checkForNewReleasesOnStartupEl = document.getElementById(
    "settings-general-check-for-new-releases-on-startup",
  );
  const backendTcpHostEl = document.getElementById("settings-backend-tcp-host");
  const backendTcpPortEl = document.getElementById("settings-backend-tcp-port");
  const backendVirusTotalApiKeyEl = document.getElementById(
    "settings-backend-virustotal-api-key",
  );
  const backendForceLegacySpawnEl = document.getElementById(
    "settings-backend-force-legacy-spawn",
  );
  const bsonGzipSessionEnabledEl = document.getElementById(
    "settings-debug-bson-gzip-session-enabled",
  );
  const ungroupedListVirtualizationEnabledEl = document.getElementById(
    "settings-debug-ungrouped-list-virtualization-enabled",
  );
  const backendHttpDataModeEnabledEl = document.getElementById(
    "settings-backend-http-data-mode-enabled",
  );
  const backendRefreshIntervalMsEl = document.getElementById(
    "settings-debug-backend-refresh-interval-ms",
  );
  const backendRefreshMinPacketsEl = document.getElementById(
    "settings-debug-backend-refresh-min-packets",
  );
  const backendJsonDataEmitIntervalMsEl = document.getElementById(
    "settings-debug-backend-json-data-emit-interval-ms",
  );
  const frontendIngestThreadingEnabledEl = document.getElementById(
    "settings-debug-frontend-ingest-threading-enabled",
  );
  const frontendIngestWorkerThreadsEl = document.getElementById(
    "settings-debug-frontend-ingest-worker-threads",
  );
  const mapProjectionZoomXEl = document.getElementById("settings-debug-map-projection-zoom-x");
  const mapProjectionZoomYEl = document.getElementById("settings-debug-map-projection-zoom-y");
  const mapProjectionOffsetXEl = document.getElementById("settings-debug-map-projection-offset-x");
  const mapProjectionOffsetYEl = document.getElementById("settings-debug-map-projection-offset-y");
  const modelEl = document.getElementById("settings-llm-model");
  const apiKeyEl = document.getElementById("settings-llm-api-key");
  const activeByDefaultEl = document.getElementById("settings-llm-active-by-default");
  const backgroundSummaryGenerationEnabledEl = document.getElementById(
    "settings-llm-background-summary-generation-enabled",
  );
  const delayEl = document.getElementById("settings-llm-delay-seconds");
  const maxTokensEl = document.getElementById("settings-llm-max-tokens");
  const timeoutSecondsEl = document.getElementById("settings-llm-timeout-seconds");
  const retryCountEl = document.getElementById("settings-llm-retry-count");
  const analysisCompactionThresholdBlubsEl = document.getElementById(
    "settings-llm-analysis-compaction-threshold-blubs",
  );
  const pluginFailureThresholdEl = document.getElementById(
    "settings-plugins-auto-disable-failure-threshold",
  );
  const privacyMetricsEnabledEl = document.getElementById(
    "settings-privacy-metrics-enabled",
  );
  const privacyEndpointUrlEl = document.getElementById(
    "settings-privacy-metrics-endpoint-url",
  );
  const privacyFlushIntervalEl = document.getElementById(
    "settings-privacy-metrics-flush-interval-seconds",
  );
  const privacyMaxQueueSizeEl = document.getElementById(
    "settings-privacy-metrics-max-queue-size",
  );
  const trimmedVirusTotalApiKey = backendVirusTotalApiKeyEl
    ? backendVirusTotalApiKeyEl.value.trim()
    : "";
  const trimmedApiKey = apiKeyEl ? apiKeyEl.value.trim() : "";
  const currentSettings = getCurrentSettings();
  return normalizeSettings({
    general: {
      themeId: themeSelectEl
        ? sanitizeThemeId(themeSelectEl.value, FALLBACK_THEME_ID)
        : DEFAULT_SETTINGS.general.themeId,
      convJsonIndentSpaces: convJsonIndentEl
        ? convJsonIndentEl.value
        : DEFAULT_SETTINGS.general.convJsonIndentSpaces,
      statusResetSeconds: statusResetSecondsEl
        ? statusResetSecondsEl.value
        : DEFAULT_SETTINGS.general.statusResetSeconds,
      backendPacketChunkSize: backendChunkSizeEl
        ? backendChunkSizeEl.value
        : DEFAULT_SETTINGS.general.backendPacketChunkSize,
      backendWorkerThreads: backendWorkerThreadsEl
        ? backendWorkerThreadsEl.value
        : DEFAULT_SETTINGS.general.backendWorkerThreads,
      streamContextWarnPacketThreshold: streamWarnThresholdEl
        ? streamWarnThresholdEl.value
        : DEFAULT_SETTINGS.general.streamContextWarnPacketThreshold,
      manualConvImportMaxBytes: manualConvImportMaxBytesEl
        ? parseManualConvImportLimitMb(manualConvImportMaxBytesEl.value)
        : DEFAULT_SETTINGS.general.manualConvImportMaxBytes,
      nmapServiceScanEnabled: nmapServiceScanEnabledEl
        ? nmapServiceScanEnabledEl.checked
        : DEFAULT_SETTINGS.general.nmapServiceScanEnabled,
      checkForNewReleasesOnStartup: checkForNewReleasesOnStartupEl
        ? checkForNewReleasesOnStartupEl.checked
        : DEFAULT_SETTINGS.general.checkForNewReleasesOnStartup,
      // Theme catalog base URL, self-signed-cert allowance, and recache
      // interval are hard-coded — never read from the UI, even if
      // older bundles still expose the inputs.
      themeServerBaseUrl: DEFAULT_SETTINGS.general.themeServerBaseUrl,
      themeRefreshIntervalHours: DEFAULT_SETTINGS.general.themeRefreshIntervalHours,
      allowInsecureTlsEndpoints: DEFAULT_SETTINGS.general.allowInsecureTlsEndpoints,
    },
    backend: {
      tcpHost: backendTcpHostEl
        ? backendTcpHostEl.value
        : DEFAULT_SETTINGS.backend.tcpHost,
      tcpPort: backendTcpPortEl
        ? backendTcpPortEl.value
        : DEFAULT_SETTINGS.backend.tcpPort,
      forceLegacySpawn: backendForceLegacySpawnEl
        ? backendForceLegacySpawnEl.checked
        : DEFAULT_SETTINGS.backend.forceLegacySpawn,
    },
    debug: {
      bsonGzipSessionEnabled: bsonGzipSessionEnabledEl
        ? bsonGzipSessionEnabledEl.checked
        : DEFAULT_SETTINGS.debug.bsonGzipSessionEnabled,
      ungroupedListVirtualizationEnabled: ungroupedListVirtualizationEnabledEl
        ? ungroupedListVirtualizationEnabledEl.checked
        : DEFAULT_SETTINGS.debug.ungroupedListVirtualizationEnabled,
      backendHttpDataModeEnabled: backendHttpDataModeEnabledEl
        ? backendHttpDataModeEnabledEl.checked
        : DEFAULT_SETTINGS.debug.backendHttpDataModeEnabled,
      backendIncrementalRefreshMinIntervalMs: backendRefreshIntervalMsEl
        ? backendRefreshIntervalMsEl.value
        : DEFAULT_SETTINGS.debug.backendIncrementalRefreshMinIntervalMs,
      backendIncrementalRefreshMinPackets: backendRefreshMinPacketsEl
        ? backendRefreshMinPacketsEl.value
        : DEFAULT_SETTINGS.debug.backendIncrementalRefreshMinPackets,
      backendJsonDataEmitMinIntervalMs: backendJsonDataEmitIntervalMsEl
        ? backendJsonDataEmitIntervalMsEl.value
        : DEFAULT_SETTINGS.debug.backendJsonDataEmitMinIntervalMs,
      frontendIngestThreadingEnabled: frontendIngestThreadingEnabledEl
        ? frontendIngestThreadingEnabledEl.checked
        : DEFAULT_SETTINGS.debug.frontendIngestThreadingEnabled,
      frontendIngestWorkerThreads: frontendIngestWorkerThreadsEl
        ? frontendIngestWorkerThreadsEl.value
        : DEFAULT_SETTINGS.debug.frontendIngestWorkerThreads,
      mapProjectionZoomX: mapProjectionZoomXEl
        ? mapProjectionZoomXEl.value
        : DEFAULT_SETTINGS.debug.mapProjectionZoomX,
      mapProjectionZoomY: mapProjectionZoomYEl
        ? mapProjectionZoomYEl.value
        : DEFAULT_SETTINGS.debug.mapProjectionZoomY,
      mapProjectionOffsetX: mapProjectionOffsetXEl
        ? mapProjectionOffsetXEl.value
        : DEFAULT_SETTINGS.debug.mapProjectionOffsetX,
      mapProjectionOffsetY: mapProjectionOffsetYEl
        ? mapProjectionOffsetYEl.value
        : DEFAULT_SETTINGS.debug.mapProjectionOffsetY,
    },
    llm: {
      ollamaModel: modelEl ? modelEl.value : DEFAULT_SETTINGS.llm.ollamaModel,
      activeByDefault: activeByDefaultEl
        ? activeByDefaultEl.checked
        : DEFAULT_SETTINGS.llm.activeByDefault,
      backgroundSummaryGenerationEnabled: backgroundSummaryGenerationEnabledEl
        ? backgroundSummaryGenerationEnabledEl.checked
        : DEFAULT_SETTINGS.llm.backgroundSummaryGenerationEnabled,
      triggerDelaySeconds: delayEl ? delayEl.value : DEFAULT_SETTINGS.llm.triggerDelaySeconds,
      maxSummaryTokens: maxTokensEl ? maxTokensEl.value : DEFAULT_SETTINGS.llm.maxSummaryTokens,
      ollamaRequestTimeoutSeconds: timeoutSecondsEl
        ? timeoutSecondsEl.value
        : DEFAULT_SETTINGS.llm.ollamaRequestTimeoutSeconds,
      retryCount: retryCountEl ? retryCountEl.value : DEFAULT_SETTINGS.llm.retryCount,
      analysisCompactionThresholdBlubs: analysisCompactionThresholdBlubsEl
        ? analysisCompactionThresholdBlubsEl.value
        : DEFAULT_SETTINGS.llm.analysisCompactionThresholdBlubs,
    },
    apiKeys: {
      ollamaApiKey: trimmedApiKey || currentSettings.apiKeys?.ollamaApiKey || "",
      virusTotalApiKey:
        trimmedVirusTotalApiKey || currentSettings.apiKeys?.virusTotalApiKey || "",
    },
    plugins: {
      autoDisableFailureThreshold: pluginFailureThresholdEl
        ? pluginFailureThresholdEl.value
        : DEFAULT_SETTINGS.plugins.autoDisableFailureThreshold,
      perPluginFailureThreshold:
        currentSettings?.plugins?.perPluginFailureThreshold
          && typeof currentSettings.plugins.perPluginFailureThreshold === "object"
          ? currentSettings.plugins.perPluginFailureThreshold
          : {},
    },
    privacy: {
      metricsEnabled: privacyMetricsEnabledEl
        ? privacyMetricsEnabledEl.checked
        : DEFAULT_SETTINGS.privacy.metricsEnabled,
      metricsEndpointUrl: privacyEndpointUrlEl
        ? privacyEndpointUrlEl.value.trim()
        : DEFAULT_SETTINGS.privacy.metricsEndpointUrl,
      metricsFlushIntervalSeconds: privacyFlushIntervalEl
        ? privacyFlushIntervalEl.value
        : DEFAULT_SETTINGS.privacy.metricsFlushIntervalSeconds,
      metricsMaxQueueSize: privacyMaxQueueSizeEl
        ? privacyMaxQueueSizeEl.value
        : DEFAULT_SETTINGS.privacy.metricsMaxQueueSize,
      // Install ID is generated on first opt-in and never edited by
      // the user; preserve whatever the loaded settings had.
      metricsInstallId:
        currentSettings?.privacy?.metricsInstallId
        || DEFAULT_SETTINGS.privacy.metricsInstallId,
    },
  });
}

// Sets settings status.
function setSettingsStatus(message) {
  const statusEl = document.getElementById("settings-status");
  if (statusEl) {
    statusEl.textContent = message;
  }
  statusUpdate("Status: " + message);
}

// Formats settings log value.
function formatSettingsLogValue(value) {
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value == null) {
    return "null";
  }
  try {
    return JSON.stringify(value);
  } catch (_error) {
    return String(value);
  }
}

// Formats manual conv import limit mb.
function formatManualConvImportLimitMb(bytes) {
  const megabytes = (Number(bytes) || 0) / (1024 * 1024);
  return Number(megabytes.toFixed(3)).toString();
}

// Parses manual conv import limit mb.
function parseManualConvImportLimitMb(rawValue) {
  const parsed = Number.parseFloat(String(rawValue ?? ""));
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_SETTINGS.general.manualConvImportMaxBytes;
  }
  return Math.max(1024, Math.round(parsed * 1024 * 1024));
}

function getPluginManagerListElement() {
  return document.getElementById("settings-plugins-list");
}

function getPluginCapabilityPanelMetaElement() {
  return document.getElementById("settings-plugins-selected-meta");
}

function getPluginCapabilityPanelListElement() {
  return document.getElementById("settings-plugins-selected-capabilities");
}

function getPluginFailureThresholdInputElement() {
  return document.getElementById("settings-plugins-auto-disable-failure-threshold");
}

function getPluginErrorPanelElement() {
  return document.getElementById("settings-plugins-error-panel");
}

function normalizePluginCapabilityList(capabilities) {
  if (!Array.isArray(capabilities)) return [];
  const seen = new Set();
  return capabilities
    .map((entry) => String(entry || "").trim())
    .filter((entry) => {
      if (!entry || seen.has(entry)) {
        return false;
      }
      seen.add(entry);
      return true;
    });
}

function getPluginCapabilityCatalogMap() {
  const map = new Map();
  if (!window.pluginapi || typeof window.pluginapi.getCapabilityCatalog !== "function") {
    return map;
  }
  const catalog = window.pluginapi.getCapabilityCatalog();
  if (!Array.isArray(catalog)) {
    return map;
  }
  catalog.forEach((entry) => {
    const id = String(entry?.capability || "").trim();
    const description = String(entry?.description || "").trim();
    if (!id || !description) return;
    map.set(id, description);
  });
  return map;
}

function createPluginCapabilityListItem(capabilityId, capabilityDescription = "") {
  const itemEl = document.createElement("li");
  const idEl = document.createElement("div");
  idEl.className = "plugin-capability-item-id";
  idEl.textContent = capabilityId;
  itemEl.appendChild(idEl);
  if (capabilityDescription) {
    const descEl = document.createElement("div");
    descEl.className = "plugin-capability-item-desc";
    descEl.textContent = capabilityDescription;
    itemEl.appendChild(descEl);
  }
  return itemEl;
}

function renderSelectedPluginCapabilities(pluginEntry) {
  const metaEl = getPluginCapabilityPanelMetaElement();
  const listEl = getPluginCapabilityPanelListElement();
  if (!metaEl || !listEl) return;
  listEl.innerHTML = "";
  if (!pluginEntry) {
    metaEl.textContent = "Select a plugin to view capabilities.";
    return;
  }

  const pluginName = String(pluginEntry.pluginName || "Plugin").trim() || "Plugin";
  const pluginVersion = String(pluginEntry.pluginVersion || "").trim();
  metaEl.textContent = `${pluginName}${pluginVersion ? ` v${pluginVersion}` : ""}`;

  const normalizedCapabilities = normalizePluginCapabilityList(pluginEntry.capabilities);
  if (!normalizedCapabilities.length) {
    const emptyEl = document.createElement("li");
    emptyEl.textContent = "No declared capabilities";
    listEl.appendChild(emptyEl);
    return;
  }

  const capabilityDescriptions = getPluginCapabilityCatalogMap();
  normalizedCapabilities.forEach((capabilityId) => {
    const capabilityDescription = capabilityDescriptions.get(capabilityId) || "";
    listEl.appendChild(createPluginCapabilityListItem(capabilityId, capabilityDescription));
  });
}

function requestPluginInstallCapabilityDialog(inspectedPlugin = {}) {
  const dialogEl = document.getElementById("plugin-install-capability-dialog");
  const titleEl = document.getElementById("plugin-install-capability-dialog-title");
  const descriptionEl = document.getElementById("plugin-install-capability-dialog-description");
  const listEl = document.getElementById("plugin-install-capability-dialog-list");
  const confirmBtn = document.getElementById("plugin-install-capability-confirm-btn");
  if (!dialogEl || !titleEl || !descriptionEl || !listEl || !confirmBtn) {
    return Promise.resolve(false);
  }

  if (activePluginInstallCapabilityDialogResolver) {
    const resolve = activePluginInstallCapabilityDialogResolver;
    activePluginInstallCapabilityDialogResolver = null;
    resolve(false);
  }

  const pluginName = String(inspectedPlugin.pluginName || "Plugin").trim() || "Plugin";
  const pluginVersion = String(inspectedPlugin.pluginVersion || "").trim();
  const normalizedCapabilities = normalizePluginCapabilityList(inspectedPlugin.capabilities);
  const capabilityDescriptions = getPluginCapabilityCatalogMap();

  titleEl.textContent = `Install ${pluginName}${pluginVersion ? ` v${pluginVersion}` : ""}`;
  descriptionEl.textContent = "Review requested plugin capabilities before install. Select Install and Enable to continue.";
  listEl.innerHTML = "";
  if (!normalizedCapabilities.length) {
    listEl.appendChild(createPluginCapabilityListItem("No declared capabilities", ""));
  } else {
    normalizedCapabilities.forEach((capabilityId) => {
      const capabilityDescription = capabilityDescriptions.get(capabilityId) || "";
      listEl.appendChild(createPluginCapabilityListItem(capabilityId, capabilityDescription));
    });
  }

  dialogEl.hidden = false;
  confirmBtn.focus();
  return new Promise((resolve) => {
    activePluginInstallCapabilityDialogResolver = resolve;
  });
}

function resolvePluginInstallCapabilityDialog(isAllowed) {
  const dialogEl = document.getElementById("plugin-install-capability-dialog");
  if (dialogEl) {
    dialogEl.hidden = true;
  }
  if (!activePluginInstallCapabilityDialogResolver) {
    return;
  }
  const resolve = activePluginInstallCapabilityDialogResolver;
  activePluginInstallCapabilityDialogResolver = null;
  resolve(Boolean(isAllowed));
}

function renderPluginErrorPanel() {
  const panelEl = getPluginErrorPanelElement();
  if (!panelEl) return;
  if (!Array.isArray(pluginErrorEntries) || pluginErrorEntries.length === 0) {
    panelEl.textContent = "No plugin errors.";
    return;
  }
  const lines = pluginErrorEntries.slice(0, 20).map((entry) => {
    const when = entry?.at || new Date().toISOString();
    const message = String(entry?.message || "Unknown plugin error");
    return `[${when}] ${message}`;
  });
  panelEl.textContent = lines.join("\n");
}

function recordPluginError(message) {
  const normalized = String(message || "").trim();
  if (!normalized) return;
  pluginErrorEntries.unshift({
    at: new Date().toISOString(),
    message: normalized,
  });
  if (pluginErrorEntries.length > 100) {
    pluginErrorEntries = pluginErrorEntries.slice(0, 100);
  }
  renderPluginErrorPanel();
}

function clearPluginErrors() {
  pluginErrorEntries = [];
  renderPluginErrorPanel();
}

function setPluginManagerMessage(message) {
  const listEl = getPluginManagerListElement();
  if (!listEl) return;
  renderSelectedPluginCapabilities(null);
  listEl.innerHTML = `<div class="settings-help-text">${escapeHtml(String(message || ""))}</div>`;
}

function resolvePluginEntryPath(pluginEntry) {
  const installPath = typeof pluginEntry?.installPath === "string"
    ? pluginEntry.installPath
    : "";
  const manifestEntry = typeof pluginEntry?.manifest?.entry === "string"
    ? pluginEntry.manifest.entry.trim()
    : "";
  const entryFile = manifestEntry || "plugin.js";
  if (!installPath) {
    throw new Error("Plugin install path is missing");
  }
  if (
    entryFile.includes("..")
    || entryFile.startsWith("/")
    || /^[a-zA-Z]:[\\/]/.test(entryFile)
  ) {
    throw new Error(`Unsafe plugin entry path: ${entryFile}`);
  }
  const normalizedInstallPath = String(installPath).replace(/\\/g, "/").replace(/\/+$/, "");
  const normalizedEntry = String(entryFile).replace(/\\/g, "/").replace(/^\/+/, "");
  return `${normalizedInstallPath}/${normalizedEntry}`;
}

async function reportPluginRuntimeFailure(pluginEntry, error) {
  const pluginId = String(pluginEntry?.pluginId || "").trim();
  const errorMessage = error?.message || String(error || "Unknown plugin runtime error");
  recordPluginError(`Plugin ${pluginId || "unknown"} runtime error: ${errorMessage}`);
  if (window.pluginapi && typeof window.pluginapi.recordFailure === "function" && pluginId) {
    try {
      await window.pluginapi.recordFailure({
        pluginId,
        critical: true,
      });
    } catch (_reportError) {
      // Ignore failure-report errors to avoid loops.
    }
  }
}

async function loadInstalledPluginEntry(pluginEntry, { forceReload = false } = {}) {
  const pluginId = String(pluginEntry?.pluginId || "").trim();
  if (!pluginId) return;
  if (!pluginEntry?.enabled) {
    loadedPluginIds.delete(pluginId);
    return;
  }
  if (!forceReload && loadedPluginIds.has(pluginId)) {
    return;
  }

  try {
    if (!window.pluginapi || typeof window.pluginapi.loadRuntime !== "function") {
      throw new Error("Plugin runtime bridge is unavailable");
    }

    const runtimeResult = await window.pluginapi.loadRuntime({
      plugin: pluginEntry,
      forceReload,
      packetsnitchVersion: String(psVer || "").trim() || "unknown",
    });
    if (!runtimeResult?.success) {
      throw new Error(runtimeResult?.error || "Plugin runtime failed to initialize");
    }
    const entryPath = runtimeResult?.entryPath || resolvePluginEntryPath(pluginEntry);

    loadedPluginIds.add(pluginId);
    writeLogEntry(`Plugin loaded id=${JSON.stringify(pluginId)} entry=${JSON.stringify(entryPath)}`);
  } catch (error) {
    await reportPluginRuntimeFailure(pluginEntry, error);
    doError(`Plugin ${pluginId} failed to load: ${error?.message || error}`);
  }
}

async function loadEnabledInstalledPlugins(pluginEntries = cachedPluginRegistry) {
  if (!Array.isArray(pluginEntries) || pluginEntries.length === 0) return;
  for (const pluginEntry of pluginEntries) {
    if (!pluginEntry?.enabled) continue;
    if (pluginEntry?.compatibleWithCurrentPacketsnitch === false) continue;
    await loadInstalledPluginEntry(pluginEntry);
  }
}

function createPluginRowElement(pluginEntry) {
  const rowEl = document.createElement("div");
  const isSelected = pluginEntry.pluginId === selectedPluginId;
  rowEl.className = `settings-help-text settings-plugin-row${isSelected ? " selected" : ""}`;
  rowEl.tabIndex = 0;
  rowEl.setAttribute("role", "button");
  rowEl.setAttribute("aria-pressed", isSelected ? "true" : "false");
  rowEl.addEventListener("click", () => {
    selectedPluginId = String(pluginEntry.pluginId || "");
    renderPluginRegistryView(cachedPluginRegistry);
  });
  rowEl.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    selectedPluginId = String(pluginEntry.pluginId || "");
    renderPluginRegistryView(cachedPluginRegistry);
  });

  const titleEl = document.createElement("div");
  titleEl.style.fontWeight = "600";
  titleEl.textContent = `${pluginEntry.pluginName} (${pluginEntry.pluginVersion})`;
  rowEl.appendChild(titleEl);

  const metaEl = document.createElement("div");
  metaEl.textContent = `Address: ${pluginEntry.address} | Failures: ${pluginEntry.failureCount || 0}${pluginEntry.disabledReason ? ` | Disabled: ${pluginEntry.disabledReason}` : ""}`;
  rowEl.appendChild(metaEl);

  const controlsEl = document.createElement("div");
  controlsEl.className = "settings-actions-row";
  controlsEl.style.marginTop = "0.35rem";
  controlsEl.addEventListener("click", (event) => {
    event.stopPropagation();
  });
  controlsEl.addEventListener("keydown", (event) => {
    event.stopPropagation();
  });

  const enabledLabel = document.createElement("label");
  enabledLabel.className = "settings-checkbox-row";
  enabledLabel.style.marginRight = "0.5rem";
  const enabledInput = document.createElement("input");
  enabledInput.type = "checkbox";
  enabledInput.checked = Boolean(pluginEntry.enabled);
  enabledInput.addEventListener("change", async () => {
    if (!window.pluginapi) return;
    const result = await window.pluginapi.setEnabled({
      pluginId: pluginEntry.pluginId,
      enabled: enabledInput.checked,
    });
    if (!result?.success) {
      const errorMessage = result?.error || "Unable to change plugin enabled state";
      recordPluginError(errorMessage);
      doError(errorMessage);
      enabledInput.checked = Boolean(pluginEntry.enabled);
      return;
    }
    if (!enabledInput.checked) {
      if (typeof window.pluginapi.unloadRuntime === "function") {
        await window.pluginapi.unloadRuntime({
          pluginId: pluginEntry.pluginId,
          plugin: result?.plugin || pluginEntry,
        });
      }
      loadedPluginIds.delete(pluginEntry.pluginId);
    } else {
      await loadInstalledPluginEntry(result?.plugin || pluginEntry, { forceReload: true });
    }
    await refreshPluginRegistryView();
  });
  enabledLabel.appendChild(enabledInput);
  enabledLabel.appendChild(document.createTextNode("Enabled"));
  controlsEl.appendChild(enabledLabel);

  const priorityInput = document.createElement("input");
  priorityInput.type = "number";
  priorityInput.min = "0";
  priorityInput.step = "1";
  priorityInput.title = "Plugin priority";
  priorityInput.value = String(Number(pluginEntry.priority) || 100);
  priorityInput.style.width = "5rem";
  priorityInput.addEventListener("change", async () => {
    if (!window.pluginapi) return;
    const result = await window.pluginapi.setPriority({
      pluginId: pluginEntry.pluginId,
      priority: Number(priorityInput.value),
    });
    if (!result?.success) {
      const errorMessage = result?.error || "Unable to update plugin priority";
      recordPluginError(errorMessage);
      doError(errorMessage);
      return;
    }
    await refreshPluginRegistryView();
  });
  controlsEl.appendChild(priorityInput);

  const thresholdInput = document.createElement("input");
  thresholdInput.type = "number";
  thresholdInput.min = "1";
  thresholdInput.step = "1";
  thresholdInput.placeholder = "Threshold";
  thresholdInput.title = "Per-plugin failure threshold override";
  thresholdInput.value = pluginEntry.failureThresholdOverride
    ? String(pluginEntry.failureThresholdOverride)
    : "";
  thresholdInput.style.width = "6rem";
  thresholdInput.addEventListener("change", async () => {
    if (!window.pluginapi) return;
    const rawValue = thresholdInput.value.trim();
    const result = await window.pluginapi.setFailureThreshold({
      pluginId: pluginEntry.pluginId,
      failureThresholdOverride: rawValue ? Number(rawValue) : null,
    });
    if (!result?.success) {
      const errorMessage = result?.error || "Unable to update plugin failure threshold";
      recordPluginError(errorMessage);
      doError(errorMessage);
      return;
    }
    await refreshPluginRegistryView();
  });
  controlsEl.appendChild(thresholdInput);

  const resetFailuresBtn = document.createElement("button");
  resetFailuresBtn.type = "button";
  resetFailuresBtn.textContent = "Reset Failures";
  resetFailuresBtn.addEventListener("click", async () => {
    if (!window.pluginapi) return;
    const result = await window.pluginapi.resetFailures({ pluginId: pluginEntry.pluginId });
    if (!result?.success) {
      const errorMessage = result?.error || "Unable to reset plugin failures";
      recordPluginError(errorMessage);
      doError(errorMessage);
      return;
    }
    await refreshPluginRegistryView();
  });
  controlsEl.appendChild(resetFailuresBtn);

  const uninstallBtn = document.createElement("button");
  uninstallBtn.type = "button";
  uninstallBtn.textContent = "Uninstall";
  uninstallBtn.addEventListener("click", async () => {
    if (!window.pluginapi) return;
    if (typeof window.pluginapi.unloadRuntime === "function") {
      await window.pluginapi.unloadRuntime({ pluginId: pluginEntry.pluginId, plugin: pluginEntry });
    }
    const result = await window.pluginapi.uninstall({ pluginId: pluginEntry.pluginId });
    if (!result?.success) {
      const errorMessage = result?.error || "Unable to uninstall plugin";
      recordPluginError(errorMessage);
      doError(errorMessage);
      return;
    }
    loadedPluginIds.delete(pluginEntry.pluginId);
    await refreshPluginRegistryView();
  });
  controlsEl.appendChild(uninstallBtn);

  rowEl.appendChild(controlsEl);
  return rowEl;
}

function renderPluginRegistryView(pluginEntries = []) {
  const listEl = getPluginManagerListElement();
  if (!listEl) return;
  listEl.innerHTML = "";
  if (!Array.isArray(pluginEntries) || pluginEntries.length === 0) {
    selectedPluginId = "";
    renderSelectedPluginCapabilities(null);
    setPluginManagerMessage("No plugins installed.");
    return;
  }
  const sortedEntries = [...pluginEntries].sort((a, b) => {
    const aPriority = Number(a?.priority) || 0;
    const bPriority = Number(b?.priority) || 0;
    if (aPriority !== bPriority) return bPriority - aPriority;
    return String(a?.pluginName || "").localeCompare(String(b?.pluginName || ""));
  });

  const selectedEntry = sortedEntries.find((pluginEntry) => pluginEntry.pluginId === selectedPluginId)
    || sortedEntries[0];
  selectedPluginId = String(selectedEntry?.pluginId || "");

  sortedEntries.forEach((pluginEntry) => {
    listEl.appendChild(createPluginRowElement(pluginEntry));
  });

  renderSelectedPluginCapabilities(selectedEntry || null);
}

async function refreshPluginRegistryView() {
  if (!window.pluginapi || typeof window.pluginapi.list !== "function") {
    const errorMessage = "Plugin API is unavailable in this build.";
    recordPluginError(errorMessage);
    setPluginManagerMessage(errorMessage);
    return;
  }
  try {
    const response = await window.pluginapi.list();
    if (!response?.success) {
      const errorMessage = response?.error || "Unable to load plugin list.";
      recordPluginError(errorMessage);
      setPluginManagerMessage(errorMessage);
      return;
    }
    cachedPluginRegistry = Array.isArray(response.plugins) ? response.plugins : [];
    renderPluginRegistryView(cachedPluginRegistry);
    await loadEnabledInstalledPlugins(cachedPluginRegistry);
  } catch (error) {
    const errorMessage = error?.message || "Unable to load plugin list.";
    recordPluginError(errorMessage);
    setPluginManagerMessage(errorMessage);
  }
}

async function installPluginFromSettingsAction() {
  if (!window.pluginapi || typeof window.pluginapi.selectZip !== "function") {
    const errorMessage = "Plugin API is unavailable.";
    recordPluginError(errorMessage);
    setSettingsStatus(errorMessage);
    return;
  }
  const selectedZip = await window.pluginapi.selectZip();
  if (!selectedZip) {
    return;
  }

  if (typeof window.pluginapi.inspectZip === "function") {
    let inspectResult = null;
    try {
      inspectResult = await window.pluginapi.inspectZip({ zipPath: selectedZip });
    } catch (inspectError) {
      const inspectErrorMessage = inspectError?.message || String(inspectError || "");
      if (!inspectErrorMessage.includes("No handler registered for 'plugins-inspect-zip'")) {
        throw inspectError;
      }
      // Older main process builds may not have the inspect handler yet.
      inspectResult = {
        success: true,
        plugin: {
          pluginName: "Plugin",
          pluginVersion: "",
          capabilities: ["Permissions unavailable in this app session"],
        },
      };
    }
    if (!inspectResult?.success) {
      const errorMessage = inspectResult?.error || "Unable to inspect plugin permissions.";
      recordPluginError(errorMessage);
      doError(errorMessage);
      setSettingsStatus("Plugin install canceled.");
      return;
    }

    const inspectedPlugin = inspectResult?.plugin || {};
    const isAllowed = await requestPluginInstallCapabilityDialog(inspectedPlugin);
    if (!isAllowed) {
      setSettingsStatus("Plugin install canceled by user.");
      return;
    }
  }

  setSettingsStatus("Installing plugin...");
  const installResult = await window.pluginapi.install({ zipPath: selectedZip });
  if (!installResult?.success) {
    const errorMessage = installResult?.error || "Plugin install failed";
    recordPluginError(errorMessage);
    doError(errorMessage);
    setSettingsStatus("Plugin install failed.");
    return;
  }
  writeLogEntry(
    `Plugin installed id=${JSON.stringify(installResult?.plugin?.pluginId || "unknown")} address=${JSON.stringify(installResult?.plugin?.address || "unknown")}`,
  );
  setSettingsStatus("Plugin installed.");
  if (installResult?.plugin?.enabled) {
    await loadInstalledPluginEntry(installResult.plugin, { forceReload: true });
  }
  await refreshPluginRegistryView();
}

// Builds settings change summaries.
function buildSettingsChangeSummaries(previousSettings, nextSettings) {
  const changes = [];
  const previousGeneral = previousSettings?.general || {};
  const nextGeneral = nextSettings?.general || {};
  const previousBackend = previousSettings?.backend || {};
  const nextBackend = nextSettings?.backend || {};
  const previousDebug = previousSettings?.debug || {};
  const nextDebug = nextSettings?.debug || {};
  const previousLlm = previousSettings?.llm || {};
  const nextLlm = nextSettings?.llm || {};
  const previousPlugins = previousSettings?.plugins || {};
  const nextPlugins = nextSettings?.plugins || {};

  const pushChange = (label, beforeValue, afterValue, { redacted = false } = {}) => {
    if (beforeValue === afterValue) {
      return;
    }
    if (redacted) {
      changes.push(`${label}=updated`);
      return;
    }
    changes.push(
      `${label}:${formatSettingsLogValue(beforeValue)}->${formatSettingsLogValue(afterValue)}`,
    );
  };

  pushChange("themeId", previousGeneral.themeId, nextGeneral.themeId);
  pushChange(
    "convJsonIndentSpaces",
    previousGeneral.convJsonIndentSpaces,
    nextGeneral.convJsonIndentSpaces,
  );
  pushChange(
    "statusResetSeconds",
    previousGeneral.statusResetSeconds,
    nextGeneral.statusResetSeconds,
  );
  pushChange(
    "backendPacketChunkSize",
    previousGeneral.backendPacketChunkSize,
    nextGeneral.backendPacketChunkSize,
  );
  pushChange(
    "backendWorkerThreads",
    previousGeneral.backendWorkerThreads,
    nextGeneral.backendWorkerThreads,
  );
  pushChange(
    "streamContextWarnPacketThreshold",
    previousGeneral.streamContextWarnPacketThreshold,
    nextGeneral.streamContextWarnPacketThreshold,
  );
  pushChange(
    "manualConvImportMaxBytes",
    previousGeneral.manualConvImportMaxBytes,
    nextGeneral.manualConvImportMaxBytes,
  );
  pushChange(
    "nmapServiceScanEnabled",
    previousGeneral.nmapServiceScanEnabled,
    nextGeneral.nmapServiceScanEnabled,
  );
  pushChange("backendTcpHost", previousBackend.tcpHost, nextBackend.tcpHost);
  pushChange("backendTcpPort", previousBackend.tcpPort, nextBackend.tcpPort);
  pushChange(
    "backendVirusTotalApiKey",
    previousBackend.virusTotalApiKey,
    nextBackend.virusTotalApiKey,
    { redacted: true },
  );
  pushChange(
    "backendForceLegacySpawn",
    previousBackend.forceLegacySpawn,
    nextBackend.forceLegacySpawn,
  );
  pushChange(
    "ungroupedListVirtualizationEnabled",
    previousDebug.ungroupedListVirtualizationEnabled,
    nextDebug.ungroupedListVirtualizationEnabled,
  );
  pushChange(
    "backendHttpDataModeEnabled",
    previousDebug.backendHttpDataModeEnabled,
    nextDebug.backendHttpDataModeEnabled,
  );
  pushChange(
    "backendIncrementalRefreshMinIntervalMs",
    previousDebug.backendIncrementalRefreshMinIntervalMs,
    nextDebug.backendIncrementalRefreshMinIntervalMs,
  );
  pushChange(
    "backendIncrementalRefreshMinPackets",
    previousDebug.backendIncrementalRefreshMinPackets,
    nextDebug.backendIncrementalRefreshMinPackets,
  );
  pushChange(
    "backendJsonDataEmitMinIntervalMs",
    previousDebug.backendJsonDataEmitMinIntervalMs,
    nextDebug.backendJsonDataEmitMinIntervalMs,
  );
  pushChange(
    "frontendIngestThreadingEnabled",
    previousDebug.frontendIngestThreadingEnabled,
    nextDebug.frontendIngestThreadingEnabled,
  );
  pushChange(
    "frontendIngestWorkerThreads",
    previousDebug.frontendIngestWorkerThreads,
    nextDebug.frontendIngestWorkerThreads,
  );
  pushChange(
    "mapProjectionZoomX",
    previousDebug.mapProjectionZoomX,
    nextDebug.mapProjectionZoomX,
  );
  pushChange(
    "mapProjectionZoomY",
    previousDebug.mapProjectionZoomY,
    nextDebug.mapProjectionZoomY,
  );
  pushChange(
    "mapProjectionOffsetX",
    previousDebug.mapProjectionOffsetX,
    nextDebug.mapProjectionOffsetX,
  );
  pushChange(
    "mapProjectionOffsetY",
    previousDebug.mapProjectionOffsetY,
    nextDebug.mapProjectionOffsetY,
  );
  pushChange("ollamaModel", previousLlm.ollamaModel, nextLlm.ollamaModel);
  pushChange(
    "ollamaApiKey",
    previousLlm.ollamaApiKey,
    nextLlm.ollamaApiKey,
    { redacted: true },
  );
  pushChange(
    "activeByDefault",
    previousLlm.activeByDefault,
    nextLlm.activeByDefault,
  );
  pushChange(
    "backgroundSummaryGenerationEnabled",
    previousLlm.backgroundSummaryGenerationEnabled,
    nextLlm.backgroundSummaryGenerationEnabled,
  );
  pushChange(
    "triggerDelaySeconds",
    previousLlm.triggerDelaySeconds,
    nextLlm.triggerDelaySeconds,
  );
  pushChange(
    "maxSummaryTokens",
    previousLlm.maxSummaryTokens,
    nextLlm.maxSummaryTokens,
  );
  pushChange(
    "ollamaRequestTimeoutSeconds",
    previousLlm.ollamaRequestTimeoutSeconds,
    nextLlm.ollamaRequestTimeoutSeconds,
  );
  pushChange(
    "retryCount",
    previousLlm.retryCount,
    nextLlm.retryCount,
  );
  pushChange(
    "pluginAutoDisableFailureThreshold",
    previousPlugins.autoDisableFailureThreshold,
    nextPlugins.autoDisableFailureThreshold,
  );

  return changes;
}

// Handles log settings mutation.
function logSettingsMutation(actionLabel, previousSettings, nextSettings) {
  const changes = buildSettingsChangeSummaries(previousSettings, nextSettings);
  if (changes.length === 0) {
    writeLogEntry(`${actionLabel} with no setting changes`);
    return;
  }
  writeLogEntry(`${actionLabel} ${changes.join(", ")}`);
}

async function persistSettingsFromForm({ resetToDefaults = false } = {}) {
  if (!window.settingsapi || typeof window.settingsapi.save !== "function") {
    setSettingsStatus("Settings storage is unavailable.");
    return null;
  }
  const previousSettings = getCurrentSettings();
  const nextSettings = resetToDefaults ? cloneDefaultSettings() : readSettingsFormState();
  // Invalidate the VirusTotal diagnostics cache so a saved/cleared API key
  // is verified immediately rather than masked by a recent successful fetch.
  if (
    previousSettings?.apiKeys?.virusTotalApiKey !==
    nextSettings?.apiKeys?.virusTotalApiKey
  ) {
    invalidateVirusTotalDiagnosticsCache();
  }
  const savedSettings = await window.settingsapi.save(nextSettings);
  setCurrentSettings(savedSettings);
  syncCaptureIngestWorkersFromSettings();
  await initializeBackendServiceFromSettings(savedSettings);
  syncRuntimeLlmToggleFromSettings();
  // Re-render the Session Threat Score card so the LLM "Get Assessment"
  // button tracks the current LLM toggle state.
  if (typeof subnetCalculatorPanel?.recomputeSessionThreatScore === "function") {
    subnetCalculatorPanel.recomputeSessionThreatScore({ silent: true });
  }
  await applyThemeById(savedSettings.general.themeId);
  syncSettingsFormFromState();
  logSettingsMutation(
    resetToDefaults ? "Settings restored defaults" : "Settings saved",
    previousSettings,
    savedSettings,
  );
  setSettingsStatus(resetToDefaults ? "Defaults restored." : "Settings saved.");
  return savedSettings;
}

async function loadPersistedSettings() {
  if (!window.settingsapi || typeof window.settingsapi.get !== "function") {
    syncSettingsFormFromState();
    return getCurrentSettings();
  }
  const loadedSettings = await window.settingsapi.get();
  setCurrentSettings(loadedSettings);
  syncCaptureIngestWorkersFromSettings();
  await initializeBackendServiceFromSettings(loadedSettings);
  syncRuntimeLlmToggleFromSettings();
  await applyThemeById(loadedSettings.general.themeId);
  syncSettingsFormFromState();
  return getCurrentSettings();
}

// Returns llmsummary delay ms.
function getLLMSummaryDelayMs() {
  return (
    Math.max(
      0,
      Number(getCurrentSettings()?.llm?.triggerDelaySeconds) ||
      DEFAULT_SETTINGS.llm.triggerDelaySeconds,
    ) * 1000
  );
}

// Returns conv json indent spaces.
function getConvJsonIndentSpaces() {
  return Math.max(
    0,
    Number(getCurrentSettings()?.general?.convJsonIndentSpaces) ||
    DEFAULT_SETTINGS.general.convJsonIndentSpaces,
  );
}

// Returns status reset delay ms.
function getStatusResetDelayMs() {
  return (
    Math.max(
      1,
      Number(getCurrentSettings()?.general?.statusResetSeconds) ||
      DEFAULT_SETTINGS.general.statusResetSeconds,
    ) * 1000
  );
}

// Returns backend packet chunk size.
function getBackendPacketChunkSize() {
  return Math.max(
    1,
    Number(getCurrentSettings()?.general?.backendPacketChunkSize) ||
    DEFAULT_SETTINGS.general.backendPacketChunkSize,
  );
}

// Returns backend worker threads.
function getBackendWorkerThreads() {
  return Math.max(
    1,
    Number(getCurrentSettings()?.general?.backendWorkerThreads) ||
    DEFAULT_SETTINGS.general.backendWorkerThreads,
  );
}

// Returns stream context warn packet threshold.
function getStreamContextWarnPacketThreshold() {
  return Math.max(
    5,
    Number(getCurrentSettings()?.general?.streamContextWarnPacketThreshold) ||
    DEFAULT_SETTINGS.general.streamContextWarnPacketThreshold,
  );
}

function getBackendIncrementalRefreshMinIntervalMs() {
  return Math.max(
    100,
    Number(getCurrentSettings()?.debug?.backendIncrementalRefreshMinIntervalMs) ||
    DEFAULT_SETTINGS.debug.backendIncrementalRefreshMinIntervalMs,
  );
}

function getBackendIncrementalRefreshMinPackets() {
  return Math.max(
    100,
    Number(getCurrentSettings()?.debug?.backendIncrementalRefreshMinPackets) ||
    DEFAULT_SETTINGS.debug.backendIncrementalRefreshMinPackets,
  );
}

function isFrontendIngestThreadingEnabled() {
  const setting = getCurrentSettings()?.debug?.frontendIngestThreadingEnabled;
  const enabled =
    typeof setting === "boolean"
      ? setting
      : DEFAULT_SETTINGS.debug.frontendIngestThreadingEnabled;
  return enabled && typeof Worker === "function";
}

function getFrontendIngestWorkerThreads() {
  const configured = Math.max(
    1,
    Number(getCurrentSettings()?.debug?.frontendIngestWorkerThreads) ||
    DEFAULT_SETTINGS.debug.frontendIngestWorkerThreads,
  );
  const hardwareThreads =
    typeof navigator !== "undefined"
      ? Number(navigator.hardwareConcurrency) || configured
      : configured;
  return Math.max(1, Math.min(configured, Math.max(1, hardwareThreads * 2)));
}

// Returns backend transport options from settings.
function getBackendTransportOptionsFromSettings(settings = getCurrentSettings()) {
  return {
    tcpHost: String(settings?.backend?.tcpHost || DEFAULT_SETTINGS.backend.tcpHost),
    tcpPort: Number(settings?.backend?.tcpPort || DEFAULT_SETTINGS.backend.tcpPort),
    forceLegacySpawn: Boolean(settings?.backend?.forceLegacySpawn),
    useHttpDataSnapshots: Boolean(settings?.debug?.backendHttpDataModeEnabled),
    jsonDataEmitMinIntervalMs: Math.max(
      250,
      Number(settings?.debug?.backendJsonDataEmitMinIntervalMs)
      || DEFAULT_SETTINGS.debug.backendJsonDataEmitMinIntervalMs,
    ),
  };
}

async function initializeBackendServiceFromSettings(settings = getCurrentSettings()) {
  if (!window.snitchapi || typeof window.snitchapi.initBackendService !== "function") {
    return null;
  }

  const backendOptions = getBackendTransportOptionsFromSettings(settings);
  try {
    const result = await window.snitchapi.initBackendService(backendOptions);
    writeLogEntry(
      `Backend service init requested tcp_host=${JSON.stringify(backendOptions.tcpHost)} tcp_port=${backendOptions.tcpPort} force_legacy=${backendOptions.forceLegacySpawn} data_mode=${backendOptions.useHttpDataSnapshots} json_data_emit_interval_ms=${backendOptions.jsonDataEmitMinIntervalMs} ready=${Boolean(result?.ready)} mode=${JSON.stringify(result?.mode || "unknown")}`,
    );
    await refreshBackendDiagnostics({ ensureReady: false });
    return result;
  } catch (error) {
    logErrorEntry("backend-init", error);
    await refreshBackendDiagnostics({ ensureReady: false });
    return null;
  }
}

// Sets settings subtab.
function setSettingsSubtab(tabName = SETTINGS_SUBTAB_GENERAL) {
  const nextTab =
    tabName === SETTINGS_SUBTAB_LLM
      ? SETTINGS_SUBTAB_LLM
      : tabName === SETTINGS_SUBTAB_API_KEYS
        ? SETTINGS_SUBTAB_API_KEYS
        : tabName === SETTINGS_SUBTAB_BACKEND
          ? SETTINGS_SUBTAB_BACKEND
          : tabName === SETTINGS_SUBTAB_DEBUG
            ? SETTINGS_SUBTAB_DEBUG
            : tabName === SETTINGS_SUBTAB_PLUGINS
              ? SETTINGS_SUBTAB_PLUGINS
              : tabName === SETTINGS_SUBTAB_THEMES
                ? SETTINGS_SUBTAB_THEMES
                : tabName === SETTINGS_SUBTAB_PRIVACY
                  ? SETTINGS_SUBTAB_PRIVACY
                  : tabName === SETTINGS_SUBTAB_ABOUT
                    ? SETTINGS_SUBTAB_ABOUT
                    : SETTINGS_SUBTAB_GENERAL;
  activeSettingsSubtab = nextTab;
  metrics.trackTabSwitch({ tab: "settings", subtab: nextTab });
  const generalBtn = document.getElementById("settings-subtab-general");
  const llmBtn = document.getElementById("settings-subtab-llm");
  const apiKeysBtn = document.getElementById("settings-subtab-api-keys");
  const backendBtn = document.getElementById("settings-subtab-backend");
  const debugBtn = document.getElementById("settings-subtab-debug");
  const pluginsBtn = document.getElementById("settings-subtab-plugins");
  const themesBtn = document.getElementById("settings-subtab-themes");
  const privacyBtn = document.getElementById("settings-subtab-privacy");
  const aboutBtn = document.getElementById("settings-subtab-about");
  const generalPanel = document.getElementById("settings-general-panel");
  const llmPanel = document.getElementById("settings-llm-panel");
  const apiKeysPanel = document.getElementById("settings-api-keys-panel");
  const backendPanel = document.getElementById("settings-backend-panel");
  const debugPanel = document.getElementById("settings-debug-panel");
  const pluginsPanel = document.getElementById("settings-plugins-panel");
  const themesPanel = document.getElementById("settings-themes-panel");
  const privacyPanel = document.getElementById("settings-privacy-panel");
  const aboutPanel = document.getElementById("settings-about-panel");
  if (generalBtn) {
    generalBtn.classList.toggle("active", nextTab === SETTINGS_SUBTAB_GENERAL);
  }
  if (llmBtn) {
    llmBtn.classList.toggle("active", nextTab === SETTINGS_SUBTAB_LLM);
  }
  if (apiKeysBtn) {
    apiKeysBtn.classList.toggle("active", nextTab === SETTINGS_SUBTAB_API_KEYS);
  }
  if (backendBtn) {
    backendBtn.classList.toggle("active", nextTab === SETTINGS_SUBTAB_BACKEND);
  }
  if (debugBtn) {
    debugBtn.classList.toggle("active", nextTab === SETTINGS_SUBTAB_DEBUG);
  }
  if (pluginsBtn) {
    pluginsBtn.classList.toggle("active", nextTab === SETTINGS_SUBTAB_PLUGINS);
  }
  if (themesBtn) {
    themesBtn.classList.toggle("active", nextTab === SETTINGS_SUBTAB_THEMES);
  }
  if (privacyBtn) {
    privacyBtn.classList.toggle("active", nextTab === SETTINGS_SUBTAB_PRIVACY);
  }
  if (aboutBtn) {
    aboutBtn.classList.toggle("active", nextTab === SETTINGS_SUBTAB_ABOUT);
  }
  if (generalPanel) {
    generalPanel.hidden = nextTab !== SETTINGS_SUBTAB_GENERAL;
  }
  if (llmPanel) {
    llmPanel.hidden = nextTab !== SETTINGS_SUBTAB_LLM;
  }
  if (apiKeysPanel) {
    apiKeysPanel.hidden = nextTab !== SETTINGS_SUBTAB_API_KEYS;
  }
  if (backendPanel) {
    backendPanel.hidden = nextTab !== SETTINGS_SUBTAB_BACKEND;
  }
  if (debugPanel) {
    debugPanel.hidden = nextTab !== SETTINGS_SUBTAB_DEBUG;
  }
  if (pluginsPanel) {
    pluginsPanel.hidden = nextTab !== SETTINGS_SUBTAB_PLUGINS;
  }
  if (themesPanel) {
    themesPanel.hidden = nextTab !== SETTINGS_SUBTAB_THEMES;
    if (!themesPanel.hidden) {
      void refreshThemesPreviewForSelected();
      // Auto-fetch the online catalog on first open if the user has a
      // theme server configured. The IPC handler returns a friendly
      // "not configured" message when the base URL is empty, so we
      // surface that as a status hint rather than a hard error.
      if (
        !themesCatalogLoading
        && themesCatalogEntries.length === 0
      ) {
        void refreshThemesCatalog({ force: false });
      }
    }
  }
  if (privacyPanel) {
    privacyPanel.hidden = nextTab !== SETTINGS_SUBTAB_PRIVACY;
  }
  if (aboutPanel) {
    aboutPanel.hidden = nextTab !== SETTINGS_SUBTAB_ABOUT;
  }
  if (nextTab === SETTINGS_SUBTAB_LLM || nextTab === SETTINGS_SUBTAB_API_KEYS) {
    syncLlmDiagnosticsIndicators();
  }
  if (nextTab === SETTINGS_SUBTAB_BACKEND || nextTab === SETTINGS_SUBTAB_API_KEYS) {
    syncBackendDiagnosticsIndicators();
    void refreshBackendDiagnostics({ ensureReady: true });
  }
  if (nextTab === SETTINGS_SUBTAB_API_KEYS) {
    syncMetricsDiagnosticsIndicators();
    void refreshMetricsDiagnostics();
  }
  if (nextTab === SETTINGS_SUBTAB_PLUGINS) {
    void refreshPluginRegistryView();
  }
  if (nextTab === SETTINGS_SUBTAB_ABOUT) {
    void loadSettingsAboutReleaseInfo();
  }
}

// Schedules session keychain auto populate.
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
      syncPluginRuntimeData();
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

// Handles estimate base64 decoded byte length.
function estimateBase64DecodedByteLength(base64Data) {
  const normalized = typeof base64Data === "string"
    ? base64Data.replace(/\s+/g, "")
    : "";
  if (!normalized) return 0;
  const paddingMatch = normalized.match(/=+$/);
  const paddingLength = paddingMatch ? paddingMatch[0].length : 0;
  return Math.max(0, Math.floor((normalized.length * 3) / 4) - paddingLength);
}

// Normalizes session pcap source.
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

// Handles update pcap size display from source.
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

// Handles update reprocess button state.
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

// Returns whether persist session now.
function canPersistSessionNow() {
  if (!isFileLoaded) return false;
  if (backendProgressState.processing) return false;
  if (!capturedPackets || typeof capturedPackets !== "object") return false;
  const hosts = capturedPackets["host"];
  if (!hosts || typeof hosts !== "object") return false;
  return Object.keys(hosts).some((host) => {
    const hostPackets = hosts[host];
    return Array.isArray(hostPackets) && hostPackets.length > 0;
  });
}

// Handles update session save controls.
function updateSessionSaveControls() {
  // Keep save controls enabled so an early click can surface the warning.
}

// Handles warn reprocess attempt before ready.
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

// Handles warn session save attempt before ready.
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

// Sets session pcap source.
function setSessionPcapSource(source, options = {}) {
  const { skipLog = false, logLabel = "session" } = options;
  sessionPcapSource = normalizeSessionPcapSource(source);
  updatePcapSizeDisplayFromSource();
  updateReprocessButtonState();
  syncPluginRuntimeData();
  if (!skipLog && sessionPcapSource) {
    writeLogEntry(
      `PCAP source cached label=${logLabel} name=${sessionPcapSource.fileName} bytes=${sessionPcapSource.byteLength}`,
    );
  }
}

// Resets backend progress state.
function resetBackendProgressState() {
  backendProgressState.firstChunkLoaded = false;
  backendProgressState.processing = false;
  backendProgressState.processedPackets = 0;
  backendProgressState.totalPackets = 0;
  backendProgressState.lastReportedPercent = -1;
  backendProgressState.etaLastSampleAtMs = 0;
  backendProgressState.etaLastSampleProcessedPackets = 0;
  backendProgressState.etaPacketsPerSecond = 0;
  pendingBackendCaptureUpdate = null;
  backendLastAppliedSnapshotProcessedPackets = 0;
  backendLastAppliedSnapshotAtMs = 0;
  ingestionChunkLogState.clear();
  deferredIngestionBacklogState.active = false;
  deferredIngestionBacklogState.deferredCount = 0;
  deferredIngestionBacklogState.lastDeferredAtMs = 0;
  updateBackendProcessingWarning();
}

// Formats a human-readable ETA label from seconds.
function formatBackendEtaLabel(etaSeconds) {
  const clampedSeconds = Math.max(0, Math.floor(Number(etaSeconds) || 0));
  if (!Number.isFinite(clampedSeconds)) return "";

  const hours = Math.floor(clampedSeconds / 3600);
  const minutes = Math.floor((clampedSeconds % 3600) / 60);
  const seconds = clampedSeconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }
  return `${seconds}s`;
}

// Estimates remaining ingestion seconds from smoothed packet throughput.
function estimateBackendRemainingSeconds(processedPackets, totalPackets) {
  const nowMs = performance.now();
  const previousSampleAtMs = Number(backendProgressState.etaLastSampleAtMs) || 0;
  const previousSampleProcessed =
    Number(backendProgressState.etaLastSampleProcessedPackets) || 0;
  const elapsedMs = previousSampleAtMs > 0 ? nowMs - previousSampleAtMs : 0;
  const packetDelta = Math.max(0, processedPackets - previousSampleProcessed);

  if (elapsedMs >= 200 && packetDelta > 0) {
    const instantaneousPps = packetDelta / (elapsedMs / 1000);
    if (Number.isFinite(instantaneousPps) && instantaneousPps > 0) {
      const previousPps = Number(backendProgressState.etaPacketsPerSecond) || 0;
      backendProgressState.etaPacketsPerSecond = previousPps > 0
        ? previousPps * 0.7 + instantaneousPps * 0.3
        : instantaneousPps;
    }
  }

  backendProgressState.etaLastSampleAtMs = nowMs;
  backendProgressState.etaLastSampleProcessedPackets = processedPackets;

  const remainingPackets = Math.max(0, totalPackets - processedPackets);
  const smoothedPps = Number(backendProgressState.etaPacketsPerSecond) || 0;
  if (!remainingPackets || !Number.isFinite(smoothedPps) || smoothedPps <= 0) {
    return null;
  }

  const etaSeconds = remainingPackets / smoothedPps;
  if (!Number.isFinite(etaSeconds) || etaSeconds < 0) {
    return null;
  }
  return etaSeconds;
}

// Returns backend progress percent.
function getBackendProgressPercent(processedPackets, totalPackets) {
  if (!Number.isFinite(processedPackets) || processedPackets < 0) return 0;
  if (!Number.isFinite(totalPackets) || totalPackets <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((processedPackets / totalPackets) * 100)));
}

// Handles update backend progress status.
function updateBackendProgressStatus({ force = false } = {}) {
  const processedPackets = Math.max(0, Number(backendProgressState.processedPackets) || 0);
  const totalPackets = Math.max(0, Number(backendProgressState.totalPackets) || 0);
  const percentComplete = getBackendProgressPercent(processedPackets, totalPackets);

  if (!force && percentComplete === backendProgressState.lastReportedPercent) {
    return;
  }

  backendProgressState.lastReportedPercent = percentComplete;

  const packetCountsSuffix = totalPackets > 0
    ? ` (${processedPackets} / ${totalPackets} packets)`
    : ` (${processedPackets} packets processed)`;

  const etaSeconds = estimateBackendRemainingSeconds(processedPackets, totalPackets);
  const etaSuffix = etaSeconds !== null
    ? ` - est. ${formatBackendEtaLabel(etaSeconds)} remaining`
    : "";

  statusUpdate(
    `Status: Processing packets... ${percentComplete}%${packetCountsSuffix}${etaSuffix}`,
  );
}

// Handles update backend processing warning.
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

  const etaSeconds = estimateBackendRemainingSeconds(
    Number(backendProgressState.processedPackets) || 0,
    Number(backendProgressState.totalPackets) || 0,
  );
  const etaText = etaSeconds !== null
    ? `ETA: ${formatBackendEtaLabel(etaSeconds)} remaining (${processedText} / ${totalText})`
    : `ETA: Calculating... (${processedText} / ${totalText})`;

  warningEl.innerHTML =
    "Warning: packets are still being processed." +
    "<br>" +
    etaText;
  warningEl.style.display = "block";
}

// Hides loading overlay.
function hideLoadingOverlay() {
  const loadingScreenEl = document.getElementById("loading-screen");
  const loadingContainerEl = document.getElementById("loading-container");
  if (loadingScreenEl) {
    loadingScreenEl.style.display = "none";
  }
  if (loadingContainerEl) {
    loadingContainerEl.style.display = "none";
  }
}

// Hides the startup preload overlay once window load and settings/theme init have finished.
function maybeHideStartupPreload() {
  if (!startupWindowLoaded || !startupSettingsInitialized || startupPreloadHidden) {
    return;
  }
  const preloadEl = document.getElementById("startup-preload-screen");
  if (!preloadEl) {
    startupPreloadHidden = true;
    return;
  }

  const STARTUP_PRELOAD_MIN_VISIBLE_MS = 6000;
  const STARTUP_PRELOAD_FADE_OUT_MS = 1800;
  const elapsedMs = Date.now() - startupPreloadShownAtMs;
  const remainingVisibleMs = Math.max(0, STARTUP_PRELOAD_MIN_VISIBLE_MS - elapsedMs);

  if (startupPreloadHideStartTimeoutId !== null) {
    window.clearTimeout(startupPreloadHideStartTimeoutId);
    startupPreloadHideStartTimeoutId = null;
  }

  startupPreloadHideStartTimeoutId = window.setTimeout(() => {
    startupPreloadHidden = true;
    preloadEl.classList.add("is-hidden");
    window.setTimeout(() => {
      preloadEl.style.display = "none";
    }, STARTUP_PRELOAD_FADE_OUT_MS);
    startupPreloadHideStartTimeoutId = null;
  }, remainingVisibleMs);
}

const packetLoadingState = {
  get activeBackendJobId() {
    return activeBackendJobId;
  },
  set activeBackendJobId(value) {
    activeBackendJobId = value;
  },
  get backendLastAppliedSnapshotProcessedPackets() {
    return backendLastAppliedSnapshotProcessedPackets;
  },
  set backendLastAppliedSnapshotProcessedPackets(value) {
    backendLastAppliedSnapshotProcessedPackets = value;
  },
  get backendLastAppliedSnapshotAtMs() {
    return backendLastAppliedSnapshotAtMs;
  },
  set backendLastAppliedSnapshotAtMs(value) {
    backendLastAppliedSnapshotAtMs = value;
  },
  get captureIngestWorkers() {
    return captureIngestWorkers;
  },
  set captureIngestWorkers(value) {
    captureIngestWorkers = value;
  },
  get captureIngestWorkerThreadCount() {
    return captureIngestWorkerThreadCount;
  },
  set captureIngestWorkerThreadCount(value) {
    captureIngestWorkerThreadCount = value;
  },
  get captureIngestWorkerCursor() {
    return captureIngestWorkerCursor;
  },
  set captureIngestWorkerCursor(value) {
    captureIngestWorkerCursor = value;
  },
  get captureIngestWorkerRequestId() {
    return captureIngestWorkerRequestId;
  },
  set captureIngestWorkerRequestId(value) {
    captureIngestWorkerRequestId = value;
  },
  pendingCaptureIngestWorkerRequests,
};

const {
  normalizeBackendJsonPathPayload,
  normalizeBackendJsonDataPayload,
  createFrontendBackendJobId,
  shouldAcceptBackendPayloadForActiveJob,
  countCaptureDataPackets,
  hasAnyCaptureDataPackets,
  createCaptureIngestWorker,
  terminateCaptureIngestWorkers,
  wireCaptureIngestWorker,
  ensureCaptureIngestWorkers,
  syncCaptureIngestWorkersFromSettings,
  requestCaptureIngestWorker,
  serializeCaptureDataForBackendLoad,
  stageIncrementalCapturePacketsInWorker,
  shouldReplacePendingBackendCaptureUpdate,
  shouldApplyIncrementalBackendSnapshot,
  markAppliedBackendSnapshot,
} = createPacketLoadingHelpers({
  state: packetLoadingState,
  backendProgressState,
  getBackendPacketChunkSize,
  isFrontendIngestThreadingEnabled,
  getFrontendIngestWorkerThreads,
  getBackendIncrementalRefreshMinPackets,
  getBackendIncrementalRefreshMinIntervalMs,
  createWorker: () =>
    new Worker(new URL("./workers/capture-ingest-worker.js", import.meta.url)),
});

initializeInstallScreen({
  installapi: window.installapi,
  documentRef: document,
  metrics,
});

void refreshOllamaStartupAvailability();
void refreshBackendDiagnostics({ ensureReady: false });

if (window.installapi && typeof window.installapi.onLlmDiagnosticsUpdated === "function") {
  window.installapi.onLlmDiagnosticsUpdated((diagnostics) => {
    cachedLlmDiagnostics = diagnostics || null;
    ollamaVersionCheckPassed = Boolean(
      cachedLlmDiagnostics?.ollamaInstalled && cachedLlmDiagnostics?.ollamaServerListening,
    );
    syncLlmDiagnosticsIndicators();
  });
}



// ============================================================================
// Panel composition and cross-panel wiring
// ============================================================================


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

const { showStats, showStatsHeatmapLocation } = createStatsPanel({
  getKeystorePanel: () => keystorePanel,
  documentRef: document,
  statusUpdate,
  writeLogEntry,
  getCurrentSettings,
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
  listCarvableFilesForStats,
  openCarvedFileInConv: loadCarvedFileCandidateIntoConvTab,
});

const summaryPanel = createSummaryPanel({
  documentRef: document,
  getJsonCapture: () => jsonCapture,
  setActiveMainTab: (tab) => {
    activeMainTab = tab;
  },
  mainTabSummary: MAIN_TAB_SUMMARY,
  statusUpdate,
  fileLoaded,
});

const { showSummary, showSummaryLoading, clearSummaryContent } = summaryPanel;
const { bindDataPanelEvents, logCurrentPacketDisplay } =
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
    populateDataTypes: (...args) => populateDataTypes(...args),
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
    writeLogEntry("Backend stop requested action=stop-processing reason=session-switch");
    const backendStopResult = await window.snitchapi.shutdownBackend().catch((error) => {
      logErrorEntry("shutdown-backend", error);
      return null;
    });
    if (backendStopResult) {
      writeLogEntry(
        `Backend stop response success=${Boolean(backendStopResult.success)} noop=${Boolean(backendStopResult.noop)} processing=${Boolean(backendStopResult.processing)}`,
      );
    }
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
  bumpPacketNavigationCacheVersion();
  activePacketCursor = 0;
  index = 0;
  currentIp = null;
  currentPacketKey = null;
  jsonCapture = "";
  summary = "";
  compactedAnalysisSummaries = [];
  analysisBlubHistory.length = 0;
  analysisCompactionInProgress = false;
  setSessionPcapSource(null, { skipLog: true });
  filterHistory.length = 0;
  hostFilterEl.value = "";
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

    if (window.settingsapi && typeof window.settingsapi.update === "function") {
      const updatedSettings = await window.settingsapi.update({
        list: {
          columnVisibility: {
            idx: false,
            host: false,
            payloadLength: false,
          },
        },
      });
      if (updatedSettings) {
        setCurrentSettings(updatedSettings);
      }
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

// Returns packet timeframe.
function getPacketTimeframe() {
  if (!capturedPackets || typeof capturedPackets !== "object") return null;
  const packetTimes = [];
  if (!capturedPackets["host"]) return null;
  for (const host of Object.keys(capturedPackets["host"])) {
    const hostPackets = capturedPackets["host"][host];
    if (!Array.isArray(hostPackets)) continue;
    hostPackets.forEach((packet) => {
      const packetTime =
        packet?.["packet.info"]?.["packet.timestamp"] ??
        packet?.["packet.info"]?.["Packet Timestamp"];
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
        lastBackendLoadRequest = {
          kind: "file",
          filePath,
        };
        runSnitch(filePath);
      })
      .catch((error) => {
        doError("Error selecting capture/session file!");
        logErrorEntry("capture-select", error);
      });
  });

// Returns whether valid json.
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

// Handles file loaded.
function fileLoaded(isLoaded) {
  isFileLoaded = isLoaded;
  if (isLoaded) {
    clearExtractionResultsForStats();
    if (typeof subnetCalculatorPanel?.recomputeSessionThreatScore === "function") {
      subnetCalculatorPanel.recomputeSessionThreatScore({ silent: true });
    }

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

// Handles escape html.
function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Handles decorate expression segment.
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

// Renders highlighted query.
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

// Syncs filter highlight.
function syncFilterHighlight() {
  filterHighlightEl.innerHTML = renderHighlightedQuery(filterInputEl.value);
  syncFilterHighlightScroll();
  updateFilterClearButtonState();
}

// Syncs filter highlight scroll.
function syncFilterHighlightScroll() {
  filterHighlightEl.scrollLeft = filterInputEl.scrollLeft;
}

// Handles update filter clear button state.
function updateFilterClearButtonState() {
  filterClearButtonEl.disabled = !canClearFilterQuery();
}

// Returns whether clear filter query.
function canClearFilterQuery() {
  return !filterInputEl.disabled && filterInputEl.value.trim() !== "";
}

// Normalizes saved filter entries.
function normalizeSavedFilterEntries(rawEntries) {
  if (!Array.isArray(rawEntries)) return [];
  return rawEntries
    .filter((entry) => entry && typeof entry === "object")
    .flatMap((entry) => {
      const id =
        typeof entry.id === "string" && entry.id.trim()
          ? entry.id.trim()
          : "";
      const label =
        typeof entry.label === "string" ? entry.label.trim() : "";
      const query =
        typeof entry.query === "string" ? entry.query.trim() : "";
      if (!id || !label || !query) return [];
      return [
        {
          id,
          label,
          query,
        },
      ];
    });
}

async function loadSavedFilterLibrary() {
  if (!window.savedfiltersapi || typeof window.savedfiltersapi.list !== "function") {
    return;
  }

  try {
    const loadedFilters = await window.savedfiltersapi.list();
    const normalizedFilters = normalizeSavedFilterEntries(loadedFilters);
    savedFilterLibrary.splice(0, savedFilterLibrary.length, ...normalizedFilters);
    renderFilterHistory();
  } catch (error) {
    logErrorEntry("saved-filters-load", error);
  }
}

// Handles resolve saved filter by id.
function resolveSavedFilterById(savedFilterId) {
  const normalizedId =
    typeof savedFilterId === "string" ? savedFilterId.trim() : "";
  if (!normalizedId) return null;
  return (
    savedFilterLibrary.find((entry) => entry.id === normalizedId) || null
  );
}

// Returns saved filter entries matching query.
function getSavedFilterEntriesMatchingQuery(queryValue) {
  const normalizedQuery =
    typeof queryValue === "string" ? queryValue.trim() : "";
  if (!normalizedQuery) return [];
  return savedFilterLibrary.filter((entry) => entry.query === normalizedQuery);
}

// Handles request saved filter label dialog.
function requestSavedFilterLabelDialog(defaultLabel, queryPreview) {
  const dialogEl = document.getElementById("saved-filter-label-dialog");
  const descriptionEl = document.getElementById(
    "saved-filter-label-description",
  );
  const inputEl = document.getElementById("saved-filter-label-input");
  const removeBtnEl = document.getElementById("saved-filter-label-remove-btn");
  if (!dialogEl || !descriptionEl || !inputEl || !removeBtnEl) {
    return Promise.resolve(null);
  }

  if (activeSavedFilterLabelDialogResolver) {
    const resolve = activeSavedFilterLabelDialogResolver;
    activeSavedFilterLabelDialogResolver = null;
    resolve({ action: "cancel" });
  }

  const compactPreview = String(queryPreview || "").replace(/\s+/g, " ").trim();
  const shortenedPreview =
    compactPreview.length > 100
      ? `${compactPreview.slice(0, 100)}...`
      : compactPreview;
  const queryMatches = getSavedFilterEntriesMatchingQuery(queryPreview);
  const removableFilter = queryMatches[0] || null;
  activeSavedFilterDialogContext = {
    query: String(queryPreview || "").trim(),
    removableFilterId: removableFilter?.id || null,
    removableFilterLabel: removableFilter?.label || "",
  };
  descriptionEl.textContent = shortenedPreview
    ? `Save current query: ${shortenedPreview}`
    : "Label your saved filter.";
  removeBtnEl.hidden = !removableFilter;
  removeBtnEl.textContent = removableFilter
    ? `Remove Saved (${removableFilter.label})`
    : "Remove Saved";
  dialogEl.hidden = false;
  inputEl.value = defaultLabel || "";
  inputEl.focus();
  inputEl.select();

  return new Promise((resolve) => {
    activeSavedFilterLabelDialogResolver = resolve;
  });
}

// Handles resolve saved filter label dialog.
function resolveSavedFilterLabelDialog(result) {
  const dialogEl = document.getElementById("saved-filter-label-dialog");
  const inputEl = document.getElementById("saved-filter-label-input");
  const removeBtnEl = document.getElementById("saved-filter-label-remove-btn");
  if (dialogEl) dialogEl.hidden = true;
  if (!activeSavedFilterLabelDialogResolver) {
    if (inputEl) inputEl.value = "";
    if (removeBtnEl) {
      removeBtnEl.hidden = true;
      removeBtnEl.textContent = "Remove Saved";
    }
    activeSavedFilterDialogContext = null;
    return;
  }
  const resolve = activeSavedFilterLabelDialogResolver;
  activeSavedFilterLabelDialogResolver = null;
  resolve(result);
  if (inputEl) inputEl.value = "";
  if (removeBtnEl) {
    removeBtnEl.hidden = true;
    removeBtnEl.textContent = "Remove Saved";
  }
  activeSavedFilterDialogContext = null;
}

// Handles submit saved filter label dialog.
function submitSavedFilterLabelDialog() {
  const inputEl = document.getElementById("saved-filter-label-input");
  resolveSavedFilterLabelDialog({
    action: "save",
    label: inputEl?.value || "",
  });
}

async function removeSavedFilterFromLabelDialog() {
  if (!window.savedfiltersapi || typeof window.savedfiltersapi.remove !== "function") {
    doError("Saved filter remove is unavailable in this build");
    return;
  }

  const removableFilterId = activeSavedFilterDialogContext?.removableFilterId;
  if (!removableFilterId) {
    statusUpdate("Status: Current query is not a saved filter");
    return;
  }

  const removableLabel =
    activeSavedFilterDialogContext?.removableFilterLabel || "saved filter";
  try {
    const nextFilters = await window.savedfiltersapi.remove({
      id: removableFilterId,
    });
    const normalizedFilters = normalizeSavedFilterEntries(nextFilters);
    savedFilterLibrary.splice(0, savedFilterLibrary.length, ...normalizedFilters);
    renderFilterHistory();
    writeLogEntry(`Saved filter removed label="${removableLabel}"`);
    statusUpdate(`Status: Removed saved filter \"${removableLabel}\"`);
    resolveSavedFilterLabelDialog({ action: "remove" });
  } catch (error) {
    logErrorEntry("saved-filters-remove", error);
    doError(`Unable to remove saved filter: ${error?.message || String(error)}`);
  }
}

async function saveCurrentFilterToLibraryFromContextMenu() {
  if (!window.savedfiltersapi || typeof window.savedfiltersapi.save !== "function") {
    statusUpdate("Status: Saved filters are unavailable in this build");
    return;
  }

  const currentQuery = String(filterInputEl?.value || "").trim();
  if (!currentQuery) {
    statusUpdate("Status: Enter a filter query before saving");
    return;
  }

  const suggestedLabel =
    currentQuery.length > 80 ? `${currentQuery.slice(0, 80)}...` : currentQuery;
  const dialogLabel = await requestSavedFilterLabelDialog(
    suggestedLabel,
    currentQuery,
  );
  if (!dialogLabel || dialogLabel.action === "cancel") {
    statusUpdate("Status: Save filter canceled");
    return;
  }
  if (dialogLabel.action === "remove") {
    return;
  }

  const normalizedLabel = String(dialogLabel.label || "").trim();
  if (!normalizedLabel) {
    doError("Saved filter label cannot be empty");
    statusUpdate("Status: Saved filter label is required");
    return;
  }

  try {
    const nextFilters = await window.savedfiltersapi.save({
      label: normalizedLabel,
      query: currentQuery,
    });
    const normalizedFilters = normalizeSavedFilterEntries(nextFilters);
    savedFilterLibrary.splice(0, savedFilterLibrary.length, ...normalizedFilters);
    renderFilterHistory();
    writeLogEntry(
      `Saved filter added label="${normalizedLabel}" query="${currentQuery}"`,
    );
    statusUpdate(`Status: Saved filter \"${normalizedLabel}\"`);
  } catch (error) {
    logErrorEntry("saved-filters-save", error);
    doError(
      `Unable to save filter: ${error?.message || String(error)}`,
    );
  }
}

// Renders filter history.
function renderFilterHistory() {
  filterHistorySelectEl.replaceChildren();

  const buildFilterDropdownLabel = (text, maxLength = 165) => {
    const normalized = String(text || "").replace(/\s+/g, " ").trim();
    if (normalized.length <= maxLength) return normalized;
    return `${normalized.slice(0, maxLength - 3)}...`;
  };

  const placeholderOption = document.createElement("option");
  placeholderOption.value = "";
  placeholderOption.textContent =
    savedFilterLibrary.length || filterHistory.length
      ? "Saved and previous filters"
      : "No saved or previous filters";
  placeholderOption.selected = true;
  filterHistorySelectEl.appendChild(placeholderOption);

  if (savedFilterLibrary.length) {
    const savedGroup = document.createElement("optgroup");
    savedGroup.label = "Saved Filters";
    savedFilterLibrary.forEach((entry) => {
      const savedOption = document.createElement("option");
      savedOption.value = `${FILTER_DROPDOWN_OPTION_PREFIX_SAVED}${entry.id}`;
      const fullSavedLabel = `${entry.label} - ${entry.query}`;
      savedOption.textContent = buildFilterDropdownLabel(fullSavedLabel);
      savedOption.title = `${entry.label}: ${entry.query}`;
      savedGroup.appendChild(savedOption);
    });
    filterHistorySelectEl.appendChild(savedGroup);
  }

  if (filterHistory.length) {
    const recentGroup = document.createElement("optgroup");
    recentGroup.label = "Session History";
    filterHistory.forEach((query) => {
      const queryOption = document.createElement("option");
      queryOption.value = `${FILTER_DROPDOWN_OPTION_PREFIX_SESSION}${query}`;
      queryOption.textContent = buildFilterDropdownLabel(query);
      queryOption.title = query;
      recentGroup.appendChild(queryOption);
    });
    filterHistorySelectEl.appendChild(recentGroup);
  }

  filterHistorySelectEl.value = "";
  filterHistorySelectEl.disabled = !isFileLoaded;
}

// Handles expand filter history dropdown aligned to filter input.
function expandFilterHistoryDropdownAlignedToFilterInput() {
  if (!filterHistorySelectEl || filterHistorySelectEl.disabled) return;
  const filterInputRect = filterInputEl?.getBoundingClientRect?.();
  const filterHistoryContainerEl = document.getElementById("filter-history");
  if (!filterInputRect || !filterHistoryContainerEl) return;

  const filterHistoryContainerRect =
    filterHistoryContainerEl.getBoundingClientRect();
  const viewportPadding = 8;
  const clampedLeft = Math.max(viewportPadding, filterInputRect.left);
  const clampedRight = Math.min(
    window.innerWidth - viewportPadding,
    filterInputRect.right,
  );
  const expandedWidth = Math.max(32, Math.round(clampedRight - clampedLeft));
  const expandedLeft = Math.round(clampedLeft - filterHistoryContainerRect.left);

  filterHistorySelectEl.classList.add("filter-history-expanded");
  filterHistorySelectEl.style.left = `${expandedLeft}px`;
  filterHistorySelectEl.style.width = `${expandedWidth}px`;
  filterHistorySelectEl.style.maxWidth = `${expandedWidth}px`;
}

// Handles collapse filter history dropdown.
function collapseFilterHistoryDropdown() {
  if (!filterHistorySelectEl) return;
  filterHistorySelectEl.classList.remove("filter-history-expanded");
  filterHistorySelectEl.style.left = "";
  filterHistorySelectEl.style.width = "";
  filterHistorySelectEl.style.maxWidth = "";
}

// Handles add filter history.
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

// Builds data tools history label.
function buildDataToolsHistoryLabel(entry) {
  const preview = entry.input.replace(/\s+/g, " ").trim();
  const truncatedPreview =
    preview.length > 80 ? `${preview.slice(0, 77)}…` : preview;
  return `${entry.format.toUpperCase()}: ${truncatedPreview}`;
}

// Renders data tools input history.
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

// Handles add data tools input history.
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

// Returns current data tools input snapshot.
function getCurrentDataToolsInputSnapshot() {
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  return {
    input: String(inputEl?.value ?? ""),
    format:
      typeof formatEl?.value === "string" && formatEl.value.trim()
        ? formatEl.value.trim().toLowerCase()
        : "hex",
  };
}

// Returns whether data tools input edited.
function isDataToolsInputEdited() {
  const snapshot = getCurrentDataToolsInputSnapshot();
  return (
    snapshot.input !== dataToolsCommittedInputValue ||
    snapshot.format !== dataToolsCommittedInputFormat
  );
}

// Handles update data tools input edited state.
function updateDataToolsInputEditedState() {
  const indicatorEl = document.getElementById("data-tools-input-edited-indicator");
  const resetButtonEl = document.getElementById("data-tools-input-reset-btn");
  const edited = isDataToolsInputEdited();
  if (indicatorEl) {
    indicatorEl.textContent = edited ? "Edited" : "Ready";
    indicatorEl.classList.toggle("edited", edited);
  }
  if (resetButtonEl) {
    resetButtonEl.disabled = !edited;
  }
}

// Normalizes hex input formatting (AA BB ... with 16-byte line wraps).
// The full parsed bytes are kept in memory, but display is capped to keep the UI responsive.
function normalizeDataToolsHexInputFormatting() {
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  if (!inputEl || !formatEl || formatEl.value !== "hex") {
    return;
  }
  if (!inputEl.value.trim()) {
    updateDataToolsHexHighlights();
    syncDataToolsHighlightScroll("data-tools-input", "data-tools-input-highlight");
    return;
  }
  // When the full source bytes are still available and unedited, the input
  // is already correctly capped/formatted. Re-parsing the truncated display
  // and reformatting it can change whitespace/line wrapping and risk making
  // the input look edited, which would cause downstream operations to parse
  // only the 8 KB visible in the textarea.
  if (
    !dataToolsInputEditedFlag &&
    dataToolsOriginalInputBytes instanceof Uint8Array &&
    dataToolsOriginalInputBytes.length > 0
  ) {
    updateDataToolsHexHighlights();
    syncDataToolsHighlightScroll("data-tools-input", "data-tools-input-highlight");
    return;
  }
  try {
    const bytes = parseDataToolsInput("hex", inputEl.value);
    const displayBytes = bytes.slice(0, DATA_TOOLS_INPUT_DISPLAY_MAX_BYTES);
    let normalized = formatHexInputBytes(displayBytes);
    if (bytes.length > DATA_TOOLS_INPUT_DISPLAY_MAX_BYTES) {
      normalized +=
        `\n\n[Input truncated for display. ${bytes.length.toLocaleString()} bytes total; only ${DATA_TOOLS_INPUT_DISPLAY_MAX_BYTES.toLocaleString()} bytes shown.]`;
    }
    if (inputEl.value !== normalized) {
      inputEl.value = normalized;
    }
  } catch (error) {
    // Keep user's input untouched when partially invalid.
  }
  updateDataToolsHexHighlights();
  syncDataToolsHighlightScroll("data-tools-input", "data-tools-input-highlight");
  updateDataToolsInputEditedState();
}

// Handles mark data tools input committed.
function markDataToolsInputCommitted() {
  const snapshot = getCurrentDataToolsInputSnapshot();
  dataToolsCommittedInputValue = snapshot.input;
  dataToolsCommittedInputFormat = snapshot.format;
  updateDataToolsInputEditedState();
}

// Resets data tools input to committed.
// Resets all Conv / data-tools state to freshly-opened defaults.
function resetConvToFreshDefaults() {
  const dataToolsInputEl = document.getElementById("data-tools-input");
  const dataToolsFormatEl = document.getElementById("data-tools-format");
  const dataToolsProtoSelectEl = document.getElementById("data-tools-proto-select");
  const dataToolsErrorEl = document.getElementById("data-tools-error");
  if (dataToolsInputEl) dataToolsInputEl.value = "";
  if (dataToolsFormatEl) dataToolsFormatEl.value = DEFAULT_DATA_TOOLS_FORMAT;
  if (dataToolsProtoSelectEl) dataToolsProtoSelectEl.value = "auto";
  if (dataToolsErrorEl) dataToolsErrorEl.textContent = "";

  // Hash input area and hash output panes.
  const hashInputEl = document.getElementById("data-tools-hash-input-reading");
  if (hashInputEl) hashInputEl.value = "";
  resetHashOutputs();

  // Packet JSON viewer.
  const packetJsonCurrentEl = document.getElementById("data-tools-packet-json-current-packet");
  const packetJsonOutputEl = document.getElementById("data-tools-packet-json-output");
  if (packetJsonCurrentEl) packetJsonCurrentEl.textContent = "Current Packet:";
  if (packetJsonOutputEl) packetJsonOutputEl.innerHTML = "";

  // Conv-related right sidebar insights are hidden by default; nothing to
  // persist here, but ensure its placeholder state is consistent.
  const rightsideConvInsightsEl = document.getElementById("rightside-conv-insights");
  if (rightsideConvInsightsEl) rightsideConvInsightsEl.hidden = true;

  dataToolsContextPacket = null;
  dataToolsOriginalInputBytes = null;
  dataToolsInputEditedFlag = false;
  dataToolsCommittedInputValue = "";
  dataToolsCommittedInputFormat = DEFAULT_DATA_TOOLS_FORMAT;
  dataToolsLastConversionBytes = new Uint8Array();
  dataToolsHistorySelectEl.value = "";
  resetDataToolsOutputs();
  clearDataToolsSelectionState();
  setDataToolsFindReplaceMode("none");
  updateDataToolsHexHighlights();
  syncDataToolsHighlightScroll("data-tools-input", "data-tools-input-highlight");
  updateDataToolsInputEditedState();
  updateDataToolsCursorReadout("data-tools-input");

  // Reset Extraction panel state as part of the clean-slate Conv reset.
  extractionPanelCurrentBytes = new Uint8Array();
  extractionPanelCurrentFormat = null;
  extractionPanelLastResult = null;
  extractionPanelArchiveEntries = [];
  extractionPanelSelectedEntry = null;
  resetExtractionOutputs();

  // Reset subnet / threat-intel Conv subtabs.
  if (typeof subnetCalculatorPanel?.clear === "function") {
    subnetCalculatorPanel.clear();
  }
}

function resetDataToolsInputToCommitted() {
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  const errorEl = document.getElementById("data-tools-error");
  if (!inputEl || !formatEl) return;

  inputEl.value = dataToolsCommittedInputValue;
  formatEl.value = dataToolsCommittedInputFormat;
  if (errorEl) {
    errorEl.textContent = "";
  }

  updateDataToolsConvertedOutputVisibility();
  updateDataToolsHexHighlights();
  syncDataToolsHighlightScroll(
    "data-tools-input",
    "data-tools-input-highlight",
  );

  if (dataToolsCommittedInputValue.trim()) {
    runDataToolsConversion();
  } else {
    dataToolsHistorySelectEl.value = "";
    resetDataToolsOutputs();
    clearDataToolsSelectionState();
    updateDataToolsInputEditedState();
  }
}

// Returns packet key.
function getPacketKey(packet, fallbackHost = "", fallbackIndex = 0) {
  if (packet && typeof packet.__packetKey === "string" && packet.__packetKey) {
    return packet.__packetKey;
  }
  const packetInfo = packet?.["packet.info"];
  const sourceIp =
    (packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"]) || fallbackHost || "Unknown";
  const packetIndex = packetInfo?.["index"] ?? packetInfo?.["Index"] ?? fallbackIndex;
  return `${sourceIp}${PACKET_KEY_SEPARATOR}${packetIndex}`;
}

function parsePacketKey(packetKey) {
  const normalizedKey = typeof packetKey === "string" ? packetKey.trim() : "";
  if (!normalizedKey) {
    return { host: "", packetIndex: null };
  }

  const preferredSeparatorIndex = normalizedKey.lastIndexOf(PACKET_KEY_SEPARATOR);
  if (preferredSeparatorIndex > 0) {
    const host = normalizedKey.slice(0, preferredSeparatorIndex).trim();
    const packetIndex = Number.parseInt(
      normalizedKey.slice(preferredSeparatorIndex + 1).trim(),
      10,
    );
    return {
      host,
      packetIndex: Number.isInteger(packetIndex) ? packetIndex : null,
    };
  }

  const legacySeparatorIndex = normalizedKey.lastIndexOf(":");
  if (legacySeparatorIndex > 0) {
    const host = normalizedKey.slice(0, legacySeparatorIndex).trim();
    const packetIndex = Number.parseInt(
      normalizedKey.slice(legacySeparatorIndex + 1).trim(),
      10,
    );
    return {
      host,
      packetIndex: Number.isInteger(packetIndex) ? packetIndex : null,
    };
  }

  return { host: normalizedKey, packetIndex: null };
}

function normalizePacketKey(packetKey) {
  const parsed = parsePacketKey(packetKey);
  if (!parsed.host || !Number.isInteger(parsed.packetIndex)) {
    return typeof packetKey === "string" ? packetKey.trim() : "";
  }
  return `${parsed.host}${PACKET_KEY_SEPARATOR}${parsed.packetIndex}`;
}

// Handles cache packet stub.
function cachePacketStub(packetKey, packetStub) {
  if (!packetKey || !packetStub) return;
  if (packetStubByKey.has(packetKey)) {
    packetStubByKey.delete(packetKey);
  }
  packetStubByKey.set(packetKey, packetStub);
  while (packetStubByKey.size > PACKET_STUB_INDEX_MAX) {
    const oldestKey = packetStubByKey.keys().next().value;
    if (!oldestKey) break;
    packetStubByKey.delete(oldestKey);
  }
}

// Handles cache hydrated packet.
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

const {
  clearStreamPacketHydrationCache,
  buildStreamPayloadHexCacheKey,
  setStreamPayloadHexCache,
  warmStreamPacketHydrationCache,
  updatePacketInCollections,
  ensurePacketHydrated,
} = createStreamHelpers({
  state: {
    streamPacketHydrationCache,
    streamPayloadHexCache,
    hydratedPacketCache,
    streamPayloadHexCacheLimit: STREAM_PAYLOAD_HEX_CACHE_LIMIT,
  },
  getPacketKey,
  buildBidirectionalStreamKey,
  yieldToRenderer,
  ensureHydratedPacketCached: cacheHydratedPacket,
  resolvePacketStubByKey: async (packetKey) => {
    const [packetStub] = await resolvePacketStubsByKeys([packetKey]);
    return packetStub || null;
  },
  dehydratePacket,
  logErrorEntry,
  getCapturedPackets: () => capturedPackets,
  getFilteredPackets: () => filteredPackets,
  getPacketsForHost: () => p,
  getCaptureApi: () => window.captureapi,
});

// Returns whether location filter query.
function isLocationFilterQuery(filterQuery) {
  if (typeof filterQuery !== "string") return false;
  return /\bloc\.(src|dst)\.(city|country|postal|tz|timezone)\s*:/i.test(
    filterQuery,
  );
}

// Handles choose target host from packet matches.
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
    const sourceIp = packet?.["packet.info"]?.["IP"]?.["ip.src.addr"] ?? packet?.["packet.info"]?.["IP"]?.["Source IP"];
    const destinationIp = packet?.["packet.info"]?.["IP"]?.["ip.dst.addr"] ?? packet?.["packet.info"]?.["IP"]?.["Destination IP"];
    [sourceIp, destinationIp].forEach((ipValue) => {
      if (typeof ipValue !== "string") return;
      const normalizedIp = ipValue.trim();
      if (!normalizedIp) return;
      if (!isLikelyIpAddress(normalizedIp)) return;
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

// Syncs target host from filtered packets.
function syncTargetHostFromFilteredPackets(matches, sourceLabel = "filter") {
  const selectedHost = chooseTargetHostFromPacketMatches(matches);
  if (!syncTargetHostSelection(selectedHost)) {
    return "";
  }
  writeLogEntry(`${sourceLabel} auto-selected target host=${selectedHost}`);
  return selectedHost;
}

// Syncs target host selection.
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

// Returns whether all hosts selection.
function isAllHostsSelection(selectedHost) {
  return String(selectedHost || "").trim() === DUMMY_ALL_HOST;
}

// Returns whether bookmarked selection.
function isBookmarkedSelection(selectedHost) {
  return String(selectedHost || "").trim() === DUMMY_BOOKMARKED_HOST;
}

// Handles append all hosts option.
function appendAllHostsOption(targetHostsDropdown) {
  const optionEl = document.createElement("option");
  optionEl.value = DUMMY_ALL_HOST;
  optionEl.textContent = `${DUMMY_ALL_HOST_ALIAS} (${DUMMY_ALL_HOST})`;
  targetHostsDropdown.appendChild(optionEl);
}

// Handles append bookmarked option.
function appendBookmarkedOption(targetHostsDropdown) {
  const optionEl = document.createElement("option");
  optionEl.value = DUMMY_BOOKMARKED_HOST;
  optionEl.textContent = DUMMY_BOOKMARKED_HOST_ALIAS;
  targetHostsDropdown.appendChild(optionEl);
}

// Returns all packet keys for filtering.
function getAllPacketKeysForFiltering() {
  const hostMap =
    capturedPackets && typeof capturedPackets["host"] === "object"
      ? capturedPackets["host"]
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

// Finds a packet stub by key in current capture data.
function findPacketStubInCaptureDataByKey(packetKey) {
  if (!packetKey) return null;
  const hostMap =
    capturedPackets && typeof capturedPackets["host"] === "object"
      ? capturedPackets["host"]
      : {};
  for (const host of Object.keys(hostMap)) {
    const hostPackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
    for (let packetIndex = 0; packetIndex < hostPackets.length; packetIndex += 1) {
      const packet = hostPackets[packetIndex];
      if (getPacketKey(packet, host, packetIndex) === packetKey) {
        if (packet && typeof packet === "object") {
          packet.__packetKey = packetKey;
        }
        cachePacketStub(packetKey, packet);
        return packet;
      }
    }
  }
  return null;
}

// Resolves packet stubs for keys, fetching evicted stubs on demand.
async function resolvePacketStubsByKeys(packetKeys) {
  if (!Array.isArray(packetKeys) || packetKeys.length === 0) {
    return [];
  }

  const resolvedPackets = [];
  for (let i = 0; i < packetKeys.length; i += 1) {
    const packetKey = packetKeys[i];
    if (typeof packetKey !== "string" || !packetKey) {
      continue;
    }

    let packetStub = packetStubByKey.get(packetKey) || null;
    if (!packetStub && window.captureapi && typeof window.captureapi.getPacketStub === "function") {
      try {
        const stubResult = await window.captureapi.getPacketStub(packetKey);
        if (stubResult?.success && stubResult.packet) {
          packetStub = stubResult.packet;
          if (packetStub && typeof packetStub === "object") {
            packetStub.__packetKey = packetKey;
          }
          cachePacketStub(packetKey, packetStub);
        }
      } catch {
        // Fallback to captureData scan below.
      }
    }

    if (!packetStub) {
      packetStub = findPacketStubInCaptureDataByKey(packetKey);
    }

    if (packetStub) {
      resolvedPackets.push(packetStub);
    }

    if (i > 0 && i % 1000 === 0) {
      await yieldToRenderer();
    }
  }

  return resolvedPackets;
}

// Returns bookmarked packets for host navigation.
function getBookmarkedPacketsForHostNavigation() {
  const bookmarkSignature = bookmarkList.join("|");
  if (
    bookmarkedNavigationPacketsCache
    && bookmarkedNavigationPacketsCache.version === packetNavigationCacheVersion
    && bookmarkedNavigationPacketsCache.signature === bookmarkSignature
  ) {
    return bookmarkedNavigationPacketsCache.packets;
  }

  const seenPacketKeys = new Set();
  const packets = [];
  bookmarkList.forEach((packetKey) => {
    if (seenPacketKeys.has(packetKey)) return;
    seenPacketKeys.add(packetKey);

    const packetStub = packetStubByKey.get(packetKey) || findPacketStubInCaptureDataByKey(packetKey);
    if (packetStub) {
      packets.push(packetStub);
    }
  });
  const sortedBookmarkedPackets = sortPacketsByOwnStreamOrder(packets);
  bookmarkedNavigationPacketsCache = {
    version: packetNavigationCacheVersion,
    signature: bookmarkSignature,
    packets: sortedBookmarkedPackets,
  };
  return sortedBookmarkedPackets;
}

// Parses filter expression parts.
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

// Normalizes local filter key.
function normalizeLocalFilterKey(filterKey) {
  return String(filterKey || "")
    .toLowerCase()
    .replace(/[._\s-]+/g, "-");
}

// Returns whether bookmark filter expression.
function isBookmarkFilterExpression(expression) {
  const parts = parseFilterExpressionParts(expression);
  if (!parts?.filterKey) return false;
  return normalizeLocalFilterKey(parts.filterKey) === "bookmark";
}

// Returns whether retransmission filter expression.
function isRetransmissionFilterExpression(expression) {
  const parts = parseFilterExpressionParts(expression);
  if (!parts?.filterKey) return false;
  const normalizedFilterKey = normalizeLocalFilterKey(parts.filterKey);
  return (
    normalizedFilterKey === "tcp-retransmission" ||
    normalizedFilterKey === "tcp-stream-retransmission"
  );
}

// Returns whether out of order filter expression.
function isOutOfOrderFilterExpression(expression) {
  const parts = parseFilterExpressionParts(expression);
  if (!parts?.filterKey) return false;
  const normalizedFilterKey = normalizeLocalFilterKey(parts.filterKey);
  return (
    normalizedFilterKey === "tcp-badorder" ||
    normalizedFilterKey === "tcp-stream-badorder"
  );
}

// Parses bookmark filter bool.
function parseBookmarkFilterBool(rawValue) {
  const normalized = String(rawValue || "").trim().toLowerCase();
  if (["true", "1", "yes", "y"].includes(normalized)) return true;
  if (["false", "0", "no", "n"].includes(normalized)) return false;
  return null;
}

// Parses retransmission filter bool.
function parseRetransmissionFilterBool(rawValue) {
  const normalized = String(rawValue || "").trim().toLowerCase();
  if (["true", "1", "yes", "y"].includes(normalized)) return true;
  if (["false", "0", "no", "n"].includes(normalized)) return false;
  return null;
}

// Handles rebuild tcp stream filter indexes.
function rebuildTcpStreamFilterIndexes() {
  retransmissionList = [];
  outOfOrderList = [];

  const hostMap =
    capturedPackets && typeof capturedPackets["host"] === "object"
      ? capturedPackets["host"]
      : {};
  const streamPacketsByKey = new Map();

  Object.keys(hostMap).forEach((host) => {
    const hostPackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
    hostPackets.forEach((packet) => {
      const packetInfo = packet?.["packet.info"];
      const protocol = String(packetInfo?.["packet.proto"] ?? packetInfo?.["Protocol"] ?? "").toUpperCase();
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

// Handles evaluate bookmark filter expression.
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

// Handles evaluate retransmission filter expression.
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

// Handles evaluate out of order filter expression.
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

// Returns all packets for host navigation.
function getAllPacketsForHostNavigation() {
  if (
    allHostsNavigationPacketsCache
    && allHostsNavigationPacketsCache.version === packetNavigationCacheVersion
  ) {
    return allHostsNavigationPacketsCache.packets;
  }

  const hostMap =
    capturedPackets && typeof capturedPackets["host"] === "object"
      ? capturedPackets["host"]
      : {};
  const allPackets = [];
  Object.keys(hostMap).forEach((host) => {
    const hostPackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
    allPackets.push(...hostPackets);
  });
  const sortedAllPackets = sortPacketsByOwnStreamOrder(allPackets);
  allHostsNavigationPacketsCache = {
    version: packetNavigationCacheVersion,
    packets: sortedAllPackets,
  };
  return sortedAllPackets;
}

// Returns packets for selected host.
function getPacketsForSelectedHost(selectedHost) {
  if (isAllHostsSelection(selectedHost)) {
    return getAllPacketsForHostNavigation();
  }
  if (isBookmarkedSelection(selectedHost)) {
    return getBookmarkedPacketsForHostNavigation();
  }

  const normalizedHost = String(selectedHost || "").trim();
  const cachedHostPackets = hostNavigationPacketsCache.get(normalizedHost);
  if (
    cachedHostPackets
    && cachedHostPackets.version === packetNavigationCacheVersion
  ) {
    return cachedHostPackets.packets;
  }

  const hostPackets = Array.isArray(capturedPackets?.["host"]?.[selectedHost])
    ? capturedPackets["host"][selectedHost]
    : [];
  const sortedHostPackets = sortPacketsByOwnStreamOrder([...hostPackets]);
  hostNavigationPacketsCache.set(normalizedHost, {
    version: packetNavigationCacheVersion,
    packets: sortedHostPackets,
  });
  return sortedHostPackets;
}

// Parses packet timestamp ms.
function parsePacketTimestampMs(packet) {
  const packetTimestamp =
    packet?.["packet.info"]?.["packet.timestamp"] ??
    packet?.["packet.info"]?.["Packet Timestamp"];
  if (typeof packetTimestamp !== "string" || !packetTimestamp.trim()) {
    return null;
  }
  const parsedTimestamp = Date.parse(packetTimestamp);
  return Number.isFinite(parsedTimestamp) ? parsedTimestamp : null;
}

// Parses packet processed number.
function parsePacketProcessedNumber(packet) {
  const processedRaw = Number(
    packet?.["packet.info"]?.["packet.processed"] ??
    packet?.["packet.info"]?.["Packet Processed"],
  );
  return Number.isFinite(processedRaw) ? processedRaw : null;
}

// Parses packet index number.
function parsePacketIndexNumber(packet) {
  const packetIndexRaw = Number(
    packet?.["packet.info"]?.["index"] ?? packet?.["packet.info"]?.["Index"],
  );
  return Number.isFinite(packetIndexRaw) ? packetIndexRaw : null;
}

// Handles compare packets chronologically.
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

// Sorts packets by own stream order.
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

// Handles tokenize local filter query.
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

// Handles union packet keys.
function unionPacketKeys(leftKeys, rightKeys) {
  return Array.from(new Set([...leftKeys, ...rightKeys]));
}

// Handles intersect packet keys.
function intersectPacketKeys(leftKeys, rightKeys) {
  const rightSet = new Set(rightKeys);
  return leftKeys.filter((packetKey) => rightSet.has(packetKey));
}

// Handles subtract packet keys.
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

  trackFilterKeyUsage(filterQuery);

  if (trackHistory) {
    addFilterHistory(filterQuery);
  }

  try {
    const matchedPacketKeys = await evaluateFilterQueryToPacketKeys(filterQuery);
    filteredPackets = await resolvePacketStubsByKeys(matchedPacketKeys);
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

// Clears filter query.
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

function packetKeyForFilterResult(packet, fallbackIndex = 0) {
  const packetInfo = packet?.["packet.info"];
  if (!packetInfo) return null;
  const sourceIp =
    packetInfo?.["IP"]?.["ip.src.addr"] ??
    packetInfo?.["IP"]?.["Source IP"] ??
    "Unknown";
  const packetIndex =
    packetInfo?.["index"] ?? packetInfo?.["Index"] ?? fallbackIndex;
  return `${sourceIp}:${packetIndex}`;
}

function collectPacketKeysForFilterResult(packetList) {
  if (!Array.isArray(packetList)) return [];
  return packetList
    .map((packet, index) => packetKeyForFilterResult(packet, index))
    .filter((packetKey) => typeof packetKey === "string" && packetKey.trim());
}

window.addEventListener("message", (event) => {
  const data = event?.data;
  if (!data || typeof data !== "object") return;
  if (data.source !== "packetsnitch-plugin-runtime") return;
  if (data.type !== "plugin-keystore-write") return;

  const requestPayload =
    data.payload && typeof data.payload === "object" ? data.payload : {};
  const action = String(requestPayload.action || "").trim();

  const respond = (resultPayload) => {
    window.postMessage(
      {
        source: "packetsnitch-renderer",
        type: "plugin-keystore-write-result",
        ...resultPayload,
      },
      "*",
    );
  };

  try {
    if (!keystorePanel || typeof keystorePanel.addSessionKeystoreEntry !== "function") {
      throw new Error("Keystore panel is unavailable");
    }

    const pushEntry = (entry) => {
      if (!entry || typeof entry !== "object") return false;
      const beforeCount =
        typeof keystorePanel.getSessionKeychainEntries === "function"
          ? keystorePanel.getSessionKeychainEntries().length
          : 0;
      keystorePanel.addSessionKeystoreEntry({
        type: entry.type,
        label: entry.label,
        source: entry.source,
        content: entry.content,
        summary: entry.summary,
        packetIndex: entry.packetIndex,
      });
      const afterCount =
        typeof keystorePanel.getSessionKeychainEntries === "function"
          ? keystorePanel.getSessionKeychainEntries().length
          : beforeCount;
      return afterCount > beforeCount;
    };

    let addedCount = 0;
    if (action === "addSessionEntries") {
      const entries = Array.isArray(requestPayload.entries)
        ? requestPayload.entries
        : [];
      entries.forEach((entry) => {
        if (pushEntry(entry)) {
          addedCount += 1;
        }
      });
    } else {
      if (pushEntry(requestPayload.entry)) {
        addedCount = 1;
      }
    }

    syncPluginRuntimeData();
    respond({ success: true, addedCount });
  } catch (error) {
    respond({
      success: false,
      error: error?.message || String(error || "Plugin keystore write failed"),
    });
  }
});

window.addEventListener("message", async (event) => {
  const data = event?.data;
  if (!data || typeof data !== "object") return;
  if (data.source !== "packetsnitch-plugin-runtime") return;
  if (data.type !== "plugin-filter-query") return;

  const requestId = String(data.requestId || "").trim();
  if (!requestId) return;

  const requestPayload =
    data.payload && typeof data.payload === "object" ? data.payload : {};
  const expression = String(requestPayload.expression || "").trim();
  const mode =
    String(requestPayload.mode || "").trim().toLowerCase() === "ui"
      ? "ui"
      : "background";

  const respond = (resultPayload) => {
    window.postMessage(
      {
        source: "packetsnitch-renderer",
        type: "plugin-filter-query-result",
        requestId,
        ...resultPayload,
      },
      "*",
    );
  };

  try {
    if (!expression) {
      throw new Error("Filter expression is required");
    }

    if (mode === "ui") {
      filterInputEl.value = expression;
      syncFilterHighlight();
      await runFilterQuery(expression, {
        trackHistory: Boolean(requestPayload.trackHistory),
        updateUi: true,
        logQueryOutcome: false,
      });
      const packetKeys = collectPacketKeysForFilterResult(filteredPackets);
      respond({
        success: true,
        result: {
          mode: "ui",
          packetKeys,
          packetCount: packetKeys.length,
        },
      });
      return;
    }

    if (window.captureapi && typeof window.captureapi.filter === "function") {
      const filterResult = await window.captureapi.filter(expression);
      if (!filterResult?.success) {
        throw new Error(filterResult?.error || "Background filter query failed");
      }
      const packetKeys = Array.isArray(filterResult.packetKeys)
        ? filterResult.packetKeys
        : [];
      respond({
        success: true,
        result: {
          mode: "background",
          packetKeys,
          packetCount: packetKeys.length,
        },
      });
      return;
    }

    await runFilterQuery(expression, {
      trackHistory: false,
      updateUi: false,
      logQueryOutcome: false,
    });
    const packetKeys = collectPacketKeysForFilterResult(filteredPackets);
    respond({
      success: true,
      result: {
        mode: "background",
        packetKeys,
        packetCount: packetKeys.length,
      },
    });
  } catch (error) {
    respond({
      success: false,
      error: error?.message || String(error || "Plugin filter query failed"),
    });
  }
});

// Handles deep clone session data.
function deepCloneSessionData(value, fallback) {
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return fallback;
  }
}

function syncPluginRuntimeData(options = {}) {
  if (!window.pluginapi || typeof window.pluginapi.updateRuntimeData !== "function") {
    return;
  }

  const includeStats = Boolean(options.includeStats);
  const contextPacket = getCurrentPacketForExport();
  const contextPacketInfo =
    contextPacket && typeof contextPacket === "object" ? contextPacket["packet.info"] : null;

  const payload = {
    currentPacketKey:
      typeof currentPacketKey === "string" && currentPacketKey.trim()
        ? currentPacketKey.trim()
        : null,
    currentPacketMetadata: contextPacketInfo
      ? {
        packetKey:
          typeof currentPacketKey === "string" && currentPacketKey.trim()
            ? currentPacketKey.trim()
            : null,
        packetInfo: deepCloneSessionData(contextPacketInfo, {}),
        activePacketCursor: getActivePacketCursor(),
      }
      : null,
    currentStreamTuple: deepCloneSessionData(getCurrentStreamTuple(), null),
    sessionPcapSource: sessionPcapSource
      ? {
        fileName: sessionPcapSource.fileName,
        encoding: sessionPcapSource.encoding,
        data: sessionPcapSource.data,
        byteLength: sessionPcapSource.byteLength,
      }
      : null,
    keystoreEntries: deepCloneSessionData(
      typeof keystorePanel?.getSessionKeychainEntries === "function"
        ? keystorePanel.getSessionKeychainEntries()
        : [],
      [],
    ),
  };

  if (includeStats) {
    payload.statsJson = buildCaptureStats(
      capturedPackets,
      Array.isArray(bookmarkList) ? bookmarkList.length : 0,
    );
  }

  try {
    window.pluginapi.updateRuntimeData(payload);
  } catch (error) {
    logErrorEntry("plugin-runtime-sync", error);
  }
}

// Normalizes note color.
function normalizeNoteColor(colorValue) {
  const normalized =
    typeof colorValue === "string" ? colorValue.trim().toLowerCase() : "";
  if (/^#[0-9a-f]{6}$/.test(normalized)) return normalized;
  return NOTE_DEFAULT_COLOR;
}

// Handles generate note id.
function generateNoteId() {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  noteIdCounter += 1;
  return `note-${Date.now()}-${noteIdCounter}`;
}

// Returns whether a note entry is flagged as concrete/verified data. Notes
// default to "inferred" because the analyst is asserting context, not
// capturing packets; the user must explicitly opt in to the concrete label.
function isNoteConcrete(noteEntry) {
  if (!noteEntry || typeof noteEntry !== "object") return false;
  return noteEntry.concrete === true;
}

// Creates note entry.
function createNoteEntry(text = "", color = NOTE_DEFAULT_COLOR, options = null) {
  const concreteFlag =
    options && typeof options === "object" && options.concrete === true;
  return {
    id: generateNoteId(),
    text: typeof text === "string" ? text : String(text || ""),
    color: normalizeNoteColor(color),
    // Inferred by default. The user can flip a note to "concrete" via the
    // Verified toggle in the Notes editor pane when they want the Summary
    // tab to treat its content as a concrete data point instead of an
    // analyst inference.
    concrete: Boolean(concreteFlag),
  };
}

// Normalizes markdown link url.
function normalizeMarkdownLinkUrl(urlText) {
  const candidate = String(urlText || "").trim().replace(/&amp;/g, "&");
  if (/^(https?:\/\/|mailto:)/i.test(candidate)) return candidate;
  return "";
}

// Handles sanitize markdown preview html.
function sanitizeMarkdownPreviewHtml(renderedHtml) {
  const template = document.createElement("template");
  template.innerHTML = String(renderedHtml || "");

  const allowedTags = new Set([
    "a",
    "blockquote",
    "br",
    "code",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "li",
    "ol",
    "p",
    "pre",
    "strong",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
  ]);

  const elementNodes = Array.from(template.content.querySelectorAll("*")).reverse();
  elementNodes.forEach((node) => {
    const tagName = node.tagName.toLowerCase();
    if (!allowedTags.has(tagName)) {
      node.replaceWith(...Array.from(node.childNodes));
      return;
    }

    Array.from(node.attributes).forEach((attribute) => {
      if (tagName === "a" && attribute.name === "href") {
        const safeUrl = normalizeMarkdownLinkUrl(attribute.value);
        if (!safeUrl) {
          node.removeAttribute("href");
        } else {
          node.setAttribute("href", safeUrl);
        }
        return;
      }

      if (tagName === "th" || tagName === "td") {
        if (attribute.name === "style" && /^text-align:\s*(left|center|right)$/i.test(attribute.value.trim())) {
          return;
        }
      }

      if (tagName === "a" && (attribute.name === "target" || attribute.name === "rel")) {
        return;
      }

      node.removeAttribute(attribute.name);
    });

    if (tagName === "a") {
      node.setAttribute("target", "_blank");
      node.setAttribute("rel", "noopener noreferrer");
    }
  });

  return template.innerHTML;
}

// Renders markdown to html.
function renderMarkdownToHtml(markdownText, options = {}) {
  const { emptyPlaceholder = "No note selected." } =
    options && typeof options === "object" ? options : {};
  const source = String(markdownText || "").replace(/\r\n?/g, "\n");
  if (!source.trim()) {
    return `<p class="notes-markdown-placeholder">${escapeHtml(String(emptyPlaceholder || ""))}</p>`;
  }

  const renderedHtml = marked.parse(source, {
    breaks: false,
    gfm: true,
    headerIds: false,
    mangle: false,
  });

  return sanitizeMarkdownPreviewHtml(renderedHtml);
}

// Renders selected note markdown preview.
function renderSelectedNoteMarkdownPreview(noteText) {
  const notesPreviewEl = document.getElementById("notes-markdown-preview");
  if (!notesPreviewEl) return;
  initializeNotesMarkdownPreviewLinkHandling();
  notesPreviewEl.innerHTML = renderMarkdownToHtml(noteText);
}

// Single source of truth for the report's top-level heading. The
// heading is prepended once at the top of the combined summary report
// rather than being added inside `normalizeSummaryMarkdownHeadings`,
// which can be invoked multiple times per entry and would otherwise
// print "PacketSnitch's Summary" repeatedly.
const SUMMARY_HEADING = "# PacketSnitch's Summary";

// Prepends the consolidated summary heading to a markdown body. The
// heading is the only place it is added so that the rest of the report
// can repeat its own section headings without producing duplicates.
function prependSummaryHeading(markdownText) {
  const body = String(markdownText || "").trim();
  if (!body) {
    return `${SUMMARY_HEADING}\n\n_No summary available._`;
  }
  // If the body already starts with the heading (e.g. caller passed
  // already-heading-prefixed content), don't double it up.
  if (body.startsWith(SUMMARY_HEADING)) {
    return body;
  }
  return `${SUMMARY_HEADING}\n\n${body}`;
}

// Normalizes summary markdown headings.
//
// This function is intentional about NOT adding the top-level report
// heading — the heading is added once at the top of the combined report
// via `prependSummaryHeading`. Adding it here too would cause repeated
// "PacketSnitch's Summary" headings when the function is invoked per
// context-scoped entry (see `buildSummaryBodyHtmlForHtmlExport`).
function normalizeSummaryMarkdownHeadings(markdownText) {
  const source = String(markdownText || "").replace(/\r\n?/g, "\n");
  if (!source.trim()) {
    return "";
  }

  const lines = source.split("\n");
  const normalizedLines = [];
  let inFence = false;

  lines.forEach((line) => {
    const trimmed = line.trim();
    if (/^(```|~~~)/.test(trimmed)) {
      inFence = !inFence;
      normalizedLines.push(line);
      return;
    }

    if (!inFence) {
      const headingMatch = line.match(/^(\s{0,3})(#{1,6})(\s+)(.*)$/);
      if (headingMatch) {
        const [, indent, hashes, spacing, titleText] = headingMatch;
        // Strip any incoming h1 from LLM content; the Summary tab
        // provides one fixed h1 at the top of the report via
        // `prependSummaryHeading`.
        if (hashes.length === 1) {
          normalizedLines.push(`${indent}##${spacing}${titleText}`);
          return;
        }

        // Clamp all remaining headings to h2/h3/h4 for accessible summary structure.
        //const clampedLevel = hashes.length <= 2 ? 2 : 3;
        const clampedLevel = Math.min(Math.max(hashes.length, 2), 4);
        normalizedLines.push(`${indent}${"#".repeat(clampedLevel)}${spacing}${titleText}`);
        return;
      }
    }

    normalizedLines.push(line);
  });

  return normalizedLines.join("\n").trim();
}

// Renders summary markdown preview.
function renderSummaryMarkdownPreview(summaryText) {
  const summaryPreviewEl = document.getElementById("summary_content");
  if (!summaryPreviewEl) return;
  initializeSummaryMarkdownLinkHandling();
  summaryPreviewEl.innerHTML = renderMarkdownToHtml(
    prependSummaryHeading(normalizeSummaryMarkdownHeadings(summaryText)),
    { emptyPlaceholder: "No summary available" },
  );
}

// Renders the running compacted analysis summary in the Summary panel.
// Renders the running compacted analysis summaries in the Summary panel.
// Individual analysis blurbs are kept internal and are only visible after
// compaction. Multiple context-scoped summaries are shown in sequence.
//
// The Summary tab also includes the analyst's Notes (split into
// "Inferred Data" and "Verified Notes" buckets) so any note added or
// edited on the Notes tab is reflected here automatically. See
// `getCurrentSummaryReportMarkdown`.
function renderCombinedAnalysisSummary() {
  renderSummaryMarkdownPreview(getCurrentSummaryReportMarkdown());
}

// Returns normalized summary markdown for export.
function getSummaryMarkdownForExport() {
  const body = normalizeSummaryMarkdownHeadings(
    getCurrentSummaryReportMarkdown(),
  );
  const statsSection = buildStatsMarkdownSection();
  let combined = body;
  if (body && statsSection) {
    combined = `${body}\n\n---\n\n${statsSection}`;
  } else if (!body && statsSection) {
    combined = statsSection;
  }
  if (!combined) return "";
  return prependSummaryHeading(combined);
}
// Formats a human-readable byte count (e.g. 1.5 KB, 12.34 MB) for the stats
// summary section. Returns "0 B" for non-positive values.
function formatStatsByteCount(bytesValue) {
  const bytes = Number(bytesValue);
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const decimals = unitIndex === 0 ? 0 : 2;
  return `${value.toFixed(decimals)} ${units[unitIndex]}`;
}

// Joins a list of strings/values as a comma-separated string, falling back to
// a placeholder when the list is empty. Non-string entries are coerced.
function joinStatsListValues(values, emptyLabel = "None") {
  if (!Array.isArray(values) || values.length === 0) return emptyLabel;
  return values
    .map((value) => (value === null || value === undefined ? "" : String(value)))
    .filter((value) => value.length > 0)
    .join(", ") || emptyLabel;
}

// Truncates a list to at most `maxItems` items and appends an indicator when
// the original list was longer. Returns the truncated array and the original
// length for the caller to format the indicator.
function truncateStatsList(values, maxItems) {
  if (!Array.isArray(values) || values.length <= maxItems) {
    return { values: Array.isArray(values) ? values : [], truncated: 0 };
  }
  return {
    values: values.slice(0, maxItems),
    truncated: values.length - maxItems,
  };
}

// Renders a markdown table from a header row and body rows. Returns an empty
// string when the body is empty so the caller can skip the section gracefully.
function buildStatsMarkdownTable(headers, rows) {
  if (!Array.isArray(rows) || rows.length === 0) return "";
  const headerLine = `| ${headers.join(" | ")} |`;
  const separatorLine = `| ${headers.map(() => "---").join(" | ")} |`;
  const bodyLines = rows
    .map((row) => {
      const cells = headers.map((_, index) => {
        const cell = row[index];
        if (cell === null || cell === undefined) return "";
        return String(cell).replace(/\|/g, "\\|").replace(/\n/g, " ");
      });
      return `| ${cells.join(" | ")} |`;
    })
    .join("\n");
  return `${headerLine}\n${separatorLine}\n${bodyLines}`;
}

// Builds a markdown section summarising the captured packet statistics. This
// is the same data shown on the Stats tab and is woven into the exported
// summary so the analyst has a complete snapshot of the pcap alongside the
// LLM's narrative. Returns an empty string when no capture data is available.
function buildStatsMarkdownSection() {
  if (!capturedPackets || typeof capturedPackets !== "object") return "";
  const hostBuckets = capturedPackets["host"];
  if (!hostBuckets || typeof hostBuckets !== "object") return "";

  const stats = (() => {
    try {
      return buildCaptureStats(
        capturedPackets,
        Array.isArray(bookmarkList) ? bookmarkList.length : 0,
      );
    } catch (err) {
      writeLogEntry(
        `buildStatsMarkdownSection: failed to compute stats: ${err?.message || err}`,
      );
      return null;
    }
  })();
  if (!stats) return "";

  const parts = [];
  parts.push("## Capture Statistics");
  parts.push("");

  // Overview table: top-line packet, stream, and traffic counts.
  const totalTraffic = formatStatsByteCount(stats.totalTraffic);
  const overviewRows = [
    ["Total packets", String(stats.totalPackets ?? 0)],
    ["Total streams", String(stats.totalStreams ?? 0)],
    ["Total traffic", totalTraffic],
    ["Internet hosts", String(stats.internetHostCount ?? 0)],
    ["Encrypted packets", String(stats.encryptedCount ?? 0)],
    ["Unencrypted packets", String(stats.unencryptedCount ?? 0)],
    ["Undecodable packets", String(stats.undecodableCount ?? 0)],
    ["Bookmarks", String(stats.bookmarkCount ?? 0)],
  ];
  if (stats.totalStreams > 1) {
    overviewRows.push(
      [
        "Stream length (avg / min / max)",
        `${stats.avgStreamLength} / ${stats.minStreamLength} / ${stats.maxStreamLength} packets`,
      ],
      [
        "TCP retransmissions",
        String(stats.retransmissionCount ?? 0),
      ],
      [
        "Out-of-order segments",
        String(stats.outOfOrderCount ?? 0),
      ],
    );
  }
  parts.push(buildStatsMarkdownTable(["Metric", "Value"], overviewRows));
  parts.push("");

  // Protocol summary. Network/link/transport stack plus decoded protocols.
  if (Array.isArray(stats.protocols) && stats.protocols.length > 0) {
    parts.push("### Protocols");
    parts.push("");
    if (
      Array.isArray(stats.networkProtocols) &&
      stats.networkProtocols.length > 0
    ) {
      parts.push(
        `- **Network layer:** ${joinStatsListValues(stats.networkProtocols)}`,
      );
    }
    if (
      Array.isArray(stats.linkProtocols) &&
      stats.linkProtocols.length > 0
    ) {
      parts.push(
        `- **Link layer:** ${joinStatsListValues(stats.linkProtocols)}`,
      );
    }
    if (
      Array.isArray(stats.transportProtocols) &&
      stats.transportProtocols.length > 0
    ) {
      parts.push(
        `- **Transport layer:** ${joinStatsListValues(stats.transportProtocols)}`,
      );
    }
    if (
      Array.isArray(stats.decodedProtocols) &&
      stats.decodedProtocols.length > 0
    ) {
      const decoded = truncateStatsList(stats.decodedProtocols, 25);
      const decodedLine = joinStatsListValues(decoded.values);
      const decodedSuffix =
        decoded.truncated > 0 ? ` (+${decoded.truncated} more)` : "";
      parts.push(`- **Decoded protocols:** ${decodedLine}${decodedSuffix}`);
    }
    if (
      Array.isArray(stats.arpOperations) &&
      stats.arpOperations.length > 0
    ) {
      parts.push(
        `- **ARP operations:** ${joinStatsListValues(stats.arpOperations)}`,
      );
    }
    if (
      Array.isArray(stats.igmpMessageTypes) &&
      stats.igmpMessageTypes.length > 0
    ) {
      parts.push(
        `- **IGMP message types:** ${joinStatsListValues(stats.igmpMessageTypes)}`,
      );
    }
    if (Array.isArray(stats.dataTypes) && stats.dataTypes.length > 0) {
      const dataTypes = truncateStatsList(stats.dataTypes, 25);
      const dataTypeLine = joinStatsListValues(dataTypes.values);
      const dataTypeSuffix =
        dataTypes.truncated > 0 ? ` (+${dataTypes.truncated} more)` : "";
      parts.push(
        `- **Data classifications:** ${dataTypeLine}${dataTypeSuffix}`,
      );
    }
    parts.push("");
  }

  // Hosts, ports, and MAC vendors.
  const hasHosts =
    Array.isArray(stats.hosts) && stats.hosts.length > 0;
  const hasPorts =
    Array.isArray(stats.ports) && stats.ports.length > 0;
  const hasMacVendors =
    Array.isArray(stats.macVendors) && stats.macVendors.length > 0;
  if (hasHosts || hasPorts || hasMacVendors) {
    parts.push("### Hosts, Ports, and Vendors");
    parts.push("");
    if (hasHosts) {
      const hosts = truncateStatsList(stats.hosts, 25);
      const hostLine = joinStatsListValues(hosts.values);
      const hostSuffix =
        hosts.truncated > 0 ? ` (+${hosts.truncated} more)` : "";
      parts.push(`- **Hosts (${stats.hosts.length}):** ${hostLine}${hostSuffix}`);
    }
    if (hasPorts) {
      const ports = truncateStatsList(stats.ports, 25);
      const portLine = joinStatsListValues(ports.values);
      const portSuffix =
        ports.truncated > 0 ? ` (+${ports.truncated} more)` : "";
      parts.push(`- **Ports (${stats.ports.length}):** ${portLine}${portSuffix}`);
    }
    if (hasMacVendors) {
      const vendors = truncateStatsList(stats.macVendors, 25);
      const vendorLine = joinStatsListValues(vendors.values);
      const vendorSuffix =
        vendors.truncated > 0 ? ` (+${vendors.truncated} more)` : "";
      parts.push(
        `- **MAC vendors (${stats.macVendors.length}):** ${vendorLine}${vendorSuffix}`,
      );
    }
    if (
      Array.isArray(stats.hostnames) &&
      stats.hostnames.length > 0
    ) {
      const hostnames = truncateStatsList(stats.hostnames, 15);
      const hostnameLine = joinStatsListValues(hostnames.values);
      const hostnameSuffix =
        hostnames.truncated > 0 ? ` (+${hostnames.truncated} more)` : "";
      parts.push(
        `- **Hostnames (${stats.hostnames.length}):** ${hostnameLine}${hostnameSuffix}`,
      );
    }
    parts.push("");
  }

  // Top talkers by packet count.
  if (Array.isArray(stats.topTalkers) && stats.topTalkers.length > 0) {
    parts.push("### Top Talkers");
    parts.push("");
    const talkerRows = stats.topTalkers.map((talker) => [
      talker?.ip ?? "unknown",
      String(talker?.count ?? 0),
    ]);
    parts.push(
      buildStatsMarkdownTable(["Host", "Packets"], talkerRows),
    );
    parts.push("");
  }

  // Geographic footprint, if any resolved locations are present.
  if (Array.isArray(stats.locations) && stats.locations.length > 0) {
    const locationRows = stats.locations
      .slice(0, 15)
      .map((locationEntry) => {
        const label = Array.isArray(locationEntry)
          ? String(locationEntry[0] ?? "Unknown")
          : "Unknown";
        const count = Array.isArray(locationEntry)
          ? String(locationEntry[1] ?? 0)
          : "0";
        return [label, count];
      });
    parts.push("### Geographic Footprint");
    parts.push("");
    parts.push(buildStatsMarkdownTable(["Location", "Hits"], locationRows));
    parts.push("");
  }

  // MIME types observed in payload streams.
  if (Array.isArray(stats.mimeTypes) && stats.mimeTypes.length > 0) {
    const mimes = truncateStatsList(stats.mimeTypes, 20);
    const mimeLine = joinStatsListValues(mimes.values);
    const mimeSuffix = mimes.truncated > 0 ? ` (+${mimes.truncated} more)` : "";
    parts.push(
      `### MIME Types\n\n- **MIME types (${stats.mimeTypes.length}):** ${mimeLine}${mimeSuffix}\n`,
    );
  }

  // Heatmap hits summary.
  if (stats.heatmapPacketHits && stats.heatmapPacketHits > 0) {
    parts.push(
      `### Heatmap\n\n- **Heatmap packet hits:** ${stats.heatmapPacketHits}\n`,
    );
  }

  // Credentials summary (uses masked values, same as the Stats tab).
  const creds = Array.isArray(stats.uniqueCredentials)
    ? stats.uniqueCredentials
    : [];
  if (creds.length > 0 || (stats.uniqueCredentialCount ?? 0) > 0) {
    const uniqueCount = stats.uniqueCredentialCount ?? creds.length;
    const previewLimit = 15;
    const previewList = creds.slice(0, previewLimit);
    const previewSuffix =
      creds.length > previewLimit ? ` (+${creds.length - previewLimit} more)` : "";
    parts.push(
      `### Credentials\n\n- **Unique credentials (${uniqueCount}):** ${joinStatsListValues(
        previewList,
      )}${previewSuffix}\n`,
    );
  }

  // Drop trailing blank line so the section joins cleanly with surrounding text.
  while (parts.length && parts[parts.length - 1] === "") {
    parts.pop();
  }
  return parts.join("\n");
}

// Returns the concatenated compacted analysis summaries for the current view.
// If no compacted summaries exist yet, falls back to the live stream summary.
//
// Note: the user-curated Notes from the Notes tab are added separately by
// `getCurrentSummaryReportMarkdown` so that the per-stream LLM content
// stays in `compactedAnalysisSummaries` while note-derived content
// (inferred / verified) flows in independently.
function getCurrentCompactedAnalysisSummary() {
  const summaries = Array.isArray(compactedAnalysisSummaries)
    ? compactedAnalysisSummaries
    : [];
  if (summaries.length === 0) {
    return summary;
  }
  return summaries
    .map((entry) => entry?.summary || "")
    .filter(Boolean)
    .join("\n\n---\n\n");
}

// Returns the analyst's Notes formatted as a markdown section for the
// Summary tab. Notes are split into two buckets:
//
//   - **Inferred notes** (default): analyst observations that the LLM
//     and the rest of the Summary tab should treat as inferred data,
//     not concrete observed facts. Rendered under a clear "Inferred
//     Data" heading so the analyst can never confuse the two.
//   - **Verified notes** (`concrete: true`): notes the analyst has
//     explicitly flagged as concrete/verified. These still appear on
//     the Summary tab but under a "Verified Notes" heading that makes
//     it obvious they carry more weight than inferred observations.
//
// Returns an empty string when there are no notes, so callers can join
// the result with `---` separators without leaving dangling dividers.
function getNotesSummarySection() {
  if (!Array.isArray(notesList) || notesList.length === 0) return "";
  const inferredNotes = [];
  const verifiedNotes = [];
  notesList.forEach((noteEntry) => {
    if (!noteEntry || typeof noteEntry !== "object") return;
    const noteText = String(noteEntry.text || "").trim();
    if (!noteText) return;
    if (isNoteConcrete(noteEntry)) {
      verifiedNotes.push({ entry: noteEntry, text: noteText });
    } else {
      inferredNotes.push({ entry: noteEntry, text: noteText });
    }
  });

  if (inferredNotes.length === 0 && verifiedNotes.length === 0) return "";

  const blocks = [];

  if (inferredNotes.length > 0) {
    const inferredLines = [
      "## Inferred Data (from Notes)",
      "",
      "> The following items were added by the analyst via the Notes tab.",
      "> They are treated as **inferred data** (analyst observations or",
      "> hypotheses) rather than concrete observed facts from the capture.",
      "",
    ];
    inferredNotes.forEach((note, index) => {
      const safeText = note.text.replace(/\r\n?/g, "\n");
      inferredLines.push(`### Inferred Note ${index + 1}`);
      inferredLines.push("");
      inferredLines.push(safeText);
      inferredLines.push("");
    });
    blocks.push(inferredLines.join("\n").trimEnd());
  }

  if (verifiedNotes.length > 0) {
    const verifiedLines = [
      "## Verified Notes (from Notes)",
      "",
      "> The following notes were explicitly marked as concrete/verified",
      "> by the analyst. They are treated as concrete data points, not as",
      "> inferences. Use them as authoritative context when reading the",
      "> Summary tab.",
      "",
    ];
    verifiedNotes.forEach((note, index) => {
      const safeText = note.text.replace(/\r\n?/g, "\n");
      verifiedLines.push(`### Verified Note ${index + 1}`);
      verifiedLines.push("");
      verifiedLines.push(safeText);
      verifiedLines.push("");
    });
    blocks.push(verifiedLines.join("\n").trimEnd());
  }

  return blocks.join("\n\n---\n\n");
}

// Returns the full Summary tab report body in markdown form: the
// compacted LLM analysis plus the analyst-curated Notes section (split
// into inferred vs. verified). Both the on-screen renderer and the
// export pipeline use this so the Notes tab content is reflected
// everywhere the Summary tab is shown.
function getCurrentSummaryReportMarkdown() {
  const analysisBody = getCurrentCompactedAnalysisSummary();
  const notesSection = getNotesSummarySection();
  if (!analysisBody && !notesSection) return "";
  if (!notesSection) return analysisBody;
  if (!analysisBody) return notesSection;
  return `${analysisBody}\n\n---\n\n${notesSection}`;
}

// Notifies the Summary tab that Notes content has changed. The Summary
// tab is the authoritative home for note-derived content, so any
// mutation to `notesList` (add, remove, text edit, verified toggle)
// must re-render the Summary tab so the inferred/verified sections
// stay in sync. Safe to call when the Summary tab is not the active
// tab; `renderCombinedAnalysisSummary` is a no-op on a hidden tab and
// will simply re-render the next time the analyst switches to it.
function refreshSummaryForNotes() {
  if (typeof renderCombinedAnalysisSummary === "function") {
    renderCombinedAnalysisSummary();
  }
}

// Builds a stable signature string that identifies the current analysis context.
// Context changes when the main tab, current packet/stream, or Data Tools
// workspace changes meaningfully.
function buildAnalysisContextSignature() {
  const parts = [];
  parts.push(`tab:${activeMainTab || "none"}`);

  const packet = getCurrentContextPacket();
  const packetKey = packet?.__packetKey || "";
  const streamTuple = getStreamTupleForPacket(packet);
  parts.push(`pkt:${packetKey}`);
  if (streamTuple && streamTuple.srcIp && streamTuple.dstIp) {
    parts.push(
      `stream:${streamTuple.srcIp}:${streamTuple.srcPort ?? "-"}:${streamTuple.dstIp}:${streamTuple.dstPort ?? "-"}:${streamTuple.protocol || "none"}`,
    );
  }

  const convSubtab = getActiveConvSubtab() || "";
  if (activeMainTab === MAIN_TAB_DATA_TOOLS) {
    const dtHash = getCurrentSummaryContextHash(convSubtab) || "";
    parts.push(`dt:${convSubtab}:${dtHash}`);
  }

  return parts.join("|");
}

// Returns true when the two context signatures are different enough to be
// considered a major context change. Within the same packet stream and Data
// Tools workspace we keep adding to the same summary; changing tabs, packet
// keys, stream tuples, or Data Tools content creates a new context scope.
function isMajorContextShift(newSignature, existingSignature) {
  if (!existingSignature) return true;
  return newSignature !== existingSignature;
}

// Finds an existing compacted summary entry whose context signature exactly
// matches the provided signature.
function findAnalysisSummaryBySignature(signature) {
  if (!signature || !Array.isArray(compactedAnalysisSummaries)) return null;
  for (let i = 0; i < compactedAnalysisSummaries.length; i += 1) {
    if (compactedAnalysisSummaries[i]?.signature === signature) {
      return { entry: compactedAnalysisSummaries[i], index: i };
    }
  }
  return null;
}

// Normalizes plain-text export segment.
function normalizePlainTextExportSegment(value) {
  return String(value || "")
    .replace(/\r\n?/g, "\n")
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/[ \t]{2,}/g, " ")
    .trim();
}

// Extracts inline text from html node.
function extractInlineTextFromHtmlNode(node) {
  if (!node) return "";
  if (node.nodeType === Node.TEXT_NODE) {
    return node.textContent || "";
  }
  if (node.nodeType !== Node.ELEMENT_NODE) {
    return "";
  }
  if (node.tagName === "BR") {
    return "\n";
  }
  return Array.from(node.childNodes)
    .map((childNode) => extractInlineTextFromHtmlNode(childNode))
    .join("");
}

// Builds an ascii table from row data.
function buildAsciiTableFromRows(rows, headerRowCount = 0) {
  if (!Array.isArray(rows) || rows.length === 0) return "";
  const normalizeTableCell = (value) =>
    normalizePlainTextExportSegment(value)
      .replace(/\s*\n+\s*/g, " / ")
      .replace(/\s{2,}/g, " ")
      .trim();
  const normalizedRows = rows.map((row) =>
    Array.isArray(row)
      ? row.map((cell) => normalizeTableCell(cell))
      : [normalizeTableCell(row)],
  );
  const columnCount = normalizedRows.reduce(
    (max, row) => Math.max(max, row.length),
    0,
  );
  if (columnCount === 0) return "";

  normalizedRows.forEach((row) => {
    while (row.length < columnCount) row.push("");
  });

  const widths = new Array(columnCount).fill(0);
  normalizedRows.forEach((row) => {
    row.forEach((cell, index) => {
      widths[index] = Math.max(widths[index], String(cell).length);
    });
  });

  const divider = `+${widths.map((width) => "-".repeat(width + 2)).join("+")}+`;
  const formattedRows = normalizedRows.map(
    (row) =>
      `| ${row
        .map((cell, index) => String(cell).padEnd(widths[index], " "))
        .join(" | ")} |`,
  );

  const lines = [divider];
  formattedRows.forEach((line, index) => {
    lines.push(line);
    if (headerRowCount > 0 && index === headerRowCount - 1) {
      lines.push(divider);
    }
  });
  lines.push(divider);
  return lines.join("\n");
}

// Converts html table element to an ascii table.
function tableElementToAscii(tableEl) {
  const headerRows = Array.from(tableEl.querySelectorAll("thead tr")).map((rowEl) =>
    Array.from(rowEl.querySelectorAll("th, td")).map((cellEl) =>
      extractInlineTextFromHtmlNode(cellEl),
    ),
  );
  const bodyRows = Array.from(tableEl.querySelectorAll("tbody tr")).map((rowEl) =>
    Array.from(rowEl.querySelectorAll("th, td")).map((cellEl) =>
      extractInlineTextFromHtmlNode(cellEl),
    ),
  );
  const fallbackRows =
    headerRows.length === 0 && bodyRows.length === 0
      ? Array.from(tableEl.querySelectorAll("tr")).map((rowEl) =>
        Array.from(rowEl.querySelectorAll("th, td")).map((cellEl) =>
          extractInlineTextFromHtmlNode(cellEl),
        ),
      )
      : [];

  const rows = [...headerRows, ...bodyRows, ...fallbackRows];
  return buildAsciiTableFromRows(rows, headerRows.length);
}

// Converts html list to plain text lines.
function listElementToPlainText(listEl, level = 0, ordered = false) {
  const lines = [];
  const listItems = Array.from(listEl.children).filter(
    (child) => child.tagName === "LI",
  );

  listItems.forEach((itemEl, itemIndex) => {
    const marker = ordered ? `${itemIndex + 1}.` : "-";
    const cloneEl = itemEl.cloneNode(true);
    Array.from(cloneEl.children).forEach((child) => {
      if (child.tagName === "UL" || child.tagName === "OL") {
        child.remove();
      }
    });
    const itemText = normalizePlainTextExportSegment(
      extractInlineTextFromHtmlNode(cloneEl),
    );
    if (itemText) {
      lines.push(`${"  ".repeat(level)}${marker} ${itemText}`);
    }

    Array.from(itemEl.children).forEach((child) => {
      if (child.tagName === "UL") {
        const nested = listElementToPlainText(child, level + 1, false);
        if (nested) lines.push(nested);
      }
      if (child.tagName === "OL") {
        const nested = listElementToPlainText(child, level + 1, true);
        if (nested) lines.push(nested);
      }
    });
  });

  return lines.join("\n");
}

// Converts markdown summary text to plain text and renders markdown tables as ascii.
function convertSummaryMarkdownToPlainText(markdownText) {
  const renderedHtml = renderMarkdownToHtml(markdownText, {
    emptyPlaceholder: "No summary available",
  });
  const template = document.createElement("template");
  template.innerHTML = renderedHtml;

  const blocks = [];
  const appendBlock = (value, { preserveSpacing = false } = {}) => {
    const normalized = preserveSpacing
      ? String(value || "")
        .replace(/\r\n?/g, "\n")
        .replace(/\u00a0/g, " ")
        .trim()
      : normalizePlainTextExportSegment(value);
    if (!normalized) return;
    blocks.push(normalized);
  };

  Array.from(template.content.childNodes).forEach((node) => {
    if (node.nodeType === Node.TEXT_NODE) {
      appendBlock(node.textContent);
      return;
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return;

    const tagName = node.tagName.toLowerCase();
    if (/^h[1-6]$/.test(tagName) || tagName === "p") {
      appendBlock(extractInlineTextFromHtmlNode(node));
      return;
    }
    if (tagName === "blockquote") {
      const quoteText = normalizePlainTextExportSegment(
        extractInlineTextFromHtmlNode(node),
      );
      appendBlock(
        quoteText
          .split("\n")
          .map((line) => `> ${line}`)
          .join("\n"),
      );
      return;
    }
    if (tagName === "pre") {
      const preText = String(node.textContent || "")
        .replace(/\r\n?/g, "\n")
        .trimEnd();
      if (preText.trim()) blocks.push(preText);
      return;
    }
    if (tagName === "table") {
      appendBlock(tableElementToAscii(node), { preserveSpacing: true });
      return;
    }
    if (tagName === "ul") {
      appendBlock(listElementToPlainText(node, 0, false));
      return;
    }
    if (tagName === "ol") {
      appendBlock(listElementToPlainText(node, 0, true));
      return;
    }
    if (tagName === "hr") {
      blocks.push("----------------------------------------");
      return;
    }

    appendBlock(extractInlineTextFromHtmlNode(node));
  });

  return blocks.join("\n\n").trim();
}

// Normalizes external markdown link href.
function normalizeExternalMarkdownLinkHref(href) {
  const candidate = String(href || "").trim().replace(/&amp;/g, "&");
  if (/^(https?:|mailto:)/i.test(candidate)) return candidate;
  return "";
}

// Initializes notes markdown preview link handling.
function initializeNotesMarkdownPreviewLinkHandling() {
  const notesPreviewEl = document.getElementById("notes-markdown-preview");
  if (!notesPreviewEl || notesPreviewEl.dataset.linkHandlingInitialized === "true") {
    return;
  }

  notesPreviewEl.dataset.linkHandlingInitialized = "true";
  notesPreviewEl.addEventListener("click", async (event) => {
    const anchorEl = event.target?.closest?.("a[href]");
    if (!anchorEl || !notesPreviewEl.contains(anchorEl)) return;

    const openableUrl = normalizeExternalMarkdownLinkHref(anchorEl.getAttribute("href"));
    if (!openableUrl) return;

    event.preventDefault();
    event.stopPropagation();

    if (typeof window.browserapi?.openExternalUrl !== "function") {
      return;
    }

    await window.browserapi.openExternalUrl(openableUrl);
  });
}

// Initializes summary markdown link handling.
function initializeSummaryMarkdownLinkHandling() {
  const summaryPreviewEl = document.getElementById("summary_content");
  if (!summaryPreviewEl || summaryPreviewEl.dataset.linkHandlingInitialized === "true") {
    return;
  }

  summaryPreviewEl.dataset.linkHandlingInitialized = "true";
  summaryPreviewEl.addEventListener("click", async (event) => {
    const anchorEl = event.target?.closest?.("a[href]");
    if (!anchorEl || !summaryPreviewEl.contains(anchorEl)) return;

    const openableUrl = normalizeExternalMarkdownLinkHref(
      anchorEl.getAttribute("href"),
    );
    if (!openableUrl) return;

    event.preventDefault();
    event.stopPropagation();

    if (typeof window.browserapi?.openExternalUrl !== "function") {
      return;
    }

    await window.browserapi.openExternalUrl(openableUrl);
  });
}

// Syncs notes editor visibility ui.
function syncNotesEditorVisibilityUi() {
  const notesEditorWrapEl = document.querySelector(".notes-editor-wrap");
  const notesEditorEl = document.getElementById("notes-editor");
  const toggleButtonEl = document.getElementById("notes-edit-toggle-btn");
  const hasSelectedNote = Boolean(getSelectedNoteEntry());
  const showEditor = hasSelectedNote && notesEditorVisible;

  if (notesEditorWrapEl) {
    notesEditorWrapEl.classList.toggle("notes-editor-hidden", !showEditor);
  }
  if (notesEditorEl) {
    notesEditorEl.disabled = !hasSelectedNote || !showEditor;
  }
  if (toggleButtonEl) {
    toggleButtonEl.disabled = !hasSelectedNote;
    toggleButtonEl.textContent = showEditor ? "Done Editing" : "Edit Note";
  }
}

// Sets notes editor visibility.
function setNotesEditorVisibility(visible) {
  notesEditorVisible = Boolean(visible);
  syncNotesEditorVisibilityUi();
}

// Returns selected note entry.
function getSelectedNoteEntry() {
  return notesList.find((entry) => entry.id === selectedNoteId) || null;
}

// Renders notes list.
function renderNotesList() {
  const notesSelectEl = document.getElementById("notes-select");
  const notesEditorEl = document.getElementById("notes-editor");
  const newNoteColorEl = document.getElementById("notes-new-color");
  if (!notesSelectEl || !notesEditorEl || !newNoteColorEl) return;

  notesSelectEl.replaceChildren();
  if (!notesList.length) {
    selectedNoteId = null;
    notesEditorVisible = false;
    notesEditorEl.value = "";
    renderSelectedNoteMarkdownPreview("");
    syncNotesEditorVisibilityUi();
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
  notesEditorEl.value = selectedNoteEntry ? selectedNoteEntry.text : "";
  renderSelectedNoteMarkdownPreview(selectedNoteEntry ? selectedNoteEntry.text : "");
  newNoteColorEl.value = selectedNoteEntry
    ? normalizeNoteColor(selectedNoteEntry.color)
    : NOTE_DEFAULT_COLOR;
  // Sync the Verified toggle so it always reflects the selected note's
  // current concrete/inferred flag.
  const notesConcreteToggleEl = document.getElementById(
    "notes-concrete-toggle",
  );
  if (notesConcreteToggleEl) {
    notesConcreteToggleEl.checked = isNoteConcrete(selectedNoteEntry);
    notesConcreteToggleEl.disabled = !selectedNoteEntry;
  }
  syncNotesEditorVisibilityUi();
}

// Handles add note.
function addNote(
  text,
  color = NOTE_DEFAULT_COLOR,
  sourceLabel = "manual",
  editorVisible = true,
) {
  const normalizedText =
    typeof text === "string" ? text.trim() : String(text || "").trim();
  if (!normalizedText) {
    statusUpdate("Status: No note text to add");
    return false;
  }
  const noteEntry = createNoteEntry(normalizedText, color);
  notesList.unshift(noteEntry);
  selectedNoteId = noteEntry.id;
  notesEditorVisible = Boolean(editorVisible);
  renderNotesList();
  // Notes feed the Summary tab as inferred/verified data, so any add
  // must refresh the rendered Summary so the analyst sees the new
  // entry without manually re-running the LLM.
  refreshSummaryForNotes();
  statusUpdate("Status: Note added");
  writeLogEntry(
    `Note added source=${sourceLabel} length=${normalizedText.length}`,
  );
  return true;
}

// Handles remove selected note.
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
  notesEditorVisible = false;
  renderNotesList();
  // Remove the deleted entry from any rendered Summary view.
  refreshSummaryForNotes();
  statusUpdate("Status: Note removed");
  writeLogEntry(`Note removed id=${selectedNoteEntry.id}`);
}

// Formats notes for export.
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

// Handles escape markdown table cell.
function escapeMarkdownTableCell(text) {
  return String(text || "").replace(/\|/g, "\\|").replace(/\n/g, "<br>");
}

// Returns conv decoded result from dom table.
function getConvDecodedResultFromDomTable() {
  const protoOutputEl = document.getElementById("data-tools-proto-output");
  const serializedResult = protoOutputEl?.dataset?.decodedResult;
  if (serializedResult) {
    try {
      const parsed = JSON.parse(serializedResult);
      if (parsed && Array.isArray(parsed.fields)) {
        return {
          protocol: parsed.protocol || null,
          fields: parsed.fields,
        };
      }
    } catch {
      // Fall back to parsing table DOM.
    }
  }

  const tableEl = document.querySelector(
    "#data-tools-proto-output table.data-tools-proto-table",
  );
  if (!tableEl) return null;

  const headerCells = tableEl.querySelectorAll("tr:first-child th");
  const protocolHeaderText = String(headerCells?.[0]?.textContent || "").trim();
  const protocolFromHeader = protocolHeaderText
    ? protocolHeaderText.replace(/\s+field$/i, "").trim()
    : "";

  const fields = Array.from(tableEl.querySelectorAll("tr"))
    .slice(1)
    .map((rowEl) => {
      const cellEls = rowEl.querySelectorAll("td");
      const name = String(cellEls?.[0]?.textContent || "").trim();
      const value = String(cellEls?.[1]?.textContent || "").trim();
      if (!name && !value) return null;
      return {
        name: name || "Field",
        value: value || "(empty)",
      };
    })
    .filter(Boolean);

  if (!fields.length && !protocolFromHeader) return null;
  return {
    protocol: protocolFromHeader || null,
    fields,
  };
}

// Returns conv decoded output text.
function getConvDecodedOutputText(outputFormat = "plain") {
  const selectedDecoderEl = document.getElementById("data-tools-proto-select");
  const selectedDecoderValue = String(selectedDecoderEl?.value || "auto").trim();
  const selectedDecoderLabel =
    selectedDecoderValue === "auto"
      ? "Auto-detect"
      : selectedDecoderValue.toUpperCase();

  const decodedResult = getActiveDataToolsProtoResult() || getConvDecodedResultFromDomTable();
  if (decodedResult && Array.isArray(decodedResult.fields) && decodedResult.fields.length > 0) {
    if (outputFormat === "markdown") {
      const lines = [
        "## Protocol Decoder",
        "",
        `Protocol: ${decodedResult.protocol || selectedDecoderLabel}`,
        "",
        "| Field | Value |",
        "| --- | --- |",
      ];
      decodedResult.fields.forEach((field) => {
        const fieldName = String(field?.name || "").trim() || "Field";
        const fieldValue = String(field?.value || "").trim() || "(empty)";
        lines.push(
          `| ${escapeMarkdownTableCell(fieldName)} | ${escapeMarkdownTableCell(fieldValue)} |`,
        );
      });
      return lines.join("\n").trim();
    }

    const lines = [
      "Protocol Decoder",
      "Protocol",
      `${decodedResult.protocol || selectedDecoderLabel}`,
      "",
      "FieldValue",
    ];
    decodedResult.fields.forEach((field) => {
      const fieldName = String(field?.name || "").trim() || "Field";
      const fieldValue = String(field?.value || "").trim() || "(empty)";
      lines.push(`${fieldName}: ${fieldValue}`);
    });
    return lines.join("\n").trim();
  }

  if (outputFormat === "markdown") {
    return `## Protocol Decoder\n\nProtocol: ${selectedDecoderLabel}`;
  }
  return `Protocol Decoder\nProtocol\n${selectedDecoderLabel}`;
}

// Returns conv context export text.
function getConvContextExportText(exportType) {
  if (
    exportType === "hex" ||
    exportType === "binary" ||
    exportType === "decimal" ||
    exportType === "decimal-integer" ||
    exportType === "ascii" ||
    exportType === "base64"
  ) {
    return getConvFullOutputText(exportType);
  }
  switch (exportType) {
    case "input":
      return document.getElementById("data-tools-input")?.value?.trim() || "";
    case "hashes":
      return buildConvHashesNoteText();
    case "decodes":
      return getConvDecodedOutputText();
    default:
      return "";
  }
}

// Returns conv context export meta.
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

// Exports conv context text from context menu.
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

// Exports conv raw from context menu.
function exportConvRawFromContextMenu() {
  const payloadHex = getConvFullOutputText("hex");
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

// Builds conv hashes note text.
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

// Handles send text to notes from context menu.
function sendTextToNotesFromContextMenu(
  text,
  sourceLabel,
  editorVisible = true,
) {
  hideConvertContextMenu();
  const didAdd = addNote(text, NOTE_DEFAULT_COLOR, sourceLabel, editorVisible);
  if (!didAdd) return;
  showNotesWorkspace();
}

// Formats selected context data as markdown for notes using llm when available.
async function formatContextDataAsMarkdownForNotesWithLlm(text, contextPacket = null) {
  const normalizedText =
    typeof text === "string" ? text.trim() : String(text || "").trim();
  if (!normalizedText) return "";
  if (!isLlmRuntimeEnabled()) return normalizedText;

  const packetSummary = buildPacketContextSummary(
    contextPacket || activeContextPacket || getCurrentContextPacket(),
  );
  const prompt = [
    "You are a network analysis assistant named PacketSnitch.",
    `This request is sent through a hook that supports Markdown in the user query and in your response. ${buildMarkdownResponseInstruction()}`,
    "",
    "Task: Reformat the provided context data as clean, readable Markdown for notes display.",
    "The first line must be exactly: # Contextually Selected Data",
    "The second section must be an H2 where you guess the data type and label it, for example: ## Data Type: HTTP Header.",
    "Do not explain, summarize, infer, or add new facts.",
    "Preserve original values exactly. Keep all important fields and data points.",
    "If the data is already structured, use headings and bullet lists.",
    "If the data looks like raw/unstructured content, preserve it in a fenced code block.",
    "After the H1 and H2, include the formatted data body.",
    "Return only the formatted Markdown.",
    "",
    `Packet context: ${packetSummary}`,
    "",
    "Context data to format:",
    normalizedText,
  ].join("\n");

  const response = await callLargeLanguageModelWithRetry(prompt);
  const formatted = String(response?.response || "").trim();
  return formatted || normalizedText;
}

// Normalizes hex for notes.
function normalizeHexForNotes(value) {
  const normalized = String(value || "").replace(/[^0-9a-fA-F]/g, "");
  if (!normalized || normalized.length % 2 !== 0) return "";
  if (!/^[0-9a-fA-F]+$/.test(normalized)) return "";
  return normalized.toLowerCase();
}

// Formats hex as hexdump code block.
function formatHexAsHexdumpCodeBlock(hexText) {
  const normalized = normalizeHexForNotes(hexText);
  if (!normalized) return String(hexText || "").trim();

  const lines = [];
  for (let byteOffset = 0; byteOffset < normalized.length / 2; byteOffset += 16) {
    const rowHex = normalized.slice(byteOffset * 2, (byteOffset + 16) * 2);
    const rowBytes = [];
    for (let i = 0; i < rowHex.length; i += 2) {
      rowBytes.push(rowHex.slice(i, i + 2));
    }

    const left = rowBytes.slice(0, 8).join(" ");
    const right = rowBytes.slice(8).join(" ");
    const hexColumn = `${left.padEnd(23, " ")}  ${right.padEnd(23, " ")}`;
    const asciiColumn = rowBytes
      .map((byteText) => {
        const byteValue = Number.parseInt(byteText, 16);
        return byteValue >= 32 && byteValue <= 126
          ? String.fromCharCode(byteValue)
          : ".";
      })
      .join("");
    lines.push(
      `${byteOffset.toString(16).padStart(8, "0")}  ${hexColumn}  |${asciiColumn.padEnd(16, " ")}|`,
    );
  }

  return ["```text", ...lines, "```"].join("\n");
}

// Formats base64 as code block.
function formatBase64AsCodeBlock(base64Text) {
  const normalized = String(base64Text || "").replace(/\s+/g, "").trim();
  if (!normalized) return "";
  const lines = [];
  for (let index = 0; index < normalized.length; index += 76) {
    lines.push(normalized.slice(index, index + 76));
  }
  return ["```text", ...lines, "```"].join("\n");
}

// Formats ascii as code block for notes.
function formatAsciiAsCodeBlockForNotes(asciiText, hexText = "") {
  const normalizedHex = normalizeHexForNotes(hexText);
  if (normalizedHex) {
    let reconstructed = "";
    for (let index = 0; index < normalizedHex.length; index += 2) {
      const byteValue = Number.parseInt(normalizedHex.slice(index, index + 2), 16);
      if (byteValue === 0x0a) {
        reconstructed += "\n";
      } else if (byteValue === 0x0d) {
        const nextByteValue =
          index + 2 < normalizedHex.length
            ? Number.parseInt(normalizedHex.slice(index + 2, index + 4), 16)
            : NaN;
        if (nextByteValue !== 0x0a) {
          reconstructed += "\n";
        }
      } else if (byteValue >= 32 && byteValue <= 126) {
        reconstructed += String.fromCharCode(byteValue);
      } else {
        reconstructed += ".";
      }
    }
    return ["```text", reconstructed, "```"].join("\n");
  }

  const raw = String(asciiText || "");
  if (!raw) return "";
  // Fallback: preserve existing line breaks if no hex source is available.
  const normalizedNewlines = raw.replace(/\r\n?/g, "\n");
  return ["```text", normalizedNewlines, "```"].join("\n");
}

// Builds conv hashes markdown table.
function buildConvHashesMarkdownTable() {
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
  const rows = hashFields
    .map(([label, id]) => {
      const value = document.getElementById(id)?.value?.trim() || "";
      if (!value) return "";
      return `| ${escapeMarkdownTableCell(label)} | ${escapeMarkdownTableCell(value)} |`;
    })
    .filter(Boolean);
  if (!rows.length) return "";
  return ["| Hash | Value |", "| --- | --- |", ...rows].join("\n");
}

// Returns context packet number for notes.
function getContextPacketNumberForNotes(packet) {
  if (!packet || typeof packet !== "object") return "unknown";
  const packetInfo = packet["packet.info"] || {};
  const packetNumber =
    packetInfo["Packet Processed"] ??
    packetInfo["index"] ??
    packetInfo["Index"] ??
    null;
  return packetNumber == null || packetNumber === "" ? "unknown" : String(packetNumber);
}

// Returns context hosts for notes.
function getContextHostsForNotes(packet) {
  if (!packet || typeof packet !== "object") return "unknown";
  const packetInfo = packet["packet.info"] || {};
  const ipInfo = packetInfo["IP"] || {};
  const src =
    ipInfo["ip.src.addr"] ||
    ipInfo["Source IP"] ||
    packetInfo["ip.src.addr"] ||
    packetInfo["Source IP"] ||
    "unknown";
  const dst =
    ipInfo["ip.dst.addr"] ||
    ipInfo["Destination IP"] ||
    packetInfo["ip.dst.addr"] ||
    packetInfo["Destination IP"] ||
    "unknown";
  return `${String(src)} -> ${String(dst)}`;
}

// Returns context detected protocols for notes.
function getContextDetectedProtocolsForNotes(packet) {
  if (!packet || typeof packet !== "object") return "unknown";
  const packetInfo = packet["packet.info"] || {};
  const protocolCandidates = [];

  const pushCandidate = (value) => {
    if (value == null) return;
    if (Array.isArray(value)) {
      value.forEach((item) => pushCandidate(item));
      return;
    }
    const text = String(value).trim();
    if (!text) return;
    text
      .split(/[>,|/]+|\s*->\s*|\s*:\s*|\s{2,}/)
      .map((token) => token.trim())
      .filter(Boolean)
      .forEach((token) => protocolCandidates.push(token));
  };

  pushCandidate(packetInfo["packet.proto"] ?? packetInfo["Protocol"]);
  pushCandidate(packetInfo["packet.decoded_protocols"] ?? packetInfo["Decoded Protocols"]);
  pushCandidate(packetInfo["Link Control"]);
  const normalized = [...new Set(protocolCandidates.map((token) => token.toUpperCase()))];
  return normalized.length ? normalized.join(", ") : "unknown";
}

// Builds conv notes markdown header.
function buildConvNotesMarkdownHeader(exportType, packet = null) {
  const normalizedType = String(exportType || "").trim().toLowerCase();
  const titleByType = {
    input: "Packet Converted Input",
    hex: "Packet Hex Payload",
    ascii: "Packet ASCII Payload",
    base64: "Packet Base64 Payload",
    hashes: "Packet Hashes",
  };
  const title = titleByType[normalizedType] || "Packet Converted Output";
  const contextPacket = packet || activeContextPacket || getCurrentContextPacket();
  const packetNumber = getContextPacketNumberForNotes(contextPacket);
  const hosts = getContextHostsForNotes(contextPacket);
  const protocols = getContextDetectedProtocolsForNotes(contextPacket);
  return [
    `## ${title}`,
    `### Converted from packet number ${packetNumber}`,
    `### Hosts: ${hosts}`,
    `### Detected Protocols: ${protocols}`,
    "",
  ].join("\n");
}

// Handles send conv export to notes from context menu.
function sendConvExportToNotesFromContextMenu(exportType, sourceLabel) {
  const rawText = getConvContextExportText(exportType);
  if (!rawText) {
    hideConvertContextMenu();
    statusUpdate("Status: No Conv data available to send to Notes");
    return;
  }

  let noteText = rawText;
  if (exportType === "hex") {
    noteText = formatHexAsHexdumpCodeBlock(rawText);
  } else if (exportType === "base64") {
    noteText = formatBase64AsCodeBlock(rawText);
  } else if (exportType === "ascii") {
    noteText = formatAsciiAsCodeBlockForNotes(
      rawText,
      getConvContextExportText("hex"),
    );
  } else if (exportType === "input") {
    const currentInputFormat = String(
      document.getElementById("data-tools-format")?.value || "",
    )
      .trim()
      .toLowerCase();
    if (currentInputFormat === "hex") {
      noteText = formatHexAsHexdumpCodeBlock(rawText);
    } else if (currentInputFormat === "base64") {
      noteText = formatBase64AsCodeBlock(rawText);
    } else if (currentInputFormat === "ascii") {
      noteText = formatAsciiAsCodeBlockForNotes(
        rawText,
        getConvContextExportText("hex"),
      );
    }
  }

  const labeledNoteText = `${buildConvNotesMarkdownHeader(exportType)}${noteText}`;

  sendTextToNotesFromContextMenu(labeledNoteText, sourceLabel);
}

// Builds list visible data note text.
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

  const lines = ["# List Tab", "## Visible Row Data:"];
  values.forEach((value, index) => {
    const header = headers[index] || `Column ${index + 1}`;
    const normalizedHeader = header === "★" ? "Bookmarked" : header;
    const normalizedValue = header === "★"
      ? value === "★"
        ? "Yes"
        : "No"
      : value || "(empty)";
    const escapedValue = String(normalizedValue).replace(/`/g, "\\`");
    lines.push(`* ${normalizedHeader}: \`${escapedValue}\``);
  });
  return lines.join("\n");
}

// Initializes notes panel.
function initializeNotesPanel() {
  if (notesPanelInitialized) {
    return;
  }
  const addButtonEl = document.getElementById("notes-add-btn");
  const removeButtonEl = document.getElementById("notes-remove-btn");
  const saveButtonEl = document.getElementById("notes-save-btn");
  const newNoteInputEl = document.getElementById("notes-new-input");
  const newNoteColorEl = document.getElementById("notes-new-color");
  const notesSelectEl = document.getElementById("notes-select");
  const notesEditorEl = document.getElementById("notes-editor");
  const editToggleButtonEl = document.getElementById("notes-edit-toggle-btn");
  if (
    !addButtonEl ||
    !removeButtonEl ||
    !saveButtonEl ||
    !newNoteInputEl ||
    !newNoteColorEl ||
    !notesSelectEl ||
    !notesEditorEl ||
    !editToggleButtonEl
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
    notesEditorVisible = false;
    renderNotesList();
  });
  editToggleButtonEl.addEventListener("click", () => {
    const selectedNoteEntry = getSelectedNoteEntry();
    if (!selectedNoteEntry) return;
    setNotesEditorVisibility(!notesEditorVisible);
    if (notesEditorVisible) {
      notesEditorEl.focus();
    }
  });
  notesEditorEl.addEventListener("input", () => {
    const selectedNoteEntry = getSelectedNoteEntry();
    if (!selectedNoteEntry) return;
    selectedNoteEntry.text = notesEditorEl.value;
    renderSelectedNoteMarkdownPreview(selectedNoteEntry.text);
    const selectedOptionEl =
      notesSelectEl.options[notesSelectEl.selectedIndex] || null;
    if (selectedOptionEl) {
      const previewText = String(selectedNoteEntry.text || "")
        .replace(/\s+/g, " ")
        .trim();
      selectedOptionEl.textContent = `${notesSelectEl.selectedIndex + 1}. ${previewText || "(empty note)"}`;
    }
    // Text edits flow through to the Summary tab's Inferred/Verified
    // buckets, so re-render so the analyst sees the change live.
    refreshSummaryForNotes();
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

  // The "Verified" toggle switches a note between inferred (default)
  // and concrete. The Summary tab mirrors this flag by routing the
  // note text into either the "Inferred Data" or "Verified Notes"
  // heading, so any flip must refresh the rendered Summary.
  const notesConcreteToggleEl = document.getElementById(
    "notes-concrete-toggle",
  );
  if (notesConcreteToggleEl) {
    notesConcreteToggleEl.addEventListener("change", () => {
      const selectedNoteEntry = getSelectedNoteEntry();
      if (!selectedNoteEntry) {
        notesConcreteToggleEl.checked = false;
        return;
      }
      selectedNoteEntry.concrete = notesConcreteToggleEl.checked === true;
      refreshSummaryForNotes();
      statusUpdate(
        selectedNoteEntry.concrete
          ? "Status: Note marked as verified data"
          : "Status: Note marked as inferred data",
      );
    });
  }

  renderNotesList();
  setNotesEditorVisibility(false);
  notesPanelInitialized = true;
}

async function ensureNotesWorkspaceMounted() {
  const notesBoxEl = document.getElementById("notes_box");
  const rightsideNotesEl = document.getElementById("rightside-notes");
  if (!notesBoxEl || !rightsideNotesEl) {
    return false;
  }
  if (notesBoxEl.dataset.fragmentMounted === "true") {
    return true;
  }

  if (!notesWorkspaceFragmentPromise) {
    notesWorkspaceFragmentPromise = (async () => {
      if (typeof window.templateapi?.getUiFragment !== "function") {
        throw new Error("UI fragment loader is unavailable");
      }

      const [notesBoxResult, rightsideNotesResult] = await Promise.all([
        window.templateapi.getUiFragment("notes-box"),
        window.templateapi.getUiFragment("rightside-notes"),
      ]);

      if (!notesBoxResult?.success || typeof notesBoxResult.data !== "string") {
        throw new Error(notesBoxResult?.error || "Failed to load notes workspace");
      }
      if (
        !rightsideNotesResult?.success ||
        typeof rightsideNotesResult.data !== "string"
      ) {
        throw new Error(rightsideNotesResult?.error || "Failed to load notes sidebar");
      }

      notesBoxEl.innerHTML = notesBoxResult.data;
      rightsideNotesEl.innerHTML = rightsideNotesResult.data;
      notesBoxEl.dataset.fragmentMounted = "true";
      rightsideNotesEl.dataset.fragmentMounted = "true";
      initializeNotesPanel();
      renderNotesList();
      return true;
    })().catch((err) => {
      notesWorkspaceFragmentPromise = null;
      throw err;
    });
  }

  return notesWorkspaceFragmentPromise;
}

// Normalizes loaded session payload.
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

  // Backward compatibility: older templates/sessions used "Host" instead of "host".
  const normalizedCaptureData =
    captureData &&
      typeof captureData === "object" &&
      !captureData.host &&
      captureData.Host &&
      typeof captureData.Host === "object"
      ? { ...captureData, host: captureData.Host }
      : captureData;

  if (
    !normalizedCaptureData ||
    typeof normalizedCaptureData !== "object" ||
    !normalizedCaptureData["host"] ||
    typeof normalizedCaptureData["host"] !== "object"
  ) {
    return null;
  }

  return {
    captureData: normalizedCaptureData,
    sessionState:
      sessionState && typeof sessionState === "object" ? sessionState : null,
  };
}

async function finalizeLoadedCapture(sessionState) {
  getCachedElement("target_hosts").hidden = false;
  getCachedElement("summary-btn").style.display = "block";
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
  currentPacketToConvJson();
  renderNotesList();

  const selectBookmarkEl = document.getElementById("selectBookmark");
  while (selectBookmarkEl.options.length > 1) {
    selectBookmarkEl.remove(1);
  }

  packetStubByKey.clear();
  hydratedPacketCache.clear();
  clearStreamPacketHydrationCache();
  bumpPacketNavigationCacheVersion();
  if (keystorePanel && typeof keystorePanel.clearSessionScanCaches === "function") {
    keystorePanel.clearSessionScanCaches();
  }
  for (const host in capturedPackets["host"]) {
    hostsList.push(host);
    const newhost = document.createElement("option");
    newhost.textContent = host;
    newhost.value = host;
    targetHostsDropdown.appendChild(newhost);
    const hostPackets = Array.isArray(capturedPackets["host"][host])
      ? capturedPackets["host"][host]
      : [];
    await cachePacketStubsForHost(host, hostPackets);
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
  const loadedTotalPacketCount = totalPacketCount();
  if (loadedTotalPacketCount > 1) {
    writeLogEntry(`Total packet count=${loadedTotalPacketCount}`);
  }

  clearFilterQuery();
  syncFilterHighlight();
  isFileLoaded = true;

  // Always reset Conv to freshly-opened defaults before restoring or starting
  // a new session so data from a previous capture/session does not carry over.
  resetConvToFreshDefaults();

  if (sessionState) {
    await restoreSessionState(sessionState);
  } else {
    scheduleSessionKeychainAutoPopulate("file-load");
    statusUpdate("Status: File loaded successfully");
    writeLogEntry("New session initialized: created new session state");
    document.getElementById("total-packets").textContent =
      "Total Packets: " + loadedTotalPacketCount;
    showPacketList();
  }
  document.getElementById("loading-screen").style.display = "none";
  document.getElementById("loading-container").style.display = "none";
  syncPluginRuntimeData({ includeStats: true });
}

// Handles rebuild bookmark dropdown.
function rebuildBookmarkDropdown() {
  const selectBookmarkEl = document.getElementById("selectBookmark");
  while (selectBookmarkEl.options.length > 1) {
    selectBookmarkEl.remove(1);
  }
  bookmarkList.forEach((bookmarkKey) => {
    selectBookmarkEl.appendChild(new Option(bookmarkKey, bookmarkKey));
  });
}

// Returns session packet view mode.
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

// Builds session state snapshot.
function buildSessionStateSnapshot() {
  const listSearchEl = document.getElementById("list-search");
  const listGroupStreamsEl = document.getElementById("list-group-streams");
  return {
    schemaVersion: SESSION_FILE_SCHEMA_VERSION,
    packetsnitchVersion: PACKETSNITCH_VERSION,
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
    currentSummary: summary,
    compactedAnalysisSummaries: Array.isArray(compactedAnalysisSummaries)
      ? compactedAnalysisSummaries.map((entry) => ({
        signature: typeof entry?.signature === "string" ? entry.signature : "",
        summary: typeof entry?.summary === "string" ? entry.summary : "",
        lastUpdatedAt: Number.isFinite(entry?.lastUpdatedAt)
          ? entry.lastUpdatedAt
          : Date.now(),
      }))
      : [],
    analysisBlubHistory: [...analysisBlubHistory],
    keystoreMode: keystorePanel.getKeystoreMode(),
    notes: deepCloneSessionData(notesList, []),
    subnet: deepCloneSessionData(
      typeof subnetCalculatorPanel?.getSessionState === "function"
        ? subnetCalculatorPanel.getSessionState()
        : null,
      null,
    ),
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
      convCurrentInputBytesBase64:
        dataToolsOriginalInputBytes instanceof Uint8Array &&
          dataToolsOriginalInputBytes.length > 0
          ? uint8ArrayToBase64(dataToolsOriginalInputBytes)
          : null,
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

// Returns whether autosave current session.
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

// Handles start session autosave timer.
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
  if (!isFileLoaded || !capturedPackets || !capturedPackets["host"]) {
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

  // Lock/close the keystore before exiting so decrypted key material is cleared.
  try {
    if (keystorePanel && typeof keystorePanel.resetKeystoreState === "function") {
      keystorePanel.resetKeystoreState();
      statusUpdate("Status: Keychain locked for exit");
      writeLogEntry(`[${threadName}] Application exit requested; keychain locked`);
    }
  } catch (error) {
    logErrorEntry("keystore-lock-on-exit", error);
  }

  window.quitapi.quitApp();
}

// Fallback: ensure the keystore is cleared whenever the renderer window is torn
// down (OS close, Cmd+Q, page reload, etc.), even if the close button path above
// is not the trigger.
window.addEventListener("beforeunload", () => {
  try {
    if (keystorePanel && typeof keystorePanel.resetKeystoreState === "function") {
      keystorePanel.resetKeystoreState();
    }
  } catch (error) {
    logErrorEntry("keystore-lock-on-beforeunload", error);
  }
});

// Handles restore session state.
async function restoreSessionState(sessionState) {
  if (!sessionState || typeof sessionState !== "object") return;

  if (typeof subnetCalculatorPanel?.restoreSessionState === "function") {
    subnetCalculatorPanel.restoreSessionState(
      sessionState.subnet || sessionState.subnetState || null,
    );
  }

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
    ).map((bookmark) => normalizePacketKey(bookmark)).filter(Boolean)
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
  if (sessionState.currentSummary && typeof sessionState.currentSummary === "string") {
    summary = sessionState.currentSummary;
    summaryFromSavedSession = true;
  }
  if (Array.isArray(sessionState.analysisBlubHistory)) {
    analysisBlubHistory.splice(
      0,
      analysisBlubHistory.length,
      ...sessionState.analysisBlubHistory.filter(
        (item) => item && typeof item === "string",
      ),
    );
  }

  // Load context-scoped compacted analysis summaries. Older sessions only saved
  // a single string; convert those to a single-entry list for compatibility.
  if (Array.isArray(sessionState.compactedAnalysisSummaries)) {
    compactedAnalysisSummaries = sessionState.compactedAnalysisSummaries
      .filter((entry) => entry && typeof entry === "object")
      .map((entry) => ({
        signature: typeof entry.signature === "string" ? entry.signature : "",
        summary: typeof entry.summary === "string" ? entry.summary : "",
        lastUpdatedAt: Number.isFinite(entry.lastUpdatedAt)
          ? entry.lastUpdatedAt
          : Date.now(),
      }));
  } else if (
    sessionState.compactedAnalysisSummary &&
    typeof sessionState.compactedAnalysisSummary === "string"
  ) {
    compactedAnalysisSummaries = [
      {
        signature: "",
        summary: sessionState.compactedAnalysisSummary,
        lastUpdatedAt: Date.now(),
      },
    ];
  } else {
    compactedAnalysisSummaries.length = 0;
  }
  renderCombinedAnalysisSummary();

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
        // Preserve the verified/concrete flag through session save+load.
        // Older sessions without the field default to inferred (false).
        concrete: note.concrete === true,
      }))
    : [];
  notesList = loadedNotes;
  selectedNoteId = notesList.length > 0 ? notesList[0].id : null;
  notesEditorVisible = false;
  renderNotesList();
  // Notes from the saved session feed the Summary tab as inferred/
  // verified data, so re-render after loading them so the rendered
  // report reflects the restored notes.
  renderCombinedAnalysisSummary();

  const selectedHost = String(sessionState.selectedHost || "").trim();
  if (
    selectedHost &&
    (
      isAllHostsSelection(selectedHost) ||
      isBookmarkedSelection(selectedHost) ||
      capturedPackets?.["host"]?.[selectedHost]
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
      ? normalizePacketKey(sessionState.currentPacketKey)
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
  } else if (savedMainTab === MAIN_TAB_SETTINGS) {
    showSettingsWorkspace();
  } else if (savedMainTab === MAIN_TAB_DATA_TOOLS) {
    showDataTools(savedConvTab);
    if (savedConvTab === CONV_SUBNET_SUBTAB) {
      subnetCalculatorPanel.maybeKickoffNmapOnTabOpen();
    } else if (savedConvTab === CONV_THREAT_INTEL_SUBTAB) {
      subnetCalculatorPanel.maybeKickoffThreatIntelOnTabOpen();
    }
  } else if (savedMainTab === MAIN_TAB_CRYPT) {
    showCryptWorkspace(savedCryptTab);
  } else if (savedMainTab === MAIN_TAB_KEYSTORE && keystorePanel.isUnlocked()) {
    keystorePanel.showKeystoreWorkspace();
  }

  if (savedMainTab !== MAIN_TAB_DATA_TOOLS) {
    setConvSubtab(savedConvTab);
  }

  resetConvToFreshDefaults();

  if (savedMainTab !== MAIN_TAB_CRYPT) {
    setCryptSubtab(savedCryptTab);
  }
  else {
    isFileLoaded = true;
  }
  writeLogEntry("Session state restored from JSON");
  statusUpdate("Status: Session restored");
  syncPluginRuntimeData({ includeStats: true });
}

async function processCapturePath(capturePath, options = {}) {
  const {
    suppressLoadingOverlay = false,
    incrementalUpdate = false,
    finalUpdate = false,
  } = options;
  if (incrementalUpdate) {
    hideLoadingOverlay();
  }
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
    await applyIncrementalCaptureSnapshot(
      loadResult.captureData || { host: {}, "final.summary": "" },
      { forceFullReindex: finalUpdate },
    );
    return;
  }

  capturedPackets = loadResult.captureData || { host: {}, "final.summary": "" };
  isCaptureStoreBackedCapture = true;
  jsonCapture = "[lazy-capture-store]";
  fileLoaded(true);

  const loadedSessionState =
    loadResult.sessionState && typeof loadResult.sessionState === "object"
      ? loadResult.sessionState
      : null;

  await finalizeLoadedCapture(loadedSessionState);
}

async function applyIncrementalCaptureSnapshot(nextCaptureData, options = {}) {
  const { forceFullReindex = false } = options;
  isCaptureStoreBackedCapture = true;
  const previousCapturedPackets =
    capturedPackets && typeof capturedPackets === "object"
      ? capturedPackets
      : { host: {}, "final.summary": "" };
  capturedPackets = nextCaptureData || { host: {}, "final.summary": "" };
  bumpPacketNavigationCacheVersion();
  jsonCapture = "[lazy-capture-store]";

  const targetHostsDropdown = getCachedElement("target_hosts");
  const previousHost = targetHostsDropdown?.value || hostFilterEl.value || "";
  const hostMap =
    capturedPackets && typeof capturedPackets["host"] === "object"
      ? capturedPackets["host"]
      : {};
  const previousHostMap =
    previousCapturedPackets && typeof previousCapturedPackets["host"] === "object"
      ? previousCapturedPackets["host"]
      : {};
  const previousRealHosts = hostsList.filter(
    (host) => host !== DUMMY_ALL_HOST && host !== DUMMY_BOOKMARKED_HOST,
  );
  const stagedPacketPlan = await stageIncrementalCapturePacketsInWorker(
    hostMap,
    previousHostMap,
    previousRealHosts,
  );
  const nextHosts = stagedPacketPlan?.nextHosts || Object.keys(hostMap);
  const hostSetChanged =
    typeof stagedPacketPlan?.hostSetChanged === "boolean"
      ? stagedPacketPlan.hostSetChanged
      : (() => {
        const previousHostSet = new Set(previousRealHosts);
        return (
          nextHosts.length !== previousRealHosts.length
          || nextHosts.some((host) => !previousHostSet.has(host))
        );
      })();

  if (hostSetChanged) {
    hostsList = [DUMMY_ALL_HOST, DUMMY_BOOKMARKED_HOST, ...nextHosts];
    while (targetHostsDropdown.options.length > 0) {
      targetHostsDropdown.remove(0);
    }
    appendAllHostsOption(targetHostsDropdown);
    appendBookmarkedOption(targetHostsDropdown);
    nextHosts.forEach((host) => {
      const optionEl = document.createElement("option");
      optionEl.textContent = host;
      optionEl.value = host;
      targetHostsDropdown.appendChild(optionEl);
    });
  } else {
    hostsList = [DUMMY_ALL_HOST, DUMMY_BOOKMARKED_HOST, ...nextHosts];
  }

  if (forceFullReindex) {
    packetStubByKey.clear();
    hydratedPacketCache.clear();
    clearStreamPacketHydrationCache();

    for (const host of nextHosts) {
      const hostPackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
      await cachePacketStubsForHost(host, hostPackets, { startIndex: 0 });
    }
  } else if (stagedPacketPlan && stagedPacketPlan.newPacketRefs.length > 0) {
    let indexedCount = 0;
    const stagedYieldInterval = getIngestionIndexYieldInterval();
    for (const packetRef of stagedPacketPlan.newPacketRefs) {
      if (!packetRef || typeof packetRef !== "object") continue;
      const host = typeof packetRef.host === "string" ? packetRef.host : "";
      const packetIndex = Number(packetRef.packetIndex);
      const packetKey = typeof packetRef.packetKey === "string" ? packetRef.packetKey : "";
      if (!host || !Number.isFinite(packetIndex) || packetIndex < 0 || !packetKey) {
        continue;
      }
      const hostPackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
      const packet = hostPackets[packetIndex];
      if (!packet || typeof packet !== "object") {
        continue;
      }
      packet.__packetKey = packetKey;
      cachePacketStub(packetKey, packet);
      indexedCount += 1;
      if (stagedYieldInterval > 0 && indexedCount % stagedYieldInterval === 0) {
        await yieldToRenderer();
      }
    }
  } else {
    for (const host of nextHosts) {
      const hostPackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
      const previousHostPackets = Array.isArray(previousHostMap[host])
        ? previousHostMap[host]
        : [];
      const startIndex = Math.min(previousHostPackets.length, hostPackets.length);

      await cachePacketStubsForHost(host, hostPackets, { startIndex });
    }
  }

  const selectedHost =
    previousHost &&
      (previousHost === DUMMY_ALL_HOST
        || previousHost === DUMMY_BOOKMARKED_HOST
        || Object.prototype.hasOwnProperty.call(hostMap, previousHost))
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
}

async function processCaptureData(captureData, options = {}) {
  const {
    suppressLoadingOverlay = false,
    incrementalUpdate = false,
    finalUpdate = false,
  } = options;
  if (incrementalUpdate) {
    hideLoadingOverlay();
  }
  if (!suppressLoadingOverlay) {
    document.getElementById("loading-screen").style.display = "flex";
    document.getElementById("loading-container").style.display = "block";
    document.getElementById("loading-text").textContent = "Indexing capture...";
  }

  if (!window.captureapi) {
    doError("Capture API is unavailable in this build");
    return;
  }

  const canLoadDataDirectly =
    typeof window.captureapi.loadData === "function"
    && captureData
    && typeof captureData === "object";
  const loadResult = canLoadDataDirectly
    ? await window.captureapi.loadData({ captureData })
    : await window.captureapi.loadJson(
      await serializeCaptureDataForBackendLoad(captureData),
    );
  if (!loadResult?.success) {
    doError(`Failed to load capture snapshot: ${loadResult?.error || "unknown error"}`);
    fileLoaded(false);
    return;
  }

  if (incrementalUpdate && isFileLoaded) {
    await applyIncrementalCaptureSnapshot(
      loadResult.captureData || { host: {}, "final.summary": "" },
      { forceFullReindex: finalUpdate },
    );
    return;
  }

  capturedPackets = loadResult.captureData || { host: {}, "final.summary": "" };
  isCaptureStoreBackedCapture = true;
  jsonCapture = "[lazy-capture-store]";
  fileLoaded(true);

  const loadedSessionState =
    loadResult.sessionState && typeof loadResult.sessionState === "object"
      ? loadResult.sessionState
      : null;

  await finalizeLoadedCapture(loadedSessionState);
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
    if (isValidJson(event.target.result) == false) {
      console.log("Invalid JSON file");
      doError("Invalid JSON file, please upload a valid JSON capture!");
      fileLoaded(false);
      return;
    }
    fileLoaded(true);
    isCaptureStoreBackedCapture = false;
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
          jsonCapture = JSON.stringify(capturedPackets, null, getConvJsonIndentSpaces());
          await finalizeLoadedCapture(loadedSessionState);
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
      jsonCapture = JSON.stringify(capturedPackets, null, getConvJsonIndentSpaces());
      await finalizeLoadedCapture(loadedSessionState);
    }
  };
  reader.onerror = (error) => {
    status.textContent = "Status: Error reading file: " + error;
    logErrorEntry("file-read", error);
    doError("Error reading file!");
  };
  reader.readAsText(file);
}

/**
 * Updates the status bar with a message, then resets after configured delay.
 */
function statusUpdate(message) {
  status.textContent = message;
  if (statusResetTimeoutId) {
    clearTimeout(statusResetTimeoutId);
  }
  statusResetTimeoutId = setTimeout(() => {
    status.textContent = "PacketSnitch " + psVer + ": Ready";
    statusResetTimeoutId = null;
  }, getStatusResetDelayMs());
}

// Builds host target filter query.
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

// Parses data tools input.
function parseDataToolsInput(format, rawInput) {
  if (!rawInput || rawInput.trim() === "") {
    throw new Error("Enter input data first.");
  }

  if (format === "hex") {
    const byteTokens = [];
    const lines = rawInput.split(/\r?\n/);
    lines.forEach((line) => {
      let work = line;
      const pipeIdx = work.indexOf("|");
      if (pipeIdx !== -1) {
        work = work.slice(0, pipeIdx);
      }

      work = work.replace(/^\s*[0-9a-fA-F]{1,8}:?\s{2,}/, "");

      const tokens = work.match(/(?:0x)?[0-9a-fA-F]{2}/g);
      if (tokens) {
        tokens.forEach((token) => {
          byteTokens.push(token.replace(/^0x/i, ""));
        });
      }
    });

    if (!byteTokens.length) throw new Error("No hex bytes were found.");
    const bytes = new Uint8Array(byteTokens.length);
    for (let i = 0; i < byteTokens.length; i += 1) {
      bytes[i] = parseInt(byteTokens[i], 16);
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

// Handles escape data tools html.
function escapeDataToolsHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Handles classify data tools hex byte.
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

// Builds input selection map.
function buildInputSelectionMap(rawInput, format, bytes) {
  const text = String(rawInput || "");
  const safeBytes = bytes instanceof Uint8Array ? bytes : new Uint8Array();
  const charToByte = new Array(text.length).fill(null);
  const byteRanges = Array.from({ length: safeBytes.length }, () => ({
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

// Builds rendered selection map.
function buildRenderedSelectionMap(values, { valuesPerLine = 0 } = {}) {
  const safeValues = Array.isArray(values) ? values : [];
  const parts = [];
  safeValues.forEach((value, byteIndex) => {
    if (byteIndex > 0) {
      parts.push(
        valuesPerLine > 0 && byteIndex % valuesPerLine === 0 ? "\n" : " ",
      );
    }
    parts.push(value);
  });
  const text = parts.join("");
  const charToByte = [];
  const byteRanges = Array.from({ length: safeValues.length }, () => ({
    start: null,
    end: null,
  }));
  let cursor = 0;
  safeValues.forEach((value, byteIndex) => {
    if (byteIndex > 0) {
      const separator =
        valuesPerLine > 0 && byteIndex % valuesPerLine === 0 ? "\n" : " ";
      for (let s = 0; s < separator.length; s += 1) {
        charToByte[cursor] = null;
        cursor += 1;
      }
    }
    for (let i = 0; i < value.length; i++) {
      charToByte[cursor + i] = byteIndex;
    }
    byteRanges[byteIndex] = { start: cursor, end: cursor + value.length };
    cursor += value.length;
  });
  return { text, charToByte, byteRanges };
}

// Builds base64 selection map.
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

// Returns data tools byte range for selection.
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

// Returns data tools selection for byte range.
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

// Builds colorized hex html.
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

// Builds the Conv input offset gutter for hex mode.
function buildDataToolsInputOffsetText(rawText, format) {
  if (format !== "hex") return "";
  const text = String(rawText || "");
  if (!text) return "";
  const lines = text.split(/\r?\n/);
  let offset = 0;
  return lines
    .map((line) => {
      const work = line.split("|")[0].replace(/^\s*[0-9a-fA-F]{1,8}:?\s{2,}/, "");
      const tokens = work.match(/(?:0x)?[0-9a-fA-F]{2}/g) || [];
      const label = offset.toString(16).padStart(8, "0");
      offset += tokens.length;
      return label;
    })
    .join("\n");
}

// Handles update data tools hex highlights.
function updateDataToolsHexHighlights() {
  const inputOffsetsEl = document.getElementById("data-tools-input-offsets");
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
    !inputOffsetsEl ||
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
    inputOffsetsEl.value = buildDataToolsInputOffsetText(
      inputEl.value,
      formatEl.value,
    );
    inputHighlightEl.innerHTML = buildColorizedHexHtml(
      inputEl.value,
      inputMap,
      bytes,
      dataToolsSelectionState.selectedByteRange,
    );
  } else {
    inputOffsetsEl.value = "";
    inputHighlightEl.innerHTML = escapeDataToolsHtml(inputEl.value);
  }
  outputHighlightEl.innerHTML = buildColorizedHexHtml(
    outputEl.value,
    outputMap,
    bytes,
    dataToolsSelectionState.selectedByteRange,
  );
}

// Syncs data tools highlight scroll.
function syncDataToolsHighlightScroll(textareaId, layerId) {
  const textarea = document.getElementById(textareaId);
  const layer = document.getElementById(layerId);
  if (!textarea || !layer) return;
  layer.scrollLeft = textarea.scrollLeft;
  layer.scrollTop = textarea.scrollTop;
  if (textareaId === "data-tools-input") {
    const offsetsEl = document.getElementById("data-tools-input-offsets");
    if (offsetsEl) {
      offsetsEl.scrollTop = textarea.scrollTop;
    }
  }
}

// Clears data tools selection state.
function clearDataToolsSelectionState() {
  dataToolsSelectionState.bytes = new Uint8Array();
  dataToolsSelectionState.maps = {};
  dataToolsSelectionState.selectedByteRange = null;
  dataToolsSelectionState.lastSelectionSignature = "";
  clearDataToolsSummary();
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

// Handles update data tools selection maps.
function updateDataToolsSelectionMaps(format, rawInput, bytes, outputs) {
  dataToolsSelectionState.bytes = bytes;
  dataToolsSelectionState.lastSelectionSignature = "";
  dataToolsSelectionState.maps = {
    "data-tools-input": buildInputSelectionMap(rawInput, format, bytes),
    "data-tools-hex-output": buildRenderedSelectionMap(outputs.hexValues, {
      valuesPerLine: 16,
    }),
    "data-tools-binary-output": buildRenderedSelectionMap(outputs.binaryValues),
    "data-tools-decimal-output": buildRenderedSelectionMap(
      outputs.decimalValues,
    ),
    "data-tools-ascii-output": {
      text: typeof outputs.asciiText === "string" ? outputs.asciiText : "",
      charToByte: Array.from(
        { length: typeof outputs.asciiText === "string" ? outputs.asciiText.length : 0 },
        (_, idx) => idx,
      ),
      byteRanges: Array.from({ length: bytes.length }, (_, idx) => ({
        start: idx,
        end: idx + 1,
      })),
    },
    "data-tools-base64-output": buildBase64SelectionMap(
      typeof outputs.base64Text === "string" ? outputs.base64Text : "",
      bytes,
    ),
  };
}

// Syncs data tools selection from field.
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
  updateDataToolsCursorReadout(sourceFieldId);
}

// Updates the cursor readout under the converted outputs based on the active
// field's current selection. Reports byte offset (hex), line/column, and the
// absolute character position, using the existing selection map to translate
// character index into byte offset.
function setDataToolsCursorValue(el, rawValue, displayValue) {
  if (!el) return;
  el.dataset.rawValue = rawValue ?? "";
  const chipValue = el.querySelector(".data-tools-cursor-chip-value");
  if (chipValue) {
    chipValue.textContent = displayValue;
  } else {
    el.textContent = displayValue;
  }
}

function updateDataToolsCursorReadout(fieldId) {
  const offsetEl = document.getElementById("data-tools-output-cursor-offset");
  const lineEl = document.getElementById("data-tools-output-cursor-line");
  const colEl = document.getElementById("data-tools-output-cursor-column");
  const posEl = document.getElementById("data-tools-output-cursor-position");
  const selLenEl = document.getElementById("data-tools-output-cursor-sel-len");
  const endRemainingEl = document.getElementById("data-tools-output-cursor-end-remaining");
  if (!offsetEl || !lineEl || !colEl || !posEl || !selLenEl || !endRemainingEl) return;
  const el = document.getElementById(fieldId);
  const map = dataToolsSelectionState.maps[fieldId];
  const streamLen = dataToolsSelectionState.bytes?.length ?? 0;
  if (!el || !map) {
    setDataToolsCursorValue(offsetEl, 0, "0x00000000");
    setDataToolsCursorValue(lineEl, 1, "1");
    setDataToolsCursorValue(colEl, 1, "1");
    setDataToolsCursorValue(posEl, 0, "0");
    setDataToolsCursorValue(selLenEl, 0, "0");
    setDataToolsCursorValue(endRemainingEl, streamLen, String(streamLen));
    return;
  }

  const charPos = Math.max(0, Math.min(el.selectionStart ?? 0, map.text?.length ?? el.value.length));
  const byteIndex = map.charToByte?.[charPos] ?? null;
  const byteOffset = byteIndex != null ? byteIndex : null;
  const textBefore = String(map.text || el.value || "").slice(0, charPos);
  const lineNumber = (textBefore.match(/\r\n|\n/g)?.length ?? 0) + 1;
  const lastBreak = Math.max(textBefore.lastIndexOf("\n"), textBefore.lastIndexOf("\r"));
  const columnNumber = charPos - Math.max(0, lastBreak);

  let selectedByteCount = 0;
  let selectionEndByte = byteOffset;
  if (el.selectionStart !== el.selectionEnd) {
    const range = getDataToolsByteRangeForSelection(map, el.selectionStart, el.selectionEnd);
    if (range) {
      selectedByteCount = Math.max(0, range.end - range.start);
      selectionEndByte = range.end;
    }
  }
  const remainingFromEnd = selectionEndByte != null
    ? Math.max(0, streamLen - selectionEndByte)
    : Math.max(0, streamLen - (byteOffset ?? 0));

  setDataToolsCursorValue(offsetEl, byteOffset ?? "", byteOffset != null
    ? `0x${byteOffset.toString(16).padStart(8, "0")}`
    : "—");
  setDataToolsCursorValue(lineEl, lineNumber, `${lineNumber}`);
  setDataToolsCursorValue(colEl, columnNumber + 1, `${columnNumber + 1}`);
  setDataToolsCursorValue(posEl, charPos, `${charPos}`);
  setDataToolsCursorValue(selLenEl, selectedByteCount, `${selectedByteCount}`);
  setDataToolsCursorValue(endRemainingEl, remainingFromEnd, `${remainingFromEnd}`);
}

// Parses a position or length input that may be decimal or prefixed with 0x.
function parseDataToolsManualCarveNumber(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value) return null;
  if (/^0x[\da-fA-F]+$/i.test(value)) {
    return parseInt(value, 16);
  }
  if (/^-?\d+$/.test(value)) {
    return parseInt(value, 10);
  }
  return null;
}

// Performs a manual carve from the current conversion bytes using the position
// and length inputs. The result is surfaced in the Manual Carve row and also
// registered in the Stats carvable files registry so it can be reloaded later.
function performDataToolsManualCarve() {
  const positionEl = document.getElementById("data-tools-manual-carve-position");
  const lengthEl = document.getElementById("data-tools-manual-carve-length");
  const position = parseDataToolsManualCarveNumber(positionEl?.value);
  const length = parseDataToolsManualCarveNumber(lengthEl?.value);

  const bytes = dataToolsLastConversionBytes;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    statusUpdate("Status: No converted bytes available to carve");
    return;
  }
  if (!Number.isInteger(position) || position < 0) {
    statusUpdate("Status: Manual carve position must be a non-negative integer");
    return;
  }
  if (!Number.isInteger(length) || length <= 0) {
    statusUpdate("Status: Manual carve length must be a positive integer");
    return;
  }
  if (position >= bytes.length) {
    statusUpdate("Status: Manual carve position is past the end of the data");
    return;
  }
  const start = position;
  const end = Math.min(position + length, bytes.length);
  const carvedBytes = bytes.slice(start, end);
  const actualLength = carvedBytes.length;

  const fileName = `manual-carve-0x${start.toString(16)}-${actualLength}-bytes.bin`;
  dataToolsManualCarveResult = {
    fileName,
    bytes: carvedBytes,
    start,
    length: actualLength,
  };

  registerExtractionResultForStats(fileName, carvedBytes);
  statusUpdate(
    `Status: Manual carved ${actualLength} bytes at offset 0x${start.toString(16)}`,
  );
  writeLogEntry(
    `Manual carve performed offset=0x${start.toString(16)} requested_length=${length} actual_length=${actualLength}`,
  );
}

// Handles clicks on the cursor readout chips/arrows to populate or nudge the
// Manual Carve position/length inputs.
function handleDataToolsCursorCarveClick(event) {
  const arrow = event.target.closest(".data-tools-cursor-arrow");
  const chip = event.target.closest(".data-tools-cursor-chip");
  const valueEl = event.target.closest(".data-tools-cursor-value");
  if ((!arrow && !chip) || !valueEl) return;

  const target = valueEl.dataset.carveTarget;
  if (!target || !["position", "length"].includes(target)) return;
  const inputId = target === "position"
    ? "data-tools-manual-carve-position"
    : "data-tools-manual-carve-length";
  const inputEl = document.getElementById(inputId);
  if (!inputEl) return;

  if (arrow) {
    const delta = Number(arrow.dataset.carveDelta || 0);
    const current = parseDataToolsManualCarveNumber(inputEl.value) ?? 0;
    inputEl.value = String(Math.max(0, current + delta));
  } else {
    const parsed = parseDataToolsManualCarveNumber(valueEl.dataset.rawValue);
    if (parsed == null) return;
    inputEl.value = String(parsed);
  }
}

// Loads the most recent manual carve result into the Conv input.
function loadDataToolsManualCarveIntoConv() {
  const result = dataToolsManualCarveResult;
  if (!result || !(result.bytes instanceof Uint8Array) || result.bytes.length === 0) {
    statusUpdate("Status: No manual carve result to load");
    return;
  }
  loadExtractionResultIntoConv(result.bytes, result.fileName);
}

// Handles bytes to base64.
function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

// Handles bytes to printable ascii.
function bytesToPrintableAscii(bytes) {
  return [...bytes]
    .map((byte) =>
      byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".",
    )
    .join("");
}

// Handles bytes to big int decimal.
function bytesToBigIntDecimal(bytes) {
  let total = 0n;
  bytes.forEach((byte) => {
    total = (total << 8n) + BigInt(byte);
  });
  return total.toString(10);
}

// Returns compression algorithms by priority.
function getCompressionAlgorithmsByPriority(preferredAlgorithm = "") {
  const normalizedPreferred = String(preferredAlgorithm || "").toLowerCase();
  const allAlgorithms = ["gzip", "deflate", "brotli"];
  if (!normalizedPreferred || !allAlgorithms.includes(normalizedPreferred)) {
    return allAlgorithms;
  }
  return [normalizedPreferred, ...allAlgorithms.filter((a) => a !== normalizedPreferred)];
}

// Handles infer compression from bytes.
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

  //const packetPayloadHex = contextPacket?.["packet.info"]?.["Raw data"]?.["Payload"]["Hex Encoded"];
  const encoding = String(httpData?.["Content-Encoding"] || "").toLowerCase();
  if (encoding.includes("br") || encoding.includes("brotli")) return "brotli";
  if (encoding.includes("gzip") || encoding.includes("gz")) return "gzip";
  if (encoding.includes("deflate") || encoding.includes("zlib")) return "deflate";

  const extraInfoData = contextPacket?.["extra.info"];
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

// Returns active conv decompression candidate.
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

// Handles calculate shannon entropy.
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

// Handles infer mime type.
function inferMimeType(bytes) {
  if (!bytes || !bytes.length) return "application/octet-stream";

  const startsWith = (signature) =>
    signature.every((value, index) => bytes[index] === value);
  if (startsWith([0x89, 0x50, 0x4e, 0x47])) return "image/png";
  if (startsWith([0xff, 0xd8, 0xff])) return "image/jpeg";
  if (startsWith([0x47, 0x49, 0x46, 0x38])) return "image/gif";
  if (
    bytes.length >= 12 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return "image/webp";
  }
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

// Returns entropy label.
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

// Handles decode bytes for text inspection.
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



// Returns whether likely readable text.
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

// Handles looks like html source.
function looksLikeHtmlSource(text) {
  return (
    /<!doctype\s+html/i.test(text) ||
    /<html\b/i.test(text) ||
    /<(?:head|body|title|script|style|div|span|p|a|form|table)\b/i.test(text)
  );
}

// Handles looks like xml source.
function looksLikeXmlSource(text) {
  return (
    /^<\?xml\b/i.test(text) ||
    (/^<[\w:-]+(?:\s+[^>]*)?>/.test(text) && /<\/[\w:-]+>\s*$/.test(text))
  );
}

// Handles looks like css source.
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

// Handles looks like java script source.
function looksLikeJavaScriptSource(text) {
  return (
    /\b(?:const|let|var|function|export|import|async|await|document|window|console)\b/.test(
      text,
    ) || /=>/.test(text)
  );
}

// Handles looks like python source.
function looksLikePythonSource(text) {
  return (
    /^\s*#!\/(?:usr\/bin\/env\s+)?python\d*\b/m.test(text) ||
    /\bdef\s+\w+\s*\(/.test(text) ||
    /\bclass\s+\w+\s*[:(]/.test(text) ||
    /\bimport\s+\w+/.test(text)
  );
}

// Handles looks like shell source.
function looksLikeShellSource(text) {
  return (
    /^\s*#!\/(?:usr\/bin\/env\s+)?(?:bash|sh|zsh|fish)\b/m.test(text) ||
    (/\b(?:echo|export|grep|awk|sed|fi|done|then)\b/.test(text) &&
      /\$\w+/.test(text))
  );
}

// Handles looks like power shell source.
function looksLikePowerShellSource(text) {
  return /\b(?:Get-|Set-|Write-Host|New-Object|Param\s*\(|\$env:)\b/i.test(
    text,
  );
}

// Handles looks like sql source.
function looksLikeSqlSource(text) {
  return /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE)\b/i.test(
    text,
  );
}

// Handles looks like php source.
function looksLikePhpSource(text) {
  return /<\?php\b/i.test(text);
}

// Handles looks like go source.
function looksLikeGoSource(text) {
  return /\bpackage\s+\w+\b/.test(text) && /\bfunc\s+\w+\s*\(/.test(text);
}

// Handles looks like rust source.
function looksLikeRustSource(text) {
  return (
    /\bfn\s+\w+\s*\(/.test(text) && /\b(?:let\s+mut|impl|use\s+\w)/.test(text)
  );
}

// Handles looks like java or csharp source.
function looksLikeJavaOrCSharpSource(text) {
  return (
    /\b(?:public|private|protected)\s+(?:class|static|void)\b/.test(text) ||
    /\bSystem\.out\.println\b/.test(text) ||
    /\busing\s+System\b/.test(text)
  );
}

// Handles looks like yaml source.
function looksLikeYamlSource(text) {
  return (
    /^\s*[A-Za-z0-9_.-]+\s*:\s+\S+/m.test(text) &&
    !/[{};]/.test(text) &&
    !/<[A-Za-z]/.test(text)
  );
}

// Handles looks like any source code.
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

// Handles add structured text type guesses.
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

// Handles guess readable text language.
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

// Handles add data type guess candidate.
function addDataTypeGuessCandidate(candidateScores, label, score) {
  const currentScore = candidateScores.get(label) || 0;
  if (score > currentScore) {
    candidateScores.set(label, score);
  }
}

// Detects data type guess from token.
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

// Handles scan ascii text for data type guesses.
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

// Handles derive data type guesses.
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

// Renders data type guesses.
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

// Renders data tools language guess.
function renderDataToolsLanguageGuess(languageGuess) {
  const languageEl = document.getElementById("data-tools-language-guess");
  if (!languageEl) return;
  languageEl.textContent = languageGuess
    ? `Text Language: ${languageGuess.label} (${languageGuess.confidence})`
    : "Text Language: Unknown";
}

// Sets data tools file name guess.
function setDataToolsFileNameGuess(fileNameGuess) {
  const normalizedGuess = String(fileNameGuess || "").trim();
  const fileNameGuessEl = document.getElementById("data-tools-file-name");
  if (!fileNameGuessEl) return;
  fileNameGuessEl.textContent = normalizedGuess
    ? `Filename Guess: ${normalizedGuess}`
    : "Filename Guess: Unknown";
}

// Returns placeholder text shown when a converted output pane is collapsed.
function getDataToolsOutputPlaceholder(outputId, shownBytes, totalBytes) {
  const label = DATA_TOOLS_OUTPUT_FORMAT_DETAILS[outputIdToFormat(outputId)]?.label || "output";
  const extra = totalBytes > shownBytes ? ` (${totalBytes.toLocaleString()} bytes total)` : "";
  return `Click to expand ${label}${extra}.`;
}

// Maps an output textarea id back to its format key.
function outputIdToFormat(outputId) {
  for (const [format, details] of Object.entries(DATA_TOOLS_OUTPUT_FORMAT_DETAILS)) {
    if (details.outputSelector === `#${outputId}`) return format;
  }
  return null;
}

// Resets data tools outputs.
function resetDataToolsOutputs() {
  dataToolsLastConversionBytes = new Uint8Array();
  dataToolsOriginalInputBytes = null;
  dataToolsInputEditedFlag = false;
  dataToolsLastRenderedOutputBytes = 0;
  dataToolsLastConversionDisplay = {
    decimalInteger: "",
  };
  dataToolsManualCarveResult = null;
  dataToolsRenderedOutputPanes.clear();
  clearExtractionResultsForStats();
  if (typeof subnetCalculatorPanel?.recomputeSessionThreatScore === "function") {
    subnetCalculatorPanel.recomputeSessionThreatScore({ silent: true });
  }
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
  setDataToolsFileNameGuess("");
  renderDataToolsLanguageGuess(null);
  renderDataTypeGuesses([]);
  document.getElementById("data-tools-entropy").textContent =
    "Shannon Entropy: 0.00 (Low)";
  resetHashOutputs();
  clearProtoDecoderOutput();
  clearDataToolsStreamPackets();
  clearDataToolsSelectionState();
  setExpandedConvertedOutput(null);
  updateDataToolsConvertedOutputVisibility();
  updateDataToolsOutputPaginationControls();
}

// Returns conv full output text.
function getConvFullOutputText(exportType) {
  const bytes = dataToolsLastConversionBytes;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    switch (exportType) {
      case "hex":
        return document.getElementById("data-tools-hex-output")?.value?.trim() || "";
      case "binary":
        return document.getElementById("data-tools-binary-output")?.value?.trim() || "";
      case "decimal":
        return document.getElementById("data-tools-decimal-output")?.value?.trim() || "";
      case "decimal-integer":
        return document
          .getElementById("data-tools-decimal-integer-output")
          ?.value?.trim() || "";
      case "ascii":
        return document.getElementById("data-tools-ascii-output")?.value?.trim() || "";
      case "base64":
        return document.getElementById("data-tools-base64-output")?.value?.trim() || "";
      default:
        return "";
    }
  }

  switch (exportType) {
    case "hex":
      return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0").toUpperCase()).join(" ");
    case "binary":
      return Array.from(bytes, (byte) => byte.toString(2).padStart(8, "0")).join(" ");
    case "decimal":
      return Array.from(bytes, (byte) => String(byte)).join(" ");
    case "decimal-integer":
      return bytes.length > DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES
        ? `Input exceeds ${DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES} bytes for decimal integer display`
        : bytesToBigIntDecimal(bytes);
    case "ascii":
      return bytesToPrintableAscii(bytes);
    case "base64":
      return bytesToBase64(bytes);
    default:
      return "";
  }
}

// Handles update data tools output pagination controls.
function updateDataToolsOutputPaginationControls() {
  const rowEl = document.getElementById("data-tools-output-pagination-row");
  const statusEl = document.getElementById("data-tools-output-pagination-status");
  const buttonEl = document.getElementById("data-tools-load-more-output-btn");
  if (!rowEl || !statusEl || !buttonEl) return;

  const totalBytes =
    dataToolsLastConversionBytes instanceof Uint8Array
      ? dataToolsLastConversionBytes.length
      : 0;
  if (!totalBytes) {
    rowEl.hidden = true;
    statusEl.textContent = "";
    buttonEl.disabled = true;
    return;
  }

  rowEl.hidden = false;
  const shownBytes = Math.min(dataToolsLastRenderedOutputBytes, totalBytes);
  statusEl.textContent = `Showing ${shownBytes.toLocaleString()} / ${totalBytes.toLocaleString()} bytes`;
  buttonEl.disabled = shownBytes >= totalBytes;
}

// Renders data tools output page.
function renderDataToolsOutputPage({ reset = false } = {}) {
  const totalBytes =
    dataToolsLastConversionBytes instanceof Uint8Array
      ? dataToolsLastConversionBytes.length
      : 0;
  if (!totalBytes) {
    updateDataToolsOutputPaginationControls();
    return;
  }

  if (reset) {
    dataToolsLastRenderedOutputBytes = Math.min(DATA_TOOLS_OUTPUT_PAGE_BYTES, totalBytes);
    dataToolsRenderedOutputPanes.clear();
  } else {
    dataToolsLastRenderedOutputBytes = Math.min(
      totalBytes,
      dataToolsLastRenderedOutputBytes + DATA_TOOLS_OUTPUT_PAGE_BYTES,
    );
  }

  const renderedBytes = dataToolsLastConversionBytes.slice(0, dataToolsLastRenderedOutputBytes);

  // Always render decimal-integer because it is already computed and cheap to assign.
  document.getElementById("data-tools-decimal-integer-output").value =
    dataToolsLastConversionDisplay.decimalInteger;
  dataToolsRenderedOutputPanes.add("data-tools-decimal-integer-output");

  const activeFormat =
    document.getElementById("data-tools-format")?.value || DEFAULT_DATA_TOOLS_FORMAT;
  const formatOutputId =
    DATA_TOOLS_OUTPUT_FORMAT_DETAILS[activeFormat]?.outputSelector?.slice(1) || null;

  let hexValues = null;
  let binaryValues = null;
  let decimalValues = null;
  let asciiText = null;
  let base64Text = null;
  let hexOutputText = null;

  for (const outputId of DATA_TOOLS_CONVERTED_OUTPUT_IDS) {
    if (outputId === "data-tools-decimal-integer-output") continue;

    const outputEl = document.getElementById(outputId);
    if (!outputEl) continue;

    const isExpanded = outputEl.classList.contains("data-tools-output-expanded");
    const shouldRender = isExpanded || dataToolsRenderedOutputPanes.has(outputId);

    // Hide the output pane matching the active input format unless it has been expanded.
    if (outputId === formatOutputId && !shouldRender) {
      outputEl.value = "";
      continue;
    }

    if (!shouldRender) {
      outputEl.value = getDataToolsOutputPlaceholder(outputId, renderedBytes.length, totalBytes);
      continue;
    }

    if (hexValues == null) {
      hexValues = Array.from(renderedBytes, (byte) =>
        byte.toString(16).padStart(2, "0").toUpperCase(),
      );
      binaryValues = Array.from(renderedBytes, (byte) =>
        byte.toString(2).padStart(8, "0"),
      );
      decimalValues = Array.from(renderedBytes, (byte) => String(byte));
      asciiText = bytesToPrintableAscii(renderedBytes);
      base64Text = bytesToBase64(renderedBytes);
      hexOutputText = buildRenderedSelectionMap(hexValues, {
        valuesPerLine: 16,
      }).text;
    }

    switch (outputId) {
      case "data-tools-hex-output":
        outputEl.value = hexOutputText;
        break;
      case "data-tools-binary-output":
        outputEl.value = binaryValues.join(" ");
        break;
      case "data-tools-decimal-output":
        outputEl.value = decimalValues.join(" ");
        break;
      case "data-tools-ascii-output":
        outputEl.value = asciiText;
        break;
      case "data-tools-base64-output":
        outputEl.value = base64Text;
        break;
    }
  }

  updateDataToolsSelectionMaps(
    activeFormat,
    document.getElementById("data-tools-input")?.value || "",
    renderedBytes,
    {
      hexValues,
      binaryValues,
      decimalValues,
      asciiText,
      base64Text,
    },
  );
  syncDataToolsSelectionFromField(
    document.activeElement && DATA_TOOLS_SELECTION_FIELD_IDS.includes(document.activeElement.id)
      ? document.activeElement.id
      : "data-tools-input",
  );
  updateDataToolsHexHighlights();
  updateDataToolsOutputPaginationControls();
  updateDataToolsCursorReadout(
    document.activeElement && DATA_TOOLS_SELECTION_FIELD_IDS.includes(document.activeElement.id)
      ? document.activeElement.id
      : "data-tools-input",
  );
}

// Loads more data tools output page.
function loadMoreDataToolsOutputPage() {
  renderDataToolsOutputPage({ reset: false });
}

// Sets expanded converted output.
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

  if (expandedOutputId) {
    dataToolsRenderedOutputPanes.add(expandedOutputId);
    renderDataToolsOutputPage({ reset: false });
    const expandedEl = document.getElementById(expandedOutputId);
    if (expandedEl) {
      requestAnimationFrame(() => {
        expandedEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
        expandedEl.focus({ preventScroll: true });
      });
    }
  }
}

// Handles bind converted output expand handlers.
function bindConvertedOutputExpandHandlers() {
  DATA_TOOLS_CONVERTED_OUTPUT_IDS.forEach((outputId) => {
    const outputEl = document.getElementById(outputId);
    if (!outputEl || outputEl.dataset.expandBinding === "1") return;
    outputEl.dataset.expandBinding = "1";
    outputEl.addEventListener("dblclick", () => {
      setExpandedConvertedOutput(outputId);
    });
  });
}

// Handles update data tools converted output visibility.
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

// Resets hash outputs.
function resetHashOutputs() {
  for (const id of HASH_IDS) {
    document.getElementById(id).value = "";
  }
}

// Handles bytes to char string.
function bytesToCharString(bytes) {
  const CHUNK_SIZE = 0x8000;
  let result = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, i + CHUNK_SIZE);
    result += String.fromCharCode(...chunk);
  }
  return result;
}

// Computes data tools hashes.
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

// Sets data tools find replace status.
function setDataToolsFindReplaceStatus(statusElementId, message, isError = false) {
  const statusEl = document.getElementById(statusElementId);
  if (!statusEl) return;
  statusEl.textContent = String(message || "");
  statusEl.style.color = isError ? "#ff8f8f" : "";
}

// Clears data tools simple find replace values.
function clearDataToolsSimpleFindReplaceValues() {
  const searchEl = document.getElementById("data-tools-simple-search");
  const replaceEl = document.getElementById("data-tools-simple-replace");
  const matchCaseEl = document.getElementById("data-tools-simple-match-case");
  if (searchEl) searchEl.value = "";
  if (replaceEl) replaceEl.value = "";
  if (matchCaseEl) matchCaseEl.checked = false;
  setDataToolsFindReplaceStatus("data-tools-simple-replace-status", "");
}

// Clears data tools advanced find replace values.
function clearDataToolsAdvancedFindReplaceValues() {
  const searchEl = document.getElementById("data-tools-pcre-search");
  const replaceEl = document.getElementById("data-tools-pcre-replace");
  const flagI = document.getElementById("data-tools-pcre-flag-i");
  const flagM = document.getElementById("data-tools-pcre-flag-m");
  const flagS = document.getElementById("data-tools-pcre-flag-s");
  const flagU = document.getElementById("data-tools-pcre-flag-u");
  if (searchEl) searchEl.value = "";
  if (replaceEl) replaceEl.value = "";
  if (flagI) flagI.checked = false;
  if (flagM) flagM.checked = false;
  if (flagS) flagS.checked = false;
  if (flagU) flagU.checked = false;
  setDataToolsFindReplaceStatus("data-tools-pcre-status", "");
}

// Sets data tools find replace section collapsed.
function setDataToolsFindReplaceSectionCollapsed(sectionEl, collapsed) {
  if (!sectionEl) return;
  sectionEl.classList.toggle("is-collapsed", Boolean(collapsed));
  const children = Array.from(sectionEl.children || []);
  children.forEach((child) => {
    if (child.classList?.contains("data-tools-find-replace-title")) {
      child.hidden = false;
      return;
    }
    child.hidden = Boolean(collapsed);
  });
}

// Sets data tools find replace mode.
function setDataToolsFindReplaceMode(mode) {
  const simpleSection = document.getElementById("data-tools-simple-find-replace-section");
  const advancedSection = document.getElementById("data-tools-advanced-find-replace-section");
  if (!simpleSection || !advancedSection) return;

  if (mode === "simple") {
    setDataToolsFindReplaceSectionCollapsed(simpleSection, false);
    setDataToolsFindReplaceSectionCollapsed(advancedSection, true);
    clearDataToolsAdvancedFindReplaceValues();
    return;
  }

  if (mode === "advanced") {
    setDataToolsFindReplaceSectionCollapsed(advancedSection, false);
    setDataToolsFindReplaceSectionCollapsed(simpleSection, true);
    clearDataToolsSimpleFindReplaceValues();
    return;
  }

  setDataToolsFindReplaceSectionCollapsed(simpleSection, false);
  setDataToolsFindReplaceSectionCollapsed(advancedSection, false);
}

// Normalizes data tools byte token.
function normalizeDataToolsByteToken(byteValue) {
  const normalized = Number(byteValue);
  if (!Number.isInteger(normalized) || normalized < 0 || normalized > 255) {
    return null;
  }
  return normalized;
}

// Parses data tools escaped bytes expression.
function parseDataToolsEscapedBytesExpression(rawExpression) {
  const expression = String(rawExpression || "");
  const bytes = [];
  let plainStart = 0;

  const flushPlain = (end) => {
    if (end <= plainStart) return;
    bytes.push(...DATA_TOOLS_TEXT_ENCODER.encode(expression.slice(plainStart, end)));
  };

  for (let i = 0; i < expression.length; i++) {
    if (expression[i] !== "\\") continue;
    const next = expression[i + 1];
    if (!next) continue;

    let parsedByte = null;
    let consumedLength = 0;

    if (next === "x") {
      const hexPair = expression.slice(i + 2, i + 4);
      if (/^[0-9A-Fa-f]{2}$/.test(hexPair)) {
        parsedByte = parseInt(hexPair, 16);
        consumedLength = 4;
      }
    } else if (next === "b") {
      const bitOctet = expression.slice(i + 2, i + 10);
      if (/^[01]{8}$/.test(bitOctet)) {
        parsedByte = parseInt(bitOctet, 2);
        consumedLength = 10;
      }
    } else if (next === "d") {
      const decimalMatch = expression.slice(i + 2).match(/^(\d{1,3})/);
      if (decimalMatch?.[1]) {
        const decimalByte = normalizeDataToolsByteToken(parseInt(decimalMatch[1], 10));
        if (decimalByte != null) {
          parsedByte = decimalByte;
          consumedLength = 2 + decimalMatch[1].length;
        }
      }
    } else if (next === "n") {
      parsedByte = 0x0a;
      consumedLength = 2;
    } else if (next === "r") {
      parsedByte = 0x0d;
      consumedLength = 2;
    } else if (next === "t") {
      parsedByte = 0x09;
      consumedLength = 2;
    } else if (next === "\\") {
      parsedByte = 0x5c;
      consumedLength = 2;
    }

    if (parsedByte == null || consumedLength <= 0) continue;
    flushPlain(i);
    bytes.push(parsedByte);
    i += consumedLength - 1;
    plainStart = i + 1;
  }

  flushPlain(expression.length);
  return new Uint8Array(bytes);
}

// Normalizes data tools pcre pattern for byte search.
function normalizeDataToolsPcrePatternForByteSearch(rawPattern) {
  const pattern = String(rawPattern || "");
  let normalized = "";
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i] !== "\\") {
      normalized += pattern[i];
      continue;
    }
    const next = pattern[i + 1];
    if (!next) {
      normalized += "\\";
      continue;
    }

    if (next === "x") {
      const hexPair = pattern.slice(i + 2, i + 4);
      if (/^[0-9A-Fa-f]{2}$/.test(hexPair)) {
        normalized += `\\x${hexPair.toUpperCase()}`;
        i += 3;
        continue;
      }
    } else if (next === "b") {
      const bitOctet = pattern.slice(i + 2, i + 10);
      if (/^[01]{8}$/.test(bitOctet)) {
        const byteValue = parseInt(bitOctet, 2).toString(16).padStart(2, "0").toUpperCase();
        normalized += `\\x${byteValue}`;
        i += 9;
        continue;
      }
    } else if (next === "d") {
      const decimalMatch = pattern.slice(i + 2).match(/^(\d{1,3})/);
      if (decimalMatch?.[1]) {
        const decimalByte = normalizeDataToolsByteToken(parseInt(decimalMatch[1], 10));
        if (decimalByte != null) {
          normalized += `\\x${decimalByte.toString(16).padStart(2, "0").toUpperCase()}`;
          i += 1 + decimalMatch[1].length;
          continue;
        }
      }
    }

    normalized += pattern[i];
  }
  return normalized;
}

// Normalizes data tools pcre replacement for byte search.
function normalizeDataToolsPcreReplacementForByteSearch(rawReplacement) {
  const replacement = String(rawReplacement || "");
  let normalized = "";
  for (let i = 0; i < replacement.length; i++) {
    if (replacement[i] !== "\\") {
      normalized += replacement[i];
      continue;
    }
    const next = replacement[i + 1];
    if (!next) {
      normalized += "\\";
      continue;
    }

    let parsedByte = null;
    let consumedLength = 0;
    if (next === "x") {
      const hexPair = replacement.slice(i + 2, i + 4);
      if (/^[0-9A-Fa-f]{2}$/.test(hexPair)) {
        parsedByte = parseInt(hexPair, 16);
        consumedLength = 4;
      }
    } else if (next === "b") {
      const bitOctet = replacement.slice(i + 2, i + 10);
      if (/^[01]{8}$/.test(bitOctet)) {
        parsedByte = parseInt(bitOctet, 2);
        consumedLength = 10;
      }
    } else if (next === "d") {
      const decimalMatch = replacement.slice(i + 2).match(/^(\d{1,3})/);
      if (decimalMatch?.[1]) {
        const decimalByte = normalizeDataToolsByteToken(parseInt(decimalMatch[1], 10));
        if (decimalByte != null) {
          parsedByte = decimalByte;
          consumedLength = 2 + decimalMatch[1].length;
        }
      }
    } else if (next === "n") {
      parsedByte = 0x0a;
      consumedLength = 2;
    } else if (next === "r") {
      parsedByte = 0x0d;
      consumedLength = 2;
    } else if (next === "t") {
      parsedByte = 0x09;
      consumedLength = 2;
    } else if (next === "\\") {
      parsedByte = 0x5c;
      consumedLength = 2;
    }

    if (parsedByte == null || consumedLength <= 0) {
      normalized += replacement[i];
      continue;
    }

    normalized += String.fromCharCode(parsedByte);
    i += consumedLength - 1;
  }
  return normalized;
}

// Handles encode data tools bytes for format.
function encodeDataToolsBytesForFormat(bytes, format) {
  const safeFormat = String(format || "hex").toLowerCase();
  if (safeFormat === "hex") {
    return [...bytes]
      .map((byte) => byte.toString(16).padStart(2, "0").toUpperCase())
      .join(" ");
  }
  if (safeFormat === "binary") {
    return [...bytes]
      .map((byte) => byte.toString(2).padStart(8, "0"))
      .join(" ");
  }
  if (safeFormat === "decimal") {
    return [...bytes].join(" ");
  }
  if (safeFormat === "base64") {
    return bytesToBase64(bytes);
  }
  return new TextDecoder().decode(bytes);
}

// Handles byte string to uint8 array.
function byteStringToUint8Array(value) {
  const input = String(value || "");
  const result = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) {
    result[i] = input.charCodeAt(i) & 0xff;
  }
  return result;
}

// Returns data tools input byte context.
function getDataToolsInputByteContext() {
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  if (!inputEl || !formatEl) return null;
  const format = String(formatEl.value || "hex").toLowerCase();
  const inputValue = String(inputEl.value || "");
  const bytes = parseDataToolsInput(format, inputValue);
  const inputMap = buildInputSelectionMap(inputValue, format, bytes);
  const selectionStart = Number(inputEl.selectionStart || 0);
  const selectionEnd = Number(inputEl.selectionEnd || 0);
  const charToByte = inputMap?.charToByte || [];

  const mapCharIndexToByteIndex = (charIndex) => {
    if (!bytes.length) return 0;
    const bounded = Math.max(0, Math.min(Number(charIndex || 0), inputValue.length));
    for (let i = bounded; i < charToByte.length; i++) {
      const byteIndex = charToByte[i];
      if (Number.isInteger(byteIndex)) return byteIndex;
    }
    for (let i = Math.min(bounded - 1, charToByte.length - 1); i >= 0; i--) {
      const byteIndex = charToByte[i];
      if (Number.isInteger(byteIndex)) return Math.min(byteIndex + 1, bytes.length);
    }
    return bytes.length;
  };

  return {
    inputEl,
    format,
    inputValue,
    bytes,
    inputMap,
    selectionStartByte: mapCharIndexToByteIndex(selectionStart),
    selectionEndByte: mapCharIndexToByteIndex(selectionEnd),
  };
}

// Handles map data tools byte range to selection.
function mapDataToolsByteRangeToSelection(inputValue, format, bytes, startByte, endByte) {
  const map = buildInputSelectionMap(inputValue, format, bytes);
  const byteRanges = map?.byteRanges || [];
  const safeStartByte = Math.max(0, Math.min(startByte, bytes.length));
  const safeEndByte = Math.max(safeStartByte, Math.min(endByte, bytes.length));
  const startChar =
    safeStartByte >= bytes.length
      ? inputValue.length
      : Number(byteRanges[safeStartByte]?.start ?? inputValue.length);
  const endChar =
    safeEndByte <= 0
      ? 0
      : safeEndByte > bytes.length
        ? inputValue.length
        : Number(byteRanges[safeEndByte - 1]?.end ?? startChar);
  return { startChar, endChar };
}

// Handles to lower ascii byte.
function toLowerAsciiByte(byteValue) {
  if (byteValue >= 0x41 && byteValue <= 0x5a) return byteValue + 32;
  return byteValue;
}

// Handles bytes match at.
function bytesMatchAt(haystack, needle, atIndex, matchCase) {
  for (let i = 0; i < needle.length; i++) {
    const sourceByte = haystack[atIndex + i];
    const targetByte = needle[i];
    if (matchCase) {
      if (sourceByte !== targetByte) return false;
    } else if (toLowerAsciiByte(sourceByte) !== toLowerAsciiByte(targetByte)) {
      return false;
    }
  }
  return true;
}

// Finds next byte pattern.
function findNextBytePattern(haystack, needle, startIndex, matchCase = true) {
  if (!needle.length || haystack.length < needle.length) return null;
  const maxIndex = haystack.length - needle.length;
  const boundedStart = Math.max(0, Math.min(startIndex, maxIndex + 1));
  for (let i = boundedStart; i <= maxIndex; i++) {
    if (bytesMatchAt(haystack, needle, i, matchCase)) {
      return { start: i, end: i + needle.length, wrapped: false };
    }
  }
  if (boundedStart > 0) {
    for (let i = 0; i < boundedStart && i <= maxIndex; i++) {
      if (bytesMatchAt(haystack, needle, i, matchCase)) {
        return { start: i, end: i + needle.length, wrapped: true };
      }
    }
  }
  return null;
}

// Handles replace all byte patterns.
function replaceAllBytePatterns(haystack, needle, replacement, matchCase = true) {
  if (!needle.length) {
    return { bytes: haystack, count: 0 };
  }
  const output = [];
  let replacedCount = 0;
  let cursor = 0;
  while (cursor <= haystack.length - needle.length) {
    if (bytesMatchAt(haystack, needle, cursor, matchCase)) {
      output.push(...replacement);
      cursor += needle.length;
      replacedCount += 1;
      continue;
    }
    output.push(haystack[cursor]);
    cursor += 1;
  }
  while (cursor < haystack.length) {
    output.push(haystack[cursor]);
    cursor += 1;
  }
  return { bytes: new Uint8Array(output), count: replacedCount };
}

// Returns data tools pcre pattern and flags.
function getDataToolsPcrePatternAndFlags(includeGlobalFlag = false) {
  const rawPattern = String(
    document.getElementById("data-tools-pcre-search")?.value || "",
  );
  let pattern = rawPattern;
  const collectedFlags = new Set();

  if (document.getElementById("data-tools-pcre-flag-i")?.checked) {
    collectedFlags.add("i");
  }
  if (document.getElementById("data-tools-pcre-flag-m")?.checked) {
    collectedFlags.add("m");
  }
  if (document.getElementById("data-tools-pcre-flag-s")?.checked) {
    collectedFlags.add("s");
  }
  if (document.getElementById("data-tools-pcre-flag-u")?.checked) {
    collectedFlags.add("u");
  }

  const inlineFlagsMatch = pattern.match(/^\(\?([imsu]+)\)/i);
  if (inlineFlagsMatch) {
    inlineFlagsMatch[1]
      .toLowerCase()
      .split("")
      .forEach((flag) => collectedFlags.add(flag));
    pattern = pattern.slice(inlineFlagsMatch[0].length);
  }

  if (!pattern) {
    throw new Error("Enter a PCRE pattern first.");
  }

  if (includeGlobalFlag) {
    collectedFlags.add("g");
  }
  return { pattern, flags: [...collectedFlags].join("") };
}

// Finds next regex match.
function findNextRegexMatch(value, regex, fromIndex) {
  const boundedStart = Math.max(0, Math.min(fromIndex, value.length));
  regex.lastIndex = boundedStart;
  let guard = 0;
  const maxIterations = value.length + 2;

  while (guard < maxIterations) {
    const match = regex.exec(value);
    if (!match) break;
    const start = match.index;
    const text = String(match[0] || "");
    const end = start + text.length;
    if (text.length === 0 && start < value.length) {
      regex.lastIndex = start + 1;
      guard += 1;
      continue;
    }
    return { match, start, end, wrapped: false };
  }

  if (boundedStart > 0) {
    regex.lastIndex = 0;
    guard = 0;
    while (guard < maxIterations) {
      const match = regex.exec(value);
      if (!match) break;
      const start = match.index;
      const text = String(match[0] || "");
      const end = start + text.length;
      if (text.length === 0 && start < value.length) {
        regex.lastIndex = start + 1;
        guard += 1;
        continue;
      }
      return { match, start, end, wrapped: true };
    }
  }

  return null;
}

// Handles update data tools input after search replace.
function updateDataToolsInputAfterSearchReplace(nextValue, selectionStart, selectionEnd) {
  const inputEl = document.getElementById("data-tools-input");
  if (!inputEl) return;
  inputEl.value = nextValue;
  dataToolsOriginalInputBytes = null;
  dataToolsInputEditedFlag = true;
  clearDataToolsStreamPackets();
  if (
    Number.isInteger(selectionStart) &&
    Number.isInteger(selectionEnd) &&
    typeof inputEl.setSelectionRange === "function"
  ) {
    inputEl.setSelectionRange(selectionStart, selectionEnd);
  }
  inputEl.focus();
  dataToolsHistorySelectEl.value = "";
  updateDataToolsHexHighlights();
  syncDataToolsHighlightScroll("data-tools-input", "data-tools-input-highlight");
  updateDataToolsInputEditedState();
  if (String(inputEl.value || "").trim()) {
    runDataToolsConversion({ suppressHistory: true, suppressCommit: true });
  } else {
    document.getElementById("data-tools-error").textContent = "";
    resetDataToolsOutputs();
    clearDataToolsSelectionState();
    updateDataToolsInputEditedState();
  }
}

// Runs data tools simple find next.
function runDataToolsSimpleFindNext() {
  setDataToolsFindReplaceMode("simple");
  const context = getDataToolsInputByteContext();
  const needleBytes = parseDataToolsEscapedBytesExpression(
    document.getElementById("data-tools-simple-search")?.value || "",
  );
  const matchCase = Boolean(
    document.getElementById("data-tools-simple-match-case")?.checked,
  );
  if (!context) return;
  if (!needleBytes.length) {
    setDataToolsFindReplaceStatus(
      "data-tools-simple-replace-status",
      "Enter text to find (bytes: \\xHH, \\b01010101, \\d10).",
      true,
    );
    return;
  }
  const result = findNextBytePattern(
    context.bytes,
    needleBytes,
    context.selectionEndByte,
    matchCase,
  );
  if (!result) {
    setDataToolsFindReplaceStatus(
      "data-tools-simple-replace-status",
      "No match found.",
      true,
    );
    return;
  }
  const selectionRange = mapDataToolsByteRangeToSelection(
    context.inputValue,
    context.format,
    context.bytes,
    result.start,
    result.end,
  );
  context.inputEl.focus();
  context.inputEl.setSelectionRange(selectionRange.startChar, selectionRange.endChar);
  syncDataToolsSelectionFromField("data-tools-input");
  setDataToolsFindReplaceStatus(
    "data-tools-simple-replace-status",
    result.wrapped ? "Match found (wrapped to top)." : "Match found.",
  );
}

// Runs data tools simple replace next.
function runDataToolsSimpleReplaceNext() {
  setDataToolsFindReplaceMode("simple");
  const context = getDataToolsInputByteContext();
  const needleBytes = parseDataToolsEscapedBytesExpression(
    document.getElementById("data-tools-simple-search")?.value || "",
  );
  const replacementBytes = parseDataToolsEscapedBytesExpression(
    document.getElementById("data-tools-simple-replace")?.value || "",
  );
  const matchCase = Boolean(
    document.getElementById("data-tools-simple-match-case")?.checked,
  );
  if (!context) return;
  if (!needleBytes.length) {
    setDataToolsFindReplaceStatus(
      "data-tools-simple-replace-status",
      "Enter text to find (bytes: \\xHH, \\b01010101, \\d10).",
      true,
    );
    return;
  }

  const target = findNextBytePattern(
    context.bytes,
    needleBytes,
    context.selectionEndByte,
    matchCase,
  );

  if (!target) {
    setDataToolsFindReplaceStatus(
      "data-tools-simple-replace-status",
      "No match found to replace.",
      true,
    );
    return;
  }

  const updatedBytes = new Uint8Array(
    context.bytes.length - needleBytes.length + replacementBytes.length,
  );
  updatedBytes.set(context.bytes.slice(0, target.start), 0);
  updatedBytes.set(replacementBytes, target.start);
  updatedBytes.set(context.bytes.slice(target.end), target.start + replacementBytes.length);

  const updatedInputValue = encodeDataToolsBytesForFormat(updatedBytes, context.format);
  const updatedSelection = mapDataToolsByteRangeToSelection(
    updatedInputValue,
    context.format,
    updatedBytes,
    target.start,
    target.start + replacementBytes.length,
  );
  updateDataToolsInputAfterSearchReplace(
    updatedInputValue,
    updatedSelection.startChar,
    updatedSelection.endChar,
  );
  setDataToolsFindReplaceStatus(
    "data-tools-simple-replace-status",
    target.wrapped
      ? "Replaced 1 match (wrapped to top)."
      : "Replaced 1 match.",
  );
}

// Runs data tools simple replace all.
function runDataToolsSimpleReplaceAll() {
  setDataToolsFindReplaceMode("simple");
  const context = getDataToolsInputByteContext();
  const needleBytes = parseDataToolsEscapedBytesExpression(
    document.getElementById("data-tools-simple-search")?.value || "",
  );
  const replacementBytes = parseDataToolsEscapedBytesExpression(
    document.getElementById("data-tools-simple-replace")?.value || "",
  );
  const matchCase = Boolean(
    document.getElementById("data-tools-simple-match-case")?.checked,
  );
  if (!context) return;
  if (!needleBytes.length) {
    setDataToolsFindReplaceStatus(
      "data-tools-simple-replace-status",
      "Enter text to find (bytes: \\xHH, \\b01010101, \\d10).",
      true,
    );
    return;
  }

  const replaceResult = replaceAllBytePatterns(
    context.bytes,
    needleBytes,
    replacementBytes,
    matchCase,
  );
  const replacedCount = replaceResult.count;

  if (!replacedCount) {
    setDataToolsFindReplaceStatus(
      "data-tools-simple-replace-status",
      "No matches replaced.",
      true,
    );
    return;
  }

  const updatedInputValue = encodeDataToolsBytesForFormat(replaceResult.bytes, context.format);
  updateDataToolsInputAfterSearchReplace(updatedInputValue, 0, 0);
  setDataToolsFindReplaceStatus(
    "data-tools-simple-replace-status",
    `Replaced ${replacedCount} match${replacedCount === 1 ? "" : "es"}.`,
  );
}

// Runs data tools pcre find next.
function runDataToolsPcreFindNext() {
  setDataToolsFindReplaceMode("advanced");
  const context = getDataToolsInputByteContext();
  if (!context) return;
  try {
    const { pattern, flags } = getDataToolsPcrePatternAndFlags(true);
    const bytePattern = normalizeDataToolsPcrePatternForByteSearch(pattern);
    const regex = new RegExp(bytePattern, flags);
    const byteString = bytesToCharString(context.bytes);
    const found = findNextRegexMatch(byteString, regex, context.selectionEndByte);
    if (!found) {
      setDataToolsFindReplaceStatus("data-tools-pcre-status", "No pattern match found.", true);
      return;
    }
    const selectionRange = mapDataToolsByteRangeToSelection(
      context.inputValue,
      context.format,
      context.bytes,
      found.start,
      found.end,
    );
    context.inputEl.focus();
    context.inputEl.setSelectionRange(selectionRange.startChar, selectionRange.endChar);
    syncDataToolsSelectionFromField("data-tools-input");
    setDataToolsFindReplaceStatus(
      "data-tools-pcre-status",
      found.wrapped ? "Pattern match found (wrapped to top)." : "Pattern match found.",
    );
  } catch (error) {
    setDataToolsFindReplaceStatus(
      "data-tools-pcre-status",
      error?.message || "Invalid PCRE pattern.",
      true,
    );
  }
}

// Runs data tools pcre replace next.
function runDataToolsPcreReplaceNext() {
  setDataToolsFindReplaceMode("advanced");
  const context = getDataToolsInputByteContext();
  const replacement = String(document.getElementById("data-tools-pcre-replace")?.value || "");
  if (!context) return;
  try {
    const { pattern, flags } = getDataToolsPcrePatternAndFlags(true);
    const bytePattern = normalizeDataToolsPcrePatternForByteSearch(pattern);
    const normalizedReplacement = normalizeDataToolsPcreReplacementForByteSearch(replacement);
    const globalRegex = new RegExp(bytePattern, flags);
    const singleRegex = new RegExp(bytePattern, flags.replace(/g/g, ""));
    const byteString = bytesToCharString(context.bytes);
    const found = findNextRegexMatch(byteString, globalRegex, context.selectionEndByte);

    if (!found) {
      setDataToolsFindReplaceStatus("data-tools-pcre-status", "No pattern match found to replace.", true);
      return;
    }

    const before = byteString.slice(0, found.start);
    const after = byteString.slice(found.end);
    const replacementText = String(found.match[0] || "").replace(
      singleRegex,
      normalizedReplacement,
    );
    const updatedByteString = `${before}${replacementText}${after}`;
    const updatedBytes = byteStringToUint8Array(updatedByteString);
    const updatedInputValue = encodeDataToolsBytesForFormat(updatedBytes, context.format);
    const updatedSelection = mapDataToolsByteRangeToSelection(
      updatedInputValue,
      context.format,
      updatedBytes,
      found.start,
      found.start + replacementText.length,
    );
    updateDataToolsInputAfterSearchReplace(
      updatedInputValue,
      updatedSelection.startChar,
      updatedSelection.endChar,
    );
    setDataToolsFindReplaceStatus(
      "data-tools-pcre-status",
      found.wrapped
        ? "Replaced 1 pattern match (wrapped to top)."
        : "Replaced 1 pattern match.",
    );
  } catch (error) {
    setDataToolsFindReplaceStatus(
      "data-tools-pcre-status",
      error?.message || "Invalid PCRE pattern.",
      true,
    );
  }
}

// Runs data tools pcre replace all.
function runDataToolsPcreReplaceAll() {
  setDataToolsFindReplaceMode("advanced");
  const context = getDataToolsInputByteContext();
  const replacement = String(document.getElementById("data-tools-pcre-replace")?.value || "");
  if (!context) return;
  try {
    const { pattern, flags } = getDataToolsPcrePatternAndFlags(true);
    const bytePattern = normalizeDataToolsPcrePatternForByteSearch(pattern);
    const normalizedReplacement = normalizeDataToolsPcreReplacementForByteSearch(replacement);
    const regex = new RegExp(bytePattern, flags);
    const byteString = bytesToCharString(context.bytes);
    let replacedCount = 0;
    byteString.replace(regex, () => {
      replacedCount += 1;
      return "";
    });
    regex.lastIndex = 0;
    const updatedByteString = byteString.replace(regex, normalizedReplacement);

    if (!replacedCount) {
      setDataToolsFindReplaceStatus("data-tools-pcre-status", "No pattern matches replaced.", true);
      return;
    }

    const updatedBytes = byteStringToUint8Array(updatedByteString);
    const updatedInputValue = encodeDataToolsBytesForFormat(updatedBytes, context.format);
    updateDataToolsInputAfterSearchReplace(updatedInputValue, 0, 0);
    setDataToolsFindReplaceStatus(
      "data-tools-pcre-status",
      `Replaced ${replacedCount} pattern match${replacedCount === 1 ? "" : "es"}.`,
    );
  } catch (error) {
    setDataToolsFindReplaceStatus(
      "data-tools-pcre-status",
      error?.message || "Invalid PCRE pattern.",
      true,
    );
  }
}

// Parses the current Conv input into bytes, preferring the untracked full
// source bytes when the displayed input has not been edited.
function getCurrentDataToolsInputBytes() {
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  if (!inputEl || !formatEl) return null;
  const canUseOriginal =
    !dataToolsInputEditedFlag &&
    dataToolsOriginalInputBytes instanceof Uint8Array &&
    dataToolsOriginalInputBytes.length > 0;
  if (canUseOriginal) {
    return dataToolsOriginalInputBytes;
  }
  try {
    const parsed = parseDataToolsInput(formatEl.value, inputEl.value);
    return parsed;
  } catch (error) {
    return null;
  }
}

// Runs data tools conversion.
async function runDataToolsConversion(options = {}) {
  const suppressHistory = Boolean(options?.suppressHistory);
  const suppressCommit = Boolean(options?.suppressCommit);
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  const errorEl = document.getElementById("data-tools-error");
  updateDataToolsConvertedOutputVisibility();
  await yieldToRenderer();

  try {
    const canUseOriginal =
      !dataToolsInputEditedFlag &&
      dataToolsOriginalInputBytes instanceof Uint8Array &&
      dataToolsOriginalInputBytes.length > 0;
    const bytes = canUseOriginal
      ? dataToolsOriginalInputBytes
      : parseDataToolsInput(formatEl.value, inputEl.value);
    const isLargePayload = bytes.length > DATA_TOOLS_HEAVY_ANALYSIS_DEFER_BYTES;
    if (isLargePayload) {
      await yieldToRenderer();
    }
    const inspectedBytes =
      bytes.length > DATA_TOOLS_TEXT_INSPECTION_MAX_BYTES
        ? bytes.slice(0, DATA_TOOLS_TEXT_INSPECTION_MAX_BYTES)
        : bytes;
    const inputTextSample =
      inputEl.value.length > DATA_TOOLS_INPUT_TEXT_SAMPLE_MAX_CHARS
        ? inputEl.value.slice(0, DATA_TOOLS_INPUT_TEXT_SAMPLE_MAX_CHARS)
        : inputEl.value;
    if (!suppressHistory) {
      addDataToolsInputHistory(formatEl.value, inputEl.value);
    }
    const inspectedText = decodeBytesForTextInspection(inspectedBytes);
    const entropy = calculateShannonEntropy(bytes);
    const entropyLabel = getEntropyLabel(entropy);
    const decimalInteger =
      bytes.length > DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES
        ? `Input exceeds ${DATA_TOOLS_MAX_DECIMAL_INTEGER_BYTES} bytes for decimal integer display`
        : bytesToBigIntDecimal(bytes);

    dataToolsLastConversionBytes = bytes;
    dataToolsLastConversionDisplay = {
      decimalInteger,
    };
    renderDataToolsOutputPage({ reset: true });
    if (isLargePayload) {
      await yieldToRenderer();
    }
    document.getElementById("data-tools-byte-length").textContent =
      `Byte Length: ${bytes.length}`;
    document.getElementById("data-tools-mime-type").textContent =
      `MIME Type: ${inferMimeType(bytes)}`;
    renderDataToolsLanguageGuess(
      guessReadableTextLanguage(
        formatEl.value === "ascii" ? inputTextSample : inspectedText,
        inspectedBytes,
      ),
    );
    // ASCII input has already been scanned as raw text; skip duplicate decoded scan.
    renderDataTypeGuesses(
      deriveDataTypeGuesses(
        formatEl.value === "ascii" ? inputTextSample : "",
        formatEl.value === "ascii" ? "" : inspectedText,
      ),
    );
    document.getElementById("data-tools-entropy").textContent =
      `Shannon Entropy: ${entropy.toFixed(2)} (${entropyLabel})`;
    errorEl.textContent = "";
    if (isLargePayload) {
      await yieldToRenderer();
    }
    if (!isLargePayload || getActiveConvSubtab() === CONV_HASHES_SUBTAB) {
      computeDataToolsHashes(bytes);
    } else {
      resetHashOutputs();
    }
    if (isLargePayload) {
      await yieldToRenderer();
    }
    if (!isLargePayload || getActiveConvSubtab() === CONV_DECODES_SUBTAB) {
      runProtoDecoder(bytes);
    } else {
      clearProtoDecoderOutput();
    }
    if (!isLargePayload || getActiveConvSubtab() === CONV_EXTRACTION_SUBTAB) {
      refreshExtractionPanelForCurrentConvInput();
    } else {
      resetExtractionOutputs();
    }
    if (!suppressCommit) {
      markDataToolsInputCommitted();
      dataToolsContextPacket = null;
      if (canUseOriginal && dataToolsOriginalInputBytes instanceof Uint8Array) {
        dataToolsOriginalInputBytes = bytes;
        dataToolsInputEditedFlag = false;
      } else {
        dataToolsOriginalInputBytes = null;
        dataToolsInputEditedFlag = false;
        clearDataToolsStreamPackets();
      }
    }
    requestDataToolsBackgroundSummary(getActiveConvSubtab());


  } catch (error) {
    errorEl.textContent =
      error && typeof error === "object" && "message" in error
        ? error.message
        : String(error);
  }
}

// ── Protocol decoders moved to src/ui/decoders/conv/ (see imports at the top) ───

// Runs deferred data tools analysis for active subtab.
function runDeferredDataToolsAnalysisForActiveSubtab() {
  const bytes = getCurrentDataToolsInputBytes();
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return;
  const activeSubtab = getActiveConvSubtab();
  if (activeSubtab === CONV_HASHES_SUBTAB) {
    computeDataToolsHashes(bytes);
  }
  if (activeSubtab === CONV_EXTRACTION_SUBTAB) {
    refreshExtractionPanelForCurrentConvInput();
  }
  if (activeSubtab === CONV_DECODES_SUBTAB) {
    runProtoDecoder(bytes);
  }
  requestDataToolsBackgroundSummary(activeSubtab);
}

// Returns the decoder hint for the current context packet so other panels or
// context actions can ask what the Conv Decodes subtab would use first.
function getCurrentPacketProtocolDecoderHint() {
  const packet =
    (dataToolsContextPacket && !dataToolsInputEditedFlag
      ? dataToolsContextPacket
      : null) ||
    getCurrentContextPacket() ||
    getCurrentPacketForExport();
  return getPacketProtocolDecoderHint(packet);
}

// ── Extraction subtab renderer logic ────────────────────────────────────────

let extractionPanelCurrentBytes = new Uint8Array();
let extractionPanelCurrentFormat = null; // detected format label
let extractionPanelLastResult = null;    // decompressed or extracted bytes
let extractionPanelArchiveEntries = [];
let extractionPanelSelectedEntry = null;
let extractionPanelActiveOperation = null;

function base64ToUint8Array(base64) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i += 1) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function uint8ArrayToBase64(bytes) {
  const binaryString = Array.from(bytes)
    .map((b) => String.fromCharCode(b))
    .join("");
  return btoa(binaryString);
}

function inferExtractionFormatName(bytes) {
  if (!bytes || bytes.length < 2) return null;
  const b = bytes;
  if (b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b) return "gzip";
  if (b.length >= 4 && b[0] === 0x42 && b[1] === 0x5a && b[2] === 0x68) return "bz2";
  if (b.length >= 6 && b[0] === 0xfd && b[1] === 0x37 && b[2] === 0x7a && b[3] === 0x58 && b[4] === 0x5a && b[5] === 0x00) return "lzma";
  if (b.length >= 3 && b[0] === 0x4c && b[1] === 0x5a && b[2] === 0x4f) return "lzo";
  if (b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return "zip";
  if (b.length >= 4 && (b[0] === 0x28 || b[0] === 0x29) && b[1] === 0xb5 && b[2] === 0x2f && b[3] === 0xfd) return "brotli";
  return null;
}

function getExtractionPanelElements() {
  return {
    detectValue: document.getElementById("data-tools-extraction-detect-value"),
    decompressBtn: document.getElementById("data-tools-extraction-decompress-btn"),
    listArchiveBtn: document.getElementById("data-tools-extraction-list-archive-btn"),
    progress: document.getElementById("data-tools-extraction-progress"),
    progressText: document.getElementById("data-tools-extraction-progress-text"),
    error: document.getElementById("data-tools-extraction-error"),
    tree: document.getElementById("data-tools-extraction-tree"),
    preview: document.getElementById("data-tools-extraction-preview"),
    previewMeta: document.getElementById("data-tools-extraction-preview-meta"),
    loadConvBtn: document.getElementById("data-tools-extraction-load-conv-btn"),
    saveBtn: document.getElementById("data-tools-extraction-save-btn"),
    hashBtn: document.getElementById("data-tools-extraction-hash-btn"),
    vtBtn: document.getElementById("data-tools-extraction-vt-btn"),
    output: document.getElementById("data-tools-extraction-output"),
    outputText: document.getElementById("data-tools-extraction-output-text"),
    outputHex: document.getElementById("data-tools-extraction-output-hex"),
    outputLoadBtn: document.getElementById("data-tools-extraction-output-load-btn"),
    outputSaveBtn: document.getElementById("data-tools-extraction-output-save-btn"),
  };
}

function showExtractionProgress(message) {
  const { progress, progressText, error } = getExtractionPanelElements();
  if (progress) {
    progress.hidden = false;
    progress.classList.add("loading");
  }
  if (progressText) progressText.textContent = message || "Working…";
  if (error) error.textContent = "";
}

function hideExtractionProgress() {
  const { progress } = getExtractionPanelElements();
  if (progress) {
    progress.hidden = true;
    progress.classList.remove("loading");
  }
}

function setExtractionError(message) {
  const { error } = getExtractionPanelElements();
  if (error) error.textContent = message || "";
  hideExtractionProgress();
}

function clearExtractionError() {
  setExtractionError("");
}

function refreshExtractionPanelForCurrentConvInput() {
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  const els = getExtractionPanelElements();
  if (!inputEl || !formatEl || !els.detectValue) return;

  extractionPanelCurrentBytes = new Uint8Array();
  extractionPanelCurrentFormat = null;
  extractionPanelLastResult = null;
  extractionPanelArchiveEntries = [];
  extractionPanelSelectedEntry = null;
  // Do NOT clear extractionCarvableRegistry here. Manual carves and archive
  // extractions are intentionally registered in Stats and should survive
  // routine Conv/Extraction panel refreshes. The registry is still cleared on
  // explicit output reset and on file load via resetDataToolsOutputs/fileLoaded.

  extractionPanelCurrentBytes = getCurrentDataToolsInputBytes() || new Uint8Array();

  const fmt = inferExtractionFormatName(extractionPanelCurrentBytes);
  extractionPanelCurrentFormat = fmt;

  els.detectValue.textContent = fmt ? fmt.toUpperCase() : "None / unknown";
  els.decompressBtn.disabled = !fmt || fmt === "zip";
  els.listArchiveBtn.disabled = fmt !== "zip";
  if (els.tree) els.tree.innerHTML = "";
  if (els.preview) els.preview.hidden = true;
  if (els.output) els.output.hidden = true;
  clearExtractionError();
}

function setExtractionOutputText(bytes) {
  const { output, outputText, outputHex } = getExtractionPanelElements();
  if (!outputText || !outputHex || !output) return;
  output.hidden = false;
  const hexString = bytesToHexString(bytes);
  outputHex.textContent = hexString;
  outputText.value = hexString;
}

async function handleExtractionDecompress() {
  const fmt = extractionPanelCurrentFormat;
  if (!fmt || fmt === "zip") return;
  if (!window.extractapi || typeof window.extractapi.decompress !== "function") {
    setExtractionError("Extraction API is unavailable.");
    return;
  }
  showExtractionProgress(`Decompressing ${fmt.toUpperCase()}…`);
  try {
    const response = await window.extractapi.decompress({
      bytesBase64: uint8ArrayToBase64(extractionPanelCurrentBytes),
      algorithm: fmt,
    });
    if (!response?.success) {
      setExtractionError(response?.error || "Decompression failed.");
      return;
    }
    const bytes = base64ToUint8Array(response.bytesBase64);
    extractionPanelLastResult = bytes;
    registerExtractionResultForStats(
      extractionPanelCurrentFormat || "decompressed.bin",
      bytes,
    );
    setExtractionOutputText(bytes);
    requestDataToolsBackgroundSummary(CONV_EXTRACTION_SUBTAB);
    statusUpdate(
      `Status: Decompressed ${fmt.toUpperCase()} into ${bytes.length} bytes`,
    );
  } catch (err) {
    setExtractionError(err?.message || String(err));
  } finally {
    hideExtractionProgress();
  }
}

async function handleExtractionListArchive() {
  if (extractionPanelCurrentFormat !== "zip") return;
  if (!window.extractapi || typeof window.extractapi.listArchive !== "function") {
    setExtractionError("Extraction API is unavailable.");
    return;
  }
  showExtractionProgress("Reading archive contents…");
  try {
    const response = await window.extractapi.listArchive({
      bytesBase64: uint8ArrayToBase64(extractionPanelCurrentBytes),
    });
    if (!response?.success) {
      setExtractionError(response?.error || "Archive listing failed.");
      return;
    }
    extractionPanelArchiveEntries = Array.isArray(response.entries) ? response.entries : [];
    renderExtractionArchiveTree(extractionPanelArchiveEntries);
    requestDataToolsBackgroundSummary(CONV_EXTRACTION_SUBTAB);
    statusUpdate(
      `Status: Listed ${extractionPanelArchiveEntries.length} archive entries`,
    );
  } catch (err) {
    setExtractionError(err?.message || String(err));
  } finally {
    hideExtractionProgress();
  }
}

function renderExtractionArchiveTree(entries) {
  const { tree } = getExtractionPanelElements();
  if (!tree) return;
  tree.innerHTML = "";
  if (!entries.length) {
    tree.textContent = "No entries found.";
    return;
  }

  const list = document.createElement("ul");
  list.className = "data-tools-extraction-tree-list";
  entries.forEach((entry) => {
    const item = document.createElement("li");
    item.className = "data-tools-extraction-tree-item";
    const isDir = entry.type === "directory";
    const isExtractable = !isDir && !!entry.safePath;
    const safeBadge = entry.isSafe && !isDir
      ? `<span class="data-tools-extraction-safe" title="Safe relative path">✓</span>`
      : `<span class="data-tools-extraction-unsafe" title="${escapeHtml(entry.unsafeReason || "Unsafe or non-extractable")}">⚠</span>`;
    const sizeText = isDir
      ? "dir"
      : `${entry.uncompressedSize || entry.compressedSize || 0} bytes`;
    item.innerHTML = `${safeBadge} <span class="data-tools-extraction-path">${escapeHtml(entry.path)}</span> <span class="data-tools-extraction-size">(${escapeHtml(String(sizeText))})</span>`;
    if (isExtractable) {
      const extractBtn = document.createElement("button");
      extractBtn.type = "button";
      extractBtn.textContent = entry.isSafe ? "Extract" : "Extract (safe)";
      extractBtn.className = "data-tools-extraction-extract-entry-btn";
      extractBtn.addEventListener("click", () => handleExtractionExtractEntry(entry));
      item.appendChild(extractBtn);
    }
    list.appendChild(item);
  });
  tree.appendChild(list);
}

async function handleExtractionExtractEntry(entry) {
  if (!entry?.safePath || entry.type === "directory") return;
  if (!window.extractapi || typeof window.extractapi.extractArchiveEntry !== "function") {
    setExtractionError("Extraction API is unavailable.");
    return;
  }
  showExtractionProgress(`Extracting ${entry.safePath || entry.path}…`);
  try {
    const response = await window.extractapi.extractArchiveEntry({
      bytesBase64: uint8ArrayToBase64(extractionPanelCurrentBytes),
      entryPath: entry.path,
      safePath: entry.safePath,
    });
    if (!response?.success) {
      setExtractionError(response?.error || "Extraction failed.");
      return;
    }
    const bytes = base64ToUint8Array(response.bytesBase64);
    extractionPanelLastResult = bytes;
    extractionPanelSelectedEntry = entry;
    registerExtractionResultForStats(getBareFilename(entry.safePath) || "extracted.bin", bytes);
    showExtractionPreview(entry, bytes);
    requestDataToolsBackgroundSummary(CONV_EXTRACTION_SUBTAB);
    statusUpdate(
      `Status: Extracted ${entry.safePath || entry.path} (${bytes.length} bytes)`,
    );
  } catch (err) {
    setExtractionError(err?.message || String(err));
  } finally {
    hideExtractionProgress();
  }
}

// Returns the bare filename from a path, dropping all directories.
function getBareFilename(filePath) {
  if (!filePath || typeof filePath !== "string") return "";
  return filePath.replace(/\\/g, "/").split("/").pop() || "";
}

function showExtractionPreview(entry, bytes) {
  const { preview, previewMeta } = getExtractionPanelElements();
  if (!preview || !previewMeta) return;
  preview.hidden = false;
  const displayPath = entry.safePath || entry.path;
  const safeText = entry.isSafe
    ? `Safe relative path (${entry.safePath})`
    : `Path sanitized from traversal; extracted as "${displayPath}"`;
  previewMeta.innerHTML = `<div class="data-tools-extraction-preview-name"><strong>${escapeHtml(displayPath)}</strong></div>
    <div class="data-tools-extraction-preview-size">${bytes.length} bytes</div>
    <div class="data-tools-extraction-preview-safety">${escapeHtml(safeText)}</div>`;
}

function loadExtractionResultIntoConv(bytes, fileNameHint) {
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  if (!inputEl || !formatEl) {
    statusUpdate("Status: Conv input fields are unavailable");
    return false;
  }
  dataToolsContextPacket = null;
  dataToolsOriginalInputBytes = bytes;
  dataToolsInputEditedFlag = false;
  clearDataToolsStreamPackets();
  dataToolsLastConversionBytes = bytes;
  inputEl.value = formatHexInputBytesWithCap(bytes);
  formatEl.value = "hex";
  setDataToolsFileNameGuess(fileNameHint || "");
  markDataToolsInputCommitted();
  showDataTools(CONV_CONVERSIONS_SUBTAB);
  runDataToolsConversion();
  statusUpdate(`Status: Loaded extracted/decompressed data into Conv (${bytes.length} bytes)`);
  return true;
}

async function saveExtractionResultToFile(bytes, defaultName) {
  if (!window.saveapi || typeof window.saveapi.saveText !== "function") {
    setExtractionError("Save API is unavailable.");
    return;
  }
  const safeDefaultName = String(defaultName || "extracted.bin").replace(/[\\/:*?"<>|]/g, "_");
  const hexString = bytesToHexString(bytes);
  try {
    await window.saveapi.saveText({
      text: hexString,
      title: "Save Extracted Data",
      defaultName: safeDefaultName,
      filters: [
        { name: "Binary Files", extensions: ["bin"] },
        { name: "All Files", extensions: ["*"] },
      ],
    });
    statusUpdate(`Status: Saved ${safeDefaultName}`);
  } catch (err) {
    setExtractionError(err?.message || String(err));
  }
}

function getExtractionResultForSaveOrLoad() {
  return extractionPanelLastResult instanceof Uint8Array && extractionPanelLastResult.length > 0
    ? extractionPanelLastResult
    : null;
}

function loadExtractionResultIntoHashesSubtab(bytes, fileNameHint) {
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  if (!inputEl || !formatEl) {
    statusUpdate("Status: Conv input fields are unavailable");
    return false;
  }
  dataToolsOriginalInputBytes = bytes;
  dataToolsInputEditedFlag = false;
  clearDataToolsStreamPackets();
  dataToolsLastConversionBytes = bytes;
  inputEl.value = formatHexInputBytesWithCap(bytes);
  formatEl.value = "hex";
  setDataToolsFileNameGuess(fileNameHint || "");
  markDataToolsInputCommitted();
  showDataTools(CONV_HASHES_SUBTAB);
  runDeferredDataToolsAnalysisForActiveSubtab();
  statusUpdate(`Status: Loaded extracted file into Hashes (${bytes.length} bytes)`);
  return true;
}

async function uploadExtractionResultToVirusTotal(bytes, fileNameHint) {
  if (!window.snitchapi || typeof window.snitchapi.lookupVirusTotal !== "function") {
    setExtractionError("VirusTotal API is unavailable.");
    return;
  }
  const apiKey = getBackendVirusTotalApiKey();
  if (!apiKey) {
    setExtractionError("VirusTotal API key is not configured in Settings > Backend.");
    return;
  }
  showExtractionProgress("Uploading to VirusTotal…");
  try {
    const sha256Hex = await window.extractapi.sha256Bytes({ bytesBase64: uint8ArrayToBase64(bytes) });
    const lookupResponse = await window.snitchapi.lookupVirusTotal(sha256Hex, {
      lookupType: "hash",
      apiKey,
      backendOptions: getBackendTransportOptionsFromSettings(),
    });
    if (lookupResponse?.success) {
      statusUpdate(`Status: VirusTotal report found for ${fileNameHint || "file"}`);
      showVirusTotalResultModal(lookupResponse, fileNameHint);
      return;
    }
    const uploadResponse = await window.extractapi.uploadVirusTotal({
      bytesBase64: uint8ArrayToBase64(bytes),
      fileName: getBareFilename(fileNameHint) || "sample.bin",
      apiKey,
    });
    if (!uploadResponse?.success) {
      setExtractionError(uploadResponse?.error || "VirusTotal upload failed.");
      return;
    }
    statusUpdate(`Status: Uploaded to VirusTotal; analysis ID ${uploadResponse.analysisId || ""}`);
    showVirusTotalResultModal(uploadResponse, fileNameHint);
  } catch (err) {
    setExtractionError(err?.message || String(err));
  } finally {
    hideExtractionProgress();
  }
}

function showVirusTotalResultModal(response, fileNameHint) {
  const analysis = response?.analysis || {};
  const title = `VirusTotal: ${fileNameHint || "file"}`;
  const rows = [
    { label: "Lookup type", value: response?.lookupType || "file" },
    { label: "Value", value: response?.lookupValue || response?.analysisId || "-" },
    { label: "Malicious", value: analysis.malicious ?? 0 },
    { label: "Suspicious", value: analysis.suspicious ?? 0 },
    { label: "Harmless", value: analysis.harmless ?? 0 },
    { label: "Undetected", value: analysis.undetected ?? 0 },
  ];
  if (response?.error) {
    rows.push({ label: "Error", value: response.error });
  }
  showInfoDialog(title, rows, response?.sourceUrl);
}

let activeInfoDialogResolver = null;

function showInfoDialog(title, rows, linkUrl) {
  const dialogEl = document.getElementById("info-message-dialog");
  const titleEl = document.getElementById("info-message-dialog-title");
  const bodyEl = document.getElementById("info-message-dialog-body");
  const linkEl = document.getElementById("info-message-dialog-link");
  const sendToNotesBtn = document.getElementById("info-message-dialog-send-to-notes-btn");
  const okBtn = document.getElementById("info-message-dialog-ok-btn");
  if (!dialogEl || !titleEl || !bodyEl || !okBtn) {
    window.alert?.(title);
    return Promise.resolve();
  }
  if (activeInfoDialogResolver) {
    const resolve = activeInfoDialogResolver;
    activeInfoDialogResolver = null;
    resolve();
  }
  titleEl.textContent = title;
  bodyEl.innerHTML = "";
  if (Array.isArray(rows) && rows.length) {
    rows.forEach(({ label, value }) => {
      const row = document.createElement("div");
      row.className = "info-message-dialog-row";
      const labelEl = document.createElement("span");
      labelEl.className = "info-message-dialog-label";
      labelEl.textContent = `${label}: `;
      const valueEl = document.createElement("span");
      valueEl.className = "info-message-dialog-value";
      valueEl.textContent = value === undefined || value === null ? "-" : String(value);
      row.appendChild(labelEl);
      row.appendChild(valueEl);
      bodyEl.appendChild(row);
    });
  }
  if (linkEl) {
    if (linkUrl) {
      linkEl.href = linkUrl;
      linkEl.textContent = "Open VirusTotal report";
      linkEl.hidden = false;
    } else {
      linkEl.href = "#";
      linkEl.textContent = "";
      linkEl.hidden = true;
    }
  }
  if (sendToNotesBtn) {
    const existingHandler = sendToNotesBtn.dataset.hasNotesHandler;
    if (!existingHandler) {
      sendToNotesBtn.addEventListener("click", () => {
        const currentLinkUrl = document.getElementById("info-message-dialog-link")?.href;
        if (!currentLinkUrl || currentLinkUrl === "#") {
          statusUpdate("Status: No report link available to add");
          return;
        }
        const noteText = `VirusTotal record: ${currentLinkUrl}`;
        const didAdd = addNote(noteText, NOTE_DEFAULT_COLOR, "virustotal-link", false);
        if (didAdd) {
          showNotesWorkspace();
          statusUpdate("Status: VirusTotal link added to Notes");
          writeLogEntry(`VirusTotal link added to notes link=${JSON.stringify(currentLinkUrl)}`);
          resolveInfoDialog();
        }
      });
      sendToNotesBtn.dataset.hasNotesHandler = "true";
    }
    sendToNotesBtn.hidden = !linkUrl;
  }
  dialogEl.hidden = false;
  okBtn.focus();
  return new Promise((resolve) => {
    activeInfoDialogResolver = resolve;
  });
}

function resolveInfoDialog() {
  const dialogEl = document.getElementById("info-message-dialog");
  if (dialogEl) dialogEl.hidden = true;
  if (!activeInfoDialogResolver) return;
  const resolve = activeInfoDialogResolver;
  activeInfoDialogResolver = null;
  resolve();
}

function installExtractionPanelListeners() {
  const els = getExtractionPanelElements();
  if (els.decompressBtn) {
    els.decompressBtn.addEventListener("click", handleExtractionDecompress);
  }
  if (els.listArchiveBtn) {
    els.listArchiveBtn.addEventListener("click", handleExtractionListArchive);
  }
  if (els.loadConvBtn) {
    els.loadConvBtn.addEventListener("click", () => {
      const bytes = getExtractionResultForSaveOrLoad();
      const hint = getBareFilename(extractionPanelSelectedEntry?.safePath || extractionPanelSelectedEntry?.path) || extractionPanelCurrentFormat || "extracted";
      if (bytes) loadExtractionResultIntoConv(bytes, hint);
    });
  }
  if (els.saveBtn) {
    els.saveBtn.addEventListener("click", () => {
      const bytes = getExtractionResultForSaveOrLoad();
      const hint = getBareFilename(extractionPanelSelectedEntry?.safePath || extractionPanelSelectedEntry?.path) || extractionPanelCurrentFormat || "extracted.bin";
      if (bytes) saveExtractionResultToFile(bytes, hint);
    });
  }
  if (els.hashBtn) {
    els.hashBtn.addEventListener("click", () => {
      const bytes = getExtractionResultForSaveOrLoad();
      const hint = getBareFilename(extractionPanelSelectedEntry?.safePath || extractionPanelSelectedEntry?.path) || extractionPanelCurrentFormat || "extracted";
      if (bytes) loadExtractionResultIntoHashesSubtab(bytes, hint);
    });
  }
  if (els.vtBtn) {
    els.vtBtn.addEventListener("click", () => {
      const bytes = getExtractionResultForSaveOrLoad();
      const hint = getBareFilename(extractionPanelSelectedEntry?.safePath || extractionPanelSelectedEntry?.path) || extractionPanelCurrentFormat || "extracted.bin";
      if (bytes) uploadExtractionResultToVirusTotal(bytes, hint);
    });
  }
  if (els.outputLoadBtn) {
    els.outputLoadBtn.addEventListener("click", () => {
      const bytes = getExtractionResultForSaveOrLoad();
      const hint = extractionPanelCurrentFormat || "decompressed";
      if (bytes) loadExtractionResultIntoConv(bytes, hint);
    });
  }
  if (els.outputSaveBtn) {
    els.outputSaveBtn.addEventListener("click", () => {
      const bytes = getExtractionResultForSaveOrLoad();
      const hint = extractionPanelCurrentFormat || "decompressed.bin";
      if (bytes) saveExtractionResultToFile(bytes, hint);
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────

// ============================================================================
// Data tools and workspace display toggles
// ============================================================================

const { showDataTools, showNotesWorkspace, showSettingsWorkspace } =
  createWorkspaceTabController({
    constants: {
      MAIN_TAB_DATA_TOOLS,
      MAIN_TAB_NOTES,
      MAIN_TAB_SETTINGS,
      CONV_CONVERSIONS_SUBTAB,
    },
    state: {
      get activeMainTab() {
        return activeMainTab;
      },
      set activeMainTab(value) {
        activeMainTab = value;
      },
      get activeSettingsSubtab() {
        return activeSettingsSubtab;
      },
    },
    statusUpdate,
    writeLogEntry,
    threadName,
    setConvSubtab,
    normalizeDataToolsHexInputFormatting,
    runDeferredDataToolsAnalysisForActiveSubtab,
    renderNotesList,
    ensureNotesWorkspaceMounted,
    setSettingsSubtab,
    syncSettingsFormFromState,
  });

// Returns first line or fallback.
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
    isLikelyIpAddress,
    extractIpv6EndpointParts,
    formatNetworkEndpointDisplay,
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
  getSessionKeychainEntries: () => keystorePanel.getSessionKeychainEntries(),
  getFirstLineOrFallback,
  sendDecryptedToConv: ({ hexValue, utf8Value }) => {
    const inputEl = document.getElementById("data-tools-input");
    const formatEl = document.getElementById("data-tools-format");
    const normalizedHex = String(hexValue || "").trim();
    const normalizedUtf8 = String(utf8Value || "");
    if (normalizedHex) {
      dataToolsContextPacket = null;
      dataToolsOriginalInputBytes = hexStringToUint8Array(normalizedHex);
      dataToolsInputEditedFlag = false;
      dataToolsLastConversionBytes = dataToolsOriginalInputBytes;
      inputEl.value = formatHexInputBytesWithCap(dataToolsOriginalInputBytes);
      formatEl.value = "hex";
    } else {
      dataToolsContextPacket = null;
      dataToolsOriginalInputBytes = null;
      dataToolsInputEditedFlag = true;
      clearDataToolsStreamPackets();
      inputEl.value = normalizedUtf8;
      formatEl.value = "ascii";
    }
    setDataToolsFileNameGuess("");
    markDataToolsInputCommitted();
    showDataTools(CONV_CONVERSIONS_SUBTAB);
    runDataToolsConversion();
  },
});

const {
  setCryptSubtab,
  applyCryptCertificateText,
  applyCryptPrivateKeyText,
  applyCryptKeyLogText,
  readCryptTextFile,
  applyCryptFilterForActiveEntry,
  loadEncounteredCertificateIntoCrypt,
  refreshCryptEncounteredEntries,
  loadStreamIntoCryptEncountered,
  refreshPgpEncounteredEntries,
  showCryptWorkspace,
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
  getCurrentPacketKey: () => currentPacketKey,
  syncBookmarkDropdown,
  setActivePacketCursor,
  showAllData,
  infoPanel,
  popHexGrid,
  populateDataTypes: (...args) => populateDataTypes(...args),
  isCaptureStoreBackedCapture: () => isCaptureStoreBackedCapture,
  getCurrentSettings,
  setCurrentSettings,
  getEnableUngroupedListVirtualization: () =>
    Boolean(getCurrentSettings()?.debug?.ungroupedListVirtualizationEnabled),
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
let activeContextLlmQuestionDialogResolver = null;
let activeContextLlmQuestionDialogContext = null;
let activeSavedFilterLabelDialogResolver = null;
let activeSavedFilterDialogContext = null;
let activeFollowStreamConfirmDialogResolver = null;
let activeManualConvImportWarningDialogResolver = null;
let activeSettingsResetConfirmDialogResolver = null;
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
  exportDecrypted: getCachedElement("ctx-export-decrypted"),
  exportSummaryMarkdown: getCachedElement("ctx-export-summary-md"),
  exportSummaryText: getCachedElement("ctx-export-summary-txt"),
  exportSummaryHtml: getCachedElement("ctx-export-summary-html"),
  hex: getCachedElement("convert-context-hex"),
  binary: getCachedElement("convert-context-binary"),
  base64: getCachedElement("convert-context-base64"),
  decimal: getCachedElement("convert-context-decimal"),
  ascii: getCachedElement("convert-context-ascii"),
  deriveGuess: getCachedElement("convert-context-derive-guess"),
  loadFile: getCachedElement("convert-context-load-file"),
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
  notesSendConvInput: getCachedElement("ctx-notes-send-conv-input"),
  notesSendConvHex: getCachedElement("ctx-notes-send-conv-hex"),
  notesSendConvAscii: getCachedElement("ctx-notes-send-conv-ascii"),
  notesSendConvBase64: getCachedElement("ctx-notes-send-conv-base64"),
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
  llmBranch: getCachedElement("ctx-llm-branch"),
  llmQuestion: getCachedElement("ctx-llm-question"),
  llmSubnetHostSummary: getCachedElement("ctx-llm-subnet-host-summary"),
  followStreamConv: getCachedElement("ctx-follow-stream-conv"),
  followStreamConvDecompress: getCachedElement("ctx-follow-stream-conv-decompress"),
  followStreamCrypt: getCachedElement("ctx-follow-stream-crypt"),
  llmExplain: getCachedElement("ctx-llm-explain"),
  llmSummarize: getCachedElement("ctx-llm-summarize"),
  openHeatmapLocation: getCachedElement("ctx-open-heatmap-location"),
  loadCarvableExtraction: getCachedElement("ctx-load-carvable-extraction"),
  loadCarvableDecoders: getCachedElement("ctx-load-carvable-decoders"),
  loadCarvableVirusTotal: getCachedElement("ctx-load-carvable-virustotal"),
  analyzeIp: getCachedElement("ctx-analyze-ip-submenu"),
  analyzeIpSubnet: getCachedElement("ctx-analyze-ip-subnet"),
  analyzeIpThreatIntel: getCachedElement("ctx-analyze-ip-threat-intel"),
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
  llm: getCachedElement("ctx-llm-submenu"),
  analyzeIp: getCachedElement("ctx-analyze-ip-submenu"),
  reports: getCachedElement("ctx-reports-submenu"),
};
const convertContextDividerEl = getCachedElement("convert-context-divider");
const convertContextSaveDividerEl = getCachedElement(
  "convert-context-save-divider",
);
const convertContextSubmenuEls = Array.from(
  convertContextMenuEl.querySelectorAll(".ctx-submenu"),
);

// Resets convert context submenu positions.
function resetConvertContextSubmenuPositions() {
  convertContextSubmenuEls.forEach((submenuEl) => {
    submenuEl.classList.remove("ctx-submenu-flip-x", "ctx-submenu-flip-y");
  });
}

// Handles update convert context submenu positions.
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

// Hides convert context menu.
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

// Returns packet from list context target.
function getPacketFromListContextTarget(target, offset = 0) {
  const row = target?.closest?.("tr[data-host][data-pkt-idx]");
  if (!row) return null;
  const host = String(row.dataset.host || "").trim();
  const packetIndex = Number.parseInt(row.dataset.pktIdx ?? "-1", 10) + offset;
  if (!host || !Number.isInteger(packetIndex) || packetIndex < 0) return null;
  const hostPackets = capturedPackets?.["host"]?.[host];
  if (!Array.isArray(hostPackets)) return null;
  return hostPackets[packetIndex] || null;
}

// Returns current context packet.
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

// Normalizes context token.
function normalizeContextToken(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/\s+/g, " ").trim();
}

// Extracts context ip.
function extractContextIp(value) {
  const normalized = normalizeContextToken(value);
  if (!normalized) return "";

  const ipv6Endpoint = extractIpv6EndpointParts(normalized);
  if (ipv6Endpoint?.host) {
    return ipv6Endpoint.host;
  }

  const unwrapped = normalized.replace(/^\[([^\]]+)\]$/, "$1");
  if (isLikelyIpAddress(unwrapped)) {
    return unwrapped;
  }

  const bracketedIpv6Match = normalized.match(/\[([^\]]+)\]:(\d{1,5})\b/);
  if (bracketedIpv6Match && isLikelyIpAddress(bracketedIpv6Match[1])) {
    return bracketedIpv6Match[1];
  }

  const match = normalized.match(CONTEXT_IPV4_REGEX);
  return match ? match[0] : "";
}

// Extracts an IP from the right-clicked element so the Analyze IP submenu
// only appears when the user is actually hovering over (or has selected) an
// IPv4 or IPv6 address. We deliberately do NOT walk the entire panel/router
// table text: an IP anywhere in the panel would also expose the menu on
// nearby labels, protocol names, or unrelated cells, which is too permissive.
//
// Considered candidates (first hit wins):
//   1. The live text selection (highest signal: user explicitly highlighted).
//   2. The right-clicked element's own textContent.
//   3. The closest containing <td>/<th> cell.
//   4. The closest containing <tr> row (e.g. row-only IP columns).
//
// For each candidate we require the IP to be the dominant content of the
// text — i.e. there must be no other non-whitespace, non-IP token competing
// for the cell — so the menu never appears when right-clicking on a protocol
// name, label, or other non-IP row despite an IP happening to live elsewhere
// in the same row.
function extractContextIpFromContextTarget(target, {
  selectedText = "",
  conversionText = "",
} = {}) {
  const fromSelection = extractContextIp(selectedText);
  if (fromSelection) return fromSelection;

  const fromConversion = extractContextIp(conversionText);
  if (fromConversion) return fromConversion;

  const isOnlyIpToken = (value) => {
    const normalized = normalizeContextToken(value);
    if (!normalized) return "";
    const ip = extractContextIp(normalized);
    if (!ip) return "";
    // Strip the IP and any surrounding space/colon/comma/bracket characters
    // that commonly wrap it (e.g. "[10.0.0.1]:443") and check that what is
    // left is empty or whitespace only. This rejects cells that contain
    // mixed content like "TCP / 10.0.0.1" or "10.0.0.1 (gateway)".
    const stripped = normalized
      .replace(ip, " ")
      .replace(/[\s\[\]<>,;:()"']/g, " ")
      .trim();
    return stripped === "" ? ip : "";
  };

  const targetText = target?.textContent || "";
  const fromTarget = isOnlyIpToken(targetText);
  if (fromTarget) return fromTarget;

  const closestCell = target?.closest?.("td, th");
  if (closestCell) {
    const fromCell = isOnlyIpToken(closestCell.textContent || "");
    if (fromCell) return fromCell;
  }

  const closestRow = target?.closest?.("tr");
  if (closestRow) {
    const cells = closestRow.querySelectorAll("td, th");
    for (const cell of cells) {
      const fromRowCell = isOnlyIpToken(cell?.textContent || "");
      if (fromRowCell) return fromRowCell;
    }
  }

  return "";
}

// Extracts context port.
function extractContextPort(value, allowStandaloneNumber = false) {
  const normalized = normalizeContextToken(value);
  const ipv6Endpoint = extractIpv6EndpointParts(normalized);
  if (ipv6Endpoint?.port) {
    const ipv6PortValue = Number.parseInt(ipv6Endpoint.port, 10);
    return ipv6PortValue >= 0 && ipv6PortValue <= 65535 ? String(ipv6PortValue) : "";
  }
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

// Extracts context mac.
function extractContextMac(value) {
  const normalized = normalizeContextToken(value);
  const match = normalized.match(CONTEXT_MAC_REGEX);
  return match ? match[0].toLowerCase() : "";
}

// Extracts context mime type.
function extractContextMimeType(value) {
  const normalized = normalizeContextToken(value);
  const labelStripped = normalized
    .replace(/^mime(?:\s+type)?\s*:\s*/i, "")
    .trim();
  if (!labelStripped) return "";
  const mimeBase = labelStripped.split(";")[0].trim();
  return CONTEXT_MIME_REGEX.test(mimeBase) ? mimeBase.toLowerCase() : "";
}


// Handles sanitize filter term.
function sanitizeFilterTerm(value) {
  return normalizeContextToken(value)
    .replace(/[^a-zA-Z0-9:./+-]/g, "")
    .trim();
}

// Builds context filter queries.
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
    rowPortEligible = /\bport\b/i.test(rowName);
    if (/^ip\s*:?\s*port$/i.test(rowName) && rowValue) {
      let parsedIpPort = false;
      const bracketedIpv6Match = rowValue.match(/^\[([^\]]+)\]:(\d{1,5})$/);
      if (bracketedIpv6Match) {
        parsedIpPort = true;
        addCandidate(bracketedIpv6Match[1]);
        addCandidate(bracketedIpv6Match[2]);
      } else {
        const ipv4PortMatch = rowValue.match(
          /^((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}):(\d{1,5})$/,
        );
        if (ipv4PortMatch) {
          parsedIpPort = true;
          addCandidate(ipv4PortMatch[1]);
          addCandidate(ipv4PortMatch[2]);
        } else {
          const lastColonIndex = rowValue.lastIndexOf(":");
          if (lastColonIndex > 0) {
            const maybeHost = rowValue.slice(0, lastColonIndex).trim();
            const maybePort = rowValue.slice(lastColonIndex + 1).trim();
            if (/^\d{1,5}$/.test(maybePort)) {
              if (isLikelyIpAddress(maybeHost)) {
                parsedIpPort = true;
                addCandidate(maybeHost);
              }
              addCandidate(maybePort);
            }
          }
        }
      }
      if (!parsedIpPort) {
        addCandidate(rowValue);
      }
    } else {
      addCandidate(rowValue);
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
    const wireProto = String(currentPkt?.["packet.info"]?.["packet.proto"] ?? currentPkt?.["packet.info"]?.["Protocol"] ?? "").toLowerCase().trim();
    const appProto = String(currentPkt?.["extra.info"]?.["Traits"]?.["Network Data"]?.["Port Protcol"] ?? "").toLowerCase().trim();
    const safeWire = wireProto ? sanitizeFilterTerm(wireProto) : "";
    const safeApp = appProto && appProto !== "unknown" ? sanitizeFilterTerm(appProto) : "";
    const safeLink = String(currentPkt?.["packet.info"]?.["link.proto"] ?? "").toLowerCase().trim();
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

// Returns trimmed selection text.
function getTrimmedSelectionText() {
  return window.getSelection()?.toString().trim() || "";
}

// Returns utf8 byte length.
function getUtf8ByteLength(value) {
  const normalized = typeof value === "string" ? value : String(value || "");
  return DATA_TOOLS_TEXT_ENCODER.encode(normalized).length;
}

// Returns manual conv import max bytes.
function getManualConvImportMaxBytes() {
  return (
    Number(getCurrentSettings()?.general?.manualConvImportMaxBytes) ||
    DEFAULT_SETTINGS.general.manualConvImportMaxBytes
  );
}

// Formats byte count.
function formatByteCount(byteCount) {
  const bytes = Number(byteCount) || 0;
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(bytes >= 10 * 1024 * 1024 ? 1 : 2)} MB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(bytes >= 10 * 1024 ? 1 : 2)} KB`;
  }
  return `${bytes} bytes`;
}

// Returns context selection byte length.
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

// Handles looks like base64.
function looksLikeBase64(text) {
  const normalized = text.replace(/\s+/g, "");
  return (
    normalized.length >= DATA_TOOLS_CONTEXT_BASE64_MIN_LENGTH &&
    normalized.length % 4 === 0 &&
    /^[A-Za-z0-9+/]*={0,2}$/.test(normalized) &&
    normalized.replace(/=/g, "").length > 0
  );
}

// Detects convertible formats.
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

// Handles split cookie header entries.
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

// Extracts cookie jar entries from http fields.
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
  callLargeLanguageModel,
  isLlmRuntimeEnabled,
  isBackgroundSummaryGenerationEnabled,
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


// Builds cookie jar text from http fields.
function buildCookieJarTextFromHttpFields(fields) {
  return extractCookieJarEntriesFromHttpFields(fields).join("\n");
}

// Returns cookie jar text for current packet.
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

// Returns cookie jar text for context target.
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

// Returns conversion text from target.
function getConversionTextFromTarget(target) {
  // For Conv Decodes, prefer specific context (selection/cell value) and
  // fallback to the full decoder table only when no granular context exists.
  if (target?.closest?.("#conv-decodes-panel")) {
    const selectedText = window.getSelection()?.toString().trim();
    if (selectedText) return selectedText;

    const decoderCell = target?.closest?.("#data-tools-proto-output td");
    if (decoderCell) {
      const rowEl = decoderCell.closest("tr");
      const rowCells = rowEl ? Array.from(rowEl.querySelectorAll("td")) : [];
      const clickedText = String(decoderCell.textContent || "").trim();
      const clickedCellIndex = rowCells.indexOf(decoderCell);
      if (clickedCellIndex === 1 && clickedText) return clickedText;
      if (clickedCellIndex === 0) {
        const pairedValue = String(rowCells?.[1]?.textContent || "").trim();
        if (pairedValue) return pairedValue;
      }
      if (clickedText) return clickedText;
    }

    const decodeContextText = getConvDecodedOutputText();
    if (decodeContextText) return decodeContextText;
  }

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

// Returns paste target from context target.
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

// Shows convert context menu.
function showConvertContextMenu(
  x,
  y,
  sourceText,
  formats,
  {
    isHexViewTarget = false,
    target = null,
    pasteTarget = null,
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
  const isSummaryTabContext =
    activeMainTab === MAIN_TAB_SUMMARY &&
    Boolean(target?.closest?.("#summary_box"));
  const hasPacketToExport =
    !isSummaryTabContext && Boolean(getCurrentPacketForExport());
  const currentPayloadHex = getCurrentRawPayloadHex();
  const hasPayloadToExport =
    !isSummaryTabContext && Boolean(currentPayloadHex);
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
  const hasDecryptedDataToExport = Boolean(
    getCryptDecryptedExportCandidate(target),
  );
  const hasSummaryMarkdownToExport =
    isSummaryTabContext && Boolean(getSummaryMarkdownForExport().trim());
  const hasSummaryTextToExport = hasSummaryMarkdownToExport;
  const hasSummaryHtmlToExport = hasSummaryMarkdownToExport;
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
  const statsCarvableTag = activeMainTab === MAIN_TAB_STATS
    ? target?.closest?.("#stats_box .stats-section .stats-tag[data-carvable-id]")
    : null;
  const hasStatsCarvableAction = Boolean(statsCarvableTag);
  const hasFileCarveActions =
    hasHttpBody ||
    canCarveSmbStream ||
    canCarveNfsStream ||
    canCarveFtpStream ||
    hasStatsCarvableAction;
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
  convertContextButtons.exportDecrypted.style.display = hasDecryptedDataToExport
    ? "block"
    : "none";
  convertContextButtons.exportSummaryMarkdown.style.display =
    hasSummaryMarkdownToExport ? "block" : "none";
  convertContextButtons.exportSummaryText.style.display = hasSummaryTextToExport
    ? "block"
    : "none";
  convertContextButtons.exportSummaryHtml.style.display = hasSummaryHtmlToExport
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
  convertContextButtons.loadCarvableExtraction.style.display = hasStatsCarvableAction
    ? "block"
    : "none";
  convertContextButtons.loadCarvableDecoders.style.display = hasStatsCarvableAction
    ? "block"
    : "none";
  convertContextButtons.loadCarvableVirusTotal.style.display = hasStatsCarvableAction
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
  convertContextButtons.loadFile.style.display = "block";
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
  const statsLocationTag = activeMainTab === MAIN_TAB_STATS
    ? target?.closest?.("#stats_box .stats-section .stats-tag[data-latitude]")
    : null;
  const hasStatsLocationHeatmapAction = Boolean(statsLocationTag);
  convertContextButtons.openHeatmapLocation.style.display = hasStatsLocationHeatmapAction
    ? "block"
    : "none";
  const allowAnalyzeIpContext =
    activeMainTab === MAIN_TAB_DATA ||
    activeMainTab === MAIN_TAB_STATS ||
    activeMainTab === MAIN_TAB_LIST;
  const contextIpForAnalyze = allowAnalyzeIpContext
    ? extractContextIpFromContextTarget(target, {
      selectedText: getTrimmedSelectionText(),
      conversionText: sourceText,
    })
    : "";
  const hasAnalyzeIpActions = allowAnalyzeIpContext && Boolean(contextIpForAnalyze);
  convertContextSubmenus.analyzeIp.style.display = hasAnalyzeIpActions ? "block" : "none";
  convertContextButtons.analyzeIpSubnet.style.display = hasAnalyzeIpActions
    ? "block"
    : "none";
  convertContextButtons.analyzeIpThreatIntel.style.display = hasAnalyzeIpActions
    ? "block"
    : "none";
  const hasContextDataForNotes =
    allowNotesDataFromContext &&
    (hasContextSourceText || hasSelectionContext);
  const hasListVisibleDataForNotes =
    activeMainTab === MAIN_TAB_LIST &&
    Boolean(buildListVisibleDataNoteText(target));
  const hasConvInputForNotes =
    allowConvNotesActions && Boolean(getConvContextExportText("input"));
  const hasConvHexForNotes =
    allowConvNotesActions && Boolean(getConvContextExportText("hex"));
  const hasConvAsciiForNotes =
    allowConvNotesActions && Boolean(getConvContextExportText("ascii"));
  const hasConvBase64ForNotes =
    allowConvNotesActions && Boolean(getConvContextExportText("base64"));
  const hasConvHashesForNotes =
    allowConvNotesActions && Boolean(buildConvHashesNoteText());
  convertContextButtons.notesSendData.style.display = hasContextDataForNotes
    ? "block"
    : "none";
  convertContextButtons.notesSendListPacket.style.display =
    hasListVisibleDataForNotes ? "block" : "none";
  convertContextButtons.notesSendConvInput.style.display =
    hasConvInputForNotes ? "block" : "none";
  convertContextButtons.notesSendConvHex.style.display = hasConvHexForNotes
    ? "block"
    : "none";
  convertContextButtons.notesSendConvAscii.style.display =
    hasConvAsciiForNotes ? "block" : "none";
  convertContextButtons.notesSendConvBase64.style.display =
    hasConvBase64ForNotes ? "block" : "none";
  convertContextButtons.notesSendConvHashes.style.display =
    hasConvHashesForNotes ? "block" : "none";
  const hasNotesActions =
    hasContextDataForNotes ||
    hasListVisibleDataForNotes ||
    hasConvInputForNotes ||
    hasConvHexForNotes ||
    hasConvAsciiForNotes ||
    hasConvBase64ForNotes ||
    hasConvHashesForNotes;
  const hasCopyActions =
    hasSelectionContext || isHexViewTarget || hasCookieActions;
  const hasClipboardActions = hasCopyActions || showPaste;
  const hasGeneralActions = hasClipboardActions;
  const hasManualFileImportAction = true;
  const hasDataTypeActions =
    formats.length > 0 ||
    hasPayloadToExport ||
    hasManualFileImportAction ||
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
    hasPacketToExport ||
    hasPayloadToExport ||
    hasCookieActions ||
    hasConvExportActions ||
    hasDecryptedDataToExport;
  const hasReportsActions =
    hasSummaryMarkdownToExport ||
    hasSummaryTextToExport ||
    hasSummaryHtmlToExport;
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
  convertContextSubmenus.reports.style.display = hasReportsActions
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
  const llmEnabled = isLlmRuntimeEnabled();
  const llmExplainText = (getTrimmedSelectionText() || sourceText || "").trim();
  const hasLlmQuestionAction = llmEnabled && Boolean(activeContextPacket);
  const hasLlmSummarizeAction = llmEnabled && Boolean(activeContextPacket);
  const hasLlmSubnetHostSummaryAction =
    llmEnabled && Boolean(getSubnetHostIpFromContextTarget(target));
  const hasLlmExplainAction =
    llmEnabled && Boolean(activeContextPacket) && isTextSignificantForLlmExplain(llmExplainText);
  const hasLlmActions =
    hasLlmQuestionAction ||
    hasLlmExplainAction ||
    hasLlmSummarizeAction ||
    hasLlmSubnetHostSummaryAction;
  convertContextButtons.llmQuestion.style.display = hasLlmQuestionAction
    ? "block"
    : "none";
  convertContextButtons.llmExplain.style.display = hasLlmExplainAction
    ? "block"
    : "none";
  convertContextButtons.llmSummarize.style.display = hasLlmSummarizeAction
    ? "block"
    : "none";
  convertContextButtons.llmSubnetHostSummary.style.display =
    hasLlmSubnetHostSummaryAction ? "block" : "none";
  convertContextSubmenus.llm.style.display = hasLlmActions ? "block" : "none";
  if (
    !hasGeneralActions &&
    !hasDataTypeActions &&
    !isHexViewTarget &&
    !hasFilterActions &&
    !hasCookieActions &&
    !hasNotesActions &&
    !hasKeystoreActions &&
    !hasExportActions &&
    !hasReportsActions &&
    !hasHttpBody &&
    !hasFileCarveActions &&
    !hasFollowStreamActions &&
    !hasLlmActions &&
    !showSaveJson &&
    !hasStatsLocationHeatmapAction &&
    !hasStatsCarvableAction &&
    !hasAnalyzeIpActions
  ) {
    hideConvertContextMenu();
    return;
  } convertContextDividerEl.style.display =
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

// Loads context value into data tools.
function loadContextValueIntoDataTools(format) {
  if (!activeContextConversionText) return;
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  dataToolsOriginalInputBytes = null;
  dataToolsInputEditedFlag = true;
  clearDataToolsStreamPackets();
  dataToolsContextPacket = null;
  inputEl.value = activeContextConversionText;
  formatEl.value = format;
  setDataToolsFileNameGuess("");
  showDataTools();
  runDataToolsConversion();
  hideConvertContextMenu();
  writeLogEntry(`Context conversion loaded format=${format}`);
}

// Handles derive context selection guess from context menu.
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
  setDataToolsFileNameGuess("");
  showDataTools();
  runDataToolsConversion();
  writeLogEntry("Derived data type guess from selected/context data");
}

// Loads raw payload into data tools from context menu.
function loadRawPayloadIntoDataToolsFromContextMenu() {
  const contextPacket = getCurrentContextPacket();
  const payloadHex = getCurrentRawPayloadHex();
  hideConvertContextMenu();
  if (!payloadHex) {
    statusUpdate("Status: No raw payload available to load");
    return;
  }
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  const payloadBytes = hexStringToUint8Array(payloadHex);
  dataToolsContextPacket = contextPacket;
  dataToolsOriginalInputBytes = payloadBytes;
  dataToolsInputEditedFlag = false;
  clearDataToolsStreamPackets();
  dataToolsLastConversionBytes = payloadBytes;
  inputEl.value = formatHexInputBytesWithCap(payloadBytes);
  formatEl.value = "hex";
  setDataToolsFileNameGuess("");
  markDataToolsInputCommitted();
  showDataTools();
  runDataToolsConversion();
  writeLogEntry("Context conversion loaded raw payload into Conv tab");
}

async function loadActiveConvInputDecompressedFromContextMenu() {
  const contextPacket = getCurrentContextPacket();
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
  dataToolsContextPacket = contextPacket;
  dataToolsOriginalInputBytes = decompressedCandidate.bytes;
  dataToolsInputEditedFlag = false;
  clearDataToolsStreamPackets();
  dataToolsLastConversionBytes = decompressedCandidate.bytes;
  inputEl.value = formatHexInputBytesWithCap(decompressedCandidate.bytes);
  formatEl.value = "hex";
  setDataToolsFileNameGuess("");
  markDataToolsInputCommitted();
  showDataTools();
  runDataToolsConversion();
  writeLogEntry(
    `Context conversion decompressed Conv input algorithm=${decompressedCandidate.algorithm}`,
  );
}

// Returns cursor ascii context load data.
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

// Loads cursor ascii into data tools from context menu.
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
  dataToolsOriginalInputBytes = null;
  dataToolsInputEditedFlag = true;
  clearDataToolsStreamPackets();
  inputEl.value = cursorAsciiLoadData.value;
  formatEl.value = cursorAsciiLoadData.format;
  setDataToolsFileNameGuess("");
  markDataToolsInputCommitted();
  showDataTools();
  runDataToolsConversion();
  writeLogEntry(
    `Context conversion loaded cursor ASCII into Conv tab format=${cursorAsciiLoadData.format}`,
  );
}

// Returns active packet cursor.
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
  if (
    totalPacketCountCache
    && totalPacketCountCache.version === packetNavigationCacheVersion
  ) {
    return totalPacketCountCache.value;
  }
  const hosts = capturedPackets?.["host"];
  if (!hosts || typeof hosts !== "object") {
    totalPacketCountCache = {
      version: packetNavigationCacheVersion,
      value: 0,
    };
    return 0;
  }
  const computedCount = Object.values(hosts).reduce(
    (sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0),
    0,
  );
  totalPacketCountCache = {
    version: packetNavigationCacheVersion,
    value: computedCount,
  };
  return computedCount;
}

// Minimum total-packet count that triggers the stream-loading overlay.
// getFollowStreamPackets() iterates every packet across all hosts, so captures
// with ~500+ packets produce a noticeable pause without the overlay.
const STREAM_LOADING_THRESHOLD = 10;
const STREAM_ASYNC_PACKET_YIELD_INTERVAL = 2000;
const STREAM_ASYNC_HEX_YIELD_INTERVAL = 200;
const STREAM_ASYNC_HYDRATE_YIELD_INTERVAL = 25;
const INGESTION_INDEX_YIELD_INTERVAL_BASE = 2000;
const INGESTION_INDEX_YIELD_INTERVAL_BACKLOG = 8000;
const INGESTION_DEFERRED_BACKLOG_THRESHOLD = 3;
const INGESTION_DEFERRED_BACKLOG_DECAY_MS = 15000;

// Handles yield to renderer.
function yieldToRenderer() {
  if (typeof window !== "undefined" && typeof window.requestAnimationFrame === "function") {
    return new Promise((resolve) => {
      window.requestAnimationFrame(() => resolve());
    });
  }
  return new Promise((resolve) => setTimeout(resolve, 0));
}

// Returns current ingestion yield interval, increasing while deferred backlog is active.
function getIngestionIndexYieldInterval() {
  if (!deferredIngestionBacklogState.active) {
    return INGESTION_INDEX_YIELD_INTERVAL_BASE;
  }

  const nowMs = performance.now();
  if (
    deferredIngestionBacklogState.lastDeferredAtMs > 0
    && nowMs - deferredIngestionBacklogState.lastDeferredAtMs
    > INGESTION_DEFERRED_BACKLOG_DECAY_MS
  ) {
    deferredIngestionBacklogState.active = false;
    deferredIngestionBacklogState.deferredCount = 0;
    deferredIngestionBacklogState.lastDeferredAtMs = 0;
    return INGESTION_INDEX_YIELD_INTERVAL_BASE;
  }

  return INGESTION_INDEX_YIELD_INTERVAL_BACKLOG;
}

// Updates deferred backlog state from ingestion chunk phase transitions.
function updateDeferredIngestionBacklogState(phase, payload, extra = {}) {
  if (
    Boolean(payload?.complete)
    || phase === "first-chunk-applied"
    || phase === "final-chunk-applied"
  ) {
    deferredIngestionBacklogState.active = false;
    deferredIngestionBacklogState.deferredCount = 0;
    deferredIngestionBacklogState.lastDeferredAtMs = 0;
    return;
  }

  if (phase !== "deferred") {
    return;
  }

  const reason = typeof extra?.reason === "string" ? extra.reason : "";
  if (reason !== "waiting-for-complete" && reason !== "waiting-for-minimum-chunk") {
    return;
  }

  deferredIngestionBacklogState.deferredCount += 1;
  deferredIngestionBacklogState.lastDeferredAtMs = performance.now();
  if (deferredIngestionBacklogState.deferredCount >= INGESTION_DEFERRED_BACKLOG_THRESHOLD) {
    deferredIngestionBacklogState.active = true;
  }
}

// Returns a rounded ingestion duration in milliseconds.
function formatIngestionDurationMs(durationMs) {
  const normalized = Number(durationMs);
  if (!Number.isFinite(normalized) || normalized < 0) {
    return 0;
  }
  return Number(normalized.toFixed(2));
}

// Returns whether ingestion chunk timing log should emit for this phase.
function shouldEmitIngestionChunkTimingLog(kind, phase, payload, extra = {}) {
  const phaseKey = `${kind}:${phase}`;
  const nowMs = performance.now();
  const processedPackets = Number(payload?.processedPackets) || 0;
  const reason = typeof extra?.reason === "string" ? extra.reason : "";
  const state = ingestionChunkLogState.get(phaseKey) || null;
  const alwaysLogPhases = new Set([
    "first-chunk-applied",
    "final-chunk-applied",
  ]);
  if (alwaysLogPhases.has(phase)) {
    ingestionChunkLogState.set(phaseKey, {
      nowMs,
      processedPackets,
      reason,
    });
    return true;
  }

  if (!state) {
    ingestionChunkLogState.set(phaseKey, {
      nowMs,
      processedPackets,
      reason,
    });
    return true;
  }

  const elapsedMs = Math.max(0, nowMs - (state.nowMs || 0));
  const packetDelta = Math.max(0, processedPackets - (state.processedPackets || 0));
  const reasonChanged = reason !== (state.reason || "");
  const shouldLog =
    reasonChanged || elapsedMs >= 1500 || packetDelta >= 2000 || Boolean(payload?.complete);

  if (shouldLog) {
    ingestionChunkLogState.set(phaseKey, {
      nowMs,
      processedPackets,
      reason,
    });
  }

  return shouldLog;
}

// Logs per-chunk ingestion timing and packet progress.
function logIngestionChunkTiming(kind, phase, payload, durationMs, extra = {}) {
  updateDeferredIngestionBacklogState(phase, payload, extra);
  if (!shouldEmitIngestionChunkTimingLog(kind, phase, payload, extra)) {
    return;
  }
  const processed = Number(payload?.processedPackets) || 0;
  const total = Number(payload?.totalPackets) || 0;
  const complete = Boolean(payload?.complete);
  const durationRounded = formatIngestionDurationMs(durationMs);
  const detailPairs = Object.entries(extra)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(" ");
  const detailSuffix = detailPairs ? ` ${detailPairs}` : "";
  writeLogEntry(
    `Ingestion chunk kind=${kind} phase=${phase} processed=${processed} total=${total} complete=${complete} duration_ms=${durationRounded}${detailSuffix}`,
  );
}

// Caches packet stubs for a host packet array in yield-friendly batches.
async function cachePacketStubsForHost(
  host,
  hostPackets,
  options = {},
) {
  const {
    startIndex = 0,
    yieldInterval = null,
  } = options;
  if (!Array.isArray(hostPackets) || !hostPackets.length) {
    return 0;
  }

  const safeStartIndex = Math.max(0, Number(startIndex) || 0);
  const effectiveYieldInterval = Number.isFinite(Number(yieldInterval)) && Number(yieldInterval) > 0
    ? Math.floor(Number(yieldInterval))
    : getIngestionIndexYieldInterval();
  let indexedCount = 0;

  for (let packetIndex = safeStartIndex; packetIndex < hostPackets.length; packetIndex += 1) {
    const packet = hostPackets[packetIndex];
    const packetKey = getPacketKey(packet, host, packetIndex);
    if (packet && typeof packet === "object") {
      packet.__packetKey = packetKey;
    }
    cachePacketStub(packetKey, packet);
    indexedCount += 1;

    if (effectiveYieldInterval > 0 && indexedCount % effectiveYieldInterval === 0) {
      await yieldToRenderer();
    }
  }

  return indexedCount;
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

// Handles request follow stream context menu load.
function requestFollowStreamContextMenuLoad(tabLabel, packetCount) {
  const dialogEl = document.getElementById("follow-stream-confirm-dialog");
  const descriptionEl = document.getElementById("follow-stream-confirm-description");
  const continueBtnEl = document.getElementById(
    "follow-stream-confirm-continue-btn",
  );
  if (!dialogEl || !descriptionEl) {
    return Promise.resolve(
      window.confirm(
        `This stream contains ${packetCount} packets. Loading it into the ${tabLabel} tab can consume significant memory and may bog down the UI.\n\nContinue?`,
      ),
    );
  }
  if (activeFollowStreamConfirmDialogResolver) {
    const resolve = activeFollowStreamConfirmDialogResolver;
    activeFollowStreamConfirmDialogResolver = null;
    resolve(false);
  }
  descriptionEl.textContent = `This stream contains ${packetCount} packets. Loading it into the ${tabLabel} tab can consume significant memory and may bog down the UI. Continue?`;
  dialogEl.hidden = false;
  if (continueBtnEl) continueBtnEl.focus();
  return new Promise((resolve) => {
    activeFollowStreamConfirmDialogResolver = resolve;
  });
}

// Handles resolve follow stream context menu load.
function resolveFollowStreamContextMenuLoad(shouldContinue) {
  const dialogEl = document.getElementById("follow-stream-confirm-dialog");
  if (dialogEl) dialogEl.hidden = true;
  if (!activeFollowStreamConfirmDialogResolver) return;
  const resolve = activeFollowStreamConfirmDialogResolver;
  activeFollowStreamConfirmDialogResolver = null;
  resolve(Boolean(shouldContinue));
}

async function confirmFollowStreamContextMenuLoad(tabLabel, packetCount) {
  if (packetCount <= getStreamContextWarnPacketThreshold()) return true;
  return requestFollowStreamContextMenuLoad(tabLabel, packetCount);
}

// Handles request manual conv import warning load.
function requestManualConvImportWarningLoad({
  fileName,
  fileSize,
  warningThreshold,
}) {
  const dialogEl = document.getElementById("manual-conv-import-warning-dialog");
  const descriptionEl = document.getElementById(
    "manual-conv-import-warning-description",
  );
  const continueBtnEl = document.getElementById(
    "manual-conv-import-warning-continue-btn",
  );
  if (!dialogEl || !descriptionEl) {
    return Promise.resolve(
      window.confirm(
        `${fileName || "This file"} is ${formatByteCount(fileSize)}. Files above ${formatByteCount(warningThreshold)} trigger a warning for the current import limit. Loading large files into Conv can consume significant memory and may bog down the UI.\n\nContinue?`,
      ),
    );
  }
  if (activeManualConvImportWarningDialogResolver) {
    const resolve = activeManualConvImportWarningDialogResolver;
    activeManualConvImportWarningDialogResolver = null;
    resolve(false);
  }
  descriptionEl.textContent = `${fileName || "This file"} is ${formatByteCount(fileSize)}. Files above ${formatByteCount(warningThreshold)} trigger a warning for the current import limit. Loading large files into Conv can consume significant memory and may bog down the UI. Continue?`;
  dialogEl.hidden = false;
  if (continueBtnEl) continueBtnEl.focus();
  return new Promise((resolve) => {
    activeManualConvImportWarningDialogResolver = resolve;
  });
}

// Handles resolve manual conv import warning load.
function resolveManualConvImportWarningLoad(shouldContinue) {
  const dialogEl = document.getElementById("manual-conv-import-warning-dialog");
  if (dialogEl) dialogEl.hidden = true;
  if (!activeManualConvImportWarningDialogResolver) return;
  const resolve = activeManualConvImportWarningDialogResolver;
  activeManualConvImportWarningDialogResolver = null;
  resolve(Boolean(shouldContinue));
}

// Handles request settings reset confirmation.
function requestSettingsResetConfirm() {
  const dialogEl = document.getElementById("settings-reset-confirm-dialog");
  const descriptionEl = document.getElementById("settings-reset-confirm-description");
  const continueBtnEl = document.getElementById("settings-reset-confirm-continue-btn");
  if (!dialogEl || !descriptionEl) {
    return Promise.resolve(
      window.confirm(
        "This will reset all settings to their default values. Any unsaved changes will be lost. Continue?",
      ),
    );
  }
  if (activeSettingsResetConfirmDialogResolver) {
    const resolve = activeSettingsResetConfirmDialogResolver;
    activeSettingsResetConfirmDialogResolver = null;
    resolve(false);
  }
  descriptionEl.textContent =
    "This will reset all settings to their default values. Any unsaved changes will be lost. Continue?";
  dialogEl.hidden = false;
  if (continueBtnEl) continueBtnEl.focus();
  return new Promise((resolve) => {
    activeSettingsResetConfirmDialogResolver = resolve;
  });
}

// Handles resolve settings reset confirmation.
function resolveSettingsResetConfirm(shouldContinue) {
  const dialogEl = document.getElementById("settings-reset-confirm-dialog");
  if (dialogEl) dialogEl.hidden = true;
  if (!activeSettingsResetConfirmDialogResolver) return;
  const resolve = activeSettingsResetConfirmDialogResolver;
  activeSettingsResetConfirmDialogResolver = null;
  resolve(Boolean(shouldContinue));
}

// Returns stream tuple for packet.
function getTransportProtocolName(packetInfo) {
  const rawProtocol = String(
    packetInfo?.["packet.proto"] ?? packetInfo?.["Protocol"] ?? "",
  )
    .trim()
    .toUpperCase();
  if (rawProtocol) return rawProtocol;
  if (packetInfo?.TCP && typeof packetInfo.TCP === "object") return "TCP";
  if (packetInfo?.UDP && typeof packetInfo.UDP === "object") return "UDP";
  if (packetInfo?.SCTP && typeof packetInfo.SCTP === "object") return "SCTP";
  return "TCP";
}

function getTransportDataForPacketInfo(packetInfo, protocolName = "") {
  if (!packetInfo || typeof packetInfo !== "object") return {};
  const normalizedProtocol = String(protocolName || "").trim();
  const candidates = [
    normalizedProtocol,
    normalizedProtocol.toUpperCase(),
    normalizedProtocol.toLowerCase(),
    "TCP",
    "UDP",
    "SCTP",
  ].filter(Boolean);

  for (const candidate of candidates) {
    const transportData = packetInfo[candidate];
    if (transportData && typeof transportData === "object") {
      return transportData;
    }
  }
  return {};
}

function getStreamTupleForPacket(packet) {
  const packetInfo = packet?.["packet.info"];
  if (!packetInfo) return null;
  const srcIp = packetInfo["IP"]?.["ip.src.addr"] ?? packetInfo["IP"]?.["Source IP"];
  const dstIp = packetInfo["IP"]?.["ip.dst.addr"] ?? packetInfo["IP"]?.["Destination IP"];
  const protocol = getTransportProtocolName(packetInfo);
  const transportData = getTransportDataForPacketInfo(packetInfo, protocol);
  const srcPort =
    transportData["tcp.src.port"] ??
    transportData["udp.src.port"] ??
    transportData["sctp.src.port"] ??
    transportData["Source port"] ??
    null;
  const dstPort =
    transportData["tcp.dst.port"] ??
    transportData["udp.dst.port"] ??
    transportData["sctp.dst.port"] ??
    transportData["Destination port"] ??
    null;
  if (!srcIp || !dstIp) return null;
  return { srcIp, srcPort, dstIp, dstPort, protocol };
}

/**
 * Returns metadata about the current packet's stream (4-tuple: srcIp, srcPort,
 * dstIp, dstPort, protocol), or null if no current packet is loaded.
 */
function getCurrentStreamTuple() {
  return getStreamTupleForPacket(getCurrentPacketForExport());
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
  const hosts = capturedPackets?.["host"];
  if (!hosts || typeof hosts !== "object") return [];
  for (const host of Object.values(hosts)) {
    if (!Array.isArray(host)) continue;
    for (const pkt of host) {
      const pi = pkt?.["packet.info"];
      if (!pi) continue;
      const pProto = getTransportProtocolName(pi);
      if (pProto !== protocol) continue;
      const pSrcIp = pi["IP"]?.["ip.src.addr"] ?? pi["IP"]?.["Source IP"];
      const pDstIp = pi["IP"]?.["ip.dst.addr"] ?? pi["IP"]?.["Destination IP"];
      if (!pSrcIp || !pDstIp) continue;
      const pTransport = getTransportDataForPacketInfo(pi, pProto);
      const pSrcPort =
        pTransport["tcp.src.port"] ??
        pTransport["udp.src.port"] ??
        pTransport["sctp.src.port"] ??
        pTransport["Source port"] ??
        null;
      const pDstPort =
        pTransport["tcp.dst.port"] ??
        pTransport["udp.dst.port"] ??
        pTransport["sctp.dst.port"] ??
        pTransport["Destination port"] ??
        null;
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
  const hosts = capturedPackets?.["host"];
  if (!hosts || typeof hosts !== "object") return [];

  let scannedPacketCount = 0;
  for (const host of Object.values(hosts)) {
    if (!Array.isArray(host)) continue;
    for (const pkt of host) {
      const pi = pkt?.["packet.info"];
      if (!pi) {
        scannedPacketCount += 1;
        if (scannedPacketCount % STREAM_ASYNC_PACKET_YIELD_INTERVAL === 0) {
          await yieldToRenderer();
        }
        continue;
      }

      const pProto = getTransportProtocolName(pi);
      if (pProto === protocol) {
        const pSrcIp = pi["IP"]?.["ip.src.addr"] ?? pi["IP"]?.["Source IP"];
        const pDstIp = pi["IP"]?.["ip.dst.addr"] ?? pi["IP"]?.["Destination IP"];
        if (pSrcIp && pDstIp) {
          const pTransport = getTransportDataForPacketInfo(pi, pProto);
          const pSrcPort =
            pTransport["tcp.src.port"] ??
            pTransport["udp.src.port"] ??
            pTransport["sctp.src.port"] ??
            pTransport["Source port"] ??
            null;
          const pDstPort =
            pTransport["tcp.dst.port"] ??
            pTransport["udp.dst.port"] ??
            pTransport["sctp.dst.port"] ??
            pTransport["Destination port"] ??
            null;
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
  const cacheKey = buildStreamPayloadHexCacheKey(streamPackets);
  if (cacheKey && streamPayloadHexCache.has(cacheKey)) {
    return streamPayloadHexCache.get(cacheKey) || null;
  }
  let combined = "";
  for (const pkt of streamPackets) {
    const payloadHex =
      pkt?.["packet.info"]?.["Raw data"]?.["Payload"]?.["payload.hex"] ??
      pkt?.["packet.info"]?.["Raw data"]?.["Payload"]?.["Hex Encoded"];
    if (typeof payloadHex === "string" && payloadHex.length > 0) {
      combined += payloadHex;
    }
  }
  const streamHex = combined || null;
  if (cacheKey && streamHex) {
    setStreamPayloadHexCache(cacheKey, streamHex);
  }
  return streamHex;
}

async function buildStreamHexAsync(streamPackets) {
  if (!streamPackets.length) return null;
  const cacheKey = buildStreamPayloadHexCacheKey(streamPackets);
  if (cacheKey && streamPayloadHexCache.has(cacheKey)) {
    return streamPayloadHexCache.get(cacheKey) || null;
  }
  const parts = [];
  let scanned = 0;
  for (const pkt of streamPackets) {
    const payloadHex =
      pkt?.["packet.info"]?.["Raw data"]?.["Payload"]?.["payload.hex"] ??
      pkt?.["packet.info"]?.["Raw data"]?.["Payload"]?.["Hex Encoded"];
    if (typeof payloadHex === "string" && payloadHex.length > 0) {
      parts.push(payloadHex);
    }
    scanned += 1;
    if (scanned % STREAM_ASYNC_HEX_YIELD_INTERVAL === 0) {
      await yieldToRenderer();
    }
  }
  const streamHex = parts.length ? parts.join("") : null;
  if (cacheKey && streamHex) {
    setStreamPayloadHexCache(cacheKey, streamHex);
  }
  return streamHex;
}

// Handles align to4.
function alignTo4(value) {
  return (value + 3) & ~3;
}

// Handles bytes to hex string.
function bytesToHexString(bytes) {
  return Array.from(bytes || [])
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Formats bytes for the Conv input textarea, capping display at 8 KB to
// keep large payloads responsive. The full Uint8Array remains in memory.
function formatHexInputBytesWithCap(bytes) {
  const displayBytes = (bytes || []).slice(0, DATA_TOOLS_INPUT_DISPLAY_MAX_BYTES);
  let normalized = formatHexInputBytes(displayBytes);
  if ((bytes || []).length > DATA_TOOLS_INPUT_DISPLAY_MAX_BYTES) {
    normalized +=
      `\n\n[Input truncated for display. ${(bytes || []).length.toLocaleString()} bytes total; only ${DATA_TOOLS_INPUT_DISPLAY_MAX_BYTES.toLocaleString()} bytes shown.]`;
  }
  return normalized;
}

// Handles hex string to Uint8Array.
function hexStringToUint8Array(hexString) {
  const normalized = String(hexString || "").replace(/\s+/g, "");
  if (normalized.length === 0 || normalized.length % 2 !== 0) {
    return new Uint8Array();
  }
  if (!/^[\da-fA-F]+$/.test(normalized)) {
    return new Uint8Array();
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = parseInt(normalized.slice(i, i + 2), 16);
  }
  return bytes;
}

// Returns packet payload hex.
function getPacketPayloadHex(packet) {
  return getPacketInfoPayloadHex(packet?.["packet.info"]);
}

// Returns packet.info payload hex across supported schema variants.
function getPacketInfoPayloadHex(packetInfo) {
  const candidates = [
    packetInfo?.["raw.data"]?.["payload"]?.["payload.hex"],
    packetInfo?.["raw.data"]?.["payload"]?.["hex.encoded"],
    packetInfo?.["raw.data"]?.["payload.hex"],
    packetInfo?.["raw.data"]?.["Payload"]?.["payload.hex"],
    packetInfo?.["raw.data"]?.["payload.hex.encoded"],
    packetInfo?.["Raw data"]?.["Payload"]?.["payload.hex"],
    packetInfo?.["Raw data"]?.["Payload"]?.["Hex Encoded"],
    packetInfo?.["Raw data"]?.["Payload"]?.["hex.encoded"],
    packetInfo?.["Raw data"]?.["payload.hex"],
    packetInfo?.["Raw data"]?.["payload.hex.encoded"],
  ];

  for (const candidate of candidates) {
    if (typeof candidate !== "string") continue;
    const trimmed = candidate.trim();
    if (trimmed) return trimmed;
  }

  return "";
}

// Returns packet.info payload length with hex-derived fallback.
function getPacketInfoPayloadLength(packetInfo) {
  const payloadLengthRaw = Number(
    packetInfo?.["raw.data"]?.["payload.len"] ??
    packetInfo?.["Raw data"]?.["payload.len"] ??
    packetInfo?.["Raw data"]?.["Payload Length"],
  );
  if (Number.isFinite(payloadLengthRaw) && payloadLengthRaw > 0) {
    return Math.floor(payloadLengthRaw);
  }

  const payloadHex = getPacketInfoPayloadHex(packetInfo);
  if (payloadHex) {
    return Math.floor(payloadHex.replace(/\s+/g, "").length / 2);
  }

  return 0;
}

// Returns packet payload bytes.
function getPacketPayloadBytes(packet) {
  const payloadHex = getPacketPayloadHex(packet);
  if (!payloadHex) return null;
  try {
    return parseDataToolsInput("hex", payloadHex);
  } catch {
    return null;
  }
}

// Returns packet transport data.
function getPacketTransportData(packet) {
  const packetInfo = packet?.["packet.info"];
  if (!packetInfo) return null;
  const protocol = getTransportProtocolName(packetInfo);
  return getTransportDataForPacketInfo(packetInfo, protocol);
}

// Builds bidirectional stream key.
function buildBidirectionalStreamKey(packetInfo) {
  if (!packetInfo || typeof packetInfo !== "object") return "";
  const transportName = getTransportProtocolName(packetInfo);
  const transportData = getTransportDataForPacketInfo(packetInfo, transportName);
  const sourceIp = packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"] ?? "";
  const destinationIp = packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"] ?? "";
  const sourcePort =
    transportData?.["tcp.src.port"] ??
    transportData?.["udp.src.port"] ??
    transportData?.["sctp.src.port"] ??
    transportData?.["Source port"] ??
    "";
  const destinationPort =
    transportData?.["tcp.dst.port"] ??
    transportData?.["udp.dst.port"] ??
    transportData?.["sctp.dst.port"] ??
    transportData?.["Destination port"] ??
    "";

  const endpointA = `${sourceIp}:${sourcePort}`;
  const endpointB = `${destinationIp}:${destinationPort}`;
  const [firstEndpoint, secondEndpoint] = [endpointA, endpointB].sort();
  return `${transportName}|${firstEndpoint}|${secondEndpoint}`;
}

// Parses tcp sequence number.
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

// Returns tcp segment length.
function getTcpSegmentLength(packetInfo, transportData) {
  const payloadLen = getPacketInfoPayloadLength(packetInfo);

  const flagsText = String(transportData?.["TCP Flag Data"]?.["Flags"] || "").toUpperCase();
  const controlByteLength =
    (flagsText.includes("SYN") ? 1 : 0) + (flagsText.includes("FIN") ? 1 : 0);
  return payloadLen + controlByteLength;
}

// Handles merge sequence range.
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

// Returns sequence range overlap length.
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

// Returns tcp stream arrival status by packet key.
function getTcpStreamArrivalStatusByPacketKey(streamPackets) {
  const statusByPacketKey = new Map();
  if (!Array.isArray(streamPackets) || streamPackets.length === 0) {
    return statusByPacketKey;
  }

  const streamStateByDirection = new Map();
  streamPackets.forEach((packet) => {
    const packetInfo = packet?.["packet.info"] || {};
    const protocol = String(packetInfo["packet.proto"] ?? packetInfo["Protocol"] ?? "").toUpperCase();
    const packetKey = getPacketKey(packet);
    if (!packetKey || protocol !== "TCP") return;

    const transportData = packetInfo["TCP"] || {};
    const sourceIp = (packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"]) || "";
    const destinationIp = (packetInfo?.["IP"]?.["ip.dst.addr"] ?? packetInfo?.["IP"]?.["Destination IP"]) || "";
    const sourcePort = transportData?.["tcp.src.port"] ?? transportData?.["Source port"] ?? "";
    const destinationPort = transportData?.["tcp.dst.port"] ?? transportData?.["Destination port"] ?? "";
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

// Handles read uint32 le.
function readUint32Le(bytes, offset) {
  if (!bytes || offset < 0 || offset + 4 > bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(offset, true);
}

// Handles read uint16 le.
function readUint16Le(bytes, offset) {
  if (!bytes || offset < 0 || offset + 2 > bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint16(offset, true);
}

// Handles read uint32 be.
function readUint32Be(bytes, offset) {
  if (!bytes || offset < 0 || offset + 4 > bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(offset, false);
}

// Handles read uint64 le number.
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

// Handles read uint64 be number.
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

// Handles read uint64 le hex.
function readUint64LeHex(bytes, offset) {
  if (!bytes || offset < 0 || offset + 8 > bytes.length) return "";
  return bytesToHexString(bytes.slice(offset, offset + 8).reverse());
}

// Handles decode utf16 le.
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

// Handles sanitize carve filename.
function sanitizeCarveFilename(name) {
  const raw = String(name || "").trim();
  if (!raw) return "";
  const parts = raw.split(/[\\/]/).filter(Boolean);
  const leaf = parts.length ? parts[parts.length - 1] : raw;
  return leaf.replace(/[\u0000-\u001f<>:"|?*]/g, "_").trim();
}

const CARVE_PGP_PRIVATE_KEY_REGEX =
  /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/i;
const CARVE_PEM_PRIVATE_KEY_REGEX =
  /-----BEGIN (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/i;
const CARVE_OPENSSH_PRIVATE_KEY_REGEX =
  /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/i;
const CARVE_SECRET_FILE_HINT_REGEX =
  /(password|passphrase|secret|token|api[_-]?key|private[_-]?key)\s*(?:=|:)/i;

// Detects sensitive carve entry.
function detectSensitiveCarveEntry(candidate, protocolLabel) {
  if (!candidate || !(candidate.bytes instanceof Uint8Array)) return null;
  if (candidate.bytes.length === 0) return null;

  const sourceLabel = `${String(protocolLabel || "CARVE").toLowerCase()}-file-carve`;
  const fileName = String(candidate.fileName || "carved.bin").trim();
  const fileNameLower = fileName.toLowerCase();
  const textSample = Buffer.from(candidate.bytes.slice(0, 1024 * 1024)).toString("utf8");
  const normalizedSample = String(textSample || "").trim();

  const pgpPrivateKeyMatch = normalizedSample.match(CARVE_PGP_PRIVATE_KEY_REGEX);
  if (pgpPrivateKeyMatch?.[0]) {
    return {
      type: "private-key",
      label: `PGP Private Key (${fileName})`,
      source: sourceLabel,
      content: String(pgpPrivateKeyMatch[0]).trim(),
      summary: `Auto-detected PGP private key from carved ${protocolLabel} stream`,
    };
  }

  const pemPrivateKeyMatch = normalizedSample.match(CARVE_PEM_PRIVATE_KEY_REGEX);
  if (pemPrivateKeyMatch?.[0]) {
    return {
      type: "private-key",
      label: `Private Key (${fileName})`,
      source: sourceLabel,
      content: String(pemPrivateKeyMatch[0]).trim(),
      summary: `Auto-detected private key from carved ${protocolLabel} stream`,
    };
  }

  const opensshPrivateKeyMatch = normalizedSample.match(CARVE_OPENSSH_PRIVATE_KEY_REGEX);
  if (opensshPrivateKeyMatch?.[0]) {
    return {
      type: "private-key",
      label: `OpenSSH Private Key (${fileName})`,
      source: sourceLabel,
      content: String(opensshPrivateKeyMatch[0]).trim(),
      summary: `Auto-detected OpenSSH private key from carved ${protocolLabel} stream`,
    };
  }

  const looksLikeSecretFile =
    CARVE_SECRET_FILE_HINT_REGEX.test(normalizedSample) ||
    [".env", ".ini", ".cfg", ".conf", ".json", ".yaml", ".yml", ".txt"].some(
      (suffix) => fileNameLower.endsWith(suffix),
    );
  if (looksLikeSecretFile && CARVE_SECRET_FILE_HINT_REGEX.test(normalizedSample)) {
    return {
      type: "secret",
      label: `Sensitive Data (${fileName})`,
      source: sourceLabel,
      content: normalizedSample.slice(0, 8192),
      summary: `Auto-detected sensitive data from carved ${protocolLabel} stream`,
    };
  }

  return null;
}

// Handles add segment to entry.
function addSegmentToEntry(entry, offset, bytes) {
  if (!entry || !Number.isInteger(offset) || offset < 0) return;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return;
  entry.segments.push({ offset, bytes });
}

// Handles assemble segments.
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

function isSmbNamedPipePath(filePath) {
  const normalizedPath = String(filePath || "")
    .replace(/\//g, "\\")
    .trim()
    .toUpperCase();
  if (!normalizedPath) return false;
  return (
    normalizedPath.startsWith("\\PIPE\\") ||
    normalizedPath.includes("\\PIPE\\") ||
    normalizedPath.includes("IPC$")
  );
}

// Extracts smb file candidates.
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
    const payload = normalizeSmbDecoderBytes(getPacketPayloadBytes(packet));
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
          if (cleanedName && !isSmbNamedPipePath(cleanedName)) {
            createRequestByMessageId.set(messageId, cleanedName);
          }
        }
      } else {
        if (payload.length < 144) return;
        const fileId = bytesToHexString(payload.slice(128, 144));
        if (!fileId) return;
        const fileName = createRequestByMessageId.get(messageId) || "";
        if (fileName && isSmbNamedPipePath(fileName)) return;
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
      if (fileIdToName.has(fileId) && isSmbNamedPipePath(fileIdToName.get(fileId))) {
        return;
      }
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
        // SMB2 READ request body offsets (after 64-byte SMB2 header):
        // StructureSize(2) + Padding(1) + Flags(1) + Length(4) + Offset(8) + FileId(16)
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
      if (
        fileIdToName.has(readRequest.fileId) &&
        isSmbNamedPipePath(fileIdToName.get(readRequest.fileId))
      ) {
        return;
      }
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
    if (isSmbNamedPipePath(entry.name)) continue;
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
    if (
      (packetIndex + 1) % STREAM_ASYNC_HYDRATE_YIELD_INTERVAL === 0 &&
      packetIndex + 1 < packetList.length
    ) {
      await yieldToRenderer();
    }
  }
  return hydratedPackets;
}

// Parses rpc base offset.
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

// Parses rpc call args offset.
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

// Parses rpc reply results offset.
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

// Parses rpc opaque.
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

// Extracts nfs file candidates.
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

// Parses ftp active mode data port.
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

// Parses ftp passive mode data port.
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

// Returns ftp control roles from stream tuple.
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

// Extracts ftp transfer context from control stream.
function extractFtpTransferContextFromControlStream(
  streamPackets,
  {
    referenceTimestamp = null,
    requiredDataPorts = null,
  } = {},
) {
  if (!Array.isArray(streamPackets) || streamPackets.length === 0) {
    return {
      hasControlMetadata: false,
      transferCommand: "",
      transferName: "",
      transferTimestamp: null,
      candidateDataPorts: new Set(),
    };
  }

  const normalizedReferenceTimestamp = Number.isFinite(referenceTimestamp)
    ? referenceTimestamp
    : null;
  const requiredPortSet = requiredDataPorts instanceof Set
    ? requiredDataPorts
    : new Set(
      Array.isArray(requiredDataPorts)
        ? requiredDataPorts.filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535)
        : [],
    );

  let hasControlMetadata = false;
  let pendingDataPorts = new Set();
  const transfers = [];

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
        pendingDataPorts = activePort ? new Set([activePort]) : new Set();
        return;
      }

      if (["RETR", "STOR", "APPE", "LIST", "NLST"].includes(command)) {
        const packetTs = parsePacketTimestampMs(packet);
        transfers.push({
          transferCommand: command,
          transferName: command === "LIST" || command === "NLST" ? "" : argument,
          transferTimestamp: Number.isFinite(packetTs) ? packetTs : null,
          candidateDataPorts: new Set(pendingDataPorts),
        });
        pendingDataPorts = new Set();
      }
      return;
    }

    if (ftpType === "response") {
      const statusCode = String(
        ftpData["ftp.status_code"] ?? ftpData["Status Code"] ?? "",
      ).trim();
      if (statusCode === "227" || statusCode === "229") {
        const passivePort = parseFtpPassiveModeDataPort(
          ftpData["Message"] ?? ftpData["ftp.message"],
        );
        pendingDataPorts = passivePort ? new Set([passivePort]) : new Set();
      }
    }
  });

  if (transfers.length === 0) {
    return {
      hasControlMetadata,
      transferCommand: "",
      transferName: "",
      transferTimestamp: null,
      candidateDataPorts: new Set(),
    };
  }

  let matchingTransfers = transfers.filter((transfer) => {
    if (requiredPortSet.size === 0 || transfer.candidateDataPorts.size === 0) return true;
    return Array.from(transfer.candidateDataPorts).some((port) => requiredPortSet.has(port));
  });
  if (matchingTransfers.length === 0) matchingTransfers = transfers;

  if (normalizedReferenceTimestamp !== null) {
    const transfersBeforeReference = matchingTransfers.filter((transfer) => {
      if (!Number.isFinite(transfer.transferTimestamp)) return true;
      return transfer.transferTimestamp <= normalizedReferenceTimestamp + 2000;
    });
    if (transfersBeforeReference.length > 0) {
      matchingTransfers = transfersBeforeReference;
    }
  }

  const selectedTransfer = matchingTransfers[matchingTransfers.length - 1] || transfers[transfers.length - 1];
  return {
    hasControlMetadata,
    transferCommand: selectedTransfer?.transferCommand || "",
    transferName: selectedTransfer?.transferName || "",
    transferTimestamp: Number.isFinite(selectedTransfer?.transferTimestamp)
      ? selectedTransfer.transferTimestamp
      : null,
    candidateDataPorts: selectedTransfer?.candidateDataPorts || new Set(),
  };
}

// Handles resolve ftp control stream for data stream.
function resolveFtpControlStreamForDataStream(streamPackets, contextPacket = null) {
  if (!Array.isArray(streamPackets) || streamPackets.length === 0) return null;

  const dataTuple = getStreamTupleForPacket(contextPacket || streamPackets[0]);
  if (!dataTuple) return null;

  const currentStreamKey = buildBidirectionalStreamKey(
    (contextPacket || streamPackets[0])?.["packet.info"] || {},
  );
  const dataPorts = new Set();
  streamPackets.forEach((packet) => {
    const tuple = getStreamTupleForPacket(packet);
    if (!tuple) return;
    const srcPort = Number(tuple.srcPort);
    const dstPort = Number(tuple.dstPort);
    if (Number.isInteger(srcPort) && srcPort >= 1 && srcPort <= 65535) {
      dataPorts.add(srcPort);
    }
    if (Number.isInteger(dstPort) && dstPort >= 1 && dstPort <= 65535) {
      dataPorts.add(dstPort);
    }
  });

  const referenceTimestamp = parsePacketTimestampMs(streamPackets[0]);
  const allPackets = getAllPacketsForHostNavigation();
  const streamMap = new Map();

  allPackets.forEach((packet) => {
    const packetInfo = packet?.["packet.info"];
    const tuple = getStreamTupleForPacket(packet);
    if (!packetInfo || !tuple) return;
    if (String(packetInfo["packet.proto"] ?? packetInfo["Protocol"] ?? "").toUpperCase() !== "TCP") {
      return;
    }

    const hasSameEndpoints =
      (tuple.srcIp === dataTuple.srcIp && tuple.dstIp === dataTuple.dstIp) ||
      (tuple.srcIp === dataTuple.dstIp && tuple.dstIp === dataTuple.srcIp);
    if (!hasSameEndpoints) return;

    const streamKey = buildBidirectionalStreamKey(packetInfo);
    if (!streamKey || streamKey === currentStreamKey) return;

    if (!streamMap.has(streamKey)) {
      streamMap.set(streamKey, []);
    }
    streamMap.get(streamKey).push(packet);
  });

  let bestMatch = null;
  let bestScore = -1;

  streamMap.forEach((packets) => {
    if (!Array.isArray(packets) || packets.length === 0) return;
    packets.sort((left, right) => comparePacketsChronologically(left, right));

    const controlTuple = getStreamTupleForPacket(packets[0]);
    const controlLooksFtp =
      Number(controlTuple?.srcPort) === 21 ||
      Number(controlTuple?.dstPort) === 21 ||
      packets.some((packet) => {
        const transportData = getPacketTransportData(packet);
        return Boolean(transportData?.["FTP"]);
      });
    if (!controlLooksFtp) return;

    const transferContext = extractFtpTransferContextFromControlStream(packets, {
      referenceTimestamp,
      requiredDataPorts: dataPorts,
    });
    if (!transferContext.hasControlMetadata || !transferContext.transferCommand) return;

    const matchedPortCount = Array.from(transferContext.candidateDataPorts).filter((port) =>
      dataPorts.has(port),
    ).length;
    const timeDelta = Number.isFinite(referenceTimestamp) && Number.isFinite(transferContext.transferTimestamp)
      ? Math.abs(referenceTimestamp - transferContext.transferTimestamp)
      : Number.MAX_SAFE_INTEGER;
    const score = matchedPortCount * 1000000 - Math.min(timeDelta, 999999);

    if (score > bestScore) {
      bestScore = score;
      bestMatch = {
        streamPackets: packets,
        transferContext,
      };
    }
  });

  return bestMatch;
}

// Builds ftp candidate from data stream.
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

// Extracts ftp file candidates.
function extractFtpFileCandidates(streamPackets, contextPacket = null) {
  if (!Array.isArray(streamPackets) || streamPackets.length === 0) return [];

  const controlContext = extractFtpTransferContextFromControlStream(streamPackets, {
    referenceTimestamp: parsePacketTimestampMs(contextPacket || streamPackets[0]),
  });
  let hasControlMetadata = controlContext.hasControlMetadata;
  let transferCommand = controlContext.transferCommand;
  let transferName = controlContext.transferName;
  let transferTimestamp = controlContext.transferTimestamp;
  let candidateDataPorts = new Set(controlContext.candidateDataPorts || []);

  if (!hasControlMetadata) {
    const relatedControlStream = resolveFtpControlStreamForDataStream(
      streamPackets,
      contextPacket,
    );
    if (relatedControlStream?.transferContext?.transferCommand) {
      const relatedTuple = getStreamTupleForPacket(
        relatedControlStream.streamPackets?.[0] || null,
      );
      const { clientIp, serverIp } = getFtpControlRolesFromStreamTuple(relatedTuple);
      const carvedCandidate = buildFtpCandidateFromDataStream(streamPackets, {
        transferCommand: relatedControlStream.transferContext.transferCommand,
        transferName: relatedControlStream.transferContext.transferName,
        clientIp,
        serverIp,
      });
      return carvedCandidate ? [carvedCandidate] : [];
    }

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
    (contextPacket || streamPackets[0])?.["packet.info"] || {},
  );
  const allPackets = getAllPacketsForHostNavigation();
  const streamMap = new Map();

  allPackets.forEach((packet) => {
    const packetInfo = packet?.["packet.info"];
    const tuple = getStreamTupleForPacket(packet);
    if (!packetInfo || !tuple) return;
    if (String(packetInfo["packet.proto"] ?? packetInfo["Protocol"] ?? "").toUpperCase() !== "TCP") return;

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

// Builds file carve candidates for protocol.
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

// Returns whether carve current stream for protocol.
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

// Selects carve candidate.
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

  const sensitiveEntry = detectSensitiveCarveEntry(selectedCandidate, protocolLabel);
  if (sensitiveEntry) {
    keystorePanel.addSessionKeystoreEntry(sensitiveEntry);
    if (
      sensitiveEntry.type === "private-key" &&
      CARVE_PGP_PRIVATE_KEY_REGEX.test(String(sensitiveEntry.content || ""))
    ) {
      cryptPanel.refreshPgpPrivateKeyCandidates();
    }
    writeLogEntry(
      `${protocolLabel} carve auto-keystore type=${sensitiveEntry.type} label="${sensitiveEntry.label}"`,
    );
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

const HTTP_FILENAME_EXT_BY_MIME = Object.freeze({
  "application/json": "json",
  "application/pdf": "pdf",
  "application/zip": "zip",
  "application/gzip": "gz",
  "application/x-7z-compressed": "7z",
  "application/x-rar-compressed": "rar",
  "application/xml": "xml",
  "text/plain": "txt",
  "text/html": "html",
  "text/css": "css",
  "text/javascript": "js",
  "text/csv": "csv",
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/gif": "gif",
  "image/webp": "webp",
  "audio/mpeg": "mp3",
  "video/mp4": "mp4",
});

// Extracts filename from content disposition.
function extractFilenameFromContentDisposition(dispositionValue) {
  const rawValue = String(dispositionValue || "").trim();
  if (!rawValue) return "";

  const utf8Match = rawValue.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return sanitizeCarveFilename(decodeURIComponent(utf8Match[1]));
    } catch {
      return sanitizeCarveFilename(utf8Match[1]);
    }
  }

  const quotedMatch = rawValue.match(/filename\s*=\s*"([^"]+)"/i);
  if (quotedMatch?.[1]) {
    return sanitizeCarveFilename(quotedMatch[1]);
  }

  const bareMatch = rawValue.match(/filename\s*=\s*([^;\s]+)/i);
  if (bareMatch?.[1]) {
    return sanitizeCarveFilename(bareMatch[1]);
  }

  return "";
}

// Returns http body filename extension.
function getHttpBodyFilenameExtension(contentTypeValue) {
  const normalizedType = String(contentTypeValue || "")
    .split(";")[0]
    .trim()
    .toLowerCase();
  if (!normalizedType) return "bin";
  return HTTP_FILENAME_EXT_BY_MIME[normalizedType] || "bin";
}

// Extracts the multipart boundary token from a Content-Type header value.
function extractMultipartBoundaryFromContentType(contentTypeValue) {
  const rawValue = String(contentTypeValue || "").trim();
  if (!rawValue) return "";
  if (!rawValue.toLowerCase().includes("multipart")) return "";
  const boundaryMatch = rawValue.match(
    /\bboundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i,
  );
  return boundaryMatch?.[1] || boundaryMatch?.[2] || "";
}

// Extracts a filename from the first Content-Disposition header inside a
// multipart boundary block. The boundary parameter must include the leading
// "--" per RFC 2046.
function extractMultipartFilenameFromBodyBytes(bodyBytes, boundaryToken) {
  if (!bodyBytes || !(bodyBytes instanceof Uint8Array) || bodyBytes.length === 0) {
    return "";
  }
  if (!boundaryToken || typeof boundaryToken !== "string") return "";

  const boundaryBytes = new TextEncoder().encode(`--${boundaryToken}`);
  const searchLimit = Math.min(bodyBytes.length, 8192);
  let boundaryIndex = -1;
  for (let i = 0; i <= searchLimit - boundaryBytes.length; i += 1) {
    let match = true;
    for (let j = 0; j < boundaryBytes.length; j += 1) {
      if (bodyBytes[i + j] !== boundaryBytes[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      boundaryIndex = i;
      break;
    }
  }
  if (boundaryIndex === -1) return "";

  const headerEndLimit = Math.min(
    bodyBytes.length,
    boundaryIndex + 4096,
  );
  const headerBytes = bodyBytes.slice(boundaryIndex, headerEndLimit);
  const headerText = new TextDecoder("utf-8", { fatal: false }).decode(
    headerBytes,
  );
  const firstCrlfCrlf = headerText.indexOf("\r\n\r\n");
  const dispositionText =
    firstCrlfCrlf !== -1 ? headerText.slice(0, firstCrlfCrlf) : headerText;

  const dispositionMatch = dispositionText.match(
    /Content-Disposition\s*:([^\r\n]*)/i,
  );
  if (!dispositionMatch?.[1]) return "";

  return extractFilenameFromContentDisposition(dispositionMatch[1].trim());
}

// Returns the byte range of the first multipart file payload inside a
// multipart body. The returned range is [start, end) where end points to the
// byte before the closing boundary marker.
function findMultipartFileByteRange(bodyBytes, boundaryToken) {
  if (!bodyBytes || !(bodyBytes instanceof Uint8Array) || bodyBytes.length === 0) {
    return null;
  }
  if (!boundaryToken || typeof boundaryToken !== "string") return null;

  const boundaryBytes = new TextEncoder().encode(`--${boundaryToken}`);
  const searchLimit = Math.min(bodyBytes.length, 8192);
  let boundaryIndex = -1;
  for (let i = 0; i <= searchLimit - boundaryBytes.length; i += 1) {
    let match = true;
    for (let j = 0; j < boundaryBytes.length; j += 1) {
      if (bodyBytes[i + j] !== boundaryBytes[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      boundaryIndex = i;
      break;
    }
  }
  if (boundaryIndex === -1) return null;

  const headerEndLimit = Math.min(bodyBytes.length, boundaryIndex + 4096);
  const headerBytes = bodyBytes.slice(boundaryIndex, headerEndLimit);
  const headerText = new TextDecoder("utf-8", { fatal: false }).decode(
    headerBytes,
  );
  const firstCrlfCrlf = headerText.indexOf("\r\n\r\n");
  if (firstCrlfCrlf === -1) return null;

  const payloadStart = boundaryIndex + firstCrlfCrlf + 4;
  if (payloadStart >= bodyBytes.length) return null;

  const closeBoundaryBytes = new TextEncoder().encode(`\r\n--${boundaryToken}`);
  let endBoundaryIndex = -1;
  for (let i = payloadStart; i <= bodyBytes.length - closeBoundaryBytes.length; i += 1) {
    let match = true;
    for (let j = 0; j < closeBoundaryBytes.length; j += 1) {
      if (bodyBytes[i + j] !== closeBoundaryBytes[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      endBoundaryIndex = i;
      break;
    }
  }

  const payloadEnd = endBoundaryIndex !== -1 ? endBoundaryIndex : bodyBytes.length;
  return { start: payloadStart, end: payloadEnd };
}

// Extracts path filename from http data.
function extractPathFilenameFromHttpData(httpData) {
  const requestTarget = String(
    httpData?.["Request URI"] ||
    httpData?.["request.uri"] ||
    httpData?.["URL"] ||
    httpData?.["Uri"] ||
    "",
  ).trim();
  if (!requestTarget) return "";

  let pathText = requestTarget;
  try {
    if (/^https?:\/\//i.test(pathText)) {
      pathText = new URL(pathText).pathname || "";
    }
  } catch {
    // Keep the raw request target when URL parsing fails.
  }

  const cleanPath = pathText.split("?")[0].split("#")[0];
  const parts = cleanPath.split("/").filter(Boolean);
  if (parts.length === 0) return "";
  return sanitizeCarveFilename(parts[parts.length - 1]);
}

// Handles guess http body filename from packet.
function guessHttpBodyFilenameFromPacket(packet, fallbackName = "http-body") {
  const httpData = getCurrentHttpData(packet) || {};
  const contentType = httpData["Content-Type"];
  const multipartBoundary = extractMultipartBoundaryFromContentType(contentType);

  const dispositionName = extractFilenameFromContentDisposition(
    httpData["Content-Disposition"],
  );
  if (dispositionName) return dispositionName;

  if (multipartBoundary) {
    const rawPayloadHex = getCurrentRawPayloadHex(packet);
    const bodyHex = extractHttpBodyHex(rawPayloadHex);
    const bodyBytes = hexStringToUint8Array(bodyHex);
    const multipartName = extractMultipartFilenameFromBodyBytes(
      bodyBytes,
      multipartBoundary,
    );
    if (multipartName) return multipartName;
  }

  const pathName = extractPathFilenameFromHttpData(httpData);
  if (pathName && pathName.includes(".")) return pathName;

  const extension = getHttpBodyFilenameExtension(contentType);
  const fallbackBase = sanitizeCarveFilename(fallbackName) || "http-body";
  if (pathName) {
    if (pathName.includes(".")) return pathName;
    if (extension === "html") return `${pathName}.html`;
    return `${pathName}.${extension}`;
  }
  return `${fallbackBase}.${extension}`;
}

// Loads carved file candidate into conv tab.
function loadCarvedFileCandidateIntoConvTab(candidate) {
  const candidateBytes = candidate?.bytes;
  if (!(candidateBytes instanceof Uint8Array) || candidateBytes.length === 0) {
    statusUpdate("Status: Carved file content is unavailable for Conv load");
    return false;
  }

  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  if (!inputEl || !formatEl) {
    statusUpdate("Status: Conv input fields are unavailable");
    return false;
  }

  dataToolsContextPacket = null;
  dataToolsOriginalInputBytes = candidateBytes;
  dataToolsInputEditedFlag = false;
  clearDataToolsStreamPackets();
  dataToolsLastConversionBytes = candidateBytes;
  inputEl.value = formatHexInputBytesWithCap(candidateBytes);
  formatEl.value = "hex";
  setDataToolsFileNameGuess(candidate.fileName || "");
  markDataToolsInputCommitted();
  showDataTools(CONV_CONVERSIONS_SUBTAB);
  runDataToolsConversion();

  const protocolLabel = String(candidate.protocol || "FILE").toUpperCase();
  statusUpdate(
    `Status: Loaded ${protocolLabel} carved file into Conv (${candidateBytes.length} bytes)`,
  );
  writeLogEntry(
    `Stats carve loaded into Conv protocol=${protocolLabel} file="${candidate.fileName || "unknown"}" bytes=${candidateBytes.length}`,
  );
  return true;
}

async function loadManualFileIntoConvTabFromContextMenu() {
  hideConvertContextMenu();
  if (!window.getfileapi || typeof window.getfileapi.selectManualConvFile !== "function") {
    doError("Manual Conv file import is unavailable.");
    return;
  }

  let selectedFile = null;
  try {
    selectedFile = await window.getfileapi.selectManualConvFile();
  } catch (error) {
    doError("Could not open file picker for Conv import.");
    logErrorEntry("manual-conv-file-picker", error);
    return;
  }

  if (!selectedFile?.base64) {
    statusUpdate("Status: Manual Conv file import cancelled");
    return;
  }

  const fileSize = Number(selectedFile.size) || 0;
  const configuredLimit = getManualConvImportMaxBytes();
  if (fileSize > configuredLimit) {
    const message =
      `Refused manual Conv import for ${selectedFile.fileName || "selected file"}: ` +
      `${formatByteCount(fileSize)} exceeds the configured limit of ${formatByteCount(configuredLimit)}.`;
    doError(message);
    statusUpdate(`Status: ${message}`);
    writeLogEntry(
      `Warning: manual Conv import refused file="${selectedFile.fileName || "unknown"}" bytes=${fileSize} limit=${configuredLimit}`,
    );
    return;
  }

  const largeImportWarningBytes = Math.max(1, Math.floor(configuredLimit / 4));
  if (fileSize > largeImportWarningBytes) {
    const shouldContinue = await requestManualConvImportWarningLoad({
      fileName: selectedFile.fileName || "This file",
      fileSize,
      warningThreshold: largeImportWarningBytes,
    });
    if (!shouldContinue) {
      statusUpdate("Status: Manual Conv file import cancelled after size warning");
      return;
    }
  }

  try {
    const bytes = base64ToUint8Array(selectedFile.base64);
    const inputEl = document.getElementById("data-tools-input");
    const formatEl = document.getElementById("data-tools-format");
    if (!inputEl || !formatEl) {
      statusUpdate("Status: Conv input fields are unavailable");
      return;
    }

    dataToolsContextPacket = null;
    dataToolsOriginalInputBytes = bytes;
    dataToolsInputEditedFlag = false;
    clearDataToolsStreamPackets();
    dataToolsLastConversionBytes = bytes;
    inputEl.value = formatHexInputBytesWithCap(bytes);
    formatEl.value = "hex";
    setDataToolsFileNameGuess(selectedFile.fileName || "");
    markDataToolsInputCommitted();
    showDataTools(CONV_CONVERSIONS_SUBTAB);
    runDataToolsConversion();

    // Register the file in the Stats carvable registry so it appears under
    // the Stats "Files" list alongside other carvable candidates. This must
    // happen here because the manual context-menu import bypasses the
    // packet-driven carvers (http/ftp/nfs/smb) that normally populate the
    // registry.
    registerExtractionResultForStats(
      selectedFile.fileName || "manual-import.bin",
      bytes,
    );

    const statusParts = [
      `Status: Loaded manual file into Conv (${fileSize} bytes)`,
    ];
    try {
      const decodedText = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      const keystoreImportCount = keystorePanel.importManualDataIntoSessionKeystore({
        bytes,
        text: decodedText,
        fileName: selectedFile.fileName || "",
        source: "manual-conv-import",
      });
      if (keystoreImportCount > 0) {
        statusParts.push(
          `and added ${keystoreImportCount} keystore entr${keystoreImportCount === 1 ? "y" : "ies"}`,
        );
      }
      writeLogEntry(
        `Manual Conv import loaded file="${selectedFile.fileName || "unknown"}" bytes=${fileSize} keystore_entries=${keystoreImportCount}`,
      );
    } catch (keystoreError) {
      // Keystore scan is a best-effort side effect; a failure here must not
      // be reported as a manual Conv import failure because the Conv tab
      // load itself already succeeded above.
      logErrorEntry("manual-conv-file-import-keystore", keystoreError);
    }
    statusUpdate(statusParts.join(" "));
  } catch (error) {
    doError("Manual Conv file import failed.");
    logErrorEntry("manual-conv-file-import", error);
  }
}

async function listCarvableFilesForStats() {
  const allPackets = getAllPacketsForHostNavigation();
  if (!Array.isArray(allPackets) || allPackets.length === 0) {
    return extractionCarvableRegistry.slice();
  }

  const streamMap = new Map();
  allPackets.forEach((packet) => {
    const packetInfo = packet?.["packet.info"];
    if (!packetInfo) return;
    const streamKey = buildBidirectionalStreamKey(packetInfo);
    if (!streamKey) return;
    if (!streamMap.has(streamKey)) {
      streamMap.set(streamKey, []);
    }
    streamMap.get(streamKey).push(packet);
  });

  const carvedEntries = [];
  const dedupeKeys = new Set();
  const protocolOrder = ["http", "ftp", "nfs", "smb"];

  const appendEntry = ({ protocol, candidate, streamKey, packetHint }) => {
    if (!candidate || !(candidate.bytes instanceof Uint8Array)) return;
    if (candidate.bytes.length === 0) return;
    const protocolName = String(protocol || "file").toLowerCase();
    const protocolLabel = protocolName.toUpperCase();
    const safeName = sanitizeCarveFilename(candidate.fileName) || `${protocolName}-file.bin`;
    const dedupeKey = `${protocolName}|${streamKey}|${safeName}|${candidate.bytes.length}`;
    if (dedupeKeys.has(dedupeKey)) return;
    dedupeKeys.add(dedupeKey);

    const packetInfo = packetHint?.["packet.info"] || {};
    const packetIndex =
      packetInfo["index"] ??
      packetInfo["Index"] ??
      packetInfo["Packet Processed"] ??
      null;
    const sourceDetail = Number.isFinite(Number(packetIndex))
      ? `packet #${packetIndex}`
      : "packet context";
    const label = `${protocolLabel}: ${safeName} (${candidate.bytes.length} bytes)`;

    carvedEntries.push({
      id: `${protocolName}:${streamKey}:${candidate.bytes.length}:${carvedEntries.length}`,
      protocol: protocolLabel,
      fileName: safeName,
      bytes: candidate.bytes,
      byteLength: candidate.bytes.length,
      label,
      sourceDetail,
    });
  };

  for (const [streamKey, streamPacketsRaw] of streamMap.entries()) {
    const streamPackets = Array.isArray(streamPacketsRaw)
      ? streamPacketsRaw.slice().sort((left, right) => comparePacketsChronologically(left, right))
      : [];
    if (!streamPackets.length) continue;
    const hydratedStreamPackets = await hydratePacketCollection(streamPackets);
    const contextPacket = hydratedStreamPackets[0] || streamPackets[0] || null;

    ["ftp", "nfs", "smb"].forEach((protocolName) => {
      const protocolCandidates = buildFileCarveCandidatesForProtocol(
        protocolName,
        hydratedStreamPackets,
        contextPacket,
      );
      protocolCandidates.forEach((candidate) => {
        appendEntry({
          protocol: protocolName,
          candidate,
          streamKey,
          packetHint: contextPacket,
        });
      });
    });

    const seenHttpDirectionKeys = new Set();
    hydratedStreamPackets.forEach((packet) => {
      const httpData = getCurrentHttpData(packet);
      if (!httpData || typeof httpData !== "object") return;
      const payloadHex = getCurrentRawPayloadHex(packet);
      if (!extractHttpBodyHex(payloadHex)) return;

      const tuple = getStreamTupleForPacket(packet);
      if (!tuple) return;
      const directionKey = `${tuple.srcIp}:${tuple.srcPort}->${tuple.dstIp}:${tuple.dstPort}`;
      if (seenHttpDirectionKeys.has(directionKey)) return;
      seenHttpDirectionKeys.add(directionKey);

      const bodyHex = collectHttpBodyHexFromStream(hydratedStreamPackets, packet);
      if (!bodyHex) return;
      let bodyBytes;
      try {
        bodyBytes = parseDataToolsInput("hex", bodyHex);
      } catch {
        return;
      }
      if (!(bodyBytes instanceof Uint8Array) || bodyBytes.length === 0) return;

      const currentHttpData = getCurrentHttpData(packet) || {};
      const contentType = currentHttpData["Content-Type"];
      const multipartBoundary = extractMultipartBoundaryFromContentType(contentType);
      let candidateFileName;
      let candidateBytes = bodyBytes;
      if (multipartBoundary) {
        const fileRange = findMultipartFileByteRange(bodyBytes, multipartBoundary);
        const multipartName = extractMultipartFilenameFromBodyBytes(
          bodyBytes,
          multipartBoundary,
        );
        candidateFileName = multipartName || "";
        if (fileRange) {
          candidateBytes = bodyBytes.slice(fileRange.start, fileRange.end);
        }
      }

      const packetIndex =
        packet?.["packet.info"]?.["index"] ??
        packet?.["packet.info"]?.["Index"] ??
        "stream";
      const guessedName = candidateFileName || guessHttpBodyFilenameFromPacket(
        packet,
        `http-body-${packetIndex}`,
      );
      appendEntry({
        protocol: "http",
        streamKey,
        packetHint: packet,
        candidate: {
          fileName: guessedName,
          bytes: candidateBytes,
        },
      });
    });
  }

  return carvedEntries
    .concat(extractionCarvableRegistry.map((entry) => ({ ...entry })))
    .sort((left, right) => {
      const protocolOrder = ["http", "ftp", "nfs", "smb", "extract"];
      const protocolDelta =
        protocolOrder.indexOf(String(left.protocol || "").toLowerCase()) -
        protocolOrder.indexOf(String(right.protocol || "").toLowerCase());
      if (protocolDelta !== 0) return protocolDelta;
      if (right.byteLength !== left.byteLength) return right.byteLength - left.byteLength;
      return String(left.fileName || "").localeCompare(String(right.fileName || ""));
    })
    .slice(0, 300);
}

// Shared registry for extracted/decompressed results surfaced in Stats.
let extractionCarvableRegistry = [];

// Looks up a carvable candidate by its id from the cached Stats carvable list.
async function getCarvableCandidateById(candidateId) {
  if (!candidateId) return null;
  try {
    const candidates = await listCarvableFilesForStats();
    const match = candidates.find((candidate) => candidate?.id === candidateId);
    return match || null;
  } catch (error) {
    const message = error?.message || String(error || "unknown");
    statusUpdate(`Status: Failed to look up carved file candidate - ${message}`);
    return null;
  }
}

// Registers an extraction result so Stats can show it as a carvable file.
function registerExtractionResultForStats(fileName, bytes) {
  if (!bytes || !(bytes instanceof Uint8Array) || bytes.length === 0) return;
  const safeName = sanitizeCarveFilename(fileName) || "extracted.bin";
  const id = `extract:${safeName}:${bytes.length}:${Date.now()}`;
  const label = `EXTRACT: ${safeName} (${bytes.length} bytes)`;
  extractionCarvableRegistry.unshift({
    id,
    protocol: "EXTRACT",
    fileName: safeName,
    bytes,
    byteLength: bytes.length,
    label,
    sourceDetail: "Conv Extraction",
  });
  extractionCarvableRegistry = extractionCarvableRegistry.slice(0, 50);
  // New carve may change the Session Threat Score (file-hash indicators).
  if (typeof subnetCalculatorPanel?.recomputeSessionThreatScore === "function") {
    subnetCalculatorPanel.recomputeSessionThreatScore({ silent: true });
  }
}

// Clears extraction carvable registry.
function clearExtractionResultsForStats() {
  extractionCarvableRegistry = [];
}

function resetExtractionOutputs() {
  const els = getExtractionPanelElements();
  if (els.tree) els.tree.innerHTML = "";
  if (els.preview) els.preview.hidden = true;
  if (els.output) els.output.hidden = true;
  clearExtractionError();
}

// Handles call large language model.
function callLargeLanguageModel(content) {
  if (!isLlmEnabledInSettings()) {
    throw new Error("LLM is disabled in settings");
  }
  if (!ollamaVersionCheckPassed) {
    throw new Error("Ollama is unavailable (startup version check failed)");
  }
  if (!window.llmapi || typeof window.llmapi.generate !== "function") {
    throw new Error("LLM API is not available");
  }
  else if (!content || typeof content !== "string") {
    throw new Error("Content must be a non-empty string");
  }
  return window.llmapi.generate(content);
}

// Handles wait for llm retry delay.
function waitForLlmRetryDelay(attemptNumber) {
  const delayMs = attemptNumber * 500;
  return new Promise((resolve) => setTimeout(resolve, delayMs));
}

// Returns configured llm retry attempts.
function getConfiguredLlmRetryAttempts() {
  const retryCount = Number(getCurrentSettings()?.llm?.retryCount);
  if (Number.isFinite(retryCount) && retryCount >= 0) {
    return Math.floor(retryCount) + 1;
  }
  return DEFAULT_SETTINGS.llm.retryCount + 1;
}

async function callLargeLanguageModelWithRetry(content, maxAttempts = getConfiguredLlmRetryAttempts()) {
  let lastError = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await callLargeLanguageModel(content);
    } catch (error) {
      lastError = error;
      if (attempt < maxAttempts) {
        await waitForLlmRetryDelay(attempt);
      }
    }
  }
  throw lastError;
}

// Builds markdown response instruction.
function buildMarkdownResponseInstruction() {
  return [
    "Return your response as valid Markdown (.md compatible).",
    "Use clear headings and include Markdown tables when they improve readability.",
    "Prefer concise bullets for key findings, and avoid HTML.",
  ].join(" ");
}

// Returns whether text significant for llm explain.
function isTextSignificantForLlmExplain(text) {
  if (!text || typeof text !== "string") return false;
  const trimmed = text.trim();
  // Must be at least 8 characters
  if (trimmed.length < 8) return false;
  // Reject purely numeric strings (port numbers, counts, raw ints, IP fragments, etc.)
  if (/^\d+(\.\d+)*$/.test(trimmed)) return false;
  // Reject bare hex/octal literals
  if (/^0x[0-9a-fA-F]+$/i.test(trimmed)) return false;
  // Require at least 4 letter/symbol characters (beyond just digits and separators)
  const alphaLike = trimmed.replace(/[\d\s.\-_:,;/\\]/g, "");
  if (alphaLike.length < 4) return false;
  return true;
}

// Builds utf8 byte preview.
function buildUtf8BytePreview(text, maxBytes = 24) {
  const normalized = String(text || "").trim();
  if (!normalized) {
    return { preview: "", truncated: false };
  }

  const encoder = new TextEncoder();
  let usedBytes = 0;
  let preview = "";

  for (const char of normalized) {
    const charBytes = encoder.encode(char).length;
    if (usedBytes + charBytes > maxBytes) break;
    preview += char;
    usedBytes += charBytes;
  }

  return {
    preview,
    truncated: preview.length < normalized.length,
  };
}

// Returns active context text for notes and llm.
function getActiveContextTextForNotesAndLlm(destination = "llm") {
  if (activeContextTarget?.closest?.("#conv-decodes-panel")) {
    const selectedContextText = (getTrimmedSelectionText() || "").trim();
    if (selectedContextText) return selectedContextText;

    const contextText = (activeContextConversionText || "").trim();
    if (contextText) {
      const plainDecodeFallback = getConvDecodedOutputText("plain").trim();
      if (
        destination === "notes" &&
        plainDecodeFallback &&
        contextText === plainDecodeFallback
      ) {
        return getConvDecodedOutputText("markdown");
      }
      return contextText;
    }

    return getConvDecodedOutputText(destination === "notes" ? "markdown" : "plain");
  }
  return (getTrimmedSelectionText() || activeContextConversionText || "").trim();
}

// Builds packet context summary.
function buildPacketContextSummary(packet) {
  if (!packet) return "No packet context available.";
  const info = packet["packet.info"] || {};
  const parts = [];
  const proto = info["packet.proto"] ?? info["Protocol"];
  if (proto) parts.push(`Protocol: ${proto}`);
  const src = info["ip.src.addr"] || info["Source IP"] || info["Source"];
  const dst = info["ip.dst.addr"] || info["Destination IP"] || info["Destination"];
  const srcPort = info["Source Port"];
  const dstPort = info["Destination Port"];
  if (src) {
    parts.push(`Source: ${formatNetworkEndpointDisplay(src, srcPort ?? "")}`);
  }
  if (dst) {
    parts.push(`Destination: ${formatNetworkEndpointDisplay(dst, dstPort ?? "")}`);
  }
  const ts = info["Timestamp"] || info["timestamp"];
  if (ts) parts.push(`Timestamp: ${ts}`);
  const decodedProtos = info["packet.decoded_protocols"] ?? info["Decoded Protocols"];
  if (decodedProtos) parts.push(`Decoded Protocols: ${decodedProtos}`);
  return parts.length ? parts.join(", ") : "Packet context unavailable.";
}

function buildFullPacketJsonContext(packet) {
  return packet ? JSON.stringify(packet, null, 2) : "No packet context available.";
}

function isConvSubnetContextTarget(target = activeContextTarget) {
  return (
    activeMainTab === MAIN_TAB_DATA_TOOLS &&
    getActiveConvSubtab() === CONV_SUBNET_SUBTAB &&
    Boolean(target?.closest?.("#conv-subnet-panel"))
  );
}

function getSubnetHostIpFromContextTarget(target = activeContextTarget) {
  if (!isConvSubnetContextTarget(target)) return "";
  const row = target?.closest?.("#subnet-calc-capture-targets table tr");
  const ipCell = row?.querySelector?.("td");
  const rowIp = normalizeContextToken(ipCell?.textContent || "");
  if (rowIp) return rowIp;

  const inputValue = normalizeContextToken(
    document.getElementById("subnet-calc-input")?.value || "",
  );
  return inputValue;
}

function collectSubnetSectionTableData(containerEl, hostIp = "") {
  const tables = [];
  const tableEls = Array.from(containerEl?.querySelectorAll?.("table") || []);
  tableEls.forEach((tableEl) => {
    const rowEls = Array.from(tableEl.querySelectorAll("tr"));
    const tableRows = rowEls
      .map((rowEl) => {
        const thCells = Array.from(rowEl.querySelectorAll("th")).map((cellEl) =>
          normalizeContextToken(cellEl.textContent),
        );
        const tdCells = Array.from(rowEl.querySelectorAll("td")).map((cellEl) =>
          normalizeContextToken(cellEl.textContent),
        );
        return {
          headers: thCells,
          values: tdCells,
        };
      })
      .filter((row) => row.headers.length > 0 || row.values.length > 0);

    tables.push(tableRows);
  });

  if (!hostIp || !tables.length) return tables;

  return tables
    .map((tableRows) => {
      if (!tableRows.length) return [];
      const hasHostRow = tableRows.some((row) => {
        const firstValue = normalizeContextToken(row.values?.[0] || "");
        return firstValue === hostIp;
      });
      if (!hasHostRow) return tableRows;
      return tableRows.filter((row, rowIndex) => {
        if (rowIndex === 0 && row.headers.length > 0) return true;
        const firstValue = normalizeContextToken(row.values?.[0] || "");
        return firstValue === hostIp;
      });
    })
    .filter((tableRows) => tableRows.length > 0);
}

function collectSubnetHostSummaryContext(hostIp) {
  const sectionDefs = [
    ["subnet-calc-summary", "Summary"],
    ["subnet-calc-range", "Range"],
    ["subnet-calc-binary", "Binary Notation"],
    ["subnet-calc-whois", "WHOIS / RDAP"],
    ["subnet-calc-geo", "GeoIP"],
    ["subnet-calc-capture-targets", "Capture Internet Targets"],
    ["subnet-calc-shodan", "Shodan InternetDB"],
    ["subnet-calc-nmap", "Nmap Scan Status"],
  ];

  const sections = sectionDefs
    .map(([id, fallbackTitle]) => {
      const containerEl = document.getElementById(id);
      if (!containerEl) return null;
      const title =
        normalizeContextToken(
          containerEl.querySelector(".subnet-calc-section-title, .data-tools-output-label")
            ?.textContent || "",
        ) || fallbackTitle;
      const placeholder = normalizeContextToken(
        containerEl.querySelector(".data-tools-proto-none")?.textContent || "",
      );
      const binaryRows = Array.from(
        containerEl.querySelectorAll(".subnet-calc-binary-row"),
      )
        .map((rowEl) => {
          const label = normalizeContextToken(
            rowEl.querySelector(".subnet-calc-binary-label")?.textContent || "",
          );
          const value = String(
            rowEl.querySelector(".subnet-calc-binary-pre")?.textContent || "",
          ).trim();
          if (!label && !value) return null;
          return { label, value };
        })
        .filter(Boolean);
      const tableData = collectSubnetSectionTableData(containerEl, hostIp);
      return {
        id,
        title,
        placeholder,
        binaryRows,
        tables: tableData,
      };
    })
    .filter(Boolean);

  const analyzedInput = normalizeContextToken(
    document.getElementById("subnet-calc-input")?.value || "",
  );
  const panelStatus = normalizeContextToken(
    document.getElementById("subnet-calc-status")?.textContent || "",
  );
  const hasSectionData = sections.some(
    (section) =>
      (Array.isArray(section.tables) && section.tables.some((tableRows) => tableRows.length > 0)) ||
      (Array.isArray(section.binaryRows) && section.binaryRows.length > 0) ||
      Boolean(section.placeholder),
  );

  return {
    hostIp,
    analyzedInput,
    panelStatus,
    sections,
    hasSectionData,
  };
}

function buildLlmSubnetHostSummaryPrompt(contextData) {
  return [
    "You are a network analysis assistant named PacketSnitch.",
    `This request is sent through a hook that supports Markdown in the user query and in your response. ${buildMarkdownResponseInstruction()}`,
    "",
    `Task: Distill and summarize the current Conv Analyze Subnet table data for host ${contextData.hostIp}.`,
    "Use only the provided data. Do not invent values or infer unsupported facts.",
    "Return clean Markdown only.",
    "The first line must be exactly: # PacketSnitch Subnet Host Summary",
    "Include concise sections for host overview, addressing/classification, threat/reputation, service exposure, and notable analyst takeaways.",
    "When a section has missing data, explicitly say data is unavailable.",
    "Use a short markdown table for key facts when appropriate.",
    "",
    "Current subnet panel data (JSON):",
    JSON.stringify(contextData, null, 2),
  ].join("\n");
}

async function summarizeSubnetHostContextWithLLM() {
  if (!isLlmRuntimeEnabled()) {
    hideConvertContextMenu();
    statusUpdate(
      "Status: PacketSnitch host summary is unavailable. Ensure LLM is enabled in settings and Ollama is installed.",
    );
    return;
  }

  const hostIp = getSubnetHostIpFromContextTarget(activeContextTarget);
  hideConvertContextMenu();
  if (!hostIp) {
    statusUpdate("Status: Select a host row in Conv > Analyze Subnet first.");
    return;
  }

  const contextData = collectSubnetHostSummaryContext(hostIp);
  if (!contextData.hasSectionData) {
    statusUpdate("Status: No subnet host table data is currently available to summarize.");
    return;
  }

  statusUpdate(`Status: Asking PacketSnitch to summarize subnet host ${hostIp}...`);
  writeLogEntry(`PacketSnitch subnet-host summary requested host=${JSON.stringify(hostIp)}`);

  try {
    const prompt = buildLlmSubnetHostSummaryPrompt(contextData);
    const response = await callLargeLanguageModelWithRetry(prompt);
    const summaryMarkdown = String(response?.response || "").trim();
    if (!summaryMarkdown) {
      statusUpdate("Status: PacketSnitch returned no subnet host summary.");
      return;
    }
    const didAdd = addNote(
      summaryMarkdown,
      NOTE_DEFAULT_COLOR,
      "llm-subnet-host-summary",
      false,
    );
    if (didAdd) {
      showNotesWorkspace();
      statusUpdate(`Status: Subnet host summary for ${hostIp} added to Notes.`);
      writeLogEntry(`PacketSnitch subnet-host summary complete host=${JSON.stringify(hostIp)} chars=${summaryMarkdown.length}`);
    }
  } catch (error) {
    const errorMessage = error?.message || String(error);
    statusUpdate(`Status: PacketSnitch subnet host summary failed: ${errorMessage}`);
    writeLogEntry(`PacketSnitch subnet-host summary failed host=${JSON.stringify(hostIp)} error=${JSON.stringify(errorMessage)}`);
  }
}

async function explainContextWithLLM() {
  if (!isLlmRuntimeEnabled()) {
    hideConvertContextMenu();
    statusUpdate(
      "Status: PacketSnitch's explanation is unavailable. Ensure LLM is enabled in settings and Ollama is installed.",
    );
    return;
  }
  const contextPacket = activeContextPacket || getCurrentContextPacket();
  const textToExplain = getActiveContextTextForNotesAndLlm("llm");
  hideConvertContextMenu();

  if (!isTextSignificantForLlmExplain(textToExplain)) {
    statusUpdate("Status: Selected text is not significant enough for PacketSnitch explanation.");
    return;
  }

  const packetCtx = buildPacketContextSummary(contextPacket);
  const prompt = `You are a network analysis assistant named PacketSnitch. A user is inspecting captured network data and selected a specific value they want explained.\n\nThis request is sent through a hook that supports Markdown in the user query and in your response. ${buildMarkdownResponseInstruction()}\n\nSelected data to explain: "${textToExplain}"\n\nPacket context summary (concise): ${packetCtx}\n\nImportant: Focus on the selected data itself. Do not attempt to summarize the whole packet or host dataset.\n\nPlease explain what this data likely represents in context. Be concise and focus on what is practically relevant to a network analyst. If it is a well-known value (e.g. a port, status code, header, algorithm name, encoding, etc.), identify it. If it appears to be encoded or encrypted content, describe that. Keep your answer to 2-4 sentences.\n\nProvide your explanation in Markdown format.`;

  statusUpdate("Status: Asking PacketSnitch to explain selection...");
  writeLogEntry(`PacketSnitch explain requested for ${textToExplain.length} chars of context data`);
  try {
    const response = await callLargeLanguageModelWithRetry(prompt);
    const explanation = response?.response?.trim() || "";
    if (!explanation) {
      statusUpdate("Status: PacketSnitch returned no explanation.");
      return;
    }
    const noteText = buildLlmThreadNote({
      title: "PacketSnitch's Explanation",
      responseText: explanation,
      packetSummary: buildPacketContextSummary(contextPacket),
      selectedText: textToExplain,
    });
    const didAdd = addNote(
      noteText,
      NOTE_DEFAULT_COLOR,
      "llm-explain",
      false,
    );
    if (didAdd) {
      showNotesWorkspace();
      statusUpdate("Status: PacketSnitch's explanation added to Notes.");
      writeLogEntry(`LLM explain complete (${explanation.length} chars)`);
    }
  } catch (error) {
    const errorMessage = error?.message || String(error);
    statusUpdate(`Status: PacketSnitch's explanation failed: ${errorMessage}`);
    writeLogEntry(`PacketSnitch explain failed: ${errorMessage}`);
  }
}

function buildLlmPacketSummaryPrompt(contextPacket) {
  const packetCtx = buildFullPacketJsonContext(contextPacket);
  return [
    "You are a network analysis assistant named PacketSnitch. A user is inspecting a captured network packet and wants a concise summary of the packet data.",
    `This request is sent through a hook that supports Markdown in the user query and in your response. ${buildMarkdownResponseInstruction()}`,
    "",
    "Summarize the packet for a network analyst. Identify the main protocol flow, notable headers or payload clues, and anything unusual or security-relevant that stands out. If the packet data is incomplete or ambiguous, say so.",
    "",
    "Packet JSON:",
    packetCtx,
  ].join("\n");
}

// Handles request llm question from context menu dialog.
function requestLlmQuestionFromContextMenuDialog() {
  const dialogEl = document.getElementById("ctx-llm-question-dialog");
  const descriptionEl = document.getElementById("ctx-llm-question-description");
  const inputEl = document.getElementById("ctx-llm-question-input");
  if (!dialogEl || !descriptionEl || !inputEl) return Promise.resolve(null);
  if (activeContextLlmQuestionDialogResolver) {
    const resolve = activeContextLlmQuestionDialogResolver;
    activeContextLlmQuestionDialogResolver = null;
    resolve(null);
  }
  const selectedText = getActiveContextTextForNotesAndLlm("llm");
  const selectedTextPreview = buildUtf8BytePreview(selectedText, 24);
  descriptionEl.textContent = selectedTextPreview.preview
    ? `Ask a question about: ${selectedTextPreview.preview}${selectedTextPreview.truncated ? "…" : ""}`
    : "Ask a question about the selected data and packet context.";
  activeContextLlmQuestionDialogContext = {
    packet: activeContextPacket,
    selectedText,
  };
  hideConvertContextMenu();
  dialogEl.hidden = false;
  inputEl.value = "";
  inputEl.focus();
  return new Promise((resolve) => {
    activeContextLlmQuestionDialogResolver = resolve;
  });
}

// Handles resolve llm question from context menu dialog.
function resolveLlmQuestionFromContextMenuDialog(value) {
  const dialogEl = document.getElementById("ctx-llm-question-dialog");
  const inputEl = document.getElementById("ctx-llm-question-input");
  const dialogContext = activeContextLlmQuestionDialogContext;
  if (dialogEl) dialogEl.hidden = true;
  if (inputEl) inputEl.value = "";
  if (!activeContextLlmQuestionDialogResolver) return;
  const resolve = activeContextLlmQuestionDialogResolver;
  activeContextLlmQuestionDialogResolver = null;
  resolve({
    question: value,
    context: dialogContext,
  });
  activeContextLlmQuestionDialogContext = null;
}

// Handles submit llm question from context menu dialog.
function submitLlmQuestionFromContextMenuDialog() {
  const inputEl = document.getElementById("ctx-llm-question-input");
  resolveLlmQuestionFromContextMenuDialog(inputEl?.value || "");
}

// Builds llm question prompt.
function buildLlmQuestionPrompt(question, contextPacket, selectedText) {
  const packetCtx = buildPacketContextSummary(contextPacket);
  const contextLines = [
    "You are a network analysis assistant named PacketSnitch. A user is inspecting a captured network packet and wants a direct answer to a question about the data in context.",
    `This request is sent through a hook that supports Markdown in the user query and in your response. ${buildMarkdownResponseInstruction()}`,
    "",
    `Packet context: ${packetCtx}`,
  ];
  if (selectedText) {
    contextLines.push(
      "",
      `Relevant data from the packet or selected context:`,
      `"${selectedText}"`,
    );
  }
  contextLines.push(
    "",
    `User question: ${question}`,
    "",
    "Answer concisely and focus on what is practically relevant to a network analyst. If the packet context does not support a confident answer, say so.",
  );
  return contextLines.join("\n");
}

// Builds llm thread note.
function buildLlmThreadNote({
  title,
  responseText,
  packetSummary,
  questionText = "",
  selectedText = "",
}) {
  return [
    `# ${title}`,
    "",
    responseText,
    "",
    "---",
    "",
    "## Original Context",
    questionText ? `Question: ${questionText}` : null,
    packetSummary ? `Packet: ${packetSummary}` : null,
    selectedText ? `Data: "${selectedText}"` : null,
  ]
    .filter(Boolean)
    .join("\n");
}

async function summarizeContextPacketWithLLM() {
  if (!isLlmRuntimeEnabled()) {
    hideConvertContextMenu();
    statusUpdate(
      "Status: PacketSnitch's packet summary is unavailable. Ensure LLM is enabled in settings and Ollama is installed.",
    );
    return;
  }
  const contextPacket = activeContextPacket || getCurrentContextPacket();
  hideConvertContextMenu();
  if (!contextPacket) {
    statusUpdate("Status: No packet context available for PacketSnitch summary.");
    return;
  }

  const packetSummary = buildPacketContextSummary(contextPacket);
  const prompt = buildLlmPacketSummaryPrompt(contextPacket);

  statusUpdate("Status: Asking PacketSnitch to summarize packet data...");
  writeLogEntry("PacketSnitch packet summary requested for current context packet");
  try {
    const response = await callLargeLanguageModelWithRetry(prompt);
    const summary = response?.response?.trim() || "";
    if (!summary) {
      statusUpdate("Status: PacketSnitch returned no packet summary.");
      return;
    }
    const noteText = buildLlmThreadNote({
      title: "PacketSnitch Packet Summary",
      responseText: summary,
      packetSummary,
    });
    const didAdd = addNote(
      noteText,
      NOTE_DEFAULT_COLOR,
      "llm-packet-summary",
      false,
    );
    if (didAdd) {
      showNotesWorkspace();
      statusUpdate("Status: PacketSnitch packet summary added to Notes.");
      writeLogEntry(`PacketSnitch packet summary complete (${summary.length} chars)`);
    }
  } catch (error) {
    const errorMessage = error?.message || String(error);
    statusUpdate(`Status: PacketSnitch packet summary failed: ${errorMessage}`);
    writeLogEntry(`PacketSnitch packet summary failed: ${errorMessage}`);
  }
}

async function askContextQuestionWithLLM() {
  if (!isLlmRuntimeEnabled()) {
    hideConvertContextMenu();
    statusUpdate(
      "Status: LLM is unavailable. Ensure LLM is enabled in settings and Ollama is installed.",
    );
    return;
  }
  const dialogResult = await requestLlmQuestionFromContextMenuDialog();
  const question = String(dialogResult?.question || "").trim();
  if (!question) return;
  const questionContext = dialogResult?.context || {};
  const contextPacket = questionContext.packet || activeContextPacket;
  const selectedText = String(questionContext.selectedText || "").trim();
  if (!contextPacket) {
    statusUpdate("Status: No packet context available for PacketSnitch question.");
    return;
  }

  const packetCtx = buildPacketContextSummary(contextPacket);
  const prompt = buildLlmQuestionPrompt(question, contextPacket, selectedText);

  statusUpdate("Status: Asking PacketSnitch a question...");
  writeLogEntry(`PacketSnitch question requested for ${question.length} chars of prompt`);
  try {
    const response = await callLargeLanguageModelWithRetry(prompt);
    const answer = response?.response?.trim() || "";
    if (!answer) {
      statusUpdate("Status: PacketSnitch returned no answer.");
      return;
    }
    const noteText = buildLlmThreadNote({
      title: "PacketSnitch Question",
      responseText: answer,
      packetSummary: packetCtx,
      questionText: question,
      selectedText,
    });
    const didAdd = addNote(
      noteText,
      NOTE_DEFAULT_COLOR,
      "llm-question",
      false,
    );
    if (didAdd) {
      showNotesWorkspace();
      statusUpdate("Status: PacketSnitch question answer added to Notes.");
      writeLogEntry(`PacketSnitch question complete (${answer.length} chars)`);
    }
  } catch (error) {
    const errorMessage = error?.message || String(error);
    statusUpdate(`Status: PacketSnitch question failed: ${errorMessage}`);
    writeLogEntry(`PacketSnitch question failed: ${errorMessage}`);
  }
}

// Handles follow stream to conv.
function followStreamToConv() {
  const contextPacket = getCurrentContextPacket();
  hideConvertContextMenu();
  void _runFollowStreamToConvAction({ contextPacket });
}

// Handles follow stream to conv decompressed.
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
    if (!(await confirmFollowStreamContextMenuLoad("Conv", streamPackets.length))) {
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
  dataToolsContextPacket = streamPackets[0] || null;
  const hydratedStreamPackets = await hydratePacketCollection(streamPackets);
  // Capture per-packet byte slices BEFORE any decompression step. The
  // per-packet decode state in data-tools-panel relies on the original
  // packet bytes; after decompression the byte-to-packet relationship is
  // lost, so we leave the stream state null in that case and let the
  // single-blob decode path run instead.
  if (!decompress) {
    const streamPacketEntries = [];
    for (let entryIndex = 0; entryIndex < hydratedStreamPackets.length; entryIndex += 1) {
      const hydratedStreamPacket = hydratedStreamPackets[entryIndex];
      if (!hydratedStreamPacket || typeof hydratedStreamPacket !== "object") {
        continue;
      }
      const packetPayloadHex = getPacketPayloadHex(hydratedStreamPacket);
      if (typeof packetPayloadHex !== "string" || !packetPayloadHex.trim()) {
        continue;
      }
      const packetBytes = hexStringToUint8Array(packetPayloadHex);
      if (!(packetBytes instanceof Uint8Array) || packetBytes.length === 0) {
        continue;
      }
      const packetInfo = hydratedStreamPacket["packet.info"];
      const packetSourceKey = typeof hydratedStreamPacket.__packetKey === "string"
        ? hydratedStreamPacket.__packetKey
        : "";
      streamPacketEntries.push({
        bytes: packetBytes,
        info: {
          packetIndex: Number.isFinite(Number(packetInfo?.index))
            ? Number(packetInfo.index)
            : null,
          sourceKey: packetSourceKey,
        },
      });
    }
    setDataToolsStreamPackets(streamPacketEntries);
  } else {
    clearDataToolsStreamPackets();
  }
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
  const streamBytes = hexStringToUint8Array(outputHex);
  dataToolsOriginalInputBytes = streamBytes;
  dataToolsInputEditedFlag = false;
  dataToolsLastConversionBytes = streamBytes;
  inputEl.value = formatHexInputBytesWithCap(streamBytes);
  formatEl.value = "hex";
  markDataToolsInputCommitted();
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

async function followStreamToCrypt() {
  const contextPacket = getCurrentContextPacket();
  hideConvertContextMenu();
  const streamPackets = getFollowStreamPackets(contextPacket);
  if (!streamPackets.length) {
    statusUpdate("Status: No stream packets found for current packet");
    return;
  }
  if (!(await confirmFollowStreamContextMenuLoad("Crypt", streamPackets.length))) {
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
  showCryptWorkspace();
  loadStreamIntoCryptEncountered(hydratedStreamPackets, combinedHex);
  writeLogEntry(
    `Follow stream loaded ${streamPackets.length} packets into Crypt tab`,
  );
}

// Returns follow stream json.
function getFollowStreamJson(streamPackets) {
  if (!Array.isArray(streamPackets) || streamPackets.length === 0) return "";
  const jsonArray = streamPackets.map((packet) => {
    const packetInfo = packet?.["packet.info"] || {};
    const protocol = String(packetInfo["packet.proto"] ?? packetInfo["Protocol"] ?? "").toUpperCase();
    const timestamp = parsePacketTimestampMs(packet);
    const payloadHex = getPacketPayloadHex(packet);
    return {
      timestamp: Number.isFinite(timestamp) ? timestamp : null,
      protocol: protocol || null,
      payloadHex: payloadHex || null,
    };
  });
  return JSON.stringify(jsonArray, null, getConvJsonIndentSpaces());
}

// Handles write summary from llm.
function writeSummaryFromLLM() {
  // we will wait 5 seconds and make sure we are sitting on a packet before calling the
  // llm to generate a summary of the packets stream. This is to avoid calling the llm
  //  too often when the user is rapidly scrolling through packets.
  // we should also check to make sure if this is a loaded session, and the stream has 
  // already been summmarized, we should not call the llm again for the same stream.
  if (!isBackgroundSummaryGenerationEnabled()) {
    if (llmSummaryTimeout) {
      clearTimeout(llmSummaryTimeout);
      llmSummaryTimeout = null;
    }
    return;
  }
  if (summaryFromSavedSession) {
    summaryFromSavedSession = false;
    return;
  }

  if (!isLlmRuntimeEnabled()) {
    if (llmSummaryTimeout) {
      clearTimeout(llmSummaryTimeout);
      llmSummaryTimeout = null;
    }
    return;
  }

  if (llmSummaryTimeout) {
    // clear any existing timeout to avoid multiple calls
    clearTimeout(llmSummaryTimeout);
  }
  llmSummaryTimeout = setTimeout(async () => {
    const contextPacket = getCurrentContextPacket();
    if (!contextPacket) return;
    if (alreadySummarizedPacketKeys.has(contextPacket?.__packetKey)) return;
    const streamPackets = getFollowStreamPackets(contextPacket);
    if (!streamPackets.length) return;
    const hydratedStreamPackets = await hydratePacketCollection(streamPackets);
    const jsonOfPacketStream = getFollowStreamJson(hydratedStreamPackets);
    const combinedHex = buildStreamHex(hydratedStreamPackets);
    if (!combinedHex) return;
    // make sure we don't recall if we are on the same packet stream as before
    if (lastLLMSummaryPacketKey === contextPacket?.__packetKey) return;
    lastLLMSummaryPacketKey = contextPacket?.__packetKey;
    // we need to keep track of what has already been summarized
    if (alreadySummarizedPacketKeys.size > 100) {
      // we need to shift out the old ones to avoid memory bloat
      const keysToRemove = Array.from(alreadySummarizedPacketKeys).slice(0, alreadySummarizedPacketKeys.size - 100);
      keysToRemove.forEach((key) => alreadySummarizedPacketKeys.delete(key));
    }
    // add the current packet key to the set of already summarized packets
    alreadySummarizedPacketKeys.add(contextPacket?.__packetKey);
    writeLogEntry(`Follow stream loaded ${streamPackets.length} packets into LLM summary`);
    // Build the capture-level overview that will be woven into the prompt
    // *initially* (at the top) so the LLM has the full pcap picture before
    // answering about this specific stream. This ensures the per-stream
    // summary can reference the overall traffic shape, top talkers, protocol
    // distribution, and other capture-wide facts.
    const captureOverviewParts = [];
    const statsContextMarkdown = buildStatsMarkdownSection();
    if (statsContextMarkdown) {
      captureOverviewParts.push(
        `## Capture Statistics (from the Stats panel)\n\nThe following is the current capture-level statistics summary. These facts describe the entire pcap and MUST be woven into your answer so the analyst has a complete view of the traffic (top talkers, protocols, traffic volume, geographic footprint, MIME types, heatmap hits, masked credentials, etc.).\n\n${statsContextMarkdown}`,
      );
    }
    const keystoreSummary =
      typeof getLatestKeystoreSummary === "function"
        ? getLatestKeystoreSummary()
        : null;
    if (keystoreSummary && keystoreSummary.text) {
      const timestampLine = keystoreSummary.timestamp
        ? ` (generated ${keystoreSummary.timestamp})`
        : "";
      captureOverviewParts.push(
        `## Keychain Overview (from the Keystore panel)${timestampLine}\n\nThe following is the latest LLM-generated review of the active keystore entries. Surface any noteworthy credential patterns, sources, or categories that are relevant to this stream.\n\n${keystoreSummary.text}`,
      );
    }
    const captureOverviewBlock = captureOverviewParts.length
      ? `${captureOverviewParts.join("\n\n---\n\n")}\n\n---\n\n`
      : "";
    let prompt = `You are PacketSnitch, a tool designed to analyze network stream data. ${buildMarkdownResponseInstruction()} Treat the Capture Statistics (and Keychain Overview, if provided) as primary context: weave their key facts into your answer so the analyst has a complete view of the pcap, not just this stream. Please provide a summary of the following network data, including any protocols, file transfers, URL/URIs, credentials, or other notable content. If the data is not recognizable, simply state that it is unrecognized. Generate two paragraphs, paragraph one should be on hard data that is available, and the second paragraph should be anything inferrable from the data points available. It is not necessary to label the paragraphs, just print the first paragraph, two newlines, then the next. SQUELCH NO-OP DATA: do not report decoders, parsers, or extractors that were attempted but failed, returned errors, or produced no usable output. If a sub-tab was opened but the operation did not yield data, omit it entirely from the summary instead of mentioning its absence. Only describe activity that actually surfaced real content.\n\n${captureOverviewBlock}Here is the stream data:\n\n${jsonOfPacketStream}.\n\nNote that you have already written the summary data: ${summary}.  Please do not repeat any of the summary data that has already been written.  Only provide new summary data that has not already been written.`;
    if (prompt.length >= LLM_MAX_CONTENT_LENGTH) {
      prompt = prompt.slice(0, LLM_MAX_CONTENT_LENGTH) + "\n\n[TRUNCATED: Stream data too long for LLM input]";
    }
    try {
      const llmResponse = await callLargeLanguageModel(prompt);
      const summPart = llmResponse?.response || "";
      summary = summary + "\n\n" + summPart;
      if (summPart.length > 0) {
        appendAnalysisBlub(summPart);
      }
      if (summPart.length > 800) {
        renderSummaryMarkdownPreview(summary);
        writeLogEntry(`LLM summary generated for ${streamPackets.length} packets`);
        statusUpdate("Status: LLM summary available for current stream!");
      } else {
        renderSummaryMarkdownPreview(summary);
      }
    } catch (error) {
      writeLogEntry(`LLM summary generation failed: ${error?.message || error}`);
    }
  }, getLLMSummaryDelayMs());  // wait before calling the LLM to avoid too many calls when scrolling rapidly
}

// Records an Analysis "blub" in chronological order and, when the threshold is
// reached, compacts the accumulated blurbs via the LLM. `blubText` should be the
// new content that is being appended to the live summary, not the compacted
// summary itself.
function appendAnalysisBlub(blubText) {
  if (!blubText || typeof blubText !== "string") return;
  const trimmed = blubText.trim();
  if (!trimmed) return;
  analysisBlubHistory.push(trimmed);
  const threshold = getAnalysisCompactionThresholdBlubs();
  if (
    !analysisCompactionInProgress &&
    analysisBlubHistory.length >= threshold
  ) {
    void runAnalysisCompaction();
  }
}

// Compacts the accumulated Analysis blurbs by asking the LLM to merge them
// into the in-depth summary for the current analysis context. If the context
// has changed significantly a new context-scoped summary entry is created. If
// the context returns to a previously seen scope, the new blurbs are merged
// back into that existing summary.
async function runAnalysisCompaction() {
  if (analysisCompactionInProgress) return;
  analysisCompactionInProgress = true;
  statusUpdate(`Status: Compacting ${analysisBlubHistory.length} Analysis blurbs...`);
  writeLogEntry(`Analysis compaction started for ${analysisBlubHistory.length} blurbs`);
  const blurbs = analysisBlubHistory.splice(0, analysisBlubHistory.length);
  if (!blurbs.length) {
    analysisCompactionInProgress = false;
    statusUpdate("Status: Analysis compaction skipped (no blurbs).");
    return;
  }

  const currentSignature = buildAnalysisContextSignature();
  let match = findAnalysisSummaryBySignature(currentSignature);
  let targetEntry = match?.entry || null;

  // If no exact signature match exists, decide whether this batch of blurbs
  // represents a major context shift versus the most recent entry. A major
  // shift creates a new context-scoped summary; otherwise we merge into the
  // latest entry to keep the summary additive and growing.
  if (!targetEntry) {
    const lastEntry = compactedAnalysisSummaries.length
      ? compactedAnalysisSummaries[compactedAnalysisSummaries.length - 1]
      : null;
    if (
      !lastEntry ||
      isMajorContextShift(currentSignature, lastEntry.signature)
    ) {
      targetEntry = {
        signature: currentSignature,
        summary: "",
        lastUpdatedAt: Date.now(),
      };
      compactedAnalysisSummaries.push(targetEntry);
      writeLogEntry(`[AnalysisCompact] New context scope detected: ${currentSignature}`);
    } else {
      targetEntry = lastEntry;
      writeLogEntry(`[AnalysisCompact] Continuing latest context scope: ${currentSignature}`);
    }
  } else {
    writeLogEntry(`[AnalysisCompact] Resuming context scope: ${currentSignature}`);
  }

  // Build prompt from the target entry's existing summary plus the new blurbs.
  const previousCompacted = (targetEntry.summary || "").trim();
  const chronologicalBlurbs = blurbs
    .map((blurb, idx) => `ANALYSIS ENTRY ${idx + 1}:\n${blurb}`)
    .join("\n\n---\n\n");

  // Build the capture-level overview that will be woven into the recompaction
  // input *initially* (at the top of the prompt) so the LLM has the full
  // pcap picture before merging the new blurbs. The Stats panel data and
  // (if available) the keystore summary provide the context that the
  // per-stream blurbs alone cannot give the model.
  const captureOverviewParts = [];
  const statsContextMarkdown = buildStatsMarkdownSection();
  if (statsContextMarkdown) {
    captureOverviewParts.push(
      `## Capture Statistics (from the Stats panel)\n\nThe following is the current capture-level statistics summary. These facts describe the entire pcap and MUST be woven into your compacted summary so the analyst has a complete view of the traffic (top talkers, protocols, traffic volume, geographic footprint, MIME types, heatmap hits, masked credentials, etc.).\n\n${statsContextMarkdown}`,
    );
  }
  const keystoreSummary =
    typeof getLatestKeystoreSummary === "function"
      ? getLatestKeystoreSummary()
      : null;
  if (keystoreSummary && keystoreSummary.text) {
    const timestampLine = keystoreSummary.timestamp
      ? ` (generated ${keystoreSummary.timestamp})`
      : "";
    captureOverviewParts.push(
      `## Keychain Overview (from the Keystore panel)${timestampLine}\n\nThe following is the latest LLM-generated review of the active keystore entries. Surface any noteworthy credential patterns, sources, or categories that are relevant to the analysis.\n\n${keystoreSummary.text}`,
    );
  }
  const captureOverview = captureOverviewParts.length
    ? `${captureOverviewParts.join("\n\n---\n\n")}\n\n---\n\n`
    : "";

  const previousCompactedBlock = previousCompacted
    ? `The following is the previously compacted summary of earlier analysis for this context. Preserve and merge its important facts into the new compacted summary. Do not remove key data points; only add new information or refine existing details. Keep the result detailed and reference-quality.\n\n${previousCompacted}\n\n---\n\n`
    : "";

  const combinedInput = `${captureOverview}${previousCompactedBlock}The following are new analysis blurbs generated from network traffic, in chronological order. Read them carefully, then produce a single in-depth summary that:
- Treats the Capture Statistics (and Keychain Overview, if provided) as primary context: weave their key facts into the output so the compacted summary covers both the LLM blurbs AND the capture-level picture.
- Preserves the most important concrete data points (e.g. IP addresses, ports, protocols, credentials, file names, URLs, hostnames, hashes, notable flags) verbatim or with minimal rephrasing so they remain usable as reference.
- Preserves the chronological order of significant events where it matters.
- Merges related facts instead of listing every blurb separately; organize by protocol, host, credential, or file transfer where appropriate.
- Adds new blurbs to the existing analysis rather than replacing it. Keep prior key analysis points and extend them with the new data.
- Drops only redundant or low-value observations; do not drop details that a security analyst might want to refer back to.
- SQUELCH NO-OP DATA: do not report decoders, parsers, or extractors that were attempted but failed, returned errors, or produced no usable output. If a decoder was opened but the operation did not yield data, omit it entirely from the summary instead of mentioning its absence. Only describe activity that actually surfaced real content. The same applies to empty hash fields, blank conversions, no-op extraction results, and failed subnet/whois/geoip lookups.
- Is detailed and reference-quality; aim for several paragraphs and use Markdown tables or bullet lists when they make the data easier to scan.

${chronologicalBlurbs}`;

  let prompt = `You are PacketSnitch, a network analysis assistant. ${buildMarkdownResponseInstruction()}\n\n${combinedInput}`;
  if (prompt.length >= LLM_MAX_CONTENT_LENGTH) {
    prompt = prompt.slice(0, LLM_MAX_CONTENT_LENGTH) + "\n\n[TRUNCATED: Analysis history too long for LLM input]";
  }

  let compacted = "";
  try {
    if (isLlmRuntimeEnabled()) {
      const llmResponse = await callLargeLanguageModelWithRetry(prompt);
      compacted = llmResponse?.response || "";
    }
  } catch (error) {
    writeLogEntry(`[AnalysisCompact] Compaction failed: ${error?.message || error}`);
    statusUpdate("Status: Analysis compaction failed.");
  }

  if (!compacted.trim()) {
    // Fallback: keep the raw blurbs in chronological order so no data is lost.
    compacted = chronologicalBlurbs.replace(/ANALYSIS ENTRY \d+:\n/g, "- ").replace(/\n---\n/g, "\n\n");
  }

  // Store the merged summary back into its context-scoped entry. The raw
  // blurbs have already been consumed and are kept out of the visible panel.
  targetEntry.summary = compacted.trim();
  targetEntry.lastUpdatedAt = Date.now();

  renderCombinedAnalysisSummary();
  statusUpdate(`Status: Analysis compacted ${blurbs.length} blurbs into running summary.`);
  writeLogEntry(`[AnalysisCompact] Compacted ${blurbs.length} blurbs into context-scoped summary`);
  analysisCompactionInProgress = false;
}

// Sets active packet cursor.
function setActivePacketCursor(nextIndex) {
  const parsedIndex = Number.parseInt(nextIndex, 10);
  activePacketCursor =
    Number.isNaN(parsedIndex) || parsedIndex < 0 ? null : parsedIndex;
  return activePacketCursor;
}

// Returns current raw payload hex.
function getCurrentRawPayloadHex(packet = null) {
  const contextPacket = packet || getCurrentContextPacket();
  const payloadHex =
    contextPacket?.["packet.info"]?.["Raw data"]?.["Payload"]?.[
    "payload.hex"
    ] ??
    contextPacket?.["packet.info"]?.["Raw data"]?.["Payload"]?.[
    "Hex Encoded"
    ];
  return typeof payloadHex === "string" ? payloadHex : "";
}

// Returns current http data.
function getCurrentHttpData(packet = null) {
  const contextPacket = packet || getCurrentContextPacket();
  const packetInfo = contextPacket?.["packet.info"];
  if (!packetInfo) return null;
  const protocol = getTransportProtocolName(packetInfo);
  const transportData = getTransportDataForPacketInfo(packetInfo, protocol);
  return transportData?.["HTTP"] || null;
}

// Extracts http body hex.
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

// Parses http content length.
function parseHttpContentLength(packet = null) {
  const httpData = getCurrentHttpData(packet);
  const rawLength = String(httpData?.["Content-Length"] || "").trim();
  if (!/^\d+$/.test(rawLength)) return null;
  const contentLength = Number.parseInt(rawLength, 10);
  return Number.isFinite(contentLength) && contentLength >= 0
    ? contentLength
    : null;
}

// Returns whether chunked http transfer.
function isChunkedHttpTransfer(packet = null) {
  const httpData = getCurrentHttpData(packet);
  return String(httpData?.["Transfer-Encoding"] || "")
    .toLowerCase()
    .includes("chunked");
}

// Handles hex to ascii string.
function hexToAsciiString(hex) {
  const normalized = typeof hex === "string" ? hex.replace(/\s+/g, "") : "";
  let result = "";
  for (let idx = 0; idx + 1 < normalized.length; idx += 2) {
    result += String.fromCharCode(Number.parseInt(normalized.slice(idx, idx + 2), 16));
  }
  return result;
}

// Handles slice complete chunked http body hex.
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

// Returns packet identity.
function getPacketIdentity(packet) {
  return (
    packet?.__packetKey ||
    packet?.["packet.info"]?.["index"] ||
    packet?.["packet.info"]?.["Index"] ||
    null
  );
}

// Returns whether same directional stream packet.
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

// Collects http body hex from stream.
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

// Returns current http body compression hint.
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

// Returns current packet for export.
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
  writeLogEntry(`Copied ${label} length = ${text.length}`);
}

// Returns ascii preview for hex offset.
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

// Handles copy selected text from context menu.
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
      writeLogEntry(`Copied selected text length = ${selectedText.length}`);
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

// Handles paste text from context menu.
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

// Saves json from context menu.
function saveJsonFromContextMenu() {
  hideConvertContextMenu();
  void persistSessionToDisk("context-menu");
}

function sanitizeFileNameForExport(name) {
  return String(name || "")
    .replace(/[\\/:*?"<>|]/g, "_")
    .replace(/\s+/g, "_")
    .slice(0, 100);
}

function formatDateTimeForFileName(date) {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate(),
  )}_${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(
    date.getSeconds(),
  )}`;
}

function getSummaryExportBaseName() {
  if (typeof currentSessionName === "string" && currentSessionName.trim()) {
    const sanitized = sanitizeFileNameForExport(currentSessionName.trim());
    if (sanitized) return sanitized;
  }
  const pcapFileName = sessionPcapSource?.fileName;
  if (typeof pcapFileName === "string" && pcapFileName.trim()) {
    const withoutExt = pcapFileName.replace(/\.[^./]+$/, "").trim();
    const sanitized = sanitizeFileNameForExport(withoutExt);
    if (sanitized) return sanitized;
  }
  return "summary";
}

function resizeAndCompressImageToJpegBase64(
  dataUrl,
  { maxWidth = 280, maxHeight = 350, quality = 0.78 } = {},
) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      let { width, height } = img;
      const scale = Math.min(maxWidth / width, maxHeight / height, 1);
      if (scale < 1) {
        width = Math.round(width * scale);
        height = Math.round(height * scale);
      }
      const canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext("2d");
      if (!ctx) {
        reject(new Error("Could not get 2d canvas context"));
        return;
      }
      ctx.drawImage(img, 0, 0, width, height);
      resolve(canvas.toDataURL("image/jpeg", quality));
    };
    img.onerror = () => reject(new Error("Failed to load image for resizing"));
    img.src = dataUrl;
  });
}

// Returns true when the given summary entry signature matches the decoded
// image's context. We match on packet key and Conv subtab prefix because the
// summary entry signature includes a data-content hash that may differ between
// the decode time and the compaction time.
function summarySignatureMatchesImage(entrySignature, image) {
  if (!entrySignature || !image) return false;
  const pktToken = image.packetKey ? `pkt:${image.packetKey}` : "";
  const dtToken = `dt:${image.convSubtab}:`;
  const mainTabToken = image.activeMainTab
    ? `tab:${image.activeMainTab}`
    : "";
  let matches = 0;
  if (pktToken && entrySignature.includes(pktToken)) matches += 1;
  if (entrySignature.includes(dtToken)) matches += 1;
  if (mainTabToken && entrySignature.includes(mainTabToken)) matches += 1;
  // Require at least the data-tools subtab match. If a packet key is known
  // it must also match; otherwise we still associate by subtab alone.
  if (matches >= 1 && entrySignature.includes(dtToken)) {
    if (pktToken) return matches >= 2;
    return true;
  }
  return false;
}

async function buildDecodedImageBlockHtml(image) {
  try {
    const compressed = await resizeAndCompressImageToJpegBase64(
      image.imageDataUrl,
    );
    const protocol = escapeHtml(String(image.protocol || "image"));
    const packetLabel = image.packetKey
      ? escapeHtml(String(image.packetKey))
      : "unspecified packet";
    return `<div class="summary-decoded-image">
  <p><strong>Decoded ${protocol}</strong> <span class="summary-image-meta">(${escapeHtml(
      String(image.mime || "image"),
    )}, packet ${packetLabel})</span></p>
  <img src="${compressed}" alt="Decoded ${protocol} from packet ${packetLabel}" class="summary-image">
</div>`;
  } catch (err) {
    console.warn("Failed to embed decoded image in HTML summary:", err);
    return "";
  }
}

// Builds the HTML body for the summary export by rendering each compacted
// summary entry separately and attaching any decoded images whose context
// matches that entry's signature. Falls back to a single section when no
// compacted summaries exist yet.
async function buildSummaryBodyHtmlForHtmlExport(summaryMarkdown) {
  const entries = Array.isArray(compactedAnalysisSummaries)
    ? compactedAnalysisSummaries
    : [];
  const registry =
    typeof getDecodedImageRegistry === "function"
      ? getDecodedImageRegistry()
      : [];

  // Pre-compress all registry images concurrently and remember which entries
  // each image is associated with.
  const imageBlocks = await Promise.all(registry.map(buildDecodedImageBlockHtml));
  const imagesWithBlock = registry
    .map((image, idx) => ({ image, block: imageBlocks[idx] }))
    .filter((entry) => Boolean(entry.block));

  if (entries.length === 0) {
    const bodyHtml = renderMarkdownToHtml(summaryMarkdown, {
      emptyPlaceholder: "No summary available",
    });
    const trailingImages = imagesWithBlock
      .map((entry) => entry.block)
      .join("\n");
    return `${bodyHtml}\n${trailingImages}`;
  }

  const sectionParts = [];
  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i] || {};
    const entryMarkdown = normalizeSummaryMarkdownHeadings(
      String(entry.summary || "").trim(),
    );
    const bodyHtml = renderMarkdownToHtml(
      entryMarkdown || "_No summary available._",
      { emptyPlaceholder: "No summary available" },
    );
    const entryImages = imagesWithBlock
      .filter((rec) => summarySignatureMatchesImage(entry.signature, rec.image))
      .map((rec) => rec.block)
      .join("\n");
    sectionParts.push(
      `<section class="summary-section" data-signature="${escapeHtml(
        String(entry.signature || ""),
      )}">\n${bodyHtml}\n${entryImages}\n</section>`,
    );
  }
  return sectionParts.join('\n<hr class="summary-section-divider">\n');
}

// Returns the minimum summary length (in characters) before the export-time
// LLM distillation pass is even attempted. Reports shorter than this are
// already concise enough that running the LLM over them would be wasteful.
const SUMMARY_DISTILL_MIN_LENGTH = 400;

// Returns the maximum number of characters of the source report that are
// fed into the export-time LLM distillation prompt. Anything beyond this is
// truncated from the tail to keep the prompt under the LLM context cap.
const SUMMARY_DISTILL_INPUT_MAX_CHARS = 60000;

// Returns the maximum number of characters of the LLM response that the
// distiller will keep. The truncated tail is dropped (with a marker) so
// runaway LLM output does not bloat the exported file.
const SUMMARY_DISTILL_OUTPUT_MAX_CHARS = 60000;

// Builds the prompt that asks the LLM to distil the final exported report.
// The LLM is told to:
//   1. Minimise repeated/redundant information across all sections.
//   2. Sort the entire report chronologically, anchoring each entry by the
//      earliest signal in the source data (protocol timestamp, packet index,
//      or session order).
//   3. Inside every main section, list the most security-relevant items
//      first so the analyst can see what stands out at a glance.
//   4. Keep the capture-level Stats section intact (it's the high-level
//      picture) but trim the LLM blurbs so they don't repeat it.
//   5. Return valid Markdown so downstream text/HTML export still works.
function buildSummaryDistillPrompt(reportMarkdown) {
  return [
    "You are PacketSnitch, a network forensics assistant.",
    "You are about to receive the full export report for a captured pcap.",
    "Your job is to produce the FINAL, distilled version of this report that the analyst will save to disk and read later.",
    "It is critical that you do not invent any facts — only reorganise and condense what is already present in the source report.",
    "",
    "Distillation rules — apply ALL of them:",
    "1. DEDUPLICATE: if the same fact, IP, port, credential, or finding appears more than once across any section, keep it ONCE in the most appropriate section. The Capture Statistics section often restates things the LLM blurbs also mention — make sure those facts live in only one place.",
    "2. CHRONOLOGICAL ORDER: re-sort the ENTIRE report in chronological order, using timestamps from the source data, packet indices, or session order as the anchor. When an event has no explicit timestamp, fall back to its position in the source. The Capture Statistics section stays at the top as the high-level overview, but everything below it should be in chronological order.",
    "3. SECTION HIGHLIGHTS: inside every main section, list the items that stand out as most important (security-relevant, anomalous, credential-bearing, or otherwise noteworthy) FIRST. Lesser findings follow.",
    "4. PRESERVE: keep all concrete data points the analyst may want to refer back to (IP addresses, ports, protocols, credentials, file names, URLs, hostnames, hashes, notable flags, masked credential values, etc.). Drop only redundant or low-value observations.",
    "5. STRUCTURE: keep valid Markdown headings, lists, and tables. Do not switch to HTML. Do not wrap the entire response in a single code fence. Do not print the report's top-level heading ('PacketSnitch's Summary') more than once — it is added automatically when the analyst reads the consolidated report, so any h1 in the source should be promoted to h2 or omitted.",
    "6. LENGTH: aim for a more compact report than the input. If the source is already concise, return it largely unchanged.",
    "7. SQUELCH NO-OP DATA: do not report decoders, parsers, extractors, lookups, or conversions that were attempted but failed, returned errors, or produced no usable output. If a decoder was opened but the operation did not yield data, omit it entirely from the distilled report instead of mentioning its absence. The same applies to empty hash fields, blank conversions, no-op extraction results, and failed subnet/whois/geoip/threat-intel lookups. Only describe activity that actually surfaced real content. Silence is preferable to a paragraph that just says 'nothing was found'.",
    "",
    "Here is the source report to distil:",
    "",
    "<<<SOURCE_REPORT_START>>>",
    reportMarkdown,
    "<<<SOURCE_REPORT_END>>>",
    "",
    "Now return the distilled report as Markdown. No preamble, no explanation, no closing remarks — just the report itself.",
  ].join("\n");
}

// Reasons the distiller may skip the LLM pass. Returned alongside the
// (unchanged) input so the caller can surface a meaningful status update.
const SUMMARY_DISTILL_SKIP_EMPTY = "empty";
const SUMMARY_DISTILL_SKIP_TOO_SHORT = "too_short";
const SUMMARY_DISTILL_SKIP_RUNTIME_DISABLED = "runtime_disabled";
const SUMMARY_DISTILL_SKIP_SETTINGS_DISABLED = "settings_disabled";
const SUMMARY_DISTILL_SKIP_PROMPT_TOO_LONG = "prompt_too_long";
const SUMMARY_DISTILL_SKIP_LLM_EMPTY = "llm_empty";
const SUMMARY_DISTILL_OK = "ok";
const SUMMARY_DISTILL_ERROR = "error";

// Distils the final export report through the LLM. This is a single-pass
// dedupe / chronological-sort / re-rank operation that runs after the LLM
// has already produced the per-stream and compaction summaries and after
// the Stats panel data has been appended. Returns an object describing
// the outcome so the caller can surface a useful status message:
//   { status: <reason>, text: <distilled-or-original markdown>, reason?: <string> }
// The `text` field is always a non-empty string the caller can use as the
// final export content (either the LLM's distilled report or the original
// input if the distiller was skipped or failed).
async function distillSummaryMarkdownWithLLM(summaryMarkdown) {
  const reportResult = (text, status, reason) => ({
    text,
    status,
    ...(reason ? { reason } : {}),
  });
  if (!summaryMarkdown || typeof summaryMarkdown !== "string") {
    return reportResult(summaryMarkdown, SUMMARY_DISTILL_SKIP_EMPTY);
  }
  const trimmed = summaryMarkdown.trim();
  if (trimmed.length < SUMMARY_DISTILL_MIN_LENGTH) {
    const reason = `report length ${trimmed.length} below threshold ${SUMMARY_DISTILL_MIN_LENGTH}`;
    writeLogEntry(`Summary distill skipped: ${reason}`);
    return reportResult(
      summaryMarkdown,
      SUMMARY_DISTILL_SKIP_TOO_SHORT,
      reason,
    );
  }
  if (typeof isLlmRuntimeEnabled === "function" && !isLlmRuntimeEnabled()) {
    const reason = "isLlmRuntimeEnabled() returned false";
    writeLogEntry(`Summary distill skipped: ${reason}`);
    return reportResult(
      summaryMarkdown,
      SUMMARY_DISTILL_SKIP_RUNTIME_DISABLED,
      reason,
    );
  }
  if (
    typeof isLlmEnabledInSettings === "function" &&
    !isLlmEnabledInSettings()
  ) {
    const reason = "LLM is not enabled in settings";
    writeLogEntry(`Summary distill skipped: ${reason}`);
    return reportResult(
      summaryMarkdown,
      SUMMARY_DISTILL_SKIP_SETTINGS_DISABLED,
      reason,
    );
  }
  let truncatedInput = trimmed;
  if (truncatedInput.length > SUMMARY_DISTILL_INPUT_MAX_CHARS) {
    truncatedInput =
      truncatedInput.slice(0, SUMMARY_DISTILL_INPUT_MAX_CHARS) +
      "\n\n[INPUT TRUNCATED: source report too long for distillation prompt]";
  }
  const prompt = buildSummaryDistillPrompt(truncatedInput);
  if (prompt.length >= LLM_MAX_CONTENT_LENGTH) {
    const reason = `prompt length ${prompt.length} exceeds LLM_MAX_CONTENT_LENGTH ${LLM_MAX_CONTENT_LENGTH}`;
    writeLogEntry(`Summary distill skipped: ${reason}`);
    return reportResult(
      summaryMarkdown,
      SUMMARY_DISTILL_SKIP_PROMPT_TOO_LONG,
      reason,
    );
  }
  writeLogEntry(
    `Summary distill: invoking LLM with prompt length ${prompt.length} chars for report of ${trimmed.length} chars`,
  );
  try {
    const llmResponse = await callLargeLanguageModelWithRetry(prompt);
    const distilled = String(llmResponse?.response || "").trim();
    if (!distilled) {
      const reason = "LLM returned an empty response";
      writeLogEntry(`Summary distill skipped: ${reason}`);
      return reportResult(
        summaryMarkdown,
        SUMMARY_DISTILL_SKIP_LLM_EMPTY,
        reason,
      );
    }
    let finalDistilled = distilled;
    if (finalDistilled.length > SUMMARY_DISTILL_OUTPUT_MAX_CHARS) {
      finalDistilled =
        finalDistilled.slice(0, SUMMARY_DISTILL_OUTPUT_MAX_CHARS) +
        "\n\n[OUTPUT TRUNCATED: distilled report exceeded output cap]";
    }
    writeLogEntry(
      `Summary distill completed: input=${trimmed.length} chars output=${finalDistilled.length} chars`,
    );
    return reportResult(finalDistilled, SUMMARY_DISTILL_OK);
  } catch (error) {
    const reason = error?.message || String(error);
    writeLogEntry(`Summary distill failed: ${reason}`);
    return reportResult(
      summaryMarkdown,
      SUMMARY_DISTILL_ERROR,
      reason,
    );
  }
}

// Signature used to mark distilled summaries in `compactedAnalysisSummaries`.
// The presence of this prefix lets the export code identify and replace
// previous distilled entries so a subsequent export doesn't keep stacking
// distilled versions on top of older distilled versions.
const SUMMARY_DISTILL_ENTRY_SIGNATURE = "__distilled__";

// Pushes the distilled report into the running Summary tab so the analyst
// can see the cleaned-up version of their pcap analysis in the UI before
// (or after) the file is saved. The distilled entry replaces any prior
// distilled entry so repeated exports don't keep stacking distilled
// versions. Non-distilled context-scoped entries are kept untouched.
function pushDistilledSummaryIntoSummaryTab(distilledText) {
  if (
    !distilledText ||
    typeof distilledText !== "string" ||
    !distilledText.trim()
  ) {
    return false;
  }
  if (!Array.isArray(compactedAnalysisSummaries)) {
    compactedAnalysisSummaries = [];
  }
  // Drop any prior distilled entry — we only ever keep the most recent
  // distilled snapshot in the running summary. Context-scoped entries
  // (the ones produced by runAnalysisCompaction) are preserved so the
  // analyst can still see how the LLM derived its findings.
  const contextEntries = compactedAnalysisSummaries.filter(
    (entry) =>
      entry &&
      typeof entry === "object" &&
      entry.signature !== SUMMARY_DISTILL_ENTRY_SIGNATURE,
  );
  // The consolidated distilled summary is the headline output for the
  // analyst, so it sits at the top of the summary stream. Everything
  // already there (per-context compaction entries) is kept in its
  // original order *below* the distilled block so the consolidated view
  // is up front and center while the supporting context is still
  // visible underneath.
  compactedAnalysisSummaries = [
    {
      signature: SUMMARY_DISTILL_ENTRY_SIGNATURE,
      summary: distilledText.trim(),
      lastUpdatedAt: Date.now(),
    },
    ...contextEntries,
  ];
  try {
    renderCombinedAnalysisSummary();
  } catch (err) {
    writeLogEntry(
      `pushDistilledSummaryIntoSummaryTab: render failed: ${err?.message || err}`,
    );
  }
  return true;
}

// Saves summary output from context menu.
async function saveSummaryFromContextMenu(format = "markdown") {
  const normalizedFormat =
    format === "text" ? "text" : format === "html" ? "html" : "markdown";
  const rawSummaryMarkdown = getSummaryMarkdownForExport();
  const summaryBaseName = getSummaryExportBaseName();
  const summaryTimestamp = formatDateTimeForFileName(new Date());
  hideConvertContextMenu();
  if (!rawSummaryMarkdown.trim()) {
    statusUpdate("Status: No summary available to export");
    return;
  }

  // Run one more LLM pass over the entire assembled report to dedupe,
  // sort chronologically, and re-rank items by importance. The save dialog
  // is only opened AFTER the LLM returns so the file the user sees in the
  // dialog is the distilled version. If the LLM is disabled, fails, or
  // the report is too short to warrant a pass, the distiller returns the
  // original markdown unchanged.
  const canDistill =
    typeof isLlmRuntimeEnabled === "function"
      ? isLlmRuntimeEnabled()
      : false;
  let summaryMarkdown = rawSummaryMarkdown;
  if (canDistill) {
    statusUpdate("Status: Distilling export report via LLM...");
  }
  let distillOutcome = {
    text: rawSummaryMarkdown,
    status: SUMMARY_DISTILL_SKIP_EMPTY,
  };
  try {
    distillOutcome = await distillSummaryMarkdownWithLLM(rawSummaryMarkdown);
  } catch (error) {
    // Defensive fallback: if the distiller itself throws (e.g. an
    // unexpected runtime error), fall back to the un-distilled report so
    // the user can still save their work.
    writeLogEntry(
      `Summary distill threw, using original report: ${error?.message || error}`,
    );
    distillOutcome = {
      text: rawSummaryMarkdown,
      status: SUMMARY_DISTILL_ERROR,
      reason: error?.message || String(error),
    };
  }
  summaryMarkdown = distillOutcome.text;
  // If the distiller produced a real distilled report, push it into the
  // Summary tab so the analyst can see the cleaned-up version in the UI
  // before the file is saved. We then re-pull the export markdown from
  // the Summary tab so the save dialog matches what the user just saw
  // on screen (this also makes the Stats section show the most recent
  // captured-packets view, in case anything has changed since the
  // initial pull).
  if (distillOutcome.status === SUMMARY_DISTILL_OK) {
    const pushed = pushDistilledSummaryIntoSummaryTab(summaryMarkdown);
    if (pushed) {
      summaryMarkdown = getSummaryMarkdownForExport();
    }
  }
  // Surface a clear status message so the user knows whether the LLM
  // actually distilled the report or whether the export is the raw
  // summary. Silent fallbacks were confusing in practice.
  if (distillOutcome.status === SUMMARY_DISTILL_OK) {
    const inputChars = rawSummaryMarkdown.trim().length;
    const outputChars = summaryMarkdown.trim().length;
    const delta = inputChars - outputChars;
    const deltaLabel = delta > 0 ? `−${delta}` : `+${Math.abs(delta)}`;
    statusUpdate(
      `Status: LLM distilled report (${inputChars} → ${outputChars} chars, ${deltaLabel}). Summary tab updated.`,
    );
  } else if (canDistill) {
    // LLM runtime is enabled but the distiller returned the original —
    // tell the user why so they know it wasn't actually distilled.
    const reason = distillOutcome.reason || distillOutcome.status;
    statusUpdate(`Status: Export not distilled (${reason}).`);
  }

  let exportText;
  let title;
  let defaultName;
  let defaultExtension;
  let filters;
  let statusLabel;

  if (normalizedFormat === "text") {
    exportText = convertSummaryMarkdownToPlainText(summaryMarkdown);
    title = "Export Summary (Text)";
    defaultName = `packetsnitch-${summaryBaseName}-${summaryTimestamp}.txt`;
    defaultExtension = "txt";
    filters = [
      { name: "Text Files", extensions: ["txt"] },
      { name: "All Files", extensions: ["*"] },
    ];
    statusLabel = "text";
  } else if (normalizedFormat === "html") {
    let logoSrc = "";
    if (
      window.saveapi &&
      typeof window.saveapi.getAssetBase64 === "function"
    ) {
      try {
        const logoResult = await window.saveapi.getAssetBase64(
          "logo/packet-snitch-tag-transp.png",
        );
        if (logoResult?.success && logoResult.data && logoResult.mime) {
          logoSrc = `data:${logoResult.mime};base64,${logoResult.data}`;
        }
      } catch (err) {
        console.warn("Failed to load logo for HTML summary export:", err);
      }
    }
    const bodyHtml = await buildSummaryBodyHtmlForHtmlExport(summaryMarkdown);
    const logoHtml = logoSrc
      ? `<img src="${logoSrc}" alt="PacketSnitch logo" class="summary-logo">`
      : "";
    const generatedDate = new Date().toLocaleString();
    exportText = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PacketSnitch Summary</title>
<style>
body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.6; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #222; }
h1, h2, h3, h4 { font-weight: 600; }
pre { background: #f5f5f5; padding: 0.75rem; overflow-x: auto; }
code { background: #f0f0f0; padding: 0.15rem 0.3rem; border-radius: 3px; }
blockquote { border-left: 4px solid #ccc; margin-left: 0; padding-left: 1rem; color: #555; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ddd; padding: 0.5rem; text-align: left; }
th { background: #f5f5f5; }
.summary-header { text-align: center; margin-bottom: 2rem; border-bottom: 1px solid #ddd; padding-bottom: 1rem; }
.summary-logo { max-width: 280px; height: auto; margin-bottom: 0.75rem; }
.summary-meta { color: #666; font-size: 0.9rem; margin: 0; }
.summary-meta a { color: #007acc; text-decoration: none; }
.summary-meta a:hover { text-decoration: underline; }
.summary-decoded-image { text-align: center; margin: 1.5rem 0; }
.summary-decoded-image p { margin: 0 0 0.5rem; color: #444; }
.summary-image { max-width: 280px; max-height: 350px; width: auto; height: auto; object-fit: contain; border: 1px solid #ddd; border-radius: 4px; }
.summary-image-meta { color: #888; font-size: 0.85rem; }
.summary-section { margin-bottom: 1.5rem; }
.summary-section-divider { border: none; border-top: 1px solid #ddd; margin: 2rem 0; }
</style>
</head>
<body>
<div class="summary-header">
  ${logoHtml}
  <p class="summary-meta">Generated by PacketSnitch ${PACKETSNITCH_VERSION} on ${generatedDate} — <a href="https://packetsnitch.com" target="_blank" rel="noopener noreferrer">packetsnitch.com</a></p>
</div>
${bodyHtml}
</body>
</html>`;
    title = "Export Summary (HTML)";
    defaultName = `packetsnitch-${summaryBaseName}-${summaryTimestamp}.html`;
    defaultExtension = "html";
    filters = [
      { name: "HTML Files", extensions: ["html", "htm"] },
      { name: "All Files", extensions: ["*"] },
    ];
    statusLabel = "HTML";
  } else {
    exportText = summaryMarkdown;
    title = "Export Summary (Markdown)";
    defaultName = `packetsnitch-${summaryBaseName}-${summaryTimestamp}.md`;
    defaultExtension = "md";
    filters = [
      { name: "Markdown Files", extensions: ["md"] },
      { name: "Text Files", extensions: ["txt"] },
      { name: "All Files", extensions: ["*"] },
    ];
    statusLabel = "markdown";
  }

  window.saveapi
    .saveText({
      text: exportText,
      title,
      defaultName,
      defaultExtension,
      filters,
    })
    .then((result) => {
      if (result.canceled) {
        statusUpdate("Status: Export cancelled");
      } else if (result.success) {
        statusUpdate(`Status: Summary exported as ${statusLabel}`);
        writeLogEntry(
          `Context menu summary export completed format=${normalizedFormat}`,
        );
      } else {
        const errorMessage =
          result && typeof result === "object" && "error" in result
            ? result.error
            : "unknown";
        doError("Summary export failed");
        logErrorEntry("export-summary", errorMessage || "unknown");
        statusUpdate(
          `Status: Summary export failed - ${errorMessage || "unknown error"}`,
        );
      }
    });
}

async function currentPacketToConvJson() {
  const contextPacket = getCurrentContextPacket();
  writeLogEntry(`Logged raw packet JSON at index = ${contextPacket?.["packet.info"]?.["index"] ?? contextPacket?.["packet.info"]?.["Index"] ?? "unknown"} to Conv subtab`);

  // turn it into json object
  const packet = contextPacket || {};
  const jsonString = JSON.stringify(packet, null, getConvJsonIndentSpaces());

  const jsonContainer = document.getElementById("data-tools-packet-json-output");
  jsonContainer.innerHTML = "";
  const jsonLines = jsonString.split("\n");
  const currentPacketEl = document.getElementById("data-tools-packet-json-current-packet");
  currentPacketEl.textContent = `Current packet at index: ${contextPacket?.["packet.info"]?.["index"] ?? contextPacket?.["packet.info"]?.["Index"] ?? "unknown"}`;
  jsonLines.forEach((line) => {
    const lineEl = document.createElement("pre");
    // this prevents blank line after each <pre> element
    lineEl.style.margin = "0";
    lineEl.className = "json-line";
    lineEl.innerHTML = syntaxHighlightJsonLine(line);
    jsonContainer.appendChild(lineEl);
  });
  // make sure that only a single newline is made, so strip any trailing newlines
  while (jsonContainer.lastChild && jsonContainer.lastChild.textContent === "") {
    jsonContainer.removeChild(jsonContainer.lastChild);
  }
  function syntaxHighlightJsonLine(line) {
    const regex = /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b|[\{\}\[\]]|:|\s+)/g;
    if (line.trim() === "") {
      return '<span class="json-newline">&nbsp;</span>';
    }

    const escapeToken = (text) =>
      text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");

    return line.replace(regex, (match) => {
      if (/^\s+$/.test(match)) {
        return match.replace(/ /g, "&nbsp;").replace(/\t/g, "&nbsp;&nbsp;&nbsp;&nbsp;");
      }

      const toNbsp = (text) => text.replace(/ /g, "&nbsp;").replace(/\t/g, "&nbsp;&nbsp;&nbsp;&nbsp;");

      const keyTokenMatch = match.match(/^"([\s\S]*)"(\s*:)$/);
      if (keyTokenMatch) {
        return (
          '<span class="json-quote">"</span>' +
          `<span class="json-key">${escapeToken(keyTokenMatch[1])}</span>` +
          '<span class="json-quote">"</span>' +
          `<span class="json-colon">${toNbsp(escapeToken(keyTokenMatch[2]))}</span>`
        );
      }

      const stringTokenMatch = match.match(/^"([\s\S]*)"$/);
      if (stringTokenMatch) {
        return (
          '<span class="json-quote">"</span>' +
          `<span class="json-string">${escapeToken(stringTokenMatch[1])}</span>` +
          '<span class="json-quote">"</span>'
        );
      }

      let cls = "json-quote";
      if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(match)) {
        cls = "json-number";
      } else if (/^(true|false)$/.test(match)) {
        cls = "json-boolean";
      } else if (/^null$/.test(match)) {
        cls = "json-null";
      } else if (/^[\{\}]$/.test(match)) {
        cls = "json-brace";
      } else if (/^[\[\]]$/.test(match)) {
        cls = "json-bracket";
      } else if (/^:$/.test(match)) {
        cls = "json-colon";
      }

      return `<span class="${cls}">${escapeToken(match)}</span>`;
    });
  }
}


// Exports current packet from context menu.
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

// Exports current payload from context menu.
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

// Returns whether likely printable utf8.
function isLikelyPrintableUtf8(value) {
  return /^[\x09\x0A\x0D\x20-\x7E]*$/.test(String(value || ""));
}

// Returns crypt decrypted export candidate.
function getCryptDecryptedExportCandidate(target = activeContextTarget) {
  if (activeMainTab !== MAIN_TAB_CRYPT) return null;
  const targetEl = target instanceof Element ? target : null;
  const isTlsPreviewTarget = Boolean(
    targetEl?.closest?.("#crypt-decrypt-preview"),
  );
  const isPgpPreviewTarget = Boolean(
    targetEl?.closest?.("#crypt-pgp-output-preview"),
  );
  if (!isTlsPreviewTarget && !isPgpPreviewTarget) {
    return null;
  }

  if (isTlsPreviewTarget) {
    const tlsPayload = getLastTlsDecryptedPayload();
    if (!tlsPayload) return null;
    const utf8Value = String(tlsPayload.utf8Value || "");
    const hexValue = String(tlsPayload.hexValue || "");
    return {
      type: "tls",
      sourceLabel: tlsPayload.sourceLabel || "TLS payload",
      utf8Value,
      hexValue,
      preferText: Boolean(utf8Value) && isLikelyPrintableUtf8(utf8Value),
    };
  }

  const pgpPayload = getLastPgpOutputPayload();
  if (!pgpPayload) return null;
  return {
    type: "pgp",
    sourceLabel: pgpPayload.sourceLabel || "PGP output",
    utf8Value: String(pgpPayload.utf8Value || ""),
    hexValue: String(pgpPayload.hexValue || ""),
    preferText: true,
  };
}

// Exports decrypted data from context menu.
function exportDecryptedDataFromContextMenu() {
  const exportCandidate = getCryptDecryptedExportCandidate();
  hideConvertContextMenu();
  if (!exportCandidate) {
    statusUpdate("Status: No decrypted data available to export");
    return;
  }

  if (exportCandidate.preferText && exportCandidate.utf8Value) {
    window.saveapi
      .saveText({
        text: exportCandidate.utf8Value,
        title:
          exportCandidate.type === "pgp"
            ? "Export Decrypted PGP Data"
            : "Export Decrypted TLS Data",
        defaultName:
          exportCandidate.type === "pgp"
            ? "decrypted-pgp-output.txt"
            : "decrypted-tls-output.txt",
      })
      .then((result) => {
        if (result.canceled) {
          statusUpdate("Status: Export cancelled");
        } else if (result.success) {
          statusUpdate("Status: Decrypted data exported successfully");
          writeLogEntry(
            `Context menu decrypted export completed type=${exportCandidate.type} mode=text source=${exportCandidate.sourceLabel}`,
          );
        } else {
          const errorMessage =
            result && typeof result === "object" && "error" in result
              ? result.error
              : "unknown";
          doError("Decrypted data export failed");
          logErrorEntry("export-decrypted", errorMessage || "unknown");
          statusUpdate(
            `Status: Decrypted data export failed - ${errorMessage || "unknown error"}`,
          );
        }
      });
    return;
  }

  if (!exportCandidate.hexValue) {
    statusUpdate("Status: No decrypted binary data available to export");
    return;
  }

  window.saveapi.savePayload(exportCandidate.hexValue).then((result) => {
    if (result.canceled) {
      statusUpdate("Status: Export cancelled");
    } else if (result.success) {
      statusUpdate("Status: Decrypted binary data exported successfully");
      writeLogEntry(
        `Context menu decrypted export completed type=${exportCandidate.type} mode=raw source=${exportCandidate.sourceLabel}`,
      );
    } else {
      const errorMessage =
        result && typeof result === "object" && "error" in result
          ? result.error
          : "unknown";
      doError("Decrypted data export failed");
      logErrorEntry("export-decrypted", errorMessage || "unknown");
      statusUpdate(
        `Status: Decrypted data export failed - ${errorMessage || "unknown error"}`,
      );
    }
  });
}

// Saves cookie jar from context menu.
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

// Returns http content type for current packet.
function getHttpContentTypeForCurrentPacket(packet = null) {
  const httpData = getCurrentHttpData(packet);
  return (httpData && httpData["Content-Type"]) || "application/octet-stream";
}

// Saves http body from context menu.
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
    decompressLabel = ` decompressed algorithm = ${decompressionCandidate.algorithm}`;
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

// Loads http body into conv tab from context menu.
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
    decompressLabel = ` decompressed algorithm = ${decompressionCandidate.algorithm}`;
  }
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  const httpBytes = hexStringToUint8Array(outputHex);
  dataToolsContextPacket = contextPacket;
  dataToolsOriginalInputBytes = httpBytes;
  dataToolsInputEditedFlag = false;
  clearDataToolsStreamPackets();
  dataToolsLastConversionBytes = httpBytes;
  inputEl.value = formatHexInputBytesWithCap(httpBytes);
  formatEl.value = "hex";
  setDataToolsFileNameGuess(
    guessHttpBodyFilenameFromPacket(
      contextPacket,
      decompress ? "http-body-decompressed" : "http-body",
    ),
  );
  markDataToolsInputCommitted();
  showDataTools();
  runDataToolsConversion();
  writeLogEntry(
    `Context menu loaded HTTP body into Conv tab${decompressLabel}`,
  );
}

// Handles preview http body in browser from context menu.
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
    decompressLabel = ` decompressed algorithm = ${decompressionCandidate.algorithm}`;
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

// Handles append filter query from context menu.
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
    `Context menu filter populated type = ${type} negated = ${negate} query = "${filterInputEl.value}"`,
  );
}

// Clears and filter query from context menu.
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
    `Context menu filter cleared and populated type = ${type} query = "${filterInputEl.value}"`,
  );
}

// Handles append parenthesis token from context menu.
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
    `Context menu filter appended token = "${token}" query = "${filterInputEl.value}"`,
  );
}

// Handles wrap current filter with parentheses from context menu.
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
  writeLogEntry(`Context menu filter wrapped query = "${filterInputEl.value}"`);
}

initConvPanel({
  writeLogEntry,
  statusUpdate,
  setActiveMainTab: (tab) => {
    activeMainTab = tab;
  },
  getCurrentContextPacket,
  getActiveMainTab: () => activeMainTab,
  callLargeLanguageModel,
  isLlmRuntimeEnabled,
  isBackgroundSummaryGenerationEnabled,
  appendAnalysisBlub,
});

const subnetCalculatorPanel = createSubnetCalculatorPanel({
  statusUpdate,
  writeLogEntry,
  addNote,
  showNotesWorkspace,
  getBackendTransportOptions: () => getBackendTransportOptionsFromSettings(),
  getCurrentSettings: () => getCurrentSettings(),
  getCapturePackets: () => capturedPackets,
  getCarvableFiles: () => extractionCarvableRegistry.slice(),
  getCurrentConvInputBytes: () => {
    try {
      return getCurrentDataToolsInputBytes();
    } catch (_error) {
      return null;
    }
  },
  isLlmRuntimeEnabled,
  callLargeLanguageModel,
  openHeatmapLocation: ({ latitude, longitude, label }) => {
    showStatsHeatmapLocation({ latitude, longitude, label });
  },
  getCurrentPacketIps: () => {
    const contextPacket = getCurrentContextPacket();
    const packetInfo = contextPacket?.["packet.info"] || {};
    const ipInfo = packetInfo["IP"] || {};
    return {
      src: String(ipInfo["ip.src.addr"] ?? ipInfo["Source IP"] ?? "").trim(),
      dst: String(ipInfo["ip.dst.addr"] ?? ipInfo["Destination IP"] ?? "").trim(),
    };
  },
  onSummaryRequested: () => requestDataToolsBackgroundSummary(CONV_SUBNET_SUBTAB),
});

document.getElementById("close-btn").addEventListener("click", () => {
  void requestApplicationClose();
});

// Show capture stats when stats button is clicked
document.getElementById("stats-btn").addEventListener("click", function () {
  if (!isFileLoaded) {
    doError("Please upload a JSON file before accessing packet statistics.");
    return;
  }
  const activeEntries = keystorePanel.getActiveCryptKeystoreEntries();
  // check the entries to only return the number of passwords (not usernames, not cookies, etc)
  const passwordEntries = activeEntries.filter(entry => entry.label && entry.label.toLowerCase().includes("password"));
  // now unique it
  const uniquePasswords = new Set(passwordEntries.map(entry => entry.content));
  window.keystoreCreds = uniquePasswords;
  showStats();
});

document.getElementById("help-btn").addEventListener("click", async function () {
  // if the window is already open, make sure it doesn't get opened again, just focus it
  if (helpWin != null && !helpWin.closed) {
    // bring the help window back in front of the main window
    helpWin.blur();
    window.focus();
    return;
  }
  // open the help page in PacketSnitch's own in-app browser window.
  // Unlike the rest of the in-app links (release notes, donate, theme
  // catalog, VirusTotal card, etc.), which route to the user's default
  // system browser via ``shell.openExternal`` so the user keeps their
  // existing browser session, the Help button is the one link that
  // should stay anchored inside PacketSnitch. The main process hooks
  // ``mainWindow.webContents.on('did-create-window', ...)`` (see
  // ``src/main.js``) to lock this child window to the whitelisted docs
  // domains, resize it to 1200x900, strip the menu bar, and tag it
  // with the desktop user-agent. Using ``window.open`` here is what
  // triggers that handler; routing through ``shell.openExternal``
  // would bypass it and pop the docs in the user's default browser
  // instead.
  const helpUrl = "https://packetsnitch.com/docu/";
  writeLogEntry("Opening help page in PacketSnitch browser: " + helpUrl);
  helpWin = window.open(helpUrl, "_blank");
  // if the window is closed, set helpWin to null
  if (helpWin) {
    helpWin.addEventListener("beforeunload", () => {
      helpWin = null;
    });
  } else {
    helpWin = null;
  }
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
    if (
      keystorePanel.getKeystoreMode() === CRYPT_KEYSTORE_MODE_PERSISTENT &&
      !keystorePanel.isUnlocked()
    ) {
      const unlocked = await keystorePanel.unlockPersistentKeystoreAndLoad();
      if (!unlocked) return;
    }
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
document
  .getElementById("ctx-llm-question-confirm-btn")
  .addEventListener("click", submitLlmQuestionFromContextMenuDialog);
document
  .getElementById("saved-filter-label-confirm-btn")
  .addEventListener("click", submitSavedFilterLabelDialog);
document
  .getElementById("saved-filter-label-remove-btn")
  .addEventListener("click", () => {
    void removeSavedFilterFromLabelDialog();
  });
document
  .getElementById("saved-filter-label-cancel-btn")
  .addEventListener("click", () =>
    resolveSavedFilterLabelDialog({ action: "cancel" }),
  );
document
  .getElementById("saved-filter-label-input")
  .addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      submitSavedFilterLabelDialog();
      return;
    }
    if (event.key === "Escape") {
      resolveSavedFilterLabelDialog({ action: "cancel" });
    }
  });
document
  .getElementById("ctx-llm-question-cancel-btn")
  .addEventListener("click", () => resolveLlmQuestionFromContextMenuDialog(null));
document
  .getElementById("ctx-llm-question-input")
  .addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    submitLlmQuestionFromContextMenuDialog();
  });
document
  .getElementById("follow-stream-confirm-continue-btn")
  .addEventListener("click", () => resolveFollowStreamContextMenuLoad(true));
document
  .getElementById("follow-stream-confirm-cancel-btn")
  .addEventListener("click", () => resolveFollowStreamContextMenuLoad(false));
document
  .getElementById("follow-stream-confirm-dialog")
  .addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      resolveFollowStreamContextMenuLoad(true);
      return;
    }
    if (event.key === "Escape") {
      resolveFollowStreamContextMenuLoad(false);
    }
  });

document
  .getElementById("manual-conv-import-warning-continue-btn")
  .addEventListener("click", () => resolveManualConvImportWarningLoad(true));
document
  .getElementById("manual-conv-import-warning-cancel-btn")
  .addEventListener("click", () => resolveManualConvImportWarningLoad(false));
document
  .getElementById("info-message-dialog-ok-btn")
  .addEventListener("click", resolveInfoDialog);
document
  .getElementById("info-message-dialog-send-to-notes-btn")
  ?.addEventListener("click", () => {
    const currentLinkUrl = document.getElementById("info-message-dialog-link")?.href;
    if (!currentLinkUrl || currentLinkUrl === "#") {
      statusUpdate("Status: No report link available to add");
      return;
    }
    const noteText = `VirusTotal record: ${currentLinkUrl}`;
    const didAdd = addNote(noteText, NOTE_DEFAULT_COLOR, "virustotal-link", false);
    if (didAdd) {
      showNotesWorkspace();
      statusUpdate("Status: VirusTotal link added to Notes");
      writeLogEntry(`VirusTotal link added to notes link=${JSON.stringify(currentLinkUrl)}`);
      resolveInfoDialog();
    }
  });
document
  .getElementById("info-message-dialog")
  .addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === "Escape") {
      resolveInfoDialog();
    }
  });
document
  .getElementById("manual-conv-import-warning-dialog")
  .addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      resolveManualConvImportWarningLoad(true);
      return;
    }
    if (event.key === "Escape") {
      resolveManualConvImportWarningLoad(false);
    }
  });

document
  .getElementById("settings-reset-confirm-continue-btn")
  .addEventListener("click", () => resolveSettingsResetConfirm(true));
document
  .getElementById("settings-reset-confirm-cancel-btn")
  .addEventListener("click", () => resolveSettingsResetConfirm(false));
document
  .getElementById("settings-reset-confirm-dialog")
  .addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      resolveSettingsResetConfirm(true);
      return;
    }
    if (event.key === "Escape") {
      resolveSettingsResetConfirm(false);
    }
  });

document
  .getElementById("plugin-install-capability-confirm-btn")
  .addEventListener("click", () => resolvePluginInstallCapabilityDialog(true));
document
  .getElementById("plugin-install-capability-cancel-btn")
  .addEventListener("click", () => resolvePluginInstallCapabilityDialog(false));
document
  .getElementById("plugin-install-capability-dialog")
  .addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      resolvePluginInstallCapabilityDialog(true);
      return;
    }
    if (event.key === "Escape") {
      resolvePluginInstallCapabilityDialog(false);
    }
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

document.getElementById("settings-btn").addEventListener("click", function () {
  showSettingsWorkspace();
});

document.getElementById("settings-save-btn").addEventListener("click", () => {
  void persistSettingsFromForm();
});

document.getElementById("settings-reset-btn").addEventListener("click", async () => {
  const shouldReset = await requestSettingsResetConfirm();
  if (!shouldReset) {
    setSettingsStatus("Restore defaults canceled.");
    return;
  }
  await persistSettingsFromForm({ resetToDefaults: true });
});

document.getElementById("settings-subtab-general").addEventListener("click", () => {
  setSettingsSubtab(SETTINGS_SUBTAB_GENERAL);
});

document.getElementById("settings-subtab-llm").addEventListener("click", () => {
  setSettingsSubtab(SETTINGS_SUBTAB_LLM);
});

document.getElementById("settings-subtab-api-keys").addEventListener("click", () => {
  setSettingsSubtab(SETTINGS_SUBTAB_API_KEYS);
});

document.getElementById("settings-subtab-backend").addEventListener("click", () => {
  setSettingsSubtab(SETTINGS_SUBTAB_BACKEND);
});

document.getElementById("settings-subtab-debug").addEventListener("click", () => {
  setSettingsSubtab(SETTINGS_SUBTAB_DEBUG);
});

document.getElementById("settings-subtab-plugins").addEventListener("click", () => {
  setSettingsSubtab(SETTINGS_SUBTAB_PLUGINS);
});

document.getElementById("settings-subtab-themes").addEventListener("click", () => {
  setSettingsSubtab(SETTINGS_SUBTAB_THEMES);
});

document.getElementById("settings-subtab-privacy").addEventListener("click", () => {
  setSettingsSubtab(SETTINGS_SUBTAB_PRIVACY);
});

document.getElementById("settings-subtab-about").addEventListener("click", () => {
  setSettingsSubtab(SETTINGS_SUBTAB_ABOUT);
});

document.getElementById("settings-about-refresh-btn").addEventListener("click", () => {
  void loadSettingsAboutReleaseInfo({ forceRefresh: true });
});

document.getElementById("settings-about-download-btn").addEventListener("click", () => {
  void openSettingsAboutDownloadUrl();
});

document.getElementById("settings-general-conv-json-indent").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated convJsonIndentSpaces=${event?.target?.value}`);
});

document.getElementById("settings-general-status-reset-seconds").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated statusResetSeconds=${event?.target?.value}`);
});

document
  .getElementById("settings-plugins-auto-disable-failure-threshold")
  .addEventListener("change", (event) => {
    writeLogEntry(`Settings updated pluginAutoDisableFailureThreshold=${event?.target?.value}`);
  });

document.getElementById("settings-plugins-install-btn").addEventListener("click", () => {
  void installPluginFromSettingsAction();
});

document.getElementById("settings-plugins-refresh-btn").addEventListener("click", () => {
  void refreshPluginRegistryView();
});

document.getElementById("settings-plugins-clear-errors-btn").addEventListener("click", () => {
  clearPluginErrors();
});

document.getElementById("settings-backend-chunk-size").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated backendPacketChunkSize=${event?.target?.value}`);
});

document
  .getElementById("settings-backend-worker-threads")
  .addEventListener("change", (event) => {
    writeLogEntry(`Settings updated backendWorkerThreads=${event?.target?.value}`);
  });

document
  .getElementById("settings-general-stream-warn-packet-threshold")
  .addEventListener("change", (event) => {
    writeLogEntry(`Settings updated streamContextWarnPacketThreshold=${event?.target?.value}`);
  });

document
  .getElementById("settings-general-nmap-service-scan-enabled")
  .addEventListener("change", (event) => {
    writeLogEntry(
      `Settings updated nmapServiceScanEnabled=${Boolean(event?.target?.checked)}`,
    );
  });

document
  .getElementById("settings-general-check-for-new-releases-on-startup")
  .addEventListener("change", (event) => {
    writeLogEntry(
      `Settings updated checkForNewReleasesOnStartup=${Boolean(event?.target?.checked)}`,
    );
  });

document.getElementById("settings-backend-tcp-host").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated backendTcpHost=${JSON.stringify(event?.target?.value || "")}`);
});

document.getElementById("settings-backend-tcp-port").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated backendTcpPort=${event?.target?.value}`);
});

document
  .getElementById("settings-backend-force-legacy-spawn")
  .addEventListener("change", (event) => {
    writeLogEntry(
      `Settings updated backendForceLegacySpawn=${Boolean(event?.target?.checked)}`,
    );
  });

document
  .getElementById("settings-debug-ungrouped-list-virtualization-enabled")
  .addEventListener("change", (event) => {
    writeLogEntry(
      `Settings updated ungroupedListVirtualizationEnabled=${Boolean(event?.target?.checked)}`,
    );
  });

document
  .getElementById("settings-backend-http-data-mode-enabled")
  .addEventListener("change", (event) => {
    writeLogEntry(
      `Settings updated backendHttpDataModeEnabled=${Boolean(event?.target?.checked)}`,
    );
  });

document
  .getElementById("settings-debug-backend-refresh-interval-ms")
  .addEventListener("change", (event) => {
    writeLogEntry(
      `Settings updated backendIncrementalRefreshMinIntervalMs=${event?.target?.value}`,
    );
  });

document
  .getElementById("settings-debug-backend-refresh-min-packets")
  .addEventListener("change", (event) => {
    writeLogEntry(
      `Settings updated backendIncrementalRefreshMinPackets=${event?.target?.value}`,
    );
  });

document
  .getElementById("settings-debug-backend-json-data-emit-interval-ms")
  .addEventListener("change", (event) => {
    writeLogEntry(
      `Settings updated backendJsonDataEmitMinIntervalMs=${event?.target?.value}`,
    );
  });

document
  .getElementById("settings-debug-frontend-ingest-threading-enabled")
  .addEventListener("change", (event) => {
    const checked = Boolean(event?.target?.checked);
    const workerCountInput = document.getElementById(
      "settings-debug-frontend-ingest-worker-threads",
    );
    if (workerCountInput) {
      workerCountInput.disabled = !checked;
    }
    writeLogEntry(`Settings updated frontendIngestThreadingEnabled=${checked}`);
  });

document
  .getElementById("settings-debug-frontend-ingest-worker-threads")
  .addEventListener("change", (event) => {
    writeLogEntry(`Settings updated frontendIngestWorkerThreads=${event?.target?.value}`);
  });

document.getElementById("settings-debug-map-projection-zoom-x").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated mapProjectionZoomX=${event?.target?.value}`);
});

document.getElementById("settings-debug-map-projection-zoom-y").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated mapProjectionZoomY=${event?.target?.value}`);
});

document.getElementById("settings-debug-map-projection-offset-x").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated mapProjectionOffsetX=${event?.target?.value}`);
});

document.getElementById("settings-debug-map-projection-offset-y").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated mapProjectionOffsetY=${event?.target?.value}`);
});

document.getElementById("settings-llm-model").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated ollamaModel=${JSON.stringify(event?.target?.value || "")}`);
});

document.getElementById("settings-llm-api-key").addEventListener("change", () => {
  writeLogEntry("Settings updated ollamaApiKey=updated");
  if (window.modelsapi && typeof window.modelsapi.invalidateOllamaModelsCache === "function") {
    window.modelsapi.invalidateOllamaModelsCache().then(() => loadAvailableOllamaModels());
  } else {
    void loadAvailableOllamaModels();
  }
});

document.getElementById("settings-llm-active-by-default").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated activeByDefault=${Boolean(event?.target?.checked)}`);
});

document
  .getElementById("settings-llm-background-summary-generation-enabled")
  .addEventListener("change", (event) => {
    writeLogEntry(
      `Settings updated backgroundSummaryGenerationEnabled=${Boolean(event?.target?.checked)}`,
    );
    if (llmSummaryTimeout) {
      clearTimeout(llmSummaryTimeout);
      llmSummaryTimeout = null;
    }
  });

document.getElementById("settings-llm-delay-seconds").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated triggerDelaySeconds=${event?.target?.value}`);
});

document.getElementById("settings-llm-max-tokens").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated maxSummaryTokens=${event?.target?.value}`);
});

document.getElementById("settings-llm-timeout-seconds").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated ollamaRequestTimeoutSeconds=${event?.target?.value}`);
});

document.getElementById("settings-llm-retry-count").addEventListener("change", (event) => {
  writeLogEntry(`Settings updated retryCount=${event?.target?.value}`);
});

document
  .getElementById("settings-llm-analysis-compaction-threshold-blubs")
  .addEventListener("change", (event) => {
    writeLogEntry(`Settings updated analysisCompactionThresholdBlubs=${event?.target?.value}`);
  });

document
  .getElementById("conv-subtab-conversions")
  .addEventListener("click", () => {
    dataToolsDecodeUseRawConvInputOverride = false;
    setConvSubtab(CONV_CONVERSIONS_SUBTAB);
    normalizeDataToolsHexInputFormatting();
    runDeferredDataToolsAnalysisForActiveSubtab();
  });
document
  .getElementById("conv-subtab-hashes")
  .addEventListener("click", () => {
    dataToolsDecodeUseRawConvInputOverride = false;
    setConvSubtab(CONV_HASHES_SUBTAB);
    runDeferredDataToolsAnalysisForActiveSubtab();
  });
document
  .getElementById("conv-subtab-extraction")
  .addEventListener("click", () => {
    dataToolsDecodeUseRawConvInputOverride = false;
    setConvSubtab(CONV_EXTRACTION_SUBTAB);
    runDeferredDataToolsAnalysisForActiveSubtab();
  });
document
  .getElementById("conv-subtab-decodes")
  .addEventListener("click", () => {
    // Manual Decodes tab open keeps the default stream-based decoder behavior.
    dataToolsDecodeUseRawConvInputOverride = false;
    setConvSubtab(CONV_DECODES_SUBTAB);
    runDeferredDataToolsAnalysisForActiveSubtab();
  });
document
  .getElementById("conv-subtab-subnet")
  .addEventListener("click", () => {
    dataToolsDecodeUseRawConvInputOverride = false;
    setConvSubtab(CONV_SUBNET_SUBTAB);
    subnetCalculatorPanel.maybeKickoffNmapOnTabOpen();
    requestDataToolsBackgroundSummary(CONV_SUBNET_SUBTAB);
  });
document
  .getElementById("conv-subtab-threat-intel")
  .addEventListener("click", () => {
    dataToolsDecodeUseRawConvInputOverride = false;
    setConvSubtab(CONV_THREAT_INTEL_SUBTAB);
    subnetCalculatorPanel.maybeKickoffThreatIntelOnTabOpen();
    requestDataToolsBackgroundSummary(CONV_THREAT_INTEL_SUBTAB);
  });
document
  .getElementById("conv-subtab-packet-json")
  .addEventListener("click", () => {
    dataToolsDecodeUseRawConvInputOverride = false;
    setConvSubtab(CONV_PACKET_JSON_SUBTAB);
    runDeferredDataToolsAnalysisForActiveSubtab();
    requestDataToolsBackgroundSummary(CONV_PACKET_JSON_SUBTAB);
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

// TLS/SSL session key log (NSS key log format) loader
document
  .getElementById("crypt-load-key-log-file-btn")
  .addEventListener("click", () =>
    document.getElementById("crypt-key-log-file-input").click(),
  );
document
  .getElementById("crypt-key-log-file-input")
  .addEventListener("change", function () {
    readCryptTextFile(this, applyCryptKeyLogText);
    this.value = "";
  });
document
  .getElementById("crypt-use-key-log-input-btn")
  .addEventListener("click", () =>
    applyCryptKeyLogText(
      document.getElementById("crypt-key-log-input").value,
      "pasted text",
    ),
  );
document.getElementById("crypt-clear-key-log-btn").addEventListener("click", () => {
  applyCryptKeyLogText("", "cleared");
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

document.getElementById("crypt-pgp-refresh-btn").addEventListener("click", () => {
  refreshPgpEncounteredEntries();
});
document
  .getElementById("crypt-pgp-encountered-list")
  .addEventListener("change", function () {
    const selectedIndex = Number(this.value);
    selectPgpEncounteredEntry(selectedIndex);
  });
document
  .getElementById("crypt-pgp-load-selected-btn")
  .addEventListener("click", loadSelectedPgpEncounteredInput);
document
  .getElementById("crypt-pgp-analyze-btn")
  .addEventListener("click", () => {
    void analyzePgpInput();
  });
document
  .getElementById("crypt-pgp-to-armor-btn")
  .addEventListener("click", () => {
    void convertPgpInputToArmor();
  });
document
  .getElementById("crypt-pgp-to-binary-btn")
  .addEventListener("click", () => {
    void convertPgpInputToBinaryHex();
  });
document
  .getElementById("crypt-pgp-decrypt-verify-btn")
  .addEventListener("click", () => {
    void decryptVerifyPgpInput();
  });
document
  .getElementById("crypt-pgp-send-conv-btn")
  .addEventListener("click", sendPgpOutputToConvTab);
document
  .getElementById("crypt-pgp-clear-output-btn")
  .addEventListener("click", clearPgpOutput);
document
  .getElementById("crypt-pgp-clear-input-btn")
  .addEventListener("click", clearPgpInput);
document
  .getElementById("crypt-pgp-use-selected-private-key-btn")
  .addEventListener("click", useSelectedPgpPrivateKeyCandidate);
document
  .getElementById("crypt-pgp-use-selected-passphrase-btn")
  .addEventListener("click", useSelectedPgpPasswordCandidate);

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
    const activeEntries = keystorePanel.getRenderedCryptKeystoreEntries();
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
  .addEventListener("click", () => {
    runDataToolsConversion();
    updateDataToolsCursorReadout("data-tools-input");
    if (typeof subnetCalculatorPanel?.recomputeSessionThreatScore === "function") {
      subnetCalculatorPanel.recomputeSessionThreatScore({ silent: true });
    }
  });
document
  .getElementById("data-tools-send-to-decodes-btn")
  .addEventListener("click", async () => {
    const bytes = getCurrentDataToolsInputBytes();
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      statusUpdate("Status: No valid data to send to Decodes.");
      return;
    }
    dataToolsLastConversionBytes = bytes;
    dataToolsDecodeUseRawConvInputOverride = true;
    const selectEl = document.getElementById("data-tools-proto-select");
    if (selectEl) {
      selectEl.value = "auto";
    }
    setConvSubtab(CONV_DECODES_SUBTAB);
    runDeferredDataToolsAnalysisForActiveSubtab();
  });
document
  .getElementById("data-tools-save-btn")
  .addEventListener("click", async () => {
    const bytes = getCurrentDataToolsInputBytes();
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      statusUpdate("Status: No valid data to save.");
      return;
    }
    const hexString = Array.from(bytes, (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    const fileNameEl = document.getElementById("data-tools-file-name");
    const dataToolsFileNameGuess = fileNameEl
      ? fileNameEl.textContent.replace(/^Filename Guess:\s*/i, "").trim()
      : "";
    const defaultName = getBareFilename(dataToolsFileNameGuess) || "converted.bin";
    window.saveapi.savePayload(hexString, { defaultName }).then((result) => {
      if (!result.success && !result.canceled) {
        console.error("Save converted data failed:", result.error);
        statusUpdate(`Status: Save failed — ${result.error || "unknown error"}`);
      } else if (result.success) {
        statusUpdate("Status: Converted data saved.");
      }
    });
  });
document
  .getElementById("data-tools-hash-btn")
  .addEventListener("click", async () => {
    const bytes = getCurrentDataToolsInputBytes();
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      statusUpdate("Status: No valid data to hash.");
      return;
    }
    dataToolsLastConversionBytes = bytes;
    computeDataToolsHashes(bytes);
    setConvSubtab(CONV_HASHES_SUBTAB);
  });
document
  .getElementById("data-tools-threat-intel-btn")
  .addEventListener("click", async () => {
    const bytes = getCurrentDataToolsInputBytes();
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
      statusUpdate("Status: No valid data for threat intel lookup.");
      return;
    }
    if (!window.snitchapi || typeof window.snitchapi.lookupVirusTotal !== "function") {
      statusUpdate("Status: VirusTotal API is unavailable.");
      return;
    }
    const apiKey = getBackendVirusTotalApiKey();
    if (!apiKey) {
      statusUpdate("Status: VirusTotal API key is not configured in Settings > Backend.");
      return;
    }
    if (bytes.length > 32 * 1024 * 1024) {
      statusUpdate("Status: Converted data exceeds VirusTotal 32 MiB upload limit.");
      return;
    }
    const fileNameEl = document.getElementById("data-tools-file-name");
    const dataToolsFileNameGuess = fileNameEl ? fileNameEl.textContent.replace(/^Filename Guess:\s*/i, "").trim() : "";
    const fileNameHint = getBareFilename(dataToolsFileNameGuess) || "converted.bin";
    try {
      statusUpdate("Status: Looking up SHA256 in VirusTotal…");
      const sha256Hex = await window.extractapi.sha256Bytes({
        bytesBase64: uint8ArrayToBase64(bytes),
      });
      const lookupResponse = await window.snitchapi.lookupVirusTotal(sha256Hex, {
        lookupType: "hash",
        apiKey,
        backendOptions: getBackendTransportOptionsFromSettings(),
      });
      if (lookupResponse?.success) {
        statusUpdate(`Status: VirusTotal report found for ${fileNameHint}`);
        showVirusTotalResultModal(lookupResponse, fileNameHint);
        return;
      }
      statusUpdate("Status: Uploading converted data to VirusTotal…");
      const uploadResponse = await window.extractapi.uploadVirusTotal({
        bytesBase64: uint8ArrayToBase64(bytes),
        fileName: fileNameHint,
        apiKey,
      });
      if (!uploadResponse?.success) {
        statusUpdate(`Status: VirusTotal upload failed — ${uploadResponse?.error || "unknown error"}`);
        return;
      }
      statusUpdate(`Status: Uploaded to VirusTotal; analysis ID ${uploadResponse.analysisId || ""}`);
      showVirusTotalResultModal(uploadResponse, fileNameHint);
    } catch (err) {
      statusUpdate(`Status: VirusTotal lookup/upload failed — ${err?.message || String(err)}`);
    }
  });
document
  .getElementById("data-tools-load-more-output-btn")
  .addEventListener("click", loadMoreDataToolsOutputPage);
bindConvertedOutputExpandHandlers();
updateDataToolsConvertedOutputVisibility();
document.getElementById("data-tools-input").addEventListener("input", () => {
  dataToolsOriginalInputBytes = null;
  dataToolsInputEditedFlag = true;
  clearDataToolsStreamPackets();
  dataToolsContextPacket = null;
  dataToolsHistorySelectEl.value = "";
  setDataToolsFileNameGuess("");
  updateDataToolsHexHighlights();
  syncDataToolsHighlightScroll(
    "data-tools-input",
    "data-tools-input-highlight",
  );
  updateDataToolsInputEditedState();
});
document.getElementById("data-tools-input").addEventListener("paste", () => {
  const formatEl = document.getElementById("data-tools-format");
  if (formatEl?.value !== "hex") return;
  dataToolsOriginalInputBytes = null;
  dataToolsInputEditedFlag = true;
  clearDataToolsStreamPackets();
  dataToolsContextPacket = null;
  requestAnimationFrame(() => {
    normalizeDataToolsHexInputFormatting();
  });
});
document.getElementById("data-tools-input").addEventListener("blur", () => {
  const formatEl = document.getElementById("data-tools-format");
  if (formatEl?.value !== "hex") return;
  requestAnimationFrame(() => {
    const nextFocusedId = document.activeElement?.id || "";
    if (
      DATA_TOOLS_SELECTION_FIELD_IDS.includes(nextFocusedId) &&
      nextFocusedId !== "data-tools-input"
    ) {
      return;
    }
    normalizeDataToolsHexInputFormatting();
  });
});
document.getElementById("data-tools-format").addEventListener("change", () => {
  dataToolsHistorySelectEl.value = "";
  if (document.getElementById("data-tools-format")?.value === "hex") {
    normalizeDataToolsHexInputFormatting();
    return;
  }
  updateDataToolsConvertedOutputVisibility();
  updateDataToolsHexHighlights();
  updateDataToolsInputEditedState();
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
  el.addEventListener("focus", () => updateDataToolsCursorReadout(fieldId));
  el.addEventListener("click", () => updateDataToolsCursorReadout(fieldId));
}
document.addEventListener("selectionchange", () => {
  if (dataToolsSelectionState.syncingSelection) return;
  const active = document.activeElement;
  if (!active || !DATA_TOOLS_SELECTION_FIELD_IDS.includes(active.id)) return;
  syncDataToolsSelectionFromField(active.id);
});
document
  .getElementById("data-tools-manual-carve-btn")
  ?.addEventListener("click", performDataToolsManualCarve);
document
  .getElementById("data-tools-manual-carve-load-conv-btn")
  ?.addEventListener("click", loadDataToolsManualCarveIntoConv);
document
  .getElementById("data-tools-output-cursor-row")
  ?.addEventListener("click", handleDataToolsCursorCarveClick);
document
  .getElementById("data-tools-hash-input-reading")
  .addEventListener("input", runDataToolsHashesFromInput);
document
  .getElementById("data-tools-cross-ref-hash-btn")
  .addEventListener("click", () => {
    crossReferenceCurrentHash(subnetCalculatorPanel?.runThreatIntelHashLookup);
  });
document
  .getElementById("data-tools-clear-btn")
  .addEventListener("click", () => {
    dataToolsHistorySelectEl.value = "";
    dataToolsContextPacket = null;
    document.getElementById("data-tools-input").value = "";
    document.getElementById("data-tools-error").textContent = "";
    resetDataToolsOutputs();
    clearDataToolsSelectionState();
    updateDataToolsHexHighlights();
    updateDataToolsInputEditedState();
    setDataToolsFindReplaceMode("none");
    updateDataToolsCursorReadout("data-tools-input");
  });
document
  .getElementById("data-tools-input-reset-btn")
  .addEventListener("click", () => {
    resetDataToolsInputToCommitted();
  });
document
  .getElementById("data-tools-simple-find-next-btn")
  .addEventListener("click", runDataToolsSimpleFindNext);
document
  .getElementById("data-tools-simple-replace-next-btn")
  .addEventListener("click", runDataToolsSimpleReplaceNext);
document
  .getElementById("data-tools-simple-replace-all-btn")
  .addEventListener("click", runDataToolsSimpleReplaceAll);
document
  .getElementById("data-tools-pcre-find-next-btn")
  .addEventListener("click", runDataToolsPcreFindNext);
document
  .getElementById("data-tools-pcre-replace-next-btn")
  .addEventListener("click", runDataToolsPcreReplaceNext);
document
  .getElementById("data-tools-pcre-replace-all-btn")
  .addEventListener("click", runDataToolsPcreReplaceAll);
document
  .getElementById("data-tools-simple-search")
  .addEventListener("input", () => setDataToolsFindReplaceMode("simple"));
document
  .getElementById("data-tools-simple-replace")
  .addEventListener("input", () => setDataToolsFindReplaceMode("simple"));
document
  .getElementById("data-tools-simple-match-case")
  .addEventListener("change", () => setDataToolsFindReplaceMode("simple"));
document
  .getElementById("data-tools-simple-find-replace-section")
  .addEventListener("focusin", () => setDataToolsFindReplaceMode("simple"));
document
  .getElementById("data-tools-pcre-search")
  .addEventListener("input", () => setDataToolsFindReplaceMode("advanced"));
document
  .getElementById("data-tools-pcre-replace")
  .addEventListener("input", () => setDataToolsFindReplaceMode("advanced"));
document
  .getElementById("data-tools-pcre-flag-i")
  .addEventListener("change", () => setDataToolsFindReplaceMode("advanced"));
document
  .getElementById("data-tools-pcre-flag-m")
  .addEventListener("change", () => setDataToolsFindReplaceMode("advanced"));
document
  .getElementById("data-tools-pcre-flag-s")
  .addEventListener("change", () => setDataToolsFindReplaceMode("advanced"));
document
  .getElementById("data-tools-pcre-flag-u")
  .addEventListener("change", () => setDataToolsFindReplaceMode("advanced"));
document
  .getElementById("data-tools-advanced-find-replace-section")
  .addEventListener("focusin", () => setDataToolsFindReplaceMode("advanced"));
setDataToolsFindReplaceMode("none");
dataToolsHistorySelectEl.addEventListener("change", () => {
  const selectedIndex = Number(dataToolsHistorySelectEl.value);
  if (!Number.isInteger(selectedIndex) || selectedIndex < 0) return;
  const selectedEntry = dataToolsInputHistory[selectedIndex];
  if (!selectedEntry) return;
  dataToolsOriginalInputBytes = null;
  dataToolsInputEditedFlag = true;
  clearDataToolsStreamPackets();
  dataToolsContextPacket = null;
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
    try {
      const bytes = dataToolsLastConversionBytes;
      if (!(bytes instanceof Uint8Array) || bytes.length === 0) return;
      runProtoDecoder(bytes);
    } catch {
      // ignore failures and preserve existing decoder output
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
convertContextButtons.loadFile.addEventListener("click", () => {
  void loadManualFileIntoConvTabFromContextMenu();
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
convertContextButtons.notesSendData.addEventListener("click", async () => {
  const rawContextText = getActiveContextTextForNotesAndLlm("notes");
  if (!String(rawContextText || "").trim()) {
    sendTextToNotesFromContextMenu(rawContextText, "context-data");
    return;
  }

  let noteText = rawContextText;
  if (isLlmRuntimeEnabled()) {
    statusUpdate("Status: Formatting context data as Markdown for Notes...");
    try {
      noteText = await formatContextDataAsMarkdownForNotesWithLlm(
        rawContextText,
        activeContextPacket || getCurrentContextPacket(),
      );
    } catch (error) {
      const errorMessage = error?.message || String(error);
      writeLogEntry(`Context-to-notes markdown formatting fallback: ${errorMessage}`);
      statusUpdate("Status: LLM markdown formatting failed; using original context data");
    }
  }

  sendTextToNotesFromContextMenu(noteText, "context-data");
});
convertContextButtons.notesSendListPacket.addEventListener("click", () => {
  sendTextToNotesFromContextMenu(
    buildListVisibleDataNoteText(),
    "context-list-row-visible-data",
    false,
  );
});
convertContextButtons.notesSendConvInput.addEventListener("click", () => {
  sendConvExportToNotesFromContextMenu("input", "context-conv-input");
});
convertContextButtons.notesSendConvHex.addEventListener("click", () => {
  sendConvExportToNotesFromContextMenu("hex", "context-conv-output-hex");
});
convertContextButtons.notesSendConvAscii.addEventListener("click", () => {
  sendConvExportToNotesFromContextMenu("ascii", "context-conv-output-ascii");
});
convertContextButtons.notesSendConvBase64.addEventListener("click", () => {
  sendConvExportToNotesFromContextMenu("base64", "context-conv-output-base64");
});
convertContextButtons.notesSendConvHashes.addEventListener("click", () => {
  const tableMarkdown = buildConvHashesMarkdownTable();
  sendTextToNotesFromContextMenu(
    tableMarkdown
      ? `${buildConvNotesMarkdownHeader("hashes")}${tableMarkdown}`
      : "",
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
convertContextButtons.openHeatmapLocation.addEventListener("click", () => {
  const tag = activeContextTarget?.closest?.("#stats_box .stats-section .stats-tag[data-latitude]");
  if (!tag) return;
  const latitude = parseFloat(tag.dataset.latitude);
  const longitude = parseFloat(tag.dataset.longitude);
  const label = tag.dataset.locationLabel || "";
  if (Number.isFinite(latitude) && Number.isFinite(longitude)) {
    showStatsHeatmapLocation({ latitude, longitude, label });
  }
  hideConvertContextMenu();
});

convertContextButtons.loadCarvableExtraction.addEventListener("click", async () => {
  const tag = activeContextTarget?.closest?.("#stats_box .stats-section .stats-tag[data-carvable-id]");
  if (!tag) return;
  const candidate = await getCarvableCandidateById(tag.dataset.carvableId);
  hideConvertContextMenu();
  if (!candidate) {
    statusUpdate("Status: Carved file candidate not found");
    return;
  }
  const bytes = candidate.bytes;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    statusUpdate("Status: Carved file content is unavailable");
    return;
  }
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  if (!inputEl || !formatEl) {
    statusUpdate("Status: Conv input fields are unavailable");
    return;
  }
  dataToolsContextPacket = null;
  dataToolsOriginalInputBytes = bytes;
  dataToolsInputEditedFlag = false;
  clearDataToolsStreamPackets();
  dataToolsLastConversionBytes = bytes;
  inputEl.value = formatHexInputBytesWithCap(bytes);
  formatEl.value = "hex";
  setDataToolsFileNameGuess(candidate.fileName || "");
  markDataToolsInputCommitted();
  showDataTools(CONV_EXTRACTION_SUBTAB);
  statusUpdate(`Status: Loaded ${candidate.fileName || "carved file"} into Extraction (${bytes.length} bytes)`);
  writeLogEntry(
    `Stats carve loaded into Extraction file="${candidate.fileName || "unknown"}" bytes=${bytes.length}`,
  );
});

convertContextButtons.loadCarvableDecoders.addEventListener("click", async () => {
  const tag = activeContextTarget?.closest?.("#stats_box .stats-section .stats-tag[data-carvable-id]");
  if (!tag) return;
  const candidate = await getCarvableCandidateById(tag.dataset.carvableId);
  hideConvertContextMenu();
  if (!candidate) {
    statusUpdate("Status: Carved file candidate not found");
    return;
  }
  const bytes = candidate.bytes;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    statusUpdate("Status: Carved file content is unavailable");
    return;
  }
  const inputEl = document.getElementById("data-tools-input");
  const formatEl = document.getElementById("data-tools-format");
  const selectEl = document.getElementById("data-tools-proto-select");
  if (!inputEl || !formatEl || !selectEl) {
    statusUpdate("Status: Conv decoders controls are unavailable");
    return;
  }
  dataToolsContextPacket = null;
  dataToolsOriginalInputBytes = bytes;
  dataToolsInputEditedFlag = false;
  clearDataToolsStreamPackets();
  dataToolsLastConversionBytes = bytes;
  inputEl.value = formatHexInputBytesWithCap(bytes);
  formatEl.value = "hex";
  setDataToolsFileNameGuess(candidate.fileName || "");

  // Hint the decoder by file extension when possible. We deliberately leave
  // the dropdown on "auto" when the extension is unknown so the existing
  // auto-detection still runs and the user can override the pick.
  const extensionHint = getProtoDecoderHintForFileName(candidate.fileName || "");
  const chosenProtocol = extensionHint && SUPPORTED_DECODER_PROTOS.has(extensionHint)
    ? extensionHint
    : "auto";
  selectEl.value = chosenProtocol;

  markDataToolsInputCommitted();
  showDataTools(CONV_DECODES_SUBTAB);
  // Force a re-run of the decoder because simply swapping the input value
  // does not always re-fire the `change` event on the proto-select when the
  // dropdown was already on the same value.
  try {
    runProtoDecoder(bytes);
  } catch (decoderError) {
    const errorMessage = decoderError?.message || String(decoderError || "unknown");
    writeLogEntry(`Stats carve decoder run failed: ${errorMessage}`);
  }
  const decoderLabel = chosenProtocol === "auto" ? "auto-detect" : chosenProtocol;
  statusUpdate(
    `Status: Loaded ${candidate.fileName || "carved file"} into Decoders (${bytes.length} bytes, decoder=${decoderLabel})`,
  );
  writeLogEntry(
    `Stats carve loaded into Decoders file="${candidate.fileName || "unknown"}" bytes=${bytes.length} extension_hint=${JSON.stringify(extensionHint || "")} decoder=${JSON.stringify(chosenProtocol)}`,
  );
});

convertContextButtons.loadCarvableVirusTotal.addEventListener("click", async () => {
  const tag = activeContextTarget?.closest?.("#stats_box .stats-section .stats-tag[data-carvable-id]");
  if (!tag) return;
  const candidate = await getCarvableCandidateById(tag.dataset.carvableId);
  hideConvertContextMenu();
  if (!candidate) {
    statusUpdate("Status: Carved file candidate not found");
    return;
  }
  const bytes = candidate.bytes;
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    statusUpdate("Status: Carved file content is unavailable");
    return;
  }
  await uploadExtractionResultToVirusTotal(bytes, candidate.fileName || "carved-file.bin");
  statusUpdate(`Status: Sent ${candidate.fileName || "carved file"} to VirusTotal (${bytes.length} bytes)`);
  writeLogEntry(
    `Stats carve sent to VirusTotal file="${candidate.fileName || "unknown"}" bytes=${bytes.length}`,
  );
});

function resolveContextIpForAnalyzeAction() {
  const target = activeContextTarget;
  if (!target) return "";
  const selectedText = getTrimmedSelectionText();
  const conversionText = getConversionTextFromTarget(target);
  return extractContextIpFromContextTarget(target, {
    selectedText,
    conversionText,
  });
}

function runIpInSubnetCalculatorFromContextMenu() {
  const ipAddress = resolveContextIpForAnalyzeAction();
  if (!ipAddress) {
    statusUpdate("Status: No IP address detected for Subnet Calculator.");
    hideConvertContextMenu();
    return;
  }
  hideConvertContextMenu();
  if (typeof subnetCalculatorPanel?.setAnalysisInput !== "function") {
    statusUpdate("Status: Subnet Calculator panel is unavailable.");
    return;
  }
  showDataTools(CONV_SUBNET_SUBTAB);
  subnetCalculatorPanel.setAnalysisInput(ipAddress);
  if (typeof subnetCalculatorPanel.analyzeCurrentInput === "function") {
    void subnetCalculatorPanel.analyzeCurrentInput();
  }
  statusUpdate(`Status: Loaded ${ipAddress} into Subnet Calculator.`);
  writeLogEntry(`Context menu analyzed IP in subnet calculator ip=${JSON.stringify(ipAddress)}`);
}

function runIpThreatIntelLookupFromContextMenu() {
  const ipAddress = resolveContextIpForAnalyzeAction();
  if (!ipAddress) {
    statusUpdate("Status: No IP address detected for Threat Intel lookup.");
    hideConvertContextMenu();
    return;
  }
  hideConvertContextMenu();
  if (typeof subnetCalculatorPanel?.runThreatIntelIpLookup !== "function") {
    statusUpdate("Status: Threat Intel lookup is unavailable.");
    return;
  }
  showDataTools(CONV_THREAT_INTEL_SUBTAB);
  subnetCalculatorPanel.runThreatIntelIpLookup(ipAddress);
  statusUpdate(`Status: Threat Intel lookup started for ${ipAddress}.`);
  writeLogEntry(`Context menu analyzed IP via threat intel ip=${JSON.stringify(ipAddress)}`);
}

convertContextButtons.analyzeIpSubnet.addEventListener(
  "click",
  runIpInSubnetCalculatorFromContextMenu,
);
convertContextButtons.analyzeIpThreatIntel.addEventListener(
  "click",
  runIpThreatIntelLookupFromContextMenu,
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
convertContextButtons.exportDecrypted.addEventListener(
  "click",
  exportDecryptedDataFromContextMenu,
);
convertContextButtons.exportSummaryMarkdown.addEventListener("click", () => {
  saveSummaryFromContextMenu("markdown");
});
convertContextButtons.exportSummaryText.addEventListener("click", () => {
  saveSummaryFromContextMenu("text");
});
convertContextButtons.exportSummaryHtml.addEventListener("click", () => {
  saveSummaryFromContextMenu("html");
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
convertContextButtons.followStreamCrypt.addEventListener("click", () => {
  void followStreamToCrypt();
});
convertContextButtons.llmQuestion.addEventListener("click", () => {
  void askContextQuestionWithLLM();
});
convertContextButtons.llmExplain.addEventListener("click", () => {
  void explainContextWithLLM();
});
convertContextButtons.llmSummarize.addEventListener("click", () => {
  void summarizeContextPacketWithLLM();
});
convertContextButtons.llmSubnetHostSummary.addEventListener("click", () => {
  void summarizeSubnetHostContextWithLLM();
});

// Handle bookmark selection from dropdown
document
  .getElementById("selectBookmark")
  .addEventListener("change", function () {
    const selectedBookmarkKey = document.getElementById("selectBookmark").value;
    const { host: bookmarkHost, packetIndex: bookmarkPacketIndex } = parsePacketKey(selectedBookmarkKey);
    if (!Number.isInteger(bookmarkPacketIndex) || bookmarkPacketIndex < 0) {
      statusUpdate("Invalid bookmark selection, missing host or packet index");
      doError("Invalid bookmark selection, missing host or packet index!");
      return;
    }
    index = bookmarkPacketIndex;
    setActivePacketCursor(index);
    p = capturedPackets["host"][bookmarkHost];
    activeBookmark["host"] = bookmarkHost;
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
      writeLogEntry(`Bookmark added key = ${currentPacketKey}`);
      syncPluginRuntimeData({ includeStats: true });
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
  return getTotalPacketCount();
}

// Handles update current packet counters.
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
    const packetInfo = packet?.["packet.info"];
    if (!packetInfo) return null;
    const sourceIp = (packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"]) || "Unknown";
    const packetIndex = packetInfo?.["index"] ?? packetInfo?.["Index"] ?? fallbackIndex;
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
 * Returns the packet array index matching a `sourceIp: packetIndex` key.
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
    const packetInfo = packet?.["packet.info"];
    if (!packetInfo) return false;
    const candidateSourceIp = packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"];
    const candidatePacketIndex = packetInfo?.["index"] ?? packetInfo?.["Index"];
    return (
      String(candidateSourceIp) === sourceIp &&
      String(candidatePacketIndex) === packetIndexValue
    );
  });
}

// Sets prev next button visibility.
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
  currentPacketToConvJson();
  await writeSummaryFromLLM();
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

  let packetSet;
  if (shouldUseFilteredPacketSet) {
    packetSet = filteredPackets;
  } else if (
    (navAction === "next" || navAction === "prev")
    && Array.isArray(p)
    && p.length > 0
  ) {
    packetSet = p;
  } else {
    packetSet = getPacketsForSelectedHost(hostFilterEl.value);
  }
  if (shouldUseFilteredPacketSet) {
    const filteredNavigationLogMessage =
      `Filtered packet navigation packets_returned = ${packetSet.length}`;
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
      navBookmark["host"] == undefined ||
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
        navBookmark["host"] +
        " packet " +
        navBookmark["Packet"],
      );
      writeLogEntry(
        `Navigating bookmark host = ${navBookmark["host"]} packet = ${navBookmark["Packet"]}`,
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
    syncPluginRuntimeData();
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
    p = packetSet;
    const activePacket = await ensurePacketHydrated(
      packetSet[index],
      hostFilterEl.value,
      index,
    );
    packetSet[index] = activePacket;
    const packetInfo = activePacket?.["packet.info"];
    if (!packetInfo) {
      statusUpdate("Status: Packet data is unavailable for this entry");
      doError("Packet data is unavailable for this entry!");
      return;
    }
    currentIp = (packetInfo?.["IP"]?.["ip.src.addr"] ?? packetInfo?.["IP"]?.["Source IP"]) || hostFilterEl.value || "Unknown";
    currentPacketKey = `${currentIp}${PACKET_KEY_SEPARATOR}${packetInfo?.["index"] ?? packetInfo?.["Index"] ?? index}`;
    syncBookmarkDropdown(currentPacketKey);
    updateCurrentPacketCounters(packetSet, {
      isFilteredView: navAction === "filtered",
    });
    console.log(activePacket);
    const hexPayload =
      (packetInfo?.["Raw data"]?.["Payload"]?.["payload.hex"] ?? packetInfo?.["Raw data"]?.["Payload"]?.["Hex Encoded"]) || "";
    infoPanel(packetSet);
    popHexGrid(hexPayload);
    populateDataTypes(packetSet);
    logCurrentPacketDisplay(navAction || "first-load");
    syncPluginRuntimeData();
  }
}

const {
  getPacketDataTypeItems,
  normalizeProtocolToken,
  collectPacketProtocolTokens,
  getMatchedHiddenDataTypeProtocol,
  hasLikelyFileLikeDataTypes,
  getDataTypesVisibilityState,
  applyDataTypesVisibility,
  populateDataTypes,
} = createDataTypeHelpers({
  constants: {
    hiddenProtocols: DATA_TYPES_DEFAULT_HIDDEN_PROTOCOLS,
    hiddenProtocolPrefixes: DATA_TYPES_DEFAULT_HIDDEN_PROTOCOL_PREFIXES,
  },
  state: {
    get index() {
      return index;
    },
    get currentPacketKey() {
      return currentPacketKey;
    },
    get dataTypesOverridePacketKey() {
      return dataTypesOverridePacketKey;
    },
  },
  getPacketInfoPayloadLength,
  setPrevNextButtonVisibility,
});

// ============================================================================
// Packet detail rendering and hex/ASCII visualization
// ============================================================================

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
  const safeHex = typeof hex === "string" ? hex : "";
  // swap it back to ASCII for the fade box
  const payloadAsciiBox = document.getElementById("payloadascii");
  const hexGridContainer = document.getElementById("hexg");
  const hexOffsetDisplay = document.getElementById("asciiOffset");
  const asciiTextBox = document.getElementById("asciiText");
  if (payloadAsciiBox) {
    payloadAsciiBox.classList.remove("visible");
  }
  if (hexGridContainer) {
    hexGridContainer.textContent = "";
  }
  if (hexOffsetDisplay) {
    hexOffsetDisplay.textContent = "";
  }
  if (asciiTextBox) {
    asciiTextBox.textContent = "";
  }
  window.currentPrintableSequence = "";
  if (!safeHex) {
    return;
  }

  const decodedAscii = hexToAscii(safeHex);
  const hexPairs = safeHex.toUpperCase().match(/.{1,2}/g) || [];
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
  infoPaneEl.style.display = "block";
  if (!Array.isArray(pk) || pk.length === 0) {
    statusUpdate("Status: No packet information found for this host");
    doError("No packet information found for this host!");
    return;
  }
  const p = pk[index];
  if (!p || !p["packet.info"]) {
    statusUpdate("Status: Packet data is unavailable for this entry");
    doError("Packet data is unavailable for this entry!");
    return;
  }
  updateCurrentPacketCounters(pk, {
    isFilteredView: Array.isArray(filteredPackets) && pk === filteredPackets,
  });
  let packetInfoData = p["packet.info"] || {};
  let extraInfoData = p["extra.info"] || {};
  const ipData = packetInfoData["IP"] || {};
  const traitsData = extraInfoData["Traits"] || {};
  const networkData = traitsData["Network Data"] || {};
  const serverInfo = traitsData["Server Info"] || {};
  const srcLocation = networkData?.["ip.src"]?.["Location"] || networkData?.["Source IP"]?.["Location"] || {};
  const dstLocation = networkData?.["ip.dst"]?.["Location"] || networkData?.["Destination IP"]?.["Location"] || {};
  const parseLocationCoordinate = (value, min, max) => {
    const numericValue = Number(value);
    if (!Number.isFinite(numericValue)) return null;
    if (numericValue < min || numericValue > max) return null;
    return numericValue;
  };
  const bindLocationTableToHeatmap = (locationData, locationSideLabel) => {
    const latitude = parseLocationCoordinate(locationData?.["Latitude"], -90, 90);
    const longitude = parseLocationCoordinate(locationData?.["Longitude"], -180, 180);
    if (latitude === null || longitude === null) return;

    const locationContainer = document.getElementById("sideloctable");
    const locationTable = locationContainer?.querySelector("table:last-of-type");
    if (!locationTable) return;

    const city = String(locationData?.["City"] || "").trim();
    const country = String(locationData?.["Country"] || "").trim();
    const locationLabel = [city, country].filter(Boolean).join(", ") || locationSideLabel;

    const openHeatmapAtLocation = () => {
      showStatsHeatmapLocation({
        latitude,
        longitude,
        label: locationLabel,
      });
    };

    locationTable.style.cursor = "pointer";
    locationTable.title = "Open Stats map and zoom to this location";
    locationTable.addEventListener("click", openHeatmapAtLocation);
  };
  let packetTimestamp =
    (packetInfoData["packet.timestamp"] ?? packetInfoData["Packet Timestamp"]) || "N/A";
  let ipChecksum = ipData["ip.chksum"] ?? ipData["IP Checksum"] ?? "N/A";

  // Determine transport protocol (TCP or UDP); fall back to TCP for older captures
  const protocol =
    (packetInfoData["packet.proto"] ?? packetInfoData["Protocol"]) || "Unknown";
  const transportData = packetInfoData[protocol] || {};

  const transportChecksum =
    protocol === "TCP"
      ? transportData["tcp.chksum"] ?? transportData["TCP checksum"]
      : protocol === "UDP"
        ? transportData["udp.chksum"] ?? transportData["UDP checksum"]
        : protocol === "IGMP"
          ? transportData["IGMP Checksum"]
          : protocol === "ICMP"
            ? transportData["ICMP Checksum"]
            : "N/A";
  const transportLayerLen =
    protocol === "TCP"
      ? transportData["tcp.len"] ?? transportData["TCP layer length"]
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

  const sourceIpPort = formatNetworkEndpointDisplay(
    ipData["ip.src.addr"] ?? ipData["Source IP"] ?? hostFilterEl.value ?? "Unknown",
    transportData["tcp.src.port"] ?? transportData["udp.src.port"] ?? transportData["sctp.src.port"] ?? transportData["Source port"] ?? "?",
  );
  const destIpPort = formatNetworkEndpointDisplay(
    ipData["ip.dst.addr"] ?? ipData["Destination IP"] ?? hostFilterEl.value ?? "Unknown",
    transportData["tcp.dst.port"] ?? transportData["udp.dst.port"] ?? transportData["sctp.dst.port"] ?? transportData["Destination port"] ?? "?",
  );
  const etherFrame =
    typeof packetInfoData["Ethernet Frame"] === "object" &&
      packetInfoData["Ethernet Frame"] !== null
      ? packetInfoData["Ethernet Frame"]
      : {};
  const srcMac = etherFrame["ether.src.mac.addr"] ?? etherFrame["MAC Source"] ?? "N/A";
  const dstMac = etherFrame["ether.dst.mac.addr"] ?? etherFrame["MAC Destination"] ?? "N/A";
  const srcMacVendor = etherFrame["ether.src.mac.vendor"] ?? etherFrame["MAC Source Vendor"] ?? "N/A";
  const dstMacVendor = etherFrame["ether.dst.mac.vendor"] ?? etherFrame["MAC Destination Vendor"] ?? "N/A";
  const ipLayerLen = ipData["ip.len"] ?? ipData["IP layer length"] ?? "N/A";
  const wireLen = transportData["Wire length"] ?? "N/A";
  const payloadLen = getPacketInfoPayloadLength(packetInfoData);
  let sslVersion = "";
  let sslAlgos = "";
  if (
    serverInfo["Encryption Data"] == "N/A" ||
    serverInfo.hasOwnProperty("Encryption Data") == false
  ) {
    sslVersion = "Not encrypted";
    sslAlgos = "";
  } else {
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
  const srcNetClass = networkData?.["ip.src"]?.["Class"] ?? networkData?.["Source IP"]?.["Class"] ?? "N/A";
  const dstNetClass = networkData?.["ip.dst"]?.["Class"] ?? networkData?.["Destination IP"]?.["Class"] ?? "N/A";
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
    const dedupeKey = `${normalizedLayer.toLowerCase()}| ${normalizedLabel.toLowerCase()} `;
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
          ? ` (${escapeHtml(String(entry.details))
          })`
          : "";
        if (!entry.layer) {
          return `${escapeHtml(String(entry.protocol))}${detailText} `;
        }
        return `${escapeHtml(String(entry.layer))}: ${escapeHtml(String(entry.protocol))}${detailText} `;
      })
      .join("<br>");
  }

  const currentStreamKey = buildBidirectionalStreamKey(packetInfoData);
  const streamPacketRefs = [];
  const streamPackets = [];

  // ensure that all the packets in the stream all report the same application protocol, for consistency
  if (capturedPackets && capturedPackets["host"]) {
    for (const host of Object.keys(capturedPackets["host"])) {
      const hostPackets = capturedPackets["host"][host];
      if (!Array.isArray(hostPackets)) continue;
      for (let packetIndex = 0; packetIndex < hostPackets.length; packetIndex += 1) {
        const pkt = hostPackets[packetIndex];
        const pi = pkt?.["packet.info"];
        if (pi && buildBidirectionalStreamKey(pi) === currentStreamKey) {
          streamPacketRefs.push({
            packet: pkt,
            host,
            packetIndex,
          });
          streamPackets.push(pkt);
          // check and see if they all have the same application protocol,
          // if not, we will use the first packet's application protocol
          //  for the stream, for consistency
          const pktProtoName =
            pi?.["extra.info"]?.["Traits"]?.["Network Data"]?.["tcp.proto"] ||
            pi?.["extra.info"]?.["Traits"]?.["Network Data"]?.["sctp.proto"] ||
            pi?.["extra.info"]?.["Traits"]?.["Network Data"]?.["udp.proto"] ||
            "Unknown";
          if (streamPackets.length === 1) {
            // first packet in the stream, set the stream protocol
            streamProtocol = pktProtoName;
          } else if (pktProtoName !== streamProtocol) {
            // different protocol found, log a warning and continue using the first packet's protocol
            console.warn(`Inconsistent application protocol in stream: expected ${streamProtocol}, but found ${pktProtoName} `);
          }
        }
      }
    }
  }

  void warmStreamPacketHydrationCache(currentStreamKey, streamPacketRefs);

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

  // WAN/link control info table (shown when ATM/PPP/Frame Relay style link layers are present)
  renderLinkControlTable(packetInfoData);

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

  // SMPP info table (shown for SMPP packets on port 2775/3550)
  renderSmppTable(transportData);

  // Soulseek info table (shown for Soulseek packets on common ports)
  renderSoulseekTable(transportData);

  // BitTorrent info table (shown for peer-wire, handshake, and DHT/KRPC packets)
  renderBitTorrentTable(transportData);

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

  // SCTP/SIGTRAN info table (shown for SCTP packets and SS7 adaptation layers)
  renderSctpTable(transportData);

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
      ? ` ${tcpStreamStatusText} `
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
    bindLocationTableToHeatmap(srcLocation, "Source location");
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
    bindLocationTableToHeatmap(dstLocation, "Destination location");
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
    const sourceJobId =
      typeof pcapSource?.jobId === "string" && pcapSource.jobId.trim()
        ? pcapSource.jobId.trim()
        : "";
    if (sourceJobId && activeBackendJobId && sourceJobId !== activeBackendJobId) {
      return;
    }
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

function queueBackendCaptureUpdate(kind, payload) {
  const nextUpdate = { kind, payload };
  if (shouldReplacePendingBackendCaptureUpdate(pendingBackendCaptureUpdate, nextUpdate)) {
    pendingBackendCaptureUpdate = nextUpdate;
  }

  if (backendCaptureUpdateDrainActive) {
    return;
  }

  backendCaptureUpdateQueue = backendCaptureUpdateQueue
    .then(async () => {
      if (backendCaptureUpdateDrainActive) return;
      backendCaptureUpdateDrainActive = true;
      try {
        while (pendingBackendCaptureUpdate) {
          const update = pendingBackendCaptureUpdate;
          pendingBackendCaptureUpdate = null;
          if (update.kind === "path") {
            await processBackendJsonPathPayload(update.payload);
          } else if (update.kind === "data") {
            await processBackendJsonDataPayload(update.payload);
          }
        }
      } finally {
        backendCaptureUpdateDrainActive = false;
      }
    })
    .catch((error) => {
      logErrorEntry("backend-progress", error);
      doError("Failed to process backend update", { backend: true });
      backendCaptureUpdateDrainActive = false;
    });
}

async function processBackendJsonPathPayload(payload) {
  const chunkStartTime = performance.now();
  document.getElementById("error-container").style.display = "none";
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
  if (payload.complete) {
    updateBackendProcessingWarning();
  }

  if (!payload.complete) {
    updateBackendProgressStatus();
  }

  const minimumChunkSize = payload.chunkSize || getBackendPacketChunkSize();
  const hasUsableChunk =
    payload.complete || payload.processedPackets >= minimumChunkSize;

  if (!backendProgressState.firstChunkLoaded) {
    if (!hasUsableChunk) {
      document.getElementById("loading-screen").style.display = "flex";
      document.getElementById("loading-container").style.display = "block";
      document.getElementById("loading-text").textContent = "Loading packets...";
      updateBackendProgressStatus({ force: true });
      updateBackendProcessingWarning();
      logIngestionChunkTiming("path", "deferred", payload, performance.now() - chunkStartTime, {
        reason: "waiting-for-minimum-chunk",
      });
      return;
    }

    document.getElementById("loading-screen").style.display = "flex";
    document.getElementById("loading-container").style.display = "block";
    document.getElementById("loading-text").textContent = "Loading packets...";
    updateBackendProgressStatus({ force: true });
    writeLogEntry(
      `Backend snapshot received path = "${payload.path}" processed = ${payload.processedPackets} total = ${payload.totalPackets} complete = ${payload.complete} `,
    );
    hideLoadingOverlay();
    await processCapturePath(payload.path, {
      suppressLoadingOverlay: true,
      incrementalUpdate: false,
    });
    subnetCalculatorPanel.maybeAutoStartCaptureNmapScan({
      reason: "backend-path-first-chunk",
      processedPackets: payload.processedPackets,
      totalPackets: payload.totalPackets,
      complete: payload.complete,
    });
    backendProgressState.firstChunkLoaded = true;
    markAppliedBackendSnapshot(payload);
    hideLoadingOverlay();
    filterInputEl.value = "";
    updateFilterClearButtonState();
    clearFilterQuery();
    syncFilterHighlight();
    logIngestionChunkTiming("path", "first-chunk-applied", payload, performance.now() - chunkStartTime);
  } else {
    if (!payload.complete) {
      updateBackendProcessingWarning();
      logIngestionChunkTiming("path", "deferred", payload, performance.now() - chunkStartTime, {
        reason: "waiting-for-complete",
      });
      return;
    }
    if (!shouldApplyIncrementalBackendSnapshot(payload)) {
      updateBackendProcessingWarning();
      logIngestionChunkTiming("path", "skipped", payload, performance.now() - chunkStartTime, {
        reason: "incremental-throttle",
      });
      return;
    }
    hideLoadingOverlay();
    updateBackendProgressStatus({ force: true });
    await processCapturePath(payload.path, {
      suppressLoadingOverlay: true,
      incrementalUpdate: true,
      finalUpdate: false,
    });
    subnetCalculatorPanel.maybeAutoStartCaptureNmapScan({
      reason: "backend-path-final",
      processedPackets: payload.processedPackets,
      totalPackets: payload.totalPackets,
      complete: payload.complete,
    });
    markAppliedBackendSnapshot(payload);
    writeLogEntry(
      `Backend incremental update processed = ${payload.processedPackets} total = ${payload.totalPackets} complete = ${payload.complete} `,
    );
    logIngestionChunkTiming("path", "final-chunk-applied", payload, performance.now() - chunkStartTime);
  }

  if (payload.complete) {
    backendProgressState.processing = false;
    if (payload.jobId && payload.jobId === activeBackendJobId) {
      activeBackendJobId = "";
    }
    hideLoadingOverlay();
    const loadEndTime = performance.now();
    document.getElementById("load-time").textContent =
      "Load time: " + ((loadEndTime - startTime) / 1000).toFixed(2) + " seconds";
    document.getElementById("total-packets").textContent =
      "Total Packets: " + totalPacketCount();
    scheduleSessionKeychainAutoPopulate("backend-complete");
    writeLogEntry(
      `Completed processing backend data total_packets = ${totalPacketCount()} load_time_sec = ${(
        (loadEndTime - startTime) /
        1000
      ).toFixed(2)
      } `,
    );
    statusUpdate("Status: Ready");
  }

  updateBackendProcessingWarning();
}

async function processBackendJsonDataPayload(payload) {
  const chunkStartTime = performance.now();
  document.getElementById("error-container").style.display = "none";
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
  if (payload.complete) {
    updateBackendProcessingWarning();
  }

  if (!payload.complete) {
    updateBackendProgressStatus();
  }

  const minimumChunkSize = payload.chunkSize || getBackendPacketChunkSize();
  const payloadHasPackets = backendProgressState.firstChunkLoaded
    ? false
    : hasAnyCaptureDataPackets(payload.captureData);
  const hasUsableChunk =
    payload.complete
    || payload.processedPackets >= minimumChunkSize
    || payloadHasPackets;

  if (!backendProgressState.firstChunkLoaded) {
    if (!hasUsableChunk) {
      document.getElementById("loading-screen").style.display = "flex";
      document.getElementById("loading-container").style.display = "block";
      document.getElementById("loading-text").textContent = "Loading packets...";
      updateBackendProgressStatus({ force: true });
      updateBackendProcessingWarning();
      logIngestionChunkTiming("data", "deferred", payload, performance.now() - chunkStartTime, {
        reason: "waiting-for-minimum-chunk",
        label: payload.label,
      });
      return;
    }

    hideLoadingOverlay();
    updateBackendProgressStatus({ force: true });
    writeLogEntry(
      `Backend in-memory snapshot received label=${JSON.stringify(payload.label)} processed = ${payload.processedPackets} total = ${payload.totalPackets} payload_has_packets = ${payloadHasPackets} complete = ${payload.complete}`,
    );
    await yieldToRenderer();
    await processCaptureData(payload.captureData, {
      suppressLoadingOverlay: true,
      incrementalUpdate: false,
    });
    subnetCalculatorPanel.maybeAutoStartCaptureNmapScan({
      reason: "backend-data-first-chunk",
      processedPackets: payload.processedPackets,
      totalPackets: payload.totalPackets,
      complete: payload.complete,
    });
    backendProgressState.firstChunkLoaded = true;
    markAppliedBackendSnapshot(payload);
    clearSummaryContent();
    hideLoadingOverlay();
    filterInputEl.value = "";
    updateFilterClearButtonState();
    clearFilterQuery();
    syncFilterHighlight();
    logIngestionChunkTiming("data", "first-chunk-applied", payload, performance.now() - chunkStartTime, {
      label: payload.label,
    });
  } else {
    if (!payload.complete) {
      updateBackendProcessingWarning();
      logIngestionChunkTiming("data", "deferred", payload, performance.now() - chunkStartTime, {
        reason: "waiting-for-complete",
        label: payload.label,
      });
      return;
    }
    if (!shouldApplyIncrementalBackendSnapshot(payload)) {
      updateBackendProcessingWarning();
      logIngestionChunkTiming("data", "skipped", payload, performance.now() - chunkStartTime, {
        reason: "incremental-throttle",
        label: payload.label,
      });
      return;
    }
    hideLoadingOverlay();
    updateBackendProgressStatus({ force: true });
    await yieldToRenderer();
    await processCaptureData(payload.captureData, {
      suppressLoadingOverlay: true,
      incrementalUpdate: true,
      finalUpdate: false,
    });
    subnetCalculatorPanel.maybeAutoStartCaptureNmapScan({
      reason: "backend-data-final",
      processedPackets: payload.processedPackets,
      totalPackets: payload.totalPackets,
      complete: payload.complete,
    });
    markAppliedBackendSnapshot(payload);
    writeLogEntry(
      `Backend in-memory incremental update processed = ${payload.processedPackets} total = ${payload.totalPackets} complete = ${payload.complete}`,
    );
    logIngestionChunkTiming("data", "final-chunk-applied", payload, performance.now() - chunkStartTime, {
      label: payload.label,
    });
  }

  if (payload.complete) {
    backendProgressState.processing = false;
    if (payload.jobId && payload.jobId === activeBackendJobId) {
      activeBackendJobId = "";
    }
    clearSummaryContent();
    hideLoadingOverlay();
    const loadEndTime = performance.now();
    document.getElementById("load-time").textContent =
      "Load time: " + ((loadEndTime - startTime) / 1000).toFixed(2) + " seconds";
    document.getElementById("total-packets").textContent =
      "Total Packets: " + totalPacketCount();
    scheduleSessionKeychainAutoPopulate("backend-complete");
    writeLogEntry(
      `Completed processing backend in-memory data total_packets = ${totalPacketCount()} load_time_sec = ${(
        (loadEndTime - startTime) /
        1000
      ).toFixed(2)
      } `,
    );
    statusUpdate("Status: Ready");
  }

  updateBackendProcessingWarning();
}

// when the main.js returns the capture path from snitch.py
window.jsonapi.onJsonPath((rawPayload) => {
  const payload = normalizeBackendJsonPathPayload(rawPayload);
  if (!payload || !payload.path) return;
  if (!shouldAcceptBackendPayloadForActiveJob(payload)) return;
  queueBackendCaptureUpdate("path", payload);
});

window.jsonapi.onJsonData((rawPayload) => {
  const payload = normalizeBackendJsonDataPayload(rawPayload);
  if (!payload || !payload.captureData) return;
  if (!shouldAcceptBackendPayloadForActiveJob(payload)) return;
  queueBackendCaptureUpdate("data", payload);
});

// here we create the backend process and hook it to the handler
function runSnitch(file, options = {}) {
  const { fromSessionSource = false, forceUnknownMagicLoad = false } = options;
  const backendJobId = createFrontendBackendJobId();
  activeBackendJobId = backendJobId;
  const backendChunkSize = getBackendPacketChunkSize();
  const backendWorkerThreads = getBackendWorkerThreads();
  const backendTransportOptions = getBackendTransportOptionsFromSettings();
  resetBackendProgressState();
  if (typeof subnetCalculatorPanel?.resetSessionCacheState === "function") {
    subnetCalculatorPanel.resetSessionCacheState();
  } else {
    subnetCalculatorPanel.resetCaptureNmapState();
  }
  backendProgressState.processing = true;
  document.getElementById("loading-screen").style.display = "block";
  document.getElementById("loading-container").style.display = "block";
  document.getElementById("loading-text").textContent = "Loading packets...";
  showSummaryLoading();
  document.getElementById("status").textContent =
    "Status: Running snitch backend, this may take a few minutes...";
  document.getElementById("error-container").style.display = "none";
  startTime = performance.now();
  const useLLM = isLlmEnabledInSettings();
  const fileLabel = fromSessionSource
    ? file?.fileName || "session-stored-pcap"
    : typeof file === "string"
      ? file
      : file?.name || "unknown";
  const backendOptions = {
    ...backendTransportOptions,
    allowUnknownMagicLoad: forceUnknownMagicLoad,
  };
  writeLogEntry(
    `Backend analysis started job_id = ${backendJobId} file = ${fileLabel} llm_enabled = ${useLLM} chunk_size = ${backendChunkSize} worker_threads = ${backendWorkerThreads} tcp_host = ${JSON.stringify(backendTransportOptions.tcpHost)} tcp_port = ${backendTransportOptions.tcpPort} force_legacy = ${backendTransportOptions.forceLegacySpawn} data_mode = ${backendTransportOptions.useHttpDataSnapshots} json_data_emit_interval_ms = ${backendTransportOptions.jsonDataEmitMinIntervalMs} force_unknown_magic = ${forceUnknownMagicLoad} `,
  );
  const backendPromise = fromSessionSource
    ? window.snitchapi && typeof window.snitchapi.runBackendCommandFromSession === "function"
      ? window.snitchapi.runBackendCommandFromSession(
        file,
        useLLM,
        backendChunkSize,
        backendWorkerThreads,
        backendOptions,
        backendJobId,
      )
      : Promise.reject(new Error("Session PCAP reprocess API is unavailable"))
    : window.snitchapi.runBackendCommand(
      file,
      useLLM,
      backendChunkSize,
      backendWorkerThreads,
      backendOptions,
      backendJobId,
    );
  backendPromise
    .then((result) => {
      if (backendJobId !== activeBackendJobId) {
        return;
      }
      if (result && result.pcapSource) {
        setSessionPcapSource(result.pcapSource, {
          logLabel: fromSessionSource ? "session-reprocess" : "backend-file",
        });
      }
    })
    .catch((error) => {
      if (backendJobId !== activeBackendJobId) {
        return;
      }
      doError("Backend run error!", { backend: true });
      logErrorEntry("backend-run", error);
    })
    .finally(() => {
      if (backendJobId !== activeBackendJobId) {
        return;
      }
      backendProgressState.processing = false;
      activeBackendJobId = "";
      updateBackendProcessingWarning();
    });
}

// Handles do error.
function doError(message, { backend = false } = {}) {
  console.error("Error from backend:", message);
  if (backend) {
    writeBackendErrorLogEntry(`Error shown message = "${message}"`);
  } else {
    writeLogEntry(`Error shown message = "${message}"`);
  }
  const loadingContainerEl = document.getElementById("loading-container");
  const loadingScreenEl = document.getElementById("loading-screen");
  const errorContainerEl = document.getElementById("error-container");
  const wantsMagicRetry = backend && /unknown file type based on magic/i.test(String(message || ""));
  clearSummaryContent();
  loadingContainerEl.style.display = "none";
  loadingScreenEl.style.display = "none";
  errorContainerEl.style.display = "block";
  errorContainerEl.innerHTML = "";

  const titleEl = document.createElement("h2");
  titleEl.textContent = "Error!";
  const spacerEl = document.createElement("br");
  const messageEl = document.createElement("p");
  messageEl.id = "error-message";
  messageEl.textContent = message;

  errorContainerEl.appendChild(titleEl);
  errorContainerEl.appendChild(spacerEl);
  errorContainerEl.appendChild(messageEl);

  if (wantsMagicRetry) {
    const actionRow = document.createElement("div");
    actionRow.id = "error-actions";
    actionRow.style.display = "flex";
    actionRow.style.gap = "0.5rem";
    actionRow.style.justifyContent = "center";
    actionRow.style.marginTop = "1rem";

    const retryButton = document.createElement("button");
    retryButton.className = "custom-btns";
    retryButton.textContent = "Retry";
    retryButton.addEventListener("click", (event) => {
      event.stopPropagation();
      const retryTarget = lastBackendLoadRequest;
      if (!retryTarget || retryTarget.kind !== "file" || !retryTarget.filePath) {
        doError("No file is available to retry.");
        return;
      }
      runSnitch(retryTarget.filePath, { forceUnknownMagicLoad: true });
    });

    const pickerButton = document.createElement("button");
    pickerButton.className = "custom-btns";
    pickerButton.textContent = "Return to Session Picker";
    pickerButton.addEventListener("click", (event) => {
      event.stopPropagation();
      errorContainerEl.style.display = "none";
      loadingContainerEl.style.display = "none";
      loadingScreenEl.style.display = "none";
      if (sessionPickerPanel && typeof sessionPickerPanel.show === "function") {
        sessionPickerPanel.show();
      }
    });

    actionRow.appendChild(retryButton);
    actionRow.appendChild(pickerButton);
    errorContainerEl.appendChild(actionRow);
  }

  errorContainerEl.onclick = () => {
    errorContainerEl.style.display = "none";
    loadingContainerEl.style.display = "none";
  };
}

// Hides all data.
function hideAllData() {
  //  document.getElementById("packetInfoPane").textContent =
  //    "No matching packets found.";
  // check if packets were returned
  if (!filteredPackets || filteredPackets.length === 0) {

    // now check if the key in the current filter string is valid
    // by checking if it exists in the validKeysCache
    const currentFilterStr = filterInputEl.value.trim();
    let isValidKey = true;
    let filterKey = "";
    if (currentFilterStr) {
      filterKey = currentFilterStr.split(":")[0].trim();
      // we also need to strip off the ! and ( ) if they exist
      filterKey = filterKey.replace(/^!/, "").replace(/^\(/, "").replace(/\)$/, "");
      if (filterKey !== "" && !validKeysCache.includes(filterKey)) {
        isValidKey = false;
      } else {
        isValidKey = true;
      }
    }
    if (currentFilterStr && !isValidKey) {
      doError(`Invalid filter key: "${filterKey}" in search query "${currentFilterStr}"`);
      statusUpdate(`Status: Invalid filter key: "${filterKey}" in search query."`);
    } else {
      doError("No packets match the filter criteria!");
      statusUpdate("Status: No packets match the filter criteria");
    }
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
// Shows all data.
function showAllData() {
  document.getElementById("prev-btn").style.opacity = "1";
  document.getElementById("next-btn").style.opacity = "1";
  document.getElementById("data-types").style.display = "block";
  document.getElementById("protoInfo").style.display = "block";
  document.getElementById("timestamp").style.display = "block";
  document.getElementById("rightside").style.display = "block";
  document.getElementById("active-recon").style.display = "block";
  const rightsideDataEl = document.getElementById("rightside-data");
  const rightsideNotesEl = document.getElementById("rightside-notes");
  const rightsideConvInsightsEl = document.getElementById("rightside-conv-insights");
  if (rightsideDataEl) rightsideDataEl.hidden = false;
  if (rightsideNotesEl) rightsideNotesEl.hidden = true;
  if (rightsideConvInsightsEl) rightsideConvInsightsEl.hidden = true;
  document.getElementById("settings_box").style.display = "none";
  document.getElementById("hexg").hidden = false;
  document.getElementById("error-container").style.display = "none";
}

// ============================================================================
// Event wiring and application bootstrap
// ============================================================================

document
  .getElementById("filterStr")
  .addEventListener("keydown", async function (event) {
    if (event.key === "Tab") {
      if (await applyTabFilterKeyAutocomplete()) {
        event.preventDefault();
      }
      return;
    }
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
  onFilterBarContextMenu: ({ event, target }) => {
    if (!(target instanceof Element)) return false;
    if (!target.closest("#filterStr-wrap")) return false;
    event.preventDefault();
    void saveCurrentFilterToLibraryFromContextMenu();
    return true;
  },
  showConvertContextMenu,
  hideConvertContextMenu,
});

filterInputEl.addEventListener("input", () => {
  syncFilterHighlight();
  void refreshFilterAutocompleteOptions();
  if (filterInputEl.value.trim() === "") {
    syncTargetHostSelection(DUMMY_ALL_HOST);
  }
});
filterInputEl.addEventListener("click", refreshFilterAutocompleteOptions);
filterInputEl.addEventListener("focus", refreshFilterAutocompleteOptions);
filterInputEl.addEventListener("scroll", syncFilterHighlightScroll);

filterHistorySelectEl.addEventListener("change", () => {
  const selectedValue = filterHistorySelectEl.value;
  if (!selectedValue) return;

  let selectedQuery = "";
  if (selectedValue.startsWith(FILTER_DROPDOWN_OPTION_PREFIX_SAVED)) {
    const savedFilterId = selectedValue.slice(
      FILTER_DROPDOWN_OPTION_PREFIX_SAVED.length,
    );
    selectedQuery = resolveSavedFilterById(savedFilterId)?.query || "";
  } else if (selectedValue.startsWith(FILTER_DROPDOWN_OPTION_PREFIX_SESSION)) {
    selectedQuery = selectedValue.slice(
      FILTER_DROPDOWN_OPTION_PREFIX_SESSION.length,
    );
  } else {
    selectedQuery = selectedValue;
  }

  if (!selectedQuery) return;
  filterInputEl.value = selectedQuery;
  syncFilterHighlight();
  void runFilterQuery(selectedQuery);
  filterHistorySelectEl.value = "";
  collapseFilterHistoryDropdown();
});

filterHistorySelectEl.addEventListener("focus", () => {
  expandFilterHistoryDropdownAlignedToFilterInput();
});

filterHistorySelectEl.addEventListener("mousedown", () => {
  expandFilterHistoryDropdownAlignedToFilterInput();
});

filterHistorySelectEl.addEventListener("blur", () => {
  collapseFilterHistoryDropdown();
});

window.addEventListener("resize", () => {
  if (filterHistorySelectEl.classList.contains("filter-history-expanded")) {
    expandFilterHistoryDropdownAlignedToFilterInput();
  }
});

renderFilterHistory();
void loadSavedFilterLibrary();
renderDataToolsInputHistory();
syncFilterHighlight();

window.onerror = (message, source, lineno, colno) => {
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

if (window.snitchapi && typeof window.snitchapi.onBackendServiceState === "function") {
  window.snitchapi.onBackendServiceState((state) => {
    const { ready, respawnPending, attempts, error } = state || {};
    console.log("[Backend service state]", state);
    if (ready) {
      refreshBackendDiagnostics({ ensureReady: false });
      statusUpdate("Backend service connected");
      return;
    }
    if (respawnPending) {
      statusUpdate(`Backend service disconnected — respawn attempt ${attempts || 1} pending`);
      return;
    }
    if (error) {
      statusUpdate(`Backend service error: ${error}`);
    }
    refreshBackendDiagnostics({ ensureReady: false });
  });
}

void loadAvailableThemes()
  .then(() => updateThemeDirectoryHint())
  .then(() => loadAvailableOllamaModels())
  .then(() => loadPersistedSettings())
  .then(() => refreshPluginRegistryView())
  .then(() => {
    // Wire the Themes subtab UI but do NOT fetch the online catalog here.
    // The catalog call hits a remote HTTPS endpoint and must never block
    // the startup-preload chain; it is invoked on-demand when the user
    // opens the Themes subtab or clicks Refresh Catalog.
    bindThemesSubtabEvents();
    setThemesCatalogStatus(
      "Click Refresh Catalog to load purchasable themes from the online catalog.",
    );
    return null;
  })
  .then(() => {
    startupSettingsInitialized = true;
    maybeHideStartupPreload();
  })
  .then(async () => {
    startupReleaseCheckPromise = maybeShowSettingsAboutForNewRelease();
    window.__PACKETSNITCH_STARTUP_RELEASE_CHECK_PROMISE__ = startupReleaseCheckPromise;
    return startupReleaseCheckPromise;
  })
  .catch((error) => {
    console.warn("Unable to initialize themes/settings:", error);
    syncSettingsFormFromState();
    startupSettingsInitialized = true;
    maybeHideStartupPreload();
  });

// On page load, hide packet info and payload panes
onload = function () {
  // document.getElementById("selectBookmark").style.display = "none";
  hideConvertContextMenu();
  keystorePanel.resetKeystoreState();
  setCryptSubtab(CRYPT_SSL_SUBTAB);
  setConvSubtab(CONV_CONVERSIONS_SUBTAB);
  setSettingsSubtab(SETTINGS_SUBTAB_GENERAL);
  syncSettingsFormFromState();
  renderPluginErrorPanel();
  updateDataToolsHexHighlights();
  syncDataToolsHighlightScroll(
    "data-tools-input",
    "data-tools-input-highlight",
  );
  syncDataToolsHighlightScroll(
    "data-tools-hex-output",
    "data-tools-hex-output-highlight",
  );
  markDataToolsInputCommitted();
  document.getElementById("packetInfoPane").style.display = "none";
  document.getElementById("packetPayloadPane").style.display = "none";
  installExtractionPanelListeners();
  document.getElementById("rightside").style.display = "block";
  document.getElementById("help-btn").style.opacity = "1";
  document.getElementById("log-btn").style.opacity = "1";
  document.getElementById("settings-btn").style.opacity = "1";
  const rightsideDataEl = document.getElementById("rightside-data");
  const rightsideNotesEl = document.getElementById("rightside-notes");
  const rightsideConvInsightsEl = document.getElementById("rightside-conv-insights");
  if (rightsideDataEl) rightsideDataEl.hidden = false;
  if (rightsideNotesEl) rightsideNotesEl.hidden = true;
  if (rightsideConvInsightsEl) rightsideConvInsightsEl.hidden = true;
  updatePcapSizeDisplayFromSource();
  updateReprocessButtonState();
  document.getElementById("leftside").style.display = "block";
  document.getElementById("loading-container").style.display = "none";
  const startupVersionEl = document.getElementById("startup-preload-version");
  if (startupVersionEl) {
    startupVersionEl.textContent = `PacketSnitch v${psVer}`;
  }
  startupWindowLoaded = true;
  maybeHideStartupPreload();
};
