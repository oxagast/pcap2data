// Settings tab diagnostic helpers — extracted from
// ``src/ui/main-frontend.js`` so the orchestrator file stays below
// the ~10k-line mark. The factory owns the LLM / Metrics / Backend /
// VirusTotal / Hashes.com diagnostic probes that surface as the four
// to eight "status pills" the user sees in the Settings → About and
// Settings → API Keys panels.
//
// State bridge: the orchestrator declares thirteen module-level
// ``let``s that the diagnostic cluster mutates (the cached probe
// payloads, the in-flight promises, the dedupe timestamps, and the
// ``ollamaVersionCheckPassed`` flag the threat-score card reads).
// The factory accesses those via a getter/setter bridge so the
// orchestrator's identifiers stay authoritative and the factory
// remains a pure module that webpack can tree-shake.
//
// External deps:
//   - ``getCurrentSettings`` and ``getBackendTransportOptionsFromSettings``:
//     orchestrator functions that read live settings for the
//     diagnostic probes (privacy.endpoint, transport.tls).
//   - ``resolveSubnetCalculatorPanel``: thunk that returns the
//     subnet-calculator panel via ``globalThis.subnetCalculatorPanel``.
//     The orchestrator publishes that thunk right after the panel's
//     ``const`` declaration so the factory can look it up lazily —
//     the original cluster already TDZ-guarded this access with
//     ``setTimeout(..., 0)`` + ``try/catch`` for the same reason.
//
// Constants:
//   - ``VIRUS_TOTAL_DIAGNOSTICS_DEDUPE_MS``,
//     ``HASHES_COM_DIAGNOSTICS_DEDUPE_MS``, and
//     ``METRICS_DIAGNOSTICS_DEDUPE_MS`` (each 30s) coalesce concurrent
//     callers and skip a probe when a recent successful one is still
//     fresh.

function createSettingsDiagnosticsHelpers({
  state,
  VIRUS_TOTAL_DIAGNOSTICS_DEDUPE_MS,
  HASHES_COM_DIAGNOSTICS_DEDUPE_MS,
  METRICS_DIAGNOSTICS_DEDUPE_MS,
  getCurrentSettings,
  getBackendTransportOptionsFromSettings,
  resolveSubnetCalculatorPanel,
}) {
async function refreshOllamaStartupAvailability() {
  if (!window.installapi || typeof window.installapi.getLlmDiagnostics !== "function") {
    state.ollamaVersionCheckPassed = false;
    state.cachedLlmDiagnostics = null;
    return state.ollamaVersionCheckPassed;
  }
  try {
    const diagnostics = await window.installapi.getLlmDiagnostics();
    state.cachedLlmDiagnostics = diagnostics || null;
    state.ollamaVersionCheckPassed = Boolean(
      diagnostics?.ollamaInstalled && diagnostics?.ollamaServerListening,
    );
    syncLlmDiagnosticsIndicators();
  } catch (error) {
    console.warn("Unable to resolve Ollama startup availability:", error);
    state.ollamaVersionCheckPassed = false;
    state.cachedLlmDiagnostics = null;
    syncLlmDiagnosticsIndicators();
  }
  // Re-render the Session Threat Score card so the LLM "Get Assessment"
  // button enables/disables to track Ollama availability. The
  // ``void refreshOllamaStartupAvailability()`` invocation runs
  // during initial load, but ``subnetCalculatorPanel`` is declared
  // further down in the module (line ~21237) as a ``const``, which
  // means it sits in its temporal dead zone until that line executes.
  // The ``await`` above normally yields long enough for the top-level
  // execution to reach the panel declaration, but if the IPC reply
  // resolves before line 21237 runs (or webpack's eval wrapper
  // changes the tick ordering), the resume can hit a TDZ. Defer
  // the recompute with ``setTimeout(..., 0)`` AND wrap it in a
  // try/catch — the try/catch protects against TDZ ``ReferenceError``
  // (which ``typeof`` does NOT), and the setTimeout guarantees the
  // access lands on a fresh macrotask after the entire renderer
  // module has finished loading.
  setTimeout(() => {
    try {
      const subnetCalculatorPanel = resolveSubnetCalculatorPanel();
      if (subnetCalculatorPanel
        && typeof subnetCalculatorPanel.recomputeSessionThreatScore === "function") {
        subnetCalculatorPanel.recomputeSessionThreatScore({ silent: true });
      }
    } catch (_error) {
      // subnetCalculatorPanel may still be in its temporal dead
      // zone if the renderer module hasn't finished loading yet.
      // Swallow — the recompute is a UI nicety, not a correctness
      // requirement, and the next legitimate refresh call will
      // succeed once the panel is bound.
    }
  }, 0);
  return state.ollamaVersionCheckPassed;
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
  const diagnostics = state.cachedLlmDiagnostics;
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
  const diagnostics = state.cachedMetricsDiagnostics || {};
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
    state.cachedMetricsDiagnostics = null;
    syncMetricsDiagnosticsIndicators();
    return null;
  }
  if (!force && state.metricsDiagnosticsInFlight) {
    return state.metricsDiagnosticsInFlight;
  }
  if (
    !force
    && state.cachedMetricsDiagnostics
    && Date.now() - state.metricsDiagnosticsLastSuccessAt < METRICS_DIAGNOSTICS_DEDUPE_MS
  ) {
    return state.cachedMetricsDiagnostics;
  }
  state.metricsDiagnosticsInFlight = (async () => {
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
      state.cachedMetricsDiagnostics = {
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
      state.metricsDiagnosticsLastSuccessAt = Date.now();
    } catch (error) {
      console.warn("Unable to resolve Metrics diagnostics:", error);
      state.cachedMetricsDiagnostics = {
        consentStatus: null,
        endpointReachable: false,
        lastFlush: {
          checkedAt: new Date().toISOString(),
          ok: false,
          reason: "probe-failed",
        },
      };
    } finally {
      state.metricsDiagnosticsInFlight = null;
    }
    syncMetricsDiagnosticsIndicators();
    return state.cachedMetricsDiagnostics;
  })();
  return state.metricsDiagnosticsInFlight;
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

function getBackendHashesComApiKey(settings = getCurrentSettings()) {
  return String(settings?.apiKeys?.hashesComApiKey || "").trim();
}

function syncVirusTotalDiagnosticsIndicators() {
  const diagnostics = state.cachedVirusTotalDiagnostics;
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
  const diagnostics = state.cachedBackendDiagnostics;
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
    state.cachedVirusTotalDiagnostics = null;
    syncVirusTotalDiagnosticsIndicators();
    return null;
  }

  // Coalesce concurrent callers so a startup burst (eager + loadPersistedSettings
  // + backend-service-ready) only hits the VirusTotal API once. Also skip the
  // probe entirely when a recent successful diagnostic is still fresh.
  if (!force) {
    if (state.virusTotalDiagnosticsInFlight) {
      return state.virusTotalDiagnosticsInFlight;
    }
    if (
      state.cachedVirusTotalDiagnostics &&
      state.cachedVirusTotalDiagnostics.endpointReachable !== false &&
      Date.now() - state.virusTotalDiagnosticsLastSuccessAt < VIRUS_TOTAL_DIAGNOSTICS_DEDUPE_MS
    ) {
      return state.cachedVirusTotalDiagnostics;
    }
  }

  const apiKey = getBackendVirusTotalApiKey();
  state.virusTotalDiagnosticsInFlight = (async () => {
    try {
      const diagnostics = await window.snitchapi.lookupVirusTotal("8.8.8.8", {
        lookupType: "ip",
        apiKey,
        diagnosticOnly: true,
        backendOptions: getBackendTransportOptionsFromSettings(),
      });
      state.cachedVirusTotalDiagnostics = diagnostics || null;
      if (state.cachedVirusTotalDiagnostics) {
        state.virusTotalDiagnosticsLastSuccessAt = Date.now();
      }
    } catch (error) {
      console.warn("Unable to resolve VirusTotal diagnostics:", error);
      state.cachedVirusTotalDiagnostics = {
        endpointReachable: false,
        keyConfigured: Boolean(apiKey),
        keyValid: false,
        error: error?.message || String(error),
      };
    } finally {
      state.virusTotalDiagnosticsInFlight = null;
    }
    syncVirusTotalDiagnosticsIndicators();
    return state.cachedVirusTotalDiagnostics;
  })();

  return state.virusTotalDiagnosticsInFlight;
}

// Clears the cached VirusTotal diagnostics so the next refresh re-probes the
// API. Used when settings (e.g. API key) change and a stale result must not
// mask the new configuration.
function invalidateVirusTotalDiagnosticsCache() {
  state.virusTotalDiagnosticsLastSuccessAt = 0;
  state.cachedVirusTotalDiagnostics = null;
  syncVirusTotalDiagnosticsIndicators();
}

// ── hashes.com diagnostics ──────────────────────────────────────────────────
//
// The hashes.com probe is a zero-credit empty lookup (POST an empty
// ``hashes[]`` field — the API accepts it as a no-op). The Settings tab
// renders four pills: endpoint reachability, key validity, last cost, and
// last lookup result. Like the VirusTotal path we coalesce concurrent
// callers and cache a recent successful probe for 30s so a startup burst
// only hits the API once.

function syncHashesComDiagnosticsIndicators() {
  const diagnostics = state.cachedHashesComDiagnostics;
  const hasStoredKey = Boolean(getBackendHashesComApiKey());
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

  // "Last Cost" pill surfaces the credit cost reported by the most
  // recent reverse lookup (cached separately from the diagnostic
  // probe so we can show the actual cost the user paid, not just the
  // cost of the diagnostic ping — which is always zero). When no
  // lookup has happened yet we surface "—" with a neutral class so
  // the pill never claims a false zero.
  const lastCost = Number(state.cachedHashesComLastLookup?.cost);
  const hasLastLookup = Boolean(state.cachedHashesComLastLookup);
  const creditValue = hasLastLookup && Number.isFinite(lastCost)
    ? `${lastCost} credit${lastCost === 1 ? "" : "s"}`
    : "—";
  const creditClass = !hasLastLookup
    ? "status-neutral"
    : lastCost === 0
      ? "status-ok"
      : "status-warn";

  const lastLookupStatus = state.cachedHashesComLastLookup?.success;
  const lastLookupError = state.cachedHashesComLastLookup?.error;
  const lastLookupValue = !state.cachedHashesComLastLookup
    ? "—"
    : lastLookupStatus === true
      ? "OK"
      : lastLookupStatus === false
        ? `Error: ${lastLookupError || "lookup failed"}`
        : "—";
  const lastLookupClass = !state.cachedHashesComLastLookup
    ? "status-neutral"
    : lastLookupStatus === true
      ? "status-ok"
      : lastLookupStatus === false
        ? "status-error"
        : "status-neutral";

  renderBackendDiagnosticIndicator(
    "settings-backend-hashescom-endpoint-status",
    "Hashes.com Endpoint",
    endpointValue,
    endpointClass,
  );
  renderBackendDiagnosticIndicator(
    "settings-backend-hashescom-key-status",
    "Hashes.com Key",
    keyValue,
    keyClass,
  );
  renderBackendDiagnosticIndicator(
    "settings-backend-hashescom-credit-status",
    "Last Cost",
    creditValue,
    creditClass,
  );
  renderBackendDiagnosticIndicator(
    "settings-backend-hashescom-last-result-status",
    "Last Lookup",
    lastLookupValue,
    lastLookupClass,
  );
}

async function refreshHashesComDiagnostics({ force = false } = {}) {
  if (
    !window.extractapi
    || typeof window.extractapi.hashesComDiagnostics !== "function"
  ) {
    state.cachedHashesComDiagnostics = null;
    syncHashesComDiagnosticsIndicators();
    return null;
  }

  if (!force) {
    if (state.hashesComDiagnosticsInFlight) {
      return state.hashesComDiagnosticsInFlight;
    }
    if (
      state.cachedHashesComDiagnostics
      && state.cachedHashesComDiagnostics.endpointReachable !== false
      && Date.now() - state.hashesComDiagnosticsLastSuccessAt
      < HASHES_COM_DIAGNOSTICS_DEDUPE_MS
    ) {
      return state.cachedHashesComDiagnostics;
    }
  }

  const apiKey = getBackendHashesComApiKey();
  state.hashesComDiagnosticsInFlight = (async () => {
    try {
      const diagnostics = await window.extractapi.hashesComDiagnostics({
        apiKey,
      });
      state.cachedHashesComDiagnostics = diagnostics || null;
      if (state.cachedHashesComDiagnostics?.endpointReachable) {
        state.hashesComDiagnosticsLastSuccessAt = Date.now();
      }
    } catch (error) {
      console.warn("Unable to resolve hashes.com diagnostics:", error);
      state.cachedHashesComDiagnostics = {
        endpointReachable: false,
        keyConfigured: Boolean(apiKey),
        keyValid: false,
        success: false,
        cost: 0,
        count: 0,
        lastError: error?.message || String(error),
        checkedAt: new Date().toISOString(),
      };
    } finally {
      state.hashesComDiagnosticsInFlight = null;
    }
    syncHashesComDiagnosticsIndicators();
    return state.cachedHashesComDiagnostics;
  })();
  return state.hashesComDiagnosticsInFlight;
}

function invalidateHashesComDiagnosticsCache() {
  state.hashesComDiagnosticsLastSuccessAt = 0;
  state.cachedHashesComDiagnostics = null;
  syncHashesComDiagnosticsIndicators();
}

// Capture the cost + success state from a real reverse lookup so the
// "Last Cost" / "Last Lookup" pills can reflect what the user actually
// paid. Called from the data-tools panel after every
// ``hashes-com:search`` round-trip.
function recordHashesComLookupOutcome({ success, cost, error }) {
  state.cachedHashesComLastLookup = {
    success: success === true,
    cost: Number.isFinite(Number(cost)) ? Number(cost) : 0,
    error: typeof error === "string" ? error : "",
    at: new Date().toISOString(),
  };
  syncHashesComDiagnosticsIndicators();
}

async function refreshBackendDiagnostics({ ensureReady = false } = {}) {
  if (!window.snitchapi || typeof window.snitchapi.getBackendDiagnostics !== "function") {
    state.cachedBackendDiagnostics = null;
    syncBackendDiagnosticsIndicators();
    return null;
  }

  try {
    const diagnostics = await window.snitchapi.getBackendDiagnostics({
      ensureReady: Boolean(ensureReady),
      backendOptions: getBackendTransportOptionsFromSettings(),
    });
    state.cachedBackendDiagnostics = diagnostics || null;
  } catch (error) {
    console.warn("Unable to resolve backend diagnostics:", error);
    state.cachedBackendDiagnostics = null;
  }
  syncBackendDiagnosticsIndicators();
  await refreshVirusTotalDiagnostics();
  await refreshHashesComDiagnostics();
  return state.cachedBackendDiagnostics;
}


  return {
    refreshOllamaStartupAvailability,
    getLlmDiagnosticElement,
    renderLlmDiagnosticIndicator,
    syncLlmDiagnosticsIndicators,
    getMetricsDiagnosticElement,
    renderMetricsDiagnosticIndicator,
    syncMetricsDiagnosticsIndicators,
    formatRelativeTimestamp,
    refreshMetricsDiagnostics,
    getBackendDiagnosticElement,
    renderBackendDiagnosticIndicator,
    getBackendVirusTotalApiKey,
    getBackendHashesComApiKey,
    syncVirusTotalDiagnosticsIndicators,
    syncBackendDiagnosticsIndicators,
    refreshVirusTotalDiagnostics,
    invalidateVirusTotalDiagnosticsCache,
    syncHashesComDiagnosticsIndicators,
    refreshHashesComDiagnostics,
    invalidateHashesComDiagnosticsCache,
    recordHashesComLookupOutcome,
    refreshBackendDiagnostics,
  };
}

module.exports = {
  createSettingsDiagnosticsHelpers,
};
