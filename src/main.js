// Runs the Electron main process, app lifecycle, and desktop IPC services.

const { app, BrowserWindow, ipcMain, dialog, shell } = require("electron");
const appLock = app.requestSingleInstanceLock();
const userAgent = `Mozilla/5.0 (compatible; PacketSnitch/${app.getVersion()}; +http://packetsnitch.com)`;
app.userAgentFallback = userAgent;
app.on("web-contents-created", (_event, webContents) => {
  webContents.setUserAgent(userAgent);
});
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { pathToFileURL } = require("url");
const { exec, execFile } = require("child_process");
const os = require("os");
const util = require("util");
const { pipeline } = require("stream");
const { gzip, gunzip, brotliDecompress } = require("zlib");
const { registerCaptureStoreHandlers } = require("./capture-store");
const { Agent, fetch: undiciFetch } = require("undici");
const {
  DEFAULT_SETTINGS,
  normalizeSettings,
} = require("./settings");

let Ollama = null;
try {
  ({ Ollama } = require("ollama"));
} catch (error) {
  console.warn(
    "Ollama Node client module is unavailable. LLM features will be disabled.",
    error,
  );
}

let lzmaNative = null;
try {
  lzmaNative = require("lzma-native");
} catch (err) {
  console.warn("lzma-native is unavailable, session compression will require fallback", err);
}
let BSON = null;
try {
  BSON = require("bson");
} catch (err) {
  console.warn("bson is unavailable, BSON session format will be disabled", err);
}
const gzipAsync = util.promisify(gzip);
const gunzipAsync = util.promisify(gunzip);
const brotliDecompressAsync = util.promisify(brotliDecompress);
const execFileAsync = util.promisify(execFile);
const streamPipelineAsync = util.promisify(pipeline);

let unzipper = null;
try {
  unzipper = require("unzipper");
} catch (error) {
  console.warn("unzipper is unavailable, plugin zip install will be disabled", error);
}
const platform = os.platform();
const SESSION_COMPRESSION_XZ = "xz";
const SESSION_COMPRESSION_GZIP = "gzip";
const SESSION_FORMAT_BSON_GZIP = "bson-gzip";
const testcaseTempDir = path.join(os.tmpdir(), "testcases");
const EXTRACTION_MAX_INPUT_BYTES = 256 * 1024 * 1024;
const EXTRACTION_MAX_OUTPUT_BYTES = 256 * 1024 * 1024;
const EXTRACTION_SYSTEM_TIMEOUT_MS = 30_000;
const CONSOLE_INSPECT_DEPTH = 6;
const CONSOLE_MAX_ARRAY_LENGTH = 50;
const ollamaDispatcherCache = new Map();
const activeNmapScans = new Set();

function getOllamaDispatcher(timeoutMs) {
  const normalizedTimeoutMs = Number.isFinite(timeoutMs) && timeoutMs > 0
    ? Math.floor(timeoutMs)
    : 5 * 60 * 1000;
  const cacheKey = String(normalizedTimeoutMs);
  if (!ollamaDispatcherCache.has(cacheKey)) {
    ollamaDispatcherCache.set(
      cacheKey,
      new Agent({
        headersTimeout: normalizedTimeoutMs,
        bodyTimeout: normalizedTimeoutMs,
      }),
    );
  }
  return ollamaDispatcherCache.get(cacheKey);
}

function getOllamaFetch(timeoutMs) {
  const dispatcher = getOllamaDispatcher(timeoutMs);
  return (input, init = {}) =>
    undiciFetch(input, {
      ...init,
      headers: (() => {
        const headers = new Headers(init.headers || {});
        headers.set("User-Agent", userAgent);
        return headers;
      })(),
      dispatcher,
    });
}

function isOllamaClientModuleAvailable() {
  return typeof Ollama === "function";
}

function isOllamaCloudModel(modelName) {
  const normalized = String(modelName || "").trim().toLowerCase();
  return normalized.endsWith(":cloud");
}

async function fetchLocalOllamaModels() {
  if (!isOllamaClientModuleAvailable()) {
    return [];
  }

  try {
    const client = new Ollama();
    const response = await client.list();
    const modelEntries = Array.isArray(response?.models)
      ? response.models
      : [];

    return modelEntries
      .map((entry) => {
        const value =
          typeof entry?.model === "string" && entry.model.trim()
            ? entry.model.trim()
            : typeof entry?.name === "string" && entry.name.trim()
              ? entry.name.trim()
              : "";
        if (!value) return null;

        const label =
          typeof entry?.details?.family === "string" && entry.details.family.trim()
            ? `${entry.details.family.trim()}:${value.split(":").pop() || value}`
            : value;

        return { value, label };
      })
      .filter(Boolean);
  } catch (error) {
    console.warn("Unable to fetch local Ollama model list:", error?.message || String(error));
    return [];
  }
}

const OLLAMA_CLOUD_PING_URL = "https://ollama.com/api/generate";
const OLLAMA_CLOUD_PING_MODEL = "gpt-oss:120b";
const RENDERER_CSP = [
  "default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com data:",
  "script-src 'self' 'unsafe-eval' 'unsafe-inline' data: blob:",
  "worker-src 'self' blob: data:",
  "connect-src 'self' https://api.github.com https://github.com",
  "img-src 'self' data: blob:"
].join("; ");

let isRendererCspHookInstalled = false;

function shouldApplyRendererCsp(url) {
  return typeof url === "string"
    && (url.startsWith("file://")
      || url.startsWith("app://")
      || url.startsWith("devtools://")
      || url.startsWith("http://localhost:")
      || url.startsWith("http://127.0.0.1:"));
}

function ensureRendererCspHeader(webContentsSession) {
  if (isRendererCspHookInstalled || !webContentsSession?.webRequest) {
    return;
  }

  webContentsSession.webRequest.onHeadersReceived((details, callback) => {
    if (details.resourceType !== "mainFrame" || !shouldApplyRendererCsp(details.url)) {
      callback({ responseHeaders: details.responseHeaders });
      return;
    }

    const responseHeaders = {
      ...(details.responseHeaders || {}),
      "Content-Security-Policy": [RENDERER_CSP],
    };

    Object.keys(responseHeaders).forEach((headerName) => {
      if (headerName.toLowerCase() === "content-security-policy" && headerName !== "Content-Security-Policy") {
        delete responseHeaders[headerName];
      }
    });

    callback({ responseHeaders });
  });

  isRendererCspHookInstalled = true;
}

function isLikelyIpAddress(value) {
  const rawValue = String(value || "").trim();
  if (!rawValue) return false;
  if (rawValue.includes(":")) {
    return /^[0-9a-fA-F:]+$/.test(rawValue);
  }
  const ipv4Parts = rawValue.split(".");
  if (ipv4Parts.length !== 4) return false;
  return ipv4Parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;
    const parsed = Number(part);
    return Number.isInteger(parsed) && parsed >= 0 && parsed <= 255;
  });
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

function normalizeNmapTargets(rawTargets) {
  if (!Array.isArray(rawTargets)) return [];
  const byIp = new Map();
  for (const candidate of rawTargets) {
    if (!candidate || typeof candidate !== "object") continue;
    const rawIp = String(candidate.ip || "").trim();
    const ip = String(extractIpv6EndpointParts(rawIp)?.host || rawIp).trim();
    if (!isLikelyIpAddress(ip)) continue;
    const ports = Array.isArray(candidate.ports)
      ? candidate.ports
      : [];
    const validPorts = ports
      .map((portValue) => Number.parseInt(String(portValue), 10))
      .filter((portValue) => Number.isInteger(portValue) && portValue >= 1 && portValue <= 65535);
    if (!validPorts.length) continue;
    if (!byIp.has(ip)) {
      byIp.set(ip, new Set());
    }
    const portSet = byIp.get(ip);
    validPorts.forEach((portValue) => portSet.add(portValue));
  }

  return Array.from(byIp.entries()).map(([ip, portSet]) => ({
    ip,
    ports: Array.from(portSet).sort((a, b) => a - b),
  }));
}

async function checkNmapInstalled() {
  try {
    const { stdout } = await execFileAsync("nmap", ["--version"], {
      timeout: 4000,
      windowsHide: true,
      maxBuffer: 512 * 1024,
    });
    const versionLine = String(stdout || "")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => line.length > 0)
      || "nmap --version";
    return {
      installed: true,
      version: versionLine,
    };
  } catch (error) {
    return {
      installed: false,
      version: "",
      error: error?.message || "nmap executable not available",
    };
  }
}

function ensureNmapOutputDirectory() {
  const nmapDir = path.join(app.getPath("userData"), "nmap-scans");
  fs.mkdirSync(nmapDir, { recursive: true });
  return nmapDir;
}

function buildNmapScanFilePath(outputDir, ipAddress) {
  const safeIp = String(ipAddress || "host")
    .trim()
    .replace(/[^a-zA-Z0-9._:-]/g, "_")
    .replace(/:/g, "-");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  return path.join(outputDir, `nmap-sv-${safeIp}-${timestamp}.xml`);
}

function getNmapScanRuntimeStatus() {
  let runningCount = 0;
  activeNmapScans.forEach((childProc) => {
    if (!childProc) return;
    if (childProc.exitCode === null && childProc.signalCode === null) {
      runningCount += 1;
    }
  });
  return {
    running: runningCount > 0,
    runningCount,
  };
}

function runTrackedNmapExec(args, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const childProc = execFile(
      "nmap",
      args,
      {
        timeout: timeoutMs,
        windowsHide: true,
        maxBuffer: 8 * 1024 * 1024,
      },
      (error, stdout, stderr) => {
        activeNmapScans.delete(childProc);
        if (settled) return;
        settled = true;
        if (error) {
          error.stdout = stdout;
          error.stderr = stderr;
          reject(error);
          return;
        }
        resolve({ stdout, stderr });
      },
    );

    activeNmapScans.add(childProc);
    childProc.once("error", () => {
      activeNmapScans.delete(childProc);
    });
    childProc.once("exit", () => {
      activeNmapScans.delete(childProc);
    });
  });
}

function isNmapServiceScanEnabledInSettings() {
  const settings = appSettings && typeof appSettings === "object"
    ? appSettings
    : DEFAULT_SETTINGS;
  return Boolean(settings?.general?.nmapServiceScanEnabled);
}

async function runNmapServiceScan(targets, options = {}) {
  const normalizedTargets = normalizeNmapTargets(targets);
  if (!normalizedTargets.length) {
    return {
      success: false,
      error: "No valid nmap targets were provided",
      targets: [],
      results: [],
    };
  }

  const nmapStatus = await checkNmapInstalled();
  if (!nmapStatus.installed) {
    return {
      success: false,
      error: nmapStatus.error || "nmap is not installed",
      nmapInstalled: false,
      targets: normalizedTargets,
      results: [],
    };
  }

  const timeoutMs = Number(options?.timeoutMs) > 0
    ? Number(options.timeoutMs)
    : 120000;
  const outputDir = ensureNmapOutputDirectory();
  const results = await Promise.all(
    normalizedTargets.map(async (target) => {
      const xmlOutputPath = buildNmapScanFilePath(outputDir, target.ip);
      const portsArg = target.ports.join(",");
      const args = ["-sV", "-p", portsArg, "-oX", xmlOutputPath, target.ip];
      try {
        const { stdout, stderr } = await runTrackedNmapExec(args, timeoutMs);
        const xml = fs.existsSync(xmlOutputPath)
          ? fs.readFileSync(xmlOutputPath, "utf8")
          : "";
        return {
          ip: target.ip,
          ports: target.ports,
          xmlPath: xmlOutputPath,
          xml,
          stdout: String(stdout || ""),
          stderr: String(stderr || ""),
          success: true,
        };
      } catch (error) {
        const xml = fs.existsSync(xmlOutputPath)
          ? fs.readFileSync(xmlOutputPath, "utf8")
          : "";
        return {
          ip: target.ip,
          ports: target.ports,
          xmlPath: xmlOutputPath,
          xml,
          stdout: String(error?.stdout || ""),
          stderr: String(error?.stderr || ""),
          success: false,
          error: error?.message || "nmap scan failed",
        };
      }
    }),
  );

  return {
    success: results.some((entry) => entry.success),
    nmapInstalled: true,
    version: nmapStatus.version || "",
    targets: normalizedTargets,
    results,
  };
}

function getLlmDiagnostics() {
  return {
    ollamaInstalled: cachedOllamaInstalled,
    ollamaServerListening: cachedOllamaServerListening,
    cloudApiReachable: cachedOllamaCloudApiReachable,
    cloudApiResultCode: cachedOllamaCloudApiResultCode,
    lastCallResultCode: cachedLlmLastCallResultCode,
    lastCallAt: cachedLlmLastCallAt,
    lastCallError: cachedLlmLastCallError,
    cloudApiCheckedAt: cachedOllamaCloudApiCheckedAt,
    cloudApiError: cachedOllamaCloudApiError,
    startupCheckedAt: cachedOllamaStartupCheckedAt,
  };
}

function broadcastLlmDiagnosticsUpdate() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send("llm-diagnostics-updated", getLlmDiagnostics());
}

function setLlmDiagnostics(partialDiagnostics = {}) {
  if (Object.prototype.hasOwnProperty.call(partialDiagnostics, "ollamaInstalled")) {
    cachedOllamaInstalled = Boolean(partialDiagnostics.ollamaInstalled);
  }
  if (Object.prototype.hasOwnProperty.call(partialDiagnostics, "ollamaServerListening")) {
    cachedOllamaServerListening = Boolean(partialDiagnostics.ollamaServerListening);
  }
  if (Object.prototype.hasOwnProperty.call(partialDiagnostics, "cloudApiReachable")) {
    cachedOllamaCloudApiReachable = Boolean(partialDiagnostics.cloudApiReachable);
  }
  if (Object.prototype.hasOwnProperty.call(partialDiagnostics, "cloudApiResultCode")) {
    cachedOllamaCloudApiResultCode = partialDiagnostics.cloudApiResultCode;
  }
  if (Object.prototype.hasOwnProperty.call(partialDiagnostics, "lastCallResultCode")) {
    cachedLlmLastCallResultCode = partialDiagnostics.lastCallResultCode;
  }
  if (Object.prototype.hasOwnProperty.call(partialDiagnostics, "lastCallAt")) {
    cachedLlmLastCallAt = partialDiagnostics.lastCallAt;
  }
  if (Object.prototype.hasOwnProperty.call(partialDiagnostics, "lastCallError")) {
    cachedLlmLastCallError = partialDiagnostics.lastCallError || "";
  }
  if (Object.prototype.hasOwnProperty.call(partialDiagnostics, "cloudApiCheckedAt")) {
    cachedOllamaCloudApiCheckedAt = partialDiagnostics.cloudApiCheckedAt;
  }
  if (Object.prototype.hasOwnProperty.call(partialDiagnostics, "cloudApiError")) {
    cachedOllamaCloudApiError = partialDiagnostics.cloudApiError || "";
  }
  if (Object.prototype.hasOwnProperty.call(partialDiagnostics, "startupCheckedAt")) {
    cachedOllamaStartupCheckedAt = partialDiagnostics.startupCheckedAt;
  }
  broadcastLlmDiagnosticsUpdate();
}

function logLlmDiagnostics(prefix, diagnostics) {
  const installCode = diagnostics?.ollamaInstalled ? 0 : 1;
  const onlineCode = diagnostics?.ollamaServerListening ? 0 : 1;
  const cloudCode = diagnostics?.cloudApiReachable ? 0 : 1;
  appendActivityLogLine(
    `[${new Date().toISOString()}] [GUI][Main] ${prefix} ollamaInstalled=${diagnostics?.ollamaInstalled ? "true" : "false"} ollamaServerListening=${diagnostics?.ollamaServerListening ? "true" : "false"} cloudApiReachable=${diagnostics?.cloudApiReachable ? "true" : "false"} installCode=${installCode} onlineCode=${onlineCode} cloudCode=${cloudCode} versionExitCode=${diagnostics?.versionExitCode ?? "n/a"} listExitCode=${diagnostics?.listExitCode ?? "n/a"} cloudResultCode=${diagnostics?.cloudApiResultCode ?? "n/a"}`,
  );
}

let mainWindow;
let selectedFilePath;
let versionFilePath;
let activityLogFilePath;
let hasLoggedProgramShutdown = false;
const activityLogEntries = [];
const pendingActivityLogEntries = [];
let isFirstRunAfterInstall = false;
let cachedOllamaInstalled = false;
let cachedOllamaServerListening = false;
let cachedOllamaCloudApiReachable = false;
let cachedOllamaCloudApiResultCode = null;
let cachedLlmLastCallResultCode = null;
let cachedLlmLastCallAt = null;
let cachedLlmLastCallError = "";
let cachedOllamaCloudApiCheckedAt = null;
let cachedOllamaCloudApiError = "";
let cachedOllamaStartupCheckedAt = null;
let sessionCompressionFallbackAccepted = null;
let goodiesDataCache = null;
let ollamaModelsCache = null;
let appSettings = null;
let backCommModule = null;
let backendShutdownOnQuitInProgress = false;
let backendShutdownOnQuitComplete = false;
const SETTINGS_DIR_NAME = "config";
const SETTINGS_FILE_NAME = "settings.json";
const FILTER_LIBRARY_FILE_NAME = "filters.json";
const MODELS_LIBRARY_FILE_NAME = "models.json";
const PLUGINS_REGISTRY_FILE_NAME = "plugins.json";
const SESSION_LIBRARY_CACHE_FILE_NAME = "session-library-cache.json";
const PLUGINS_DIR_NAME = "plugins";
const PLUGINS_PACKAGE_DIR_NAME = "packages";
const PLUGINS_EXTRACTED_DIR_NAME = "installed";
const THEMES_DIR_NAME = "themes";
const THEME_FILE_EXTENSION = ".json";
const BUNDLED_THEMES_DIR_NAME = "themes";
const DEFAULT_THEME_DEFINITIONS = Object.freeze([
  {
    id: "snitchbitch",
    name: "SnitchBitch",
    description: "Original PacketSnitch look.",
    variables: {
      "--app-bg": "#000000",
      "--surface-0": "#000000",
      "--surface-1": "#171a2f",
      "--surface-2": "#000000",
      "--scrollbar-track": "#000000",
      "--border-strong": "#6a68a4",
      "--color-1": "#9ca2ff",
      "--color-2": "#3a3a67",
      "--color-2-hover": "#474777",
      "--color-3": "#6a68a4",
      "--color-4": "#161a2f",
      "--color-5": "#ccbdde",
      "--color-6": "#b5b5b5",
      "--color-7": "#2a2f54",
      "--top-bar-bg": "#1d1f3b",
      "--header-text-color": "#d6d8ff",
      "--sidebar-text-color": "#cfd2ff",
      "--input-bg-color": "#000000",
      "--input-text-color": "#ffffff",
      "--quit-btn-color": "#5da4ff",
      "--quit-btn-hover-color": "#9fc8ff",
      "--panel-bg-opacity": "100%",
      "--tab-inactive-opacity": "0.92",
      "--data-tools-frame-bg": "#0d1f47",
      "--data-tools-hex-color": "#ccbdde",
      "--data-tools-binary-color": "#ccbdde",
      "--data-tools-decimal-color": "#ccbdde",
      "--data-tools-decimal-integer-color": "#ccbdde",
      "--data-tools-ascii-color": "#ccbdde",
      "--data-tools-base64-color": "#ccbdde",
    },
  },
  {
    id: "dark",
    name: "Dark",
    description: "Neutral grey dark workspace.",
    variables: {
      "--app-bg": "#1e2024",
      "--surface-0": "#16181c",
      "--surface-1": "#22252b",
      "--surface-2": "#1d2026",
      "--scrollbar-track": "#14161a",
      "--border-strong": "#2b3038",
      "--color-1": "#c7d0db",
      "--color-2": "#2a2f37",
      "--color-2-hover": "#333943",
      "--color-3": "#535b67",
      "--color-4": "#1a1e24",
      "--color-5": "#e4e8ee",
      "--color-6": "#aab2be",
      "--color-7": "#303641",
      "--data-tools-frame-bg": "#21262e",
      "--data-tools-hex-color": "#e4e8ee",
      "--data-tools-binary-color": "#e4e8ee",
      "--data-tools-decimal-color": "#e4e8ee",
      "--data-tools-decimal-integer-color": "#e4e8ee",
      "--data-tools-ascii-color": "#e4e8ee",
      "--data-tools-base64-color": "#e4e8ee",
    },
  },
  {
    id: "pastels",
    name: "Pastels",
    description: "Soft pastel tones with readable contrast.",
    variables: {
      "--app-bg": "#e7ecef",
      "--surface-0": "#f8fbfd",
      "--surface-1": "#eef5f8",
      "--surface-2": "#f3f8fb",
      "--scrollbar-track": "#dce6eb",
      "--border-strong": "#b6c8d1",
      "--color-1": "#3a6a8d",
      "--color-2": "#d8e6ef",
      "--color-2-hover": "#c8dce8",
      "--color-3": "#8fb1c4",
      "--color-4": "#e3edf3",
      "--color-5": "#1e3342",
      "--color-6": "#4e6a7e",
      "--color-7": "#c9dce8",
      "--data-tools-frame-bg": "#e8f2f7",
      "--data-tools-hex-color": "#1e3342",
      "--data-tools-binary-color": "#1e3342",
      "--data-tools-decimal-color": "#1e3342",
      "--data-tools-decimal-integer-color": "#1e3342",
      "--data-tools-ascii-color": "#1e3342",
      "--data-tools-base64-color": "#1e3342",
      "--notes-link-color": "#2f6b3f",
      "--notes-markdown-bg": "#fffdf0",
    },
  },
  {
    id: "matrix",
    name: "Matrix",
    description: "Classic matrix-green terminal vibe.",
    variables: {
      "--app-bg": "#020302",
      "--surface-0": "#000000",
      "--surface-1": "#040705",
      "--surface-2": "#010201",
      "--scrollbar-track": "#000000",
      "--border-strong": "#0a190c",
      "--color-1": "#00ff41",
      "--color-2": "#041108",
      "--color-2-hover": "#08200f",
      "--color-3": "#00a32a",
      "--color-4": "#030b05",
      "--color-5": "#b9ffbf",
      "--color-6": "#63d471",
      "--color-7": "#06150a",
      "--data-tools-frame-bg": "#05150a",
      "--data-tools-hex-color": "#b9ffbf",
      "--data-tools-binary-color": "#b9ffbf",
      "--data-tools-decimal-color": "#b9ffbf",
      "--data-tools-decimal-integer-color": "#b9ffbf",
      "--data-tools-ascii-color": "#b9ffbf",
      "--data-tools-base64-color": "#b9ffbf",
    },
  },
  {
    id: "light",
    name: "Light",
    description: "Grey high-contrast light layout tuned for readability.",
    variables: {
      "--app-bg": "#ced3d9",
      "--surface-0": "#f4f5f7",
      "--surface-1": "#e6e9ed",
      "--surface-2": "#eff1f4",
      "--scrollbar-track": "#bcc3cb",
      "--border-strong": "#4b5563",
      "--color-1": "#0d1117",
      "--color-2": "#8e97a3",
      "--color-2-hover": "#798492",
      "--color-3": "#5f6873",
      "--color-4": "#d5dbe2",
      "--color-5": "#05070a",
      "--color-6": "#111827",
      "--color-7": "#6f7a87",
      "--data-tools-frame-bg": "#d9dfe6",
      "--data-tools-hex-color": "#05070a",
      "--data-tools-binary-color": "#05070a",
      "--data-tools-decimal-color": "#05070a",
      "--data-tools-decimal-integer-color": "#05070a",
      "--data-tools-ascii-color": "#05070a",
      "--data-tools-base64-color": "#05070a",
      "--header-text-color": "#000000",
      "--sidebar-text-color": "#070a0e",
      "--input-bg-color": "#ffffff",
      "--input-text-color": "#9aa3af",
      "--stats-tag-text-color": "#1f6fff",
      "--stats-heatmap-water-color-1": "#f2f2f2",
      "--stats-heatmap-water-color-2": "#ededed",
      "--stats-heatmap-water-color-3-top": "#f8f8f8",
      "--stats-heatmap-water-color-3-bottom": "#e6e6e6",
      "--stats-heatmap-land-fill-color": "#4a4a4a",
      "--stats-heatmap-land-filter": "grayscale(1) contrast(1.14) brightness(0.92)",
      "--stats-heatmap-land-opacity": "0.96",
      "--stats-heatmap-selection-border-color": "#8fd3ff",
      "--stats-heatmap-selection-highlight-color": "rgba(19, 52, 102, 0.28)",
      "--stats-heatmap-selection-active-border-color": "#8fd3ff",
      "--stats-heatmap-selection-active-highlight-color": "rgba(19, 52, 102, 0.34)",
      "--crypt-panel-bg": "#edf2f7",
      "--crypt-panel-text": "#0b1220",
      "--tab-inactive-opacity": "0.78",
    },
  },
]);
if (!appLock) {
  console.error(
    "Another instance of PacketSnitch is already running. Exiting this instance.",
  );
  app.quit();
  process.exit(0);
}
app.on("second-instance", () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) {
      mainWindow.restore();
    }
    mainWindow.focus();
  }
});

if (require("electron-squirrel-startup")) {
  app.quit();
}




ipcMain.handle('ollama:generate', async (_event, prompt) => {
  try {
    if (!isOllamaClientModuleAvailable()) {
      throw new Error("Ollama client module is unavailable");
    }
    if (!appSettings) {
      await loadSettingsFromDisk();
    }
    const settings = getAppSettings();
    const ollamaFetch = getOllamaFetch(
      Number(settings.llm.ollamaRequestTimeoutSeconds) * 1000,
    );
    const ollamaClient = settings.apiKeys.ollamaApiKey
      ? new Ollama({
        fetch: ollamaFetch,
        headers: {
          Authorization: settings.apiKeys.ollamaApiKey.startsWith("Bearer ")
            ? settings.apiKeys.ollamaApiKey
            : `Bearer ${settings.apiKeys.ollamaApiKey}`,
        },
      })
      : new Ollama({ fetch: ollamaFetch });
    const response = await ollamaClient.generate({
      model: settings.llm.ollamaModel,
      prompt,
      options: {
        temperature: 0.5,
        num_predict: settings.llm.maxSummaryTokens,
      },
    });
    setLlmDiagnostics({
      lastCallResultCode: 0,
      lastCallAt: new Date().toISOString(),
      lastCallError: "",
    });
    appendActivityLogLine(
      `[${new Date().toISOString()}] [GUI][Main] Ollama LLM request completed resultCode=0 model=${settings.llm.ollamaModel}`,
    );
    return response;
  } catch (error) {
    const resultCode = Number.isInteger(error?.status)
      ? error.status
      : Number.isInteger(error?.code)
        ? error.code
        : 1;
    setLlmDiagnostics({
      lastCallResultCode: resultCode,
      lastCallAt: new Date().toISOString(),
      lastCallError: error?.message || String(error),
    });
    appendActivityLogLine(
      `[${new Date().toISOString()}] [GUI][Main] Ollama LLM request failed resultCode=${resultCode} message=${JSON.stringify(error?.message || String(error))}`,
    );
    console.error("Error generating response from Ollama:", error);
    throw error;
  }
});

ipcMain.handle("file-size", async () => {
  try {
    // Get file stats asynchronously
    const fileStats = await fs.promises.stat(selectedFilePath); // Using promises version of stat
    return fileStats.size; // Send back the file size
  } catch (fileError) {
    console.log("Error getting file stats:", fileError);
    return 0; // Return 0 if there's an error
  }
});

// ── Anonymous usage metrics transport ──────────────────────────────────────
//
// All network I/O for telemetry lives in the main process. The renderer holds
// the in-memory queue (src/metrics.js) and forwards a batch via
// `metrics:flush` whenever the main process asks for one (every flush
// interval) or when the user explicitly requests it. The endpoint URL is
// stored in settings.json under `privacy.metricsEndpointUrl` and is fully
// user-configurable; if the user has not opted in (`privacy.metricsEnabled`
// is false), the renderer never asks us to flush, and this code path is a
// no-op.
const METRICS_FLUSH_REQUEST = "metrics:flush-request";
const METRICS_MAX_EVENT_BATCH = 1000;
let metricsFlushTimer = null;

function getMetricsPrivacy() {
  try {
    const settings = getAppSettings();
    return settings?.privacy && typeof settings.privacy === "object"
      ? settings.privacy
      : {};
  } catch (_error) {
    return {};
  }
}

async function flushMetricsQueue(payload) {
  if (!payload || typeof payload !== "object") {
    return { ok: false, error: "invalid-payload" };
  }
  const privacy = getMetricsPrivacy();
  if (!privacy.metricsEnabled) {
    return { ok: false, error: "disabled" };
  }
  const endpoint = String(privacy.metricsEndpointUrl || "").trim();
  if (!endpoint) {
    return { ok: false, error: "no-endpoint" };
  }
  let parsedUrl;
  try {
    parsedUrl = new URL(endpoint);
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      return { ok: false, error: "endpoint-protocol" };
    }
  } catch (_error) {
    return { ok: false, error: "endpoint-invalid" };
  }
  const events = Array.isArray(payload.events) ? payload.events : [];
  if (events.length === 0) {
    return { ok: true, status: 204, sent: 0 };
  }
  if (events.length > METRICS_MAX_EVENT_BATCH) {
    return { ok: false, error: "batch-too-large" };
  }
  const body = {
    installId: String(payload.installId || privacy.metricsInstallId || "").trim(),
    appVersion: String(payload.appVersion || app.getVersion() || "").trim(),
    platform: String(platform || process.platform || "").trim(),
    sentAt: String(payload.sentAt || new Date().toISOString()).trim(),
    events,
  };
  try {
    const response = await undiciFetch(parsedUrl.href, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "User-Agent": userAgent,
        "X-PacketSnitch-Client": "electron",
      },
      body: JSON.stringify(body),
      headersTimeout: 5000,
      bodyTimeout: 5000,
    });
    const status = response.status;
    const ok = status >= 200 && status < 300;
    return {
      ok,
      status,
      sent: events.length,
      error: ok ? undefined : `http-${status}`,
    };
  } catch (error) {
    appendActivityLogLine(
      `[${new Date().toISOString()}] [GUI][Main] Metrics flush failed endpoint=${parsedUrl.host} message=${JSON.stringify(error?.message || String(error))}`,
    );
    return {
      ok: false,
      error: error?.message || "exception",
    };
  }
}

ipcMain.handle("metrics:track", async (_event, payload) => {
  // The renderer's metrics service owns the queue. This handler exists so
  // the renderer can sanity-check that the bridge is alive; we don't store
  // anything here.
  if (!payload || typeof payload !== "object") {
    return { ok: false, error: "invalid-payload" };
  }
  return { ok: true };
});

ipcMain.handle("metrics:flush", async (_event, payload) => {
  return flushMetricsQueue(payload || {});
});

ipcMain.handle("metrics:status", async () => {
  const privacy = getMetricsPrivacy();
  return {
    enabled: Boolean(privacy.metricsEnabled),
    endpoint: String(privacy.metricsEndpointUrl || "").trim(),
    hasInstallId: Boolean(String(privacy.metricsInstallId || "").trim()),
    appVersion: String(app.getVersion() || "").trim(),
  };
});

function requestMetricsFlushFromRenderer() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  try {
    mainWindow.webContents.send(METRICS_FLUSH_REQUEST, { at: new Date().toISOString() });
  } catch (_error) {
    // ignore: renderer is gone
  }
}

function installMetricsFlushTimer() {
  if (metricsFlushTimer) return;
  const intervalSeconds = Math.max(5, Number(getMetricsPrivacy().metricsFlushIntervalSeconds) || 60);
  metricsFlushTimer = setInterval(() => {
    requestMetricsFlushFromRenderer();
  }, intervalSeconds * 1000);
  if (typeof metricsFlushTimer.unref === "function") {
    metricsFlushTimer.unref();
  }
}

// make sure we have a fresh temp dir
fs.rmSync(testcaseTempDir, { recursive: true, force: true });

async function shutdownBackendGracefullyForExit() {
  const shutdownBackendService = backCommModule?.requestBackendShutdown
    || backCommModule?.shutdownHttpBackendService
    || backCommModule?.shutdownTcpBackendService;
  if (typeof shutdownBackendService !== "function") {
    return;
  }
  try {
    await shutdownBackendService();
  } catch (error) {
    console.warn("Failed to shut down backend service cleanly:", error);
  }
}

// Looks for a snitch HTTP backend that may already be running on the
// configured port (e.g. left over from a previous GUI session) and tries to
// shut it down gracefully, falling back to a forced kill if it won't
// release the port. The user's configured backend mode (forceLegacySpawn,
// host, port) is honored — the reclaim is a no-op for legacy-spawn mode.
async function reclaimPreExistingBackendAtStartup() {
  if (!backCommModule) {
    return;
  }
  // Force-legacy mode runs a one-shot per-pcap spawn and does not use the
  // long-lived HTTP service, so there is no persistent listener to reclaim.
  if (appSettings?.backend?.forceLegacySpawn) {
    return;
  }
  const reclaim = backCommModule.reclaimExistingBackendService;
  if (typeof reclaim !== "function") {
    return;
  }
  // Sync the bridge module's host/port to whatever the user has configured
  // before probing so we reclaim the right port.
  if (typeof backCommModule.applyBackendTransportOptions === "function") {
    try {
      backCommModule.applyBackendTransportOptions(appSettings?.backend || {});
    } catch (error) {
      console.warn("Failed to apply backend transport options before reclaim:", error);
    }
  }
  try {
    const result = await reclaim({
      host: appSettings?.backend?.tcpHost,
      port: appSettings?.backend?.tcpPort,
    });
    if (result?.detected) {
      appendActivityLogLine(
        `[${new Date().toISOString()}] [GUI][Main] Startup backend reclaim action=${result.action} host=${result.host || "n/a"} port=${result.port || "n/a"}`,
      );
    }
  } catch (error) {
    console.warn("Startup backend reclaim failed:", error);
  }
}

function checkOllama() {
  return new Promise((resolve) => {
    if (!isOllamaClientModuleAvailable()) {
      resolve({
        ollamaInstalled: false,
        ollamaServerListening: false,
        versionExitCode: null,
        listExitCode: null,
      });
      return;
    }
    exec("ollama --version", (versionError) => {
      if (versionError) {
        resolve({
          ollamaInstalled: false,
          ollamaServerListening: false,
          versionExitCode: versionError?.code ?? 1,
          listExitCode: null,
        });
        return;
      }
      // Backend reachability check: this fails when the daemon/API is down.
      exec("ollama list", (listError) => {
        resolve({
          ollamaInstalled: true,
          ollamaServerListening: !listError,
          versionExitCode: 0,
          listExitCode: listError ? listError?.code ?? 1 : 0,
        });
      });
    });
  });
}

async function checkOllamaCloudApi() {
  const settings = getAppSettings();
  const apiKey = settings?.apiKeys?.ollamaApiKey;
  if (typeof apiKey !== "string" || !apiKey.trim()) {
    return {
      cloudApiReachable: false,
      cloudApiResultCode: null,
      cloudApiCheckedAt: new Date().toISOString(),
      cloudApiError: "No Ollama API key configured",
    };
  }

  const ollamaFetch = getOllamaFetch(Number(settings.llm.ollamaRequestTimeoutSeconds) * 1000);
  try {
    const response = await ollamaFetch(OLLAMA_CLOUD_PING_URL, {
      method: "POST",
      headers: {
        Authorization: apiKey.startsWith("Bearer ") ? apiKey : `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: OLLAMA_CLOUD_PING_MODEL,
        prompt: "ping",
        stream: false,
      }),
    });

    const responseText = await response.text();
    let parsedResponse = null;
    try {
      parsedResponse = JSON.parse(responseText);
    } catch (_parseError) {
      parsedResponse = null;
    }

    const pongText = typeof parsedResponse?.response === "string"
      ? parsedResponse.response
      : responseText;
    const ok = response.ok && typeof pongText === "string" && /pong/i.test(pongText);
    return {
      cloudApiReachable: ok,
      cloudApiResultCode: ok ? 0 : response.status,
      cloudApiCheckedAt: new Date().toISOString(),
      cloudApiError: ok ? "" : (parsedResponse?.error || response.statusText || responseText || "Cloud ping failed"),
    };
  } catch (error) {
    return {
      cloudApiReachable: false,
      cloudApiResultCode: Number.isInteger(error?.status)
        ? error.status
        : Number.isInteger(error?.code)
          ? error.code
          : 1,
      cloudApiCheckedAt: new Date().toISOString(),
      cloudApiError: error?.message || String(error),
    };
  }
}

async function refreshOllamaCloudApiDiagnostics() {
  if (!appSettings) {
    await loadSettingsFromDisk();
  }
  const cloudDiagnostics = await checkOllamaCloudApi();
  setLlmDiagnostics(cloudDiagnostics);
  return cloudDiagnostics;
}


function getSettingsFilePath() {
  return path.join(app.getPath("userData"), SETTINGS_DIR_NAME, SETTINGS_FILE_NAME);
}

function getFilterLibraryFilePath() {
  return path.join(app.getPath("userData"), SETTINGS_DIR_NAME, FILTER_LIBRARY_FILE_NAME);
}

function getModelsLibraryFilePath() {
  return path.join(app.getPath("userData"), SETTINGS_DIR_NAME, MODELS_LIBRARY_FILE_NAME);
}

function getBundledModelsLibraryFilePath() {
  return path.join(app.getAppPath(), SETTINGS_DIR_NAME, MODELS_LIBRARY_FILE_NAME);
}

function getPluginsRegistryFilePath() {
  return path.join(app.getPath("userData"), SETTINGS_DIR_NAME, PLUGINS_REGISTRY_FILE_NAME);
}

function getPluginPackagesDir() {
  return path.join(app.getPath("userData"), PLUGINS_DIR_NAME, PLUGINS_PACKAGE_DIR_NAME);
}

function getPluginInstallRootDir() {
  return path.join(app.getPath("userData"), PLUGINS_DIR_NAME, PLUGINS_EXTRACTED_DIR_NAME);
}

function sanitizePluginToken(value, fallback = "plugin") {
  if (typeof value !== "string") return fallback;
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return normalized || fallback;
}

function normalizePluginRegistry(rawRegistry = {}) {
  const source = rawRegistry && typeof rawRegistry === "object" ? rawRegistry : {};
  const sourcePlugins = Array.isArray(source.plugins) ? source.plugins : [];
  const plugins = sourcePlugins
    .map((plugin) => {
      if (!plugin || typeof plugin !== "object") return null;
      const pluginId = sanitizePluginToken(
        String(plugin.pluginId || plugin.pluginName || ""),
        "plugin",
      );
      const pluginName = String(plugin.pluginName || pluginId).trim() || pluginId;
      const pluginVersion = String(plugin.pluginVersion || "0.0.0").trim() || "0.0.0";
      const packageHash = String(plugin.packageHash || "").trim().toLowerCase();
      const contentHash = String(plugin.contentHash || "").trim().toLowerCase();
      const installPath = typeof plugin.installPath === "string" ? plugin.installPath : "";
      const packagePath = typeof plugin.packagePath === "string" ? plugin.packagePath : "";
      const enabled = typeof plugin.enabled === "boolean" ? plugin.enabled : true;
      const priority = Number.isFinite(Number(plugin.priority))
        ? Number(plugin.priority)
        : 100;
      const failureCount = Number.isFinite(Number(plugin.failureCount))
        ? Math.max(0, Number(plugin.failureCount))
        : 0;
      const disabledReason = typeof plugin.disabledReason === "string"
        ? plugin.disabledReason
        : "";
      const failureThresholdOverride = Number.isFinite(Number(plugin.failureThresholdOverride))
        ? Math.max(1, Number(plugin.failureThresholdOverride))
        : null;
      const address = String(plugin.address || "").trim()
        || `${pluginName}@${pluginVersion}#${(contentHash || packageHash || "unknown").slice(0, 12)}`;
      const capabilities = Array.isArray(plugin.capabilities)
        ? plugin.capabilities
          .map((entry) => String(entry || "").trim())
          .filter(Boolean)
        : [];
      const author = typeof plugin.author === "string" ? plugin.author : "";
      const authorHomepage = typeof plugin.authorHomepage === "string" ? plugin.authorHomepage : "";
      const updateUrl = typeof plugin.updateUrl === "string" ? plugin.updateUrl : "";
      const compatiblePacketsnitchVersions = Array.isArray(plugin.compatiblePacketsnitchVersions)
        ? plugin.compatiblePacketsnitchVersions
          .map((entry) => String(entry || "").trim())
          .filter(Boolean)
        : [];
      const compatibleWithCurrentPacketsnitch =
        typeof plugin.compatibleWithCurrentPacketsnitch === "boolean"
          ? plugin.compatibleWithCurrentPacketsnitch
          : true;

      return {
        pluginId,
        pluginName,
        pluginVersion,
        address,
        capabilities,
        author,
        authorHomepage,
        updateUrl,
        compatiblePacketsnitchVersions,
        compatibleWithCurrentPacketsnitch,
        packageHash,
        contentHash,
        packagePath,
        installPath,
        enabled,
        priority,
        failureCount,
        failureThresholdOverride,
        disabledReason,
        manifest: plugin.manifest && typeof plugin.manifest === "object" ? plugin.manifest : {},
        installedAt:
          typeof plugin.installedAt === "string" && plugin.installedAt.trim()
            ? plugin.installedAt
            : new Date().toISOString(),
        updatedAt:
          typeof plugin.updatedAt === "string" && plugin.updatedAt.trim()
            ? plugin.updatedAt
            : new Date().toISOString(),
      };
    })
    .filter(Boolean);

  return {
    version: 1,
    plugins,
    updatedAt:
      typeof source.updatedAt === "string" && source.updatedAt.trim()
        ? source.updatedAt
        : new Date().toISOString(),
  };
}

function normalizeOptionalHttpUrl(rawValue) {
  const candidate = String(rawValue || "").trim();
  if (!candidate) return "";
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    return parsed.href;
  } catch (_error) {
    return "";
  }
}

function parseVersionParts(rawVersion) {
  const normalized = String(rawVersion || "")
    .trim()
    .replace(/^v/i, "")
    .split("-")[0];
  const parts = normalized
    .split(".")
    .map((entry) => Number.parseInt(entry, 10))
    .filter((entry) => Number.isInteger(entry) && entry >= 0);
  return parts.length ? parts : [0];
}

function compareVersionParts(leftVersion, rightVersion) {
  const leftParts = parseVersionParts(leftVersion);
  const rightParts = parseVersionParts(rightVersion);
  const maxLength = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < maxLength; index += 1) {
    const leftPart = leftParts[index] ?? 0;
    const rightPart = rightParts[index] ?? 0;
    if (leftPart > rightPart) return 1;
    if (leftPart < rightPart) return -1;
  }
  return 0;
}

function isVersionPatternMatch(currentVersion, pattern) {
  const normalizedPattern = String(pattern || "").trim();
  if (!normalizedPattern || normalizedPattern === "*") return true;
  if (normalizedPattern.endsWith(".*")) {
    const prefix = normalizedPattern.slice(0, -1);
    return String(currentVersion || "").startsWith(prefix);
  }
  return compareVersionParts(currentVersion, normalizedPattern) === 0;
}

function evaluateVersionConstraint(currentVersion, rawConstraint) {
  const constraint = String(rawConstraint || "").trim();
  if (!constraint) return false;
  if (constraint.startsWith(">=")) {
    return compareVersionParts(currentVersion, constraint.slice(2).trim()) >= 0;
  }
  if (constraint.startsWith("<=")) {
    return compareVersionParts(currentVersion, constraint.slice(2).trim()) <= 0;
  }
  if (constraint.startsWith(">")) {
    return compareVersionParts(currentVersion, constraint.slice(1).trim()) > 0;
  }
  if (constraint.startsWith("<")) {
    return compareVersionParts(currentVersion, constraint.slice(1).trim()) < 0;
  }
  if (constraint.startsWith("=")) {
    return compareVersionParts(currentVersion, constraint.slice(1).trim()) === 0;
  }
  return isVersionPatternMatch(currentVersion, constraint);
}

function isPacketsnitchVersionCompatible(currentVersion, versionConstraints = []) {
  const normalizedConstraints = Array.isArray(versionConstraints)
    ? versionConstraints
      .map((entry) => String(entry || "").trim())
      .filter(Boolean)
    : [];
  if (!normalizedConstraints.length) return false;
  return normalizedConstraints.some((constraint) =>
    evaluateVersionConstraint(currentVersion, constraint)
  );
}

async function ensurePluginsRegistryFileExists(registry) {
  const registryPath = getPluginsRegistryFilePath();
  await fs.promises.mkdir(path.dirname(registryPath), { recursive: true });
  await fs.promises.writeFile(
    registryPath,
    JSON.stringify(normalizePluginRegistry(registry), null, 2) + os.EOL,
    "utf8",
  );
  return registryPath;
}

async function loadPluginsRegistryFromDisk() {
  const registryPath = getPluginsRegistryFilePath();
  try {
    const rawText = await fs.promises.readFile(registryPath, "utf8");
    return normalizePluginRegistry(JSON.parse(rawText));
  } catch (error) {
    if (error && error.code !== "ENOENT") {
      console.warn("Failed to load plugin registry, using defaults:", error);
    }
    const defaults = normalizePluginRegistry({ plugins: [] });
    await ensurePluginsRegistryFileExists(defaults);
    return defaults;
  }
}

async function savePluginsRegistryToDisk(nextRegistry) {
  const normalizedRegistry = normalizePluginRegistry(nextRegistry);
  normalizedRegistry.updatedAt = new Date().toISOString();
  await ensurePluginsRegistryFileExists(normalizedRegistry);
  return normalizedRegistry;
}

function sha256Hex(bufferLike) {
  return crypto.createHash("sha256").update(bufferLike).digest("hex");
}

function isSafeArchiveRelativePath(rawPath) {
  if (typeof rawPath !== "string" || !rawPath.trim()) return false;
  const normalized = path.posix.normalize(rawPath.replace(/\\/g, "/"));
  if (!normalized || normalized === ".") return false;
  if (normalized.startsWith("../") || normalized === "..") return false;
  if (path.posix.isAbsolute(normalized)) return false;
  return true;
}

function normalizeArchivePath(rawPath) {
  return path.posix.normalize(String(rawPath || "").replace(/\\/g, "/"));
}

function sanitizeArchiveRelativePath(rawPath) {
  if (typeof rawPath !== "string" || !rawPath.trim()) return null;
  const normalized = path.posix.normalize(String(rawPath).replace(/\\/g, "/"));
  if (!normalized || normalized === ".") return null;
  const parts = normalized.split("/").filter((part) => part && part !== "..");
  return parts.pop() || null;
}

async function openZipDirectory(zipPath) {
  if (!unzipper || !unzipper.Open || typeof unzipper.Open.file !== "function") {
    throw new Error("Plugin zip support is unavailable (missing unzipper dependency)");
  }
  return unzipper.Open.file(zipPath);
}

async function parsePluginManifestFromZipEntries(directoryEntries) {
  const manifestEntry = directoryEntries.find((entry) => {
    const normalized = normalizeArchivePath(entry.path).toLowerCase();
    return normalized === "plugin.json" || normalized.endsWith("/plugin.json");
  });
  if (!manifestEntry) {
    throw new Error("Plugin zip does not contain plugin.json");
  }
  const manifestBuffer = await manifestEntry.buffer();
  let manifest = null;
  try {
    manifest = JSON.parse(String(manifestBuffer || ""));
  } catch (error) {
    throw new Error(`Invalid plugin.json: ${error?.message || error}`);
  }
  if (!manifest || typeof manifest !== "object") {
    throw new Error("Invalid plugin.json: expected object");
  }
  const pluginName = String(manifest.pluginName || manifest.name || "").trim();
  const pluginVersion = String(manifest.pluginVersion || manifest.version || "").trim();
  const capabilities = Array.isArray(manifest.capabilities)
    ? manifest.capabilities
      .map((entry) => String(entry || "").trim())
      .filter(Boolean)
    : [];
  const author = String(manifest.author || "").trim();
  const authorHomepage = normalizeOptionalHttpUrl(
    manifest.authorHomepage || manifest.author_homepage || "",
  );
  const updateUrl = normalizeOptionalHttpUrl(
    manifest.updateUrl || manifest.update_url || "",
  );
  const compatiblePacketsnitchVersions = Array.isArray(
    manifest.compatiblePacketsnitchVersions,
  )
    ? manifest.compatiblePacketsnitchVersions
      .map((entry) => String(entry || "").trim())
      .filter(Boolean)
    : Array.isArray(manifest.compatibleVersions)
      ? manifest.compatibleVersions
        .map((entry) => String(entry || "").trim())
        .filter(Boolean)
      : [];

  const manifestEntryPath = normalizeArchivePath(manifestEntry.path);
  const manifestDir = path.posix.dirname(manifestEntryPath);
  const declaredEntry = typeof manifest.entry === "string"
    ? manifest.entry.trim()
    : "";
  const safeDeclaredEntry = declaredEntry && !declaredEntry.includes("..")
    ? normalizeArchivePath(declaredEntry)
    : "plugin.js";
  const effectiveEntry = manifestDir && manifestDir !== "."
    ? normalizeArchivePath(path.posix.join(manifestDir, safeDeclaredEntry))
    : safeDeclaredEntry;

  if (!pluginName) {
    throw new Error("Invalid plugin.json: missing pluginName");
  }
  if (!pluginVersion) {
    throw new Error("Invalid plugin.json: missing version/pluginVersion");
  }
  if (!capabilities.length) {
    throw new Error("Invalid plugin.json: missing capabilities array");
  }
  if (!compatiblePacketsnitchVersions.length) {
    throw new Error("Invalid plugin.json: missing compatiblePacketsnitchVersions array");
  }
  return {
    ...manifest,
    pluginName,
    pluginVersion,
    version: pluginVersion,
    entry: effectiveEntry,
    capabilities,
    author,
    authorHomepage,
    updateUrl,
    compatiblePacketsnitchVersions,
  };
}

async function computeContentHashFromZipEntries(directoryEntries) {
  const hash = crypto.createHash("sha256");
  const fileEntries = directoryEntries
    .filter((entry) => entry.type === "File" && isSafeArchiveRelativePath(entry.path))
    .sort((a, b) => normalizeArchivePath(a.path).localeCompare(normalizeArchivePath(b.path)));

  for (const entry of fileEntries) {
    const normalizedPath = normalizeArchivePath(entry.path);
    const entryBuffer = await entry.buffer();
    hash.update(normalizedPath);
    hash.update("\n");
    hash.update(entryBuffer);
    hash.update("\n");
  }
  return hash.digest("hex");
}

async function extractPluginZipToDirectory(zipPath, destinationDir) {
  const directory = await openZipDirectory(zipPath);
  await fs.promises.mkdir(destinationDir, { recursive: true });
  for (const entry of directory.files) {
    if (!isSafeArchiveRelativePath(entry.path)) {
      throw new Error(`Unsafe path in plugin archive: ${entry.path}`);
    }
    const normalizedPath = normalizeArchivePath(entry.path);
    const targetPath = path.resolve(destinationDir, normalizedPath);
    if (!targetPath.startsWith(path.resolve(destinationDir) + path.sep) && targetPath !== path.resolve(destinationDir)) {
      throw new Error(`Unsafe extraction path in plugin archive: ${entry.path}`);
    }

    if (entry.type === "Directory") {
      await fs.promises.mkdir(targetPath, { recursive: true });
      continue;
    }

    await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });
    const readStream = entry.stream();
    const writeStream = fs.createWriteStream(targetPath, { mode: 0o644 });
    await streamPipelineAsync(readStream, writeStream);
  }
}

// ── Extraction / decompression service ──────────────────────────────────────

function inferExtractionFormatFromBytes(bytes) {
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

async function decompressWithSystemTool(inputPath, algorithm) {
  const commandMap = {
    gzip: ["gzip", ["-dc", inputPath]],
    brotli: ["brotli", ["--decompress", "--output", "-", inputPath]],
    bz2: ["bzip2", ["-dc", inputPath]],
    lzma: ["xz", ["-dc", inputPath]],
    lzo: ["lzop", ["-dc", inputPath]],
  };
  const spec = commandMap[algorithm];
  if (!spec) throw new Error(`No system decompression tool configured for ${algorithm}`);
  const [cmd, args] = spec;
  const result = await execFileAsync(cmd, args, {
    maxBuffer: EXTRACTION_MAX_OUTPUT_BYTES + 1024 * 1024,
    timeout: EXTRACTION_SYSTEM_TIMEOUT_MS,
  });
  return Buffer.from(result.stdout, "binary");
}

async function decompressBytesMain(bytes, algorithm) {
  if (!bytes || bytes.length === 0) {
    throw new Error("No input bytes to decompress");
  }
  if (bytes.length > EXTRACTION_MAX_INPUT_BYTES) {
    throw new Error(`Input too large for decompression (${formatByteCount(bytes.length)} > ${formatByteCount(EXTRACTION_MAX_INPUT_BYTES)})`);
  }

  const normalizedAlgorithm = String(algorithm || "").toLowerCase().replace(/^(x-)?/, "");
  const safeAlgorithm = normalizedAlgorithm === "gz" ? "gzip" : normalizedAlgorithm;

  // Internal support first.
  if (safeAlgorithm === "gzip") {
    return await gunzipAsync(bytes);
  }
  if (safeAlgorithm === "brotli") {
    return await brotliDecompressAsync(bytes);
  }
  if (safeAlgorithm === "lzma" && lzmaNative) {
    return await lzmaNative.decompress(bytes);
  }
  if (safeAlgorithm === "zip") {
    throw new Error("For PKZIP archives use 'list-archive' and 'extract-archive-entry'");
  }

  // Fall back to system tools for everything else.
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "ps-extract-"));
  try {
    const ext = safeAlgorithm === "bz2" ? "bz2" : safeAlgorithm;
    const inputPath = path.join(tmpDir, `input.${ext}`);
    await fs.promises.writeFile(inputPath, bytes);
    return await decompressWithSystemTool(inputPath, safeAlgorithm === "xz" ? "lzma" : safeAlgorithm);
  } finally {
    fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => { });
  }
}

async function listArchiveEntriesMain(bytes) {
  if (!bytes || bytes.length === 0) throw new Error("No archive bytes to inspect");
  if (bytes.length > EXTRACTION_MAX_INPUT_BYTES) {
    throw new Error(`Archive too large (${formatByteCount(bytes.length)} > ${formatByteCount(EXTRACTION_MAX_INPUT_BYTES)})`);
  }
  const detected = inferExtractionFormatFromBytes(bytes);
  if (detected !== "zip") {
    throw new Error("Archive browsing is only supported for PKZIP (.zip) files");
  }
  if (!unzipper || !unzipper.Open || typeof unzipper.Open.buffer !== "function") {
    throw new Error("ZIP archive support is unavailable (missing unzipper dependency)");
  }
  const directory = await unzipper.Open.buffer(bytes);
  return directory.files.map((entry) => {
    const type = entry.type === "Directory" ? "directory" : "file";
    const isSafe = isSafeArchiveRelativePath(entry.path);
    const safePath = isSafe
      ? normalizeArchivePath(entry.path)
      : sanitizeArchiveRelativePath(entry.path);
    return {
      path: entry.path,
      safePath,
      type,
      compressedSize: Number.isFinite(Number(entry.compressedSize)) ? Number(entry.compressedSize) : 0,
      uncompressedSize: Number.isFinite(Number(entry.vars?.uncompressedSize)) ? Number(entry.vars.uncompressedSize) : 0,
      isSafe: isSafe && type !== "directory",
      unsafeReason: isSafe ? null : "Path contains traversal or absolute components",
    };
  });
}

async function extractArchiveEntryMain(bytes, entryPath, safePath) {
  if (!bytes || bytes.length === 0) throw new Error("No archive bytes to extract from");
  if (!entryPath) throw new Error("No archive entry path specified");
  const detected = inferExtractionFormatFromBytes(bytes);
  if (detected !== "zip") {
    throw new Error("Single-entry extraction is only supported for PKZIP (.zip) files");
  }
  if (!unzipper || !unzipper.Open || typeof unzipper.Open.buffer !== "function") {
    throw new Error("ZIP archive support is unavailable (missing unzipper dependency)");
  }
  const normalizedTarget = normalizeArchivePath(entryPath);
  const normalizedSafe = safePath ? normalizeArchivePath(safePath) : null;
  if (!isSafeArchiveRelativePath(normalizedTarget) && !normalizedSafe) {
    throw new Error(`Unsafe archive entry path: ${entryPath}`);
  }
  const directory = await unzipper.Open.buffer(bytes);
  const entry = directory.files.find((e) => {
    const n = normalizeArchivePath(e.path);
    return n === normalizedTarget || (normalizedSafe && n === normalizedSafe);
  });
  if (!entry) throw new Error(`Archive entry not found: ${entryPath}`);
  if (entry.type === "Directory") throw new Error("Cannot extract a directory entry");
  const extractedBuffer = await entry.buffer();
  if (extractedBuffer.length > EXTRACTION_MAX_OUTPUT_BYTES) {
    throw new Error(`Extracted entry too large (${formatByteCount(extractedBuffer.length)} > ${formatByteCount(EXTRACTION_MAX_OUTPUT_BYTES)})`);
  }
  return extractedBuffer;
}

function formatByteCount(n) {
  const num = Number.isFinite(Number(n)) ? Number(n) : 0;
  if (num >= 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(2)} MiB`;
  if (num >= 1024) return `${(num / 1024).toFixed(1)} KiB`;
  return `${num} bytes`;
}

function installExtractionHandlers() {
  ipcMain.handle("decompress-bytes", async (_event, { bytesBase64, algorithm } = {}) => {
    try {
      const input = Buffer.from(String(bytesBase64 || ""), "base64");
      if (input.length === 0) throw new Error("Empty input");
      const result = await decompressBytesMain(input, algorithm);
      return { success: true, algorithm, bytesBase64: result.toString("base64"), byteLength: result.length };
    } catch (err) {
      console.error("decompress-bytes error:", err);
      return { success: false, error: err?.message || String(err) };
    }
  });

  ipcMain.handle("list-archive", async (_event, { bytesBase64 } = {}) => {
    try {
      const input = Buffer.from(String(bytesBase64 || ""), "base64");
      const entries = await listArchiveEntriesMain(input);
      return { success: true, format: "zip", entries };
    } catch (err) {
      console.error("list-archive error:", err);
      return { success: false, error: err?.message || String(err) };
    }
  });

  ipcMain.handle("extract-archive-entry", async (_event, { bytesBase64, entryPath, safePath } = {}) => {
    try {
      const input = Buffer.from(String(bytesBase64 || ""), "base64");
      const result = await extractArchiveEntryMain(input, entryPath, safePath);
      return { success: true, entryPath, safePath, bytesBase64: result.toString("base64"), byteLength: result.length };
    } catch (err) {
      console.error("extract-archive-entry error:", err);
      return { success: false, error: err?.message || String(err) };
    }
  });

  ipcMain.handle("sha256-bytes", async (_event, { bytesBase64 } = {}) => {
    try {
      const input = Buffer.from(String(bytesBase64 || ""), "base64");
      if (input.length === 0) throw new Error("Empty input");
      const hash = crypto.createHash("sha256").update(input).digest("hex");
      return { success: true, sha256: hash };
    } catch (err) {
      console.error("sha256-bytes error:", err);
      return { success: false, error: err?.message || String(err) };
    }
  });

  ipcMain.handle("upload-virustotal", async (_event, { bytesBase64, fileName, apiKey } = {}) => {
    try {
      const input = Buffer.from(String(bytesBase64 || ""), "base64");
      if (input.length === 0) throw new Error("Empty input");
      if (input.length > 32 * 1024 * 1024) throw new Error("VirusTotal upload limited to 32 MiB");
      const key = String(apiKey || getBackendVirusTotalApiKeyFromSettings() || "").trim();
      if (!key) throw new Error("VirusTotal API key is required");
      const result = await uploadFileToVirusTotal(input, String(fileName || "sample.bin"), key);
      return { success: true, ...result };
    } catch (err) {
      console.error("upload-virustotal error:", err);
      return { success: false, error: err?.message || String(err) };
    }
  });
}

async function uploadFileToVirusTotal(fileBuffer, fileName, apiKey) {
  const boundary = `----PacketSnitchFormBoundary${crypto.randomBytes(8).toString("hex")}`;
  const disposition = Buffer.from(
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="file"; filename="${String(fileName).replace(/"/g, "")}"\r\n` +
    `Content-Type: application/octet-stream\r\n\r\n`,
    "utf-8",
  );
  const closing = Buffer.from(`\r\n--${boundary}--\r\n`, "utf-8");
  const body = Buffer.concat([disposition, fileBuffer, closing]);

  const response = await undiciFetch("https://www.virustotal.com/api/v3/files", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "x-apikey": apiKey,
      "Content-Type": `multipart/form-data; boundary=${boundary}`,
      "Content-Length": String(body.length),
    },
    body,
  });

  const responseText = await response.text().catch(() => "");
  const responseData = (() => {
    try {
      return JSON.parse(responseText);
    } catch (_err) {
      return {};
    }
  })();

  if (response.status === 409) {
    const analysisId = responseData?.data?.id || responseData?.data?.attributes?.analysis_id || null;
    return {
      analysisId,
      lookupType: "hash",
      lookupValue: responseData?.meta?.file_info?.sha256 || null,
      sourceUrl: analysisId ? `https://www.virustotal.com/gui/file-analysis/${analysisId}` : null,
      analysis: buildVirusTotalAnalysisSummary(responseData),
      raw: responseData,
      alreadySubmitted: true,
    };
  }

  if (!response.ok && response.status !== 200 && response.status !== 201) {
    throw new Error(`VirusTotal upload failed: ${response.status} ${response.statusText} ${responseText}`);
  }
  const data = responseData;
  const analysisId = data?.data?.id || data?.data?.attributes?.analysis_id || null;
  const sha256 = data?.meta?.file_info?.sha256 || null;
  return {
    analysisId,
    lookupType: "hash",
    lookupValue: sha256,
    sourceUrl: analysisId ? `https://www.virustotal.com/gui/file-analysis/${analysisId}` : null,
    analysis: buildVirusTotalAnalysisSummary(data),
    raw: data,
  };
}

function buildVirusTotalAnalysisSummary(vtData) {
  const stats = vtData?.data?.attributes?.stats || vtData?.data?.attributes?.last_analysis_stats || {};
  return {
    malicious: Number(stats.malicious || 0),
    suspicious: Number(stats.suspicious || 0),
    harmless: Number(stats.harmless || 0),
    undetected: Number(stats.undetected || 0),
    timeout: Number(stats.timeout || 0),
    confirmedTimeout: Number(stats["confirmed-timeout"] || 0),
    failure: Number(stats.failure || 0),
    typeUnsupported: Number(stats["type-unsupported"] || 0),
  };
}

function getBackendVirusTotalApiKeyFromSettings() {
  try {
    const settings = getAppSettings();
    return String(
      settings?.apiKeys?.virusTotalApiKey
      || settings?.backend?.virusTotalApiKey
      || settings?.backend?.virustotal_api_key
      || "",
    ).trim();
  } catch (err) {
    console.error("getBackendVirusTotalApiKeyFromSettings error:", err);
    return "";
  }
}

function resolvePluginFailureThreshold(pluginEntry, settings) {
  const globalThreshold = Math.max(
    1,
    Number(settings?.plugins?.autoDisableFailureThreshold)
    || DEFAULT_SETTINGS.plugins.autoDisableFailureThreshold,
  );
  const perPluginThresholds =
    settings?.plugins?.perPluginFailureThreshold
      && typeof settings.plugins.perPluginFailureThreshold === "object"
      ? settings.plugins.perPluginFailureThreshold
      : {};
  const configuredPerPlugin = Number(perPluginThresholds?.[pluginEntry.pluginId]);
  const localOverride = Number(pluginEntry.failureThresholdOverride);
  if (Number.isFinite(localOverride) && localOverride > 0) {
    return Math.max(1, Math.floor(localOverride));
  }
  if (Number.isFinite(configuredPerPlugin) && configuredPerPlugin > 0) {
    return Math.max(1, Math.floor(configuredPerPlugin));
  }
  return globalThreshold;
}

async function installPluginFromZip(zipPath) {
  const absoluteZipPath = path.resolve(String(zipPath || ""));
  if (!absoluteZipPath) {
    throw new Error("Plugin zip path is required");
  }
  const zipStats = await fs.promises.stat(absoluteZipPath);
  if (!zipStats.isFile()) {
    throw new Error("Plugin zip path is not a file");
  }

  const zipBuffer = await fs.promises.readFile(absoluteZipPath);
  const packageHash = sha256Hex(zipBuffer);
  const zipDirectory = await openZipDirectory(absoluteZipPath);
  const manifest = await parsePluginManifestFromZipEntries(zipDirectory.files);
  const contentHash = await computeContentHashFromZipEntries(zipDirectory.files);
  const pluginId = sanitizePluginToken(manifest.pluginName, "plugin");
  const pluginVersion = manifest.pluginVersion;
  const pluginAddress = `${manifest.pluginName}@${pluginVersion}#${contentHash.slice(0, 12)}`;
  const packetsnitchVersion = String(app.getVersion() || "").trim();
  const compatibleWithCurrentPacketsnitch = isPacketsnitchVersionCompatible(
    packetsnitchVersion,
    manifest.compatiblePacketsnitchVersions,
  );
  if (!compatibleWithCurrentPacketsnitch) {
    throw new Error(
      `Plugin ${manifest.pluginName}@${pluginVersion} is not compatible with PacketSnitch ${packetsnitchVersion}`,
    );
  }

  const packageDir = getPluginPackagesDir();
  const installRootDir = getPluginInstallRootDir();
  const packagePath = path.join(
    packageDir,
    `${pluginId}-${pluginVersion}-${packageHash.slice(0, 12)}.zip`,
  );
  const installPath = path.join(
    installRootDir,
    pluginId,
    `${pluginVersion}-${contentHash.slice(0, 12)}`,
  );

  await fs.promises.mkdir(packageDir, { recursive: true });
  await fs.promises.mkdir(path.dirname(installPath), { recursive: true });
  await fs.promises.copyFile(absoluteZipPath, packagePath);
  await fs.promises.rm(installPath, { recursive: true, force: true });
  await extractPluginZipToDirectory(absoluteZipPath, installPath);

  const nowIso = new Date().toISOString();
  return {
    pluginId,
    pluginName: manifest.pluginName,
    pluginVersion,
    address: pluginAddress,
    capabilities: manifest.capabilities,
    author: manifest.author,
    authorHomepage: manifest.authorHomepage,
    updateUrl: manifest.updateUrl,
    compatiblePacketsnitchVersions: manifest.compatiblePacketsnitchVersions,
    compatibleWithCurrentPacketsnitch,
    packageHash,
    contentHash,
    packagePath,
    installPath,
    enabled: true,
    priority: Number.isFinite(Number(manifest.priority)) ? Number(manifest.priority) : 100,
    failureCount: 0,
    failureThresholdOverride: null,
    disabledReason: "",
    manifest,
    installedAt: nowIso,
    updatedAt: nowIso,
  };
}

async function inspectPluginZip(zipPath) {
  const absoluteZipPath = path.resolve(String(zipPath || ""));
  if (!absoluteZipPath) {
    throw new Error("Plugin zip path is required");
  }
  const zipStats = await fs.promises.stat(absoluteZipPath);
  if (!zipStats.isFile()) {
    throw new Error("Plugin zip path is not a file");
  }

  const zipDirectory = await openZipDirectory(absoluteZipPath);
  const manifest = await parsePluginManifestFromZipEntries(zipDirectory.files);
  const packetsnitchVersion = String(app.getVersion() || "").trim();
  const compatibleWithCurrentPacketsnitch = isPacketsnitchVersionCompatible(
    packetsnitchVersion,
    manifest.compatiblePacketsnitchVersions,
  );

  return {
    pluginName: manifest.pluginName,
    pluginVersion: manifest.pluginVersion,
    capabilities: Array.isArray(manifest.capabilities) ? manifest.capabilities : [],
    author: manifest.author || "",
    authorHomepage: manifest.authorHomepage || "",
    updateUrl: manifest.updateUrl || "",
    compatiblePacketsnitchVersions: Array.isArray(manifest.compatiblePacketsnitchVersions)
      ? manifest.compatiblePacketsnitchVersions
      : [],
    compatibleWithCurrentPacketsnitch,
  };
}

function getThemesDir() {
  return path.join(app.getPath("userData"), THEMES_DIR_NAME);
}

function getBundledThemesDir() {
  return path.join(app.getAppPath(), BUNDLED_THEMES_DIR_NAME);
}

function getBundledThemeDirs() {
  const appBundledDir = getBundledThemesDir();
  const candidateDirs = [appBundledDir];
  if (
    process.resourcesPath &&
    path.basename(process.resourcesPath) !== "resources"
  ) {
    candidateDirs.push(path.join(process.resourcesPath, BUNDLED_THEMES_DIR_NAME));
  }
  return Array.from(new Set(candidateDirs.filter((entry) => typeof entry === "string" && entry.trim())));
}

function sanitizeThemeId(value, fallback = "snitchbitch") {
  const safeFallback = typeof fallback === "string" && fallback ? fallback : "snitchbitch";
  if (typeof value !== "string") return safeFallback;
  const normalized = value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
  return normalized || safeFallback;
}

function normalizeThemeDefinition(rawTheme, fallbackId = "custom", metadata = {}) {
  if (!rawTheme || typeof rawTheme !== "object") return null;
  const id = sanitizeThemeId(rawTheme.id, fallbackId);
  const name = typeof rawTheme.name === "string" && rawTheme.name.trim()
    ? rawTheme.name.trim()
    : id;
  const description = typeof rawTheme.description === "string"
    ? rawTheme.description.trim()
    : "";
  const variables = rawTheme.variables && typeof rawTheme.variables === "object"
    ? Object.entries(rawTheme.variables).reduce((acc, [key, value]) => {
      if (!String(key).startsWith("--")) return acc;
      if (typeof value !== "string" || !value.trim()) return acc;
      acc[String(key)] = value.trim();
      return acc;
    }, {})
    : {};

  if (Object.keys(variables).length === 0) return null;
  const logoImage = normalizeThemeEmbeddedImage(rawTheme.logoImage);
  const backdropImage = normalizeThemeEmbeddedImage(rawTheme.backdropImage);
  const quitButtonCharacter =
    typeof rawTheme.quitButtonCharacter === "string" && rawTheme.quitButtonCharacter.trim()
      ? rawTheme.quitButtonCharacter.trim()
      : null;
  return {
    id,
    name,
    description,
    variables,
    logoImage,
    backdropImage,
    quitButtonCharacter,
    sourcePath: typeof metadata.sourcePath === "string" ? metadata.sourcePath : "",
    sourceKind: typeof metadata.sourceKind === "string" ? metadata.sourceKind : "unknown",
    sourceMtimeMs: Number.isFinite(metadata.sourceMtimeMs)
      ? metadata.sourceMtimeMs
      : 0,
  };
}

function normalizeThemeEmbeddedImage(rawImage) {
  if (!rawImage || typeof rawImage !== "object") {
    return null;
  }

  const rawFormat = typeof rawImage.format === "string"
    ? rawImage.format.trim().toLowerCase()
    : "";
  const normalizedFormat = rawFormat === "jpeg" ? "jpg" : rawFormat;
  if (normalizedFormat !== "png" && normalizedFormat !== "jpg") {
    return null;
  }

  const rawBase64 =
    typeof rawImage.base64 === "string"
      ? rawImage.base64
      : typeof rawImage.data === "string"
        ? rawImage.data
        : "";
  const strippedDataUri = rawBase64.replace(/^data:image\/(png|jpeg|jpg);base64,/i, "");
  const normalizedBase64 = strippedDataUri.replace(/\s+/g, "");
  if (!normalizedBase64 || !/^[A-Za-z0-9+/=]+$/.test(normalizedBase64)) {
    return null;
  }

  return {
    format: normalizedFormat,
    base64: normalizedBase64,
  };
}

function getComparableThemePayload(theme) {
  const normalizedVariables = theme && theme.variables && typeof theme.variables === "object"
    ? Object.fromEntries(Object.entries(theme.variables).sort(([a], [b]) => a.localeCompare(b)))
    : {};
  return {
    name: typeof theme?.name === "string" ? theme.name : "",
    description: typeof theme?.description === "string" ? theme.description : "",
    variables: normalizedVariables,
    logoImage: theme?.logoImage || null,
    backdropImage: theme?.backdropImage || null,
    quitButtonCharacter:
      typeof theme?.quitButtonCharacter === "string" ? theme.quitButtonCharacter : null,
  };
}

function areThemeDefinitionsEquivalent(leftTheme, rightTheme) {
  return JSON.stringify(getComparableThemePayload(leftTheme))
    === JSON.stringify(getComparableThemePayload(rightTheme));
}

async function readThemeDefinitionsFromDir(dirPath) {
  const fileEntries = await fs.promises.readdir(dirPath, { withFileTypes: true });
  const parsedThemes = [];

  for (const entry of fileEntries) {
    if (!entry.isFile() || !entry.name.toLowerCase().endsWith(THEME_FILE_EXTENSION)) {
      continue;
    }
    const filePath = path.join(dirPath, entry.name);
    try {
      const rawText = await fs.promises.readFile(filePath, "utf8");
      const stats = await fs.promises.stat(filePath);
      const parsed = JSON.parse(rawText);
      const fallbackId = sanitizeThemeId(path.basename(entry.name, THEME_FILE_EXTENSION), "custom");
      const normalized = normalizeThemeDefinition(parsed, fallbackId, {
        sourcePath: filePath,
        sourceKind: "unknown",
        sourceMtimeMs: stats.mtimeMs,
      });
      if (!normalized) continue;
      parsedThemes.push(normalized);
    } catch (error) {
      console.warn(`Skipping invalid theme file: ${filePath}`, error);
    }
  }

  return parsedThemes;
}

async function getDefaultThemeDefinitions() {
  const bundledThemeDirs = getBundledThemeDirs();
  for (const bundledThemesDir of bundledThemeDirs) {
    try {
      const bundledThemes = await readThemeDefinitionsFromDir(bundledThemesDir);
      if (bundledThemes.length > 0) {
        return bundledThemes;
      }
    } catch {
      // Try the next bundled theme directory candidate.
    }
  }

  // Fallback to in-code defaults when bundled theme files are unavailable.
  return DEFAULT_THEME_DEFINITIONS.map((theme) => ({
    ...theme,
    variables: { ...theme.variables },
  }));
}

async function ensureThemeFilesExist() {
  const themesDir = getThemesDir();
  await fs.promises.mkdir(themesDir, { recursive: true });
  const defaultThemes = await getDefaultThemeDefinitions();
  for (const defaultTheme of defaultThemes) {
    const filePath = path.join(themesDir, `${defaultTheme.id}${THEME_FILE_EXTENSION}`);
    try {
      await fs.promises.access(filePath, fs.constants.F_OK);
      // Existing user theme files are never modified automatically.
    } catch {
      await fs.promises.writeFile(
        filePath,
        JSON.stringify(defaultTheme, null, 2) + os.EOL,
        "utf8",
      );
    }
  }
  return themesDir;
}

async function listThemeDefinitions() {
  await ensureThemeFilesExist();
  const themesDir = getThemesDir();
  const bundledThemeDirs = getBundledThemeDirs();

  const userThemes = await readThemeDefinitionsFromDir(themesDir);
  userThemes.forEach((theme) => {
    theme.sourceKind = "user";
  });

  let bundledThemes = [];
  for (const bundledThemesDir of bundledThemeDirs) {
    try {
      const themesFromDir = await readThemeDefinitionsFromDir(bundledThemesDir);
      themesFromDir.forEach((theme) => {
        theme.sourceKind = "bundled";
      });
      bundledThemes = bundledThemes.concat(themesFromDir);
    } catch (error) {
      console.warn(`Unable to read bundled theme definitions from ${bundledThemesDir}:`, error);
    }
  }

  const allThemes = [...userThemes, ...bundledThemes];
  const themesById = new Map();
  const duplicateStateById = new Map();

  allThemes.forEach((theme) => {
    const existing = themesById.get(theme.id);
    if (!existing) {
      themesById.set(theme.id, theme);
      return;
    }

    const hasDiff = !areThemeDefinitionsEquivalent(existing, theme);
    const existingDuplicateState = duplicateStateById.get(theme.id) || {
      hasUserBundledConflict: false,
      hasUserBundledDiff: false,
    };
    const hasUserBundledPair =
      (existing.sourceKind === "user" && theme.sourceKind === "bundled")
      || (existing.sourceKind === "bundled" && theme.sourceKind === "user");
    duplicateStateById.set(theme.id, {
      hasUserBundledConflict: existingDuplicateState.hasUserBundledConflict || hasUserBundledPair,
      hasUserBundledDiff: existingDuplicateState.hasUserBundledDiff || (hasUserBundledPair && hasDiff),
    });

    const existingMtime = Number.isFinite(existing.sourceMtimeMs)
      ? existing.sourceMtimeMs
      : 0;
    const currentMtime = Number.isFinite(theme.sourceMtimeMs)
      ? theme.sourceMtimeMs
      : 0;

    let nextTheme;
    if (currentMtime > existingMtime) {
      nextTheme = theme;
    } else if (currentMtime < existingMtime) {
      nextTheme = existing;
    } else {
      nextTheme = [existing, theme].find((entry) => entry.sourceKind === "user") || existing;
    }

    themesById.set(theme.id, nextTheme);
  });

  const deduped = Array.from(themesById.values()).map((theme) => ({
    id: theme.id,
    name: theme.name,
    description: theme.description,
    variables: theme.variables,
    logoImage: theme.logoImage,
    backdropImage: theme.backdropImage,
    quitButtonCharacter: theme.quitButtonCharacter,
    sourceKind: theme.sourceKind,
    hasUserBundledConflict: Boolean(duplicateStateById.get(theme.id)?.hasUserBundledConflict),
    hasUserBundledDiff: Boolean(duplicateStateById.get(theme.id)?.hasUserBundledDiff),
  }));

  deduped.sort((a, b) => a.name.localeCompare(b.name));
  return deduped;
}

async function getThemeById(themeId) {
  const requestedId = sanitizeThemeId(themeId, "snitchbitch");
  const themes = await listThemeDefinitions();
  const found = themes.find((theme) => theme.id === requestedId);
  if (found) return found;
  return themes.find((theme) => theme.id === "snitchbitch") || themes[0] || null;
}

async function ensureSettingsFileExists(settings) {
  const settingsFilePath = getSettingsFilePath();
  await fs.promises.mkdir(path.dirname(settingsFilePath), { recursive: true });
  await fs.promises.writeFile(
    settingsFilePath,
    JSON.stringify(settings, null, 2) + os.EOL,
    "utf8",
  );
  return settingsFilePath;
}

async function loadSettingsFromDisk() {
  const settingsFilePath = getSettingsFilePath();
  try {
    const rawText = await fs.promises.readFile(settingsFilePath, "utf8");
    const parsedSettings = normalizeSettings(JSON.parse(rawText));
    appSettings = parsedSettings;
    return parsedSettings;
  } catch (error) {
    if (error && error.code !== "ENOENT") {
      console.warn("Failed to load PacketSnitch settings, using defaults:", error);
    }
    appSettings = normalizeSettings(DEFAULT_SETTINGS);
    await ensureSettingsFileExists(appSettings);
    return appSettings;
  }
}

async function saveSettingsToDisk(nextSettings) {
  const normalizedSettings = normalizeSettings(nextSettings);
  appSettings = normalizedSettings;
  ollamaModelsCache = null;
  await ensureSettingsFileExists(normalizedSettings);
  return normalizedSettings;
}

function normalizeFilterLibraryEntry(rawEntry = {}) {
  if (!rawEntry || typeof rawEntry !== "object") return null;

  const label =
    typeof rawEntry.label === "string" ? rawEntry.label.trim() : "";
  const query =
    typeof rawEntry.query === "string" ? rawEntry.query.trim() : "";
  if (!label || !query) return null;

  const idCandidate =
    typeof rawEntry.id === "string" && rawEntry.id.trim()
      ? rawEntry.id.trim()
      : `saved-filter-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const createdAtCandidate =
    typeof rawEntry.createdAt === "string" && rawEntry.createdAt.trim()
      ? rawEntry.createdAt.trim()
      : new Date().toISOString();
  const updatedAtCandidate =
    typeof rawEntry.updatedAt === "string" && rawEntry.updatedAt.trim()
      ? rawEntry.updatedAt.trim()
      : createdAtCandidate;

  return {
    id: idCandidate,
    label,
    query,
    createdAt: createdAtCandidate,
    updatedAt: updatedAtCandidate,
  };
}

function normalizeFilterLibrary(rawFilters) {
  if (!Array.isArray(rawFilters)) return [];
  const seen = new Set();
  const normalized = [];
  for (const entry of rawFilters) {
    const normalizedEntry = normalizeFilterLibraryEntry(entry);
    if (!normalizedEntry) continue;
    const duplicateKey = `${normalizedEntry.label.toLowerCase()}\u0000${normalizedEntry.query}`;
    if (seen.has(duplicateKey)) continue;
    seen.add(duplicateKey);
    normalized.push(normalizedEntry);
  }

  normalized.sort((left, right) => {
    const byLabel = left.label.localeCompare(right.label);
    if (byLabel !== 0) return byLabel;
    return right.updatedAt.localeCompare(left.updatedAt);
  });
  return normalized;
}

async function loadFilterLibraryFromDisk() {
  const filePath = getFilterLibraryFilePath();
  try {
    const rawText = await fs.promises.readFile(filePath, "utf8");
    const parsed = JSON.parse(rawText);
    const sourceEntries = Array.isArray(parsed)
      ? parsed
      : Array.isArray(parsed?.filters)
        ? parsed.filters
        : [];
    return normalizeFilterLibrary(sourceEntries);
  } catch (error) {
    if (error && error.code !== "ENOENT") {
      console.warn("Failed to load saved filters; continuing with empty list:", error);
    }
    return [];
  }
}

async function saveFilterLibraryToDisk(filters) {
  const normalizedFilters = normalizeFilterLibrary(filters);
  const filePath = getFilterLibraryFilePath();
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
  await fs.promises.writeFile(
    filePath,
    JSON.stringify({ filters: normalizedFilters }, null, 2) + os.EOL,
    "utf8",
  );
  return normalizedFilters;
}

function normalizeOllamaModelName(rawValue) {
  if (typeof rawValue !== "string") return "";
  const normalized = rawValue.trim();
  if (!normalized || normalized.startsWith("#")) return "";
  return normalized;
}

function normalizeOllamaModelLabel(rawValue, fallbackValue) {
  if (typeof rawValue !== "string") {
    return fallbackValue;
  }
  const normalized = rawValue.trim();
  return normalized || fallbackValue;
}

function normalizeOllamaModelEntry(rawEntry) {
  if (typeof rawEntry === "string") {
    const value = normalizeOllamaModelName(rawEntry);
    return value ? { value, label: value } : null;
  }
  if (!rawEntry || typeof rawEntry !== "object") return null;

  const valueCandidates = [
    rawEntry.name,
    rawEntry.model,
    rawEntry.id,
    rawEntry.value,
  ];

  for (const candidate of valueCandidates) {
    const value = normalizeOllamaModelName(candidate);
    if (value) {
      return {
        value,
        label: normalizeOllamaModelLabel(rawEntry.label, value),
      };
    }
  }

  return null;
}

function normalizeOllamaModelsLibrary(rawLibrary) {
  const entries = Array.isArray(rawLibrary)
    ? rawLibrary
    : Array.isArray(rawLibrary?.models)
      ? rawLibrary.models
      : [];
  const seen = new Set();
  const normalized = [];

  for (const entry of entries) {
    const normalizedEntry = normalizeOllamaModelEntry(entry);
    if (!normalizedEntry || seen.has(normalizedEntry.value)) continue;
    seen.add(normalizedEntry.value);
    normalized.push(normalizedEntry);
  }

  return normalized;
}

async function getBundledOllamaModels() {
  const bundledModelsPath = getBundledModelsLibraryFilePath();
  try {
    const rawText = await fs.promises.readFile(bundledModelsPath, "utf8");
    const parsed = JSON.parse(rawText);
    const models = normalizeOllamaModelsLibrary(parsed);
    if (models.length > 0) {
      return models;
    }
  } catch (error) {
    console.warn("Unable to load bundled models library from config/models.json:", error);
  }

  return [];
}

async function ensureModelsLibraryFileExists() {
  const filePath = getModelsLibraryFilePath();
  try {
    await fs.promises.access(filePath, fs.constants.F_OK);
    return filePath;
  } catch {
    const defaultModels = await getBundledOllamaModels();
    const initialPayload = {
      models: defaultModels.map((entry) => ({
        name: entry.value,
        label: entry.label,
      })),
    };
    await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
    await fs.promises.writeFile(
      filePath,
      JSON.stringify(initialPayload, null, 2) + os.EOL,
      "utf8",
    );
    return filePath;
  }
}

async function loadOllamaModelsFromDisk() {
  const filePath = await ensureModelsLibraryFileExists();
  try {
    const rawText = await fs.promises.readFile(filePath, "utf8");
    const parsed = JSON.parse(rawText);
    const models = normalizeOllamaModelsLibrary(parsed);
    if (models.length > 0) {
      return models;
    }
  } catch (error) {
    console.warn("Failed to load config/models.json; falling back to bundled defaults:", error);
  }

  return getBundledOllamaModels();
}

async function upsertSavedFilter(label, query) {
  const normalizedLabel = typeof label === "string" ? label.trim() : "";
  const normalizedQuery = typeof query === "string" ? query.trim() : "";
  if (!normalizedLabel || !normalizedQuery) {
    throw createTaggedError(
      "EINVAL",
      "Both filter label and query are required.",
    );
  }

  const existingFilters = await loadFilterLibraryFromDisk();
  const nowIso = new Date().toISOString();
  const existingIndex = existingFilters.findIndex(
    (entry) => entry.label.toLowerCase() === normalizedLabel.toLowerCase(),
  );

  if (existingIndex !== -1) {
    const existingEntry = existingFilters[existingIndex];
    existingFilters[existingIndex] = {
      ...existingEntry,
      label: normalizedLabel,
      query: normalizedQuery,
      updatedAt: nowIso,
    };
  } else {
    existingFilters.push({
      id: `saved-filter-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      label: normalizedLabel,
      query: normalizedQuery,
      createdAt: nowIso,
      updatedAt: nowIso,
    });
  }

  return saveFilterLibraryToDisk(existingFilters);
}

async function removeSavedFilterById(filterId) {
  const normalizedFilterId =
    typeof filterId === "string" ? filterId.trim() : "";
  if (!normalizedFilterId) {
    throw createTaggedError("EINVAL", "Saved filter id is required.");
  }

  const existingFilters = await loadFilterLibraryFromDisk();
  const filtered = existingFilters.filter(
    (entry) => entry.id !== normalizedFilterId,
  );
  return saveFilterLibraryToDisk(filtered);
}

function getAppSettings() {
  if (!appSettings) {
    appSettings = normalizeSettings(DEFAULT_SETTINGS);
  }
  return appSettings;
}


function checkNewInstall() {
  if (!versionFilePath) return false;
  try {
    if (!fs.existsSync(versionFilePath)) {
      return true;
    }
    const storedVersion = fs.readFileSync(versionFilePath, "utf8").trim();
    return storedVersion !== app.getVersion();
  } catch (err) {
    console.error("Error checking install version:", err);
    return true;
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    minWidth: 1275,
    minHeight: 600,
    width: 1400,
    height: 820,
    // the icon only sets under linux, windows uses the forge config 
    // specified icons for the exe and installer, and macOS uses 
    // the .icns file specified in the forge config
    icon: path.join("/", "usr", "share", "pixmaps", "packetsnitch.png"),
    frame: false,
    webPreferences: {
      preload: MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY,
      contextIsolation: true,
      nodeIntegration: true,
    },
  });
  mainWindow.webContents.setUserAgent(userAgent);
  ensureRendererCspHeader(mainWindow.webContents.session);
  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);
  const appendRendererDiagnostic = (message) => {
    appendActivityLogLine(
      `[${new Date().toISOString()}] [Console][Renderer] ${message}`,
    );
  };
  mainWindow.webContents.on(
    "did-fail-load",
    (_event, errorCode, errorDescription, validatedURL, isMainFrame) => {
      const diagnostic = JSON.stringify({
        errorCode,
        errorDescription,
        validatedURL,
        isMainFrame,
      });
      console.error("Main window failed to load:", diagnostic);
      appendRendererDiagnostic(`did-fail-load ${diagnostic}`);
    },
  );
  mainWindow.webContents.on("render-process-gone", (_event, details) => {
    console.error("Renderer process exited unexpectedly:", details);
    appendRendererDiagnostic(`render-process-gone ${JSON.stringify(details)}`);
  });
  mainWindow.webContents.on("preload-error", (_event, preloadPath, error) => {
    const diagnostic = `${preloadPath} ${error?.message || String(error)}`;
    console.error("Preload script error:", preloadPath, error);
    appendRendererDiagnostic(`preload-error ${diagnostic}`);
  });
  mainWindow.webContents.on(
    "console-message",
    (eventOrPayload, levelArg, messageArg, lineArg, sourceIdArg) => {
      const payload =
        typeof levelArg === "number"
          ? {
            level: levelArg,
            message: messageArg,
            line: lineArg,
            sourceId: sourceIdArg,
          }
          : eventOrPayload || {};
      const level = Number(payload?.level ?? 0);
      if (level >= 2) {
        const diagnostic = JSON.stringify({
          message: payload?.message || "",
          line: Number(payload?.line ?? 0),
          sourceId: payload?.sourceId || "",
        });
        console.error("Renderer console error:", diagnostic);
        appendRendererDiagnostic(`console-message ${diagnostic}`);
      }
    },
  );
  mainWindow.webContents.on("did-finish-load", () => {
    mainWindow.webContents.setZoomFactor(0.7); // makes everything fit snuggly
  });
  mainWindow.webContents.once("did-finish-load", () => {
    const settings = getAppSettings();
    if (settings?.backend?.forceLegacySpawn) {
      return;
    }
    if (backCommModule && typeof backCommModule.primeBackendHttpServer === "function") {
      void backCommModule.primeBackendHttpServer(settings?.backend).then((ready) => {
        if (!ready) {
          global.logBackend("[Bridge] HTTP backend service unavailable; legacy spawn mode remains active");
        }
      });
    }
    // Start the metrics flush loop now that the renderer is ready to
    // accept `metrics:flush-request` messages. The timer is unref()'d so
    // it never blocks process exit.
    installMetricsFlushTimer();
    requestMetricsFlushFromRenderer();
  });
  mainWindow.once("close", () => {
    appendActivityLogLine(
      timestampLifecycleMessage(
        `Session closed for PacketSnitch v${app.getVersion()}`,
      ),
      { broadcast: false },
    );
  });
  mainWindow.webContents.on('did-create-window', (helpWinChild) => {
    helpWinChild.webContents.on('will-navigate', (event, url) => {
      const hostname = new URL(url).hostname;
      const isPacketSnitchHost = hostname === 'packetsnitch.com' || hostname.endsWith('.packetsnitch.com');
      const isBuyMeACoffeeHost = hostname === 'buymeacoffee.com' || hostname.endsWith('.buymeacoffee.com');
      const isVirusTotalHost = hostname === 'virustotal.com' || hostname.endsWith('.virustotal.com');

      if ((hostname !== 'github.com' && !isPacketSnitchHost && !isBuyMeACoffeeHost && !isVirusTotalHost)) {
        if (!url.startsWith('https://github.com/oxasploits/packetsnitch/') && !url.startsWith('https://packetsnitch.com/') && !url.startsWith('https://www.packetsnitch.com/') && !url.startsWith('https://buymeacoffee.com/') && !url.startsWith('https://www.buymeacoffee.com/') && !url.startsWith('https://www.virustotal.com/')) {
          console.log(`Blocked navigation to external domain: ${url}`);
          event.preventDefault();
        }
      }
    });
    helpWinChild.removeMenu();
    helpWinChild.setSize(1200, 900);
    helpWinChild.webContents.setUserAgent(userAgent);
    helpWinChild.webContents.on('did-finish-load', () => {
      let helpPage = "";
      let helpURL = helpWinChild.webContents.getURL();
      // regex for matching the help page within the URL
      const helpPageRegex = /.*\/(.+?)\/$/;
      pageMatch = helpURL.match(helpPageRegex);
      if (helpURL.startsWith("https://packetsnitch.com/")) {
        helpPage = pageMatch ? pageMatch[1] : "unknown";
      }
      else if (helpURL.startsWith("https://github.com/oxasploits/PacketSnitch")) {
        helpPage = "Repo";
      }
      else {
        helpPage = "Unknown";
      }
      if (pageMatch && pageMatch[1]) {
        helpPage = helpPage.replace(/\//g, ""); // remove slashes
      }
      if (helpPage === "packetsnitch.com") {
        helpPage = "Home";
      }
      helpPage = helpPage.charAt(0).toUpperCase() + helpPage.slice(1);
      console.log(`Help loaded PacketSnitch DocsHub ${helpPage}`);
    });

    helpWinChild.webContents.on('did-fail-load', (
      event,
      errorCode,
      errorDescription,
      validatedURL
    ) => {
      console.error(
        `Failed to load ${validatedURL}: ${errorDescription} (${errorCode})`
      );
    });
  });
}

function formatConsoleArgs(args) {
  return args
    .map((arg) => {
      if (arg instanceof Error) {
        return arg.stack || arg.message;
      }
      if (typeof arg === "string") {
        return arg;
      }
      return util.inspect(arg, {
        depth: CONSOLE_INSPECT_DEPTH,
        breakLength: Infinity,
        maxArrayLength: CONSOLE_MAX_ARRAY_LENGTH,
      });
    })
    .join(" ");
}

function appendActivityLogToFile(entry) {
  try {
    fs.appendFileSync(activityLogFilePath, entry + os.EOL, "utf8");
  } catch (error) {
    console.error("Unable to append activity log:", error);
  }
}

function cacheActivityLogEntry(entry) {
  activityLogEntries.unshift(entry);
}

function broadcastActivityLogEntry(entry) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send("activity-log-entry", entry);
  }
}

function normalizeActivityLogEntry(entry) {
  if (typeof entry !== "string" || entry.trim() === "" || entry.trim() === "\n")
    return null;
  return entry.trim();
}

function timestampLifecycleMessage(message) {
  return `[${new Date().toISOString()}] [GUI][Main] ${message}`;
}

function appendActivityLogLine(entry, options = {}) {
  const { broadcast = true } = options;
  const normalizedEntry = normalizeActivityLogEntry(entry);
  if (!normalizedEntry) return;
  cacheActivityLogEntry(normalizedEntry);
  if (activityLogFilePath) {
    appendActivityLogToFile(normalizedEntry);
  } else {
    pendingActivityLogEntries.push(normalizedEntry);
  }
  if (broadcast) {
    broadcastActivityLogEntry(normalizedEntry);
  }
}

function flushPendingActivityLogEntries() {
  if (!activityLogFilePath || pendingActivityLogEntries.length === 0) return;
  pendingActivityLogEntries.forEach((entry) => {
    appendActivityLogToFile(entry);
  });
  pendingActivityLogEntries.splice(0);
}

const originalConsoleLog = console.log.bind(console);
console.log = (...args) => {
  originalConsoleLog(...args);
  const message = formatConsoleArgs(args);
  if (!message) return;
  appendActivityLogLine(
    `[${new Date().toISOString()}] [Console][Main] ${message}`,
  );
};

global.logBackend = (...args) => {
  const message = formatConsoleArgs(args);
  if (!message) return;
  originalConsoleLog(message);
  const timestamp = new Date().toISOString();
  message.split(/\r?\n/).forEach((line) => {
    if (line.trim() === "") return;
    // if the line begins with a space, remove it
    if (line.startsWith(" ")) {
      line = line.substring(1);
    }
    if (line.includes("[Worker] Processing packet")) {
      return;
    }
    if (line.includes("warnings.warn")) {
      return;
    }
    appendActivityLogLine(`[${timestamp}] [Console][Snitch]${line}`);
  });
};

app.whenReady().then(() => {
  versionFilePath = path.join(app.getPath("userData"), "installed_version.txt");
  activityLogFilePath = path.join(app.getPath("userData"), "activity-log.txt");
  flushPendingActivityLogEntries();
  appendActivityLogLine(
    `[${new Date().toISOString()}] [GUI][Main] Session started for PacketSnitch v${app.getVersion()}`,
  );
  isFirstRunAfterInstall = checkNewInstall();
  void ensureThemeFilesExist().catch((error) => {
    console.warn("Unable to initialize theme directory:", error);
  });
  checkOllama().then(async (ollamaDiagnostics) => {
    cachedOllamaInstalled = Boolean(ollamaDiagnostics?.ollamaInstalled);
    cachedOllamaServerListening = Boolean(ollamaDiagnostics?.ollamaServerListening);
    cachedOllamaStartupCheckedAt = new Date().toISOString();
    logLlmDiagnostics("LLM startup diagnostics", ollamaDiagnostics);
    await loadSettingsFromDisk();
    refreshOllamaCloudApiDiagnostics()
      .then((cloudDiagnostics) => {
        logLlmDiagnostics("LLM cloud diagnostics", cloudDiagnostics);
      })
      .catch((error) => {
        console.warn("Unable to resolve Ollama cloud diagnostics:", error);
      });
    if (!cachedOllamaInstalled) {
      console.log(
        "Ollama is unavailable (not installed or not in PATH). LLM summarisation will be unavailable.",
      );
    } else if (!cachedOllamaServerListening) {
      console.log(
        "Ollama is installed but the server is not listening. LLM summarisation will be unavailable until the daemon is started.",
      );
    }
    createWindow();
    app.on("activate", function () {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
    console.log("App ready, waiting for file selection...");
    registerCaptureStoreHandlers(ipcMain);
    installExtractionHandlers();
    // start the process that listens for the file selection and runs the backend command
    backCommModule = require("./back-comm");
    // Reclaim the configured HTTP backend port before any IPC traffic is
    // exchanged. If a previous GUI session exited without cleanly shutting
    // down its backend, the orphan is asked to stop gracefully and only
    // force-killed as a last resort. This runs before the window's
    // did-finish-load handler primes the backend for normal operation.
    void reclaimPreExistingBackendAtStartup();
    ipcMain.handle("select-file", async () => {
      const { canceled, filePaths } = await dialog.showOpenDialog({
        properties: ["openFile"],
        filters: [
          {
            name: "Capture and Session Files",
            extensions: [
              "pcap",
              "pcapng",
              "cap",
              "pss",
              "pss.gz",
            ],
          },
        ],
      });
      if (canceled) return null;
      selectedFilePath = filePaths[0];
      return filePaths[0];
    });
    ipcMain.handle("select-manual-conv-file", async () => {
      const { canceled, filePaths } = await dialog.showOpenDialog({
        properties: ["openFile"],
        filters: [
          {
            name: "All Files",
            extensions: ["*"],
          },
        ],
      });
      if (canceled || !filePaths?.[0]) return null;
      const filePath = filePaths[0];
      const fileBuffer = await fs.promises.readFile(filePath);
      return {
        filePath,
        fileName: path.basename(filePath),
        size: fileBuffer.length,
        base64: fileBuffer.toString("base64"),
      };
    });
    ipcMain.handle("select-plugin-zip", async () => {
      const { canceled, filePaths } = await dialog.showOpenDialog({
        properties: ["openFile"],
        filters: [
          {
            name: "Plugin Archives",
            extensions: ["zip"],
          },
          {
            name: "All Files",
            extensions: ["*"],
          },
        ],
      });
      if (canceled || !filePaths?.[0]) return null;
      return filePaths[0];
    });
  });
});

ipcMain.handle("check-first-run", async () => {
  const isDev = !app.isPackaged;
  const basePath = isDev
    ? path.join(__dirname, "../../src/backend/")
    : process.resourcesPath;
  const backendExe = platform === "win32" ? "snitch.exe" : "snitch";

  const backendCandidates = [
    path.join(basePath, "snitch", backendExe),
    path.join(basePath, backendExe),
  ];
  if (isDev) {
    backendCandidates.push(path.join(basePath, "snitch.py"));
  }

  let resolvedBackendPath = backendCandidates[0];
  let backendExists = false;
  for (const candidatePath of backendCandidates) {
    if (fs.existsSync(candidatePath)) {
      resolvedBackendPath = candidatePath;
      backendExists = true;
      break;
    }
  }

  const filesToCheck = [
    {
      name: "PacketSnitch Backend (" + backendExe + ")",
      path: resolvedBackendPath,
      exists: backendExists,
    },
    {
      name: "GeoIP Database (GeoLite2-City.mmdb)",
      path: path.join(basePath, "common", "GeoLite2-City.mmdb"),
    },
    {
      name: "MAC Vendors Database (mac-vendors-export.csv)",
      path: path.join(basePath, "common", "mac-vendors-export.csv"),
    },
    {
      name: "Services Database (service-names-port-numbers.csv)",
      path: path.join(basePath, "common", "service-names-port-numbers.csv"),
    },
    {
      name: "Frontend Interface (app.asar)",
      path: path.join(process.resourcesPath, "app.asar"),
    },
  ];
  const installedFiles = filesToCheck.map((f) => {
    const exists = Object.prototype.hasOwnProperty.call(f, "exists")
      ? Boolean(f.exists)
      : fs.existsSync(f.path);
    return {
      name: f.name,
      path: f.path,
      exists,
    };
  });
  return {
    isFirstRun: isFirstRunAfterInstall,
    version: app.getVersion(),
    ollamaInstalled: cachedOllamaInstalled,
    ollamaServerListening: cachedOllamaServerListening,
    llmDiagnostics: getLlmDiagnostics(),
    installedFiles,
  };
});

ipcMain.handle("get-llm-diagnostics", async () => getLlmDiagnostics());

ipcMain.handle("get-backend-diagnostics", async (_event, options = {}) => {
  if (
    !backCommModule
    || typeof backCommModule.getBackendServiceDiagnostics !== "function"
  ) {
    return {
      success: false,
      error: "Backend bridge is not initialized",
      mode: "unknown",
      forceLegacySpawn: false,
      host: "",
      port: 0,
      backendProcessRunning: false,
      backendWebserverUp: false,
      backendVersion: null,
      backendVersionService: null,
      backendVersionReachable: false,
      checkedAt: new Date().toISOString(),
    };
  }
  try {
    return await backCommModule.getBackendServiceDiagnostics(options);
  } catch (error) {
    return {
      success: false,
      error: error?.message || "Unable to get backend diagnostics",
      mode: "unknown",
      forceLegacySpawn: false,
      host: "",
      port: 0,
      backendProcessRunning: false,
      backendWebserverUp: false,
      backendVersion: null,
      backendVersionService: null,
      backendVersionReachable: false,
      checkedAt: new Date().toISOString(),
    };
  }
});

ipcMain.handle("check-nmap-installed", async () => {
  return checkNmapInstalled();
});

ipcMain.handle("get-nmap-scan-status", async () => {
  return getNmapScanRuntimeStatus();
});

ipcMain.handle("run-nmap-service-scan", async (_event, targets = [], options = {}) => {
  if (!appSettings) {
    await loadSettingsFromDisk();
  }

  if (!isNmapServiceScanEnabledInSettings()) {
    return {
      success: false,
      nmapInstalled: false,
      error: "Nmap service scans are disabled in Settings",
      results: [],
      targets: [],
      disabledBySettings: true,
    };
  }

  try {
    return await runNmapServiceScan(targets, options);
  } catch (error) {
    return {
      success: false,
      nmapInstalled: false,
      error: error?.message || "Nmap service scan failed",
      results: [],
      targets: normalizeNmapTargets(targets),
    };
  }
});

ipcMain.handle("dismiss-first-run", async () => {
  if (app.isPackaged) {
    const currentVersion = app.getVersion();
    try {
      fs.writeFileSync(versionFilePath, currentVersion, "utf8");
      isFirstRunAfterInstall = false;
      return { success: true };
    } catch (err) {
      console.error("Failed to write version file:", err);
      return { success: false, error: err.message };
    }
  }
});

ipcMain.handle("get-goodies", async () => {
  // now we look for src/data/goodies.txt in the resources path, and if it exists, we read it and return it
  if (goodiesDataCache) {
    return goodiesDataCache;
  }
  const goodiesPath = path.join(
    app.isPackaged ? process.resourcesPath :
      "src",
    "data",
    "goodies.txt"
  );
  if (fs.existsSync(goodiesPath)) {
    const goodiesData = fs.readFileSync(goodiesPath, "utf8");
    const goodies = goodiesData.split("\n").map((line) => line.trim()).filter((line) => line.length > 0 && !line.startsWith("#"));
    goodiesDataCache = goodies;
    console.log(`Loaded ${goodies.length} goodies from ${goodiesPath}`);

    return goodies;
  } else {
    console.warn(`Goodies file not found at ${goodiesPath}`);
    return [];
  }
});

ipcMain.handle("quit-app", () => {
  app.quit();
});

ipcMain.handle("prompt-save-session-on-exit", async () => {
  const response = await dialog.showMessageBox({
    type: "question",
    buttons: ["Save Session", "Don't Save", "Cancel"],
    defaultId: 0,
    cancelId: 2,
    title: "Save Session",
    message: "Do you want to save your PacketSnitch session before exiting?",
  });
  if (response.response === 0) return "save";
  if (response.response === 1) return "discard";
  return "cancel";
});

ipcMain.handle("save-json", async (_event, jsonData) => {
  if (typeof jsonData !== "string" || jsonData.trim() === "") {
    return { success: false, error: "No JSON data to save" };
  }

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Save PacketSnitch Session",
    defaultPath: path.join(
      app.getPath("documents"),
      "packetsnitch-session.json",
    ),
    filters: [{ name: "JSON Files", extensions: ["json"] }],
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    await fs.promises.writeFile(filePath, jsonData, "utf8");
    return { success: true };
  } catch (err) {
    console.error("Save error:", err);
    return { success: false, error: err.message };
  }
});


ipcMain.handle("current-packet-json", async (_event, packetData) => {
  // we need to use main-frontend.js's getCurrentPacketForExport() function

  const packetJson = JSON.stringify(packetData, null, 2);
  if (packetJson === null || packetJson === undefined) {
    return { success: false, error: "No packet data available" };
  }
  return { success: true, data: packetJson };
});

ipcMain.handle("save-packet", async (_event, packetData) => {
  if (packetData === null || packetData === undefined) {
    return { success: false, error: "No packet data to save" };
  }
  const packetJson = JSON.stringify(packetData, null, 2);

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Export Packet",
    defaultPath: path.join(app.getPath("documents"), "packet.json"),
    filters: [{ name: "JSON Files", extensions: ["json"] }],
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    await fs.promises.writeFile(filePath, packetJson, "utf8");
    return { success: true };
  } catch (err) {
    console.error("Packet export error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("save-payload", async (_event, payloadHex, options = {}) => {
  if (typeof payloadHex !== "string") {
    return { success: false, error: "No payload data to save" };
  }
  const normalizedHex = payloadHex.replace(/\s+/g, "");
  if (
    normalizedHex.length === 0 ||
    normalizedHex.length % 2 !== 0 ||
    !/^[\da-fA-F]+$/.test(normalizedHex)
  ) {
    return {
      success: false,
      error: "Payload must be a non-empty hex string with an even length",
    };
  }

  const defaultNameRaw =
    typeof options?.defaultName === "string" && options.defaultName.trim()
      ? options.defaultName.trim()
      : "packet-payload.bin";
  const baseName = path
    .basename(defaultNameRaw)
    .replace(/[\\/:*?"<>|]/g, "_")
    .replace(/\.$/, "");
  const guessedExtensionMatch = baseName.match(/\.([^.]+)$/);
  const guessedExtension = guessedExtensionMatch ? guessedExtensionMatch[1] : "";
  const defaultName = guessedExtension
    ? baseName
    : `${baseName || "packet-payload"}.bin`;
  const defaultExtension = guessedExtension || "bin";

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Export Packet Payload",
    defaultPath: path.join(app.getPath("documents"), defaultName),
    filters: [
      {
        name: guessedExtension
          ? `${guessedExtension.toUpperCase()} Files`
          : "Binary Files",
        extensions: [guessedExtension || "bin", "*"],
      },
      { name: "All Files", extensions: ["*"] },
    ],
    defaultExtension,
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    const payloadBuffer = Buffer.from(normalizedHex, "hex");
    await fs.promises.writeFile(filePath, payloadBuffer);
    return { success: true };
  } catch (err) {
    console.error("Payload export error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("save-text", async (_event, options = {}) => {
  const text = typeof options?.text === "string" ? options.text : "";
  if (!text.trim()) {
    return { success: false, error: "No text data to save" };
  }

  const dialogTitle =
    typeof options?.title === "string" && options.title.trim()
      ? options.title.trim()
      : "Save Text";
  const defaultNameRaw =
    typeof options?.defaultName === "string" && options.defaultName.trim()
      ? options.defaultName.trim()
      : "packetsnitch-export.txt";
  const defaultName = path.basename(defaultNameRaw);
  const customFilters = Array.isArray(options?.filters)
    ? options.filters
      .map((entry) => {
        const name =
          typeof entry?.name === "string" && entry.name.trim()
            ? entry.name.trim()
            : "";
        const extensions = Array.isArray(entry?.extensions)
          ? entry.extensions
            .map((extension) =>
              typeof extension === "string" ? extension.trim().replace(/^\./, "") : "",
            )
            .filter(Boolean)
          : [];
        if (!name || !extensions.length) return null;
        return { name, extensions };
      })
      .filter(Boolean)
    : [];
  const dialogFilters = customFilters.length
    ? customFilters
    : [
      { name: "Text Files", extensions: ["txt"] },
      { name: "All Files", extensions: ["*"] },
    ];
  const defaultExtension =
    typeof options?.defaultExtension === "string" && options.defaultExtension.trim()
      ? options.defaultExtension.trim().replace(/^\./, "")
      : undefined;

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: dialogTitle,
    defaultPath: path.join(app.getPath("documents"), defaultName),
    filters: dialogFilters,
    defaultExtension,
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    await fs.promises.writeFile(filePath, text, "utf8");
    return { success: true };
  } catch (err) {
    console.error("Text save error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("get-asset-base64", async (_event, relativePath) => {
  const rel = typeof relativePath === "string" ? relativePath.trim() : "";
  if (!rel) {
    return { success: false, error: "Missing asset path" };
  }
  const appRoot = path.resolve(app.getAppPath());
  const assetPath = path.resolve(path.join(appRoot, rel));
  if (!assetPath.startsWith(appRoot + path.sep)) {
    return { success: false, error: "Invalid asset path" };
  }
  try {
    const buffer = await fs.promises.readFile(assetPath);
    const ext = path.extname(assetPath).toLowerCase();
    const mimeTypeMap = {
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".svg": "image/svg+xml",
      ".webp": "image/webp",
      ".gif": "image/gif",
    };
    const mime = mimeTypeMap[ext] || "application/octet-stream";
    return { success: true, data: buffer.toString("base64"), mime };
  } catch (err) {
    console.error("Asset read error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("save-cookie-jar", async (_event, cookieJarText) => {
  if (typeof cookieJarText !== "string" || cookieJarText.trim() === "") {
    return { success: false, error: "No cookie jar data to save" };
  }

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Save Cookie Jar",
    defaultPath: path.join(app.getPath("documents"), "cookie_jar.txt"),
    filters: [
      { name: "Text Files", extensions: ["txt"] },
      { name: "All Files", extensions: ["*"] },
    ],
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    await fs.promises.writeFile(filePath, cookieJarText, "utf8");
    return { success: true };
  } catch (err) {
    console.error("Cookie jar save error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("get-valid-keys", async () => {
  // set valid keys array to the line by line contense of the src/data/valid-keys.txt file
  // ignoring blank lines and comments
  const validKeysPath = path.join(
    app.isPackaged ? process.resourcesPath : "src",
    "data",
    "valid-keys.txt",
  );
  if (!fs.existsSync(validKeysPath)) {
    console.warn(`Valid keys file not found at ${validKeysPath}`);
    return [];
  }
  const validKeysData = fs.readFileSync(validKeysPath, "utf8");
  const validKeys = validKeysData
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  return validKeys;
});

ipcMain.handle("invalidate-ollama-models-cache", () => {
  ollamaModelsCache = null;
  return true;
});

ipcMain.handle("get-ollama-models", async () => {
  if (ollamaModelsCache) {
    return ollamaModelsCache;
  }

  if (!appSettings) {
    await loadSettingsFromDisk();
  }
  const settings = getAppSettings();
  const apiKey = settings?.apiKeys?.ollamaApiKey;
  const hasApiKey = typeof apiKey === "string" && apiKey.trim();

  // 1. Try live ollama models first (returns [] if ollama is unavailable).
  const liveModels = await fetchLocalOllamaModels();

  // 2. Load JSON-backed models as a fallback / supplement.
  const diskModels = await loadOllamaModelsFromDisk();

  // 3. Merge: live models take priority; disk models fill gaps.
  const mergedByValue = new Map();
  for (const entry of liveModels) {
    mergedByValue.set(entry.value, entry);
  }
  for (const entry of diskModels) {
    if (!mergedByValue.has(entry.value)) {
      mergedByValue.set(entry.value, entry);
    }
  }

  let mergedModels = Array.from(mergedByValue.values());

  // 4. Filter out cloud models when no API key is configured.
  if (!hasApiKey) {
    mergedModels = mergedModels.filter((entry) => !isOllamaCloudModel(entry.value));
  }

  // 5. Ensure at least the default model is present.
  const models = mergedModels.length > 0
    ? mergedModels
    : normalizeOllamaModelsLibrary([
      { name: DEFAULT_SETTINGS.llm.ollamaModel, label: DEFAULT_SETTINGS.llm.ollamaModel },
    ]);

  ollamaModelsCache = models;
  return models;
});

ipcMain.handle("save-notes", async (_event, notesText) => {
  if (typeof notesText !== "string" || notesText.trim() === "") {
    return { success: false, error: "No notes data to save" };
  }

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Save Notes",
    defaultPath: path.join(app.getPath("documents"), "packetsnitch-notes.txt"),
    filters: [
      { name: "Text Files", extensions: ["txt"] },
      { name: "All Files", extensions: ["*"] },
    ],
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    await fs.promises.writeFile(filePath, notesText, "utf8");
    return { success: true };
  } catch (err) {
    console.error("Notes save error:", err);
    return { success: false, error: err.message };
  }
});

// Map a Content-Type header value to a file extension for HTTP body exports.
function extFromContentType(contentType) {
  const base = (contentType || "").split(";")[0].trim().toLowerCase();
  const map = {
    "text/html": "html",
    "text/plain": "txt",
    "text/css": "css",
    "text/csv": "csv",
    "text/xml": "xml",
    "application/javascript": "js",
    "application/x-javascript": "js",
    "text/javascript": "js",
    "application/json": "json",
    "application/xml": "xml",
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/svg+xml": "svg",
    "image/webp": "webp",
    "image/bmp": "bmp",
    "image/x-icon": "ico",
    "image/ico": "ico",
    "application/pdf": "pdf",
    "application/zip": "zip",
    "application/x-zip-compressed": "zip",
    "application/gzip": "gz",
    "application/x-gzip": "gz",
    "application/octet-stream": "bin",
  };
  return map[base] || "bin";
}

// Validate and decode a hex string into a Buffer; returns null on failure.
function hexToBuffer(hex) {
  if (typeof hex !== "string") return null;
  const normalized = hex.replace(/\s+/g, "");
  if (normalized.length === 0 || normalized.length % 2 !== 0) return null;
  if (!/^[\da-fA-F]+$/.test(normalized)) return null;
  return Buffer.from(normalized, "hex");
}

ipcMain.handle("save-http-body", async (_event, bodyHex, contentType) => {
  const buf = hexToBuffer(bodyHex);
  if (!buf) return { success: false, error: "Invalid HTTP body data" };

  const ext = extFromContentType(contentType);
  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Save HTTP Body",
    defaultPath: path.join(app.getPath("documents"), `http-body.${ext}`),
    filters: [
      { name: "HTTP Body", extensions: [ext] },
      { name: "All Files", extensions: ["*"] },
    ],
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    await fs.promises.writeFile(filePath, buf);
    return { success: true };
  } catch (err) {
    console.error("HTTP body save error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("preview-http-body", async (_event, bodyHex, contentType) => {
  const buf = hexToBuffer(bodyHex);
  if (!buf) return { success: false, error: "Invalid HTTP body data" };

  const ext = extFromContentType(contentType);
  try {
    // Use a unique temp directory per preview to avoid races and data leaks.
    const tmpDir = await fs.promises.mkdtemp(
      path.join(os.tmpdir(), "ps-preview-"),
    );
    const tmpFile = path.join(tmpDir, `http-preview.${ext}`);
    await fs.promises.writeFile(tmpFile, buf);
    const fileUrl = pathToFileURL(tmpFile).href;
    await shell.openExternal(fileUrl);
    // Schedule cleanup after a delay to give the browser time to read the file.
    setTimeout(() => {
      fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => { });
    }, 30000);
    return { success: true };
  } catch (err) {
    console.error("HTTP body preview error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("open-external-url", async (_event, rawUrl) => {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    return { success: false, error: "Invalid URL" };
  }
  try {
    const parsed = new URL(rawUrl.trim());
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:" && parsed.protocol !== "mailto:") {
      return { success: false, error: "Only HTTP/HTTPS/mailto URLs are supported" };
    }
    await shell.openExternal(parsed.href);
    return { success: true };
  } catch (err) {
    return { success: false, error: err?.message || "Invalid URL" };
  }
});

ipcMain.handle("get-linux-release-package-family", async () => {
  if (process.platform !== "linux") {
    return { success: true, family: "" };
  }

  const hasFile = (filePath) => {
    try {
      return fs.existsSync(filePath);
    } catch (_error) {
      return false;
    }
  };

  const readTextFile = (filePath) => {
    try {
      return fs.readFileSync(filePath, "utf8");
    } catch (_error) {
      return "";
    }
  };

  const parseOsRelease = (rawText) => {
    const parsed = {};
    String(rawText || "")
      .split(/\r?\n/)
      .forEach((line) => {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) return;
        const equalsIndex = trimmed.indexOf("=");
        if (equalsIndex <= 0) return;
        const key = trimmed.slice(0, equalsIndex).trim().toUpperCase();
        const valueRaw = trimmed.slice(equalsIndex + 1).trim();
        const unquoted = valueRaw.replace(/^"|"$/g, "").replace(/^'|'$/g, "");
        parsed[key] = unquoted.toLowerCase();
      });
    return parsed;
  };

  const osReleaseRaw = readTextFile("/etc/os-release");
  const osRelease = parseOsRelease(osReleaseRaw);
  const idTokens = [osRelease.ID || "", osRelease.ID_LIKE || "", osRelease.NAME || ""]
    .join(" ")
    .toLowerCase();

  const redhatLikeTokens = ["rhel", "redhat", "fedora", "centos", "rocky", "almalinux", "suse"];
  const debianLikeTokens = ["debian", "ubuntu", "kali", "mint", "pop", "raspbian"];

  const hasRedhatMarkerFile =
    hasFile("/etc/redhat-release")
    || hasFile("/etc/fedora-release")
    || hasFile("/etc/centos-release")
    || hasFile("/etc/almalinux-release")
    || hasFile("/etc/rocky-release")
    || hasFile("/etc/SuSE-release");
  const hasDebianMarkerFile = hasFile("/etc/debian_version");

  // Prefer explicit Fedora/RHEL markers when present.
  if (hasRedhatMarkerFile || redhatLikeTokens.some((token) => idTokens.includes(token))) {
    return { success: true, family: "redhat" };
  }
  if (hasDebianMarkerFile || debianLikeTokens.some((token) => idTokens.includes(token))) {
    return { success: true, family: "debian" };
  }

  return { success: true, family: "" };
});

ipcMain.handle("get-runtime-platform", async () => {
  return {
    success: true,
    platform: process.platform,
  };
});

ipcMain.handle("append-activity-log", async (_event, entry) => {
  const normalizedEntry = normalizeActivityLogEntry(entry);
  if (!normalizedEntry) {
    return { success: false, error: "Invalid log entry" };
  }
  // Renderer entries are already shown locally, so skip broadcasting them back.
  appendActivityLogLine(normalizedEntry, { broadcast: false });
  return { success: true, path: activityLogFilePath };
});

ipcMain.handle("get-activity-log-path", async () => {
  return activityLogFilePath;
});

ipcMain.handle("get-activity-log-entries", async () => {
  return [...activityLogEntries];
});

ipcMain.handle("settings-get", async () => {
  if (!appSettings) {
    await loadSettingsFromDisk();
  }
  return getAppSettings();
});

ipcMain.handle("settings-save", async (_event, settings) => {
  if (!appSettings) {
    await loadSettingsFromDisk();
  }
  const savedSettings = await saveSettingsToDisk(settings);
  void refreshOllamaCloudApiDiagnostics().then((cloudDiagnostics) => {
    logLlmDiagnostics("LLM cloud diagnostics", cloudDiagnostics);
  });
  return savedSettings;
});

ipcMain.handle("settings-update", async (_event, partialSettings) => {
  if (!appSettings) {
    await loadSettingsFromDisk();
  }
  const currentSettings = getAppSettings();
  const partialLlmSettings =
    partialSettings && typeof partialSettings === "object" && partialSettings.llm && typeof partialSettings.llm === "object"
      ? partialSettings.llm
      : {};
  const partialPrivacySettings =
    partialSettings && typeof partialSettings === "object" && partialSettings.privacy && typeof partialSettings.privacy === "object"
      ? partialSettings.privacy
      : {};
  // Deep-merge the privacy block too: a partial update that only
  // carries ``metricsInstallId`` (e.g. the metrics service writing
  // back its generated UUID) must not blow away the user's
  // ``metricsEnabled`` toggle or the custom ``metricsEndpointUrl``.
  const currentPrivacy = currentSettings?.privacy && typeof currentSettings.privacy === "object"
    ? currentSettings.privacy
    : {};
  const savedSettings = await saveSettingsToDisk({
    ...currentSettings,
    ...partialSettings,
    llm: {
      ...currentSettings.llm,
      ...partialLlmSettings,
    },
    privacy: {
      ...currentPrivacy,
      ...partialPrivacySettings,
    },
  });
  void refreshOllamaCloudApiDiagnostics().then((cloudDiagnostics) => {
    logLlmDiagnostics("LLM cloud diagnostics", cloudDiagnostics);
  });
  return savedSettings;
});

ipcMain.handle("themes-list", async () => {
  return listThemeDefinitions();
});

ipcMain.handle("themes-get", async (_event, themeId) => {
  return getThemeById(themeId);
});

ipcMain.handle("themes-directory", async () => {
  return ensureThemeFilesExist();
});

ipcMain.handle("saved-filters-list", async () => {
  return loadFilterLibraryFromDisk();
});

ipcMain.handle("saved-filters-save", async (_event, payload = {}) => {
  return upsertSavedFilter(payload?.label, payload?.query);
});

ipcMain.handle("saved-filters-remove", async (_event, payload = {}) => {
  return removeSavedFilterById(payload?.id);
});

ipcMain.handle("plugins-list", async () => {
  const registry = await loadPluginsRegistryFromDisk();
  if (!appSettings) {
    await loadSettingsFromDisk();
  }
  return {
    success: true,
    plugins: registry.plugins,
    settings: {
      autoDisableFailureThreshold: Math.max(
        1,
        Number(getAppSettings()?.plugins?.autoDisableFailureThreshold)
        || DEFAULT_SETTINGS.plugins.autoDisableFailureThreshold,
      ),
      perPluginFailureThreshold:
        getAppSettings()?.plugins?.perPluginFailureThreshold
          && typeof getAppSettings().plugins.perPluginFailureThreshold === "object"
          ? getAppSettings().plugins.perPluginFailureThreshold
          : {},
    },
  };
});

ipcMain.handle("plugins-install", async (_event, payload = {}) => {
  try {
    const zipPath = typeof payload?.zipPath === "string" ? payload.zipPath : "";
    if (!zipPath) {
      return { success: false, error: "Plugin zip path is required" };
    }
    const installedPlugin = await installPluginFromZip(zipPath);
    const registry = await loadPluginsRegistryFromDisk();
    const existingIndex = registry.plugins.findIndex(
      (entry) => entry.pluginId === installedPlugin.pluginId,
    );
    if (existingIndex >= 0) {
      registry.plugins[existingIndex] = {
        ...registry.plugins[existingIndex],
        ...installedPlugin,
      };
    } else {
      registry.plugins.push(installedPlugin);
    }
    const savedRegistry = await savePluginsRegistryToDisk(registry);
    appendActivityLogLine(
      `[${new Date().toISOString()}] [GUI][Plugin] Installed plugin id=${installedPlugin.pluginId} address=${installedPlugin.address}`,
    );
    return {
      success: true,
      plugin: installedPlugin,
      plugins: savedRegistry.plugins,
    };
  } catch (error) {
    appendActivityLogLine(
      `[${new Date().toISOString()}] [GUI][Plugin] Install failed error=${error?.message || error}`,
    );
    return {
      success: false,
      error: error?.message || "Plugin install failed",
    };
  }
});

ipcMain.handle("plugins-inspect-zip", async (_event, payload = {}) => {
  try {
    const zipPath = typeof payload?.zipPath === "string" ? payload.zipPath : "";
    if (!zipPath) {
      return { success: false, error: "Plugin zip path is required" };
    }
    const details = await inspectPluginZip(zipPath);
    return {
      success: true,
      plugin: details,
    };
  } catch (error) {
    return {
      success: false,
      error: error?.message || "Unable to inspect plugin zip",
    };
  }
});

ipcMain.handle("plugins-set-enabled", async (_event, payload = {}) => {
  const pluginId = sanitizePluginToken(payload?.pluginId || "", "");
  const enabled = Boolean(payload?.enabled);
  if (!pluginId) {
    return { success: false, error: "pluginId is required" };
  }
  const registry = await loadPluginsRegistryFromDisk();
  const pluginEntry = registry.plugins.find((entry) => entry.pluginId === pluginId);
  if (!pluginEntry) {
    return { success: false, error: "Plugin not found" };
  }
  pluginEntry.enabled = enabled;
  pluginEntry.disabledReason = enabled ? "" : (pluginEntry.disabledReason || "manual-disable");
  pluginEntry.updatedAt = new Date().toISOString();
  const savedRegistry = await savePluginsRegistryToDisk(registry);
  appendActivityLogLine(
    `[${new Date().toISOString()}] [GUI][Plugin] ${enabled ? "Enabled" : "Disabled"} plugin id=${pluginEntry.pluginId}`,
  );
  return { success: true, plugin: pluginEntry, plugins: savedRegistry.plugins };
});

ipcMain.handle("plugins-set-priority", async (_event, payload = {}) => {
  const pluginId = sanitizePluginToken(payload?.pluginId || "", "");
  const priority = Number.isFinite(Number(payload?.priority)) ? Number(payload.priority) : null;
  if (!pluginId || priority === null) {
    return { success: false, error: "pluginId and numeric priority are required" };
  }
  const registry = await loadPluginsRegistryFromDisk();
  const pluginEntry = registry.plugins.find((entry) => entry.pluginId === pluginId);
  if (!pluginEntry) {
    return { success: false, error: "Plugin not found" };
  }
  pluginEntry.priority = priority;
  pluginEntry.updatedAt = new Date().toISOString();
  const savedRegistry = await savePluginsRegistryToDisk(registry);
  return { success: true, plugin: pluginEntry, plugins: savedRegistry.plugins };
});

ipcMain.handle("plugins-set-failure-threshold", async (_event, payload = {}) => {
  const pluginId = sanitizePluginToken(payload?.pluginId || "", "");
  const override = payload?.failureThresholdOverride;
  if (!pluginId) {
    return { success: false, error: "pluginId is required" };
  }
  const registry = await loadPluginsRegistryFromDisk();
  const pluginEntry = registry.plugins.find((entry) => entry.pluginId === pluginId);
  if (!pluginEntry) {
    return { success: false, error: "Plugin not found" };
  }
  if (override === null || override === undefined || override === "") {
    pluginEntry.failureThresholdOverride = null;
  } else {
    const parsedOverride = Number(override);
    if (!Number.isFinite(parsedOverride) || parsedOverride < 1) {
      return { success: false, error: "failureThresholdOverride must be >= 1 or empty" };
    }
    pluginEntry.failureThresholdOverride = Math.floor(parsedOverride);
  }
  pluginEntry.updatedAt = new Date().toISOString();
  const savedRegistry = await savePluginsRegistryToDisk(registry);
  return { success: true, plugin: pluginEntry, plugins: savedRegistry.plugins };
});

ipcMain.handle("plugins-record-failure", async (_event, payload = {}) => {
  const pluginId = sanitizePluginToken(payload?.pluginId || "", "");
  const isCritical = payload?.critical !== false;
  if (!pluginId) {
    return { success: false, error: "pluginId is required" };
  }
  const registry = await loadPluginsRegistryFromDisk();
  const pluginEntry = registry.plugins.find((entry) => entry.pluginId === pluginId);
  if (!pluginEntry) {
    return { success: false, error: "Plugin not found" };
  }
  if (!isCritical) {
    return { success: true, plugin: pluginEntry, autoDisabled: false };
  }
  pluginEntry.failureCount = Math.max(0, Number(pluginEntry.failureCount) || 0) + 1;
  const threshold = resolvePluginFailureThreshold(pluginEntry, getAppSettings());
  let autoDisabled = false;
  if (pluginEntry.failureCount >= threshold) {
    pluginEntry.enabled = false;
    pluginEntry.disabledReason = "failure-threshold";
    autoDisabled = true;
  }
  pluginEntry.updatedAt = new Date().toISOString();
  await savePluginsRegistryToDisk(registry);
  appendActivityLogLine(
    `[${new Date().toISOString()}] [GUI][Plugin] Failure plugin=${pluginEntry.pluginId} count=${pluginEntry.failureCount} threshold=${threshold} autoDisabled=${autoDisabled ? "true" : "false"}`,
  );
  return {
    success: true,
    plugin: pluginEntry,
    autoDisabled,
    threshold,
  };
});

ipcMain.handle("plugins-reset-failures", async (_event, payload = {}) => {
  const pluginId = sanitizePluginToken(payload?.pluginId || "", "");
  if (!pluginId) {
    return { success: false, error: "pluginId is required" };
  }
  const registry = await loadPluginsRegistryFromDisk();
  const pluginEntry = registry.plugins.find((entry) => entry.pluginId === pluginId);
  if (!pluginEntry) {
    return { success: false, error: "Plugin not found" };
  }
  pluginEntry.failureCount = 0;
  if (pluginEntry.disabledReason === "failure-threshold") {
    pluginEntry.disabledReason = "";
  }
  pluginEntry.updatedAt = new Date().toISOString();
  const savedRegistry = await savePluginsRegistryToDisk(registry);
  return { success: true, plugin: pluginEntry, plugins: savedRegistry.plugins };
});

ipcMain.handle("plugins-uninstall", async (_event, payload = {}) => {
  const pluginId = sanitizePluginToken(payload?.pluginId || "", "");
  if (!pluginId) {
    return { success: false, error: "pluginId is required" };
  }
  const registry = await loadPluginsRegistryFromDisk();
  const pluginIndex = registry.plugins.findIndex((entry) => entry.pluginId === pluginId);
  if (pluginIndex < 0) {
    return { success: false, error: "Plugin not found" };
  }
  const pluginEntry = registry.plugins[pluginIndex];
  registry.plugins.splice(pluginIndex, 1);
  await savePluginsRegistryToDisk(registry);
  if (pluginEntry.packagePath) {
    await fs.promises.rm(pluginEntry.packagePath, { force: true }).catch(() => { });
  }
  if (pluginEntry.installPath) {
    await fs.promises.rm(pluginEntry.installPath, { recursive: true, force: true }).catch(() => { });
  }
  appendActivityLogLine(
    `[${new Date().toISOString()}] [GUI][Plugin] Uninstalled plugin id=${pluginEntry.pluginId}`,
  );
  return { success: true, removedPluginId: pluginId, plugins: registry.plugins };
});

// Session library helpers
function getSessionsDir() {
  return path.join(app.getPath("userData"), "sessions");
}

function getSessionLibraryCacheFilePath() {
  return path.join(app.getPath("userData"), SETTINGS_DIR_NAME, SESSION_LIBRARY_CACHE_FILE_NAME);
}

async function readSessionLibraryCache() {
  const filePath = getSessionLibraryCacheFilePath();
  try {
    const rawText = await fs.promises.readFile(filePath, "utf8");
    const parsed = JSON.parse(rawText);
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.sessions)) {
      return null;
    }
    const sessions = parsed.sessions.filter(
      (s) => s && typeof s === "object" && typeof s.name === "string" && s.name.trim(),
    );
    return {
      sessions,
      writtenAt: typeof parsed.writtenAt === "string" ? parsed.writtenAt : null,
    };
  } catch (error) {
    if (error && error.code !== "ENOENT") {
      console.warn("Failed to read session library cache:", error);
    }
    return null;
  }
}

async function writeSessionLibraryCache(sessions) {
  const filePath = getSessionLibraryCacheFilePath();
  try {
    await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
    await fs.promises.writeFile(
      filePath,
      JSON.stringify({ writtenAt: new Date().toISOString(), sessions }, null, 2) + os.EOL,
      "utf8",
    );
  } catch (error) {
    console.warn("Failed to write session library cache:", error);
  }
}

function sanitizeSessionName(name) {
  // Replace characters that are unsafe in filenames, collapse spaces
  return name
    .trim()
    .replace(/[/\\:*?"<>|]/g, "_")
    .replace(/\s+/g, " ")
    .slice(0, 128);
}

function sessionFilePath(name) {
  return path.join(getSessionsDir(), sanitizeSessionName(name) + ".json");
}

function sessionCompressedFilePath(name, compression = SESSION_COMPRESSION_XZ) {
  const base = path.join(getSessionsDir(), sanitizeSessionName(name));
  if (compression === SESSION_COMPRESSION_XZ) return base + ".pss";
  if (compression === SESSION_COMPRESSION_GZIP) return base + ".pss.gz";
  throw new Error(`Unsupported compression: ${compression}`);
}

function sessionBsonGzipFilePath(name) {
  return path.join(getSessionsDir(), sanitizeSessionName(name) + ".psb");
}

function sessionLegacyCompressedFilePath(name, compression = SESSION_COMPRESSION_XZ) {
  const base = path.join(getSessionsDir(), sanitizeSessionName(name) + ".json");
  if (compression === SESSION_COMPRESSION_XZ) return base + ".xz";
  if (compression === SESSION_COMPRESSION_GZIP) return base + ".gz";
  throw new Error(`Unsupported compression: ${compression}`);
}

async function fileExists(filePath) {
  try {
    await fs.promises.access(filePath);
    return true;
  } catch (_err) {
    return false;
  }
}

function createTaggedError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function getExistingCompressedSessionPath(name) {
  const bsonGzipPath = sessionBsonGzipFilePath(name);
  const xzPath = sessionCompressedFilePath(name, SESSION_COMPRESSION_XZ);
  const gzipPath = sessionCompressedFilePath(name, SESSION_COMPRESSION_GZIP);
  const legacyXzPath = sessionLegacyCompressedFilePath(
    name,
    SESSION_COMPRESSION_XZ,
  );
  const legacyGzipPath = sessionLegacyCompressedFilePath(
    name,
    SESSION_COMPRESSION_GZIP,
  );
  return Promise.all([
    fileExists(bsonGzipPath),
    fileExists(xzPath),
    fileExists(gzipPath),
    fileExists(legacyXzPath),
    fileExists(legacyGzipPath),
  ]).then(([hasBsonGzip, hasXz, hasGzip, hasLegacyXz, hasLegacyGzip]) => {
    if (hasBsonGzip) {
      return { compression: SESSION_FORMAT_BSON_GZIP, filePath: bsonGzipPath };
    }
    if (hasXz) {
      return { compression: SESSION_COMPRESSION_XZ, filePath: xzPath };
    }
    if (hasGzip) {
      return { compression: SESSION_COMPRESSION_GZIP, filePath: gzipPath };
    }
    if (hasLegacyXz) {
      return { compression: SESSION_COMPRESSION_XZ, filePath: legacyXzPath };
    }
    if (hasLegacyGzip) {
      return { compression: SESSION_COMPRESSION_GZIP, filePath: legacyGzipPath };
    }
    return null;
  });
}

/**
 * Returns SESSION_FORMAT_BSON_GZIP when the debug setting is on and the bson
 * module is available, otherwise falls through to the standard compression
 * selection path.  Callers that receive SESSION_FORMAT_BSON_GZIP should use
 * saveBsonGzipSession() directly instead of compressSessionJson().
 */
async function getPreferredSaveFormat() {
  if (appSettings?.debug?.bsonGzipSessionEnabled && BSON) {
    return SESSION_FORMAT_BSON_GZIP;
  }
  return getPreferredSaveCompression();
}

async function getPreferredSaveCompression() {
  if (
    lzmaNative &&
    typeof lzmaNative.compress === "function" &&
    typeof lzmaNative.decompress === "function"
  ) {
    return SESSION_COMPRESSION_XZ;
  }

  if (sessionCompressionFallbackAccepted === null) {
    const result = await dialog.showMessageBox(mainWindow || undefined, {
      type: "warning",
      title: "XZ Compression Unavailable",
      message:
        "PacketSnitch could not load Node xz compression support for session saves.",
      detail:
        "Use gzip compression instead? Session files will be saved as .pss.gz and still decompressed to .json on load.",
      buttons: ["Use gzip", "Cancel Save"],
      defaultId: 0,
      cancelId: 1,
      noLink: true,
    });
    sessionCompressionFallbackAccepted = result.response === 0;
  }

  if (!sessionCompressionFallbackAccepted) {
    throw createTaggedError(
      "COMPRESSION_FALLBACK_DECLINED",
      "Session save cancelled because gzip fallback was not accepted",
    );
  }

  return SESSION_COMPRESSION_GZIP;
}

function formatCompressionError(err, operation) {
  return `Unable to ${operation}: ${err?.message || "unknown error"}`;
}

function serializeSessionDocumentToBson(doc) {
  if (!BSON || typeof BSON.serialize !== "function") {
    throw new Error("bson module is unavailable");
  }

  const serializerOptions = {};
  if (typeof BSON.calculateObjectSize === "function") {
    try {
      const estimatedSize = BSON.calculateObjectSize(doc);
      if (Number.isFinite(estimatedSize) && estimatedSize > 0) {
        // Add headroom so near-boundary writes do not overflow BSON's
        // internal serialization buffer.
        serializerOptions.minInternalBufferSize = Math.max(
          1024 * 1024,
          estimatedSize + 64 * 1024,
        );
      }
    } catch (_sizeErr) {
      // If estimation fails, fall through to the serializer defaults.
    }
  }

  try {
    return BSON.serialize(doc, serializerOptions);
  } catch (err) {
    if (!serializerOptions.minInternalBufferSize) {
      throw err;
    }

    const retryOptions = {
      minInternalBufferSize: serializerOptions.minInternalBufferSize + 2 * 1024 * 1024,
    };
    return BSON.serialize(doc, retryOptions);
  }
}

/**
 * Serialise jsonData as BSON and gzip the result, writing to the .psb path.
 * Removes any legacy JSON/.pss/.pss.gz files for the same session name so the
 * library doesn't accumulate duplicate files.
 */
async function saveBsonGzipSession(name, jsonData) {
  if (!BSON) throw new Error("bson module is unavailable");
  const bsonPath = sessionBsonGzipFilePath(name);
  try {
    const doc = JSON.parse(jsonData);
    const bsonBuffer = serializeSessionDocumentToBson(doc);
    const compressedBuffer = await gzipAsync(bsonBuffer, { level: 9 });
    await fs.promises.writeFile(bsonPath, compressedBuffer);

    // Clean up older format files for the same session name
    for (const stale of [
      sessionFilePath(name),
      sessionCompressedFilePath(name, SESSION_COMPRESSION_XZ),
      sessionCompressedFilePath(name, SESSION_COMPRESSION_GZIP),
      sessionLegacyCompressedFilePath(name, SESSION_COMPRESSION_XZ),
      sessionLegacyCompressedFilePath(name, SESSION_COMPRESSION_GZIP),
    ]) {
      if (await fileExists(stale)) await fs.promises.unlink(stale);
    }
  } catch (err) {
    throw new Error(formatCompressionError(err, "save BSON session"));
  }
}


async function compressSessionJson(name, compression) {
  const jsonPath = sessionFilePath(name);
  const compressedPath = sessionCompressedFilePath(name, compression);
  const otherCompressedPath =
    compression === SESSION_COMPRESSION_XZ
      ? sessionCompressedFilePath(name, SESSION_COMPRESSION_GZIP)
      : sessionCompressedFilePath(name, SESSION_COMPRESSION_XZ);

  try {
    if (compression === SESSION_COMPRESSION_XZ && !lzmaNative) {
      throw new Error("Node xz compression support is unavailable");
    }

    const sourceBuffer = await fs.promises.readFile(jsonPath);
    const compressedBuffer =
      compression === SESSION_COMPRESSION_XZ
        ? await lzmaNative.compress(sourceBuffer, 6)
        : await gzipAsync(sourceBuffer, { level: 9 });

    await fs.promises.writeFile(compressedPath, compressedBuffer);
    if (await fileExists(otherCompressedPath)) {
      await fs.promises.unlink(otherCompressedPath);
    }
    const legacySameCompressionPath = sessionLegacyCompressedFilePath(
      name,
      compression,
    );
    if (await fileExists(legacySameCompressionPath)) {
      await fs.promises.unlink(legacySameCompressionPath);
    }
    await fs.promises.unlink(jsonPath);
  } catch (err) {
    throw new Error(formatCompressionError(err, "compress session"));
  }
}

async function resolveSessionFilePath(name) {
  const jsonPath = sessionFilePath(name);
  if (await fileExists(jsonPath)) {
    return { filePath: jsonPath, compression: null };
  }

  const compressedSource = await getExistingCompressedSessionPath(name);
  if (!compressedSource) {
    throw new Error("Session not found");
  }

  return compressedSource;
}

async function readSessionFileContent(filePath, compression) {
  if (!compression) {
    return fs.promises.readFile(filePath, "utf8");
  }

  if (compression === SESSION_FORMAT_BSON_GZIP) {
    if (!BSON) {
      throw new Error(
        "Cannot load BSON session (.psb) without the bson module",
      );
    }
    const compressedBuffer = await fs.promises.readFile(filePath);
    const bsonBuffer = await gunzipAsync(compressedBuffer);
    const doc = BSON.deserialize(bsonBuffer);
    return JSON.stringify(doc);
  }

  if (compression === SESSION_COMPRESSION_XZ && !lzmaNative) {
    throw new Error(
      "Cannot load xz-compressed session (.pss / legacy .json.xz) without Node xz compression support",
    );
  }

  const compressedBuffer = await fs.promises.readFile(filePath);
  const decompressedBuffer =
    compression === SESSION_COMPRESSION_XZ
      ? await lzmaNative.decompress(compressedBuffer)
      : await gunzipAsync(compressedBuffer);
  return decompressedBuffer.toString("utf8");
}

async function ensureSessionsDir() {
  const dir = getSessionsDir();
  try {
    await fs.promises.mkdir(dir, { recursive: true });
  } catch (err) {
    if (err.code !== "EEXIST") throw err;
  }
  return dir;
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

function normalizeSessionVersionValue(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function readSessionGeneratedByVersion(parsedPayload, sessionState) {
  const sessionStateVersionCandidates = [
    sessionState?.packetsnitchVersion,
    sessionState?.packetSnitchVersion,
    sessionState?.generatedByPacketSnitchVersion,
    sessionState?.generatedBy?.packetsnitchVersion,
    sessionState?.generatedBy?.packetSnitchVersion,
  ];
  for (const candidate of sessionStateVersionCandidates) {
    const normalized = normalizeSessionVersionValue(candidate);
    if (normalized) return normalized;
  }

  const rootVersionCandidates = [
    parsedPayload?.packetsnitchVersion,
    parsedPayload?.packetSnitchVersion,
    parsedPayload?.generatedByPacketSnitchVersion,
    parsedPayload?.generatedBy?.packetsnitchVersion,
    parsedPayload?.generatedBy?.packetSnitchVersion,
  ];
  for (const candidate of rootVersionCandidates) {
    const normalized = normalizeSessionVersionValue(candidate);
    if (normalized) return normalized;
  }

  return null;
}

function readSessionPcapSizeBytes(sessionState) {
  if (!sessionState || typeof sessionState !== "object") return null;
  const explicitByteLength = Number(sessionState?.sourcePcap?.byteLength);
  if (Number.isFinite(explicitByteLength) && explicitByteLength > 0) {
    return Math.floor(explicitByteLength);
  }
  const base64Data = sessionState?.sourcePcap?.data;
  const estimatedSize = estimateBase64DecodedByteLength(base64Data);
  return estimatedSize > 0 ? estimatedSize : null;
}

function inferSessionSaveType(filePath, compression) {
  if (compression === SESSION_FORMAT_BSON_GZIP) {
    return "BSON + gzip (.psb)";
  }
  if (compression === SESSION_COMPRESSION_XZ) {
    return filePath.endsWith(".json.xz")
      ? "JSON + xz (legacy .json.xz)"
      : "JSON + xz (.pss)";
  }
  if (compression === SESSION_COMPRESSION_GZIP) {
    return filePath.endsWith(".json.gz")
      ? "JSON + gzip (legacy .json.gz)"
      : "JSON + gzip (.pss.gz)";
  }
  if (filePath.endsWith(".json")) {
    return "JSON (.json)";
  }
  return "Unknown";
}

async function buildSessionList() {
  const dir = await ensureSessionsDir();
  const files = await fs.promises.readdir(dir);
  const sessions = [];
  const names = new Set();

  for (const file of files) {
    if (file.endsWith(".json")) {
      names.add(file.slice(0, -5));
    } else if (file.endsWith(".json.xz")) {
      names.add(file.slice(0, -8));
    } else if (file.endsWith(".json.gz")) {
      names.add(file.slice(0, -8));
    } else if (file.endsWith(".pss.gz")) {
      names.add(file.slice(0, -7));
    } else if (file.endsWith(".psb")) {
      names.add(file.slice(0, -4));
    } else if (file.endsWith(".pss")) {
      names.add(file.slice(0, -4));
    }
  }

  for (const name of names) {
    const jsonPath = path.join(dir, name + ".json");
    const bsonGzipPath = path.join(dir, name + ".psb");
    const compressedPath = path.join(dir, name + ".pss");
    const gzipPath = path.join(dir, name + ".pss.gz");
    const legacyXzPath = path.join(dir, name + ".json.xz");
    const legacyGzipPath = path.join(dir, name + ".json.gz");
    try {
      let savedAt = null;
      let filePath = compressedPath;
      let compression = SESSION_COMPRESSION_XZ;
      if (await fileExists(jsonPath)) {
        filePath = jsonPath;
        compression = null;
      } else if (await fileExists(bsonGzipPath)) {
        filePath = bsonGzipPath;
        compression = SESSION_FORMAT_BSON_GZIP;
      } else if (await fileExists(compressedPath)) {
        compression = SESSION_COMPRESSION_XZ;
      } else if (await fileExists(gzipPath)) {
        filePath = gzipPath;
        compression = SESSION_COMPRESSION_GZIP;
      } else if (await fileExists(legacyXzPath)) {
        filePath = legacyXzPath;
        compression = SESSION_COMPRESSION_XZ;
      } else if (await fileExists(legacyGzipPath)) {
        filePath = legacyGzipPath;
        compression = SESSION_COMPRESSION_GZIP;
      } else {
        continue;
      }

      const stats = await fs.promises.stat(filePath);
      if (stats?.mtime) {
        savedAt = stats.mtime.toISOString();
      }

      let packetsnitchVersion = null;
      let pcapSizeBytes = null;
      try {
        const content = await readSessionFileContent(filePath, compression);
        const parsedPayload = JSON.parse(content);
        const sessionState =
          parsedPayload && typeof parsedPayload === "object"
            && parsedPayload["session.state"]
            && typeof parsedPayload["session.state"] === "object"
            ? parsedPayload["session.state"]
            : null;

        const stateSavedAt =
          typeof sessionState?.savedAt === "string" ? sessionState.savedAt.trim() : "";
        if (stateSavedAt) {
          savedAt = stateSavedAt;
        }

        packetsnitchVersion = readSessionGeneratedByVersion(
          parsedPayload,
          sessionState,
        );
        pcapSizeBytes = readSessionPcapSizeBytes(sessionState);
      } catch (_metadataErr) {
        // Keep listing robust for older/corrupted saves that still have a file timestamp.
      }

      sessions.push({
        name,
        savedAt,
        filePath,
        saveType: inferSessionSaveType(filePath, compression),
        totalSizeBytes: Number.isFinite(stats?.size) ? stats.size : null,
        pcapSizeBytes,
        packetsnitchVersion,
      });
    } catch (_err) {
      // Skip files that cannot be read or parsed – they may be corrupted
    }
  }
  sessions.sort((a, b) => {
    if (!a.savedAt && !b.savedAt) return a.name.localeCompare(b.name);
    if (!a.savedAt) return 1;
    if (!b.savedAt) return -1;
    return b.savedAt.localeCompare(a.savedAt);
  });
  return sessions;
}

async function refreshSessionLibraryCacheAndNotify() {
  try {
    const sessions = await buildSessionList();
    await writeSessionLibraryCache(sessions);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("sessions-list-refreshed", {
        success: true,
        sessions,
      });
    }
    return { success: true, sessions };
  } catch (err) {
    console.error("refresh session library cache error:", err);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("sessions-list-refreshed", {
        success: false,
        error: err.message,
        sessions: [],
      });
    }
    return { success: false, error: err.message, sessions: [] };
  }
}

ipcMain.handle("sessions-list", async () => {
  try {
    const cache = await readSessionLibraryCache();
    // Kick off the authoritative scan asynchronously. The front end will
    // receive the refreshed list via "sessions-list-refreshed" and re-render.
    if (cache?.sessions?.length > 0) {
      refreshSessionLibraryCacheAndNotify();
      return { success: true, sessions: cache.sessions, fromCache: true };
    }

    // No cache available yet: fall back to a blocking full scan and write the
    // cache for the next startup.
    const sessions = await buildSessionList();
    await writeSessionLibraryCache(sessions);
    return { success: true, sessions, fromCache: false };
  } catch (err) {
    console.error("sessions-list error:", err);
    return { success: false, error: err.message, sessions: [] };
  }
});

ipcMain.handle("session-load", async (_event, name) => {
  if (typeof name !== "string" || !name.trim()) {
    return { success: false, error: "Invalid session name" };
  }
  try {
    const { filePath, compression } = await resolveSessionFilePath(name);
    const content = await readSessionFileContent(filePath, compression);
    return { success: true, data: content };
  } catch (err) {
    console.error("session-load error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("session-save", async (_event, name, jsonData) => {
  if (typeof name !== "string" || !name.trim()) {
    return { success: false, error: "Invalid session name" };
  }
  if (typeof jsonData !== "string" || jsonData.trim() === "") {
    return { success: false, error: "No JSON data to save" };
  }
  // if the name is "autosave" we should ask what the name should be since "autosave"
  // is a throwaway session
  // show the save dialog to get the new name from the user

  try {
    await ensureSessionsDir();
    const format = await getPreferredSaveFormat();
    if (format === SESSION_FORMAT_BSON_GZIP) {
      try {
        await saveBsonGzipSession(name, jsonData);
      } catch (bsonErr) {
        // Large/complex session payloads can exceed BSON serializer limits.
        // Fall back to the standard JSON session compression path instead of
        // failing the save entirely.
        console.warn(
          "session-save bson fallback triggered:",
          bsonErr?.message || bsonErr,
        );
        const fallbackCompression = await getPreferredSaveCompression();
        const filePath = sessionFilePath(name);
        await fs.promises.writeFile(filePath, jsonData, "utf8");
        await compressSessionJson(name, fallbackCompression);
      }
    } else {
      const filePath = sessionFilePath(name);
      await fs.promises.writeFile(filePath, jsonData, "utf8");
      await compressSessionJson(name, format);
    }
    writeSessionLibraryCache(await buildSessionList());
    return { success: true, name: sanitizeSessionName(name) };
  } catch (err) {
    if (err && err.code === "COMPRESSION_FALLBACK_DECLINED") {
      return { success: false, canceled: true, error: err.message };
    }
    console.error("session-save error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("session-rename", async (_event, oldName, newName) => {
  if (
    typeof oldName !== "string" ||
    !oldName.trim() ||
    typeof newName !== "string" ||
    !newName.trim()
  ) {
    return { success: false, error: "Invalid session name" };
  }
  const sanitizedNew = sanitizeSessionName(newName);
  if (!sanitizedNew) {
    return { success: false, error: "New name is invalid after sanitization" };
  }
  try {
    await ensureSessionsDir();
    const oldJsonPath = sessionFilePath(oldName);
    const oldBsonGzipPath = sessionBsonGzipFilePath(oldName);
    const oldXzPath = sessionCompressedFilePath(oldName, SESSION_COMPRESSION_XZ);
    const oldGzipPath = sessionCompressedFilePath(oldName, SESSION_COMPRESSION_GZIP);
    const newJsonPath = sessionFilePath(sanitizedNew);
    const newBsonGzipPath = sessionBsonGzipFilePath(sanitizedNew);
    const newXzPath = sessionCompressedFilePath(sanitizedNew, SESSION_COMPRESSION_XZ);
    const newGzipPath = sessionCompressedFilePath(
      sanitizedNew,
      SESSION_COMPRESSION_GZIP,
    );

    const oldJsonExists = await fileExists(oldJsonPath);
    const oldBsonGzipExists = await fileExists(oldBsonGzipPath);
    const oldXzExists = await fileExists(oldXzPath);
    const oldGzipExists = await fileExists(oldGzipPath);
    if (!oldJsonExists && !oldBsonGzipExists && !oldXzExists && !oldGzipExists) {
      return { success: false, error: "Session not found" };
    }

    if (
      (oldJsonPath !== newJsonPath && (await fileExists(newJsonPath))) ||
      (oldBsonGzipPath !== newBsonGzipPath && (await fileExists(newBsonGzipPath))) ||
      (oldXzPath !== newXzPath && (await fileExists(newXzPath))) ||
      (oldGzipPath !== newGzipPath && (await fileExists(newGzipPath)))
    ) {
      return { success: false, error: "A session with that name already exists" };
    }

    if (oldJsonExists && oldJsonPath !== newJsonPath) {
      await fs.promises.rename(oldJsonPath, newJsonPath);
    }
    if (oldBsonGzipExists && oldBsonGzipPath !== newBsonGzipPath) {
      await fs.promises.rename(oldBsonGzipPath, newBsonGzipPath);
    }
    if (oldXzExists && oldXzPath !== newXzPath) {
      await fs.promises.rename(oldXzPath, newXzPath);
    }
    if (oldGzipExists && oldGzipPath !== newGzipPath) {
      await fs.promises.rename(oldGzipPath, newGzipPath);
    }

    writeSessionLibraryCache(await buildSessionList());
    return { success: true, name: sanitizedNew };
  } catch (err) {
    console.error("session-rename error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("session-delete", async (_event, name) => {
  if (typeof name !== "string" || !name.trim()) {
    return { success: false, error: "Invalid session name" };
  }
  try {
    const jsonPath = sessionFilePath(name);
    const bsonGzipPath = sessionBsonGzipFilePath(name);
    const xzPath = sessionCompressedFilePath(name, SESSION_COMPRESSION_XZ);
    const gzipPath = sessionCompressedFilePath(name, SESSION_COMPRESSION_GZIP);
    const hasJson = await fileExists(jsonPath);
    const hasBsonGzip = await fileExists(bsonGzipPath);
    const hasXz = await fileExists(xzPath);
    const hasGzip = await fileExists(gzipPath);

    if (!hasJson && !hasBsonGzip && !hasXz && !hasGzip) {
      return { success: false, error: "Session not found" };
    }

    if (hasJson) {
      await fs.promises.unlink(jsonPath);
    }
    if (hasBsonGzip) {
      await fs.promises.unlink(bsonGzipPath);
    }
    if (hasXz) {
      await fs.promises.unlink(xzPath);
    }
    if (hasGzip) {
      await fs.promises.unlink(gzipPath);
    }

    writeSessionLibraryCache(await buildSessionList());
    return { success: true };
  } catch (err) {
    if (err.code === "ENOENT") {
      return { success: false, error: "Session not found" };
    }
    console.error("session-delete error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("get-new-session-template", async () => {
  try {
    const templatePath = path.join(
      app.isPackaged ? process.resourcesPath : path.join(__dirname, "../../src/data/"),
      "new_session.json",
    );
    const content = await fs.promises.readFile(templatePath, "utf8");
    return { success: true, data: content };
  } catch (err) {
    console.error("get-new-session-template error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("get-ui-fragment", async (_event, fragmentName) => {
  const allowedFragments = new Map([
    ["notes-box", "notes-box.html"],
    ["rightside-notes", "rightside-notes.html"],
  ]);

  try {
    const fragmentKey = String(fragmentName || "").trim();
    const fragmentFileName = allowedFragments.get(fragmentKey);
    if (!fragmentFileName) {
      return { success: false, error: "Unknown UI fragment" };
    }

    const fragmentPathCandidates = app.isPackaged
      ? [
        path.join(process.resourcesPath, "ui", "fragments", fragmentFileName),
        path.join(process.resourcesPath, "fragments", fragmentFileName),
        path.join(process.resourcesPath, fragmentFileName),
      ]
      : [path.join(__dirname, "../../src/ui/fragments", fragmentFileName)];
    const fragmentPath = fragmentPathCandidates.find((candidate) =>
      fs.existsSync(candidate),
    ) || fragmentPathCandidates[0];
    const content = await fs.promises.readFile(fragmentPath, "utf8");
    return { success: true, data: content };
  } catch (err) {
    console.error("get-ui-fragment error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("session-export", async (_event, name, jsonData) => {
  if (typeof jsonData !== "string" || jsonData.trim() === "") {
    return { success: false, error: "No JSON data to export" };
  }

  let format;
  try {
    format = await getPreferredSaveFormat();
  } catch (err) {
    if (err && err.code === "COMPRESSION_FALLBACK_DECLINED") {
      return { success: false, canceled: true, error: err.message };
    }
    return { success: false, error: err?.message || "Failed to choose save format" };
  }

  if (format === SESSION_FORMAT_BSON_GZIP) {
    const defaultSessionBaseName =
      typeof name === "string" && name.trim()
        ? sanitizeSessionName(name)
        : "packetsnitch-session";
    const bsonDefaultName = `${defaultSessionBaseName}.psb`;
    const { canceled, filePath } = await dialog.showSaveDialog({
      title: "Export PacketSnitch Session",
      defaultPath: path.join(app.getPath("documents"), bsonDefaultName),
      filters: [
        { name: "PacketSnitch BSON Session (PSB)", extensions: ["psb"] },
        { name: "PacketSnitch Session (PSS GZip)", extensions: ["pss.gz", "gz"] },
        { name: "PacketSnitch Session (PSS)", extensions: ["pss"] },
      ],
    });
    if (canceled || !filePath) return { success: false, canceled: true };
    try {
      const outputPath = filePath.endsWith(".psb") ? filePath : filePath + ".psb";
      const doc = JSON.parse(jsonData);
      const bsonBuffer = serializeSessionDocumentToBson(doc);
      const compressedBuffer = await gzipAsync(bsonBuffer, { level: 9 });
      await fs.promises.writeFile(outputPath, compressedBuffer);
      return { success: true };
    } catch (err) {
      console.warn(
        "session-export bson fallback triggered:",
        err?.message || err,
      );

      const fallbackCompression = await getPreferredSaveCompression();
      const fallbackOutputPath =
        fallbackCompression === SESSION_COMPRESSION_XZ
          ? (filePath.endsWith(".pss") ? filePath : `${filePath}.pss`)
          : (filePath.endsWith(".pss.gz") || filePath.endsWith(".gz")
            ? filePath
            : `${filePath}.pss.gz`);

      try {
        const sourceBuffer = Buffer.from(jsonData, "utf8");
        const compressedBuffer =
          fallbackCompression === SESSION_COMPRESSION_XZ
            ? await lzmaNative.compress(sourceBuffer, 6)
            : await gzipAsync(sourceBuffer, { level: 9 });
        await fs.promises.writeFile(fallbackOutputPath, compressedBuffer);
        return { success: true };
      } catch (fallbackErr) {
        console.error("session-export fallback error:", fallbackErr);
        return {
          success: false,
          error: fallbackErr?.message || err?.message || "Unable to export session",
        };
      }
    }
  }

  const compression = format;
  const defaultExtension =
    compression === SESSION_COMPRESSION_XZ ? "pss" : "pss.gz";
  const defaultName =
    typeof name === "string" && name.trim()
      ? sanitizeSessionName(name) + "." + defaultExtension
      : "packetsnitch-session." + defaultExtension;
  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Export PacketSnitch Session",
    defaultPath: path.join(app.getPath("documents"), defaultName),
    filters:
      compression === SESSION_COMPRESSION_XZ
        ? [
          { name: "PacketSnitch Session (PSS)", extensions: ["pss"] },
          { name: "PacketSnitch Session (PSS GZip)", extensions: ["pss.gz", "gz"] },
        ]
        : [
          { name: "PacketSnitch Session (PSS GZip)", extensions: ["pss.gz", "gz"] },
          { name: "PacketSnitch Session (PSS)", extensions: ["pss"] },
        ],
  });
  if (canceled || !filePath) return { success: false, canceled: true };
  try {
    const sourceBuffer = Buffer.from(jsonData, "utf8");
    const outputPath =
      filePath.endsWith(".pss")
        ? filePath
        : filePath.endsWith(".pss.gz") || filePath.endsWith(".gz")
          ? filePath
          : compression === SESSION_COMPRESSION_XZ
            ? filePath + ".pss"
            : filePath + ".pss.gz";

    const targetCompression =
      outputPath.endsWith(".pss")
        ? SESSION_COMPRESSION_XZ
        : SESSION_COMPRESSION_GZIP;

    if (targetCompression === SESSION_COMPRESSION_XZ && !lzmaNative) {
      return {
        success: false,
        error:
          "Cannot export as .pss because Node xz compression support is unavailable",
      };
    }

    const compressedBuffer =
      targetCompression === SESSION_COMPRESSION_XZ
        ? await lzmaNative.compress(sourceBuffer, 6)
        : await gzipAsync(sourceBuffer, { level: 9 });

    await fs.promises.writeFile(outputPath, compressedBuffer);
    return { success: true };
  } catch (err) {
    console.error("session-export error:", err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle("sessions-list-refresh", async () => {
  return refreshSessionLibraryCacheAndNotify();
});

app.on("before-quit", (event) => {
  if (!hasLoggedProgramShutdown) {
    appendActivityLogLine(
      timestampLifecycleMessage(
        `Program shutdown requested for PacketSnitch v${app.getVersion()}`,
      ),
      { broadcast: false },
    );
    hasLoggedProgramShutdown = true;
  }

  // Ask the backend service to stop gracefully during app exit, and wait
  // for the API request to finish before allowing Electron to terminate.
  if (!backCommModule || backendShutdownOnQuitComplete) {
    return;
  }

  event.preventDefault();
  if (backendShutdownOnQuitInProgress) {
    return;
  }

  backendShutdownOnQuitInProgress = true;
  const refreshPromise = refreshSessionLibraryCacheAndNotify().catch((err) =>
    console.error("Failed to refresh session library cache before quit:", err),
  );
  void shutdownBackendGracefullyForExit().finally(async () => {
    await refreshPromise;
    backendShutdownOnQuitInProgress = false;
    backendShutdownOnQuitComplete = true;
    app.quit();
  });
});

