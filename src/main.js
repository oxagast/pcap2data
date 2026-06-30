const { app, BrowserWindow, ipcMain, dialog, shell } = require("electron");
const appLock = app.requestSingleInstanceLock();
const userAgent = `PacketSnitch v${app.getVersion()} (${process.platform}; ${process.arch})`;
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");
const { exec } = require("child_process");
const os = require("os");
const util = require("util");
const { gzip, gunzip } = require("zlib");
const { registerCaptureStoreHandlers } = require("./capture-store");
const { Ollama } = require("ollama");
const {
  DEFAULT_SETTINGS,
  normalizeSettings,
} = require("./settings");

let lzmaNative = null;
try {
  lzmaNative = require("lzma-native");
} catch (err) {
  console.warn("lzma-native is unavailable, session compression will require fallback", err);
}
const gzipAsync = util.promisify(gzip);
const gunzipAsync = util.promisify(gunzip);
const platform = os.platform();
const SESSION_COMPRESSION_XZ = "xz";
const SESSION_COMPRESSION_GZIP = "gzip";
const testcaseTempDir = path.join(os.tmpdir(), "testcases");
const CONSOLE_INSPECT_DEPTH = 6;
const CONSOLE_MAX_ARRAY_LENGTH = 50;
let mainWindow;
let selectedFilePath;
let isBackendLoaded = false;
let versionFilePath;
let activityLogFilePath;
let hasLoggedProgramShutdown = false;
const activityLogEntries = [];
const pendingActivityLogEntries = [];
let isFirstRunAfterInstall = false;
let cachedOllamaInstalled = false;
let sessionCompressionFallbackAccepted = null;
let goodiesDataCache = null;
let appSettings = null;
const SETTINGS_DIR_NAME = "config";
const SETTINGS_FILE_NAME = "settings.json";
const THEMES_DIR_NAME = "themes";
const THEME_FILE_EXTENSION = ".json";
const BUNDLED_THEMES_DIR_NAME = "themes";
const DEFAULT_THEME_DEFINITIONS = Object.freeze([
  {
    id: "snitchbitch",
    name: "SnitchBitch",
    description: "Original PacketSnitch look.",
    variables: {
      "--app-bg": "#333333",
      "--surface-0": "#000000",
      "--surface-1": "#111111",
      "--surface-2": "#000000",
      "--scrollbar-track": "#000000",
      "--border-strong": "#000000",
      "--color-1": "#7f80ff",
      "--color-2": "#2a284a",
      "--color-2-hover": "#201e3d",
      "--color-3": "#8a87c0",
      "--color-4": "#161a2b",
      "--color-5": "#ccbdde",
      "--color-6": "#b5b5b5",
      "--color-7": "#413f6e",
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
    if (!appSettings) {
      await loadSettingsFromDisk();
    }
    const settings = getAppSettings();
    const ollamaClient = settings.llm.ollamaApiKey
      ? new Ollama({
        headers: {
          Authorization: settings.llm.ollamaApiKey.startsWith("Bearer ")
            ? settings.llm.ollamaApiKey
            : `Bearer ${settings.llm.ollamaApiKey}`,
        },
      })
      : new Ollama();
    const response = await ollamaClient.generate({
      model: settings.llm.ollamaModel,
      prompt,
      options: {
        temperature: 0.5,
        num_predict: settings.llm.maxSummaryTokens,
      },
    });
    return response;
  } catch (error) {
    console.log("Error generating response from Ollama:", error);
    return;
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

// make sure we have a fresh temp dir
fs.rmSync(testcaseTempDir, { recursive: true, force: true });

// make a trigger so we can call killBackendProcess from the renderer process
ipcMain.handle("kill-snitch-process", () => {
  console.log("Received request to kill snitch process from renderer");
  killBackendProcess();
});

function killBackendProcess() {
  console.log("Shutting down preprocessor...");
  if (platform === "win32") {
    exec("taskkill /IM snitch.exe /T /F", (fileError) => {
      if (fileError) console.error(fileError);
    });
  }
  if (platform === "linux") {
    exec('pkill -f "testcases"', (fileError) => {
      if (fileError) console.error(fileError);
    });
  }
}

function checkOllama() {
  return new Promise((resolve) => {
    exec("ollama --version", (execError) => {
      if (execError) {
        resolve(false); // not installed or not in PATH
      } else {
        resolve(true);
      }
    });
  });
}


function getSettingsFilePath() {
  return path.join(app.getPath("userData"), SETTINGS_DIR_NAME, SETTINGS_FILE_NAME);
}

function getThemesDir() {
  return path.join(app.getPath("userData"), THEMES_DIR_NAME);
}

function getBundledThemesDir() {
  return path.join(app.getAppPath(), BUNDLED_THEMES_DIR_NAME);
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
  const logoImage = normalizeThemeLogoImage(rawTheme.logoImage);
  return {
    id,
    name,
    description,
    variables,
    logoImage,
    sourcePath: typeof metadata.sourcePath === "string" ? metadata.sourcePath : "",
    sourceKind: typeof metadata.sourceKind === "string" ? metadata.sourceKind : "unknown",
    sourceMtimeMs: Number.isFinite(metadata.sourceMtimeMs)
      ? metadata.sourceMtimeMs
      : 0,
  };
}

function normalizeThemeLogoImage(rawLogoImage) {
  if (!rawLogoImage || typeof rawLogoImage !== "object") {
    return null;
  }

  const rawFormat = typeof rawLogoImage.format === "string"
    ? rawLogoImage.format.trim().toLowerCase()
    : "";
  const normalizedFormat = rawFormat === "jpeg" ? "jpg" : rawFormat;
  if (normalizedFormat !== "png" && normalizedFormat !== "jpg") {
    return null;
  }

  const rawBase64 =
    typeof rawLogoImage.base64 === "string"
      ? rawLogoImage.base64
      : typeof rawLogoImage.data === "string"
        ? rawLogoImage.data
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
  const bundledThemesDir = getBundledThemesDir();
  try {
    const bundledThemes = await readThemeDefinitionsFromDir(bundledThemesDir);
    if (bundledThemes.length > 0) {
      return bundledThemes;
    }
  } catch {
    // Fallback to in-code defaults when bundled theme files are unavailable.
  }
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
  const bundledThemesDir = getBundledThemesDir();

  const userThemes = await readThemeDefinitionsFromDir(themesDir);
  userThemes.forEach((theme) => {
    theme.sourceKind = "user";
  });

  let bundledThemes = [];
  try {
    bundledThemes = await readThemeDefinitionsFromDir(bundledThemesDir);
    bundledThemes.forEach((theme) => {
      theme.sourceKind = "bundled";
    });
  } catch (error) {
    console.warn("Unable to read bundled theme definitions:", error);
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

    const mtimeReason = currentMtime === existingMtime
      ? "modification times are equal (preferring user theme when present)"
      : "it has the most recent modification time";

    themesById.set(theme.id, nextTheme);
  });

  const deduped = Array.from(themesById.values()).map((theme) => ({
    id: theme.id,
    name: theme.name,
    description: theme.description,
    variables: theme.variables,
    logoImage: theme.logoImage,
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
  await ensureSettingsFileExists(normalizedSettings);
  return normalizedSettings;
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
  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);
  mainWindow.webContents.on("did-finish-load", () => {
    mainWindow.webContents.setZoomFactor(0.7); // makes everything fit snuggly
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

      if ((hostname !== 'github.com' && hostname !== 'packetsnitch.oxasploits.com')) {
        if (!url.startsWith('https://github.com/oxasploits/packetsnitch/') && !url.startsWith('https://packetsnitch.oxasploits.com/')) {
          console.log(`Blocked navigation to external domain: ${url}`);
          event.preventDefault();
        }
      }
    });
    helpWinChild.removeMenu();
    helpWinChild.setSize(1000, 900);
    helpWinChild.webContents.setUserAgent(userAgent);
    helpWinChild.webContents.on('did-finish-load', () => {
      let helpPage = "";
      let helpURL = helpWinChild.webContents.getURL();
      // regex for matching the help page within the URL
      const helpPageRegex = /.*\/(.+?)\/$/;
      pageMatch = helpURL.match(helpPageRegex);
      if (helpURL.startsWith("https://packetsnitch.oxasploits.com/")) {
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
      if (helpPage === "packetsnitch.oxasploits.com") {
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
  checkOllama().then((isInstalled) => {
    cachedOllamaInstalled = isInstalled;
    void loadSettingsFromDisk();
    if (!isInstalled) {
      console.log(
        "Ollama is not installed. LLM summarisation will be unavailable.",
      );
    }
    createWindow();
    app.on("activate", function () {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
    console.log("App ready, waiting for file selection...");
    registerCaptureStoreHandlers(ipcMain);
    // start the process that listens for the file selection and runs the backend command
    require("./back-comm");
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
      isBackendLoaded = true;
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
  const filesToCheck = [
    {
      name: "PacketSnitch Backend (" + backendExe + ")",
      path: path.join(basePath, "snitch", backendExe),
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
  const installedFiles = filesToCheck.map((f) => ({
    name: f.name,
    path: f.path,
    exists: fs.existsSync(f.path),
  }));
  return {
    isFirstRun: isFirstRunAfterInstall,
    version: app.getVersion(),
    ollamaInstalled: cachedOllamaInstalled,
    installedFiles,
  };
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
  const currentSessionName = path.basename(selectedFilePath || "", path.extname(selectedFilePath || ""));
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

ipcMain.handle("save-payload", async (_event, payloadHex) => {
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

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Export Packet Payload",
    defaultPath: path.join(app.getPath("documents"), "packet-payload.bin"),
    filters: [
      { name: "Binary Files", extensions: ["bin"] },
      { name: "All Files", extensions: ["*"] },
    ],
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

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: dialogTitle,
    defaultPath: path.join(app.getPath("documents"), defaultName),
    filters: [
      { name: "Text Files", extensions: ["txt"] },
      { name: "All Files", extensions: ["*"] },
    ],
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
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { success: false, error: "Only HTTP/HTTPS URLs are supported" };
    }
    await shell.openExternal(parsed.href);
    return { success: true };
  } catch (err) {
    return { success: false, error: err?.message || "Invalid URL" };
  }
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
  return saveSettingsToDisk(settings);
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
  return saveSettingsToDisk({
    ...currentSettings,
    ...partialSettings,
    llm: {
      ...currentSettings.llm,
      ...partialLlmSettings,
    },
  });
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

// Session library helpers
function getSessionsDir() {
  return path.join(app.getPath("userData"), "sessions");
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
    fileExists(xzPath),
    fileExists(gzipPath),
    fileExists(legacyXzPath),
    fileExists(legacyGzipPath),
  ]).then(([hasXz, hasGzip, hasLegacyXz, hasLegacyGzip]) => {
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

async function ensureSessionJsonFile(name) {
  const jsonPath = sessionFilePath(name);
  if (await fileExists(jsonPath)) return jsonPath;

  const compressedSource = await getExistingCompressedSessionPath(name);
  if (!compressedSource) {
    throw new Error("Session not found");
  }

  try {
    if (compressedSource.compression === SESSION_COMPRESSION_XZ && !lzmaNative) {
      throw new Error(
        "Cannot load xz-compressed session (.pss / legacy .json.xz) without Node xz compression support",
      );
    }

    const compressedBuffer = await fs.promises.readFile(compressedSource.filePath);
    const decompressedBuffer =
      compressedSource.compression === SESSION_COMPRESSION_XZ
        ? await lzmaNative.decompress(compressedBuffer)
        : await gunzipAsync(compressedBuffer);

    await fs.promises.writeFile(jsonPath, decompressedBuffer);
  } catch (err) {
    throw new Error(formatCompressionError(err, "decompress session"));
  }

  if (!(await fileExists(jsonPath))) {
    throw new Error("Session decompression completed but JSON file was not created");
  }
  return jsonPath;
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

ipcMain.handle("sessions-list", async () => {
  try {
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
      } else if (file.endsWith(".pss")) {
        names.add(file.slice(0, -4));
      }
    }

    for (const name of names) {
      const jsonPath = path.join(dir, name + ".json");
      const compressedPath = path.join(dir, name + ".pss");
      const gzipPath = path.join(dir, name + ".pss.gz");
      const legacyXzPath = path.join(dir, name + ".json.xz");
      const legacyGzipPath = path.join(dir, name + ".json.gz");
      try {
        let savedAt = null;
        let filePath = compressedPath;
        if (await fileExists(jsonPath)) {
          const content = await fs.promises.readFile(jsonPath, "utf8");
          const parsed = JSON.parse(content);
          const sessionState = parsed["Session State"] || {};
          savedAt = sessionState.savedAt || null;
          filePath = jsonPath;
        } else if (await fileExists(compressedPath)) {
          const stats = await fs.promises.stat(compressedPath);
          if (stats?.mtime) {
            savedAt = stats.mtime.toISOString();
          }
        } else if (await fileExists(gzipPath)) {
          const stats = await fs.promises.stat(gzipPath);
          if (stats?.mtime) {
            savedAt = stats.mtime.toISOString();
          }
          filePath = gzipPath;
        } else if (await fileExists(legacyXzPath)) {
          const stats = await fs.promises.stat(legacyXzPath);
          if (stats?.mtime) {
            savedAt = stats.mtime.toISOString();
          }
          filePath = legacyXzPath;
        } else if (await fileExists(legacyGzipPath)) {
          const stats = await fs.promises.stat(legacyGzipPath);
          if (stats?.mtime) {
            savedAt = stats.mtime.toISOString();
          }
          filePath = legacyGzipPath;
        } else {
          continue;
        }

        sessions.push({
          name,
          savedAt,
          filePath,
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
    return { success: true, sessions };
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
    const compression = await getPreferredSaveCompression();
    const filePath = sessionFilePath(name);
    await fs.promises.writeFile(filePath, jsonData, "utf8");
    await compressSessionJson(name, compression);
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
    const oldXzPath = sessionCompressedFilePath(oldName, SESSION_COMPRESSION_XZ);
    const oldGzipPath = sessionCompressedFilePath(oldName, SESSION_COMPRESSION_GZIP);
    const newJsonPath = sessionFilePath(sanitizedNew);
    const newXzPath = sessionCompressedFilePath(sanitizedNew, SESSION_COMPRESSION_XZ);
    const newGzipPath = sessionCompressedFilePath(
      sanitizedNew,
      SESSION_COMPRESSION_GZIP,
    );

    const oldJsonExists = await fileExists(oldJsonPath);
    const oldXzExists = await fileExists(oldXzPath);
    const oldGzipExists = await fileExists(oldGzipPath);
    if (!oldJsonExists && !oldXzExists && !oldGzipExists) {
      return { success: false, error: "Session not found" };
    }

    if (
      (oldJsonPath !== newJsonPath && (await fileExists(newJsonPath))) ||
      (oldXzPath !== newXzPath && (await fileExists(newXzPath))) ||
      (oldGzipPath !== newGzipPath && (await fileExists(newGzipPath)))
    ) {
      return { success: false, error: "A session with that name already exists" };
    }

    if (oldJsonExists && oldJsonPath !== newJsonPath) {
      await fs.promises.rename(oldJsonPath, newJsonPath);
    }
    if (oldXzExists && oldXzPath !== newXzPath) {
      await fs.promises.rename(oldXzPath, newXzPath);
    }
    if (oldGzipExists && oldGzipPath !== newGzipPath) {
      await fs.promises.rename(oldGzipPath, newGzipPath);
    }

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
    const xzPath = sessionCompressedFilePath(name, SESSION_COMPRESSION_XZ);
    const gzipPath = sessionCompressedFilePath(name, SESSION_COMPRESSION_GZIP);
    const hasJson = await fileExists(jsonPath);
    const hasXz = await fileExists(xzPath);
    const hasGzip = await fileExists(gzipPath);

    if (!hasJson && !hasXz && !hasGzip) {
      return { success: false, error: "Session not found" };
    }

    if (hasJson) {
      await fs.promises.unlink(jsonPath);
    }
    if (hasXz) {
      await fs.promises.unlink(xzPath);
    }
    if (hasGzip) {
      await fs.promises.unlink(gzipPath);
    }

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

ipcMain.handle("session-export", async (_event, name, jsonData) => {
  if (typeof jsonData !== "string" || jsonData.trim() === "") {
    return { success: false, error: "No JSON data to export" };
  }

  let compression;
  try {
    compression = await getPreferredSaveCompression();
  } catch (err) {
    if (err && err.code === "COMPRESSION_FALLBACK_DECLINED") {
      return { success: false, canceled: true, error: err.message };
    }
    return { success: false, error: err?.message || "Failed to choose compression" };
  }

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

app.on("before-quit", () => {
  if (!hasLoggedProgramShutdown) {
    appendActivityLogLine(
      timestampLifecycleMessage(
        `Program shutdown requested for PacketSnitch v${app.getVersion()}`,
      ),
      { broadcast: false },
    );
    hasLoggedProgramShutdown = true;
  }
  // make sure the backend snitch process dies!
  if (isBackendLoaded) {
    killBackendProcess();
  }
});

