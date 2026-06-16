const { app, BrowserWindow, ipcMain, dialog, shell } = require("electron");
const appLock = app.requestSingleInstanceLock();
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");
const { exec } = require("child_process");
const os = require("os");
const util = require("util");
const platform = os.platform();
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

ipcMain.handle("file-size", async () => {
  try {
    // Get file stats asynchronously
    const fileStats = await fs.promises.stat(selectedFilePath); // Using promises version of stat
    return fileStats.size; // Send back the file size
  } catch (fileError) {
    console.error("Error getting file stats:", fileError);
    return 0; // Return 0 if there's an error
  }
});

// make sure we have a fresh temp dir
fs.rmSync(testcaseTempDir, { recursive: true, force: true });

function killBackendProcess() {
  console.log("Killing backend proc...");
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
  checkOllama().then((isInstalled) => {
    cachedOllamaInstalled = isInstalled;
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
    // start the process that listens for the file selection and runs the backend command
    require("./back-comm");
    ipcMain.handle("select-file", async () => {
      const { canceled, filePaths } = await dialog.showOpenDialog({
        properties: ["openFile"],
        filters: [
          {
            name: "Capture and Session Files",
            extensions: ["pcap", "pcapng", "json"],
          },
        ],
      });
      if (canceled) return null;
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
    for (const file of files) {
      if (!file.endsWith(".json")) continue;
      const filePath = path.join(dir, file);
      const name = file.slice(0, -5); // strip .json
      try {
        const content = await fs.promises.readFile(filePath, "utf8");
        const parsed = JSON.parse(content);
        const sessionState = parsed["Session State"] || {};
        sessions.push({
          name,
          savedAt: sessionState.savedAt || null,
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
    const filePath = sessionFilePath(name);
    const content = await fs.promises.readFile(filePath, "utf8");
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
    const filePath = sessionFilePath(name);
    await fs.promises.writeFile(filePath, jsonData, "utf8");
    return { success: true, name: sanitizeSessionName(name) };
  } catch (err) {
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
    const oldPath = sessionFilePath(oldName);
    const newPath = sessionFilePath(sanitizedNew);
    // Check source exists
    try {
      await fs.promises.access(oldPath);
    } catch (_e) {
      return { success: false, error: "Session not found" };
    }
    // Check destination doesn't already exist (skip if same path)
    if (oldPath !== newPath) {
      try {
        await fs.promises.access(newPath);
        return { success: false, error: "A session with that name already exists" };
      } catch (_e) {
        // Destination does not exist – safe to rename
      }
    }
    await fs.promises.rename(oldPath, newPath);
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
    const filePath = sessionFilePath(name);
    await fs.promises.unlink(filePath);
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
  const defaultName =
    typeof name === "string" && name.trim()
      ? sanitizeSessionName(name) + ".json"
      : "packetsnitch-session.json";
  const { canceled, filePath } = await dialog.showSaveDialog({
    title: "Export PacketSnitch Session",
    defaultPath: path.join(app.getPath("documents"), defaultName),
    filters: [{ name: "JSON Files", extensions: ["json"] }],
  });
  if (canceled || !filePath) return { success: false, canceled: true };
  try {
    await fs.promises.writeFile(filePath, jsonData, "utf8");
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

