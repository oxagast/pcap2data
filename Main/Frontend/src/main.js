const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { exec } = require('child_process');
const os = require('os');
const util = require('util');
const platform = os.platform();
const testcaseTempDir = path.join(os.tmpdir(), 'testcases');
const CONSOLE_INSPECT_DEPTH = 6;
const CONSOLE_MAX_ARRAY_LENGTH = 50;
let mainWindow;
let selectedFilePath;
let isBackendLoaded = false;
let versionFilePath;
let activityLogFilePath;
const activityLogEntries = [];
const pendingActivityLogEntries = [];
let isFirstRunAfterInstall = false;
let cachedOllamaInstalled = false;
if (require('electron-squirrel-startup')) {
  app.quit();
}

ipcMain.handle('file-size', async () => {
  try {
    // Get file stats asynchronously
    const fileStats = await fs.promises.stat(selectedFilePath); // Using promises version of stat
    return fileStats.size; // Send back the file size
  } catch (fileError) {
    console.error('Error getting file stats:', fileError);
    return 0; // Return 0 if there's an error
  }
});

// make sure we have a fresh temp dir
fs.rmSync(testcaseTempDir, { recursive: true, force: true });

function killBackendProcess() {
  console.log('Killing backend proc...');
  if (platform === 'win32') {
    exec('taskkill /IM snitch.exe /T /F', (fileError) => {
      if (fileError) console.error(fileError);
    });
  }
  if (platform === 'linux') {
    exec('pkill -f "testcases"', (fileError) => {
      if (fileError) console.error(fileError);
    });
  }
}

function checkOllama() {
  return new Promise((resolve) => {
    exec('ollama --version', (execError) => {
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
    const storedVersion = fs.readFileSync(versionFilePath, 'utf8').trim();
    return storedVersion !== app.getVersion();
  } catch (err) {
    console.error('Error checking install version:', err);
    return true;
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    minWidth: 1450,
    minHeight: 750,
    frame: false,
    webPreferences: {
      preload: MAIN_WINDOW_PRELOAD_WEBPACK_ENTRY,
      contextIsolation: true,
      nodeIntegration: true,
    },
  });
  mainWindow.loadURL(MAIN_WINDOW_WEBPACK_ENTRY);
  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.setZoomFactor(0.8); // makes everything fit snuggly
  });
}

function formatConsoleArgs(args) {
  return args
    .map((arg) => {
      if (arg instanceof Error) {
        return arg.stack || arg.message;
      }
      if (typeof arg === 'string') {
        return arg;
      }
      return util.inspect(arg, {
        depth: CONSOLE_INSPECT_DEPTH,
        breakLength: Infinity,
        maxArrayLength: CONSOLE_MAX_ARRAY_LENGTH,
      });
    })
    .join(' ');
}

function appendActivityLogToFile(entry) {
  try {
    fs.appendFileSync(activityLogFilePath, entry + os.EOL, 'utf8');
  } catch (error) {
    console.error('Unable to append activity log:', error);
  }
}

function cacheActivityLogEntry(entry) {
  activityLogEntries.unshift(entry);
}

function broadcastActivityLogEntry(entry) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('activity-log-entry', entry);
  }
}

function normalizeActivityLogEntry(entry) {
  if (typeof entry !== 'string' || entry.trim() === '') return null;
  return entry.trim();
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
  appendActivityLogLine(
    `[${new Date().toISOString()}] [Console][Backend] ${message}`,
  );
};

app.whenReady().then(() => {
  versionFilePath = path.join(app.getPath('userData'), 'installed_version.txt');
  activityLogFilePath = path.join(app.getPath('userData'), 'activity-log.txt');
  flushPendingActivityLogEntries();
  appendActivityLogLine(
    `[${new Date().toISOString()}] Session started for PacketSnitch v${app.getVersion()}`,
  );
  isFirstRunAfterInstall = checkNewInstall();
  checkOllama().then((isInstalled) => {
    cachedOllamaInstalled = isInstalled;
    if (!isInstalled) {
      console.log(
        'Ollama is not installed. LLM summarisation will be unavailable.',
      );
    }
    createWindow();
    app.on('activate', function () {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
    console.log('App ready, waiting for file selection...');
    // start the process that listens for the file selection and runs the backend command
    require('./back-comm');
    ipcMain.handle('select-file', async () => {
      const { canceled, filePaths } = await dialog.showOpenDialog({
        properties: ['openFile'],
      });
      if (canceled) return null;
      console.log('Accepted pcapng.. Checking for json existence...');
      isBackendLoaded = true;
      // Remove stale output directory so snitch always starts with a clean slate
      if (fs.existsSync(testcaseTempDir)) {
        fs.rmSync(testcaseTempDir, { recursive: true, force: true });
      }
      console.log('File selected:', filePaths[0]);
      selectedFilePath = filePaths[0];
      return filePaths[0];
    });
  });
});

ipcMain.handle('check-first-run', async () => {
  const isDev = !app.isPackaged;
  const basePath = isDev
    ? path.join(__dirname, '../..')
    : process.resourcesPath;
  const backendExe = platform === 'win32' ? 'snitch.exe' : 'snitch';
  const filesToCheck = [
    {
      name: 'PacketSnitch Backend (' + backendExe + ')',
      path: path.join(basePath, 'backend', backendExe),
    },
    {
      name: 'GeoIP Database (GeoLite2-City.mmdb)',
      path: path.join(basePath, 'backend', 'common', 'GeoLite2-City.mmdb'),
    },
    {
      name: 'MAC Vendors Database (mac-vendors-export.csv)',
      path: path.join(basePath, 'backend', 'common', 'mac-vendors-export.csv'),
    },
    {
      name: 'Services Database (service-names-port-numbers.csv)',
      path: path.join(
        basePath,
        'backend',
        'common',
        'service-names-port-numbers.csv',
      ),
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

ipcMain.handle('dismiss-first-run', async () => {
  const currentVersion = app.getVersion();
  try {
    fs.writeFileSync(versionFilePath, currentVersion, 'utf8');
    isFirstRunAfterInstall = false;
    return { success: true };
  } catch (err) {
    console.error('Failed to write version file:', err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('quit-app', () => {
  app.quit();
});

ipcMain.handle('prompt-save-session-on-exit', async () => {
  const response = await dialog.showMessageBox({
    type: 'question',
    buttons: ['Save Session', "Don't Save", 'Cancel'],
    defaultId: 0,
    cancelId: 2,
    title: 'Save Session',
    message: 'Do you want to save your PacketSnitch session before exiting?',
  });
  if (response.response === 0) return 'save';
  if (response.response === 1) return 'discard';
  return 'cancel';
});

ipcMain.handle('save-json', async (_event, jsonData) => {
  if (typeof jsonData !== 'string' || jsonData.trim() === '') {
    return { success: false, error: 'No JSON data to save' };
  }

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: 'Save PacketSnitch Session',
    defaultPath: path.join(app.getPath('documents'), 'packetsnitch-session.json'),
    filters: [{ name: 'JSON Files', extensions: ['json'] }],
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    await fs.promises.writeFile(filePath, jsonData, 'utf8');
    return { success: true };
  } catch (err) {
    console.error('Save error:', err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('save-packet', async (_event, packetData) => {
  if (packetData === null || packetData === undefined) {
    return { success: false, error: 'No packet data to save' };
  }
  const packetJson = JSON.stringify(packetData, null, 2);

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: 'Export Packet',
    defaultPath: path.join(app.getPath('documents'), 'packet.json'),
    filters: [{ name: 'JSON Files', extensions: ['json'] }],
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    await fs.promises.writeFile(filePath, packetJson, 'utf8');
    return { success: true };
  } catch (err) {
    console.error('Packet export error:', err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('save-payload', async (_event, payloadHex) => {
  if (typeof payloadHex !== 'string') {
    return { success: false, error: 'No payload data to save' };
  }
  const normalizedHex = payloadHex.replace(/\s+/g, '');
  if (
    normalizedHex.length === 0 ||
    normalizedHex.length % 2 !== 0 ||
    !/^[\da-fA-F]+$/.test(normalizedHex)
  ) {
    return {
      success: false,
      error: 'Payload must be a non-empty hex string with an even length',
    };
  }

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: 'Export Packet Payload',
    defaultPath: path.join(app.getPath('documents'), 'packet-payload.bin'),
    filters: [
      { name: 'Binary Files', extensions: ['bin'] },
      { name: 'All Files', extensions: ['*'] },
    ],
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    const payloadBuffer = Buffer.from(normalizedHex, 'hex');
    await fs.promises.writeFile(filePath, payloadBuffer);
    return { success: true };
  } catch (err) {
    console.error('Payload export error:', err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('save-cookie-jar', async (_event, cookieJarText) => {
  if (typeof cookieJarText !== 'string' || cookieJarText.trim() === '') {
    return { success: false, error: 'No cookie jar data to save' };
  }

  const { canceled, filePath } = await dialog.showSaveDialog({
    title: 'Save Cookie Jar',
    defaultPath: path.join(app.getPath('documents'), 'cookie_jar.txt'),
    filters: [
      { name: 'Text Files', extensions: ['txt'] },
      { name: 'All Files', extensions: ['*'] },
    ],
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    await fs.promises.writeFile(filePath, cookieJarText, 'utf8');
    return { success: true };
  } catch (err) {
    console.error('Cookie jar save error:', err);
    return { success: false, error: err.message };
  }
});

// Map a Content-Type header value to a file extension for HTTP body exports.
function extFromContentType(contentType) {
  const base = (contentType || '').split(';')[0].trim().toLowerCase();
  const map = {
    'text/html': 'html',
    'text/plain': 'txt',
    'text/css': 'css',
    'text/csv': 'csv',
    'text/xml': 'xml',
    'application/javascript': 'js',
    'application/x-javascript': 'js',
    'text/javascript': 'js',
    'application/json': 'json',
    'application/xml': 'xml',
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/svg+xml': 'svg',
    'image/webp': 'webp',
    'image/bmp': 'bmp',
    'image/x-icon': 'ico',
    'image/ico': 'ico',
    'application/pdf': 'pdf',
    'application/zip': 'zip',
    'application/x-zip-compressed': 'zip',
    'application/gzip': 'gz',
    'application/x-gzip': 'gz',
    'application/octet-stream': 'bin',
  };
  return map[base] || 'bin';
}

// Validate and decode a hex string into a Buffer; returns null on failure.
function hexToBuffer(hex) {
  if (typeof hex !== 'string') return null;
  const normalized = hex.replace(/\s+/g, '');
  if (normalized.length === 0 || normalized.length % 2 !== 0) return null;
  if (!/^[\da-fA-F]+$/.test(normalized)) return null;
  return Buffer.from(normalized, 'hex');
}

ipcMain.handle('save-http-body', async (_event, bodyHex, contentType) => {
  const buf = hexToBuffer(bodyHex);
  if (!buf) return { success: false, error: 'Invalid HTTP body data' };

  const ext = extFromContentType(contentType);
  const { canceled, filePath } = await dialog.showSaveDialog({
    title: 'Save HTTP Body',
    defaultPath: path.join(app.getPath('documents'), `http-body.${ext}`),
    filters: [
      { name: 'HTTP Body', extensions: [ext] },
      { name: 'All Files', extensions: ['*'] },
    ],
  });
  if (canceled || !filePath) return { success: false, canceled: true };

  try {
    await fs.promises.writeFile(filePath, buf);
    return { success: true };
  } catch (err) {
    console.error('HTTP body save error:', err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('preview-http-body', async (_event, bodyHex, contentType) => {
  const buf = hexToBuffer(bodyHex);
  if (!buf) return { success: false, error: 'Invalid HTTP body data' };

  const ext = extFromContentType(contentType);
  try {
    // Use a unique temp directory per preview to avoid races and data leaks.
    const tmpDir = await fs.promises.mkdtemp(
      path.join(os.tmpdir(), 'ps-preview-'),
    );
    const tmpFile = path.join(tmpDir, `http-preview.${ext}`);
    await fs.promises.writeFile(tmpFile, buf);
    const fileUrl = pathToFileURL(tmpFile).href;
    await shell.openExternal(fileUrl);
    // Schedule cleanup after a delay to give the browser time to read the file.
    setTimeout(() => {
      fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }, 30000);
    return { success: true };
  } catch (err) {
    console.error('HTTP body preview error:', err);
    return { success: false, error: err.message };
  }
});

ipcMain.handle('append-activity-log', async (_event, entry) => {
  const normalizedEntry = normalizeActivityLogEntry(entry);
  if (!normalizedEntry) {
    return { success: false, error: 'Invalid log entry' };
  }
  // Renderer entries are already shown locally, so skip broadcasting them back.
  appendActivityLogLine(normalizedEntry, { broadcast: false });
  return { success: true, path: activityLogFilePath };
});

ipcMain.handle('get-activity-log-path', async () => {
  return activityLogFilePath;
});

ipcMain.handle('get-activity-log-entries', async () => {
  return [...activityLogEntries];
});

app.on('before-quit', () => {
  // make sure the backend snitch process dies!
  if (isBackendLoaded) {
    killBackendProcess();
  }
});
