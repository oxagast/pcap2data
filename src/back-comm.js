const { BrowserWindow, ipcMain } = require("electron");
const { exec } = require("child_process");
const os = require("os");
const platform = os.platform();
const path = require("path");
const fs = require("fs");
const systemTempDir = os.tmpdir();
const testcaseOutputDir = path.join(systemTempDir, "testcases");
ipcMain.handle("run-backend-command", async (event, filename, useLLM) => {
  global.logBackend(`[Bridge] Received pcap: ${filename}`);
  const isDev = !require("electron").app.isPackaged;
  const basePath = isDev
    ? path.join(__dirname, "../../src/backend/")
    : process.resourcesPath;
  let snitchExePath;

  if (platform === "win32") {
    snitchExePath = path.join(basePath, "\\snitch\\snitch.exe");
  } else if (platform === "linux") {
    snitchExePath = path.join(basePath, "/snitch/snitch");
  } else {
    snitchExePath = path.join(basePath, "/snitch/snitch");
  }

  if (fs.existsSync(snitchExePath)) {
    global.logBackend(`[Bridge] Found snitch executable at: ${snitchExePath}`);
  } else {
    global.logBackend(`[Bridge] Snitch executable not found at: ${snitchExePath}`);
    const mainWin = BrowserWindow.getAllWindows()[0];
    if (mainWin) {
      mainWin.webContents.send(
        "backend-error",
        "[Bridge] Snitch executable not found! Please ensure it is included in the resources.",
      );
    }
    return;
  }
  const backendCommand = `"${snitchExePath}" "${filename}" -v -a -o "${testcaseOutputDir}"${useLLM ? "" : " --nollm"}`;

  // Always start with a clean output directory so snitch never hits the
  // interactive overwrite prompt on second (and later) runs.
  if (fs.existsSync(testcaseOutputDir)) {
    fs.rmSync(testcaseOutputDir, { recursive: true, force: true });
  }

  global.logBackend("[Bridge]", backendCommand);

  function sendError(message) {
    const mainWin = BrowserWindow.getAllWindows()[0]; // or track your main window
    if (mainWin) {
      mainWin.webContents.send("backend-error", message);
    }
  }

  return new Promise((resolve) => {
    exec(
      backendCommand,
      { maxBuffer: 1024 * 1024 * 20 },
      (error, stdout, stderr) => {
        resolve(stdout);
        global.logBackend("", stdout);
        global.logBackend("", stderr);
        if (stdout.includes("Ollama")) {
          sendError("[Bridge] Backend LLM generation error!");
        }
        if (error) {
          if (stderr.includes("supported capture file")) {
            sendError("[Bridge] Unsupported file format!");
          } else {
            sendError("[Bridge] Backend execution error! " + error);
          }
        } else {
          const hostsJsonPath = path.join(testcaseOutputDir, "hosts.json");
          const mainWin = BrowserWindow.getAllWindows()[0];
          if (mainWin && fs.existsSync(hostsJsonPath)) {
            const hostsJsonData = fs.readFileSync(hostsJsonPath, "utf8");
            mainWin.webContents.send("json-data", hostsJsonData);
          }
        }
      },
    );

    global.logBackend("[Bridge] Backend started");
  });
});
