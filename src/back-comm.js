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
  let backendCommand;
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
  let isPCAP = false;
  // try to make a prelimienary determination of what type of file this is based on magic
  const fileForMagic = fs.readFileSync(filename, "binary", { encoding: "utf8" });
  if (fileForMagic.startsWith("{")) {
    if (fileForMagic.includes("hosts") && fileForMagic.includes("packets")) {
      global.logBackend("[Bridge] File looks like a session file with hosts and packets!");
    }
  } else if (fileForMagic.startsWith("\xd4\xc3\xb2\xa1")) {
    global.logBackend("[Bridge] File looks like PCAP file with microsecond resolution");
    isPCAP = true;
  } else if (fileForMagic.startsWith("\x0a\x0d\x0d\x0a")) {
    global.logBackend("[Bridge] File looks like PCAPNG file with a Section Header Block in little-endian byte order");
    isPCAP = true;
  } else if (fileForMagic.startsWith("\x50\x41\x43\x45\x54\x43\x4f\x4e\x46")) {
    global.logBackend("[Bridge] File looks like PCAPNG file with a Section Header Block");
    isPCAP = true;
  } else if (fileForMagic.startsWith("\x4d\x3c\x2b\x1a")) {
    global.logBackend("[Bridge] File looks like PCAP file with reversed byte order");
    isPCAP = true;
  } else if (fileForMagic.startsWith("\xc3\xd4\xa1\xb2")) {
    global.logBackend("[Bridge] File looks like PCAP file with reversed byte order and nanosecond resolution");
    isPCAP = true;
  } else {
    global.logBackend("[Bridge] File type is unknown based on magic (we will try to parse it anyway, but may fail!");
    isPCAP = true;
    // we can still try to parse it and see if snitch can make sense of it
    // , but it likely will fail and that's ok since snitch will report 
    // the error back to us and we can show that to the user
  }
  if (!isPCAP) {
    backendCommand = `echo "This appears to be a session file, passing off to frontend..."`; // dummy command that succeeds so it skips through
  } else {
    backendCommand = `"${snitchExePath}" "${filename}" -v -a -o "${testcaseOutputDir}"${useLLM ? "" : " --nollm"}`;
  }
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
    let hostsJsonPath;
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
          if (isPCAP) {
            hostsJsonPath = path.join(testcaseOutputDir, "hosts.json");
          } else {
            hostsJsonPath = filename;
          }
          const mainWin = BrowserWindow.getAllWindows()[0];
          if (mainWin && fs.existsSync(hostsJsonPath)) {
            const hostsJsonData = fs.readFileSync(hostsJsonPath, "utf8");
            mainWin.webContents.send("json-data", hostsJsonData);
          } else {
            sendError("[Bridge] hosts.json not found after backend execution!");
          }
        }
      },
    );

    global.logBackend("[Bridge] Backend started");
  });
});
