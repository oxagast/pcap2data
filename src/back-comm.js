const { BrowserWindow, ipcMain } = require("electron");
const { spawn } = require("child_process");
const os = require("os");
const platform = os.platform();
const path = require("path");
const fs = require("fs");
const { promisify } = require("util");
const zlib = require("zlib");
const gunzipAsync = promisify(zlib.gunzip);
const systemTempDir = os.tmpdir();
const testcaseOutputDir = path.join(systemTempDir, "testcases");

const HOST_CHUNK_SIZE = 250;

function getMainWindow() {
  return BrowserWindow.getAllWindows()[0];
}

function sendError(message) {
  const mainWin = getMainWindow();
  if (mainWin) {
    mainWin.webContents.send("backend-error", message);
  }
}

function sendJsonPathPayload(payload) {
  const mainWin = getMainWindow();
  if (!mainWin) return;
  mainWin.webContents.send("json-path", payload);
}

function parseBridgeProgressLine(line) {
  if (!line || !line.includes("[Bridge]")) return null;
  const pathMatch = line.match(/path=([^\s]+)/);
  const processedMatch = line.match(/processed=(\d+)/);
  const totalMatch = line.match(/total=(\d+)/);
  const finalMatch = line.match(/final=(\d+)/);
  if (!pathMatch) return null;

  return {
    path: pathMatch[1],
    processedPackets: processedMatch ? Number(processedMatch[1]) : 0,
    totalPackets: totalMatch ? Number(totalMatch[1]) : 0,
    complete: finalMatch ? finalMatch[1] === "1" : false,
    chunkSize: HOST_CHUNK_SIZE,
  };
}

function scanChunkSnapshots(sentSnapshotPaths) {
  if (!fs.existsSync(testcaseOutputDir)) return [];
  const entries = fs
    .readdirSync(testcaseOutputDir)
    .filter((name) => /^hosts-\d+\.json$/.test(name))
    .sort((left, right) => {
      const leftCount = Number(left.match(/hosts-(\d+)\.json/)?.[1] || 0);
      const rightCount = Number(right.match(/hosts-(\d+)\.json/)?.[1] || 0);
      return leftCount - rightCount;
    });

  const unsent = [];
  entries.forEach((entryName) => {
    const fullPath = path.join(testcaseOutputDir, entryName);
    if (sentSnapshotPaths.has(fullPath)) return;
    sentSnapshotPaths.add(fullPath);
    const processedPackets = Number(entryName.match(/hosts-(\d+)\.json/)?.[1] || 0);
    unsent.push({
      path: fullPath,
      processedPackets,
      totalPackets: 0,
      complete: false,
      chunkSize: HOST_CHUNK_SIZE,
    });
  });

  return unsent;
}

ipcMain.handle("run-backend-command", async (event, filename, useLLM) => {
  global.logBackend(`[Bridge] Received pcap: ${filename}`);
  const isDev = !require("electron").app.isPackaged;
  const basePath = isDev
    ? path.join(__dirname, "../../src/backend/")
    : process.resourcesPath;
  const backendScriptPath = path.join(basePath, "snitch.py");
  let snitchExePath;
  if (platform === "win32") {
    snitchExePath = path.join(basePath, "\\snitch\\snitch.exe");
  } else if (platform === "linux") {
    snitchExePath = path.join(basePath, "/snitch/snitch");
  } else {
    snitchExePath = path.join(basePath, "/snitch/snitch");
  }

  const usePythonBackend = isDev && fs.existsSync(backendScriptPath);
  const backendCommandPath = usePythonBackend
    ? platform === "win32"
      ? "python"
      : "python3"
    : snitchExePath;

  if (usePythonBackend) {
    global.logBackend(`[Bridge] Using Python backend script at: ${backendScriptPath}`);
  } else if (fs.existsSync(snitchExePath)) {
    global.logBackend(`[Bridge] Found snitch executable at: ${snitchExePath}`);
  } else {
    global.logBackend(`[Bridge] Snitch executable not found at: ${snitchExePath}`);
    sendError(
      "[Bridge] Snitch executable not found! Please ensure it is included in the resources.",
    );
    return;
  }
  let isPCAP = false;
  let isSession = false;
  let isCompressedSession = false;
  let sessionCompression = null;
  // try to make a prelimienary determination of what type of file this is based on magic
  const fileForMagic = fs.readFileSync(filename, "binary", { encoding: "utf8" });
  if (fileForMagic.startsWith("{") && fileForMagic.endsWith("}")) {
    global.logBackend("[Bridge] File looks like a JSON file");
    if (fileForMagic.includes("hosts") && fileForMagic.includes("packets")) {
      global.logBackend("[Bridge] File looks like a PacketSnitch session file with hosts and packets!");
      isSession = true;
    }
  } else if (fileForMagic.startsWith("\xfd\x37\x7a\x58\x5a")) {
    global.logBackend("[Bridge] File looks like an xz-compressed file, this is probably a .pss session file!");
    isSession = true;
    isCompressedSession = true;
    sessionCompression = "xz";
  } else if (fileForMagic.startsWith("\x1f\x8b")) {
    global.logBackend("[Bridge] File looks like a gzip-compressed file, this is probably a .pss.gz session file!");
    isSession = true;
    isCompressedSession = true;
    sessionCompression = "gzip";
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
    if (!isSession) {
      global.logBackend("[Bridge] File does not appear to be a session file or a known pcap format?");
      sendError("[Bridge] File does not appear to be a session file or a known pcap format!");
    } else {
      let sessionJsonPath = filename;
      if (isCompressedSession) {
        try {
          const compressedBuffer = fs.readFileSync(filename);
          let decompressedBuffer;
          if (sessionCompression === "gzip") {
            decompressedBuffer = await gunzipAsync(compressedBuffer);
          } else {
            let lzmaNative = null;
            try { lzmaNative = require("lzma-native"); } catch { }
            if (!lzmaNative) {
              sendError("[Bridge] Cannot load xz-compressed session (.pss / .json.xz) without lzma-native support!");
              return "";
            }
            decompressedBuffer = await lzmaNative.decompress(compressedBuffer);
          }
          const tempPath = path.join(systemTempDir, `pss-session-${Date.now()}.json`);
          fs.writeFileSync(tempPath, decompressedBuffer);
          sessionJsonPath = tempPath;
          global.logBackend(`[Bridge] Decompressed session to temp file: ${tempPath}`);
        } catch (err) {
          sendError(`[Bridge] Failed to decompress session file: ${err.message}`);
          return "";
        }
      }
      sendJsonPathPayload({
        path: sessionJsonPath,
        processedPackets: 0,
        totalPackets: 0,
        complete: true,
        chunkSize: HOST_CHUNK_SIZE,
      });
    }
    return "";
  }

  const backendArgs = usePythonBackend
    ? [backendScriptPath, filename, "-v", "-a", "-o", testcaseOutputDir]
    : [filename, "-v", "-a", "-o", testcaseOutputDir];
  if (!useLLM) {
    backendArgs.push("--nollm");
  }
  // Always start with a clean output directory so snitch never hits the
  // interactive overwrite prompt on second (and later) runs.
  if (fs.existsSync(testcaseOutputDir)) {
    fs.rmSync(testcaseOutputDir, { recursive: true, force: true });
  }

  global.logBackend("[Bridge]", `${backendCommandPath} ${backendArgs.join(" ")}`);

  return new Promise((resolve) => {
    const sentSnapshotPaths = new Set();
    let stdoutBuffer = "";
    let stderrBuffer = "";
    let parsedTotalPackets = 0;
    let latestProcessedPackets = 0;
    const backendProc = spawn(backendCommandPath, backendArgs, {
      windowsHide: true,
    });

    const snapshotScanTimer = setInterval(() => {
      const snapshotPayloads = scanChunkSnapshots(sentSnapshotPaths);
      snapshotPayloads.forEach((payload) => {
        latestProcessedPackets = Math.max(
          latestProcessedPackets,
          payload.processedPackets,
        );
        payload.totalPackets = parsedTotalPackets;
        sendJsonPathPayload(payload);
      });
    }, 600);

    const handleProgressText = (text) => {
      if (!text) return;
      const progressPayload = parseBridgeProgressLine(text);
      if (progressPayload) {
        parsedTotalPackets = Math.max(
          parsedTotalPackets,
          progressPayload.totalPackets || 0,
        );
        latestProcessedPackets = Math.max(
          latestProcessedPackets,
          progressPayload.processedPackets || 0,
        );
        sentSnapshotPaths.add(progressPayload.path);
        sendJsonPathPayload(progressPayload);
        return;
      }

      const totalMatch = text.match(/Preparing to process\s+(\d+)/);
      if (totalMatch) {
        parsedTotalPackets = Number(totalMatch[1]);
      }
    };

    backendProc.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdoutBuffer += text;
      global.logBackend("", text);
      text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .forEach(handleProgressText);
    });

    backendProc.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      stderrBuffer += text;
      global.logBackend("", text);
      text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .forEach(handleProgressText);
    });

    backendProc.on("error", (error) => {
      clearInterval(snapshotScanTimer);
      sendError("[Bridge] Backend execution error! " + error);
      resolve(stdoutBuffer);
    });

    backendProc.on("close", (code) => {
      clearInterval(snapshotScanTimer);

      const trailingSnapshots = scanChunkSnapshots(sentSnapshotPaths);
      trailingSnapshots.forEach((payload) => {
        latestProcessedPackets = Math.max(
          latestProcessedPackets,
          payload.processedPackets,
        );
        payload.totalPackets = parsedTotalPackets;
        sendJsonPathPayload(payload);
      });

      if (stdoutBuffer.includes("Ollama")) {
        sendError("[Bridge] Backend LLM generation error!");
      }

      if (code !== 0) {
        if (stderrBuffer.includes("supported capture file")) {
          sendError("[Bridge] Unsupported file format!");
        } else {
          sendError(`[Bridge] Backend execution error! Exit code ${code}`);
        }
        resolve(stdoutBuffer);
        return;
      }

      const finalHostsPath = path.join(testcaseOutputDir, "hosts.json");
      if (fs.existsSync(finalHostsPath)) {
        sendJsonPathPayload({
          path: finalHostsPath,
          processedPackets: Math.max(latestProcessedPackets, parsedTotalPackets),
          totalPackets: parsedTotalPackets,
          complete: true,
          chunkSize: HOST_CHUNK_SIZE,
        });
      } else {
        sendError("[Bridge] hosts.json not found after backend execution!");
      }

      resolve(stdoutBuffer);
    });

    global.logBackend("[Bridge] Backend started");
  });
});
