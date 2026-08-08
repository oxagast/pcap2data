// Talks to the backend service/process and normalizes capture-processing IPC flows.

const { app, BrowserWindow, ipcMain } = require("electron");
const { spawn, execFile } = require("child_process");
const http = require("http");
const os = require("os");
const platform = os.platform();
const path = require("path");
const fs = require("fs");
const { promisify } = require("util");
const execFileAsync = promisify(execFile);
const zlib = require("zlib");
const gunzipAsync = promisify(zlib.gunzip);
const systemTempDir = os.tmpdir();
const testcaseOutputDir = path.join(systemTempDir, "testcases");
let BSON = null;
try { BSON = require("bson"); } catch { }
let entries = [];

const DEFAULT_HOST_CHUNK_SIZE = 250;
const VALID_HOST_CHUNK_SIZES = new Set([25, 100, 250, 500, 2000]);
const DEFAULT_JSON_DATA_EMIT_MIN_INTERVAL_MS = 800;
const JSON_DATA_EMIT_MIN_PACKET_DELTA = 2000;
const BACKEND_HTTP_HOST = "127.0.0.1";
const BACKEND_HTTP_PORT = 9020;
const BACKEND_HTTP_READY_TIMEOUT_MS = 4000;
const BACKEND_HTTP_REQUEST_TIMEOUT_MS = 15 * 60 * 1000;
// Startup reclaim: when the GUI launches, look for an already-running backend
// on the configured HTTP port and try to shut it down gracefully before falling
// back to a hard kill.
const STARTUP_RECLAIM_GRACEFUL_TIMEOUT_MS = 5000;
const STARTUP_RECLAIM_PORT_POLL_INTERVAL_MS = 150;
const STARTUP_RECLAIM_KILL_TIMEOUT_MS = 4000;
const PACKETSNITCH_USER_AGENT =
  `Mozilla/5.0 (compatible; PacketSnitch/${app.getVersion()}; +http://packetsnitch.com)`;

function buildSnitchHttpHeaders(extraHeaders = {}) {
  return {
    "User-Agent": PACKETSNITCH_USER_AGENT,
    ...extraHeaders,
  };
}

let backendHttpServerProc = null;
let backendHttpReadyPromise = null;
let currentBackendHttpHost = BACKEND_HTTP_HOST;
let currentBackendHttpPort = BACKEND_HTTP_PORT;
let backendHttpShutdownExpected = false;
let backendHttpRespawnAttempts = 0;
let backendHttpRespawnTimer = null;
const pendingJsonDataPayloadByJob = new Map();
const jsonDataEmitTimerByJob = new Map();
const lastJsonDataEmitAtMsByJob = new Map();
const lastJsonDataEmitProcessedPacketsByJob = new Map();
let currentJsonDataEmitMinIntervalMs = DEFAULT_JSON_DATA_EMIT_MIN_INTERVAL_MS;
const bridgeProgressLogStateByKey = new Map();
let activeBackendRunCount = 0;

function normalizeBackendJobId(jobId) {
  const normalized = String(jobId || "").trim();
  return normalized || "";
}

function getBackendJobMapKey(jobId) {
  const normalized = normalizeBackendJobId(jobId);
  return normalized || "__default_job__";
}

function createBackendJobId(prefix = "job") {
  const safePrefix = String(prefix || "job").trim() || "job";
  return `${safePrefix}-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

function shouldLogBridgeProgress(kind, processedPackets, totalPackets, complete, jobId = "") {
  const kindKey = kind === "json-path" ? "json-path" : "json-data";
  const progressKey = `${kindKey}:${getBackendJobMapKey(jobId)}`;
  const state = bridgeProgressLogStateByKey.get(progressKey) || {
    lastPercent: -1,
    lastProcessed: 0,
  };
  bridgeProgressLogStateByKey.set(progressKey, state);
  const processed = Math.max(0, Number(processedPackets) || 0);
  const total = Math.max(0, Number(totalPackets) || 0);
  const isComplete = Boolean(complete);

  if (isComplete) {
    state.lastPercent = -1;
    state.lastProcessed = processed;
    return true;
  }

  if (total > 0) {
    const percent = Math.max(0, Math.min(100, Math.round((processed / total) * 100)));
    if (percent === state.lastPercent) {
      return false;
    }
    state.lastPercent = percent;
    state.lastProcessed = processed;
    return true;
  }

  if (processed - state.lastProcessed < 5000) {
    return false;
  }
  state.lastProcessed = processed;
  return true;
}

function buildBackendProcessEnv() {
  const env = {
    ...process.env,
  };
  env.PACKETSNITCH_RESOURCES_PATH = process.resourcesPath;
  env.PACKETSNITCH_COMMON_PATH = path.join(process.resourcesPath, "common");
  try {
    env.PACKETSNITCH_USERDATA_PATH = app.getPath("userData");
  } catch (_error) {
    env.PACKETSNITCH_USERDATA_PATH = path.join(os.homedir(), ".packetsnitch");
  }
  // Manylinux wheels (numpy, scipy, gRPC, OpenCV, PyArrow, ...) ship tuned
  // native binaries in a sibling `<package>.libs/` directory next to the
  // package's `__init__.py`. CPython extension modules that link against
  // those vendored `.so` files fail to load unless the dynamic linker can
  // resolve them, which it does NOT do from `<package>.libs/` by default —
  // it only checks standard paths, RPATH, and LD_LIBRARY_PATH. Without this
  // injection, snitch.py crashes on import with
  // `ImportError: libscipy_openblas64_-<hash>.so: cannot open shared
  // object file` whenever the dev-mode `python3` backend is launched
  // against a site-packages tree where the openblas shim lives next to a
  // numpy that wasn't installed alongside its sibling scipy.
  if (platform === "linux") {
    const libsRoots = [];
    const homeDir = os.homedir();
    const versionRoots = [
      path.join(homeDir, ".local", "lib"),
      path.join("/usr/local/lib64"),
      path.join("/usr/local/lib"),
      path.join(homeDir, ".local", "lib64"),
    ];
    for (const versionRoot of versionRoots) {
      let entries = [];
      try {
        entries = fs.readdirSync(versionRoot);
      } catch (_error) {
        continue;
      }
      for (const entry of entries) {
        if (!/^python3\.\d+$/.test(entry)) continue;
        libsRoots.push(path.join(versionRoot, entry, "site-packages"));
      }
    }
    // Project-local venv (created by `npm run build:deps` /
    // `pip3 install --break-system-packages`) lives one level above
    // src/back-comm.js (src/back-comm.js -> src/ -> <project>).
    const projectRoot = path.resolve(__dirname, "..");
    const venvLibRoot = path.join(projectRoot, ".venv", "lib");
    let venvVersionEntries = [];
    try {
      venvVersionEntries = fs.readdirSync(venvLibRoot);
    } catch (_error) {
      venvVersionEntries = [];
    }
    for (const venvEntry of venvVersionEntries) {
      if (!/^python3\.\d+$/.test(venvEntry)) continue;
      libsRoots.push(path.join(venvLibRoot, venvEntry, "site-packages"));
    }

    const libPathEntries = new Set();
    for (const root of libsRoots) {
      let candidates = [];
      try {
        candidates = fs.readdirSync(root);
      } catch (_error) {
        continue;
      }
      for (const candidate of candidates) {
        if (!candidate.endsWith(".libs")) continue;
        const fullPath = path.join(root, candidate);
        try {
          if (fs.statSync(fullPath).isDirectory()) {
            libPathEntries.add(fullPath);
          }
        } catch (_error) {
          // ignore stat failures (race, permission, etc.)
        }
      }
    }

    if (libPathEntries.size > 0) {
      const merged = Array.from(libPathEntries).join(path.delimiter);
      env.LD_LIBRARY_PATH = env.LD_LIBRARY_PATH
        ? `${merged}${path.delimiter}${env.LD_LIBRARY_PATH}`
        : merged;
    }
  }
  return env;
}

async function sendBackendControlCommand(action, timeoutMs = 5000, extraPayload = null) {
  const isReady = await probeSnitchHttpBackendReady(
    currentBackendHttpHost,
    currentBackendHttpPort,
    Math.min(timeoutMs, 1500),
  );
  if (!isReady) {
    return {
      success: true,
      noop: true,
      message: "Backend service is not running",
    };
  }

  return new Promise((resolve) => {
    const body = JSON.stringify(extraPayload && typeof extraPayload === "object"
      ? { action, ...extraPayload }
      : { action });
    const req = http.request(
      {
        host: currentBackendHttpHost,
        port: currentBackendHttpPort,
        path: "/control",
        method: "POST",
        timeout: timeoutMs,
        headers: buildSnitchHttpHeaders({
          "Content-Type": "application/json; charset=utf-8",
          "Content-Length": Buffer.byteLength(body),
          Accept: "application/x-ndjson, application/json",
        }),
      },
      (res) => {
        const emitProgressEvent = (event) => {
          const processedPackets = Number(event?.processedPackets) || 0;
          const totalPackets = Number(event?.totalPackets) || 0;
          const complete = Boolean(event?.complete);
          if (event?.captureData && typeof event.captureData === "object") {
            sendJsonDataPayload({
              captureData: event.captureData,
              processedPackets,
              totalPackets,
              complete,
              chunkSize: DEFAULT_HOST_CHUNK_SIZE,
              label: typeof event?.path === "string" ? event.path : "in-memory-snapshot",
            });
            return;
          }
          if (event?.path) {
            sendJsonPathPayload({
              path: event.path,
              processedPackets,
              totalPackets,
              complete,
              chunkSize: DEFAULT_HOST_CHUNK_SIZE,
            });
          }
        };

        const contentType = String(res.headers["content-type"] || "").toLowerCase();
        if (contentType.includes("application/x-ndjson")) {
          let ndjsonBuffer = "";
          let sawComplete = false;
          let latestCaptureData = null;
          let latestProgressPath = "";
          let finalResult = {
            success: false,
            error: "HTTP backend stream ended without completion event",
            stdout: "",
            fallbackRecommended: false,
          };

          const processNdjsonLine = (line) => {
            const trimmed = String(line || "").trim();
            if (!trimmed) return;
            let message;
            try {
              message = JSON.parse(trimmed);
            } catch (_err) {
              return;
            }

            if (message?.type === "progress") {
              if (sawComplete) {
                return;
              }
              if (typeof message?.path === "string" && message.path.trim()) {
                latestProgressPath = message.path.trim();
              }
              emitProgressEvent(message);
              if (message?.captureData && typeof message.captureData === "object") {
                latestCaptureData = message.captureData;
              }
              return;
            }

            if (message?.type === "complete") {
              sawComplete = true;
              const finalCaptureData =
                message?.captureData && typeof message.captureData === "object"
                  ? message.captureData
                  : latestCaptureData;
              if (finalCaptureData) {
                sendJsonDataPayload({
                  captureData: finalCaptureData,
                  processedPackets: Number(message?.processedPackets) || 0,
                  totalPackets: Number(message?.totalPackets) || 0,
                  complete: true,
                  chunkSize: hostChunkSize,
                  label: typeof message?.path === "string" ? message.path : "in-memory-snapshot",
                });
              } else if (latestProgressPath) {
                sendJsonPathPayload({
                  path: latestProgressPath,
                  processedPackets: Number(message?.processedPackets) || 0,
                  totalPackets: Number(message?.totalPackets) || 0,
                  complete: true,
                  chunkSize: hostChunkSize,
                });
              }
              finalResult = {
                success: Boolean(message?.success),
                error: message?.error || "",
                stdout: typeof message?.stdout === "string" ? message.stdout : "",
                fallbackRecommended: false,
              };
              return;
            }

            if (message?.type === "error") {
              if (sawComplete) {
                return;
              }
              finalResult = {
                success: false,
                error: message?.error || "HTTP backend stream error",
                stdout: "",
                fallbackRecommended: false,
              };
            }
          };

          res.on("data", (chunk) => {
            ndjsonBuffer += chunk.toString();
            const lines = ndjsonBuffer.split(/\r?\n/);
            ndjsonBuffer = lines.pop() || "";
            lines.forEach(processNdjsonLine);
          });

          res.on("end", () => {
            processNdjsonLine(ndjsonBuffer);
            finish(finalResult);
          });
          return;
        }

        let responseBody = "";
        res.on("data", (chunk) => {
          responseBody += chunk.toString();
        });
        res.on("end", () => {
          let parsed = {};
          try {
            parsed = JSON.parse(responseBody || "{}");
          } catch (_err) {
            parsed = {};
          }
          resolve({
            success: res.statusCode === 200 && parsed?.success !== false,
            ...parsed,
          });
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("HTTP backend control request timed out"));
    });
    req.on("error", (error) => {
      resolve({
        success: false,
        error: error?.message || "HTTP backend control request failed",
      });
    });
    req.write(body);
    req.end();
  });
}

async function requestBackendStopProcessing() {
  return sendBackendControlCommand("stop-processing", 5000);
}

async function requestBackendShutdown() {
  backendHttpShutdownExpected = true;
  const result = await sendBackendControlCommand("shutdown", 5000);
  if (!result?.success && !result?.noop) {
    backendHttpShutdownExpected = false;
  }
  return result;
}

// ── Startup port reclaim ────────────────────────────────────────────────────
// When the GUI starts up, look for an already-running snitch backend on the
// configured HTTP port. If found, ask it to shut down gracefully via the
// /control endpoint, then fall back to an OS-level kill if the port stays
// bound. This protects against stale or orphaned backend processes left over
// from a previous GUI session that exited without cleanup.

function sleepMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, Number(ms) || 0)));
}

function parseListeningPidsFromLsofOutput(stdout) {
  if (typeof stdout !== "string" || !stdout.trim()) return [];
  const pids = new Set();
  const lines = stdout.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;
    // When lsof is invoked with `-t` the output is a bare list of PIDs,
    // one per line. Otherwise the standard header row is "COMMAND PID ..."
    // and PID is the second whitespace-separated column.
    const headerLine = line.toLowerCase().startsWith("command") && /\bpid\b/.test(line.toLowerCase());
    if (headerLine) continue;
    const parts = line.split(/\s+/);
    let pidCandidate = null;
    if (parts.length === 1) {
      pidCandidate = Number.parseInt(parts[0], 10);
    } else if (parts.length >= 2) {
      // Standard format: the PID column follows the COMMAND column.
      pidCandidate = Number.parseInt(parts[1], 10);
    }
    if (Number.isInteger(pidCandidate) && pidCandidate > 0) {
      pids.add(pidCandidate);
    }
  }
  return Array.from(pids);
}

function parseListeningPidsFromNetstatOutput(stdout) {
  if (typeof stdout !== "string" || !stdout.trim()) return [];
  const pids = new Set();
  const lines = stdout.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;
    if (/proto/i.test(line.split(/\s+/)[0] || "")) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length < 4) continue;
    // Look for the LISTENING state token and capture the PID (last column on
    // Windows netstat -ano output, or one of the trailing columns on Linux).
    let listeningIndex = -1;
    for (let index = 0; index < tokens.length; index += 1) {
      if (/^listening$/i.test(tokens[index])) {
        listeningIndex = index;
        break;
      }
    }
    if (listeningIndex < 0) continue;
    for (let index = listeningIndex + 1; index < tokens.length; index += 1) {
      const candidate = Number.parseInt(tokens[index], 10);
      if (Number.isInteger(candidate) && candidate > 0) {
        pids.add(candidate);
        break;
      }
    }
  }
  return Array.from(pids);
}

async function findListeningProcessIdsForPort(port) {
  const normalizedPort = Number.parseInt(String(port), 10);
  if (!Number.isInteger(normalizedPort) || normalizedPort <= 0) return [];
  if (platform === "win32") {
    try {
      const { stdout } = await execFileAsync("netstat", ["-ano", "-p", "TCP"], {
        timeout: 3000,
        windowsHide: true,
        maxBuffer: 256 * 1024,
      });
      const lines = String(stdout || "").split(/\r?\n/);
      const matches = [];
      const portToken = `:${normalizedPort}`;
      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;
        if (!line.includes(portToken)) continue;
        if (!/\bLISTENING\b/i.test(line)) continue;
        const tokens = line.split(/\s+/);
        const pid = Number.parseInt(tokens[tokens.length - 1], 10);
        if (Number.isInteger(pid) && pid > 0) {
          matches.push(pid);
        }
      }
      return Array.from(new Set(matches));
    } catch (error) {
      global.logBackend?.(
        "[Bridge] Unable to look up listening PIDs via netstat:",
        error?.message || String(error),
      );
      return [];
    }
  }
  // macOS ships lsof; Linux usually has lsof as well but fuser is a backup.
  try {
    const { stdout } = await execFileAsync("lsof", ["-nP", `-iTCP:${normalizedPort}`, "-sTCP:LISTEN", "-t"], {
      timeout: 3000,
      windowsHide: true,
      maxBuffer: 64 * 1024,
    });
    return parseListeningPidsFromLsofOutput(String(stdout || ""));
  } catch (lsofError) {
    // Fall through to fuser for Linux systems without lsof.
  }
  if (platform === "linux") {
    try {
      const { stdout } = await execFileAsync("fuser", [`${normalizedPort}/tcp`], {
        timeout: 3000,
        windowsHide: true,
        maxBuffer: 64 * 1024,
      });
      // fuser prints "<pid> <pid> ..." on stdout.
      const tokens = String(stdout || "").split(/\s+/);
      const pids = tokens
        .map((token) => Number.parseInt(token, 10))
        .filter((value) => Number.isInteger(value) && value > 0);
      return Array.from(new Set(pids));
    } catch (fuserError) {
      global.logBackend?.(
        "[Bridge] Unable to look up listening PIDs for port:",
        normalizedPort,
        fuserError?.message || String(fuserError),
      );
      return [];
    }
  }
  return [];
}

async function killProcessById(pid) {
  const numericPid = Number.parseInt(String(pid), 10);
  if (!Number.isInteger(numericPid) || numericPid <= 0) {
    return { killed: false, reason: "invalid-pid" };
  }
  if (numericPid === process.pid) {
    return { killed: false, reason: "self" };
  }
  try {
    if (platform === "win32") {
      await execFileAsync("taskkill", ["/F", "/T", "/PID", String(numericPid)], {
        timeout: 4000,
        windowsHide: true,
      });
    } else {
      process.kill(numericPid, "SIGTERM");
    }
    return { killed: true, signal: platform === "win32" ? "taskkill" : "SIGTERM" };
  } catch (error) {
    if (platform !== "win32" && (error?.code === "ESRCH" || /No such process/i.test(error?.message || ""))) {
      return { killed: false, reason: "already-gone" };
    }
    if (platform === "win32" && /not found/i.test(error?.message || "")) {
      return { killed: false, reason: "already-gone" };
    }
    return {
      killed: false,
      reason: "error",
      error: error?.message || String(error),
    };
  }
}

async function forceKillProcessById(pid) {
  const numericPid = Number.parseInt(String(pid), 10);
  if (!Number.isInteger(numericPid) || numericPid <= 0) {
    return { killed: false, reason: "invalid-pid" };
  }
  if (numericPid === process.pid) {
    return { killed: false, reason: "self" };
  }
  try {
    if (platform === "win32") {
      await execFileAsync("taskkill", ["/F", "/T", "/PID", String(numericPid)], {
        timeout: 4000,
        windowsHide: true,
      });
    } else {
      process.kill(numericPid, "SIGKILL");
    }
    return { killed: true, signal: platform === "win32" ? "taskkill" : "SIGKILL" };
  } catch (error) {
    if (error?.code === "ESRCH" || /No such process/i.test(error?.message || "")) {
      return { killed: false, reason: "already-gone" };
    }
    return {
      killed: false,
      reason: "error",
      error: error?.message || String(error),
    };
  }
}

async function waitForBackendPortFree(host, port, timeoutMs, pollIntervalMs) {
  const deadline = Date.now() + Math.max(0, Number(timeoutMs) || 0);
  const interval = Math.max(50, Number(pollIntervalMs) || STARTUP_RECLAIM_PORT_POLL_INTERVAL_MS);
  while (Date.now() < deadline) {
    const stillReady = await probeSnitchHttpBackendReady(host, port, 600);
    if (!stillReady) {
      return { released: true };
    }
    await sleepMs(interval);
  }
  return { released: false, reason: "timeout" };
}

async function reclaimExistingBackendService(options = {}) {
  const source = options && typeof options === "object" ? options : {};
  const host = typeof source.host === "string" && source.host.trim()
    ? source.host.trim()
    : currentBackendHttpHost;
  const port = Number.parseInt(String(source.port ?? currentBackendHttpPort), 10);
  if (!Number.isInteger(port) || port <= 0) {
    return { detected: false, action: "skipped", reason: "invalid-port" };
  }
  const gracefulTimeoutMs = Number.isFinite(Number(source.gracefulTimeoutMs))
    ? Number(source.gracefulTimeoutMs)
    : STARTUP_RECLAIM_GRACEFUL_TIMEOUT_MS;
  const killTimeoutMs = Number.isFinite(Number(source.killTimeoutMs))
    ? Number(source.killTimeoutMs)
    : STARTUP_RECLAIM_KILL_TIMEOUT_MS;

  // The /ping probe only matches a real snitch-http service. If nothing is
  // listening, or the port is held by something that isn't our backend,
  // there's nothing to reclaim.
  const detected = await probeSnitchHttpBackendReady(host, port, 800);
  if (!detected) {
    return { detected: false, action: "none", host, port };
  }
  global.logBackend?.(
    `[Bridge] Startup reclaim: detected existing snitch HTTP backend on ${host}:${port}`,
  );

  // 1) Try graceful shutdown via the /control endpoint.
  const shutdownResult = await sendBackendControlCommand("shutdown", Math.max(1500, Math.min(gracefulTimeoutMs, 4000)));
  const shutdownAccepted = Boolean(shutdownResult?.success || shutdownResult?.noop);
  if (!shutdownAccepted) {
    global.logBackend?.(
      "[Bridge] Startup reclaim: graceful shutdown was not accepted; proceeding to hard kill",
      shutdownResult?.error || "",
    );
  }

  // 2) Wait for the port to be released.
  const release = await waitForBackendPortFree(
    host,
    port,
    Math.max(500, gracefulTimeoutMs),
    STARTUP_RECLAIM_PORT_POLL_INTERVAL_MS,
  );
  if (release.released) {
    global.logBackend?.(
      `[Bridge] Startup reclaim: existing backend on ${host}:${port} stopped gracefully`,
    );
    return {
      detected: true,
      action: shutdownAccepted ? "graceful-shutdown" : "graceful-shutdown-fallback",
      host,
      port,
    };
  }

  // 3) Port still bound — fall back to OS-level kill of whatever process is
  //    listening on the port. This handles orphans from a previous GUI crash
  //    as well as the case where the graceful shutdown did not run cleanly.
  const listeningPids = await findListeningProcessIdsForPort(port);
  if (!listeningPids.length) {
    global.logBackend?.(
      `[Bridge] Startup reclaim: port ${port} still reports busy but no listening PID could be resolved; will rely on spawn-time re-probe`,
    );
    return {
      detected: true,
      action: "no-pid-found",
      host,
      port,
      gracefulShutdownAccepted: shutdownAccepted,
    };
  }

  global.logBackend?.(
    `[Bridge] Startup reclaim: forcing kill of process(es) bound to ${host}:${port}: ${listeningPids.join(", ")}`,
  );

  const killResults = [];
  for (const pid of listeningPids) {
    const result = await killProcessById(pid);
    killResults.push({ pid, ...result });
  }

  const recheck = await waitForBackendPortFree(
    host,
    port,
    Math.max(500, killTimeoutMs),
    STARTUP_RECLAIM_PORT_POLL_INTERVAL_MS,
  );

  // 4) If the port is STILL bound after SIGTERM, escalate to SIGKILL.
  if (!recheck.released) {
    for (const pid of listeningPids) {
      const prior = killResults.find((entry) => entry.pid === pid);
      if (prior && (prior.killed || prior.reason === "already-gone")) continue;
      // eslint-disable-next-line no-await-in-loop
      const escalated = await forceKillProcessById(pid);
      killResults.push({ pid, ...escalated, escalated: true });
    }
    const finalRecheck = await waitForBackendPortFree(
      host,
      port,
      Math.max(500, killTimeoutMs / 2),
      STARTUP_RECLAIM_PORT_POLL_INTERVAL_MS,
    );
    if (!finalRecheck.released) {
      global.logBackend?.(
        `[Bridge] Startup reclaim: failed to free port ${host}:${port} after kill; subsequent spawn may report address-in-use`,
      );
    } else {
      global.logBackend?.(
        `[Bridge] Startup reclaim: forced kill cleared port ${host}:${port}`,
      );
    }
    return {
      detected: true,
      action: "force-kill",
      host,
      port,
      gracefulShutdownAccepted: shutdownAccepted,
      killedPids: killResults,
    };
  }

  global.logBackend?.(
    `[Bridge] Startup reclaim: killed process(es) on ${host}:${port}; port is now free`,
  );
  return {
    detected: true,
    action: "kill",
    host,
    port,
    gracefulShutdownAccepted: shutdownAccepted,
    killedPids: killResults,
  };
}

function probeSnitchHttpBackendReady(host = BACKEND_HTTP_HOST, port = BACKEND_HTTP_PORT, timeoutMs = 1200) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (ready) => {
      if (settled) return;
      settled = true;
      resolve(Boolean(ready));
    };

    const req = http.request(
      {
        host,
        port,
        path: "/ping",
        method: "GET",
        timeout: timeoutMs,
        headers: buildSnitchHttpHeaders({
          Accept: "application/json",
        }),
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk.toString();
        });
        res.on("end", () => {
          try {
            const payload = JSON.parse(body);
            finish(
              res.statusCode === 200
              && payload?.type === "pong"
              && payload?.service === "snitch-http",
            );
          } catch (_err) {
            finish(false);
          }
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("HTTP ping timed out"));
    });
    req.on("error", () => finish(false));
    req.end();
  });
}

function requestSnitchHttpBackendVersion(
  host = BACKEND_HTTP_HOST,
  port = BACKEND_HTTP_PORT,
  timeoutMs = 1500,
) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host,
        port,
        path: "/version",
        method: "GET",
        timeout: timeoutMs,
        headers: buildSnitchHttpHeaders({
          Accept: "application/json",
        }),
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk.toString();
        });
        res.on("end", () => {
          try {
            const payload = JSON.parse(body || "{}");
            resolve({
              ok:
                res.statusCode === 200
                && payload?.type === "version"
                && typeof payload?.version === "string"
                && payload.version.trim().length > 0,
              service:
                typeof payload?.service === "string" && payload.service.trim()
                  ? payload.service.trim()
                  : null,
              version:
                typeof payload?.version === "string" && payload.version.trim()
                  ? payload.version.trim()
                  : null,
            });
          } catch (_err) {
            resolve({
              ok: false,
              service: null,
              version: null,
            });
          }
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("HTTP version request timed out"));
    });
    req.on("error", () => {
      resolve({
        ok: false,
        service: null,
        version: null,
      });
    });
    req.end();
  });
}

function requestSnitchHttpBackendGeoip(
  ipAddress,
  {
    side = "src",
    host = currentBackendHttpHost,
    port = currentBackendHttpPort,
    timeoutMs = 3000,
  } = {},
) {
  return new Promise((resolve) => {
    const normalizedIp = String(ipAddress || "").trim();
    const normalizedSide = String(side || "src").trim().toLowerCase() === "dst"
      ? "dst"
      : "src";
    if (!normalizedIp) {
      resolve({
        success: false,
        error: "Missing IP address",
      });
      return;
    }

    const requestPath = `/geoip?ip=${encodeURIComponent(normalizedIp)}&side=${encodeURIComponent(normalizedSide)}`;
    const req = http.request(
      {
        host,
        port,
        path: requestPath,
        method: "GET",
        timeout: timeoutMs,
        headers: buildSnitchHttpHeaders({
          Accept: "application/json",
        }),
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk.toString();
        });
        res.on("end", () => {
          let payload = {};
          try {
            payload = JSON.parse(body || "{}");
          } catch (_err) {
            payload = {};
          }
          resolve({
            success: res.statusCode === 200 && payload?.success !== false,
            ...payload,
          });
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("HTTP GeoIP request timed out"));
    });
    req.on("error", (error) => {
      resolve({
        success: false,
        error: error?.message || "HTTP GeoIP request failed",
      });
    });
    req.end();
  });
}

function requestSnitchHttpBackendWhois(
  ipAddress,
  {
    host = currentBackendHttpHost,
    port = currentBackendHttpPort,
    timeoutMs = 7000,
  } = {},
) {
  return new Promise((resolve) => {
    const normalizedIp = String(ipAddress || "").trim();
    if (!normalizedIp) {
      resolve({
        success: false,
        error: "Missing IP address",
      });
      return;
    }

    const requestPath = `/whois?ip=${encodeURIComponent(normalizedIp)}`;
    const req = http.request(
      {
        host,
        port,
        path: requestPath,
        method: "GET",
        timeout: timeoutMs,
        headers: buildSnitchHttpHeaders({
          Accept: "application/json",
        }),
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk.toString();
        });
        res.on("end", () => {
          let payload = {};
          try {
            payload = JSON.parse(body || "{}");
          } catch (_err) {
            payload = {};
          }
          resolve({
            success: res.statusCode === 200 && payload?.success !== false,
            ...payload,
          });
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("HTTP WHOIS request timed out"));
    });
    req.on("error", (error) => {
      resolve({
        success: false,
        error: error?.message || "HTTP WHOIS request failed",
      });
    });
    req.end();
  });
}

function requestSnitchHttpBackendIpsum(
  ipAddress,
  {
    host = currentBackendHttpHost,
    port = currentBackendHttpPort,
    timeoutMs = 10000,
  } = {},
) {
  return new Promise((resolve) => {
    const normalizedIp = String(ipAddress || "").trim();
    if (!normalizedIp) {
      resolve({
        success: false,
        error: "Missing IP address",
      });
      return;
    }

    const requestPath = `/ipsum?ip=${encodeURIComponent(normalizedIp)}`;
    const req = http.request(
      {
        host,
        port,
        path: requestPath,
        method: "GET",
        timeout: timeoutMs,
        headers: buildSnitchHttpHeaders({
          Accept: "application/json",
        }),
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk.toString();
        });
        res.on("end", () => {
          let payload = {};
          try {
            payload = JSON.parse(body || "{}");
          } catch (_err) {
            payload = {};
          }
          resolve({
            success: res.statusCode === 200 && payload?.success !== false,
            ...payload,
          });
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("HTTP IPSum request timed out"));
    });
    req.on("error", (error) => {
      resolve({
        success: false,
        error: error?.message || "HTTP IPSum request failed",
      });
    });
    req.end();
  });
}

function requestSnitchHttpBackendTor(
  ipAddress,
  {
    host = currentBackendHttpHost,
    port = currentBackendHttpPort,
    timeoutMs = 7000,
  } = {},
) {
  return new Promise((resolve) => {
    const normalizedIp = String(ipAddress || "").trim();
    if (!normalizedIp) {
      resolve({
        success: false,
        error: "Missing IP address",
      });
      return;
    }

    const requestPath = `/tor?ip=${encodeURIComponent(normalizedIp)}`;
    const req = http.request(
      {
        host,
        port,
        path: requestPath,
        method: "GET",
        timeout: timeoutMs,
        headers: buildSnitchHttpHeaders({
          Accept: "application/json",
        }),
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk.toString();
        });
        res.on("end", () => {
          let payload = {};
          try {
            payload = JSON.parse(body || "{}");
          } catch (_err) {
            payload = {};
          }
          resolve({
            success: res.statusCode === 200 && payload?.success !== false,
            ...payload,
          });
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("HTTP Tor request timed out"));
    });
    req.on("error", (error) => {
      resolve({
        success: false,
        error: error?.message || "HTTP Tor request failed",
      });
    });
    req.end();
  });
}

function requestSnitchHttpBackendShodan(
  ipAddress,
  {
    host = currentBackendHttpHost,
    port = currentBackendHttpPort,
    timeoutMs = 8000,
  } = {},
) {
  return new Promise((resolve) => {
    const normalizedIp = String(ipAddress || "").trim();
    if (!normalizedIp) {
      resolve({
        success: false,
        error: "Missing IP address",
      });
      return;
    }

    const requestPath = `/shodan?ip=${encodeURIComponent(normalizedIp)}`;
    const req = http.request(
      {
        host,
        port,
        path: requestPath,
        method: "GET",
        timeout: timeoutMs,
        headers: buildSnitchHttpHeaders({
          Accept: "application/json",
        }),
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk.toString();
        });
        res.on("end", () => {
          let payload = {};
          try {
            payload = JSON.parse(body || "{}");
          } catch (_err) {
            payload = {};
          }
          resolve({
            success: res.statusCode === 200 && payload?.success !== false,
            ...payload,
          });
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("HTTP Shodan request timed out"));
    });
    req.on("error", (error) => {
      resolve({
        success: false,
        error: error?.message || "HTTP Shodan request failed",
      });
    });
    req.end();
  });
}

function requestSnitchHttpBackendVirusTotal(
  lookupValue,
  {
    lookupType = "ip",
    apiKey = "",
    diagnosticOnly = false,
    host = currentBackendHttpHost,
    port = currentBackendHttpPort,
    timeoutMs = 12000,
  } = {},
) {
  return new Promise((resolve) => {
    const normalizedType = String(lookupType || "auto").trim().toLowerCase() || "auto";
    const normalizedValue = String(lookupValue || "").trim();
    const normalizedApiKey = String(apiKey || "").trim();

    if (!diagnosticOnly && !normalizedValue) {
      resolve({
        success: false,
        error: "Missing lookup value",
      });
      return;
    }

    const queryParts = [
      `type=${encodeURIComponent(normalizedType)}`,
      `diagnostic=${diagnosticOnly ? "1" : "0"}`,
    ];
    if (normalizedValue) {
      queryParts.push(`value=${encodeURIComponent(normalizedValue)}`);
    }
    const requestPath = `/virustotal?${queryParts.join("&")}`;

    const req = http.request(
      {
        host,
        port,
        path: requestPath,
        method: "GET",
        timeout: timeoutMs,
        headers: buildSnitchHttpHeaders({
          Accept: "application/json",
          ...(normalizedApiKey ? { "x-apikey": normalizedApiKey } : {}),
        }),
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => {
          body += chunk.toString();
        });
        res.on("end", () => {
          let payload = {};
          try {
            payload = JSON.parse(body || "{}");
          } catch (_err) {
            payload = {};
          }
          resolve({
            success: res.statusCode === 200 && payload?.success !== false,
            ...payload,
          });
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("HTTP VirusTotal request timed out"));
    });
    req.on("error", (error) => {
      resolve({
        success: false,
        error: error?.message || "HTTP VirusTotal request failed",
      });
    });
    req.end();
  });
}

function normalizeBackendTransportOptions(rawOptions = {}) {
  const source = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
  const host =
    typeof source.tcpHost === "string" && source.tcpHost.trim()
      ? source.tcpHost.trim()
      : BACKEND_HTTP_HOST;
  const parsedPort = Number.parseInt(String(source.tcpPort ?? BACKEND_HTTP_PORT), 10);
  const port = Number.isFinite(parsedPort) && parsedPort > 0
    ? parsedPort
    : BACKEND_HTTP_PORT;
  const forceLegacySpawn = Boolean(source.forceLegacySpawn);
  const useHttpDataSnapshots = Boolean(source.useHttpDataSnapshots);
  const parsedJsonDataEmitMinIntervalMs = Number.parseInt(
    String(source.jsonDataEmitMinIntervalMs ?? currentJsonDataEmitMinIntervalMs),
    10,
  );
  const jsonDataEmitMinIntervalMs =
    Number.isFinite(parsedJsonDataEmitMinIntervalMs) && parsedJsonDataEmitMinIntervalMs >= 250
      ? parsedJsonDataEmitMinIntervalMs
      : DEFAULT_JSON_DATA_EMIT_MIN_INTERVAL_MS;
  return {
    tcpHost: host,
    tcpPort: port,
    forceLegacySpawn,
    useHttpDataSnapshots,
    jsonDataEmitMinIntervalMs,
  };
}

function applyBackendTransportOptions(options = {}) {
  const normalized = normalizeBackendTransportOptions(options);
  const hostChanged = normalized.tcpHost !== currentBackendHttpHost;
  const portChanged = normalized.tcpPort !== currentBackendHttpPort;
  if (hostChanged || portChanged) {
    shutdownHttpBackendService();
    currentBackendHttpHost = normalized.tcpHost;
    currentBackendHttpPort = normalized.tcpPort;
  }
  currentJsonDataEmitMinIntervalMs = normalized.jsonDataEmitMinIntervalMs;
  return normalized;
}

async function getBackendServiceDiagnostics(options = {}) {
  const optionsSource = options && typeof options === "object" ? options : {};
  const normalizedTransport = applyBackendTransportOptions(
    optionsSource.backendOptions,
  );
  const ensureReady = Boolean(optionsSource.ensureReady);
  const forceLegacySpawn = Boolean(normalizedTransport.forceLegacySpawn);

  let backendWebserverUp = false;
  if (!forceLegacySpawn) {
    backendWebserverUp = ensureReady
      ? await ensureBackendHttpServerReady()
      : await probeSnitchHttpBackendReady(
        currentBackendHttpHost,
        currentBackendHttpPort,
      );
  }

  const versionResult = backendWebserverUp
    ? await requestSnitchHttpBackendVersion(
      currentBackendHttpHost,
      currentBackendHttpPort,
    )
    : { ok: false, service: null, version: null };

  const managedProcessAlive = Boolean(
    backendHttpServerProc && !backendHttpServerProc.killed,
  );
  return {
    success: true,
    mode: forceLegacySpawn ? "legacy" : "http",
    forceLegacySpawn,
    host: currentBackendHttpHost,
    port: currentBackendHttpPort,
    backendProcessRunning: forceLegacySpawn
      ? managedProcessAlive
      : managedProcessAlive || backendWebserverUp,
    backendWebserverUp,
    backendVersion: versionResult.version,
    backendVersionService: versionResult.service,
    backendVersionReachable: Boolean(versionResult.ok),
    checkedAt: new Date().toISOString(),
  };
}

async function primeBackendHttpServer(options = {}) {
  const normalizedTransport = applyBackendTransportOptions(options);
  if (normalizedTransport.forceLegacySpawn) {
    return false;
  }
  return ensureBackendHttpServerReady();
}

function resolveBackendRuntime() {
  const isDev = !require("electron").app.isPackaged;
  const basePath = isDev
    ? path.join(__dirname, "../../src/backend/")
    : process.resourcesPath;
  const backendScriptPath = path.join(basePath, "snitch.py");
  const hasBackendScript = fs.existsSync(backendScriptPath);

  const snitchExecutableCandidates = platform === "win32"
    ? [
      path.join(basePath, "snitch.exe"),
      path.join(basePath, "snitch", "snitch.exe"),
      path.join(basePath, "snitch"),
    ]
    : [
      path.join(basePath, "snitch"),
      path.join(basePath, "snitch", "snitch"),
      path.join(basePath, "snitch.exe"),
    ];

  const snitchExePath =
    snitchExecutableCandidates.find((candidatePath) => fs.existsSync(candidatePath))
    || snitchExecutableCandidates[0];

  const hasBundledBackendExe = !isDev && fs.existsSync(snitchExePath);
  const usePythonBackend = isDev && hasBackendScript;
  const canUseServerMode = Boolean((!isDev && hasBundledBackendExe) || hasBackendScript);
  const backendCommandPath = usePythonBackend
    ? platform === "win32"
      ? "python"
      : "python3"
    : snitchExePath;
  const pythonCommandPath = platform === "win32" ? "python" : "python3";

  return {
    isDev,
    basePath,
    backendScriptPath,
    hasBackendScript,
    snitchExePath,
    snitchExecutableCandidates,
    hasBundledBackendExe,
    usePythonBackend,
    canUseServerMode,
    pythonCommandPath,
    backendCommandPath,
  };
}

function shutdownHttpBackendService() {
  const shutdownPromise = requestBackendShutdown();
  // Reset local readiness tracking; the service close callback will reconcile state.
  backendHttpReadyPromise = null;
  return shutdownPromise;
}

async function ensureBackendHttpServerReady() {
  if (backendHttpReadyPromise) {
    return backendHttpReadyPromise;
  }

  if (await probeSnitchHttpBackendReady(currentBackendHttpHost, currentBackendHttpPort)) {
    return true;
  }

  backendHttpReadyPromise = new Promise((resolve) => {
    const runtime = resolveBackendRuntime();
    if (!runtime.canUseServerMode) {
      resolve(false);
      return;
    }

    const backendCommandPath = runtime.usePythonBackend
      ? runtime.pythonCommandPath
      : runtime.backendCommandPath;
    const backendArgs = runtime.usePythonBackend
      ? [
        runtime.backendScriptPath,
        "--server",
        "--server-host",
        currentBackendHttpHost,
        "--server-port",
        String(currentBackendHttpPort),
      ]
      : [
        "--server",
        "--server-host",
        currentBackendHttpHost,
        "--server-port",
        String(currentBackendHttpPort),
      ];

    let resolved = false;
    let detectedAddressInUse = false;
    const finish = (ready) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(readyTimeout);
      resolve(ready);
    };

    backendHttpServerProc = spawn(backendCommandPath, backendArgs, {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: buildBackendProcessEnv(),
    });

    const onBackendOutput = (text) => {
      if (!text) return;
      if (/Address already in use|Errno\s*98/i.test(text)) {
        detectedAddressInUse = true;
        return;
      }

      // When a second backend instance races startup against an already-running
      // service, Python emits a traceback. We suppress that noisy traceback and
      // rely on the explicit "reusing existing service" bridge log instead.
      if (
        detectedAddressInUse
        && /(Traceback \(most recent call last\)|^\s*File\s+"|socketserver\.py|http\/server\.py|self\.socket\.bind|OSError: \[Errno\s*98\])/m.test(text)
      ) {
        return;
      }

      global.logBackend("", text);
      if (text.includes("[BridgeServer] Listening")) {
        void probeSnitchHttpBackendReady(currentBackendHttpHost, currentBackendHttpPort)
          .then((ready) => finish(ready));
      }
    };

    const readyTimeout = setTimeout(() => {
      finish(false);
    }, BACKEND_HTTP_READY_TIMEOUT_MS);

    backendHttpServerProc.stdout.on("data", (chunk) => onBackendOutput(chunk.toString()));
    backendHttpServerProc.stderr.on("data", (chunk) => onBackendOutput(chunk.toString()));

    backendHttpServerProc.on("error", (error) => {
      global.logBackend("[Bridge] HTTP backend startup failed:", error?.message || String(error));
      backendHttpServerProc = null;
      finish(false);
    });

    backendHttpServerProc.on("close", async (code, signal) => {
      const expectedShutdown = backendHttpShutdownExpected;
      backendHttpShutdownExpected = false;
      const descriptor = code === null
        ? `signal ${signal || "unknown"}`
        : `code ${code}`;
      const readyViaExternalListener = await probeSnitchHttpBackendReady(
        currentBackendHttpHost,
        currentBackendHttpPort,
      );
      if (expectedShutdown) {
        global.logBackend(`[Bridge] HTTP backend stopped (${descriptor})`);
        cancelBackendHttpRespawn();
        backendHttpRespawnAttempts = 0;
      } else if (detectedAddressInUse && readyViaExternalListener) {
        global.logBackend(
          `[Bridge] HTTP backend already running on ${currentBackendHttpHost}:${currentBackendHttpPort}; reusing existing service`,
        );
        cancelBackendHttpRespawn();
        backendHttpRespawnAttempts = 0;
      } else {
        global.logBackend(`[Bridge] HTTP backend exited unexpectedly (${descriptor})`);
        backendHttpServerProc = null;
        backendHttpReadyPromise = null;
        if (readyViaExternalListener) {
          global.logBackend("[Bridge] External HTTP backend is reachable; switching to it");
          cancelBackendHttpRespawn();
          backendHttpRespawnAttempts = 0;
          sendBackendServiceState({ ready: true });
          return;
        }
        sendBackendServiceState({ ready: false, exitCode: code, exitSignal: signal });
        scheduleBackendHttpRespawn();
        return;
      }
      backendHttpServerProc = null;
      backendHttpReadyPromise = null;
      finish(readyViaExternalListener);
    });
  });

  const ready = await backendHttpReadyPromise;
  if (ready) {
    cancelBackendHttpRespawn();
    backendHttpRespawnAttempts = 0;
    sendBackendServiceState({ ready: true });
  } else {
    backendHttpReadyPromise = null;
  }
  return ready;
}

async function runBackendCommandViaHttp(filename, options = {}) {
  const {
    hostChunkSize = DEFAULT_HOST_CHUNK_SIZE,
    workerThreads = 0,
    pcapSourcePayload = null,
    useHttpDataSnapshots = false,
    jobId = "",
    wifiKeys = null,
  } = options;
  const normalizedJobId = normalizeBackendJobId(jobId) || createBackendJobId("http");

  const ready = await ensureBackendHttpServerReady();
  if (!ready) {
    return {
      jobId: normalizedJobId,
      success: false,
      error: "HTTP backend service unavailable",
      fallbackRecommended: true,
    };
  }

  return new Promise((resolve) => {
    const emitProgressEvent = (event) => {
      const eventJobId = normalizeBackendJobId(event?.jobId) || normalizedJobId;
      const processedPackets = Number(event?.processedPackets) || 0;
      const totalPackets = Number(event?.totalPackets) || 0;
      const complete = Boolean(event?.complete);
      if (event?.captureData && typeof event.captureData === "object") {
        if (shouldLogBridgeProgress("json-data", processedPackets, totalPackets, complete, eventJobId)) {
          global.logBackend(
            `[Bridge] HTTP progress jobId=${eventJobId} json-data processed=${processedPackets} total=${totalPackets} complete=${complete ? 1 : 0}`,
          );
        }
        sendJsonDataPayload({
          jobId: eventJobId,
          captureData: event.captureData,
          processedPackets,
          totalPackets,
          complete,
          chunkSize: hostChunkSize,
          label: typeof event?.path === "string" ? event.path : "in-memory-snapshot",
        });
        return;
      }
      if (event?.path) {
        if (shouldLogBridgeProgress("json-path", processedPackets, totalPackets, complete, eventJobId)) {
          global.logBackend(
            `[Bridge] HTTP progress jobId=${eventJobId} json-path processed=${processedPackets} total=${totalPackets} complete=${complete ? 1 : 0}`,
          );
        }
        sendJsonPathPayload({
          jobId: eventJobId,
          path: event.path,
          processedPackets,
          totalPackets,
          complete,
          chunkSize: hostChunkSize,
        });
      }
    };

    const requestPayload = {
      jobId: normalizedJobId,
      pcapPath: filename,
      hostChunkSize,
      workerThreads,
      emitJsonSnapshots: Boolean(useHttpDataSnapshots),
      verbose: 1,
    };
    if (Array.isArray(wifiKeys)) {
      requestPayload.wifiKeys = wifiKeys;
    }
    if (pcapSourcePayload && typeof pcapSourcePayload.data === "string") {
      requestPayload.pcapBase64 = pcapSourcePayload.data;
      requestPayload.pcapFileName = pcapSourcePayload.fileName || "session-reprocess.pcap";
    }

    const body = JSON.stringify(requestPayload);
    let resolved = false;
    const finish = (result) => {
      if (resolved) return;
      resolved = true;
      resolve(result);
    };

    const req = http.request(
      {
        host: currentBackendHttpHost,
        port: currentBackendHttpPort,
        path: "/process",
        method: "POST",
        timeout: BACKEND_HTTP_REQUEST_TIMEOUT_MS,
        headers: buildSnitchHttpHeaders({
          "Content-Type": "application/json; charset=utf-8",
          "Content-Length": Buffer.byteLength(body),
          Accept: "application/x-ndjson, application/json",
        }),
      },
      (res) => {
        const contentType = String(res.headers["content-type"] || "").toLowerCase();

        if (contentType.includes("application/x-ndjson")) {
          let ndjsonBuffer = "";
          let sawComplete = false;
          let latestCaptureData = null;
          let latestProgressPath = "";
          let finalResult = {
            jobId: normalizedJobId,
            success: false,
            error: "HTTP backend stream ended without completion event",
            stdout: "",
            fallbackRecommended: false,
            pcapSource: pcapSourcePayload,
          };

          const processNdjsonLine = (line) => {
            const trimmed = String(line || "").trim();
            if (!trimmed) return;

            let message;
            try {
              message = JSON.parse(trimmed);
            } catch (_err) {
              return;
            }

            if (message?.type === "progress") {
              if (sawComplete) {
                return;
              }
              if (typeof message?.path === "string" && message.path.trim()) {
                latestProgressPath = message.path.trim();
              }
              emitProgressEvent(message);
              if (message?.captureData && typeof message.captureData === "object") {
                latestCaptureData = message.captureData;
              }
              return;
            }

            if (message?.type === "complete") {
              sawComplete = true;
              const finalCaptureData =
                message?.captureData && typeof message.captureData === "object"
                  ? message.captureData
                  : latestCaptureData;
              if (finalCaptureData) {
                sendJsonDataPayload({
                  jobId: normalizeBackendJobId(message?.jobId) || normalizedJobId,
                  captureData: finalCaptureData,
                  processedPackets: Number(message?.processedPackets) || 0,
                  totalPackets: Number(message?.totalPackets) || 0,
                  complete: true,
                  chunkSize: hostChunkSize,
                  label: typeof message?.path === "string" ? message.path : "in-memory-snapshot",
                });
              } else if (latestProgressPath) {
                sendJsonPathPayload({
                  jobId: normalizeBackendJobId(message?.jobId) || normalizedJobId,
                  path: latestProgressPath,
                  processedPackets: Number(message?.processedPackets) || 0,
                  totalPackets: Number(message?.totalPackets) || 0,
                  complete: true,
                  chunkSize: hostChunkSize,
                });
              }
              finalResult = {
                jobId: normalizeBackendJobId(message?.jobId) || normalizedJobId,
                success: Boolean(message?.success),
                error: message?.error || "",
                stdout: typeof message?.stdout === "string" ? message.stdout : "",
                fallbackRecommended: false,
                pcapSource: pcapSourcePayload,
              };
              return;
            }

            if (message?.type === "error") {
              if (sawComplete) {
                return;
              }
              finalResult = {
                jobId: normalizeBackendJobId(message?.jobId) || normalizedJobId,
                success: false,
                error: message?.error || "HTTP backend stream error",
                stdout: "",
                fallbackRecommended: false,
                pcapSource: pcapSourcePayload,
              };
            }
          };

          res.on("data", (chunk) => {
            ndjsonBuffer += chunk.toString();
            const lines = ndjsonBuffer.split(/\r?\n/);
            ndjsonBuffer = lines.pop() || "";
            lines.forEach(processNdjsonLine);
          });

          res.on("end", () => {
            processNdjsonLine(ndjsonBuffer);
            if (sawComplete) {
              finish(finalResult);
              return;
            }
            finish({
              jobId: finalResult.jobId || normalizedJobId,
              success: false,
              error: finalResult.error || "HTTP backend stream ended before completion",
              stdout: finalResult.stdout || "",
              fallbackRecommended: false,
              pcapSource: pcapSourcePayload,
            });
          });
          return;
        }

        let responseBody = "";
        res.on("data", (chunk) => {
          responseBody += chunk.toString();
        });
        res.on("end", () => {
          let parsed;
          try {
            parsed = JSON.parse(responseBody || "{}");
          } catch (_err) {
            finish({
              jobId: normalizedJobId,
              success: false,
              error: "HTTP backend returned invalid JSON",
              fallbackRecommended: false,
              pcapSource: pcapSourcePayload,
            });
            return;
          }

          const progressEvents = Array.isArray(parsed.progressEvents)
            ? parsed.progressEvents
            : [];
          progressEvents.forEach(emitProgressEvent);

          if (res.statusCode !== 200 || !parsed.success) {
            finish({
              jobId: normalizedJobId,
              success: false,
              error: parsed.error || "HTTP backend processing failed",
              stdout: typeof parsed.stdout === "string" ? parsed.stdout : "",
              fallbackRecommended: false,
              pcapSource: pcapSourcePayload,
            });
            return;
          }

          finish({
            jobId: normalizedJobId,
            success: true,
            stdout: typeof parsed.stdout === "string" ? parsed.stdout : "",
            pcapSource: pcapSourcePayload,
          });
        });
      },
    );

    req.on("timeout", () => {
      req.destroy(new Error("HTTP backend request timed out"));
    });
    req.on("error", (error) => {
      finish({
        jobId: normalizedJobId,
        success: false,
        error: error?.message || "HTTP backend request failed",
        fallbackRecommended: true,
        pcapSource: pcapSourcePayload,
      });
    });
    req.write(body);
    req.end();
  });
}

function normalizeHostChunkSize(rawValue) {
  const parsed = Number(rawValue);
  if (!Number.isFinite(parsed)) return DEFAULT_HOST_CHUNK_SIZE;
  const whole = Math.trunc(parsed);
  return VALID_HOST_CHUNK_SIZES.has(whole) ? whole : DEFAULT_HOST_CHUNK_SIZE;
}

function removePacketsChunkFromFS(jsonPath) {
  if (!jsonPath || typeof jsonPath !== "string") return;
  try {
    if (fs.existsSync(jsonPath)) {
      fs.unlinkSync(jsonPath);
    }
  } catch (err) {
    console.error(`Failed to remove file at ${jsonPath}:`, err);
  }
}

function getMainWindow() {
  return BrowserWindow.getAllWindows()[0];
}

function sendBackendServiceState(state) {
  const mainWin = getMainWindow();
  if (!mainWin) return;
  mainWin.webContents.send("backend-service-state", {
    mode: "http",
    host: currentBackendHttpHost,
    port: currentBackendHttpPort,
    ready: false,
    ...state,
  });
}

function cancelBackendHttpRespawn() {
  if (backendHttpRespawnTimer) {
    clearTimeout(backendHttpRespawnTimer);
    backendHttpRespawnTimer = null;
  }
}

function scheduleBackendHttpRespawn(reason) {
  cancelBackendHttpRespawn();
  const attempt = backendHttpRespawnAttempts;
  const delayMs = Math.min(1000 * 2 ** attempt, 30000);
  backendHttpRespawnAttempts += 1;
  global.logBackend(
    `[Bridge] Scheduling HTTP backend respawn in ${delayMs}ms (attempt ${backendHttpRespawnAttempts})${reason ? `: ${reason}` : ""}`,
  );
  sendBackendServiceState({ ready: false, respawnPending: true, attempts: backendHttpRespawnAttempts });
  backendHttpRespawnTimer = setTimeout(() => {
    backendHttpRespawnTimer = null;
    global.logBackend("[Bridge] Respawning HTTP backend after unexpected exit");
    // Reset the promise guard so ensureBackendHttpServerReady can spawn again.
    backendHttpReadyPromise = null;
    ensureBackendHttpServerReady()
      .then((ready) => {
        if (ready) {
          backendHttpRespawnAttempts = 0;
          global.logBackend("[Bridge] HTTP backend respawned successfully");
          sendBackendServiceState({ ready: true, respawnPending: false });
        } else {
          global.logBackend("[Bridge] HTTP backend respawn failed; will retry");
          scheduleBackendHttpRespawn("ready probe failed");
        }
      })
      .catch((err) => {
        global.logBackend("[Bridge] HTTP backend respawn error:", err?.message || String(err));
        scheduleBackendHttpRespawn(String(err?.message || err));
      });
  }, delayMs);
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
  const nextPayload = {
    ...(payload || {}),
    jobId: normalizeBackendJobId(payload?.jobId),
  };
  mainWin.webContents.send("json-path", nextPayload);
}

function sendJsonDataPayload(payload) {
  if (!payload || typeof payload !== "object") return;

  const jobMapKey = getBackendJobMapKey(payload?.jobId);

  const nextPayload = {
    ...payload,
    jobId: normalizeBackendJobId(payload.jobId),
    processedPackets: Number(payload.processedPackets) || 0,
    totalPackets: Number(payload.totalPackets) || 0,
    complete: Boolean(payload.complete),
  };

  const flushNow = () => {
    const existingTimer = jsonDataEmitTimerByJob.get(jobMapKey);
    if (existingTimer) {
      clearTimeout(existingTimer);
      jsonDataEmitTimerByJob.delete(jobMapKey);
    }

    const pendingPayload = pendingJsonDataPayloadByJob.get(jobMapKey);
    if (!pendingPayload) {
      return;
    }

    const mainWin = getMainWindow();
    if (!mainWin) {
      pendingJsonDataPayloadByJob.delete(jobMapKey);
      return;
    }

    const payloadToSend = pendingPayload;
    pendingJsonDataPayloadByJob.delete(jobMapKey);
    mainWin.webContents.send("json-data", payloadToSend);
    lastJsonDataEmitAtMsByJob.set(jobMapKey, Date.now());
    lastJsonDataEmitProcessedPacketsByJob.set(
      jobMapKey,
      Number(payloadToSend.processedPackets) || 0,
    );
  };

  if (nextPayload.complete) {
    pendingJsonDataPayloadByJob.set(jobMapKey, nextPayload);
    flushNow();
    return;
  }

  pendingJsonDataPayloadByJob.set(jobMapKey, nextPayload);
  const nowMs = Date.now();
  const previousEmitAt = Number(lastJsonDataEmitAtMsByJob.get(jobMapKey)) || 0;
  const previousProcessed =
    Number(lastJsonDataEmitProcessedPacketsByJob.get(jobMapKey)) || 0;
  const elapsedMs = Math.max(0, nowMs - previousEmitAt);
  const packetDelta = Math.max(
    0,
    nextPayload.processedPackets - previousProcessed,
  );
  const chunkSize = Number(nextPayload.chunkSize) || DEFAULT_HOST_CHUNK_SIZE;
  const minPacketDelta = Math.max(
    JSON_DATA_EMIT_MIN_PACKET_DELTA,
    chunkSize * 4,
  );
  if (elapsedMs >= currentJsonDataEmitMinIntervalMs || packetDelta >= minPacketDelta) {
    flushNow();
    return;
  }

  if (!jsonDataEmitTimerByJob.has(jobMapKey)) {
    const waitMs = Math.max(0, currentJsonDataEmitMinIntervalMs - elapsedMs);
    const timer = setTimeout(() => {
      flushNow();
    }, waitMs);
    jsonDataEmitTimerByJob.set(jobMapKey, timer);
  }
}

function sendBackendPcapSource(payload) {
  const mainWin = getMainWindow();
  if (!mainWin) return;
  const nextPayload = {
    ...(payload || {}),
    jobId: normalizeBackendJobId(payload?.jobId),
  };
  mainWin.webContents.send("backend-pcap-source", nextPayload);
}

function sanitizeBase64PcapInput(value) {
  if (typeof value !== "string") return "";
  return value.replace(/\s+/g, "").trim();
}

function buildPcapSourcePayloadFromBuffer(buffer, fileName) {
  if (!Buffer.isBuffer(buffer)) return null;
  const normalizedName =
    typeof fileName === "string" && fileName.trim() ? fileName.trim() : "capture.pcap";
  return {
    fileName: path.basename(normalizedName),
    encoding: "base64",
    data: buffer.toString("base64"),
    byteLength: buffer.length,
  };
}

function emitPcapSourceFromFile(filePath, jobId = "") {
  const fileBuffer = fs.readFileSync(filePath);
  const payload = buildPcapSourcePayloadFromBuffer(fileBuffer, path.basename(filePath));
  if (payload) {
    sendBackendPcapSource({
      ...payload,
      jobId: normalizeBackendJobId(jobId),
    });
  }
  return payload;
}

function writeSessionPcapTempFile(sessionPcap) {
  const normalizedData = sanitizeBase64PcapInput(sessionPcap?.data);
  if (!normalizedData) {
    throw new Error("Session PCAP payload is missing base64 data");
  }

  let fileBuffer;
  try {
    fileBuffer = Buffer.from(normalizedData, "base64");
  } catch (_err) {
    throw new Error("Session PCAP payload is not valid base64");
  }

  if (!fileBuffer || fileBuffer.length === 0) {
    throw new Error("Session PCAP payload decoded to an empty buffer");
  }

  const requestedName =
    typeof sessionPcap?.fileName === "string" && sessionPcap.fileName.trim()
      ? path.basename(sessionPcap.fileName.trim())
      : "session-reprocess.pcap";
  const hasKnownExtension = /\.(pcap|pcapng)$/i.test(requestedName);
  const tempName =
    `pss-reprocess-${Date.now()}-${Math.random().toString(16).slice(2)}` +
    (hasKnownExtension ? `-${requestedName}` : `-${requestedName}.pcap`);
  const tempPath = path.join(systemTempDir, tempName);
  fs.writeFileSync(tempPath, fileBuffer);
  return {
    tempPath,
    payload: buildPcapSourcePayloadFromBuffer(fileBuffer, requestedName),
  };
}

function parseBridgeProgressLine(line, hostChunkSize = DEFAULT_HOST_CHUNK_SIZE) {
  if (!line || !line.includes("[Bridge]")) return null;
  const pathMatch = line.match(/path=([^\s]+)/);
  const processedMatch = line.match(/processed=(\d+)/);
  const totalMatch = line.match(/total=(\d+)/);
  const finalMatch = line.match(/final=(\d+)/);
  const jobIdMatch = line.match(/jobId=([^\s]+)/);
  if (!pathMatch) return null;

  return {
    path: pathMatch[1],
    jobId: jobIdMatch ? String(jobIdMatch[1] || "").trim() : "",
    processedPackets: processedMatch ? Number(processedMatch[1]) : 0,
    totalPackets: totalMatch ? Number(totalMatch[1]) : 0,
    complete: finalMatch ? finalMatch[1] === "1" : false,
    chunkSize: hostChunkSize,
  };
}

function scanChunkSnapshots(outputDirPath, sentSnapshotPaths, hostChunkSize = DEFAULT_HOST_CHUNK_SIZE) {
  if (!outputDirPath || !fs.existsSync(outputDirPath)) return [];
  const entries = fs
    .readdirSync(outputDirPath)
    .filter((name) => /^hosts-\d+\.json$/.test(name))
    .sort((left, right) => {
      const leftCount = Number(left.match(/hosts-(\d+)\.json/)?.[1] || 0);
      const rightCount = Number(right.match(/hosts-(\d+)\.json/)?.[1] || 0);
      return leftCount - rightCount;
    });

  const unsent = [];
  entries.forEach((entryName) => {
    const fullPath = path.join(outputDirPath, entryName);
    if (sentSnapshotPaths.has(fullPath)) return;
    sentSnapshotPaths.add(fullPath);
    const processedPackets = Number(entryName.match(/hosts-(\d+)\.json/)?.[1] || 0);
    unsent.push({
      path: fullPath,
      processedPackets,
      totalPackets: 0,
      complete: false,
      chunkSize: hostChunkSize,
    });
  });
  return unsent;
}

async function runBackendCommandInternal(filename, useLLM, options = {}) {
  const {
    pcapSourcePayload: providedPcapSourcePayload = null,
    hostChunkSize: requestedHostChunkSize = DEFAULT_HOST_CHUNK_SIZE,
    workerThreads: requestedWorkerThreads = 0,
    backendOptions = {},
    jobId: requestedJobId = "",
    allowUnknownMagicLoad = false,
  } = options;
  const backendJobId = normalizeBackendJobId(requestedJobId) || createBackendJobId("backend");
  const concurrentRunDetected = activeBackendRunCount > 0;
  activeBackendRunCount += 1;

  try {
    const hostChunkSize = normalizeHostChunkSize(requestedHostChunkSize);
    const parsedWorkerThreads = Number.parseInt(String(requestedWorkerThreads || 0), 10);
    const workerThreads = Number.isFinite(parsedWorkerThreads) && parsedWorkerThreads > 0
      ? parsedWorkerThreads
      : 0;
    const normalizedTransport = applyBackendTransportOptions(backendOptions);
    global.logBackend(`[Bridge] Received pcap: ${filename}`);
    const runtime = resolveBackendRuntime();
    const {
      backendScriptPath,
      snitchExePath,
      snitchExecutableCandidates,
      hasBundledBackendExe,
      usePythonBackend,
      backendCommandPath,
    } = runtime;

    if (usePythonBackend) {
      global.logBackend(`[Bridge] Using Python backend script at: ${backendScriptPath}`);
    } else if (hasBundledBackendExe) {
      global.logBackend(`[Bridge] Found snitch executable at: ${snitchExePath}`);
    } else {
      global.logBackend(`[Bridge] Snitch executable not found at: ${snitchExePath}`);
      global.logBackend(
        `[Bridge] Checked executable candidates: ${(snitchExecutableCandidates || []).join(", ")}`,
      );
      sendError(
        "[Bridge] Snitch executable not found! Please ensure it is included in the resources.",
      );
      return {
        jobId: backendJobId,
        success: false,
        error: "Snitch executable not found",
      };
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
      if (filename.endsWith(".psb")) {
        global.logBackend("[Bridge] File looks like a gzip-compressed BSON file (.psb session)!");
        isSession = true;
        isCompressedSession = true;
        sessionCompression = "bson-gzip";
      } else {
        global.logBackend("[Bridge] File looks like a gzip-compressed file, this is probably a .pss.gz session file!");
        isSession = true;
        isCompressedSession = true;
        sessionCompression = "gzip";
      }
    } else if (fileForMagic.startsWith("\xd4\xc3\xb2\xa1")) {
      global.logBackend("[Bridge] File looks like PCAP file (microsecond resolution)");
      isPCAP = true;
    } else if (fileForMagic.startsWith("\x0a\x0d\x0d\x0a")) {
      global.logBackend("[Bridge] File looks like PCAPNG file (little-endian byte order)");
      isPCAP = true;
    } else if (fileForMagic.startsWith("\xa1\xb2\xc3\xd4")) {
      global.logBackend("[Bridge] File looks like PCAP file (big-endian with nanosecond resolution)");
      isPCAP = true;
    } else if (fileForMagic.startsWith("\x50\x41\x43\x45\x54\x43\x4f\x4e\x46")) {
      global.logBackend("[Bridge] File looks like PCAPNG file (with a Section Header Block)");
      isPCAP = true;
    } else if (fileForMagic.startsWith("\x4d\x3c\x2b\x1a")) {
      global.logBackend("[Bridge] File looks like PCAP file (reversed byte order)");
      isPCAP = true;
    } else if (fileForMagic.startsWith("\xc3\xd4\xa1\xb2")) {
      global.logBackend("[Bridge] File looks like PCAP file (reversed byte order and nanosecond resolution)");
      isPCAP = true;
    } else {
      if (!allowUnknownMagicLoad) {
        const unknownMagicMessage =
          "[Bridge] File type is unknown based on magic. Please try again or return to the session picker.";
        global.logBackend(unknownMagicMessage);
        sendError(unknownMagicMessage);
        return {
          jobId: backendJobId,
          success: false,
          error: "Unknown file type based on magic",
        };
      }
      global.logBackend(
        "[Bridge] File type is unknown based on magic, but the retry path requested a forced load.",
      );
      isPCAP = true;
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
            if (sessionCompression === "bson-gzip") {
              if (!BSON) {
                sendError("[Bridge] Cannot load BSON session (.psb) without the bson module!");
                return {
                  jobId: backendJobId,
                  success: false,
                  error: "Cannot load BSON session without bson module",
                };
              }
              const gunzipped = await gunzipAsync(compressedBuffer);
              const doc = BSON.deserialize(gunzipped);
              decompressedBuffer = Buffer.from(JSON.stringify(doc), "utf8");
            } else if (sessionCompression === "gzip") {
              decompressedBuffer = await gunzipAsync(compressedBuffer);
            } else {
              let lzmaNative = null;
              try { lzmaNative = require("lzma-native"); } catch { }
              if (!lzmaNative) {
                sendError("[Bridge] Cannot load xz-compressed session (.pss / .json.xz) without lzma-native support!");
                return {
                  jobId: backendJobId,
                  success: false,
                  error: "Cannot load xz-compressed session without lzma-native support",
                };
              }
              decompressedBuffer = await lzmaNative.decompress(compressedBuffer);
            }
            const tempPath = path.join(systemTempDir, `pss-session-${Date.now()}.json`);
            fs.writeFileSync(tempPath, decompressedBuffer);
            sessionJsonPath = tempPath;
            global.logBackend(`[Bridge] Decompressed session to temp file: ${tempPath}`);
          } catch (err) {
            sendError(`[Bridge] Failed to decompress session file: ${err.message}`);
            return {
              jobId: backendJobId,
              success: false,
              error: err.message,
            };
          }
        }
        sendJsonPathPayload({
          jobId: backendJobId,
          path: sessionJsonPath,
          processedPackets: 0,
          totalPackets: 0,
          complete: true,
          chunkSize: hostChunkSize,
        });
      }
      return {
        jobId: backendJobId,
        success: true,
        stdout: "",
        pcapSource: null,
      };
    }

    let pcapSourcePayload = providedPcapSourcePayload;
    if (!pcapSourcePayload) {
      try {
        pcapSourcePayload = emitPcapSourceFromFile(filename, backendJobId);
      } catch (error) {
        global.logBackend(`[Bridge] Failed to prepare source PCAP payload: ${error.message}`);
      }
    }

    const canUseHttpForThisRun = !normalizedTransport.forceLegacySpawn && !concurrentRunDetected;
    if (canUseHttpForThisRun) {
      const httpResult = await runBackendCommandViaHttp(filename, {
        hostChunkSize,
        workerThreads,
        pcapSourcePayload,
        useHttpDataSnapshots: normalizedTransport.useHttpDataSnapshots,
        jobId: backendJobId,
        wifiKeys: options.wifiKeys,
      });
      if (httpResult?.success) {
        global.logBackend("[Bridge] Backend completed using HTTP service mode");
        return {
          ...httpResult,
          jobId: normalizeBackendJobId(httpResult?.jobId) || backendJobId,
        };
      }
      if (!httpResult?.fallbackRecommended) {
        return {
          jobId: normalizeBackendJobId(httpResult?.jobId) || backendJobId,
          success: false,
          stdout: httpResult?.stdout || "",
          error: httpResult?.error || "HTTP backend processing failed",
          pcapSource: pcapSourcePayload,
        };
      }
      global.logBackend(
        `[Bridge] HTTP backend unavailable (${httpResult?.error || "unknown error"}); using legacy spawn mode`,
      );
    } else {
      if (concurrentRunDetected && !normalizedTransport.forceLegacySpawn) {
        global.logBackend("[Bridge] Concurrent backend run detected; using legacy backend spawn mode for job isolation");
      } else {
        global.logBackend("[Bridge] Force-legacy setting enabled; using legacy backend spawn mode");
      }
    }

    const jobOutputDir = path.join(testcaseOutputDir, backendJobId);
    // The legacy spawn path can't ride along with the HTTP service's
    // runtime config update, so when wifi keys are supplied we write
    // them to a per-job JSON file and pass --wifi-keys-file so the
    // python backend can install them at startup. Without this, a
    // background rerun triggered while the first backend run is still
    // releasing its handles (concurrent-run guard) would silently drop
    // the keys and produce undecrypted 802.11 frames.
    //
    // The keys file is staged in testcaseOutputDir (sibling of
    // jobOutputDir) so the jobOutputDir wipe below doesn't delete it
    // — previously the wifi-keys file lived inside jobOutputDir and
    // the wipe on second/later runs removed it before the backend
    // could read it, which made decryption silently no-op.
    let wifiKeysFilePath = null;
    if (Array.isArray(options.wifiKeys) && options.wifiKeys.length > 0) {
      try {
        fs.mkdirSync(testcaseOutputDir, { recursive: true });
        wifiKeysFilePath = path.join(
          testcaseOutputDir,
          `wifi-keys-${backendJobId}.json`,
        );
        fs.writeFileSync(
          wifiKeysFilePath,
          JSON.stringify(options.wifiKeys),
          "utf8",
        );
      } catch (writeError) {
        global.logBackend(
          `[Bridge] Failed to stage wifi keys for legacy spawn: ${writeError.message}`,
        );
        wifiKeysFilePath = null;
      }
    }
    const legacyExtraArgs = wifiKeysFilePath
      ? ["--wifi-keys-file", wifiKeysFilePath]
      : [];
    const backendArgs = usePythonBackend
      ? [backendScriptPath, filename, "-v", "-a", "-o", jobOutputDir, "--host-chunk-size", String(hostChunkSize), "--worker-threads", String(workerThreads), ...legacyExtraArgs]
      : [filename, "-v", "-a", "-o", jobOutputDir, "--host-chunk-size", String(hostChunkSize), "--worker-threads", String(workerThreads), ...legacyExtraArgs];
    // Always start with a clean output directory so snitch never hits the
    // interactive overwrite prompt on second (and later) runs.
    if (fs.existsSync(jobOutputDir)) {
      fs.rmSync(jobOutputDir, { recursive: true, force: true });
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
        env: buildBackendProcessEnv(),
      });

      const snapshotScanTimer = setInterval(() => {
        const snapshotPayloads = scanChunkSnapshots(jobOutputDir, sentSnapshotPaths, hostChunkSize);
        // thisis to avoid exceeding our disk inode limit on large captures
        // we remove the oldest snapshot file after sending the latest one to the renderer
        // first we check if it has been used (sent) already
        // we should then give it some time to make sure the frontend has caught up before
        // removing it.
        if (entries[0] && sentSnapshotPaths.has(path.join(jobOutputDir, entries[0]))) {
          // give some time for the frontend to catch up before removing
          setTimeout(() => {
            removePacketsChunkFromFS(path.join(jobOutputDir, entries[0]));
          }, 10000);
        }
        snapshotPayloads.forEach((payload) => {
          latestProcessedPackets = Math.max(
            latestProcessedPackets,
            payload.processedPackets,
          );
          payload.totalPackets = parsedTotalPackets;
          payload.jobId = backendJobId;
          sendJsonPathPayload(payload);
        });
      }, 600);

      const handleProgressText = (text) => {
        if (!text) return;
        const progressPayload = parseBridgeProgressLine(text, hostChunkSize);
        if (progressPayload) {
          if (!normalizeBackendJobId(progressPayload.jobId)) {
            progressPayload.jobId = backendJobId;
          }
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
        resolve({
          jobId: backendJobId,
          success: false,
          stdout: stdoutBuffer,
          error: error?.message || "Backend execution error",
          pcapSource: pcapSourcePayload,
        });
      });

      backendProc.on("close", (code) => {
        clearInterval(snapshotScanTimer);

        const trailingSnapshots = scanChunkSnapshots(jobOutputDir, sentSnapshotPaths, hostChunkSize);
        // thisis to avoid exceeding our disk inode limit on large captures
        // we remove the oldest snapshot file after sending the latest one to the renderer
        // first we check if it has been used (sent) already
        // we should then give it some time to make sure the frontend has caught up before
        // removing it.
        if (entries[0] && sentSnapshotPaths.has(path.join(jobOutputDir, entries[0]))) {
          // give some time for the frontend to catch up before removing
          setTimeout(() => {
            removePacketsChunkFromFS(path.join(jobOutputDir, entries[0]));
          }, 10000);
        }
        trailingSnapshots.forEach((payload) => {
          latestProcessedPackets = Math.max(
            latestProcessedPackets,
            payload.processedPackets,
          );
          payload.totalPackets = parsedTotalPackets;
          payload.jobId = backendJobId;
          sendJsonPathPayload(payload);
        });
        if (stderrBuffer.includes("No such file or directory")) {
          sendError("[Bridge] Backend execution error! File not found.  Please be sure the last pcap is not still being processed.");
          resolve({
            jobId: backendJobId,
            success: false,
            stdout: stdoutBuffer,
            error: "Backend execution error: PCAP not found! Wait for processing to complete before requesting a reprocess.",
            pcapSource: pcapSourcePayload,
          });
          return;
        }
        if (stdoutBuffer.includes("Ollama")) {
          sendError("[Bridge] Backend LLM generation error!");
        }
        if (stderrBuffer.includes("Disk quota exceeded")) {
          sendError("[Bridge] Backend execution error! Disk quota exceeded.  Apparently PacketSnitch does not scale as well as we thought.  Killingg bckend process to avoid further issues.");
          resolve({
            jobId: backendJobId,
            success: false,
            stdout: stdoutBuffer,
            error: "Backend execution error: Disk quota exceeded!",
            pcapSource: pcapSourcePayload,
          });
          return;
        }
        if (code !== 0) {
          if (stderrBuffer.includes("No module named 'cryptography'")) {
            sendError(
              "[Bridge] Backend is missing Python module 'cryptography'. Rebuild backend artifacts (npm run build-backend) or install backend requirements before launching.",
            );
            resolve({
              jobId: backendJobId,
              success: false,
              stdout: stdoutBuffer,
              error: "Backend dependency missing: cryptography",
              pcapSource: pcapSourcePayload,
            });
            return;
          }
          if (stderrBuffer.includes("supported capture file")) {
            sendError("[Bridge] Unsupported file format!");
          } else {
            sendError(`[Bridge] Backend execution error! Exit code ${code}`);
          }
          resolve({
            jobId: backendJobId,
            success: false,
            stdout: stdoutBuffer,
            error: `Backend exited with code ${code}`,
            pcapSource: pcapSourcePayload,
          });
          return;
        }

        const finalHostsPath = path.join(jobOutputDir, "hosts.json");
        if (fs.existsSync(finalHostsPath)) {
          sendJsonPathPayload({
            jobId: backendJobId,
            path: finalHostsPath,
            processedPackets: Math.max(latestProcessedPackets, parsedTotalPackets),
            totalPackets: parsedTotalPackets,
            complete: true,
            chunkSize: hostChunkSize,
          });
        } else {
          sendError("[Bridge] hosts.json not found after backend execution!");
        }

        // Clean up the staged wifi keys file now that the backend has
        // finished.  It's owned by this job and isn't needed again.
        if (wifiKeysFilePath && fs.existsSync(wifiKeysFilePath)) {
          try {
            fs.unlinkSync(wifiKeysFilePath);
          } catch (cleanupError) {
            global.logBackend(
              `[Bridge] Failed to remove staged wifi keys file ${wifiKeysFilePath}: ${cleanupError.message}`,
            );
          }
        }

        resolve({
          jobId: backendJobId,
          success: true,
          stdout: stdoutBuffer,
          pcapSource: pcapSourcePayload,
        });
      });

      global.logBackend("[Bridge] Backend started");
    });
  } finally {
    activeBackendRunCount = Math.max(0, activeBackendRunCount - 1);
  }
}

ipcMain.handle("run-backend-command", async (_event, filename, useLLM, hostChunkSize, workerThreads, backendOptions, jobId, wifiKeys) => {
  return runBackendCommandInternal(filename, useLLM, {
    hostChunkSize,
    workerThreads,
    backendOptions,
    jobId,
    wifiKeys: Array.isArray(wifiKeys) ? wifiKeys : null,
  });
});

ipcMain.handle("init-backend-service", async (_event, backendOptions) => {
  const normalizedTransport = applyBackendTransportOptions(backendOptions);
  if (normalizedTransport.forceLegacySpawn) {
    return {
      success: true,
      mode: "legacy",
      ready: false,
      host: normalizedTransport.tcpHost,
      port: normalizedTransport.tcpPort,
    };
  }

  const ready = await ensureBackendHttpServerReady();
  return {
    success: Boolean(ready),
    mode: "http",
    ready: Boolean(ready),
    host: currentBackendHttpHost,
    port: currentBackendHttpPort,
  };
});

ipcMain.handle("run-backend-command-from-session", async (_event, sessionPcap, useLLM, hostChunkSize, workerThreads, backendOptions, jobId, wifiKeys) => {
  const backendJobId = normalizeBackendJobId(jobId) || createBackendJobId("backend");
  let tempPathForCleanup = "";
  try {
    const prepared = writeSessionPcapTempFile(sessionPcap);
    tempPathForCleanup = prepared.tempPath;
    if (prepared.payload) {
      sendBackendPcapSource({
        ...prepared.payload,
        jobId: backendJobId,
      });
    }
    const result = await runBackendCommandInternal(prepared.tempPath, useLLM, {
      pcapSourcePayload: prepared.payload,
      hostChunkSize,
      workerThreads,
      backendOptions,
      jobId: backendJobId,
      // Pass wifi keys straight through to the backend so the first packet
      // the backend decrypts can use them — no need to wait for a separate
      // set-runtime-config round-trip after the run starts.
      wifiKeys: Array.isArray(wifiKeys) ? wifiKeys : null,
    });
    return result;
  } catch (error) {
    sendError("[Bridge] Unable to run backend from session PCAP data");
    return {
      jobId: backendJobId,
      success: false,
      error: error?.message || "Unable to run backend from session PCAP",
    };
  } finally {
    if (tempPathForCleanup) {
      try {
        fs.unlinkSync(tempPathForCleanup);
      } catch (_err) {
        // ignore cleanup errors for temp files
      }
    }
  }
});

ipcMain.handle("control-backend-service", async (_event, action) => {
  if (action === "stop-processing") {
    return requestBackendStopProcessing();
  }
  if (action === "shutdown") {
    return requestBackendShutdown();
  }
  if (action && typeof action === "object" && action.action === "set-runtime-config") {
    const payload = { ...action };
    delete payload.action;
    return sendBackendControlCommand("set-runtime-config", 5000, payload);
  }
  return {
    success: false,
    error: "Unsupported backend control action",
  };
});

ipcMain.handle("set-backend-wifi-keys", async (_event, wifiKeys) => {
  const keys = Array.isArray(wifiKeys) ? wifiKeys : [];
  if (!keys.length) {
    return {
      success: true,
      accepted: 0,
      message: "No Wi-Fi keys supplied; backend will not decrypt 802.11 payloads",
    };
  }
  return sendBackendControlCommand("set-runtime-config", 5000, { wifiKeys: keys });
});

ipcMain.handle("lookup-backend-geoip", async (_event, ipAddress, options = {}) => {
  const optionsSource = options && typeof options === "object" ? options : {};
  const normalizedTransport = applyBackendTransportOptions(
    optionsSource.backendOptions,
  );
  if (normalizedTransport.forceLegacySpawn) {
    return {
      success: false,
      error: "Backend GeoIP lookup requires HTTP backend mode",
      mode: "legacy",
    };
  }

  const ready = await ensureBackendHttpServerReady();
  if (!ready) {
    return {
      success: false,
      error: "Backend HTTP service unavailable",
      mode: "http",
    };
  }

  return requestSnitchHttpBackendGeoip(ipAddress, {
    side: optionsSource.side,
    host: currentBackendHttpHost,
    port: currentBackendHttpPort,
    timeoutMs: Number(optionsSource.timeoutMs) > 0
      ? Number(optionsSource.timeoutMs)
      : 3000,
  });
});

ipcMain.handle("lookup-backend-whois", async (_event, ipAddress, options = {}) => {
  const optionsSource = options && typeof options === "object" ? options : {};
  const normalizedTransport = applyBackendTransportOptions(
    optionsSource.backendOptions,
  );
  if (normalizedTransport.forceLegacySpawn) {
    return {
      success: false,
      error: "Backend WHOIS lookup requires HTTP backend mode",
      mode: "legacy",
    };
  }

  const ready = await ensureBackendHttpServerReady();
  if (!ready) {
    return {
      success: false,
      error: "Backend HTTP service unavailable",
      mode: "http",
    };
  }

  return requestSnitchHttpBackendWhois(ipAddress, {
    host: currentBackendHttpHost,
    port: currentBackendHttpPort,
    timeoutMs: Number(optionsSource.timeoutMs) > 0
      ? Number(optionsSource.timeoutMs)
      : 7000,
  });
});

ipcMain.handle("lookup-backend-ipsum", async (_event, ipAddress, options = {}) => {
  const optionsSource = options && typeof options === "object" ? options : {};
  const normalizedTransport = applyBackendTransportOptions(
    optionsSource.backendOptions,
  );
  if (normalizedTransport.forceLegacySpawn) {
    return {
      success: false,
      error: "Backend IPSum lookup requires HTTP backend mode",
      mode: "legacy",
    };
  }

  const ready = await ensureBackendHttpServerReady();
  if (!ready) {
    return {
      success: false,
      error: "Backend HTTP service unavailable",
      mode: "http",
    };
  }

  return requestSnitchHttpBackendIpsum(ipAddress, {
    host: currentBackendHttpHost,
    port: currentBackendHttpPort,
    timeoutMs: Number(optionsSource.timeoutMs) > 0
      ? Number(optionsSource.timeoutMs)
      : 10000,
  });
});

ipcMain.handle("lookup-backend-tor", async (_event, ipAddress, options = {}) => {
  const optionsSource = options && typeof options === "object" ? options : {};
  const normalizedTransport = applyBackendTransportOptions(
    optionsSource.backendOptions,
  );
  if (normalizedTransport.forceLegacySpawn) {
    return {
      success: false,
      error: "Backend Tor lookup requires HTTP backend mode",
      mode: "legacy",
    };
  }

  const ready = await ensureBackendHttpServerReady();
  if (!ready) {
    return {
      success: false,
      error: "Backend HTTP service unavailable",
      mode: "http",
    };
  }

  return requestSnitchHttpBackendTor(ipAddress, {
    host: currentBackendHttpHost,
    port: currentBackendHttpPort,
    timeoutMs: Number(optionsSource.timeoutMs) > 0
      ? Number(optionsSource.timeoutMs)
      : 7000,
  });
});

ipcMain.handle("lookup-backend-shodan", async (_event, ipAddress, options = {}) => {
  const optionsSource = options && typeof options === "object" ? options : {};
  const normalizedTransport = applyBackendTransportOptions(
    optionsSource.backendOptions,
  );
  if (normalizedTransport.forceLegacySpawn) {
    return {
      success: false,
      error: "Backend Shodan lookup requires HTTP backend mode",
      mode: "legacy",
    };
  }

  const ready = await ensureBackendHttpServerReady();
  if (!ready) {
    return {
      success: false,
      error: "Backend HTTP service unavailable",
      mode: "http",
    };
  }

  return requestSnitchHttpBackendShodan(ipAddress, {
    host: currentBackendHttpHost,
    port: currentBackendHttpPort,
    timeoutMs: Number(optionsSource.timeoutMs) > 0
      ? Number(optionsSource.timeoutMs)
      : 8000,
  });
});

ipcMain.handle("lookup-backend-virustotal", async (_event, lookupValue, options = {}) => {
  const optionsSource = options && typeof options === "object" ? options : {};
  const normalizedTransport = applyBackendTransportOptions(
    optionsSource.backendOptions,
  );
  if (normalizedTransport.forceLegacySpawn) {
    return {
      success: false,
      error: "Backend VirusTotal lookup requires HTTP backend mode",
      mode: "legacy",
    };
  }

  const ready = await ensureBackendHttpServerReady();
  if (!ready) {
    return {
      success: false,
      error: "Backend HTTP service unavailable",
      mode: "http",
    };
  }

  return requestSnitchHttpBackendVirusTotal(lookupValue, {
    lookupType: optionsSource.lookupType,
    apiKey: optionsSource.apiKey,
    diagnosticOnly: Boolean(optionsSource.diagnosticOnly),
    host: currentBackendHttpHost,
    port: currentBackendHttpPort,
    timeoutMs: Number(optionsSource.timeoutMs) > 0
      ? Number(optionsSource.timeoutMs)
      : 12000,
  });
});

module.exports = {
  shutdownHttpBackendService,
  ensureBackendHttpServerReady,
  primeBackendHttpServer,
  applyBackendTransportOptions,
  reclaimExistingBackendService,
  requestBackendStopProcessing,
  requestBackendShutdown,
  getBackendServiceDiagnostics,
  requestSnitchHttpBackendGeoip,
  requestSnitchHttpBackendWhois,
  requestSnitchHttpBackendIpsum,
  requestSnitchHttpBackendTor,
  requestSnitchHttpBackendVirusTotal,
  // Backward-compatible aliases for existing imports in main process code.
  shutdownTcpBackendService: shutdownHttpBackendService,
  ensureBackendTcpServerReady: ensureBackendHttpServerReady,
};
