// Centralizes renderer activity logging and duplicate-suppression helpers.

let lastViewMode = "";
const CONSOLE_DUPLICATE_WINDOW_MS = 5000;

// When true, ``addActivityLogEntry`` short-circuits so neither the in-memory
// log panel nor the on-disk log file receives new entries. Used by the
// session-clear / blank-template load path in ``main-frontend.js`` to avoid
// spamming the log with "0 packets" / "User opened X view" noise while the
// renderer tears down the previous session and indexes the empty template.
// Genuine errors raised inside the suppressed window still reach the console
// via the un-hooked ``consoleRef`` calls — only the redirected log panel/file
// writes are gated.
let logEntrySuppressed = false;

function setLogEntrySuppressed(value) {
  logEntrySuppressed = Boolean(value);
}

function initializeLogging({
  logapi = null,
  documentRef = document,
  consoleRef = console,
}) {
  let activityLogPath = "Unavailable";
  const activityLogEntries = [];
  let lastConsoleMessage = "";
  let lastConsoleMessageTs = 0;

  function renderActivityLogEntries(searchText = "") {
    const entriesEl = documentRef.getElementById("activity-log-entries");
    if (!entriesEl) return;
    entriesEl.replaceChildren();
    const normalizedSearch = searchText.trim().toLowerCase();
    activityLogEntries
      .filter((entry) =>
        normalizedSearch
          ? entry.message.toLowerCase().includes(normalizedSearch)
          : true,
      )
      .forEach((entry) => {
        const row = documentRef.createElement("div");
        row.className = "activity-log-entry";
        row.textContent = entry.message;
        entriesEl.appendChild(row);
      });
  }

  function syncActivityLogPath(result) {
    if (result && result.path) {
      activityLogPath = result.path;
      const pathEl = documentRef.getElementById("activity-log-path");
      if (pathEl) {
        pathEl.textContent = `Log file: ${activityLogPath}`;
      }
    }
  }

  function addActivityLogEntry(message, writeToFile = true) {
    if (logEntrySuppressed) return;
    if (typeof message !== "string" || message.trim() === "") return;
    const normalizedMessage = message.trim();
    activityLogEntries.unshift({ message: normalizedMessage });
    renderActivityLogEntries(
      documentRef.getElementById("activity-log-search")?.value || "",
    );
    if (writeToFile && logapi) {
      logapi.append(normalizedMessage).then(syncActivityLogPath);
    }
  }

  function writeLogEntry(message) {
    const matchViewMode = message.match(/User opened (.+) view/);
    if (matchViewMode) {
      const viewMode = matchViewMode[1];
      if (viewMode !== lastViewMode) {
        lastViewMode = viewMode;
        const stampedMessage = `[${new Date().toISOString()}] [GUI][Renderer]${message}`;
        addActivityLogEntry(stampedMessage);
        return;
      }
    } else {
      if (message.startsWith("[")) {
        const stampedMessage = `[${new Date().toISOString()}] [GUI][Renderer]${message}`;
        addActivityLogEntry(stampedMessage);
        return;
      }

      const stampedMessage = `[${new Date().toISOString()}] [GUI][Renderer][MainFrontend] ${message}`;
      addActivityLogEntry(stampedMessage);
    }
  }

  function writeConsoleLogEntry(message) {
    if (message.includes("0.0.0.0")) {
      // this is the dummy structure packet
      return;
    }
    if (message.length > 110) {
      message = message.substring(0, 110) + " [truncated]";
    }

    const now = Date.now();
    if (
      message === lastConsoleMessage &&
      now - lastConsoleMessageTs < CONSOLE_DUPLICATE_WINDOW_MS
    ) {
      return;
    }
    lastConsoleMessage = message;
    lastConsoleMessageTs = now;

    const stampedMessage = `[${new Date().toISOString()}] [Console][Renderer] ${message}`;
    addActivityLogEntry(stampedMessage);
  }

  function writeBackendErrorLogEntry(message) {
    const stampedMessage = `[${new Date().toISOString()}] [Console][Snitch]${message}`;
    addActivityLogEntry(stampedMessage);
  }

  function logErrorEntry(context, error) {
    const errorDetails =
      error && typeof error === "object" && "message" in error
        ? error.message
        : String(error);
    writeLogEntry(`Error context=${context} details="${errorDetails}"`);
  }

  function formatConsoleValue(value) {
    if (value instanceof Error) {
      return value.stack || value.message;
    }
    if (typeof value === "string") {
      return value;
    }
    if (typeof value === "undefined") {
      return "undefined";
    }
    try {
      return JSON.stringify(value);
    } catch (_error) {
      return String(value);
    }
  }

  function formatConsoleArgs(args) {
    return args.map((value) => formatConsoleValue(value)).join(" ");
  }

  const originalConsoleLog = consoleRef.log.bind(consoleRef);
  consoleRef.log = (...args) => {
    originalConsoleLog(...args);
    const message = formatConsoleArgs(args);
    if (message) {
      writeConsoleLogEntry(message);
    }
  };

  const originalConsoleError = consoleRef.error.bind(consoleRef);
  consoleRef.error = (...args) => {
    originalConsoleError(...args);
    const message = formatConsoleArgs(args);
    if (message) {
      writeConsoleLogEntry(message);
    }
  };

  async function initializeActivityLog() {
    const pathEl = documentRef.getElementById("activity-log-path");
    const panelEl = documentRef.getElementById("activity-log-panel");
    const searchEl = documentRef.getElementById("activity-log-search");
    const logBtn = documentRef.getElementById("log-btn");
    const closeBtn = documentRef.getElementById("close-log-btn");
    if (logapi) {
      try {
        const [path, entries] = await Promise.all([
          logapi.getPath(),
          logapi.getEntries(),
        ]);
        if (Array.isArray(entries)) {
          activityLogEntries.splice(0);
          entries.forEach((entry) => {
            activityLogEntries.push({ message: entry });
          });
          renderActivityLogEntries();
        }
        if (path) {
          activityLogPath = path;
          pathEl.textContent = `Log file: ${activityLogPath}`;
        }
        logapi.onEntry((entry) => {
          addActivityLogEntry(entry, false);
        });
      } catch (error) {
        logErrorEntry("activity-log-init", error);
      }
    }
    if (logBtn && panelEl) {
      logBtn.addEventListener("click", () => {
        if (panelEl.style.display === "block") {
          panelEl.style.display = "none";
        } else {
          panelEl.style.display = "block";
        }
      });
    }
    if (closeBtn && panelEl) {
      closeBtn.addEventListener("click", () => {
        panelEl.style.display = "none";
      });
    }
    if (searchEl) {
      searchEl.addEventListener("input", (event) => {
        renderActivityLogEntries(event.target.value);
      });
    }
    writeLogEntry("PacketSnitch UI session initialized");
  }

  return {
    initializeActivityLog,
    writeLogEntry,
    writeBackendErrorLogEntry,
    logErrorEntry,
    setLogEntrySuppressed,
  };
}

module.exports = {
  initializeLogging,
  setLogEntrySuppressed,
};
