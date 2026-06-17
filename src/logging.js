let lastViewMode = "";


function initializeLogging({
  logapi = null,
  documentRef = document,
  consoleRef = console,
}) {
  let activityLogPath = "Unavailable";
  const activityLogEntries = [];

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
        const stampedMessage = `[${new Date().toISOString()}] [GUI][Renderer] User opened ${viewMode} view`;
        addActivityLogEntry(stampedMessage);
      }
    } else {
      const stampedMessage = `[${new Date().toISOString()}] [GUI][Renderer] ${message}`;
      addActivityLogEntry(stampedMessage);
    }
  }

  function writeConsoleLogEntry(message) {
    if (message.includes("0.0.0.0")) {
      // this is the dummy structure packet
      return;
    }
    if (message.length > 300) {
      message = message.substring(0, 300) + " [truncated]";
    }
    const stampedMessage = `[${new Date().toISOString()}] [Console][Renderer] ${message}`;
    addActivityLogEntry(stampedMessage);
  }

  function writeBackendErrorLogEntry(message) {
    const stampedMessage = `[${new Date().toISOString()}] [Console][Snitch] ${message}`;
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
    logBtn.addEventListener("click", () => {
      if (panelEl.style.display === "block") {
        panelEl.style.display = "none";
      } else {
        panelEl.style.display = "block";
      }
    });
    closeBtn.addEventListener("click", () => {
      panelEl.style.display = "none";
    });
    searchEl.addEventListener("input", (event) => {
      renderActivityLogEntries(event.target.value);
    });
    writeLogEntry("PacketSnitch UI session initialized");
  }

  return {
    initializeActivityLog,
    writeLogEntry,
    writeBackendErrorLogEntry,
    logErrorEntry,
  };
}

module.exports = {
  initializeLogging,
};
