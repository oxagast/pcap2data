// Controls the session picker UI used for opening, restoring, and managing sessions.

/**
 * Session Picker panel – shows a library of saved sessions on startup and
 * provides rename / delete / export-to-file management actions.
 */

// we need to declare the writeLogEntry function here

function formatSavedAt(iso) {
  if (!iso) return "No date information";
  try {
    return new Date(iso).toLocaleString();
  } catch (_e) {
    return iso;
  }
}

function formatBytes(value) {
  const byteCount = Number(value);
  if (!Number.isFinite(byteCount) || byteCount <= 0) return "Unknown";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let unitIndex = 0;
  let displayValue = byteCount;
  while (displayValue >= 1024 && unitIndex < units.length - 1) {
    displayValue /= 1024;
    unitIndex += 1;
  }
  const digits = displayValue >= 100 ? 0 : displayValue >= 10 ? 1 : 2;
  return `${displayValue.toFixed(digits)} ${units[unitIndex]}`;
}

function formatSessionInfo(session) {
  const saveType =
    typeof session?.saveType === "string" && session.saveType.trim()
      ? session.saveType.trim()
      : "Unknown";
  const packetsnitchVersion =
    typeof session?.packetsnitchVersion === "string" && session.packetsnitchVersion.trim()
      ? session.packetsnitchVersion.trim()
      : "Unknown";
  const pcapSizeLabel = formatBytes(session?.pcapSizeBytes);
  const saveSizeLabel = formatBytes(session?.totalSizeBytes);
  return [
    `Type: ${saveType}`,
    `PCAP: ${pcapSizeLabel}`,
    `Save size: ${saveSizeLabel}`,
    `PS: ${packetsnitchVersion}`,
  ].join("\n");
}

// Initializes session picker.
function initializeSessionPicker({
  sessionsapi,
  documentRef,
  onSessionSelected,
  onNewSession,
  buildSessionFilePayload,
}) {
  if (!sessionsapi) return;

  const screen = documentRef.getElementById("session-picker");
  if (!screen) return;

  const listEl = documentRef.getElementById("session-picker-list");
  const statusEl = documentRef.getElementById("session-picker-status");
  const newBtn = documentRef.getElementById("session-picker-new-btn");
  const importBtn = documentRef.getElementById("session-picker-import-btn");
  const closeBtn = documentRef.getElementById("session-picker-close-btn");
  const refreshBtn = documentRef.getElementById("session-picker-refresh-btn");

  // Name-prompt dialog elements
  const nameDialog = documentRef.getElementById("session-name-dialog");
  const nameInput = documentRef.getElementById("session-name-input");
  const nameConfirmBtn = documentRef.getElementById("session-name-confirm-btn");
  const nameCancelBtn = documentRef.getElementById("session-name-cancel-btn");
  const nameDialogTitle = documentRef.getElementById("session-name-dialog-title");
  const nameDialogStatus = documentRef.getElementById("session-name-dialog-status");
  const deleteDialog = documentRef.getElementById("session-delete-dialog");
  const deleteDialogDescription = documentRef.getElementById(
    "session-delete-dialog-description",
  );
  const deleteConfirmBtn = documentRef.getElementById("session-delete-confirm-btn");
  const deleteCancelBtn = documentRef.getElementById("session-delete-cancel-btn");

  let nameDialogResolve = null;
  let deleteDialogResolve = null;

  function showStatus(msg, isError) {
    if (!statusEl) return;
    statusEl.textContent = msg;
    statusEl.className = isError ? "session-picker-status error" : "session-picker-status";
  }

  function clearStatus() {
    if (statusEl) {
      statusEl.textContent = "";
      statusEl.className = "session-picker-status";
    }
  }

  /**
   * Prompt the user for a session name. Returns the entered name string, or
   * null if the user cancelled.
   */
  function promptSessionName(title, defaultValue) {
    return new Promise((resolve) => {
      if (!nameDialog || !nameInput) {
        const val = window.prompt(title || "Enter session name:", defaultValue || "");
        resolve(val && val.trim() ? val.trim() : null);
        return;
      }
      nameDialogResolve = resolve;
      if (nameDialogTitle) nameDialogTitle.textContent = title || "Session Name";
      if (nameDialogStatus) nameDialogStatus.textContent = "";
      nameInput.value = defaultValue || "";
      nameDialog.hidden = false;
      nameInput.focus();
      nameInput.select();
    });
  }

  function resolveNameDialog(value) {
    if (nameDialog) nameDialog.hidden = true;
    if (nameDialogResolve) {
      const cb = nameDialogResolve;
      nameDialogResolve = null;
      cb(value);
    }
  }

  function promptDeleteSession(name) {
    return new Promise((resolve) => {
      if (!deleteDialog || !deleteDialogDescription) {
        resolve(
          window.confirm(
            'Delete session "' + name + '"?\nThis cannot be undone.',
          ),
        );
        return;
      }
      if (deleteDialogResolve) {
        const cb = deleteDialogResolve;
        deleteDialogResolve = null;
        cb(false);
      }
      deleteDialogDescription.textContent =
        'Delete session "' + name + '"? This cannot be undone.';
      deleteDialog.hidden = false;
      if (deleteConfirmBtn) deleteConfirmBtn.focus();
      deleteDialogResolve = resolve;
    });
  }

  function resolveDeleteDialog(value) {
    if (deleteDialog) deleteDialog.hidden = true;
    if (!deleteDialogResolve) return;
    const cb = deleteDialogResolve;
    deleteDialogResolve = null;
    cb(Boolean(value));
  }

  if (nameConfirmBtn) {
    nameConfirmBtn.addEventListener("click", () => {
      const val = nameInput ? nameInput.value.trim() : "";
      if (!val) {
        if (nameDialogStatus) nameDialogStatus.textContent = "Please enter a name.";
        return;
      }
      resolveNameDialog(val);
    });
  }

  if (nameCancelBtn) {
    nameCancelBtn.addEventListener("click", () => resolveNameDialog(null));
  }

  if (nameInput) {
    nameInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const val = nameInput.value.trim();
        if (!val) {
          if (nameDialogStatus) nameDialogStatus.textContent = "Please enter a name.";
          return;
        }
        resolveNameDialog(val);
      } else if (e.key === "Escape") {
        resolveNameDialog(null);
      }
    });
  }

  if (deleteConfirmBtn) {
    deleteConfirmBtn.addEventListener("click", () => resolveDeleteDialog(true));
  }

  if (deleteCancelBtn) {
    deleteCancelBtn.addEventListener("click", () => resolveDeleteDialog(false));
  }

  if (deleteDialog) {
    deleteDialog.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        resolveDeleteDialog(true);
        return;
      }
      if (event.key === "Escape") {
        resolveDeleteDialog(false);
      }
    });
  }

  async function loadSessions(options = {}) {
    if (!listEl) return;
    const { fromCache } = options;
    if (fromCache !== false) {
      listEl.innerHTML = '<tr><td colspan="4" class="session-picker-loading">Loading sessions…</td></tr>';
    }
    setRefreshIndicator(true);
    clearStatus();
    try {
      const result = await sessionsapi.list();
      renderSessionList(result.sessions || [], { fromCache: result.fromCache });
    } catch (err) {
      showStatus("Failed to load sessions: " + (err && err.message ? err.message : String(err)), true);
    } finally {
      setRefreshIndicator(false);
    }
  }

  function setRefreshIndicator(active) {
    if (!refreshBtn) return;
    refreshBtn.disabled = active;
    refreshBtn.setAttribute("aria-busy", active ? "true" : "false");
    refreshBtn.title = active ? "Refreshing session list…" : "Refresh session list";
  }

  function renderSessionList(sessions, options = {}) {
    if (!listEl) return;
    listEl.innerHTML = "";
    if (!sessions || sessions.length === 0) {
      listEl.innerHTML = '<tr><td colspan="4" class="session-picker-empty">No saved sessions found. Start by loading a PCAP or JSON file.</td></tr>';
      return;
    }
    sessions.forEach((session) => {
      const tr = documentRef.createElement("tr");
      tr.className = "session-picker-row";

      const nameTd = documentRef.createElement("td");
      nameTd.className = "session-picker-name";
      nameTd.textContent = session.name;
      nameTd.title = session.name;

      const dateTd = documentRef.createElement("td");
      dateTd.className = "session-picker-date";
      dateTd.textContent = formatSavedAt(session.savedAt);

      const infoTd = documentRef.createElement("td");
      infoTd.className = "session-picker-info";
      const infoText = formatSessionInfo(session);
      infoTd.textContent = infoText;
      infoTd.title = infoText;

      const actionsTd = documentRef.createElement("td");
      actionsTd.className = "session-picker-actions";

      const openBtn = documentRef.createElement("button");
      openBtn.textContent = "Open";
      openBtn.className = "session-picker-action-btn session-open-btn";
      openBtn.addEventListener("click", () => handleOpen(session.name));

      const renameBtn = documentRef.createElement("button");
      renameBtn.textContent = "Rename";
      renameBtn.className = "session-picker-action-btn session-rename-btn";
      renameBtn.addEventListener("click", () => handleRename(session.name));

      const deleteBtn = documentRef.createElement("button");
      deleteBtn.textContent = "Delete";
      deleteBtn.className = "session-picker-action-btn session-delete-btn";
      deleteBtn.addEventListener("click", () => handleDelete(session.name));

      const exportBtn = documentRef.createElement("button");
      exportBtn.textContent = "Export";
      exportBtn.className = "session-picker-action-btn session-export-btn";
      exportBtn.addEventListener("click", () => handleExport(session.name));

      actionsTd.appendChild(openBtn);
      actionsTd.appendChild(renameBtn);
      actionsTd.appendChild(deleteBtn);
      actionsTd.appendChild(exportBtn);

      tr.appendChild(nameTd);
      tr.appendChild(dateTd);
      tr.appendChild(infoTd);
      tr.appendChild(actionsTd);
      listEl.appendChild(tr);
    });
  }

  async function handleOpen(name) {
    clearStatus();
    try {
      const result = await sessionsapi.load(name);
      if (!result.success) {
        showStatus("Failed to open session: " + (result.error || "unknown error"), true);
        return;
      }
      hide();
      if (onSessionSelected) {
        onSessionSelected(name, result.data);
      }
    } catch (err) {
      showStatus("Failed to open session: " + (err && err.message ? err.message : String(err)), true);
    }
  }

  async function handleRename(oldName) {
    clearStatus();
    const newName = await promptSessionName("Rename Session", oldName);
    if (!newName || newName === oldName) return;
    try {
      const result = await sessionsapi.rename(oldName, newName);
      if (!result.success) {
        showStatus("Rename failed: " + (result.error || "unknown error"), true);
        return;
      }
      showStatus('Renamed "' + oldName + '" → "' + result.name + '"');
      await loadSessions();
    } catch (err) {
      showStatus("Rename failed: " + (err && err.message ? err.message : String(err)), true);
    }
  }

  async function handleDelete(name) {
    clearStatus();
    const confirmed = await promptDeleteSession(name);
    if (!confirmed) return;
    try {
      const result = await sessionsapi.remove(name);
      if (!result.success) {
        showStatus("Delete failed: " + (result.error || "unknown error"), true);
        return;
      }
      showStatus('Session "' + name + '" deleted.');
      await loadSessions();
    } catch (err) {
      showStatus("Delete failed: " + (err && err.message ? err.message : String(err)), true);
    }
  }

  async function handleExport(name) {
    clearStatus();
    try {
      const loadResult = await sessionsapi.load(name);
      if (!loadResult.success) {
        showStatus("Export failed: could not read session data.", true);
        return;
      }
      const exportResult = await sessionsapi.exportToFile(name, loadResult.data);
      if (exportResult.canceled) return;
      if (!exportResult.success) {
        showStatus("Export failed: " + (exportResult.error || "unknown error"), true);
        return;
      }
      showStatus('Session "' + name + '" exported.');
    } catch (err) {
      showStatus("Export failed: " + (err && err.message ? err.message : String(err)), true);
    }
  }

  async function handleImport() {
    clearStatus();
    if (!sessionsapi || typeof sessionsapi.importFromFile !== "function") {
      showStatus("Import is not available in this build.", true);
      return;
    }
    showStatus("Importing session…");
    try {
      const result = await sessionsapi.importFromFile();
      if (result && result.canceled) {
        clearStatus();
        return;
      }
      if (!result || !result.success) {
        showStatus(
          "Import failed: " + ((result && result.error) || "unknown error"),
          true,
        );
        return;
      }
      // Surface deprecation/legacy-format warnings returned by the main
      // process so the user knows to re-export legacy sessions as .psb.
      if (result.warning) {
        showStatus(
          'Session "' + result.name + '" imported. ' + result.warning,
          false,
        );
      } else {
        showStatus('Session "' + result.name + '" imported.');
      }
      await loadSessions();
    } catch (err) {
      showStatus("Import failed: " + (err && err.message ? err.message : String(err)), true);
    }
  }

  // The main process requests a destination name for an imported session via
  // 'session-import-prompt-name'. Reuse the existing session-name dialog and
  // send the result back through sessionsapi.sendImportNameResult. A warning
  // (e.g. legacy-format deprecation notice) may be shown in the dialog status
  // line.
  if (sessionsapi && typeof sessionsapi.onImportPromptName === "function") {
    sessionsapi.onImportPromptName(async (payload) => {
      const defaultName =
        payload && typeof payload.defaultName === "string" ? payload.defaultName : "";
      const warning =
        payload && typeof payload.warning === "string" ? payload.warning : "";
      const chosen = await promptSessionName("Import Session", defaultName);
      if (warning && nameDialogStatus) {
        // Show the deprecation warning after the dialog closes so it is
        // visible in the picker status line context too.
        nameDialogStatus.textContent = warning;
      }
      if (typeof sessionsapi.sendImportNameResult === "function") {
        sessionsapi.sendImportNameResult(chosen || "");
      }
    });
  }

  function show() {
    if (screen) screen.style.display = "flex";
    loadSessions();
  }

  function hide() {
    if (screen) screen.style.display = "none";
  }

  if (newBtn) {
    newBtn.addEventListener("click", () => {
      hide();
      if (onNewSession) onNewSession();
    });
  }

  if (importBtn) {
    importBtn.addEventListener("click", () => handleImport());
  }

  if (closeBtn) {
    closeBtn.addEventListener("click", async () => {
      const sessionData = await buildSessionFilePayload();
      if (sessionData && sessionData.length > 5000) {
        sessionsapi.save("autosave", sessionData).finally(() => hide());
      } else {
        hide();
      }
    });
  }

  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => loadSessions());
  }

  // Listen for authoritative re-scans from the main process. If the cached list
  // is stale or missing entries, the renderer will be updated automatically.
  if (typeof sessionsapi.onRefreshed === "function") {
    sessionsapi.onRefreshed((result) => {
      if (result && result.sessions) {
        renderSessionList(result.sessions, { fromCache: false });
        setRefreshIndicator(false);
      }
    });
  }

  // Check for saved sessions and show picker if any exist
  sessionsapi.list().then(async (result) => {
    try {
      const startupReleaseCheckPromise = window.__PACKETSNITCH_STARTUP_RELEASE_CHECK_PROMISE__;
      if (startupReleaseCheckPromise && typeof startupReleaseCheckPromise.then === "function") {
        const aboutShown = await startupReleaseCheckPromise;
        if (aboutShown) {
          return;
        }
      }
      if (result.success && result.sessions && result.sessions.length > 0) {
        show();
      }
    } catch (_error) {
      // If the startup gate fails, fall back to the existing behavior.
      if (result.success && result.sessions && result.sessions.length > 0) {
        show();
      }
    }
  }).catch(() => {
    // If listing fails, just don't show the picker
  });

  return {
    show,
    hide,
    reload: loadSessions,
    promptSessionName,
  };
}

module.exports = { initializeSessionPicker };
