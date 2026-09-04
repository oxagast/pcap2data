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
  const mergedLabel = session?.merged
    ? `Merged sources: ${Number.isFinite(Number(session.sourceCount)) ? Number(session.sourceCount) : "multiple"}`
    : null;
  return [
    `Type: ${saveType}`,
    ...(mergedLabel ? [mergedLabel] : []),
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
  const mergeBtn = documentRef.getElementById("session-picker-merge-btn");
  const selectionCountEl = documentRef.getElementById("session-picker-selection-count");
  const mergeDialog = documentRef.getElementById("session-merge-dialog");
  const mergeSourcesEl = documentRef.getElementById("session-merge-sources");
  const mergeNameInput = documentRef.getElementById("session-merge-name-input");
  const mergeOptionsEl = documentRef.getElementById("session-merge-options");
  const mergeConfirmBtn = documentRef.getElementById("session-merge-confirm-btn");
  const mergeCancelBtn = documentRef.getElementById("session-merge-cancel-btn");
  const mergeDialogStatus = documentRef.getElementById("session-merge-dialog-status");

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
  let listedSessions = [];
  const selectedNames = new Set();
  let mergeDialogResolve = null;

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

  function updateSelectionUi() {
    const count = selectedNames.size;
    if (selectionCountEl) {
      selectionCountEl.textContent = count ? `${count} selected` : "Select sessions to merge";
    }
    if (mergeBtn) mergeBtn.disabled = count < 2;
  }

  function closeMergeDialog() {
    if (mergeDialog) mergeDialog.hidden = true;
    if (mergeDialogResolve) {
      const resolve = mergeDialogResolve;
      mergeDialogResolve = null;
      resolve(null);
    }
  }

  function renderMergeDialogSources() {
    if (!mergeSourcesEl) return;
    mergeSourcesEl.replaceChildren();
    const selected = listedSessions.filter((session) => selectedNames.has(session.name));
    selected.forEach((session, index) => {
      const row = documentRef.createElement("div");
      row.className = "session-merge-source-row";
      const label = documentRef.createElement("label");
      label.textContent = `${index + 1}. ${session.name}`;
      const seconds = documentRef.createElement("input");
      seconds.type = "number";
      seconds.step = "any";
      seconds.value = "0";
      seconds.dataset.mergeOffsetSeconds = session.name;
      seconds.title = "Signed seconds offset";
      const milliseconds = documentRef.createElement("input");
      milliseconds.type = "number";
      milliseconds.step = "any";
      milliseconds.value = "0";
      milliseconds.dataset.mergeOffsetMilliseconds = session.name;
      milliseconds.title = "Signed milliseconds offset";
      row.appendChild(label);
      row.appendChild(seconds);
      row.appendChild(documentRef.createTextNode("s + "));
      row.appendChild(milliseconds);
      row.appendChild(documentRef.createTextNode("ms"));
      mergeSourcesEl.appendChild(row);
    });
  }

  function renderMergeRelationships() {
    if (!mergeOptionsEl) return;
    mergeOptionsEl.replaceChildren();
    const selected = listedSessions.filter((session) => selectedNames.has(session.name));
    for (let leftIndex = 0; leftIndex < selected.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < selected.length; rightIndex += 1) {
        const left = selected[leftIndex];
        const right = selected[rightIndex];
        const row = documentRef.createElement("div");
        row.className = "session-merge-relationship-row";
        const label = documentRef.createElement("span");
        label.textContent = `${left.name} ↔ ${right.name}`;
        const select = documentRef.createElement("select");
        select.dataset.mergeRelationshipA = left.name;
        select.dataset.mergeRelationshipB = right.name;
        [
          ["auto", "Auto (conservative)"],
          ["same", "Same machine"],
          ["separate", "Separate machine"],
        ].forEach(([value, text]) => {
          const option = documentRef.createElement("option");
          option.value = value;
          option.textContent = text;
          select.appendChild(option);
        });
        row.appendChild(label);
        row.appendChild(select);
        mergeOptionsEl.appendChild(row);
      }
    }
  }

  function openMergeDialog() {
    if (selectedNames.size < 2) {
      showStatus("Select at least two sessions to merge.", true);
      return Promise.resolve(null);
    }
    renderMergeDialogSources();
    renderMergeRelationships();
    if (mergeNameInput) mergeNameInput.value = "Merged Session";
    if (mergeDialogStatus) mergeDialogStatus.textContent = "";
    if (mergeDialog) mergeDialog.hidden = false;
    if (mergeNameInput) mergeNameInput.focus();
    return new Promise((resolve) => {
      mergeDialogResolve = resolve;
    });
  }

  function resolveMergeDialog(value) {
    if (mergeDialog) mergeDialog.hidden = true;
    if (!mergeDialogResolve) return;
    const resolve = mergeDialogResolve;
    mergeDialogResolve = null;
    resolve(value);
  }

  function collectMergeOptions() {
    const offsets = {};
    if (mergeSourcesEl) {
      mergeSourcesEl.querySelectorAll("[data-merge-offset-seconds]").forEach((input) => {
        const name = input.dataset.mergeOffsetSeconds;
        const millisecondsInput = [...mergeSourcesEl.querySelectorAll(
          "[data-merge-offset-milliseconds]",
        )].find((candidate) => candidate.dataset.mergeOffsetMilliseconds === name);
        const seconds = Number(input.value || 0);
        const milliseconds = Number(millisecondsInput?.value || 0);
        if (!Number.isFinite(seconds) || !Number.isFinite(milliseconds)) {
          throw new Error(`Invalid clock offset for ${name}`);
        }
        offsets[name] = { offsetSeconds: seconds, offsetMilliseconds: milliseconds };
      });
    }
    const relationships = [];
    if (mergeOptionsEl) {
      mergeOptionsEl.querySelectorAll("[data-merge-relationship-a]").forEach((select) => {
        relationships.push({
          sourceA: select.dataset.mergeRelationshipA,
          sourceB: select.dataset.mergeRelationshipB,
          mode: select.value,
        });
      });
    }
    return { offsets, relationships };
  }

  async function handleMerge() {
    const result = await openMergeDialog();
    if (!result) return;
    const outputName = result.name;
    try {
      showStatus("Merging sessions…");
      const response = await sessionsapi.merge(
        [...selectedNames],
        outputName,
        result.options,
      );
      if (!response?.success) {
        showStatus(`Merge failed: ${response?.error || "unknown error"}`, true);
        return;
      }
      selectedNames.clear();
      updateSelectionUi();
      hide();
      if (onSessionSelected) onSessionSelected(response.name || outputName, response.data);
    } catch (error) {
      showStatus(`Merge failed: ${error?.message || String(error)}`, true);
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
    listedSessions = Array.isArray(sessions) ? sessions : [];
    const validNames = new Set(listedSessions.map((session) => session.name));
    [...selectedNames].forEach((name) => {
      if (!validNames.has(name)) selectedNames.delete(name);
    });
    updateSelectionUi();
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
      const checkbox = documentRef.createElement("input");
      checkbox.type = "checkbox";
      checkbox.className = "session-picker-select";
      checkbox.checked = selectedNames.has(session.name);
      checkbox.title = `Select ${session.name} for merge`;
      checkbox.addEventListener("click", (event) => event.stopPropagation());
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) selectedNames.add(session.name);
        else selectedNames.delete(session.name);
        updateSelectionUi();
      });
      nameTd.appendChild(checkbox);
      nameTd.appendChild(documentRef.createTextNode(` ${session.name}`));
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

  if (mergeBtn) {
    mergeBtn.addEventListener("click", async () => {
      await handleMerge();
    });
  }

  if (mergeConfirmBtn) {
    mergeConfirmBtn.addEventListener("click", () => {
      const outputName = mergeNameInput ? mergeNameInput.value.trim() : "";
      if (!outputName) {
        if (mergeDialogStatus) mergeDialogStatus.textContent = "Please enter a destination name.";
        return;
      }
      try {
        resolveMergeDialog({ name: outputName, options: collectMergeOptions() });
      } catch (error) {
        if (mergeDialogStatus) mergeDialogStatus.textContent = error.message;
      }
    });
  }

  if (mergeCancelBtn) {
    mergeCancelBtn.addEventListener("click", () => resolveMergeDialog(null));
  }

  if (mergeDialog) {
    mergeDialog.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeMergeDialog();
      } else if (event.key === "Enter" && event.target === mergeNameInput) {
        if (mergeConfirmBtn) mergeConfirmBtn.click();
      }
    });
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
