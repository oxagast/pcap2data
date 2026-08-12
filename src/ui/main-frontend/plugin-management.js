// Plugin management helpers — extracted from
// ``src/ui/main-frontend.js`` so the orchestrator file stays
// below the ~10k-line mark. The factory owns the Settings → Plugins
// subtab: capability catalog lookup, capability-install dialog,
// plugin registry rendering, install/load/uninstall actions, the
// error log panel, and the row-level controls (enabled, priority,
// failure threshold, reset, uninstall).
//
// State bridge: the orchestrator declares five module-level bindings
// that the plugin cluster mutates:
//   - ``cachedPluginRegistry``: array of installed plugins (refreshed
//     from ``window.pluginapi.list()``).
//   - ``pluginErrorEntries``: array of timestamped error messages
//     (capped at 100).
//   - ``loadedPluginIds``: ``Set<string>`` of plugin ids currently
//     running.
//   - ``selectedPluginId``: string id of the row currently focused in
//     the registry panel.
//   - ``activePluginInstallCapabilityDialogResolver``: ``((allowed:
//     boolean) => void) | null`` for the install-confirmation dialog.
//
// External callbacks (orchestrator functions passed as factory deps):
//   - ``getCurrentSettings`` / ``doError`` / ``writeLogEntry``:
//     standard reporting hooks.
//   - ``setSettingsStatus`` / ``escapeHtml``: UI helpers used by the
//     install dialog flow.
//   - ``psVer``: package.json version (used as the
//     ``packetsnitchVersion`` field on the plugin runtime payload).
//
// All IPC goes through ``window.pluginapi.*`` and ``document.*`` so
// no Electron-bridge objects have to be passed through the factory
// signature.

function createPluginManagementHelpers({
  state,
  getCurrentSettings,
  doError,
  writeLogEntry,
  setSettingsStatus,
  escapeHtml,
  psVer,
}) {
function getPluginManagerListElement() {
  return document.getElementById("settings-plugins-list");
}

function getPluginCapabilityPanelMetaElement() {
  return document.getElementById("settings-plugins-selected-meta");
}

function getPluginCapabilityPanelListElement() {
  return document.getElementById("settings-plugins-selected-capabilities");
}

function getPluginErrorPanelElement() {
  return document.getElementById("settings-plugins-error-panel");
}

function normalizePluginCapabilityList(capabilities) {
  if (!Array.isArray(capabilities)) return [];
  const seen = new Set();
  return capabilities
    .map((entry) => String(entry || "").trim())
    .filter((entry) => {
      if (!entry || seen.has(entry)) {
        return false;
      }
      seen.add(entry);
      return true;
    });
}

function getPluginCapabilityCatalogMap() {
  const map = new Map();
  if (!window.pluginapi || typeof window.pluginapi.getCapabilityCatalog !== "function") {
    return map;
  }
  const catalog = window.pluginapi.getCapabilityCatalog();
  if (!Array.isArray(catalog)) {
    return map;
  }
  catalog.forEach((entry) => {
    const id = String(entry?.capability || "").trim();
    const description = String(entry?.description || "").trim();
    if (!id || !description) return;
    map.set(id, description);
  });
  return map;
}

function createPluginCapabilityListItem(capabilityId, capabilityDescription = "") {
  const itemEl = document.createElement("li");
  const idEl = document.createElement("div");
  idEl.className = "plugin-capability-item-id";
  idEl.textContent = capabilityId;
  itemEl.appendChild(idEl);
  if (capabilityDescription) {
    const descEl = document.createElement("div");
    descEl.className = "plugin-capability-item-desc";
    descEl.textContent = capabilityDescription;
    itemEl.appendChild(descEl);
  }
  return itemEl;
}

function renderSelectedPluginCapabilities(pluginEntry) {
  const metaEl = getPluginCapabilityPanelMetaElement();
  const listEl = getPluginCapabilityPanelListElement();
  if (!metaEl || !listEl) return;
  listEl.innerHTML = "";
  if (!pluginEntry) {
    metaEl.textContent = "Select a plugin to view capabilities.";
    return;
  }

  const pluginName = String(pluginEntry.pluginName || "Plugin").trim() || "Plugin";
  const pluginVersion = String(pluginEntry.pluginVersion || "").trim();
  metaEl.textContent = `${pluginName}${pluginVersion ? ` v${pluginVersion}` : ""}`;

  const normalizedCapabilities = normalizePluginCapabilityList(pluginEntry.capabilities);
  if (!normalizedCapabilities.length) {
    const emptyEl = document.createElement("li");
    emptyEl.textContent = "No declared capabilities";
    listEl.appendChild(emptyEl);
    return;
  }

  const capabilityDescriptions = getPluginCapabilityCatalogMap();
  normalizedCapabilities.forEach((capabilityId) => {
    const capabilityDescription = capabilityDescriptions.get(capabilityId) || "";
    listEl.appendChild(createPluginCapabilityListItem(capabilityId, capabilityDescription));
  });
}

function requestPluginInstallCapabilityDialog(inspectedPlugin = {}) {
  const dialogEl = document.getElementById("plugin-install-capability-dialog");
  const titleEl = document.getElementById("plugin-install-capability-dialog-title");
  const descriptionEl = document.getElementById("plugin-install-capability-dialog-description");
  const listEl = document.getElementById("plugin-install-capability-dialog-list");
  const confirmBtn = document.getElementById("plugin-install-capability-confirm-btn");
  if (!dialogEl || !titleEl || !descriptionEl || !listEl || !confirmBtn) {
    return Promise.resolve(false);
  }

  if (state.activePluginInstallCapabilityDialogResolver) {
    const resolve = state.activePluginInstallCapabilityDialogResolver;
    state.activePluginInstallCapabilityDialogResolver = null;
    resolve(false);
  }

  const pluginName = String(inspectedPlugin.pluginName || "Plugin").trim() || "Plugin";
  const pluginVersion = String(inspectedPlugin.pluginVersion || "").trim();
  const normalizedCapabilities = normalizePluginCapabilityList(inspectedPlugin.capabilities);
  const capabilityDescriptions = getPluginCapabilityCatalogMap();

  titleEl.textContent = `Install ${pluginName}${pluginVersion ? ` v${pluginVersion}` : ""}`;
  descriptionEl.textContent = "Review requested plugin capabilities before install. Select Install and Enable to continue.";
  listEl.innerHTML = "";
  if (!normalizedCapabilities.length) {
    listEl.appendChild(createPluginCapabilityListItem("No declared capabilities", ""));
  } else {
    normalizedCapabilities.forEach((capabilityId) => {
      const capabilityDescription = capabilityDescriptions.get(capabilityId) || "";
      listEl.appendChild(createPluginCapabilityListItem(capabilityId, capabilityDescription));
    });
  }

  dialogEl.hidden = false;
  confirmBtn.focus();
  return new Promise((resolve) => {
    state.activePluginInstallCapabilityDialogResolver = resolve;
  });
}

function resolvePluginInstallCapabilityDialog(isAllowed) {
  const dialogEl = document.getElementById("plugin-install-capability-dialog");
  if (dialogEl) {
    dialogEl.hidden = true;
  }
  if (!state.activePluginInstallCapabilityDialogResolver) {
    return;
  }
  const resolve = state.activePluginInstallCapabilityDialogResolver;
  state.activePluginInstallCapabilityDialogResolver = null;
  resolve(Boolean(isAllowed));
}

function renderPluginErrorPanel() {
  const panelEl = getPluginErrorPanelElement();
  if (!panelEl) return;
  if (!Array.isArray(state.pluginErrorEntries) || state.pluginErrorEntries.length === 0) {
    panelEl.textContent = "No plugin errors.";
    return;
  }
  const lines = state.pluginErrorEntries.slice(0, 20).map((entry) => {
    const when = entry?.at || new Date().toISOString();
    const message = String(entry?.message || "Unknown plugin error");
    return `[${when}] ${message}`;
  });
  panelEl.textContent = lines.join("\n");
}

function recordPluginError(message) {
  const normalized = String(message || "").trim();
  if (!normalized) return;
  state.pluginErrorEntries.unshift({
    at: new Date().toISOString(),
    message: normalized,
  });
  if (state.pluginErrorEntries.length > 100) {
    state.pluginErrorEntries = state.pluginErrorEntries.slice(0, 100);
  }
  renderPluginErrorPanel();
}

function clearPluginErrors() {
  state.pluginErrorEntries = [];
  renderPluginErrorPanel();
}

function setPluginManagerMessage(message) {
  const listEl = getPluginManagerListElement();
  if (!listEl) return;
  renderSelectedPluginCapabilities(null);
  listEl.innerHTML = `<div class="settings-help-text">${escapeHtml(String(message || ""))}</div>`;
}

function resolvePluginEntryPath(pluginEntry) {
  const installPath = typeof pluginEntry?.installPath === "string"
    ? pluginEntry.installPath
    : "";
  const manifestEntry = typeof pluginEntry?.manifest?.entry === "string"
    ? pluginEntry.manifest.entry.trim()
    : "";
  const entryFile = manifestEntry || "plugin.js";
  if (!installPath) {
    throw new Error("Plugin install path is missing");
  }
  if (
    entryFile.includes("..")
    || entryFile.startsWith("/")
    || /^[a-zA-Z]:[\\/]/.test(entryFile)
  ) {
    throw new Error(`Unsafe plugin entry path: ${entryFile}`);
  }
  const normalizedInstallPath = String(installPath).replace(/\\/g, "/").replace(/\/+$/, "");
  const normalizedEntry = String(entryFile).replace(/\\/g, "/").replace(/^\/+/, "");
  return `${normalizedInstallPath}/${normalizedEntry}`;
}

async function reportPluginRuntimeFailure(pluginEntry, error) {
  const pluginId = String(pluginEntry?.pluginId || "").trim();
  const errorMessage = error?.message || String(error || "Unknown plugin runtime error");
  recordPluginError(`Plugin ${pluginId || "unknown"} runtime error: ${errorMessage}`);
  if (window.pluginapi && typeof window.pluginapi.recordFailure === "function" && pluginId) {
    try {
      await window.pluginapi.recordFailure({
        pluginId,
        critical: true,
      });
    } catch (_reportError) {
      // Ignore failure-report errors to avoid loops.
    }
  }
}

async function loadInstalledPluginEntry(pluginEntry, { forceReload = false } = {}) {
  const pluginId = String(pluginEntry?.pluginId || "").trim();
  if (!pluginId) return;
  if (!pluginEntry?.enabled) {
    state.loadedPluginIds.delete(pluginId);
    return;
  }
  if (!forceReload && state.loadedPluginIds.has(pluginId)) {
    return;
  }

  try {
    if (!window.pluginapi || typeof window.pluginapi.loadRuntime !== "function") {
      throw new Error("Plugin runtime bridge is unavailable");
    }

    const runtimeResult = await window.pluginapi.loadRuntime({
      plugin: pluginEntry,
      forceReload,
      packetsnitchVersion: String(psVer || "").trim() || "unknown",
    });
    if (!runtimeResult?.success) {
      throw new Error(runtimeResult?.error || "Plugin runtime failed to initialize");
    }
    const entryPath = runtimeResult?.entryPath || resolvePluginEntryPath(pluginEntry);

    state.loadedPluginIds.add(pluginId);
    writeLogEntry(`Plugin loaded id=${JSON.stringify(pluginId)} entry=${JSON.stringify(entryPath)}`);
  } catch (error) {
    await reportPluginRuntimeFailure(pluginEntry, error);
    doError(`Plugin ${pluginId} failed to load: ${error?.message || error}`);
  }
}

async function loadEnabledInstalledPlugins(pluginEntries = state.cachedPluginRegistry) {
  if (!Array.isArray(pluginEntries) || pluginEntries.length === 0) return;
  for (const pluginEntry of pluginEntries) {
    if (!pluginEntry?.enabled) continue;
    if (pluginEntry?.compatibleWithCurrentPacketsnitch === false) continue;
    await loadInstalledPluginEntry(pluginEntry);
  }
}

function createPluginRowElement(pluginEntry) {
  const rowEl = document.createElement("div");
  const isSelected = pluginEntry.pluginId === state.selectedPluginId;
  rowEl.className = `settings-help-text settings-plugin-row${isSelected ? " selected" : ""}`;
  rowEl.tabIndex = 0;
  rowEl.setAttribute("role", "button");
  rowEl.setAttribute("aria-pressed", isSelected ? "true" : "false");
  rowEl.addEventListener("click", () => {
    state.selectedPluginId = String(pluginEntry.pluginId || "");
    renderPluginRegistryView(state.cachedPluginRegistry);
  });
  rowEl.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    state.selectedPluginId = String(pluginEntry.pluginId || "");
    renderPluginRegistryView(state.cachedPluginRegistry);
  });

  const titleEl = document.createElement("div");
  titleEl.style.fontWeight = "600";
  titleEl.textContent = `${pluginEntry.pluginName} (${pluginEntry.pluginVersion})`;
  rowEl.appendChild(titleEl);

  const metaEl = document.createElement("div");
  metaEl.textContent = `Address: ${pluginEntry.address} | Failures: ${pluginEntry.failureCount || 0}${pluginEntry.disabledReason ? ` | Disabled: ${pluginEntry.disabledReason}` : ""}`;
  rowEl.appendChild(metaEl);

  const controlsEl = document.createElement("div");
  controlsEl.className = "settings-actions-row";
  controlsEl.style.marginTop = "0.35rem";
  controlsEl.addEventListener("click", (event) => {
    event.stopPropagation();
  });
  controlsEl.addEventListener("keydown", (event) => {
    event.stopPropagation();
  });

  const enabledLabel = document.createElement("label");
  enabledLabel.className = "settings-checkbox-row";
  enabledLabel.style.marginRight = "0.5rem";
  const enabledInput = document.createElement("input");
  enabledInput.type = "checkbox";
  enabledInput.checked = Boolean(pluginEntry.enabled);
  enabledInput.addEventListener("change", async () => {
    if (!window.pluginapi) return;
    const result = await window.pluginapi.setEnabled({
      pluginId: pluginEntry.pluginId,
      enabled: enabledInput.checked,
    });
    if (!result?.success) {
      const errorMessage = result?.error || "Unable to change plugin enabled state";
      recordPluginError(errorMessage);
      doError(errorMessage);
      enabledInput.checked = Boolean(pluginEntry.enabled);
      return;
    }
    if (!enabledInput.checked) {
      if (typeof window.pluginapi.unloadRuntime === "function") {
        await window.pluginapi.unloadRuntime({
          pluginId: pluginEntry.pluginId,
          plugin: result?.plugin || pluginEntry,
        });
      }
      state.loadedPluginIds.delete(pluginEntry.pluginId);
    } else {
      await loadInstalledPluginEntry(result?.plugin || pluginEntry, { forceReload: true });
    }
    await refreshPluginRegistryView();
  });
  enabledLabel.appendChild(enabledInput);
  enabledLabel.appendChild(document.createTextNode("Enabled"));
  controlsEl.appendChild(enabledLabel);

  const priorityInput = document.createElement("input");
  priorityInput.type = "number";
  priorityInput.min = "0";
  priorityInput.step = "1";
  priorityInput.title = "Plugin priority";
  priorityInput.value = String(Number(pluginEntry.priority) || 100);
  priorityInput.style.width = "5rem";
  priorityInput.addEventListener("change", async () => {
    if (!window.pluginapi) return;
    const result = await window.pluginapi.setPriority({
      pluginId: pluginEntry.pluginId,
      priority: Number(priorityInput.value),
    });
    if (!result?.success) {
      const errorMessage = result?.error || "Unable to update plugin priority";
      recordPluginError(errorMessage);
      doError(errorMessage);
      return;
    }
    await refreshPluginRegistryView();
  });
  controlsEl.appendChild(priorityInput);

  const thresholdInput = document.createElement("input");
  thresholdInput.type = "number";
  thresholdInput.min = "1";
  thresholdInput.step = "1";
  thresholdInput.placeholder = "Threshold";
  thresholdInput.title = "Per-plugin failure threshold override";
  thresholdInput.value = pluginEntry.failureThresholdOverride
    ? String(pluginEntry.failureThresholdOverride)
    : "";
  thresholdInput.style.width = "6rem";
  thresholdInput.addEventListener("change", async () => {
    if (!window.pluginapi) return;
    const rawValue = thresholdInput.value.trim();
    const result = await window.pluginapi.setFailureThreshold({
      pluginId: pluginEntry.pluginId,
      failureThresholdOverride: rawValue ? Number(rawValue) : null,
    });
    if (!result?.success) {
      const errorMessage = result?.error || "Unable to update plugin failure threshold";
      recordPluginError(errorMessage);
      doError(errorMessage);
      return;
    }
    await refreshPluginRegistryView();
  });
  controlsEl.appendChild(thresholdInput);

  const resetFailuresBtn = document.createElement("button");
  resetFailuresBtn.type = "button";
  resetFailuresBtn.textContent = "Reset Failures";
  resetFailuresBtn.addEventListener("click", async () => {
    if (!window.pluginapi) return;
    const result = await window.pluginapi.resetFailures({ pluginId: pluginEntry.pluginId });
    if (!result?.success) {
      const errorMessage = result?.error || "Unable to reset plugin failures";
      recordPluginError(errorMessage);
      doError(errorMessage);
      return;
    }
    await refreshPluginRegistryView();
  });
  controlsEl.appendChild(resetFailuresBtn);

  const uninstallBtn = document.createElement("button");
  uninstallBtn.type = "button";
  uninstallBtn.textContent = "Uninstall";
  uninstallBtn.addEventListener("click", async () => {
    if (!window.pluginapi) return;
    if (typeof window.pluginapi.unloadRuntime === "function") {
      await window.pluginapi.unloadRuntime({ pluginId: pluginEntry.pluginId, plugin: pluginEntry });
    }
    const result = await window.pluginapi.uninstall({ pluginId: pluginEntry.pluginId });
    if (!result?.success) {
      const errorMessage = result?.error || "Unable to uninstall plugin";
      recordPluginError(errorMessage);
      doError(errorMessage);
      return;
    }
    state.loadedPluginIds.delete(pluginEntry.pluginId);
    await refreshPluginRegistryView();
  });
  controlsEl.appendChild(uninstallBtn);

  rowEl.appendChild(controlsEl);
  return rowEl;
}

function renderPluginRegistryView(pluginEntries = []) {
  const listEl = getPluginManagerListElement();
  if (!listEl) return;
  listEl.innerHTML = "";
  if (!Array.isArray(pluginEntries) || pluginEntries.length === 0) {
    state.selectedPluginId = "";
    renderSelectedPluginCapabilities(null);
    setPluginManagerMessage("No plugins installed.");
    return;
  }
  const sortedEntries = [...pluginEntries].sort((a, b) => {
    const aPriority = Number(a?.priority) || 0;
    const bPriority = Number(b?.priority) || 0;
    if (aPriority !== bPriority) return bPriority - aPriority;
    return String(a?.pluginName || "").localeCompare(String(b?.pluginName || ""));
  });

  const selectedEntry = sortedEntries.find((pluginEntry) => pluginEntry.pluginId === state.selectedPluginId)
    || sortedEntries[0];
  state.selectedPluginId = String(selectedEntry?.pluginId || "");

  sortedEntries.forEach((pluginEntry) => {
    listEl.appendChild(createPluginRowElement(pluginEntry));
  });

  renderSelectedPluginCapabilities(selectedEntry || null);
}

async function refreshPluginRegistryView() {
  if (!window.pluginapi || typeof window.pluginapi.list !== "function") {
    const errorMessage = "Plugin API is unavailable in this build.";
    recordPluginError(errorMessage);
    setPluginManagerMessage(errorMessage);
    return;
  }
  try {
    const response = await window.pluginapi.list();
    if (!response?.success) {
      const errorMessage = response?.error || "Unable to load plugin list.";
      recordPluginError(errorMessage);
      setPluginManagerMessage(errorMessage);
      return;
    }
    state.cachedPluginRegistry = Array.isArray(response.plugins) ? response.plugins : [];
    renderPluginRegistryView(state.cachedPluginRegistry);
    await loadEnabledInstalledPlugins(state.cachedPluginRegistry);
  } catch (error) {
    const errorMessage = error?.message || "Unable to load plugin list.";
    recordPluginError(errorMessage);
    setPluginManagerMessage(errorMessage);
  }
}

async function installPluginFromSettingsAction() {
  if (!window.pluginapi || typeof window.pluginapi.selectZip !== "function") {
    const errorMessage = "Plugin API is unavailable.";
    recordPluginError(errorMessage);
    setSettingsStatus(errorMessage);
    return;
  }
  const selectedZip = await window.pluginapi.selectZip();
  if (!selectedZip) {
    return;
  }

  if (typeof window.pluginapi.inspectZip === "function") {
    let inspectResult = null;
    try {
      inspectResult = await window.pluginapi.inspectZip({ zipPath: selectedZip });
    } catch (inspectError) {
      const inspectErrorMessage = inspectError?.message || String(inspectError || "");
      if (!inspectErrorMessage.includes("No handler registered for 'plugins-inspect-zip'")) {
        throw inspectError;
      }
      // Older main process builds may not have the inspect handler yet.
      inspectResult = {
        success: true,
        plugin: {
          pluginName: "Plugin",
          pluginVersion: "",
          capabilities: ["Permissions unavailable in this app session"],
        },
      };
    }
    if (!inspectResult?.success) {
      const errorMessage = inspectResult?.error || "Unable to inspect plugin permissions.";
      recordPluginError(errorMessage);
      doError(errorMessage);
      setSettingsStatus("Plugin install canceled.");
      return;
    }

    const inspectedPlugin = inspectResult?.plugin || {};
    const isAllowed = await requestPluginInstallCapabilityDialog(inspectedPlugin);
    if (!isAllowed) {
      setSettingsStatus("Plugin install canceled by user.");
      return;
    }
  }

  setSettingsStatus("Installing plugin...");
  const installResult = await window.pluginapi.install({ zipPath: selectedZip });
  if (!installResult?.success) {
    const errorMessage = installResult?.error || "Plugin install failed";
    recordPluginError(errorMessage);
    doError(errorMessage);
    setSettingsStatus("Plugin install failed.");
    return;
  }
  writeLogEntry(
    `Plugin installed id=${JSON.stringify(installResult?.plugin?.pluginId || "unknown")} address=${JSON.stringify(installResult?.plugin?.address || "unknown")}`,
  );
  setSettingsStatus("Plugin installed.");
  if (installResult?.plugin?.enabled) {
    await loadInstalledPluginEntry(installResult.plugin, { forceReload: true });
  }
  await refreshPluginRegistryView();
}

// Builds settings change summaries.

  return {
    getPluginManagerListElement,
    getPluginCapabilityPanelMetaElement,
    getPluginCapabilityPanelListElement,
    getPluginErrorPanelElement,
    normalizePluginCapabilityList,
    getPluginCapabilityCatalogMap,
    createPluginCapabilityListItem,
    renderSelectedPluginCapabilities,
    requestPluginInstallCapabilityDialog,
    resolvePluginInstallCapabilityDialog,
    renderPluginErrorPanel,
    recordPluginError,
    clearPluginErrors,
    setPluginManagerMessage,
    resolvePluginEntryPath,
    reportPluginRuntimeFailure,
    loadInstalledPluginEntry,
    loadEnabledInstalledPlugins,
    createPluginRowElement,
    renderPluginRegistryView,
    refreshPluginRegistryView,
    installPluginFromSettingsAction,
  };
}

module.exports = {
  createPluginManagementHelpers,
};
