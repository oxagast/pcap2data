// Exposes the safe preload bridge APIs from Electron to the renderer process.

const { contextBridge, ipcRenderer } = require('electron');
const loadedPluginRuntimes = new Map();

function resolvePluginEntryPath(pluginEntry = {}) {
  const installPath = typeof pluginEntry?.installPath === 'string'
    ? pluginEntry.installPath
    : '';
  const manifestEntry = typeof pluginEntry?.manifest?.entry === 'string'
    ? pluginEntry.manifest.entry.trim()
    : '';
  const entryFile = manifestEntry || 'plugin.js';

  if (!installPath) {
    throw new Error('Plugin install path is missing');
  }
  if (
    entryFile.includes('..')
    || entryFile.startsWith('/')
    || /^[a-zA-Z]:[\\/]/.test(entryFile)
  ) {
    throw new Error(`Unsafe plugin entry path: ${entryFile}`);
  }

  const normalizedInstallPath = String(installPath).replace(/\\/g, '/').replace(/\/+$/, '');
  const normalizedEntry = String(entryFile).replace(/\\/g, '/').replace(/^\/+/, '');
  return `${normalizedInstallPath}/${normalizedEntry}`;
}

function buildPluginEntryCandidates(pluginEntry = {}) {
  const primaryEntryPath = resolvePluginEntryPath(pluginEntry);
  const installPath = typeof pluginEntry?.installPath === 'string'
    ? pluginEntry.installPath
    : '';
  const pluginId = String(pluginEntry?.pluginId || '').trim();
  const pluginName = String(pluginEntry?.pluginName || '').trim();
  const manifestEntry = typeof pluginEntry?.manifest?.entry === 'string'
    ? pluginEntry.manifest.entry.trim()
    : '';
  const entryFile = manifestEntry || 'plugin.js';
  const normalizedInstallPath = String(installPath).replace(/\\/g, '/').replace(/\/+$/, '');
  const normalizedEntry = String(entryFile).replace(/\\/g, '/').replace(/^\/+/, '');
  const basename = normalizedEntry.split('/').filter(Boolean).pop() || normalizedEntry;
  const candidates = [primaryEntryPath];

  [pluginId, pluginName]
    .map((value) => String(value || '').trim())
    .filter(Boolean)
    .forEach((prefix) => {
      candidates.push(`${normalizedInstallPath}/${prefix}/${normalizedEntry}`);
      candidates.push(`${normalizedInstallPath}/${prefix}/${basename}`);
    });

  return Array.from(new Set(candidates.filter(Boolean)));
}

async function loadPluginRuntime(payload = {}) {
  const pluginEntry = payload?.plugin && typeof payload.plugin === 'object'
    ? payload.plugin
    : {};
  const pluginId = String(pluginEntry?.pluginId || '').trim();
  const forceReload = Boolean(payload?.forceReload);
  const packetsnitchVersion = String(payload?.packetsnitchVersion || '').trim() || 'unknown';

  try {
    if (!window.installapi || typeof window.installapi.checkFirstRun !== 'function') {
      window.installapi = {
        checkFirstRun: async () => ({
          success: true,
          version: packetsnitchVersion,
        }),
      };
    }

    const entryCandidates = buildPluginEntryCandidates(pluginEntry);
    const runtimeRequire =
      typeof __non_webpack_require__ === 'function' ? __non_webpack_require__ : null;
    if (!runtimeRequire) {
      throw new Error('Plugin runtime require is unavailable in preload');
    }

    let pluginModule = null;
    let entryPath = '';
    let lastLoadError = null;

    for (const candidatePath of entryCandidates) {
      try {
        if (forceReload) {
          try {
            if (runtimeRequire.cache && typeof runtimeRequire.resolve === 'function') {
              delete runtimeRequire.cache[runtimeRequire.resolve(candidatePath)];
            }
          } catch (_cacheError) {
            // Ignore cache misses.
          }
        }
        pluginModule = runtimeRequire(candidatePath);
        entryPath = candidatePath;
        break;
      } catch (loadError) {
        lastLoadError = loadError;
      }
    }

    if (!pluginModule) {
      throw lastLoadError || new Error('Unable to load plugin entry module');
    }

    const pluginRuntime = pluginModule?.default || pluginModule;

    const runtimeContext = {
      plugin: pluginEntry,
      packetsnitchVersion,
      documentRef: document,
      windowRef: window,
      statusUpdate: (message) => {
        try {
          window.postMessage(
            {
              source: 'packetsnitch-plugin-runtime',
              type: 'status-update',
              pluginId,
              message: String(message || ''),
            },
            '*',
          );
        } catch (_statusError) {
          // Best-effort status update.
        }
      },
      writeLogEntry: async (message) => {
        try {
          await ipcRenderer.invoke('append-activity-log', {
            source: pluginId || 'plugin-runtime',
            message: String(message || ''),
            level: 'info',
          });
        } catch (_logError) {
          // Logging failures should not stop plugin execution.
        }
      },
    };

    let result;
    if (pluginRuntime && typeof pluginRuntime.init === 'function') {
      result = await pluginRuntime.init(runtimeContext);
    } else if (typeof pluginRuntime === 'function') {
      result = await pluginRuntime(runtimeContext);
    } else if (
      window.HelloSnitchPlugin
      && typeof window.HelloSnitchPlugin.init === 'function'
      && pluginId === 'hello-snitch'
    ) {
      result = await window.HelloSnitchPlugin.init(runtimeContext);
    } else {
      throw new Error('Plugin entry does not export an init function');
    }

    loadedPluginRuntimes.set(pluginId, {
      pluginRuntime,
      runtimeContext,
    });

    return {
      success: true,
      pluginId,
      entryPath,
      result: result === undefined ? null : result,
    };
  } catch (error) {
    return {
      success: false,
      pluginId,
      error: error?.message || String(error || 'Unknown plugin runtime error'),
    };
  }
}

async function unloadPluginRuntime(payload = {}) {
  const pluginEntry = payload?.plugin && typeof payload.plugin === 'object'
    ? payload.plugin
    : {};
  const pluginId = String(payload?.pluginId || pluginEntry?.pluginId || '').trim();
  if (!pluginId) {
    return {
      success: false,
      error: 'Plugin id is required for unload',
    };
  }

  const runtimeRecord = loadedPluginRuntimes.get(pluginId);
  if (!runtimeRecord) {
    return {
      success: true,
      pluginId,
      unloaded: false,
    };
  }

  try {
    const { pluginRuntime, runtimeContext } = runtimeRecord;
    if (pluginRuntime && typeof pluginRuntime.dispose === 'function') {
      await pluginRuntime.dispose(runtimeContext);
    } else if (pluginRuntime && typeof pluginRuntime.deinit === 'function') {
      await pluginRuntime.deinit(runtimeContext);
    } else if (pluginRuntime && typeof pluginRuntime.shutdown === 'function') {
      await pluginRuntime.shutdown(runtimeContext);
    }
    loadedPluginRuntimes.delete(pluginId);
    return {
      success: true,
      pluginId,
      unloaded: true,
    };
  } catch (error) {
    return {
      success: false,
      pluginId,
      error: error?.message || String(error || 'Unknown plugin unload error'),
    };
  }
}

contextBridge.exposeInMainWorld('jsonapi', {
  onJsonPath: (callback) => {
    ipcRenderer.on('json-path', (_event, jsonPath) => {
      callback(jsonPath);
    });
  },
  onJsonData: (callback) => {
    ipcRenderer.on('json-data', (event, hostsJsonData) => {
      callback(hostsJsonData);
    });
  },
});

contextBridge.exposeInMainWorld('captureapi', {
  loadFile: (sourcePath) => ipcRenderer.invoke('capture-store-load-file', sourcePath),
  loadJson: (jsonData) => ipcRenderer.invoke('capture-store-load-json', jsonData),
  loadData: (payload) => ipcRenderer.invoke('capture-store-load-data', payload),
  getPacket: (packetKey) => ipcRenderer.invoke('capture-store-get-packet', packetKey),
  getPacketStub: (packetKey) => ipcRenderer.invoke('capture-store-get-packet-stub', packetKey),
  getListWindow: (request) => ipcRenderer.invoke('capture-store-get-list-window', request),
  exportSessionData: () => ipcRenderer.invoke('capture-store-export-session-data'),
  filter: (query) => ipcRenderer.invoke('capture-store-filter', query),
});

contextBridge.exposeInMainWorld('snitchapi', {
  initBackendService: (backendOptions) =>
    ipcRenderer.invoke('init-backend-service', backendOptions),
  getBackendDiagnostics: (options = {}) =>
    ipcRenderer.invoke('get-backend-diagnostics', options),
  lookupGeoip: (ipAddress, options = {}) =>
    ipcRenderer.invoke('lookup-backend-geoip', ipAddress, options),
  lookupWhois: (ipAddress, options = {}) =>
    ipcRenderer.invoke('lookup-backend-whois', ipAddress, options),
  lookupIpsum: (ipAddress, options = {}) =>
    ipcRenderer.invoke('lookup-backend-ipsum', ipAddress, options),
  lookupTor: (ipAddress, options = {}) =>
    ipcRenderer.invoke('lookup-backend-tor', ipAddress, options),
  lookupShodan: (ipAddress, options = {}) =>
    ipcRenderer.invoke('lookup-backend-shodan', ipAddress, options),
  checkNmapInstalled: () =>
    ipcRenderer.invoke('check-nmap-installed'),
  getNmapScanStatus: () =>
    ipcRenderer.invoke('get-nmap-scan-status'),
  runNmapServiceScan: (targets, options = {}) =>
    ipcRenderer.invoke('run-nmap-service-scan', targets, options),
  runBackendCommand: (filename, useLLM, chunkSize, workerThreads, backendOptions, jobId = "") =>
    ipcRenderer.invoke('run-backend-command', filename, useLLM, chunkSize, workerThreads, backendOptions, jobId),
  runBackendCommandFromSession: (sessionPcap, useLLM, chunkSize, workerThreads, backendOptions, jobId = "") =>
    ipcRenderer.invoke('run-backend-command-from-session', sessionPcap, useLLM, chunkSize, workerThreads, backendOptions, jobId),
  onPcapSource: (callback) => {
    ipcRenderer.on('backend-pcap-source', (_event, payload) => {
      callback(payload);
    });
  },
  shutdownBackend: () => ipcRenderer.invoke('control-backend-service', 'stop-processing'),
});

contextBridge.exposeInMainWorld('getfileapi', {
  selectFile: () => ipcRenderer.invoke('select-file'),
  selectManualConvFile: () => ipcRenderer.invoke('select-manual-conv-file'),
});

contextBridge.exposeInMainWorld('api', {
  onError: (callback) => {
    ipcRenderer.on('backend-error', (_event, message) => {
      callback(message);
    });
  },
});

contextBridge.exposeInMainWorld('fsize', {
  getFSize: () => ipcRenderer.invoke('file-size'), // Expose this method to renderer
});

contextBridge.exposeInMainWorld('saveapi', {
  saveJson: (jsonData) => ipcRenderer.invoke('save-json', jsonData),
  savePacket: (packetData) => ipcRenderer.invoke('save-packet', packetData),
  savePayload: (payloadHex) => ipcRenderer.invoke('save-payload', payloadHex),
  saveText: (options) => ipcRenderer.invoke('save-text', options),
  saveCookieJar: (cookieJarText) =>
    ipcRenderer.invoke('save-cookie-jar', cookieJarText),
  saveHttpBody: (bodyHex, contentType) =>
    ipcRenderer.invoke('save-http-body', bodyHex, contentType),
  saveNotes: (notesText) => ipcRenderer.invoke('save-notes', notesText),
});

contextBridge.exposeInMainWorld('previewapi', {
  previewHttpBody: (bodyHex, contentType) =>
    ipcRenderer.invoke('preview-http-body', bodyHex, contentType),
});

contextBridge.exposeInMainWorld('browserapi', {
  openExternalUrl: (url) => ipcRenderer.invoke('open-external-url', url),
  getLinuxReleasePackageFamily: () => ipcRenderer.invoke('get-linux-release-package-family'),
  getRuntimePlatform: () => ipcRenderer.invoke('get-runtime-platform'),
});

contextBridge.exposeInMainWorld('quitapi', {
  quitApp: () => ipcRenderer.invoke('quit-app'),
  promptSaveOnExit: () => ipcRenderer.invoke('prompt-save-session-on-exit'),
});

contextBridge.exposeInMainWorld('installapi', {
  checkFirstRun: () => ipcRenderer.invoke('check-first-run'),
  getLlmDiagnostics: () => ipcRenderer.invoke('get-llm-diagnostics'),
  onLlmDiagnosticsUpdated: (callback) => {
    const listener = (_event, diagnostics) => {
      callback(diagnostics);
    };
    ipcRenderer.on('llm-diagnostics-updated', listener);
    return () => ipcRenderer.removeListener('llm-diagnostics-updated', listener);
  },
  dismissFirstRun: () => ipcRenderer.invoke('dismiss-first-run'),
});

contextBridge.exposeInMainWorld('logapi', {
  append: (entry) => ipcRenderer.invoke('append-activity-log', entry),
  getPath: () => ipcRenderer.invoke('get-activity-log-path'),
  getEntries: () => ipcRenderer.invoke('get-activity-log-entries'),
  onEntry: (callback) => {
    const listener = (_event, entry) => {
      callback(entry);
    };
    ipcRenderer.on('activity-log-entry', listener);
    return () => ipcRenderer.removeListener('activity-log-entry', listener);
  },
});

contextBridge.exposeInMainWorld('sessionsapi', {
  list: () => ipcRenderer.invoke('sessions-list'),
  load: (name) => ipcRenderer.invoke('session-load', name),
  save: (name, jsonData) => ipcRenderer.invoke('session-save', name, jsonData),
  rename: (oldName, newName) => ipcRenderer.invoke('session-rename', oldName, newName),
  remove: (name) => ipcRenderer.invoke('session-delete', name),
  exportToFile: (name, jsonData) => ipcRenderer.invoke('session-export', name, jsonData),
});

contextBridge.exposeInMainWorld('templateapi', {
  onJsonTemplate: (callback) => {
    ipcRenderer.on('json-template', (event, templateJsonData) => {
      callback(templateJsonData);
    });
  },
  getNewSessionTemplate: () => ipcRenderer.invoke('get-new-session-template'),
  getUiFragment: (fragmentName) => ipcRenderer.invoke('get-ui-fragment', fragmentName),
});

contextBridge.exposeInMainWorld('goodiesapi', {
  getGoodies: () => ipcRenderer.invoke('get-goodies'),
  onGoodies: (callback) => {
    ipcRenderer.on('goodies-data', (_event, goodiesData) => {
      callback(goodiesData);
    });
  },
});

contextBridge.exposeInMainWorld('validkeysapi', {
  getValidKeys: () => ipcRenderer.invoke('get-valid-keys'),
  onValidKeys: (callback) => {
    ipcRenderer.on('valid-keys-data', (_event, validKeysData) => {
      callback(validKeysData);
    });
  },
});

contextBridge.exposeInMainWorld('modelsapi', {
  getOllamaModels: () => ipcRenderer.invoke('get-ollama-models'),
});

contextBridge.exposeInMainWorld('settingsapi', {
  get: () => ipcRenderer.invoke('settings-get'),
  save: (settings) => ipcRenderer.invoke('settings-save', settings),
  update: (partialSettings) => ipcRenderer.invoke('settings-update', partialSettings),
});

contextBridge.exposeInMainWorld('themeapi', {
  list: () => ipcRenderer.invoke('themes-list'),
  get: (themeId) => ipcRenderer.invoke('themes-get', themeId),
  getThemesDirectory: () => ipcRenderer.invoke('themes-directory'),
});

contextBridge.exposeInMainWorld('savedfiltersapi', {
  list: () => ipcRenderer.invoke('saved-filters-list'),
  save: (payload) => ipcRenderer.invoke('saved-filters-save', payload),
  remove: (payload) => ipcRenderer.invoke('saved-filters-remove', payload),
});

contextBridge.exposeInMainWorld('pluginapi', {
  selectZip: () => ipcRenderer.invoke('select-plugin-zip'),
  list: () => ipcRenderer.invoke('plugins-list'),
  inspectZip: (payload) => ipcRenderer.invoke('plugins-inspect-zip', payload),
  install: (payload) => ipcRenderer.invoke('plugins-install', payload),
  loadRuntime: (payload) => loadPluginRuntime(payload),
  unloadRuntime: (payload) => unloadPluginRuntime(payload),
  setEnabled: (payload) => ipcRenderer.invoke('plugins-set-enabled', payload),
  setPriority: (payload) => ipcRenderer.invoke('plugins-set-priority', payload),
  setFailureThreshold: (payload) => ipcRenderer.invoke('plugins-set-failure-threshold', payload),
  recordFailure: (payload) => ipcRenderer.invoke('plugins-record-failure', payload),
  resetFailures: (payload) => ipcRenderer.invoke('plugins-reset-failures', payload),
  uninstall: (payload) => ipcRenderer.invoke('plugins-uninstall', payload),
});


contextBridge.exposeInMainWorld("llmapi", {
  generate: (prompt, options = {}) => ipcRenderer.invoke("ollama:generate", prompt, options),
});
