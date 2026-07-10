const { contextBridge, ipcRenderer } = require('electron');

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
  checkNmapInstalled: () =>
    ipcRenderer.invoke('check-nmap-installed'),
  getNmapScanStatus: () =>
    ipcRenderer.invoke('get-nmap-scan-status'),
  runNmapServiceScan: (targets, options = {}) =>
    ipcRenderer.invoke('run-nmap-service-scan', targets, options),
  runBackendCommand: (filename, useLLM, chunkSize, workerThreads, backendOptions) =>
    ipcRenderer.invoke('run-backend-command', filename, useLLM, chunkSize, workerThreads, backendOptions),
  runBackendCommandFromSession: (sessionPcap, useLLM, chunkSize, workerThreads, backendOptions) =>
    ipcRenderer.invoke('run-backend-command-from-session', sessionPcap, useLLM, chunkSize, workerThreads, backendOptions),
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


contextBridge.exposeInMainWorld("llmapi", {
  generate: (prompt, options = {}) => ipcRenderer.invoke("ollama:generate", prompt, options),
});
