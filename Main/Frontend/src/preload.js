const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('jsonapi', {
  onJsonData: (callback) => {
    ipcRenderer.on('json-data', (event, hostsJsonData) => {
      callback(hostsJsonData);
    });
  },
});

contextBridge.exposeInMainWorld('snitchapi', {
  runBackendCommand: (filename, useLLM) =>
    ipcRenderer.invoke('run-backend-command', filename, useLLM),
});

contextBridge.exposeInMainWorld('getfileapi', {
  selectFile: () => ipcRenderer.invoke('select-file'),
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
  saveCookieJar: (cookieJarText) =>
    ipcRenderer.invoke('save-cookie-jar', cookieJarText),
  saveHttpBody: (bodyHex, contentType) =>
    ipcRenderer.invoke('save-http-body', bodyHex, contentType),
});

contextBridge.exposeInMainWorld('previewapi', {
  previewHttpBody: (bodyHex, contentType) =>
    ipcRenderer.invoke('preview-http-body', bodyHex, contentType),
});

contextBridge.exposeInMainWorld('quitapi', {
  quitApp: () => ipcRenderer.invoke('quit-app'),
  promptSaveOnExit: () => ipcRenderer.invoke('prompt-save-session-on-exit'),
});

contextBridge.exposeInMainWorld('installapi', {
  checkFirstRun: () => ipcRenderer.invoke('check-first-run'),
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
