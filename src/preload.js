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