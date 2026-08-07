// Exposes the safe preload bridge APIs from Electron to the renderer process.

const { contextBridge, ipcRenderer } = require('electron');
const runtimeRequire =
  typeof __non_webpack_require__ === 'function' ? __non_webpack_require__ : null;

if (!runtimeRequire) {
  throw new Error('Plugin runtime require is unavailable in preload');
}

const childProcess = runtimeRequire('child_process');
const fs = runtimeRequire('fs');
const net = runtimeRequire('net');
const os = runtimeRequire('os');
const path = runtimeRequire('path');
const loadedPluginRuntimes = new Map();
const pendingPluginFilterUiRequests = new Map();
let pluginFilterUiRequestCounter = 0;
let pluginFilterUiResponseListenerAttached = false;
const pluginRuntimeDataState = {
  currentPacketKey: null,
  currentPacketMetadata: null,
  currentStreamTuple: null,
  sessionPcapSource: null,
  statsJson: null,
  keystoreEntries: [],
};

const PLUGIN_CAPABILITY_CATALOG = [
  {
    capability: 'version.read',
    description: 'Read PacketSnitch runtime version',
  },
  {
    capability: 'ui.dialog.add',
    description: 'Open plugin-owned UI dialogs',
  },
  {
    capability: 'ui.dom.write',
    description: 'Modify renderer DOM nodes',
  },
  {
    capability: 'ui.tabs.create',
    description: 'Create plugin tabs',
  },
  {
    capability: 'ui.tabs.modify',
    description: 'Modify plugin tabs',
  },
  {
    capability: 'ui.contextmenu.create',
    description: 'Create context menu entries',
  },
  {
    capability: 'ui.contextmenu.modify',
    description: 'Modify context menu entries',
  },
  {
    capability: 'ui.statusbar.modify',
    description: 'Change status bar messages',
  },
  {
    capability: 'fs.read',
    description: 'Read files from disk',
  },
  {
    capability: 'fs.write',
    description: 'Write files to disk',
  },
  {
    capability: 'fs.execute',
    description: 'Execute filesystem commands/programs',
  },
  {
    capability: 'fs.chmod',
    description: 'Modify filesystem mode/permissions',
  },
  {
    capability: 'network.fetch.http',
    description: 'Perform HTTP/HTTPS fetch requests',
  },
  {
    capability: 'network.socket.listen',
    description: 'Listen for inbound socket connections',
  },
  {
    capability: 'network.socket.connect',
    description: 'Open outbound socket connections',
  },
  {
    capability: 'packetsnitch.functions.use',
    description: 'Use exposed PacketSnitch host functions',
  },
  {
    capability: 'packetsnitch.functions.overwrite',
    description: 'Temporarily wrap/override exposed host functions',
  },
  {
    capability: 'backend.talk',
    description: 'Invoke backend IPC bridge endpoints',
  },
  {
    capability: 'packet.metadata.read',
    description: 'Read current packet metadata exposed by the renderer',
  },
  {
    capability: 'session.pcap.read',
    description: 'Read the raw session source PCAP payload',
  },
  {
    capability: 'stats.json.read',
    description: 'Read Stats workspace JSON snapshot data',
  },
  {
    capability: 'keystore.read',
    description: 'Read session keystore entries',
  },
  {
    capability: 'keystore.write',
    description: 'Write session keystore entries',
  },
  {
    capability: 'filter.query',
    description: 'Query capture filter expressions in background or UI mode',
  },
  {
    capability: 'plugin.log.write',
    description: 'Write plugin log entries to activity log',
  },
];

const LEGACY_CAPABILITY_ALIASES = {
  'ui.message': 'ui.statusbar.modify',
  'ui.tab': 'ui.tabs.create',
  'ui.contextmenu': 'ui.contextmenu.create',
  'filesystem.read': 'fs.read',
  'filesystem.write': 'fs.write',
  'documents.write': 'ui.dom.write',
  'network.fetch': 'network.fetch.http',
  'status.wrap': 'packetsnitch.functions.overwrite',
};

const DOM_MUTATION_METHODS = new Set([
  'append',
  'appendChild',
  'after',
  'before',
  'insertAdjacentHTML',
  'insertAdjacentText',
  'insertBefore',
  'prepend',
  'remove',
  'removeAttribute',
  'removeChild',
  'replaceChild',
  'replaceWith',
  'setAttribute',
  'setAttributeNS',
  'toggleAttribute',
]);

const DOM_MUTATION_PROPERTIES = new Set([
  'className',
  'hidden',
  'id',
  'innerHTML',
  'innerText',
  'onclick',
  'onchange',
  'oninput',
  'outerHTML',
  'style',
  'textContent',
  'value',
]);

const PLUGIN_BACKEND_CHANNEL_ALLOWLIST = new Set([
  'lookup-backend-geoip',
  'lookup-backend-whois',
  'lookup-backend-ipsum',
  'lookup-backend-tor',
  'lookup-backend-shodan',
  'lookup-backend-virustotal',
  'get-backend-diagnostics',
  'control-backend-service',
]);

function normalizeCapabilityToken(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizePluginCapabilities(capabilities) {
  const normalized = new Set();
  const capabilityList = Array.isArray(capabilities) ? capabilities : [];
  for (const entry of capabilityList) {
    const token = normalizeCapabilityToken(entry);
    if (!token) continue;
    normalized.add(token);
    const alias = LEGACY_CAPABILITY_ALIASES[token];
    if (alias) {
      normalized.add(alias);
    }
  }
  return normalized;
}

function capabilityIsGranted(grantedCapabilities, requiredCapability) {
  if (!(grantedCapabilities instanceof Set)) {
    return false;
  }
  const required = normalizeCapabilityToken(requiredCapability);
  if (!required) {
    return true;
  }
  if (grantedCapabilities.has('*') || grantedCapabilities.has(required)) {
    return true;
  }
  const segments = required.split('.');
  for (let index = segments.length - 1; index > 0; index -= 1) {
    const wildcard = `${segments.slice(0, index).join('.')}.*`;
    if (grantedCapabilities.has(wildcard)) {
      return true;
    }
  }
  return false;
}

async function appendPluginActivityLog(pluginId, message, level = 'info') {
  const safePluginId = String(pluginId || 'plugin-runtime').trim() || 'plugin-runtime';
  const safeMessage = String(message || '').trim();
  if (!safeMessage) {
    return;
  }
  const entry = `[${new Date().toISOString()}] [GUI][Plugin][${safePluginId}] ${safeMessage}`;
  try {
    await ipcRenderer.invoke('append-activity-log', entry);
  } catch (_error) {
    // Log writes are best-effort.
  }
}

async function logPluginDeniedCapability(pluginState, requiredCapability, reason) {
  const pluginId = pluginState?.pluginId || 'plugin-runtime';
  const deniedCapability = String(requiredCapability || 'unknown').trim() || 'unknown';
  const deniedReason = String(reason || '').trim();
  const deniedMessage = deniedReason
    ? `Plugin permission denied capability=${JSON.stringify(deniedCapability)} reason=${JSON.stringify(deniedReason)}`
    : `Plugin permission denied capability=${JSON.stringify(deniedCapability)}`;
  await appendPluginActivityLog(pluginId, deniedMessage, 'warn');
}

function assertPluginCapability(pluginState, requiredCapability, reason = '') {
  if (capabilityIsGranted(pluginState?.capabilities, requiredCapability)) {
    return;
  }
  logPluginDeniedCapability(pluginState, requiredCapability, reason);
  const detail = String(reason || '').trim();
  throw new Error(
    detail
      ? `Plugin permission denied: ${requiredCapability} (${detail})`
      : `Plugin permission denied: ${requiredCapability}`,
  );
}

function createPluginSecurityState(pluginEntry = {}) {
  const pluginId = String(pluginEntry?.pluginId || '').trim();
  return {
    pluginId,
    capabilities: normalizePluginCapabilities(pluginEntry?.capabilities),
  };
}

function createGuardedFetch(pluginState) {
  return async (input, init) => {
    assertPluginCapability(pluginState, 'network.fetch.http', 'fetch');
    const requestUrl =
      typeof input === 'string'
        ? input
        : typeof input?.url === 'string'
          ? input.url
          : '';
    const parsedUrl = (() => {
      try {
        return new URL(String(requestUrl || ''));
      } catch (_error) {
        return null;
      }
    })();
    const protocol = String(parsedUrl?.protocol || '').toLowerCase();
    if (protocol !== 'http:' && protocol !== 'https:') {
      await logPluginDeniedCapability(
        pluginState,
        'network.fetch.http',
        `unsupported URL protocol ${protocol || 'unknown'}`,
      );
      throw new Error('Plugin permission denied: network.fetch.http requires http/https URL');
    }
    return fetch(input, init);
  };
}

function createPluginFsApi(pluginState) {
  return {
    readText: async (filePath, encoding = 'utf8') => {
      assertPluginCapability(pluginState, 'fs.read', 'fs.readText');
      return fs.promises.readFile(String(filePath || ''), String(encoding || 'utf8'));
    },
    writeText: async (filePath, content, encoding = 'utf8') => {
      assertPluginCapability(pluginState, 'fs.write', 'fs.writeText');
      await fs.promises.writeFile(
        String(filePath || ''),
        String(content || ''),
        String(encoding || 'utf8'),
      );
      return { success: true, path: String(filePath || '') };
    },
    chmod: async (filePath, mode) => {
      assertPluginCapability(pluginState, 'fs.chmod', 'fs.chmod');
      await fs.promises.chmod(String(filePath || ''), mode);
      return { success: true, path: String(filePath || ''), mode };
    },
    execute: async (command, options = {}) => {
      assertPluginCapability(pluginState, 'fs.execute', 'fs.execute');
      return new Promise((resolve, reject) => {
        childProcess.exec(String(command || ''), options, (error, stdout, stderr) => {
          if (error) {
            reject(error);
            return;
          }
          resolve({ stdout, stderr });
        });
      });
    },
    homeDirectory: () => {
      assertPluginCapability(pluginState, 'fs.read', 'fs.homeDirectory');
      return os.homedir();
    },
    joinPath: (...segments) => path.join(...segments.map((entry) => String(entry || ''))),
  };
}

function createPluginNetworkApi(pluginState, guardedFetch) {
  return {
    fetch: guardedFetch,
    socketConnect: ({ host, port, timeoutMs = 5000 } = {}) => {
      assertPluginCapability(pluginState, 'network.socket.connect', 'network.socket.connect');
      return new Promise((resolve, reject) => {
        const socket = net.createConnection({ host, port: Number(port) }, () => {
          socket.end();
          resolve({ success: true, host, port: Number(port) });
        });
        socket.setTimeout(Math.max(1, Number(timeoutMs) || 5000));
        socket.on('timeout', () => {
          socket.destroy(new Error('Socket connect timed out'));
        });
        socket.on('error', (error) => {
          reject(error);
        });
      });
    },
    socketListen: ({ host = '127.0.0.1', port = 0 } = {}) => {
      assertPluginCapability(pluginState, 'network.socket.listen', 'network.socket.listen');
      return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.once('error', (error) => {
          reject(error);
        });
        server.listen(Number(port), host, () => {
          const addressInfo = server.address();
          server.close(() => {
            resolve({
              success: true,
              host,
              port: typeof addressInfo === 'object' && addressInfo ? addressInfo.port : Number(port),
            });
          });
        });
      });
    },
  };
}

function createGuardedDomProxy(targetValue, pluginState, cache = new WeakMap()) {
  if (!targetValue || (typeof targetValue !== 'object' && typeof targetValue !== 'function')) {
    return targetValue;
  }
  if (cache.has(targetValue)) {
    return cache.get(targetValue);
  }

  const proxiedValue = new Proxy(targetValue, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (typeof value === 'function') {
        return (...args) => {
          const name = String(property || '');
          if (DOM_MUTATION_METHODS.has(name)) {
            assertPluginCapability(pluginState, 'ui.dom.write', `dom.${name}`);
          }
          const callResult = value.apply(target, args);
          return createGuardedDomProxy(callResult, pluginState, cache);
        };
      }
      return createGuardedDomProxy(value, pluginState, cache);
    },
    set(target, property, value, receiver) {
      if (DOM_MUTATION_PROPERTIES.has(String(property || ''))) {
        assertPluginCapability(pluginState, 'ui.dom.write', `dom.set.${String(property || '')}`);
      }
      return Reflect.set(target, property, value, receiver);
    },
    deleteProperty(target, property) {
      assertPluginCapability(pluginState, 'ui.dom.write', `dom.delete.${String(property || '')}`);
      return Reflect.deleteProperty(target, property);
    },
  });

  cache.set(targetValue, proxiedValue);
  return proxiedValue;
}

function createPluginHostFunctions(baseFunctions = {}) {
  const functionMap = new Map();
  Object.keys(baseFunctions).forEach((name) => {
    if (typeof baseFunctions[name] === 'function') {
      functionMap.set(name, baseFunctions[name]);
    }
  });
  return {
    call(name, ...args) {
      const handler = functionMap.get(String(name || ''));
      if (!handler) {
        throw new Error(`Unknown PacketSnitch function: ${name}`);
      }
      return handler(...args);
    },
    overwrite(name, wrapperFactory) {
      const functionName = String(name || '');
      const original = functionMap.get(functionName);
      if (!original) {
        throw new Error(`Unknown PacketSnitch function: ${name}`);
      }
      if (typeof wrapperFactory !== 'function') {
        throw new Error('Function wrapper must be a function');
      }
      const wrapped = wrapperFactory(original);
      if (typeof wrapped !== 'function') {
        throw new Error('Function wrapper must return a function');
      }
      functionMap.set(functionName, wrapped);
      return () => {
        functionMap.set(functionName, original);
      };
    },
  };
}

function createPluginUiApi(pluginState, hostFunctions) {
  return {
    dialog: {
      alert: (message) => {
        assertPluginCapability(pluginState, 'ui.dialog.add', 'ui.dialog.alert');
        window.alert(String(message || ''));
      },
      confirm: (message) => {
        assertPluginCapability(pluginState, 'ui.dialog.add', 'ui.dialog.confirm');
        return window.confirm(String(message || ''));
      },
      prompt: (message, defaultValue = '') => {
        assertPluginCapability(pluginState, 'ui.dialog.add', 'ui.dialog.prompt');
        return window.prompt(String(message || ''), String(defaultValue || ''));
      },
    },
    statusBar: {
      setText: (message) => {
        assertPluginCapability(pluginState, 'ui.statusbar.modify', 'ui.statusbar.modify');
        hostFunctions.call('statusUpdate', String(message || ''));
      },
    },
    tabs: {
      create: ({ id, label }) => {
        assertPluginCapability(pluginState, 'ui.tabs.create', 'ui.tabs.create');
        const tabRow = document.getElementById('tab-btns');
        if (!tabRow) throw new Error('Unable to resolve tab button row');
        const tabId = String(id || '').trim();
        if (!tabId) throw new Error('Tab id is required');
        let tabButton = document.getElementById(tabId);
        if (!tabButton) {
          tabButton = document.createElement('input');
          tabButton.type = 'button';
          tabButton.id = tabId;
          tabButton.className = 'custom-btns';
          tabRow.appendChild(tabButton);
        }
        tabButton.value = String(label || tabButton.value || tabId);
        return { id: tabId, label: tabButton.value };
      },
      modify: ({ id, label, hidden } = {}) => {
        assertPluginCapability(pluginState, 'ui.tabs.modify', 'ui.tabs.modify');
        const tabButton = document.getElementById(String(id || '').trim());
        if (!tabButton) throw new Error('Tab not found');
        if (label !== undefined) tabButton.value = String(label || '');
        if (hidden !== undefined) tabButton.hidden = Boolean(hidden);
        return { id: tabButton.id, label: tabButton.value, hidden: tabButton.hidden };
      },
    },
    contextMenu: {
      create: ({ id, text, onClick } = {}) => {
        assertPluginCapability(pluginState, 'ui.contextmenu.create', 'ui.contextmenu.create');
        const contextMenu = document.getElementById('convert-context-menu');
        if (!contextMenu) {
          throw new Error('Context menu root was not found');
        }
        const itemId = String(id || '').trim();
        if (!itemId) {
          throw new Error('Context menu item id is required');
        }
        let button = document.getElementById(itemId);
        if (!button) {
          button = document.createElement('button');
          button.type = 'button';
          button.id = itemId;
          button.setAttribute('role', 'menuitem');
          contextMenu.appendChild(button);
        }
        button.textContent = String(text || button.textContent || itemId);
        if (typeof onClick === 'function') {
          button.onclick = () => {
            onClick();
          };
        }
        return { id: itemId, text: button.textContent };
      },
      modify: ({ id, text, hidden } = {}) => {
        assertPluginCapability(pluginState, 'ui.contextmenu.modify', 'ui.contextmenu.modify');
        const button = document.getElementById(String(id || '').trim());
        if (!button) throw new Error('Context menu entry not found');
        if (text !== undefined) button.textContent = String(text || '');
        if (hidden !== undefined) button.hidden = Boolean(hidden);
        return { id: button.id, text: button.textContent, hidden: button.hidden };
      },
    },
    dom: {
      query: (selector) => {
        assertPluginCapability(pluginState, 'ui.dom.write', 'ui.dom.query');
        return document.querySelector(String(selector || ''));
      },
      setText: (selector, text) => {
        assertPluginCapability(pluginState, 'ui.dom.write', 'ui.dom.setText');
        const element = document.querySelector(String(selector || ''));
        if (!element) {
          return { updated: false };
        }
        element.textContent = String(text || '');
        return { updated: true };
      },
    },
  };
}

function createPluginBackendApi(pluginState) {
  return {
    invoke: async (channel, ...args) => {
      assertPluginCapability(pluginState, 'backend.talk', 'backend.talk');
      const channelName = String(channel || '').trim();
      if (!PLUGIN_BACKEND_CHANNEL_ALLOWLIST.has(channelName)) {
        await logPluginDeniedCapability(
          pluginState,
          'backend.talk',
          `backend channel ${JSON.stringify(channelName)} is not allowlisted`,
        );
        throw new Error(`Plugin backend channel is not allowed: ${channelName}`);
      }
      return ipcRenderer.invoke(channelName, ...args);
    },
  };
}

function cloneJsonValue(value, fallback = null) {
  try {
    if (value === undefined) {
      return fallback;
    }
    return JSON.parse(JSON.stringify(value));
  } catch (_error) {
    return fallback;
  }
}

function estimateBase64DecodedByteLength(base64Data) {
  const normalized = typeof base64Data === 'string'
    ? base64Data.replace(/\s+/g, '')
    : '';
  if (!normalized) return 0;
  const paddingMatch = normalized.match(/=+$/);
  const paddingLength = paddingMatch ? paddingMatch[0].length : 0;
  return Math.max(0, Math.floor((normalized.length * 3) / 4) - paddingLength);
}

function normalizeSessionPcapSource(source) {
  if (!source || typeof source !== 'object') return null;
  const normalizedBase64 =
    typeof source.data === 'string' ? source.data.replace(/\s+/g, '').trim() : '';
  if (!normalizedBase64) return null;
  const explicitByteLength = Number(source.byteLength);
  const byteLength =
    Number.isFinite(explicitByteLength) && explicitByteLength > 0
      ? Math.floor(explicitByteLength)
      : estimateBase64DecodedByteLength(normalizedBase64);
  const fileName =
    typeof source.fileName === 'string' && source.fileName.trim()
      ? source.fileName.trim()
      : 'capture.pcap';
  return {
    fileName,
    encoding: 'base64',
    data: normalizedBase64,
    byteLength,
  };
}

function updatePluginRuntimeDataState(payload = {}) {
  if (!payload || typeof payload !== 'object') {
    return { success: false, error: 'Invalid plugin runtime data payload' };
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'currentPacketKey')) {
    const key =
      typeof payload.currentPacketKey === 'string' && payload.currentPacketKey.trim()
        ? payload.currentPacketKey.trim()
        : null;
    pluginRuntimeDataState.currentPacketKey = key;
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'currentPacketMetadata')) {
    pluginRuntimeDataState.currentPacketMetadata =
      payload.currentPacketMetadata && typeof payload.currentPacketMetadata === 'object'
        ? cloneJsonValue(payload.currentPacketMetadata, null)
        : null;
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'currentStreamTuple')) {
    pluginRuntimeDataState.currentStreamTuple =
      payload.currentStreamTuple && typeof payload.currentStreamTuple === 'object'
        ? cloneJsonValue(payload.currentStreamTuple, null)
        : null;
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'sessionPcapSource')) {
    pluginRuntimeDataState.sessionPcapSource = normalizeSessionPcapSource(payload.sessionPcapSource);
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'statsJson')) {
    pluginRuntimeDataState.statsJson =
      payload.statsJson && typeof payload.statsJson === 'object'
        ? cloneJsonValue(payload.statsJson, null)
        : null;
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'keystoreEntries')) {
    pluginRuntimeDataState.keystoreEntries = Array.isArray(payload.keystoreEntries)
      ? cloneJsonValue(payload.keystoreEntries, [])
      : [];
  }

  return { success: true };
}

function createPluginCaptureApi(pluginState) {
  return {
    getCurrentPacketKey: () => {
      assertPluginCapability(pluginState, 'packet.metadata.read', 'capture.getCurrentPacketKey');
      return pluginRuntimeDataState.currentPacketKey;
    },
    getCurrentPacketMetadata: () => {
      assertPluginCapability(
        pluginState,
        'packet.metadata.read',
        'capture.getCurrentPacketMetadata',
      );
      return cloneJsonValue(pluginRuntimeDataState.currentPacketMetadata, null);
    },
    getCurrentStreamTuple: () => {
      assertPluginCapability(pluginState, 'packet.metadata.read', 'capture.getCurrentStreamTuple');
      return cloneJsonValue(pluginRuntimeDataState.currentStreamTuple, null);
    },
    getSessionPcapSource: async () => {
      assertPluginCapability(pluginState, 'session.pcap.read', 'capture.getSessionPcapSource');
      if (pluginRuntimeDataState.sessionPcapSource) {
        return cloneJsonValue(pluginRuntimeDataState.sessionPcapSource, null);
      }
      try {
        const exportResult = await ipcRenderer.invoke('capture-store-export-session-data');
        const sourcePcap = exportResult?.sessionState?.sourcePcap;
        return normalizeSessionPcapSource(sourcePcap);
      } catch (_error) {
        return null;
      }
    },
  };
}

function createPluginStatsApi(pluginState) {
  return {
    getJson: () => {
      assertPluginCapability(pluginState, 'stats.json.read', 'stats.getJson');
      return cloneJsonValue(pluginRuntimeDataState.statsJson, null);
    },
  };
}

function createPluginKeystoreApi(pluginState) {
  const normalizeKeystoreEntry = (entry = {}) => {
    if (!entry || typeof entry !== 'object') {
      return null;
    }
    const normalizedContent = String(entry.content || '').trim();
    if (!normalizedContent) {
      return null;
    }
    const normalizedType = String(entry.type || '').trim() || 'secret';
    return {
      id:
        typeof entry.id === 'string' && entry.id.trim()
          ? entry.id.trim()
          : `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
      type: normalizedType,
      label:
        typeof entry.label === 'string' && entry.label.trim()
          ? entry.label.trim()
          : `${normalizedType}-${new Date().toISOString()}`,
      source:
        typeof entry.source === 'string' && entry.source.trim()
          ? entry.source.trim()
          : 'plugin-runtime',
      content: normalizedContent,
      summary: typeof entry.summary === 'string' ? entry.summary : '',
      packetIndex:
        Number.isFinite(Number(entry.packetIndex)) || typeof entry.packetIndex === 'string'
          ? entry.packetIndex
          : '?',
      createdAt:
        typeof entry.createdAt === 'string' && entry.createdAt.trim()
          ? entry.createdAt.trim()
          : new Date().toISOString(),
    };
  };

  const sendKeystoreWriteRequestToRenderer = (payload = {}) => {
    if (!window || typeof window.postMessage !== 'function') {
      return;
    }
    window.postMessage(
      {
        source: 'packetsnitch-plugin-runtime',
        type: 'plugin-keystore-write',
        payload,
      },
      '*',
    );
  };

  return {
    getSessionEntries: () => {
      assertPluginCapability(pluginState, 'keystore.read', 'keystore.getSessionEntries');
      return cloneJsonValue(pluginRuntimeDataState.keystoreEntries, []);
    },
    addSessionEntry: (entry = {}) => {
      assertPluginCapability(pluginState, 'keystore.write', 'keystore.addSessionEntry');
      const normalizedEntry = normalizeKeystoreEntry(entry);
      if (!normalizedEntry) {
        throw new Error('Invalid keystore entry content');
      }

      const exists = pluginRuntimeDataState.keystoreEntries.some(
        (existingEntry) =>
          String(existingEntry?.type || '') === normalizedEntry.type
          && String(existingEntry?.label || '') === normalizedEntry.label
          && String(existingEntry?.content || '').trim() === normalizedEntry.content,
      );

      if (!exists) {
        pluginRuntimeDataState.keystoreEntries.unshift(normalizedEntry);
      }

      sendKeystoreWriteRequestToRenderer({
        action: 'addSessionEntry',
        entry: normalizedEntry,
      });

      return {
        success: true,
        added: !exists,
        entry: cloneJsonValue(normalizedEntry, null),
      };
    },
    addSessionEntries: (entries = []) => {
      assertPluginCapability(pluginState, 'keystore.write', 'keystore.addSessionEntries');
      const entryList = Array.isArray(entries) ? entries : [];
      const normalizedEntries = entryList
        .map((entry) => normalizeKeystoreEntry(entry))
        .filter(Boolean);
      let addedCount = 0;

      normalizedEntries.forEach((normalizedEntry) => {
        const exists = pluginRuntimeDataState.keystoreEntries.some(
          (existingEntry) =>
            String(existingEntry?.type || '') === normalizedEntry.type
            && String(existingEntry?.label || '') === normalizedEntry.label
            && String(existingEntry?.content || '').trim() === normalizedEntry.content,
        );
        if (exists) {
          return;
        }
        pluginRuntimeDataState.keystoreEntries.unshift(normalizedEntry);
        addedCount += 1;
      });

      if (normalizedEntries.length > 0) {
        sendKeystoreWriteRequestToRenderer({
          action: 'addSessionEntries',
          entries: normalizedEntries,
        });
      }

      return {
        success: true,
        addedCount,
        entries: cloneJsonValue(normalizedEntries, []),
      };
    },
  };
}

function attachPluginFilterUiResponseListener() {
  if (pluginFilterUiResponseListenerAttached) {
    return;
  }
  window.addEventListener('message', (event) => {
    const data = event?.data;
    if (!data || typeof data !== 'object') {
      return;
    }
    if (data.source !== 'packetsnitch-renderer' || data.type !== 'plugin-filter-query-result') {
      return;
    }
    const requestId = String(data.requestId || '').trim();
    if (!requestId || !pendingPluginFilterUiRequests.has(requestId)) {
      return;
    }

    const requestRecord = pendingPluginFilterUiRequests.get(requestId);
    pendingPluginFilterUiRequests.delete(requestId);
    clearTimeout(requestRecord.timeoutId);

    if (data.success) {
      requestRecord.resolve(cloneJsonValue(data.result, null));
      return;
    }

    const errorMessage = String(data.error || 'Renderer filter request failed');
    requestRecord.reject(new Error(errorMessage));
  });
  pluginFilterUiResponseListenerAttached = true;
}

function invokePluginFilterUiQuery(requestPayload = {}, timeoutMs = 30000) {
  attachPluginFilterUiResponseListener();
  return new Promise((resolve, reject) => {
    pluginFilterUiRequestCounter += 1;
    const requestId = `plugin-filter-${Date.now()}-${pluginFilterUiRequestCounter}`;
    const timeoutId = setTimeout(() => {
      if (!pendingPluginFilterUiRequests.has(requestId)) {
        return;
      }
      pendingPluginFilterUiRequests.delete(requestId);
      reject(new Error('Renderer UI filter query timed out'));
    }, timeoutMs);

    pendingPluginFilterUiRequests.set(requestId, {
      resolve,
      reject,
      timeoutId,
    });

    window.postMessage(
      {
        source: 'packetsnitch-plugin-runtime',
        type: 'plugin-filter-query',
        requestId,
        payload: requestPayload,
      },
      '*',
    );
  });
}

function createPluginFilterApi(pluginState) {
  return {
    query: async (expression, options = {}) => {
      assertPluginCapability(pluginState, 'filter.query', 'filter.query');
      const filterExpression = String(expression || '').trim();
      if (!filterExpression) {
        throw new Error('Filter expression is required');
      }

      const mode =
        String(options?.mode || '').trim().toLowerCase() === 'ui' ? 'ui' : 'background';

      if (mode === 'ui') {
        const uiResult = await invokePluginFilterUiQuery({
          expression: filterExpression,
          mode: 'ui',
          trackHistory: Boolean(options?.trackHistory),
        });
        return {
          success: true,
          mode: 'ui',
          expression: filterExpression,
          ...(uiResult && typeof uiResult === 'object' ? uiResult : {}),
        };
      }

      const backgroundResult = await ipcRenderer.invoke('capture-store-filter', filterExpression);
      if (!backgroundResult?.success) {
        throw new Error(backgroundResult?.error || 'Background filter query failed');
      }
      return {
        success: true,
        mode: 'background',
        expression: filterExpression,
        packetKeys: Array.isArray(backgroundResult.packetKeys) ? backgroundResult.packetKeys : [],
      };
    },
  };
}

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
  const pluginSecurityState = createPluginSecurityState(pluginEntry);

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
    let pluginModule = null;
    let entryPath = '';
    let lastLoadError = null;

    for (const candidatePath of entryCandidates) {
      try {
        if (!fs.existsSync(candidatePath)) {
          continue;
        }
        if (forceReload) {
          try {
            if (runtimeRequire.cache && typeof runtimeRequire.resolve === 'function') {
              delete runtimeRequire.cache[runtimeRequire.resolve(candidatePath)];
            }
          } catch (_cacheError) {
            // Ignore cache misses and continue load.
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

    const hostFunctions = createPluginHostFunctions({
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
        await appendPluginActivityLog(pluginId || 'plugin-runtime', message, 'info');
      },
    });

    const guardedFetch = createGuardedFetch(pluginSecurityState);
    const pluginUiApi = createPluginUiApi(pluginSecurityState, hostFunctions);

    const runtimeContext = {
      plugin: pluginEntry,
      packetsnitchVersion,
      permissions: {
        list: Array.from(pluginSecurityState.capabilities),
        has: (capability) => capabilityIsGranted(pluginSecurityState.capabilities, capability),
        assert: (capability, reason = '') =>
          assertPluginCapability(pluginSecurityState, capability, reason),
        catalog: PLUGIN_CAPABILITY_CATALOG,
      },
      api: {
        version: {
          read: () => {
            assertPluginCapability(pluginSecurityState, 'version.read', 'version.read');
            return packetsnitchVersion;
          },
        },
        ui: pluginUiApi,
        fs: createPluginFsApi(pluginSecurityState),
        network: createPluginNetworkApi(pluginSecurityState, guardedFetch),
        capture: createPluginCaptureApi(pluginSecurityState),
        stats: createPluginStatsApi(pluginSecurityState),
        keystore: createPluginKeystoreApi(pluginSecurityState),
        filter: createPluginFilterApi(pluginSecurityState),
        packetsnitch: {
          useFunction: (name, ...args) => {
            assertPluginCapability(
              pluginSecurityState,
              'packetsnitch.functions.use',
              `packetsnitch.functions.use:${String(name || '')}`,
            );
            return hostFunctions.call(name, ...args);
          },
          overwriteFunction: (name, wrapperFactory) => {
            assertPluginCapability(
              pluginSecurityState,
              'packetsnitch.functions.overwrite',
              `packetsnitch.functions.overwrite:${String(name || '')}`,
            );
            return hostFunctions.overwrite(name, wrapperFactory);
          },
        },
        backend: createPluginBackendApi(pluginSecurityState),
      },
      documentRef: capabilityIsGranted(pluginSecurityState.capabilities, 'ui.dom.write')
        ? document
        : createGuardedDomProxy(document, pluginSecurityState),
      windowRef: capabilityIsGranted(pluginSecurityState.capabilities, 'ui.dom.write')
        ? window
        : createGuardedDomProxy(window, pluginSecurityState),
      fetch: guardedFetch,
      statusUpdate: (message) => {
        assertPluginCapability(pluginSecurityState, 'ui.statusbar.modify', 'statusUpdate');
        hostFunctions.call('statusUpdate', message);
      },
      writeLogEntry: async (message) => {
        if (!capabilityIsGranted(pluginSecurityState.capabilities, 'plugin.log.write')) {
          await logPluginDeniedCapability(pluginSecurityState, 'plugin.log.write', 'writeLogEntry');
          return {
            success: false,
            denied: true,
            capability: 'plugin.log.write',
          };
        }
        await hostFunctions.call('writeLogEntry', String(message || ''));
        return { success: true };
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
      capabilities: Array.from(pluginSecurityState.capabilities),
      result: result === undefined ? null : result,
    };
  } catch (error) {
    const runtimeErrorMessage = error?.message || String(error || 'Unknown plugin runtime error');
    if (runtimeErrorMessage.includes('Plugin permission denied')) {
      await appendPluginActivityLog(
        pluginId || 'plugin-runtime',
        `Plugin runtime blocked by security: ${runtimeErrorMessage}`,
        'warn',
      );
    }
    return {
      success: false,
      pluginId,
      error: runtimeErrorMessage,
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
    const unloadErrorMessage = error?.message || String(error || 'Unknown plugin unload error');
    if (unloadErrorMessage.includes('Plugin permission denied')) {
      await appendPluginActivityLog(
        pluginId || 'plugin-runtime',
        `Plugin unload blocked by security: ${unloadErrorMessage}`,
        'warn',
      );
    }
    return {
      success: false,
      pluginId,
      error: unloadErrorMessage,
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
  lookupVirusTotal: (lookupValue, options = {}) =>
    ipcRenderer.invoke('lookup-backend-virustotal', lookupValue, options),
  checkNmapInstalled: () =>
    ipcRenderer.invoke('check-nmap-installed'),
  getNmapScanStatus: () =>
    ipcRenderer.invoke('get-nmap-scan-status'),
  runNmapServiceScan: (targets, options = {}) =>
    ipcRenderer.invoke('run-nmap-service-scan', targets, options),
  runBackendCommand: (filename, useLLM, chunkSize, workerThreads, backendOptions, jobId = "", wifiKeys = null) =>
    ipcRenderer.invoke('run-backend-command', filename, useLLM, chunkSize, workerThreads, backendOptions, jobId, wifiKeys),
  runBackendCommandFromSession: (sessionPcap, useLLM, chunkSize, workerThreads, backendOptions, jobId = "", wifiKeys = null) =>
    ipcRenderer.invoke('run-backend-command-from-session', sessionPcap, useLLM, chunkSize, workerThreads, backendOptions, jobId, wifiKeys),
  onPcapSource: (callback) => {
    ipcRenderer.on('backend-pcap-source', (_event, payload) => {
      callback(payload);
    });
  },
  shutdownBackend: () => ipcRenderer.invoke('control-backend-service', 'stop-processing'),
  setBackendWifiKeys: (wifiKeys = []) =>
    ipcRenderer.invoke('set-backend-wifi-keys', wifiKeys),
  sendBackendRuntimeConfig: (config = {}) =>
    ipcRenderer.invoke('control-backend-service', { action: 'set-runtime-config', ...config }),
  onBackendServiceState: (callback) => {
    ipcRenderer.on('backend-service-state', (_event, payload) => {
      callback(payload);
    });
  },
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
  savePayload: (payloadHex, options) =>
    ipcRenderer.invoke('save-payload', payloadHex, options),
  saveText: (options) => ipcRenderer.invoke('save-text', options),
  getAssetBase64: (relativePath) =>
    ipcRenderer.invoke('get-asset-base64', relativePath),
  saveCookieJar: (cookieJarText) =>
    ipcRenderer.invoke('save-cookie-jar', cookieJarText),
  saveHttpBody: (bodyHex, contentType) =>
    ipcRenderer.invoke('save-http-body', bodyHex, contentType),
  saveNotes: (notesText) => ipcRenderer.invoke('save-notes', notesText),
  savePdfReport: (options) => ipcRenderer.invoke('save-pdf-report', options),
});

contextBridge.exposeInMainWorld('extractapi', {
  decompress: ({ bytesBase64, algorithm }) =>
    ipcRenderer.invoke('decompress-bytes', { bytesBase64, algorithm }),
  listArchive: ({ bytesBase64 }) =>
    ipcRenderer.invoke('list-archive', { bytesBase64 }),
  extractArchiveEntry: ({ bytesBase64, entryPath, safePath }) =>
    ipcRenderer.invoke('extract-archive-entry', { bytesBase64, entryPath, safePath }),
  sha256Bytes: ({ bytesBase64 }) =>
    ipcRenderer.invoke('sha256-bytes', { bytesBase64 }),
  uploadVirusTotal: ({ bytesBase64, fileName, apiKey }) =>
    ipcRenderer.invoke('upload-virustotal', { bytesBase64, fileName, apiKey }),
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

contextBridge.exposeInMainWorld('cryptoapi', {
  __version: '2026-07-21-a',
  getRsaConstants: () => {
    const crypto = runtimeRequire('crypto');
    return {
      RSA_PKCS1_OAEP_PADDING: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      RSA_PKCS1_PADDING: crypto.constants.RSA_PKCS1_PADDING,
    };
  },
  getPrivateKeyModulusByteLength: (privateKeyPem) => {
    const crypto = runtimeRequire('crypto');
    try {
      // Try to derive the modulus length from the public components of the key
      // without decrypting/processing the private key material.
      const key = crypto.createPublicKey(privateKeyPem);
      const modulusLength = key.asymmetricKeyDetails?.modulusLength || key.asymmetricKeySize;
      return typeof modulusLength === 'number' ? modulusLength / 8 : 0;
    } catch (_) {
      // Fall back to private key parsing if the PEM is not a public key/cert.
      try {
        const key = crypto.createPrivateKey(privateKeyPem);
        const modulusLength = key.asymmetricKeyDetails?.modulusLength || key.asymmetricKeySize;
        return typeof modulusLength === 'number' ? modulusLength / 8 : 0;
      } catch (_) {
        return 0;
      }
    }
  },
  privateDecrypt: (keyPem, encryptedHex, options) => {
    const crypto = runtimeRequire('crypto');
    const encryptedBuffer = Buffer.from(encryptedHex, 'hex');
    const decrypted = crypto.privateDecrypt(
      { key: keyPem, ...options },
      encryptedBuffer,
    );
    return decrypted.toString('hex');
  },
  getPublicKeyFromPrivateKeyPem: (privateKeyPem) => {
    const crypto = runtimeRequire('crypto');
    return crypto
      .createPublicKey(privateKeyPem)
      .export({ type: 'spki', format: 'pem' });
  },
  getPublicKeyFromCertificatePem: (certificatePem) => {
    const crypto = runtimeRequire('crypto');
    const cert = new crypto.X509Certificate(certificatePem);
    return crypto
      .createPublicKey(cert.publicKey)
      .export({ type: 'spki', format: 'pem' });
  },
  // TLS 1.2 PRF (P_SHA256) and symmetric decryption helpers for NSS key log decryption.
  hmac: (hash, keyHex, dataHex) => {
    const crypto = runtimeRequire('crypto');
    const hmac = crypto.createHmac(hash, Buffer.from(keyHex, 'hex'));
    hmac.update(Buffer.from(dataHex, 'hex'));
    return hmac.digest('hex');
  },
  tlsPrf: (secretHex, label, seedHex, length, hash = 'sha256') => {
    const crypto = runtimeRequire('crypto');
    const secret = Buffer.from(secretHex, 'hex');
    const seed = Buffer.concat([
      Buffer.from(label, 'ascii'),
      Buffer.from(seedHex, 'hex'),
    ]);
    function pHash(prfHash, secret, seed, targetLength) {
      let result = Buffer.alloc(0);
      let a = seed;
      while (result.length < targetLength) {
        a = crypto.createHmac(prfHash, secret).update(a).digest();
        result = Buffer.concat([
          result,
          crypto.createHmac(prfHash, secret).update(a).update(seed).digest(),
        ]);
      }
      return result.subarray(0, targetLength);
    }
    return pHash(hash, secret, seed, length).toString('hex');
  },
  hkdfSha256: (ikmHex, saltHex, infoHex, length) => {
    const crypto = runtimeRequire('crypto');
    return crypto
      .hkdfSync(
        'sha256',
        Buffer.from(ikmHex, 'hex'),
        Buffer.from(saltHex, 'hex'),
        Buffer.from(infoHex, 'hex'),
        length,
      )
      .toString('hex');
  },
  hkdfSha384: (ikmHex, saltHex, infoHex, length) => {
    const crypto = runtimeRequire('crypto');
    return crypto
      .hkdfSync(
        'sha384',
        Buffer.from(ikmHex, 'hex'),
        Buffer.from(saltHex, 'hex'),
        Buffer.from(infoHex, 'hex'),
        length,
      )
      .toString('hex');
  },
  decryptAesCbc: (keyHex, ivHex, cipherHex) => {
    const crypto = runtimeRequire('crypto');
    const key = Buffer.from(keyHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const algorithm = key.length === 32 ? 'aes-256-cbc' : 'aes-128-cbc';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    const r1 = decipher.update(Buffer.from(cipherHex, 'hex'));
    const r2 = decipher.final();
    return Buffer.concat([r1, r2]).toString('hex');
  },
  decryptAesGcm: (keyHex, ivHex, aadHex, cipherHex, tagHex) => {
    const crypto = runtimeRequire('crypto');
    const key = Buffer.from(keyHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const algorithm = key.length === 32 ? 'aes-256-gcm' : 'aes-128-gcm';
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAAD(Buffer.from(aadHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    const r1 = decipher.update(Buffer.from(cipherHex, 'hex'));
    const r2 = decipher.final();
    return Buffer.concat([r1, r2]).toString('hex');
  },
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
  onRefreshed: (callback) => {
    ipcRenderer.on('sessions-list-refreshed', (_event, result) => {
      callback(result);
    });
  },
  refresh: () => ipcRenderer.invoke('sessions-list-refresh'),
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
  invalidateOllamaModelsCache: () => ipcRenderer.invoke('invalidate-ollama-models-cache'),
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
  listCatalog: (payload) => ipcRenderer.invoke('themes-catalog', payload),
  fetchPreview: (payload) => ipcRenderer.invoke('themes-fetch-preview', payload),
  startCheckout: (payload) => ipcRenderer.invoke('themes-start-checkout', payload),
  refreshLicenses: (payload) => ipcRenderer.invoke('themes-refresh-licenses', payload),
  download: (payload) => ipcRenderer.invoke('themes-download', payload),
  openExternalUrl: (url) => ipcRenderer.invoke('open-external-url', url),
  // Listen for ``packetsnitch://checkout-success?...`` deeplinks that
  // the main process received from the OS protocol handler. Returns
  // an unsubscribe function. ``callback`` receives the parsed deeplink
  // payload (transactionId, installUuid, themeId, unlockedThemeIds,
  // error, at).
  onCheckoutSuccessDeeplink: (callback) => {
    const listener = (_event, payload) => {
      try {
        callback(payload);
      } catch (_error) {
        // never throw across the bridge
      }
    };
    ipcRenderer.on('deeplink:checkout-success', listener);
    return () => ipcRenderer.removeListener('deeplink:checkout-success', listener);
  },
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
  updateRuntimeData: (payload) => updatePluginRuntimeDataState(payload),
  getCapabilityCatalog: () => PLUGIN_CAPABILITY_CATALOG,
});


contextBridge.exposeInMainWorld("llmapi", {
  generate: (prompt, options = {}) => ipcRenderer.invoke("ollama:generate", prompt, options),
});

contextBridge.exposeInMainWorld("metricsapi", {
  track: (payload) => ipcRenderer.invoke("metrics:track", payload),
  flush: (payload) => ipcRenderer.invoke("metrics:flush", payload),
  getStatus: () => ipcRenderer.invoke("metrics:status"),
  onFlushRequest: (handler) => {
    if (typeof handler !== "function") return () => { };
    const listener = (_event, payload) => {
      try {
        handler(payload);
      } catch (_error) {
        // ignore listener errors
      }
    };
    ipcRenderer.on("metrics:flush-request", listener);
    return () => ipcRenderer.removeListener("metrics:flush-request", listener);
  },
});
