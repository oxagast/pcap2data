const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

jest.mock('electron', () => {
    const bridge = {
        exposeInMainWorld: (name, api) => {
            global[name] = api;
        },
    };

    const ipc = {
        invoke: jest.fn(async (channel) => {
            if (channel === 'append-activity-log') {
                return { success: true };
            }
            if (channel === 'get-backend-diagnostics') {
                return { success: true, diagnostics: true };
            }
            return { success: true };
        }),
        on: jest.fn(),
    };

    return {
        contextBridge: bridge,
        ipcRenderer: ipc,
    };
});

function createFakeElement(id = '') {
    return {
        id,
        type: '',
        value: '',
        textContent: '',
        className: '',
        hidden: false,
        style: {},
        attributes: {},
        children: [],
        parentNode: null,
        appendChild(child) {
            child.parentNode = this;
            this.children.push(child);
            return child;
        },
        removeChild(child) {
            const index = this.children.indexOf(child);
            if (index >= 0) {
                this.children.splice(index, 1);
            }
            child.parentNode = null;
            return child;
        },
        setAttribute(name, value) {
            this.attributes[name] = value;
        },
    };
}

function createFakeDom() {
    const elements = new Map();
    const tabRow = createFakeElement('tab-btns');
    const contextMenu = createFakeElement('convert-context-menu');
    const existingTab = createFakeElement('existing-tab');
    const existingMenu = createFakeElement('existing-menu-item');
    const probe = createFakeElement('probe');

    existingTab.value = 'before';
    existingMenu.textContent = 'before';

    elements.set('tab-btns', tabRow);
    elements.set('convert-context-menu', contextMenu);
    elements.set('existing-tab', existingTab);
    elements.set('existing-menu-item', existingMenu);
    elements.set('probe', probe);

    tabRow.appendChild(existingTab);
    contextMenu.appendChild(existingMenu);

    return {
        getElementById(id) {
            return elements.get(String(id || '')) || null;
        },
        createElement() {
            return createFakeElement('');
        },
        querySelector(selector) {
            if (selector === '#probe') {
                return probe;
            }
            return null;
        },
    };
}

function buildPluginScript(code) {
    return `module.exports = {\n  init: async (context) => {\n    ${code}\n    return { ok: true };\n  }\n};\n`;
}

const TEMP_READ_FILE = path.join(os.tmpdir(), 'packetsnitch-cap-read.tmp');
const TEMP_WRITE_FILE = path.join(os.tmpdir(), 'packetsnitch-cap-write.tmp');
const TEMP_CHMOD_FILE = path.join(os.tmpdir(), 'packetsnitch-cap-chmod.tmp');

async function loadPluginWithCode({ pluginId, capabilities, code }) {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'packetsnitch-cap-'));
    const entryPath = path.join(tempDir, 'entry.js');
    fs.writeFileSync(entryPath, buildPluginScript(code), 'utf8');

    const payload = {
        plugin: {
            pluginId,
            pluginName: pluginId,
            installPath: tempDir,
            capabilities,
            manifest: {
                entry: 'entry.js',
            },
        },
        packetsnitchVersion: '2.0.0',
        forceReload: true,
    };

    const result = await global.pluginapi.loadRuntime(payload);
    if (result?.success) {
        await global.pluginapi.unloadRuntime({ pluginId, plugin: payload.plugin });
    }

    fs.rmSync(tempDir, { recursive: true, force: true });
    return result;
}

describe('plugin capability enforcement', () => {
    beforeAll(() => {
        global.__non_webpack_require__ = require;
        global.window = {
            alert: jest.fn(),
            confirm: jest.fn(() => true),
            prompt: jest.fn(() => 'ok'),
            postMessage: jest.fn(),
        };
        global.fetch = jest.fn(async () => ({
            ok: true,
            status: 200,
            json: async () => ({ ok: true }),
        }));

        jest.isolateModules(() => {
            require('../src/preload');
        });

        fs.writeFileSync(TEMP_READ_FILE, 'read-ok', 'utf8');
        fs.writeFileSync(TEMP_CHMOD_FILE, 'chmod-ok', 'utf8');
    });

    beforeEach(() => {
        global.document = createFakeDom();
        if (global.pluginapi && typeof global.pluginapi.updateRuntimeData === 'function') {
            global.pluginapi.updateRuntimeData({
                currentPacketKey: '10.0.0.1:7',
                currentPacketMetadata: {
                    packetKey: '10.0.0.1:7',
                    packetInfo: {
                        index: 7,
                        IP: {
                            'ip.src.addr': '10.0.0.1',
                            'ip.dst.addr': '10.0.0.2',
                        },
                    },
                    activePacketCursor: 3,
                },
                currentStreamTuple: {
                    srcIp: '10.0.0.1',
                    srcPort: 443,
                    dstIp: '10.0.0.2',
                    dstPort: 51515,
                    protocol: 'TCP',
                },
                sessionPcapSource: {
                    fileName: 'fixture.pcap',
                    encoding: 'base64',
                    data: 'AAECAwQ=',
                    byteLength: 5,
                },
                statsJson: {
                    totalPackets: 5,
                    totalStreams: 2,
                    bookmarkCount: 1,
                },
                keystoreEntries: [
                    {
                        id: 'fixture-entry',
                        label: 'fixture',
                        type: 'token',
                        content: 'abc123',
                    },
                ],
            });
        }
    });

    const capabilityCases = [
        {
            capability: 'version.read',
            code: `const version = context.api.version.read(); if (!version) { throw new Error('version missing'); }`,
        },
        {
            capability: 'ui.dialog.add',
            code: `context.api.ui.dialog.alert('hi');`,
        },
        {
            capability: 'ui.dom.write',
            code: `context.api.ui.dom.setText('#probe', 'updated');`,
        },
        {
            capability: 'ui.tabs.create',
            code: `context.api.ui.tabs.create({ id: 'tab-created', label: 'Created' });`,
        },
        {
            capability: 'ui.tabs.modify',
            code: `context.api.ui.tabs.modify({ id: 'existing-tab', label: 'Updated' });`,
        },
        {
            capability: 'ui.contextmenu.create',
            code: `context.api.ui.contextMenu.create({ id: 'ctx-created', text: 'Created' });`,
        },
        {
            capability: 'ui.contextmenu.modify',
            code: `context.api.ui.contextMenu.modify({ id: 'existing-menu-item', text: 'Updated' });`,
        },
        {
            capability: 'ui.statusbar.modify',
            code: `context.api.ui.statusBar.setText('status update');`,
        },
        {
            capability: 'fs.read',
            code: `await context.api.fs.readText(${JSON.stringify(TEMP_READ_FILE)}, 'utf8');`,
        },
        {
            capability: 'fs.write',
            code: `await context.api.fs.writeText(${JSON.stringify(TEMP_WRITE_FILE)}, 'ok', 'utf8');`,
        },
        {
            capability: 'fs.execute',
            code: `await context.api.fs.execute(${JSON.stringify(`${process.execPath} -e "process.exit(0)"`)});`,
        },
        {
            capability: 'fs.chmod',
            code: `await context.api.fs.chmod(${JSON.stringify(TEMP_CHMOD_FILE)}, 0o600);`,
        },
        {
            capability: 'network.fetch.http',
            code: `await context.api.network.fetch('https://example.com');`,
        },
        {
            capability: 'network.socket.listen',
            code: `await context.api.network.socketListen({ host: '127.0.0.1', port: 0 });`,
        },
        {
            capability: 'network.socket.connect',
            code: `
        const server = net.createServer(() => {});
        const port = await new Promise((resolve, reject) => {
          server.once('error', reject);
          server.listen(0, '127.0.0.1', () => resolve(server.address().port));
        });
        try {
          await context.api.network.socketConnect({ host: '127.0.0.1', port });
        } finally {
          await new Promise((resolve) => server.close(resolve));
        }
      `,
            injectNet: true,
        },
        {
            capability: 'packetsnitch.functions.use',
            code: `context.api.packetsnitch.useFunction('statusUpdate', 'hello');`,
        },
        {
            capability: 'packetsnitch.functions.overwrite',
            code: `
        const restore = context.api.packetsnitch.overwriteFunction('statusUpdate', (original) => {
          return (message) => original('[wrapped] ' + message);
        });
        restore();
      `,
        },
        {
            capability: 'backend.talk',
            code: `await context.api.backend.invoke('get-backend-diagnostics');`,
        },
        {
            capability: 'packet.metadata.read',
            code: `
                const metadata = context.api.capture.getCurrentPacketMetadata();
                if (!metadata || !metadata.packetInfo) {
                    throw new Error('packet metadata missing');
                }
            `,
        },
        {
            capability: 'session.pcap.read',
            code: `
                const source = await context.api.capture.getSessionPcapSource();
                if (!source || !source.data) {
                    throw new Error('session pcap source missing');
                }
            `,
        },
        {
            capability: 'stats.json.read',
            code: `
                const stats = context.api.stats.getJson();
                if (!stats || typeof stats.totalPackets !== 'number') {
                    throw new Error('stats json missing');
                }
            `,
        },
        {
            capability: 'keystore.read',
            code: `
                const entries = context.api.keystore.getSessionEntries();
                if (!Array.isArray(entries) || entries.length < 1) {
                    throw new Error('keystore entries missing');
                }
            `,
        },
        {
            capability: 'keystore.write',
            allowedCapabilities: ['keystore.write', 'keystore.read'],
            code: `
                const outcome = context.api.keystore.addSessionEntry({
                    type: 'secret',
                    label: 'plugin-token',
                    source: 'plugin-test',
                    content: 'token-xyz',
                    summary: 'added from test',
                    packetIndex: 7,
                });
                if (!outcome || outcome.success !== true) {
                    throw new Error('keystore write failed');
                }
                const entries = context.api.keystore.getSessionEntries();
                if (!Array.isArray(entries) || entries.length < 1) {
                    throw new Error('keystore entries missing after write');
                }
            `,
        },
        {
            capability: 'filter.query',
            code: `
                const result = await context.api.filter.query('ip.src.addr: 10.0.0.1', { mode: 'background' });
                if (!result || result.success !== true) {
                    throw new Error('filter query failed');
                }
            `,
        },
        {
            capability: 'plugin.log.write',
            code: `
        const outcome = await context.writeLogEntry('hello');
        if (!outcome || outcome.success !== true) {
          throw new Error('Plugin permission denied: plugin.log.write');
        }
      `,
        },
    ];

    for (const testCase of capabilityCases) {
        const allowedCapabilities = testCase.allowedCapabilities || [testCase.capability];

        test(`${testCase.capability} is denied when missing`, async () => {
            const code = testCase.injectNet ? `const net = require('net'); ${testCase.code}` : testCase.code;
            const result = await loadPluginWithCode({
                pluginId: `deny-${testCase.capability.replace(/\./g, '-')}`,
                capabilities: [],
                code,
            });

            expect(result.success).toBe(false);
            expect(String(result.error || '')).toContain('Plugin permission denied');
        });

        test(`${testCase.capability} is allowed when declared`, async () => {
            const code = testCase.injectNet ? `const net = require('net'); ${testCase.code}` : testCase.code;
            const result = await loadPluginWithCode({
                pluginId: `allow-${testCase.capability.replace(/\./g, '-')}`,
                capabilities: allowedCapabilities,
                code,
            });

            expect(result.success).toBe(true);
        });
    }
});
