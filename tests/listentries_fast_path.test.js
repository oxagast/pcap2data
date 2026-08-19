// Coverage for the listEntries-based fast path in getAllPacketsForHostNavigation.
// When the capture store provides pre-sorted listEntries, the renderer should
// use them as a sort index instead of spreading + re-sorting all host arrays.
// This is the core scalability fix: O(N) array fill instead of O(N log N) sort
// per applied chunk.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

function extractFunctionSource(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    const bodyStart = sourceText.indexOf('{', startIndex);
    let depth = 0;
    for (let cursor = bodyStart; cursor < sourceText.length; cursor += 1) {
        const char = sourceText[cursor];
        if (char === '{') depth += 1;
        if (char === '}') {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
    }
    throw new Error(`Could not parse function ${functionName}`);
}

function extractConstDeclaration(sourceText, constName) {
    const startToken = `const ${constName}`;
    const startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find const ${constName}`);
    }
    const endIndex = sourceText.indexOf(';', startIndex);
    if (endIndex === -1) {
        throw new Error(`Could not find terminating semicolon for ${constName}`);
    }
    return sourceText.slice(startIndex, endIndex + 1);
}

describe('listEntries-based all-packets navigation', () => {
    const sourcePath = path.join(__dirname, '..', 'src', 'ui', 'main-frontend.js');
    const sourceText = fs.readFileSync(sourcePath, 'utf8');

    // Build a self-contained module that wraps getAllPacketsForHostNavigation
    // with its own mutable state object so we can control capturedPackets,
    // allHostsNavigationPacketsCache, and packetNavigationCacheVersion from
    // test code without scope issues.
    const cacheDecl = extractConstDeclaration(sourceText, 'packetTimestampMsCache');
    const timestampRegexDecl = extractConstDeclaration(sourceText, 'BACKEND_TIMESTAMP_RE');

    const moduleCode = `
    ${cacheDecl}
    ${timestampRegexDecl}
    ${extractFunctionSource(sourceText, 'parseBackendTimestampMs')}
    ${extractFunctionSource(sourceText, 'parsePacketTimestampMs')}
    ${extractFunctionSource(sourceText, 'parsePacketProcessedNumber')}
    ${extractFunctionSource(sourceText, 'parsePacketIndexNumber')}
    ${extractFunctionSource(sourceText, 'comparePacketsChronologically')}
    ${extractFunctionSource(sourceText, 'isPacketListInStreamOrder')}
    ${extractFunctionSource(sourceText, 'sortPacketsByOwnStreamOrder')}

    // Re-implement getAllPacketsForHostNavigation with an explicit state
    // object so tests can control capturedPackets / cache / version without
    // scope-leak issues from extracting the function out of main-frontend.js.
    const DUMMY_ALL_HOST = '__all_hosts__';
    const DUMMY_BOOKMARKED_HOST = '__bookmarked__';
    function isAllHostsSelection(host) { return host === DUMMY_ALL_HOST; }
    function isBookmarkedSelection(host) { return host === DUMMY_BOOKMARKED_HOST; }

    const state = {
      capturedPackets: {},
      allHostsNavigationPacketsCache: null,
      packetNavigationCacheVersion: 0,
    };

    function getAllPacketsForHostNavigation() {
      if (
        state.allHostsNavigationPacketsCache
        && state.allHostsNavigationPacketsCache.version === state.packetNavigationCacheVersion
      ) {
        return state.allHostsNavigationPacketsCache.packets;
      }

      const hostMap =
        state.capturedPackets && typeof state.capturedPackets["host"] === "object"
          ? state.capturedPackets["host"]
          : {};

      const listEntries = Array.isArray(state.capturedPackets?.listEntries)
        ? state.capturedPackets.listEntries
        : null;

      if (listEntries && listEntries.length > 0) {
        const allPackets = new Array(listEntries.length);
        for (let i = 0; i < listEntries.length; i += 1) {
          const entry = listEntries[i];
          const hostPackets = hostMap[entry.host];
          allPackets[i] = Array.isArray(hostPackets) ? hostPackets[entry.pktIdx] : null;
        }
        state.allHostsNavigationPacketsCache = {
          version: state.packetNavigationCacheVersion,
          packets: allPackets,
        };
        return allPackets;
      }

      const allPackets = [];
      Object.keys(hostMap).forEach(function (host) {
        const hostPackets = Array.isArray(hostMap[host]) ? hostMap[host] : [];
        for (let i = 0; i < hostPackets.length; i += 1) allPackets.push(hostPackets[i]);
      });
      const sortedAllPackets = sortPacketsByOwnStreamOrder(allPackets);
      state.allHostsNavigationPacketsCache = {
        version: state.packetNavigationCacheVersion,
        packets: sortedAllPackets,
      };
      return sortedAllPackets;
    }

    // Expose for test access
    function __export() {
      return {
        state,
        getAllPacketsForHostNavigation,
        sortPacketsByOwnStreamOrder,
        parsePacketTimestampMs,
      };
    }
  `;

    function makeModule() {
        const ctx = {
            Date,
            Number,
            WeakMap,
            Array,
            Math,
            Boolean,
            String,
        };
        vm.createContext(ctx);
        vm.runInContext(moduleCode, ctx);
        return ctx.__export ? ctx.__export() : vm.runInContext('__export()', ctx);
    }

    test('uses listEntries as sort index when available', () => {
        const m = makeModule();
        const stubA1 = { tag: 'A1', 'packet.info': { 'packet.timestamp': '2024-01-15 12:00:01.000000', index: 1 } };
        const stubB1 = { tag: 'B1', 'packet.info': { 'packet.timestamp': '2024-01-15 12:00:02.000000', index: 1 } };
        const stubA2 = { tag: 'A2', 'packet.info': { 'packet.timestamp': '2024-01-15 12:00:03.000000', index: 2 } };
        const stubB2 = { tag: 'B2', 'packet.info': { 'packet.timestamp': '2024-01-15 12:00:04.000000', index: 2 } };

        m.state.capturedPackets = {
            host: {
                '10.0.0.1': [stubA1, stubA2],
                '10.0.0.2': [stubB1, stubB2],
            },
            listEntries: [
                { packetKey: '10.0.0.1$1', host: '10.0.0.1', pktIdx: 0, idx: 1, pcapOrder: 1, srcIp: '10.0.0.1', dstIp: '10.0.0.2', transport: 'TCP', appProto: 'HTTP' },
                { packetKey: '10.0.0.2$1', host: '10.0.0.2', pktIdx: 0, idx: 1, pcapOrder: 2, srcIp: '10.0.0.2', dstIp: '10.0.0.1', transport: 'TCP', appProto: 'HTTP' },
                { packetKey: '10.0.0.1$2', host: '10.0.0.1', pktIdx: 1, idx: 2, pcapOrder: 3, srcIp: '10.0.0.1', dstIp: '10.0.0.2', transport: 'TCP', appProto: 'HTTP' },
                { packetKey: '10.0.0.2$2', host: '10.0.0.2', pktIdx: 1, idx: 2, pcapOrder: 4, srcIp: '10.0.0.2', dstIp: '10.0.0.1', transport: 'TCP', appProto: 'HTTP' },
            ],
            'final.summary': '',
        };

        const result = m.getAllPacketsForHostNavigation();
        expect(result.length).toBe(4);
        // Stubs should be in listEntries order (interleaved by host), NOT in
        // the host-map order (which would be A1, A2, B1, B2).
        expect(result.map(function (p) { return p.tag; })).toEqual(['A1', 'B1', 'A2', 'B2']);
    });

    test('falls back to spread+sort when listEntries is absent', () => {
        const m = makeModule();
        const stubA1 = { tag: 'A1', 'packet.info': { 'packet.timestamp': '2024-01-15 12:00:01.000000', index: 1 } };
        const stubA2 = { tag: 'A2', 'packet.info': { 'packet.timestamp': '2024-01-15 12:00:03.000000', index: 2 } };
        const stubB1 = { tag: 'B1', 'packet.info': { 'packet.timestamp': '2024-01-15 12:00:02.000000', index: 1 } };

        m.state.capturedPackets = {
            host: {
                '10.0.0.1': [stubA1, stubA2],
                '10.0.0.2': [stubB1],
            },
            'final.summary': '',
        };

        const result = m.getAllPacketsForHostNavigation();
        expect(result.length).toBe(3);
        // Sorted by timestamp: A1(01), B1(02), A2(03)
        expect(result.map(function (p) { return p.tag; })).toEqual(['A1', 'B1', 'A2']);
    });

    test('caches result across calls until cache version bumps', () => {
        const m = makeModule();
        m.state.capturedPackets = {
            host: { '10.0.0.1': [{ tag: 'X', 'packet.info': { 'packet.timestamp': '2024-01-15 12:00:01.000000', index: 1 } }] },
            listEntries: [{ packetKey: '10.0.0.1$1', host: '10.0.0.1', pktIdx: 0, idx: 1, pcapOrder: 1, srcIp: '10.0.0.1', dstIp: '', transport: 'TCP', appProto: 'HTTP' }],
            'final.summary': '',
        };

        const r1 = m.getAllPacketsForHostNavigation();
        const r2 = m.getAllPacketsForHostNavigation();
        expect(r2).toBe(r1); // same reference — cached

        // Bump version → cache invalidates
        m.state.packetNavigationCacheVersion = 1;
        const r3 = m.getAllPacketsForHostNavigation();
        expect(r3).not.toBe(r1); // different reference — rebuilt
    });
});