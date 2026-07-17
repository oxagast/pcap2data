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

describe('bookmark packet key helpers', () => {
    const sourcePath = path.join(__dirname, '..', 'src/ui/main-frontend.js');
    const sourceText = fs.readFileSync(sourcePath, 'utf8');
    const helperSource = [
        'const PACKET_KEY_SEPARATOR = "$";',
        extractFunctionSource(sourceText, 'getPacketKey'),
        extractFunctionSource(sourceText, 'parsePacketKey'),
        extractFunctionSource(sourceText, 'normalizePacketKey'),
        extractFunctionSource(sourceText, 'formatNetworkEndpointDisplay'),
        extractFunctionSource(sourceText, 'buildPacketContextSummary'),
    ].join('\n\n');

    const context = { Number };
    vm.createContext(context);
    vm.runInContext(helperSource, context);

    test('getPacketKey emits $ separator for IPv4 and IPv6', () => {
        const ipv4Key = context.getPacketKey({
            'packet.info': {
                IP: { 'ip.src.addr': '10.0.0.1' },
                index: 7,
            },
        });
        const ipv6Key = context.getPacketKey({
            'packet.info': {
                IP: { 'ip.src.addr': '2001:db8::10' },
                index: 11,
            },
        });

        expect(ipv4Key).toBe('10.0.0.1$7');
        expect(ipv6Key).toBe('2001:db8::10$11');
    });

    test('parsePacketKey supports new $ bookmark keys', () => {
        expect(context.parsePacketKey('2001:db8::10$11')).toEqual({
            host: '2001:db8::10',
            packetIndex: 11,
        });
    });

    test('parsePacketKey supports legacy : bookmark keys by splitting on the last colon', () => {
        expect(context.parsePacketKey('2001:db8::10:11')).toEqual({
            host: '2001:db8::10',
            packetIndex: 11,
        });
    });

    test('normalizePacketKey migrates legacy IPv4 and IPv6 bookmark keys', () => {
        expect(context.normalizePacketKey('10.0.0.1:7')).toBe('10.0.0.1$7');
        expect(context.normalizePacketKey('2001:db8::10:11')).toBe('2001:db8::10$11');
        expect(context.normalizePacketKey('2001:db8::10$11')).toBe('2001:db8::10$11');
    });

    test('formatNetworkEndpointDisplay brackets IPv6 endpoints with ports', () => {
        expect(context.formatNetworkEndpointDisplay('10.0.0.1', 443)).toBe('10.0.0.1:443');
        expect(context.formatNetworkEndpointDisplay('2001:db8::10', 443)).toBe('[2001:db8::10]:443');
        expect(context.formatNetworkEndpointDisplay('[2001:db8::10]', 443)).toBe('[2001:db8::10]:443');
        expect(context.formatNetworkEndpointDisplay('2001:db8::10', '')).toBe('2001:db8::10');
    });

    test('buildPacketContextSummary brackets IPv6 endpoints in summary text', () => {
        const summary = context.buildPacketContextSummary({
            'packet.info': {
                Protocol: 'TCP',
                'Source IP': '2001:db8::10',
                'Destination IP': '2001:db8::20',
                'Source Port': 443,
                'Destination Port': 51515,
            },
        });

        expect(summary).toContain('Source: [2001:db8::10]:443');
        expect(summary).toContain('Destination: [2001:db8::20]:51515');
        expect(summary).not.toContain('Source Port:');
        expect(summary).not.toContain('Destination Port:');
    });

    test('capture store derives $ packet keys for list-window rows', () => {
        const captureStoreSourcePath = path.join(__dirname, '..', 'src', 'capture-store.js');
        const captureStoreSourceText = fs.readFileSync(captureStoreSourcePath, 'utf8');
        const captureStoreHelperSource = [
            'const PACKET_KEY_SEPARATOR = "$";',
            extractFunctionSource(captureStoreSourceText, 'normalizeIpCandidate'),
            extractFunctionSource(captureStoreSourceText, 'extractPacketIpAddress'),
            extractFunctionSource(captureStoreSourceText, 'derivePacketKey'),
        ].join('\n\n');

        const captureStoreContext = {
            String,
            Set,
        };
        vm.createContext(captureStoreContext);
        vm.runInContext(captureStoreHelperSource, captureStoreContext);

        const ipv4Key = captureStoreContext.derivePacketKey(
            {
                'packet.info': {
                    IP: { 'ip.src.addr': '10.0.0.1' },
                    index: 3,
                },
            },
            '10.0.0.1',
            3,
            new Set(),
        );
        const ipv6Key = captureStoreContext.derivePacketKey(
            {
                'packet.info': {
                    IP: { 'ip.src.addr': '2001:db8::10' },
                    index: 4,
                },
            },
            '2001:db8::10',
            4,
            new Set(),
        );

        expect(ipv4Key).toBe('10.0.0.1$3');
        expect(ipv6Key).toBe('2001:db8::10$4');
    });

    test('list panel normalizes legacy source-backed packet keys for bookmarks', () => {
        const listPanelSourcePath = path.join(__dirname, '..', 'src', 'ui', 'panels', 'list-panel.js');
        const listPanelSourceText = fs.readFileSync(listPanelSourcePath, 'utf8');
        const listPanelHelperSource = [
            'const PACKET_KEY_SEPARATOR = "$";',
            extractFunctionSource(listPanelSourceText, 'buildPacketKey'),
            extractFunctionSource(listPanelSourceText, 'normalizePacketKey'),
        ].join('\n\n');

        const listPanelContext = {};
        vm.createContext(listPanelContext);
        vm.runInContext(listPanelHelperSource, listPanelContext);

        expect(listPanelContext.normalizePacketKey('10.0.0.1:3')).toBe('10.0.0.1$3');
        expect(listPanelContext.normalizePacketKey('2001:db8::10:4')).toBe('2001:db8::10$4');
        expect(listPanelContext.normalizePacketKey('2001:db8::10$4')).toBe('2001:db8::10$4');
    });

    test('context-menu filter queries detect direct IPv6 selections', () => {
        const contextHelperSource = [
            'const CONTEXT_IPV4_REGEX = /\\b(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}\\b/;',
            'const STRICT_IPV4_REGEX = /^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$/;',
            'const CONTEXT_MAC_REGEX = /\\b([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}\\b/;',
            'const CONTEXT_MIME_REGEX = /^[a-z0-9][a-z0-9!#$&^_.+-]*\\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i;',
            extractFunctionSource(sourceText, 'isLikelyIpAddress'),
            extractFunctionSource(sourceText, 'extractIpv6EndpointParts'),
            extractFunctionSource(sourceText, 'normalizeContextToken'),
            extractFunctionSource(sourceText, 'extractContextIp'),
            extractFunctionSource(sourceText, 'extractContextPort'),
            extractFunctionSource(sourceText, 'extractContextMac'),
            extractFunctionSource(sourceText, 'extractContextMimeType'),
            extractFunctionSource(sourceText, 'sanitizeFilterTerm'),
            extractFunctionSource(sourceText, 'buildContextFilterQueries'),
        ].join('\n\n');

        const contextMenuContext = {
            p: [],
            index: 0,
        };
        vm.createContext(contextMenuContext);
        vm.runInContext(contextHelperSource, contextMenuContext);

        expect(contextMenuContext.buildContextFilterQueries(null, '2001:db8::10', '')).toEqual({
            ip: 'ip.src.addr: 2001:db8::10 || ip.dst.addr: 2001:db8::10',
        });

        expect(contextMenuContext.buildContextFilterQueries(null, '2001:db8::10:443', '')).toEqual({
            ip: 'ip.src.addr: 2001:db8::10 || ip.dst.addr: 2001:db8::10',
            port: 'tcp.src.port: 443 || tcp.dst.port: 443 || udp.src.port: 443 || udp.dst.port: 443',
        });
    });

    test('context-menu filter queries detect IPv6 IP:Port row values', () => {
        const contextHelperSource = [
            'const CONTEXT_IPV4_REGEX = /\\b(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}\\b/;',
            'const STRICT_IPV4_REGEX = /^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$/;',
            'const CONTEXT_MAC_REGEX = /\\b([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}\\b/;',
            'const CONTEXT_MIME_REGEX = /^[a-z0-9][a-z0-9!#$&^_.+-]*\\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i;',
            extractFunctionSource(sourceText, 'isLikelyIpAddress'),
            extractFunctionSource(sourceText, 'extractIpv6EndpointParts'),
            extractFunctionSource(sourceText, 'normalizeContextToken'),
            extractFunctionSource(sourceText, 'extractContextIp'),
            extractFunctionSource(sourceText, 'extractContextPort'),
            extractFunctionSource(sourceText, 'extractContextMac'),
            extractFunctionSource(sourceText, 'extractContextMimeType'),
            extractFunctionSource(sourceText, 'sanitizeFilterTerm'),
            extractFunctionSource(sourceText, 'buildContextFilterQueries'),
        ].join('\n\n');

        const contextMenuContext = {
            p: [],
            index: 0,
        };
        vm.createContext(contextMenuContext);
        vm.runInContext(contextHelperSource, contextMenuContext);

        const row = {
            querySelectorAll: () => ([
                { textContent: 'IP : Port' },
                { textContent: '2001:db8::10:443' },
            ]),
        };
        const target = {
            closest: (selector) => (selector === 'tr' ? row : null),
        };

        expect(contextMenuContext.buildContextFilterQueries(target, '', '')).toEqual({
            ip: 'ip.src.addr: 2001:db8::10 || ip.dst.addr: 2001:db8::10',
            port: 'tcp.src.port: 443 || tcp.dst.port: 443 || udp.src.port: 443 || udp.dst.port: 443',
        });
    });

    test('main-process nmap target normalization strips trailing port from compressed IPv6 endpoints', () => {
        const mainSourcePath = path.join(__dirname, '..', 'src', 'main.js');
        const mainSourceText = fs.readFileSync(mainSourcePath, 'utf8');
        const mainHelperSource = [
            extractFunctionSource(mainSourceText, 'isLikelyIpAddress'),
            extractFunctionSource(mainSourceText, 'extractIpv6EndpointParts'),
            extractFunctionSource(mainSourceText, 'normalizeNmapTargets'),
        ].join('\n\n');

        const mainContext = {
            Array,
            Map,
            Number,
            Set,
            String,
        };
        vm.createContext(mainContext);
        vm.runInContext(mainHelperSource, mainContext);

        expect(mainContext.normalizeNmapTargets([
            { ip: '2001:db8::10:443', ports: [443] },
            { ip: '[2001:db8::20]:8443', ports: [8443] },
        ])).toEqual([
            { ip: '2001:db8::10', ports: [443] },
            { ip: '2001:db8::20', ports: [8443] },
        ]);
    });
});