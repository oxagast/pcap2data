// Regression tests for the List-panel "App Protocol" inference.
//
// These tests reproduce a bug where TCP/UDP/ICMP packets that were
// recovered from a decrypted IEEE 802.11 (Wi-Fi) frame had "WIFI" in
// ``packet.decoded_protocols``.  Because ``collectDecodedProtocolNames``
// added every decoded name (including "WIFI") to its candidate set, the
// List panel ended up rendering "WIFI" as the application-layer label
// for every decrypted TCP/UDP frame — masking the real protocol that
// was actually decoded inside the stripped 802.11 payload.
//
// The fix has two parts:
//
//   1. The backend must NOT prepend "WIFI" to ``decoded_protocols``
//      when splicing wireless metadata into a decrypted inner packet
//      (link-layer info is already carried by ``link.proto``).
//   2. The renderer must defensively ignore link-layer protocol names
//      when picking an application-layer label from
//      ``decoded_protocols``.
//
// These tests pin both behaviours down: a decrypted TCP frame whose
// ``decoded_protocols`` still contains "WIFI" (the worst-case legacy
// shape) must not be displayed as "WIFI", and a fresh decrypted TCP
// frame from the current backend must report its real app layer
// (HTTP, SSH, ...) when the decoder surfaces one.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const LIST_PANEL_SOURCE_PATH = path.join(
    PROJECT_ROOT,
    'src',
    'ui',
    'panels',
    'list-panel.js',
);

function extractFunctionSource(sourceText, functionName) {
    const startToken = `function ${functionName}`;
    let startIndex = sourceText.indexOf(startToken);
    if (startIndex === -1) {
        throw new Error(`Could not find function ${functionName}`);
    }
    const lastIndex = sourceText.lastIndexOf(startToken);
    if (lastIndex !== -1 && lastIndex !== startIndex) {
        startIndex = lastIndex;
    }
    const bodyStart = sourceText.indexOf('{', startIndex);
    if (bodyStart === -1) {
        throw new Error(`Could not find body for ${functionName}`);
    }

    let depth = 0;
    let cursor = bodyStart;
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inTemplate = false;
    let inLineComment = false;
    let inBlockComment = false;
    let inRegex = false;
    let inRegexCharClass = false;
    let escaped = false;

    function isRegexStart(idx) {
        let j = idx - 1;
        while (j >= 0 && /\s/.test(sourceText[j])) j -= 1;
        if (j < 0) return true;
        const prev = sourceText[j];
        if (/[=(,:\[{};?!|&]|^$/.test(prev)) return true;
        const back = sourceText.slice(Math.max(0, j - 30), j + 1);
        const match = back.match(
            /\b(return|break|continue|with|if|else|case|while|do|for|switch|throw|catch|await|yield|new|typeof|instanceof|delete|void)$/,
        );
        if (match) return true;
        return false;
    }

    while (cursor < sourceText.length) {
        const char = sourceText[cursor];
        const next = sourceText[cursor + 1];

        if (inLineComment) {
            if (char === '\n') inLineComment = false;
            cursor += 1;
            continue;
        }
        if (inBlockComment) {
            if (char === '*' && next === '/') {
                inBlockComment = false;
                cursor += 2;
                continue;
            }
            cursor += 1;
            continue;
        }
        if (inRegex) {
            if (escaped) {
                escaped = false;
                cursor += 1;
                continue;
            }
            if (char === '\\') {
                escaped = true;
                cursor += 1;
                continue;
            }
            if (char === '[' && !inRegexCharClass) inRegexCharClass = true;
            if (char === ']' && inRegexCharClass) inRegexCharClass = false;
            if (char === '/' && !inRegexCharClass) {
                inRegex = false;
                cursor += 1;
                while (
                    cursor < sourceText.length &&
                    /[dgimsuvy]/i.test(sourceText[cursor])
                ) cursor += 1;
                continue;
            }
            cursor += 1;
            continue;
        }
        if (inSingleQuote || inDoubleQuote || inTemplate) {
            if (escaped) {
                escaped = false;
                cursor += 1;
                continue;
            }
            if (char === '\\') {
                escaped = true;
                cursor += 1;
                continue;
            }
            if (inSingleQuote && char === "'") inSingleQuote = false;
            else if (inDoubleQuote && char === '"') inDoubleQuote = false;
            else if (inTemplate && char === '`') inTemplate = false;
            cursor += 1;
            continue;
        }
        if (char === '/' && next === '/') {
            inLineComment = true;
            cursor += 2;
            continue;
        }
        if (char === '/' && next === '*') {
            inBlockComment = true;
            cursor += 2;
            continue;
        }
        if (char === "'") {
            inSingleQuote = true;
            cursor += 1;
            continue;
        }
        if (char === '"') {
            inDoubleQuote = true;
            cursor += 1;
            continue;
        }
        if (char === '`') {
            inTemplate = true;
            cursor += 1;
            continue;
        }
        if (char === '/') {
            if (isRegexStart(cursor)) {
                inRegex = true;
                cursor += 1;
                continue;
            }
        }

        if (char === '{') depth += 1;
        if (char === '}') {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
        cursor += 1;
    }
    throw new Error(
        `Could not parse function ${functionName} (reached EOF at depth ${depth})`,
    );
}

function loadListPanelHelpers() {
    const sourceText = fs.readFileSync(LIST_PANEL_SOURCE_PATH, 'utf8');
    const functionNames = [
        'getPacketPayloadLength',
        'getPacketPayloadHex',
        'isUnknownLikeProtocol',
        'isProtocolLikeFieldName',
        'isLinkLayerProtocolName',
        'collectDecodedProtocolNames',
        'formatLayerOnlyLabel',
        'normalizeGenericApplicationProtocolLabel',
        'inferZeroPayloadProtocolLabel',
        'inferApplicationProtocol',
    ];
    // The link-layer protocol allow-list is a module-level ``const``
    // declaration that the function-body extractor above does not
    // pick up.  Inject it explicitly so the VM context sees the same
    // set the real module does.
    const linkLayerConstMatch = sourceText.match(
        /const\s+LINK_LAYER_PROTOCOL_NAMES\s*=\s*new\s+Set\([\s\S]*?\]\.map\([\s\S]*?\);/,
    );
    if (!linkLayerConstMatch) {
        throw new Error(
            'Could not locate LINK_LAYER_PROTOCOL_NAMES declaration in list-panel.js',
        );
    }
    const extractedSource = [
        linkLayerConstMatch[0],
        ...functionNames.map((name) => extractFunctionSource(sourceText, name)),
    ].join('\n\n');
    const context = {
        String,
        Number,
        Set,
        Map,
        Array,
        Object,
    };
    vm.createContext(context);
    vm.runInContext(extractedSource, context);
    return context;
}

function makeDecryptedTcpPacket({
    extraProtocolsInSection = {},
    includeWifiInDecoded = true,
    appLayerFromTraits = '',
} = {}) {
    const decodedProtocols = [];
    if (includeWifiInDecoded) decodedProtocols.push('WIFI');
    decodedProtocols.push('TCP', 'IP');

    const tcpSection = {
        'tcp.src.port': 51515,
        'tcp.dst.port': 443,
        'TCP Flag Data': { Flags: 'ACK|PSH' },
        ...extraProtocolsInSection,
    };
    if (extraProtocolsInSection.HTTP) {
        tcpSection.HTTP = extraProtocolsInSection.HTTP;
    }

    return {
        packetInfo: {
            'packet.proto': 'TCP',
            'link.proto': 'IEEE 802.11',
            'wifi.decrypt.ok': true,
            'packet.decoded_protocols': decodedProtocols,
            IP: {
                'ip.src.addr': '10.0.0.1',
                'ip.dst.addr': '10.0.0.2',
            },
            TCP: tcpSection,
            'Raw data': {
                'payload.len': 256,
                'payload.hex': '00',
            },
        },
        extraInfo: {
            Traits: {
                'Network Data': {
                    'Port Protocol': appLayerFromTraits || 'https',
                    'Port Protcol': appLayerFromTraits || 'https',
                },
            },
        },
    };
}

describe('List panel — app-protocol inference for decrypted Wi-Fi frames', () => {
    let helpers;
    beforeAll(() => {
        helpers = loadListPanelHelpers();
    });

    test('collectDecodedProtocolNames filters link-layer names out of the candidate set', () => {
        const names = helpers.collectDecodedProtocolNames({
            'packet.proto': 'TCP',
            'packet.decoded_protocols': ['WIFI', 'TCP', 'IP'],
            IP: { 'ip.src.addr': '10.0.0.1' },
            TCP: { 'tcp.src.port': 1, 'tcp.dst.port': 2 },
        });
        expect(names).not.toContain('WIFI');
        expect(names).not.toContain('IEEE 802.11');
        expect(names).toContain('TCP');
        expect(names).toContain('IP');
    });

    test('collectDecodedProtocolNames still surfaces higher-layer decoded protocols', () => {
        const names = helpers.collectDecodedProtocolNames({
            'packet.proto': 'TCP',
            'packet.decoded_protocols': ['WIFI', 'HTTP', 'TCP', 'IP'],
            IP: { 'ip.src.addr': '10.0.0.1' },
            TCP: {
                'tcp.src.port': 51515,
                'tcp.dst.port': 80,
                HTTP: { 'http.request.method': 'GET' },
            },
        });
        expect(names).toContain('HTTP');
        expect(names).toContain('TCP');
        expect(names).not.toContain('WIFI');
    });

    test('isLinkLayerProtocolName flags every common link-layer placeholder', () => {
        for (const name of [
            'WIFI',
            'wifi',
            'IEEE 802.11',
            'ieee 802.11',
            'Ethernet',
            'LINUX COOKED',
            'Linux Cooked',
            'FRAME',
            'LINK',
        ]) {
            expect(helpers.isLinkLayerProtocolName(name)).toBe(true);
        }
        for (const name of ['HTTP', 'TCP', 'SSH', 'DNS', 'TLS']) {
            expect(helpers.isLinkLayerProtocolName(name)).toBe(false);
        }
    });

    test('decrypted TCP packet with WIFI in decoded_protocols reports its real app layer (HTTP)', () => {
        const { packetInfo, extraInfo } = makeDecryptedTcpPacket({
            extraProtocolsInSection: {
                HTTP: { 'http.request.method': 'GET', 'http.request.uri': '/' },
            },
        });
        expect(helpers.inferApplicationProtocol(packetInfo, extraInfo)).toBe('HTTP');
    });

    test('decrypted TCP packet with only WIFI in decoded_protocols falls through to the traits app protocol', () => {
        const packetInfo = {
            'packet.proto': 'TCP',
            'link.proto': 'IEEE 802.11',
            'wifi.decrypt.ok': true,
            // The legacy bug-shape: decoded_protocols contained only the
            // link-layer "WIFI" entry.  Filtered out by collectDecodedProtocolNames,
            // the function must NOT report "WIFI" — it should fall through
            // to the traits "Port Protocol" value instead.
            'packet.decoded_protocols': ['WIFI'],
            IP: { 'ip.src.addr': '10.0.0.1', 'ip.dst.addr': '10.0.0.2' },
            TCP: {
                'tcp.src.port': 51515,
                'tcp.dst.port': 443,
                'TCP Flag Data': { Flags: 'ACK|PSH' },
            },
            'Raw data': { 'payload.len': 256, 'payload.hex': '00' },
        };
        const extraInfo = {
            Traits: {
                'Network Data': { 'Port Protocol': 'https' },
            },
        };
        const result = helpers.inferApplicationProtocol(packetInfo, extraInfo);
        expect(result).toBe('https');
        // Explicit anti-regression: it must NOT have returned "WIFI".
        expect(result).not.toBe('WIFI');
        expect(result).not.toMatch(/^WIFI/i);
    });

    test('decrypted TCP packet without decoded_protocols at all reports transport-only TCP', () => {
        const { packetInfo, extraInfo } = makeDecryptedTcpPacket({
            includeWifiInDecoded: false,
            appLayerFromTraits: '',
        });
        // Strip decoded_protocols to mimic a normal (non-Wi-Fi-merged)
        // TCP packet and strip traits so we exercise the transport-only
        // fallback.
        delete packetInfo['packet.decoded_protocols'];
        delete extraInfo.Traits['Network Data']['Port Protocol'];
        delete extraInfo.Traits['Network Data']['Port Protcol'];
        const result = helpers.inferApplicationProtocol(packetInfo, extraInfo);
        // Non-zero payload + no decoded protocols + no traits → the
        // transport-only label, NOT "WIFI" and NOT "Unknown protocol".
        expect(result).toBe('TCP (Transport Only)');
        expect(result).not.toMatch(/^WIFI/i);
        expect(result).not.toMatch(/^Unknown protocol/i);
    });

    test('decrypted UDP packet with WIFI in decoded_protocols reports DNS when DNS section is present', () => {
        const packetInfo = {
            'packet.proto': 'UDP',
            'link.proto': 'IEEE 802.11',
            'wifi.decrypt.ok': true,
            'packet.decoded_protocols': ['WIFI', 'UDP', 'IP'],
            IP: { 'ip.src.addr': '10.0.0.1', 'ip.dst.addr': '10.0.0.2' },
            UDP: {
                'udp.src.port': 51515,
                'udp.dst.port': 53,
                DNS: {
                    'dns.id': 0xabcd,
                    'dns.qname': 'example.com',
                },
            },
            'Raw data': { 'payload.len': 64, 'payload.hex': '00' },
        };
        const extraInfo = {
            Traits: {
                'Network Data': { 'Port Protocol': 'domain' },
            },
        };
        // DNS is one of the preferred decoded names — it should win
        // over both WIFI and the traits "domain" placeholder.
        expect(helpers.inferApplicationProtocol(packetInfo, extraInfo)).toBe('DNS');
    });

    test('decrypted ICMP packet with WIFI in decoded_protocols still reports Ping', () => {
        const packetInfo = {
            'packet.proto': 'ICMP',
            'link.proto': 'IEEE 802.11',
            'wifi.decrypt.ok': true,
            'packet.decoded_protocols': ['WIFI', 'ICMP'],
            ICMP: {
                'icmp.type': 8,
                'icmp.code': 0,
            },
            'Raw data': { 'payload.len': 64, 'payload.hex': '00' },
        };
        expect(helpers.inferApplicationProtocol(packetInfo, {})).toBe('Ping');
    });
});

describe('List panel — backend Wi-Fi merge shape', () => {
    // Read the backend source and grep for the post-merge prepend of
    // "WIFI" in ``packet.decoded_protocols``.  This regression test
    // pins down the backend fix: the merge must NOT prepend "WIFI"
    // (the link-layer protocol is already captured via link.proto).
    test('snitch.py does NOT prepend "WIFI" when splicing wireless metadata into a decrypted inner packet', () => {
        const snitchPath = path.join(
            PROJECT_ROOT,
            'src',
            'backend',
            'snitch.py',
        );
        const sourceText = fs.readFileSync(snitchPath, 'utf8');
        // Look for any code path that appends "WIFI" to
        // ``packet.decoded_protocols`` of an inner (already-decoded)
        // packet.  The legacy pre-fix code looked like:
        //
        //   if "WIFI" not in decryptedProtocols:
        //       decryptedProtocols.append("WIFI")
        //   innerPacketInfo["packet.decoded_protocols"] = decryptedProtocols
        //
        // Pin down that this exact pattern is gone so the renderer no
        // longer has to defend against a misleading link-layer name
        // appearing in the decoded-protocols list.
        const legacyPrependPattern =
            /decryptedProtocols[\s\S]{0,200}append\(\s*["']WIFI["']\s*\)/;
        expect(sourceText).not.toMatch(legacyPrependPattern);
    });

    test('snitch.py still surfaces Wi-Fi decryption metadata via wifi.decrypt.* fields', () => {
        const snitchPath = path.join(
            PROJECT_ROOT,
            'src',
            'backend',
            'snitch.py',
        );
        const sourceText = fs.readFileSync(snitchPath, 'utf8');
        // We must still set the wifi.decrypt.ok / wifi.decrypt.algorithm
        // flags on the spliced inner packet so the renderer can tell
        // the user the packet was decrypted (and which key/algorithm
        // was used).  Pin that the post-merge assignments still exist.
        expect(sourceText).toContain('innerPacketInfo["wifi.decrypt.ok"]');
        expect(sourceText).toContain('innerPacketInfo["wifi.decrypt.algorithm"]');
        expect(sourceText).toContain('innerPacketInfo["link.proto"] = "IEEE 802.11"');
    });
});