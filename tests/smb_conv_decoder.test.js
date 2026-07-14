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
    if (bodyStart === -1) {
        throw new Error(`Could not find body for ${functionName}`);
    }
    let depth = 0;
    let cursor = bodyStart;
    while (cursor < sourceText.length) {
        const char = sourceText[cursor];
        if (char === '{') depth += 1;
        if (char === '}') {
            depth -= 1;
            if (depth === 0) {
                return sourceText.slice(startIndex, cursor + 1);
            }
        }
        cursor += 1;
    }
    throw new Error(`Could not parse function ${functionName}`);
}

function loadDecoderFunctions(filePath) {
    const sourceText = fs.readFileSync(filePath, 'utf8');
    const functionNames = [
        'normalizeSmbDecoderBytes',
        'findBytesSubsequence',
        'parseSmbNtlmSecurityBuffer',
        'decodeSmbTextBytes',
        'bytesToHexLower',
        'decodeSmbFromBytes',
        'autoDetectProtoFromBytes',
    ];
    const extractedSource = functionNames
        .map((functionName) => extractFunctionSource(sourceText, functionName))
        .join('\n\n');
    const context = {
        Uint8Array,
        DataView,
        TextDecoder,
        Buffer,
    };
    vm.createContext(context);
    vm.runInContext(extractedSource, context);
    return {
        decodeSmbFromBytes: context.decodeSmbFromBytes,
        autoDetectProtoFromBytes: context.autoDetectProtoFromBytes,
    };
}

function securityBuffer(length, offset) {
    const bytes = new Uint8Array(8);
    const view = new DataView(bytes.buffer);
    view.setUint16(0, length, true);
    view.setUint16(2, length, true);
    view.setUint32(4, offset, true);
    return bytes;
}

function buildNtlmAuthenticateBlob() {
    const domainBytes = Buffer.from('CORP', 'utf16le');
    const userBytes = Buffer.from('alice', 'utf16le');
    const workstationBytes = Buffer.from('WS01', 'utf16le');
    const lmResponse = Uint8Array.from({ length: 24 }, (_value, index) => index);
    const ntlmResponse = Uint8Array.from({ length: 24 }, (_value, index) => index + 24);

    const header = new Uint8Array(64);
    header.set(Buffer.from('NTLMSSP\0', 'binary'), 0);
    new DataView(header.buffer).setUint32(8, 3, true);
    new DataView(header.buffer).setUint32(60, 0x00000001, true);

    let dataOffset = 64;
    const lmOffset = dataOffset;
    dataOffset += lmResponse.length;
    const ntOffset = dataOffset;
    dataOffset += ntlmResponse.length;
    const domainOffset = dataOffset;
    dataOffset += domainBytes.length;
    const userOffset = dataOffset;
    dataOffset += userBytes.length;
    const workstationOffset = dataOffset;

    header.set(securityBuffer(lmResponse.length, lmOffset), 12);
    header.set(securityBuffer(ntlmResponse.length, ntOffset), 20);
    header.set(securityBuffer(domainBytes.length, domainOffset), 28);
    header.set(securityBuffer(userBytes.length, userOffset), 36);
    header.set(securityBuffer(workstationBytes.length, workstationOffset), 44);

    return Buffer.concat([
        Buffer.from(header),
        Buffer.from(lmResponse),
        Buffer.from(ntlmResponse),
        domainBytes,
        userBytes,
        workstationBytes,
    ]);
}

function buildSmb2Payload() {
    const header = Buffer.alloc(64);
    header.write('\xfeSMB', 0, 'binary');
    header.writeUInt16LE(0x0001, 12);
    const ntlmBlob = buildNtlmAuthenticateBlob();
    return Buffer.concat([header, ntlmBlob]);
}

function buildOffsetSmb2Payload(offset = 4) {
    return Buffer.concat([Buffer.alloc(offset, 0), buildSmb2Payload()]);
}

describe('SMB Conv decoder wiring', () => {
    const projectRoot = path.resolve(__dirname, '..');
    const decoderFiles = [
        path.join(projectRoot, 'src/ui/panels/data-tools-panel.js'),
        path.join(projectRoot, 'src/ui/main-frontend.js'),
    ];

    test.each(decoderFiles)('auto-detects and decodes SMB auth from %s', (filePath) => {
        const { decodeSmbFromBytes, autoDetectProtoFromBytes } = loadDecoderFunctions(filePath);
        const payload = new Uint8Array(buildSmb2Payload());

        expect(autoDetectProtoFromBytes(payload)).toBe('smb');
        expect(decodeSmbFromBytes(payload)).toEqual({
            protocol: 'SMB',
            fields: expect.arrayContaining([
                { name: 'Version', value: 'SMBv2/v3' },
                { name: 'Command', value: 'SESSION_SETUP' },
                { name: 'NTLMSSP', value: 'AUTHENTICATE' },
                { name: 'Domain', value: 'CORP' },
                { name: 'Username', value: 'alice' },
                { name: 'Workstation', value: 'WS01' },
            ]),
        });
    });

    test.each(decoderFiles)('detects SMB when signature is offset in %s', (filePath) => {
        const { decodeSmbFromBytes, autoDetectProtoFromBytes } = loadDecoderFunctions(filePath);
        const payload = new Uint8Array(buildOffsetSmb2Payload(4));

        expect(autoDetectProtoFromBytes(payload)).toBe('smb');
        expect(decodeSmbFromBytes(payload)).toEqual(
            expect.objectContaining({ protocol: 'SMB' }),
        );
    });

    test('Conv protocol dropdown includes SMB option', () => {
        const indexHtml = fs.readFileSync(path.join(projectRoot, 'src/index.html'), 'utf8');
        expect(indexHtml).toContain('<option value="smb">SMB / Samba</option>');
    });
});