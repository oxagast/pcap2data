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

function buildSecurityBuffer(length, offset) {
    const bytes = new Uint8Array(8);
    const view = new DataView(bytes.buffer);
    view.setUint16(0, length, true);
    view.setUint16(2, length, true);
    view.setUint32(4, offset, true);
    return bytes;
}

function buildSmbAuthenticatePayload() {
    const domainBytes = Buffer.from('DESKTOP-2AEFM7G', 'utf16le');
    const usernameBytes = Buffer.from('user', 'utf16le');
    const workstationBytes = Buffer.from('DESKTOP-2AEFM7G', 'utf16le');
    const lmResponse = Buffer.alloc(24, 0);
    const ntlmResponse = Buffer.from(
        '28a0c9f4e792c408913d2878feaa9a22010100000000000078a7ed218527d201',
        'hex',
    );
    const header = Buffer.alloc(64);
    header.write('NTLMSSP\0', 0, 'binary');
    header.writeUInt32LE(3, 8);
    header.writeUInt32LE(0x00000001, 60);

    let offset = 64;
    const lmOffset = offset;
    offset += lmResponse.length;
    const ntlmOffset = offset;
    offset += ntlmResponse.length;
    const domainOffset = offset;
    offset += domainBytes.length;
    const usernameOffset = offset;
    offset += usernameBytes.length;
    const workstationOffset = offset;

    Buffer.from(buildSecurityBuffer(lmResponse.length, lmOffset)).copy(header, 12);
    Buffer.from(buildSecurityBuffer(ntlmResponse.length, ntlmOffset)).copy(header, 20);
    Buffer.from(buildSecurityBuffer(domainBytes.length, domainOffset)).copy(header, 28);
    Buffer.from(buildSecurityBuffer(usernameBytes.length, usernameOffset)).copy(header, 36);
    Buffer.from(buildSecurityBuffer(workstationBytes.length, workstationOffset)).copy(header, 44);

    const smbHeader = Buffer.alloc(64);
    smbHeader.write('\xfeSMB', 0, 'binary');
    smbHeader.writeUInt16LE(0x0001, 12);

    const payload = Buffer.concat([
        Buffer.from([0x00, 0x00, 0x00, 0x00]),
        smbHeader,
        header,
        lmResponse,
        ntlmResponse,
        domainBytes,
        usernameBytes,
        workstationBytes,
    ]);
    return payload.toString('hex');
}

describe('SMB keystore helper extraction', () => {
    const sourcePath = path.join(__dirname, '..', 'src/ui/panels/keystore-panel.js');
    const sourceText = fs.readFileSync(sourcePath, 'utf8');
    const functionNames = [
        'normalizeSessionSecretValue',
        'isLikelyEmailAddress',
        'normalizeSmbPayloadBytes',
        'readUint32LeFromBytes',
        'readSmbSecurityBuffer',
        'decodeSmbUtf16Text',
        'findBytesPatternIndex',
        'bytesToHexStringLower',
        'extractSmbCredentialEntriesFromPayloadHex',
    ];
    const extractedSource = functionNames.map((name) => extractFunctionSource(sourceText, name)).join('\n\n');
    const context = {
        Uint8Array,
        DataView,
        TextDecoder,
        parseDataToolsInput: (format, rawInput) => {
            if (format !== 'hex') throw new Error('Unexpected format');
            return Uint8Array.from(Buffer.from(rawInput, 'hex'));
        },
    };
    vm.createContext(context);
    vm.runInContext(extractedSource, context);

    const mainFrontendSourcePath = path.join(__dirname, '..', 'src/ui/main-frontend.js');
    const mainFrontendSourceText = fs.readFileSync(mainFrontendSourcePath, 'utf8');
    const namedPipeHelperSource = extractFunctionSource(mainFrontendSourceText, 'isSmbNamedPipePath');
    const namedPipeContext = {};
    vm.createContext(namedPipeContext);
    vm.runInContext(namedPipeHelperSource, namedPipeContext);

    test('extracts SMB username/domain/hash from NTLM authenticate payload hex', () => {
        const entries = context.extractSmbCredentialEntriesFromPayloadHex(buildSmbAuthenticatePayload());
        expect(entries).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ label: 'SMB Username', content: 'user' }),
                expect.objectContaining({ label: 'SMB Domain', content: 'DESKTOP-2AEFM7G' }),
                expect.objectContaining({ label: 'SMB Workstation', content: 'DESKTOP-2AEFM7G' }),
                expect.objectContaining({ label: 'SMB NTLM Response (AUTHENTICATE)' }),
            ]),
        );
    });

    test('named-pipe SMB create paths are ignored for file carving', () => {
        expect(namedPipeContext.isSmbNamedPipePath('\\PIPE\\srvsvc')).toBe(true);
        expect(namedPipeContext.isSmbNamedPipePath('IPC$\\srvsvc')).toBe(true);
        expect(namedPipeContext.isSmbNamedPipePath('\\Users\\Public\\report.txt')).toBe(false);
    });
});