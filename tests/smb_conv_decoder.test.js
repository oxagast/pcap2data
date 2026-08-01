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
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inTemplate = false;
    let inLineComment = false;
    let inBlockComment = false;
    let inRegex = false;
    let escaped = false;

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
        if (inSingleQuote || inDoubleQuote || inTemplate || inRegex) {
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
            else if (inRegex && char === '/') inRegex = false;
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
            const prev = sourceText[cursor - 1];
            if (!prev || /[=(:,!&|?{};\s]/.test(prev)) {
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
    throw new Error(`Could not parse function ${functionName}`);
}

function loadDecoderFunctions(filePath) {
    const sourceText = fs.readFileSync(filePath, 'utf8');
    // decodeSmbFromBytes and the SMB helpers now live under
    // src/ui/decoders/conv/ (refactor: moved out of data-tools-panel.js).
    // The same is true for the pure orchestrator helper
    // autoDetectProtoFromBytes — it now lives under
    // src/ui/decoders/conv/auto-detect.js, which is what the panel aliases.
    // We extract from auto-detect.js for the panel path, and from the
    // parallel main-frontend.js copy (which still has the inline
    // declaration) otherwise.
    const convDecoders = require(path.join(path.resolve(__dirname, '..'), 'src/ui/decoders/conv'));
    let extractedSource = '';
    if (sourceText.includes('function autoDetectProtoFromBytes')) {
        extractedSource = extractFunctionSource(sourceText, 'autoDetectProtoFromBytes');
    } else {
        const autoDetectSource = fs.readFileSync(
            path.join(path.resolve(__dirname, '..'), 'src/ui/decoders/conv/auto-detect.js'),
            'utf8',
        );
        extractedSource = extractFunctionSource(autoDetectSource, 'autoDetectProtoFromBytes');
    }
    const alwaysNull = () => null;
    const context = {
        Uint8Array,
        DataView,
        TextDecoder,
        Buffer,
        getImageTypeFromExifReader: alwaysNull,
        decodeHtmlFromBytes: alwaysNull,
        normalizeSmbDecoderBytes: convDecoders.normalizeSmbDecoderBytes,
        findBytesSubsequence: convDecoders.findBytesSubsequence,
        parseSmbNtlmSecurityBuffer: convDecoders.parseSmbNtlmSecurityBuffer,
        decodeSmbTextBytes: convDecoders.decodeSmbTextBytes,
        bytesToHexLower: convDecoders.bytesToHexLower,
        extractSmb2CreateFileName: convDecoders.extractSmb2CreateFileName,
        parseDceRpcBind: convDecoders.parseDceRpcBind,
        formatDceRpcUuid: convDecoders.formatDceRpcUuid,
        lookupDceRpcService: convDecoders.lookupDceRpcService,
        decodeSmbFromBytes: convDecoders.decodeSmbFromBytes,
        autoDetectProtoFromBytes: convDecoders.autoDetectProtoFromBytes,
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

// Build an SMB2 CREATE request body whose NameOffset/NameLength point to a
// UTF-16LE pipe path. The CREATE request body layout (after the 64-byte
// SMB2 header) is at least 56 bytes of fixed fields followed by the variable
// "name path buffer" (offset 40, length 48 = uint32 + uint16 + BufferFormat).
function buildSmb2CreatePayload(pipeName) {
    const nameBytes = Buffer.from(pipeName, 'utf16le');
    const body = Buffer.alloc(56 + nameBytes.length);
    body.writeUInt16LE(0, 0);          // SecurityFlags
    body.writeUInt8(0, 2);             // RequestedOplockLevel
    body.writeUInt32LE(0, 4);          // ImpersonationLevel
    // 8..16 SmbCreateFlags
    // 16..24 RootDirectory
    // 24..32 DesiredAccess
    // 32..40 FileAttributes
    // 40..48 NameOffset + NameLength
    body.writeUInt32LE(56, 40);        // NameOffset → right after fixed body
    body.writeUInt16LE(nameBytes.length, 48);
    body.writeUInt8(0x04, 50);         // BufferFormat (0x04 = path, per spec)
    nameBytes.copy(body, 56);
    const header = Buffer.alloc(64);
    header.write('\xfeSMB', 0, 'binary');
    header.writeUInt16LE(0x0005, 12);  // CREATE
    return Buffer.concat([header, body]);
}

// Build a DCE/RPC bind PDU body that names a well-known interface. The body
// is what `parseDceRpcBind` consumes directly (16-byte common header + bind
// fields). 16-byte UUID written little-endian per MS-RPCE.
function buildDceRpcBindPayload(uuid) {
    // canonical 8-4-4-4-12 → bytes
    const [d1, d2, d3, d4a, d4b] = uuid.split('-');
    const uuidBytes = Buffer.alloc(16);
    uuidBytes.writeUInt32LE(parseInt(d1, 16), 0);
    uuidBytes.writeUInt16LE(parseInt(d2, 16), 4);
    uuidBytes.writeUInt16LE(parseInt(d3, 16), 6);
    uuidBytes.write(d4a, 8, 2, 'hex');
    uuidBytes.write(d4b, 10, 6, 'hex');
    const common = Buffer.alloc(16);
    common[0] = 0x05; common[1] = 0x00; common[2] = 0x0b; // BIND
    common[3] = 0x03; // PFC flags (first + last)
    common.writeUInt32LE(0x10, 4); // drep (LE)
    // fragLength (uint16 @ offset 8) filled later
    common.writeUInt32LE(1, 12); // call_id
    const bind = Buffer.alloc(16);
    bind.writeUInt32LE(0x1000, 0);  // max_xmit_frag
    bind.writeUInt32LE(0x1000, 4);  // max_recv_frag
    bind.writeUInt32LE(0, 8);       // assoc_group_id
    bind.writeUInt8(1, 12);         // num_contexts
    bind.writeUInt8(0, 13);         // reserved
    bind.writeUInt16LE(0, 14);      // reserved
    const ctx = Buffer.alloc(4 + 20);
    ctx.writeUInt16LE(0, 0);        // p_cont_id
    ctx.writeUInt8(1, 2);           // n_transfer_syn
    ctx.writeUInt8(0, 3);           // reserved
    uuidBytes.copy(ctx, 4);
    ctx.writeUInt32LE(0x00010000, 20); // abstract version (1.0)
    const payload = Buffer.concat([common, bind, ctx]);
    payload.writeUInt16LE(payload.length, 8);
    return payload;
}

// Wrap a DCE/RPC bind PDU inside an SMB2 WRITE request body. SMB2 WRITE body
// (MS-SMB2 §2.2.15): Offset(2) + reserved(4) + Length(4) + Buffer. The
// length is a uint32 and the data starts at offset 10.
function buildSmb2WritePayload(bindPdu) {
    const body = Buffer.alloc(10 + bindPdu.length);
    body.writeUInt16LE(0, 0);
    body.writeUInt32LE(0, 2);
    body.writeUInt32LE(bindPdu.length, 6);
    bindPdu.copy(body, 10);
    const header = Buffer.alloc(64);
    header.write('\xfeSMB', 0, 'binary');
    header.writeUInt16LE(0x0009, 12); // WRITE
    return Buffer.concat([header, body]);
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

    test('Conv protocol dropdown includes SMB and Plain text options', () => {
        const indexHtml = fs.readFileSync(path.join(projectRoot, 'src/index.html'), 'utf8');
        expect(indexHtml).toContain('<option value="smb">SMB / Samba</option>');
        expect(indexHtml).toContain('<option value="plaintext">Plain text</option>');
    });

    test.each(decoderFiles)('surfaces named pipe on SMB2 CREATE in %s', (filePath) => {
        const { decodeSmbFromBytes } = loadDecoderFunctions(filePath);
        const payload = new Uint8Array(buildSmb2CreatePayload('\\PIPE\\lsarpc'));
        const result = decodeSmbFromBytes(payload);
        expect(result).toEqual(
            expect.objectContaining({
                protocol: 'SMB',
                fields: expect.arrayContaining([
                    { name: 'Version', value: 'SMBv2/v3' },
                    { name: 'Command', value: 'CREATE' },
                    { name: 'Named Pipe', value: '\\PIPE\\lsarpc' },
                ]),
            }),
        );
    });

    test.each(decoderFiles)('surfaces DCE/RPC bind info on SMB2 WRITE in %s', (filePath) => {
        const { decodeSmbFromBytes } = loadDecoderFunctions(filePath);
        // samr interface UUID — well-known DC RPC service.
        const bindPdu = buildDceRpcBindPayload('12345778-1234-1234-1234-123456789012');
        const payload = new Uint8Array(buildSmb2WritePayload(bindPdu));
        const result = decodeSmbFromBytes(payload);
        expect(result).toEqual(
            expect.objectContaining({
                protocol: 'SMB',
                fields: expect.arrayContaining([
                    { name: 'Command', value: 'WRITE' },
                    { name: 'RPC Op', value: 'BIND' },
                    { name: 'RPC Service', value: 'samr' },
                ]),
            }),
        );
        const ifaceField = result.fields.find((f) => f.name === 'RPC Interface');
        expect(ifaceField.value).toBe('12345778-1234-1234-1234-123456789012');
    });

    test('UUID lookup maps well-known DC interfaces', () => {
        const { lookupDceRpcService, formatDceRpcUuid } = require(
            path.join(projectRoot, 'src/ui/decoders/conv/smb-helpers'),
        );
        expect(lookupDceRpcService('12345778-1234-1234-1234-123456789013')).toBe('lsarpc');
        expect(lookupDceRpcService('e3514235-4b06-11d1-ab04-00c04fc2dcd2')).toBe('drs');
        expect(lookupDceRpcService('00000000-0000-0000-0000-000000000000')).toBeNull();
        // UUID byte order is mixed LE/BE; verify formatting reconstructs the
        // canonical form (Data1/Data2/Data3 stored little-endian).
        const u = formatDceRpcUuid(
            new Uint8Array([
                0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12,
                0x34, 0x12, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12,
            ]),
        );
        expect(u).toBe('12345778-1234-1234-3412-123456789012');
    });
});