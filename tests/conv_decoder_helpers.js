// Shared helper used by Conv decoder tests. Loads the EPMAP decoder (and
// optionally the auto-detect + protocol/port hint maps) into a fresh VM
// context with the unrelated decoders stubbed out, mirroring the pattern
// used by sip_conv_decoder.test.js / p2p_smpp_conv_decoder.test.js.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

// Lightweight source-text walker: finds the named function declaration in
// source text and returns its full source (from `function name` up to and
// including the matching closing brace). Brace counting respects strings,
// template literals, line/block comments, and regular-expression literals.
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

// Extract either a `function NAME(...) { ... }` declaration or a top-level
// `const NAME = <primitive|object|array>;` declaration. Returns the source
// text starting at the matched token and ending at the terminator (closing
// brace for functions, closing `;` or matching bracket for const
// declarations).
function extractNamedDeclaration(sourceText, name) {
    const functionIdx = sourceText.indexOf(`function ${name}(`);
    if (functionIdx !== -1) {
        return extractFunctionSource(sourceText, name);
    }
    const constRegex = new RegExp(`(?:^|\\n)\\s*const\\s+${name}\\s*=\\s*`, 'g');
    const match = constRegex.exec(sourceText);
    if (!match) {
        throw new Error(`Could not find declaration for ${name}`);
    }
    const startIdx = match.index + match[0].length;
    // Walk forward and count brackets/braces; the declaration ends when we
    // return to depth 0 and encounter `;` or `,` at the top level.
    let depth = 0;
    let cursor = startIdx;
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inTemplate = false;
    let inLineComment = false;
    let inBlockComment = false;
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
        if (char === "'") { inSingleQuote = true; cursor += 1; continue; }
        if (char === '"') { inDoubleQuote = true; cursor += 1; continue; }
        if (char === '`') { inTemplate = true; cursor += 1; continue; }
        if (char === '{' || char === '[' || char === '(') depth += 1;
        else if (char === '}' || char === ']' || char === ')') depth -= 1;
        else if (depth === 0 && (char === ';' || char === ',' || char === '\n')) {
            return sourceText.slice(match.index, cursor + 1);
        }
        cursor += 1;
    }
    throw new Error(`Could not parse declaration for ${name}`);
}

// Inlines the helpers that epmap.js references at module scope into a
// single self-contained source string. The vm context provides
// `bytesToHexLower` (from smb-helpers) so the decoder still works, while
// the inlined declarations keep the const tables + helper functions in
// scope.
function buildInlineDecoderSource(epmapSource) {
    const symbols = [
        'EPM_INTERFACE_UUID',
        'EPM_INTERFACE_VERSION_MAJOR',
        'EPM_INTERFACE_VERSION_MINOR',
        'EPM_OPNUMS',
        'EPM_INQUIRY_TYPES',
        'EPM_FLOOR_PROTOCOLS',
        'EPM_RPC_PROTOCOLS',
        'EPM_ADDRESS_FAMILIES',
        'EPM_MAX_PDUS',
        'EPM_UUID_TEXT_LIMIT',
        'EPM_ANNOTATION_LIMIT',
        'EPM_PROTOCOL_LIMIT',
        'EPM_PDU_TYPE_NAMES',
        'readUint16LE',
        'readUint32LE',
        'reverseHexPairs',
        'formatEpmUuid',
        'truncate',
        'parseEpmTower',
        'parseEpmLookupRequest',
        'parseEpmLookupResponse',
    ];
    return symbols
        .map((name) => extractNamedDeclaration(epmapSource, name))
        .concat([extractFunctionSource(epmapSource, 'decodeEpmapFromBytes')])
        .join('\n\n');
}

function runInContextWithEpmDecoder(epmapFile, options = {}) {
    const projectRoot = path.resolve(__dirname, '..');
    const convDecoders = require(path.join(projectRoot, 'src/ui/decoders/conv'));
    const epmapSource = fs.readFileSync(epmapFile, 'utf8');
    const inlineSource = buildInlineDecoderSource(epmapSource);

    const alwaysNull = () => null;
    const context = {
        Uint8Array,
        DataView,
        TextDecoder,
        TextEncoder,
        console,
        Buffer,
        // EPMAP's `bytesToHexLower` import from smb-helpers.
        bytesToHexLower: convDecoders.bytesToHexLower,
        // Stubs for the auto-detect branches that EPMAP doesn't exercise:
        getImageTypeFromExifReader: alwaysNull,
        decodeJsonFromBytes: alwaysNull,
        decodeXmlFromBytes: alwaysNull,
        decodeHtmlFromBytes: alwaysNull,
        decodeBsonFromBytes: alwaysNull,
        decodeMessagePackFromBytes: alwaysNull,
        decodeProtobufFromBytes: alwaysNull,
        decodeBerFromBytes: alwaysNull,
        decodeDerFromBytes: alwaysNull,
        decodeYamlFromBytes: alwaysNull,
        decodeLdapFromBytes: alwaysNull,
        normalizeSmbDecoderBytes: convDecoders.normalizeSmbDecoderBytes,
        decodeEpmapFromBytes: convDecoders.decodeEpmapFromBytes,
        decodeSmppFromBytes: convDecoders.decodeSmppFromBytes,
        decodeSoulseekFromBytes: convDecoders.decodeSoulseekFromBytes,
        decodeBittorrentFromBytes: convDecoders.decodeBittorrentFromBytes,
        decodeKerberosFromBytes: convDecoders.decodeKerberosFromBytes,
        decodeDnsFromBytes: convDecoders.decodeDnsFromBytes,
        decodeSnmpFromBytes: convDecoders.decodeSnmpFromBytes,
        decodeDhcpFromBytes: convDecoders.decodeDhcpFromBytes,
        decodeDhcpv6FromBytes: convDecoders.decodeDhcpv6FromBytes,
    };
    vm.createContext(context);
    vm.runInContext(inlineSource, context);

    const out = {
        decodeEpmapFromBytes: context.decodeEpmapFromBytes,
    };

    if (options.withAutoDetect) {
        // Pull autoDetectProtoFromBytes straight from the real module so we
        // exercise the production code path (not a copy).
        out.autoDetectProtoFromBytes = convDecoders.autoDetectProtoFromBytes;
    }

    if (options.hintsOnly) {
        out.protocolHints = convDecoders.PROTOCOL_DECODER_HINTS;
        out.portHints = convDecoders.PORT_DECODER_HINTS;
    }

    return out;
}

module.exports = {
    extractFunctionSource,
    runInContextWithEpmDecoder,
};
