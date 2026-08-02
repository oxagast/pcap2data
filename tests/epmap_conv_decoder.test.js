const fs = require('fs');
const path = require('path');
const vm = require('vm');

// The shared `runInContextWithEpmDecoder` loader lives in a sibling file.
const { runInContextWithEpmDecoder } = require('./conv_decoder_helpers');

function getFieldValue(result, name) {
    const item = (result.fields || []).find((field) => field.name === name);
    return item ? item.value : null;
}

// Build a 16-byte UUID in the little-endian DCE/RPC wire format from a
// canonical "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" string.
function uuidToWire(canonical) {
    const clean = canonical.replace(/-/g, "").toLowerCase();
    if (clean.length !== 32) {
        throw new Error(`Invalid UUID: ${canonical}`);
    }
    const out = [];
    // Data1 (8 hex chars) — reverse byte order
    for (let i = 6; i >= 0; i -= 2) {
        out.push(parseInt(clean.slice(i, i + 2), 16));
    }
    // Data2 (4 hex chars) — reverse byte order
    for (let i = 10; i >= 8; i -= 2) {
        out.push(parseInt(clean.slice(i, i + 2), 16));
    }
    // Data3 (4 hex chars) — reverse byte order
    for (let i = 14; i >= 12; i -= 2) {
        out.push(parseInt(clean.slice(i, i + 2), 16));
    }
    // Data4 (12 hex chars) — keep byte order
    for (let i = 16; i < 32; i += 2) {
        out.push(parseInt(clean.slice(i, i + 2), 16));
    }
    return out;
}

const EPM_UUID_CANONICAL = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";
const NDR20_UUID_CANONICAL = "8a885d04-1ceb-11c9-9f08-08002b1029b1";

function buildEpmBindPdu() {
    // Build the presentation context body first so we can size the PDU.
    const abstractUuid = uuidToWire(EPM_UUID_CANONICAL);
    const transferUuid = uuidToWire(NDR20_UUID_CANONICAL);
    const contextBody = [];
    // p_cont_id = 0, n_transfer_syn = 1, reserved = 0
    contextBody.push(0x00, 0x00, 0x01, 0x00);
    // abstract_syntax UUID
    contextBody.push(...abstractUuid);
    // abstract_version = 4.0 (uint32 LE)
    contextBody.push(0x04, 0x00, 0x00, 0x00);
    // transfer_syntax UUID
    contextBody.push(...transferUuid);
    // transfer_syntax_version = 2.0 (uint32 LE)
    contextBody.push(0x02, 0x00, 0x00, 0x00);

    // Body = max_xmit(4) + max_recv(4) + assoc_group(4) +
    //        num_contexts(1) + reserved(3) + contextBody
    const bodyLen = 12 + 4 + contextBody.length;
    const fragLength = 16 + bodyLen;

    const pdu = [];
    // Common header
    pdu.push(0x05, 0x00, 0x0b, 0x23); // version 5.0, Bind, PFC_FIRST|PFC_LAST|PFC_CONC_MPX
    pdu.push(0x10, 0x00, 0x00, 0x00); // drep (little-endian)
    pdu.push(fragLength & 0xff, (fragLength >> 8) & 0xff, 0x00, 0x00); // frag_length, auth_length
    pdu.push(0x01, 0x00, 0x00, 0x00); // call_id = 1
    // max_xmit / max_recv / assoc_group
    pdu.push(0x10, 0x00, 0x00, 0x00);
    pdu.push(0x10, 0x00, 0x00, 0x00);
    pdu.push(0x00, 0x00, 0x00, 0x00);
    pdu.push(0x01, 0x00, 0x00, 0x00); // num_contexts + 3 reserved bytes
    pdu.push(...contextBody);
    return new Uint8Array(pdu);
}

// Build an EPM `ept_lookup` request stub (NDR encoded). The fields are
// referent_id, inquiry_type, object UUID, interface UUID, interface_ver
// (uint32 = (major << 16) | minor), vers_option, tower_length, tower.
function buildEpmLookupRequestStub({ objectUuid, major = 1, minor = 0 } = {}) {
    const object = objectUuid
        ? uuidToWire(objectUuid)
        : uuidToWire("12345778-1234-1234-1234-123456789abc");
    const interfaceUuid = new Array(16).fill(0);
    const versionWord = ((major & 0xffff) << 16) | (minor & 0xffff);
    const stub = [];
    stub.push(0x01, 0x00, 0x00, 0x00); // referent_id
    stub.push(0x00, 0x00, 0x00, 0x00); // inquiry_type = 0 (interface)
    stub.push(...object); // object UUID
    stub.push(...interfaceUuid); // interface UUID (all zeros)
    stub.push(versionWord & 0xff, (versionWord >> 8) & 0xff,
        (versionWord >> 16) & 0xff, (versionWord >> 24) & 0xff);
    stub.push(0x01, 0x00, 0x00, 0x00); // vers_option = 1 (explicit)
    stub.push(0x00, 0x00, 0x00, 0x00); // tower_length = 0
    return new Uint8Array(stub);
}

// Wrap a stub as a DCE/RPC Request PDU with the given opnum.
function wrapAsRequest(stub, opnum, fragLengthOverride = null) {
    const requestHeaderLen = 16 + 4 + 2 + 2; // common + alloc_hint + p_cont_id + opnum
    const total = requestHeaderLen + 4 + stub.length; // +4 for stub length prefix
    const fragLength = fragLengthOverride || total;
    const pdu = [];
    pdu.push(0x05, 0x00, 0x00, 0x23); // version 5.0, Request, PFC_FIRST|PFC_LAST|PFC_CONC_MPX
    pdu.push(0x10, 0x00, 0x00, 0x00); // drep
    pdu.push(fragLength & 0xff, (fragLength >> 8) & 0xff, 0x00, 0x00);
    pdu.push(0x02, 0x00, 0x00, 0x00); // call_id = 2
    pdu.push(0x00, 0x00, 0x00, 0x00); // alloc_hint
    pdu.push(0x00, 0x00); // p_cont_id = 0
    pdu.push(opnum & 0xff, (opnum >> 8) & 0xff); // opnum
    pdu.push(stub.length & 0xff, (stub.length >> 8) & 0xff,
        (stub.length >> 16) & 0xff, (stub.length >> 24) & 0xff);
    pdu.push(...stub);
    return new Uint8Array(pdu);
}

describe('EPMAP Conv decoder wiring', () => {
    const projectRoot = path.resolve(__dirname, '..');
    const decoderFile = path.join(projectRoot, 'src/ui/decoders/conv/epmap.js');

    test('returns null for non-EPMAP payloads', () => {
        const { decodeEpmapFromBytes } = runInContextWithEpmDecoder(decoderFile);
        expect(decodeEpmapFromBytes(new Uint8Array([0x00, 0x01, 0x02, 0x03]))).toBeNull();
        expect(decodeEpmapFromBytes(new Uint8Array())).toBeNull();
        expect(decodeEpmapFromBytes(null)).toBeNull();
    });

    test('decodes a bare EPM Bind PDU', () => {
        const { decodeEpmapFromBytes } = runInContextWithEpmDecoder(decoderFile);
        const bindPdu = buildEpmBindPdu();
        const decoded = decodeEpmapFromBytes(bindPdu);
        expect(decoded).not.toBeNull();
        expect(decoded.protocol).toBe("EPMAP");
        // No request/response PDUs in this stream — only the bind marker.
        // The decoder should still surface a non-null result with at least
        // one notice row to indicate we hit the bind but found no messages.
        expect(Array.isArray(decoded.fields)).toBe(true);
    });

    test('decodes an EPM Bind followed by an ept_lookup request', () => {
        const { decodeEpmapFromBytes } = runInContextWithEpmDecoder(decoderFile);
        const bindPdu = buildEpmBindPdu();
        const stub = buildEpmLookupRequestStub({ major: 1, minor: 0 });
        const requestPdu = wrapAsRequest(stub, 2); // opnum 2 = ept_lookup
        const stream = new Uint8Array(bindPdu.length + requestPdu.length);
        stream.set(bindPdu, 0);
        stream.set(requestPdu, bindPdu.length);

        const decoded = decodeEpmapFromBytes(stream);
        expect(decoded).not.toBeNull();
        expect(decoded.protocol).toBe("EPMAP");
        expect(getFieldValue(decoded, "Message 1 Type")).toBe("Request");
        expect(getFieldValue(decoded, "Message 1 Opnum")).toBe("ept_lookup");
        expect(getFieldValue(decoded, "Message 1 Inquiry Type")).toBe("interface");
        expect(getFieldValue(decoded, "Message 1 Object UUID")).toBe(
            "12345778-1234-1234-1234-123456789abc"
        );
        expect(getFieldValue(decoded, "Message 1 Interface Version")).toBe("1.0");
        expect(getFieldValue(decoded, "Message 1 Version Option")).toBe("explicit");
    });

    test('maps opnums to their EPM operation names', () => {
        const { decodeEpmapFromBytes } = runInContextWithEpmDecoder(decoderFile);
        const bindPdu = buildEpmBindPdu();
        const stub = new Uint8Array([0x01, 0x00, 0x00, 0x00]);
        const knownOpNames = [
            { opnum: 0, name: "ept_insert" },
            { opnum: 1, name: "ept_delete" },
            { opnum: 3, name: "ept_map" },
            { opnum: 4, name: "ept_lookup_handle_free" },
            { opnum: 5, name: "ept_inq_object" },
            { opnum: 6, name: "ept_mgmt_delete" },
        ];
        for (const { opnum, name } of knownOpNames) {
            const requestPdu = wrapAsRequest(stub, opnum);
            const stream = new Uint8Array(bindPdu.length + requestPdu.length);
            stream.set(bindPdu, 0);
            stream.set(requestPdu, bindPdu.length);
            const decoded = decodeEpmapFromBytes(stream);
            expect(decoded).not.toBeNull();
            expect(getFieldValue(decoded, "Message 1 Opnum")).toBe(name);
        }
    });

    test('does not detect non-EPM BIND PDUs as EPMAP', () => {
        const { decodeEpmapFromBytes } = runInContextWithEpmDecoder(decoderFile);
        // Build a Bind PDU with a samr-like UUID instead of EPM.
        const fakeUuid = uuidToWire("12345778-1234-1234-1234-123456789012");
        const transferUuid = uuidToWire(NDR20_UUID_CANONICAL);
        const contextBody = [
            0x00, 0x00, 0x01, 0x00,
            ...fakeUuid,
            0x01, 0x00, 0x00, 0x00,
            ...transferUuid,
            0x02, 0x00, 0x00, 0x00,
        ];
        const bodyLen = 12 + 4 + contextBody.length;
        const fragLength = 16 + bodyLen;
        const pdu = [
            0x05, 0x00, 0x0b, 0x23,
            0x10, 0x00, 0x00, 0x00,
            fragLength & 0xff, (fragLength >> 8) & 0xff, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,
            ...contextBody,
        ];
        expect(decodeEpmapFromBytes(new Uint8Array(pdu))).toBeNull();
    });

    test('detects EPMAP via the auto-detect chain', () => {
        const { autoDetectProtoFromBytes } = runInContextWithEpmDecoder(decoderFile, { withAutoDetect: true });
        const bindPdu = buildEpmBindPdu();
        expect(autoDetectProtoFromBytes(bindPdu)).toBe("epmap");
    });

    test('protocol/port hints expose EPMAP', () => {
        const { protocolHints, portHints } = runInContextWithEpmDecoder(decoderFile, { hintsOnly: true });
        expect(protocolHints.get("epmap")).toBe("epmap");
        expect(portHints.get(135)).toBe("epmap");
    });
});
