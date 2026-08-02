// EPMAP (Microsoft RPC Endpoint Mapper) Conv decoder.
//
// The Endpoint Mapper (MS-RPCE §3 / [MS-RPCE]) listens on TCP/UDP 135 and
// answers "where do I connect to talk to <UUID, version>?" queries from
// clients. It uses a DCE/RPC presentation context bound to the EPM
// interface UUID (e1af8308-5d1f-11c9-91a4-08002b14a0fa, version 4.0) and
// the standard EPM opnum set:
//
//   0  ept_insert              register a tower
//   1  ept_delete              unregister a tower
//   2  ept_lookup              resolve a UUID+version to a tower
//   3  ept_map                 resolve a vector of UUID+version to towers
//   4  ept_lookup_handle_free  free a handle returned by lookup_handle
//   5  ept_inq_object          enumerate objects registered for a UUID
//   6  ept_mgmt_delete         delete bindings by object UUID
//
// The decoder first runs the shared `parseDceRpcBind` helper to confirm
// the bound interface is EPM, then walks a stream of DCE/RPC request /
// response PDUs at the application layer. For each PDU it identifies the
// opnum and surfaces the key EPM fields:
//
//   Request (ept_lookup):
//     - Inquire (object UUID being resolved)
//     - MapVersion (interface version, e.g. 4.0 → "4.0")
//     - Inquiry Type (0=interface, 1=object, 2=both)
//     - Tower: Protocol Sequence (ncacn_ip_tcp / ncadg_ip_udp / ...)
//
//   Response (ept_lookup):
//     - Port / Host (resolved dynamic port or hostname from the returned tower)
//     - Protocol Sequence
//     - Annotation (RPC server annotation if returned)
//     - Number of Towers
//
// Tower parsing is best-effort: a tower is a sequence of "floors" each
// tagged with a 16-bit floor ID + 16-bit floor length. Recognized
// floor values come from DCE/RPC Appendix I / [MS-RPCE] §2.2.2.10:
//
//   0x00  Floor protocol ID  (0x01 = NCA Connection-oriented, 0x00 = floor end)
//   0x01  RPC Protocol ID     (0x0A = UUID, 0x09 = NDR20)
//   0x02  Address family      (0x02 = Connection-oriented, 0x0B = inet, ...)
//   0x03  Host address        (ASCII hostname or 4-byte IPv4 in big-endian)
//   0x04  Port                (ASCII decimal port number)
//   0x05  UUID                (16-byte interface UUID)
//   0x06  Version             (ASCII "X.Y" interface version)
//
// We render the protocol sequence, host, and port (when present) plus a
// hex preview of any unrecognized tower floors so the user can spot
// unusual bind points at a glance.

const { bytesToHexLower } = require("./smb-helpers");

const EPM_INTERFACE_UUID = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";
const EPM_INTERFACE_VERSION_MAJOR = 4;
const EPM_INTERFACE_VERSION_MINOR = 0;

const EPM_OPNUMS = {
    0: "ept_insert",
    1: "ept_delete",
    2: "ept_lookup",
    3: "ept_map",
    4: "ept_lookup_handle_free",
    5: "ept_inq_object",
    6: "ept_mgmt_delete",
};

const EPM_INQUIRY_TYPES = {
    0: "interface",
    1: "object",
    2: "both",
};

// Floor protocol IDs (lifted from DCE/RPC Appendix I).
const EPM_FLOOR_PROTOCOLS = {
    0x00: "floor",
    0x01: "ncacn",
    0x02: "ncacn_osi_dna",
    0x03: "ncacn_dnet",
    0x04: "ncacn_osi",
    0x05: "ncadg_ip_udp",
    0x06: "ncacn_ip_tcp",
    0x07: "ncadg_ipx",
    0x08: "ncacn_spx",
    0x09: "ncacn_nb_ipx",
    0x0a: "ncadg_nb_ipx",
    0x0b: "ncacn_nb_tcp",
    0x0c: "ncacn_spx_ii",
    0x0d: "ncacn_http",
    0x0e: "ncalrpc",
};

// "RPC Protocol" IDs that appear in the second floor of a tower.
const EPM_RPC_PROTOCOLS = {
    0x00: "invalid",
    0x01: "ncacn",
    0x09: "ndr20",
    0x0a: "uuid",
    0x0b: "ipv4",
};

// "Address family" floor values (subset that is meaningful for EPM over IP).
const EPM_ADDRESS_FAMILIES = {
    0x02: "connection-oriented",
    0x0b: "inet",
    0x0c: "inet6",
};

const EPM_MAX_PDUS = 32;
const EPM_UUID_TEXT_LIMIT = 36;
const EPM_ANNOTATION_LIMIT = 220;
const EPM_PROTOCOL_LIMIT = 24;

// EPM uses the standard DCE/RPC common header. PDU types we care about:
//   0x00 = Request, 0x02 = Response, 0x0b = Bind, 0x0c = BindAck.
const EPM_PDU_TYPE_NAMES = {
    0x00: "Request",
    0x01: "Ping",
    0x02: "Response",
    0x03: "Fault",
    0x04: "Working",
    0x05: "NoCall",
    0x06: "Reject",
    0x07: "Ack",
    0x08: "ClCancel",
    0x09: "BindNak",
    0x0a: "Auth3",
    0x0b: "Bind",
    0x0c: "BindAck",
    0x0d: "Auth3",
    0x0e: "Shutdown",
};

function readUint16LE(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 2 > bytes.length) return null;
    return bytes[offset] | (bytes[offset + 1] << 8);
}

function readUint32LE(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 4 > bytes.length) return null;
    return (
        (bytes[offset] |
            (bytes[offset + 1] << 8) |
            (bytes[offset + 2] << 16) |
            (bytes[offset + 3] << 24)) >>>
        0
    );
}

// Reverse the byte order of a hex segment (used for DCE/RPC UUID parsing).
function reverseHexPairs(hex) {
    return hex.match(/.{2}/g).reverse().join("");
}

function formatEpmUuid(uuidBytes) {
    if (!(uuidBytes instanceof Uint8Array) || uuidBytes.length !== 16) return "";
    const hex = bytesToHexLower(uuidBytes);
    // DCE/RPC stores UUIDs as 8/4/4/4/12 little-endian (Data1/Data2/Data3)
    // plus big-endian Data4 — same wire format used by the SMB helper.
    const data1 = reverseHexPairs(hex.slice(0, 8));
    const data2 = reverseHexPairs(hex.slice(8, 12));
    const data3 = reverseHexPairs(hex.slice(12, 16));
    const data4 = hex.slice(16, 32);
    return `${data1}-${data2}-${data3}-${data4.slice(0, 4)}-${data4.slice(4)}`;
}

function truncate(value, limit) {
    if (typeof value !== "string") return "";
    if (value.length > limit) return `${value.slice(0, limit - 1)}…`;
    return value;
}

// Parse a tower (a sequence of "floors" each with a 16-bit protocol ID +
// 16-bit length) starting at `offset`. The byte at offset is the count of
// floors; each floor is then 2 bytes protocol + 2 bytes length + payload.
// Returns { sequence, host, port, uuid, version, rawFloors, endIndex, ok }.
function parseEpmTower(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset >= bytes.length) {
        return { sequence: "", host: "", port: "", rawFloors: "", ok: false };
    }
    const numFloors = bytes[offset];
    let cursor = offset + 1;
    const floorSummaries = [];
    let sequence = "";
    let host = "";
    let port = "";
    let uuid = "";
    let version = "";
    for (let i = 0; i < numFloors && cursor + 4 <= bytes.length; i += 1) {
        const protocolId = readUint16LE(bytes, cursor);
        const payloadLength = readUint16LE(bytes, cursor + 2);
        cursor += 4;
        if (cursor + payloadLength > bytes.length) {
            floorSummaries.push(`floor${i}=0x${protocolId.toString(16).padStart(4, "0")}:truncated`);
            break;
        }
        const payload = bytes.slice(cursor, cursor + payloadLength);
        cursor += payloadLength;
        const label = EPM_FLOOR_PROTOCOLS[protocolId] || `0x${protocolId.toString(16).padStart(4, "0")}`;
        if (i === 0) {
            sequence = EPM_FLOOR_PROTOCOLS[protocolId] || `protocol 0x${protocolId.toString(16).padStart(4, "0")}`;
        }
        // Floor 4 (port) is ASCII-decimal per DCE/RPC §2.2.2.10.
        if (protocolId === 0x04 && payloadLength > 0) {
            let raw = "";
            for (let j = 0; j < payload.length; j += 1) {
                raw += String.fromCharCode(payload[j]);
            }
            port = raw.trim();
        }
        // Floor 3 (host) is either ASCII hostname or 4-byte IPv4.
        if (protocolId === 0x03 && payloadLength > 0) {
            if (payloadLength === 4) {
                host = `${payload[0]}.${payload[1]}.${payload[2]}.${payload[3]}`;
            } else {
                let raw = "";
                for (let j = 0; j < payload.length; j += 1) {
                    const byte = payload[j];
                    raw += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
                }
                host = raw.trim();
            }
        }
        // Floor 5 (UUID) is the 16-byte interface UUID.
        if (protocolId === 0x05 && payloadLength === 16) {
            uuid = formatEpmUuid(payload);
        }
        // Floor 6 (version) is ASCII "X.Y".
        if (protocolId === 0x06 && payloadLength > 0) {
            let raw = "";
            for (let j = 0; j < payload.length; j += 1) {
                raw += String.fromCharCode(payload[j]);
            }
            version = raw.trim();
        }
        const preview =
            payloadLength > 8
                ? `${bytesToHexLower(payload.slice(0, 8))}…`
                : bytesToHexLower(payload);
        floorSummaries.push(`floor${i}=${label}(${preview})`);
    }
    return {
        sequence,
        host,
        port,
        uuid,
        version,
        rawFloors: floorSummaries.join(" "),
        endIndex: cursor,
        ok: floorSummaries.length > 0,
    };
}

// Parse a request stub. For ept_lookup the wire format is:
//   referent_id     : uint32 (0 for first/only)
//   inquiry_type    : uint32 (0=interface, 1=object, 2=both)
//   object          : UUID   (16 bytes, the service UUID to resolve)
//   interface_id    : UUID   (16 bytes, 0 for EPM v4.0+ uses interface_ver below)
//   interface_ver   : uint32 (major in high 16 bits, minor in low 16 bits)
//   vers_option     : uint32 (1 = explicit version, 0 = any)
//   tower_length    : uint32 (0 for ept_lookup)
//   tower           : tower_t (only when length > 0)
// For ept_lookup_handle_t, the stub opens with a 20-byte
// `policy_handle` (4 bytes pad + 4 bytes handle value + 12 bytes UUID)
// then a uint32 max_ents.
function parseEpmLookupRequest(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 24 > bytes.length) return null;
    const referentId = readUint32LE(bytes, offset);
    const inquiryTypeRaw = readUint32LE(bytes, offset + 4);
    const objectUuid = formatEpmUuid(bytes.slice(offset + 8, offset + 24));
    let cursor = offset + 24;
    let interfaceUuid = "";
    let interfaceVer = "";
    if (cursor + 16 <= bytes.length) {
        interfaceUuid = formatEpmUuid(bytes.slice(cursor, cursor + 16));
        cursor += 16;
    }
    if (cursor + 4 <= bytes.length) {
        const versionRaw = readUint32LE(bytes, cursor);
        cursor += 4;
        const major = (versionRaw >>> 16) & 0xffff;
        const minor = versionRaw & 0xffff;
        interfaceVer = `${major}.${minor}`;
    }
    let versOption = "";
    if (cursor + 4 <= bytes.length) {
        const vOption = readUint32LE(bytes, cursor);
        cursor += 4;
        versOption = vOption === 1 ? "explicit" : vOption === 0 ? "any" : `0x${vOption.toString(16)}`;
    }
    return {
        referentId,
        inquiryType: EPM_INQUIRY_TYPES[inquiryTypeRaw] || `0x${inquiryTypeRaw.toString(16)}`,
        objectUuid: truncate(objectUuid, EPM_UUID_TEXT_LIMIT),
        interfaceUuid: truncate(interfaceUuid, EPM_UUID_TEXT_LIMIT),
        interfaceVer,
        versOption,
        nextOffset: cursor,
    };
}

// Best-effort response stub. For ept_lookup the first field is a
// `pointer_default` uint32 (often 0 or a referent id), then a uint32
// num_towers, then num_towers towers. Each tower is uint32 length +
// tower bytes. We don't try to fully NDR-decode — we just walk forward
// and surface the first tower we can parse, plus the port/host it picks.
function parseEpmLookupResponse(bytes, offset) {
    if (!(bytes instanceof Uint8Array) || offset + 8 > bytes.length) return null;
    const pointer = readUint32LE(bytes, offset);
    const numTowers = readUint32LE(bytes, offset + 4);
    let cursor = offset + 8;
    const towers = [];
    for (let i = 0; i < numTowers && i < 8; i += 1) {
        if (cursor + 4 > bytes.length) break;
        const towerLength = readUint32LE(bytes, cursor);
        cursor += 4;
        if (cursor + towerLength > bytes.length) break;
        const towerBytes = bytes.slice(cursor, cursor + towerLength);
        const parsed = parseEpmTower(towerBytes, 0);
        if (parsed.ok) {
            towers.push(parsed);
        }
        cursor += towerLength;
    }
    return {
        pointer,
        numTowers: String(numTowers),
        towers,
    };
}

function decodeEpmapFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;

    // Capture EPM Bind / BindAck positions so we can surface them as
    // "Bound Interface" rows and so we don't double-count the same PDU
    // when scanning for messages.
    const epmBindPositions = [];
    let bindsEpm = false;
    for (let i = 0; i + 16 <= bytes.length; i += 1) {
        if (bytes[i] !== 0x05 || bytes[i + 1] !== 0x00) continue;
        const pduType = bytes[i + 2];
        if (pduType !== 0x0b && pduType !== 0x0c) continue;
        const fragLength = readUint16LE(bytes, i + 8);
        if (fragLength < 24 || fragLength > bytes.length - i) continue;
        // 16-byte header + 12 bytes (max_xmit/max_recv/assoc_group) + 1 byte
        // num_contexts + 3 reserved bytes = 32 bytes before the first context.
        let cursor = i + 16;
        if (cursor + 16 > bytes.length) continue;
        cursor += 12; // max_xmit, max_recv, assoc_group
        const numContexts = bytes[cursor];
        cursor += 4; // num_contexts + 3 reserved bytes

        for (let c = 0; c < numContexts && cursor + 24 <= bytes.length; c += 1) {
            // Per context: p_cont_id(2) + n_transfer_syn(1) + reserved(1)
            // + abstract_syntax_uuid(16) + abstract_version(4) = 24-byte
            // fixed header. The abstract syntax UUID starts at offset 4
            // inside the context block.
            if (cursor + 24 > bytes.length) break;
            const contextStart = cursor;
            const nTransfer = bytes[cursor + 2];
            cursor += 24;
            // Bound the transfer-syntax walk by fragLength so a malformed
            // PDU doesn't drag us past the PDU's end.
            const transferLimit = i + fragLength;
            if (cursor > transferLimit) break;
            for (let t = 0; t < nTransfer; t += 1) {
                if (cursor + 20 > transferLimit) break;
                cursor += 20;
            }
            const uuidStart = contextStart + 4;
            const uuidBytes = bytes.slice(uuidStart, uuidStart + 16);
            const uuid = formatEpmUuid(uuidBytes);
            if (uuid === EPM_INTERFACE_UUID) {
                bindsEpm = true;
                epmBindPositions.push({
                    pduType,
                    fragLength,
                    index: i,
                });
                break;
            }
        }
        if (bindsEpm && epmBindPositions.length > 0) break;
    }

    if (!bindsEpm) {
        // No EPM Bind/BindAck seen; the stream is not EPMAP.
        return null;
    }

    // Walk the PDU stream. Per MS-RPCE §2.2.2.3 / §2.2.2.4 the request
    // and response body layouts are:
    //
    //   Request  : common_header(16) + alloc_hint(4) + p_cont_id(2)
    //              + opnum(2) + stub_length(4) + stub
    //   Response : common_header(16) + alloc_hint(4) + p_cont_id(2)
    //              + opnum(2) + stub
    //
    // We hop over common headers and decode opnums + ept_lookup/ept_map
    // application stubs without trying to recover inter-PDU framing.
    const fields = [];
    const fieldsLimit = 200;
    for (const bindPos of epmBindPositions) {
        const bindLabel = bindPos.pduType === 0x0c ? "BindAck" : "Bind";
        fields.push({
            name: `Bound Interface (${bindLabel})`,
            value: `EPM ${EPM_INTERFACE_VERSION_MAJOR}.${EPM_INTERFACE_VERSION_MINOR} (${EPM_INTERFACE_UUID})`,
        });
    }
    let pduIndex = 0;
    for (let i = 0; i + 24 <= bytes.length && pduIndex < EPM_MAX_PDUS; i += 1) {
        if (bytes[i] !== 0x05 || bytes[i + 1] !== 0x00) continue;
        const pduType = bytes[i + 2];
        if (!EPM_PDU_TYPE_NAMES[pduType]) continue;
        const fragLength = readUint16LE(bytes, i + 8);
        if (fragLength < 16 || fragLength > bytes.length - i) continue;
        // We only handle request/response at the application layer.
        if (pduType !== 0x00 && pduType !== 0x02) continue;

        const prefix = `Message ${pduIndex + 1}`;
        pduIndex += 1;
        const typeLabel = EPM_PDU_TYPE_NAMES[pduType];
        fields.push({ name: `${prefix} Type`, value: typeLabel });

        // Opnum is at offset 22 from the PDU start for both request and
        // response (16-byte common header + 4-byte alloc_hint + 2-byte
        // p_cont_id).
        const opnum = readUint16LE(bytes, i + 22);
        const opName = EPM_OPNUMS[opnum] || `opnum 0x${(opnum || 0).toString(16).padStart(4, "0")}`;
        fields.push({ name: `${prefix} Opnum`, value: opName });

        if (pduType === 0x00) {
            // Request: stub_length(4) + stub
            const stubLengthOffset = i + 24;
            if (stubLengthOffset + 4 > bytes.length) {
                if (fields.length >= fieldsLimit) break;
                continue;
            }
            const stubLength = readUint32LE(bytes, stubLengthOffset);
            fields.push({ name: `${prefix} Stub Length`, value: String(stubLength) });
            const stubDataOffset = stubLengthOffset + 4;
            const stubEnd = Math.min(
                stubDataOffset + stubLength,
                i + fragLength,
                bytes.length,
            );
            const stubBytes = bytes.slice(stubDataOffset, stubEnd);
            if (stubBytes.length > 0) {
                if (opnum === 2 || opnum === 3) {
                    const req = parseEpmLookupRequest(stubBytes, 0);
                    if (req) {
                        fields.push({ name: `${prefix} Inquiry Type`, value: req.inquiryType });
                        fields.push({ name: `${prefix} Object UUID`, value: req.objectUuid });
                        if (req.interfaceUuid) {
                            fields.push({ name: `${prefix} Interface UUID`, value: req.interfaceUuid });
                        }
                        if (req.interfaceVer) {
                            fields.push({ name: `${prefix} Interface Version`, value: req.interfaceVer });
                        }
                        if (req.versOption) {
                            fields.push({ name: `${prefix} Version Option`, value: req.versOption });
                        }
                    }
                } else {
                    fields.push({
                        name: `${prefix} Stub (hex preview)`,
                        value: bytesToHexLower(stubBytes.slice(0, 32)),
                    });
                }
            }
        } else {
            // Response: stub follows the 24-byte common body header.
            const stubStart = i + 24;
            if (stubStart >= bytes.length) {
                if (fields.length >= fieldsLimit) break;
                continue;
            }
            const stubEnd = Math.min(stubStart + Math.max(0, fragLength - 24), bytes.length);
            const stubBytes = bytes.slice(stubStart, stubEnd);
            if (stubBytes.length > 0) {
                if (opnum === 2 || opnum === 3) {
                    const resp = parseEpmLookupResponse(stubBytes, 0);
                    if (resp) {
                        fields.push({ name: `${prefix} Number of Towers`, value: resp.numTowers });
                        for (let t = 0; t < resp.towers.length; t += 1) {
                            const tower = resp.towers[t];
                            const seq = truncate(tower.sequence || "(unknown)", EPM_PROTOCOL_LIMIT);
                            const host = tower.host || "";
                            const port = tower.port || "";
                            const endpoint = host && port ? `${host}:${port}` : host || port || "(no endpoint)";
                            fields.push({ name: `${prefix} Tower ${t + 1} Protocol`, value: seq });
                            fields.push({ name: `${prefix} Tower ${t + 1} Endpoint`, value: endpoint });
                            if (tower.uuid) {
                                fields.push({ name: `${prefix} Tower ${t + 1} UUID`, value: tower.uuid });
                            }
                            if (tower.version) {
                                fields.push({ name: `${prefix} Tower ${t + 1} Version`, value: tower.version });
                            }
                        }
                    }
                } else {
                    fields.push({
                        name: `${prefix} Stub (hex preview)`,
                        value: bytesToHexLower(stubBytes.slice(0, 32)),
                    });
                }
            }
        }

        // Advance to the next PDU; fragLength covers the rest of this PDU.
        i = i + fragLength - 1;
        if (fields.length >= fieldsLimit) {
            fields.push({
                name: "Notice",
                value: `Field limit (${fieldsLimit}) reached; remaining messages omitted.`,
            });
            break;
        }
    }

    if (!fields.length) return null;
    return {
        protocol: "EPMAP",
        fields,
    };
}

module.exports = {
    decodeEpmapFromBytes,
    EPM_INTERFACE_UUID,
    EPM_INTERFACE_VERSION_MAJOR,
    EPM_INTERFACE_VERSION_MINOR,
};
