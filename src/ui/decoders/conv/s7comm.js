// S7comm Conv decoder: parses Siemens S7 Communication protocol messages
// carried over ISO-on-TCP (TPKT + COTP), typically on TCP port 102.
// Identifies messages by the TPKT header (version 0x03, reserved 0x00) and
// the S7comm protocol ID (0x32).

const S7COMM_TYPES = {
    1: "Job (Request)",
    2: "Ack",
    3: "Ack-Data (Response)",
    7: "Userdata (Diagnostic)",
};

const S7COMM_PARAM_FUNCTIONS = {
    0x00: "Userdata / Cyclic Services",
    0x04: "Read Var",
    0x05: "Write Var",
    0xf0: "Setup Communication",
    0x28: "Request Download",
    0x29: "Download Block",
    0x2a: "Download Ended",
    0x2b: "Start Upload",
    0x2c: "Upload",
    0x2d: "End Upload",
    0x2e: "Start Program",
    0x2f: "Stop Program",
    0x38: "PI Service (Program Invoke)",
    0x39: "PPI Service (Program Invoke)",
    0x3c: "List Blocks",
    0x3d: "List Blocks of Type",
    0x3e: "Get Block Info",
};

const S7COMM_ERROR_CODES = {
    0x01: "No S5 area defined for this address",
    0x02: "S5 area does not exist",
    0x03: "S5 area protected",
    0x05: "S5 segment missing",
    0x08: "S5 data block not available",
    0x09: "S5 data block exists already",
    0x0a: "S5 block exists already",
    0x0b: "S5 block exists, but is protected",
    0x12: "S5 operand range exceeded",
    0x13: "S5 access not permitted",
    0x14: "S5 data type not valid",
    0x85: "General error (see error code byte)",
    0xd2: "General error: block exists",
    0xd5: "General error: block does not exist",
    0xd6: "General error: block is not in correct state",
    0xd7: "General error: block is protected",
    0xda: "General error: block not available",
    0xe2: "General error: access not permitted",
    0xed: "General error: password not entered",
    0xfc: "General error: access not permitted",
    0xff: "General error: no password set",
};

const COTP_TYPE_NAMES = {
    0xe0: "CR (Connection Request)",
    0xd0: "CC (Connection Confirm)",
    0x80: "DR (Disconnect Request)",
    0xc0: "DC (Disconnect Confirm)",
    0xf0: "DT (Data Transfer, Class 0)",
    0x70: "DT (Data Transfer)",
};

function readUint16BE(bytes, offset) {
    return (bytes[offset] << 8) | bytes[offset + 1];
}

function hexPreview(bytes, maxLen = 128) {
    if (!bytes || bytes.length === 0) return "";
    const slice = bytes.slice(0, maxLen);
    let hex = "";
    for (let i = 0; i < slice.length; i++) {
        hex += slice[i].toString(16).padStart(2, "0");
    }
    if (bytes.length > maxLen) hex += "…";
    return hex;
}

function decodeS7commFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 10) return null;

    // TPKT header: Version=3, Reserved=0, Length (2 bytes BE)
    const tpktVersion = bytes[0];
    const tpktReserved = bytes[1];
    const tpktLength = readUint16BE(bytes, 2);

    if (tpktVersion !== 0x03 || tpktReserved !== 0x00) return null;
    if (tpktLength < 7) return null;

    // COTP DT PDU header (typically 2 bytes for Class 0)
    const cotpLen = bytes[4];
    const cotpType = bytes[5];
    const cotpTypeName = COTP_TYPE_NAMES[cotpType] || `Unknown (0x${cotpType.toString(16).padStart(2, "0")})`;

    // If COTP type is not Data Transfer, still report the TPKT/COTP layer
    if (cotpType !== 0xf0) {
        return {
            protocol: "S7comm",
            fields: [
                { name: "TPKT Version", value: tpktVersion },
                { name: "TPKT Length", value: tpktLength },
                { name: "COTP Length", value: cotpLen },
                { name: "COTP Type", value: `0x${cotpType.toString(16).padStart(2, "0")}` },
                { name: "COTP Type Name", value: cotpTypeName },
                { name: "Type", value: "COTP (non-data)" },
                { name: "Frame Hex", value: hexPreview(bytes) },
            ],
        };
    }

    // S7comm data starts after TPKT(4) + COTP header
    const s7Start = 4 + 1 + Math.max(cotpLen, 2);
    if (bytes.length < s7Start + 10) return null;

    const protoId = bytes[s7Start];
    if (protoId !== 0x32) return null;

    const rosctr = bytes[s7Start + 1];
    const redundancy = readUint16BE(bytes, s7Start + 2);
    const pduRef = readUint16BE(bytes, s7Start + 4);
    const rosctrName = S7COMM_TYPES[rosctr] || `Unknown (0x${rosctr.toString(16).padStart(2, "0")})`;

    const fields = [
        { name: "TPKT Version", value: tpktVersion },
        { name: "TPKT Length", value: tpktLength },
        { name: "COTP Length", value: cotpLen },
        { name: "COTP Type", value: `0x${cotpType.toString(16).padStart(2, "0")}` },
        { name: "COTP Type Name", value: cotpTypeName },
        { name: "Protocol ID", value: "0x32" },
        { name: "ROSCTR", value: rosctr },
        { name: "Message Type", value: rosctrName },
        { name: "Redundancy", value: redundancy },
        { name: "PDU Reference", value: pduRef },
        { name: "Type", value: rosctrName },
    ];

    // For Job (1), Ack-Data (3), and Userdata (7), parse parameter and data lengths.
    // Layout: param_len(2) at s7Start+6, data_len(2) at s7Start+8.
    // For Ack-Data only, error_class(1) + error_code(1) at s7Start+10..11.
    // Parameter data starts at s7Start+10 for Job/Userdata, s7Start+12 for Ack-Data.
    if (rosctr === 1 || rosctr === 3 || rosctr === 7) {
        if (bytes.length >= s7Start + 10) {
            const paramLen = readUint16BE(bytes, s7Start + 6);
            const dataLen = readUint16BE(bytes, s7Start + 8);
            fields.push(
                { name: "Parameter Length", value: paramLen },
                { name: "Data Length", value: dataLen },
            );

            let paramOffset = s7Start + 10;

            // For Ack-Data (rosctr=3), parse error class and error code at s7Start+10..11
            if (rosctr === 3 && bytes.length >= s7Start + 12) {
                const errorClass = bytes[s7Start + 10];
                const errorCode = bytes[s7Start + 11];
                paramOffset = s7Start + 12;
                if (errorClass !== 0x00 || errorCode !== 0x00) {
                    const errorName = S7COMM_ERROR_CODES[errorCode] || `Unknown (0x${errorCode.toString(16).padStart(2, "0")})`;
                    fields.push(
                        { name: "Error Class", value: `0x${errorClass.toString(16).padStart(2, "0")}` },
                        { name: "Error Code", value: `0x${errorCode.toString(16).padStart(2, "0")}` },
                        { name: "Error Name", value: errorName },
                    );
                }
            }

            // Parse parameter function
            if (bytes.length > paramOffset) {
                const paramHead = bytes[paramOffset];
                const funcName = S7COMM_PARAM_FUNCTIONS[paramHead];
                if (funcName) {
                    fields.push({ name: "Parameter Function", value: funcName });
                }

                // Setup Communication (0xF0) parses AMQ and PDU size
                if (paramHead === 0xf0 && bytes.length >= paramOffset + 8) {
                    fields.push(
                        { name: "Max AMQ Caller", value: readUint16BE(bytes, paramOffset + 2) },
                        { name: "Max AMQ Called", value: readUint16BE(bytes, paramOffset + 4) },
                        { name: "Negotiated PDU Size", value: readUint16BE(bytes, paramOffset + 6) },
                    );
                }
            }
        }
    }

    fields.push({ name: "Frame Hex", value: hexPreview(bytes) });

    return { protocol: "S7comm", fields };
}

module.exports = { decodeS7commFromBytes };