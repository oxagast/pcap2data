// Modbus/TCP Conv decoder: parses the Modbus Application Protocol (MBAP)
// header and PDU per RFC 502 / MB-AP. Identifies messages by the 7-byte
// MBAP header with protocol identifier 0x0000 and a valid function code.

const MODBUS_FUNCTION_CODES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    11: "Get Comm Event Counter",
    12: "Get Comm Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Encapsulated Interface Transport",
};

const MODBUS_EXCEPTION_CODES = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Server Device Failure",
    5: "Acknowledge",
    6: "Server Device Busy",
    7: "Negative Acknowledge",
    8: "Memory Parity Error",
    9: "Gateway Path Unavailable",
    10: "Gateway Target Device Failed to Respond",
};

function readUint16BE(bytes, offset) {
    return (bytes[offset] << 8) | bytes[offset + 1];
}

function hexPreview(bytes, maxLen = 64) {
    if (!bytes || bytes.length === 0) return "";
    const slice = bytes.slice(0, maxLen);
    let hex = "";
    for (let i = 0; i < slice.length; i++) {
        hex += slice[i].toString(16).padStart(2, "0");
    }
    if (bytes.length > maxLen) hex += "…";
    return hex;
}

function decodeModbusFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 8) return null;

    // MBAP header: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1)
    const transId = readUint16BE(bytes, 0);
    const protoId = readUint16BE(bytes, 2);
    const length = readUint16BE(bytes, 4);
    const unitId = bytes[6];

    // Protocol identifier must be 0 for Modbus/TCP
    if (protoId !== 0) return null;
    // Length must cover at least Unit ID (1) + Function Code (1) = 2
    if (length < 2) return null;
    // Need at least 7 (MBAP) + 1 (function code)
    if (bytes.length < 8) return null;

    const funcCode = bytes[7];
    const isException = (funcCode & 0x80) !== 0;
    const baseFunc = funcCode & 0x7f;
    const funcName = MODBUS_FUNCTION_CODES[baseFunc] || `Unknown (0x${baseFunc.toString(16).padStart(2, "0")})`;

    const fields = [
        { name: "Transaction ID", value: transId },
        { name: "Protocol ID", value: protoId },
        { name: "Length", value: length },
        { name: "Unit ID", value: unitId },
        { name: "Function Code", value: baseFunc },
        { name: "Function Name", value: funcName },
        { name: "Type", value: isException ? "Exception Response" : "Request/Response" },
    ];

    // PDU = bytes after unit id, up to 6 + length
    const pduEnd = Math.min(6 + length, bytes.length);
    const pdu = bytes.slice(8, pduEnd);

    if (isException) {
        if (pdu.length >= 1) {
            const excCode = pdu[0];
            const excName = MODBUS_EXCEPTION_CODES[excCode] || `Unknown (0x${excCode.toString(16).padStart(2, "0")})`;
            fields.push(
                { name: "Exception Code", value: excCode },
                { name: "Exception Name", value: excName },
            );
        }
    } else {
        // Decode function-specific data
        if (baseFunc === 1 || baseFunc === 2 || baseFunc === 3 || baseFunc === 4) {
            // Read functions: Request has Starting Address (2) + Quantity (2)
            // Response has Byte Count (1) + Data
            if (pdu.length === 4) {
                fields.push(
                    { name: "Starting Address", value: readUint16BE(pdu, 0) },
                    { name: "Quantity", value: readUint16BE(pdu, 2) },
                );
            } else if (pdu.length >= 1) {
                fields.push(
                    { name: "Byte Count", value: pdu[0] },
                    { name: "Data", value: hexPreview(pdu.slice(1), 128) },
                );
            }
        } else if (baseFunc === 5) {
            // Write Single Coil: Address (2) + Value (2: 0xFF00=ON, 0x0000=OFF)
            if (pdu.length === 4) {
                fields.push(
                    { name: "Address", value: readUint16BE(pdu, 0) },
                    { name: "Value", value: readUint16BE(pdu, 2) === 0xff00 ? "ON" : "OFF" },
                );
            }
        } else if (baseFunc === 6) {
            // Write Single Register: Address (2) + Value (2)
            if (pdu.length === 4) {
                fields.push(
                    { name: "Address", value: readUint16BE(pdu, 0) },
                    { name: "Register Value", value: readUint16BE(pdu, 2) },
                );
            }
        } else if (baseFunc === 15 || baseFunc === 16) {
            // Write Multiple: Request has Address(2)+Quantity(2)+ByteCount(1)+Data
            // Response has Address(2)+Quantity(2)
            if (pdu.length === 4) {
                fields.push(
                    { name: "Address", value: readUint16BE(pdu, 0) },
                    { name: "Quantity", value: readUint16BE(pdu, 2) },
                );
            } else if (pdu.length >= 5) {
                fields.push(
                    { name: "Address", value: readUint16BE(pdu, 0) },
                    { name: "Quantity", value: readUint16BE(pdu, 2) },
                    { name: "Byte Count", value: pdu[4] },
                    { name: "Data", value: hexPreview(pdu.slice(5), 128) },
                );
            }
        } else if (baseFunc === 23) {
            // Read/Write Multiple Registers
            if (pdu.length >= 8) {
                fields.push(
                    { name: "Read Starting Address", value: readUint16BE(pdu, 0) },
                    { name: "Read Quantity", value: readUint16BE(pdu, 2) },
                    { name: "Write Starting Address", value: readUint16BE(pdu, 4) },
                    { name: "Write Quantity", value: readUint16BE(pdu, 6) },
                );
                if (pdu.length >= 9) {
                    fields.push(
                        { name: "Write Byte Count", value: pdu[8] },
                        { name: "Write Data", value: hexPreview(pdu.slice(9), 128) },
                    );
                }
            }
        }
    }

    fields.push({ name: "PDU Hex", value: hexPreview(pdu, 128) });

    return { protocol: "Modbus/TCP", fields };
}

module.exports = { decodeModbusFromBytes };