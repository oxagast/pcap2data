// DNP3 Conv decoder: parses DNP3 (Distributed Network Protocol 3) link-layer
// frames as used in SCADA/ICS environments over TCP/UDP port 20000.
// Identifies messages by the 0x0564 start-byte sync and parses the link-layer
// header plus application-layer function code and object header.

const DNP3_LINK_FUNCTIONS = {
    0: "Reset Link States",
    1: "Reset User Process",
    2: "Test Link States",
    3: "User Data",
    4: "Unconfirmed User Data",
    9: "Request Link Status",
    10: "Response Link Status",
    11: "Ack (Not Positive/Positive)",
};

const DNP3_APP_FUNCTIONS = {
    0: "Confirm",
    1: "Read",
    2: "Write",
    3: "Select",
    4: "Operate",
    5: "Direct Operate",
    6: "Direct Operate No Ack",
    7: "Immediate Freeze",
    8: "Immediate Freeze No Ack",
    9: "Freeze Clear",
    10: "Freeze Clear No Ack",
    11: "Freeze at Time",
    12: "Freeze at Time No Ack",
    13: "Cold Restart",
    14: "Warm Restart",
    15: "Initialize Data",
    16: "Initialize Application",
    17: "Start Application",
    18: "Stop Application",
    19: "Save Configuration",
    20: "Enable Unsolicited",
    21: "Disable Unsolicited",
    22: "Assign Class",
    23: "Delay Measure",
    24: "Record Current Time",
    129: "Response",
    130: "Unsolicited Response",
};

const DNP3_APP_FIR = 0x80;
const DNP3_APP_FIN = 0x40;
const DNP3_APP_CON = 0x20;
const DNP3_APP_UNS = 0x10;
const DNP3_APP_SEQ_MASK = 0x0f;

function readUint16LE(bytes, offset) {
    return bytes[offset] | (bytes[offset + 1] << 8);
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

function decodeDnp3FromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 10) return null;

    // DNP3 frames always start with 0x05 0x64
    if (bytes[0] !== 0x05 || bytes[1] !== 0x64) return null;

    const length = bytes[2];
    const control = bytes[3];
    const dest = readUint16LE(bytes, 4);
    const src = readUint16LE(bytes, 6);

    if (length < 5) return null;

    const dirBit = (control & 0x80) !== 0;
    const prmBit = (control & 0x40) !== 0;
    const linkFunc = (control >> 2) & 0x0f;
    const linkFuncName = DNP3_LINK_FUNCTIONS[linkFunc] || `Unknown (0x${linkFunc.toString(16).padStart(2, "0")})`;
    const fcb = (control & 0x20) !== 0;
    const fcv = (control & 0x10) !== 0;

    const fields = [
        { name: "Start Bytes", value: "0x0564" },
        { name: "Length", value: length },
        { name: "Control", value: `0x${control.toString(16).padStart(2, "0")}` },
        { name: "Direction", value: dirBit ? "Master→Outstation" : "Outstation→Master" },
        { name: "From Primary", value: prmBit },
        { name: "Link Function", value: linkFuncName },
        { name: "FCB", value: fcb },
        { name: "FCV", value: fcv },
        { name: "Destination", value: dest },
        { name: "Source", value: src },
    ];

    // Header CRC at bytes 8-9 (little-endian)
    if (bytes.length >= 12) {
        const headerCrc = readUint16LE(bytes, 8);
        fields.push({ name: "Header CRC", value: `0x${headerCrc.toString(16).padStart(4, "0")}` });
    }

    // Application layer starts at byte 10 (first data block)
    // The first byte is the transport header (FIR/FIN/SEQ),
    // followed by the application control byte and function code.
    const dataStart = 10;
    if (bytes.length > dataStart + 2) {
        const transportHeader = bytes[dataStart];
        const appControl = bytes[dataStart + 1];
        const appFunc = bytes[dataStart + 2];
        const appFuncName = DNP3_APP_FUNCTIONS[appFunc] || `Unknown (0x${appFunc.toString(16).padStart(2, "0")})`;

        fields.push(
            { name: "Transport Header", value: `0x${transportHeader.toString(16).padStart(2, "0")}` },
            { name: "App Control", value: `0x${appControl.toString(16).padStart(2, "0")}` },
            { name: "App Function Code", value: appFunc },
            { name: "App Function Name", value: appFuncName },
            { name: "App FIR", value: (appControl & DNP3_APP_FIR) !== 0 },
            { name: "App FIN", value: (appControl & DNP3_APP_FIN) !== 0 },
            { name: "App Confirm", value: (appControl & DNP3_APP_CON) !== 0 },
            { name: "App Unsolicited", value: (appControl & DNP3_APP_UNS) !== 0 },
            { name: "App Sequence", value: appControl & DNP3_APP_SEQ_MASK },
        );

        // Object header for Read/Write/Response functions
        if (bytes.length > dataStart + 5 && [1, 2, 129, 130].includes(appFunc)) {
            const group = bytes[dataStart + 3];
            const variation = bytes[dataStart + 4];
            const qualifier = bytes[dataStart + 5];
            fields.push(
                { name: "Object Group", value: group },
                { name: "Object Variation", value: variation },
                { name: "Qualifier", value: `0x${qualifier.toString(16).padStart(2, "0")}` },
            );
        }
    }

    fields.push({ name: "Frame Hex", value: hexPreview(bytes) });

    return { protocol: "DNP3", fields };
}

module.exports = { decodeDnp3FromBytes };