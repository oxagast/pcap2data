// SMPP Conv decoder: reads the big-endian SMPP PDU header (command_length,
// command_id, command_status, sequence_number) and reports a recognized
// command name plus the response bit.

const SMPP_COMMAND_MAP = {
    0x00000001: "bind_receiver",
    0x00000002: "bind_transmitter",
    0x00000003: "query_sm",
    0x00000004: "submit_sm",
    0x00000005: "deliver_sm",
    0x00000006: "unbind",
    0x00000009: "bind_transceiver",
    0x00000015: "enquire_link",
    0x00000021: "submit_multi",
    0x00000103: "data_sm",
};

const SMPP_RESPONSE_BIT = 0x80000000;

function decodeSmppFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 16) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const commandLength = view.getUint32(0, false);
    const commandId = view.getUint32(4, false);
    const commandStatus = view.getUint32(8, false);
    const sequenceNumber = view.getUint32(12, false);

    if (commandLength < 16 || commandLength > bytes.length) return null;

    const baseCommandId = commandId & 0x7fffffff;
    const command = SMPP_COMMAND_MAP[baseCommandId];
    if (!command) return null;

    return {
        protocol: "SMPP",
        fields: [
            { name: "Command", value: command },
            { name: "Command ID", value: `0x${commandId.toString(16).padStart(8, "0")}` },
            { name: "Is Response", value: (commandId & SMPP_RESPONSE_BIT) !== 0 ? "Yes" : "No" },
            { name: "Command Status", value: String(commandStatus) },
            { name: "Sequence Number", value: String(sequenceNumber) },
            { name: "Body Length", value: String(commandLength - 16) },
        ],
    };
}

module.exports = { decodeSmppFromBytes };
