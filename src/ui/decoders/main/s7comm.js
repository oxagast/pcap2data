// Renders S7comm packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderS7commTable(transportData) {
    const s7Data = transportData['S7comm'];
    if (!s7Data) return;
    const rows = [
        { name: 'Type', value: dotField(s7Data, 's7comm.type', 'Type') },
        { name: 'TPKT Version', value: dotField(s7Data, 's7comm.tpkt_version', 'TPKT Version') },
        { name: 'TPKT Length', value: dotField(s7Data, 's7comm.tpkt_length', 'TPKT Length') },
        { name: 'COTP Length', value: dotField(s7Data, 's7comm.cotp_length', 'COTP Length') },
        { name: 'COTP Type', value: dotField(s7Data, 's7comm.cotp_type', 'COTP Type') },
        { name: 'COTP Type Name', value: dotField(s7Data, 's7comm.cotp_type_name', 'COTP Type Name') },
    ];

    // S7comm protocol header fields (present for data messages)
    const protoId = dotField(s7Data, 's7comm.proto_id', 'Protocol ID', null);
    if (protoId !== null) {
        rows.push(
            { name: 'Protocol ID', value: protoId },
            { name: 'ROSCTR', value: dotField(s7Data, 's7comm.rosctr', 'ROSCTR') },
            { name: 'Message Type', value: dotField(s7Data, 's7comm.msg_type', 'Message Type') },
            { name: 'Redundancy', value: dotField(s7Data, 's7comm.redundancy', 'Redundancy') },
            { name: 'PDU Reference', value: dotField(s7Data, 's7comm.pdu_ref', 'PDU Reference') },
        );
    }

    // Parameter and data length fields
    const paramLen = dotField(s7Data, 's7comm.param_len', 'Parameter Length', null);
    if (paramLen !== null) {
        rows.push(
            { name: 'Parameter Length', value: paramLen },
            { name: 'Data Length', value: dotField(s7Data, 's7comm.data_len', 'Data Length') },
        );
    }

    // Parameter function
    const paramFunc = dotField(s7Data, 's7comm.param_func', 'Parameter Function', null);
    if (paramFunc !== null) {
        rows.push({ name: 'Parameter Function', value: paramFunc });
    }

    // Setup Communication specific fields
    const amqCaller = dotField(s7Data, 's7comm.max_amq_caller', 'Max AMQ Caller', null);
    if (amqCaller !== null) {
        rows.push(
            { name: 'Max AMQ Caller', value: amqCaller },
            { name: 'Max AMQ Called', value: dotField(s7Data, 's7comm.max_amq_called', 'Max AMQ Called') },
            { name: 'Negotiated PDU Size', value: dotField(s7Data, 's7comm.pdu_size', 'Negotiated PDU Size') },
        );
    }

    // Error fields (Ack-Data with errors)
    const errorClass = dotField(s7Data, 's7comm.error_class', 'Error Class', null);
    if (errorClass !== null) {
        rows.push(
            { name: 'Error Class', value: errorClass },
            { name: 'Error Code', value: dotField(s7Data, 's7comm.error_code', 'Error Code') },
            { name: 'Error Name', value: dotField(s7Data, 's7comm.error_name', 'Error Name') },
        );
    }

    // Raw frame hex
    const frameHex = dotField(s7Data, 's7comm.frame_hex', 'Frame Hex', null);
    if (frameHex !== null) {
        rows.push({ name: 'Frame Hex', value: frameHex });
    }

    createTable(rows, ['S7comm Field', 'Value'], 'sidedatatable');
}

module.exports = { renderS7commTable };