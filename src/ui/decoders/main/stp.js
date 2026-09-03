// Renders STP (IEEE 802.1D Spanning Tree Protocol) packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderStpTable(transportData) {
    // For link-layer protocols, transportData IS the decoded section
    // (e.g. packetInfo['STP'] = stpSection), not a wrapper. The section
    // key may also be present for backward compatibility.
    const stpData = transportData && typeof transportData['STP'] === 'object'
        ? transportData['STP']
        : transportData;
    if (!stpData || typeof stpData !== 'object' || !('stp.bpdu_type' in stpData || 'BPDU Type' in stpData)) return;

    const rows = [
        { name: 'Protocol Identifier', value: dotField(stpData, 'stp.proto_id', 'Protocol Identifier') },
        { name: 'Protocol Version', value: dotField(stpData, 'stp.version', 'Protocol Version') },
        { name: 'BPDU Type', value: dotField(stpData, 'stp.bpdu_type', 'BPDU Type') },
        { name: 'BPDU Type Code', value: dotField(stpData, 'stp.bpdu_type_code', 'BPDU Type Code') },
    ];

    // TCN BPDUs have no body — return after the header fields
    const bpduType = dotField(stpData, 'stp.bpdu_type', 'BPDU Type', null);
    const isTcn = bpduType && bpduType.includes('Topology Change Notification');
    if (isTcn) {
        createTable(rows, ['STP Field', 'Value'], 'sidedatatable');
        return;
    }

    // Flags
    const flags = dotField(stpData, 'stp.flags', 'Flags', null);
    if (flags !== null) {
        rows.push(
            { name: 'Flags', value: flags },
            { name: 'Flags Code', value: dotField(stpData, 'stp.flags_code', 'Flags Code') },
        );
    }

    // Root Bridge
    rows.push(
        { name: 'Root Bridge ID', value: dotField(stpData, 'stp.root_bridge_id', 'Root Bridge ID') },
        { name: 'Root Priority', value: dotField(stpData, 'stp.root_priority', 'Root Priority') },
        { name: 'Root MAC', value: dotField(stpData, 'stp.root_mac', 'Root MAC') },
        { name: 'Root Path Cost', value: dotField(stpData, 'stp.root_path_cost', 'Root Path Cost') },
    );

    // Bridge
    rows.push(
        { name: 'Bridge ID', value: dotField(stpData, 'stp.bridge_id', 'Bridge ID') },
        { name: 'Bridge Priority', value: dotField(stpData, 'stp.bridge_priority', 'Bridge Priority') },
        { name: 'Bridge MAC', value: dotField(stpData, 'stp.bridge_mac', 'Bridge MAC') },
    );

    // Port + Timers
    rows.push(
        { name: 'Port ID', value: dotField(stpData, 'stp.port_id', 'Port ID') },
        { name: 'Message Age', value: dotField(stpData, 'stp.message_age', 'Message Age') },
        { name: 'Max Age', value: dotField(stpData, 'stp.max_age', 'Max Age') },
        { name: 'Hello Time', value: dotField(stpData, 'stp.hello_time', 'Hello Time') },
        { name: 'Forward Delay', value: dotField(stpData, 'stp.forward_delay', 'Forward Delay') },
    );

    // Wire length
    const wireLen = dotField(stpData, 'wire.len', 'Wire Length', null);
    if (wireLen !== null) {
        rows.push({ name: 'Wire Length', value: wireLen });
    }

    // Frame hex preview
    const frameHex = dotField(stpData, 'stp.frame_hex', 'Frame Hex', null);
    if (frameHex !== null) {
        rows.push({ name: 'Frame Hex (first 64B)', value: frameHex });
    }

    createTable(rows, ['STP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderStpTable };