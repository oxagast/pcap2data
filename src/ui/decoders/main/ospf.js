// Renders OSPF packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderOspfTable(protocol, transportData) {
    if (protocol !== 'OSPF') return;
    const rows = [
        { name: 'Version', value: dotField(transportData, 'ospf.version', 'Version') },
        { name: 'Type', value: dotField(transportData, 'ospf.type', 'Type') },
        { name: 'Packet Length', value: dotField(transportData, 'ospf.length', 'Packet Length') },
        { name: 'Router ID', value: dotField(transportData, 'ospf.router_id', 'Router ID') },
        { name: 'Area ID', value: dotField(transportData, 'ospf.area_id', 'Area ID') },
        { name: 'Checksum', value: dotField(transportData, 'ospf.chksum', 'Checksum') },
    ];

    // OSPFv2 authentication
    const authType = dotField(transportData, 'ospf.auth_type', 'Auth Type', null);
    if (authType !== null) {
        rows.push({ name: 'Auth Type', value: authType });
    }

    // Hello-specific fields
    const hello = dotField(transportData, 'ospf.hello_interval', 'Hello Interval (s)', null);
    if (hello !== null) {
        rows.push(
            { name: 'Network Mask', value: dotField(transportData, 'ospf.network_mask', 'Network Mask') },
            { name: 'Hello Interval (s)', value: hello },
            { name: 'Options', value: dotField(transportData, 'ospf.options', 'Options') },
            { name: 'Router Priority', value: dotField(transportData, 'ospf.router_priority', 'Router Priority') },
            { name: 'Dead Interval (s)', value: dotField(transportData, 'ospf.dead_interval', 'Dead Interval (s)') },
            { name: 'Designated Router', value: dotField(transportData, 'ospf.dr', 'Designated Router') },
            { name: 'Backup Designated Router', value: dotField(transportData, 'ospf.bdr', 'Backup Designated Router') },
        );
        const neighborCount = dotField(transportData, 'ospf.neighbor_count', 'Neighbor Count', null);
        if (neighborCount !== null) {
            rows.push({ name: 'Neighbor Count', value: neighborCount });
        }
    }

    // OSPFv3 instance ID
    const instanceId = dotField(transportData, 'ospf.instance_id', 'Instance ID', null);
    if (instanceId !== null) {
        rows.push({ name: 'Instance ID', value: instanceId });
    }

    // Database Description fields
    const ddSeq = dotField(transportData, 'ospf.dd_seq', 'DD Sequence', null);
    if (ddSeq !== null) {
        rows.push(
            { name: 'Interface MTU', value: dotField(transportData, 'ospf.if_mtu', 'Interface MTU') },
            { name: 'DD Flags', value: dotField(transportData, 'ospf.dd_flags', 'DD Flags') },
            { name: 'DD Sequence', value: ddSeq },
        );
    }

    // Link State Update LSA count
    const lsaCount = dotField(transportData, 'ospf.lsa_count', 'LSA Count', null);
    if (lsaCount !== null) {
        rows.push({ name: 'LSA Count', value: lsaCount });
    }

    createTable(rows, ['OSPF Field', 'Value'], 'sidedatatable');
}

module.exports = { renderOspfTable };