// Renders HSRP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderHsrpTable(transportData) {
    const hsrpData = transportData['HSRP'];
    if (!hsrpData) return;
    const rows = [
        { name: 'Version', value: dotField(hsrpData, 'hsrp.version', 'Version') },
        { name: 'Op Code', value: dotField(hsrpData, 'hsrp.opcode', 'Op Code') },
        { name: 'State', value: dotField(hsrpData, 'hsrp.state', 'State') },
        { name: 'State Code', value: dotField(hsrpData, 'hsrp.state_code', 'State Code') },
        { name: 'Hello Time (s)', value: dotField(hsrpData, 'hsrp.hello_time', 'Hello Time (s)') },
        { name: 'Hold Time (s)', value: dotField(hsrpData, 'hsrp.hold_time', 'Hold Time (s)') },
        { name: 'Priority', value: dotField(hsrpData, 'hsrp.priority', 'Priority') },
        { name: 'Group', value: dotField(hsrpData, 'hsrp.group', 'Group') },
    ];

    // Authentication (HSRPv1 only)
    const auth = dotField(hsrpData, 'hsrp.auth', 'Authentication', null);
    if (auth !== null) {
        rows.push({ name: 'Authentication', value: auth });
    }

    // Virtual IP
    const virtualIp = dotField(hsrpData, 'hsrp.virtual_ip', 'Virtual IP', null);
    if (virtualIp !== null) {
        rows.push({ name: 'Virtual IP', value: virtualIp });
    }

    // HSRPv2 TLV count
    const tlvs = dotField(hsrpData, 'hsrp.tlvs', 'TLVs', null);
    if (tlvs !== null && Array.isArray(tlvs)) {
        rows.push({ name: 'TLV Count', value: tlvs.length });
    }

    createTable(rows, ['HSRP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderHsrpTable };