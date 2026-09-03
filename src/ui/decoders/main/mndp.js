// Renders MNDP (MikroTik Neighbor Discovery Protocol) packet details into
// the shared sidebar table UI. Mirrors renderCdpTable in cdp.js.

const { createTable, dotField } = require("./shared");

function renderMndpTable(transportData) {
    // For link/transport-layer protocols, transportData IS the decoded
    // section (e.g. packetInfo['MNDP'] = mndpSection), not a wrapper. The
    // section key may also be present for backward compatibility.
    const mndpData = transportData && typeof transportData['MNDP'] === 'object'
        ? transportData['MNDP']
        : transportData;
    if (!mndpData || typeof mndpData !== 'object' || !('mndp.seqno' in mndpData || 'SeqNo' in mndpData)) return;
    const rows = [
        { name: 'SeqNo', value: dotField(mndpData, 'mndp.seqno', 'SeqNo') },
    ];

    // MAC Address
    const mac = dotField(mndpData, 'mndp.mac', 'MAC Address', null);
    if (mac !== null) {
        rows.push({ name: 'MAC Address', value: mac });
    }

    // Identity
    const identity = dotField(mndpData, 'mndp.identity', 'Identity', null);
    if (identity !== null) {
        rows.push({ name: 'Identity', value: identity });
    }

    // Version
    const version = dotField(mndpData, 'mndp.version', 'Version', null);
    if (version !== null) {
        rows.push({ name: 'Version', value: version });
    }

    // Platform
    const platform = dotField(mndpData, 'mndp.platform', 'Platform', null);
    if (platform !== null) {
        rows.push({ name: 'Platform', value: platform });
    }

    // Uptime
    const uptime = dotField(mndpData, 'mndp.uptime', 'Uptime', null);
    if (uptime !== null) {
        rows.push({ name: 'Uptime', value: uptime });
    }

    // Software ID
    const softwareId = dotField(mndpData, 'mndp.software_id', 'Software ID', null);
    if (softwareId !== null) {
        rows.push({ name: 'Software ID', value: softwareId });
    }

    // Board
    const board = dotField(mndpData, 'mndp.board', 'Board', null);
    if (board !== null) {
        rows.push({ name: 'Board', value: board });
    }

    // Unpack
    const unpack = dotField(mndpData, 'mndp.unpack', 'Unpack', null);
    if (unpack !== null) {
        rows.push({ name: 'Unpack', value: unpack });
    }

    // IPv4 Address
    const ipv4 = dotField(mndpData, 'mndp.ipv4_address', 'IPv4 Address', null);
    if (ipv4 !== null) {
        rows.push({ name: 'IPv4 Address', value: ipv4 });
    }

    // IPv6 Address
    const ipv6 = dotField(mndpData, 'mndp.ipv6_address', 'IPv6 Address', null);
    if (ipv6 !== null) {
        rows.push({ name: 'IPv6 Address', value: ipv6 });
    }

    // Interface Name
    const ifaceName = dotField(mndpData, 'mndp.interface_name', 'Interface Name', null);
    if (ifaceName !== null) {
        rows.push({ name: 'Interface Name', value: ifaceName });
    }

    // TLV count
    const tlvs = dotField(mndpData, 'mndp.tlvs', 'TLVs', null);
    if (tlvs !== null && Array.isArray(tlvs)) {
        rows.push({ name: 'TLV Count', value: tlvs.length });
    }

    createTable(rows, ['MNDP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderMndpTable };