// Renders CDP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderCdpTable(transportData) {
    const cdpData = transportData['CDP'];
    if (!cdpData) return;
    const rows = [
        { name: 'Version', value: dotField(cdpData, 'cdp.version', 'Version') },
        { name: 'TTL (s)', value: dotField(cdpData, 'cdp.ttl', 'TTL (s)') },
        { name: 'Checksum', value: dotField(cdpData, 'cdp.chksum', 'Checksum') },
    ];

    // Device ID
    const deviceId = dotField(cdpData, 'cdp.device_id', 'Device ID', null);
    if (deviceId !== null) {
        rows.push({ name: 'Device ID', value: deviceId });
    }

    // Port ID
    const portId = dotField(cdpData, 'cdp.port_id', 'Port ID', null);
    if (portId !== null) {
        rows.push({ name: 'Port ID', value: portId });
    }

    // Capabilities
    const capabilities = dotField(cdpData, 'cdp.capabilities', 'Capabilities', null);
    if (capabilities !== null) {
        rows.push({ name: 'Capabilities', value: capabilities });
    }

    // Software Version
    const swVersion = dotField(cdpData, 'cdp.software_version', 'Software Version', null);
    if (swVersion !== null) {
        rows.push({ name: 'Software Version', value: swVersion });
    }

    // Platform
    const platform = dotField(cdpData, 'cdp.platform', 'Platform', null);
    if (platform !== null) {
        rows.push({ name: 'Platform', value: platform });
    }

    // IP Addresses (list)
    const addresses = dotField(cdpData, 'cdp.addresses', 'Addresses', null);
    if (addresses !== null) {
        rows.push({ name: 'Addresses', value: Array.isArray(addresses) ? addresses.join(', ') : addresses });
    }

    // Management Address (list)
    const mgmtAddress = dotField(cdpData, 'cdp.mgmt_address', 'Management Address', null);
    if (mgmtAddress !== null) {
        rows.push({ name: 'Management Address', value: Array.isArray(mgmtAddress) ? mgmtAddress.join(', ') : mgmtAddress });
    }

    // Native VLAN
    const nativeVlan = dotField(cdpData, 'cdp.native_vlan', 'Native VLAN', null);
    if (nativeVlan !== null) {
        rows.push({ name: 'Native VLAN', value: nativeVlan });
    }

    // VTP Management Domain
    const vtpDomain = dotField(cdpData, 'cdp.vtp_domain', 'VTP Management Domain', null);
    if (vtpDomain !== null) {
        rows.push({ name: 'VTP Management Domain', value: vtpDomain });
    }

    // MTU
    const mtu = dotField(cdpData, 'cdp.mtu', 'MTU', null);
    if (mtu !== null) {
        rows.push({ name: 'MTU', value: mtu });
    }

    // System Name
    const systemName = dotField(cdpData, 'cdp.system_name', 'System Name', null);
    if (systemName !== null) {
        rows.push({ name: 'System Name', value: systemName });
    }

    // Location
    const location = dotField(cdpData, 'cdp.location', 'Location', null);
    if (location !== null) {
        rows.push({ name: 'Location', value: location });
    }

    // TLV count
    const tlvs = dotField(cdpData, 'cdp.tlvs', 'TLVs', null);
    if (tlvs !== null && Array.isArray(tlvs)) {
        rows.push({ name: 'TLV Count', value: tlvs.length });
    }

    createTable(rows, ['CDP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderCdpTable };