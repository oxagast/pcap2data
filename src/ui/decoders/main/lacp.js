// Renders LACP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderLacpTable(transportData) {
    // For link-layer protocols, transportData IS the decoded section
    // (e.g. packetInfo['LACP'] = lacpSection), not a wrapper. The section
    // key may also be present for backward compatibility.
    const lacpData = transportData && typeof transportData['LACP'] === 'object'
        ? transportData['LACP']
        : transportData;
    if (!lacpData || typeof lacpData !== 'object' || !('lacp.subtype' in lacpData || 'Subtype' in lacpData)) return;
    const rows = [
        { name: 'Subtype', value: dotField(lacpData, 'lacp.subtype', 'Subtype') },
        { name: 'Version', value: dotField(lacpData, 'lacp.version', 'Version') },
    ];

    // Actor fields
    const actorType = dotField(lacpData, 'Actor.tlv_type', 'Actor TLV Type', null);
    if (actorType !== null) {
        rows.push(
            { name: 'Actor TLV Type', value: actorType },
            { name: 'Actor TLV Length', value: dotField(lacpData, 'Actor.tlv_len', 'Actor TLV Length') },
            { name: 'Actor System Priority', value: dotField(lacpData, 'Actor.sys_priority', 'Actor System Priority') },
            { name: 'Actor System', value: dotField(lacpData, 'Actor.system', 'Actor System') },
            { name: 'Actor Key', value: dotField(lacpData, 'Actor.key', 'Actor Key') },
            { name: 'Actor Port Priority', value: dotField(lacpData, 'Actor.port_priority', 'Actor Port Priority') },
            { name: 'Actor Port', value: dotField(lacpData, 'Actor.port', 'Actor Port') },
            { name: 'Actor State', value: dotField(lacpData, 'Actor.state', 'Actor State') },
            { name: 'Actor State Code', value: dotField(lacpData, 'Actor.state_code', 'Actor State Code') },
        );
    }

    // Partner fields
    const partnerType = dotField(lacpData, 'Partner.tlv_type', 'Partner TLV Type', null);
    if (partnerType !== null) {
        rows.push(
            { name: 'Partner TLV Type', value: partnerType },
            { name: 'Partner TLV Length', value: dotField(lacpData, 'Partner.tlv_len', 'Partner TLV Length') },
            { name: 'Partner System Priority', value: dotField(lacpData, 'Partner.sys_priority', 'Partner System Priority') },
            { name: 'Partner System', value: dotField(lacpData, 'Partner.system', 'Partner System') },
            { name: 'Partner Key', value: dotField(lacpData, 'Partner.key', 'Partner Key') },
            { name: 'Partner Port Priority', value: dotField(lacpData, 'Partner.port_priority', 'Partner Port Priority') },
            { name: 'Partner Port', value: dotField(lacpData, 'Partner.port', 'Partner Port') },
            { name: 'Partner State', value: dotField(lacpData, 'Partner.state', 'Partner State') },
            { name: 'Partner State Code', value: dotField(lacpData, 'Partner.state_code', 'Partner State Code') },
        );
    }

    // Collector fields
    const collectorType = dotField(lacpData, 'lacp.collector_tlv_type', 'Collector TLV Type', null);
    if (collectorType !== null) {
        rows.push(
            { name: 'Collector TLV Type', value: collectorType },
            { name: 'Collector TLV Length', value: dotField(lacpData, 'lacp.collector_tlv_len', 'Collector TLV Length') },
            { name: 'Collector Max Delay', value: dotField(lacpData, 'lacp.collector_max_delay', 'Collector Max Delay') },
        );
    }

    createTable(rows, ['LACP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderLacpTable };