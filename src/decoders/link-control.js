// Renders link-control packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderLinkControlTable(packetInfoData) {
  const linkData = packetInfoData['Link Control'];
  if (!linkData) return;

  const detectedProtocolsRaw = linkData['wan.detected'] ?? linkData['Detected Protocols'];
  const detectedProtocols = Array.isArray(detectedProtocolsRaw)
    ? detectedProtocolsRaw.join(', ')
    : detectedProtocolsRaw || '—';
  const layerNamesRaw = linkData['wan.layers'] ?? linkData['Layer Names'];
  const layerNames = Array.isArray(layerNamesRaw)
    ? layerNamesRaw.join(', ')
    : layerNamesRaw || '—';

  const linkRows = [
    { name: 'Primary WAN Protocol', value: dotField(linkData, 'wan.primary', 'Primary WAN Protocol') },
    { name: 'Detected Protocols', value: detectedProtocols },
    { name: 'Layer Names', value: layerNames },
  ];
  if (linkData['PPP Protocol Field']) {
    linkRows.push({ name: 'PPP Protocol Field', value: linkData['PPP Protocol Field'] });
  }
  if (linkData['PPPoE Stage']) {
    linkRows.push({ name: 'PPPoE Stage', value: linkData['PPPoE Stage'] });
  }
  if (linkData['PPPoE Code']) {
    linkRows.push({ name: 'PPPoE Code', value: linkData['PPPoE Code'] });
  }
  if (linkData['PPPoE Session ID']) {
    linkRows.push({ name: 'PPPoE Session ID', value: linkData['PPPoE Session ID'] });
  }
  if (linkData['EtherType']) {
    linkRows.push({ name: 'EtherType', value: linkData['EtherType'] });
  }
  if (linkData['LLDP Chassis ID']) {
    linkRows.push({ name: 'LLDP Chassis ID', value: linkData['LLDP Chassis ID'] });
  }
  if (linkData['LLDP Port ID']) {
    linkRows.push({ name: 'LLDP Port ID', value: linkData['LLDP Port ID'] });
  }
  if (linkData['LLDP TTL']) {
    linkRows.push({ name: 'LLDP TTL', value: linkData['LLDP TTL'] });
  }
  if (linkData['ATM Encapsulation']) {
    linkRows.push({ name: 'ATM Encapsulation', value: linkData['ATM Encapsulation'] });
  }
  createTable(linkRows, ['WAN Field', 'Value'], 'sidedatatable');
}

module.exports = { renderLinkControlTable };
