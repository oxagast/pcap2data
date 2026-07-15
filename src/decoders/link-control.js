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
  if (linkData['ATM Encapsulation']) {
    linkRows.push({ name: 'ATM Encapsulation', value: linkData['ATM Encapsulation'] });
  }
  createTable(linkRows, ['WAN Field', 'Value'], 'sidedatatable');
}

module.exports = { renderLinkControlTable };
