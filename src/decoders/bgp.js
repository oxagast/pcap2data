// Renders BGP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderBgpTable(transportData) {
  const bgpData = transportData['BGP'];
  if (!bgpData) return;
  const bgpRows = [
    { name: 'Message Type', value: dotField(bgpData, 'bgp.type', 'Message Type') },
    { name: 'Message Length', value: dotField(bgpData, 'bgp.length', 'Message Length') },
  ];
  if (bgpData['BGP Version'] !== undefined) {
    bgpRows.push(
      { name: 'BGP Version', value: bgpData['BGP Version'] },
      { name: 'ASN', value: bgpData['ASN'] ?? '—' },
      { name: 'Hold Time', value: bgpData['Hold Time'] ?? '—' },
      { name: 'Router ID', value: bgpData['Router ID'] || '—' },
    );
  }
  if (bgpData['bgp.error_code'] !== undefined || bgpData['Error Code'] !== undefined) {
    bgpRows.push(
      { name: 'Error Name', value: dotField(bgpData, 'bgp.error_name', 'Error Name') },
      { name: 'Error Code', value: dotField(bgpData, 'bgp.error_code', 'Error Code') },
      { name: 'Error Subcode', value: dotField(bgpData, 'bgp.error_subcode', 'Error Subcode') },
    );
  }
  createTable(bgpRows, ['BGP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderBgpTable };
