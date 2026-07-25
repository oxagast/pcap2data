// Renders DHCP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderDhcpTable(transportData) {
  const dhcpData = transportData['DHCP'];
  if (!dhcpData) return;
  const dhcpRows = [
    { name: 'Message Type', value: dotField(dhcpData, 'dhcp.msg_type', 'Message Type') },
    { name: 'Transaction ID', value: dhcpData['Transaction ID'] || '—' },
    { name: 'Client IP', value: dhcpData['Client IP'] || '—' },
    { name: 'Your IP', value: dhcpData['Your IP'] || '—' },
    { name: 'Server IP', value: dhcpData['Server IP'] || '—' },
  ];
  createTable(dhcpRows, ['DHCP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderDhcpTable };
