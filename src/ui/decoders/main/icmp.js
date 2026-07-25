// Renders ICMP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderIcmpTable(protocol, transportData) {
  if (protocol !== 'ICMP') return;
  const icmpRows = [
    { name: 'Type', value: transportData['Type'] ?? '—' },
    { name: 'Code', value: transportData['Code'] ?? '—' },
    { name: 'ID', value: transportData['ID'] ?? '—' },
    { name: 'Sequence', value: transportData['Sequence'] ?? '—' },
  ];
  createTable(icmpRows, ['ICMP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderIcmpTable };
