// Renders SIP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderSipTable(transportData) {
  const sipData = transportData['SIP'];
  if (!sipData) return;
  const sipRows = [
    { name: 'Type', value: sipData['Type'] || '—' },
    {
      name: sipData['Type'] === 'Request' ? 'Method' : 'Status Code',
      value: sipData['Method'] || dotField(sipData, 'sip.status_code', 'Status Code'),
    },
    { name: 'From', value: sipData['From'] || '—' },
    { name: 'To', value: sipData['To'] || '—' },
    { name: 'Call-ID', value: sipData['Call-ID'] || '—' },
  ];
  if (sipData['Authorization']) {
    sipRows.push({ name: 'Authorization', value: sipData['Authorization'] || '—' });
  }
  if (sipData['Proxy-Authorization']) {
    sipRows.push({ name: 'Proxy-Authorization', value: sipData['Proxy-Authorization'] || '—' });
  }
  createTable(sipRows, ['SIP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderSipTable };
