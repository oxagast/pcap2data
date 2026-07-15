const { createTable, dotField } = require("./shared");

function renderDnsTable(transportData) {
  const dnsData = transportData['DNS'];
  if (!dnsData) return;
  const dnsRows = [
    { name: 'Transaction ID', value: dnsData['Transaction ID'] },
    {
      name: 'Type',
      value: dnsData['Is Response'] ? 'Response' : 'Query',
    },
    {
      name: 'Query Names',
      value: (dnsData['Query Names'] || []).join(', ') || '—',
    },
    {
      name: 'Answer IPs',
      value: (dnsData['Answer IPs'] || []).join(', ') || '—',
    },
    { name: 'Questions', value: dnsData['Question Count'] },
    { name: 'Answers', value: dnsData['Answer Count'] },
  ];
  createTable(dnsRows, ['DNS Field', 'Value'], 'sidedatatable');
}

module.exports = { renderDnsTable };
