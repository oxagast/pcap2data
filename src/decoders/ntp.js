const { createTable, dotField } = require("./shared");

function renderNtpTable(transportData) {
  const ntpData = transportData['NTP'];
  if (!ntpData) return;
  const ntpRows = [
    { name: 'Version', value: ntpData['Version'] ?? '—' },
    { name: 'Mode', value: ntpData['Mode'] || '—' },
    { name: 'Stratum', value: ntpData['Stratum'] ?? '—' },
    { name: 'Reference ID', value: dotField(ntpData, 'ntp.ref_id', 'Reference ID') },
    { name: 'Leap Indicator', value: dotField(ntpData, 'ntp.leap', 'Leap Indicator') },
  ];
  createTable(ntpRows, ['NTP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderNtpTable };
