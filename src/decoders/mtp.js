const { createTable, dotField } = require("./shared");

function renderMtpTable(transportData) {
  const mtpData = transportData['MTP'];
  if (!mtpData) return;
  const mtpRows = [
    { name: 'Protocol', value: mtpData['Protocol'] || '—' },
    { name: 'Command', value: mtpData['Command'] || '—' },
    { name: 'Command ID', value: dotField(mtpData, 'mtp.cmd_id', 'Command ID') },
    { name: 'Length', value: mtpData['Length'] ?? '—' },
  ];
  createTable(mtpRows, ['MTP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderMtpTable };
