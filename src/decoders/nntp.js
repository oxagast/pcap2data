const { createTable, dotField } = require("./shared");

function renderNntpTable(transportData) {
  const nntpData = transportData['NNTP'];
  if (!nntpData) return;
  const nntpRows = [{ name: 'Type', value: nntpData['Type'] || '—' }];
  if (nntpData['Type'] === 'Command') {
    nntpRows.push(
      { name: 'Command', value: nntpData['Command'] || '—' },
      { name: 'Argument', value: nntpData['Argument'] || '—' },
    );
  } else {
    nntpRows.push(
      { name: 'Status Code', value: dotField(nntpData, 'nntp.status_code', 'Status Code') },
      { name: 'Message', value: nntpData['Message'] || '—' },
    );
  }
  createTable(nntpRows, ['NNTP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderNntpTable };
