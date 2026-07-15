const { createTable, dotField } = require("./shared");

function renderFtpTable(transportData) {
  const ftpData = transportData['FTP'];
  if (!ftpData) return;
  const ftpRows = [{ name: 'Type', value: ftpData['Type'] || '—' }];
  if (ftpData['Type'] === 'Command') {
    ftpRows.push(
      { name: 'Command', value: ftpData['Command'] || '—' },
      { name: 'Argument', value: ftpData['Argument'] || '—' },
    );
  } else {
    ftpRows.push(
      { name: 'Status Code', value: dotField(ftpData, 'ftp.status_code', 'Status Code') },
      { name: 'Message', value: ftpData['Message'] || '—' },
    );
  }
  createTable(ftpRows, ['FTP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderFtpTable };
