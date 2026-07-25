// Renders SMTP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderSmtpTable(transportData) {
  const smtpData = transportData['SMTP'];
  if (!smtpData) return;
  const smtpRows = [{ name: 'Type', value: smtpData['Type'] || '—' }];
  if (smtpData['Type'] === 'Command') {
    smtpRows.push(
      { name: 'Command', value: smtpData['Command'] || '—' },
      { name: 'Argument', value: smtpData['Argument'] || '—' },
    );
  } else {
    smtpRows.push(
      { name: 'Status Code', value: dotField(smtpData, 'smtp.status_code', 'Status Code') },
      { name: 'Message', value: smtpData['Message'] || '—' },
    );
  }
  createTable(smtpRows, ['SMTP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderSmtpTable };
