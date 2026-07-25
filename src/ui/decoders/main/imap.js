// Renders IMAP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderImapTable(transportData) {
  const imapData = transportData['IMAP'];
  if (!imapData) return;
  const imapRows = [{ name: 'Type', value: imapData['Type'] || '—' }];
  if (imapData['Type'] === 'Command') {
    imapRows.push(
      { name: 'Tag', value: imapData['Tag'] || '—' },
      { name: 'Command', value: imapData['Command'] || '—' },
      { name: 'Argument', value: imapData['Argument'] || '—' },
    );
  } else if (imapData['Type'] === 'Response') {
    imapRows.push(
      { name: 'Tag', value: imapData['Tag'] || '—' },
      { name: 'Status', value: imapData['Status'] || '—' },
      { name: 'Message', value: imapData['Message'] || '—' },
    );
  } else {
    imapRows.push(
      { name: 'Status', value: imapData['Status'] || '—' },
      { name: 'Info', value: imapData['Info'] || '—' },
    );
  }
  createTable(imapRows, ['IMAP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderImapTable };
