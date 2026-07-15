const { createTable, dotField } = require("./shared");

function renderPop3Table(transportData) {
  const pop3Data = transportData['POP3'];
  if (!pop3Data) return;
  const pop3Rows = [{ name: 'Type', value: pop3Data['Type'] || '—' }];
  if (pop3Data['Type'] === 'Command') {
    pop3Rows.push(
      { name: 'Command', value: pop3Data['Command'] || '—' },
      { name: 'Argument', value: pop3Data['Argument'] || '—' },
    );
  } else {
    pop3Rows.push(
      { name: 'Status', value: pop3Data['Status'] || '—' },
      { name: 'Message', value: pop3Data['Message'] || '—' },
    );
  }
  createTable(pop3Rows, ['POP3 Field', 'Value'], 'sidedatatable');
}

module.exports = { renderPop3Table };
