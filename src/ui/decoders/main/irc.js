// Renders IRC packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderIrcTable(transportData) {
  const ircData = transportData['IRC'];
  if (!ircData) return;
  const ircRows = [
    { name: 'Command', value: ircData['Command'] || '—' },
    { name: 'Prefix', value: ircData['Prefix'] || '—' },
    { name: 'Parameters', value: ircData['Parameters'] || '—' },
    { name: 'Message Count', value: dotField(ircData, 'irc.msg_count', 'Message Count') },
  ];
  createTable(ircRows, ['IRC Field', 'Value'], 'sidedatatable');
}

module.exports = { renderIrcTable };
