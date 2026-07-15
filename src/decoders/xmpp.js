const { createTable, dotField } = require("./shared");

function renderXmppTable(transportData) {
  const xmppData = transportData['XMPP'];
  if (!xmppData) return;
  const xmppRows = [
    { name: 'Stanza Type', value: dotField(xmppData, 'xmpp.stanza', 'Stanza Type') },
    { name: 'From', value: xmppData['From'] || '—' },
    { name: 'To', value: xmppData['To'] || '—' },
  ];
  createTable(xmppRows, ['XMPP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderXmppTable };
