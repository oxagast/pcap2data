// Renders Telnet packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderTelnetTable(transportData) {
  const telnetData = transportData['Telnet'];
  if (!telnetData) return;
  const negotiations = (telnetData['Negotiations'] || []).join(', ') || '—';
  const telnetRows = [
    { name: 'Negotiations', value: negotiations },
    { name: 'Text', value: dotField(telnetData, 'telnet.text', 'Printable Text') },
  ];
  createTable(telnetRows, ['Telnet Field', 'Value'], 'sidedatatable');
}

module.exports = { renderTelnetTable };
