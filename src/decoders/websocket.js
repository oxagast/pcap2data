const { createTable, dotField } = require("./shared");

function renderWebSocketTable(transportData) {
  const wsData = transportData['WebSocket'];
  if (!wsData) return;
  const wsRows = [{ name: 'Type', value: wsData['Type'] || '—' }];
  if (wsData['Type'] === 'Upgrade') {
    wsRows.push(
      { name: 'Host', value: wsData['host'] || '—' },
      { name: 'Sec-WebSocket-Key', value: wsData['Sec-WebSocket-Key'] || '—' },
      { name: 'Sec-WebSocket-Version', value: wsData['Sec-WebSocket-Version'] || '—' },
    );
  } else {
    wsRows.push(
      { name: 'Opcode', value: wsData['Opcode'] || '—' },
      { name: 'FIN', value: wsData['FIN'] ? 'Yes' : 'No' },
      { name: 'Masked', value: wsData['Masked'] ? 'Yes' : 'No' },
      { name: 'Payload Length', value: dotField(wsData, 'ws.payload_len', 'Payload Length') },
    );
  }
  createTable(wsRows, ['WebSocket Field', 'Value'], 'sidedatatable');
}

module.exports = { renderWebSocketTable };
