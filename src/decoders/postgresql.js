const { createTable, dotField } = require("./shared");

function renderPostgresqlTable(transportData) {
  const pgData = transportData['PostgreSQL'];
  if (!pgData) return;
  const pgRows = [
    { name: 'Type', value: pgData['Type'] || '—' },
    { name: 'Direction', value: pgData['Direction'] || '—' },
  ];
  if (pgData['pg.proto_version'] || pgData['Protocol Version']) {
    pgRows.push({ name: 'Protocol Version', value: dotField(pgData, 'pg.proto_version', 'Protocol Version') });
  }
  if (pgData['pg.msg_length'] !== undefined || pgData['Message Length'] !== undefined) {
    pgRows.push({ name: 'Message Length', value: dotField(pgData, 'pg.msg_length', 'Message Length') });
  }
  if (pgData['Body']) {
    pgRows.push({ name: 'Body', value: pgData['Body'] });
  }
  createTable(pgRows, ['PostgreSQL Field', 'Value'], 'sidedatatable');
}

module.exports = { renderPostgresqlTable };
