const { createTable, dotField } = require("./shared");

function renderMysqlTable(transportData) {
  const mysqlData = transportData['MySQL'];
  if (!mysqlData) return;
  const mysqlRows = [
    { name: 'Type', value: mysqlData['Type'] || '—' },
    { name: 'Sequence', value: mysqlData['Sequence'] ?? '—' },
  ];
  if (mysqlData['Type'] === 'Server Greeting') {
    mysqlRows.push(
      { name: 'Protocol Version', value: dotField(mysqlData, 'mysql.proto_version', 'Protocol Version') },
      { name: 'Server Version', value: dotField(mysqlData, 'mysql.server_version', 'Server Version') },
    );
  } else if (mysqlData['Type'] === 'Command') {
    mysqlRows.push(
      { name: 'Command', value: mysqlData['Command'] || '—' },
      { name: 'Query', value: mysqlData['Query'] || '—' },
    );
  } else if (mysqlData['Type'] === 'Error') {
    mysqlRows.push(
      { name: 'Error Code', value: dotField(mysqlData, 'mysql.error_code', 'Error Code') },
      { name: 'Error Message', value: dotField(mysqlData, 'mysql.error_msg', 'Error Message') },
    );
  }
  createTable(mysqlRows, ['MySQL Field', 'Value'], 'sidedatatable');
}

module.exports = { renderMysqlTable };
