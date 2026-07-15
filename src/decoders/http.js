const { createTable, dotField } = require("./shared");

function renderHttpTable(transportData) {
  const httpData = transportData['HTTP'];
  if (!httpData) return;
  const httpRows = [{ name: 'Type', value: httpData['Type'] || '—' }];
  if (httpData['Type'] === 'Request') {
    httpRows.push(
      { name: 'Method', value: httpData['Method'] || '—' },
      { name: 'URL', value: httpData['URL'] || '—' },
      { name: 'HTTP Version', value: dotField(httpData, 'http.version', 'HTTP Version') },
      { name: 'Host', value: httpData['host'] || '—' },
      { name: 'User-Agent', value: httpData['User-Agent'] || '—' },
      { name: 'Content-Type', value: httpData['Content-Type'] || '—' },
      { name: 'Content-Length', value: httpData['Content-Length'] || '—' },
      { name: 'Referer', value: httpData['Referer'] || '—' },
      { name: 'Accept', value: httpData['Accept'] || '—' },
      { name: 'Accept-Encoding', value: httpData['Accept-Encoding'] || '—' },
      { name: 'Connection', value: httpData['Connection'] || '—' },
    );
  } else {
    httpRows.push(
      { name: 'Status Code', value: dotField(httpData, 'http.status_code', 'Status Code') },
      { name: 'Status Message', value: dotField(httpData, 'http.status_msg', 'Status Message') },
      { name: 'HTTP Version', value: dotField(httpData, 'http.version', 'HTTP Version') },
      { name: 'Server', value: httpData['Server'] || '—' },
      { name: 'Content-Type', value: httpData['Content-Type'] || '—' },
      { name: 'Content-Length', value: httpData['Content-Length'] || '—' },
      {
        name: 'Content-Encoding',
        value: httpData['Content-Encoding'] || '—',
      },
      {
        name: 'Transfer-Encoding',
        value: httpData['Transfer-Encoding'] || '—',
      },
      { name: 'Connection', value: httpData['Connection'] || '—' },
      { name: 'Location', value: httpData['Location'] || '—' },
    );
  }
  createTable(httpRows, ['HTTP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderHttpTable };
