// Renders RTSP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderRtspTable(transportData) {
  const rtspData = transportData['RTSP'];
  if (!rtspData) return;
  const rtspRows = [{ name: 'Type', value: rtspData['Type'] || '—' }];
  if (rtspData['Type'] === 'Request') {
    rtspRows.push(
      { name: 'Method', value: rtspData['Method'] || '—' },
      { name: 'URL', value: rtspData['URL'] || '—' },
      { name: 'RTSP Version', value: dotField(rtspData, 'rtsp.version', 'RTSP Version') },
      { name: 'CSeq', value: rtspData['CSeq'] || '—' },
      { name: 'Session', value: rtspData['Session'] || '—' },
      { name: 'Transport', value: rtspData['Transport'] || '—' },
    );
  } else {
    rtspRows.push(
      { name: 'Status Code', value: dotField(rtspData, 'rtsp.status_code', 'Status Code') },
      { name: 'Status Message', value: dotField(rtspData, 'rtsp.status_msg', 'Status Message') },
      { name: 'RTSP Version', value: dotField(rtspData, 'rtsp.version', 'RTSP Version') },
      { name: 'CSeq', value: rtspData['CSeq'] || '—' },
      { name: 'Content-Type', value: rtspData['Content-Type'] || '—' },
      { name: 'Content-Length', value: rtspData['Content-Length'] || '—' },
    );
  }
  createTable(rtspRows, ['RTSP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderRtspTable };
