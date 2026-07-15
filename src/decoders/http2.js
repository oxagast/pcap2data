// Renders HTTP/2 packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderHttp2Table(transportData) {
  const http2Data = transportData['HTTP2'];
  if (!http2Data) return;
  const http2Rows = [
    { name: 'Frame Type', value: dotField(http2Data, 'http2.frame_type', 'Frame Type') },
    {
      name: 'Connection Preface',
      value: (http2Data['http2.preface'] ?? http2Data['Connection Preface']) ? 'Yes' : 'No',
    },
  ];
  if (http2Data['http2.frame_length'] !== undefined || http2Data['Frame Length'] !== undefined) {
    http2Rows.push(
      { name: 'Frame Length', value: dotField(http2Data, 'http2.frame_length', 'Frame Length') },
      { name: 'Frame Flags', value: dotField(http2Data, 'http2.frame_flags', 'Frame Flags') },
      { name: 'Stream ID', value: dotField(http2Data, 'http2.stream_id', 'Stream ID') },
    );
  }
  createTable(http2Rows, ['HTTP/2 Field', 'Value'], 'sidedatatable');
}

module.exports = { renderHttp2Table };
