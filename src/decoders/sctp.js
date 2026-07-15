const { createTable, dotField } = require("./shared");

function renderSctpTable(transportData) {
  const sctpData = transportData;
  if (!sctpData) return;

  // Only render when SCTP-specific evidence exists; Source/Destination port
  // keys are shared by TCP/UDP and would otherwise produce false SCTP tables.
  const hasSctpData =
    sctpData['sctp.vtag'] !== undefined ||
    sctpData['sctp.chunk.count'] !== undefined ||
    sctpData['SIGTRAN'] !== undefined ||
    sctpData['transport.proto'] === 'SCTP';
  if (!hasSctpData) return;

  const sctpRows = [
    { name: 'Source Port', value: sctpData['sctp.src.port'] ?? '—' },
    { name: 'Destination Port', value: sctpData['sctp.dst.port'] ?? '—' },
    { name: 'Verification Tag', value: sctpData['sctp.vtag'] ?? '—' },
    { name: 'Checksum', value: sctpData['sctp.chksum'] ?? '—' },
    { name: 'Chunk Count', value: sctpData['sctp.chunk.count'] ?? '—' },
    { name: 'Wire Length', value: sctpData['wire.len'] ?? '—' },
  ];

  const sigtranData = sctpData['SIGTRAN'];
  if (sigtranData) {
    sctpRows.push(
      { name: 'SIGTRAN Protocol', value: sigtranData['sigtran.proto'] || '—' },
      { name: 'Likely Signaling', value: sigtranData['sigtran.signaling'] || '—' },
    );
    if (sigtranData['sigtran.message.class_name'] !== undefined || sigtranData['sigtran.message.class'] !== undefined) {
      sctpRows.push({ name: 'Message Class', value: sigtranData['sigtran.message.class_name'] ?? sigtranData['sigtran.message.class'] });
    }
    if (sigtranData['sigtran.message.type'] !== undefined) {
      sctpRows.push({ name: 'Message Type', value: sigtranData['sigtran.message.type'] });
    }
    if (sigtranData['sigtran.length'] !== undefined) {
      sctpRows.push({ name: 'Message Length', value: sigtranData['sigtran.length'] });
    }
    if (sigtranData['sigtran.payload.len'] !== undefined) {
      sctpRows.push({ name: 'Payload Length', value: sigtranData['sigtran.payload.len'] });
    }
  }

  createTable(sctpRows, ['SCTP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderSctpTable };
