// Renders NFS packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderNfsTable(transportData) {
  const nfsData = transportData['NFS'];
  if (!nfsData) return;
  const nfsRows = [
    { name: 'XID', value: nfsData['XID'] || '—' },
    { name: 'Message Type', value: dotField(nfsData, 'rpc.msg_type', 'Message Type') },
  ];
  if (nfsData['Program']) {
    nfsRows.push(
      { name: 'Program', value: nfsData['Program'] },
      { name: 'Program Version', value: dotField(nfsData, 'rpc.prog_version', 'Program Version') },
      { name: 'Procedure', value: nfsData['Procedure'] || '—' },
      { name: 'RPC Version', value: dotField(nfsData, 'rpc.version', 'RPC Version') },
    );
  }
  if (nfsData['Reply Status']) {
    nfsRows.push({ name: 'Reply Status', value: nfsData['Reply Status'] });
  }
  createTable(nfsRows, ['NFS/RPC Field', 'Value'], 'sidedatatable');
}

module.exports = { renderNfsTable };
