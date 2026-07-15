const { createTable, dotField } = require("./shared");

function renderSshTable(transportData) {
  const sshData = transportData['SSH'];
  if (!sshData) return;
  const sshRows = [
    { name: 'Type', value: sshData['Type'] || '—' },
    { name: 'Direction', value: sshData['Direction'] || '—' },
    { name: 'Banner', value: sshData['Banner'] || '—' },
    { name: 'Protocol Version', value: dotField(sshData, 'ssh.protocol_version', 'Protocol Version') },
    { name: 'Software Version', value: dotField(sshData, 'ssh.software_version', 'Software Version') },
    { name: 'Comments', value: sshData['Comments'] || '—' },
    { name: 'Packet Length', value: dotField(sshData, 'ssh.packet_length', 'Packet Length') },
    { name: 'Padding Length', value: dotField(sshData, 'ssh.padding_length', 'Padding Length') },
    { name: 'Message Type', value: dotField(sshData, 'ssh.msg_type', 'Message Type') },
    {
      name: 'Likely Encrypted',
      value:
        (sshData['ssh.likely_encrypted'] ?? sshData['Likely Encrypted']) === undefined
          ? '—'
          : (sshData['ssh.likely_encrypted'] ?? sshData['Likely Encrypted'])
            ? 'Yes'
            : 'No',
    },
  ];
  createTable(sshRows, ['SSH Field', 'Value'], 'sidedatatable');
}

module.exports = { renderSshTable };
