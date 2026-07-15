const { createTable, dotField } = require("./shared");

function renderSmbTable(transportData) {
  const smbData = transportData['SMB'];
  if (!smbData) return;
  const smbRows = [
    { name: 'Version', value: smbData['Version'] || '—' },
    { name: 'Command', value: smbData['Command'] || '—' },
    { name: 'Status', value: smbData['Status'] || '—' },
    { name: 'Is Response', value: (smbData['smb.is_response'] ?? smbData['Is Response']) ? 'Yes' : 'No' },
  ];
  [
    ['NTLMSSP', 'NTLMSSP'],
    ['Username', 'Username'],
    ['Domain', 'Domain'],
    ['Workstation', 'Workstation'],
    ['Target Name', 'Target Name'],
    ['LM Response', 'LM Response'],
    ['NTLM Response', 'NTLM Response'],
  ].forEach(([label, fieldName]) => {
    if (typeof smbData[fieldName] === 'string' && smbData[fieldName]) {
      smbRows.push({ name: label, value: smbData[fieldName] });
    }
  });
  createTable(smbRows, ['SMB Field', 'Value'], 'sidedatatable');
}

module.exports = { renderSmbTable };
