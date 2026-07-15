const { createTable, dotField } = require("./shared");

function renderKerberosTable(transportData) {
  const krbData = transportData['Kerberos'];
  if (!krbData) return;
  const krbRows = [
    { name: 'Message Type', value: dotField(krbData, 'krb5.msg_type', 'Message Type') },
  ];
  if (krbData['Protocol Version'] !== undefined) {
    krbRows.push({ name: 'Protocol Version', value: krbData['Protocol Version'] });
  }
  createTable(krbRows, ['Kerberos Field', 'Value'], 'sidedatatable');
}

module.exports = { renderKerberosTable };
