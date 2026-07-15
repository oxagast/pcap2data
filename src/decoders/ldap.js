// Renders LDAP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderLdapTable(transportData) {
  const ldapData = transportData['LDAP'];
  if (!ldapData) return;
  const ldapRows = [
    { name: 'Message ID', value: dotField(ldapData, 'ldap.msg_id', 'Message ID') },
    { name: 'Operation', value: ldapData['Operation'] || '—' },
  ];
  createTable(ldapRows, ['LDAP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderLdapTable };
