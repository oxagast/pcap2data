const { createTable, dotField } = require("./shared");

function renderSnmpTable(transportData) {
  const snmpData = transportData['SNMP'];
  if (!snmpData) return;
  const snmpRows = [
    { name: 'Version', value: snmpData['Version'] || '—' },
    { name: 'Community', value: snmpData['Community'] || '—' },
    { name: 'PDU Type', value: dotField(snmpData, 'snmp.pdu_type', 'PDU Type') },
  ];
  createTable(snmpRows, ['SNMP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderSnmpTable };
