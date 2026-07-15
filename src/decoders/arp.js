// Renders ARP/RARP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderArpTable(protocol, transportData) {
  if (protocol !== 'ARP' && protocol !== 'RARP') return;
  const arpRows = [
    { name: 'Operation', value: dotField(transportData, 'arp.op', 'Operation') },
    { name: 'Opcode', value: dotField(transportData, 'arp.opcode', 'Opcode') },
    { name: 'Sender MAC', value: dotField(transportData, 'arp.src.mac', 'Sender MAC') },
    { name: 'Sender IP', value: dotField(transportData, 'arp.src.ip', 'Sender IP') },
    { name: 'Target MAC', value: dotField(transportData, 'arp.dst.mac', 'Target MAC') },
    { name: 'Target IP', value: dotField(transportData, 'arp.dst.ip', 'Target IP') },
    { name: 'Hardware Type', value: dotField(transportData, 'arp.hw.type', 'Hardware Type') },
    { name: 'Protocol Type', value: dotField(transportData, 'arp.proto.type', 'Protocol Type') },
  ];
  createTable(arpRows, [`${protocol} Field`, 'Value'], 'sidedatatable');
}

module.exports = { renderArpTable };
