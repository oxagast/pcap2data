const { createTable, dotField } = require("./shared");

function renderIgmpTable(protocol, transportData) {
  if (protocol !== 'IGMP') return;
  const igmpRows = [
    { name: 'Type', value: transportData['Type'] ?? '—' },
    { name: 'Type Number', value: dotField(transportData, 'igmp.type_num', 'Type Number') },
    { name: 'Version', value: transportData['Version'] ?? '—' },
    { name: 'Group Address', value: dotField(transportData, 'igmp.group_addr', 'Group Address') },
    {
      name: 'Max Response Time (ds)',
      value: dotField(transportData, 'igmp.max_resp_time_ds', 'Max Response Time (ds)'),
    },
  ];
  createTable(igmpRows, ['IGMP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderIgmpTable };
