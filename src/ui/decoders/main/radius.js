// Renders RADIUS packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderRadiusTable(transportData) {
  const radiusData = transportData['RADIUS'];
  if (!radiusData) return;
  const radiusRows = [
    { name: 'Code', value: radiusData['Code'] || '—' },
    { name: 'Identifier', value: radiusData['Identifier'] ?? '—' },
    { name: 'Length', value: radiusData['Length'] ?? '—' },
  ];
  const attrs = radiusData['Attributes'] || [];
  attrs.forEach((attr) => {
    radiusRows.push({ name: attr['Type'] || 'Attr', value: attr['Value'] || '—' });
  });
  createTable(radiusRows, ['RADIUS Field', 'Value'], 'sidedatatable');
}

module.exports = { renderRadiusTable };
