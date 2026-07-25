// Renders MQTT packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderMqttTable(transportData) {
  const mqttData = transportData['MQTT'];
  if (!mqttData) return;
  const mqttRows = [
    { name: 'Message Type', value: dotField(mqttData, 'mqtt.msg_type', 'Message Type') },
    { name: 'QoS', value: mqttData['QoS'] ?? '—' },
    { name: 'DUP Flag', value: (mqttData['mqtt.dup'] ?? mqttData['DUP Flag']) ? 'Yes' : 'No' },
    { name: 'Retain Flag', value: (mqttData['mqtt.retain'] ?? mqttData['Retain Flag']) ? 'Yes' : 'No' },
  ];
  if (mqttData['Topic']) {
    mqttRows.push({ name: 'Topic', value: mqttData['Topic'] });
  }
  createTable(mqttRows, ['MQTT Field', 'Value'], 'sidedatatable');
}

module.exports = { renderMqttTable };
