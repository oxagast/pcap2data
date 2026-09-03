// Renders Modbus/TCP packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderModbusTable(transportData) {
    const modbusData = transportData['Modbus'];
    if (!modbusData) return;
    const rows = [
        { name: 'Type', value: modbusData['Type'] || '—' },
        { name: 'Transaction ID', value: dotField(modbusData, 'modbus.trans_id', 'Transaction ID') },
        { name: 'Protocol ID', value: dotField(modbusData, 'modbus.proto_id', 'Protocol ID') },
        { name: 'Length', value: dotField(modbusData, 'modbus.length', 'Length') },
        { name: 'Unit ID', value: dotField(modbusData, 'modbus.unit_id', 'Unit ID') },
        { name: 'Function Code', value: dotField(modbusData, 'modbus.func_code', 'Function Code') },
        { name: 'Function Name', value: dotField(modbusData, 'modbus.func_name', 'Function Name') },
    ];

    // Read/Write function-specific fields
    const startAddr = dotField(modbusData, 'modbus.start_addr', 'Starting Address', null);
    if (startAddr !== null) {
        rows.push({ name: 'Starting Address', value: startAddr });
    }
    const addr = dotField(modbusData, 'modbus.address', 'Address', null);
    if (addr !== null) {
        rows.push({ name: 'Address', value: addr });
    }
    const quantity = dotField(modbusData, 'modbus.quantity', 'Quantity', null);
    if (quantity !== null) {
        rows.push({ name: 'Quantity', value: quantity });
    }
    const byteCount = dotField(modbusData, 'modbus.byte_count', 'Byte Count', null);
    if (byteCount !== null) {
        rows.push({ name: 'Byte Count', value: byteCount });
    }
    const regValue = dotField(modbusData, 'modbus.reg_value', 'Register Value', null);
    if (regValue !== null) {
        rows.push({ name: 'Register Value', value: regValue });
    }
    const value = dotField(modbusData, 'modbus.value', 'Value', null);
    if (value !== null) {
        rows.push({ name: 'Value', value: value });
    }
    const data = dotField(modbusData, 'modbus.data', 'Data', null);
    if (data !== null) {
        rows.push({ name: 'Data', value: data });
    }

    // Read/Write Multiple Registers (func 23) specific fields
    const readStart = dotField(modbusData, 'modbus.read_start_addr', 'Read Starting Address', null);
    if (readStart !== null) {
        rows.push(
            { name: 'Read Starting Address', value: readStart },
            { name: 'Read Quantity', value: dotField(modbusData, 'modbus.read_quantity', 'Read Quantity') },
            { name: 'Write Starting Address', value: dotField(modbusData, 'modbus.write_start_addr', 'Write Starting Address') },
            { name: 'Write Quantity', value: dotField(modbusData, 'modbus.write_quantity', 'Write Quantity') },
        );
        const writeData = dotField(modbusData, 'modbus.write_data', 'Write Data', null);
        if (writeData !== null) {
            rows.push({ name: 'Write Data', value: writeData });
        }
    }

    // Exception response fields
    const excCode = dotField(modbusData, 'modbus.exception_code', 'Exception Code', null);
    if (excCode !== null) {
        rows.push(
            { name: 'Exception Code', value: excCode },
            { name: 'Exception Name', value: dotField(modbusData, 'modbus.exception_name', 'Exception Name') },
        );
    }

    // Raw PDU hex
    const pduHex = dotField(modbusData, 'modbus.pdu_hex', 'PDU Hex', null);
    if (pduHex !== null) {
        rows.push({ name: 'PDU Hex', value: pduHex });
    }

    createTable(rows, ['Modbus Field', 'Value'], 'sidedatatable');
}

module.exports = { renderModbusTable };