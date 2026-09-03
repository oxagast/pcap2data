// Renders DNP3 packet details into the shared sidebar table UI.

const { createTable, dotField } = require("./shared");

function renderDnp3Table(transportData) {
    const dnp3Data = transportData['DNP3'];
    if (!dnp3Data) return;
    const rows = [
        { name: 'Start Bytes', value: dotField(dnp3Data, 'dnp3.start', 'Start Bytes') },
        { name: 'Length', value: dotField(dnp3Data, 'dnp3.length', 'Length') },
        { name: 'Control', value: dotField(dnp3Data, 'dnp3.control', 'Control') },
        { name: 'Direction', value: dotField(dnp3Data, 'dnp3.direction', 'Direction') },
        { name: 'From Primary', value: dotField(dnp3Data, 'dnp3.prm', 'From Primary') },
        { name: 'Link Function', value: dotField(dnp3Data, 'dnp3.link_func', 'Link Function') },
        { name: 'FCB', value: dotField(dnp3Data, 'dnp3.fcb', 'FCB') },
        { name: 'FCV', value: dotField(dnp3Data, 'dnp3.fcv', 'FCV') },
        { name: 'Destination', value: dotField(dnp3Data, 'dnp3.dest', 'Destination') },
        { name: 'Source', value: dotField(dnp3Data, 'dnp3.source', 'Source') },
    ];

    // Header CRC
    const headerCrc = dotField(dnp3Data, 'dnp3.header_crc', 'Header CRC', null);
    if (headerCrc !== null) {
        rows.push(
            { name: 'Header CRC', value: headerCrc },
            { name: 'Header CRC Valid', value: dotField(dnp3Data, 'dnp3.header_crc_valid', 'Header CRC Valid') },
        );
    }

    // Transport header
    const transportHeader = dotField(dnp3Data, 'dnp3.transport_header', 'Transport Header', null);
    if (transportHeader !== null) {
        rows.push({ name: 'Transport Header', value: transportHeader });
    }

    // Application layer fields
    const appControl = dotField(dnp3Data, 'dnp3.app_control', 'App Control', null);
    if (appControl !== null) {
        rows.push(
            { name: 'App Control', value: appControl },
            { name: 'App Function Code', value: dotField(dnp3Data, 'dnp3.app_func_code', 'App Function Code') },
            { name: 'App Function Name', value: dotField(dnp3Data, 'dnp3.app_func_name', 'App Function Name') },
            { name: 'App FIR', value: dotField(dnp3Data, 'dnp3.app_fir', 'App FIR') },
            { name: 'App FIN', value: dotField(dnp3Data, 'dnp3.app_fin', 'App FIN') },
            { name: 'App Confirm', value: dotField(dnp3Data, 'dnp3.app_con', 'App Confirm') },
            { name: 'App Unsolicited', value: dotField(dnp3Data, 'dnp3.app_uns', 'App Unsolicited') },
            { name: 'App Sequence', value: dotField(dnp3Data, 'dnp3.app_seq', 'App Sequence') },
        );
    }

    // Object header fields (for Read/Write/Response)
    const objGroup = dotField(dnp3Data, 'dnp3.obj_group', 'Object Group', null);
    if (objGroup !== null) {
        rows.push(
            { name: 'Object Group', value: objGroup },
            { name: 'Object Variation', value: dotField(dnp3Data, 'dnp3.obj_variation', 'Object Variation') },
            { name: 'Qualifier', value: dotField(dnp3Data, 'dnp3.qualifier', 'Qualifier') },
        );
    }

    // Raw frame hex
    const frameHex = dotField(dnp3Data, 'dnp3.frame_hex', 'Frame Hex', null);
    if (frameHex !== null) {
        rows.push({ name: 'Frame Hex', value: frameHex });
    }

    createTable(rows, ['DNP3 Field', 'Value'], 'sidedatatable');
}

module.exports = { renderDnp3Table };