const { createTable, dotField } = require("./shared");

function renderTftpTable(transportData) {
  const tftpData = transportData['TFTP'];
  if (!tftpData) return;
  const tftpRows = [{ name: 'Opcode', value: tftpData['Opcode'] || '—' }];
  if (tftpData['Filename'] !== undefined) {
    tftpRows.push(
      { name: 'Filename', value: tftpData['Filename'] || '—' },
      { name: 'Mode', value: tftpData['Mode'] || '—' },
    );
  }
  if (tftpData['tftp.block'] !== undefined || tftpData['Block Number'] !== undefined) {
    tftpRows.push({ name: 'Block Number', value: dotField(tftpData, 'tftp.block', 'Block Number') });
  }
  if (tftpData['tftp.data_len'] !== undefined || tftpData['Data Length'] !== undefined) {
    tftpRows.push({ name: 'Data Length', value: dotField(tftpData, 'tftp.data_len', 'Data Length') });
  }
  if (tftpData['tftp.error_code'] !== undefined || tftpData['Error Code'] !== undefined) {
    tftpRows.push(
      { name: 'Error Code', value: dotField(tftpData, 'tftp.error_code', 'Error Code') },
      { name: 'Error Description', value: dotField(tftpData, 'tftp.error_desc', 'Error Description') },
      { name: 'Error Message', value: dotField(tftpData, 'tftp.error_msg', 'Error Message') },
    );
  }
  createTable(tftpRows, ['TFTP Field', 'Value'], 'sidedatatable');
}

module.exports = { renderTftpTable };
