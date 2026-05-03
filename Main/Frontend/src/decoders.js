// Protocol decoder render functions for the info panel side tables.
// Each function reads the relevant sub-object from transportData and appends
// a table to the "sidedatatable" container (or no-ops when the data is absent).

// Reusable element pools to reduce garbage collection
const elementPool = {
  table: null,
  tr: null,
  th: null,
  td: null,
  reset() {
    this.table = null;
    this.tr = null;
    this.th = null;
    this.td = null;
  }
};

function createTable(data, headers, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  // Use DocumentFragment for batched DOM insertion
  const fragment = document.createDocumentFragment();

  const table = document.createElement('table');
  const headerRow = document.createElement('tr');
  for (let i = 0; i < headers.length; i++) {
    const th = document.createElement('th');
    th.textContent = headers[i];
    headerRow.appendChild(th);
  }
  table.appendChild(headerRow);

  // Build all rows first, then append once
  for (let i = 0; i < data.length; i++) {
    const item = data[i];
    const row = document.createElement('tr');
    const values = Object.values(item);
    for (let j = 0; j < values.length; j++) {
      const td = document.createElement('td');
      td.textContent = values[j];
      row.appendChild(td);
    }
    table.appendChild(row);
  }

  fragment.appendChild(table);
  container.appendChild(fragment);
}

// Optimized batch table creation for multiple tables
function createTablesBatch(tablesData, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const fragment = document.createDocumentFragment();

  for (const tableData of tablesData) {
    const table = document.createElement('table');
    const headerRow = document.createElement('tr');
    for (let i = 0; i < tableData.headers.length; i++) {
      const th = document.createElement('th');
      th.textContent = tableData.headers[i];
      headerRow.appendChild(th);
    }
    table.appendChild(headerRow);

    for (let i = 0; i < tableData.rows.length; i++) {
      const item = tableData.rows[i];
      const row = document.createElement('tr');
      const values = Object.values(item);
      for (let j = 0; j < values.length; j++) {
        const td = document.createElement('td');
        td.textContent = values[j];
        row.appendChild(td);
      }
      table.appendChild(row);
    }
    fragment.appendChild(table);
  }

  container.appendChild(fragment);
}

function renderDnsTable(transportData) {
  const dnsData = transportData['DNS'];
  if (!dnsData) return;
  const dnsRows = [
    { name: 'Transaction ID', value: dnsData['Transaction ID'] },
    {
      name: 'Type',
      value: dnsData['Is Response'] ? 'Response' : 'Query',
    },
    {
      name: 'Query Names',
      value: (dnsData['Query Names'] || []).join(', ') || '—',
    },
    {
      name: 'Answer IPs',
      value: (dnsData['Answer IPs'] || []).join(', ') || '—',
    },
    { name: 'Questions', value: dnsData['Question Count'] },
    { name: 'Answers', value: dnsData['Answer Count'] },
  ];
  createTable(dnsRows, ['DNS Field', 'Value'], 'sidedatatable');
}

function renderIcmpTable(protocol, transportData) {
  if (protocol !== 'ICMP') return;
  const icmpRows = [
    { name: 'Type', value: transportData['Type'] ?? '—' },
    { name: 'Code', value: transportData['Code'] ?? '—' },
    { name: 'ID', value: transportData['ID'] ?? '—' },
    { name: 'Sequence', value: transportData['Sequence'] ?? '—' },
  ];
  createTable(icmpRows, ['ICMP Field', 'Value'], 'sidedatatable');
}

function renderSnmpTable(transportData) {
  const snmpData = transportData['SNMP'];
  if (!snmpData) return;
  const snmpRows = [
    { name: 'Version', value: snmpData['Version'] || '—' },
    { name: 'Community', value: snmpData['Community'] || '—' },
    { name: 'PDU Type', value: snmpData['PDU Type'] || '—' },
  ];
  createTable(snmpRows, ['SNMP Field', 'Value'], 'sidedatatable');
}

function renderDhcpTable(transportData) {
  const dhcpData = transportData['DHCP'];
  if (!dhcpData) return;
  const dhcpRows = [
    { name: 'Message Type', value: dhcpData['Message Type'] || '—' },
    { name: 'Transaction ID', value: dhcpData['Transaction ID'] || '—' },
    { name: 'Client IP', value: dhcpData['Client IP'] || '—' },
    { name: 'Your IP', value: dhcpData['Your IP'] || '—' },
    { name: 'Server IP', value: dhcpData['Server IP'] || '—' },
  ];
  createTable(dhcpRows, ['DHCP Field', 'Value'], 'sidedatatable');
}

function renderNtpTable(transportData) {
  const ntpData = transportData['NTP'];
  if (!ntpData) return;
  const ntpRows = [
    { name: 'Version', value: ntpData['Version'] ?? '—' },
    { name: 'Mode', value: ntpData['Mode'] || '—' },
    { name: 'Stratum', value: ntpData['Stratum'] ?? '—' },
    { name: 'Reference ID', value: ntpData['Reference ID'] || '—' },
    { name: 'Leap Indicator', value: ntpData['Leap Indicator'] ?? '—' },
  ];
  createTable(ntpRows, ['NTP Field', 'Value'], 'sidedatatable');
}

function renderSipTable(transportData) {
  const sipData = transportData['SIP'];
  if (!sipData) return;
  const sipRows = [
    { name: 'Type', value: sipData['Type'] || '—' },
    {
      name: sipData['Type'] === 'Request' ? 'Method' : 'Status Code',
      value: sipData['Method'] || sipData['Status Code'] || '—',
    },
    { name: 'From', value: sipData['From'] || '—' },
    { name: 'To', value: sipData['To'] || '—' },
    { name: 'Call-ID', value: sipData['Call-ID'] || '—' },
  ];
  createTable(sipRows, ['SIP Field', 'Value'], 'sidedatatable');
}

function renderHttpTable(transportData) {
  const httpData = transportData['HTTP'];
  if (!httpData) return;
  const httpRows = [{ name: 'Type', value: httpData['Type'] || '—' }];
  if (httpData['Type'] === 'Request') {
    httpRows.push(
      { name: 'Method', value: httpData['Method'] || '—' },
      { name: 'URL', value: httpData['URL'] || '—' },
      { name: 'HTTP Version', value: httpData['HTTP Version'] || '—' },
      { name: 'Host', value: httpData['Host'] || '—' },
      { name: 'User-Agent', value: httpData['User-Agent'] || '—' },
      { name: 'Content-Type', value: httpData['Content-Type'] || '—' },
      { name: 'Content-Length', value: httpData['Content-Length'] || '—' },
      { name: 'Referer', value: httpData['Referer'] || '—' },
      { name: 'Accept', value: httpData['Accept'] || '—' },
      { name: 'Accept-Encoding', value: httpData['Accept-Encoding'] || '—' },
      { name: 'Connection', value: httpData['Connection'] || '—' },
    );
  } else {
    httpRows.push(
      { name: 'Status Code', value: httpData['Status Code'] || '—' },
      { name: 'Status Message', value: httpData['Status Message'] || '—' },
      { name: 'HTTP Version', value: httpData['HTTP Version'] || '—' },
      { name: 'Server', value: httpData['Server'] || '—' },
      { name: 'Content-Type', value: httpData['Content-Type'] || '—' },
      { name: 'Content-Length', value: httpData['Content-Length'] || '—' },
      {
        name: 'Content-Encoding',
        value: httpData['Content-Encoding'] || '—',
      },
      {
        name: 'Transfer-Encoding',
        value: httpData['Transfer-Encoding'] || '—',
      },
      { name: 'Connection', value: httpData['Connection'] || '—' },
      { name: 'Location', value: httpData['Location'] || '—' },
    );
  }
  createTable(httpRows, ['HTTP Field', 'Value'], 'sidedatatable');
}

function renderFtpTable(transportData) {
  const ftpData = transportData['FTP'];
  if (!ftpData) return;
  const ftpRows = [{ name: 'Type', value: ftpData['Type'] || '—' }];
  if (ftpData['Type'] === 'Command') {
    ftpRows.push(
      { name: 'Command', value: ftpData['Command'] || '—' },
      { name: 'Argument', value: ftpData['Argument'] || '—' },
    );
  } else {
    ftpRows.push(
      { name: 'Status Code', value: ftpData['Status Code'] || '—' },
      { name: 'Message', value: ftpData['Message'] || '—' },
    );
  }
  createTable(ftpRows, ['FTP Field', 'Value'], 'sidedatatable');
}

function renderSmtpTable(transportData) {
  const smtpData = transportData['SMTP'];
  if (!smtpData) return;
  const smtpRows = [{ name: 'Type', value: smtpData['Type'] || '—' }];
  if (smtpData['Type'] === 'Command') {
    smtpRows.push(
      { name: 'Command', value: smtpData['Command'] || '—' },
      { name: 'Argument', value: smtpData['Argument'] || '—' },
    );
  } else {
    smtpRows.push(
      { name: 'Status Code', value: smtpData['Status Code'] || '—' },
      { name: 'Message', value: smtpData['Message'] || '—' },
    );
  }
  createTable(smtpRows, ['SMTP Field', 'Value'], 'sidedatatable');
}

function renderPop3Table(transportData) {
  const pop3Data = transportData['POP3'];
  if (!pop3Data) return;
  const pop3Rows = [{ name: 'Type', value: pop3Data['Type'] || '—' }];
  if (pop3Data['Type'] === 'Command') {
    pop3Rows.push(
      { name: 'Command', value: pop3Data['Command'] || '—' },
      { name: 'Argument', value: pop3Data['Argument'] || '—' },
    );
  } else {
    pop3Rows.push(
      { name: 'Status', value: pop3Data['Status'] || '—' },
      { name: 'Message', value: pop3Data['Message'] || '—' },
    );
  }
  createTable(pop3Rows, ['POP3 Field', 'Value'], 'sidedatatable');
}

function renderImapTable(transportData) {
  const imapData = transportData['IMAP'];
  if (!imapData) return;
  const imapRows = [{ name: 'Type', value: imapData['Type'] || '—' }];
  if (imapData['Type'] === 'Command') {
    imapRows.push(
      { name: 'Tag', value: imapData['Tag'] || '—' },
      { name: 'Command', value: imapData['Command'] || '—' },
      { name: 'Argument', value: imapData['Argument'] || '—' },
    );
  } else if (imapData['Type'] === 'Response') {
    imapRows.push(
      { name: 'Tag', value: imapData['Tag'] || '—' },
      { name: 'Status', value: imapData['Status'] || '—' },
      { name: 'Message', value: imapData['Message'] || '—' },
    );
  } else {
    imapRows.push(
      { name: 'Status', value: imapData['Status'] || '—' },
      { name: 'Info', value: imapData['Info'] || '—' },
    );
  }
  createTable(imapRows, ['IMAP Field', 'Value'], 'sidedatatable');
}

function renderTelnetTable(transportData) {
  const telnetData = transportData['Telnet'];
  if (!telnetData) return;
  const negotiations = (telnetData['Negotiations'] || []).join(', ') || '—';
  const telnetRows = [
    { name: 'Negotiations', value: negotiations },
    { name: 'Text', value: telnetData['Printable Text'] || '—' },
  ];
  createTable(telnetRows, ['Telnet Field', 'Value'], 'sidedatatable');
}

function renderIrcTable(transportData) {
  const ircData = transportData['IRC'];
  if (!ircData) return;
  const ircRows = [
    { name: 'Command', value: ircData['Command'] || '—' },
    { name: 'Prefix', value: ircData['Prefix'] || '—' },
    { name: 'Parameters', value: ircData['Parameters'] || '—' },
    { name: 'Message Count', value: ircData['Message Count'] ?? '—' },
  ];
  createTable(ircRows, ['IRC Field', 'Value'], 'sidedatatable');
}

function renderMtpTable(transportData) {
  const mtpData = transportData['MTP'];
  if (!mtpData) return;
  const mtpRows = [
    { name: 'Protocol', value: mtpData['Protocol'] || '—' },
    { name: 'Command', value: mtpData['Command'] || '—' },
    { name: 'Command ID', value: mtpData['Command ID'] || '—' },
    { name: 'Length', value: mtpData['Length'] ?? '—' },
  ];
  createTable(mtpRows, ['MTP Field', 'Value'], 'sidedatatable');
}

function renderLdapTable(transportData) {
  const ldapData = transportData['LDAP'];
  if (!ldapData) return;
  const ldapRows = [
    { name: 'Message ID', value: ldapData['Message ID'] ?? '—' },
    { name: 'Operation', value: ldapData['Operation'] || '—' },
  ];
  createTable(ldapRows, ['LDAP Field', 'Value'], 'sidedatatable');
}

function renderMysqlTable(transportData) {
  const mysqlData = transportData['MySQL'];
  if (!mysqlData) return;
  const mysqlRows = [
    { name: 'Type', value: mysqlData['Type'] || '—' },
    { name: 'Sequence', value: mysqlData['Sequence'] ?? '—' },
  ];
  if (mysqlData['Type'] === 'Server Greeting') {
    mysqlRows.push(
      { name: 'Protocol Version', value: mysqlData['Protocol Version'] ?? '—' },
      { name: 'Server Version', value: mysqlData['Server Version'] || '—' },
    );
  } else if (mysqlData['Type'] === 'Command') {
    mysqlRows.push(
      { name: 'Command', value: mysqlData['Command'] || '—' },
      { name: 'Query', value: mysqlData['Query'] || '—' },
    );
  } else if (mysqlData['Type'] === 'Error') {
    mysqlRows.push(
      { name: 'Error Code', value: mysqlData['Error Code'] ?? '—' },
      { name: 'Error Message', value: mysqlData['Error Message'] || '—' },
    );
  }
  createTable(mysqlRows, ['MySQL Field', 'Value'], 'sidedatatable');
}

function renderPostgresqlTable(transportData) {
  const pgData = transportData['PostgreSQL'];
  if (!pgData) return;
  const pgRows = [
    { name: 'Type', value: pgData['Type'] || '—' },
    { name: 'Direction', value: pgData['Direction'] || '—' },
  ];
  if (pgData['Protocol Version']) {
    pgRows.push({ name: 'Protocol Version', value: pgData['Protocol Version'] });
  }
  if (pgData['Message Length'] !== undefined) {
    pgRows.push({ name: 'Message Length', value: pgData['Message Length'] });
  }
  if (pgData['Body']) {
    pgRows.push({ name: 'Body', value: pgData['Body'] });
  }
  createTable(pgRows, ['PostgreSQL Field', 'Value'], 'sidedatatable');
}

function renderXmppTable(transportData) {
  const xmppData = transportData['XMPP'];
  if (!xmppData) return;
  const xmppRows = [
    { name: 'Stanza Type', value: xmppData['Stanza Type'] || '—' },
    { name: 'From', value: xmppData['From'] || '—' },
    { name: 'To', value: xmppData['To'] || '—' },
  ];
  createTable(xmppRows, ['XMPP Field', 'Value'], 'sidedatatable');
}

function renderSmbTable(transportData) {
  const smbData = transportData['SMB'];
  if (!smbData) return;
  const smbRows = [
    { name: 'Version', value: smbData['Version'] || '—' },
    { name: 'Command', value: smbData['Command'] || '—' },
    { name: 'Status', value: smbData['Status'] || '—' },
    { name: 'Is Response', value: smbData['Is Response'] ? 'Yes' : 'No' },
  ];
  createTable(smbRows, ['SMB Field', 'Value'], 'sidedatatable');
}

function renderMqttTable(transportData) {
  const mqttData = transportData['MQTT'];
  if (!mqttData) return;
  const mqttRows = [
    { name: 'Message Type', value: mqttData['Message Type'] || '—' },
    { name: 'QoS', value: mqttData['QoS'] ?? '—' },
    { name: 'DUP Flag', value: mqttData['DUP Flag'] ? 'Yes' : 'No' },
    { name: 'Retain Flag', value: mqttData['Retain Flag'] ? 'Yes' : 'No' },
  ];
  if (mqttData['Topic']) {
    mqttRows.push({ name: 'Topic', value: mqttData['Topic'] });
  }
  createTable(mqttRows, ['MQTT Field', 'Value'], 'sidedatatable');
}

function renderRtspTable(transportData) {
  const rtspData = transportData['RTSP'];
  if (!rtspData) return;
  const rtspRows = [{ name: 'Type', value: rtspData['Type'] || '—' }];
  if (rtspData['Type'] === 'Request') {
    rtspRows.push(
      { name: 'Method', value: rtspData['Method'] || '—' },
      { name: 'URL', value: rtspData['URL'] || '—' },
      { name: 'RTSP Version', value: rtspData['RTSP Version'] || '—' },
      { name: 'CSeq', value: rtspData['CSeq'] || '—' },
      { name: 'Session', value: rtspData['Session'] || '—' },
      { name: 'Transport', value: rtspData['Transport'] || '—' },
    );
  } else {
    rtspRows.push(
      { name: 'Status Code', value: rtspData['Status Code'] || '—' },
      { name: 'Status Message', value: rtspData['Status Message'] || '—' },
      { name: 'RTSP Version', value: rtspData['RTSP Version'] || '—' },
      { name: 'CSeq', value: rtspData['CSeq'] || '—' },
      { name: 'Content-Type', value: rtspData['Content-Type'] || '—' },
      { name: 'Content-Length', value: rtspData['Content-Length'] || '—' },
    );
  }
  createTable(rtspRows, ['RTSP Field', 'Value'], 'sidedatatable');
}

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
  if (tftpData['Block Number'] !== undefined) {
    tftpRows.push({ name: 'Block Number', value: tftpData['Block Number'] });
  }
  if (tftpData['Data Length'] !== undefined) {
    tftpRows.push({ name: 'Data Length', value: tftpData['Data Length'] });
  }
  if (tftpData['Error Code'] !== undefined) {
    tftpRows.push(
      { name: 'Error Code', value: tftpData['Error Code'] },
      { name: 'Error Description', value: tftpData['Error Description'] || '—' },
      { name: 'Error Message', value: tftpData['Error Message'] || '—' },
    );
  }
  createTable(tftpRows, ['TFTP Field', 'Value'], 'sidedatatable');
}

function renderBgpTable(transportData) {
  const bgpData = transportData['BGP'];
  if (!bgpData) return;
  const bgpRows = [
    { name: 'Message Type', value: bgpData['Message Type'] || '—' },
    { name: 'Message Length', value: bgpData['Message Length'] ?? '—' },
  ];
  if (bgpData['BGP Version'] !== undefined) {
    bgpRows.push(
      { name: 'BGP Version', value: bgpData['BGP Version'] },
      { name: 'ASN', value: bgpData['ASN'] ?? '—' },
      { name: 'Hold Time', value: bgpData['Hold Time'] ?? '—' },
      { name: 'Router ID', value: bgpData['Router ID'] || '—' },
    );
  }
  if (bgpData['Error Code'] !== undefined) {
    bgpRows.push(
      { name: 'Error Name', value: bgpData['Error Name'] || '—' },
      { name: 'Error Code', value: bgpData['Error Code'] },
      { name: 'Error Subcode', value: bgpData['Error Subcode'] ?? '—' },
    );
  }
  createTable(bgpRows, ['BGP Field', 'Value'], 'sidedatatable');
}

function renderHttp2Table(transportData) {
  const http2Data = transportData['HTTP2'];
  if (!http2Data) return;
  const http2Rows = [
    { name: 'Frame Type', value: http2Data['Frame Type'] || '—' },
    {
      name: 'Connection Preface',
      value: http2Data['Connection Preface'] ? 'Yes' : 'No',
    },
  ];
  if (http2Data['Frame Length'] !== undefined) {
    http2Rows.push(
      { name: 'Frame Length', value: http2Data['Frame Length'] },
      { name: 'Frame Flags', value: http2Data['Frame Flags'] || '—' },
      { name: 'Stream ID', value: http2Data['Stream ID'] ?? '—' },
    );
  }
  createTable(http2Rows, ['HTTP/2 Field', 'Value'], 'sidedatatable');
}

function renderNntpTable(transportData) {
  const nntpData = transportData['NNTP'];
  if (!nntpData) return;
  const nntpRows = [{ name: 'Type', value: nntpData['Type'] || '—' }];
  if (nntpData['Type'] === 'Command') {
    nntpRows.push(
      { name: 'Command', value: nntpData['Command'] || '—' },
      { name: 'Argument', value: nntpData['Argument'] || '—' },
    );
  } else {
    nntpRows.push(
      { name: 'Status Code', value: nntpData['Status Code'] || '—' },
      { name: 'Message', value: nntpData['Message'] || '—' },
    );
  }
  createTable(nntpRows, ['NNTP Field', 'Value'], 'sidedatatable');
}

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

module.exports = {
  createTable,
  renderDnsTable,
  renderIcmpTable,
  renderSnmpTable,
  renderDhcpTable,
  renderNtpTable,
  renderSipTable,
  renderHttpTable,
  renderFtpTable,
  renderSmtpTable,
  renderPop3Table,
  renderImapTable,
  renderTelnetTable,
  renderIrcTable,
  renderMtpTable,
  renderLdapTable,
  renderMysqlTable,
  renderPostgresqlTable,
  renderXmppTable,
  renderSmbTable,
  renderMqttTable,
  renderRtspTable,
  renderTftpTable,
  renderBgpTable,
  renderHttp2Table,
  renderNntpTable,
  renderRadiusTable,
};
