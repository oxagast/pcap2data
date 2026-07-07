
// Protocol decoder render functions for the info panel side tables.
// Each function reads the relevant sub-object from transportData and appends
// a table to the "sidedatatable" container (or no-ops when the data is absent).

function dotField(data, dotKey, legacyKey, fallback = '—') {
  if (!data) return fallback;
  const value = data[dotKey] ?? (legacyKey ? data[legacyKey] : undefined);
  return value === undefined || value === null || value === '' ? fallback : value;
}

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

function renderLinkControlTable(packetInfoData) {
  const linkData = packetInfoData['Link Control'];
  if (!linkData) return;

  const detectedProtocolsRaw = linkData['wan.detected'] ?? linkData['Detected Protocols'];
  const detectedProtocols = Array.isArray(detectedProtocolsRaw)
    ? detectedProtocolsRaw.join(', ')
    : detectedProtocolsRaw || '—';
  const layerNamesRaw = linkData['wan.layers'] ?? linkData['Layer Names'];
  const layerNames = Array.isArray(layerNamesRaw)
    ? layerNamesRaw.join(', ')
    : layerNamesRaw || '—';

  const linkRows = [
    { name: 'Primary WAN Protocol', value: dotField(linkData, 'wan.primary', 'Primary WAN Protocol') },
    { name: 'Detected Protocols', value: detectedProtocols },
    { name: 'Layer Names', value: layerNames },
  ];
  if (linkData['PPP Protocol Field']) {
    linkRows.push({ name: 'PPP Protocol Field', value: linkData['PPP Protocol Field'] });
  }
  if (linkData['ATM Encapsulation']) {
    linkRows.push({ name: 'ATM Encapsulation', value: linkData['ATM Encapsulation'] });
  }
  createTable(linkRows, ['WAN Field', 'Value'], 'sidedatatable');
}

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

function renderDhcpTable(transportData) {
  const dhcpData = transportData['DHCP'];
  if (!dhcpData) return;
  const dhcpRows = [
    { name: 'Message Type', value: dotField(dhcpData, 'dhcp.msg_type', 'Message Type') },
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
    { name: 'Reference ID', value: dotField(ntpData, 'ntp.ref_id', 'Reference ID') },
    { name: 'Leap Indicator', value: dotField(ntpData, 'ntp.leap', 'Leap Indicator') },
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
      value: sipData['Method'] || dotField(sipData, 'sip.status_code', 'Status Code'),
    },
    { name: 'From', value: sipData['From'] || '—' },
    { name: 'To', value: sipData['To'] || '—' },
    { name: 'Call-ID', value: sipData['Call-ID'] || '—' },
  ];
  if (sipData['Authorization']) {
    sipRows.push({ name: 'Authorization', value: sipData['Authorization'] || '—' });
  }
  if (sipData['Proxy-Authorization']) {
    sipRows.push({ name: 'Proxy-Authorization', value: sipData['Proxy-Authorization'] || '—' });
  }
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
      { name: 'HTTP Version', value: dotField(httpData, 'http.version', 'HTTP Version') },
      { name: 'Host', value: httpData['host'] || '—' },
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
      { name: 'Status Code', value: dotField(httpData, 'http.status_code', 'Status Code') },
      { name: 'Status Message', value: dotField(httpData, 'http.status_msg', 'Status Message') },
      { name: 'HTTP Version', value: dotField(httpData, 'http.version', 'HTTP Version') },
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
      { name: 'Status Code', value: dotField(ftpData, 'ftp.status_code', 'Status Code') },
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
      { name: 'Status Code', value: dotField(smtpData, 'smtp.status_code', 'Status Code') },
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
    { name: 'Text', value: dotField(telnetData, 'telnet.text', 'Printable Text') },
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
    { name: 'Message Count', value: dotField(ircData, 'irc.msg_count', 'Message Count') },
  ];
  createTable(ircRows, ['IRC Field', 'Value'], 'sidedatatable');
}

function renderMtpTable(transportData) {
  const mtpData = transportData['MTP'];
  if (!mtpData) return;
  const mtpRows = [
    { name: 'Protocol', value: mtpData['Protocol'] || '—' },
    { name: 'Command', value: mtpData['Command'] || '—' },
    { name: 'Command ID', value: dotField(mtpData, 'mtp.cmd_id', 'Command ID') },
    { name: 'Length', value: mtpData['Length'] ?? '—' },
  ];
  createTable(mtpRows, ['MTP Field', 'Value'], 'sidedatatable');
}

function renderLdapTable(transportData) {
  const ldapData = transportData['LDAP'];
  if (!ldapData) return;
  const ldapRows = [
    { name: 'Message ID', value: dotField(ldapData, 'ldap.msg_id', 'Message ID') },
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
      { name: 'Protocol Version', value: dotField(mysqlData, 'mysql.proto_version', 'Protocol Version') },
      { name: 'Server Version', value: dotField(mysqlData, 'mysql.server_version', 'Server Version') },
    );
  } else if (mysqlData['Type'] === 'Command') {
    mysqlRows.push(
      { name: 'Command', value: mysqlData['Command'] || '—' },
      { name: 'Query', value: mysqlData['Query'] || '—' },
    );
  } else if (mysqlData['Type'] === 'Error') {
    mysqlRows.push(
      { name: 'Error Code', value: dotField(mysqlData, 'mysql.error_code', 'Error Code') },
      { name: 'Error Message', value: dotField(mysqlData, 'mysql.error_msg', 'Error Message') },
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
  if (pgData['pg.proto_version'] || pgData['Protocol Version']) {
    pgRows.push({ name: 'Protocol Version', value: dotField(pgData, 'pg.proto_version', 'Protocol Version') });
  }
  if (pgData['pg.msg_length'] !== undefined || pgData['Message Length'] !== undefined) {
    pgRows.push({ name: 'Message Length', value: dotField(pgData, 'pg.msg_length', 'Message Length') });
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
    { name: 'Stanza Type', value: dotField(xmppData, 'xmpp.stanza', 'Stanza Type') },
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
    { name: 'Is Response', value: (smbData['smb.is_response'] ?? smbData['Is Response']) ? 'Yes' : 'No' },
  ];
  createTable(smbRows, ['SMB Field', 'Value'], 'sidedatatable');
}

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

function renderRtspTable(transportData) {
  const rtspData = transportData['RTSP'];
  if (!rtspData) return;
  const rtspRows = [{ name: 'Type', value: rtspData['Type'] || '—' }];
  if (rtspData['Type'] === 'Request') {
    rtspRows.push(
      { name: 'Method', value: rtspData['Method'] || '—' },
      { name: 'URL', value: rtspData['URL'] || '—' },
      { name: 'RTSP Version', value: dotField(rtspData, 'rtsp.version', 'RTSP Version') },
      { name: 'CSeq', value: rtspData['CSeq'] || '—' },
      { name: 'Session', value: rtspData['Session'] || '—' },
      { name: 'Transport', value: rtspData['Transport'] || '—' },
    );
  } else {
    rtspRows.push(
      { name: 'Status Code', value: dotField(rtspData, 'rtsp.status_code', 'Status Code') },
      { name: 'Status Message', value: dotField(rtspData, 'rtsp.status_msg', 'Status Message') },
      { name: 'RTSP Version', value: dotField(rtspData, 'rtsp.version', 'RTSP Version') },
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

function renderBgpTable(transportData) {
  const bgpData = transportData['BGP'];
  if (!bgpData) return;
  const bgpRows = [
    { name: 'Message Type', value: dotField(bgpData, 'bgp.type', 'Message Type') },
    { name: 'Message Length', value: dotField(bgpData, 'bgp.length', 'Message Length') },
  ];
  if (bgpData['BGP Version'] !== undefined) {
    bgpRows.push(
      { name: 'BGP Version', value: bgpData['BGP Version'] },
      { name: 'ASN', value: bgpData['ASN'] ?? '—' },
      { name: 'Hold Time', value: bgpData['Hold Time'] ?? '—' },
      { name: 'Router ID', value: bgpData['Router ID'] || '—' },
    );
  }
  if (bgpData['bgp.error_code'] !== undefined || bgpData['Error Code'] !== undefined) {
    bgpRows.push(
      { name: 'Error Name', value: dotField(bgpData, 'bgp.error_name', 'Error Name') },
      { name: 'Error Code', value: dotField(bgpData, 'bgp.error_code', 'Error Code') },
      { name: 'Error Subcode', value: dotField(bgpData, 'bgp.error_subcode', 'Error Subcode') },
    );
  }
  createTable(bgpRows, ['BGP Field', 'Value'], 'sidedatatable');
}

function renderHttp2Table(transportData) {
  const http2Data = transportData['HTTP2'];
  if (!http2Data) return;
  const http2Rows = [
    { name: 'Frame Type', value: dotField(http2Data, 'http2.frame_type', 'Frame Type') },
    {
      name: 'Connection Preface',
      value: (http2Data['http2.preface'] ?? http2Data['Connection Preface']) ? 'Yes' : 'No',
    },
  ];
  if (http2Data['http2.frame_length'] !== undefined || http2Data['Frame Length'] !== undefined) {
    http2Rows.push(
      { name: 'Frame Length', value: dotField(http2Data, 'http2.frame_length', 'Frame Length') },
      { name: 'Frame Flags', value: dotField(http2Data, 'http2.frame_flags', 'Frame Flags') },
      { name: 'Stream ID', value: dotField(http2Data, 'http2.stream_id', 'Stream ID') },
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
      { name: 'Status Code', value: dotField(nntpData, 'nntp.status_code', 'Status Code') },
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

function renderWebSocketTable(transportData) {
  const wsData = transportData['WebSocket'];
  if (!wsData) return;
  const wsRows = [{ name: 'Type', value: wsData['Type'] || '—' }];
  if (wsData['Type'] === 'Upgrade') {
    wsRows.push(
      { name: 'Host', value: wsData['host'] || '—' },
      { name: 'Sec-WebSocket-Key', value: wsData['Sec-WebSocket-Key'] || '—' },
      { name: 'Sec-WebSocket-Version', value: wsData['Sec-WebSocket-Version'] || '—' },
    );
  } else {
    wsRows.push(
      { name: 'Opcode', value: wsData['Opcode'] || '—' },
      { name: 'FIN', value: wsData['FIN'] ? 'Yes' : 'No' },
      { name: 'Masked', value: wsData['Masked'] ? 'Yes' : 'No' },
      { name: 'Payload Length', value: dotField(wsData, 'ws.payload_len', 'Payload Length') },
    );
  }
  createTable(wsRows, ['WebSocket Field', 'Value'], 'sidedatatable');
}

function renderNfsTable(transportData) {
  const nfsData = transportData['NFS'];
  if (!nfsData) return;
  const nfsRows = [
    { name: 'XID', value: nfsData['XID'] || '—' },
    { name: 'Message Type', value: dotField(nfsData, 'rpc.msg_type', 'Message Type') },
  ];
  if (nfsData['Program']) {
    nfsRows.push(
      { name: 'Program', value: nfsData['Program'] },
      { name: 'Program Version', value: dotField(nfsData, 'rpc.prog_version', 'Program Version') },
      { name: 'Procedure', value: nfsData['Procedure'] || '—' },
      { name: 'RPC Version', value: dotField(nfsData, 'rpc.version', 'RPC Version') },
    );
  }
  if (nfsData['Reply Status']) {
    nfsRows.push({ name: 'Reply Status', value: nfsData['Reply Status'] });
  }
  createTable(nfsRows, ['NFS/RPC Field', 'Value'], 'sidedatatable');
}

function renderKerberosTable(transportData) {
  const krbData = transportData['Kerberos'];
  if (!krbData) return;
  const krbRows = [
    { name: 'Message Type', value: dotField(krbData, 'krb5.msg_type', 'Message Type') },
  ];
  if (krbData['Protocol Version'] !== undefined) {
    krbRows.push({ name: 'Protocol Version', value: krbData['Protocol Version'] });
  }
  createTable(krbRows, ['Kerberos Field', 'Value'], 'sidedatatable');
}

function renderSshTable(transportData) {
  const sshData = transportData['SSH'];
  if (!sshData) return;
  const sshRows = [
    { name: 'Type', value: sshData['Type'] || '—' },
    { name: 'Direction', value: sshData['Direction'] || '—' },
    { name: 'Banner', value: sshData['Banner'] || '—' },
    { name: 'Protocol Version', value: dotField(sshData, 'ssh.protocol_version', 'Protocol Version') },
    { name: 'Software Version', value: dotField(sshData, 'ssh.software_version', 'Software Version') },
    { name: 'Comments', value: sshData['Comments'] || '—' },
    { name: 'Packet Length', value: dotField(sshData, 'ssh.packet_length', 'Packet Length') },
    { name: 'Padding Length', value: dotField(sshData, 'ssh.padding_length', 'Padding Length') },
    { name: 'Message Type', value: dotField(sshData, 'ssh.msg_type', 'Message Type') },
    {
      name: 'Likely Encrypted',
      value:
        (sshData['ssh.likely_encrypted'] ?? sshData['Likely Encrypted']) === undefined
          ? '—'
          : (sshData['ssh.likely_encrypted'] ?? sshData['Likely Encrypted'])
            ? 'Yes'
            : 'No',
    },
  ];
  createTable(sshRows, ['SSH Field', 'Value'], 'sidedatatable');
}

function renderSctpTable(transportData) {
  const sctpData = transportData;
  if (!sctpData) return;

  // Only render when SCTP-specific evidence exists; Source/Destination port
  // keys are shared by TCP/UDP and would otherwise produce false SCTP tables.
  const hasSctpData =
    sctpData['sctp.vtag'] !== undefined ||
    sctpData['sctp.chunk.count'] !== undefined ||
    sctpData['SIGTRAN'] !== undefined ||
    sctpData['transport.proto'] === 'SCTP';
  if (!hasSctpData) return;

  const sctpRows = [
    { name: 'Source Port', value: sctpData['sctp.src.port'] ?? '—' },
    { name: 'Destination Port', value: sctpData['sctp.dst.port'] ?? '—' },
    { name: 'Verification Tag', value: sctpData['sctp.vtag'] ?? '—' },
    { name: 'Checksum', value: sctpData['sctp.chksum'] ?? '—' },
    { name: 'Chunk Count', value: sctpData['sctp.chunk.count'] ?? '—' },
    { name: 'Wire Length', value: sctpData['wire.len'] ?? '—' },
  ];

  const sigtranData = sctpData['SIGTRAN'];
  if (sigtranData) {
    sctpRows.push(
      { name: 'SIGTRAN Protocol', value: sigtranData['sigtran.proto'] || '—' },
      { name: 'Likely Signaling', value: sigtranData['sigtran.signaling'] || '—' },
    );
    if (sigtranData['sigtran.message.class_name'] !== undefined || sigtranData['sigtran.message.class'] !== undefined) {
      sctpRows.push({ name: 'Message Class', value: sigtranData['sigtran.message.class_name'] ?? sigtranData['sigtran.message.class'] });
    }
    if (sigtranData['sigtran.message.type'] !== undefined) {
      sctpRows.push({ name: 'Message Type', value: sigtranData['sigtran.message.type'] });
    }
    if (sigtranData['sigtran.length'] !== undefined) {
      sctpRows.push({ name: 'Message Length', value: sigtranData['sigtran.length'] });
    }
    if (sigtranData['sigtran.payload.len'] !== undefined) {
      sctpRows.push({ name: 'Payload Length', value: sigtranData['sigtran.payload.len'] });
    }
  }

  createTable(sctpRows, ['SCTP Field', 'Value'], 'sidedatatable');
}

module.exports = {
  createTable,
  renderDnsTable,
  renderIcmpTable,
  renderIgmpTable,
  renderArpTable,
  renderLinkControlTable,
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
  renderWebSocketTable,
  renderNfsTable,
  renderKerberosTable,
  renderSshTable,
  renderSctpTable,
};
