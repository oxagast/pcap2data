// Collects and re-exports the protocol detail renderers used by the frontend.

const { createTable } = require("./shared");
const { renderDnsTable } = require("./dns");
const { renderIcmpTable } = require("./icmp");
const { renderIgmpTable } = require("./igmp");
const { renderArpTable } = require("./arp");
const { renderLinkControlTable } = require("./link-control");
const { renderSnmpTable } = require("./snmp");
const { renderDhcpTable } = require("./dhcp");
const { renderDhcpv6Table } = require("./dhcpv6");
const { renderEpmapTable } = require("./epmap");
const { renderMdnsTable, renderLlmnrTable } = require("./dns-wire");
const { renderSsdpTable } = require("./ssdp");
const { renderGrpcTable } = require("./grpc");
const { renderNtpTable } = require("./ntp");
const { renderSipTable } = require("./sip");
const { renderHttpTable } = require("./http");
const { renderFtpTable } = require("./ftp");
const { renderSmtpTable } = require("./smtp");
const { renderPop3Table } = require("./pop3");
const { renderImapTable } = require("./imap");
const { renderTelnetTable } = require("./telnet");
const { renderIrcTable } = require("./irc");
const { renderMtpTable } = require("./mtp");
const { renderLdapTable } = require("./ldap");
const { renderMysqlTable } = require("./mysql");
const { renderPostgresqlTable } = require("./postgresql");
const { renderXmppTable } = require("./xmpp");
const { renderSmbTable } = require("./smb");
const { renderSmppTable } = require("./smpp");
const { renderSoulseekTable } = require("./soulseek");
const { renderBitTorrentTable } = require("./bittorrent");
const { renderMqttTable } = require("./mqtt");
const { renderRtspTable } = require("./rtsp");
const { renderTftpTable } = require("./tftp");
const { renderBgpTable } = require("./bgp");
const { renderHttp2Table } = require("./http2");
const { renderNntpTable } = require("./nntp");
const { renderRadiusTable } = require("./radius");
const { renderWebSocketTable } = require("./websocket");
const { renderNfsTable } = require("./nfs");
const { renderKerberosTable } = require("./kerberos");
const { renderSshTable } = require("./ssh");
const { renderSctpTable } = require("./sctp");
const { renderModbusTable } = require("./modbus");
const { renderDnp3Table } = require("./dnp3");
const { renderS7commTable } = require("./s7comm");
const { renderOspfTable } = require("./ospf");
const { renderHsrpTable } = require("./hsrp");
const { renderLacpTable } = require("./lacp");
const { renderCdpTable } = require("./cdp");
const { renderMndpTable } = require("./mndp");
const { renderStpTable } = require("./stp");

module.exports = {
  createTable,
  renderDnsTable,
  renderIcmpTable,
  renderIgmpTable,
  renderArpTable,
  renderLinkControlTable,
  renderSnmpTable,
  renderDhcpTable,
  renderDhcpv6Table,
  renderEpmapTable,
  renderMdnsTable,
  renderLlmnrTable,
  renderSsdpTable,
  renderGrpcTable,
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
  renderSmppTable,
  renderSoulseekTable,
  renderBitTorrentTable,
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
  renderModbusTable,
  renderDnp3Table,
  renderS7commTable,
  renderOspfTable,
  renderHsrpTable,
  renderLacpTable,
  renderCdpTable,
  renderMndpTable,
  renderStpTable,
};
