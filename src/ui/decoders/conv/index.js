// Barrel re-export for the Conv decoders under src/ui/decoders/conv/.
// Each per-protocol file is added as it is moved out of data-tools-panel.js.

const { decodeJsonFromBytes } = require("./json");
const { decodeXmlFromBytes } = require("./xml");
const { decodeHtmlFromBytes } = require("./html");
const { decodeYamlFromBytes } = require("./yaml");

const { decodeHttpFromBytes } = require("./http");
const {
    extractHttpBodyHex,
    findHttpHeaderBodySeparators,
    looksLikeHttpStartLine,
    sliceHttpMessageSegments,
    httpHeadersHaveExplicitFraming,
    collectHttpMessageBodiesFromStream,
    HTTP_FILENAME_EXT_BY_MIME,
    getHttpBodyFilenameExtension,
    extractFilenameFromContentDisposition,
    extractMultipartBoundaryFromContentType,
    extractMultipartFilenameFromBodyBytes,
    findMultipartFileByteRange,
    findMultipartFileByteRanges,
    sliceCompleteChunkedHttpBodyHex,
    hexToAsciiString,
    isChunkedTransferEncodingHeader,
    parseContentLengthFromHeaderAscii,
    splitHttpMessageHeaders,
} = require("./http");
const { decodeTelnetFromBytes } = require("./telnet");
const { decodeSshFromBytes } = require("./ssh");
const { decodePop3FromBytes } = require("./pop3");
const { decodeImapFromBytes } = require("./imap");
const { decodeSmtpFromBytes } = require("./smtp");
const { decodeFtpFromBytes } = require("./ftp");

const { decodeBerFromBytes } = require("./ber");
const { decodeDerFromBytes } = require("./der");
const { decodeProtobufFromBytes, readVarint } = require("./protobuf");
const { decodeMessagePackFromBytes } = require("./msgpack");
const { decodeBsonFromBytes } = require("./bson");

const { decodeLdapFromBytes } = require("./ldap");
const { decodeSmbFromBytes } = require("./smb");
const { decodeEpmapFromBytes } = require("./epmap");
const { decodeSipFromBytes } = require("./sip");
const { decodeSmppFromBytes } = require("./smpp");
const { decodeSoulseekFromBytes } = require("./soulseek");
const { decodeBittorrentFromBytes } = require("./bittorrent");
const { decodeKerberosFromBytes } = require("./kerberos");
const { decodeDnsFromBytes } = require("./dns");
const { decodeLlmnrFromBytes } = require("./llmnr");
const { decodeNbnsFromBytes } = require("./nbns");
const { decodeNbdgmFromBytes } = require("./nbdgm");
const { decodeSnmpFromBytes } = require("./snmp");
const { decodeDhcpFromBytes } = require("./dhcp");
const { decodeDhcpv6FromBytes } = require("./dhcpv6");
const { decodeIso8583FromBytes } = require("./iso8583");

const { decodeModbusFromBytes } = require("./modbus");
const { decodeDnp3FromBytes } = require("./dnp3");
const { decodeS7commFromBytes } = require("./s7comm");
const { decodeOspfFromBytes } = require("./ospf");
const { decodeHsrpFromBytes } = require("./hsrp");
const { decodeLacpFromBytes } = require("./lacp");
const { decodeCdpFromBytes } = require("./cdp");

const { decodeJpegFromBytes } = require("./jpeg");
const { decodePngFromBytes } = require("./png");
const { decodeGifFromBytes } = require("./gif");
const { decodeWebpFromBytes } = require("./webp");
const { createImageDecodeResult, validateImageBytes } = require("./image-helpers");

const {
    EXIF_FILE_TYPE_TO_PROTO,
    getImageTypeFromExifReader,
} = require("./exif-helpers");

const {
    normalizeSmbDecoderBytes,
    findBytesSubsequence,
    parseSmbNtlmSecurityBuffer,
    decodeSmbTextBytes,
    bytesToHexLower,
    extractSmb2CreateFileName,
    parseDceRpcBind,
    formatDceRpcUuid,
    lookupDceRpcService,
    DCE_RPC_SERVICE_UUIDS,
} = require("./smb-helpers");

const {
    parseAsn1Length,
    getAsn1TagDescription,
    decodeAsn1GenericFromBytes,
} = require("./asn1");

const {
    parseXmlElementToTreeObject,
    formatDataTreeLeafValue,
    getDataTreeBranchSummary,
    createDataTreeNode,
    renderStructuredDecoderTree,
} = require("./xml-tree");

const {
    parseSimpleYamlScalar,
    parseSimpleYamlKeyValue,
    parseSimpleYamlToObject,
} = require("./yaml-parser");

const { MIME_TO_PROTO } = require("./mime-maps");
const {
    FILE_EXTENSION_TO_PROTO,
    SUPPORTED_DECODER_PROTOS,
    extractFileExtension,
    getProtoDecoderHintForFileName,
} = require("./mime-maps");

const { PROTOCOL_DECODER_HINTS, PORT_DECODER_HINTS } = require("./protocol-hints");

const {
    getPacketProtocolDecoderHint,
    autoDetectProtoFromBytes,
    LOW_CONFIDENCE_DECODERS,
    LOW_CONFIDENCE_CORROBORATING_HINTS,
} = require("./auto-detect");

module.exports = {
    decodeJsonFromBytes,
    decodeXmlFromBytes,
    decodeHtmlFromBytes,
    decodeYamlFromBytes,
    decodeHttpFromBytes,
    extractHttpBodyHex,
    findHttpHeaderBodySeparators,
    looksLikeHttpStartLine,
    sliceHttpMessageSegments,
    httpHeadersHaveExplicitFraming,
    collectHttpMessageBodiesFromStream,
    HTTP_FILENAME_EXT_BY_MIME,
    getHttpBodyFilenameExtension,
    extractFilenameFromContentDisposition,
    extractMultipartBoundaryFromContentType,
    extractMultipartFilenameFromBodyBytes,
    findMultipartFileByteRange,
    findMultipartFileByteRanges,
    sliceCompleteChunkedHttpBodyHex,
    hexToAsciiString,
    isChunkedTransferEncodingHeader,
    parseContentLengthFromHeaderAscii,
    splitHttpMessageHeaders,
    decodeTelnetFromBytes,
    decodeSshFromBytes,
    decodePop3FromBytes,
    decodeImapFromBytes,
    decodeSmtpFromBytes,
    decodeFtpFromBytes,
    decodeBerFromBytes,
    decodeDerFromBytes,
    decodeProtobufFromBytes,
    decodeMessagePackFromBytes,
    decodeBsonFromBytes,
    decodeLdapFromBytes,
    decodeSmbFromBytes,
    decodeEpmapFromBytes,
    decodeSipFromBytes,
    decodeSmppFromBytes,
    decodeSoulseekFromBytes,
    decodeBittorrentFromBytes,
    decodeKerberosFromBytes,
    decodeDnsFromBytes,
    decodeLlmnrFromBytes,
    decodeNbnsFromBytes,
    decodeNbdgmFromBytes,
    decodeSnmpFromBytes,
    decodeDhcpFromBytes,
    decodeDhcpv6FromBytes,
    decodeIso8583FromBytes,
    decodeModbusFromBytes,
    decodeDnp3FromBytes,
    decodeS7commFromBytes,
    decodeOspfFromBytes,
    decodeHsrpFromBytes,
    decodeLacpFromBytes,
    decodeCdpFromBytes,
    decodeJpegFromBytes,
    decodePngFromBytes,
    decodeGifFromBytes,
    decodeWebpFromBytes,
    createImageDecodeResult,
    validateImageBytes,
    EXIF_FILE_TYPE_TO_PROTO,
    getImageTypeFromExifReader,
    parseAsn1Length,
    getAsn1TagDescription,
    decodeAsn1GenericFromBytes,
    readVarint,
    normalizeSmbDecoderBytes,
    findBytesSubsequence,
    parseSmbNtlmSecurityBuffer,
    decodeSmbTextBytes,
    bytesToHexLower,
    parseXmlElementToTreeObject,
    formatDataTreeLeafValue,
    getDataTreeBranchSummary,
    createDataTreeNode,
    renderStructuredDecoderTree,
    parseSimpleYamlScalar,
    parseSimpleYamlKeyValue,
    parseSimpleYamlToObject,
    MIME_TO_PROTO,
    FILE_EXTENSION_TO_PROTO,
    SUPPORTED_DECODER_PROTOS,
    extractFileExtension,
    getProtoDecoderHintForFileName,
    PROTOCOL_DECODER_HINTS,
    PORT_DECODER_HINTS,
    getPacketProtocolDecoderHint,
    autoDetectProtoFromBytes,
    LOW_CONFIDENCE_DECODERS,
    LOW_CONFIDENCE_CORROBORATING_HINTS,
};
