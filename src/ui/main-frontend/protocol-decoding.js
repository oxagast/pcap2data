// Handles protocol decoder selection and decoded output helpers in the renderer.

const {
    decodeHttpFromBytes,
    decodeTelnetFromBytes,
    decodeSshFromBytes,
    decodePop3FromBytes,
    decodeImapFromBytes,
    decodeSmtpFromBytes,
    decodeFtpFromBytes,
    decodeBerFromBytes,
    decodeDerFromBytes,
    decodeJsonFromBytes,
    decodeXmlFromBytes,
    decodeHtmlFromBytes,
    decodeYamlFromBytes,
    decodeProtobufFromBytes,
    decodeMessagePackFromBytes,
    decodeBsonFromBytes,
    decodeLdapFromBytes,
    decodeSmbFromBytes,
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
    decodeJpegFromBytes,
    decodePngFromBytes,
    decodeGifFromBytes,
    decodeWebpFromBytes,
    decodePlainTextFromBytes,
    autoDetectProtoFromBytes,
    getPacketProtocolDecoderHint,
    getImageTypeFromExifReader,
} = require("../panels/data-tools-panel");

function createProtocolDecodingHelpers({
    getDecodeUseRawConvInputOverride,
    getCurrentContextPacket,
    getCurrentPacketForExport,
    getFollowStreamPackets,
    buildStreamHex,
    parseDataToolsInput,
}) {
    function resolveDecoderInputBytes(bytes) {
        if (!(bytes instanceof Uint8Array) || bytes.length === 0) return bytes;

        if (getDecodeUseRawConvInputOverride()) {
            return bytes;
        }

        const contextPacket = getCurrentContextPacket() || getCurrentPacketForExport();
        const streamPackets = getFollowStreamPackets(contextPacket);
        if (!Array.isArray(streamPackets) || streamPackets.length === 0) return bytes;

        const streamHex = buildStreamHex(streamPackets);
        if (!streamHex) return bytes;

        try {
            return parseDataToolsInput("hex", streamHex);
        } catch {
            return bytes;
        }
    }

    function renderProtoDecoderOutput(result, selectedProtocol, protocol) {
        const protoOutput = document.getElementById("data-tools-proto-output");
        if (!protoOutput) return;
        protoOutput.innerHTML = "";
        if (!result) {
            const span = document.createElement("span");
            span.className = "data-tools-proto-none";
            span.textContent =
                selectedProtocol === "auto"
                    ? "No known protocol detected"
                    : `Could not decode as ${(protocol || selectedProtocol).toUpperCase()}`;
            protoOutput.appendChild(span);
            return;
        }
        const table = document.createElement("table");
        table.className = "data-tools-proto-table";
        const headerRow = document.createElement("tr");
        const th1 = document.createElement("th");
        th1.textContent = `${result.protocol} Field`;
        const th2 = document.createElement("th");
        th2.textContent = "Value";
        headerRow.appendChild(th1);
        headerRow.appendChild(th2);
        table.appendChild(headerRow);
        result.fields.forEach((field) => {
            const tr = document.createElement("tr");
            const tdName = document.createElement("td");
            tdName.textContent = field.name;
            const tdVal = document.createElement("td");
            // ISO 8583 field values are often BCD-packed or binary; render
            // them as hex so the user sees the actual bytes, not garbled
            // ASCII. Field names like "Field 2 (PAN)" match this pattern.
            if (/^Field \d+/.test(field.name)) {
                tdVal.textContent = field.value;
                tdVal.className = "data-tools-proto-hex";
            } else {
                tdVal.textContent = field.value;
            }
            tr.appendChild(tdName);
            tr.appendChild(tdVal);
            table.appendChild(tr);
        });
        protoOutput.appendChild(table);
    }

    function decodeProtocolBytes(protocol, bytes) {
        switch (protocol) {
            case "http":
                return decodeHttpFromBytes(bytes);
            case "telnet":
                return decodeTelnetFromBytes(bytes);
            case "ssh":
                return decodeSshFromBytes(bytes);
            case "pop3":
                return decodePop3FromBytes(bytes);
            case "imap":
                return decodeImapFromBytes(bytes);
            case "smtp":
                return decodeSmtpFromBytes(bytes);
            case "ftp":
                return decodeFtpFromBytes(bytes);
            case "ber":
                return decodeBerFromBytes(bytes);
            case "der":
                return decodeDerFromBytes(bytes);
            case "json":
                return decodeJsonFromBytes(bytes);
            case "xml":
                return decodeXmlFromBytes(bytes);
            case "html":
                return decodeHtmlFromBytes(bytes);
            case "yaml":
                return decodeYamlFromBytes(bytes);
            case "protobuf":
                return decodeProtobufFromBytes(bytes);
            case "msgpack":
                return decodeMessagePackFromBytes(bytes);
            case "bson":
                return decodeBsonFromBytes(bytes);
            case "ldap":
                return decodeLdapFromBytes(bytes);
            case "smb":
                return decodeSmbFromBytes(bytes);
            case "sip":
                return decodeSipFromBytes(bytes);
            case "smpp":
                return decodeSmppFromBytes(bytes);
            case "soulseek":
                return decodeSoulseekFromBytes(bytes);
            case "bittorrent":
                return decodeBittorrentFromBytes(bytes);
            case "kerberos":
                return decodeKerberosFromBytes(bytes);
            case "dns":
                return decodeDnsFromBytes(bytes);
            case "snmp":
                return decodeSnmpFromBytes(bytes);
            case "dhcp":
                return decodeDhcpFromBytes(bytes);
            case "dhcpv6":
                return decodeDhcpv6FromBytes(bytes);
            case "iso8583":
                return decodeIso8583FromBytes(bytes);
            case "jpeg":
                return decodeJpegFromBytes(bytes);
            case "png":
                return decodePngFromBytes(bytes);
            case "gif":
                return decodeGifFromBytes(bytes);
            case "webp":
                return decodeWebpFromBytes(bytes);
            case "plaintext":
                return decodePlainTextFromBytes(bytes);
            default:
                return null;
        }
    }

    function runProtoDecoder(bytes) {
        const decodeBytes = resolveDecoderInputBytes(bytes);
        const selectEl = document.getElementById("data-tools-proto-select");
        const selectedProtocol = selectEl ? selectEl.value : "auto";
        let protocol = selectedProtocol;
        if (protocol === "auto") {
            const contextPacket = getCurrentContextPacket() || getCurrentPacketForExport();
            const { protocolHint, portHint } = getPacketProtocolDecoderHint(contextPacket);
            protocol = autoDetectProtoFromBytes(decodeBytes, {
                protocolHint,
                portHint,
            });
            if (selectEl && protocol && selectEl.value !== protocol) {
                selectEl.value = protocol;
            }
        }

        let result = null;
        const actualImageType = getImageTypeFromExifReader(decodeBytes);
        const isImageProtocolSelected = ["jpeg", "png", "gif", "webp"].includes(protocol);
        if (isImageProtocolSelected && actualImageType && actualImageType !== protocol) {
            renderProtoDecoderOutput(null, selectedProtocol, protocol);
            return;
        }

        result = protocol ? decodeProtocolBytes(protocol, decodeBytes) : null;
        renderProtoDecoderOutput(result, selectedProtocol, result ? protocol : null);
    }

    function clearProtoDecoderOutput() {
        const protoOutput = document.getElementById("data-tools-proto-output");
        if (protoOutput) protoOutput.innerHTML = "";
    }

    return {
        decodeHttpFromBytes,
        decodeSmbFromBytes,
        autoDetectProtoFromBytes,
        resolveDecoderInputBytes,
        renderProtoDecoderOutput,
        runProtoDecoder,
        clearProtoDecoderOutput,
        getPacketProtocolDecoderHint,
    };
}

module.exports = {
    createProtocolDecodingHelpers,
};