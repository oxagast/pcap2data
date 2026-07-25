// LDAP Conv decoder: walks a stream of ASN.1 SEQUENCEs and emits a
// (MessageID, Operation) pair for each recognized LDAP application tag.

const { parseAsn1Length } = require("./asn1");

const MAX_LDAP_MESSAGES = 100;

const LDAP_OPERATIONS = {
    0x60: "BindRequest",
    0x61: "BindResponse",
    0x62: "UnbindRequest",
    0x63: "SearchRequest",
    0x64: "SearchResEntry",
    0x65: "SearchResDone",
    0x66: "SearchResRef",
    0x67: "ModifyRequest",
    0x68: "ModifyResponse",
    0x69: "AddRequest",
    0x6a: "AddResponse",
    0x6b: "DelRequest",
    0x6c: "DelResponse",
    0x6d: "ModDNRequest",
    0x6e: "ModDNResponse",
    0x6f: "CompareRequest",
    0x70: "CompareResponse",
    0x77: "ExtendedRequest",
    0x78: "ExtendedResponse",
    0x79: "IntermediateResponse",
};

function decodeLdapFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4) return null;

    try {
        const fields = [];
        let parsedMessages = 0;
        let index = 0;

        while (index < bytes.length && parsedMessages < MAX_LDAP_MESSAGES) {
            while (index < bytes.length && bytes[index] !== 0x30) {
                index += 1;
            }
            if (index >= bytes.length) break;

            const sequenceStart = index;
            const sequenceLengthInfo = parseAsn1Length(bytes, sequenceStart + 1, bytes.length);
            if (!sequenceLengthInfo) {
                index = sequenceStart + 1;
                continue;
            }

            const sequenceValueStart = sequenceLengthInfo.nextIndex;
            const sequenceEnd = sequenceValueStart + sequenceLengthInfo.length;
            if (sequenceEnd > bytes.length) break;

            let cursor = sequenceValueStart;
            if (cursor >= sequenceEnd || bytes[cursor] !== 0x02) {
                index = sequenceStart + 1;
                continue;
            }

            const messageIdLengthInfo = parseAsn1Length(bytes, cursor + 1, sequenceEnd);
            if (!messageIdLengthInfo) {
                index = sequenceStart + 1;
                continue;
            }

            const messageIdStart = messageIdLengthInfo.nextIndex;
            const messageIdEnd = messageIdStart + messageIdLengthInfo.length;
            if (messageIdLengthInfo.length < 1 || messageIdEnd > sequenceEnd) {
                index = sequenceStart + 1;
                continue;
            }

            let messageId = 0;
            for (let offset = messageIdStart; offset < messageIdEnd; offset += 1) {
                messageId = (messageId << 8) | bytes[offset];
            }

            cursor = messageIdEnd;
            if (cursor >= sequenceEnd) {
                index = Math.max(sequenceEnd, sequenceStart + 1);
                continue;
            }

            const operationTag = bytes[cursor];
            if (operationTag < 0x60 || operationTag > 0x7f) {
                index = sequenceStart + 1;
                continue;
            }

            parsedMessages += 1;
            fields.push(
                { name: `Message ${parsedMessages} ID`, value: String(messageId) },
                {
                    name: `Message ${parsedMessages} Operation`,
                    value:
                        LDAP_OPERATIONS[operationTag] ||
                        `0x${operationTag.toString(16).padStart(2, "0").toUpperCase()}`,
                },
            );

            index = Math.max(sequenceEnd, sequenceStart + 1);
        }

        if (!fields.length) return null;
        if (parsedMessages >= MAX_LDAP_MESSAGES && index < bytes.length) {
            fields.push({
                name: "Notice",
                value: `Showing first ${MAX_LDAP_MESSAGES} LDAP messages from stream.`,
            });
        }

        return {
            protocol: "LDAP",
            fields,
        };
    } catch {
        return null;
    }
}

module.exports = { decodeLdapFromBytes };
