// Shared ASN.1 length / tag / generic-tree helpers used by BER, DER, and
// LDAP decoders. encodeDer may flip encodeDer for stricter length encoding.

function parseAsn1Length(buffer, startIndex, endIndex, enforceDer = false) {
    if (!(buffer instanceof Uint8Array)) return null;
    if (startIndex >= endIndex) return null;
    const firstByte = buffer[startIndex];
    if ((firstByte & 0x80) === 0) {
        return { length: firstByte, nextIndex: startIndex + 1 };
    }

    const octetCount = firstByte & 0x7f;
    if (octetCount === 0 || octetCount > 4) return null;
    if (startIndex + octetCount >= endIndex) return null;

    if (enforceDer && octetCount === 1 && buffer[startIndex + 1] < 0x80) {
        return null;
    }

    let length = 0;
    for (let offset = 1; offset <= octetCount; offset += 1) {
        const byteValue = buffer[startIndex + offset];
        if (enforceDer && offset === 1 && byteValue === 0x00) {
            return null;
        }
        length = (length << 8) | byteValue;
    }
    return {
        length,
        nextIndex: startIndex + 1 + octetCount,
    };
}

function getAsn1TagDescription(tagByte) {
    const tagClass = (tagByte & 0xc0) >> 6;
    const classLabel = ["Universal", "Application", "Context-specific", "Private"][tagClass] || "Unknown";
    const constructed = Boolean(tagByte & 0x20);
    const tagNumber = tagByte & 0x1f;
    return {
        classLabel,
        constructed,
        tagNumber,
        tagHex: `0x${tagByte.toString(16).padStart(2, "0").toUpperCase()}`,
    };
}

function decodeAsn1GenericFromBytes(bytes, { encodingLabel = "BER", enforceDer = false } = {}) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 2) return null;

    // Strict gate for auto-detection: ASN.1/BER/DER is extremely permissive
    // (any tag byte + any length is syntactically valid), so merely parsing
    // TLV triples doesn't distinguish real ASN.1 from arbitrary binary data.
    // We require:
    //
    //   1. The first node must be a **Universal-class** tag (tagByte & 0xC0
    //      === 0x00). Context-specific (0x80) and Private (0xC0) class tags
    //      are valid ASN.1 but are almost never the first byte of a
    //      standalone ASN.1 document — they appear inside protocol-specific
    //      wrappers (LDAP, SNMP, Kerberos, X.509). If the first byte is
    //      context-specific or private, it's likely random binary data that
    //      happens to parse, not a real ASN.1 structure.
    //   2. The entire input must be consumed as valid TLV nodes — no
    //      trailing garbage bytes.
    //
    // This makes the decoder suitable for auto-detection without a "force"
    // flag: random binary data will usually have a non-universal first byte
    // or leave trailing bytes, causing the decoder to return null.
    const firstTagByte = bytes[0];
    const firstTagClass = (firstTagByte & 0xc0) >> 6;
    if (firstTagClass !== 0) return null; // 0 = Universal class

    const fields = [];
    const maxNodes = 100;
    let parsedNodes = 0;
    let index = 0;

    while (index < bytes.length && parsedNodes < maxNodes) {
        const tagByte = bytes[index];
        const lengthInfo = parseAsn1Length(bytes, index + 1, bytes.length, enforceDer);
        if (!lengthInfo) {
            index += 1;
            continue;
        }

        const valueStart = lengthInfo.nextIndex;
        const valueEnd = valueStart + lengthInfo.length;
        if (valueEnd > bytes.length) break;

        parsedNodes += 1;
        const tagInfo = getAsn1TagDescription(tagByte);
        fields.push(
            {
                name: `Node ${parsedNodes} Tag`,
                value: `${tagInfo.tagHex} (${tagInfo.classLabel}, ${tagInfo.constructed ? "Constructed" : "Primitive"}, #${tagInfo.tagNumber})`,
            },
            { name: `Node ${parsedNodes} Length`, value: String(lengthInfo.length) },
        );

        if (lengthInfo.length > 0) {
            const previewBytes = bytes.slice(valueStart, Math.min(valueEnd, valueStart + 32));
            const previewHex = Array.from(previewBytes, (byteValue) =>
                byteValue.toString(16).padStart(2, "0"),
            ).join(" ");
            fields.push({
                name: `Node ${parsedNodes} Value (hex preview)`,
                value: valueEnd - valueStart > 32 ? `${previewHex} …` : previewHex,
            });
        }

        index = Math.max(valueEnd, index + 1);
    }

    if (!fields.length) return null;

    // Strict: the entire input must be consumed. Trailing bytes mean the
    // input isn't a clean ASN.1 structure — it's probably some other binary
    // format that happened to parse partially.
    if (index !== bytes.length) return null;

    if (parsedNodes >= maxNodes && index < bytes.length) {
        fields.push({
            name: "Notice",
            value: `Showing first ${maxNodes} ASN.1 nodes from stream.`,
        });
    }
    return {
        protocol: `ASN.1 ${encodingLabel}`,
        fields,
    };
}

module.exports = {
    parseAsn1Length,
    getAsn1TagDescription,
    decodeAsn1GenericFromBytes,
};
