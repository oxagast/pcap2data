// mDNS / Bonjour Conv decoder. Bonjour uses the DNS wire format for
// multicast DNS (UDP/5353), with DNS-SD PTR/SRV/TXT records describing
// discoverable services.

const { decodeDnsFromBytes } = require("./dns");

function decodeMdnsFromBytes(bytes) {
    const decoded = decodeDnsFromBytes(bytes);
    if (!decoded) return null;
    const hasBonjourRecords = decoded.fields.some((field) => {
        if (!field || typeof field.value !== "string") return false;
        return /\s(PTR|SRV|TXT)\s/.test(field.value);
    });
    const fields = [
        { name: "Protocol Profile", value: hasBonjourRecords ? "Bonjour (DNS-SD)" : "mDNS" },
        ...decoded.fields,
    ];
    return { protocol: hasBonjourRecords ? "Bonjour (mDNS/DNS-SD)" : "mDNS", fields };
}

module.exports = { decodeMdnsFromBytes };
