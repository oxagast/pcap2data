// SSDP / UPnP Conv decoder for UDP/1900 discovery messages.

const SSDP_START_LINE_RE = /^(M-SEARCH|NOTIFY|HTTP\/1\.1\s+\d{3})(?:\s+(.*))?$/i;
const UPNP_MARKERS = ["upnp:rootdevice", "urn:schemas-upnp-org:", "/rootdesc.xml"];

function decodeSsdpFromBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
    let text;
    try {
        text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    } catch {
        return null;
    }
    const lines = text.replace(/\r\n/g, "\n").split("\n");
    const startLine = (lines.shift() || "").trim();
    if (!SSDP_START_LINE_RE.test(startLine)) return null;

    const headers = {};
    lines.forEach((line) => {
        const separator = line.indexOf(":");
        if (separator <= 0) return;
        const name = line.slice(0, separator).trim();
        const value = line.slice(separator + 1).trim();
        if (name && value) headers[name.toLowerCase()] = value;
    });

    const markerText = `${startLine} ${Object.values(headers).join(" ")}`.toLowerCase();
    const isUpnp = UPNP_MARKERS.some((marker) => markerText.includes(marker));
    const fields = [
        { name: "Start Line", value: startLine },
        { name: "Type", value: startLine.toUpperCase().startsWith("HTTP/") ? "Response" : startLine.split(/\s+/, 1)[0].toUpperCase() },
        { name: "Profile", value: isUpnp ? "UPnP" : "SSDP" },
    ];
    [
        ["host", "Host"], ["cache-control", "Cache-Control"], ["location", "Location"],
        ["server", "Server"], ["st", "ST"], ["nt", "NT"], ["usn", "USN"],
        ["man", "MAN"], ["mx", "MX"],
    ].forEach(([key, label]) => {
        if (headers[key]) fields.push({ name: label, value: headers[key] });
    });
    return { protocol: isUpnp ? "UPnP" : "SSDP", fields };
}

module.exports = { decodeSsdpFromBytes };
