// SSH Conv decoder: identifies an SSH banner ("SSH-<protoversion>-<software>\n")
// and reports the protocol / software version plus any trailing key-exchange bytes.

const SSH_BANNER_RE = /^SSH-([\S]+)\r?\n/;

function decodeSshFromBytes(bytes) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(
        bytes.slice(0, 512),
    );
    const bannerMatch = text.match(SSH_BANNER_RE);
    if (!bannerMatch) return null;
    const versionStr = bannerMatch[1];
    const dashIdx = versionStr.indexOf("-");
    const protocolVersion =
        dashIdx >= 0 ? versionStr.slice(0, dashIdx) : versionStr;
    const softwareVersion = dashIdx >= 0 ? versionStr.slice(dashIdx + 1) : "—";
    const fields = [
        { name: "Protocol Version", value: protocolVersion },
        { name: "Software Version", value: softwareVersion },
    ];
    const bannerEnd = text.indexOf("\n");
    if (bannerEnd > 0 && bytes.length > bannerEnd + 1) {
        fields.push({
            name: "Additional Data",
            value: `${bytes.length - bannerEnd - 1} bytes (key exchange)`,
        });
    }
    return { protocol: "SSH / OpenSSH", fields };
}

module.exports = { decodeSshFromBytes };
