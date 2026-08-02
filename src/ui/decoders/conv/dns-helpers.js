// Shared DNS-style name decoder used by every protocol that re-uses the
// DNS label-sequence / compression-pointer encoding. The LLMNR, mDNS, and
// NetBIOS name-service decoders all inherit this walker, so any future
// bug fix or improvement only has to land here.

const DNS_MAX_NAME_HOPS = 16;

// Decode a DNS name (label sequence) starting at `startIndex`. Supports
// compression pointers (RFC 1035 §4.1.4): the high two bits of a length
// byte are `11`, the remaining 14 bits are an offset back into the
// message. When the pointer is followed the parser keeps walking the
// *target* labels and does not re-enter the compression state, so a
// single loop is sufficient.
//
// Returns { name, endIndex, ok }.
//   * `name` is the joined label sequence ("." separator, "." for the
//     root label).
//   * `endIndex` is the index immediately after the consumed name in
//     the original message (NOT in the dereferenced message).
//   * `ok` is false when the parse went out of bounds, hit a cycle, or
//     encountered a reserved label type.
function decodeDnsName(bytes, startIndex, messageEnd) {
    if (!(bytes instanceof Uint8Array) || startIndex < 0 || startIndex >= messageEnd) {
        return { name: "", endIndex: startIndex, ok: false };
    }
    const labels = [];
    let cursor = startIndex;
    let jumping = false;
    let lastJumpEnd = -1;
    const visited = new Set();
    let jumps = 0;
    while (cursor < messageEnd) {
        if (visited.has(cursor)) return { name: "", endIndex: startIndex, ok: false };
        visited.add(cursor);
        const length = bytes[cursor];
        if (length === 0) {
            cursor += 1;
            break;
        }
        if ((length & 0xc0) === 0xc0) {
            // Compression pointer (14-bit offset). The pointer consumes
            // two bytes in the original message regardless of the jump.
            if (cursor + 1 >= messageEnd) return { name: "", endIndex: startIndex, ok: false };
            const pointer = ((length & 0x3f) << 8) | bytes[cursor + 1];
            if (pointer >= messageEnd) return { name: "", endIndex: startIndex, ok: false };
            if (!jumping) lastJumpEnd = cursor + 2;
            cursor = pointer;
            jumping = true;
            jumps += 1;
            if (jumps > DNS_MAX_NAME_HOPS) return { name: "", endIndex: startIndex, ok: false };
            continue;
        }
        if ((length & 0xc0) !== 0) {
            // Reserved label type; abort to avoid runaway parses.
            return { name: "", endIndex: startIndex, ok: false };
        }
        if (cursor + 1 + length > messageEnd) return { name: "", endIndex: startIndex, ok: false };
        let label = "";
        for (let offset = cursor + 1; offset < cursor + 1 + length; offset += 1) {
            const byte = bytes[offset];
            if (byte >= 0x20 && byte <= 0x7e) label += String.fromCharCode(byte);
            else label += `\\x${byte.toString(16).padStart(2, "0")}`;
        }
        labels.push(label);
        cursor += 1 + length;
    }
    const name = labels.join(".") || ".";
    return { name, endIndex: lastJumpEnd === -1 ? cursor : lastJumpEnd, ok: true };
}

module.exports = { decodeDnsName };
