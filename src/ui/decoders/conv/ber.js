// BER Conv decoder: thin wrapper around the shared ASN.1 generic parser in
// non-strict (BER) mode.

const { decodeAsn1GenericFromBytes } = require("./asn1");

function decodeBerFromBytes(bytes) {
    return decodeAsn1GenericFromBytes(bytes, { encodingLabel: "BER", enforceDer: false });
}

module.exports = { decodeBerFromBytes };
