// DER Conv decoder: thin wrapper around the shared ASN.1 generic parser in
// strict (DER) length-encoding mode.

const { decodeAsn1GenericFromBytes } = require("./asn1");

function decodeDerFromBytes(bytes) {
    return decodeAsn1GenericFromBytes(bytes, { encodingLabel: "DER", enforceDer: true });
}

module.exports = { decodeDerFromBytes };
