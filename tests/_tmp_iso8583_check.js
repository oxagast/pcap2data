const { decodeIso8583FromBytes } = require('../src/ui/decoders/conv/iso8583.js');
const { autoDetectProtoFromBytes } = require('../src/ui/decoders/conv/auto-detect.js');

const asciiHex = '6e003132303064303230303030303030326330303030303030303030303030303030303030383136313233343536373839303132333435363030303030303030353639393030303233343030343132333435202020363738393031323334202020202020';
const asciiBytes = new Uint8Array(Buffer.from(asciiHex, 'hex'));
console.log('=== ASCII sample (raw, ' + asciiBytes.length + ' bytes) ===');
console.log('auto-detect:', autoDetectProtoFromBytes(asciiBytes));
const r = decodeIso8583FromBytes(asciiBytes);
console.log('decode:', r ? r.protocol : 'null');
if (r) r.fields.forEach(f => console.log('  ' + f.name + ' = ' + f.value));

const binHex = '48001200d020000002c000000000000000000008161234567890123456000000005699000234000431323334352020203637383930313233342020202020200009424c414820424c4148';
const binBytes = new Uint8Array(Buffer.from(binHex, 'hex'));
console.log('\n=== Binary sample (raw, ' + binBytes.length + ' bytes) ===');
console.log('auto-detect:', autoDetectProtoFromBytes(binBytes));
const r2 = decodeIso8583FromBytes(binBytes);
console.log('decode:', r2 ? r2.protocol : 'null');
if (r2) r2.fields.forEach(f => console.log('  ' + f.name + ' = ' + f.value));