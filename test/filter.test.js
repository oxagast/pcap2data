const assert = require('assert');

const { filterPackets } = require('../src/filter');

function makePacket({
    protocol = 'TCP',
    transportProto = 'TCP',
    applicationProto = 'ssh',
    portProtoTypo = 'ssh',
    withSshSection = true,
} = {}) {
    const tcpSection = withSshSection ? { SSH: { Type: 'Identification' } } : {};

    return {
        'Packet Info': {
            Protocol: protocol,
            'transport.proto': transportProto,
            TCP: tcpSection,
        },
        'Extra Info': {
            Traits: {
                'Network Data': {
                    'application.proto': applicationProto,
                    'Port Protcol': portProtoTypo,
                },
            },
        },
    };
}

function buildHostData(packets) {
    return {
        Host: {
            '1.1.1.1': packets,
        },
    };
}

function run() {
    const data = buildHostData([
        makePacket(),
        makePacket({
            applicationProto: 'http',
            portProtoTypo: 'http',
            withSshSection: false,
        }),
    ]);

    const appMatches = filterPackets(data, 'application.proto: ssh');
    assert.strictEqual(
        appMatches.length,
        1,
        'application.proto alias should match SSH packet',
    );

    const transportMatches = filterPackets(data, 'transport.proto: tcp');
    assert.strictEqual(
        transportMatches.length,
        2,
        'transport.proto alias should match TCP packets',
    );

    const frameButTcpData = buildHostData([
        makePacket({ protocol: 'FRAME', transportProto: '', withSshSection: true }),
    ]);
    const frameFallbackMatches = filterPackets(
        frameButTcpData,
        'transport.proto: tcp',
    );
    assert.strictEqual(
        frameFallbackMatches.length,
        1,
        'transport.proto alias should derive TCP from section data when Protocol is FRAME',
    );

    const decodedMatches = filterPackets(data, 'decoded-proto: ssh');
    assert.strictEqual(
        decodedMatches.length,
        1,
        'decoded-proto should include SSH when TCP SSH section exists',
    );

    const typoFallbackMatches = filterPackets(data, 'application.proto: http');
    assert.strictEqual(
        typoFallbackMatches.length,
        1,
        'application.proto alias should still work with legacy Port Protcol fallback',
    );

    console.log('filter alias regression tests passed');
}

run();
