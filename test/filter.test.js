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

    const locationAliasData = buildHostData([
        {
            'Packet Info': {
                Protocol: 'TCP',
            },
            'Extra Info': {
                Traits: {
                    'Network Data': {
                        'Source IP': {
                            Location: {
                                City: 'Berlin',
                                Country: 'Germany',
                                'Time Zone': 'Europe/Berlin',
                            },
                        },
                        'Destination IP': {
                            Location: {
                                City: 'Paris',
                                Country: 'France',
                            },
                        },
                    },
                },
            },
        },
    ]);

    const locationCityMatches = filterPackets(locationAliasData, 'loc.src.city: berlin');
    assert.strictEqual(
        locationCityMatches.length,
        1,
        'loc.src.city alias should resolve nested Source IP Location city values',
    );

    const locationTzMatches = filterPackets(locationAliasData, 'loc.src.timezone: europe/berlin');
    assert.strictEqual(
        locationTzMatches.length,
        1,
        'loc.src.timezone alias should resolve nested Source IP Location time zone values',
    );

    const normalizedFallbackData = buildHostData([
        {
            'Packet Info': {
                Protocol: 'TCP',
                'Custom Field Name': 'AlphaValue',
            },
        },
    ]);

    const normalizedFallbackMatches = filterPackets(
        normalizedFallbackData,
        'custom.field.name: alphavalue',
    );
    assert.strictEqual(
        normalizedFallbackMatches.length,
        1,
        'normalized-key fallback should match equivalent key spellings',
    );

    const portAliasData = buildHostData([
        {
            'Packet Info': {
                Protocol: 'TCP',
                TCP: {
                    'Source port': 51515,
                    'Destination port': 443,
                },
            },
        },
        {
            'Packet Info': {
                Protocol: 'UDP',
                UDP: {
                    'Source port': 5353,
                    'Destination port': 53,
                },
            },
        },
        {
            'Packet Info': {
                Protocol: 'SCTP',
                SCTP: {
                    'Source port': 2905,
                    'Destination port': 3868,
                },
            },
        },
    ]);

    assert.strictEqual(
        filterPackets(portAliasData, 'tcp.src.port: 51515').length,
        1,
        'tcp.src.port alias should match nested TCP source port values',
    );
    assert.strictEqual(
        filterPackets(portAliasData, 'tcp.dst.port: 443').length,
        1,
        'tcp.dst.port alias should match nested TCP destination port values',
    );
    assert.strictEqual(
        filterPackets(portAliasData, 'udp.src.port: 5353').length,
        1,
        'udp.src.port alias should match nested UDP source port values',
    );
    assert.strictEqual(
        filterPackets(portAliasData, 'udp.dst.port: 53').length,
        1,
        'udp.dst.port alias should match nested UDP destination port values',
    );
    assert.strictEqual(
        filterPackets(portAliasData, 'sctp.src.port: 2905').length,
        1,
        'sctp.src.port alias should match nested SCTP source port values',
    );
    assert.strictEqual(
        filterPackets(portAliasData, 'sctp.dst.port: 3868').length,
        1,
        'sctp.dst.port alias should match nested SCTP destination port values',
    );

    console.log('filter alias regression tests passed');
}

run();
