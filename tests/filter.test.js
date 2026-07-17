const { filterPackets, validateFilterSyntax } = require('../src/filter');

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

describe('filter alias regression tests', () => {
    test('IPv6 filter values are parsed without truncation', () => {
        const data = buildHostData([
            {
                'Packet Info': {
                    Protocol: 'TCP',
                    IP: {
                        'ip.src.addr': '2001:db8::10',
                        'ip.dst.addr': '2001:db8::20',
                    },
                },
            },
        ]);

        expect(() => validateFilterSyntax('ip.src.addr: 2001:db8::10')).not.toThrow();
        expect(filterPackets(data, 'ip.src.addr: 2001:db8::10')).toHaveLength(1);
    });

    test('application.proto alias matches SSH packet', () => {
        const data = buildHostData([
            makePacket(),
            makePacket({
                applicationProto: 'http',
                portProtoTypo: 'http',
                withSshSection: false,
            }),
        ]);

        expect(filterPackets(data, 'application.proto: ssh')).toHaveLength(1);
    });

    test('transport.proto alias matches TCP packets', () => {
        const data = buildHostData([
            makePacket(),
            makePacket({
                applicationProto: 'http',
                portProtoTypo: 'http',
                withSshSection: false,
            }),
        ]);

        expect(filterPackets(data, 'transport.proto: tcp')).toHaveLength(2);
    });

    test('transport.proto derives TCP from section data when Protocol is FRAME', () => {
        const frameButTcpData = buildHostData([
            makePacket({
                protocol: 'FRAME',
                transportProto: '',
                withSshSection: true,
            }),
        ]);

        expect(filterPackets(frameButTcpData, 'transport.proto: tcp')).toHaveLength(1);
    });

    test('decoded-proto includes SSH when TCP SSH section exists', () => {
        const data = buildHostData([
            makePacket(),
            makePacket({
                applicationProto: 'http',
                portProtoTypo: 'http',
                withSshSection: false,
            }),
        ]);

        expect(filterPackets(data, 'decoded-proto: ssh')).toHaveLength(1);
    });

    test('application.proto falls back to legacy Port Protcol field', () => {
        const data = buildHostData([
            makePacket(),
            makePacket({
                applicationProto: 'http',
                portProtoTypo: 'http',
                withSshSection: false,
            }),
        ]);

        expect(filterPackets(data, 'application.proto: http')).toHaveLength(1);
    });

    test('application.proto prefers network data protocol when explicit fields conflict', () => {
        const conflictingAliasData = buildHostData([
            {
                'Packet Info': {
                    Protocol: 'TCP',
                    'transport.proto': 'TCP',
                    TCP: {
                        'Source port': 31337,
                        'Destination port': 2049,
                    },
                },
                'Extra Info': {
                    Traits: {
                        'Network Data': {
                            'application.proto': 'openvpn',
                            'app.proto': 'openvpn',
                            'Port Protocol': 'nfs',
                            'Port Protcol': 'nfs',
                        },
                    },
                },
            },
        ]);

        expect(filterPackets(conflictingAliasData, 'application.proto: openvpn')).toHaveLength(0);
        expect(filterPackets(conflictingAliasData, 'application.proto: nfs')).toHaveLength(1);
    });

    test('loc.src.city alias resolves nested location city', () => {
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

        expect(filterPackets(locationAliasData, 'loc.src.city: berlin')).toHaveLength(1);
    });

    test('loc.src.timezone alias resolves nested location timezone', () => {
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

        expect(
            filterPackets(locationAliasData, 'loc.src.timezone: europe/berlin')
        ).toHaveLength(1);
    });

    test('normalized-key fallback matches equivalent key spellings', () => {
        const normalizedFallbackData = buildHostData([
            {
                'Packet Info': {
                    Protocol: 'TCP',
                    'Custom Field Name': 'AlphaValue',
                },
            },
        ]);

        expect(
            filterPackets(
                normalizedFallbackData,
                'custom.field.name: alphavalue'
            )
        ).toHaveLength(1);
    });

    test('tcp.src.port alias matches nested TCP source port', () => {
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

        expect(filterPackets(portAliasData, 'tcp.src.port: 51515')).toHaveLength(1);
    });

    test('tcp.dst.port alias matches nested TCP destination port', () => {
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

        expect(filterPackets(portAliasData, 'tcp.dst.port: 443')).toHaveLength(1);
    });

    test('udp.src.port alias matches nested UDP source port', () => {
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

        expect(filterPackets(portAliasData, 'udp.src.port: 5353')).toHaveLength(1);
    });

    test('udp.dst.port alias matches nested UDP destination port', () => {
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

        expect(filterPackets(portAliasData, 'udp.dst.port: 53')).toHaveLength(1);
    });

    test('sctp.src.port alias matches nested SCTP source port', () => {
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

        expect(filterPackets(portAliasData, 'sctp.src.port: 2905')).toHaveLength(1);
    });

    test('sctp.dst.port alias matches nested SCTP destination port', () => {
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

        expect(filterPackets(portAliasData, 'sctp.dst.port: 3868')).toHaveLength(1);
    });
});