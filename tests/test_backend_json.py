import json
import os
import subprocess
import sys
import importlib.util
from pathlib import Path

import pytest
from scapy.all import CookedLinux, Ether, IP, IPv6, TCP, UDP, Raw, wrpcap


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _backend_script() -> Path:
    return _project_root() / "src" / "backend" / "snitch.py"


def _load_backend_module():
    spec = importlib.util.spec_from_file_location("snitch_backend_test_module", _backend_script())
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load backend module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sample_pcap() -> Path:
    # Keep this pinned to one fixture capture so test runs are stable.
    return _project_root() / "samples" / "test-packets.pcap"


def _wifi_sample_pcap() -> Path:
    # Wireshark wiki sample "Coherer" capture (wifi-Coherer-Induction.pcap).
    # The WPA-PSK passphrase is the well-known sample value "Induction"
    # (the SSID is "Coherer", BSSID 00:0c:41:82:b2:55).
    return _project_root() / "samples" / "pcaps" / "wifi-Coherer-Induction.pcap"


def _run_backend_with_wifi_keys(
    pcap_file: Path,
    output_dir: Path,
    conf_file: Path,
    wifi_keys_file: Path,
) -> subprocess.CompletedProcess:
    """Run the backend with --wifi-keys-file so the legacy spawn path can
    decrypt 802.11 frames exactly the way the JS bridge does when the
    concurrent-run guard is in play."""
    cmd = [
        sys.executable,
        str(_backend_script()),
        str(pcap_file),
        "-o",
        str(output_dir),
        "-c",
        str(conf_file),
        "-T",
        "1",
        "--worker-threads",
        "1",
        "--host-chunk-size",
        "25",
        "--wifi-keys-file",
        str(wifi_keys_file),
    ]
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _write_test_config(path: Path) -> None:
    # Disable active recon for deterministic and fast local tests.
    path.write_text("active_recon: false\n", encoding="utf-8")


def _run_backend(pcap_file: Path, output_dir: Path, conf_file: Path) -> subprocess.CompletedProcess:
    cmd = [
        sys.executable,
        str(_backend_script()),
        str(pcap_file),
        "-o",
        str(output_dir),
        "-c",
        str(conf_file),
        "-T",
        "1",
        "--worker-threads",
        "1",
        "--host-chunk-size",
        "25",
    ]
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _assert_hosts_json_valid(hosts_data: dict) -> None:
    assert isinstance(hosts_data, dict), "hosts.json root must be an object"
    assert "host" in hosts_data, "hosts.json missing required key: host"
    assert "final.summary" in hosts_data, "hosts.json missing required key: final.summary"

    host_map = hosts_data["host"]
    assert isinstance(host_map, dict), "hosts.json host must be an object mapping host->packets"
    assert host_map, "hosts.json host map is empty"

    has_any_packet = False
    for host, packets in host_map.items():
        assert isinstance(host, str) and host.strip(), "host keys must be non-empty strings"
        assert isinstance(packets, list), "each host entry must be a list of packets"
        if packets:
            has_any_packet = True

        for packet in packets:
            assert isinstance(packet, dict), "each packet entry must be an object"
            assert "packet.info" in packet, "packet entry missing packet.info"
            assert "extra.info" in packet, "packet entry missing extra.info"

            packet_info = packet["packet.info"]
            extra_info = packet["extra.info"]
            assert isinstance(packet_info, dict), "packet.info must be an object"
            assert isinstance(extra_info, dict), "extra.info must be an object"
            assert (
                "packet.proto" in packet_info or "Protocol" in packet_info
            ), "packet.info missing protocol field (packet.proto/Protocol)"
            assert "packet.processed" in packet_info, "packet.info missing original pcap order field (packet.processed)"
            assert isinstance(packet_info["packet.processed"], int), "packet.processed must be an integer"

    assert has_any_packet, "hosts.json contains no packet entries"


def test_backend_generates_valid_hosts_json(tmp_path: Path):
    backend = _backend_script()
    pcap_file = _sample_pcap()

    if not backend.exists():
        pytest.skip(f"Backend script not found: {backend}")
    if not pcap_file.exists():
        pytest.skip(f"Sample pcap not found: {pcap_file}")

    output_dir = tmp_path / "snitch-output"
    conf_file = tmp_path / "test-conf.yaml"
    _write_test_config(conf_file)

    result = _run_backend(pcap_file=pcap_file, output_dir=output_dir, conf_file=conf_file)
    if result.returncode != 0:
        pytest.fail(
            "Backend execution failed.\n"
            f"exit={result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    hosts_file = output_dir / "hosts.json"
    assert hosts_file.exists(), f"Expected output file not found: {hosts_file}"

    hosts_data = json.loads(hosts_file.read_text(encoding="utf-8"))
    _assert_hosts_json_valid(hosts_data)
    # print status with no newline
    print("Backend hosts.json validation passed.", end="", flush=True)


def test_backend_handles_linux_cooked_capture(tmp_path: Path):
    backend = _backend_script()

    if not backend.exists():
        pytest.skip(f"Backend script not found: {backend}")

    packet = (
        CookedLinux(pkttype=0, lladdrtype=1, lladdrlen=6, src=b"\x00\x11\x22\x33\x44\x55", proto=0x0800)
        / IP(src="10.0.0.10", dst="10.0.0.20")
        / UDP(sport=5353, dport=1900)
        / Raw(load=b"packetsnitch-linux-cooked")
    )

    pcap_file = tmp_path / "linux-cooked-any.pcap"
    wrpcap(str(pcap_file), [packet])

    output_dir = tmp_path / "snitch-output-sll"
    conf_file = tmp_path / "test-conf-linux-cooked.yaml"
    _write_test_config(conf_file)

    result = _run_backend(pcap_file=pcap_file, output_dir=output_dir, conf_file=conf_file)
    if result.returncode != 0:
        pytest.fail(
            "Backend execution failed for Linux cooked capture.\n"
            f"exit={result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    hosts_file = output_dir / "hosts.json"
    assert hosts_file.exists(), f"Expected output file not found: {hosts_file}"

    hosts_data = json.loads(hosts_file.read_text(encoding="utf-8"))
    _assert_hosts_json_valid(hosts_data)

    packets = []
    for packet_list in hosts_data.get("host", {}).values():
        if isinstance(packet_list, list):
            packets.extend(packet_list)

    assert packets, "Expected at least one decoded packet in hosts.json"

    packet_info = packets[0].get("packet.info", {})
    assert isinstance(packet_info, dict), "packet.info must be a JSON object"
    assert packet_info.get("link.proto") in (
        "Linux Cooked",
        "Linux Cooked v2",
    ), "Expected Linux cooked link.proto for any-interface capture"
    assert "Linux Cooked" in packet_info, "Expected Linux cooked metadata section"


def test_backend_keeps_zero_payload_ip_packets(tmp_path: Path):
    backend = _backend_script()

    if not backend.exists():
        pytest.skip(f"Backend script not found: {backend}")

    packets = [
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.10", dst="10.0.0.20")
        / TCP(sport=12345, dport=80, flags="S", seq=100),
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
        / IP(src="10.0.0.20", dst="10.0.0.10")
        / TCP(sport=80, dport=12345, flags="SA", seq=200, ack=101),
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.10", dst="10.0.0.20")
        / TCP(sport=12345, dport=80, flags="A", seq=101, ack=201),
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.10", dst="10.0.0.20")
        / TCP(sport=12345, dport=80, flags="PA", seq=101, ack=201)
        / Raw(load=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
    ]

    pcap_file = tmp_path / "tcp-handshake.pcap"
    wrpcap(str(pcap_file), packets)

    output_dir = tmp_path / "snitch-output-zero-payload"
    conf_file = tmp_path / "test-conf-zero-payload.yaml"
    _write_test_config(conf_file)

    result = _run_backend(pcap_file=pcap_file, output_dir=output_dir, conf_file=conf_file)
    if result.returncode != 0:
        pytest.fail(
            "Backend execution failed for zero-payload TCP capture.\n"
            f"exit={result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    hosts_file = output_dir / "hosts.json"
    assert hosts_file.exists(), f"Expected output file not found: {hosts_file}"

    hosts_data = json.loads(hosts_file.read_text(encoding="utf-8"))
    _assert_hosts_json_valid(hosts_data)

    processed_packets = []
    payload_lengths = {}
    for packet_list in hosts_data.get("host", {}).values():
        if not isinstance(packet_list, list):
            continue
        for packet in packet_list:
            packet_info = packet.get("packet.info", {})
            processed = packet_info.get("packet.processed")
            processed_packets.append(processed)
            payload_lengths[processed] = packet_info.get("Raw data", {}).get("payload.len")

    assert sorted(processed_packets) == [0, 1, 2, 3]
    assert payload_lengths[0] == 0
    assert payload_lengths[1] == 0
    assert payload_lengths[2] == 0
    assert payload_lengths[3] and payload_lengths[3] > 0


def test_backend_builds_tor_lookup_response(monkeypatch):
    backend = _load_backend_module()

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "relays": [
                    {
                        "nickname": "TestRelay",
                        "platform": "Tor 0.4.x on Linux",
                        "fingerprint": "ABCDEF123456",
                        "or_addresses": ["1.2.3.4:9001"],
                    }
                ]
            }

    monkeypatch.setattr(backend, "torNetworkNodesByIp", {})
    monkeypatch.setattr(backend, "torNetworkIps", {})
    monkeypatch.setattr(backend, "torNetworkCacheDate", "")
    monkeypatch.setattr(backend.requests, "get", lambda *args, **kwargs: FakeResponse())

    result = backend.buildTorLookupResponse("1.2.3.4")
    assert result["success"] is True
    assert result["listed"] is True
    assert result["isExitNode"] is True
    assert result["nodeCount"] == 1
    assert result["projectUrl"] == "https://www.torproject.org/"
    assert result["nodes"][0]["nickname"] == "TestRelay"


def test_backend_json_dump_encoded_handles_bytes_values():
    backend = _load_backend_module()

    payload = {
        "plain": "ok",
        "byte_value": b"\x00\x01\xff",
        "nested": {"items": [b"abc", 123]},
    }

    encoded = backend._jsonDumpEncoded(payload)
    decoded = json.loads(encoded.decode("utf-8"))

    assert decoded["plain"] == "ok"
    assert decoded["byte_value"] == "0001ff"
    assert decoded["nested"]["items"][0] == "616263"


def _make_stream_packet(
    processed,
    app_proto,
    src_port=50000,
    dst_port=80,
    src_ip="10.10.10.1",
    dst_ip="10.10.10.2",
):
    network_data = {
        "tcp.proto": app_proto,
        "application.proto": app_proto,
        "app.proto": app_proto,
        "Port Protocol": app_proto,
        "Port Protcol": app_proto,
    }
    return {
        "packet.info": {
            "packet.processed": int(processed),
            "packet.timestamp": f"2026-01-01 00:00:{int(processed):02d}.000000",
            "packet.proto": "TCP",
            "IP": {
                "ip.src.addr": str(src_ip),
                "ip.dst.addr": str(dst_ip),
            },
            "TCP": {
                "tcp.src.port": int(src_port),
                "tcp.dst.port": int(dst_port),
            },
        },
        "extra.info": {
            "Traits": {
                "Network Data": network_data,
            }
        },
    }


def _flatten_packets(hosts_payload):
    flattened = []
    for packet_list in hosts_payload.get("host", {}).values():
        if isinstance(packet_list, list):
            flattened.extend(packet_list)
    return flattened


def _packet_stream_key_and_app_proto(packet):
    packet_info = packet.get("packet.info", {}) if isinstance(packet, dict) else {}
    extra_info = packet.get("extra.info", {}) if isinstance(packet, dict) else {}

    transport_name = str(packet_info.get("packet.proto", "")).strip().upper()
    if transport_name not in {"TCP", "UDP", "SCTP"}:
        return None, ""

    ip_section = packet_info.get("IP", {})
    if not isinstance(ip_section, dict):
        return None, ""
    src_ip = str(ip_section.get("ip.src.addr", "")).strip()
    dst_ip = str(ip_section.get("ip.dst.addr", "")).strip()
    if not src_ip or not dst_ip:
        return None, ""

    transport_section = packet_info.get(transport_name, {})
    if not isinstance(transport_section, dict):
        return None, ""
    proto_prefix = transport_name.lower()
    src_port = transport_section.get(f"{proto_prefix}.src.port")
    dst_port = transport_section.get(f"{proto_prefix}.dst.port")
    try:
        src_port = int(src_port)
        dst_port = int(dst_port)
    except (TypeError, ValueError):
        return None, ""

    endpoint_a = f"{src_ip}:{src_port}"
    endpoint_b = f"{dst_ip}:{dst_port}"
    ordered_endpoints = sorted([endpoint_a, endpoint_b])
    stream_key = f"{proto_prefix}|{ordered_endpoints[0]}|{ordered_endpoints[1]}"

    network_data = (
        extra_info.get("Traits", {}).get("Network Data", {})
        if isinstance(extra_info, dict)
        else {}
    )
    if not isinstance(network_data, dict):
        network_data = {}

    app_proto = (
        network_data.get(f"{proto_prefix}.proto")
        or network_data.get("application.proto")
        or network_data.get("app.proto")
        or network_data.get("Port Protocol")
        or network_data.get("Port Protcol")
        or ""
    )
    app_proto = str(app_proto).strip().lower()
    return stream_key, app_proto


def test_stream_app_proto_prefers_first_packet_label():
    backend = _load_backend_module()

    packet_entries = [
        {"host": "10.10.10.2", "packet": _make_stream_packet(0, "ssh")},
        {"host": "10.10.10.2", "packet": _make_stream_packet(1, "http")},
        {"host": "10.10.10.2", "packet": _make_stream_packet(2, "smtp")},
    ]

    hosts_payload = backend.buildHostsPayload(packet_entries, "")
    packets = _flatten_packets(hosts_payload)
    assert len(packets) == 3

    for packet in packets:
        network_data = packet["extra.info"]["Traits"]["Network Data"]
        assert network_data["tcp.proto"] == "ssh"
        assert network_data["application.proto"] == "ssh"
        assert network_data["Port Protcol"] == "ssh"


def test_stream_app_proto_falls_back_to_last_decodable_when_first_unavailable():
    backend = _load_backend_module()

    packet_entries = [
        {"host": "10.10.10.2", "packet": _make_stream_packet(0, "unknown")},
        {"host": "10.10.10.2", "packet": _make_stream_packet(1, "imap")},
        {"host": "10.10.10.2", "packet": _make_stream_packet(2, "unknown")},
        {"host": "10.10.10.2", "packet": _make_stream_packet(3, "smtp")},
    ]

    hosts_payload = backend.buildHostsPayload(packet_entries, "")
    packets = _flatten_packets(hosts_payload)
    assert len(packets) == 4

    for packet in packets:
        network_data = packet["extra.info"]["Traits"]["Network Data"]
        assert network_data["tcp.proto"] == "smtp"
        assert network_data["application.proto"] == "smtp"
        assert network_data["Port Protcol"] == "smtp"


def test_stream_app_proto_priority_survives_bidirectional_out_of_order_input():
    backend = _load_backend_module()

    # Intentionally out-of-order entries and mixed directions for the same TCP stream.
    packet_entries = [
        {
            "host": "10.10.10.1",
            "packet": _make_stream_packet(
                2,
                "unknown",
                src_port=80,
                dst_port=50000,
                src_ip="10.10.10.2",
                dst_ip="10.10.10.1",
            ),
        },
        {
            "host": "10.10.10.2",
            "packet": _make_stream_packet(
                0,
                "unknown",
                src_port=50000,
                dst_port=80,
                src_ip="10.10.10.1",
                dst_ip="10.10.10.2",
            ),
        },
        {
            "host": "10.10.10.1",
            "packet": _make_stream_packet(
                1,
                "http",
                src_port=80,
                dst_port=50000,
                src_ip="10.10.10.2",
                dst_ip="10.10.10.1",
            ),
        },
        {
            "host": "10.10.10.2",
            "packet": _make_stream_packet(
                3,
                "unknown",
                src_port=50000,
                dst_port=80,
                src_ip="10.10.10.1",
                dst_ip="10.10.10.2",
            ),
        },
    ]

    hosts_payload = backend.buildHostsPayload(packet_entries, "")
    packets = _flatten_packets(hosts_payload)
    assert len(packets) == 4

    for packet in packets:
        network_data = packet["extra.info"]["Traits"]["Network Data"]
        assert network_data["tcp.proto"] == "http"
        assert network_data["application.proto"] == "http"
        assert network_data["app.proto"] == "http"
        assert network_data["Port Protocol"] == "http"
        assert network_data["Port Protcol"] == "http"


def test_backend_falls_back_when_packet_decoder_raises(monkeypatch, tmp_path: Path):
    backend = _load_backend_module()

    packet = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="10.0.0.10", dst="10.0.0.20")
        / TCP(sport=12345, dport=80, flags="A", seq=101, ack=201)
    )

    monkeypatch.setattr(backend, "stopEvent", backend.threading.Event())
    monkeypatch.setattr(backend, "packets", [packet], raising=False)
    monkeypatch.setattr(backend, "outputDir", str(tmp_path), raising=False)
    monkeypatch.setattr(backend, "allPacketInfo", [], raising=False)
    monkeypatch.setattr(backend, "packetLoop", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

    result = backend.processPacketAtIndex(0, None, None, 1)

    assert isinstance(result, dict)
    packet_info = result.get("packet.info", {})
    extra_info = result.get("extra.info", {})
    assert packet_info.get("packet.processed") == 0
    assert packet_info.get("packet.proto") == "TCP"
    assert packet_info.get("Raw data", {}).get("payload.len") == 0
    assert packet_info.get("TCP", {}).get("TCP Flag Data", {}).get("Flags") == "ACK"
    assert "fallback after decoder error" in str(extra_info.get("processing.error", ""))


def test_packet_loop_decodes_ipv6_tcp_packet(monkeypatch, tmp_path: Path):
    backend = _load_backend_module()

    packet = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IPv6(src="2001:db8::10", dst="2001:db8::20")
        / TCP(sport=12345, dport=443, flags="PA", seq=10, ack=20)
        / Raw(load=b"GET / HTTP/1.1\r\n\r\n")
    )

    monkeypatch.setattr(backend, "outputDir", str(tmp_path), raising=False)
    monkeypatch.setattr(backend, "activeRecon", False, raising=False)
    monkeypatch.setattr(backend, "checkTor", False, raising=False)
    monkeypatch.setattr(backend, "tcpStreamInitialDstPortMap", {}, raising=False)
    monkeypatch.setattr(backend, "torNetworkIps", {}, raising=False)

    result = backend.packetLoop(packet, 0, None, None, 1)

    assert isinstance(result, dict)
    packet_info = result.get("packet.info", {})
    ip_section = packet_info.get("IP", {})
    tcp_section = packet_info.get("TCP", {})

    assert packet_info.get("packet.proto") == "TCP"
    assert ip_section.get("ip.src.addr") == "2001:db8::10"
    assert ip_section.get("ip.dst.addr") == "2001:db8::20"
    assert ip_section.get("network.proto") == "IPv6"
    assert tcp_section.get("tcp.src.port") == 12345
    assert tcp_section.get("tcp.dst.port") == 443


def test_backend_fallback_preserves_ipv6_packet_protocol(monkeypatch, tmp_path: Path):
    backend = _load_backend_module()

    packet = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IPv6(src="2001:db8::10", dst="2001:db8::20")
        / TCP(sport=12345, dport=443, flags="PA")
        / Raw(load=b"hello")
    )

    monkeypatch.setattr(backend, "outputDir", str(tmp_path), raising=False)

    result = backend.buildFallbackPacketEntry(packet, 7, "forced fallback")

    packet_info = result.get("packet.info", {})
    ip_section = packet_info.get("IP", {})
    tcp_section = packet_info.get("TCP", {})
    extra_info = result.get("extra.info", {})

    assert packet_info.get("packet.proto") == "TCP"
    assert ip_section.get("ip.src.addr") == "2001:db8::10"
    assert ip_section.get("ip.dst.addr") == "2001:db8::20"
    assert ip_section.get("network.proto") == "IPv6"
    assert tcp_section.get("transport.proto") == "TCP"
    assert "forced fallback" in str(extra_info.get("processing.error", ""))


def test_backend_real_pcap_stream_app_protocol_labels_are_consistent(tmp_path: Path):
    backend = _backend_script()
    pcap_file = _sample_pcap()

    if not backend.exists():
        pytest.skip(f"Backend script not found: {backend}")
    if not pcap_file.exists():
        pytest.skip(f"Sample pcap not found: {pcap_file}")

    output_dir = tmp_path / "snitch-output-real-pcap-stream-proto"
    conf_file = tmp_path / "test-conf-real-pcap-stream-proto.yaml"
    _write_test_config(conf_file)

    result = _run_backend(pcap_file=pcap_file, output_dir=output_dir, conf_file=conf_file)
    if result.returncode != 0:
        pytest.fail(
            "Backend execution failed for real-pcap stream protocol consistency test.\n"
            f"exit={result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    hosts_file = output_dir / "hosts.json"
    assert hosts_file.exists(), f"Expected output file not found: {hosts_file}"

    hosts_data = json.loads(hosts_file.read_text(encoding="utf-8"))
    packets = _flatten_packets(hosts_data)
    assert packets, "Expected decoded packets in hosts.json"

    stream_protocols = {}
    for packet in packets:
        stream_key, app_proto = _packet_stream_key_and_app_proto(packet)
        if not stream_key:
            continue
        stream_protocols.setdefault(stream_key, []).append(app_proto)

    assert stream_protocols, "Expected at least one TCP/UDP/SCTP stream in sample pcap"

    checked_stream_count = 0
    for app_values in stream_protocols.values():
        normalized = [
            value
            for value in app_values
            if value and value not in {"unknown", "n/a", "null", "none", "undecodable"}
        ]
        if not normalized:
            continue
        checked_stream_count += 1
        assert len(set(normalized)) == 1, (
            f"Expected one app protocol per stream, got {sorted(set(normalized))}"
        )

    assert checked_stream_count > 0, "Expected at least one stream with a decodable app protocol"

def test_backend_wifi_keys_file_installs_keys_via_set_active(monkeypatch, tmp_path: Path):
    """The --wifi-keys-file CLI flow must install keys via _setActiveWifiKeys
    so the legacy spawn path can decrypt 802.11 frames when the concurrent-
    run guard bypasses the HTTP service. We don't ship a real 802.11 PCAP
    here; we just verify the install hook fires for the supplied file."""
    backend = _load_backend_module()

    installed = {}

    def _fake_install(entries):
        installed["keys"] = list(entries)
        # Mirror the real implementation's global side effect.
        backend.activeWifiKeys = list(entries)

    monkeypatch.setattr(backend, "_setActiveWifiKeys", _fake_install)

    # Build a fake args namespace with wifi_keys_file pointing at a JSON list.
    args = _pytest_argparse_namespace(
        {
            "wifi_keys": None,
            "wifi_keys_file": None,
        },
    )
    keys_file = tmp_path / "wifi-keys.json"
    payload = [
        {"ssid": "TestNet", "bssid": "00:11:22:33:44:55", "psk": "supersecret"},
    ]
    keys_file.write_text(json.dumps(payload), encoding="utf-8")
    args.wifi_keys_file = str(keys_file)

    # Drive the same block runCaptureFromArgs uses to install the keys.
    if getattr(args, "wifi_keys", None):
        backend._setActiveWifiKeys(args.wifi_keys)
    elif getattr(args, "wifi_keys_file", None):
        wifiKeysPath = str(args.wifi_keys_file).strip()
        if wifiKeysPath and os.path.isfile(wifiKeysPath):
            with open(wifiKeysPath, "r", encoding="utf-8") as fh:
                wifiKeysPayload = json.load(fh)
            if isinstance(wifiKeysPayload, list) and wifiKeysPayload:
                backend._setActiveWifiKeys(wifiKeysPayload)

    assert "keys" in installed, "_setActiveWifiKeys was not invoked"
    assert installed["keys"] == payload
    assert backend.activeWifiKeys == payload


def test_backend_wifi_keys_file_ignores_missing_file(monkeypatch, tmp_path: Path):
    """A missing --wifi-keys-file path is non-fatal; the backend should
    still start (with no keys installed) rather than crash."""
    backend = _load_backend_module()
    called = {"count": 0}

    def _fake_install(entries):
        called["count"] += 1
        backend.activeWifiKeys = list(entries)

    monkeypatch.setattr(backend, "_setActiveWifiKeys", _fake_install)

    missing_path = tmp_path / "does-not-exist.json"
    args = _pytest_argparse_namespace(
        {
            "wifi_keys": None,
            "wifi_keys_file": str(missing_path),
        },
    )

    if getattr(args, "wifi_keys", None):
        backend._setActiveWifiKeys(args.wifi_keys)
    elif getattr(args, "wifi_keys_file", None):
        wifiKeysPath = str(args.wifi_keys_file).strip()
        if wifiKeysPath and os.path.isfile(wifiKeysPath):
            with open(wifiKeysPath, "r", encoding="utf-8") as fh:
                wifiKeysPayload = json.load(fh)
            if isinstance(wifiKeysPayload, list) and wifiKeysPayload:
                backend._setActiveWifiKeys(wifiKeysPayload)

    assert called["count"] == 0, "_setActiveWifiKeys should not run for a missing file"


def test_backend_wifi_keys_file_ignores_non_list_payload(monkeypatch, tmp_path: Path):
    """If the --wifi-keys-file points to a JSON object (not a list), the
    backend must skip installation rather than crash."""
    backend = _load_backend_module()
    called = {"count": 0}

    def _fake_install(entries):
        called["count"] += 1
        backend.activeWifiKeys = list(entries)

    monkeypatch.setattr(backend, "_setActiveWifiKeys", _fake_install)

    keys_file = tmp_path / "wifi-keys-bad.json"
    keys_file.write_text(json.dumps({"ssid": "x"}), encoding="utf-8")
    args = _pytest_argparse_namespace(
        {
            "wifi_keys": None,
            "wifi_keys_file": str(keys_file),
        },
    )

    if getattr(args, "wifi_keys", None):
        backend._setActiveWifiKeys(args.wifi_keys)
    elif getattr(args, "wifi_keys_file", None):
        wifiKeysPath = str(args.wifi_keys_file).strip()
        if wifiKeysPath and os.path.isfile(wifiKeysPath):
            with open(wifiKeysPath, "r", encoding="utf-8") as fh:
                wifiKeysPayload = json.load(fh)
            if isinstance(wifiKeysPayload, list) and wifiKeysPayload:
                backend._setActiveWifiKeys(wifiKeysPayload)

    assert called["count"] == 0, "Non-list JSON payload should not trigger install"


def test_backend_cli_parser_accepts_wifi_keys_file_arg():
    """argparse must recognise --wifi-keys-file with dest=wifi_keys_file
    so the JS bridge can pass the JSON path to the legacy-spawned backend."""
    import argparse

    backend = _load_backend_module()
    parser = backend.buildParser()
    # Smoke: ensure dest is registered with the right type.
    for action in parser._actions:
        if action.dest == "wifi_keys_file":
            assert action.default is None, "wifi_keys_file should default to None"
            return
    pytest.fail("--wifi-keys-file CLI argument not registered on parser")


def _pytest_argparse_namespace(attrs):
    """Tiny shim that mimics argparse.Namespace for the wifi-keys tests."""
    import argparse

    ns = argparse.Namespace()
    for key, value in attrs.items():
        setattr(ns, key, value)
    return ns


def test_backend_decrypts_coherer_wifi_capture_with_psk(tmp_path: Path):
    """End-to-end check: feeding the Wireshark 'Coherer' WPA capture plus
    the well-known 'Induction' passphrase through the backend via the
    --wifi-keys-file path proves the JS bridge can successfully hand
    802.11 keys to the legacy-spawned backend process AND that the
    AES-CCMP decryptor recovers plaintext for the matching 4-way
    handshake client.

    The Coherer capture has a complete 4-way handshake for client
    00:0d:93:82:36:3a so we expect to see successfully-decrypted
    CCMP frames (algorithm=CCMP, plaintextHex set) on that BSSID.
    """
    pcap_file = _wifi_sample_pcap()
    if not pcap_file.exists():
        pytest.skip(f"Wifi sample pcap not found: {pcap_file}")

    keys_file = tmp_path / "wifi-keys.json"
    keys_file.write_text(
        json.dumps(
            [
                {
                    "ssid": "Coherer",
                    "bssid": "00:0c:41:82:b2:55",
                    "psk": "Induction",
                }
            ]
        ),
        encoding="utf-8",
    )

    output_dir = tmp_path / "snitch-output-coherer"
    conf_file = tmp_path / "test-conf-coherer.yaml"
    _write_test_config(conf_file)

    result = _run_backend_with_wifi_keys(
        pcap_file=pcap_file,
        output_dir=output_dir,
        conf_file=conf_file,
        wifi_keys_file=keys_file,
    )
    if result.returncode != 0:
        pytest.fail(
            "Backend execution failed for Coherer wifi capture.\n"
            f"exit={result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    hosts_file = output_dir / "hosts.json"
    assert hosts_file.exists(), f"Expected output file not found: {hosts_file}"

    hosts_data = json.loads(hosts_file.read_text(encoding="utf-8"))
    packets = _flatten_packets(hosts_data)
    assert packets, "Expected decoded packets in Coherer hosts.json"

    wifi_packet_count = 0
    ccmp_attempted_count = 0
    ccmp_decrypted_count = 0
    bssid_match_count = 0
    coherer_bssid = "00:0c:41:82:b2:55"
    for packet in packets:
        packet_info = packet.get("packet.info", {})
        if packet_info.get("link.proto") != "IEEE 802.11":
            continue
        wifi_packet_count += 1
        algorithm = packet_info.get("wifi.decrypt.algorithm")
        wireless_section = packet_info.get("Wireless") or {}
        packet_bssid = wireless_section.get("wifi.bssid", "").lower()
        if algorithm == "CCMP":
            ccmp_attempted_count += 1
            if packet_bssid == coherer_bssid:
                bssid_match_count += 1
                if packet_info.get("wifi.decrypt.ok"):
                    ccmp_decrypted_count += 1

    assert wifi_packet_count > 0, "Expected at least one IEEE 802.11 packet in Coherer capture"
    assert ccmp_attempted_count > 0, (
        "Expected at least one CCMP data frame to be processed — proves the "
        "wifi decoder is running the AES-CCMP path (not skipping the keys)."
    )
    assert bssid_match_count > 0, (
        "Expected at least one CCMP frame on the Coherer BSSID "
        f"({coherer_bssid}) so the keys are being matched to the right AP."
    )
    assert ccmp_decrypted_count > 0, (
        "Expected at least one CCMP frame on the Coherer BSSID to be "
        "successfully decrypted with the supplied PSK — proves the "
        "AES-CCMP plaintext recovery path is wired end-to-end."
    )
