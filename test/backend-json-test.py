import json
import subprocess
import sys
import importlib.util
from pathlib import Path

import pytest
from scapy.all import CookedLinux, Ether, IP, TCP, UDP, Raw, wrpcap


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