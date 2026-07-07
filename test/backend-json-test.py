import json
import subprocess
import sys
from pathlib import Path

import pytest


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _backend_script() -> Path:
    return _project_root() / "src" / "backend" / "snitch.py"


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
