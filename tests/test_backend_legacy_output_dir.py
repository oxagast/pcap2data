import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _backend_script() -> Path:
    return _project_root() / "src" / "backend" / "snitch.py"


def _load_backend_module():
    spec = importlib.util.spec_from_file_location(
        "snitch_legacy_output_test_module", _backend_script()
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load backend module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def backend_module():
    return _load_backend_module()


@pytest.fixture(autouse=True)
def _reset_resolver_cache(backend_module, monkeypatch):
    """Reset the module-level resolver cache + env between tests so the
    override and platform-fallback branches are exercised independently."""
    backend_module.cachedLegacyOutputDir = ""
    monkeypatch.delenv(
        backend_module.LEGACY_OUTPUT_DIR_ENV_VAR, raising=False
    )
    yield


def test_resolver_honours_explicit_env_override(backend_module, tmp_path):
    override = tmp_path / "ramdisk"
    override.mkdir()
    backend_module.cachedLegacyOutputDir = ""
    # The override is created by the resolver, so point at a non-existing
    # subdir to prove the resolver created it.
    target = override / "auto"
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(
            backend_module.LEGACY_OUTPUT_DIR_ENV_VAR, str(target)
        )
        backend_module.cachedLegacyOutputDir = ""
        resolved = backend_module._resolveLegacyOutputDirectory()
    assert resolved == str(target)
    assert target.is_dir()


def test_resolver_fallback_when_override_unwritable(backend_module, tmp_path):
    # Root-owned path can't be written by the test user; the resolver
    # should log and fall back rather than raising.
    if os.geteuid() == 0:
        pytest.skip("root would actually be able to write the target")
    bogus = "/proc/this-cannot-be-created/packetsnitch"
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(
            backend_module.LEGACY_OUTPUT_DIR_ENV_VAR, bogus
        )
        backend_module.cachedLegacyOutputDir = ""
        resolved = backend_module._resolveLegacyOutputDirectory()
    assert resolved
    assert resolved != bogus
    assert Path(resolved).is_dir()


def test_resolver_linux_prefers_run_user(backend_module, monkeypatch):
    if not sys.platform.startswith("linux"):
        pytest.skip("Linux-only /run/user/<uid> path")
    monkeypatch.setattr(backend_module.sys, "platform", "linux")
    uid = os.getuid()
    candidate = Path(f"/run/user/{uid}")
    if not candidate.is_dir():
        pytest.skip(f"/run/user/{uid} unavailable on this host")
    backend_module.cachedLegacyOutputDir = ""
    resolved = backend_module._resolveLegacyOutputDirectory()
    expected = candidate / backend_module.LEGACY_OUTPUT_DIR_NAME
    assert resolved == str(expected)
    assert Path(resolved).is_dir()


def test_resolver_caches_first_resolution(backend_module, tmp_path):
    override = str(tmp_path / "cached")
    Path(override).mkdir()
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(
            backend_module.LEGACY_OUTPUT_DIR_ENV_VAR, override
        )
        backend_module.cachedLegacyOutputDir = ""
        first = backend_module._resolveLegacyOutputDirectory()
        # Move the cache to a different path - the resolver should
        # keep returning the original first choice.
        Path(override).rmdir()
        second = backend_module._resolveLegacyOutputDirectory()
    assert first == second == override


def test_write_hosts_snapshot_uses_tmpfs_dir(backend_module, monkeypatch, tmp_path):
    """When called with an empty outputDirPath, the snapshot should land
    in the resolved tmpfs location and the cleanup timer should delete
    the file after the grace period."""
    fake_tmpfs = tmp_path / "tmpfs"
    fake_tmpfs.mkdir()
    monkeypatch.setattr(
        backend_module, "_resolveLegacyOutputDirectory", lambda: str(fake_tmpfs)
    )
    backend_module.cachedLegacyOutputDir = ""
    # Shorten the cleanup grace so the test doesn't take 2 seconds.
    monkeypatch.setattr(
        backend_module,
        "LEGACY_OUTPUT_DIR_CLEANUP_GRACE_SECONDS",
        0.05,
    )
    packetEntries = [
        {"host": "10.0.0.1", "packet": {"packet.info": {"packet.proto": "TCP"}}}
    ]
    snapshot_path = backend_module.writeHostsSnapshot(
        "", packetEntries, "summary", "hosts.json"
    )
    assert snapshot_path == str(fake_tmpfs / "hosts.json")
    assert Path(snapshot_path).is_file()
    # Wait for the cleanup timer to fire.
    import time
    deadline = time.time() + 2.0
    while Path(snapshot_path).exists() and time.time() < deadline:
        time.sleep(0.05)
    assert not Path(snapshot_path).exists()


def test_write_hosts_snapshot_with_explicit_dir_uses_that_dir(
    backend_module, tmp_path
):
    """When given an explicit outputDirPath, the snapshot should
    land there (legacy callers passing --output still work)."""
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    packetEntries = [
        {"host": "10.0.0.1", "packet": {"packet.info": {"packet.proto": "TCP"}}}
    ]
    snapshot_path = backend_module.writeHostsSnapshot(
        str(explicit), packetEntries, "summary", "hosts.json"
    )
    assert snapshot_path == str(explicit / "hosts.json")
    payload = json.loads(Path(snapshot_path).read_text())
    assert payload["final.summary"] == "summary"
    assert "host" in payload


def test_write_testcase_defaults_to_tmpfs(backend_module, monkeypatch, tmp_path):
    fake_tmpfs = tmp_path / "tmpfs"
    fake_tmpfs.mkdir()
    monkeypatch.setattr(
        backend_module, "_resolveLegacyOutputDirectory", lambda: str(fake_tmpfs)
    )
    backend_module.cachedLegacyOutputDir = ""
    monkeypatch.setattr(
        backend_module,
        "LEGACY_OUTPUT_DIR_CLEANUP_GRACE_SECONDS",
        0.05,
    )
    backend_module.writeTestcase(b"hello", "", "80", 1)
    written = fake_tmpfs / "80" / "pcap.data_packet.1.dat"
    assert written.is_file()
    assert written.read_bytes() == b"hello"
    import time
    deadline = time.time() + 2.0
    while written.exists() and time.time() < deadline:
        time.sleep(0.05)
    assert not written.exists()


def test_write_testcase_creates_port_subdir(backend_module, tmp_path):
    """``writeTestcase`` creates a per-port subdirectory under the
    resolved output dir and writes ``pcap.data_packet.<index>.dat``
    inside it. The legacy path is still expected to produce the
    same file layout as before so test-case tooling keeps working."""
    outdir = tmp_path / "out"
    backend_module.writeTestcase(b"payload", str(outdir), "80", 7)
    expected = outdir / "80" / "pcap.data_packet.7.dat"
    assert expected.is_file()
    assert expected.read_bytes() == b"payload"


def test_schedule_cleanup_handles_missing_path(backend_module):
    # Should not raise even for empty / None inputs.
    backend_module._scheduleLegacyOutputCleanup("")
    backend_module._scheduleLegacyOutputCleanup(None)
    # If a non-existent path is supplied, the cleanup worker should
    # silently no-op (no exception bubbles up).
    backend_module._scheduleLegacyOutputCleanup("/nope/does-not-exist.dat")
