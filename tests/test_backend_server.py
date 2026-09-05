import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _backend_script() -> Path:
    return _project_root() / "src" / "backend" / "snitch.py"


def _collect_libs_dirs(site_packages_roots):
    """Walk every site-packages root and return the unique set of
    `<package>.libs/` directories found inside it.

    Manylinux wheels ship tuned native binaries in `<package>.libs/`;
    CPython extensions that link against them fail to load unless the
    dynamic linker can resolve them. See
    /memories/repo/manylinux_libs_ld_library_path.md.
    """
    libs = []
    seen = set()
    for root in site_packages_roots:
        if root is None or not root.exists():
            continue
        try:
            entries = list(root.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.name.endswith(".libs"):
                continue
            try:
                if not entry.is_dir():
                    continue
            except OSError:
                continue
            if entry in seen:
                continue
            seen.add(entry)
            libs.append(str(entry))
    return libs


def _build_backend_subprocess_env():
    """Inject `LD_LIBRARY_PATH` so the spawned Python can dlopen
    manylinux `.libs/` shims (e.g. `libscipy_openblas64_-<hash>.so`).

    Mirrors the Linux-only behavior in
    `src/back-comm.js::buildBackendProcessEnv`.
    """
    env = os.environ.copy()
    if sys.platform != "linux":
        return env

    home = Path.home()
    version_roots = [
        home / ".local" / "lib",
        Path("/usr/local/lib64"),
        Path("/usr/local/lib"),
        home / ".local" / "lib64",
    ]
    site_packages_roots = []
    for version_root in version_roots:
        if not version_root.exists():
            continue
        try:
            for entry in version_root.iterdir():
                if entry.name.startswith("python") and entry.is_dir():
                    site_packages_roots.append(entry / "site-packages")
        except OSError:
            continue

    project_root = _project_root()
    for sibling in ("lib", "lib64"):
        venv_lib = project_root / ".venv" / sibling
        if venv_lib.exists():
            try:
                for entry in venv_lib.iterdir():
                    if entry.name.startswith("python") and entry.is_dir():
                        site_packages_roots.append(entry / "site-packages")
            except OSError:
                pass

    libs = _collect_libs_dirs(site_packages_roots)
    if not libs:
        return env

    path_sep = ":"
    merged = path_sep.join(libs)
    existing = env.get("LD_LIBRARY_PATH")
    env["LD_LIBRARY_PATH"] = f"{merged}{path_sep}{existing}" if existing else merged
    return env


def _run_backend(server_port: int) -> subprocess.CompletedProcess:
    cmd = [
        sys.executable,
        str(_backend_script()),
        "--server", "--server-port", str(server_port)
    ]
    # we need to run this in the background so wget can run
    snitch = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_build_backend_subprocess_env(),
    )
    try:
        # wait a bit for the server to start
        snitch.wait(timeout=3)
    except subprocess.TimeoutExpired:
        # server is still running, which is expected
        pass
    return snitch

def wget_backend_version(port: int) -> str:
    """Fetch the backend version from the running server using wget."""
    url = f"http://localhost:{port}/version"
    try:
        result = subprocess.run(
            ["wget", "-qO-", url],
            capture_output=True,
            text=True,
            check=True
        )
        print("Backend version response:", result.stdout.strip(), end="", flush=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        pytest.fail(f"Failed to fetch backend version: {e.stderr}")


def wget_backend_json(port: int, path: str) -> dict:
    """Fetch and decode a JSON payload from a backend endpoint using wget."""
    url = f"http://localhost:{port}{path}"
    try:
        result = subprocess.run(
            ["wget", "-qO-", url],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        pytest.fail(f"Failed to fetch backend JSON from {path}: {e.stderr}")
    except json.JSONDecodeError as e:
        pytest.fail(f"Backend endpoint {path} did not return valid JSON: {e}")


def kill_if_running() -> None:
    """Terminate the backend server process if it's still running."""
    subprocess.run(["pkill", "-f", "snitch.py"], check=False)

def kill_backend(snitch: subprocess.Popen) -> None:
    """Terminate the backend server process."""
    snitch.terminate()
    try:
        snitch.wait(timeout=5)
    except subprocess.TimeoutExpired:
        snitch.kill()
        snitch.wait()


def _wait_for_port(port: int) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    pytest.fail(f"Backend did not listen on port {port}")

def test_backend_serves_http(port: int = 9020):
    backend = _backend_script()

    if not backend.exists():
        pytest.skip(f"Backend script not found: {backend}")
    kill_if_running()
    startbend = _run_backend(server_port=port)


    
    # fire off the wget in a different thread or process to avoid blocking the backend server

    version = wget_backend_version(port=port)
    assert version, "No version response from backend server"
    kill_backend(startbend)


def test_backend_status_endpoints(port: int = 9021):
    backend = _backend_script()

    if not backend.exists():
        pytest.skip(f"Backend script not found: {backend}")
    kill_if_running()
    startbend = _run_backend(server_port=port)

    status_payload = wget_backend_json(port=port, path="/status")
    root_payload = wget_backend_json(port=port, path="/")

    for payload in (status_payload, root_payload):
        assert payload.get("type") == "status"
        assert payload.get("status") == "ok"
        assert isinstance(payload.get("statusLine"), str)
        assert "status=ok" in payload.get("statusLine")
        assert "jobsProcessed=" in payload.get("statusLine")
        assert payload.get("service") == "packetsnitch"
        assert payload.get("version")
        assert isinstance(payload.get("runtime"), dict)
        assert "workerThreads" in payload["runtime"]
        assert "hostChunkSize" in payload["runtime"]
        assert isinstance(payload.get("jobsProcessedSinceStart"), int)
        assert payload["jobsProcessedSinceStart"] >= 0
        assert isinstance(payload["runtime"].get("jobsProcessedSinceStart"), int)
        assert payload["runtime"]["jobsProcessedSinceStart"] >= 0
        assert isinstance(payload.get("runningJobs"), list)

    kill_backend(startbend)


def test_backend_status_reports_active_job_shape(port: int = 9022):
    backend = _backend_script()
    if not backend.exists():
        pytest.skip(f"Backend script not found: {backend}")
    kill_if_running()
    process = _run_backend(server_port=port)
    try:
        _wait_for_port(port)
        status_payload = wget_backend_json(port=port, path="/status")
        assert isinstance(status_payload.get("runningJobs"), list)
        assert status_payload["runtime"]["processing"] is False
    finally:
        kill_backend(process)