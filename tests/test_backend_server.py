import json
import subprocess
import sys
from pathlib import Path

import pytest


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _backend_script() -> Path:
    return _project_root() / "src" / "backend" / "snitch.py"


def _run_backend(server_port: int) -> subprocess.CompletedProcess:
    cmd = [
        sys.executable,
        str(_backend_script()),
        "--server", "--server-port", str(server_port)
    ]
    # we need to run this in the background so wget can run
    snitch = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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