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
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        pytest.fail(f"Failed to fetch backend version: {e.stderr}")


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

    curl = subprocess.Popen(
        ["curl", f"http://localhost:{port}/version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    stdout, stderr = curl.communicate(timeout=5)
    assert stdout.strip(), "No version response from backend server"
    kill_backend(startbend)