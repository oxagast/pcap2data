import subprocess
import sys
import shutil
from pathlib import Path
import tempfile

import pytest



def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _get_os_temp_folder() -> Path:
    """Get the OS temporary folder path."""
    return Path(tempfile.gettempdir())

def _backend_script() -> Path:
    return _project_root() / "src" / "backend" / "snitch.py"


def _is_extract_error(stderr: str) -> bool:
    """Detect transient PyInstaller onefile extraction errors."""
    return (
        "Failed to extract" in stderr
        or "decompression resulted in return code -3" in stderr
    )


def _run_compiled_version(binary_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [binary_path, "--version"],
        capture_output=True,
        text=True,
        check=False,
    )

# Build the backend with PyInstaller using the script directly (no .spec)
# so the test always uses the freshest entry point and never has to know
# about OS-specific spec files committed by previous builds.
def _compile_backend(timeout_seconds: int = 300) -> Path:
    compile_dir = Path(tempfile.mkdtemp(prefix="snitch_", dir=_get_os_temp_folder()))

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        "--distpath",
        str(compile_dir),
        "--onefile",
        str(_backend_script()),
    ]
    compile_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = compile_proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        compile_proc.kill()
        stdout, stderr = compile_proc.communicate()
        pytest.fail(
            f"Backend compile timed out after {timeout_seconds}s\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        )

    if compile_proc.returncode != 0:
        pytest.fail(
            f"Backend compile failed with exit code {compile_proc.returncode}\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        )

    binary_name = "snitch.exe" if sys.platform.startswith("win") else "snitch"
    compiled_binary_path = compile_dir / binary_name
    if not compiled_binary_path.exists():
        pytest.fail(
            f"Compile completed but expected binary was not created at {compiled_binary_path}\n"
            f"stdout:\n{stdout}\n"
            f"stderr:\n{stderr}"
        )

    return compiled_binary_path

@pytest.fixture(scope="module", autouse=True)
def test_compile_backend_fixture():
    global compiled_binary_path
    global compiled_backend_version
    compiled_binary_path = _compile_backend()

    # PyInstaller onefile extraction can fail intermittently on first run; retry once.
    version_result = _run_compiled_version(compiled_binary_path)
    if version_result.returncode != 0 and _is_extract_error(version_result.stderr):
        if compiled_binary_path.exists():
            compiled_binary_path.unlink()
        compiled_binary_path = _compile_backend()
        version_result = _run_compiled_version(compiled_binary_path)

    if version_result.returncode != 0:
        pytest.fail(
            "Failed to fetch compiled backend version after compile "
            f"(exit {version_result.returncode})\n"
            f"stdout:\n{version_result.stdout}\n"
            f"stderr:\n{version_result.stderr}"
        )

    compiled_backend_version = version_result.stdout.strip()
    yield compiled_binary_path
    if compiled_binary_path.exists():
        shutil.rmtree(compiled_binary_path.parent, ignore_errors=True)

def test_is_file() -> None:
    """Check if the compiled binary is a file."""
    assert Path(compiled_binary_path).is_file()

def test_exists() -> None:
    """Check if the compiled binary exists."""
    assert Path(compiled_binary_path).exists()

def test_size_of_compiled_binary() -> None:
    """Test that the compiled binary is not empty."""
    assert Path(compiled_binary_path).stat().st_size > 0, f"Compiled binary is empty at {compiled_binary_path}"

def test_backend_compiled_version() -> None:
    """Run the compiled backend binary and fetch its version."""
    print("Compiled backend version response:", compiled_backend_version, end="", flush=True)
    assert compiled_backend_version

