import os
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
    """Inject `LD_LIBRARY_PATH` so the spawned Python (or PyInstaller
    subprocess) can dlopen manylinux `.libs/` shims.

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


def _run_compiled_version(binary_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [binary_path, "--version"],
        capture_output=True,
        text=True,
        check=False,
        env=_build_backend_subprocess_env(),
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
    compile_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_build_backend_subprocess_env(),
    )
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

