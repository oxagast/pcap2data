# Pytest configuration for PacketSnitch backend tests.
#
# Manylinux wheels (numpy, scipy, gRPC, OpenCV, PyArrow, ...) ship tuned
# native binaries in a sibling `<package>.libs/` directory next to the
# package's `__init__.py`. CPython extension modules that link against
# those vendored `.so` files fail to load unless the dynamic linker can
# resolve them — which it does NOT do from `<package>.libs/` by default.
#
# Without this injection, in-process tests that import `snitch.py` via
# `importlib.util.spec_from_file_location` (which transitively imports
# numpy) crash with:
#   ImportError: libscipy_openblas64_-<hash>.so: cannot open shared
#                 object file
#
# This conftest must run BEFORE any test imports the backend, so it sets
# `LD_LIBRARY_PATH` at module-import time. Mirrors the Linux-only behavior
# in `src/back-comm.js::buildBackendProcessEnv`. See also
# /memories/repo/manylinux_libs_ld_library_path.md.

from __future__ import annotations

import os
import sys
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _site_packages_roots() -> list[Path]:
    roots: list[Path] = []
    home = Path.home()
    version_roots = [
        home / ".local" / "lib",
        Path("/usr/local/lib64"),
        Path("/usr/local/lib"),
        home / ".local" / "lib64",
    ]
    for version_root in version_roots:
        if not version_root.exists():
            continue
        try:
            for entry in version_root.iterdir():
                if entry.name.startswith("python") and entry.is_dir():
                    roots.append(entry / "site-packages")
        except OSError:
            continue

    project_root = _project_root()
    for sibling in ("lib", "lib64"):
        venv_lib = project_root / ".venv" / sibling
        if venv_lib.exists():
            try:
                for entry in venv_lib.iterdir():
                    if entry.name.startswith("python") and entry.is_dir():
                        roots.append(entry / "site-packages")
            except OSError:
                pass
    return roots


def _libs_dirs() -> list[str]:
    seen: set[Path] = set()
    libs: list[str] = []
    for root in _site_packages_roots():
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


if sys.platform == "linux":
    libs = _libs_dirs()
    if libs:
        merged = ":".join(libs)
        existing = os.environ.get("LD_LIBRARY_PATH")
        os.environ["LD_LIBRARY_PATH"] = (
            f"{merged}:{existing}" if existing else merged
        )


def pytest_configure(config):
    """Register warning filters that match snitch.py's runtime filters.

    pytest installs its own warning filters at session start. snitch.py
    re-registers the same filters after ``warnings.simplefilter("module")``
    so they are honored at runtime, but pytest's session-level filter is
    the one that actually drives the warning summary at the end of a test
    run. Without these filters here, every test run prints the scapy /
    cryptography TripleDES deprecation twice, which is noise.

    We deliberately keep the filter list narrow (only the categories the
    production code already suppresses) so any *new* deprecation warnings
    still surface in test output and can be triaged.
    """
    warnings_filter = config.builtin_settings.filters if hasattr(config, "builtin_settings") else []
    try:
        from cryptography.utils import CryptographyDeprecationWarning
    except Exception:  # pragma: no cover - cryptography is a hard dep
        CryptographyDeprecationWarning = None

    if CryptographyDeprecationWarning is not None:
        config.addinivalue_line(
            "filterwarnings",
            "ignore:TripleDES has been moved to cryptography.hazmat.decrepit.ciphers.algorithms:"
            f"{CryptographyDeprecationWarning.__module__}.{CryptographyDeprecationWarning.__qualname__}",
        )
        config.addinivalue_line(
            "filterwarnings",
            "ignore:ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms:"
            f"{CryptographyDeprecationWarning.__module__}.{CryptographyDeprecationWarning.__qualname__}",
        )
    try:
        from urllib3.exceptions import InsecureRequestWarning
        config.addinivalue_line(
            "filterwarnings",
            "ignore::urllib3.exceptions.InsecureRequestWarning",
        )
    except Exception:  # pragma: no cover - urllib3 is a hard dep
        pass
    del warnings_filter