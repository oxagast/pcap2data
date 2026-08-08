"""Stage non-writable .so files with DT_RUNPATH into a writable cache
and patch them in place. Emits a JSON manifest mapping original source
paths to cached copies.

Why this exists: ``scripts/build-backend.js`` / ``build-extractor.js`` run
PyInstaller with the active Python's site-packages as the source of truth.
If a wheel ships .so files whose DT_RUNPATH is `$ORIGIN`-relative (e.g.
``libabsl_*.so.20260526`` from grpcio / tensorboard / pyarrow), and the
build environment has those wheels installed **system-wide** (root-owned,
not writable), PyInstaller copies the un-patched .so into the onefile
archive and ``staticx`` then refuses to re-wrap with::

    staticx: Unsupported PyInstaller input
      /tmp/staticx-pyi-XXX/libabsl_*.so.20260526: DT_RUNPATH='$ORIGIN'

This script walks active site-packages, finds .so files that have
DT_RUNPATH and that we cannot write to, copies them to a writable cache
under ``${BUILD_WORK_DIR}/patched-sos/`` (preserving relative path), runs
``patchelf --remove-rpath`` on the cached copy, and writes
``manifest.json`` so the build script can re-route PyInstaller's
``a.binaries`` ``src_name`` entries to the patched copies.

The manifest schema::

    {
        "version": 1,
        "cache_dir": "/abs/path/to/build/pyinstaller/patched-sos",
        "patches": {
            "/abs/path/to/original/.../libabsl_base.so.20260526":
                "/abs/path/to/build/.../libabsl_base.so.20260526"
        }
    }

The script is idempotent: re-running cleans and rebuilds the cache.

Note: ``scripts/run_pyinstaller.py`` now also patches DT_RUNPATH
in-place via ``_ensure_patched()`` for any ``a.binaries`` entry whose
source file is not in this manifest. This script is therefore a
fast-path: it pre-stages everything in site-packages so the build
spends less time on per-binary patchelf work. Files in system
directories (e.g. ``/usr/lib/x86_64-linux-gnu/libabsl_*.so`` on Kali)
that PyInstaller pulls in as transitive dependencies are handled
on-the-fly by the spec.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


def _probe_python_site_packages(python: str) -> list[str]:
    """Return the list of (sys.prefix + user-site + system site-packages)
    directories for ``python``. Mirrors ``stripBadRpaths`` in the JS build
    scripts so the two stay in lockstep.
    """
    code = (
        "import site, sys;\n"
        "print('\\n'.join(site.getsitepackages() + [site.getusersitepackages()]))"
    )
    result = subprocess.run(
        [python, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"could not resolve site-packages from {python!r}: {result.stderr.strip()}"
        )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _read_dynamic(so_path: Path) -> Optional[str]:
    """Return the DT_RUNPATH value of ``so_path`` if any, else None."""
    result = subprocess.run(
        ["readelf", "-d", str(so_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    import re

    for line in result.stdout.splitlines():
        m = re.search(r"\(RUNPATH\).*?:\s*\[([^\]]*)\]", line)
        if m:
            return m.group(1)
    return None


def _rewrite_runpath(so_path: Path) -> None:
    """Strip DT_RUNPATH and re-set it as DT_RPATH via patchelf. Two cases
    handled identically here -- the JS side branches on $ORIGIN vs
    absolute paths for sibling lookups, but for non-writable .so files
    the wheel has already placed its libabsl siblings next to itself, so
    $ORIGIN preserves whatever self-relative lookup the loader would
    have done at runtime, and absolute paths are unreachable in any
    case (they pointed at the build host's cpython site-packages).

    ``--remove-rpath`` drops both RPATH and RUNPATH. ``--force-rpath``
    is critical: modern patchelf defaults to writing DT_RUNPATH, but
    staticx forbids DT_RUNPATH outright, so we must explicitly choose
    DT_RPATH.
    """
    runpath = _read_dynamic(so_path)
    if runpath is None:
        return  # No DT_RUNPATH -> nothing to do.
    subprocess.run(
        ["patchelf", "--remove-rpath", str(so_path)],
        check=True,
    )
    subprocess.run(
        ["patchelf", "--force-rpath", "--set-rpath", runpath, str(so_path)],
        check=True,
    )


def _writable(so_path: Path) -> bool:
    return os.access(so_path, os.W_OK)


def stage(
    python: str,
    cache_dir: Path,
    site_roots: Optional[list[str]] = None,
) -> dict[str, str]:
    """Walk site-packages, find non-writable .so files with DT_RUNPATH,
    copy + patch them into ``cache_dir``, return a manifest mapping
    original absolute path -> cached absolute path.
    """
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    if site_roots is None:
        site_roots = _probe_python_site_packages(python)

    patches: dict[str, str] = {}

    for root in site_roots:
        root_path = Path(root)
        if not root_path.exists():
            continue
        # Walk every .so file directly (no rglob) so we keep the
        # relative path from root for cache_dir mirroring.
        stack = [root_path]
        while stack:
            cur = stack.pop()
            try:
                entries = list(cur.iterdir())
            except (PermissionError, OSError):
                continue
            for entry in entries:
                if entry.is_dir():
                    if not entry.is_symlink():
                        stack.append(entry)
                    continue
                if entry.is_symlink():
                    # Follow directory symlinks (e.g. cv2 -> opencv_python_headless).
                    try:
                        target_stat = entry.stat()
                    except OSError:
                        continue
                    if target_stat.st_mode & 0o170000 == 0o040000:  # S_ISDIR
                        stack.append(entry)
                    continue
                # ``entry.suffix`` returns the *last* suffix, which is
                # wrong for versioned .so files like
                # ``libabsl_base.so.20260526``. ``entry.suffixes``
                # returns the full list, so we check membership.
                if ".so" not in entry.suffixes:
                    continue
                if _writable(entry):
                    # Writable -> JS stripBadRpaths will handle it
                    # in place. Skip here so we don't double-rewrite.
                    continue
                if _read_dynamic(entry) is None:
                    continue
                # Mirror the relative path under cache_dir.
                rel = entry.relative_to(root_path)
                cached = cache_dir / rel
                cached.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(entry, cached)
                # ``shutil.copy2`` preserves the source mode bits,
                # so a root-owned 0444 source ends up read-only in the
                # cache too -- useless because patchelf needs to write
                # back the patched ELF. Reset to 0644 after copy.
                cached.chmod(0o644)
                try:
                    _rewrite_runpath(cached)
                except subprocess.CalledProcessError as exc:
                    print(
                        f"[stage-patched-sos] failed to patch "
                        f"{cached}: {exc}",
                        file=sys.stderr,
                    )
                    continue
                patches[str(entry.resolve())] = str(cached.resolve())

    manifest = {
        "version": 1,
        "cache_dir": str(cache_dir.resolve()),
        "python": python,
        "patches": patches,
    }
    manifest_path = cache_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(
        f"[stage-patched-sos] staged {len(patches)} non-writable .so "
        f"file(s) with DT_RUNPATH into {cache_dir}"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter to probe for site-packages "
        "(default: current interpreter)",
    )
    parser.add_argument(
        "--cache-dir",
        required=True,
        type=Path,
        help="Writable directory under BUILD_WORK_DIR for patched copies",
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        default=None,
        help="Where to write manifest.json (default: <cache-dir>/manifest.json)",
    )
    args = parser.parse_args()

    manifest = stage(args.python, args.cache_dir)
    if args.manifest_out is not None:
        args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
        args.manifest_out.write_text(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())