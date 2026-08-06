#!/usr/bin/env python3
## snitch_extract.py: Cross-platform archive helper bundled by PyInstaller and
# invoked by the Electron main process when an archive format the Node side
# cannot decode on its own is requested from the Conv tab's Extract subtab.
#
# Today this script handles Microsoft Cabinet (.cab) and 7-Zip (.7z). It is
# deliberately minimal so PyInstaller keeps it cheap:
#
#   * No third-party deps for tar / zip (the Node side handles those).
#   * ``cabarchive`` for CAB listing/extraction (read-only, pure Python).
#   * ``py7zr`` for 7z listing/extraction (pure Python LZMA/LZMA2 stack).
#
# CLI contract (input is raw archive bytes on stdin; output is a single JSON
# object on stdout; non-zero exit + stderr on failure):
#
#   python3 snitch_extract.py detect                     -> {"format": "cab"}
#   python3 snitch_extract.py list                       -> {"format": "cab",
#                                                             "entries": [...]}
#   python3 snitch_extract.py extract <entry-path>       -> {"format": "cab",
#                                                             "entryPath": "...",
#                                                             "byteLength": N,
#                                                             "bytesBase64": "..."}
#
# The Node wrapper adds safety limits (max input size, max output size,
# timeout) and is the only thing the renderer talks to directly.
#
# Author: oxagast

import argparse
import base64
import io
import json
import sys
import traceback


MAX_OUTPUT_BYTES = 256 * 1024 * 1024  # mirrors EXTRACTION_MAX_OUTPUT_BYTES in main.js


def emit(payload):
    """Write a single JSON object to stdout and exit 0."""
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


def fail(message):
    """Write a JSON error envelope to stderr and exit non-zero."""
    sys.stderr.write(json.dumps({"error": message}))
    sys.stderr.flush()
    sys.exit(1)


def detect_format(buf):
    """Cheap magic-byte sniffer. Mirrors ``inferExtractionFormatFromBytes``
    in ``src/main.js`` so the Node side can preflight without spawning us
    for formats it already understands."""
    if len(buf) < 2:
        return "unknown"
    if buf[:2] == b"MS":
        # CAB signature is the ASCII bytes "MSCF" at offset 0.
        if len(buf) >= 4 and buf[:4] == b"MSCF":
            return "cab"
    if len(buf) >= 6 and buf[:6] == b"\x37\x7a\xbc\xaf\x27\x1c":
        return "7z"
    return "unknown"


def list_cab(buf):
    """Return the entry list of a Microsoft Cabinet archive.

    ``cabarchive.CabArchive`` (the package shipped under the
    ``cabarchive`` / ``cabarchive-windows`` PyPI names) is a ``dict``
    subclass — the dict keys are entry filenames and the values are
    ``CabFile`` instances. There is no ``.files`` attribute; iterate
    over the archive directly. CAB has no real directory concept but
    some writers emit a trailing ``"\\"`` continuation entry for
    folders — we surface those as directories for the renderer.
    """
    import cabarchive  # imported lazily so 7z-only builds stay slim

    archive = cabarchive.CabArchive(buf)
    entries = []
    for filename in archive:
        entry = archive[filename]
        size = len(entry) if entry.buf is not None else 0
        # CAB folder entries use a trailing backslash; everything else
        # is a regular file record.
        is_dir = bool(filename) and (filename.endswith("\\") or filename.endswith("/"))
        entries.append(
            {
                "path": filename,
                "type": "directory" if is_dir else "file",
                "size": int(size),
                "compressedSize": int(size),
            }
        )
    return entries


def extract_cab(buf, target_path):
    """Return the bytes for ``target_path`` inside a CAB archive."""
    import cabarchive

    archive = cabarchive.CabArchive(buf)
    # ``cabarchive`` lookup is case-sensitive. Try the path verbatim
    # first, then fall back to lowercasing and finally to a basename-only
    # match — Windows CABs in the wild are notoriously inconsistent
    # about case.
    base = target_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    candidates = []
    for cand in (target_path, target_path.lower(), base, base.lower()):
        if cand and cand not in candidates:
            candidates.append(cand)
    for cand in candidates:
        if cand not in archive:
            continue
        entry = archive[cand]
        if entry.buf is None:
            raise ValueError("Cannot extract a directory CAB entry")
        buf_data = entry.buf
        if len(buf_data) > MAX_OUTPUT_BYTES:
            raise ValueError(
                "Extracted entry too large ({} > {})".format(
                    len(buf_data), MAX_OUTPUT_BYTES
                )
            )
        return buf_data
    raise KeyError("Archive entry not found: {}".format(target_path))


def list_7z(buf):
    """Return the entry list of a 7-Zip archive."""
    import py7zr

    archive = py7zr.SevenZipFile(io.BytesIO(buf))
    try:
        infos = archive.list()
    finally:
        archive.close()
    entries = []
    for info in infos:
        # ``info.is_directory`` exists on modern py7zr; fall back to
        # checking the size + filename trailing slash for safety.
        is_dir = bool(
            getattr(info, "is_directory", False)
            or (info.filename.endswith("/") and not getattr(info, "size", 0))
        )
        entries.append(
            {
                "path": info.filename,
                "type": "directory" if is_dir else "file",
                "size": int(getattr(info, "size", 0) or 0),
                "compressedSize": int(getattr(info, "compressed", 0) or 0),
            }
        )
    return entries


def extract_7z(buf, target_path):
    """Return the bytes for ``target_path`` inside a 7z archive."""
    import py7zr

    archive = py7zr.SevenZipFile(io.BytesIO(buf))
    try:
        # ``py7zr.read()`` returns a dict of name -> BytesIO. Strip any
        # leading "./" because py7zr normalises paths that way even when
        # the on-disk name has no prefix.
        names_to_try = [target_path, target_path.lstrip("./")]
        base = target_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        names_to_try.append(base)
        extracted = archive.read(names_to_try)
    finally:
        archive.close()
    for name, data in extracted.items():
        if data is None:
            continue
        payload = data.read() if hasattr(data, "read") else bytes(data)
        if len(payload) > MAX_OUTPUT_BYTES:
            raise ValueError(
                "Extracted entry too large ({} > {})".format(
                    len(payload), MAX_OUTPUT_BYTES
                )
            )
        return payload
    raise KeyError("Archive entry not found: {}".format(target_path))


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="snitch_extract",
        description="Archive helper invoked by the PacketSnitch main process.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("detect", help="Return the detected archive format.")
    sub.add_parser("list", help="Return the list of archive entries.")
    extract = sub.add_parser(
        "extract", help="Return the bytes for a single archive entry."
    )
    extract.add_argument("entryPath", help="Archive entry path to extract.")

    args = parser.parse_args(argv)
    raw = sys.stdin.buffer.read() if not sys.stdin.isatty() else b""
    fmt = detect_format(raw)

    try:
        if args.command == "detect":
            emit({"format": fmt})
            return 0
        if args.command == "list":
            if fmt == "cab":
                entries = list_cab(raw)
            elif fmt == "7z":
                entries = list_7z(raw)
            else:
                emit({"format": fmt, "entries": []})
                return 0
            emit({"format": fmt, "entries": entries})
            return 0
        if args.command == "extract":
            if fmt == "cab":
                payload = extract_cab(raw, args.entryPath)
            elif fmt == "7z":
                payload = extract_7z(raw, args.entryPath)
            else:
                fail("Unknown archive format: {}".format(fmt or "empty"))
            emit(
                {
                    "format": fmt,
                    "entryPath": args.entryPath,
                    "byteLength": len(payload),
                    "bytesBase64": base64.b64encode(payload).decode("ascii"),
                }
            )
            return 0
        fail("Unhandled command: {}".format(args.command))
    except KeyError as exc:
        fail(str(exc))
    except ValueError as exc:
        fail(str(exc))
    except Exception as exc:  # noqa: BLE001
        # Surface a useful diagnostic on stderr but still emit a JSON
        # envelope so the Node side can surface the message verbatim.
        sys.stderr.write(traceback.format_exc())
        sys.stderr.flush()
        fail("{}: {}".format(type(exc).__name__, exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
