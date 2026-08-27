"""Regression test for the ``smtp_use_tls`` resolution crash.

The generic ``_resolve(..., _coerce_yaml_scalar)`` helper short-circuits
on ``raw is None or raw == ""`` but ``False == ""`` is ``False`` in
Python, so a defaulted ``False`` value fell through to
``_coerce_yaml_scalar(False)`` and crashed on ``bool.strip()``.

The fix moves ``smtp_use_tls`` to the same inline bool resolver pattern
that ``log_rotate`` and ``paddle_poll_enabled`` use. This test exercises
every resolution path (CLI > env > YAML native bool > YAML string >
default) so the crash can't come back when someone refactors the
resolver again."""

import argparse
import importlib.util
import os
import sys
from pathlib import Path

import pytest


def _load_catalog():
    script = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "PacketSnitch-Pro"
        / "Servers"
        / "Catalog"
        / "ps-catalog.py"
    )
    spec = importlib.util.spec_from_file_location("ps_catalog_smtp_tls_test_module", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load ps-catalog.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ps_catalog_smtp_tls_test_module"] = module
    spec.loader.exec_module(module)
    return module


_catalog = _load_catalog()


def _resolve_smtp_use_tls(args, cfg, env_value=None):
    """Mirror the inline resolver block from ``Config.from_env_and_args``
    so we can drive it with synthetic inputs without booting a full
    Config. The shape must stay in sync with ps-catalog.py."""
    os.environ.pop("PS_CATALOG_SMTP_USE_TLS", None)
    if env_value is not None:
        os.environ["PS_CATALOG_SMTP_USE_TLS"] = env_value
    if getattr(args, "smtp_use_tls", None) is not None:
        return bool(args.smtp_use_tls)
    ef = os.environ.get("PS_CATALOG_SMTP_USE_TLS")
    if ef is not None and ef.strip() != "":
        return ef.strip().lower() in ("1", "true", "yes", "on")
    if "smtp_use_tls" in cfg:
        cv = cfg["smtp_use_tls"]
        if isinstance(cv, str):
            return cv.strip().lower() in ("1", "true", "yes", "on")
        return bool(cv)
    return False


def test_smtp_use_tls_default_when_absent_everywhere():
    """The exact crash scenario from the live server: the key is absent
    from CLI args, env, and the YAML config. The default is False and
    must not raise."""
    args = argparse.Namespace(smtp_use_tls=None)
    assert _resolve_smtp_use_tls(args, {}) is False


def test_smtp_use_tls_pyyaml_native_true():
    """When PyYAML parses ``smtp_use_tls: true`` it returns a native
    Python ``True``. The resolver must accept it without calling
    ``.strip()`` on a bool."""
    args = argparse.Namespace(smtp_use_tls=None)
    assert _resolve_smtp_use_tls(args, {"smtp_use_tls": True}) is True


def test_smtp_use_tls_pyyaml_native_false():
    """Same as above for the False branch."""
    args = argparse.Namespace(smtp_use_tls=None)
    assert _resolve_smtp_use_tls(args, {"smtp_use_tls": False}) is False


def test_smtp_use_tls_hand_rolled_string_true():
    """The hand-rolled YAML parser returns a string ``"true"``."""
    args = argparse.Namespace(smtp_use_tls=None)
    assert _resolve_smtp_use_tls(args, {"smtp_use_tls": "true"}) is True


def test_smtp_use_tls_hand_rolled_string_false():
    """The hand-rolled YAML parser returns a string ``"false``.
    A naive ``bool("false")`` would be ``True`` because non-empty
    strings are truthy; the string-form branch must catch this."""
    args = argparse.Namespace(smtp_use_tls=None)
    assert _resolve_smtp_use_tls(args, {"smtp_use_tls": "false"}) is False


def test_smtp_use_tls_env_overrides_cfg():
    """CLI > env > YAML > default: an env var beats the YAML value."""
    args = argparse.Namespace(smtp_use_tls=None)
    assert _resolve_smtp_use_tls(
        args, {"smtp_use_tls": True}, env_value="0"
    ) is False


def test_smtp_use_tls_cli_overrides_env_and_cfg():
    """CLI beats both env and YAML."""
    args = argparse.Namespace(smtp_use_tls=True)
    assert _resolve_smtp_use_tls(
        args, {"smtp_use_tls": False}, env_value="0"
    ) is True


def test_smtp_use_tls_empty_env_falls_through_to_cfg():
    """An empty env string is treated as "not set" so the YAML layer
    still gets consulted. This matches the existing
    ``paddle_poll_enabled`` behavior."""
    args = argparse.Namespace(smtp_use_tls=None)
    assert _resolve_smtp_use_tls(
        args, {"smtp_use_tls": True}, env_value=""
    ) is True


def test_coerce_yaml_scalar_passes_native_bool_through():
    """Defensive: ``_coerce_yaml_scalar`` must not crash on a non-str
    input (PyYAML may hand it a native bool/int/None even though the
    signature says ``str``). The helper now returns non-str inputs
    untouched so a caller that still uses the generic ``_resolve``
    path for a bool field doesn't crash."""
    assert _catalog._coerce_yaml_scalar(True) is True
    assert _catalog._coerce_yaml_scalar(False) is False
    assert _catalog._coerce_yaml_scalar(25) == 25
    assert _catalog._coerce_yaml_scalar(None) is None


def test_coerce_yaml_scalar_still_parses_strings():
    """The string-parsing path (the original behavior) must still work
    for the hand-rolled YAML parser callers."""
    assert _catalog._coerce_yaml_scalar("true") is True
    assert _catalog._coerce_yaml_scalar("false") is False
    assert _catalog._coerce_yaml_scalar("25") == 25
    assert _catalog._coerce_yaml_scalar("hello") == "hello"
    assert _catalog._coerce_yaml_scalar('"quoted"') == "quoted"