"""Bridge helpers that call decoder implementations still defined in snitch.py."""

import importlib
import os
import sys


def _is_snitch_module(module):
    file_path = getattr(module, "__file__", "")
    return bool(file_path) and os.path.basename(file_path) == "snitch.py"


def get_snitch_module():
    module = sys.modules.get("snitch")
    if module is not None and _is_snitch_module(module):
        return module

    main_module = sys.modules.get("__main__")
    if main_module is not None and _is_snitch_module(main_module):
        return main_module

    return importlib.import_module("snitch")


def call_decoder(decoder_name, *args, **kwargs):
    module = get_snitch_module()
    decoder_fn = getattr(module, decoder_name, None)
    if not callable(decoder_fn):
        raise RuntimeError(f"Decoder function not available: {decoder_name}")
    return decoder_fn(*args, **kwargs)
