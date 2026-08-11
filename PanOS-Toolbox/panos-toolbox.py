#!/usr/bin/env python3
"""Canonical standalone entry point for PanOS Toolbox."""

from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
VENDOR = BACKEND / "vendor"

for path in (BACKEND, VENDOR if VENDOR.is_dir() else None):
    if path is None:
        continue
    value = str(path)
    sys.path[:] = [entry for entry in sys.path if entry != value]
    sys.path.insert(0, value)

from panos_toolbox.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
