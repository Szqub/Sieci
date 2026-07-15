#!/usr/bin/env python3
"""Repository entry point for PanOS Toolbox."""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent / "backend"
backend_text = str(BACKEND)
sys.path[:] = [entry for entry in sys.path if entry != backend_text]
sys.path.insert(0, backend_text)
VENDOR = BACKEND / "vendor"
if VENDOR.is_dir():
    vendor_text = str(VENDOR)
    sys.path[:] = [entry for entry in sys.path if entry != vendor_text]
    sys.path.insert(0, vendor_text)

from panos_toolbox.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
