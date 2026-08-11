"""Resolve trusted Windows system executables without consulting PATH."""

from __future__ import annotations

import os
import re
from typing import Optional


_EXECUTABLE_NAME = re.compile(r"^[A-Za-z0-9_.-]+\.exe$", re.IGNORECASE)


def windows_system_tool(name: str) -> Optional[str]:
    """Return a System32/Sysnative executable or None, never a PATH result."""

    if os.name != "nt" or not _EXECUTABLE_NAME.fullmatch(name):
        return None
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        return None
    for directory in ("System32", "Sysnative"):
        candidate = os.path.abspath(os.path.join(system_root, directory, name))
        if os.path.isfile(candidate):
            return candidate
    return None
