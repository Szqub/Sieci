"""Validate Active Directory groups and build PAN-OS custom LDAP filters."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence

from .errors import DependencyError, InputError


MAX_GROUPS = 500
FILTER_CHUNK_SIZE = 6
PANORAMA_PREFIX = "AD__"
_ALLOWED_STATUSES = {"valid", "empty", "not-found", "error"}


def _clean_text(value: object, label: str, *, maximum: int = 255) -> str:
    if not isinstance(value, str):
        raise InputError(f"Pole {label} musi być tekstem.")
    cleaned = value.strip()
    if not cleaned:
        raise InputError(f"Pole {label} nie może być puste.")
    if len(cleaned) > maximum:
        raise InputError(f"Pole {label} może mieć maksymalnie {maximum} znaków.")
    if any(ord(character) < 32 or ord(character) == 127 for character in cleaned):
        raise InputError(f"Pole {label} zawiera niedozwolony znak sterujący.")
    return cleaned


def normalize_group_names(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        name = _clean_text(raw, "groups[]")
        if name.startswith(("#", ";")):
            continue
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(name)
    if not result:
        raise InputError("Wklej przynajmniej jedną nazwę grupy AD.")
    if len(result) > MAX_GROUPS:
        raise InputError(f"Jedno sprawdzenie może zawierać maksymalnie {MAX_GROUPS} grup AD.")
    return result


def panorama_group_name(value: str) -> str:
    raw = _clean_text(value, "output_name", maximum=251)
    suffix = raw[4:] if raw[:4].casefold() == PANORAMA_PREFIX.casefold() else raw
    suffix = suffix.strip()
    if not suffix:
        raise InputError("Nazwa wynikowa musi zawierać tekst po prefiksie AD__.")
    return PANORAMA_PREFIX + suffix


def escape_ldap_filter_value(value: str) -> str:
    """Escape an LDAP assertion value according to RFC 4515."""

    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    return "".join(replacements.get(character, character) for character in value)


def build_filter_blocks(valid_groups: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for start in range(0, len(valid_groups), FILTER_CHUNK_SIZE):
        chunk = valid_groups[start : start + FILTER_CHUNK_SIZE]
        parts = [
            f"(memberof={escape_ldap_filter_value(str(item['distinguishedName']))})"
            for item in chunk
        ]
        ldap_filter = parts[0] if len(parts) == 1 else "(|" + "".join(parts) + ")"
        blocks.append(
            {
                "index": len(blocks) + 1,
                "filter": ldap_filter,
                "sourceGroups": [str(item["name"]) for item in chunk],
            }
        )
    return blocks


def _powershell_executable() -> str:
    for candidate in ("powershell.exe", "powershell"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise DependencyError(
        "Nie znaleziono Windows PowerShell. Walidacja AD wymaga PowerShell oraz modułu ActiveDirectory (RSAT)."
    )


def lookup_ad_groups(group_names: Sequence[str], *, timeout_seconds: int = 90) -> list[dict[str, Any]]:
    script = Path(__file__).with_name("ad_group_lookup.ps1")
    if not script.is_file():
        raise DependencyError("Paczka nie zawiera helpera walidacji AD.")
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        completed = subprocess.run(
            [
                _powershell_executable(),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
            ],
            input=json.dumps({"groups": list(group_names)}, ensure_ascii=False),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
            creationflags=creation_flags,
        )
    except subprocess.TimeoutExpired as exc:
        raise DependencyError("Walidacja AD przekroczyła limit 90 sekund.") from exc
    except OSError as exc:
        raise DependencyError("Nie udało się uruchomić lokalnej walidacji AD.") from exc

    if completed.returncode != 0:
        raise DependencyError("PowerShell zakończył walidację AD błędem.")
    try:
        payload = json.loads(completed.stdout.strip())
    except (json.JSONDecodeError, TypeError) as exc:
        raise DependencyError("Walidator AD zwrócił niepoprawną odpowiedź.") from exc
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        message = payload.get("message") if isinstance(payload, dict) else None
        raise DependencyError(str(message or "Moduł ActiveDirectory nie jest dostępny."))
    items = payload.get("groups")
    if not isinstance(items, list):
        raise DependencyError("Walidator AD nie zwrócił listy grup.")
    return items


def generate_ad_group_definition(
    group_names: Iterable[str],
    *,
    output_name: str,
    mapping_name: str = "LDAP_GM1",
    vsys: str = "vsys1",
    template_name: str = "",
    lookup: Optional[Callable[[Sequence[str]], list[dict[str, Any]]]] = None,
) -> dict[str, Any]:
    names = normalize_group_names(group_names)
    final_name = panorama_group_name(output_name)
    mapping = _clean_text(mapping_name, "mapping_name")
    target_vsys = _clean_text(vsys, "vsys")
    template = template_name.strip() if isinstance(template_name, str) else ""
    if len(template) > 255 or any(ord(character) < 32 or ord(character) == 127 for character in template):
        raise InputError("Pole template_name jest niepoprawne.")

    raw_items = (lookup or lookup_ad_groups)(names)
    by_name = {
        str(item.get("name", "")).casefold(): item
        for item in raw_items
        if isinstance(item, dict) and item.get("name")
    }
    results: list[dict[str, Any]] = []
    for name in names:
        raw = by_name.get(name.casefold()) or {}
        status = str(raw.get("status") or "error")
        if status not in _ALLOWED_STATUSES:
            status = "error"
        member_count = raw.get("memberCount", 0)
        if isinstance(member_count, bool) or not isinstance(member_count, int) or member_count < 0:
            member_count = 0
        distinguished_name = str(raw.get("distinguishedName") or "").strip()
        if status == "valid" and (member_count < 1 or not distinguished_name):
            status = "error"
        detail = {
            "valid": f"Grupa istnieje i ma {member_count} członków.",
            "empty": "Grupa istnieje, ale nie ma żadnego członka — pominięto.",
            "not-found": "Nie znaleziono grupy w Active Directory — pominięto.",
            "error": "Nie udało się potwierdzić grupy w Active Directory — pominięto.",
        }[status]
        results.append(
            {
                "name": name,
                "status": status,
                "memberCount": member_count,
                "distinguishedName": distinguished_name if status == "valid" else None,
                "detail": detail,
            }
        )

    valid = [item for item in results if item["status"] == "valid"]
    blocks = build_filter_blocks(valid)
    warnings = [item["detail"] + f" ({item['name']})" for item in results if item["status"] != "valid"]
    target_parts = ["Device Templates"]
    if template:
        target_parts.append(template)
    target_parts.extend(
        ["User Identification", "Group Mapping Settings", mapping, f"Custom Group (VSYS: {target_vsys})"]
    )
    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "outputGroupName": final_name,
        "mappingName": mapping,
        "vsys": target_vsys,
        "templateName": template,
        "panoramaPath": " > ".join(target_parts),
        "chunkSize": FILTER_CHUNK_SIZE,
        "inputCount": len(names),
        "validCount": len(valid),
        "skippedCount": len(results) - len(valid),
        "groups": results,
        "blocks": blocks,
        "clipboardText": "\n\n".join(block["filter"] for block in blocks),
        "warnings": warnings,
    }
