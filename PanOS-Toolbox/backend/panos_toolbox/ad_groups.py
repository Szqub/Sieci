"""Validate Active Directory groups and build PAN-OS custom LDAP filters."""

from __future__ import annotations

import locale
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional, Sequence

from .errors import DependencyError, InputError
from .handmode import quote_cli
from .platform_tools import windows_system_tool


MAX_GROUPS = 500
FILTER_CHUNK_SIZE = 6
PANORAMA_PREFIX = "AD__"
_ALLOWED_STATUSES = {"valid", "empty", "not-found", "error"}
_DN_PREFIX = re.compile(r"^(?:CN|OU|DC|O|C|L|ST|UID)=", re.IGNORECASE)


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


def _custom_group_name(base: str, index: int, total: int) -> str:
    """Give every LDAP block a distinct PAN-OS Custom Group entry name."""

    if total == 1:
        return base
    suffix = f"__{index:02d}"
    return base[: 255 - len(suffix)] + suffix


def build_custom_group_cli(
    blocks: Sequence[dict[str, Any]],
    *,
    output_name: str,
    template_name: str,
    vsys: str,
    mapping_name: str,
) -> list[dict[str, Any]]:
    """Build command-only Hand Mode entries for Panorama template CLI.

    PAN-OS stores one LDAP filter per Custom Group entry.  More than one
    six-DN block therefore receives a deterministic numbered entry instead of
    repeatedly overwriting the same ``ldap-filter`` leaf.
    """

    if not template_name:
        return []
    prefix = [
        "template",
        quote_cli(template_name, context="Device Template"),
        "config",
        "vsys",
        quote_cli(vsys, context="VSYS"),
        "group-mapping",
        quote_cli(mapping_name, context="Group Mapping"),
        "custom-group",
    ]
    result: list[dict[str, Any]] = []
    total = len(blocks)
    for block in blocks:
        index = int(block["index"])
        name = _custom_group_name(output_name, index, total)
        entry_path = [*prefix, quote_cli(name, context="Custom Group")]
        command = " ".join(
            [
                "set",
                *entry_path,
                "ldap-filter",
                quote_cli(str(block["filter"]), context="LDAP filter"),
            ]
        )
        rollback = " ".join(["delete", *entry_path])
        result.append(
            {
                **dict(block),
                "panoramaGroupName": name,
                "cliCommand": command,
                "rollbackCliCommand": rollback,
            }
        )
    return result


def _directory_service_tools() -> tuple[str, str]:
    """Return Microsoft RSAT tools only from protected Windows system paths."""

    dsquery = windows_system_tool("dsquery.exe")
    dsget = windows_system_tool("dsget.exe")
    if not dsquery or not dsget:
        raise DependencyError(
            "Nie znaleziono dsquery.exe/dsget.exe. Walidacja AD wymaga zatwierdzonych "
            "narzędzi RSAT Active Directory Domain Services."
        )
    return dsquery, dsget


def _decode_directory_output(payload: bytes) -> str:
    if not payload:
        return ""
    if payload.startswith((b"\xff\xfe", b"\xfe\xff")):
        return payload.decode("utf-16", errors="replace")
    if b"\x00" in payload[:32]:
        return payload.decode("utf-16-le", errors="replace")
    return payload.decode(locale.getpreferredencoding(False), errors="replace")


def _directory_dns(payload: str) -> list[str]:
    """Extract only directory object DNs, ignoring localized tool status text."""

    result: list[str] = []
    for raw_line in payload.splitlines():
        value = raw_line.strip().lstrip("\ufeff")
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace('""', '"').strip()
        if value and _DN_PREFIX.match(value):
            result.append(value)
    return result


def _run_directory_command(
    executable: str, arguments: Sequence[str], *, timeout_seconds: float
) -> tuple[int, str]:
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    completed = subprocess.run(
        [executable, *arguments],
        capture_output=True,
        timeout=max(0.1, timeout_seconds),
        check=False,
        creationflags=creation_flags,
    )
    return completed.returncode, _decode_directory_output(completed.stdout)


def lookup_ad_groups(group_names: Sequence[str], *, timeout_seconds: int = 90) -> list[dict[str, Any]]:
    """Validate exact group names through Microsoft-signed RSAT executables.

    The implementation deliberately does not invoke PowerShell, change an
    execution policy, pass credentials, or use a shell.  Both tools use the
    current Windows identity and every query is restricted to one exact SAM
    account name supplied by the operator.
    """

    if not 1 <= timeout_seconds <= 600:
        raise ValueError("timeout_seconds musi być w zakresie 1..600")
    names = list(group_names)
    if any("*" in name or "?" in name for name in names):
        raise InputError(
            "Walidacja AD przyjmuje dokładne nazwy grup; znaki wieloznaczne * i ? są zabronione."
        )
    dsquery, dsget = _directory_service_tools()
    deadline = time.monotonic() + timeout_seconds
    results: list[dict[str, Any]] = []

    def remaining() -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise subprocess.TimeoutExpired("RSAT AD lookup", timeout_seconds)
        return value

    try:
        for name in names:
            query_code, query_output = _run_directory_command(
                dsquery,
                ("group", "-samid", name, "-o", "dn", "-limit", "2", "-uco"),
                timeout_seconds=remaining(),
            )
            distinguished_names = _directory_dns(query_output)
            if query_code != 0:
                results.append(
                    {
                        "name": name,
                        "status": "error",
                        "memberCount": 0,
                        "distinguishedName": None,
                    }
                )
                continue
            if not distinguished_names:
                results.append(
                    {
                        "name": name,
                        "status": "not-found",
                        "memberCount": 0,
                        "distinguishedName": None,
                    }
                )
                continue
            if len(distinguished_names) != 1:
                results.append(
                    {
                        "name": name,
                        "status": "error",
                        "memberCount": 0,
                        "distinguishedName": None,
                    }
                )
                continue

            distinguished_name = distinguished_names[0]
            members_code, members_output = _run_directory_command(
                dsget,
                ("group", distinguished_name, "-members", "-uco"),
                timeout_seconds=remaining(),
            )
            if members_code != 0:
                results.append(
                    {
                        "name": name,
                        "status": "error",
                        "memberCount": 0,
                        "distinguishedName": None,
                    }
                )
                continue
            member_count = len(_directory_dns(members_output))
            results.append(
                {
                    "name": name,
                    "status": "valid" if member_count else "empty",
                    "memberCount": member_count,
                    "distinguishedName": distinguished_name,
                }
            )
    except subprocess.TimeoutExpired as exc:
        raise DependencyError(
            f"Walidacja AD przekroczyła limit {timeout_seconds} sekund."
        ) from exc
    except OSError as exc:
        raise DependencyError("Nie udało się uruchomić lokalnej walidacji AD.") from exc
    return results


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
    cli_groups = build_custom_group_cli(
        blocks,
        output_name=final_name,
        template_name=template,
        vsys=target_vsys,
        mapping_name=mapping,
    )
    if blocks and not template:
        warnings.append(
            "Hand Mode CLI ma status BLOCK: podaj dokładny Device Template; "
            "Toolbox nie wygeneruje komendy z placeholderem."
        )
    if len(cli_groups) > 1:
        warnings.append(
            f"Filtr wymaga {len(cli_groups)} wpisów Custom Group; nadano im "
            f"nazwy {cli_groups[0]['panoramaGroupName']} … "
            f"{cli_groups[-1]['panoramaGroupName']}, aby kolejne set nie nadpisywały ldap-filter."
        )
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
        "cliGroups": cli_groups,
        "cliText": "\n".join(item["cliCommand"] for item in cli_groups)
        + ("\n" if cli_groups else ""),
        "rollbackCliText": "\n".join(
            reversed([item["rollbackCliCommand"] for item in cli_groups])
        )
        + ("\n" if cli_groups else ""),
        "handModeReady": bool(cli_groups),
        "warnings": warnings,
    }
