"""Non-blocking running/candidate comparison for operator information."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Optional

from .xmlutil import raw_sha256, supported_entities


def summarize_native_change_summary(root: Optional[ET.Element]) -> dict[str, Any]:
    if root is None:
        return {
            "available": False,
            "has_changes": None,
            "detail": "Natywny change-summary nie został pobrany.",
        }
    raw = ET.tostring(root, encoding="utf-8")
    result = root.find("./result") if root.tag == "response" else root
    text = " ".join(item.strip() for item in result.itertext() if item.strip()) if result is not None else ""
    lowered = text.casefold()
    meaningful = [
        node
        for node in (result.iter() if result is not None else ())
        if node is not result and (node.attrib or (node.text or "").strip())
    ]
    if "no change" in lowered or "brak zmian" in lowered:
        has_changes: Optional[bool] = False
    else:
        has_changes = bool(meaningful)
    return {
        "available": True,
        "has_changes": has_changes,
        "sha256": raw_sha256(raw),
        "detail": text[:1000] or "Panorama zwróciła pusty change-summary.",
    }


def semantic_diff(running: ET.Element, candidate: ET.Element) -> dict[str, Any]:
    running_entities = supported_entities(running)
    candidate_entities = supported_entities(candidate)
    running_keys = set(running_entities)
    candidate_keys = set(candidate_entities)
    added = sorted(candidate_keys - running_keys)
    removed = sorted(running_keys - candidate_keys)
    changed = sorted(
        key
        for key in running_keys & candidate_keys
        if running_entities[key] != candidate_entities[key]
    )
    return {
        "has_changes": bool(added or removed or changed),
        "added": added,
        "removed": removed,
        "changed": changed,
        "running_entity_count": len(running_entities),
        "candidate_entity_count": len(candidate_entities),
    }


def compare_configs(
    running: ET.Element,
    candidate: ET.Element,
    native_summary: Optional[ET.Element],
) -> dict[str, Any]:
    native = summarize_native_change_summary(native_summary)
    semantic = semantic_diff(running, candidate)
    warnings: list[str] = []
    if (
        native["has_changes"] is not None
        and native["has_changes"] != semantic["has_changes"]
    ):
        warnings.append(
            "Natywny change-summary i semantyczny diff obsługiwanych namespace'ów "
            "dają różne wyniki. Jest to informacja diagnostyczna, nie globalna blokada."
        )
    return {
        "blocking": False,
        "native": native,
        "semantic": semantic,
        "warnings": warnings,
    }
