"""Targeted read-only lookup for a few exact Panorama entities.

The full cleaner still owns dependency planning.  This module intentionally
uses narrow configuration XPaths so an operator can first locate and inspect a
small number of objects without downloading the complete running config.
"""

from __future__ import annotations

import concurrent.futures
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .cleaner_adapter import _legacy_root
from .errors import InputError, ToolboxError
from .xmlutil import xpath_literal


LOOKUP_TYPES = {"address", "address-group", "policy", "ip"}
POLICY_TYPES = ("security", "nat", "application-override")
RULEBASES = ("pre-rulebase", "post-rulebase")


@dataclass(frozen=True)
class _Query:
    requested_name: str
    entity_type: str
    scope: str
    xpath: str
    rulebase: Optional[str] = None
    policy_type: Optional[str] = None


def _normalize_names(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if any(character in value for character in ("\r", "\n", "\x00")):
            raise InputError("Nazwa wyszukiwania zawiera niedozwolony znak sterujący.")
        if value not in seen:
            seen.add(value)
            result.append(value)
    if not result:
        raise InputError("Podaj co najmniej jedną dokładną nazwę lub adres IP.")
    if len(result) > 20:
        raise InputError("Tryb punktowy obsługuje maksymalnie 20 wartości; użyj batch dla większej listy.")
    return tuple(result)


def _scope_root(scope: str) -> str:
    if scope == "shared":
        return "/config/shared"
    return (
        "/config/devices/entry/device-group/entry[@name="
        + xpath_literal(scope)
        + "]"
    )


def _queries(kind: str, names: tuple[str, ...], scopes: tuple[str, ...]) -> list[_Query]:
    result: list[_Query] = []
    for scope in scopes:
        root = _scope_root(scope)
        for name in names:
            literal = xpath_literal(name)
            if kind == "address":
                result.append(_Query(name, "address", scope, f"{root}/address/entry[@name={literal}]"))
            elif kind == "address-group":
                result.append(_Query(name, "address-group", scope, f"{root}/address-group/entry[@name={literal}]"))
            elif kind == "ip":
                values = (name, f"{name}/32" if ":" not in name and "/" not in name else name)
                for value in dict.fromkeys(values):
                    value_literal = xpath_literal(value)
                    for field in ("ip-netmask", "ip-range"):
                        result.append(
                            _Query(
                                name,
                                "address",
                                scope,
                                f"{root}/address/entry[{field}={value_literal}]",
                            )
                        )
            else:
                for rulebase in RULEBASES:
                    for policy_type in POLICY_TYPES:
                        result.append(
                            _Query(
                                name,
                                "policy",
                                scope,
                                f"{root}/{rulebase}/{policy_type}/rules/entry[@name={literal}]",
                                rulebase,
                                policy_type,
                            )
                        )
    return result


def _matching_entries(root: ET.Element, query: _Query) -> list[ET.Element]:
    matches: list[ET.Element] = []
    for entry in root.iter("entry"):
        name = entry.get("name") or ""
        if query.entity_type == "address" and query.requested_name != name:
            values = {
                (entry.findtext("./ip-netmask") or "").strip(),
                (entry.findtext("./ip-range") or "").strip(),
            }
            requested = query.requested_name
            if requested not in values and f"{requested}/32" not in values:
                continue
        elif name != query.requested_name:
            continue
        if query.entity_type == "address" and not any(
            entry.find(f"./{field}") is not None
            for field in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard")
        ):
            continue
        if query.entity_type == "address-group" and not any(
            entry.find(f"./{field}") is not None for field in ("static", "dynamic")
        ):
            continue
        matches.append(entry)
    return matches


def _members(entry: ET.Element, field: str) -> str:
    values = [
        (node.text or "").strip()
        for node in entry.findall(f"./{field}/member")
        if (node.text or "").strip()
    ]
    return ", ".join(values) if values else "—"


def _member_list(entry: ET.Element, field: str) -> list[str]:
    return [
        (node.text or "").strip()
        for node in entry.findall(f"./{field}/member")
        if (node.text or "").strip()
    ]


def _dependency(
    query: _Query,
    *,
    name: str,
    relation: str,
    dependency_type: str = "address-or-group",
) -> dict[str, Any]:
    return {
        "id": (
            f"reference:{query.scope}:{query.rulebase or '-'}:"
            f"{query.policy_type or '-'}:{query.requested_name}:{relation}:{name}"
        ),
        "type": dependency_type,
        "name": name,
        "scope": query.scope,
        "relation": relation,
        "path": query.xpath,
        "readOnly": query.policy_type == "application-override",
    }


def _wire_entry(entry: ET.Element, query: _Query) -> dict[str, Any]:
    name = entry.get("name") or query.requested_name
    read_only = False
    blocked_reason = None
    fields: list[dict[str, str]] = []
    dependencies: list[dict[str, Any]] = []
    value = ""
    if query.entity_type == "address":
        for field in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard"):
            text = (entry.findtext(f"./{field}") or "").strip()
            if text:
                value = text
                fields.append({"k": "Wartość", "v": text})
                fields.append({"k": "Typ", "v": field})
                break
        tags = _members(entry, "tag")
        if tags != "—":
            fields.append({"k": "Tagi", "v": tags})
    elif query.entity_type == "address-group":
        dynamic = entry.find("./dynamic")
        if dynamic is not None:
            value = (dynamic.findtext("./filter") or "").strip()
            fields.extend(({"k": "Typ", "v": "dynamic"}, {"k": "Filtr", "v": value or "—"}))
            read_only = True
            blocked_reason = "Dynamic Address Group wymaga ręcznego review; Toolbox jej automatycznie nie usuwa."
        else:
            members = _members(entry, "static")
            value = members
            fields.extend(({"k": "Typ", "v": "static"}, {"k": "Członkowie", "v": members}))
            dependencies.extend(
                _dependency(query, name=name, relation="contains")
                for name in _member_list(entry, "static")
            )
    else:
        value = query.policy_type or "policy"
        fields.extend(
            [
                {"k": "Device group", "v": query.scope},
                {"k": "Rulebase", "v": query.rulebase or "—"},
                {"k": "Typ polityki", "v": query.policy_type or "—"},
                {"k": "From / strefa", "v": _members(entry, "from")},
                {"k": "To / strefa", "v": _members(entry, "to")},
                {"k": "Source", "v": _members(entry, "source")},
                {"k": "Destination", "v": _members(entry, "destination")},
                {"k": "Service", "v": _members(entry, "service")},
                {"k": "Application", "v": _members(entry, "application")},
                {"k": "Tagi", "v": _members(entry, "tag")},
                {
                    "k": "Komentarz",
                    "v": (
                        entry.findtext("./description")
                        or entry.findtext("./comments")
                        or entry.findtext("./audit-comment")
                        or "—"
                    ).strip(),
                },
            ]
        )
        action = (entry.findtext("./action") or "").strip()
        if action:
            fields.append({"k": "Action", "v": action})
        for field in ("source", "destination"):
            dependencies.extend(
                _dependency(query, name=name, relation=field)
                for name in _member_list(entry, field)
                if name not in {"any", "none"}
            )
        translated_names = {
            (node.text or "").strip()
            for node in entry.findall(".//translated-address/member")
            if (node.text or "").strip()
        }
        translated_names.update(
            (node.text or "").strip()
            for node in entry.findall(".//translated-address")
            if not list(node) and (node.text or "").strip()
        )
        dependencies.extend(
            _dependency(query, name=name, relation="translated-address")
            for name in sorted(translated_names - {"any", "none"})
        )
        if name.casefold() == "default":
            read_only = True
            blocked_reason = (
                "Polityka DEFAULT jest chroniona. Jej usunięcie i dotknięcie "
                "zależności wymaga jawnego override w planie cleanup."
            )
        elif query.policy_type == "application-override":
            read_only = True
            blocked_reason = (
                "Application Override jest oznaczony jako read-only: usuń regułę ręcznie "
                "w Panoramie, aby nie zablokowała bezpiecznego planu."
            )
    fields.insert(0, {"k": "Scope", "v": query.scope})
    return {
        "id": f"{query.entity_type}:{query.scope}:{query.rulebase or '-'}:{query.policy_type or '-'}:{name}",
        "type": query.entity_type,
        "name": name,
        "value": value,
        "scope": query.scope,
        "rulebase": query.rulebase,
        "policyType": query.policy_type,
        "xpath": query.xpath,
        "readOnly": read_only,
        "blockedReason": blocked_reason,
        "fields": fields,
        "dependencies": dependencies,
        "hitCount": None,
        "lastHit": None,
        "lastHitStatus": None,
        "lastHitAgeDays": None,
        "lastHitDetail": None,
    }


def _attach_hit_counts(reader: Any, items: list[dict[str, Any]], recent_days: int) -> None:
    policy_items = [item for item in items if item["type"] == "policy"]
    if not policy_items:
        return
    _legacy_root()
    from panorama_cleanup.hitcounts import collect_rule_hit_counts  # type: ignore[import-not-found]
    from panorama_cleanup.models import RuleKey  # type: ignore[import-not-found]

    keys = {
        RuleKey(item["scope"], item["rulebase"], item["policyType"], item["name"])
        for item in policy_items
    }
    results = collect_rule_hit_counts(reader, keys, recent_days=recent_days)
    for item in policy_items:
        key = RuleKey(item["scope"], item["rulebase"], item["policyType"], item["name"])
        hit = results[key]
        item.update(
            hitCount=hit.hit_count,
            lastHit=hit.last_hit_utc,
            lastHitStatus=hit.status,
            lastHitAgeDays=hit.age_days,
            lastHitDetail=hit.detail,
        )


def lookup_exact(
    reader: Any,
    kind: str,
    raw_names: Iterable[str],
    *,
    device_group: Optional[str] = None,
    recent_days: int = 14,
) -> dict[str, Any]:
    if kind not in LOOKUP_TYPES:
        raise InputError("type musi być address, address-group, policy albo ip.")
    if not 1 <= recent_days <= 3650:
        raise InputError("recent_days musi być w zakresie 1..3650.")
    names = _normalize_names(raw_names)
    started = time.perf_counter()
    warnings: list[str] = []
    partial = False
    api_calls = 0
    if device_group:
        scopes = (device_group.strip(),)
    else:
        try:
            device_groups = tuple(reader.device_group_names())
            api_calls += 1
        except ToolboxError as exc:
            device_groups = ()
            partial = True
            warnings.append(f"Nie udało się pobrać lekkiej listy device groups: {exc}")
        scopes = ("shared", *device_groups)
    tasks = _queries(kind, names, scopes)
    found: dict[str, dict[str, Any]] = {}

    def execute(query: _Query) -> tuple[_Query, ET.Element]:
        return query, reader.fetch_xpath(query.xpath, config_type="running")

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(1, len(tasks)))) as pool:
        futures = [pool.submit(execute, query) for query in tasks]
        for future in concurrent.futures.as_completed(futures):
            api_calls += 1
            try:
                query, response = future.result()
            except ToolboxError as exc:
                partial = True
                warnings.append(str(exc))
                continue
            for entry in _matching_entries(response, query):
                item = _wire_entry(entry, query)
                found[item["id"]] = item

    items = sorted(
        found.values(),
        key=lambda item: (item["name"].casefold(), item["scope"], item.get("rulebase") or "", item.get("policyType") or ""),
    )
    _attach_hit_counts(reader, items, recent_days)
    if any(item["policyType"] == "application-override" for item in items):
        warnings.append(
            "Wykryto Application Override. Toolbox pokazuje XPath, ale nie doda tej reguły do automatycznego usuwania."
        )
    if any(item["name"].casefold() == "default" for item in items):
        warnings.append(
            "Wykryto politykę DEFAULT. Jest chroniona przed usunięciem i dotknięciem zależności bez jawnego override."
        )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return {
        "found": items,
        "requested": list(names),
        "searchedScopes": len(scopes),
        "apiCalls": api_calls,
        "elapsedMs": elapsed_ms,
        "partial": partial,
        "warnings": list(dict.fromkeys(warnings))[:20],
    }
