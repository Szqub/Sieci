"""Application service shared by the CLI and localhost web adapter."""

from __future__ import annotations

import concurrent.futures
import copy
import dataclasses
import ipaddress
import json
import os
import subprocess
import time
import xml.etree.ElementTree as ET
from contextlib import ExitStack
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from .cleaner_adapter import (
    CleanerPlanResult,
    _expanded_device_groups,
    _legacy_root,
    build_cleanup_patchset,
)
from .client import PanoramaReadClient, PanoramaWriteClient
from .diffing import compare_configs
from .engine import ApplyResult, apply_candidate, commit_session, push_session
from .errors import InputError, SessionError, ToolboxError
from .models import ApiStage, PatchSet, SessionState
from .profile import PanoramaProfile, issue_write_lease
from .restore import (
    HistoricalMutation,
    SelectedHistory,
    apply_operation_to_tree,
    build_restore_patchset_history,
    mutation_owner_xpath,
    select_history,
)
from .sessions import AppliedCleanup, SessionStore
from .xmlutil import (
    device_group_from_xpath,
    find_xpath,
    parent_xpath,
    xpath_literal,
)


@dataclass(frozen=True)
class PingObservation:
    ip: str
    status: str
    detail: str
    elapsed_seconds: float


def normalize_ips(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(values, 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        try:
            normalized = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise InputError(f"Pozycja IP {index} jest niepoprawna: {value!r}.") from exc
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    if not result:
        raise InputError("Nie podano żadnego poprawnego IP.")
    return tuple(result)


def _ping_one(ip: str, timeout_ms: int) -> PingObservation:
    parsed = ipaddress.ip_address(ip)
    if os.name == "nt":
        command = ["ping", "-n", "1", "-w", str(timeout_ms)]
        if parsed.version == 6:
            command.append("-6")
        command.append(ip)
    else:
        command = ["ping", "-n", "-c", "1", "-W", str(max(1, timeout_ms // 1000))]
        if parsed.version == 6:
            command.append("-6")
        command.append(ip)
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_ms / 1000 + 3,
            check=False,
            env={
                key: value
                for key, value in os.environ.items()
                if "PASSWORD" not in key.upper() and "TOKEN" not in key.upper()
            },
        )
    except FileNotFoundError:
        return PingObservation(ip, "ERROR", "Program ping nie jest dostępny", time.perf_counter() - started)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return PingObservation(ip, "ERROR", f"Błąd procesu ping: {type(exc).__name__}", time.perf_counter() - started)
    if completed.returncode == 0:
        status, detail = "REPLIED", "Odebrano odpowiedź ICMP"
    else:
        output = (completed.stdout + completed.stderr).decode(errors="replace").casefold()
        fatal_markers = (
            "could not find host",
            "unknown host",
            "name or service not known",
            "general failure",
            "invalid argument",
            "nie można odnaleźć hosta",
            "nie mozna odnalezc hosta",
            "błąd ogólny",
            "blad ogolny",
        )
        ordinary_timeout = completed.returncode == 1 and not any(
            marker in output for marker in fatal_markers
        )
        status = "NO_REPLY" if ordinary_timeout else "ERROR"
        detail = (
            f"Brak odpowiedzi ICMP (kod {completed.returncode})"
            if ordinary_timeout
            else f"Błąd procesu ICMP (kod {completed.returncode})"
        )
    return PingObservation(ip, status, detail, time.perf_counter() - started)


def ping_ips(
    ips: Iterable[str], *, bypass: bool, timeout_ms: int = 1000, workers: int = 32
) -> dict[str, PingObservation]:
    values = tuple(sorted(set(ips)))
    if bypass:
        return {
            ip: PingObservation(ip, "BYPASSED", "ICMP pominięty jawnie", 0.0)
            for ip in values
        }
    if not 100 <= timeout_ms <= 60_000 or not 1 <= workers <= 128:
        raise InputError("Niepoprawny timeout/workers ICMP.")
    result: dict[str, PingObservation] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(values))) as pool:
        futures = {pool.submit(_ping_one, ip, timeout_ms): ip for ip in values}
        for future in concurrent.futures.as_completed(futures):
            observation = future.result()
            result[observation.ip] = observation
    return {ip: result[ip] for ip in values}


def _last_hit_summary(
    reader: PanoramaReadClient,
    plan_result: CleanerPlanResult,
    *,
    recent_days: int,
) -> dict[str, Any]:
    _legacy_root()
    from panorama_cleanup.hitcounts import collect_rule_hit_counts  # type: ignore[import-not-found]

    results = collect_rule_hit_counts(
        reader, plan_result.plan.deleted_rules, recent_days=recent_days
    )
    records = []
    for key, value in sorted(results.items()):
        record = dataclasses.asdict(value)
        record["rule"] = {
            "location": key.location,
            "rulebase": key.rulebase,
            "policy_type": key.policy_type,
            "name": key.name,
        }
        records.append(record)
    review = [record for record in records if record["status"] != "STALE"]
    recent_count = sum(record["status"] == "RECENT" for record in records)
    error_count = sum(
        record["status"] in {"ERROR", "NEVER", "NOT_FOUND", "INVALID", "NOT_LATEST"}
        for record in records
    )
    return {
        "recent_days": recent_days,
        "records": records,
        "review_count": len(review),
        "recent_hit_count": recent_count,
        "error_or_unknown_count": error_count,
        "blocking": False,
    }


def _cleanup_inventory(
    result: Optional[CleanerPlanResult], ips: Iterable[str]
) -> dict[str, Any]:
    inventory: dict[str, Any] = {
        ip: {"objects": [], "blocked_reasons": []} for ip in ips
    }
    if result is None:
        return inventory
    from panorama_cleanup.planner import dependency_inventories  # type: ignore[import-not-found]

    keys = {
        key
        for match in result.matches.values()
        for key in match.exact_objects + match.containing_objects
    }
    dependencies = dependency_inventories(result.model, keys)
    for ip in ips:
        match = result.matches.get(ip)
        if match is not None:
            exact = set(match.exact_objects)
            for key in match.exact_objects + match.containing_objects:
                groups, rules, warnings = dependencies[key]
                inventory[ip]["objects"].append(
                    {
                        "location": key.location,
                        "name": key.name,
                        "match": "exact" if key in exact else "containing",
                        "groups": [
                            {"location": item.location, "name": item.name}
                            for item in sorted(groups)
                        ],
                        "policies": [
                            {
                                "location": item.location,
                                "rulebase": item.rulebase,
                                "policy_type": item.policy_type,
                                "name": item.name,
                            }
                            for item in sorted(rules)
                        ],
                        "warnings": list(warnings),
                    }
                )
        inventory[ip]["blocked_reasons"] = [
            dataclasses.asdict(reason) for reason in result.blocked_ips.get(ip, ())
        ]
    return inventory


def _planned_reports(
    ips: Iterable[str],
    pings: dict[str, PingObservation],
    patch: PatchSet,
    inventory: dict[str, Any],
    commands_by_ip: dict[str, list[str]],
) -> tuple[str, str]:
    short_lines: list[str] = []
    detail_lines: list[str] = [
        "RAPORT SZCZEGÓŁOWY PLANU PANOS TOOLBOX",
        "Plan nie oznacza jeszcze zapisu do candidate, commit ani push.",
        "",
    ]
    for lp, ip in enumerate(ips, 1):
        observation = pings[ip]
        record = inventory.get(ip) or {"objects": [], "blocked_reasons": []}
        blocked = record.get("blocked_reasons") or []
        if observation.status == "REPLIED":
            status = "POMINIĘTO_ICMP_ODPOWIEDŹ"
        elif observation.status == "ERROR":
            status = "POMINIĘTO_BŁĄD_ICMP"
        elif blocked:
            status = "REVIEW/BLOKADA: " + ", ".join(
                str(item.get("code", "UNKNOWN")) for item in blocked
            )
        elif not record.get("objects"):
            status = "OBIEKT_NIE_ISTNIEJE"
        elif ip in patch.targets:
            status = "ZAPLANOWANO"
        else:
            status = "BRAK_BEZPIECZNEJ_MUTACJI"
        short_lines.append(f"{lp}. {ip}: {status}")

        detail_lines.extend(
            [
                f"{lp}. IP {ip}",
                f"   ICMP: {observation.status} — {observation.detail}",
                f"   Decyzja: {status}",
            ]
        )
        for obj in record.get("objects") or []:
            detail_lines.append(
                f"   Obiekt: {obj['location']}/{obj['name']} ({obj['match']})"
            )
            for group in obj.get("groups") or []:
                detail_lines.append(
                    f"     Grupa: {group['location']}/{group['name']}"
                )
            for policy in obj.get("policies") or []:
                detail_lines.append(
                    "     Polityka: "
                    f"{policy['location']}/{policy['rulebase']}/"
                    f"{policy['policy_type']}/{policy['name']}"
                )
            for warning in obj.get("warnings") or []:
                detail_lines.append(f"     Ostrzeżenie: {warning}")
        for reason in blocked:
            suffix = f"; path={reason['path']}" if reason.get("path") else ""
            detail_lines.append(
                f"   Blokada {reason.get('code')}: {reason.get('message')}{suffix}"
            )
        commands = commands_by_ip.get(ip) or []
        if commands:
            detail_lines.append("   Komendy CLI planu:")
            detail_lines.extend(f"     {command}" for command in commands)
        detail_lines.append("")
    return "\n".join(short_lines) + "\n", "\n".join(detail_lines)


def plan_cleanup_session(
    store: SessionStore,
    reader: PanoramaReadClient,
    raw_ips: Iterable[str],
    *,
    no_ping: bool = False,
    ping_timeout_ms: int = 1000,
    ping_workers: int = 32,
    nat_translation_action: str = "delete-rule",
    recent_hit_days: int = 14,
) -> dict[str, Any]:
    if nat_translation_action not in {"delete-rule", "block"}:
        raise InputError("nat_translation_action musi być delete-rule albo block.")
    if not 1 <= recent_hit_days <= 3650:
        raise InputError("recent_hit_days musi być w zakresie 1..3650.")
    ips = normalize_ips(raw_ips)
    pings = ping_ips(
        ips, bypass=no_ping, timeout_ms=ping_timeout_ms, workers=ping_workers
    )
    eligible = tuple(
        ip for ip, result in pings.items() if result.status in {"NO_REPLY", "BYPASSED"}
    )
    running = reader.fetch_config("running")
    candidate = reader.fetch_config("candidate")
    native = None
    native_warning: Optional[str] = None
    try:
        native = reader.change_summary()
    except ToolboxError as exc:
        native_warning = f"Nie udało się pobrać change-summary: {exc}"
    diff = compare_configs(running, candidate, native)
    if native_warning:
        diff["warnings"].append(native_warning)

    if eligible:
        result = build_cleanup_patchset(
            running,
            eligible,
            panorama_host=reader.profile.host,
            panorama_username=reader.profile.username,
            nat_translation_action=nat_translation_action,
        )
        patch = result.patchset
        last_hit = _last_hit_summary(
            reader, result, recent_days=recent_hit_days
        )
    else:
        patch = PatchSet.new(
            kind="cleanup",
            panorama_host=reader.profile.host,
            panorama_username=reader.profile.username,
            mutations=(),
            targets=(),
            affected_device_groups=(),
            warnings=("Wszystkie IP odpowiedziały na ICMP albo zwróciły błąd; brak planu cleanup.",),
        )
        result = None
        last_hit = {
            "recent_days": recent_hit_days,
            "records": [],
            "review_count": 0,
            "recent_hit_count": 0,
            "error_or_unknown_count": 0,
            "blocking": False,
        }

    warnings = list(patch.warnings)
    for observation in pings.values():
        if observation.status == "REPLIED":
            warnings.append(f"{observation.ip}: odpowiedział na ICMP i został pominięty.")
        elif observation.status == "ERROR":
            warnings.append(f"{observation.ip}: błąd ICMP, IP pominięto bez blokowania batcha.")
    if last_hit["review_count"]:
        warnings.append(
            f"{last_hit['review_count']} polityk ma last-hit/status wymagający review; nie blokuje planu."
        )
    patch = replace(patch, warnings=tuple(warnings))
    inventory = _cleanup_inventory(result, ips)
    session_id = store.create(
        patch,
        reader.profile,
        planning_running=running,
        planning_candidate=candidate,
        diff_summary=diff,
    )
    ping_records = [dataclasses.asdict(value) for value in pings.values()]

    def enrich(manifest: dict[str, Any]) -> None:
        manifest["icmp"] = ping_records
        manifest["last_hit"] = last_hit
        manifest["input_ips"] = list(ips)
        manifest["inventory"] = inventory
        manifest["nat_translation_action"] = nat_translation_action

    store.update(session_id, enrich)

    commands_text = ""
    commands_by_ip: dict[str, list[str]] = {}
    if result is not None:
        try:
            from panorama_cleanup.render import render_plan  # type: ignore[import-not-found]

            rendered = render_plan(result.model, result.plan)
            commands_text = "\n".join(record.command for record in rendered.commands)
            if commands_text:
                commands_text += "\n"
            for record in rendered.commands:
                for cause in record.causes:
                    commands_by_ip.setdefault(cause, []).append(record.command)
        except Exception as exc:
            # CLI preview is secondary. The structured PatchSet remains valid
            # and executable; record why a pasteable preview was unavailable.
            store.write_artifact(
                session_id,
                "commands_preview_warning.txt",
                f"Nie wygenerowano pomocniczego CLI preview: {type(exc).__name__}: {exc}\n",
                kind="warning",
            )
    store.write_artifact(session_id, "commands.txt", commands_text, kind="cli-preview")
    short_report, detailed_report = _planned_reports(
        ips, pings, patch, inventory, commands_by_ip
    )
    store.write_artifact(
        session_id, "raport_krotki.txt", short_report, kind="report"
    )
    store.write_artifact(
        session_id,
        "raport_szczegolowy.txt",
        detailed_report,
        kind="detailed-report",
    )
    store.write_artifact(
        session_id,
        "plan_summary.json",
        json.dumps(
            {
                "session_id": session_id,
                "patchset": patch.to_dict(),
                "icmp": ping_records,
                "last_hit": last_hit,
                "diff": diff,
                "inventory": inventory,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        kind="report",
    )
    return {
        "session_id": session_id,
        "state": SessionState.PLANNED.value,
        "mutation_count": len(patch.mutations),
        "targets": list(patch.targets),
        "warnings": list(patch.warnings),
        "diff": diff,
        "icmp": ping_records,
        "last_hit": last_hit,
    }


def _history_records(history: Sequence[AppliedCleanup]) -> tuple[HistoricalMutation, ...]:
    return tuple(
        HistoricalMutation(
            source_session_id=cleanup.session_id,
            applied_utc=cleanup.applied_utc,
            source_index=index,
            mutation=mutation,
        )
        for cleanup in history
        for index, mutation in enumerate(cleanup.mutations)
    )


@dataclass(frozen=True)
class HistoricalDependencyGraph:
    owner_sets: tuple[tuple[str, ...], ...]
    forward_dependencies: dict[str, tuple[str, ...]]
    forward_dependencies_by_session: dict[tuple[str, str], tuple[str, ...]]
    unresolved_owners: frozenset[str]
    models_by_session: dict[str, Any]


def _historical_dependency_graph(
    store: SessionStore, history: Sequence[AppliedCleanup]
) -> HistoricalDependencyGraph:
    """Build reverse inventory and forward backup-reference relationships."""

    owner_sets: list[tuple[str, ...]] = []
    forward: dict[str, set[str]] = {}
    forward_by_session: dict[tuple[str, str], set[str]] = {}
    unresolved: set[str] = set()
    models_by_session: dict[str, Any] = {}
    _legacy_root()
    from panorama_cleanup.panos import (  # type: ignore[import-not-found]
        ADDRESS_MEMBER_CONTAINERS,
        parse_config,
        resolve_name,
    )

    for cleanup in history:
        try:
            model = parse_config(store.load_snapshot(cleanup.session_id, "pre_candidate"))
        except Exception as exc:
            raise SessionError(
                f"Sesja {cleanup.session_id} nie ma integralnego pre_candidate potrzebnego "
                "do odtworzenia faktycznego kontekstu zastosowanego cleanupu."
            ) from exc
        models_by_session[cleanup.session_id] = model
        address_paths = {key: value.xpath for key, value in model.addresses.items()}
        group_paths = {key: value.xpath for key, value in model.static_groups.items()}
        dynamic_paths = {key: value.xpath for key, value in model.dynamic_groups.items()}
        group_by_xpath = {value.xpath: value for value in model.static_groups.values()}
        rule_by_xpath = {value.xpath: value for value in model.rules.values()}

        for owner in {mutation_owner_xpath(item) for item in cleanup.mutations}:
            group = group_by_xpath.get(owner)
            rule = rule_by_xpath.get(owner)
            if group is None and rule is None:
                continue
            if group is not None:
                location = group.key.location
                names = group.members
            else:
                assert rule is not None
                location = rule.key.location
                entry = ET.fromstring(rule.xml)
                values: list[str] = []
                for container in entry.iter():
                    if container.tag not in ADDRESS_MEMBER_CONTAINERS:
                        continue
                    members = [
                        member.text.strip()
                        for member in container.findall("./member")
                        if member.text and member.text.strip()
                    ]
                    if members:
                        values.extend(members)
                    elif not list(container) and container.text and container.text.strip():
                        values.append(container.text.strip())
                names = tuple(dict.fromkeys(values))
            dependencies: set[str] = set()
            for name in names:
                kind, resolved, _detail = resolve_name(model, location, name)
                path = None
                if kind == "address" and resolved is not None:
                    path = address_paths.get(resolved)
                elif kind == "static-group" and resolved is not None:
                    path = group_paths.get(resolved)
                elif kind == "dynamic-group" and resolved is not None:
                    path = dynamic_paths.get(resolved)
                elif kind not in {"literal", "builtin"}:
                    unresolved.add(owner)
                if path:
                    dependencies.add(path)
            if dependencies:
                forward.setdefault(owner, set()).update(dependencies)
                forward_by_session.setdefault(
                    (cleanup.session_id, owner), set()
                ).update(dependencies)
                owner_sets.append(tuple(sorted({owner, *dependencies})))

        object_records = [
            record
            for value in cleanup.inventory.values()
            if isinstance(value, dict)
            for record in (value.get("objects") or ())
            if isinstance(record, dict)
        ]
        if not object_records:
            continue
        addresses = {
            (key.location, key.name): value.xpath
            for key, value in model.addresses.items()
        }
        groups = {
            (key.location, key.name): value.xpath
            for key, value in model.static_groups.items()
        }
        policies = {
            (key.location, key.rulebase, key.policy_type, key.name): value.xpath
            for key, value in model.rules.items()
        }
        for record in object_records:
            paths: set[str] = set()
            object_path = addresses.get(
                (str(record.get("location")), str(record.get("name")))
            )
            if object_path:
                paths.add(object_path)
            for group in record.get("groups") or ():
                if not isinstance(group, dict):
                    continue
                path = groups.get(
                    (str(group.get("location")), str(group.get("name")))
                )
                if path:
                    paths.add(path)
            for policy in record.get("policies") or ():
                if not isinstance(policy, dict):
                    continue
                path = policies.get(
                    (
                        str(policy.get("location")),
                        str(policy.get("rulebase")),
                        str(policy.get("policy_type")),
                        str(policy.get("name")),
                    )
                )
                if path:
                    paths.add(path)
            if paths:
                owner_sets.append(tuple(sorted(paths)))
    return HistoricalDependencyGraph(
        owner_sets=tuple(dict.fromkeys(owner_sets)),
        forward_dependencies={
            owner: tuple(sorted(paths)) for owner, paths in forward.items()
        },
        forward_dependencies_by_session={
            key: tuple(sorted(paths)) for key, paths in forward_by_session.items()
        },
        unresolved_owners=frozenset(unresolved),
        models_by_session=models_by_session,
    )


def _history_guard_owner_paths(
    selected: SelectedHistory, graph: HistoricalDependencyGraph
) -> set[str]:
    owners = {mutation_owner_xpath(record.mutation) for record in selected.records}
    changed = True
    while changed:
        changed = False
        for owner_set in graph.owner_sets:
            values = set(owner_set)
            if owners.intersection(values) and not values.issubset(owners):
                owners.update(values)
                changed = True
    for record in selected.records:
        mutation = record.mutation
        if mutation.entity_type != "policy":
            continue
        container = parent_xpath(mutation_owner_xpath(mutation))
        for anchor in (mutation.order_previous, mutation.order_next):
            if anchor:
                owners.add(f"{container}/entry[@name={xpath_literal(anchor)}]")
    return owners


def _historical_scope_conflicts(
    selected: SelectedHistory,
    graph: HistoricalDependencyGraph,
    current_model: Any,
) -> set[str]:
    _legacy_root()
    from panorama_cleanup.panos import resolution_chain  # type: ignore[import-not-found]

    conflicts: set[str] = set()
    for record in selected.records:
        historical = graph.models_by_session[record.source_session_id]
        location = (
            "shared"
            if record.mutation.target_xpath.startswith("/config/shared/")
            else device_group_from_xpath(record.mutation.target_xpath)
        )
        try:
            mismatch = (
                location is None
                or historical.device_entry_name != current_model.device_entry_name
                or historical.ancestor_objects_take_precedence
                != current_model.ancestor_objects_take_precedence
                or resolution_chain(historical, location)
                != resolution_chain(current_model, location)
            )
        except Exception:
            mismatch = True
        if mismatch:
            conflicts.add(
                selected.component_by_qualified_id[record.qualified_id]
            )
    return conflicts


def _forward_dependency_conflicts(
    selected: SelectedHistory,
    graph: HistoricalDependencyGraph,
    candidate: ET.Element,
) -> set[str]:
    by_owner: dict[str, set[str]] = {}
    full_restore_owners: set[str] = set()
    for record in selected.records:
        owner = mutation_owner_xpath(record.mutation)
        component = selected.component_by_qualified_id[record.qualified_id]
        by_owner.setdefault(owner, set()).add(component)
        if record.mutation.entity_type in {"address", "group", "policy"}:
            full_restore_owners.add(owner)
    conflicts: set[str] = set()
    for owner, components in by_owner.items():
        if owner in graph.unresolved_owners:
            conflicts.update(components)
        for dependency in graph.forward_dependencies.get(owner, ()):
            if (
                find_xpath(candidate, dependency) is None
                and dependency not in full_restore_owners
            ):
                conflicts.update(components)
    return conflicts


def _model_entities_by_xpath(model: Any) -> dict[str, tuple[str, Any]]:
    entities: dict[str, tuple[str, Any]] = {}
    for kind, mapping in (
        ("address", model.addresses),
        ("static-group", model.static_groups),
        ("dynamic-group", model.dynamic_groups),
    ):
        for key, entity in mapping.items():
            entities[entity.xpath] = (kind, key)
    return entities


def _final_resolution_conflicts(
    selected: SelectedHistory,
    graph: HistoricalDependencyGraph,
    current: ET.Element,
    patch: PatchSet,
    *,
    preconflicted_components: Iterable[str] = (),
) -> set[str]:
    """Verify historical address/group name resolution after simulated restore.

    Exact-XPath checks alone miss inherited namespace changes.  In particular,
    with ancestor precedence enabled, a newly created parent address can win
    over a restored child address-group of the same name.  The final simulated
    config must resolve every restored namespace owner and every historical
    forward dependency to the same typed XPath as the applied cleanup context.
    """

    conflicts = set(preconflicted_components)
    candidates = {
        selected.component_by_qualified_id[record.qualified_id]
        for record in selected.records
    } - conflicts
    if not candidates:
        return conflicts
    final = copy.deepcopy(current)
    try:
        for mutation in patch.mutations:
            for operation in mutation.forward:
                apply_operation_to_tree(final, operation)
        _legacy_root()
        from panorama_cleanup.panos import (  # type: ignore[import-not-found]
            parse_config,
            resolve_name,
        )

        final_model = parse_config(final)
    except Exception:
        conflicts.update(candidates)
        return conflicts

    final_mappings = {
        "address": final_model.addresses,
        "static-group": final_model.static_groups,
        "dynamic-group": final_model.dynamic_groups,
    }
    historical_entities = {
        session_id: _model_entities_by_xpath(model)
        for session_id, model in graph.models_by_session.items()
    }
    for record in selected.records:
        component = selected.component_by_qualified_id[record.qualified_id]
        if component in conflicts:
            continue
        mutation = record.mutation
        owner = mutation_owner_xpath(mutation)
        location = (
            "shared"
            if owner.startswith("/config/shared/")
            else device_group_from_xpath(owner)
        )
        if location is None:
            conflicts.add(component)
            continue
        expected_paths = set(
            graph.forward_dependencies_by_session.get(
                (record.source_session_id, owner), ()
            )
        )
        if mutation.entity_type == "address":
            expected_paths.add(owner)
        elif mutation.entity_type in {"group", "group-member"}:
            expected_paths.add(owner)

        entities = historical_entities[record.source_session_id]
        for expected_path in expected_paths:
            expected = entities.get(expected_path)
            if expected is None:
                conflicts.add(component)
                break
            expected_kind, expected_key = expected
            resolved_kind, resolved_key, _detail = resolve_name(
                final_model, location, expected_key.name
            )
            resolved = (
                final_mappings.get(resolved_kind, {}).get(resolved_key)
                if resolved_key is not None
                else None
            )
            if (
                resolved_kind != expected_kind
                or resolved is None
                or resolved.xpath != expected_path
            ):
                conflicts.add(component)
                break
    return conflicts


def _guard_unknown_restore_source(
    store: SessionStore,
    reader: PanoramaReadClient,
) -> None:
    for item in store.list_sessions_strict():
        if (
            item.get("operation_kind") != "cleanup"
            or item.get("state") != SessionState.OUTCOME_UNKNOWN.value
        ):
            continue
        session_id = str(item.get("session_id") or "")
        manifest = store.load_manifest(session_id)
        profile = manifest.get("profile") or {}
        if (
            profile.get("host") != reader.profile.host
            or profile.get("username") != reader.profile.username
        ):
            continue
        raise SessionError(
            f"Sesja cleanup {session_id} ma OUTCOME_UNKNOWN dla tej Panoramy i "
            "administratora; najpierw uzgodnij jej rzeczywisty stan. Nie można "
            "udowodnić, że nie dotyka przechodniej zależności restore."
        )


def plan_restore_session(
    store: SessionStore,
    reader: PanoramaReadClient,
    *,
    source_session_id: Optional[str] = None,
    ip: Optional[str] = None,
) -> dict[str, Any]:
    if bool(source_session_id) == bool(ip):
        raise InputError("Restore plan wymaga dokładnie --source-session albo --ip.")
    normalized = str(ipaddress.ip_address(ip)) if ip else None
    _guard_unknown_restore_source(store, reader)
    history = store.iter_applied_cleanup_history(
        reader.profile.host, reader.profile.username
    )
    if not history:
        raise SessionError("Nie znaleziono zastosowanej historii cleanup dla tej Panoramy.")
    if source_session_id and source_session_id not in {
        cleanup.session_id for cleanup in history
    }:
        raise SessionError(
            f"Sesja {source_session_id} nie jest stabilnym zastosowanym cleanupem "
            "dla tej Panoramy i administratora."
        )
    records = _history_records(history)
    dependency_graph = _historical_dependency_graph(store, history)
    try:
        selected = select_history(
            records,
            ip=normalized,
            source_session_id=source_session_id,
            dependency_owner_sets=dependency_graph.owner_sets,
        )
    except ValidationError as exc:
        raise SessionError(str(exc)) from exc
    selected_history = {
        cleanup.session_id: cleanup
        for cleanup in history
        if cleanup.session_id in selected.source_session_ids
    }
    revisions = {
        session_id: selected_history[session_id].revision
        for session_id in selected.source_session_ids
    }
    history_baseline = {
        cleanup.session_id: cleanup.revision for cleanup in history
    }
    history_guard_owners = _history_guard_owner_paths(selected, dependency_graph)
    primary_source = source_session_id or selected.source_session_ids[0]

    running = reader.fetch_config("running")
    candidate = reader.fetch_config("candidate")
    selected_mutations = [record.mutation for record in selected.records]
    direct_locations = {
        "shared"
        if mutation.target_xpath.startswith("/config/shared/")
        else device_group_from_xpath(mutation.target_xpath)
        for mutation in selected_mutations
    }
    direct_locations.discard(None)
    if not direct_locations:
        raise SessionError("Nie można ustalić bezpiecznego zakresu device groups restore.")
    _legacy_root()
    from panorama_cleanup.panos import parse_config  # type: ignore[import-not-found]

    running_model = parse_config(running)
    candidate_model = parse_config(candidate)
    affected_device_groups = tuple(
        sorted(
            set(
                _expanded_device_groups(
                    running_model, (str(item) for item in direct_locations)
                )
            )
            | set(
                _expanded_device_groups(
                    candidate_model, (str(item) for item in direct_locations)
                )
            )
        )
    )
    native = None
    try:
        native = reader.change_summary()
    except ToolboxError:
        pass
    diff = compare_configs(running, candidate, native)

    states = {cleanup.state for cleanup in selected_history.values()}
    committed_only = states <= {SessionState.COMMITTED, SessionState.PUSHED}
    static_conflicts = (
        _historical_scope_conflicts(selected, dependency_graph, running_model)
        | _historical_scope_conflicts(selected, dependency_graph, candidate_model)
        | _forward_dependency_conflicts(selected, dependency_graph, candidate)
    )
    if committed_only:
        static_conflicts.update(
            _forward_dependency_conflicts(selected, dependency_graph, running)
        )
    running_conflicts: set[str] = set(static_conflicts)
    running_evidence = None
    if committed_only:
        running_evidence = build_restore_patchset_history(
            selected,
            running,
            panorama_host=reader.profile.host,
            panorama_username=reader.profile.username,
            affected_device_groups=affected_device_groups,
            preconflicted_components=static_conflicts,
        )
        running_conflicts.update(running_evidence.conflicted_components)
        running_conflicts.update(
            _final_resolution_conflicts(
                selected,
                dependency_graph,
                running,
                running_evidence.patchset,
                preconflicted_components=running_conflicts,
            )
        )
    candidate_preview = build_restore_patchset_history(
        selected,
        candidate,
        panorama_host=reader.profile.host,
        panorama_username=reader.profile.username,
        affected_device_groups=affected_device_groups,
        preconflicted_components=running_conflicts,
    )
    running_conflicts.update(candidate_preview.conflicted_components)
    running_conflicts.update(
        _final_resolution_conflicts(
            selected,
            dependency_graph,
            candidate,
            candidate_preview.patchset,
            preconflicted_components=running_conflicts,
        )
    )
    if committed_only and running_evidence is not None:
        running_decisions = {
            finding.mutation_id: finding.decision
            for finding in running_evidence.findings
        }
        # If running is already at the pre-cleanup value but candidate was
        # changed back to the cleanup result, that candidate edit happened
        # after the committed timeline.  Identical XML cannot prove intent,
        # so fail closed instead of silently undoing another administrator.
        for finding in candidate_preview.findings:
            running_decision = running_decisions.get(finding.mutation_id)
            if (
                running_decision is not None
                and running_decision.value == "ALREADY_RESTORED"
                and finding.decision.value == "RESTORE"
            ):
                running_conflicts.add(finding.component_id)
    result = (
        build_restore_patchset_history(
            selected,
            candidate,
            panorama_host=reader.profile.host,
            panorama_username=reader.profile.username,
            affected_device_groups=affected_device_groups,
            preconflicted_components=running_conflicts,
        )
        if set(candidate_preview.conflicted_components) != running_conflicts
        else candidate_preview
    )
    mode_warning = (
        "Three-way zweryfikowano względem current running, a PatchSet zrebasowano "
        "na bieżący candidate."
        if committed_only
        else "Historia zawiera cleanup candidate-only lub mieszany; three-way i "
        "PatchSet obliczono względem bieżącego candidate."
    )
    result = replace(
        result,
        patchset=replace(
            result.patchset,
            source_session_id=primary_source,
            warnings=(*result.patchset.warnings, mode_warning),
        ),
    )

    # Lock and re-check every source revision before publishing a restore plan.
    with ExitStack() as locks:
        for session_id in sorted(selected.source_session_ids):
            locks.enter_context(store.operation_lock(session_id))
        store.verify_cleanup_revisions(revisions)
        current_history = store.iter_applied_cleanup_history(
            reader.profile.host, reader.profile.username
        )
        if {
            cleanup.session_id: cleanup.revision for cleanup in current_history
        } != history_baseline:
            raise SessionError(
                "Historia cleanup zmieniła się podczas planowania restore; uruchom plan ponownie."
            )
        session_id = store.create(
            result.patchset,
            reader.profile,
            planning_running=running,
            planning_candidate=candidate,
            diff_summary=diff,
        )
        store.update(
            session_id,
            lambda manifest: manifest.update(
                {
                    "restore_history_guard": {
                        "baseline_revisions": {
                            key: list(value)
                            for key, value in sorted(history_baseline.items())
                        },
                        "selected_source_revisions": {
                            key: list(value)
                            for key, value in sorted(revisions.items())
                        },
                        "selected_causes": sorted(result.patchset.targets),
                        "guard_owner_xpaths": sorted(history_guard_owners),
                    }
                }
            ),
        )

    record_by_id = {record.qualified_id: record for record in selected.records}
    findings = []
    for finding in result.findings:
        source_record = record_by_id[finding.mutation_id]
        findings.append(
            {
                **dataclasses.asdict(finding),
                "decision": finding.decision.value,
                "source_session_id": source_record.source_session_id,
                "source_mutation_id": source_record.mutation.mutation_id,
                "entity_type": source_record.mutation.entity_type,
                "target_xpath": source_record.mutation.target_xpath,
            }
        )
    store.add_conflicts(
        session_id,
        [finding for finding in findings if finding["decision"] == "CONFLICT"],
    )
    store.write_artifact(
        session_id,
        "restore_operations.json",
        json.dumps(
            {
                "source_session_id": primary_source,
                "source_session_ids": list(selected.source_session_ids),
                "findings": findings,
                "patchset": result.patchset.to_dict(),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        kind="restore-report",
    )
    conflicted_components = set(result.conflicted_components)
    manual_records = list(reversed([
        record
        for record in selected.records
        if selected.component_by_qualified_id[record.qualified_id]
        in conflicted_components
    ]))
    if manual_records:
        store.write_artifact(
            session_id,
            "manual_conflicts.json",
            json.dumps(
                {
                    "warning": "Nie stosować automatycznie; wymaga ręcznego review XML API/CLI.",
                    "mutations": [
                        {
                            "qualified_id": record.qualified_id,
                            "source_session_id": record.source_session_id,
                            "mutation": record.mutation.to_dict(),
                        }
                        for record in manual_records
                    ],
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            kind="manual-conflicts",
        )
        bundle = ET.Element(
            "panos-toolbox-manual-restore",
            {
                "source-sessions": ",".join(selected.source_session_ids),
                "warning": "manual-review-required",
            },
        )
        for record in manual_records:
            mutation = record.mutation
            mutation_node = ET.SubElement(
                bundle,
                "mutation",
                {
                    "id": record.qualified_id,
                    "component": selected.component_by_qualified_id[
                        record.qualified_id
                    ],
                    "entity": mutation.entity_key,
                },
            )
            for operation in mutation.inverse:
                attributes = {
                    "action": operation.action.value,
                    "xpath": operation.xpath,
                }
                if operation.where:
                    attributes["where"] = operation.where
                if operation.destination:
                    attributes["dst"] = operation.destination
                operation_node = ET.SubElement(
                    mutation_node, "xml-api-operation", attributes
                )
                if operation.element is not None:
                    ET.SubElement(
                        operation_node, "element", {"encoding": "escaped-xml"}
                    ).text = operation.element
        store.write_artifact(
            session_id,
            "manual_conflicts.xml",
            ET.tostring(bundle, encoding="unicode") + "\n",
            kind="manual-conflicts-xml",
        )
    report_lines = [
        f"Restore session: {session_id}",
        "Źródłowe sesje cleanup: " + ", ".join(selected.source_session_ids),
        f"Bezpieczne mutacje: {len(result.patchset.mutations)}",
        f"Komponenty konfliktowe: {len(result.conflicted_components)}",
        f"Tryb three-way: {'running + rebase candidate' if committed_only else 'candidate'}",
        "",
    ]
    for finding in findings:
        report_lines.append(
            f"{finding['decision']}: {finding['entity_key']} "
            f"(component={finding['component_id']}, mutation={finding['mutation_id']})"
        )
    store.write_artifact(
        session_id,
        "raport_restore.txt",
        "\n".join(report_lines) + "\n",
        kind="restore-report-text",
    )
    if not result.patchset.mutations:
        if result.conflicted_components:
            store.transition(session_id, SessionState.CONFLICT)
        else:
            store.transition(session_id, SessionState.RESTORED)
    return {
        "session_id": session_id,
        "source_session_id": primary_source,
        "source_session_ids": list(selected.source_session_ids),
        "state": store.load_manifest(session_id)["state"],
        "mutation_count": len(result.patchset.mutations),
        "conflicted_components": list(result.conflicted_components),
        "findings": findings,
    }


def make_writer(
    reader: PanoramaReadClient,
    requested_stage: ApiStage,
    *,
    enable_api_write: bool,
) -> PanoramaWriteClient:
    lease = issue_write_lease(
        reader.profile,
        requested_stage,
        enable_api_write=enable_api_write,
        ttl_seconds=3600,
    )
    return reader.enable_write(lease)
