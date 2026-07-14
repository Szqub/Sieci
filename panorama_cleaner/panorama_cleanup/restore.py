"""Emergency, read-only restore bundle generation from cleanup run backups."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import tempfile
import unicodedata
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .models import ConfigModel, InputError, OutputError, RuleKey, ScopedName, UnsafePlanError
from .panos import (
    ADDRESS_MEMBER_CONTAINERS,
    VOLATILE_ATTRIBUTES,
    _xpath_literal,
    is_supported_address_literal,
    resolution_chain,
)
from .render import _entry_to_set_commands, quote_cli


@dataclass(frozen=True, order=True)
class RestoreEntity:
    entity_type: str
    location: str
    name: str
    rulebase: str = ""
    policy_type: str = ""

    @property
    def text(self) -> str:
        if self.entity_type == "policy":
            return (
                f"{self.location}/{self.rulebase}/{self.policy_type}/{self.name}"
            )
        return f"{self.location}/{self.name}"


@dataclass(frozen=True)
class BackupVersion:
    entity: RestoreEntity
    manifest_path: str
    run_dir: str
    started_utc: str
    record: Mapping[str, Any]
    xml: str
    device_group_parents: Mapping[str, Optional[str]]
    ancestor_objects_take_precedence: bool
    historical_scope_context_available: bool


@dataclass(frozen=True)
class CleanupRun:
    manifest_path: str
    run_dir: str
    panorama_host: str
    device_entry_name: str
    started_utc: str
    sort_timestamp: float
    commands: Tuple[Mapping[str, Any], ...]
    backups: Tuple[BackupVersion, ...]


@dataclass(frozen=True)
class EmergencyRestorePlan:
    target_ips: Tuple[str, ...]
    manifests: Tuple[str, ...]
    seeds: Tuple[RestoreEntity, ...]
    selected: Tuple[RestoreEntity, ...]
    reasons: Mapping[RestoreEntity, Tuple[str, ...]]
    current_states: Mapping[RestoreEntity, str]
    backup_versions: Mapping[RestoreEntity, BackupVersion]
    cli_commands: Tuple[str, ...]
    move_commands: Tuple[str, ...]
    partial_load_commands: Tuple[str, ...]
    bundle_xml: str
    warnings: Tuple[str, ...]
    seed_evidence: Tuple[str, ...]

    @property
    def review_required(self) -> bool:
        return bool(self.warnings)


def discover_cleanup_manifests(
    supplied: Sequence[Path], runs_dir: Path
) -> Tuple[Path, ...]:
    if supplied:
        candidates = [path / "manifest.json" if path.is_dir() else path for path in supplied]
    else:
        candidates = sorted(runs_dir.glob("run_*/manifest.json"))
    unique: List[Path] = []
    seen: Set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise InputError(f"Nie można odnaleźć manifestu cleanup: {candidate}") from exc
        identity = os.path.normcase(str(resolved))
        if identity not in seen:
            seen.add(identity)
            unique.append(resolved)
    if not unique:
        raise InputError(
            f"Nie znaleziono manifestów run_*/manifest.json w {runs_dir}."
        )
    return tuple(unique)


def load_cleanup_runs(manifest_paths: Sequence[Path]) -> Tuple[CleanupRun, ...]:
    runs: List[CleanupRun] = []
    for manifest_path in manifest_paths:
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise InputError(f"Nie można odczytać manifestu: {manifest_path}") from exc
        backups_payload = payload.get("backups")
        commands_payload = payload.get("commands")
        if not isinstance(backups_payload, list) or not isinstance(commands_payload, list):
            raise InputError(
                f"Manifest nie zawiera list backups/commands: {manifest_path}"
            )
        run_dir = manifest_path.parent.resolve()
        safety = payload.get("safety")
        if (
            not isinstance(safety, dict)
            or safety.get("commands_file_expected_on_success") is not True
        ):
            raise InputError(
                f"Run nie opublikował stosowalnego commands.txt: {manifest_path}"
            )
        panorama_host = payload.get("panorama_host")
        device_entry_name = payload.get("device_entry_name")
        if not isinstance(panorama_host, str) or not panorama_host:
            raise InputError(f"Manifest nie ma panorama_host: {manifest_path}")
        if not isinstance(device_entry_name, str) or not device_entry_name:
            raise InputError(f"Manifest nie ma device_entry_name: {manifest_path}")
        (
            device_group_parents,
            ancestor_objects_take_precedence,
            historical_scope_context_available,
        ) = _manifest_scope_context(payload, manifest_path)
        if historical_scope_context_available:
            context_device = payload["configuration_context"].get(
                "device_entry_name"
            )
            if context_device != device_entry_name:
                raise InputError(
                    f"Sprzeczny device_entry_name w {manifest_path}"
                )
        started_text = str(payload.get("started_utc") or "")
        try:
            started = datetime.fromisoformat(started_text.replace("Z", "+00:00"))
            if started.tzinfo is None:
                raise ValueError("started_utc nie ma strefy czasowej")
            sort_timestamp = started.timestamp()
        except (ValueError, OverflowError, OSError) as exc:
            raise InputError(
                f"Niepoprawny started_utc w {manifest_path}: {started_text!r}"
            ) from exc

        versions: List[BackupVersion] = []
        seen_entities: Set[RestoreEntity] = set()
        seen_backup_files: Set[str] = set()
        for record in backups_payload:
            if not isinstance(record, dict):
                raise InputError(f"Niepoprawny rekord backupu: {manifest_path}")
            entity = _entity_from_backup(record, manifest_path)
            if entity in seen_entities:
                raise InputError(
                    f"Zduplikowany backup encji {entity.text} w {manifest_path}"
                )
            seen_entities.add(entity)
            relative_file = record.get("file")
            expected_hash = record.get("sha256")
            if not isinstance(relative_file, str) or not isinstance(expected_hash, str):
                raise InputError(
                    f"Backup {entity.text} nie ma file/sha256: {manifest_path}"
                )
            if relative_file in seen_backup_files:
                raise InputError(
                    f"Zduplikowana ścieżka backupu {relative_file!r}: {manifest_path}"
                )
            seen_backup_files.add(relative_file)
            if len(expected_hash) != 64 or any(
                character not in "0123456789abcdefABCDEF"
                for character in expected_hash
            ):
                raise InputError(
                    f"Niepoprawny SHA256 backupu {entity.text}: {manifest_path}"
                )
            xpath = record.get("xpath")
            if not isinstance(xpath, str) or not xpath.startswith("/config/"):
                raise InputError(
                    f"Niepoprawny XPath backupu {entity.text}: {manifest_path}"
                )
            _validate_backup_identity(record, entity, manifest_path)
            backup_path = (run_dir / relative_file).resolve()
            try:
                backup_path.relative_to(run_dir)
            except ValueError as exc:
                raise InputError(
                    f"Ścieżka backupu wychodzi poza katalog runu: {relative_file}"
                ) from exc
            try:
                raw = backup_path.read_bytes()
            except OSError as exc:
                raise InputError(f"Brak backupu XML: {backup_path}") from exc
            actual_hash = hashlib.sha256(raw).hexdigest()
            if actual_hash != expected_hash.casefold():
                raise InputError(
                    f"Niezgodny SHA256 backupu {entity.text}: {backup_path}"
                )
            try:
                xml = raw.decode("utf-8")
                entry = ET.fromstring(xml)
            except (UnicodeError, ET.ParseError) as exc:
                raise InputError(f"Niepoprawny backup XML: {backup_path}") from exc
            if entry.tag != "entry" or entry.get("name") != entity.name:
                raise InputError(
                    f"Backup XML nie odpowiada encji {entity.text}: {backup_path}"
                )
            versions.append(
                BackupVersion(
                    entity=entity,
                    manifest_path=str(manifest_path),
                    run_dir=str(run_dir),
                    started_utc=started_text,
                    record=dict(record),
                    xml=xml,
                    device_group_parents=device_group_parents,
                    ancestor_objects_take_precedence=(
                        ancestor_objects_take_precedence
                    ),
                    historical_scope_context_available=(
                        historical_scope_context_available
                    ),
                )
            )
        commands = tuple(
            dict(record) for record in commands_payload if isinstance(record, dict)
        )
        if len(commands) != len(commands_payload):
            raise InputError(f"Niepoprawny rekord commands: {manifest_path}")
        _validate_commands(run_dir, manifest_path, commands, versions)
        runs.append(
            CleanupRun(
                manifest_path=str(manifest_path),
                run_dir=str(run_dir),
                panorama_host=panorama_host,
                device_entry_name=device_entry_name,
                started_utc=started_text,
                sort_timestamp=sort_timestamp,
                commands=commands,
                backups=tuple(versions),
            )
        )
    return tuple(sorted(runs, key=lambda item: (item.sort_timestamp, item.manifest_path)))


def _manifest_scope_context(
    payload: Mapping[str, Any], manifest_path: Path
) -> Tuple[Mapping[str, Optional[str]], bool, bool]:
    context = payload.get("configuration_context")
    if context is None:
        return {}, False, False
    if not isinstance(context, dict):
        raise InputError(
            f"Niepoprawne configuration_context w {manifest_path}"
        )
    parents_payload = context.get("device_group_parents")
    precedence = context.get("ancestor_objects_take_precedence")
    if not isinstance(parents_payload, dict) or not isinstance(precedence, bool):
        raise InputError(
            f"Niepełne configuration_context w {manifest_path}"
        )
    parents: Dict[str, Optional[str]] = {}
    for child, parent in parents_payload.items():
        if not isinstance(child, str) or not child or child == "shared":
            raise InputError(
                f"Niepoprawna nazwa device group w {manifest_path}: {child!r}"
            )
        if parent is not None and (not isinstance(parent, str) or not parent):
            raise InputError(
                f"Niepoprawny parent-dg dla {child!r} w {manifest_path}"
            )
        parents[child] = parent
    for child, parent in parents.items():
        if parent is not None and parent not in parents:
            raise InputError(
                f"Nieznany parent-dg {parent!r} dla {child!r} w {manifest_path}"
            )
        seen: Set[str] = set()
        current: Optional[str] = child
        while current is not None:
            if current in seen:
                raise InputError(
                    f"Cykl device group obejmujący {child!r} w {manifest_path}"
                )
            seen.add(current)
            current = parents[current]
    return parents, precedence, True


def _validate_backup_identity(
    record: Mapping[str, Any], entity: RestoreEntity, manifest_path: Path
) -> None:
    if entity.entity_type == "address":
        expected = f"address|{entity.location}|{entity.name}"
    elif entity.entity_type == "static-group":
        expected = f"group|{entity.location}|{entity.name}"
    else:
        expected = (
            f"policy|{entity.location}|{entity.rulebase}|"
            f"{entity.policy_type}|{entity.name}"
        )
    if record.get("identity") != expected:
        raise InputError(
            f"Niezgodna identity backupu {entity.text} w {manifest_path}"
        )
    if entity.entity_type != "policy":
        return
    order_index = record.get("order_index")
    if not isinstance(order_index, int) or isinstance(order_index, bool) or order_index < 0:
        raise InputError(
            f"Niepoprawny order_index polityki {entity.text}: {manifest_path}"
        )
    for key in ("previous_rule", "next_rule"):
        value = record.get(key)
        if value is not None and (not isinstance(value, str) or not value):
            raise InputError(
                f"Niepoprawny {key} polityki {entity.text}: {manifest_path}"
            )
    rule_order = record.get("rule_order")
    if rule_order is None:
        return
    if (
        not isinstance(rule_order, list)
        or not rule_order
        or any(not isinstance(name, str) or not name for name in rule_order)
        or len(set(rule_order)) != len(rule_order)
        or entity.name not in rule_order
        or order_index >= len(rule_order)
        or rule_order[order_index] != entity.name
    ):
        raise InputError(
            f"Niepoprawny rule_order polityki {entity.text}: {manifest_path}"
        )
    expected_previous = rule_order[order_index - 1] if order_index > 0 else None
    expected_next = (
        rule_order[order_index + 1]
        if order_index + 1 < len(rule_order)
        else None
    )
    if (
        record.get("previous_rule") != expected_previous
        or record.get("next_rule") != expected_next
    ):
        raise InputError(
            f"previous_rule/next_rule nie odpowiada rule_order dla "
            f"{entity.text}: {manifest_path}"
        )


def _validate_commands(
    run_dir: Path,
    manifest_path: Path,
    commands: Sequence[Mapping[str, Any]],
    versions: Sequence[BackupVersion],
) -> None:
    if not commands:
        raise InputError(f"Run nie zawiera żadnej komendy: {manifest_path}")
    expected_entities = {
        (
            "group"
            if version.entity.entity_type == "static-group"
            else version.entity.entity_type,
            version.entity.text,
        )
        for version in versions
    }
    command_entities: Set[Tuple[str, str]] = set()
    command_ids: Set[str] = set()
    command_lines: List[str] = []
    for record in commands:
        command_id = record.get("command_id")
        category = record.get("category")
        command = record.get("command")
        causes = record.get("causes")
        entity_type = record.get("entity_type")
        entity_key = record.get("entity_key")
        if not isinstance(command_id, str) or not command_id:
            raise InputError(f"Komenda bez command_id: {manifest_path}")
        if command_id in command_ids:
            raise InputError(f"Zduplikowany command_id {command_id}: {manifest_path}")
        command_ids.add(command_id)
        if not isinstance(category, str) or not category:
            raise InputError(f"Komenda {command_id} bez category: {manifest_path}")
        if (
            not isinstance(command, str)
            or not command.startswith("delete ")
            or any(
                unicodedata.category(character) in {"Cc", "Zl", "Zp"}
                for character in command
            )
        ):
            raise InputError(f"Niepoprawna komenda {command_id}: {manifest_path}")
        if entity_type not in {"address", "group", "policy"}:
            raise InputError(
                f"Niepoprawny entity_type komendy {command_id}: {manifest_path}"
            )
        if not isinstance(entity_key, str) or not entity_key:
            raise InputError(f"Komenda {command_id} bez entity_key: {manifest_path}")
        identity = (entity_type, entity_key)
        if identity not in expected_entities:
            raise InputError(
                f"Komenda {command_id} nie ma odpowiadającego backupu: "
                f"{manifest_path}"
            )
        command_entities.add(identity)
        if not isinstance(causes, list) or not causes:
            raise InputError(f"Komenda {command_id} nie ma causes: {manifest_path}")
        for cause in causes:
            if not isinstance(cause, str):
                raise InputError(
                    f"Niepoprawne causes komendy {command_id}: {manifest_path}"
                )
            try:
                canonical = str(ipaddress.ip_address(cause))
            except ValueError as exc:
                raise InputError(
                    f"Niepoprawny IP causes komendy {command_id}: {manifest_path}"
                ) from exc
            if canonical != cause:
                raise InputError(
                    f"Niekanoniczny IP causes komendy {command_id}: {manifest_path}"
                )
        command_lines.append(command)
    if command_entities != expected_entities:
        missing = sorted(expected_entities - command_entities)
        raise InputError(
            f"Backupy bez odpowiadających komend w {manifest_path}: {missing}"
        )

    commands_path = run_dir / "commands.txt"
    try:
        published_lines = [
            line for line in commands_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError) as exc:
        raise InputError(f"Brak opublikowanego commands.txt: {run_dir}") from exc
    if published_lines != command_lines:
        raise InputError(
            f"commands.txt nie odpowiada rekordom manifestu: {manifest_path}"
        )


def build_emergency_restore(
    model: ConfigModel,
    runs: Sequence[CleanupRun],
    target_ips: Iterable[str],
    *,
    bundle_filename: str,
) -> EmergencyRestorePlan:
    targets = tuple(sorted(set(target_ips)))
    if not targets:
        raise InputError("Brak IP do awaryjnego restore.")
    foreign_device_entries = sorted(
        {
            run.device_entry_name
            for run in runs
            if run.device_entry_name != model.device_entry_name
        }
    )
    if foreign_device_entries:
        raise UnsafePlanError(
            "Manifesty pochodzą z innego devices/entry niż bieżący running: "
            + ", ".join(foreign_device_entries)
        )
    versions_by_entity: Dict[RestoreEntity, List[BackupVersion]] = defaultdict(list)
    for run in runs:
        for version in run.backups:
            versions_by_entity[version.entity].append(version)
    earliest = {
        entity: versions[0] for entity, versions in versions_by_entity.items()
    }

    seeds: Set[RestoreEntity] = set()
    seed_evidence: List[str] = []
    for run in runs:
        command_entities = _command_entity_map(run)
        for command in run.commands:
            causes = command.get("causes")
            if not isinstance(causes, list) or not set(targets).intersection(
                str(item) for item in causes
            ):
                continue
            entity = command_entities.get(_command_identity(command))
            if entity is None:
                raise UnsafePlanError(
                    "Nie można połączyć komendy z autorytatywnym backupem: "
                    f"{command.get('command_id', '?')} w {run.manifest_path}"
                )
            seeds.add(entity)
            seed_evidence.append(
                f"{command.get('command_id', '?')} | {entity.entity_type} "
                f"{entity.text} | causes={','.join(str(item) for item in causes)} | "
                f"komenda={command.get('command', '?')} | {run.manifest_path}"
            )

    warnings: List[str] = []
    adjacency: Dict[RestoreEntity, Set[RestoreEntity]] = {
        entity: set() for entity in earliest
    }
    group_dependencies: Dict[RestoreEntity, Set[RestoreEntity]] = {
        entity: set()
        for entity in earliest
        if entity.entity_type == "static-group"
    }
    edge_details: Dict[Tuple[RestoreEntity, RestoreEntity], str] = {}
    resolution_issues: Dict[RestoreEntity, Set[str]] = defaultdict(set)
    for owner, version in sorted(earliest.items()):
        if owner.entity_type == "address":
            continue
        for name in _backup_address_references(owner, version.xml):
            dependency, detail = _resolve_historical_reference(
                model,
                earliest,
                owner.location,
                name,
                historical_version=version,
            )
            if detail:
                resolution_issues[owner].add(detail)
            if dependency is None or dependency not in earliest:
                continue
            adjacency[owner].add(dependency)
            adjacency[dependency].add(owner)
            if (
                owner.entity_type == "static-group"
                and dependency.entity_type == "static-group"
            ):
                group_dependencies[owner].add(dependency)
            edge_details[(owner, dependency)] = name
            edge_details[(dependency, owner)] = name

    selected: Set[RestoreEntity] = set(seeds)
    reasons: Dict[RestoreEntity, Set[str]] = defaultdict(set)
    queue: deque[RestoreEntity] = deque(sorted(seeds))
    for entity in seeds:
        reasons[entity].add("bezpośrednia zmiana cleanup dla wskazanego IP")
    while queue:
        entity = queue.popleft()
        for neighbor in sorted(adjacency.get(entity, set())):
            reference = edge_details.get((entity, neighbor), "?")
            reasons[neighbor].add(
                f"domknięcie zależności z {entity.entity_type} {entity.text} "
                f"przez nazwę {reference!r}"
            )
            if neighbor not in selected:
                selected.add(neighbor)
                queue.append(neighbor)

    incomplete_dependencies = [
        f"{owner.text}: {detail}"
        for owner in sorted(selected)
        for detail in sorted(resolution_issues.get(owner, set()))
    ]
    if incomplete_dependencies:
        raise UnsafePlanError(
            "Nie można zbudować kompletnego restore: "
            + "; ".join(incomplete_dependencies)
        )
    historical_namespace: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    for entity in selected:
        if entity.entity_type in {"address", "static-group"}:
            historical_namespace[(entity.location, entity.name)].add(
                entity.entity_type
            )
    historical_collisions = [
        f"{location}/{name}: {','.join(sorted(types))}"
        for (location, name), types in sorted(historical_namespace.items())
        if len(types) > 1
    ]
    if historical_collisions:
        raise UnsafePlanError(
            "Historyczna zmiana typu w namespace uniemożliwia automatyczny "
            "restore: " + "; ".join(historical_collisions)
        )
    legacy_context_manifests = sorted(
        {
            earliest[entity].manifest_path
            for entity in selected
            if not earliest[entity].historical_scope_context_available
        }
    )
    if legacy_context_manifests:
        warnings.append(
            "HISTORICAL_SCOPE_CONTEXT_MISSING: starsze manifesty nie zapisały "
            "hierarchii device group; rozwiązywanie nazw użyło bieżącej "
            "hierarchii running: "
            + ", ".join(legacy_context_manifests)
        )
    _validate_selected_scope_context(model, selected, earliest)
    _validate_cleanup_timeline(model, runs, selected, versions_by_entity)

    current_states = {
        entity: _current_state(model, entity, earliest[entity].xml)
        for entity in sorted(selected)
    }
    namespace_collisions = [
        f"{entity.text}: {state}"
        for entity, state in sorted(current_states.items())
        if state.startswith("KOLIZJA_")
    ]
    if namespace_collisions:
        raise UnsafePlanError(
            "Restore koliduje z bieżącym namespace Panoramy: "
            + "; ".join(namespace_collisions)
        )
    for entity, state in sorted(current_states.items()):
        if state == "ISTNIEJE_ALE_ROZNI_SIE_OD_BACKUPU":
            warnings.append(
                f"EXISTING_ENTITY_WILL_BE_REPLACED: {entity.entity_type} "
                f"{entity.text}; XML restore odtworzy całą encję z backupu."
            )
    group_order = _restore_group_order(selected, group_dependencies)
    policy_order = sorted(
        (entity for entity in selected if entity.entity_type == "policy"),
        key=lambda entity: (
            entity.location,
            entity.rulebase,
            entity.policy_type,
            int(earliest[entity].record.get("order_index", 0)),
            entity.name,
        ),
    )
    entity_order = (
        sorted(entity for entity in selected if entity.entity_type == "address")
        + group_order
        + policy_order
    )

    cli_warnings: List[str] = []
    cli_commands: List[str] = []
    for entity in entity_order:
        if current_states[entity] == "ZGODNY_Z_BACKUPEM":
            continue
        version = earliest[entity]
        entry = ET.fromstring(version.xml)
        extra_attributes = sorted(set(entry.attrib) - {"name"})
        if extra_attributes:
            cli_warnings.append(
                f"CLI_ATTRIBUTE_NOT_RESTORED: {entity.text}: "
                + ", ".join(extra_attributes)
                + "; użyj restore_bundle.xml dla odtworzenia atrybutów."
            )
        cli_commands.extend(
            _entry_to_set_commands(
                _cli_path(entity),
                version.xml,
                entity_label=f"{entity.entity_type} {entity.text}",
                rollback_warnings=cli_warnings,
            )
        )

    policies_requiring_position_restore = [
        entity
        for entity in policy_order
        if _entity_has_command_category(runs, entity, "rule-delete")
    ]
    move_commands, move_warnings = _policy_move_commands(
        model, policies_requiring_position_restore, earliest
    )
    cli_commands.extend(move_commands)
    warnings.extend(cli_warnings)
    warnings.extend(move_warnings)
    cli_commands = _deduplicate(cli_commands)

    bundle_xml = _build_bundle_xml(model.device_entry_name, entity_order, earliest)
    partial_load_commands = _partial_load_commands(
        entity_order,
        current_states,
        bundle_filename,
        move_commands,
        model.device_entry_name,
    )
    if not seeds:
        warnings.append(
            "NO_ACTION_FOR_IP: żaden wskazany IP nie występuje w causes komend "
            "podanych runów cleanup."
        )
    return EmergencyRestorePlan(
        target_ips=targets,
        manifests=tuple(run.manifest_path for run in runs),
        seeds=tuple(sorted(seeds)),
        selected=tuple(entity_order),
        reasons={
            entity: tuple(sorted(values)) for entity, values in sorted(reasons.items())
        },
        current_states=current_states,
        backup_versions={entity: earliest[entity] for entity in entity_order},
        cli_commands=tuple(cli_commands),
        move_commands=tuple(move_commands),
        partial_load_commands=tuple(partial_load_commands),
        bundle_xml=bundle_xml,
        warnings=tuple(sorted(set(warnings))),
        seed_evidence=tuple(sorted(seed_evidence)),
    )


def create_restore_directory(
    base: Path, target_ips: Sequence[str], now: Optional[datetime] = None
) -> Path:
    timestamp = (now or datetime.now().astimezone()).astimezone()
    label = "_".join(ip.replace(":", "-").replace(".", "-") for ip in target_ips[:3])
    if len(target_ips) > 3:
        digest = hashlib.sha256("\n".join(target_ips).encode("utf-8")).hexdigest()[:8]
        label += f"_plus_{len(target_ips) - 3}_{digest}"
    name = f"restore_{label}_{timestamp.strftime('%d%m%y_%H_%M_%S')}"
    candidate = base / name
    suffix = 1
    while candidate.exists():
        candidate = base / f"{name}_{suffix:02d}"
        suffix += 1
    try:
        candidate.mkdir(parents=True, exist_ok=False)
        try:
            candidate.chmod(0o700)
        except OSError:
            pass
    except OSError as exc:
        raise OutputError(f"Nie można utworzyć katalogu restore: {candidate}") from exc
    return candidate


def write_restore_artifacts(
    restore_dir: Path,
    plan: EmergencyRestorePlan,
    *,
    bundle_filename: str,
    metadata: Mapping[str, Any],
) -> None:
    command_path = restore_dir / "restore_commands.txt"
    partial_path = restore_dir / "restore_partial_load_commands.txt"
    ready_path = restore_dir / "RESTORE_READY"
    try:
        _write_text(restore_dir / bundle_filename, plan.bundle_xml)
        _write_text(
            restore_dir / "restore_report.txt",
            _restore_report(plan),
        )
        _write_text(
            restore_dir / "RESTORE_INSTRUCTIONS.txt",
            _restore_instructions(plan, bundle_filename),
        )
        _write_text(
            restore_dir / "restore_warnings.txt",
            _warning_report(plan),
        )
        payload = dict(metadata)
        command_text = "\n".join(plan.cli_commands)
        command_payload = (
            command_text + "\n"
        ) if command_text else "# brak komend\n"
        partial_text = "\n".join(plan.partial_load_commands)
        partial_payload = (
            partial_text + "\n"
        ) if partial_text else "# brak komend\n"
        payload.update(
            {
                "target_ips": list(plan.target_ips),
                "source_manifests": list(plan.manifests),
                "selected_entities": [asdict(entity) for entity in plan.selected],
                "seed_evidence": list(plan.seed_evidence),
                "selection_reasons": {
                    entity.text: list(plan.reasons.get(entity, ()))
                    for entity in plan.selected
                },
                "backup_sources": {
                    entity.text: {
                        "manifest": plan.backup_versions[entity].manifest_path,
                        "file": plan.backup_versions[entity].record.get("file"),
                        "sha256": plan.backup_versions[entity].record.get("sha256"),
                        "started_utc": plan.backup_versions[entity].started_utc,
                    }
                    for entity in plan.selected
                },
                "current_states": {
                    entity.text: state
                    for entity, state in sorted(plan.current_states.items())
                },
                "warnings": list(plan.warnings),
                "cli_command_count": len(plan.cli_commands),
                "partial_load_command_count": len(plan.partial_load_commands),
                "command_file_sha256": hashlib.sha256(
                    command_payload.encode("utf-8")
                ).hexdigest(),
                "partial_load_file_sha256": hashlib.sha256(
                    partial_payload.encode("utf-8")
                ).hexdigest(),
                "changes_executed": False,
                "commit_command_generated": False,
                "safety": {
                    "commands_files_expected_on_success": True,
                    "publication_proof": (
                        "RESTORE_READY exists and was written after both "
                        "command files"
                    ),
                    "candidate_diff_administrator_confirmed": metadata.get(
                        "candidate_diff_administrator_confirmed", False
                    ),
                },
            }
        )
        _write_json(restore_dir / "restore_manifest.json", payload)
        # Applicable command files are deliberately the final payload writes.
        _write_text(command_path, command_payload)
        _write_text(partial_path, partial_payload)
        ready_payload = (
            "RESTORE PACKAGE READY\n"
            f"restore_commands.txt sha256={payload['command_file_sha256']}\n"
            "restore_partial_load_commands.txt sha256="
            f"{payload['partial_load_file_sha256']}\n"
        )
        _write_text(ready_path, ready_payload)
    except (OutputError, OSError) as exc:
        for path in (ready_path, command_path, partial_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if isinstance(exc, OutputError):
            raise
        raise OutputError(f"Błąd zapisu artefaktów restore w {restore_dir}") from exc


def _entity_from_backup(record: Mapping[str, Any], manifest: Path) -> RestoreEntity:
    entity_type = record.get("entity_type")
    location = record.get("location")
    name = record.get("name")
    if entity_type not in {"address", "static-group", "policy"}:
        raise InputError(f"Nieobsługiwany entity_type w {manifest}: {entity_type!r}")
    if not isinstance(location, str) or not location or not isinstance(name, str) or not name:
        raise InputError(f"Backup bez location/name w {manifest}")
    if entity_type == "policy":
        rulebase = record.get("rulebase")
        policy_type = record.get("policy_type")
        if rulebase not in {"pre-rulebase", "post-rulebase"} or policy_type not in {
            "security", "nat", "application-override"
        }:
            raise InputError(f"Niepoprawny backup policy w {manifest}: {record}")
        return RestoreEntity("policy", location, name, rulebase, policy_type)
    return RestoreEntity(entity_type, location, name)


def _command_identity(command: Mapping[str, Any]) -> Tuple[str, str]:
    return str(command.get("entity_type") or ""), str(command.get("entity_key") or "")


def _command_entity_map(run: CleanupRun) -> Dict[Tuple[str, str], RestoreEntity]:
    result: Dict[Tuple[str, str], RestoreEntity] = {}
    for version in run.backups:
        command_type = (
            "group"
            if version.entity.entity_type == "static-group"
            else version.entity.entity_type
        )
        identity = (command_type, version.entity.text)
        if identity in result and result[identity] != version.entity:
            raise UnsafePlanError(f"Niejednoznaczna encja w {run.manifest_path}: {identity}")
        result[identity] = version.entity
    return result


def _backup_address_references(entity: RestoreEntity, xml: str) -> Tuple[str, ...]:
    entry = ET.fromstring(xml)
    if entity.entity_type == "static-group":
        return tuple(
            member.text.strip()
            for member in entry.findall("./static/member")
            if member.text and member.text.strip()
        )
    if entity.entity_type != "policy":
        return ()
    values: List[str] = []
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
    return tuple(dict.fromkeys(values))


def _resolve_historical_reference(
    model: ConfigModel,
    backups: Mapping[RestoreEntity, BackupVersion],
    owner_location: str,
    name: str,
    *,
    historical_version: BackupVersion,
) -> Tuple[Optional[RestoreEntity], str]:
    if name == "any":
        return None, ""
    if historical_version.historical_scope_context_available:
        scopes = _historical_resolution_chain(historical_version, owner_location)
    else:
        scopes = resolution_chain(model, owner_location)
    for scope in scopes:
        address_entity = RestoreEntity("address", scope, name)
        group_entity = RestoreEntity("static-group", scope, name)
        candidates: List[Tuple[str, Optional[RestoreEntity]]] = []
        if ScopedName(scope, name) in model.addresses or address_entity in backups:
            candidates.append(("address", address_entity))
        static_exists = (
            ScopedName(scope, name) in model.static_groups
            or group_entity in backups
        )
        dynamic_exists = ScopedName(scope, name) in model.dynamic_groups
        other_definition = model.other_address_definitions.get(
            ScopedName(scope, name)
        )
        if static_exists:
            candidates.append(("static-group", group_entity))
        elif dynamic_exists:
            candidates.append(("dynamic-group", None))
        elif other_definition is not None:
            candidates.append((other_definition, None))
        if len(candidates) > 1:
            kinds = ",".join(kind for kind, _ in candidates)
            return None, (
                f"AMBIGUOUS_HISTORICAL_REFERENCE {name!r} w scope {scope}: "
                f"{kinds}"
            )
        if candidates:
            return candidates[0][1], ""
    # PAN-OS permits IP-looking object names. A token becomes a literal only
    # after every effective object scope has been checked.
    if is_supported_address_literal(name):
        return None, ""
    return None, f"UNRESOLVED_HISTORICAL_REFERENCE {name!r}"


def _historical_resolution_chain(
    version: BackupVersion, owner_location: str
) -> Tuple[str, ...]:
    if owner_location == "shared":
        return ("shared",)
    parents = version.device_group_parents
    if owner_location not in parents:
        raise UnsafePlanError(
            f"Manifest {version.manifest_path} nie zawiera scope "
            f"{owner_location!r} encji {version.entity.text}."
        )
    chain: List[str] = []
    seen: Set[str] = set()
    current: Optional[str] = owner_location
    while current is not None:
        if current in seen:
            raise UnsafePlanError(
                f"Cykl historycznej hierarchii scope dla {version.entity.text}."
            )
        seen.add(current)
        chain.append(current)
        current = parents[current]
    chain.append("shared")
    if version.ancestor_objects_take_precedence:
        chain.reverse()
    return tuple(chain)


def _validate_selected_scope_context(
    model: ConfigModel,
    selected: Set[RestoreEntity],
    backups: Mapping[RestoreEntity, BackupVersion],
) -> None:
    for entity in sorted(selected):
        if entity.location != "shared" and entity.location not in model.parents:
            raise UnsafePlanError(
                f"Device group {entity.location!r} encji {entity.text} nie istnieje "
                "w bieżącym running config."
            )
        version = backups[entity]
        if not version.historical_scope_context_available:
            continue
        historical = _historical_resolution_chain(version, entity.location)
        current = resolution_chain(model, entity.location)
        if historical != current:
            raise UnsafePlanError(
                f"Zmieniła się hierarchia lub object precedence dla "
                f"{entity.text}: historycznie={historical}, obecnie={current}. "
                "Nie można zagwarantować restore 1:1."
            )


def _validate_cleanup_timeline(
    model: ConfigModel,
    runs: Sequence[CleanupRun],
    selected: Set[RestoreEntity],
    versions_by_entity: Mapping[RestoreEntity, Sequence[BackupVersion]],
) -> None:
    """Prove that repeated backups form one cleanup-only state sequence.

    A current entity may match any known point in that sequence, which permits
    rerunning the generator after a complete or partial emergency rollback. An
    unrelated administrator change does not match and therefore fails closed.
    """

    run_by_manifest = {run.manifest_path: run for run in runs}
    for entity in sorted(selected):
        versions = list(versions_by_entity[entity])
        state_xml: Optional[str] = versions[0].xml
        known_states: Set[Optional[Tuple[Any, ...]]] = {
            _canonical_entry(state_xml)
        }
        for index, version in enumerate(versions):
            if index and (
                state_xml is None
                or _canonical_entry(state_xml) != _canonical_entry(version.xml)
            ):
                raise UnsafePlanError(
                    f"NIECIĄGŁA_HISTORIA_BACKUPÓW: {entity.text}; stan po runie "
                    f"{versions[index - 1].manifest_path} nie odpowiada backupowi "
                    f"w {version.manifest_path}. Możliwa zmiana administratora "
                    "pomiędzy cleanupami."
                )
            known_states.add(_canonical_entry(version.xml))
            run = run_by_manifest[version.manifest_path]
            records = _entity_command_records(run, entity)
            state_xml = _apply_cleanup_records(entity, version.xml, records)
            known_states.add(
                None if state_xml is None else _canonical_entry(state_xml)
            )

        current_xml = _current_entity_xml(model, entity)
        current_state = (
            None if current_xml is None else _canonical_entry(current_xml)
        )
        if current_state not in known_states:
            raise UnsafePlanError(
                f"BIEŻĄCY_STAN_POZA_HISTORIĄ_CLEANUP: {entity.text}; running "
                "nie odpowiada żadnemu zweryfikowanemu stanowi przed/po "
                "podanych runach. Automatyczny restore mógłby nadpisać cudzą zmianę."
            )


def _entity_command_records(
    run: CleanupRun, entity: RestoreEntity
) -> Tuple[Mapping[str, Any], ...]:
    expected_type = "group" if entity.entity_type == "static-group" else entity.entity_type
    records = tuple(
        record
        for record in run.commands
        if _command_identity(record) == (expected_type, entity.text)
    )
    if not records:
        raise UnsafePlanError(
            f"Backup {entity.text} nie ma komendy w {run.manifest_path}."
        )
    return records


def _entity_has_command_category(
    runs: Sequence[CleanupRun], entity: RestoreEntity, category: str
) -> bool:
    expected_type = "group" if entity.entity_type == "static-group" else entity.entity_type
    identity = (expected_type, entity.text)
    return any(
        record.get("category") == category
        for run in runs
        for record in run.commands
        if _command_identity(record) == identity
    )


def _apply_cleanup_records(
    entity: RestoreEntity,
    backup_xml: str,
    records: Sequence[Mapping[str, Any]],
) -> Optional[str]:
    full_delete_categories = {
        "address": "address-delete",
        "static-group": "group-delete",
        "policy": "rule-delete",
    }
    full_delete = [
        record
        for record in records
        if record.get("category") == full_delete_categories[entity.entity_type]
    ]
    if full_delete:
        if len(records) != 1 or len(full_delete) != 1:
            raise UnsafePlanError(
                f"Sprzeczne komendy pełnego usunięcia dla {entity.text}."
            )
        return None
    if entity.entity_type == "address":
        raise UnsafePlanError(
            f"Address {entity.text} nie ma komendy address-delete."
        )

    entry = ET.fromstring(backup_xml)
    for record in records:
        tokens = _parse_cleanup_cli(str(record.get("command") or ""))
        category = record.get("category")
        if entity.entity_type == "static-group" and category == "group-member":
            if len(tokens) < 2 or tokens[-2] != "static":
                raise UnsafePlanError(
                    f"Nie można odtworzyć semantyki komendy {record.get('command_id')}."
                )
            container = entry.find("./static")
            member_name = tokens[-1]
        elif entity.entity_type == "policy" and category == "rule-member":
            if len(tokens) < 2 or tokens[-2] not in {"source", "destination"}:
                raise UnsafePlanError(
                    f"Nie można odtworzyć semantyki komendy {record.get('command_id')}."
                )
            container = entry.find(f"./{tokens[-2]}")
            member_name = tokens[-1]
        else:
            raise UnsafePlanError(
                f"Nieobsługiwana kategoria {category!r} dla {entity.text}."
            )
        if container is None:
            raise UnsafePlanError(
                f"Backup {entity.text} nie ma kontenera z komendy "
                f"{record.get('command_id')}."
            )
        matches = [
            member
            for member in container.findall("./member")
            if (member.text or "").strip() == member_name
        ]
        if len(matches) != 1:
            raise UnsafePlanError(
                f"Komenda {record.get('command_id')} oczekuje dokładnie jednego "
                f"member {member_name!r} w backupie {entity.text}; znaleziono "
                f"{len(matches)}."
            )
        container.remove(matches[0])
    return ET.tostring(entry, encoding="unicode")


def _parse_cleanup_cli(command: str) -> Tuple[str, ...]:
    tokens: List[str] = []
    current: List[str] = []
    quoted = False
    escaped = False
    for character in command:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character.isspace() and not quoted:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(character)
    if escaped or quoted:
        raise UnsafePlanError("Niepoprawne quoting w komendzie cleanup.")
    if current:
        tokens.append("".join(current))
    if not tokens or tokens[0] != "delete":
        raise UnsafePlanError("Niepoprawna komenda cleanup w manifeście.")
    return tuple(tokens)


def _current_entity_xml(
    model: ConfigModel, entity: RestoreEntity
) -> Optional[str]:
    if entity.entity_type == "address":
        current = model.addresses.get(ScopedName(entity.location, entity.name))
    elif entity.entity_type == "static-group":
        current = model.static_groups.get(ScopedName(entity.location, entity.name))
    else:
        current = model.rules.get(
            RuleKey(entity.location, entity.rulebase, entity.policy_type, entity.name)
        )
    return current.xml if current is not None else None


def _current_state(model: ConfigModel, entity: RestoreEntity, backup_xml: str) -> str:
    current_xml: Optional[str] = None
    scoped = ScopedName(entity.location, entity.name)
    if entity.entity_type == "address":
        current = model.addresses.get(scoped)
        current_xml = current.xml if current else None
        if current is None and (
            scoped in model.static_groups or scoped in model.dynamic_groups
        ):
            return "KOLIZJA_Z_ADDRESS_GROUP"
    elif entity.entity_type == "static-group":
        current = model.static_groups.get(scoped)
        current_xml = current.xml if current else None
        if current is None and scoped in model.addresses:
            return "KOLIZJA_Z_ADDRESS"
        if current is None and scoped in model.dynamic_groups:
            return "KOLIZJA_Z_DYNAMIC_GROUP"
    else:
        current = model.rules.get(
            RuleKey(entity.location, entity.rulebase, entity.policy_type, entity.name)
        )
        current_xml = current.xml if current else None
    if current_xml is None:
        return "BRAK_W_RUNNING"
    return (
        "ZGODNY_Z_BACKUPEM"
        if _canonical_entry(current_xml) == _canonical_entry(backup_xml)
        else "ISTNIEJE_ALE_ROZNI_SIE_OD_BACKUPU"
    )


def _canonical_entry(xml: str) -> Tuple[Any, ...]:
    def walk(node: ET.Element) -> Tuple[Any, ...]:
        text = (node.text or "").strip()
        return (
            node.tag,
            tuple(
                sorted(
                    (name, value)
                    for name, value in node.attrib.items()
                    if name not in VOLATILE_ATTRIBUTES
                )
            ),
            text,
            tuple(walk(child) for child in list(node)),
        )

    return walk(ET.fromstring(xml))


def _restore_group_order(
    selected: Set[RestoreEntity],
    dependencies: Mapping[RestoreEntity, Set[RestoreEntity]],
) -> List[RestoreEntity]:
    groups = {entity for entity in selected if entity.entity_type == "static-group"}
    visiting: Set[RestoreEntity] = set()
    visited: Set[RestoreEntity] = set()
    order: List[RestoreEntity] = []

    def visit(group: RestoreEntity) -> None:
        if group in visited:
            return
        if group in visiting:
            raise UnsafePlanError(f"Cykl grup w restore obejmuje {group.text}")
        visiting.add(group)
        for dependency in sorted(dependencies.get(group, set())):
            if dependency in groups:
                visit(dependency)
        visiting.remove(group)
        visited.add(group)
        order.append(group)

    for group in sorted(groups):
        visit(group)
    return order


def _cli_path(entity: RestoreEntity) -> List[str]:
    prefix = ["shared"] if entity.location == "shared" else [
        "device-group", quote_cli(entity.location, context="device group restore")
    ]
    if entity.entity_type == "address":
        return prefix + ["address", quote_cli(entity.name, context="address restore")]
    if entity.entity_type == "static-group":
        return prefix + [
            "address-group", quote_cli(entity.name, context="address-group restore")
        ]
    return prefix + [
        entity.rulebase,
        entity.policy_type,
        "rules",
        quote_cli(entity.name, context="policy restore"),
    ]


def _policy_move_commands(
    model: ConfigModel,
    policies: Sequence[RestoreEntity],
    backups: Mapping[RestoreEntity, BackupVersion],
) -> Tuple[List[str], List[str]]:
    selected_keys = {
        RuleKey(item.location, item.rulebase, item.policy_type, item.name)
        for item in policies
    }
    existing_after = set(model.rules) | selected_keys
    policy_by_key = {
        RuleKey(entity.location, entity.rulebase, entity.policy_type, entity.name): version
        for entity, version in backups.items()
        if entity.entity_type == "policy"
    }
    commands: List[str] = []
    warnings: List[str] = []
    for entity in reversed(policies):
        key = RuleKey(entity.location, entity.rulebase, entity.policy_type, entity.name)
        record = backups[entity].record
        next_name = (
            record.get("next_rule")
            if isinstance(record.get("next_rule"), str)
            else None
        )
        previous_name = (
            record.get("previous_rule")
            if isinstance(record.get("previous_rule"), str)
            else None
        )
        full_order_anchor = _full_rule_order_anchor(
            key, record.get("rule_order"), existing_after
        )
        next_anchor: Optional[str] = None
        previous_anchor: Optional[str] = None
        if full_order_anchor is not None:
            direction, anchor = full_order_anchor
            if direction == "before":
                next_anchor = anchor
            else:
                previous_anchor = anchor
        else:
            next_anchor = _follow_rule_anchor(
                key, next_name, "next_rule", existing_after, policy_by_key
            )
            previous_anchor = _follow_rule_anchor(
                key, previous_name, "previous_rule", existing_after, policy_by_key
            )
        if next_anchor:
            commands.append(
                " ".join(
                    ["move"]
                    + _cli_path(entity)
                    + ["before", quote_cli(next_anchor, context="next rule restore")]
                )
            )
        elif previous_anchor:
            commands.append(
                " ".join(
                    ["move"]
                    + _cli_path(entity)
                    + ["after", quote_cli(previous_anchor, context="previous rule restore")]
                )
            )
        else:
            other_rules = [
                candidate
                for candidate in existing_after
                if candidate != key
                and (
                    candidate.location,
                    candidate.rulebase,
                    candidate.policy_type,
                )
                == (key.location, key.rulebase, key.policy_type)
            ]
            if other_rules:
                raise UnsafePlanError(
                    f"Nie można dowieść pozycji 1:1 dla {entity.text}; "
                    f"previous={previous_name!r}, next={next_name!r}, a rulebase "
                    "nie jest pusty. Generator nie użyje niebezpiecznego fallbacku."
                )
    return _deduplicate(commands), warnings


def _full_rule_order_anchor(
    owner: RuleKey,
    order_value: Any,
    existing_after: Set[RuleKey],
) -> Optional[Tuple[str, str]]:
    if not isinstance(order_value, list) or owner.name not in order_value:
        return None
    index = order_value.index(owner.name)
    for name in order_value[index + 1 :]:
        candidate = RuleKey(
            owner.location, owner.rulebase, owner.policy_type, name
        )
        if candidate in existing_after:
            return "before", name
    for name in reversed(order_value[:index]):
        candidate = RuleKey(
            owner.location, owner.rulebase, owner.policy_type, name
        )
        if candidate in existing_after:
            return "after", name
    return None


def _follow_rule_anchor(
    owner: RuleKey,
    name: Optional[str],
    direction: str,
    existing_after: Set[RuleKey],
    policy_backups: Mapping[RuleKey, BackupVersion],
) -> Optional[str]:
    seen: Set[str] = set()
    current = name
    while current and current not in seen:
        seen.add(current)
        key = RuleKey(owner.location, owner.rulebase, owner.policy_type, current)
        if key in existing_after:
            return current
        version = policy_backups.get(key)
        if version is None:
            return None
        value = version.record.get(direction)
        current = value if isinstance(value, str) and value else None
    return None


def _build_bundle_xml(
    device_entry_name: str,
    entities: Sequence[RestoreEntity],
    backups: Mapping[RestoreEntity, BackupVersion],
) -> str:
    root = ET.Element("config")
    for entity in entities:
        if entity.location == "shared":
            scope = _ensure_child(root, "shared")
        else:
            devices = _ensure_child(root, "devices")
            device = _ensure_entry(devices, device_entry_name)
            groups = _ensure_child(device, "device-group")
            scope = _ensure_entry(groups, entity.location)
        if entity.entity_type == "address":
            container = _ensure_child(scope, "address")
        elif entity.entity_type == "static-group":
            container = _ensure_child(scope, "address-group")
        else:
            rulebase = _ensure_child(scope, entity.rulebase)
            policy = _ensure_child(rulebase, entity.policy_type)
            container = _ensure_child(policy, "rules")
        container.append(ET.fromstring(backups[entity].xml))
    try:
        ET.indent(root, space="  ")
    except AttributeError:  # pragma: no cover - Python < 3.9
        pass
    return ET.tostring(root, encoding="unicode") + "\n"


def _ensure_child(parent: ET.Element, tag: str) -> ET.Element:
    child = parent.find(f"./{tag}")
    return child if child is not None else ET.SubElement(parent, tag)


def _ensure_entry(parent: ET.Element, name: str) -> ET.Element:
    for entry in parent.findall("./entry"):
        if entry.get("name") == name:
            return entry
    return ET.SubElement(parent, "entry", {"name": name})


def _partial_load_commands(
    entities: Sequence[RestoreEntity],
    current_states: Mapping[RestoreEntity, str],
    bundle_filename: str,
    move_commands: Sequence[str],
    device_entry_name: str,
) -> List[str]:
    commands: List[str] = []
    for entity in entities:
        state = current_states[entity]
        if state == "ZGODNY_Z_BACKUPEM":
            continue
        xpath = _entity_xpath(device_entry_name, entity)
        mode = "merge" if state == "BRAK_W_RUNNING" else "replace"
        source_xpath = xpath[len("/config/") :]
        destination_xpath = (
            _parent_xpath(xpath) if mode == "merge" else xpath
        )
        commands.append(
            " ".join(
                [
                    "load config partial mode",
                    mode,
                    "from-xpath",
                    quote_cli(source_xpath, context="restore from-xpath"),
                    "to-xpath",
                    quote_cli(destination_xpath, context="restore to-xpath"),
                    "from",
                    quote_cli(bundle_filename, context="restore bundle filename"),
                ]
            )
        )
    commands.extend(move_commands)
    return _deduplicate(commands)


def _entity_xpath(device_entry_name: str, entity: RestoreEntity) -> str:
    if entity.location == "shared":
        scope = "/config/shared"
    else:
        scope = (
            "/config/devices/entry[@name="
            + _xpath_literal(device_entry_name)
            + "]/device-group/entry[@name="
            + _xpath_literal(entity.location)
            + "]"
        )
    if entity.entity_type == "address":
        container = "address"
    elif entity.entity_type == "static-group":
        container = "address-group"
    else:
        container = f"{entity.rulebase}/{entity.policy_type}/rules"
    return (
        f"{scope}/{container}/entry[@name="
        + _xpath_literal(entity.name)
        + "]"
    )


def _parent_xpath(xpath: str) -> str:
    marker = "/entry[@name="
    parent, separator, _ = xpath.rpartition(marker)
    if not separator or not parent.startswith("/config/"):
        raise UnsafePlanError(f"Nie można ustalić nadrzędnego XPath dla {xpath!r}.")
    return parent


def _deduplicate(values: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen: Set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _restore_report(plan: EmergencyRestorePlan) -> str:
    lines = [
        "AWARYJNY RESTORE PER IP — RAPORT DOMKNIĘCIA ZALEŻNOŚCI",
        "======================================================",
        "",
        "Skrypt niczego nie zmienił w Panoramie.",
        "IP: " + ", ".join(plan.target_ips),
        "",
        "BEZPOŚREDNIE ZMIANY DLA IP:",
    ]
    lines.extend(f"  - {item}" for item in plan.seed_evidence)
    if not plan.seed_evidence:
        lines.append("  - brak")
    lines.extend(["", "PEŁNY KOMPONENT DO ODTWORZENIA:"])
    for entity in plan.selected:
        version = plan.backup_versions[entity]
        lines.append(
            f"  - {entity.entity_type} {entity.text} | "
            f"running={plan.current_states[entity]}"
        )
        lines.append(f"    backup: {version.record.get('file')} | {version.manifest_path}")
        for reason in plan.reasons.get(entity, ()):
            lines.append(f"    powód: {reason}")
    if not plan.selected:
        lines.append("  - brak")
    lines.extend(["", "OSTRZEŻENIA:"])
    lines.extend(f"  - {item}" for item in plan.warnings)
    if not plan.warnings:
        lines.append("  - brak")
    lines.extend(
        [
            "",
            f"Komendy szybkiego CLI: {len(plan.cli_commands)}",
            f"Komendy load config partial: {len(plan.partial_load_commands)}",
            "",
        ]
    )
    return "\n".join(lines)


def _warning_report(plan: EmergencyRestorePlan) -> str:
    lines = [
        "OSTRZEŻENIA AWARYJNEGO RESTORE",
        "===============================",
        "",
    ]
    if plan.warnings:
        lines.extend(f"- {warning}" for warning in plan.warnings)
    else:
        lines.append("brak")
    return "\n".join(lines) + "\n"


def _restore_instructions(plan: EmergencyRestorePlan, bundle_filename: str) -> str:
    return (
        "AWARYJNE ODTWORZENIE PANORAMA — INSTRUKCJA\n"
        "==========================================\n\n"
        "Skrypt wyłącznie wygenerował pakiet; nie wykonał zmian ani commit.\n\n"
        "WARUNEK GOTOWOŚCI\n"
        "Nie używaj żadnego pliku komend, jeżeli w katalogu nie ma pliku "
        "RESTORE_READY. Jest on publikowany jako ostatni po kompletnym zapisie "
        "pakietu. Przeczytaj również restore_warnings.txt.\n\n"
        "ZALECANA ŚCIEŻKA 1:1 (pełny XML i zapisane atrybuty)\n"
        f"1. Zaimportuj {bundle_filename} do Panoramy jako named configuration snapshot.\n"
        "2. Ponownie sprawdź, że nie ma cudzych zmian candidate, i wykonaj "
        "backup bieżącej konfiguracji. Potwierdzenie przy generacji nie chroni "
        "przed późniejszą zmianą candidate.\n"
        "3. Wejdź do configure i wklej restore_partial_load_commands.txt.\n"
        "   Dla brakujących encji używany jest merge, a dla istniejących różniących\n"
        "   się od backupu — replace całej encji. To świadomie odtwarza stan sprzed cleanup.\n"
        "4. Wykonaj validate full oraz show config diff.\n"
        "5. Dopiero po review wykonaj ręczny commit i właściwy push do managed firewalli.\n"
        "UWAGA OPERACYJNA: load config partial z XPath na Panoramie może "
        "zablokować selective push dla wszystkich device groups do czasu full "
        "commit/full push. Zaplanuj zakres i okno zmiany przed użyciem XML.\n"
        "KB Palo Alto: https://knowledgebase.paloaltonetworks.com/"
        "KCSArticleDetail?id=kA14u000000CrRyCAK\n\n"
        "SZYBKA ŚCIEŻKA CLI\n"
        "Po configure można wkleić restore_commands.txt. Odtwarza wszystkie pola\n"
        "możliwe do bezpiecznego zapisania przez set i przesuwa reguły na zapisaną\n"
        "pozycję. CLI nie odtwarza atrybutów entry takich jak UUID; dla pełnego\n"
        "odtworzenia użyj XML.\n\n"
        "WAŻNE\n"
        "Pakiet obejmuje pełny połączony komponent zależności ze wskazanych runów,\n"
        "więc może zawierać inne IP, grupy i polityki niezbędne do spójnego restore.\n"
        "Podawaj wyłącznie runy, których commands.txt faktycznie zastosowano.\n"
        "Nie używaj obu ścieżek jednocześnie.\n"
    )


def _write_text(path: Path, content: str) -> None:
    _atomic_write(path, content.encode("utf-8"))


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _atomic_write(path: Path, content: bytes) -> None:
    temporary_name: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as handle:
            temporary_name = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary_name, 0o600)
        except OSError:
            pass
        os.replace(temporary_name, path)
    except OSError as exc:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
        raise OutputError(f"Nie można zapisać artefaktu {path}") from exc
