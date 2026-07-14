"""Read-only post-cleanup audit of Panorama address evidence and references."""

from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from .models import (
    ConfigModel,
    InputError,
    InputRow,
    OutputError,
    PingResult,
    PingStatus,
    ResolvedReference,
    RuleKey,
    ScopedName,
)
from .panos import (
    address_literal_relation,
    is_supported_address_literal,
    match_ip_objects,
    normalize_host_literal,
    resolve_occurrence,
    scope_chain,
)
from .planner import dependency_inventories, dynamic_group_impacts_for_addresses


@dataclass(frozen=True, order=True)
class AuditReference:
    relation: str
    location: str
    owner_type: str
    owner_name: str
    configuration_path: str
    value: str
    field: str = ""
    rulebase: str = ""
    policy_type: str = ""
    detail: str = ""


@dataclass(frozen=True)
class AuditObject:
    location: str
    name: str
    object_type: str
    raw_value: str
    xpath: str
    groups: Tuple[str, ...]
    rules: Tuple[str, ...]
    paths: Tuple[str, ...]
    dynamic_groups: Tuple[str, ...]
    dynamic_group_rules: Tuple[str, ...]


@dataclass(frozen=True)
class IPAudit:
    ip: str
    status: str
    ping_status: str
    ping_detail: str
    exact_objects: Tuple[AuditObject, ...]
    containing_objects: Tuple[AuditObject, ...]
    literal_references: Tuple[AuditReference, ...]
    historical_objects: Tuple[str, ...]
    historical_name_references: Tuple[AuditReference, ...]

    @property
    def unexpected(self) -> bool:
        return self.status.startswith("ALERT_")

    @property
    def review_required(self) -> bool:
        return self.unexpected or self.status.startswith("REVIEW_")


@dataclass(frozen=True)
class AuditBatch:
    results: Mapping[str, IPAudit]
    previous_manifests: Tuple[str, ...]
    historical_name_coverage: bool
    warnings: Tuple[str, ...]

    @property
    def review_required(self) -> bool:
        return (not self.historical_name_coverage) or any(
            result.review_required for result in self.results.values()
        )


def load_historical_objects(
    paths: Sequence[Path], ips: Iterable[str]
) -> Tuple[Dict[str, Set[ScopedName]], Tuple[str, ...]]:
    """Recover original IP-to-object identities from earlier cleanup manifests."""

    normalized_ips = tuple(sorted(set(ips)))
    result: Dict[str, Set[ScopedName]] = {ip: set() for ip in normalized_ips}
    manifests: List[str] = []
    for supplied_path in paths:
        manifest_path = (
            supplied_path / "manifest.json" if supplied_path.is_dir() else supplied_path
        )
        if not manifest_path.is_file():
            raise InputError(f"Brak manifestu poprzedniego runu: {manifest_path}")
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise InputError(
                f"Nie można odczytać manifestu poprzedniego runu: {manifest_path}"
            ) from exc
        backups = payload.get("backups")
        if not isinstance(backups, list):
            raise InputError(
                f"Manifest nie zawiera poprawnej listy backups: {manifest_path}"
            )
        manifests.append(str(manifest_path.resolve()))
        for record in backups:
            if not isinstance(record, dict) or record.get("entity_type") != "address":
                continue
            location = record.get("location")
            name = record.get("name")
            raw_value = record.get("raw_value")
            if not all(isinstance(value, str) and value for value in (location, name, raw_value)):
                continue
            key = ScopedName(location, name)
            exact_ip = normalize_host_literal(raw_value)
            if exact_ip in result:
                result[exact_ip].add(key)
    return result, tuple(sorted(set(manifests)))


def audit_config(
    model: ConfigModel,
    ips: Iterable[str],
    pings: Mapping[str, PingResult],
    *,
    historical_objects: Optional[Mapping[str, Set[ScopedName]]] = None,
    previous_manifests: Sequence[str] = (),
) -> AuditBatch:
    normalized_ips = tuple(sorted(set(ips)))
    matches = match_ip_objects(model, normalized_ips)
    history = historical_objects or {}
    all_object_keys = {
        key
        for match in matches.values()
        for key in match.exact_objects + match.containing_objects
    }
    inventories = dependency_inventories(model, all_object_keys)
    dag_impacts = dynamic_group_impacts_for_addresses(model, all_object_keys)
    dynamic_rules = _dynamic_group_rule_references(model, set(dag_impacts))
    literal_references_by_ip = _literal_references_many(model, normalized_ips)
    historical_references_by_ip = _historical_name_references_many(
        model, normalized_ips, history
    )

    results: Dict[str, IPAudit] = {}
    for ip in normalized_ips:
        exact_objects = tuple(
            _object_audit(
                model,
                key,
                inventories,
                dag_impacts,
                dynamic_rules,
            )
            for key in matches[ip].exact_objects
        )
        containing_objects = tuple(
            _object_audit(
                model,
                key,
                inventories,
                dag_impacts,
                dynamic_rules,
            )
            for key in matches[ip].containing_objects
        )
        literal_references = literal_references_by_ip[ip]
        old_keys = tuple(sorted(history.get(ip, set())))
        historical_references = historical_references_by_ip[ip]
        status = _classify(
            pings[ip],
            exact_objects,
            containing_objects,
            literal_references,
            old_keys,
            historical_references,
        )
        results[ip] = IPAudit(
            ip=ip,
            status=status,
            ping_status=pings[ip].status.value,
            ping_detail=pings[ip].detail,
            exact_objects=exact_objects,
            containing_objects=containing_objects,
            literal_references=literal_references,
            historical_objects=tuple(
                f"{key.location}/{key.name}" for key in old_keys
            ),
            historical_name_references=historical_references,
        )

    warnings = list(dict.fromkeys(model.warnings))
    historical_coverage = bool(previous_manifests)
    if not historical_coverage:
        warnings.append(
            "HISTORIA_NIEPODANA: bez --previous-run można potwierdzić bieżące "
            "obiekty i literały IP, ale nie można przypisać osieroconej referencji "
            "po usuniętej nazwie obiektu do konkretnego IP."
        )
    return AuditBatch(
        results=results,
        previous_manifests=tuple(previous_manifests),
        historical_name_coverage=historical_coverage,
        warnings=tuple(warnings),
    )


def _object_audit(
    model: ConfigModel,
    key: ScopedName,
    inventories: Mapping[ScopedName, Tuple[Set[ScopedName], Set[RuleKey], List[str]]],
    dag_impacts: Mapping[ScopedName, Set[ScopedName]],
    dynamic_rules: Mapping[ScopedName, Set[RuleKey]],
) -> AuditObject:
    obj = model.addresses[key]
    groups, rules, paths = inventories[key]
    object_dags = tuple(
        sorted(
            f"{group.location}/{group.name}"
            for group, objects in dag_impacts.items()
            if key in objects
        )
    )
    dag_rule_keys = {
        rule
        for group, objects in dag_impacts.items()
        if key in objects
        for rule in dynamic_rules.get(group, set())
    }
    return AuditObject(
        location=key.location,
        name=key.name,
        object_type=obj.object_type,
        raw_value=obj.raw_value,
        xpath=obj.xpath,
        groups=tuple(f"{item.location}/{item.name}" for item in sorted(groups)),
        rules=tuple(_rule_text(item) for item in sorted(rules)),
        paths=tuple(paths),
        dynamic_groups=object_dags,
        dynamic_group_rules=tuple(_rule_text(item) for item in sorted(dag_rule_keys)),
    )


def _dynamic_group_rule_references(
    model: ConfigModel, group_keys: Set[ScopedName]
) -> Dict[ScopedName, Set[RuleKey]]:
    result: Dict[ScopedName, Set[RuleKey]] = {key: set() for key in group_keys}
    for rule_key, refs in model.rule_references.items():
        for ref in refs:
            if ref.resolved_kind == "dynamic-group" and ref.resolved_key in result:
                result[ref.resolved_key].add(rule_key)
    return result


def _literal_references_many(
    model: ConfigModel, ips: Sequence[str]
) -> Dict[str, Tuple[AuditReference, ...]]:
    """Index literal occurrences once; repeated values share IP matching work."""

    references: Dict[str, Set[AuditReference]] = {ip: set() for ip in ips}
    relation_cache: Dict[str, Tuple[Tuple[str, str], ...]] = {}

    def matching_ips(value: str) -> Tuple[Tuple[str, str], ...]:
        if value not in relation_cache:
            if not is_supported_address_literal(value):
                relation_cache[value] = ()
            else:
                relation_cache[value] = tuple(
                    (ip, relation)
                    for ip in ips
                    for relation in (address_literal_relation(value, ip),)
                    if relation is not None
                )
        return relation_cache[value]

    for refs in model.group_references.values():
        for ref in refs:
            if ref.resolved_kind not in {"literal", "unresolved"}:
                continue
            for ip, relation in matching_ips(ref.referenced_name):
                references[ip].add(_reference_from_resolved(ref, relation))
    for refs in model.rule_references.values():
        for ref in refs:
            if ref.resolved_kind not in {"literal", "unresolved"}:
                continue
            for ip, relation in matching_ips(ref.referenced_name):
                references[ip].add(_reference_from_resolved(ref, relation))
    for occurrence in model.unknown_occurrences:
        kind, _, detail = resolve_occurrence(model, occurrence)
        if kind not in {"literal", "unresolved"}:
            continue
        owner_rule = occurrence.owner_rule
        for ip, relation in matching_ips(occurrence.value):
            references[ip].add(
                AuditReference(
                    relation=relation,
                    location=occurrence.location,
                    owner_type=occurrence.owner_type,
                    owner_name=occurrence.owner_name,
                    configuration_path=occurrence.configuration_path,
                    value=occurrence.value,
                    field=occurrence.configuration_path.rsplit("/", 1)[-1],
                    rulebase=owner_rule.rulebase if owner_rule else "",
                    policy_type=owner_rule.policy_type if owner_rule else "",
                    detail=detail,
                )
            )
    return {ip: tuple(sorted(items)) for ip, items in references.items()}


def _reference_from_resolved(
    ref: ResolvedReference, relation: str
) -> AuditReference:
    owner_rule = ref.owner_rule
    return AuditReference(
        relation=relation,
        location=ref.owner_location,
        owner_type=ref.owner_type,
        owner_name=ref.owner_name,
        configuration_path=ref.configuration_path,
        value=ref.referenced_name,
        field=ref.field,
        rulebase=owner_rule.rulebase if owner_rule else "",
        policy_type=owner_rule.policy_type if owner_rule else "",
        detail=ref.detail,
    )


def _historical_name_references_many(
    model: ConfigModel,
    ips: Sequence[str],
    historical_objects: Mapping[str, Set[ScopedName]],
) -> Dict[str, Tuple[AuditReference, ...]]:
    """Scan current references once and join them to deleted historical names."""

    references: Dict[str, Set[AuditReference]] = {ip: set() for ip in ips}
    candidates_by_name: Dict[str, List[Tuple[str, ScopedName]]] = defaultdict(list)
    for ip in ips:
        for old_key in historical_objects.get(ip, set()):
            if old_key not in model.addresses:
                candidates_by_name[old_key.name].append((ip, old_key))

    for refs in model.group_references.values():
        for ref in refs:
            for ip, old_key in candidates_by_name.get(ref.referenced_name, ()):
                if _scope_could_see(model, ref.owner_location, old_key.location):
                    references[ip].add(
                        _historical_reference(ref, old_key, ref.resolved_kind)
                    )
    for refs in model.rule_references.values():
        for ref in refs:
            for ip, old_key in candidates_by_name.get(ref.referenced_name, ()):
                if _scope_could_see(model, ref.owner_location, old_key.location):
                    references[ip].add(
                        _historical_reference(ref, old_key, ref.resolved_kind)
                    )
    for occurrence in model.unknown_occurrences:
        candidates = candidates_by_name.get(occurrence.value, ())
        if not candidates:
            continue
        kind, resolved, detail = resolve_occurrence(model, occurrence)
        current = kind
        if resolved is not None:
            current += f":{resolved.location}/{resolved.name}"
        if detail:
            current += f":{detail}"
        owner_rule = occurrence.owner_rule
        for ip, old_key in candidates:
            if not _scope_could_see(
                model, occurrence.location, old_key.location
            ):
                continue
            references[ip].add(
                AuditReference(
                    relation="historical-name",
                    location=occurrence.location,
                    owner_type=occurrence.owner_type,
                    owner_name=occurrence.owner_name,
                    configuration_path=occurrence.configuration_path,
                    value=occurrence.value,
                    field=occurrence.configuration_path.rsplit("/", 1)[-1],
                    rulebase=owner_rule.rulebase if owner_rule else "",
                    policy_type=owner_rule.policy_type if owner_rule else "",
                    detail=(
                        f"history={old_key.location}/{old_key.name}; "
                        f"current_resolution={current}"
                    ),
                )
            )
    return {ip: tuple(sorted(items)) for ip, items in references.items()}


def _historical_reference(
    ref: ResolvedReference, old_key: ScopedName, current_kind: str
) -> AuditReference:
    owner_rule = ref.owner_rule
    current = current_kind
    if ref.resolved_key is not None:
        current += f":{ref.resolved_key.location}/{ref.resolved_key.name}"
    return AuditReference(
        relation="historical-name",
        location=ref.owner_location,
        owner_type=ref.owner_type,
        owner_name=ref.owner_name,
        configuration_path=ref.configuration_path,
        value=ref.referenced_name,
        field=ref.field,
        rulebase=owner_rule.rulebase if owner_rule else "",
        policy_type=owner_rule.policy_type if owner_rule else "",
        detail=(
            f"history={old_key.location}/{old_key.name}; "
            f"current_resolution={current}"
        ),
    )


def _scope_could_see(model: ConfigModel, owner_location: str, old_location: str) -> bool:
    return old_location in scope_chain(model, owner_location)


def _classify(
    ping: PingResult,
    exact_objects: Sequence[AuditObject],
    containing_objects: Sequence[AuditObject],
    literal_references: Sequence[AuditReference],
    historical_objects: Sequence[ScopedName],
    historical_references: Sequence[AuditReference],
) -> str:
    exact_literals = any(item.relation == "exact" for item in literal_references)
    containing_literals = any(
        item.relation == "containing" for item in literal_references
    )
    exact_remains = bool(exact_objects or exact_literals or historical_references)
    containing_remains = bool(containing_objects or containing_literals)

    if ping.status == PingStatus.ERROR:
        return "REVIEW_BLAD_ICMP"
    if ping.status == PingStatus.REPLIED:
        if historical_references:
            return "ALERT_ICMP_POZOSTALA_REFERENCJA_PO_USUNIETEJ_NAZWIE"
        if exact_objects:
            return "OCZEKIWANIE_POZOSTAWIONY_ICMP"
        if historical_objects:
            return "ALERT_ICMP_ODPOWIADA_OBIEKT_USUNIETY"
        if exact_literals:
            return "OCZEKIWANIE_POZOSTAWIONY_ICMP"
        if containing_remains:
            return "REVIEW_ICMP_ODPOWIADA_TYLKO_SZERSZY_ZAKRES"
        return "REVIEW_ICMP_ODPOWIADA_BEZ_OBIEKTU"
    if ping.status == PingStatus.BYPASSED:
        if exact_remains:
            return "REVIEW_POZOSTALO_BEZ_TESTU_ICMP"
        if containing_remains:
            return "REVIEW_TYLKO_SZERSZY_ZAKRES_BEZ_TESTU_ICMP"
        return "CZYSTO_BEZ_TESTU_ICMP"
    if exact_remains:
        return "ALERT_POZOSTAL_DOKLADNY_OBIEKT_LUB_REFERENCJA"
    if containing_remains:
        return "REVIEW_TYLKO_SZERSZY_ZAKRES"
    return "CZYSTO"


def create_audit_directory(base: Path, now: Optional[datetime] = None) -> Path:
    timestamp = (now or datetime.now().astimezone()).astimezone()
    name = "audit_" + timestamp.strftime("%d%m%y_%H_%M_%S")
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
        raise OutputError(f"Nie można utworzyć katalogu audytu: {candidate}") from exc
    return candidate


def write_audit_artifacts(
    *,
    audit_dir: Path,
    batch: AuditBatch,
    rows: Sequence[InputRow],
    pings: Mapping[str, PingResult],
    metadata: Mapping[str, Any],
) -> None:
    try:
        _write_text(audit_dir / "audit_summary.txt", _summary(batch, rows))
        _write_text(audit_dir / "audit_detailed.txt", _detailed(batch, rows))
        _write_text(audit_dir / "audit_status.csv", _status_csv(batch, rows))
        _write_text(
            audit_dir / "icmp_responded.txt",
            _ping_report(rows, pings, PingStatus.REPLIED),
        )
        _write_text(
            audit_dir / "icmp_no_response.txt",
            _ping_report(rows, pings, PingStatus.NO_REPLY),
        )
        _write_text(
            audit_dir / "icmp_errors.txt",
            _ping_report(rows, pings, PingStatus.ERROR),
        )
        result_payload = {
            ip: asdict(result) for ip, result in sorted(batch.results.items())
        }
        _write_json(audit_dir / "audit_results.json", result_payload)
        status_counts: Dict[str, int] = {}
        for result in batch.results.values():
            status_counts[result.status] = status_counts.get(result.status, 0) + 1
        manifest = dict(metadata)
        manifest.update(
            {
                "previous_manifests": list(batch.previous_manifests),
                "historical_name_coverage": batch.historical_name_coverage,
                "warnings": list(batch.warnings),
                "status_counts": dict(sorted(status_counts.items())),
                "review_required": batch.review_required,
                "changes_executed": False,
                "commands_generated": False,
            }
        )
        _write_json(audit_dir / "audit_manifest.json", manifest)
    except OutputError:
        raise
    except OSError as exc:
        raise OutputError(f"Błąd zapisu artefaktów audytu w {audit_dir}") from exc


def _summary(batch: AuditBatch, rows: Sequence[InputRow]) -> str:
    lines = [
        "AUDYT PO CZYSZCZENIU — NIC NIE ZOSTAŁO ZMIENIONE",
        "=================================================",
        "",
        "Adresy odpowiadające na ICMP są traktowane jako oczekiwane do pozostawienia.",
        "",
    ]
    if batch.warnings:
        lines.append("OSTRZEŻENIA I GRANICE AUDYTU:")
        lines.extend(f"  - {warning}" for warning in batch.warnings)
        lines.append("")
    for row in rows:
        if not row.valid or not row.normalized:
            lines.append(f"LP {row.lp} | {row.raw} | NIEPOPRAWNY_IP")
            continue
        result = batch.results[row.normalized]
        duplicate = f" | DUPLIKAT LP {row.duplicate_of_lp}" if row.duplicate_of_lp else ""
        lines.append(f"LP {row.lp} | {result.ip} | {result.status}{duplicate}")
        lines.append(
            f"  ICMP: {result.ping_status} — {result.ping_detail}"
        )
        if result.exact_objects:
            lines.append(
                "  Dokładne obiekty: "
                + ", ".join(
                    f"{obj.location}/{obj.name}" for obj in result.exact_objects
                )
            )
        if result.containing_objects:
            lines.append(
                "  Szersze obiekty: "
                + ", ".join(
                    f"{obj.location}/{obj.name}" for obj in result.containing_objects
                )
            )
        exact_refs = [
            ref for ref in result.literal_references if ref.relation == "exact"
        ]
        if exact_refs:
            lines.append(f"  Dokładne literały w konfiguracji: {len(exact_refs)}")
        if result.historical_name_references:
            lines.append(
                "  Referencje po starej nazwie: "
                f"{len(result.historical_name_references)}"
            )
        lines.append("")
    lines.extend(_count_lines(batch))
    return "\n".join(lines) + "\n"


def _detailed(batch: AuditBatch, rows: Sequence[InputRow]) -> str:
    first_lp: Dict[str, int] = {}
    lps: Dict[str, List[str]] = {}
    for row in rows:
        if row.normalized:
            first_lp.setdefault(row.normalized, row.lp)
            lps.setdefault(row.normalized, []).append(str(row.lp))
    lines = [
        "AUDYT SZCZEGÓŁOWY PO CZYSZCZENIU — RUNNING CONFIG",
        "==================================================",
        "Skrypt nie wykonał żadnej zmiany i nie wygenerował komend.",
        "",
    ]
    if batch.warnings:
        lines.append("OSTRZEŻENIA I GRANICE AUDYTU:")
        lines.extend(f"  - {warning}" for warning in batch.warnings)
        lines.append("")
    for ip in sorted(first_lp, key=first_lp.get):
        result = batch.results[ip]
        lines.extend(
            [
                f"=== IP {ip} | LP {', '.join(lps[ip])} | {result.status} ===",
                f"ICMP: {result.ping_status} — {result.ping_detail}",
                "",
            ]
        )
        _append_objects(lines, "DOKŁADNE OBIEKTY", result.exact_objects)
        _append_objects(lines, "SZERSZE OBIEKTY ZAWIERAJĄCE IP", result.containing_objects)
        _append_references(lines, "BEZPOŚREDNIE LITERAŁY IP", result.literal_references)
        lines.append("OBIEKTY Z POPRZEDNICH RUNÓW:")
        if result.historical_objects:
            lines.extend(f"  - {item}" for item in result.historical_objects)
        else:
            lines.append("  - brak danych")
        lines.append("")
        _append_references(
            lines,
            "REFERENCJE PO USUNIĘTEJ NAZWIE",
            result.historical_name_references,
        )
    lines.extend(_count_lines(batch))
    return "\n".join(lines) + "\n"


def _append_objects(lines: List[str], heading: str, objects: Sequence[AuditObject]) -> None:
    lines.append(heading + ":")
    if not objects:
        lines.append("  - brak")
        lines.append("")
        return
    for obj in objects:
        lines.append(
            f"  - {obj.location}/{obj.name}: {obj.object_type}={obj.raw_value}"
        )
        lines.append(f"    xpath: {obj.xpath}")
        lines.extend(f"    grupa: {item}" for item in obj.groups)
        lines.extend(f"    polityka: {item}" for item in obj.rules)
        lines.extend(f"    ścieżka: {item}" for item in obj.paths)
        lines.extend(f"    dynamic-group: {item}" for item in obj.dynamic_groups)
        lines.extend(
            f"    polityka-przez-DAG: {item}" for item in obj.dynamic_group_rules
        )
        if not (
            obj.groups
            or obj.rules
            or obj.paths
            or obj.dynamic_groups
            or obj.dynamic_group_rules
        ):
            lines.append("    referencje: brak")
    lines.append("")


def _append_references(
    lines: List[str], heading: str, references: Sequence[AuditReference]
) -> None:
    lines.append(heading + ":")
    if not references:
        lines.append("  - brak")
        lines.append("")
        return
    for ref in references:
        rule = ""
        if ref.rulebase:
            rule = f" | {ref.rulebase}/{ref.policy_type}"
        lines.append(
            f"  - {ref.relation} | {ref.location} | {ref.owner_type} "
            f"{ref.owner_name}{rule} | field={ref.field} | value={ref.value}"
        )
        lines.append(f"    ścieżka: {ref.configuration_path}")
        if ref.detail:
            lines.append(f"    szczegóły: {ref.detail}")
    lines.append("")


def _status_csv(batch: AuditBatch, rows: Sequence[InputRow]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "lp",
            "input",
            "normalized_ip",
            "duplicate_of_lp",
            "ping_status",
            "status",
            "exact_objects",
            "containing_objects",
            "literal_references",
            "historical_objects",
            "historical_name_references",
        ]
    )
    for row in rows:
        if not row.valid or not row.normalized:
            writer.writerow(
                [row.lp, row.raw, "", "", "", "NIEPOPRAWNY_IP", "", "", "", "", ""]
            )
            continue
        result = batch.results[row.normalized]
        writer.writerow(
            [
                row.lp,
                row.raw,
                row.normalized,
                row.duplicate_of_lp or "",
                result.ping_status,
                result.status,
                ";".join(f"{obj.location}/{obj.name}" for obj in result.exact_objects),
                ";".join(
                    f"{obj.location}/{obj.name}" for obj in result.containing_objects
                ),
                ";".join(ref.configuration_path for ref in result.literal_references),
                ";".join(result.historical_objects),
                ";".join(
                    ref.configuration_path
                    for ref in result.historical_name_references
                ),
            ]
        )
    return output.getvalue()


def _ping_report(
    rows: Sequence[InputRow], pings: Mapping[str, PingResult], status: PingStatus
) -> str:
    lines = ["LP | IP | STATUS | SZCZEGÓŁY"]
    for row in rows:
        if row.normalized and row.normalized in pings:
            result = pings[row.normalized]
            if result.status == status:
                lines.append(
                    f"{row.lp} | {row.normalized} | {status.value} | {result.detail}"
                )
    return "\n".join(lines) + "\n"


def _count_lines(batch: AuditBatch) -> List[str]:
    statuses: Dict[str, int] = {}
    for result in batch.results.values():
        statuses[result.status] = statuses.get(result.status, 0) + 1
    lines = ["PODSUMOWANIE:", f"  Unikalnych IP: {len(batch.results)}"]
    lines.extend(f"  {status}: {count}" for status, count in sorted(statuses.items()))
    lines.append(
        "  Kompletność nazw historycznych: "
        + ("TAK" if batch.historical_name_coverage else "NIE — podaj --previous-run")
    )
    return lines


def _rule_text(key: RuleKey) -> str:
    return f"{key.location}/{key.rulebase}/{key.policy_type}/{key.name}"


def _write_text(path: Path, content: str) -> None:
    _atomic_write(path, content.encode("utf-8"))


def _write_json(path: Path, value: Any) -> None:
    _write_text(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
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
