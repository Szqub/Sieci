"""Atomic backups, reports, and run manifest generation."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .models import (
    BatchPlan,
    CandidateComparison,
    ConfigModel,
    InputRow,
    IPMatch,
    OutputError,
    PingResult,
    PingStatus,
    RenderedPlan,
    RuleKey,
    RunMetrics,
    ScopedName,
    __version__,
)
from .planner import dependency_inventories


def create_run_directory(base: Path, now: Optional[datetime] = None) -> Tuple[Path, str]:
    timestamp = (now or datetime.now().astimezone()).astimezone()
    file_stamp = timestamp.strftime("%d%m%y_%H_%M")
    run_name = "run_" + timestamp.strftime("%d%m%y_%H_%M_%S")
    candidate = base / run_name
    suffix = 1
    while candidate.exists():
        candidate = base / f"{run_name}_{suffix:02d}"
        suffix += 1
    try:
        candidate.mkdir(parents=True, exist_ok=False)
        try:
            candidate.chmod(0o700)
        except OSError:
            pass
    except OSError as exc:
        raise OutputError(f"Nie można utworzyć katalogu run: {candidate}") from exc
    return candidate, file_stamp


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _write_text(path: Path, content: str) -> None:
    _atomic_write(path, content.encode("utf-8"))


def _write_json(path: Path, value: Any) -> None:
    _write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _safe_name(value: str, identity: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value).strip(" .")
    cleaned = re.sub(r"\s+", "_", cleaned) or "unnamed"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:10]
    return f"{cleaned[:80]}_{digest}"


def _location_dir(location: str) -> str:
    return _safe_name(location, "location:" + location)


def _backup_entities(
    run_dir: Path,
    file_stamp: str,
    model: ConfigModel,
    rendered: RenderedPlan,
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    def save(
        *,
        entity_type: str,
        identity: str,
        name: str,
        location: str,
        xpath: str,
        xml: str,
        relative_parent: Path,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        safe_identity = _safe_name(name, identity)
        safe_label, digest = safe_identity.rsplit("_", 1)
        filename = f"{safe_label}_{file_stamp}_{digest}.xml"
        relative_path = Path("backups") / relative_parent / filename
        payload = xml.rstrip() + "\n"
        _write_text(run_dir / relative_path, payload)
        record: Dict[str, Any] = {
            "entity_type": entity_type,
            "identity": identity,
            "name": name,
            "location": location,
            "xpath": xpath,
            "file": relative_path.as_posix(),
            "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        }
        if extra:
            record.update(extra)
        entries.append(record)

    for key in sorted(rendered.affected_addresses):
        obj = model.addresses[key]
        identity = f"address|{key.location}|{key.name}"
        save(
            entity_type="address",
            identity=identity,
            name=key.name,
            location=key.location,
            xpath=obj.xpath,
            xml=obj.xml,
            relative_parent=Path("objects") / _location_dir(key.location),
            extra={"object_type": obj.object_type, "raw_value": obj.raw_value},
        )

    for key in sorted(rendered.affected_groups):
        group = model.static_groups[key]
        identity = f"group|{key.location}|{key.name}"
        save(
            entity_type="static-group",
            identity=identity,
            name=key.name,
            location=key.location,
            xpath=group.xpath,
            xml=group.xml,
            relative_parent=Path("groups") / _location_dir(key.location),
            extra={"original_members": list(group.members)},
        )

    for key in sorted(rendered.affected_rules):
        rule = model.rules[key]
        identity = (
            f"policy|{key.location}|{key.rulebase}|{key.policy_type}|{key.name}"
        )
        save(
            entity_type="policy",
            identity=identity,
            name=key.name,
            location=key.location,
            xpath=rule.xpath,
            xml=rule.xml,
            relative_parent=(
                Path("policies")
                / _location_dir(key.location)
                / key.rulebase
                / key.policy_type
            ),
            extra={
                "rulebase": key.rulebase,
                "policy_type": key.policy_type,
                "uuid": rule.uuid,
                "order_index": rule.order_index,
                "previous_rule": rule.previous_rule,
                "next_rule": rule.next_rule,
                "original_source": list(rule.source_members),
                "original_destination": list(rule.destination_members),
            },
        )
    return entries


def write_run_artifacts(
    *,
    run_dir: Path,
    file_stamp: str,
    model: ConfigModel,
    plan: BatchPlan,
    rendered: RenderedPlan,
    rows: Sequence[InputRow],
    pings: Mapping[str, PingResult],
    matches: Mapping[str, IPMatch],
    comparison: CandidateComparison,
    host: str,
    username: str,
    system_info: Mapping[str, str],
    sanitized_arguments: Mapping[str, Any],
    metrics: RunMetrics,
    started_utc: datetime,
    publication_blockers: Sequence[str] = (),
) -> Path:
    """Write every prerequisite first; publish applicable commands absolutely last."""

    try:
        backup_manifest = _backup_entities(run_dir, file_stamp, model, rendered)
        normalized_blockers = tuple(
            sorted({item.strip() for item in publication_blockers if item.strip()})
        )
        global_warnings = tuple(
            sorted(set(plan.warnings) | set(rendered.rollback_warnings))
        )

        command_text = "\n".join(record.command for record in rendered.commands)
        if command_text:
            command_text += "\n"
        rollback_text = "\n".join(rendered.rollback_commands)
        if rollback_text:
            rollback_text += "\n"

        candidate_control_passed = (
            comparison.automated_check_performed
            and comparison.relevant_different is False
        ) or (
            not comparison.automated_check_performed
            and comparison.administrator_confirmed
        )
        commands_published = candidate_control_passed and not normalized_blockers
        runtime_blocker_prefixes = (
            "RUNTIME_DAG_",
            "FQDN_",
            "IP_EDL_",
            "REGION_",
            "UNMODELED_",
        )
        if (
            comparison.automated_check_performed
            and comparison.relevant_different is True
        ):
            draft_reason = "candidate_drift"
        elif not candidate_control_passed:
            draft_reason = "candidate_confirmation"
        elif any(
            blocker.startswith(runtime_blocker_prefixes)
            for blocker in normalized_blockers
        ):
            draft_reason = "runtime_dependencies"
        else:
            draft_reason = "incomplete_input"
        draft_command_name = f"draft_commands_BLOCKED_{draft_reason}.txt"
        draft_rollback_name = f"draft_rollback_BLOCKED_{draft_reason}.txt"
        if not commands_published:
            _write_text(
                run_dir / draft_command_name,
                command_text,
            )
            _write_text(
                run_dir / draft_rollback_name,
                rollback_text,
            )
        if rendered.rollback_warnings:
            _write_text(
                run_dir / "rollback_manual_restore_required.txt",
                _rollback_warning_report(rendered.rollback_warnings),
            )
        _write_text(
            run_dir / "apply_readme.txt",
            _apply_readme(
                comparison=comparison,
                has_commands=bool(rendered.commands),
                commands_published=commands_published,
                publication_blockers=normalized_blockers,
                warnings=global_warnings,
                rollback_warnings=rendered.rollback_warnings,
                draft_command_name=draft_command_name,
                draft_rollback_name=draft_rollback_name,
            ),
        )
        _write_text(
            run_dir / "icmp_responded.txt",
            _ping_report(rows, pings, PingStatus.REPLIED),
        )
        _write_text(
            run_dir / "icmp_no_response.txt",
            _ping_report(rows, pings, PingStatus.NO_REPLY),
        )
        _write_text(
            run_dir / "icmp_errors.txt",
            _ping_report(rows, pings, PingStatus.ERROR),
        )
        _write_text(
            run_dir / "raport_krotki.txt",
            _short_report(
                model,
                rows,
                pings,
                matches,
                plan,
                rendered,
                normalized_blockers,
                global_warnings,
            ),
        )
        _write_text(
            run_dir / "raport_szczegolowy.txt",
            _detailed_report(
                model,
                rows,
                pings,
                matches,
                plan,
                rendered,
                normalized_blockers,
                global_warnings,
            ),
        )
        _write_text(
            run_dir / "input_status.csv",
            _status_csv(rows, pings, matches, plan, rendered),
        )
        _write_json(
            run_dir / "candidate_comparison.json",
            asdict(comparison),
        )
        _write_json(
            run_dir / "manual_review.json",
            _manual_review(
                rows,
                pings,
                matches,
                plan,
                comparison,
                normalized_blockers,
                global_warnings,
                rendered.rollback_warnings,
            ),
        )

        finished_utc = datetime.now(timezone.utc)
        manifest = {
            "script": "panorama_cleanup_planner.py",
            "script_version": __version__,
            "started_utc": started_utc.astimezone(timezone.utc).isoformat(),
            "finished_utc": finished_utc.isoformat(),
            "panorama_host": host,
            "panorama_username": username,
            "panorama_system": dict(system_info),
            "coverage": "panorama-running-config-visible-to-api-account",
            "device_entry_name": model.device_entry_name,
            "device_groups": sorted(model.parents),
            "ancestor_objects_take_precedence": model.ancestor_objects_take_precedence,
            "arguments": dict(sanitized_arguments),
            "candidate_comparison": asdict(comparison),
            "metrics": asdict(metrics),
            "backups": backup_manifest,
            "commands": [asdict(command) for command in rendered.commands],
            "rollback_command_count": len(rendered.rollback_commands),
            "rollback_cli_complete": not rendered.rollback_warnings,
            "rollback_warnings": sorted(set(rendered.rollback_warnings)),
            "blocked_ips": {
                ip: [asdict(reason) for reason in reasons]
                for ip, reasons in sorted(plan.blocked_ips.items())
            },
            "icmp_errors": {
                ip: result.detail
                for ip, result in sorted(pings.items())
                if result.status == PingStatus.ERROR
            },
            "warnings": list(global_warnings),
            "publication_blockers": list(normalized_blockers),
            "safety": {
                "changes_executed": False,
                "commit_command_generated": False,
                "candidate_automated_check_performed": comparison.automated_check_performed,
                "candidate_administrator_confirmed": comparison.administrator_confirmed,
                "commands_file_expected_on_success": commands_published,
                "commands_publication_proof": (
                    "commands.txt exists; it is the final atomic write"
                    if commands_published
                    else "applicable commands intentionally withheld"
                ),
                "planning_snapshot": "running",
                "dependency_scope": sanitized_arguments.get("dependency_scope"),
                "runtime_membership_audit_performed": sanitized_arguments.get(
                    "runtime_membership_audit_performed", False
                ),
                "administrator_confirmed_dependency_scope": sanitized_arguments.get(
                    "administrator_confirmed_dependency_scope", False
                ),
                "candidate_diff_requires_operator_review": comparison.different,
            },
        }
        _write_json(run_dir / "manifest.json", manifest)

        # Applicable CLI is exposed only after every backup, report, review file,
        # and the manifest have been durably written. Nothing may write after it.
        if commands_published:
            _write_text(run_dir / "rollback_commands.txt", rollback_text)
            _write_text(run_dir / "commands.txt", command_text)
        return run_dir
    except OutputError:
        # A partial run directory is intentionally retained for diagnostics.
        # commands.txt is the last write, so an earlier failure cannot publish it.
        raise
    except OSError as exc:
        raise OutputError(f"Błąd tworzenia artefaktów w {run_dir}") from exc


def _ping_report(
    rows: Sequence[InputRow], pings: Mapping[str, PingResult], status: PingStatus
) -> str:
    lines = ["LP | IP | STATUS | SZCZEGÓŁY"]
    for row in rows:
        if row.normalized and pings.get(row.normalized) and pings[row.normalized].status == status:
            result = pings[row.normalized]
            lines.append(
                f"{row.lp} | {row.normalized} | {status.value} | {result.detail}"
            )
    return "\n".join(lines) + "\n"


def _commands_by_ip(rendered: RenderedPlan) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    for record in rendered.commands:
        for ip in record.causes:
            result.setdefault(ip, []).append(f"{record.command_id}: {record.command}")
    return result


def _status_for_ip(
    ip: str,
    pings: Mapping[str, PingResult],
    matches: Mapping[str, IPMatch],
    plan: BatchPlan,
    commands_by_ip: Mapping[str, List[str]],
) -> str:
    ping = pings[ip]
    if ping.status == PingStatus.REPLIED:
        return "POMINIĘTO_ICMP_ODPOWIADA"
    if ping.status == PingStatus.ERROR:
        return "ZABLOKOWANO_BŁĄD_ICMP"
    if ip in plan.blocked_ips:
        return "ZABLOKOWANO_REVIEW"
    if commands_by_ip.get(ip):
        return "ZAPLANOWANO"
    if matches[ip].exact_objects:
        return "BRAK_ZMIAN"
    return "OBIEKT_NIE_ISTNIEJE"


def _short_report(
    model: ConfigModel,
    rows: Sequence[InputRow],
    pings: Mapping[str, PingResult],
    matches: Mapping[str, IPMatch],
    plan: BatchPlan,
    rendered: RenderedPlan,
    publication_blockers: Sequence[str],
    global_warnings: Sequence[str],
) -> str:
    commands_by_ip = _commands_by_ip(rendered)
    inventory_keys = {
        key for match in matches.values() for key in match.exact_objects
    }
    inventories = dependency_inventories(model, inventory_keys)
    lines = [
        "PLANOWANE USUNIĘCIA — KOMEND NIE WYKONANO",
        "Każdy LP odpowiada pozycji z ip.txt; duplikaty zachowano raportowo.",
        "",
    ]
    if publication_blockers:
        lines.append("BLOKADY PUBLIKACJI commands.txt:")
        lines.extend(f"  - {item}" for item in publication_blockers)
        lines.append("")
    if global_warnings:
        lines.append("OSTRZEŻENIA GLOBALNE:")
        lines.extend(f"  - {item}" for item in global_warnings)
        lines.append("")
    records_by_id = {record.command_id: record for record in rendered.commands}
    for row in rows:
        if not row.valid or not row.normalized:
            lines.append(f"LP {row.lp} | {row.raw} | NIEPOPRAWNY_IP")
            continue
        ip = row.normalized
        status = _status_for_ip(ip, pings, matches, plan, commands_by_ip)
        duplicate = f" | DUPLIKAT LP {row.duplicate_of_lp}" if row.duplicate_of_lp else ""
        lines.append(f"LP {row.lp} | {ip} | {status}{duplicate}")
        if not matches[ip].exact_objects:
            lines.append("  Obiekt nie istnieje jako dokładny host address object.")
        for key in matches[ip].exact_objects:
            lines.append(f"  Obiekt: {key.name} [{key.location}]")
            groups, rules, _ = inventories[key]
            lines.extend(
                f"  Znaleziono w grupie: {group.location}/{group.name}"
                for group in sorted(groups)
            )
            lines.extend(
                "  Znaleziono w polityce: "
                f"{rule.location}/{rule.rulebase}/{rule.policy_type}/{rule.name}"
                for rule in sorted(rules)
            )
        for command_line in commands_by_ip.get(ip, []):
            command_id = command_line.split(":", 1)[0]
            record = records_by_id[command_id]
            label = {
                "policy": "Polityka",
                "group": "Grupa",
                "address": "Obiekt",
            }.get(record.entity_type, record.entity_type)
            lines.append(f"  {label}: {record.entity_key} ({record.command_id})")
        if ip in plan.blocked_ips:
            for reason in plan.blocked_ips[ip]:
                lines.append(f"  BLOKADA {reason.code}: {reason.message}")
        lines.append("")
    unique_valid = {row.normalized for row in rows if row.normalized}
    planned = sum(1 for ip in unique_valid if commands_by_ip.get(ip))
    ping_error_count = sum(
        pings[ip].status == PingStatus.ERROR for ip in unique_valid
    )
    lines.extend(
        [
            f"Pozycji wejściowych: {len(rows)}",
            f"Unikalnych poprawnych IP: {len(unique_valid)}",
            f"IP z planowanymi komendami: {planned}",
            f"Zablokowanych przez zależności planu: {len(plan.blocked_ips)}",
            f"Pominiętych przez trwały błąd ICMP: {ping_error_count}",
            f"Wygenerowanych komend: {len(rendered.commands)}",
        ]
    )
    return "\n".join(lines) + "\n"


def _detailed_report(
    model: ConfigModel,
    rows: Sequence[InputRow],
    pings: Mapping[str, PingResult],
    matches: Mapping[str, IPMatch],
    plan: BatchPlan,
    rendered: RenderedPlan,
    publication_blockers: Sequence[str],
    global_warnings: Sequence[str],
) -> str:
    commands_by_ip = _commands_by_ip(rendered)
    inventory_keys = {
        key
        for match in matches.values()
        for key in match.exact_objects + match.containing_objects
    }
    inventories = dependency_inventories(model, inventory_keys)
    first_rows: Dict[str, int] = {}
    for row in rows:
        if row.normalized and row.normalized not in first_rows:
            first_rows[row.normalized] = row.lp
    lines = [
        "RAPORT SZCZEGÓŁOWY — PLAN; NIC NIE ZOSTAŁO WYKONANE NA PANORAMIE",
        "Zakres: konfiguracja running Panoramy widoczna dla konta API.",
        "Brak odpowiedzi ICMP nie jest dowodem wyłączenia hosta.",
        "",
    ]
    if publication_blockers:
        lines.append("BLOKADY PUBLIKACJI commands.txt:")
        lines.extend(f"  - {item}" for item in publication_blockers)
        lines.append("")
    if global_warnings:
        lines.append("OSTRZEŻENIA GLOBALNE:")
        lines.extend(f"  - {item}" for item in global_warnings)
        lines.append("")
    for ip, first_lp in sorted(first_rows.items(), key=lambda item: item[1]):
        status = _status_for_ip(ip, pings, matches, plan, commands_by_ip)
        related_lps = [str(row.lp) for row in rows if row.normalized == ip]
        lines.extend(
            [
                f"=== IP {ip} | LP {', '.join(related_lps)} | {status} ===",
                f"ICMP: {pings[ip].status.value} — {pings[ip].detail}",
            ]
        )
        match = matches[ip]
        if not match.exact_objects:
            lines.append("Dokładny address object: NIE ISTNIEJE")
        for key in match.exact_objects:
            obj = model.addresses[key]
            lines.append(
                f"Obiekt: {key.name} | location={key.location} | {obj.object_type}={obj.raw_value}"
            )
            groups, rules, paths = inventories[key]
            lines.append("Grupy bezpośrednie/pośrednie:")
            if groups:
                lines.extend(f"  - {item.location}/{item.name}" for item in sorted(groups))
            else:
                lines.append("  - brak")
            lines.append("Polityki bezpośrednie/pośrednie:")
            if rules:
                lines.extend(
                    f"  - {item.location}/{item.rulebase}/{item.policy_type}/{item.name}"
                    for item in sorted(rules)
                )
            else:
                lines.append("  - brak")
            lines.append("Ścieżki konfiguracji:")
            if paths:
                lines.extend(f"  - {path}" for path in paths)
            else:
                lines.append("  - brak")
        if match.containing_objects:
            lines.append("Obiekty tylko zawierające IP — NIE SĄ USUWANE; MANUAL REVIEW:")
            for key in match.containing_objects:
                obj = model.addresses[key]
                lines.append(
                    f"  - {key.location}/{key.name}: {obj.object_type}={obj.raw_value}"
                )
                groups, rules, paths = inventories[key]
                if groups:
                    lines.extend(
                        f"      grupa: {item.location}/{item.name}"
                        for item in sorted(groups)
                    )
                if rules:
                    lines.extend(
                        "      polityka: "
                        f"{item.location}/{item.rulebase}/{item.policy_type}/{item.name}"
                        for item in sorted(rules)
                    )
                if paths:
                    lines.extend(f"      ścieżka: {path}" for path in paths)
        exact_keys = set(match.exact_objects)
        dynamic_impacts = [
            (group, objects)
            for group, objects in plan.dynamic_group_impacts.items()
            if objects.intersection(exact_keys)
        ]
        if dynamic_impacts:
            lines.append("Wpływ tagów na dynamic address groups:")
            for group, _ in dynamic_impacts:
                lines.append(f"  - {group.location}/{group.name}")
        if ip in plan.blocked_ips:
            lines.append("Blokady/manual review:")
            for reason in plan.blocked_ips[ip]:
                suffix = f" | {reason.path}" if reason.path else ""
                lines.append(f"  - {reason.code}: {reason.message}{suffix}")
        lines.append("Komendy:")
        if commands_by_ip.get(ip):
            lines.extend(f"  > {command}" for command in commands_by_ip[ip])
        else:
            lines.append("  > brak")
        lines.append("")
    return "\n".join(lines) + "\n"

def _status_csv(
    rows: Sequence[InputRow],
    pings: Mapping[str, PingResult],
    matches: Mapping[str, IPMatch],
    plan: BatchPlan,
    rendered: RenderedPlan,
) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "lp",
            "input",
            "normalized_ip",
            "duplicate_of_lp",
            "ping_status",
            "ping_detail",
            "result",
            "exact_objects",
            "containing_objects_not_deleted",
            "command_ids",
        ]
    )
    commands_by_ip = _commands_by_ip(rendered)
    ids_by_ip: Dict[str, List[str]] = {}
    for record in rendered.commands:
        for ip in record.causes:
            ids_by_ip.setdefault(ip, []).append(record.command_id)
    for row in rows:
        if not row.valid or not row.normalized:
            writer.writerow(
                [row.lp, row.raw, "", "", "", "", "NIEPOPRAWNY_IP", "", "", ""]
            )
            continue
        ip = row.normalized
        writer.writerow(
            [
                row.lp,
                row.raw,
                ip,
                row.duplicate_of_lp or "",
                pings[ip].status.value,
                pings[ip].detail,
                _status_for_ip(ip, pings, matches, plan, commands_by_ip),
                ";".join(f"{key.location}/{key.name}" for key in matches[ip].exact_objects),
                ";".join(
                    f"{key.location}/{key.name}" for key in matches[ip].containing_objects
                ),
                ";".join(ids_by_ip.get(ip, [])),
            ]
        )
    return output.getvalue()


def _manual_review(
    rows: Sequence[InputRow],
    pings: Mapping[str, PingResult],
    matches: Mapping[str, IPMatch],
    plan: BatchPlan,
    comparison: CandidateComparison,
    publication_blockers: Sequence[str],
    global_warnings: Sequence[str],
    rollback_warnings: Sequence[str],
) -> Dict[str, Any]:
    invalid = [
        {"lp": row.lp, "value": row.raw, "error": row.error}
        for row in rows
        if not row.valid
    ]
    ping_errors = {
        ip: result.detail for ip, result in pings.items() if result.status == PingStatus.ERROR
    }
    return {
        "candidate_drift": asdict(comparison),
        "publication_blockers": list(publication_blockers),
        "warnings": list(global_warnings),
        "rollback_warnings": sorted(set(rollback_warnings)),
        "invalid_input": invalid,
        "ping_errors": ping_errors,
        "blocked_ips": {
            ip: [asdict(reason) for reason in reasons]
            for ip, reasons in sorted(plan.blocked_ips.items())
        },
        "containing_objects_not_deleted": {
            ip: [f"{key.location}/{key.name}" for key in match.containing_objects]
            for ip, match in sorted(matches.items())
            if match.containing_objects
        },
        "dynamic_group_tag_impacts": {
            f"{group.location}/{group.name}": [
                f"{key.location}/{key.name}" for key in sorted(objects)
            ]
            for group, objects in sorted(plan.dynamic_group_impacts.items())
        },
    }


def _rollback_warning_report(warnings: Sequence[str]) -> str:
    lines = [
        "ROLLBACK CLI — WYMAGANE RĘCZNE ODTWORZENIE WYBRANYCH PÓL",
        "========================================================",
        "",
        "Nie wykonuj rollback_commands.txt jako jedynego źródła odtworzenia.",
        "Poniższe pola pominięto, ponieważ nie można ich bezpiecznie wkleić do CLI.",
        "Pełne backupy XML w backups/ zachowują wartości do kontrolowanego",
        "load config partial/XML API.",
        "",
    ]
    lines.extend(f"- {item}" for item in sorted(set(warnings)))
    return "\n".join(lines) + "\n"


def _apply_readme(
    *,
    comparison: CandidateComparison,
    has_commands: bool,
    commands_published: bool,
    publication_blockers: Sequence[str],
    warnings: Sequence[str],
    rollback_warnings: Sequence[str],
    draft_command_name: str,
    draft_rollback_name: str,
) -> str:
    if not comparison.automated_check_performed and comparison.administrator_confirmed:
        drift = (
            "Automatyczne porównanie running/candidate było wyłączone. "
            "Administrator jawnie potwierdził wcześniejsze sprawdzenie diffu "
            "w Panoramie i zgodę na kontynuowanie. Oba snapshoty pobrano, ale "
            "plan policzono wyłącznie z running.\n"
        )
    elif not comparison.automated_check_performed:
        drift = (
            "BLOKADA KRYTYCZNA: nie wykonano automatycznego porównania ani nie "
            "zapisano potwierdzenia administratora.\n"
        )
    elif comparison.relevant_different is None:
        drift = (
            "BLOKADA KRYTYCZNA: wynik automatycznego porównania jest niekompletny.\n"
        )
    elif comparison.relevant_different:
        drift = (
            "BLOKADA KRYTYCZNA: running i candidate różnią się w obiektach, "
            "device groupach lub rulebase. Plan policzono z running, ale nie "
            "opublikowano stosowalnego commands.txt, ponieważ CLI zmienia candidate. "
            "Uzgodnij candidate i uruchom planner ponownie.\n"
        )
    elif comparison.different:
        drift = (
            "UWAGA: running i candidate różnią się poza analizowanym zakresem. "
            "Przed użyciem jakiegokolwiek planu nadal sprawdź diff.\n"
        )
    else:
        drift = "Running i candidate były zgodne w chwili pobierania snapshotów.\n"
    blockers_note = ""
    if publication_blockers:
        blockers_note = "BLOKADY PUBLIKACJI commands.txt:\n" + "".join(
            f"  - {item}\n" for item in publication_blockers
        )
    warnings_note = ""
    if warnings:
        warnings_note = "OSTRZEŻENIA WYMAGAJĄCE REVIEW:\n" + "".join(
            f"  - {item}\n" for item in sorted(set(warnings))
        )
    rollback_note = ""
    if rollback_warnings:
        rollback_note = (
            "UWAGA: pomocniczy rollback CLI jest niepełny dla pól ze znakami "
            "sterującymi. Szczegóły zapisano w "
            "rollback_manual_restore_required.txt. Dla wskazanych encji użyj "
            "pełnego XML z backups/ przez kontrolowany load config partial/XML API.\n"
        )
    if has_commands and commands_published:
        command_note = "Plik commands.txt zawiera plan zmian.\n"
    elif has_commands:
        command_note = (
            f"Plan zapisano wyłącznie jako {draft_command_name}; nie wolno go "
            "wklejać.\n"
        )
    else:
        command_note = "Brak bezpiecznych zmian do wklejenia.\n"
    cli_steps = (
        "W CLI Panoramy wykonaj:\n\n"
        "set cli scripting-mode on\n"
        "configure\n\n"
        "Wklej zawartość commands.txt, a następnie wykonaj:\n\n"
        "validate full\n"
        "show config diff\n\n"
        if commands_published
        else (
            "Nie stosuj draftu. Usuń wszystkie wskazane blokady i uruchom "
            "planner ponownie.\n\n"
        )
    )
    rollback_name = (
        "rollback_commands.txt"
        if commands_published
        else draft_rollback_name
    )
    return (
        "INSTRUKCJA DLA ADMINISTRATORA PANORAMY\n"
        "======================================\n\n"
        "Skrypt NIE wykonał żadnej zmiany i NIE wygenerował commit.\n"
        + drift
        + blockers_note
        + warnings_note
        + rollback_note
        + command_note
        + "Backupy XML każdej dotkniętej encji są w katalogu backups/.\n\n"
        "Bezpośrednio przed zastosowaniem uruchom planner ponownie i porównaj manifest.\n"
        + cli_steps
        + "Dopiero administrator ręcznie decyduje o commit.\n"
        + rollback_name
        + " jest pomocniczym planem odwrotnym dla candidate; "
        "przed użyciem również wykonaj backup, validate full i show config diff. "
        "Odtwarzane reguły są przesuwane na zapisaną pozycję, ale atrybut UUID "
        "może wymagać odtworzenia z autorytatywnego backupu XML przez kontrolowany "
        "load partial/XML API. Pełne pliki XML w backups/ są źródłem rollbacku.\n"
    )
