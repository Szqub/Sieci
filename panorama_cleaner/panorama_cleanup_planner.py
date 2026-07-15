#!/usr/bin/env python3
"""Generate a safe, reviewable Panorama address cleanup plan from running XML."""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from panorama_cleanup.artifacts import create_run_directory, write_run_artifacts
from panorama_cleanup.hitcounts import collect_rule_hit_counts
from panorama_cleanup.models import (
    ConfigModel,
    InputError,
    OutputError,
    ParseError,
    PingStatus,
    RunMetrics,
    SnapshotError,
    TransportError,
    UnsafePlanError,
)
from panorama_cleanup.panos import (
    compare_configs,
    is_supported_address_literal,
    match_ip_objects,
    parse_config,
    resolve_occurrence,
)
from panorama_cleanup.planner import plan_cleanup
from panorama_cleanup.render import render_plan
from panorama_cleanup.runtime import (
    PanoramaXMLAPI,
    load_host_settings,
    load_ip_rows,
    obtain_password,
    ping_many,
    unique_valid_ips,
    validate_ca_bundle,
)

EXPECTED_PAN_OS = "10.2.16-h4"
PROJECT_DIR = Path(__file__).resolve().parent


def config_completeness_findings(
    model: ConfigModel, running_config: Any
) -> Tuple[List[str], List[str]]:
    """Report runtime namespaces without treating unrelated entries as dependencies."""

    warnings: List[str] = []
    blockers: List[str] = []
    if model.dynamic_groups:
        warnings.append(
            f"RUNTIME_DAG_PRESENT: snapshot zawiera {len(model.dynamic_groups)} "
            "dynamic address group. Nie jest to globalna zależność usuwanego "
            "obiektu; planner osobno blokuje tylko targety, których tagi mogą "
            "pasować do filtra DAG. Operacyjne rejestracje IP→tag nie są częścią "
            "running/candidate."
        )

    fqdn_count = sum(obj.object_type == "fqdn" for obj in model.addresses.values())
    if fqdn_count:
        warnings.append(
            f"FQDN_PRESENT: snapshot zawiera {fqdn_count} obiektów FQDN. "
            "Nie są bezpośrednimi referencjami do usuwanych address objects i "
            "nie blokują globalnie planu; ich bieżących rozwiązań DNS nie można "
            "potwierdzić z running config."
        )

    ip_edl_count = sum(
        entry.find("./type/ip") is not None
        for entry in running_config.findall(".//external-list/entry")
    )
    if ip_edl_count:
        warnings.append(
            f"IP_EDL_PRESENT: snapshot zawiera {ip_edl_count} IP External "
            "Dynamic List. Ich runtime contents nie są zawarte w "
            "running/candidate, ale nie są referencją do usuwanej definicji "
            "address object i nie blokują globalnie planu."
        )

    region_count = len(running_config.findall(".//region/entry"))
    if region_count:
        warnings.append(
            f"REGION_PRESENT: snapshot zawiera {region_count} custom region; "
            "planner nie rozwija regionów do IP, ale region nie jest referencją "
            "do usuwanej definicji address object i nie blokuje globalnie planu."
        )

    unresolved_values = {
        ref.referenced_name
        for refs in list(model.group_references.values())
        + list(model.rule_references.values())
        for ref in refs
        if ref.resolved_kind == "unresolved"
        and not is_supported_address_literal(ref.referenced_name)
    }
    unresolved_values.update(
        occurrence.value
        for occurrence in model.unknown_occurrences
        if resolve_occurrence(model, occurrence)[0] == "unresolved"
        and not is_supported_address_literal(occurrence.value)
    )
    if unresolved_values:
        sample = ", ".join(
            value.encode("unicode_escape").decode("ascii")
            for value in sorted(unresolved_values)[:10]
        )
        warnings.append(
            f"UNMODELED_ADDRESS_REFERENCE_PRESENT: wykryto "
            f"{len(unresolved_values)} nierozwiązanych nazw w polach adresowych "
            f"(przykłady: {sample}). Niezwiązane nazwy nie blokują całego batcha; "
            "dotknięte grupy i reguły są nadal blokowane targetowo przez planner."
        )
    return warnings, blockers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Po ręcznym potwierdzeniu diffu pobiera running i candidate, analizuje "
            "running oraz generuje backupy, raporty i komendy CLI. Nie wykonuje "
            "zmian ani commit."
        )
    )
    parser.add_argument(
        "--host-file",
        default=str(PROJECT_DIR / "panorama_host.txt"),
        help=(
            "Plik host=..., username=... i opcjonalnie ssl=yes/no "
            "(domyślnie panorama_host.txt obok skryptu)."
        ),
    )
    parser.add_argument(
        "--ip-file",
        default=str(PROJECT_DIR / "ip.txt"),
        help="Plik z IPv4/IPv6 (domyślnie ip.txt obok skryptu).",
    )
    parser.add_argument(
        "--password-env",
        default="PANORAMA_PASSWORD",
        help=(
            "Nazwa zmiennej środowiskowej z hasłem; przy braku hasło jest pytane "
            "przez getpass (domyślnie PANORAMA_PASSWORD)."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_DIR),
        help=(
            "Katalog nadrzędny dla run_DDMMYY_HH_MM_SS "
            "(domyślnie katalog skryptu)."
        ),
    )
    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Jawnie pomija ochronny test ICMP dla wszystkich adresów.",
    )
    parser.add_argument("---no-ping", dest="no_ping", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--ping-workers", type=int, default=64)
    parser.add_argument("--ping-timeout-ms", type=int, default=1000)
    parser.add_argument(
        "--ping-error-retries",
        type=int,
        default=2,
        help=(
            "Liczba automatycznych ponowień wyłącznie dla lokalnego błędu "
            "wykonania ping (domyślnie 2, zakres 0..5)."
        ),
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--ca-bundle",
        help="Ścieżka do zaufanego CA bundle dla certyfikatu Panoramy.",
    )
    tls.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Zgodnościowy override wyłączający weryfikację TLS; preferowane "
            "jest ssl=no w panorama_host.txt (niezalecane)."
        ),
    )
    parser.add_argument(
        "--nat-translation",
        choices=("block", "delete-rule"),
        default="delete-rule",
        help=(
            "Dla dokładnych referencji w polach translacji NAT: delete-rule "
            "(domyślnie usuwa regułę, ale zachowuje ją, gdy wystarczy bezpiecznie "
            "oczyścić niepustą grupę) albo block, aby wymusić manual review."
        ),
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    started_perf = time.perf_counter()
    started_utc = datetime.now(timezone.utc)
    metrics = RunMetrics()
    client: Optional[PanoramaXMLAPI] = None
    password = ""

    try:
        ca_bundle = validate_ca_bundle(args.ca_bundle)
        host_settings = load_host_settings(Path(args.host_file))
        if not host_settings.verify_ssl and ca_bundle:
            raise InputError(
                "ssl=no w panorama_host.txt jest sprzeczne z --ca-bundle. "
                "Ustaw ssl=yes, aby użyć wskazanego CA."
            )
        ssl_verification_disabled = args.insecure or not host_settings.verify_ssl
        verify: Any = False if ssl_verification_disabled else (ca_bundle or True)
        rows = load_ip_rows(Path(args.ip_file))
        valid_ips = unique_valid_ips(rows)
        if not valid_ips:
            raise InputError("Brak poprawnych adresów IP do analizy.")
        metrics.input_row_count = len(rows)
        metrics.unique_ip_count = len(valid_ips)
        print(f"Załadowano {len(rows)} pozycji, {len(valid_ips)} unikalnych poprawnych IP.")
        print("Uruchamianie ochronnego ICMP..." if not args.no_ping else "ICMP pominięty jawnie (--no-ping).")
        phase = time.perf_counter()
        pings = ping_many(
            valid_ips,
            bypass=args.no_ping,
            workers=args.ping_workers,
            timeout_ms=args.ping_timeout_ms,
            error_retries=args.ping_error_retries,
            sensitive_environment_names=(args.password_env,),
        )
        metrics.ping_seconds = time.perf_counter() - phase
        eligible_ips = [
            ip
            for ip in valid_ips
            if pings[ip].status in {PingStatus.NO_REPLY, PingStatus.BYPASSED}
        ]
        print(
            f"ICMP: odpowiedziało {sum(p.status == PingStatus.REPLIED for p in pings.values())}, "
            f"brak odpowiedzi {sum(p.status == PingStatus.NO_REPLY for p in pings.values())}, "
            f"błędy {sum(p.status == PingStatus.ERROR for p in pings.values())}."
        )

        has_invalid = any(not row.valid for row in rows)
        has_ping_error = any(
            result.status == PingStatus.ERROR for result in pings.values()
        )
        ping_error_count = sum(
            result.status == PingStatus.ERROR for result in pings.values()
        )
        publication_blockers = []
        icmp_warnings = []
        if has_invalid:
            invalid_count = sum(not row.valid for row in rows)
            publication_blockers.append(
                f"Niepoprawne pozycje w ip.txt: {invalid_count}; plan dotyczyłby "
                "tylko części wejścia. Popraw plik i uruchom planner ponownie."
            )
        if has_ping_error:
            icmp_warnings.append(
                f"Błąd wykonania ICMP pozostał dla {ping_error_count} IP po "
                f"maksymalnie {args.ping_error_retries + 1} próbach. Te IP "
                "pominięto i oznaczono ZABLOKOWANO_BŁĄD_ICMP; commands.txt "
                "obejmuje wyłącznie pozostałe, poprawnie sprawdzone IP."
            )
            print(
                "UWAGA: trwałe błędy ICMP dotyczą tylko wskazanych IP. "
                "Zostaną one pominięte, a commands.txt może zostać opublikowany "
                "dla pozostałego bezpiecznego podzbioru.",
                file=sys.stderr,
            )

        password = obtain_password(args.password_env)
        if ssl_verification_disabled:
            print(
                "UWAGA: HTTPS pozostaje włączone, ale weryfikacja certyfikatu "
                "TLS została wyłączona.",
                file=sys.stderr,
            )

        print(f"Pobieranie running i candidate z Panoramy {host_settings.host}...")
        phase = time.perf_counter()
        client = PanoramaXMLAPI(
            host_settings.host,
            host_settings.username,
            verify=verify,
        )
        client.authenticate(password)
        # Do not retain the password after key generation.
        password = ""
        running_config = client.fetch_config("show")  # running/active
        candidate_config = client.fetch_config("get")  # candidate
        metrics.remote_snapshot_command_count = client.snapshot_call_count
        system_info = {
            "declared_target_version": EXPECTED_PAN_OS,
            "config_version": running_config.get("version", "unknown"),
            "live_system_info_queried": "no",
        }
        metrics.snapshot_seconds = time.perf_counter() - phase

        comparison = compare_configs(running_config, candidate_config)
        if comparison.relevant_different:
            print(
                "INFORMACJA: running i candidate różnią się w analizowanym "
                "zakresie. Plan nadal powstaje z running; szczegóły zapisano "
                "w candidate_comparison.json.",
                file=sys.stderr,
            )
        elif comparison.different:
            print(
                "INFORMACJA: running i candidate różnią się poza analizowanym "
                "zakresem. Nie blokuje to publikacji planu.",
                file=sys.stderr,
            )
        else:
            print("Running i candidate są semantycznie zgodne.")

        phase = time.perf_counter()
        model = parse_config(running_config)
        model.warnings.extend(icmp_warnings)
        metrics.parse_seconds = time.perf_counter() - phase
        metrics.discovered_object_count = len(model.addresses)
        if running_config.get("version") and not running_config.get("version", "").startswith("10.2"):
            model.warnings.append(
                f"Skrypt zaprojektowano dla PAN-OS {EXPECTED_PAN_OS}, a config deklaruje "
                f"wersję {running_config.get('version')}; składnię należy zweryfikować."
            )
        completeness_warnings, completeness_blockers = (
            config_completeness_findings(model, running_config)
        )
        model.warnings.extend(
            warning
            for warning in completeness_warnings
            if warning not in model.warnings
        )
        publication_blockers.extend(completeness_blockers)
        if completeness_blockers:
            print(
                "BLOKADA: runtime/unmodeled address namespaces uniemożliwiają "
                "kompletny spis zależności z samych snapshotów; powstanie draft.",
                file=sys.stderr,
            )

        matches = match_ip_objects(model, valid_ips)
        phase = time.perf_counter()
        plan = plan_cleanup(
            model,
            matches,
            eligible_ips,
            nat_translation_action=args.nat_translation,
        )
        metrics.planning_seconds = time.perf_counter() - phase

        phase = time.perf_counter()
        rendered = render_plan(model, plan)
        if rendered.rollback_warnings:
            print(
                "UWAGA: część pomocniczego rollbacku CLI wymaga odtworzenia z "
                "pełnych backupów XML; szczegóły znajdą się w artefaktach runu.",
                file=sys.stderr,
            )
        metrics.rendering_seconds = time.perf_counter() - phase
        metrics.affected_rule_count = len(rendered.affected_rules)
        metrics.affected_group_count = len(rendered.affected_groups)
        metrics.blocked_ip_count = len(plan.blocked_ips) + ping_error_count
        metrics.generated_command_count = len(rendered.commands)

        phase = time.perf_counter()
        hit_counts = collect_rule_hit_counts(client, plan.deleted_rules)
        metrics.hit_count_seconds = time.perf_counter() - phase
        metrics.remote_operational_command_count = client.operational_call_count
        metrics.hit_count_rule_count = len(hit_counts)
        metrics.recent_hit_rule_count = sum(
            result.status == "RECENT" for result in hit_counts.values()
        )
        metrics.no_last_hit_rule_count = sum(
            result.status == "NEVER" for result in hit_counts.values()
        )
        metrics.hit_count_error_count = sum(
            result.status in {"ERROR", "NOT_FOUND", "INVALID", "NOT_LATEST"}
            for result in hit_counts.values()
        )
        if metrics.recent_hit_rule_count:
            print(
                "UWAGA: polityki przeznaczone do usunięcia mają last-hit z "
                "ostatnich 14 dni. Szczegóły: policies_recent_hits_review.txt. "
                "Nie wstrzymuje to commands.txt.",
                file=sys.stderr,
            )
        if metrics.hit_count_error_count:
            print(
                "UWAGA: części last-hit nie udało się potwierdzić. Szczegóły: "
                "policies_hit_count_errors.txt. Nie wstrzymuje to commands.txt.",
                file=sys.stderr,
            )
        if metrics.no_last_hit_rule_count:
            print(
                "UWAGA: część polityk nie ma last-hit. Bez potwierdzonego "
                "14-dniowego okna obserwacji wymaga to review; szczegóły: "
                "policies_no_last_hit_review.txt. Nie wstrzymuje to commands.txt.",
                file=sys.stderr,
            )
        metrics.total_seconds = time.perf_counter() - started_perf

        run_dir, file_stamp = create_run_directory(Path(args.output_dir).resolve())
        sanitized_arguments: Dict[str, Any] = {
            "host_file": str(Path(args.host_file)),
            "ip_file": str(Path(args.ip_file)),
            "password_env": args.password_env,
            "output_dir": str(Path(args.output_dir)),
            "no_ping": args.no_ping,
            "ping_workers": args.ping_workers,
            "ping_timeout_ms": args.ping_timeout_ms,
            "ping_error_retries": args.ping_error_retries,
            "ca_bundle": ca_bundle,
            "ssl_configured": "yes" if host_settings.verify_ssl else "no",
            "ssl_certificate_verification": not ssl_verification_disabled,
            "legacy_insecure_override": args.insecure,
            "candidate_diff_automated_check": True,
            "candidate_diff_administrator_confirmed": False,
            "dependency_scope": "named-address-objects-from-running-config",
            "runtime_membership_audit_performed": False,
            "administrator_confirmed_dependency_scope": True,
            "nat_translation": args.nat_translation,
        }
        write_run_artifacts(
            run_dir=run_dir,
            file_stamp=file_stamp,
            model=model,
            plan=plan,
            rendered=rendered,
            rows=rows,
            pings=pings,
            matches=matches,
            comparison=comparison,
            host=host_settings.host,
            username=host_settings.username,
            system_info=system_info,
            sanitized_arguments=sanitized_arguments,
            metrics=metrics,
            started_utc=started_utc,
            hit_counts=hit_counts,
            publication_blockers=publication_blockers,
        )

        print(f"Gotowe: {run_dir}")
        print(
            f"Komendy w planie: {len(rendered.commands)}, obiekty: {len(rendered.affected_addresses)}, "
            f"grupy: {len(rendered.affected_groups)}, polityki: {len(rendered.affected_rules)}, "
            f"blokady IP: {len(plan.blocked_ips) + ping_error_count}."
        )
        if publication_blockers:
            print("commands.txt wstrzymany przez bramkę bezpieczeństwa.")

        if has_invalid:
            return 3
        has_skipped = any(result.status == PingStatus.REPLIED for result in pings.values())
        has_review = bool(
            plan.blocked_ips
            or plan.dynamic_group_impacts
            or plan.warnings
            or rendered.rollback_warnings
            or any(match.containing_objects for match in matches.values())
            or has_skipped
            or has_ping_error
            or any(result.requires_review for result in hit_counts.values())
        )
        return 2 if has_review else 0

    except InputError as exc:
        print(f"BŁĄD WEJŚCIA: {exc}", file=sys.stderr)
        return 3
    except (TransportError, SnapshotError) as exc:
        print(f"BŁĄD SNAPSHOTU: {exc}", file=sys.stderr)
        return 4
    except ParseError as exc:
        print(f"BŁĄD PARSOWANIA/SCOPE: {exc}", file=sys.stderr)
        return 5
    except OutputError as exc:
        print(f"BŁĄD BACKUPU/WYJŚCIA: {exc}", file=sys.stderr)
        return 6
    except UnsafePlanError as exc:
        print(f"BŁĄD INWARIANTU: {exc}", file=sys.stderr)
        return 7
    finally:
        password = ""
        if client is not None:
            close = getattr(client, "close", None)
            if callable(close):
                close()


if __name__ == "__main__":
    raise SystemExit(main())
