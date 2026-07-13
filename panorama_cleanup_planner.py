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


def config_completeness_findings(
    model: ConfigModel, running_config: Any
) -> Tuple[List[str], List[str]]:
    """Find runtime/unmodeled address namespaces that make IP inventory partial."""

    warnings: List[str] = []
    blockers: List[str] = []
    if model.dynamic_groups:
        warnings.append(
            f"Snapshot zawiera {len(model.dynamic_groups)} dynamic address group. "
            "Running/candidate nie zawierają operacyjnych rejestracji IP→tag "
            "z firewalli, więc pełnego członkostwa target IP nie da się dowieść."
        )
        blockers.append(
            "RUNTIME_DAG_MEMBERSHIP_UNVERIFIED: commands.txt wstrzymany, "
            "ponieważ dwa snapshoty konfiguracji nie obejmują runtime DAG."
        )

    fqdn_count = sum(obj.object_type == "fqdn" for obj in model.addresses.values())
    if fqdn_count:
        warnings.append(
            f"Snapshot zawiera {fqdn_count} obiektów FQDN; ich bieżących "
            "rozwiązań DNS nie można wiarygodnie przypisać do IP wyłącznie "
            "z running config."
        )
        blockers.append(
            "FQDN_RESOLUTION_UNVERIFIED: commands.txt wstrzymany, ponieważ "
            "snapshot nie dowodzi, czy FQDN wskazuje któryś target IP."
        )

    ip_edl_count = sum(
        entry.find("./type/ip") is not None
        for entry in running_config.findall(".//external-list/entry")
    )
    if ip_edl_count:
        warnings.append(
            f"Snapshot zawiera {ip_edl_count} IP External Dynamic List; "
            "ich runtime contents nie są zawarte w running/candidate."
        )
        blockers.append(
            "IP_EDL_CONTENT_UNVERIFIED: commands.txt wstrzymany, ponieważ "
            "target IP może znajdować się w runtime EDL."
        )

    region_count = len(running_config.findall(".//region/entry"))
    if region_count:
        warnings.append(
            f"Snapshot zawiera {region_count} custom region; planner nie "
            "rozwija regionów do adresów target IP."
        )
        blockers.append(
            "REGION_MEMBERSHIP_UNVERIFIED: commands.txt wstrzymany, ponieważ "
            "target IP może należeć do custom/predefined region."
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
        sample = ", ".join(sorted(unresolved_values)[:10])
        warnings.append(
            f"Wykryto {len(unresolved_values)} nierozwiązanych nazw w polach "
            f"adresowych (przykłady: {sample}); mogą oznaczać EDL, region "
            "predefined albo niewidoczny obiekt."
        )
        blockers.append(
            "UNMODELED_ADDRESS_REFERENCE: commands.txt wstrzymany do czasu "
            "rozwiązania wszystkich nazw z pól adresowych."
        )
    return warnings, blockers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analizuje running config Panoramy, porównuje candidate i generuje "
            "backupy, raporty oraz komendy CLI. Nie wykonuje zmian ani commit."
        )
    )
    parser.add_argument(
        "--host-file",
        default="panorama_host.txt",
        help="Plik host=... i username=... (domyślnie panorama_host.txt).",
    )
    parser.add_argument(
        "--ip-file",
        default="ip.txt",
        help="Plik z jednym IPv4/IPv6 na linię (domyślnie ip.txt).",
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
        default=".",
        help="Katalog nadrzędny dla run_DDMMYY_HH_MM_SS (domyślnie bieżący).",
    )
    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Jawnie pomija ochronny test ICMP dla wszystkich adresów.",
    )
    parser.add_argument("---no-ping", dest="no_ping", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--ping-workers", type=int, default=64)
    parser.add_argument("--ping-timeout-ms", type=int, default=1000)
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--ca-bundle",
        help="Ścieżka do zaufanego CA bundle dla certyfikatu Panoramy.",
    )
    tls.add_argument(
        "--insecure",
        action="store_true",
        help="Jawnie wyłącza weryfikację TLS (niezalecane).",
    )
    parser.add_argument(
        "--nat-translation",
        choices=("block", "delete-rule"),
        default="block",
        help=(
            "Dla referencji w polach translacji NAT: block (domyślnie) albo "
            "delete-rule po jawnej decyzji operatora."
        ),
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    started_perf = time.perf_counter()
    started_utc = datetime.now(timezone.utc)
    metrics = RunMetrics()

    try:
        ca_bundle = validate_ca_bundle(args.ca_bundle)
        host_settings = load_host_settings(Path(args.host_file))
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
        publication_blockers = []
        if has_invalid:
            invalid_count = sum(not row.valid for row in rows)
            publication_blockers.append(
                f"Niepoprawne pozycje w ip.txt: {invalid_count}; plan dotyczyłby "
                "tylko części wejścia. Popraw plik i uruchom planner ponownie."
            )
        if has_ping_error:
            ping_error_count = sum(
                result.status == PingStatus.ERROR for result in pings.values()
            )
            publication_blockers.append(
                f"Błędy wykonania ICMP: {ping_error_count}; nie można bezpiecznie "
                "potwierdzić kompletności ochronnego prechecku."
            )

        password = obtain_password(args.password_env)
        verify: Any = False if args.insecure else (ca_bundle or True)
        if args.insecure:
            print("UWAGA: weryfikacja TLS została jawnie wyłączona.", file=sys.stderr)

        print(f"Pobieranie running i candidate z Panoramy {host_settings.host}...")
        phase = time.perf_counter()
        try:
            with PanoramaXMLAPI(
                host_settings.host,
                host_settings.username,
                verify=verify,
            ) as client:
                client.authenticate(password)
                # Do not retain the password longer than needed by this scope.
                password = ""
                running_config = client.fetch_config("show")  # running/active
                candidate_config = client.fetch_config("get")  # candidate
                metrics.remote_snapshot_command_count = client.snapshot_call_count
        finally:
            password = ""
        system_info = {
            "declared_target_version": EXPECTED_PAN_OS,
            "config_version": running_config.get("version", "unknown"),
            "live_system_info_queried": "no",
        }
        metrics.snapshot_seconds = time.perf_counter() - phase

        comparison = compare_configs(running_config, candidate_config)
        if comparison.relevant_different:
            print(
                "BLOKADA: running i candidate różnią się w analizowanym zakresie. "
                "Plan powstanie z running, ale commands.txt nie zostanie opublikowany.",
                file=sys.stderr,
            )
        elif comparison.different:
            print(
                "UWAGA: running i candidate różnią się poza analizowanym zakresem.",
                file=sys.stderr,
            )

        phase = time.perf_counter()
        model = parse_config(running_config)
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
        metrics.rendering_seconds = time.perf_counter() - phase
        metrics.affected_rule_count = len(rendered.affected_rules)
        metrics.affected_group_count = len(rendered.affected_groups)
        metrics.blocked_ip_count = len(plan.blocked_ips)
        metrics.generated_command_count = len(rendered.commands)
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
            "ca_bundle": ca_bundle,
            "insecure": args.insecure,
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
            publication_blockers=publication_blockers,
        )

        print(f"Gotowe: {run_dir}")
        print(
            f"Komendy w planie: {len(rendered.commands)}, obiekty: {len(rendered.affected_addresses)}, "
            f"grupy: {len(rendered.affected_groups)}, polityki: {len(rendered.affected_rules)}, "
            f"blokady IP: {len(plan.blocked_ips)}."
        )
        if comparison.relevant_different or publication_blockers:
            print("commands.txt wstrzymany przez bramkę bezpieczeństwa.")

        if has_invalid or has_ping_error:
            return 3
        has_skipped = any(result.status == PingStatus.REPLIED for result in pings.values())
        has_review = bool(
            plan.blocked_ips
            or comparison.different
            or plan.dynamic_group_impacts
            or plan.warnings
            or any(match.containing_objects for match in matches.values())
            or has_skipped
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


if __name__ == "__main__":
    raise SystemExit(main())
