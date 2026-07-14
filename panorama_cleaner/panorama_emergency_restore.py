#!/usr/bin/env python3
"""Generate a verified, transitive emergency restore package for selected IPs."""

from __future__ import annotations

import argparse
import ipaddress
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Sequence

from panorama_cleanup.models import (
    InputError,
    OutputError,
    ParseError,
    SnapshotError,
    TransportError,
    UnsafePlanError,
    __version__,
)
from panorama_cleanup.panos import parse_config
from panorama_cleanup.restore import (
    build_emergency_restore,
    create_restore_directory,
    discover_cleanup_manifests,
    load_cleanup_runs,
    write_restore_artifacts,
)
from panorama_cleanup.runtime import (
    PanoramaXMLAPI,
    load_host_settings,
    load_ip_rows,
    obtain_password,
    unique_valid_ips,
    validate_ca_bundle,
)


EXPECTED_PAN_OS = "10.2.16-h4"
PROJECT_DIR = Path(__file__).resolve().parent
BUNDLE_FILENAME = "restore_bundle.xml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Wyłącznie odczytowy generator awaryjnego restore per IP. Weryfikuje "
            "manifesty i backupy cleanup, pobiera running oraz candidate, analizuje "
            "running i tworzy pełne domknięcie adresów, grup oraz polityk. Nie "
            "wykonuje zmian ani commit."
        )
    )
    parser.add_argument(
        "ips",
        nargs="*",
        help="Jeden lub więcej IPv4/IPv6 do awaryjnego odtworzenia.",
    )
    parser.add_argument(
        "--ip",
        action="append",
        default=[],
        help="Dodatkowy IP; opcję można podać wielokrotnie.",
    )
    parser.add_argument(
        "--ip-file",
        help="Opcjonalny plik UTF-8 z IP, po jednym na linię.",
    )
    parser.add_argument(
        "--run",
        action="append",
        default=[],
        help=(
            "Katalog zastosowanego run_... albo jego manifest.json. Opcję można "
            "podać wielokrotnie."
        ),
    )
    parser.add_argument(
        "--all-runs-applied",
        action="store_true",
        help=(
            "Jawne potwierdzenie, że wszystkie run_*/manifest.json z --runs-dir "
            "zostały faktycznie zastosowane; dopiero wtedy włącza autodiscovery."
        ),
    )
    parser.add_argument(
        "--runs-dir",
        default=str(PROJECT_DIR),
        help="Katalog dla autodiscovery run_*/manifest.json.",
    )
    parser.add_argument(
        "--host-file",
        default=str(PROJECT_DIR / "panorama_host.txt"),
        help="Plik host=..., username=... i opcjonalnie ssl=yes/no.",
    )
    parser.add_argument(
        "--password-env",
        default="PANORAMA_PASSWORD",
        help=(
            "Nazwa zmiennej środowiskowej z hasłem; przy braku używany jest "
            "ukryty prompt (domyślnie PANORAMA_PASSWORD)."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_DIR),
        help="Katalog nadrzędny dla restore_IP_DDMMYY_HH_MM_SS.",
    )
    parser.add_argument(
        "--allow-host-mismatch",
        action="store_true",
        help=(
            "Jawny override, gdy panorama_host w manifeście różni się od "
            "bieżącego host-file. devices/entry nadal musi być zgodne."
        ),
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--ca-bundle", help="Ścieżka do CA bundle Panoramy.")
    tls.add_argument(
        "--insecure",
        action="store_true",
        help="Wyłącza weryfikację TLS; preferowane jest ssl=no w host-file.",
    )
    return parser


def _target_ips(args: argparse.Namespace) -> List[str]:
    raw_values = list(args.ips) + list(args.ip)
    normalized: List[str] = []
    invalid: List[str] = []
    for raw in raw_values:
        try:
            normalized.append(str(ipaddress.ip_address(raw.strip())))
        except ValueError:
            invalid.append(raw)
    if args.ip_file:
        rows = load_ip_rows(Path(args.ip_file))
        invalid.extend(row.raw for row in rows if not row.valid)
        normalized.extend(unique_valid_ips(rows))
    if invalid:
        raise InputError(
            "Niepoprawne IP dla restore: " + ", ".join(repr(item) for item in invalid)
        )
    targets = sorted(set(normalized))
    if not targets:
        raise InputError("Podaj IP jako argument, przez --ip albo --ip-file.")
    return targets


def _manifest_paths(args: argparse.Namespace) -> Sequence[Path]:
    if args.run and args.all_runs_applied:
        raise InputError("Użyj albo --run, albo --all-runs-applied, nie obu.")
    if not args.run and not args.all_runs_applied:
        raise InputError(
            "Podaj co najmniej jeden faktycznie zastosowany --run. Jeżeli każdy "
            "run w katalogu został zastosowany, użyj jawnie --all-runs-applied."
        )
    supplied = [Path(value) for value in args.run]
    return discover_cleanup_manifests(
        supplied,
        Path(args.runs_dir).resolve(),
    )


def _confirm_candidate_ready() -> None:
    print(
        "UWAGA: generator analizuje running, ale przyszłe komendy zmienią candidate.\n"
        "Administrator musi wcześniej sprawdzić diff w Panoramie i potwierdzić "
        "brak oczekujących cudzych zmian."
    )
    try:
        answer = input(
            "Potwierdzasz sprawdzenie diffu i chcesz wygenerować restore? "
            "Wpisz dokładnie TAK: "
        )
    except EOFError as exc:
        raise InputError("Brak interaktywnego potwierdzenia diffu.") from exc
    if answer != "TAK":
        raise InputError("Nie potwierdzono ręcznej kontroli diffu; przerwano.")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    started_utc = datetime.now(timezone.utc)
    started_perf = time.perf_counter()
    password = ""
    try:
        targets = _target_ips(args)
        manifest_paths = _manifest_paths(args)
        runs = load_cleanup_runs(manifest_paths)

        ca_bundle = validate_ca_bundle(args.ca_bundle)
        host_settings = load_host_settings(Path(args.host_file))
        if not host_settings.verify_ssl and ca_bundle:
            raise InputError(
                "ssl=no w panorama_host.txt jest sprzeczne z --ca-bundle. "
                "Ustaw ssl=yes, aby użyć wskazanego CA."
            )
        ssl_verification_disabled = args.insecure or not host_settings.verify_ssl
        verify: Any = False if ssl_verification_disabled else (ca_bundle or True)
        manifest_hosts = sorted({run.panorama_host for run in runs})
        host_mismatch = any(
            host.casefold() != host_settings.host.casefold()
            for host in manifest_hosts
        )
        if host_mismatch and not args.allow_host_mismatch:
            raise InputError(
                "panorama_host z manifestów nie odpowiada bieżącemu host-file: "
                f"manifesty={manifest_hosts}, bieżący={host_settings.host!r}. "
                "Jeżeli to świadomie ten sam system pod inną nazwą, użyj "
                "--allow-host-mismatch."
            )

        _confirm_candidate_ready()

        password = obtain_password(args.password_env)
        if ssl_verification_disabled:
            print(
                "UWAGA: HTTPS działa, ale weryfikacja certyfikatu TLS jest wyłączona.",
                file=sys.stderr,
            )
        print(
            f"Pobieranie running i candidate z Panoramy {host_settings.host}..."
        )
        try:
            with PanoramaXMLAPI(
                host_settings.host,
                host_settings.username,
                verify=verify,
            ) as client:
                client.authenticate(password)
                password = ""
                running_config = client.fetch_config("show")
                candidate_config = client.fetch_config("get")
                snapshot_call_count = client.snapshot_call_count
        finally:
            password = ""
        del candidate_config

        model = parse_config(running_config)
        config_version = running_config.get("version", "unknown")
        plan = build_emergency_restore(
            model,
            runs,
            targets,
            bundle_filename=BUNDLE_FILENAME,
        )
        if config_version != "unknown" and not config_version.startswith("10.2"):
            plan = replace(
                plan,
                warnings=tuple(
                    sorted(
                        set(plan.warnings)
                        | {
                            f"WERSJA: generator projektowano dla {EXPECTED_PAN_OS}, "
                            f"a running config deklaruje {config_version}."
                        }
                    )
                ),
            )
        if host_mismatch:
            plan = replace(
                plan,
                warnings=tuple(
                    sorted(
                        set(plan.warnings)
                        | {
                            "HOST_MISMATCH_OVERRIDDEN: manifesty="
                            f"{manifest_hosts}, bieżący={host_settings.host!r}."
                        }
                    )
                ),
            )

        restore_dir = create_restore_directory(
            Path(args.output_dir).resolve(), targets
        )
        finished_utc = datetime.now(timezone.utc)
        write_restore_artifacts(
            restore_dir,
            plan,
            bundle_filename=BUNDLE_FILENAME,
            metadata={
                "script": "panorama_emergency_restore.py",
                "script_version": __version__,
                "started_utc": started_utc.isoformat(),
                "finished_utc": finished_utc.isoformat(),
                "elapsed_seconds": time.perf_counter() - started_perf,
                "panorama_host": host_settings.host,
                "panorama_username": host_settings.username,
                "declared_target_version": EXPECTED_PAN_OS,
                "running_config_version": config_version,
                "planning_snapshot": "running",
                "candidate_snapshot_fetched": True,
                "candidate_snapshot_compared": False,
                "candidate_diff_administrator_confirmed": True,
                "host_mismatch_override": args.allow_host_mismatch,
                "remote_snapshot_command_count": snapshot_call_count,
                "ssl_configured": "yes" if host_settings.verify_ssl else "no",
                "ssl_certificate_verification": not ssl_verification_disabled,
            },
        )
        print(f"Gotowe: {restore_dir}")
        print(
            f"IP: {len(targets)}, bezpośrednie encje: {len(plan.seeds)}, "
            f"pełne domknięcie: {len(plan.selected)}, ostrzeżenia: "
            f"{len(plan.warnings)}."
        )
        print("Skrypt nie wykonał zmian, nie wykonał commit i nie uruchomił ICMP.")
        return 2 if plan.review_required else 0

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
        print(f"BŁĄD WYJŚCIA: {exc}", file=sys.stderr)
        return 6
    except UnsafePlanError as exc:
        print(f"BŁĄD INWARIANTU RESTORE: {exc}", file=sys.stderr)
        return 7
    finally:
        password = ""


if __name__ == "__main__":
    raise SystemExit(main())
