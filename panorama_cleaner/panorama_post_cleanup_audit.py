#!/usr/bin/env python3
"""Audit what remains after a Panorama address cleanup; never change config."""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

from panorama_cleanup.audit import (
    audit_config,
    create_audit_directory,
    load_historical_objects,
    write_audit_artifacts,
)
from panorama_cleanup.models import (
    InputError,
    OutputError,
    ParseError,
    PingStatus,
    SnapshotError,
    TransportError,
    __version__,
)
from panorama_cleanup.panos import parse_config
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Wyłącznie odczytowy audyt po czyszczeniu. Ponownie sprawdza ICMP, "
            "pobiera running i candidate, analizuje running oraz raportuje "
            "pozostałe obiekty, literały, grupy, polityki i ścieżki konfiguracji."
        )
    )
    parser.add_argument(
        "--host-file",
        default=str(PROJECT_DIR / "panorama_host.txt"),
        help="Plik host=..., username=... i opcjonalnie ssl=yes/no.",
    )
    parser.add_argument(
        "--ip-file",
        default=str(PROJECT_DIR / "ip.txt"),
        help="Plik z IPv4/IPv6 do ponownego sprawdzenia.",
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
        help="Katalog nadrzędny dla audit_DDMMYY_HH_MM_SS.",
    )
    parser.add_argument(
        "--previous-run",
        action="append",
        default=[],
        help=(
            "Katalog run_... albo jego manifest.json z poprzedniego czyszczenia. "
            "Opcję można podać wielokrotnie; umożliwia wykrycie referencji po "
            "nazwie obiektu, którego definicja została już usunięta."
        ),
    )
    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Jawnie pomija test ICMP; pozostałości otrzymają status review.",
    )
    parser.add_argument("---no-ping", dest="no_ping", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--ping-workers", type=int, default=64)
    parser.add_argument("--ping-timeout-ms", type=int, default=1000)
    parser.add_argument(
        "--ping-error-retries",
        type=int,
        default=2,
        help="Ponowienia lokalnego błędu procesu ping (domyślnie 2, zakres 0..5).",
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--ca-bundle", help="Ścieżka do CA bundle Panoramy.")
    tls.add_argument(
        "--insecure",
        action="store_true",
        help="Wyłącza weryfikację TLS; preferowane jest ssl=no w host-file.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    started_utc = datetime.now(timezone.utc)
    started_perf = time.perf_counter()
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
            raise InputError("Brak poprawnych adresów IP do audytu.")
        has_invalid = any(not row.valid for row in rows)
        print(
            f"Załadowano {len(rows)} pozycji, "
            f"{len(valid_ips)} unikalnych poprawnych IP."
        )

        print(
            "Ponowne sprawdzanie ICMP..."
            if not args.no_ping
            else "ICMP pominięty jawnie (--no-ping)."
        )
        pings = ping_many(
            valid_ips,
            bypass=args.no_ping,
            workers=args.ping_workers,
            timeout_ms=args.ping_timeout_ms,
            error_retries=args.ping_error_retries,
            sensitive_environment_names=(args.password_env,),
        )
        print(
            f"ICMP: odpowiedziało "
            f"{sum(item.status == PingStatus.REPLIED for item in pings.values())}, "
            f"brak odpowiedzi "
            f"{sum(item.status == PingStatus.NO_REPLY for item in pings.values())}, "
            f"błędy {sum(item.status == PingStatus.ERROR for item in pings.values())}."
        )

        previous_paths = [Path(value).resolve() for value in args.previous_run]
        historical_objects, previous_manifests = load_historical_objects(
            previous_paths, valid_ips
        )

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
        if config_version != "unknown" and not config_version.startswith("10.2"):
            model.warnings.append(
                f"WERSJA: audyt projektowano dla {EXPECTED_PAN_OS}, "
                f"a running config deklaruje {config_version}."
            )
        if model.dynamic_groups:
            model.warnings.append(
                f"RUNTIME_DAG_PRESENT: snapshot zawiera {len(model.dynamic_groups)} "
                "dynamic address group. Audyt raportuje dopasowania na podstawie "
                "skonfigurowanych tagów obiektów, ale operacyjne rejestracje IP→tag "
                "nie są częścią running/candidate."
            )
        ip_edl_count = sum(
            entry.find("./type/ip") is not None
            for entry in running_config.findall(".//external-list/entry")
        )
        if ip_edl_count:
            model.warnings.append(
                f"IP_EDL_PRESENT: snapshot zawiera {ip_edl_count} IP External "
                "Dynamic List; ich runtime contents nie są częścią running/candidate."
            )
        region_count = len(running_config.findall(".//region/entry"))
        if region_count:
            model.warnings.append(
                f"REGION_PRESENT: snapshot zawiera {region_count} custom region; "
                "audyt nie rozwija regionów do adresów IP."
            )
        batch = audit_config(
            model,
            valid_ips,
            pings,
            historical_objects=historical_objects,
            previous_manifests=previous_manifests,
        )

        audit_dir = create_audit_directory(Path(args.output_dir).resolve())
        finished_utc = datetime.now(timezone.utc)
        write_audit_artifacts(
            audit_dir=audit_dir,
            batch=batch,
            rows=rows,
            pings=pings,
            metadata={
                "script": "panorama_post_cleanup_audit.py",
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
                "remote_snapshot_command_count": snapshot_call_count,
                "input_rows": len(rows),
                "unique_valid_ips": len(valid_ips),
                "ssl_configured": "yes" if host_settings.verify_ssl else "no",
                "ssl_certificate_verification": not ssl_verification_disabled,
                "ping_bypassed": args.no_ping,
                "ping_workers": args.ping_workers,
                "ping_timeout_ms": args.ping_timeout_ms,
                "ping_error_retries": args.ping_error_retries,
            },
        )

        alert_count = sum(item.unexpected for item in batch.results.values())
        review_count = sum(item.review_required for item in batch.results.values())
        retained_count = sum(
            item.status == "OCZEKIWANIE_POZOSTAWIONY_ICMP"
            for item in batch.results.values()
        )
        clean_count = sum(item.status.startswith("CZYSTO") for item in batch.results.values())
        print(f"Gotowe: {audit_dir}")
        print(
            f"Czysto: {clean_count}, oczekiwanie pozostawione po ICMP: "
            f"{retained_count}, alerty: {alert_count}, review łącznie: {review_count}."
        )
        print("Audyt nie wykonał zmian i nie wygenerował commands.txt.")
        if has_invalid:
            return 3
        return 2 if batch.review_required else 0

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


if __name__ == "__main__":
    raise SystemExit(main())
