"""Command-line interface for staged PanOS Toolbox operations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

from .client import PanoramaReadClient
from .doctor import run_doctor
from .engine import apply_candidate, commit_session, push_session
from .errors import ToolboxError
from .models import ApiStage
from .profile import load_profile, obtain_password
from .service import make_writer, plan_cleanup_session, plan_restore_session
from .sessions import SessionStore


PROJECT_DIR = Path(__file__).resolve().parents[2]


def _add_connection(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--host-file",
        default=str(PROJECT_DIR / "panorama_host.txt"),
        help="Profil host/username/ssl/verify_ssl/api_max_stage.",
    )
    parser.add_argument("--password-env", default="PANORAMA_PASSWORD")


def _add_store(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--session-dir",
        help="Niestandardowy katalog sesji (domyślnie Dokumenty\\PanOS Toolbox\\sessions).",
    )


def _add_apply(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--session", required=True)
    parser.add_argument("--enable-api-write", action="store_true")
    parser.add_argument("--no-server-snapshot", action="store_true")
    _add_connection(parser)
    _add_store(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="panos-toolbox",
        description="Lokalny generator i kontrolowany executor PAN-OS XML API.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    cleanup = commands.add_parser("cleanup", help="Planowanie i staged cleanup.")
    cleanup_commands = cleanup.add_subparsers(dest="cleanup_command", required=True)
    cleanup_plan = cleanup_commands.add_parser("plan", help="Utwórz plan bez zapisu API.")
    cleanup_plan.add_argument("--ip-file", default=str(PROJECT_DIR / "ip.txt"))
    cleanup_plan.add_argument("--ip", action="append", default=[])
    cleanup_plan.add_argument("--object", action="append", default=[], help="Dokładna nazwa obiektu adresowego; opcję można powtarzać.")
    cleanup_plan.add_argument("--group", action="append", default=[], help="Dokładna nazwa statycznej address group; opcję można powtarzać.")
    cleanup_plan.add_argument("--policy", action="append", default=[], help="Dokładna nazwa polityki; opcję można powtarzać.")
    cleanup_plan.add_argument("--no-ping", action="store_true")
    cleanup_plan.add_argument("--ping-timeout-ms", type=int, default=1000)
    cleanup_plan.add_argument("--ping-workers", type=int, default=32)
    cleanup_plan.add_argument("--recent-hit-days", type=int, default=14)
    cleanup_plan.add_argument(
        "--nat-translation", choices=("delete-rule", "block"), default="delete-rule"
    )
    cleanup_plan.add_argument(
        "--allow-default-policy-override",
        action="store_true",
        help="Jawnie zezwól na dotknięcie polityki DEFAULT i jej zależności (ryzykowne).",
    )
    _add_connection(cleanup_plan)
    _add_store(cleanup_plan)
    cleanup_apply = cleanup_commands.add_parser("apply", help="Zastosuj PatchSet do candidate.")
    _add_apply(cleanup_apply)

    session = commands.add_parser("session", help="Historia, commit i push sesji.")
    session_commands = session.add_subparsers(dest="session_command", required=True)
    session_list = session_commands.add_parser("list")
    _add_store(session_list)
    session_show = session_commands.add_parser("show")
    session_show.add_argument("--session", required=True)
    _add_store(session_show)
    session_commit = session_commands.add_parser("commit")
    session_commit.add_argument("--session", required=True)
    session_commit.add_argument("--enable-api-write", action="store_true")
    session_commit.add_argument("--full", action="store_true")
    session_commit.add_argument("--allow-unisolated-commit", action="store_true")
    session_commit.add_argument("--allow-full-commit", action="store_true")
    _add_connection(session_commit)
    _add_store(session_commit)
    session_push = session_commands.add_parser("push")
    session_push.add_argument("--session", required=True)
    session_push.add_argument("--enable-api-write", action="store_true")
    session_push.add_argument("--device-group", action="append", required=True)
    _add_connection(session_push)
    _add_store(session_push)

    restore = commands.add_parser("restore", help="Three-way Emergency Restore.")
    restore_commands = restore.add_subparsers(dest="restore_command", required=True)
    restore_plan = restore_commands.add_parser("plan")
    restore_plan.add_argument("--ip")
    restore_plan.add_argument("--source-session")
    _add_connection(restore_plan)
    _add_store(restore_plan)
    restore_apply = restore_commands.add_parser("apply")
    _add_apply(restore_apply)

    doctor = commands.add_parser("doctor", help="Sprawdź środowisko maszyny docelowej.")
    doctor.add_argument("--host-file")
    doctor.add_argument("--password-env", default="PANORAMA_PASSWORD")
    doctor.add_argument("--api-check", action="store_true")
    _add_store(doctor)

    serve = commands.add_parser("serve", help="Uruchom GUI wyłącznie na 127.0.0.1.")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument(
        "--static-dir",
        default=str(Path(__file__).resolve().parent / "static"),
        help="Release: backend/panos_toolbox/static; dev: wskaż frontend/dist.",
    )
    serve.add_argument(
        "--host-file",
        default=None,
        help=(
            "Opcjonalny legacy profil hosta będący dodatkowym sufitem zapisu GUI. "
            "Bez tego pliku GUI korzysta z zapisanych profili i przełącznika READ ONLY/WRITE."
        ),
    )
    _add_store(serve)
    return parser


def _store(args: argparse.Namespace) -> SessionStore:
    return SessionStore(Path(args.session_dir) if args.session_dir else None)


def _reader(args: argparse.Namespace) -> PanoramaReadClient:
    profile = load_profile(Path(args.host_file))
    reader = PanoramaReadClient(profile)
    password = obtain_password(args.password_env)
    reader.authenticate(password)
    password = ""
    return reader


def _input_ips(args: argparse.Namespace) -> list[str]:
    values = list(args.ip)
    path = Path(args.ip_file)
    if path.is_file():
        values.extend(path.read_text(encoding="utf-8-sig").splitlines())
    elif not values and not (args.object or args.group or args.policy):
        raise ToolboxError(f"Brak pliku IP i argumentów --ip: {path}.")
    return values


def _print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    reader: Optional[PanoramaReadClient] = None
    try:
        if args.command == "doctor":
            result = run_doctor(
                session_dir=Path(args.session_dir) if args.session_dir else None,
                profile_path=Path(args.host_file) if args.host_file else None,
                static_dir=Path(__file__).resolve().parent / "static",
                api_check=args.api_check,
                password_env=args.password_env,
            )
            _print(result)
            return 0 if result["ok"] else 2
        if args.command == "serve":
            from .web import run_server

            run_server(
                port=args.port,
                static_dir=Path(args.static_dir),
                session_dir=Path(args.session_dir) if args.session_dir else None,
                profile_path=Path(args.host_file) if args.host_file else None,
            )
            return 0
        store = _store(args)
        if args.command == "session" and args.session_command == "list":
            _print(store.list_sessions())
            return 0
        if args.command == "session" and args.session_command == "show":
            _print(store.load_manifest(args.session))
            return 0

        reader = _reader(args)
        if args.command == "cleanup" and args.cleanup_command == "plan":
            result = plan_cleanup_session(
                store,
                reader,
                _input_ips(args),
                address_objects=args.object,
                address_groups=args.group,
                policies=args.policy,
                no_ping=args.no_ping,
                ping_timeout_ms=args.ping_timeout_ms,
                ping_workers=args.ping_workers,
                nat_translation_action=args.nat_translation,
                recent_hit_days=args.recent_hit_days,
                allow_default_policy_override=args.allow_default_policy_override,
            )
        elif args.command in {"cleanup", "restore"} and getattr(
            args, f"{args.command}_command"
        ) == "apply":
            writer = make_writer(
                reader, ApiStage.CANDIDATE, enable_api_write=args.enable_api_write
            )
            result = dataclass_to_dict(
                apply_candidate(
                    store,
                    args.session,
                    reader,
                    writer,
                    save_server_snapshot=not args.no_server_snapshot,
                    acquire_locks=True,
                )
            )
        elif args.command == "session" and args.session_command == "commit":
            writer = make_writer(reader, ApiStage.COMMIT, enable_api_write=args.enable_api_write)
            result = commit_session(
                store,
                args.session,
                reader,
                writer,
                partial=not args.full,
                allow_unisolated_commit=args.allow_unisolated_commit,
                allow_full_commit=args.allow_full_commit,
            )
        elif args.command == "session" and args.session_command == "push":
            writer = make_writer(reader, ApiStage.PUSH, enable_api_write=args.enable_api_write)
            result = push_session(
                store,
                args.session,
                reader,
                writer,
                device_groups=args.device_group,
            )
        elif args.command == "restore" and args.restore_command == "plan":
            result = plan_restore_session(
                store,
                reader,
                source_session_id=args.source_session,
                ip=args.ip,
            )
        else:  # pragma: no cover - argparse makes this unreachable
            raise ToolboxError("Nieobsługiwana komenda.")
        _print(result)
        return 0
    except ToolboxError as exc:
        print(f"BŁĄD: {exc}", file=sys.stderr)
        return 2
    finally:
        if reader is not None:
            reader.close()


def dataclass_to_dict(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        import dataclasses

        result = dataclasses.asdict(value)
        if "state" in result and hasattr(result["state"], "value"):
            result["state"] = result["state"].value
        return result
    return value
