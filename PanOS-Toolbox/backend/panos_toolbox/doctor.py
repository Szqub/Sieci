"""Restricted-host readiness checks for the localhost Toolbox."""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import sys
import importlib.util
from pathlib import Path
from typing import Any, Optional

from .client import PanoramaReadClient
from .profile import PanoramaProfile, load_profile, obtain_password
from .sessions import SessionStore


def run_doctor(
    *,
    session_dir: Optional[Path] = None,
    profile_path: Optional[Path] = None,
    probe_profile: Optional[PanoramaProfile] = None,
    static_dir: Optional[Path] = None,
    api_check: bool = False,
    password_env: str = "PANORAMA_PASSWORD",
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def record(name: str, ok: bool, detail: str, *, state: Optional[str] = None) -> None:
        checks.append(
            {
                "id": name,
                "name": name,
                "label": name.replace("-", " ").title(),
                "ok": ok,
                "state": state or ("pass" if ok else "fail"),
                "detail": detail,
            }
        )

    record(
        "python",
        sys.version_info >= (3, 10),
        f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )
    web_runtime_ok = all(
        importlib.util.find_spec(name) is not None for name in ("flask", "werkzeug")
    )
    record(
        "web-runtime",
        web_runtime_ok,
        "Flask/Werkzeug dostępne."
        if web_runtime_ok
        else "Brak spakowanego Flask/Werkzeug; GUI nie wystartuje.",
    )
    ad_helper = Path(__file__).with_name("ad_group_lookup.ps1")
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not ad_helper.is_file():
        record("active-directory", False, "Brak helpera ad_group_lookup.ps1 w paczce.")
    elif not powershell:
        record(
            "active-directory",
            True,
            "Brak Windows PowerShell; generator grup AD będzie niedostępny.",
            state="warn",
        )
    else:
        try:
            probe = subprocess.run(
                [
                    powershell,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "if (Get-Module -ListAvailable -Name ActiveDirectory) { exit 0 } else { exit 2 }",
                ],
                capture_output=True,
                timeout=10,
                check=False,
                creationflags=(
                    getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
                ),
            )
            available = probe.returncode == 0
            record(
                "active-directory",
                True,
                (
                    "PowerShell i moduł ActiveDirectory (RSAT) dostępne."
                    if available
                    else "PowerShell dostępny, ale brak modułu ActiveDirectory (RSAT); generator grup AD będzie niedostępny."
                ),
                state="pass" if available else "warn",
            )
        except (OSError, subprocess.TimeoutExpired):
            record(
                "active-directory",
                True,
                "Nie udało się potwierdzić modułu ActiveDirectory; generator sprawdzi go ponownie przy użyciu.",
                state="warn",
            )
    if static_dir is not None:
        static_index = static_dir / "index.html"
        record(
            "static-gui",
            static_index.is_file(),
            str(static_index),
        )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        record("loopback-bind", True, f"127.0.0.1:{port}")
    except OSError as exc:
        record("loopback-bind", False, f"{type(exc).__name__}: {exc}")
    finally:
        listener.close()

    proxy_present = any(
        os.environ.get(name)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
    )
    no_proxy = (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "").casefold()
    bypass_ok = "127.0.0.1" in no_proxy and "localhost" in no_proxy
    if proxy_present and not bypass_ok:
        record(
            "loopback-proxy",
            True,
            "Ustawiono proxy, ale NO_PROXY nie zawiera jednocześnie 127.0.0.1 i localhost.",
            state="warn",
        )
    else:
        record("loopback-proxy", True, "Konfiguracja proxy nie powinna przechwycić localhost.")

    try:
        store = SessionStore(session_dir)
        probe = store.root / ".doctor-write-test"
        probe.write_text("ok", encoding="ascii")
        probe.unlink()
        record("session-store", True, str(store.root))
        job_markers = sorted(store.root.glob(".panorama-job-*.lock"))
        record(
            "panorama-job-marker",
            not job_markers,
            (
                "Brak markerów nieustalonego zapisu candidate/commit/push."
                if not job_markers
                else f"Wymagane reconciliation: {len(job_markers)} marker(y) zapisu API."
            ),
        )
    except Exception as exc:
        record("session-store", False, f"{type(exc).__name__}: {exc}")

    profile: Optional[PanoramaProfile] = probe_profile
    if profile is not None:
        record(
            "profile",
            True,
            f"{profile.base_url} max={profile.api_max_stage.value} verify_ssl={profile.verify_ssl}",
        )
    elif profile_path is not None:
        try:
            profile = load_profile(profile_path)
            record(
                "profile",
                True,
                f"{profile.base_url} max={profile.api_max_stage.value} verify_ssl={profile.verify_ssl}",
            )
        except Exception as exc:
            record("profile", False, f"{type(exc).__name__}: {exc}")
    else:
        record("profile", True, "Pominięto (nie wskazano --host-file).")

    if profile is not None:
        from urllib.parse import urlsplit

        parsed = urlsplit(profile.base_url)
        port = parsed.port or (443 if profile.use_ssl else 80)
        try:
            connection = socket.create_connection((parsed.hostname, port), timeout=4.0)
            try:
                if profile.use_ssl:
                    context = (
                        ssl.create_default_context()
                        if profile.verify_ssl
                        else ssl._create_unverified_context()  # noqa: SLF001
                    )
                    connection = context.wrap_socket(
                        connection,
                        server_hostname=parsed.hostname if profile.verify_ssl else None,
                    )
                record(
                    "panorama-network",
                    True,
                    f"Połączenie {'TLS' if profile.use_ssl else 'TCP'} do {parsed.hostname}:{port} OK.",
                )
            finally:
                connection.close()
        except Exception as exc:
            record(
                "panorama-network",
                False,
                f"{type(exc).__name__}: {exc}",
            )

    if api_check:
        if profile is None:
            record("api-read", False, "--api-check wymaga poprawnego --host-file.")
        else:
            reader = PanoramaReadClient(profile)
            try:
                password = obtain_password(password_env)
                reader.authenticate(password)
                password = ""
                reader.fetch_config("running")
                reader.fetch_config("candidate")
                record("api-read", True, "Keygen + running + candidate OK (bez zapisu).")
            except Exception as exc:
                record("api-read", False, f"{type(exc).__name__}: {exc}")
            finally:
                reader.close()
    from datetime import datetime, timezone

    return {
        "ok": all(item["state"] != "fail" for item in checks),
        "checks": checks,
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
