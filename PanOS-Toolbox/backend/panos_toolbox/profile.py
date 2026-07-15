"""Panorama host profile and short-lived write capability leases."""

from __future__ import annotations

import getpass
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from .errors import CapabilityError, InputError
from .models import ApiStage


@dataclass(frozen=True)
class PanoramaProfile:
    host: str
    username: str
    use_ssl: bool = True
    verify_ssl: bool = True
    api_max_stage: ApiStage = ApiStage.READ_ONLY

    @property
    def base_url(self) -> str:
        return f"{'https' if self.use_ssl else 'http'}://{self.host}/api/"


def normalize_host(value: str, *, expected_scheme: Optional[str] = None) -> str:
    candidate = value.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"{expected_scheme or 'https'}://{candidate}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise InputError("host musi wskazywać endpoint HTTP/HTTPS Panoramy.")
    if expected_scheme and parsed.scheme != expected_scheme:
        raise InputError(f"Schemat hosta jest sprzeczny z ssl={expected_scheme == 'https'}.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise InputError("host nie może zawierać poświadczeń, query ani fragmentu.")
    if parsed.path not in {"", "/"}:
        raise InputError("host nie może zawierać ścieżki URL.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise InputError("Niepoprawny port hosta.") from exc
    hostname = parsed.hostname
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    return f"{hostname}:{port}" if port else hostname


def _read_bool(value: str, key: str) -> bool:
    normalized = value.strip().casefold()
    if normalized not in {"yes", "no"}:
        raise InputError(f"{key} musi mieć wartość yes albo no.")
    return normalized == "yes"


def load_profile(path: Path) -> PanoramaProfile:
    try:
        content = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise InputError(f"Nie można odczytać profilu Panoramy: {path}.") from exc
    values: dict[str, str] = {}
    allowed = {"host", "username", "ssl", "verify_ssl", "api_max_stage"}
    for line_number, raw in enumerate(content.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise InputError(f"{path}:{line_number}: oczekiwano klucz=wartość.")
        key, value = (part.strip() for part in stripped.split("=", 1))
        if key not in allowed:
            raise InputError(f"{path}:{line_number}: nieznany klucz {key!r}.")
        if not value or key in values:
            raise InputError(f"{path}:{line_number}: pusta lub zduplikowana wartość {key}.")
        values[key] = value
    missing = {"host", "username"} - values.keys()
    if missing:
        raise InputError(f"W profilu brakuje: {', '.join(sorted(missing))}.")

    # ``ssl`` was the cleaner's historical certificate-verification switch.
    # ``verify_ssl`` is the unambiguous Toolbox name and wins when both exist.
    ssl_value = _read_bool(values.get("ssl", "yes"), "ssl")
    if "verify_ssl" in values:
        # New Toolbox form: ssl controls transport; verify_ssl controls TLS.
        use_ssl = ssl_value
        verify_ssl = _read_bool(values["verify_ssl"], "verify_ssl")
        if not use_ssl and verify_ssl:
            raise InputError("verify_ssl=yes nie ma sensu dla ssl=no (HTTP).")
    else:
        # Legacy cleaner form: transport was always HTTPS and ssl was the
        # certificate-verification switch.
        use_ssl = True
        verify_ssl = ssl_value
    return PanoramaProfile(
        host=normalize_host(
            values["host"], expected_scheme="https" if use_ssl else "http"
        ),
        username=values["username"],
        use_ssl=use_ssl,
        verify_ssl=verify_ssl,
        api_max_stage=ApiStage.parse(values.get("api_max_stage", "read-only")),
    )


def obtain_password(environment_name: str = "PANORAMA_PASSWORD") -> str:
    password = os.environ.get(environment_name)
    if password is None:
        try:
            password = getpass.getpass(
                f"Hasło Panoramy (lub ustaw {environment_name}): "
            )
        except EOFError as exc:
            raise InputError(
                f"Brak wejścia interaktywnego; ustaw zmienną {environment_name}."
            ) from exc
    if not password:
        raise InputError("Hasło Panoramy nie może być puste.")
    return password


@dataclass(frozen=True)
class WriteLease:
    stage: ApiStage
    profile_host: str
    expires_monotonic: float
    nonce: str

    def assert_valid(self, profile: PanoramaProfile, required: ApiStage) -> None:
        self.assert_recovery_valid(profile, required)
        if time.monotonic() >= self.expires_monotonic:
            raise CapabilityError("Krótkotrwały lease zapisu wygasł.")

    def assert_recovery_valid(
        self, profile: PanoramaProfile, required: ApiStage
    ) -> None:
        """Validate identity/stage for rollback and lock cleanup.

        Recovery belongs to an operation that was admitted while the lease was
        live.  Expiry must stop *new* forward writes, but it must never strand a
        partial candidate mutation or an owned config lock.
        """

        if self.profile_host != profile.host:
            raise CapabilityError("Lease zapisu wydano dla innej Panoramy.")
        if required.rank > self.stage.rank:
            raise CapabilityError(
                f"Operacja wymaga etapu {required.value}, lease pozwala na {self.stage.value}."
            )


def issue_write_lease(
    profile: PanoramaProfile,
    requested: ApiStage,
    *,
    enable_api_write: bool,
    ttl_seconds: int = 900,
) -> WriteLease:
    if requested is ApiStage.READ_ONLY:
        raise CapabilityError("Tryb read-only nie potrzebuje lease zapisu.")
    if not enable_api_write:
        raise CapabilityError(
            "Zapis API wymaga jawnego --enable-api-write/przełącznika bieżącej sesji."
        )
    if requested.rank > profile.api_max_stage.rank:
        raise CapabilityError(
            f"Profil pozwala maksymalnie na {profile.api_max_stage.value}, "
            f"żądano {requested.value}."
        )
    if ttl_seconds < 30 or ttl_seconds > 3600:
        raise InputError("TTL lease zapisu musi być w zakresie 30..3600 sekund.")
    return WriteLease(
        stage=requested,
        profile_host=profile.host,
        expires_monotonic=time.monotonic() + ttl_seconds,
        nonce=secrets.token_urlsafe(24),
    )
