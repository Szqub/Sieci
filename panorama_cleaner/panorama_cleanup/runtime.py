"""Input, ICMP, and read-only Panorama XML API runtime services."""

from __future__ import annotations

import concurrent.futures
import getpass
import ipaddress
import os
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Union
from urllib.parse import urlsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import (
    InputError,
    InputRow,
    PingResult,
    PingStatus,
    SnapshotError,
    TransportError,
)
from .panos import parse_api_response


@dataclass(frozen=True)
class HostSettings:
    host: str
    username: str
    verify_ssl: bool


def load_host_settings(path: Path) -> HostSettings:
    if not path.is_file():
        raise InputError(f"Brak pliku ustawień Panoramy: {path}")
    values: Dict[str, str] = {}
    for line_number, raw in enumerate(_read_input_text(path).splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise InputError(f"{path}:{line_number}: oczekiwano klucz=wartość.")
        key, value = (part.strip() for part in stripped.split("=", 1))
        if key not in {"host", "username", "ssl"}:
            raise InputError(f"{path}:{line_number}: nieznany klucz {key!r}.")
        if not value:
            raise InputError(f"{path}:{line_number}: pusta wartość {key}.")
        if key in values:
            raise InputError(f"{path}:{line_number}: zduplikowany klucz {key}.")
        values[key] = value
    missing = {"host", "username"} - values.keys()
    if missing:
        raise InputError(f"W {path} brakuje: {', '.join(sorted(missing))}.")
    ssl_value = values.get("ssl", "yes").casefold()
    if ssl_value not in {"yes", "no"}:
        raise InputError(f"W {path} ssl musi mieć wartość yes albo no.")
    host = _normalize_host(values["host"])
    return HostSettings(
        host=host,
        username=values["username"],
        verify_ssl=ssl_value == "yes",
    )


def _normalize_host(value: str) -> str:
    candidate = value.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    if parsed.scheme != "https" or not parsed.hostname:
        raise InputError("host musi być adresem IP/FQDN Panoramy używanym przez HTTPS.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise InputError("host nie może zawierać poświadczeń, query ani fragmentu.")
    if parsed.path not in {"", "/"}:
        raise InputError("host nie może zawierać ścieżki URL.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise InputError("Niepoprawny port hosta.") from exc
    if port and not (1 <= port <= 65535):
        raise InputError("Niepoprawny port hosta.")
    if ":" in parsed.hostname and not parsed.hostname.startswith("["):
        hostname = f"[{parsed.hostname}]"
    else:
        hostname = parsed.hostname
    return f"{hostname}:{port}" if port else hostname


def obtain_password(environment_name: str) -> str:
    password = os.environ.get(environment_name)
    if password is not None:
        if not password:
            raise InputError(f"Zmienna {environment_name} istnieje, ale jest pusta.")
        return password
    try:
        password = getpass.getpass(
            f"Hasło Panoramy (lub ustaw zmienną {environment_name}): "
        )
    except EOFError as exc:
        raise InputError(
            f"Brak interaktywnego wejścia dla hasła; ustaw zmienną {environment_name}."
        ) from exc
    if not password:
        raise InputError("Hasło nie może być puste.")
    return password


def confirm_candidate_diff_checked() -> None:
    """Backward-compatible no-op retained for third-party imports.

    Since 1.6 candidate drift is recorded as review information and never
    requires a typed acknowledgement during read-only plan generation.
    """

    return None


def validate_ca_bundle(value: Optional[str]) -> Optional[str]:
    """Return an absolute CA path or fail before any ICMP/network activity."""

    if value is None:
        return None
    candidate = Path(value).expanduser()
    try:
        if not candidate.is_file():
            raise InputError(f"CA bundle nie jest plikiem: {candidate}")
        return str(candidate.resolve(strict=True))
    except InputError:
        raise
    except OSError as exc:
        raise InputError(f"Nie można odczytać ścieżki CA bundle: {candidate}") from exc


def _read_input_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise InputError(f"Nie można odczytać pliku wejściowego UTF-8: {path}") from exc


def load_ip_rows(path: Path) -> List[InputRow]:
    if not path.is_file():
        raise InputError(f"Brak pliku wejściowego IP: {path}")
    rows: List[InputRow] = []
    first_lp_by_ip: Dict[str, int] = {}
    logical_lp = 0
    for raw in _read_input_text(path).splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        logical_lp += 1
        try:
            normalized = str(ipaddress.ip_address(stripped))
        except ValueError as exc:
            rows.append(
                InputRow(
                    lp=logical_lp,
                    raw=stripped,
                    normalized=None,
                    valid=False,
                    error=str(exc),
                )
            )
            continue
        duplicate = first_lp_by_ip.get(normalized)
        if duplicate is None:
            first_lp_by_ip[normalized] = logical_lp
        rows.append(
            InputRow(
                lp=logical_lp,
                raw=stripped,
                normalized=normalized,
                valid=True,
                duplicate_of_lp=duplicate,
            )
        )
    if not rows:
        raise InputError(f"Plik {path} nie zawiera żadnej pozycji IP.")
    return rows


def unique_valid_ips(rows: Iterable[InputRow]) -> List[str]:
    return sorted({row.normalized for row in rows if row.valid and row.normalized})


def ping_many(
    ips: Iterable[str],
    *,
    bypass: bool,
    workers: int,
    timeout_ms: int,
    error_retries: int = 2,
    sensitive_environment_names: Iterable[str] = (),
) -> Dict[str, PingResult]:
    ordered = sorted(set(ips))
    if bypass:
        return {
            ip: PingResult(ip, PingStatus.BYPASSED, "ICMP pominięty jawnie", 0.0)
            for ip in ordered
        }
    if workers < 1 or workers > 256:
        raise InputError("--ping-workers musi być w zakresie 1..256.")
    if timeout_ms < 100 or timeout_ms > 60000:
        raise InputError("--ping-timeout-ms musi być w zakresie 100..60000.")
    if error_retries < 0 or error_retries > 5:
        raise InputError("--ping-error-retries musi być w zakresie 0..5.")
    excluded_names = {name.casefold() for name in sensitive_environment_names}
    child_environment = {
        key: value
        for key, value in os.environ.items()
        if key.casefold() not in excluded_names
    }
    results: Dict[str, PingResult] = {}
    attempts = {ip: 0 for ip in ordered}
    elapsed = {ip: 0.0 for ip in ordered}
    pending = ordered
    for attempt_index in range(error_retries + 1):
        # Retry only failed processes and reduce local process pressure. This is
        # especially relevant when Windows launches many ping.exe instances.
        attempt_workers = workers if attempt_index == 0 else min(workers, 8)
        attempt_results = _ping_attempt(
            pending,
            timeout_ms=timeout_ms,
            workers=attempt_workers,
            child_environment=child_environment,
        )
        retry_ips: List[str] = []
        for ip in pending:
            result = attempt_results[ip]
            attempts[ip] += 1
            elapsed[ip] += result.elapsed_seconds
            retryable = (
                result.status == PingStatus.ERROR
                and result.detail != "Program ping nie jest dostępny"
            )
            if retryable and attempt_index < error_retries:
                retry_ips.append(ip)
                continue
            detail = result.detail
            if attempts[ip] > 1:
                if result.status == PingStatus.ERROR:
                    detail += f"; błąd utrzymał się po {attempts[ip]} próbach"
                else:
                    detail += f"; wynik uzyskano w próbie {attempts[ip]}"
            results[ip] = PingResult(
                ip,
                result.status,
                detail,
                elapsed[ip],
            )
        pending = retry_ips
        if not pending:
            break
    return {ip: results[ip] for ip in ordered}


def _ping_attempt(
    ips: Iterable[str],
    *,
    timeout_ms: int,
    workers: int,
    child_environment: Mapping[str, str],
) -> Dict[str, PingResult]:
    ordered = sorted(set(ips))
    results: Dict[str, PingResult] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_ping_one, ip, timeout_ms, child_environment): ip
            for ip in ordered
        }
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                results[ip] = future.result()
            except Exception as exc:  # defensive boundary around worker process launch
                results[ip] = PingResult(
                    ip,
                    PingStatus.ERROR,
                    f"Nieoczekiwany błąd ICMP: {type(exc).__name__}",
                    0.0,
                )
    return {ip: results[ip] for ip in ordered}


def _ping_one(
    ip: str,
    timeout_ms: int,
    child_environment: Mapping[str, str],
) -> PingResult:
    parsed = ipaddress.ip_address(ip)
    if os.name == "nt":
        command = ["ping", "-n", "1", "-w", str(timeout_ms)]
        if parsed.version == 6:
            command.append("-6")
        command.append(ip)
    else:
        timeout_seconds = max(1, (timeout_ms + 999) // 1000)
        command = ["ping", "-n", "-c", "1", "-W", str(timeout_seconds)]
        if parsed.version == 6:
            command.append("-6")
        command.append(ip)
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=(timeout_ms / 1000.0) + 3.0,
            check=False,
            env=child_environment,
        )
    except FileNotFoundError:
        return PingResult(
            ip,
            PingStatus.ERROR,
            "Program ping nie jest dostępny",
            time.perf_counter() - started,
        )
    except subprocess.TimeoutExpired:
        return PingResult(
            ip,
            PingStatus.ERROR,
            "Proces ping przekroczył limit wykonania",
            time.perf_counter() - started,
        )
    elapsed = time.perf_counter() - started
    if completed.returncode == 0:
        return PingResult(ip, PingStatus.REPLIED, "Odebrano odpowiedź ICMP", elapsed)
    output = b" ".join(
        value
        for value in (completed.stdout, completed.stderr)
        if isinstance(value, bytes)
    ).decode(errors="replace").casefold()
    execution_error_markers = (
        "general failure",
        "transmit failed",
        "could not find host",
        "invalid option",
        "bad value",
        "permission denied",
        "operation not permitted",
        "network is unreachable",
        "błąd ogólny",
        "błąd transmisji",
        "nie można odnaleźć hosta",
        "nie może odnaleźć hosta",
        "odmowa dostępu",
        "brak uprawnień",
        "sieć jest nieosiągalna",
    )
    if completed.returncode != 1 or any(
        marker in output for marker in execution_error_markers
    ):
        return PingResult(
            ip,
            PingStatus.ERROR,
            f"Błąd wykonania ICMP (kod {completed.returncode})",
            elapsed,
        )
    return PingResult(
        ip,
        PingStatus.NO_REPLY,
        f"Brak odpowiedzi ICMP (kod {completed.returncode})",
        elapsed,
    )


MAX_XML_RESPONSE_BYTES = 512 * 1024 * 1024


def _read_limited_response(response: requests.Response) -> bytes:
    declared = response.headers.get("Content-Length")
    if declared:
        try:
            declared_size = int(declared)
        except (TypeError, ValueError):
            declared_size = -1
        if declared_size > MAX_XML_RESPONSE_BYTES:
            raise TransportError(
                "Odpowiedź Panorama XML API przekracza bezpieczny limit 512 MiB."
            )

    chunks: List[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=1024 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_XML_RESPONSE_BYTES:
            raise TransportError(
                "Odpowiedź Panorama XML API przekracza bezpieczny limit 512 MiB."
            )
        chunks.append(chunk)
    return b"".join(chunks)


class PanoramaXMLAPI:
    """Read-only XML API client; the API key exists in memory only."""

    def __init__(
        self,
        host: str,
        username: str,
        *,
        verify: Union[bool, str] = True,
        connect_timeout: float = 10.0,
        read_timeout: float = 300.0,
    ) -> None:
        self.host = host
        self.username = username
        self.base_url = f"https://{host}/api/"
        self.verify = verify
        self.timeout = (connect_timeout, read_timeout)
        self.session = requests.Session()
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            status=2,
            backoff_factor=0.5,
            status_forcelist=(429, 502, 503, 504),
            allowed_methods=frozenset({"POST"}),
            raise_on_status=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.headers.update({"User-Agent": "ByteTech-Panorama-Cleanup/1.0"})
        self._authenticated = False
        self.snapshot_call_count = 0
        self.operational_call_count = 0
        if verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def authenticate(self, password: str) -> None:
        payload = self._post(
            {"type": "keygen", "user": self.username, "password": password},
            authenticated=False,
        )
        root = parse_api_response(payload)
        key = root.findtext(".//key")
        if not key or not key.strip():
            raise TransportError("Panorama nie zwróciła klucza API po poprawnym keygen.")
        self.session.headers["X-PAN-KEY"] = key.strip()
        self._authenticated = True

    def fetch_config(self, action: str):
        if action not in {"show", "get"}:
            raise ValueError("action must be show (running) or get (candidate)")
        payload = self._post(
            {"type": "config", "action": action, "xpath": "/config"},
            authenticated=True,
        )
        self.snapshot_call_count += 1
        return parse_api_response(payload, expect_config=True)

    def run_op_show(self, command: ET.Element) -> ET.Element:
        """Execute one authenticated, read-only operational show command."""

        if command.tag != "show":
            raise ValueError("Dozwolone są wyłącznie operacyjne komendy <show>.")
        self.operational_call_count += 1
        payload = self._post(
            {
                "type": "op",
                "cmd": ET.tostring(command, encoding="unicode"),
            },
            authenticated=True,
        )
        return parse_api_response(payload)

    def _post(self, data: Dict[str, str], *, authenticated: bool) -> bytes:
        if authenticated and not self._authenticated:
            raise TransportError("Klient XML API nie jest uwierzytelniony.")
        response: Optional[requests.Response] = None
        try:
            response = self.session.post(
                self.base_url,
                data=data,
                verify=self.verify,
                timeout=self.timeout,
                allow_redirects=False,
                stream=True,
            )
            if 300 <= response.status_code < 400:
                raise TransportError(
                    "Panorama XML API zwróciła redirect HTTPS; przerwano, aby nie "
                    "przekazać hasła ani klucza API do innego endpointu."
                )
            response.raise_for_status()
            return _read_limited_response(response)
        except requests.exceptions.SSLError as exc:
            raise TransportError(
                "Weryfikacja TLS Panoramy nie powiodła się. Użyj --ca-bundle "
                "albo ustaw ssl=no w panorama_host.txt tylko po świadomej decyzji."
            ) from exc
        except requests.RequestException as exc:
            raise TransportError(
                f"Błąd HTTPS/XML API Panoramy: {type(exc).__name__}"
            ) from exc
        except OSError as exc:
            raise TransportError(
                f"Błąd lokalnego transportu HTTPS/XML API: {type(exc).__name__}"
            ) from exc
        finally:
            if response is not None:
                response.close()

    def close(self) -> None:
        self.session.headers.pop("X-PAN-KEY", None)
        self.session.close()
        self._authenticated = False

    def __enter__(self) -> "PanoramaXMLAPI":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
