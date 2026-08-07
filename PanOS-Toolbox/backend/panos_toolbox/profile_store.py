"""Encrypted, per-user Panorama profiles and the durable Toolbox data root.

Windows uses DPAPI with the current user's logon key.  A profile file can
therefore be copied as a backup without exposing the password, but it is not
portable to another Windows account.  Non-Windows development environments use
Fernet when the optional ``cryptography`` package is available; production
portable builds target Windows and use the operating-system primitive.
"""

from __future__ import annotations

import base64
import ctypes
import getpass
import json
import os
import re
import secrets
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from .errors import InputError, SessionError
from .models import ApiStage, json_sha256
from .profile import PanoramaProfile, normalize_host


PROFILE_SCHEMA_VERSION = 1
PROFILE_ID_RE = re.compile(r"^profile-[A-Za-z0-9_-]{8,64}$")


class ProfileStoreError(SessionError):
    """Profile storage or encryption failed without exposing secret values."""


def _windows_documents() -> Optional[Path]:
    if os.name != "nt":
        return None
    try:
        class _Guid(ctypes.Structure):
            _fields_ = [
                ("data1", ctypes.c_ulong),
                ("data2", ctypes.c_ushort),
                ("data3", ctypes.c_ushort),
                ("data4", ctypes.c_ubyte * 8),
            ]

        # FOLDERID_Documents = {FDD39AD0-238F-46AF-ADB4-6C85480369C7}
        guid = _Guid(
            0xFDD39AD0,
            0x238F,
            0x46AF,
            (ctypes.c_ubyte * 8)(0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7),
        )
        shell32 = ctypes.windll.shell32
        shell32.SHGetKnownFolderPath.argtypes = [
            ctypes.POINTER(_Guid),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar_p),
        ]
        shell32.SHGetKnownFolderPath.restype = ctypes.c_int
        pointer = ctypes.c_wchar_p()
        result = shell32.SHGetKnownFolderPath(
            ctypes.byref(guid), 0, None, ctypes.byref(pointer)
        )
        if result == 0 and pointer.value:
            path = Path(pointer.value)
            ctypes.windll.ole32.CoTaskMemFree(pointer)
            return path
    except (AttributeError, OSError, TypeError, ValueError):
        pass
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        return Path(user_profile) / "Documents"
    return Path.home() / "Documents"


def default_toolbox_root() -> Path:
    """Return the stable per-user data directory used by GUI and launchers."""

    override = os.environ.get("PANOS_TOOLBOX_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    documents = _windows_documents() or Path.home() / "Documents"
    return (documents / "PanOS Toolbox").resolve()


def _secure_directory(path: Path, *, enforce: bool) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        if enforce:
            raise ProfileStoreError(f"Nie można ograniczyć uprawnień katalogu {path}.") from exc
    if os.name != "nt" or not enforce:
        return
    domain = os.environ.get("USERDOMAIN")
    username = os.environ.get("USERNAME") or getpass.getuser()
    principal = f"{domain}\\{username}" if domain else username
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    completed = subprocess.run(
        ["icacls", str(path), "/inheritance:r", "/grant:r", f"{principal}:(OI)(CI)F"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        startupinfo=startup,
    )
    if completed.returncode != 0:
        raise ProfileStoreError(f"Nie można ustawić prywatnego ACL katalogu {path}.")


def _atomic_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary, mode)
        except OSError:
            pass
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _dpapi_protect(value: bytes) -> bytes:
    if os.name != "nt":
        raise ProfileStoreError("DPAPI jest dostępne wyłącznie na Windows.")
    buffer = ctypes.create_string_buffer(value)
    source = _DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptProtectData(
        ctypes.byref(source),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(output),
    ):
        raise ProfileStoreError("Windows DPAPI nie zaszyfrowało hasła.")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)


def _dpapi_unprotect(value: bytes) -> bytes:
    if os.name != "nt":
        raise ProfileStoreError(
            "Ten profil został zaszyfrowany przez konto Windows i nie może być "
            "odszyfrowany poza tym środowiskiem."
        )
    buffer = ctypes.create_string_buffer(value)
    source = _DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(output),
    ):
        raise ProfileStoreError(
            "Windows DPAPI nie odszyfrowało profilu; użyj tego samego konta Windows."
        )
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)


class _SecretCipher:
    def __init__(self, root: Path, *, enforce_acl: bool) -> None:
        self.root = root
        self.enforce_acl = enforce_acl

    def encrypt(self, secret: str) -> str:
        if not secret:
            raise InputError("Hasło nie może być puste.")
        raw = secret.encode("utf-8")
        if os.name == "nt":
            encrypted = _dpapi_protect(raw)
            return "dpapi:v1:" + base64.b64encode(encrypted).decode("ascii")
        try:
            from cryptography.fernet import Fernet  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ProfileStoreError(
                "Brak bezpiecznego magazynu sekretów: na Windows wymagany jest DPAPI."
            ) from exc
        key_path = self.root / "profile.key"
        if key_path.exists():
            key = key_path.read_bytes()
        else:
            key = Fernet.generate_key()
            _atomic_write(key_path, key)
        return "fernet:v1:" + Fernet(key).encrypt(raw).decode("ascii")

    def decrypt(self, encoded: str) -> str:
        try:
            scheme, version, payload = encoded.split(":", 2)
            if version != "v1" or not payload:
                raise ValueError
            raw = base64.b64decode(payload.encode("ascii"), validate=True) if scheme == "dpapi" else None
            if scheme == "dpapi":
                return _dpapi_unprotect(raw or b"").decode("utf-8")
            if scheme != "fernet":
                raise ValueError
            from cryptography.fernet import Fernet  # type: ignore[import-not-found]
            key_path = self.root / "profile.key"
            return Fernet(key_path.read_bytes()).decrypt(payload.encode("ascii")).decode("utf-8")
        except ProfileStoreError:
            raise
        except Exception as exc:
            raise ProfileStoreError("Nie można odszyfrować hasła profilu.") from exc


@dataclass(frozen=True)
class StoredProfile:
    id: str
    name: str
    profile: PanoramaProfile
    has_password: bool
    created_at: str
    updated_at: str

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "host": self.profile.host,
            "username": self.profile.username,
            "ssl": self.profile.use_ssl,
            "verify_ssl": self.profile.verify_ssl,
            "api_max_stage": self.profile.api_max_stage.value,
            "has_password": self.has_password,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class ProfileStore:
    """Atomic profile file with encrypted password fields and private ACL."""

    def __init__(self, root: Optional[Path] = None, *, enforce_acl: bool = True):
        self.root = (root or default_toolbox_root()).expanduser().resolve()
        self.enforce_acl = enforce_acl
        _secure_directory(self.root, enforce=enforce_acl)
        self.path = self.root / "profiles.json"
        self._cipher = _SecretCipher(self.root, enforce_acl=enforce_acl)

    def _read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
            payload = envelope.get("payload")
            if envelope.get("schema_version") != PROFILE_SCHEMA_VERSION or not isinstance(payload, list):
                raise ValueError
            if envelope.get("sha256") != json_sha256({"profiles": payload}):
                raise ValueError
            return [dict(item) for item in payload if isinstance(item, dict)]
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise ProfileStoreError("Nie można odczytać profili PanOS Toolbox.") from exc

    def _write(self, records: list[dict[str, Any]]) -> None:
        payload = {"profiles": records}
        envelope = {
            "schema_version": PROFILE_SCHEMA_VERSION,
            "payload": records,
            "sha256": json_sha256(payload),
        }
        _atomic_write(
            self.path,
            (json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

    @staticmethod
    def _validate_id(profile_id: str) -> str:
        if not PROFILE_ID_RE.fullmatch(profile_id):
            raise InputError("Niepoprawny identyfikator profilu.")
        return profile_id

    @staticmethod
    def _profile_from_record(record: Mapping[str, Any]) -> PanoramaProfile:
        try:
            use_ssl = bool(record["use_ssl"])
            verify_ssl = bool(record["verify_ssl"])
            if not use_ssl and verify_ssl:
                raise ValueError
            return PanoramaProfile(
                host=normalize_host(str(record["host"]), expected_scheme="https" if use_ssl else "http"),
                username=str(record["username"]),
                use_ssl=use_ssl,
                verify_ssl=verify_ssl,
                api_max_stage=ApiStage.parse(str(record.get("api_max_stage", "read-only"))),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProfileStoreError("Profil ma niepoprawne ustawienia połączenia.") from exc

    def _find(self, profile_id: str) -> dict[str, Any]:
        profile_id = self._validate_id(profile_id)
        for record in self._read():
            if record.get("id") == profile_id:
                return record
        raise InputError("Nie znaleziono zapisanego profilu.")

    def list(self) -> list[dict[str, Any]]:
        result = []
        for record in self._read():
            try:
                profile = self._profile_from_record(record)
            except ProfileStoreError:
                continue
            result.append(
                StoredProfile(
                    id=str(record["id"]),
                    name=str(record.get("name") or profile.host),
                    profile=profile,
                    has_password=bool(record.get("password_ciphertext")),
                    created_at=str(record.get("created_at") or ""),
                    updated_at=str(record.get("updated_at") or ""),
                ).public_dict()
            )
        return sorted(result, key=lambda item: (str(item["name"]).casefold(), str(item["id"])))

    def get(self, profile_id: str) -> tuple[PanoramaProfile, str]:
        record = self._find(profile_id)
        ciphertext = record.get("password_ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext:
            raise ProfileStoreError("Zapisany profil nie zawiera hasła.")
        return self._profile_from_record(record), self._cipher.decrypt(ciphertext)

    def save(
        self,
        *,
        profile: PanoramaProfile,
        password: str,
        name: str = "",
        profile_id: Optional[str] = None,
    ) -> dict[str, Any]:
        if not password:
            raise InputError("Hasło nie może być puste.")
        if profile_id:
            profile_id = self._validate_id(profile_id)
        records = self._read()
        existing = next((item for item in records if item.get("id") == profile_id), None)
        if profile_id and existing is None:
            raise InputError("Nie znaleziono profilu do aktualizacji.")
        identifier = profile_id or "profile-" + secrets.token_urlsafe(10).replace("=", "")
        now = _utc_now()
        record = {
            "id": identifier,
            "name": (name.strip() or (str(existing.get("name")) if existing else profile.host))[:120],
            "host": profile.host,
            "username": profile.username,
            "use_ssl": profile.use_ssl,
            "verify_ssl": profile.verify_ssl,
            "api_max_stage": profile.api_max_stage.value,
            "password_ciphertext": self._cipher.encrypt(password),
            "created_at": str(existing.get("created_at") if existing else now),
            "updated_at": now,
        }
        if existing is None:
            records.append(record)
        else:
            records[records.index(existing)] = record
        self._write(records)
        return next(item for item in self.list() if item["id"] == identifier)

    def delete(self, profile_id: str) -> None:
        profile_id = self._validate_id(profile_id)
        records = self._read()
        remaining = [item for item in records if item.get("id") != profile_id]
        if len(remaining) == len(records):
            raise InputError("Nie znaleziono zapisanego profilu.")
        self._write(remaining)
