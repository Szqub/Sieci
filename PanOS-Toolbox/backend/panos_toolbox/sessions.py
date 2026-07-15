"""Durable, integrity-checked operation sessions and append-only journal."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import secrets
import stat
import subprocess
import tempfile
import re
from contextlib import contextmanager
from dataclasses import dataclass
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from .errors import IntegrityError, SessionError
from .models import Mutation, PatchSet, SessionState, canonical_json, json_sha256, utc_now
from .profile import PanoramaProfile
from .xmlutil import raw_sha256


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class AppliedCleanup:
    """Integrity-checked view of mutations actually written by one cleanup."""

    session_id: str
    revision: tuple[Any, ...]
    applied_utc: str
    state: SessionState
    patchset: PatchSet
    mutations: tuple[Mutation, ...]
    inventory: Mapping[str, Any]


def default_session_root() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / "PanOSToolbox" / "sessions"
    return Path.home() / ".local" / "share" / "PanOSToolbox" / "sessions"


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


def _envelope(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "payload": payload,
        "sha256": json_sha256(payload),
    }


def _encode_envelope(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(_envelope(payload), ensure_ascii=False, indent=2, sort_keys=True).encode(
        "utf-8"
    ) + b"\n"


def _decode_envelope(path: Path) -> dict[str, Any]:
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"Nie można odczytać artefaktu sesji: {path}.") from exc
    if envelope.get("schema_version") != SCHEMA_VERSION:
        raise IntegrityError(f"Nieobsługiwany schema_version w {path}.")
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or envelope.get("sha256") != json_sha256(payload):
        raise IntegrityError(f"Suma integralności artefaktu jest błędna: {path}.")
    return payload


def _harden_directory(path: Path, *, enforce: bool) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        if enforce:
            raise SessionError(f"Nie można ograniczyć uprawnień katalogu {path}.") from exc
    if os.name != "nt" or not enforce:
        return
    domain = os.environ.get("USERDOMAIN")
    username = os.environ.get("USERNAME") or getpass.getuser()
    principal = f"{domain}\\{username}" if domain else username
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    completed = subprocess.run(
        [
            "icacls",
            str(path),
            "/inheritance:r",
            "/grant:r",
            f"{principal}:(OI)(CI)F",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        startupinfo=startup,
    )
    if completed.returncode != 0:
        raise SessionError(f"Nie można ustawić prywatnego ACL katalogu {path}.")


_TRANSITIONS: dict[SessionState, set[SessionState]] = {
    SessionState.PLANNED: {
        SessionState.WRITING_CANDIDATE,
        SessionState.RESTORING,
        SessionState.CONFLICT,
        SessionState.FAILED,
        SessionState.OUTCOME_UNKNOWN,
        SessionState.RESTORED,
    },
    SessionState.WRITING_CANDIDATE: {
        SessionState.CANDIDATE_APPLIED,
        SessionState.PARTIAL,
        SessionState.FAILED,
        SessionState.OUTCOME_UNKNOWN,
    },
    SessionState.CANDIDATE_APPLIED: {
        SessionState.COMMITTING,
        SessionState.CONFLICT,
        SessionState.FAILED,
        SessionState.OUTCOME_UNKNOWN,
    },
    SessionState.PARTIAL: {
        SessionState.COMMITTING,
        SessionState.CONFLICT,
        SessionState.FAILED,
        SessionState.OUTCOME_UNKNOWN,
    },
    SessionState.RESTORING: {
        SessionState.RESTORED,
        SessionState.PARTIAL,
        SessionState.CONFLICT,
        SessionState.FAILED,
        SessionState.OUTCOME_UNKNOWN,
    },
    SessionState.RESTORED: {
        SessionState.COMMITTING,
        SessionState.CONFLICT,
        SessionState.FAILED,
        SessionState.OUTCOME_UNKNOWN,
    },
    SessionState.COMMITTING: {
        SessionState.COMMITTED,
        SessionState.FAILED,
        SessionState.OUTCOME_UNKNOWN,
    },
    SessionState.COMMITTED: {
        SessionState.PUSHING,
        SessionState.RESTORING,
        SessionState.CONFLICT,
        SessionState.FAILED,
        SessionState.OUTCOME_UNKNOWN,
    },
    SessionState.PUSHING: {
        SessionState.PUSHED,
        SessionState.FAILED,
        SessionState.OUTCOME_UNKNOWN,
    },
    SessionState.PUSHED: {SessionState.RESTORING, SessionState.FAILED},
    SessionState.CONFLICT: set(),
    SessionState.FAILED: set(),
    SessionState.OUTCOME_UNKNOWN: set(),
}


class SessionStore:
    def __init__(self, root: Optional[Path] = None, *, enforce_acl: bool = True):
        self.root = (root or default_session_root()).expanduser().resolve()
        self.enforce_acl = enforce_acl
        _harden_directory(self.root, enforce=enforce_acl)

    def _directory(self, session_id: str) -> Path:
        if not session_id.startswith("session-") or any(
            char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            for char in session_id
        ):
            raise SessionError("Niepoprawny identyfikator sesji.")
        directory = (self.root / session_id).resolve()
        if directory.parent != self.root:
            raise SessionError("Identyfikator sesji wychodzi poza session store.")
        return directory

    @contextmanager
    def operation_lock(self, session_id: str):
        """Fail-fast cross-process lock for one session state machine."""

        directory = self._directory(session_id)
        if not directory.is_dir():
            raise SessionError(f"Nie istnieje sesja {session_id}.")
        path = directory / ".operation.lock"
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise SessionError(
                "Sesja ma już aktywną operację. Nie wykonano oczekiwania ani replay."
            ) from exc
        try:
            os.write(descriptor, f"pid={os.getpid()} utc={utc_now()}\n".encode("ascii"))
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            yield
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    @contextmanager
    def panorama_job_lock(self, panorama_host: str, session_id: str):
        """Serialize candidate apply/commit/push across sessions and processes.

        A leftover file after a process crash is intentionally fail-closed: the
        preceding job may still be active and must be reconciled manually.
        """

        digest = hashlib.sha256(panorama_host.encode("utf-8")).hexdigest()[:20]
        path = self.root / f".panorama-job-{digest}.lock"
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise SessionError(
                "Dla tej Panoramy trwa albo wymaga reconciliation inny zapis "
                "candidate/commit/push."
            ) from exc
        interrupted_exit = False
        try:
            os.write(
                descriptor,
                f"pid={os.getpid()} host_sha256={digest} utc={utc_now()}\n".encode("ascii"),
            )
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            yield
        except BaseException as exc:
            # KeyboardInterrupt/SystemExit do not inherit from Exception.  If
            # either escapes while the host-wide transaction mutex is held,
            # the process may have sent a mutating request whose result cannot
            # be reconciled locally.  Keep the durable marker fail-closed.
            interrupted_exit = not isinstance(exc, Exception)
            raise
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            retain = interrupted_exit
            try:
                state = self.load_manifest(session_id, verify=False).get("state")
                retain = retain or state in {
                    SessionState.WRITING_CANDIDATE.value,
                    SessionState.RESTORING.value,
                    SessionState.COMMITTING.value,
                    SessionState.PUSHING.value,
                    SessionState.OUTCOME_UNKNOWN.value,
                }
            except BaseException:
                # If durable state itself cannot be read, fail closed and leave
                # the marker for explicit operator reconciliation.
                retain = True
            if not retain:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

    def create(
        self,
        patchset: PatchSet,
        profile: PanoramaProfile,
        *,
        planning_running: Optional[ET.Element] = None,
        planning_candidate: Optional[ET.Element] = None,
        diff_summary: Optional[Mapping[str, Any]] = None,
    ) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        session_id = f"session-{stamp}-{secrets.token_hex(4)}"
        directory = self._directory(session_id)
        _harden_directory(directory, enforce=self.enforce_acl)
        (directory / "journal").mkdir(mode=0o700)
        (directory / "entities").mkdir(mode=0o700)

        patch_payload = patchset.to_dict()
        _atomic_write(directory / "patchset.json", _encode_envelope(patch_payload))
        backups: list[dict[str, Any]] = []
        backup_stamp = datetime.now(timezone.utc).strftime("%d%m%y_%H_%M")
        for mutation in patchset.mutations:
            if mutation.before_xml is None:
                continue
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", mutation.entity_key).strip("._")
            safe_name = (safe_name or mutation.entity_type)[:80]
            relative = (
                f"entities/{safe_name}_{backup_stamp}_{mutation.mutation_id}.xml"
            )
            data = mutation.before_xml.encode("utf-8")
            _atomic_write(directory / relative, data)
            backups.append(
                {
                    "mutation_id": mutation.mutation_id,
                    "entity_type": mutation.entity_type,
                    "entity_key": mutation.entity_key,
                    "xpath": mutation.target_xpath,
                    "file": relative,
                    "sha256": raw_sha256(data),
                }
            )
        now = utc_now()
        manifest: dict[str, Any] = {
            "session_id": session_id,
            "created_utc": now,
            "updated_utc": now,
            "state": SessionState.PLANNED.value,
            "profile": {
                "host": profile.host,
                "username": profile.username,
                "use_ssl": profile.use_ssl,
                "verify_ssl": profile.verify_ssl,
                "api_max_stage": profile.api_max_stage.value,
            },
            "patchset_file": "patchset.json",
            "patchset_sha256": json_sha256(patch_payload),
            "operation_kind": patchset.kind,
            "source_session_id": patchset.source_session_id,
            "source_session_ids": list(patchset.source_session_ids),
            "targets": list(patchset.targets),
            "affected_device_groups": list(patchset.affected_device_groups),
            "touched_xpaths": list(patchset.touched_xpaths),
            "entity_backups": backups,
            "snapshots": {},
            "diff_summary": dict(diff_summary or {}),
            "journal_count": 0,
            "journal_head_sha256": None,
            "jobs": [],
            "conflicts": [],
            "warnings": list(patchset.warnings),
            "risks": [],
            "candidate_application": None,
        }
        self._write_manifest(session_id, manifest)
        if planning_running is not None:
            self.write_snapshot(session_id, "plan_running", planning_running)
        if planning_candidate is not None:
            self.write_snapshot(session_id, "plan_candidate", planning_candidate)
        self.append_event(
            session_id,
            "SESSION_CREATED",
            {"patch_id": patchset.patch_id, "mutation_count": len(patchset.mutations)},
        )
        return session_id

    def _write_manifest(self, session_id: str, manifest: Mapping[str, Any]) -> None:
        _atomic_write(
            self._directory(session_id) / "manifest.json", _encode_envelope(manifest)
        )

    def load_manifest(self, session_id: str, *, verify: bool = True) -> dict[str, Any]:
        directory = self._directory(session_id)
        manifest = _decode_envelope(directory / "manifest.json")
        if manifest.get("session_id") != session_id:
            raise IntegrityError("Manifest wskazuje inny session_id.")
        if verify:
            self.verify(session_id, manifest=manifest)
        return manifest

    def load_patchset(self, session_id: str) -> PatchSet:
        manifest = self.load_manifest(session_id, verify=False)
        payload = _decode_envelope(self._directory(session_id) / manifest["patchset_file"])
        if json_sha256(payload) != manifest.get("patchset_sha256"):
            raise IntegrityError("PatchSet nie odpowiada sumie zapisanej w manifeście.")
        return PatchSet.from_dict(payload)

    def update(
        self, session_id: str, callback: Callable[[dict[str, Any]], None]
    ) -> dict[str, Any]:
        manifest = self.load_manifest(session_id, verify=False)
        callback(manifest)
        manifest["updated_utc"] = utc_now()
        self._write_manifest(session_id, manifest)
        return manifest

    def transition(self, session_id: str, new_state: SessionState) -> dict[str, Any]:
        def change(manifest: dict[str, Any]) -> None:
            try:
                current = SessionState(manifest["state"])
            except (KeyError, ValueError) as exc:
                raise IntegrityError("Manifest ma niepoprawny stan sesji.") from exc
            if new_state not in _TRANSITIONS[current]:
                raise SessionError(
                    f"Niedozwolone przejście sesji: {current.value} -> {new_state.value}."
                )
            manifest["state"] = new_state.value

        manifest = self.update(session_id, change)
        self.append_event(session_id, "STATE_CHANGED", {"state": new_state.value})
        return manifest

    def force_terminal_state(
        self, session_id: str, state: SessionState, *, detail: str
    ) -> None:
        if state not in {
            SessionState.FAILED,
            SessionState.OUTCOME_UNKNOWN,
            SessionState.CONFLICT,
        }:
            raise ValueError("force_terminal_state accepts only terminal failure states")

        def change(manifest: dict[str, Any]) -> None:
            manifest["state"] = state.value
            manifest.setdefault("warnings", []).append(detail)

        self.update(session_id, change)
        self.append_event(session_id, "TERMINAL_STATE", {"state": state.value, "detail": detail})

    def record_recoverable_stage_failure(
        self,
        session_id: str,
        *,
        stable_state: SessionState,
        detail: str,
    ) -> None:
        """Return a failed commit/push job to the last known-safe state."""

        allowed = {
            SessionState.COMMITTING: {
                SessionState.CANDIDATE_APPLIED,
                SessionState.PARTIAL,
                SessionState.RESTORED,
            },
            SessionState.PUSHING: {SessionState.COMMITTED},
        }

        def change(manifest: dict[str, Any]) -> None:
            try:
                current = SessionState(manifest["state"])
            except (KeyError, ValueError) as exc:
                raise IntegrityError("Manifest ma niepoprawny stan sesji.") from exc
            if stable_state not in allowed.get(current, set()):
                raise SessionError(
                    f"Nie można wrócić po błędzie {current.value} do {stable_state.value}."
                )
            manifest["state"] = stable_state.value
            manifest.setdefault("warnings", []).append(detail)
            manifest.setdefault("stage_failures", []).append(
                {
                    "from_state": current.value,
                    "stable_state": stable_state.value,
                    "detail": detail,
                    "recorded_utc": utc_now(),
                }
            )

        self.update(session_id, change)
        self.append_event(
            session_id,
            "STAGE_FAILED_RECOVERABLE",
            {"state": stable_state.value, "detail": detail},
        )

    def write_snapshot(self, session_id: str, label: str, config: ET.Element) -> dict[str, Any]:
        if not label.replace("_", "").isalnum():
            raise SessionError("Niepoprawna etykieta snapshotu.")
        data = ET.tostring(config, encoding="utf-8")
        relative = f"{label}.xml"
        _atomic_write(self._directory(session_id) / relative, data)
        record = {"file": relative, "sha256": raw_sha256(data), "written_utc": utc_now()}

        def change(manifest: dict[str, Any]) -> None:
            manifest.setdefault("snapshots", {})[label] = record

        self.update(session_id, change)
        return record

    def load_snapshot(self, session_id: str, label: str) -> ET.Element:
        manifest = self.load_manifest(session_id)
        record = (manifest.get("snapshots") or {}).get(label)
        if not isinstance(record, dict):
            raise SessionError(f"Sesja nie zawiera snapshotu {label}.")
        path = (self._directory(session_id) / str(record.get("file", ""))).resolve()
        if self._directory(session_id) not in path.parents:
            raise SessionError("Snapshot wychodzi poza katalog sesji.")
        try:
            return ET.fromstring(path.read_bytes())
        except (OSError, ET.ParseError) as exc:
            raise IntegrityError(f"Nie można odczytać snapshotu {label}.") from exc

    def append_event(
        self, session_id: str, event_type: str, details: Mapping[str, Any]
    ) -> dict[str, Any]:
        manifest = self.load_manifest(session_id, verify=False)
        sequence = int(manifest.get("journal_count", 0)) + 1
        payload = {
            "sequence": sequence,
            "timestamp_utc": utc_now(),
            "event_type": event_type,
            "details": dict(details),
            "previous_sha256": manifest.get("journal_head_sha256"),
        }
        event_hash = json_sha256(payload)
        relative = f"journal/{sequence:06d}.json"
        _atomic_write(self._directory(session_id) / relative, _encode_envelope(payload))
        manifest["journal_count"] = sequence
        manifest["journal_head_sha256"] = event_hash
        manifest["updated_utc"] = utc_now()
        self._write_manifest(session_id, manifest)
        return payload

    def add_job(self, session_id: str, stage: str, job: Mapping[str, Any]) -> None:
        def change(manifest: dict[str, Any]) -> None:
            manifest.setdefault("jobs", []).append({"stage": stage, **dict(job)})

        self.update(session_id, change)

    def add_conflicts(self, session_id: str, conflicts: Iterable[Mapping[str, Any]]) -> None:
        records = [dict(item) for item in conflicts]
        self.update(
            session_id,
            lambda manifest: manifest.setdefault("conflicts", []).extend(records),
        )

    def add_risk(self, session_id: str, code: str, detail: str) -> None:
        self.update(
            session_id,
            lambda manifest: manifest.setdefault("risks", []).append(
                {"code": code, "detail": detail, "recorded_utc": utc_now()}
            ),
        )

    def record_candidate_application(
        self,
        session_id: str,
        *,
        applied_mutation_ids: Iterable[str],
        skipped_components: Iterable[str],
    ) -> None:
        record = {
            "applied_mutation_ids": list(applied_mutation_ids),
            "skipped_components": sorted(set(skipped_components)),
            "recorded_utc": utc_now(),
        }
        self.update(session_id, lambda manifest: manifest.__setitem__("candidate_application", record))

    def write_artifact(
        self, session_id: str, filename: str, content: str, *, kind: str
    ) -> dict[str, Any]:
        if (
            not filename
            or Path(filename).name != filename
            or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in filename)
        ):
            raise SessionError("Niepoprawna nazwa artefaktu.")
        destination = self._directory(session_id) / filename
        manifest = self.load_manifest(session_id, verify=False)
        if destination.exists() or any(
            record.get("file") == filename for record in manifest.get("artifacts", [])
        ):
            raise SessionError(
                f"Artefakt {filename} już istnieje; raporty sesji są niezmienne."
            )
        data = content.encode("utf-8")
        _atomic_write(destination, data)
        record = {
            "file": filename,
            "kind": kind,
            "sha256": raw_sha256(data),
            "written_utc": utc_now(),
        }
        self.update(
            session_id,
            lambda manifest: manifest.setdefault("artifacts", []).append(record),
        )
        return record

    def verify(
        self, session_id: str, *, manifest: Optional[dict[str, Any]] = None
    ) -> None:
        manifest = manifest or self.load_manifest(session_id, verify=False)
        directory = self._directory(session_id)
        patch = _decode_envelope(directory / manifest["patchset_file"])
        if json_sha256(patch) != manifest.get("patchset_sha256"):
            raise IntegrityError("Błędna suma PatchSet.")
        for record in manifest.get("entity_backups", []):
            path = (directory / record["file"]).resolve()
            if directory not in path.parents or raw_sha256(path.read_bytes()) != record["sha256"]:
                raise IntegrityError(f"Błędna integralność backupu {record.get('entity_key')}.")
        for label, record in manifest.get("snapshots", {}).items():
            path = (directory / record["file"]).resolve()
            if directory not in path.parents or raw_sha256(path.read_bytes()) != record["sha256"]:
                raise IntegrityError(f"Błędna integralność snapshotu {label}.")
        for record in manifest.get("artifacts", []):
            path = (directory / record["file"]).resolve()
            if directory not in path.parents or raw_sha256(path.read_bytes()) != record["sha256"]:
                raise IntegrityError(f"Błędna integralność artefaktu {record['file']}.")
        previous = None
        count = int(manifest.get("journal_count", 0))
        for sequence in range(1, count + 1):
            event = _decode_envelope(directory / "journal" / f"{sequence:06d}.json")
            if event.get("sequence") != sequence or event.get("previous_sha256") != previous:
                raise IntegrityError("Łańcuch journalu sesji jest przerwany.")
            previous = json_sha256(event)
        if previous != manifest.get("journal_head_sha256"):
            raise IntegrityError("Head journalu nie odpowiada manifestowi.")

    def _list_sessions(self, *, strict: bool) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for directory in sorted(self.root.glob("session-*"), reverse=True):
            try:
                manifest = self.load_manifest(directory.name)
            except (SessionError, OSError):
                if strict:
                    raise
                continue
            result.append(
                {
                    key: manifest.get(key)
                    for key in (
                        "session_id",
                        "created_utc",
                        "updated_utc",
                        "state",
                        "operation_kind",
                        "targets",
                        "affected_device_groups",
                    )
                }
            )
        return result

    def list_sessions(self) -> list[dict[str, Any]]:
        """Best-effort list for the GUI; corrupt entries are omitted."""

        return self._list_sessions(strict=False)

    def list_sessions_strict(self) -> list[dict[str, Any]]:
        """Integrity-strict enumeration used by restore safety decisions."""

        return self._list_sessions(strict=True)

    @staticmethod
    def manifest_revision(manifest: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            manifest.get("updated_utc"),
            manifest.get("state"),
            manifest.get("journal_head_sha256"),
            json_sha256(manifest.get("candidate_application") or {}),
        )

    def load_applied_cleanup(self, session_id: str) -> AppliedCleanup:
        manifest = self.load_manifest(session_id)
        if manifest.get("operation_kind") != "cleanup":
            raise SessionError(f"Sesja {session_id} nie jest cleanupem.")
        try:
            state = SessionState(str(manifest.get("state")))
        except ValueError as exc:
            raise SessionError(f"Sesja {session_id} ma niepoprawny stan.") from exc
        if state not in {
            SessionState.CANDIDATE_APPLIED,
            SessionState.PARTIAL,
            SessionState.COMMITTED,
            SessionState.PUSHED,
        }:
            raise SessionError(
                f"Sesja cleanup {session_id} nie ma stabilnego zastosowanego stanu."
            )
        application = manifest.get("candidate_application")
        if not isinstance(application, Mapping):
            raise SessionError(
                f"Sesja cleanup {session_id} nie zapisuje wyniku candidate apply."
            )
        applied_ids = tuple(
            str(item) for item in application.get("applied_mutation_ids", ())
        )
        if len(applied_ids) != len(set(applied_ids)):
            raise IntegrityError(
                f"Sesja {session_id} powtarza applied_mutation_ids."
            )
        patchset = self.load_patchset(session_id)
        known = {mutation.mutation_id: mutation for mutation in patchset.mutations}
        unknown = sorted(set(applied_ids) - set(known))
        if unknown:
            raise IntegrityError(
                f"Sesja {session_id} wskazuje nieznane zastosowane mutacje: "
                + ", ".join(unknown)
            )
        mutations = tuple(known[item] for item in applied_ids)
        if not mutations:
            raise SessionError(
                f"Sesja cleanup {session_id} nie zawiera zastosowanych mutacji."
            )
        inventory = manifest.get("inventory")
        if not isinstance(inventory, Mapping):
            inventory = {}
        return AppliedCleanup(
            session_id=session_id,
            revision=self.manifest_revision(manifest),
            applied_utc=str(application.get("recorded_utc") or manifest["updated_utc"]),
            state=state,
            patchset=patchset,
            mutations=mutations,
            inventory=inventory,
        )

    def iter_applied_cleanup_history(
        self, host: str, username: str
    ) -> tuple[AppliedCleanup, ...]:
        history: list[AppliedCleanup] = []
        for item in self.list_sessions_strict():
            session_id = str(item.get("session_id") or "")
            if not session_id or item.get("operation_kind") != "cleanup":
                continue
            if item.get("state") not in {
                SessionState.CANDIDATE_APPLIED.value,
                SessionState.PARTIAL.value,
                SessionState.COMMITTED.value,
                SessionState.PUSHED.value,
            }:
                continue
            cleanup = self.load_applied_cleanup(session_id)
            if (
                cleanup.patchset.panorama_host == host
                and cleanup.patchset.panorama_username == username
            ):
                history.append(cleanup)
        return tuple(
            sorted(history, key=lambda item: (item.applied_utc, item.session_id))
        )

    def verify_cleanup_revisions(
        self, expected: Mapping[str, tuple[Any, ...]]
    ) -> None:
        for session_id, revision in expected.items():
            current = self.load_manifest(session_id)
            if self.manifest_revision(current) != revision:
                raise SessionError(
                    f"Źródłowa sesja {session_id} zmieniła stan podczas planowania "
                    "restore; uruchom plan ponownie."
                )

    def find_by_target(self, target: str) -> list[dict[str, Any]]:
        return [item for item in self.list_sessions() if target in (item.get("targets") or [])]

    def resolve_download(self, session_id: str, filename: str) -> Path:
        if Path(filename).name != filename:
            raise SessionError("Niepoprawna nazwa pobieranego artefaktu.")
        manifest = self.load_manifest(session_id)
        allowed = {"manifest.json", manifest["patchset_file"]}
        allowed.update(record["file"] for record in manifest.get("snapshots", {}).values())
        allowed.update(record["file"] for record in manifest.get("artifacts", []))
        # Entity XML lives one directory deeper and is addressed by its exact
        # manifest-relative path through the dedicated backup endpoint later;
        # generic filename downloads intentionally stay flat.
        if filename not in allowed:
            raise SessionError("Artefakt nie jest zarejestrowany w manifeście sesji.")
        path = (self._directory(session_id) / filename).resolve()
        if self._directory(session_id) not in path.parents or not path.is_file():
            raise SessionError("Artefakt nie istnieje lub wychodzi poza sesję.")
        return path
