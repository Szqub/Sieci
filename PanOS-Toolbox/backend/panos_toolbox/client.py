"""PAN-OS XML API clients with a hard read/write capability boundary."""

from __future__ import annotations

import copy
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Protocol

from .errors import (
    CapabilityError,
    OutcomeUnknownError,
    PanoramaResponseError,
    TransportError,
)
from .models import ApiStage, MutationAction, MutationOperation
from .profile import PanoramaProfile, WriteLease
from .xmlutil import parse_api_response, raw_sha256


class XMLTransport(Protocol):
    def post(
        self,
        params: Mapping[str, str],
        *,
        headers: Mapping[str, str],
        mutating: bool,
    ) -> bytes: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class UrllibXMLTransport:
    """Single-attempt HTTPS transport.

    Mutating POSTs are deliberately never retried.  A timeout after dispatch is
    reported as outcome-unknown so the caller reconciles current state instead
    of replaying a potentially successful operation.
    """

    def __init__(
        self,
        profile: PanoramaProfile,
        *,
        ca_bundle: Optional[str] = None,
        timeout: float = 300.0,
    ) -> None:
        self.profile = profile
        self.timeout = timeout
        if profile.use_ssl and profile.verify_ssl:
            context = ssl.create_default_context(cafile=ca_bundle)
        elif profile.use_ssl:
            context = ssl._create_unverified_context()  # noqa: SLF001 - explicit operator choice
        else:
            context = None
        handlers = [_NoRedirect()]
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self.opener = urllib.request.build_opener(*handlers)

    def post(
        self,
        params: Mapping[str, str],
        *,
        headers: Mapping[str, str],
        mutating: bool,
    ) -> bytes:
        request = urllib.request.Request(
            self.profile.base_url,
            data=urllib.parse.urlencode(params).encode("utf-8"),
            headers={
                "User-Agent": "ByteTech-PanOS-Toolbox/0.7.3",
                "Content-Type": "application/x-www-form-urlencoded",
                **headers,
            },
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise TransportError(
                    "Panorama zwróciła redirect; przerwano, aby nie przekazać poświadczeń."
                ) from exc
            if mutating:
                raise OutcomeUnknownError(
                    f"Mutujący POST zwrócił HTTP {exc.code}; nie można bezpiecznie "
                    "założyć, że Panorama nie zastosowała żądania."
                ) from exc
            raise TransportError(f"Panorama XML API zwróciła HTTP {exc.code}.") from exc
        except (TimeoutError, socket.timeout) as exc:
            if mutating:
                raise OutcomeUnknownError(
                    "Timeout mutującego POST: wynik jest nieznany; żądanie nie zostanie powtórzone."
                ) from exc
            raise TransportError("Timeout odczytu Panorama XML API.") from exc
        except urllib.error.URLError as exc:
            if mutating:
                raise OutcomeUnknownError(
                    "Mutujący POST nie otrzymał jednoznacznej odpowiedzi; wynik jest "
                    "nieznany i wymaga reconciliation."
                ) from exc
            raise TransportError(
                f"Błąd HTTPS/XML API: {type(exc.reason).__name__}."
            ) from exc
        except OSError as exc:
            if mutating:
                raise OutcomeUnknownError(
                    "Mutujący POST zakończył się błędem transportu bez jednoznacznej "
                    "odpowiedzi; wynik wymaga reconciliation."
                ) from exc
            raise TransportError(f"Błąd lokalnego transportu: {type(exc).__name__}.") from exc


@dataclass(frozen=True)
class JobResult:
    job_id: str
    status: str
    result: str
    details: str = ""

    @property
    def succeeded(self) -> bool:
        return self.status == "FIN" and self.result in {"OK", "SUCCESS"}


def _job_id(root: ET.Element) -> Optional[str]:
    value = root.findtext(".//job")
    return value.strip() if value and value.strip().isdigit() else None


class PanoramaReadClient:
    def __init__(self, profile: PanoramaProfile, transport: Optional[XMLTransport] = None):
        self.profile = profile
        self.transport: XMLTransport = transport or UrllibXMLTransport(profile)
        self._api_key: Optional[str] = None
        self._config_cache: dict[str, tuple[float, ET.Element]] = {}
        self._config_cache_proof_sha256: Optional[str] = None
        self._device_group_cache: Optional[tuple[str, ...]] = None

    def _post(self, params: Mapping[str, str], *, mutating: bool = False) -> ET.Element:
        headers = {"X-PAN-KEY": self._api_key} if self._api_key else {}
        payload = self.transport.post(params, headers=headers, mutating=mutating)
        return parse_api_response(payload)

    def authenticate(self, password: str) -> None:
        root = self._post(
            {"type": "keygen", "user": self.profile.username, "password": password}
        )
        key = root.findtext(".//key")
        if not key or not key.strip():
            raise TransportError("Keygen nie zwrócił klucza API.")
        self._api_key = key.strip()

    def assert_authenticated(self) -> None:
        if not self._api_key:
            raise TransportError("Klient XML API nie jest uwierzytelniony.")

    def fetch_config(self, config_type: str) -> ET.Element:
        self.assert_authenticated()
        action = {"running": "show", "candidate": "get"}.get(config_type)
        if action is None:
            raise ValueError("config_type must be running or candidate")
        root = self._post(
            {"type": "config", "action": action, "xpath": "/config"}
        )
        config = parse_api_response(ET.tostring(root), expect_config=True)
        self._config_cache[config_type] = (time.monotonic(), copy.deepcopy(config))
        return config

    def fetch_config_cached(
        self, config_type: str, *, max_age_seconds: float = 300.0
    ) -> ET.Element:
        cached = self._config_cache.get(config_type)
        if cached and time.monotonic() - cached[0] <= max_age_seconds:
            return copy.deepcopy(cached[1])
        return self.fetch_config(config_type)

    def fetch_config_pair_coherent(
        self,
        *,
        max_age_seconds: float = 1800.0,
        copy_cached: bool = True,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> tuple[ET.Element, ET.Element, Optional[ET.Element], bool, Optional[str]]:
        """Return one coherent running/candidate pair with proof-based reuse.

        A TTL alone is not evidence that a huge cached Panorama configuration
        is still current.  The lightweight native change-summary is used as a
        strict cache key.  A first read downloads both trees; later analyses on
        an unchanged candidate reuse them without another /config transfer.
        """

        callback = progress_callback or (lambda _stage, _attempt: None)
        try:
            before_summary = self.change_summary()
        except Exception as exc:
            # Older PAN-OS variants may not expose change-summary.  Read-only
            # analysis may still use the bounded cache; Candidate execution
            # independently performs its fail-closed live preflight.
            cached_before = all(
                kind in self._config_cache
                and time.monotonic() - self._config_cache[kind][0] <= max_age_seconds
                for kind in ("running", "candidate")
            )
            callback("running", 1)
            running = self.fetch_config_cached(
                "running", max_age_seconds=max_age_seconds
            )
            callback("candidate", 1)
            candidate = self.fetch_config_cached(
                "candidate", max_age_seconds=max_age_seconds
            )
            return (
                running,
                candidate,
                None,
                cached_before,
                f"{type(exc).__name__}: {exc}",
            )

        before_proof = raw_sha256(ET.tostring(before_summary, encoding="utf-8"))
        cache_is_fresh = all(
            kind in self._config_cache
            and time.monotonic() - self._config_cache[kind][0] <= max_age_seconds
            for kind in ("running", "candidate")
        )
        if cache_is_fresh and self._config_cache_proof_sha256 == before_proof:
            callback("cache", 0)
            running_cached = self._config_cache["running"][1]
            candidate_cached = self._config_cache["candidate"][1]
            return (
                copy.deepcopy(running_cached) if copy_cached else running_cached,
                copy.deepcopy(candidate_cached) if copy_cached else candidate_cached,
                before_summary,
                True,
                None,
            )

        for attempt in (1, 2):
            callback("running", attempt)
            running = self.fetch_config("running")
            callback("candidate", attempt)
            candidate = self.fetch_config("candidate")
            after_summary = self.change_summary()
            after_proof = raw_sha256(
                ET.tostring(after_summary, encoding="utf-8")
            )
            if before_proof == after_proof:
                self._config_cache_proof_sha256 = after_proof
                return running, candidate, after_summary, False, None
            before_summary = after_summary
            before_proof = after_proof
        self.invalidate_config_cache("running", "candidate")
        raise TransportError(
            "Candidate zmieniał się podczas pobierania snapshotu; spróbuj ponownie po zakończeniu innych zmian."
        )

    def invalidate_config_cache(self, *config_types: str) -> None:
        """Forget cached trees after a local mutation or commit attempt."""

        targets = config_types or tuple(self._config_cache)
        for config_type in targets:
            self._config_cache.pop(config_type, None)
        self._config_cache_proof_sha256 = None

    def fetch_xpath(self, xpath: str, *, config_type: str = "running") -> ET.Element:
        """Read one exact configuration XPath without downloading ``/config``.

        ``show`` reads the active/running tree and ``get`` reads candidate.  The
        returned element deliberately remains the normal PAN-OS response wrapper
        because a targeted XPath may return an entry, a container, or an empty
        result rather than a complete ``<config>`` document.
        """

        self.assert_authenticated()
        action = {"running": "show", "candidate": "get"}.get(config_type)
        if action is None:
            raise ValueError("config_type must be running or candidate")
        if not xpath.startswith("/config/"):
            raise ValueError("targeted xpath must start with /config/")
        return self._post({"type": "config", "action": action, "xpath": xpath})

    def complete_xpath(self, xpath: str) -> ET.Element:
        """Return lightweight XPath completions (used to enumerate DG names)."""

        self.assert_authenticated()
        if not xpath.startswith("/config/"):
            raise ValueError("completion xpath must start with /config/")
        return self._post({"type": "config", "action": "complete", "xpath": xpath})

    def device_group_names(self) -> tuple[str, ...]:
        """Discover device-group names without retrieving their configuration."""

        if self._device_group_cache is not None:
            return self._device_group_cache
        root = self.complete_xpath("/config/devices/entry/device-group/entry")
        names: set[str] = set()
        for element in root.iter():
            if element.tag == "completion":
                raw = element.get("value") or element.get("name") or (element.text or "")
            elif element.tag == "entry" and element.get("name"):
                raw = element.get("name") or ""
            else:
                continue
            value = raw.strip().strip("'\"")
            if value and value not in {"entry", "device-group", "localhost.localdomain"}:
                names.add(value)
        self._device_group_cache = tuple(sorted(names))
        return self._device_group_cache

    def system_info(self) -> ET.Element:
        """Read the real appliance software version, model and system mode."""

        return self.run_op_show(ET.fromstring("<show><system><info /></system></show>"))

    def run_op_show(self, command: ET.Element) -> ET.Element:
        self.assert_authenticated()
        if command.tag != "show":
            raise CapabilityError("Klient read-only pozwala wyłącznie na operacyjne <show>.")
        return self._post(
            {"type": "op", "cmd": ET.tostring(command, encoding="unicode")}
        )

    def change_summary(self) -> ET.Element:
        command = ET.fromstring("<show><config><list><change-summary /></list></config></show>")
        return self.run_op_show(command)

    def show_config_locks(self) -> ET.Element:
        return self.run_op_show(ET.fromstring("<show><config-locks /></show>"))

    def show_commit_locks(self) -> ET.Element:
        return self.run_op_show(ET.fromstring("<show><commit-locks /></show>"))

    def enable_write(self, lease: WriteLease) -> "PanoramaWriteClient":
        lease.assert_valid(self.profile, ApiStage.CANDIDATE)
        if not self._api_key:
            raise TransportError("Najpierw uwierzytelnij klienta read-only.")
        return PanoramaWriteClient(self, lease)

    def close(self) -> None:
        self._api_key = None
        self._config_cache.clear()
        self._config_cache_proof_sha256 = None
        self._device_group_cache = None


class PanoramaWriteClient:
    _locks_guard = threading.Lock()
    _job_locks: dict[str, threading.Lock] = {}
    _active_jobs: dict[str, str] = {}

    def __init__(self, reader: PanoramaReadClient, lease: WriteLease):
        self.reader = reader
        self.profile = reader.profile
        self.lease = lease

    def _assert(self, stage: ApiStage) -> None:
        self.lease.assert_valid(self.profile, stage)

    def _assert_recovery(self, stage: ApiStage) -> None:
        self.lease.assert_recovery_valid(self.profile, stage)

    def _operation_params(self, operation: MutationOperation) -> dict[str, str]:
        params = {
            "type": "config",
            "action": operation.action.value,
            "xpath": operation.xpath,
        }
        if operation.element is not None:
            params["element"] = operation.element
        if operation.where is not None:
            params["where"] = operation.where
        if operation.destination is not None:
            params["dst"] = operation.destination
        return params

    def apply_operation(self, operation: MutationOperation) -> ET.Element:
        self._assert(ApiStage.CANDIDATE)
        try:
            return self.reader._post(self._operation_params(operation), mutating=True)
        finally:
            # Even a transport-ambiguous mutating POST makes a cached candidate
            # unsafe.  A later analysis must read it again.
            self.reader.invalidate_config_cache("candidate")

    def apply_recovery_operation(self, operation: MutationOperation) -> ET.Element:
        """Apply an inverse operation admitted by an already-started transaction."""

        self._assert_recovery(ApiStage.CANDIDATE)
        try:
            return self.reader._post(self._operation_params(operation), mutating=True)
        finally:
            self.reader.invalidate_config_cache("candidate")

    def validate_candidate(self) -> Optional[str]:
        self._assert(ApiStage.CANDIDATE)
        command = ET.fromstring("<validate><full /></validate>")
        root = self.reader._post(
            {"type": "op", "cmd": ET.tostring(command, encoding="unicode")}
        )
        return _job_id(root)

    def save_candidate_snapshot(self, filename: str) -> ET.Element:
        self._assert(ApiStage.CANDIDATE)
        if not filename or len(filename) > 32 or any(char in filename for char in "<>\r\n"):
            raise ValueError("Nazwa snapshotu musi mieć 1–32 znaki i nie może zawierać <, > ani nowej linii.")
        command = ET.Element("save")
        config = ET.SubElement(command, "config")
        ET.SubElement(config, "to").text = filename
        return self.reader._post(
            {"type": "op", "cmd": ET.tostring(command, encoding="unicode")},
            mutating=True,
        )

    def acquire_config_lock(self, device_group: Optional[str], comment: str) -> ET.Element:
        self._assert(ApiStage.CANDIDATE)
        command = ET.fromstring("<request><config-lock><add /></config-lock></request>")
        add = command.find(".//add")
        assert add is not None
        ET.SubElement(add, "comment").text = comment
        params = {"type": "op", "cmd": ET.tostring(command, encoding="unicode")}
        if device_group and device_group != "shared":
            params["vsys"] = device_group
        return self.reader._post(
            params,
            mutating=True,
        )

    def release_config_lock(self, device_group: Optional[str]) -> ET.Element:
        # Releasing an owned lock is a safety cleanup step and must remain
        # possible if a long validation/commit outlives the short lease.
        self._assert_recovery(ApiStage.CANDIDATE)
        command = ET.fromstring("<request><config-lock><remove /></config-lock></request>")
        remove = command.find(".//remove")
        assert remove is not None
        params = {"type": "op", "cmd": ET.tostring(command, encoding="unicode")}
        if device_group and device_group != "shared":
            params["vsys"] = device_group
        return self.reader._post(
            params,
            mutating=True,
        )

    @classmethod
    def _job_lock(cls, host: str) -> threading.Lock:
        with cls._locks_guard:
            return cls._job_locks.setdefault(host, threading.Lock())

    def commit(
        self,
        *,
        partial: bool = True,
        allow_unisolated_commit: bool = False,
        allow_full_commit: bool = False,
    ) -> str:
        self._assert(ApiStage.COMMIT)
        if partial and not allow_unisolated_commit:
            raise CapabilityError(
                "Partial commit administratora może objąć inne jego zmiany; "
                "wymagane --allow-unisolated-commit."
            )
        if not partial and not allow_full_commit:
            raise CapabilityError("Full commit wymaga --allow-full-commit.")
        command = ET.Element("commit")
        if partial:
            partial_node = ET.SubElement(command, "partial")
            admin = ET.SubElement(partial_node, "admin")
            ET.SubElement(admin, "member").text = self.profile.username
        lock = self._job_lock(self.profile.host)
        if not lock.acquire(blocking=False):
            raise CapabilityError("Commit/push dla tej Panoramy jest już wykonywany sekwencyjnie.")
        try:
            # A successful commit changes running; an outcome-unknown commit
            # may have changed it.  In both cases both cached trees are stale.
            self.reader.invalidate_config_cache("running", "candidate")
            params = {"type": "commit", "cmd": ET.tostring(command, encoding="unicode")}
            if partial:
                params["action"] = "partial"
            root = self.reader._post(
                params,
                mutating=True,
            )
            job = _job_id(root)
            if not job:
                raise PanoramaResponseError("Commit nie zwrócił job ID.")
            self._active_jobs[self.profile.host] = job
            return job
        except OutcomeUnknownError:
            # Keep the process-local guard locked.  Reconciliation or process
            # restart is required; replaying commit could overlap a live job.
            self._active_jobs[self.profile.host] = "outcome-unknown"
            raise
        except Exception:
            lock.release()
            raise

    def push(self, device_groups: tuple[str, ...]) -> str:
        self._assert(ApiStage.PUSH)
        if not device_groups:
            raise CapabilityError("Push wymaga co najmniej jednej device group.")
        command = ET.Element("commit-all")
        shared_policy = ET.SubElement(command, "shared-policy")
        ET.SubElement(shared_policy, "include-template").text = "no"
        dg_node = ET.SubElement(shared_policy, "device-group")
        for name in device_groups:
            ET.SubElement(dg_node, "entry", {"name": name})
        lock = self._job_lock(self.profile.host)
        if not lock.acquire(blocking=False):
            raise CapabilityError("Commit/push dla tej Panoramy jest już wykonywany sekwencyjnie.")
        try:
            root = self.reader._post(
                {
                    "type": "commit",
                    "action": "all",
                    "cmd": ET.tostring(command, encoding="unicode"),
                },
                mutating=True,
            )
            job = _job_id(root)
            if not job:
                raise PanoramaResponseError("Push nie zwrócił job ID.")
            self._active_jobs[self.profile.host] = job
            return job
        except OutcomeUnknownError:
            self._active_jobs[self.profile.host] = "outcome-unknown"
            raise
        except Exception:
            lock.release()
            raise

    def poll_job(
        self,
        job_id: str,
        *,
        timeout_seconds: float = 900,
        interval_seconds: float = 2,
        progress_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> JobResult:
        if not job_id.isdigit():
            raise ValueError("job_id musi być liczbą.")
        started = time.monotonic()
        deadline = time.monotonic() + timeout_seconds
        poll_count = 0
        while True:
            poll_count += 1
            show = ET.Element("show")
            jobs = ET.SubElement(show, "jobs")
            ET.SubElement(jobs, "id").text = job_id
            root = self.reader.run_op_show(show)
            job = root.find(".//job")
            if job is None:
                raise PanoramaResponseError(f"Brak job {job_id} w odpowiedzi Panoramy.")
            status = (job.findtext("./status") or "").strip().upper()
            result = (job.findtext("./result") or "").strip().upper()
            details = " ".join(text.strip() for text in job.itertext() if text.strip())[:2000]
            raw_progress = (job.findtext("./progress") or "").strip().rstrip("%")
            panorama_progress: Optional[int]
            try:
                panorama_progress = max(0, min(100, int(float(raw_progress))))
            except (TypeError, ValueError):
                panorama_progress = None
            queued = (job.findtext("./queued") or "").strip().upper() or None
            position_text = (job.findtext("./positionInQ") or "").strip()
            try:
                position_in_queue: Optional[int] = int(position_text)
            except (TypeError, ValueError):
                position_in_queue = None
            elapsed_seconds = round(time.monotonic() - started, 1)
            warnings = " ".join(
                (line.text or "").strip()
                for line in job.findall("./warnings/line")
                if (line.text or "").strip()
            )[:1000]
            progress_event = {
                "event": "panorama-job-finished" if status == "FIN" else "panorama-job-poll",
                "jobId": job_id,
                "status": status or "UNKNOWN",
                "result": result or None,
                "panoramaProgress": panorama_progress,
                "details": details,
                "pollCount": poll_count,
                "elapsedSeconds": elapsed_seconds,
                "jobType": (job.findtext("./type") or "").strip() or None,
                "queued": queued,
                "positionInQueue": position_in_queue,
                "stoppable": (job.findtext("./stoppable") or "").strip() or None,
                "warnings": warnings or None,
                "lastResponseAt": datetime.now(timezone.utc).isoformat().replace(
                    "+00:00", "Z"
                ),
                "longRunning": elapsed_seconds >= 120,
            }
            if progress_callback is not None:
                # UI telemetry must never influence the outcome of a Panorama job.
                try:
                    progress_callback(progress_event)
                except Exception:
                    pass
            if status == "FIN":
                result_value = JobResult(job_id, status, result, details)
                if self._active_jobs.get(self.profile.host) == job_id:
                    self._active_jobs.pop(self.profile.host, None)
                    lock = self._job_lock(self.profile.host)
                    if lock.locked():
                        lock.release()
                return result_value
            if time.monotonic() >= deadline:
                raise TransportError(
                    f"Job {job_id} nie zakończył się przed timeoutem; nie uruchamiaj kolejnego joba."
                )
            time.sleep(interval_seconds)
