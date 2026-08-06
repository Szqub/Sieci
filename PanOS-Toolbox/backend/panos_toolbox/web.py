"""Loopback-only Flask adapter for the React GUI."""

from __future__ import annotations

import ipaddress
import json
import secrets
import threading
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from .client import PanoramaReadClient
from .diffing import compare_configs
from .doctor import run_doctor
from .engine import apply_candidate, commit_session, push_session
from .errors import (
    CapabilityError,
    ConflictError,
    InputError,
    IntegrityError,
    OutcomeUnknownError,
    ToolboxError,
)
from .models import ApiStage
from .profile import PanoramaProfile, load_profile, normalize_host
from .service import (
    make_writer,
    normalize_ips,
    ping_ips,
    plan_cleanup_session,
    plan_restore_session,
)
from .sessions import SessionStore
from .xmlutil import device_group_from_xpath


def _wire_diff(value: dict[str, Any]) -> dict[str, Any]:
    native = value.get("native") or {}
    semantic = value.get("semantic") or {}
    semantic_entries = sum(
        len(semantic.get(key) or ()) for key in ("added", "removed", "changed")
    )
    native_changed = bool(native.get("has_changes"))
    semantic_changed = bool(semantic.get("has_changes"))
    return {
        "nativeChanged": native_changed,
        "semanticChanged": semantic_changed,
        "nativeEntries": 1 if native_changed else 0,
        "semanticEntries": semantic_entries,
        "summary": (
            "Running i candidate różnią się; informacja nie blokuje planu."
            if native_changed or semantic_changed
            else "Running i candidate są zgodne w analizowanym zakresie."
        ),
        "diagnosticMismatch": native.get("has_changes") is not None
        and native_changed != semantic_changed,
    }


def _scope_for_mutation(mutation) -> tuple[str, str]:
    if mutation.target_xpath.startswith("/config/shared/"):
        return "shared", "shared"
    dg = device_group_from_xpath(mutation.target_xpath) or "unknown"
    return dg, dg


def _wire_operations(patch) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    order = 0
    for mutation in patch.mutations:
        scope, dg = _scope_for_mutation(mutation)
        for op_index, operation in enumerate(mutation.forward, 1):
            order += 1
            entity_type = (
                "member"
                if "member" in mutation.entity_type
                else "address-group"
                if mutation.entity_type == "group"
                else mutation.entity_type
            )
            records.append(
                {
                    "id": f"{mutation.mutation_id}-{op_index}",
                    "componentId": mutation.component_id,
                    "order": order,
                    "action": operation.action.value,
                    "entityType": entity_type,
                    "entityName": mutation.entity_key,
                    "scope": scope,
                    "xpath": operation.xpath,
                    "summary": f"{operation.action.value} {mutation.entity_key}",
                    "inverseSummary": ", ".join(
                        f"{item.action.value} {item.xpath}" for item in mutation.inverse
                    ),
                    "fingerprint": mutation.before_sha256,
                }
            )
    return records


def _wire_session(store: SessionStore, session_id: str) -> dict[str, Any]:
    manifest = store.load_manifest(session_id)
    patch = store.load_patchset(session_id)
    jobs = []
    for index, record in enumerate(manifest.get("jobs", []), 1):
        result = str(record.get("result", "")).upper()
        status = str(record.get("status", "")).upper()
        state = (
            "success"
            if status == "FIN" and result in {"OK", "SUCCESS"}
            else "failed"
            if status == "FIN"
            else "running"
        )
        jobs.append(
            {
                "id": str(record.get("job_id") or record.get("jobId") or f"local-{index}"),
                "kind": "candidate"
                if record.get("stage") == "validation"
                else str(record.get("stage", "candidate")).split("-", 1)[0],
                "state": state,
                "progress": 100 if state in {"success", "failed"} else 50,
                "message": str(record.get("details") or record.get("stage") or ""),
                "startedAt": manifest["created_utc"],
                "finishedAt": (
                    manifest["updated_utc"]
                    if state in {"success", "failed"}
                    else None
                ),
            }
        )
    return {
        "id": session_id,
        "kind": manifest["operation_kind"],
        "state": manifest["state"],
        "createdAt": manifest["created_utc"],
        "updatedAt": manifest["updated_utc"],
        "operator": manifest["profile"]["username"],
        "panoramaHost": manifest["profile"]["host"],
        "itemCount": len(manifest.get("targets") or ()),
        "affectedDeviceGroups": manifest.get("affected_device_groups") or [],
        "sourceSessionId": patch.source_session_id,
        "sourceSessionIds": list(patch.source_session_ids),
        "description": (
            "Emergency Restore" if manifest["operation_kind"] == "restore" else "Cleanup adresów"
        ),
        "jobs": jobs,
    }


def _wire_cleanup_plan(store: SessionStore, session_id: str) -> dict[str, Any]:
    manifest = store.load_manifest(session_id)
    patch = store.load_patchset(session_id)
    ping_by_ip = {item["ip"]: item for item in manifest.get("icmp", [])}
    inventory_by_ip = manifest.get("inventory") or {}
    input_targets = manifest.get("input_targets") or {}
    ordered_targets = (
        input_targets.get("ordered")
        or manifest.get("input_ips")
        or manifest.get("targets")
        or []
    )
    processed = {cause for mutation in patch.mutations for cause in mutation.causes}
    rule_hits: dict[str, dict[str, Any]] = {}
    for record in (manifest.get("last_hit") or {}).get("records", []):
        rule = record["rule"]
        key = f"{rule['location']}/{rule['rulebase']}/{rule['policy_type']}/{rule['name']}"
        rule_hits[key] = record
    addresses = []
    for target in ordered_targets:
        ping = ping_by_ip.get(target, {"status": "BYPASSED", "detail": "ICMP nie dotyczy"})
        ping_state = {
            "REPLIED": "responded",
            "NO_REPLY": "timeout",
            "ERROR": "error",
            "BYPASSED": "not-run",
        }.get(ping.get("status"), "not-run")
        inventory = inventory_by_ip.get(target) or {
            "objects": [],
            "blocked_reasons": [],
        }
        decision = (
            "skip-live"
            if ping_state == "responded"
            else "skip-error"
            if ping_state == "error"
            else "blocked"
            if inventory.get("blocked_reasons")
            else "process"
            if target in processed
            else "not-found"
        )
        related = [mutation for mutation in patch.mutations if target in mutation.causes]
        references = []
        object_names: list[str] = []
        for object_record in inventory.get("objects") or []:
            location = str(object_record.get("location") or "unknown")
            object_name = str(object_record.get("name") or "unknown")
            object_names.append(f"{location}/{object_name}")
            for group in object_record.get("groups") or []:
                group_location = str(group.get("location") or location)
                group_name = str(group.get("name") or "unknown")
                references.append(
                    {
                        "id": f"inventory-group-{target}-{len(references) + 1}",
                        "scope": group_location,
                        "deviceGroup": group_location,
                        "rulebase": "shared" if group_location == "shared" else "local",
                        "policyType": "group",
                        "name": group_name,
                        "field": "static",
                        "path": f"{group_location}/address-group/{group_name}",
                    }
                )
            for policy in object_record.get("policies") or []:
                policy_location = str(policy.get("location") or location)
                rulebase_value = str(policy.get("rulebase") or "")
                references.append(
                    {
                        "id": f"inventory-policy-{target}-{len(references) + 1}",
                        "scope": policy_location,
                        "deviceGroup": policy_location,
                        "rulebase": (
                            "pre"
                            if rulebase_value == "pre-rulebase"
                            else "post"
                            if rulebase_value == "post-rulebase"
                            else "shared"
                            if policy_location == "shared"
                            else "local"
                        ),
                        "policyType": policy.get("policy_type") or "security",
                        "name": policy.get("name") or "unknown",
                        "field": "dependency",
                        "path": (
                            f"{policy_location}/{rulebase_value}/"
                            f"{policy.get('policy_type')}/{policy.get('name')}"
                        ),
                    }
                )
        for mutation in related:
            scope, dg = _scope_for_mutation(mutation)
            policy_type = (
                "security"
                if "/security/" in mutation.target_xpath
                else "nat"
                if "/nat/" in mutation.target_xpath
                else "application-override"
                if "/application-override/" in mutation.target_xpath
                else "group"
                if "group" in mutation.entity_type
                else "object"
            )
            rulebase = (
                "pre"
                if "/pre-rulebase/" in mutation.target_xpath
                else "post"
                if "/post-rulebase/" in mutation.target_xpath
                else "shared"
                if scope == "shared"
                else "local"
            )
            references.append(
                {
                    "id": mutation.mutation_id,
                    "scope": scope,
                    "deviceGroup": dg,
                    "rulebase": rulebase,
                    "policyType": policy_type,
                    "name": mutation.entity_key,
                    "field": mutation.entity_type,
                    "path": mutation.target_xpath,
                }
            )
        related_hit_records = [
            value
            for mutation in related
            for key, value in rule_hits.items()
            if mutation.entity_key == key
        ]
        hit_priority = {
            "RECENT": 7,
            "ERROR": 6,
            "INVALID": 5,
            "NOT_LATEST": 4,
            "NOT_FOUND": 3,
            "NEVER": 2,
            "STALE": 1,
        }
        last_hit_record = max(
            related_hit_records,
            key=lambda item: hit_priority.get(str(item.get("status")), 0),
            default=None,
        )
        addresses.append(
            {
                "ip": target,
                "label": inventory.get("label") or target,
                "targetType": inventory.get("kind") or "ip",
                "objectNames": sorted(
                    set(
                        object_names
                        + [
                            mutation.entity_key
                            for mutation in related
                            if mutation.entity_type == "address"
                        ]
                    )
                ),
                "icmp": ping_state,
                "icmpDetail": ping.get("detail"),
                "decision": decision,
                "lastHit": (last_hit_record or {}).get("last_hit_utc"),
                "lastHitStatus": (last_hit_record or {}).get("status"),
                "lastHitDetail": (last_hit_record or {}).get("detail"),
                "recentLastHit": (last_hit_record or {}).get("status") == "RECENT",
                "componentId": related[0].component_id if related else None,
                "references": references,
            }
        )
    return {
        "id": session_id,
        "sessionId": session_id,
        "createdAt": manifest["created_utc"],
        "state": manifest["state"],
        "sourceCount": len(addresses),
        "processCount": sum(item["decision"] == "process" for item in addresses),
        "skippedLiveCount": sum(item["decision"] == "skip-live" for item in addresses),
        "skippedErrorCount": sum(item["decision"] == "skip-error" for item in addresses),
        "notFoundCount": sum(item["decision"] == "not-found" for item in addresses),
        "recentHitCount": (manifest.get("last_hit") or {}).get("recent_hit_count", 0),
        "affectedDeviceGroups": manifest.get("affected_device_groups") or [],
        "diff": _wire_diff(manifest.get("diff_summary") or {}),
        "warnings": manifest.get("warnings") or [],
        "addresses": addresses,
        "operations": _wire_operations(patch),
    }


def _wire_restore_plan(store: SessionStore, result: dict[str, Any]) -> dict[str, Any]:
    session_id = result["session_id"]
    manifest = store.load_manifest(session_id)
    patch = store.load_patchset(session_id)
    outcome = {
        "RESTORE": "restore",
        "ALREADY_RESTORED": "already-present",
        "CONFLICT": "conflict",
    }
    entities = [
        {
            "id": finding["mutation_id"],
            "componentId": finding["component_id"],
            "type": (
                "member"
                if "member" in str(finding.get("entity_type"))
                else "address-group"
                if finding.get("entity_type") == "group"
                else finding.get("entity_type")
            ),
            "name": finding["entity_key"],
            "scope": (
                "shared"
                if str(finding.get("target_xpath", "")).startswith("/config/shared/")
                else device_group_from_xpath(str(finding.get("target_xpath", "")))
                or "unknown"
            ),
            "outcome": outcome[finding["decision"]],
            "detail": finding["decision"],
        }
        for finding in result["findings"]
    ]
    safe_components = {mutation.component_id for mutation in patch.mutations}
    return {
        "id": session_id,
        "sessionId": session_id,
        "sourceSessionId": result["source_session_id"],
        "sourceSessionIds": result.get("source_session_ids") or [],
        "query": ", ".join(patch.targets),
        "createdAt": manifest["created_utc"],
        "state": manifest["state"],
        "safeComponentCount": len(safe_components),
        "conflictComponentCount": len(result["conflicted_components"]),
        "affectedDeviceGroups": manifest.get("affected_device_groups") or [],
        "entities": entities,
        "warnings": manifest.get("warnings") or [],
        "operations": _wire_operations(patch),
    }


class ConnectionRegistry:
    """Authenticated clients live only in process memory and expire."""

    def __init__(self, ttl_seconds: int = 8 * 3600):
        self.ttl_seconds = ttl_seconds
        self._items: dict[str, tuple[float, PanoramaReadClient]] = {}
        self._lock = threading.Lock()

    def add(self, reader: PanoramaReadClient) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._items[token] = (time.monotonic() + self.ttl_seconds, reader)
        return token

    def get(self, token: Optional[str]) -> PanoramaReadClient:
        if not token:
            raise InputError("Brak nietrwałego X-Toolbox-Session.")
        with self._lock:
            item = self._items.get(token)
            if item is None:
                raise InputError("Nieznany connection token.")
            expires, reader = item
            if time.monotonic() >= expires:
                self._items.pop(token, None)
                reader.close()
                raise InputError("Connection token wygasł; połącz się ponownie.")
            return reader

    def remove(self, token: str) -> None:
        with self._lock:
            item = self._items.pop(token, None)
        if item:
            item[1].close()


def _profile_from_json(value: dict[str, Any]) -> PanoramaProfile:
    host = str(value.get("host", "")).strip()
    username = str(value.get("username", "")).strip()
    if not host or not username:
        raise InputError("Połączenie wymaga host i username.")
    use_ssl = _json_bool(value, "ssl", fallback_key="useSsl", default=True)
    verify_ssl = _json_bool(
        value, "verify_ssl", fallback_key="verifySsl", default=use_ssl
    )
    if not use_ssl and verify_ssl:
        raise InputError("verify_ssl nie może być włączone dla HTTP.")
    return PanoramaProfile(
        host=normalize_host(host, expected_scheme="https" if use_ssl else "http"),
        username=username,
        use_ssl=use_ssl,
        verify_ssl=verify_ssl,
        api_max_stage=ApiStage.parse(
            str(value.get("api_max_stage", value.get("apiMaxStage", "read-only")))
        ),
    )


def _apply_profile_ceiling(
    requested: PanoramaProfile, ceiling: Optional[PanoramaProfile]
) -> tuple[PanoramaProfile, Optional[str]]:
    if ceiling is None:
        return (
            replace(requested, api_max_stage=ApiStage.READ_ONLY),
            "Brak lokalnego panorama_host.txt serwera; GUI ograniczono do read-only.",
        )
    identity_matches = (
        requested.host == ceiling.host
        and requested.username == ceiling.username
        and requested.use_ssl == ceiling.use_ssl
        and requested.verify_ssl == ceiling.verify_ssl
    )
    if not identity_matches:
        return (
            replace(requested, api_max_stage=ApiStage.READ_ONLY),
            "Dane GUI nie odpowiadają lokalnemu profilowi serwera; zapis API wyłączono.",
        )
    effective = min(
        (requested.api_max_stage, ceiling.api_max_stage), key=lambda stage: stage.rank
    )
    warning = None
    if effective != requested.api_max_stage:
        warning = (
            f"Lokalny profil ograniczył żądany etap do {effective.value}."
        )
    return replace(requested, api_max_stage=effective), warning


def _json_bool(
    value: dict[str, Any],
    key: str,
    *,
    fallback_key: Optional[str] = None,
    default: bool,
) -> bool:
    raw = value.get(key, value.get(fallback_key, default) if fallback_key else default)
    if not isinstance(raw, bool):
        raise InputError(f"Pole {key} musi być boolean JSON true/false.")
    return raw


def _contract() -> dict[str, Any]:
    return {
        "name": "PanOS Toolbox local API",
        "version": "v1",
        "basePath": "/api/v1",
        "writeStages": [stage.value for stage in ApiStage],
        "authentication": {
            "connectionTokenHeader": "X-Toolbox-Session",
            "persistence": "memory-only",
        },
        "paths": {
            "POST /connections": "keygen and create memory-only connection",
            "DELETE /connections/current": "destroy current connection",
            "POST /cleanup/plans": "read snapshots, ICMP/last-hit, create PatchSet session",
            "POST /sessions/{id}/candidate": "candidate write with ephemeral gate",
            "POST /sessions/{id}/commit": "sequential partial/full commit job",
            "POST /sessions/{id}/push": "one sequential specific-DG commit-all job",
            "POST /restore/plans": "three-way restore by IP/session",
            "POST /audits": "read-only dependency audit",
            "GET /sessions": "session history",
            "GET /sessions/{id}": "integrity-checked manifest",
        },
    }


def create_app(
    *,
    static_dir: Optional[Path] = None,
    store: Optional[SessionStore] = None,
    profile_ceiling: Optional[PanoramaProfile] = None,
):
    try:
        from flask import Flask, Response, jsonify, request, send_file, send_from_directory
        from werkzeug.exceptions import HTTPException
    except ImportError as exc:  # pragma: no cover - packaging diagnostic
        raise RuntimeError(
            "Brak spakowanego Flask/Werkzeug. Uruchom kompletną paczkę portable "
            "z https://github.com/Szqub/Sieci/releases/latest po użyciu opcji "
            "'Wyodrębnij wszystkie'; nie instaluj zależności przez pip."
        ) from exc

    frontend = (static_dir or Path(__file__).resolve().parent / "static").resolve()
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
    session_store = store or SessionStore()
    connections = ConnectionRegistry()

    @app.before_request
    def localhost_boundary():
        try:
            parsed_host = urlsplit("//" + request.host)
            host_port = parsed_host.port
        except ValueError:
            return jsonify({"code": "InvalidHost", "message": "Niepoprawny Host header."}), 400
        if parsed_host.hostname not in {"127.0.0.1", "localhost"}:
            return jsonify(
                {
                    "code": "InvalidHost",
                    "message": "Host header spoza localhost został odrzucony.",
                }
            ), 400
        if request.path.startswith("/api/") and request.method not in {"GET", "HEAD"}:
            origin = request.headers.get("Origin")
            if not origin:
                return jsonify(
                    {
                        "code": "InvalidOrigin",
                        "message": "Brak wymaganego Origin dla operacji lokalnego GUI.",
                    }
                ), 403
            parsed_origin = urlsplit(origin)
            try:
                valid_origin = (
                    parsed_origin.scheme == "http"
                    and parsed_origin.hostname in {"127.0.0.1", "localhost"}
                    and parsed_origin.port == host_port
                )
            except ValueError:
                valid_origin = False
            if not valid_origin:
                return jsonify(
                    {
                        "code": "InvalidOrigin",
                        "message": "Origin spoza bieżącego localhost został odrzucony.",
                    }
                ), 403
        return None

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        # Deliberately no Access-Control-Allow-Origin: this API is same-origin only.
        return response

    @app.errorhandler(ToolboxError)
    def expected_error(error):
        status = (
            409
            if isinstance(error, (ConflictError, IntegrityError, OutcomeUnknownError))
            or "aktywną operację" in str(error)
            else 403
            if isinstance(error, CapabilityError)
            else 400
        )
        return jsonify(
            {
                "code": type(error).__name__,
                "message": str(error),
                "detail": str(error),
            }
        ), status

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"code": "NotFound", "message": "Nie znaleziono endpointu."}), 404

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(
            {
                "code": type(error).__name__,
                "message": error.description or "Niepoprawne żądanie HTTP.",
            }
        ), error.code or 400

    @app.errorhandler(Exception)
    def unexpected_error(error):
        correlation_id = secrets.token_hex(8)
        app.logger.exception("Unhandled Toolbox error correlation=%s", correlation_id)
        return jsonify(
            {
                "code": "InternalError",
                "message": "Nieoczekiwany błąd backendu; nie wykonuj ponownie zapisu bez sprawdzenia sesji.",
                "correlation_id": correlation_id,
            }
        ), 500

    def body() -> dict[str, Any]:
        value = request.get_json(silent=False)
        if not isinstance(value, dict):
            raise InputError("Body JSON musi być obiektem.")
        return value

    def integer_field(
        value: dict[str, Any],
        key: str,
        *,
        fallback_key: Optional[str] = None,
        default: int,
        minimum: int,
        maximum: int,
    ) -> int:
        raw = value.get(
            key,
            value.get(fallback_key, default) if fallback_key else default,
        )
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise InputError(f"Pole {key} musi być liczbą całkowitą JSON.")
        if not minimum <= raw <= maximum:
            raise InputError(f"Pole {key} musi być w zakresie {minimum}..{maximum}.")
        return raw

    def string_list_field(
        value: dict[str, Any], key: str, *, fallback_key: Optional[str] = None
    ) -> list[str]:
        raw = value.get(key, value.get(fallback_key, ()) if fallback_key else ())
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            raise InputError(f"Pole {key} musi być tablicą tekstów JSON.")
        return raw

    def reader() -> PanoramaReadClient:
        return connections.get(request.headers.get("X-Toolbox-Session"))

    @app.get("/api/health")
    @app.get("/api/v1/health")
    def health():
        return jsonify(
            {"ok": True, "status": "ok", "version": "0.1.1", "bind": "127.0.0.1", "api": "v1"}
        )

    @app.get("/api/v1/meta")
    def meta():
        return jsonify(_contract())

    @app.get("/api/v1/doctor")
    @app.post("/api/v1/doctor")
    def doctor_endpoint():
        probe_profile = None
        if request.method == "POST":
            value = body()
            host = value.get("host")
            if host is not None:
                if not isinstance(host, str) or not host.strip():
                    raise InputError("Pole host diagnostyki musi być niepustym tekstem.")
                use_ssl = _json_bool(value, "ssl", default=True)
                verify_ssl = _json_bool(value, "verify_ssl", default=use_ssl)
                if not use_ssl and verify_ssl:
                    raise InputError("verify_ssl nie może być włączone dla HTTP.")
                probe_profile = PanoramaProfile(
                    host=normalize_host(
                        host, expected_scheme="https" if use_ssl else "http"
                    ),
                    username="doctor-read-only",
                    use_ssl=use_ssl,
                    verify_ssl=verify_ssl,
                    api_max_stage=ApiStage.READ_ONLY,
                )
        return jsonify(
            run_doctor(
                session_dir=session_store.root,
                probe_profile=probe_profile,
                static_dir=frontend,
            )
        )

    @app.post("/api/v1/connections")
    def connect():
        value = body()
        profile, capability_warning = _apply_profile_ceiling(
            _profile_from_json(value), profile_ceiling
        )
        password = value.get("password")
        if not isinstance(password, str) or not password:
            raise InputError("Połączenie wymaga hasła; nie zostanie ono utrwalone.")
        client = PanoramaReadClient(profile)
        try:
            client.authenticate(password)
            password = ""
            running = client.fetch_config("running")
            candidate = client.fetch_config("candidate")
            token = connections.add(client)
            diff = compare_configs(running, candidate, None)
        except Exception:
            client.close()
            raise
        return jsonify(
            {
                "id": "connection-" + secrets.token_hex(6),
                "session_token": token,
                "connectionToken": token,
                "host": profile.host,
                "username": profile.username,
                "panorama_version": running.get("version") or "nieznana",
                "api_max_stage": profile.api_max_stage.value,
                "connected_at": __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ).isoformat(timespec="seconds"),
                "candidate_dirty": bool(diff["semantic"]["has_changes"]),
                "capability_warning": capability_warning,
                "profile": {
                    "host": profile.host,
                    "username": profile.username,
                    "ssl": profile.use_ssl,
                    "verifySsl": profile.verify_ssl,
                    "apiMaxStage": profile.api_max_stage.value,
                },
                "runningVersion": running.get("version"),
                "candidateVersion": candidate.get("version"),
            }
        )

    @app.delete("/api/v1/connections/current")
    def disconnect():
        token = request.headers.get("X-Toolbox-Session")
        if token:
            connections.remove(token)
        return ("", 204)

    @app.get("/api/v1/diff")
    def diff_endpoint():
        client = reader()
        running = client.fetch_config("running")
        candidate = client.fetch_config("candidate")
        try:
            native = client.change_summary()
        except ToolboxError:
            native = None
        return jsonify(compare_configs(running, candidate, native))

    @app.post("/api/v1/cleanup/plan")
    @app.post("/api/v1/cleanup/plans")
    def cleanup_plan():
        value = body()
        result = plan_cleanup_session(
            session_store,
            reader(),
            string_list_field(value, "addresses", fallback_key="ips"),
            address_objects=string_list_field(value, "address_objects"),
            address_groups=string_list_field(value, "address_groups"),
            policies=string_list_field(value, "policies"),
            no_ping=not _json_bool(
                value,
                "run_icmp",
                default=not _json_bool(value, "noPing", default=False),
            ),
            ping_timeout_ms=integer_field(
                value,
                "ping_timeout_ms",
                fallback_key="pingTimeoutMs",
                default=1000,
                minimum=100,
                maximum=60_000,
            ),
            ping_workers=integer_field(
                value,
                "ping_workers",
                fallback_key="pingWorkers",
                default=32,
                minimum=1,
                maximum=128,
            ),
            nat_translation_action=str(
                value.get("nat_translation", value.get("natTranslation", "delete-rule"))
            ),
            recent_hit_days=integer_field(
                value,
                "recent_hit_days",
                fallback_key="recentHitDays",
                default=14,
                minimum=1,
                maximum=3650,
            ),
        )
        return jsonify(_wire_cleanup_plan(session_store, result["session_id"])), 201

    @app.get("/api/v1/cleanup/plans/<plan_id>")
    def cleanup_plan_get(plan_id: str):
        reader()
        return jsonify(_wire_cleanup_plan(session_store, plan_id))

    @app.get("/api/v1/sessions")
    def sessions_list():
        reader()
        return jsonify(
            [
                _wire_session(session_store, item["session_id"])
                for item in session_store.list_sessions()
            ]
        )

    @app.get("/api/v1/sessions/<session_id>")
    def session_get(session_id: str):
        reader()
        return jsonify(_wire_session(session_store, session_id))

    @app.get("/api/v1/sessions/<session_id>/artifacts/<filename>")
    def artifact_get(session_id: str, filename: str):
        reader()
        manifest = session_store.load_manifest(session_id)
        artifact_files = {
            record.get("file") for record in manifest.get("artifacts", [])
        }
        semantic = {
            "commands": "commands.txt",
            "report": (
                "raport_wykonania_candidate.txt"
                if "raport_wykonania_candidate.txt" in artifact_files
                else "raport_restore.txt"
                if manifest["operation_kind"] == "restore"
                else "raport_szczegolowy.txt"
            ),
            "manifest": "manifest.json",
            "conflicts": (
                "manual_conflicts.xml"
                if "manual_conflicts.xml" in artifact_files
                else "manual_conflicts.json"
            ),
        }
        requested = semantic.get(filename, filename)
        try:
            path = session_store.resolve_download(session_id, requested)
        except ToolboxError:
            if filename == "report":
                requested = "restore_operations.json" if manifest["operation_kind"] == "restore" else "plan_summary.json"
                path = session_store.resolve_download(session_id, requested)
            elif filename == "commands" and manifest["operation_kind"] == "restore":
                path = session_store.resolve_download(session_id, "restore_operations.json")
            elif filename == "conflicts":
                return Response(
                    json.dumps(manifest.get("conflicts") or [], ensure_ascii=False, indent=2),
                    content_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="conflicts.json"'},
                )
            else:
                raise
        return send_file(path, as_attachment=True)

    @app.post("/api/v1/sessions/<session_id>/apply")
    @app.post("/api/v1/sessions/<session_id>/candidate")
    def session_apply(session_id: str):
        value = body()
        client = reader()
        writer = make_writer(
            client,
            ApiStage.CANDIDATE,
            enable_api_write=_json_bool(
                value, "enable_api_write", fallback_key="enableApiWrite", default=False
            ),
        )
        result = apply_candidate(
            session_store,
            session_id,
            client,
            writer,
            save_server_snapshot=_json_bool(
                value,
                "save_server_snapshot",
                fallback_key="saveServerSnapshot",
                default=True,
            ),
            acquire_locks=True,
        )
        payload = asdict(result)
        payload["state"] = result.state.value
        return jsonify(
            {
                "session": _wire_session(session_store, session_id),
                "message": f"Candidate zakończony stanem {result.state.value}.",
            }
        )

    @app.post("/api/v1/sessions/<session_id>/commit")
    def session_commit(session_id: str):
        value = body()
        client = reader()
        writer = make_writer(
            client,
            ApiStage.COMMIT,
            enable_api_write=_json_bool(
                value, "enable_api_write", fallback_key="enableApiWrite", default=False
            ),
        )
        job = commit_session(
                session_store,
                session_id,
                client,
                writer,
                partial=not _json_bool(value, "full", default=False),
                allow_unisolated_commit=_json_bool(
                    value,
                    "allow_unisolated_commit",
                    fallback_key="allowUnisolatedCommit",
                    default=False,
                ),
                allow_full_commit=_json_bool(
                    value,
                    "allow_full_commit",
                    fallback_key="allowFullCommit",
                    default=False,
                ),
            )
        return jsonify(
            {
                "session": _wire_session(session_store, session_id),
                "message": "Commit zakończony poprawnie.",
            }
        )

    @app.post("/api/v1/sessions/<session_id>/push")
    def session_push(session_id: str):
        value = body()
        client = reader()
        writer = make_writer(
            client,
            ApiStage.PUSH,
            enable_api_write=_json_bool(
                value, "enable_api_write", fallback_key="enableApiWrite", default=False
            ),
        )
        push_session(
                session_store,
                session_id,
                client,
                writer,
                device_groups=string_list_field(
                    value, "device_groups", fallback_key="deviceGroups"
                ),
            )
        return jsonify(
            {
                "session": _wire_session(session_store, session_id),
                "message": "Push zakończony poprawnie.",
            }
        )

    @app.post("/api/v1/restore/plan")
    @app.post("/api/v1/restore/plans")
    def restore_plan_endpoint():
        value = body()
        result = plan_restore_session(
                session_store,
                reader(),
                source_session_id=value.get("source_session_id") or value.get("sourceSessionId"),
                ip=value.get("ip"),
            )
        return jsonify(_wire_restore_plan(session_store, result)), 201

    @app.post("/api/v1/restore/plans/<plan_id>/candidate")
    def restore_candidate_alias(plan_id: str):
        value = body()
        client = reader()
        writer = make_writer(
            client,
            ApiStage.CANDIDATE,
            enable_api_write=_json_bool(value, "enable_api_write", default=False),
        )
        result = apply_candidate(session_store, plan_id, client, writer)
        return jsonify(
            {
                "session": _wire_session(session_store, plan_id),
                "message": f"Restore candidate zakończony stanem {result.state.value}.",
            }
        )

    @app.post("/api/v1/audit")
    @app.post("/api/v1/audits")
    def audit_endpoint():
        value = body()
        ips = normalize_ips(string_list_field(value, "addresses", fallback_key="ips"))
        client = reader()
        running = client.fetch_config("running")
        from .cleaner_adapter import _legacy_root

        _legacy_root()
        from panorama_cleanup.panos import match_ip_objects, parse_config  # type: ignore[import-not-found]
        from panorama_cleanup.planner import dependency_inventories  # type: ignore[import-not-found]

        model = parse_config(running)
        matches = match_ip_objects(model, ips)
        all_keys = {
            key
            for match in matches.values()
            for key in match.exact_objects + match.containing_objects
        }
        inventories = dependency_inventories(model, all_keys)
        records = []
        for ip in ips:
            objects = []
            for key in matches[ip].exact_objects + matches[ip].containing_objects:
                groups, rules, warnings = inventories[key]
                objects.append(
                    {
                        "location": key.location,
                        "name": key.name,
                        "exact": key in matches[ip].exact_objects,
                        "groups": [
                            {"location": item.location, "name": item.name}
                            for item in sorted(groups)
                        ],
                        "policies": [
                            {
                                "location": item.location,
                                "rulebase": item.rulebase,
                                "policy_type": item.policy_type,
                                "name": item.name,
                            }
                            for item in sorted(rules)
                        ],
                        "warnings": warnings,
                    }
                )
            records.append({"ip": ip, "objects": objects})
        wire_addresses = []
        residual_count = 0
        for record in records:
            references = []
            object_names = []
            for obj in record["objects"]:
                object_names.append(f"{obj['location']}/{obj['name']}")
                for group in obj["groups"]:
                    references.append(
                        {
                            "id": f"{record['ip']}-group-{len(references) + 1}",
                            "scope": group["location"],
                            "deviceGroup": group["location"],
                            "rulebase": (
                                "shared" if group["location"] == "shared" else "local"
                            ),
                            "policyType": "group",
                            "name": group["name"],
                            "field": "dependency",
                            "path": f"{group['location']}/address-group/{group['name']}",
                        }
                    )
                for policy in obj["policies"]:
                    references.append(
                        {
                            "id": f"{record['ip']}-policy-{len(references) + 1}",
                            "scope": policy["location"],
                            "deviceGroup": policy["location"],
                            "rulebase": (
                                "pre"
                                if policy["rulebase"] == "pre-rulebase"
                                else "post"
                            ),
                            "policyType": policy["policy_type"],
                            "name": policy["name"],
                            "field": "dependency",
                            "path": (
                                f"{policy['location']}/{policy['rulebase']}/"
                                f"{policy['policy_type']}/{policy['name']}"
                            ),
                        }
                    )
            residual_count += len(object_names) + len(references)
            wire_addresses.append(
                {
                    "ip": record["ip"],
                    "objectNames": object_names,
                    "icmp": "not-run",
                    "decision": "process" if object_names or references else "not-found",
                    "recentLastHit": False,
                    "references": references,
                }
            )
        return jsonify(
            {
                "generatedAt": __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ).isoformat(timespec="seconds"),
                "addresses": wire_addresses,
                "residualReferenceCount": residual_count,
                "cleanCount": sum(
                    not item["objectNames"] and not item["references"] for item in wire_addresses
                ),
            }
        )

    @app.get("/")
    def index():
        index_file = frontend / "index.html"
        if index_file.is_file():
            return send_from_directory(frontend, "index.html")
        return Response(
            "<!doctype html><meta charset=utf-8><title>PanOS Toolbox</title>"
            "<h1>PanOS Toolbox backend działa</h1><p>Brak spakowanych statycznych assetów GUI.</p>",
            content_type="text/html; charset=utf-8",
        )

    @app.get("/<path:path>")
    def spa(path: str):
        candidate = (frontend / path).resolve()
        if frontend in candidate.parents and candidate.is_file():
            return send_from_directory(frontend, path)
        if (frontend / "index.html").is_file():
            return send_from_directory(frontend, "index.html")
        return index()

    return app


def run_server(
    *,
    port: int,
    static_dir: Path,
    session_dir: Optional[Path],
    profile_path: Optional[Path] = None,
) -> None:
    if not 0 <= port <= 65535:
        raise InputError("Port GUI musi być w zakresie 0..65535.")
    try:
        from werkzeug.serving import make_server
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Brak Flask/Werkzeug dla serwera GUI.") from exc
    profile_ceiling = None
    if profile_path is not None and profile_path.is_file():
        profile_ceiling = load_profile(profile_path)
        print(
            "GUI API ceiling: "
            f"{profile_ceiling.host} / {profile_ceiling.username} / "
            f"{profile_ceiling.api_max_stage.value}",
            flush=True,
        )
    elif profile_path is not None:
        print(
            f"UWAGA: brak {profile_path}; GUI zostaje wymuszone w read-only.",
            flush=True,
        )
    app = create_app(
        static_dir=static_dir,
        store=SessionStore(session_dir),
        profile_ceiling=profile_ceiling,
    )
    server = make_server("127.0.0.1", port, app, threaded=True)
    actual_port = server.server_port
    print(f"PanOS Toolbox: http://127.0.0.1:{actual_port}/", flush=True)
    server.serve_forever()
