"""Transactional candidate apply, rollback, commit and push orchestration."""

from __future__ import annotations

import json
import hashlib
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

from .cleaner_adapter import build_cleanup_patchset
from .client import PanoramaReadClient, PanoramaWriteClient
from .commit_review import build_commit_review, build_scope_guard
from .errors import (
    CapabilityError,
    ConflictError,
    OutcomeUnknownError,
    PanoramaResponseError,
    SessionError,
    ToolboxError,
    ValidationError,
)
from .models import ApiStage, Mutation, PatchSet, SessionState, utc_now
from .sessions import SessionStore
from .restore import mutation_owner_xpath
from .xmlutil import (
    device_group_from_xpath,
    find_xpath,
    fingerprint_element,
    fingerprint_xpath,
    parent_xpath,
    rule_order_context_sha256,
)


@dataclass(frozen=True)
class ApplyResult:
    session_id: str
    state: SessionState
    applied_mutations: tuple[str, ...]
    skipped_components: tuple[str, ...]
    conflicts: tuple[dict[str, Any], ...]


def server_snapshot_filename(session_id: str) -> str:
    """Return a human-recognisable PAN-OS config name within its 32-char limit."""

    raw_stamp = session_id.removeprefix("session-").split("-", 1)[0]
    stamp = "".join(character for character in raw_stamp if character.isalnum())[:16]
    if not stamp:
        stamp = "session"
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:6]
    filename = f"ptb_{stamp}_{digest}.xml"
    if len(filename) > 32:  # defensive if the format above changes later
        filename = f"ptb_{digest}.xml"
    return filename


def reconcile_external_execution(
    store: SessionStore,
    session_id: str,
    reader: PanoramaReadClient,
    *,
    source: str = "CLI",
) -> SessionState:
    """Prove that a generated plan was executed outside Toolbox.

    Generating CLI commands is never treated as proof of execution.  This
    function compares every planned postcondition against live candidate and
    running, including policy order, before admitting the durable session into
    restore history.
    """

    if source not in {"CLI", "API"}:
        raise ValidationError("Źródło wykonania zewnętrznego musi być CLI albo API.")
    with store.operation_lock(session_id):
        with store.panorama_job_lock(reader.profile.host, session_id):
            manifest = store.load_manifest(session_id)
            if manifest["state"] not in {
                SessionState.PLANNED.value,
                SessionState.FAILED.value,
            }:
                raise SessionError(
                    "Tylko sesję PLANNED albo FAILED można zweryfikować jako wykonanie zewnętrzne."
                )
            patch = store.load_patchset(session_id)
            _assert_session_identity(patch, reader)
            if not patch.mutations:
                raise ValidationError("Sesja nie zawiera operacji do uzgodnienia.")
            running = reader.fetch_config("running")
            candidate = reader.fetch_config("candidate")
            running_failures = _postcondition_failures(patch.mutations, running)
            candidate_failures = _postcondition_failures(patch.mutations, candidate)
            if not running_failures:
                state = SessionState.COMMITTED
                matched = "running"
            elif not candidate_failures:
                state = SessionState.CANDIDATE_APPLIED
                matched = "candidate"
            else:
                sample = [
                    str(item.get("mutation_id"))
                    for item in candidate_failures[:8]
                ]
                raise ConflictError(
                    "Live Panorama nie odpowiada kompletnemu wynikowi wygenerowanego planu. "
                    "Brak potwierdzenia dla: " + ", ".join(sample)
                )
            store.write_snapshot(session_id, "external_verified_running", running)
            store.write_snapshot(session_id, "external_verified_candidate", candidate)
            store.record_external_execution(
                session_id,
                state=state,
                source=source,
                applied_mutation_ids=(mutation.mutation_id for mutation in patch.mutations),
                evidence={
                    "matchedTree": matched,
                    "mutationCount": len(patch.mutations),
                },
            )
            if state is SessionState.CANDIDATE_APPLIED:
                try:
                    native_summary, native_error = _read_native_change_summary(reader)
                    baseline = _review_baseline_candidate(
                        store, session_id, fallback=running
                    )
                    _persist_commit_review(
                        store,
                        session_id,
                        running=running,
                        baseline_candidate=baseline,
                        candidate=candidate,
                        patch=patch,
                        applied_mutation_ids=(
                            mutation.mutation_id for mutation in patch.mutations
                        ),
                        native_summary=native_summary,
                        native_error=native_error,
                    )
                except Exception as review_error:
                    store.add_risk(
                        session_id,
                        "COMMIT_REVIEW_FAILED",
                        (
                            "Wykonanie zewnętrzne uzgodniono, ale pełny diff "
                            f"wymaga ponowienia: {type(review_error).__name__}: "
                            f"{review_error}"
                        ),
                    )
            return state


def _assert_session_identity(patch: PatchSet, reader: PanoramaReadClient) -> None:
    if (
        patch.panorama_host != reader.profile.host
        or patch.panorama_username != reader.profile.username
    ):
        raise CapabilityError(
            "Sesja została zaplanowana dla innego hosta lub administratora Panoramy."
        )


def _precondition_conflicts(
    patch: PatchSet, candidate: ET.Element
) -> tuple[set[str], list[dict[str, Any]]]:
    components: set[str] = set()
    conflicts: list[dict[str, Any]] = []
    for mutation in patch.mutations:
        current = fingerprint_xpath(candidate, mutation.target_xpath)
        if current != mutation.before_sha256:
            components.add(mutation.component_id)
            conflicts.append(
                {
                    "mutation_id": mutation.mutation_id,
                    "component_id": mutation.component_id,
                    "entity_key": mutation.entity_key,
                    "xpath": mutation.target_xpath,
                    "expected_sha256": mutation.before_sha256,
                    "current_sha256": current,
                }
            )
            continue
        if mutation.order_context_sha256 is not None:
            current_order_context = rule_order_context_sha256(
                candidate,
                mutation.target_xpath,
                mutation.order_previous,
                mutation.order_next,
            )
            if current_order_context != mutation.order_context_sha256:
                components.add(mutation.component_id)
                conflicts.append(
                    {
                        "mutation_id": mutation.mutation_id,
                        "component_id": mutation.component_id,
                        "entity_key": mutation.entity_key,
                        "xpath": mutation.target_xpath,
                        "reason": "RULE_ORDER_CONTEXT_CHANGED",
                        "expected_order_context_sha256": mutation.order_context_sha256,
                        "current_order_context_sha256": current_order_context,
                    }
                )
    return components, conflicts


def _cleanup_candidate_replan_conflicts(
    patch: PatchSet,
    candidate: ET.Element,
    manifest: dict[str, Any],
) -> tuple[set[str], list[dict[str, Any]]]:
    """Re-run the known cleaner planner against current candidate.

    The original analysis is intentionally based on running.  Before write we
    require the structural operation set for every original dependency
    component to remain identical on candidate.  This catches semantic scope,
    newly added references and empty/non-empty group changes that an exact
    target fingerprint alone cannot see.
    """

    if patch.kind != "cleanup" or "input_ips" not in manifest:
        return set(), []

    def signature(mutation: Mutation) -> tuple[Any, ...]:
        return (
            mutation.entity_type,
            mutation.entity_key,
            mutation.target_xpath,
            tuple(
                (
                    operation.action.value,
                    operation.xpath,
                    operation.element,
                    operation.where,
                    operation.destination,
                )
                for operation in mutation.forward
            ),
            tuple(sorted(mutation.causes)),
        )

    components = {mutation.component_id for mutation in patch.mutations}
    try:
        input_targets = manifest.get("input_targets") or {}
        replan_ips = (
            manifest.get("eligible_input_ips")
            if "eligible_input_ips" in manifest
            else patch.targets
        )
        replanned = build_cleanup_patchset(
            candidate,
            replan_ips or (),
            address_object_names=input_targets.get("address_objects") or (),
            address_group_names=input_targets.get("address_groups") or (),
            policy_names=input_targets.get("policies") or (),
            panorama_host=patch.panorama_host,
            panorama_username=patch.panorama_username,
            nat_translation_action=str(
                manifest.get("nat_translation_action") or "delete-rule"
            ),
            allow_default_policy_override=bool(
                manifest.get("allow_default_policy_override")
            ),
        ).patchset
    except Exception as exc:
        return components, [
            {
                "component_id": component,
                "reason": "CANDIDATE_REPLAN_FAILED",
                "detail": f"{type(exc).__name__}: {exc}",
            }
            for component in sorted(components)
        ]

    original_by_cause: dict[str, set[tuple[Any, ...]]] = {}
    candidate_by_cause: dict[str, set[tuple[Any, ...]]] = {}
    for mutation in patch.mutations:
        value = signature(mutation)
        for cause in mutation.causes:
            original_by_cause.setdefault(cause, set()).add(value)
    for mutation in replanned.mutations:
        value = signature(mutation)
        for cause in mutation.causes:
            candidate_by_cause.setdefault(cause, set()).add(value)

    changed_causes = {
        cause
        for cause in set(original_by_cause) | set(candidate_by_cause)
        if original_by_cause.get(cause, set())
        != candidate_by_cause.get(cause, set())
    }
    affected = {
        mutation.component_id
        for mutation in patch.mutations
        if changed_causes.intersection(mutation.causes)
    }
    if patch.affected_device_groups != replanned.affected_device_groups:
        affected.update(components)
    records = [
        {
            "component_id": component,
            "reason": "CANDIDATE_REPLAN_CHANGED",
            "changed_causes": sorted(changed_causes),
            "planned_device_groups": list(patch.affected_device_groups),
            "candidate_device_groups": list(replanned.affected_device_groups),
        }
        for component in sorted(affected)
    ]
    return affected, records


def _history_owner_key(xpath: str) -> str:
    return xpath.replace(
        "/address-group/entry[", "/address-namespace/entry[", 1
    ).replace("/address/entry[", "/address-namespace/entry[", 1)


def _paths_overlap(left: str, right: str) -> bool:
    return (
        left == right
        or left.startswith(right.rstrip("/") + "/")
        or right.startswith(left.rstrip("/") + "/")
    )


def _restore_history_conflicts(
    store: SessionStore,
    manifest: dict[str, Any],
    patch: PatchSet,
) -> list[dict[str, Any]]:
    if patch.kind != "restore":
        return []
    guard = manifest.get("restore_history_guard")
    if not isinstance(guard, dict):
        return [
            {
                "reason": "RESTORE_HISTORY_GUARD_MISSING",
                "detail": "Sesja restore nie zapisuje watermarku historii cleanup.",
            }
        ]
    expected_sources = guard.get("selected_source_revisions")
    baseline = guard.get("baseline_revisions")
    if not isinstance(expected_sources, dict) or not isinstance(baseline, dict):
        return [
            {
                "reason": "RESTORE_HISTORY_GUARD_INVALID",
                "detail": "Watermark historii restore ma niepoprawny format.",
            }
        ]
    for session_id, expected in expected_sources.items():
        current = store.load_manifest(str(session_id))
        if tuple(expected) != store.manifest_revision(current):
            return [
                {
                    "reason": "RESTORE_SOURCE_REVISION_CHANGED",
                    "source_session_id": session_id,
                }
            ]

    # An OUTCOME_UNKNOWN cleanup may have changed candidate even though no
    # applied-mutation list exists.  Its scope cannot be proven safely.
    for item in store.list_sessions_strict():
        if (
            item.get("operation_kind") != "cleanup"
            or item.get("state") != SessionState.OUTCOME_UNKNOWN.value
        ):
            continue
        unknown = store.load_manifest(str(item["session_id"]))
        profile = unknown.get("profile") or {}
        if (
            profile.get("host") == patch.panorama_host
            and profile.get("username") == patch.panorama_username
        ):
            return [
                {
                    "reason": "CLEANUP_OUTCOME_UNKNOWN",
                    "source_session_id": item["session_id"],
                }
            ]

    current_history = store.iter_applied_cleanup_history(
        patch.panorama_host, patch.panorama_username
    )
    current_ids = {cleanup.session_id for cleanup in current_history}
    missing = set(baseline) - current_ids
    if missing:
        return [
            {
                "reason": "RESTORE_HISTORY_SESSION_MISSING",
                "source_session_ids": sorted(missing),
            }
        ]
    guard_paths = {str(item) for item in guard.get("guard_owner_xpaths") or ()}
    guard_keys = {_history_owner_key(path) for path in guard_paths}
    selected_causes = {str(item) for item in guard.get("selected_causes") or ()}
    for cleanup in current_history:
        if cleanup.session_id in baseline:
            continue
        for mutation in cleanup.mutations:
            owner = mutation_owner_xpath(mutation)
            related = bool(selected_causes.intersection(mutation.causes)) or any(
                _paths_overlap(_history_owner_key(owner), guarded)
                for guarded in guard_keys
            )
            if related:
                return [
                    {
                        "reason": "RELATED_CLEANUP_AFTER_RESTORE_PLAN",
                        "source_session_id": cleanup.session_id,
                        "mutation_id": mutation.mutation_id,
                        "owner_xpath": owner,
                    }
                ]
    return []


def _postcondition_failures(
    mutations: Iterable[Mutation], candidate: ET.Element
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for mutation in mutations:
        current = fingerprint_xpath(candidate, mutation.target_xpath)
        if current != mutation.after_sha256:
            failures.append(
                {
                    "mutation_id": mutation.mutation_id,
                    "xpath": mutation.target_xpath,
                    "expected_sha256": mutation.after_sha256,
                    "current_sha256": current,
                }
            )
            continue
        order_problem = _rule_order_problem(
            mutation, candidate, expect_xml=mutation.after_xml
        )
        if order_problem:
            failures.append(
                {
                    "mutation_id": mutation.mutation_id,
                    "xpath": mutation.target_xpath,
                    "reason": order_problem,
                }
            )
    return failures


def _rule_order_problem(
    mutation: Mutation,
    config: ET.Element,
    *,
    expect_xml: Optional[str],
) -> Optional[str]:
    if mutation.entity_type != "policy" or expect_xml is None:
        return None
    rule = find_xpath(config, mutation.target_xpath)
    container = find_xpath(config, parent_xpath(mutation.target_xpath))
    if rule is None or container is None or not rule.get("name"):
        return "Nie można potwierdzić pozycji odtworzonej polityki."
    names = [entry.get("name") for entry in container.findall("./entry")]
    name = rule.get("name")
    if name not in names:
        return "Odtworzona polityka nie występuje w kolejności rulebase."
    index = names.index(name)
    if mutation.order_previous:
        if mutation.order_previous not in names:
            return f"Brakuje historycznego poprzednika {mutation.order_previous}."
        if names.index(mutation.order_previous) + 1 != index:
            return f"Polityka nie znajduje się bezpośrednio po {mutation.order_previous}."
    elif index != 0:
        return "Polityka bez poprzednika nie została odtworzona na pozycji top."
    if mutation.order_next:
        if mutation.order_next not in names:
            return f"Brakuje historycznego następnika {mutation.order_next}."
        if index + 1 != names.index(mutation.order_next):
            return f"Polityka nie znajduje się bezpośrednio przed {mutation.order_next}."
    elif index != len(names) - 1:
        return "Polityka bez następnika nie została odtworzona na pozycji bottom."
    return None


def _release_locks(
    store: SessionStore,
    session_id: str,
    writer: PanoramaWriteClient,
    acquired: list[Optional[str]],
) -> None:
    for scope in reversed(acquired):
        try:
            writer.release_config_lock(scope)
            store.append_event(session_id, "CONFIG_LOCK_RELEASED", {"scope": scope or "shared"})
        except ToolboxError as exc:
            store.append_event(
                session_id,
                "CONFIG_LOCK_RELEASE_WARNING",
                {"scope": scope or "shared", "detail": str(exc)},
            )


def _direct_lock_scopes(patch: PatchSet) -> list[Optional[str]]:
    if any(xpath.startswith("/config/shared/") for xpath in patch.touched_xpaths):
        return [None]
    return sorted(
        {
            scope
            for scope in (device_group_from_xpath(xpath) for xpath in patch.touched_xpaths)
            if scope
        }
    )


def _rollback(
    store: SessionStore,
    session_id: str,
    writer: PanoramaWriteClient,
    applied: list[Mutation],
) -> None:
    for mutation in reversed(applied):
        store.append_event(
            session_id,
            "ROLLBACK_MUTATION_START",
            {"mutation": mutation.to_dict()},
        )
        for operation in mutation.inverse:
            writer.apply_recovery_operation(operation)
            store.append_event(
                session_id,
                "ROLLBACK_OPERATION_OK",
                {
                    "mutation_id": mutation.mutation_id,
                    "operation": operation.to_dict(),
                },
            )
    candidate = writer.reader.fetch_config("candidate")
    failures = []
    for mutation in applied:
        current = fingerprint_xpath(candidate, mutation.target_xpath)
        if current != mutation.before_sha256:
            failures.append(mutation.mutation_id)
            continue
        if _rule_order_problem(mutation, candidate, expect_xml=mutation.before_xml):
            failures.append(mutation.mutation_id + "(order)")
    if failures:
        raise ValidationError(
            "Rollback nie odtworzył precondition dla: " + ", ".join(failures)
        )


def _write_execution_report(
    store: SessionStore,
    session_id: str,
    patch: PatchSet,
    applied: Iterable[Mutation],
    skipped_components: Iterable[str],
) -> None:
    applied_values = list(applied)
    verb = "przywrócono" if patch.kind == "restore" else "usunięto/zmieniono"
    lines = [
        f"Sesja: {session_id}",
        "Etap: zapisano do candidate; commit i push NIE są częścią tego raportu.",
        f"Mutacje zastosowane: {len(applied_values)}",
        "",
    ]
    for mutation in applied_values:
        lines.append(
            f"{mutation.entity_type} {mutation.entity_key}: {verb} "
            f"(component={mutation.component_id})"
        )
        for operation in mutation.forward:
            lines.append(
                "  XML API: "
                + json.dumps(operation.to_dict(), ensure_ascii=False, sort_keys=True)
            )
    skipped = sorted(set(skipped_components))
    if skipped:
        lines.extend(
            ["", "Pominięte komponenty (konflikt/review):", *[f"- {item}" for item in skipped]]
        )
    store.write_artifact(
        session_id,
        "raport_wykonania_candidate.txt",
        "\n".join(lines) + "\n",
        kind="execution-report",
    )


def _read_native_change_summary(
    reader: PanoramaReadClient,
) -> tuple[Optional[ET.Element], Optional[str]]:
    """Read the small Panorama change-summary without invalidating review.

    Some PAN-OS releases do not expose this operational command consistently.
    The full running/candidate snapshots remain authoritative; an unavailable
    native summary is recorded and forces a full-running fallback at commit.
    """

    try:
        return reader.change_summary(), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _review_baseline_candidate(
    store: SessionStore,
    session_id: str,
    fallback: ET.Element,
) -> ET.Element:
    for label in ("pre_candidate", "plan_candidate"):
        try:
            return store.load_snapshot(session_id, label)
        except (SessionError, ValidationError):
            continue
        except Exception:
            continue
    return fallback


def _persist_commit_review(
    store: SessionStore,
    session_id: str,
    *,
    running: ET.Element,
    baseline_candidate: ET.Element,
    candidate: ET.Element,
    patch: PatchSet,
    applied_mutation_ids: Iterable[str],
    native_summary: Optional[ET.Element],
    native_error: Optional[str],
) -> dict[str, Any]:
    generated_at = utc_now()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    names = {
        "reviewJson": f"pre_commit_review_{stamp}.json",
        "reviewText": f"pre_commit_review_{stamp}.txt",
        "candidateDiff": f"candidate_diff_{stamp}.txt",
        "scopeGuard": f"scope_guard_{stamp}.txt",
    }
    documents = build_commit_review(
        session_id=session_id,
        generated_at=generated_at,
        running=running,
        baseline_candidate=baseline_candidate,
        candidate=candidate,
        patch=patch,
        applied_mutation_ids=applied_mutation_ids,
        native_summary=native_summary,
        native_error=native_error,
    )
    documents.compact["artifacts"] = dict(names)
    documents.payload["artifacts"] = dict(names)
    store.write_snapshot(session_id, "review_running", running)
    store.write_snapshot(session_id, "review_candidate", candidate)
    store.write_artifact(
        session_id,
        names["reviewJson"],
        json.dumps(documents.payload, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        kind="pre-commit-review-json",
    )
    store.write_artifact(
        session_id,
        names["reviewText"],
        documents.review_text,
        kind="pre-commit-review-text",
    )
    store.write_artifact(
        session_id,
        names["candidateDiff"],
        documents.config_diff_text,
        kind="full-running-candidate-diff",
    )
    store.write_artifact(
        session_id,
        names["scopeGuard"],
        documents.scope_guard_text,
        kind="pre-commit-scope-guard",
    )
    store.record_commit_review(session_id, documents.compact)
    return documents.compact


def prepare_commit_review(
    store: SessionStore,
    session_id: str,
    reader: PanoramaReadClient,
    *,
    progress_callback: Optional[
        Callable[[int, str, Optional[dict[str, Any]]], None]
    ] = None,
) -> dict[str, Any]:
    """Refresh the exact diff/scope proof for an applied candidate session."""

    with store.operation_lock(session_id):
        with store.panorama_job_lock(reader.profile.host, session_id):
            started = time.monotonic()

            def progress(
                value: int, message: str, detail: Optional[dict[str, Any]] = None
            ) -> None:
                if progress_callback is None:
                    return
                payload = dict(detail or {})
                payload.setdefault(
                    "elapsedSeconds", round(time.monotonic() - started, 1)
                )
                try:
                    progress_callback(max(0, min(100, value)), message, payload)
                except Exception:
                    pass

            progress(
                1,
                "Przygotowanie pełnego przeglądu przed commit",
                {"event": "review-start"},
            )
            manifest = store.load_manifest(session_id)
            if manifest["state"] not in {
                SessionState.CANDIDATE_APPLIED.value,
                SessionState.PARTIAL.value,
                SessionState.RESTORED.value,
            }:
                raise SessionError(
                    "Pełny diff przed commit wymaga zastosowanego candidate PatchSet."
                )
            patch = store.load_patchset(session_id)
            _assert_session_identity(patch, reader)
            application = manifest.get("candidate_application") or {}
            applied_ids = application.get("applied_mutation_ids") or []
            if not applied_ids:
                raise SessionError(
                    "Manifest nie zawiera listy zastosowanych mutacji candidate."
                )
            progress(
                8,
                "Pobieranie live running do pełnego diffu (1/2)",
                {"event": "review-running", "indeterminate": True},
            )
            running = reader.fetch_config("running")
            progress(
                42,
                "Pobieranie live candidate do pełnego diffu (2/2)",
                {"event": "review-candidate", "indeterminate": True},
            )
            candidate = reader.fetch_config("candidate")
            _check_expected_post_state(patch, candidate, applied_ids)
            progress(
                66,
                "Pobieranie lekkiego Panorama change-summary",
                {"event": "review-native-summary"},
            )
            native, native_error = _read_native_change_summary(reader)
            baseline = _review_baseline_candidate(
                store, session_id, fallback=running
            )
            progress(
                74,
                "Budowanie pełnego diffu i scope guard",
                {"event": "review-build", "indeterminate": True},
            )
            review = _persist_commit_review(
                store,
                session_id,
                running=running,
                baseline_candidate=baseline,
                candidate=candidate,
                patch=patch,
                applied_mutation_ids=applied_ids,
                native_summary=native,
                native_error=native_error,
            )
            progress(
                100,
                (
                    "Diff gotowy — scope guard PASS"
                    if review.get("commitReady")
                    else "Diff gotowy — scope guard zablokował commit"
                ),
                {
                    "event": "review-finished",
                    "commitReady": bool(review.get("commitReady")),
                    "findingCount": (
                        (review.get("scopeGuard") or {}).get("findingCount")
                    ),
                },
            )
            return review


def apply_candidate(
    store: SessionStore,
    session_id: str,
    reader: PanoramaReadClient,
    writer: PanoramaWriteClient,
    *,
    save_server_snapshot: bool = True,
    acquire_locks: bool = True,
    progress_callback: Optional[
        Callable[[int, str, Optional[dict[str, Any]]], None]
    ] = None,
) -> ApplyResult:
    with store.operation_lock(session_id):
        # One durable host-wide transaction mutex serializes every Toolbox
        # candidate apply, commit and push.  The restore history watermark is
        # rechecked while this mutex and the Panorama config locks are held,
        # closing the plan/apply TOCTOU window against another Toolbox process.
        with store.panorama_job_lock(reader.profile.host, session_id):
            return _apply_candidate_unlocked(
                store,
                session_id,
                reader,
                writer,
                save_server_snapshot=save_server_snapshot,
                acquire_locks=acquire_locks,
                progress_callback=progress_callback,
            )


def _apply_candidate_unlocked(
    store: SessionStore,
    session_id: str,
    reader: PanoramaReadClient,
    writer: PanoramaWriteClient,
    *,
    save_server_snapshot: bool = True,
    acquire_locks: bool = True,
    progress_callback: Optional[
        Callable[[int, str, Optional[dict[str, Any]]], None]
    ] = None,
) -> ApplyResult:
    def progress(
        value: int, message: str, detail: Optional[dict[str, Any]] = None
    ) -> None:
        if progress_callback is None:
            return
        # Progress is observational.  A broken browser/poller must never alter
        # the transactional outcome of a Panorama write.
        try:
            progress_callback(max(0, min(100, value)), message, detail)
        except Exception:
            pass

    progress(1, "Weryfikacja sesji i backupów", None)
    manifest = store.load_manifest(session_id)
    if manifest["state"] != SessionState.PLANNED.value:
        raise SessionError("Candidate apply wymaga sesji w stanie PLANNED.")
    patch = store.load_patchset(session_id)
    _assert_session_identity(patch, reader)
    writer.lease.assert_valid(writer.profile, ApiStage.CANDIDATE)
    if not patch.mutations:
        raise ValidationError("PatchSet nie zawiera żadnej bezpiecznej mutacji.")

    # Full local snapshots precede even the config-lock request.  They are
    # refreshed after locks, immediately before fingerprint checks and writes.
    progress(4, "Pobieranie running do bezpiecznego snapshotu", None)
    running = reader.fetch_config("running")
    progress(11, "Pobieranie candidate przed zapisem", None)
    candidate = reader.fetch_config("candidate")
    store.write_snapshot(session_id, "pre_running", running)
    store.write_snapshot(session_id, "pre_candidate", candidate)
    progress(
        18,
        "Backup każdej encji i pełne snapshoty są gotowe",
        {
            "event": "backups-ready",
            "backupCount": len(manifest.get("entity_backups") or ()),
        },
    )
    locks = reader.show_config_locks()
    commit_locks = reader.show_commit_locks()
    store.append_event(
        session_id,
        "CONFIG_LOCKS_CHECKED",
        {
            "config_locks_sha256": __import__("hashlib").sha256(ET.tostring(locks)).hexdigest(),
            "commit_locks_sha256": __import__("hashlib").sha256(ET.tostring(commit_locks)).hexdigest(),
        },
    )

    acquired: list[Optional[str]] = []
    try:
        progress(22, "Sprawdzono locki Panorama", None)
        if acquire_locks:
            for scope in _direct_lock_scopes(patch):
                writer.acquire_config_lock(scope, f"PanOS Toolbox {session_id}")
                acquired.append(scope)
                store.append_event(
                    session_id, "CONFIG_LOCK_ACQUIRED", {"scope": scope or "shared"}
                )
        progress(27, "Lock konfiguracji aktywny; ponowny odczyt candidate", None)

        # Re-fetch after lock acquisition.  Preconditions are per touched XPath;
        # unrelated candidate changes are informational and never a blocker.
        running = reader.fetch_config("running")
        candidate = reader.fetch_config("candidate")
        store.write_snapshot(session_id, "pre_running", running)
        store.write_snapshot(session_id, "pre_candidate", candidate)
        history_conflicts = _restore_history_conflicts(store, manifest, patch)
        if history_conflicts:
            components = tuple(
                sorted({mutation.component_id for mutation in patch.mutations})
            )
            records = [
                {**record, "component_ids": list(components)}
                for record in history_conflicts
            ]
            store.add_conflicts(session_id, records)
            store.transition(session_id, SessionState.CONFLICT)
            _release_locks(store, session_id, writer, acquired)
            return ApplyResult(
                session_id,
                SessionState.CONFLICT,
                (),
                components,
                tuple(records),
            )
        conflicted_components, conflicts = _precondition_conflicts(patch, candidate)
        replanned_components, replan_conflicts = _cleanup_candidate_replan_conflicts(
            patch, candidate, manifest
        )
        conflicted_components.update(replanned_components)
        conflicts.extend(replan_conflicts)
        store.add_conflicts(session_id, conflicts)
        safe = [
            mutation
            for mutation in patch.mutations
            if mutation.component_id not in conflicted_components
        ]
        if not safe:
            store.transition(session_id, SessionState.CONFLICT)
            _release_locks(store, session_id, writer, acquired)
            return ApplyResult(
                session_id,
                SessionState.CONFLICT,
                (),
                tuple(sorted(conflicted_components)),
                tuple(conflicts),
            )

        progress(
            43,
            "Fingerprint i graf zależności potwierdzone",
            {
                "event": "preconditions-ok",
                "safeMutations": len(safe),
                "skippedComponents": len(conflicted_components),
            },
        )

        store.transition(
            session_id,
            SessionState.RESTORING
            if patch.kind == "restore"
            else SessionState.WRITING_CANDIDATE,
        )
        applied: list[Mutation] = []
        try:
            if save_server_snapshot:
                writer.save_candidate_snapshot(server_snapshot_filename(session_id))
                store.append_event(session_id, "SERVER_CANDIDATE_SNAPSHOT_SAVED", {})
            total_operations = sum(len(mutation.forward) for mutation in safe)
            completed_operations = 0
            for mutation in safe:
                progress(
                    45 + int(38 * completed_operations / max(1, total_operations)),
                    f"Przygotowanie: {mutation.entity_key}",
                    {
                        "event": "mutation-start",
                        "mutationId": mutation.mutation_id,
                        "entityType": mutation.entity_type,
                        "entityKey": mutation.entity_key,
                        "completedOperations": completed_operations,
                        "totalOperations": total_operations,
                    },
                )
                store.append_event(
                    session_id, "MUTATION_START", {"mutation": mutation.to_dict()}
                )
                started = False
                for operation in mutation.forward:
                    writer.apply_operation(operation)
                    if not started:
                        applied.append(mutation)
                        started = True
                    store.append_event(
                        session_id,
                        "MUTATION_OPERATION_OK",
                        {
                            "mutation_id": mutation.mutation_id,
                            "operation": operation.to_dict(),
                        },
                    )
                    completed_operations += 1
                    progress(
                        45
                        + int(
                            38
                            * completed_operations
                            / max(1, total_operations)
                        ),
                        (
                            f"XML API {completed_operations}/{total_operations}: "
                            f"{mutation.entity_key}"
                        ),
                        {
                            "event": "operation-ok",
                            "mutationId": mutation.mutation_id,
                            "entityType": mutation.entity_type,
                            "entityKey": mutation.entity_key,
                            "action": operation.action.value,
                            "xpath": operation.xpath,
                            "completedOperations": completed_operations,
                            "totalOperations": total_operations,
                        },
                    )
            progress(86, "Walidacja candidate w Panorama", None)
            validation_job = writer.validate_candidate()
            if validation_job:
                validation = writer.poll_job(validation_job)
                store.add_job(session_id, "validation", validation.__dict__)
                if not validation.succeeded:
                    raise ValidationError(
                        f"Walidacja candidate zakończyła się {validation.result}."
                    )
            progress(90, "Kontrola wyniku każdej dotkniętej ścieżki", None)
            post_candidate = reader.fetch_config("candidate")
            post_failures = _postcondition_failures(safe, post_candidate)
            if post_failures:
                raise ValidationError(
                    "Postcondition candidate nie odpowiada PatchSet: "
                    + ", ".join(item["mutation_id"] for item in post_failures)
                )
            store.write_snapshot(session_id, "post_candidate", post_candidate)
            skipped = set(conflicted_components) | set(patch.skipped_components)
            state = (
                SessionState.PARTIAL
                if skipped
                else (
                    SessionState.RESTORED
                    if patch.kind == "restore"
                    else SessionState.CANDIDATE_APPLIED
                )
            )
            _write_execution_report(store, session_id, patch, safe, skipped)
            store.record_candidate_application(
                session_id,
                applied_mutation_ids=(mutation.mutation_id for mutation in safe),
                skipped_components=skipped,
            )
            progress(
                94,
                "Candidate gotowy; budowanie pełnego diffu running → candidate",
                {"event": "review-build", "indeterminate": True},
            )
            review: Optional[dict[str, Any]] = None
            try:
                native_summary, native_error = _read_native_change_summary(reader)
                review = _persist_commit_review(
                    store,
                    session_id,
                    running=running,
                    baseline_candidate=candidate,
                    candidate=post_candidate,
                    patch=patch,
                    applied_mutation_ids=(
                        mutation.mutation_id for mutation in safe
                    ),
                    native_summary=native_summary,
                    native_error=native_error,
                )
                progress(
                    99,
                    (
                        "Pełny diff gotowy; scope guard PASS"
                        if review.get("commitReady")
                        else "Pełny diff gotowy; scope guard zablokował commit"
                    ),
                    {
                        "event": "review-ready",
                        "commitReady": bool(review.get("commitReady")),
                        "findingCount": (
                            (review.get("scopeGuard") or {}).get("findingCount")
                        ),
                    },
                )
            except Exception as review_error:
                # Candidate has already passed every per-XPath postcondition.
                # A local report-generation failure must not guess a rollback;
                # it simply leaves commit unavailable until review is retried.
                store.add_risk(
                    session_id,
                    "COMMIT_REVIEW_FAILED",
                    (
                        "Candidate zastosowany, ale nie przygotowano przeglądu "
                        f"przed commit: {type(review_error).__name__}: {review_error}"
                    ),
                )
            store.transition(session_id, state)
            progress(
                100,
                (
                    "Candidate zapisany, zwalidowany i gotowy do przeglądu"
                    if review is not None
                    else "Candidate zapisany; przed commit odśwież pełny diff"
                ),
                {
                    "event": "complete",
                    "completedOperations": completed_operations,
                    "totalOperations": total_operations,
                },
            )
        except OutcomeUnknownError:
            store.force_terminal_state(
                session_id,
                SessionState.OUTCOME_UNKNOWN,
                detail=(
                    "Wynik mutacji jest nieznany. Nie wykonano automatycznego replay ani rollbacku; "
                    "zachowano lock do ręcznego reconciliation."
                ),
            )
            raise
        except Exception as original:
            try:
                _rollback(store, session_id, writer, applied)
            except OutcomeUnknownError:
                store.force_terminal_state(
                    session_id,
                    SessionState.OUTCOME_UNKNOWN,
                    detail="Timeout podczas rollbacku; wymagane ręczne reconciliation.",
                )
                raise
            except Exception as rollback_error:
                store.force_terminal_state(
                    session_id,
                    SessionState.OUTCOME_UNKNOWN,
                    detail=f"Błąd apply i niepełny rollback: {type(rollback_error).__name__}.",
                )
                raise OutcomeUnknownError(
                    "Candidate apply nie powiódł się, a rollback był niepełny; "
                    "candidate i historia wymagają ręcznego reconciliation."
                ) from original
            store.force_terminal_state(
                session_id,
                SessionState.FAILED,
                detail=f"Candidate apply wycofany: {type(original).__name__}: {original}",
            )
            raise

        _release_locks(store, session_id, writer, acquired)
        return ApplyResult(
            session_id,
            state,
            tuple(mutation.mutation_id for mutation in safe),
            tuple(sorted(skipped)),
            tuple(conflicts),
        )
    except OutcomeUnknownError:
        # Deliberately retain locks: an unknown mutating outcome must first be
        # reconciled against candidate before any other operator changes it.
        current = store.load_manifest(session_id, verify=False)["state"]
        if current != SessionState.OUTCOME_UNKNOWN.value:
            store.force_terminal_state(
                session_id,
                SessionState.OUTCOME_UNKNOWN,
                detail="Mutujący request bez jednoznacznej odpowiedzi; zachowano lock do reconciliation.",
            )
        raise
    except Exception:
        _release_locks(store, session_id, writer, acquired)
        raise
    except BaseException as interrupted:
        # Ctrl+C/SystemExit can arrive after Panorama accepted a write but
        # before the client recorded the operation.  Never attempt a guessed
        # rollback and never release the config locks in that situation.
        try:
            current = store.load_manifest(session_id, verify=False)["state"]
            if current in {
                SessionState.WRITING_CANDIDATE.value,
                SessionState.RESTORING.value,
            }:
                store.force_terminal_state(
                    session_id,
                    SessionState.OUTCOME_UNKNOWN,
                    detail=(
                        "Przerwano proces podczas zapisu candidate "
                        f"({type(interrupted).__name__}); zachowano locki i marker "
                        "do ręcznego reconciliation."
                    ),
                )
        except Exception:
            # panorama_job_lock independently retains its durable marker when
            # an interrupt escapes, even if the manifest cannot be updated.
            pass
        raise


def _check_expected_post_state(
    patch: PatchSet, candidate: ET.Element, applied_mutation_ids: Iterable[str]
) -> None:
    applied = set(applied_mutation_ids)
    failures = _postcondition_failures(
        (mutation for mutation in patch.mutations if mutation.mutation_id in applied),
        candidate,
    )
    if failures:
        raise ConflictError(
            "Dotknięte ścieżki candidate zmieniły się po apply: "
            + ", ".join(item["mutation_id"] for item in failures)
        )


def commit_session(
    store: SessionStore,
    session_id: str,
    reader: PanoramaReadClient,
    writer: PanoramaWriteClient,
    *,
    partial: bool = True,
    allow_unisolated_commit: bool = False,
    allow_full_commit: bool = False,
    progress_callback: Optional[
        Callable[[int, str, Optional[dict[str, Any]]], None]
    ] = None,
) -> dict[str, Any]:
    with store.operation_lock(session_id):
        with store.panorama_job_lock(reader.profile.host, session_id):
            return _commit_session_unlocked(
                store,
                session_id,
                reader,
                writer,
                partial=partial,
                allow_unisolated_commit=allow_unisolated_commit,
                allow_full_commit=allow_full_commit,
                progress_callback=progress_callback,
            )


def _commit_session_unlocked(
    store: SessionStore,
    session_id: str,
    reader: PanoramaReadClient,
    writer: PanoramaWriteClient,
    *,
    partial: bool = True,
    allow_unisolated_commit: bool = False,
    allow_full_commit: bool = False,
    progress_callback: Optional[
        Callable[[int, str, Optional[dict[str, Any]]], None]
    ] = None,
) -> dict[str, Any]:
    started = time.monotonic()
    phase_timeline: dict[str, float] = {}

    def progress(
        value: int, message: str, detail: Optional[dict[str, Any]] = None
    ) -> None:
        payload = dict(detail or {})
        payload.setdefault("elapsedSeconds", round(time.monotonic() - started, 1))
        event = str(payload.get("event") or "")
        if event and (event not in phase_timeline or event == "panorama-job-finished"):
            phase_timeline[event] = float(payload["elapsedSeconds"])
        if progress_callback is None:
            return
        try:
            progress_callback(max(0, min(100, value)), message, payload)
        except Exception:
            pass

    progress(1, "Weryfikacja sesji przed commitem", {"event": "stage-start"})
    manifest = store.load_manifest(session_id)
    allowed = {
        SessionState.CANDIDATE_APPLIED.value,
        SessionState.PARTIAL.value,
        SessionState.RESTORED.value,
    }
    if manifest["state"] not in allowed:
        raise SessionError("Commit wymaga zastosowanego candidate PatchSet.")
    stable_state = SessionState(manifest["state"])
    patch = store.load_patchset(session_id)
    _assert_session_identity(patch, reader)
    writer.lease.assert_valid(writer.profile, ApiStage.COMMIT)
    if partial and not allow_unisolated_commit:
        raise CapabilityError(
            "Partial commit wymaga --allow-unisolated-commit przed rozpoczęciem joba."
        )
    if not partial and not allow_full_commit:
        raise CapabilityError("Full commit wymaga --allow-full-commit przed rozpoczęciem joba.")
    application = manifest.get("candidate_application") or {}
    applied_ids = application.get("applied_mutation_ids") or []
    if not applied_ids:
        raise SessionError("Manifest nie zawiera listy zastosowanych mutacji candidate.")
    review = manifest.get("commit_review")
    if not isinstance(review, dict):
        raise ConflictError(
            "Commit zablokowany: sesja nie ma pełnego diffu running → candidate. "
            "Uruchom „Odśwież diff i scope guard”, przejrzyj wynik i spróbuj ponownie."
        )
    review_guard = review.get("scopeGuard") or {}
    if not review.get("commitReady") or not review_guard.get("passed"):
        raise ConflictError(
            "Commit zablokowany przez scope guard z przeglądu. Otwórz pełny "
            "raport, usuń zależności lub zmiany spoza PatchSet i odśwież diff."
        )

    # The expensive two-tree review was already generated immediately after
    # Candidate.  Commit now reads only live candidate and a small native
    # change-summary before dispatch.  A full running read is a compatibility
    # fallback only when PAN-OS does not expose change-summary.
    progress(5, "Sprawdzanie locków konfiguracji i commit", {"event": "lock-check"})
    reader.show_config_locks()
    reader.show_commit_locks()
    acquired: list[Optional[str]] = []
    dispatched = False
    terminal_job_result = False
    job_succeeded = False
    full_config_reads = 0
    try:
        progress(9, "Zakładanie locków dla dotkniętych zakresów", {"event": "lock-acquire"})
        for scope in _direct_lock_scopes(patch):
            writer.acquire_config_lock(scope, f"PanOS Toolbox commit {session_id}")
            acquired.append(scope)
            store.append_event(session_id, "CONFIG_LOCK_ACQUIRED", {"scope": scope or "shared"})
        progress(
            15,
            "Preflight: job commit NIE został jeszcze wysłany — pobieranie jedynego live candidate",
            {"event": "preflight-candidate", "indeterminate": True, "jobDispatched": False},
        )
        candidate = reader.fetch_config("candidate")
        full_config_reads += 1
        store.write_snapshot(session_id, "pre_commit_candidate", candidate)
        progress(
            24,
            "Preflight: sprawdzanie fingerprintów i zgodności z pokazanym diffem",
            {"event": "fingerprint-check", "jobDispatched": False},
        )
        try:
            _check_expected_post_state(patch, candidate, applied_ids)
        except ConflictError as exc:
            store.add_conflicts(session_id, [{"stage": "pre-commit", "detail": str(exc)}])
            raise
        reviewed_candidate = review.get("candidate") or {}
        reviewed_candidate_sha = reviewed_candidate.get("semanticSha256")
        live_candidate_sha = fingerprint_element(candidate)
        if not reviewed_candidate_sha or live_candidate_sha != reviewed_candidate_sha:
            detail = (
                "Candidate zmienił się po przygotowaniu przeglądu. Commit nie został "
                "wysłany; odśwież pełny diff i scope guard."
            )
            store.add_conflicts(
                session_id,
                [
                    {
                        "stage": "pre-commit",
                        "reason": "REVIEWED_CANDIDATE_CHANGED",
                        "detail": detail,
                        "reviewed_sha256": reviewed_candidate_sha,
                        "live_sha256": live_candidate_sha,
                    }
                ],
            )
            raise ConflictError(detail)

        progress(
            28,
            "Preflight: ponowny pełny scope guard zależności",
            {"event": "preflight-scope-guard", "jobDispatched": False},
        )
        review_running = store.load_snapshot(session_id, "review_running")
        baseline_candidate = _review_baseline_candidate(
            store, session_id, fallback=review_running
        )
        live_guard = build_scope_guard(
            running=review_running,
            baseline_candidate=baseline_candidate,
            candidate=candidate,
            patch=patch,
            applied_mutation_ids=applied_ids,
        )
        live_guard["candidateSemanticSha256"] = live_candidate_sha
        live_guard["reviewGeneratedAt"] = review.get("generatedAt")
        store.record_precommit_guard(session_id, live_guard)
        if not live_guard.get("passed"):
            store.add_conflicts(
                session_id,
                [
                    {
                        "stage": "pre-commit-scope-guard",
                        **finding,
                    }
                    for finding in live_guard.get("findings") or ()
                ],
            )
            raise ConflictError(
                "Commit nie został wysłany: live scope guard znalazł zależność "
                "lub zmianę poza zakresem. Odśwież diff i sprawdź raport."
            )

        progress(
            32,
            "Preflight: potwierdzanie, że running nie zmienił się od przeglądu",
            {"event": "preflight-running-proof", "jobDispatched": False},
        )
        review_native = review.get("native") or {}
        reviewed_native_sha = review_native.get("semanticSha256")
        current_native, current_native_error = _read_native_change_summary(reader)
        if current_native is not None and reviewed_native_sha:
            current_native_sha = fingerprint_element(current_native)
            if current_native_sha != reviewed_native_sha:
                detail = (
                    "Panorama change-summary zmienił się od wygenerowania diffu. "
                    "Commit nie został wysłany; odśwież przegląd."
                )
                store.add_conflicts(
                    session_id,
                    [
                        {
                            "stage": "pre-commit",
                            "reason": "RUNNING_OR_CHANGE_SUMMARY_CHANGED",
                            "detail": detail,
                            "reviewed_sha256": reviewed_native_sha,
                            "live_sha256": current_native_sha,
                        }
                    ],
                )
                raise ConflictError(detail)
        else:
            progress(
                34,
                "Change-summary niedostępny; awaryjne pobieranie live running",
                {
                    "event": "preflight-running-fallback",
                    "indeterminate": True,
                    "jobDispatched": False,
                    "detail": current_native_error,
                },
            )
            live_running = reader.fetch_config("running")
            full_config_reads += 1
            reviewed_running_sha = (review.get("running") or {}).get(
                "semanticSha256"
            )
            if (
                not reviewed_running_sha
                or fingerprint_element(live_running) != reviewed_running_sha
            ):
                detail = (
                    "Running zmienił się od wygenerowania diffu. Commit nie został "
                    "wysłany; odśwież przegląd."
                )
                store.add_conflicts(
                    session_id,
                    [
                        {
                            "stage": "pre-commit",
                            "reason": "REVIEWED_RUNNING_CHANGED",
                            "detail": detail,
                        }
                    ],
                )
                raise ConflictError(detail)
        if partial:
            store.add_risk(
                session_id,
                "UNISOLATED_ADMIN_PARTIAL_COMMIT",
                "Partial commit może objąć inne oczekujące zmiany tego samego administratora.",
            )
        else:
            store.add_risk(
                session_id,
                "FULL_COMMIT",
                "Full commit może objąć oczekujące zmiany innych administratorów.",
            )
        store.transition(session_id, SessionState.COMMITTING)
        progress(
            38,
            "Preflight PASS — wysyłanie żądania commit do Panorama",
            {"event": "panorama-job-dispatch", "jobDispatched": False},
        )
        job_id = writer.commit(
            partial=partial,
            allow_unisolated_commit=allow_unisolated_commit,
            allow_full_commit=allow_full_commit,
        )
        dispatched = True
        store.add_job(session_id, "commit-dispatched", {"job_id": job_id})
        progress(
            42,
            f"Panorama przyjęła commit job {job_id}",
            {"event": "panorama-job-dispatched", "jobId": job_id, "jobDispatched": True},
        )

        def job_progress(detail: dict[str, Any]) -> None:
            panorama_value = detail.get("panoramaProgress")
            mapped = (
                42 + int(53 * int(panorama_value) / 100)
                if isinstance(panorama_value, int)
                else 44
            )
            status = str(detail.get("status") or "UNKNOWN")
            suffix = (
                f" · {panorama_value}%"
                if isinstance(panorama_value, int)
                else " · Panorama nie podała procentu"
            )
            progress(mapped, f"Commit job {job_id}: {status}{suffix}", detail)

        panorama_job_started = time.monotonic()
        result = writer.poll_job(job_id, progress_callback=job_progress)
        terminal_job_result = True
        job_succeeded = result.succeeded
        job_record = {
            **result.__dict__,
            "duration_seconds": round(time.monotonic() - panorama_job_started, 1),
            "phase_timeline_seconds": dict(phase_timeline),
        }
        store.add_job(session_id, "commit", job_record)
        if not result.succeeded:
            store.record_recoverable_stage_failure(
                session_id,
                stable_state=stable_state,
                detail=f"Commit job {job_id} zakończył się {result.result}.",
            )
            raise PanoramaResponseError(f"Commit job zakończył się {result.result}.")
        progress(
            97,
            "Panorama potwierdziła sukces joba; finalizacja sesji bez kolejnego pełnego pobrania",
            {"event": "commit-job-confirmed", "jobId": job_id},
        )
        store.transition(session_id, SessionState.COMMITTED)
        _release_locks(store, session_id, writer, acquired)
        progress(100, "Commit zakończony poprawnie", {"event": "stage-finished", "jobId": job_id})
        total_duration = round(time.monotonic() - started, 1)
        store.append_event(
            session_id,
            "COMMIT_PERFORMANCE",
            {
                "job_id": job_id,
                "total_duration_seconds": total_duration,
                "panorama_job_duration_seconds": job_record["duration_seconds"],
                "phase_timeline_seconds": dict(phase_timeline),
                "full_config_reads": full_config_reads,
                "post_running_deferred_to_push_or_audit": True,
            },
        )
        return {**job_record, "phase_timeline_seconds": dict(phase_timeline), "total_duration_seconds": total_duration}
    except OutcomeUnknownError:
        store.force_terminal_state(
            session_id,
            SessionState.OUTCOME_UNKNOWN,
            detail="Wynik dispatchu commit jest nieznany; nie wolno uruchamiać push.",
        )
        raise
    except Exception as exc:
        current = store.load_manifest(session_id, verify=False)["state"]
        if current == SessionState.COMMITTING.value:
            if job_succeeded:
                store.force_terminal_state(
                    session_id,
                    SessionState.OUTCOME_UNKNOWN,
                    detail=(
                        "Commit job zakończył się sukcesem, ale lokalna finalizacja sesji "
                        "nie została potwierdzona; push wymaga reconciliation."
                    ),
                )
            elif dispatched and not terminal_job_result:
                store.force_terminal_state(
                    session_id,
                    SessionState.OUTCOME_UNKNOWN,
                    detail="Nie potwierdzono końcowego wyniku commit job; wymagane reconciliation.",
                )
            else:
                store.record_recoverable_stage_failure(
                    session_id,
                    stable_state=stable_state,
                    detail=f"Commit odrzucony przed uruchomieniem joba: {type(exc).__name__}: {exc}",
                )
        if store.load_manifest(session_id, verify=False)["state"] != SessionState.OUTCOME_UNKNOWN.value:
            _release_locks(store, session_id, writer, acquired)
        raise
    except BaseException as interrupted:
        try:
            current = store.load_manifest(session_id, verify=False)["state"]
            if current == SessionState.COMMITTING.value:
                store.force_terminal_state(
                    session_id,
                    SessionState.OUTCOME_UNKNOWN,
                    detail=(
                        "Przerwano proces podczas commit/pollingu "
                        f"({type(interrupted).__name__}); wynik joba wymaga reconciliation."
                    ),
                )
        except Exception:
            pass
        # The job may still be active; preserve both Panorama config locks and
        # the host-wide durable marker.
        raise


def push_session(
    store: SessionStore,
    session_id: str,
    reader: PanoramaReadClient,
    writer: PanoramaWriteClient,
    *,
    device_groups: Iterable[str],
    progress_callback: Optional[
        Callable[[int, str, Optional[dict[str, Any]]], None]
    ] = None,
) -> dict[str, Any]:
    with store.operation_lock(session_id):
        with store.panorama_job_lock(reader.profile.host, session_id):
            return _push_session_unlocked(
                store,
                session_id,
                reader,
                writer,
                device_groups=device_groups,
                progress_callback=progress_callback,
            )


def _push_session_unlocked(
    store: SessionStore,
    session_id: str,
    reader: PanoramaReadClient,
    writer: PanoramaWriteClient,
    *,
    device_groups: Iterable[str],
    progress_callback: Optional[
        Callable[[int, str, Optional[dict[str, Any]]], None]
    ] = None,
) -> dict[str, Any]:
    started = time.monotonic()
    phase_timeline: dict[str, float] = {}

    def progress(
        value: int, message: str, detail: Optional[dict[str, Any]] = None
    ) -> None:
        payload = dict(detail or {})
        payload.setdefault("elapsedSeconds", round(time.monotonic() - started, 1))
        event = str(payload.get("event") or "")
        if event and (event not in phase_timeline or event == "panorama-job-finished"):
            phase_timeline[event] = float(payload["elapsedSeconds"])
        if progress_callback is None:
            return
        try:
            progress_callback(max(0, min(100, value)), message, payload)
        except Exception:
            pass

    progress(1, "Weryfikacja sesji przed push", {"event": "stage-start"})
    manifest = store.load_manifest(session_id)
    if manifest["state"] != SessionState.COMMITTED.value:
        raise SessionError("Push jest dozwolony wyłącznie po potwierdzonym COMMITTED.")
    patch = store.load_patchset(session_id)
    _assert_session_identity(patch, reader)
    writer.lease.assert_valid(writer.profile, ApiStage.PUSH)
    selected = tuple(sorted(set(device_groups)))
    expected = tuple(sorted(set(patch.affected_device_groups)))
    if selected != expected:
        raise CapabilityError(
            "Push musi obejmować dokładnie pełny rozwinięty zakres dotkniętych DG: "
            + ", ".join(expected)
        )
    application = manifest.get("candidate_application") or {}
    applied_ids = application.get("applied_mutation_ids") or []
    # Push sends committed running state.  Candidate is not part of commit-all,
    # so downloading it twice added latency without strengthening the gate.
    # One live running snapshot after config locks is sufficient for the
    # postcondition check and durable pre-push evidence.
    progress(5, "Sprawdzanie locków konfiguracji i commit", {"event": "lock-check"})
    reader.show_config_locks()
    reader.show_commit_locks()
    acquired: list[Optional[str]] = []
    dispatched = False
    terminal_job_result = False
    job_succeeded = False
    try:
        progress(10, "Zakładanie locków dla zakresu push", {"event": "lock-acquire"})
        for scope in _direct_lock_scopes(patch):
            writer.acquire_config_lock(scope, f"PanOS Toolbox push {session_id}")
            acquired.append(scope)
            store.append_event(session_id, "CONFIG_LOCK_ACQUIRED", {"scope": scope or "shared"})
        progress(18, "Pobieranie jednego live running przed push", {"event": "snapshot-running"})
        pre_push_running = reader.fetch_config("running")
        store.write_snapshot(session_id, "pre_push_running", pre_push_running)
        progress(30, "Sprawdzanie fingerprintów committed state", {"event": "fingerprint-check"})
        try:
            _check_expected_post_state(patch, pre_push_running, applied_ids)
        except ConflictError as exc:
            store.add_conflicts(session_id, [{"stage": "pre-push", "detail": str(exc)}])
            store.transition(session_id, SessionState.CONFLICT)
            raise
        store.add_risk(
            session_id,
            "PUSH_NOT_ADMIN_ISOLATED",
            "PAN-OS 10.2 specific-DG commit-all nie izoluje push według administratora.",
        )
        store.transition(session_id, SessionState.PUSHING)
        # One batch job for the full DG set: never per-IP and never parallel.
        progress(38, "Wysyłanie commit-all do Panorama", {"event": "panorama-job-dispatch"})
        job_id = writer.push(selected)
        dispatched = True
        store.add_job(session_id, "push-dispatched", {"job_id": job_id})
        progress(
            42,
            f"Panorama przyjęła push job {job_id}",
            {"event": "panorama-job-dispatched", "jobId": job_id},
        )

        def job_progress(detail: dict[str, Any]) -> None:
            panorama_value = detail.get("panoramaProgress")
            mapped = (
                42 + int(55 * int(panorama_value) / 100)
                if isinstance(panorama_value, int)
                else 44
            )
            status = str(detail.get("status") or "UNKNOWN")
            suffix = (
                f" · {panorama_value}%"
                if isinstance(panorama_value, int)
                else " · Panorama nie podała procentu"
            )
            progress(mapped, f"Push job {job_id}: {status}{suffix}", detail)

        panorama_job_started = time.monotonic()
        result = writer.poll_job(job_id, progress_callback=job_progress)
        terminal_job_result = True
        job_succeeded = result.succeeded
        job_record = {
            **result.__dict__,
            "duration_seconds": round(time.monotonic() - panorama_job_started, 1),
            "phase_timeline_seconds": dict(phase_timeline),
        }
        store.add_job(session_id, "push", job_record)
        if not result.succeeded:
            store.record_recoverable_stage_failure(
                session_id,
                stable_state=SessionState.COMMITTED,
                detail=f"Push job {job_id} zakończył się {result.result}.",
            )
            raise PanoramaResponseError(f"Push job zakończył się {result.result}.")
        store.transition(session_id, SessionState.PUSHED)
        _release_locks(store, session_id, writer, acquired)
        progress(100, "Push zakończony poprawnie", {"event": "stage-finished", "jobId": job_id})
        total_duration = round(time.monotonic() - started, 1)
        store.append_event(
            session_id,
            "PUSH_PERFORMANCE",
            {
                "job_id": job_id,
                "total_duration_seconds": total_duration,
                "panorama_job_duration_seconds": job_record["duration_seconds"],
                "phase_timeline_seconds": dict(phase_timeline),
                "full_config_reads": 1,
            },
        )
        return {**job_record, "phase_timeline_seconds": dict(phase_timeline), "total_duration_seconds": total_duration}
    except OutcomeUnknownError:
        store.force_terminal_state(
            session_id,
            SessionState.OUTCOME_UNKNOWN,
            detail="Wynik dispatchu push jest nieznany; nie wolno uruchamiać kolejnego joba.",
        )
        raise
    except Exception as exc:
        current = store.load_manifest(session_id, verify=False)["state"]
        if current == SessionState.PUSHING.value:
            if job_succeeded:
                store.force_terminal_state(
                    session_id,
                    SessionState.OUTCOME_UNKNOWN,
                    detail=(
                        "Push job zakończył się sukcesem, ale lokalna finalizacja sesji "
                        "nie została potwierdzona; wymagane reconciliation."
                    ),
                )
            elif dispatched and not terminal_job_result:
                store.force_terminal_state(
                    session_id,
                    SessionState.OUTCOME_UNKNOWN,
                    detail="Nie potwierdzono końcowego wyniku push job; wymagane reconciliation.",
                )
            else:
                store.record_recoverable_stage_failure(
                    session_id,
                    stable_state=SessionState.COMMITTED,
                    detail=f"Push odrzucony przed uruchomieniem joba: {type(exc).__name__}: {exc}",
                )
        if store.load_manifest(session_id, verify=False)["state"] != SessionState.OUTCOME_UNKNOWN.value:
            _release_locks(store, session_id, writer, acquired)
        raise
    except BaseException as interrupted:
        try:
            current = store.load_manifest(session_id, verify=False)["state"]
            if current == SessionState.PUSHING.value:
                store.force_terminal_state(
                    session_id,
                    SessionState.OUTCOME_UNKNOWN,
                    detail=(
                        "Przerwano proces podczas push/pollingu "
                        f"({type(interrupted).__name__}); wynik joba wymaga reconciliation."
                    ),
                )
        except Exception:
            pass
        raise
