"""Transactional candidate apply, rollback, commit and push orchestration."""

from __future__ import annotations

import concurrent.futures
import copy
import json
import hashlib
import hmac
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

from .cleaner_adapter import build_cleanup_patchset
from .client import PanoramaReadClient, PanoramaWriteClient
from .commit_review import (
    build_commit_review,
    build_scope_guard,
    render_scope_guard_text,
)
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
    raw_sha256,
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
            full_config_reads = 0
            targeted_xpath_reads = 0
            running: Optional[ET.Element] = None
            candidate: Optional[ET.Element] = None
            try:
                running_failures = _targeted_running_postcondition_failures(
                    reader,
                    patch.mutations,
                    progress_callback=lambda done, _total, _xpath: None,
                )
                targeted_xpath_reads += _targeted_xpath_query_count(
                    patch.mutations, expected_state="after"
                )
                if running_failures:
                    candidate_failures = _targeted_candidate_postcondition_failures(
                        reader, patch.mutations
                    )
                    targeted_xpath_reads += _targeted_xpath_query_count(
                        patch.mutations, expected_state="after"
                    )
                else:
                    candidate_failures = []
            except Exception:
                running = reader.fetch_config("running")
                candidate = reader.fetch_config("candidate")
                full_config_reads = 2
                running_failures = _postcondition_failures(
                    patch.mutations, running
                )
                candidate_failures = _postcondition_failures(
                    patch.mutations, candidate
                )
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
            # A candidate match still needs full trees for the mandatory
            # commit review.  An already committed match is proven entirely by
            # exact running XPath reads and avoids downloading either tree.
            if state is SessionState.CANDIDATE_APPLIED and (
                running is None or candidate is None
            ):
                running = reader.fetch_config("running")
                candidate = reader.fetch_config("candidate")
                full_config_reads += 2
                running_failures = _postcondition_failures(
                    patch.mutations, running
                )
                candidate_failures = _postcondition_failures(
                    patch.mutations, candidate
                )
                if not running_failures:
                    state = SessionState.COMMITTED
                    matched = "running"
                elif candidate_failures:
                    raise ConflictError(
                        "Live Panorama zmieniła się podczas uzgadniania wykonania zewnętrznego."
                    )
            if running is not None:
                store.write_snapshot(
                    session_id, "external_verified_running", running
                )
            if candidate is not None:
                store.write_snapshot(
                    session_id, "external_verified_candidate", candidate
                )
            store.record_external_execution(
                session_id,
                state=state,
                source=source,
                applied_mutation_ids=(mutation.mutation_id for mutation in patch.mutations),
                evidence={
                    "matchedTree": matched,
                    "mutationCount": len(patch.mutations),
                    "targetedXPathReads": targeted_xpath_reads,
                    "fullConfigReads": full_config_reads,
                },
            )
            if state is SessionState.CANDIDATE_APPLIED:
                assert running is not None and candidate is not None
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
    started_at = time.monotonic()

    def progress(
        value: int, message: str, detail: Optional[dict[str, Any]] = None
    ) -> None:
        if progress_callback is None:
            return
        # Progress is observational.  A broken browser/poller must never alter
        # the transactional outcome of a Panorama write.
        try:
            payload = dict(detail or {})
            payload.setdefault(
                "elapsedSeconds", round(time.monotonic() - started_at, 1)
            )
            progress_callback(max(0, min(100, value)), message, payload)
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

    # Planning already persisted integrity-checked full snapshots and entity
    # backups.  Loading them locally avoids two redundant /config downloads
    # before locks.  A strict live change-summary plus targeted XPath reads
    # below decides whether they are still current; otherwise we fail over to
    # fresh full snapshots before the first write.
    progress(4, "Wczytywanie lokalnych snapshotów planu", None)
    local_plan_snapshots = True
    full_config_reads = 0
    targeted_xpath_reads = 0
    try:
        running = store.load_snapshot(session_id, "plan_running")
        candidate = store.load_snapshot(session_id, "plan_candidate")
    except (SessionError, ValidationError):
        local_plan_snapshots = False
        progress(
            6,
            "Starszy plan nie ma snapshotów — jednorazowe pobieranie live config",
            {"event": "candidate-snapshot-fallback", "indeterminate": True},
        )
        running = reader.fetch_config("running")
        candidate = reader.fetch_config("candidate")
        full_config_reads += 2
    store.write_snapshot(session_id, "pre_running", running)
    store.write_snapshot(session_id, "pre_candidate", candidate)
    progress(
        18,
        "Backup każdej encji i lokalne snapshoty są gotowe",
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
        progress(27, "Lock aktywny; lekki proof i punktowe XPath", None)

        planned_native_raw_sha = (
            ((manifest.get("diff_summary") or {}).get("native") or {}).get("sha256")
        )
        live_native, live_native_error = _read_native_change_summary(reader)
        live_native_raw_sha = (
            raw_sha256(ET.tostring(live_native, encoding="utf-8"))
            if live_native is not None
            else None
        )
        strict_plan_proof = bool(
            local_plan_snapshots
            and planned_native_raw_sha
            and live_native_raw_sha
            and hmac.compare_digest(
                str(planned_native_raw_sha), str(live_native_raw_sha)
            )
        )
        targeted_conflicted_components: set[str] = set()
        targeted_conflicts: list[dict[str, Any]] = []
        if strict_plan_proof:
            def precondition_progress(done: int, total: int, xpath: str) -> None:
                nonlocal targeted_xpath_reads
                targeted_xpath_reads = done
                progress(
                    27 + int(8 * done / max(1, total)),
                    f"Live precheck XPath {done}/{total}",
                    {
                        "event": "candidate-targeted-precheck",
                        "completedOperations": done,
                        "totalOperations": total,
                        "xpath": xpath,
                    },
                )

            targeted_failures = _targeted_candidate_precondition_failures(
                reader,
                patch.mutations,
                progress_callback=precondition_progress,
            )
            mutation_by_id = {
                mutation.mutation_id: mutation for mutation in patch.mutations
            }
            for failure in targeted_failures:
                mutation = mutation_by_id[str(failure["mutation_id"])]
                targeted_conflicted_components.add(mutation.component_id)
                targeted_conflicts.append(
                    {
                        "stage": "candidate-targeted-precheck",
                        "component_id": mutation.component_id,
                        **failure,
                    }
                )
            progress(
                36,
                "Snapshot planu potwierdzony bez pełnego pobrania /config",
                {
                    "event": "candidate-fast-path",
                    "fullConfigReads": full_config_reads,
                    "targetedXPathReads": targeted_xpath_reads,
                },
            )
        else:
            progress(
                28,
                "Proof planu zmienił się lub jest niedostępny — pełny live fallback",
                {
                    "event": "candidate-full-config-fallback",
                    "indeterminate": True,
                    "detail": live_native_error,
                },
            )
            running = reader.fetch_config("running")
            candidate = reader.fetch_config("candidate")
            full_config_reads += 2
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
        conflicted_components.update(targeted_conflicted_components)
        conflicts.extend(targeted_conflicts)
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
            store.append_event(
                session_id,
                "CANDIDATE_BATCH_START",
                {
                    "mutation_ids": [mutation.mutation_id for mutation in safe],
                    "mutation_count": len(safe),
                    "operation_count": total_operations,
                },
            )
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
                started = False
                for operation in mutation.forward:
                    writer.apply_operation(operation)
                    if not started:
                        applied.append(mutation)
                        started = True
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
                def validation_progress(detail: dict[str, Any]) -> None:
                    panorama_value = detail.get("panoramaProgress")
                    mapped = (
                        86 + int(4 * int(panorama_value) / 100)
                        if isinstance(panorama_value, int)
                        else 87
                    )
                    progress(
                        mapped,
                        f"Validate job {validation_job}: "
                        f"{detail.get('status') or 'UNKNOWN'}",
                        detail,
                    )

                validation = writer.poll_job(
                    validation_job, progress_callback=validation_progress
                )
                store.add_job(session_id, "validation", validation.__dict__)
                if not validation.succeeded:
                    raise ValidationError(
                        f"Walidacja candidate zakończyła się {validation.result}."
                    )
            progress(90, "Kontrola wyniku każdej dotkniętej ścieżki", None)
            post_candidate = reader.fetch_config("candidate")
            full_config_reads += 1
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
            store.append_event(
                session_id,
                "CANDIDATE_BATCH_APPLIED",
                {
                    "mutation_ids": [mutation.mutation_id for mutation in safe],
                    "mutation_count": len(safe),
                    "operation_count": completed_operations,
                    "postconditions_verified": True,
                },
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
            total_duration = round(time.monotonic() - started_at, 1)
            store.append_event(
                session_id,
                "CANDIDATE_PERFORMANCE",
                {
                    "total_duration_seconds": total_duration,
                    "full_config_reads": full_config_reads,
                    "targeted_xpath_reads": targeted_xpath_reads,
                    "plan_snapshots_reused": bool(local_plan_snapshots),
                    "completed_operations": completed_operations,
                    "validation_job_id": validation_job,
                },
            )
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
                    "fullConfigReads": full_config_reads,
                    "targetedXPathReads": targeted_xpath_reads,
                    "elapsedSeconds": total_duration,
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


def _target_element_from_response(
    response: ET.Element, mutation: Mutation
) -> Optional[ET.Element]:
    """Extract one mutation target from a targeted PAN-OS ``action=get``.

    PAN-OS returns the requested entry below ``response/result`` without its
    complete /config ancestry.  Matching the identity from the immutable
    before/after backup works for both present and deleted entries and avoids
    reconstructing a fake configuration tree.
    """

    identity_xml = mutation.after_xml or mutation.before_xml
    if not identity_xml:
        return None
    identity = ET.fromstring(identity_xml)
    expected_name = identity.get("name")
    for element in response.iter(identity.tag):
        if expected_name is None or element.get("name") == expected_name:
            return element
    return None


def _targeted_rule_order_problem(
    mutation: Mutation, response: ET.Element
) -> Optional[str]:
    if mutation.entity_type != "policy" or mutation.after_xml is None:
        return None
    expected = ET.fromstring(mutation.after_xml)
    name = expected.get("name")
    if not name:
        return "Nie można ustalić nazwy odtwarzanej polityki."
    rules = next(response.iter("rules"), None)
    result = response.find("./result")
    entries = (
        rules.findall("./entry")
        if rules is not None
        else result.findall("./entry") if result is not None else []
    )
    names = [entry.get("name") for entry in entries if entry.get("name")]
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


def _targeted_candidate_state_failures(
    reader: PanoramaReadClient,
    mutations: Iterable[Mutation],
    *,
    expected_state: str,
    config_type: str = "candidate",
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> list[dict[str, Any]]:
    """Verify touched entries with small concurrent XPath reads."""

    if expected_state not in {"before", "after"}:
        raise ValueError("expected_state must be before or after")
    if config_type not in {"running", "candidate"}:
        raise ValueError("config_type must be running or candidate")

    selected = tuple(mutations)
    queries = {mutation.target_xpath for mutation in selected}
    queries.update(
        parent_xpath(mutation.target_xpath)
        for mutation in selected
        if expected_state == "after"
        and mutation.entity_type == "policy"
        and mutation.after_xml is not None
    )
    responses: dict[str, ET.Element] = {}

    def fetch(xpath: str) -> tuple[str, ET.Element]:
        return xpath, reader.fetch_xpath(xpath, config_type=config_type)

    total = len(queries)
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(8, max(1, total))
    ) as pool:
        futures = [pool.submit(fetch, xpath) for xpath in sorted(queries)]
        for future in concurrent.futures.as_completed(futures):
            xpath, response = future.result()
            responses[xpath] = response
            completed += 1
            if progress_callback is not None:
                progress_callback(completed, total, xpath)

    failures: list[dict[str, Any]] = []
    for mutation in selected:
        current = _target_element_from_response(
            responses[mutation.target_xpath], mutation
        )
        current_sha = fingerprint_element(current)
        expected_sha = (
            mutation.after_sha256
            if expected_state == "after"
            else mutation.before_sha256
        )
        if current_sha != expected_sha:
            failures.append(
                {
                    "mutation_id": mutation.mutation_id,
                    "xpath": mutation.target_xpath,
                    "expected_sha256": expected_sha,
                    "current_sha256": current_sha,
                }
            )
            continue
        if (
            expected_state == "after"
            and mutation.entity_type == "policy"
            and mutation.after_xml is not None
        ):
            order_problem = _targeted_rule_order_problem(
                mutation, responses[parent_xpath(mutation.target_xpath)]
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


def _targeted_xpath_query_count(
    mutations: Iterable[Mutation], *, expected_state: str
) -> int:
    selected = tuple(mutations)
    queries = {mutation.target_xpath for mutation in selected}
    if expected_state == "after":
        queries.update(
            parent_xpath(mutation.target_xpath)
            for mutation in selected
            if mutation.entity_type == "policy" and mutation.after_xml is not None
        )
    return len(queries)


def _targeted_candidate_precondition_failures(
    reader: PanoramaReadClient,
    mutations: Iterable[Mutation],
    *,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> list[dict[str, Any]]:
    return _targeted_candidate_state_failures(
        reader,
        mutations,
        expected_state="before",
        progress_callback=progress_callback,
    )


def _targeted_candidate_postcondition_failures(
    reader: PanoramaReadClient,
    mutations: Iterable[Mutation],
    *,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> list[dict[str, Any]]:
    return _targeted_candidate_state_failures(
        reader,
        mutations,
        expected_state="after",
        progress_callback=progress_callback,
    )


def _targeted_running_postcondition_failures(
    reader: PanoramaReadClient,
    mutations: Iterable[Mutation],
    *,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> list[dict[str, Any]]:
    return _targeted_candidate_state_failures(
        reader,
        mutations,
        expected_state="after",
        config_type="running",
        progress_callback=progress_callback,
    )


def _scope_guard_override_matches(
    guard: dict[str, Any],
    *,
    allowed: bool,
    acknowledged_digest: Optional[str],
) -> bool:
    current_digest = str(guard.get("findingDigest") or "")
    supplied_digest = str(acknowledged_digest or "")
    return bool(
        allowed
        and current_digest
        and supplied_digest
        and hmac.compare_digest(current_digest, supplied_digest)
    )


def _scope_guard_block_detail(guard: dict[str, Any]) -> str:
    findings = list(guard.get("findings") or ())
    if not findings:
        return "Scope guard nie zwrócił szczegółowego findingu."
    samples: list[str] = []
    for finding in findings[:5]:
        location = (
            finding.get("xpath")
            or finding.get("target")
            or finding.get("detail")
            or "brak ścieżki"
        )
        samples.append(f"{finding.get('code') or 'UNKNOWN'}: {location}")
    suffix = f"; oraz {len(findings) - 5} kolejnych" if len(findings) > 5 else ""
    return "; ".join(samples) + suffix


def commit_session(
    store: SessionStore,
    session_id: str,
    reader: PanoramaReadClient,
    writer: PanoramaWriteClient,
    *,
    partial: bool = True,
    allow_unisolated_commit: bool = False,
    allow_full_commit: bool = False,
    allow_scope_guard_override: bool = False,
    acknowledged_scope_guard_digest: Optional[str] = None,
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
                allow_scope_guard_override=allow_scope_guard_override,
                acknowledged_scope_guard_digest=acknowledged_scope_guard_digest,
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
    allow_scope_guard_override: bool = False,
    acknowledged_scope_guard_digest: Optional[str] = None,
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
    review_override_accepted = _scope_guard_override_matches(
        review_guard,
        allowed=allow_scope_guard_override,
        acknowledged_digest=acknowledged_scope_guard_digest,
    )
    previous_guard = manifest.get("precommit_guard") or {}
    previous_override_accepted = bool(
        isinstance(previous_guard, dict)
        and _scope_guard_override_matches(
            previous_guard,
            allowed=allow_scope_guard_override,
            acknowledged_digest=acknowledged_scope_guard_digest,
        )
    )
    if (
        not review.get("commitReady") or not review_guard.get("passed")
    ) and not (review_override_accepted or previous_override_accepted):
        raise ConflictError(
            "Commit zablokowany przez scope guard z przeglądu. "
            + _scope_guard_block_detail(review_guard)
            + " Otwórz dokładne ustalenia albo użyj jawnego override dla "
            "fingerprintu tej konkretnej blokady."
        )

    # The expensive two-tree review was already generated immediately after
    # Candidate.  Commit first proves the unchanged lightweight change-summary
    # and rechecks only touched XPath values.  Full candidate/running downloads
    # are compatibility fallbacks, never the normal path.
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
        proof_guard = previous_guard if previous_override_accepted else review_guard
        review_native = review.get("native") or {}
        reviewed_native_sha = (
            proof_guard.get("nativeChangeSummarySemanticSha256")
            if previous_override_accepted
            else None
        ) or review_native.get("semanticSha256")
        reviewed_native_raw_sha = (
            proof_guard.get("nativeChangeSummaryRawSha256")
            if previous_override_accepted
            else None
        ) or review_native.get("rawSha256")
        reviewed_candidate = review.get("candidate") or {}
        reviewed_candidate_sha = (
            proof_guard.get("candidateSemanticSha256")
            if previous_override_accepted
            else None
        ) or reviewed_candidate.get("semanticSha256")
        review_running = store.load_snapshot(session_id, "review_running")
        current_native: Optional[ET.Element]
        current_native_error: Optional[str]

        progress(
            15,
            "Preflight: lekki proof change-summary — pełny candidate nie jest jeszcze pobierany",
            {
                "event": "preflight-change-proof",
                "jobDispatched": False,
                "fullConfigReads": 0,
            },
        )
        current_native, current_native_error = _read_native_change_summary(reader)
        current_native_sha = (
            fingerprint_element(current_native) if current_native is not None else None
        )
        current_native_raw_sha = (
            raw_sha256(ET.tostring(current_native, encoding="utf-8"))
            if current_native is not None
            else None
        )
        if (
            current_native_sha
            and reviewed_native_sha
            and current_native_sha != reviewed_native_sha
        ):
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

        strict_change_proof = bool(
            current_native_raw_sha
            and reviewed_native_raw_sha
            and hmac.compare_digest(
                str(current_native_raw_sha), str(reviewed_native_raw_sha)
            )
        )
        applied_set = set(applied_ids)
        selected_mutations = tuple(
            mutation
            for mutation in patch.mutations
            if mutation.mutation_id in applied_set
        )
        targeted_reads = 0
        if strict_change_proof:
            progress(
                17,
                "Change-summary bez zmian — punktowa kontrola dotkniętych XPath",
                {
                    "event": "preflight-targeted-xpaths",
                    "jobDispatched": False,
                    "totalOperations": len(selected_mutations),
                },
            )

            def targeted_progress(done: int, total: int, xpath: str) -> None:
                nonlocal targeted_reads
                targeted_reads = done
                mapped = 17 + int(7 * done / max(1, total))
                progress(
                    mapped,
                    f"Punktowa kontrola candidate {done}/{total}",
                    {
                        "event": "preflight-targeted-xpaths",
                        "jobDispatched": False,
                        "completedOperations": done,
                        "totalOperations": total,
                        "xpath": xpath,
                    },
                )

            targeted_failures = _targeted_candidate_postcondition_failures(
                reader,
                selected_mutations,
                progress_callback=targeted_progress,
            )
            if targeted_failures:
                detail = (
                    "Dotknięte ścieżki candidate zmieniły się po przeglądzie: "
                    + ", ".join(
                        str(item["mutation_id"])
                        for item in targeted_failures[:10]
                    )
                )
                store.add_conflicts(
                    session_id,
                    [
                        {"stage": "pre-commit-targeted-xpath", **item}
                        for item in targeted_failures
                    ],
                )
                raise ConflictError(detail)

            # Close the gap between the first change proof and concurrent XPath
            # reads.  Any edit during that window switches to the authoritative
            # full-config fallback instead of being trusted.
            final_native, final_native_error = _read_native_change_summary(reader)
            final_native_raw_sha = (
                raw_sha256(ET.tostring(final_native, encoding="utf-8"))
                if final_native is not None
                else None
            )
            strict_change_proof = bool(
                final_native_raw_sha
                and reviewed_native_raw_sha
                and hmac.compare_digest(
                    str(final_native_raw_sha), str(reviewed_native_raw_sha)
                )
            )
            current_native = final_native
            current_native_error = final_native_error

        if strict_change_proof:
            candidate = store.load_snapshot(
                session_id,
                "pre_commit_candidate" if previous_override_accepted else "review_candidate",
            )
            live_candidate_sha = fingerprint_element(candidate)
            if not reviewed_candidate_sha or live_candidate_sha != reviewed_candidate_sha:
                raise ValidationError(
                    "Lokalny snapshot review_candidate nie zgadza się z manifestem sesji."
                )
            store.write_snapshot(session_id, "pre_commit_candidate", candidate)
            live_guard = copy.deepcopy(proof_guard)
            live_guard["verificationMode"] = (
                "strict-change-summary+targeted-candidate-xpaths"
            )
            live_guard["targetedXPathReads"] = targeted_reads
            progress(
                28,
                "Szybki preflight PASS — bez ponownego pobierania pełnego candidate",
                {
                    "event": "preflight-fast-path",
                    "jobDispatched": False,
                    "fullConfigReads": 0,
                    "targetedXPathReads": targeted_reads,
                },
            )
        else:
            progress(
                18,
                "Brak stabilnego proof change-summary — awaryjne pobieranie pełnego live candidate",
                {
                    "event": "preflight-candidate-fallback",
                    "indeterminate": True,
                    "jobDispatched": False,
                    "detail": current_native_error,
                },
            )
            candidate = reader.fetch_config("candidate")
            full_config_reads += 1
            store.write_snapshot(session_id, "pre_commit_candidate", candidate)
            progress(
                24,
                "Preflight fallback: fingerprinty i zgodność z pokazanym diffem",
                {"event": "fingerprint-check", "jobDispatched": False},
            )
            try:
                _check_expected_post_state(patch, candidate, applied_ids)
            except ConflictError as exc:
                store.add_conflicts(
                    session_id, [{"stage": "pre-commit", "detail": str(exc)}]
                )
                raise
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
                "Preflight fallback: ponowny pełny scope guard zależności",
                {"event": "preflight-scope-guard", "jobDispatched": False},
            )
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
            live_guard["verificationMode"] = "full-candidate-fallback"
            # Use a fresh proof after the fallback snapshot so edits during the
            # download cannot slip between review and dispatch.
            current_native, current_native_error = _read_native_change_summary(reader)

        live_guard["candidateSemanticSha256"] = live_candidate_sha
        live_guard["reviewGeneratedAt"] = review.get("generatedAt")
        live_guard["nativeChangeSummarySemanticSha256"] = (
            fingerprint_element(current_native)
            if current_native is not None
            else None
        )
        live_guard["nativeChangeSummaryRawSha256"] = (
            raw_sha256(ET.tostring(current_native, encoding="utf-8"))
            if current_native is not None
            else None
        )
        live_override_accepted = _scope_guard_override_matches(
            live_guard,
            allowed=allow_scope_guard_override,
            acknowledged_digest=acknowledged_scope_guard_digest,
        )
        live_guard["overrideRequested"] = bool(allow_scope_guard_override)
        live_guard["overrideApplied"] = bool(
            not live_guard.get("passed") and live_override_accepted
        )
        checked_at = utc_now()
        guard_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        guard_artifact = f"precommit_scope_guard_{guard_stamp}.txt"
        live_guard["artifact"] = guard_artifact
        store.write_artifact(
            session_id,
            guard_artifact,
            render_scope_guard_text(session_id, checked_at, live_guard),
            kind="live-precommit-scope-guard",
        )
        store.record_precommit_guard(session_id, live_guard)
        if not live_guard.get("passed") and not live_override_accepted:
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
                "lub zmianę poza zakresem. "
                + _scope_guard_block_detail(live_guard)
                + f" Dokładny raport: {guard_artifact}."
            )
        if not live_guard.get("passed") and live_override_accepted:
            store.add_risk(
                session_id,
                "SCOPE_GUARD_OVERRIDE",
                (
                    "Operator jawnie zaakceptował dokładny fingerprint blokady "
                    f"{live_guard.get('findingDigest')} obejmujący "
                    f"{live_guard.get('findingCount')} ustaleń."
                ),
            )
            store.append_event(
                session_id,
                "SCOPE_GUARD_OVERRIDE_APPLIED",
                {
                    "finding_digest": live_guard.get("findingDigest"),
                    "finding_count": live_guard.get("findingCount"),
                    "finding_codes": sorted(
                        {
                            str(finding.get("code") or "UNKNOWN")
                            for finding in live_guard.get("findings") or ()
                        }
                    ),
                    "artifact": guard_artifact,
                },
            )
            progress(
                30,
                "Scope guard BLOCK — operator zaakceptował dokładny fingerprint; commit nadal nie został wysłany",
                {
                    "event": "scope-guard-override",
                    "jobDispatched": False,
                    "findingCount": live_guard.get("findingCount"),
                    "findingDigest": live_guard.get("findingDigest"),
                },
            )

        progress(
            32,
            "Preflight: potwierdzanie, że running nie zmienił się od przeglądu",
            {"event": "preflight-running-proof", "jobDispatched": False},
        )
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
    applied_set = set(applied_ids)
    selected_mutations = tuple(
        mutation
        for mutation in patch.mutations
        if mutation.mutation_id in applied_set
    )
    if not selected_mutations:
        raise SessionError("Manifest nie zawiera mutacji potwierdzonych po commit.")
    # Push sends committed running state.  Candidate is not part of commit-all.
    # Normal preflight therefore checks only the touched running XPath values;
    # a full /config read is retained solely as a compatibility fallback.
    progress(5, "Sprawdzanie locków konfiguracji i commit", {"event": "lock-check"})
    reader.show_config_locks()
    reader.show_commit_locks()
    acquired: list[Optional[str]] = []
    dispatched = False
    terminal_job_result = False
    job_succeeded = False
    full_config_reads = 0
    targeted_xpath_reads = 0
    try:
        progress(10, "Zakładanie locków dla zakresu push", {"event": "lock-acquire"})
        for scope in _direct_lock_scopes(patch):
            writer.acquire_config_lock(scope, f"PanOS Toolbox push {session_id}")
            acquired.append(scope)
            store.append_event(session_id, "CONFIG_LOCK_ACQUIRED", {"scope": scope or "shared"})
        progress(
            18,
            "Punktowa kontrola committed running przed push",
            {
                "event": "pre-push-targeted-xpaths",
                "totalOperations": len(selected_mutations),
                "fullConfigReads": 0,
            },
        )

        def targeted_progress(done: int, total: int, xpath: str) -> None:
            nonlocal targeted_xpath_reads
            targeted_xpath_reads = done
            mapped = 18 + int(12 * done / max(1, total))
            progress(
                mapped,
                f"Kontrola running {done}/{total}",
                {
                    "event": "pre-push-targeted-xpaths",
                    "completedOperations": done,
                    "totalOperations": total,
                    "xpath": xpath,
                    "fullConfigReads": 0,
                },
            )

        targeted_failures: list[dict[str, Any]]
        try:
            targeted_failures = _targeted_running_postcondition_failures(
                reader,
                selected_mutations,
                progress_callback=targeted_progress,
            )
        except Exception as targeted_error:
            progress(
                22,
                "Punktowa kontrola niedostępna — awaryjny pełny odczyt running",
                {
                    "event": "pre-push-running-fallback",
                    "indeterminate": True,
                    "detail": f"{type(targeted_error).__name__}: {targeted_error}",
                },
            )
            pre_push_running = reader.fetch_config("running")
            full_config_reads += 1
            store.write_snapshot(session_id, "pre_push_running", pre_push_running)
            targeted_failures = _postcondition_failures(
                selected_mutations, pre_push_running
            )
        if targeted_failures:
            detail = (
                "Dotknięty committed running zmienił się przed push: "
                + ", ".join(
                    str(item["mutation_id"])
                    for item in targeted_failures[:10]
                )
            )
            store.add_conflicts(
                session_id,
                [
                    {"stage": "pre-push", **item}
                    for item in targeted_failures
                ],
            )
            store.transition(session_id, SessionState.CONFLICT)
            raise ConflictError(detail)
        progress(
            30,
            "Committed running zgodny z planem",
            {
                "event": "pre-push-fingerprint-pass",
                "fullConfigReads": full_config_reads,
                "targetedXPathReads": targeted_xpath_reads,
            },
        )
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
                "full_config_reads": full_config_reads,
                "targeted_xpath_reads": targeted_xpath_reads,
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
