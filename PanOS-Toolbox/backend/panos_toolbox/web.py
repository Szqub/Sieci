"""Loopback-only Flask adapter for the React GUI."""

from __future__ import annotations

import ipaddress
import json
import secrets
import threading
import time
import webbrowser
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

from .ad_groups import generate_ad_group_definition
from .client import PanoramaReadClient
from .diffing import compare_configs
from .doctor import run_doctor
from .engine import (
    apply_candidate,
    commit_session,
    prepare_commit_review,
    push_session,
    reconcile_external_execution,
)
from .errors import (
    CapabilityError,
    ConflictError,
    DependencyError,
    InputError,
    IntegrityError,
    OutcomeUnknownError,
    ToolboxError,
)
from .handmode import (
    write_handmode_artifacts,
    write_restore_conflict_handmode_artifacts,
)
from .models import ApiStage, Mutation, PatchSet, SessionState
from .lookup import lookup_exact
from .policy_requests import build_policy_creation_plan
from .profile import PanoramaProfile, load_profile, normalize_host
from .profile_store import ProfileStore
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


def _wire_session(
    store: SessionStore,
    session_id: str,
    *,
    verify: bool = True,
) -> dict[str, Any]:
    # Write-stage workers have already verified the session before mutation.
    # Their terminal UI update may skip a second full re-hash of multi-MB XML
    # snapshots so a completed Panorama job is reflected immediately.  Normal
    # GET/history/restore paths keep the integrity-strict default.
    manifest = store.load_manifest(session_id, verify=verify)
    patch = store.load_patchset(session_id)
    jobs = []
    job_records = list(manifest.get("jobs", []))
    finished_job_kinds = {
        str(record.get("stage", "")).split("-", 1)[0]
        for record in job_records
        if str(record.get("status", "")).upper() == "FIN"
    }
    for index, record in enumerate(job_records, 1):
        stage = str(record.get("stage", "candidate"))
        kind = "candidate" if stage == "validation" else stage.split("-", 1)[0]
        # ``*-dispatched`` is only an audit breadcrumb.  Once the matching
        # terminal Panorama result exists, exposing both records left a fake
        # 50% running row in the GUI forever.
        if stage.endswith("-dispatched") and kind in finished_job_kinds:
            continue
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
                "kind": kind,
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
    input_targets = manifest.get("input_targets") or {}
    targets = list(input_targets.get("ordered") or manifest.get("targets") or ())
    mutations = {mutation.mutation_id: mutation for mutation in patch.mutations}
    backup_items = []
    for record in manifest.get("entity_backups") or ():
        mutation = mutations.get(str(record.get("mutation_id")))
        backup_items.append(
            {
                "mutationId": record.get("mutation_id"),
                "entityType": record.get("entity_type"),
                "entityName": record.get("entity_key"),
                "file": record.get("file"),
                "sha256": record.get("sha256"),
                "targets": list(mutation.causes) if mutation is not None else [],
                "componentId": mutation.component_id if mutation is not None else None,
            }
        )
    stable_restore_states = {
        SessionState.CANDIDATE_APPLIED.value,
        SessionState.PARTIAL.value,
        SessionState.COMMITTED.value,
        SessionState.PUSHED.value,
    }
    return {
        "id": session_id,
        "kind": manifest["operation_kind"],
        "state": manifest["state"],
        "createdAt": manifest["created_utc"],
        "updatedAt": manifest["updated_utc"],
        "operator": manifest["profile"]["username"],
        "panoramaHost": manifest["profile"]["host"],
        "itemCount": len(targets),
        "targets": targets,
        "backupCount": len(backup_items),
        "backupItems": backup_items,
        "canRestore": (
            manifest["operation_kind"] == "cleanup"
            and manifest["state"] in stable_restore_states
        ),
        "canReconcileExternal": (
            manifest["operation_kind"] == "cleanup"
            and manifest["state"]
            in {SessionState.PLANNED.value, SessionState.FAILED.value}
            and bool(patch.mutations)
        ),
        "executionSource": (manifest.get("external_execution") or {}).get(
            "source", "GUI"
        ),
        "affectedDeviceGroups": manifest.get("affected_device_groups") or [],
        "sourceSessionId": patch.source_session_id,
        "sourceSessionIds": list(patch.source_session_ids),
        "description": (
            "Emergency Restore"
            if manifest["operation_kind"] == "restore"
            else "Cleanup Panorama"
        ),
        "jobs": jobs,
        "commitReview": manifest.get("commit_review"),
        "precommitGuard": manifest.get("precommit_guard"),
        "artifacts": store.artifact_catalog(session_id, manifest=manifest),
    }


def _wire_cleanup_plan(
    store: SessionStore, session_id: str, *, verify: bool = True
) -> dict[str, Any]:
    manifest = store.load_manifest(session_id, verify=verify)
    patch = store.load_patchset(session_id)
    excluded_targets = {
        str(item) for item in manifest.get("excluded_targets") or ()
    }
    exclusion_impacted_targets = {
        str(item) for item in manifest.get("exclusion_impacted_targets") or ()
    }
    excluded_component_ids = {
        str(item) for item in manifest.get("excluded_component_ids") or ()
    }
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
    backup_by_mutation = {
        str(record.get("mutation_id")): record
        for record in manifest.get("entity_backups") or ()
    }

    def hit_for(
        scope: str,
        rulebase: Optional[str],
        policy_type: Optional[str],
        name: str,
    ) -> Optional[dict[str, Any]]:
        if not rulebase or not policy_type:
            return None
        return rule_hits.get(f"{scope}/{rulebase}/{policy_type}/{name}")

    def wire_dependency(record: dict[str, Any]) -> dict[str, Any]:
        dependency_type = str(record.get("type") or "unknown")
        scope = str(record.get("scope") or "unknown")
        rulebase = record.get("rulebase")
        policy_type = record.get("policy_type")
        name = str(record.get("name") or "unknown")
        hit = (
            hit_for(scope, str(rulebase), str(policy_type), name)
            if dependency_type == "policy"
            else None
        )
        return {
            "id": str(record.get("id") or f"dependency:{scope}:{name}"),
            "type": dependency_type,
            "name": name,
            "scope": scope,
            "deviceGroup": scope,
            "rulebase": rulebase,
            "policyType": policy_type,
            "relation": str(record.get("relation") or "dependency"),
            "field": str(record.get("relation") or "dependency"),
            "path": str(record.get("path") or ""),
            "readOnly": bool(record.get("read_only")),
            "hitCount": (hit or {}).get("hit_count"),
            "lastHit": (hit or {}).get("last_hit_utc"),
            "lastHitStatus": (hit or {}).get("status"),
            "lastHitAgeDays": (hit or {}).get("age_days"),
            "lastHitDetail": (hit or {}).get("detail"),
        }

    def wire_entity(record: dict[str, Any]) -> dict[str, Any]:
        scope = str(record.get("scope") or "unknown")
        rulebase = record.get("rulebase")
        policy_type = record.get("policy_type")
        name = str(record.get("name") or "unknown")
        hit = (
            hit_for(scope, str(rulebase), str(policy_type), name)
            if record.get("type") == "policy"
            else None
        )
        dependencies = [
            wire_dependency(dependency)
            for dependency in record.get("dependencies") or ()
        ]
        return {
            "id": str(record.get("id") or f"entity:{scope}:{name}"),
            "type": str(record.get("type") or "unknown"),
            "name": name,
            "scope": scope,
            "rulebase": rulebase,
            "policyType": policy_type,
            "path": str(record.get("path") or ""),
            "readOnly": bool(record.get("read_only")),
            "blockedReason": record.get("blocked_reason"),
            "fields": list(record.get("fields") or ()),
            "dependencies": dependencies,
            "hitCount": (hit or {}).get("hit_count"),
            "lastHit": (hit or {}).get("last_hit_utc"),
            "lastHitStatus": (hit or {}).get("status"),
            "lastHitAgeDays": (hit or {}).get("age_days"),
            "lastHitDetail": (hit or {}).get("detail"),
        }

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
        default_protected = any(
            str(reason.get("code")) == "DEFAULT_POLICY_PROTECTED"
            for reason in inventory.get("blocked_reasons") or ()
        )
        decision = (
            "excluded"
            if target in exclusion_impacted_targets or default_protected
            else "skip-live"
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
        entities = [wire_entity(record) for record in inventory.get("entities") or ()]
        reference_by_id: dict[str, dict[str, Any]] = {}
        for entity in entities:
            for dependency in entity["dependencies"]:
                reference_by_id.setdefault(dependency["id"], dependency)
        references = list(reference_by_id.values())
        object_names: list[str] = []
        for object_record in inventory.get("objects") or []:
            location = str(object_record.get("location") or "unknown")
            object_name = str(object_record.get("name") or "unknown")
            object_names.append(f"{location}/{object_name}")
        direct_policy_hits = [
            hit_for(
                str(entity.get("scope") or ""),
                entity.get("rulebase"),
                entity.get("policyType"),
                str(entity.get("name") or ""),
            )
            for entity in entities
            if entity.get("type") == "policy"
        ]
        dependency_policy_hits = [
            hit_for(
                str(reference.get("scope") or ""),
                reference.get("rulebase"),
                reference.get("policyType"),
                str(reference.get("name") or ""),
            )
            for reference in references
            if reference.get("type") == "policy"
        ]
        related_hit_records = [
            value for value in [*direct_policy_hits, *dependency_policy_hits] if value
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
                "excludedByUser": target in excluded_targets,
                "defaultPolicyProtected": default_protected,
                "exclusionReason": (
                    "Wykluczony: dotyka chronionej polityki DEFAULT."
                    if default_protected
                    else
                    "Wykluczony ręcznie przez operatora."
                    if target in excluded_targets
                    else "Wykluczony razem z atomowym komponentem zależności."
                    if target in exclusion_impacted_targets
                    else None
                ),
                "lastHit": (last_hit_record or {}).get("last_hit_utc"),
                "hitCount": (last_hit_record or {}).get("hit_count"),
                "lastHitAgeDays": (last_hit_record or {}).get("age_days"),
                "lastHitStatus": (last_hit_record or {}).get("status"),
                "lastHitDetail": (last_hit_record or {}).get("detail"),
                "recentLastHit": (last_hit_record or {}).get("status") == "RECENT",
                "componentId": related[0].component_id if related else None,
                "componentIds": sorted({mutation.component_id for mutation in related}),
                "operationIds": [mutation.mutation_id for mutation in related],
                "entities": entities,
                "backupFiles": [
                    {
                        "mutationId": mutation.mutation_id,
                        "entityType": backup_by_mutation[mutation.mutation_id].get("entity_type"),
                        "entityName": backup_by_mutation[mutation.mutation_id].get("entity_key"),
                        "file": backup_by_mutation[mutation.mutation_id].get("file"),
                        "sha256": backup_by_mutation[mutation.mutation_id].get("sha256"),
                    }
                    for mutation in related
                    if mutation.mutation_id in backup_by_mutation
                ],
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
        "excludedCount": sum(item["decision"] == "excluded" for item in addresses),
        "excludedTargets": sorted(excluded_targets),
        "exclusionImpactedTargets": sorted(exclusion_impacted_targets),
        "excludedComponentIds": sorted(excluded_component_ids),
        "parentSessionId": manifest.get("parent_session_id"),
        "kind": patch.kind,
        "defaultPolicyOverride": bool(manifest.get("allow_default_policy_override")),
        "recentHitCount": (manifest.get("last_hit") or {}).get("recent_hit_count", 0),
        "affectedDeviceGroups": manifest.get("affected_device_groups") or [],
        "diff": _wire_diff(manifest.get("diff_summary") or {}),
        "warnings": manifest.get("warnings") or [],
        "addresses": addresses,
        "operations": _wire_operations(patch),
        "commitReview": manifest.get("commit_review"),
        "analysisPerformance": manifest.get("analysis_performance"),
        "artifacts": store.artifact_catalog(session_id, manifest=manifest),
    }


def _cleanup_exclusion_closure(
    patch: PatchSet,
    targets: Iterable[str] = (),
    *,
    component_ids: Iterable[str] = (),
) -> tuple[tuple[Any, ...], tuple[str, ...], tuple[str, ...]]:
    """Remove every atomically connected component for the excluded targets.

    One target can participate in several components and one component can be
    shared by several targets.  The seed may therefore be either a target or
    an exact component selected from the operation inspector.  Expanding the
    closure until it is stable guarantees that an indirectly impacted target
    cannot still retain a mutation in the executable child plan.
    """

    impacted = {str(target) for target in targets}
    removed_components = {str(component_id) for component_id in component_ids}
    impacted.update(
        cause
        for mutation in patch.mutations
        if mutation.component_id in removed_components
        for cause in mutation.causes
    )
    # The PatchSet already contains connected-component IDs.  Do not perform
    # another cause-based transitive walk here: it made a later exclusion of
    # one row consume unrelated components that happened to share a target
    # label.  A target removes only its own component; a caller that truly
    # wants a larger closure sends explicit component IDs from the inspector.
    removed_components.update(
        mutation.component_id
        for mutation in patch.mutations
        if impacted.intersection(mutation.causes)
    )
    impacted.update(
        cause
        for mutation in patch.mutations
        if mutation.component_id in removed_components
        for cause in mutation.causes
    )
    remaining = tuple(
        mutation
        for mutation in patch.mutations
        if mutation.component_id not in removed_components
    )
    return remaining, tuple(sorted(removed_components)), tuple(sorted(impacted))


def _create_cleanup_child_plan(
    store: SessionStore,
    parent_id: str,
    client: PanoramaReadClient,
    selected: Iterable[Any],
    *,
    note: str,
    chosen_targets: Iterable[str],
    allow_empty: bool = False,
    excluded_targets: Iterable[str] = (),
    exclusion_impacted_targets: Iterable[str] = (),
    excluded_component_ids: Iterable[str] = (),
) -> str:
    # This is a local, read-only transformation.  The manifest envelope and
    # PatchSet checksum are enough here; full snapshot/entity verification is
    # deliberately deferred to the existing fail-closed Candidate preflight.
    parent_manifest = store.load_manifest(parent_id, verify=False)
    if parent_manifest["state"] != SessionState.PLANNED.value:
        raise InputError("Podzbiór można wydzielić tylko z planu PLANNED.")
    parent_patch = store.load_patchset(parent_id)
    if (
        parent_patch.panorama_host != client.profile.host
        or parent_patch.panorama_username != client.profile.username
    ):
        raise InputError("Plan nadrzędny należy do innego hosta lub operatora.")
    mutations = tuple(selected)
    chosen = tuple(dict.fromkeys(chosen_targets))
    excluded = tuple(dict.fromkeys(excluded_targets))
    exclusion_impacted = tuple(dict.fromkeys(exclusion_impacted_targets))
    excluded_components = tuple(dict.fromkeys(excluded_component_ids))
    exclusion_mode = bool(excluded or exclusion_impacted or excluded_components)
    if not mutations and not allow_empty:
        raise InputError("Wybrany podzbiór nie zawiera bezpiecznych mutacji.")
    selected_components = {mutation.component_id for mutation in mutations}
    complete = tuple(
        mutation
        for mutation in parent_patch.mutations
        if mutation.component_id in selected_components
    )
    if len(complete) != len(mutations):
        raise InputError(
            "Podzbiór narusza atomowy komponent zależności; wybierz cały komponent."
        )
    component_targets = tuple(
        sorted({cause for mutation in complete for cause in mutation.causes})
    )
    child_patch = PatchSet.new(
        kind=parent_patch.kind,
        panorama_host=parent_patch.panorama_host,
        panorama_username=parent_patch.panorama_username,
        mutations=complete,
        targets=component_targets,
        affected_device_groups=(
            parent_patch.affected_device_groups if complete else ()
        ),
        warnings=(*parent_patch.warnings, note),
    )
    child_id = store.create(
        child_patch,
        client.profile,
        diff_summary=parent_manifest.get("diff_summary") or {},
        inherit_from_session_id=parent_id,
        inherit_snapshot_labels=("plan_running", "plan_candidate"),
    )
    parent_inputs = parent_manifest.get("input_targets") or {}
    parent_inventory = parent_manifest.get("inventory") or {}
    parent_icmp = parent_manifest.get("icmp") or []
    selected_entity_keys = {mutation.entity_key for mutation in complete}
    parent_hit = parent_manifest.get("last_hit") or {}
    hit_records = list(parent_hit.get("records") or []) if exclusion_mode else [
        record
        for record in parent_hit.get("records") or []
        if "/".join(
            str((record.get("rule") or {}).get(key, ""))
            for key in ("location", "rulebase", "policy_type", "name")
        )
        in selected_entity_keys
    ]
    child_hit = {
        **parent_hit,
        "records": hit_records,
        "review_count": sum(
            str(record.get("status"))
            in {"RECENT", "ERROR", "INVALID", "NOT_LATEST", "NOT_FOUND"}
            for record in hit_records
        ),
        "recent_hit_count": sum(
            str(record.get("status")) == "RECENT" for record in hit_records
        ),
    }

    def enrich_child(manifest: dict[str, Any]) -> None:
        manifest["parent_session_id"] = parent_id
        manifest["allow_default_policy_override"] = bool(
            parent_manifest.get("allow_default_policy_override")
        )
        manifest["selected_targets"] = list(component_targets if exclusion_mode else chosen)
        manifest["excluded_targets"] = list(excluded)
        manifest["exclusion_impacted_targets"] = list(exclusion_impacted)
        manifest["excluded_component_ids"] = list(excluded_components)
        manifest["icmp"] = list(parent_icmp) if exclusion_mode else [
            item for item in parent_icmp if item.get("ip") in component_targets
        ]
        manifest["last_hit"] = child_hit
        if exclusion_mode:
            manifest["input_targets"] = dict(parent_inputs)
            manifest["inventory"] = dict(parent_inventory)
        else:
            manifest["input_targets"] = {
                "ips": [item for item in parent_inputs.get("ips", []) if item in component_targets],
                "address_objects": [
                    item
                    for item in parent_inputs.get("address_objects", [])
                    if f"object:{item}" in component_targets
                ],
                "address_groups": [
                    item
                    for item in parent_inputs.get("address_groups", [])
                    if f"group:{item}" in component_targets
                ],
                "policies": [
                    item
                    for item in parent_inputs.get("policies", [])
                    if f"policy:{item}" in component_targets
                ],
                "ordered": list(component_targets),
            }
            manifest["inventory"] = {
                item: parent_inventory[item]
                for item in component_targets
                if item in parent_inventory
            }

    store.update(child_id, enrich_child)
    excluded_mutations: tuple[Any, ...] = ()
    excluded_source_session_id: Optional[str] = None
    if excluded_components:
        # Repeated exclusions form a child-session chain.  Mutation and
        # component IDs stay stable, so the root plan is the authoritative
        # source for a cumulative, separately labelled manual command set.
        root_id = parent_id
        seen_parents: set[str] = set()
        while root_id not in seen_parents:
            seen_parents.add(root_id)
            root_manifest = store.load_manifest(root_id, verify=False)
            ancestor = root_manifest.get("parent_session_id")
            if not isinstance(ancestor, str) or not ancestor:
                break
            root_id = ancestor
        root_patch = store.load_patchset(root_id)
        excluded_component_set = set(excluded_components)
        excluded_mutations = tuple(
            mutation
            for mutation in root_patch.mutations
            if mutation.component_id in excluded_component_set
        )
        excluded_source_session_id = root_id
    write_handmode_artifacts(
        store,
        child_id,
        child_patch,
        excluded_mutations=excluded_mutations,
        excluded_source_session_id=excluded_source_session_id,
    )
    store.write_artifact(
        child_id,
        "raport_szczegolowy.txt",
        "\n".join(
            [
                f"Plan podzbioru: {child_id}",
                f"Plan nadrzędny: {parent_id}",
                "Cele wybrane w GUI: " + ", ".join(chosen),
                "Cele jawnie wykluczone: " + ", ".join(excluded),
                "Cele wykluczone przez atomowy komponent: "
                + ", ".join(exclusion_impacted),
                "Komponenty wybrane do wykluczenia: "
                + ", ".join(excluded_components),
                "Powiązane cele atomowych komponentów: " + ", ".join(component_targets),
                f"Komponenty: {len(selected_components)}",
                f"Mutacje: {len(complete)}",
            ]
        )
        + "\n",
        kind="detailed-report",
    )
    return child_id


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
        "artifacts": store.artifact_catalog(session_id, manifest=manifest),
    }


def _materialize_session_handmode(
    store: SessionStore, session_id: str
) -> tuple[str, ...]:
    """Append Hand Mode artifacts to a legacy session without changing old files."""

    manifest = store.load_manifest(session_id)
    patch = store.load_patchset(session_id)
    excluded_components = {
        str(item) for item in manifest.get("excluded_component_ids") or ()
    }
    excluded_mutations: tuple[Mutation, ...] = ()
    excluded_source_session_id: Optional[str] = None
    if excluded_components:
        root_id = session_id
        seen_parents: set[str] = set()
        while root_id not in seen_parents:
            seen_parents.add(root_id)
            root_manifest = store.load_manifest(root_id)
            ancestor = root_manifest.get("parent_session_id")
            if not isinstance(ancestor, str) or not ancestor:
                break
            root_id = ancestor
        root_patch = store.load_patchset(root_id)
        excluded_mutations = tuple(
            mutation
            for mutation in root_patch.mutations
            if mutation.component_id in excluded_components
        )
        excluded_source_session_id = root_id

    write_handmode_artifacts(
        store,
        session_id,
        patch,
        excluded_mutations=excluded_mutations,
        excluded_source_session_id=excluded_source_session_id,
    )

    warnings: list[str] = []
    if patch.kind == "restore":
        refreshed = store.load_manifest(session_id)
        artifact_by_kind = {
            str(record.get("kind")): str(record.get("file"))
            for record in refreshed.get("artifacts") or ()
            if record.get("kind") and record.get("file")
        }
        if "handmode-cli-conflict-restore-manual-review" not in artifact_by_kind:
            conflicts_file = artifact_by_kind.get("manual-conflicts")
            if conflicts_file:
                try:
                    conflicts_path = store.resolve_download(session_id, conflicts_file)
                    payload = json.loads(conflicts_path.read_text(encoding="utf-8"))
                    records = payload.get("mutations") or []
                    # manual_conflicts.json stores the reverse traversal used by
                    # the report.  The renderer accepts original cleanup order.
                    conflict_mutations = tuple(
                        Mutation.from_dict(item["mutation"])
                        for item in reversed(records)
                    )
                    if conflict_mutations:
                        write_restore_conflict_handmode_artifacts(
                            store,
                            session_id,
                            conflict_mutations,
                            source_session_ids=patch.source_session_ids
                            or ((patch.source_session_id,) if patch.source_session_id else ()),
                        )
                except (OSError, ValueError, KeyError, TypeError, ToolboxError) as exc:
                    warnings.append(
                        "Nie udało się odtworzyć konfliktowego zestawu CLI ze "
                        f"starszego raportu: {exc}. Bezpieczny Hand Mode jest dostępny."
                    )
            elif manifest.get("conflicts"):
                warnings.append(
                    "Starsza sesja Restore nie zawiera strukturalnego manual_conflicts.json; "
                    "wygenerowano wyłącznie bezpieczny subset Hand Mode."
                )
    return tuple(warnings)


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


def _profile_from_json(
    value: dict[str, Any], saved: Optional[PanoramaProfile] = None
) -> PanoramaProfile:
    host = str(value.get("host", saved.host if saved else "")).strip()
    username = str(value.get("username", saved.username if saved else "")).strip()
    if not host or not username:
        raise InputError("Połączenie wymaga host i username.")
    use_ssl = _json_bool(
        value,
        "ssl",
        fallback_key="useSsl",
        default=saved.use_ssl if saved else True,
    )
    verify_ssl = _json_bool(
        value,
        "verify_ssl",
        fallback_key="verifySsl",
        default=saved.verify_ssl if saved else False,
    )
    if not use_ssl and verify_ssl:
        raise InputError("verify_ssl nie może być włączone dla HTTP.")
    return PanoramaProfile(
        host=normalize_host(host, expected_scheme="https" if use_ssl else "http"),
        username=username,
        use_ssl=use_ssl,
        verify_ssl=verify_ssl,
        api_max_stage=ApiStage.parse(
            str(
                value.get(
                    "api_max_stage",
                    value.get(
                        "apiMaxStage",
                        saved.api_max_stage.value if saved else "read-only",
                    ),
                )
            )
        ),
    )


def _apply_profile_ceiling(
    requested: PanoramaProfile, ceiling: Optional[PanoramaProfile]
) -> tuple[PanoramaProfile, Optional[str]]:
    # The localhost GUI has one volatile READ ONLY / WRITE switch.  A profile
    # file may still provide defaults to the CLI, but it must not create a
    # second, contradictory permission selector in the GUI.  Real mutations
    # remain blocked by the per-request runtime gate in ``make_writer``.
    del ceiling
    return replace(requested, api_max_stage=ApiStage.PUSH), None


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


def _scope_guard_override(value: dict[str, Any]) -> tuple[bool, Optional[str]]:
    allowed = _json_bool(
        value,
        "allow_scope_guard_override",
        fallback_key="allowScopeGuardOverride",
        default=False,
    )
    raw_digest = value.get(
        "acknowledged_scope_guard_digest",
        value.get("acknowledgedScopeGuardDigest"),
    )
    if raw_digest is None:
        digest = None
    elif isinstance(raw_digest, str):
        digest = raw_digest.strip().lower() or None
    else:
        raise InputError("Fingerprint scope guard musi być tekstem SHA-256.")
    if digest is not None and (
        len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise InputError("Fingerprint scope guard musi zawierać dokładnie 64 znaki hex.")
    if allowed and digest is None:
        raise InputError(
            "Jawny override scope guard wymaga fingerprintu dokładnie pokazanej blokady."
        )
    if digest is not None and not allowed:
        raise InputError(
            "Fingerprint blokady podano bez jawnego allow_scope_guard_override=true."
        )
    return allowed, digest


def _contract() -> dict[str, Any]:
    return {
        "name": "PanOS Toolbox local API",
        "version": "v1",
        "basePath": "/api/v1",
        "writeStages": [stage.value for stage in ApiStage],
        "authentication": {
            "appTokenHeader": "X-Toolbox-App-Token",
            "appTokenPersistence": "memory-only server token and browser sessionStorage",
            "connectionTokenHeader": "X-Toolbox-Session",
            "persistence": "encrypted-profiles-and-memory-session-token",
            "profileStorage": "per-user LocalAppData/PanOS Toolbox/profiles.json",
        },
        "paths": {
            "POST /connections": "keygen and create memory-only connection",
            "DELETE /connections/current": "destroy current connection",
            "GET /profiles": "list saved profile metadata without secrets",
            "DELETE /profiles/{id}": "delete an encrypted saved profile",
            "GET|POST /lookup": "targeted exact lookup without full running config",
            "POST /ad-groups/generate": "validate local AD groups and build custom LDAP filters",
            "POST /cleanup/plans": "read snapshots, ICMP/last-hit, create PatchSet session",
            "POST /cleanup/analysis-jobs": "asynchronous cleanup plan with progress",
            "GET /cleanup/analysis-jobs/{id}": "poll analysis progress/result",
            "POST /cleanup/plans/{id}/components/{component}": "derive isolated component plan",
            "POST /cleanup/plans/{id}/selection": "derive plan for selected target rows",
            "POST /cleanup/plans/{id}/exclusions": "derive a safe plan without selected targets and their atomic components",
            "POST /policy-requests/plans": "parse ServiceNow-style request text and prepare targeted create operations",
            "POST /sessions/{id}/candidate-jobs": "path-by-path candidate write with progress",
            "POST /sessions/{id}/commit-review-jobs": "refresh full running/candidate diff and scope guard",
            "POST /sessions/{id}/commit-jobs": "background Panorama commit with phase timings",
            "POST /sessions/{id}/push-jobs": "background Panorama push with phase timings",
            "GET /execution-jobs/{id}": "poll candidate, commit or push progress",
            "POST /sessions/{id}/candidate": "candidate write with ephemeral gate",
            "POST /sessions/{id}/commit": "sequential partial/full commit job",
            "POST /sessions/{id}/push": "one sequential specific-DG commit-all job",
            "POST /restore/plans": "three-way restore by IP/session",
            "POST /audits": "read-only dependency audit",
            "GET /history": "offline searchable session, mutation and backup catalog",
            "GET /sessions": "offline integrity-checked session history",
            "GET /sessions/{id}": "offline integrity-checked manifest",
            "POST /sessions/{id}/handmode": "append paste-ready CLI artifacts to a legacy local session without Panorama",
            "POST /sessions/{id}/reconcile-external": "verify CLI/API post-state and admit restore history",
            "GET /sessions/{id}/artifacts/{path}": "inline preview or download of every registered session file",
            "GET /sessions/{id}/artifacts/bundle": "download complete session backup ZIP",
        },
    }


def create_app(
    *,
    static_dir: Optional[Path] = None,
    store: Optional[SessionStore] = None,
    profile_store: Optional[ProfileStore] = None,
    profile_ceiling: Optional[PanoramaProfile] = None,
    app_token: Optional[str] = None,
    test_client_auto_auth: bool = False,
):
    try:
        from flask import Flask, Response, jsonify, request, send_file, send_from_directory
        from flask.testing import FlaskClient
        from werkzeug.datastructures import Headers
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
    effective_app_token = app_token or secrets.token_urlsafe(32)
    app.config["TOOLBOX_APP_TOKEN"] = effective_app_token
    if test_client_auto_auth:
        class AuthenticatedToolboxTestClient(FlaskClient):
            def open(self, *args, **kwargs):  # noqa: ANN002, ANN003 - Flask test API
                headers = Headers(kwargs.get("headers"))
                if "X-Toolbox-App-Token" not in headers:
                    headers["X-Toolbox-App-Token"] = effective_app_token
                kwargs["headers"] = headers
                return super().open(*args, **kwargs)

        app.test_client_class = AuthenticatedToolboxTestClient
    session_store = store or SessionStore()
    profiles = profile_store or ProfileStore(
        session_store.root.parent if store is not None else None,
        enforce_acl=session_store.enforce_acl,
    )
    connections = ConnectionRegistry()
    analysis_jobs: dict[str, dict[str, Any]] = {}
    analysis_jobs_lock = threading.Lock()
    execution_jobs: dict[str, dict[str, Any]] = {}
    execution_jobs_lock = threading.Lock()

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
        if request.path.startswith("/api/"):
            supplied_app_token = request.headers.get("X-Toolbox-App-Token", "")
            if not secrets.compare_digest(supplied_app_token, effective_app_token):
                return jsonify(
                    {
                        "code": "AppAuthenticationRequired",
                        "message": (
                            "Brak poprawnego tokenu lokalnej aplikacji. Uruchom Toolbox "
                            "ponownie przez start_toolbox.cmd lub start_toolbox.ps1 i użyj otwartego linku sesji."
                        ),
                    }
                ), 401
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
            503
            if isinstance(error, DependencyError)
            else
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
        raw = value.get(key, value.get(fallback_key, []) if fallback_key else [])
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            raise InputError(f"Pole {key} musi być tablicą tekstów JSON.")
        return raw

    def reader() -> PanoramaReadClient:
        return connections.get(request.headers.get("X-Toolbox-Session"))

    def execution_stage(value: dict[str, Any]) -> ApiStage:
        raw = value.get("execution_stage", value.get("executionStage"))
        if not isinstance(raw, str):
            raise InputError(
                "Wykonanie przez GUI wymaga jawnego execution_stage: candidate, commit albo push."
            )
        stage = ApiStage.parse(raw)
        if stage is ApiStage.READ_ONLY:
            raise InputError("execution_stage read-only nie zezwala na zapis.")
        return stage

    def plan_from_value(
        value: dict[str, Any],
        client: PanoramaReadClient,
        *,
        progress_callback=None,
    ) -> dict[str, Any]:
        return plan_cleanup_session(
            session_store,
            client,
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
            allow_default_policy_override=_json_bool(
                value,
                "allow_default_policy_override",
                default=_json_bool(value, "allowDefaultPolicyOverride", default=False),
            ),
            progress_callback=progress_callback,
        )

    def wire_analysis_job(job: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": job["id"],
            "state": job["state"],
            "progress": job["progress"],
            "message": job["message"],
            "plan": job.get("plan"),
            "error": job.get("error"),
        }

    def wire_execution_job(job: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": job["id"],
            "sessionId": job["session_id"],
            "kind": job["kind"],
            "state": job["state"],
            "progress": job["progress"],
            "message": job["message"],
            "current": job.get("current"),
            "items": list(job.get("items") or ()),
            "session": job.get("session"),
            "error": job.get("error"),
            "startedAt": job.get("started_at"),
            "finishedAt": job.get("finished_at"),
        }

    def utc_timestamp() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def start_execution_job(
        *,
        session_id: str,
        owner: Optional[str],
        kind: str,
        initial_message: str,
        runner,
    ) -> dict[str, Any]:
        """Run a write stage outside the HTTP request and retain live evidence."""

        with execution_jobs_lock:
            active = next(
                (
                    item
                    for item in execution_jobs.values()
                    if item["session_id"] == session_id
                    and item["state"] in {"queued", "running"}
                ),
                None,
            )
            if active is not None:
                raise ConflictError(
                    f"Sesja ma już aktywną operację {active['kind']}: {active['id']}."
                )
            job_id = f"{kind}-{secrets.token_hex(8)}"
            job = {
                "id": job_id,
                "owner": owner,
                "session_id": session_id,
                "kind": kind,
                "state": "queued",
                "progress": 0,
                "message": initial_message,
                "items": [],
                "started_at": utc_timestamp(),
            }
            execution_jobs[job_id] = job

        sequence = 0

        def update(
            progress: int, message: str, detail: Optional[dict[str, Any]]
        ) -> None:
            nonlocal sequence
            sequence += 1
            value = max(0, min(100, int(progress)))
            event = {
                **dict(detail or {}),
                "message": message,
                "progress": value,
                "sequence": sequence,
                "timestamp": utc_timestamp(),
            }
            with execution_jobs_lock:
                current = execution_jobs[job_id]
                current.update(
                    state="running",
                    progress=max(int(current.get("progress", 0)), value),
                    message=message,
                    current=event,
                )
                items = current.setdefault("items", [])
                if (
                    event.get("event") == "panorama-job-poll"
                    and items
                    and items[-1].get("event") == "panorama-job-poll"
                ):
                    # Keep one live polling row and update its elapsed time /
                    # poll count.  Hundreds of identical ACT/PEND rows would
                    # hide the useful phase transitions without adding signal.
                    items[-1] = event
                else:
                    items.append(event)
                # A large path-by-path batch must not grow process memory
                # without limit, while the durable session journal remains
                # the complete source of truth.
                if len(items) > 400:
                    del items[:-400]

        def session_payload() -> Optional[dict[str, Any]]:
            try:
                return _wire_session(session_store, session_id)
            except Exception:
                return None

        def worker() -> None:
            try:
                outcome = runner(update) or {}
                finished_session = outcome.get("session") or session_payload()
                with execution_jobs_lock:
                    execution_jobs[job_id].update(
                        state="success",
                        progress=100,
                        message=str(outcome.get("message") or f"Etap {kind} zakończony poprawnie"),
                        session=finished_session,
                        finished_at=utc_timestamp(),
                    )
            except ToolboxError as exc:
                failed_session = session_payload()
                with execution_jobs_lock:
                    execution_jobs[job_id].update(
                        state="failed",
                        message=f"Etap {kind} został zatrzymany",
                        error={"code": type(exc).__name__, "message": str(exc)},
                        session=failed_session,
                        finished_at=utc_timestamp(),
                    )
            except Exception:
                correlation_id = secrets.token_hex(8)
                app.logger.exception(
                    "Unhandled %s job error correlation=%s", kind, correlation_id
                )
                failed_session = session_payload()
                with execution_jobs_lock:
                    execution_jobs[job_id].update(
                        state="failed",
                        message=f"Nieoczekiwany błąd etapu {kind}",
                        error={
                            "code": "InternalError",
                            "message": f"Nieoczekiwany błąd backendu podczas etapu {kind}.",
                            "correlation_id": correlation_id,
                        },
                        session=failed_session,
                        finished_at=utc_timestamp(),
                    )

        threading.Thread(
            target=worker,
            name=f"panos-toolbox-{job_id}",
            daemon=True,
        ).start()
        return job

    @app.get("/api/health")
    @app.get("/api/v1/health")
    def health():
        return jsonify(
            {"ok": True, "status": "ok", "version": "0.8.2", "bind": "127.0.0.1", "api": "v1"}
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
                verify_ssl = _json_bool(value, "verify_ssl", default=False)
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

    @app.post("/api/v1/ad-groups/generate")
    def ad_groups_generate():
        value = body()
        raw_groups = value.get("groups")
        if not isinstance(raw_groups, list) or any(not isinstance(item, str) for item in raw_groups):
            raise InputError("Pole groups musi być tablicą nazw grup AD.")
        return jsonify(
            generate_ad_group_definition(
                raw_groups,
                output_name=value.get("output_name", value.get("outputName", "")),
                mapping_name=value.get("mapping_name", value.get("mappingName", "LDAP_GM1")),
                vsys=value.get("vsys", "vsys1"),
                template_name=value.get("template_name", value.get("templateName", "")),
            )
        )

    @app.get("/api/v1/profiles")
    def profiles_list():
        return jsonify({"profiles": profiles.list(), "storage": str(profiles.root)})

    @app.delete("/api/v1/profiles/<profile_id>")
    def profiles_delete(profile_id: str):
        profiles.delete(profile_id)
        return ("", 204)

    @app.post("/api/v1/connections")
    def connect():
        value = body()
        saved_profile_id = value.get("profile_id", value.get("profileId"))
        if saved_profile_id is not None and not isinstance(saved_profile_id, str):
            raise InputError("profile_id musi być tekstem.")
        saved_profile = None
        saved_password = None
        if saved_profile_id:
            saved_profile, saved_password = profiles.get(saved_profile_id)
        profile, capability_warning = _apply_profile_ceiling(
            _profile_from_json(value, saved_profile), profile_ceiling
        )
        password = value.get("password")
        if not isinstance(password, str) or not password:
            password = saved_password
        if not isinstance(password, str) or not password:
            raise InputError(
                "Połączenie wymaga hasła albo wybranego zapisanego profilu."
            )
        remember_profile = _json_bool(
            value,
            "save_profile",
            fallback_key="rememberProfile",
            default=False,
        )
        profile_name = value.get("profile_name", value.get("profileName", ""))
        if profile_name is not None and not isinstance(profile_name, str):
            raise InputError("profile_name musi być tekstem.")
        client = PanoramaReadClient(profile)
        try:
            client.authenticate(password)
            system_info = client.system_info()
            panorama_version = (
                system_info.findtext(".//sw-version")
                or system_info.findtext(".//version")
                or "nieznana"
            ).strip()
            try:
                summary = client.change_summary()
                result_node = summary.find(".//result")
                candidate_dirty = bool(
                    result_node is not None
                    and (
                        list(result_node)
                        or (result_node.text and result_node.text.strip())
                    )
                )
                candidate_status = "dirty" if candidate_dirty else "clean"
            except ToolboxError:
                candidate_dirty = False
                candidate_status = "unknown"
            saved_record = None
            if remember_profile:
                saved_record = profiles.save(
                    profile=profile,
                    password=password,
                    name=profile_name or "",
                    profile_id=saved_profile_id or None,
                )
            password = ""
            token = connections.add(client)
        except Exception:
            password = ""
            client.close()
            raise
        return jsonify(
            {
                "id": "connection-" + secrets.token_hex(6),
                "session_token": token,
                "connectionToken": token,
                "host": profile.host,
                "username": profile.username,
                "panorama_version": panorama_version,
                "api_max_stage": profile.api_max_stage.value,
                "connected_at": __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ).isoformat(timespec="seconds"),
                "candidate_dirty": candidate_dirty,
                "candidate_status": candidate_status,
                "capability_warning": capability_warning,
                "profile": {
                    "host": profile.host,
                    "username": profile.username,
                    "ssl": profile.use_ssl,
                    "verifySsl": profile.verify_ssl,
                    "apiMaxStage": profile.api_max_stage.value,
                },
                "systemMode": system_info.findtext(".//system-mode") or "unknown",
                "profile_id": saved_record["id"] if saved_record else saved_profile_id,
                "profile_saved": bool(saved_record),
            }
        )

    @app.get("/api/v1/lookup")
    @app.post("/api/v1/lookup")
    def lookup_endpoint():
        if request.method == "POST":
            value = body()
            kind = value.get("type")
            names = value.get("names")
            device_group = value.get("device_group", value.get("deviceGroup"))
            recent_days = integer_field(
                value,
                "recent_days",
                fallback_key="recentDays",
                default=14,
                minimum=1,
                maximum=3650,
            )
        else:
            kind = request.args.get("type")
            names = [request.args.get("name", "")]
            device_group = request.args.get("dg")
            try:
                recent_days = int(request.args.get("recent_days", "14"))
            except ValueError as exc:
                raise InputError("recent_days musi być liczbą całkowitą.") from exc
        if not isinstance(kind, str):
            raise InputError("Lookup wymaga pola type.")
        if not isinstance(names, list) or any(not isinstance(item, str) for item in names):
            raise InputError("Lookup wymaga tablicy names.")
        if device_group is not None and not isinstance(device_group, str):
            raise InputError("device_group musi być tekstem.")
        return jsonify(
            lookup_exact(
                reader(),
                kind,
                names,
                device_group=device_group or None,
                recent_days=recent_days,
            )
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
        result = plan_from_value(value, reader())
        return jsonify(
            _wire_cleanup_plan(session_store, result["session_id"], verify=False)
        ), 201

    @app.post("/api/v1/policy-requests/plans")
    def policy_request_plan():
        value = body()
        raw = value.get("text", value.get("request", value.get("payload")))
        if not isinstance(raw, str) or not raw.strip():
            raise InputError("Pole text z wklejką zlecenia nie może być puste.")
        client = reader()
        result = build_policy_creation_plan(client, raw)
        session_id = session_store.create(result.patchset, client.profile)

        def enrich(manifest: dict[str, Any]) -> None:
            manifest["input_targets"] = {
                **dict(result.input_targets),
                "ordered": list(result.patchset.targets),
            }
            manifest["inventory"] = dict(result.inventory)
            manifest["icmp"] = []
            manifest["last_hit"] = {
                "records": [],
                "recent_hit_count": 0,
                "review_count": 0,
            }
            manifest["request_kind"] = "policy-create"

        session_store.update(session_id, enrich)
        write_handmode_artifacts(session_store, session_id, result.patchset)
        session_store.write_artifact(
            session_id,
            "raport_szczegolowy.txt",
            "\n".join(
                [
                    f"Plan tworzenia polityk: {session_id}",
                    "Źródło: wklejka ServiceNow / Passes ToDo",
                    f"Przepływy: {len(result.input_targets.get('flows') or [])}",
                    f"Mutacje: {len(result.patchset.mutations)}",
                    *result.warnings,
                ]
            )
            + "\n",
            kind="detailed-report",
        )
        return jsonify(_wire_cleanup_plan(session_store, session_id, verify=False)), 201

    @app.post("/api/v1/cleanup/analysis-jobs")
    def cleanup_analysis_job_start():
        value = body()
        token = request.headers.get("X-Toolbox-Session")
        client = connections.get(token)
        job_id = "analysis-" + secrets.token_hex(8)
        job = {
            "id": job_id,
            "owner": token,
            "state": "queued",
            "progress": 0,
            "message": "Oczekiwanie na analizę",
        }
        with analysis_jobs_lock:
            analysis_jobs[job_id] = job

        def update(progress: int, message: str) -> None:
            with analysis_jobs_lock:
                current = analysis_jobs[job_id]
                current.update(
                    state="running",
                    progress=max(0, min(100, int(progress))),
                    message=message,
                )

        def worker() -> None:
            try:
                result = plan_from_value(value, client, progress_callback=update)
                plan = _wire_cleanup_plan(
                    session_store, result["session_id"], verify=False
                )
                with analysis_jobs_lock:
                    analysis_jobs[job_id].update(
                        state="success",
                        progress=100,
                        message="Plan jest gotowy",
                        plan=plan,
                    )
            except ToolboxError as exc:
                with analysis_jobs_lock:
                    analysis_jobs[job_id].update(
                        state="failed",
                        message="Analiza nie powiodła się",
                        error={"code": type(exc).__name__, "message": str(exc)},
                    )
            except Exception:
                correlation_id = secrets.token_hex(8)
                app.logger.exception(
                    "Unhandled analysis error correlation=%s", correlation_id
                )
                with analysis_jobs_lock:
                    analysis_jobs[job_id].update(
                        state="failed",
                        message="Nieoczekiwany błąd analizy",
                        error={
                            "code": "InternalError",
                            "message": "Nieoczekiwany błąd backendu podczas analizy.",
                            "correlation_id": correlation_id,
                        },
                    )

        threading.Thread(
            target=worker,
            name=f"panos-toolbox-{job_id}",
            daemon=True,
        ).start()
        return jsonify(wire_analysis_job(job)), 202

    @app.get("/api/v1/cleanup/analysis-jobs/<job_id>")
    def cleanup_analysis_job_get(job_id: str):
        token = request.headers.get("X-Toolbox-Session")
        connections.get(token)
        with analysis_jobs_lock:
            job = analysis_jobs.get(job_id)
            if job is None or job["owner"] != token:
                raise InputError("Nieznany job analizy dla tej sesji połączenia.")
            payload = wire_analysis_job(dict(job))
        return jsonify(payload)

    @app.get("/api/v1/cleanup/plans/<plan_id>")
    def cleanup_plan_get(plan_id: str):
        reader()
        return jsonify(_wire_cleanup_plan(session_store, plan_id))

    @app.post("/api/v1/cleanup/plans/<plan_id>/components/<component_id>")
    def cleanup_component_plan(plan_id: str, component_id: str):
        value = body()
        client = reader()
        target = value.get("target")
        if not isinstance(target, str) or not target.strip():
            raise InputError("Osobny plan wymaga dokładnego pola target.")
        target = target.strip()
        parent_patch = session_store.load_patchset(plan_id)
        selected = tuple(
            mutation
            for mutation in parent_patch.mutations
            if mutation.component_id == component_id
        )
        if not selected or not any(target in mutation.causes for mutation in selected):
            raise InputError("Cel nie należy do wskazanego komponentu planu.")
        child_id = _create_cleanup_child_plan(
            session_store,
            plan_id,
            client,
            selected,
            note=f"Osobny plan wydzielony z {plan_id}; komponent {component_id}.",
            chosen_targets=(target,),
        )
        return jsonify(_wire_cleanup_plan(session_store, child_id, verify=False)), 201

    @app.post("/api/v1/cleanup/plans/<plan_id>/selection")
    def cleanup_selection_plan(plan_id: str):
        value = body()
        client = reader()
        targets = string_list_field(value, "targets")
        targets = list(dict.fromkeys(item.strip() for item in targets if item.strip()))
        if not targets:
            raise InputError("Zaznacz co najmniej jeden cel planu.")
        parent_manifest = session_store.load_manifest(plan_id, verify=False)
        known_targets = set(
            (parent_manifest.get("input_targets") or {}).get("ordered") or ()
        )
        unknown = sorted(set(targets) - known_targets)
        if unknown:
            raise InputError("Cele nie należą do planu: " + ", ".join(unknown[:10]))
        parent_patch = session_store.load_patchset(plan_id)
        selected_components = {
            mutation.component_id
            for mutation in parent_patch.mutations
            if set(mutation.causes).intersection(targets)
        }
        selected = tuple(
            mutation
            for mutation in parent_patch.mutations
            if mutation.component_id in selected_components
        )
        child_id = _create_cleanup_child_plan(
            session_store,
            plan_id,
            client,
            selected,
            note=(
                f"Plan zaznaczonego podzbioru z {plan_id}; wybrano "
                f"{len(targets)} celów i {len(selected_components)} atomowych komponentów."
            ),
            chosen_targets=targets,
        )
        return jsonify(_wire_cleanup_plan(session_store, child_id, verify=False)), 201

    @app.post("/api/v1/cleanup/plans/<plan_id>/exclusions")
    def cleanup_exclusion_plan(plan_id: str):
        value = body()
        client = reader()
        requested = string_list_field(value, "targets")
        requested = list(
            dict.fromkeys(item.strip() for item in requested if item.strip())
        )
        requested_components = string_list_field(value, "component_ids")
        requested_components = list(
            dict.fromkeys(
                item.strip() for item in requested_components if item.strip()
            )
        )
        if not requested and not requested_components:
            raise InputError(
                "Zaznacz co najmniej jeden cel albo komponent do wykluczenia."
            )

        parent_manifest = session_store.load_manifest(plan_id, verify=False)
        if parent_manifest["state"] != SessionState.PLANNED.value:
            raise InputError("Cele można wykluczać tylko z planu PLANNED.")
        known_targets = set(
            (parent_manifest.get("input_targets") or {}).get("ordered") or ()
        )
        unknown = sorted(set(requested) - known_targets)
        if unknown:
            raise InputError(
                "Cele nie należą do planu: " + ", ".join(unknown[:10])
            )

        parent_patch = session_store.load_patchset(plan_id)
        known_components = {
            mutation.component_id for mutation in parent_patch.mutations
        }
        unknown_components = sorted(
            set(requested_components) - known_components
        )
        if unknown_components:
            raise InputError(
                "Komponenty nie należą do aktywnego planu: "
                + ", ".join(unknown_components[:10])
            )
        processable = {
            cause for mutation in parent_patch.mutations for cause in mutation.causes
        }
        inactive = sorted(set(requested) - processable)
        if inactive:
            raise InputError(
                "Cel nie ma aktywnych operacji do wykluczenia: "
                + ", ".join(inactive[:10])
            )

        remaining, removed_components, newly_impacted = _cleanup_exclusion_closure(
            parent_patch,
            requested,
            component_ids=requested_components,
        )
        existing_excluded = {
            str(item) for item in parent_manifest.get("excluded_targets") or ()
        }
        existing_impacted = {
            str(item)
            for item in parent_manifest.get("exclusion_impacted_targets") or ()
        }
        existing_components = {
            str(item)
            for item in parent_manifest.get("excluded_component_ids") or ()
        }
        excluded = tuple(sorted(existing_excluded.union(requested)))
        impacted = tuple(
            sorted(existing_impacted.union(newly_impacted).intersection(known_targets))
        )
        excluded_components = tuple(
            sorted(existing_components.union(removed_components))
        )
        remaining_targets = tuple(
            sorted({cause for mutation in remaining for cause in mutation.causes})
        )
        note = (
            f"Wykluczenie operatora: {len(requested)} celów i "
            f"{len(requested_components)} komponentów; usunięto z wykonania "
            f"{len(removed_components)} atomowych komponentów; "
            f"{len(impacted)} celów jest poza planem wykonawczym."
        )
        child_id = _create_cleanup_child_plan(
            session_store,
            plan_id,
            client,
            remaining,
            note=note,
            chosen_targets=remaining_targets,
            allow_empty=True,
            excluded_targets=excluded,
            exclusion_impacted_targets=impacted,
            excluded_component_ids=excluded_components,
        )
        return jsonify(_wire_cleanup_plan(session_store, child_id, verify=False)), 201

    @app.get("/api/v1/sessions")
    def sessions_list():
        return jsonify(
            [
                _wire_session(session_store, item["session_id"])
                for item in session_store.list_sessions()
            ]
        )

    @app.get("/api/v1/sessions/<session_id>")
    def session_get(session_id: str):
        return jsonify(_wire_session(session_store, session_id))

    @app.post("/api/v1/sessions/<session_id>/handmode")
    def session_handmode(session_id: str):
        # Purely local, append-only migration.  It never reads Panorama and
        # preserves a legacy commands.txt under its original hash/name.
        warnings = _materialize_session_handmode(session_store, session_id)
        return jsonify(
            {
                "session": _wire_session(session_store, session_id),
                "warnings": list(warnings),
                "message": (
                    "Hand Mode wygenerowany lokalnie z zapisanego PatchSetu; "
                    "nie pobrano configu i nie wykonano operacji w Panoramie."
                ),
            }
        )

    @app.get("/api/v1/history")
    def history_get():
        # History belongs to the local Windows user and remains available
        # without a Panorama connection token.  The server is loopback-only;
        # write/reconciliation endpoints continue to require live auth.
        return jsonify(session_store.history_catalog())

    @app.post("/api/v1/sessions/<session_id>/reconcile-external")
    def session_reconcile_external(session_id: str):
        value = body()
        source = value.get("source", "CLI")
        if not isinstance(source, str):
            raise InputError("Pole source musi być tekstem CLI albo API.")
        state = reconcile_external_execution(
            session_store,
            session_id,
            reader(),
            source=source.strip().upper(),
        )
        return jsonify(
            {
                "session": _wire_session(session_store, session_id),
                "message": (
                    "Live Panorama potwierdziła wykonanie zewnętrzne; "
                    f"sesja ma stan {state.value} i jest dostępna dla Restore."
                ),
            }
        )

    @app.get("/api/v1/sessions/<session_id>/artifacts/<path:filename>")
    def artifact_get(session_id: str, filename: str):
        manifest = session_store.load_manifest(session_id, verify=False)
        inline = request.args.get("disposition", "attachment").casefold() == "inline"
        if filename == "bundle":
            payload = session_store.bundle_bytes(session_id)
            return Response(
                payload,
                content_type="application/zip",
                headers={
                    "Content-Disposition": (
                        f'attachment; filename="PanOS-Toolbox-{session_id}.zip"'
                    )
                },
            )
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
                    headers={
                        "Content-Disposition": (
                            'inline; filename="conflicts.json"'
                            if inline
                            else 'attachment; filename="conflicts.json"'
                        )
                    },
                )
            else:
                raise
        return send_file(
            path,
            as_attachment=not inline,
            download_name=Path(path).name,
            max_age=0,
        )

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
            operator_authorized_stage=execution_stage(value),
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

    @app.post("/api/v1/sessions/<session_id>/candidate-jobs")
    def session_candidate_job_start(session_id: str):
        value = body()
        token = request.headers.get("X-Toolbox-Session")
        client = connections.get(token)
        writer = make_writer(
            client,
            ApiStage.CANDIDATE,
            enable_api_write=_json_bool(
                value, "enable_api_write", fallback_key="enableApiWrite", default=False
            ),
            operator_authorized_stage=execution_stage(value),
        )
        # Validate the target before detaching work from the request context.
        session_store.load_manifest(session_id)
        save_server_snapshot = _json_bool(
            value,
            "save_server_snapshot",
            fallback_key="saveServerSnapshot",
            default=True,
        )

        def run_candidate(update):
            result = apply_candidate(
                session_store,
                session_id,
                client,
                writer,
                save_server_snapshot=save_server_snapshot,
                acquire_locks=True,
                progress_callback=update,
            )
            return {
                "message": f"Candidate zakończony stanem {result.state.value}",
                "session": _wire_session(session_store, session_id),
            }

        job = start_execution_job(
            session_id=session_id,
            owner=token,
            kind="candidate",
            initial_message="Oczekiwanie na bezpieczny zapis candidate",
            runner=run_candidate,
        )
        return jsonify(wire_execution_job(job)), 202

    @app.get("/api/v1/execution-jobs/<job_id>")
    def session_execution_job_get(job_id: str):
        token = request.headers.get("X-Toolbox-Session")
        connections.get(token)
        with execution_jobs_lock:
            job = execution_jobs.get(job_id)
            if job is None or job["owner"] != token:
                raise InputError("Nieznany job wykonania dla tej sesji połączenia.")
            snapshot = dict(job)
        # Polling progress must stay lightweight.  Wiring a live session here
        # re-hashed full XML snapshots and every large diff artifact every
        # 350 ms.  The worker attaches one verified session payload at the
        # terminal update, which is the only point the UI consumes it.
        payload = wire_execution_job(snapshot)
        return jsonify(payload)

    @app.post("/api/v1/sessions/<session_id>/commit-review-jobs")
    def session_commit_review_job_start(session_id: str):
        token = request.headers.get("X-Toolbox-Session")
        client = connections.get(token)
        session_store.load_manifest(session_id)

        def run_review(update):
            review = prepare_commit_review(
                session_store,
                session_id,
                client,
                progress_callback=update,
            )
            return {
                "message": (
                    "Pełny diff i scope guard są gotowe"
                    if review.get("commitReady")
                    else "Pełny diff gotowy; scope guard blokuje commit"
                ),
                "session": _wire_session(session_store, session_id),
            }

        job = start_execution_job(
            session_id=session_id,
            owner=token,
            kind="review",
            initial_message="Oczekiwanie na pełny diff running → candidate",
            runner=run_review,
        )
        return jsonify(wire_execution_job(job)), 202

    @app.post("/api/v1/sessions/<session_id>/commit-jobs")
    def session_commit_job_start(session_id: str):
        value = body()
        token = request.headers.get("X-Toolbox-Session")
        client = connections.get(token)
        writer = make_writer(
            client,
            ApiStage.COMMIT,
            enable_api_write=_json_bool(
                value, "enable_api_write", fallback_key="enableApiWrite", default=False
            ),
            operator_authorized_stage=execution_stage(value),
        )
        session_store.load_manifest(session_id)
        partial = not _json_bool(value, "full", default=False)
        allow_unisolated = _json_bool(
            value,
            "allow_unisolated_commit",
            fallback_key="allowUnisolatedCommit",
            default=False,
        )
        allow_full = _json_bool(
            value,
            "allow_full_commit",
            fallback_key="allowFullCommit",
            default=False,
        )
        allow_scope_override, acknowledged_scope_digest = _scope_guard_override(value)

        def run_commit(update):
            result = commit_session(
                session_store,
                session_id,
                client,
                writer,
                partial=partial,
                allow_unisolated_commit=allow_unisolated,
                allow_full_commit=allow_full,
                allow_scope_guard_override=allow_scope_override,
                acknowledged_scope_guard_digest=acknowledged_scope_digest,
                progress_callback=update,
            )
            elapsed = result.get("total_duration_seconds")
            suffix = f" w {elapsed:.1f} s" if isinstance(elapsed, (int, float)) else ""
            return {
                "message": f"Commit zakończony poprawnie{suffix}",
                "session": _wire_session(
                    session_store, session_id, verify=False
                ),
            }

        job = start_execution_job(
            session_id=session_id,
            owner=token,
            kind="commit",
            initial_message="Oczekiwanie na uruchomienie commit",
            runner=run_commit,
        )
        return jsonify(wire_execution_job(job)), 202

    @app.post("/api/v1/sessions/<session_id>/push-jobs")
    def session_push_job_start(session_id: str):
        value = body()
        token = request.headers.get("X-Toolbox-Session")
        client = connections.get(token)
        writer = make_writer(
            client,
            ApiStage.PUSH,
            enable_api_write=_json_bool(
                value, "enable_api_write", fallback_key="enableApiWrite", default=False
            ),
            operator_authorized_stage=execution_stage(value),
        )
        session_store.load_manifest(session_id)
        device_groups = string_list_field(
            value, "device_groups", fallback_key="deviceGroups"
        )

        def run_push(update):
            result = push_session(
                session_store,
                session_id,
                client,
                writer,
                device_groups=device_groups,
                progress_callback=update,
            )
            elapsed = result.get("total_duration_seconds")
            suffix = f" w {elapsed:.1f} s" if isinstance(elapsed, (int, float)) else ""
            return {
                "message": f"Push zakończony poprawnie{suffix}",
                "session": _wire_session(
                    session_store, session_id, verify=False
                ),
            }

        job = start_execution_job(
            session_id=session_id,
            owner=token,
            kind="push",
            initial_message="Oczekiwanie na uruchomienie push",
            runner=run_push,
        )
        return jsonify(wire_execution_job(job)), 202

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
            operator_authorized_stage=execution_stage(value),
        )
        allow_scope_override, acknowledged_scope_digest = _scope_guard_override(value)
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
                allow_scope_guard_override=allow_scope_override,
                acknowledged_scope_guard_digest=acknowledged_scope_digest,
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
            operator_authorized_stage=execution_stage(value),
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
                target=value.get("target"),
                targets=string_list_field(value, "targets"),
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
            operator_authorized_stage=execution_stage(value),
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
    app_token = secrets.token_urlsafe(32)
    app = create_app(
        static_dir=static_dir,
        store=SessionStore(session_dir),
        profile_ceiling=profile_ceiling,
        app_token=app_token,
    )
    server = make_server("127.0.0.1", port, app, threaded=True)
    actual_port = server.server_port
    launch_url = (
        f"http://127.0.0.1:{actual_port}/"
        f"#toolbox-token={app_token}"
    )
    print(f"PanOS Toolbox - bezpieczny link tej sesji: {launch_url}", flush=True)

    def open_browser() -> None:
        try:
            if not webbrowser.open_new_tab(launch_url):
                print(
                    "Nie udało się automatycznie otworzyć przeglądarki; użyj linku powyżej.",
                    flush=True,
                )
        except (OSError, webbrowser.Error):
            print(
                "Nie udało się automatycznie otworzyć przeglądarki; użyj linku powyżej.",
                flush=True,
            )

    browser_timer = threading.Timer(0.25, open_browser)
    browser_timer.daemon = True
    browser_timer.start()
    server.serve_forever()
