"""Detailed pre-commit evidence and fail-closed cleanup scope guard.

The commit review is deliberately generated after candidate apply.  It shows
the complete running -> candidate delta while the scope guard independently
proves that cleanup did not leave a reference to a deleted address/group and
that candidate contains no configuration change outside the admitted PatchSet.
"""

from __future__ import annotations

import copy
import difflib
import ipaddress
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence

from .cleaner_adapter import _legacy_root
from .diffing import summarize_native_change_summary
from .models import Mutation, PatchSet
from .restore import apply_operation_to_tree
from .xmlutil import (
    VOLATILE_ATTRIBUTES,
    fingerprint_element,
    raw_sha256,
    xpath_literal,
)


_MAX_PATH_DIFFERENCES = 500


@dataclass(frozen=True)
class CommitReviewDocuments:
    """Compact UI data plus immutable full-text evidence."""

    compact: dict[str, Any]
    payload: dict[str, Any]
    review_text: str
    config_diff_text: str
    scope_guard_text: str


def _paths_overlap(left: str, right: str) -> bool:
    left_value = left.rstrip("/")
    right_value = right.rstrip("/")
    return (
        left_value == right_value
        or left_value.startswith(right_value + "/")
        or right_value.startswith(left_value + "/")
    )


def _pretty_xml(element: Optional[ET.Element]) -> str:
    if element is None:
        return ""
    cloned = copy.deepcopy(element)
    try:
        ET.indent(cloned, space="  ")
    except AttributeError:  # pragma: no cover - supported Python is >= 3.9
        pass
    return ET.tostring(cloned, encoding="unicode", short_empty_elements=True)


def _unified_xml_diff(
    before: Optional[ET.Element],
    after: Optional[ET.Element],
    *,
    before_label: str,
    after_label: str,
) -> str:
    before_lines = _pretty_xml(before).splitlines()
    after_lines = _pretty_xml(after).splitlines()
    return "\n".join(
        difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile=before_label,
            tofile=after_label,
            lineterm="",
            n=3,
        )
    )


def _entity_inventory(config: ET.Element) -> dict[str, dict[str, Any]]:
    """Return supported Panorama entities with exact GUI/API identity."""

    result: dict[str, dict[str, Any]] = {}

    def collect(
        scope_node: ET.Element,
        *,
        key_prefix: str,
        xpath_prefix: str,
        scope: str,
    ) -> None:
        for container, entity_type in (
            ("address", "address"),
            ("address-group", "address-group"),
        ):
            for entry in scope_node.findall(f"./{container}/entry"):
                name = entry.get("name")
                if not name:
                    continue
                key = f"{key_prefix}/{container}/{name}"
                result[key] = {
                    "key": key,
                    "entityType": entity_type,
                    "scope": scope,
                    "name": name,
                    "rulebase": None,
                    "policyType": None,
                    "xpath": (
                        f"{xpath_prefix}/{container}/entry"
                        f"[@name={xpath_literal(name)}]"
                    ),
                    "element": entry,
                    "fingerprint": fingerprint_element(entry),
                }
        for rulebase in ("pre-rulebase", "post-rulebase"):
            for policy_type in ("security", "nat", "application-override"):
                for entry in scope_node.findall(
                    f"./{rulebase}/{policy_type}/rules/entry"
                ):
                    name = entry.get("name")
                    if not name:
                        continue
                    key = f"{key_prefix}/{rulebase}/{policy_type}/rules/{name}"
                    result[key] = {
                        "key": key,
                        "entityType": "policy",
                        "scope": scope,
                        "name": name,
                        "rulebase": rulebase,
                        "policyType": policy_type,
                        "xpath": (
                            f"{xpath_prefix}/{rulebase}/{policy_type}/rules/entry"
                            f"[@name={xpath_literal(name)}]"
                        ),
                        "element": entry,
                        "fingerprint": fingerprint_element(entry),
                    }

    shared = config.find("./shared")
    if shared is not None:
        collect(
            shared,
            key_prefix="shared",
            xpath_prefix="/config/shared",
            scope="shared",
        )
    for device in config.findall("./devices/entry"):
        device_name = device.get("name") or "localhost.localdomain"
        for group in device.findall("./device-group/entry"):
            group_name = group.get("name")
            if not group_name:
                continue
            collect(
                group,
                key_prefix=f"devices/{device_name}/device-group/{group_name}",
                xpath_prefix=(
                    f"/config/devices/entry[@name={xpath_literal(device_name)}]"
                    f"/device-group/entry[@name={xpath_literal(group_name)}]"
                ),
                scope=group_name,
            )
    return result


def _mutation_details(
    entity_xpath: str, mutations: Sequence[Mutation]
) -> tuple[list[Mutation], list[dict[str, Any]]]:
    related = [
        mutation
        for mutation in mutations
        if _paths_overlap(entity_xpath, mutation.target_xpath)
    ]
    operations = [
        {
            "mutationId": mutation.mutation_id,
            "action": operation.action.value,
            "xpath": operation.xpath,
            "where": operation.where,
            "destination": operation.destination,
        }
        for mutation in related
        for operation in mutation.forward
    ]
    return related, operations


def _change_entries(
    running: ET.Element,
    candidate: ET.Element,
    mutations: Sequence[Mutation],
) -> list[dict[str, Any]]:
    running_entities = _entity_inventory(running)
    candidate_entities = _entity_inventory(candidate)
    entries: list[dict[str, Any]] = []
    for key in sorted(set(running_entities) | set(candidate_entities)):
        before = running_entities.get(key)
        after = candidate_entities.get(key)
        if before and after and before["fingerprint"] == after["fingerprint"]:
            continue
        identity = before or after
        assert identity is not None
        change = "removed" if before and not after else "added" if after and not before else "changed"
        related, operations = _mutation_details(identity["xpath"], mutations)
        planned = bool(related)
        action_label = {
            "removed": "Encja zostanie usunięta z candidate.",
            "added": "Encja zostanie dodana do candidate.",
            "changed": "Zawartość encji zostanie zmieniona w candidate.",
        }[change]
        if not planned:
            action_label += " Zmiana NIE należy do zakresu tej sesji."
        entries.append(
            {
                "key": key,
                "change": change,
                "entityType": identity["entityType"],
                "scope": identity["scope"],
                "name": identity["name"],
                "rulebase": identity["rulebase"],
                "policyType": identity["policyType"],
                "xpath": identity["xpath"],
                "planned": planned,
                "explanation": action_label,
                "mutationIds": [item.mutation_id for item in related],
                "componentIds": sorted({item.component_id for item in related}),
                "causes": sorted({cause for item in related for cause in item.causes}),
                "operations": operations,
                "beforeXml": _pretty_xml(before["element"] if before else None),
                "afterXml": _pretty_xml(after["element"] if after else None),
                "unifiedDiff": _unified_xml_diff(
                    before["element"] if before else None,
                    after["element"] if after else None,
                    before_label=f"running/{key}",
                    after_label=f"candidate/{key}",
                ),
            }
        )
    return entries


def _ip_causes(mutations: Sequence[Mutation]) -> tuple[str, ...]:
    result: set[str] = set()
    for mutation in mutations:
        for cause in mutation.causes:
            try:
                result.add(str(ipaddress.ip_address(cause)))
            except ValueError:
                continue
    return tuple(sorted(result))


def _child_identity(
    child: ET.Element,
    *,
    tag_index: int,
    duplicate_index: int,
) -> tuple[tuple[str, str, str, int], str]:
    """Return a stable comparison key and a human-readable exact XPath segment."""

    name = child.get("name")
    if name is not None:
        base = (child.tag, "name", name, duplicate_index)
        segment = f"{child.tag}[@name={xpath_literal(name)}]"
    elif child.tag == "member" and (child.text or "").strip():
        text = (child.text or "").strip()
        base = (child.tag, "text", text, duplicate_index)
        segment = f"{child.tag}[text()={xpath_literal(text)}]"
    else:
        base = (child.tag, "position", str(tag_index), duplicate_index)
        segment = child.tag if tag_index == 1 else f"{child.tag}[{tag_index}]"
    if duplicate_index > 1:
        segment += f"[duplicate={duplicate_index}]"
    return base, segment


def _indexed_children(
    parent: ET.Element,
) -> list[tuple[tuple[str, str, str, int], str, ET.Element]]:
    tag_counts: dict[str, int] = {}
    identity_counts: dict[tuple[str, str, str], int] = {}
    result: list[tuple[tuple[str, str, str, int], str, ET.Element]] = []
    for child in list(parent):
        tag_counts[child.tag] = tag_counts.get(child.tag, 0) + 1
        name = child.get("name")
        text = (child.text or "").strip()
        if name is not None:
            identity = (child.tag, "name", name)
        elif child.tag == "member" and text:
            identity = (child.tag, "text", text)
        else:
            identity = (child.tag, "position", str(tag_counts[child.tag]))
        identity_counts[identity] = identity_counts.get(identity, 0) + 1
        key, segment = _child_identity(
            child,
            tag_index=tag_counts[child.tag],
            duplicate_index=identity_counts[identity],
        )
        result.append((key, segment, child))
    return result


def _candidate_path_differences(
    expected: ET.Element,
    candidate: ET.Element,
) -> tuple[list[dict[str, str]], bool]:
    """Locate the exact XML paths responsible for a projection mismatch.

    Values are deliberately not copied into the report.  The path and the
    structural difference are enough for an operator, while passwords,
    certificates and other configuration values stay out of GUI diagnostics.
    """

    differences: list[dict[str, str]] = []
    truncated = False

    def add(xpath: str, kind: str, detail: str) -> None:
        nonlocal truncated
        if len(differences) >= _MAX_PATH_DIFFERENCES:
            truncated = True
            return
        differences.append(
            {"xpath": xpath, "differenceKind": kind, "detail": detail}
        )

    def compare(left: ET.Element, right: ET.Element, xpath: str) -> None:
        left_attributes = {
            key: value
            for key, value in left.attrib.items()
            if key not in VOLATILE_ATTRIBUTES
        }
        right_attributes = {
            key: value
            for key, value in right.attrib.items()
            if key not in VOLATILE_ATTRIBUTES
        }
        changed_attributes = sorted(
            key
            for key in set(left_attributes) | set(right_attributes)
            if left_attributes.get(key) != right_attributes.get(key)
        )
        if changed_attributes:
            add(
                xpath,
                "attributes-changed",
                "Candidate ma inne atrybuty niż projekcja PatchSet: "
                + ", ".join(changed_attributes),
            )
        if (left.text or "").strip() != (right.text or "").strip():
            add(
                xpath,
                "text-changed",
                "Wartość elementu w candidate różni się od projekcji PatchSet.",
            )

        left_items = _indexed_children(left)
        right_items = _indexed_children(right)
        left_by_key = {key: (segment, child) for key, segment, child in left_items}
        right_by_key = {key: (segment, child) for key, segment, child in right_items}
        left_order = [key for key, _segment, _child in left_items]
        right_order = [key for key, _segment, _child in right_items]
        if set(left_order) == set(right_order) and left_order != right_order:
            add(
                xpath,
                "child-order-changed",
                "Kolejność elementów potomnych w candidate różni się od projekcji PatchSet.",
            )

        for key in left_order:
            segment, left_child = left_by_key[key]
            child_xpath = f"{xpath.rstrip('/')}/{segment}"
            right_item = right_by_key.get(key)
            if right_item is None:
                add(
                    child_xpath,
                    "missing-from-candidate",
                    "Element oczekiwany po zastosowaniu PatchSet nie istnieje w candidate.",
                )
                continue
            compare(left_child, right_item[1], child_xpath)
        for key in right_order:
            if key in left_by_key:
                continue
            segment, _right_child = right_by_key[key]
            add(
                f"{xpath.rstrip('/')}/{segment}",
                "unexpected-in-candidate",
                "Candidate zawiera element, którego nie ma w projekcji PatchSet.",
            )

    compare(expected, candidate, "/config")
    return differences, truncated


def _finalize_scope_guard(
    *,
    candidate: ET.Element,
    mutations: Sequence[Mutation],
    findings: Sequence[dict[str, Any]],
    projection_matches: Optional[bool],
    projection_sha256: Optional[str],
    projection_error: Optional[str],
) -> dict[str, Any]:
    canonical_findings = [
        {
            key: finding.get(key)
            for key in (
                "code",
                "detail",
                "target",
                "ownerType",
                "ownerName",
                "scope",
                "field",
                "xpath",
                "outsidePlan",
                "differenceKind",
            )
        }
        for finding in findings
    ]
    candidate_sha256 = fingerprint_element(candidate)
    finding_digest = (
        raw_sha256(
            json.dumps(
                {
                    "candidateSemanticSha256": candidate_sha256,
                    "findings": canonical_findings,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        if findings
        else None
    )
    return {
        "passed": not findings,
        "findingCount": len(findings),
        "outsidePlanCount": sum(bool(item["outsidePlan"]) for item in findings),
        "checkedMutationCount": len(mutations),
        "candidateProjectionMatches": projection_matches,
        "candidateProjectionSha256": projection_sha256,
        "candidateSemanticSha256": candidate_sha256,
        "projectionError": projection_error,
        "findingDigest": finding_digest,
        "overrideEligible": bool(findings),
        "findings": list(findings),
    }


def _scope_guard(
    running: ET.Element,
    baseline_candidate: ET.Element,
    candidate: ET.Element,
    patch: PatchSet,
    mutations: Sequence[Mutation],
    changes: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    touched_xpaths = tuple(mutation.target_xpath for mutation in mutations)

    def add_finding(
        *,
        code: str,
        detail: str,
        target: str = "",
        owner_type: str = "",
        owner_name: str = "",
        owner_scope: str = "",
        field: str = "",
        xpath: str = "",
        difference_kind: str = "",
    ) -> None:
        outside = not any(_paths_overlap(xpath, item) for item in touched_xpaths) if xpath else True
        record = {
            "code": code,
            "detail": detail,
            "target": target,
            "ownerType": owner_type,
            "ownerName": owner_name,
            "scope": owner_scope,
            "field": field,
            "xpath": xpath,
            "outsidePlan": outside,
            "differenceKind": difference_kind,
        }
        identity = (
            record["code"],
            record["target"],
            record["ownerType"],
            record["ownerName"],
            record["scope"],
            record["field"],
            record["xpath"],
            record["differenceKind"],
        )
        if not any(
            (
                item["code"],
                item["target"],
                item["ownerType"],
                item["ownerName"],
                item["scope"],
                item["field"],
                item["xpath"],
                item.get("differenceKind", ""),
            )
            == identity
            for item in findings
        ):
            findings.append(record)

    for change in changes:
        if change["planned"]:
            continue
        add_finding(
            code="OUTSIDE_PLAN_ENTITY_CHANGE",
            detail=(
                f"Candidate zawiera zmianę {change['change']} encji "
                f"{change['scope']}/{change['name']}, której nie ma w PatchSet."
            ),
            target=change["key"],
            owner_type=change["entityType"],
            owner_name=change["name"],
            owner_scope=change["scope"],
            xpath=change["xpath"],
        )

    # For cleanup every forward operation is deterministic and can be applied
    # to running locally.  Equality with live candidate proves there is no
    # hidden change in an unsupported namespace either.
    projection_matches: Optional[bool] = None
    projection_sha256: Optional[str] = None
    projection_error: Optional[str] = None
    if patch.kind == "cleanup":
        expected = copy.deepcopy(running)
        try:
            for mutation in mutations:
                for operation in mutation.forward:
                    apply_operation_to_tree(expected, operation)
            projection_sha256 = fingerprint_element(expected)
            projection_matches = projection_sha256 == fingerprint_element(candidate)
            if not projection_matches:
                add_finding(
                    code="CANDIDATE_OUTSIDE_PATCHSET",
                    detail=(
                        "Pełny candidate różni się od running + dokładnie operacje tej "
                        "sesji. Commit mógłby utrwalić zmianę spoza zakresu."
                    ),
                )
                path_differences, path_differences_truncated = (
                    _candidate_path_differences(expected, candidate)
                )
                for difference in path_differences:
                    add_finding(
                        code="CANDIDATE_PATH_OUTSIDE_PATCHSET",
                        detail=difference["detail"],
                        target="running + PatchSet",
                        xpath=difference["xpath"],
                        difference_kind=difference["differenceKind"],
                    )
                if path_differences_truncated:
                    add_finding(
                        code="CANDIDATE_PATH_DIFF_TRUNCATED",
                        detail=(
                            f"Wykryto więcej niż {_MAX_PATH_DIFFERENCES} różnic XML. "
                            "Raport pokazuje pierwsze ścieżki; pełny diff pozostaje "
                            "w artefakcie candidate_diff."
                        ),
                    )
        except Exception as exc:  # fail closed: an incomplete proof is unsafe
            projection_matches = False
            projection_error = f"{type(exc).__name__}: {exc}"
            add_finding(
                code="PATCHSET_PROJECTION_FAILED",
                detail=(
                    "Nie można lokalnie udowodnić pełnego zakresu candidate: "
                    + projection_error
                ),
            )

    if patch.kind != "cleanup":
        return _finalize_scope_guard(
            candidate=candidate,
            mutations=mutations,
            findings=findings,
            projection_matches=projection_matches,
            projection_sha256=projection_sha256,
            projection_error=projection_error,
        )

    try:
        _legacy_root()
        from panorama_cleanup.models import ScopedName  # type: ignore[import-not-found]
        from panorama_cleanup.panos import (  # type: ignore[import-not-found]
            address_literal_relation,
            parse_config,
            resolve_name,
            resolve_occurrence,
        )

        baseline_model = parse_config(baseline_candidate)
        candidate_model = parse_config(candidate)
        deleted: dict[Any, str] = {}
        for mutation in mutations:
            if mutation.after_xml is not None or mutation.entity_type not in {"address", "group"}:
                continue
            matches = (
                baseline_model.addresses
                if mutation.entity_type == "address"
                else baseline_model.static_groups
            )
            key = next(
                (item for item, value in matches.items() if value.xpath == mutation.target_xpath),
                None,
            )
            if key is None and "/" in mutation.entity_key:
                location, name = mutation.entity_key.rsplit("/", 1)
                candidate_key = ScopedName(location, name)
                if candidate_key in matches:
                    key = candidate_key
            if key is not None:
                deleted[key] = mutation.entity_type

        target_ips = _ip_causes(mutations)

        def inspect_reference(reference: Any) -> None:
            target_label = ""
            try:
                _kind, historical_key, _detail = resolve_name(
                    baseline_model,
                    reference.owner_location,
                    reference.referenced_name,
                )
            except Exception:
                historical_key = None
            if historical_key in deleted:
                target_label = f"{historical_key.location}/{historical_key.name}"
            literal_target = next(
                (
                    ip
                    for ip in target_ips
                    if reference.resolved_kind in {"literal", "unresolved"}
                    and address_literal_relation(reference.referenced_name, ip)
                ),
                None,
            )
            if not target_label and literal_target:
                target_label = literal_target
            if not target_label:
                return
            add_finding(
                code="RESIDUAL_REFERENCE",
                detail=(
                    f"{reference.owner_type} {reference.owner_location}/"
                    f"{reference.owner_name} nadal wskazuje {reference.referenced_name}."
                ),
                target=target_label,
                owner_type=reference.owner_type,
                owner_name=reference.owner_name,
                owner_scope=reference.owner_location,
                field=reference.field,
                xpath=reference.configuration_path,
            )

        for references in (
            *candidate_model.group_references.values(),
            *candidate_model.rule_references.values(),
        ):
            for reference in references:
                inspect_reference(reference)

        for occurrence in candidate_model.unknown_occurrences:
            target_label = ""
            try:
                _kind, historical_key, _detail = resolve_occurrence(
                    baseline_model, occurrence
                )
            except Exception:
                historical_key = None
            if historical_key in deleted:
                target_label = f"{historical_key.location}/{historical_key.name}"
            literal_target = next(
                (
                    ip
                    for ip in target_ips
                    if address_literal_relation(occurrence.value, ip)
                ),
                None,
            )
            if not target_label and literal_target:
                target_label = literal_target
            if target_label:
                add_finding(
                    code="RESIDUAL_UNMODELED_REFERENCE",
                    detail=(
                        f"{occurrence.owner_type} {occurrence.location}/"
                        f"{occurrence.owner_name} nadal zawiera {occurrence.value}."
                    ),
                    target=target_label,
                    owner_type=occurrence.owner_type,
                    owner_name=occurrence.owner_name,
                    owner_scope=occurrence.location,
                    field="address-bearing-field",
                    xpath=occurrence.configuration_path,
                )
    except Exception as exc:  # parser is the proof boundary; never guess
        add_finding(
            code="DEPENDENCY_SCAN_FAILED",
            detail=(
                "Nie można zakończyć pełnego skanu zależności candidate: "
                f"{type(exc).__name__}: {exc}"
            ),
        )

    return _finalize_scope_guard(
        candidate=candidate,
        mutations=mutations,
        findings=findings,
        projection_matches=projection_matches,
        projection_sha256=projection_sha256,
        projection_error=projection_error,
    )


def _compact_change(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        key: entry[key]
        for key in (
            "key",
            "change",
            "entityType",
            "scope",
            "name",
            "rulebase",
            "policyType",
            "xpath",
            "planned",
            "explanation",
            "mutationIds",
            "componentIds",
            "causes",
            "operations",
        )
    }


def build_scope_guard(
    *,
    running: ET.Element,
    baseline_candidate: ET.Element,
    candidate: ET.Element,
    patch: PatchSet,
    applied_mutation_ids: Iterable[str],
) -> dict[str, Any]:
    """Re-run only the fail-closed proof used immediately before commit."""

    applied = set(applied_mutation_ids)
    mutations = tuple(
        mutation for mutation in patch.mutations if mutation.mutation_id in applied
    )
    changes = _change_entries(running, candidate, mutations)
    return _scope_guard(
        running,
        baseline_candidate,
        candidate,
        patch,
        mutations,
        changes,
    )


def _render_review_text(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    native = payload["native"]
    guard = payload["scopeGuard"]
    lines = [
        "PANOS TOOLBOX — PEŁNY PRZEGLĄD PRZED COMMIT",
        f"Sesja: {payload['sessionId']}",
        f"Wygenerowano UTC: {payload['generatedAt']}",
        f"Running SHA256: {payload['running']['semanticSha256']}",
        f"Candidate SHA256: {payload['candidate']['semanticSha256']}",
        "",
        "PODSUMOWANIE",
        f"- zmiany razem: {summary['total']}",
        f"- zaplanowane: {summary['planned']}",
        f"- poza planem: {summary['outsidePlan']}",
        f"- dodane: {summary['added']}",
        f"- usunięte: {summary['removed']}",
        f"- zmienione: {summary['changed']}",
        f"- scope guard: {'PASS' if guard['passed'] else 'BLOCK'} ({guard['findingCount']} ustaleń)",
        f"- Panorama change-summary: {native.get('detail') or 'brak'}",
        "",
        "ZMIANY ENCJI",
    ]
    if not payload["changes"]:
        lines.append("Brak zmian w obsługiwanych encjach.")
    for index, entry in enumerate(payload["changes"], 1):
        lines.extend(
            [
                "",
                f"{index}. [{entry['change'].upper()}] {entry['entityType']} "
                f"{entry['scope']}/{entry['name']}",
                f"   Zakres: {'PLAN' if entry['planned'] else 'POZA PLANEM'}",
                f"   Rulebase/type: {entry['rulebase'] or '-'} / {entry['policyType'] or '-'}",
                f"   XPath: {entry['xpath']}",
                f"   Powód/cel: {entry['explanation']}",
                f"   Mutacje: {', '.join(entry['mutationIds']) or '-'}",
                f"   Przyczyny: {', '.join(entry['causes']) or '-'}",
                "   Diff XML:",
                entry["unifiedDiff"] or "   (brak tekstowej różnicy)",
            ]
        )
    lines.extend(["", "DOKŁADNE USTALENIA SCOPE GUARD"])
    if guard["passed"]:
        lines.append("Brak ustaleń blokujących.")
    for index, finding in enumerate(guard["findings"], 1):
        lines.extend(
            [
                f"{index}. {finding['code']}: {finding['detail']}",
                f"   Typ różnicy: {finding.get('differenceKind') or '-'}",
                f"   Cel: {finding['target'] or '-'}",
                f"   Właściciel: {finding['ownerType'] or '-'} "
                f"{finding['scope'] or '-'}/{finding['ownerName'] or '-'}",
                f"   Pole: {finding['field'] or '-'}",
                f"   XPath: {finding['xpath'] or '-'}",
                f"   Poza planem: {'TAK' if finding['outsidePlan'] else 'NIE'}",
            ]
        )
    return "\n".join(lines) + "\n"


def render_scope_guard_text(
    session_id: str, generated_at: str, guard: dict[str, Any]
) -> str:
    lines = [
        "PANOS TOOLBOX — SCOPE GUARD PRZED COMMIT",
        f"Sesja: {session_id}",
        f"Wygenerowano UTC: {generated_at}",
        f"Wynik: {'PASS' if guard['passed'] else 'BLOCK'}",
        f"Ustalenia: {guard['findingCount']}",
        f"Pełna projekcja candidate: {guard['candidateProjectionMatches']}",
        f"Fingerprint blokady: {guard.get('findingDigest') or '-'}",
        f"Tryb weryfikacji: {guard.get('verificationMode') or 'pełny przegląd'}",
        f"Punktowe odczyty XPath: {guard.get('targetedXPathReads') or 0}",
        f"Override zażądany: {'TAK' if guard.get('overrideRequested') else 'NIE'}",
        f"Override zastosowany: {'TAK' if guard.get('overrideApplied') else 'NIE'}",
        "",
    ]
    if guard["passed"]:
        lines.append(
            "Nie znaleziono zależności do usuwanych obiektów ani zmian poza PatchSet."
        )
    for index, finding in enumerate(guard["findings"], 1):
        lines.extend(
            [
                f"{index}. {finding['code']}: {finding['detail']}",
                f"   Typ różnicy: {finding.get('differenceKind') or '-'}",
                f"   Cel: {finding['target'] or '-'}",
                f"   Właściciel: {finding['ownerType'] or '-'} "
                f"{finding['scope'] or '-'}/{finding['ownerName'] or '-'}",
                f"   Pole: {finding['field'] or '-'}",
                f"   XPath: {finding['xpath'] or '-'}",
                f"   Poza planem: {'TAK' if finding['outsidePlan'] else 'NIE'}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def build_commit_review(
    *,
    session_id: str,
    generated_at: str,
    running: ET.Element,
    baseline_candidate: ET.Element,
    candidate: ET.Element,
    patch: PatchSet,
    applied_mutation_ids: Iterable[str],
    native_summary: Optional[ET.Element],
    native_error: Optional[str] = None,
) -> CommitReviewDocuments:
    applied = set(applied_mutation_ids)
    mutations = tuple(
        mutation for mutation in patch.mutations if mutation.mutation_id in applied
    )
    changes = _change_entries(running, candidate, mutations)
    guard = _scope_guard(
        running,
        baseline_candidate,
        candidate,
        patch,
        mutations,
        changes,
    )
    native = summarize_native_change_summary(native_summary)
    native["semanticSha256"] = (
        fingerprint_element(native_summary) if native_summary is not None else None
    )
    # ``semanticSha256`` intentionally ignores volatile PAN attributes and is
    # useful for human-facing diffs.  Commit preflight also needs a strict
    # proof that the lightweight change-summary is byte-for-byte equivalent to
    # the one reviewed by the operator.  When this proof matches, Toolbox can
    # verify only the touched XPath values instead of downloading /config
    # again.  Older reviews without this field safely use the full-config
    # fallback.
    native["rawSha256"] = (
        raw_sha256(ET.tostring(native_summary, encoding="utf-8"))
        if native_summary is not None
        else None
    )
    if native_error:
        native["error"] = native_error
        native["detail"] = f"Change-summary niedostępny: {native_error}"
    summary = {
        "total": len(changes),
        "planned": sum(bool(item["planned"]) for item in changes),
        "outsidePlan": sum(not bool(item["planned"]) for item in changes),
        "added": sum(item["change"] == "added" for item in changes),
        "removed": sum(item["change"] == "removed" for item in changes),
        "changed": sum(item["change"] == "changed" for item in changes),
    }
    full_config_diff = _unified_xml_diff(
        running,
        candidate,
        before_label="running.xml",
        after_label="candidate.xml",
    )
    payload = {
        "schemaVersion": 1,
        "sessionId": session_id,
        "generatedAt": generated_at,
        "commitReady": bool(guard["passed"]),
        "running": {
            "rawSha256": raw_sha256(ET.tostring(running, encoding="utf-8")),
            "semanticSha256": fingerprint_element(running),
        },
        "candidate": {
            "rawSha256": raw_sha256(ET.tostring(candidate, encoding="utf-8")),
            "semanticSha256": fingerprint_element(candidate),
        },
        "native": native,
        "summary": summary,
        "scopeGuard": guard,
        "changes": changes,
        "fullConfigUnifiedDiff": full_config_diff,
    }
    compact = {
        key: value
        for key, value in payload.items()
        if key not in {"changes", "fullConfigUnifiedDiff"}
    }
    compact["changes"] = [_compact_change(item) for item in changes]
    config_diff_text = "\n".join(
        [
            "PANOS TOOLBOX — PEŁNY DIFF RUNNING -> CANDIDATE",
            f"Sesja: {session_id}",
            f"Wygenerowano UTC: {generated_at}",
            "Linie '-' pochodzą z running; linie '+' są w candidate i zostaną objęte commitem.",
            "",
            full_config_diff or "Brak różnic tekstowych.",
            "",
        ]
    )
    return CommitReviewDocuments(
        compact=compact,
        payload=payload,
        review_text=_render_review_text(payload),
        config_diff_text=config_diff_text,
        scope_guard_text=render_scope_guard_text(session_id, generated_at, guard),
    )
