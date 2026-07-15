"""Three-way, path-scoped restore planning."""

from __future__ import annotations

import copy
import hashlib
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping, Optional, Sequence

from .errors import ValidationError
from .models import Mutation, MutationAction, MutationOperation, PatchSet
from .xmlutil import (
    element_xml,
    find_xpath,
    fingerprint_xpath,
    parent_xpath,
    rule_order_context_sha256,
)


class RestoreDecision(str, Enum):
    RESTORE = "RESTORE"
    ALREADY_RESTORED = "ALREADY_RESTORED"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True)
class RestoreFinding:
    mutation_id: str
    component_id: str
    entity_key: str
    decision: RestoreDecision
    before_sha256: str
    expected_cleanup_sha256: str
    current_sha256: str


@dataclass(frozen=True)
class RestorePlanResult:
    patchset: PatchSet
    findings: tuple[RestoreFinding, ...]
    conflicted_components: tuple[str, ...]


@dataclass(frozen=True)
class HistoricalMutation:
    """One applied cleanup mutation with a globally unique identity."""

    source_session_id: str
    applied_utc: str
    source_index: int
    mutation: Mutation

    @property
    def qualified_id(self) -> str:
        return f"{self.source_session_id}:{self.mutation.mutation_id}"


@dataclass(frozen=True)
class SelectedHistory:
    records: tuple[HistoricalMutation, ...]
    component_by_qualified_id: Mapping[str, str]
    source_session_ids: tuple[str, ...]


def decide_three_way(
    *, before_sha256: str, expected_sha256: str, current_sha256: str
) -> RestoreDecision:
    """Decide without ever overwriting a value changed after cleanup."""

    if current_sha256 == before_sha256:
        return RestoreDecision.ALREADY_RESTORED
    if current_sha256 == expected_sha256:
        return RestoreDecision.RESTORE
    return RestoreDecision.CONFLICT


def merge_removed_members(
    before: Iterable[str], expected: Iterable[str], current: Iterable[str]
) -> tuple[str, ...]:
    """Restore only cleanup-removed members and preserve later additions.

    This helper is independently testable; the production PatchSet uses even
    narrower ``member[text()=...]`` mutations, so it never replaces a complete
    source/destination/static list.
    """

    before_values = list(dict.fromkeys(before))
    expected_set = set(expected)
    current_values = list(dict.fromkeys(current))
    current_set = set(current_values)
    removed_by_cleanup = [item for item in before_values if item not in expected_set]
    result = list(current_values)
    for item in removed_by_cleanup:
        if item not in current_set:
            # Preserve the original relative order among restored members.  Do
            # not reorder members that were added later by another operator.
            preceding = [value for value in before_values[: before_values.index(item)] if value in result]
            if preceding:
                result.insert(result.index(preceding[-1]) + 1, item)
            else:
                result.insert(0, item)
            current_set.add(item)
    return tuple(result)


def mutation_owner_xpath(mutation: Mutation) -> str:
    """Return the complete address/group/rule entry changed by a mutation."""

    if mutation.entity_type in {"group-member", "policy-member"}:
        return parent_xpath(parent_xpath(mutation.target_xpath))
    return mutation.target_xpath


def _policy_name(mutation: Mutation) -> str:
    if mutation.before_xml:
        try:
            name = ET.fromstring(mutation.before_xml).get("name")
        except ET.ParseError:
            name = None
        if name:
            return name
    return mutation.entity_key.rsplit("/", 1)[-1]


def _address_namespace_key(mutation: Mutation) -> Optional[str]:
    owner = mutation_owner_xpath(mutation)
    if "/address/entry[" in owner:
        return owner.replace("/address/entry[", "/address-namespace/entry[", 1)
    if "/address-group/entry[" in owner:
        return owner.replace(
            "/address-group/entry[", "/address-namespace/entry[", 1
        )
    return None


def _opposite_namespace_xpath(mutation: Mutation) -> Optional[str]:
    if mutation.entity_type == "address":
        return mutation.target_xpath.replace(
            "/address/entry[", "/address-group/entry[", 1
        )
    if mutation.entity_type == "group":
        return mutation.target_xpath.replace(
            "/address-group/entry[", "/address/entry[", 1
        )
    return None


def select_history(
    records: Sequence[HistoricalMutation],
    *,
    ip: Optional[str] = None,
    source_session_id: Optional[str] = None,
    dependency_owner_sets: Iterable[Iterable[str]] = (),
) -> SelectedHistory:
    """Select the transitive cleanup history needed for an IP or session.

    Original per-session components remain atomic.  Cross-session edges join
    repeated/overlapping owners, the same cleanup cause, historical inventory
    dependencies and rule-order anchors.
    """

    if bool(ip) == bool(source_session_id):
        raise ValidationError("Restore history wymaga dokładnie IP albo source session.")
    by_id = {record.qualified_id: record for record in records}
    adjacency: dict[str, set[str]] = {key: set() for key in by_id}

    def connect(values: Iterable[str]) -> None:
        known = sorted({value for value in values if value in adjacency})
        if len(known) < 2:
            return
        first = known[0]
        for other in known[1:]:
            adjacency[first].add(other)
            adjacency[other].add(first)

    by_original_component: dict[tuple[str, str], list[str]] = {}
    by_cause: dict[str, list[str]] = {}
    by_owner: dict[str, list[str]] = {}
    by_namespace: dict[str, list[str]] = {}
    for record in records:
        qualified = record.qualified_id
        mutation = record.mutation
        by_original_component.setdefault(
            (record.source_session_id, mutation.component_id), []
        ).append(qualified)
        for cause in mutation.causes:
            by_cause.setdefault(cause, []).append(qualified)
        by_owner.setdefault(mutation_owner_xpath(mutation), []).append(qualified)
        namespace = _address_namespace_key(mutation)
        if namespace:
            by_namespace.setdefault(namespace, []).append(qualified)
    for values in by_original_component.values():
        connect(values)
    for values in by_cause.values():
        connect(values)
    for values in by_owner.values():
        connect(values)
    for values in by_namespace.values():
        connect(values)

    owners = set(by_owner)
    for owner in sorted(owners):
        ancestor = parent_xpath(owner)
        while ancestor != "/config":
            if ancestor in owners:
                connect((*by_owner[owner], *by_owner[ancestor]))
            ancestor = parent_xpath(ancestor)

    for owner_set in dependency_owner_sets:
        connect(
            qualified
            for owner in set(owner_set)
            for qualified in by_owner.get(owner, ())
        )

    policy_by_anchor: dict[tuple[str, str], list[str]] = {}
    for record in records:
        if record.mutation.entity_type != "policy":
            continue
        owner = mutation_owner_xpath(record.mutation)
        policy_by_anchor.setdefault(
            (parent_xpath(owner), _policy_name(record.mutation)), []
        ).append(record.qualified_id)
    for record in records:
        mutation = record.mutation
        if mutation.entity_type != "policy":
            continue
        container = parent_xpath(mutation_owner_xpath(mutation))
        for anchor in (mutation.order_previous, mutation.order_next):
            if anchor:
                connect(
                    (
                        record.qualified_id,
                        *policy_by_anchor.get((container, anchor), ()),
                    )
                )

    seeds = {
        record.qualified_id
        for record in records
        if (
            ip is not None
            and ip in record.mutation.causes
            or source_session_id is not None
            and record.source_session_id == source_session_id
        )
    }
    if not seeds:
        target = ip or source_session_id or "?"
        raise ValidationError(f"Historia nie zawiera zastosowanej mutacji dla {target}.")
    selected: set[str] = set(seeds)
    queue = deque(sorted(seeds))
    while queue:
        current = queue.popleft()
        for neighbor in sorted(adjacency[current]):
            if neighbor not in selected:
                selected.add(neighbor)
                queue.append(neighbor)

    component_by_id: dict[str, str] = {}
    remaining = set(selected)
    while remaining:
        start = min(remaining)
        component_nodes: set[str] = {start}
        pending = deque((start,))
        while pending:
            current = pending.popleft()
            for neighbor in adjacency[current] & selected:
                if neighbor not in component_nodes:
                    component_nodes.add(neighbor)
                    pending.append(neighbor)
        component = "component-history-" + hashlib.sha256(
            "|".join(sorted(component_nodes)).encode("utf-8")
        ).hexdigest()[:12]
        for qualified in component_nodes:
            component_by_id[qualified] = component
        remaining -= component_nodes

    chosen = tuple(
        record
        for record in sorted(
            records,
            key=lambda item: (
                item.applied_utc,
                item.source_session_id,
                item.source_index,
            ),
        )
        if record.qualified_id in selected
    )
    sessions = tuple(dict.fromkeys(record.source_session_id for record in chosen))
    return SelectedHistory(chosen, component_by_id, sessions)


def _fragment_nodes(element: str) -> list[ET.Element]:
    try:
        wrapper = ET.fromstring(f"<fragment>{element}</fragment>")
    except ET.ParseError as exc:
        raise ValidationError(f"Simulator restore otrzymał błędny XML: {exc}.") from exc
    return list(wrapper)


def _same_child(left: ET.Element, right: ET.Element) -> bool:
    if left.tag != right.tag:
        return False
    if right.get("name") is not None:
        return left.get("name") == right.get("name")
    if right.tag == "member":
        return (left.text or "").strip() == (right.text or "").strip()
    return False


def apply_operation_to_tree(config: ET.Element, operation: MutationOperation) -> None:
    """Apply the conservative PatchSet operation subset without an API call."""

    if operation.action is MutationAction.SET:
        parent = find_xpath(config, operation.xpath)
        if parent is None:
            raise ValidationError(f"SET wskazuje brakujący parent {operation.xpath}.")
        assert operation.element is not None
        pending: list[ET.Element] = []
        for fragment in _fragment_nodes(operation.element):
            existing = next(
                (
                    child
                    for child in [*list(parent), *pending]
                    if _same_child(child, fragment)
                ),
                None,
            )
            if existing is not None:
                if ET.tostring(existing) != ET.tostring(fragment):
                    raise ValidationError(
                        f"SET koliduje z istniejącym elementem pod {operation.xpath}."
                    )
                continue
            pending.append(fragment)
        for fragment in pending:
            parent.append(copy.deepcopy(fragment))
        return

    target = find_xpath(config, operation.xpath)
    parent = find_xpath(config, parent_xpath(operation.xpath))
    if operation.action is MutationAction.DELETE:
        if target is None or parent is None:
            raise ValidationError(f"DELETE wskazuje brakujący XPath {operation.xpath}.")
        parent.remove(target)
        return
    if operation.action is MutationAction.EDIT:
        if target is None or parent is None:
            raise ValidationError(f"EDIT wskazuje brakujący XPath {operation.xpath}.")
        assert operation.element is not None
        fragments = _fragment_nodes(operation.element)
        if len(fragments) != 1:
            raise ValidationError("EDIT w simulatorze wymaga dokładnie jednego elementu.")
        index = list(parent).index(target)
        parent.remove(target)
        parent.insert(index, copy.deepcopy(fragments[0]))
        return
    if operation.action is MutationAction.MOVE:
        if target is None or parent is None:
            raise ValidationError(f"MOVE wskazuje brakujący XPath {operation.xpath}.")
        destination = None
        if operation.where in {"before", "after"}:
            destination = next(
                (
                    child
                    for child in list(parent)
                    if child.get("name") == operation.destination
                ),
                None,
            )
            if destination is None or destination is target:
                raise ValidationError(
                    f"MOVE nie znajduje bezpiecznego anchoru {operation.destination!r}."
                )
        parent.remove(target)
        if operation.where == "top":
            parent.insert(0, target)
        elif operation.where == "bottom":
            parent.append(target)
        else:
            assert destination is not None
            index = list(parent).index(destination)
            if operation.where == "after":
                index += 1
            parent.insert(index, target)
        return
    raise ValidationError(f"Nieobsługiwana operacja simulatora: {operation.action}.")


def _policy_step_is_safe(
    mutation: Mutation,
    config: ET.Element,
    selected_policy_anchors: set[tuple[str, str]],
) -> bool:
    """Validate anchors available at this point in reverse chronology.

    An adjacent rule that belongs to the same restore component can still be
    absent because it is restored by the next inverse step.  A surviving
    anchor must already exist and be immediately adjacent.
    """

    if mutation.entity_type != "policy":
        return True
    rule = find_xpath(config, mutation.target_xpath)
    container_xpath = parent_xpath(mutation.target_xpath)
    container = find_xpath(config, container_xpath)
    if rule is None or container is None or not rule.get("name"):
        return False
    names = [entry.get("name") for entry in container.findall("./entry")]
    name = rule.get("name")
    if name not in names:
        return False
    index = names.index(name)
    if mutation.order_previous:
        if mutation.order_previous in names:
            if names.index(mutation.order_previous) + 1 != index:
                return False
        elif (container_xpath, mutation.order_previous) not in selected_policy_anchors:
            return False
    elif index != 0:
        return False
    if mutation.order_next:
        if mutation.order_next in names:
            if index + 1 != names.index(mutation.order_next):
                return False
        elif (container_xpath, mutation.order_next) not in selected_policy_anchors:
            return False
    elif index != len(names) - 1:
        return False
    return True


def _final_policy_anchors(
    mutation: Mutation, config: ET.Element
) -> tuple[Optional[str], Optional[str]]:
    if mutation.entity_type != "policy":
        return mutation.order_previous, mutation.order_next
    rule = find_xpath(config, mutation.target_xpath)
    container = find_xpath(config, parent_xpath(mutation.target_xpath))
    if rule is None or container is None or not rule.get("name"):
        raise ValidationError(
            f"Nie można wyprowadzić końcowej pozycji polityki {mutation.entity_key}."
        )
    names = [entry.get("name") for entry in container.findall("./entry")]
    index = names.index(rule.get("name"))
    previous = names[index - 1] if index else None
    following = names[index + 1] if index + 1 < len(names) else None
    return previous, following


def build_restore_patchset_history(
    selected: SelectedHistory,
    current_config: ET.Element,
    *,
    panorama_host: str,
    panorama_username: str,
    affected_device_groups: Iterable[str],
    preconflicted_components: Iterable[str] = (),
) -> RestorePlanResult:
    """Reverse an applied multi-session cleanup timeline in a local XML copy."""

    by_component: dict[str, list[HistoricalMutation]] = {}
    for record in selected.records:
        component = selected.component_by_qualified_id[record.qualified_id]
        by_component.setdefault(component, []).append(record)

    findings: list[RestoreFinding] = []
    conflicted: set[str] = set(preconflicted_components)
    planned: list[tuple[str, HistoricalMutation]] = []
    # Components selected by the dependency graph do not overlap owners.  A
    # single combined simulator therefore preserves their final interaction
    # without copying a potentially very large Panorama config per component.
    # A component that fails its three-way/order checks is rewound locally with
    # the original cleanup forward operations before processing continues.
    working = copy.deepcopy(current_config)
    for component, records in sorted(by_component.items()):
        component_findings: list[RestoreFinding] = []
        component_applied: list[HistoricalMutation] = []
        component_policy_anchors = {
            (
                parent_xpath(mutation_owner_xpath(record.mutation)),
                _policy_name(record.mutation),
            )
            for record in records
            if record.mutation.entity_type == "policy"
        }
        sessions_by_time: dict[str, set[str]] = {}
        for record in records:
            sessions_by_time.setdefault(record.applied_utc, set()).add(
                record.source_session_id
            )
        if any(len(sessions) > 1 for sessions in sessions_by_time.values()):
            conflicted.add(component)
        namespace_types: dict[str, set[str]] = {}
        for record in records:
            namespace = _address_namespace_key(record.mutation)
            if namespace and record.mutation.entity_type in {"address", "group"}:
                namespace_types.setdefault(namespace, set()).add(
                    record.mutation.entity_type
                )
            opposite = _opposite_namespace_xpath(record.mutation)
            if opposite and find_xpath(current_config, opposite) is not None:
                conflicted.add(component)
        if any(len(types) > 1 for types in namespace_types.values()):
            conflicted.add(component)
        if component in conflicted:
            component_findings = [
                RestoreFinding(
                    mutation_id=record.qualified_id,
                    component_id=component,
                    entity_key=record.mutation.entity_key,
                    decision=RestoreDecision.CONFLICT,
                    before_sha256=record.mutation.before_sha256,
                    expected_cleanup_sha256=record.mutation.after_sha256,
                    current_sha256=fingerprint_xpath(
                        working, record.mutation.target_xpath
                    ),
                )
                for record in records
            ]
            findings.extend(component_findings)
            continue
        for record in reversed(records):
            mutation = record.mutation
            current_hash = fingerprint_xpath(working, mutation.target_xpath)
            decision = decide_three_way(
                before_sha256=mutation.before_sha256,
                expected_sha256=mutation.after_sha256,
                current_sha256=current_hash,
            )
            component_findings.append(
                RestoreFinding(
                    mutation_id=record.qualified_id,
                    component_id=component,
                    entity_key=mutation.entity_key,
                    decision=decision,
                    before_sha256=mutation.before_sha256,
                    expected_cleanup_sha256=mutation.after_sha256,
                    current_sha256=current_hash,
                )
            )
            if decision is RestoreDecision.CONFLICT:
                conflicted.add(component)
                break
            if decision is RestoreDecision.ALREADY_RESTORED:
                if not _policy_step_is_safe(
                    mutation, working, component_policy_anchors
                ):
                    conflicted.add(component)
                    break
                continue
            operation_applied = False
            try:
                for operation in mutation.inverse:
                    apply_operation_to_tree(working, operation)
                    operation_applied = True
            except ValidationError:
                if operation_applied:
                    component_applied.append(record)
                conflicted.add(component)
                break
            component_applied.append(record)
            if not _policy_step_is_safe(
                mutation, working, component_policy_anchors
            ):
                conflicted.add(component)
                break

        if component in conflicted:
            try:
                for record in reversed(component_applied):
                    for operation in record.mutation.forward:
                        apply_operation_to_tree(working, operation)
            except ValidationError as exc:
                raise ValidationError(
                    "Simulator restore nie zdołał wycofać konfliktowego komponentu "
                    f"{component}."
                ) from exc
            seen = {finding.mutation_id for finding in component_findings}
            for record in records:
                if record.qualified_id not in seen:
                    mutation = record.mutation
                    component_findings.append(
                        RestoreFinding(
                            mutation_id=record.qualified_id,
                            component_id=component,
                            entity_key=mutation.entity_key,
                            decision=RestoreDecision.CONFLICT,
                            before_sha256=mutation.before_sha256,
                            expected_cleanup_sha256=mutation.after_sha256,
                            current_sha256=fingerprint_xpath(
                                working, mutation.target_xpath
                            ),
                        )
                    )
            component_findings = [
                RestoreFinding(
                    mutation_id=finding.mutation_id,
                    component_id=finding.component_id,
                    entity_key=finding.entity_key,
                    decision=RestoreDecision.CONFLICT,
                    before_sha256=finding.before_sha256,
                    expected_cleanup_sha256=finding.expected_cleanup_sha256,
                    current_sha256=finding.current_sha256,
                )
                for finding in component_findings
            ]
        else:
            planned.extend((component, record) for record in component_applied)
        findings.extend(component_findings)

    # ``working`` is now the combined final state of every safe component.
    final_tree = working

    restore_mutations: list[Mutation] = []
    previous_by_component: dict[str, str] = {}
    for index, (component, record) in enumerate(planned, 1):
        source = record.mutation
        mutation_id = f"mutation-{index:05d}"
        dependency = previous_by_component.get(component)
        final_previous, final_next = _final_policy_anchors(source, final_tree)
        restore_mutations.append(
            Mutation(
                mutation_id=mutation_id,
                component_id=component,
                entity_type=source.entity_type,
                entity_key=source.entity_key,
                target_xpath=source.target_xpath,
                before_xml=element_xml(find_xpath(current_config, source.target_xpath)),
                after_xml=element_xml(find_xpath(final_tree, source.target_xpath)),
                forward=source.inverse,
                inverse=source.forward,
                causes=source.causes,
                depends_on=(dependency,) if dependency else (),
                order_previous=final_previous,
                order_next=final_next,
                order_context_sha256=(
                    rule_order_context_sha256(
                        current_config,
                        source.target_xpath,
                        final_previous,
                        final_next,
                    )
                    if source.entity_type == "policy"
                    else None
                ),
            )
        )
        previous_by_component[component] = mutation_id

    targets = sorted(
        {cause for record in selected.records for cause in record.mutation.causes}
    )
    warnings: list[str] = []
    if len(selected.source_session_ids) > 1:
        warnings.append(
            "Restore obejmuje przechodnią historię cleanup z wielu sesji: "
            + ", ".join(selected.source_session_ids)
        )
    if conflicted:
        warnings.append(
            "Restore pominął całe zależne komponenty z konfliktem: "
            + ", ".join(sorted(conflicted))
        )
    already_count = sum(
        finding.decision is RestoreDecision.ALREADY_RESTORED for finding in findings
    )
    if already_count:
        warnings.append(f"Mutacje już przywrócone pominięto: {already_count}.")
    primary = selected.source_session_ids[0]
    patchset = PatchSet.new(
        kind="restore",
        panorama_host=panorama_host,
        panorama_username=panorama_username,
        mutations=restore_mutations,
        targets=targets,
        affected_device_groups=affected_device_groups,
        warnings=warnings,
        source_session_id=primary,
        source_session_ids=selected.source_session_ids,
        skipped_components=conflicted,
    )
    return RestorePlanResult(
        patchset=patchset,
        findings=tuple(findings),
        conflicted_components=tuple(sorted(conflicted)),
    )


def build_restore_patchset(
    original: PatchSet,
    current_config: ET.Element,
    *,
    panorama_host: str,
    panorama_username: str,
    source_session_id: str,
    affected_device_groups: Optional[Iterable[str]] = None,
) -> RestorePlanResult:
    findings: list[RestoreFinding] = []
    conflicted: set[str] = set()
    original_rule_by_name: dict[tuple[str, str], Mutation] = {}
    for mutation in original.mutations:
        if mutation.entity_type == "policy":
            original_rule_by_name[(parent_xpath(mutation.target_xpath), mutation.entity_key.rsplit("/", 1)[-1])] = mutation

    for mutation in original.mutations:
        current_hash = fingerprint_xpath(current_config, mutation.target_xpath)
        decision = decide_three_way(
            before_sha256=mutation.before_sha256,
            expected_sha256=mutation.after_sha256,
            current_sha256=current_hash,
        )
        findings.append(
            RestoreFinding(
                mutation_id=mutation.mutation_id,
                component_id=mutation.component_id,
                entity_key=mutation.entity_key,
                decision=decision,
                before_sha256=mutation.before_sha256,
                expected_cleanup_sha256=mutation.after_sha256,
                current_sha256=current_hash,
            )
        )
        if decision is RestoreDecision.CONFLICT:
            conflicted.add(mutation.component_id)

    # Deleted rules carry their surviving order anchors.  A missing/reordered
    # anchor would place a restored rule under a different rule (often DROP),
    # so conflict the whole dependency component before generating any writes.
    changed = True
    while changed:
        changed = False
        for mutation in original.mutations:
            if mutation.entity_type != "policy" or mutation.component_id in conflicted:
                continue
            container_xpath = parent_xpath(mutation.target_xpath)
            container = find_xpath(current_config, container_xpath)
            current_names = (
                [entry.get("name") for entry in container.findall("./entry")]
                if container is not None
                else []
            )

            def surviving(anchor: Optional[str]) -> bool:
                if not anchor:
                    return False
                deleted = original_rule_by_name.get((container_xpath, anchor))
                return deleted is None

            invalid = False
            if surviving(mutation.order_previous) and mutation.order_previous not in current_names:
                invalid = True
            if surviving(mutation.order_next) and mutation.order_next not in current_names:
                invalid = True
            if (
                surviving(mutation.order_previous)
                and surviving(mutation.order_next)
                and mutation.order_previous in current_names
                and mutation.order_next in current_names
                and current_names.index(mutation.order_next)
                != current_names.index(mutation.order_previous) + 1
            ):
                invalid = True
            for anchor in (mutation.order_previous, mutation.order_next):
                deleted = original_rule_by_name.get((container_xpath, anchor or ""))
                if deleted is not None and deleted.component_id in conflicted:
                    invalid = True
            if invalid:
                conflicted.add(mutation.component_id)
                changed = True

    # Anchor conflicts apply to the complete dependency component, not merely
    # the rule that exposed the ambiguity. Reflect that in reports/manual XML.
    findings = [
        RestoreFinding(
            mutation_id=finding.mutation_id,
            component_id=finding.component_id,
            entity_key=finding.entity_key,
            decision=(
                RestoreDecision.CONFLICT
                if finding.component_id in conflicted
                else finding.decision
            ),
            before_sha256=finding.before_sha256,
            expected_cleanup_sha256=finding.expected_cleanup_sha256,
            current_sha256=finding.current_sha256,
        )
        for finding in findings
    ]
    decision_by_id = {item.mutation_id: item for item in findings}
    selected = [
        mutation
        for mutation in reversed(original.mutations)
        if mutation.component_id not in conflicted
        and decision_by_id[mutation.mutation_id].decision is RestoreDecision.RESTORE
    ]
    previous_by_component: dict[str, str] = {}
    restore_mutations: list[Mutation] = []
    for index, mutation in enumerate(selected, 1):
        mutation_id = f"mutation-{index:05d}"
        dependency = previous_by_component.get(mutation.component_id)
        restore_mutations.append(
            Mutation(
                mutation_id=mutation_id,
                component_id=mutation.component_id,
                entity_type=mutation.entity_type,
                entity_key=mutation.entity_key,
                target_xpath=mutation.target_xpath,
                before_xml=mutation.after_xml,
                after_xml=mutation.before_xml,
                forward=mutation.inverse,
                inverse=mutation.forward,
                causes=mutation.causes,
                depends_on=(dependency,) if dependency else (),
                order_previous=mutation.order_previous,
                order_next=mutation.order_next,
                order_context_sha256=(
                    rule_order_context_sha256(
                        current_config,
                        mutation.target_xpath,
                        mutation.order_previous,
                        mutation.order_next,
                    )
                    if mutation.entity_type == "policy"
                    else None
                ),
            )
        )
        previous_by_component[mutation.component_id] = mutation_id

    warnings = list(original.warnings)
    if conflicted:
        warnings.append(
            "Restore pominął całe zależne komponenty z konfliktem: "
            + ", ".join(sorted(conflicted))
        )
    already = [
        finding.entity_key
        for finding in findings
        if finding.decision is RestoreDecision.ALREADY_RESTORED
    ]
    if already:
        warnings.append(f"Encje już przywrócone pominięto: {len(already)}.")

    patchset = PatchSet.new(
        kind="restore",
        panorama_host=panorama_host,
        panorama_username=panorama_username,
        mutations=restore_mutations,
        targets=original.targets,
        affected_device_groups=(
            original.affected_device_groups
            if affected_device_groups is None
            else affected_device_groups
        ),
        warnings=warnings,
        source_session_id=source_session_id,
        skipped_components=conflicted,
    )
    return RestorePlanResult(patchset, tuple(findings), tuple(sorted(conflicted)))
