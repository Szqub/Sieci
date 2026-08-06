"""Structural adapter from the proven cleaner planner to XML API PatchSet."""

from __future__ import annotations

import hashlib
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from .errors import InputError, ValidationError
from .models import Mutation, MutationAction, MutationOperation, PatchSet
from .xmlutil import parent_xpath, rule_order_names_sha256, xpath_literal


def _legacy_root() -> Path:
    candidates = (
        Path(__file__).resolve().parents[3] / "panorama_cleaner",
        Path(__file__).resolve().parents[1] / "vendor" / "panorama_cleaner",
        Path(__file__).resolve().parents[2] / "vendor" / "panorama_cleaner",
    )
    root = next((candidate for candidate in candidates if (candidate / "panorama_cleanup").is_dir()), None)
    if root is None:
        raise InputError(
            "Nie znaleziono współdzielonego cleanera. Release bundler musi dostarczyć "
            "backend/vendor/panorama_cleaner/panorama_cleanup."
        )
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return root


def _completeness_findings(model: Any, running_config: ET.Element) -> tuple[list[str], list[str]]:
    """Stdlib-only copy of the cleaner's small namespace boundary report."""

    from panorama_cleanup.panos import (  # type: ignore[import-not-found]
        is_supported_address_literal,
        resolve_occurrence,
    )

    warnings: list[str] = []
    if model.dynamic_groups:
        warnings.append(
            f"RUNTIME_DAG_PRESENT: {len(model.dynamic_groups)} dynamic address group; "
            "runtime IP→tag wymaga osobnego audytu managed firewalli."
        )
    fqdn_count = sum(obj.object_type == "fqdn" for obj in model.addresses.values())
    if fqdn_count:
        warnings.append(
            f"FQDN_PRESENT: {fqdn_count} obiektów FQDN; running config nie zawiera ich runtime DNS."
        )
    ip_edl_count = sum(
        entry.find("./type/ip") is not None
        for entry in running_config.findall(".//external-list/entry")
    )
    if ip_edl_count:
        warnings.append(f"IP_EDL_PRESENT: {ip_edl_count} list IP EDL bez runtime contents.")
    region_count = len(running_config.findall(".//region/entry"))
    if region_count:
        warnings.append(f"REGION_PRESENT: {region_count} custom region wymaga review.")
    unresolved = {
        ref.referenced_name
        for refs in list(model.group_references.values()) + list(model.rule_references.values())
        for ref in refs
        if ref.resolved_kind == "unresolved"
        and not is_supported_address_literal(ref.referenced_name)
    }
    unresolved.update(
        occurrence.value
        for occurrence in model.unknown_occurrences
        if resolve_occurrence(model, occurrence)[0] == "unresolved"
        and not is_supported_address_literal(occurrence.value)
    )
    if unresolved:
        warnings.append(
            f"UNMODELED_ADDRESS_REFERENCE_PRESENT: {len(unresolved)} nierozwiązanych nazw; "
            "planner stosuje targetowane blokady zależności."
        )
    return warnings, []


@dataclass(frozen=True)
class CleanerPlanResult:
    patchset: PatchSet
    model: Any
    plan: Any
    matches: Mapping[str, Any]
    blocked_ips: Mapping[str, Any]
    discovery: Mapping[str, Mapping[str, Any]]
    target_order: tuple[str, ...]


@dataclass
class _Spec:
    entity_type: str
    entity_key: str
    location: str
    target_xpath: str
    before_xml: Optional[str]
    after_xml: Optional[str]
    forward: tuple[MutationOperation, ...]
    inverse: tuple[MutationOperation, ...]
    causes: tuple[str, ...]
    order_previous: Optional[str] = None
    order_next: Optional[str] = None
    order_context_sha256: Optional[str] = None


def _member_xml(value: str) -> str:
    node = ET.Element("member")
    node.text = value
    return ET.tostring(node, encoding="unicode")


def _deleted_group_order(model: Any, deleted: set[Any]) -> list[Any]:
    outgoing = {key: set() for key in deleted}
    indegree = {key: 0 for key in deleted}
    for owner in deleted:
        for reference in model.group_references.get(owner, ()):
            target = reference.resolved_key
            if reference.resolved_kind == "static-group" and target in deleted:
                if target not in outgoing[owner]:
                    outgoing[owner].add(target)
                    indegree[target] += 1
    ready = sorted(key for key, degree in indegree.items() if degree == 0)
    result: list[Any] = []
    while ready:
        owner = ready.pop(0)
        result.append(owner)
        for target in sorted(outgoing[owner]):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
                ready.sort()
    if len(result) != len(deleted):
        raise ValidationError("Nie można bezpiecznie ustalić kolejności usuwania grup.")
    return result


def _causes(tokens: Iterable[Any]) -> tuple[str, ...]:
    result = tuple(sorted({token.ip for token in tokens}))
    if not result:
        raise ValidationError("Encja planu cleanera nie zawiera przyczyny/IP.")
    return result


def _rule_key(key: Any) -> str:
    return f"{key.location}/{key.rulebase}/{key.policy_type}/{key.name}"


def _scoped_key(key: Any) -> str:
    return f"{key.location}/{key.name}"


def _components(specs: Sequence[_Spec]) -> dict[str, str]:
    parent: dict[str, str] = {}

    def find(value: str) -> str:
        parent.setdefault(value, value)
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for spec in specs:
        for cause in spec.causes:
            find(cause)
        for cause in spec.causes[1:]:
            union(spec.causes[0], cause)
    groups: dict[str, list[str]] = {}
    for cause in sorted(parent):
        groups.setdefault(find(cause), []).append(cause)
    identifiers = {
        root: "component-" + hashlib.sha256("|".join(values).encode()).hexdigest()[:12]
        for root, values in groups.items()
    }
    return {cause: identifiers[find(cause)] for cause in parent}


def _expanded_device_groups(model: Any, changed_locations: Iterable[str]) -> tuple[str, ...]:
    changed = set(changed_locations)
    all_groups = set(model.parents)
    if "shared" in changed:
        return tuple(sorted(all_groups))
    affected: set[str] = set()
    for group in all_groups:
        current: Optional[str] = group
        while current is not None:
            if current in changed:
                affected.add(group)
                break
            current = model.parents.get(current)
    return tuple(sorted(affected))


def patchset_from_cleaner_plan(
    model: Any,
    plan: Any,
    *,
    panorama_host: str,
    panorama_username: str,
) -> PatchSet:
    """Convert typed planner structures directly; never parse rendered CLI."""

    specs: list[_Spec] = []

    for (key, field), removals in sorted(plan.rule_field_removals.items()):
        if key in plan.deleted_rules:
            continue
        rule = model.rules[key]
        for member, tokens in sorted(removals.items()):
            field_xpath = f"{rule.xpath}/{field}"
            target = f"{field_xpath}/member[text()={xpath_literal(member)}]"
            specs.append(
                _Spec(
                    "policy-member",
                    f"{_rule_key(key)}:{field}:{member}",
                    key.location,
                    target,
                    _member_xml(member),
                    None,
                    (MutationOperation(MutationAction.DELETE, target),),
                    (
                        MutationOperation(
                            MutationAction.SET, field_xpath, element=_member_xml(member)
                        ),
                    ),
                    _causes(tokens),
                )
            )

    # Original order is essential: rollback/restore executes mutations in
    # reverse, so a deleted rule's original next-rule is already present when
    # the move-before operation runs.
    deleted_rules = sorted(
        plan.deleted_rules,
        key=lambda key: (
            key.location,
            key.rulebase,
            key.policy_type,
            model.rules[key].order_index,
        ),
    )
    for key in deleted_rules:
        rule = model.rules[key]
        inverse = [
            MutationOperation(MutationAction.SET, parent_xpath(rule.xpath), element=rule.xml)
        ]
        if rule.next_rule:
            inverse.append(
                MutationOperation(
                    MutationAction.MOVE,
                    rule.xpath,
                    where="before",
                    destination=rule.next_rule,
                )
            )
        else:
            inverse.append(
                MutationOperation(MutationAction.MOVE, rule.xpath, where="bottom")
            )
        container_order = [
            candidate.name
            for candidate in sorted(
                (
                    item.key
                    for item in model.rules.values()
                    if item.key.location == key.location
                    and item.key.rulebase == key.rulebase
                    and item.key.policy_type == key.policy_type
                ),
                key=lambda candidate: model.rules[candidate].order_index,
            )
        ]
        specs.append(
            _Spec(
                "policy",
                _rule_key(key),
                key.location,
                rule.xpath,
                rule.xml,
                None,
                (MutationOperation(MutationAction.DELETE, rule.xpath),),
                tuple(inverse),
                _causes(plan.rule_causes.get(key, ())),
                rule.previous_rule,
                rule.next_rule,
                rule_order_names_sha256(
                    container_order, rule.previous_rule, rule.next_rule
                ),
            )
        )

    for key, removals in sorted(plan.group_member_removals.items()):
        if key in plan.deleted_groups:
            continue
        group = model.static_groups[key]
        static_xpath = f"{group.xpath}/static"
        for member, tokens in sorted(removals.items()):
            target = f"{static_xpath}/member[text()={xpath_literal(member)}]"
            specs.append(
                _Spec(
                    "group-member",
                    f"{_scoped_key(key)}:{member}",
                    key.location,
                    target,
                    _member_xml(member),
                    None,
                    (MutationOperation(MutationAction.DELETE, target),),
                    (
                        MutationOperation(
                            MutationAction.SET, static_xpath, element=_member_xml(member)
                        ),
                    ),
                    _causes(tokens),
                )
            )

    for key in _deleted_group_order(model, set(plan.deleted_groups)):
        group = model.static_groups[key]
        specs.append(
            _Spec(
                "group",
                _scoped_key(key),
                key.location,
                group.xpath,
                group.xml,
                None,
                (MutationOperation(MutationAction.DELETE, group.xpath),),
                (
                    MutationOperation(
                        MutationAction.SET, parent_xpath(group.xpath), element=group.xml
                    ),
                ),
                _causes(plan.group_causes.get(key, ())),
            )
        )

    token_by_address = {
        token.scoped_name: token
        for token in plan.active_tokens
        if token.kind == "address" and token.scoped_name is not None
    }
    for key in sorted(plan.deleted_addresses):
        address = model.addresses[key]
        token = token_by_address.get(key)
        if token is None:
            raise ValidationError(f"Brak TargetToken dla address {_scoped_key(key)}.")
        specs.append(
            _Spec(
                "address",
                _scoped_key(key),
                key.location,
                address.xpath,
                address.xml,
                None,
                (MutationOperation(MutationAction.DELETE, address.xpath),),
                (
                    MutationOperation(
                        MutationAction.SET, parent_xpath(address.xpath), element=address.xml
                    ),
                ),
                (token.ip,),
            )
        )

    component_by_cause = _components(specs) if specs else {}
    previous_by_component: dict[str, str] = {}
    mutations: list[Mutation] = []
    for index, spec in enumerate(specs, 1):
        component = component_by_cause[spec.causes[0]]
        mutation_id = f"mutation-{index:05d}"
        depends = (
            (previous_by_component[component],) if component in previous_by_component else ()
        )
        mutations.append(
            Mutation(
                mutation_id=mutation_id,
                component_id=component,
                entity_type=spec.entity_type,
                entity_key=spec.entity_key,
                target_xpath=spec.target_xpath,
                before_xml=spec.before_xml,
                after_xml=spec.after_xml,
                forward=spec.forward,
                inverse=spec.inverse,
                causes=spec.causes,
                depends_on=depends,
                order_previous=spec.order_previous,
                order_next=spec.order_next,
                order_context_sha256=spec.order_context_sha256,
            )
        )
        previous_by_component[component] = mutation_id

    active_ips = sorted({token.ip for token in plan.active_tokens})
    warning_list = list(plan.warnings)
    for ip, reasons in sorted(plan.blocked_ips.items()):
        warning_list.append(
            f"{ip} pominięty przez planner: "
            + "; ".join(f"{reason.code}: {reason.message}" for reason in reasons)
        )
    affected_groups = _expanded_device_groups(model, (spec.location for spec in specs))
    if any(spec.location == "shared" for spec in specs):
        warning_list.append(
            "Zmiana shared wymaga jawnego review pełnej listy widocznych potomnych DG przed push."
        )
    return PatchSet.new(
        kind="cleanup",
        panorama_host=panorama_host,
        panorama_username=panorama_username,
        mutations=mutations,
        targets=active_ips,
        affected_device_groups=affected_groups,
        warnings=warning_list,
    )


def build_cleanup_patchset(
    running_config: ET.Element,
    ips: Iterable[str],
    *,
    address_object_names: Iterable[str] = (),
    address_group_names: Iterable[str] = (),
    policy_names: Iterable[str] = (),
    panorama_host: str,
    panorama_username: str,
    nat_translation_action: str = "delete-rule",
) -> CleanerPlanResult:
    _legacy_root()
    from panorama_cleanup.models import BlockReason, TargetToken  # type: ignore[import-not-found]
    from panorama_cleanup.panos import match_ip_objects, parse_config  # type: ignore[import-not-found]
    from panorama_cleanup.planner import (  # type: ignore[import-not-found]
        build_target_tokens,
        plan_cleanup_targets,
    )

    normalized = tuple(dict.fromkeys(ips))
    object_names = tuple(dict.fromkeys(address_object_names))
    group_names = tuple(dict.fromkeys(address_group_names))
    rule_names = tuple(dict.fromkeys(policy_names))
    model = parse_config(running_config)
    warnings, blockers = _completeness_findings(model, running_config)
    model.warnings.extend(item for item in warnings if item not in model.warnings)
    if blockers:
        raise ValidationError(
            "Snapshot nie pozwala na kompletny bezpieczny plan: " + "; ".join(blockers)
        )
    matches = match_ip_objects(model, normalized)
    tokens = build_target_tokens(matches, normalized)
    forced_groups: dict[Any, Any] = {}
    forced_rules: dict[Any, Any] = {}
    discovery: dict[str, dict[str, Any]] = {}
    target_order = tuple(
        [*normalized]
        + [f"object:{name}" for name in object_names]
        + [f"group:{name}" for name in group_names]
        + [f"policy:{name}" for name in rule_names]
    )

    for ip in normalized:
        discovery[ip] = {
            "kind": "ip",
            "label": ip,
            "status": "found" if matches[ip].exact_objects else "not-found",
            "matches": [
                {"location": key.location, "name": key.name, "entity_type": "address"}
                for key in matches[ip].exact_objects
            ],
        }

    for name in object_names:
        cause = f"object:{name}"
        found = sorted(key for key in model.addresses if key.name == name)
        token_records = [TargetToken.address(cause, key) for key in found]
        tokens.update(token_records)
        discovery[cause] = {
            "kind": "address-object",
            "label": name,
            "status": "found" if found else "not-found",
            "matches": [
                {"location": key.location, "name": key.name, "entity_type": "address"}
                for key in found
            ],
        }

    unsupported: dict[str, list[Any]] = {}
    for name in group_names:
        cause = f"group:{name}"
        static = sorted(key for key in model.static_groups if key.name == name)
        dynamic = sorted(key for key in model.dynamic_groups if key.name == name)
        token = TargetToken("group", cause, name=name)
        if dynamic:
            unsupported[cause] = dynamic
        elif static:
            tokens.add(token)
            forced_groups.update({key: token for key in static})
        discovery[cause] = {
            "kind": "address-group",
            "label": name,
            "status": "unsupported-dynamic" if dynamic else "found" if static else "not-found",
            "matches": [
                {
                    "location": key.location,
                    "name": key.name,
                    "entity_type": "dynamic-address-group" if key in model.dynamic_groups else "address-group",
                }
                for key in [*static, *dynamic]
            ],
        }

    for name in rule_names:
        cause = f"policy:{name}"
        found = sorted(key for key in model.rules if key.name == name)
        token = TargetToken("policy", cause, name=name)
        if found:
            tokens.add(token)
            forced_rules.update({key: token for key in found})
        discovery[cause] = {
            "kind": "policy",
            "label": name,
            "status": "found" if found else "not-found",
            "matches": [
                {
                    "location": key.location,
                    "rulebase": key.rulebase,
                    "policy_type": key.policy_type,
                    "name": key.name,
                    "entity_type": "policy",
                }
                for key in found
            ],
        }

    plan = plan_cleanup_targets(
        model,
        tokens,
        forced_groups=forced_groups,
        forced_rules=forced_rules,
        nat_translation_action=nat_translation_action,
    )

    # Application Override rules are commonly inherited/read-only on Panorama.
    # Never let one such reference fail halfway through a candidate batch.  A
    # target touching App Override is reported as blocked and the planner is
    # rerun without its complete dependency component.
    app_override_paths: dict[Any, set[str]] = {}
    for key in plan.deleted_rules:
        if key.policy_type != "application-override":
            continue
        for target in plan.rule_causes.get(key, ()):
            app_override_paths.setdefault(target, set()).add(model.rules[key].xpath)
    for (key, _field), removals in plan.rule_field_removals.items():
        if key.policy_type != "application-override":
            continue
        for affected_tokens in removals.values():
            for target in affected_tokens:
                app_override_paths.setdefault(target, set()).add(model.rules[key].xpath)

    if app_override_paths:
        blocked_tokens = set(app_override_paths)
        plan = plan_cleanup_targets(
            model,
            set(tokens) - blocked_tokens,
            forced_groups={
                key: target
                for key, target in forced_groups.items()
                if target not in blocked_tokens
            },
            forced_rules={
                key: target
                for key, target in forced_rules.items()
                if target not in blocked_tokens and key.policy_type != "application-override"
            },
            nat_translation_action=nat_translation_action,
        )
        for target, paths in sorted(app_override_paths.items(), key=lambda item: item[0].ip):
            plan.blocked_ips[target.ip] = [
                BlockReason(
                    "APP_OVERRIDE_READ_ONLY",
                    "Znaleziono zależność Application Override. Reguła może być "
                    "dziedziczona/read-only, dlatego Toolbox nie wykonuje automatycznej "
                    "mutacji ani usunięcia powiązanego celu.",
                    sorted(paths)[0],
                )
            ]
        plan.warnings.append(
            "Application Override wykryty: powiązane cele zablokowano przed zapisem "
            "candidate; wymagany ręczny review właściciela reguły."
        )
        for cause, record in discovery.items():
            if cause in {target.ip for target in blocked_tokens}:
                record["status"] = "blocked-app-override"

    for cause, keys in unsupported.items():
        plan.blocked_ips[cause] = [
            BlockReason(
                "DYNAMIC_GROUP_DELETE_REQUIRES_REVIEW",
                "Dynamic address group nie jest automatycznie usuwana; wymagany review filtra i runtime membership.",
                model.dynamic_groups[keys[0]].xpath,
            )
        ]
    patchset = patchset_from_cleaner_plan(
        model,
        plan,
        panorama_host=panorama_host,
        panorama_username=panorama_username,
    )
    return CleanerPlanResult(
        patchset,
        model,
        plan,
        matches,
        plan.blocked_ips,
        discovery,
        target_order,
    )
