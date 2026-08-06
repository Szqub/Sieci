"""Deterministic cumulative dependency planning for Panorama cleanup."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import DefaultDict, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from .models import (
    BatchPlan,
    BlockReason,
    ConfigModel,
    IPMatch,
    ResolvedReference,
    RuleKey,
    ScopedName,
    TargetToken,
    UnknownOccurrence,
    UnsafePlanError,
)
from .panos import (
    address_literal_relation,
    evaluate_dynamic_filter,
    resolve_occurrence,
    resolve_name,
    scope_chain,
    static_group_cycle_nodes,
)


@dataclass
class _ComputedPlan:
    group_member_removals: Dict[ScopedName, Dict[str, Set[TargetToken]]]
    deleted_groups: Set[ScopedName]
    group_causes: Dict[ScopedName, Set[TargetToken]]
    rule_field_removals: Dict[Tuple[RuleKey, str], Dict[str, Set[TargetToken]]]
    deleted_rules: Set[RuleKey]
    rule_causes: Dict[RuleKey, Set[TargetToken]]
    blockers: Dict[str, List[BlockReason]]


NAT_TRANSLATION_FIELDS = {
    "source-translation",
    "destination-translation",
    "dynamic-destination-translation",
}


def _is_nat_translation_occurrence(
    model: ConfigModel, occurrence: UnknownOccurrence
) -> bool:
    owner = occurrence.owner_rule
    if owner is None or owner.policy_type != "nat":
        return False
    rule = model.rules.get(owner)
    if rule is None:
        return False
    prefix = rule.xpath.rstrip("/") + "/"
    if not occurrence.configuration_path.startswith(prefix):
        return False
    relative_path = occurrence.configuration_path[len(prefix):]
    root_field = relative_path.split("/", 1)[0]
    return root_field in NAT_TRANSLATION_FIELDS


def _add_reason(
    blockers: Dict[str, List[BlockReason]],
    tokens: Iterable[TargetToken],
    code: str,
    message: str,
    path: Optional[str] = None,
) -> None:
    reason = BlockReason(code, message, path)
    for ip in sorted({token.ip for token in tokens}):
        existing = blockers.setdefault(ip, [])
        if not any(
            item.code == reason.code
            and item.message == reason.message
            and item.path == reason.path
            for item in existing
        ):
            existing.append(reason)


def build_target_tokens(
    matches: Mapping[str, IPMatch], eligible_ips: Iterable[str]
) -> Set[TargetToken]:
    tokens: Set[TargetToken] = set()
    for ip in sorted(set(eligible_ips)):
        match = matches[ip]
        for key in match.exact_objects:
            tokens.add(TargetToken.address(ip, key))
        # Direct IP literals in policies/groups are dependencies even when no
        # address object definition exists.
        tokens.add(TargetToken.literal(ip))
    return tokens


def plan_cleanup(
    model: ConfigModel,
    matches: Mapping[str, IPMatch],
    eligible_ips: Iterable[str],
    *,
    nat_translation_action: str = "delete-rule",
) -> BatchPlan:
    """Create a global plan and atomically block unsafe IPs until convergence."""

    if nat_translation_action not in {"block", "delete-rule"}:
        raise ValueError("nat_translation_action must be block or delete-rule")
    return plan_cleanup_targets(
        model,
        build_target_tokens(matches, eligible_ips),
        nat_translation_action=nat_translation_action,
    )


def plan_cleanup_targets(
    model: ConfigModel,
    tokens: Iterable[TargetToken],
    *,
    forced_groups: Optional[Mapping[ScopedName, TargetToken]] = None,
    forced_rules: Optional[Mapping[RuleKey, TargetToken]] = None,
    nat_translation_action: str = "delete-rule",
) -> BatchPlan:
    """Plan an atomic mixed batch of IP, object, group and policy targets."""

    if nat_translation_action not in {"block", "delete-rule"}:
        raise ValueError("nat_translation_action must be block or delete-rule")
    all_tokens = set(tokens)
    all_forced_groups = dict(forced_groups or {})
    all_forced_rules = dict(forced_rules or {})
    active_tokens = set(all_tokens)
    blocked_ips: Dict[str, List[BlockReason]] = {}

    for _ in range(len({token.ip for token in all_tokens}) + 2):
        computed = _compute_plan(
            model,
            active_tokens,
            nat_translation_action,
            forced_groups={
                key: token
                for key, token in all_forced_groups.items()
                if token in active_tokens
            },
            forced_rules={
                key: token
                for key, token in all_forced_rules.items()
                if token in active_tokens
            },
        )
        newly_blocked = {
            ip: reasons
            for ip, reasons in computed.blockers.items()
            if ip not in blocked_ips
        }
        if not newly_blocked:
            _validate_final_plan(model, active_tokens, computed)
            impacts = _dynamic_group_impacts(model, active_tokens)
            return BatchPlan(
                active_tokens=active_tokens,
                blocked_ips=blocked_ips,
                group_member_removals=computed.group_member_removals,
                deleted_groups=computed.deleted_groups,
                group_causes=computed.group_causes,
                rule_field_removals=computed.rule_field_removals,
                deleted_rules=computed.deleted_rules,
                rule_causes=computed.rule_causes,
                deleted_addresses={
                    token.scoped_name
                    for token in active_tokens
                    if token.kind == "address" and token.scoped_name is not None
                },
                dynamic_group_impacts=impacts,
                warnings=list(model.warnings),
            )
        for ip, reasons in sorted(newly_blocked.items()):
            blocked_ips[ip] = sorted(
                reasons, key=lambda item: (item.code, item.path or "", item.message)
            )
        active_tokens = {token for token in active_tokens if token.ip not in blocked_ips}

    raise UnsafePlanError("Plan blokad nie osiągnął punktu stałego.")


def _token_maps(
    active_tokens: Set[TargetToken],
) -> Tuple[Dict[ScopedName, TargetToken], Dict[str, TargetToken]]:
    address_tokens: Dict[ScopedName, TargetToken] = {}
    literal_tokens: Dict[str, TargetToken] = {}
    for token in active_tokens:
        if token.kind == "address" and token.scoped_name is not None:
            address_tokens[token.scoped_name] = token
        elif token.kind == "literal":
            literal_tokens[token.ip] = token
    return address_tokens, literal_tokens


def _reference_tokens(
    ref: ResolvedReference,
    address_tokens: Mapping[ScopedName, TargetToken],
    literal_tokens: Mapping[str, TargetToken],
    deleted_groups: Set[ScopedName],
    group_causes: Mapping[ScopedName, Set[TargetToken]],
) -> Set[TargetToken]:
    if ref.resolved_kind == "address" and ref.resolved_key in address_tokens:
        return {address_tokens[ref.resolved_key]}
    if ref.resolved_kind == "literal" and ref.detail in literal_tokens:
        return {literal_tokens[ref.detail]}
    if ref.resolved_kind == "static-group" and ref.resolved_key in deleted_groups:
        return set(group_causes.get(ref.resolved_key, set()))
    return set()


def _descendant_contexts(model: ConfigModel, location: str) -> Tuple[str, ...]:
    contexts = [location]
    for candidate in sorted(model.parents):
        if candidate != location and location in scope_chain(model, candidate):
            contexts.append(candidate)
    return tuple(contexts)


def _reference_contexts(
    model: ConfigModel, ref: ResolvedReference
) -> Tuple[str, ...]:
    contexts: List[str] = []
    for context in _descendant_contexts(model, ref.owner_location):
        if ref.owner_group is not None:
            kind, owner, _ = resolve_name(model, context, ref.owner_group.name)
            if kind != "static-group" or owner != ref.owner_group:
                continue
        contexts.append(context)
    return tuple(contexts)


def _resolution_tokens(
    model: ConfigModel,
    context: str,
    value: str,
    address_tokens: Mapping[ScopedName, TargetToken],
    literal_tokens: Mapping[str, TargetToken],
    deleted_groups: Set[ScopedName],
    group_causes: Mapping[ScopedName, Set[TargetToken]],
) -> Set[TargetToken]:
    kind, resolved, detail = resolve_name(model, context, value)
    if kind == "address" and resolved in address_tokens:
        return {address_tokens[resolved]}
    if kind == "literal" and detail in literal_tokens:
        return {literal_tokens[detail]}
    if kind == "static-group" and resolved in deleted_groups:
        return set(group_causes.get(resolved, set()))
    return set()


def _effective_group_causes(
    model: ConfigModel,
    address_tokens: Mapping[ScopedName, TargetToken],
    literal_tokens: Mapping[str, TargetToken],
) -> Dict[Tuple[str, ScopedName], Set[TargetToken]]:
    """Expand target membership of static groups separately per effective scope."""

    affected: Dict[Tuple[str, ScopedName], Set[TargetToken]] = {}
    contexts_by_group: Dict[ScopedName, Tuple[str, ...]] = {}
    for group_key in sorted(model.static_groups):
        contexts = tuple(
            context
            for context in _descendant_contexts(model, group_key.location)
            if _resolves_to(
                model, context, group_key.name, "static-group", group_key
            )
        )
        contexts_by_group[group_key] = contexts
        for context in contexts:
            affected[(context, group_key)] = set()

    for _ in range(len(model.static_groups) + 1):
        changed = False
        for owner, refs in sorted(model.group_references.items()):
            for context in contexts_by_group.get(owner, ()):
                owner_causes = affected[(context, owner)]
                before = len(owner_causes)
                for ref in refs:
                    kind, resolved, detail = resolve_name(
                        model, context, ref.referenced_name
                    )
                    if kind == "address" and resolved in address_tokens:
                        owner_causes.add(address_tokens[resolved])
                    elif kind == "literal" and detail in literal_tokens:
                        owner_causes.add(literal_tokens[detail])
                    elif kind == "static-group" and resolved is not None:
                        owner_causes.update(affected.get((context, resolved), set()))
                if len(owner_causes) != before:
                    changed = True
        if not changed:
            return {key: causes for key, causes in affected.items() if causes}
    raise UnsafePlanError(
        "Ekspansja effective-scope grup statycznych nie osiągnęła punktu stałego."
    )


def _occurrence_resolution_tokens(
    model: ConfigModel,
    context: str,
    value: str,
    address_tokens: Mapping[ScopedName, TargetToken],
    literal_tokens: Mapping[str, TargetToken],
    deleted_groups: Set[ScopedName],
    group_causes: Mapping[ScopedName, Set[TargetToken]],
    effective_group_causes: Mapping[
        Tuple[str, ScopedName], Set[TargetToken]
    ],
) -> Set[TargetToken]:
    kind, resolved, detail = resolve_name(model, context, value)
    if kind == "static-group" and resolved is not None:
        effective = effective_group_causes.get((context, resolved), set())
        if effective:
            return set(effective)
    if kind == "address" and resolved in address_tokens:
        return {address_tokens[resolved]}
    if kind == "literal" and detail in literal_tokens:
        return {literal_tokens[detail]}
    if kind == "static-group" and resolved in deleted_groups:
        return set(group_causes.get(resolved, set()))
    return set()


def _resolves_to(
    model: ConfigModel,
    context: str,
    value: str,
    expected_kind: str,
    expected_key: ScopedName,
) -> bool:
    kind, resolved, _ = resolve_name(model, context, value)
    return kind == expected_kind and resolved == expected_key


def _containing_literal_tokens(
    model: ConfigModel,
    context: str,
    value: str,
    literal_tokens: Mapping[str, TargetToken],
) -> Set[TargetToken]:
    kind, _, _ = resolve_name(model, context, value)
    if kind != "unresolved":
        return set()
    return {
        token
        for ip, token in literal_tokens.items()
        if address_literal_relation(value, ip) == "containing"
    }


def _audit_effective_scope_references(
    model: ConfigModel,
    *,
    address_tokens: Mapping[ScopedName, TargetToken],
    literal_tokens: Mapping[str, TargetToken],
    deleted_groups: Set[ScopedName],
    group_causes: Dict[ScopedName, Set[TargetToken]],
    effective_group_causes: Mapping[
        Tuple[str, ScopedName], Set[TargetToken]
    ],
    group_removals: Dict[ScopedName, Dict[str, Set[TargetToken]]],
    deleted_rules: Set[RuleKey],
    rule_causes: Dict[RuleKey, Set[TargetToken]],
    field_removals: Dict[Tuple[RuleKey, str], Dict[str, Set[TargetToken]]],
    occurrence_removal_causes: Mapping[UnknownOccurrence, Set[TargetToken]],
    blockers: Dict[str, List[BlockReason]],
    directly_deleted_groups: Set[ScopedName],
    directly_deleted_rules: Set[RuleKey],
) -> None:
    """Fail closed when one physical mutation has different DG meanings."""

    all_refs = [
        ref
        for refs in list(model.group_references.values())
        + list(model.rule_references.values())
        for ref in refs
    ]
    for ref in all_refs:
        contexts = _reference_contexts(model, ref)
        context_causes = {
            context: _resolution_tokens(
                model,
                context,
                ref.referenced_name,
                address_tokens,
                literal_tokens,
                deleted_groups,
                group_causes,
            )
            for context in contexts
        }
        target_causes = set().union(*context_causes.values()) if context_causes else set()

        planned_causes: Optional[Set[TargetToken]] = None
        if ref.owner_group is not None:
            planned_causes = group_removals.get(ref.owner_group, {}).get(
                ref.referenced_name
            )
        elif ref.owner_rule is not None:
            planned_causes = field_removals.get(
                (ref.owner_rule, ref.field), {}
            ).get(ref.referenced_name)

        if ref.owner_group in directly_deleted_groups:
            group_causes.setdefault(ref.owner_group, set()).update(target_causes)
            continue
        if ref.owner_rule in directly_deleted_rules:
            rule_causes.setdefault(ref.owner_rule, set()).update(target_causes)
            continue

        containing = set()
        for context in contexts or (ref.owner_location,):
            containing.update(
                _containing_literal_tokens(
                    model, context, ref.referenced_name, literal_tokens
                )
            )
        if containing:
            _add_reason(
                blockers,
                containing,
                "CONTAINING_LITERAL_REFERENCE",
                f"{ref.owner_type} {ref.owner_name} zawiera szerszy literal "
                f"{ref.referenced_name}; pojedynczego IP nie można usunąć automatycznie.",
                ref.configuration_path,
            )

        if planned_causes is not None:
            if not contexts or any(not causes for causes in context_causes.values()):
                affected = set(planned_causes) | target_causes
                _add_reason(
                    blockers,
                    affected,
                    "OWNER_AFFECTS_NON_TARGET_OVERRIDE",
                    f"Zmiana {ref.owner_type} {ref.owner_name} dla nazwy "
                    f"{ref.referenced_name} miałaby inne znaczenie w co najmniej "
                    "jednym descendant device group.",
                    ref.configuration_path,
                )
            else:
                planned_causes.update(target_causes)
                if ref.owner_group is not None and ref.owner_group in deleted_groups:
                    group_causes.setdefault(ref.owner_group, set()).update(target_causes)
                if ref.owner_rule is not None and ref.owner_rule in deleted_rules:
                    rule_causes.setdefault(ref.owner_rule, set()).update(target_causes)
        elif target_causes:
            target_contexts = ",".join(
                context for context, causes in context_causes.items() if causes
            )
            _add_reason(
                blockers,
                target_causes,
                "INHERITED_OVERRIDE_REFERENCE",
                f"{ref.owner_type} {ref.owner_name} jest dziedziczony i w jednym "
                f"z effective scopes (effective_scope={target_contexts}) rozwiązuje "
                f"{ref.referenced_name} do usuwanej definicji; samo usunięcie "
                "override spowodowałoby fallback.",
                ref.configuration_path,
            )

    for occurrence in model.unknown_occurrences:
        contexts = _descendant_contexts(model, occurrence.location)
        context_causes = {
            context: _occurrence_resolution_tokens(
                model,
                context,
                occurrence.value,
                address_tokens,
                literal_tokens,
                deleted_groups,
                group_causes,
                effective_group_causes,
            )
            for context in contexts
        }
        target_causes = set().union(*context_causes.values()) if context_causes else set()
        containing = set()
        for context in contexts:
            containing.update(
                _containing_literal_tokens(
                    model, context, occurrence.value, literal_tokens
                )
            )
        if containing:
            _add_reason(
                blockers,
                containing,
                "CONTAINING_LITERAL_REFERENCE",
                f"{occurrence.owner_type} {occurrence.owner_name} zawiera szerszy "
                f"literal {occurrence.value}; wymagany manual review.",
                occurrence.configuration_path,
            )

        planned_causes = occurrence_removal_causes.get(occurrence)
        if planned_causes is not None:
            if any(not causes for causes in context_causes.values()):
                _add_reason(
                    blockers,
                    set(planned_causes) | target_causes,
                    "OWNER_AFFECTS_NON_TARGET_OVERRIDE",
                    f"Usunięcie {occurrence.owner_type} {occurrence.owner_name} "
                    "wpłynęłoby na nietargetową definicję w descendant scope.",
                    occurrence.configuration_path,
                )
            else:
                planned_causes.update(target_causes)
                if occurrence.owner_rule is not None:
                    rule_causes.setdefault(occurrence.owner_rule, set()).update(
                        target_causes
                    )
        elif occurrence.owner_rule in deleted_rules:
            rule_causes.setdefault(occurrence.owner_rule, set()).update(target_causes)
        else:
            owner_causes = context_causes.get(occurrence.location, set())
            inherited_causes = set().union(
                *(
                    causes
                    for context, causes in context_causes.items()
                    if context != occurrence.location
                )
            ) if len(context_causes) > 1 else set()
            inherited_causes.difference_update(owner_causes)
            if inherited_causes:
                target_contexts = ",".join(
                    context
                    for context, causes in context_causes.items()
                    if context != occurrence.location
                    and causes.intersection(inherited_causes)
                )
                _add_reason(
                    blockers,
                    inherited_causes,
                    "INHERITED_OVERRIDE_REFERENCE",
                    f"Dziedziczona {occurrence.owner_type} {occurrence.owner_name} "
                    f"odwołuje się do usuwanej definicji w "
                    f"effective_scope={target_contexts}.",
                    occurrence.configuration_path,
                )


def _propagate_plan_causes(
    model: ConfigModel,
    *,
    address_tokens: Mapping[ScopedName, TargetToken],
    literal_tokens: Mapping[str, TargetToken],
    deleted_groups: Set[ScopedName],
    group_causes: Dict[ScopedName, Set[TargetToken]],
    effective_group_causes: Mapping[
        Tuple[str, ScopedName], Set[TargetToken]
    ],
    group_removals: Dict[ScopedName, Dict[str, Set[TargetToken]]],
    deleted_rules: Set[RuleKey],
    rule_causes: Dict[RuleKey, Set[TargetToken]],
    field_removals: Dict[Tuple[RuleKey, str], Dict[str, Set[TargetToken]]],
    occurrence_removal_causes: Dict[UnknownOccurrence, Set[TargetToken]],
) -> None:
    """Propagate all batch IP causes through nested effective references."""

    max_passes = len(model.static_groups) + len(model.rules) + 2
    for _ in range(max_passes):
        before = sum(len(tokens) for tokens in group_causes.values()) + sum(
            len(tokens) for tokens in rule_causes.values()
        )
        before += sum(
            len(tokens)
            for removals in group_removals.values()
            for tokens in removals.values()
        )
        before += sum(
            len(tokens)
            for removals in field_removals.values()
            for tokens in removals.values()
        )

        for refs in list(model.group_references.values()) + list(
            model.rule_references.values()
        ):
            for ref in refs:
                planned: Optional[Set[TargetToken]] = None
                if ref.owner_group is not None:
                    planned = group_removals.get(ref.owner_group, {}).get(
                        ref.referenced_name
                    )
                elif ref.owner_rule is not None:
                    planned = field_removals.get(
                        (ref.owner_rule, ref.field), {}
                    ).get(ref.referenced_name)
                if planned is None:
                    continue
                for context in _reference_contexts(model, ref):
                    planned.update(
                        _resolution_tokens(
                            model,
                            context,
                            ref.referenced_name,
                            address_tokens,
                            literal_tokens,
                            deleted_groups,
                            group_causes,
                        )
                    )

        for group_key in deleted_groups:
            for causes in group_removals.get(group_key, {}).values():
                group_causes.setdefault(group_key, set()).update(causes)
        for rule_key in deleted_rules:
            for field in ("source", "destination"):
                for causes in field_removals.get((rule_key, field), {}).values():
                    rule_causes.setdefault(rule_key, set()).update(causes)
        for occurrence, planned in occurrence_removal_causes.items():
            for context in _descendant_contexts(model, occurrence.location):
                planned.update(
                    _occurrence_resolution_tokens(
                        model,
                        context,
                        occurrence.value,
                        address_tokens,
                        literal_tokens,
                        deleted_groups,
                        group_causes,
                        effective_group_causes,
                    )
                )
            if occurrence.owner_rule is not None:
                rule_causes.setdefault(occurrence.owner_rule, set()).update(planned)

        after = sum(len(tokens) for tokens in group_causes.values()) + sum(
            len(tokens) for tokens in rule_causes.values()
        )
        after += sum(
            len(tokens)
            for removals in group_removals.values()
            for tokens in removals.values()
        )
        after += sum(
            len(tokens)
            for removals in field_removals.values()
            for tokens in removals.values()
        )
        if after == before:
            return
    raise UnsafePlanError("Propagacja przyczyn planu nie osiągnęła punktu stałego.")


def _compute_plan(
    model: ConfigModel,
    active_tokens: Set[TargetToken],
    nat_translation_action: str,
    *,
    forced_groups: Optional[Mapping[ScopedName, TargetToken]] = None,
    forced_rules: Optional[Mapping[RuleKey, TargetToken]] = None,
) -> _ComputedPlan:
    address_tokens, literal_tokens = _token_maps(active_tokens)
    blockers: Dict[str, List[BlockReason]] = {}
    cycle_nodes = static_group_cycle_nodes(model)

    direct_group_removals: Dict[ScopedName, Dict[str, Set[TargetToken]]] = {}
    for group_key, refs in sorted(model.group_references.items()):
        removals: Dict[str, Set[TargetToken]] = {}
        for ref in refs:
            causes = _reference_tokens(
                ref, address_tokens, literal_tokens, set(), {}
            )
            if causes:
                removals.setdefault(ref.referenced_name, set()).update(causes)
            if (
                ref.resolved_kind == "ambiguous"
                and ref.resolved_key in address_tokens
            ):
                _add_reason(
                    blockers,
                    {address_tokens[ref.resolved_key]},
                    "AMBIGUOUS_REFERENCE",
                    f"Nazwa {ref.referenced_name} jest niejednoznaczna w grupie {group_key.location}/{group_key.name}.",
                    ref.configuration_path,
                )
        if removals:
            direct_group_removals[group_key] = removals

    deleted_groups: Set[ScopedName] = set(forced_groups or {})
    group_causes: Dict[ScopedName, Set[TargetToken]] = {
        key: {token} for key, token in (forced_groups or {}).items()
    }
    changed = True
    while changed:
        changed = False
        for group_key, group in sorted(model.static_groups.items()):
            if group_key in deleted_groups or not group.members:
                continue
            removed: Dict[str, Set[TargetToken]] = {
                member: set(causes)
                for member, causes in direct_group_removals.get(group_key, {}).items()
            }
            for ref in model.group_references.get(group_key, []):
                if (
                    ref.resolved_kind == "static-group"
                    and ref.resolved_key in deleted_groups
                ):
                    removed.setdefault(ref.referenced_name, set()).update(
                        group_causes[ref.resolved_key]
                    )
            if removed and all(member in removed for member in group.members):
                causes = set().union(*(removed[member] for member in group.members))
                deleted_groups.add(group_key)
                group_causes[group_key] = causes
                changed = True

    group_removals: Dict[ScopedName, Dict[str, Set[TargetToken]]] = {}
    for group_key, group in sorted(model.static_groups.items()):
        removals = {
            member: set(causes)
            for member, causes in direct_group_removals.get(group_key, {}).items()
        }
        for ref in model.group_references.get(group_key, []):
            if (
                ref.resolved_kind == "static-group"
                and ref.resolved_key in deleted_groups
            ):
                removals.setdefault(ref.referenced_name, set()).update(
                    group_causes[ref.resolved_key]
                )
        if removals:
            group_removals[group_key] = removals
            if group_key in cycle_nodes:
                _add_reason(
                    blockers,
                    set().union(*removals.values()),
                    "STATIC_GROUP_CYCLE",
                    f"Plan dotyka cyklicznej grupy {group_key.location}/{group_key.name}.",
                    model.static_groups[group_key].xpath,
                )

    effective_group_causes = _effective_group_causes(
        model, address_tokens, literal_tokens
    )

    field_removals: Dict[
        Tuple[RuleKey, str], Dict[str, Set[TargetToken]]
    ] = {}
    deleted_rules: Set[RuleKey] = set(forced_rules or {})
    independently_deleted_rules: Set[RuleKey] = set(forced_rules or {})
    rule_causes: Dict[RuleKey, Set[TargetToken]] = {
        key: {token} for key, token in (forced_rules or {}).items()
    }
    pending_negated: List[Tuple[RuleKey, str, Set[TargetToken], str]] = []

    for rule_key, rule in sorted(model.rules.items()):
        refs = model.rule_references.get(rule_key, [])
        by_field: Dict[str, Dict[str, Set[TargetToken]]] = {
            "source": {},
            "destination": {},
        }
        for ref in refs:
            causes = _reference_tokens(
                ref,
                address_tokens,
                literal_tokens,
                deleted_groups,
                group_causes,
            )
            if causes:
                by_field[ref.field].setdefault(ref.referenced_name, set()).update(causes)
            if (
                ref.resolved_kind == "ambiguous"
                and ref.resolved_key in address_tokens
            ):
                _add_reason(
                    blockers,
                    {address_tokens[ref.resolved_key]},
                    "AMBIGUOUS_REFERENCE",
                    f"Nazwa {ref.referenced_name} jest niejednoznaczna w regule {rule_key.name}.",
                    ref.configuration_path,
                )

        deletes_rule = False
        for field, original in (
            ("source", rule.source_members),
            ("destination", rule.destination_members),
        ):
            removals = by_field[field]
            if not removals:
                continue
            field_removals[(rule_key, field)] = removals
            remaining = [member for member in original if member not in removals]
            if not remaining:
                deletes_rule = True
                negated = rule.negate_source if field == "source" else rule.negate_destination
                if not negated:
                    independently_deleted_rules.add(rule_key)
        if deletes_rule:
            deleted_rules.add(rule_key)
            causes = set()
            for removals in by_field.values():
                for member_causes in removals.values():
                    causes.update(member_causes)
            rule_causes[rule_key] = causes
        for field, removals in by_field.items():
            if not removals:
                continue
            negated = rule.negate_source if field == "source" else rule.negate_destination
            if negated:
                pending_negated.append(
                    (
                        rule_key,
                        field,
                        set().union(*removals.values()),
                        f"{rule.xpath}/{field}",
                    )
                )

    # Exact occurrences in NAT translation and other address-bearing contexts
    # are intentionally not treated like source/destination list members.
    occurrence_causes: List[Tuple[UnknownOccurrence, Set[TargetToken]]] = []
    # A translation may keep referencing a static group after that group is
    # safely trimmed. Deleting the NAT rule in that case would break traffic
    # for non-target members that remain in the pool.
    group_cleanup_occurrences: Set[UnknownOccurrence] = set()
    for occurrence in model.unknown_occurrences:
        kind, resolved_key, detail = resolve_occurrence(model, occurrence)
        causes: Set[TargetToken] = set()
        if kind == "address" and resolved_key in address_tokens:
            causes.add(address_tokens[resolved_key])
        elif kind == "literal" and detail in literal_tokens:
            causes.add(literal_tokens[detail])
        elif kind == "static-group" and resolved_key is not None:
            if resolved_key in deleted_groups:
                causes.update(group_causes.get(resolved_key, set()))
            else:
                causes.update(
                    effective_group_causes.get(
                        (occurrence.location, resolved_key), set()
                    )
                )
            if (
                causes
                and resolved_key not in deleted_groups
                and nat_translation_action == "delete-rule"
                and _is_nat_translation_occurrence(model, occurrence)
            ):
                group_cleanup_occurrences.add(occurrence)
        if causes:
            occurrence_causes.append((occurrence, causes))

    occurrence_removal_causes: Dict[UnknownOccurrence, Set[TargetToken]] = {}
    if nat_translation_action == "delete-rule":
        for occurrence, causes in occurrence_causes:
            if occurrence in group_cleanup_occurrences:
                continue
            owner_rule = occurrence.owner_rule
            if (
                owner_rule is not None
                and _is_nat_translation_occurrence(model, occurrence)
            ):
                occurrence_removal_causes[occurrence] = set(causes)
                deleted_rules.add(owner_rule)
                independently_deleted_rules.add(owner_rule)
                rule_causes.setdefault(owner_rule, set()).update(causes)
                for field in ("source", "destination"):
                    for field_causes in field_removals.get((owner_rule, field), {}).values():
                        rule_causes[owner_rule].update(field_causes)

    _audit_effective_scope_references(
        model,
        address_tokens=address_tokens,
        literal_tokens=literal_tokens,
        deleted_groups=deleted_groups,
        group_causes=group_causes,
        effective_group_causes=effective_group_causes,
        group_removals=group_removals,
        deleted_rules=deleted_rules,
        rule_causes=rule_causes,
        field_removals=field_removals,
        occurrence_removal_causes=occurrence_removal_causes,
        blockers=blockers,
        directly_deleted_groups=set(forced_groups or {}),
        directly_deleted_rules=set(forced_rules or {}),
    )
    _propagate_plan_causes(
        model,
        address_tokens=address_tokens,
        literal_tokens=literal_tokens,
        deleted_groups=deleted_groups,
        group_causes=group_causes,
        effective_group_causes=effective_group_causes,
        group_removals=group_removals,
        deleted_rules=deleted_rules,
        rule_causes=rule_causes,
        field_removals=field_removals,
        occurrence_removal_causes=occurrence_removal_causes,
    )

    for rule_key, field, causes, path in pending_negated:
        if rule_key in deleted_rules and rule_key in independently_deleted_rules:
            rule_causes.setdefault(rule_key, set()).update(causes)
            continue
        _add_reason(
            blockers,
            causes,
            "NEGATED_FIELD_REQUIRES_REVIEW",
            f"Reguła {rule_key.location}/{rule_key.name} ma zanegowane pole {field}.",
            path,
        )

    for group_key, removals in group_removals.items():
        causes = set().union(*removals.values())
        for ref in model.group_references.get(group_key, []):
            if ref.supported_for_automatic_modification and ref.resolved_kind not in {
                "unresolved",
                "ambiguous",
            }:
                continue
            _add_reason(
                blockers,
                causes,
                "UNRESOLVED_GROUP_MEMBER",
                f"Dotknięta grupa {group_key.location}/{group_key.name} ma "
                f"nierozwiązywalny lub nieobsługiwany element {ref.referenced_name}.",
                ref.configuration_path,
            )

    for occurrence, causes in occurrence_causes:
        if occurrence.owner_rule in deleted_rules:
            if occurrence.owner_rule is not None:
                rule_causes.setdefault(occurrence.owner_rule, set()).update(causes)
            continue
        if occurrence in group_cleanup_occurrences:
            continue
        code = (
            "NAT_TRANSLATION_REFERENCE"
            if _is_nat_translation_occurrence(model, occurrence)
            else "UNSUPPORTED_REFERENCE"
        )
        _add_reason(
            blockers,
            causes,
            code,
            f"Nieobsługiwana automatycznie referencja w {occurrence.owner_type} {occurrence.owner_name}.",
            occurrence.configuration_path,
        )

    # Ambiguous values in known fields that point at a target definition must
    # also fail closed even if no supported removal could be built.
    for refs in list(model.group_references.values()) + list(model.rule_references.values()):
        for ref in refs:
            if ref.resolved_kind == "ambiguous" and ref.resolved_key in address_tokens:
                _add_reason(
                    blockers,
                    {address_tokens[ref.resolved_key]},
                    "AMBIGUOUS_REFERENCE",
                    f"Nie można jednoznacznie rozwiązać {ref.referenced_name}.",
                    ref.configuration_path,
                )

    dag_impacts = _dynamic_group_impacts(model, active_tokens)
    for group_key, object_keys in sorted(dag_impacts.items()):
        tokens = {
            address_tokens[key] for key in object_keys if key in address_tokens
        }
        downstream_rules = sorted(
            {
                rule_key
                for rule_key, refs in model.rule_references.items()
                for ref in refs
                if any(
                    _resolves_to(
                        model,
                        context,
                        ref.referenced_name,
                        "dynamic-group",
                        group_key,
                    )
                    for context in _reference_contexts(model, ref)
                )
            }
        )
        rules_text = ", ".join(
            f"{key.location}/{key.rulebase}/{key.policy_type}/{key.name}"
            for key in downstream_rules
        ) or "brak bezpośrednich reguł"
        _add_reason(
            blockers,
            tokens,
            "DYNAMIC_GROUP_MEMBERSHIP_REQUIRES_REVIEW",
            f"Obiekt może należeć do dynamic address group "
            f"{group_key.location}/{group_key.name}; running config nie dowodzi "
            f"runtime membership ani niepustości. Reguły DAG: {rules_text}.",
            model.dynamic_groups[group_key].xpath,
        )

    return _ComputedPlan(
        group_member_removals=group_removals,
        deleted_groups=deleted_groups,
        group_causes=group_causes,
        rule_field_removals=field_removals,
        deleted_rules=deleted_rules,
        rule_causes=rule_causes,
        blockers=blockers,
    )


def _validate_final_plan(
    model: ConfigModel,
    active_tokens: Set[TargetToken],
    plan: _ComputedPlan,
) -> None:
    address_tokens, literal_tokens = _token_maps(active_tokens)

    for group_key, removals in plan.group_member_removals.items():
        if group_key in plan.deleted_groups:
            continue
        original = model.static_groups[group_key].members
        remaining = [member for member in original if member not in removals]
        if not remaining:
            raise UnsafePlanError(
                f"Inwariant: zachowana grupa {group_key} zostałaby pusta."
            )

    for (rule_key, field), removals in plan.rule_field_removals.items():
        if rule_key in plan.deleted_rules:
            continue
        rule = model.rules[rule_key]
        original = rule.source_members if field == "source" else rule.destination_members
        remaining = [member for member in original if member not in removals]
        if not remaining:
            raise UnsafePlanError(
                f"Inwariant: zachowana reguła {rule_key} ma puste {field}."
            )

    for group_key, refs in model.group_references.items():
        if group_key in plan.deleted_groups:
            continue
        removed = plan.group_member_removals.get(group_key, {})
        for ref in refs:
            if ref.referenced_name in removed:
                continue
            if ref.resolved_kind == "address" and ref.resolved_key in address_tokens:
                raise UnsafePlanError(
                    f"Inwariant: grupa {group_key} nadal wskazuje usuwany obiekt {ref.resolved_key}."
                )
            if ref.resolved_kind == "static-group" and ref.resolved_key in plan.deleted_groups:
                raise UnsafePlanError(
                    f"Inwariant: grupa {group_key} nadal wskazuje usuwaną grupę {ref.resolved_key}."
                )
            if ref.resolved_kind == "literal" and ref.detail in literal_tokens:
                raise UnsafePlanError(
                    f"Inwariant: grupa {group_key} nadal wskazuje usuwany literal {ref.detail}."
                )

    for rule_key, refs in model.rule_references.items():
        if rule_key in plan.deleted_rules:
            continue
        for ref in refs:
            removed = plan.rule_field_removals.get((rule_key, ref.field), {})
            if ref.referenced_name in removed:
                continue
            if ref.resolved_kind == "address" and ref.resolved_key in address_tokens:
                raise UnsafePlanError(
                    f"Inwariant: reguła {rule_key} nadal wskazuje usuwany obiekt {ref.resolved_key}."
                )
            if ref.resolved_kind == "static-group" and ref.resolved_key in plan.deleted_groups:
                raise UnsafePlanError(
                    f"Inwariant: reguła {rule_key} nadal wskazuje usuwaną grupę {ref.resolved_key}."
                )
            if ref.resolved_kind == "literal" and ref.detail in literal_tokens:
                raise UnsafePlanError(
                    f"Inwariant: reguła {rule_key} nadal wskazuje usuwany literal {ref.detail}."
                )


def _dynamic_group_impacts(
    model: ConfigModel, active_tokens: Set[TargetToken]
) -> Dict[ScopedName, Set[ScopedName]]:
    address_keys = {
        token.scoped_name
        for token in active_tokens
        if token.kind == "address" and token.scoped_name is not None
    }
    impacts: Dict[ScopedName, Set[ScopedName]] = {}
    for group_key, group in sorted(model.dynamic_groups.items()):
        contexts = [
            context
            for context in _descendant_contexts(model, group_key.location)
            if _resolves_to(
                model, context, group_key.name, "dynamic-group", group_key
            )
        ]
        matched: Set[ScopedName] = set()
        for key in address_keys:
            if key not in model.addresses:
                continue
            effective_together = any(
                _resolves_to(model, context, key.name, "address", key)
                for context in contexts
            )
            if not effective_together:
                continue
            evaluation = evaluate_dynamic_filter(
                group.filter_text, model.addresses[key].tags
            )
            if evaluation is True or evaluation is None:
                matched.add(key)
        if matched:
            impacts[group_key] = matched
    return impacts


def dynamic_group_impacts_for_addresses(
    model: ConfigModel, address_keys: Iterable[ScopedName]
) -> Dict[ScopedName, Set[ScopedName]]:
    """Report configured-tag membership in dynamic groups for existing objects."""

    tokens = {
        TargetToken.address("", key)
        for key in set(address_keys)
        if key in model.addresses
    }
    return _dynamic_group_impacts(model, tokens)


def dependency_inventory(
    model: ConfigModel, address_key: ScopedName
) -> Tuple[Set[ScopedName], Set[RuleKey], List[str]]:
    """Return direct/indirect group and rule dependencies for reporting."""

    return dependency_inventories(model, [address_key])[address_key]


def dependency_inventories(
    model: ConfigModel, address_keys: Iterable[ScopedName]
) -> Dict[ScopedName, Tuple[Set[ScopedName], Set[RuleKey], List[str]]]:
    """Build reverse indexes once and report dependencies for many objects."""

    group_referrers: DefaultDict[ScopedName, List[Tuple[ScopedName, str]]] = defaultdict(list)
    rule_referrers: DefaultDict[ScopedName, List[Tuple[RuleKey, str]]] = defaultdict(list)
    for owner, refs in model.group_references.items():
        for ref in refs:
            for context in _reference_contexts(model, ref):
                kind, resolved, _ = resolve_name(
                    model, context, ref.referenced_name
                )
                if resolved is not None and kind in {"address", "static-group"}:
                    group_referrers[resolved].append(
                        (
                            owner,
                            f"{ref.configuration_path} [effective_scope={context}]",
                        )
                    )
    for owner, refs in model.rule_references.items():
        for ref in refs:
            for context in _reference_contexts(model, ref):
                kind, resolved, _ = resolve_name(
                    model, context, ref.referenced_name
                )
                if resolved is not None and kind in {"address", "static-group"}:
                    rule_referrers[resolved].append(
                        (
                            owner,
                            f"{ref.configuration_path} [effective_scope={context}]",
                        )
                    )

    unknown_paths: DefaultDict[ScopedName, List[Tuple[Optional[RuleKey], str]]] = defaultdict(list)
    for occurrence in model.unknown_occurrences:
        for context in _descendant_contexts(model, occurrence.location):
            kind, resolved, _ = resolve_name(model, context, occurrence.value)
            if kind in {"address", "static-group"} and resolved is not None:
                unknown_paths[resolved].append(
                    (
                        occurrence.owner_rule,
                        f"{occurrence.configuration_path} [effective_scope={context}]",
                    )
                )

    result: Dict[ScopedName, Tuple[Set[ScopedName], Set[RuleKey], List[str]]] = {}
    for address_key in sorted(set(address_keys)):
        groups: Set[ScopedName] = set()
        rules: Set[RuleKey] = set()
        paths: Set[str] = set()
        queue: deque[ScopedName] = deque()

        for owner, path in group_referrers.get(address_key, []):
            if owner not in groups:
                groups.add(owner)
                queue.append(owner)
            paths.add(path)
        for owner, path in rule_referrers.get(address_key, []):
            rules.add(owner)
            paths.add(path)
        for owner, path in unknown_paths.get(address_key, []):
            if owner is not None:
                rules.add(owner)
            paths.add(path)

        while queue:
            target_group = queue.popleft()
            for owner, path in group_referrers.get(target_group, []):
                if owner not in groups:
                    groups.add(owner)
                    queue.append(owner)
                paths.add(path)
            for owner, path in rule_referrers.get(target_group, []):
                rules.add(owner)
                paths.add(path)
            for owner, path in unknown_paths.get(target_group, []):
                if owner is not None:
                    rules.add(owner)
                paths.add(path)
        result[address_key] = (groups, rules, sorted(paths))
    return result
