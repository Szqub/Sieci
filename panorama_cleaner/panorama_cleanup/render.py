"""PAN-OS CLI command and rollback rendering."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Dict, Iterable, List, Sequence, Set, Tuple

from .models import (
    BatchPlan,
    CommandRecord,
    ConfigModel,
    RenderedPlan,
    RuleKey,
    ScopedName,
    TargetToken,
    UnsafePlanError,
)


def quote_cli(value: str) -> str:
    """Quote one PAN-OS CLI value; keywords are supplied separately."""

    if any(character in value for character in ("\x00", "\r", "\n")):
        raise UnsafePlanError("Nazwa lub wartość CLI zawiera niedozwolony znak sterujący.")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _scope_prefix(location: str) -> List[str]:
    if location == "shared":
        return ["shared"]
    return ["device-group", quote_cli(location)]


def _rule_path(key: RuleKey) -> List[str]:
    return _scope_prefix(key.location) + [
        key.rulebase,
        key.policy_type,
        "rules",
        quote_cli(key.name),
    ]


def _group_path(key: ScopedName) -> List[str]:
    return _scope_prefix(key.location) + ["address-group", quote_cli(key.name)]


def _address_path(key: ScopedName) -> List[str]:
    return _scope_prefix(key.location) + ["address", quote_cli(key.name)]


def _causes(tokens: Iterable[TargetToken]) -> Tuple[str, ...]:
    return tuple(sorted({token.ip for token in tokens}))


def _deleted_group_order(model: ConfigModel, deleted: Set[ScopedName]) -> List[ScopedName]:
    """Return referrers before referenced groups (parent before child)."""

    outgoing: Dict[ScopedName, Set[ScopedName]] = {key: set() for key in deleted}
    indegree: Dict[ScopedName, int] = {key: 0 for key in deleted}
    for owner in sorted(deleted):
        for ref in model.group_references.get(owner, []):
            target = ref.resolved_key
            if ref.resolved_kind == "static-group" and target in deleted:
                if target not in outgoing[owner]:
                    outgoing[owner].add(target)
                    indegree[target] += 1
    ready = sorted(key for key, degree in indegree.items() if degree == 0)
    result: List[ScopedName] = []
    while ready:
        node = ready.pop(0)
        result.append(node)
        for target in sorted(outgoing[node]):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
                ready.sort()
    if len(result) != len(deleted):
        raise UnsafePlanError("Nie można ustalić bezpiecznej kolejności usuwania grup (cykl).")
    return result


def render_plan(model: ConfigModel, plan: BatchPlan) -> RenderedPlan:
    """Render a validated plan into deterministic apply and inverse commands."""

    staged: List[Tuple[str, str, Tuple[str, ...], str, str]] = []

    for (rule_key, field), removals in sorted(plan.rule_field_removals.items()):
        if rule_key in plan.deleted_rules:
            continue
        for member, tokens in sorted(removals.items()):
            command = " ".join(["delete"] + _rule_path(rule_key) + [field, quote_cli(member)])
            staged.append(
                ("rule-member", command, _causes(tokens), "policy", _rule_key_text(rule_key))
            )

    for rule_key in sorted(plan.deleted_rules):
        tokens = plan.rule_causes.get(rule_key, set())
        command = " ".join(["delete"] + _rule_path(rule_key))
        staged.append(
            ("rule-delete", command, _causes(tokens), "policy", _rule_key_text(rule_key))
        )

    for group_key, removals in sorted(plan.group_member_removals.items()):
        if group_key in plan.deleted_groups:
            continue
        for member, tokens in sorted(removals.items()):
            command = " ".join(
                ["delete"] + _group_path(group_key) + ["static", quote_cli(member)]
            )
            staged.append(
                ("group-member", command, _causes(tokens), "group", _scoped_text(group_key))
            )

    group_order = _deleted_group_order(model, plan.deleted_groups)
    for group_key in group_order:
        tokens = plan.group_causes.get(group_key, set())
        command = " ".join(["delete"] + _group_path(group_key))
        staged.append(
            ("group-delete", command, _causes(tokens), "group", _scoped_text(group_key))
        )

    address_token_by_key = {
        token.scoped_name: token
        for token in plan.active_tokens
        if token.kind == "address" and token.scoped_name is not None
    }
    for address_key in sorted(plan.deleted_addresses):
        token = address_token_by_key[address_key]
        command = " ".join(["delete"] + _address_path(address_key))
        staged.append(
            (
                "address-delete",
                command,
                (token.ip,),
                "address",
                _scoped_text(address_key),
            )
        )

    seen: Dict[str, Tuple[str, str, Set[str], str]] = {}
    ordered_commands: List[str] = []
    for category, command, causes, entity_type, entity_key in staged:
        if command not in seen:
            seen[command] = (category, entity_type, set(causes), entity_key)
            ordered_commands.append(command)
        else:
            seen[command][2].update(causes)

    records: List[CommandRecord] = []
    for index, command in enumerate(ordered_commands, start=1):
        category, entity_type, causes, entity_key = seen[command]
        records.append(
            CommandRecord(
                command_id=f"CMD-{index:05d}",
                category=category,
                command=command,
                causes=tuple(sorted(causes)),
                entity_type=entity_type,
                entity_key=entity_key,
            )
        )

    rollback = _render_rollback(model, plan, group_order)
    return RenderedPlan(
        commands=records,
        rollback_commands=rollback,
        affected_addresses=set(plan.deleted_addresses),
        affected_groups=set(plan.group_member_removals) | set(plan.deleted_groups),
        affected_rules={key for key, _ in plan.rule_field_removals} | set(plan.deleted_rules),
    )


def _render_rollback(
    model: ConfigModel, plan: BatchPlan, deleted_group_order: Sequence[ScopedName]
) -> List[str]:
    commands: List[str] = []

    # Definitions must exist before groups and rules can reference them.
    for key in sorted(plan.deleted_addresses):
        commands.extend(_entry_to_set_commands(_address_path(key), model.addresses[key].xml))

    # Apply-time order is parent -> child. Restore in reverse: child -> parent.
    for key in reversed(deleted_group_order):
        commands.extend(_entry_to_set_commands(_group_path(key), model.static_groups[key].xml))

    for key, removals in sorted(plan.group_member_removals.items()):
        if key in plan.deleted_groups:
            continue
        for member in sorted(removals):
            commands.append(
                " ".join(["set"] + _group_path(key) + ["static", quote_cli(member)])
            )

    deleted_rules_sorted = sorted(
        plan.deleted_rules,
        key=lambda key: (
            key.location,
            key.rulebase,
            key.policy_type,
            model.rules[key].order_index,
            key.name,
        ),
    )
    for key in deleted_rules_sorted:
        commands.extend(_entry_to_set_commands(_rule_path(key), model.rules[key].xml))

    # Re-establish first-match order after all deleted rules have been recreated.
    for key in reversed(deleted_rules_sorted):
        rule = model.rules[key]
        base = _rule_path(key)
        if rule.next_rule:
            commands.append(
                " ".join(["move"] + base + ["before", quote_cli(rule.next_rule)])
            )
        elif rule.previous_rule:
            commands.append(
                " ".join(["move"] + base + ["after", quote_cli(rule.previous_rule)])
            )

    for (key, field), removals in sorted(plan.rule_field_removals.items()):
        if key in plan.deleted_rules:
            continue
        for member in sorted(removals):
            commands.append(
                " ".join(["set"] + _rule_path(key) + [field, quote_cli(member)])
            )

    deduplicated: List[str] = []
    seen: Set[str] = set()
    for command in commands:
        if command not in seen:
            seen.add(command)
            deduplicated.append(command)
    return deduplicated


def _entry_to_set_commands(base_path: Sequence[str], entry_xml: str) -> List[str]:
    """Convert a backed-up entry into reconstructive set commands."""

    try:
        entry = ET.fromstring(entry_xml)
    except ET.ParseError as exc:  # pragma: no cover - parser produced the XML
        raise UnsafePlanError(f"Nie można odtworzyć backupu XML: {exc}") from exc
    if entry.tag != "entry":
        raise UnsafePlanError("Backup encji nie zaczyna się od <entry>.")
    result: List[str] = []

    def walk(node: ET.Element, path: List[str]) -> None:
        children = list(node)
        if not children:
            text = (node.text or "").strip()
            if not text:
                # Presence-only nodes (for example NAT <none/> or nested
                # target <entry name="..."/>) are represented by the path.
                result.append(" ".join(["set"] + path))
                return
            result.append(" ".join(["set"] + path + [quote_cli(text)]))
            return
        for child in children:
            if child.tag == "entry":
                name = child.get("name")
                if not name:
                    raise UnsafePlanError("Zagnieżdżony entry bez nazwy w backupie.")
                walk(child, path + [quote_cli(name)])
            elif child.tag == "member":
                walk(child, path)
            else:
                walk(child, path + [child.tag])

    for child in list(entry):
        if child.tag == "member":
            walk(child, list(base_path))
        else:
            walk(child, list(base_path) + [child.tag])
    return result


def _scoped_text(key: ScopedName) -> str:
    return f"{key.location}/{key.name}"


def _rule_key_text(key: RuleKey) -> str:
    return f"{key.location}/{key.rulebase}/{key.policy_type}/{key.name}"
