"""PAN-OS XML parsing, scope resolution, and semantic snapshot helpers."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .models import (
    AddressObject,
    CandidateComparison,
    ConfigModel,
    DynamicGroup,
    IPMatch,
    ParseError,
    PolicyRule,
    ResolvedReference,
    RuleKey,
    ScopedName,
    SnapshotError,
    StaticGroup,
    UnknownOccurrence,
)

SHARED = "shared"
RULEBASES = ("pre-rulebase", "post-rulebase")
POLICY_TYPES = ("security", "nat", "application-override")
VOLATILE_ATTRIBUTES = {"admin", "dirtyId", "time", "last-modified"}
FREE_TEXT_TAGS = {"description", "audit-comment", "comments"}
ADDRESS_MEMBER_CONTAINERS = {
    "source",
    "destination",
    "source-address",
    "destination-address",
    "translated-address",
    "addresses",
    "excluded-address",
}


def _xml_text(element: ET.Element) -> str:
    clone = copy.deepcopy(element)
    try:
        ET.indent(clone, space="  ")
    except AttributeError:  # pragma: no cover - Python < 3.9 compatibility
        pass
    return ET.tostring(clone, encoding="unicode")


def _xpath_literal(value: str) -> str:
    """Quote an XPath attribute value without assuming it lacks apostrophes."""

    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    parts = value.split("'")
    joined: List[str] = []
    for index, part in enumerate(parts):
        if part:
            joined.append(f"'{part}'")
        if index != len(parts) - 1:
            joined.append('"\'"')
    return "concat(" + ",".join(joined) + ")"


def _members(entry: ET.Element, field: str) -> Tuple[str, ...]:
    values = []
    for node in entry.findall(f"./{field}/member"):
        if node.text is not None and node.text.strip():
            values.append(node.text.strip())
    return tuple(values)


def _yes(entry: ET.Element, field: str) -> bool:
    value = entry.findtext(f"./{field}")
    return bool(value and value.strip().lower() == "yes")


def _find_config_element(root: ET.Element) -> ET.Element:
    if root.tag == "config":
        return root
    config = root.find("./result/config")
    if config is None:
        config = root.find(".//config")
    if config is None:
        raise SnapshotError("Odpowiedź XML nie zawiera kompletnego elementu <config>.")
    return config


def safe_xml_fromstring(payload: bytes | str) -> ET.Element:
    """Parse XML with DTD, entities and external references disabled."""

    try:
        return SafeET.fromstring(
            payload,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except DefusedXmlException as exc:
        raise ET.ParseError(str(exc)) from exc


def parse_api_response(payload: bytes, *, expect_config: bool = False) -> ET.Element:
    """Parse and validate a complete PAN-OS XML API response."""

    if not payload or not payload.rstrip().endswith(b">"):
        raise SnapshotError("Odpowiedź Panoramy jest pusta lub ucięta.")
    try:
        root = safe_xml_fromstring(payload)
    except ET.ParseError as exc:
        raise SnapshotError(f"Niepoprawna lub ucięta odpowiedź XML: {exc}") from exc
    if root.tag == "response":
        status = root.get("status")
        if status != "success":
            message = " ".join(
                text.strip()
                for text in root.itertext()
                if text and text.strip()
            )
            raise SnapshotError(
                f"Panorama zwróciła status {status or 'brak'}: {message[:500]}"
            )
    if expect_config:
        return _find_config_element(root)
    return root


def _scope_xpath(device_entry_name: str, location: str) -> str:
    if location == SHARED:
        return "/config/shared"
    return (
        "/config/devices/entry[@name="
        + _xpath_literal(device_entry_name)
        + "]/device-group/entry[@name="
        + _xpath_literal(location)
        + "]"
    )


def parse_config(config: ET.Element) -> ConfigModel:
    """Parse the complete Panorama configuration into scoped typed entities."""

    if config.tag != "config":
        config = _find_config_element(config)

    addresses: Dict[ScopedName, AddressObject] = {}
    static_groups: Dict[ScopedName, StaticGroup] = {}
    dynamic_groups: Dict[ScopedName, DynamicGroup] = {}
    other_address_definitions: Dict[ScopedName, str] = {}
    rules: Dict[RuleKey, PolicyRule] = {}
    parents: Dict[str, Optional[str]] = {}
    warnings: List[str] = []

    device_entries = [
        entry
        for entry in config.findall("./devices/entry")
        if entry.find("./device-group") is not None
    ]
    if len(device_entries) > 1:
        names = ", ".join(entry.get("name", "?") for entry in device_entries)
        raise ParseError(
            "Konfiguracja zawiera device-group w więcej niż jednym devices/entry: " + names
        )
    device_entry = device_entries[0] if device_entries else None
    device_entry_name = device_entry.get("name", "localhost.localdomain") if device_entry is not None else "localhost.localdomain"

    precedence_values = []
    for value in (
        config.findtext(
            "./deviceconfig/setting/management/ancestor-objects-take-precedence"
        ),
        device_entry.findtext(
            "./deviceconfig/setting/management/ancestor-objects-take-precedence"
        )
        if device_entry is not None
        else None,
    ):
        if value and value.strip():
            precedence_values.append(value.strip().lower())
    if any(value not in {"yes", "no"} for value in precedence_values):
        raise ParseError(
            "Nieznana wartość deviceconfig/setting/management/"
            "ancestor-objects-take-precedence."
        )
    if len(set(precedence_values)) > 1:
        raise ParseError(
            "Sprzeczne wartości ancestor-objects-take-precedence w snapshotcie."
        )
    ancestor_objects_take_precedence = bool(
        precedence_values and precedence_values[0] == "yes"
    )

    scope_nodes: List[Tuple[str, ET.Element]] = []
    shared_node = config.find("./shared")
    if shared_node is not None:
        scope_nodes.append((SHARED, shared_node))
    else:
        warnings.append("Brak sekcji /config/shared w widocznej konfiguracji.")

    if device_entry is not None:
        for dg in device_entry.findall("./device-group/entry"):
            name = dg.get("name")
            if not name:
                raise ParseError("Device group bez atrybutu name.")
            if name == SHARED or name in parents:
                raise ParseError(f"Zduplikowana lub niedozwolona nazwa device group: {name}")
            parent = dg.findtext("./parent-dg")
            parents[name] = parent.strip() if parent and parent.strip() else None
            scope_nodes.append((name, dg))

    _validate_hierarchy(parents)

    skipped_definition_entries: Set[int] = set()
    handled_value_nodes: Set[int] = set()
    rule_entry_keys: Dict[int, RuleKey] = {}
    group_entry_keys: Dict[int, ScopedName] = {}

    for location, scope in scope_nodes:
        scope_xpath = _scope_xpath(device_entry_name, location)
        address_container = scope.find("./address")
        if address_container is not None:
            for entry in address_container.findall("./entry"):
                name = entry.get("name")
                if not name:
                    raise ParseError(f"Obiekt address bez nazwy w {location}.")
                key = ScopedName(location, name)
                if key in addresses:
                    raise ParseError(f"Zduplikowany obiekt address {location}/{name}.")
                typed_children = [
                    child
                    for child in list(entry)
                    if child.tag in {"ip-netmask", "ip-range", "fqdn", "ip-wildcard"}
                ]
                if len(typed_children) != 1:
                    raise ParseError(
                        f"Obiekt {location}/{name} ma {len(typed_children)} obsługiwanych typów zamiast jednego."
                    )
                value_node = typed_children[0]
                raw_value = (value_node.text or "").strip()
                if not raw_value:
                    raise ParseError(f"Obiekt {location}/{name} ma pustą wartość.")
                tags = tuple(
                    member.text.strip()
                    for member in entry.findall("./tag/member")
                    if member.text and member.text.strip()
                )
                xpath = f"{scope_xpath}/address/entry[@name={_xpath_literal(name)}]"
                addresses[key] = AddressObject(
                    key=key,
                    object_type=value_node.tag,
                    raw_value=raw_value,
                    tags=tags,
                    xml=_xml_text(entry),
                    xpath=xpath,
                )
                skipped_definition_entries.add(id(entry))

        group_container = scope.find("./address-group")
        if group_container is not None:
            for entry in group_container.findall("./entry"):
                name = entry.get("name")
                if not name:
                    raise ParseError(f"Address-group bez nazwy w {location}.")
                key = ScopedName(location, name)
                if key in addresses:
                    raise ParseError(
                        f"Kolizja namespace w {location}: {name} jest jednocześnie address i address-group."
                    )
                if key in static_groups or key in dynamic_groups:
                    raise ParseError(f"Zduplikowana address-group {location}/{name}.")
                static = entry.find("./static")
                dynamic = entry.find("./dynamic")
                if static is not None and dynamic is not None:
                    raise ParseError(f"Grupa {location}/{name} jest jednocześnie static i dynamic.")
                xpath = f"{scope_xpath}/address-group/entry[@name={_xpath_literal(name)}]"
                tags = tuple(
                    member.text.strip()
                    for member in entry.findall("./tag/member")
                    if member.text and member.text.strip()
                )
                if static is not None:
                    members = tuple(
                        member.text.strip()
                        for member in static.findall("./member")
                        if member.text and member.text.strip()
                    )
                    static_groups[key] = StaticGroup(key, members, _xml_text(entry), xpath)
                    if not members:
                        warnings.append(
                            f"Zastano pustą statyczną grupę {location}/{name}; nie będzie sprzątana automatycznie."
                        )
                    for member in static.findall("./member"):
                        handled_value_nodes.add(id(member))
                elif dynamic is not None:
                    filter_text = (dynamic.findtext("./filter") or "").strip()
                    dynamic_groups[key] = DynamicGroup(
                        key, filter_text, tags, _xml_text(entry), xpath
                    )
                else:
                    raise ParseError(f"Grupa {location}/{name} nie ma static ani dynamic.")
                skipped_definition_entries.add(id(entry))
                group_entry_keys[id(entry)] = key

        for entry in scope.findall("./region/entry"):
            name = entry.get("name")
            if name:
                other_address_definitions[ScopedName(location, name)] = "region"
        for entry in scope.findall("./external-list/entry"):
            name = entry.get("name")
            if name and entry.find("./type/ip") is not None:
                other_address_definitions[
                    ScopedName(location, name)
                ] = "ip-external-list"

        for rulebase in RULEBASES:
            for policy_type in POLICY_TYPES:
                rules_container = scope.find(f"./{rulebase}/{policy_type}/rules")
                if rules_container is None:
                    continue
                entries = rules_container.findall("./entry")
                names = [entry.get("name") for entry in entries]
                for index, entry in enumerate(entries):
                    name = entry.get("name")
                    if not name:
                        raise ParseError(
                            f"Reguła {policy_type} bez nazwy w {location}/{rulebase}."
                        )
                    key = RuleKey(location, rulebase, policy_type, name)
                    if key in rules:
                        raise ParseError(f"Zduplikowana reguła {key}.")
                    source = _members(entry, "source")
                    destination = _members(entry, "destination")
                    if not source or not destination:
                        raise ParseError(
                            f"Reguła {location}/{rulebase}/{policy_type}/{name} ma puste source lub destination w running config."
                        )
                    for member in entry.findall("./source/member") + entry.findall("./destination/member"):
                        handled_value_nodes.add(id(member))
                    xpath = (
                        f"{scope_xpath}/{rulebase}/{policy_type}/rules/entry"
                        f"[@name={_xpath_literal(name)}]"
                    )
                    rules[key] = PolicyRule(
                        key=key,
                        uuid=entry.get("uuid"),
                        source_members=source,
                        destination_members=destination,
                        negate_source=_yes(entry, "negate-source"),
                        negate_destination=_yes(entry, "negate-destination"),
                        disabled=_yes(entry, "disabled"),
                        action=(entry.findtext("./action") or "").strip() or None,
                        xml=_xml_text(entry),
                        xpath=xpath,
                        order_index=index,
                        previous_rule=names[index - 1] if index > 0 else None,
                        next_rule=names[index + 1] if index + 1 < len(names) else None,
                    )
                    rule_entry_keys[id(entry)] = key

    model = ConfigModel(
        device_entry_name=device_entry_name,
        ancestor_objects_take_precedence=ancestor_objects_take_precedence,
        parents=parents,
        addresses=addresses,
        static_groups=static_groups,
        dynamic_groups=dynamic_groups,
        other_address_definitions=other_address_definitions,
        rules=rules,
        group_references={},
        rule_references={},
        unknown_occurrences=[],
        warnings=warnings,
    )
    model.group_references = _resolve_group_references(model)
    model.rule_references = _resolve_rule_references(model)
    model.unknown_occurrences = _scan_unknown_occurrences(
        scope_nodes,
        rule_entry_keys,
        rules,
        skipped_definition_entries,
        handled_value_nodes,
    )
    return model


def _validate_hierarchy(parents: Dict[str, Optional[str]]) -> None:
    for child, parent in parents.items():
        if parent == SHARED:
            parents[child] = None
            continue
        if parent and parent not in parents:
            raise ParseError(
                f"Device group {child} wskazuje niewidocznego rodzica {parent}."
            )
    for start in parents:
        seen: Set[str] = set()
        current: Optional[str] = start
        while current is not None:
            if current in seen:
                raise ParseError(f"Cykl hierarchii device group obejmuje {current}.")
            seen.add(current)
            current = parents.get(current)


def scope_chain(model: ConfigModel, location: str) -> Tuple[str, ...]:
    if location == SHARED:
        return (SHARED,)
    if location not in model.parents:
        raise ParseError(f"Nieznany scope referencji: {location}")
    chain: List[str] = []
    seen: Set[str] = set()
    current: Optional[str] = location
    while current is not None:
        if current in seen:
            raise ParseError(f"Cykl podczas rozwiązywania scope {location}.")
        seen.add(current)
        chain.append(current)
        current = model.parents[current]
    chain.append(SHARED)
    return tuple(chain)


def resolution_chain(model: ConfigModel, location: str) -> Tuple[str, ...]:
    """Return object lookup precedence for one effective device-group scope."""

    chain = scope_chain(model, location)
    if model.ancestor_objects_take_precedence:
        return tuple(reversed(chain))
    return chain


def normalize_host_literal(value: str) -> Optional[str]:
    """Return a canonical IP only when the literal denotes one exact host."""

    stripped = value.strip()
    if "-" in stripped:
        try:
            start_text, end_text = stripped.split("-", 1)
            start = ipaddress.ip_address(start_text.strip())
            end = ipaddress.ip_address(end_text.strip())
        except ValueError:
            return None
        if start == end:
            return str(start)
        return None
    if "/" in stripped:
        base_text, mask_text = stripped.split("/", 1)
        if mask_text.strip() == "0.0.0.0":  # nosec B104 - wildcard mask, not bind
            try:
                return str(ipaddress.IPv4Address(base_text.strip()))
            except ValueError:
                return None
    try:
        interface = ipaddress.ip_interface(stripped)
    except ValueError:
        return None
    if interface.network.prefixlen != interface.max_prefixlen:
        return None
    return str(interface.ip)


def address_literal_relation(value: str, target_ip: str) -> Optional[str]:
    """Return exact/containing when a raw address literal covers target_ip."""

    stripped = value.strip()
    try:
        target = ipaddress.ip_address(target_ip)
    except ValueError:
        return None

    if "-" in stripped:
        try:
            start_text, end_text = stripped.split("-", 1)
            start = ipaddress.ip_address(start_text.strip())
            end = ipaddress.ip_address(end_text.strip())
        except ValueError:
            return None
        if start.version != end.version or start.version != target.version:
            return None
        if int(start) > int(end) or not (int(start) <= int(target) <= int(end)):
            return None
        return "exact" if start == end == target else "containing"

    # PAN-OS serializes wildcard policy literals as base/dotted-wildcard. A
    # leading-zero dotted mask must be interpreted before ip_interface(),
    # which otherwise treats 0.0.0.0 as the IPv4 /0 netmask.
    if "/" in stripped:
        base_text, mask_text = stripped.split("/", 1)
        if "." in mask_text and mask_text.strip().split(".", 1)[0] == "0":
            try:
                base = ipaddress.IPv4Address(base_text.strip())
                wildcard = ipaddress.IPv4Address(mask_text.strip())
            except ValueError:
                return None
            if not isinstance(target, ipaddress.IPv4Address):
                return None
            wildcard_int = int(wildcard)
            if ((int(target) ^ int(base)) & (~wildcard_int & 0xFFFFFFFF)) != 0:
                return None
            return "exact" if wildcard_int == 0 and target == base else "containing"

    try:
        interface = ipaddress.ip_interface(stripped)
    except ValueError:
        # PAN-OS also accepts IPv4 wildcard literals (base/wildcard-mask) in
        # address-bearing policy fields. They are intentionally attempted only
        # when the value is not a valid CIDR/netmask literal.
        try:
            base_text, wildcard_text = stripped.split("/", 1)
            base = ipaddress.IPv4Address(base_text.strip())
            wildcard = ipaddress.IPv4Address(wildcard_text.strip())
        except ValueError:
            return None
        if not isinstance(target, ipaddress.IPv4Address):
            return None
        wildcard_int = int(wildcard)
        if ((int(target) ^ int(base)) & (~wildcard_int & 0xFFFFFFFF)) != 0:
            return None
        return "exact" if wildcard_int == 0 and target == base else "containing"
    if interface.version != target.version or target not in interface.network:
        return None
    if interface.network.prefixlen == interface.max_prefixlen and interface.ip == target:
        return "exact"
    return "containing"


def is_supported_address_literal(value: str) -> bool:
    """Return whether a token is a syntactically modeled IP/range/wildcard."""

    stripped = value.strip()
    if "-" in stripped:
        try:
            start_text, end_text = stripped.split("-", 1)
            start = ipaddress.ip_address(start_text.strip())
            end = ipaddress.ip_address(end_text.strip())
        except ValueError:
            return False
        return start.version == end.version and int(start) <= int(end)
    try:
        ipaddress.ip_interface(stripped)
        return True
    except ValueError:
        pass
    if "/" not in stripped:
        return False
    try:
        base_text, wildcard_text = stripped.split("/", 1)
        ipaddress.IPv4Address(base_text.strip())
        ipaddress.IPv4Address(wildcard_text.strip())
        return True
    except ValueError:
        return False


def resolve_name(
    model: ConfigModel, location: str, value: str
) -> Tuple[str, Optional[ScopedName], str]:
    """Resolve an address/group reference using nearest effective scope."""

    if value == "any":
        return "builtin", None, ""
    # A PAN-OS object can itself have an IP-looking name. Resolve definitions
    # first; only an otherwise unresolved token is treated as a raw literal.
    for scope in resolution_chain(model, location):
        key = ScopedName(scope, value)
        candidates: List[str] = []
        if key in model.addresses:
            candidates.append("address")
        if key in model.static_groups:
            candidates.append("static-group")
        if key in model.dynamic_groups:
            candidates.append("dynamic-group")
        if len(candidates) > 1:
            return "ambiguous", key, ",".join(candidates)
        if candidates:
            return candidates[0], key, ""
    literal = normalize_host_literal(value)
    if literal is not None:
        return "literal", None, literal
    return "unresolved", None, ""


def _resolve_group_references(
    model: ConfigModel,
) -> Dict[ScopedName, List[ResolvedReference]]:
    result: Dict[ScopedName, List[ResolvedReference]] = {}
    for key, group in sorted(model.static_groups.items()):
        refs: List[ResolvedReference] = []
        for member in group.members:
            kind, resolved, detail = resolve_name(model, key.location, member)
            refs.append(
                ResolvedReference(
                    owner_location=key.location,
                    owner_type="static-group",
                    owner_name=key.name,
                    configuration_path=f"{group.xpath}/static/member",
                    field="static",
                    referenced_name=member,
                    resolved_kind=kind,
                    resolved_key=resolved,
                    owner_group=key,
                    supported_for_automatic_modification=kind
                    in {"address", "static-group", "literal", "builtin"},
                    detail=detail,
                )
            )
        result[key] = refs
    return result


def _resolve_rule_references(
    model: ConfigModel,
) -> Dict[RuleKey, List[ResolvedReference]]:
    result: Dict[RuleKey, List[ResolvedReference]] = {}
    for key, rule in sorted(model.rules.items()):
        refs: List[ResolvedReference] = []
        for field, members in (
            ("source", rule.source_members),
            ("destination", rule.destination_members),
        ):
            for member in members:
                kind, resolved, detail = resolve_name(model, key.location, member)
                refs.append(
                    ResolvedReference(
                        owner_location=key.location,
                        owner_type=f"{key.policy_type}-rule",
                        owner_name=key.name,
                        configuration_path=f"{rule.xpath}/{field}/member",
                        field=field,
                        referenced_name=member,
                        resolved_kind=kind,
                        resolved_key=resolved,
                        owner_rule=key,
                        supported_for_automatic_modification=kind
                        in {
                            "address",
                            "static-group",
                            "dynamic-group",
                            "literal",
                            "builtin",
                        },
                        detail=detail,
                    )
                )
        result[key] = refs
    return result


def _scan_unknown_occurrences(
    scope_nodes: Sequence[Tuple[str, ET.Element]],
    rule_entry_keys: Dict[int, RuleKey],
    rules: Dict[RuleKey, PolicyRule],
    skipped_definition_entries: Set[int],
    handled_value_nodes: Set[int],
) -> List[UnknownOccurrence]:
    occurrences: List[UnknownOccurrence] = []

    def is_address_value_leaf(node: ET.Element, next_path: Tuple[str, ...]) -> bool:
        """Recognize only schema leaves that can contain an address value.

        A broad ancestor test is unsafe here: for example translated-port is
        below destination-translation but is not an address reference.
        """

        parent = next_path[-2] if len(next_path) >= 2 else ""
        if node.tag == "member" and parent in ADDRESS_MEMBER_CONTAINERS:
            return True
        if node.tag == "translated-address" and parent in {
            "destination-translation",
            "dynamic-destination-translation",
            "static-ip",
        }:
            return True
        # Source NAT can select one literal interface IP. This is address data,
        # unlike the sibling interface name and translated port fields.
        if node.tag in {"ip", "ipv6", "floating-ip"} and parent == "interface-address":
            return True
        return False

    def walk(
        location: str,
        node: ET.Element,
        path: Tuple[str, ...],
        owner_rule: Optional[RuleKey],
        rule_relative_path: Tuple[str, ...],
        unknown_rule_name: Optional[str],
        unknown_rule_type: Optional[str],
    ) -> None:
        if id(node) in skipped_definition_entries:
            return
        next_path = path + (node.tag,)
        entry_owner = rule_entry_keys.get(id(node))
        current_owner = entry_owner or owner_rule
        if entry_owner is not None:
            current_rule_relative_path: Tuple[str, ...] = ()
        elif current_owner is not None:
            current_rule_relative_path = rule_relative_path + (node.tag,)
        else:
            current_rule_relative_path = ()
        current_unknown_name = unknown_rule_name
        current_unknown_type = unknown_rule_type
        if node.tag == "entry" and path and path[-1] == "rules" and current_owner is None:
            current_unknown_name = node.get("name", "?")
            current_unknown_type = "/".join(path[-3:-1]) or "unknown-rule"

        children = list(node)
        text = (node.text or "").strip()
        if (
            not children
            and text
            and id(node) not in handled_value_nodes
            and node.tag not in FREE_TEXT_TAGS
            and (
                current_owner is not None
                or current_unknown_name is not None
            )
            and is_address_value_leaf(node, next_path)
        ):
            if current_owner is not None:
                owner_type = f"{current_owner.policy_type}-rule"
                owner_name = current_owner.name
            else:
                owner_type = current_unknown_type or "unknown-rule"
                owner_name = current_unknown_name or "?"
            configuration_path = "/" + "/".join(next_path)
            if current_owner is not None:
                configuration_path = (
                    rules[current_owner].xpath
                    + "/"
                    + "/".join(current_rule_relative_path)
                )
            occurrences.append(
                UnknownOccurrence(
                    location=location,
                    configuration_path=configuration_path,
                    value=text,
                    owner_type=owner_type,
                    owner_name=owner_name,
                    owner_rule=current_owner,
                )
            )
        for child in children:
            walk(
                location,
                child,
                next_path,
                current_owner,
                current_rule_relative_path,
                current_unknown_name,
                current_unknown_type,
            )

    for location, scope in scope_nodes:
        for child in list(scope):
            walk(location, child, ("config", location), None, (), None, None)
    return occurrences


def match_ip_objects(model: ConfigModel, ips: Iterable[str]) -> Dict[str, IPMatch]:
    normalized_ips = sorted({str(ipaddress.ip_address(ip)) for ip in ips})
    parsed_ips = {ip: ipaddress.ip_address(ip) for ip in normalized_ips}
    exact: Dict[str, List[ScopedName]] = {ip: [] for ip in normalized_ips}
    containing: Dict[str, List[ScopedName]] = {ip: [] for ip in normalized_ips}

    for key, obj in sorted(model.addresses.items()):
        if obj.object_type == "ip-netmask":
            try:
                interface = ipaddress.ip_interface(obj.raw_value)
            except ValueError:
                model.warnings.append(
                    f"Nie można zinterpretować ip-netmask {key.location}/{key.name}: {obj.raw_value}"
                )
                continue
            if interface.network.prefixlen == interface.max_prefixlen:
                value = str(interface.ip)
                if value in exact:
                    exact[value].append(key)
            else:
                for ip, parsed in parsed_ips.items():
                    if parsed.version == interface.version and parsed in interface.network:
                        containing[ip].append(key)
        elif obj.object_type == "ip-range":
            try:
                start_text, end_text = obj.raw_value.split("-", 1)
                start = ipaddress.ip_address(start_text.strip())
                end = ipaddress.ip_address(end_text.strip())
            except ValueError:
                model.warnings.append(
                    f"Nie można zinterpretować ip-range {key.location}/{key.name}: {obj.raw_value}"
                )
                continue
            if start.version != end.version or int(start) > int(end):
                model.warnings.append(
                    f"Niepoprawny ip-range {key.location}/{key.name}: {obj.raw_value}"
                )
                continue
            if start == end:
                value = str(start)
                if value in exact:
                    exact[value].append(key)
            else:
                for ip, parsed in parsed_ips.items():
                    if parsed.version == start.version and int(start) <= int(parsed) <= int(end):
                        containing[ip].append(key)
        elif obj.object_type == "ip-wildcard":
            try:
                base_text, wildcard_text = obj.raw_value.split("/", 1)
                base = ipaddress.IPv4Address(base_text.strip())
                wildcard = ipaddress.IPv4Address(wildcard_text.strip())
            except ValueError:
                model.warnings.append(
                    f"Nie można zinterpretować ip-wildcard {key.location}/{key.name}: {obj.raw_value}"
                )
                continue
            wildcard_int = int(wildcard)
            for ip, parsed in parsed_ips.items():
                if not isinstance(parsed, ipaddress.IPv4Address):
                    continue
                matches = (
                    (int(parsed) ^ int(base)) & (~wildcard_int & 0xFFFFFFFF)
                ) == 0
                if not matches:
                    continue
                if wildcard_int == 0 and parsed == base:
                    exact[ip].append(key)
                else:
                    containing[ip].append(key)

    fqdn_count = sum(
        1 for obj in model.addresses.values() if obj.object_type == "fqdn"
    )
    if fqdn_count:
        warning = (
            f"Snapshot zawiera {fqdn_count} obiektów FQDN; ich bieżących rozwiązań DNS "
            "nie można wiarygodnie przypisać do IP wyłącznie z running config."
        )
        if warning not in model.warnings:
            model.warnings.append(warning)

    return {
        ip: IPMatch(ip, tuple(sorted(exact[ip])), tuple(sorted(containing[ip])))
        for ip in normalized_ips
    }


def static_group_cycle_nodes(model: ConfigModel) -> Set[ScopedName]:
    graph: Dict[ScopedName, Set[ScopedName]] = defaultdict(set)
    for owner, refs in model.group_references.items():
        for ref in refs:
            if ref.resolved_kind == "static-group" and ref.resolved_key is not None:
                graph[owner].add(ref.resolved_key)

    nodes = set(model.static_groups)
    reverse_graph: Dict[ScopedName, Set[ScopedName]] = defaultdict(set)
    for owner, targets in graph.items():
        for target in targets:
            reverse_graph[target].add(owner)

    # Iterative Kosaraju avoids Python's recursion limit for deeply nested,
    # otherwise valid static-group chains.
    visited: Set[ScopedName] = set()
    finish_order: List[ScopedName] = []
    for start in sorted(nodes):
        if start in visited:
            continue
        visited.add(start)
        stack = [(start, iter(sorted(graph.get(start, set()))))]
        while stack:
            node, targets = stack[-1]
            try:
                target = next(targets)
            except StopIteration:
                stack.pop()
                finish_order.append(node)
                continue
            if target not in visited:
                visited.add(target)
                stack.append((target, iter(sorted(graph.get(target, set())))))

    cyclic: Set[ScopedName] = set()
    assigned: Set[ScopedName] = set()
    for start in reversed(finish_order):
        if start in assigned:
            continue
        component: Set[ScopedName] = set()
        component_stack = [start]
        assigned.add(start)
        while component_stack:
            node = component_stack.pop()
            component.add(node)
            for target in reverse_graph.get(node, set()):
                if target not in assigned:
                    assigned.add(target)
                    component_stack.append(target)
        if len(component) > 1 or start in graph.get(start, set()):
            cyclic.update(component)
    return cyclic


def evaluate_dynamic_filter(filter_text: str, object_tags: Iterable[str]) -> Optional[bool]:
    """Evaluate the common PAN-OS DAG boolean grammar; None means unknown."""

    token_pattern = re.compile(
        r"\s*(?:"
        r"(?P<paren>[()])|"
        r"'(?P<single>(?:\\.|[^'\\])*)'|"
        r'"(?P<double>(?:\\.|[^"\\])*)"|'
        r"(?P<bare>[^\s()]+)"
        r")",
        re.IGNORECASE,
    )
    tokens: List[Tuple[str, str]] = []
    position = 0
    while position < len(filter_text):
        match = token_pattern.match(filter_text, position)
        if not match:
            return None
        position = match.end()
        if match.lastgroup == "paren":
            value = match.group("paren") or ""
            tokens.append((value, value))
        else:
            value = next(
                (
                    match.group(name)
                    for name in ("single", "double", "bare")
                    if match.group(name) is not None
                ),
                "",
            )
            value = value.replace("\\'", "'").replace('\\"', '"')
            if match.lastgroup == "bare" and value.lower() in {"and", "or", "not"}:
                tokens.append(("op", value.lower()))
            else:
                tokens.append(("tag", value))
    if not tokens:
        return None

    tags = {tag.casefold() for tag in object_tags}
    index = 0

    def parse_atom() -> bool:
        nonlocal index
        if index >= len(tokens):
            raise ValueError
        kind, value = tokens[index]
        if kind == "tag":
            index += 1
            return value.casefold() in tags
        if kind == "(":
            index += 1
            result = parse_or()
            if index >= len(tokens) or tokens[index][0] != ")":
                raise ValueError
            index += 1
            return result
        raise ValueError

    def parse_not() -> bool:
        nonlocal index
        if index < len(tokens) and tokens[index] == ("op", "not"):
            index += 1
            return not parse_not()
        return parse_atom()

    def parse_and() -> bool:
        nonlocal index
        result = parse_not()
        while index < len(tokens) and tokens[index] == ("op", "and"):
            index += 1
            result = parse_not() and result
        return result

    def parse_or() -> bool:
        nonlocal index
        result = parse_and()
        while index < len(tokens) and tokens[index] == ("op", "or"):
            index += 1
            result = parse_and() or result
        return result

    try:
        result = parse_or()
    except ValueError:
        return None
    return result if index == len(tokens) else None


def _normalized_config_bytes(config: ET.Element, *, relevant_only: bool) -> bytes:
    if relevant_only:
        root = ET.Element("relevant-config")
        shared = config.find("./shared")
        if shared is not None:
            root.append(copy.deepcopy(shared))
        for device in config.findall("./devices/entry"):
            groups = device.find("./device-group")
            if groups is None:
                continue
            wrapper = ET.SubElement(root, "device", {"name": device.get("name", "")})
            wrapper.append(copy.deepcopy(groups))
            precedence = device.find(
                "./deviceconfig/setting/management/ancestor-objects-take-precedence"
            )
            if precedence is not None:
                settings = ET.SubElement(wrapper, "relevant-panorama-settings")
                settings.append(copy.deepcopy(precedence))
        root_precedence = config.find(
            "./deviceconfig/setting/management/ancestor-objects-take-precedence"
        )
        if root_precedence is not None:
            settings = ET.SubElement(root, "relevant-root-panorama-settings")
            settings.append(copy.deepcopy(root_precedence))
    else:
        root = copy.deepcopy(config)

    for node in root.iter():
        node.attrib = {
            key: value
            for key, value in sorted(node.attrib.items())
            if key not in VOLATILE_ATTRIBUTES
        }
        if node.text is not None and not node.text.strip():
            node.text = None
        if node.tail is not None and not node.tail.strip():
            node.tail = None
    return ET.tostring(root, encoding="utf-8", short_empty_elements=True)


def compare_configs(running: ET.Element, candidate: ET.Element) -> CandidateComparison:
    running_full = hashlib.sha256(
        _normalized_config_bytes(running, relevant_only=False)
    ).hexdigest()
    candidate_full = hashlib.sha256(
        _normalized_config_bytes(candidate, relevant_only=False)
    ).hexdigest()
    running_relevant = hashlib.sha256(
        _normalized_config_bytes(running, relevant_only=True)
    ).hexdigest()
    candidate_relevant = hashlib.sha256(
        _normalized_config_bytes(candidate, relevant_only=True)
    ).hexdigest()
    return CandidateComparison(
        different=running_full != candidate_full,
        full_running_sha256=running_full,
        full_candidate_sha256=candidate_full,
        relevant_running_sha256=running_relevant,
        relevant_candidate_sha256=candidate_relevant,
        relevant_different=running_relevant != candidate_relevant,
    )


def resolve_occurrence(
    model: ConfigModel, occurrence: UnknownOccurrence
) -> Tuple[str, Optional[ScopedName], str]:
    return resolve_name(model, occurrence.location, occurrence.value)
