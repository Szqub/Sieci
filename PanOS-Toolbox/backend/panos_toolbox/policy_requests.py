"""Parse ServiceNow-style network requests into safe PAN-OS create plans.

The input seen in the field is usually a mixture of JSON/Python repr blocks
and human-readable ``Passes ToDo`` lines.  This module intentionally keeps the
parser tolerant, but the output is strict: every generated value is validated,
every object is checked with a targeted XML API read, and writes are represented
as the normal durable ``PatchSet`` used by Candidate/Commit/Push.
"""

from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional

from .client import PanoramaReadClient
from .errors import InputError
from .models import Mutation, MutationAction, MutationOperation, PatchSet
from .xmlutil import parent_xpath, xpath_literal


_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")
_FLOW_SEPARATOR = re.compile(r"\s+->\s+")
_ALLOWED_RULEBASES = {"pre-rulebase", "post-rulebase"}
_ALLOWED_POLICY_TYPES = {"security", "nat", "application-override"}


@dataclass(frozen=True)
class RequestFlow:
    source: str
    destination: str
    service: str
    application: str = "any"
    duration: str = "bezterminowo"
    source_info: Mapping[str, Any] = field(default_factory=dict)
    destination_info: Mapping[str, Any] = field(default_factory=dict)
    device_group: str = "shared"
    rulebase: str = "pre-rulebase"
    policy_type: str = "security"
    source_zone: str = "any"
    destination_zone: str = "any"
    action: str = "allow"
    tags: tuple[str, ...] = ()
    description: str = ""
    policy_name: Optional[str] = None


@dataclass(frozen=True)
class ParsedPolicyRequest:
    flows: tuple[RequestFlow, ...]
    warnings: tuple[str, ...] = ()
    passes_done: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyCreationResult:
    patchset: PatchSet
    input_targets: Mapping[str, Any]
    inventory: Mapping[str, Any]
    warnings: tuple[str, ...]


def _clean_comments(value: str) -> str:
    """Remove ``//`` comments without damaging file:// inside quoted strings."""

    output: list[str] = []
    for line in value.splitlines():
        quote: Optional[str] = None
        escaped = False
        cut = len(line)
        for index, char in enumerate(line):
            if escaped:
                escaped = False
                continue
            if char == "\\" and quote:
                escaped = True
                continue
            if char in {"'", '"'}:
                if quote == char:
                    quote = None
                elif quote is None:
                    quote = char
                continue
            if quote is None and line[index : index + 2] == "//":
                cut = index
                break
        output.append(line[:cut])
    return "\n".join(output)


def _balanced_literal(text: str, start: int) -> tuple[str, int]:
    opening = text[start]
    closing = "}" if opening == "{" else "]"
    depth = 0
    quote: Optional[str] = None
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return text[start : index + 1], index + 1
    raise InputError("Nie domknięto bloku słownika/listy w wklejce.")


def _literal(value: str) -> Any:
    candidate = _clean_comments(value).strip()
    candidate = re.sub(r",\s*\.\.\.\s*$", "", candidate, flags=re.MULTILINE)
    candidate = candidate.replace("…", "")
    try:
        return json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        try:
            return ast.literal_eval(candidate)
        except (SyntaxError, ValueError) as exc:
            raise InputError("Nie można odczytać bloku JSON/Python z wklejki.") from exc


def _blocks(text: str, label: str) -> list[Any]:
    result: list[Any] = []
    cursor = 0
    while True:
        position = text.casefold().find(label.casefold(), cursor)
        if position < 0:
            break
        start = next((index for index in range(position + len(label), len(text)) if text[index] in "[{"), None)
        if start is None:
            break
        raw, cursor = _balanced_literal(text, start)
        result.append(_literal(raw))
    return result


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _lookup(mapping: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = mapping.get(key)
    if isinstance(value, Mapping):
        return value
    folded = key.casefold()
    for candidate, record in mapping.items():
        if str(candidate).casefold() == folded and isinstance(record, Mapping):
            return record
    return {}


def _safe_name(value: str, *, fallback: str) -> str:
    result = _SAFE_NAME.sub("-", value.strip()).strip("-._")
    return (result or fallback)[:63]


def _device_group(value: Any) -> str:
    result = str(value or "shared").strip()
    return result or "shared"


def _endpoint_name(value: str, info: Mapping[str, Any], *, prefix: str = "H") -> tuple[str, Optional[str]]:
    raw = value.strip().strip("[]")
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return raw, None
    if network.prefixlen == network.max_prefixlen:
        return f"H-{network.network_address}-{network.max_prefixlen}", f"{network.network_address}/{network.max_prefixlen}"
    return f"{prefix}-{network.network_address}-{network.prefixlen}", str(network)


def _service_name(value: str) -> tuple[str, Optional[str], Optional[str]]:
    raw = value.strip()
    match = re.fullmatch(r"<?(\d{1,5})>?-?(tcp|udp)", raw, re.IGNORECASE)
    if not match:
        return _safe_name(raw, fallback="application-default"), None, None
    port, protocol = match.groups()
    port_number = int(port)
    if not 1 <= port_number <= 65535:
        raise InputError(f"Port usługi poza zakresem 1..65535: {value!r}.")
    name = f"SVC__{port_number}-{protocol.lower()}"
    return name, protocol.lower(), str(port_number)


def _parse_flow(value: str, src_info: Mapping[str, Any], dst_info: Mapping[str, Any]) -> RequestFlow:
    parts = [part.strip() for part in value.split("|")]
    if not parts or "->" not in parts[0]:
        raise InputError(f"Nie rozpoznano przepływu Passes ToDo: {value!r}.")
    source, destination = _FLOW_SEPARATOR.split(parts[0], maxsplit=1)
    service = parts[1] if len(parts) > 1 and parts[1] else "application-default"
    application = parts[2] if len(parts) > 2 and parts[2] else "any"
    duration = parts[3] if len(parts) > 3 and parts[3] else "bezterminowo"
    source_zone = str(src_info.get("zone") or "any")
    destination_zone = str(dst_info.get("zone") or "any")
    device_group = _device_group(
        dst_info.get("device_group")
        or dst_info.get("device-group")
        or dst_info.get("dg")
        or src_info.get("device_group")
        or src_info.get("device-group")
        or src_info.get("dg")
        or dst_info.get("device")
        or src_info.get("device")
    )
    rulebase = str(
        dst_info.get("rulebase")
        or dst_info.get("rule_base")
        or src_info.get("rulebase")
        or src_info.get("rule_base")
        or "pre-rulebase"
    ).strip() or "pre-rulebase"
    if rulebase not in _ALLOWED_RULEBASES:
        raise InputError(
            f"Nieobsługiwany rulebase {rulebase!r}; dozwolone są: "
            + ", ".join(sorted(_ALLOWED_RULEBASES))
            + "."
        )
    policy_type = str(
        dst_info.get("policy_type")
        or dst_info.get("policy-type")
        or src_info.get("policy_type")
        or src_info.get("policy-type")
        or "security"
    ).strip() or "security"
    if policy_type not in _ALLOWED_POLICY_TYPES:
        raise InputError(
            f"Nieobsługiwany typ polityki {policy_type!r}; dozwolone są: "
            + ", ".join(sorted(_ALLOWED_POLICY_TYPES))
            + "."
        )
    return RequestFlow(
        source=source.strip(),
        destination=destination.strip(),
        service=service,
        application=application,
        duration=duration,
        source_info=src_info,
        destination_info=dst_info,
        device_group=device_group,
        rulebase=rulebase,
        policy_type=policy_type,
        source_zone=source_zone,
        destination_zone=destination_zone,
        description=f"Wygenerowano z wklejki: {source.strip()} -> {destination.strip()} ({duration})",
    )


def parse_policy_request(text: str) -> ParsedPolicyRequest:
    if not isinstance(text, str) or not text.strip():
        raise InputError("Wklejka zlecenia polityk nie może być pusta.")
    if len(text) > 2_000_000:
        raise InputError("Wklejka zlecenia przekracza limit 2 MB.")
    source_blocks = _blocks(text, "Info Src")
    destination_blocks = _blocks(text, "Info Dst")
    todo_blocks = _blocks(text, "Passes ToDo")
    done_blocks = _blocks(text, "Passes Done")

    source_map: Mapping[str, Any] = {}
    destination_map: Mapping[str, Any] = {}
    for block in source_blocks:
        if isinstance(block, Mapping):
            source_map = {**source_map, **block}
    for block in destination_blocks:
        if isinstance(block, Mapping):
            destination_map = {**destination_map, **block}
    raw_flows: list[str] = []
    for block in todo_blocks:
        if isinstance(block, list):
            raw_flows.extend(str(item) for item in block if isinstance(item, str) and "->" in item)
    if not raw_flows:
        # Also accept a plain text export with one flow per line.
        raw_flows = [line.strip() for line in text.splitlines() if "->" in line and "|" in line]
    flows: list[RequestFlow] = []
    seen: set[tuple[str, ...]] = set()
    missing_context: list[str] = []
    for raw in raw_flows:
        head = raw.split("|", 1)[0]
        source = head.split("->", 1)[0].strip()
        destination = head.split("->", 1)[1].strip()
        src_info = _lookup(source_map, source)
        dst_info = _lookup(destination_map, destination)
        if not src_info and source_map:
            missing_context.append(f"Info Src nie zawiera dokładnego klucza {source!r}.")
        if not dst_info and destination_map:
            missing_context.append(f"Info Dst nie zawiera dokładnego klucza {destination!r}.")
        flow = _parse_flow(raw, src_info, dst_info)
        key = (flow.source, flow.destination, flow.service, flow.application, flow.device_group)
        if key not in seen:
            flows.append(flow)
            seen.add(key)
    if not flows:
        raise InputError("Nie znaleziono żadnego przepływu w Passes ToDo.")
    warnings: list[str] = []
    warnings.extend(dict.fromkeys(missing_context))
    if done_blocks:
        warnings.append("Wklejka zawiera Passes Done; do planu dodano wyłącznie Passes ToDo.")
    if any("API Answer Success" in line and "false" in line.casefold() for line in text.splitlines()):
        warnings.append("Źródłowe API zgłosiło niepowodzenie; plan jest tylko do ręcznej weryfikacji.")
    return ParsedPolicyRequest(tuple(flows), tuple(warnings), tuple(str(item) for block in done_blocks for item in (block if isinstance(block, list) else [])))


def _entry_xpath(device_group: str, container: str, name: str) -> str:
    base = "/config/shared" if device_group.casefold() == "shared" else f"/config/devices/entry/device-group/entry[@name={xpath_literal(device_group)}]"
    return f"{base}/{container}/entry[@name={xpath_literal(name)}]"


def _policy_xpath(flow: RequestFlow, name: str) -> str:
    base = "/config/shared" if flow.device_group.casefold() == "shared" else f"/config/devices/entry/device-group/entry[@name={xpath_literal(flow.device_group)}]"
    return f"{base}/{flow.rulebase}/{flow.policy_type}/rules/entry[@name={xpath_literal(name)}]"


def _xml_entry(name: str, children: Iterable[tuple[str, Optional[str]]]) -> str:
    entry = ET.Element("entry", {"name": name})
    for tag, value in children:
        if value is None:
            continue
        node = ET.SubElement(entry, tag)
        node.text = value
    return ET.tostring(entry, encoding="unicode")


def _xml_members(tag: str, values: Iterable[str]) -> ET.Element:
    node = ET.Element(tag)
    for value in values:
        ET.SubElement(node, "member").text = value
    return node


def _policy_xml(flow: RequestFlow, name: str, source_name: str, destination_name: str, service_name: str) -> str:
    entry = ET.Element("entry", {"name": name})
    ET.SubElement(entry, "from").append(ET.Element("member"))
    entry.find("./from/member").text = flow.source_zone
    ET.SubElement(entry, "to").append(ET.Element("member"))
    entry.find("./to/member").text = flow.destination_zone
    source = _xml_members("source", [source_name])
    destination = _xml_members("destination", [destination_name])
    service = _xml_members("service", [service_name])
    application = _xml_members("application", [flow.application])
    entry.extend((source, destination, service, application))
    if str(flow.source_info.get("IdType") or "").casefold() in {"user", "palogroup"}:
        entry.append(_xml_members("source-user", [flow.source.strip("[]")]))
    ET.SubElement(entry, "action").text = flow.action or "allow"
    if flow.tags:
        entry.append(_xml_members("tag", flow.tags))
    ET.SubElement(entry, "description").text = flow.description
    return ET.tostring(entry, encoding="unicode")


def _exists(reader: PanoramaReadClient, xpath: str) -> bool:
    for config_type in ("running", "candidate"):
        root = reader.fetch_xpath(xpath, config_type=config_type)
        if any(element.tag == "entry" and element.get("name") for element in root.iter()):
            return True
    return False


def build_policy_creation_plan(
    reader: PanoramaReadClient,
    text: str,
    *,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> PolicyCreationResult:
    parsed = parse_policy_request(text)
    progress = progress_callback or (lambda _value, _message: None)
    progress(8, "Parsowanie Passes ToDo i map źródło/cel")
    mutations: list[Mutation] = []
    warnings = list(parsed.warnings)
    targets: list[str] = []
    inventory: dict[str, Any] = {}
    created_keys: set[tuple[str, str, str]] = set()
    mutation_index = 0
    component_id = "create-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]

    def add_create(target: str, entity_type: str, name: str, xpath: str, parent: str, xml: str, scope: str, flow_label: str) -> None:
        nonlocal mutation_index
        identity = (scope, entity_type, name)
        if identity in created_keys:
            return
        created_keys.add(identity)
        if _exists(reader, xpath):
            warnings.append(f"{entity_type} {name} już istnieje w {scope}; pominięto tworzenie.")
            return
        mutation_index += 1
        mutation_id = f"mutation-{mutation_index:05d}"
        depends = (mutations[-1].mutation_id,) if mutations else ()
        mutations.append(Mutation(
            mutation_id=mutation_id,
            component_id=component_id,
            entity_type=entity_type,
            entity_key=f"create/{scope}/{name}",
            target_xpath=xpath,
            before_xml=None,
            after_xml=xml,
            forward=(MutationOperation(MutationAction.SET, parent, element=xml),),
            inverse=(MutationOperation(MutationAction.DELETE, xpath),),
            causes=(flow_label,),
            depends_on=depends,
        ))

    progress(18, "Sprawdzanie istniejących obiektów punktowym XPath API")
    for index, flow in enumerate(parsed.flows, 1):
        flow_label = f"create-flow:{index}"
        targets.append(flow_label)
        source_name, source_value = _endpoint_name(flow.source, flow.source_info, prefix="N")
        destination_name, destination_value = _endpoint_name(flow.destination, flow.destination_info, prefix="N")
        source_is_user = str(flow.source_info.get("IdType") or "").casefold() in {"user", "palogroup"}
        if source_is_user:
            source_name = flow.source.strip("[]")
        service_name, protocol, port = _service_name(flow.service)
        destination_group = str(flow.destination_info.get("hg") or "").strip()
        if destination_group.casefold() in {"", "none", "null"}:
            destination_group = ""
        group_name = f"HG__{_safe_name(destination_group, fallback='HOSTS')}" if destination_group else ""
        policy_base = flow.policy_name or f"{_safe_name(source_name, fallback='SOURCE')}__{_safe_name(destination_name, fallback='DEST')}"
        policy_name = _safe_name(policy_base, fallback=f"POLICY__{index}")
        suffix = 2
        while (flow.device_group, "policy", policy_name) in created_keys:
            policy_name = f"{_safe_name(policy_base, fallback=f'POLICY__{index}')[:58]}__{suffix}"
            suffix += 1
        if source_value and not source_is_user:
            source_path = _entry_xpath(flow.device_group, "address", source_name)
            source_xml = _xml_entry(source_name, (("ip-netmask", source_value),))
            add_create(f"object:{source_name}", "address", source_name, source_path, parent_xpath(source_path), source_xml, flow.device_group, flow_label)
        if destination_value:
            destination_path = _entry_xpath(flow.device_group, "address", destination_name)
            destination_xml = _xml_entry(destination_name, (("ip-netmask", destination_value),))
            add_create(f"object:{destination_name}", "address", destination_name, destination_path, parent_xpath(destination_path), destination_xml, flow.device_group, flow_label)
        if group_name:
            group_path = _entry_xpath(flow.device_group, "address-group", group_name)
            group_xml = _xml_entry(group_name, ())
            group_entry = ET.fromstring(group_xml)
            static = ET.SubElement(group_entry, "static")
            ET.SubElement(static, "member").text = destination_name
            group_xml = ET.tostring(group_entry, encoding="unicode")
            add_create(f"group:{group_name}", "address-group", group_name, group_path, parent_xpath(group_path), group_xml, flow.device_group, flow_label)
            destination_name = group_name
        if protocol and port:
            service_path = _entry_xpath(flow.device_group, "service", service_name)
            service_xml = _xml_entry(service_name, ())
            service_entry = ET.fromstring(service_xml)
            protocol_root = ET.SubElement(service_entry, "protocol")
            protocol_node = ET.SubElement(protocol_root, protocol)
            ET.SubElement(protocol_node, "port").text = port
            service_xml = ET.tostring(service_entry, encoding="unicode")
            add_create(f"service:{service_name}", "service", service_name, service_path, parent_xpath(service_path), service_xml, flow.device_group, flow_label)
        policy_path = _policy_xpath(flow, policy_name)
        policy_parent = parent_xpath(policy_path)
        policy_xml = _policy_xml(flow, policy_name, source_name, destination_name, service_name)
        add_create(f"policy:{policy_name}", "policy", policy_name, policy_path, policy_parent, policy_xml, flow.device_group, flow_label)
        inventory[flow_label] = {
            "kind": "policy",
            "label": policy_name,
            "status": "planned",
            "device_group": flow.device_group,
            "rulebase": flow.rulebase,
            "source": source_name,
            "destination": destination_name,
            "service": service_name,
            "source_zone": flow.source_zone,
            "destination_zone": flow.destination_zone,
        }
        progress(18 + int(index / max(1, len(parsed.flows)) * 70), f"Przygotowano przepływ {index}/{len(parsed.flows)}")
    if not mutations:
        warnings.append("Nie utworzono nowych encji: wszystkie obiekty/polityki już istnieją albo nie przeszły walidacji.")
    patch = PatchSet.new(
        kind="future-create",
        panorama_host=reader.profile.host,
        panorama_username=reader.profile.username,
        mutations=mutations,
        targets=targets,
        affected_device_groups=tuple(
            sorted(
                {
                    mutation.target_xpath.split("entry[@name=", 1)[1]
                    .split("]", 1)[0]
                    .strip("'\"")
                    for mutation in mutations
                    if "/device-group/" in mutation.target_xpath
                    and "entry[@name=" in mutation.target_xpath
                }
            )
        ),
        warnings=warnings,
    )
    progress(100, "Plan tworzenia polityk jest gotowy")
    return PolicyCreationResult(
        patchset=patch,
        input_targets={"ordered": targets, "flows": [flow.__dict__ for flow in parsed.flows]},
        inventory=inventory,
        warnings=tuple(warnings),
    )
