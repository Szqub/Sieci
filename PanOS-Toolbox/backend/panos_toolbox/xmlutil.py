"""Safe XML parsing, XPath lookup and semantic fingerprints."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from typing import Iterable, Optional

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .errors import PanoramaResponseError, ValidationError


MISSING_FINGERPRINT = hashlib.sha256(b"<panos-toolbox:missing>").hexdigest()
VOLATILE_ATTRIBUTES = {"admin", "dirtyId", "time", "last-modified"}


def parse_xml(payload: bytes | str) -> ET.Element:
    if isinstance(payload, bytes):
        if not payload or not payload.rstrip().endswith(b">"):
            raise PanoramaResponseError("Odpowiedź XML jest pusta lub ucięta.")
    elif not payload or not payload.rstrip().endswith(">"):
        raise PanoramaResponseError("Odpowiedź XML jest pusta lub ucięta.")
    try:
        return SafeET.fromstring(
            payload,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (ET.ParseError, DefusedXmlException) as exc:
        raise PanoramaResponseError(f"Niepoprawny XML: {exc}.") from exc


def parse_api_response(payload: bytes | str, *, expect_config: bool = False) -> ET.Element:
    root = parse_xml(payload)
    if root.tag == "response" and root.get("status") != "success":
        message = " ".join(text.strip() for text in root.itertext() if text.strip())
        raise PanoramaResponseError(
            f"Panorama zwróciła status {root.get('status') or 'brak'}: {message[:500]}"
        )
    if not expect_config:
        return root
    if root.tag == "config":
        return root
    config = root.find("./result/config")
    if config is None:
        config = root.find(".//config")
    if config is None:
        raise PanoramaResponseError("Odpowiedź Panoramy nie zawiera kompletnego <config>.")
    return config


def element_xml(element: Optional[ET.Element]) -> Optional[str]:
    return None if element is None else ET.tostring(element, encoding="unicode")


def _canonical_tuple(element: ET.Element):
    attributes = tuple(
        sorted(
            (key, value)
            for key, value in element.attrib.items()
            if key not in VOLATILE_ATTRIBUTES
        )
    )
    text = (element.text or "").strip()
    children = tuple(_canonical_tuple(child) for child in list(element))
    return element.tag, attributes, text, children


def fingerprint_element(element: Optional[ET.Element]) -> str:
    if element is None:
        return MISSING_FINGERPRINT
    value = repr(_canonical_tuple(element)).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def fingerprint_xml(xml: Optional[str]) -> str:
    if xml is None:
        return MISSING_FINGERPRINT
    return fingerprint_element(parse_xml(xml))


def raw_sha256(payload: bytes | str) -> str:
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    return hashlib.sha256(data).hexdigest()


def xpath_literal(value: str) -> str:
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    parts = value.split("'")
    joined: list[str] = []
    for index, part in enumerate(parts):
        if part:
            joined.append(f"'{part}'")
        if index != len(parts) - 1:
            joined.append('"\'"')
    return "concat(" + ",".join(joined) + ")"


def _split_xpath(xpath: str) -> list[str]:
    if not xpath.startswith("/config"):
        raise ValidationError("XPath musi zaczynać się od /config.")
    parts: list[str] = []
    current: list[str] = []
    quote: Optional[str] = None
    depth = 0
    for character in xpath.strip("/"):
        if quote:
            current.append(character)
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
            current.append(character)
        elif character == "[":
            depth += 1
            current.append(character)
        elif character == "]":
            depth -= 1
            current.append(character)
        elif character == "/" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    if quote or depth != 0:
        raise ValidationError(f"Niepoprawny XPath: {xpath!r}.")
    if current:
        parts.append("".join(current))
    return parts


def _split_arguments(value: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    quote: Optional[str] = None
    for character in value:
        if quote:
            current.append(character)
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
            current.append(character)
        elif character == ",":
            args.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if quote:
        raise ValidationError("Niedomknięty literał XPath.")
    if current:
        args.append("".join(current).strip())
    return args


def decode_xpath_literal(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if value.startswith("concat(") and value.endswith(")"):
        return "".join(decode_xpath_literal(part) for part in _split_arguments(value[7:-1]))
    raise ValidationError(f"Nieobsługiwany literał XPath: {value!r}.")


_PREDICATE = re.compile(r"^([^\[]+)(?:\[(.+)\])?$")


def find_xpath(config: ET.Element, xpath: str) -> Optional[ET.Element]:
    """Resolve the conservative XPath subset emitted by Toolbox/cleaner."""

    if config.tag != "config":
        config = parse_api_response(ET.tostring(config), expect_config=True)
    parts = _split_xpath(xpath)
    if not parts or parts[0] != "config":
        raise ValidationError("XPath nie wskazuje /config.")
    current = config
    for raw_segment in parts[1:]:
        match = _PREDICATE.fullmatch(raw_segment)
        if not match:
            raise ValidationError(f"Nieobsługiwany segment XPath: {raw_segment!r}.")
        tag, predicate = match.groups()
        candidates = current.findall(f"./{tag}")
        if predicate is None:
            current = candidates[0] if candidates else None  # type: ignore[assignment]
        elif predicate.startswith("@name="):
            name = decode_xpath_literal(predicate[len("@name=") :])
            current = next((item for item in candidates if item.get("name") == name), None)  # type: ignore[assignment]
        elif predicate.startswith("text()="):
            text = decode_xpath_literal(predicate[len("text()=") :])
            current = next(
                (item for item in candidates if (item.text or "").strip() == text),
                None,
            )  # type: ignore[assignment]
        else:
            raise ValidationError(f"Nieobsługiwany predykat XPath: {predicate!r}.")
        if current is None:
            return None
    return current


def fingerprint_xpath(config: ET.Element, xpath: str) -> str:
    return fingerprint_element(find_xpath(config, xpath))


def parent_xpath(xpath: str) -> str:
    parts = _split_xpath(xpath)
    if len(parts) <= 1:
        raise ValidationError("/config nie ma nadrzędnego XPath do modyfikacji.")
    return "/" + "/".join(parts[:-1])


def rule_order_context_sha256(
    config: ET.Element,
    target_xpath: str,
    order_previous: Optional[str],
    order_next: Optional[str],
) -> str:
    """Fingerprint the ordered rule names in the exact owning rulebase.

    Rule content edits do not change the fingerprint.  Any add/delete/move in
    that container does, because it can make a previously safe restore anchor
    ambiguous between plan and apply.
    """

    container = find_xpath(config, parent_xpath(target_xpath))
    names = (
        [name for entry in container.findall("./entry") if (name := entry.get("name"))]
        if container is not None
        else []
    )
    context: dict[str, object] = {
        "container_present": container is not None,
        "ordered_names": names,
        "historical_previous": order_previous,
        "historical_next": order_next,
    }
    payload = json.dumps(context, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def rule_order_names_sha256(
    names: Iterable[str],
    order_previous: Optional[str],
    order_next: Optional[str],
) -> str:
    context = {
        "container_present": True,
        "ordered_names": list(names),
        "historical_previous": order_previous,
        "historical_next": order_next,
    }
    payload = json.dumps(context, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def device_group_from_xpath(xpath: str) -> Optional[str]:
    parts = _split_xpath(xpath)
    for index, segment in enumerate(parts[:-1]):
        if segment != "device-group":
            continue
        match = _PREDICATE.fullmatch(parts[index + 1])
        if match and match.group(1) == "entry" and (match.group(2) or "").startswith("@name="):
            return decode_xpath_literal(match.group(2)[len("@name=") :])
    return None


def supported_entities(config: ET.Element) -> dict[str, str]:
    """Return fingerprints for namespaces understood by the cleanup planner."""

    if config.tag != "config":
        config = parse_api_response(ET.tostring(config), expect_config=True)
    result: dict[str, str] = {}

    def collect(scope: ET.Element, prefix: str) -> None:
        for container in ("address", "address-group"):
            for entry in scope.findall(f"./{container}/entry"):
                name = entry.get("name")
                if name:
                    result[f"{prefix}/{container}/{name}"] = fingerprint_element(entry)
        for rulebase in ("pre-rulebase", "post-rulebase"):
            for policy_type in ("security", "nat", "application-override"):
                for entry in scope.findall(f"./{rulebase}/{policy_type}/rules/entry"):
                    name = entry.get("name")
                    if name:
                        result[
                            f"{prefix}/{rulebase}/{policy_type}/rules/{name}"
                        ] = fingerprint_element(entry)

    shared = config.find("./shared")
    if shared is not None:
        collect(shared, "shared")
    for device in config.findall("./devices/entry"):
        device_name = device.get("name", "?")
        for group in device.findall("./device-group/entry"):
            group_name = group.get("name")
            if group_name:
                collect(group, f"devices/{device_name}/device-group/{group_name}")
    return result
