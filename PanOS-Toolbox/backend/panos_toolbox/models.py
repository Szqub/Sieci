"""Serializable transaction model used by CLI, web UI and future planners."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Optional, Sequence

from .errors import InputError, ValidationError


def utc_now() -> str:
    # Microseconds make chronological multi-session restore unambiguous even
    # when two small candidate batches finish within the same second.
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class ApiStage(str, Enum):
    READ_ONLY = "read-only"
    CANDIDATE = "candidate"
    COMMIT = "commit"
    PUSH = "push"

    @property
    def rank(self) -> int:
        return {
            ApiStage.READ_ONLY: 0,
            ApiStage.CANDIDATE: 1,
            ApiStage.COMMIT: 2,
            ApiStage.PUSH: 3,
        }[self]

    @classmethod
    def parse(cls, value: str) -> "ApiStage":
        try:
            return cls(value.strip().casefold())
        except (AttributeError, ValueError) as exc:
            allowed = ", ".join(stage.value for stage in cls)
            raise InputError(f"api_max_stage musi być jednym z: {allowed}.") from exc


class MutationAction(str, Enum):
    SET = "set"
    EDIT = "edit"
    DELETE = "delete"
    MOVE = "move"


class SessionState(str, Enum):
    PLANNED = "PLANNED"
    WRITING_CANDIDATE = "WRITING_CANDIDATE"
    CANDIDATE_APPLIED = "CANDIDATE_APPLIED"
    COMMITTING = "COMMITTING"
    COMMITTED = "COMMITTED"
    PUSHING = "PUSHING"
    PUSHED = "PUSHED"
    RESTORING = "RESTORING"
    RESTORED = "RESTORED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CONFLICT = "CONFLICT"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")


def _reject_controls(value: str, label: str) -> None:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValidationError(f"{label} zawiera niedozwolony znak sterujący.")


@dataclass(frozen=True)
class MutationOperation:
    """One native PAN-OS XML API config operation.

    ``element`` is raw XML supplied to ``set``/``edit``.  ``where`` and
    ``destination`` are used only by ``move``.  No CLI command is ever parsed
    to construct this model.
    """

    action: MutationAction
    xpath: str
    element: Optional[str] = None
    where: Optional[str] = None
    destination: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.xpath.startswith("/config"):
            raise ValidationError("XPath mutacji musi zaczynać się od /config.")
        _reject_controls(self.xpath, "XPath")
        if self.action in {MutationAction.SET, MutationAction.EDIT}:
            if not self.element or not self.element.strip():
                raise ValidationError(f"Operacja {self.action.value} wymaga element XML.")
            # TAB/LF/CR are legal XML 1.0 content (notably in descriptions).
            # ElementTree rejects the forbidden C0 controls while the wrapper
            # permits the multi-node fragment accepted by PAN-OS ``element``.
            try:
                ET.fromstring(f"<panos-toolbox-fragment>{self.element}</panos-toolbox-fragment>")
            except ET.ParseError as exc:
                raise ValidationError(f"Niepoprawny fragment element XML: {exc}.") from exc
        elif self.element is not None:
            raise ValidationError(f"Operacja {self.action.value} nie przyjmuje element XML.")
        if self.action is MutationAction.MOVE:
            if self.where not in {"before", "after", "top", "bottom"}:
                raise ValidationError("Operacja move ma niepoprawne where.")
            if self.where in {"before", "after"} and not self.destination:
                raise ValidationError("Operacja move before/after wymaga destination.")
        elif self.where is not None or self.destination is not None:
            raise ValidationError("where/destination są dozwolone wyłącznie dla move.")
        if self.destination is not None:
            _reject_controls(self.destination, "Cel move")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "xpath": self.xpath,
            "element": self.element,
            "where": self.where,
            "destination": self.destination,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MutationOperation":
        return cls(
            action=MutationAction(str(value["action"])),
            xpath=str(value["xpath"]),
            element=value.get("element"),
            where=value.get("where"),
            destination=value.get("destination"),
        )


@dataclass(frozen=True)
class Mutation:
    mutation_id: str
    component_id: str
    entity_type: str
    entity_key: str
    target_xpath: str
    before_xml: Optional[str]
    after_xml: Optional[str]
    forward: tuple[MutationOperation, ...]
    inverse: tuple[MutationOperation, ...]
    causes: tuple[str, ...]
    depends_on: tuple[str, ...] = ()
    order_previous: Optional[str] = None
    order_next: Optional[str] = None
    order_context_sha256: Optional[str] = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.mutation_id, "mutation_id"),
            (self.component_id, "component_id"),
            (self.entity_type, "entity_type"),
        ):
            if not _SAFE_IDENTIFIER.fullmatch(value):
                raise ValidationError(f"Niepoprawny {label}: {value!r}.")
        if not self.entity_key:
            raise ValidationError("entity_key nie może być pusty.")
        _reject_controls(self.entity_key, "entity_key")
        if not self.target_xpath.startswith("/config"):
            raise ValidationError("target_xpath musi zaczynać się od /config.")
        if not self.forward or not self.inverse:
            raise ValidationError("Mutacja wymaga operacji forward i inverse.")
        if not self.causes:
            raise ValidationError("Mutacja musi zapisywać co najmniej jedną przyczynę/IP.")
        if self.order_context_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", self.order_context_sha256
        ):
            raise ValidationError("order_context_sha256 musi być sumą SHA256.")

    @property
    def before_sha256(self) -> str:
        from .xmlutil import fingerprint_xml

        return fingerprint_xml(self.before_xml)

    @property
    def after_sha256(self) -> str:
        from .xmlutil import fingerprint_xml

        return fingerprint_xml(self.after_xml)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mutation_id": self.mutation_id,
            "component_id": self.component_id,
            "entity_type": self.entity_type,
            "entity_key": self.entity_key,
            "target_xpath": self.target_xpath,
            "before_xml": self.before_xml,
            "after_xml": self.after_xml,
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "forward": [operation.to_dict() for operation in self.forward],
            "inverse": [operation.to_dict() for operation in self.inverse],
            "causes": list(self.causes),
            "depends_on": list(self.depends_on),
            "order_previous": self.order_previous,
            "order_next": self.order_next,
            "order_context_sha256": self.order_context_sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Mutation":
        mutation = cls(
            mutation_id=str(value["mutation_id"]),
            component_id=str(value["component_id"]),
            entity_type=str(value["entity_type"]),
            entity_key=str(value["entity_key"]),
            target_xpath=str(value["target_xpath"]),
            before_xml=value.get("before_xml"),
            after_xml=value.get("after_xml"),
            forward=tuple(MutationOperation.from_dict(item) for item in value["forward"]),
            inverse=tuple(MutationOperation.from_dict(item) for item in value["inverse"]),
            causes=tuple(str(item) for item in value["causes"]),
            depends_on=tuple(str(item) for item in value.get("depends_on", ())),
            order_previous=value.get("order_previous"),
            order_next=value.get("order_next"),
            order_context_sha256=value.get("order_context_sha256"),
        )
        for key, actual in (
            ("before_sha256", mutation.before_sha256),
            ("after_sha256", mutation.after_sha256),
        ):
            recorded = value.get(key)
            if recorded is not None and recorded != actual:
                raise ValidationError(f"Integralność {key} mutacji {mutation.mutation_id} jest błędna.")
        return mutation


@dataclass(frozen=True)
class PatchSet:
    patch_id: str
    kind: str
    created_utc: str
    panorama_host: str
    panorama_username: str
    mutations: tuple[Mutation, ...]
    targets: tuple[str, ...]
    affected_device_groups: tuple[str, ...]
    warnings: tuple[str, ...] = ()
    source_session_id: Optional[str] = None
    source_session_ids: tuple[str, ...] = ()
    skipped_components: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _SAFE_IDENTIFIER.fullmatch(self.patch_id):
            raise ValidationError("Niepoprawny patch_id.")
        if self.kind not in {"cleanup", "restore", "future-create"}:
            raise ValidationError(f"Nieobsługiwany rodzaj PatchSet: {self.kind}.")
        ids = [mutation.mutation_id for mutation in self.mutations]
        if len(ids) != len(set(ids)):
            raise ValidationError("PatchSet zawiera zduplikowane mutation_id.")
        known: set[str] = set()
        for mutation in self.mutations:
            missing = set(mutation.depends_on) - known
            if missing:
                raise ValidationError(
                    f"Mutacja {mutation.mutation_id} zależy od późniejszej/nieznanej mutacji: "
                    + ", ".join(sorted(missing))
                )
            known.add(mutation.mutation_id)
        if self.source_session_id and self.source_session_ids:
            if self.source_session_id not in self.source_session_ids:
                raise ValidationError(
                    "source_session_id musi należeć do source_session_ids."
                )

    @property
    def touched_xpaths(self) -> tuple[str, ...]:
        return tuple(sorted({mutation.target_xpath for mutation in self.mutations}))

    @classmethod
    def new(
        cls,
        *,
        kind: str,
        panorama_host: str,
        panorama_username: str,
        mutations: Sequence[Mutation],
        targets: Iterable[str],
        affected_device_groups: Iterable[str],
        warnings: Iterable[str] = (),
        source_session_id: Optional[str] = None,
        source_session_ids: Iterable[str] = (),
        skipped_components: Iterable[str] = (),
    ) -> "PatchSet":
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        all_source_sessions = tuple(dict.fromkeys(source_session_ids))
        if source_session_id and not all_source_sessions:
            all_source_sessions = (source_session_id,)
        return cls(
            patch_id=f"patch-{stamp}-{secrets.token_hex(4)}",
            kind=kind,
            created_utc=utc_now(),
            panorama_host=panorama_host,
            panorama_username=panorama_username,
            mutations=tuple(mutations),
            targets=tuple(sorted(set(targets))),
            affected_device_groups=tuple(sorted(set(affected_device_groups))),
            warnings=tuple(warnings),
            source_session_id=source_session_id,
            source_session_ids=all_source_sessions,
            skipped_components=tuple(sorted(set(skipped_components))),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "kind": self.kind,
            "created_utc": self.created_utc,
            "panorama_host": self.panorama_host,
            "panorama_username": self.panorama_username,
            "targets": list(self.targets),
            "affected_device_groups": list(self.affected_device_groups),
            "warnings": list(self.warnings),
            "source_session_id": self.source_session_id,
            "source_session_ids": list(self.source_session_ids),
            "skipped_components": list(self.skipped_components),
            "touched_xpaths": list(self.touched_xpaths),
            "mutations": [mutation.to_dict() for mutation in self.mutations],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PatchSet":
        primary_source = value.get("source_session_id")
        source_sessions = tuple(
            str(item) for item in value.get("source_session_ids", ())
        )
        if primary_source and not source_sessions:
            source_sessions = (str(primary_source),)
        patch = cls(
            patch_id=str(value["patch_id"]),
            kind=str(value["kind"]),
            created_utc=str(value["created_utc"]),
            panorama_host=str(value["panorama_host"]),
            panorama_username=str(value["panorama_username"]),
            mutations=tuple(Mutation.from_dict(item) for item in value["mutations"]),
            targets=tuple(str(item) for item in value.get("targets", ())),
            affected_device_groups=tuple(
                str(item) for item in value.get("affected_device_groups", ())
            ),
            warnings=tuple(str(item) for item in value.get("warnings", ())),
            source_session_id=primary_source,
            source_session_ids=source_sessions,
            skipped_components=tuple(
                str(item) for item in value.get("skipped_components", ())
            ),
        )
        recorded = tuple(value.get("touched_xpaths", patch.touched_xpaths))
        if recorded != patch.touched_xpaths:
            raise ValidationError("Integralność touched_xpaths PatchSet jest błędna.")
        return patch


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()
