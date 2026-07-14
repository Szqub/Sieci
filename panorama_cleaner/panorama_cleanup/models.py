"""Typed data model shared by the Panorama cleanup parser and planner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

__version__ = "1.5.0"


class CleanupError(Exception):
    """Base class for expected, operator-facing failures."""


class InputError(CleanupError):
    """Input file or argument is invalid."""


class TransportError(CleanupError):
    """Panorama could not be reached or authenticated."""


class SnapshotError(CleanupError):
    """A complete, successful XML snapshot could not be obtained."""


class ParseError(CleanupError):
    """The Panorama configuration cannot be parsed safely."""


class UnsafePlanError(CleanupError):
    """The simulated plan violates a safety invariant."""


class OutputError(CleanupError):
    """Backups or output artifacts could not be written safely."""


class PingStatus(str, Enum):
    REPLIED = "REPLIED"
    NO_REPLY = "NO_REPLY"
    BYPASSED = "BYPASSED"
    ERROR = "ERROR"


@dataclass(frozen=True, order=True)
class ScopedName:
    """Object identity; names alone are not unique across Panorama scopes."""

    location: str
    name: str


@dataclass(frozen=True, order=True)
class RuleKey:
    location: str
    rulebase: str
    policy_type: str
    name: str


@dataclass(frozen=True, order=True)
class TargetToken:
    """One removable definition or a direct literal IP reference."""

    kind: str  # address | literal
    ip: str
    location: str = ""
    name: str = ""

    @classmethod
    def address(cls, ip: str, key: ScopedName) -> "TargetToken":
        return cls("address", ip, key.location, key.name)

    @classmethod
    def literal(cls, ip: str) -> "TargetToken":
        return cls("literal", ip)

    @property
    def scoped_name(self) -> Optional[ScopedName]:
        if self.kind != "address":
            return None
        return ScopedName(self.location, self.name)


@dataclass
class InputRow:
    lp: int
    raw: str
    normalized: Optional[str]
    valid: bool
    duplicate_of_lp: Optional[int] = None
    error: Optional[str] = None


@dataclass
class PingResult:
    ip: str
    status: PingStatus
    detail: str
    elapsed_seconds: float


@dataclass
class AddressObject:
    key: ScopedName
    object_type: str
    raw_value: str
    tags: Tuple[str, ...]
    xml: str
    xpath: str


@dataclass
class StaticGroup:
    key: ScopedName
    members: Tuple[str, ...]
    xml: str
    xpath: str


@dataclass
class DynamicGroup:
    key: ScopedName
    filter_text: str
    tags: Tuple[str, ...]
    xml: str
    xpath: str


@dataclass
class PolicyRule:
    key: RuleKey
    uuid: Optional[str]
    source_members: Tuple[str, ...]
    destination_members: Tuple[str, ...]
    negate_source: bool
    negate_destination: bool
    disabled: bool
    action: Optional[str]
    xml: str
    xpath: str
    order_index: int
    previous_rule: Optional[str]
    next_rule: Optional[str]


@dataclass(frozen=True)
class ResolvedReference:
    owner_location: str
    owner_type: str
    owner_name: str
    configuration_path: str
    field: str
    referenced_name: str
    resolved_kind: str
    resolved_key: Optional[ScopedName]
    owner_rule: Optional[RuleKey] = None
    owner_group: Optional[ScopedName] = None
    supported_for_automatic_modification: bool = True
    detail: str = ""


@dataclass(frozen=True)
class UnknownOccurrence:
    location: str
    configuration_path: str
    value: str
    owner_type: str
    owner_name: str
    owner_rule: Optional[RuleKey] = None
    owner_group: Optional[ScopedName] = None


@dataclass
class ConfigModel:
    device_entry_name: str
    ancestor_objects_take_precedence: bool
    parents: Dict[str, Optional[str]]
    addresses: Dict[ScopedName, AddressObject]
    static_groups: Dict[ScopedName, StaticGroup]
    dynamic_groups: Dict[ScopedName, DynamicGroup]
    other_address_definitions: Dict[ScopedName, str]
    rules: Dict[RuleKey, PolicyRule]
    group_references: Dict[ScopedName, List[ResolvedReference]]
    rule_references: Dict[RuleKey, List[ResolvedReference]]
    unknown_occurrences: List[UnknownOccurrence]
    warnings: List[str]


@dataclass
class IPMatch:
    ip: str
    exact_objects: Tuple[ScopedName, ...]
    containing_objects: Tuple[ScopedName, ...]


@dataclass
class BlockReason:
    code: str
    message: str
    path: Optional[str] = None


@dataclass
class BatchPlan:
    active_tokens: Set[TargetToken]
    blocked_ips: Dict[str, List[BlockReason]]
    group_member_removals: Dict[ScopedName, Dict[str, Set[TargetToken]]]
    deleted_groups: Set[ScopedName]
    group_causes: Dict[ScopedName, Set[TargetToken]]
    rule_field_removals: Dict[Tuple[RuleKey, str], Dict[str, Set[TargetToken]]]
    deleted_rules: Set[RuleKey]
    rule_causes: Dict[RuleKey, Set[TargetToken]]
    deleted_addresses: Set[ScopedName]
    dynamic_group_impacts: Dict[ScopedName, Set[ScopedName]]
    warnings: List[str]


@dataclass(frozen=True)
class CommandRecord:
    command_id: str
    category: str
    command: str
    causes: Tuple[str, ...]
    entity_type: str
    entity_key: str


@dataclass
class RenderedPlan:
    commands: List[CommandRecord]
    rollback_commands: List[str]
    affected_addresses: Set[ScopedName]
    affected_groups: Set[ScopedName]
    affected_rules: Set[RuleKey]
    rollback_warnings: List[str] = field(default_factory=list)


@dataclass
class CandidateComparison:
    different: Optional[bool]
    full_running_sha256: Optional[str]
    full_candidate_sha256: Optional[str]
    relevant_running_sha256: Optional[str]
    relevant_candidate_sha256: Optional[str]
    relevant_different: Optional[bool]
    automated_check_performed: bool = True
    administrator_confirmed: bool = False


@dataclass
class RunMetrics:
    ping_seconds: float = 0.0
    snapshot_seconds: float = 0.0
    parse_seconds: float = 0.0
    planning_seconds: float = 0.0
    rendering_seconds: float = 0.0
    hit_count_seconds: float = 0.0
    total_seconds: float = 0.0
    remote_snapshot_command_count: int = 0
    remote_operational_command_count: int = 0
    input_row_count: int = 0
    unique_ip_count: int = 0
    discovered_object_count: int = 0
    affected_rule_count: int = 0
    affected_group_count: int = 0
    blocked_ip_count: int = 0
    generated_command_count: int = 0
    hit_count_rule_count: int = 0
    recent_hit_rule_count: int = 0
    no_last_hit_rule_count: int = 0
    hit_count_error_count: int = 0


@dataclass(frozen=True)
class RuleHitCount:
    rule: RuleKey
    status: str
    hit_count: Optional[int]
    last_hit_timestamp: Optional[int]
    last_hit_utc: Optional[str]
    age_days: Optional[float]
    latest: Optional[bool]
    detail: str = ""

    @property
    def requires_review(self) -> bool:
        return self.status in {
            "RECENT",
            "NEVER",
            "ERROR",
            "NOT_FOUND",
            "INVALID",
            "NOT_LATEST",
        }
