"""Paste-ready PAN-OS CLI rendering for every durable PatchSet.

Hand Mode is deliberately a projection of the structured XML API operations,
not a second planner.  This keeps the manual and API paths tied to the same
validated mutation order, dependency components and rollback data.

The command files contain *only* configuration-mode commands.  They never
contain ``configure``, commit or push, so copying a file cannot accidentally
cross an operator-controlled stage boundary.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from .errors import PanoramaResponseError, ValidationError
from .models import Mutation, MutationAction, MutationOperation, PatchSet
from .xmlutil import (
    _PREDICATE,
    _split_xpath,
    decode_xpath_literal,
    parent_xpath,
    parse_xml,
)


@dataclass(frozen=True)
class HandModeCommand:
    command: str
    mutation_id: str
    component_id: str
    entity_type: str
    entity_key: str
    causes: tuple[str, ...]
    operation_action: str


@dataclass(frozen=True)
class HandModeRender:
    commands: tuple[str, ...]
    records: tuple[HandModeCommand, ...]
    warnings: tuple[str, ...] = ()

    @property
    def text(self) -> str:
        return "\n".join(self.commands) + ("\n" if self.commands else "")


@dataclass(frozen=True)
class HandModeArtifacts:
    active: HandModeRender
    rollback: HandModeRender
    excluded: Optional[HandModeRender] = None
    excluded_rollback: Optional[HandModeRender] = None


def _write_artifact_once(
    store,
    session_id: str,
    *,
    preferred_filename: str,
    fallback_filename: str,
    content: str,
    kind: str,
) -> str:
    """Append one immutable artifact, preserving legacy files with the same name."""

    manifest = store.load_manifest(session_id, verify=False)
    records = tuple(manifest.get("artifacts") or ())
    for record in records:
        if record.get("kind") == kind and isinstance(record.get("file"), str):
            return str(record["file"])
    used = {str(record.get("file")) for record in records if record.get("file")}
    filename = preferred_filename if preferred_filename not in used else fallback_filename
    if filename in used:
        stem, separator, suffix = filename.rpartition(".")
        stem = stem if separator else filename
        suffix = f".{suffix}" if separator else ""
        index = 2
        while f"{stem}_{index}{suffix}" in used:
            index += 1
        filename = f"{stem}_{index}{suffix}"
    store.write_artifact(session_id, filename, content, kind=kind)
    return filename


def quote_cli(value: str, *, context: str = "wartość CLI") -> str:
    """Quote one CLI value without allowing command or line injection."""

    if not isinstance(value, str):
        raise ValidationError(f"{context} musi być tekstem.")
    controls = [f"U+{ord(character):04X}" for character in value if ord(character) < 32 or ord(character) == 127]
    if controls:
        raise ValidationError(
            f"Hand Mode BLOCK: {context} zawiera znak sterujący "
            + ", ".join(controls[:10])
            + ". Nie wygenerowano niepełnej komendy CLI."
        )
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _predicate(raw_segment: str) -> tuple[str, Optional[str]]:
    match = _PREDICATE.fullmatch(raw_segment)
    if not match:
        raise ValidationError(f"Hand Mode nie obsługuje segmentu XPath {raw_segment!r}.")
    return match.group(1), match.group(2)


def xpath_cli_tokens(xpath: str) -> list[str]:
    """Translate the conservative Toolbox XPath subset into PAN-OS CLI tokens."""

    parts = _split_xpath(xpath)
    if not parts or parts[0] != "config":
        raise ValidationError("Hand Mode wymaga XPath zaczynającego się od /config.")
    tokens: list[str] = []
    index = 1
    while index < len(parts):
        tag, predicate = _predicate(parts[index])

        # Both the Panorama root and a template's embedded firewall config use
        # <devices><entry name="localhost.localdomain">.  Neither node is a
        # token in the corresponding Panorama CLI hierarchy.
        if tag == "devices" and predicate is None:
            index += 1
            if index < len(parts):
                next_tag, next_predicate = _predicate(parts[index])
                if next_tag == "entry" and (
                    next_predicate is None or next_predicate.startswith("@name=")
                ):
                    index += 1
            continue

        if tag == "entry":
            if not predicate or not predicate.startswith("@name="):
                raise ValidationError(
                    f"Hand Mode nie może ustalić nazwy entry w XPath {xpath!r}."
                )
            tokens.append(
                quote_cli(
                    decode_xpath_literal(predicate[len("@name=") :]),
                    context="nazwa entry z XPath",
                )
            )
        elif tag == "member":
            if predicate is None:
                # XML API /member means the whole list; CLI expresses that by
                # stopping at the owning field rather than using a member token.
                pass
            elif predicate.startswith("text()="):
                tokens.append(
                    quote_cli(
                        decode_xpath_literal(predicate[len("text()=") :]),
                        context="wartość member z XPath",
                    )
                )
            else:
                raise ValidationError(
                    f"Hand Mode nie obsługuje predykatu member {predicate!r}."
                )
        else:
            tokens.append(tag)
            if predicate is not None:
                if not predicate.startswith("@name="):
                    raise ValidationError(
                        f"Hand Mode nie obsługuje predykatu XPath {predicate!r}."
                    )
                tokens.append(
                    quote_cli(
                        decode_xpath_literal(predicate[len("@name=") :]),
                        context=f"nazwa {tag} z XPath",
                    )
                )
        index += 1
    if not tokens:
        raise ValidationError(f"Hand Mode nie może modyfikować całego {xpath!r}.")
    return tokens


def _set_fragment_commands(
    xpath: str,
    element: str,
) -> tuple[list[str], list[str]]:
    """Render an XML API ``element`` fragment as deterministic set commands."""

    try:
        wrapper = parse_xml(f"<panos-toolbox-fragment>{element}</panos-toolbox-fragment>")
    except PanoramaResponseError as exc:  # MutationOperation already validates this.
        raise ValidationError(f"Hand Mode nie może odczytać element XML: {exc}.") from exc
    base = xpath_cli_tokens(xpath)
    commands: list[str] = []
    warnings: list[str] = []

    def walk(node: ET.Element, path: list[str], relative: list[str]) -> None:
        node_path = list(path)
        if node.tag == "entry":
            name = node.get("name")
            if not name:
                raise ValidationError(
                    "Hand Mode BLOCK: element <entry> nie zawiera atrybutu name."
                )
            node_path.append(quote_cli(name, context="nazwa entry w element XML"))
        elif node.tag == "member":
            pass
        else:
            node_path.append(node.tag)
            if "name" in node.attrib:
                node_path.append(
                    quote_cli(node.attrib["name"], context=f"atrybut name elementu {node.tag}")
                )

        ignored_attributes = sorted(set(node.attrib) - {"name"})
        if ignored_attributes:
            warnings.append(
                "CLI nie odtwarza atrybutów XML "
                + ", ".join(ignored_attributes)
                + " dla "
                + "/".join(relative or [node.tag])
                + "; pełny XML pozostaje w backupie sesji."
            )

        children = list(node)
        raw_text = node.text or ""
        if children:
            if raw_text.strip():
                raise ValidationError(
                    "Hand Mode BLOCK: mieszana zawartość tekst/XML nie ma bezpiecznego odpowiednika CLI."
                )
            for child in children:
                walk(child, node_path, [*relative, child.tag])
            return

        if not raw_text.strip():
            commands.append(" ".join(["set", *node_path]))
            return
        # Preserve leading/trailing printable characters.  Generated plans use
        # normalized values; restore fails closed if historical XML contains a
        # newline or another command-injection-capable control character.
        commands.append(
            " ".join(
                [
                    "set",
                    *node_path,
                    quote_cli(raw_text, context=f"tekst XML {'/'.join(relative or [node.tag])}"),
                ]
            )
        )

    children = list(wrapper)
    if not children:
        raise ValidationError("Hand Mode BLOCK: operacja set/edit ma pusty element XML.")
    for child in children:
        walk(child, list(base), [child.tag])
    return commands, warnings


def render_operation(operation: MutationOperation) -> tuple[list[str], list[str]]:
    if operation.action is MutationAction.DELETE:
        return [" ".join(["delete", *xpath_cli_tokens(operation.xpath)])], []
    if operation.action is MutationAction.SET:
        assert operation.element is not None
        return _set_fragment_commands(operation.xpath, operation.element)
    if operation.action is MutationAction.EDIT:
        assert operation.element is not None
        recreated, warnings = _set_fragment_commands(
            parent_xpath(operation.xpath), operation.element
        )
        return [
            " ".join(["delete", *xpath_cli_tokens(operation.xpath)]),
            *recreated,
        ], [
            "Operację XML API edit odwzorowano jako delete + set; sprawdź diff przed ręcznym commit.",
            *warnings,
        ]
    if operation.action is MutationAction.MOVE:
        tokens = ["move", *xpath_cli_tokens(operation.xpath), str(operation.where)]
        if operation.where in {"before", "after"}:
            tokens.append(quote_cli(str(operation.destination), context="cel move"))
        return [" ".join(tokens)], []
    raise ValidationError(f"Hand Mode nie obsługuje akcji {operation.action.value!r}.")


def render_mutations(
    mutations: Iterable[Mutation],
    *,
    direction: str = "forward",
    reverse_for_inverse: bool = True,
) -> HandModeRender:
    values = tuple(mutations)
    if direction not in {"forward", "inverse"}:
        raise ValueError("direction musi być forward albo inverse")
    ordered: Sequence[Mutation] = (
        tuple(reversed(values))
        if direction == "inverse" and reverse_for_inverse
        else values
    )
    records: list[HandModeCommand] = []
    warnings: list[str] = []
    for mutation in ordered:
        operations = mutation.forward if direction == "forward" else mutation.inverse
        for operation in operations:
            operation_commands, operation_warnings = render_operation(operation)
            warnings.extend(
                f"{mutation.entity_key}: {warning}" for warning in operation_warnings
            )
            for command in operation_commands:
                records.append(
                    HandModeCommand(
                        command=command,
                        mutation_id=mutation.mutation_id,
                        component_id=mutation.component_id,
                        entity_type=mutation.entity_type,
                        entity_key=mutation.entity_key,
                        causes=mutation.causes,
                        operation_action=operation.action.value,
                    )
                )
    return HandModeRender(
        commands=tuple(record.command for record in records),
        records=tuple(records),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def render_patchset(patchset: PatchSet, *, direction: str = "forward") -> HandModeRender:
    return render_mutations(patchset.mutations, direction=direction)


def _render_or_block(
    mutations: Iterable[Mutation],
    *,
    direction: str,
) -> tuple[HandModeRender, Optional[str]]:
    try:
        return render_mutations(mutations, direction=direction), None
    except ValidationError as exc:
        # Never publish a partially rendered command list.  The API PatchSet
        # remains valid, while Hand Mode is explicitly marked as blocked.
        return HandModeRender((), ()), str(exc)


def build_handmode_artifacts(
    patchset: PatchSet,
    *,
    excluded_mutations: Iterable[Mutation] = (),
    excluded_source_session_id: Optional[str] = None,
) -> tuple[HandModeArtifacts, str]:
    excluded_values = tuple(excluded_mutations)
    active, active_error = _render_or_block(patchset.mutations, direction="forward")
    rollback, rollback_error = _render_or_block(patchset.mutations, direction="inverse")
    excluded: Optional[HandModeRender] = None
    excluded_rollback: Optional[HandModeRender] = None
    excluded_error: Optional[str] = None
    excluded_rollback_error: Optional[str] = None
    if excluded_values:
        excluded, excluded_error = _render_or_block(excluded_values, direction="forward")
        excluded_rollback, excluded_rollback_error = _render_or_block(
            excluded_values, direction="inverse"
        )

    report = [
        "PanOS Toolbox — Hand Mode",
        f"PatchSet: {patchset.patch_id}",
        f"Rodzaj: {patchset.kind}",
        f"Komendy aktywnego planu: {len(active.commands)}",
        f"Komendy rollback aktywnego planu: {len(rollback.commands)}",
        "",
        "commands.txt oraz handmode_rollback.txt zawierają wyłącznie komendy trybu configure (#).",
        "Nie zawierają configure, commit ani push. Te etapy operator wykonuje i weryfikuje osobno.",
        "Przed wklejeniem: włącz CLI scripting-mode w trybie operacyjnym, przejdź do configure,",
        "wklej komendy, a następnie sprawdź pełny show | compare przed ręcznym commit.",
    ]
    if active_error:
        report.extend(["", "STATUS AKTYWNEGO HAND MODE: BLOCK", active_error])
    else:
        report.extend(["", "STATUS AKTYWNEGO HAND MODE: READY"])
    if rollback_error:
        report.extend(["", "STATUS ROLLBACK CLI: BLOCK", rollback_error])
    elif rollback.warnings:
        report.extend(["", "OSTRZEŻENIA ROLLBACK CLI:", *rollback.warnings])
    if active.warnings:
        report.extend(["", "OSTRZEŻENIA AKTYWNEGO CLI:", *active.warnings])

    if excluded_values:
        report.extend(
            [
                "",
                "ELEMENTY WYKLUCZONE — POZA AKTYWNYM PLANEM",
                f"Źródłowa sesja backupu: {excluded_source_session_id or 'patrz łańcuch parent_session_id'}",
                f"Mutacje: {len(excluded_values)}",
                f"Komendy: {len(excluded.commands) if excluded else 0}",
                "handmode_excluded_commands.txt NIE jest częścią wykonywalnego PatchSetu.",
                "Może obejmować elementy wykluczone przez operatora, Last Hit, DEFAULT lub zależności.",
                "Użycie wymaga osobnego ręcznego review i pozostanie poza automatycznym reconcile tej sesji.",
            ]
        )
        if excluded_error:
            report.extend(["STATUS WYKLUCZONEGO CLI: BLOCK", excluded_error])
        else:
            report.append("STATUS WYKLUCZONEGO CLI: MANUAL-REVIEW")
        if excluded_rollback_error:
            report.extend(["STATUS ROLLBACK WYKLUCZONYCH: BLOCK", excluded_rollback_error])
        if excluded and excluded.warnings:
            report.extend(["OSTRZEŻENIA WYKLUCZONEGO CLI:", *excluded.warnings])
        if excluded_rollback and excluded_rollback.warnings:
            report.extend(["OSTRZEŻENIA ROLLBACK WYKLUCZONYCH:", *excluded_rollback.warnings])

    return (
        HandModeArtifacts(
            active=active,
            rollback=rollback,
            excluded=excluded,
            excluded_rollback=excluded_rollback,
        ),
        "\n".join(report) + "\n",
    )


def write_handmode_artifacts(
    store,
    session_id: str,
    patchset: PatchSet,
    *,
    excluded_mutations: Iterable[Mutation] = (),
    excluded_source_session_id: Optional[str] = None,
) -> HandModeArtifacts:
    """Write immutable command-only files and their separate safety report."""

    bundle, report = build_handmode_artifacts(
        patchset,
        excluded_mutations=excluded_mutations,
        excluded_source_session_id=excluded_source_session_id,
    )
    _write_artifact_once(
        store,
        session_id,
        preferred_filename="commands.txt",
        fallback_filename="handmode_commands.txt",
        content=bundle.active.text,
        kind="handmode-cli-active",
    )
    _write_artifact_once(
        store,
        session_id,
        preferred_filename="handmode_rollback.txt",
        fallback_filename="handmode_rollback_generated.txt",
        content=bundle.rollback.text,
        kind="handmode-cli-rollback",
    )
    if bundle.excluded is not None:
        _write_artifact_once(
            store,
            session_id,
            preferred_filename="handmode_excluded_commands.txt",
            fallback_filename="handmode_excluded_commands_generated.txt",
            content=bundle.excluded.text,
            kind="handmode-cli-excluded-manual-review",
        )
        assert bundle.excluded_rollback is not None
        _write_artifact_once(
            store,
            session_id,
            preferred_filename="handmode_excluded_rollback.txt",
            fallback_filename="handmode_excluded_rollback_generated.txt",
            content=bundle.excluded_rollback.text,
            kind="handmode-cli-excluded-rollback",
        )
    _write_artifact_once(
        store,
        session_id,
        preferred_filename="handmode_instructions.txt",
        fallback_filename="handmode_instructions_generated.txt",
        content=report,
        kind="handmode-instructions",
    )
    return bundle


def write_restore_conflict_handmode_artifacts(
    store,
    session_id: str,
    cleanup_mutations: Iterable[Mutation],
    *,
    source_session_ids: Iterable[str] = (),
) -> HandModeRender:
    """Publish command-only manual restore for components rejected by 3-way merge.

    The input mutations are in their original cleanup order.  Restoring uses
    their inverse operations in reverse order; undoing that manual restore uses
    the original forward order.
    """

    values = tuple(cleanup_mutations)
    restore, restore_error = _render_or_block(values, direction="inverse")
    undo, undo_error = _render_or_block(values, direction="forward")
    _write_artifact_once(
        store,
        session_id,
        preferred_filename="handmode_conflict_restore_commands.txt",
        fallback_filename="handmode_conflict_restore_commands_generated.txt",
        content=restore.text,
        kind="handmode-cli-conflict-restore-manual-review",
    )
    _write_artifact_once(
        store,
        session_id,
        preferred_filename="handmode_conflict_restore_rollback.txt",
        fallback_filename="handmode_conflict_restore_rollback_generated.txt",
        content=undo.text,
        kind="handmode-cli-conflict-restore-rollback",
    )
    report = [
        "PanOS Toolbox — konfliktowy Restore w Hand Mode",
        "Źródłowe sesje cleanup: " + ", ".join(source_session_ids),
        f"Mutacje konfliktowe: {len(values)}",
        f"Komendy ręcznego Restore: {len(restore.commands)}",
        "",
        "UWAGA: ten plik dotyczy komponentów odrzuconych przez three-way merge.",
        "Nie jest częścią bezpiecznego PatchSetu Restore i nie wolno łączyć go w ciemno",
        "z commands.txt. Sprawdź manual_conflicts.xml, aktualny config i pełny diff.",
        "Commit oraz push pozostają ręcznymi, osobnymi decyzjami operatora.",
    ]
    if restore_error:
        report.extend(["", "STATUS RESTORE KONFLIKTÓW: BLOCK", restore_error])
    else:
        report.extend(["", "STATUS RESTORE KONFLIKTÓW: MANUAL-REVIEW"])
    if undo_error:
        report.extend(["", "STATUS ROLLBACK KONFLIKTÓW: BLOCK", undo_error])
    if restore.warnings:
        report.extend(["", "OSTRZEŻENIA RESTORE:", *restore.warnings])
    if undo.warnings:
        report.extend(["", "OSTRZEŻENIA ROLLBACK:", *undo.warnings])
    _write_artifact_once(
        store,
        session_id,
        preferred_filename="handmode_conflict_restore_instructions.txt",
        fallback_filename="handmode_conflict_restore_instructions_generated.txt",
        content="\n".join(report) + "\n",
        kind="handmode-conflict-restore-instructions",
    )
    return restore
