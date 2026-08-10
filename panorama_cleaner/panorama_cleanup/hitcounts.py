"""Read-only Panorama rule hit-count collection and 14-day classification."""

from __future__ import annotations

import concurrent.futures
import csv
import io
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Mapping, Optional

from .models import RuleHitCount, RuleKey, SnapshotError, TransportError


DEFAULT_RECENT_DAYS = 14


def collect_rule_hit_counts(
    client: object,
    rules: Iterable[RuleKey],
    *,
    now: Optional[datetime] = None,
    recent_days: int = DEFAULT_RECENT_DAYS,
    workers: int = 8,
    progress_callback: Optional[Callable[[int, int, RuleKey], None]] = None,
) -> Dict[RuleKey, RuleHitCount]:
    """Query relevant policies concurrently with a bounded Panorama load."""

    if recent_days < 1 or recent_days > 3650:
        raise ValueError("recent_days musi być w zakresie 1..3650")
    if workers < 1 or workers > 16:
        raise ValueError("workers musi być w zakresie 1..16")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    selected = tuple(sorted(set(rules)))
    if not selected:
        return {}

    def read_one(rule: RuleKey) -> tuple[RuleKey, RuleHitCount]:
        command = build_hit_count_command(
            rule.location,
            rule.rulebase,
            rule.policy_type,
            rule.name,
        )
        try:
            response = client.run_op_show(command)
            return rule, _parse_rule_response(
                response, rule, current, recent_days
            )
        except TransportError as exc:
            return rule, _error_result(
                rule, "Transport XML API podczas odczytu last-hit: " + str(exc)
            )
        except SnapshotError as exc:
            detail = "Odpowiedź last-hit odrzucona: " + str(exc)
            return rule, _error_result(rule, detail)
        except Exception as exc:  # hit-count must never block command publication
            detail = (
                "Nieoczekiwany błąd pomocniczego odczytu last-hit "
                f"({type(exc).__name__}): {exc}"
            )
            return rule, _error_result(rule, detail)

    results: Dict[RuleKey, RuleHitCount] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(workers, len(selected)),
        thread_name_prefix="panos-last-hit",
    ) as pool:
        futures = [pool.submit(read_one, rule) for rule in selected]
        for completed, future in enumerate(
            concurrent.futures.as_completed(futures), start=1
        ):
            rule, result = future.result()
            results[rule] = result
            if progress_callback is not None:
                try:
                    progress_callback(completed, len(selected), rule)
                except Exception:
                    pass
    return {rule: results[rule] for rule in selected}


def build_hit_count_command(
    location: str,
    rulebase: str,
    policy_type: str,
    rule_name: str,
) -> ET.Element:
    if rulebase not in {"pre-rulebase", "post-rulebase"}:
        raise ValueError(f"Nieobsługiwany rulebase hit-count: {rulebase}")
    if policy_type not in {"security", "nat", "application-override"}:
        raise ValueError(f"Nieobsługiwany typ polityki hit-count: {policy_type}")
    if not rule_name:
        raise ValueError("Nazwa polityki hit-count nie może być pusta")
    command = ET.Element("show")
    node = ET.SubElement(command, "rule-hit-count")
    if location == "shared":
        node = ET.SubElement(node, "shared")
    else:
        node = ET.SubElement(node, "device-group")
        node = ET.SubElement(node, "entry", {"name": location})
    node = ET.SubElement(node, rulebase)
    node = ET.SubElement(node, "entry", {"name": policy_type})
    node = ET.SubElement(node, "rules")
    requested = ET.SubElement(node, "rule-name")
    ET.SubElement(requested, "entry", {"name": rule_name})
    return command


def _parse_rule_response(
    response: ET.Element,
    rule: RuleKey,
    now: datetime,
    recent_days: int,
) -> RuleHitCount:
    # A detailed Panorama rule-name query can return one observation per
    # managed firewall/VSYS.  The enclosing entry names are therefore not
    # necessarily the policy name.  Select only nodes that directly own hit
    # fields and aggregate the newest last-hit conservatively.
    entries = [
        element
        for element in response.iter()
        if element.find("./hit-count") is not None
        or element.find("./last-hit-timestamp") is not None
    ]
    if not entries:
        return RuleHitCount(
            rule=rule,
            status="NOT_FOUND",
            hit_count=None,
            last_hit_timestamp=None,
            last_hit_utc=None,
            age_days=None,
            latest=None,
            detail="Panorama nie zwróciła szczegółowych statystyk dla reguły.",
        )

    observations = [
        _parse_entry(rule, entry, now, recent_days) for entry in entries
    ]
    for index, observation in enumerate(observations, start=1):
        if observation.status == "INVALID":
            return RuleHitCount(
                rule=rule,
                status="INVALID",
                hit_count=None,
                last_hit_timestamp=None,
                last_hit_utc=None,
                age_days=None,
                latest=None,
                detail=(
                    f"Niepoprawny odczyt urządzenie/VSYS {index}/{len(entries)}: "
                    + observation.detail
                ),
            )

    aggregate_hit_count = sum(
        observation.hit_count or 0 for observation in observations
    )
    aggregate_timestamp = max(
        observation.last_hit_timestamp or 0 for observation in observations
    )
    if all(observation.latest is True for observation in observations):
        aggregate_latest: Optional[bool] = True
    elif any(observation.latest is False for observation in observations):
        aggregate_latest = False
    else:
        aggregate_latest = None

    aggregate = ET.Element("entry")
    ET.SubElement(aggregate, "hit-count").text = str(aggregate_hit_count)
    ET.SubElement(aggregate, "last-hit-timestamp").text = str(
        aggregate_timestamp
    )
    if aggregate_latest is not None:
        ET.SubElement(aggregate, "latest").text = (
            "yes" if aggregate_latest else "no"
        )
    result = _parse_entry(rule, aggregate, now, recent_days)
    return RuleHitCount(
        rule=result.rule,
        status=result.status,
        hit_count=result.hit_count,
        last_hit_timestamp=result.last_hit_timestamp,
        last_hit_utc=result.last_hit_utc,
        age_days=result.age_days,
        latest=result.latest,
        detail=(
            result.detail
            + f" Odczyty urządzenie/VSYS: {len(entries)}; hit-count jest sumą, "
            "a last-hit najnowszym timestampem."
        ),
    )


def _parse_entry(
    rule: RuleKey,
    entry: ET.Element,
    now: datetime,
    recent_days: int,
) -> RuleHitCount:
    hit_count = _optional_nonnegative_int(entry.findtext("hit-count"))
    timestamp = _optional_nonnegative_int(entry.findtext("last-hit-timestamp"))
    latest_text = (entry.findtext("latest") or "").strip().casefold()
    latest = True if latest_text == "yes" else False if latest_text == "no" else None
    if hit_count is None:
        return RuleHitCount(
            rule, "INVALID", None, timestamp, None, None, latest,
            "Brak poprawnego pola hit-count w odpowiedzi Panoramy.",
        )
    if timestamp is None:
        return RuleHitCount(
            rule, "INVALID", hit_count, None, None, None, latest,
            "Brak poprawnego pola last-hit-timestamp w odpowiedzi Panoramy.",
        )
    if timestamp == 0:
        if hit_count > 0:
            return RuleHitCount(
                rule=rule,
                status="INVALID",
                hit_count=hit_count,
                last_hit_timestamp=timestamp or 0,
                last_hit_utc=None,
                age_days=None,
                latest=latest,
                detail=(
                    "Niespójna odpowiedź: hit-count > 0, ale brak "
                    "last-hit-timestamp."
                ),
            )
        return RuleHitCount(
            rule=rule,
            status="NEVER" if latest is True else "NOT_LATEST",
            hit_count=hit_count,
            last_hit_timestamp=timestamp or 0,
            last_hit_utc=None,
            age_days=None,
            latest=latest,
            detail=(
                "Brak zarejestrowanego last-hit; bez czasu utworzenia/resetu "
                "nie dowodzi to pełnych 14 dni obserwacji."
                if latest is True
                else "Panorama nie potwierdziła latest=yes i nie zwróciła last-hit."
            ),
        )
    try:
        last_hit = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return RuleHitCount(
            rule, "INVALID", hit_count, timestamp, None, None, latest,
            "Niepoprawny Unix timestamp last-hit.",
        )
    age_seconds = (now - last_hit).total_seconds()
    if age_seconds < -300:
        return RuleHitCount(
            rule, "INVALID", hit_count, timestamp, last_hit.isoformat(),
            age_seconds / 86400.0, latest,
            "Last-hit znajduje się w przyszłości względem czasu skryptu.",
        )
    age_days = max(0.0, age_seconds / 86400.0)
    status = "RECENT" if age_days <= recent_days else "STALE"
    detail = (
        f"Last-hit z ostatnich {recent_days} dni — wymaga weryfikacji."
        if status == "RECENT"
        else f"Last-hit starszy niż {recent_days} dni."
    )
    if latest is not True:
        status = "NOT_LATEST"
        detail += (
            " Panorama nie potwierdziła danych jako latest=yes — wymaga "
            "weryfikacji."
        )
    return RuleHitCount(
        rule, status, hit_count, timestamp, last_hit.isoformat(), age_days, latest, detail
    )


def _optional_nonnegative_int(value: Optional[str]) -> Optional[int]:
    try:
        parsed = int((value or "").strip())
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _error_result(rule: RuleKey, detail: str) -> RuleHitCount:
    return RuleHitCount(rule, "ERROR", None, None, None, None, None, detail)


def hit_count_csv(results: Mapping[RuleKey, RuleHitCount]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "location", "rulebase", "policy_type", "rule", "status",
            "hit_count", "last_hit_utc", "age_days", "latest", "detail",
        ]
    )
    for key, result in sorted(results.items()):
        writer.writerow(
            [
                key.location,
                key.rulebase,
                key.policy_type,
                key.name,
                result.status,
                "" if result.hit_count is None else result.hit_count,
                result.last_hit_utc or "",
                "" if result.age_days is None else f"{result.age_days:.3f}",
                "" if result.latest is None else ("yes" if result.latest else "no"),
                result.detail,
            ]
        )
    return output.getvalue()


def hit_count_text(
    results: Mapping[RuleKey, RuleHitCount], statuses: Iterable[str], heading: str
) -> str:
    selected = set(statuses)
    lines = [heading, "=" * len(heading), ""]
    matches = [item for item in sorted(results.items()) if item[1].status in selected]
    if not matches:
        lines.append("brak")
    for key, result in matches:
        lines.extend(
            [
                f"{key.location}/{key.rulebase}/{key.policy_type}/{key.name}",
                f"  status: {result.status}",
                f"  hit-count: {result.hit_count if result.hit_count is not None else 'brak'}",
                f"  last-hit UTC: {result.last_hit_utc or 'brak'}",
                (
                    f"  wiek dni: {result.age_days:.3f}"
                    if result.age_days is not None
                    else "  wiek dni: brak"
                ),
                f"  latest: {result.latest if result.latest is not None else 'brak'}",
                f"  szczegóły: {result.detail}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"
