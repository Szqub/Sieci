from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET
import threading
import time
from datetime import datetime, timedelta, timezone

from panorama_cleanup.hitcounts import (
    build_hit_count_command,
    collect_rule_hit_counts,
)
from panorama_cleanup.models import RuleKey


class FakeHitCountClient:
    def __init__(
        self,
        response: ET.Element | Exception | dict[str, ET.Element | Exception],
    ) -> None:
        self.response = response
        self.commands: list[ET.Element] = []

    def run_op_show(self, command: ET.Element) -> ET.Element:
        self.commands.append(command)
        response = self.response
        if isinstance(response, dict):
            requested = command.find(".//rule-name/entry")
            name = requested.get("name") if requested is not None else None
            response = response.get(name or "", _response(""))
        if isinstance(response, Exception):
            raise response
        return response


def _response(entries: str) -> ET.Element:
    return ET.fromstring(
        "<response status='success'><result><rule-hit-count><shared>"
        "<pre-rulebase><entry name='security'><rules>"
        + entries
        + "</rules></entry></pre-rulebase></shared></rule-hit-count>"
        "</result></response>"
    )


class HitCountTests(unittest.TestCase):
    def test_builds_panorama_shared_and_device_group_commands(self) -> None:
        shared = ET.tostring(
            build_hit_count_command(
                "shared", "pre-rulebase", "security", "A"
            ),
            encoding="unicode",
        )
        self.assertEqual(
            "<show><rule-hit-count><shared><pre-rulebase><entry "
            'name="security"><rules><rule-name><entry name="A" /></rule-name>'
            "</rules></entry></pre-rulebase></shared></rule-hit-count></show>",
            shared,
        )

        device_group = ET.tostring(
            build_hit_count_command(
                "DG PROD",
                "post-rulebase",
                "application-override",
                "APP",
            ),
            encoding="unicode",
        )
        self.assertIn('<device-group><entry name="DG PROD">', device_group)
        self.assertIn("<post-rulebase>", device_group)
        self.assertIn('<entry name="application-override">', device_group)
        self.assertIn('<rule-name><entry name="APP" /></rule-name>', device_group)

    def test_classifies_recent_stale_never_missing_and_not_latest(self) -> None:
        now = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)
        recent = int((now - timedelta(days=7)).timestamp())
        stale = int((now - timedelta(days=15)).timestamp())
        client = FakeHitCountClient(
            {
                "RECENT": _response(
                    f"<entry name='FW-1'><latest>yes</latest>"
                    f"<hit-count>3</hit-count>"
                    f"<last-hit-timestamp>{recent}</last-hit-timestamp></entry>"
                ),
                "STALE": _response(
                    f"<entry name='FW-1'><latest>yes</latest>"
                    f"<hit-count>7</hit-count>"
                    f"<last-hit-timestamp>{stale}</last-hit-timestamp></entry>"
                ),
                "NEVER": _response(
                    "<entry name='FW-1'><latest>yes</latest>"
                    "<hit-count>0</hit-count>"
                    "<last-hit-timestamp>0</last-hit-timestamp></entry>"
                ),
                "OLD-DATA": _response(
                    f"<entry name='FW-1'><latest>no</latest>"
                    f"<hit-count>8</hit-count>"
                    f"<last-hit-timestamp>{stale}</last-hit-timestamp></entry>"
                ),
            }
        )
        names = ["RECENT", "STALE", "NEVER", "MISSING", "OLD-DATA"]
        rules = {
            RuleKey("shared", "pre-rulebase", "security", name)
            for name in names
        }

        results = collect_rule_hit_counts(client, rules, now=now)

        self.assertEqual(5, len(client.commands))
        self.assertEqual("RECENT", results[next(k for k in rules if k.name == "RECENT")].status)
        self.assertEqual("STALE", results[next(k for k in rules if k.name == "STALE")].status)
        self.assertEqual("NEVER", results[next(k for k in rules if k.name == "NEVER")].status)
        self.assertEqual(
            "NOT_FOUND", results[next(k for k in rules if k.name == "MISSING")].status
        )
        old_data = results[next(k for k in rules if k.name == "OLD-DATA")]
        self.assertEqual("NOT_LATEST", old_data.status)
        self.assertTrue(old_data.requires_review)

    def test_aggregates_newest_hit_across_managed_firewalls_and_vsys(self) -> None:
        now = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)
        stale = int((now - timedelta(days=40)).timestamp())
        recent = int((now - timedelta(days=2)).timestamp())
        response = _response(
            "<entry name='SERIAL-1'><vsys>vsys1</vsys><latest>yes</latest>"
            "<hit-count>2</hit-count>"
            f"<last-hit-timestamp>{stale}</last-hit-timestamp></entry>"
            "<entry name='SERIAL-2'><vsys>vsys2</vsys><latest>yes</latest>"
            "<hit-count>5</hit-count>"
            f"<last-hit-timestamp>{recent}</last-hit-timestamp></entry>"
        )
        client = FakeHitCountClient(response)
        rule = RuleKey("DG", "post-rulebase", "nat", "NAT-1")

        result = collect_rule_hit_counts(client, [rule], now=now)[rule]

        self.assertEqual("RECENT", result.status)
        self.assertEqual(7, result.hit_count)
        self.assertEqual(recent, result.last_hit_timestamp)
        self.assertIn("Odczyty urządzenie/VSYS: 2", result.detail)

    def test_missing_timestamp_is_invalid_not_never(self) -> None:
        client = FakeHitCountClient(
            _response(
                "<entry name='FW-1'><latest>yes</latest>"
                "<hit-count>0</hit-count></entry>"
            )
        )
        rule = RuleKey("shared", "pre-rulebase", "security", "RULE-1")

        result = collect_rule_hit_counts(client, [rule])[rule]

        self.assertEqual("INVALID", result.status)
        self.assertIn("last-hit-timestamp", result.detail)

    def test_unexpected_hit_count_failure_becomes_nonblocking_error_result(self) -> None:
        client = FakeHitCountClient(RuntimeError("temporary failure"))
        rule = RuleKey("shared", "pre-rulebase", "nat", "NAT-1")

        result = collect_rule_hit_counts(client, [rule])[rule]

        self.assertEqual("ERROR", result.status)
        self.assertTrue(result.requires_review)
        self.assertIn("RuntimeError", result.detail)

    def test_queries_many_rules_with_bounded_parallelism(self) -> None:
        class ConcurrentClient:
            def __init__(self) -> None:
                self.lock = threading.Lock()
                self.active = 0
                self.maximum_active = 0

            def run_op_show(self, _command: ET.Element) -> ET.Element:
                with self.lock:
                    self.active += 1
                    self.maximum_active = max(self.maximum_active, self.active)
                try:
                    time.sleep(0.02)
                    return _response(
                        "<entry name='FW-1'><latest>yes</latest>"
                        "<hit-count>0</hit-count>"
                        "<last-hit-timestamp>0</last-hit-timestamp></entry>"
                    )
                finally:
                    with self.lock:
                        self.active -= 1

        client = ConcurrentClient()
        rules = {
            RuleKey("shared", "pre-rulebase", "security", f"RULE-{index}")
            for index in range(12)
        }

        results = collect_rule_hit_counts(client, rules, workers=4)

        self.assertEqual(len(results), 12)
        self.assertGreater(client.maximum_active, 1)
        self.assertLessEqual(client.maximum_active, 4)


if __name__ == "__main__":
    unittest.main()
