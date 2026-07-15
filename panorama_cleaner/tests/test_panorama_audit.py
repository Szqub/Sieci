import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from panorama_cleanup.audit import (
    audit_config,
    create_audit_directory,
    load_historical_objects,
    write_audit_artifacts,
)
from panorama_cleanup.models import InputRow, PingResult, PingStatus, ScopedName
from panorama_cleanup.panos import parse_config
from panorama_post_cleanup_audit import main


FIXTURE = Path(__file__).parent / "fixtures" / "panorama_running.xml"


def ping(ip: str, status: PingStatus) -> PingResult:
    return PingResult(ip, status, f"test {status.value}", 0.01)


class PanoramaPostCleanupAuditTests(unittest.TestCase):
    def test_no_reply_exact_object_reports_all_modeled_dependencies(self) -> None:
        model = parse_config(ET.parse(FIXTURE).getroot())
        batch = audit_config(
            model,
            ["10.0.0.1"],
            {"10.0.0.1": ping("10.0.0.1", PingStatus.NO_REPLY)},
            previous_manifests=("previous/manifest.json",),
        )
        result = batch.results["10.0.0.1"]
        self.assertEqual(
            "ALERT_POZOSTAL_DOKLADNY_OBIEKT_LUB_REFERENCJA", result.status
        )
        self.assertEqual(["TARGET_A"], [item.name for item in result.exact_objects])
        target = result.exact_objects[0]
        self.assertIn("shared/G-MIX", target.groups)
        self.assertIn("shared/G-OUTER", target.groups)
        self.assertIn("shared/pre-rulebase/security/SEC-MIX", target.rules)
        self.assertIn("shared/pre-rulebase/nat/NAT-MIX", target.rules)
        self.assertIn(
            "shared/pre-rulebase/application-override/APP-MIX", target.rules
        )
        self.assertEqual(
            {"NET_CONTAINS", "RANGE_CONTAINS"},
            {item.name for item in result.containing_objects},
        )

    def test_replied_exact_object_is_expected_to_remain(self) -> None:
        model = parse_config(ET.parse(FIXTURE).getroot())
        batch = audit_config(
            model,
            ["10.0.0.1"],
            {"10.0.0.1": ping("10.0.0.1", PingStatus.REPLIED)},
            previous_manifests=("previous/manifest.json",),
        )
        self.assertEqual(
            "OCZEKIWANIE_POZOSTAWIONY_ICMP",
            batch.results["10.0.0.1"].status,
        )
        self.assertFalse(batch.review_required)

    def test_replied_exact_object_does_not_hide_dangling_historical_reference(
        self,
    ) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address><entry name="CURRENT">
                <ip-netmask>10.0.0.1/32</ip-netmask>
              </entry></address>
              <address-group><entry name="G">
                <static><member>OLD</member></static>
              </entry></address-group>
            </shared></config>
            """
        )
        model = parse_config(config)
        batch = audit_config(
            model,
            ["10.0.0.1"],
            {"10.0.0.1": ping("10.0.0.1", PingStatus.REPLIED)},
            historical_objects={"10.0.0.1": {ScopedName("shared", "OLD")}},
            previous_manifests=("previous/manifest.json",),
        )
        result = batch.results["10.0.0.1"]
        self.assertEqual(
            "ALERT_ICMP_POZOSTALA_REFERENCJA_PO_USUNIETEJ_NAZWIE",
            result.status,
        )
        self.assertEqual("CURRENT", result.exact_objects[0].name)
        self.assertEqual(1, len(result.historical_name_references))

    def test_replied_exact_literal_is_expected_to_remain(self) -> None:
        config = ET.fromstring(
            """
            <config><shared><pre-rulebase><security><rules><entry name="SEC">
              <source><member>10.0.0.1</member></source>
              <destination><member>any</member></destination>
            </entry></rules></security></pre-rulebase></shared></config>
            """
        )
        model = parse_config(config)
        batch = audit_config(
            model,
            ["10.0.0.1"],
            {"10.0.0.1": ping("10.0.0.1", PingStatus.REPLIED)},
            previous_manifests=("previous/manifest.json",),
        )
        result = batch.results["10.0.0.1"]
        self.assertEqual("OCZEKIWANIE_POZOSTAWIONY_ICMP", result.status)
        self.assertEqual(1, len(result.literal_references))
        self.assertFalse(batch.review_required)

    def test_missing_previous_run_is_explicitly_incomplete(self) -> None:
        model = parse_config(ET.fromstring("<config><shared/></config>"))
        batch = audit_config(
            model,
            ["10.0.0.1"],
            {"10.0.0.1": ping("10.0.0.1", PingStatus.NO_REPLY)},
        )
        self.assertEqual("CZYSTO", batch.results["10.0.0.1"].status)
        self.assertFalse(batch.historical_name_coverage)
        self.assertTrue(batch.review_required)
        self.assertTrue(
            any("HISTORIA_NIEPODANA" in warning for warning in batch.warnings)
        )

    def test_deleted_no_reply_object_is_clean_when_history_has_no_dangling_ref(
        self,
    ) -> None:
        model = parse_config(ET.fromstring("<config><shared/></config>"))
        old = ScopedName("shared", "OLD")
        batch = audit_config(
            model,
            ["10.0.0.1"],
            {"10.0.0.1": ping("10.0.0.1", PingStatus.NO_REPLY)},
            historical_objects={"10.0.0.1": {old}},
            previous_manifests=("previous/manifest.json",),
        )
        result = batch.results["10.0.0.1"]
        self.assertEqual("CZYSTO", result.status)
        self.assertEqual(("shared/OLD",), result.historical_objects)
        self.assertFalse(batch.review_required)

    def test_replied_ip_whose_historical_object_is_gone_is_alerted(self) -> None:
        model = parse_config(ET.fromstring("<config><shared/></config>"))
        batch = audit_config(
            model,
            ["10.0.0.1"],
            {"10.0.0.1": ping("10.0.0.1", PingStatus.REPLIED)},
            historical_objects={"10.0.0.1": {ScopedName("shared", "OLD")}},
            previous_manifests=("previous/manifest.json",),
        )
        self.assertEqual(
            "ALERT_ICMP_ODPOWIADA_OBIEKT_USUNIETY",
            batch.results["10.0.0.1"].status,
        )

    def test_direct_security_app_override_and_nat_literals_are_reported(self) -> None:
        config = ET.fromstring(
            """
            <config><shared><pre-rulebase>
              <security><rules><entry name="SEC">
                <source><member>10.0.0.1</member></source>
                <destination><member>any</member></destination>
              </entry></rules></security>
              <application-override><rules><entry name="APP">
                <source><member>any</member></source>
                <destination><member>10.0.0.1/32</member></destination>
              </entry></rules></application-override>
              <nat><rules><entry name="NAT">
                <source><member>any</member></source>
                <destination><member>any</member></destination>
                <destination-translation>
                  <translated-address>10.0.0.0/24</translated-address>
                </destination-translation>
              </entry></rules></nat>
            </pre-rulebase></shared></config>
            """
        )
        model = parse_config(config)
        batch = audit_config(
            model,
            ["10.0.0.1"],
            {"10.0.0.1": ping("10.0.0.1", PingStatus.NO_REPLY)},
            previous_manifests=("previous/manifest.json",),
        )
        result = batch.results["10.0.0.1"]
        self.assertEqual(
            "ALERT_POZOSTAL_DOKLADNY_OBIEKT_LUB_REFERENCJA", result.status
        )
        self.assertEqual(
            {"application-override", "nat", "security"},
            {item.policy_type for item in result.literal_references},
        )
        self.assertEqual(
            {"exact", "containing"},
            {item.relation for item in result.literal_references},
        )

    def test_previous_manifest_finds_dangling_references_by_deleted_name(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address-group><entry name="G"><static><member>OLD</member></static></entry></address-group>
              <pre-rulebase><security><rules><entry name="SEC">
                <source><member>OLD</member></source><destination><member>any</member></destination>
              </entry></rules></security><nat><rules><entry name="NAT">
                <source><member>any</member></source><destination><member>any</member></destination>
                <destination-translation><translated-address>OLD</translated-address></destination-translation>
              </entry></rules></nat></pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        batch = audit_config(
            model,
            ["10.0.0.1"],
            {"10.0.0.1": ping("10.0.0.1", PingStatus.NO_REPLY)},
            historical_objects={
                "10.0.0.1": {ScopedName("shared", "OLD")}
            },
            previous_manifests=("previous/manifest.json",),
        )
        result = batch.results["10.0.0.1"]
        self.assertEqual(
            "ALERT_POZOSTAL_DOKLADNY_OBIEKT_LUB_REFERENCJA", result.status
        )
        self.assertEqual(3, len(result.historical_name_references))
        self.assertTrue(
            all(
                "history=shared/OLD" in item.detail
                for item in result.historical_name_references
            )
        )

    def test_previous_manifest_maps_backup_value_to_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp) / "run_010126_10_00_00"
            run_dir.mkdir()
            (run_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "backups": [
                            {
                                "entity_type": "address",
                                "location": "DG-A",
                                "name": "OLD",
                                "object_type": "ip-netmask",
                                "raw_value": "10.0.0.1/32",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            history, manifests = load_historical_objects(
                [run_dir], ["10.0.0.1", "10.0.0.2"]
            )
        self.assertEqual({ScopedName("DG-A", "OLD")}, history["10.0.0.1"])
        self.assertEqual(set(), history["10.0.0.2"])
        self.assertEqual(1, len(manifests))

    def test_artifacts_are_read_only_and_include_exact_paths(self) -> None:
        model = parse_config(ET.parse(FIXTURE).getroot())
        pings = {"10.0.0.1": ping("10.0.0.1", PingStatus.NO_REPLY)}
        batch = audit_config(
            model,
            ["10.0.0.1"],
            pings,
            previous_manifests=("previous/manifest.json",),
        )
        with tempfile.TemporaryDirectory() as temp:
            audit_dir = create_audit_directory(
                Path(temp), datetime(2026, 7, 14, 10, 0, tzinfo=timezone.utc)
            )
            write_audit_artifacts(
                audit_dir=audit_dir,
                batch=batch,
                rows=[InputRow(1, "10.0.0.1", "10.0.0.1", True)],
                pings=pings,
                metadata={"script": "test"},
            )
            detailed = (audit_dir / "audit_detailed.txt").read_text(
                encoding="utf-8"
            )
            manifest = json.loads(
                (audit_dir / "audit_manifest.json").read_text(encoding="utf-8")
            )
            self.assertIn("shared/pre-rulebase/security/SEC-MIX", detailed)
            self.assertIn("/config/shared/address/entry", detailed)
            self.assertFalse((audit_dir / "commands.txt").exists())
            self.assertFalse(manifest["changes_executed"])
            self.assertFalse(manifest["commands_generated"])

    def test_main_fetches_exactly_running_and_candidate_and_audits_running(self) -> None:
        running = ET.fromstring(
            """
            <config version="10.2.16-h4"><shared><address>
              <entry name="LEFT"><ip-netmask>10.0.0.1/32</ip-netmask></entry>
            </address></shared></config>
            """
        )

        class FakeClient:
            def __init__(self):
                self.snapshot_call_count = 0
                self.actions = []

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def authenticate(self, password: str) -> None:
                self.password_was_supplied = bool(password)

            def fetch_config(self, action: str):
                self.actions.append(action)
                self.snapshot_call_count += 1
                snapshot = ET.fromstring(ET.tostring(running))
                if action == "get":
                    snapshot.find("./shared/address/entry/ip-netmask").text = (
                        "203.0.113.1/32"
                    )
                return snapshot

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            host_file = base / "panorama_host.txt"
            ip_file = base / "ip.txt"
            previous = base / "previous"
            previous.mkdir()
            (previous / "manifest.json").write_text(
                json.dumps({"backups": []}), encoding="utf-8"
            )
            host_file.write_text(
                "host=192.0.2.10\nusername=readonly\nssl=no\n", encoding="utf-8"
            )
            ip_file.write_text("10.0.0.1\n", encoding="utf-8")
            client = FakeClient()
            with mock.patch(
                "panorama_post_cleanup_audit.PanoramaXMLAPI", return_value=client
            ), mock.patch(
                "panorama_post_cleanup_audit.obtain_password", return_value="secret"
            ), mock.patch(
                "panorama_post_cleanup_audit.ping_many",
                return_value={
                    "10.0.0.1": ping("10.0.0.1", PingStatus.NO_REPLY)
                },
            ):
                code = main(
                    [
                        "--host-file",
                        str(host_file),
                        "--ip-file",
                        str(ip_file),
                        "--output-dir",
                        str(base),
                        "--previous-run",
                        str(previous),
                    ]
                )
            self.assertEqual(2, code)
            self.assertEqual(["show", "get"], client.actions)
            audit_dir = next(base.glob("audit_*"))
            results = json.loads(
                (audit_dir / "audit_results.json").read_text(encoding="utf-8")
            )
            manifest = json.loads(
                (audit_dir / "audit_manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual("LEFT", results["10.0.0.1"]["exact_objects"][0]["name"])
            self.assertTrue(manifest["candidate_snapshot_compared"])
            self.assertTrue(manifest["candidate_comparison"]["different"])
            self.assertTrue(manifest["candidate_comparison"]["relevant_different"])
            self.assertFalse((audit_dir / "commands.txt").exists())


if __name__ == "__main__":
    unittest.main()
