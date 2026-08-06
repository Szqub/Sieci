from __future__ import annotations

import subprocess
import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from panos_toolbox.diffing import compare_configs
from panos_toolbox.errors import SessionError
from panos_toolbox.models import (
    ApiStage,
    Mutation,
    MutationAction,
    MutationOperation,
    PatchSet,
    SessionState,
)
from panos_toolbox.profile import PanoramaProfile
from panos_toolbox.service import (
    PingObservation,
    _ping_one,
    plan_cleanup_session,
    plan_restore_session,
)
from panos_toolbox.sessions import SessionStore
from panos_toolbox.web import _wire_cleanup_plan
from panos_toolbox.xmlutil import parse_xml


REPO_ROOT = Path(__file__).resolve().parents[3]


class PlanningReader:
    def __init__(self, config):
        self.profile = PanoramaProfile(
            "pano", "admin", api_max_stage=ApiStage.READ_ONLY
        )
        self.config = config

    def fetch_config(self, _kind):
        return copy.deepcopy(self.config)

    def change_summary(self):
        return parse_xml('<response status="success"><result /></response>')

    def run_op_show(self, _command):
        return parse_xml(
            '<response status="success"><result><rule-hit-count><rules>'
            '<entry name="result"><latest>yes</latest><hit-count>1</hit-count>'
            '<last-hit-timestamp>1</last-hit-timestamp></entry>'
            '</rules></rule-hit-count></result></response>'
        )


class SplitPlanningReader(PlanningReader):
    def __init__(self, running, candidate):
        super().__init__(running)
        self.running = running
        self.candidate = candidate

    def fetch_config(self, kind):
        return copy.deepcopy(self.running if kind == "running" else self.candidate)


class IcmpClassificationTests(unittest.TestCase):
    @mock.patch("panos_toolbox.service.subprocess.run")
    def test_process_error_is_not_treated_as_no_reply(self, run):
        run.return_value = subprocess.CompletedProcess(
            ["ping"], 2, stdout=b"General failure", stderr=b""
        )
        self.assertEqual(_ping_one("192.0.2.1", 1000).status, "ERROR")

        run.return_value = subprocess.CompletedProcess(
            ["ping"], 1, stdout=b"Request timed out", stderr=b""
        )
        self.assertEqual(_ping_one("192.0.2.1", 1000).status, "NO_REPLY")


class InformationalDiffTests(unittest.TestCase):
    def test_native_semantic_mismatch_never_blocks(self):
        running = parse_xml("<config><shared /></config>")
        candidate = parse_xml("<config><shared /></config>")
        native = parse_xml(
            '<response status="success"><result><entry name="change"><xpath>/config/shared</xpath></entry></result></response>'
        )
        result = compare_configs(running, candidate, native)
        self.assertFalse(result["blocking"])
        self.assertTrue(result["warnings"])


class PlanningReportTests(unittest.TestCase):
    def fixture(self):
        return parse_xml(
            (REPO_ROOT / "panorama_cleaner/tests/fixtures/panorama_running.xml").read_text(
                encoding="utf-8"
            )
        )

    @mock.patch("panos_toolbox.service._last_hit_summary")
    @mock.patch("panos_toolbox.service.ping_ips")
    def test_recent_hit_warns_without_blocking_and_reports_are_complete(
        self, ping_mock, hit_mock
    ):
        ip = "203.0.113.10"
        ping_mock.return_value = {
            ip: PingObservation(ip, "BYPASSED", "test", 0.0)
        }
        hit_mock.return_value = {
            "recent_days": 14,
            "records": [],
            "review_count": 1,
            "recent_hit_count": 1,
            "error_or_unknown_count": 0,
            "blocking": False,
        }
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            result = plan_cleanup_session(
                store, PlanningReader(self.fixture()), (ip,), no_ping=True
            )
            session = Path(temporary) / result["session_id"]
            self.assertTrue((session / "commands.txt").is_file())
            self.assertIn(ip, (session / "raport_krotki.txt").read_text(encoding="utf-8"))
            detail = (session / "raport_szczegolowy.txt").read_text(encoding="utf-8")
            self.assertIn("Polityka:", detail)
            manifest = store.load_manifest(result["session_id"])
            self.assertFalse(manifest["last_hit"]["blocking"])
            self.assertTrue(any("last-hit" in item for item in manifest["warnings"]))

    @mock.patch("panos_toolbox.service.ping_ips")
    def test_icmp_error_skips_only_ip_and_still_writes_reports(self, ping_mock):
        ip = "203.0.113.10"
        ping_mock.return_value = {
            ip: PingObservation(ip, "ERROR", "process failure", 0.0)
        }
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            result = plan_cleanup_session(
                store, PlanningReader(self.fixture()), (ip,)
            )
            session = Path(temporary) / result["session_id"]
            self.assertEqual((session / "commands.txt").read_text(encoding="utf-8"), "")
            short = (session / "raport_krotki.txt").read_text(encoding="utf-8")
            self.assertIn("POMINIĘTO_BŁĄD_ICMP", short)
            self.assertEqual(result["mutation_count"], 0)

    @mock.patch("panos_toolbox.service._last_hit_summary")
    def test_named_policy_group_and_object_are_saved_in_manifest_and_reports(self, hit_mock):
        hit_mock.return_value = {
            "recent_days": 14,
            "records": [],
            "review_count": 0,
            "recent_hit_count": 0,
            "error_or_unknown_count": 0,
            "blocking": False,
        }
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            result = plan_cleanup_session(
                store,
                PlanningReader(self.fixture()),
                (),
                address_objects=("PARENT_ONLY",),
                address_groups=("G-INNER",),
                policies=("SEC-MIX",),
                no_ping=True,
            )
            manifest = store.load_manifest(result["session_id"])
            self.assertEqual(manifest["input_targets"]["address_objects"], ["PARENT_ONLY"])
            self.assertEqual(manifest["input_targets"]["address_groups"], ["G-INNER"])
            self.assertEqual(manifest["input_targets"]["policies"], ["SEC-MIX"])
            report = (Path(temporary) / result["session_id"] / "raport_krotki.txt").read_text(encoding="utf-8")
            self.assertIn("[address-object] PARENT_ONLY: ZAPLANOWANO", report)
            self.assertIn("[address-group] G-INNER: ZAPLANOWANO", report)
            self.assertIn("[policy] SEC-MIX: ZAPLANOWANO", report)

    @mock.patch("panos_toolbox.service._last_hit_summary")
    def test_plan_reports_monotonic_progress_phases(self, hit_mock):
        hit_mock.return_value = {
            "recent_days": 14,
            "records": [],
            "review_count": 0,
            "recent_hit_count": 0,
            "error_or_unknown_count": 0,
            "blocking": False,
        }
        updates = []
        with tempfile.TemporaryDirectory() as temporary:
            plan_cleanup_session(
                SessionStore(Path(temporary), enforce_acl=False),
                PlanningReader(self.fixture()),
                (),
                address_objects=("PARENT_ONLY", "OVERRIDE"),
                no_ping=True,
                progress_callback=lambda value, message: updates.append((value, message)),
            )
        self.assertEqual(updates[-1], (100, "Plan jest gotowy"))
        self.assertEqual([value for value, _ in updates], sorted(value for value, _ in updates))
        self.assertTrue(any("running" in message for _, message in updates))

    def test_named_policy_always_collects_last_hit_before_plan_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            result = plan_cleanup_session(
                store,
                PlanningReader(self.fixture()),
                (),
                policies=("SEC-MIX",),
                no_ping=True,
            )
            records = store.load_manifest(result["session_id"])["last_hit"]["records"]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["rule"]["name"], "SEC-MIX")
            self.assertEqual(records[0]["rule"]["location"], "shared")
            self.assertEqual(records[0]["rule"]["rulebase"], "pre-rulebase")
            wire = _wire_cleanup_plan(store, result["session_id"])
            self.assertEqual(wire["addresses"][0]["targetType"], "policy")
            self.assertEqual(wire["addresses"][0]["label"], "SEC-MIX")
            self.assertEqual(wire["addresses"][0]["lastHitStatus"], "STALE")


class RestoreSessionSelectionTests(unittest.TestCase):
    @staticmethod
    def address_mutation(index, name, cause, component, depends=()):
        xpath = f"/config/shared/address/entry[@name='{name}']"
        xml = f'<entry name="{name}"><ip-netmask>{cause}/32</ip-netmask></entry>'
        return Mutation(
            mutation_id=f"mutation-{index:05d}",
            component_id=component,
            entity_type="address",
            entity_key=f"shared/{name}",
            target_xpath=xpath,
            before_xml=xml,
            after_xml=None,
            forward=(MutationOperation(MutationAction.DELETE, xpath),),
            inverse=(
                MutationOperation(
                    MutationAction.SET, "/config/shared/address", element=xml
                ),
            ),
            causes=(cause,),
            depends_on=depends,
        )

    def test_restore_by_ip_selects_full_component_not_entire_batch(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        first = self.address_mutation(1, "A", "192.0.2.1", "component-ab")
        second = self.address_mutation(
            2,
            "B",
            "192.0.2.2",
            "component-ab",
            depends=(first.mutation_id,),
        )
        third = self.address_mutation(3, "C", "192.0.2.3", "component-c")
        source = PatchSet.new(
            kind="cleanup",
            panorama_host=profile.host,
            panorama_username=profile.username,
            mutations=(first, second, third),
            targets=("192.0.2.1", "192.0.2.2", "192.0.2.3"),
            affected_device_groups=(),
        )
        current = parse_xml("<config><shared><address /></shared></config>")
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            source_id = store.create(
                source,
                profile,
                planning_running=current,
                planning_candidate=current,
            )
            store.write_snapshot(source_id, "pre_candidate", parse_xml(
                "<config><shared><address>"
                '<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
                '<entry name="B"><ip-netmask>192.0.2.2/32</ip-netmask></entry>'
                '<entry name="C"><ip-netmask>192.0.2.3/32</ip-netmask></entry>'
                "</address></shared></config>"
            ))
            store.record_candidate_application(
                source_id,
                applied_mutation_ids=(item.mutation_id for item in source.mutations),
                skipped_components=(),
            )
            store.transition(source_id, SessionState.WRITING_CANDIDATE)
            store.transition(source_id, SessionState.CANDIDATE_APPLIED)

            result = plan_restore_session(
                store,
                PlanningReader(current),
                ip="192.0.2.1",
            )
            restore = store.load_patchset(result["session_id"])
            self.assertEqual(set(restore.targets), {"192.0.2.1", "192.0.2.2"})
            self.assertEqual(len(restore.mutations), 2)
            self.assertNotIn("192.0.2.3", restore.targets)

    def test_restore_by_ip_closes_dependencies_across_cleanup_sessions(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        group_xpath = "/config/shared/address-group/entry[@name='G']"
        member_xpath = f"{group_xpath}/static/member[text()='A']"
        member = Mutation(
            mutation_id="mutation-00001",
            component_id="component-member",
            entity_type="group-member",
            entity_key="shared/G:A",
            target_xpath=member_xpath,
            before_xml="<member>A</member>",
            after_xml=None,
            forward=(MutationOperation(MutationAction.DELETE, member_xpath),),
            inverse=(
                MutationOperation(
                    MutationAction.SET,
                    f"{group_xpath}/static",
                    element="<member>A</member>",
                ),
            ),
            causes=("192.0.2.1",),
        )
        group_xml = '<entry name="G"><static><member>B</member></static></entry>'
        group = Mutation(
            mutation_id="mutation-00001",
            component_id="component-group",
            entity_type="group",
            entity_key="shared/G",
            target_xpath=group_xpath,
            before_xml=group_xml,
            after_xml=None,
            forward=(MutationOperation(MutationAction.DELETE, group_xpath),),
            inverse=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/address-group",
                    element=group_xml,
                ),
            ),
            causes=("192.0.2.2",),
        )
        address_defs = (
            "<address>"
            '<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
            '<entry name="B"><ip-netmask>192.0.2.2/32</ip-netmask></entry>'
            "</address>"
        )
        current = parse_xml(
            "<config><shared>" + address_defs + "<address-group /></shared></config>"
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            source_ids = []
            for timestamp, mutation, snapshot in (
                (
                    "2026-07-15T10:00:00+00:00",
                    member,
                    parse_xml(
                        "<config><shared><address-group>"
                        '<entry name="G"><static><member>A</member><member>B</member>'
                        "</static></entry></address-group>"
                        + address_defs
                        + "</shared></config>"
                    ),
                ),
                (
                    "2026-07-15T11:00:00+00:00",
                    group,
                    parse_xml(
                        "<config><shared><address-group>"
                        + group_xml
                        + "</address-group>"
                        + address_defs
                        + "</shared></config>"
                    ),
                ),
            ):
                patch = PatchSet.new(
                    kind="cleanup",
                    panorama_host=profile.host,
                    panorama_username=profile.username,
                    mutations=(mutation,),
                    targets=mutation.causes,
                    affected_device_groups=(),
                )
                source_id = store.create(
                    patch,
                    profile,
                    planning_running=current,
                    planning_candidate=current,
                )
                source_ids.append(source_id)
                store.write_snapshot(source_id, "pre_candidate", snapshot)
                store.record_candidate_application(
                    source_id,
                    applied_mutation_ids=(mutation.mutation_id,),
                    skipped_components=(),
                )
                store.update(
                    source_id,
                    lambda manifest, value=timestamp: manifest[
                        "candidate_application"
                    ].__setitem__("recorded_utc", value),
                )
                store.transition(source_id, SessionState.WRITING_CANDIDATE)
                store.transition(source_id, SessionState.CANDIDATE_APPLIED)

            result = plan_restore_session(
                store,
                PlanningReader(current),
                ip="192.0.2.1",
            )
            restore = store.load_patchset(result["session_id"])
            self.assertEqual(result["source_session_ids"], source_ids)
            self.assertEqual(restore.source_session_ids, tuple(source_ids))
            self.assertEqual(
                [mutation.entity_type for mutation in restore.mutations],
                ["group", "group-member"],
            )
            self.assertIn(">A<", restore.mutations[0].after_xml or "")

    def test_committed_restore_does_not_undo_new_candidate_cleanup_state(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        source_mutation = self.address_mutation(
            1, "A", "192.0.2.1", "component-address"
        )
        source = PatchSet.new(
            kind="cleanup",
            panorama_host=profile.host,
            panorama_username=profile.username,
            mutations=(source_mutation,),
            targets=("192.0.2.1",),
            affected_device_groups=(),
        )
        running = parse_xml(
            "<config><shared><address>"
            '<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
            "</address></shared></config>"
        )
        candidate = parse_xml("<config><shared><address /></shared></config>")
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            source_id = store.create(
                source,
                profile,
                planning_running=running,
                planning_candidate=candidate,
            )
            store.write_snapshot(source_id, "pre_candidate", running)
            store.record_candidate_application(
                source_id,
                applied_mutation_ids=(source_mutation.mutation_id,),
                skipped_components=(),
            )
            store.transition(source_id, SessionState.WRITING_CANDIDATE)
            store.transition(source_id, SessionState.CANDIDATE_APPLIED)
            store.transition(source_id, SessionState.COMMITTING)
            store.transition(source_id, SessionState.COMMITTED)

            result = plan_restore_session(
                store,
                SplitPlanningReader(running, candidate),
                ip="192.0.2.1",
            )
            self.assertEqual(result["state"], SessionState.CONFLICT.value)
            self.assertEqual(result["mutation_count"], 0)

    def test_restore_closes_policy_reference_to_object_deleted_later(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        policy_xpath = (
            "/config/shared/pre-rulebase/security/rules/entry[@name='P']"
        )
        policy_parent = "/config/shared/pre-rulebase/security/rules"
        policy_xml = (
            '<entry name="P"><source><member>A</member></source>'
            '<destination><member>B</member></destination></entry>'
        )
        policy = Mutation(
            mutation_id="mutation-00001",
            component_id="component-policy",
            entity_type="policy",
            entity_key="shared/pre-rulebase/security/P",
            target_xpath=policy_xpath,
            before_xml=policy_xml,
            after_xml=None,
            forward=(MutationOperation(MutationAction.DELETE, policy_xpath),),
            inverse=(
                MutationOperation(
                    MutationAction.SET, policy_parent, element=policy_xml
                ),
                MutationOperation(
                    MutationAction.MOVE, policy_xpath, where="bottom"
                ),
            ),
            causes=("192.0.2.1",),
            order_previous=None,
            order_next=None,
        )
        address_b = self.address_mutation(
            2, "B", "192.0.2.2", "component-address-b"
        )
        before_policy_cleanup = parse_xml(
            "<config><shared><address>"
            '<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
            '<entry name="B"><ip-netmask>192.0.2.2/32</ip-netmask></entry>'
            "</address><pre-rulebase><security><rules>"
            + policy_xml
            + "</rules></security></pre-rulebase></shared></config>"
        )
        before_address_cleanup = parse_xml(
            "<config><shared><address>"
            '<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
            '<entry name="B"><ip-netmask>192.0.2.2/32</ip-netmask></entry>'
            "</address><pre-rulebase><security><rules />"
            "</security></pre-rulebase></shared></config>"
        )
        current = parse_xml(
            "<config><shared><address>"
            '<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
            "</address><pre-rulebase><security><rules />"
            "</security></pre-rulebase></shared></config>"
        )

        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            source_ids = []
            for applied_utc, item, snapshot in (
                ("2026-07-15T10:00:00+00:00", policy, before_policy_cleanup),
                ("2026-07-15T11:00:00+00:00", address_b, before_address_cleanup),
            ):
                patch = PatchSet.new(
                    kind="cleanup",
                    panorama_host=profile.host,
                    panorama_username=profile.username,
                    mutations=(item,),
                    targets=item.causes,
                    affected_device_groups=(),
                )
                source_id = store.create(
                    patch,
                    profile,
                    planning_running=snapshot,
                    planning_candidate=snapshot,
                )
                source_ids.append(source_id)
                store.write_snapshot(source_id, "pre_candidate", snapshot)
                store.record_candidate_application(
                    source_id,
                    applied_mutation_ids=(item.mutation_id,),
                    skipped_components=(),
                )
                store.update(
                    source_id,
                    lambda manifest, value=applied_utc: manifest[
                        "candidate_application"
                    ].__setitem__("recorded_utc", value),
                )
                store.transition(source_id, SessionState.WRITING_CANDIDATE)
                store.transition(source_id, SessionState.CANDIDATE_APPLIED)

            result = plan_restore_session(
                store, PlanningReader(current), ip="192.0.2.1"
            )
            restore = store.load_patchset(result["session_id"])
            self.assertEqual(result["source_session_ids"], source_ids)
            self.assertEqual(
                [item.entity_type for item in restore.mutations],
                ["address", "policy"],
            )
            self.assertEqual(restore.mutations[1].depends_on, ("mutation-00001",))

    def test_restore_conflicts_when_device_group_resolution_chain_changed(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']/device-group/"
            "entry[@name='Child']/address/entry[@name='A']"
        )
        xml = '<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
        address = Mutation(
            mutation_id="mutation-00001",
            component_id="component-address",
            entity_type="address",
            entity_key="Child/A",
            target_xpath=xpath,
            before_xml=xml,
            after_xml=None,
            forward=(MutationOperation(MutationAction.DELETE, xpath),),
            inverse=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/devices/entry[@name='localhost.localdomain']/"
                    "device-group/entry[@name='Child']/address",
                    element=xml,
                ),
            ),
            causes=("192.0.2.1",),
        )

        def dg_config(parent, include_address):
            address_xml = xml if include_address else ""
            return parse_xml(
                "<config><shared /><devices><entry name=\"localhost.localdomain\">"
                "<device-group>"
                f'<entry name="{parent}" />'
                f'<entry name="Child"><parent-dg>{parent}</parent-dg><address>'
                f"{address_xml}</address></entry>"
                "</device-group></entry></devices></config>"
            )

        historical = dg_config("Parent-A", True)
        current = dg_config("Parent-B", False)
        source = PatchSet.new(
            kind="cleanup",
            panorama_host=profile.host,
            panorama_username=profile.username,
            mutations=(address,),
            targets=address.causes,
            affected_device_groups=("Child",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            source_id = store.create(
                source,
                profile,
                planning_running=historical,
                planning_candidate=historical,
            )
            store.write_snapshot(source_id, "pre_candidate", historical)
            store.record_candidate_application(
                source_id,
                applied_mutation_ids=(address.mutation_id,),
                skipped_components=(),
            )
            store.transition(source_id, SessionState.WRITING_CANDIDATE)
            store.transition(source_id, SessionState.CANDIDATE_APPLIED)

            result = plan_restore_session(
                store, PlanningReader(current), ip="192.0.2.1"
            )
            self.assertEqual(result["state"], SessionState.CONFLICT.value)
            self.assertEqual(result["mutation_count"], 0)
            self.assertTrue(result["conflicted_components"])

    def test_restore_checks_candidate_hierarchy_not_only_running(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']/device-group/"
            "entry[@name='Child']/address/entry[@name='A']"
        )
        xml = '<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
        address = Mutation(
            mutation_id="mutation-00001",
            component_id="component-address",
            entity_type="address",
            entity_key="Child/A",
            target_xpath=xpath,
            before_xml=xml,
            after_xml=None,
            forward=(MutationOperation(MutationAction.DELETE, xpath),),
            inverse=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/devices/entry[@name='localhost.localdomain']/"
                    "device-group/entry[@name='Child']/address",
                    element=xml,
                ),
            ),
            causes=("192.0.2.1",),
        )

        def snapshot(parent, include_address):
            return parse_xml(
                "<config><shared /><devices><entry name=\"localhost.localdomain\">"
                "<device-group>"
                f'<entry name="{parent}" />'
                f'<entry name="Child"><parent-dg>{parent}</parent-dg><address>'
                f"{xml if include_address else ''}</address></entry>"
                "</device-group></entry></devices></config>"
            )

        historical = snapshot("Parent-A", True)
        candidate = snapshot("Parent-B", False)
        source = PatchSet.new(
            kind="cleanup",
            panorama_host=profile.host,
            panorama_username=profile.username,
            mutations=(address,),
            targets=address.causes,
            affected_device_groups=("Child",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            source_id = store.create(
                source,
                profile,
                planning_running=historical,
                planning_candidate=historical,
            )
            store.write_snapshot(source_id, "pre_candidate", historical)
            store.record_candidate_application(
                source_id,
                applied_mutation_ids=(address.mutation_id,),
                skipped_components=(),
            )
            store.transition(source_id, SessionState.WRITING_CANDIDATE)
            store.transition(source_id, SessionState.CANDIDATE_APPLIED)

            result = plan_restore_session(
                store,
                SplitPlanningReader(historical, candidate),
                ip="192.0.2.1",
            )
            self.assertEqual(result["state"], SessionState.CONFLICT.value)
            self.assertEqual(result["mutation_count"], 0)

    def test_restore_rejects_inherited_address_group_namespace_change(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        scope = (
            "/config/devices/entry[@name='localhost.localdomain']/device-group/"
            "entry[@name='Child']"
        )
        address_xpath = f"{scope}/address/entry[@name='A']"
        group_xpath = f"{scope}/address-group/entry[@name='X']"
        rule_parent = f"{scope}/pre-rulebase/security/rules"
        rule_xpath = f"{rule_parent}/entry[@name='P']"
        address_xml = (
            '<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
        )
        group_xml = '<entry name="X"><static><member>A</member></static></entry>'
        rule_xml = (
            '<entry name="P"><source><member>X</member></source>'
            '<destination><member>any</member></destination></entry>'
        )
        policy = Mutation(
            mutation_id="mutation-00001",
            component_id="component-all",
            entity_type="policy",
            entity_key="Child/pre-rulebase/security/P",
            target_xpath=rule_xpath,
            before_xml=rule_xml,
            after_xml=None,
            forward=(MutationOperation(MutationAction.DELETE, rule_xpath),),
            inverse=(
                MutationOperation(MutationAction.SET, rule_parent, element=rule_xml),
                MutationOperation(MutationAction.MOVE, rule_xpath, where="bottom"),
            ),
            causes=("192.0.2.1",),
            order_previous=None,
            order_next=None,
        )
        group = Mutation(
            mutation_id="mutation-00002",
            component_id="component-all",
            entity_type="group",
            entity_key="Child/X",
            target_xpath=group_xpath,
            before_xml=group_xml,
            after_xml=None,
            forward=(MutationOperation(MutationAction.DELETE, group_xpath),),
            inverse=(
                MutationOperation(
                    MutationAction.SET, f"{scope}/address-group", element=group_xml
                ),
            ),
            causes=("192.0.2.1",),
            depends_on=(policy.mutation_id,),
        )
        address = Mutation(
            mutation_id="mutation-00003",
            component_id="component-all",
            entity_type="address",
            entity_key="Child/A",
            target_xpath=address_xpath,
            before_xml=address_xml,
            after_xml=None,
            forward=(MutationOperation(MutationAction.DELETE, address_xpath),),
            inverse=(
                MutationOperation(
                    MutationAction.SET, f"{scope}/address", element=address_xml
                ),
            ),
            causes=("192.0.2.1",),
            depends_on=(group.mutation_id,),
        )
        prefix = (
            "<config><deviceconfig><setting><management>"
            "<ancestor-objects-take-precedence>yes</ancestor-objects-take-precedence>"
            "</management></setting></deviceconfig><shared /><devices>"
            '<entry name="localhost.localdomain"><device-group>'
        )
        historical = parse_xml(
            prefix
            + '<entry name="Parent" />'
            + '<entry name="Child"><parent-dg>Parent</parent-dg><address>'
            + address_xml
            + "</address><address-group>"
            + group_xml
            + "</address-group><pre-rulebase><security><rules>"
            + rule_xml
            + "</rules></security></pre-rulebase></entry>"
            + "</device-group></entry></devices></config>"
        )
        current = parse_xml(
            prefix
            + '<entry name="Parent"><address><entry name="X">'
            + "<ip-netmask>198.51.100.10/32</ip-netmask></entry></address></entry>"
            + '<entry name="Child"><parent-dg>Parent</parent-dg><address />'
            + "<address-group /><pre-rulebase><security><rules />"
            + "</security></pre-rulebase></entry>"
            + "</device-group></entry></devices></config>"
        )
        source = PatchSet.new(
            kind="cleanup",
            panorama_host=profile.host,
            panorama_username=profile.username,
            mutations=(policy, group, address),
            targets=("192.0.2.1",),
            affected_device_groups=("Child",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            source_id = store.create(
                source,
                profile,
                planning_running=historical,
                planning_candidate=historical,
            )
            store.write_snapshot(source_id, "pre_candidate", historical)
            store.record_candidate_application(
                source_id,
                applied_mutation_ids=(
                    policy.mutation_id,
                    group.mutation_id,
                    address.mutation_id,
                ),
                skipped_components=(),
            )
            store.transition(source_id, SessionState.WRITING_CANDIDATE)
            store.transition(source_id, SessionState.CANDIDATE_APPLIED)

            result = plan_restore_session(
                store, PlanningReader(current), ip="192.0.2.1"
            )
            self.assertEqual(result["state"], SessionState.CONFLICT.value)
            self.assertEqual(result["mutation_count"], 0)
            self.assertTrue(result["conflicted_components"])

    def test_outcome_unknown_cleanup_blocks_restore_for_same_identity(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        current = parse_xml("<config><shared><address /></shared></config>")
        stable_mutation = self.address_mutation(
            1, "A", "192.0.2.1", "component-a"
        )
        unknown_mutation = self.address_mutation(
            2, "B", "192.0.2.2", "component-b"
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            stable = PatchSet.new(
                kind="cleanup",
                panorama_host=profile.host,
                panorama_username=profile.username,
                mutations=(stable_mutation,),
                targets=stable_mutation.causes,
                affected_device_groups=(),
            )
            stable_id = store.create(
                stable,
                profile,
                planning_running=current,
                planning_candidate=current,
            )
            store.write_snapshot(stable_id, "pre_candidate", current)
            store.record_candidate_application(
                stable_id,
                applied_mutation_ids=(stable_mutation.mutation_id,),
                skipped_components=(),
            )
            store.transition(stable_id, SessionState.WRITING_CANDIDATE)
            store.transition(stable_id, SessionState.CANDIDATE_APPLIED)

            unknown = PatchSet.new(
                kind="cleanup",
                panorama_host=profile.host,
                panorama_username=profile.username,
                mutations=(unknown_mutation,),
                targets=unknown_mutation.causes,
                affected_device_groups=(),
            )
            unknown_id = store.create(unknown, profile)
            store.transition(unknown_id, SessionState.OUTCOME_UNKNOWN)

            with self.assertRaises(SessionError):
                plan_restore_session(
                    store, PlanningReader(current), ip="192.0.2.1"
                )


if __name__ == "__main__":
    unittest.main()
