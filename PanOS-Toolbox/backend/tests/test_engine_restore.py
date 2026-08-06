from __future__ import annotations

import copy
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from panos_toolbox.cleaner_adapter import build_cleanup_patchset
from panos_toolbox.client import JobResult
from panos_toolbox.engine import (
    _cleanup_candidate_replan_conflicts,
    _postcondition_failures,
    _precondition_conflicts,
    _restore_history_conflicts,
    apply_candidate,
    commit_session,
    push_session,
    reconcile_external_execution,
    server_snapshot_filename,
)
from panos_toolbox.errors import (
    CapabilityError,
    ConflictError,
    OutcomeUnknownError,
    PanoramaResponseError,
    SessionError,
    ValidationError,
)
from panos_toolbox.models import (
    ApiStage,
    Mutation,
    MutationAction,
    MutationOperation,
    PatchSet,
    SessionState,
)
from panos_toolbox.profile import PanoramaProfile
from panos_toolbox.restore import (
    HistoricalMutation,
    RestoreDecision,
    apply_operation_to_tree,
    build_restore_patchset,
    build_restore_patchset_history,
    decide_three_way,
    merge_removed_members,
    select_history,
)
from panos_toolbox.sessions import SessionStore
from panos_toolbox.xmlutil import find_xpath, parent_xpath, parse_xml


class FakeLease:
    def __init__(self, stage=ApiStage.PUSH):
        self.stage = stage

    def assert_valid(self, profile, required):
        if required.rank > self.stage.rank:
            raise CapabilityError("stage")


class StatefulReader:
    def __init__(self, profile, config):
        self.profile = profile
        self.running = copy.deepcopy(config)
        self.candidate = copy.deepcopy(config)
        self.events = []

    def fetch_config(self, kind):
        self.events.append(f"fetch:{kind}")
        return copy.deepcopy(self.running if kind == "running" else self.candidate)

    def show_config_locks(self):
        self.events.append("show:config-locks")
        return parse_xml('<response status="success"><result /></response>')

    def show_commit_locks(self):
        self.events.append("show:commit-locks")
        return parse_xml('<response status="success"><result /></response>')


class StatefulWriter:
    def __init__(self, reader, fail_on_operation=None):
        self.reader = reader
        self.profile = reader.profile
        self.lease = FakeLease()
        self.fail_on_operation = fail_on_operation
        self.operation_count = 0
        self.events = []

    def acquire_config_lock(self, scope, comment):
        self.events.append(f"lock:{scope or 'shared'}")

    def release_config_lock(self, scope):
        self.events.append(f"unlock:{scope or 'shared'}")

    def save_candidate_snapshot(self, filename):
        self.events.append("snapshot")

    def apply_operation(self, operation):
        self.operation_count += 1
        if self.operation_count == self.fail_on_operation:
            raise ValidationError("injected failure")
        config = self.reader.candidate
        if operation.action is MutationAction.DELETE:
            target = find_xpath(config, operation.xpath)
            if target is None:
                raise ValidationError("missing target")
            parent = find_xpath(config, parent_xpath(operation.xpath))
            parent.remove(target)
        elif operation.action is MutationAction.SET:
            parent = find_xpath(config, operation.xpath)
            parent.append(parse_xml(operation.element))
        elif operation.action is MutationAction.MOVE:
            pass

    def apply_recovery_operation(self, operation):
        self.apply_operation(operation)

    def validate_candidate(self):
        return None

    def commit(self, **kwargs):
        self.events.append("commit")
        self.reader.running = copy.deepcopy(self.reader.candidate)
        return "101"

    def push(self, device_groups):
        self.events.append("push:" + ",".join(device_groups))
        return "102"

    def poll_job(self, job_id, **kwargs):
        callback = kwargs.get("progress_callback")
        if callback:
            callback(
                {
                    "event": "panorama-job-finished",
                    "jobId": job_id,
                    "status": "FIN",
                    "result": "OK",
                    "panoramaProgress": 100,
                    "pollCount": 1,
                    "elapsedSeconds": 0.1,
                }
            )
        return JobResult(job_id, "FIN", "OK", "done")


class FailedCommitWriter(StatefulWriter):
    def commit(self, **kwargs):
        self.events.append("commit")
        return "201"

    def poll_job(self, job_id, **_kwargs):
        return JobResult(job_id, "FIN", "FAIL", "injected commit failure")


class FailedPushWriter(StatefulWriter):
    def push(self, device_groups):
        self.events.append("push:" + ",".join(device_groups))
        return "202"

    def poll_job(self, job_id, **_kwargs):
        return JobResult(job_id, "FIN", "FAIL", "injected push failure")


class UnknownCommitWriter(StatefulWriter):
    def commit(self, **kwargs):
        raise OutcomeUnknownError("injected transport ambiguity")


class RollbackFailureWriter(StatefulWriter):
    def apply_recovery_operation(self, operation):
        raise ValidationError("injected rollback failure")


class InterruptAfterWriteWriter(StatefulWriter):
    def apply_operation(self, operation):
        super().apply_operation(operation)
        raise KeyboardInterrupt("injected interrupt after accepted write")


class InterruptPollingWriter(StatefulWriter):
    def poll_job(self, job_id, **_kwargs):
        raise KeyboardInterrupt(f"injected interrupt while polling {job_id}")


def config(*names):
    entries = "".join(
        f'<entry name="{name}"><ip-netmask>192.0.2.{index}/32</ip-netmask></entry>'
        for index, name in enumerate(names, 1)
    )
    return parse_xml(f"<config><shared><address>{entries}</address></shared></config>")


def mutation(index, name, component=None):
    xpath = f"/config/shared/address/entry[@name='{name}']"
    xml = (
        f'<entry name="{name}"><ip-netmask>192.0.2.{index}/32</ip-netmask></entry>'
    )
    return Mutation(
        mutation_id=f"mutation-{index:05d}",
        component_id=component or f"component-{name.lower()}",
        entity_type="address",
        entity_key=f"shared/{name}",
        target_xpath=xpath,
        before_xml=xml,
        after_xml=None,
        forward=(MutationOperation(MutationAction.DELETE, xpath),),
        inverse=(MutationOperation(MutationAction.SET, "/config/shared/address", element=xml),),
        causes=(f"192.0.2.{index}",),
    )


class EngineTests(unittest.TestCase):
    def make_session(self, store, profile, mutations, affected=("DG-A",)):
        patch = PatchSet.new(
            kind="cleanup",
            panorama_host=profile.host,
            panorama_username=profile.username,
            mutations=mutations,
            targets=tuple(cause for item in mutations for cause in item.causes),
            affected_device_groups=affected,
        )
        return store.create(patch, profile), patch

    def test_apply_success_and_inverse_rollback_on_mid_batch_failure(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            reader = StatefulReader(profile, config("A", "B"))
            session_id, _ = self.make_session(
                store, profile, (mutation(1, "A"), mutation(2, "B"))
            )
            writer = StatefulWriter(reader, fail_on_operation=2)
            with self.assertRaises(ValidationError):
                apply_candidate(store, session_id, reader, writer)
            self.assertIsNotNone(find_xpath(reader.candidate, "/config/shared/address/entry[@name='A']"))
            self.assertIsNotNone(find_xpath(reader.candidate, "/config/shared/address/entry[@name='B']"))
            self.assertEqual(store.load_manifest(session_id)["state"], "FAILED")

            reader2 = StatefulReader(profile, config("A"))
            session2, _ = self.make_session(store, profile, (mutation(1, "A"),))
            result = apply_candidate(store, session2, reader2, StatefulWriter(reader2))
            self.assertEqual(result.state, SessionState.CANDIDATE_APPLIED)
            self.assertIsNone(find_xpath(reader2.candidate, "/config/shared/address/entry[@name='A']"))

    def test_server_snapshot_filename_respects_panorama_32_character_limit(self):
        session_id = "session-20260806T110947Z-b68dfb0b"
        filename = server_snapshot_filename(session_id)
        self.assertLessEqual(len(filename), 32)
        self.assertTrue(filename.startswith("ptb_20260806T110947Z_"))
        self.assertTrue(filename.endswith(".xml"))
        self.assertEqual(filename, server_snapshot_filename(session_id))

    def test_candidate_progress_reports_each_path_operation(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            reader = StatefulReader(profile, config("A", "B"))
            session_id, _ = self.make_session(
                store, profile, (mutation(1, "A"), mutation(2, "B"))
            )
            updates = []
            result = apply_candidate(
                store,
                session_id,
                reader,
                StatefulWriter(reader),
                progress_callback=lambda value, message, detail: updates.append(
                    (value, message, detail)
                ),
            )
            self.assertEqual(result.state, SessionState.CANDIDATE_APPLIED)
            self.assertEqual(updates[-1][0], 100)
            operation_updates = [
                detail
                for _value, _message, detail in updates
                if detail and detail.get("event") == "operation-ok"
            ]
            self.assertEqual(len(operation_updates), 2)
            self.assertEqual(operation_updates[-1]["completedOperations"], 2)
            self.assertEqual(operation_updates[-1]["totalOperations"], 2)

    def test_external_cli_execution_requires_complete_live_postconditions(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            reader = StatefulReader(profile, config("A"))
            session_id, _ = self.make_session(store, profile, (mutation(1, "A"),))
            with self.assertRaises(ConflictError):
                reconcile_external_execution(store, session_id, reader, source="CLI")
            self.assertEqual(store.load_manifest(session_id)["state"], "PLANNED")

            reader.candidate = config()
            reader.running = config()
            state = reconcile_external_execution(store, session_id, reader, source="CLI")
            self.assertEqual(state, SessionState.COMMITTED)
            manifest = store.load_manifest(session_id)
            self.assertEqual(manifest["external_execution"]["source"], "CLI")
            self.assertEqual(
                manifest["candidate_application"]["applied_mutation_ids"],
                ["mutation-00001"],
            )

    def test_commit_and_push_guards_and_sequential_states(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            reader = StatefulReader(profile, config("A"))
            session_id, _ = self.make_session(store, profile, (mutation(1, "A"),))
            writer = StatefulWriter(reader)
            apply_candidate(store, session_id, reader, writer)
            with self.assertRaises(CapabilityError):
                commit_session(store, session_id, reader, writer)
            self.assertEqual(store.load_manifest(session_id)["state"], "CANDIDATE_APPLIED")
            reader.events.clear()
            commit_updates = []
            commit_result = commit_session(
                store,
                session_id,
                reader,
                writer,
                allow_unisolated_commit=True,
                progress_callback=lambda value, message, detail: commit_updates.append(
                    (value, message, detail)
                ),
            )
            self.assertEqual(store.load_manifest(session_id)["state"], "COMMITTED")
            self.assertEqual(
                [event for event in reader.events if event.startswith("fetch:")],
                ["fetch:running", "fetch:candidate", "fetch:running"],
            )
            self.assertEqual(commit_updates[-1][0], 100)
            self.assertIn("stage-finished", commit_result["phase_timeline_seconds"])
            self.assertTrue(
                any(
                    detail and detail.get("event") == "panorama-job-finished"
                    for _value, _message, detail in commit_updates
                )
            )
            with self.assertRaises(CapabilityError):
                push_session(store, session_id, reader, writer, device_groups=())
            self.assertEqual(store.load_manifest(session_id)["state"], "COMMITTED")
            reader.events.clear()
            push_updates = []
            push_result = push_session(
                store,
                session_id,
                reader,
                writer,
                device_groups=("DG-A",),
                progress_callback=lambda value, message, detail: push_updates.append(
                    (value, message, detail)
                ),
            )
            self.assertEqual(store.load_manifest(session_id)["state"], "PUSHED")
            self.assertEqual(
                [event for event in reader.events if event.startswith("fetch:")],
                ["fetch:running"],
            )
            self.assertEqual(push_updates[-1][0], 100)
            self.assertIn("stage-finished", push_result["phase_timeline_seconds"])

    def test_partial_apply_commit_checks_only_applied_mutations(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            reader = StatefulReader(profile, config("A", "B"))
            # Drift B before apply; its component is skipped while A remains safe.
            find_xpath(
                reader.candidate, "/config/shared/address/entry[@name='B']/ip-netmask"
            ).text = "198.51.100.200/32"
            session_id, _ = self.make_session(
                store, profile, (mutation(1, "A"), mutation(2, "B"))
            )
            writer = StatefulWriter(reader)
            result = apply_candidate(store, session_id, reader, writer)
            self.assertEqual(result.state, SessionState.PARTIAL)
            application = store.load_manifest(session_id)["candidate_application"]
            self.assertEqual(application["applied_mutation_ids"], ["mutation-00001"])
            commit_session(
                store,
                session_id,
                reader,
                writer,
                allow_unisolated_commit=True,
            )
            self.assertEqual(store.load_manifest(session_id)["state"], "COMMITTED")

    def test_known_job_failures_return_to_retryable_stable_state(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            reader = StatefulReader(profile, config("A"))
            session_id, _ = self.make_session(store, profile, (mutation(1, "A"),))
            apply_candidate(store, session_id, reader, StatefulWriter(reader))

            with self.assertRaises(PanoramaResponseError):
                commit_session(
                    store,
                    session_id,
                    reader,
                    FailedCommitWriter(reader),
                    allow_unisolated_commit=True,
                )
            self.assertEqual(
                store.load_manifest(session_id)["state"], "CANDIDATE_APPLIED"
            )

            commit_session(
                store,
                session_id,
                reader,
                StatefulWriter(reader),
                allow_unisolated_commit=True,
            )
            with self.assertRaises(PanoramaResponseError):
                push_session(
                    store,
                    session_id,
                    reader,
                    FailedPushWriter(reader),
                    device_groups=("DG-A",),
                )
            self.assertEqual(store.load_manifest(session_id)["state"], "COMMITTED")

    def test_unknown_commit_retains_cross_process_job_marker(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.COMMIT)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = SessionStore(root, enforce_acl=False)
            reader = StatefulReader(profile, config("A"))
            session_id, _ = self.make_session(store, profile, (mutation(1, "A"),))
            apply_candidate(store, session_id, reader, StatefulWriter(reader))
            with self.assertRaises(OutcomeUnknownError):
                commit_session(
                    store,
                    session_id,
                    reader,
                    UnknownCommitWriter(reader),
                    allow_unisolated_commit=True,
                )
            self.assertEqual(store.load_manifest(session_id)["state"], "OUTCOME_UNKNOWN")
            self.assertEqual(len(list(root.glob(".panorama-job-*.lock"))), 1)

    def test_incomplete_candidate_rollback_requires_reconciliation(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = SessionStore(root, enforce_acl=False)
            reader = StatefulReader(profile, config("A", "B"))
            session_id, _ = self.make_session(
                store, profile, (mutation(1, "A"), mutation(2, "B"))
            )
            writer = RollbackFailureWriter(reader, fail_on_operation=2)

            with self.assertRaises(OutcomeUnknownError):
                apply_candidate(store, session_id, reader, writer)

            self.assertEqual(
                store.load_manifest(session_id)["state"],
                SessionState.OUTCOME_UNKNOWN.value,
            )
            self.assertEqual(len(list(root.glob(".panorama-job-*.lock"))), 1)
            self.assertFalse(any(event.startswith("unlock:") for event in writer.events))

    def test_candidate_interrupt_after_write_is_outcome_unknown(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = SessionStore(root, enforce_acl=False)
            reader = StatefulReader(profile, config("A"))
            session_id, _ = self.make_session(store, profile, (mutation(1, "A"),))
            writer = InterruptAfterWriteWriter(reader)

            with self.assertRaises(KeyboardInterrupt):
                apply_candidate(store, session_id, reader, writer)

            self.assertIsNone(
                find_xpath(reader.candidate, "/config/shared/address/entry[@name='A']")
            )
            self.assertEqual(
                store.load_manifest(session_id)["state"],
                SessionState.OUTCOME_UNKNOWN.value,
            )
            self.assertEqual(len(list(root.glob(".panorama-job-*.lock"))), 1)
            self.assertFalse(any(event.startswith("unlock:") for event in writer.events))

    def test_commit_interrupt_while_polling_is_outcome_unknown(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = SessionStore(root, enforce_acl=False)
            reader = StatefulReader(profile, config("A"))
            session_id, _ = self.make_session(store, profile, (mutation(1, "A"),))
            apply_candidate(store, session_id, reader, StatefulWriter(reader))
            writer = InterruptPollingWriter(reader)

            with self.assertRaises(KeyboardInterrupt):
                commit_session(
                    store,
                    session_id,
                    reader,
                    writer,
                    allow_unisolated_commit=True,
                )

            self.assertEqual(
                store.load_manifest(session_id)["state"],
                SessionState.OUTCOME_UNKNOWN.value,
            )
            self.assertEqual(len(list(root.glob(".panorama-job-*.lock"))), 1)
            self.assertFalse(any(event.startswith("unlock:") for event in writer.events))

    def test_push_interrupt_while_polling_is_outcome_unknown(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = SessionStore(root, enforce_acl=False)
            reader = StatefulReader(profile, config("A"))
            session_id, _ = self.make_session(store, profile, (mutation(1, "A"),))
            writer = StatefulWriter(reader)
            apply_candidate(store, session_id, reader, writer)
            commit_session(
                store,
                session_id,
                reader,
                writer,
                allow_unisolated_commit=True,
            )
            interrupting_writer = InterruptPollingWriter(reader)

            with self.assertRaises(KeyboardInterrupt):
                push_session(
                    store,
                    session_id,
                    reader,
                    interrupting_writer,
                    device_groups=("DG-A",),
                )

            self.assertEqual(
                store.load_manifest(session_id)["state"],
                SessionState.OUTCOME_UNKNOWN.value,
            )
            self.assertEqual(len(list(root.glob(".panorama-job-*.lock"))), 1)
            self.assertFalse(
                any(event.startswith("unlock:") for event in interrupting_writer.events)
            )

    def test_host_mutex_marker_survives_interrupt_before_state_transition(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = SessionStore(root, enforce_acl=False)
            session_id, _ = self.make_session(store, profile, (mutation(1, "A"),))

            with self.assertRaises(KeyboardInterrupt):
                with store.panorama_job_lock(profile.host, session_id):
                    raise KeyboardInterrupt("injected pre-write interrupt")

            self.assertEqual(store.load_manifest(session_id)["state"], "PLANNED")
            self.assertEqual(len(list(root.glob(".panorama-job-*.lock"))), 1)

    def test_candidate_apply_uses_host_wide_transaction_mutex(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            reader = StatefulReader(profile, config("A"))
            session_id, _ = self.make_session(store, profile, (mutation(1, "A"),))
            writer = StatefulWriter(reader)

            with store.panorama_job_lock(profile.host, session_id):
                with self.assertRaises(SessionError):
                    apply_candidate(store, session_id, reader, writer)

            self.assertEqual(store.load_manifest(session_id)["state"], "PLANNED")
            self.assertEqual(reader.events, [])
            self.assertEqual(writer.events, [])

    def test_cleanup_replan_detects_new_candidate_dependency(self):
        running = parse_xml(
            "<config><shared><address>"
            '<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
            "</address></shared></config>"
        )
        candidate = parse_xml(
            "<config><shared><address>"
            '<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
            "</address><pre-rulebase><security><rules>"
            '<entry name="P"><source><member>A</member></source>'
            '<destination><member>any</member></destination></entry>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        patch = build_cleanup_patchset(
            running,
            ("192.0.2.1",),
            panorama_host="pano",
            panorama_username="admin",
        ).patchset
        components, conflicts = _cleanup_candidate_replan_conflicts(
            patch,
            candidate,
            {
                "input_ips": ["192.0.2.1"],
                "nat_translation_action": "delete-rule",
            },
        )
        self.assertEqual(components, {patch.mutations[0].component_id})
        self.assertEqual(conflicts[0]["reason"], "CANDIDATE_REPLAN_CHANGED")


class RestorePrimitiveTests(unittest.TestCase):
    def test_three_way_and_member_merge(self):
        self.assertEqual(
            decide_three_way(before_sha256="a", expected_sha256="b", current_sha256="b"),
            RestoreDecision.RESTORE,
        )
        self.assertEqual(
            decide_three_way(before_sha256="a", expected_sha256="b", current_sha256="a"),
            RestoreDecision.ALREADY_RESTORED,
        )
        self.assertEqual(
            decide_three_way(before_sha256="a", expected_sha256="b", current_sha256="c"),
            RestoreDecision.CONFLICT,
        )
        self.assertEqual(
            merge_removed_members(("A", "B"), ("B",), ("B", "NEW")),
            ("A", "B", "NEW"),
        )

    def test_restore_safe_already_conflict_and_rule_order_anchor(self):
        original_mutation = mutation(1, "A")
        patch = PatchSet.new(
            kind="cleanup",
            panorama_host="pano",
            panorama_username="admin",
            mutations=(original_mutation,),
            targets=("192.0.2.1",),
            affected_device_groups=(),
        )
        missing = config()
        result = build_restore_patchset(
            patch,
            missing,
            panorama_host="pano",
            panorama_username="admin",
            source_session_id="session-source",
        )
        self.assertEqual(len(result.patchset.mutations), 1)
        self.assertEqual(result.findings[0].decision, RestoreDecision.RESTORE)
        already = build_restore_patchset(
            patch,
            config("A"),
            panorama_host="pano",
            panorama_username="admin",
            source_session_id="session-source",
        )
        self.assertFalse(already.patchset.mutations)

        changed = parse_xml(
            '<config><shared><address><entry name="A"><ip-netmask>198.51.100.9/32</ip-netmask></entry></address></shared></config>'
        )
        conflict = build_restore_patchset(
            patch,
            changed,
            panorama_host="pano",
            panorama_username="admin",
            source_session_id="session-source",
        )
        self.assertTrue(conflict.conflicted_components)

        rule_xml = '<entry name="R"><source><member>any</member></source><destination><member>any</member></destination></entry>'
        rule_xpath = "/config/shared/pre-rulebase/security/rules/entry[@name='R']"
        rule_mutation = Mutation(
            mutation_id="mutation-00001",
            component_id="component-rule",
            entity_type="policy",
            entity_key="shared/pre-rulebase/security/R",
            target_xpath=rule_xpath,
            before_xml=rule_xml,
            after_xml=None,
            forward=(MutationOperation(MutationAction.DELETE, rule_xpath),),
            inverse=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/pre-rulebase/security/rules",
                    element=rule_xml,
                ),
                MutationOperation(MutationAction.MOVE, rule_xpath, where="before", destination="Next"),
            ),
            causes=("192.0.2.1",),
            order_previous="Prev",
            order_next="Next",
        )
        rule_patch = PatchSet.new(
            kind="cleanup",
            panorama_host="pano",
            panorama_username="admin",
            mutations=(rule_mutation,),
            targets=("192.0.2.1",),
            affected_device_groups=(),
        )
        reordered = parse_xml(
            '<config><shared><pre-rulebase><security><rules>'
            '<entry name="Prev"/><entry name="NEW"/><entry name="Next"/>'
            '</rules></security></pre-rulebase></shared></config>'
        )
        ordered_conflict = build_restore_patchset(
            rule_patch,
            reordered,
            panorama_host="pano",
            panorama_username="admin",
            source_session_id="session-source",
        )
        self.assertEqual(ordered_conflict.conflicted_components, ("component-rule",))
        self.assertEqual(
            ordered_conflict.findings[0].decision, RestoreDecision.CONFLICT
        )

    def test_restore_postcondition_verifies_actual_rule_position(self):
        rule_xml = '<entry name="R"><source><member>any</member></source></entry>'
        xpath = "/config/shared/pre-rulebase/security/rules/entry[@name='R']"
        restore_mutation = Mutation(
            mutation_id="mutation-00001",
            component_id="component-rule",
            entity_type="policy",
            entity_key="shared/pre-rulebase/security/R",
            target_xpath=xpath,
            before_xml=None,
            after_xml=rule_xml,
            forward=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/pre-rulebase/security/rules",
                    element=rule_xml,
                ),
                MutationOperation(
                    MutationAction.MOVE, xpath, where="before", destination="Next"
                ),
            ),
            inverse=(MutationOperation(MutationAction.DELETE, xpath),),
            causes=("192.0.2.1",),
            order_previous="Prev",
            order_next="Next",
        )
        wrong = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="Prev"/><entry name="R"><source><member>any</member></source></entry>'
            '<entry name="NEW"/><entry name="Next"/>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        self.assertTrue(_postcondition_failures((restore_mutation,), wrong))

        wrong_previous = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="Prev"/><entry name="NEW"/>'
            '<entry name="R"><source><member>any</member></source></entry>'
            '<entry name="Next"/>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        self.assertTrue(
            _postcondition_failures((restore_mutation,), wrong_previous)
        )

        correct = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="Prev"/><entry name="R"><source><member>any</member></source></entry>'
            '<entry name="Next"/>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        self.assertFalse(_postcondition_failures((restore_mutation,), correct))

    def test_restore_postcondition_verifies_top_and_bottom_boundaries(self):
        top_xml = '<entry name="Top"><source><member>any</member></source></entry>'
        top_xpath = "/config/shared/pre-rulebase/security/rules/entry[@name='Top']"
        top_mutation = Mutation(
            mutation_id="mutation-00001",
            component_id="component-top",
            entity_type="policy",
            entity_key="shared/pre-rulebase/security/Top",
            target_xpath=top_xpath,
            before_xml=None,
            after_xml=top_xml,
            forward=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/pre-rulebase/security/rules",
                    element=top_xml,
                ),
                MutationOperation(
                    MutationAction.MOVE,
                    top_xpath,
                    where="before",
                    destination="Next",
                ),
            ),
            inverse=(MutationOperation(MutationAction.DELETE, top_xpath),),
            causes=("192.0.2.1",),
            order_previous=None,
            order_next="Next",
        )
        wrong_top = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="NEW"/>'
            '<entry name="Top"><source><member>any</member></source></entry>'
            '<entry name="Next"/>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        correct_top = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="Top"><source><member>any</member></source></entry>'
            '<entry name="Next"/>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        self.assertTrue(_postcondition_failures((top_mutation,), wrong_top))
        self.assertFalse(_postcondition_failures((top_mutation,), correct_top))

        bottom_xml = '<entry name="Bottom"><source><member>any</member></source></entry>'
        bottom_xpath = "/config/shared/pre-rulebase/security/rules/entry[@name='Bottom']"
        bottom_mutation = Mutation(
            mutation_id="mutation-00002",
            component_id="component-bottom",
            entity_type="policy",
            entity_key="shared/pre-rulebase/security/Bottom",
            target_xpath=bottom_xpath,
            before_xml=None,
            after_xml=bottom_xml,
            forward=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/pre-rulebase/security/rules",
                    element=bottom_xml,
                ),
                MutationOperation(
                    MutationAction.MOVE,
                    bottom_xpath,
                    where="bottom",
                ),
            ),
            inverse=(MutationOperation(MutationAction.DELETE, bottom_xpath),),
            causes=("192.0.2.1",),
            order_previous="Prev",
            order_next=None,
        )
        wrong_bottom = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="Prev"/>'
            '<entry name="Bottom"><source><member>any</member></source></entry>'
            '<entry name="NEW"/>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        correct_bottom = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="Prev"/>'
            '<entry name="Bottom"><source><member>any</member></source></entry>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        self.assertTrue(_postcondition_failures((bottom_mutation,), wrong_bottom))
        self.assertFalse(
            _postcondition_failures((bottom_mutation,), correct_bottom)
        )

    def test_restore_precondition_detects_anchor_change_after_plan(self):
        rule_xml = '<entry name="R"><source><member>any</member></source></entry>'
        xpath = "/config/shared/pre-rulebase/security/rules/entry[@name='R']"
        cleanup_mutation = Mutation(
            mutation_id="mutation-00001",
            component_id="component-rule",
            entity_type="policy",
            entity_key="shared/pre-rulebase/security/R",
            target_xpath=xpath,
            before_xml=rule_xml,
            after_xml=None,
            forward=(MutationOperation(MutationAction.DELETE, xpath),),
            inverse=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/pre-rulebase/security/rules",
                    element=rule_xml,
                ),
                MutationOperation(
                    MutationAction.MOVE, xpath, where="before", destination="Next"
                ),
            ),
            causes=("192.0.2.1",),
            order_previous="Prev",
            order_next="Next",
        )
        source = PatchSet.new(
            kind="cleanup",
            panorama_host="pano",
            panorama_username="admin",
            mutations=(cleanup_mutation,),
            targets=("192.0.2.1",),
            affected_device_groups=(),
        )
        at_plan = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="Prev"/><entry name="Next"/>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        planned = build_restore_patchset(
            source,
            at_plan,
            panorama_host="pano",
            panorama_username="admin",
            source_session_id="session-source",
        ).patchset
        self.assertIsNotNone(planned.mutations[0].order_context_sha256)

        content_only_drift = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="Prev"><description>changed outside restored rule</description></entry>'
            '<entry name="Next"><disabled>yes</disabled></entry>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        components, conflicts = _precondition_conflicts(planned, content_only_drift)
        self.assertEqual(components, set())
        self.assertEqual(conflicts, [])

        added_rule = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="Prev"/><entry name="NEW"/><entry name="Next"/>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        moved_rule = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="Next"/><entry name="Prev"/>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        for label, before_apply in (
            ("added rule", added_rule),
            ("moved rule", moved_rule),
        ):
            with self.subTest(label=label):
                components, conflicts = _precondition_conflicts(planned, before_apply)
                self.assertEqual(components, {"component-rule"})
                self.assertEqual(
                    conflicts[0]["reason"], "RULE_ORDER_CONTEXT_CHANGED"
                )

    def test_restore_two_adjacent_trailing_rules_preserves_order(self):
        container_xpath = "/config/shared/pre-rulebase/security/rules"

        def deleted_rule(
            mutation_id,
            name,
            *,
            previous,
            next_rule,
            move_where,
            move_destination=None,
            depends_on=(),
        ):
            rule_xml = (
                f'<entry name="{name}"><source><member>any</member></source></entry>'
            )
            xpath = f"{container_xpath}/entry[@name='{name}']"
            return Mutation(
                mutation_id=mutation_id,
                component_id="component-trailing-rules",
                entity_type="policy",
                entity_key=f"shared/pre-rulebase/security/{name}",
                target_xpath=xpath,
                before_xml=rule_xml,
                after_xml=None,
                forward=(MutationOperation(MutationAction.DELETE, xpath),),
                inverse=(
                    MutationOperation(
                        MutationAction.SET,
                        container_xpath,
                        element=rule_xml,
                    ),
                    MutationOperation(
                        MutationAction.MOVE,
                        xpath,
                        where=move_where,
                        destination=move_destination,
                    ),
                ),
                causes=("192.0.2.1",),
                depends_on=depends_on,
                order_previous=previous,
                order_next=next_rule,
            )

        first = deleted_rule(
            "mutation-00001",
            "R1",
            previous="KEEP",
            next_rule="R2",
            move_where="before",
            move_destination="R2",
        )
        second = deleted_rule(
            "mutation-00002",
            "R2",
            previous="R1",
            next_rule=None,
            move_where="bottom",
            depends_on=(first.mutation_id,),
        )
        source = PatchSet.new(
            kind="cleanup",
            panorama_host="pano",
            panorama_username="admin",
            mutations=(first, second),
            targets=("192.0.2.1",),
            affected_device_groups=(),
        )
        after_cleanup = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="KEEP"/>'
            "</rules></security></pre-rulebase></shared></config>"
        )

        planned = build_restore_patchset(
            source,
            after_cleanup,
            panorama_host="pano",
            panorama_username="admin",
            source_session_id="session-source",
        ).patchset

        self.assertEqual(
            [mutation.entity_key.rsplit("/", 1)[-1] for mutation in planned.mutations],
            ["R2", "R1"],
        )
        self.assertEqual(planned.mutations[0].forward[1].where, "bottom")
        self.assertIsNone(planned.mutations[0].forward[1].destination)
        self.assertEqual(planned.mutations[1].forward[1].where, "before")
        self.assertEqual(planned.mutations[1].forward[1].destination, "R2")

        restored = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="KEEP"/>'
            '<entry name="R1"><source><member>any</member></source></entry>'
            '<entry name="R2"><source><member>any</member></source></entry>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        self.assertFalse(_postcondition_failures(planned.mutations, restored))

    def test_multi_session_member_then_full_group_restore_uses_final_post_state(self):
        group_xpath = "/config/shared/address-group/entry[@name='G']"
        member_xpath = f"{group_xpath}/static/member[text()='A']"
        member = Mutation(
            mutation_id="mutation-00001",
            component_id="component-a",
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
            component_id="component-b",
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
        records = (
            HistoricalMutation(
                "session-a", "2026-07-15T10:00:00+00:00", 0, member
            ),
            HistoricalMutation(
                "session-b", "2026-07-15T11:00:00+00:00", 0, group
            ),
        )
        selected = select_history(records, ip="192.0.2.1")
        self.assertEqual(selected.source_session_ids, ("session-a", "session-b"))
        selected_many = select_history(
            records, targets=("192.0.2.1", "192.0.2.2")
        )
        self.assertEqual(
            {record.qualified_id for record in selected_many.records},
            {record.qualified_id for record in records},
        )
        current = parse_xml("<config><shared><address-group /></shared></config>")
        result = build_restore_patchset_history(
            selected,
            current,
            panorama_host="pano",
            panorama_username="admin",
            affected_device_groups=(),
        )
        self.assertFalse(result.conflicted_components)
        self.assertEqual(
            [mutation.entity_type for mutation in result.patchset.mutations],
            ["group", "group-member"],
        )
        self.assertIn(">A<", result.patchset.mutations[0].after_xml or "")
        simulated = copy.deepcopy(current)
        for mutation in result.patchset.mutations:
            for operation in mutation.forward:
                apply_operation_to_tree(simulated, operation)
        self.assertFalse(_postcondition_failures(result.patchset.mutations, simulated))

    def test_multi_session_adjacent_policy_deletions_restore_exact_order(self):
        container = "/config/shared/pre-rulebase/security/rules"

        def deleted_rule(
            source_id,
            applied_utc,
            name,
            cause,
            previous,
            following,
        ):
            xpath = f"{container}/entry[@name='{name}']"
            xml = f'<entry name="{name}"><source><member>any</member></source></entry>'
            return HistoricalMutation(
                source_id,
                applied_utc,
                0,
                Mutation(
                    mutation_id="mutation-00001",
                    component_id=f"component-{name.lower()}",
                    entity_type="policy",
                    entity_key=f"shared/pre-rulebase/security/{name}",
                    target_xpath=xpath,
                    before_xml=xml,
                    after_xml=None,
                    forward=(MutationOperation(MutationAction.DELETE, xpath),),
                    inverse=(
                        MutationOperation(MutationAction.SET, container, element=xml),
                        MutationOperation(
                            MutationAction.MOVE,
                            xpath,
                            where="before" if following else "bottom",
                            destination=following,
                        ),
                    ),
                    causes=(cause,),
                    order_previous=previous,
                    order_next=following,
                ),
            )

        first = deleted_rule(
            "session-a",
            "2026-07-15T10:00:00+00:00",
            "R1",
            "192.0.2.1",
            "KEEP",
            "R2",
        )
        second = deleted_rule(
            "session-b",
            "2026-07-15T11:00:00+00:00",
            "R2",
            "192.0.2.2",
            "KEEP",
            "NEXT",
        )
        selected = select_history((first, second), ip="192.0.2.1")
        current = parse_xml(
            "<config><shared><pre-rulebase><security><rules>"
            '<entry name="KEEP"/><entry name="NEXT"/>'
            "</rules></security></pre-rulebase></shared></config>"
        )
        planned = build_restore_patchset_history(
            selected,
            current,
            panorama_host="pano",
            panorama_username="admin",
            affected_device_groups=("shared",),
        )

        self.assertFalse(planned.conflicted_components)
        self.assertEqual(
            [item.entity_key.rsplit("/", 1)[-1] for item in planned.patchset.mutations],
            ["R2", "R1"],
        )
        restored = copy.deepcopy(current)
        for item in planned.patchset.mutations:
            for operation in item.forward:
                apply_operation_to_tree(restored, operation)
        rules = find_xpath(restored, container)
        self.assertEqual(
            [entry.get("name") for entry in rules.findall("./entry")],
            ["KEEP", "R1", "R2", "NEXT"],
        )
        self.assertFalse(_postcondition_failures(planned.patchset.mutations, restored))

    def test_restore_rejects_address_group_namespace_collision(self):
        original = mutation(1, "X")
        record = HistoricalMutation(
            "session-source", "2026-07-15T10:00:00+00:00", 0, original
        )
        selected = select_history((record,), ip="192.0.2.1")
        current = parse_xml(
            "<config><shared><address />"
            '<address-group><entry name="X"><static /></entry></address-group>'
            "</shared></config>"
        )
        planned = build_restore_patchset_history(
            selected,
            current,
            panorama_host="pano",
            panorama_username="admin",
            affected_device_groups=("shared",),
        )
        self.assertFalse(planned.patchset.mutations)
        self.assertTrue(planned.conflicted_components)

    def test_restore_history_guard_detects_related_cleanup_after_plan(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            first = mutation(1, "A")
            source_patch = PatchSet.new(
                kind="cleanup",
                panorama_host=profile.host,
                panorama_username=profile.username,
                mutations=(first,),
                targets=first.causes,
                affected_device_groups=("shared",),
            )
            source = store.create(source_patch, profile)
            store.record_candidate_application(
                source,
                applied_mutation_ids=(first.mutation_id,),
                skipped_components=(),
            )
            store.transition(source, SessionState.WRITING_CANDIDATE)
            store.transition(source, SessionState.CANDIDATE_APPLIED)
            baseline = store.load_applied_cleanup(source)

            restore_patch = PatchSet.new(
                kind="restore",
                panorama_host=profile.host,
                panorama_username=profile.username,
                mutations=(
                    Mutation(
                        mutation_id="mutation-00001",
                        component_id="component-restore",
                        entity_type="address",
                        entity_key="shared/A",
                        target_xpath=first.target_xpath,
                        before_xml=None,
                        after_xml=first.before_xml,
                        forward=first.inverse,
                        inverse=first.forward,
                        causes=first.causes,
                    ),
                ),
                targets=first.causes,
                affected_device_groups=("shared",),
                source_session_id=source,
                source_session_ids=(source,),
            )
            restore_id = store.create(restore_patch, profile)
            store.update(
                restore_id,
                lambda manifest: manifest.update(
                    {
                        "restore_history_guard": {
                            "baseline_revisions": {source: list(baseline.revision)},
                            "selected_source_revisions": {
                                source: list(baseline.revision)
                            },
                            "selected_causes": list(first.causes),
                            "guard_owner_xpaths": [first.target_xpath],
                        }
                    }
                ),
            )

            later = mutation(2, "A")
            later_patch = PatchSet.new(
                kind="cleanup",
                panorama_host=profile.host,
                panorama_username=profile.username,
                mutations=(later,),
                targets=later.causes,
                affected_device_groups=("shared",),
            )
            later_id = store.create(later_patch, profile)
            store.record_candidate_application(
                later_id,
                applied_mutation_ids=(later.mutation_id,),
                skipped_components=(),
            )
            store.transition(later_id, SessionState.WRITING_CANDIDATE)
            store.transition(later_id, SessionState.CANDIDATE_APPLIED)

            conflicts = _restore_history_conflicts(
                store, store.load_manifest(restore_id), restore_patch
            )
            self.assertEqual(
                conflicts[0]["reason"], "RELATED_CLEANUP_AFTER_RESTORE_PLAN"
            )


if __name__ == "__main__":
    unittest.main()
