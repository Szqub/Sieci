from __future__ import annotations

import json
import io
import tempfile
import unittest
import urllib.error
import zipfile
from dataclasses import replace
from unittest import mock
from pathlib import Path

from panos_toolbox.client import PanoramaReadClient, UrllibXMLTransport
from panos_toolbox.errors import (
    CapabilityError,
    InputError,
    IntegrityError,
    OutcomeUnknownError,
    TransportError,
    ValidationError,
)
from panos_toolbox.models import (
    ApiStage,
    Mutation,
    MutationAction,
    MutationOperation,
    PatchSet,
)
from panos_toolbox.profile import PanoramaProfile, issue_write_lease, load_profile
from panos_toolbox.service import make_writer
from panos_toolbox.sessions import SessionStore
from panos_toolbox.xmlutil import parse_xml


class RecordingTransport:
    def __init__(self):
        self.calls = []
        self.responses = []

    def queue(self, xml: str) -> None:
        self.responses.append(xml.encode())

    def post(self, params, *, headers, mutating):
        self.calls.append((dict(params), dict(headers), mutating))
        if not self.responses:
            raise AssertionError("missing fake response")
        return self.responses.pop(0)


def sample_mutation(name: str = "A") -> Mutation:
    xpath = f"/config/shared/address/entry[@name='{name}']"
    xml = f'<entry name="{name}"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
    return Mutation(
        mutation_id="mutation-00001",
        component_id="component-a",
        entity_type="address",
        entity_key=f"shared/{name}",
        target_xpath=xpath,
        before_xml=xml,
        after_xml=None,
        forward=(MutationOperation(MutationAction.DELETE, xpath),),
        inverse=(
            MutationOperation(MutationAction.SET, "/config/shared/address", element=xml),
        ),
        causes=("192.0.2.1",),
    )


class ProfileAndCapabilityTests(unittest.TestCase):
    def test_profile_legacy_and_new_ssl_semantics(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "legacy.txt"
            path.write_text("host=pano\nusername=admin\nssl=no\n", encoding="utf-8")
            legacy = load_profile(path)
            self.assertTrue(legacy.use_ssl)
            self.assertFalse(legacy.verify_ssl)
            self.assertEqual(legacy.base_url, "https://pano/api/")

            path.write_text(
                "host=pano\nusername=admin\nssl=no\nverify_ssl=no\napi_max_stage=candidate\n",
                encoding="utf-8",
            )
            modern = load_profile(path)
            self.assertFalse(modern.use_ssl)
            self.assertFalse(modern.verify_ssl)
            self.assertEqual(modern.base_url, "http://pano/api/")
            self.assertEqual(modern.api_max_stage, ApiStage.CANDIDATE)

    def test_write_lease_requires_both_profile_and_runtime_gate(self):
        profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.CANDIDATE)
        with self.assertRaises(CapabilityError):
            issue_write_lease(profile, ApiStage.CANDIDATE, enable_api_write=False)
        with self.assertRaises(CapabilityError):
            issue_write_lease(profile, ApiStage.COMMIT, enable_api_write=True)
        lease = issue_write_lease(profile, ApiStage.CANDIDATE, enable_api_write=True)
        lease.assert_valid(profile, ApiStage.CANDIDATE)

    def test_stage_matrix_never_exceeds_profile_ceiling(self):
        for maximum in ApiStage:
            profile = PanoramaProfile("pano", "admin", api_max_stage=maximum)
            for requested in (ApiStage.CANDIDATE, ApiStage.COMMIT, ApiStage.PUSH):
                if requested.rank <= maximum.rank:
                    issue_write_lease(profile, requested, enable_api_write=True)
                else:
                    with self.assertRaises(CapabilityError):
                        issue_write_lease(profile, requested, enable_api_write=True)

    def test_gui_runtime_stage_can_authorize_write_independently_from_read_profile(self):
        reader = PanoramaReadClient(
            PanoramaProfile("pano", "admin", api_max_stage=ApiStage.READ_ONLY),
            RecordingTransport(),
        )
        reader._api_key = "memory-only-test-key"
        writer = make_writer(
            reader,
            ApiStage.COMMIT,
            enable_api_write=True,
            operator_authorized_stage=ApiStage.COMMIT,
        )
        self.assertEqual(writer.lease.stage, ApiStage.COMMIT)
        with self.assertRaises(InputError):
            make_writer(
                reader,
                ApiStage.PUSH,
                enable_api_write=True,
                operator_authorized_stage=ApiStage.COMMIT,
            )

    def test_xml_fragment_allows_newlines_but_rejects_forbidden_control(self):
        MutationOperation(
            MutationAction.SET,
            "/config/shared/address",
            element='<entry name="A"><description>linia 1\n\tlinia 2</description></entry>',
        )
        with self.assertRaises(ValidationError):
            MutationOperation(
                MutationAction.SET,
                "/config/shared/address",
                element='<entry name="A"><description>bad\x01</description></entry>',
            )


class ClientSerializationTests(unittest.TestCase):
    def test_single_target_config_cache_avoids_second_download(self):
        transport = RecordingTransport()
        transport.queue(
            '<response status="success"><result><config version="10.2"><shared /></config></result></response>'
        )
        reader = PanoramaReadClient(
            PanoramaProfile("pano", "admin", verify_ssl=False), transport
        )
        reader._api_key = "memory-only-test-key"
        first = reader.fetch_config("running")
        second = reader.fetch_config_cached("running")
        self.assertEqual(first.get("version"), second.get("version"))
        self.assertEqual(len(transport.calls), 1)

    def test_candidate_mutation_invalidates_only_candidate_cache(self):
        profile = PanoramaProfile(
            "pano", "admin", verify_ssl=False, api_max_stage=ApiStage.CANDIDATE
        )
        transport = RecordingTransport()
        response = (
            '<response status="success"><result><config version="10.2">'
            '<shared /></config></result></response>'
        )
        transport.queue(response)
        transport.queue(response)
        reader = PanoramaReadClient(profile, transport)
        reader._api_key = "memory-only-test-key"
        reader.fetch_config("running")
        reader.fetch_config("candidate")
        writer = reader.enable_write(
            issue_write_lease(profile, ApiStage.CANDIDATE, enable_api_write=True)
        )
        transport.queue('<response status="success"><result /></response>')
        writer.apply_operation(sample_mutation().forward[0])
        reader.fetch_config_cached("running")
        transport.queue(response)
        reader.fetch_config_cached("candidate")
        self.assertEqual(len(transport.calls), 4)

    def test_mutating_transport_failure_is_never_retried(self):
        profile = PanoramaProfile("pano", "admin", verify_ssl=False)
        transport = UrllibXMLTransport(profile)
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.URLError(OSError("network"))
        transport.opener = opener
        with self.assertRaises(OutcomeUnknownError):
            transport.post(
                {"type": "config", "action": "delete", "xpath": "/config/shared/address"},
                headers={"X-PAN-KEY": "redacted"},
                mutating=True,
            )
        self.assertEqual(opener.open.call_count, 1)

    def test_config_commit_push_and_lock_serialization(self):
        profile = PanoramaProfile(
            "pano", "admin", verify_ssl=False, api_max_stage=ApiStage.PUSH
        )
        transport = RecordingTransport()
        transport.queue('<response status="success"><result><key>SECRET</key></result></response>')
        reader = PanoramaReadClient(profile, transport)
        reader.authenticate("password")
        lease = issue_write_lease(profile, ApiStage.PUSH, enable_api_write=True)
        writer = reader.enable_write(lease)

        transport.queue('<response status="success"><result /></response>')
        writer.apply_operation(sample_mutation().forward[0])
        params, headers, mutating = transport.calls[-1]
        self.assertEqual(params["action"], "delete")
        self.assertTrue(mutating)
        self.assertNotIn("SECRET", json.dumps(params))

        transport.queue('<response status="success"><result /></response>')
        writer.acquire_config_lock("DG-A", "test")
        params = transport.calls[-1][0]
        self.assertEqual(params["vsys"], "DG-A")
        self.assertNotIn("device-group", params["cmd"])

        with self.assertRaises(CapabilityError):
            writer.commit(partial=True)
        transport.queue('<response status="success"><result><job>11</job></result></response>')
        self.assertEqual(
            writer.commit(partial=True, allow_unisolated_commit=True), "11"
        )
        params = transport.calls[-1][0]
        self.assertEqual(params["action"], "partial")
        transport.queue(
            '<response status="success"><result><job><id>11</id><status>FIN</status><result>OK</result></job></result></response>'
        )
        self.assertTrue(writer.poll_job("11", interval_seconds=0).succeeded)

        with self.assertRaises(CapabilityError):
            writer.commit(partial=False)
        transport.queue('<response status="success"><result><job>13</job></result></response>')
        self.assertEqual(
            writer.commit(partial=False, allow_full_commit=True), "13"
        )
        params = transport.calls[-1][0]
        self.assertNotIn("action", params)
        transport.queue(
            '<response status="success"><result><job><id>13</id><status>FIN</status><result>OK</result></job></result></response>'
        )
        writer.poll_job("13", interval_seconds=0)

        transport.queue('<response status="success"><result><job>12</job></result></response>')
        self.assertEqual(writer.push(("DG-A", "DG-B")), "12")
        params = transport.calls[-1][0]
        self.assertEqual(params["action"], "all")
        self.assertIn("<include-template>no</include-template>", params["cmd"])
        self.assertIn('entry name="DG-A"', params["cmd"])
        transport.queue(
            '<response status="success"><result><job><id>12</id><status>FIN</status><result>OK</result></job></result></response>'
        )
        writer.poll_job("12", interval_seconds=0)

    def test_expired_lease_blocks_forward_but_allows_rollback_and_unlock(self):
        profile = PanoramaProfile(
            "pano", "admin", verify_ssl=False, api_max_stage=ApiStage.CANDIDATE
        )
        transport = RecordingTransport()
        transport.queue('<response status="success"><result><key>SECRET</key></result></response>')
        reader = PanoramaReadClient(profile, transport)
        reader.authenticate("password")
        writer = reader.enable_write(
            issue_write_lease(profile, ApiStage.CANDIDATE, enable_api_write=True)
        )
        writer.lease = replace(writer.lease, expires_monotonic=0.0)
        with self.assertRaises(CapabilityError):
            writer.apply_operation(sample_mutation().forward[0])

        transport.queue('<response status="success"><result /></response>')
        writer.apply_recovery_operation(sample_mutation().inverse[0])
        transport.queue('<response status="success"><result /></response>')
        writer.release_config_lock("DG-A")


class SessionIntegrityTests(unittest.TestCase):
    def test_restore_source_session_list_is_backward_compatible(self):
        patch = PatchSet.new(
            kind="restore",
            panorama_host="pano",
            panorama_username="admin",
            mutations=(sample_mutation(),),
            targets=("192.0.2.1",),
            affected_device_groups=(),
            source_session_id="session-primary",
            source_session_ids=("session-primary", "session-related"),
        )
        self.assertEqual(
            PatchSet.from_dict(patch.to_dict()).source_session_ids,
            ("session-primary", "session-related"),
        )
        legacy = patch.to_dict()
        legacy.pop("source_session_ids")
        self.assertEqual(
            PatchSet.from_dict(legacy).source_session_ids,
            ("session-primary",),
        )

    def test_manifest_journal_backups_and_tamper_detection(self):
        profile = PanoramaProfile("pano", "admin")
        patch = PatchSet.new(
            kind="cleanup",
            panorama_host="pano",
            panorama_username="admin",
            mutations=(sample_mutation(),),
            targets=("192.0.2.1",),
            affected_device_groups=(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            session_id = store.create(
                patch,
                profile,
                planning_running=parse_xml("<config><shared /></config>"),
                planning_candidate=parse_xml("<config><shared /></config>"),
            )
            manifest = store.load_manifest(session_id)
            backup = manifest["entity_backups"][0]
            self.assertRegex(
                backup["file"], r"shared_A_\d{6}_\d{2}_\d{2}_mutation-00001\.xml$"
            )
            store.verify(session_id)
            path = Path(temporary) / session_id / backup["file"]
            path.write_text("tampered", encoding="utf-8")
            with self.assertRaises(IntegrityError):
                store.verify(session_id)

    def test_operation_lock_is_fail_fast(self):
        profile = PanoramaProfile("pano", "admin")
        patch = PatchSet.new(
            kind="cleanup",
            panorama_host="pano",
            panorama_username="admin",
            mutations=(sample_mutation(),),
            targets=("192.0.2.1",),
            affected_device_groups=(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            session_id = store.create(patch, profile)
            with store.operation_lock(session_id):
                with self.assertRaises(Exception):
                    with store.operation_lock(session_id):
                        pass

    def test_complete_session_bundle_contains_manifest_backups_and_journal(self):
        profile = PanoramaProfile("pano", "admin")
        patch = PatchSet.new(
            kind="cleanup",
            panorama_host="pano",
            panorama_username="admin",
            mutations=(sample_mutation(),),
            targets=("192.0.2.1",),
            affected_device_groups=(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            session_id = store.create(
                patch,
                profile,
                planning_running=parse_xml("<config><shared /></config>"),
                planning_candidate=parse_xml("<config><shared /></config>"),
            )
            payload = store.bundle_bytes(session_id)
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                names = set(archive.namelist())
            prefix = f"{session_id}/"
            self.assertIn(prefix + "manifest.json", names)
            self.assertTrue(any(name.startswith(prefix + "entities/") for name in names))
            self.assertTrue(any(name.startswith(prefix + "journal/") for name in names))

    def test_restore_history_enumeration_fails_closed_on_corrupt_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = SessionStore(root, enforce_acl=False)
            (root / "session-corrupt").mkdir()

            self.assertEqual(store.list_sessions(), [])
            with self.assertRaises(IntegrityError):
                store.list_sessions_strict()


if __name__ == "__main__":
    unittest.main()
