from __future__ import annotations

import copy
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from panos_toolbox.cli import build_parser
from panos_toolbox.cleaner_adapter import build_cleanup_patchset
from panos_toolbox.policy_requests import build_policy_creation_plan, parse_policy_request
from panos_toolbox.models import ApiStage
from panos_toolbox.profile import PanoramaProfile
from panos_toolbox.sessions import SessionStore
from panos_toolbox.web import (
    _apply_profile_ceiling,
    _cleanup_exclusion_closure,
    _wire_session,
    create_app,
)
from panos_toolbox.xmlutil import parse_xml


REPO_ROOT = Path(__file__).resolve().parents[3]


class CleanerAdapterTests(unittest.TestCase):
    @staticmethod
    def fixture():
        return parse_xml(
            (REPO_ROOT / "panorama_cleaner/tests/fixtures/panorama_running.xml").read_text(
                encoding="utf-8"
            )
        )

    def test_real_cleaner_batch_plan_becomes_structural_patchset(self):
        config = self.fixture()
        result = build_cleanup_patchset(
            config,
            ("203.0.113.10",),
            panorama_host="pano",
            panorama_username="admin",
        )
        self.assertTrue(result.patchset.mutations)
        self.assertTrue(
            any(
                mutation.entity_type == "policy" and "NAT-TRANS" in mutation.entity_key
                for mutation in result.patchset.mutations
            )
        )
        self.assertTrue(
            any(mutation.entity_type == "address" for mutation in result.patchset.mutations)
        )
        self.assertEqual(
            set(result.patchset.affected_device_groups), {"DG-PARENT", "DG-CHILD"}
        )
        for mutation in result.patchset.mutations:
            self.assertTrue(mutation.forward)
            self.assertTrue(mutation.inverse)
            self.assertTrue(mutation.target_xpath.startswith("/config"))

    def test_named_policy_is_discovered_with_scope_and_deleted(self):
        result = build_cleanup_patchset(
            self.fixture(),
            (),
            policy_names=("SEC-MIX",),
            panorama_host="pano",
            panorama_username="admin",
        )
        self.assertEqual(result.patchset.targets, ("policy:SEC-MIX",))
        self.assertEqual(
            result.discovery["policy:SEC-MIX"]["matches"][0],
            {
                "location": "shared",
                "rulebase": "pre-rulebase",
                "policy_type": "security",
                "name": "SEC-MIX",
                "entity_type": "policy",
            },
        )
        self.assertTrue(
            any(
                mutation.entity_type == "policy"
                and mutation.entity_key.endswith("/SEC-MIX")
                for mutation in result.patchset.mutations
            )
        )

    def test_named_group_removes_dependencies_before_group(self):
        result = build_cleanup_patchset(
            self.fixture(),
            (),
            address_group_names=("G-INNER",),
            panorama_host="pano",
            panorama_username="admin",
        )
        entity_keys = [mutation.entity_key for mutation in result.patchset.mutations]
        self.assertIn("shared/G-INNER", entity_keys)
        self.assertIn("shared/G-OUTER", entity_keys)
        self.assertIn("shared/pre-rulebase/security/SEC-GROUP", entity_keys)
        self.assertLess(entity_keys.index("shared/G-OUTER"), entity_keys.index("shared/G-INNER"))

    def test_dynamic_group_is_reported_without_mutation(self):
        result = build_cleanup_patchset(
            self.fixture(),
            (),
            address_group_names=("DAG-RETIRE",),
            panorama_host="pano",
            panorama_username="admin",
        )
        self.assertEqual(result.discovery["group:DAG-RETIRE"]["status"], "unsupported-dynamic")
        self.assertIn("group:DAG-RETIRE", result.blocked_ips)
        self.assertFalse(result.patchset.mutations)

    def test_application_override_blocks_related_object_and_direct_rule(self):
        for kwargs, cause in (
            ({"address_object_names": ("TARGET_A",)}, "object:TARGET_A"),
            ({"policy_names": ("APP-MIX",)}, "policy:APP-MIX"),
        ):
            with self.subTest(cause=cause):
                result = build_cleanup_patchset(
                    self.fixture(),
                    (),
                    panorama_host="pano",
                    panorama_username="admin",
                    **kwargs,
                )
                self.assertIn(cause, result.blocked_ips)
                self.assertEqual(
                    result.blocked_ips[cause][0].code,
                    "APP_OVERRIDE_READ_ONLY",
                )
                self.assertFalse(result.patchset.mutations)
                self.assertTrue(
                    any("Application Override" in item for item in result.patchset.warnings)
                )

    def test_default_policy_is_protected_unless_explicit_override_is_enabled(self):
        config = self.fixture()
        shared = config.find("./shared")
        self.assertIsNotNone(shared)
        address = shared.find("./address")
        security_rules = shared.find("./pre-rulebase/security/rules")
        self.assertIsNotNone(address)
        self.assertIsNotNone(security_rules)
        address.append(parse_xml('<entry name="DEFAULT_TARGET"><ip-netmask>198.51.100.77/32</ip-netmask></entry>'))
        security_rules.append(
            parse_xml(
                '<entry name="DEFAULT"><source><member>DEFAULT_TARGET</member></source>'
                '<destination><member>any</member></destination><action>allow</action></entry>'
            )
        )

        protected = build_cleanup_patchset(
            config,
            ("198.51.100.77",),
            panorama_host="pano",
            panorama_username="admin",
        )
        self.assertIn("198.51.100.77", protected.blocked_ips)
        self.assertEqual(
            protected.blocked_ips["198.51.100.77"][0].code,
            "DEFAULT_POLICY_PROTECTED",
        )
        self.assertFalse(protected.patchset.mutations)
        self.assertTrue(any("DEFAULT" in warning for warning in protected.patchset.warnings))

        direct = build_cleanup_patchset(
            config,
            (),
            policy_names=("DEFAULT",),
            panorama_host="pano",
            panorama_username="admin",
        )
        self.assertIn("policy:DEFAULT", direct.blocked_ips)
        self.assertEqual(
            direct.blocked_ips["policy:DEFAULT"][0].code,
            "DEFAULT_POLICY_PROTECTED",
        )

        overridden = build_cleanup_patchset(
            config,
            ("198.51.100.77",),
            panorama_host="pano",
            panorama_username="admin",
            allow_default_policy_override=True,
        )
        self.assertTrue(overridden.patchset.mutations)
        self.assertTrue(any("override polityki DEFAULT" in warning for warning in overridden.patchset.warnings))

    def test_exclusion_expands_over_the_whole_atomic_dependency_component(self):
        result = build_cleanup_patchset(
            self.fixture(),
            ("192.0.2.1", "192.0.2.2", "192.0.2.3"),
            panorama_host="pano",
            panorama_username="admin",
        )
        remaining, removed_components, impacted = _cleanup_exclusion_closure(
            result.patchset, ("192.0.2.2",)
        )
        self.assertEqual(set(impacted), {"192.0.2.2", "192.0.2.3"})
        self.assertEqual(len(removed_components), 1)
        self.assertEqual(
            {cause for mutation in remaining for cause in mutation.causes},
            {"192.0.2.1"},
        )

        shared_component = next(
            mutation.component_id
            for mutation in result.patchset.mutations
            if "192.0.2.1" in mutation.causes
        )
        remaining, removed_components, impacted = _cleanup_exclusion_closure(
            result.patchset, component_ids=(shared_component,)
        )
        self.assertEqual(impacted, ("192.0.2.1",))
        self.assertEqual(removed_components, (shared_component,))
        self.assertEqual(
            {cause for mutation in remaining for cause in mutation.causes},
            {"192.0.2.2", "192.0.2.3"},
        )

    def test_sequential_exclusions_keep_unrelated_component_available(self):
        result = build_cleanup_patchset(
            self.fixture(),
            ("192.0.2.1", "192.0.2.2", "192.0.2.3"),
            panorama_host="pano",
            panorama_username="admin",
        )
        after_first, _, impacted_first = _cleanup_exclusion_closure(
            result.patchset, ("192.0.2.1",)
        )
        self.assertEqual(impacted_first, ("192.0.2.1",))
        self.assertEqual(
            {cause for mutation in after_first for cause in mutation.causes},
            {"192.0.2.2", "192.0.2.3"},
        )
        after_second, _, impacted_second = _cleanup_exclusion_closure(
            result.patchset, ("192.0.2.2",)
        )
        self.assertEqual(set(impacted_second), {"192.0.2.2", "192.0.2.3"})
        self.assertEqual(
            {cause for mutation in after_second for cause in mutation.causes},
            {"192.0.2.1"},
        )


class PolicyRequestTests(unittest.TestCase):
    SAMPLE = """API Answer Success: true
Passes Done
[]
Passes ToDo
['[GRUPA/USER AD] -> 443-tcp |  |  | bezterminowo',
 '10.10.10.0/24 -> 10.20.30.40 | 8443-tcp | ssl | bezterminowo']
Info Src
{
  '[GRUPA/USER AD]': {
    'IdType': 'paloGroup', 'zone': 'USERS', 'device_group': 'DG-APP'
  },
  '10.10.10.0/24': {
    'zone': 'SERVERS', 'device_group': 'DG-APP'
  }
}
Info Dst
{
  '443-tcp': {'zone': 'INET', 'device_group': 'DG-APP', 'hg': 'none'},
  '10.20.30.40': {'zone': 'INET', 'device_group': 'DG-APP', 'hg': 'none'}
}
"""

    def test_parser_accepts_mixed_service_request_and_ignores_passes_done(self):
        parsed = parse_policy_request(self.SAMPLE)
        self.assertEqual(len(parsed.flows), 2)
        self.assertEqual(parsed.flows[0].device_group, "DG-APP")
        self.assertEqual(parsed.flows[0].source_zone, "USERS")
        self.assertTrue(any("Passes Done" in warning for warning in parsed.warnings))

    def test_creation_plan_uses_targeted_reads_and_naming_conventions(self):
        class FakeReader:
            profile = PanoramaProfile("pano", "admin")

            def __init__(self):
                self.reads = []

            def fetch_xpath(self, xpath, *, config_type="running"):
                self.reads.append((xpath, config_type))
                return parse_xml('<response status="success"><result /></response>')

        reader = FakeReader()
        result = build_policy_creation_plan(reader, self.SAMPLE)
        self.assertEqual(len(reader.reads), len(result.patchset.mutations) * 2)
        self.assertTrue(any(m.entity_key.endswith("/H-10.20.30.40-32") for m in result.patchset.mutations))
        self.assertTrue(any(m.entity_key.endswith("/N-10.10.10.0-24") for m in result.patchset.mutations))
        self.assertTrue(any(m.entity_type == "service" and "SVC__8443-tcp" in m.entity_key for m in result.patchset.mutations))
        policy = next(m for m in result.patchset.mutations if m.entity_type == "policy" and "N-10.10.10.0-24__H-10.20.30.40-32" in m.entity_key)
        self.assertIn("<action>allow</action>", policy.after_xml or "")


class WebBoundaryTests(unittest.TestCase):
    def test_gui_serve_does_not_require_legacy_hostname_file(self):
        args = build_parser().parse_args(["serve"])
        self.assertIsNone(args.host_file)

    def test_terminal_job_hides_dispatched_breadcrumb_instead_of_staying_at_50_percent(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary) / "sessions", enforce_acl=False)
            profile = PanoramaProfile("pano", "admin", api_max_stage=ApiStage.PUSH)
            patch = build_cleanup_patchset(
                CleanerAdapterTests.fixture(),
                (),
                policy_names=("SEC-MIX",),
                panorama_host="pano",
                panorama_username="admin",
            ).patchset
            session_id = store.create(patch, profile)
            store.add_job(session_id, "commit-dispatched", {"job_id": "77"})
            store.add_job(
                session_id,
                "commit",
                {"job_id": "77", "status": "FIN", "result": "OK", "details": "done"},
            )
            wired = _wire_session(store, session_id)
            self.assertEqual(len(wired["jobs"]), 1)
            self.assertEqual(wired["jobs"][0]["state"], "success")
            self.assertEqual(wired["jobs"][0]["progress"], 100)

    def test_gui_profile_always_allows_runtime_write_gate(self):
        requested = PanoramaProfile(
            "pano", "admin", api_max_stage=ApiStage.PUSH
        )
        effective, warning = _apply_profile_ceiling(requested, None)
        self.assertEqual(effective.api_max_stage, ApiStage.PUSH)
        self.assertIsNone(warning)

        ceiling = PanoramaProfile(
            "pano", "admin", api_max_stage=ApiStage.COMMIT
        )
        effective, warning = _apply_profile_ceiling(requested, ceiling)
        self.assertEqual(effective.api_max_stage, ApiStage.PUSH)
        self.assertIsNone(warning)

    def test_localhost_origin_csp_contract_and_no_cors(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = create_app(
                static_dir=Path(temporary) / "static",
                store=SessionStore(Path(temporary) / "sessions", enforce_acl=False),
            )
            client = app.test_client()
            response = client.get("/api/v1/health", headers={"Host": "evil.example"})
            self.assertEqual(response.status_code, 400)
            response = client.get("/api/v1/meta", headers={"Host": "localhost"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                response.json["authentication"]["connectionTokenHeader"],
                "X-Toolbox-Session",
            )
            self.assertIn("POST /sessions/{id}/commit-jobs", response.json["paths"])
            self.assertIn("POST /sessions/{id}/push-jobs", response.json["paths"])
            self.assertIn(
                "POST /cleanup/plans/{id}/exclusions", response.json["paths"]
            )
            self.assertNotIn("Access-Control-Allow-Origin", response.headers)
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
            self.assertNotIn("unsafe-inline", response.headers["Content-Security-Policy"])
            denied = client.post("/api/v1/doctor", json={}, headers={"Host": "localhost"})
            self.assertEqual(denied.status_code, 403)
            allowed = client.post(
                "/api/v1/doctor",
                json={},
                headers={"Host": "localhost", "Origin": "http://localhost"},
            )
            self.assertEqual(allowed.status_code, 200)
            self.assertIn("checks", allowed.json)
            bad_json = client.post(
                "/api/v1/doctor",
                data="not-json",
                headers={
                    "Host": "localhost",
                    "Origin": "http://localhost",
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(bad_json.status_code, 400)
            self.assertIn("message", bad_json.json)

    def test_connection_endpoint_builds_profile_and_keeps_password_out_of_response(self):
        class FakeReadClient:
            def __init__(self, profile):
                self.profile = profile
                self.closed = False

            def authenticate(self, password):
                self.authenticated_with = password

            def system_info(self):
                return parse_xml(
                    '<response status="success"><result><system>'
                    '<sw-version>10.2.16-h4</sw-version>'
                    '</system></result></response>'
                )

            def change_summary(self):
                return parse_xml('<response status="success"><result /></response>')

            def fetch_config(self, _config_type):
                raise AssertionError("Połączenie nie może pobierać pełnej konfiguracji.")

            def close(self):
                self.closed = True

        with tempfile.TemporaryDirectory() as temporary:
            ceiling = PanoramaProfile(
                "192.0.2.10",
                "superadmin",
                use_ssl=False,
                verify_ssl=False,
                api_max_stage=ApiStage.CANDIDATE,
            )
            app = create_app(
                static_dir=Path(temporary) / "static",
                store=SessionStore(Path(temporary) / "sessions", enforce_acl=False),
                profile_ceiling=ceiling,
            )
            with mock.patch("panos_toolbox.web.PanoramaReadClient", FakeReadClient):
                client = app.test_client()
                response = client.post(
                    "/api/v1/connections",
                    json={
                        "host": "192.0.2.10",
                        "username": "superadmin",
                        "password": "not-persisted",
                        "ssl": False,
                        "verify_ssl": False,
                        "api_max_stage": "candidate",
                        "save_profile": True,
                        "profile_name": "Test Panorama",
                    },
                    headers={"Host": "localhost", "Origin": "http://localhost"},
                )

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json["api_max_stage"], "push")
                self.assertEqual(response.json["panorama_version"], "10.2.16-h4")
                self.assertTrue(response.json["profile_saved"])
                self.assertNotIn("not-persisted", response.get_data(as_text=True))
                profiles = client.get(
                    "/api/v1/profiles", headers={"Host": "localhost"}
                )
                self.assertEqual(profiles.status_code, 200)
                self.assertEqual(profiles.json["profiles"][0]["name"], "Test Panorama")
                token = response.json["session_token"]
                disconnected = client.delete(
                    "/api/v1/connections/current",
                    headers={
                        "Host": "localhost",
                        "Origin": "http://localhost",
                        "X-Toolbox-Session": token,
                    },
                )
                self.assertEqual(disconnected.status_code, 204)

    def test_commit_endpoint_runs_as_background_job_with_live_phase_log(self):
        fixture = CleanerAdapterTests.fixture()

        class FakeReadClient:
            def __init__(self, profile):
                self.profile = profile

            def authenticate(self, _password):
                return None

            def system_info(self):
                return parse_xml(
                    '<response status="success"><result><system>'
                    '<sw-version>10.2.16-h4</sw-version>'
                    '</system></result></response>'
                )

            def change_summary(self):
                return parse_xml('<response status="success"><result /></response>')

            def close(self):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary) / "sessions", enforce_acl=False)
            profile = PanoramaProfile("192.0.2.10", "admin", api_max_stage=ApiStage.PUSH)
            patchset = build_cleanup_patchset(
                fixture,
                (),
                policy_names=("SEC-MIX",),
                panorama_host=profile.host,
                panorama_username=profile.username,
            ).patchset
            session_id = store.create(patchset, profile)
            app = create_app(
                static_dir=Path(temporary) / "static",
                store=store,
                profile_ceiling=profile,
            )
            headers = {"Host": "localhost", "Origin": "http://localhost"}

            def fake_commit(_store, _session_id, _reader, _writer, **kwargs):
                callback = kwargs["progress_callback"]
                callback(44, "Panorama przyjęła commit job 88", {"event": "panorama-job-dispatched", "jobId": "88"})
                callback(100, "Commit zakończony poprawnie", {"event": "stage-finished", "jobId": "88", "elapsedSeconds": 1.2})
                return {"total_duration_seconds": 1.2}

            with (
                mock.patch("panos_toolbox.web.PanoramaReadClient", FakeReadClient),
                mock.patch("panos_toolbox.web.make_writer", return_value=object()),
                mock.patch("panos_toolbox.web.commit_session", side_effect=fake_commit),
            ):
                client = app.test_client()
                connected = client.post(
                    "/api/v1/connections",
                    json={
                        "host": profile.host,
                        "username": profile.username,
                        "password": "memory-only",
                        "ssl": True,
                        "verify_ssl": False,
                        "api_max_stage": "push",
                    },
                    headers=headers,
                )
                token = connected.json["session_token"]
                session_headers = {**headers, "X-Toolbox-Session": token}
                started = client.post(
                    f"/api/v1/sessions/{session_id}/commit-jobs",
                    json={
                        "enable_api_write": True,
                        "execution_stage": "push",
                        "allow_unisolated_commit": True,
                    },
                    headers=session_headers,
                )
                self.assertEqual(started.status_code, 202, started.get_data(as_text=True))
                job = started.json
                for _ in range(100):
                    if job["state"] in {"success", "failed"}:
                        break
                    time.sleep(0.01)
                    job = client.get(
                        f"/api/v1/execution-jobs/{job['id']}",
                        headers={"Host": "localhost", "X-Toolbox-Session": token},
                    ).json
                self.assertEqual(job["state"], "success", job.get("error"))
                self.assertEqual(job["kind"], "commit")
                self.assertEqual(job["progress"], 100)
                self.assertTrue(any(item["event"] == "stage-finished" for item in job["items"]))
                self.assertIsNotNone(job["finishedAt"])

    def test_async_analysis_reports_progress_and_can_split_single_component(self):
        fixture = CleanerAdapterTests.fixture()

        class FakeReadClient:
            def __init__(self, profile):
                self.profile = profile

            def authenticate(self, _password):
                return None

            def system_info(self):
                return parse_xml(
                    '<response status="success"><result><system>'
                    '<sw-version>10.2.16-h4</sw-version>'
                    '</system></result></response>'
                )

            def fetch_config(self, _config_type):
                return copy.deepcopy(fixture)

            def fetch_config_cached(self, config_type, **_kwargs):
                return self.fetch_config(config_type)

            def change_summary(self):
                return parse_xml('<response status="success"><result /></response>')

            def run_op_show(self, _command):
                return parse_xml(
                    '<response status="success"><result><rule-hit-count><rules>'
                    '<entry name="result"><latest>yes</latest><hit-count>0</hit-count>'
                    '<last-hit-timestamp>0</last-hit-timestamp></entry>'
                    '</rules></rule-hit-count></result></response>'
                )

            def close(self):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            profile = PanoramaProfile(
                "192.0.2.10",
                "superadmin",
                use_ssl=False,
                verify_ssl=False,
                api_max_stage=ApiStage.READ_ONLY,
            )
            store = SessionStore(Path(temporary) / "sessions", enforce_acl=False)
            app = create_app(
                static_dir=Path(temporary) / "static",
                store=store,
                profile_ceiling=profile,
            )
            headers = {"Host": "localhost", "Origin": "http://localhost"}
            with mock.patch("panos_toolbox.web.PanoramaReadClient", FakeReadClient):
                client = app.test_client()
                connected = client.post(
                    "/api/v1/connections",
                    json={
                        "host": "192.0.2.10",
                        "username": "superadmin",
                        "password": "memory-only",
                        "ssl": False,
                        "verify_ssl": False,
                        "api_max_stage": "read-only",
                    },
                    headers=headers,
                )
                token = connected.json["session_token"]
                session_headers = {**headers, "X-Toolbox-Session": token}
                started = client.post(
                    "/api/v1/cleanup/analysis-jobs",
                    json={
                        "addresses": [],
                        "address_objects": [],
                        "address_groups": [],
                        "policies": ["SEC-MIX"],
                        "run_icmp": False,
                    },
                    headers=session_headers,
                )
                self.assertEqual(started.status_code, 202)
                job = started.json
                for _ in range(200):
                    if job["state"] in {"success", "failed"}:
                        break
                    time.sleep(0.01)
                    job = client.get(
                        f"/api/v1/cleanup/analysis-jobs/{job['id']}",
                        headers={"Host": "localhost", "X-Toolbox-Session": token},
                    ).json
                self.assertEqual(job["state"], "success", job.get("error"))
                self.assertEqual(job["progress"], 100)
                target = job["plan"]["addresses"][0]
                split = client.post(
                    f"/api/v1/cleanup/plans/{job['plan']['sessionId']}/components/{target['componentId']}",
                    json={"target": target["ip"]},
                    headers=session_headers,
                )
                self.assertEqual(split.status_code, 201, split.get_data(as_text=True))
                self.assertEqual(split.json["sourceCount"], 1)
                self.assertTrue(split.json["operations"])

                excluded = client.post(
                    f"/api/v1/cleanup/plans/{job['plan']['sessionId']}/exclusions",
                    json={"targets": [target["ip"]]},
                    headers=session_headers,
                )
                self.assertEqual(
                    excluded.status_code, 201, excluded.get_data(as_text=True)
                )
                self.assertEqual(excluded.json["excludedCount"], 1)
                self.assertEqual(excluded.json["excludedTargets"], [target["ip"]])
                self.assertEqual(
                    excluded.json["parentSessionId"], job["plan"]["sessionId"]
                )
                self.assertEqual(excluded.json["addresses"][0]["decision"], "excluded")
                self.assertTrue(excluded.json["addresses"][0]["excludedByUser"])
                self.assertFalse(excluded.json["operations"])

                excluded_component = client.post(
                    f"/api/v1/cleanup/plans/{job['plan']['sessionId']}/exclusions",
                    json={"targets": [], "component_ids": [target["componentId"]]},
                    headers=session_headers,
                )
                self.assertEqual(
                    excluded_component.status_code,
                    201,
                    excluded_component.get_data(as_text=True),
                )
                self.assertEqual(
                    excluded_component.json["excludedComponentIds"],
                    [target["componentId"]],
                )
                self.assertEqual(excluded_component.json["excludedCount"], 1)
                self.assertFalse(excluded_component.json["operations"])

                parent = client.get(
                    f"/api/v1/cleanup/plans/{job['plan']['sessionId']}",
                    headers={"Host": "localhost", "X-Toolbox-Session": token},
                )
                self.assertEqual(parent.status_code, 200)
                self.assertTrue(parent.json["operations"])


if __name__ == "__main__":
    unittest.main()
