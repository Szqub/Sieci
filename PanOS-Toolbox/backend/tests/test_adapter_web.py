from __future__ import annotations

import copy
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from panos_toolbox.cleaner_adapter import build_cleanup_patchset
from panos_toolbox.models import ApiStage
from panos_toolbox.profile import PanoramaProfile
from panos_toolbox.sessions import SessionStore
from panos_toolbox.web import _apply_profile_ceiling, create_app
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


class WebBoundaryTests(unittest.TestCase):
    def test_gui_profile_is_clamped_by_independent_server_ceiling(self):
        requested = PanoramaProfile(
            "pano", "admin", api_max_stage=ApiStage.PUSH
        )
        effective, warning = _apply_profile_ceiling(requested, None)
        self.assertEqual(effective.api_max_stage, ApiStage.READ_ONLY)
        self.assertIsNotNone(warning)

        ceiling = PanoramaProfile(
            "pano", "admin", api_max_stage=ApiStage.COMMIT
        )
        effective, warning = _apply_profile_ceiling(requested, ceiling)
        self.assertEqual(effective.api_max_stage, ApiStage.COMMIT)
        self.assertIsNotNone(warning)

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

            def fetch_config(self, config_type):
                self.assert_config_type(config_type)
                return parse_xml('<config version="10.2.16-h4"><shared /></config>')

            @staticmethod
            def assert_config_type(config_type):
                if config_type not in {"running", "candidate"}:
                    raise AssertionError(config_type)

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
                    },
                    headers={"Host": "localhost", "Origin": "http://localhost"},
                )

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json["api_max_stage"], "candidate")
                self.assertEqual(response.json["panorama_version"], "10.2.16-h4")
                self.assertNotIn("not-persisted", response.get_data(as_text=True))
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

    def test_async_analysis_reports_progress_and_can_split_single_component(self):
        fixture = CleanerAdapterTests.fixture()

        class FakeReadClient:
            def __init__(self, profile):
                self.profile = profile

            def authenticate(self, _password):
                return None

            def fetch_config(self, _config_type):
                return copy.deepcopy(fixture)

            def fetch_config_cached(self, config_type):
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


if __name__ == "__main__":
    unittest.main()
