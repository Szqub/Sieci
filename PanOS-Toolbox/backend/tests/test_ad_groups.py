from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from panos_toolbox.ad_groups import (
    build_filter_blocks,
    escape_ldap_filter_value,
    generate_ad_group_definition,
    panorama_group_name,
)
from panos_toolbox.errors import DependencyError
from panos_toolbox.sessions import SessionStore
from panos_toolbox.web import create_app


class AdGroupGeneratorTests(unittest.TestCase):
    def test_prefix_validation_and_rfc4515_escaping(self):
        self.assertEqual(panorama_group_name("VPN_USERS"), "AD__VPN_USERS")
        self.assertEqual(panorama_group_name("ad__VPN_USERS"), "AD__VPN_USERS")
        self.assertEqual(
            escape_ldap_filter_value(r"CN=Ops (Tier*),OU=Net\,DC=example"),
            r"CN=Ops \28Tier\2a\29,OU=Net\5c,DC=example",
        )

    def test_validation_skips_empty_and_missing_and_chunks_by_six(self):
        names = [f"GROUP-{index}" for index in range(1, 9)]

        def lookup(values):
            self.assertEqual(list(values), names)
            return [
                {
                    "name": name,
                    "status": "empty" if name == "GROUP-7" else "not-found" if name == "GROUP-8" else "valid",
                    "memberCount": 0 if name in {"GROUP-7", "GROUP-8"} else index,
                    "distinguishedName": None if name in {"GROUP-7", "GROUP-8"} else f"CN={name},OU=Groups,DC=example,DC=local",
                }
                for index, name in enumerate(names, start=1)
            ]

        result = generate_ad_group_definition(
            names,
            output_name="NET_ACCESS",
            mapping_name="LDAP_GM1",
            vsys="vsys1",
            template_name="TPL-NET",
            lookup=lookup,
        )

        self.assertEqual(result["outputGroupName"], "AD__NET_ACCESS")
        self.assertEqual(result["validCount"], 6)
        self.assertEqual(result["skippedCount"], 2)
        self.assertEqual(len(result["blocks"]), 1)
        self.assertTrue(result["blocks"][0]["filter"].startswith("(|"))
        self.assertIn("TPL-NET", result["panoramaPath"])
        self.assertIn("LDAP_GM1", result["panoramaPath"])

    def test_filter_blocks_create_second_block_after_six(self):
        groups = [
            {"name": f"G-{index}", "distinguishedName": f"CN=G-{index},DC=example"}
            for index in range(7)
        ]
        blocks = build_filter_blocks(groups)
        self.assertEqual([len(block["sourceGroups"]) for block in blocks], [6, 1])
        self.assertTrue(blocks[1]["filter"].startswith("(memberof="))


class AdGroupWebTests(unittest.TestCase):
    def app_client(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        app = create_app(
            static_dir=Path(temporary.name) / "static",
            store=SessionStore(Path(temporary.name) / "sessions", enforce_acl=False),
        )
        return app.test_client()

    def test_endpoint_is_local_only_but_does_not_require_panorama_connection(self):
        result = {
            "outputGroupName": "AD__VPN",
            "groups": [],
            "blocks": [],
            "warnings": [],
        }
        with mock.patch("panos_toolbox.web.generate_ad_group_definition", return_value=result) as generate:
            response = self.app_client().post(
                "/api/v1/ad-groups/generate",
                json={
                    "groups": ["GG-VPN"],
                    "output_name": "VPN",
                    "mapping_name": "LDAP_GM1",
                    "vsys": "vsys1",
                    "template_name": "TPL-NET",
                },
                headers={"Host": "localhost", "Origin": "http://localhost"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["outputGroupName"], "AD__VPN")
        generate.assert_called_once_with(
            ["GG-VPN"],
            output_name="VPN",
            mapping_name="LDAP_GM1",
            vsys="vsys1",
            template_name="TPL-NET",
        )

    def test_missing_rsat_is_reported_as_dependency_error(self):
        with mock.patch(
            "panos_toolbox.web.generate_ad_group_definition",
            side_effect=DependencyError("Brak RSAT"),
        ):
            response = self.app_client().post(
                "/api/v1/ad-groups/generate",
                json={"groups": ["GG-VPN"], "output_name": "VPN"},
                headers={"Host": "localhost", "Origin": "http://localhost"},
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json["code"], "DependencyError")


if __name__ == "__main__":
    unittest.main()
