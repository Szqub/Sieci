from __future__ import annotations

import unittest
from unittest import mock

from panos_toolbox.lookup import lookup_exact
from panos_toolbox.xmlutil import parse_xml


class FakeLookupReader:
    def __init__(self):
        self.paths: list[str] = []

    def device_group_names(self):
        return ("DG-A",)

    def fetch_xpath(self, xpath, *, config_type):
        self.assert_running(config_type)
        self.paths.append(xpath)
        if "security/rules" in xpath and "SEC-A" in xpath and "DG-A" in xpath:
            return parse_xml(
                '<response status="success"><result><entry name="SEC-A">'
                '<from><member>trust</member></from><to><member>dmz</member></to>'
                '<source><member>SRC-A</member><member>SRC-GRP</member></source>'
                '<destination><member>DST-A</member></destination>'
                '<service><member>tcp-443</member></service>'
                '<application><member>ssl</member></application>'
                '<tag><member>retire-review</member></tag>'
                '<description>ticket CHG-42</description><action>allow</action>'
                '</entry></result></response>'
            )
        if "application-override/rules" in xpath and "APP-A" in xpath:
            return parse_xml(
                '<response status="success"><result><entry name="APP-A">'
                '<source><member>SRC-A</member></source>'
                '<destination><member>DST-A</member></destination>'
                '</entry></result></response>'
            )
        if "address-group" in xpath and "GRP-A" in xpath:
            return parse_xml(
                '<response status="success"><result><entry name="GRP-A">'
                '<static><member>A</member><member>B</member></static>'
                '</entry></result></response>'
            )
        return parse_xml('<response status="success"><result /></response>')

    @staticmethod
    def assert_running(config_type):
        if config_type != "running":
            raise AssertionError(config_type)


class PointLookupTests(unittest.TestCase):
    @mock.patch("panos_toolbox.lookup._attach_hit_counts")
    def test_policy_lookup_returns_full_fields_dependencies_and_app_override_warning(
        self, attach_hits
    ):
        reader = FakeLookupReader()
        result = lookup_exact(reader, "policy", ["SEC-A", "APP-A"])

        self.assertEqual(result["searchedScopes"], 2)
        self.assertGreater(result["apiCalls"], 1)
        security = next(item for item in result["found"] if item["name"] == "SEC-A")
        values = {field["k"]: field["v"] for field in security["fields"]}
        self.assertEqual(values["Device group"], "DG-A")
        self.assertEqual(values["From / strefa"], "trust")
        self.assertEqual(values["To / strefa"], "dmz")
        self.assertEqual(values["Komentarz"], "ticket CHG-42")
        self.assertEqual(
            {(item["relation"], item["name"]) for item in security["dependencies"]},
            {("source", "SRC-A"), ("source", "SRC-GRP"), ("destination", "DST-A")},
        )
        override = next(item for item in result["found"] if item["name"] == "APP-A")
        self.assertTrue(override["readOnly"])
        self.assertIn("Application Override", override["blockedReason"])
        self.assertTrue(any("Application Override" in warning for warning in result["warnings"]))
        attach_hits.assert_called_once()

    def test_group_lookup_for_explicit_device_group_uses_one_targeted_call(self):
        reader = FakeLookupReader()
        result = lookup_exact(reader, "address-group", ["GRP-A"], device_group="DG-A")
        self.assertEqual(result["apiCalls"], 1)
        self.assertEqual(len(reader.paths), 1)
        self.assertEqual(result["found"][0]["value"], "A, B")
        self.assertEqual(
            [item["name"] for item in result["found"][0]["dependencies"]],
            ["A", "B"],
        )


if __name__ == "__main__":
    unittest.main()
