from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from panorama_cleanup.artifacts import create_run_directory, write_run_artifacts
from panorama_cleanup.models import (
    CandidateComparison,
    InputError,
    InputRow,
    OutputError,
    ParseError,
    PingResult,
    PingStatus,
    RuleKey,
    RunMetrics,
    ScopedName,
    SnapshotError,
    TransportError,
    UnsafePlanError,
)
from panorama_cleanup.panos import (
    address_literal_relation,
    compare_configs,
    evaluate_dynamic_filter,
    match_ip_objects,
    parse_api_response,
    parse_config,
    static_group_cycle_nodes,
)
from panorama_cleanup.planner import dependency_inventory, plan_cleanup
from panorama_cleanup.render import quote_cli, render_plan
from panorama_cleanup.runtime import (
    confirm_candidate_diff_checked,
    load_host_settings,
    load_ip_rows,
    obtain_password,
    ping_many,
    validate_ca_bundle,
)
from panorama_cleanup.runtime import PanoramaXMLAPI
from panorama_cleanup_planner import (
    PROJECT_DIR,
    build_parser,
    config_completeness_findings,
    main,
)

FIXTURE = Path(__file__).parent / "fixtures" / "panorama_running.xml"


class PlannerFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = ET.parse(FIXTURE).getroot()

    def setUp(self) -> None:
        # parse_config appends format warnings while matching malformed values;
        # each test receives an independent model.
        self.model = parse_config(ET.fromstring(ET.tostring(self.config)))

    def plan_for(self, *ips: str, nat_translation: str = "delete-rule"):
        matches = match_ip_objects(self.model, ips)
        plan = plan_cleanup(
            self.model,
            matches,
            ips,
            nat_translation_action=nat_translation,
        )
        return matches, plan, render_plan(self.model, plan)

    def test_safe_member_removal_and_nested_group_cascade(self) -> None:
        _, plan, rendered = self.plan_for("10.0.0.1")
        self.assertNotIn("10.0.0.1", plan.blocked_ips)
        self.assertIn(ScopedName("shared", "TARGET_A"), plan.deleted_addresses)
        self.assertIn(ScopedName("shared", "G-INNER"), plan.deleted_groups)
        self.assertIn(ScopedName("shared", "G-OUTER"), plan.deleted_groups)
        commands = [record.command for record in rendered.commands]
        self.assertIn(
            'delete shared pre-rulebase security rules "SEC-MIX" source "TARGET_A"',
            commands,
        )
        self.assertIn(
            'delete shared pre-rulebase nat rules "NAT-MIX" source "TARGET_A"',
            commands,
        )
        self.assertIn(
            'delete shared pre-rulebase application-override rules "APP-MIX" source "TARGET_A"',
            commands,
        )
        self.assertIn(
            'delete shared pre-rulebase security rules "SEC-GROUP"', commands
        )
        self.assertNotIn(
            'delete shared pre-rulebase security rules "SEC-GROUP" source "G-OUTER"',
            commands,
        )

    def test_batch_removal_deletes_rule_and_group_instead_of_emptying(self) -> None:
        _, plan, rendered = self.plan_for("10.0.0.1", "10.0.0.2")
        self.assertIn(ScopedName("shared", "G-BATCH"), plan.deleted_groups)
        command_text = "\n".join(record.command for record in rendered.commands)
        self.assertIn(
            'delete shared pre-rulebase security rules "SEC-BATCH"\n',
            command_text + "\n",
        )
        self.assertNotIn('rules "SEC-BATCH" source "TARGET_A"', command_text)
        self.assertNotIn('rules "SEC-BATCH" source "TARGET_B"', command_text)
        self.assertNotIn('address-group "G-BATCH" static', command_text)

    def test_input_order_does_not_change_commands(self) -> None:
        _, _, first = self.plan_for("10.0.0.1", "10.0.0.2")
        _, _, second = self.plan_for("10.0.0.2", "10.0.0.1")
        self.assertEqual(
            [record.command for record in first.commands],
            [record.command for record in second.commands],
        )

    def test_supported_policy_singleton_fields_delete_whole_rules(self) -> None:
        _, plan, rendered = self.plan_for("10.0.0.2")
        commands = {record.command for record in rendered.commands}
        self.assertIn(
            'delete shared pre-rulebase security rules "SEC-B-ONLY"', commands
        )
        self.assertIn('delete shared pre-rulebase nat rules "NAT-B-ONLY"', commands)
        self.assertIn(
            'delete shared pre-rulebase application-override rules "APP-B-ONLY"',
            commands,
        )
        self.assertFalse(
            any('SEC-B-ONLY" destination' in command for command in commands)
        )
        self.assertFalse(any('NAT-B-ONLY" source' in command for command in commands))
        self.assertFalse(
            any('APP-B-ONLY" destination' in command for command in commands)
        )

    def test_deleted_group_order_is_parent_before_child_and_object_last(self) -> None:
        _, _, rendered = self.plan_for("10.0.0.1")
        commands = [record.command for record in rendered.commands]
        outer = commands.index('delete shared address-group "G-OUTER"')
        inner = commands.index('delete shared address-group "G-INNER"')
        address = commands.index('delete shared address "TARGET_A"')
        self.assertLess(outer, inner)
        self.assertLess(inner, address)

    def test_nat_translation_deletes_owner_rule_by_default(self) -> None:
        _, plan, rendered = self.plan_for("203.0.113.10")
        self.assertNotIn("203.0.113.10", plan.blocked_ips)
        commands = {record.command for record in rendered.commands}
        self.assertIn('delete shared pre-rulebase nat rules "NAT-TRANS"', commands)
        self.assertIn('delete shared address "TRANS_TARGET"', commands)
        self.assertIn(
            'set shared pre-rulebase nat rules "NAT-TRANS" '
            'destination-translation translated-address "TRANS_TARGET"',
            rendered.rollback_commands,
        )

    def test_nat_translation_can_be_blocked_explicitly(self) -> None:
        _, plan, rendered = self.plan_for(
            "203.0.113.10", nat_translation="block"
        )
        self.assertIn("203.0.113.10", plan.blocked_ips)
        self.assertEqual([], rendered.commands)
        self.assertIn(
            "NAT_TRANSLATION_REFERENCE",
            {reason.code for reason in plan.blocked_ips["203.0.113.10"]},
        )

    def test_nat_source_destination_and_translation_are_cleaned_atomically(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address>
                <entry name="TARGET"><ip-netmask>198.51.100.10/32</ip-netmask></entry>
                <entry name="KEEP"><ip-netmask>198.51.100.20/32</ip-netmask></entry>
              </address>
              <pre-rulebase><nat><rules>
                <entry name="NAT-MIX">
                  <source><member>TARGET</member><member>KEEP</member></source>
                  <destination><member>any</member></destination>
                </entry>
                <entry name="NAT-ONLY">
                  <source><member>any</member></source>
                  <destination><member>TARGET</member></destination>
                </entry>
                <entry name="NAT-TRANSLATION">
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <destination-translation>
                    <translated-address>TARGET</translated-address>
                  </destination-translation>
                </entry>
              </rules></nat></pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["198.51.100.10"])
        plan = plan_cleanup(model, matches, ["198.51.100.10"])
        rendered = render_plan(model, plan)

        self.assertEqual({}, plan.blocked_ips)
        self.assertEqual(
            {
                'delete shared pre-rulebase nat rules "NAT-MIX" source "TARGET"',
                'delete shared pre-rulebase nat rules "NAT-ONLY"',
                'delete shared pre-rulebase nat rules "NAT-TRANSLATION"',
                'delete shared address "TARGET"',
            },
            {record.command for record in rendered.commands},
        )
        self.assertNotIn(
            'delete shared pre-rulebase nat rules "NAT-TRANSLATION" '
            'destination-translation translated-address "TARGET"',
            {record.command for record in rendered.commands},
        )

    def test_translation_word_in_rule_name_does_not_trigger_nat_rule_deletion(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address><entry name="TARGET">
                <ip-netmask>198.51.100.10/32</ip-netmask>
              </entry></address>
              <pre-rulebase><nat><rules>
                <entry name="contains-translation-word">
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <future-field><addresses><member>TARGET</member></addresses></future-field>
                </entry>
              </rules></nat></pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["198.51.100.10"])
        plan = plan_cleanup(model, matches, ["198.51.100.10"])

        self.assertEqual([], render_plan(model, plan).commands)
        self.assertIn(
            "UNSUPPORTED_REFERENCE",
            {reason.code for reason in plan.blocked_ips["198.51.100.10"]},
        )
        self.assertNotIn(
            "NAT_TRANSLATION_REFERENCE",
            {reason.code for reason in plan.blocked_ips["198.51.100.10"]},
        )

    def test_negated_security_field_blocks_atomically(self) -> None:
        _, plan, rendered = self.plan_for("203.0.113.11")
        self.assertEqual([], rendered.commands)
        self.assertIn(
            "NEGATED_FIELD_REQUIRES_REVIEW",
            {reason.code for reason in plan.blocked_ips["203.0.113.11"]},
        )

    def test_unsupported_policy_reference_blocks(self) -> None:
        _, plan, rendered = self.plan_for("203.0.113.12")
        self.assertEqual([], rendered.commands)
        self.assertIn(
            "UNSUPPORTED_REFERENCE",
            {reason.code for reason in plan.blocked_ips["203.0.113.12"]},
        )

    def test_touched_static_group_cycle_blocks(self) -> None:
        _, plan, rendered = self.plan_for("10.0.0.3")
        self.assertEqual([], rendered.commands)
        self.assertIn(
            "STATIC_GROUP_CYCLE",
            {reason.code for reason in plan.blocked_ips["10.0.0.3"]},
        )

    def test_exact_match_never_deletes_containing_subnet_or_range(self) -> None:
        matches = match_ip_objects(self.model, ["10.0.0.1", "10.0.0.50"])
        self.assertEqual(
            (ScopedName("shared", "TARGET_A"),), matches["10.0.0.1"].exact_objects
        )
        self.assertEqual(
            {"NET_CONTAINS", "RANGE_CONTAINS"},
            {key.name for key in matches["10.0.0.1"].containing_objects},
        )
        self.assertEqual(
            (ScopedName("shared", "SINGLE_RANGE"),),
            matches["10.0.0.50"].exact_objects,
        )

    def test_scope_override_and_parent_inheritance(self) -> None:
        matches = match_ip_objects(
            self.model, ["192.0.2.1", "192.0.2.2", "192.0.2.3", "198.51.100.10"]
        )
        self.assertEqual("shared", matches["192.0.2.1"].exact_objects[0].location)
        self.assertEqual("DG-PARENT", matches["192.0.2.2"].exact_objects[0].location)
        self.assertEqual("DG-CHILD", matches["192.0.2.3"].exact_objects[0].location)
        _, plan, rendered = self.plan_for("198.51.100.10")
        commands = {record.command for record in rendered.commands}
        self.assertIn(
            'delete device-group "DG-CHILD" post-rulebase nat rules "CHILD-NAT"',
            commands,
        )
        self.assertIn(
            'delete device-group "DG-PARENT" address "PARENT_ONLY"', commands
        )

    def test_dynamic_group_membership_blocks_object_deletion(self) -> None:
        _, plan, rendered = self.plan_for("10.0.0.4")
        self.assertEqual([], rendered.commands)
        self.assertIn(
            "DYNAMIC_GROUP_MEMBERSHIP_REQUIRES_REVIEW",
            {reason.code for reason in plan.blocked_ips["10.0.0.4"]},
        )

    def test_all_definitions_of_one_ip_are_blocked_atomically(self) -> None:
        config = ET.fromstring(
            """
            <config>
              <shared>
                <address><entry name="SHARED-T"><ip-netmask>100.64.0.1/32</ip-netmask></entry></address>
                <pre-rulebase><pbf><rules><entry name="PBF-T">
                  <source><member>SHARED-T</member></source><destination><member>any</member></destination>
                </entry></rules></pbf></pre-rulebase>
              </shared>
              <devices><entry name="localhost.localdomain"><device-group><entry name="DG-A">
                <address><entry name="LOCAL-T"><ip-netmask>100.64.0.1/32</ip-netmask></entry></address>
              </entry></device-group></entry></devices>
            </config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["100.64.0.1"])
        plan = plan_cleanup(model, matches, ["100.64.0.1"])
        rendered = render_plan(model, plan)
        self.assertIn("100.64.0.1", plan.blocked_ips)
        self.assertEqual(set(), plan.deleted_addresses)
        self.assertEqual([], rendered.commands)

    def test_inherited_rule_using_child_override_blocks_child_deletion(self) -> None:
        config = ET.fromstring(
            """
            <config>
              <shared/>
              <devices><entry name="localhost.localdomain"><device-group>
                <entry name="PARENT">
                  <address><entry name="OVR"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address>
                  <pre-rulebase><security><rules><entry name="PARENT-RULE">
                    <source><member>OVR</member></source><destination><member>any</member></destination>
                  </entry></rules></security></pre-rulebase>
                </entry>
                <entry name="CHILD"><parent-dg>PARENT</parent-dg>
                  <address><entry name="OVR"><ip-netmask>192.0.2.2/32</ip-netmask></entry></address>
                </entry>
              </device-group></entry></devices>
            </config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["192.0.2.2"])
        plan = plan_cleanup(model, matches, ["192.0.2.2"])
        rendered = render_plan(model, plan)
        self.assertEqual([], rendered.commands)
        reasons = plan.blocked_ips["192.0.2.2"]
        self.assertIn("INHERITED_OVERRIDE_REFERENCE", {item.code for item in reasons})
        self.assertIn("effective_scope=CHILD", reasons[0].message)
        _, rules, paths = dependency_inventory(model, ScopedName("CHILD", "OVR"))
        self.assertIn(
            next(key for key in model.rules if key.name == "PARENT-RULE"), rules
        )
        self.assertTrue(any("effective_scope=CHILD" in path for path in paths))

    def test_ancestor_precedence_resolves_parent_before_child_override(self) -> None:
        config = ET.fromstring(
            """
            <config>
              <shared/>
              <devices><entry name="localhost.localdomain">
                <deviceconfig><setting><management>
                  <ancestor-objects-take-precedence>yes</ancestor-objects-take-precedence>
                </management></setting></deviceconfig>
                <device-group>
                  <entry name="PARENT">
                    <address><entry name="OVR"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address>
                    <pre-rulebase><security><rules><entry name="PARENT-RULE">
                      <source><member>OVR</member></source><destination><member>any</member></destination>
                    </entry></rules></security></pre-rulebase>
                  </entry>
                  <entry name="CHILD"><parent-dg>PARENT</parent-dg>
                    <address><entry name="OVR"><ip-netmask>192.0.2.2/32</ip-netmask></entry></address>
                  </entry>
                </device-group>
              </entry></devices>
            </config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["192.0.2.2"])
        plan = plan_cleanup(model, matches, ["192.0.2.2"])
        rendered = render_plan(model, plan)
        self.assertNotIn("192.0.2.2", plan.blocked_ips)
        self.assertEqual(
            ['delete device-group "CHILD" address "OVR"'],
            [record.command for record in rendered.commands],
        )

    def test_parent_rule_mutation_blocks_non_target_child_override(self) -> None:
        config = ET.fromstring(
            """
            <config><shared/><devices><entry name="localhost.localdomain"><device-group>
              <entry name="PARENT">
                <address><entry name="O"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address>
                <pre-rulebase><security><rules><entry name="R">
                  <source><member>O</member></source><destination><member>any</member></destination>
                </entry></rules></security></pre-rulebase>
              </entry>
              <entry name="CHILD"><parent-dg>PARENT</parent-dg>
                <address><entry name="O"><ip-netmask>198.51.100.9/32</ip-netmask></entry></address>
              </entry>
            </device-group></entry></devices></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["192.0.2.10"])
        plan = plan_cleanup(model, matches, ["192.0.2.10"])
        self.assertEqual([], render_plan(model, plan).commands)
        self.assertIn(
            "OWNER_AFFECTS_NON_TARGET_OVERRIDE",
            {reason.code for reason in plan.blocked_ips["192.0.2.10"]},
        )

    def test_deleted_child_group_override_cannot_fall_back_in_parent_rule(self) -> None:
        config = ET.fromstring(
            """
            <config><shared/><devices><entry name="localhost.localdomain"><device-group>
              <entry name="PARENT">
                <address><entry name="SAFE"><ip-netmask>192.0.2.20/32</ip-netmask></entry></address>
                <address-group><entry name="G"><static><member>SAFE</member></static></entry></address-group>
                <pre-rulebase><security><rules><entry name="R">
                  <source><member>G</member></source><destination><member>any</member></destination>
                </entry></rules></security></pre-rulebase>
              </entry>
              <entry name="CHILD"><parent-dg>PARENT</parent-dg>
                <address><entry name="O"><ip-netmask>192.0.2.21/32</ip-netmask></entry></address>
                <address-group><entry name="G"><static><member>O</member></static></entry></address-group>
              </entry>
            </device-group></entry></devices></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["192.0.2.21"])
        plan = plan_cleanup(model, matches, ["192.0.2.21"])
        self.assertEqual([], render_plan(model, plan).commands)
        self.assertIn("192.0.2.21", plan.blocked_ips)

    def test_inherited_unsupported_rule_reference_blocks_child_override(self) -> None:
        config = ET.fromstring(
            """
            <config><shared/><devices><entry name="localhost.localdomain"><device-group>
              <entry name="PARENT">
                <address><entry name="O"><ip-netmask>192.0.2.30/32</ip-netmask></entry></address>
                <pre-rulebase><pbf><rules><entry name="P">
                  <source><member>O</member></source><destination><member>any</member></destination>
                </entry></rules></pbf></pre-rulebase>
              </entry>
              <entry name="CHILD"><parent-dg>PARENT</parent-dg>
                <address><entry name="O"><ip-netmask>192.0.2.31/32</ip-netmask></entry></address>
              </entry>
            </device-group></entry></devices></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["192.0.2.31"])
        plan = plan_cleanup(model, matches, ["192.0.2.31"])
        self.assertEqual([], render_plan(model, plan).commands)
        self.assertIn("192.0.2.31", plan.blocked_ips)

    def test_effective_override_causes_propagate_through_nested_deletes(self) -> None:
        config = ET.fromstring(
            """
            <config><shared/><devices><entry name="localhost.localdomain"><device-group>
              <entry name="PARENT">
                <address><entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address>
                <address-group>
                  <entry name="H"><static><member>A</member></static></entry>
                  <entry name="G"><static><member>H</member></static></entry>
                </address-group>
                <pre-rulebase><security><rules><entry name="R">
                  <source><member>G</member></source><destination><member>any</member></destination>
                </entry></rules></security></pre-rulebase>
              </entry>
              <entry name="CHILD"><parent-dg>PARENT</parent-dg>
                <address><entry name="A"><ip-netmask>192.0.2.2/32</ip-netmask></entry></address>
              </entry>
            </device-group></entry></devices></config>
            """
        )
        model = parse_config(config)
        ips = ["192.0.2.1", "192.0.2.2"]
        matches = match_ip_objects(model, ips)
        plan = plan_cleanup(model, matches, ips)
        rendered = render_plan(model, plan)
        self.assertEqual({}, plan.blocked_ips)
        for record in rendered.commands:
            if record.entity_type in {"group", "policy"}:
                self.assertEqual(tuple(ips), record.causes)


class DirectLiteralAndQuotingTests(unittest.TestCase):
    def test_direct_literal_singleton_deletes_rule_without_address_definition(self) -> None:
        config = ET.fromstring(
            """
            <config><shared><pre-rulebase><security><rules>
              <entry name="Literal Rule"><source><member>10.10.10.10</member></source>
              <destination><member>any</member></destination><action>allow</action></entry>
            </rules></security></pre-rulebase></shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["10.10.10.10"])
        plan = plan_cleanup(model, matches, ["10.10.10.10"])
        rendered = render_plan(model, plan)
        self.assertEqual(
            ['delete shared pre-rulebase security rules "Literal Rule"'],
            [record.command for record in rendered.commands],
        )

    def test_application_override_direct_literal_is_removed_or_deletes_rule(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <pre-rulebase><application-override><rules>
                <entry name="APP-MIX">
                  <from><member>any</member></from>
                  <source><member>10.10.10.10</member><member>10.10.10.20</member></source>
                  <to><member>any</member></to>
                  <destination><member>any</member></destination>
                  <application>custom-app</application><protocol>tcp</protocol><port>443</port>
                </entry>
              </rules></application-override></pre-rulebase>
            </shared>
            <devices><entry name="localhost.localdomain"><device-group>
              <entry name="DG-APP"><post-rulebase><application-override><rules>
                  <entry name="APP-ONLY">
                    <from><member>any</member></from><source><member>any</member></source>
                    <to><member>any</member></to><destination><member>10.10.10.10</member></destination>
                    <application>custom-app</application><protocol>tcp</protocol><port>8443</port>
                  </entry>
              </rules></application-override></post-rulebase></entry>
            </device-group></entry></devices></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["10.10.10.10"])
        plan = plan_cleanup(model, matches, ["10.10.10.10"])
        rendered = render_plan(model, plan)

        self.assertEqual({}, plan.blocked_ips)
        self.assertEqual((), matches["10.10.10.10"].exact_objects)
        self.assertEqual(
            {
                'delete shared pre-rulebase application-override rules "APP-MIX" source "10.10.10.10"',
                'delete device-group "DG-APP" post-rulebase application-override rules "APP-ONLY"',
            },
            {record.command for record in rendered.commands},
        )
        self.assertEqual(
            {
                RuleKey("shared", "pre-rulebase", "application-override", "APP-MIX"),
                RuleKey("DG-APP", "post-rulebase", "application-override", "APP-ONLY"),
            },
            rendered.affected_rules,
        )
        self.assertIn(
            'set shared pre-rulebase application-override rules "APP-MIX" source "10.10.10.10"',
            rendered.rollback_commands,
        )
        self.assertFalse(
            any(
                occurrence.value == "10.10.10.10"
                for occurrence in model.unknown_occurrences
            )
        )

    def test_cli_quoting_handles_spaces_quotes_and_backslashes(self) -> None:
        self.assertEqual('"Name with spaces"', quote_cli("Name with spaces"))
        self.assertEqual('"a\\"b\\\\c"', quote_cli('a"b\\c'))
        for character, label in (
            ("\n", "LF\\(U\\+000A\\)"),
            ("\u0085", "NEL\\(U\\+0085\\)"),
            ("\u2028", "LS\\(U\\+2028\\)"),
            ("\u2029", "PS\\(U\\+2029\\)"),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                UnsafePlanError, label
            ):
                quote_cli(f"bad{character}value", context="test member")

    def test_multiline_description_does_not_abort_apply_plan(self) -> None:
        config = ET.fromstring(
            """
            <config><shared><address><entry name="TARGET">
              <ip-netmask>10.10.10.10/32</ip-netmask>
              <description>address-secret-first
address-secret-second</description>
            </entry></address>
            <address-group><entry name="TARGET-GROUP">
              <static><member>TARGET</member></static>
              <description>group-secret-first&#133;group-secret-second</description>
            </entry></address-group>
            <pre-rulebase><security><rules><entry name="TARGET-RULE">
              <source><member>TARGET-GROUP</member></source>
              <destination><member>any</member></destination>
              <description>rule-secret-first&#8232;rule-secret-middle&#8233;rule-secret-second</description>
            </entry></rules></security></pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["10.10.10.10"])
        plan = plan_cleanup(model, matches, ["10.10.10.10"])
        rendered = render_plan(model, plan)

        self.assertEqual(
            [
                'delete shared pre-rulebase security rules "TARGET-RULE"',
                'delete shared address-group "TARGET-GROUP"',
                'delete shared address "TARGET"',
            ],
            [record.command for record in rendered.commands],
        )
        self.assertEqual(3, len(rendered.rollback_warnings))
        warning_text = "\n".join(rendered.rollback_warnings)
        self.assertIn("ROLLBACK_CLI_FIELD_OMITTED", warning_text)
        self.assertIn("LF(U+000A)", warning_text)
        self.assertIn("NEL(U+0085)", warning_text)
        self.assertIn("LS(U+2028)", warning_text)
        self.assertIn("PS(U+2029)", warning_text)
        self.assertIn("address shared/TARGET", warning_text)
        self.assertIn("address-group shared/TARGET-GROUP", warning_text)
        self.assertIn("rule shared/pre-rulebase/security/TARGET-RULE", warning_text)
        self.assertNotIn("address-secret-first", warning_text)
        self.assertNotIn("group-secret-first", warning_text)
        self.assertNotIn("rule-secret-first", warning_text)
        rollback_text = "\n".join(rendered.rollback_commands)
        self.assertIn('set shared address "TARGET" ip-netmask "10.10.10.10/32"', rollback_text)
        self.assertNotIn("description", rollback_text)

    def test_ipv6_host_is_exact_but_prefix_is_containment_only(self) -> None:
        config = ET.fromstring(
            """
            <config><shared><address>
              <entry name="V6-HOST"><ip-netmask>2001:db8::1/128</ip-netmask></entry>
              <entry name="V6-NET"><ip-netmask>2001:db8::/64</ip-netmask></entry>
            </address></shared></config>
            """
        )
        model = parse_config(config)
        match = match_ip_objects(model, ["2001:0db8::1"])["2001:db8::1"]
        self.assertEqual((ScopedName("shared", "V6-HOST"),), match.exact_objects)
        self.assertEqual((ScopedName("shared", "V6-NET"),), match.containing_objects)

    def test_address_and_group_namespace_collision_fails_closed(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address><entry name="COLLIDE"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address>
              <address-group><entry name="COLLIDE"><static><member>OTHER</member></static></entry></address-group>
            </shared></config>
            """
        )
        with self.assertRaises(ParseError):
            parse_config(config)

    def test_nat_translated_port_is_not_treated_as_address_reference(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address><entry name="80"><ip-netmask>10.0.0.1/32</ip-netmask></entry></address>
              <pre-rulebase><nat><rules><entry name="DNAT">
                <source><member>any</member></source><destination><member>any</member></destination>
                <destination-translation><translated-address>REAL-TRANS</translated-address>
                  <translated-port>80</translated-port></destination-translation>
              </entry></rules></nat></pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["10.0.0.1"])
        plan = plan_cleanup(
            model, matches, ["10.0.0.1"], nat_translation_action="delete-rule"
        )
        rendered = render_plan(model, plan)
        self.assertEqual(
            ['delete shared address "80"'],
            [record.command for record in rendered.commands],
        )

    def test_deleted_rule_records_all_target_causes(self) -> None:
        config = ET.fromstring(
            """
            <config><shared><pre-rulebase><nat><rules><entry name="N">
              <source><member>10.0.0.1</member></source><destination><member>any</member></destination>
              <destination-translation><translated-address>10.0.0.2</translated-address></destination-translation>
            </entry></rules></nat></pre-rulebase></shared></config>
            """
        )
        model = parse_config(config)
        ips = ["10.0.0.1", "10.0.0.2"]
        matches = match_ip_objects(model, ips)
        plan = plan_cleanup(model, matches, ips)
        rendered = render_plan(model, plan)
        self.assertEqual({}, plan.blocked_ips)
        self.assertEqual(1, len(rendered.commands))
        self.assertEqual(("10.0.0.1", "10.0.0.2"), rendered.commands[0].causes)

    def test_nat_pool_range_and_security_subnet_block_contained_ip(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address><entry name="OBJ80"><ip-netmask>192.0.2.80/32</ip-netmask></entry></address>
              <pre-rulebase>
                <security><rules><entry name="NET">
                  <source><member>192.0.2.0/24</member></source><destination><member>any</member></destination>
                </entry></rules></security>
                <nat><rules><entry name="POOL">
                  <source><member>any</member></source><destination><member>any</member></destination>
                  <source-translation><dynamic-ip-and-port><translated-address>
                    <member>192.0.2.1-192.0.2.100</member>
                  </translated-address></dynamic-ip-and-port></source-translation>
                </entry></rules></nat>
              </pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["192.0.2.80"])
        plan = plan_cleanup(model, matches, ["192.0.2.80"])
        self.assertEqual([], render_plan(model, plan).commands)
        reasons = plan.blocked_ips["192.0.2.80"]
        self.assertIn("CONTAINING_LITERAL_REFERENCE", {reason.code for reason in reasons})
        self.assertTrue(any("NET" in reason.message for reason in reasons))
        self.assertTrue(any("POOL" in reason.message for reason in reasons))

    def test_retained_group_in_nat_translation_is_cleaned_without_rule_deletion(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address>
                <entry name="T"><ip-netmask>192.0.2.1/32</ip-netmask></entry>
                <entry name="K"><ip-netmask>192.0.2.2/32</ip-netmask></entry>
              </address>
              <address-group><entry name="POOL"><static>
                <member>T</member><member>K</member>
              </static></entry></address-group>
              <pre-rulebase><nat><rules><entry name="N">
                <source><member>any</member></source><destination><member>any</member></destination>
                <source-translation><dynamic-ip-and-port><translated-address>
                  <member>POOL</member>
                </translated-address></dynamic-ip-and-port></source-translation>
              </entry></rules></nat></pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["192.0.2.1"])

        blocked = plan_cleanup(
            model, matches, ["192.0.2.1"], nat_translation_action="block"
        )
        self.assertEqual([], render_plan(model, blocked).commands)
        self.assertIn(
            "NAT_TRANSLATION_REFERENCE",
            {reason.code for reason in blocked.blocked_ips["192.0.2.1"]},
        )

        plan = plan_cleanup(model, matches, ["192.0.2.1"])
        self.assertEqual({}, plan.blocked_ips)
        commands = {record.command for record in render_plan(model, plan).commands}
        self.assertEqual(
            {
                'delete shared address-group "POOL" static "T"',
                'delete shared address "T"',
            },
            commands,
        )
        self.assertNotIn('delete shared pre-rulebase nat rules "N"', commands)

        groups, rules, paths = dependency_inventory(
            model, ScopedName("shared", "T")
        )
        self.assertIn(ScopedName("shared", "POOL"), groups)
        self.assertIn(RuleKey("shared", "pre-rulebase", "nat", "N"), rules)
        self.assertTrue(any("translated-address" in path for path in paths))

    def test_deleted_group_in_nat_translation_deletes_owner_rule(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address><entry name="T"><ip-netmask>192.0.2.1/32</ip-netmask></entry></address>
              <address-group><entry name="POOL"><static>
                <member>T</member>
              </static></entry></address-group>
              <pre-rulebase><nat><rules><entry name="N">
                <source><member>any</member></source><destination><member>any</member></destination>
                <source-translation><dynamic-ip-and-port><translated-address>
                  <member>POOL</member>
                </translated-address></dynamic-ip-and-port></source-translation>
              </entry></rules></nat></pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["192.0.2.1"])
        plan = plan_cleanup(model, matches, ["192.0.2.1"])
        rendered = render_plan(model, plan)

        self.assertEqual({}, plan.blocked_ips)
        self.assertEqual(
            {
                'delete shared pre-rulebase nat rules "N"',
                'delete shared address-group "POOL"',
                'delete shared address "T"',
            },
            {record.command for record in rendered.commands},
        )

    def test_nested_group_override_in_inherited_nat_fails_closed(self) -> None:
        config = ET.fromstring(
            """
            <config><shared/><devices><entry name="localhost.localdomain"><device-group>
              <entry name="P">
                <address><entry name="PKEEP"><ip-netmask>192.0.2.100/32</ip-netmask></entry></address>
                <address-group>
                  <entry name="B"><static><member>PKEEP</member></static></entry>
                  <entry name="A"><static><member>B</member></static></entry>
                </address-group>
                <pre-rulebase><nat><rules><entry name="N">
                  <source><member>any</member></source><destination><member>any</member></destination>
                  <source-translation><dynamic-ip-and-port><translated-address>
                    <member>A</member>
                  </translated-address></dynamic-ip-and-port></source-translation>
                </entry></rules></nat></pre-rulebase>
              </entry>
              <entry name="C"><parent-dg>P</parent-dg>
                <address>
                  <entry name="T"><ip-netmask>192.0.2.1/32</ip-netmask></entry>
                  <entry name="K"><ip-netmask>192.0.2.2/32</ip-netmask></entry>
                </address>
                <address-group><entry name="B"><static>
                  <member>T</member><member>K</member>
                </static></entry></address-group>
              </entry>
            </device-group></entry></devices></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["192.0.2.1"])
        for action in ("block", "delete-rule"):
            plan = plan_cleanup(
                model,
                matches,
                ["192.0.2.1"],
                nat_translation_action=action,
            )
            self.assertEqual([], render_plan(model, plan).commands)
            self.assertIn("192.0.2.1", plan.blocked_ips)

        _, rules, paths = dependency_inventory(model, ScopedName("C", "T"))
        self.assertIn(RuleKey("P", "pre-rulebase", "nat", "N"), rules)
        self.assertTrue(any("effective_scope=C" in path for path in paths))
        self.assertTrue(
            any(
                "/config/devices/entry[@name='localhost.localdomain']/"
                "device-group/entry[@name='P']/pre-rulebase/nat/rules/"
                "entry[@name='N']/source-translation" in path
                for path in paths
            )
        )

    def test_direct_wildcard_policy_literal_blocks_contained_ip(self) -> None:
        config = ET.fromstring(
            """
            <config><shared><pre-rulebase><security><rules><entry name="WILD">
              <source><member>10.1.2.3/0.127.248.0</member></source>
              <destination><member>any</member></destination>
            </entry></rules></security></pre-rulebase></shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["10.1.2.3"])
        plan = plan_cleanup(model, matches, ["10.1.2.3"])
        self.assertEqual([], render_plan(model, plan).commands)
        self.assertIn(
            "CONTAINING_LITERAL_REFERENCE",
            {reason.code for reason in plan.blocked_ips["10.1.2.3"]},
        )

    def test_exact_wildcard_literal_does_not_match_unrelated_ipv4(self) -> None:
        value = "10.1.1.1/0.0.0.0"
        self.assertEqual("exact", address_literal_relation(value, "10.1.1.1"))
        self.assertIsNone(address_literal_relation(value, "10.1.1.2"))
        self.assertIsNone(address_literal_relation(value, "192.0.2.1"))

        config = ET.fromstring(
            """
            <config><shared><pre-rulebase><security><rules><entry name="W-HOST">
              <source><member>10.1.1.1/0.0.0.0</member></source>
              <destination><member>any</member></destination>
            </entry></rules></security></pre-rulebase></shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["10.1.1.1"])
        plan = plan_cleanup(model, matches, ["10.1.1.1"])
        self.assertEqual(
            ['delete shared pre-rulebase security rules "W-HOST"'],
            [record.command for record in render_plan(model, plan).commands],
        )

    def test_ip_wildcard_exact_and_containing_are_classified(self) -> None:
        config = ET.fromstring(
            """
            <config><shared><address>
              <entry name="W-HOST"><ip-wildcard>10.1.1.1/0.0.0.0</ip-wildcard></entry>
              <entry name="W-MANY"><ip-wildcard>10.1.1.0/0.0.0.255</ip-wildcard></entry>
            </address></shared></config>
            """
        )
        model = parse_config(config)
        match = match_ip_objects(model, ["10.1.1.1"])["10.1.1.1"]
        self.assertEqual((ScopedName("shared", "W-HOST"),), match.exact_objects)
        self.assertEqual((ScopedName("shared", "W-MANY"),), match.containing_objects)

    def test_touched_group_with_unresolved_member_blocks(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address><entry name="A"><ip-netmask>10.0.0.1/32</ip-netmask></entry></address>
              <address-group><entry name="G"><static>
                <member>A</member><member>MISSING</member>
              </static></entry></address-group>
            </shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["10.0.0.1"])
        plan = plan_cleanup(model, matches, ["10.0.0.1"])
        self.assertEqual([], render_plan(model, plan).commands)
        self.assertIn(
            "UNRESOLVED_GROUP_MEMBER",
            {reason.code for reason in plan.blocked_ips["10.0.0.1"]},
        )

    def test_later_nat_rule_delete_suppresses_negated_field_blocker(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address>
                <entry name="NEG"><ip-netmask>10.0.0.1/32</ip-netmask></entry>
                <entry name="TRANS"><ip-netmask>10.0.0.2/32</ip-netmask></entry>
                <entry name="KEEP"><ip-netmask>10.0.0.3/32</ip-netmask></entry>
              </address>
              <pre-rulebase><nat><rules><entry name="N">
                <source><member>NEG</member><member>KEEP</member></source>
                <destination><member>any</member></destination><negate-source>yes</negate-source>
                <destination-translation><translated-address>TRANS</translated-address></destination-translation>
              </entry></rules></nat></pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        ips = ["10.0.0.1", "10.0.0.2"]
        matches = match_ip_objects(model, ips)
        plan = plan_cleanup(
            model, matches, ips, nat_translation_action="delete-rule"
        )
        rendered = render_plan(model, plan)
        self.assertEqual({}, plan.blocked_ips)
        self.assertIn('delete shared pre-rulebase nat rules "N"', [r.command for r in rendered.commands])

    def test_singleton_negated_field_does_not_auto_delete_rule(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address><entry name="NEG"><ip-netmask>10.0.0.1/32</ip-netmask></entry></address>
              <pre-rulebase><security><rules><entry name="N">
                <source><member>NEG</member></source><destination><member>any</member></destination>
                <negate-source>yes</negate-source>
              </entry></rules></security></pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["10.0.0.1"])
        plan = plan_cleanup(model, matches, ["10.0.0.1"])
        self.assertEqual([], render_plan(model, plan).commands)
        self.assertIn(
            "NEGATED_FIELD_REQUIRES_REVIEW",
            {reason.code for reason in plan.blocked_ips["10.0.0.1"]},
        )

    def test_dynamic_filter_boolean_evaluation(self) -> None:
        self.assertFalse(evaluate_dynamic_filter("'A' and 'B'", {"A"}))
        self.assertTrue(evaluate_dynamic_filter("'A' and not 'B'", {"A"}))
        self.assertFalse(evaluate_dynamic_filter("not 'A'", {"A"}))
        self.assertTrue(evaluate_dynamic_filter("not-prod", {"not-prod"}))
        self.assertTrue(evaluate_dynamic_filter("'PROD'", {"prod"}))

    def test_cycle_detection_handles_deep_acyclic_group_chain(self) -> None:
        group_entries = [
            '<entry name="G0"><static><member>A</member></static></entry>'
        ]
        group_entries.extend(
            f'<entry name="G{index}"><static><member>G{index - 1}</member>'
            "</static></entry>"
            for index in range(1, 1100)
        )
        config = ET.fromstring(
            "<config><shared><address><entry name=\"A\"><ip-netmask>"
            "10.0.0.1/32</ip-netmask></entry></address><address-group>"
            + "".join(group_entries)
            + "</address-group></shared></config>"
        )
        model = parse_config(config)
        self.assertEqual(set(), static_group_cycle_nodes(model))

    def test_cycle_detection_does_not_misclassify_dag_cross_edge(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address><entry name="A"><ip-netmask>10.0.0.1/32</ip-netmask></entry></address>
              <address-group>
                <entry name="G0"><static><member>G1</member><member>G2</member></static></entry>
                <entry name="G1"><static><member>G2</member></static></entry>
                <entry name="G2"><static><member>A</member></static></entry>
              </address-group>
            </shared></config>
            """
        )
        model = parse_config(config)
        self.assertEqual(set(), static_group_cycle_nodes(model))

    def test_dynamic_group_tags_are_case_insensitive_end_to_end(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address><entry name="A"><ip-netmask>10.0.0.1/32</ip-netmask>
                <tag><member>prod</member></tag></entry></address>
              <address-group><entry name="D"><dynamic><filter>'PROD'</filter></dynamic></entry></address-group>
              <pre-rulebase><security><rules><entry name="S">
                <source><member>D</member></source><destination><member>any</member></destination>
              </entry></rules></security></pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["10.0.0.1"])
        plan = plan_cleanup(model, matches, ["10.0.0.1"])
        self.assertEqual([], render_plan(model, plan).commands)
        self.assertIn(
            "DYNAMIC_GROUP_MEMBERSHIP_REQUIRES_REVIEW",
            {reason.code for reason in plan.blocked_ips["10.0.0.1"]},
        )


class SnapshotAndRuntimeTests(unittest.TestCase):
    def test_main_manual_confirmation_publishes_when_other_gates_are_clear(self) -> None:
        running = ET.fromstring(
            """
            <config version="10.2.16-h4"><shared>
              <address><entry name="TARGET">
                <ip-netmask>10.0.0.1/32</ip-netmask>
              </entry></address>
              <pre-rulebase><security><rules><entry name="ONLY-RULE">
                <source><member>TARGET</member></source>
                <destination><member>any</member></destination>
              </entry></rules></security></pre-rulebase>
            </shared><devices><entry name="localhost.localdomain">
              <device-group/>
            </entry></devices></config>
            """
        )

        class FakeClient:
            snapshot_call_count = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def authenticate(self, password: str) -> None:
                self.password_was_supplied = bool(password)

            def fetch_config(self, action: str):
                self.snapshot_call_count += 1
                snapshot = ET.fromstring(ET.tostring(running))
                if action == "get":
                    snapshot.find("./shared/address/entry/ip-netmask").text = (
                        "203.0.113.250/32"
                    )
                return snapshot

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            host_file = base / "panorama_host.txt"
            ip_file = base / "ip.txt"
            client = FakeClient()
            host_file.write_text(
                "host=192.0.2.10\nusername=readonly\nssl=yes\n",
                encoding="utf-8",
            )
            ip_file.write_text("10.0.0.1\n", encoding="utf-8")
            with mock.patch(
                "panorama_cleanup_planner.PanoramaXMLAPI",
                return_value=client,
            ), mock.patch(
                "panorama_cleanup_planner.obtain_password", return_value="secret"
            ), mock.patch("builtins.input", return_value="TAK"):
                code = main(
                    [
                        "--host-file",
                        str(host_file),
                        "--ip-file",
                        str(ip_file),
                        "--output-dir",
                        str(base),
                        "--no-ping",
                    ]
                )
            self.assertEqual(0, code)
            self.assertEqual(2, client.snapshot_call_count)
            run_dir = next(base.glob("run_*"))
            self.assertTrue((run_dir / "commands.txt").is_file())
            self.assertFalse(any(run_dir.glob("draft_commands_BLOCKED_*.txt")))

    def test_main_stops_before_icmp_and_api_without_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            host_file = base / "panorama_host.txt"
            ip_file = base / "ip.txt"
            host_file.write_text(
                "host=192.0.2.10\nusername=readonly\nssl=yes\n",
                encoding="utf-8",
            )
            ip_file.write_text("10.0.0.1\n", encoding="utf-8")
            with mock.patch("builtins.input", return_value="NIE"), mock.patch(
                "panorama_cleanup_planner.ping_many"
            ) as ping, mock.patch(
                "panorama_cleanup_planner.PanoramaXMLAPI"
            ) as api:
                code = main(
                    [
                        "--host-file",
                        str(host_file),
                        "--ip-file",
                        str(ip_file),
                        "--output-dir",
                        str(base),
                    ]
                )
            self.assertEqual(3, code)
            ping.assert_not_called()
            api.assert_not_called()
            self.assertEqual([], list(base.glob("run_*")))

    def test_main_quarantines_persistent_icmp_error_and_publishes_safe_subset(
        self,
    ) -> None:
        running = ET.fromstring(
            """
            <config version="10.2.16-h4"><shared>
              <address>
                <entry name="SAFE"><ip-netmask>10.0.0.1/32</ip-netmask></entry>
                <entry name="ICMP-ERROR"><ip-netmask>10.0.0.2/32</ip-netmask></entry>
              </address>
              <pre-rulebase><security><rules><entry name="SAFE-RULE">
                <source><member>SAFE</member></source>
                <destination><member>any</member></destination>
              </entry></rules></security></pre-rulebase>
            </shared><devices><entry name="localhost.localdomain">
              <device-group/>
            </entry></devices></config>
            """
        )

        class FakeClient:
            snapshot_call_count = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def authenticate(self, password: str) -> None:
                self.password_was_supplied = bool(password)

            def fetch_config(self, action: str):
                self.snapshot_call_count += 1
                return ET.fromstring(ET.tostring(running))

        ping_results = {
            "10.0.0.1": PingResult(
                "10.0.0.1", PingStatus.NO_REPLY, "brak odpowiedzi", 0.01
            ),
            "10.0.0.2": PingResult(
                "10.0.0.2",
                PingStatus.ERROR,
                "Proces ping przekroczył limit wykonania; "
                "błąd utrzymał się po 3 próbach",
                12.0,
            ),
        }

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            host_file = base / "panorama_host.txt"
            ip_file = base / "ip.txt"
            host_file.write_text(
                "host=192.0.2.10\nusername=readonly\nssl=no\n", encoding="utf-8"
            )
            ip_file.write_text("10.0.0.1\n10.0.0.2\n", encoding="utf-8")
            with mock.patch(
                "panorama_cleanup_planner.PanoramaXMLAPI",
                return_value=FakeClient(),
            ), mock.patch(
                "panorama_cleanup_planner.obtain_password", return_value="secret"
            ), mock.patch(
                "panorama_cleanup_planner.ping_many", return_value=ping_results
            ) as ping, mock.patch(
                "builtins.input", return_value="TAK"
            ):
                code = main(
                    [
                        "--host-file",
                        str(host_file),
                        "--ip-file",
                        str(ip_file),
                        "--output-dir",
                        str(base),
                    ]
                )

            self.assertEqual(2, code)
            self.assertEqual(2, ping.call_args.kwargs["error_retries"])
            run_dir = next(base.glob("run_*"))
            commands = (run_dir / "commands.txt").read_text(encoding="utf-8")
            self.assertIn('delete shared address "SAFE"', commands)
            self.assertIn(
                'delete shared pre-rulebase security rules "SAFE-RULE"', commands
            )
            self.assertNotIn("ICMP-ERROR", commands)
            self.assertFalse(any(run_dir.glob("draft_commands_BLOCKED_*.txt")))
            apply_text = (run_dir / "apply_readme.txt").read_text(encoding="utf-8")
            self.assertIn("Błąd wykonania ICMP pozostał dla 1 IP", apply_text)
            self.assertNotIn("BLOKADY PUBLIKACJI commands.txt", apply_text)

            errors = (run_dir / "icmp_errors.txt").read_text(encoding="utf-8")
            self.assertIn("10.0.0.2 | ERROR", errors)
            self.assertIn("błąd utrzymał się po 3 próbach", errors)
            input_status = (run_dir / "input_status.csv").read_text(encoding="utf-8")
            self.assertIn("ZABLOKOWANO_BŁĄD_ICMP", input_status)
            manual = json.loads(
                (run_dir / "manual_review.json").read_text(encoding="utf-8")
            )
            self.assertIn("10.0.0.2", manual["ping_errors"])
            manifest = json.loads(
                (run_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertIn("10.0.0.2", manifest["icmp_errors"])
            self.assertEqual(1, manifest["metrics"]["blocked_ip_count"])

    def test_main_reports_unrelated_runtime_namespaces_without_global_block(self) -> None:
        running = ET.parse(FIXTURE).getroot()

        class FakeClient:
            snapshot_call_count = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def authenticate(self, password: str) -> None:
                self.password_was_supplied = bool(password)

            def fetch_config(self, action: str):
                self.snapshot_call_count += 1
                snapshot = ET.fromstring(ET.tostring(running))
                if action == "get":
                    snapshot.find("./shared/address/entry/ip-netmask").text = (
                        "203.0.113.250/32"
                    )
                return snapshot

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            host_file = base / "panorama_host.txt"
            ip_file = base / "ip.txt"
            host_file.write_text(
                "host=192.0.2.10\nusername=readonly\nssl=no\n", encoding="utf-8"
            )
            ip_file.write_text("10.0.0.1\n10.0.0.4\n", encoding="utf-8")
            with mock.patch(
                "panorama_cleanup_planner.PanoramaXMLAPI",
                return_value=FakeClient(),
            ) as api_factory, mock.patch(
                "panorama_cleanup_planner.obtain_password", return_value="secret"
            ), mock.patch(
                "builtins.input", return_value="TAK"
            ):
                code = main(
                    [
                        "--host-file",
                        str(host_file),
                        "--ip-file",
                        str(ip_file),
                        "--output-dir",
                        str(base),
                        "--no-ping",
                    ]
                )
            self.assertEqual(2, code)
            self.assertFalse(api_factory.call_args.kwargs["verify"])
            run_dir = next(base.glob("run_*"))
            self.assertTrue((run_dir / "commands.txt").is_file())
            self.assertFalse(
                (run_dir / "draft_commands_BLOCKED_runtime_dependencies.txt").exists()
            )
            self.assertFalse(
                (run_dir / "draft_commands_BLOCKED_candidate_drift.txt").exists()
            )
            candidate_control = json.loads(
                (run_dir / "candidate_comparison.json").read_text(encoding="utf-8")
            )
            self.assertFalse(candidate_control["automated_check_performed"])
            self.assertTrue(candidate_control["administrator_confirmed"])
            self.assertIsNone(candidate_control["different"])
            self.assertIsNone(candidate_control["relevant_different"])
            manifest = json.loads(
                (run_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                "named-address-objects-from-running-config",
                manifest["safety"]["dependency_scope"],
            )
            self.assertFalse(
                manifest["safety"]["runtime_membership_audit_performed"]
            )
            self.assertTrue(
                manifest["safety"]["administrator_confirmed_dependency_scope"]
            )
            report = (run_dir / "raport_krotki.txt").read_text(encoding="utf-8")
            self.assertIn("RUNTIME_DAG_PRESENT", report)
            self.assertIn("DYNAMIC_GROUP_MEMBERSHIP_REQUIRES_REVIEW", report)
            commands = (run_dir / "commands.txt").read_text(encoding="utf-8")
            self.assertIn('delete shared address "TARGET_A"', commands)
            self.assertNotIn("DAG_TARGET", commands)

    def test_config_completeness_warns_about_runtime_address_namespaces(self) -> None:
        config = ET.fromstring(
            """
            <config><shared>
              <address><entry name="F"><fqdn>host.example.test</fqdn></entry></address>
              <address-group><entry name="D"><dynamic><filter>'prod'</filter></dynamic></entry></address-group>
              <external-list><entry name="E"><type><ip><url>https://example.test/list</url></ip></type></entry></external-list>
              <region><entry name="R"><address><member>10.0.0.0/8</member></address></entry></region>
              <pre-rulebase><security><rules><entry name="S">
                <source><member>PREDEFINED-REGION</member></source>
                <destination><member>any</member></destination>
              </entry></rules></security></pre-rulebase>
            </shared></config>
            """
        )
        model = parse_config(config)
        warnings, blockers = config_completeness_findings(model, config)
        warning_text = "\n".join(warnings)
        self.assertEqual([], blockers)
        self.assertIn("RUNTIME_DAG_PRESENT", warning_text)
        self.assertIn("FQDN_PRESENT", warning_text)
        self.assertIn("IP_EDL_PRESENT", warning_text)
        self.assertIn("REGION_PRESENT", warning_text)
        self.assertIn("UNMODELED_ADDRESS_REFERENCE_PRESENT", warning_text)

    def test_modeled_wide_literal_is_not_an_unresolved_namespace(self) -> None:
        config = ET.fromstring(
            """
            <config><shared><pre-rulebase><security><rules><entry name="S">
              <source><member>10.0.0.0/24</member></source>
              <destination><member>any</member></destination>
            </entry></rules></security></pre-rulebase></shared></config>
            """
        )
        model = parse_config(config)
        warnings, blockers = config_completeness_findings(model, config)
        self.assertEqual([], blockers)
        self.assertFalse(
            any("UNMODELED_ADDRESS_REFERENCE" in item for item in warnings)
        )

    def test_running_candidate_semantic_comparison(self) -> None:
        running = ET.parse(FIXTURE).getroot()
        same = ET.fromstring(ET.tostring(running))
        comparison = compare_configs(running, same)
        self.assertFalse(comparison.different)
        changed = ET.fromstring(ET.tostring(running))
        changed.find("./shared/address/entry/ip-netmask").text = "10.0.0.200/32"
        comparison = compare_configs(running, changed)
        self.assertTrue(comparison.different)
        self.assertTrue(comparison.relevant_different)

    def test_precedence_setting_is_part_of_relevant_candidate_hash(self) -> None:
        running = ET.fromstring(
            """
            <config><shared/><devices><entry name="localhost.localdomain">
              <deviceconfig><setting><management>
                <ancestor-objects-take-precedence>yes</ancestor-objects-take-precedence>
              </management></setting></deviceconfig>
              <device-group><entry name="DG"/></device-group>
            </entry></devices></config>
            """
        )
        candidate = ET.fromstring(ET.tostring(running))
        candidate.find(
            "./devices/entry/deviceconfig/setting/management/ancestor-objects-take-precedence"
        ).text = "no"
        comparison = compare_configs(running, candidate)
        self.assertTrue(comparison.relevant_different)

    def test_truncated_and_error_api_responses_are_rejected(self) -> None:
        with self.assertRaises(SnapshotError):
            parse_api_response(b"<response status='success'><result>", expect_config=True)
        with self.assertRaises(SnapshotError):
            parse_api_response(
                b"<response status='error'><msg>denied</msg></response>",
                expect_config=True,
            )

    def test_ip_rows_preserve_lp_duplicates_and_invalid_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ip.txt"
            path.write_text(
                "# comment\n10.0.0.1\ninvalid\n10.0.0.1\n2001:0db8::1\n",
                encoding="utf-8",
            )
            rows = load_ip_rows(path)
        self.assertEqual([1, 2, 3, 4], [row.lp for row in rows])
        self.assertFalse(rows[1].valid)
        self.assertEqual(1, rows[2].duplicate_of_lp)
        self.assertEqual("2001:db8::1", rows[3].normalized)

    def test_input_decode_error_is_reported_as_input_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ip.txt"
            path.write_bytes(b"\xff\xfe\xfa")
            with self.assertRaises(InputError):
                load_ip_rows(path)

    def test_ca_bundle_must_be_an_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(InputError):
                validate_ca_bundle(str(Path(temp) / "missing.pem"))

    def test_host_settings_support_ssl_yes_no_and_safe_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "panorama_host.txt"
            path.write_text(
                "host=192.0.2.10\nusername=admin\nssl=no\n", encoding="utf-8"
            )
            self.assertFalse(load_host_settings(path).verify_ssl)
            path.write_text(
                "host=192.0.2.10\nusername=admin\nssl=yes\n", encoding="utf-8"
            )
            self.assertTrue(load_host_settings(path).verify_ssl)
            path.write_text(
                "host=192.0.2.10\nusername=admin\n", encoding="utf-8"
            )
            self.assertTrue(load_host_settings(path).verify_ssl)
            path.write_text(
                "host=192.0.2.10\nusername=admin\nssl=maybe\n", encoding="utf-8"
            )
            with self.assertRaises(InputError):
                load_host_settings(path)

    def test_candidate_diff_confirmation_requires_exact_tak(self) -> None:
        with mock.patch("builtins.input", return_value="TAK"):
            confirm_candidate_diff_checked()
        for answer in ("tak", "yes", "", "NIE", " TAK ", "TAK "):
            with self.subTest(answer=answer), mock.patch(
                "builtins.input", return_value=answer
            ):
                with self.assertRaises(InputError):
                    confirm_candidate_diff_checked()

    def test_missing_password_tty_is_reported_as_input_error(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch(
            "panorama_cleanup.runtime.getpass.getpass", side_effect=EOFError
        ):
            with self.assertRaises(InputError):
                obtain_password("PANORAMA_PASSWORD")

    @mock.patch("panorama_cleanup.runtime.subprocess.run")
    def test_ping_reply_and_no_reply_are_classified(self, run: mock.Mock) -> None:
        run.side_effect = [
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 1),
        ]
        results = ping_many(
            ["10.0.0.1", "10.0.0.2"], bypass=False, workers=1, timeout_ms=1000
        )
        self.assertEqual(PingStatus.REPLIED, results["10.0.0.1"].status)
        self.assertEqual(PingStatus.NO_REPLY, results["10.0.0.2"].status)
        self.assertTrue(all(call.kwargs["shell"] is False for call in run.mock_calls))

    @mock.patch("panorama_cleanup.runtime.subprocess.run")
    def test_ping_execution_error_is_retried_and_can_recover(
        self, run: mock.Mock
    ) -> None:
        run.side_effect = [
            subprocess.TimeoutExpired(cmd=["ping"], timeout=4.0),
            subprocess.CompletedProcess([], 1),
        ]
        result = ping_many(
            ["10.0.0.1"],
            bypass=False,
            workers=64,
            timeout_ms=1000,
            error_retries=2,
        )["10.0.0.1"]
        self.assertEqual(PingStatus.NO_REPLY, result.status)
        self.assertEqual(2, run.call_count)
        self.assertIn("wynik uzyskano w próbie 2", result.detail)

    @mock.patch("panorama_cleanup.runtime.subprocess.run")
    def test_persistent_ping_execution_error_stops_after_retry_limit(
        self, run: mock.Mock
    ) -> None:
        run.side_effect = subprocess.TimeoutExpired(cmd=["ping"], timeout=4.0)
        result = ping_many(
            ["10.0.0.1"],
            bypass=False,
            workers=64,
            timeout_ms=1000,
            error_retries=2,
        )["10.0.0.1"]
        self.assertEqual(PingStatus.ERROR, result.status)
        self.assertEqual(3, run.call_count)
        self.assertIn("błąd utrzymał się po 3 próbach", result.detail)

    @mock.patch("panorama_cleanup.runtime.subprocess.run")
    def test_missing_ping_program_is_not_retried(self, run: mock.Mock) -> None:
        run.side_effect = FileNotFoundError
        result = ping_many(
            ["10.0.0.1"],
            bypass=False,
            workers=1,
            timeout_ms=1000,
            error_retries=5,
        )["10.0.0.1"]
        self.assertEqual(PingStatus.ERROR, result.status)
        self.assertEqual(1, run.call_count)
        self.assertEqual("Program ping nie jest dostępny", result.detail)

    def test_ping_error_retry_limit_is_validated(self) -> None:
        for value in (-1, 6):
            with self.subTest(value=value), self.assertRaises(InputError):
                ping_many(
                    ["10.0.0.1"],
                    bypass=False,
                    workers=1,
                    timeout_ms=1000,
                    error_retries=value,
                )

    @mock.patch("panorama_cleanup.runtime.subprocess.run")
    def test_ping_child_environment_excludes_password_variable(
        self, run: mock.Mock
    ) -> None:
        run.return_value = subprocess.CompletedProcess([], 1)
        with mock.patch.dict(
            os.environ,
            {"PANORAMA_PASSWORD": "do-not-inherit", "SAFE_MARKER": "present"},
            clear=False,
        ):
            ping_many(
                ["10.0.0.1"],
                bypass=False,
                workers=1,
                timeout_ms=1000,
                sensitive_environment_names=("panorama_password",),
            )
        child_env = run.call_args.kwargs["env"]
        self.assertNotIn("PANORAMA_PASSWORD", child_env)
        self.assertEqual("present", child_env["SAFE_MARKER"])

    def test_legacy_triple_dash_no_ping_alias_is_accepted(self) -> None:
        args = build_parser().parse_args(["---no-ping"])
        self.assertTrue(args.no_ping)

    def test_default_paths_stay_inside_panorama_cleaner(self) -> None:
        args = build_parser().parse_args([])
        self.assertEqual(PROJECT_DIR / "panorama_host.txt", Path(args.host_file))
        self.assertEqual(PROJECT_DIR / "ip.txt", Path(args.ip_file))
        self.assertEqual(PROJECT_DIR, Path(args.output_dir))
        self.assertEqual("delete-rule", args.nat_translation)
        self.assertEqual(2, args.ping_error_retries)
        self.assertEqual(
            "block",
            build_parser().parse_args(
                ["--nat-translation", "block"]
            ).nat_translation,
        )

    def test_xml_api_uses_header_and_exactly_two_snapshot_calls(self) -> None:
        key_response = mock.Mock()
        key_response.status_code = 200
        key_response.content = b"<response status='success'><result><key>secret-key</key></result></response>"
        key_response.raise_for_status.return_value = None
        config_response = mock.Mock()
        config_response.status_code = 200
        config_response.content = b"<response status='success'><result><config><shared/></config></result></response>"
        config_response.raise_for_status.return_value = None
        client = PanoramaXMLAPI("192.0.2.10", "admin")
        with mock.patch.object(
            client.session, "post", side_effect=[key_response, config_response, config_response]
        ) as post:
            client.authenticate("password")
            client.fetch_config("show")
            client.fetch_config("get")
        self.assertEqual("secret-key", client.session.headers["X-PAN-KEY"])
        self.assertEqual(2, client.snapshot_call_count)
        self.assertEqual("show", post.call_args_list[1].kwargs["data"]["action"])
        self.assertEqual("get", post.call_args_list[2].kwargs["data"]["action"])
        self.assertTrue(
            all(call.kwargs["allow_redirects"] is False for call in post.call_args_list)
        )
        client.close()

    def test_xml_api_rejects_redirect_without_following_it(self) -> None:
        redirect = mock.Mock()
        redirect.status_code = 307
        redirect.content = b""
        redirect.raise_for_status.return_value = None
        client = PanoramaXMLAPI("192.0.2.10", "admin")
        with mock.patch.object(client.session, "post", return_value=redirect) as post:
            with self.assertRaises(TransportError):
                client.authenticate("password")
        self.assertIs(post.call_args.kwargs["allow_redirects"], False)
        self.assertNotIn("X-PAN-KEY", client.session.headers)
        client.close()


class ArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = ET.parse(FIXTURE).getroot()
        self.model = parse_config(ET.fromstring(ET.tostring(self.config)))
        self.matches = match_ip_objects(self.model, ["10.0.0.2"])
        self.plan = plan_cleanup(self.model, self.matches, ["10.0.0.2"])
        self.rendered = render_plan(self.model, self.plan)

    def test_backups_reports_and_rollback_are_written(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir, stamp = create_run_directory(
                Path(temp), datetime(2026, 7, 13, 15, 30, tzinfo=timezone.utc)
            )
            rows = [InputRow(1, "10.0.0.2", "10.0.0.2", True)]
            pings = {
                "10.0.0.2": PingResult(
                    "10.0.0.2", PingStatus.NO_REPLY, "brak", 0.01
                )
            }
            comparison = CandidateComparison(
                None,
                None,
                None,
                None,
                None,
                None,
                automated_check_performed=False,
                administrator_confirmed=True,
            )
            write_run_artifacts(
                run_dir=run_dir,
                file_stamp=stamp,
                model=self.model,
                plan=self.plan,
                rendered=self.rendered,
                rows=rows,
                pings=pings,
                matches=self.matches,
                comparison=comparison,
                host="192.0.2.10",
                username="admin",
                system_info={"sw_version": "10.2.16-h4"},
                sanitized_arguments={"no_ping": False},
                metrics=RunMetrics(generated_command_count=len(self.rendered.commands)),
                started_utc=datetime.now(timezone.utc),
            )
            command_text = (run_dir / "commands.txt").read_text(encoding="utf-8")
            rollback = (run_dir / "rollback_commands.txt").read_text(encoding="utf-8")
            backups = list((run_dir / "backups").rglob("*.xml"))
            self.assertTrue(backups)
            self.assertTrue(all(stamp in path.name for path in backups))
            self.assertNotIn("commit", command_text.lower())
            self.assertIn(
                'delete shared pre-rulebase application-override rules "APP-B-ONLY"',
                command_text,
            )
            self.assertIn(
                'set shared address "TARGET_B" ip-netmask "10.0.0.2"', rollback
            )
            self.assertIn(
                'set shared pre-rulebase application-override rules "APP-B-ONLY" destination "TARGET_B"',
                rollback,
            )
            app_override_backups = list(
                (run_dir / "backups" / "policies").glob(
                    "*/pre-rulebase/application-override/*.xml"
                )
            )
            self.assertEqual(1, len(app_override_backups))
            self.assertIn(
                'name="APP-B-ONLY"',
                app_override_backups[0].read_text(encoding="utf-8"),
            )
            self.assertTrue((run_dir / "raport_krotki.txt").is_file())
            self.assertTrue((run_dir / "raport_szczegolowy.txt").is_file())
            self.assertTrue((run_dir / "icmp_errors.txt").is_file())
            self.assertTrue((run_dir / "manifest.json").is_file())
            self.assertIn(
                "Administrator jawnie potwierdził",
                (run_dir / "apply_readme.txt").read_text(encoding="utf-8"),
            )
            short_text = (run_dir / "raport_krotki.txt").read_text(encoding="utf-8")
            self.assertIn("Znaleziono w grupie:", short_text)
            self.assertIn("Znaleziono w polityce:", short_text)
            manifest_text = (run_dir / "manifest.json").read_text(encoding="utf-8")
            self.assertNotIn('"commands_published"', manifest_text)
            self.assertIn('"commands_file_expected_on_success": true', manifest_text)

    def test_incomplete_rollback_cli_keeps_commands_and_requires_xml_restore(self) -> None:
        config = ET.fromstring(
            """
            <config><shared><address><entry name="TARGET">
              <ip-netmask>10.10.10.10/32</ip-netmask>
              <description>do-not-leak-first
do-not-leak-second</description>
            </entry></address></shared></config>
            """
        )
        model = parse_config(config)
        matches = match_ip_objects(model, ["10.10.10.10"])
        plan = plan_cleanup(model, matches, ["10.10.10.10"])
        rendered = render_plan(model, plan)
        self.assertTrue(rendered.rollback_warnings)
        with tempfile.TemporaryDirectory() as temp:
            run_dir, stamp = create_run_directory(Path(temp))
            write_run_artifacts(
                run_dir=run_dir,
                file_stamp=stamp,
                model=model,
                plan=plan,
                rendered=rendered,
                rows=[InputRow(1, "10.10.10.10", "10.10.10.10", True)],
                pings={
                    "10.10.10.10": PingResult(
                        "10.10.10.10", PingStatus.NO_REPLY, "brak", 0.01
                    )
                },
                matches=matches,
                comparison=CandidateComparison(
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    automated_check_performed=False,
                    administrator_confirmed=True,
                ),
                host="192.0.2.10",
                username="admin",
                system_info={},
                sanitized_arguments={},
                metrics=RunMetrics(),
                started_utc=datetime.now(timezone.utc),
            )

            self.assertTrue((run_dir / "commands.txt").is_file())
            restore_note = run_dir / "rollback_manual_restore_required.txt"
            self.assertTrue(restore_note.is_file())
            restore_text = restore_note.read_text(encoding="utf-8")
            self.assertIn("ROLLBACK_CLI_FIELD_OMITTED", restore_text)
            self.assertNotIn("do-not-leak-first", restore_text)
            apply_text = (run_dir / "apply_readme.txt").read_text(encoding="utf-8")
            self.assertIn("rollback_manual_restore_required.txt", apply_text)
            self.assertNotIn("do-not-leak-first", apply_text)
            backup_text = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (run_dir / "backups").rglob("*.xml")
            )
            self.assertIn("do-not-leak-first", backup_text)
            manifest = json.loads(
                (run_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(manifest["rollback_cli_complete"])
            self.assertEqual(rendered.rollback_warnings, manifest["rollback_warnings"])

    def test_backup_failure_never_creates_commands_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir, stamp = create_run_directory(Path(temp))
            with mock.patch(
                "panorama_cleanup.artifacts._write_text",
                side_effect=OutputError("disk failed"),
            ):
                with self.assertRaises(OutputError):
                    write_run_artifacts(
                        run_dir=run_dir,
                        file_stamp=stamp,
                        model=self.model,
                        plan=self.plan,
                        rendered=self.rendered,
                        rows=[InputRow(1, "10.0.0.2", "10.0.0.2", True)],
                        pings={
                            "10.0.0.2": PingResult(
                                "10.0.0.2", PingStatus.NO_REPLY, "brak", 0.01
                            )
                        },
                        matches=self.matches,
                        comparison=CandidateComparison(False, "a", "a", "b", "b", False),
                        host="192.0.2.10",
                        username="admin",
                        system_info={},
                        sanitized_arguments={},
                        metrics=RunMetrics(),
                        started_utc=datetime.now(timezone.utc),
                    )
            self.assertFalse((run_dir / "commands.txt").exists())

    def test_late_report_failure_never_publishes_commands_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir, stamp = create_run_directory(Path(temp))
            from panorama_cleanup import artifacts

            real_write_text = artifacts._write_text

            def fail_on_report(path: Path, content: str) -> None:
                if path.name == "raport_szczegolowy.txt":
                    raise OutputError("late disk failure")
                real_write_text(path, content)

            with mock.patch(
                "panorama_cleanup.artifacts._write_text",
                side_effect=fail_on_report,
            ):
                with self.assertRaises(OutputError):
                    write_run_artifacts(
                        run_dir=run_dir,
                        file_stamp=stamp,
                        model=self.model,
                        plan=self.plan,
                        rendered=self.rendered,
                        rows=[InputRow(1, "10.0.0.2", "10.0.0.2", True)],
                        pings={
                            "10.0.0.2": PingResult(
                                "10.0.0.2", PingStatus.NO_REPLY, "brak", 0.01
                            )
                        },
                        matches=self.matches,
                        comparison=CandidateComparison(False, "a", "a", "b", "b", False),
                        host="192.0.2.10",
                        username="admin",
                        system_info={},
                        sanitized_arguments={},
                        metrics=RunMetrics(),
                        started_utc=datetime.now(timezone.utc),
                    )
            self.assertFalse((run_dir / "commands.txt").exists())

    def test_commands_file_is_the_last_artifact_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir, stamp = create_run_directory(Path(temp))
            from panorama_cleanup import artifacts

            writes = []
            real_write_text = artifacts._write_text

            def record_write(path: Path, content: str) -> None:
                writes.append(path.name)
                real_write_text(path, content)

            with mock.patch(
                "panorama_cleanup.artifacts._write_text",
                side_effect=record_write,
            ):
                write_run_artifacts(
                    run_dir=run_dir,
                    file_stamp=stamp,
                    model=self.model,
                    plan=self.plan,
                    rendered=self.rendered,
                    rows=[InputRow(1, "10.0.0.2", "10.0.0.2", True)],
                    pings={
                        "10.0.0.2": PingResult(
                            "10.0.0.2", PingStatus.NO_REPLY, "brak", 0.01
                        )
                    },
                    matches=self.matches,
                    comparison=CandidateComparison(False, "a", "a", "b", "b", False),
                    host="192.0.2.10",
                    username="admin",
                    system_info={},
                    sanitized_arguments={},
                    metrics=RunMetrics(),
                    started_utc=datetime.now(timezone.utc),
                )
            self.assertEqual("commands.txt", writes[-1])

    def test_relevant_candidate_drift_withholds_applicable_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir, stamp = create_run_directory(Path(temp))
            write_run_artifacts(
                run_dir=run_dir,
                file_stamp=stamp,
                model=self.model,
                plan=self.plan,
                rendered=self.rendered,
                rows=[InputRow(1, "10.0.0.2", "10.0.0.2", True)],
                pings={
                    "10.0.0.2": PingResult(
                        "10.0.0.2", PingStatus.NO_REPLY, "brak", 0.01
                    )
                },
                matches=self.matches,
                comparison=CandidateComparison(True, "a", "b", "c", "d", True),
                host="192.0.2.10",
                username="admin",
                system_info={},
                sanitized_arguments={},
                metrics=RunMetrics(),
                started_utc=datetime.now(timezone.utc),
            )
            self.assertFalse((run_dir / "commands.txt").exists())
            self.assertTrue(
                (run_dir / "draft_commands_BLOCKED_candidate_drift.txt").is_file()
            )
            self.assertIn(
                "BLOKADA KRYTYCZNA",
                (run_dir / "apply_readme.txt").read_text(encoding="utf-8"),
            )

    def test_missing_manual_confirmation_withholds_applicable_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir, stamp = create_run_directory(Path(temp))
            write_run_artifacts(
                run_dir=run_dir,
                file_stamp=stamp,
                model=self.model,
                plan=self.plan,
                rendered=self.rendered,
                rows=[InputRow(1, "10.0.0.2", "10.0.0.2", True)],
                pings={
                    "10.0.0.2": PingResult(
                        "10.0.0.2", PingStatus.NO_REPLY, "brak", 0.01
                    )
                },
                matches=self.matches,
                comparison=CandidateComparison(
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    automated_check_performed=False,
                    administrator_confirmed=False,
                ),
                host="192.0.2.10",
                username="admin",
                system_info={},
                sanitized_arguments={},
                metrics=RunMetrics(),
                started_utc=datetime.now(timezone.utc),
            )
            self.assertFalse((run_dir / "commands.txt").exists())
            self.assertTrue(
                (run_dir / "draft_commands_BLOCKED_candidate_confirmation.txt").is_file()
            )

    def test_partial_input_blocker_withholds_commands_and_surfaces_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            run_dir, stamp = create_run_directory(Path(temp))
            self.plan.warnings.append("testowe ostrzeżenie globalne")
            write_run_artifacts(
                run_dir=run_dir,
                file_stamp=stamp,
                model=self.model,
                plan=self.plan,
                rendered=self.rendered,
                rows=[InputRow(1, "10.0.0.2", "10.0.0.2", True)],
                pings={
                    "10.0.0.2": PingResult(
                        "10.0.0.2", PingStatus.NO_REPLY, "brak", 0.01
                    )
                },
                matches=self.matches,
                comparison=CandidateComparison(False, "a", "a", "b", "b", False),
                host="192.0.2.10",
                username="admin",
                system_info={},
                sanitized_arguments={},
                metrics=RunMetrics(),
                started_utc=datetime.now(timezone.utc),
                publication_blockers=("Niepoprawna pozycja wejściowa",),
            )
            self.assertFalse((run_dir / "commands.txt").exists())
            self.assertTrue(
                (run_dir / "draft_commands_BLOCKED_incomplete_input.txt").is_file()
            )
            apply_text = (run_dir / "apply_readme.txt").read_text(encoding="utf-8")
            short_text = (run_dir / "raport_krotki.txt").read_text(encoding="utf-8")
            detailed_text = (run_dir / "raport_szczegolowy.txt").read_text(encoding="utf-8")
            manual = (run_dir / "manual_review.json").read_text(encoding="utf-8")
            self.assertIn("Niepoprawna pozycja wejściowa", apply_text)
            self.assertIn("testowe ostrzeżenie globalne", apply_text)
            self.assertIn("testowe ostrzeżenie globalne", short_text)
            self.assertIn("testowe ostrzeżenie globalne", detailed_text)
            self.assertIn("testowe ostrzeżenie globalne", manual)


if __name__ == "__main__":
    unittest.main()
