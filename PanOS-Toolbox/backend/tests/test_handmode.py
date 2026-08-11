from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from panos_toolbox.errors import ValidationError
from panos_toolbox.handmode import (
    build_handmode_artifacts,
    quote_cli,
    render_mutations,
    render_operation,
    write_handmode_artifacts,
    xpath_cli_tokens,
)
from panos_toolbox.models import Mutation, MutationAction, MutationOperation, PatchSet
from panos_toolbox.profile import PanoramaProfile
from panos_toolbox.sessions import SessionStore


def mutation(
    index: int,
    *,
    entity_type: str,
    entity_key: str,
    target_xpath: str,
    forward: tuple[MutationOperation, ...],
    inverse: tuple[MutationOperation, ...],
    component_id: str = "component-1",
) -> Mutation:
    return Mutation(
        mutation_id=f"mutation-{index:05d}",
        component_id=component_id,
        entity_type=entity_type,
        entity_key=entity_key,
        target_xpath=target_xpath,
        before_xml=None,
        after_xml=None,
        forward=forward,
        inverse=inverse,
        causes=(f"policy:TARGET-{index}",),
    )


class HandModeRendererTests(unittest.TestCase):
    def test_xpath_to_cli_for_device_group_member_and_template_vsys(self):
        self.assertEqual(
            xpath_cli_tokens(
                "/config/devices/entry/device-group/entry[@name='DG-NET']"
                "/pre-rulebase/security/rules/entry[@name='ALLOW WEB']"
                "/source/member[text()='H-10.0.0.1-32']"
            ),
            [
                "device-group",
                '"DG-NET"',
                "pre-rulebase",
                "security",
                "rules",
                '"ALLOW WEB"',
                "source",
                '"H-10.0.0.1-32"',
            ],
        )
        self.assertEqual(
            xpath_cli_tokens(
                "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='TPL-NET']"
                "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
                "/group-mapping/entry[@name='LDAP_GM1']/custom-group/entry[@name='AD__VPN']"
            ),
            [
                "template",
                '"TPL-NET"',
                "config",
                "vsys",
                '"vsys1"',
                "group-mapping",
                '"LDAP_GM1"',
                "custom-group",
                '"AD__VPN"',
            ],
        )

    def test_cleanup_delete_is_a_real_human_cli_command(self):
        operation = MutationOperation(
            MutationAction.DELETE,
            "/config/devices/entry/device-group/entry[@name='DG1']"
            "/post-rulebase/security/rules/entry[@name='OLD POLICY']",
        )
        commands, warnings = render_operation(operation)
        self.assertEqual(
            commands,
            ['delete device-group "DG1" post-rulebase security rules "OLD POLICY"'],
        )
        self.assertEqual(warnings, [])

    def test_create_policy_objects_groups_services_and_members(self):
        cases = [
            (
                MutationOperation(
                    MutationAction.SET,
                    "/config/devices/entry/device-group/entry[@name='DG1']/address",
                    element='<entry name="H-10.0.0.1-32"><ip-netmask>10.0.0.1/32</ip-netmask></entry>',
                ),
                ['set device-group "DG1" address "H-10.0.0.1-32" ip-netmask "10.0.0.1/32"'],
            ),
            (
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/address-group",
                    element='<entry name="HG__WEB"><static><member>H-10.0.0.1-32</member><member>H-10.0.0.2-32</member></static></entry>',
                ),
                [
                    'set shared address-group "HG__WEB" static "H-10.0.0.1-32"',
                    'set shared address-group "HG__WEB" static "H-10.0.0.2-32"',
                ],
            ),
            (
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/service",
                    element='<entry name="SVC__443-tcp"><protocol><tcp><port>443</port></tcp></protocol></entry>',
                ),
                ['set shared service "SVC__443-tcp" protocol tcp port "443"'],
            ),
            (
                MutationOperation(
                    MutationAction.SET,
                    "/config/devices/entry/device-group/entry[@name='DG1']/pre-rulebase/security/rules",
                    element=(
                        '<entry name="INSIDE__WEB"><from><member>TRUST</member></from>'
                        '<to><member>DMZ</member></to><source><member>HG__USERS</member></source>'
                        '<destination><member>HG__WEB</member></destination>'
                        '<service><member>SVC__443-tcp</member></service>'
                        '<application><member>ssl</member></application><action>allow</action>'
                        '<description>ServiceNow request 123</description></entry>'
                    ),
                ),
                [
                    'set device-group "DG1" pre-rulebase security rules "INSIDE__WEB" from "TRUST"',
                    'set device-group "DG1" pre-rulebase security rules "INSIDE__WEB" to "DMZ"',
                    'set device-group "DG1" pre-rulebase security rules "INSIDE__WEB" source "HG__USERS"',
                    'set device-group "DG1" pre-rulebase security rules "INSIDE__WEB" destination "HG__WEB"',
                    'set device-group "DG1" pre-rulebase security rules "INSIDE__WEB" service "SVC__443-tcp"',
                    'set device-group "DG1" pre-rulebase security rules "INSIDE__WEB" application "ssl"',
                    'set device-group "DG1" pre-rulebase security rules "INSIDE__WEB" action "allow"',
                    'set device-group "DG1" pre-rulebase security rules "INSIDE__WEB" description "ServiceNow request 123"',
                ],
            ),
        ]
        for operation, expected in cases:
            with self.subTest(xpath=operation.xpath):
                commands, _warnings = render_operation(operation)
                self.assertEqual(commands, expected)

    def test_inverse_reverses_mutations_and_restores_policy_order(self):
        address_path = "/config/shared/address/entry[@name='H-10.0.0.1-32']"
        rule_path = "/config/shared/pre-rulebase/security/rules/entry[@name='OLD']"
        values = (
            mutation(
                1,
                entity_type="policy",
                entity_key="shared/pre-rulebase/security/OLD",
                target_xpath=rule_path,
                forward=(MutationOperation(MutationAction.DELETE, rule_path),),
                inverse=(
                    MutationOperation(
                        MutationAction.SET,
                        "/config/shared/pre-rulebase/security/rules",
                        element='<entry name="OLD"><action>allow</action></entry>',
                    ),
                    MutationOperation(
                        MutationAction.MOVE,
                        rule_path,
                        where="before",
                        destination="DROP",
                    ),
                ),
            ),
            mutation(
                2,
                entity_type="address",
                entity_key="shared/H-10.0.0.1-32",
                target_xpath=address_path,
                forward=(MutationOperation(MutationAction.DELETE, address_path),),
                inverse=(
                    MutationOperation(
                        MutationAction.SET,
                        "/config/shared/address",
                        element='<entry name="H-10.0.0.1-32"><ip-netmask>10.0.0.1/32</ip-netmask></entry>',
                    ),
                ),
            ),
        )
        rendered = render_mutations(values, direction="inverse")
        self.assertEqual(
            rendered.commands,
            (
                'set shared address "H-10.0.0.1-32" ip-netmask "10.0.0.1/32"',
                'set shared pre-rulebase security rules "OLD" action "allow"',
                'move shared pre-rulebase security rules "OLD" before "DROP"',
            ),
        )

    def test_control_characters_block_whole_command_file(self):
        with self.assertRaises(ValidationError):
            quote_cli("SAFE\nDELETE", context="test")
        path = "/config/shared/address/entry[@name='A']"
        value = mutation(
            1,
            entity_type="address",
            entity_key="shared/A",
            target_xpath=path,
            forward=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/address",
                    element='<entry name="A"><description>line 1\nline 2</description></entry>',
                ),
            ),
            inverse=(MutationOperation(MutationAction.DELETE, path),),
        )
        patch = PatchSet.new(
            kind="future-create",
            panorama_host="panorama.example",
            panorama_username="operator",
            mutations=(value,),
            targets=("A",),
            affected_device_groups=(),
        )
        bundle, report = build_handmode_artifacts(patch)
        self.assertEqual(bundle.active.text, "")
        self.assertIn("STATUS AKTYWNEGO HAND MODE: BLOCK", report)

    def test_large_batch_of_300_policies_is_complete_and_has_no_json(self):
        values = []
        for index in range(1, 301):
            path = (
                "/config/devices/entry/device-group/entry[@name='DG-BULK']"
                f"/pre-rulebase/security/rules/entry[@name='OLD-{index:03d}']"
            )
            values.append(
                mutation(
                    index,
                    entity_type="policy",
                    entity_key=f"DG-BULK/pre-rulebase/security/OLD-{index:03d}",
                    target_xpath=path,
                    forward=(MutationOperation(MutationAction.DELETE, path),),
                    inverse=(
                        MutationOperation(
                            MutationAction.SET,
                            "/config/devices/entry/device-group/entry[@name='DG-BULK']"
                            "/pre-rulebase/security/rules",
                            element=f'<entry name="OLD-{index:03d}"><action>allow</action></entry>',
                        ),
                    ),
                    component_id=f"component-{index}",
                )
            )
        rendered = render_mutations(values)
        self.assertEqual(len(rendered.commands), 300)
        self.assertEqual(len(set(rendered.commands)), 300)
        self.assertTrue(all(command.startswith("delete device-group ") for command in rendered.commands))
        self.assertFalse(any(command.lstrip().startswith("{") for command in rendered.commands))

    def test_repeated_command_is_not_deduplicated_across_ordered_mutations(self):
        path = "/config/shared/address/entry[@name='A']"
        first = mutation(
            1,
            entity_type="address",
            entity_key="shared/A",
            target_xpath=path,
            forward=(MutationOperation(MutationAction.DELETE, path),),
            inverse=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/address",
                    element='<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>',
                ),
            ),
            component_id="component-1",
        )
        second = mutation(
            2,
            entity_type="address",
            entity_key="shared/A",
            target_xpath=path,
            forward=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/address",
                    element='<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>',
                ),
                MutationOperation(MutationAction.DELETE, path),
            ),
            inverse=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/address",
                    element='<entry name="A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>',
                ),
            ),
            component_id="component-2",
        )
        rendered = render_mutations((first, second))
        self.assertEqual(rendered.commands[0], rendered.commands[2])
        self.assertEqual(len(rendered.commands), 3)

    def test_legacy_commands_are_preserved_and_handmode_backfill_is_idempotent(self):
        path = "/config/shared/address/entry[@name='OLD']"
        value = mutation(
            1,
            entity_type="address",
            entity_key="shared/OLD",
            target_xpath=path,
            forward=(MutationOperation(MutationAction.DELETE, path),),
            inverse=(
                MutationOperation(
                    MutationAction.SET,
                    "/config/shared/address",
                    element='<entry name="OLD"><ip-netmask>192.0.2.1/32</ip-netmask></entry>',
                ),
            ),
        )
        patch = PatchSet.new(
            kind="cleanup",
            panorama_host="panorama.example",
            panorama_username="operator",
            mutations=(value,),
            targets=("OLD",),
            affected_device_groups=(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = SessionStore(Path(temporary), enforce_acl=False)
            session_id = store.create(patch, PanoramaProfile("panorama.example", "operator"))
            store.write_artifact(
                session_id,
                "commands.txt",
                '{"legacy":"xml-api-operation"}\n',
                kind="legacy-command-report",
            )
            write_handmode_artifacts(store, session_id, patch)
            first_manifest = store.load_manifest(session_id)
            write_handmode_artifacts(store, session_id, patch)
            second_manifest = store.load_manifest(session_id)
            self.assertEqual(len(first_manifest["artifacts"]), len(second_manifest["artifacts"]))
            self.assertEqual(
                (Path(temporary) / session_id / "commands.txt").read_text(encoding="utf-8"),
                '{"legacy":"xml-api-operation"}\n',
            )
            generated = (Path(temporary) / session_id / "handmode_commands.txt").read_text(encoding="utf-8")
            self.assertEqual(generated, 'delete shared address "OLD"\n')


if __name__ == "__main__":
    unittest.main()
