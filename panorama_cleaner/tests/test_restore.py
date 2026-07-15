from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from panorama_cleanup.models import InputError, OutputError, UnsafePlanError
from panorama_cleanup.panos import parse_config
from panorama_cleanup.restore import (
    BackupVersion,
    RestoreEntity,
    _resolve_historical_reference,
    build_emergency_restore,
    create_restore_directory,
    load_cleanup_runs,
    write_restore_artifacts,
)
from panorama_emergency_restore import main as restore_main


DEVICE = "localhost.localdomain"
HOST = "192.0.2.10"


def _address(name: str, value: str) -> tuple[dict[str, object], str]:
    xml = f'<entry name="{name}"><ip-netmask>{value}/32</ip-netmask></entry>'
    return (
        {
            "entity_type": "address",
            "identity": f"address|shared|{name}",
            "name": name,
            "location": "shared",
            "xpath": f"/config/shared/address/entry[@name='{name}']",
        },
        xml,
    )


def _group(name: str, members: list[str]) -> tuple[dict[str, object], str]:
    member_xml = "".join(f"<member>{member}</member>" for member in members)
    xml = f'<entry name="{name}"><static>{member_xml}</static></entry>'
    return (
        {
            "entity_type": "static-group",
            "identity": f"group|shared|{name}",
            "name": name,
            "location": "shared",
            "xpath": f"/config/shared/address-group/entry[@name='{name}']",
            "original_members": members,
        },
        xml,
    )


def _policy(
    name: str,
    source: str,
    *,
    order: list[str],
) -> tuple[dict[str, object], str]:
    index = order.index(name)
    xml = (
        f'<entry name="{name}" uuid="uuid-{name}">'
        f"<source><member>{source}</member></source>"
        "<destination><member>any</member></destination>"
        "<action>allow</action></entry>"
    )
    return (
        {
            "entity_type": "policy",
            "identity": f"policy|shared|pre-rulebase|security|{name}",
            "name": name,
            "location": "shared",
            "xpath": (
                "/config/shared/pre-rulebase/security/rules/"
                f"entry[@name='{name}']"
            ),
            "rulebase": "pre-rulebase",
            "policy_type": "security",
            "uuid": f"uuid-{name}",
            "order_index": index,
            "previous_rule": order[index - 1] if index else None,
            "next_rule": order[index + 1] if index + 1 < len(order) else None,
            "rule_order": order,
            "original_source": [source],
            "original_destination": ["any"],
        },
        xml,
    )


def _command(
    command_id: str,
    category: str,
    command: str,
    causes: list[str],
    entity_type: str,
    entity_key: str,
) -> dict[str, object]:
    return {
        "command_id": command_id,
        "category": category,
        "command": command,
        "causes": causes,
        "entity_type": entity_type,
        "entity_key": entity_key,
    }


def _write_run(
    base: Path,
    name: str,
    started: datetime,
    entities: list[tuple[dict[str, object], str]],
    commands: list[dict[str, object]],
) -> Path:
    run_dir = base / name
    backup_dir = run_dir / "backups"
    backup_dir.mkdir(parents=True)
    backups: list[dict[str, object]] = []
    for index, (record, xml) in enumerate(entities, start=1):
        payload = xml.rstrip() + "\n"
        relative = f"backups/{index:02d}.xml"
        (run_dir / relative).write_bytes(payload.encode("utf-8"))
        item = dict(record)
        item["file"] = relative
        item["sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        backups.append(item)
    command_lines = [str(command["command"]) for command in commands]
    (run_dir / "commands.txt").write_text(
        "\n".join(command_lines) + "\n", encoding="utf-8"
    )
    manifest = {
        "script": "panorama_cleanup_planner.py",
        "script_version": "1.5.0",
        "started_utc": started.astimezone(timezone.utc).isoformat(),
        "panorama_host": HOST,
        "device_entry_name": DEVICE,
        "configuration_context": {
            "device_entry_name": DEVICE,
            "ancestor_objects_take_precedence": False,
            "device_group_parents": {},
        },
        "backups": backups,
        "commands": commands,
        "safety": {"commands_file_expected_on_success": True},
    }
    manifest_path = run_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def _history(base: Path) -> tuple[Path, Path]:
    run1 = _write_run(
        base,
        "run_010726_10_00_00",
        datetime(2026, 7, 1, 10, 0, tzinfo=timezone.utc),
        [
            _address("A", "10.0.0.1"),
            _group("G", ["A", "B"]),
        ],
        [
            _command(
                "CMD-00001",
                "group-member",
                'delete shared address-group "G" static "A"',
                ["10.0.0.1"],
                "group",
                "shared/G",
            ),
            _command(
                "CMD-00002",
                "address-delete",
                'delete shared address "A"',
                ["10.0.0.1"],
                "address",
                "shared/A",
            ),
        ],
    )
    run2 = _write_run(
        base,
        "run_020726_10_00_00",
        datetime(2026, 7, 2, 10, 0, tzinfo=timezone.utc),
        [
            _address("B", "10.0.0.2"),
            _group("G", ["B"]),
            _group("H", ["G"]),
            _policy(
                "ALLOW-P",
                "H",
                order=["ALLOW-P", "MIDDLE-NOW-MISSING", "DROP"],
            ),
        ],
        [
            _command(
                "CMD-00001",
                "rule-delete",
                'delete shared pre-rulebase security rules "ALLOW-P"',
                ["10.0.0.2"],
                "policy",
                "shared/pre-rulebase/security/ALLOW-P",
            ),
            _command(
                "CMD-00002",
                "group-delete",
                'delete shared address-group "H"',
                ["10.0.0.2"],
                "group",
                "shared/H",
            ),
            _command(
                "CMD-00003",
                "group-delete",
                'delete shared address-group "G"',
                ["10.0.0.2"],
                "group",
                "shared/G",
            ),
            _command(
                "CMD-00004",
                "address-delete",
                'delete shared address "B"',
                ["10.0.0.2"],
                "address",
                "shared/B",
            ),
        ],
    )
    return run1, run2


def _current(*, partial_group: bool = False) -> ET.Element:
    group = (
        "<address-group><entry name='G'><static><member>B</member>"
        "</static></entry></address-group>"
        if partial_group
        else ""
    )
    return ET.fromstring(
        "<config version='10.2.16-h4'><shared>"
        + group
        + "<pre-rulebase><security><rules><entry name='DROP'>"
        "<source><member>any</member></source>"
        "<destination><member>any</member></destination>"
        "<action>deny</action></entry></rules></security></pre-rulebase>"
        "</shared><devices><entry name='localhost.localdomain'>"
        "<device-group/></entry></devices></config>"
    )


def _fully_restored_but_rule_after_drop() -> ET.Element:
    return ET.fromstring(
        "<config version='10.2.16-h4'><shared>"
        "<address>"
        "<entry name='A'><ip-netmask>10.0.0.1/32</ip-netmask></entry>"
        "<entry name='B'><ip-netmask>10.0.0.2/32</ip-netmask></entry>"
        "</address>"
        "<address-group>"
        "<entry name='G'><static><member>A</member><member>B</member></static></entry>"
        "<entry name='H'><static><member>G</member></static></entry>"
        "</address-group>"
        "<pre-rulebase><security><rules>"
        "<entry name='DROP'><source><member>any</member></source>"
        "<destination><member>any</member></destination><action>deny</action></entry>"
        "<entry name='ALLOW-P' uuid='uuid-ALLOW-P'>"
        "<source><member>H</member></source>"
        "<destination><member>any</member></destination>"
        "<action>allow</action></entry>"
        "</rules></security></pre-rulebase>"
        "</shared><devices><entry name='localhost.localdomain'>"
        "<device-group/></entry></devices></config>"
    )


class RestoreTests(unittest.TestCase):
    def test_ip_looking_object_name_resolves_before_literal(self) -> None:
        model = parse_config(
            ET.fromstring(
                "<config><shared/><devices><entry name='localhost.localdomain'>"
                "<device-group/></entry></devices></config>"
            )
        )
        address = RestoreEntity("address", "shared", "10.0.0.1")
        group = RestoreEntity("static-group", "shared", "G")
        common = {
            "manifest_path": "manifest.json",
            "run_dir": ".",
            "started_utc": "2026-07-01T00:00:00+00:00",
            "device_group_parents": {},
            "ancestor_objects_take_precedence": False,
            "historical_scope_context_available": True,
        }
        address_version = BackupVersion(
            entity=address,
            record={},
            xml='<entry name="10.0.0.1"><ip-netmask>10.0.0.1/32</ip-netmask></entry>',
            **common,
        )
        group_version = BackupVersion(
            entity=group,
            record={},
            xml='<entry name="G"><static><member>10.0.0.1</member></static></entry>',
            **common,
        )

        resolved, detail = _resolve_historical_reference(
            model,
            {address: address_version, group: group_version},
            "shared",
            "10.0.0.1",
            historical_version=group_version,
        )

        self.assertEqual(address, resolved)
        self.assertEqual("", detail)

    def test_transitive_restore_includes_other_ip_nested_groups_and_rule_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            manifests = _history(base)
            runs = load_cleanup_runs(manifests)
            plan = build_emergency_restore(
                parse_config(_current()),
                runs,
                ["10.0.0.1"],
                bundle_filename="restore_bundle.xml",
            )

            selected = [f"{item.entity_type}:{item.text}" for item in plan.selected]
            self.assertEqual(
                [
                    "address:shared/A",
                    "address:shared/B",
                    "static-group:shared/G",
                    "static-group:shared/H",
                    "policy:shared/pre-rulebase/security/ALLOW-P",
                ],
                selected,
            )
            cli = "\n".join(plan.cli_commands)
            self.assertLess(cli.index('address "A"'), cli.index('address-group "G"'))
            self.assertLess(cli.index('address-group "G"'), cli.index('address-group "H"'))
            self.assertLess(cli.index('address-group "H"'), cli.index('rules "ALLOW-P"'))
            self.assertIn('move shared pre-rulebase security rules "ALLOW-P" before "DROP"', cli)
            self.assertIn('uuid="uuid-ALLOW-P"', plan.bundle_xml)
            partial = "\n".join(plan.partial_load_commands)
            self.assertIn(
                'from-xpath "shared/address/entry[@name=\'A\']" '
                'to-xpath "/config/shared/address"',
                partial,
            )
            self.assertIn(
                'move shared pre-rulebase security rules "ALLOW-P" before "DROP"',
                partial,
            )

            restore_dir = create_restore_directory(base, ["10.0.0.1"])
            write_restore_artifacts(
                restore_dir,
                plan,
                bundle_filename="restore_bundle.xml",
                metadata={"candidate_diff_administrator_confirmed": True},
            )
            self.assertTrue((restore_dir / "RESTORE_READY").is_file())
            self.assertTrue((restore_dir / "restore_commands.txt").is_file())
            self.assertTrue((restore_dir / "restore_manifest.json").is_file())

    def test_existing_known_intermediate_group_uses_entry_replace(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            runs = load_cleanup_runs(_history(base))
            plan = build_emergency_restore(
                parse_config(_current(partial_group=True)),
                runs,
                ["10.0.0.1"],
                bundle_filename="restore_bundle.xml",
            )

            command = next(
                item
                for item in plan.partial_load_commands
                if "address-group/entry" in item and "@name='G'" in item
            )
            self.assertIn("mode replace", command)
            self.assertIn(
                'from-xpath "shared/address-group/entry[@name=\'G\']"',
                command,
            )
            self.assertIn(
                'to-xpath "/config/shared/address-group/entry[@name=\'G\']"',
                command,
            )

    def test_already_restored_deleted_policy_is_still_moved_before_drop(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            runs = load_cleanup_runs(_history(base))
            plan = build_emergency_restore(
                parse_config(_fully_restored_but_rule_after_drop()),
                runs,
                ["10.0.0.1"],
                bundle_filename="restore_bundle.xml",
            )

            self.assertEqual(
                (
                    'move shared pre-rulebase security rules "ALLOW-P" '
                    'before "DROP"'
                ),
                plan.cli_commands[-1],
            )
            self.assertEqual(plan.move_commands[-1], plan.partial_load_commands[-1])

    def test_discontinuous_history_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            run1, run2 = _history(base)
            manifest = json.loads(run2.read_text(encoding="utf-8"))
            group_record = next(
                record
                for record in manifest["backups"]
                if record["entity_type"] == "static-group" and record["name"] == "G"
            )
            path = run2.parent / group_record["file"]
            payload = '<entry name="G"><static><member>C</member></static></entry>\n'
            path.write_bytes(payload.encode("utf-8"))
            group_record["sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            run2.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
            runs = load_cleanup_runs([run1, run2])

            with self.assertRaisesRegex(UnsafePlanError, "NIECIĄGŁA_HISTORIA"):
                build_emergency_restore(
                    parse_config(_current()),
                    runs,
                    ["10.0.0.1"],
                    bundle_filename="restore_bundle.xml",
                )

    def test_modified_backup_is_rejected_by_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            run1, _ = _history(base)
            manifest = json.loads(run1.read_text(encoding="utf-8"))
            backup_path = run1.parent / manifest["backups"][0]["file"]
            backup_path.write_bytes(b"<entry name='tampered'/>\n")

            with self.assertRaisesRegex(InputError, "SHA256"):
                load_cleanup_runs([run1])

    def test_failed_final_ready_write_removes_applicable_command_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            runs = load_cleanup_runs(_history(base))
            plan = build_emergency_restore(
                parse_config(_current()),
                runs,
                ["10.0.0.1"],
                bundle_filename="restore_bundle.xml",
            )
            restore_dir = create_restore_directory(base, ["10.0.0.1"])
            from panorama_cleanup import restore as restore_module

            original = restore_module._write_text

            def fail_ready(path: Path, content: str) -> None:
                if path.name == "RESTORE_READY":
                    raise OutputError("simulated")
                original(path, content)

            with mock.patch.object(restore_module, "_write_text", side_effect=fail_ready):
                with self.assertRaises(OutputError):
                    write_restore_artifacts(
                        restore_dir,
                        plan,
                        bundle_filename="restore_bundle.xml",
                        metadata={"candidate_diff_administrator_confirmed": True},
                    )
            self.assertFalse((restore_dir / "RESTORE_READY").exists())
            self.assertFalse((restore_dir / "restore_commands.txt").exists())
            self.assertFalse(
                (restore_dir / "restore_partial_load_commands.txt").exists()
            )


class RestoreEntrypointTests(unittest.TestCase):
    def test_entrypoint_fetches_two_snapshots_and_publishes_ready_package(self) -> None:
        class FakeClient:
            snapshot_call_count = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def authenticate(self, password: str) -> None:
                self.authenticated = bool(password)

            def fetch_config(self, action: str) -> ET.Element:
                self.snapshot_call_count += 1
                return ET.fromstring(ET.tostring(_current()))

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            run1, run2 = _history(base)
            host_file = base / "panorama_host.txt"
            host_file.write_text(
                f"host={HOST}\nusername=readonly\nssl=yes\n",
                encoding="utf-8",
            )
            client = FakeClient()
            with mock.patch(
                "panorama_emergency_restore.PanoramaXMLAPI", return_value=client
            ), mock.patch(
                "panorama_emergency_restore.obtain_password", return_value="secret"
            ), mock.patch("builtins.input", return_value="TAK"):
                code = restore_main(
                    [
                        "10.0.0.1",
                        "--run",
                        str(run1.parent),
                        "--run",
                        str(run2.parent),
                        "--host-file",
                        str(host_file),
                        "--output-dir",
                        str(base),
                    ]
                )

            self.assertEqual(2, code)
            self.assertEqual(2, client.snapshot_call_count)
            restore_dir = next(base.glob("restore_*"))
            self.assertTrue((restore_dir / "RESTORE_READY").is_file())
            manifest = json.loads(
                (restore_dir / "restore_manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(manifest["candidate_diff_administrator_confirmed"])
            self.assertTrue(manifest["candidate_snapshot_compared"])
            self.assertIn("candidate_comparison", manifest)
            self.assertFalse(manifest["changes_executed"])

    def test_restore_generation_requires_no_typed_confirmation(self) -> None:
        class FakeClient:
            snapshot_call_count = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def authenticate(self, password: str) -> None:
                self.authenticated = bool(password)

            def fetch_config(self, action: str) -> ET.Element:
                self.snapshot_call_count += 1
                return ET.fromstring(ET.tostring(_current()))

        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            run1, run2 = _history(base)
            host_file = base / "panorama_host.txt"
            host_file.write_text(
                f"host={HOST}\nusername=readonly\nssl=yes\n",
                encoding="utf-8",
            )
            client = FakeClient()
            with mock.patch(
                "builtins.input", side_effect=AssertionError("no prompt")
            ), mock.patch(
                "panorama_emergency_restore.PanoramaXMLAPI", return_value=client
            ) as api, mock.patch(
                "panorama_emergency_restore.obtain_password", return_value="secret"
            ):
                code = restore_main(
                    [
                        "10.0.0.1",
                        "--run",
                        str(run1.parent),
                        "--run",
                        str(run2.parent),
                        "--host-file",
                        str(host_file),
                        "--output-dir",
                        str(base),
                    ]
                )
            self.assertEqual(2, code)
            api.assert_called_once()
            self.assertEqual(2, client.snapshot_call_count)

    def test_manifest_host_mismatch_stops_before_prompt_and_network(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            run1, _ = _history(base)
            host_file = base / "panorama_host.txt"
            host_file.write_text(
                "host=192.0.2.99\nusername=readonly\nssl=yes\n",
                encoding="utf-8",
            )
            with mock.patch("builtins.input") as confirmation, mock.patch(
                "panorama_emergency_restore.PanoramaXMLAPI"
            ) as api:
                code = restore_main(
                    [
                        "10.0.0.1",
                        "--run",
                        str(run1.parent),
                        "--host-file",
                        str(host_file),
                        "--output-dir",
                        str(base),
                    ]
                )

            self.assertEqual(3, code)
            confirmation.assert_not_called()
            api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
