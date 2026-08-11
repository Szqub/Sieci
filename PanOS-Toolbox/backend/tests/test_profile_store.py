from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from panos_toolbox.models import ApiStage
from panos_toolbox.profile import PanoramaProfile
from panos_toolbox.profile_store import (
    ProfileStore,
    ProfileStoreError,
    default_toolbox_root,
)


class ProfileStoreTests(unittest.TestCase):
    def test_default_root_uses_local_app_data_not_documents(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ, {}, clear=True
        ), mock.patch(
            "panos_toolbox.profile_store._windows_local_app_data",
            return_value=Path(temporary) / "AppData" / "Local",
        ):
            self.assertEqual(
                default_toolbox_root(),
                (Path(temporary) / "AppData" / "Local" / "PanOS Toolbox").resolve(),
            )

    def test_remote_smb_profile_root_is_rejected_before_write(self):
        with self.assertRaisesRegex(ProfileStoreError, "SMB"):
            ProfileStore(Path(r"\\server\share\PanOS Toolbox"), enforce_acl=False)

    def test_password_is_encrypted_and_roundtrips_without_plaintext(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = ProfileStore(root, enforce_acl=False)
            profile = PanoramaProfile(
                "panorama.example",
                "superadmin",
                use_ssl=True,
                verify_ssl=False,
                api_max_stage=ApiStage.PUSH,
            )
            saved = store.save(
                profile=profile,
                password="very-secret-password",
                name="Produkcja",
            )

            raw = (root / "profiles.json").read_text(encoding="utf-8")
            self.assertNotIn("very-secret-password", raw)
            self.assertEqual(store.get(saved["id"])[1], "very-secret-password")
            self.assertEqual(store.list()[0]["name"], "Produkcja")
            self.assertTrue(store.list()[0]["has_password"])

    def test_default_store_copies_valid_legacy_profile_without_deleting_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            legacy = base / "Documents" / "PanOS Toolbox"
            destination = base / "AppData" / "Local" / "PanOS Toolbox"
            source = ProfileStore(legacy, enforce_acl=False)
            saved = source.save(
                profile=PanoramaProfile("pano", "admin", verify_ssl=False),
                password="migration-secret",
                name="Legacy",
            )

            with mock.patch(
                "panos_toolbox.profile_store.default_toolbox_root",
                return_value=destination,
            ), mock.patch(
                "panos_toolbox.profile_store.legacy_toolbox_roots",
                return_value=(legacy,),
            ):
                migrated = ProfileStore(enforce_acl=False)

            self.assertEqual(migrated.get(saved["id"])[1], "migration-secret")
            self.assertTrue((legacy / "profiles.json").is_file())
            self.assertTrue((destination / "profiles.json").is_file())

    def test_update_keeps_profile_name_and_delete_removes_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = ProfileStore(Path(temporary), enforce_acl=False)
            profile = PanoramaProfile("pano-a", "admin", verify_ssl=False)
            saved = store.save(profile=profile, password="one", name="Pano A")
            updated = store.save(
                profile=PanoramaProfile("pano-b", "admin2", verify_ssl=False),
                password="two",
                profile_id=saved["id"],
            )
            self.assertEqual(updated["name"], "Pano A")
            self.assertEqual(store.get(saved["id"])[1], "two")
            store.delete(saved["id"])
            self.assertEqual(store.list(), [])


if __name__ == "__main__":
    unittest.main()
