from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from panos_toolbox.models import ApiStage
from panos_toolbox.profile import PanoramaProfile
from panos_toolbox.profile_store import ProfileStore


class ProfileStoreTests(unittest.TestCase):
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
