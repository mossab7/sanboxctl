from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from appsbx.app_store import ApplicationStore, OFFICIAL_LAUNCHER_URL
from appsbx.profile import ProfileError


class ApplicationStoreTests(unittest.TestCase):
    def _game(self, home: Path) -> Path:
        root = home / ".config/Ankama/Retro"
        root.mkdir(parents=True)
        executable = root / "dofus1electron"
        executable.write_bytes(b"official game")
        executable.chmod(0o755)
        data = root / "resources.pak"
        data.write_bytes(b"content")
        manifest = {
            "dofus1electron": {"size": executable.stat().st_size},
            "resources.pak": {"size": data.stat().st_size},
        }
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        # This resembles launcher-local state and must not be imported.
        (root / "migration.launcher.json").write_text('{"launcher":1}', encoding="utf-8")
        return root

    def test_import_is_immutable_and_excludes_unlisted_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self._game(root / "private-home")
            store = ApplicationStore(root / "state")
            imported = store.import_retro(root / "private-home")
            self.assertEqual(store.game_root(), imported)
            self.assertTrue((imported / "dofus1electron").is_file())
            self.assertFalse((imported / "migration.launcher.json").exists())
            self.assertFalse(imported.stat().st_mode & 0o022)
            self.assertEqual((imported / "resources.pak").read_bytes(), b"content")
            self.assertEqual(imported, store.import_retro(root / "private-home"))

    def test_import_rejects_manifest_escape_or_missing_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "private-home"
            root = self._game(home)
            (root / "manifest.json").write_text(json.dumps({
                "dofus1electron": {"size": (root / "dofus1electron").stat().st_size},
                "../escape": {"size": 1},
            }), encoding="utf-8")
            with self.assertRaisesRegex(ProfileError, "unsafe entry"):
                ApplicationStore(Path(directory) / "state").import_retro(home)

    def test_staged_appdir_is_managed_and_source_is_not_used(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "official.AppDir"
            source.mkdir()
            executable = source / "zaap"
            executable.write_bytes(b"\x7fELF official launcher")
            executable.chmod(0o755)
            (source / "resources").mkdir()
            (source / "resources" / "app.asar").write_text("launcher", encoding="utf-8")
            store = ApplicationStore(root / "state")
            staged = store.stage_launcher(source)
            self.assertEqual(store.launcher_root(), staged)
            self.assertNotEqual(staged, source)
            self.assertFalse(staged.stat().st_mode & 0o022)
            executable.write_bytes(b"changed outside store")
            self.assertEqual((store.launcher_root() / "zaap").read_bytes(), b"\x7fELF official launcher")

    def test_staging_rejects_external_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "official.AppDir"
            source.mkdir()
            (source / "zaap").write_bytes(b"launcher")
            (source / "zaap").chmod(0o755)
            (source / "outside").symlink_to("/etc/passwd")
            with self.assertRaisesRegex(ProfileError, "outside"):
                ApplicationStore(root / "state").stage_launcher(source)

    def test_official_download_policy_rejects_insecure_and_foreign_urls(self):
        with self.assertRaisesRegex(ProfileError, "HTTPS"):
            ApplicationStore._validate_official_url("http://download.ankama.com/launcher")
        with self.assertRaisesRegex(ProfileError, "Ankama-controlled"):
            ApplicationStore._validate_official_url("https://example.invalid/launcher")
        ApplicationStore._validate_official_url("https://download.ankama.com/launcher/full/linux/x64")
        ApplicationStore._validate_official_url(OFFICIAL_LAUNCHER_URL)


if __name__ == "__main__":
    unittest.main()
