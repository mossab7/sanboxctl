from __future__ import annotations

import json
import os
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
        executable.write_bytes(b"\x7fELF" + b"official game")
        executable.chmod(0o755)
        data = root / "resources.pak"
        data.write_bytes(b"content")
        release = root / "main"
        release.write_text("main\n", encoding="ascii")
        manifest = {
            "dofus1electron": {"size": executable.stat().st_size},
            "resources.pak": {"size": data.stat().st_size},
            "main": {"size": release.stat().st_size},
        }
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        # This resembles launcher-local state and must not be imported.
        (root / "migration.launcher.json").write_text('{"launcher":1}', encoding="utf-8")
        repository = home / ".config/zaap/repositories/production/retro/main"
        repository.mkdir(parents=True)
        (repository / "release.json").write_text(json.dumps({
            "_schemaVersion": 1,
            "gameId": 101,
            "gameName": "Retro",
            "gameOrder": 2,
            "gameUid": "retro",
            "location": "/home/source/.config/Ankama/Retro",
            "isInstalling": False,
            "repositoryVersion": "6.0_1.49.9.5673.465-64394b4",
            "version": "6.0_1.49.9.5673.465-64394b4",
            "accountToken": "must-not-cross-realms",
        }), encoding="utf-8")
        (repository / "information.json").write_text('{"_schemaVersion":1,"version":"hash"}', encoding="utf-8")
        (repository / "data").mkdir()
        (repository / "data" / "release.json").write_text('{"displayName":"Dofus Retro","multiAccount":true}', encoding="utf-8")
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
            self.assertFalse((imported / ".release.infos.json").exists())
            self.assertFalse(imported.stat().st_mode & 0o022)
            self.assertEqual((imported / "resources.pak").read_bytes(), b"content")
            self.assertEqual(imported, store.import_retro(root / "private-home"))

    def test_materialized_game_is_private_writable_and_has_release_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ApplicationStore(root / "state")
            # Keep the fixture construction explicit: the managed seed is
            # populated from one realm, while the second receives no files
            # except the approved manifest payload and release selector.
            self._game(root / "source-home")
            shared = store.import_retro(root / "source-home")
            second_home = root / "second-home"
            second_home.mkdir(mode=0o700)
            view = store.materialize_retro(second_home)
            self.assertTrue((view / "dofus1electron").is_file())
            self.assertEqual(
                json.loads((view / ".release.infos.json").read_text(encoding="utf-8")),
                {"gameUid": "retro", "release": "main"},
            )
            self.assertFalse((view / "migration.launcher.json").exists())
            self.assertNotEqual(view.resolve(), shared.resolve())
            self.assertTrue(os.access(view, os.W_OK))
            # The second materialization is idempotent and does not replace
            # data that Zaap has created inside its own private view.
            marker = view / "zaap-private-state"
            marker.write_text("realm-only", encoding="ascii")
            self.assertEqual(store.materialize_retro(second_home), view)
            self.assertEqual(marker.read_text(encoding="ascii"), "realm-only")

    def test_materialization_seeds_only_public_retro_install_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ApplicationStore(root / "state")
            self._game(root / "source-home")
            store.import_retro(root / "source-home")
            second = root / "second-home"
            second.mkdir(mode=0o700)
            store.materialize_retro(second)
            record_path = second / ".config/zaap/repositories/production/retro/main/release.json"
            record = json.loads(record_path.read_text(encoding="utf-8"))
            self.assertEqual(record["location"], "/home/appsbx/.config/Ankama/Retro")
            self.assertEqual(record["gameUid"], "retro")
            self.assertNotIn("accountToken", record)
            self.assertTrue((second / ".config/zaap/repositories/production/retro/main/information.json").is_file())
            self.assertTrue((second / ".config/zaap/repositories/production/retro/main/data/release.json").is_file())
            self.assertFalse((second / ".config/zaap/Settings").exists())
            # A launcher-owned record must not be overwritten at later runs.
            record_path.write_text('{"launcher":"owns-this"}', encoding="utf-8")
            store.materialize_retro(second)
            self.assertEqual(json.loads(record_path.read_text(encoding="utf-8")), {"launcher": "owns-this"})

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

    def test_import_rejects_incomplete_non_elf_game_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "private-home"
            game = self._game(home)
            executable = game / "dofus1electron"
            executable.write_bytes(b"\0" * 4096)
            manifest = json.loads((game / "manifest.json").read_text(encoding="utf-8"))
            manifest["dofus1electron"]["size"] = executable.stat().st_size
            (game / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ProfileError, "not a Linux ELF"):
                ApplicationStore(root / "state").import_retro(home)

    def test_missing_first_run_game_directory_is_a_recoverable_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "private-home"
            home.mkdir()
            with self.assertRaisesRegex(ProfileError, "game directory is unavailable"):
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
