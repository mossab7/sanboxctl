"""Small offscreen integration checks for launcher-store GUI controls."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


try:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    from appsbx import gui
    QT_AVAILABLE = gui.QT_AVAILABLE
except ModuleNotFoundError:
    QT_AVAILABLE = False


@unittest.skipUnless(QT_AVAILABLE, "PySide6 is not installed")
class LauncherSettingsGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_settings_exposes_managed_launcher_and_game_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(gui, "GUI_STATE", root / "gui-instances"), \
                 mock.patch("appsbx.gui.state_root", return_value=root / "state"):
                window = gui.MainWindow()
                window.show_section("settings")
                self.assertFalse(window.launcher_button.isHidden())
                self.assertFalse(window.prepare_game_button.isHidden())
                self.assertFalse(window.update_game_button.isHidden())
                self.assertIn("ANKAMA LAUNCHER PATH", window.info_panel.toPlainText())
                window.show_section("realms")
                self.assertTrue(window.launcher_button.isHidden())
                self.assertTrue(window.prepare_game_button.isHidden())
                self.assertTrue(window.update_game_button.isHidden())
                window.close()
