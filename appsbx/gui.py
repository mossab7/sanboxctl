"""PySide6 desktop controller for persistent Zaap sandbox instances."""

from __future__ import annotations

import os
from pathlib import Path
import re
import signal
import sys
import time

from .instances import InstanceRecord, InstanceStore, active_interface_users, discover_egresses
from .network import DEFAULT_EGRESS_DIR, load_egress_definition
from .paths import PROJECT_ROOT, state_root
from .profile import ProfileError, load_profiles


PROFILES_DIR = PROJECT_ROOT / "profiles"
GUI_STATE = state_root() / "gui-instances"
BASE_PROFILE_NAME = "example"
VNC_ENDPOINT_RE = re.compile(r"appsbx VNC: (127\.0\.0\.1::\d+) \(loopback only\)")

try:
    from PySide6.QtCore import QAbstractListModel, QModelIndex, QObject, QProcess, QProcessEnvironment, QIODevice, Qt, QTimer, Signal, Slot
    from PySide6.QtGui import QPixmap
    from PySide6.QtWidgets import (
        QApplication, QComboBox, QDialog, QDialogButtonBox, QFrame,
        QGridLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QLineEdit,
        QMainWindow, QMessageBox, QPushButton, QTextEdit, QVBoxLayout, QWidget,
    )
    QT_AVAILABLE = True
except ModuleNotFoundError:
    QT_AVAILABLE = False


def _pid_alive(pid: int | None) -> bool:
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


if QT_AVAILABLE:

    class InstanceListModel(QAbstractListModel):
        """Small Qt model backing the visible instance list."""

        def __init__(self, records: list[InstanceRecord] | None = None, parent: QObject | None = None):
            super().__init__(parent)
            self.records = records or []

        def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
            return 0 if parent.isValid() else len(self.records)

        def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
            if not index.isValid() or not 0 <= index.row() < len(self.records):
                return None
            record = self.records[index.row()]
            if role == Qt.ItemDataRole.DisplayRole:
                return f"{record.name} — {record.state}"
            if role == Qt.ItemDataRole.UserRole:
                return record
            return None

        def replace(self, records: list[InstanceRecord]) -> None:
            self.beginResetModel()
            self.records = records
            self.endResetModel()


    class InstanceController(QObject):
        recordChanged = Signal(str)
        message = Signal(str)
        processFinished = Signal(str, int)

        def __init__(self, store: InstanceStore, parent: QObject | None = None):
            super().__init__(parent)
            self.store = store
            self.processes: dict[str, QProcess] = {}
            self.pending_delete: set[str] = set()
            self.stopping: set[str] = set()
            self._shutting_down = False
            self._recover()

        def _record(self, key: str) -> InstanceRecord:
            for record in self.store.list():
                if record.key == key:
                    return record
            raise ProfileError("instance no longer exists")

        def shared_interface_users(self, record: InstanceRecord) -> list[InstanceRecord]:
            """Return active records using the same resolved host interface."""
            return active_interface_users(record, self.store.list(), DEFAULT_EGRESS_DIR)

        def _recover(self) -> None:
            for record in self.store.list():
                if record.pid and _pid_alive(record.pid):
                    record.state = "Running"
                    record.error = None
                elif record.state in {"Running", "Starting"}:
                    record.state = "Stopped"
                    record.pid = None
                    record.vnc_endpoint = None
                self.store.update(record)

        def launch(self, record: InstanceRecord) -> None:
            if record.key in self.processes:
                return
            if record.state in {"Running", "Starting"} or (record.pid and _pid_alive(record.pid)):
                return
            self.stopping.discard(record.key)
            process = None
            log = None
            try:
                command = [
                    str(PROJECT_ROOT / "sandboxctl"), "run",
                    "--profile", BASE_PROFILE_NAME,
                    "--instance-id", str(record.profile_id),
                    "--identity-dir", str(self.store.identity_dir(record)),
                    "--mode", "real", "--egress", record.network, "--force-egress",
                    "--display", "host",
                    # OAuth opens in the staged private browser, in the same
                    # Bubblewrap/network namespace as Zaap. Never delegate
                    # authentication URLs to the host desktop.
                    "--url-broker", "browser",
                    "--gpu-mode", "hardware",
                    "--execute", "--",
                    "/opt/app/zaap",
                ]
                log_path = self.store._instance_dir(record.key) / "run.log"
                log_path.parent.mkdir(mode=0o700, exist_ok=True)
                log = log_path.open("a", encoding="utf-8")
                process = QProcess(self)
                process.setProgram(command[0])
                process.setArguments(command[1:])
                process.setWorkingDirectory(str(PROJECT_ROOT))
                environment = QProcessEnvironment()
                environment.insert("PATH", "/usr/bin:/bin")
                environment.insert("LANG", "C")
                environment.insert("LC_ALL", "C")
                environment.insert("PYTHONPATH", str(PROJECT_ROOT))
                # These variables are available only to the host-side
                # controller/VNC viewer. runtime.execute() supplies a clean
                # environment to the sandboxed application.
                for name in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR"):
                    value = os.environ.get(name)
                    if value:
                        environment.insert(name, value)
                # QProcess has no interactive terminal for sudo's password
                # prompt. Ask the desktop policy agent to authorize only the
                # already restricted root-owned network helper instead.
                environment.insert("APPSBX_PRIVILEGE_BACKEND", "pkexec")
                process.setProcessEnvironment(environment)
                process.setStandardOutputFile(str(log_path), QIODevice.OpenModeFlag.Append)
                process.setStandardErrorFile(str(log_path), QIODevice.OpenModeFlag.Append)
                process.readyReadStandardError.connect(lambda key=record.key: self._read_output(key))
                process.finished.connect(lambda code, _status, key=record.key: self._finished(key, code))
                process.errorOccurred.connect(lambda error, key=record.key: self._process_error(key, error))
                self.processes[record.key] = process
                record.state = "Starting"
                record.pid = None
                record.vnc_endpoint = None
                record.error = None
                self.store.update(record)
                process.start()
                if not process.waitForStarted(3000):
                    raise ProfileError(process.errorString() or "sandbox process could not start")
                record.pid = process.processId()
                if record.display_backend == "host":
                    # Host display mode has no VNC endpoint to announce.
                    record.state = "Running"
                self.store.update(record)
                self.recordChanged.emit(record.key)
                QTimer.singleShot(250, lambda key=record.key, path=log_path: self._poll_log(key, path))
                log.close()
            except Exception as exc:
                if process is not None and process.state() != QProcess.ProcessState.NotRunning:
                    process.terminate()
                if process is not None:
                    self.processes.pop(record.key, None)
                try:
                    if log is not None:
                        log.close()
                except OSError:
                    pass
                record.state = "Error"
                record.error = str(exc)
                record.pid = None
                self.store.update(record)
                self.message.emit(str(exc))
                self.recordChanged.emit(record.key)

        @Slot(str)
        def _read_output(self, key: str) -> None:
            process = self.processes.get(key)
            if process is None:
                return
            data = bytes(process.readAllStandardError()).decode("utf-8", "replace")
            match = VNC_ENDPOINT_RE.search(data)
            if match:
                record = self._record(key)
                record.vnc_endpoint = match.group(1)
                record.state = "Running"
                self.store.update(record)
                self.recordChanged.emit(key)

        def _poll_log(self, key: str, path: Path) -> None:
            process = self.processes.get(key)
            if process is None:
                return
            try:
                text = path.read_text(encoding="utf-8", errors="replace")[-20_000:]
            except OSError:
                text = ""
            match = VNC_ENDPOINT_RE.search(text)
            if match:
                record = self._record(key)
                if record.vnc_endpoint != match.group(1):
                    record.vnc_endpoint = match.group(1)
                    record.state = "Running"
                    self.store.update(record)
                    self.recordChanged.emit(key)
            if process.state() != QProcess.ProcessState.NotRunning:
                QTimer.singleShot(500, lambda: self._poll_log(key, path))

        def _process_error(self, key: str, error: QProcess.ProcessError) -> None:
            if error == QProcess.ProcessError.FailedToStart:
                record = self._record(key)
                record.state = "Error"
                record.error = "sandboxctl could not be started"
                self.store.update(record)
                self.recordChanged.emit(key)

        def _finished(self, key: str, code: int) -> None:
            process = self.processes.pop(key, None)
            intentional_stop = key in self.stopping or self._shutting_down
            self.stopping.discard(key)
            record = self._record(key)
            record.pid = None
            record.vnc_endpoint = None
            if key in self.pending_delete:
                self.pending_delete.remove(key)
                try:
                    self.store.delete(record)
                except Exception as exc:
                    record.state = "Error"
                    record.error = str(exc)
                    self.store.update(record)
                    self.message.emit(str(exc))
            else:
                record.state = "Stopped" if code == 0 or intentional_stop else "Error"
                record.error = None if record.state == "Stopped" else f"sandboxctl exited with status {code}"
                self.store.update(record)
            self.processFinished.emit(key, code)
            self.recordChanged.emit(key)

        def shutdown(self) -> None:
            """Stop controller-owned launches before Qt destroys QProcess objects."""
            if self._shutting_down:
                return
            self._shutting_down = True
            for key, process in list(self.processes.items()):
                self.stopping.add(key)
                try:
                    if process.state() != QProcess.ProcessState.NotRunning:
                        process.terminate()
                        if not process.waitForFinished(8000):
                            process.kill()
                            process.waitForFinished(3000)
                except RuntimeError:
                    # The C++ object may already be gone during interpreter
                    # shutdown; the normal finished path has no object call.
                    pass
                try:
                    record = self._record(key)
                    record.pid = None
                    record.vnc_endpoint = None
                    record.state = "Stopped"
                    record.error = None
                    self.store.update(record)
                except (ProfileError, RuntimeError):
                    pass
            self.processes.clear()

        def _kill_if_running(self, key: str, process: QProcess) -> None:
            if self.processes.get(key) is not process:
                return
            try:
                if process.state() != QProcess.ProcessState.NotRunning:
                    process.kill()
            except RuntimeError:
                pass

        def stop(self, record: InstanceRecord) -> None:
            process = self.processes.get(record.key)
            if process is not None:
                self.stopping.add(record.key)
                try:
                    process.terminate()
                except RuntimeError:
                    return
                QTimer.singleShot(5000, lambda key=record.key, child=process: self._kill_if_running(key, child))
                return
            if record.pid and _pid_alive(record.pid):
                try:
                    os.kill(record.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            record.vnc_endpoint = None
            record.state = "Stopped"
            self.store.update(record)
            self.recordChanged.emit(record.key)
            if record.pid:
                QTimer.singleShot(1000, lambda key=record.key: self._finish_external_stop(key))

        def _finish_external_stop(self, key: str) -> None:
            try:
                record = self._record(key)
            except ProfileError:
                return
            if record.pid and _pid_alive(record.pid):
                QTimer.singleShot(1000, lambda: self._finish_external_stop(key))
                return
            record.pid = None
            self.store.update(record)
            if key in self.pending_delete:
                self.pending_delete.remove(key)
                self.store.delete(record)
            self.recordChanged.emit(key)

        def delete(self, record: InstanceRecord) -> None:
            if record.key in self.processes or (record.pid and _pid_alive(record.pid)):
                self.pending_delete.add(record.key)
                self.stop(record)
                return
            self.store.delete(record)
            self.recordChanged.emit(record.key)

        def open_window(self, record: InstanceRecord) -> None:
            if not record.vnc_endpoint:
                self.message.emit("The VNC display is not ready yet.")
                return
            from .display import vnc_viewer_command
            try:
                command = vnc_viewer_command(int(record.vnc_endpoint.rsplit("::", 1)[1]))
            except Exception as exc:
                self.message.emit(str(exc))
                return
            if not QProcess.startDetached(command[0], command[1:]):
                self.message.emit("Could not open the VNC viewer.")

        def log_text(self, record: InstanceRecord) -> str:
            path = self.store._instance_dir(record.key) / "run.log"
            try:
                return path.read_text(encoding="utf-8", errors="replace")[-100_000:]
            except OSError:
                return "No log is available yet."


    class LogDialog(QDialog):
        def __init__(self, title: str, text: str, parent: QWidget | None = None):
            super().__init__(parent)
            self.setWindowTitle(title)
            self.resize(760, 480)
            layout = QVBoxLayout(self)
            editor = QTextEdit(self)
            editor.setReadOnly(True)
            editor.setPlainText(text)
            layout.addWidget(editor)
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
            buttons.rejected.connect(self.reject)
            layout.addWidget(buttons)


    class InstanceCard(QFrame):
        networkChanged = Signal(str, str)
        launchClicked = Signal(str)
        stopClicked = Signal(str)
        openClicked = Signal(str)
        deleteClicked = Signal(str)
        detailsClicked = Signal(str)

        def __init__(self, record: InstanceRecord, egresses: list[tuple[str, str]],
                     interface_users: set[str] | None = None, parent: QWidget | None = None):
            super().__init__(parent)
            self.record = record
            self.setFrameShape(QFrame.Shape.StyledPanel)
            self.setObjectName("instanceCard")
            layout = QHBoxLayout(self)
            layout.setContentsMargins(18, 16, 18, 16)
            info = QVBoxLayout()
            info.setSpacing(5)
            title = QLabel(record.name)
            title.setObjectName("instanceName")
            subtitle = QLabel(f"Profile {record.profile_name}  •  ID {record.profile_id}")
            subtitle.setObjectName("instanceSubtitle")
            self.status = QLabel(f"●  {record.state.upper()}")
            self.status.setProperty("state", record.state.lower())
            info.addWidget(title)
            info.addWidget(subtitle)
            info.addWidget(self.status)
            layout.addLayout(info, 1)
            details = QVBoxLayout()
            details.setSpacing(4)
            network_title = QLabel("NETWORK")
            network_title.setObjectName("eyebrow")
            details.addWidget(network_title)
            self.network = QComboBox()
            self.network.setMinimumWidth(220)
            for name, label in egresses:
                self.network.addItem(label, name)
            current = self.network.findData(record.network)
            if current >= 0:
                self.network.setCurrentIndex(current)
            self.network.currentIndexChanged.connect(lambda _index: self.networkChanged.emit(record.key, self.network.currentData()))
            details.addWidget(self.network)
            display = QLabel("HOST DESKTOP  •  GPU HARDWARE")
            display.setObjectName("displayBadge")
            details.addWidget(display)
            if interface_users and record.network in interface_users:
                shared = QLabel("●  shared interface")
                shared.setObjectName("sharedBadge")
                details.addWidget(shared)
            layout.addLayout(details)
            self.launch = QPushButton("Launch")
            self.launch.clicked.connect(lambda: self.launchClicked.emit(record.key))
            self.stop = QPushButton("Stop")
            self.stop.clicked.connect(lambda: self.stopClicked.emit(record.key))
            self.open = QPushButton("Open Window")
            self.open.clicked.connect(lambda: self.openClicked.emit(record.key))
            details = QPushButton("Details")
            details.clicked.connect(lambda: self.detailsClicked.emit(record.key))
            delete = QPushButton("Delete")
            delete.clicked.connect(lambda: self.deleteClicked.emit(record.key))
            for button in (self.launch, self.stop, self.open, details, delete):
                layout.addWidget(button)
            running = record.state in {"Running", "Starting"} or record.pid is not None
            self.network.setEnabled(not running)
            self.launch.setEnabled(not running)
            self.stop.setEnabled(running)
            self.open.setEnabled(record.vnc_endpoint is not None)
            self.setToolTip(record.error or "")


    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Zaap Realms  •  appsbx")
            self.resize(1240, 760)
            self.setMinimumSize(900, 600)
            profiles = load_profiles(PROFILES_DIR)
            if BASE_PROFILE_NAME not in profiles:
                raise ProfileError(f"missing base profile: {BASE_PROFILE_NAME}")
            self.egresses = discover_egresses(DEFAULT_EGRESS_DIR)
            self.store = InstanceStore(GUI_STATE, PROFILES_DIR, profiles[BASE_PROFILE_NAME])
            self.model = InstanceListModel(self.store.list(), self)
            self.controller = InstanceController(self.store, self)
            self.controller.recordChanged.connect(lambda _key: self.refresh())
            self.controller.message.connect(lambda message: QMessageBox.warning(self, "Sandbox", message))
            central = QWidget(self)
            self.setCentralWidget(central)
            root = QHBoxLayout(central)
            root.setContentsMargins(0, 0, 0, 0)
            sidebar = QFrame()
            sidebar.setObjectName("sidebar")
            sidebar.setFixedWidth(230)
            side = QVBoxLayout(sidebar)
            side.setContentsMargins(24, 28, 24, 24)
            logo = QLabel("ZAAP\nREALMS")
            logo.setObjectName("logo")
            side.addWidget(logo)
            sigil = QLabel()
            sigil.setPixmap(QPixmap(str(PROJECT_ROOT / "assets" / "realm-sigil.svg")).scaled(62, 62, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
            side.addWidget(sigil)
            tagline = QLabel("PRIVATE WORLDS\nONE DESKTOP")
            tagline.setObjectName("tagline")
            side.addWidget(tagline)
            side.addSpacing(34)
            nav = QLabel("✦  DASHBOARD\n\n◈  INSTANCES\n\n⌁  NETWORKS\n\n▤  ACTIVITY")
            nav.setObjectName("nav")
            side.addWidget(nav)
            side.addStretch(1)
            side_note = QLabel("HOST DESKTOP\nHARDWARE GPU\n\nIsolation stays active\nbehind the scenes.")
            side_note.setObjectName("sideNote")
            side.addWidget(side_note)
            root.addWidget(sidebar)
            content = QWidget()
            root.addWidget(content, 1)
            content_layout = QVBoxLayout(content)
            content_layout.setContentsMargins(34, 28, 34, 28)
            header = QHBoxLayout()
            heading = QLabel("Your realms")
            heading.setObjectName("heading")
            header.addWidget(heading)
            header.addStretch(1)
            self.new_button = QPushButton("+ New Instance")
            self.new_button.clicked.connect(self.new_instance)
            self.new_button.setEnabled(bool(self.egresses))
            header.addWidget(self.new_button)
            content_layout.addLayout(header)
            self.notice = QLabel("Choose a network for each realm. Display and GPU are managed automatically.")
            self.notice.setObjectName("notice")
            content_layout.addWidget(self.notice)
            stats = QGridLayout()
            stats.setSpacing(12)
            self.running_stat = self._stat_card("RUNNING REALMS", "0")
            self.network_stat = self._stat_card("NETWORK PATHS", str(len(self.egresses)))
            self.gpu_stat = self._stat_card("GRAPHICS", "Hardware GPU")
            stats.addWidget(self.running_stat, 0, 0)
            stats.addWidget(self.network_stat, 0, 1)
            stats.addWidget(self.gpu_stat, 0, 2)
            content_layout.addLayout(stats)
            section = QHBoxLayout()
            section_title = QLabel("ACTIVE INSTANCES")
            section_title.setObjectName("eyebrow")
            section.addWidget(section_title)
            section.addStretch(1)
            self.search = QLineEdit()
            self.search.setPlaceholderText("Search realms…")
            self.search.setMaximumWidth(220)
            self.search.textChanged.connect(self.refresh)
            section.addWidget(self.search)
            content_layout.addLayout(section)
            self.list_widget = QListWidget()
            self.list_widget.setObjectName("instanceList")
            self.list_widget.setSpacing(8)
            content_layout.addWidget(self.list_widget, 1)
            self.setStyleSheet("""
                QWidget { color: #F1F4EE; font-family: Inter, DejaVu Sans; }
                QMainWindow, QWidget { background: #0D1110; }
                #sidebar { background: #171E1A; border-right: 1px solid #253329; }
                #logo { color: #D9F4A4; font-size: 23px; font-weight: 800; letter-spacing: 2px; }
                #tagline, #eyebrow { color: #C5A66A; font-size: 10px; font-weight: 700; letter-spacing: 2px; }
                #nav { color: #9BA89D; font-size: 13px; line-height: 1.7; }
                #sideNote { color: #718074; font-size: 11px; line-height: 1.5; }
                #heading { color: #F1F4EE; font-size: 30px; font-weight: 700; }
                #notice { color: #9BA89D; padding: 2px 0 14px; }
                #instanceCard { background: #171E1A; border: 1px solid #253329; border-radius: 14px; }
                #instanceCard:hover { border: 1px solid #55743A; }
                #instanceName { color: #F1F4EE; font-size: 18px; font-weight: 700; }
                #instanceSubtitle { color: #718074; font-size: 11px; }
                QLabel[state="running"] { color: #92D543; font-size: 11px; font-weight: 700; }
                QLabel[state="starting"] { color: #C5A66A; font-size: 11px; font-weight: 700; }
                QLabel[state="error"] { color: #E47D6B; font-size: 11px; font-weight: 700; }
                QLabel[state="stopped"] { color: #718074; font-size: 11px; font-weight: 700; }
                #displayBadge { color: #92D543; font-size: 10px; font-weight: 700; }
                #sharedBadge { color: #C5A66A; font-size: 10px; }
                QListWidget { background: transparent; border: none; outline: none; }
                QComboBox, QLineEdit { background: #0D1110; border: 1px solid #253329; border-radius: 7px; padding: 8px; color: #F1F4EE; }
                QPushButton { background: #253329; border: 1px solid #3C5140; border-radius: 7px; padding: 9px 13px; color: #F1F4EE; font-weight: 600; }
                QPushButton:hover { background: #344A36; border-color: #92D543; }
                QPushButton:pressed { background: #92D543; color: #0D1110; }
                QPushButton#newButton { background: #92D543; color: #0D1110; border: none; padding: 11px 18px; }
                QPushButton#newButton:hover { background: #D9F4A4; }
                QFrame#statCard { background: #171E1A; border: 1px solid #253329; border-radius: 12px; }
                QLabel#statValue { color: #D9F4A4; font-size: 18px; font-weight: 700; }
                QLabel#statLabel { color: #718074; font-size: 10px; font-weight: 700; letter-spacing: 1px; }
            """)
            self.new_button.setObjectName("newButton")
            if not self.egresses:
                self.notice.setText("No valid network definitions were found. Configure an egress before creating an instance.")
            # The list widget is populated by refresh(), not by the model
            # constructor.  Do this once after every widget it touches exists;
            # refresh_egresses() intentionally refreshes only when network
            # state changes, so it cannot be relied on for initial rendering.
            self.refresh()
            self.refresh_egresses()
            self.egress_timer = QTimer(self)
            self.egress_timer.setInterval(5000)
            self.egress_timer.timeout.connect(self.refresh_egresses)
            self.egress_timer.start()

        def _stat_card(self, label: str, value: str) -> QFrame:
            card = QFrame()
            card.setObjectName("statCard")
            layout = QVBoxLayout(card)
            layout.setContentsMargins(16, 12, 16, 12)
            value_label = QLabel(value)
            value_label.setObjectName("statValue")
            label_widget = QLabel(label)
            label_widget.setObjectName("statLabel")
            layout.addWidget(value_label)
            layout.addWidget(label_widget)
            card.value_label = value_label
            return card

        def closeEvent(self, event) -> None:
            self.controller.shutdown()
            event.accept()

        def refresh(self) -> None:
            self.model.replace(self.store.list())
            self.list_widget.clear()
            query = self.search.text().lower().strip() if hasattr(self, "search") else ""
            active = [r for r in self.model.records if not query or query in r.name.lower() or query in r.profile_name.lower()]
            running = sum(r.state in {"Running", "Starting"} or r.pid is not None for r in self.model.records)
            self.running_stat.value_label.setText(str(running))
            self.network_stat.value_label.setText(str(len(self.egresses)))
            for record in active:
                shared = {r.network for r in self.model.records if r.key != record.key and r.state in {"Running", "Starting"}}
                card = InstanceCard(record, self.egresses, shared, self.list_widget)
                card.networkChanged.connect(self.network_changed)
                card.launchClicked.connect(self.launch)
                card.stopClicked.connect(self.stop)
                card.openClicked.connect(self.open_window)
                card.deleteClicked.connect(self.delete)
                card.detailsClicked.connect(self.details)
                item = QListWidgetItem(self.list_widget)
                item.setSizeHint(card.sizeHint())
                self.list_widget.addItem(item)
                self.list_widget.setItemWidget(item, card)

        @Slot()
        def refresh_egresses(self) -> None:
            """Pick up newly connected interfaces without restarting the GUI."""
            current = discover_egresses(DEFAULT_EGRESS_DIR)
            names = {name for name, _label in current}
            migrated = False
            for record in self.store.list():
                if record.network in names:
                    continue
                try:
                    old = load_egress_definition(record.network, DEFAULT_EGRESS_DIR)
                except Exception:
                    old = None
                replacement = None
                if old is not None:
                    replacement = next(
                        (name for name, _label in current
                         if name == f"auto-{old.interface}"),
                        None,
                    )
                if replacement is not None:
                    record.network = replacement
                    self.store.update(record)
                    migrated = True
            if current != self.egresses or migrated:
                self.egresses = current
                self.new_button.setEnabled(bool(current))
                self.refresh()

        def _record(self, key: str) -> InstanceRecord:
            return next(item for item in self.store.list() if item.key == key)

        @Slot()
        def new_instance(self) -> None:
            try:
                record = self.store.create(self.egresses[0][0])
            except Exception as exc:
                QMessageBox.critical(self, "Could not create instance", str(exc))
                return
            self.refresh()

        @Slot(str, str)
        def network_changed(self, key: str, network: str) -> None:
            try:
                record = self._record(key)
                if record.state in {"Running", "Starting"}:
                    return
                record.network = network
                self.store.update(record)
            except Exception as exc:
                QMessageBox.warning(self, "Network selection", str(exc))
            self.refresh()

        @Slot(str, str)
        def display_changed(self, key: str, display_backend: str) -> None:
            try:
                record = self._record(key)
                if record.state in {"Running", "Starting"}:
                    return
                if display_backend not in {"isolated", "host"}:
                    raise ProfileError("invalid display backend")
                record.display_backend = display_backend
                self.store.update(record)
            except Exception as exc:
                QMessageBox.warning(self, "Display selection", str(exc))
            self.refresh()

        @Slot(str)
        def launch(self, key: str) -> None:
            try:
                record = self._record(key)
                duplicate = self.controller.shared_interface_users(record)
                if duplicate:
                    names = ", ".join(item.name for item in duplicate)
                    warning = QMessageBox(self)
                    warning.setIcon(QMessageBox.Icon.Warning)
                    warning.setWindowTitle("Network Interface Already in Use")
                    warning.setText(
                        f"Another active realm ({names}) is using the selected interface.\n\n"
                        "Both instances may share the same network egress or public IP. "
                        "Separate interfaces do not guarantee separate public IP addresses.\n\n"
                        "Continue anyway?"
                    )
                    warning.setStandardButtons(
                        QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes
                    )
                    warning.button(QMessageBox.StandardButton.Cancel).setText("Cancel Launch")
                    warning.button(QMessageBox.StandardButton.Yes).setText("Continue Anyway")
                    answer = warning.exec()
                    if answer != QMessageBox.StandardButton.Yes:
                        return
                # Re-read immediately before starting to reduce races between
                # the warning and the backend launch.
                record = self._record(key)
                self.controller.launch(record)
            except Exception as exc:
                QMessageBox.critical(self, "Launch failed", str(exc))
            self.refresh()

        @Slot(str)
        def stop(self, key: str) -> None:
            self.controller.stop(self._record(key))
            self.refresh()

        @Slot(str)
        def open_window(self, key: str) -> None:
            self.controller.open_window(self._record(key))

        @Slot(str)
        def details(self, key: str) -> None:
            record = self._record(key)
            LogDialog(f"{record.name} details", self.controller.log_text(record), self).exec()

        @Slot(str)
        def delete(self, key: str) -> None:
            record = self._record(key)
            answer = QMessageBox.question(self, "Delete instance", f"Delete {record.name} and its private application data? This cannot be undone.")
            if answer == QMessageBox.StandardButton.Yes:
                self.controller.delete(record)
                self.refresh()


def main() -> int:
    if not QT_AVAILABLE:
        print("appsbx GUI requires PySide6. Install it for the current Python environment.", file=sys.stderr)
        return 2
    app = QApplication(sys.argv)
    # Convert Ctrl+C into the same orderly shutdown used by the window close
    # button. Without this, QProcess wrappers can disappear while their
    # sandbox descendants continue running.
    signal.signal(signal.SIGINT, lambda _signum, _frame: app.quit())
    try:
        window = MainWindow()
    except Exception as exc:
        QMessageBox.critical(None, "appsbx", str(exc))
        return 2
    window.show()
    app.aboutToQuit.connect(window.controller.shutdown)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
