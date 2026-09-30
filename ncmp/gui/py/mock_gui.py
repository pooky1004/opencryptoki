#!/usr/bin/env python3
"""Mock HSM GUI - launch, configure, monitor and debug emulated NCMP tokens.

Runs (or attaches to) the C ``mock_server`` and drives it over the control
channel. One window manages several slots (each an emulated token) at once:

  * Identity   - view/edit label, serial, manufacturer, model, versions, UTC.
  * Statistics - live request/response/byte/error counters and in-flight peak.
  * Debug      - a tail of recent messages (opcode, session, seq, ack, sizes).
  * Link       - force a slot's host link up/down and reset its state.

The App GUI (app_gui.py) connects to each slot's data port to send commands.

Requires PySide6:  pip install -r requirements.txt
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from typing import Dict, List, Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QColor, QFont
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGridLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QMainWindow,
    QMessageBox, QPushButton, QSpinBox, QSplitter, QTableWidget,
    QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from ncmp_gui import ci, link


def find_server() -> str:
    """Best-effort locate the mock_server binary."""
    env = os.environ.get("NCMP_MOCK_SERVER")
    if env and os.path.exists(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "..", "..", "build", "gui", "mock_server"),
        os.path.join(here, "..", "..", "build", "mock_server"),
        os.path.join(here, "..", "server", "mock_server"),
        shutil.which("mock_server") or "",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return os.path.abspath(c)
    return ""


class IdentityPanel(QWidget):
    """Editable token identity for one slot."""

    def __init__(self, get_ctrl, slot: int):
        super().__init__()
        self._get_ctrl = get_ctrl
        self._slot = slot
        form = QFormLayout(self)
        self.label = QLineEdit()
        self.serial = QLineEdit()
        self.manufacturer = QLineEdit()
        self.model = QLineEdit()
        self.hw_major = QSpinBox(); self.hw_major.setRange(0, 255)
        self.hw_minor = QSpinBox(); self.hw_minor.setRange(0, 255)
        self.fw_major = QSpinBox(); self.fw_major.setRange(0, 255)
        self.fw_minor = QSpinBox(); self.fw_minor.setRange(0, 255)
        self.flags = QLineEdit()
        self.utc = QLineEdit()
        self.login = QLabel("-")
        form.addRow("Label", self.label)
        form.addRow("Serial", self.serial)
        form.addRow("Manufacturer", self.manufacturer)
        form.addRow("Model", self.model)
        hw = QHBoxLayout(); hw.addWidget(self.hw_major); hw.addWidget(QLabel("."))
        hw.addWidget(self.hw_minor)
        hww = QWidget(); hww.setLayout(hw); form.addRow("HW version", hww)
        fw = QHBoxLayout(); fw.addWidget(self.fw_major); fw.addWidget(QLabel("."))
        fw.addWidget(self.fw_minor)
        fww = QWidget(); fww.setLayout(fw); form.addRow("FW version", fww)
        form.addRow("Flags (u32)", self.flags)
        form.addRow("UTC (16)", self.utc)
        form.addRow("Login state", self.login)
        btns = QHBoxLayout()
        b_load = QPushButton("Reload"); b_load.clicked.connect(self.load)
        b_apply = QPushButton("Apply"); b_apply.clicked.connect(self.apply)
        btns.addWidget(b_load); btns.addWidget(b_apply); btns.addStretch(1)
        bw = QWidget(); bw.setLayout(btns); form.addRow(bw)

    def load(self) -> None:
        ctrl = self._get_ctrl()
        if not ctrl:
            return
        d = ctrl.get_identity(self._slot)
        if d.get("ok") != 1:
            return
        self.label.setText(str(d.get("label", "")))
        self.serial.setText(str(d.get("serial", "")))
        self.manufacturer.setText(str(d.get("manufacturer", "")))
        self.model.setText(str(d.get("model", "")))
        self.hw_major.setValue(int(d.get("hw_major", 0)))
        self.hw_minor.setValue(int(d.get("hw_minor", 0)))
        self.fw_major.setValue(int(d.get("fw_major", 0)))
        self.fw_minor.setValue(int(d.get("fw_minor", 0)))
        self.flags.setText(str(d.get("flags", 0)))
        self.utc.setText(str(d.get("utc", "")))
        self.login.setText(
            f"logged_in={d.get('logged_in')}, user={d.get('login_user')}, "
            f"objects={d.get('obj_count')}"
        )

    def apply(self) -> None:
        ctrl = self._get_ctrl()
        if not ctrl:
            return
        try:
            flags = int(self.flags.text(), 0)
        except ValueError:
            flags = 0
        ctrl.set_identity(
            self._slot,
            label=self.label.text(),
            serial=self.serial.text(),
            manufacturer=self.manufacturer.text(),
            model=self.model.text(),
            hw_major=self.hw_major.value(),
            hw_minor=self.hw_minor.value(),
            fw_major=self.fw_major.value(),
            fw_minor=self.fw_minor.value(),
            flags=flags,
            utc=self.utc.text(),
        )
        self.load()


class SlotPanel(QWidget):
    """Identity + stats + debug + link controls for a single slot."""

    def __init__(self, get_ctrl, slot: int, data_port: int):
        super().__init__()
        self._get_ctrl = get_ctrl
        self._slot = slot
        v = QVBoxLayout(self)

        info = QLabel(f"<b>Slot {slot}</b> &nbsp; data port "
                      f"<code>127.0.0.1:{data_port}</code>")
        v.addWidget(info)

        # Link controls
        linkbox = QGroupBox("Host link")
        lh = QHBoxLayout(linkbox)
        self.link_state = QLabel("link: ?  connected: ?")
        self.btn_up = QPushButton("Link Up")
        self.btn_down = QPushButton("Link Down")
        self.btn_reset = QPushButton("Reset")
        self.btn_up.clicked.connect(lambda: self._link(True))
        self.btn_down.clicked.connect(lambda: self._link(False))
        self.btn_reset.clicked.connect(self._reset)
        lh.addWidget(self.link_state, 1)
        lh.addWidget(self.btn_up); lh.addWidget(self.btn_down)
        lh.addWidget(self.btn_reset)
        v.addWidget(linkbox)

        tabs = QTabWidget()
        self.identity = IdentityPanel(get_ctrl, slot)
        tabs.addTab(self.identity, "Identity")

        # Stats grid
        stat_w = QWidget(); sg = QGridLayout(stat_w)
        self._stat_labels: Dict[str, QLabel] = {}
        keys = ["requests", "responses", "bytes_in", "bytes_out", "errors",
                "connects", "in_flight", "max_in_flight", "last_opcode"]
        for i, k in enumerate(keys):
            sg.addWidget(QLabel(f"{k}:"), i, 0)
            lab = QLabel("0"); lab.setFont(QFont("monospace"))
            self._stat_labels[k] = lab
            sg.addWidget(lab, i, 1)
        sg.setRowStretch(len(keys), 1)
        tabs.addTab(stat_w, "Statistics")

        # Debug table
        self.dbg = QTableWidget(0, 7)
        self.dbg.setHorizontalHeaderLabels(
            ["time", "opcode", "session", "seq", "ack", "req", "rsp"])
        self.dbg.horizontalHeader().setStretchLastSection(True)
        tabs.addTab(self.dbg, "Debug")

        v.addWidget(tabs, 1)
        self.identity.load()

    def _link(self, up: bool) -> None:
        ctrl = self._get_ctrl()
        if ctrl:
            ctrl.set_link(self._slot, up)

    def _reset(self) -> None:
        ctrl = self._get_ctrl()
        if ctrl:
            ctrl.reset(self._slot)

    def refresh(self) -> None:
        ctrl = self._get_ctrl()
        if not ctrl:
            return
        try:
            st = ctrl.stats(self._slot)
        except Exception:
            return
        if st.get("ok") != 1:
            return
        for k, lab in self._stat_labels.items():
            val = st.get(k, 0)
            if k == "last_opcode":
                lab.setText(f"{ci.opcode_name(val)} (0x{val:04X})")
            else:
                lab.setText(str(val))
        self.link_state.setText(
            f"link: {'UP' if st.get('link') else 'DOWN'}   "
            f"connected: {'yes' if st.get('connected') else 'no'}")
        # Debug tail
        try:
            events = ctrl.debug(self._slot)
        except Exception:
            events = []
        self.dbg.setRowCount(len(events))
        for row, e in enumerate(events):
            ts = time.strftime("%H:%M:%S", time.localtime(e["ts"] / 1000))
            ts += f".{e['ts'] % 1000:03d}"
            vals = [ts, f"{ci.opcode_name(e['opcode'])}",
                    str(e["session"]), str(e["seq"]),
                    ci.ckr_name(e["ack"]), str(e["req_len"]), str(e["rsp_len"])]
            for col, txt in enumerate(vals):
                item = QTableWidgetItem(txt)
                if col == 4 and e["ack"] != 0:
                    item.setForeground(QColor("#c0392b"))
                self.dbg.setItem(row, col, item)
        self.dbg.scrollToBottom()


class MockGui(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NCMP Mock HSM")
        self.resize(760, 640)
        self._proc: Optional[subprocess.Popen] = None
        self._ctrl: Optional[link.ControlClient] = None
        self._panels: List[SlotPanel] = []
        self._data_base = 7010
        self._ctrl_port = 7000

        self._build_toolbar()

        central = QWidget(); self.setCentralWidget(central)
        outer = QVBoxLayout(central)

        conn = QGroupBox("Server")
        cg = QHBoxLayout(conn)
        self.server_path = QLineEdit(find_server())
        b_browse = QPushButton("…"); b_browse.setFixedWidth(30)
        b_browse.clicked.connect(self._browse)
        self.slots = QSpinBox(); self.slots.setRange(1, 4); self.slots.setValue(2)
        self.ctrl_port = QSpinBox(); self.ctrl_port.setRange(1, 65535)
        self.ctrl_port.setValue(7000)
        self.data_port = QSpinBox(); self.data_port.setRange(1, 65535)
        self.data_port.setValue(7010)
        self.btn_start = QPushButton("Start"); self.btn_start.clicked.connect(self.start_server)
        self.btn_attach = QPushButton("Attach"); self.btn_attach.clicked.connect(self.attach)
        self.btn_stop = QPushButton("Stop"); self.btn_stop.clicked.connect(self.stop_server)
        cg.addWidget(QLabel("bin:")); cg.addWidget(self.server_path, 1)
        cg.addWidget(b_browse)
        cg.addWidget(QLabel("slots:")); cg.addWidget(self.slots)
        cg.addWidget(QLabel("ctrl:")); cg.addWidget(self.ctrl_port)
        cg.addWidget(QLabel("data:")); cg.addWidget(self.data_port)
        cg.addWidget(self.btn_start); cg.addWidget(self.btn_attach)
        cg.addWidget(self.btn_stop)
        outer.addWidget(conn)

        split = QSplitter(Qt.Horizontal)
        self.slot_list = QListWidget(); self.slot_list.setMaximumWidth(160)
        self.slot_list.currentRowChanged.connect(self._select_slot)
        split.addWidget(self.slot_list)
        self.slot_tabs = QTabWidget()
        split.addWidget(self.slot_tabs)
        split.setStretchFactor(1, 1)
        outer.addWidget(split, 1)

        self.statusBar().showMessage("Not connected.")
        self._timer = QTimer(self); self._timer.timeout.connect(self._tick)
        self._timer.start(600)

    def _build_toolbar(self) -> None:
        tb = self.addToolBar("main")
        act_quit = QAction("Quit", self); act_quit.triggered.connect(self.close)
        tb.addAction(act_quit)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Locate mock_server")
        if path:
            self.server_path.setText(path)

    # -- server lifecycle -------------------------------------------------
    def start_server(self) -> None:
        path = self.server_path.text().strip()
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, "mock_server",
                                "Server binary not found. Build it or set the path.")
            return
        if self._proc and self._proc.poll() is None:
            QMessageBox.information(self, "Server", "Server already running.")
            return
        self._ctrl_port = self.ctrl_port.value()
        self._data_base = self.data_port.value()
        try:
            self._proc = subprocess.Popen(
                [path, "--slots", str(self.slots.value()),
                 "--data-port", str(self._data_base),
                 "--ctrl-port", str(self._ctrl_port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as exc:
            QMessageBox.critical(self, "Server", f"Failed to start:\n{exc}")
            return
        time.sleep(0.4)
        self.attach()

    def attach(self) -> None:
        self._ctrl_port = self.ctrl_port.value()
        self._data_base = self.data_port.value()
        try:
            ctrl = link.ControlClient(port=self._ctrl_port)
            ctrl.connect()
            slots = ctrl.list_slots()
        except Exception as exc:
            QMessageBox.critical(self, "Attach",
                                 f"Cannot reach control port {self._ctrl_port}:\n{exc}")
            return
        self._ctrl = ctrl
        self._rebuild_slots(slots)
        self.statusBar().showMessage(
            f"Connected to control 127.0.0.1:{self._ctrl_port} "
            f"({len(slots)} slot(s)).")

    def stop_server(self) -> None:
        if self._ctrl:
            self._ctrl.close(); self._ctrl = None
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except Exception:
                self._proc.kill()
        self._proc = None
        self.slot_list.clear(); self.slot_tabs.clear(); self._panels = []
        self.statusBar().showMessage("Stopped.")

    def _rebuild_slots(self, slots: List[dict]) -> None:
        self.slot_list.clear(); self.slot_tabs.clear(); self._panels = []
        for s in slots:
            idx = int(s["slot"])
            port = int(s.get("data_port", self._data_base + idx))
            self.slot_list.addItem(f"Slot {idx}  ·  {s.get('label','')}")
            panel = SlotPanel(lambda: self._ctrl, idx, port)
            self._panels.append(panel)
            self.slot_tabs.addTab(panel, f"Slot {idx}")
        if self._panels:
            self.slot_list.setCurrentRow(0)

    def _select_slot(self, row: int) -> None:
        if 0 <= row < self.slot_tabs.count():
            self.slot_tabs.setCurrentIndex(row)

    def _tick(self) -> None:
        if not self._ctrl:
            return
        idx = self.slot_tabs.currentIndex()
        if 0 <= idx < len(self._panels):
            self._panels[idx].refresh()

    def closeEvent(self, event) -> None:  # noqa: N802
        self.stop_server()
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    win = MockGui()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
