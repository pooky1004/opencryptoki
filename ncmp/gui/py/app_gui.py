#!/usr/bin/env python3
"""NCMP Test App GUI - exercise an NCMP token (mock or real bridge) over a link.

Connects to one slot's data port and drives the token's command interface:

  * Connection - host/port/slot, connect/disconnect, target type (mock/real).
  * HSM State  - vendor queries (ping/selftest/fw/token-info) and the admin
                 lifecycle (login/logout, PIN, init-token, UTC clock).
  * Crypto     - RNG, digest (one-shot), AES-CTR / AES-GCM round-trips, SHAKE,
                 each with a software-reference comparison.
  * File check - read a >=1MB file, process it on the token (streaming digest or
                 chunked AES-CTR) and compare against the software reference.
  * Scenarios  - run built-in multi-step test sequences with pass/fail results.
  * Statistics - per-opcode counts, pass/fail, bytes and average latency.

Requires PySide6:  pip install -r requirements.txt
"""
from __future__ import annotations

import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QPlainTextEdit, QProgressBar, QPushButton,
    QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from ncmp_gui import ci, link, pkcs11_link, swcrypto, wire

MONO = QFont("monospace")


# --------------------------------------------------------------------------- #
# Session statistics                                                          #
# --------------------------------------------------------------------------- #
@dataclass
class OpStat:
    count: int = 0
    ok: int = 0
    fail: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    total_ms: float = 0.0


@dataclass
class SessionStats:
    per_op: Dict[int, OpStat] = field(default_factory=lambda: defaultdict(OpStat))

    def record(self, opcode: int, ok: bool, bin_: int, bout: int,
               ms: float) -> None:
        s = self.per_op[opcode]
        s.count += 1
        s.ok += 1 if ok else 0
        s.fail += 0 if ok else 1
        s.bytes_in += bin_
        s.bytes_out += bout
        s.total_ms += ms

    def clear(self) -> None:
        self.per_op.clear()


# --------------------------------------------------------------------------- #
# File-compare worker (background thread)                                     #
# --------------------------------------------------------------------------- #
class FileWorker(QThread):
    progress = Signal(int)
    done = Signal(dict)

    def __init__(self, dl: link.DataLink, path: str, mode: str, mech: int,
                 key: bytes, iv: bytes, reference: str):
        super().__init__()
        self.dl = dl
        self.path = path
        self.mode = mode          # "digest" | "aesctr"
        self.mech = mech
        self.key = key
        self.iv = iv
        self.reference = reference  # "mock" | "real"
        self.chunk = 32 * 1024

    def run(self) -> None:
        try:
            result = (self._digest() if self.mode == "digest"
                      else self._aesctr())
        except Exception as exc:  # noqa: BLE001
            result = {"ok": False, "error": str(exc)}
        self.done.emit(result)

    def _digest(self) -> dict:
        size = os.path.getsize(self.path)
        t0 = time.time()
        init = self.dl.command(ci.digest_init(self.mech))
        if init.ack != ci.CKR_OK:
            return {"ok": False, "error": f"INIT ack {ci.ckr_name(init.ack)}"}
        ctx_id = wire.rd_u32(init.param(0))
        hasher_data = bytearray() if self.reference == "mock" else None
        real = None
        if self.reference == "real":
            import hashlib
            algo = {ci.MECH_SHA256: "sha256", ci.MECH_SHA512: "sha512",
                    ci.MECH_SHA3_224: "sha3_224", ci.MECH_SHA3_256: "sha3_256",
                    ci.MECH_SHA3_384: "sha3_384",
                    ci.MECH_SHA3_512: "sha3_512"}[self.mech]
            real = hashlib.new(algo)
        seen = 0
        with open(self.path, "rb") as f:
            while True:
                chunk = f.read(self.chunk)
                if not chunk:
                    break
                self.dl.command(ci.digest_update(ctx_id, chunk))
                if hasher_data is not None:
                    hasher_data += chunk
                if real is not None:
                    real.update(chunk)
                seen += len(chunk)
                self.progress.emit(int(seen * 100 / max(size, 1)))
        fin = self.dl.command(ci.digest_final(ctx_id))
        token = fin.param(0)
        if self.reference == "mock":
            ref = swcrypto.mock_digest(self.mech, bytes(hasher_data))
        else:
            ref = real.digest()
        elapsed = time.time() - t0
        return {
            "ok": True, "mode": "digest", "size": size,
            "token": token.hex(), "ref": ref.hex(),
            "equal": token == ref, "elapsed": elapsed,
            "mbps": (size / (1024 * 1024)) / elapsed if elapsed else 0,
            "reference": self.reference,
        }

    def _aesctr(self) -> dict:
        size = os.path.getsize(self.path)
        t0 = time.time()
        mismatches = 0
        rt_fail = 0
        seen = 0
        with open(self.path, "rb") as f:
            while True:
                chunk = f.read(self.chunk)
                if not chunk:
                    break
                enc = self.dl.command(ci.aes_ctr(self.key, self.iv, chunk, True))
                ct = enc.param(0)
                ref = swcrypto.mock_aes_stream(self.key, self.iv, chunk)
                if ct != ref:
                    mismatches += 1
                dec = self.dl.command(ci.aes_ctr(self.key, self.iv, ct, False))
                if dec.param(0) != chunk:
                    rt_fail += 1
                seen += len(chunk)
                self.progress.emit(int(seen * 100 / max(size, 1)))
        elapsed = time.time() - t0
        return {
            "ok": True, "mode": "aesctr", "size": size,
            "equal": mismatches == 0 and rt_fail == 0,
            "mismatches": mismatches, "rt_fail": rt_fail,
            "elapsed": elapsed,
            "mbps": (size / (1024 * 1024)) / elapsed if elapsed else 0,
            "reference": "mock (datapath)",
        }


# --------------------------------------------------------------------------- #
# Main window                                                                 #
# --------------------------------------------------------------------------- #
class AppGui(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NCMP Test App")
        self.resize(880, 720)
        self.link: Optional[link.DataLink] = None
        self.stats = SessionStats()
        self._worker: Optional[FileWorker] = None
        self.p11 = pkcs11_link.Pkcs11Link()   # PKCS#11 (real stack) mode

        central = QWidget(); self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.addWidget(self._build_conn_bar())

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_state_tab(), "HSM State")
        self.tabs.addTab(self._build_crypto_tab(), "Crypto / Hash")
        self.tabs.addTab(self._build_pqc_tab(), "PQC")
        self.tabs.addTab(self._build_file_tab(), "File Compare")
        self.tabs.addTab(self._build_scenario_tab(), "Scenarios")
        self.tabs.addTab(self._build_pkcs11_tab(), "PKCS#11 (real stack)")
        self.tabs.addTab(self._build_stats_tab(), "Statistics")
        outer.addWidget(self.tabs, 1)

        self.statusBar().showMessage("Disconnected.")
        self._set_connected(False)

    # -- connection bar ---------------------------------------------------
    def _build_conn_bar(self) -> QWidget:
        box = QGroupBox("Link")
        h = QHBoxLayout(box)
        self.host = QLineEdit("127.0.0.1"); self.host.setMaximumWidth(120)
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(7010)
        self.port.setToolTip("Base data port; the App connects to base + slot.")
        self.slot = QSpinBox(); self.slot.setRange(0, 3)
        self.target = QComboBox(); self.target.addItems(["mock", "real (bridge)"])
        self.btn_conn = QPushButton("Connect"); self.btn_conn.clicked.connect(self.connect_link)
        self.btn_disc = QPushButton("Disconnect"); self.btn_disc.clicked.connect(self.disconnect_link)
        self.lbl_state = QLabel("●"); self.lbl_state.setStyleSheet("color:#c0392b")
        h.addWidget(QLabel("host:")); h.addWidget(self.host)
        h.addWidget(QLabel("port:")); h.addWidget(self.port)
        h.addWidget(QLabel("slot:")); h.addWidget(self.slot)
        h.addWidget(QLabel("target:")); h.addWidget(self.target)
        h.addWidget(self.btn_conn); h.addWidget(self.btn_disc)
        h.addStretch(1); h.addWidget(self.lbl_state)
        return box

    def connect_link(self) -> None:
        self.disconnect_link()
        # The mock server listens for slot s on (base data port + s); the App
        # connects to that computed port so the slot selector is meaningful.
        port = self.port.value() + self.slot.value()
        dl = link.DataLink(host=self.host.text(), port=port)
        try:
            dl.connect()
        except Exception as exc:  # noqa: BLE001
            self._log(self.state_out, f"connect failed: {exc}")
            self.statusBar().showMessage(f"Connect failed: {exc}")
            return
        self.link = dl
        self._set_connected(True)
        self.statusBar().showMessage(
            f"Connected to {self.host.text()}:{port} ({self.target.currentText()}).")

    def disconnect_link(self) -> None:
        if self.link:
            self.link.close(); self.link = None
        self._set_connected(False)
        self.statusBar().showMessage("Disconnected.")

    def _set_connected(self, on: bool) -> None:
        self.lbl_state.setStyleSheet("color:#27ae60" if on else "color:#c0392b")
        self.btn_conn.setEnabled(not on)
        self.btn_disc.setEnabled(on)

    def _is_mock(self) -> bool:
        return self.target.currentIndex() == 0

    # -- command helper ---------------------------------------------------
    def exec_ci(self, req: Tuple[int, List[bytes]], *,
                fail_bit: bool = False) -> Optional[wire.Message]:
        if not self.link:
            self.statusBar().showMessage("Not connected.")
            return None
        opcode = req[0] & 0xFFFF
        bin_ = sum(len(p) for p in req[1])
        t0 = time.time()
        try:
            msg = self.link.command(req, fail_bit=fail_bit)
        except Exception as exc:  # noqa: BLE001
            self.stats.record(opcode, False, bin_, 0, (time.time() - t0) * 1000)
            self.statusBar().showMessage(f"link error: {exc}")
            self.disconnect_link()
            return None
        ms = (time.time() - t0) * 1000
        bout = sum(len(p) for p in msg.params)
        self.stats.record(opcode, msg.ack == ci.CKR_OK, bin_, bout, ms)
        return msg

    # -- HSM State tab ----------------------------------------------------
    def _build_state_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)
        q = QGroupBox("Queries")
        qg = QHBoxLayout(q)
        for text, fn in [
            ("Ping", lambda: self._q(ci.vd_ping(), "epoch")),
            ("Selftest", lambda: self._q(ci.vd_selftest(), "status")),
            ("FW Info", lambda: self._q(ci.vd_fw_info(), "fw")),
            ("Token Info", lambda: self._q(ci.vd_token_info(), "identity")),
            ("Token Params", lambda: self._q(ci.get_token_params(), "params")),
            ("Get UTC", lambda: self._q(ci.get_utc_time(), "utc")),
        ]:
            b = QPushButton(text); b.clicked.connect(fn); qg.addWidget(b)
        v.addWidget(q)

        a = QGroupBox("Admin / login")
        ag = QFormLayout(a)
        self.user_type = QComboBox(); self.user_type.addItems(["USER", "SO"])
        self.pin = QLineEdit("1234")
        row1 = QHBoxLayout()
        row1.addWidget(self.user_type); row1.addWidget(QLabel("PIN:"))
        row1.addWidget(self.pin)
        b_login = QPushButton("Login"); b_login.clicked.connect(self._login)
        b_logout = QPushButton("Logout")
        b_logout.clicked.connect(lambda: self._q(ci.logout(), "logout"))
        row1.addWidget(b_login); row1.addWidget(b_logout)
        rw1 = QWidget(); rw1.setLayout(row1); ag.addRow("Login", rw1)

        self.old_pin = QLineEdit("1234"); self.new_pin = QLineEdit("5678")
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("old:")); row2.addWidget(self.old_pin)
        row2.addWidget(QLabel("new:")); row2.addWidget(self.new_pin)
        b_setpin = QPushButton("Set PIN")
        b_setpin.clicked.connect(lambda: self._q(
            ci.set_pin(self.old_pin.text().encode(), self.new_pin.text().encode()),
            "set_pin"))
        row2.addWidget(b_setpin)
        rw2 = QWidget(); rw2.setLayout(row2); ag.addRow("Change PIN", rw2)

        self.so_pin = QLineEdit("12345678"); self.tok_label = QLineEdit("MYTOKEN")
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("SO PIN:")); row3.addWidget(self.so_pin)
        row3.addWidget(QLabel("label:")); row3.addWidget(self.tok_label)
        b_init = QPushButton("Init Token")
        b_init.clicked.connect(lambda: self._q(
            ci.init_token(self.so_pin.text().encode(),
                          self.tok_label.text().encode()), "init_token"))
        row3.addWidget(b_init)
        rw3 = QWidget(); rw3.setLayout(row3); ag.addRow("Init token", rw3)
        v.addWidget(a)

        # Session CI (OpenSession/CloseSession -> HSM SID)
        se = QGroupBox("Session (CI 0x003A/0x003B)")
        sg = QHBoxLayout(se)
        self.sess_pid = QLineEdit(str(os.getpid())); self.sess_pid.setMaximumWidth(90)
        self.sess_sid = QSpinBox(); self.sess_sid.setRange(0, 2_000_000_000)
        self.sess_hsid = QSpinBox(); self.sess_hsid.setRange(0, 255)
        b_open = QPushButton("Open"); b_open.clicked.connect(self._open_session)
        b_close = QPushButton("Close"); b_close.clicked.connect(self._close_session)
        sg.addWidget(QLabel("pid:")); sg.addWidget(self.sess_pid)
        sg.addWidget(QLabel("sid:")); sg.addWidget(self.sess_sid)
        sg.addWidget(b_open)
        sg.addWidget(QLabel("HSM SID:")); sg.addWidget(self.sess_hsid)
        sg.addWidget(b_close)
        v.addWidget(se)

        self.state_out = QPlainTextEdit(); self.state_out.setReadOnly(True)
        self.state_out.setFont(MONO)
        v.addWidget(self.state_out, 1)
        return w

    def _login(self) -> None:
        ut = ci.CKU_USER if self.user_type.currentIndex() == 0 else ci.CKU_SO
        self._q(ci.login(ut, self.pin.text().encode()), "login")

    def _open_session(self) -> None:
        try:
            pid = int(self.sess_pid.text(), 0)
        except ValueError:
            pid = os.getpid()
        msg = self.exec_ci(ci.open_session(pid, self.sess_sid.value()))
        if msg is None:
            return
        if msg.ack == ci.CKR_OK:
            hsid = wire.rd_u32(msg.param(0))
            self.sess_hsid.setValue(hsid)
            self._log(self.state_out,
                      f"OPEN_SESSION pid={pid} sid={self.sess_sid.value()} "
                      f"-> HSM SID {hsid}")
        else:
            self._log(self.state_out,
                      f"OPEN_SESSION failed: {ci.ckr_name(msg.ack)}")

    def _close_session(self) -> None:
        msg = self.exec_ci(ci.close_session(self.sess_hsid.value()))
        if msg is None:
            return
        self._log(self.state_out,
                  f"CLOSE_SESSION HSM SID {self.sess_hsid.value()} "
                  f"-> {ci.ckr_name(msg.ack)}")

    def _q(self, req, kind: str) -> None:
        msg = self.exec_ci(req)
        if msg is None:
            return
        p0 = msg.param(0)
        detail = f"ack={ci.ckr_name(msg.ack)}"
        if kind == "epoch" and len(p0) >= 4:
            detail += f"  epoch={wire.rd_u32(p0)}"
        elif kind == "status" and len(p0) >= 4:
            detail += f"  status={wire.rd_u32(p0)}"
        elif kind == "fw" and len(p0) >= 16:
            detail += (f"  v{wire.rd_u32(p0)}.{wire.rd_u32(p0,4)}."
                       f"{wire.rd_u32(p0,8)} build=0x{wire.rd_u32(p0,12):X}")
        elif kind == "identity" and len(p0) >= 104:
            label = p0[0:32].split(b'\x00')[0].decode('latin1')
            serial = p0[32:48].split(b'\x00')[0].decode('latin1')
            manuf = p0[48:80].split(b'\x00')[0].decode('latin1')
            model = p0[80:96].split(b'\x00')[0].decode('latin1')
            detail += f"  label='{label}' serial='{serial}' manuf='{manuf}' model='{model}'"
        elif kind == "params":
            label = msg.param(0).split(b'\x00')[0].decode('latin1')
            serial = msg.param(1).split(b'\x00')[0].decode('latin1')
            detail += f"  label='{label}' serial='{serial}'"
            if len(msg.params) >= 4:
                detail += (f" minpin={wire.rd_u32(msg.param(2))}"
                           f" maxpin={wire.rd_u32(msg.param(3))}")
        elif kind == "utc":
            detail += f"  utc='{p0.decode('latin1', 'replace')}'"
        self._log(self.state_out, f"{ci.opcode_name(req[0])}: {detail}")

    # -- Crypto tab -------------------------------------------------------
    def _build_crypto_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)

        # RNG
        g_rng = QGroupBox("RNG"); h = QHBoxLayout(g_rng)
        self.rng_n = QSpinBox(); self.rng_n.setRange(1, 4096); self.rng_n.setValue(32)
        b = QPushButton("Generate"); b.clicked.connect(self._do_rng)
        h.addWidget(QLabel("bytes:")); h.addWidget(self.rng_n); h.addWidget(b)
        h.addStretch(1); v.addWidget(g_rng)

        # Digest
        g_dg = QGroupBox("Digest (one-shot, compared to SW)")
        dg = QHBoxLayout(g_dg)
        self.dg_mech = QComboBox()
        for m, name in ci.MECH_NAMES.items():
            self.dg_mech.addItem(name, m)
        self.dg_in = QLineEdit("The quick brown fox")
        b2 = QPushButton("Digest"); b2.clicked.connect(self._do_digest)
        dg.addWidget(self.dg_mech); dg.addWidget(self.dg_in, 1); dg.addWidget(b2)
        v.addWidget(g_dg)

        # AES-CTR
        g_ct = QGroupBox("AES-CTR (round-trip + SW compare)")
        cf = QFormLayout(g_ct)
        self.ctr_key = QLineEdit("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        self.ctr_iv = QLineEdit("000102030405060708090a0b0c0d0e0f")
        self.ctr_data = QLineEdit("stream this payload")
        b3 = QPushButton("Encrypt+Decrypt"); b3.clicked.connect(self._do_ctr)
        cf.addRow("key (hex)", self.ctr_key)
        cf.addRow("iv (hex)", self.ctr_iv)
        cf.addRow("data", self.ctr_data)
        cf.addRow(b3)
        v.addWidget(g_ct)

        # AES-GCM one-shot round-trip
        g_gcm = QGroupBox("AES-GCM (one-shot round-trip)")
        gf = QFormLayout(g_gcm)
        self.gcm_key = QLineEdit("000102030405060708090a0b0c0d0e0f")
        self.gcm_iv = QLineEdit("000102030405060708090a0b")
        self.gcm_aad = QLineEdit("")
        self.gcm_data = QLineEdit("authenticated payload")
        b4 = QPushButton("Encrypt+Decrypt"); b4.clicked.connect(self._do_gcm)
        gf.addRow("key (hex)", self.gcm_key)
        gf.addRow("iv (hex)", self.gcm_iv)
        gf.addRow("aad (hex)", self.gcm_aad)
        gf.addRow("data", self.gcm_data)
        gf.addRow(b4)
        v.addWidget(g_gcm)

        self.crypto_out = QPlainTextEdit(); self.crypto_out.setReadOnly(True)
        self.crypto_out.setFont(MONO)
        v.addWidget(self.crypto_out, 1)
        return w

    @staticmethod
    def _hex(s: str) -> bytes:
        return bytes.fromhex(s.strip().replace(" ", ""))

    def _do_rng(self) -> None:
        msg = self.exec_ci(ci.rng(self.rng_n.value()))
        if msg is None:
            return
        out = msg.param(0)
        note = ""
        if self._is_mock():
            note = "  [matches SW replica]" if out == swcrypto.mock_rng(len(out)) \
                   else "  [MISMATCH vs replica]"
        self._log(self.crypto_out, f"RNG {len(out)}B: {out.hex()}{note}")

    def _do_digest(self) -> None:
        mech = self.dg_mech.currentData()
        data = self.dg_in.text().encode()
        msg = self.exec_ci(ci.digest(mech, data))
        if msg is None:
            return
        out = msg.param(0)
        if self._is_mock():
            ref = swcrypto.mock_digest(mech, data)
        else:
            ref = swcrypto.real_digest(mech, data)
        eq = "EQUAL" if out == ref else "DIFFERENT"
        self._log(self.crypto_out,
                  f"{ci.MECH_NAMES[mech]}({len(data)}B) = {out.hex()}\n"
                  f"    SW ref ({'mock' if self._is_mock() else 'real'}) "
                  f"= {ref.hex()}  [{eq}]")

    def _do_ctr(self) -> None:
        try:
            key = self._hex(self.ctr_key.text()); iv = self._hex(self.ctr_iv.text())
        except ValueError as e:
            self._log(self.crypto_out, f"hex error: {e}"); return
        pt = self.ctr_data.text().encode()
        enc = self.exec_ci(ci.aes_ctr(key, iv, pt, True))
        if enc is None:
            return
        ct = enc.param(0)
        dec = self.exec_ci(ci.aes_ctr(key, iv, ct, False))
        rt = dec.param(0) == pt if dec else False
        note = ""
        if self._is_mock():
            note = ("  [ct matches replica]" if ct == swcrypto.mock_aes_stream(key, iv, pt)
                    else "  [ct MISMATCH]")
        self._log(self.crypto_out,
                  f"AES-CTR ct={ct.hex()}{note}\n"
                  f"    round-trip decrypt: {'OK' if rt else 'FAIL'}")

    def _do_gcm(self) -> None:
        try:
            key = self._hex(self.gcm_key.text()); iv = self._hex(self.gcm_iv.text())
            aad = self._hex(self.gcm_aad.text()) if self.gcm_aad.text() else b""
        except ValueError as e:
            self._log(self.crypto_out, f"hex error: {e}"); return
        pt = self.gcm_data.text().encode()
        taglen = 16
        enc = self.exec_ci(ci.aes_gcm(key, iv, aad, taglen, pt, True))
        if enc is None:
            return
        # Response param0 = ciphertext || tag (mock GCM AEAD layout).
        blob = enc.param(0)
        ct, tag = blob[:-taglen], blob[-taglen:]
        # Decrypt takes the whole ct||tag blob back and returns the plaintext.
        dec = self.exec_ci(ci.aes_gcm(key, iv, aad, taglen, blob, False))
        rt = bool(dec) and dec.ack == ci.CKR_OK and dec.param(0) == pt
        self._log(self.crypto_out,
                  f"AES-GCM ct={ct.hex()} tag={tag.hex()}  ack={ci.ckr_name(enc.ack)}\n"
                  f"    round-trip decrypt: {'OK (tag verified)' if rt else 'FAIL'}")

    # -- PQC tab ----------------------------------------------------------
    def _build_pqc_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)

        # ML-DSA (sign / verify)
        g_dsa = QGroupBox("ML-DSA  (keygen → sign → verify)")
        df = QFormLayout(g_dsa)
        self.dsa_set = QComboBox()
        for name in ci.MLDSA_SETS:
            self.dsa_set.addItem(name)
        self.dsa_data = QLineEdit("post-quantum message")
        b_dsa = QPushButton("Run ML-DSA round-trip")
        b_dsa.clicked.connect(self._run_mldsa)
        df.addRow("Parameter set", self.dsa_set)
        df.addRow("Message", self.dsa_data)
        df.addRow(b_dsa)
        v.addWidget(g_dsa)

        # ML-KEM (encapsulate / decapsulate)
        g_kem = QGroupBox("ML-KEM  (keygen → encapsulate → decapsulate)")
        kf = QFormLayout(g_kem)
        self.kem_set = QComboBox()
        for name in ci.MLKEM_SETS:
            self.kem_set.addItem(name)
        b_kem = QPushButton("Run ML-KEM round-trip")
        b_kem.clicked.connect(self._run_mlkem)
        kf.addRow("Parameter set", self.kem_set)
        kf.addRow(b_kem)
        v.addWidget(g_kem)

        note = QLabel(
            "<i>PQC keys are opaque blobs; the mock produces deterministic, "
            "size-correct output so round-trips succeed (not real ML-DSA/ML-KEM). "
            "A real token returns true keys/signatures.</i>")
        note.setWordWrap(True)
        v.addWidget(note)

        self.pqc_out = QPlainTextEdit(); self.pqc_out.setReadOnly(True)
        self.pqc_out.setFont(MONO)
        v.addWidget(self.pqc_out, 1)
        return w

    def _run_mldsa(self) -> None:
        if not self.link:
            self._log(self.pqc_out, "not connected"); return
        name = self.dsa_set.currentText()
        set_, pub_len, priv_len, sig_len = ci.MLDSA_SETS[name]
        data = self.dsa_data.text().encode()
        self._log(self.pqc_out, f"── {name} (set={set_}) ──")

        kg = self.exec_ci(ci.mldsa_keygen(set_, pub_len, priv_len))
        if kg is None:
            return
        pub, priv = kg.param(0), kg.param(1)
        kg_ok = (kg.ack == ci.CKR_OK and len(pub) == pub_len
                 and len(priv) == priv_len and priv[:pub_len] == pub)
        self._log(self.pqc_out,
                  f"  keygen: {'OK' if kg_ok else 'FAIL'}  "
                  f"pub={len(pub)}B priv={len(priv)}B (priv is pub-prefixed)")

        sg = self.exec_ci(ci.mldsa_sign(set_, pub_len, sig_len, priv, data))
        if sg is None:
            return
        sig = sg.param(0)
        sg_ok = sg.ack == ci.CKR_OK and len(sig) == sig_len
        self._log(self.pqc_out,
                  f"  sign:   {'OK' if sg_ok else 'FAIL'}  sig={len(sig)}B  "
                  f"{sig[:16].hex()}…")

        vf = self.exec_ci(ci.mldsa_verify(set_, pub, data, sig))
        neg = self.exec_ci(ci.mldsa_verify(set_, pub, data + b"!", sig))
        vf_ok = bool(vf) and vf.ack == ci.CKR_OK
        neg_ok = bool(neg) and neg.ack != ci.CKR_OK
        self._log(self.pqc_out,
                  f"  verify: {ci.ckr_name(vf.ack) if vf else '-'}  "
                  f"| tampered → {ci.ckr_name(neg.ack) if neg else '-'} "
                  f"(expect SIGNATURE_INVALID)")
        overall = kg_ok and sg_ok and vf_ok and neg_ok
        self._log(self.pqc_out,
                  f"  RESULT: {'PASS ✓' if overall else 'FAIL ✗'}\n")

    def _run_mlkem(self) -> None:
        if not self.link:
            self._log(self.pqc_out, "not connected"); return
        name = self.kem_set.currentText()
        set_, pub_len, priv_len, ct_len, ss_len = ci.MLKEM_SETS[name]
        self._log(self.pqc_out, f"── {name} (set={set_}) ──")

        kg = self.exec_ci(ci.mlkem_keygen(set_, pub_len, priv_len))
        if kg is None:
            return
        pub, priv = kg.param(0), kg.param(1)
        kg_ok = (kg.ack == ci.CKR_OK and len(pub) == pub_len
                 and len(priv) == priv_len and priv[:pub_len] == pub)
        self._log(self.pqc_out,
                  f"  keygen:   {'OK' if kg_ok else 'FAIL'}  "
                  f"pub={len(pub)}B priv={len(priv)}B")

        en = self.exec_ci(ci.mlkem_encaps(set_, ct_len, ss_len, pub))
        if en is None:
            return
        ct, ss = en.param(0), en.param(1)
        en_ok = en.ack == ci.CKR_OK and len(ct) == ct_len and len(ss) == ss_len
        self._log(self.pqc_out,
                  f"  encaps:   {'OK' if en_ok else 'FAIL'}  "
                  f"ct={len(ct)}B ss={ss.hex()}")

        de = self.exec_ci(ci.mlkem_decaps(set_, pub_len, ss_len, priv, ct))
        if de is None:
            return
        ss2 = de.param(0)
        match = de.ack == ci.CKR_OK and ss2 == ss
        self._log(self.pqc_out,
                  f"  decaps:   {'OK' if de.ack == ci.CKR_OK else 'FAIL'}  "
                  f"ss={ss2.hex()}")
        self._log(self.pqc_out,
                  f"  shared secret match: {'YES' if match else 'NO'}")
        overall = kg_ok and en_ok and match
        self._log(self.pqc_out,
                  f"  RESULT: {'PASS ✓' if overall else 'FAIL ✗'}\n")

    # -- File Compare tab -------------------------------------------------
    def _build_file_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)
        form = QFormLayout()
        fh = QHBoxLayout()
        self.file_path = QLineEdit()
        b_browse = QPushButton("Browse…"); b_browse.clicked.connect(self._pick_file)
        b_gen = QPushButton("Make 1MB test file"); b_gen.clicked.connect(self._gen_file)
        fh.addWidget(self.file_path, 1); fh.addWidget(b_browse); fh.addWidget(b_gen)
        fw = QWidget(); fw.setLayout(fh); form.addRow("File", fw)

        self.file_mode = QComboBox()
        self.file_mode.addItems(["Digest (streaming, multipart)",
                                 "AES-CTR (chunked, mock datapath)"])
        form.addRow("Operation", self.file_mode)
        self.file_mech = QComboBox()
        for m, name in ci.MECH_NAMES.items():
            self.file_mech.addItem(name, m)
        form.addRow("Digest mech", self.file_mech)
        v.addLayout(form)

        h = QHBoxLayout()
        self.file_run = QPushButton("Run & Compare"); self.file_run.clicked.connect(self._run_file)
        self.file_prog = QProgressBar()
        h.addWidget(self.file_run); h.addWidget(self.file_prog, 1)
        v.addLayout(h)

        self.file_out = QPlainTextEdit(); self.file_out.setReadOnly(True)
        self.file_out.setFont(MONO)
        v.addWidget(self.file_out, 1)
        return w

    def _pick_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file")
        if path:
            self.file_path.setText(path)

    def _gen_file(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Create test file",
                                              "ncmp_testfile.bin")
        if not path:
            return
        with open(path, "wb") as f:
            block = bytes((i * 37 + 11) & 0xFF for i in range(4096))
            for _ in range(320):  # ~1.25 MB
                f.write(block)
        self.file_path.setText(path)
        self._log(self.file_out, f"created {path} ({os.path.getsize(path)} bytes)")

    def _run_file(self) -> None:
        if not self.link:
            self._log(self.file_out, "not connected"); return
        path = self.file_path.text().strip()
        if not path or not os.path.exists(path):
            self._log(self.file_out, "pick an existing file"); return
        mode = "digest" if self.file_mode.currentIndex() == 0 else "aesctr"
        reference = "mock" if self._is_mock() else "real"
        if mode == "aesctr" and reference == "real":
            self._log(self.file_out,
                      "note: AES-CTR chunked compare is a mock datapath test "
                      "(per-chunk keystream reset); use Digest for a real target.")
        key = bytes(range(32)); iv = bytes(range(16))
        self.file_run.setEnabled(False)
        self.file_prog.setValue(0)
        self._log(self.file_out,
                  f"running {mode} over {os.path.getsize(path)} bytes …")
        self._worker = FileWorker(self.link, path, mode,
                                  self.file_mech.currentData(), key, iv, reference)
        self._worker.progress.connect(self.file_prog.setValue)
        self._worker.done.connect(self._file_done)
        self._worker.start()

    def _file_done(self, r: dict) -> None:
        self.file_run.setEnabled(True)
        if not r.get("ok"):
            self._log(self.file_out, f"ERROR: {r.get('error')}"); return
        if r["mode"] == "digest":
            verdict = "IDENTICAL ✓" if r["equal"] else "DIFFERENT ✗"
            self._log(self.file_out,
                      f"[{verdict}]  {r['size']} bytes in {r['elapsed']:.2f}s "
                      f"({r['mbps']:.1f} MB/s), ref={r['reference']}\n"
                      f"    token = {r['token']}\n    swref = {r['ref']}")
        else:
            verdict = "IDENTICAL ✓" if r["equal"] else "DIFFERENT ✗"
            self._log(self.file_out,
                      f"[{verdict}]  {r['size']} bytes in {r['elapsed']:.2f}s "
                      f"({r['mbps']:.1f} MB/s)\n"
                      f"    chunk mismatches={r['mismatches']} "
                      f"round-trip failures={r['rt_fail']}")

    # -- Scenarios tab ----------------------------------------------------
    def _build_scenario_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)
        h = QHBoxLayout()
        self.scenario = QComboBox()
        self.scenario.addItems(["Smoke (queries + RNG + digest)",
                                "Admin lifecycle (login/PIN)",
                                "Crypto round-trips",
                                "PQC round-trips (ML-DSA + ML-KEM)"])
        b = QPushButton("Run scenario"); b.clicked.connect(self._run_scenario)
        h.addWidget(self.scenario, 1); h.addWidget(b)
        v.addLayout(h)
        self.scen_tbl = QTableWidget(0, 3)
        self.scen_tbl.setHorizontalHeaderLabels(["step", "result", "detail"])
        self.scen_tbl.horizontalHeader().setStretchLastSection(True)
        v.addWidget(self.scen_tbl, 1)
        return w

    def _run_scenario(self) -> None:
        if not self.link:
            self.statusBar().showMessage("not connected"); return
        idx = self.scenario.currentIndex()
        steps = [self._scen_smoke, self._scen_admin, self._scen_crypto,
                 self._scen_pqc][idx]()
        self.scen_tbl.setRowCount(len(steps))
        for row, (name, ok, detail) in enumerate(steps):
            self.scen_tbl.setItem(row, 0, QTableWidgetItem(name))
            it = QTableWidgetItem("PASS" if ok else "FAIL")
            it.setForeground(Qt.GlobalColor.darkGreen if ok else Qt.GlobalColor.red)
            self.scen_tbl.setItem(row, 1, it)
            self.scen_tbl.setItem(row, 2, QTableWidgetItem(detail))

    def _step(self, name, req, pred, fail_bit=False):
        msg = self.exec_ci(req, fail_bit=fail_bit)
        if msg is None:
            return (name, False, "no response")
        try:
            ok, detail = pred(msg)
        except Exception as e:  # noqa: BLE001
            return (name, False, f"exc {e}")
        return (name, ok, detail)

    def _scen_smoke(self):
        out = []
        out.append(self._step("VD_PING", ci.vd_ping(),
                              lambda m: (m.ack == 0 and len(m.param(0)) == 4,
                                         f"epoch={wire.rd_u32(m.param(0))}")))
        out.append(self._step("VD_SELFTEST", ci.vd_selftest(),
                              lambda m: (wire.rd_u32(m.param(0)) == 0, "status=0")))
        out.append(self._step("RNG64", ci.rng(64),
                              lambda m: (len(m.param(0)) == 64, "64 bytes")))
        out.append(self._step("SHA-256", ci.digest(ci.MECH_SHA256, b"abc"),
                              lambda m: (m.param(0) == swcrypto.mock_digest(ci.MECH_SHA256, b"abc"),
                                         "matches replica")))
        return out

    def _scen_admin(self):
        out = []
        out.append(self._step("login USER 1234", ci.login(ci.CKU_USER, b"1234"),
                              lambda m: (m.ack == 0, ci.ckr_name(m.ack))))
        out.append(self._step("login bad PIN", ci.login(ci.CKU_USER, b"0000"),
                              lambda m: (m.ack != 0, ci.ckr_name(m.ack))))
        out.append(self._step("logout", ci.logout(),
                              lambda m: (m.ack == 0, ci.ckr_name(m.ack))))
        out.append(self._step("token params", ci.get_token_params(),
                              lambda m: (len(m.param(0)) == 32, "label present")))
        return out

    def _scen_crypto(self):
        out = []
        key = bytes(range(32)); iv = bytes(range(16)); pt = b"round trip" * 20
        enc = self.exec_ci(ci.aes_ctr(key, iv, pt, True))
        ct = enc.param(0) if enc else b""
        out.append(("AES-CTR encrypt", bool(enc) and enc.ack == 0,
                    f"{len(ct)} bytes"))
        dec = self.exec_ci(ci.aes_ctr(key, iv, ct, False))
        out.append(("AES-CTR round-trip", bool(dec) and dec.param(0) == pt,
                    "plaintext recovered"))
        out.append(self._step("multipart digest",
                              ci.digest_init(ci.MECH_SHA512),
                              lambda m: (m.ack == 0, "ctx allocated")))
        return out

    def _scen_pqc(self):
        out = []
        # ML-DSA-65 keygen -> sign -> verify (+ tamper)
        s, pl, prl, sl = ci.MLDSA_SETS["ML-DSA-65"]
        kg = self.exec_ci(ci.mldsa_keygen(s, pl, prl))
        pub = kg.param(0) if kg else b""
        priv = kg.param(1) if kg else b""
        out.append(("ML-DSA keygen", bool(kg) and kg.ack == 0
                    and priv[:pl] == pub, f"pub={len(pub)} priv={len(priv)}"))
        sg = self.exec_ci(ci.mldsa_sign(s, pl, sl, priv, b"scenario"))
        sig = sg.param(0) if sg else b""
        out.append(("ML-DSA sign", bool(sg) and sg.ack == 0 and len(sig) == sl,
                    f"sig={len(sig)}"))
        vf = self.exec_ci(ci.mldsa_verify(s, pub, b"scenario", sig))
        out.append(("ML-DSA verify", bool(vf) and vf.ack == 0,
                    ci.ckr_name(vf.ack) if vf else "-"))
        neg = self.exec_ci(ci.mldsa_verify(s, pub, b"scenarioX", sig))
        out.append(("ML-DSA reject tampered", bool(neg) and neg.ack != 0,
                    ci.ckr_name(neg.ack) if neg else "-"))
        # ML-KEM-768 keygen -> encaps -> decaps
        s, pl, prl, cl, ssl = ci.MLKEM_SETS["ML-KEM-768"]
        kg = self.exec_ci(ci.mlkem_keygen(s, pl, prl))
        pub = kg.param(0) if kg else b""
        priv = kg.param(1) if kg else b""
        out.append(("ML-KEM keygen", bool(kg) and kg.ack == 0, f"pub={len(pub)}"))
        en = self.exec_ci(ci.mlkem_encaps(s, cl, ssl, pub))
        ct = en.param(0) if en else b""
        ss = en.param(1) if en else b""
        out.append(("ML-KEM encaps", bool(en) and en.ack == 0, f"ct={len(ct)}"))
        de = self.exec_ci(ci.mlkem_decaps(s, pl, ssl, priv, ct))
        ss2 = de.param(0) if de else b""
        out.append(("ML-KEM shared-secret match", bool(de) and ss2 == ss,
                    "ss identical" if ss2 == ss else "ss differ"))
        return out

    # -- PKCS#11 (real stack) tab -----------------------------------------
    def _build_pkcs11_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)

        avail, detail = pkcs11_link.available()
        banner = QLabel(
            "실 PKCS#11 스택(App→libopencryptoki→STDLL→ncmpd→USB/소켓)을 C_* 로 구동. "
            "프레임 링크(상단 Link)와는 독립이며, 표준 C_* 로 표현 가능한 연산만 제공. "
            + ("" if avail else f"<br><b>{detail}</b>"))
        banner.setWordWrap(True)
        v.addWidget(banner)

        conn = QGroupBox("PKCS#11 module")
        cf = QFormLayout(conn)
        self.p11_module = QLineEdit(os.environ.get("PKCS11_MODULE", ""))
        self.p11_module.setPlaceholderText("/usr/local/lib/opencryptoki/libopencryptoki.so")
        b_browse = QPushButton("Browse…"); b_browse.clicked.connect(self._p11_browse)
        mrow = QHBoxLayout()
        mrow.addWidget(self.p11_module, 1); mrow.addWidget(b_browse)
        mrw = QWidget(); mrw.setLayout(mrow)
        self.p11_slot = QSpinBox(); self.p11_slot.setRange(0, 254)
        self.p11_pin = QLineEdit("1234")
        row = QHBoxLayout()
        b_load = QPushButton("Load+Open"); b_load.clicked.connect(self._p11_connect)
        b_login = QPushButton("Login"); b_login.clicked.connect(self._p11_login)
        b_logout = QPushButton("Logout"); b_logout.clicked.connect(self._p11_logout)
        b_disc = QPushButton("Close"); b_disc.clicked.connect(self._p11_close)
        row.addWidget(b_load); row.addWidget(b_login)
        row.addWidget(b_logout); row.addWidget(b_disc); row.addStretch(1)
        rw = QWidget(); rw.setLayout(row)
        cf.addRow("module (.so)", mrw)
        hs = QHBoxLayout()
        hs.addWidget(QLabel("slot:")); hs.addWidget(self.p11_slot)
        hs.addWidget(QLabel("PIN:")); hs.addWidget(self.p11_pin)
        hsw = QWidget(); hsw.setLayout(hs)
        cf.addRow("slot / PIN", hsw)
        cf.addRow(rw)
        v.addWidget(conn)

        ops = QGroupBox("Operations (C_*)")
        og = QHBoxLayout(ops)
        self.p11_rng_n = QSpinBox(); self.p11_rng_n.setRange(1, 4096); self.p11_rng_n.setValue(32)
        b_rng = QPushButton("GenerateRandom"); b_rng.clicked.connect(self._p11_rng)
        self.p11_mech = QComboBox()
        for name in ci.MECH_NAMES.values():
            self.p11_mech.addItem(name)
        self.p11_in = QLineEdit("The quick brown fox")
        b_dg = QPushButton("Digest"); b_dg.clicked.connect(self._p11_digest)
        b_gcm = QPushButton("AES-GCM round-trip"); b_gcm.clicked.connect(self._p11_gcm)
        b_ti = QPushButton("Token Info"); b_ti.clicked.connect(self._p11_tokeninfo)
        og.addWidget(QLabel("RNG:")); og.addWidget(self.p11_rng_n); og.addWidget(b_rng)
        og.addWidget(self.p11_mech); og.addWidget(self.p11_in, 1); og.addWidget(b_dg)
        og.addWidget(b_gcm); og.addWidget(b_ti)
        v.addWidget(ops)

        note = QLabel(
            "<i>벤더 datapath·세션 CI·fail-bit·원시 opcode는 C_* 로 도달 불가 → 프레임 "
            "링크 모드에서 시험. 사용·레시피: docs/app-stdll-path-design.md.</i>")
        note.setWordWrap(True)
        v.addWidget(note)

        self.p11_out = QPlainTextEdit(); self.p11_out.setReadOnly(True)
        self.p11_out.setFont(MONO)
        v.addWidget(self.p11_out, 1)
        return w

    # Guidance shown when the real PKCS#11 stack is not usable yet.
    _P11_HINT = (
        "→ 지금 mock을 시험하려면 이 탭 대신 상단 Link 바에서 "
        "target=mock, port=7010, slot 선택 후 Connect 하고 다른 탭(HSM State/"
        "Crypto/PQC/File Compare/Scenarios)을 사용하세요.\n"
        "→ 이 PKCS#11 탭을 쓰려면 빌드된 libopencryptoki.so + 기동된 ncmpd가 "
        "필요합니다(레시피: docs/app-stdll-path-design.md)."
    )

    def _p11_browse(self) -> None:
        start = self.p11_module.text().strip()
        start_dir = os.path.dirname(start) if start else "/usr/local/lib"
        path, _ = QFileDialog.getOpenFileName(
            self, "Select PKCS#11 module (libopencryptoki.so)", start_dir,
            "Shared libraries (*.so *.so.*);;All files (*)")
        if path:
            self.p11_module.setText(path)

    def _p11_connect(self) -> None:
        module = self.p11_module.text().strip()
        if not module:
            self._log(self.p11_out,
                      "모듈 경로가 비어 있습니다($PKCS11_MODULE 미설정).\n"
                      + self._P11_HINT)
            return
        try:
            self.p11.load(module)
            slots = self.p11.slots()
            self._log(self.p11_out, f"loaded; token-present slots: {slots}")
            self.p11.open(self.p11_slot.value(), rw=True)
            self._log(self.p11_out, f"session open on slot {self.p11_slot.value()}")
        except pkcs11_link.Pkcs11Error as e:
            self._log(self.p11_out, f"ERROR: {e}\n" + self._P11_HINT)

    def _p11_need_session(self) -> bool:
        """Log guidance and return False when there is no open PKCS#11 session."""
        if self.p11.connected:
            return True
        self._log(self.p11_out,
                  "세션이 없습니다. 먼저 module 경로 지정 후 Load+Open 하세요.\n"
                  + self._P11_HINT)
        return False

    def _p11_login(self) -> None:
        if not self._p11_need_session():
            return
        try:
            self.p11.login(self.p11_pin.text())
            self._log(self.p11_out, "C_Login OK")
        except Exception as e:  # noqa: BLE001
            self._log(self.p11_out, f"login error: {e}")

    def _p11_logout(self) -> None:
        self.p11.logout(); self._log(self.p11_out, "C_Logout")

    def _p11_close(self) -> None:
        self.p11.close(); self._log(self.p11_out, "session closed")

    def _p11_rng(self) -> None:
        if not self._p11_need_session():
            return
        try:
            out = self.p11.generate_random(self.p11_rng_n.value())
            self._log(self.p11_out, f"C_GenerateRandom({len(out)}): {out.hex()}")
        except Exception as e:  # noqa: BLE001
            self._log(self.p11_out, f"RNG error: {e}")

    def _p11_digest(self) -> None:
        if not self._p11_need_session():
            return
        try:
            out = self.p11.digest(self.p11_mech.currentText(),
                                  self.p11_in.text().encode())
            self._log(self.p11_out,
                      f"C_Digest {self.p11_mech.currentText()}: {out.hex()}")
        except Exception as e:  # noqa: BLE001
            self._log(self.p11_out, f"digest error: {e}")

    def _p11_gcm(self) -> None:
        if not self._p11_need_session():
            return
        try:
            ok, detail = self.p11.aes_gcm_roundtrip(b"authenticated payload")
            self._log(self.p11_out,
                      f"AES-GCM: {detail} [{'PASS' if ok else 'FAIL'}]")
        except Exception as e:  # noqa: BLE001
            self._log(self.p11_out, f"AES-GCM error: {e}")

    def _p11_tokeninfo(self) -> None:
        try:
            ti = self.p11.token_info(self.p11_slot.value())
            self._log(self.p11_out, f"C_GetTokenInfo: {ti}")
        except Exception as e:  # noqa: BLE001
            self._log(self.p11_out, f"token info error: {e}")

    # -- Statistics tab ---------------------------------------------------
    def _build_stats_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)
        h = QHBoxLayout()
        b_ref = QPushButton("Refresh"); b_ref.clicked.connect(self._refresh_stats)
        b_clr = QPushButton("Clear"); b_clr.clicked.connect(self._clear_stats)
        h.addWidget(b_ref); h.addWidget(b_clr); h.addStretch(1)
        v.addLayout(h)
        self.stats_tbl = QTableWidget(0, 7)
        self.stats_tbl.setHorizontalHeaderLabels(
            ["opcode", "count", "ok", "fail", "bytes_in", "bytes_out", "avg_ms"])
        self.stats_tbl.horizontalHeader().setStretchLastSection(True)
        v.addWidget(self.stats_tbl, 1)
        return w

    def _refresh_stats(self) -> None:
        rows = sorted(self.stats.per_op.items())
        self.stats_tbl.setRowCount(len(rows))
        for r, (op, s) in enumerate(rows):
            avg = s.total_ms / s.count if s.count else 0.0
            vals = [ci.opcode_name(op), str(s.count), str(s.ok), str(s.fail),
                    str(s.bytes_in), str(s.bytes_out), f"{avg:.3f}"]
            for c, txt in enumerate(vals):
                self.stats_tbl.setItem(r, c, QTableWidgetItem(txt))

    def _clear_stats(self) -> None:
        self.stats.clear(); self._refresh_stats()

    # -- utilities --------------------------------------------------------
    def _log(self, widget: QPlainTextEdit, text: str) -> None:
        widget.appendPlainText(text)

    def closeEvent(self, event):  # noqa: N802
        self.disconnect_link()
        try:
            self.p11.close()
        except Exception:  # noqa: BLE001
            pass
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    win = AppGui()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
