#!/usr/bin/env python3
"""End-to-end smoke test: drive a running mock_server over the socket links.

Usage:
    # terminal 1
    ./mock_server --slots 2 --data-port 7010 --ctrl-port 7000
    # terminal 2
    python3 smoke_test.py

Exercises the data link (RNG, digest one-shot + multipart, AES-CTR round-trip,
vendor ping/selftest/fw) and the control channel (identity get/set, stats,
debug, link up/down), asserting outputs against the SW mock replicas.
"""
from __future__ import annotations

import sys

from ncmp_gui import ci, link, swcrypto, wire

DATA_PORT = 7010
CTRL_PORT = 7000
FAILURES = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global FAILURES
    status = "PASS" if cond else "FAIL"
    if not cond:
        FAILURES += 1
    print(f"[{status}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def main() -> int:
    # --- control channel ---------------------------------------------------
    ctrl = link.ControlClient(port=CTRL_PORT)
    ctrl.connect()
    slots = ctrl.list_slots()
    check("control: list slots", len(slots) >= 1, str(slots))

    ident = ctrl.get_identity(0)
    check("control: get identity", ident.get("ok") == 1 and "label" in ident)

    ctrl.set_identity(0, label="MYTOKEN", serial="SN99", fw_major=2)
    ident2 = ctrl.get_identity(0)
    check("control: set/get identity", ident2.get("label") == "MYTOKEN"
          and ident2.get("fw_major") == 2, str(ident2))

    # --- data link ---------------------------------------------------------
    dl = link.DataLink(port=DATA_PORT)
    dl.connect()

    # RNG
    r = dl.command(ci.rng(64))
    check("data: RNG bytes match mock replica",
          r.param(0) == swcrypto.mock_rng(64))

    # Vendor ping / selftest / fw
    p = dl.command(ci.vd_ping())
    check("data: VD_PING returns epoch u32", len(p.param(0)) == 4)
    st = dl.command(ci.vd_selftest())
    check("data: VD_SELFTEST ok", wire.rd_u32(st.param(0)) == 0)
    fw = dl.command(ci.vd_fw_info())
    check("data: VD_FW_INFO 16 bytes", len(fw.param(0)) == 16)

    # One-shot digest
    data = b"The quick brown fox" * 100
    d = dl.command(ci.digest(ci.MECH_SHA256, data))
    check("data: DIGEST one-shot matches replica",
          d.param(0) == swcrypto.mock_digest(ci.MECH_SHA256, data))

    # Multipart digest (INIT/UPDATE/FINAL) over the same data in chunks
    init = dl.command(ci.digest_init(ci.MECH_SHA256))
    ctx_id = wire.rd_u32(init.param(0))
    for off in range(0, len(data), 500):
        dl.command(ci.digest_update(ctx_id, data[off : off + 500]))
    fin = dl.command(ci.digest_final(ctx_id))
    check("data: DIGEST multipart == one-shot == replica",
          fin.param(0) == swcrypto.mock_digest(ci.MECH_SHA256, data))

    # AES-CTR round-trip + SW replica
    key = bytes(range(32))
    iv = bytes(range(16))
    pt = b"stream me" * 1000
    enc = dl.command(ci.aes_ctr(key, iv, pt, encrypt=True))
    ct = enc.param(0)
    check("data: AES-CTR ciphertext matches replica",
          ct == swcrypto.mock_aes_stream(key, iv, pt))
    dec = dl.command(ci.aes_ctr(key, iv, ct, encrypt=False))
    check("data: AES-CTR round-trips to plaintext", dec.param(0) == pt)

    # Fail-injection hook
    f = dl.command(ci.rng(8), fail_bit=True)
    check("data: fail-bit forces CKR_FUNCTION_FAILED",
          f.ack == ci.CKR_FUNCTION_FAILED, ci.ckr_name(f.ack))

    # Stats + debug reflect the traffic
    stt = ctrl.stats(0)
    check("control: stats counted requests",
          stt.get("requests", 0) >= 8, str(stt))
    ev = ctrl.debug(0)
    check("control: debug ring populated", len(ev) >= 1)

    # Link down forces the data link closed
    ctrl.set_link(0, up=False)
    try:
        dl.command(ci.rng(4))
        closed = False
    except Exception:
        closed = True
    check("control: link-down drops the data link", closed)
    dl.close()
    ctrl.set_link(0, up=True)

    ctrl.close()
    print()
    if FAILURES:
        print(f"{FAILURES} check(s) FAILED")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
