#!/usr/bin/env python3
"""Part-4 example: drive the REAL stack via PKCS#11 (libopencryptoki).

    App (this script)
      → libopencryptoki (C_*)              PKCS11_MODULE=/.../libopencryptoki.so
        → libpkcs11_ncmp.so (STDLL SC_*)
          → token_specific (ncmp_specific.c)
            → ncmpd  ──(USB real  |  socket→mock_server)──> token

Unlike app_gui.py's direct wire-frame link, this exercises the production
PKCS#11 path end to end. It therefore needs a BUILT and RUNNING stack and
cannot run in a bare checkout — see the recipe in
docs/app-stdll-path-design.md. This script is an illustrative, dependency-light
client (PyKCS11), not part of the automated suite.

Run (in your build environment):
    pip install PyKCS11
    export PKCS11_MODULE=/usr/local/lib/opencryptoki/libopencryptoki.so
    # ncmpd must be up (e.g. built -DENABLE_SOCKET_TOKEN=ON against mock_server,
    # or the USB backend with real hardware), and the ncmp slot configured.
    python3 pkcs11_example.py --slot 0 --pin 1234
"""
from __future__ import annotations

import argparse
import os
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description="NCMP PKCS#11 (real stack) example")
    ap.add_argument("--module", default=os.environ.get("PKCS11_MODULE", ""),
                    help="path to libopencryptoki.so (or $PKCS11_MODULE)")
    ap.add_argument("--slot", type=int, default=0, help="PKCS#11 slot index")
    ap.add_argument("--pin", default="1234", help="user PIN")
    args = ap.parse_args()

    if not args.module:
        print("error: set --module or $PKCS11_MODULE to libopencryptoki.so",
              file=sys.stderr)
        return 2
    try:
        import PyKCS11  # type: ignore
    except Exception:
        print("error: PyKCS11 not installed. `pip install PyKCS11`",
              file=sys.stderr)
        return 2

    lib = PyKCS11.PyKCS11Lib()
    lib.load(args.module)                        # C_Initialize + C_GetFunctionList
    slots = lib.getSlotList(tokenPresent=True)
    if not slots:
        print("no token-present slots", file=sys.stderr)
        return 1
    slot = slots[args.slot] if args.slot < len(slots) else slots[0]

    info = lib.getTokenInfo(slot)
    print(f"token: label='{info.label.strip()}' "
          f"manufacturer='{info.manufacturerID.strip()}' "
          f"model='{info.model.strip()}' serial='{info.serialNumber.strip()}'")

    session = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    try:
        session.login(args.pin)                  # C_Login (CKU_USER)

        # RNG via C_GenerateRandom (NCMP_CMD_RNG under the hood).
        rnd = session.generateRandom(16)
        print("C_GenerateRandom(16):", bytes(rnd).hex())

        # SHA-256 digest via C_DigestInit/C_Digest.
        mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256, None)
        digest = session.digest(b"The quick brown fox", mech)
        print("C_Digest SHA-256:", bytes(digest).hex())

        # AES-GCM: generate a key, then C_Encrypt/C_Decrypt round-trip.
        keytmpl = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_VALUE_LEN, 16),
            (PyKCS11.CKA_ENCRYPT, True), (PyKCS11.CKA_DECRYPT, True),
            (PyKCS11.CKA_TOKEN, False),
        ]
        key = session.generateKey(keytmpl,
                                  PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_GEN, None))
        iv = bytes(range(12))
        gcm = PyKCS11.AES_GCM_Mechanism(iv, b"", 128) \
            if hasattr(PyKCS11, "AES_GCM_Mechanism") else None
        if gcm is not None:
            ct = session.encrypt(key, b"authenticated payload", gcm)
            pt = session.decrypt(key, bytes(ct), gcm)
            print("AES-GCM round-trip:",
                  "OK" if bytes(pt) == b"authenticated payload" else "FAIL")
        else:
            print("AES-GCM: PyKCS11 build lacks AES_GCM_Mechanism; skipped")

        session.logout()
    finally:
        session.closeSession()
    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
