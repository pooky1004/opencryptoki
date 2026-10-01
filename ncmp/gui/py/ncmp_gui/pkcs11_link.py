"""PKCS#11 link: drive the REAL stack via libopencryptoki (PyKCS11).

This is the Part-4 "PKCS#11 mode": instead of sending wire frames to a frame
server, the App loads libopencryptoki (C_*) which dlopens the NCMP STDLL, which
proxies to ncmpd -> USB(real) / socket(mock). See docs/app-stdll-path-design.md.

Only operations expressible through the standard PKCS#11 C_* surface are
available here (RNG, digest, AES-GCM, token info); vendor datapath, session CI,
fail-injection and raw opcodes are frame-link-only (see that doc §6).

PyKCS11 is imported lazily so this module (and the App GUI) import fine without
it; ``Pkcs11Link.available()`` reports whether it can be used.
"""
from __future__ import annotations

import os
from typing import Any, List, Optional, Tuple


class Pkcs11Error(Exception):
    """PKCS#11 adapter error (missing binding, load failure, op failure)."""


def available() -> Tuple[bool, str]:
    """Return (ok, detail). ok=False means PyKCS11 is not importable."""
    try:
        import PyKCS11  # noqa: F401
        return True, "PyKCS11 present"
    except Exception as exc:  # noqa: BLE001
        return False, f"PyKCS11 not installed ({exc}); pip install PyKCS11"


# Digest mechanism names -> PyKCS11 CKM attribute names.
_DIGEST_CKM = {
    "SHA-256": "CKM_SHA256",
    "SHA-512": "CKM_SHA512",
    "SHA3-224": "CKM_SHA3_224",
    "SHA3-256": "CKM_SHA3_256",
    "SHA3-384": "CKM_SHA3_384",
    "SHA3-512": "CKM_SHA3_512",
}


class Pkcs11Link:
    """Thin wrapper over a PyKCS11 library + session."""

    def __init__(self) -> None:
        self._pk: Any = None          # PyKCS11 module
        self._lib: Any = None         # PyKCS11Lib
        self._session: Any = None
        self._slot: Optional[int] = None
        self.module_path = ""

    # -- lifecycle --------------------------------------------------------
    def load(self, module_path: str) -> None:
        """C_Initialize via libopencryptoki at module_path."""
        import_ok, detail = available()
        if not import_ok:
            raise Pkcs11Error(detail)
        import PyKCS11
        if not module_path:
            raise Pkcs11Error("set the PKCS#11 module path ($PKCS11_MODULE)")
        if not os.path.exists(module_path):
            raise Pkcs11Error(f"module not found: {module_path}")
        self._pk = PyKCS11
        self._lib = PyKCS11.PyKCS11Lib()
        try:
            self._lib.load(module_path)
        except Exception as exc:  # noqa: BLE001
            self._lib = None
            raise Pkcs11Error(f"C_Initialize/load failed: {exc}") from exc
        self.module_path = module_path

    def slots(self) -> List[dict]:
        """List token-present slots with basic token info."""
        if self._lib is None:
            raise Pkcs11Error("module not loaded")
        out = []
        for s in self._lib.getSlotList(tokenPresent=True):
            ti = self._lib.getTokenInfo(s)
            out.append({"slot": s,
                        "label": ti.label.strip(),
                        "serial": ti.serialNumber.strip(),
                        "model": ti.model.strip()})
        return out

    def open(self, slot: int, rw: bool = True) -> None:
        if self._lib is None:
            raise Pkcs11Error("module not loaded")
        flags = self._pk.CKF_SERIAL_SESSION | (self._pk.CKF_RW_SESSION if rw else 0)
        self._session = self._lib.openSession(slot, flags)
        self._slot = slot

    def login(self, pin: str) -> None:
        self._require_session()
        self._session.login(pin)

    def logout(self) -> None:
        if self._session is not None:
            try:
                self._session.logout()
            except Exception:  # noqa: BLE001
                pass

    def close(self) -> None:
        if self._session is not None:
            try:
                self._session.closeSession()
            except Exception:  # noqa: BLE001
                pass
            self._session = None
        self._slot = None

    @property
    def connected(self) -> bool:
        return self._session is not None

    def _require_session(self) -> None:
        if self._session is None:
            raise Pkcs11Error("no open session")

    # -- operations (C_* expressible only) --------------------------------
    def token_info(self, slot: int) -> dict:
        if self._lib is None:
            raise Pkcs11Error("module not loaded")
        ti = self._lib.getTokenInfo(slot)
        return {"label": ti.label.strip(), "manufacturer": ti.manufacturerID.strip(),
                "model": ti.model.strip(), "serial": ti.serialNumber.strip()}

    def generate_random(self, n: int) -> bytes:
        self._require_session()
        return bytes(self._session.generateRandom(n))

    def digest(self, mech_name: str, data: bytes) -> bytes:
        self._require_session()
        ckm = _DIGEST_CKM.get(mech_name)
        if ckm is None or not hasattr(self._pk, ckm):
            raise Pkcs11Error(f"digest mechanism unavailable: {mech_name}")
        mech = self._pk.Mechanism(getattr(self._pk, ckm), None)
        return bytes(self._session.digest(data, mech))

    def aes_gcm_roundtrip(self, data: bytes) -> Tuple[bool, str]:
        """Generate an AES key, C_Encrypt then C_Decrypt; return (ok, detail)."""
        self._require_session()
        pk = self._pk
        if not hasattr(pk, "AES_GCM_Mechanism"):
            raise Pkcs11Error("this PyKCS11 build lacks AES_GCM_Mechanism")
        tmpl = [
            (pk.CKA_CLASS, pk.CKO_SECRET_KEY),
            (pk.CKA_KEY_TYPE, pk.CKK_AES),
            (pk.CKA_VALUE_LEN, 16),
            (pk.CKA_ENCRYPT, True), (pk.CKA_DECRYPT, True),
            (pk.CKA_TOKEN, False),
        ]
        key = self._session.generateKey(tmpl, pk.Mechanism(pk.CKM_AES_KEY_GEN, None))
        iv = bytes(range(12))
        gcm = pk.AES_GCM_Mechanism(iv, b"", 128)
        ct = bytes(self._session.encrypt(key, data, gcm))
        pt = bytes(self._session.decrypt(key, ct, gcm))
        ok = pt == data
        return ok, f"ct={len(ct)}B, decrypt {'OK' if ok else 'MISMATCH'}"
