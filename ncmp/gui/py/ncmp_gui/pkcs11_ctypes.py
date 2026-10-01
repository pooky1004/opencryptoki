"""Mode-2 PKCS#11 link: dlopen libpkcs11_ncmp.so and dlsym C_* directly.

This is the App's "second way" of using libpkcs11_ncmp.so (docs/
dual-mode-provider.md): the app loads the .so itself and resolves the standard
PKCS#11 entry points by symbol, with NO libopencryptoki and NO PyKCS11 - just
ctypes (dlopen) + getattr on the CDLL (dlsym).

Only the subset the GUI exercises is bound (init, slots, token info, session,
login, RNG, digest, AES-GCM round-trip). ``resolve(names)`` reports which
version-specific entry points (C_GetFunctionList / C_GetInterface(List) / C_*)
are present via dlsym, to demonstrate mode-2 discovery.

Runtime needs a built libpkcs11_ncmp.so and a running ncmpd; this module itself
imports with no dependencies.
"""
from __future__ import annotations

import ctypes as C
from typing import Dict, List, Tuple

# --- CK scalar aliases ------------------------------------------------------
CK_RV = C.c_ulong
CK_ULONG = C.c_ulong
CK_BYTE = C.c_ubyte
CK_BBOOL = C.c_ubyte

# --- constants (subset) -----------------------------------------------------
CKF_SERIAL_SESSION = 0x04
CKF_RW_SESSION = 0x02
CKU_SO = 0
CKU_USER = 1
CKO_SECRET_KEY = 0x04
CKK_AES = 0x1F
CKA_CLASS = 0x0000
CKA_TOKEN = 0x0001
CKA_KEY_TYPE = 0x0100
CKA_VALUE = 0x0011
CKA_VALUE_LEN = 0x0161
CKA_ENCRYPT = 0x0104
CKA_DECRYPT = 0x0105
CKM_AES_KEY_GEN = 0x1080
CKM_AES_GCM = 0x1087
CKR_OK = 0

_DIGEST_CKM = {
    "SHA-256": 0x250, "SHA-512": 0x270,
    "SHA3-224": 0x2B5, "SHA3-256": 0x2B0, "SHA3-384": 0x2C0, "SHA3-512": 0x2D0,
}

# All version-specific entry points we probe for with dlsym (mode-2 discovery).
VERSIONED_ENTRIES = [
    "C_GetFunctionList",      # 2.40
    "C_GetInterfaceList",     # 3.0
    "C_GetInterface",         # 3.0 / 3.2
]


# --- CK structs (ctypes) ----------------------------------------------------
class CK_VERSION(C.Structure):
    _fields_ = [("major", CK_BYTE), ("minor", CK_BYTE)]


class CK_MECHANISM(C.Structure):
    _fields_ = [("mechanism", CK_ULONG), ("pParameter", C.c_void_p),
                ("ulParameterLen", CK_ULONG)]


class CK_ATTRIBUTE(C.Structure):
    _fields_ = [("type", CK_ULONG), ("pValue", C.c_void_p),
                ("ulValueLen", CK_ULONG)]


class CK_GCM_PARAMS(C.Structure):
    _fields_ = [("pIv", C.c_void_p), ("ulIvLen", CK_ULONG),
                ("ulIvBits", CK_ULONG), ("pAAD", C.c_void_p),
                ("ulAADLen", CK_ULONG), ("ulTagBits", CK_ULONG)]


class CK_TOKEN_INFO(C.Structure):
    _fields_ = [
        ("label", CK_BYTE * 32), ("manufacturerID", CK_BYTE * 32),
        ("model", CK_BYTE * 16), ("serialNumber", CK_BYTE * 16),
        ("flags", CK_ULONG),
        ("ulMaxSessionCount", CK_ULONG), ("ulSessionCount", CK_ULONG),
        ("ulMaxRwSessionCount", CK_ULONG), ("ulRwSessionCount", CK_ULONG),
        ("ulMaxPinLen", CK_ULONG), ("ulMinPinLen", CK_ULONG),
        ("ulTotalPublicMemory", CK_ULONG), ("ulFreePublicMemory", CK_ULONG),
        ("ulTotalPrivateMemory", CK_ULONG), ("ulFreePrivateMemory", CK_ULONG),
        ("hardwareVersion", CK_VERSION), ("firmwareVersion", CK_VERSION),
        ("utcTime", CK_BYTE * 16),
    ]


class Pkcs11CtypesError(Exception):
    pass


def _ck(rv: int, what: str) -> None:
    if rv != CKR_OK:
        raise Pkcs11CtypesError(f"{what} -> CKR 0x{rv:08X}")


class Pkcs11CtypesLink:
    """dlopen + dlsym driver for libpkcs11_ncmp.so (mode 2)."""

    def __init__(self) -> None:
        self._lib = None
        self._session = None
        self.module_path = ""

    # -- load / discover --------------------------------------------------
    def load(self, module_path: str) -> None:
        if not module_path:
            raise Pkcs11CtypesError("set the module path (libpkcs11_ncmp.so)")
        try:
            self._lib = C.CDLL(module_path)        # dlopen
        except OSError as exc:
            self._lib = None
            raise Pkcs11CtypesError(f"dlopen failed: {exc}") from exc
        self.module_path = module_path

    def _sym(self, name: str):
        """dlsym a C_* entry point and set a permissive prototype."""
        if self._lib is None:
            raise Pkcs11CtypesError("module not loaded")
        try:
            fn = getattr(self._lib, name)          # dlsym
        except AttributeError as exc:
            raise Pkcs11CtypesError(f"symbol not found: {name}") from exc
        fn.restype = CK_RV
        return fn

    def resolve(self, names: List[str]) -> Dict[str, bool]:
        """Report which symbols are resolvable via dlsym (mode-2 discovery)."""
        if self._lib is None:
            raise Pkcs11CtypesError("module not loaded")
        out: Dict[str, bool] = {}
        for n in names:
            try:
                getattr(self._lib, n)
                out[n] = True
            except AttributeError:
                out[n] = False
        return out

    # -- lifecycle --------------------------------------------------------
    def initialize(self) -> None:
        fn = self._sym("C_Initialize")
        fn.argtypes = [C.c_void_p]
        _ck(fn(None), "C_Initialize")

    def finalize(self) -> None:
        if self._lib is None:
            return
        try:
            fn = self._sym("C_Finalize")
            fn.argtypes = [C.c_void_p]
            fn(None)
        except Pkcs11CtypesError:
            pass

    def slots(self) -> List[int]:
        fn = self._sym("C_GetSlotList")
        fn.argtypes = [CK_BBOOL, C.c_void_p, C.POINTER(CK_ULONG)]
        n = CK_ULONG(0)
        _ck(fn(1, None, C.byref(n)), "C_GetSlotList(count)")
        if n.value == 0:
            return []
        arr = (CK_ULONG * n.value)()
        _ck(fn(1, arr, C.byref(n)), "C_GetSlotList")
        return [arr[i] for i in range(n.value)]

    def token_info(self, slot: int) -> dict:
        fn = self._sym("C_GetTokenInfo")
        fn.argtypes = [CK_ULONG, C.POINTER(CK_TOKEN_INFO)]
        ti = CK_TOKEN_INFO()
        _ck(fn(slot, C.byref(ti)), "C_GetTokenInfo")

        def s(a):
            return bytes(a).split(b"\x00")[0].rstrip().decode("latin1").strip()
        return {"label": s(ti.label), "manufacturer": s(ti.manufacturerID),
                "model": s(ti.model), "serial": s(ti.serialNumber)}

    def open(self, slot: int, rw: bool = True) -> None:
        fn = self._sym("C_OpenSession")
        fn.argtypes = [CK_ULONG, CK_ULONG, C.c_void_p, C.c_void_p,
                       C.POINTER(CK_ULONG)]
        h = CK_ULONG(0)
        flags = CKF_SERIAL_SESSION | (CKF_RW_SESSION if rw else 0)
        _ck(fn(slot, flags, None, None, C.byref(h)), "C_OpenSession")
        self._session = h.value

    def login(self, pin: str) -> None:
        self._require()
        fn = self._sym("C_Login")
        fn.argtypes = [CK_ULONG, CK_ULONG, C.c_char_p, CK_ULONG]
        pb = pin.encode()
        _ck(fn(self._session, CKU_USER, pb, len(pb)), "C_Login")

    def logout(self) -> None:
        if self._session is None:
            return
        try:
            fn = self._sym("C_Logout")
            fn.argtypes = [CK_ULONG]
            fn(self._session)
        except Pkcs11CtypesError:
            pass

    def close(self) -> None:
        if self._session is not None and self._lib is not None:
            try:
                fn = self._sym("C_CloseSession")
                fn.argtypes = [CK_ULONG]
                fn(self._session)
            except Pkcs11CtypesError:
                pass
        self._session = None

    @property
    def connected(self) -> bool:
        return self._session is not None

    def _require(self) -> None:
        if self._session is None:
            raise Pkcs11CtypesError("no open session")

    # -- operations -------------------------------------------------------
    def generate_random(self, nbytes: int) -> bytes:
        self._require()
        fn = self._sym("C_GenerateRandom")
        fn.argtypes = [CK_ULONG, C.POINTER(CK_BYTE), CK_ULONG]
        buf = (CK_BYTE * nbytes)()
        _ck(fn(self._session, buf, nbytes), "C_GenerateRandom")
        return bytes(buf)

    def digest(self, mech_name: str, data: bytes) -> bytes:
        self._require()
        ckm = _DIGEST_CKM.get(mech_name)
        if ckm is None:
            raise Pkcs11CtypesError(f"unsupported digest: {mech_name}")
        init = self._sym("C_DigestInit")
        init.argtypes = [CK_ULONG, C.POINTER(CK_MECHANISM)]
        m = CK_MECHANISM(ckm, None, 0)
        _ck(init(self._session, C.byref(m)), "C_DigestInit")
        dig = self._sym("C_Digest")
        dig.argtypes = [CK_ULONG, C.POINTER(CK_BYTE), CK_ULONG,
                        C.POINTER(CK_BYTE), C.POINTER(CK_ULONG)]
        din = (CK_BYTE * len(data)).from_buffer_copy(data) if data else None
        outlen = CK_ULONG(0)
        _ck(dig(self._session, din, len(data), None, C.byref(outlen)),
            "C_Digest(len)")
        out = (CK_BYTE * outlen.value)()
        _ck(dig(self._session, din, len(data), out, C.byref(outlen)),
            "C_Digest")
        return bytes(out)[:outlen.value]

    def aes_gcm_roundtrip(self, data: bytes) -> Tuple[bool, str]:
        self._require()
        # C_GenerateKey(CKM_AES_KEY_GEN) with a 16-byte AES key.
        gk = self._sym("C_GenerateKey")
        gk.argtypes = [CK_ULONG, C.POINTER(CK_MECHANISM),
                       C.POINTER(CK_ATTRIBUTE), CK_ULONG, C.POINTER(CK_ULONG)]
        cls = CK_ULONG(CKO_SECRET_KEY); kt = CK_ULONG(CKK_AES)
        vlen = CK_ULONG(16); yes = CK_BBOOL(1); no = CK_BBOOL(0)
        tmpl = (CK_ATTRIBUTE * 6)(
            CK_ATTRIBUTE(CKA_CLASS, C.cast(C.byref(cls), C.c_void_p), 8),
            CK_ATTRIBUTE(CKA_KEY_TYPE, C.cast(C.byref(kt), C.c_void_p), 8),
            CK_ATTRIBUTE(CKA_VALUE_LEN, C.cast(C.byref(vlen), C.c_void_p), 8),
            CK_ATTRIBUTE(CKA_ENCRYPT, C.cast(C.byref(yes), C.c_void_p), 1),
            CK_ATTRIBUTE(CKA_DECRYPT, C.cast(C.byref(yes), C.c_void_p), 1),
            CK_ATTRIBUTE(CKA_TOKEN, C.cast(C.byref(no), C.c_void_p), 1),
        )
        mkg = CK_MECHANISM(CKM_AES_KEY_GEN, None, 0)
        hkey = CK_ULONG(0)
        _ck(gk(self._session, C.byref(mkg), tmpl, 6, C.byref(hkey)),
            "C_GenerateKey")
        # GCM params.
        iv = (CK_BYTE * 12)(*range(12))
        gcm = CK_GCM_PARAMS(C.cast(iv, C.c_void_p), 12, 96, None, 0, 128)
        mg = CK_MECHANISM(CKM_AES_GCM, C.cast(C.byref(gcm), C.c_void_p),
                          C.sizeof(gcm))
        ei = self._sym("C_EncryptInit")
        ei.argtypes = [CK_ULONG, C.POINTER(CK_MECHANISM), CK_ULONG]
        _ck(ei(self._session, C.byref(mg), hkey.value), "C_EncryptInit")
        enc = self._sym("C_Encrypt")
        enc.argtypes = [CK_ULONG, C.POINTER(CK_BYTE), CK_ULONG,
                        C.POINTER(CK_BYTE), C.POINTER(CK_ULONG)]
        din = (CK_BYTE * len(data)).from_buffer_copy(data)
        clen = CK_ULONG(0)
        _ck(enc(self._session, din, len(data), None, C.byref(clen)),
            "C_Encrypt(len)")
        ct = (CK_BYTE * clen.value)()
        _ck(enc(self._session, din, len(data), ct, C.byref(clen)), "C_Encrypt")
        # Decrypt back (fresh GCM params struct).
        gcm2 = CK_GCM_PARAMS(C.cast(iv, C.c_void_p), 12, 96, None, 0, 128)
        mg2 = CK_MECHANISM(CKM_AES_GCM, C.cast(C.byref(gcm2), C.c_void_p),
                           C.sizeof(gcm2))
        di = self._sym("C_DecryptInit")
        di.argtypes = [CK_ULONG, C.POINTER(CK_MECHANISM), CK_ULONG]
        _ck(di(self._session, C.byref(mg2), hkey.value), "C_DecryptInit")
        dec = self._sym("C_Decrypt")
        dec.argtypes = [CK_ULONG, C.POINTER(CK_BYTE), CK_ULONG,
                        C.POINTER(CK_BYTE), C.POINTER(CK_ULONG)]
        plen = CK_ULONG(0)
        _ck(dec(self._session, ct, clen.value, None, C.byref(plen)),
            "C_Decrypt(len)")
        pt = (CK_BYTE * plen.value)()
        _ck(dec(self._session, ct, clen.value, pt, C.byref(plen)), "C_Decrypt")
        ok = bytes(pt)[:plen.value] == data
        return ok, f"ct={clen.value}B, decrypt {'OK' if ok else 'MISMATCH'}"
