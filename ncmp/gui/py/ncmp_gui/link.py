"""Socket clients for the mock HSM server (and, later, a real-HSM bridge).

- DataLink   : carries raw NCMP wire frames (the emulated USB "host link").
- ControlClient : newline-delimited JSON to inspect/configure the mock server.
"""
from __future__ import annotations

import json
import socket
import struct
import threading
from typing import Any, Dict, List, Optional, Tuple

from . import wire


class LinkError(Exception):
    """Raised on connection/protocol failures."""


class DataLink:
    """A frame-oriented link to one slot's data port (mock or real bridge)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 7010,
                 timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._seq = 0
        self._lock = threading.Lock()

    # -- connection -------------------------------------------------------
    def connect(self) -> None:
        s = socket.create_connection((self.host, self.port), self.timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock = s

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def __enter__(self) -> "DataLink":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- low-level frame I/O ---------------------------------------------
    def _recv_exact(self, n: int) -> bytes:
        assert self._sock is not None
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise LinkError("link closed by peer")
            buf.extend(chunk)
        return bytes(buf)

    def send_frame(self, frame: bytes) -> None:
        if self._sock is None:
            raise LinkError("not connected")
        self._sock.sendall(frame)

    def recv_frame(self) -> bytes:
        prefix = self._recv_exact(wire.FRAME_PREFIX_SIZE)
        frame_len = struct.unpack("<I", prefix)[0]
        rest = self._recv_exact(frame_len)
        return prefix + rest

    # -- command/response -------------------------------------------------
    def command(self, req: Tuple[int, List[bytes]], *, session_id: int = 0,
                fail_bit: bool = False) -> wire.Message:
        """Send one CI request tuple and return the decoded response."""
        command_id, params = req
        if fail_bit:
            command_id |= 0x80000000
        with self._lock:
            self._seq = (self._seq + 1) & 0xFFFFFFFF
            frame = wire.encode(command_id, params, session_id=session_id,
                                sequence_id=self._seq)
            self.send_frame(frame)
            resp = self.recv_frame()
        return wire.decode(resp)


class ControlClient:
    """JSON control channel to the mock server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 7000,
                 timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._buf = b""
        self._lock = threading.Lock()

    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port),
                                              self.timeout)

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def _rpc(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        if self._sock is None:
            raise LinkError("control channel not connected")
        line = (json.dumps(obj) + "\n").encode()
        with self._lock:
            self._sock.sendall(line)
            while b"\n" not in self._buf:
                chunk = self._sock.recv(65536)
                if not chunk:
                    raise LinkError("control channel closed")
                self._buf += chunk
            nl = self._buf.index(b"\n")
            resp = self._buf[:nl]
            self._buf = self._buf[nl + 1 :]
        return json.loads(resp.decode())

    # -- typed control operations ----------------------------------------
    def list_slots(self) -> List[Dict[str, Any]]:
        return self._rpc({"op": "list"}).get("slots", [])

    def get_identity(self, slot: int) -> Dict[str, Any]:
        return self._rpc({"op": "get", "slot": slot})

    def set_identity(self, slot: int, **fields: Any) -> Dict[str, Any]:
        req = {"op": "set", "slot": slot}
        req.update(fields)
        return self._rpc(req)

    def stats(self, slot: int) -> Dict[str, Any]:
        return self._rpc({"op": "stats", "slot": slot})

    def debug(self, slot: int) -> List[Dict[str, Any]]:
        return self._rpc({"op": "debug", "slot": slot}).get("events", [])

    def set_link(self, slot: int, up: bool) -> Dict[str, Any]:
        return self._rpc({"op": "link", "slot": slot, "up": 1 if up else 0})

    def reset(self, slot: int) -> Dict[str, Any]:
        return self._rpc({"op": "reset", "slot": slot})
