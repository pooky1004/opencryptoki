"""NCMP GUI toolkit: wire codec, socket links, CI builders, SW references.

Used by the mock HSM GUI (mock_gui.py) and the test App GUI (app_gui.py), and
importable on its own for headless scripting/scenarios.
"""
from . import ci, link, swcrypto, wire  # noqa: F401

__all__ = ["wire", "ci", "link", "swcrypto"]
