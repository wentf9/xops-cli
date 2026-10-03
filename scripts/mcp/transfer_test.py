#!/usr/bin/env python3
"""Compatibility entry point for the shared MCP transfer client."""
from pathlib import Path

_shared = Path(__file__).resolve().parents[2] / "core" / "mcp" / "transferclient" / "transfer_test.py"
exec(compile(_shared.read_bytes(), str(_shared), "exec"), globals())
