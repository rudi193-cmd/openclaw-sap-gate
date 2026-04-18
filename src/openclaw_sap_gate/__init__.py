"""
openclaw-sap-gate — SAFE Authorization Protocol for MCP tool calls.

SAP/1.0: four-step authorization chain using filesystem manifests and GPG signatures.

Usage:
    from openclaw_sap_gate import authorized, require_authorized

    if not authorized("my-app"):
        raise PermissionError("not authorized")

    # or raise automatically:
    require_authorized("my-app")
"""

from .gate import authorized, require_authorized, get_manifest, list_authorized

__version__ = "1.0.0"
__all__ = ["authorized", "require_authorized", "get_manifest", "list_authorized"]
