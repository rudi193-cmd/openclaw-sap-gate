"""sap-gate CLI — verify and initialize SAFE app entries."""

import json
import sys
from pathlib import Path


def _get_safe_root() -> Path:
    import os
    return Path(os.environ.get("SAP_SAFE_ROOT", Path.home() / ".sap" / "Applications"))


def cmd_verify(app_id: str) -> int:
    from .gate import authorized
    if authorized(app_id):
        print(f"✓ {app_id}: authorized")
        return 0
    else:
        print(f"✗ {app_id}: denied (check ~/.sap/log/gaps.jsonl for reason)")
        return 1


def cmd_init(app_id: str) -> int:
    import re
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_\-]*$', app_id):
        print(f"Error: invalid app_id '{app_id}'", file=sys.stderr)
        return 1

    safe_root = _get_safe_root()
    app_dir = safe_root / app_id
    manifest_path = app_dir / "safe-app-manifest.json"

    if manifest_path.exists():
        print(f"Already exists: {manifest_path}")
        return 0

    app_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "app_id": app_id,
        "name": app_id,
        "version": "1.0.0",
        "safe_version": ">=1.0.0",
        "description": f"SAP-authorized application: {app_id}",
        "author": "",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Created: {manifest_path}")
    print(f"\nNext steps:")
    print(f"  1. Edit {manifest_path}")
    print(f"  2. gpg --detach-sign --armor {manifest_path}")
    print(f"  3. mv {manifest_path}.asc {manifest_path}.sig")
    print(f"  4. sap-gate verify {app_id}")
    return 0


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: sap-gate verify <app_id>")
        print("       sap-gate init <app_id>")
        sys.exit(1)

    command = sys.argv[1]
    app_id = sys.argv[2]

    if command == "verify":
        sys.exit(cmd_verify(app_id))
    elif command == "init":
        sys.exit(cmd_init(app_id))
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)
