# openclaw-sap-gate

Python reference implementation of [SAP/1.0](https://github.com/rudi193-cmd/sap-rfc) — SAFE Authorization Protocol for MCP tool calls.

```bash
pip install openclaw-sap-gate
```

## Usage

```python
from openclaw_sap_gate import authorized, require_authorized

# Check (returns bool)
if not authorized("my-app"):
    return "denied"

# Assert (raises PermissionError on failure)
require_authorized("my-app")
```

## CLI

```bash
# Verify an app_id passes the full auth chain
sap-gate verify my-app

# Scaffold a new SAFE folder + manifest template
sap-gate init my-app
```

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `SAP_SAFE_ROOT` | `~/.sap/Applications` | Root directory for SAFE folders |
| `SAP_PGP_FINGERPRINT` | *(empty — any valid sig passes)* | Pinned primary key fingerprint |
| `SAP_LOG_DIR` | `~/.sap/log` | Directory for gaps.jsonl and grants.jsonl |

## How It Works

Authorization requires all four steps:

1. `SAP_SAFE_ROOT/<app_id>/` exists
2. `safe-app-manifest.json` present and readable
3. `safe-app-manifest.json.sig` present
4. `gpg --verify` passes, signer fingerprint matches `SAP_PGP_FINGERPRINT`

Revoke by deleting the folder or `.sig` file.

## OpenClaw Enforcement Skill

→ [rudi193-cmd/openclaw-skill-sap](https://github.com/rudi193-cmd/openclaw-skill-sap)

## Protocol Spec

→ [SAP/1.0 RFC](https://github.com/rudi193-cmd/sap-rfc)

## License

MIT — Sean Campbell 2026
