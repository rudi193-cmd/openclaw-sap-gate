---
b17: OSPG1
title: Security Audit — openclaw-sap-gate
date: 2026-05-06
auditor: Hanuman (Claude Code, Sonnet 4.6)
status: open
---

# Security Audit — openclaw-sap-gate

Part of Level 2 full-fleet security audit. openclaw-sap-gate — SAP/1.0 reference implementation. Four-step authorization chain: SAFE folder present, manifest present, .sig present, gpg signature verified against pinned fingerprint.

## Rubric Results

| # | Check | Status | Notes |
|---|---|---|---|
| R1 | SQL injection | N/A | No database queries |
| R2 | Shell injection | ✅ PASS | subprocess.run(["gpg", ...]) with list args; app_id validated by regex before path construction |
| R3 | Path traversal | ✅ PASS | `_APP_ID_RE = r'^[a-zA-Z0-9][a-zA-Z0-9_\-]*$'` blocks `..` and `/`; case-insensitive dir scan bounded to SAFE_ROOT |
| R4 | Hardcoded credentials | ✅ PASS | All paths and fingerprint via env vars (SAP_SAFE_ROOT, SAP_LOG_DIR, SAP_PGP_FINGERPRINT) |
| R5 | CORS wildcard | N/A | Not an HTTP server |
| R6 | XSS | N/A | No HTML rendering |
| R7 | Unsigned code execution | ✅ PASS | No eval(), exec(), or dynamic imports; this library IS the signature verification layer |
| R8 | Missing auth on APIs | N/A | This library is the auth gate |
| R9 | Bare except swallowing errors | ⚠️ WARN | `get_manifest()` catches bare `except Exception: return None` — hides manifest read/parse errors |
| R10 | Predictable temp paths | ✅ PASS | No temp files created |
| R11 | Race conditions | ✅ PASS | Single-threaded usage; log writes are append-only; no shared mutable state |
| R12 | safe_integration.py status() | N/A | This package IS the integration library |
| R13 | Entry point importable | ✅ PASS | `sap-gate` CLI entry point wired in pyproject.toml; imports clean |
| R14 | requirements.txt pinned | ✅ PASS | No external runtime dependencies; stdlib only (subprocess, pathlib, json, re, logging) |
| R15 | No hardcoded dev paths | ✅ PASS | All paths derived from env vars or `Path.home()` |

## Findings

### P1: S-FP-01 — Fingerprint pin bypassed when SAP_PGP_FINGERPRINT not set

**Severity:** P1
**Status:** Open
**File:** `src/openclaw_sap_gate/gate.py`, line ~85

```python
if _EXPECTED_FP and signer_fp != _EXPECTED_FP:
    return False, f"signature by unexpected key: ..."
```

`_EXPECTED_FP = os.environ.get("SAP_PGP_FINGERPRINT", "").upper().replace(" ", "")`

When `SAP_PGP_FINGERPRINT` is not set, `_EXPECTED_FP` is empty string, the `and` short-circuits, and the fingerprint comparison is **never performed**. Any valid GPG signature from any key passes. The fingerprint pin is the critical security control in the SAP/1.0 chain — making it conditional on an env var silently degrades the gate from "trust this specific key" to "trust any key."

**Recommended fix:**
```python
if not _EXPECTED_FP:
    return False, "SAP_PGP_FINGERPRINT not configured — gate cannot verify signer identity"
if signer_fp != _EXPECTED_FP:
    return False, f"signature by unexpected key: {signer_fp[:16]}... (expected: {_EXPECTED_FP[:16]}...)"
```

Or: fail-closed by default, allow opt-out with an explicit `SAP_FP_OPTIONAL=1` env var for dev environments.

---

### P2: S-EXC-01 — Silent exception swallowing in get_manifest()

**Severity:** P2
**Status:** Open
**File:** `src/openclaw_sap_gate/gate.py`, line ~130

```python
try:
    return json.loads(manifest_path.read_text(encoding="utf-8"))
except Exception:
    return None
```

Swallows all errors silently. A corrupt manifest, encoding error, or race condition on the filesystem returns `None` with no log entry. Since `authorized()` already ran to get here, a silent None could cause silent failures in callers that don't check the return value.

**Recommended fix:** Log the exception before returning None, or use `logger.warning(...)`.

---

## Strengths

- **app_id validation is correct.** Regex blocks all path traversal characters before any filesystem operation.
- **subprocess.run with list args.** No shell=True; gpg is invoked directly with validated path arguments.
- **VALIDSIG parsing is explicit.** Extracts fingerprint from structured GPG status output (`--status-fd=1`), not stderr parsing.
- **Deny-by-default.** Every failure path returns False and logs to gaps.jsonl. No silent passes except P1 above.
- **gpg timeout.** 5-second timeout prevents hanging on slow or broken gpg installations.
