"""
SAP Gate — SAFE Authorization Protocol v1.0

Four-step authorization chain:
1. SAFE folder exists at SAFE_ROOT/<app_id>/
2. safe-app-manifest.json present and readable
3. safe-app-manifest.json.sig present
4. gpg --verify confirms signature against pinned fingerprint

Any failure → deny + log. Revocation = delete folder or .sig.

RFC: https://github.com/rudi193-cmd/sap-rfc
"""

import json
import logging
import os
import re as _re
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

SAFE_ROOT = Path(
    os.environ.get("WILLOW_SAFE_ROOT")        # primary: set by willow.sh
    or os.environ.get("SAP_SAFE_ROOT")        # backwards-compat alias
    or Path.home() / ".sap" / "Applications"  # legacy fallback
)
LOG_DIR = Path(os.environ.get("SAP_LOG_DIR", Path.home() / ".sap" / "log"))

# Trust anchor: prefer the SAP-standard env name, fall back to the willow-fleet
# name so a gate sharing an environment with willow-2.0 resolves the same key.
# Fail-closed preserved: if NEITHER is set, _EXPECTED_FP is "" and _verify_pgp
# denies ("SAP_PGP_FINGERPRINT not configured").
_EXPECTED_FP = (
    os.environ.get("SAP_PGP_FINGERPRINT")
    or os.environ.get("WILLOW_PGP_FINGERPRINT")
    or ""
).upper().replace(" ", "")

_APP_ID_RE = _re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_\-]*$')

logger = logging.getLogger("sap.gate")


def _resolve_app_path(root: Path, app_id: str) -> Optional[Path]:
    """Return the app directory under root, matching app_id case-insensitively."""
    exact = root / app_id
    if exact.exists() and exact.is_dir():
        return exact
    try:
        for entry in root.iterdir():
            if entry.is_dir() and entry.name.lower() == app_id.lower():
                return entry
    except (PermissionError, OSError):
        pass
    return None


def _validate_app_id(app_id: str) -> str:
    """Reject app_id values that could escape SAFE_ROOT via path traversal."""
    if not _APP_ID_RE.match(app_id or ""):
        raise ValueError(f"Invalid app_id: {app_id!r} — must match ^[a-zA-Z0-9][a-zA-Z0-9_\\-]*$")
    return app_id


def _log_gap(app_id: str, reason: str) -> None:
    """Record unauthorized access attempt."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "app_id": app_id,
        "event": "access_denied",
        "reason": reason,
    }
    logger.warning("SAP gate denied: app_id=%s reason=%s", app_id, reason)
    log_path = LOG_DIR / "gaps.jsonl"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _log_grant(app_id: str) -> None:
    """Record authorized access."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "app_id": app_id,
        "event": "access_granted",
    }
    log_path = LOG_DIR / "grants.jsonl"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _verify_pgp(manifest_path: Path) -> tuple[bool, str]:
    """
    Verify the manifest's GPG detached signature AND confirm signer identity.

    Uses gpg --status-fd=1 to get machine-readable output and parse
    the primary key fingerprint from the VALIDSIG status line.
    Expected fingerprint comes from SAP_PGP_FINGERPRINT (or the
    WILLOW_PGP_FINGERPRINT fallback); unset ⇒ fail-closed deny.

    Returns (ok, reason).
    """
    sig_path = manifest_path.parent / (manifest_path.name + ".sig")
    if not sig_path.exists():
        return False, f"No signature file: {sig_path.name}"

    try:
        result = subprocess.run(
            ["gpg", "--verify", "--status-fd=1", str(sig_path), str(manifest_path)],
            capture_output=True, timeout=5,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace").strip()
            return False, f"gpg verify failed: {stderr[:200]}"

        stdout = result.stdout.decode("utf-8", errors="replace")
        signer_fp = None
        for line in stdout.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG"):
                parts = line.split()
                # Full line: [GNUPG:] VALIDSIG <subkey-fp> <date> <ts> <ts-exp>
                #            <expire> <reserved> <pk-algo> <hash-algo> <sig-class> <primary-fp>
                # parts indices: 0=[GNUPG:] 1=VALIDSIG 2=subkey-fp ... 11=primary-fp
                if len(parts) >= 12:
                    signer_fp = parts[11].upper()
                    break

        if signer_fp is None:
            return False, f"No VALIDSIG in gpg output: {stdout[:200].replace(chr(10), ' ')}"

        if not _EXPECTED_FP:
            return False, "SAP_PGP_FINGERPRINT not configured — gate cannot verify signer identity"
        if signer_fp != _EXPECTED_FP:
            return False, f"signature by unexpected key: {signer_fp[:16]}... (expected: {_EXPECTED_FP[:16]}...)"

        return True, "signature verified"

    except FileNotFoundError:
        return False, "gpg not found on PATH"
    except subprocess.TimeoutExpired:
        return False, "gpg verify timed out (5s)"
    except Exception as e:
        return False, f"gpg verify error: {e}"


def authorized(app_id: str) -> bool:
    """
    Run the SAP/1.0 four-step authorization chain.

    Returns True only when all four steps pass.
    Logs all denials to SAP_LOG_DIR/gaps.jsonl.
    """
    try:
        app_id = _validate_app_id(app_id)
    except ValueError as e:
        _log_gap(app_id, f"Invalid app_id: {e}")
        return False

    app_path = _resolve_app_path(SAFE_ROOT, app_id)
    if app_path is None:
        _log_gap(app_id, f"SAFE folder not found: {SAFE_ROOT / app_id}")
        return False

    manifest_path = app_path / "safe-app-manifest.json"
    if not manifest_path.exists():
        _log_gap(app_id, f"No manifest at: {manifest_path}")
        return False

    try:
        manifest_path.read_text(encoding="utf-8")
    except Exception as e:
        _log_gap(app_id, f"Manifest unreadable: {e}")
        return False

    sig_ok, sig_reason = _verify_pgp(manifest_path)
    if not sig_ok:
        _log_gap(app_id, f"PGP verification failed: {sig_reason}")
        return False

    _log_grant(app_id)
    return True


def require_authorized(app_id: str) -> None:
    """
    Assert authorization. Raises PermissionError on denial.
    Prefer this over checking authorized() — callers cannot silently ignore it.
    """
    if not authorized(app_id):
        raise PermissionError(
            f"SAP gate denied: '{app_id}' failed authorization. "
            f"Check SAFE folder exists, manifest is present, "
            f"and safe-app-manifest.json.sig is valid."
        )


def get_manifest(app_id: str) -> Optional[dict]:
    """Return parsed manifest for an authorized app_id, or None."""
    try:
        app_id = _validate_app_id(app_id)
    except ValueError:
        return None
    if not authorized(app_id):
        return None
    app_path = _resolve_app_path(SAFE_ROOT, app_id)
    if app_path is None:
        # The app dir vanished between authorized() and here (or SAFE_ROOT
        # changed). Never fall back to a CWD-relative path.
        return None
    manifest_path = app_path / "safe-app-manifest.json"
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("get_manifest(%s): failed to read/parse manifest: %s", app_id, exc)
        return None


def list_authorized() -> list[str]:
    """
    Return all app_ids under SAFE_ROOT that pass the full auth chain.
    Runs gpg --verify for each candidate — use sparingly.
    """
    if not SAFE_ROOT.exists():
        return []
    result = []
    for entry in sorted(SAFE_ROOT.iterdir()):
        if entry.is_dir() and (entry / "safe-app-manifest.json").exists():
            if authorized(entry.name):
                result.append(entry.name)
    return result
