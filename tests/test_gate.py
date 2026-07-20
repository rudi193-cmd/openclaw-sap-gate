"""Tests for openclaw-sap-gate authorization chain."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from openclaw_sap_gate.gate import authorized, require_authorized, get_manifest, _validate_app_id


@pytest.fixture
def safe_root(tmp_path, monkeypatch):
    root = tmp_path / "Applications"
    root.mkdir()
    monkeypatch.setattr("openclaw_sap_gate.gate.SAFE_ROOT", root)
    monkeypatch.setattr("openclaw_sap_gate.gate.LOG_DIR", tmp_path / "log")
    return root


def _make_app(safe_root: Path, app_id: str, sign: bool = True, valid_sig: bool = True) -> Path:
    app_dir = safe_root / app_id
    app_dir.mkdir()
    manifest = {"app_id": app_id, "name": app_id, "version": "1.0.0"}
    (app_dir / "safe-app-manifest.json").write_text(json.dumps(manifest))
    if sign:
        (app_dir / "safe-app-manifest.json.sig").write_bytes(b"fake-sig")
    return app_dir


class TestValidateAppId:
    def test_valid_ids(self):
        for app_id in ["my-app", "App1", "a", "hello_world", "x-y-z"]:
            assert _validate_app_id(app_id) == app_id

    def test_rejects_path_traversal(self):
        with pytest.raises(ValueError):
            _validate_app_id("../etc/passwd")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            _validate_app_id("")

    def test_rejects_slash(self):
        with pytest.raises(ValueError):
            _validate_app_id("a/b")


class TestAuthorized:
    def test_missing_safe_folder(self, safe_root):
        assert authorized("nonexistent") is False

    def test_missing_manifest(self, safe_root):
        (safe_root / "no-manifest").mkdir()
        assert authorized("no-manifest") is False

    def test_missing_sig(self, safe_root):
        _make_app(safe_root, "no-sig", sign=False)
        assert authorized("no-sig") is False

    def test_gpg_not_found(self, safe_root):
        _make_app(safe_root, "my-app")
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert authorized("my-app") is False

    def test_gpg_timeout(self, safe_root):
        import subprocess
        _make_app(safe_root, "my-app")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("gpg", 5)):
            assert authorized("my-app") is False

    def test_gpg_bad_returncode(self, safe_root):
        _make_app(safe_root, "my-app")
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = b"bad signature"
        with patch("subprocess.run", return_value=mock_result):
            assert authorized("my-app") is False

    def test_gpg_fingerprint_mismatch(self, safe_root, monkeypatch):
        _make_app(safe_root, "my-app")
        monkeypatch.setattr("openclaw_sap_gate.gate._EXPECTED_FP", "AAAA")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"[GNUPG:] VALIDSIG abc 2026 123 0 0 0 17 8 00 BBBB\n"
        mock_result.stderr = b""
        with patch("subprocess.run", return_value=mock_result):
            assert authorized("my-app") is False

    def test_no_fingerprint_pinned_fails_closed(self, safe_root, monkeypatch, tmp_path):
        """A valid signature with NO pinned fingerprint must DENY (fail-closed):
        without a trust anchor the gate cannot verify signer identity."""
        _make_app(safe_root, "my-app")
        monkeypatch.setattr("openclaw_sap_gate.gate._EXPECTED_FP", "")
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"[GNUPG:] VALIDSIG abc 2026 123 0 0 0 17 8 00 AAAA\n"
        mock_result.stderr = b""
        with patch("subprocess.run", return_value=mock_result):
            assert authorized("my-app") is False
        gaps = (tmp_path / "log" / "gaps.jsonl").read_text()
        assert "not configured" in gaps

    def test_case_insensitive_folder(self, safe_root):
        _make_app(safe_root, "MyApp")
        with patch("openclaw_sap_gate.gate._verify_pgp", return_value=(True, "ok")):
            assert authorized("myapp") is True

    def test_logs_denial(self, safe_root, tmp_path):
        assert authorized("nonexistent") is False
        gaps = (tmp_path / "log" / "gaps.jsonl")
        assert gaps.exists()
        entry = json.loads(gaps.read_text().strip())
        assert entry["event"] == "access_denied"
        assert entry["app_id"] == "nonexistent"


class TestRequireAuthorized:
    def test_raises_on_denial(self, safe_root):
        with pytest.raises(PermissionError):
            require_authorized("nonexistent")

    def test_passes_on_grant(self, safe_root, monkeypatch):
        _make_app(safe_root, "my-app")
        with patch("openclaw_sap_gate.gate._verify_pgp", return_value=(True, "ok")):
            require_authorized("my-app")  # should not raise


class TestGetManifest:
    def test_returns_parsed_manifest(self, safe_root):
        _make_app(safe_root, "my-app")
        with patch("openclaw_sap_gate.gate._verify_pgp", return_value=(True, "ok")):
            manifest = get_manifest("my-app")
        assert manifest is not None
        assert manifest["app_id"] == "my-app"

    def test_no_cwd_fallback_when_app_path_unresolvable(self, safe_root, tmp_path, monkeypatch):
        """If the app dir can't be resolved after authorized(), get_manifest must
        return None — never read safe-app-manifest.json from the current directory."""
        cwd = tmp_path / "attacker-cwd"
        cwd.mkdir()
        (cwd / "safe-app-manifest.json").write_text(
            json.dumps({"app_id": "planted", "name": "planted"})
        )
        monkeypatch.chdir(cwd)
        # authorized() passes but path resolution then fails (e.g. dir removed race)
        with patch("openclaw_sap_gate.gate.authorized", return_value=True), \
             patch("openclaw_sap_gate.gate._resolve_app_path", return_value=None):
            assert get_manifest("my-app") is None
