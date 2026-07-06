"""Tests for library-implementation vs. application context hints."""

from __future__ import annotations

from pathlib import Path

from pqcscan.config import PqcConfig
from pqcscan.output.console import render_to_string
from pqcscan.scanner.context import path_context_hint, wrapper_context_hint
from pqcscan.scanner.engine import run_scan

RSA_SNIPPET = (
    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    "def build():\n"
    "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
)


def test_path_heuristic_segments():
    assert path_context_hint("lib/hazmat/rsa.py")
    assert path_context_hint("src/pkg/_internal/keys.py")
    assert path_context_hint("vendor/thing/crypto.py")
    # whole-segment matching only — no substring hits
    assert path_context_hint("src/implementations/service.py") is None
    assert path_context_hint("app/views.py") is None


def test_wrapper_heuristic_names():
    assert wrapper_context_hint("generate_rsa_key")
    assert wrapper_context_hint("create_signing_keypair")
    assert wrapper_context_hint("make_host_key")
    assert wrapper_context_hint("sign_document") is None
    assert wrapper_context_hint(None) is None


def test_scan_sets_path_hint_for_library_code(tmp_path):
    impl = tmp_path / "mylib" / "hazmat" / "keys.py"
    impl.parent.mkdir(parents=True)
    impl.write_text(RSA_SNIPPET, encoding="utf-8")
    result = run_scan([str(tmp_path)], PqcConfig.default())
    assert result.findings
    assert all(f.context_hint for f in result.findings)
    assert "library implementation" in result.findings[0].context_hint


def test_scan_sets_wrapper_hint(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def generate_signing_key():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
        encoding="utf-8",
    )
    result = run_scan([str(tmp_path)], PqcConfig.default())
    assert result.findings
    hint = result.findings[0].context_hint
    assert hint and "generate_signing_key" in hint


def test_plain_application_code_has_no_hint(tmp_path):
    app = tmp_path / "views.py"
    app.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
        encoding="utf-8",
    )
    result = run_scan([str(tmp_path)], PqcConfig.default())
    assert result.findings
    assert all(f.context_hint is None for f in result.findings)


def test_console_renders_context_hint(tmp_path):
    impl = tmp_path / "vendor" / "keys.py"
    impl.parent.mkdir(parents=True)
    impl.write_text(RSA_SNIPPET, encoding="utf-8")
    # `vendor` is in the default excludes, so scan the file directly.
    result = run_scan([str(impl)], PqcConfig.default())
    assert result.findings
    text = render_to_string(result)
    assert "Context:" in text
    assert "library implementation" in text


def test_sarif_carries_context_hint(tmp_path):
    from pqcscan.output import sarif as sarif_out

    impl = tmp_path / "backends" / "rsa_backend.py"
    impl.parent.mkdir(parents=True)
    impl.write_text(RSA_SNIPPET, encoding="utf-8")
    result = run_scan([str(impl)], PqcConfig.default())
    doc = sarif_out.to_sarif(result, base_path=str(tmp_path))
    props = doc["runs"][0]["results"][0]["properties"]
    assert "contextHint" in props
