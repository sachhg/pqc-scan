"""Tests for the multi-ecosystem dependency-manifest scanner (PQC014)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pqcscan.scanner.base import ScanContext
from pqcscan.scanner.dependency_scanner import DependencyScanner

FIXTURES = Path(__file__).parent / "fixtures" / "dependencies"
SAFE = FIXTURES / "safe"


def _scan(path: Path):
    return DependencyScanner(ScanContext(severity_threshold="low")).scan_file(path)


def _names(findings) -> set[str]:
    return {f.algorithm.removeprefix("dependency: ") for f in findings}


def _write(tmp_path: Path, name: str, body: str) -> Path:
    target = tmp_path / name
    target.write_text(body, encoding="utf-8")
    return target


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name",
    [
        "requirements.txt", "requirements-dev.txt", "setup.py", "pyproject.toml",
        "Pipfile", "package.json", "Cargo.toml", "go.mod", "pom.xml",
        "build.gradle", "build.gradle.kts", "Gemfile", "fixture.gemspec",
        "composer.json",
    ],
)
def test_supported_manifest_names(name, tmp_path):
    assert DependencyScanner().supports(tmp_path / name)


@pytest.mark.parametrize(
    "name",
    ["app.py", "Cargo.lock", "go.sum", "package-lock.json", "yarn.lock", "README.md"],
)
def test_unsupported_names_are_not_routed_here(name, tmp_path):
    """Lock files in particular: they restate the whole transitive closure."""
    assert not DependencyScanner().supports(tmp_path / name)


# --------------------------------------------------------------------------- #
# Per-ecosystem detection
# --------------------------------------------------------------------------- #


def test_python_requirements():
    findings = _scan(FIXTURES / "requirements.txt")
    assert _names(findings) == {"pycrypto", "ecdsa", "rsa", "paramiko"}
    assert all(f.rule_id == "PQC014" for f in findings)


def test_npm_package_json():
    assert _names(_scan(FIXTURES / "package.json")) == {
        "node-forge", "jsrsasign", "elliptic", "node-rsa"
    }


def test_cargo_toml_covers_every_dependency_table():
    names = _names(_scan(FIXTURES / "Cargo.toml"))
    assert {"rsa", "p256", "ed25519-dalek", "x25519-dalek"} <= names
    assert "sha1" in names, "dev-dependencies must be scanned"
    assert "openssl" in names, "target-specific dependencies must be scanned"
    assert "sha2" not in names and "aes-gcm" not in names


def test_cargo_renamed_dependency_uses_the_published_name():
    """`digest = { package = "md-5" }` is the md-5 crate under a local alias."""
    assert "md-5" in _names(_scan(FIXTURES / "Cargo.toml"))


def test_go_mod_matches_the_longest_registered_prefix():
    findings = _scan(FIXTURES / "go.mod")
    assert _names(findings) == {
        "github.com/golang-jwt/jwt",          # declared as .../jwt/v5
        "github.com/btcsuite/btcd/btcec",     # declared as .../btcec/v2
        "golang.org/x/crypto",
        "github.com/dgrijalva/jwt-go",        # single-line require form
    }


def test_go_mod_ignores_replace_directives(tmp_path):
    path = _write(
        tmp_path, "go.mod",
        "module example.com/x\n\ngo 1.22\n\n"
        "replace (\n\tgithub.com/dgrijalva/jwt-go v3.2.0 => ./local\n)\n",
    )
    assert _scan(path) == []


def test_maven_pom_coordinates():
    findings = _scan(FIXTURES / "pom.xml")
    assert _names(findings) == {
        "org.bouncycastle", "com.jcraft:jsch", "com.auth0:java-jwt"
    }
    # The finding points at the artifactId line, not at line 1.
    assert all(f.line_number > 1 for f in findings)


def test_gradle_both_declaration_styles():
    names = _names(_scan(FIXTURES / "build.gradle"))
    assert "org.bouncycastle" in names           # 'group:artifact:version' string
    assert "io.jsonwebtoken" in names            # double-quoted string
    assert "com.jcraft:jsch" in names            # group: .., name: .. form
    assert not any(n.startswith("com.google") for n in names)


def test_ruby_gemfile():
    assert _names(_scan(FIXTURES / "Gemfile")) == {"jwt", "ed25519", "net-ssh"}


def test_ruby_gemspec(tmp_path):
    path = _write(
        tmp_path, "fixture.gemspec",
        'Gem::Specification.new do |s|\n'
        '  s.add_dependency "jwt", "~> 2.8"\n'
        '  s.add_development_dependency "rspec"\n'
        'end\n',
    )
    assert _names(_scan(path)) == {"jwt"}


def test_php_composer():
    assert _names(_scan(FIXTURES / "composer.json")) == {
        "phpseclib/phpseclib", "firebase/php-jwt"
    }


# --------------------------------------------------------------------------- #
# Precision
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name", ["Cargo.toml", "go.mod", "pom.xml", "Gemfile", "composer.json", "package.json"]
)
def test_safe_manifests_yield_zero_findings(name):
    assert _scan(SAFE / name) == []


def test_a_version_string_is_not_mistaken_for_a_package(tmp_path):
    """`rsa` in a version or URL must not become a dependency finding."""
    path = _write(
        tmp_path, "package.json",
        '{"dependencies": {"express": "^4.18.0"},'
        ' "repository": "https://github.com/example/rsa-notes"}\n',
    )
    assert _scan(path) == []


def test_malformed_manifest_does_not_raise(tmp_path):
    path = _write(tmp_path, "Cargo.toml", "[dependencies\nrsa = \n")
    findings = _scan(path)  # best-effort regex fallback, never an exception
    assert all(f.rule_id == "PQC014" for f in findings)


def test_each_library_is_reported_once(tmp_path):
    path = _write(
        tmp_path, "requirements.txt", "ecdsa==0.18.0\necdsa>=0.18\necdsa\n"
    )
    assert len(_scan(path)) == 1


def test_rule_can_be_disabled():
    scanner = DependencyScanner(ScanContext(disabled_rules=frozenset({"PQC014"})))
    assert scanner.scan_file(FIXTURES / "requirements.txt") == []


def test_findings_name_the_ecosystem_in_the_description():
    findings = _scan(FIXTURES / "Cargo.toml")
    assert all("crates.io" in f.description for f in findings)
    assert all(f.migration_suggestion.recommended_algorithm for f in findings)
