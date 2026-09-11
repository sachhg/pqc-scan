# pqc-scan

**Snyk for Post-Quantum Cryptography** — a developer-first static analysis tool that
finds quantum-vulnerable cryptography in your code, configs, dependencies, keys and
certificates before quantum computers (or your auditors) do.

`pqc-scan` is zero-friction and lives where your code lives: in your editor, on the
command line, and right inside your pull requests. It parses real source with
tree-sitter ASTs (not brittle regexes), tells you exactly which line is vulnerable,
why it matters, and how to migrate to a NIST-standardized post-quantum algorithm.

```bash
pqc-scan scan .
```

```text
  pqc-scan  ·  Post-Quantum Cryptography scan

  ✖  CRITICAL  PQC001 · RSA Key Generation   [high confidence]
  ┌─ app/keys.py:10:19   (RSA-2048)
  │  rsa.generate_private_key(
  │          public_exponent=65537,
  │          key_size=2048,
  │      )
  └─ RSA key generation detected. RSA is broken by Shor's algorithm on a
     cryptographically relevant quantum computer, regardless of key size.
       Migrate to: ML-KEM-768 (CRYSTALS-Kyber) …  ·  FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA)
       see: https://csrc.nist.gov/pubs/fips/203/final

────────────────────────────────────────────────────────────────────────────────
  Critical: 2  High: 2  Medium: 0  Low: 0   |  Total findings: 4
  Files scanned: 1  |  Time: 0.00s
```

---

## Why post-quantum, why now

The public-key cryptography that secures almost everything online — TLS handshakes,
SSH, code signing, JWTs, certificates, VPNs — relies on math problems that are hard
*for classical computers*. **Shor's algorithm**, run on a cryptographically relevant
quantum computer, solves all of them efficiently. That breaks, completely:

- **RSA** (any key size, including RSA-4096)
- **Elliptic-curve crypto**: ECDSA, ECDH/ECDHE, X25519/X448, Ed25519/Ed448
- **Finite-field crypto**: Diffie-Hellman (DH/DHE), DSA

Symmetric crypto and hashing are weakened but not broken: **Grover's algorithm** only
halves the effective security level, so AES-256 and SHA-256/SHA3-256 remain safe.

### Harvest Now, Decrypt Later

You don't need a quantum computer to exist *today* to be at risk. Adversaries can
**capture encrypted traffic now and decrypt it later** once quantum hardware matures.
Any data with a long confidentiality lifetime — health records, financial data, state
secrets, long-lived credentials — is already exposed. Key-exchange material (ECDH,
X25519, DH) is the prime target.

### The clock is real

- **August 2024** — NIST finalized the first post-quantum standards:
  **FIPS 203 (ML-KEM)** for key encapsulation, **FIPS 204 (ML-DSA)** and
  **FIPS 205 (SLH-DSA)** for digital signatures.
- **2030 / 2035** — US federal guidance (CNSA 2.0, NSM-10) sets a migration deadline:
  begin now, complete the transition for most systems by **2030**, finish by 2035.

Migration is a multi-year inventory-and-replace effort. `pqc-scan` is the inventory
step you can run on every commit.

---

## Install

`pqc-scan` requires **Python ≥ 3.10**.

Install editable from a clone of the source:

```bash
git clone https://github.com/pqc-scan/pqc-scan.git
cd pqc-scan
pip install -e .
```

This installs the `pqc-scan` console script. Verify:

```bash
pqc-scan --version
# pqc-scan 0.2.1
```

For development (tests + coverage):

```bash
pip install -e ".[dev]"
pytest
```

All scanning dependencies (tree-sitter grammars for Python, JavaScript, Java, Go
and Rust, plus Typer, Rich and PyYAML) are installed automatically — there is
**no** native toolchain to build. Key and certificate parsing uses a small
built-in DER reader, so no OpenSSL or Rust toolchain is required either.

---

## Quickstart

```bash
pqc-scan scan .                       # scan the current tree, pretty console report
pqc-scan scan src/ -s high            # only report HIGH and CRITICAL findings
pqc-scan scan . -o sarif -f out.sarif # write SARIF for GitHub code scanning
pqc-scan scan . -o markdown           # a report you can paste into a PR comment
pqc-scan scan . --changed-only        # only files changed in the current git diff
pqc-scan scan . -s medium --fail-on critical   # report widely, block narrowly
pqc-scan baseline .                    # accept today's findings; gate on new ones
pqc-scan explain PQC001                # full rule + before/after migration example
pqc-scan rules                         # list every detection rule
pqc-scan init                          # write a starter .pqcscan.yml
```

`pqc-scan` exposes six commands: `scan`, `report`, `baseline`, `init`, `rules`,
and `explain`.

### `scan` — scan a path

```text
pqc-scan scan [PATH] [OPTIONS]
```

`PATH` defaults to `.` (the current directory) and may be a file or a directory.

| Flag | Alias | Description |
| --- | --- | --- |
| `--output` | `-o` | Output format: `console` (default), `sarif`, `cbom`, `json`, `markdown`. |
| `--output-file` | `-f` | Write output to this file instead of stdout. |
| `--severity` | `-s` | Minimum severity to report: `critical`, `high`, `medium`, `low`. |
| `--exclude` | | Glob pattern to exclude. Repeatable. |
| `--changed-only` | | Only scan files changed in the current git diff (fast PR scans). |
| `--config` | | Path to a `.pqcscan.yml` config file. |
| `--no-color` | | Disable colored output (auto-disabled when writing to a file). |
| `--fail-on-findings` | | Exit with code `1` if any findings are reported — for CI gating. |
| `--fail-on SEV` | | Exit with code `1` only when a finding is at least this severe. |
| `--baseline FILE` | | Report only findings that are **not** in this baseline. |
| `--no-baseline` | | Ignore a baseline configured in `.pqcscan.yml`. |
| `--no-suppress` | | Ignore inline `pqc-scan: ignore` directives (audit mode). |
| `--show-suppressed` | | Also list suppressed findings, with their reasons. |
| `--limit N` | | Show at most `N` findings in console output (`0` = all). |
| `--summary` | | Console output: totals and a per-file breakdown only, no per-finding detail. |
| `--group-by` | | Console grouping: `severity` (default) or `file`. |

Examples:

```bash
# Console report, but gate CI: non-zero exit if anything is found.
pqc-scan scan . --fail-on-findings

# Scan only application code, skip tests and vendored code.
pqc-scan scan . --exclude "**/tests/**" --exclude "**/third_party/**"

# Emit machine-readable JSON to stdout (pipe into jq, dashboards, etc.).
pqc-scan scan src/ -o json

# Only audit what this branch changed, at HIGH severity and above.
pqc-scan scan . --changed-only -s high --fail-on-findings

# Report everything from medium up, but only fail the build on a critical.
pqc-scan scan . -s medium --fail-on critical

# Large repo? Get the overview first, then drill into one file at a time.
pqc-scan scan . --summary
pqc-scan scan . --group-by file --limit 50
```

Example console output (scanning a single file):

```text
  pqc-scan  ·  Post-Quantum Cryptography scan

  ✖  CRITICAL  PQC001 · RSA Key Generation   [high confidence]
  ┌─ app/keys.py:10:19   (RSA-2048)
  │  rsa.generate_private_key(
  │          public_exponent=65537,
  │          key_size=2048,
  │      )
  └─ RSA key generation detected. RSA is broken by Shor's algorithm on a
     cryptographically relevant quantum computer, regardless of key size.
       Migrate to: ML-KEM-768 (CRYSTALS-Kyber) for encryption / key
       establishment, or ML-DSA-65 …  ·  FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA)
       see: https://csrc.nist.gov/pubs/fips/203/final

  ⚠  HIGH  PQC002 · RSA Encryption / Padding   [high confidence]
  ┌─ app/keys.py:26:9   (RSA-OAEP)
  │  padding.OAEP(
  │              mgf=padding.MGF1(algorithm=hashes.SHA256()),
  │              algorithm=hashes.SHA256(),
  │              label=None,
  │          )
  └─ RSA-based encryption or padding (OAEP / PKCS1v15) detected. RSA encryption
     is broken by Shor's algorithm.
       Migrate to: ML-KEM-768 (CRYSTALS-Kyber)  ·  FIPS 203
       see: https://csrc.nist.gov/pubs/fips/203/final

────────────────────────────────────────────────────────────────────────────────
  Critical: 2  High: 2  Medium: 0  Low: 0   |  Total findings: 4
  Files scanned: 1  |  Time: 0.00s
```

### `report` — write a report file

`report` runs a scan and writes a machine-readable artifact to disk. Unlike `scan`,
the format defaults to `cbom` and `--output-file` is **required**.

```text
pqc-scan report [PATH] --output-file FILE [--format cbom|sarif|json|markdown] [--config FILE]
```

```bash
# Generate a CycloneDX Cryptography Bill of Materials.
pqc-scan report . --output-file cbom.json

# Generate a SARIF report for archival / upload.
pqc-scan report . --format sarif --output-file results.sarif
```

### `baseline` — accept today's findings

```text
pqc-scan baseline [PATH] [--output-file FILE] [--severity SEV] [--exclude GLOB] [--config FILE]
```

Writes `.pqcscan-baseline.json` (by default, next to `PATH`). Commit it, then
point `scan` at it so only *new* findings are reported. See
[Baselines](#baselines) below.

### `explain` — read one rule in full

```text
pqc-scan explain PQC001 [--json]
```

Prints the rule, its severity and category, the recommended post-quantum
replacement, and the **before/after code example** — which is the one piece of
migration guidance that console and SARIF output are too terse to show.

```text
PQC001  RSA Key Generation  critical  (key-generation · pke)

RSA key generation detected. RSA is broken by Shor's algorithm on a
cryptographically relevant quantum computer, regardless of key size.

Migrate to
  ML-KEM-768 (CRYSTALS-Kyber) for encryption / key establishment, or
  ML-DSA-65 (CRYSTALS-Dilithium) if the key is used for signing
  FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA)
...
```

### `init` — scaffold a config

```text
pqc-scan init [PATH] [--force]
```

Writes a starter `.pqcscan.yml` to `PATH` (default `.`). Refuses to overwrite an
existing file unless `--force` is given.

```bash
pqc-scan init
# Created .pqcscan.yml
```

### `rules` — list detection rules

```bash
pqc-scan rules          # table
pqc-scan rules --json   # the registry, for your own tooling
```

Prints every rule (ID, name, severity, category, description).

---

## What it detects

`pqc-scan` ships **16 rules**, covering quantum-vulnerable key generation, signatures,
encryption, key exchange, hashing, weak JWT/TLS configuration, legacy ciphers,
quantum-vulnerable dependencies, and deployed key material and certificates.

| ID | Name | Severity | Category |
| --- | --- | --- | --- |
| **PQC001** | RSA Key Generation | `critical` | key-generation |
| **PQC002** | RSA Encryption / Padding | `high` | encryption |
| **PQC003** | RSA Signature | `critical` | signing |
| **PQC004** | ECDSA Key Generation or Signing | `critical` | signing |
| **PQC005** | ECDH / X25519 Key Exchange | `high` | key-exchange |
| **PQC006** | Ed25519 / Ed448 Key Generation | `high` | signing |
| **PQC007** | Diffie-Hellman Key Exchange | `high` | key-exchange |
| **PQC008** | DSA Key Generation or Signing | `critical` | signing |
| **PQC009** | SHA-1 Usage | `medium` | hashing |
| **PQC010** | MD5 Usage | `high` | hashing |
| **PQC011** | Weak JWT Algorithm (RS/ES/PS) | `high` | signing |
| **PQC012** | Weak TLS Configuration | `medium` | configuration |
| **PQC013** | DES / 3DES Usage | `high` | encryption |
| **PQC014** | Quantum-Vulnerable Dependency | `medium` | dependency |
| **PQC015** | Quantum-Vulnerable Key Material | `high` | key-material |
| **PQC016** | Quantum-Vulnerable Certificate | `high` | certificate |

Run `pqc-scan rules` for the full descriptions and to confirm the set installed on
your machine.

**Supported languages (code):** Python, JavaScript/TypeScript, Java, Go, Rust.

**Supported dependency manifests:** `requirements*.txt`, `setup.py`,
`pyproject.toml`, `Pipfile`, `package.json`, `Cargo.toml`, `go.mod`, `pom.xml`,
`build.gradle` / `build.gradle.kts`, `Gemfile` / `*.gemspec`, `composer.json`.
Each is parsed in its own format — a version string or repository URL that merely
contains a library name does not fire. Lock files are deliberately out of scope:
they restate the manifest plus the whole transitive closure and would bury the
actionable direct declaration.

**Supported configs:** YAML / JSON / TOML / `.conf` / `.ini` / `.env` (TLS, JWT,
cipher lists, protocol versions).

**Supported key material:** `.pem`, `.crt`, `.cer`, `.key`, `.pub`, `.csr`,
`id_*`, `authorized_keys`, `known_hosts` — and PEM blocks inlined into
configuration files.

**Library coverage highlights** (beyond the language standard libraries):

- **Python** — `cryptography` (hazmat), pycryptodome/pycrypto (`RSA.generate`,
  `pkcs1_15`, `pss`, `DSS`, `PKCS1_OAEP`), pyOpenSSL (`TYPE_RSA`), paramiko,
  PyJWT / python-jose, `ssl`, `hashlib` (including `hashlib.new("sha1")` and
  the `usedforsecurity=False` demotion to `low`).
- **JavaScript** — Node `crypto` (`generateKeyPair`, `createDiffieHellman`,
  `publicEncrypt`, `createSign`), WebCrypto `SubtleCrypto`, `jsonwebtoken`,
  `jose` (`setProtectedHeader`), node-forge, AWS KMS asymmetric `KeySpec`s.
- **Java** — JCA factories (`KeyPairGenerator`, `Signature`, `Cipher`,
  `MessageDigest`, `KeyAgreement`), Bouncy Castle lightweight API
  (`RSAKeyGenerationParameters`, `ECDSASigner`, `Ed25519Signer`, …), and
  `SSLContext.getInstance` with legacy protocols.
- **Go** — `crypto/rsa`, `crypto/ecdsa`, `crypto/ecdh`, `crypto/ed25519`,
  `crypto/dsa`, `crypto/tls` configuration (`MinVersion` pins and weak
  `CipherSuites`), `x/crypto/curve25519`, and golang-jwt signing methods.
- **Rust** — RustCrypto (`rsa`, `p256`/`p384`/`p521`/`k256`, `ed25519-dalek`,
  `x25519-dalek`, `sha1`, `md-5`, `des`), `ring` (`signature::*`,
  `agreement::*`, `digest::SHA1_*`), the `openssl` bindings (`Rsa::generate`,
  `EcKey`, `Dsa`, `Dh`, `MessageDigest::sha1`, DES `Cipher`s, legacy
  `SslVersion`), and `jsonwebtoken`.

**Context hints.** Findings inside code that *looks like* crypto-library
plumbing (paths containing `hazmat`, `_internal`, `backends`, `vendor`, …) or
inside a `generate_*_key()`-style wrapper carry a `context_hint` explaining
whether the call site is actionable for you or belongs to a library you merely
consume. Hints appear in console output, SARIF `properties.contextHint`, and
the JSON `context_hint` field.

**Keys and certificates.** `PQC015` / `PQC016` read the actual DER, not the PEM
label, so a finding names the real parameters — `RSA-3072`, `ECDSA-P-384`,
`Ed25519` — along with a certificate's subject CN, signature algorithm and
expiry:

```text
  ⚠  HIGH  PQC016 · Quantum-Vulnerable Certificate   [high confidence]
  ┌─ deploy/tls/server.crt:1:1   (RSA-2048)
  │  -----BEGIN CERTIFICATE-----
  └─ X.509 certificate with a RSA-2048 public key (subject CN=api.example.com;
     signed with sha256WithRSAEncryption; expires 2027-03-04). …
```

That matters for precision as much as for detail: a PKCS#8 block labelled
`PRIVATE KEY` may hold RSA, EC, Ed25519 — **or ML-DSA**, which must not be
flagged. Only algorithms on a known quantum-vulnerable OID list produce a
finding, so real ML-KEM / ML-DSA keys and ML-DSA-signed certificates come back
clean. A certificate signed with SHA-1 or MD5 is additionally reported as
`critical`, because that signature is forgeable today without any quantum
computer.

---

## Living with a scan

Two features exist so that dropping `pqc-scan` into a repository that already has
crypto does not mean a permanently red build or a disabled scanner.

### Inline suppressions

Waive a finding next to the code that needs it, with a reason:

```python
key = rsa.generate_private_key(...)   # pqc-scan: ignore[PQC001] -- legacy peer, JIRA-42

# pqc-scan: ignore-next-line[PQC004,PQC005]
key = ec.generate_private_key(ec.SECP256R1())
```

```go
// pqc-scan: ignore-file[PQC014] -- vendored reference implementation
```

| Directive | Applies to |
| --- | --- |
| `pqc-scan: ignore` | the line it appears on |
| `pqc-scan: ignore-next-line` | the following line |
| `pqc-scan: ignore-file` | every finding in the file |

- A bracketed list scopes the waiver (`ignore[PQC001,PQC009]`); no brackets means
  every rule. Rule IDs are case-insensitive.
- Text after `--` is recorded as the reason and reported back.
- The parser is **comment-syntax agnostic** — `#`, `//`, `/* */`, `<!-- -->` and
  YAML comments all work, in source, configs and manifests alike. The trade-off
  is that a directive inside a string literal also suppresses.

Waivers stay auditable rather than disappearing:

- suppressed findings never gate CI and are not counted in `total`;
- they are emitted in SARIF with `suppressions: [{ "kind": "inSource" }]`, which
  GitHub code scanning honors — the finding is recorded, not shown as an open alert;
- they appear in JSON under `suppressed_findings`, and in the console summary as
  `(+N suppressed)`; `--show-suppressed` lists them with their reasons;
- they are **still inventoried in the CBOM**, because an accepted risk is still a
  deployed algorithm.

`--no-suppress` (or `suppressions: false` in config) ignores every directive, for
an audit run that must see everything.

### Baselines

A baseline says "this is the debt we already have; tell me about anything new."

```bash
# 1. Snapshot the current findings and commit the file.
pqc-scan baseline .
git add .pqcscan-baseline.json

# 2. In CI, gate on new crypto only.
pqc-scan scan . --baseline .pqcscan-baseline.json --fail-on high
```

Or configure it once, in `.pqcscan.yml`:

```yaml
baseline: .pqcscan-baseline.json
```

Fingerprints hash the rule ID, the baseline-relative file path, the algorithm and
the whitespace-normalized snippet — **not the line number**. Adding an import
above a finding does not invalidate the baseline, and neither does reformatting.
Identical findings are tracked by count, so if a file baselines two
`hashlib.sha1()` calls and someone adds a third, the third is reported as new.

The document keeps `rule_id` / `path` / `algorithm` alongside each hash, so a
baseline diff is reviewable in a pull request instead of being an opaque wall of
hashes. Regenerating prints what changed since the previous snapshot.

Baselined findings are kept out of SARIF — the whole point is that pre-existing
debt stops annotating pull requests — but remain in the CBOM inventory and in the
JSON `baselined_findings` array. A missing or malformed baseline file exits `2`
rather than silently treating everything as new.

---

## Output formats

Choose with `-o`/`--output` on `scan`, or `--format` on `report`.

### `console` (default)

A colorized, human-readable report with severity badges, the exact code snippet, the
migration target, and the relevant NIST standard. Color is auto-disabled when writing
to a file or with `--no-color`.

### `sarif` — GitHub code scanning

Static Analysis Results Interchange Format **2.1.0**. Upload it with the CodeQL action
and findings appear as **inline annotations on the exact line** in pull requests and
in the repository's Security → Code scanning tab.

```bash
pqc-scan scan . -o sarif -f pqc-scan.sarif
```

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/.../sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "pqc-scan", "version": "0.2.1", "rules": [ ... ] } },
      "results": [ ... ]
    }
  ]
}
```

### `cbom` — CycloneDX Cryptography Bill of Materials

A **CycloneDX 1.6 CBOM**: a structured inventory of every cryptographic asset found,
emitted as `cryptographic-asset` components. Ideal for compliance, supply-chain
attestation, and tracking migration progress over time.

```bash
pqc-scan report . --format cbom --output-file cbom.json
```

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    { "type": "cryptographic-asset", "name": "RSA-2048", "...": "..." }
  ]
}
```

### `markdown` — pull-request comments and CI job summaries

A report you can paste into a PR comment or pipe straight into
`$GITHUB_STEP_SUMMARY`: a counts table, one scannable row per finding, and the
migration guidance folded into `<details>` blocks so the comment stays short
until someone opens one.

```bash
pqc-scan scan . -o markdown -f pqc-scan.md
```

```markdown
## 🔐 pqc-scan — Post-Quantum Cryptography scan

| Critical | High | Medium | Low | Total |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 2 | 0 | 0 | **4** |

_1 file(s) scanned · 0.01s_

### Findings

| Severity | Rule | Name | Location | Algorithm |
| --- | --- | --- | --- | --- |
| 🔴 critical | `PQC001` | RSA Key Generation | `app/keys.py:10` | RSA-2048 |
```

Table rows and detail blocks are capped independently (100 and 20 by default) so
the output stays under GitHub's 65,536-character comment limit; whatever is left
out is stated explicitly rather than silently truncated. The GitHub Action writes
this to the job summary page automatically.

### `json` — plain JSON

Scan metadata plus every finding with full migration metadata — easy to pipe into
`jq`, dashboards, or custom tooling.

```bash
pqc-scan scan . -o json | jq '.findings[] | {rule_id, severity, file_path, line_number, algorithm}'
```

```json
{
  "tool": "pqc-scan",
  "version": "0.2.1",
  "generated_at": "2026-07-06T12:00:00Z",
  "paths": ["/repo"],
  "summary": {
    "total": 4,
    "by_severity": { "critical": 2, "high": 2, "medium": 0, "low": 0 },
    "files_scanned": 128,
    "duration_seconds": 0.4211,
    "errors": []
  },
  "findings": [
    {
      "file_path": "app/keys.py",
      "line_number": 10,
      "column_number": 19,
      "algorithm": "RSA-2048",
      "category": "key-generation",
      "severity": "critical",
      "confidence": "high",
      "rule_id": "PQC001",
      "context_hint": null,
      "migration_suggestion": {
        "recommended_algorithm": "ML-KEM-768 (CRYSTALS-Kyber) …",
        "nist_standard": "FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA)",
        "docs_url": "https://csrc.nist.gov/pubs/fips/203/final"
      }
    }
  ]
}
```

---

## GitHub Action

Run `pqc-scan` on every pull request and surface findings as inline code-scanning
annotations. Save this as `.github/workflows/pqc-scan.yml`:

```yaml
name: pqc-scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required to upload SARIF to code scanning

jobs:
  pqc-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0                  # only needed for changed-only

      - name: Run pqc-scan
        uses: ./                          # this repo's action; or pin: pqc-scan/pqc-scan@v1
        with:
          path: .
          severity: medium                # report from medium up...
          fail-on: critical               # ...but only block the PR on a critical
          changed-only: ${{ github.event_name == 'pull_request' }}
```

The action uploads the SARIF to code scanning itself, so no separate
`upload-sarif` step is required.

**Action inputs**

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | File or directory to scan. |
| `severity` | `medium` | Minimum severity to **report**. |
| `fail-on` | `''` | Fail the job only when a finding is at least this severe. |
| `fail-on-findings` | `false` | Fail the job if **any** finding is reported. |
| `changed-only` | `false` | Only scan files changed in this PR (needs `fetch-depth: 0`). |
| `baseline` | `''` | Baseline file of accepted findings; report only what is new. |
| `config` | `''` | Path to a `.pqcscan.yml` config file. |
| `output-sarif` | `pqc-scan.sarif` | Path to write the SARIF report. |
| `upload-sarif` | `true` | Upload the SARIF to GitHub code scanning. |
| `job-summary` | `true` | Write the Markdown report to the job summary page. |
| `python-version` | `3.12` | Python used to run pqc-scan. |

**Action outputs**

| Output | Description |
| --- | --- |
| `sarif-file` | Path of the SARIF report that was written. |
| `total-findings` | Number of findings reported by the scan. |

`severity` and `fail-on` are deliberately separate: the common setup reports
everything from `medium` up — so it all shows as code-scanning annotations and in
the job summary — while only a `critical` finding actually blocks the pull
request. The SARIF is written before the failing exit, so annotations appear even
on a red build.

If you prefer to run the CLI directly without the composite action, the equivalent
step is just:

```yaml
      - run: pip install -e . && pqc-scan scan . -o sarif -f pqc-scan.sarif -s high
```

Pair it with `--changed-only` in PR jobs to scan only the diff and keep runs fast.

---

## Configuration

`pqc-scan` reads a `.pqcscan.yml` file. It is discovered automatically by walking up
from the scanned path, or pointed at explicitly with `--config`. Generate a starter
with `pqc-scan init`. Full schema:

```yaml
# .pqcscan.yml — configuration for pqc-scan

exclude:
  - "**/tests/**"
  - "**/*.test.py"
  - "**/vendor/**"
  - "**/node_modules/**"

# Minimum severity to report: critical | high | medium | low
severity_threshold: medium

languages:
  - python
  - javascript
  - java
  - go
  - rust

scan_configs: true        # Scan YAML/JSON/TOML/.conf config files
scan_dependencies: true   # Scan dependency manifests (requirements.txt, Cargo.toml, ...)
scan_certificates: true   # Scan PEM/OpenSSH keys and X.509 certificates (PQC015/PQC016)

# Honor inline "pqc-scan: ignore" directives (set false for an audit run).
suppressions: true

# Path to a baseline of accepted findings, relative to this file. Generate it
# with `pqc-scan baseline`; later scans then report only NEW findings.
# baseline: .pqcscan-baseline.json

rules:
  disable: []             # e.g. [PQC010] to silence a specific rule

output:
  default_format: console # console | sarif | cbom | json | markdown
  cbom_path: cbom.json
```

Notes:

- CLI flags override config values (e.g. `-s high` beats `severity_threshold`).
- `rules.disable` takes rule IDs (`PQC001` … `PQC016`), case-insensitive.
- `baseline` is resolved relative to the config file, so the same config works
  from any working directory. `--no-baseline` overrides it.
- Without a config file, the defaults exclude `**/tests/**`, `**/node_modules/**`,
  `**/.venv/**`, `**/venv/**`, `**/vendor/**`, `**/dist/**`, and `**/build/**`
  (the `tests` glob matches test directories at **any** depth), and the walker
  never descends into `.git`, `site-packages`, caches, or IDE directories.
- A malformed `--config` file exits with code `2`; a malformed *discovered*
  config prints a warning and falls back to defaults.

---

## Migration guidance

Every finding ships with concrete, NIST-aligned migration guidance and a
before/after code example. The high-level mapping:

| Vulnerable today | Migrate to | NIST standard |
| --- | --- | --- |
| RSA key generation / encryption (PQC001/002) | **ML-KEM-768** (CRYSTALS-Kyber) | FIPS 203 |
| RSA signatures (PQC003) | **ML-DSA-65** (CRYSTALS-Dilithium) | FIPS 204 |
| ECDSA / EC keys (PQC004) | **ML-DSA-65** | FIPS 204 |
| ECDH / ECDHE / X25519 (PQC005) | **ML-KEM-768** | FIPS 203 |
| Ed25519 / Ed448 (PQC006) | **ML-DSA-65** (or SLH-DSA) | FIPS 204 / 205 |
| Diffie-Hellman (PQC007) | **ML-KEM-768** | FIPS 203 |
| DSA (PQC008) | **ML-DSA-65** | FIPS 204 |
| SHA-1 (PQC009) | **SHA-256 / SHA3-256** | FIPS 180-4 / 202 |
| MD5 (PQC010) | **SHA-256 / SHA3-256** | FIPS 180-4 / 202 |
| Weak JWT RS/ES/PS256 (PQC011) | HS256 internally; track IETF JOSE for PQC | — |
| Weak TLS config (PQC012) | TLS 1.3 + hybrid **X25519MLKEM768** | FIPS 203 |
| DES / 3DES (PQC013) | **AES-256-GCM** | FIPS 197 |
| Stored key material (PQC015) | **ML-KEM-768** / **ML-DSA-65** — inventory, reissue, revoke | FIPS 203 / 204 |
| Certificates (PQC016) | **ML-DSA-65** or hybrid/composite certificates | FIPS 204 |

> **Heads-up about liboqs.** The Python post-quantum library `oqs`
> (liboqs-python) is **not** a pure `pip install`. It wraps the compiled **liboqs**
> C library, which must be available first: `pip install liboqs` builds it from
> source via CMake, or you install the distro package / build from
> <https://github.com/open-quantum-safe/liboqs>. Hash and symmetric replacements
> (SHA-256, AES-256-GCM) need no special install — they live in `hashlib` and the
> `cryptography` package.

---

## How it works

`pqc-scan` uses two complementary detection strategies:

- **Code (Python, JavaScript/TypeScript, Java, Go): tree-sitter AST analysis.**
  Source is parsed into a concrete syntax tree and the analyzers traverse real
  nodes — call expressions, imports, dotted attribute access, string and keyword
  arguments. This is **not** regex matching: it resolves what is actually being
  *called* (e.g. `rsa.generate_private_key(...)`, `ec.generate_private_key(...)`),
  so it sees through aliasing and whitespace, reports precise 1-based line/column
  positions, and avoids matching the same construct inside comments or strings.

- **Configs and dependencies: pattern-based scanning.** TLS/JWT/cipher settings in
  YAML/JSON/TOML/`.conf`, and manifests like `requirements.txt` and `package.json`,
  are matched against curated patterns of quantum-vulnerable algorithms and
  libraries.

Each language analyzer exposes a common contract (`LANGUAGE`, `EXTENSIONS`,
`GRAMMAR`, `analyze(...)`) and emits `Finding` objects through a single shared
factory, so console, SARIF, CBOM, and JSON outputs all stay perfectly consistent.

---

## Limitations & accuracy

`pqc-scan` is a **static** analyzer. It is tuned for high-confidence, low-noise
detection, but a few caveats apply:

- **It flags presence, not necessarily exploitable risk.** A `PQC014` dependency
  match means a quantum-vulnerable library is declared, not that a vulnerable code
  path is exercised. Treat findings as an inventory to triage.
- **Dynamic / reflective crypto can be missed.** Algorithms chosen at runtime, built
  from string concatenation, or invoked through heavy indirection may not be
  resolved by static analysis.
- **Detection is best-effort across libraries.** Coverage targets the most common
  crypto APIs per language; exotic or in-house wrappers may not be recognized.
- **Configuration heuristics are pattern-based** and can occasionally over- or
  under-match unusual config layouts. Tune with `rules.disable` and `exclude`.
- **Rust detection needs a resolvable import.** A call whose type does not trace
  back to a known crate through a `use` declaration is not flagged — deliberately,
  since a local `Sha1` type is as likely as the crate.
- **Encrypted private keys are skipped.** Their algorithm cannot be determined
  without the passphrase, and guessing from the PEM label would be wrong as often
  as right.
- **Lock files are not scanned.** They restate the manifest plus the whole
  transitive closure; the direct declaration in the manifest is the actionable one.
- **Inline suppressions are text-matched**, so a `pqc-scan: ignore` directive
  inside a string literal also suppresses.

Use `--changed-only` for fast PR feedback, the full scan for an inventory/CBOM, and
the migration guidance attached to each finding as your remediation checklist.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md). The current release is **0.2.1**.

---

## License

Apache-2.0. See the project metadata in `pyproject.toml`.
