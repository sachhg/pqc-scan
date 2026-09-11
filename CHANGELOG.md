# Changelog

All notable changes to `pqc-scan` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] — 2026-09-11

Bug fixes found by adversarially probing the 0.2.0 surface. All four were
reachable from ordinary use, and two failed silently.

### Fixed

- **A suppression directive on the closing line of a multi-line call did
  nothing.** Directives were matched against a finding's first line only, so the
  idiomatic placement — a trailing `# pqc-scan: ignore` after a multi-line
  `rsa.generate_private_key(...)` — had no effect. Findings now carry
  `end_line_number` and a directive anywhere in the span counts. Measured over
  the fixture corpus, 177 of 180 findings are single-line and the largest spans
  5 lines, so the widened match cannot swallow unrelated code. SARIF gained
  `endLine` for multi-line findings as a result, so GitHub highlights the whole
  construct.
- **A package name quoted in a `requirements.txt` comment was reported as a
  declared dependency** (`requests==2.31.0  # replaces 'rsa' eventually` →
  `PQC014 rsa`). The quoted-name scan exists for `setup.py` and `Pipfile`, where
  names really are string literals; `requirements*.txt` now reads the line-start
  name only and skips pip options and includes.
- **A snippet containing a backtick run escaped its Markdown code block.**
  `hashlib.md5(b"```")` is valid Python and would spill the snippet — and
  everything after it — into the surrounding document, corrupting a whole PR
  comment. Fences are now sized to beat the content, the `<details>` summary is
  HTML-escaped, and table cells strip carriage returns.
- **Quadratic blowup on files with many PEM markers.** An unterminated `BEGIN`
  made the block regex scan to end of file, and `_position` counted newlines
  from byte 0 per match. 0.56 MB of bare `BEGIN` lines took ~39 seconds — well
  within the walker's 2 MB limit, so a single file could stall a CI run.
  Markers are now paired in one linear pass and line starts are indexed once per
  file: **39s → 0.014s**, and a 500-certificate chain or 5,000 SSH public keys
  now scan in ~0.05s.

### Added

- A PyPI trusted-publishing workflow: the build job validates the distribution,
  smoke-tests the wheel in a clean venv, and refuses a tag that disagrees with
  the version in `pyproject.toml`.

## [0.2.0] — 2026-09-10

The theme of this release is **making a scan livable in a real repository**:
a way to accept findings you have consciously decided not to fix yet, a way to
gate CI on new crypto without fixing the backlog first, and a much wider view of
what "your cryptography" actually is — Rust code, six more package ecosystems,
and the keys and certificates already deployed.

### Added

**Inline suppressions.** Waive an accepted finding next to the code that needs
it, with a reason attached:

```python
key = rsa.generate_private_key(...)   # pqc-scan: ignore[PQC001] -- legacy peer, JIRA-42
# pqc-scan: ignore-next-line[PQC004]
# pqc-scan: ignore-file
```

The directive parser is comment-syntax agnostic, so the same spelling works in
source, configs and manifests. Waivers stay auditable: suppressed findings never
gate CI, but they are emitted in SARIF with a `suppressions` array that GitHub
code scanning honors, listed separately in JSON, counted in the console summary
(`--show-suppressed` lists them with their reasons), and still inventoried in the
CBOM. `--no-suppress` / `suppressions: false` force a full audit run.

**Baselines.** `pqc-scan baseline` snapshots today's findings; `scan --baseline`
then reports only what is new. Fingerprints are line-independent, so adding an
import above a finding does not invalidate the baseline, and identical findings
are tracked by count so an extra occurrence still surfaces. A missing or
malformed baseline exits `2` rather than silently treating everything as new.

**Rust support** (5th language). RustCrypto (`rsa`, `p256`/`p384`/`p521`/`k256`,
`ed25519-dalek`, `x25519-dalek`, `sha1`, `md-5`, `des`), `ring`, the `openssl`
bindings and `jsonwebtoken`. Because idiomatic Rust writes `use rsa::RsaPrivateKey;`
and then calls `RsaPrivateKey::new(..)`, the analyzer resolves `use` declarations
(aliases, brace lists, globs) and matches the resolved path — which is also the
precision gate: a bare `Sha1::new()` that does not trace back to a known crate is
not flagged.

**Dependency scanning for six more ecosystems.** `Cargo.toml`, `go.mod`,
`pom.xml`, `build.gradle(.kts)`, `Gemfile` / `*.gemspec` and `composer.json`, each
parsed in its own format with its own flagged-library registry. Go module paths
match by longest prefix (`.../jwt/v5` → `.../jwt`) and Maven coordinates fall back
from `group:artifact` to the bare `group`.

**Key material and certificates — `PQC015` and `PQC016`.** PEM private and public
keys (PKCS#1, PKCS#8, SEC1, OpenSSH), X.509 certificates and CSRs, SSH public keys
(`id_*.pub`, `authorized_keys`, `known_hosts`), DH parameters, and PEM blocks
inlined into configuration files. Findings report the real parameters —
`RSA-3072`, `ECDSA-P-384`, `Ed25519` — plus a certificate's subject CN, signature
algorithm and expiry, and a SHA-1/MD5-signed certificate is raised to `critical`
because that signature is forgeable today. Identification reads the DER via a
small bounded ASN.1 reader rather than trusting the PEM label, so a PKCS#8 block
holding an ML-DSA key is correctly left alone.

**Markdown output** (`-o markdown`) for PR comments and CI job summaries, with
independent caps on table rows and detail blocks so it stays under GitHub's
limits and reports what it omitted.

**`pqc-scan explain PQC0xx`** — the full rule, plus the before/after migration
code example that console and SARIF output are too terse to show. `--json` on
both `explain` and `rules` makes the registry consumable by other tooling.

**`scan --fail-on <severity>`** separates reporting from gating: report from
`medium` up, block only on `critical`.

**GitHub Action inputs**: `fail-on`, `changed-only`, `baseline`, `config`,
`upload-sarif`, `job-summary`, `python-version`. The action now writes the
Markdown report to the job summary page and exposes `total-findings` as an output.

### Changed

- The CBOM is now a full inventory: suppressed and baselined findings are
  included, because an accepted risk is still a deployed algorithm.
- `_helpers` gained `field_expression`, `generic_type` / `generic_function`
  (turbofish stripping) and `string_literal`, so the shared node accessors cover
  the Rust grammar.
- The file router is additive for key material: a config file can both enable a
  weak cipher suite and inline a private key, and both are reported.

## [0.1.0]

Initial release: tree-sitter AST analysis for Python, JavaScript/TypeScript, Java
and Go; config-file and dependency-manifest scanning; rules PQC001–PQC014;
console, SARIF, CycloneDX CBOM and JSON output; `.pqcscan.yml` configuration; and
a composite GitHub Action that uploads SARIF to code scanning.
