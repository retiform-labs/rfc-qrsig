# Changelog

## v0.1.4 - 2026-11-17

Two changes: an **L3 conformance fix that unblocks every
self-signed document**, and a hardening pass in which every public entry
point that reads attacker-controlled bytes refuses instead of crashing.

### Fixed (L3 conformance - the headline)

- **L3 was an AND where the spec says OR, which made every embedded
  signature permanently unverifiable.** Spec section 8 reads: *doc_sha256
  matches ... **and/or** the content binding matches*. The implementation
  required both. A document that carries its own signature CANNOT carry a
  hash of itself, so doc_sha256 is necessarily absent for exactly the
  placement that is most useful - and the AND turned that into a hard FAIL.
  Confirmed against a real executed instrument: our own Operating Agreement
  amendment reported FAILED under 0.1.3 while its content binding passed.
  - **New required payload field signature_placement**: detached
    (signature lives beside the document; doc_sha256 required) or
    embedded (signature lives inside the document; doc_sha256 MUST be
    absent and the content binding MUST be present). The spec now requires a
    signer to state which it produced rather than leaving a verifier to infer
    it from absent fields.
  - **doc_sha256 is now CONDITIONALLY required** rather than always, and
    the CLI reports the two legs separately as L3a byte binding and
    L3b content binding.
  - **N/A is not a pass.** The first cut of this fix set the byte leg to
    True for embedded signatures, so a text-tampered document still printed
    VERIFIED. The embedded verdict now rides on the content binding ALONE:
    l3 = content_ok. Two regression tests pin it.
  - --placement on qrsig sign, defaulting to detached so existing
    callers are unaffected.

### Fixed (packaging)

- **The PDF content binding died with a bare ModuleNotFoundError.** pypdf
  is a declared optional extra (qrsig[pdf]), which is correct - a base
  install should not drag a PDF library - but nothing caught the absence, so
  the tool headline use case on its most common file type ended in a
  traceback with exit 1. It now raises with actionable guidance and the CLI
  exits 2 with: PDF content binding needs the optional extra: pip install
  qrsig[pdf]. A missing dependency is not a verification verdict and must
  never be silently reported as one.

### Fixed (defects)

- **`canonical()` did not NFC-normalize dict KEYS.** It normalized values
  only, so an NFC-spelled key and an NFD-spelled key produced different
  canonical bytes - a signature-malleability hole in the one function whose
  entire purpose is determinism, and a direct contradiction of this module's
  own docstring. Keys now normalize too. A payload whose two DISTINCT keys
  collide after normalization raises `ValueError` instead of silently
  collapsing one, since which entry survived would otherwise depend on
  insertion order.
- **`validate_payload_shape` accepted `v = True` and `v = 1.0`.** `True == 1`
  and `1.0 == 1` in Python, so a bare `!=` let a non-integer version pass.
  Now type-checked. `anchor.validate_directory` carried the identical
  expression and was fixed in lockstep - two validators disagreeing about
  the same field is worse than both being permissive.
- **`validate_payload_shape` crashed on hostile field types.** `doc_sha256`
  as a list raised `AttributeError`, as an int raised `TypeError`; a
  non-dict payload raised `AttributeError`. It is documented to return a
  list of problems and never raise, and the payload is attacker-controlled.
- **`doc_sha256` accepted non-hex.** The old check was "64 chars and already
  lowercase", which passes a string of 64 z characters. Now an anchored hex
  regex, applied to `content_sha256` as well.
- **`signed_at` accepted any string, including non-UTC offsets.** Now shape-
  checked as RFC 3339 UTC, with a calendar check for impossible dates.
- **`verify_signature` raised instead of returning `(False, reason)`** on
  hostile envelope shapes (non-dict payload, non-string `sig_b64`, any
  non-JSON-serialisable payload value). On the CLI path that was a traceback
  where a `FAILED` line belongs.
- **`lookup_key` failed OPEN on an unrecognized `status`.** Any value other
  than `revoked`/`rotated` - including `compromised`, `ACTIVE`, the empty
  string, or an absent field - was treated as active and therefore trusted.
  Now fails closed, matching the spec's closed three-value vocabulary. This
  is the one deliberate behaviour change in the pass.
- **`lookup_key` / `validate_directory` / `check_envelope` crashed on a
  malformed anchor document** (`keys` as a dict, a list of strings, a
  non-dict entry). `lookup_key` is reachable from `check_envelope` with no
  validation gate in between, so it is hardened directly.
- **`qrcode.render_png_bytes` skipped the `QRSIG1:` prefix check that
  `render_png` enforces.** The two are documented mirrors; the asymmetry let
  a pipeline encode an arbitrary attacker-chosen string as a QR. Both paths
  now share one guard, and the message names the offending value.
- **`qrsig qr` crashed when `--out` was omitted**, though `--help` presents
  the flag as optional. Now derives the sibling `.qrsig.png`.
- **`qrsig sign` on a missing document, `qrsig decode` on a non-image, and
  `qrsig anchor-validate` with neither `--domain` nor `--url`** all raised
  tracebacks. All are clean `error:` messages with exit 2 now, matching the
  `_die` convention already used elsewhere in the CLI.
- **`anchor.fetch` reached any URI scheme, including `file://`.** With
  `require_https=False` - the documented escape hatch for a local test server
  or a self-hosted registry - the only scheme check was skipped entirely, so an
  `--anchor-url file:///etc/hostname` would read and parse a local file. The
  scheme gate is now ALWAYS on and admits only http and https; `require_https`
  raises the bar from that to https-only rather than replacing it.
- **`anchor` in a signed payload was never shape-checked.** It is signed
  content a verifier feeds straight into a URL fetch, so a newline, space,
  slash or `@` in it is a URL/header-injection attempt. `validate_payload_shape`
  now requires a bare hostname (letters, digits, dots, hyphens, an optional
  port, bracketed IPv6). Relying on urllib to reject it was not a defence - it
  raised `InvalidURL` only after the request object had already been built.
- **Uppercase URL schemes were refused for their case alone.** `HTTPS://` is a
  legitimate https URL (RFC 3986 makes schemes case-insensitive) and was being
  rejected by a case-sensitive `startswith`. The scheme is normalised before
  the check now, so `FILE://` is still refused and `HTTPS://` is not.
- **`qrsig verify --offline` printed two contradictory L2 lines**, the second
  claiming the payload carried no anchor while it demonstrably did. One
  true line now.

### Added (tests)

- Three adversarial test modules - `test_adversarial_core.py`,
  `test_adversarial_anchor.py`, `test_adversarial_cli.py` - covering hostile
  URIs, hostile payloads, hostile anchor documents, key substitution, status
  semantics, QR round-trip integrity, and the CLI exit-code contract.
- Every defect above has a test that was watched going RED with the fix
  reverted, not merely green with it in place.
- The self-consistent-forgery property is now pinned: an attacker can build
  an envelope that passes L1, and our anchor directory must refuse it.
- Suite: 64 to 355 passing (1 skipped, pre-existing). Coverage 82% to 94%.

### Known gaps (documented, deliberately not repaired)

Each is pinned by a test that will flip loudly when someone fixes it.

- `check_envelope` does not bind `payload["anchor"]` to `anchor_doc["domain"]`.
  Not a live bypass: the verifier derives the fetch URL from the payload's own
  anchor, and the CLI separately guards with validate_directory(expect_domain).
- A revocation applied by APPENDING a second, revoked entry for the same
  key_id is ignored - lookup_key returns the first match. An operator footgun,
  not an attacker capability.
- valid_from is never enforced; no expiry field exists anywhere.
- revoked_at only has to be truthy, not a parseable date.

## v0.1.3 - 2026-10-28

- Fixed `qrsig --version` reporting 0.1.0. `__init__.py` hardcoded the string
  at the initial commit and it was never bumped, so 0.1.1 and 0.1.2 both
  claimed to be 0.1.0. `__version__` now reads from installed package
  metadata, with an explicit 0.0.0+unknown fallback for an uninstalled source
  tree.
- Added tests pinning the drift class: the version string must equal installed
  metadata, and the --version flag must report it.

0.1.2 shipped with the stale version string because it was found only after
that artifact was published and PyPI has no yank API. No functional or
wire-format changes in 0.1.3.

## v0.1.2 - 2026-10-28

- Dropped Python 3.9 (end-of-life October 2025). requires-python is now >=3.10:
  3.9 cannot be installed on current runners, so advertising support for it was an
  untestable claim rather than a supported one.
- CI matrix widened to 3.10 / 3.11 / 3.12 / 3.13 - every supported version is now
  actually exercised.
- Package metadata author corrected to Guan <guan@retiform.dev> alone. Both
  addresses remain on LICENSE, per the retiform address policy: legal surfaces
  carry both parties, package metadata carries one.

## v0.1.1 - 2026-10-26

- Moved public identity addresses to retiform.dev across LICENSE and package
  metadata, and carried that identity into the published artifact.

## v0.1.0 — 2026-10-18

Initial release of the QRSIG1 reference implementation and specification.

### Specification
- `docs/draft-guan-qrsig-00.md`: the QRSIG1 draft (RFC 2119; envelope
  format, canonical JSON, payload schema, trust anchors, L1/L2/L3
  verification levels, content binding, legacy GUANSIG1 compatibility,
  security + privacy considerations, deterministic test vectors in
  Appendix A).

### Implementation
- `qrsig.core` — canonical JSON (sorted keys, NFC, no whitespace),
  Ed25519 envelope (signature covers canonical(payload) alone),
  QRSIG1 URI codec, key-id derivation, payload shape validation.
- `qrsig.binding` — content-level document binding: `plain-text-v1`,
  `pdf-pypdf-text-v1` (survives container-rewriting PDF apps).
- `qrsig.anchor` — well-known key directory fetch/validate, trust
  lookup with active/rotated/revoked statuses, pubkey-forgery check.
- `qrsig.legacy` — verify-only GUANSIG1 adapter (SPKI-strip at wrapper
  level; never mutates the signed payload).
- `qrsig.qrcode` — segno render (EC level Q) + pyzbar decode (2x retry).
- `qrsig.cli` — `keygen | sign | verify | qr | decode | anchor-validate`;
  sidecar artifacts; offline mode.

### Tooling
- GitHub Actions CI (Python 3.9/3.11/3.12), opsec preflight gate +
  pre-commit hook (injected, never-committed marker list), FUNDING.yml,
  57-test suite incl. RFC conformance vectors from a fixed seed.

### Verified in the field
- The executed Operating Agreement that motivated the format verifies
  at L1 through the legacy adapter; its byte-binding failure is the
  container-rewrite lesson that motivated content binding, reproduced
  live (see RFC §9 and §12).
