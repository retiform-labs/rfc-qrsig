# Changelog

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
