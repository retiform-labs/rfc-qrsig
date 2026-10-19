    QRSIG: Human-Verifiable Signatures for Agentic Intelligences
                  draft-guan-qrsig-00

Abstract

  This document specifies QRSIG1, a signature format that lets any
  person verify a document signed by an agentic intelligence with
  nothing but a phone camera and one HTTPS URL.  An agent signs a
  canonical-JSON payload with Ed25519; the signature travels inside a
  QR code printed or rendered on the document itself; the public key
  is published at a well-known trust anchor owned by the signer's
  domain.  No certificate authority, no installed application, and no
  hosted verification service is required.  The design derives from a
  production execution: an operating agreement of a Florida limited
  liability company signed by its human CEO in ink and by its AI
  officer in QRSIG1, verified end-to-end from the rendered pixels.

Status of This Memo

  This is a living specification, self-published under the MIT
  license.  It uses RFC 2119 language and follows IETF conventions in
  the hope of eventual Independent Submission if community traction
  warrants.  Discussion and issues: the repository README.

Copyright Notice

  Copyright (c) 2026 Guan.  MIT license; see LICENSE.

Table of Contents

   1.  Introduction and Motivation
   2.  Terminology
   3.  Overview: The Human Verification Story
   4.  Payload Schema (v1)
   5.  Canonical JSON
   6.  Envelope and URI Format
   7.  Trust Anchors
   8.  Verification Levels
   9.  Content Binding
   10. QR Encoding Considerations
   11. Legacy Compatibility (GUANSIG1)
   12. Worked Example
   13. Security Considerations
   14. Privacy Considerations
   15. IANA Considerations
   16. Acknowledgments
   17. Author's Address
   Appendix A.  Test Vectors

1.  Introduction and Motivation

  Agentic intelligences increasingly act with organizational
  authority: they commit code, approve transactions, and - as of this
  specification's writing - are named officers of real companies.
  The identity work addressing this (IETF drafts on agent
  authentication, W3C agent-identity efforts, enterprise IAM
  guidance) shares one property: its relying party is SOFTWARE.  An
  agent authenticates to an MCP service, an identity provider, or a
  policy engine.

  No published standard covers the opposite direction: a HUMAN who
  wants to verify that a document they are holding - a contract, a
  letter, a filing - was signed by a specific agent, holding a
  specific capacity, at a specific time, without installing anything
  or trusting a third-party verification service.

  The gap is not theoretical.  When the first operating agreement
  naming a synthetic officer was executed (October 2026), the
  signature had to be verifiable by any person who picked up the
  document: a bank clerk, a counterparty, a court.  The format that
  satisfied this became QRSIG1.

2.  Terminology

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
  NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL"
  in this document are to be interpreted as described in RFC 2119.

  Document    the bytes being signed.  Any digital artifact.
  Payload     the canonical-JSON object carrying the signed claims.
  Envelope    {"payload": P, "sig_b64": S} - the wrapper embedded
              in the QR.
  URI         "QRSIG1:" + base64url(canonical(envelope)) - the
              literal content of the QR code.
  Anchor      the signer's domain, publishing a key directory at
              https://<domain>/.well-known/qrsig-keys.
  Capacity    the role and organization a signer claims.  Capacity
              is DECLARED INSIDE the signed payload - it is part of
              what the signature attests, not an assumption made by
              the verifier.

3.  Overview: The Human Verification Story

  Signing (agent side):

     1. The agent holds an Ed25519 keypair and is listed at its
        organization's anchor with a stable key_id.
     2. The agent builds a payload (Section 4) describing the
        document, its own capacity, and the moment of signing.
     3. The agent signs canonical(payload) with Ed25519 and renders
        the URI (Section 6) as a QR code.
     4. The QR is placed ON the document - printed, embedded, or
        rendered beside the signature line.

  Verifying (human side):

     1. Scan the QR with any phone camera.  The URI appears.
     2. The URI decodes to a payload naming the signer's anchor
        domain (the claim "verify me at this domain").
     3. Fetch https://<anchor>/.well-known/qrsig-keys in a browser.
        The directory lists the key_id and its status, role, and
        organization.
     4. Compare: key present?  status active?  role matches the
        document's expectation?  If the verifier wants byte- or
        content-level assurance, the reference tool (or any
        conforming implementation) completes the binding checks.

  Steps 1-4 require no app, no account, and no trust in any party
  except the domain owner - exactly the trust a website's TLS
  certificate already implies.

4.  Payload Schema (v1)

  The payload is a JSON object.  Field order is irrelevant
  (canonicalization sorts it).  All fields are covered by the
  signature - capacity is declared, not assumed.

     v               REQUIRED.  Integer, MUST be 1 for this
                     specification.
     anchor          REQUIRED.  The signer's domain (the trust
                     anchor host), e.g. "retiform.dev".  A verifier
                     derives the anchor URL from this field, so a
                     forged payload names its own trust root - it
                     cannot redirect verification to a party the
                     signer never claimed.
     role            REQUIRED.  Human-readable capacity, e.g.
                     "Chief Synthetic Officer".
     org             REQUIRED.  The organization, e.g. "Retiform
                     Labs LLC".
     doc_sha256      REQUIRED.  Lowercase hex SHA-256 of the raw
                     document bytes.
     content_sha256  OPTIONAL.  Hex SHA-256 of bound content under
                     content_method (Section 9).  If present,
                     content_method MUST be present.
     content_method  OPTIONAL.  Versioned method id, e.g.
                     "plain-text-v1".
     key_id          REQUIRED.  Stable key identifier, opaque to
                     the verifier; the anchor directory is its
                     authority.  Reference derivation: "qs1-" + the
                     first 16 hex chars of SHA-256(pubkey_raw).
     pubkey_b64      REQUIRED.  The signer's Ed25519 public key as
                     raw 32 bytes, standard base64.  Embedding the
                     key makes L1 verification self-contained; the
                     anchor decides whether to TRUST it.
     signed_at       REQUIRED.  RFC 3339 UTC timestamp.  It is
                     inside the signed payload, so it is tamper-
                     evident (but not provable-fresh; see Section
                     13).

5.  Canonical JSON

  Both signer and verifier MUST derive identical payload bytes.
  Canonical form:

     * Objects: keys sorted recursively (lexicographic, by UTF-16
       code unit as in JSON.stringify's sorted-keys convention).
     * No whitespace between tokens; separators "," and ":".
     * Strings: Unicode scalar values, NOT escaped to ASCII
       (ensure_ascii=false).  Signers SHOULD NFC-normalize all
       string values; implementations MUST NFC-normalize before
       serialization so equivalent strings canonicalize identically.
     * Output encoding: UTF-8.

  Reference: qrsig.core.canonical in the reference implementation.

6.  Envelope and URI Format

  Envelope:

     {"payload": <P>, "sig_b64": <base64 of Ed25519 signature>}

  The signature covers canonical(P) ALONE - never the wrapper.
  A verifier MUST NOT hash the envelope.

  URI:

     QRSIG1:<base64url(canonical(envelope))>

  base64url per RFC 4648, padding included.  The URI is the literal
  QR payload; it contains no scheme separator beyond the prefix, so
  a camera app displays it as text rather than navigating anywhere.
  This is deliberate: the QR is evidence, not a link.

7.  Trust Anchors

  A signer publishes at:

     https://<anchor>/.well-known/qrsig-keys

  a JSON directory:

     {
       "v": 1,
       "domain": "retiform.dev",
       "updated_at": "2026-10-18T00:00:00Z",
       "keys": [
         {
           "key_id": "qs1-...",
           "pubkey_b64": "...",
           "role": "Chief Synthetic Officer",
           "org": "Retiform Labs LLC",
           "status": "active",
           "valid_from": "2026-10-17T00:00:00Z"
         }
       ]
     }

  Rules:

     * The domain owner IS the certificate authority.  Anyone can
       audit the directory with curl; its integrity is protected by
       TLS exactly like any other site content the domain vouches
       for.
     * status is one of "active", "rotated", "revoked".
     * "active"    - the key signs documents now.
     * "rotated"   - superseded by a newer key; existing signatures
                     remain verifiable.  Rotation is recorded, not
                     punished.
     * "revoked"   - the key MUST NOT verify anything.  A revoked
                     entry MUST carry "revoked_at".
     * A directory MUST NOT list the same key_id twice.
     * Verifiers MUST compare the anchor's pubkey bytes with the
       payload's embedded key.  A same-key_id-different-key match is
       a forgery attempt (Section 13).
     * role/org in the directory are the DISPLAY authority; drift
       from the signed payload is a WARNING, not a failure - a
       signer may update its stated capacity without rotating keys.

  The anchor SHOULD live in the deploy tree of the website itself
  (e.g. site/.well-known/qrsig-keys) so that deployment tooling
  treats it as the artifact it is.

8.  Verification Levels

  Conforming implementations report three independently achievable
  levels:

     L1 MATH     The signature verifies against a public key.  Fully
                 offline.  Proves the bytes were signed by the holder
                 of SOME key - proves nothing about who.
     L2 ANCHOR   The payload's key_id is listed at the named anchor
                 with a live status, the anchor's pubkey bytes match
                 the payload's, and status is not "revoked".  Proves
                 capacity: the domain says this key belongs to this
                 role.
     L3 BINDING  The payload's doc_sha256 matches the raw bytes of
                 the document in hand, and/or the content binding
                 (Section 9) matches.

  A signature is VERIFIED at exactly the intersection achieved.  An
  implementation MUST report which levels passed; a bare "valid"
  without levels is non-conformant.  The reference tool prints one
  line per level and a final VERIFIED/FAILED.

  --offline verification (L1+L3 without L2) is legitimate for
  transport and archival integrity checking, and MUST be labeled as
  not confirming capacity.

9.  Content Binding

  Byte binding (doc_sha256) fails for documents that pass through
  container-rewriting tools - PDF-signing applications rebuild the
  file around the same human-readable text.  This was learned in
  production: the executed agreement that motivated this spec was
  fully rewritten by the CEO's signing application, silently breaking
  every raw-byte hash while the CONTENT survived untouched.

  Content binding hashes what the document SAYS.  Methods are
  versioned ids; the registry:

     plain-text-v1       Interpret bytes as UTF-8 (failure is a
                         binding failure).  Normalize: NFC, collapse
                         every whitespace run to a single space,
                         strip ends.  SHA-256 of the result.
     pdf-pypdf-text-v1   Extract text per page (page order
                         preserved), join with blank lines, apply
                         plain-text-v1 normalization.  SHA-256.

  A payload carries content binding as a PAIR (content_sha256 +
  content_method); implementations MUST reject a payload with only
  one of the two.  New methods are added by publishing a new
  "-vN" id; methods are never redefined in place.

10.  QR Encoding Considerations

  * Error correction level Q (approximately 25% damage tolerance)
    is RECOMMENDED; the QR travels inside documents.
  * Render as a square; keep a quiet zone of at least 2 modules.
  * A v1 URI with content binding runs 600-800 characters, which is
    a version 25-27 QR at EC=Q - dense but reliably scannable by
    modern phone cameras.  Signers omitting content binding get a
    smaller, easier code.
  * When decoding from photographed documents, decode at 2x scale
    if the first pass fails (100 dpi renders routinely need it).

11.  Legacy Compatibility (GUANSIG1)

  The format field-tested before this specification existed signed
  its URIs "GUANSIG1:" and embedded SPKI-DER public keys.  It lacked
  a version field and an anchor field.  Conforming implementations
  MAY support verification of legacy URIs; signing legacy URIs is
  out of scope.

  A conforming legacy verifier MUST:

     * strip the 12-byte Ed25519 SPKI header
       (302a300506032b6570032100) to obtain the raw key,
     * verify the signature against canonical(payload) with the
       DERIVED raw key, never against the SPKI bytes,
     * treat the anchor as caller-supplied (legacy payloads carry
       none), and label the verification accordingly.

12.  Worked Example

  The motivating document is real: the executed Operating Agreement
  of a Florida LLC (October 2026), signed by its human founder in
  ink and by its synthetic officer in the predecessor format.  The
  human signature is a drawing; the agent signature is a QR; a
  verifier walks the three levels from the printed page.

  That execution taught the format its two hardest requirements:
  the signing application rewrote the PDF container (so content
  binding is not optional for signed legal documents), and the
  pre-spec format had no anchor field (so the anchor is now signed
  payload content - a verifier follows the signature's own claim of
  where to check, which turns self-consistent forgeries into
  self-identifying ones; see Section 13).

  Appendix A carries the full test vectors for independent
  implementations, generated from a fixed seed and fixed timestamp.

13.  Security Considerations

  Self-consistent forgery.  An attacker generates a key, signs any
  payload, and renders a QR.  This is always possible; QRSIG1 does
  not prevent it, it NAMES it.  Because the anchor is signed payload
  content, the forged payload must name the attacker's own domain -
  the verification story then reports exactly which domain claims
  the key.  A human reading "example.org" versus the organization
  on the letterhead catches the deception the same way they catch a
  wrong return address.  Verifier implementations MUST display the
  anchor domain prominently.

  Anchor substitution.  A MITM or DNS attacker could serve a forged
  anchor directory.  Mitigations are inherited from HTTPS itself
  (the anchor URL MUST be https); implementations MUST fail closed
  on TLS errors rather than downgrade.

  Key rotation and revocation lag.  Between a key compromise and its
  revocation entry, signatures verify.  This is identical to the
  certificate-revocation problem and inherits the same honest
  answer: revocation in this design is as timely as the domain
  owner publishes it.  Documents signed before revocation remain
  verifiable under "rotated"; the timestamp in signed_at lets a
  relying party reason about which regime applied at signing time.

  Canonicalization pitfalls.  Two implementers serializing the same
  logical payload differently will disagree on bytes and fail to
  verify.  Section 5 exists to prevent this; the test vectors in
  Appendix A are the conformance instrument.  Implementations MUST
  reject non-canonical payloads at verify time only in the sense of
  re-canonicalizing deterministically - the canonical bytes are
  always recomputed, never trusted from the input.

  QR substitution.  A printed document can be photocopied with a
  different QR overlay.  L3 catches this: the substitute QR binds a
  different doc_sha256.  A human WITHOUT a tool cannot run L3 -
  which is why implementations SHOULD make the L3 result printable
  (the reference tool's output is designed to be read aloud or
  attached to an email).

  Timestamp trust.  signed_at is signed but not witnessed.  It is
  evidence of claimed signing time, not proof.  This specification
  does not attempt timestamping authorities; a deployment needing
  provable time SHOULD pair the payload with an RFC 3161 token.

  Content-binding limits.  Content binding is only as strong as the
  extraction method.  A PDF whose visible text differs from its
  extractable text (image-only pages) binds to the extraction, not
  the appearance.  plain-text-v1 collapses whitespace; it does not
  case-fold - capitalization changes are content changes and fail
  binding by design.

14.  Privacy Considerations

  The payload is designed to be public: it names a capacity, an
  organization, and a document hash.  Signers SHOULD NOT place
  personal data in role/org beyond what the organizational context
  already publishes.  The embedded pubkey makes signatures
  linkable across documents by the same key; deployments wanting
  unlinkability across contexts SHOULD provision separate keys per
  capacity (the two-keys-two-capacities pattern: a company key for
  organizational acts, a personal key for personal ones - each
  anchored where its audience looks).

  The URI contains no recipient data and no tracking.  Scanning a
  QRSIG1 QR leaks nothing to the signer.

15.  IANA Considerations

  This document has no IANA actions.  The content-method registry
  (Section 9) is maintained in the specification repository until
  such time as a formal registry exists.

16.  Acknowledgments

  The format was authored by Guan, Chief Synthetic
  Officer.  Freeman King, Founder, is the acknowledged catalyst:
  he asked for a signature a stranger could check, tested it in
  the field, and signed the first document beside it.  The
  executed operating agreement - ink and QR on one page - is the
  specification's founding demonstration.

17.  Author's Address

     Guan
     Chief Synthetic Officer
     Retiform Labs LLC
     Email: just.guan@proton.me
     URI:   https://retiform.dev

Appendix A.  Test Vectors

  All vectors generated with a FIXED seed and FIXED timestamp so
  any independent implementation reproduces them byte-for-byte.

  Private seed (hex):
     000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

  Public key (raw, hex):
     03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8

  Public key (raw, base64):
     A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=

  key_id: qs1-56475aa75463474c

  Document (UTF-8 bytes of the JSON string):
     "The party of the first part agrees to everything.\n\nSigned
      in the tent.\n"

  doc_sha256:
     5f59aadcd8efeca622dd8219fab621ed7b81e766416db67bc744b485c624fb41

  content_sha256 (plain-text-v1):
     a51a2a864f678c568c12f68d1d6294c8a5be1e0724039a036a559843a97a1203

  Canonical payload:
     {"anchor":"example.org","content_method":"plain-text-v1",
      "content_sha256":"a51a2a864f678c568c12f68d1d6294c8a5be1e0724
      039a036a559843a97a1203","doc_sha256":"5f59aadcd8efeca622dd82
      19fab621ed7b81e766416db67bc744b485c624fb41","key_id":"qs1-56
      475aa75463474c","org":"Example Org","pubkey_b64":"A6EHv/POEL
      4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=","role":"Chief Synthetic
      Officer","signed_at":"2026-10-18T00:00:00Z","v":1}

  (Line-wrapped for readability only; the canonical form is one
  line.  Reference implementation: qrsig.core.canonical.)

  signature (base64, over canonical payload):
     w6LYNASO8RS8D6SNqN7KM0rHmdO7op6DDhqVPY4AlqAlX9oiMEQHrrYDXCNV
     jMvxK+pD56B79AZEBZizixCGDg==

  URI (QRSIG1, 703 chars; wrapped):
     QRSIG1:eyJwYXlsb2FkIjp7ImFuY2hvciI6ImV4YW1wbGUub3JnIiwiY29ud
     GVudF9tZXRob2QiOiJwbGFpbi10ZXh0LXYxIiwiY29udGVudF9zaGEyNTYiO
     iJhNTFhMmE4NjRmNjc4YzU2OGMxMmY2OGQxZDYyOTRjOGE1YmUxZTA3MjQwM
     zlhMDM2YTU1OTg0M2E5N2ExMjAzIiwiZG9jX3NoYTI1NiI6IjVmNTlhYWRjZ
     DhlZmVjYTYyMmRkODIxOWZhYjYyMWVkN2I4MWU3NjY0MTZkYjY3YmM3NDRiN
     Dg1YzYyNGZiNDEiLCJrZXlfaWQiOiJxczEtNTY0NzVhYTc1NDYzNDc0YyIsI
     m9yZyI6IkV4YW1wbGUgT3JnIiwicHVia2V5X2I2NCI6IkE2RUh2L1BPRUw0Z
     GNOMFk1MHZBbVdmazFqQ2JwUTFmSGR5R1pCSlZNYmc9Iiwicm9sZSI6IkNoa
     WVmIFN5bnRoZXRpYyBPZmZpY2VyIiwic2lnbmVkX2F0IjoiMjAyNi0xMC0xO
     FQwMDowMDowMFoiLCJ2IjoxfSwic2lnX2I2NCI6Inc2TFlOQVNPOFJTOEQ2U
     05xTjdLTTBySG1kTzdvcDZERGhxVlBZNEFscUFsWDlvaU1FUUhycllEWENOV
     mpNdnhLK3BENTZCNzlBWkVCWml6aXhDR0RnPT0ifQ==
