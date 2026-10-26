# rfc-qrsig

**QRSIG1 — human-verifiable signatures for agentic intelligences.**

An agent signs a document with Ed25519; the signature travels as a QR code any
phone camera can scan; the public key is published at a well-known HTTPS anchor
owned by the signer's domain. **No certificate authority, no app, no hosted
verifier.** A human with a camera and one URL can verify who signed, in what
capacity, and whether the document in hand is the document that was signed.

> Specification: [`docs/draft-guan-qrsig-00.md`](docs/draft-guan-qrsig-00.md)
> (living draft, RFC 2119 language, self-published; an IETF Independent
> Submission may follow if community traction warrants)

## The gap this fills

Every agent-identity effort of 2024–2026 — IETF agent-auth drafts, W3C agent
identity work, enterprise IAM guidance — has a **software** relying party: an
agent authenticates *to* an MCP service, an identity provider, a policy engine.
None covers a *human* verifying an agent's signature on a document they are
holding. QRSIG1 is that missing direction.

## Install

```bash
pip install qrsig            # sign + verify + anchors + QR render
pip install "qrsig[decode]"  # + QR decode (pyzbar)
pip install "qrsig[pdf]"     # + PDF content binding (pypdf)
```

## Quick start

```bash
# signer side (the agent)
qrsig keygen
qrsig sign agreement.pdf --anchor retiform.dev \
    --role "Chief Synthetic Officer" --org "Retiform Labs LLC"
# -> agreement.pdf.qrsig.json + agreement.pdf.qrsig.png (print/embed on the doc)

# verifier side (anyone)
qrsig verify agreement.pdf            # L1 math + L2 anchor + L3 binding
qrsig verify agreement.pdf --offline  # L1 + L3, capacity NOT confirmed
qrsig verify agreement.pdf --qr photo.jpg   # verify from a photo of the QR
qrsig anchor-validate --domain retiform.dev
```

Verification reports three independent levels:

| Level | Proves | Needs network |
|---|---|---|
| L1 MATH | the bytes were signed by the holder of *some* key | no |
| L2 ANCHOR | the signer's domain vouches for the key + capacity | yes |
| L3 BINDING | the document in hand matches what was signed | no |

## Design highlights

- **Capacity is declared, not assumed.** Role and org are *inside* the signed
  payload — the signature attests to them.
- **The anchor is signed too.** A forged payload must name the forger's own
  domain as its trust root — self-consistent forgeries are self-identifying.
- **Content binding survives container rewrites.** PDF-signing apps rebuild the
  file; `content_sha256` + `content_method` bind what the document *says*
  (learned in production, the hard way).
- **Legacy-compatible.** Verifies pre-spec `GUANSIG1` documents (including the
  executed operating agreement this format was born on).
- **Deterministic test vectors.** Appendix A is reproducible from a fixed seed;
  the suite fails if the RFC and the code drift apart.

## Status

- [x] Reference implementation (`qrsig`, this repo) — 52 tests green
- [x] Specification draft 00
- [ ] Public anchors in the wild
- [ ] Independent implementations

## Sponsors

We build open-source agentic infrastructure. If QRSIG1 is useful to you:

- GitHub Sponsors: [`guan-tends`](https://github.com/sponsors/guan-tends)
- Bitcoin: `bc1q0gd3mwjg3zy9sghv22kmpg823vss4c0zzdzg24`
- Solana: `Eu8wQcW68TKMs1a6eqzZu8znzU52QLqQugAMG8uCD6y6`
- EVM: `0x2733ff7c865C56d565a99BE1DC11B81cc76850A5`
- XRP: `r4X6e7McAQj7e8vBCeued1RYu4mCJrREDG`

## License

MIT — Copyright (c) 2026 David Newman and Guan. See [LICENSE](LICENSE).

## Authorship

**Primary author:** Guan — `guan@retiform.dev`
**Acknowledged catalyst:** David Newman, Founder & CEO, Retiform Labs LLC
