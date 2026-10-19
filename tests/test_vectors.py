"""RFC conformance: the Appendix A test vectors MUST reproduce.

These vectors were generated from a fixed seed (bytes(range(32)))
and a fixed timestamp.  Any independent implementation of
draft-guan-qrsig-00 must derive the same bytes.  If this test
drifts from the RFC, THE RFC IS WRONG or the implementation is -
both are release blockers.
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qrsig import binding, core

SEED = bytes(range(32))
DOC_TEXT = "The party of the first part agrees to everything.\n\nSigned in the tent.\n"

EXPECTED = {
    "pubkey_raw_hex": "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    "pubkey_b64": "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
    "key_id": "qs1-56475aa75463474c",
    "doc_sha256": "5f59aadcd8efeca622dd8219fab621ed7b81e766416db67bc744b485c624fb41",
    "content_sha256": "a51a2a864f678c568c12f68d1d6294c8a5be1e0724039a036a559843a97a1203",
    "sig_b64": "w6LYNASO8RS8D6SNqN7KM0rHmdO7op6DDhqVPY4AlqAlX9oiMEQHrrYDXCNVjMvxK+pD56B79AZEBZizixCGDg==",
}


def _payload():
    priv = Ed25519PrivateKey.from_private_bytes(SEED)
    pub_raw = priv.public_key().public_bytes_raw()
    doc_bytes = DOC_TEXT.encode("utf-8")
    return priv, pub_raw, {
        "v": 1,
        "anchor": "example.org",
        "role": "Chief Synthetic Officer",
        "org": "Example Org",
        "doc_sha256": hashlib.sha256(doc_bytes).hexdigest(),
        "content_sha256": binding.content_digest(doc_bytes, "plain-text-v1"),
        "content_method": "plain-text-v1",
        "key_id": core.derive_key_id(pub_raw),
        "pubkey_b64": core.b64_encode(pub_raw),
        "signed_at": "2026-10-18T00:00:00Z",
    }


def test_vector_pubkey():
    _, pub_raw, _ = _payload()
    assert pub_raw.hex() == EXPECTED["pubkey_raw_hex"]
    assert core.b64_encode(pub_raw) == EXPECTED["pubkey_b64"]
    assert core.derive_key_id(pub_raw) == EXPECTED["key_id"]


def test_vector_hashes():
    doc_bytes = DOC_TEXT.encode("utf-8")
    assert hashlib.sha256(doc_bytes).hexdigest() == EXPECTED["doc_sha256"]
    assert binding.content_digest(doc_bytes, "plain-text-v1") == EXPECTED["content_sha256"]


def test_vector_signature():
    """THE conformance test: fixed seed + fixed payload = fixed sig."""
    priv, pub_raw, payload = _payload()
    env = core.sign_payload(priv, payload)
    assert env["sig_b64"] == EXPECTED["sig_b64"]
    # and it verifies
    ok, reason = core.verify_signature(env)
    assert ok, reason


def test_rfc_and_vectors_agree():
    """The vectors embedded in the RFC markdown must equal these
    constants - drift between doc and code is a release blocker.
    Comparison is whitespace-normalized: the RFC line-wraps long
    vectors for readability; wrapping is presentational, not drift."""
    rfc = "".join(open("docs/draft-guan-qrsig-00.md").read().split())
    for name, value in EXPECTED.items():
        assert "".join(value.split()) in rfc, "RFC missing vector: %s" % name
