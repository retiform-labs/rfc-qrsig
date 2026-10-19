"""Unit tests: canonical JSON, envelope codec, Ed25519 sign/verify.

Tamper cases are the load-bearing half: a signature tool is defined by
what it REFUSES as much as what it accepts.
"""

import base64
import json

import pytest

from qrsig import core


@pytest.fixture()
def keypair():
    return core.new_keypair()


def make_payload(pub_raw: bytes = None) -> dict:
    """A valid v1 payload. ``pub_raw`` ties the embedded key to the
    signer; the default placeholder is fine for shape-only tests."""
    return {
        "v": 1,
        "anchor": "example.org",
        "role": "Test Officer",
        "org": "Example Org",
        "doc_sha256": "a" * 64,
        "key_id": "qs1-test",
        "pubkey_b64": core.b64_encode(pub_raw if pub_raw is not None else bytes(range(32))),
        "signed_at": "2026-10-18T00:00:00Z",
    }


@pytest.fixture()
def payload():
    return make_payload()


class TestCanonical:
    def test_sorted_no_whitespace(self):
        assert core.canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_recursive_sort(self):
        assert core.canonical({"z": {"c": 1, "b": 2}, "a": 1}) == b'{"a":1,"z":{"b":2,"c":1}}'

    def test_nfc_normalization(self):
        # e + combining acute == precomposed e-acute under NFC
        assert core.canonical({"k": "café"}) == core.canonical({"k": "café"})

    def test_unicode_not_escaped(self):
        assert "café".encode() in core.canonical({"k": "café"})


class TestEnvelope:
    def test_roundtrip(self, keypair):
        priv, pub = keypair
        payload = make_payload(pub)
        env = core.sign_payload(priv, payload)
        uri = core.envelope_to_uri(env)
        parsed = core.parse_uri(uri)
        assert parsed["payload"] == payload
        assert parsed["sig_b64"] == env["sig_b64"]

    def test_uri_prefix(self, keypair):
        _, pub = keypair
        uri = core.envelope_to_uri(core.sign_payload(keypair[0], make_payload(pub)))
        assert uri.startswith("QRSIG1:")

    def test_parse_garbage_raises(self):
        with pytest.raises(ValueError):
            core.parse_uri("QRSIG1:!!!not-base64!!!")
        with pytest.raises(ValueError):
            core.parse_uri("NOSIG:abc")

    def test_parse_missing_fields_raises(self, keypair):
        # An envelope without sig_b64 must not silently verify later.
        bad = core.b64url_encode(json.dumps({"payload": {}}).encode())
        with pytest.raises(ValueError):
            core.parse_uri("QRSIG1:" + bad)


class TestSignVerify:
    def test_happy_path(self, keypair):
        priv, pub = keypair
        env = core.sign_payload(priv, make_payload(pub))
        ok, reason = core.verify_signature(env)
        assert ok, reason

    def test_external_pubkey(self, keypair):
        priv, pub = keypair
        env = core.sign_payload(priv, make_payload(pub))
        ok, reason = core.verify_signature(env, pubkey_raw=pub)
        assert ok, reason

    def test_tampered_payload_fails(self, keypair):
        priv, pub = keypair
        env = core.sign_payload(priv, make_payload(pub))
        env["payload"]["role"] = "Someone Else"
        ok, reason = core.verify_signature(env)
        assert not ok

    def test_tampered_sig_fails(self, keypair):
        priv, pub = keypair
        env = core.sign_payload(priv, make_payload(pub))
        raw = bytearray(base64.b64decode(env["sig_b64"]))
        raw[0] ^= 0xFF
        env["sig_b64"] = base64.b64encode(bytes(raw)).decode()
        ok, reason = core.verify_signature(env)
        assert not ok

    def test_wrong_key_fails(self, keypair):
        _, pub = keypair
        env = core.sign_payload(keypair[0], make_payload(pub))
        _, other_pub = core.new_keypair()
        ok, _ = core.verify_signature(env, pubkey_raw=other_pub)
        assert not ok

    def test_wrapper_not_signed(self, keypair):
        """THE canonical-JSON lesson: only payload is signed. Mutating the
        wrapper (outside payload) must not change verification."""
        priv, pub = keypair
        env = core.sign_payload(priv, make_payload(pub))
        env["extra_wrapper_field"] = "injected"
        ok, _ = core.verify_signature(env)
        assert ok  # wrapper is not part of the signed material - and not trusted either


class TestShape:
    def test_valid_payload(self, payload):
        assert core.validate_payload_shape(payload) == []

    def test_missing_anchor(self, payload):
        del payload["anchor"]
        assert any("anchor" in p for p in core.validate_payload_shape(payload))

    def test_bad_hash_case(self, payload):
        payload["doc_sha256"] = "A" * 64
        assert core.validate_payload_shape(payload)

    def test_bad_pubkey_length(self, payload):
        payload["pubkey_b64"] = core.b64_encode(bytes(16))
        assert core.validate_payload_shape(payload)

    def test_content_pair_required(self, payload):
        payload["content_method"] = "plain-text-v1"
        assert core.validate_payload_shape(payload)
        payload["content_sha256"] = "b" * 64
        assert core.validate_payload_shape(payload) == []


class TestSpki:
    def test_roundtrip_raw(self, keypair):
        _, pub = keypair
        assert core.spki_to_raw(_spki(pub)) == pub

    def test_rejects_garbage(self):
        with pytest.raises(ValueError):
            core.spki_to_raw(b"nope")


def _spki(raw: bytes) -> bytes:
    return bytes.fromhex("302a300506032b6570032100") + raw
