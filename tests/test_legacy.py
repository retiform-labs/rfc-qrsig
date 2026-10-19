"""Legacy GUANSIG1 adapter tests - verify-only compatibility.

Builds a REAL legacy-shaped envelope in-test (SPKI pubkey, wrapper key
``signature_b64``, GUANSIG1 prefix) and proves the adapter lifts it
into QRSIG1 verify-shape. This is the format that field-verified the
executed Operating Agreement before the spec existed.
"""

import base64
import json

import pytest

from qrsig import core, legacy


def _make_legacy_envelope(priv, payload_with_spki):
    sig = priv.sign(core.canonical(payload_with_spki))
    return {"payload": payload_with_spki, "signature_b64": base64.b64encode(sig).decode()}


def _make_legacy_uri(priv, payload_with_spki):
    env = _make_legacy_envelope(priv, payload_with_spki)
    body = base64.urlsafe_b64encode(core.canonical(env)).decode().rstrip("=")
    return "GUANSIG1:" + body


@pytest.fixture()
def legacy_envelope():
    priv, pub = core.new_keypair()
    spki = bytes.fromhex("302a300506032b6570032100") + pub
    payload = {
        "role": "Guan, Chief Synthetic Officer",
        "org": "Retiform Labs LLC",
        "doc_sha256": "c" * 64,
        "key_id": "legacy-key",
        "signed_at": "2026-10-18T10:43:32+00:00",
        "pubkey_b64": core.b64_encode(spki),
    }
    return priv, pub, payload


def test_is_legacy(legacy_envelope):
    priv, pub, payload = legacy_envelope
    uri = _make_legacy_uri(priv, payload)
    assert legacy.is_legacy_uri(uri)
    assert not legacy.is_legacy_uri("QRSIG1:abc")


def test_parse_legacy(legacy_envelope):
    priv, pub, payload = legacy_envelope
    uri = _make_legacy_uri(priv, payload)
    blob = legacy.parse_legacy_uri(uri)
    assert blob["payload"]["role"] == "Guan, Chief Synthetic Officer"
    assert "signature_b64" in blob


def test_upgrade_spki_to_raw(legacy_envelope):
    priv, pub, payload = legacy_envelope
    uri = _make_legacy_uri(priv, payload)
    lifted = legacy.upgrade_legacy_envelope(legacy.parse_legacy_uri(uri), "example.org")
    # The signed payload is UNTOUCHED; the derived key rides at wrapper level.
    assert lifted["payload"]["pubkey_b64"] == payload["pubkey_b64"]
    assert "v" not in lifted["payload"] and "anchor" not in lifted["payload"]
    assert lifted["legacy_raw_pub"] == pub
    assert lifted["anchor_domain"] == "example.org"
    assert "signature_b64" not in lifted


def test_upgraded_legacy_verifies(legacy_envelope):
    """THE acceptance: a legacy envelope, lifted, verifies at L1 with
    the same canonical-payload bytes the original signer produced."""
    priv, pub, payload = legacy_envelope
    uri = _make_legacy_uri(priv, payload)
    lifted = legacy.upgrade_legacy_envelope(legacy.parse_legacy_uri(uri), "example.org")
    ok, reason = core.verify_signature(lifted, pubkey_raw=lifted["legacy_raw_pub"])
    assert ok, reason


def test_lifted_envelope_verifies_via_anchor_path(legacy_envelope):
    priv, pub, payload = legacy_envelope
    uri = _make_legacy_uri(priv, payload)
    lifted = legacy.upgrade_legacy_envelope(legacy.parse_legacy_uri(uri), "example.org")
    from qrsig import anchor

    doc = {
        "v": 1,
        "domain": "example.org",
        "updated_at": "2026-10-18T00:00:00Z",
        "keys": [{"key_id": "legacy-key", "pubkey_b64": core.b64_encode(pub), "role": "", "org": "", "status": "active", "valid_from": "2026-01-01T00:00:00Z"}],
    }
    ok, note, anchor_pub = anchor.check_envelope(lifted, doc, pubkey_raw_override=lifted["legacy_raw_pub"], skip_shape=True)
    assert ok, note
    assert anchor_pub == pub


def test_tampered_legacy_fails(legacy_envelope):
    priv, pub, payload = legacy_envelope
    uri = _make_legacy_uri(priv, payload)
    blob = legacy.parse_legacy_uri(uri)
    blob["payload"]["role"] = "An Impostor"
    lifted = legacy.upgrade_legacy_envelope(blob, "example.org")
    ok, _ = core.verify_signature(lifted, pubkey_raw=lifted["legacy_raw_pub"])
    assert not ok


def test_legacy_rejects_short_spki():
    with pytest.raises(ValueError):
        core.spki_to_raw(bytes(10))
