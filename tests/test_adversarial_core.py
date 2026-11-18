"""Adversarial and regression hardening tests for qrsig.core.

Every test here exists because the code, as it shipped before this
suite, either crashed on attacker-controlled input, accepted something
the spec says it must refuse, or produced two different answers for
equivalent input.

The two failure classes are different in kind and both matter:

  * A verifier that RAISES on hostile input is a denial of service. Its
    contract is a (ok, reason) tuple; an exception escaping it is not a
    stricter verifier, it is a broken one, because a caller reading only
    the boolean never sees it and a caller that does not expect it dies.
  * A canonicaliser that yields two byte strings for one payload is a
    malleability hole. The whole point of canonical form is that the
    signature commit to one representation per document.

Falsifier discipline: every defect test in this file was watched go RED
against the pre-fix qrsig/core.py before it was accepted as green. A
test that was never observed failing is not a regression test.
"""

import base64
import json

import pytest

from qrsig import core


# --------------------------------------------------------------------------
# Fixtures and helpers.
#
# Deliberately self-contained apart from the shared keypair fixture, so a
# defect can be re-proved against a pre-fix core.py in an isolated copy of
# the package without touching the live checkout.
# --------------------------------------------------------------------------

RFC_DOC_SHA256 = "5f59aadcd8efeca622dd8219fab621ed7b81e766416db67bc744b485c624fb41"
RFC_CONTENT_SHA256 = "a51a2a864f678c568c12f68d1d6294c8a5be1e0724039a036a559843a97a1203"
RFC_KEY_ID = "qs1-56475aa75463474c"
RFC_PUBKEY_B64 = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="

# Exactly the bytes the Appendix A payload canonicalises to. Every key and
# value in it is ASCII, so NFC normalisation is the identity on all of
# them. That makes this pin do double duty: RFC conformance, AND proof
# that normalising dict keys changed no existing signature's bytes.
RFC_CANONICAL = (
    b'{"anchor":"example.org","content_method":"plain-text-v1",'
    b'"content_sha256":"a51a2a864f678c568c12f68d1d6294c8a5be1e0724039a036a559843a97a1203",'
    b'"doc_sha256":"5f59aadcd8efeca622dd8219fab621ed7b81e766416db67bc744b485c624fb41",'
    b'"key_id":"qs1-56475aa75463474c","org":"Example Org",'
    b'"pubkey_b64":"A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",'
    b'"role":"Chief Synthetic Officer","signed_at":"2026-10-18T00:00:00Z","v":1}'
)

SPKI_HEADER = bytes.fromhex("302a300506032b6570032100")


@pytest.fixture()
def keypair():
    return core.new_keypair()


def make_payload(pub_raw=None, **overrides):
    """A payload the shape validator accepts. Overrides patch one field."""
    payload = {
        "v": 1,
        "anchor": "example.org",
        "role": "Test Officer",
        "org": "Example Org",
        "doc_sha256": "a" * 64,
        "signature_placement": "detached",
        "key_id": "qs1-test",
        "pubkey_b64": core.b64_encode(pub_raw if pub_raw is not None else bytes(range(32))),
        "signed_at": "2026-10-18T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def signed_envelope(keypair):
    priv, pub = keypair
    return core.sign_payload(priv, make_payload(pub))


# --------------------------------------------------------------------------
# R0. Byte stability. The key-normalisation fix must be invisible to every
# signature that already exists.
# --------------------------------------------------------------------------


class TestCanonicalByteStability:

    def test_rfc_vector_canonical_bytes_are_unchanged(self):
        """The Appendix A payload must still canonicalise to these bytes.

        If this fails, the key-normalisation change altered the signed
        material of a published vector - which would invalidate every
        signature made by any conforming implementation.
        """
        payload = {
            "v": 1,
            "anchor": "example.org",
            "role": "Chief Synthetic Officer",
            "org": "Example Org",
            "doc_sha256": RFC_DOC_SHA256,
            "content_sha256": RFC_CONTENT_SHA256,
            "content_method": "plain-text-v1",
            "key_id": RFC_KEY_ID,
            "pubkey_b64": RFC_PUBKEY_B64,
            "signed_at": "2026-10-18T00:00:00Z",
        }
        assert core.canonical(payload) == RFC_CANONICAL


# --------------------------------------------------------------------------
# R1. The canonicalisation bug: dict KEYS were never normalised.
# --------------------------------------------------------------------------


class TestCanonicalKeyNormalization:
    """canonical() normalised every string VALUE and passed dict KEYS through.

    Consequence: two payloads that are equivalent Unicode canonicalised to
    different byte strings, so one document could carry two different valid
    signatures depending on how a key's spelling arrived. That is precisely
    the signature malleability canonical form exists to prevent.
    """

    def test_nfc_and_nfd_key_spellings_produce_identical_bytes(self):
        precomposed = {"caf\u00e9": 1}
        decomposed = {"cafe\u0301": 1}
        assert list(precomposed) != list(decomposed), "fixture premise: distinct spellings"
        assert core.canonical(precomposed) == core.canonical(decomposed), (
            "NFC and NFD spellings of one key produced different canonical bytes: "
            "%r vs %r" % (core.canonical(precomposed), core.canonical(decomposed))
        )

    def test_value_normalisation_control_still_holds(self):
        """The control that already passed before the fix - it must keep passing."""
        assert core.canonical({"k": "caf\u00e9"}) == core.canonical({"k": "cafe\u0301"})

    def test_keys_are_normalised_in_nested_objects(self):
        a = {"outer": {"caf\u00e9": 1}}
        b = {"outer": {"cafe\u0301": 1}}
        assert core.canonical(a) == core.canonical(b)

    def test_keys_are_normalised_inside_lists(self):
        a = {"items": [{"caf\u00e9": 1}]}
        b = {"items": [{"cafe\u0301": 1}]}
        assert core.canonical(a) == core.canonical(b)

    def test_distinct_keys_that_normalise_together_raise(self):
        """Silently collapsing one of two colliding keys makes the survivor
        depend on insertion order - the deterministic answer is to refuse."""
        ambiguous = {"caf\u00e9": 1, "cafe\u0301": 2}
        assert len(ambiguous) == 2, "fixture premise: two distinct keys"
        with pytest.raises(ValueError) as excinfo:
            core.canonical(ambiguous)
        assert "ambiguous" in str(excinfo.value), (
            "collision must be reported as ambiguity, got: %s" % excinfo.value
        )

    def test_non_string_keys_do_not_silently_collide_with_their_string_form(self):
        """A Python int key and its string form serialise identically.
        Hand-built dicts can hold both; parsed JSON never can. Refusing is
        the deterministic answer, and it is the pre-existing behaviour."""
        with pytest.raises(TypeError):
            core.canonical({1: "x", "1": "y"})


# --------------------------------------------------------------------------
# R2. validate_payload_shape on hostile field VALUES.
#
# Both failure directions appear here, and they need different assertions:
#
#   * SILENT ACCEPTANCE (v=True, v=1.0, signed_at="NOT-A-DATE",
#     anchor=[...]) returns [] where the spec requires a problem.
#   * AN UNCAUGHT EXCEPTION (doc_sha256=[...], doc_sha256=5) is worse:
#     the function returns nothing at all, so a caller that logs the
#     problems crashes instead of logging.
#
# Every test in this class calls the function directly and asserts on its
# return value. None of them wrap it in pytest.raises for a crash - a crash
# is the defect, not the contract.
# --------------------------------------------------------------------------


class TestShapeRejectsWrongTypes:

    def test_baseline_payload_is_valid(self):
        """Control: the fixture itself must be clean, or every test below
        proves nothing."""
        assert core.validate_payload_shape(make_payload()) == []

    def test_v_true_is_rejected(self):
        """`True == 1` in Python, so `payload.get("v") != 1` is False and a
        JSON `{"v": true}` validated as v1. bool is an int subclass, which
        makes this comparison silently succeed rather than error."""
        problems = core.validate_payload_shape(make_payload(v=True))
        assert problems, "v=True must be rejected; a bool is not the integer 1"
        assert any("v must be" in p for p in problems), problems

    def test_v_float_one_is_rejected(self):
        """`1.0 == 1` is also True - JSON has no int/float distinction in
        some serialisers, but the spec says Integer, MUST be 1."""
        problems = core.validate_payload_shape(make_payload(v=1.0))
        assert problems, "v=1.0 must be rejected; the spec says Integer"
        assert any("v must be" in p for p in problems), problems

    def test_v_correct_int_still_passes(self):
        """Control for the two above: the tightened check must not reject
        the value it exists to accept."""
        assert core.validate_payload_shape(make_payload(v=1)) == []
        assert core.validate_payload_shape(make_payload(v=core.SCHEMA_VERSION)) == []

    def test_v_zero_and_two_and_string_are_rejected(self):
        for bad in (0, 2, "1", -1, None):
            problems = core.validate_payload_shape(make_payload(v=bad))
            assert problems, "v=%r must be rejected" % (bad,)

    @pytest.mark.parametrize("bad", [[1] * 64, 5, None, 1.5, b"a" * 64, {"a": 1}])
    def test_doc_sha256_wrong_type_returns_problem_not_exception(self, bad):
        """doc_sha256=5 raised `TypeError: object of type 'int' has no len()`
        and doc_sha256=[1]*64 raised `AttributeError: ... has no attribute
        'lower'`. A validator that raises reports nothing at all."""
        if bad is None:
            problems = core.validate_payload_shape(make_payload(doc_sha256=bad))
            assert any("doc_sha256" in p for p in problems), problems
            return
        problems = core.validate_payload_shape(make_payload(doc_sha256=bad))
        assert problems, "doc_sha256=%r must be rejected" % (bad,)
        assert any("doc_sha256" in p for p in problems), problems

    def test_doc_sha256_must_be_hex_not_merely_lowercase_and_64_long(self):
        """The old check was `len == 64 and value == value.lower()`, which
        accepts 64 characters of ANY lowercase letter - 'z'*64 passed. A
        SHA-256 hex digest has sixteen possible symbols, not twenty-six."""
        problems = core.validate_payload_shape(make_payload(doc_sha256="z" * 64))
        assert problems, "'z'*64 is lowercase and 64 long but is not hex"
        assert core.validate_payload_shape(make_payload(doc_sha256="a" * 64)) == []

    def test_signed_at_garbage_is_rejected(self):
        """The spec says RFC 3339 UTC. 'NOT-A-DATE' was accepted silently."""
        for bad in ("NOT-A-DATE", "", "2026-10-18", "2026-10-18T00:00:00",
                    "18/10/2026", "2026-10-18 00:00:00Z", 12345, None, ["x"]):
            if bad == "":
                problems = core.validate_payload_shape(make_payload(signed_at=bad))
                assert any("signed_at" in p for p in problems), (bad, problems)
                continue
            problems = core.validate_payload_shape(make_payload(signed_at=bad))
            assert any("signed_at" in p for p in problems), (
                "signed_at=%r must be rejected, got %r" % (bad, problems)
            )

    def test_signed_at_valid_utc_forms_are_accepted(self):
        """Control: the accepted forms are the ones our own tests and CLI
        actually produce, plus the RFC's fractional-second variant."""
        for good in ("2026-10-18T00:00:00Z", "2026-10-18T10:43:32+00:00",
                     "2026-10-18T00:00:00.123Z", "2026-11-16T00:00:00Z"):
            problems = core.validate_payload_shape(make_payload(signed_at=good))
            assert problems == [], "signed_at=%r should be accepted, got %r" % (good, problems)

    def test_signed_at_with_non_utc_offset_is_rejected(self):
        """The field is specified as UTC. A local offset makes the same
        instant serialise two ways, which is the same malleability class as
        the canonicalisation bug."""
        problems = core.validate_payload_shape(make_payload(signed_at="2026-10-18T00:00:00+02:00"))
        assert any("signed_at" in p for p in problems), problems

    def test_signed_at_impossible_calendar_values_are_rejected(self):
        """The regex pins the shape; only a real date parse rejects month 13.
        Both checks are needed - neither subsumes the other."""
        for bad in ("2026-13-18T00:00:00Z", "2026-10-32T00:00:00Z",
                    "2026-10-18T25:00:00Z", "2026-10-18T00:61:00Z"):
            problems = core.validate_payload_shape(make_payload(signed_at=bad))
            assert any("signed_at" in p for p in problems), bad

    def test_anchor_must_be_a_string(self):
        """anchor=["a.com"] was accepted silently. The verifier derives the
        fetch URL from this field, so a non-string is not cosmetic."""
        for bad in (["a.com"], {"host": "a.com"}, 5, True):
            problems = core.validate_payload_shape(make_payload(anchor=bad))
            assert any("anchor" in p for p in problems), (
                "anchor=%r must be rejected, got %r" % (bad, problems)
            )

    def test_anchor_string_still_passes(self):
        assert core.validate_payload_shape(make_payload(anchor="retiform.dev")) == []

    @pytest.mark.parametrize("field", ["role", "org", "key_id", "pubkey_b64"])
    def test_required_string_fields_reject_non_strings(self, field):
        """Same class as anchor: truthy non-strings passed the `not value`
        check. A list is truthy, so `if not payload.get(field)` never fired."""
        problems = core.validate_payload_shape(make_payload(**{field: ["x"]}))
        assert any(field in p for p in problems), (
            "%s=['x'] must be rejected, got %r" % (field, problems)
        )

    @pytest.mark.parametrize("bad", ["str", [], None, 5, True])
    def test_non_dict_payload_returns_problem_not_exception(self, bad):
        """`payload.get(...)` on a non-dict raised AttributeError. parse_uri
        does not require payload to be a dict, so this is reachable from a
        URI an attacker controls."""
        problems = core.validate_payload_shape(bad)
        assert problems, "payload=%r must be rejected" % (bad,)
        assert any("JSON object" in p for p in problems), problems

    def test_content_sha256_must_be_hex_when_present(self):
        problems = core.validate_payload_shape(
            make_payload(content_sha256="z" * 64, content_method="plain-text-v1")
        )
        assert any("content_sha256" in p for p in problems), problems

    def test_content_sha256_wrong_type_returns_problem_not_exception(self):
        problems = core.validate_payload_shape(
            make_payload(content_sha256=[1] * 64, content_method="plain-text-v1")
        )
        assert problems, "a list content_sha256 must be rejected, not raise"


# --------------------------------------------------------------------------
# R3. verify_signature must return (False, reason) for ANY hostile envelope.
#
# This is the load-bearing contract of the whole library. verify_signature
# returns a tuple; a caller reads the boolean. An exception escaping it is
# not a stricter verifier - it is a verifier that took the caller down
# instead of answering. On the CLI path that is a traceback where a FAILED
# line belongs.
# --------------------------------------------------------------------------


class TestVerifySignatureNeverRaises:

    def test_valid_envelope_verifies(self, keypair):
        ok, reason = core.verify_signature(signed_envelope(keypair))
        assert ok, reason

    @pytest.mark.parametrize("envelope", [
        {},
        {"payload": {}},
        {"sig_b64": "AAAA"},
        {"payload": {}, "sig_b64": "AAAA"},
        [1, 2, 3],
        "not a dict",
        None,
        5,
    ])
    def test_malformed_envelope_returns_false(self, envelope):
        result = core.verify_signature(envelope)
        assert isinstance(result, tuple) and len(result) == 2, result
        ok, reason = result
        assert ok is False, "must not accept %r" % (envelope,)
        assert isinstance(reason, str) and reason

    @pytest.mark.parametrize("payload", [[], "a string", None, 5, True])
    def test_non_dict_payload_returns_false_not_exception(self, payload, keypair):
        """`payload["pubkey_b64"]` on a list raised
        `TypeError: list indices must be integers or slices, not str`."""
        _, pub = keypair
        sig = core.b64_encode(b"\x00" * 64)
        ok, reason = core.verify_signature({"payload": payload, "sig_b64": sig})
        assert ok is False
        assert "payload" in reason.lower() or "malformed" in reason.lower(), reason

    @pytest.mark.parametrize("sig", [None, 5, 1.5, [], {}, True, b"bytes-not-b64"])
    def test_non_string_sig_b64_returns_false_not_exception(self, sig, keypair):
        """b64_decode calls .encode() on its argument; None and int both
        raised `AttributeError: 'NoneType'/'int' object has no attribute
        'encode'`."""
        _, pub = keypair
        ok, reason = core.verify_signature(
            {"payload": make_payload(pub), "sig_b64": sig}
        )
        assert ok is False, "sig_b64=%r must not verify" % (sig,)
        assert isinstance(reason, str) and reason

    def test_sig_of_wrong_length_returns_false(self, keypair):
        """Valid base64, wrong byte length. Ed25519 signatures are 64 bytes."""
        _, pub = keypair
        for n in (0, 10, 32, 63, 65, 128):
            ok, reason = core.verify_signature(
                {"payload": make_payload(pub), "sig_b64": core.b64_encode(b"\x00" * n)}
            )
            assert ok is False, "a %d-byte signature must not verify" % n

    @pytest.mark.parametrize("bad_key", ["!!!!not base64!!!!", "", "zzz", 5, None, ["x"]])
    def test_bad_pubkey_b64_returns_false_not_exception(self, bad_key, keypair):
        ok, reason = core.verify_signature(
            {"payload": make_payload(pubkey_b64=bad_key), "sig_b64": core.b64_encode(b"\x00" * 64)}
        )
        assert ok is False
        assert ("pubkey" in reason.lower() or "public key" in reason.lower()
                or "malformed" in reason.lower()), reason

    def test_pubkey_of_wrong_length_returns_false(self, keypair):
        _, pub = keypair
        for n in (0, 16, 31, 33, 64):
            ok, reason = core.verify_signature(
                {"payload": make_payload(pubkey_b64=core.b64_encode(b"\x00" * n)),
                 "sig_b64": core.b64_encode(b"\x00" * 64)}
            )
            assert ok is False, "a %d-byte key must not verify" % n
            assert "32" in reason or "malformed" in reason.lower(), reason

    @pytest.mark.parametrize("nonserialisable", [
        {"a", "b"},
        b"\x00\x01",
        object(),
        frozenset({1}),
    ])
    def test_non_json_serialisable_payload_returns_false_not_exception(
        self, nonserialisable, keypair
    ):
        """canonical() calls json.dumps, which raises TypeError on a set or
        bytes. That TypeError propagated straight out of the verifier:
        `TypeError: Object of type set is not JSON serializable`."""
        _, pub = keypair
        payload = make_payload(pub)
        payload["extra"] = nonserialisable
        ok, reason = core.verify_signature(
            {"payload": payload, "sig_b64": core.b64_encode(b"\x00" * 64)}
        )
        assert ok is False, "%r must not verify" % (type(nonserialisable).__name__,)
        assert isinstance(reason, str) and reason

    def test_deeply_nested_payload_returns_false_not_recursion_error(self, keypair):
        """canonical() recurses through _nfc. A payload nested past the
        interpreter's stack limit raised RecursionError straight out of
        verify_signature.

        REACHABILITY, MEASURED, NOT ASSUMED: this is reachable through the
        public API but NOT through a QRSIG1 URI. json's decoder gives out at
        depth 992 and _nfc at 993, so parse_uri raises ValueError one level
        before canonical() would fail. The URI path is therefore closed by
        accident of two nearly identical limits.

        It still matters: verify_signature is a public function that accepts
        an arbitrary dict, the CLI sidecar path json.load()s a local file
        with the same decoder ahead of any depth check, and a caller who
        builds a payload in-process gets no protection at all. The margin is
        one (992 vs 993) and it is a property of the interpreter's default
        recursion limit, not of this library - raise the limit, or nest one
        level deeper through a different shape, and it reopens.
        """
        _, pub = keypair
        deep = {}
        cursor = deep
        for _ in range(4000):
            cursor["a"] = {}
            cursor = cursor["a"]
        cursor["a"] = 1
        payload = {"pubkey_b64": core.b64_encode(pub), "deep": deep}
        ok, reason = core.verify_signature(
            {"payload": payload, "sig_b64": core.b64_encode(b"\x00" * 64)}
        )
        assert ok is False
        assert isinstance(reason, str) and reason

    def test_external_pubkey_of_wrong_type_returns_false(self, keypair):
        _, pub = keypair
        for bad in ("string", 5, [1] * 32, {}, b"too short"):
            ok, reason = core.verify_signature(signed_envelope(keypair), pubkey_raw=bad)
            assert ok is False, "pubkey_raw=%r must not verify" % (bad,)

    def test_external_pubkey_bypasses_embedded_key(self, keypair):
        """Control: a valid override must still work, even when the payload's
        embedded key is garbage. This is the anchor path."""
        priv, pub = keypair
        payload = make_payload(pubkey_b64="!!!!garbage!!!!")
        env = core.sign_payload(priv, payload)
        # Sanity: without the override the embedded key is unusable.
        ok_without, why = core.verify_signature(env)
        assert ok_without is False, "garbage embedded key must not verify"
        assert "pubkey" in why.lower() or "public key" in why.lower(), why
        # With the override, the SAME signed bytes verify against the real key.
        ok, reason = core.verify_signature(env, pubkey_raw=pub)
        assert ok, reason

    def test_tampered_payload_still_fails(self, keypair):
        """Control: the never-raises hardening must not have softened the
        actual verification."""
        env = signed_envelope(keypair)
        env["payload"]["role"] = "Someone Else"
        ok, _ = core.verify_signature(env)
        assert ok is False


# --------------------------------------------------------------------------
# R4. parse_uri on hostile input. It is ALLOWED to raise ValueError - that
# is its documented contract - but nothing else may escape it.
# --------------------------------------------------------------------------


class TestParseUriHostileInput:

    def test_valid_uri_round_trips(self, keypair):
        env = signed_envelope(keypair)
        assert core.parse_uri(core.envelope_to_uri(env)) == env

    @pytest.mark.parametrize("uri", [
        "",
        "abc",
        "QRSIG1",
        "qrsig1:abc",
        "GUANSIG1:abc",
        " QRSIG1:abc",
        "QRSIG1",
    ])
    def test_missing_or_wrong_prefix_raises_value_error(self, uri):
        with pytest.raises(ValueError):
            core.parse_uri(uri)

    @pytest.mark.parametrize("body", ["!!!!", "a", "////", "日本語", "QQ==", "abc def"])
    def test_non_base64_body_raises_value_error(self, body):
        with pytest.raises(ValueError):
            core.parse_uri("QRSIG1:" + body)

    @pytest.mark.parametrize("raw", [
        b"",
        b"not json",
        b"{",
        b"\x00\x01\x02",
        b"{}trailing",
    ])
    def test_base64_of_non_json_raises_value_error(self, raw):
        with pytest.raises(ValueError):
            core.parse_uri("QRSIG1:" + core.b64url_encode(raw))

    @pytest.mark.parametrize("raw", [
        b"[1,2,3]",
        b'"a string"',
        b"null",
        b"5",
        b"true",
    ])
    def test_base64_of_json_that_is_not_a_dict_raises_value_error(self, raw):
        with pytest.raises(ValueError):
            core.parse_uri("QRSIG1:" + core.b64url_encode(raw))

    def test_dict_missing_payload_raises_value_error(self):
        body = core.b64url_encode(json.dumps({"sig_b64": "x"}).encode())
        with pytest.raises(ValueError):
            core.parse_uri("QRSIG1:" + body)

    def test_dict_missing_sig_b64_raises_value_error(self):
        body = core.b64url_encode(json.dumps({"payload": {}}).encode())
        with pytest.raises(ValueError):
            core.parse_uri("QRSIG1:" + body)

    def test_payload_not_a_dict_passes_parse_but_fails_verify(self):
        """parse_uri is a codec, not a validator: it checks presence, not
        type. That division is fine AS LONG AS the consumer survives the
        value - which is what R3 pins."""
        body = core.b64url_encode(json.dumps({"payload": [], "sig_b64": "x"}).encode())
        env = core.parse_uri("QRSIG1:" + body)
        assert env["payload"] == []
        ok, _ = core.verify_signature(env)
        assert ok is False

    def test_extra_wrapper_keys_are_preserved_not_rejected(self):
        """Wrapper fields outside `payload` are unsigned and untrusted, but
        they are not an error - `legacy_raw_pub` rides there by design."""
        body = core.b64url_encode(json.dumps({"payload": {}, "sig_b64": "x", "evil": 1}).encode())
        env = core.parse_uri("QRSIG1:" + body)
        assert env["evil"] == 1

    def test_deeply_nested_json_raises_value_error_not_recursion_error(self):
        """A body nested past the JSON decoder's limit must raise ValueError.

        This passed BEFORE the fix as well - the decoder's RecursionError
        was already swallowed by parse_uri's `except Exception`. The test
        exists so a future refactor that narrows that except clause cannot
        silently reopen it.
        """
        depth = 100000
        raw = ('{"payload":' + "[" * depth + "]" * depth + ',"sig_b64":"x"}').encode()
        with pytest.raises(ValueError):
            core.parse_uri("QRSIG1:" + core.b64url_encode(raw))

    def test_enormous_body_is_handled_without_hanging(self):
        """A QR code cannot carry this, but a URI can be pasted. The codec
        must terminate and answer; either outcome is acceptable as long as
        nothing escapes but ValueError."""
        raw = b'{"payload":{},"sig_b64":"' + b"a" * 2_000_000 + b'"}'
        try:
            env = core.parse_uri("QRSIG1:" + core.b64url_encode(raw))
        except ValueError:
            return
        assert env["sig_b64"] == "a" * 2_000_000

    def test_uri_is_url_safe(self, keypair):
        """A QRSIG1 body travels in a QR code and in URLs. base64url must
        emit `-` and `_`, never `+` or `/`. Padding `=` is permitted but
        must appear only as a suffix."""
        body = core.envelope_to_uri(signed_envelope(keypair))[len(core.URI_PREFIX):]
        assert "+" not in body, "base64url must not emit '+'"
        assert "/" not in body, "base64url must not emit '/'"
        assert body == body.rstrip("=") + "=" * (len(body) - len(body.rstrip("="))), (
            "padding must be a suffix only"
        )
        assert "=" not in body.rstrip("=")

    def test_uri_round_trip_preserves_every_field(self, keypair):
        priv, pub = keypair
        payload = make_payload(pub)
        payload["content_sha256"] = "b" * 64
        payload["content_method"] = "plain-text-v1"
        env = core.sign_payload(priv, payload)
        parsed = core.parse_uri(core.envelope_to_uri(env))
        assert parsed == env
        assert parsed["payload"]["signed_at"] == "2026-10-18T00:00:00Z"
        assert parsed["sig_b64"] == env["sig_b64"]
        ok, reason = core.verify_signature(parsed)
        assert ok, reason


# --------------------------------------------------------------------------
# R5. spki_to_raw. Raises ValueError by contract; anything else escaping it
# would be a defect. The control case proves the happy path is not dead.
# --------------------------------------------------------------------------


class TestSpkiToRaw:

    def test_correct_ed25519_spki_round_trips(self, keypair):
        """Control: a real SPKI DER blob must yield the embedded raw key."""
        _, pub = keypair
        assert core.spki_to_raw(SPKI_HEADER + pub) == pub

    @pytest.mark.parametrize("blob", [
        b"",
        b"nope",
        bytes(12),
        SPKI_HEADER.replace(b"\x2b\x65\x70", b"\x2b\x65\x71"),  # X25519 not Ed25519
        b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x22\x00" + bytes(32),
    ])
    def test_wrong_header_raises_value_error(self, blob):
        with pytest.raises(ValueError):
            core.spki_to_raw(blob)

    @pytest.mark.parametrize("raw_len", [0, 1, 16, 31, 33, 64, 128])
    def test_wrong_length_after_header_raises_value_error(self, raw_len):
        """Header present, payload the wrong size. 32 raw bytes is the only
        valid Ed25519 key length."""
        with pytest.raises(ValueError):
            core.spki_to_raw(SPKI_HEADER + bytes(raw_len))

    def test_raw_key_without_header_raises_value_error(self, keypair):
        """A caller who passes raw bytes instead of SPKI must get a clear
        error, not a silently truncated key."""
        _, pub = keypair
        with pytest.raises(ValueError):
            core.spki_to_raw(pub)

    def test_error_messages_distinguish_header_from_length(self):
        """The two failures are different bugs and must be told apart - a
        wrong-header error sends a caller to inspect their key format, a
        wrong-length error sends them to inspect their key size."""
        with pytest.raises(ValueError) as bad_header:
            core.spki_to_raw(bytes(44))
        with pytest.raises(ValueError) as bad_length:
            core.spki_to_raw(SPKI_HEADER + bytes(31))
        assert "SPKI" in str(bad_header.value)
        assert "length" in str(bad_length.value)
        assert str(bad_header.value) != str(bad_length.value)


# --------------------------------------------------------------------------
# R6. derive_key_id. Properties, not a hardcoded value - the literal is
# pinned by test_vectors.py against the RFC, this checks the contract.
# --------------------------------------------------------------------------


class TestDeriveKeyId:

    def test_is_stable_across_calls(self, keypair):
        _, pub = keypair
        assert core.derive_key_id(pub) == core.derive_key_id(pub)

    def test_has_qs1_prefix(self, keypair):
        _, pub = keypair
        assert core.derive_key_id(pub).startswith("qs1-")

    def test_suffix_is_sixteen_lowercase_hex_chars(self, keypair):
        _, pub = keypair
        suffix = core.derive_key_id(pub)[len("qs1-"):]
        assert len(suffix) == 16
        assert suffix == suffix.lower()
        assert all(c in "0123456789abcdef" for c in suffix), suffix

    def test_total_length_is_twenty(self, keypair):
        _, pub = keypair
        assert len(core.derive_key_id(pub)) == 20

    def test_differs_for_two_different_keys(self):
        _, pub_a = core.new_keypair()
        _, pub_b = core.new_keypair()
        assert pub_a != pub_b, "fixture premise: distinct keys"
        assert core.derive_key_id(pub_a) != core.derive_key_id(pub_b)

    def test_derives_from_the_key_not_from_its_encoding(self, keypair):
        """Two encodings of one key must give one id - otherwise the id is a
        hash of a transport format, and key_id stability is a fiction."""
        _, pub = keypair
        assert core.derive_key_id(pub) == core.derive_key_id(core.b64_decode(core.b64_encode(pub)))

    def test_accepts_empty_input_without_raising(self):
        """Not a valid key, but a hash function must not crash on it - the
        len-32 check belongs to the callers that verify, not to a naming
        helper. Pinned so a future "tighten it" does not silently break a
        caller that derives an id for a not-yet-valid key."""
        assert core.derive_key_id(b"").startswith("qs1-")


# --------------------------------------------------------------------------
# R7. The interaction the spec actually cares about: a payload that passes
# the shape validator must not be one the verifier crashes on. The two
# functions are checked against each other, not just in isolation.
# --------------------------------------------------------------------------


class TestShapeAndVerifyAgree:

    @pytest.mark.parametrize("overrides", [
        {"v": True},
        {"v": 1.0},
        {"doc_sha256": [1] * 64},
        {"doc_sha256": 5},
        {"signed_at": "NOT-A-DATE"},
        {"anchor": ["a.com"]},
        {"role": ["x"]},
        {"pubkey_b64": 12345},
        {"pubkey_b64": [1] * 32},
        {"content_sha256": [1] * 64, "content_method": "plain-text-v1"},
    ])
    def test_every_shape_rejection_also_survives_verify(self, overrides, keypair):
        """Two INDEPENDENT claims about one payload:

          1. the shape validator reports a problem, and
          2. the verifier returns a (ok, reason) tuple instead of raising.

        Neither implies the other, and the original defects violated them
        independently - the shape validator crashed on four of these while
        the verifier crashed on others.

        DELIBERATELY NOT ASSERTED: `ok is False`. verify_signature is the L1
        MATH check by design; shape is applied separately (cli.verify combines
        them with `l1 = ok and not shape`, and anchor.check_envelope runs the
        shape check itself). A correctly-signed payload with a bad `v` type
        therefore returns (True, 'ok') here and is refused one layer up.
        Asserting otherwise would test my assumption about the layering
        rather than the layering, and would fail against correct code.
        """
        priv, pub = keypair
        payload = make_payload(pub, **overrides)
        problems = core.validate_payload_shape(payload)
        assert problems, "shape must reject %r" % (overrides,)
        env = core.sign_payload(priv, payload)
        result = core.verify_signature(env)
        assert isinstance(result, tuple) and len(result) == 2, result
        ok, reason = result
        assert isinstance(ok, bool), "ok must be a bool, got %r" % (ok,)
        assert isinstance(reason, str) and reason

    def test_l1_math_is_independent_of_shape_by_design(self, keypair):
        """Pin the division of labour itself, so neither side drifts into the
        other's job without someone noticing.

        A payload whose `v` is the wrong TYPE but whose bytes were signed
        correctly passes L1 - the signature really does verify - and is
        refused by the shape validator. That is the documented contract of
        both functions, and it is what lets a verifier report "the math is
        sound, the payload is malformed" instead of collapsing the two.
        """
        priv, pub = keypair
        payload = make_payload(pub, v=True)
        env = core.sign_payload(priv, payload)
        math_ok, _ = core.verify_signature(env)
        assert math_ok is True, "the signature over these exact bytes is valid"
        assert core.validate_payload_shape(payload), "but the shape is invalid"


class TestAnchorShapeGate:
    """`anchor` is SIGNED content that a verifier feeds into a URL fetch.

    Found by attacking the surface (2026-11-17), not by reading the code: a
    payload could carry `anchor: "a.com\\nHost: evil"`, `validate_payload_shape`
    accepted it, and the value went to `anchor_url()` verbatim. urllib raised
    `InvalidURL` only after the Request object had already been constructed -
    a parser complaint, not a gate.
    """

    def _payload(self, **over):
        import base64
        base = {
            "v": 1, "anchor": "retiform.dev", "role": "r", "org": "o",
            "key_id": "k",
            "pubkey_b64": base64.b64encode(bytes(32)).decode(),
            "signed_at": "2026-11-17T00:00:00Z",
            "signature_placement": "detached",
            "doc_sha256": "a" * 64,
        }
        base.update(over)
        return base

    def test_a_real_hostname_is_accepted(self):
        assert core.validate_payload_shape(self._payload()) == []

    def test_hostname_with_a_port_is_accepted(self):
        assert core.validate_payload_shape(self._payload(anchor="a.com:8443")) == []

    def test_subdomain_and_punycode_are_accepted(self):
        assert core.validate_payload_shape(
            self._payload(anchor="sub.domain.co.uk")) == []
        assert core.validate_payload_shape(
            self._payload(anchor="xn--e1afmkfd.xn--p1ai")) == []

    def test_bracketed_ipv6_with_port_is_accepted(self):
        assert core.validate_payload_shape(self._payload(anchor="[::1]:8443")) == []

    def test_newline_in_anchor_is_rejected(self):
        """The header-injection case. A newline in a host is never a host."""
        problems = core.validate_payload_shape(
            self._payload(anchor="a.com\nHost: evil"))
        assert problems, "a newline in anchor must be rejected"
        assert any("bare hostname" in p for p in problems)

    def test_carriage_return_and_tab_are_rejected(self):
        for bad in ("a.com\r\nHost: evil", "a.com\tx", "a.com\x00b"):
            problems = core.validate_payload_shape(self._payload(anchor=bad))
            assert problems, "%r must be rejected" % (bad,)

    def test_slash_in_anchor_is_rejected(self):
        """A path in the anchor would let a signer redirect the trust lookup."""
        problems = core.validate_payload_shape(
            self._payload(anchor="a.com/../../b"))
        assert problems, "a path in anchor must be rejected"

    def test_at_sign_in_anchor_is_rejected(self):
        """`evil@a.com` is a userinfo injection, not a hostname."""
        problems = core.validate_payload_shape(self._payload(anchor="evil@a.com"))
        assert problems, "a userinfo '@' in anchor must be rejected"

    def test_scheme_in_anchor_is_rejected(self):
        for bad in ("https://a.com", "file:///etc/passwd"):
            problems = core.validate_payload_shape(self._payload(anchor=bad))
            assert problems, "%r must be rejected" % (bad,)

    def test_empty_and_punctuation_only_anchors_are_rejected(self):
        for bad in ("", " ", "..", ".", "-", "..."):
            problems = core.validate_payload_shape(self._payload(anchor=bad))
            assert problems, "%r must be rejected" % (bad,)

    def test_non_string_anchor_is_rejected(self):
        for bad in (["a.com"], 5, {"host": "a.com"}, True):
            problems = core.validate_payload_shape(self._payload(anchor=bad))
            assert problems, "%r must be rejected" % (bad,)

    def test_the_rejection_names_the_value_so_a_human_can_see_it(self):
        problems = core.validate_payload_shape(self._payload(anchor="a.com\nHost: evil"))
        joined = "; ".join(problems)
        assert "a.com" in joined, (
            "the problem message must echo the offending value: %s" % joined)
