"""Adversarial + regression hardening for qrsig.anchor (L2 trust anchors).

Companion to tests/test_binding_anchor.py. That file covers the happy
path and the four headline rejections. This file attacks the module
boundary a HOSTILE anchor document can actually reach::

    fetch()                untrusted bytes off the network
        |
    validate_directory()   OPTIONAL - a caller may skip it entirely
        |
    check_envelope()  ->  lookup_key()

check_envelope is public API and does NOT require pre-validation, so
every unguarded attribute access below it is reachable from network
input. The rule these tests enforce:

    A verifier must never RAISE on hostile input. It must return a
    negative verdict carrying a reason.

A crash is not a diagnosis, and a caller wrapping check_envelope in a
broad try/except converts an uncaught exception into a fail-open. The
CLI currently does exactly that (except Exception -> "UNREACHABLE"),
which happens to be safe today only because l2 stays False.
"""

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError

import pytest

from qrsig import anchor, core


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def make_payload(pub_raw, key_id="qs1-test", anchor_domain="example.org",
                 role="Test Officer", org="Example Org"):
    """A payload that validate_payload_shape accepts."""
    return {
        "v": 1,
        "anchor": anchor_domain,
        "role": role,
        "org": org,
        "doc_sha256": "a" * 64,
        "signature_placement": "detached",
        "key_id": key_id,
        "pubkey_b64": core.b64_encode(pub_raw),
        "signed_at": "2026-10-18T00:00:00Z",
    }


def make_doc(pub_raw, key_id="qs1-test", domain="example.org",
             status="active", role="Test Officer", org="Example Org"):
    return {
        "v": 1,
        "domain": domain,
        "updated_at": "2026-10-18T00:00:00Z",
        "keys": [{
            "key_id": key_id,
            "pubkey_b64": core.b64_encode(pub_raw),
            "role": role,
            "org": org,
            "status": status,
            "valid_from": "2026-01-01T00:00:00Z",
        }],
    }


def signed_env(priv, payload):
    return core.sign_payload(priv, payload)


@contextlib.contextmanager
def raw_http_server(body, status=200, content_type="application/json"):
    """Serve fixed raw bytes - lets us emit non-JSON, empty, and array bodies
    that tests/conftest.py's json.dumps server cannot produce."""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d/.well-known/qrsig-keys" % srv.server_address[1]
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------
# DEFECT 1-3: lookup_key is public and callable on an UNVALIDATED document.
# Every one of these raised AttributeError before hardening.
# --------------------------------------------------------------------------

class TestLookupKeyHostility:

    def test_keys_is_a_dict_returns_none(self):
        """DEFECT 1: `keys` is a dict, not a list.

        Before the fix: AttributeError: 'str' object has no attribute 'get'
        (iterating a dict yields its keys, so `entry` was the string
        'key_id' and `entry.get(...)` exploded).
        """
        entry, note = anchor.lookup_key({"keys": {"key_id": "x"}}, "x")
        assert entry is None
        assert isinstance(note, str) and note

    def test_keys_is_a_list_of_strings_returns_none(self):
        """DEFECT 2: list of strings.

        Before the fix: AttributeError: 'str' object has no attribute 'get'
        """
        entry, note = anchor.lookup_key({"keys": ["x"]}, "x")
        assert entry is None
        assert isinstance(note, str) and note

    def test_none_entry_in_keys_does_not_raise(self):
        """DEFECT 3: a None element in the key list.

        Before the fix: AttributeError: 'NoneType' object has no attribute 'get'
        """
        entry, note = anchor.lookup_key({"keys": [None]}, "x")
        assert entry is None
        assert isinstance(note, str) and note

    def test_integer_entry_does_not_raise(self):
        """Before the fix: AttributeError: 'int' object has no attribute 'get'"""
        entry, note = anchor.lookup_key({"keys": [5]}, "x")
        assert entry is None

    def test_nested_list_entry_does_not_raise(self):
        """Before the fix: AttributeError: 'list' object has no attribute 'get'"""
        entry, note = anchor.lookup_key({"keys": [[]]}, "x")
        assert entry is None

    def test_doc_is_none_does_not_raise(self):
        """Before the fix: AttributeError: 'NoneType' object has no attribute 'get'"""
        entry, note = anchor.lookup_key(None, "x")
        assert entry is None

    def test_doc_is_a_list_does_not_raise(self):
        """Before the fix: AttributeError: 'list' object has no attribute 'get'"""
        entry, note = anchor.lookup_key([], "x")
        assert entry is None

    def test_doc_is_a_string_does_not_raise(self):
        entry, note = anchor.lookup_key("nope", "x")
        assert entry is None

    def test_missing_keys_field(self):
        entry, note = anchor.lookup_key({}, "x")
        assert entry is None
        assert "not found" in note

    def test_empty_keys_list(self):
        entry, note = anchor.lookup_key({"keys": []}, "x")
        assert entry is None
        assert "not found" in note

    def test_junk_entries_do_not_hide_a_real_key(self):
        """A hostile document must not be able to SHIELD a real entry by
        padding the list with garbage ahead of it."""
        pub = core.new_keypair()[1]
        doc = {"keys": [None, "junk", 7, {"key_id": "qs1-test",
                                          "pubkey_b64": core.b64_encode(pub),
                                          "status": "active"}]}
        entry, note = anchor.lookup_key(doc, "qs1-test")
        assert entry is not None
        assert "active" in note

    def test_key_id_of_none_does_not_match_entries_missing_key_id(self):
        entry, note = anchor.lookup_key({"keys": [{"status": "active"}]}, None)
        assert entry is None


# --------------------------------------------------------------------------
# DEFECT 4 (+ status): an unlisted status string currently falls through to
# the ACTIVE branch. validate_directory reports it, but check_envelope does
# not require validation - so the public API fails OPEN on unrecognized state.
# --------------------------------------------------------------------------

class TestStatusFailOpen:

    @pytest.mark.parametrize("status", [
        "compromised",
        "ACTIVE",
        "active ",
        None,
        "",
        "Revoked",
    ])
    def test_unrecognized_status_is_not_trusted(self, status):
        """A verifier must not read "unrecognized" as "fine".

        Before the fix every one of these returned the entry with the note
        "key x is active" - i.e. TRUSTED. The safe disposition for an
        unrecognized state in a trust decision is not-trusted.
        """
        doc = {"keys": [{"key_id": "x", "status": status,
                         "pubkey_b64": core.b64_encode(bytes(32))}]}
        entry, note = anchor.lookup_key(doc, "x")
        assert entry is None, "unrecognized status %r was TRUSTED" % (status,)
        assert "status" in note.lower()

    def test_missing_status_key_is_not_trusted(self):
        """Absent status is the same class as an unrecognized one."""
        doc = {"keys": [{"key_id": "x",
                         "pubkey_b64": core.b64_encode(bytes(32))}]}
        entry, note = anchor.lookup_key(doc, "x")
        assert entry is None

    def test_unrecognized_status_blocks_check_envelope(self, keypair):
        """The fail-open must not survive the check_envelope path, which is
        reachable WITHOUT validate_directory."""
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        doc = make_doc(pub)
        doc["keys"][0]["status"] = "compromised"
        ok, note, _ = anchor.check_envelope(env, doc)
        assert not ok, "check_envelope TRUSTED an entry with status 'compromised'"
        assert "status" in note.lower()

    def test_active_still_trusted(self, keypair):
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        ok, note, _ = anchor.check_envelope(env, make_doc(pub, status="active"))
        assert ok, note

    def test_rotated_still_trusted(self, keypair):
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        ok, note, _ = anchor.check_envelope(env, make_doc(pub, status="rotated"))
        assert ok, note
        assert "rotated" in note

    def test_absent_status_blocks_check_envelope_with_validation_skipped(
            self, keypair):
        """The check_envelope path does not require validate_directory, so
        an entry with NO status reaches lookup_key unvetted. Before the fix
        it fell through to the active branch and VERIFIED."""
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        doc = {"v": 1, "domain": "example.org",
               "keys": [{"key_id": "qs1-test",
                         "pubkey_b64": core.b64_encode(pub)}]}
        ok, note, _ = anchor.check_envelope(env, doc)
        assert not ok
        assert "status" in note.lower()

    def test_revoked_still_rejected(self, keypair):
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        doc = make_doc(pub, status="revoked")
        doc["keys"][0]["revoked_at"] = "2026-10-20T00:00:00Z"
        ok, note, _ = anchor.check_envelope(env, doc)
        assert not ok
        assert "REVOKED" in note


# --------------------------------------------------------------------------
# DEFECT 4: validate_directory must return problems, never raise, on any
# hostile directory document.
# --------------------------------------------------------------------------

class TestValidateDirectoryHostility:

    @pytest.mark.parametrize("doc", [None, "a string", [], 42, 3.5, True])
    def test_non_dict_document(self, doc):
        problems = anchor.validate_directory(doc)
        assert problems
        assert any("not a JSON object" in p for p in problems)

    def test_empty_dict(self):
        problems = anchor.validate_directory({})
        assert problems
        assert any("v must be 1" in p for p in problems)
        assert any("missing domain" in p for p in problems)
        assert any("at least one key" in p for p in problems)

    def test_v_only_no_keys(self):
        problems = anchor.validate_directory({"v": 1, "domain": "d"})
        assert any("at least one key" in p for p in problems)

    def test_empty_keys_list(self):
        problems = anchor.validate_directory({"v": 1, "domain": "d", "keys": []})
        assert any("at least one key" in p for p in problems)

    def test_keys_is_not_a_list(self):
        problems = anchor.validate_directory(
            {"v": 1, "domain": "d", "keys": "notalist"})
        assert any("at least one key" in p for p in problems)

    def test_keys_is_a_dict(self):
        problems = anchor.validate_directory(
            {"v": 1, "domain": "d", "keys": {"key_id": "k"}})
        assert any("at least one key" in p for p in problems)

    @pytest.mark.parametrize("entry", [None, "nope", [], 3, float("nan")])
    def test_non_dict_key_entry_reports_a_problem(self, entry):
        """DEFECT 4.

        Before the fix: AttributeError: 'NoneType'/'str'/'list' object has
        no attribute 'get'. validate_directory is the function whose entire
        contract is "return problems, never raise" - it must survive this.
        """
        problems = anchor.validate_directory(
            {"v": 1, "domain": "d", "keys": [entry]})
        assert problems
        assert any("key entry" in p for p in problems)

    def test_entry_missing_key_id(self):
        problems = anchor.validate_directory(
            {"v": 1, "domain": "d",
             "keys": [{"pubkey_b64": core.b64_encode(bytes(32)),
                       "status": "active"}]})
        assert any("missing key_id" in p for p in problems)

    def test_duplicate_key_ids(self):
        pub = core.b64_encode(bytes(32))
        entry = {"key_id": "dup", "pubkey_b64": pub, "status": "active"}
        problems = anchor.validate_directory(
            {"v": 1, "domain": "d", "keys": [entry, dict(entry)]})
        assert any("duplicate" in p for p in problems)

    def test_bad_pubkey_length(self):
        problems = anchor.validate_directory(
            {"v": 1, "domain": "d",
             "keys": [{"key_id": "k", "pubkey_b64": core.b64_encode(b"\x00" * 31),
                       "status": "active"}]})
        assert any("32 bytes" in p for p in problems)

    def test_bad_base64_pubkey(self):
        problems = anchor.validate_directory(
            {"v": 1, "domain": "d",
             "keys": [{"key_id": "k", "pubkey_b64": "!!!not-b64-!!!",
                       "status": "active"}]})
        assert any("not valid base64" in p for p in problems)

    def test_revoked_without_date(self):
        problems = anchor.validate_directory(make_doc(bytes(32), status="revoked"))
        assert any("revoked without revoked_at" in p for p in problems)

    def test_domain_mismatch(self):
        problems = anchor.validate_directory(
            make_doc(bytes(32), domain="example.org"), expect_domain="other.org")
        assert any("does not match expected" in p for p in problems)

    def test_expected_domain_trailing_slash_is_stripped(self):
        """expect_domain='d/' must compare equal to a doc domain of 'd'."""
        problems = anchor.validate_directory(make_doc(bytes(32), domain="d"),
                                             expect_domain="d/")
        assert not any("domain" in p for p in problems)

    def test_doc_domain_with_trailing_slash_is_NOT_stripped(self):
        """The asymmetry, pinned deliberately: the doc's own domain must be
        canonical. A doc claiming 'd/' does not match expected 'd'."""
        problems = anchor.validate_directory(
            make_doc(bytes(32), domain="d/"), expect_domain="d")
        assert any("does not match expected" in p for p in problems)

    def test_missing_domain(self):
        doc = make_doc(bytes(32))
        del doc["domain"]
        problems = anchor.validate_directory(doc)
        assert any("missing domain" in p for p in problems)

    def test_v_string_is_rejected(self):
        doc = make_doc(bytes(32))
        doc["v"] = "1"
        assert any("v must be 1" in p for p in anchor.validate_directory(doc))

    def test_v_two_is_rejected(self):
        doc = make_doc(bytes(32))
        doc["v"] = 2
        assert any("v must be 1" in p for p in anchor.validate_directory(doc))

    def test_v_true_is_rejected(self):
        """`True == 1` in Python, so a bare `!=` accepts a JSON {"v": true}
        as a v1 directory. Rejected by type check, in lockstep with
        core.validate_payload_shape - the two validators must not diverge.
        """
        doc = make_doc(bytes(32))
        doc["v"] = True
        problems = anchor.validate_directory(doc)
        assert any("v must be 1" in p for p in problems), (
            "v=True must be rejected; a bool is not the integer 1. Got %r" % (problems,)
        )

    def test_v_float_one_is_rejected(self):
        """Same class as v=True: json parses 1.0 as float, and 1.0 != 1 is False."""
        doc = make_doc(bytes(32))
        doc["v"] = 1.0
        problems = anchor.validate_directory(doc)
        assert any("v must be 1" in p for p in problems), (
            "v=1.0 must be rejected; the spec says Integer. Got %r" % (problems,)
        )


# --------------------------------------------------------------------------
# A. TRUST-ANCHOR INTEGRITY - the property that makes the scheme work.
# Documented in core.py's module docstring: a self-consistent forgery names
# ITS OWN trust root, which is the honest answer, instead of ours.
# --------------------------------------------------------------------------

class TestTrustAnchorProperty:

    def test_self_consistent_forgery_passes_L1_but_not_our_anchor(self):
        """THE property. An attacker with their own keypair can build a
        perfectly self-consistent envelope - signature verifies, payload
        shape valid, anchor field naming THEIR domain. L1 cannot and should
        not catch it. L2 against OUR directory must refuse, because our
        directory does not vouch for that key_id.
        """
        victim_priv, victim_pub = core.new_keypair()
        our_doc = make_doc(victim_pub, key_id="qs1-victim")

        att_priv, att_pub = core.new_keypair()
        forged = signed_env(att_priv, make_payload(
            att_pub, key_id="qs1-victim",   # reuses OUR key_id
            anchor_domain="attacker.example"))

        # L1 passes: the math is real, it is the attacker's own key.
        ok_l1, reason = core.verify_signature(forged)
        assert ok_l1, reason

        # L2 against our directory must refuse.
        ok, note, anchor_pub = anchor.check_envelope(forged, our_doc)
        assert not ok, "self-consistent forgery was ACCEPTED against our anchor"
        assert "MISMATCH" in note
        assert anchor_pub == victim_pub

    def test_forgery_using_its_own_key_id_is_not_found(self):
        """The weaker but more common shape: attacker uses their own key_id.
        Our directory has never heard of it."""
        victim_pub = core.new_keypair()[1]
        our_doc = make_doc(victim_pub, key_id="qs1-victim")
        att_priv, att_pub = core.new_keypair()
        forged = signed_env(att_priv, make_payload(
            att_pub, key_id="qs1-attacker", anchor_domain="attacker.example"))
        ok, note, _ = anchor.check_envelope(forged, our_doc)
        assert not ok
        assert "not found" in note

    def test_honest_envelope_passes_its_own_anchor(self):
        priv, pub = core.new_keypair()
        env = signed_env(priv, make_payload(pub))
        ok, note, anchor_pub = anchor.check_envelope(env, make_doc(pub))
        assert ok, note
        assert anchor_pub == pub


# --------------------------------------------------------------------------
# B. STATUS SEMANTICS - the bypass attempts.
# --------------------------------------------------------------------------

class TestStatusSemantics:

    def test_revoked_with_date_rejected_by_lookup_and_envelope(self, keypair):
        priv, pub = keypair
        doc = make_doc(pub, status="revoked")
        doc["keys"][0]["revoked_at"] = "2026-10-20T00:00:00Z"

        entry, note = anchor.lookup_key(doc, "qs1-test")
        assert entry is None
        assert "REVOKED" in note
        assert "2026-10-20" in note

        env = signed_env(priv, make_payload(pub))
        ok, note2, _ = anchor.check_envelope(env, doc)
        assert not ok
        assert "REVOKED" in note2

    def test_revoked_without_date_still_rejected_by_envelope(self, keypair):
        """validate_directory flags the malformed entry; but check_envelope is
        reachable without validation and must still refuse."""
        priv, pub = keypair
        doc = make_doc(pub, status="revoked")
        assert any("revoked without revoked_at" in p
                   for p in anchor.validate_directory(doc))
        env = signed_env(priv, make_payload(pub))
        ok, note, _ = anchor.check_envelope(env, doc)
        assert not ok
        assert "REVOKED" in note

    def test_rotated_key_with_MISMATCHED_bytes_still_fails_binding(self, keypair):
        """Rotation status must not bypass the key comparison. A `rotated`
        entry is still verifiable, but only for the bytes it actually
        published."""
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        other_pub = core.new_keypair()[1]
        ok, note, _ = anchor.check_envelope(env, make_doc(other_pub, status="rotated"))
        assert not ok, "rotated status bypassed the key-bytes comparison"
        assert "MISMATCH" in note

    def test_rotated_with_matching_bytes_passes_and_says_so(self, keypair):
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        ok, note, _ = anchor.check_envelope(env, make_doc(pub, status="rotated"))
        assert ok, note
        assert "rotated" in note

    def test_revoked_wins_over_rotated_if_both_somehow_present(self, keypair):
        """Status is a single field, but a hostile doc could try a duplicated
        entry. First match wins - pin that the first match is what decides."""
        priv, pub = keypair
        doc = make_doc(pub, status="revoked")
        doc["keys"][0]["revoked_at"] = "2026-10-20T00:00:00Z"
        doc["keys"].append({"key_id": "qs1-test",
                            "pubkey_b64": core.b64_encode(pub),
                            "status": "active"})
        entry, note = anchor.lookup_key(doc, "qs1-test")
        assert entry is None
        assert "REVOKED" in note


# --------------------------------------------------------------------------
# C. KEY-SUBSTITUTION ATTACKS.
# --------------------------------------------------------------------------

class TestKeySubstitution:

    def test_anchor_publishes_key_a_id_with_key_b_bytes(self, keypair):
        """The classic substitution: key_id is ours, the bytes are not."""
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        b_pub = core.new_keypair()[1]
        doc = make_doc(b_pub, key_id="qs1-test")
        ok, note, anchor_pub = anchor.check_envelope(env, doc)
        assert not ok
        assert "ANCHOR MISMATCH" in note
        assert "forgery" in note
        assert anchor_pub == b_pub

    def test_override_not_matching_anchor_fails_against_the_override(self, keypair):
        """Legacy path: the override is what the signature actually binds, so
        the comparison MUST be against the override, not the payload field."""
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        doc = make_doc(pub)
        ok, note, _ = anchor.check_envelope(
            env, doc, pubkey_raw_override=b"\x01" * 32)
        assert not ok
        assert "MISMATCH" in note

    def test_override_matching_anchor_passes(self, keypair):
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        ok, note, anchor_pub = anchor.check_envelope(
            env, make_doc(pub), pubkey_raw_override=pub)
        assert ok, note
        assert anchor_pub == pub

    def test_override_wins_over_a_lying_payload_pubkey(self, keypair):
        """The payload claims a DIFFERENT key than the anchor publishes, but
        the verifier derived the true key from the signature (override).
        The override must be used, and it must match the anchor."""
        priv, pub = keypair
        payload = make_payload(core.new_keypair()[1])  # lying embedded key
        env = signed_env(priv, payload)                # signed with `priv`
        ok, note, _ = anchor.check_envelope(
            env, make_doc(pub), pubkey_raw_override=pub, skip_shape=True)
        assert ok, note

    @pytest.mark.parametrize("nbytes", [31, 33, 64, 1])
    def test_wrong_length_pubkey_in_directory_is_a_problem(self, nbytes):
        doc = {"v": 1, "domain": "d",
               "keys": [{"key_id": "k",
                         "pubkey_b64": core.b64_encode(b"\x00" * nbytes),
                         "status": "active"}]}
        problems = anchor.validate_directory(doc)
        assert any("32 bytes" in p for p in problems)

    def test_zero_length_pubkey_reports_missing_not_wrong_length(self):
        """b64_encode(b"") is "", which is falsy - so validate_directory's
        `if not pub` branch fires first and the message is "missing", not
        "must decode to 32 bytes". Both are refusals; pin which one so an
        over-specified test cannot mask the real behaviour."""
        doc = {"v": 1, "domain": "d",
               "keys": [{"key_id": "k", "pubkey_b64": "", "status": "active"}]}
        problems = anchor.validate_directory(doc)
        assert any("missing pubkey_b64" in p for p in problems)

    @pytest.mark.parametrize("nbytes", [31, 33])
    def test_wrong_length_pubkey_must_not_make_check_envelope_raise(
            self, keypair, nbytes):
        """validate_directory reports it - but check_envelope must not EXPLODE
        on the same document when called without validation."""
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        doc = {"v": 1, "domain": "example.org",
               "keys": [{"key_id": "qs1-test",
                         "pubkey_b64": core.b64_encode(b"\x00" * nbytes),
                         "status": "active"}]}
        ok, note, _ = anchor.check_envelope(env, doc)
        assert not ok
        assert isinstance(note, str) and note

    def test_anchor_entry_missing_pubkey_b64_does_not_raise(self, keypair):
        """Before the fix: KeyError: 'pubkey_b64'"""
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        doc = {"v": 1, "domain": "example.org",
               "keys": [{"key_id": "qs1-test", "status": "active"}]}
        ok, note, _ = anchor.check_envelope(env, doc)
        assert not ok
        assert "pubkey" in note.lower()

    def test_anchor_pubkey_b64_is_none_does_not_raise(self, keypair):
        """Before the fix: AttributeError: 'NoneType' object has no attribute 'encode'"""
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        doc = {"v": 1, "domain": "example.org",
               "keys": [{"key_id": "qs1-test", "status": "active",
                         "pubkey_b64": None}]}
        ok, note, _ = anchor.check_envelope(env, doc)
        assert not ok

    def test_anchor_pubkey_b64_not_base64_does_not_raise(self, keypair):
        """Before the fix: binascii.Error: Incorrect padding"""
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        doc = {"v": 1, "domain": "example.org",
               "keys": [{"key_id": "qs1-test", "status": "active",
                         "pubkey_b64": "!!!not-b64!!!"}]}
        ok, note, _ = anchor.check_envelope(env, doc)
        assert not ok
        assert "base64" in note.lower()

    def test_payload_pubkey_b64_not_base64_under_skip_shape_does_not_raise(
            self, keypair):
        """The legacy path skips shape validation, so a hostile payload field
        reaches b64_decode unguarded. Before the fix: binascii.Error."""
        _, pub = keypair
        honest = make_doc(pub)
        env = {"payload": {"key_id": "qs1-test", "pubkey_b64": "!!!bad!!!"},
               "sig_b64": "AAAA"}
        ok, note, _ = anchor.check_envelope(env, honest, skip_shape=True)
        assert not ok
        assert isinstance(note, str) and note

    def test_payload_missing_pubkey_b64_under_skip_shape_does_not_raise(
            self, keypair):
        """Before the fix: KeyError: 'pubkey_b64'"""
        _, pub = keypair
        env = {"payload": {"key_id": "qs1-test"}, "sig_b64": "AAAA"}
        ok, note, _ = anchor.check_envelope(env, make_doc(pub), skip_shape=True)
        assert not ok


# --------------------------------------------------------------------------
# D. A HOSTILE DIRECTORY DOCUMENT MUST NOT CRASH check_envelope.
# check_envelope does not require validate_directory first.
# --------------------------------------------------------------------------

class TestHostileDirectoryReachesCheckEnvelope:

    @pytest.mark.parametrize("doc", [None, "a string", [], 42])
    def test_non_dict_document_does_not_raise(self, keypair, doc):
        """Before the fix: AttributeError on None/str/list."""
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        ok, note, anchor_pub = anchor.check_envelope(env, doc)
        assert not ok
        assert isinstance(note, str) and note
        assert anchor_pub is None

    @pytest.mark.parametrize("keys", [
        {"key_id": "qs1-test"},
        ["qs1-test"],
        [None],
        "notalist",
        7,
    ])
    def test_hostile_keys_field_does_not_raise(self, keypair, keys):
        """Before the fix: AttributeError for dict / list-of-str / [None]."""
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        ok, note, _ = anchor.check_envelope(
            env, {"v": 1, "domain": "example.org", "keys": keys})
        assert not ok
        assert isinstance(note, str) and note

    @pytest.mark.parametrize("envelope", [None, "a string", [], 42])
    def test_non_dict_envelope_does_not_raise(self, envelope):
        """Before the fix: AttributeError: 'NoneType' object has no attribute 'get'"""
        ok, note, _ = anchor.check_envelope(envelope, make_doc(bytes(32)))
        assert not ok
        assert isinstance(note, str) and note

    def test_envelope_with_no_payload_key(self):
        ok, note, _ = anchor.check_envelope({"sig_b64": "AAAA"}, make_doc(bytes(32)))
        assert not ok

    @pytest.mark.parametrize("payload", [None, "x", [], 7])
    def test_payload_that_is_not_a_dict(self, payload):
        ok, note, _ = anchor.check_envelope(
            {"payload": payload, "sig_b64": "AAAA"}, make_doc(bytes(32)),
            skip_shape=True)
        assert not ok

    def test_empty_directory_returns_not_found_not_a_crash(self, keypair):
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        ok, note, _ = anchor.check_envelope(env, {})
        assert not ok
        assert "not found" in note


# --------------------------------------------------------------------------
# E. URL CONSTRUCTION.
# --------------------------------------------------------------------------

class TestAnchorUrl:

    def test_trailing_slash_is_stripped(self):
        assert anchor.anchor_url("retiform.dev") == anchor.anchor_url("retiform.dev/")

    def test_double_trailing_slash_is_stripped(self):
        assert anchor.anchor_url("retiform.dev//") == anchor.anchor_url("retiform.dev")

    def test_form(self):
        assert anchor.anchor_url("retiform.dev") == (
            "https://retiform.dev/.well-known/qrsig-keys")

    def test_always_https(self):
        assert anchor.anchor_url("retiform.dev").startswith("https://")

    def test_no_double_slash_after_host(self):
        assert "dev//" not in anchor.anchor_url("retiform.dev/")


# --------------------------------------------------------------------------
# E. TRANSPORT.
# --------------------------------------------------------------------------

class TestFetchTransport:

    @pytest.mark.parametrize("url", [
        "http://example.org/.well-known/qrsig-keys",
        "ftp://example.org/x",
        "file:///etc/passwd",
        "example.org/.well-known/qrsig-keys",   # scheme-less
        "//example.org/x",                       # protocol-relative
        "data:application/json,{}",
    ])
    def test_non_https_is_refused_when_required(self, url):
        with pytest.raises(ValueError):
            anchor.fetch(url, timeout=2)

    def test_refusal_message_names_the_reason(self):
        with pytest.raises(ValueError) as ei:
            anchor.fetch("http://example.org/x")
        msg = str(ei.value)
        assert "https" in msg
        assert "require_https" in msg

    def test_uppercase_schemes_are_normalised_not_case_compared(self):
        """RFC 3986: URL schemes are case-insensitive.

        FIXED 2026-11-17. The old guard compared with `startswith("https://")`,
        so `HTTPS://` - a legitimate https URL - was refused for its case. The
        gate is now derived from a lowercased scheme, which fixes that without
        weakening anything: `FILE://` is refused exactly as `file://` is,
        because the gate is on the SCHEME, not on its spelling.
        """
        with pytest.raises(ValueError):
            anchor.fetch("FILE:///etc/hostname", timeout=2)
        with pytest.raises(ValueError):
            anchor.fetch("FILE:///etc/hostname", require_https=False, timeout=2)
        try:
            anchor.fetch("HTTPS://127.0.0.1:1/.well-known/qrsig-keys", timeout=1)
        except ValueError as exc:
            msg = str(exc)
            assert "must be https" not in msg and "must be http" not in msg, (
                "the scheme gate refused an uppercase HTTPS URL: %s" % msg)
        except Exception:
            pass

    def test_require_https_false_against_local_fixture_succeeds(self, anchor_server):
        """The documented escape hatch for self-hosted registries. If this
        ever breaks, local-registry verification breaks with it."""
        docs, server = anchor_server
        docs["/.well-known/qrsig-keys"] = make_doc(bytes(32))
        url = "http://127.0.0.1:%d/.well-known/qrsig-keys" % server.server_address[1]
        doc = anchor.fetch(url, require_https=False)
        assert doc["domain"] == "example.org"

    def test_404_raises_http_error(self, anchor_server):
        _, server = anchor_server
        url = "http://127.0.0.1:%d/nope" % server.server_address[1]
        with pytest.raises(HTTPError):
            anchor.fetch(url, require_https=False)

    def test_non_json_body_raises_value_error(self):
        """JSONDecodeError IS a ValueError, so this is a clean catchable
        failure - but note fetch() does NOT wrap it, so the message carries
        no URL. Reported as an ergonomics observation, not a hole."""
        with raw_http_server(b"<html>not json</html>") as url:
            with pytest.raises(ValueError):
                anchor.fetch(url, require_https=False)

    def test_empty_body_raises_value_error(self):
        with raw_http_server(b"") as url:
            with pytest.raises(ValueError):
                anchor.fetch(url, require_https=False)

    def test_json_array_body_is_returned_then_rejected_by_validate(self):
        """Layering, pinned: fetch does not validate. A JSON array parses,
        and validate_directory is what refuses it."""
        with raw_http_server(b'[1, 2, 3]') as url:
            doc = anchor.fetch(url, require_https=False)
            assert doc == [1, 2, 3]
            assert anchor.validate_directory(doc)

    def test_json_scalar_body_is_returned_then_rejected_by_validate(self):
        with raw_http_server(b'"a string"') as url:
            doc = anchor.fetch(url, require_https=False)
            assert doc == "a string"
            assert anchor.validate_directory(doc)


# --------------------------------------------------------------------------
# REPORTED-WEAKNESS PINNING - behaviour that is arguably wrong but is NOT
# fixed by this shard. Each test documents WHY. Flip deliberately.
# --------------------------------------------------------------------------

class TestReportedNotFixed:

    def test_WEAKNESS_KNOWN_check_envelope_does_not_bind_payload_anchor_to_doc_domain(
            self, keypair):
        """REPORTED, NOT FIXED: hole #2.

        check_envelope never compares payload["anchor"] with
        anchor_doc["domain"]. A document served BY attacker.example that
        happens to carry our key_id and our bytes is accepted as an L2
        anchor for a signature claiming example.org.

        Why it is not a live bypass today: the verifier derives the fetch
        URL from payload["anchor"], so the document it holds came from the
        domain the payload names. It bites only when a caller supplies an
        arbitrary document - and the CLI guards that with
        validate_directory(expect_domain=payload_anchor).

        Why NOT fixed here: adding the check to check_envelope changes the
        security semantics of a shared public function (and must skip when
        payload carries no `anchor`, which is exactly the legacy path), and
        qrsig/cli.py is out of scope for this shard. Documented in
        check_envelope's docstring instead.
        """
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub, anchor_domain="example.org"))
        foreign_doc = make_doc(pub, domain="attacker.example")
        ok, note, _ = anchor.check_envelope(env, foreign_doc)
        assert ok, (
            "check_envelope now binds domain - the gap was closed. Update "
            "this test and check_envelope's docstring together."
        )

    def test_WEAKNESS_KNOWN_is_caught_by_validate_directory(self, keypair):
        """The mitigation for hole #2, pinned so it is not lost: the CLI's
        two-call sequence does catch it."""
        priv, pub = keypair
        payload = make_payload(pub, anchor_domain="example.org")
        foreign_doc = make_doc(pub, domain="attacker.example")
        problems = anchor.validate_directory(
            foreign_doc, expect_domain=payload["anchor"])
        assert any("does not match expected" in p for p in problems)


# --------------------------------------------------------------------------
# REPORTED GAPS FOUND BY THIS SHARD - all pinned, none fixed. Each is a
# semantic hole rather than a crash, and each needs a policy decision that
# is not a shard's to make unilaterally.
# --------------------------------------------------------------------------

class TestSemanticGapsReported:

    def test_GAP_valid_from_is_never_enforced(self, keypair):
        """GAP #3: `valid_from` is in the schema, documented, and NEVER READ.

        `valid_from` appears in anchor.py exactly once: the module
        docstring's example JSON. It is never read. validate_directory
        does not check it and lookup_key does not compare it to now, so a
        directory can publish a key stamped `valid_from: 2099-01-01` and
        it verifies TODAY.

        Reported as a field-that-looks-load-bearing-and-is-not, the same
        class as a display field that reads like a state check. Not fixed:
        enforcing time would require a clock at a pure-function boundary
        (every test and caller would need injectable time), which is a
        design change to a public function.
        """
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        doc = make_doc(pub)
        doc["keys"][0]["valid_from"] = "2099-01-01T00:00:00Z"
        assert anchor.validate_directory(doc) == []
        ok, note, _ = anchor.check_envelope(env, doc)
        assert ok, note

    def test_GAP_revoked_at_is_not_date_validated(self, keypair):
        """GAP #4: `revoked_at` only has to be TRUTHY, not a date.

        `revoked_at: "NOT-A-DATE"` satisfies validate_directory. Low
        severity - the key is still rejected - but the timestamp is
        printed in the rejection note, so garbage reaches the operator.
        """
        priv, pub = keypair
        doc = make_doc(pub, status="revoked")
        doc["keys"][0]["revoked_at"] = "NOT-A-DATE"
        assert anchor.validate_directory(doc) == []
        entry, note = anchor.lookup_key(doc, "qs1-test")
        assert entry is None
        assert "NOT-A-DATE" in note

    def test_HOLE_duplicate_key_id_first_match_wins_even_if_revoked_later(
            self, keypair):
        """HOLE #5, the sharpest of the set: a revocation applied by APPEND
        is silently ignored.

        lookup_key returns the FIRST entry whose key_id matches. So a
        rotation done as "append a revoked record" - a plausible operator
        move, and the shape a naive script produces - leaves the earlier
        `active` entry winning and the revocation invisible.

        validate_directory DOES flag "duplicate key_id", so a caller that
        runs it catches this. check_envelope does not require it.

        Not fixed here: preferring the most restrictive entry is a
        fail-closed change to a public function's semantics, and it is an
        OPERATOR footgun rather than an attacker capability - whoever
        controls the domain can simply omit the active entry. Flagged for
        a deliberate ruling.
        """
        priv, pub = keypair
        env = signed_env(priv, make_payload(pub))
        doc = {"v": 1, "domain": "example.org", "keys": [
            {"key_id": "qs1-test", "pubkey_b64": core.b64_encode(pub),
             "status": "active"},
            {"key_id": "qs1-test", "pubkey_b64": core.b64_encode(pub),
             "status": "revoked", "revoked_at": "2026-10-20T00:00:00Z"},
        ]}
        # validate_directory sees it.
        assert any("duplicate" in p for p in anchor.validate_directory(doc))
        # check_envelope does not, and VERIFIES.
        ok, note, _ = anchor.check_envelope(env, doc)
        assert ok, (
            "check_envelope now prefers the restrictive duplicate - that is "
            "the fix landing. Update this test and the docstring together."
        )
        assert "active" in note

    def test_GAP_no_key_expiry_concept_exists(self, keypair):
        """GAP #6: the schema has no expiry and anchor.py has no clock.

        A key that is compromised but NOT explicitly revoked verifies
        forever. Rotation (`rotated`) is explicitly still-valid, and there
        is no `not_after`. This is a documented design characteristic, not
        a bug - revocation is the only kill switch - but it means the
        anchor's freshness is entirely the operator's discipline.
        Pinned so nobody assumes an expiry check exists.
        """
        import inspect
        import re
        src = inspect.getsource(anchor)
        for term in ("expire", "expires", "not_after", "valid_until", "not_before"):
            assert not re.search(term, src), (
                "%r appeared in anchor.py - an expiry mechanism was added. "
                "Verify it is enforced, then update this test." % term
            )
