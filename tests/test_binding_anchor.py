"""Tests: content binding (L3) and trust anchors (L2)."""

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from qrsig import anchor, binding, core


class TestPlainText:
    def test_whitespace_collapse(self):
        assert binding.content_digest(b"a  \t\n b", "plain-text-v1") == binding.content_digest(b"a b", "plain-text-v1")

    def test_nfc(self):
        assert binding.content_digest("café".encode(), "plain-text-v1") == binding.content_digest("café".encode(), "plain-text-v1")

    def test_unknown_method(self):
        with pytest.raises(ValueError):
            binding.content_digest(b"x", "no-such-method")

    def test_detect(self):
        assert binding.detect_method("x.pdf") == "pdf-pypdf-text-v1"
        assert binding.detect_method("x.txt") == "plain-text-v1"


class TestPdfBinding:
    def test_rewritten_container_still_binds(self, tmp_path):
        """THE field lesson: same text, two different PDF containers ->
        byte hashes differ, content hashes MATCH."""
        try:
            from pypdf import PdfReader, PdfWriter
        except ImportError:
            pytest.skip("pypdf not installed")
        # Build a minimal PDF via reportlab-free path: pypdf can't create
        # from scratch, so skip if we can't make a source PDF. The e2e
        # suite covers this with a real document instead.
        pytest.skip("pdf fixture creation covered in e2e")


def make_anchor_doc(pub_raw: bytes, key_id: str, role="Test Officer", org="Example Org", status="active", domain="example.org"):
    return {
        "v": 1,
        "domain": domain,
        "updated_at": "2026-10-18T00:00:00Z",
        "keys": [
            {"key_id": key_id, "pubkey_b64": core.b64_encode(pub_raw), "role": role, "org": org, "status": status, "valid_from": "2026-01-01T00:00:00Z"}
        ],
    }


@pytest.fixture()
def anchor_server():
    """Local https-less anchor server for tests. anchor.fetch enforces
    https for REAL anchors; tests inject a plain http URL - so this
    fixture serves JSON and tests call fetch() with the http URL
    explicitly (fetch's https guard is separately tested)."""
    docs = {}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            path_key = self.path.split("?")[0]
            doc = docs.get(path_key)
            if doc is None:
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(doc).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), H)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield docs, server
    server.shutdown()


class TestAnchorFetch:
    def test_https_required(self):
        with pytest.raises(ValueError):
            anchor.fetch("http://example.org/.well-known/qrsig-keys")

    def test_fetch_json(self, anchor_server):
        docs, server = anchor_server
        docs["/.well-known/qrsig-keys"] = make_anchor_doc(bytes(32), "qs1-x")
        url = "http://127.0.0.1:%d/.well-known/qrsig-keys" % server.server_address[1]
        doc = anchor.fetch(url, require_https=False)
        assert doc["domain"] == "example.org"


class TestAnchorValidate:
    def test_valid(self):
        assert anchor.validate_directory(make_anchor_doc(bytes(32), "qs1-x"), expect_domain="example.org") == []

    def test_domain_mismatch(self):
        problems = anchor.validate_directory(make_anchor_doc(bytes(32), "qs1-x"), expect_domain="other.org")
        assert any("domain" in p for p in problems)

    def test_bad_status(self):
        doc = make_anchor_doc(bytes(32), "qs1-x")
        doc["keys"][0]["status"] = "meh"
        assert anchor.validate_directory(doc)

    def test_revoked_needs_date(self):
        doc = make_anchor_doc(bytes(32), "qs1-x", status="revoked")
        assert any("revoked" in p for p in anchor.validate_directory(doc))
        doc["keys"][0]["revoked_at"] = "2026-10-18T00:00:00Z"
        assert anchor.validate_directory(doc) == []

    def test_duplicate_key_ids(self):
        doc = make_anchor_doc(bytes(32), "qs1-x")
        doc["keys"].append(dict(doc["keys"][0]))
        assert any("duplicate" in p for p in anchor.validate_directory(doc))


class TestCheckEnvelope:
    def _envelope(self, keypair, payload):
        return core.sign_payload(keypair[0], payload)

    @pytest.fixture()
    def full_payload(self):
        return {
            "v": 1,
            "anchor": "example.org",
            "role": "Test Officer",
            "org": "Example Org",
            "doc_sha256": "a" * 64,
            "key_id": "qs1-live",
            "pubkey_b64": "PENDING",
            "signed_at": "2026-10-18T00:00:00Z",
        }

    def test_active_key_passes(self, keypair, full_payload, anchor_server):
        _, pub = keypair
        full_payload["pubkey_b64"] = core.b64_encode(pub)
        env = self._envelope(keypair, full_payload)
        docs, server = anchor_server
        docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub, "qs1-live")
        ok, note, anchor_pub = anchor.check_envelope(env, docs["/.well-known/qrsig-keys"])
        assert ok, note
        assert anchor_pub == pub

    def test_key_not_found(self, keypair, full_payload, anchor_server):
        _, pub = keypair
        full_payload["pubkey_b64"] = core.b64_encode(pub)
        env = self._envelope(keypair, full_payload)
        docs, _ = anchor_server
        docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub, "qs1-other")
        ok, note, _ = anchor.check_envelope(env, docs["/.well-known/qrsig-keys"])
        assert not ok
        assert "not found" in note

    def test_pubkey_mismatch_is_forgery(self, keypair, full_payload):
        """The attack this check exists for: same key_id, different key.
        The payload embeds a VALID signing key; the anchor lists a
        DIFFERENT valid key under the same key_id."""
        _, pub = keypair
        full_payload["pubkey_b64"] = core.b64_encode(pub)
        env = self._envelope(keypair, full_payload)
        other_pub = core.new_keypair()[1]
        ok, note, _ = anchor.check_envelope(env, make_anchor_doc(other_pub, "qs1-live"))
        assert not ok
        assert "MISMATCH" in note

    def test_role_mismatch_warns_but_binds(self, keypair, full_payload, anchor_server):
        """Key bytes are the binding; role drift is a WARNING. The
        anchor's published role remains the display authority."""
        _, pub = keypair
        full_payload["pubkey_b64"] = core.b64_encode(pub)
        env = self._envelope(keypair, full_payload)
        docs, _ = anchor_server
        docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub, "qs1-live", role="Different Role")
        ok, note, _ = anchor.check_envelope(env, docs["/.well-known/qrsig-keys"])
        assert ok
        assert "WARNING" in note

    def test_revoked_key_rejected(self, keypair, full_payload, anchor_server):
        _, pub = keypair
        full_payload["pubkey_b64"] = core.b64_encode(pub)
        env = self._envelope(keypair, full_payload)
        docs, _ = anchor_server
        docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub, "qs1-live", status="revoked")
        ok, note, _ = anchor.check_envelope(env, docs["/.well-known/qrsig-keys"])
        assert not ok
        assert "REVOKED" in note

    def test_rotated_key_still_verifies(self, keypair, full_payload, anchor_server):
        _, pub = keypair
        full_payload["pubkey_b64"] = core.b64_encode(pub)
        env = self._envelope(keypair, full_payload)
        docs, _ = anchor_server
        docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub, "qs1-live", status="rotated")
        ok, note, _ = anchor.check_envelope(env, docs["/.well-known/qrsig-keys"])
        assert ok, note
