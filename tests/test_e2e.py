"""End-to-end CLI tests: the full human workflow.

keygen -> sign -> (qr render -> decode -> verify) against a LOCAL
anchor server, including negative cases and the offline path.
"""

import base64
import json

import pytest

from qrsig import core

from test_binding_anchor import make_anchor_doc

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "agreement.txt").write_text("The party of the first part agrees to everything.\n\nSigned in the tent.\n", encoding="utf-8")
    return tmp_path


def run_cli(*argv, expect=0):
    from qrsig import cli

    import io
    import contextlib

    buf = io.StringIO()
    rc = 0
    try:
        with contextlib.redirect_stdout(buf):
            cli.main(list(argv))
    except SystemExit as exc:
        rc = exc.code or 0
    # Read the buffer AFTER exception handling: verify/anchor-validate end
    # with SystemExit, and reading inside the try would skip it - leaving
    # out empty exactly when the failure output matters most.
    out = buf.getvalue().splitlines()
    assert rc == expect, "rc=%s out=%s" % (rc, out)
    return out


def test_full_workflow(workspace, keypair_and_anchor):
    """keygen -> sign -> verify (L1+L2+L3) against the local anchor."""
    priv, pub_raw, anchor_url, docs = keypair_and_anchor
    host = anchor_url.split("//")[1]
    domain = host.split(":")[0]
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    doc = workspace / "agreement.txt"

    run_cli("keygen", "--out", "k", "--force")
    # Real-world order: keygen -> publish -> sign -> verify.
    pub_b64 = (workspace / "k.pub").read_text().strip().splitlines()[-1]
    pub_raw = core.b64_decode(pub_b64)
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    assert (workspace / "k.key").stat().st_mode & 0o777 == 0o600
    run_cli("sign", str(doc), "--key", "k.key", "--anchor", domain, "--role", "CSO", "--org", "Example Org", "--signed-at", "2026-10-18T00:00:00Z")
    assert (workspace / "agreement.txt.qrsig.json").exists()
    assert (workspace / "agreement.txt.qrsig.png").exists()

    # QR round trip: decode the PNG, verify from the decoded URI.
    uri = run_cli("decode", str(workspace / "agreement.txt.qrsig.png"))[0]
    assert uri.startswith("QRSIG1:")
    out = run_cli("verify", str(doc), "--uri", uri, "--anchor-url", anchor_url + "/.well-known/qrsig-keys")
    assert any("VERIFIED" in line for line in out)
    assert any("L1 math" in line and "PASS" in line for line in out)
    assert any("L2 anchor" in line and "PASS" in line for line in out)
    assert any("L3a byte binding" in line and "PASS" in line for line in out)
    assert any("L3b content binding" in line and "PASS" in line for line in out)


def test_sidecar_verify(workspace, keypair_and_anchor):
    priv, pub_raw, anchor_url, docs = keypair_and_anchor
    host = anchor_url.split("//")[1]
    domain = host.split(":")[0]
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    doc = workspace / "agreement.txt"
    run_cli("keygen", "--out", "k", "--force")
    # Real-world order: keygen -> publish -> sign -> verify.
    pub_b64 = (workspace / "k.pub").read_text().strip().splitlines()[-1]
    pub_raw = core.b64_decode(pub_b64)
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    run_cli("sign", str(doc), "--key", "k.key", "--anchor", domain, "--role", "CSO", "--org", "Example Org")
    out = run_cli("verify", str(doc), "--anchor-url", anchor_url + "/.well-known/qrsig-keys")
    assert any("VERIFIED" in line for line in out)


def test_tampered_document_fails(workspace, keypair_and_anchor):
    priv, pub_raw, anchor_url, docs = keypair_and_anchor
    host = anchor_url.split("//")[1]
    domain = host.split(":")[0]
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    doc = workspace / "agreement.txt"
    run_cli("keygen", "--out", "k", "--force")
    # Real-world order: keygen -> publish -> sign -> verify.
    pub_b64 = (workspace / "k.pub").read_text().strip().splitlines()[-1]
    pub_raw = core.b64_decode(pub_b64)
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    run_cli("sign", str(doc), "--key", "k.key", "--anchor", domain, "--role", "CSO", "--org", "Example Org")
    doc.write_text("The party of the first part agrees to everything EXCEPT this word.\n", encoding="utf-8")
    out = run_cli("verify", str(doc), "--anchor-url", anchor_url + "/.well-known/qrsig-keys", expect=1)
    assert any("FAILED" in line for line in out)
    assert any("L3" in line and "FAIL" in line for line in out)


def test_offline_verify_caps_assurance(workspace, keypair_and_anchor):
    priv, pub_raw, anchor_url, docs = keypair_and_anchor
    host = anchor_url.split("//")[1]
    domain = host.split(":")[0]
    doc = workspace / "agreement.txt"
    run_cli("keygen", "--out", "k", "--force")
    # Real-world order: keygen -> publish -> sign -> verify.
    pub_b64 = (workspace / "k.pub").read_text().strip().splitlines()[-1]
    pub_raw = core.b64_decode(pub_b64)
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    run_cli("sign", str(doc), "--key", "k.key", "--anchor", domain, "--role", "CSO", "--org", "Example Org")
    out = run_cli("verify", str(doc), "--offline")
    assert any("VERIFIED" in line for line in out)
    assert any("capacity NOT confirmed" in line for line in out)


def test_content_binding_survives_reformat(workspace, keypair_and_anchor):
    """Same words, different whitespace -> content binding still holds
    even though byte binding broke. THE container-rewrite lesson."""
    priv, pub_raw, anchor_url, docs = keypair_and_anchor
    host = anchor_url.split("//")[1]
    domain = host.split(":")[0]
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    doc = workspace / "agreement.txt"
    run_cli("keygen", "--out", "k", "--force")
    # Real-world order: keygen -> publish -> sign -> verify.
    pub_b64 = (workspace / "k.pub").read_text().strip().splitlines()[-1]
    pub_raw = core.b64_decode(pub_b64)
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    run_cli("sign", str(doc), "--key", "k.key", "--anchor", domain, "--role", "CSO", "--org", "Example Org")
    doc.write_text("The  party   of\nthe first part\tagrees to everything.\n\n\nSigned in the tent.", encoding="utf-8")
    # Reformatting breaks byte binding but NOT content binding.  Section 8
    # makes L3 an and/or, so a content match VERIFIES: that is the whole
    # reason content binding exists.
    out = run_cli("verify", str(doc), "--anchor-url", anchor_url + "/.well-known/qrsig-keys")
    assert any("L3a byte binding" in line and "FAIL" in line for line in out)
    assert any("L3b content binding" in line and "PASS" in line for line in out)
    assert any("VERIFIED" in line for line in out)


def test_wrong_document_for_qr(workspace, keypair_and_anchor):
    """A QR from document A must not verify against document B."""
    priv, pub_raw, anchor_url, docs = keypair_and_anchor
    host = anchor_url.split("//")[1]
    domain = host.split(":")[0]
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    doc = workspace / "agreement.txt"
    run_cli("keygen", "--out", "k", "--force")
    # Real-world order: keygen -> publish -> sign -> verify.
    pub_b64 = (workspace / "k.pub").read_text().strip().splitlines()[-1]
    pub_raw = core.b64_decode(pub_b64)
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    run_cli("sign", str(doc), "--key", "k.key", "--anchor", domain, "--role", "CSO", "--org", "Example Org")
    other = workspace / "other.txt"
    other.write_text("an unrelated document", encoding="utf-8")
    out = run_cli("verify", str(other), "--qr", str(workspace / "agreement.txt.qrsig.png"), "--offline", expect=1)
    assert any("FAILED" in line for line in out)


def test_anchor_validate_command(anchor_server):
    docs, server = anchor_server
    _, pub = core.new_keypair()
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub, "qs1-v")
    port = server.server_address[1]
    out = run_cli("anchor-validate", "--url", "http://127.0.0.1:%d/.well-known/qrsig-keys" % port, "--domain", "example.org")
    assert any("VALID" in line for line in out)
    docs["/.well-known/qrsig-keys"]["keys"][0]["status"] = "bogus"
    out = run_cli("anchor-validate", "--url", "http://127.0.0.1:%d/.well-known/qrsig-keys" % port, "--domain", "example.org", expect=1)
    assert any("INVALID" in line for line in out)


def test_embedded_signature_verifies_without_byte_binding(workspace, keypair_and_anchor):
    """THE self-referential case: a document that carries its own signature."""
    priv, pub_raw, anchor_url, docs = keypair_and_anchor
    host = anchor_url.split("//")[1]
    domain = host.split(":")[0]
    doc = workspace / "agreement.txt"
    run_cli("keygen", "--out", "k", "--force")
    pub_b64 = (workspace / "k.pub").read_text().strip().splitlines()[-1]
    pub_raw = core.b64_decode(pub_b64)
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    run_cli("sign", str(doc), "--key", "k.key", "--anchor", domain,
            "--role", "CSO", "--org", "Example Org", "--placement", "embedded")
    env = json.loads((workspace / "agreement.txt.qrsig.json").read_text())
    assert env["payload"]["signature_placement"] == "embedded"
    assert "doc_sha256" not in env["payload"]
    out = run_cli("verify", str(doc), "--anchor-url", anchor_url + "/.well-known/qrsig-keys")
    assert any("L3a byte binding" in l and "N/A" in l for l in out)
    assert any("L3b content binding" in l and "PASS" in l for l in out)
    assert any("VERIFIED" in l for l in out)


def test_embedded_payload_rejects_doc_sha256(workspace):
    from qrsig import core as C
    payload = {
        "v": 1, "anchor": "example.org", "role": "CSO", "org": "Example Org",
        "doc_sha256": "a" * 64, "signature_placement": "embedded",
        "content_sha256": "b" * 64, "content_method": "plain-text-v1",
        "key_id": "qs1-x", "pubkey_b64": C.b64_encode(bytes(range(32))),
        "signed_at": "2026-11-16T00:00:00Z",
    }
    problems = C.validate_payload_shape(payload)
    assert any("doc_sha256 must be absent" in p for p in problems)


def test_detached_payload_requires_doc_sha256(workspace):
    from qrsig import core as C
    payload = {
        "v": 1, "anchor": "example.org", "role": "CSO", "org": "Example Org",
        "signature_placement": "detached",
        "content_sha256": "b" * 64, "content_method": "plain-text-v1",
        "key_id": "qs1-x", "pubkey_b64": C.b64_encode(bytes(range(32))),
        "signed_at": "2026-11-16T00:00:00Z",
    }
    problems = C.validate_payload_shape(payload)
    assert any("doc_sha256" in p and "detached" in p for p in problems)


def test_embedded_tampered_content_fails(workspace, keypair_and_anchor):
    """An embedded signature must NOT verify once the TEXT changes.

    Regression guard: the first cut of the placement fix reported L3a as N/A
    and then let the aggregate through, so a tampered embedded document
    passed.  N/A is not a pass.
    """
    priv, pub_raw, anchor_url, docs = keypair_and_anchor
    host = anchor_url.split("//")[1]
    domain = host.split(":")[0]
    doc = workspace / "agreement.txt"
    run_cli("keygen", "--out", "k", "--force")
    pub_b64 = (workspace / "k.pub").read_text().strip().splitlines()[-1]
    pub_raw = core.b64_decode(pub_b64)
    kid = core.derive_key_id(pub_raw)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(pub_raw, kid, domain=domain)
    run_cli("sign", str(doc), "--key", "k.key", "--anchor", domain, "--role", "CSO", "--org", "Example Org", "--placement", "embedded")
    doc.write_text("The party of the first part agrees to NOTHING at all.\n", encoding="utf-8")
    out = run_cli("verify", str(doc), "--anchor-url", anchor_url + "/.well-known/qrsig-keys", expect=1)
    assert any("L3b content binding" in l and "FAIL" in l for l in out)
    assert any("FAILED" in l for l in out)


def test_embedded_without_content_binding_is_incoherent(workspace):
    """Embedded placement REQUIRES content binding: it is the only leg left."""
    from qrsig import core as C
    payload = {
        "v": 1, "anchor": "example.org", "role": "CSO", "org": "Example Org",
        "signature_placement": "embedded",
        "key_id": "qs1-x", "pubkey_b64": C.b64_encode(bytes(range(32))),
        "signed_at": "2026-11-16T00:00:00Z",
    }
    problems = C.validate_payload_shape(payload)
    assert any("embedded placement requires content" in p for p in problems)
