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
    assert any("L3 byte binding" in line and "PASS" in line for line in out)
    assert any("L3 content binding" in line and "PASS" in line for line in out)


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
    out = run_cli("verify", str(doc), "--anchor-url", anchor_url + "/.well-known/qrsig-keys", expect=1)
    assert any("L3 byte binding" in line and "FAIL" in line for line in out)
    assert any("L3 content binding" in line and "PASS" in line for line in out)


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
