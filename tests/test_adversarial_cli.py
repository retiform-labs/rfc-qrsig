"""Adversarial / e2e / regression hardening for the qrsig CLI and QR codec.

Three surfaces, in order of how much damage a regression does:

  A. QR round-trip integrity  - the QR IS the format. If it does not carry
     the exact URI back, a human scanning a printed page is verifying
     something other than what the signer signed.
  B. CLI contract             - exit codes are the machine contract
     (0 VERIFIED / 1 FAILED / 2 hard error) and the _die messages are the
     human contract. A traceback is neither.
  C. Placement invariants     - embedded means byte binding is IMPOSSIBLE,
     not merely failed, so N/A must never be read as a pass.

Deliberately NOT duplicated from tests/test_e2e.py: test_full_workflow,
test_sidecar_verify, test_tampered_document_fails,
test_offline_verify_caps_assurance, test_content_binding_survives_reformat,
test_wrong_document_for_qr, test_anchor_validate_command,
test_embedded_signature_verifies_without_byte_binding,
test_embedded_payload_rejects_doc_sha256,
test_detached_payload_requires_doc_sha256, test_embedded_tampered_content_fails,
test_embedded_without_content_binding_is_incoherent.
"""

import contextlib
import hashlib
import io
import json
import os

import pytest

from qrsig import cli, core, qrcode

from test_binding_anchor import make_anchor_doc

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


# ---------------------------------------------------------------- harness

def run(argv):
    """Invoke the CLI in-process; return (exit_code, stdout_lines, stderr).

    A traceback escaping main() is reported as a string exit code rather than
    raised, so a test can assert that the CLI did NOT crash -- which is the
    whole point of several tests here.
    """
    out, err = io.StringIO(), io.StringIO()
    # A command that returns normally IS exit 0: keygen/sign/qr/decode end by
    # returning, while verify/anchor-validate end with an explicit SystemExit.
    code = 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code if exc.code is not None else 0
    except BaseException as exc:  # noqa: BLE001 - an uncaught escape IS the finding
        code = "TRACEBACK:%s:%s" % (type(exc).__name__, exc)
    return code, out.getvalue().splitlines(), err.getvalue().strip()


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "agreement.txt").write_text(
        "The party of the first part agrees to everything.\n\nSigned in the tent.\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture()
def bench(workspace, keypair_and_anchor):
    """keygen -> publish pubkey at the local anchor -> ready to sign.

    Returns (domain, anchor_url, workspace, docs). Mirrors the real order:
    keygen, publish, sign, verify -- the anchor must exist before a signature
    that names the domain is meaningful.
    """
    _priv, _pub, anchor_url, docs = keypair_and_anchor
    domain = anchor_url.split("//")[1].split(":")[0]
    code, _out, err = run(["keygen", "--out", "k", "--force"])
    assert code == 0, err
    pub_b64 = (workspace / "k.pub").read_text().strip().splitlines()[-1]
    pub_raw = core.b64_decode(pub_b64)
    docs["/.well-known/qrsig-keys"] = make_anchor_doc(
        pub_raw, core.derive_key_id(pub_raw), domain=domain
    )
    return domain, anchor_url + "/.well-known/qrsig-keys", workspace, docs


def sign(bench, *extra):
    domain, anchor, workspace, _docs = bench
    code, out, err = run(
        ["sign", "agreement.txt", "--key", "k.key", "--anchor", domain,
         "--role", "CSO", "--org", "Example Org",
         "--signed-at", "2026-11-17T00:00:00Z"] + list(extra)
    )
    assert code == 0, "sign failed rc=%s out=%s err=%s" % (code, out, err)
    return workspace / "agreement.txt.qrsig.json"


def qr_codec_available():
    try:
        import pyzbar.pyzbar  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError as exc:
        pytest.skip("QR decoding unavailable in this environment: %s" % exc)
    return True


# =============================================================== A. QR e2e

def test_signed_png_decodes_to_the_signed_uri(bench):
    """The emitted PNG must carry EXACTLY envelope_to_uri(envelope).

    Not merely 'a QRSIG1 URI' -- the same one. A QR that decodes to a
    re-serialised envelope could differ in canonical form and verify against
    a document the signer never saw.
    """
    codec = qr_codec_available()
    assert codec
    sig = sign(bench)
    envelope = json.loads(sig.read_text())
    expected = core.envelope_to_uri(envelope)

    code, out, err = run(["decode", "agreement.txt.qrsig.png"])
    assert code == 0, err
    assert out == [expected]
    assert qrcode.decode_png(str(bench[2] / "agreement.txt.qrsig.png")) == expected


def test_render_png_and_render_png_bytes_are_true_mirrors(bench):
    """Two documented mirrors must produce byte-equivalent QR payloads."""
    codec = qr_codec_available()
    assert codec
    sig = sign(bench)
    uri = core.envelope_to_uri(json.loads(sig.read_text()))

    from_bytes = qrcode.decode_png_bytes(qrcode.render_png_bytes(uri))
    from_file = qrcode.decode_png(str(bench[2] / "agreement.txt.qrsig.png"))
    assert from_bytes == uri
    assert from_file == uri
    assert from_bytes == from_file


def test_qr_path_reaches_the_same_verdict_as_the_sidecar(bench):
    """Signature source must not change the answer: sidecar and --qr agree.

    The QR is the paper leg of the workflow. If it were weaker than the
    sidecar, a printed document would verify differently from a digital one.
    """
    codec = qr_codec_available()
    assert codec
    _domain, anchor_url, _ws, _docs = bench
    sign(bench)

    side_code, side_out, side_err = run(
        ["verify", "agreement.txt", "--anchor-url", anchor_url]
    )
    qr_code, qr_out, qr_err = run(
        ["verify", "agreement.txt", "--qr", "agreement.txt.qrsig.png",
         "--anchor-url", anchor_url]
    )
    assert side_code == 0, side_err + str(side_out)
    assert qr_code == 0, qr_err + str(qr_out)
    assert "VERIFIED" in side_out and "VERIFIED" in qr_out
    # Same trust levels reached, not just the same final word.
    assert [l for l in side_out if l.startswith(("L1", "L2", "L3"))] == \
           [l for l in qr_out if l.startswith(("L1", "L2", "L3"))]


def test_qr_decodes_at_the_modules_own_scale_and_border(bench):
    """SCALE=8 / BORDER=2 (the shipped defaults) must decode without a retry.

    If the module's own output needed the upscale fallback, every print
    would be riding on a rescue path rather than on the format working.
    """
    codec = qr_codec_available()
    assert codec
    from pyzbar.pyzbar import decode as zbar
    from PIL import Image

    sig = sign(bench)
    uri = core.envelope_to_uri(json.loads(sig.read_text()))
    png = bench[2] / "agreement.txt.qrsig.png"

    img = Image.open(str(png)).convert("L")
    direct = zbar(img)
    assert len(direct) == 1, "QR at shipped SCALE=%d/BORDER=%d needs a rescue path" % (
        qrcode.SCALE, qrcode.BORDER)
    assert direct[0].data.decode("utf-8") == uri


def test_low_scale_qr_is_recovered_by_the_2x_upscale_retry(workspace):
    """Prove the 2x retry branch is reachable, not merely present in source.

    Rendered at scale=1 the direct zbar pass returns nothing and the retry
    finds the code. That is the exact 100-dpi-document failure the fallback
    exists for. (Cannot be produced from the shipped SCALE=8 output, so this
    fixture renders its own low-scale QR.)
    """
    codec = qr_codec_available()
    assert codec
    import segno
    from pyzbar.pyzbar import decode as zbar
    from PIL import Image

    envelope = {
        "payload": {
            "v": core.SCHEMA_VERSION, "anchor": "example.org", "role": "CSO",
            "org": "Example Org", "doc_sha256": "a" * 64, "key_id": "qs1-x",
            "pubkey_b64": core.b64_encode(bytes(range(32))),
            "signed_at": "2026-11-16T00:00:00Z",
            "signature_placement": "detached",
        },
        "sig_b64": "x" * 86,
    }
    uri = core.envelope_to_uri(envelope)
    qr = segno.make(uri, error=qrcode.EC_LEVEL)
    out = str(workspace / "tiny.png")
    qr.save(out, scale=1, border=qrcode.BORDER)

    img = Image.open(out).convert("L")
    assert len(zbar(img)) == 0, "fixture not small enough to exercise the retry"
    assert len(zbar(img.resize((img.width * 2, img.height * 2)))) == 1
    assert qrcode.decode_png(out) == uri


# ======================================================== B. CLI exit codes

def test_verify_missing_document_is_a_hard_error(workspace):
    code, _out, err = run(["verify", "nosuch.txt"])
    assert code == 2
    assert "document not found: nosuch.txt" in err


def test_verify_without_any_signature_names_the_sidecar_and_the_flags(workspace):
    """A refusal must name its cause AND the cure (not just the symptom).

    'no signature found' alone leaves a human stuck. The message must name
    the sidecar path that was expected and the two flags that would work.
    """
    code, _out, err = run(["verify", "agreement.txt"])
    assert code == 2
    assert "agreement.txt.qrsig.json" in err
    assert "--qr" in err
    assert "--uri" in err


def test_tampered_document_is_a_verdict_not_a_crash(bench):
    """FAILED is exit 1. A crash would be exit 2 or a traceback -- both wrong."""
    _domain, anchor_url, ws, _docs = bench
    sign(bench)
    (ws / "agreement.txt").write_text("tampered beyond recognition\n", encoding="utf-8")
    code, out, err = run(["verify", "agreement.txt", "--anchor-url", anchor_url])
    assert code == 1, "tampered doc must be exit 1 (FAILED), got %s: %s%s" % (
        code, out, err)
    assert "FAILED" in out
    assert "TRACEBACK" not in str(code)


def test_sign_missing_key_names_the_command_that_creates_one(workspace):
    code, _out, err = run(
        ["sign", "agreement.txt", "--key", "nokey.key", "--anchor", "a.org",
         "--role", "r", "--org", "o"]
    )
    assert code == 2
    assert "key not found: nokey.key" in err
    assert "qrsig keygen" in err


def test_sign_missing_document_is_a_hard_error_not_a_traceback(bench):
    """FIXED: cmd_sign read the document with no existence check, so a typo
    surfaced as an unhandled FileNotFoundError. Every sibling command (_die)
    reports a missing input cleanly; sign must too."""
    code, _out, err = run(
        ["sign", "nosuchdoc.txt", "--key", "k.key", "--anchor", "a.org",
         "--role", "r", "--org", "o"]
    )
    assert code == 2, "expected clean exit 2, got %r" % (code,)
    assert "document not found: nosuchdoc.txt" in err


def test_keygen_refuses_to_clobber_then_force_overwrites(bench):
    _domain, _anchor, ws, _docs = bench
    before = (ws / "k.pub").read_text()
    code, _out, err = run(["keygen", "--out", "k"])
    assert code == 2
    assert "--force" in err
    assert (ws / "k.pub").read_text() == before, "refused keygen must not touch files"

    code, _out, err = run(["keygen", "--out", "k", "--force"])
    assert code == 0, err
    assert (ws / "k.pub").read_text() != before, "--force must actually regenerate"


def test_keygen_private_key_mode_is_0600(bench):
    _domain, _anchor, ws, _docs = bench
    mode = os.stat(str(ws / "k.key")).st_mode & 0o777
    assert mode == 0o600, "private key mode is %o, expected 600" % mode


def test_anchor_validate_without_domain_or_url_is_a_hard_error():
    """FIXED: anchor_mod.anchor_url(None) raised AttributeError on None.rstrip,
    so the bare command dumped a traceback instead of usage guidance."""
    code, _out, err = run(["anchor-validate"])
    assert code == 2, "expected clean exit 2, got %r" % (code,)
    assert "--domain" in err and "--url" in err


# =================================================== C. Placement invariants

def test_embedded_sign_omits_doc_sha256_and_carries_content(bench):
    sig = sign(bench, "--placement", "embedded")
    payload = json.loads(sig.read_text())["payload"]
    assert payload["signature_placement"] == "embedded"
    assert "doc_sha256" not in payload
    assert payload["content_sha256"] and payload["content_method"]


def test_detached_sign_carries_doc_sha256(bench):
    sig = sign(bench, "--placement", "detached")
    payload = json.loads(sig.read_text())["payload"]
    assert payload["signature_placement"] == "detached"
    assert payload["doc_sha256"] == hashlib.sha256(
        (bench[2] / "agreement.txt").read_bytes()).hexdigest()


def test_embedded_with_content_none_emits_a_payload_its_own_validator_rejects(bench):
    """HOLE, documented rather than fixed: sign accepts the combination and
    writes an artifact the product then refuses to verify.

    An embedded signature has no doc_sha256 (impossible, not failed) and
    --content none removes the content binding, which leaves NO binding leg
    at all. validate_payload_shape already calls this incoherent, so verify
    fails -- but sign happily emits the JSON and the QR first.
    """
    sig = sign(bench, "--placement", "embedded", "--content", "none")
    payload = json.loads(sig.read_text())["payload"]
    assert "doc_sha256" not in payload, "embedded must never carry doc_sha256"
    assert "content_sha256" not in payload, "fixture premise: --content none"
    assert "content_method" not in payload

    problems = core.validate_payload_shape(payload)
    assert any("embedded placement requires content" in p for p in problems), \
        "shape validator must reject the no-binding payload"

    code, out, err = run(["verify", "agreement.txt", "--offline"])
    assert code == 1, "a payload with no binding leg must FAILED, got %r" % (code,)
    assert any("shape: embedded placement requires content" in l for l in out)
    assert "FAILED" in out
    assert "VERIFIED" not in out


def test_embedded_na_byte_binding_is_not_a_pass(bench):
    """THE 5b3ba2a REGRESSION PIN. N/A is not a pass.

    For an embedded signature L3a prints N/A because byte binding is
    impossible. If N/A were folded into the aggregate as truthy, a tampered
    embedded document would VERIFY. Content binding is the only leg, so it
    has to carry the whole verdict alone.
    """
    _domain, anchor_url, ws, _docs = bench
    sign(bench, "--placement", "embedded")

    # Untampered: N/A on L3a, content PASS, VERIFIED.
    code, out, _err = run(["verify", "agreement.txt", "--anchor-url", anchor_url])
    assert code == 0
    assert any("L3a byte binding" in l and "N/A" in l for l in out)
    assert any("L3b content binding" in l and "PASS" in l for l in out)
    assert "VERIFIED" in out

    # Tampered: N/A on L3a still, content FAIL, and therefore FAILED.
    (ws / "agreement.txt").write_text(
        "The party of the first part agrees to NOTHING whatsoever.\n", encoding="utf-8")
    code, out, _err = run(["verify", "agreement.txt", "--anchor-url", anchor_url])
    assert code == 1, "tampered embedded doc must be exit 1, got %r: %s" % (code, out)
    assert any("L3a byte binding" in l and "N/A" in l for l in out), \
        "L3a must still report N/A -- the fix is that N/A cannot pass, not that it hides"
    assert any("L3b content binding" in l and "FAIL" in l for l in out)
    assert "FAILED" in out
    assert "VERIFIED" not in out


# ======================================================== D. Hostile input

def test_uri_without_the_qrsig1_prefix_names_the_prefix_problem(workspace):
    code, _out, err = run(["verify", "agreement.txt", "--uri", "https://evil.example/x"])
    assert code == 2
    assert "QRSIG1" in err
    assert "prefix" in err


def test_uri_with_base64_garbage_is_a_clean_error(workspace):
    code, _out, err = run(["verify", "agreement.txt", "--uri", "QRSIG1:!!!notbase64!!!"])
    assert code == 2, "expected clean exit 2, got %r" % (code,)
    assert err.startswith("error: malformed QRSIG1 body")


def test_uri_with_valid_base64_but_non_json_body_is_a_clean_error(workspace):
    code, _out, err = run(["verify", "agreement.txt", "--uri", "QRSIG1:YWJjZGVm"])
    assert code == 2, "expected clean exit 2, got %r" % (code,)
    assert err.startswith("error: malformed QRSIG1 body")


def test_qr_pointing_at_a_non_image_is_a_clean_error(workspace):
    """FIXED: PIL raises UnidentifiedImageError (an OSError subclass) straight
    out of Image.open, so --qr on a text file dumped a traceback on a human."""
    (workspace / "notes.txt").write_text("this is not an image\n", encoding="utf-8")
    code, _out, err = run(
        ["verify", "agreement.txt", "--qr", "notes.txt", "--offline"])
    assert code == 2, "expected clean exit 2, got %r" % (code,)
    assert "cannot read notes.txt as an image" in err
    assert "UnidentifiedImageError" not in err


def test_qr_image_with_no_qr_in_it_is_a_clean_error(workspace):
    """FIXED: decode_png raises ValueError('no QR code found in ...'), which
    the CLI did not catch."""
    codec = qr_codec_available()
    assert codec
    from PIL import Image

    Image.new("RGB", (200, 200), "white").save(str(workspace / "blank.png"), "PNG")
    code, _out, err = run(
        ["verify", "agreement.txt", "--qr", "blank.png", "--offline"])
    assert code == 2, "expected clean exit 2, got %r" % (code,)
    assert "no QR code found in blank.png" in err


def test_decode_pointing_at_a_non_image_is_a_clean_error(workspace):
    (workspace / "notes.txt").write_text("not an image\n", encoding="utf-8")
    code, _out, err = run(["decode", "notes.txt"])
    assert code == 2, "expected clean exit 2, got %r" % (code,)
    assert "cannot read notes.txt as an image" in err


def test_decode_of_a_missing_file_is_a_clean_error(workspace):
    code, _out, err = run(["decode", "nosuch.png"])
    assert code == 2
    assert "image not found: nosuch.png" in err


def test_qr_command_without_out_derives_a_sibling_png(bench):
    """FIXED: --out defaulted to None and reached segno.save, which called
    None.rfind -- an AttributeError for a flag the help text presents as
    optional."""
    codec = qr_codec_available()
    assert codec
    sig = sign(bench)
    code, out, err = run(["qr", str(sig)])
    assert code == 0, "qrsig qr without --out crashed: %r %s" % (code, err)
    assert out == [str(bench[2] / "agreement.txt.qrsig.png")]
    assert qrcode.decode_png(out[0]) == core.envelope_to_uri(json.loads(sig.read_text()))


def test_qr_command_on_a_missing_signature_is_a_clean_error(workspace):
    code, _out, err = run(["qr", "nosuch.json"])
    assert code == 2, "expected clean exit 2, got %r" % (code,)
    assert "signature not found: nosuch.json" in err


def test_qr_command_on_malformed_json_is_a_clean_error(workspace):
    (workspace / "bad.json").write_text("{not json", encoding="utf-8")
    code, _out, err = run(["qr", "bad.json"])
    assert code == 2, "expected clean exit 2, got %r" % (code,)
    assert "not valid JSON" in err


# ====================================== E. codec contract: the phishing hole

def test_render_png_bytes_refuses_a_non_qrsig1_uri():
    """DEFECT (falsified below): render_png validated the prefix, its
    documented mirror render_png_bytes did not, so a pipeline could mint a
    QR of an attacker-chosen string that decodes fine and is not a signature.
    """
    with pytest.raises(ValueError) as exc:
        qrcode.render_png_bytes("https://evil.example/pay")
    assert "QRSIG1" in str(exc.value)


def test_render_png_refuses_a_non_qrsig1_uri(tmp_path):
    out = str(tmp_path / "x.png")
    with pytest.raises(ValueError) as exc:
        qrcode.render_png("https://evil.example/pay", out)
    assert "QRSIG1" in str(exc.value)
    assert not os.path.exists(out), "a refused render must not leave a file behind"


def test_both_render_paths_agree_on_what_they_accept(tmp_path):
    """The mirror claim, tested as a claim: same input, same verdict."""
    accepted = "QRSIG1:abc"
    assert qrcode.render_png_bytes(accepted)[:8] == b"\x89PNG\r\n\x1a\n"
    never = str(tmp_path / "should-never-exist.png")
    for bad in ("", "not-a-uri", "QRSIG2:abc", "qrsig1:abc", " HTTPS://x"):
        with pytest.raises(ValueError):
            qrcode.render_png_bytes(bad)
        with pytest.raises(ValueError):
            qrcode.render_png(bad, never)
    assert not os.path.exists(never), "a refused render must not leave a file behind"


class TestOfflineLMessaging:
    """A --offline verify must print ONE L2 line, and it must be TRUE.

    Regression: the L2 block printed "SKIPPED (--offline)" and then fell
    through to a second branch that printed "SKIPPED (payload carries no
    anchor)" -- while the payload demonstrably carried one. A message that
    names a cause the code never checked is worse than silence: it sends a
    human looking for a missing field that is present.
    """

    def _signed(self, tmp_path, anchor="retiform.dev"):
        from qrsig import cli as cli_mod, core
        priv, pub = core.new_keypair()
        key = str(tmp_path / "k.key")
        from cryptography.hazmat.primitives.serialization import (
            Encoding, NoEncryption, PrivateFormat,
        )
        open(key, "wb").write(priv.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()))
        doc = tmp_path / "doc.txt"
        doc.write_bytes(b"a document\n")
        cli_mod.main(["sign", str(doc), "--key", key, "--anchor", anchor,
                      "--role", "r", "--org", "o",
                      "--signed-at", "2026-11-17T00:00:00Z"])
        return str(doc)

    def test_offline_prints_exactly_one_l2_line(self, tmp_path, capsys):
        from qrsig import cli as cli_mod
        doc = self._signed(tmp_path)
        capsys.readouterr()
        try:
            cli_mod.main(["verify", doc, "--offline"])
        except SystemExit as exc:
            assert exc.code == 0, "offline verify of a valid signature must exit 0"
        out = capsys.readouterr().out
        l2_lines = [ln for ln in out.splitlines() if ln.startswith("L2 anchor")]
        assert len(l2_lines) == 1, "expected exactly one L2 line, got %r" % (l2_lines,)
        assert "--offline" in l2_lines[0]

    def test_offline_does_not_claim_the_payload_lacks_an_anchor(self, tmp_path, capsys):
        """The specific false message. The payload HAS an anchor; saying it
        does not is a lie about a field a human can check in one command."""
        from qrsig import cli as cli_mod
        doc = self._signed(tmp_path)
        capsys.readouterr()
        try:
            cli_mod.main(["verify", doc, "--offline"])
        except SystemExit:
            pass
        out = capsys.readouterr().out
        assert "payload carries no anchor" not in out, (
            "offline verify claimed the payload carries no anchor: %r" % out
        )
