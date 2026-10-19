"""qrsig CLI - the human-verifiable signature workflow.

Commands (each does one thing, composable, silent on success):

    qrsig keygen            generate an Ed25519 keypair -> qrsig.key/.pub
    qrsig sign <file>       sign a document, emit .qrsig.json + QR PNG
    qrsig verify <file>     verify a document (L1 math, L2 anchor, L3 binding)
    qrsig qr <sig.json>     render the QR PNG from a saved signature
    qrsig decode <img>      decode a QR image back to a URI
    qrsig anchor-validate   fetch + structurally validate an anchor

Verify resolution order for the signature source: a *.qrsig.json next
to the document, then a --qr image (photo/print of the document), then
--uri. The verify command is the spec made walkable: it prints the
trust levels reached and fails LOUDLY on any mismatch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Optional

from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from . import __version__, anchor as anchor_mod
from . import binding, core, legacy, qrcode

KEY_FILE = "qrsig.key"
PUB_FILE = "qrsig.pub"
SIG_SUFFIX = ".qrsig.json"
PEM_PUB_HEADER = b"-----BEGIN PUBLIC KEY-----\n"
PEM_PUB_FOOTER = "-----END PUBLIC KEY-----\n"


def _encryption(password: str):
    """Empty password = unencrypted PKCS8 (NoEncryption); a supplied
    password = BestAvailableEncryption. Never encrypt with b''."""
    return BestAvailableEncryption(password.encode()) if password else NoEncryption()


def _now_rfc3339() -> str:
    """Current UTC time as RFC 3339 with second precision."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit(msg: str) -> None:
    print(msg)


def _die(msg: str) -> "None":
    print("error: %s" % msg, file=sys.stderr)
    raise SystemExit(2)


def cmd_keygen(args: argparse.Namespace) -> None:
    priv, pub_raw = core.new_keypair()
    if os.path.exists(args.out + ".key") and not args.force:
        _die("%s.key exists; use --force to overwrite" % args.out)
    pem = priv.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=_encryption(args.password),
    )
    with open(args.out + ".key", "wb") as fh:
        fh.write(pem)
    os.chmod(args.out + ".key", 0o600)
    b64 = core.b64_encode(pub_raw)
    with open(args.out + ".pub", "w") as fh:
        fh.write("# QRSIG1 public key | key_id %s\n%s\n" % (core.derive_key_id(pub_raw), b64))
    _emit("key_id: %s" % core.derive_key_id(pub_raw))
    _emit("public key (b64, 32 raw bytes): %s" % b64)


def _load_private_key(path: str, password: str):
    return load_pem_private_key(open(path, "rb").read(), password=password.encode() if password else None)


def cmd_sign(args: argparse.Namespace) -> None:
    if not os.path.exists(args.key):
        _die("key not found: %s (run `qrsig keygen`)" % args.key)
    data = open(args.file, "rb").read()
    priv = _load_private_key(args.key, args.password)
    pub_raw = priv.public_key().public_bytes_raw()
    payload = {
        "v": core.SCHEMA_VERSION,
        "anchor": args.anchor,
        "role": args.role,
        "org": args.org,
        "doc_sha256": hashlib.sha256(data).hexdigest(),
        "key_id": args.key_id or core.derive_key_id(pub_raw),
        "pubkey_b64": core.b64_encode(pub_raw),
        "signed_at": args.signed_at or _now_rfc3339(),
    }
    if args.content != "none":
        method = binding.detect_method(args.file) if args.content == "auto" else args.content
        try:
            payload["content_sha256"] = binding.content_digest(data, method)
            payload["content_method"] = method
        except ValueError as exc:
            _die(str(exc))
    envelope = core.sign_payload(priv, payload)
    sig_path = args.file + SIG_SUFFIX
    with open(sig_path, "w") as fh:
        json.dump(envelope, fh, indent=1, sort_keys=True)
    png_path = args.file + ".qrsig.png"
    qrcode.render_png(core.envelope_to_uri(envelope), png_path)
    _emit(sig_path)
    _emit(png_path)
    _emit("doc_sha256: %s" % payload["doc_sha256"])
    if "content_sha256" in payload:
        _emit("content (%s): %s" % (payload["content_method"], payload["content_sha256"]))


def _resolve_envelope(args: argparse.Namespace, doc_path: str):
    """Find the signature envelope: sidecar json > --qr image > --uri.
    Legacy GUANSIG1 URIs are detected and lifted transparently."""
    uri = None
    if getattr(args, "uri", None):
        uri = args.uri
    elif getattr(args, "qr", None):
        decoded = qrcode.decode_png(args.qr)
        if legacy.is_legacy_uri(decoded):
            _emit("legacy format detected (GUANSIG1)")
            legacy_env = legacy.parse_legacy_uri(decoded)
            anchor = args.anchor or (legacy_env["payload"].get("anchor") if "anchor" in legacy_env["payload"] else None)
            if not anchor:
                _die("legacy envelope has no anchor; pass --anchor <domain> (or --anchor-url)")
            return "legacy", legacy.upgrade_legacy_envelope(legacy_env, anchor)
        uri = decoded
    else:
        sidecar = doc_path + SIG_SUFFIX
        if os.path.exists(sidecar):
            return "qrsig", json.load(open(sidecar))
        _die("no signature found: expected %s, or pass --qr <image> / --uri <QRSIG1:...>" % sidecar)
    try:
        return "qrsig", core.parse_uri(uri)
    except ValueError as exc:
        if legacy.is_legacy_uri(uri):
            return "legacy", legacy.upgrade_legacy_envelope(legacy.parse_legacy_uri(uri), args.anchor or _die("legacy URI needs --anchor"))
        _die(str(exc))


def cmd_verify(args: argparse.Namespace) -> None:
    if not os.path.exists(args.file):
        _die("document not found: %s" % args.file)
    doc_bytes = open(args.file, "rb").read()
    source, envelope = _resolve_envelope(args, args.file)
    payload = envelope["payload"]

    # L1 - MATH: does the signature verify at all?
    # Legacy envelopes embed an SPKI key; the signature binds the
    # DERIVED raw key, so verify externally against it.
    pubkey_override = envelope.get("legacy_raw_pub") if source == "legacy" else None
    ok, reason = core.verify_signature(envelope, pubkey_raw=pubkey_override)
    _emit("L1 math (self-contained):        %s" % ("PASS" if ok else "FAIL - " + reason))
    shape = core.validate_payload_shape(payload, require_anchor=(source == "qrsig"))
    if shape:
        for problem in shape:
            _emit("    shape: %s" % problem)
    l1 = ok and not shape

    # L2 - ANCHOR: does the signer's domain vouch for this key?
    anchor_pub: Optional[bytes] = None
    l2 = False
    domain = payload.get("anchor") or (envelope.get("anchor_domain") if source == "legacy" else None)
    if args.offline:
        _emit("L2 anchor:                       SKIPPED (--offline)")
        url = None
    elif getattr(args, "anchor_url", None):
        url = args.anchor_url
        _emit("using explicit anchor URL: %s (trusted as given)" % url)
    elif domain:
        url = anchor_mod.anchor_url(domain)
    else:
        url = None
    if url:
        try:
            doc = anchor_mod.fetch(url, require_https=url.startswith("https://"))
            problems = anchor_mod.validate_directory(doc, expect_domain=domain)
            if problems:
                for problem in problems:
                    _emit("    anchor: %s" % problem)
            else:
                aok, note, anchor_pub = anchor_mod.check_envelope(
                envelope, doc, pubkey_raw_override=pubkey_override, skip_shape=(source == "legacy")
            )
                _emit("L2 anchor (%s):         %s - %s" % (domain, "PASS" if aok else "FAIL", note))
                l2 = aok
        except Exception as exc:  # noqa: BLE001 - network errors are findings
            _emit("L2 anchor (%s):         UNREACHABLE - %s" % (domain, exc))
    elif source == "legacy":
        _emit("L2 anchor:                       SKIPPED (legacy envelope; supply --anchor-url)")
    else:
        _emit("L2 anchor:                       SKIPPED (payload carries no anchor)")

    # L3 - BINDING: does the payload name THIS document?
    doc_ok = payload.get("doc_sha256") == hashlib.sha256(doc_bytes).hexdigest()
    _emit("L3 byte binding (doc_sha256):    %s" % ("PASS" if doc_ok else "FAIL"))
    l3 = doc_ok
    if payload.get("content_sha256") and payload.get("content_method"):
        try:
            content_ok = binding.content_digest(doc_bytes, payload["content_method"]) == payload["content_sha256"]
        except ValueError as exc:
            content_ok = False
            _emit("    content method error: %s" % exc)
        _emit("L3 content binding (%s):  %s" % (payload["content_method"], "PASS" if content_ok else "FAIL"))
        l3 = l3 and content_ok

    verified = l1 and l3 and (l2 or args.offline)
    if verified and not l2:
        _emit("NOTE: verified offline (math + binding only); capacity NOT confirmed without the anchor")
    _emit("role: %s | org: %s | key_id: %s | signed_at: %s" % (
        payload.get("role"), payload.get("org"), payload.get("key_id"), payload.get("signed_at")))
    _emit("VERIFIED" if verified else "FAILED")
    raise SystemExit(0 if verified else 1)


def cmd_qr(args: argparse.Namespace) -> None:
    envelope = json.load(open(args.sig))
    qrcode.render_png(core.envelope_to_uri(envelope), args.out)
    _emit(args.out)


def cmd_decode(args: argparse.Namespace) -> None:
    _emit(qrcode.decode_png(args.image))


def cmd_anchor_validate(args: argparse.Namespace) -> None:
    url = args.url or anchor_mod.anchor_url(args.domain)
    doc = anchor_mod.fetch(url, require_https=url.startswith("https://"))
    problems = anchor_mod.validate_directory(doc, expect_domain=args.domain)
    for problem in problems:
        _emit("problem: %s" % problem)
    _emit("anchor %s: %s (%d keys)" % (url, "VALID" if not problems else "INVALID", len(doc.get("keys", []))))
    raise SystemExit(0 if not problems else 1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qrsig", description="QRSIG1 - human-verifiable signatures for agentic intelligences")
    parser.add_argument("--version", action="version", version="qrsig %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate an Ed25519 keypair")
    p.add_argument("--out", default="qrsig", help="basename for <out>.key / <out>.pub")
    p.add_argument("--password", default="", help="optional private-key passphrase")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_keygen)

    p = sub.add_parser("sign", help="sign a document and emit sidecar + QR PNG")
    p.add_argument("file")
    p.add_argument("--key", default=KEY_FILE)
    p.add_argument("--password", default="")
    p.add_argument("--anchor", required=True, help="signer's domain (trust anchor host)")
    p.add_argument("--role", required=True)
    p.add_argument("--org", required=True)
    p.add_argument("--key-id", default=None)
    p.add_argument("--signed-at", default=None, help="RFC 3339 UTC; defaults to now (tests pin this)")
    p.add_argument("--content", default="auto", choices=["auto", "none", "plain-text-v1", "pdf-pypdf-text-v1"])
    p.set_defaults(fn=cmd_sign)

    p = sub.add_parser("verify", help="verify a document at L1/L2/L3")
    p.add_argument("file")
    p.add_argument("--qr", default=None, help="QR image carrying the signature")
    p.add_argument("--uri", default=None, help="QRSIG1:/GUANSIG1: URI")
    p.add_argument("--anchor", default=None, help="override anchor domain (legacy envelopes)")
    p.add_argument("--anchor-url", default=None, help="explicit anchor JSON URL (legacy)")
    p.add_argument("--offline", action="store_true", help="skip L2; caps assurance at math+binding")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("qr", help="render QR PNG from a saved signature")
    p.add_argument("sig")
    p.add_argument("--out", default=None)
    p.set_defaults(fn=cmd_qr)

    p = sub.add_parser("decode", help="decode a QR image to its URI")
    p.add_argument("image")
    p.set_defaults(fn=cmd_decode)

    p = sub.add_parser("anchor-validate", help="fetch + validate a trust anchor")
    p.add_argument("--domain", default=None)
    p.add_argument("--url", default=None)
    p.set_defaults(fn=cmd_anchor_validate)
    return parser


def main(argv=None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
