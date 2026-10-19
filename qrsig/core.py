"""QRSIG1 core: canonical JSON, envelope codec, Ed25519 sign/verify.

Envelope (the URI embedded in the QR code)::

    QRSIG1:<base64url( canonical({"payload": {...}, "sig_b64": "..."}))>

The Ed25519 signature covers canonical(payload) ALONE - never the
wrapper. Payload v1 fields (all signed - capacity is declared, not
assumed):

    v               integer, 1
    anchor          signer's domain (the trust anchor host, e.g. "retiform.dev")
    role            human-readable capacity, e.g. "Chief Synthetic Officer"
    org             organization, e.g. "Retiform Labs LLC"
    doc_sha256      lowercase hex SHA-256 of the raw document bytes
    content_sha256  optional; hex SHA-256 of bound CONTENT (see binding)
    content_method  optional; versioned method id for content binding
    key_id          stable key identifier (opaque; see cli.keygen)
    pubkey_b64      RAW 32-byte Ed25519 public key, base64 (std, padded)
    signed_at       RFC 3339 UTC timestamp (tamper-evident via signature)

Design notes carried from field verification (executed OA, 2026-10-18):

* The signature binds canonical(payload) alone. A verifier MUST NOT
  hash the wrapper.
* ``doc_sha256`` binds raw bytes. Documents that pass through
  container-rewriting tools (PDF signing apps) break byte binding;
  add ``content_sha256`` + ``content_method`` to survive rewrites.
* ``anchor`` is INSIDE the signed payload: a verifier derives the
  anchor URL from the signature itself, so a self-consistent forgery
  (attacker key + attacker payload) still points at the attacker's
  domain, which is exactly the honest answer - it names its own trust
  root instead of ours.
"""

from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

URI_PREFIX = "QRSIG1:"
SCHEMA_VERSION = 1

# SPKI DER header for Ed25519 (RFC 8410): 12 bytes before the raw key.
_SPKI_ED25519_HEADER = bytes.fromhex("302a300506032b6570032100")


def _nfc(value: Any) -> Any:
    """Recursively NFC-normalize every string in a JSON-shaped value.

    Canonical form is only well-defined if equivalent Unicode strings
    serialize identically; normalization happens HERE so both signer
    and verifier derive the same bytes without trusting the caller.
    """
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_nfc(v) for v in value]
    if isinstance(value, dict):
        return {k: _nfc(v) for k, v in value.items()}
    return value


def canonical(payload: Any) -> bytes:
    """Serialize to the canonical JSON form: sorted keys (recursively),
    no whitespace, UTF-8 literals (ensure_ascii=False), NFC strings.

    Note for GUANSIG1 compatibility: the legacy signer used
    ensure_ascii=True; payloads were pure ASCII, so bytes are identical.
    """
    return json.dumps(
        _nfc(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def derive_key_id(pubkey_raw: bytes) -> str:
    """Default key_id: stable, derived, collision-checkable.
    qs1-<first 16 hex chars of SHA-256(pubkey_raw)>"""
    return "qs1-" + hashlib.sha256(pubkey_raw).hexdigest()[:16]


def new_keypair() -> Tuple[Ed25519PrivateKey, bytes]:
    """Generate an Ed25519 keypair; return (private, raw_public_32B)."""
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key().public_bytes_raw()


def spki_to_raw(spki_der: bytes) -> bytes:
    """Strip the 12-byte SPKI header from an Ed25519 SubjectPublicKeyInfo
    DER blob, returning the raw 32-byte public key. (GUANSIG1 legacy
    keys embed SPKI; QRSIG1 embeds raw bytes.)"""
    if not spki_der.startswith(_SPKI_ED25519_HEADER):
        raise ValueError("not an Ed25519 SPKI DER blob")
    raw = spki_der[len(_SPKI_ED25519_HEADER):]
    if len(raw) != 32:
        raise ValueError("unexpected Ed25519 key length: %d" % len(raw))
    return raw


def sign_payload(priv: Ed25519PrivateKey, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Sign canonical(payload); return the envelope dict.

    The envelope is what gets base64url'd into the QR URI. The
    signature covers canonical(payload) ALONE.
    """
    sig = priv.sign(canonical(payload))
    return {"payload": payload, "sig_b64": b64_encode(sig)}


def verify_signature(envelope: Dict[str, Any], pubkey_raw: Optional[bytes] = None) -> Tuple[bool, str]:
    """Verify the envelope's signature at the math level (L1).

    Returns (ok, reason). Uses the key embedded in the payload unless
    an external ``pubkey_raw`` is supplied (anchor mode).
    """
    try:
        payload = envelope["payload"]
        sig = b64_decode(envelope["sig_b64"])
    except (KeyError, TypeError, ValueError):
        return False, "malformed envelope"
    if pubkey_raw is None:
        try:
            pubkey_raw = b64_decode(payload["pubkey_b64"])
        except (KeyError, ValueError):
            return False, "missing or malformed pubkey_b64"
    if len(pubkey_raw) != 32:
        return False, "public key must be 32 raw bytes"
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_raw).verify(sig, canonical(payload))
    except InvalidSignature:
        return False, "signature invalid"
    return True, "ok"


def envelope_to_uri(envelope: Dict[str, Any]) -> str:
    """Envelope dict -> QRSIG1: URI (the QR payload)."""
    return URI_PREFIX + b64url_encode(canonical(envelope))


def parse_uri(uri: str) -> Dict[str, Any]:
    """QRSIG1: URI -> envelope dict. Raises ValueError on garbage."""
    if not uri.startswith(URI_PREFIX):
        raise ValueError("not a QRSIG1 URI (missing %r prefix)" % URI_PREFIX)
    try:
        blob = json.loads(b64url_decode(uri[len(URI_PREFIX):]).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - single failure surface
        raise ValueError("malformed QRSIG1 body: %s" % exc) from exc
    if not isinstance(blob, dict) or "payload" not in blob or "sig_b64" not in blob:
        raise ValueError("QRSIG1 body must contain payload and sig_b64")
    return blob


def validate_payload_shape(payload: Dict[str, Any], require_anchor: bool = True) -> list:
    """Structural checks for a v1 payload. Returns a list of problems
    (empty = valid). Field presence only - semantics live in anchor.py.
    """
    problems = []
    if payload.get("v") != SCHEMA_VERSION:
        problems.append("payload v must be %d" % SCHEMA_VERSION)
    for field in ("role", "org", "doc_sha256", "key_id", "pubkey_b64", "signed_at"):
        if not payload.get(field):
            problems.append("missing required field: %s" % field)
    if require_anchor and not payload.get("anchor"):
        problems.append("missing required field: anchor")
    if payload.get("doc_sha256"):
        if len(payload["doc_sha256"]) != 64 or payload["doc_sha256"] != payload["doc_sha256"].lower():
            problems.append("doc_sha256 must be 64 lowercase hex chars")
    try:
        if len(b64_decode(payload["pubkey_b64"])) != 32:
            problems.append("pubkey_b64 must decode to 32 bytes")
    except Exception:  # noqa: BLE001
        problems.append("pubkey_b64 is not valid base64")
    if (payload.get("content_sha256") is None) != (payload.get("content_method") is None):
        problems.append("content_sha256 and content_method must be present together")
    return problems
