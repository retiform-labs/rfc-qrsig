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
import re
import unicodedata
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

URI_PREFIX = "QRSIG1:"
SCHEMA_VERSION = 1

PLACEMENTS = ("detached", "embedded")

# A bare hostname, an optional port, and bracketed IPv6.
_HOSTNAME_RE = re.compile(r"^(?=.*[A-Za-z0-9])[A-Za-z0-9._:\[\]-]+$")

# SPKI DER header for Ed25519 (RFC 8410): 12 bytes before the raw key.
_SPKI_ED25519_HEADER = bytes.fromhex("302a300506032b6570032100")


def _nfc(value: Any) -> Any:
    """Recursively NFC-normalize every string in a JSON-shaped value.

    Canonical form is only well-defined if equivalent Unicode strings
    serialize identically; normalization happens HERE so both signer
    and verifier derive the same bytes without trusting the caller.

    Dict KEYS are normalized as well as values. Normalizing only values
    let two equivalent payloads canonicalize to different bytes, one
    precomposed and one decomposed - a malleability hole in a function
    whose whole purpose is determinism.

    Two distinct keys that collapse onto the same NFC form are AMBIGUOUS
    and raise rather than silently dropping one: the survivor would
    depend on insertion order.
    """
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_nfc(v) for v in value]
    if isinstance(value, dict):
        normalized = {}
        original = {}
        for key, item in value.items():
            norm_key = unicodedata.normalize("NFC", key) if isinstance(key, str) else key
            if norm_key in normalized:
                raise ValueError(
                    "canonical form is ambiguous: distinct keys %r and %r "
                    "both normalize to %r" % (original[norm_key], key, norm_key)
                )
            original[norm_key] = key
            normalized[norm_key] = _nfc(item)
        return normalized
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

    NEVER raises: the envelope is attacker-controlled input. A hostile
    payload, a hostile key, or a structure this function did not
    anticipate must all come back as (False, reason). An exception
    escaping a verifier is itself a failure - a caller that only reads
    the boolean never sees it, but a caller that does not expect it dies.
    """
    try:
        payload = envelope["payload"]
        sig = b64_decode(envelope["sig_b64"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return False, "malformed envelope"
    if not isinstance(payload, dict):
        return False, "malformed envelope (payload is not a JSON object)"
    if pubkey_raw is None:
        embedded = payload.get("pubkey_b64")
        if not isinstance(embedded, str):
            return False, "missing or malformed pubkey_b64"
        try:
            pubkey_raw = b64_decode(embedded)
        except (TypeError, ValueError, AttributeError):
            return False, "missing or malformed pubkey_b64"
    if not isinstance(pubkey_raw, (bytes, bytearray)):
        return False, "public key must be 32 raw bytes"
    if len(pubkey_raw) != 32:
        return False, "public key must be 32 raw bytes"
    try:
        message = canonical(payload)
    except Exception as exc:  # noqa: BLE001 - a verifier must not crash
        return False, "payload is not canonicalisable: %s" % type(exc).__name__
    try:
        Ed25519PublicKey.from_public_bytes(bytes(pubkey_raw)).verify(sig, message)
    except InvalidSignature:
        return False, "signature invalid"
    except Exception as exc:  # noqa: BLE001 - a verifier must not crash
        return False, "malformed envelope: %s" % type(exc).__name__
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


_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-]00:00)$"
)


def _is_rfc3339_utc(value: Any) -> bool:
    """True for an RFC 3339 timestamp expressed in UTC.

    The regex pins the SHAPE and the zero offset; fromisoformat then
    rejects impossible field values the regex cannot (month 13, hour
    25). Neither check subsumes the other.
    """
    if not isinstance(value, str) or not _RFC3339_UTC_RE.match(value):
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return False
    return True


def validate_payload_shape(payload: Dict[str, Any], require_anchor: bool = True) -> list:
    """Structural checks for a v1 payload. Returns a list of problems
    (empty = valid). Field presence and TYPE only - semantics live in
    anchor.py.

    NEVER raises, for the same reason verify_signature must not: the
    payload is attacker-controlled. Every check below tolerates a value
    of the wrong type, not merely the wrong content - a validator that
    throws on `doc_sha256: [1]` reports nothing and takes the caller
    down instead.
    """
    if not isinstance(payload, dict):
        return ["payload must be a JSON object"]
    problems = []
    version = payload.get("v")
    # `True == 1` and `1.0 == 1` in Python, so a bare `!=` accepts both,
    # and bool being an int subclass makes that comparison silently pass.
    if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
        problems.append("payload v must be %d" % SCHEMA_VERSION)
    for field in ("role", "org", "key_id", "pubkey_b64"):
        value = payload.get(field)
        if not value:
            problems.append("missing required field: %s" % field)
        elif not isinstance(value, str):
            problems.append("%s must be a string" % field)
    signed_at = payload.get("signed_at")
    if not signed_at:
        problems.append("missing required field: signed_at")
    elif not _is_rfc3339_utc(signed_at):
        problems.append("signed_at must be an RFC 3339 UTC timestamp")
    placement = payload.get("signature_placement")
    if placement not in PLACEMENTS:
        problems.append("signature_placement must be one of %s" % (PLACEMENTS,))
    elif placement == "detached" and not payload.get("doc_sha256"):
        problems.append("missing required field: doc_sha256 (required when detached)")
    elif placement == "embedded":
        if payload.get("doc_sha256"):
            problems.append("doc_sha256 must be absent when signature_placement is embedded")
        if not (payload.get("content_sha256") and payload.get("content_method")):
            problems.append("embedded placement requires content_sha256 + content_method")
    if require_anchor:
        anchor = payload.get("anchor")
        if not anchor:
            problems.append("missing required field: anchor")
        elif not isinstance(anchor, str):
            problems.append("anchor must be a string")
        elif not _HOSTNAME_RE.match(anchor):
            # ``anchor`` is signed content that a verifier feeds into a URL
            # fetch. A newline, space, slash or '@' in it is not a host: it is
            # a malformed anchor or a URL/header-injection attempt. Relying on
            # urllib's parser to reject it is not a defence - it raised
            # InvalidURL only after the request object was built.
            problems.append(
                "anchor must be a bare hostname (letters, digits, dots, "
                "hyphens, an optional port); got %r" % (anchor,))
    for field in ("doc_sha256", "content_sha256"):
        value = payload.get(field)
        if value and not (isinstance(value, str) and _HEX64_RE.match(value)):
            problems.append("%s must be 64 lowercase hex chars" % field)
    if isinstance(payload.get("pubkey_b64"), str):
        try:
            if len(b64_decode(payload["pubkey_b64"])) != 32:
                problems.append("pubkey_b64 must decode to 32 bytes")
        except Exception:  # noqa: BLE001
            problems.append("pubkey_b64 is not valid base64")
    if (payload.get("content_sha256") is None) != (payload.get("content_method") is None):
        problems.append("content_sha256 and content_method must be present together")
    return problems
