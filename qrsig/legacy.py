"""GUANSIG1 legacy adapter - verify-only.

The format field-tested before the spec existed signed its URIs
``GUANSIG1:`` and embedded SPKI-DER public keys (no anchor field, no
version). This adapter lifts legacy envelopes into QRSIG1 shape so the
reference tool keeps verifying every pre-spec document. Legacy
signing is out of scope on purpose: new signatures use QRSIG1.
"""

from __future__ import annotations

from typing import Any, Dict

from .core import b64_decode, b64_encode, spki_to_raw

LEGACY_PREFIX = "GUANSIG1:"


def is_legacy_uri(uri: str) -> bool:
    return uri.startswith(LEGACY_PREFIX)


def parse_legacy_uri(uri: str) -> Dict[str, Any]:
    """Parse a GUANSIG1 URI into the RAW legacy envelope dict."""
    import base64
    import json

    if not is_legacy_uri(uri):
        raise ValueError("not a GUANSIG1 URI")
    body = uri[len(LEGACY_PREFIX):]
    # Legacy padding was stripped in transit; restore it.
    padding = "=" * (-len(body) % 4)
    blob = json.loads(base64.urlsafe_b64decode(body + padding).decode("utf-8"))
    if "payload" not in blob or "signature_b64" not in blob:
        raise ValueError("legacy body must contain payload and signature_b64")
    return blob


def upgrade_legacy_envelope(legacy: Dict[str, Any], anchor: str) -> Dict[str, Any]:
    """Adapt a legacy envelope for verification WITHOUT touching the
    signed payload.

    The payload bytes ARE the signature's commitment: rewriting the
    embedded SPKI key (or injecting v/anchor) breaks the very binding
    this adapter exists to honor. Instead:

    * ``signature_b64`` -> ``sig_b64`` (bytes identical)
    * the SPKI pubkey is converted and exposed as ``legacy_raw_pub``
      (a WRAPPER field - never signed, never trusted as content);
      the verifier uses it as the EXTERNAL verification key.
    * ``anchor`` is recorded at wrapper level for the L2 step; the
      legacy format carried no anchor, so the caller supplies it
      (CLI --anchor-url / --anchor).
    """
    payload = legacy["payload"]
    raw = spki_to_raw(b64_decode(payload["pubkey_b64"]))
    return {"payload": payload, "sig_b64": legacy["signature_b64"], "legacy_raw_pub": raw, "anchor_domain": anchor}
