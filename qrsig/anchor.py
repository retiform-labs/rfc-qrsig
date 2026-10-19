"""Trust anchors: the well-known key directory that replaces a PKI.

A signer publishes at ``https://<anchor>/.well-known/qrsig-keys``::

    {
      "v": 1,
      "domain": "retiform.dev",
      "keys": [
        {"key_id": "qs1-...", "pubkey_b64": "...", "role": "...",
         "org": "...", "status": "active|rotated|revoked",
         "valid_from": "...", "revoked_at": "..."}
      ],
      "updated_at": "..."
    }

The domain owner IS the certificate authority - auditable by anyone
with curl. Verification levels:

    L1 MATH    - signature verifies against the payload's embedded key
                 (offline; proves nothing about WHO)
    L2 ANCHOR  - key_id is listed at the anchor with a live status and
                 the pubkey bytes match (proves capacity: who says this
                 key belongs to this role at this domain)
    L3 BINDING - the document hashes in the payload match the document
                 you hold (byte and/or content level)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

WELL_KNOWN_PATH = "/.well-known/qrsig-keys"
STATUSES = ("active", "rotated", "revoked")
_TIMEOUT = 10


def anchor_url(domain: str) -> str:
    return "https://%s%s" % (domain.rstrip("/"), WELL_KNOWN_PATH)


def fetch(url: str, timeout: int = _TIMEOUT, require_https: bool = True) -> Dict[str, Any]:
    """GET and JSON-parse an anchor document.

    Derived anchor URLs (from a payload's signed domain) are ALWAYS
    https - a trust anchor fetched over plaintext is not a trust
    anchor. An explicitly-supplied URL (--anchor-url) may be http for
    testing and self-hosted registries; the caller opted in."""
    if require_https and not url.startswith("https://"):
        raise ValueError("anchor URL must be https (derived); pass require_https=False only for an explicitly supplied URL")
    with urlopen(Request(url, headers={"Accept": "application/json"}), timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def validate_directory(doc: Any, expect_domain: Optional[str] = None) -> List[str]:
    """Structural validation of an anchor document. Returns problems."""
    problems = []
    if not isinstance(doc, dict):
        return ["anchor document is not a JSON object"]
    if doc.get("v") != 1:
        problems.append("anchor v must be 1")
    if not doc.get("domain"):
        problems.append("anchor missing domain")
    if expect_domain and doc.get("domain") != expect_domain.rstrip("/"):
        problems.append("anchor domain %r does not match expected %r" % (doc.get("domain"), expect_domain))
    keys = doc.get("keys")
    if not isinstance(keys, list) or not keys:
        problems.append("anchor must list at least one key")
        return problems
    for entry in keys:
        kid = entry.get("key_id")
        if not kid:
            problems.append("key entry missing key_id")
            continue
        if entry.get("status") not in STATUSES:
            problems.append("key %s: invalid status %r" % (kid, entry.get("status")))
        pub = entry.get("pubkey_b64")
        if not pub:
            problems.append("key %s: missing pubkey_b64" % kid)
        else:
            import base64 as _b64

            try:
                if len(_b64.b64decode(pub)) != 32:
                    problems.append("key %s: pubkey_b64 must decode to 32 bytes" % kid)
            except Exception:  # noqa: BLE001
                problems.append("key %s: pubkey_b64 is not valid base64" % kid)
        if entry.get("status") == "revoked" and not entry.get("revoked_at"):
            problems.append("key %s: revoked without revoked_at" % kid)
    ids = [k.get("key_id") for k in keys if k.get("key_id")]
    if len(ids) != len(set(ids)):
        problems.append("duplicate key_id in anchor")
    return problems


def lookup_key(doc: Dict[str, Any], key_id: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Find a key_id in a validated directory.

    Returns (entry_or_None, note). Status rules:
      active  -> verifiable now
      rotated -> still verifiable (historical signatures remain valid
                 until explicitly revoked; rotation is recorded, not
                 punishment)
      revoked -> NOT verifiable
    """
    for entry in doc.get("keys", []):
        if entry.get("key_id") == key_id:
            status = entry.get("status")
            if status == "revoked":
                return None, "key %s is REVOKED at %s" % (key_id, entry.get("revoked_at", "?"))
            if status == "rotated":
                return entry, "key %s is rotated (still valid for existing signatures)" % key_id
            return entry, "key %s is active" % key_id
    return None, "key %s not found at this anchor" % key_id


def check_envelope(
    envelope: Dict[str, Any],
    anchor_doc: Dict[str, Any],
    pubkey_raw_override: Optional[bytes] = None,
    skip_shape: bool = False,
) -> Tuple[bool, str, Optional[bytes]]:
    """Level-2 check: does this anchor vouch for the payload's key?

    ``pubkey_raw_override``: for legacy envelopes whose payload embeds
    an SPKI key, the verifier passes the DERIVED raw key here - the
    comparison is made against what the signature actually binds.
    ``skip_shape``: legacy payloads predate the v1 shape (no v/anchor
    fields); structural checks are the adapter's job, not the anchor's.
    Returns (ok, note, pubkey_raw_from_anchor)."""
    from .core import b64_decode, validate_payload_shape

    payload = envelope.get("payload", {})
    if not skip_shape:
        shape = validate_payload_shape(payload)
        if shape:
            return False, "; ".join(shape), None
    if "key_id" not in payload:
        return False, "payload missing key_id", None
    entry, note = lookup_key(anchor_doc, payload["key_id"])
    if entry is None:
        return False, note, None
    anchor_pub = b64_decode(entry["pubkey_b64"])
    payload_pub = pubkey_raw_override if pubkey_raw_override is not None else b64_decode(payload["pubkey_b64"])
    if anchor_pub != payload_pub:
        return False, (
            "ANCHOR MISMATCH: key %s is published at the anchor with DIFFERENT "
            "public key bytes than the payload embeds - treat as forgery attempt" % payload["key_id"]
        ), anchor_pub
    notes = [note]
    role_ok = (not entry.get("role")) or entry.get("role") == payload.get("role")
    org_ok = (not entry.get("org")) or entry.get("org") == payload.get("org")
    if not (role_ok and org_ok):
        # The key BYTES are the trust binding; role/org drift between
        # payload and directory is surfaced as a WARNING, not a hard
        # failure (a signer may update its stated capacity without
        # rotating keys). The anchor's version is authoritative for
        # display; the payload's is what was signed.
        notes.append("WARNING: payload role/org differs from the anchor's published role/org for key %s" % payload["key_id"])
    return True, "; ".join(notes), anchor_pub
