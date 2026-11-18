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

HOSTILE-INPUT CONTRACT
Every function here except ``anchor_url`` can be handed a document that
came off the network. ``validate_directory`` is OPTIONAL - a caller may
skip it entirely and hand the raw document straight to
``check_envelope``. Therefore:

    No function in this module may RAISE on hostile input. It must
    return a negative verdict carrying a reason.

A crash is not a diagnosis, and it is actively dangerous: a caller that
wraps ``check_envelope`` in a broad try/except turns an uncaught
exception into whatever that except-branch does. ``qrsig.cli`` catches
``Exception`` and prints UNREACHABLE with ``l2`` still False, so today
it fails closed - but that is the *caller's* accident, not this
module's guarantee.
"""

from __future__ import annotations

import base64
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
    testing and self-hosted registries; the caller opted in.

    Returns whatever the server sent, parsed. This function does NOT
    validate - structural checks belong to ``validate_directory``. A
    non-JSON body raises ValueError (JSONDecodeError subclasses it) and
    a non-2xx raises urllib.error.HTTPError; neither is wrapped.
    """
    # The scheme gate is ALWAYS on; require_https only raises the bar from
    # "http or https" to "https only". require_https=False is the documented
    # escape hatch for an explicitly supplied URL (a local test server, a
    # self-hosted registry) - it is NOT a licence to reach file:// or any
    # other scheme, which would turn a trusted-as-given anchor URL into an
    # arbitrary local file read.
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme not in ("http", "https"):
        raise ValueError(
            "anchor URL must be http or https, got %r; a non-HTTP scheme is "
            "never a trust anchor" % (scheme or url,))
    if require_https and scheme != "https":
        raise ValueError("anchor URL must be https (derived); pass require_https=False only for an explicitly supplied URL")
    with urlopen(Request(url, headers={"Accept": "application/json"}), timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def validate_directory(doc: Any, expect_domain: Optional[str] = None) -> List[str]:
    """Structural validation of an anchor document. Returns problems.

    Never raises: a non-dict document, a non-list ``keys`` field and
    non-dict key ENTRIES are all reported as problems. This is the
    module's declared contract and the reason callers may treat a
    non-empty return as a safe refusal.
    """
    problems = []
    if not isinstance(doc, dict):
        return ["anchor document is not a JSON object"]
    version = doc.get("v")
    # Same guard as core.validate_payload_shape: `True == 1` and
    # `1.0 == 1` in Python, so a bare `!=` lets a JSON `{"v": true}`
    # validate as a v1 directory. Keep the two validators identical -
    # a divergence between them is worse than a shared permissiveness.
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
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
        if not isinstance(entry, dict):
            problems.append("key entry is not a JSON object")
            continue
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
            try:
                if len(base64.b64decode(pub)) != 32:
                    problems.append("key %s: pubkey_b64 must decode to 32 bytes" % kid)
            except Exception:  # noqa: BLE001
                problems.append("key %s: pubkey_b64 is not valid base64" % kid)
        if entry.get("status") == "revoked" and not entry.get("revoked_at"):
            problems.append("key %s: revoked without revoked_at" % kid)
    ids = [k.get("key_id") for k in keys if isinstance(k, dict) and k.get("key_id")]
    if len(ids) != len(set(ids)):
        problems.append("duplicate key_id in anchor")
    return problems


def _decode_pubkey(value: Any) -> Tuple[Optional[bytes], str]:
    """Decode a base64 pubkey field defensively. Returns (raw_or_None, reason).

    Exists because both the anchor entry AND (on the legacy/skip_shape
    path) the payload itself carry attacker-reachable base64 strings.
    """
    if not isinstance(value, str) or not value:
        return None, "missing pubkey_b64"
    try:
        return base64.b64decode(value.encode("ascii")), "ok"
    except Exception:  # noqa: BLE001 - binascii.Error, UnicodeEncodeError, TypeError
        return None, "pubkey_b64 is not valid base64"


def lookup_key(doc: Any, key_id: Any) -> Tuple[Optional[Dict[str, Any]], str]:
    """Find a key_id in a directory. Safe on an UNVALIDATED document.

    Returns (entry_or_None, note). Status rules:
      active  -> verifiable now
      rotated -> still verifiable (historical signatures remain valid
                 until explicitly revoked; rotation is recorded, not
                 punishment)
      revoked -> NOT verifiable
      anything else - absent, unrecognized, or mistyped (case, trailing
                 whitespace) - is NOT verifiable. An unrecognized state
                 in a trust decision fails CLOSED: a verifier that reads
                 "a status I do not know" as "fine" has no status
                 handling at all, and a directory serving
                 ``"status": "compromised"`` must not verify.

    Structural garbage anywhere in ``doc`` yields a not-found note
    rather than an exception - see the module's hostile-input contract.
    """
    if not isinstance(doc, dict):
        return None, "anchor document is not a JSON object"
    if not isinstance(key_id, str) or not key_id:
        return None, "payload key_id is missing or not a string"
    keys = doc.get("keys")
    if not isinstance(keys, list):
        return None, "anchor has no key list; key %s not found at this anchor" % key_id
    for entry in keys:
        if not isinstance(entry, dict):
            continue
        if entry.get("key_id") != key_id:
            continue
        status = entry.get("status")
        if status == "revoked":
            return None, "key %s is REVOKED at %s" % (key_id, entry.get("revoked_at", "?"))
        if status == "rotated":
            return entry, "key %s is rotated (still valid for existing signatures)" % key_id
        if status == "active":
            return entry, "key %s is active" % key_id
        return None, "key %s has unrecognized status %r - NOT trusted (expected one of %s)" % (
            key_id, status, ", ".join(STATUSES))
    return None, "key %s not found at this anchor" % key_id


def check_envelope(
    envelope: Any,
    anchor_doc: Any,
    pubkey_raw_override: Optional[bytes] = None,
    skip_shape: bool = False,
) -> Tuple[bool, str, Optional[bytes]]:
    """Level-2 check: does this anchor vouch for the payload's key?

    ``pubkey_raw_override``: for legacy envelopes whose payload embeds
    an SPKI key, the verifier passes the DERIVED raw key here - the
    comparison is made against what the signature actually binds.
    ``skip_shape``: legacy payloads predate the v1 shape (no v/anchor
    fields); structural checks are the adapter's job, not the anchor's.
    NOTE it does NOT skip the anchor lookup - ``lookup_key`` still runs,
    and it is hardened because of exactly that.

    Returns (ok, note, pubkey_raw_from_anchor).

    SCOPE LIMIT, deliberate: this function does NOT compare
    ``payload["anchor"]`` against ``anchor_doc["domain"]``. A document
    that carries a matching key_id and matching bytes is accepted
    whatever domain it claims. That is safe in the intended call
    pattern - the verifier derives the fetch URL from
    ``payload["anchor"]``, so the document in hand came from the domain
    the payload names - and it is the caller's job when a document is
    supplied some other way. ``validate_directory(doc,
    expect_domain=payload["anchor"])`` is the check that closes it, and
    qrsig.cli runs it. Binding it here as well would change the
    semantics of a public function for the legacy path, which carries no
    ``anchor`` field at all.

    Never raises. Structural garbage in the envelope, the payload, the
    directory, or any base64 field returns (False, reason, None-or-bytes).
    """
    from .core import validate_payload_shape

    if not isinstance(envelope, dict):
        return False, "malformed envelope (not a JSON object)", None
    payload = envelope.get("payload", {})
    if not isinstance(payload, dict):
        return False, "malformed envelope (payload is not a JSON object)", None
    if not skip_shape:
        shape = validate_payload_shape(payload)
        if shape:
            return False, "; ".join(shape), None
    if "key_id" not in payload:
        return False, "payload missing key_id", None
    entry, note = lookup_key(anchor_doc, payload["key_id"])
    if entry is None:
        return False, note, None
    anchor_pub, why = _decode_pubkey(entry.get("pubkey_b64"))
    if anchor_pub is None:
        return False, "anchor entry for key %s: %s" % (payload["key_id"], why), None
    if pubkey_raw_override is not None:
        payload_pub: Optional[bytes] = pubkey_raw_override
    else:
        payload_pub, why = _decode_pubkey(payload.get("pubkey_b64"))
        if payload_pub is None:
            return False, "payload for key %s: %s" % (payload["key_id"], why), None
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
