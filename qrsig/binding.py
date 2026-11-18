"""Content binding: versioned methods for hashing what a document SAYS,
not just the bytes it is stored in.

Why: the field test (executed Operating Agreement, 2026-10-18) showed a
PDF-signing app fully rewrites the document container - byte hashes die
while the CONTENT survives. Content-level binding extracts the human-
readable text and hashes that, so a re-printed, re-saved, or re-signed
copy still verifies.
"""

from __future__ import annotations

import hashlib
import unicodedata
from typing import Callable, Dict

METHODS: Dict[str, Callable[[bytes], bytes]] = {}


def method(name: str) -> Callable:
    """Registry decorator for content-binding methods."""

    def wrap(fn: Callable[[bytes], bytes]) -> Callable[[bytes], bytes]:
        METHODS[name] = fn
        return fn

    return wrap


def _normalize_text(text: str) -> str:
    """The one normalization every text method shares: NFC, then
    collapse all whitespace runs to single spaces, then strip.
    (Page order and paragraph breaks are preserved as spaces - a
    re-flowed print of the same words binds identically.)"""
    return " ".join(unicodedata.normalize("NFC", text).split())


@method("plain-text-v1")
def _plain_text(data: bytes) -> bytes:
    return _normalize_text(data.decode("utf-8", errors="strict")).encode("utf-8")


@method("pdf-pypdf-text-v1")
def _pdf_text(data: bytes) -> bytes:
    import io

    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError(
            "PDF content binding needs the optional extra: pip install qrsig[pdf]"
        ) from exc

    # TWO distinct failures, one requirement: the caller gets a message, not a
    # traceback.  A missing extra is a deployment problem; a file pypdf cannot
    # parse is a property of the DOCUMENT.  Conflating them would give actively
    # misleading advice - 'install this package' for a corrupt PDF, or 'this
    # document is unreadable' for a missing dependency.
    try:
        reader = PdfReader(io.BytesIO(data))
        pages = [(page.extract_text() or "") for page in reader.pages]
    except Exception as exc:  # noqa: BLE001 - any parse failure is a finding
        raise RuntimeError(
            "cannot read document as PDF (content method pdf-pypdf-text-v1): %s" % exc
        ) from exc
    return _normalize_text("\n\n".join(pages)).encode("utf-8")


def content_digest(data: bytes, method_name: str) -> str:
    """Hex SHA-256 of the bound content under a named method."""
    try:
        fn = METHODS[method_name]
    except KeyError:
        raise ValueError("unknown content method: %s" % method_name) from None
    return hashlib.sha256(fn(data)).hexdigest()


def detect_method(filename: str) -> str:
    """'auto' policy: PDFs get the pdf method, everything else plain text."""
    if filename.lower().endswith(".pdf"):
        return "pdf-pypdf-text-v1"
    return "plain-text-v1"
