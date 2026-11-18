"""QR codec: render a QRSIG1 URI as a scannable PNG, decode one back.

Rendering (segno) is a hard dependency - the QR is the format.
Decoding (pyzbar + Pillow) is an optional extra: a human with a phone
camera never needs it, but automated pipelines can use ``decode``.
"""

from __future__ import annotations

import segno

from .core import URI_PREFIX, parse_uri

# Error correction level Q: ~25% damage tolerance. The QR travels
# printed inside documents; durability beats density.
EC_LEVEL = "q"
SCALE = 8
BORDER = 2


def _require_qrsig1(uri: str) -> str:
    """Both render paths must enforce the SAME contract.

    ``render_png`` and ``render_png_bytes`` are documented mirrors, so
    neither may encode anything that is not a QRSIG1: URI.  A QR carrying a
    non-QRSIG1 string is a phishing surface: a scanner reads it, and a naive
    verifier may hand whatever it holds to ``parse_uri``.
    """
    if not uri.startswith(URI_PREFIX):
        raise ValueError(
            "refusing to encode a non-QRSIG1 URI (missing %r prefix): %r"
            % (URI_PREFIX, uri[:32])
        )
    return uri


def render_png(uri: str, out_path: str) -> str:
    """Write the QR PNG for a QRSIG1 URI; returns the path."""
    _require_qrsig1(uri)
    qr = segno.make(uri, error=EC_LEVEL)
    qr.save(out_path, scale=SCALE, border=BORDER)
    return out_path


def render_png_bytes(uri: str) -> bytes:
    """QR PNG for a QRSIG1 URI, as bytes (for tests and pipelines)."""
    _require_qrsig1(uri)
    qr = segno.make(uri, error=EC_LEVEL)
    import io

    buf = io.BytesIO()
    qr.save(buf, scale=SCALE, border=BORDER, kind="png")
    return buf.getvalue()


def decode_png(path: str) -> str:
    """Decode the FIRST QR found in an image file; returns the URI.

    Uses pyzbar; installed via ``pip install qrsig[decode]``. Raises
    RuntimeError with install guidance when the extra is missing.
    """
    try:
        from pyzbar.pyzbar import decode as zbar_decode
        from PIL import Image
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError(
            "QR decoding needs the optional extra: pip install 'qrsig[decode]'"
        ) from exc
    # Field lesson: decode renders at ~2x for reliability on 100dpi docs.
    img = Image.open(path).convert("L")
    results = zbar_decode(img)
    if not results:
        results = zbar_decode(img.resize((img.width * 2, img.height * 2)))
    if not results:
        raise ValueError("no QR code found in %s" % path)
    return results[0].data.decode("utf-8")


def decode_png_bytes(png: bytes) -> str:
    """Decode a QR from raw PNG bytes (mirror of decode_png)."""
    import io
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as fh:
        fh.write(png)
        tmp = fh.name
    try:
        return decode_png(tmp)
    finally:
        import os

        os.unlink(tmp)


def uri_from_qr(path: str) -> dict:
    """Convenience: decode an image and parse it into an envelope."""
    return parse_uri(decode_png(path))
