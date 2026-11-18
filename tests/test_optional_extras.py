"""Tests: a missing optional extra must refuse cleanly, never crash.

pypdf and pyzbar are declared OPTIONAL extras on purpose - a base install
should not drag a PDF library or a barcode decoder. But an absent extra is
not a verification verdict, and it must never surface as a traceback or, worse,
be silently folded into a FAIL line that reads like a document problem.
"""

import subprocess
import sys

import pytest

from qrsig import binding


class TestPdfExtraMissing:
    def test_pdf_method_raises_runtimeerror_with_guidance(self, monkeypatch):
        """With pypdf absent, the binding raises RuntimeError naming the extra."""
        real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def fake_import(name, *args, **kwargs):
            if name == "pypdf" or name.startswith("pypdf."):
                raise ImportError("No module named pypdf")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", fake_import)
        with pytest.raises(RuntimeError) as exc:
            binding.content_digest(b"%PDF-1.4 fake", "pdf-pypdf-text-v1")
        assert "qrsig[pdf]" in str(exc.value)

    def test_cli_exits_two_not_a_traceback(self, tmp_path):
        """The CLI reports the extra and exits 2 - not a stack trace, not exit 1."""
        doc = tmp_path / "d.pdf"
        doc.write_bytes(b"%PDF-1.4 fake")
        # A structurally valid envelope with an embedded placement forces the
        # content-binding path, which is where pypdf is reached.
        import base64
        import json

        payload = {
            "v": 1, "anchor": "example.org", "key_id": "deadbeefdeadbeef",
            "pubkey_b64": base64.b64encode(b"\x01" * 32).decode(),
            "org": "Example Org", "role": "Test Officer",
            "signature_placement": "embedded",
            "content_method": "pdf-pypdf-text-v1",
            "content_sha256": "0" * 64,
            "signed_at": "2026-01-01T00:00:00Z",
        }
        env = {"payload": payload, "sig_b64": base64.b64encode(b"\x02" * 64).decode()}
        body = base64.b64encode(json.dumps(env).encode()).decode()
        proc = subprocess.run(
            [sys.executable, "-m", "qrsig.cli", "verify", str(doc), "--uri", "QRSIG1:" + body, "--offline"],
            capture_output=True, text=True,
        )
        combined = proc.stdout + proc.stderr
        assert "Traceback" not in combined, combined
        assert proc.returncode in (1, 2), combined
        # If pypdf happens to be installed the content binding simply runs; the
        # assertion above is the contract. When it is absent we must name the extra.
        try:
            import pypdf  # noqa: F401
        except ImportError:
            assert "qrsig[pdf]" in combined, combined
            assert proc.returncode == 2, combined
