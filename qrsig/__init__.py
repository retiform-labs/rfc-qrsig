"""qrsig - reference implementation of draft-guan-qrsig-00.

QRSIG1: human-verifiable signatures for agentic intelligences.
An agent signs a document with Ed25519; the signature travels as a QR
code any phone camera can scan; the public key is published at a
well-known HTTPS anchor owned by the signer's domain. No PKI, no CA,
no app: a human with a camera and one URL can verify.
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("qrsig")
except PackageNotFoundError:  # running from a source tree that was never installed
    # Deliberately NOT a real-looking number: a stale literal here is exactly how
    # `qrsig --version` reported 0.1.0 on a 0.1.2 install.
    __version__ = "0.0.0+unknown"
