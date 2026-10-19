"""qrsig - reference implementation of draft-guan-qrsig-00.

QRSIG1: human-verifiable signatures for agentic intelligences.
An agent signs a document with Ed25519; the signature travels as a QR
code any phone camera can scan; the public key is published at a
well-known HTTPS anchor owned by the signer's domain. No PKI, no CA,
no app: a human with a camera and one URL can verify.
"""

__version__ = "0.1.0"
