"""Shared fixtures: keypairs and a local anchor server."""

import pytest

from qrsig import core


@pytest.fixture()
def keypair():
    return core.new_keypair()


@pytest.fixture()
def anchor_server():
    """Local HTTP anchor server; docs dict is the mutable fixture state."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    docs = {}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            doc = docs.get(self.path.split("?")[0])
            if doc is None:
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(doc).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield docs, server
    server.shutdown()


@pytest.fixture()
def keypair_and_anchor(anchor_server):
    """(private, pub_raw, base_url, docs) - the e2e workbench."""
    priv, pub = core.new_keypair()
    docs, server = anchor_server
    docs["/.well-known/qrsig-keys"] = {"pending": True}
    return priv, pub, "http://127.0.0.1:%d" % server.server_address[1], docs
