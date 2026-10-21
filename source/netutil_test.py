"""
Checks that the remoteapi helpers send PYCRASHEXT_API_KEY as X-API-Key and
explain a 401, against a local HTTP server that checks the key the way
remoteapi does.

Run directly: python3 source/netutil_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import os
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

import netutil

SERVER_KEY = "s3cret"


class KeyChecker(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.headers.get("X-API-Key", "") != SERVER_KEY:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}')
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def start_server():
    server = HTTPServer(("127.0.0.1", 0), KeyChecker)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d/api/git" % server.server_address[1]


def post(url, key):
    if key is None:
        os.environ.pop(netutil.API_KEY_VAR, None)
    else:
        os.environ[netutil.API_KEY_VAR] = key
    try:
        return netutil.urlopen_post(url, b"a=1", timeout=5)
    finally:
        os.environ.pop(netutil.API_KEY_VAR, None)


def check_key_is_sent():
    server, url = start_server()
    try:
        assert post(url, SERVER_KEY).read() == b"ok"
    finally:
        server.shutdown()


def check_401_is_explained():
    server, url = start_server()
    try:
        for key, words in ((None, "requires an API key"),
                           ("wrong", "does not match")):
            try:
                post(url, key)
                assert False, "expected a 401"
            except urllib.error.HTTPError as e:
                assert e.code == 401
                os.environ[netutil.API_KEY_VAR] = key or ""
                hint = netutil.api_key_hint(e)
                os.environ.pop(netutil.API_KEY_VAR, None)
                assert words in hint and netutil.API_KEY_VAR in hint, hint
    finally:
        server.shutdown()


def check_other_errors_have_no_hint():
    assert netutil.api_key_hint(urllib.error.URLError("refused")) == ""
    e = urllib.error.HTTPError("http://x", 500, "boom", {}, None)
    assert netutil.api_key_hint(e) == ""


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
