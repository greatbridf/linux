#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the KV server with TCP fragmentation and complete binary bodies."""

import argparse
import hashlib
import http.client
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import unittest

# Width of one key: 2 * RSWAP_HASH_LEN (48 byte digest, mm/rswap.h) hex digits,
# i.e. RSWAP_KV_KEY_LEN - 1 bytes (mm/rswap_backend.h).
KEY_HEXLEN = 96
SHA256_HEXLEN = 64


def digest_key(data):
    """Key the legacy rswap path produces: SHA-256 zero-extended to 48 bytes."""
    return hashlib.sha256(data).hexdigest() + "0" * (KEY_HEXLEN - SHA256_HEXLEN)


class KVSwapTest(unittest.TestCase):
    server = None
    port = None
    directory = None

    def request(self, method, key, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        op = "write" if method == "POST" else "read"
        conn.request(method, f"/v1/folios/{key}/{op}", body=body)
        response = conn.getresponse()
        status, data = response.status, response.read()
        conn.close()
        return status, data

    def assert_rejected(self, method, key, body):
        """The server refuses the request and stores nothing.

        A body it cannot accept is answered with 400, and the connection is
        closed without draining the body, so a large body can surface as a
        connection error on the client instead of a status line.  Either
        outcome is a refusal; what matters is that the object was not stored.
        """
        try:
            status, _ = self.request(method, key, body)
        except (ConnectionError, http.client.HTTPException):
            return
        self.assertEqual(status, 400)

    def round_trip(self, size):
        body = os.urandom(size)
        key = digest_key(body)
        self.assertEqual(self.request("POST", key, body)[0], 200)
        status, actual = self.request("GET", key)
        self.assertEqual(status, 200)
        self.assertEqual(len(actual), len(body), "stored body was truncated")
        self.assertEqual(actual, body)

    def test_digest_key_round_trip(self):
        body = os.urandom(16384)
        key = bytes(range(48)).hex()
        self.assertEqual(len(key), KEY_HEXLEN)
        self.assertEqual(self.request("POST", key, body), (200, b""))
        self.assertTrue(os.path.isfile(
            os.path.join(self.directory, key[:2], key)))
        self.assertEqual(self.request("GET", key), (200, body))

    def test_uppercase_digest_key_round_trip(self):
        body = os.urandom(4096)
        key = bytes(range(48)).hex().upper()
        self.assertEqual(self.request("POST", key, body), (200, b""))
        self.assertEqual(self.request("GET", key), (200, body))

    def test_4k(self):
        self.round_trip(4096)

    def test_16k(self):
        self.round_trip(16384)

    def test_64k(self):
        self.round_trip(65536)

    def test_non_page_size_body_rejected(self):
        """Only one base page is a body the kernel can read back.

        mm/rswap_http.c rejects any object that is not exactly one base page,
        so the server refuses such a body instead of storing it.  A large
        folio is never one KV object either: the core splits it into base
        pages.
        """
        for size in (0, 1000, 2 * 1024 * 1024):
            body = os.urandom(size)
            key = digest_key(f"size-{size}".encode())
            with self.subTest(size=size):
                self.assert_rejected("POST", key, body)
                self.assertEqual(self.request("GET", key), (404, b""))

    def test_fragmented_header(self):
        body = os.urandom(16384)
        key = digest_key(body)
        header = (f"POST /v1/folios/{key}/write HTTP/1.0\r\n"
                  f"Content-Length: {len(body)}\r\n\r\n").encode()
        with socket.create_connection(("127.0.0.1", self.port), 5) as conn:
            conn.sendall(header[:20])
            time.sleep(0.05)
            conn.sendall(header[20:] + body)
            response = http.client.HTTPResponse(conn)
            response.begin()
            self.assertEqual(response.status, 200)
            response.read()
        self.assertEqual(self.request("GET", key), (200, body))

    def test_fragmented_body(self):
        body = os.urandom(16384)
        key = digest_key(body)
        header = (f"POST /v1/folios/{key}/write HTTP/1.0\r\n"
                  f"Content-Length: {len(body)}\r\n\r\n").encode()
        with socket.create_connection(("127.0.0.1", self.port), 5) as conn:
            conn.sendall(header)
            time.sleep(0.05)
            conn.sendall(body)
            response = http.client.HTTPResponse(conn)
            response.begin()
            self.assertEqual(response.status, 200)
            response.read()
        self.assertEqual(self.request("GET", key), (200, body))

    def test_missing_key(self):
        self.assertEqual(self.request("GET", "f" * KEY_HEXLEN), (404, b""))

    def test_wrong_key_length(self):
        before = sorted(os.listdir(self.directory))
        for length in (0, 63, 65, 128, 2 * KEY_HEXLEN):
            key = "a" * length
            with self.subTest(length=length):
                self.assertEqual(self.request("GET", key), (400, b""))
                self.assertEqual(self.request("POST", key, b"page"), (400, b""))
        self.assertEqual(sorted(os.listdir(self.directory)), before,
                         "a rejected key created store entries")

    def test_non_hex_key(self):
        for key in ("g" * KEY_HEXLEN, "a" * (KEY_HEXLEN - 1) + "."):
            with self.subTest(key=key):
                self.assertEqual(self.request("GET", key), (400, b""))
                self.assertEqual(self.request("POST", key, b"page"), (400, b""))

    def test_path_traversal(self):
        before = sorted(os.listdir(self.directory))
        for key in ("../../etc/passwd", "..", "../" + "a" * KEY_HEXLEN,
                    "." * KEY_HEXLEN):
            with self.subTest(key=key):
                self.assertEqual(self.request("GET", key), (400, b""))
                self.assertEqual(self.request("POST", key, b"page"), (400, b""))
        self.assertEqual(sorted(os.listdir(self.directory)), before,
                         "a traversal attempt left the store directory")

    def test_oversized_request(self):
        key = "e" * KEY_HEXLEN
        header = (f"POST /v1/folios/{key}/write HTTP/1.0\r\n"
                  "Content-Length: 67108865\r\n\r\n").encode()
        with socket.create_connection(("127.0.0.1", self.port), 5) as conn:
            conn.sendall(header)
            response = http.client.HTTPResponse(conn)
            response.begin()
            self.assertEqual(response.status, 400)
            response.read()
        self.assertEqual(self.request("GET", key), (404, b""))

    def test_duplicate_length(self):
        key = "d" * KEY_HEXLEN
        header = (f"POST /v1/folios/{key}/write HTTP/1.0\r\n"
                  "Content-Length: 4\r\nContent-Length: 2\r\n\r\nABCD").encode()
        with socket.create_connection(("127.0.0.1", self.port), 5) as conn:
            conn.sendall(header)
            response = http.client.HTTPResponse(conn)
            response.begin()
            self.assertEqual(response.status, 400)
            response.read()

    def test_short_post_preserves_old_value(self):
        body = os.urandom(16384)
        key = digest_key(body)
        self.assertEqual(self.request("POST", key, body)[0], 200)
        header = (f"POST /v1/folios/{key}/write HTTP/1.0\r\n"
                  f"Content-Length: {len(body)}\r\n\r\n").encode()
        with socket.create_connection(("127.0.0.1", self.port), 5) as conn:
            conn.sendall(header + body[:100])
            conn.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(conn)
            response.begin()
            self.assertNotEqual(response.status, 200)
            response.read()
        self.assertEqual(self.request("GET", key), (200, body))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default=str(
        pathlib.Path(__file__).with_name("kvswap_server")))
    args, remaining = parser.parse_known_args()
    with tempfile.TemporaryDirectory(prefix="kvswap-protocol-") as directory:
        KVSwapTest.directory = directory
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            KVSwapTest.port = sock.getsockname()[1]
        server = subprocess.Popen(
            [args.server, "-d", directory, "-p", str(KVSwapTest.port)],
            stdout=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError("KV server exited during startup")
                try:
                    with socket.create_connection(
                            ("127.0.0.1", KVSwapTest.port), 0.1):
                        break
                except OSError:
                    time.sleep(0.01)
            else:
                raise RuntimeError("KV server did not listen")
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(KVSwapTest)
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            return 0 if result.wasSuccessful() else 1
        finally:
            server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
