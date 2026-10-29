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


class KVSwapTest(unittest.TestCase):
    server = None
    port = None

    def request(self, method, key, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        op = "write" if method == "POST" else "read"
        conn.request(method, f"/v1/folios/{key}/{op}", body=body)
        response = conn.getresponse()
        status, data = response.status, response.read()
        conn.close()
        return status, data

    def round_trip(self, size):
        body = os.urandom(size)
        key = hashlib.sha256(body).hexdigest()
        self.assertEqual(self.request("POST", key, body)[0], 200)
        status, actual = self.request("GET", key)
        self.assertEqual(status, 200)
        self.assertEqual(len(actual), len(body), "stored body was truncated")
        self.assertEqual(actual, body)

    def test_4k(self):
        self.round_trip(4096)

    def test_16k(self):
        self.round_trip(16384)

    def test_64k(self):
        self.round_trip(65536)

    def test_large_folio(self):
        self.round_trip(2 * 1024 * 1024)

    def test_fragmented_header(self):
        body = os.urandom(16384)
        key = hashlib.sha256(body).hexdigest()
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
        key = hashlib.sha256(body).hexdigest()
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
        self.assertEqual(self.request("GET", "f" * 64), (404, b""))

    def test_empty_value(self):
        self.round_trip(0)

    def test_oversized_request(self):
        key = "e" * 64
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
        key = "d" * 64
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
        key = hashlib.sha256(body).hexdigest()
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
