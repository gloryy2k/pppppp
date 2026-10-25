"""HTTP client tests against a local, deterministic test server.

No external network is used.  The tests exercise the error paths that are most
likely to be mistaken for a crash: proxy 502, WAF 413/431, timeout, connection
reset, opaque 500, application OOM and reflected markers.
"""

from __future__ import annotations

import http.server
import ssl
import threading
import time
import unittest
from urllib.parse import urlsplit

from p2s.classifier import (
    KIND_FRONTEND_REJECT,
    KIND_NETWORK,
    KIND_OK,
    KIND_PHP_OOM,
    KIND_PHP_WARNING,
    KIND_PROXY_ERROR,
    KIND_RESET,
    KIND_TIMEOUT,
    classify,
)
from p2s.http import HttpClient

OOM_BODY = (
    b"PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted "
    b"(tried to allocate 4096 bytes) in /var/www/html/index.php on line 42"
)
WARN_BODY = b"PHP Warning:  Undefined array key 1 in /var/www/html/a.php on line 3"


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        return

    def _send(
        self,
        status: int,
        body: bytes = b"",
        headers: dict | None = None,
    ) -> None:
        try:
            self.send_response(status)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True

    def do_POST(self) -> None:  # noqa: N802
        # Consume the declared body before answering.  A WAF-style 413/431
        # response that closes the socket with unread request bytes makes
        # Windows send RST, which can discard the response and look like a
        # connection reset to the client.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 0:
            self.rfile.read(length)
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        raw_path = self.path
        if raw_path.startswith("http://") or raw_path.startswith("https://"):
            # Absolute-form request, i.e. this server is acting as a proxy.
            self._send(
                502,
                b"<html>proxy could not reach upstream</html>",
                {"Via": "1.1 p2s-test-proxy", "Server": "test-proxy"},
            )
            return
        path = urlsplit(raw_path).path
        if path == "/":
            self._send(
                200,
                b"ok",
                {"X-Powered-By": "PHP/8.2.12", "Content-Type": "text/plain"},
            )
        elif path == "/redirect":
            self._send(302, b"", {"Location": "/"})
        elif path == "/reset":
            self.close_connection = True
            try:
                self.connection.close()
            except OSError:
                pass
        elif path == "/slow":
            time.sleep(0.8)
            self._send(200, b"slow")
        elif path == "/413":
            self._send(413, b"Request entity too large")
        elif path == "/431":
            self._send(431, b"Request header fields too large")
        elif path == "/502":
            self._send(502, b"bad gateway")
        elif path == "/500":
            self._send(500, b"Internal Server Error")
        elif path == "/oom":
            self._send(500, OOM_BODY)
        elif path == "/warn":
            self._send(200, WARN_BODY)
        elif path == "/reflect":
            nonce = self.headers.get("X-P2S-Nonce", "")
            self._send(200, ("echo:" + nonce).encode("utf-8"))
        elif path == "/big":
            self._send(200, b"Z" * 1000)
        elif path == "/echo":
            request_id = self.headers.get("X-P2S-Request-ID", "")
            nonce = self.headers.get("X-P2S-Nonce", "")
            host = self.headers.get("Host", "")
            body = f"rid={request_id};nonce={nonce};host={host}".encode("utf-8")
            self._send(200, body)
        elif path == "/count":
            self._send(200, b"1")
        else:
            self._send(404, b"not found")


class HttpClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.daemon_threads = True
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def client(self, **kwargs: object) -> HttpClient:
        return HttpClient(f"http://127.0.0.1:{self.port}/", timeout=2.0, **kwargs)

    def test_ok_and_request_identity_headers(self) -> None:
        exchange = self.client().request("GET", "/echo", nonce="P2S-NONCE1234567890")
        self.assertEqual(exchange.status, 200)
        self.assertIn("rid=" + exchange.request_id, exchange.body_preview)
        self.assertIn("nonce=P2S-NONCE1234567890", exchange.body_preview)
        self.assertEqual(classify(exchange).kind, KIND_OK)

    def test_host_header_override(self) -> None:
        exchange = self.client(host_header="virtual.example").request("GET", "/echo")
        self.assertIn("host=virtual.example", exchange.body_preview)

    def test_redirect_is_followed_and_recorded(self) -> None:
        exchange = self.client().request("GET", "/redirect")
        self.assertEqual(exchange.status, 200)
        self.assertEqual(len(exchange.redirect_chain), 1)
        self.assertTrue(exchange.notes)

    def test_redirect_can_be_disabled(self) -> None:
        exchange = self.client(follow_redirects=False).request("GET", "/redirect")
        self.assertEqual(exchange.status, 302)
        self.assertEqual(exchange.redirect_chain, [])
        self.assertEqual(classify(exchange).kind, "REDIRECT")

    def test_timeout_is_a_network_error(self) -> None:
        exchange = self.client().request("GET", "/slow", timeout=0.2)
        self.assertEqual(exchange.error_kind, "timeout")
        self.assertEqual(classify(exchange).kind, KIND_TIMEOUT)
        self.assertFalse(classify(exchange).oom)

    def test_timeout_preserves_actual_send_time(self) -> None:
        exchange = self.client().request("GET", "/slow", timeout=0.2)
        # sent_at is when the request was written, not when the timeout fired.
        self.assertLess(exchange.sent_at, exchange.received_at)

    def test_connection_reset_is_a_network_error(self) -> None:
        exchange = self.client().request("GET", "/reset")
        self.assertIn(exchange.error_kind, ("reset", "network"))
        self.assertEqual(classify(exchange).kind, KIND_RESET if exchange.error_kind == "reset" else KIND_NETWORK)
        self.assertFalse(classify(exchange).oom)

    def test_proxy_502_is_not_a_crash(self) -> None:
        proxy_client = HttpClient(
            "http://example.invalid/",
            timeout=2.0,
            proxy=f"http://127.0.0.1:{self.port}",
        )
        exchange = proxy_client.request("GET", "/")
        self.assertEqual(exchange.status, 502)
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_PROXY_ERROR)
        self.assertTrue(result.gateway_error)
        self.assertFalse(result.oom)
        self.assertFalse(result.worker_crash_suspected)

    def test_waf_413_and_431_are_frontend_rejects(self) -> None:
        for path in ("/413", "/431"):
            exchange = self.client().request("POST", path, body=b"x", headers={"Content-Type": "text/plain"})
            result = classify(exchange)
            self.assertEqual(result.kind, KIND_FRONTEND_REJECT, path)
            self.assertTrue(result.frontend_reject, path)
            self.assertFalse(result.oom, path)

    def test_application_oom_is_script_context(self) -> None:
        exchange = self.client().request("GET", "/oom")
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_PHP_OOM)
        self.assertTrue(result.oom)
        self.assertEqual(result.oom_context, "script")

    def test_display_errors_warning_is_not_oom(self) -> None:
        exchange = self.client().request("GET", "/warn")
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_PHP_WARNING)
        self.assertFalse(result.oom)
        self.assertTrue(result.display_errors)

    def test_reflected_nonce_is_detected(self) -> None:
        nonce = "P2S-REFLECTNONCE123456789"
        exchange = self.client().request("GET", "/reflect", nonce=nonce)
        result = classify(exchange, nonce=nonce)
        self.assertTrue(result.reflection)

    def test_body_is_bounded_and_hashed(self) -> None:
        exchange = self.client(max_body=100).request("GET", "/big")
        self.assertEqual(exchange.body_bytes, 100)
        self.assertTrue(exchange.body_truncated)
        self.assertEqual(len(exchange.body_preview), 100)

    def test_secret_headers_are_redacted(self) -> None:
        exchange = self.client(extra_headers={"Authorization": "Bearer super-secret"}).request("GET", "/")
        self.assertEqual(exchange.request_headers.get("Authorization"), "***redacted***")

    def test_tls_verification_is_on_by_default(self) -> None:
        context = self.client()._ssl_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_insecure_is_an_explicit_opt_in(self) -> None:
        context = self.client(insecure=True)._ssl_context()
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)

    def test_opaque_500_is_not_oom(self) -> None:
        exchange = self.client().request("GET", "/500")
        result = classify(exchange)
        self.assertFalse(result.oom)
        self.assertTrue(result.origin_error)

    def test_502_without_proxy_hint_is_origin_error(self) -> None:
        exchange = self.client().request("GET", "/502")
        result = classify(exchange)
        self.assertTrue(result.gateway_error)
        self.assertFalse(result.oom)


if __name__ == "__main__":
    unittest.main()
