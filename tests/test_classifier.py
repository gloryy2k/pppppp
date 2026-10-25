"""Response classifier tests, focused on false-positive exclusions."""

from __future__ import annotations

import unittest

from p2s.classifier import (
    KIND_EMPTY_BODY,
    KIND_FRONTEND_REJECT,
    KIND_NETWORK,
    KIND_NOT_FOUND,
    KIND_OK,
    KIND_ORIGIN_ERROR,
    KIND_PHP_FATAL,
    KIND_PHP_OOM,
    KIND_PHP_WARNING,
    KIND_PROXY_ERROR,
    KIND_REDIRECT,
    KIND_RESET,
    KIND_TIMEOUT,
    classify,
    detect_frontend,
)

try:
    from tests.helpers import make_exchange
except ImportError:  # pragma: no cover - unittest discover -s tests
    from helpers import make_exchange


OOM_SCRIPT = (
    "PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted "
    "(tried to allocate 4096 bytes) in /var/www/html/index.php on line 42"
)
OOM_STARTUP = (
    "PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted "
    "(tried to allocate 4096 bytes) in Unknown on line 0"
)


class ClassifierTests(unittest.TestCase):
    def test_proxy_502_is_not_a_crash(self) -> None:
        exchange = make_exchange(
            status=502,
            body="<html>Bad Gateway</html>",
            headers={"Server": "nginx", "Via": "1.1 edge-proxy"},
        )
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_PROXY_ERROR)
        self.assertTrue(result.gateway_error)
        self.assertTrue(result.proxy)
        self.assertFalse(result.oom)
        self.assertFalse(result.worker_crash_suspected)

    def test_opaque_502_is_not_a_crash(self) -> None:
        exchange = make_exchange(status=502, body="")
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_ORIGIN_ERROR)
        self.assertTrue(result.gateway_error)
        self.assertFalse(result.oom)

    def test_waf_413_is_a_frontend_reject(self) -> None:
        exchange = make_exchange(
            status=413,
            body="Request entity too large",
            headers={"Server": "cloudflare"},
        )
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_FRONTEND_REJECT)
        self.assertTrue(result.frontend_reject)
        self.assertFalse(result.oom)

    def test_waf_431_is_a_frontend_reject(self) -> None:
        exchange = make_exchange(
            status=431,
            body="Request Header Fields Too Large",
            headers={"Server": "nginx"},
        )
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_FRONTEND_REJECT)
        self.assertTrue(result.frontend_reject)
        self.assertFalse(result.oom)

    def test_waf_403_block_page_is_a_frontend_reject(self) -> None:
        exchange = make_exchange(
            status=403,
            body="Request blocked by the web application firewall",
        )
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_FRONTEND_REJECT)
        self.assertTrue(result.frontend_reject)

    def test_network_timeout_is_not_a_crash(self) -> None:
        exchange = make_exchange(error_kind="timeout", error_message="timed out")
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_TIMEOUT)
        self.assertFalse(result.oom)
        self.assertFalse(result.worker_crash_suspected)

    def test_connection_reset_is_not_a_crash(self) -> None:
        exchange = make_exchange(error_kind="reset", error_message="connection reset")
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_RESET)
        self.assertFalse(result.oom)
        self.assertFalse(result.worker_crash_suspected)

    def test_network_error_is_not_a_crash(self) -> None:
        exchange = make_exchange(error_kind="network", error_message="socket error")
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_NETWORK)
        self.assertFalse(result.oom)

    def test_application_oom_is_script_context(self) -> None:
        exchange = make_exchange(status=500, body=OOM_SCRIPT)
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_PHP_OOM)
        self.assertTrue(result.oom)
        self.assertEqual(result.oom_context, "script")
        self.assertTrue(result.display_errors)
        self.assertIn("index.php", result.oom_location or "")

    def test_startup_oom_is_startup_like_not_proof(self) -> None:
        exchange = make_exchange(status=500, body=OOM_STARTUP)
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_PHP_OOM)
        self.assertTrue(result.oom)
        self.assertEqual(result.oom_context, "startup_like")
        self.assertTrue(any("does not prove" in item for item in result.limitations))

    def test_display_errors_warning_is_not_oom(self) -> None:
        exchange = make_exchange(
            status=200,
            body="PHP Warning:  Undefined array key 1 in /var/www/html/a.php on line 3",
        )
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_PHP_WARNING)
        self.assertFalse(result.oom)
        self.assertTrue(result.display_errors)

    def test_reflected_nonce_is_recorded(self) -> None:
        nonce = "P2S-PROBENONCE1234567890"
        exchange = make_exchange(status=200, body=f"echo:{nonce}", nonce=nonce)
        result = classify(exchange, nonce=nonce)
        self.assertTrue(result.reflection)
        self.assertIn("nonce_reflected_in_body", result.markers)

    def test_fake_banner_is_only_a_marker(self) -> None:
        exchange = make_exchange(
            status=200,
            body="hello",
            headers={"X-Powered-By": "PHP/8.4.99"},
        )
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_OK)
        self.assertTrue(result.php_marker)
        self.assertFalse(result.oom)

    def test_hidden_banner_is_not_php_evidence(self) -> None:
        exchange = make_exchange(status=200, body="hello")
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_OK)
        self.assertFalse(result.php_marker)
        self.assertFalse(result.php_generated)

    def test_server_header_does_not_identify_sapi(self) -> None:
        hints = detect_frontend({"Server": "Apache/2.4.58 (Unix)"})
        self.assertIn("server", hints)
        self.assertEqual(hints["server"], "Apache/2.4.58 (Unix)")
        # detect_frontend only reports frontend hints; it has no SAPI field.
        self.assertNotIn("sapi", hints)

    def test_empty_body_is_ambiguous(self) -> None:
        exchange = make_exchange(status=200, body="")
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_EMPTY_BODY)
        self.assertTrue(result.empty_body)
        self.assertFalse(result.oom)

    def test_opaque_500_is_not_oom(self) -> None:
        exchange = make_exchange(status=500, body="Internal Server Error")
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_ORIGIN_ERROR)
        self.assertFalse(result.oom)

    def test_redirect_is_recorded(self) -> None:
        exchange = make_exchange(
            status=302,
            headers={"Location": "https://lab.invalid/login"},
        )
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_REDIRECT)

    def test_execution_timeout_is_fatal_not_oom(self) -> None:
        exchange = make_exchange(
            status=500,
            body="PHP Fatal error: Maximum execution time of 30 seconds exceeded",
        )
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_PHP_FATAL)
        self.assertTrue(result.execution_timeout)
        self.assertFalse(result.oom)

    def test_rate_limit_is_frontend_reject(self) -> None:
        exchange = make_exchange(status=429, body="slow down")
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_FRONTEND_REJECT)
        self.assertTrue(result.frontend_reject)

    def test_not_found(self) -> None:
        exchange = make_exchange(status=404, body="not found")
        result = classify(exchange)
        self.assertEqual(result.kind, KIND_NOT_FOUND)


if __name__ == "__main__":
    unittest.main()
