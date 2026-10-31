"""Tests for p2s.scenarios (builders, selectors) and p2s.cli._public_host."""

from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from p2s.scenarios import (
    MAX_BUILT_BODY,
    SCENARIOS,
    _bound,
    app_oom_boundary,
    build_app_oom,
    build_control_multipart,
    build_empty_file_nested,
    build_part_header_bomb,
    build_undeclared_length,
    build_upload_progress,
    chunked_boundary,
    control_boundary,
    header_bomb_boundary,
    nested_boundary,
    new_scenario_nonce,
    scenario_list,
    select,
    upload_progress_boundary,
)
from p2s.cli import _public_host


# ---------------------------------------------------------------------------
# scenario_list / select
# ---------------------------------------------------------------------------

class ScenarioListTests(unittest.TestCase):
    def test_returns_all_seven(self):
        items = scenario_list()
        self.assertEqual(len(items), 7)

    def test_sorted_by_id(self):
        items = scenario_list()
        ids = [s.id for s in items]
        self.assertEqual(ids, sorted(ids))


class SelectTests(unittest.TestCase):
    def test_expand_618(self):
        items = select(["618"])
        ids = {s.id for s in items}
        self.assertEqual(ids, {"618-S1", "618-S2", "618-S3", "618-S4"})

    def test_expand_619(self):
        items = select(["619"])
        ids = {s.id for s in items}
        self.assertEqual(ids, {"619-S1", "619-S2", "619-S3"})

    def test_single_scenario(self):
        items = select(["618-S2"])
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].id, "618-S2")

    def test_unknown_raises(self):
        with self.assertRaises(ValueError):
            select(["unknown"])

    def test_deduplicates(self):
        items = select(["618", "618-S2"])
        ids = [s.id for s in items]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("618-S2", ids)

    def test_cve_string_618(self):
        items = select(["CVE-2026-109618"])
        self.assertEqual(len(items), 4)

    def test_cve_string_619(self):
        items = select(["CVE-2026-109619"])
        self.assertEqual(len(items), 3)

    def test_empty_spec_skipped(self):
        items = select(["", "618-S1"])
        self.assertEqual(len(items), 1)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

NONCE = "P2STESTNONCE1234"


class BuildControlMultipartTests(unittest.TestCase):
    def test_contains_boundary(self):
        body = build_control_multipart(NONCE)
        boundary = control_boundary(NONCE)
        self.assertIn(boundary.encode(), body)

    def test_contains_control_field(self):
        body = build_control_multipart(NONCE)
        self.assertIn(b"p2s_control", body)

    def test_ends_with_closing_boundary(self):
        body = build_control_multipart(NONCE)
        boundary = control_boundary(NONCE)
        self.assertTrue(body.rstrip().endswith(f"--{boundary}--".encode()))


class BuildPartHeaderBombTests(unittest.TestCase):
    def test_default_header_count(self):
        body = build_part_header_bomb(NONCE)
        count = body.count(b"X-P2S-Pad-")
        self.assertEqual(count, 5000)

    def test_custom_headers(self):
        body = build_part_header_bomb(NONCE, headers=10, header_size=50)
        count = body.count(b"X-P2S-Pad-")
        self.assertEqual(count, 10)

    def test_custom_header_size(self):
        body = build_part_header_bomb(NONCE, headers=1, header_size=200)
        # The header line: "X-P2S-Pad-00000: " + "A"*200 + "\r\n"
        self.assertIn(b"A" * 200, body)

    def test_boundary_matches(self):
        body = build_part_header_bomb(NONCE)
        boundary = header_bomb_boundary(NONCE)
        self.assertIn(boundary.encode(), body)


class BuildEmptyFileNestedTests(unittest.TestCase):
    def test_default_part_count(self):
        body = build_empty_file_nested(NONCE)
        count = body.count(b"Content-Disposition:")
        self.assertEqual(count, 1200)

    def test_custom_parts(self):
        body = build_empty_file_nested(NONCE, parts=5, depth=2)
        count = body.count(b"Content-Disposition:")
        self.assertEqual(count, 5)

    def test_nesting_depth(self):
        body = build_empty_file_nested(NONCE, parts=1, depth=3)
        self.assertIn(b"[a][a][a]", body)

    def test_boundary_matches(self):
        body = build_empty_file_nested(NONCE)
        boundary = nested_boundary(NONCE)
        self.assertIn(boundary.encode(), body)


class BuildUndeclaredLengthTests(unittest.TestCase):
    def test_approximately_1mib(self):
        body = build_undeclared_length(NONCE, mib=1)
        self.assertAlmostEqual(len(body), 1 << 20, delta=512)

    def test_boundary_matches(self):
        body = build_undeclared_length(NONCE)
        boundary = chunked_boundary(NONCE)
        self.assertIn(boundary.encode(), body)


class BuildUploadProgressTests(unittest.TestCase):
    def test_contains_progress_field(self):
        body = build_upload_progress(NONCE)
        self.assertIn(b"PHP_SESSION_UPLOAD_PROGRESS", body)

    def test_contains_nonce(self):
        body = build_upload_progress(NONCE)
        self.assertIn(NONCE.encode(), body)

    def test_boundary_matches(self):
        body = build_upload_progress(NONCE)
        boundary = upload_progress_boundary(NONCE)
        self.assertIn(boundary.encode(), body)


class BuildAppOomTests(unittest.TestCase):
    def test_approximately_1mib(self):
        body = build_app_oom(NONCE, "bigfield", 1)
        self.assertAlmostEqual(len(body), 1 << 20, delta=512)

    def test_contains_field_name(self):
        body = build_app_oom(NONCE, "bigfield", 1)
        self.assertIn(b"bigfield", body)

    def test_boundary_matches(self):
        body = build_app_oom(NONCE, "f", 1)
        boundary = app_oom_boundary(NONCE)
        self.assertIn(boundary.encode(), body)


class BoundTests(unittest.TestCase):
    def test_small_body_passes(self):
        data = b"hello"
        self.assertIs(_bound(data), data)

    def test_oversized_raises(self):
        data = b"X" * (MAX_BUILT_BODY + 1)
        with self.assertRaises(ValueError):
            _bound(data)

    def test_exactly_max_passes(self):
        data = b"X" * MAX_BUILT_BODY
        self.assertIs(_bound(data), data)


class NewScenarioNonceTests(unittest.TestCase):
    def test_starts_with_p2s(self):
        nonce = new_scenario_nonce("618-S2")
        self.assertTrue(nonce.startswith("P2S"))

    def test_deterministic_prefix(self):
        a = new_scenario_nonce("618-S2")
        b = new_scenario_nonce("618-S2")
        self.assertEqual(a[:6], b[:6])


# ---------------------------------------------------------------------------
# Boundary determinism
# ---------------------------------------------------------------------------

class BoundaryDeterminismTests(unittest.TestCase):
    def test_control_boundary_deterministic(self):
        self.assertEqual(control_boundary(NONCE), control_boundary(NONCE))

    def test_header_bomb_boundary_deterministic(self):
        self.assertEqual(header_bomb_boundary(NONCE), header_bomb_boundary(NONCE))

    def test_nested_boundary_deterministic(self):
        self.assertEqual(nested_boundary(NONCE), nested_boundary(NONCE))

    def test_chunked_boundary_deterministic(self):
        self.assertEqual(chunked_boundary(NONCE), chunked_boundary(NONCE))

    def test_upload_progress_boundary_deterministic(self):
        self.assertEqual(upload_progress_boundary(NONCE), upload_progress_boundary(NONCE))

    def test_app_oom_boundary_deterministic(self):
        self.assertEqual(app_oom_boundary(NONCE), app_oom_boundary(NONCE))


# ---------------------------------------------------------------------------
# _public_host
# ---------------------------------------------------------------------------

class PublicHostTests(unittest.TestCase):
    def test_loopback_is_not_public(self):
        self.assertFalse(_public_host("127.0.0.1"))

    def test_localhost_is_not_public(self):
        self.assertFalse(_public_host("localhost"))

    def test_private_192_168(self):
        self.assertFalse(_public_host("192.168.1.1"))

    def test_private_10(self):
        self.assertFalse(_public_host("10.0.0.1"))

    def test_dns_failure_returns_false(self):
        self.assertFalse(_public_host("nonexistent.invalid"))

    @patch("p2s.cli.socket.getaddrinfo")
    def test_global_ip_returns_true(self, mock_gai):
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0)),
        ]
        self.assertTrue(_public_host("example.com"))

    @patch("p2s.cli.socket.getaddrinfo")
    def test_ipv6_loopback_returns_false(self, mock_gai):
        mock_gai.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0)),
        ]
        self.assertFalse(_public_host("ip6-localhost"))

    @patch("p2s.cli.socket.getaddrinfo")
    def test_ipv4_mapped_ipv6_private(self, mock_gai):
        mock_gai.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::ffff:10.0.0.1", 0, 0, 0)),
        ]
        self.assertFalse(_public_host("mapped-private"))

    @patch("p2s.cli.socket.getaddrinfo")
    def test_mixed_private_and_global(self, mock_gai):
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        ]
        self.assertTrue(_public_host("mixed.example"))


if __name__ == "__main__":
    unittest.main()
