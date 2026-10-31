"""Tests for p2s.canary — canary verification logic."""

from __future__ import annotations

import unittest
from p2s.canary import CanaryAssessment, check_canary, _contains
from p2s.http import HttpExchange
from p2s.telemetry import TelemetryEvent


def _exchange(body: str = "", request_id: str = "REQ-1",
              sent_at: str = "2026-01-01T00:00:00Z",
              received_at: str = "2026-01-01T00:00:01Z") -> HttpExchange:
    return HttpExchange(
        request_id=request_id, method="GET", url="http://lab/canary",
        sent_at=sent_at, received_at=received_at, duration_ms=100.0,
        body_preview=body,
    )


def _event(event_type: str = "canary_write", nonce: str = "",
           worker_id: str = "", request_id: str = "",
           timestamp: str = "2026-01-01T00:00:01Z",
           line_no: int = 1) -> TelemetryEvent:
    return TelemetryEvent(
        source="test", timestamp=timestamp, message="test event",
        event_type=event_type, nonce=nonce, worker_id=worker_id,
        request_id=request_id, line_no=line_no,
    )


class ContainsTests(unittest.TestCase):
    def test_nonce_in_body(self):
        self.assertTrue(_contains("hello P2S-ABC123 world", "P2S-ABC123"))

    def test_nonce_not_in_body(self):
        self.assertFalse(_contains("hello world", "P2S-ABC123"))

    def test_empty_nonce(self):
        self.assertFalse(_contains("anything", ""))

    def test_none_body(self):
        self.assertFalse(_contains(None, "P2S-ABC123"))


class CheckCanaryNoNonceTests(unittest.TestCase):
    def test_no_nonce_returns_unverified(self):
        result = check_canary(None, _exchange(), _exchange(), [], [])
        self.assertFalse(result.verified)
        self.assertFalse(result.requested)
        self.assertTrue(any("no canary nonce" in m for m in result.missing))


class CheckCanaryMissingExchangesTests(unittest.TestCase):
    def test_missing_before(self):
        result = check_canary("NONCE1", None, _exchange(), [], [])
        self.assertFalse(result.verified)
        self.assertTrue(any("readback before/after" in m for m in result.missing))

    def test_missing_after(self):
        result = check_canary("NONCE1", _exchange(), None, [], [])
        self.assertFalse(result.verified)
        self.assertTrue(any("readback before/after" in m for m in result.missing))


class CheckCanaryReadbackTests(unittest.TestCase):
    def test_nonce_present_before_not_fresh(self):
        before = _exchange(body="has NONCE1 here")
        after = _exchange(body="has NONCE1 here")
        result = check_canary("NONCE1", before, after, [], [])
        self.assertTrue(result.before_present)
        self.assertFalse(result.readback_verified)
        self.assertFalse(result.verified)
        self.assertTrue(any("already present before" in m for m in result.missing))

    def test_nonce_absent_before_present_after(self):
        before = _exchange(body="clean")
        after = _exchange(body="found NONCE1")
        result = check_canary("NONCE1", before, after, [], [])
        self.assertFalse(result.before_present)
        self.assertTrue(result.after_present)
        self.assertTrue(result.readback_verified)

    def test_nonce_absent_everywhere(self):
        before = _exchange(body="clean")
        after = _exchange(body="still clean")
        result = check_canary("NONCE1", before, after, [], [])
        self.assertFalse(result.after_present)
        self.assertFalse(result.readback_verified)
        self.assertTrue(any("did not appear" in m for m in result.missing))


class CheckCanaryReflectionTests(unittest.TestCase):
    def test_nonce_reflected_in_test_response(self):
        before = _exchange(body="clean")
        after = _exchange(body="found NONCE1")
        test_ex = _exchange(body="NONCE1 leaked here", request_id="REQ-TEST")
        result = check_canary("NONCE1", before, after, [test_ex], [])
        self.assertTrue(result.reflected_in_test_responses)
        self.assertFalse(result.verified)
        self.assertTrue(any("reflected" in m for m in result.missing))

    def test_no_reflection(self):
        before = _exchange(body="clean")
        after = _exchange(body="found NONCE1")
        test_ex = _exchange(body="no leaks here", request_id="REQ-TEST")
        result = check_canary("NONCE1", before, after, [test_ex], [])
        self.assertFalse(result.reflected_in_test_responses)


class CheckCanaryTelemetryTests(unittest.TestCase):
    def test_telemetry_write_with_worker_match(self):
        before = _exchange(body="clean")
        after = _exchange(body="found NONCE1")
        event = _event(nonce="NONCE1", worker_id="42", request_id="REQ-1")
        result = check_canary(
            "NONCE1", before, after, [], [event],
            expected_worker_id="42",
        )
        self.assertTrue(result.telemetry_write)
        self.assertTrue(result.telemetry_worker_match)

    def test_telemetry_write_without_worker_match(self):
        before = _exchange(body="clean")
        after = _exchange(body="found NONCE1")
        event = _event(nonce="NONCE1", worker_id="99", request_id="REQ-OTHER")
        result = check_canary(
            "NONCE1", before, after, [], [event],
            expected_worker_id="42",
        )
        self.assertTrue(result.telemetry_write)
        self.assertFalse(result.telemetry_worker_match)
        self.assertFalse(result.verified)

    def test_telemetry_write_matched_by_request_id(self):
        before = _exchange(body="clean")
        after = _exchange(body="found NONCE1")
        event = _event(nonce="NONCE1", worker_id="99", request_id="REQ-1")
        result = check_canary(
            "NONCE1", before, after, [], [event],
            expected_request_id="REQ-1",
        )
        self.assertTrue(result.telemetry_worker_match)

    def test_no_telemetry(self):
        before = _exchange(body="clean")
        after = _exchange(body="found NONCE1")
        result = check_canary("NONCE1", before, after, [], [])
        self.assertFalse(result.telemetry_write)
        self.assertTrue(any("no telemetry canary_write" in m for m in result.missing))


class CheckCanaryFullVerificationTests(unittest.TestCase):
    def test_all_conditions_met(self):
        before = _exchange(body="clean")
        after = _exchange(body="found NONCE1")
        event = _event(nonce="NONCE1", worker_id="42", request_id="REQ-1")
        result = check_canary(
            "NONCE1", before, after, [], [event],
            expected_worker_id="42",
        )
        self.assertTrue(result.readback_verified)
        self.assertFalse(result.reflected_in_test_responses)
        self.assertTrue(result.telemetry_write)
        self.assertTrue(result.telemetry_worker_match)
        self.assertTrue(result.verified)


class CanaryAssessmentToDictTests(unittest.TestCase):
    def test_round_trip(self):
        ca = CanaryAssessment(
            requested=True, nonce="N1", readback_url="/canary",
            before_present=False, after_present=True,
            reflected_in_test_responses=False, telemetry_write=True,
            telemetry_worker_match=True, readback_verified=True,
            verified=True, reasons=["ok"], missing=[],
            before_ref="B1", after_ref="A1", telemetry_refs=["T1"],
        )
        d = ca.to_dict()
        self.assertEqual(d["nonce"], "N1")
        self.assertTrue(d["verified"])
        self.assertTrue(d["readback_verified"])
        self.assertEqual(d["reasons"], ["ok"])
        self.assertEqual(d["telemetry_refs"], ["T1"])
        self.assertIsInstance(d, dict)


if __name__ == "__main__":
    unittest.main()
