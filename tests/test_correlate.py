"""Tests for p2s.correlate — producer/consumer correlation logic."""

from __future__ import annotations

import unittest
from p2s.correlate import (
    CorrelationResult,
    correlate_requests,
    correlate_with_fallback,
    _events_for_request,
    _workers,
    _between,
)
from p2s.http import HttpExchange
from p2s.telemetry import TelemetryEvent


def _exchange(request_id: str = "REQ-1",
              sent_at: str = "2026-01-01T00:00:00Z",
              received_at: str = "2026-01-01T00:00:01Z") -> HttpExchange:
    return HttpExchange(
        request_id=request_id, method="POST", url="http://lab/target",
        sent_at=sent_at, received_at=received_at, duration_ms=100.0,
    )


def _event(event_type: str, worker_id: str = "", request_id: str = "",
           timestamp: str = "2026-01-01T00:00:01Z",
           nonce: str = "", line_no: int = 1) -> TelemetryEvent:
    return TelemetryEvent(
        source="test", timestamp=timestamp, message="test",
        event_type=event_type, worker_id=worker_id,
        request_id=request_id, nonce=nonce, line_no=line_no,
    )


class CorrelateNoneInputTests(unittest.TestCase):
    def test_none_producer(self):
        r = correlate_requests(None, _exchange("REQ-C"), [])
        self.assertTrue(any("both producer and consumer" in m for m in r.missing))
        self.assertEqual(r.correlation_strength, "none")

    def test_none_consumer(self):
        r = correlate_requests(_exchange("REQ-P"), None, [])
        self.assertTrue(any("both producer and consumer" in m for m in r.missing))

    def test_both_none(self):
        r = correlate_requests(None, None, [])
        self.assertTrue(any("both producer and consumer" in m for m in r.missing))


class CorrelateIdenticalRequestTests(unittest.TestCase):
    def test_same_request_id(self):
        ex = _exchange("REQ-SAME")
        r = correlate_requests(ex, ex, [])
        self.assertTrue(any("must be different" in m for m in r.missing))


class CorrelateNoTelemetryTests(unittest.TestCase):
    def test_no_events(self):
        p = _exchange("REQ-P", sent_at="2026-01-01T00:00:00Z", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:02Z", received_at="2026-01-01T00:00:03Z")
        r = correlate_requests(p, c, [])
        self.assertEqual(r.correlation_strength, "none")
        self.assertFalse(r.same_worker)


class CorrelateSameWorkerTests(unittest.TestCase):
    def test_same_worker_pid(self):
        p = _exchange("REQ-P", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:02Z")
        events = [
            _event("oom", worker_id="42", request_id="REQ-P", timestamp="2026-01-01T00:00:00Z"),
            _event("state_consume", worker_id="42", request_id="REQ-C", timestamp="2026-01-01T00:00:02Z"),
        ]
        r = correlate_requests(p, c, events)
        self.assertTrue(r.same_worker)
        self.assertEqual(r.producer_worker, "42")
        self.assertEqual(r.consumer_worker, "42")

    def test_different_worker_pids(self):
        p = _exchange("REQ-P", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:02Z")
        events = [
            _event("oom", worker_id="42", request_id="REQ-P"),
            _event("state_consume", worker_id="99", request_id="REQ-C"),
        ]
        r = correlate_requests(p, c, events)
        self.assertFalse(r.same_worker)
        self.assertEqual(r.producer_worker, "42")
        self.assertEqual(r.consumer_worker, "99")


class CorrelateWorkerRecycleTests(unittest.TestCase):
    def test_worker_recycled_resets_same_worker(self):
        p = _exchange("REQ-P", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:05Z")
        events = [
            _event("oom", worker_id="42", request_id="REQ-P", timestamp="2026-01-01T00:00:00Z"),
            _event("worker_exit", worker_id="42", timestamp="2026-01-01T00:00:03Z"),
            _event("state_consume", worker_id="42", request_id="REQ-C", timestamp="2026-01-01T00:00:05Z"),
        ]
        r = correlate_requests(p, c, events)
        self.assertTrue(r.worker_recycled_between)
        self.assertFalse(r.same_worker)


class CorrelateStrongTests(unittest.TestCase):
    def _strong_result(self) -> CorrelationResult:
        p = _exchange("REQ-P", sent_at="2026-01-01T00:00:00Z", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:02Z", received_at="2026-01-01T00:00:03Z")
        events = [
            _event("state_publish", worker_id="42", request_id="REQ-P", timestamp="2026-01-01T00:00:00Z"),
            _event("oom", worker_id="42", request_id="REQ-P", timestamp="2026-01-01T00:00:01Z"),
            _event("state_consume", worker_id="42", request_id="REQ-C", timestamp="2026-01-01T00:00:02Z"),
        ]
        return correlate_requests(p, c, events)

    def test_strong_correlation(self):
        r = self._strong_result()
        self.assertEqual(r.correlation_strength, "strong")
        self.assertTrue(r.same_worker)
        self.assertTrue(r.producer_ended_before_consumer)
        self.assertTrue(r.state_published)
        self.assertTrue(r.state_consumed)

    def test_strong_without_stale_marker_warns(self):
        r = self._strong_result()
        self.assertTrue(any("pointer" in m or "identity" in m for m in r.missing))


class CorrelateProducerFlagsTests(unittest.TestCase):
    def test_producer_oom_flag(self):
        p = _exchange("REQ-P", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:02Z")
        events = [
            _event("oom", worker_id="42", request_id="REQ-P"),
            _event("ini_diagnostic", worker_id="42", request_id="REQ-C"),
        ]
        r = correlate_requests(p, c, events)
        self.assertTrue(r.producer_oom)
        self.assertTrue(r.producer_fatal)

    def test_producer_fatal_without_oom(self):
        p = _exchange("REQ-P", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:02Z")
        events = [
            _event("fatal", worker_id="42", request_id="REQ-P"),
        ]
        r = correlate_requests(p, c, events)
        self.assertTrue(r.producer_fatal)
        self.assertFalse(r.producer_oom)


class CorrelateConsumerFlagsTests(unittest.TestCase):
    def test_early_consumer(self):
        p = _exchange("REQ-P", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:02Z")
        events = [
            _event("state_publish", worker_id="42", request_id="REQ-P"),
            _event("ini_diagnostic", worker_id="42", request_id="REQ-C"),
        ]
        r = correlate_requests(p, c, events)
        self.assertTrue(r.early_consumer)
        self.assertTrue(r.state_consumed)

    def test_address_reuse_flag(self):
        p = _exchange("REQ-P", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:02Z")
        events = [
            _event("address_reuse", worker_id="42", request_id="REQ-C"),
        ]
        r = correlate_requests(p, c, events)
        self.assertTrue(r.address_reuse)

    def test_patched_baseline_flag(self):
        p = _exchange("REQ-P", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:02Z")
        events = [
            _event("patched_baseline", worker_id="42", request_id="REQ-C"),
        ]
        r = correlate_requests(p, c, events)
        self.assertTrue(r.patched_baseline)


class CorrelateFallbackTests(unittest.TestCase):
    def test_fallback_warns_no_request_ids(self):
        p = _exchange("REQ-P", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:02Z")
        r = correlate_with_fallback(p, c, [])
        self.assertTrue(any("request IDs" in m for m in r.missing))

    def test_fallback_no_extra_warn_when_events_exist(self):
        p = _exchange("REQ-P", received_at="2026-01-01T00:00:01Z")
        c = _exchange("REQ-C", sent_at="2026-01-01T00:00:02Z")
        events = [
            _event("oom", worker_id="42", request_id="REQ-P"),
        ]
        r = correlate_with_fallback(p, c, events)
        self.assertFalse(any("request IDs" in m and "timing alone" in m for m in r.missing))


class HelperFunctionTests(unittest.TestCase):
    def test_events_for_request_filters(self):
        events = [
            _event("oom", request_id="REQ-A"),
            _event("fatal", request_id="REQ-B"),
            _event("oom", request_id="REQ-A"),
        ]
        filtered = _events_for_request(events, "REQ-A")
        self.assertEqual(len(filtered), 2)

    def test_events_for_request_none_id(self):
        events = [_event("oom", request_id="REQ-A")]
        self.assertEqual(_events_for_request(events, None), [])

    def test_workers_extracts_unique(self):
        events = [
            _event("oom", worker_id="42"),
            _event("fatal", worker_id="42"),
            _event("oom", worker_id="99"),
        ]
        self.assertEqual(_workers(events), {"42", "99"})

    def test_workers_skips_empty(self):
        events = [_event("oom", worker_id=""), _event("oom", worker_id="42")]
        self.assertEqual(_workers(events), {"42"})

    def test_between_filters_by_time(self):
        events = [
            _event("oom", timestamp="2026-01-01T00:00:00Z"),
            _event("fatal", timestamp="2026-01-01T00:00:05Z"),
            _event("oom", timestamp="2026-01-01T00:00:10Z"),
        ]
        filtered = _between(events, "2026-01-01T00:00:01Z", "2026-01-01T00:00:09Z")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].event_type, "fatal")


class CorrelationResultToDictTests(unittest.TestCase):
    def test_round_trip(self):
        r = CorrelationResult(
            same_worker=True, producer_worker="42", consumer_worker="42",
            correlation_strength="strong",
            reasons=["matched"], missing=[],
        )
        d = r.to_dict()
        self.assertTrue(d["same_worker"])
        self.assertEqual(d["producer_worker"], "42")
        self.assertEqual(d["correlation_strength"], "strong")
        self.assertIsInstance(d, dict)


if __name__ == "__main__":
    unittest.main()
