"""Tests for p2s.prove — budget enforcement, degradation, preflight, dataclasses."""

from __future__ import annotations

import unittest

from p2s.prove import (
    Budget,
    BudgetExceeded,
    ProveLimits,
    ProveOptions,
    ProveOutcome,
    _degraded,
)


class ProveLimitsTests(unittest.TestCase):
    def test_defaults(self):
        lim = ProveLimits()
        self.assertEqual(lim.max_requests, 8)
        self.assertEqual(lim.max_bytes, 32 * 1024 * 1024)
        self.assertEqual(lim.concurrency, 1)
        self.assertTrue(lim.stop_on_degradation)

    def test_to_dict_keys(self):
        d = ProveLimits().to_dict()
        self.assertIn("max_requests", d)
        self.assertIn("max_bytes", d)
        self.assertIn("timeout_seconds", d)
        self.assertIn("health_timeout_seconds", d)
        self.assertIn("max_seconds", d)


class BudgetRequestCapTests(unittest.TestCase):
    def test_within_budget(self):
        b = Budget(ProveLimits(max_requests=3, max_bytes=10_000))
        b.check(100)
        b.consume(100)
        self.assertEqual(b.requests, 1)
        self.assertEqual(b.bytes, 100)

    def test_exceeds_request_count(self):
        b = Budget(ProveLimits(max_requests=1, max_bytes=10_000))
        b.check(10)
        b.consume(10)
        with self.assertRaises(BudgetExceeded):
            b.check(10)

    def test_exceeds_byte_total(self):
        b = Budget(ProveLimits(max_requests=100, max_bytes=50))
        b.check(30)
        b.consume(30)
        with self.assertRaises(BudgetExceeded):
            b.check(30)

    def test_exceeds_per_request_bytes(self):
        b = Budget(ProveLimits(max_request_bytes=100))
        with self.assertRaises(BudgetExceeded):
            b.check(200)


class DegradedTests(unittest.TestCase):
    def test_ok_to_not_ok(self):
        before = {"ok": True, "latency_ms": 50}
        after = {"ok": False, "latency_ms": 60}
        self.assertTrue(_degraded(before, after))

    def test_both_ok_normal_latency(self):
        before = {"ok": True, "latency_ms": 50}
        after = {"ok": True, "latency_ms": 60}
        self.assertFalse(_degraded(before, after))

    def test_high_latency_spike(self):
        before = {"ok": True, "latency_ms": 100}
        after = {"ok": True, "latency_ms": 5000}
        self.assertTrue(_degraded(before, after))

    def test_both_not_ok(self):
        before = {"ok": False, "latency_ms": 50}
        after = {"ok": False, "latency_ms": 50}
        self.assertFalse(_degraded(before, after))

    def test_missing_latency(self):
        before = {"ok": True}
        after = {"ok": True}
        self.assertFalse(_degraded(before, after))


class ProveOutcomeTests(unittest.TestCase):
    def test_to_dict(self):
        o = ProveOutcome(
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:01:00Z",
            request_count=3,
            byte_count=1024,
            stopped_reason="budget",
        )
        d = o.to_dict()
        self.assertEqual(d["request_count"], 3)
        self.assertEqual(d["byte_count"], 1024)
        self.assertEqual(d["stopped_reason"], "budget")
        self.assertFalse(d["interrupted"])
        self.assertIsInstance(d["runs"], list)

    def test_empty_outcome(self):
        o = ProveOutcome()
        d = o.to_dict()
        self.assertEqual(d["runs"], [])
        self.assertEqual(d["stopped_reason"], "")


class ProveOptionsTests(unittest.TestCase):
    def test_defaults(self):
        opts = ProveOptions()
        self.assertFalse(opts.acknowledge_authorised)
        self.assertEqual(opts.environment_kind, "lab")
        self.assertFalse(opts.allow_rerun)
        self.assertIsInstance(opts.limits, ProveLimits)


if __name__ == "__main__":
    unittest.main()
