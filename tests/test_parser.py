"""Version, patch and telemetry parser tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from p2s.patch import assess_patch, branch_of, fixed_version, is_packaged_version, parse_version
from p2s.telemetry import (
    merge_events,
    parse_json_event,
    parse_telemetry_file,
    parse_text_event,
    source_for_path,
)
from p2s.version import CVE_618, CVE_619


class VersionParsingTests(unittest.TestCase):
    def test_parse_version(self) -> None:
        self.assertEqual(parse_version("8.2.12"), (8, 2, 12, ""))
        self.assertEqual(parse_version("8.4.27-1+deb12u2")[:3], (8, 4, 27))
        self.assertIsNone(parse_version("not-a-version"))
        self.assertIsNone(parse_version(None))

    def test_branch_and_fixed(self) -> None:
        self.assertEqual(branch_of("8.3.36"), "8.3")
        self.assertEqual(fixed_version("8.2.1"), "8.2.35")
        self.assertEqual(fixed_version("8.5.0"), "8.5.12")
        self.assertIsNone(fixed_version("7.4.33"))

    def test_packaged_detection(self) -> None:
        self.assertTrue(is_packaged_version("8.2.29-1+deb12u6"))
        self.assertTrue(is_packaged_version("8.2.29-1ubuntu1"))
        self.assertTrue(is_packaged_version("8.2.29-1.el9"))
        self.assertFalse(is_packaged_version("8.2.29"))
        self.assertFalse(is_packaged_version("8.2.29RC1"))


class PatchAssessmentTests(unittest.TestCase):
    def test_plain_affected_build(self) -> None:
        result = assess_patch("8.2.12", source="lab", trust="high")
        self.assertEqual(result.state, "AFFECTED")
        self.assertEqual(result.trust, "high")
        self.assertEqual(result.per_cve[CVE_618]["state"], "AFFECTED")
        self.assertEqual(result.per_cve[CVE_619]["state"], "AFFECTED")

    def test_plain_patched_build(self) -> None:
        result = assess_patch("8.4.27", source="lab", trust="high")
        self.assertEqual(result.state, "PATCHED")
        self.assertEqual(result.per_cve[CVE_618]["state"], "PATCHED")
        self.assertEqual(result.per_cve[CVE_619]["state"], "PATCHED")

    def test_low_trust_banner_is_not_patch_evidence(self) -> None:
        result = assess_patch("8.4.27", source="x-powered-by", trust="low")
        self.assertEqual(result.state, "PATCHED")
        self.assertEqual(result.trust, "low")

    def test_packaged_below_fixed_is_unknown_without_backport(self) -> None:
        result = assess_patch("8.2.29-1+deb12u6", source="package-manifest", trust="high")
        self.assertEqual(result.state, "UNKNOWN")
        self.assertEqual(result.per_cve[CVE_618]["state"], "UNKNOWN")
        self.assertEqual(result.per_cve[CVE_619]["state"], "UNKNOWN")

    def test_backport_can_patch_only_one_cve(self) -> None:
        backports = [
            {
                "cve": CVE_618,
                "source": "debian",
                "reference": "DSA-2026-0001",
                "status": "fixed",
            }
        ]
        result = assess_patch(
            "8.2.29-1+deb12u6",
            source="package-manifest",
            trust="high",
            backports=backports,
        )
        self.assertEqual(result.per_cve[CVE_618]["state"], "PATCHED")
        self.assertEqual(result.per_cve[CVE_619]["state"], "UNKNOWN")
        self.assertEqual(result.state, "UNKNOWN")

    def test_backport_not_fixed_marks_affected(self) -> None:
        backports = [
            {
                "cve": CVE_619,
                "source": "ubuntu",
                "reference": "USN-0001-1",
                "status": "not_fixed",
            }
        ]
        result = assess_patch(
            "8.2.29-1+deb12u6",
            source="package-manifest",
            trust="high",
            backports=backports,
        )
        self.assertEqual(result.per_cve[CVE_619]["state"], "AFFECTED")
        self.assertEqual(result.per_cve[CVE_619]["trust"], "high")

    def test_untracked_branch_is_not_extrapolated(self) -> None:
        result = assess_patch("7.4.33", source="lab", trust="high")
        self.assertEqual(result.state, "UNKNOWN")
        self.assertIn("not covered", result.details)


class TelemetryParserTests(unittest.TestCase):
    def _write(self, text: str) -> str:
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".log", delete=False, encoding="utf-8", newline=""
        )
        handle.write(text)
        handle.close()
        self.addCleanup(lambda: os.path.exists(handle.name) and os.unlink(handle.name))
        return handle.name

    def test_php_log_line_with_named_timezone(self) -> None:
        path = self._write(
            "[23-Oct-2026 19:43:18 Europe/Berlin] PHP Fatal error:  "
            "Allowed memory size of 16777216 bytes exhausted (tried to allocate "
            "4096 bytes) in Unknown on line 0\n"
        )
        events, errors = parse_telemetry_file(path, "php_log")
        self.assertEqual(errors, [])
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.event_type, "oom")
        self.assertEqual(event.timestamp, "2026-10-23T17:43:18.000Z")
        self.assertEqual(event.phase, "startup_like")
        self.assertIn("Allowed memory size", event.message)

    def test_jsonl_event_with_identity(self) -> None:
        path = self._write(
            json.dumps(
                {
                    "timestamp": "2026-10-24T10:00:00Z",
                    "event": "state_publish",
                    "message": "state_publish request-owned",
                    "request_id": "req-abc",
                    "worker_pid": 4242,
                    "phase": "post_startup",
                }
            )
            + "\n"
        )
        events, errors = parse_telemetry_file(path, "lab_trace")
        self.assertEqual(errors, [])
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.event_type, "state_publish")
        self.assertEqual(event.request_id, "req-abc")
        self.assertEqual(event.worker_id, "4242")
        self.assertEqual(event.phase, "post_startup")

    def test_json_array_of_events(self) -> None:
        path = self._write(
            json.dumps(
                [
                    {"timestamp": "2026-10-24T10:00:00Z", "event": "state_publish"},
                    {"timestamp": "2026-10-24T10:00:01Z", "event": "state_consume"},
                ]
            )
            + "\n"
        )
        events, errors = parse_telemetry_file(path, "lab_trace")
        self.assertEqual(errors, [])
        self.assertEqual([event.event_type for event in events], ["state_publish", "state_consume"])

    def test_malformed_json_is_reported_not_silently_dropped(self) -> None:
        path = self._write('{"timestamp": "2026-10-24T10:00:00Z", "event": \n')
        events, errors = parse_telemetry_file(path, "lab_trace")
        self.assertEqual(events, [])
        self.assertTrue(errors)
        self.assertIn("invalid JSON", errors[0])

    def test_bracketed_non_log_line_is_reported(self) -> None:
        path = self._write("[not a timestamp and not json]\n")
        events, errors = parse_telemetry_file(path, "php_log")
        self.assertEqual(events, [])
        self.assertTrue(errors)

    def test_text_line_extracts_request_and_pid(self) -> None:
        event = parse_text_event(
            "2026-10-24 10:00:00 request_id=req-xyz worker_pid=777 "
            "PHP Warning: something",
            "php_log",
            7,
        )
        self.assertEqual(event.request_id, "req-xyz")
        self.assertEqual(event.worker_id, "777")
        self.assertEqual(event.event_type, "diagnostic")

    def test_unknown_line_is_still_retained(self) -> None:
        event = parse_text_event("a plain line with no timestamp", "php_log", 1)
        self.assertEqual(event.event_type, "log")
        self.assertTrue(event.timestamp)

    def test_source_for_path(self) -> None:
        self.assertEqual(source_for_path("/var/log/php-fpm.log"), "worker_telemetry")
        self.assertEqual(source_for_path("nginx-access.log"), "web_server_log")
        self.assertEqual(source_for_path("lab-trace.jsonl"), "lab_trace")
        self.assertEqual(source_for_path("php-error.log"), "php_log")

    def test_merge_events_deduplicates_and_sorts(self) -> None:
        first = parse_text_event("2026-10-24 10:00:02 PHP Warning: b", "php_log", 2)
        second = parse_text_event("2026-10-24 10:00:01 PHP Warning: a", "php_log", 1)
        merged = merge_events([first, second], [first])
        self.assertEqual(len(merged), 2)
        self.assertLess(merged[0].timestamp, merged[1].timestamp)

    def test_json_event_direct(self) -> None:
        event = parse_json_event(
            {
                "timestamp": "2026-10-24T10:00:00Z",
                "event_type": "canary_write",
                "message": "canary write",
                "nonce": "P2S-CANARYTESTNONCE123456",
            },
            "lab_trace",
            3,
        )
        self.assertEqual(event.event_type, "canary_write")
        self.assertEqual(event.nonce, "P2S-CANARYTESTNONCE123456")


if __name__ == "__main__":
    unittest.main()
