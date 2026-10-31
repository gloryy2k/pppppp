"""Tests for p2s.report — evidence_summary, build_document, render_markdown, render_html."""

from __future__ import annotations

import unittest

from p2s.models import (
    CaseFile,
    Evidence,
    Finding,
    PatchAssessment,
    ReachAssessment,
    ScenarioRun,
    TargetProfile,
)
from p2s.report import (
    _evidence_summary,
    _global_limitations,
    _md,
    build_document,
    render_html,
    render_markdown,
)


def _profile() -> TargetProfile:
    return TargetProfile(
        target="http://lab:8080",
        base_url="http://lab:8080/",
        host="lab",
        port=8080,
        tls=False,
        php_version="8.3.6",
        version_source="phpinfo",
        version_trust="high",
        sapi="mod_php",
        sapi_source="phpinfo",
        sapi_verified=True,
        patch=PatchAssessment(state="AFFECTED", trust="high"),
        reach=ReachAssessment(state="REACHABLE", basis=["200 on control"]),
        environment_kind="lab",
    )


def _case(synthetic: bool = False) -> CaseFile:
    return CaseFile(
        run_id="run-001",
        tool_version="4.0.0",
        mode="prove",
        profile=_profile(),
        evidence=[
            Evidence(
                id="ev-1",
                source="http",
                timestamp="2026-01-01T00:00:01Z",
                data={
                    "exchange": {"method": "POST", "url": "http://lab/", "status": 200},
                    "classification": {"kind": "normal"},
                },
                sha256="a" * 64,
                scenario_id="618-S1",
                request_id="REQ-1",
            ),
        ],
        scenario_runs=[
            ScenarioRun(
                scenario_id="618-S1",
                cve="CVE-2026-109618",
                executed=True,
                producer_request_id="REQ-1",
            ),
        ],
        environment={"kind": "lab" if not synthetic else "fixture", "synthetic": synthetic},
    )


def _finding_618(status: str = "OOM_OBSERVED") -> Finding:
    return Finding(
        cve="CVE-2026-109618",
        status=status,
        scenario_id="618-S1",
        evidence_refs=["ev-1"],
        proof_method="session upload progress OOM",
        proof_limitations=["Remote black-box: cannot observe PHP memory internals"],
        alternative_explanations=["application logic OOM"],
        missing_evidence=[],
        remediation=["Upgrade to PHP 8.3.8+"],
    )


class EvidenceSummaryTests(unittest.TestCase):
    def test_http_evidence(self):
        ev = Evidence(
            id="ev-1", source="http",
            timestamp="2026-01-01T00:00:01Z",
            data={
                "exchange": {"method": "POST", "url": "http://lab/", "status": 200},
                "classification": {"kind": "normal"},
            },
            sha256="a" * 64,
        )
        s = _evidence_summary(ev)
        self.assertEqual(s["phase"], "http")
        self.assertIn("POST", s["summary"])
        self.assertIn("200", s["summary"])

    def test_telemetry_evidence(self):
        ev = Evidence(
            id="ev-2", source="php_log",
            timestamp="2026-01-01T00:00:02Z",
            data={"event": {"event_type": "oom", "message": "out of memory"}},
            sha256="b" * 64,
        )
        s = _evidence_summary(ev)
        self.assertEqual(s["phase"], "telemetry")
        self.assertIn("oom", s["summary"])

    def test_canary_evidence(self):
        ev = Evidence(
            id="ev-3", source="canary",
            timestamp="2026-01-01T00:00:03Z",
            data={"assessment": {"verified": True, "nonce": "N1"}},
            sha256="c" * 64,
        )
        s = _evidence_summary(ev)
        self.assertEqual(s["phase"], "canary")
        self.assertIn("verified=True", s["summary"])

    def test_host_inventory_evidence(self):
        ev = Evidence(
            id="ev-4", source="host_inventory",
            timestamp="2026-01-01T00:00:04Z",
            data={"inventory": {"php_version": "8.3.6", "sapi": "mod_php"}},
            sha256="d" * 64,
        )
        s = _evidence_summary(ev)
        self.assertEqual(s["phase"], "inventory")
        self.assertIn("8.3.6", s["summary"])


class MdEscapeTests(unittest.TestCase):
    def test_pipe_escaped(self):
        self.assertEqual(_md("a|b"), "a\\|b")

    def test_newline_replaced(self):
        self.assertEqual(_md("a\nb"), "a b")

    def test_none_becomes_empty(self):
        self.assertEqual(_md(None), "")


class GlobalLimitationsTests(unittest.TestCase):
    def test_baseline_limitations(self):
        case = _case()
        items = _global_limitations(case, [])
        self.assertTrue(len(items) >= 5)
        self.assertTrue(any("Remote black-box" in i for i in items))

    def test_synthetic_warning(self):
        case = _case(synthetic=True)
        items = _global_limitations(case, [])
        self.assertTrue(any("FIXTURE" in i for i in items))

    def test_finding_limitations_appended(self):
        case = _case()
        finding = _finding_618()
        items = _global_limitations(case, [finding])
        self.assertTrue(any("CVE-2026-109618" in i for i in items))


class BuildDocumentTests(unittest.TestCase):
    def test_schema_version(self):
        doc = build_document(_case(), [_finding_618()])
        self.assertEqual(doc["schema_version"], "php2shell-report/1")

    def test_verdicts_present(self):
        doc = build_document(_case(), [_finding_618()])
        verdicts = doc["executive_summary"]["verdicts"]
        self.assertIn("CVE-2026-109618", verdicts)
        self.assertEqual(verdicts["CVE-2026-109618"]["status"], "OOM_OBSERVED")

    def test_evidence_index_sorted(self):
        doc = build_document(_case(), [_finding_618()])
        self.assertIsInstance(doc["evidence_index"], list)
        self.assertTrue(len(doc["evidence_index"]) > 0)

    def test_integrity_block(self):
        doc = build_document(_case(), [_finding_618()])
        self.assertIn("integrity", doc)
        self.assertTrue(doc["integrity"]["verified"])
        self.assertEqual(doc["integrity"]["evidence_count"], 1)

    def test_verification_errors(self):
        doc = build_document(_case(), [_finding_618()], verification_errors=["bad hash"])
        self.assertFalse(doc["integrity"]["verified"])
        self.assertIn("bad hash", doc["integrity"]["errors"])

    def test_answers_section(self):
        doc = build_document(_case(), [_finding_618()])
        answers = doc["answers"]
        self.assertIn("did_test_request_reach_php", answers)
        self.assertIn("did_oom_occur_in_php", answers)
        self.assertIn("highest_conclusion_supported", answers)


class RenderMarkdownTests(unittest.TestCase):
    def test_has_executive_summary(self):
        doc = build_document(_case(), [_finding_618()])
        md = render_markdown(doc)
        self.assertIn("Executive summary", md)

    def test_has_environment_section(self):
        doc = build_document(_case(), [_finding_618()])
        md = render_markdown(doc)
        self.assertIn("Environment", md)
        self.assertIn("8.3.6", md)

    def test_has_recommendations(self):
        doc = build_document(_case(), [_finding_618()])
        md = render_markdown(doc)
        self.assertIn("Recommendations", md)

    def test_synthetic_warning_in_markdown(self):
        doc = build_document(_case(synthetic=True), [_finding_618()])
        md = render_markdown(doc)
        self.assertIn("SYNTHETIC", md)


class RenderHtmlTests(unittest.TestCase):
    def test_returns_html(self):
        doc = build_document(_case(), [_finding_618()])
        output = render_html(doc)
        self.assertIn("<!doctype html>", output.lower())
        self.assertIn("php2shell", output.lower())

    def test_contains_target(self):
        doc = build_document(_case(), [_finding_618()])
        output = render_html(doc)
        self.assertIn("lab:8080", output)


if __name__ == "__main__":
    unittest.main()
