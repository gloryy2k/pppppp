"""Assessor tests: status ladders, negative cases and per-CVE separation."""

from __future__ import annotations

import unittest

from p2s.assess import assess_618, assess_619, assess_all
from p2s.patch import assess_patch
from p2s.version import CVE_618, CVE_619

try:
    from tests.helpers import (
        canary_evidence,
        http_evidence,
        make_case,
        make_profile,
        make_run,
        strong_619_correlation,
        telemetry_evidence,
        ts,
        two_worker_619_correlation,
    )
except ImportError:  # pragma: no cover
    from helpers import (
        canary_evidence,
        http_evidence,
        make_case,
        make_profile,
        make_run,
        strong_619_correlation,
        telemetry_evidence,
        ts,
        two_worker_619_correlation,
    )


OOM_SCRIPT = (
    "PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted "
    "(tried to allocate 4096 bytes) in /var/www/html/app.php on line 42"
)
OOM_STARTUP = (
    "PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted "
    "(tried to allocate 4096 bytes) in Unknown on line 0"
)


class BuildExposureTests(unittest.TestCase):
    def test_high_trust_affected_build_is_exposed_not_proven(self) -> None:
        profile = make_profile(version="8.2.12", version_trust="high")
        case = make_case(profile, [], [], synthetic=True)
        finding = assess_618(case)
        self.assertEqual(finding.status, "EXPOSED_BUILD")
        self.assertEqual(finding.cve, CVE_618)
        self.assertTrue(finding.missing_evidence)
        self.assertEqual(assess_619(case).status, "EXPOSED_BUILD")

    def test_low_trust_banner_is_inconclusive(self) -> None:
        profile = make_profile(
            version="8.2.12",
            version_trust="low",
            version_source="x-powered-by",
            sapi="unknown",
            sapi_verified=False,
            reach="PROBABLE",
        )
        case = make_case(profile, [], [], synthetic=True)
        self.assertEqual(assess_618(case).status, "INCONCLUSIVE")
        self.assertEqual(assess_619(case).status, "INCONCLUSIVE")

    def test_hidden_banner_is_inconclusive(self) -> None:
        profile = make_profile(
            version=None,
            version_trust="none",
            version_source="none",
            sapi="unknown",
            sapi_verified=False,
            reach="PROBABLE",
        )
        case = make_case(profile, [], [], synthetic=True)
        self.assertEqual(assess_618(case).status, "INCONCLUSIVE")
        self.assertEqual(assess_619(case).status, "INCONCLUSIVE")

    def test_patched_high_trust_build_is_patch_confirmed(self) -> None:
        profile = make_profile(version="8.2.35", version_trust="high")
        case = make_case(profile, [], [], synthetic=True)
        for finding in assess_all(case):
            self.assertEqual(finding.status, "PATCH_CONFIRMED")
            self.assertEqual(finding.patch_evidence["state"], "PATCHED")

    def test_low_trust_patched_banner_is_not_patch_confirmed(self) -> None:
        # A banner claiming a fixed version is still only a banner: no SAPI
        # identity and no build evidence, so nothing can be confirmed.
        profile = make_profile(
            version="8.4.27",
            version_trust="low",
            version_source="x-powered-by",
            sapi="unknown",
            sapi_verified=False,
            reach="PROBABLE",
        )
        case = make_case(profile, [], [], synthetic=True)
        for finding in assess_all(case):
            self.assertEqual(finding.status, "INCONCLUSIVE")
            self.assertNotEqual(finding.status, "PATCH_CONFIRMED")
            self.assertEqual(finding.patch_evidence["per_cve"][finding.cve]["trust"], "low")

    def test_backport_for_one_cve_keeps_verdicts_separate(self) -> None:
        patch = assess_patch(
            "8.2.29-1+deb12u6",
            source="package-manifest",
            trust="high",
            backports=[
                {
                    "cve": CVE_618,
                    "source": "debian",
                    "reference": "DSA-2026-0001",
                    "status": "fixed",
                }
            ],
        )
        profile = make_profile(
            version="8.2.29-1+deb12u6",
            version_trust="high",
            version_source="package-manifest",
            patch=patch,
            packaging="deb",
        )
        case = make_case(profile, [], [], synthetic=True)
        finding_618 = assess_618(case)
        finding_619 = assess_619(case)
        self.assertEqual(finding_618.status, "PATCH_CONFIRMED")
        self.assertEqual(finding_619.status, "PREREQUISITE_OBSERVED")
        self.assertNotEqual(finding_619.status, "PATCH_CONFIRMED")
        self.assertEqual(
            finding_619.patch_evidence["per_cve"][CVE_619]["state"], "UNKNOWN"
        )
        self.assertTrue(
            any(CVE_619 in item for item in finding_619.missing_evidence)
        )


class Cve618OomTests(unittest.TestCase):
    def _oom_case(
        self,
        *,
        sapi: str = "mod_php",
        phase: str = "post_startup",
        trace: bool = True,
        control: bool = True,
        oom_request_id: str | None = "req-producer",
        oom_worker_id: str | None = "123",
        oom_timestamp: str | None = None,
        synthetic: bool = False,
        kind: str = "lab",
        http_oom_body: str | None = None,
    ):
        profile = make_profile(version="8.2.12", version_trust="high", sapi=sapi)
        producer = http_evidence(
            "EV-0001",
            request_id="req-producer",
            method="POST",
            status=500 if http_oom_body else 0,
            body=http_oom_body or "",
            error_kind=None if http_oom_body else "reset",
            sent_at=ts(0),
            received_at=ts(2),
            scenario_id="618-S2",
            synthetic=synthetic,
        )
        evidence = [producer]
        run = make_run(
            "618-S2",
            CVE_618,
            producer_request_id="req-producer",
            producer_worker_id=oom_worker_id,
            request_refs=["EV-0001"],
            started_at=ts(0),
            finished_at=ts(2),
        )
        if control:
            control_evidence = http_evidence(
                "EV-0002",
                request_id="req-control",
                status=200,
                body="ok",
                sent_at=ts(-1),
                received_at=ts(-0.5),
                scenario_id="618-S2",
                synthetic=synthetic,
            )
            evidence.append(control_evidence)
            run.control_refs.append("EV-0002")
        oom = telemetry_evidence(
            "EV-0003",
            "oom",
            request_id=oom_request_id,
            worker_id=oom_worker_id,
            message=OOM_STARTUP if phase in ("startup", "startup_like") else OOM_SCRIPT,
            timestamp=oom_timestamp or ts(1),
            phase=phase,
            source="php_log",
            scenario_id="618-S2",
            synthetic=synthetic,
        )
        evidence.append(oom)
        run.telemetry_refs.append("EV-0003")
        run.oom_refs.append("EV-0003")
        if trace:
            for index, event_type in enumerate(
                ("patched_baseline", "longjmp_from_oom", "invalid_state_processed"),
                start=4,
            ):
                item = telemetry_evidence(
                    f"EV-{index:04d}",
                    event_type,
                    request_id="req-producer",
                    worker_id=oom_worker_id,
                    timestamp=ts(1.1 + index * 0.01),
                    source="lab_trace",
                    scenario_id="618-S2",
                    synthetic=synthetic,
                )
                evidence.append(item)
                run.telemetry_refs.append(item.id)
                run.trace_refs.append(item.id)
        return make_case(
            profile,
            evidence,
            [run],
            synthetic=synthetic,
            kind=kind,
        )

    def test_oom_telemetry_alone_is_oom_observed(self) -> None:
        finding = assess_618(self._oom_case(trace=False))
        self.assertEqual(finding.status, "OOM_OBSERVED")
        self.assertNotEqual(finding.status, "AFFECTED_PATH_CONFIRMED")
        self.assertTrue(any("invalid-state" in item for item in finding.missing_evidence))

    def test_http_oom_text_alone_is_oom_observed(self) -> None:
        finding = assess_618(self._oom_case(trace=False, http_oom_body=OOM_SCRIPT))
        self.assertEqual(finding.status, "OOM_OBSERVED")
        self.assertNotEqual(finding.status, "AFFECTED_PATH_CONFIRMED")

    def test_oom_with_trace_and_control_can_confirm_path(self) -> None:
        finding = assess_618(self._oom_case(trace=True, control=True))
        self.assertEqual(finding.status, "AFFECTED_PATH_CONFIRMED")
        self.assertEqual(finding.validate(), [])

    def test_time_window_only_cannot_confirm_path(self) -> None:
        finding = assess_618(
            self._oom_case(
                trace=True,
                control=True,
                oom_request_id=None,
                oom_worker_id=None,
                oom_timestamp=ts(1),
            )
        )
        self.assertEqual(finding.status, "OOM_OBSERVED")
        self.assertNotEqual(finding.status, "AFFECTED_PATH_CONFIRMED")

    def test_fpm_startup_oom_is_not_the_mod_php_path(self) -> None:
        finding = assess_618(
            self._oom_case(trace=True, control=True, sapi="fpm", phase="startup_like")
        )
        self.assertEqual(finding.status, "OOM_OBSERVED")
        self.assertNotEqual(finding.status, "AFFECTED_PATH_CONFIRMED")

    def test_cli_server_is_not_evaluated_by_the_advisory(self) -> None:
        finding = assess_618(
            self._oom_case(trace=True, control=True, sapi="cli-server", phase="post_startup")
        )
        self.assertEqual(finding.status, "OOM_OBSERVED")
        self.assertNotEqual(finding.status, "AFFECTED_PATH_CONFIRMED")

    def test_fixture_cannot_confirm_affected_path(self) -> None:
        finding = assess_618(
            self._oom_case(trace=True, control=True, synthetic=True, kind="fixture")
        )
        self.assertEqual(finding.status, "OOM_OBSERVED")
        self.assertNotEqual(finding.status, "AFFECTED_PATH_CONFIRMED")

    def test_proxy_502_is_not_oom(self) -> None:
        profile = make_profile(version="8.2.12", version_trust="high")
        item = http_evidence(
            "EV-0001",
            request_id="req-1",
            status=502,
            body="bad gateway",
            headers={"Via": "1.1 proxy"},
            scenario_id="618-S2",
            synthetic=True,
        )
        run = make_run("618-S2", CVE_618, request_refs=["EV-0001"])
        finding = assess_618(make_case(profile, [item], [run], synthetic=True))
        self.assertNotIn(finding.status, ("OOM_OBSERVED", "AFFECTED_PATH_CONFIRMED"))

    def test_waf_413_is_not_oom(self) -> None:
        profile = make_profile(version="8.2.12", version_trust="high")
        item = http_evidence(
            "EV-0001",
            request_id="req-1",
            method="POST",
            status=413,
            body="too large",
            scenario_id="618-S2",
            synthetic=True,
        )
        run = make_run("618-S2", CVE_618, request_refs=["EV-0001"])
        finding = assess_618(make_case(profile, [item], [run], synthetic=True))
        self.assertNotIn(finding.status, ("OOM_OBSERVED", "AFFECTED_PATH_CONFIRMED"))

    def test_display_errors_warning_is_not_oom(self) -> None:
        profile = make_profile(version="8.2.12", version_trust="high")
        item = http_evidence(
            "EV-0001",
            request_id="req-1",
            status=200,
            body="PHP Warning:  Undefined array key 1 in /app/a.php on line 3",
            scenario_id="618-S2",
            synthetic=True,
        )
        run = make_run("618-S2", CVE_618, request_refs=["EV-0001"])
        finding = assess_618(make_case(profile, [item], [run], synthetic=True))
        self.assertNotIn(finding.status, ("OOM_OBSERVED", "AFFECTED_PATH_CONFIRMED"))
        self.assertTrue(any(o["kind"] == "display_errors_visible" for o in finding.observations))


class CanaryTests(unittest.TestCase):
    def _canary_case(self, **overrides: object):
        profile = make_profile(version="8.2.12", version_trust="high", sapi="mod_php")
        canary = canary_evidence(
            "EV-0001",
            verified=bool(overrides.get("verified", True)),
            reflected=bool(overrides.get("reflected", False)),
            telemetry_worker_match=bool(overrides.get("telemetry_worker_match", True)),
            before_present=bool(overrides.get("before_present", False)),
            after_present=bool(overrides.get("after_present", True)),
            request_id="req-1",
            worker_id="123",
            scenario_id="618-S2",
            synthetic=bool(overrides.get("evidence_synthetic", False)),
        )
        run = make_run(
            "618-S2",
            CVE_618,
            producer_request_id="req-1",
            producer_worker_id="123",
            canary_refs=["EV-0001"],
            canary={"verified": bool(overrides.get("run_verified", True))},
        )
        return make_case(
            profile,
            [canary],
            [run],
            synthetic=bool(overrides.get("case_synthetic", False)),
            kind="fixture" if overrides.get("case_synthetic", False) else "lab",
        )

    def test_verified_canary_can_confirm_code_execution(self) -> None:
        finding = assess_618(self._canary_case())
        self.assertEqual(finding.status, "CODE_EXECUTION_CONFIRMED")
        self.assertEqual(finding.validate(), [])

    def test_reflected_nonce_invalidates_canary(self) -> None:
        finding = assess_618(self._canary_case(reflected=True))
        self.assertNotEqual(finding.status, "CODE_EXECUTION_CONFIRMED")

    def test_canary_without_worker_binding_is_not_code_execution(self) -> None:
        finding = assess_618(self._canary_case(telemetry_worker_match=False))
        self.assertNotEqual(finding.status, "CODE_EXECUTION_CONFIRMED")

    def test_canary_already_present_before_is_invalid(self) -> None:
        finding = assess_618(self._canary_case(before_present=True))
        self.assertNotEqual(finding.status, "CODE_EXECUTION_CONFIRMED")

    def test_canary_absent_after_is_invalid(self) -> None:
        finding = assess_618(self._canary_case(after_present=False))
        self.assertNotEqual(finding.status, "CODE_EXECUTION_CONFIRMED")

    def test_synthetic_case_cannot_claim_code_execution(self) -> None:
        finding = assess_618(self._canary_case(case_synthetic=True))
        self.assertNotEqual(finding.status, "CODE_EXECUTION_CONFIRMED")


class Cve619CorrelationTests(unittest.TestCase):
    def _correlated_case(
        self,
        *,
        correlation=None,
        trace: bool = False,
        synthetic: bool = True,
        kind: str = "fixture",
        trace_synthetic: bool = True,
    ):
        profile = make_profile(version="8.2.12", version_trust="high", sapi="mod_php")
        producer = http_evidence(
            "EV-0001",
            request_id="req-producer",
            method="POST",
            status=500,
            body=OOM_STARTUP,
            sent_at=ts(0),
            received_at=ts(1),
            scenario_id="619-S2",
            synthetic=synthetic,
        )
        consumer = http_evidence(
            "EV-0002",
            request_id="req-consumer",
            method="POST",
            status=200,
            body="ok",
            sent_at=ts(1.1),
            received_at=ts(1.6),
            scenario_id="619-S2",
            synthetic=synthetic,
        )
        publish = telemetry_evidence(
            "EV-0003",
            "state_publish",
            request_id="req-producer",
            worker_id="123",
            timestamp=ts(0.5),
            source="lab_trace",
            scenario_id="619-S2",
            synthetic=synthetic,
        )
        consume = telemetry_evidence(
            "EV-0004",
            "upload_progress_consumer",
            request_id="req-consumer",
            worker_id="123",
            timestamp=ts(1.2),
            source="lab_trace",
            scenario_id="619-S2",
            synthetic=synthetic,
        )
        evidence = [producer, consumer, publish, consume]
        run = make_run(
            "619-S2",
            CVE_619,
            producer_request_id="req-producer",
            consumer_request_id="req-consumer",
            producer_worker_id="123",
            consumer_worker_id="123",
            request_refs=["EV-0001", "EV-0002"],
            telemetry_refs=["EV-0003", "EV-0004"],
            state_publish_refs=["EV-0003"],
            state_consume_refs=["EV-0004"],
            correlation=correlation or strong_619_correlation(),
            started_at=ts(0),
            finished_at=ts(2),
        )
        if trace:
            for index, event_type in enumerate(
                ("patched_baseline", "stale_global_consumed", "address_reuse"),
                start=5,
            ):
                item = telemetry_evidence(
                    f"EV-{index:04d}",
                    event_type,
                    request_id="req-consumer",
                    worker_id="123",
                    timestamp=ts(1.3 + index * 0.01),
                    source="lab_trace",
                    scenario_id="619-S2",
                    synthetic=trace_synthetic,
                )
                evidence.append(item)
                run.telemetry_refs.append(item.id)
                run.trace_refs.append(item.id)
        return make_case(profile, evidence, [run], synthetic=synthetic, kind=kind)

    def test_same_worker_correlation_is_not_stale_state(self) -> None:
        finding = assess_619(self._correlated_case())
        self.assertEqual(finding.status, "PRODUCER_CONSUMER_CORRELATED")
        self.assertNotEqual(finding.status, "STALE_STATE_CONFIRMED")
        self.assertTrue(
            any("pointer/address identity" in item for item in finding.missing_evidence)
        )

    def test_different_workers_are_not_correlated(self) -> None:
        finding = assess_619(
            self._correlated_case(correlation=two_worker_619_correlation())
        )
        self.assertNotEqual(finding.status, "PRODUCER_CONSUMER_CORRELATED")
        self.assertEqual(finding.status, "PRODUCER_OBSERVED")
        self.assertTrue(any("same worker" in item.lower() for item in finding.missing_evidence))

    def test_worker_recycle_blocks_correlation(self) -> None:
        correlation = strong_619_correlation()
        correlation["worker_recycled_between"] = True
        finding = assess_619(self._correlated_case(correlation=correlation))
        self.assertNotEqual(finding.status, "PRODUCER_CONSUMER_CORRELATED")

    def test_stale_state_requires_non_synthetic_trace(self) -> None:
        finding = assess_619(
            self._correlated_case(trace=True, synthetic=False, kind="lab", trace_synthetic=False)
        )
        self.assertEqual(finding.status, "STALE_STATE_CONFIRMED")
        self.assertEqual(finding.validate(), [])

    def test_synthetic_trace_cannot_confirm_stale_state(self) -> None:
        finding = assess_619(self._correlated_case(trace=True, synthetic=True, trace_synthetic=True))
        self.assertEqual(finding.status, "PRODUCER_CONSUMER_CORRELATED")
        self.assertNotEqual(finding.status, "STALE_STATE_CONFIRMED")

    def test_fixture_cannot_confirm_stale_state_even_with_lab_trace(self) -> None:
        finding = assess_619(
            self._correlated_case(trace=True, synthetic=True, kind="fixture", trace_synthetic=False)
        )
        self.assertEqual(finding.status, "PRODUCER_CONSUMER_CORRELATED")
        self.assertNotEqual(finding.status, "STALE_STATE_CONFIRMED")

    def test_bare_producer_oom_is_not_state_publication(self) -> None:
        profile = make_profile(version="8.2.12", version_trust="high", sapi="mod_php")
        producer = http_evidence(
            "EV-0001",
            request_id="req-producer",
            method="POST",
            status=500,
            body=OOM_STARTUP,
            scenario_id="619-S2",
            synthetic=True,
        )
        oom = telemetry_evidence(
            "EV-0002",
            "oom",
            request_id="req-producer",
            worker_id="123",
            phase="startup_like",
            source="php_log",
            scenario_id="619-S2",
            synthetic=True,
        )
        run = make_run(
            "619-S2",
            CVE_619,
            producer_request_id="req-producer",
            request_refs=["EV-0001"],
            telemetry_refs=["EV-0002"],
            oom_refs=["EV-0002"],
        )
        finding = assess_619(make_case(profile, [producer, oom], [run], synthetic=True))
        self.assertNotIn(
            finding.status,
            ("PRODUCER_CONSUMER_CORRELATED", "STALE_STATE_CONFIRMED"),
        )

    def test_patch_confirmed_from_build_evidence(self) -> None:
        profile = make_profile(version="8.2.35", version_trust="high")
        finding = assess_619(make_case(profile, [], [], synthetic=True))
        self.assertEqual(finding.status, "PATCH_CONFIRMED")

    def test_619_canary_positive(self) -> None:
        profile = make_profile(version="8.2.12", version_trust="high", sapi="mod_php")
        canary = canary_evidence(
            "EV-0001",
            verified=True,
            request_id="req-1",
            worker_id="123",
            scenario_id="619-S2",
            synthetic=False,
        )
        run = make_run(
            "619-S2",
            CVE_619,
            producer_request_id="req-1",
            producer_worker_id="123",
            canary_refs=["EV-0001"],
            canary={"verified": True},
        )
        finding = assess_619(make_case(profile, [canary], [run], synthetic=False, kind="lab"))
        self.assertEqual(finding.status, "CODE_EXECUTION_CONFIRMED")
        self.assertEqual(finding.validate(), [])

    def test_619_reflected_canary_is_not_code_execution(self) -> None:
        profile = make_profile(version="8.2.12", version_trust="high", sapi="mod_php")
        canary = canary_evidence(
            "EV-0001",
            verified=True,
            reflected=True,
            request_id="req-1",
            worker_id="123",
            scenario_id="619-S2",
            synthetic=False,
        )
        run = make_run(
            "619-S2",
            CVE_619,
            producer_request_id="req-1",
            producer_worker_id="123",
            canary_refs=["EV-0001"],
            canary={"verified": True},
        )
        finding = assess_619(make_case(profile, [canary], [run], synthetic=False, kind="lab"))
        self.assertNotEqual(finding.status, "CODE_EXECUTION_CONFIRMED")


if __name__ == "__main__":
    unittest.main()
