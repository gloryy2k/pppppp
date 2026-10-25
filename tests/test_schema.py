"""Schema, finding-contract and evidence-integrity tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from p2s.cli import _merge_runs
from p2s.evidence import RunStore
from p2s.inventory import InventoryOptions, collect
from p2s.probe import run_probe
from p2s.prove import _health
from p2s.report import build_document
from p2s.models import (
    CaseFile,
    Evidence,
    Finding,
    PatchAssessment,
    ScenarioRun,
    TargetProfile,
)
from p2s.util import canonical_json, sha256_bytes
from p2s.version import CVE_618, CVE_619

try:
    from tests.helpers import (
        make_case,
        make_exchange,
        make_profile,
        make_run,
        telemetry_evidence,
        ts,
    )
except ImportError:  # pragma: no cover
    from helpers import (  # type: ignore[no-redef]
        make_case,
        make_exchange,
        make_profile,
        make_run,
        telemetry_evidence,
        ts,
    )


def _evidence(evidence_id: str = "EV-0001", data: dict | None = None) -> Evidence:
    payload = data or {"message": "hello"}
    return Evidence(
        id=evidence_id,
        source="operator",
        timestamp=ts(),
        data=payload,
        sha256=sha256_bytes(canonical_json(payload)),
    )


def _finding(**overrides: object) -> Finding:
    values = {
        "cve": CVE_618,
        "status": "INCONCLUSIVE",
        "scenario_id": "inventory",
        "evidence_refs": [],
        "proof_method": "none",
        "proof_limitations": ["test"],
        "alternative_explanations": ["test"],
        "missing_evidence": ["test"],
        "patch_evidence": {"state": "UNKNOWN", "trust": "none"},
        "remediation": ["upgrade"],
        "reproduction_context": {},
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


class EvidenceSchemaTests(unittest.TestCase):
    def test_valid_evidence(self) -> None:
        self.assertEqual(_evidence().validate(), [])

    def test_invalid_source(self) -> None:
        item = _evidence()
        item.source = "made-up"
        self.assertTrue(any("invalid source" in error for error in item.validate()))

    def test_invalid_timestamp(self) -> None:
        item = _evidence()
        item.timestamp = "yesterday"
        self.assertTrue(any("invalid timestamp" in error for error in item.validate()))

    def test_invalid_hash(self) -> None:
        item = _evidence()
        item.sha256 = "abc"
        self.assertTrue(any("invalid sha256" in error for error in item.validate()))

    def test_invalid_trust(self) -> None:
        item = _evidence()
        item.trust = "certain"
        self.assertTrue(any("invalid trust" in error for error in item.validate()))

    def test_data_must_be_object(self) -> None:
        item = _evidence()
        item.data = ["not", "an", "object"]  # type: ignore[assignment]
        self.assertTrue(any("data must be an object" in error for error in item.validate()))

    def test_hash_recomputation(self) -> None:
        item = _evidence(data={"a": 1, "b": [2, 3]})
        self.assertEqual(item.recompute_sha256(), item.sha256)

    def test_round_trip(self) -> None:
        item = _evidence()
        again = Evidence.from_dict(item.to_dict())
        self.assertEqual(again.to_dict(), item.to_dict())


class FindingSchemaTests(unittest.TestCase):
    def test_minimal_valid_finding(self) -> None:
        self.assertEqual(_finding().validate(), [])

    def test_invalid_status_for_cve(self) -> None:
        finding = _finding(status="STALE_STATE_CONFIRMED")
        self.assertTrue(any("invalid status" in error for error in finding.validate()))

    def test_invalid_cve(self) -> None:
        finding = _finding(cve="CVE-0000-0000")
        self.assertTrue(any("invalid cve" in error for error in finding.validate()))

    def test_proof_status_needs_evidence(self) -> None:
        finding = _finding(status="AFFECTED_PATH_CONFIRMED")
        self.assertTrue(any("without evidence_refs" in error for error in finding.validate()))

    def test_code_execution_needs_canary(self) -> None:
        finding = _finding(
            status="CODE_EXECUTION_CONFIRMED",
            evidence_refs=["EV-0001"],
            reproduction_context={},
        )
        self.assertTrue(any("canary_verified" in error for error in finding.validate()))

    def test_code_execution_with_canary_passes(self) -> None:
        finding = _finding(
            status="CODE_EXECUTION_CONFIRMED",
            evidence_refs=["EV-0001"],
            reproduction_context={"canary_verified": True},
        )
        self.assertEqual(finding.validate(), [])

    def test_patch_confirmed_needs_patched_build_evidence(self) -> None:
        finding = _finding(
            status="PATCH_CONFIRMED",
            evidence_refs=["EV-0001"],
            patch_evidence={"state": "UNKNOWN", "trust": "low"},
        )
        self.assertTrue(any("without patched build evidence" in error for error in finding.validate()))

    def test_patch_confirmed_with_per_cve_evidence_passes(self) -> None:
        finding = _finding(
            status="PATCH_CONFIRMED",
            evidence_refs=["EV-0001"],
            patch_evidence={
                "state": "UNKNOWN",
                "trust": "high",
                "per_cve": {CVE_618: {"state": "PATCHED", "trust": "high"}},
            },
        )
        self.assertEqual(finding.validate(), [])

    def test_required_fields_are_present_in_dict(self) -> None:
        payload = _finding().to_dict()
        for key in (
            "cve",
            "status",
            "scenario_id",
            "evidence_refs",
            "proof_method",
            "proof_limitations",
            "alternative_explanations",
            "missing_evidence",
            "patch_evidence",
            "remediation",
            "reproduction_context",
        ):
            self.assertIn(key, payload)

    def test_round_trip(self) -> None:
        finding = _finding(status="OOM_OBSERVED", evidence_refs=["EV-0001"])
        again = Finding.from_dict(finding.to_dict())
        self.assertEqual(again.to_dict(), finding.to_dict())


class CaseSchemaTests(unittest.TestCase):
    def test_duplicate_evidence_id_is_rejected(self) -> None:
        profile = make_profile()
        case = make_case(profile, [_evidence("EV-0001"), _evidence("EV-0001")])
        self.assertTrue(any("duplicate evidence id" in error for error in case.validate()))

    def test_dangling_scenario_ref_is_rejected(self) -> None:
        profile = make_profile()
        run = make_run(request_refs=["EV-9999"])
        case = make_case(profile, [_evidence("EV-0001")], [run])
        self.assertTrue(any("dangling evidence ref" in error for error in case.validate()))

    def test_patch_assessment_round_trip_keeps_per_cve(self) -> None:
        patch = PatchAssessment(
            state="UNKNOWN",
            trust="high",
            per_cve={CVE_618: {"state": "PATCHED", "trust": "high"}},
        )
        again = PatchAssessment.from_dict(patch.to_dict())
        self.assertEqual(again.per_cve[CVE_618]["state"], "PATCHED")


class ReportDocumentTests(unittest.TestCase):
    def test_artifact_rows_keep_scenario_id(self) -> None:
        profile = make_profile()
        item = _evidence()
        item.scenario_id = "619-S2"
        case = make_case(profile, [item], [])
        doc = build_document(case, [], [])
        self.assertEqual(doc["proof"]["artifacts"][0]["scenario_id"], "619-S2")
        self.assertEqual(doc["integrity"]["evidence_count"], 1)
        self.assertTrue(doc["integrity"]["verified"])

    def test_patched_baseline_is_detected_from_trace(self) -> None:
        profile = make_profile()
        trace = telemetry_evidence("EV-0001", "patched_baseline", synthetic=True)
        run = make_run("618-S2", CVE_618, trace_refs=[trace.id])
        case = make_case(profile, [trace], [run])
        doc = build_document(case, [], [])
        self.assertTrue(
            doc["answers"]["patched_vs_unpatched_control"]["patched_baseline_observed"]
        )


class RunMergeTests(unittest.TestCase):
    def test_skipped_duplicate_does_not_replace_executed_run(self) -> None:
        old = make_run("618-S2", CVE_618, executed=True)
        skipped = make_run("618-S2", CVE_618, executed=False)
        merged = _merge_runs([old], [skipped])
        self.assertEqual(len(merged), 1)
        self.assertTrue(merged[0].executed)
        self.assertEqual(merged[0].started_at, old.started_at)

    def test_explicit_rerun_replaces_case_view(self) -> None:
        old = make_run("618-S2", CVE_618, executed=True, started_at=ts())
        new = make_run("618-S2", CVE_618, executed=True, started_at=ts(30))
        merged = _merge_runs([old], [new])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].started_at, new.started_at)


class EvidenceStoreTests(unittest.TestCase):
    def test_write_read_verify(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            store = RunStore(root, "run-1", "http://lab.invalid/", "prove", "4.0.0")
            item = store.add("operator", {"message": "hello"}, scenario_id="test")
            self.assertTrue(item.id.startswith("EV-"))
            errors = store.verify()
            self.assertEqual(errors, [])
            loaded = store.load_evidence()
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].data["message"], "hello")

    def test_tampered_artifact_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            store = RunStore(root, "run-1", "http://lab.invalid/", "prove", "4.0.0")
            item = store.add("operator", {"message": "hello"})
            path = os.path.join(root, item.artifact_path.replace("/", os.sep))
            with open(path, "wb") as handle:
                handle.write(b'{"message":"tampered"}')
            self.assertTrue(
                any("artifact hash mismatch" in error for error in store.verify())
            )

    def test_tampered_inline_data_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            store = RunStore(root, "run-1", "http://lab.invalid/", "prove", "4.0.0")
            store.add("operator", {"message": "hello"})
            with open(store.evidence_path, "r", encoding="utf-8") as handle:
                payload = json.loads(handle.readline())
            payload["data"]["message"] = "tampered"
            with open(store.evidence_path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, sort_keys=True) + "\n")
            self.assertTrue(
                any("inline data hash mismatch" in error for error in store.verify())
            )

    def test_reopening_a_run_does_not_duplicate_ids(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            first = RunStore(root, "run-1", "http://lab.invalid/", "inventory", "4.0.0")
            one = first.add("operator", {"message": "one"})
            second = RunStore(root, "run-1", "http://lab.invalid/", "probe", "4.0.0")
            two = second.add("operator", {"message": "two"})
            self.assertEqual(one.id, "EV-0001")
            self.assertEqual(two.id, "EV-0002")
            self.assertEqual(second.verify(), [])
            self.assertEqual(len(second.load_evidence()), 2)

    def test_case_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            store = RunStore(root, "run-1", "http://lab.invalid/", "prove", "4.0.0")
            item = store.add("operator", {"message": "hello"})
            profile = make_profile()
            run = make_run(request_refs=[item.id])
            case = make_case(profile, store.load_evidence(), [run])
            store.write_case(case)
            again = store.read_case()
            self.assertEqual(again.run_id, case.run_id)
            self.assertEqual(again.profile.php_version, profile.php_version)
            self.assertEqual(len(again.scenario_runs), 1)


class SyntheticPropagationTests(unittest.TestCase):
    """--synthetic-fixture must label every stored evidence item, not only telemetry."""

    class _StubClient:
        def __init__(self) -> None:
            self.calls = 0

        def request(self, *args: object, **kwargs: object):
            self.calls += 1
            return make_exchange(
                request_id=f"req-{self.calls}",
                url="http://lab.invalid/",
            )

    def test_inventory_evidence_inherits_synthetic_flag(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            store = RunStore(root, "run-1", "http://lab.invalid/", "inventory", "4.0.0")
            options = InventoryOptions(environment_kind="fixture", synthetic=True)
            collect("http://lab.invalid/", self._StubClient(), options, store=store)
            self.assertTrue(store._evidence)
            self.assertTrue(all(item.synthetic for item in store._evidence))

    def test_inventory_evidence_is_not_synthetic_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            store = RunStore(root, "run-1", "http://lab.invalid/", "inventory", "4.0.0")
            options = InventoryOptions(environment_kind="lab")
            collect("http://lab.invalid/", self._StubClient(), options, store=store)
            self.assertTrue(store._evidence)
            self.assertFalse(any(item.synthetic for item in store._evidence))

    def test_probe_evidence_inherits_synthetic_flag(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            store = RunStore(root, "run-1", "http://lab.invalid/", "probe", "4.0.0")
            profile = make_profile(environment_kind="fixture")
            run_probe(self._StubClient(), profile, store, synthetic=True)
            self.assertTrue(store._evidence)
            self.assertTrue(all(item.synthetic for item in store._evidence))

    def test_health_evidence_inherits_synthetic_flag(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            store = RunStore(root, "run-1", "http://lab.invalid/", "prove", "4.0.0")
            result = _health(
                self._StubClient(),
                "http://lab.invalid/",
                store,
                "prove",
                5.0,
                synthetic=True,
            )
            self.assertTrue(result["ok"])
            self.assertTrue(store._evidence[0].synthetic)


if __name__ == "__main__":
    unittest.main()
