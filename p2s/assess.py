"""CVE assessors.

Two independent pipelines.  Each assessor receives a CaseFile (profile,
evidence, scenario runs) and returns one Finding.  It never reads a "best
confidence" from another check and never promotes a status without naming the
evidence that justifies it.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .inventory import patch_evidence
from .models import (
    ST_AFFECTED_PATH_CONFIRMED,
    ST_CODE_EXECUTION_CONFIRMED,
    ST_EXPOSED_BUILD,
    ST_INCONCLUSIVE,
    ST_NOT_TESTED,
    ST_OOM_OBSERVED,
    ST_PATCH_CONFIRMED,
    ST_PREREQUISITE_OBSERVED,
    ST_PRODUCER_CONSUMER_CORRELATED,
    ST_PRODUCER_OBSERVED,
    ST_STALE_STATE_CONFIRMED,
    CaseFile,
    Evidence,
    Finding,
    ScenarioRun,
)
from .telemetry import TelemetryEvent
from .util import dedupe, parse_iso
from .version import (
    ADVISORIES,
    CVE_618,
    CVE_619,
    REMEDIATION,
    SUSCEPTIBLE_SAPI_618,
    SUSCEPTIBLE_SAPI_619,
)

TRACE_EVENTS = {
    "longjmp_from_oom",
    "startup_failed",
    "shutdown_after_failed_startup",
    "invalid_state_processed",
    "request_memory_freed",
    "state_publish",
    "state_consume",
    "stale_global_referenced",
    "stale_global_consumed",
    "use_after_free",
    "address_reuse",
    "patched_baseline",
    "canary_write",
    "worker_recycle",
}


def _event(item: Evidence) -> Optional[TelemetryEvent]:
    payload = (item.data or {}).get("event")
    if not isinstance(payload, dict):
        return None
    return TelemetryEvent(
        source=str(payload.get("source") or item.source),
        timestamp=str(payload.get("timestamp") or item.timestamp),
        message=str(payload.get("message") or ""),
        event_type=str(payload.get("event_type") or "log"),
        severity=str(payload.get("severity") or "info"),
        request_id=payload.get("request_id") or item.request_id,
        worker_id=payload.get("worker_id") or item.worker_id,
        pid=payload.get("pid"),
        nonce=payload.get("nonce"),
        sapi=payload.get("sapi"),
        phase=payload.get("phase"),
        raw=str(payload.get("raw") or ""),
        line_no=int(payload.get("line_no") or 0),
        extra=dict(payload.get("extra") or {}),
    )


def _http_payload(item: Evidence) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    return (
        dict((item.data or {}).get("exchange") or {}),
        dict((item.data or {}).get("classification") or {}),
    )


def _items(case: CaseFile, refs: Iterable[str]) -> List[Evidence]:
    index = case.evidence_index()
    return [index[ref] for ref in dedupe(refs) if ref in index]


def _run_refs(run: ScenarioRun) -> List[str]:
    return dedupe(
        run.request_refs
        + run.control_refs
        + run.health_refs
        + run.telemetry_refs
        + run.trace_refs
        + run.canary_refs
        + run.oom_refs
        + run.state_publish_refs
        + run.state_consume_refs
    )


def _trace_types(case: CaseFile, run: ScenarioRun) -> Set[str]:
    types: Set[str] = set()
    for item in _items(case, run.trace_refs):
        event = _event(item)
        if event is None:
            continue
        if item.source == "lab_trace" or event.source == "lab_trace":
            types.add(event.event_type)
    return types


def _trace_synthetic(case: CaseFile, run: ScenarioRun) -> bool:
    items = _items(case, run.trace_refs)
    return bool(items) and all(item.synthetic for item in items)


def _oom_evidence(case: CaseFile, run: ScenarioRun) -> Dict[str, Any]:
    """Return correlated OOM evidence, not merely an HTTP 500/502."""
    result = {
        "observed": False,
        "refs": [],
        "phase": "unknown",
        "worker": None,
        "source": None,
        "telemetry": False,
        "http_text": False,
        "correlation_basis": None,
        "limitations": [],
    }
    index = case.evidence_index()
    for ref in dedupe(run.request_refs + run.oom_refs):
        item = index.get(ref)
        if item is None or item.source != "http":
            continue
        exchange, classification = _http_payload(item)
        if not classification.get("oom"):
            continue
        if classification.get("frontend_reject"):
            continue
        result["observed"] = True
        result["refs"].append(ref)
        result["http_text"] = True
        result["source"] = "http"
        result["phase"] = classification.get("oom_context") or "unknown"
        result["correlation_basis"] = "http_response"
        result["limitations"].append(
            "PHP OOM text in an HTTP body proves an allocation failed, not the CVE path; "
            "application code can also OOM."
        )

    for ref in dedupe(run.telemetry_refs + run.oom_refs):
        item = index.get(ref)
        if item is None or item.source not in ("php_log", "worker_telemetry", "lab_trace", "web_server_log"):
            continue
        event = _event(item)
        if event is None or event.event_type != "oom":
            continue
        basis = _event_correlation_basis(event, run, case)
        if basis is None:
            continue
        result["observed"] = True
        result["refs"].append(ref)
        result["telemetry"] = True
        result["source"] = item.source
        result["worker"] = event.worker_id or result["worker"]
        if result["correlation_basis"] != "request_id":
            result["correlation_basis"] = basis
        if basis == "time_window":
            result["limitations"].append(
                "The log line had no request id or worker PID; correlation is by the "
                "single in-flight request time window only."
            )
        if event.phase in ("startup", "startup_like", "post_startup", "shutdown"):
            result["phase"] = event.phase
        elif "unknown on line 0" in event.message.lower():
            result["phase"] = "startup_like"
        elif result["phase"] == "unknown":
            result["phase"] = "script"
    result["refs"] = dedupe(result["refs"])
    return result


def _event_correlates(event: TelemetryEvent, run: ScenarioRun) -> bool:
    return _event_correlation_basis(event, run, None) is not None


def _run_window(case: CaseFile, run: ScenarioRun) -> Tuple[Optional[str], Optional[str]]:
    starts: List[str] = []
    ends: List[str] = []
    index = case.evidence_index()
    for ref in run.request_refs:
        item = index.get(ref)
        if item is None or item.source != "http":
            continue
        exchange, _ = _http_payload(item)
        if exchange.get("sent_at"):
            starts.append(str(exchange["sent_at"]))
        if exchange.get("received_at"):
            ends.append(str(exchange["received_at"]))
    starts.sort()
    ends.sort()
    return (starts[0] if starts else None, ends[-1] if ends else None)


def _event_correlation_basis(
    event: TelemetryEvent, run: ScenarioRun, case: Optional[CaseFile]
) -> Optional[str]:
    if event.request_id and event.request_id in (run.producer_request_id, run.consumer_request_id):
        return "request_id"
    if event.worker_id and event.worker_id in (run.producer_worker_id, run.consumer_worker_id):
        return "worker_pid"
    # Time-window fallback is only valid when the event has no identity at all
    # and the scenario was executed sequentially.  It can support OOM_OBSERVED,
    # never AFFECTED_PATH_CONFIRMED.
    if case is not None and not event.request_id and not event.worker_id:
        start, end = _run_window(case, run)
        event_dt = parse_iso(event.timestamp)
        start_dt = parse_iso(start) if start else None
        end_dt = parse_iso(end) if end else None
        if event_dt and start_dt and end_dt:
            from datetime import timedelta

            if start_dt - timedelta(seconds=2) <= event_dt <= end_dt + timedelta(seconds=10):
                return "time_window"
    return None


def _control_stable(case: CaseFile, run: ScenarioRun) -> bool:
    index = case.evidence_index()
    for ref in run.control_refs:
        item = index.get(ref)
        if item is None:
            continue
        exchange, classification = _http_payload(item)
        if exchange.get("error_kind"):
            return False
        status = int(exchange.get("status") or 0)
        if status >= 500 or classification.get("frontend_reject"):
            return False
    return True


def _canary_verified(case: CaseFile, run: ScenarioRun) -> bool:
    if not run.canary.get("verified"):
        return False
    if case.environment.get("synthetic") or case.environment.get("kind") == "fixture":
        return False
    for item in _items(case, run.canary_refs):
        if item.source != "canary" or item.synthetic:
            continue
        assessment = (item.data or {}).get("assessment") or {}
        if (
            assessment.get("verified")
            and assessment.get("readback_verified")
            and assessment.get("telemetry_write")
            and assessment.get("telemetry_worker_match")
            and not assessment.get("reflected_in_test_responses")
            and not assessment.get("before_present")
            and assessment.get("after_present")
        ):
            return True
    return False


def assess_exploit(case: CaseFile) -> Dict[str, Any]:
    """Read out-of-band exploit callbacks from hashed evidence only.

    This deliberately does not promote either CVE ladder.  A callback proves
    that the injected payload executed; it does not prove that the OOM /
    stale-state primitive from the advisory is what executed it.  Callers use
    this for the report's exploit section and for the exit code, never to
    fabricate a ``CODE_EXECUTION_CONFIRMED`` finding.
    """
    result: Dict[str, Any] = {
        "confirmed": False,
        "chains": [],
        "evidence_refs": [],
        "command_output": None,
        "attribution": "not_established",
        "synthetic": bool(
            case.environment.get("synthetic")
            or case.environment.get("kind") == "fixture"
        ),
        "reasons": [],
        "limitations": [
            "A callback proves that the payload executed on the target. It does "
            "not prove which CVE path delivered it.",
            "The exploit result is reported separately from the two CVE "
            "ladders; the ladder statuses remain independent.",
        ],
    }
    if result["synthetic"]:
        result["reasons"].append(
            "synthetic/fixture evidence is never accepted as RCE proof"
        )
        return result

    index = case.evidence_index()
    seen: Set[str] = set()
    for run in case.scenario_runs:
        for ref in run.canary_refs:
            if ref in seen:
                continue
            item = index.get(ref)
            if item is None or item.source != "canary" or item.synthetic:
                continue
            assessment = (item.data or {}).get("assessment") or {}
            chain = str(assessment.get("exploit_chain") or "")
            if not chain or not assessment.get("verified"):
                continue
            if not assessment.get("nonce_match"):
                continue
            if not assessment.get("source_ip_match"):
                continue
            if assessment.get("uses_response_content"):
                continue
            if assessment.get("reflected_in_test_responses"):
                continue
            seen.add(ref)
            output = (item.data or {}).get("callback", {}).get("command_output")
            entry = {
                "chain": chain,
                "scenario_id": run.scenario_id,
                "cve_label": run.cve,
                "evidence_ref": ref,
                "remote_addr": assessment.get("remote_addr"),
                "command_output": output,
                "attribution": "not_established",
            }
            result["chains"].append(entry)
            result["evidence_refs"].append(ref)
            if result["command_output"] is None and output:
                result["command_output"] = output

    if result["chains"]:
        result["confirmed"] = True
        result["reasons"].append(
            "out-of-band callback with a matching nonce, an accepted source "
            "address, and no reliance on response reflection"
        )
    else:
        result["reasons"].append(
            "no accepted out-of-band exploit callback was found in the evidence"
        )
    return result


def _patch_for_cve(profile: Any, cve: str) -> Dict[str, Any]:
    per_cve = getattr(profile.patch, "per_cve", None) or {}
    item = per_cve.get(cve)
    if isinstance(item, dict) and item:
        return item
    return {
        "state": profile.patch.state,
        "trust": profile.patch.trust,
        "details": profile.patch.details,
    }


def _patch_finding_state(profile: Any, cve: str) -> str:
    item = _patch_for_cve(profile, cve)
    if item.get("state") == "PATCHED" and item.get("trust") == "high":
        return ST_PATCH_CONFIRMED
    return ""


def _exposure_build(profile: Any, cve: str) -> bool:
    item = _patch_for_cve(profile, cve)
    return (
        item.get("state") == "AFFECTED"
        and item.get("trust") in ("high", "medium")
        and bool(profile.php_version)
    )


def _build_missing(profile: Any) -> List[str]:
    missing: List[str] = []
    if not profile.php_version or profile.version_trust not in ("high", "medium"):
        missing.append(
            "verified PHP build/package inventory (X-Powered-By is low trust and "
            "cannot establish the build)"
        )
    if not profile.sapi_verified:
        missing.append("verified SAPI identity (Server/X-Powered-By headers are not SAPI evidence)")
    return missing


def _patch_missing(profile: Any, cve: str) -> List[str]:
    """Name per-CVE patch gaps; never borrow another advisory's backport."""
    item = _patch_for_cve(profile, cve)
    if item.get("state") == "PATCHED" and item.get("trust") == "high":
        return []
    if item.get("state") == "UNKNOWN":
        return [
            f"per-CVE patch/backport evidence for {cve} (the build is packaged below "
            "the upstream fixed release, so the version number alone is not enough)"
        ]
    return []


def _base_evidence(case: CaseFile, runs: List[ScenarioRun]) -> List[str]:
    refs: List[str] = []
    refs.extend(case.profile.build_metadata.get("evidence_refs") or [])
    for run in runs:
        refs.extend(_run_refs(run))
    return dedupe(refs)


def _context(case: CaseFile, runs: List[ScenarioRun], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    profile = case.profile
    payload: Dict[str, Any] = {
        "target": profile.target,
        "environment_kind": case.environment.get("kind", profile.environment_kind),
        "synthetic": bool(case.environment.get("synthetic")),
        "php_version": profile.php_version,
        "version_source": profile.version_source,
        "version_trust": profile.version_trust,
        "sapi": profile.sapi,
        "sapi_source": profile.sapi_source,
        "sapi_verified": profile.sapi_verified,
        "reach": profile.reach.to_dict(),
        "patch_state": profile.patch.state,
        "patch_trust": profile.patch.trust,
        "scenario_ids": [run.scenario_id for run in runs],
        "producer_request_ids": [run.producer_request_id for run in runs if run.producer_request_id],
        "consumer_request_ids": [run.consumer_request_id for run in runs if run.consumer_request_id],
        "worker_ids": dedupe(
            [run.producer_worker_id for run in runs if run.producer_worker_id]
            + [run.consumer_worker_id for run in runs if run.consumer_worker_id]
        ),
        "run_id": case.run_id,
        "tool_version": case.tool_version,
        "mode": case.mode,
        "limits": case.environment.get("limits"),
        "telemetry_files": case.environment.get("telemetry_files"),
        "canary": next((run.canary for run in runs if run.canary), {}),
    }
    if extra:
        payload.update(extra)
    return payload


def _observations(case: CaseFile) -> List[Dict[str, Any]]:
    observations: List[Dict[str, Any]] = []
    seen = set()

    def add(kind: str, detail: str, item: Evidence, attribution: str = "none") -> None:
        key = (kind, detail[:120])
        if key in seen:
            return
        seen.add(key)
        observations.append(
            {
                "kind": kind,
                "detail": detail[:1000],
                "attribution": attribution,
                "evidence_ref": item.id,
                "note": (
                    "Application/configuration observation. It is not proof of "
                    "CVE-2026-109618 or CVE-2026-109619."
                ),
            }
        )

    for item in case.evidence:
        if item.source != "http":
            continue
        exchange, classification = _http_payload(item)
        body = str(exchange.get("body_preview") or "")
        low = body.lower()
        if "session id is too long or contains illegal characters" in low:
            add(
                "session_upload_progress_warning",
                "Session ID/upload-progress warning visible in an HTTP response.",
                item,
            )
        if "failed to decode session object" in low or "session object destruction failed" in low:
            add(
                "session_handler_deserialization_error",
                "Session decoder/destruction diagnostic visible in an HTTP response.",
                item,
            )
        if classification.get("display_errors"):
            add(
                "display_errors_visible",
                f"PHP diagnostics are exposed to clients ({classification.get('kind')}).",
                item,
            )
        if classification.get("frontend_reject"):
            add(
                "frontend_rejected_request",
                f"Frontend/WAF rejection observed: {classification.get('detail')}.",
                item,
            )
        if classification.get("gateway_error"):
            add(
                "gateway_error_observed",
                "A gateway error was observed; cause is unknown and is not crash evidence.",
                item,
            )
    return observations


def _finding(
    cve: str,
    status: str,
    scenario_id: str,
    reason: str,
    evidence_refs: List[str],
    proof_method: str,
    limitations: List[str],
    alternatives: List[str],
    missing: List[str],
    patch: Dict[str, Any],
    context: Dict[str, Any],
    observations: Optional[List[Dict[str, Any]]] = None,
) -> Finding:
    return Finding(
        cve=cve,
        status=status,
        scenario_id=scenario_id,
        evidence_refs=dedupe(evidence_refs),
        proof_method=proof_method,
        proof_limitations=dedupe(limitations),
        alternative_explanations=dedupe(alternatives),
        missing_evidence=dedupe(missing),
        patch_evidence=patch,
        remediation=list(REMEDIATION[cve]),
        reproduction_context=context,
        status_reason=reason,
        observations=observations or [],
        advisory=ADVISORIES[cve],
    )


# ---------------------------------------------------------------------------
# CVE-2026-109618
# ---------------------------------------------------------------------------


def assess_618(case: CaseFile) -> Finding:
    profile = case.profile
    runs = [run for run in case.scenario_runs if run.cve == CVE_618 and run.executed]
    refs = _base_evidence(case, runs)
    patch = patch_evidence(profile)
    context = _context(case, runs)
    observations = _observations(case)
    scenario_id = runs[0].scenario_id if runs else "inventory"
    limitations = [
        "No negative result proves absence of the vulnerability.",
        "An HTTP 500/502/503/504, timeout, empty body or connection reset is not "
        "evidence of OOM or of CVE-2026-109618.",
        "A PHP OOM proves only that an allocation failed; it does not prove the "
        "invalid-state shutdown path.",
        "OOM observed in application code has a different root cause from the "
        "advisory's startup/parser path.",
        "A worker crash is a worker failure, not automatically this CVE.",
    ]
    alternatives = [
        "Application/extension allocation failure unrelated to the advisory.",
        "Frontend/WAF/proxy generated the error response.",
        "Generic PHP fatal error or resource exhaustion unrelated to CVE-2026-109618.",
        "PHP banner spoofed/stripped, or a distro backport changed the effective build.",
        "Higher memory_limit or a different SAPI prevented the advisory path.",
    ]

    # 1. Independently verified code execution.
    for run in runs:
        if _canary_verified(case, run):
            return _finding(
                CVE_618,
                ST_CODE_EXECUTION_CONFIRMED,
                run.scenario_id,
                "Independent canary readback with a fresh nonce, reflection excluded, "
                "and telemetry binding the effect to the scenario request/worker.",
                _run_refs(run) + [ref for ref in run.canary_refs],
                "non-destructive canary readback + telemetry request/worker binding + "
                "reflection exclusion",
                limitations
                + [
                    "Canary proves a code-execution effect in this lab harness; it does "
                    "not by itself identify which internal primitive produced it.",
                ],
                alternatives,
                [],
                patch,
                _context(case, [run], {"canary_verified": True}),
                observations,
            )

    # 2. Patch from build/package evidence.  Never from a probe or banner.
    if _patch_finding_state(profile, CVE_618) == ST_PATCH_CONFIRMED:
        return _finding(
            CVE_618,
            ST_PATCH_CONFIRMED,
            scenario_id,
            f"High-trust build/package evidence reports {profile.php_version} patched "
            f"({_patch_for_cve(profile, CVE_618).get('details')})",
            refs,
            "build/package version and backport evidence",
            limitations,
            alternatives,
            [],
            patch,
            context,
            observations,
        )

    # 3. OOM and, separately, the advisory-specific invalid-state path.
    oom_runs = []
    affected_runs = []
    for run in runs:
        oom = _oom_evidence(case, run)
        if oom["observed"]:
            oom_runs.append((run, oom))
        if oom["observed"] and _affected_path(case, run, oom):
            affected_runs.append((run, oom))

    if affected_runs:
        run, oom = affected_runs[0]
        return _finding(
            CVE_618,
            ST_AFFECTED_PATH_CONFIRMED,
            run.scenario_id,
            "Correlated PHP OOM plus lab trace of the advisory's invalid-state "
            "startup/shutdown path and a patched-baseline differential.",
            _run_refs(run),
            "lab trace: longjmp/OOM during the relevant lifecycle + invalid state "
            "processed during shutdown + patched baseline shows no such effect",
            limitations,
            alternatives
            + [
                "Trace instrumentation itself altered allocator/lifecycle timing.",
            ],
            [],
            patch,
            _context(
                case,
                [run],
                {
                    "oom_phase": oom["phase"],
                    "oom_worker": oom["worker"],
                    "patched_baseline": "patched_baseline" in _trace_types(case, run),
                },
            ),
            observations,
        )

    if oom_runs:
        run, oom = oom_runs[0]
        missing = [
            "lab trace of the advisory's invalid-state window (the OOM occurred while "
            "request memory was temporarily invalid) and of shutdown processing it",
            "same scenario against a patched build with equivalent configuration",
        ]
        if not oom["telemetry"]:
            missing.append("PHP/worker telemetry with a request or worker correlation id")
        if not profile.sapi_verified:
            missing.append("verified SAPI identity")
        return _finding(
            CVE_618,
            ST_OOM_OBSERVED,
            run.scenario_id,
            "OOM was observed in PHP and correlated to the scenario request, but the "
            "advisory-specific invalid-state path is not proven.",
            _run_refs(run),
            "HTTP PHP OOM diagnostic and/or PHP telemetry correlated to the request",
            limitations
            + [
                f"Observed OOM context: {oom['phase']}; this is not a lifecycle proof.",
            ],
            alternatives,
            missing,
            patch,
            _context(case, [run], {"oom_phase": oom["phase"], "oom_worker": oom["worker"]}),
            observations,
        )

    if _exposure_build(profile, CVE_618):
        missing = [
            "prove-mode OOM scenario execution with telemetry",
            "correlated PHP OOM observation",
            "lab trace of the startup/shutdown invalid-state path",
            "patched-baseline differential",
        ]
        return _finding(
            CVE_618,
            ST_EXPOSED_BUILD,
            scenario_id,
            f"Build/package evidence indicates an affected PHP version "
            f"({profile.php_version}); exposure only, not proof.",
            refs,
            "build/package inventory",
            limitations
            + ["EXPOSED_BUILD is an exposure assessment; no CVE path was exercised."],
            alternatives,
            missing,
            patch,
            context,
            observations,
        )

    # Prerequisite observed: verified reach + compatible SAPI, but no build/test.
    if (
        profile.reach.state == "REACHED"
        and profile.sapi_verified
        and profile.sapi in SUSCEPTIBLE_SAPI_618
    ):
        return _finding(
            CVE_618,
            ST_PREREQUISITE_OBSERVED,
            scenario_id,
            "PHP reach and a SAPI named by the advisory were verified, but no build "
            "patch evidence or OOM scenario result exists.",
            refs,
            "reachability + SAPI inventory",
            limitations,
            alternatives,
            _build_missing(profile)
            + _patch_missing(profile, CVE_618)
            + ["prove-mode scenario result with telemetry"],
            patch,
            context,
            observations,
        )

    if runs:
        missing = [
            "correlated PHP OOM evidence",
            "lab trace of the invalid-state path",
            "patched-baseline differential",
        ]
        if profile.reach.state == "BLOCKED":
            missing.insert(0, "a request path that reaches PHP (frontend blocked the probe)")
        return _finding(
            CVE_618,
            ST_INCONCLUSIVE,
            scenario_id,
            "Scenarios were attempted but no correlated OOM or advisory-path evidence "
            "was obtained.",
            refs,
            "none (inconclusive)",
            limitations,
            alternatives,
            missing,
            patch,
            context,
            observations,
        )

    if not profile.php_version and profile.reach.state in ("UNKNOWN", "BLOCKED"):
        return _finding(
            CVE_618,
            ST_NOT_TESTED,
            "inventory",
            "No verified build and no prove-mode scenario; nothing supports a CVE status.",
            refs,
            "none",
            limitations,
            alternatives,
            _build_missing(profile) + ["prove-mode scenario selection"],
            patch,
            context,
            observations,
        )

    return _finding(
        CVE_618,
        ST_INCONCLUSIVE,
        scenario_id,
        "Inventory/probe evidence is insufficient to establish either an affected "
        "build or the advisory path.",
        refs,
        "none (inconclusive)",
        limitations,
        alternatives,
        _build_missing(profile)
        + ["correlated OOM observation", "lab trace", "patched-baseline differential"],
        patch,
        context,
        observations,
    )


def _affected_path(case: CaseFile, run: ScenarioRun, oom: Dict[str, Any]) -> bool:
    profile = case.profile
    if not oom.get("observed"):
        return False
    # A fixture can demonstrate the pipeline and an OOM observation, but it
    # cannot claim that the advisory's invalid-state path was proven.
    if case.environment.get("synthetic") or case.environment.get("kind") == "fixture":
        return False
    if not profile.sapi_verified or profile.sapi not in SUSCEPTIBLE_SAPI_618:
        return False
    if not _control_stable(case, run):
        return False
    if oom.get("correlation_basis") == "time_window":
        return False
    if _trace_synthetic(case, run):
        return False
    types = _trace_types(case, run)
    if not types:
        return False
    if "patched_baseline" not in types:
        return False
    invalid_state = bool(
        types
        & {
            "invalid_state_processed",
            "request_memory_freed",
            "stale_global_referenced",
            "use_after_free",
        }
    )
    if not invalid_state:
        return False
    # FPM exits the child when request startup fails.  A startup-phase OOM is
    # therefore a child exit, not evidence that invalid state was consumed
    # during shutdown.  Do not carry the mod_php startup conclusion to FPM.
    if profile.sapi == "fpm" and oom.get("phase") in ("startup", "startup_like"):
        return False
    return True


# ---------------------------------------------------------------------------
# CVE-2026-109619
# ---------------------------------------------------------------------------


def assess_619(case: CaseFile) -> Finding:
    profile = case.profile
    runs = [run for run in case.scenario_runs if run.cve == CVE_619 and run.executed]
    refs = _base_evidence(case, runs)
    patch = patch_evidence(profile)
    context = _context(case, runs)
    observations = _observations(case)
    scenario_id = runs[0].scenario_id if runs else "inventory"
    limitations = [
        "HTTP keep-alive does not identify a PHP-FPM worker; same-worker proof needs "
        "a worker PID or equivalent telemetry.",
        "A single OOM is not proof of stale global state.",
        "A consumer reading state is not proof that the state belonged to a freed request.",
        "An HTTP 500/502/503/504, timeout or empty body is not producer/consumer evidence.",
        "No negative result proves absence of the vulnerability.",
    ]
    alternatives = [
        "Producer and consumer were handled by different workers.",
        "The consumer performed normal initialisation rather than reading stale state.",
        "The producer OOM/fatal did not publish request-owned global state.",
        "A worker was recycled between requests (same PID may be a new process).",
        "Application/session logic produced the diagnostic independently of stale state.",
        "A reflected marker or static response was mistaken for a canary effect.",
    ]

    for run in runs:
        if _canary_verified(case, run):
            return _finding(
                CVE_619,
                ST_CODE_EXECUTION_CONFIRMED,
                run.scenario_id,
                "Independent canary effect verified with reflection excluded and "
                "telemetry binding it to the correlated request/worker.",
                _run_refs(run),
                "non-destructive canary + same-worker correlation + reflection exclusion",
                limitations,
                alternatives,
                [],
                patch,
                _context(case, [run], {"canary_verified": True}),
                observations,
            )

    if _patch_finding_state(profile, CVE_619) == ST_PATCH_CONFIRMED:
        return _finding(
            CVE_619,
            ST_PATCH_CONFIRMED,
            scenario_id,
            f"High-trust build/package evidence reports {profile.php_version} patched "
            f"({_patch_for_cve(profile, CVE_619).get('details')})",
            refs,
            "build/package version and backport evidence",
            limitations,
            alternatives,
            [],
            patch,
            context,
            observations,
        )

    producer_runs = []
    correlated_runs = []
    stale_runs = []
    for run in runs:
        corr = dict(run.correlation or {})
        if corr.get("state_published") or run.state_publish_refs:
            producer_runs.append(run)
        if (
            corr.get("same_worker")
            and corr.get("producer_ended_before_consumer")
            and corr.get("state_published")
            and corr.get("state_consumed")
            and not corr.get("worker_recycled_between")
            and corr.get("correlation_strength") == "strong"
        ):
            correlated_runs.append(run)
        if _stale_state_confirmed(case, run, corr):
            stale_runs.append(run)

    if stale_runs:
        run = stale_runs[0]
        corr = dict(run.correlation or {})
        return _finding(
            CVE_619,
            ST_STALE_STATE_CONFIRMED,
            run.scenario_id,
            "Same-worker producer/consumer correlation plus lab trace showing the "
            "consumer acted on state from the freed producer request, with a "
            "patched-baseline differential.",
            _run_refs(run),
            "trace: state publication + same-worker consumer + freed-request identity "
            "(pointer/address or UAF) + patched baseline",
            limitations,
            alternatives,
            [],
            patch,
            _context(
                case,
                [run],
                {
                    "producer_worker": corr.get("producer_worker"),
                    "consumer_worker": corr.get("consumer_worker"),
                    "correlation_strength": corr.get("correlation_strength"),
                },
            ),
            observations,
        )

    if correlated_runs:
        run = correlated_runs[0]
        corr = dict(run.correlation or {})
        return _finding(
            CVE_619,
            ST_PRODUCER_CONSUMER_CORRELATED,
            run.scenario_id,
            "Producer state publication and an early consumer operation are correlated "
            "to the same worker across request boundaries; stale memory identity is "
            "not yet proven.",
            _run_refs(run),
            "telemetry: state_publish + same worker PID + producer end before consumer "
            "+ consumer early operation",
            limitations,
            alternatives,
            [
                "trace proving the consumed state is the freed producer request's memory "
                "(pointer/address identity, UAF report or non-reflectable canary)",
                "patched-baseline differential",
            ],
            patch,
            _context(
                case,
                [run],
                {
                    "producer_worker": corr.get("producer_worker"),
                    "consumer_worker": corr.get("consumer_worker"),
                    "correlation_strength": corr.get("correlation_strength"),
                },
            ),
            observations,
        )

    if producer_runs:
        run = producer_runs[0]
        return _finding(
            CVE_619,
            ST_PRODUCER_OBSERVED,
            run.scenario_id,
            "A producer request published request-owned state and was interrupted, but "
            "no same-worker consumer was demonstrated.",
            _run_refs(run),
            "telemetry state_publish on the producer request",
            limitations,
            alternatives,
            [
                "a later consumer request handled by the same worker",
                "consumer telemetry showing it read/freed/branched on the state",
                "worker PID for both requests",
            ],
            patch,
            context,
            observations,
        )

    if _exposure_build(profile, CVE_619):
        return _finding(
            CVE_619,
            ST_EXPOSED_BUILD,
            scenario_id,
            f"Build/package evidence indicates an affected PHP version "
            f"({profile.php_version}); exposure only, not proof.",
            refs,
            "build/package inventory",
            limitations
            + ["EXPOSED_BUILD is an exposure assessment; no producer/consumer path was exercised."],
            alternatives,
            [
                "prove-mode producer/consumer scenario with telemetry",
                "same-worker PID correlation",
                "state_publish and state_consume trace events",
                "patched-baseline differential",
            ],
            patch,
            context,
            observations,
        )

    if (
        profile.reach.state == "REACHED"
        and profile.sapi_verified
        and profile.sapi in SUSCEPTIBLE_SAPI_619
    ):
        return _finding(
            CVE_619,
            ST_PREREQUISITE_OBSERVED,
            scenario_id,
            "PHP reach and a SAPI named by the advisory were verified, but no build "
            "patch evidence or producer/consumer result exists.",
            refs,
            "reachability + SAPI inventory",
            limitations,
            alternatives,
            _build_missing(profile)
            + _patch_missing(profile, CVE_619)
            + ["producer/consumer scenario with telemetry and worker correlation"],
            patch,
            context,
            observations,
        )

    if runs:
        missing = [
            "producer state-publication telemetry",
            "same-worker PID correlation",
            "consumer early-operation telemetry",
            "trace or canary proving stale memory identity",
        ]
        if any((run.correlation or {}).get("producer_worker") and (run.correlation or {}).get("consumer_worker") and not (run.correlation or {}).get("same_worker") for run in runs):
            missing.insert(0, "producer and consumer landing on the same worker")
        return _finding(
            CVE_619,
            ST_INCONCLUSIVE,
            scenario_id,
            "Scenarios ran but no producer/consumer stale-state chain was demonstrated.",
            refs,
            "none (inconclusive)",
            limitations,
            alternatives,
            missing,
            patch,
            context,
            observations,
        )

    if not profile.php_version and profile.reach.state in ("UNKNOWN", "BLOCKED"):
        return _finding(
            CVE_619,
            ST_NOT_TESTED,
            "inventory",
            "No verified build and no prove-mode scenario; nothing supports a CVE status.",
            refs,
            "none",
            limitations,
            alternatives,
            _build_missing(profile) + ["prove-mode producer/consumer scenario"],
            patch,
            context,
            observations,
        )

    return _finding(
        CVE_619,
        ST_INCONCLUSIVE,
        scenario_id,
        "Inventory/probe evidence is insufficient to establish an affected build or "
        "the producer/consumer chain.",
        refs,
        "none (inconclusive)",
        limitations,
        alternatives,
        _build_missing(profile)
        + [
            "producer/consumer scenario",
            "same-worker PID correlation",
            "state_publish/state_consume trace",
        ],
        patch,
        context,
        observations,
    )


def _stale_state_confirmed(case: CaseFile, run: ScenarioRun, corr: Dict[str, Any]) -> bool:
    if case.environment.get("synthetic") or case.environment.get("kind") == "fixture":
        return False
    if not corr.get("same_worker") or not corr.get("producer_ended_before_consumer"):
        return False
    if corr.get("worker_recycled_between"):
        return False
    if not (corr.get("state_published") and corr.get("state_consumed")):
        return False
    if _trace_synthetic(case, run):
        return False
    types = _trace_types(case, run)
    if "patched_baseline" not in types:
        return False
    stale = bool(
        types
        & {
            "stale_global_consumed",
            "stale_global_referenced",
            "use_after_free",
            "invalid_state_processed",
        }
    )
    identity = bool(types & {"address_reuse", "use_after_free", "request_memory_freed"})
    return stale and identity


def assess_all(case: CaseFile) -> List[Finding]:
    return [assess_618(case), assess_619(case)]
