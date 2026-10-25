"""Shared builders for deterministic, schema-valid test evidence.

These helpers never touch the network.  They construct the same dataclasses the
scanner writes to disk so the assessors can be tested in isolation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from p2s.classifier import classify
from p2s.http import HttpExchange
from p2s.models import (
    CaseFile,
    Evidence,
    ScenarioRun,
    TargetProfile,
)
from p2s.patch import assess_patch
from p2s.telemetry import TelemetryEvent
from p2s.util import canonical_json, sha256_bytes
from p2s.version import CVE_618, CVE_619

BASE_TS = "2026-10-24T10:00:00.000Z"


def ts(offset: float = 0.0) -> str:
    """A deterministic ISO timestamp a number of seconds after BASE_TS."""
    from datetime import datetime, timedelta, timezone

    base = datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)
    value = base + timedelta(seconds=offset)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make_profile(
    version: Optional[str] = "8.2.12",
    version_trust: str = "high",
    version_source: str = "lab-status-endpoint",
    sapi: str = "mod_php",
    sapi_verified: bool = True,
    reach: str = "REACHED",
    patch: Optional[Any] = None,
    packaging: Optional[str] = None,
    environment_kind: str = "fixture",
) -> TargetProfile:
    profile = TargetProfile(
        target="http://lab.invalid/",
        base_url="http://lab.invalid/",
        host="lab.invalid",
        port=80,
        tls=False,
        php_version=version,
        version_source=version_source,
        version_trust=version_trust,
        sapi=sapi,
        sapi_source=version_source if sapi_verified else "none",
        sapi_verified=sapi_verified,
        environment_kind=environment_kind,
        packaging=packaging,
        collected_at=ts(),
    )
    profile.reach.state = reach
    profile.reach.basis = ["test fixture"]
    if patch is None:
        patch = assess_patch(
            version,
            source=version_source,
            trust=version_trust,
            packaging=packaging,
        )
    profile.patch = patch
    return profile


def make_exchange(
    request_id: str = "req-1",
    method: str = "GET",
    url: str = "http://lab.invalid/",
    status: int = 200,
    body: str = "",
    headers: Optional[Dict[str, str]] = None,
    sent_at: Optional[str] = None,
    received_at: Optional[str] = None,
    error_kind: Optional[str] = None,
    error_message: Optional[str] = None,
    nonce: Optional[str] = None,
) -> HttpExchange:
    return HttpExchange(
        request_id=request_id,
        method=method,
        url=url,
        sent_at=sent_at or ts(),
        received_at=received_at or ts(0.5),
        duration_ms=500.0,
        status=status,
        response_headers=dict(headers or {}),
        body_bytes=len(body.encode("utf-8")),
        body_preview=body,
        error_kind=error_kind,
        error_message=error_message,
        nonce=nonce,
    )


def http_evidence(
    evidence_id: str,
    request_id: str = "req-1",
    status: int = 200,
    body: str = "",
    headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
    url: str = "http://lab.invalid/",
    sent_at: Optional[str] = None,
    received_at: Optional[str] = None,
    error_kind: Optional[str] = None,
    nonce: Optional[str] = None,
    scenario_id: Optional[str] = None,
    synthetic: bool = True,
    timestamp: Optional[str] = None,
) -> Evidence:
    exchange = make_exchange(
        request_id=request_id,
        method=method,
        url=url,
        status=status,
        body=body,
        headers=headers,
        sent_at=sent_at,
        received_at=received_at,
        error_kind=error_kind,
        nonce=nonce,
    )
    classification = classify(exchange, nonce=nonce)
    data = {"exchange": exchange.to_dict(), "classification": classification.to_dict()}
    return Evidence(
        id=evidence_id,
        source="http",
        timestamp=timestamp or exchange.received_at,
        data=data,
        sha256=sha256_bytes(canonical_json(data)),
        correlation_id=request_id,
        request_id=request_id,
        scenario_id=scenario_id,
        trust="high",
        synthetic=synthetic,
    )


def telemetry_evidence(
    evidence_id: str,
    event_type: str,
    *,
    request_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    message: Optional[str] = None,
    timestamp: Optional[str] = None,
    phase: Optional[str] = None,
    source: str = "lab_trace",
    scenario_id: Optional[str] = None,
    synthetic: bool = True,
    nonce: Optional[str] = None,
) -> Evidence:
    event = TelemetryEvent(
        source=source,
        timestamp=timestamp or ts(),
        message=message or event_type,
        event_type=event_type,
        severity="info",
        request_id=request_id,
        worker_id=worker_id,
        phase=phase,
        nonce=nonce,
    )
    data = {"event": event.to_dict()}
    return Evidence(
        id=evidence_id,
        source=source,
        timestamp=event.timestamp,
        data=data,
        sha256=sha256_bytes(canonical_json(data)),
        correlation_id=request_id,
        request_id=request_id,
        worker_id=worker_id,
        scenario_id=scenario_id,
        trust="high" if source == "lab_trace" else "medium",
        synthetic=synthetic,
    )


def canary_evidence(
    evidence_id: str,
    *,
    verified: bool,
    reflected: bool = False,
    telemetry_worker_match: bool = True,
    before_present: bool = False,
    after_present: bool = True,
    request_id: Optional[str] = None,
    worker_id: Optional[str] = None,
    scenario_id: Optional[str] = None,
    synthetic: bool = False,
) -> Evidence:
    assessment = {
        "requested": True,
        "nonce": "P2S-CANARYTESTNONCE123456",
        "readback_url": "http://lab.invalid/canary",
        "before_present": before_present,
        "after_present": after_present,
        "reflected_in_test_responses": reflected,
        "telemetry_write": True,
        "telemetry_worker_match": telemetry_worker_match,
        "readback_verified": after_present and not before_present,
        "verified": verified,
        "reasons": [],
        "missing": [],
    }
    data = {"assessment": assessment, "nonce": assessment["nonce"]}
    return Evidence(
        id=evidence_id,
        source="canary",
        timestamp=ts(),
        data=data,
        sha256=sha256_bytes(canonical_json(data)),
        correlation_id=request_id,
        request_id=request_id,
        worker_id=worker_id,
        scenario_id=scenario_id,
        trust="high" if verified else "low",
        synthetic=synthetic,
    )


def make_run(
    scenario_id: str = "618-S2",
    cve: str = CVE_618,
    *,
    producer_request_id: Optional[str] = "req-producer",
    consumer_request_id: Optional[str] = None,
    producer_worker_id: Optional[str] = None,
    consumer_worker_id: Optional[str] = None,
    request_refs: Optional[List[str]] = None,
    control_refs: Optional[List[str]] = None,
    telemetry_refs: Optional[List[str]] = None,
    trace_refs: Optional[List[str]] = None,
    oom_refs: Optional[List[str]] = None,
    state_publish_refs: Optional[List[str]] = None,
    state_consume_refs: Optional[List[str]] = None,
    canary_refs: Optional[List[str]] = None,
    correlation: Optional[Dict[str, Any]] = None,
    canary: Optional[Dict[str, Any]] = None,
    executed: bool = True,
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
) -> ScenarioRun:
    return ScenarioRun(
        scenario_id=scenario_id,
        cve=cve,
        executed=executed,
        started_at=started_at or ts(),
        finished_at=finished_at or ts(2),
        producer_request_id=producer_request_id,
        consumer_request_id=consumer_request_id,
        producer_worker_id=producer_worker_id,
        consumer_worker_id=consumer_worker_id,
        request_refs=list(request_refs or []),
        control_refs=list(control_refs or []),
        telemetry_refs=list(telemetry_refs or []),
        trace_refs=list(trace_refs or []),
        oom_refs=list(oom_refs or []),
        state_publish_refs=list(state_publish_refs or []),
        state_consume_refs=list(state_consume_refs or []),
        canary_refs=list(canary_refs or []),
        correlation=dict(correlation or {}),
        canary=dict(canary or {}),
    )


def make_case(
    profile: TargetProfile,
    evidence: List[Evidence],
    runs: Optional[List[ScenarioRun]] = None,
    *,
    synthetic: bool = True,
    kind: str = "fixture",
) -> CaseFile:
    return CaseFile(
        profile=profile,
        evidence=evidence,
        scenario_runs=list(runs or []),
        run_id="test-run",
        tool_version="4.0.0-test",
        mode="prove",
        started_at=ts(),
        finished_at=ts(10),
        environment={
            "kind": kind,
            "synthetic": synthetic,
            "telemetry_files": [],
            "limits": {},
        },
    )


def strong_619_correlation() -> Dict[str, Any]:
    return {
        "same_worker": True,
        "producer_worker": "1234",
        "consumer_worker": "1234",
        "producer_ended_before_consumer": True,
        "worker_recycled_between": False,
        "producer_events": 2,
        "consumer_events": 2,
        "producer_fatal": True,
        "producer_oom": True,
        "state_published": True,
        "state_consumed": True,
        "early_consumer": True,
        "stale_marker": False,
        "address_reuse": False,
        "correlation_strength": "strong",
        "reasons": ["fixture"],
        "missing": [],
    }


def two_worker_619_correlation() -> Dict[str, Any]:
    value = strong_619_correlation()
    value.update(
        {
            "same_worker": False,
            "consumer_worker": "5678",
            "correlation_strength": "weak",
            "reasons": ["producer and consumer were handled by different workers"],
        }
    )
    return value


__all__ = [
    "BASE_TS",
    "CVE_618",
    "CVE_619",
    "canary_evidence",
    "http_evidence",
    "make_case",
    "make_exchange",
    "make_profile",
    "make_run",
    "strong_619_correlation",
    "telemetry_evidence",
    "ts",
    "two_worker_619_correlation",
]
