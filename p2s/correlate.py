"""Producer/consumer correlation for CVE-2026-109619.

Rules enforced here:

* Same HTTP keep-alive connection is NOT same worker.
* Same worker requires a telemetry-derived worker identity (PID) for BOTH
  requests, plus no worker exit/start between them.
* Producer must have completed before the consumer started.
* A single OOM is not state publication; a ``state_publish`` event (or an
  explicit trace event) is required.
* A consumer reading state is only "correlated", not "stale", until a trace
  or canary shows the consumed state belonged to the freed request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

from .http import HttpExchange
from .telemetry import TelemetryEvent
from .util import parse_iso

STATE_PUBLISH_TYPES = {
    "state_publish",
    "state_producer",
    "stale_state_published",
    "session_state_published",
}
STATE_CONSUME_TYPES = {
    "state_consume",
    "state_consumed",
    "stale_global_consumed",
    "stale_global_referenced",
    "ini_diagnostic",
    "upload_progress_consumer",
    "use_after_free",
}
EARLY_CONSUMER_TYPES = {"ini_diagnostic", "upload_progress_consumer", "state_consume", "stale_global_consumed"}
FATAL_TYPES = {"oom", "fatal"}
TRACE_TYPES = {
    "state_publish",
    "state_consume",
    "stale_global_referenced",
    "stale_global_consumed",
    "use_after_free",
    "address_reuse",
    "invalid_state_processed",
    "longjmp_from_oom",
    "shutdown_after_failed_startup",
    "request_memory_freed",
}


@dataclass
class CorrelationResult:
    same_worker: bool = False
    producer_worker: Optional[str] = None
    consumer_worker: Optional[str] = None
    producer_ended_before_consumer: bool = False
    worker_recycled_between: bool = False
    producer_events: int = 0
    consumer_events: int = 0
    producer_fatal: bool = False
    producer_oom: bool = False
    state_published: bool = False
    state_consumed: bool = False
    early_consumer: bool = False
    stale_marker: bool = False
    address_reuse: bool = False
    patched_baseline: bool = False
    correlation_strength: str = "none"  # none | weak | strong
    reasons: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    producer_event_refs: List[str] = field(default_factory=list)
    consumer_event_refs: List[str] = field(default_factory=list)
    stale_event_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "same_worker": self.same_worker,
            "producer_worker": self.producer_worker,
            "consumer_worker": self.consumer_worker,
            "producer_ended_before_consumer": self.producer_ended_before_consumer,
            "worker_recycled_between": self.worker_recycled_between,
            "producer_events": self.producer_events,
            "consumer_events": self.consumer_events,
            "producer_fatal": self.producer_fatal,
            "producer_oom": self.producer_oom,
            "state_published": self.state_published,
            "state_consumed": self.state_consumed,
            "early_consumer": self.early_consumer,
            "stale_marker": self.stale_marker,
            "address_reuse": self.address_reuse,
            "patched_baseline": self.patched_baseline,
            "correlation_strength": self.correlation_strength,
            "reasons": list(self.reasons),
            "missing": list(self.missing),
        }


def _events_for_request(events: Iterable[TelemetryEvent], request_id: Optional[str]) -> List[TelemetryEvent]:
    if not request_id:
        return []
    return [event for event in events if event.request_id == request_id]


def _workers(events: Iterable[TelemetryEvent]) -> Set[str]:
    return {str(event.worker_id) for event in events if event.worker_id}


def _between(events: Iterable[TelemetryEvent], start: Optional[str], end: Optional[str]) -> List[TelemetryEvent]:
    start_dt = parse_iso(start) if start else None
    end_dt = parse_iso(end) if end else None
    out = []
    for event in events:
        event_dt = parse_iso(event.timestamp)
        if event_dt is None:
            continue
        if start_dt and event_dt < start_dt:
            continue
        if end_dt and event_dt > end_dt:
            continue
        out.append(event)
    return out


def correlate_requests(
    producer: Optional[HttpExchange],
    consumer: Optional[HttpExchange],
    events: List[TelemetryEvent],
) -> CorrelationResult:
    result = CorrelationResult()
    if producer is None or consumer is None:
        result.missing.append("both producer and consumer HTTP exchanges are required")
        return result

    producer_id = producer.request_id
    consumer_id = consumer.request_id
    if producer_id == consumer_id:
        result.missing.append("producer and consumer must be different requests")
        return result

    p_events = _events_for_request(events, producer_id)
    c_events = _events_for_request(events, consumer_id)
    result.producer_events = len(p_events)
    result.consumer_events = len(c_events)
    result.producer_event_refs = [f"TEL:{e.line_no}" for e in p_events]
    result.consumer_event_refs = [f"TEL:{e.line_no}" for e in c_events]

    p_workers = _workers(p_events)
    c_workers = _workers(c_events)
    if not p_workers:
        result.missing.append(f"no telemetry with producer request_id {producer_id}")
    if not c_workers:
        result.missing.append(f"no telemetry with consumer request_id {consumer_id}")
    if len(p_workers) > 1:
        result.missing.append(f"ambiguous producer worker ids: {sorted(p_workers)}")
    if len(c_workers) > 1:
        result.missing.append(f"ambiguous consumer worker ids: {sorted(c_workers)}")
    if len(p_workers) == 1 and len(c_workers) == 1:
        result.producer_worker = next(iter(p_workers))
        result.consumer_worker = next(iter(c_workers))
        result.same_worker = result.producer_worker == result.consumer_worker
        if result.same_worker:
            result.reasons.append(
                f"producer and consumer both reported worker PID {result.producer_worker}"
            )
        else:
            result.reasons.append(
                "producer and consumer were handled by different workers "
                f"({result.producer_worker} != {result.consumer_worker}); no stale-state "
                "correlation is possible."
            )

    p_dt = parse_iso(producer.received_at)
    c_dt = parse_iso(consumer.sent_at)
    if p_dt and c_dt:
        result.producer_ended_before_consumer = p_dt <= c_dt
        if not result.producer_ended_before_consumer:
            result.missing.append("producer did not finish before consumer started")
        result.reasons.append(
            f"producer response {producer.received_at} <= consumer request {consumer.sent_at}: "
            f"{result.producer_ended_before_consumer}"
        )
    else:
        result.missing.append("missing parser-readable producer/consumer timestamps")

    # Worker recycle detection.  Same PID after an exit is a different process
    # instance for correlation purposes.
    if result.same_worker and result.producer_worker:
        window = _between(events, producer.received_at, consumer.sent_at)
        for event in window:
            if event.event_type in ("worker_exit", "worker_recycle", "worker_start") and str(
                event.worker_id
            ) == result.producer_worker:
                result.worker_recycled_between = True
                result.reasons.append(
                    f"worker {result.producer_worker} exited/restarted between requests "
                    f"at {event.timestamp}"
                )
                break
        if result.worker_recycled_between:
            result.same_worker = False

    for event in p_events:
        if event.event_type in STATE_PUBLISH_TYPES or event.event_type == "state_published":
            result.state_published = True
        if event.event_type == "oom":
            result.producer_oom = True
            result.producer_fatal = True
        elif event.event_type == "fatal":
            result.producer_fatal = True
        if event.event_type in TRACE_TYPES:
            if event.event_type in ("stale_global_referenced", "invalid_state_processed"):
                result.stale_marker = True

    for event in c_events:
        if event.event_type in STATE_CONSUME_TYPES:
            result.state_consumed = True
        if event.event_type in EARLY_CONSUMER_TYPES:
            result.early_consumer = True
        if event.event_type in TRACE_TYPES and event.event_type in (
            "stale_global_consumed",
            "use_after_free",
            "invalid_state_processed",
        ):
            result.stale_marker = True
        if event.event_type == "address_reuse":
            result.address_reuse = True
        if event.event_type == "patched_baseline":
            result.patched_baseline = True

    if not result.state_published:
        result.missing.append(
            "no producer state-publication event (a bare OOM/fatal does not prove "
            "request-owned global state survived)"
        )
    if not result.state_consumed:
        result.missing.append(
            "no consumer event showing an early operation read/freed/branched on "
            "the published state"
        )
    if result.same_worker and result.producer_ended_before_consumer and result.state_published and result.state_consumed:
        result.correlation_strength = "strong"
        result.reasons.append(
            "producer/consumer are correlated to the same worker and the consumer "
            "performed an early operation on state published by the producer"
        )
    elif result.producer_events or result.consumer_events:
        result.correlation_strength = "weak"
    else:
        result.correlation_strength = "none"

    if result.correlation_strength == "strong" and not result.stale_marker:
        result.missing.append(
            "correlation is strong but no trace proves the consumed state belonged "
            "to the freed producer request (pointer/address identity or canary)"
        )
    return result


def correlate_with_fallback(
    producer: HttpExchange,
    consumer: HttpExchange,
    events: List[TelemetryEvent],
    time_window_seconds: float = 5.0,
) -> CorrelationResult:
    """Correlate; if request IDs are absent, report that fact instead of guessing.

    Kept as a separate entry point so callers cannot accidentally treat a
    time-window match as same-worker proof.
    """
    result = correlate_requests(producer, consumer, events)
    if not result.producer_events and not result.consumer_events:
        result.missing.append(
            "telemetry did not contain the scanner request IDs; same-worker proof "
            "cannot be established from timing alone"
        )
    return result
