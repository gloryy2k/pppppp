"""Prove mode: bounded, auditable scenario execution.

Safety properties:

* explicit authorisation flag required;
* request, byte, time and concurrency caps;
* health check before and after every scenario;
* stop on service degradation;
* a scenario id is executed at most once per run unless --allow-rerun;
* evidence is written as it is produced, including on interruption;
* no OOM payload is sent in inventory/probe mode.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional

from .canary import CanaryAssessment, check_canary
from .classifier import KIND_FRONTEND_REJECT, KIND_PROXY_ERROR, classify
from .correlate import correlate_requests
from .http import HttpClient, HttpExchange
from .models import ScenarioDefinition, ScenarioRun, TargetProfile
from .scenarios import (
    app_oom_boundary,
    build_app_oom,
    build_control_multipart,
    build_empty_file_nested,
    build_part_header_bomb,
    build_undeclared_length,
    build_upload_progress,
    chunked_boundary,
    control_boundary,
    header_bomb_boundary,
    nested_boundary,
    new_scenario_nonce,
    upload_progress_boundary,
)
from .telemetry import TelemetryEvent, merge_events, parse_telemetry_file, source_for_path
from .util import (
    human_bytes,
    new_nonce,
    parse_iso,
    utcnow,
)
from .version import CVE_618, CVE_619

DEFAULT_LIMITS = {
    "max_requests": 8,
    "max_bytes": 32 * 1024 * 1024,
    "max_request_bytes": 8 * 1024 * 1024,
    "timeout": 30.0,
    "health_timeout": 10.0,
    "max_seconds": 180.0,
    "concurrency": 1,
}


class BudgetExceeded(Exception):
    pass


@dataclass
class ProveLimits:
    max_requests: int = DEFAULT_LIMITS["max_requests"]
    max_bytes: int = DEFAULT_LIMITS["max_bytes"]
    max_request_bytes: int = DEFAULT_LIMITS["max_request_bytes"]
    timeout: float = DEFAULT_LIMITS["timeout"]
    health_timeout: float = DEFAULT_LIMITS["health_timeout"]
    max_seconds: float = DEFAULT_LIMITS["max_seconds"]
    concurrency: int = 1
    stop_on_degradation: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_requests": self.max_requests,
            "max_bytes": self.max_bytes,
            "max_request_bytes": self.max_request_bytes,
            "timeout_seconds": self.timeout,
            "health_timeout_seconds": self.health_timeout,
            "max_seconds": self.max_seconds,
            "concurrency": self.concurrency,
            "stop_on_degradation": self.stop_on_degradation,
        }


@dataclass
class ProveOptions:
    scenarios: List[ScenarioDefinition] = field(default_factory=list)
    acknowledge_authorised: bool = False
    health_url: Optional[str] = None
    status_url: Optional[str] = None
    telemetry_files: List[str] = field(default_factory=list)
    telemetry_source: Optional[str] = None
    producer_url: Optional[str] = None
    consumer_url: Optional[str] = None
    app_oom_endpoint: Optional[str] = None
    app_oom_field: Optional[str] = None
    app_oom_mib: int = 8
    canary_readback_url: Optional[str] = None
    allow_rerun: bool = False
    allow_non_advisory_sapi: bool = False
    environment_kind: str = "lab"
    synthetic: bool = False
    limits: ProveLimits = field(default_factory=ProveLimits)


@dataclass
class ProveOutcome:
    runs: List[ScenarioRun] = field(default_factory=list)
    events: List[TelemetryEvent] = field(default_factory=list)
    health_before: Dict[str, Any] = field(default_factory=dict)
    health_after: Dict[str, Any] = field(default_factory=dict)
    stopped_reason: str = ""
    interrupted: bool = False
    request_count: int = 0
    byte_count: int = 0
    started_at: str = ""
    finished_at: str = ""
    canary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runs": [run.to_dict() for run in self.runs],
            "health_before": self.health_before,
            "health_after": self.health_after,
            "stopped_reason": self.stopped_reason,
            "interrupted": self.interrupted,
            "request_count": self.request_count,
            "byte_count": self.byte_count,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "canary": self.canary,
        }


class Budget:
    def __init__(self, limits: ProveLimits):
        self.limits = limits
        self.requests = 0
        self.bytes = 0
        self.started = time.monotonic()

    def check(self, body_len: int = 0) -> None:
        if self.requests + 1 > self.limits.max_requests:
            raise BudgetExceeded(f"request budget exhausted ({self.limits.max_requests})")
        if self.bytes + body_len > self.limits.max_bytes:
            raise BudgetExceeded(
                f"byte budget exhausted ({human_bytes(self.limits.max_bytes)})"
            )
        if body_len > self.limits.max_request_bytes:
            raise BudgetExceeded(
                f"request body {human_bytes(body_len)} exceeds per-request cap "
                f"{human_bytes(self.limits.max_request_bytes)}"
            )
        if time.monotonic() - self.started > self.limits.max_seconds:
            raise BudgetExceeded(f"time budget exhausted ({self.limits.max_seconds}s)")

    def consume(self, body_len: int = 0) -> None:
        self.requests += 1
        self.bytes += body_len


def _health(
    client: HttpClient,
    url: str,
    store: Any,
    scenario_id: str,
    timeout: float,
    synthetic: bool = False,
) -> Dict[str, Any]:
    exchange = client.request("GET", url, headers={"Accept": "*/*"}, timeout=timeout)
    classification = classify(exchange)
    item = store.add_http(
        exchange,
        classification,
        scenario_id=f"{scenario_id}-health",
        trust="high",
        notes="health check",
        synthetic=synthetic,
    )
    return {
        "ok": exchange.error_kind is None and exchange.status < 500,
        "status": exchange.status,
        "error": exchange.error_kind,
        "latency_ms": exchange.duration_ms,
        "evidence_ref": item.id,
        "timestamp": exchange.received_at,
        "classification": classification.kind,
    }


def _degraded(before: Dict[str, Any], after: Dict[str, Any]) -> bool:
    if before.get("ok") and not after.get("ok"):
        return True
    try:
        if after.get("latency_ms", 0) > max(3000.0, before.get("latency_ms", 0) * 3 + 1000):
            return True
    except (TypeError, ValueError):
        pass
    return False


class ProveEngine:
    def __init__(
        self,
        client: HttpClient,
        store: Any,
        profile: TargetProfile,
        options: ProveOptions,
        existing_runs: Optional[List[ScenarioRun]] = None,
    ):
        self.client = client
        self.store = store
        self.profile = profile
        self.options = options
        self.limits = options.limits
        self.budget = Budget(self.limits)
        self.events: List[TelemetryEvent] = []
        self._seen_events = set()
        self._event_refs: Dict[tuple, str] = {}
        self._scenario_nonces: Dict[str, str] = {}
        self.existing_runs = existing_runs or []
        self._existing_ids = {run.scenario_id for run in self.existing_runs if run.executed}

    # -- telemetry ---------------------------------------------------------

    def _ingest_telemetry(self, run: Optional[ScenarioRun] = None) -> List[str]:
        refs: List[str] = []
        for path in self.options.telemetry_files:
            source = self.options.telemetry_source or source_for_path(path)
            events, errors = parse_telemetry_file(path, source)
            for error in errors:
                self.store.add(
                    "operator",
                    {"parse_error": error, "file": path},
                    scenario_id=run.scenario_id if run else "telemetry-parse",
                    trust="low",
                    notes="telemetry parse error",
                    synthetic=self.options.synthetic,
                )
            for event in events:
                key = (event.source, event.timestamp, event.message, event.request_id, event.worker_id)
                if key in self._seen_events:
                    if run is not None:
                        existing = self._event_refs.get(key)
                        if existing and self._belongs(event, run):
                            refs.append(existing)
                    continue
                self._seen_events.add(key)
                item = self.store.add_telemetry(
                    event,
                    scenario_id=run.scenario_id if run else "telemetry",
                    synthetic=self.options.synthetic,
                    trust="high" if event.source == "lab_trace" else "medium",
                )
                self._event_refs[key] = item.id
                self.events.append(event)
                if run is not None and self._belongs(event, run):
                    refs.append(item.id)
                elif run is None:
                    refs.append(item.id)
        self.events = merge_events(self.events)
        return refs

    def _belongs(self, event: TelemetryEvent, run: ScenarioRun) -> bool:
        if event.request_id and event.request_id in (
            run.producer_request_id,
            run.consumer_request_id,
        ):
            return True
        if event.worker_id and event.worker_id in (run.producer_worker_id, run.consumer_worker_id):
            return True
        if event.source == "lab_trace" and run.scenario_id and run.scenario_id in event.message:
            return True
        if self._event_in_run_window(event, run):
            return True
        return False

    def _event_in_run_window(self, event: TelemetryEvent, run: ScenarioRun) -> bool:
        """Attach an identity-less diagnostic line by the request time window.

        This is deliberately narrow.  Only diagnostics that a PHP/web worker can
        emit without knowing the scanner's request id are eligible, and the
        resulting evidence still supports at most ``OOM_OBSERVED``: the
        assessors explicitly refuse a time-window match for
        ``AFFECTED_PATH_CONFIRMED``.  State-publication and state-consumption
        events are never attached this way because they need request identity
        to support any producer/consumer claim.
        """
        if event.request_id or event.worker_id:
            return False
        if event.event_type not in ("oom", "fatal", "diagnostic", "worker_exit", "worker_start"):
            return False
        starts: List[str] = []
        ends: List[str] = []
        for item in self.store._evidence:
            if item.source != "http":
                continue
            if item.request_id not in (run.producer_request_id, run.consumer_request_id):
                continue
            exchange = item.data.get("exchange") or {}
            if exchange.get("sent_at"):
                starts.append(str(exchange["sent_at"]))
            if exchange.get("received_at"):
                ends.append(str(exchange["received_at"]))
        if not starts or not ends:
            return False
        starts.sort()
        ends.sort()
        event_dt = parse_iso(event.timestamp)
        start_dt = parse_iso(starts[0])
        end_dt = parse_iso(ends[-1])
        if not (event_dt and start_dt and end_dt):
            return False
        if not (start_dt - timedelta(seconds=2) <= event_dt <= end_dt + timedelta(seconds=10)):
            return False
        note = (
            f"telemetry {event.event_type} at {event.timestamp} was attached by the "
            "request time window only; it has no request id or worker PID and cannot "
            "support AFFECTED_PATH_CONFIRMED"
        )
        if note not in run.notes:
            run.notes.append(note)
        return True

    def _assign_telemetry(self, run: ScenarioRun, refs: List[str]) -> None:
        index = {item.id: item for item in self.store._evidence}
        for ref in refs:
            item = index.get(ref)
            if item is None:
                continue
            event = item.data.get("event", {})
            event_type = event.get("event_type")
            run.telemetry_refs.append(ref)
            if item.source == "lab_trace":
                run.trace_refs.append(ref)
            if event_type == "oom":
                run.oom_refs.append(ref)
            if event_type in ("state_publish", "state_published", "state_producer"):
                run.state_publish_refs.append(ref)
            if event_type in (
                "state_consume",
                "state_consumed",
                "stale_global_consumed",
                "stale_global_referenced",
                "ini_diagnostic",
                "upload_progress_consumer",
            ):
                run.state_consume_refs.append(ref)

    # -- request helpers ---------------------------------------------------

    def _send(
        self,
        run: ScenarioRun,
        method: str,
        url: str,
        body: Optional[bytes],
        headers: Dict[str, str],
        chunked: bool = False,
        nonce: Optional[str] = None,
        role: str = "test",
    ) -> tuple:
        self.budget.check(len(body or b""))
        exchange = self.client.request(
            method,
            url,
            body=body,
            headers=headers,
            chunked=chunked,
            nonce=nonce,
            timeout=self.limits.timeout,
        )
        self.budget.consume(len(body or b""))
        classification = classify(exchange, nonce=nonce)
        item = self.store.add_http(
            exchange,
            classification,
            scenario_id=run.scenario_id,
            trust="high",
            notes=f"{role} request",
            synthetic=self.options.synthetic,
        )
        if role in ("producer", "test"):
            run.request_refs.append(item.id)
            if role == "producer":
                run.producer_request_id = exchange.request_id
        elif role == "consumer":
            run.request_refs.append(item.id)
            run.consumer_request_id = exchange.request_id
        elif role == "control":
            run.control_refs.append(item.id)
        if classification.oom:
            run.oom_refs.append(item.id)
        return exchange, classification, item

    def _control(self, run: ScenarioRun, url: str, nonce: str) -> None:
        body = build_control_multipart(nonce)
        self._send(
            run,
            "POST",
            url,
            body,
            {"Content-Type": f"multipart/form-data; boundary={control_boundary(nonce)}"},
            nonce=nonce,
            role="control",
        )

    # -- scenario execution ------------------------------------------------

    def _preflight(self, scenario: ScenarioDefinition) -> Optional[str]:
        if scenario.id in self._existing_ids and not self.options.allow_rerun:
            return "scenario already executed in this evidence set; refusing a duplicate run"
        if scenario.lab_only:
            if scenario.id in ("619-S1", "619-S3") and not (
                self.options.producer_url and self.options.consumer_url
            ):
                return "lab-only scenario requires --producer-url and --consumer-url"
        if scenario.id == "618-S4" and not (
            self.options.app_oom_endpoint and self.options.app_oom_field
        ):
            return "application-OOM scenario requires --app-oom-endpoint and --app-oom-field"
        if scenario.cve == CVE_618:
            if self.profile.patch.state == "PATCHED" and self.profile.patch.trust == "high":
                return "PATCH_CONFIRMED from build/package evidence; OOM payload not sent"
            if self.profile.reach.state == "BLOCKED":
                return "frontend/WAF blocked the control path; OOM payload would not reach PHP"
            if (
                not self.options.allow_non_advisory_sapi
                and self.profile.sapi not in ("mod_php", "fpm", "frankenphp", "lsapi", "unknown")
            ):
                return (
                    f"SAPI {self.profile.sapi} is not evaluated by the advisory; "
                    "use --allow-non-advisory-sapi to run a diagnostic OOM test"
                )
        return None

    def run(self) -> ProveOutcome:
        outcome = ProveOutcome(started_at=utcnow())
        if not self.options.acknowledge_authorised:
            outcome.stopped_reason = (
                "prove mode requires --ack-authorised (written authorisation for the "
                "internal target and a prepared lab/telemetry channel)"
            )
            outcome.finished_at = utcnow()
            return outcome

        if self.limits.concurrency != 1:
            outcome.stopped_reason = (
                "concurrency > 1 is refused in prove mode: worker correlation and "
                "health checks require sequential requests"
            )
            outcome.finished_at = utcnow()
            return outcome

        # Baseline telemetry before any scenario.
        self._ingest_telemetry(None)

        health_url = self.options.health_url or self.profile.base_url
        outcome.health_before = _health(
            self.client,
            health_url,
            self.store,
            "prove",
            self.limits.health_timeout,
            synthetic=self.options.synthetic,
        )
        if not outcome.health_before.get("ok"):
            outcome.stopped_reason = "pre-flight health check failed; no OOM payload sent"
            outcome.health_after = dict(outcome.health_before)
            outcome.finished_at = utcnow()
            return outcome

        try:
            for scenario in self.options.scenarios:
                run = ScenarioRun(
                    scenario_id=scenario.id,
                    cve=scenario.cve,
                    started_at=utcnow(),
                )
                reason = self._preflight(scenario)
                if reason:
                    run.skipped_reason = reason
                    run.finished_at = utcnow()
                    outcome.runs.append(run)
                    continue

                run.executed = True
                try:
                    self._run_scenario(scenario, run)
                except BudgetExceeded as exc:
                    run.notes.append(f"stopped: {exc}")
                    outcome.stopped_reason = str(exc)
                except KeyboardInterrupt:
                    run.interrupted = True
                    outcome.interrupted = True
                    run.notes.append("interrupted by operator; partial evidence persisted")
                    outcome.stopped_reason = "interrupted"
                    outcome.runs.append(run)
                    self._finalise_run(run, self._scenario_nonces.get(run.scenario_id))
                    raise
                except Exception as exc:  # defensive: persist and keep going
                    run.notes.append(f"scenario error: {type(exc).__name__}: {exc}")
                finally:
                    run.finished_at = run.finished_at or utcnow()

                refs = self._ingest_telemetry(run)
                self._assign_telemetry(run, refs)
                self._finalise_run(run, self._scenario_nonces.get(run.scenario_id))
                outcome.runs.append(run)

                if run.executed and not run.interrupted:
                    after = _health(
                        self.client,
                        health_url,
                        self.store,
                        f"prove-{scenario.id}",
                        self.limits.health_timeout,
                        synthetic=self.options.synthetic,
                    )
                    run.health_refs.append(after["evidence_ref"])
                    if _degraded(outcome.health_before, after):
                        outcome.health_after = after
                        if self.limits.stop_on_degradation:
                            outcome.stopped_reason = (
                                f"service degradation detected after {scenario.id}; "
                                "remaining scenarios skipped"
                            )
                            break
                if self.budget.requests >= self.limits.max_requests:
                    outcome.stopped_reason = "request budget exhausted"
                    break
        except KeyboardInterrupt:
            outcome.interrupted = True
            if not outcome.stopped_reason:
                outcome.stopped_reason = "interrupted"
        finally:
            # Final telemetry ingest captures OOM lines written after the response.
            refs = self._ingest_telemetry(None)
            for run in outcome.runs:
                self._assign_telemetry(run, [r for r in refs if self._ref_belongs(r, run)])
            if not outcome.health_after:
                outcome.health_after = _health(
                    self.client,
                    health_url,
                    self.store,
                    "prove-final",
                    self.limits.health_timeout,
                    synthetic=self.options.synthetic,
                )
            outcome.request_count = self.budget.requests
            outcome.byte_count = self.budget.bytes
            outcome.finished_at = utcnow()
        return outcome

    def _ref_belongs(self, ref: str, run: ScenarioRun) -> bool:
        for item in self.store._evidence:
            if item.id != ref:
                continue
            payload = (item.data or {}).get("event")
            if not isinstance(payload, dict):
                return False
            event = TelemetryEvent(
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
            return self._belongs(event, run)
        return False

    def _run_scenario(self, scenario: ScenarioDefinition, run: ScenarioRun) -> None:
        nonce = new_scenario_nonce(scenario.id)
        self._scenario_nonces[scenario.id] = nonce
        if self.options.canary_readback_url:
            before, before_ref = self._readback(run, nonce, "before")
            run.canary = {"nonce": nonce, "before_ref": before_ref}
            run.canary_refs.append(before_ref)
        self._control(run, self.profile.base_url, new_nonce("P2SCTRL"))

        if scenario.id in ("618-S1", "618-S2", "618-S3"):
            self._run_618_parsing(scenario, run, nonce)
        elif scenario.id == "618-S4":
            self._run_618_app(run, nonce)
        elif scenario.id == "619-S2":
            self._run_619_s2(run, nonce)
        elif scenario.id in ("619-S1", "619-S3"):
            self._run_619_lab(scenario, run, nonce)
        else:
            run.notes.append(f"no implementation for scenario {scenario.id}")

    def _run_618_parsing(self, scenario: ScenarioDefinition, run: ScenarioRun, nonce: str) -> None:
        if scenario.id == "618-S1":
            body = build_undeclared_length(nonce)
            headers = {"Content-Type": f"multipart/form-data; boundary={chunked_boundary(nonce)}"}
            exchange, classification, _ = self._send(
                run,
                "POST",
                self.profile.base_url,
                body,
                headers,
                chunked=True,
                nonce=nonce,
                role="producer",
            )
            run.notes.append("chunked multipart sent with no Content-Length")
        elif scenario.id == "618-S2":
            body = build_part_header_bomb(nonce)
            headers = {"Content-Type": f"multipart/form-data; boundary={header_bomb_boundary(nonce)}"}
            exchange, classification, _ = self._send(
                run, "POST", self.profile.base_url, body, headers, nonce=nonce, role="producer"
            )
        else:
            body = build_empty_file_nested(nonce)
            headers = {"Content-Type": f"multipart/form-data; boundary={nested_boundary(nonce)}"}
            exchange, classification, _ = self._send(
                run, "POST", self.profile.base_url, body, headers, nonce=nonce, role="producer"
            )

        run.producer_request_id = exchange.request_id
        run.notes.append(f"response classification: {classification.kind} ({classification.detail})")
        if classification.oom:
            run.notes.append(
                f"PHP OOM text observed in the response (context={classification.oom_context}); "
                "telemetry is still required for the CVE assessor."
            )
        if classification.frontend_reject:
            run.notes.append("frontend rejected the scenario body; no OOM conclusion")
        if classification.gateway_error:
            run.notes.append("gateway error; not evidence of a PHP crash or OOM")

    def _run_618_app(self, run: ScenarioRun, nonce: str) -> None:
        field = self.options.app_oom_field or "p2s_oom"
        body = build_app_oom(nonce, field, self.options.app_oom_mib)
        headers = {"Content-Type": f"multipart/form-data; boundary={app_oom_boundary(nonce)}"}
        exchange, classification, _ = self._send(
            run,
            "POST",
            self.options.app_oom_endpoint or self.profile.base_url,
            body,
            headers,
            nonce=nonce,
            role="producer",
        )
        run.producer_request_id = exchange.request_id
        run.notes.append(
            "application fixture OOM: this can demonstrate an application allocation "
            "failure, not the advisory's parser/startup path"
        )

    def _run_619_s2(self, run: ScenarioRun, nonce: str) -> None:
        producer_nonce = new_nonce("P2S619PROD")
        producer_body = build_part_header_bomb(producer_nonce)
        producer_headers = {
            "Content-Type": f"multipart/form-data; boundary={header_bomb_boundary(producer_nonce)}"
        }
        producer, p_class, _ = self._send(
            run,
            "POST",
            self.profile.base_url,
            producer_body,
            producer_headers,
            nonce=producer_nonce,
            role="producer",
        )
        run.producer_request_id = producer.request_id
        run.notes.append(f"producer classification: {p_class.kind}")

        time.sleep(0.05)
        consumer_nonce = new_nonce("P2S619CONS")
        consumer_body = build_upload_progress(consumer_nonce)
        consumer_headers = {
            "Content-Type": f"multipart/form-data; boundary={upload_progress_boundary(consumer_nonce)}"
        }
        consumer, c_class, _ = self._send(
            run,
            "POST",
            self.options.consumer_url or self.profile.base_url,
            consumer_body,
            consumer_headers,
            nonce=consumer_nonce,
            role="consumer",
        )
        run.consumer_request_id = consumer.request_id
        run.notes.append(f"consumer classification: {c_class.kind}")
        run.notes.append(
            "A 502/500/timeout on the consumer is not stale-state proof; telemetry and "
            "same-worker PID correlation are required."
        )

    def _run_619_lab(self, scenario: ScenarioDefinition, run: ScenarioRun, nonce: str) -> None:
        producer_url = self.options.producer_url or self.profile.base_url
        consumer_url = self.options.consumer_url or self.profile.base_url
        producer, p_class, _ = self._send(
            run, "GET", producer_url, None, {}, nonce=nonce, role="producer"
        )
        run.producer_request_id = producer.request_id
        time.sleep(0.05)
        if scenario.id == "619-S3":
            consumer_nonce = new_nonce("P2S619CONS")
            consumer_body = build_upload_progress(consumer_nonce)
            consumer, c_class, _ = self._send(
                run,
                "POST",
                consumer_url,
                consumer_body,
                {
                    "Content-Type": (
                        f"multipart/form-data; boundary={upload_progress_boundary(consumer_nonce)}"
                    )
                },
                nonce=consumer_nonce,
                role="consumer",
            )
        else:
            consumer, c_class, _ = self._send(
                run, "GET", consumer_url, None, {}, nonce=nonce, role="consumer"
            )
        run.consumer_request_id = consumer.request_id
        run.notes.append(f"producer classification: {p_class.kind}; consumer: {c_class.kind}")
        run.notes.append("lab harness must provide state_publish/state_consume trace events")

    # -- finalise ----------------------------------------------------------

    def _finalise_run(self, run: ScenarioRun, nonce: Optional[str] = None) -> None:
        if run.producer_request_id and not run.producer_worker_id:
            run.producer_worker_id = self._worker_for(run.producer_request_id)
        if run.consumer_request_id and not run.consumer_worker_id:
            run.consumer_worker_id = self._worker_for(run.consumer_request_id)

        producer = self._exchange_for(run.producer_request_id)
        consumer = self._exchange_for(run.consumer_request_id)
        if producer is not None and consumer is not None:
            correlation = correlate_requests(producer, consumer, self.events)
            run.notes.append(
                "correlation: same_worker={} strength={}".format(
                    correlation.same_worker, correlation.correlation_strength
                )
            )
            run.notes.extend(correlation.missing)
            run.correlation = correlation.to_dict()
            run.producer_worker_id = correlation.producer_worker or run.producer_worker_id
            run.consumer_worker_id = correlation.consumer_worker or run.consumer_worker_id

        if self.options.canary_readback_url and nonce:
            self._finalise_canary(run, nonce)

    def _worker_for(self, request_id: str) -> Optional[str]:
        for event in self.events:
            if event.request_id == request_id and event.worker_id:
                return str(event.worker_id)
        return None

    def _exchange_for(self, request_id: Optional[str]) -> Optional[HttpExchange]:
        if not request_id:
            return None
        for item in self.store._evidence:
            if item.request_id != request_id or item.source != "http":
                continue
            exchange_data = item.data.get("exchange") or {}
            # Reconstruct only the fields the correlator needs.
            return HttpExchange(
                request_id=exchange_data.get("request_id", request_id),
                method=exchange_data.get("method", "GET"),
                url=exchange_data.get("url", self.profile.base_url),
                sent_at=exchange_data.get("sent_at", ""),
                received_at=exchange_data.get("received_at", ""),
                duration_ms=float(exchange_data.get("duration_ms", 0) or 0),
                body_preview=exchange_data.get("body_preview", ""),
            )
        return None

    def _finalise_canary(self, run: ScenarioRun, nonce: str) -> None:
        before_ref = (run.canary or {}).get("before_ref")
        before = None
        if before_ref:
            for item in self.store._evidence:
                if item.id == before_ref:
                    data = item.data.get("exchange") or {}
                    before = HttpExchange(
                        request_id=data.get("request_id", before_ref),
                        method=data.get("method", "GET"),
                        url=data.get("url", ""),
                        sent_at=data.get("sent_at", ""),
                        received_at=data.get("received_at", ""),
                        duration_ms=0,
                        body_preview=data.get("body_preview", ""),
                    )
                    break
        after, after_ref = self._readback(run, nonce, "after")
        tests = []
        for ref in run.request_refs:
            for item in self.store._evidence:
                if item.id == ref and item.source == "http":
                    data = item.data.get("exchange") or {}
                    tests.append(
                        HttpExchange(
                            request_id=data.get("request_id", ref),
                            method=data.get("method", "POST"),
                            url=data.get("url", ""),
                            sent_at=data.get("sent_at", ""),
                            received_at=data.get("received_at", ""),
                            duration_ms=0,
                            body_preview=data.get("body_preview", ""),
                        )
                    )
        assessment = check_canary(
            nonce,
            before,
            after,
            tests,
            self.events,
            expected_request_id=run.consumer_request_id or run.producer_request_id,
            expected_worker_id=run.consumer_worker_id or run.producer_worker_id,
        )
        item = self.store.add(
            "canary",
            {"assessment": assessment.to_dict(), "nonce": nonce, "reflection_exclusion": "nonce checked in every scenario HTTP body"},
            scenario_id=run.scenario_id,
            request_id=run.consumer_request_id or run.producer_request_id,
            worker_id=run.consumer_worker_id or run.producer_worker_id,
            trust="high" if assessment.verified else "low",
            notes="non-destructive canary verification",
            synthetic=self.options.synthetic,
        )
        run.canary_refs = [before_ref, after_ref, item.id]
        run.canary = assessment.to_dict()
        if assessment.verified:
            run.notes.append("canary verified independently; eligible for CODE_EXECUTION_CONFIRMED")
        else:
            run.notes.append("canary not verified: " + "; ".join(assessment.missing))

    def _readback(self, run: ScenarioRun, nonce: str, label: str):
        url = self.options.canary_readback_url or ""
        exchange = self.client.request(
            "GET",
            url,
            headers={"Accept": "text/plain", "X-P2S-Nonce": nonce},
            nonce=nonce,
            timeout=self.limits.health_timeout,
        )
        item = self.store.add_http(
            exchange,
            classify(exchange, nonce=nonce),
            scenario_id=run.scenario_id,
            trust="high",
            notes=f"canary readback {label}",
            request_id=exchange.request_id,
            synthetic=self.options.synthetic,
        )
        return exchange, item.id
