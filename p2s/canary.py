"""Non-destructive canary verification.

A canary is only proof when all of the following hold:

1. the nonce was absent from the readback channel before the scenario;
2. it is present afterwards on an independent readback request;
3. it never appeared in any HTTP response body produced by the scenario
   (reflection exclusion);
4. telemetry records a write of the same nonce tied to the scenario request or
   the correlated worker.

The scanner does not generate arbitrary payloads.  A lab harness may arrange a
safe, single-effect canary; this module verifies it and records how reflection
was excluded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from .http import HttpClient, HttpExchange
from .telemetry import TelemetryEvent


@dataclass
class CanaryAssessment:
    requested: bool = False
    nonce: Optional[str] = None
    readback_url: Optional[str] = None
    before_present: bool = False
    after_present: bool = False
    reflected_in_test_responses: bool = False
    telemetry_write: bool = False
    telemetry_worker_match: bool = False
    readback_verified: bool = False
    verified: bool = False
    reasons: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    before_ref: Optional[str] = None
    after_ref: Optional[str] = None
    telemetry_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requested": self.requested,
            "nonce": self.nonce,
            "readback_url": self.readback_url,
            "before_present": self.before_present,
            "after_present": self.after_present,
            "reflected_in_test_responses": self.reflected_in_test_responses,
            "telemetry_write": self.telemetry_write,
            "telemetry_worker_match": self.telemetry_worker_match,
            "readback_verified": self.readback_verified,
            "verified": self.verified,
            "reasons": list(self.reasons),
            "missing": list(self.missing),
            "before_ref": self.before_ref,
            "after_ref": self.after_ref,
            "telemetry_refs": list(self.telemetry_refs),
        }


def _contains(body: str, nonce: str) -> bool:
    return bool(nonce and nonce in (body or ""))


def check_canary(
    nonce: Optional[str],
    before: Optional[HttpExchange],
    after: Optional[HttpExchange],
    test_exchanges: Iterable[HttpExchange],
    events: Iterable[TelemetryEvent],
    expected_request_id: Optional[str] = None,
    expected_worker_id: Optional[str] = None,
) -> CanaryAssessment:
    result = CanaryAssessment(requested=bool(nonce), nonce=nonce)
    if not nonce:
        result.missing.append("no canary nonce was generated")
        return result
    if before is None or after is None:
        result.missing.append("canary readback before/after exchanges are missing")
        return result

    result.before_present = _contains(before.body_preview, nonce)
    result.after_present = _contains(after.body_preview, nonce)
    result.reasons.append(
        f"readback before={result.before_present} after={result.after_present} "
        f"(nonce {nonce})"
    )

    for exchange in test_exchanges:
        if _contains(exchange.body_preview, nonce) or _contains(exchange.body_preview, nonce.lower()):
            result.reflected_in_test_responses = True
            result.reasons.append(
                f"nonce appeared in HTTP response body of {exchange.request_id}; "
                "reflection cannot be excluded"
            )
            break

    matching = [event for event in events if event.nonce == nonce]
    for event in matching:
        if event.event_type == "canary_write":
            result.telemetry_write = True
            worker_match = bool(
                (expected_worker_id and event.worker_id == expected_worker_id)
                or (expected_request_id and event.request_id == expected_request_id)
            )
            if worker_match:
                result.telemetry_worker_match = True
            result.reasons.append(
                f"telemetry canary_write at {event.timestamp} worker={event.worker_id} "
                f"request={event.request_id}"
            )

    result.readback_verified = not result.before_present and result.after_present

    if result.before_present:
        result.missing.append("nonce was already present before the scenario (not a fresh effect)")
    if not result.after_present:
        result.missing.append("nonce did not appear on the independent readback channel")
    if result.reflected_in_test_responses:
        result.missing.append("nonce was reflected in a test response; canary is invalid")
    if not result.telemetry_write:
        result.missing.append("no telemetry canary_write event with this nonce")
    if result.telemetry_write and not result.telemetry_worker_match:
        result.missing.append(
            "canary write telemetry was not bound to the scenario request id or worker PID"
        )

    result.verified = all(
        [
            result.readback_verified,
            not result.reflected_in_test_responses,
            result.telemetry_write,
            result.telemetry_worker_match,
        ]
    )
    if result.verified:
        result.reasons.append(
            "fresh nonce observed on an independent readback, absent from all test "
            "responses, and bound to the scenario worker/request by telemetry"
        )
    return result


def read_canary(client: HttpClient, store: Any, url: str, nonce_label: str, timeout: float = 10.0):
    nonce = category = None
    exchange = client.request("GET", url, headers={"Accept": "text/plain"}, timeout=timeout)
    item = store.add_http(
        exchange,
        __import__("p2s.classifier", fromlist=["classify"]).classify(exchange),
        scenario_id=f"canary-{nonce_label}",
        trust="high",
        notes=f"canary readback ({nonce_label})",
    )
    return exchange, item.id
