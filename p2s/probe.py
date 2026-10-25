"""Low-impact probe mode.

Probe answers one question: can this frontend deliver a request to PHP, and
what evidence do we have for that?  It does not send OOM payloads and it never
creates a CVE finding above EXPOSED_BUILD / INCONCLUSIVE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .classifier import (
    KIND_EMPTY_BODY,
    KIND_FRONTEND_REJECT,
    KIND_OK,
    KIND_PHP_WARNING,
    KIND_PROXY_ERROR,
    classify,
)
from .http import HttpClient, HttpExchange
from .inventory import InventoryOptions, _status_endpoint, normalise_sapi
from .models import ReachAssessment, TargetProfile
from .scenarios import build_control_multipart, control_boundary, new_scenario_nonce
from .util import header_lookup, new_nonce


@dataclass
class ProbeResult:
    http_refs: List[str] = field(default_factory=list)
    reach: str = "UNKNOWN"
    blocked_by: Optional[str] = None
    observations: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    request_ids: List[str] = field(default_factory=list)
    worker_id: Optional[str] = None
    status_endpoint_verified: bool = False
    reflection_suspected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "http_refs": list(self.http_refs),
            "reach": self.reach,
            "blocked_by": self.blocked_by,
            "observations": list(self.observations),
            "limitations": list(self.limitations),
            "request_ids": list(self.request_ids),
            "worker_id": self.worker_id,
            "status_endpoint_verified": self.status_endpoint_verified,
            "reflection_suspected": self.reflection_suspected,
        }


def run_probe(
    client: HttpClient,
    profile: TargetProfile,
    store: Any,
    status_url: Optional[str] = None,
    timeout: float = 10.0,
    synthetic: bool = False,
) -> ProbeResult:
    result = ProbeResult()
    nonce = new_nonce("P2SPROBE")

    # 1. Small multipart POST.  Same shape as a benign form upload.
    body = build_control_multipart(nonce)
    exchange = client.request(
        "POST",
        profile.base_url,
        body=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={control_boundary(nonce)}",
            "X-P2S-Nonce": nonce,
        },
        nonce=nonce,
        timeout=timeout,
    )
    classification = classify(exchange, nonce=nonce)
    item = store.add_http(
        exchange,
        classification,
        scenario_id="probe-control",
        trust="high",
        notes="low-impact multipart control",
        synthetic=synthetic,
    )
    result.http_refs.append(item.id)
    result.request_ids.append(exchange.request_id)
    if classification.reflection:
        result.reflection_suspected = True
        result.observations.append(
            "The nonce was reflected in the control response body; response text cannot "
            "be used as a canary channel."
        )

    if exchange.error_kind:
        result.reach = "UNKNOWN"
        result.limitations.append(f"control POST failed: {exchange.error_kind}: {exchange.error_message}")
    elif classification.frontend_reject:
        result.reach = "BLOCKED"
        result.blocked_by = classification.detail
        result.limitations.append(
            "Control multipart was rejected by the frontend; OOM probes would not "
            "reach PHP and must not be run."
        )
    elif classification.kind in (KIND_PROXY_ERROR,):
        result.reach = "UNKNOWN"
        result.observations.append(
            "Gateway error on the control request; the request may not have reached PHP."
        )
    elif classification.kind in (KIND_PHP_WARNING,):
        result.reach = "PROBABLE"
        result.observations.append(
            "PHP diagnostic visible in the control response (display_errors may be On)."
        )
    elif classification.kind == KIND_EMPTY_BODY:
        result.observations.append("Control POST returned an empty body; cause ambiguous.")
    elif classification.php_marker:
        result.reach = "PROBABLE"
        result.observations.append("PHP-generated header/cookie present on control POST.")
    elif classification.kind == KIND_OK:
        result.reach = "PROBABLE" if classification.php_generated else "UNKNOWN"
        if result.reach == "UNKNOWN":
            result.limitations.append(
                "A successful generic response does not prove PHP processed the request."
            )

    # 2. Redirect behaviour (GET).  A redirect is recorded, not followed blindly
    #    across hosts by the client beyond its configured limit.
    redirect_exchange = client.request(
        "GET",
        profile.base_url,
        headers={"Accept": "text/html"},
        nonce=new_nonce("P2SREDIR"),
        timeout=timeout,
    )
    redirect_class = classify(redirect_exchange, nonce=redirect_exchange.nonce)
    redirect_item = store.add_http(
        redirect_exchange,
        redirect_class,
        scenario_id="probe-redirect",
        trust="high",
        notes="redirect/frontend behaviour",
        synthetic=synthetic,
    )
    result.http_refs.append(redirect_item.id)
    result.request_ids.append(redirect_exchange.request_id)
    if redirect_exchange.redirect_chain:
        result.observations.append(
            "Redirect chain: "
            + " -> ".join(f"{hop['status']} {hop['location']}" for hop in redirect_exchange.redirect_chain)
        )
    if redirect_class.frontend_reject:
        result.observations.append(f"Frontend rejected GET: {redirect_class.detail}")

    # 3. Verified status endpoint, if provided.
    status = _status_endpoint(client, status_url, timeout)
    if status is not None:
        status_exchange, payload, verified = status
        status_class = classify(status_exchange, nonce=status_exchange.nonce)
        status_item = store.add_http(
            status_exchange,
            status_class,
            scenario_id="probe-status",
            trust="high" if verified else "low",
            notes="lab status endpoint",
            synthetic=synthetic,
        )
        result.http_refs.append(status_item.id)
        result.request_ids.append(status_exchange.request_id)
        if verified:
            result.status_endpoint_verified = True
            result.reach = "REACHED"
            sapi = normalise_sapi(payload.get("sapi"))
            if sapi != "unknown":
                profile.sapi = sapi
                profile.sapi_source = "lab-status-endpoint"
                profile.sapi_verified = True
            worker = payload.get("worker_pid")
            result.worker_id = str(worker) if worker is not None else None
            profile.reach = ReachAssessment(
                state="REACHED",
                basis=["status endpoint echoed nonce and scanner request id"],
                request_id=str(payload.get("request_id") or ""),
                worker_id=result.worker_id,
                frontend=profile.frontend,
                evidence_refs=[status_item.id],
                limitations=["Reach verified only for the status endpoint path"],
            )
        else:
            result.limitations.append(
                "Status endpoint did not bind its response to the scanner request; "
                "it cannot be used as reach/worker evidence."
            )

    if result.reach == "BLOCKED":
        profile.reach = ReachAssessment(
            state="BLOCKED",
            basis=[result.blocked_by or "frontend rejection"],
            frontend=profile.frontend,
            blocked_by=result.blocked_by,
            evidence_refs=list(result.http_refs),
            limitations=list(result.limitations),
        )
    elif result.reach in ("REACHED", "PROBABLE") and profile.reach.state != "REACHED":
        profile.reach = ReachAssessment(
            state=result.reach,
            basis=list(result.observations) or ["low-impact probe"],
            request_id=result.request_ids[-1] if result.request_ids else None,
            worker_id=result.worker_id,
            frontend=profile.frontend,
            evidence_refs=list(result.http_refs),
            limitations=list(result.limitations),
        )

    result.limitations.extend(
        [
            "Probe does not test OOM, stale state, or either CVE.",
            "HTTP success/failure and keep-alive do not identify a PHP worker.",
            "A WAF/CDN may answer before PHP; headers alone cannot prove the origin.",
        ]
    )
    return result
