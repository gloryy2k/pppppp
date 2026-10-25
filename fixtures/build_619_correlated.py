"""Build the synthetic 619 producer/consumer fixture.

This fixture exercises the evidence, correlation and report pipeline.  It is
explicitly labelled synthetic/fixture and therefore can never yield
STALE_STATE_CONFIRMED, AFFECTED_PATH_CONFIRMED or CODE_EXECUTION_CONFIRMED.

Run from the repository root:

    python fixtures/build_619_correlated.py
    python php2shell_scanner_v4.py report fixtures/619-correlated
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from p2s.assess import assess_all  # noqa: E402
from p2s.classifier import classify  # noqa: E402
from p2s.evidence import RunStore  # noqa: E402
from p2s.http import HttpExchange  # noqa: E402
from p2s.models import CaseFile, ReachAssessment, ScenarioRun, TargetProfile  # noqa: E402
from p2s.patch import assess_patch  # noqa: E402
from p2s.report import build_document, write_reports  # noqa: E402
from p2s.telemetry import TelemetryEvent  # noqa: E402
from p2s.util import utcnow  # noqa: E402
from p2s.version import CVE_618, CVE_619, VERSION  # noqa: E402

OUT = os.path.join(ROOT, "fixtures", "619-correlated")
TARGET = "http://fixture.invalid/"
WORKER = "4242"
PRODUCER_REQ = "fixture-producer-req"
CONSUMER_REQ = "fixture-consumer-req"
BASE = "2026-10-24T12:00:00.000Z"


def _exchange(
    request_id: str,
    method: str,
    path: str,
    status: int,
    body: str,
    *,
    seconds: float,
    error_kind: str | None = None,
) -> HttpExchange:
    from datetime import datetime, timedelta, timezone

    start = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    end = start + timedelta(seconds=0.4)
    return HttpExchange(
        request_id=request_id,
        method=method,
        url=TARGET.rstrip("/") + path,
        sent_at=start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        received_at=end.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        duration_ms=400.0,
        status=status,
        response_headers={"Content-Type": "text/html"},
        body_bytes=len(body.encode("utf-8")),
        body_preview=body,
        error_kind=error_kind,
    )


def _event(
    event_type: str,
    request_id: str,
    message: str,
    *,
    seconds: float,
    phase: str,
    source: str = "lab_trace",
) -> TelemetryEvent:
    from datetime import datetime, timedelta, timezone

    moment = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return TelemetryEvent(
        source=source,
        timestamp=moment.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        message=message,
        event_type=event_type,
        severity="warning",
        request_id=request_id,
        worker_id=WORKER,
        phase=phase,
    )


def _reset_output() -> None:
    """Make the fixture reproducible; never append to a previous build."""
    import shutil

    for name in ("artifacts", "report", "report-rebuilt"):
        shutil.rmtree(os.path.join(OUT, name), ignore_errors=True)
    for name in ("evidence.jsonl", "case.json", "findings.json", "manifest.json"):
        try:
            os.remove(os.path.join(OUT, name))
        except FileNotFoundError:
            pass


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    _reset_output()
    store = RunStore(OUT, "fixture-619-correlated", TARGET, "fixture", VERSION)

    profile = TargetProfile(
        target=TARGET,
        base_url=TARGET,
        host="fixture.invalid",
        port=80,
        tls=False,
        php_version="8.2.12",
        version_source="fixture-lab-status-endpoint",
        version_trust="high",
        sapi="fpm",
        sapi_source="fixture-lab-status-endpoint",
        sapi_verified=True,
        environment_kind="fixture",
        collected_at=BASE,
        notes=[
            "Synthetic fixture: no network request was made.",
            "Version/SAPI values are invented to exercise the status ladder.",
        ],
    )
    profile.reach = ReachAssessment(
        state="REACHED",
        basis=["fixture status endpoint echoed a request id"],
        request_id=PRODUCER_REQ,
        worker_id=WORKER,
        limitations=["Synthetic fixture; not a real reachability observation."],
    )
    profile.patch = assess_patch(
        profile.php_version,
        source=profile.version_source,
        trust=profile.version_trust,
        notes=["fixture"],
    )

    producer = _exchange(
        PRODUCER_REQ,
        "POST",
        "/producer.php",
        500,
        "PHP Fatal error: Uncaught RuntimeException: producer request aborted "
        "in /var/www/producer.php on line 12",
        seconds=1.0,
    )
    producer_ev = store.add_http(
        producer,
        classify(producer),
        scenario_id="619-S2",
        trust="high",
        synthetic=True,
        notes="synthetic producer request; body is fabricated",
    )

    consumer = _exchange(
        CONSUMER_REQ,
        "GET",
        "/consumer.php",
        200,
        "consumer completed normally",
        seconds=2.0,
    )
    consumer_ev = store.add_http(
        consumer,
        classify(consumer),
        scenario_id="619-S2",
        trust="high",
        synthetic=True,
        notes="synthetic consumer request; body is fabricated",
    )

    publish = _event(
        "state_publish",
        PRODUCER_REQ,
        "request-owned global state published during interrupted shutdown",
        seconds=1.2,
        phase="shutdown",
    )
    publish_ev = store.add_telemetry(
        publish,
        scenario_id="619-S2",
        trust="high",
        synthetic=True,
        notes="synthetic lab trace; not collected from a real worker",
    )

    consume = _event(
        "state_consume",
        CONSUMER_REQ,
        "early consumer operation read state left by the previous request",
        seconds=2.1,
        phase="request_startup",
    )
    consume_ev = store.add_telemetry(
        consume,
        scenario_id="619-S2",
        trust="high",
        synthetic=True,
        notes="synthetic lab trace; not collected from a real worker",
    )

    correlation = {
        "same_worker": True,
        "producer_worker": WORKER,
        "consumer_worker": WORKER,
        "producer_ended_before_consumer": True,
        "worker_recycled_between": False,
        "producer_events": 1,
        "consumer_events": 1,
        "producer_fatal": True,
        "producer_oom": False,
        "state_published": True,
        "state_consumed": True,
        "early_consumer": True,
        "stale_marker": False,
        "address_reuse": False,
        "correlation_strength": "strong",
        "reasons": [
            "SYNTHETIC fixture: same worker PID and ordered requests were invented",
            "no pointer/address identity links the consumed state to freed memory",
        ],
        "missing": [
            "trace proving the consumed state is the freed producer request's memory",
            "patched-baseline differential",
        ],
    }
    run = ScenarioRun(
        scenario_id="619-S2",
        cve=CVE_619,
        executed=True,
        started_at=BASE,
        finished_at="2026-10-24T12:00:03.000Z",
        request_refs=[producer_ev.id, consumer_ev.id],
        telemetry_refs=[publish_ev.id, consume_ev.id],
        producer_request_id=PRODUCER_REQ,
        consumer_request_id=CONSUMER_REQ,
        producer_worker_id=WORKER,
        consumer_worker_id=WORKER,
        state_publish_refs=[publish_ev.id],
        state_consume_refs=[consume_ev.id],
        correlation=correlation,
        notes=[
            "SYNTHETIC fixture run. It demonstrates correlation reporting, not a "
            "real stale-state finding.",
        ],
    )

    case = CaseFile(
        profile=profile,
        evidence=store.load_evidence(),
        scenario_runs=[run],
        run_id="fixture-619-correlated",
        tool_version=VERSION,
        mode="fixture",
        started_at=BASE,
        finished_at=utcnow(),
        environment={
            "kind": "fixture",
            "synthetic": True,
            "telemetry_files": [],
            "limits": {},
            "note": (
                "Synthetic fixture used to exercise PRODUCER_CONSUMER_CORRELATED. "
                "It cannot produce confirmed proof statuses."
            ),
        },
        notes=["No network requests were sent while building this fixture."],
    )

    findings = assess_all(case)
    store.write_case(case)
    store.write_findings(findings)
    errors = store.verify() + case.validate()
    for finding in findings:
        errors.extend(finding.validate())
    doc = build_document(case, findings, errors)
    paths = write_reports(os.path.join(OUT, "report"), doc, findings)

    print(f"fixture: {OUT}")
    for finding in findings:
        print(f"  {finding.cve}  {finding.status}")
    print(f"integrity: {'PASS' if not errors else 'FAIL'}")
    for error in errors:
        print(f"  - {error}")
    print(f"report: {paths['markdown']}")
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
