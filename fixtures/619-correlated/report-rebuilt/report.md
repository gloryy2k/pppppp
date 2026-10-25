# php2shell exposure and proof report — http://fixture.invalid/

- Run: `fixture-619-correlated`
- Tool: `php2shell-evidence-scanner 4.0.0`
- Mode: `report`
- Generated: `2026-10-23T18:13:39.429Z`
- Environment: `fixture` **(SYNTHETIC/FIXTURE)**

## 1. Executive summary

| CVE | Status | Why | Scenario |
|---|---|---|---|
| CVE-2026-109618 | **EXPOSED_BUILD** | Build/package evidence indicates an affected PHP version (8.2.12); exposure only, not proof. | `inventory` |
| CVE-2026-109619 | **PRODUCER_CONSUMER_CORRELATED** | Producer state publication and an early consumer operation are correlated to the same worker across request boundaries; stale memory identity is not yet proven. | `619-S2` |

The two CVE verdicts are independent. No combined confidence is computed and PATCH_CONFIRMED comes only from build/package evidence.

> **Warning:** this report was built from fixture/synthetic evidence. It demonstrates the reporting pipeline and must not be used as proof that a real target is vulnerable or patched.

## 2. Environment

- Target: `http://fixture.invalid/`
- PHP build: `8.2.12` (source: fixture-lab-status-endpoint, trust: high)
- SAPI: `fpm` (source: fixture-lab-status-endpoint, verified: True)
- Patch: `AFFECTED` (trust: high); CVE-2026-109618: PHP 8.2.12 is below fixed release 8.2.35.; CVE-2026-109619: PHP 8.2.12 is below fixed release 8.2.35.
- Reachability: `REACHED`
  - fixture status endpoint echoed a request id
- Frontend hints: `{}`
- Telemetry imported: none

## 3. Scenarios run / not run

| Scenario | CVE | Executed | Producer | Consumer | Reason / conclusion |
|---|---|---|---|---|---|
| `619-S2` | CVE-2026-109619 | yes | `fixture-producer-req` | `fixture-consumer-req` | SYNTHETIC fixture run. It demonstrates correlation reporting, not a real stale-state finding. |

## 4. Timeline: request → PHP → worker → log/trace → conclusion

| Time (UTC) | Phase | Source | Scenario | Request | Worker | Observation | Evidence |
|---|---|---|---|---|---|---|---|
| 2026-10-24T12:00:01.200Z | telemetry | lab_trace | `619-S2` | `fixture-producer-req` | `4242` | state_publish: request-owned global state published during interrupted shutdown | `EV-0003` |
| 2026-10-24T12:00:01.400Z | http | http | `619-S2` | `fixture-producer-req` | `-` | POST http://fixture.invalid/producer.php -> 500 (PHP_FATAL) | `EV-0001` |
| 2026-10-24T12:00:02.100Z | telemetry | lab_trace | `619-S2` | `fixture-consumer-req` | `4242` | state_consume: early consumer operation read state left by the previous request | `EV-0004` |
| 2026-10-24T12:00:02.400Z | http | http | `619-S2` | `fixture-consumer-req` | `-` | GET http://fixture.invalid/consumer.php -> 200 (OK) | `EV-0002` |

## 5. Proof, controls and false-positive exclusion

### Evidence artefacts

| ID | Source | Scenario | SHA-256 | Synthetic |
|---|---|---|---|---|
| `EV-0003` | lab_trace | `619-S2` | `50a8b83763ec89ad…` | True |
| `EV-0001` | http | `619-S2` | `8719233d16700cae…` | True |
| `EV-0004` | lab_trace | `619-S2` | `73ddde65095dfbda…` | True |
| `EV-0002` | http | `619-S2` | `ecddb4fe7ff11bdc…` | True |

### Canary

No canary was configured/verified. `CODE_EXECUTION_CONFIRMED` was therefore not claimed.

### Controls

No control request was recorded for this run.

A control request must reach PHP and be stable before a test result can be compared. A 502-vs-200 difference alone is not a root-cause proof.

## 6. Limits: what is not proven

- THIS IS A FIXTURE/SYNTHETIC REPORT. It exercises the evidence and report pipeline; it is not proof about a real deployment.
- Remote black-box HTTP cannot observe PHP request memory, shutdown ordering or worker-internal state.
- A negative result does not prove absence of either vulnerability.
- HTTP status codes (500/502/503/504), timeouts, empty bodies and connection resets are not crash or CVE evidence.
- X-Powered-By is low trust and is never used for PATCH_CONFIRMED.
- OOM proves an allocation failure, not the CVE-2026-109618 invalid-state path.
- A worker crash is a worker failure, not automatically either CVE.
- HTTP keep-alive is not evidence that two requests used the same PHP worker.
- Evidence hashes cover the stored, bounded/redacted artefact, not the full unbounded wire body.
- Timing correlation alone cannot establish same-worker identity.
- CVE-2026-109618: No negative result proves absence of the vulnerability.
- CVE-2026-109618: An HTTP 500/502/503/504, timeout, empty body or connection reset is not evidence of OOM or of CVE-2026-109618.
- CVE-2026-109618: A PHP OOM proves only that an allocation failed; it does not prove the invalid-state shutdown path.
- CVE-2026-109618: OOM observed in application code has a different root cause from the advisory's startup/parser path.
- CVE-2026-109618: A worker crash is a worker failure, not automatically this CVE.
- CVE-2026-109618: EXPOSED_BUILD is an exposure assessment; no CVE path was exercised.
- CVE-2026-109619: HTTP keep-alive does not identify a PHP-FPM worker; same-worker proof needs a worker PID or equivalent telemetry.
- CVE-2026-109619: A single OOM is not proof of stale global state.
- CVE-2026-109619: A consumer reading state is not proof that the state belonged to a freed request.
- CVE-2026-109619: An HTTP 500/502/503/504, timeout or empty body is not producer/consumer evidence.
- CVE-2026-109619: No negative result proves absence of the vulnerability.

## 7. Recommendations

### CVE-2026-109618

- Upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later (the only complete mitigation).
- If upgrading is impossible, administratively set memory_limit=-1 and restart every worker; this removes the predictable control point but is not complete (mmap/underlying allocation failure can still longjmp).
- Keep post_max_size conservative and enforce the decoded request size independently at the frontend.
- Bound multipart parts, headers per part, input nesting and uploads; reject multipart bodies entirely if the application does not use them.
- Do not use RLIMIT_AS/RLIMIT_DATA as a mitigation: they make mmap fail and can re-enter the vulnerable longjmp path.
- Disabling session.upload_progress is NOT a mitigation for 109618.

### CVE-2026-109619

- Upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later (the only reliable mitigation; there is no complete generic config fix).
- PHP 8.5 only: set fatal_error_backtraces=0 administratively and restart every worker to remove the confirmed backtrace producer.
- Session lifecycle path only: set session.upload_progress.enabled=0 administratively and restart every worker. This does not cover other state families.
- Remove attacker-reachable fatal errors (including request timeouts) and diagnostics emitted before request initialisation or during cleanup.
- Prefer startup php.ini / FPM pool configuration over per-request INI overrides; remove obsolete or invalid directives.
- Consider pm.max_requests=1 to shorten worker state lifetime.

## Questions the report answers

- **Did the test request reach PHP?** `REACHED` — fixture status endpoint echoed a request id
- **Did OOM actually occur in PHP?** `NO/NOT PROVEN`
- **At what stage?** `n/a`
- **Which worker?** `4242`
- **What links the observation to the CVE?** CVE-2026-109618: build/package inventory; CVE-2026-109619: telemetry: state_publish + same worker PID + producer end before consumer + consumer early operation
- **Is there a patched/unpatched control?** patch=`AFFECTED`; baseline observed=False
- **Highest conclusion actually supported?** CVE-2026-109618: EXPOSED_BUILD; CVE-2026-109619: PRODUCER_CONSUMER_CORRELATED

## Integrity and reproduction

- Evidence items: 4
- Hash verification: PASS
- Hash covers: canonical JSON of the bounded, redacted evidence data

Re-run the report without sending requests:

```
python php2shell_scanner_v4.py report <evidence-dir> --out <report-dir>
```

`<evidence-dir>` is the directory containing this run's `evidence.jsonl` and `case.json` (run id `fixture-619-correlated`).

Verify the stored artefact hashes without network access:

```
python php2shell_scanner_v4.py verify <evidence-dir>
```

