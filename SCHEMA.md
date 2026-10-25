# Schema

The scanner writes four persisted objects:

| File | Object |
|---|---|
| `manifest.json` | run metadata and hash convention |
| `evidence.jsonl` | one `Evidence` record per line (append-only) |
| `case.json` | `CaseFile`: profile, scenario runs, environment |
| `findings.json` | one `Finding` per CVE |
| `report/report.json` | rendered report document (`php2shell-report/1`) |

Samples:

- `schema/sample-report.json` — full report from the synthetic 619 fixture.
- `schema/sample-findings.jsonl` — the two findings from that report.
- `schema/sample-evidence.json` — one evidence record with its artefact hash.

## 1. Evidence

```json
{
  "id": "EV-0001",
  "source": "http",
  "timestamp": "2026-10-24T12:00:01.400Z",
  "correlation_id": "fixture-producer-req",
  "request_id": "fixture-producer-req",
  "worker_id": null,
  "data": {
    "exchange": { "...": "bounded HttpExchange fields" },
    "classification": { "...": "response classification" }
  },
  "sha256": "d6545557bcfb7369...64 hex chars...",
  "artifact_path": "artifacts/EV-0001-619-S2.json",
  "scenario_id": "619-S2",
  "trust": "high",
  "redacted": true,
  "truncated": false,
  "notes": "synthetic producer request; body is fabricated",
  "synthetic": true
}
```

Required by validation:

- `id` non-empty and unique within the case;
- `source` in `http`, `php_log`, `web_server_log`, `worker_telemetry`,
  `host_inventory`, `lab_trace`, `canary`, `operator`;
- `timestamp` parseable ISO-8601;
- `sha256` 64 lowercase hex characters;
- `trust` in `high`, `medium`, `low`, `none`;
- `data` is a JSON object.

Every record is also written as `artifacts/<id>-<scenario-or-source>.json`.
`verify` checks the inline hash and the artefact hash.

`synthetic` is `true` for every record created under `--synthetic-fixture`
(HTTP, telemetry, health and canary records alike), and for records built by
the fixture generator. It is a per-record provenance flag, not a claim about
the target.

### HTTP `data`

`exchange` contains request/response metadata: `request_id`, `method`, `url`,
`sent_at`, `received_at`, `duration_ms`, request/response headers (redacted),
body byte counts and hashes, bounded `body_preview`, `error_kind`,
`error_message`, `redirect_chain`, `nonce`, `peer`, `tls_verified`.

`classification` contains the classifier output: `kind`, `detail`, `status`,
`oom`, `oom_context`, `oom_limit_bytes`, `oom_location`, `oom_line`,
`php_generated`, `php_marker`, `display_errors`, `frontend_reject`, `proxy`,
`gateway_error`, `origin_error`, `worker_crash_suspected`, `empty_body`,
`reflection`, `execution_timeout`, `startup_error`, `markers`, `limitations`.

### Telemetry `data`

```json
{
  "event": {
    "source": "php_log",
    "timestamp": "2026-10-23T17:49:28.000Z",
    "message": "PHP Fatal error: Allowed memory size ...",
    "event_type": "oom",
    "severity": "fatal",
    "request_id": null,
    "worker_id": null,
    "pid": null,
    "nonce": null,
    "sapi": null,
    "phase": "startup_like",
    "raw": "...",
    "line_no": 1,
    "extra": {}
  }
}
```

Event types used by the assessors include `oom`, `fatal`, `diagnostic`,
`worker_exit`, `worker_start`, `state_publish`, `state_consume`,
`stale_global_consumed`, `stale_global_referenced`, `use_after_free`,
`address_reuse`, `request_memory_freed`, `invalid_state_processed`,
`patched_baseline`, `worker_recycle`.

### Exploit callback `data` (`source="canary"`)

Exploit mode stores a verified or rejected out-of-band callback as its own
hashed record. The report reads this record, not `environment.exploit`.

```json
{
  "assessment": {
    "requested": true,
    "exploit_chain": "A",
    "nonce": "P2SEXPLOIT...",
    "verified": true,
    "readback_verified": true,
    "nonce_match": true,
    "source_ip_match": true,
    "source_check": "127.0.0.1 is a resolved/explicit target address",
    "uses_response_content": false,
    "reflected_in_test_responses": false,
    "payload_seen_in_test_responses": false,
    "command_output_present": true,
    "remote_addr": "127.0.0.1",
    "remote_port": 4242,
    "expected_sources": ["127.0.0.1"],
    "cve_attribution": "not_established",
    "reasons": [],
    "missing": []
  },
  "nonce": "P2SEXPLOIT...",
  "callback": {
    "timestamp": "2026-10-24T12:00:03.000Z",
    "remote_addr": "127.0.0.1",
    "remote_port": 4242,
    "method": "GET",
    "path": "/cb/P2SEXPLOIT.../uid%3D33",
    "has_command_output": true,
    "command_output": "uid=33(www-data)"
  }
}
```

`trust` is `high` only when the callback is verified and non-synthetic;
otherwise it is `low`. A verified record must have `verified`,
`nonce_match` and `source_ip_match` all true, and both
`uses_response_content` and `reflected_in_test_responses` false. The
`assessment.exploit_chain` field is required: a canary record without it is
ignored by the exploit reader.

## 2. Finding

Required fields (validated):

```json
{
  "cve": "CVE-2026-109619",
  "status": "PRODUCER_CONSUMER_CORRELATED",
  "scenario_id": "619-S2",
  "evidence_refs": ["EV-0001", "EV-0002", "EV-0003", "EV-0004"],
  "proof_method": "telemetry: state_publish + same worker PID + ...",
  "proof_limitations": ["..."],
  "alternative_explanations": ["..."],
  "missing_evidence": ["..."],
  "patch_evidence": {
    "state": "AFFECTED",
    "trust": "high",
    "per_cve": {
      "CVE-2026-109618": {"state": "AFFECTED", "trust": "high", "details": "..."},
      "CVE-2026-109619": {"state": "AFFECTED", "trust": "high", "details": "..."}
    }
  },
  "remediation": ["..."],
  "reproduction_context": {
    "target": "http://fixture.invalid/",
    "environment_kind": "fixture",
    "synthetic": true,
    "php_version": "8.2.12",
    "sapi": "fpm",
    "sapi_verified": true,
    "scenario_ids": ["619-S2"],
    "producer_request_ids": ["fixture-producer-req"],
    "consumer_request_ids": ["fixture-consumer-req"],
    "worker_ids": ["4242"],
    "run_id": "fixture-619-correlated",
    "tool_version": "4.0.0",
    "mode": "fixture",
    "limits": {},
    "telemetry_files": [],
    "canary": {}
  },
  "status_reason": "...",
  "observations": [],
  "advisory": {"ghsa": "...", "url": "...", "title": "...", "fixed": {}},
  "generated_at": "2026-10-24T12:00:04.000Z"
}
```

Validation rules:

- `cve` must be one of the two supported CVEs.
- `status` must belong to that CVE's enum.
- proof statuses require non-empty `evidence_refs`;
- `CODE_EXECUTION_CONFIRMED` requires
  `reproduction_context.canary_verified = true`;
- `PATCH_CONFIRMED` requires `patch_evidence.state = PATCHED` or
  `patch_evidence.per_cve[cve].state = PATCHED`.

### Status enums

CVE-2026-109618:

```
NOT_TESTED, INCONCLUSIVE, PREREQUISITE_OBSERVED, EXPOSED_BUILD,
OOM_OBSERVED, AFFECTED_PATH_CONFIRMED, CODE_EXECUTION_CONFIRMED,
PATCH_CONFIRMED
```

CVE-2026-109619:

```
NOT_TESTED, INCONCLUSIVE, PREREQUISITE_OBSERVED, EXPOSED_BUILD,
PRODUCER_OBSERVED, PRODUCER_CONSUMER_CORRELATED, STALE_STATE_CONFIRMED,
CODE_EXECUTION_CONFIRMED, PATCH_CONFIRMED
```

`PATCH_CONFIRMED` is not part of the proof ladder; it is a build/package
conclusion.

## 3. ScenarioRun

```json
{
  "scenario_id": "618-S2",
  "cve": "CVE-2026-109618",
  "executed": true,
  "skipped_reason": "",
  "started_at": "2026-10-24T12:00:00.000Z",
  "finished_at": "2026-10-24T12:00:02.000Z",
  "request_refs": ["EV-0001"],
  "control_refs": ["EV-0002"],
  "health_refs": ["EV-0003"],
  "telemetry_refs": ["EV-0004"],
  "trace_refs": [],
  "canary_refs": [],
  "producer_request_id": "req-...",
  "consumer_request_id": null,
  "producer_worker_id": null,
  "consumer_worker_id": null,
  "oom_refs": ["EV-0004"],
  "state_publish_refs": [],
  "state_consume_refs": [],
  "correlation": {},
  "canary": {},
  "interrupted": false,
  "notes": []
}
```

All `*_refs` must resolve to evidence ids in the same case; `case.validate()`
reports dangling references.

An exploit run also creates a ScenarioRun (`scenario_id` like `exploit-A`) with
`canary_refs` pointing at the callback record. `run.canary` mirrors the
callback assessment (`verified`, `exploit_chain`, `nonce_match`,
`source_ip_match`, `cve_attribution`). An authorised invocation produces a run
even when the chain stops early (for example a missing `--lfi-path`); in that
case `notes` carries the error text. Refused invocations (no
`--ack-authorised`, unknown chain, out-of-range attempts) return before any
run is created.

## 4. CaseFile

`case.json`:

```json
{
  "run_id": "lab-618-s2-v3",
  "tool_version": "4.0.0",
  "mode": "prove",
  "started_at": "...",
  "finished_at": "...",
  "profile": {
    "target": "...", "base_url": "...", "host": "...", "port": 80,
    "tls": false, "php_version": "8.2.12", "version_source": "...",
    "version_trust": "high", "sapi": "cli-server", "sapi_source": "...",
    "sapi_verified": true, "patch": {}, "reach": {},
    "environment_kind": "lab", "packaging": null, "build_metadata": {},
    "config": {}, "frontend": {}, "collected_at": "...", "notes": []
  },
  "scenario_runs": [],
  "environment": {
    "kind": "lab",
    "synthetic": false,
    "telemetry_files": [],
    "limits": {},
    "started_at": "...",
    "stopped_reason": "...",
    "interrupted": false
  },
  "notes": []
}
```

`environment.synthetic=true` or `environment.kind="fixture"` is a hard guard:
the assessors refuse `AFFECTED_PATH_CONFIRMED`, `STALE_STATE_CONFIRMED` and
`CODE_EXECUTION_CONFIRMED` even if the fixture contains matching trace events.

In `mode="exploit"`, `environment` additionally carries:

| Field | Meaning |
|---|---|
| `probe` | the low-impact probe summary collected before the chain |
| `exploit` | the chain's own result: chain, cve, success, callback, budget, notes, errors, limitations |
| `limits` | the request/byte/time budget snapshot |
| `degraded` | health check degraded after the chain |
| `exploit_assessment` | derived from hashed `canary` evidence; `confirmed`, `attribution`, `chains`, `evidence_refs`, `reasons` |

`environment.exploit` is a convenience copy for operators. It is not hashed
evidence and must never be the source of an RCE conclusion; use
`environment.exploit_assessment`, which only reads evidence records.

## 5. Report document

Top-level keys (`schema_version = php2shell-report/1`):

| Key | Meaning |
|---|---|
| `schema_version` | report schema id |
| `generated_at` | render time |
| `tool_version`, `run_id`, `mode`, `target` | provenance |
| `environment` | build, SAPI, patch, reach, config, frontend, limits; exploit results in `mode=exploit` |
| `executive_summary.verdicts` | separate verdict per CVE, never merged |
| `findings` | full findings with all required fields |
| `scenarios` | scenario runs, including skipped ones |
| `exploit` | out-of-band callback result: `confirmed`, `attribution`, `chains`, `evidence_refs`, `reasons`, `limitations` |
| `timeline` | timestamp-ordered request → PHP → worker → log/trace rows |
| `evidence_index` | id, source, scenario, request, worker, summary, hash |
| `proof` | canaries, controls, artefact hashes |
| `answers` | reach, OOM stage, worker, linkage, patched control, code execution, highest conclusion |
| `limitations` | global and per-finding limits |
| `remediation` | per-CVE recommendations |
| `integrity` | evidence count, verification result, hash algorithm/scope |

The `exploit` block is present even when no exploit ran:

```json
{
  "confirmed": false,
  "chains": [],
  "evidence_refs": [],
  "command_output": null,
  "attribution": "not_established",
  "synthetic": false,
  "reasons": ["no accepted out-of-band exploit callback was found in the evidence"],
  "limitations": ["..."]
}
```

A confirmed block lists one entry per accepted callback
(`chain`, `scenario_id`, `cve_label`, `evidence_ref`, `remote_addr`,
`command_output`, `attribution`). `attribution` is always
`not_established`: the report does not claim which CVE delivered the execution.

`answers.code_execution_observed` is the short form:

```json
{
  "confirmed": true,
  "attribution": "not_established",
  "chains": ["A"],
  "evidence_refs": ["EV-0007"],
  "note": "Out-of-band exploit callback. It proves payload execution, not which CVE path delivered it; the CVE verdicts above are independent."
}
```

Rendered outputs:

- `report.json` — machine-readable document;
- `findings.jsonl` — one finding per line;
- `report.md` — the human report;
- `report.html` — dependency-free HTML view.

Required human sections are present in `report.md`: executive summary with
separate verdicts, environment, scenarios, timeline, proof/canary/hash/controls,
exploit callback, limits, and per-CVE remediation.

## 6. Hashing

- Canonical JSON: sorted keys, compact separators, UTF-8.
- `sha256` covers `canonical_json(data)` after bounding/redaction.
- `verify` checks both `evidence.jsonl` inline data and
  `artifacts/<id>-*.json`.
- A hash mismatch is an integrity error and makes the report fail closed.
