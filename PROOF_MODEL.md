# Proof model

The scanner never computes a single "confidence score". Each CVE has its own
ladder, and each rung names the evidence that would be needed to climb it.

## 1. Non-negotiable rules

1. **Version exposure is not proof.** A version below 8.2.35 / 8.3.36 /
   8.4.27 / 8.5.12 is `EXPOSED_BUILD` at most.
2. **An OOM is an OOM.** `Allowed memory size ... exhausted` proves an
   allocation failed. It does not prove the 109618 invalid-state shutdown path.
3. **A worker crash is a worker failure.** A 500/502/503/504, timeout, empty
   body or connection reset is not a CVE observation.
4. **A consumer reading state is not stale state.** 109619 needs same-worker
   correlation and memory identity.
5. **A reflected marker is not execution.** A canary must be absent before,
   present after, independently read back, not reflected in test responses, and
   bound to the scenario request/worker by telemetry.
6. **No negative result proves absence.** A clean run is `INCONCLUSIVE` or
   `NOT_TESTED`, never "not vulnerable".
7. **The two CVEs are independent.** A distro backport for one advisory is
   never applied to the other (`PatchAssessment.per_cve`).
8. **A callback is execution, not attribution.** An out-of-band exploit
   callback with a matching nonce and an accepted source proves the payload
   ran. It does not prove which CVE path delivered it, so exploit results are
   kept in a separate `exploit` block with `attribution: not_established` and
   never promote either ladder.

## 2. Evidence trust

| Source | Trust | Use |
|---|---|---|
| nonce/request-bound lab status endpoint | high | build, SAPI, worker, config |
| package manifest / distro advisory / vendor attestation / build metadata | high | patch state |
| local `php` binary on the same host | high | build/SAPI |
| local `php` binary on a different host | medium | build/SAPI, target match must be checked |
| `X-Powered-By` | low | never build proof, never SAPI proof |
| `Server` header | none for SAPI | frontend hints only |
| imported PHP/web/worker logs | medium (lab trace high) | correlation and OOM |
| canary readback | high only if all checks pass | code execution |
| out-of-band exploit callback | high only if nonce + source + non-synthetic all pass | payload execution; never CVE attribution |

`--sapi auto` stays `unknown` unless a verified source supplies it. An
operator-declared `--sapi` is recorded but `sapi_verified=false`.

## 3. CVE-2026-109618 ladder

### `NOT_TESTED`
No verified build and no prove-mode scenario.

### `INCONCLUSIVE`
Inventory/probe evidence is insufficient. Typical causes: low-trust banner,
no verified SAPI, frontend blocked the probe, or a scenario ran without an OOM.

### `PREREQUISITE_OBSERVED`
- reach `REACHED`;
- `sapi_verified` and SAPI in `{mod_php, fpm, frankenphp, lsapi}`;
- no high-trust patch confirmation and no correlated OOM.

The finding lists the missing per-CVE patch evidence and the missing scenario.

### `EXPOSED_BUILD`
- per-CVE patch state `AFFECTED` with trust `high` or `medium`;
- a parsed PHP version exists.

`EXPOSED_BUILD` explicitly says "exposure only, not proof".

### `OOM_OBSERVED`
Requires at least one of:

- an HTTP response whose visible body contains a PHP OOM diagnostic and is not
  a frontend reject; or
- a PHP/worker/lab-trace event of type `oom` correlated by request id, worker
  id, or (only for identity-less diagnostics) the single-request time window.

It never claims the invalid-state path. Missing evidence names the lab trace
and the patched baseline.

### `AFFECTED_PATH_CONFIRMED`
All of the following are required:

- non-synthetic, non-fixture case;
- verified SAPI in `{mod_php, fpm, frankenphp, lsapi}`;
- a stable control request (no error, no 5xx, no frontend reject);
- OOM correlation by request id or worker id, **not** time window;
- non-synthetic `lab_trace` evidence containing:
  - `patched_baseline`; and
  - at least one of `invalid_state_processed`, `request_memory_freed`,
    `stale_global_referenced`, `use_after_free`;
- for FPM, the OOM phase must not be `startup`/`startup_like` (FPM exits the
  child on startup failure; the mod_php startup sequence does not carry over).

### `CODE_EXECUTION_CONFIRMED`
- a canary assessment with `verified=true`;
- fresh nonce, absent before, present after;
- independent readback verified;
- nonce not reflected in any test response;
- telemetry write and worker match;
- evidence source `canary`, non-synthetic;
- `reproduction_context.canary_verified=true`.

### `PATCH_CONFIRMED`
Only from build/package evidence: per-CVE state `PATCHED` with `trust=high`.
A banner claiming a fixed version is not enough.

## 4. CVE-2026-109619 ladder

### `NOT_TESTED` / `INCONCLUSIVE` / `PREREQUISITE_OBSERVED` / `EXPOSED_BUILD`
Same principles as 109618, with per-CVE patch state.

### `PRODUCER_OBSERVED`
A producer request published request-owned state and was interrupted, but no
same-worker consumer was demonstrated.

### `PRODUCER_CONSUMER_CORRELATED`
All of:

- `correlation.same_worker = true`;
- `producer_ended_before_consumer = true`;
- `worker_recycled_between = false`;
- `state_published = true` and `state_consumed = true`;
- `correlation_strength = "strong"`.

This rung says the requests were handled by the same worker and the consumer
performed an early operation. It does **not** say the consumed memory belonged
to the freed producer request.

A synthetic fixture can reach this rung, because it is a correlation exercise.
It cannot go higher.

### `STALE_STATE_CONFIRMED`
All of the above, plus:

- non-synthetic, non-fixture case;
- non-synthetic `lab_trace`;
- `patched_baseline`;
- at least one stale signal: `stale_global_consumed`,
  `stale_global_referenced`, `use_after_free`, `invalid_state_processed`;
- at least one identity signal: `address_reuse`, `use_after_free`,
  `request_memory_freed`.

Without memory identity, the report stays at
`PRODUCER_CONSUMER_CORRELATED`.

### `CODE_EXECUTION_CONFIRMED`
Same canary requirements as 109618, with the same-worker correlation required.

### `PATCH_CONFIRMED`
Per-CVE high-trust package/build evidence only.

## 5. Correlation rules

| Basis | Supports `OOM_OBSERVED` | Supports path/stale proof |
|---|---|---|
| matching request id | yes | yes |
| matching worker PID | yes | yes |
| time window only (no ids) | yes | **no** |
| HTTP keep-alive | no | no |
| same source IP | no | no |
| same TCP connection | no | no |

A worker PID is not a process identity forever. `worker_recycled_between` blocks
correlation, and `pm.max_requests`/restart behaviour must be considered.

## 6. Controls, health and budgets

Prove mode:

- records a baseline health check before any payload;
- runs a benign multipart control before the scenario body;
- checks health after each scenario;
- stops on a pre/post health transition or a latency spike above
  `max(3000 ms, 3 × baseline + 1000 ms)`;
- caps requests, bytes, per-request bytes, elapsed time and concurrency;
- writes evidence as it is produced, including on `KeyboardInterrupt`.

A 502-vs-200 difference is not a root-cause proof. The control must have
reached PHP and remained stable; a degraded control invalidates the comparison.

## 7. False-positive exclusions

| Observation | Not evidence of |
|---|---|
| `502/503/504` from proxy/WAF | PHP crash, OOM, either CVE |
| `413/431` | vulnerable path reached |
| timeout / connection reset | crash or OOM |
| opaque `500` | OOM or worker failure |
| `display_errors` warning | OOM or CVE |
| fake/hidden `X-Powered-By` | build, SAPI, patch |
| version below fixed | exploitation |
| OOM in application code | 109618 parser/startup path |
| FPM startup OOM | mod_php shutdown path |
| producer OOM alone | 109619 stale state |
| different worker PIDs | producer/consumer correlation |
| reflected nonce | code execution |
| exploit response marker or PHP source in an LFI response | code execution |
| `unserialize`/`destruction` diagnostic | code execution |
| out-of-band callback from an address other than the target | code execution |
| verified exploit callback | CVE-2026-109618/109619 attribution |
| synthetic/fixture trace | confirmed proof statuses |
| distro backport for 109618 | 109619 patch |

## 8. Integrity model

- Each evidence record is written to `evidence.jsonl` and as a canonical JSON
  artefact under `artifacts/`.
- `sha256` covers the canonical JSON of the bounded, redacted `data`.
- `verify` recomputes both the inline hash and the artefact hash.
- `report` recomputes findings from stored evidence and sends no requests.
- Hashes prove the stored evidence was not modified after collection. They do
  not prove the evidence was truthful when collected; provenance/trust labels
  are separate.
