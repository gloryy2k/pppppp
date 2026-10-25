# Limitations and honest non-claims

This file exists so a reader cannot mistake the scanner's output for more than
it is.

## 1. Environment limits in this repository

- **No Docker daemon.** The patched/unpatched matrix in `lab/matrix/` was not
  executed. The runner exits `3` and says so. It is not a pass.
- **No patched PHP.** No PHP 8.2.35+ runtime was available, so
  `PATCH_CONFIRMED` was not demonstrated on a real build.
- **No Apache mod_php.** The advisory's confirmed 109618 startup path and
  109619 backtrace/upload-progress paths were not exercised.
- **No PHP-FPM.** The advisory's FPM application path was not exercised.
- **No real worker trace.** No `lab_trace` with `patched_baseline`,
  `invalid_state_processed`, `address_reuse` or `use_after_free` exists here.
- **No real canary.** No independent readback against a real target was
  verified.
- **No code execution in scan/prove mode.** `inventory`, `probe` and `prove`
  contain no exploit chain. `CODE_EXECUTION_CONFIRMED` remains unreachable
  through those modes in this environment.
- **Exploit mode is destructive and separate.** `p2s/exploit.py` sends real
  command-execution payloads and can write PHP code into session files. It is
  gated by `--ack-authorised`, refuses public targets by default, enforces
  budgets and requires an out-of-band callback for any RCE claim. No end-to-end
  exploit run with a real callback is included here; only unit tests.

Consequently these statuses were **not** reached here:
`AFFECTED_PATH_CONFIRMED`, `STALE_STATE_CONFIRMED`,
`CODE_EXECUTION_CONFIRMED`, `PATCH_CONFIRMED`.

## 2. Black-box HTTP limits

Remote HTTP cannot observe:

- PHP request memory or allocator state;
- request startup/shutdown ordering;
- whether request shutdown processed invalid state;
- whether two requests were handled by the same worker;
- whether a consumer read memory owned by a freed producer request;
- whether an OOM came from the parser/startup path or application code.

A response body can show a PHP OOM diagnostic only when `display_errors` is on
or the application prints it. With `display_errors=Off` the OOM is invisible to
HTTP and must come from imported telemetry.

A 500/502/503/504, timeout, empty body or connection reset can be produced by a
proxy, WAF, CDN, upstream timeout, maintenance or application code. v4 records
these as classifications, never as crash proof.

## 3. Telemetry limits

- Log lines often have no request id or worker PID. The scanner may attach an
  identity-less `oom`/`fatal` line by the single-request time window; that
  supports at most `OOM_OBSERVED`, never `AFFECTED_PATH_CONFIRMED`.
- Time-window correlation assumes roughly synchronised clocks and a sequential
  run. Clock skew, buffering, log rotation and delayed writes can break it.
- A worker PID can be reused after a restart. `worker_recycled_between` blocks
  correlation, but the scanner cannot always detect recycling.
- `pm.max_requests`, Apache child recycling, container restarts and supervisor
  behaviour can all change worker identity between requests.
- Imported logs are only as trustworthy as their source. A lab trace is
  high-trust only when the operator controls it; a production log may be
  incomplete, filtered or attacker-influenced.
- PHP log lines beginning with `[` are parsed as bracketed timestamps; malformed
  or non-PHP lines are retained as parse errors rather than silently dropped,
  but they still may not correlate.

## 4. Build and patch limits

- `X-Powered-By` is low trust: it can be spoofed, stripped, or describe a
  different layer. It never yields `PATCH_CONFIRMED` or verified SAPI.
- The `Server` header is not SAPI evidence.
- A local `php -v` probe describes the host it ran on. If the target is a
  different host, trust is downgraded and the match is marked unverified.
- Packaged versions below the upstream fixed release are `UNKNOWN` unless
  backport evidence is supplied. A distro may have backported one advisory but
  not the other; v4 tracks patch state per CVE.
- The parser understands common version suffixes but not every vendor epoch or
  packaging scheme. Unparseable versions are `UNKNOWN`, not guessed.
- Branches outside 8.2/8.3/8.4/8.5 are not extrapolated. The advisory publishes
  fixed releases only for those branches.
- A patched banner is not a patched build.

## 5. Status-endpoint limits

`--status-url` is an operator-supplied lab endpoint. v4 trusts it only when it
echoes the per-request nonce **and** the scanner request id, and it uses that to
upgrade build/SAPI trust. This proves the response is bound to the scanner's
request; it does not prove the endpoint is honest, uncompromised, or describing
the same host as the tested application. A malicious or misconfigured status
endpoint can lie consistently.

## 6. Canary limits

`CODE_EXECUTION_CONFIRMED` requires:

- a fresh nonce;
- absent before, present after;
- an independent readback;
- no reflection in any test response;
- telemetry binding the write to the scenario request/worker;
- non-synthetic evidence.

Even then, the canary proves a code-execution effect in the lab harness. It does
not by itself identify which internal PHP primitive produced it, and it does not
prove the effect is reachable on an uninstrumented production target. A
synthetic fixture can never claim this status.

## 7. Exploit-mode limits

- A verified out-of-band callback proves that the injected payload executed.
  It does **not** prove that CVE-2026-109618 or CVE-2026-109619 is the cause.
  The report therefore keeps `attribution: not_established` and leaves both
  CVE ladders untouched.
- Response markers (`___START___`/`___END___`) are display-only. An LFI that
  returns the session file verbatim produces markers plus PHP source; that is
  reflection, not execution.
- A `unserialize`/`destruction` diagnostic is not execution and is not accepted.
- Chain A and C need `session.upload_progress.enabled=1`, a writable session
  path, and an LFI/include primitive. Chain B additionally needs `--gadget`
  (an application-specific POP chain, which the scanner does not provide) and
  the advisory's same-worker precondition, which exploit mode cannot prove
  without telemetry.
- A serialised gadget is static, so chain B cannot insert the scanner's runtime
  nonce into it. Use `--canary-nonce` together with `--callback-port` and embed
  that value in the gadget's callback URL; otherwise any callback fails the
  nonce check and RCE cannot be confirmed. Use a fresh nonce per run.
- Chain B's producer phase posts a ~2 MiB part-header bomb. On single-process
  `cli-server` this terminates the PHP process (observed as a connection reset
  and a dead server), so the gadget step never runs. Chain B needs a
  multi-worker SAPI (mod_php/FPM) and a target where an OOM does not take the
  whole service down.
- Chain A/C also need the session file to survive until the LFI request. The PHP
  default `session.upload_progress.cleanup=1` deletes it at request end; the lab
  used `cleanup=0`. With cleanup on, use a concurrent server and a working
  upload-progress race. Single-threaded `cli-server` cannot provide that race,
  so exploit mode skips the stall there rather than blocking itself.
- The LFI request must not reuse the injection session id: `session_start()`
  would lock the file that `include()` is about to read (on Windows this showed
  up as an empty body). Exploit mode sends no session cookie on the LFI request.
- `--session-path` must match the target's `session.save_path`; the default
  `/tmp/sessions/sess_` is a guess, not a discovery. On Windows, PHP also treats
  `~` specially in this path, so use a full non-shortened path.
- Callback verification depends on the source address. NAT, a reverse proxy or
  a multi-homed target can make the callback arrive from an address that does
  not resolve to the target; supply `--callback-expect` explicitly in that case.
- Commands run through `shell_exec`/`system` on the target's shell. Windows
  targets are not supported by the POSIX shell quoting used here.
- The mode leaves session files and other artefacts on the target. It does not
  clean them up.
- Request/byte/time budgets are enforced, but a target can still be destabilised
  by the OOM producer or by repeated attempts. Health checks only show
  reachability, not internal state.

## 8. Prove-mode limits

- Scenarios are bounded and may not reach OOM on a target with a large
  `memory_limit` or a frontend that rejects the body.
- The default 618-S2 header bomb is about 5,000 headers × 400 bytes (~2.1 MB).
  A 2,500-header variant did not OOM at `memory_limit=16M`; results are
  configuration-dependent.
- `cli-server` is not evaluated by either advisory. An OOM there is
  `OOM_OBSERVED`, never `AFFECTED_PATH_CONFIRMED`.
- FPM exits the child on startup failure, so a startup-phase OOM is not the
  mod_php shutdown path. v4 refuses to carry that conclusion across SAPIs.
- Prove mode is sequential by design. It refuses `concurrency > 1` because
  worker correlation and health checks require ordering.
- Health checks can themselves fail because the service is down. That is
  recorded as degradation, not as a CVE signal.
- The scanner does not restart services, clean up sessions, or repair a target.
  An OOM can leave a lab service down; restart it yourself.

## 9. Report and evidence limits

- `verify` proves the stored evidence was not modified after collection. It does
  not prove the evidence was truthful when collected.
- `case.json` and `findings.json` are not covered by the evidence hash chain.
  Someone with write access to the run directory can edit the case and re-run
  `report`. Treat the run directory as sensitive and compare it with the
  original collection logs.
- `report` does not contact the target and does not revalidate that the target
  still exists or is unchanged. It reports what the saved evidence supports.
- A verified exploit callback is read only from a hashed `canary` record that a
  scenario run references. `environment.exploit` is an operator convenience
  copy, not evidence.
- Hashes cover the bounded, redacted artefact, not the full unbounded wire body.
  Large bodies are truncated at `--max-body`.
- Redaction removes common secret headers/fields but cannot guarantee that every
  application-specific secret is gone. Review evidence before sharing.
- There is no multi-target batch mode. Use one run directory per target so
  evidence and hashes stay isolated.

## 10. Scope limits

- v4 assesses only CVE-2026-109618 and CVE-2026-109619. Other PHP
  vulnerabilities, framework bugs and application logic are out of scope.
- `inventory`, `probe` and `prove` do not test session/LFI chains,
  handler-mismatch gadgets, webshell uploads or arbitrary command execution.
- `exploit` can send session/LFI and deserialization payloads for those two
  CVEs only. It does not enumerate gadgets, upload webshells, exfiltrate files
  or persist access, and it never assigns a CVE status from a callback.
- v4 does not decide whether a target is "vulnerable" or "clean". It reports the
  highest status the evidence supports and names what is missing.
- The two CVE verdicts are independent. Do not combine them into one score.

## 11. What would change the conclusions

To reach `AFFECTED_PATH_CONFIRMED` for 109618, provide:

- a real mod_php or post-startup FPM run;
- a correlated OOM with request/worker identity;
- non-synthetic lab trace with `patched_baseline` and an invalid-state event;
- a stable control and a patched-build differential.

To reach `STALE_STATE_CONFIRMED` for 109619, provide:

- a real producer/consumer run on the same worker;
- non-synthetic trace with `patched_baseline` plus a stale signal;
- memory identity (`address_reuse`, `use_after_free` or
  `request_memory_freed`).

To reach `CODE_EXECUTION_CONFIRMED`, provide a verified independent canary
readback bound to the request/worker, with reflection excluded.

To attribute a verified exploit callback to 109618/109619, add the
CVE-specific evidence above (correlated OOM or same-worker stale state). A
callback alone keeps `attribution: not_established`.

Until then, the honest answers are `INCONCLUSIVE`, `PREREQUISITE_OBSERVED`,
`EXPOSED_BUILD`, `OOM_OBSERVED` or `PRODUCER_CONSUMER_CORRELATED`, with the
missing evidence listed in the finding.
