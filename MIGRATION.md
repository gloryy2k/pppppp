# Migration from `php2shell_scanner.py` (v3) to v4

The original scanner is still present and unmodified. v4 is a separate
entrypoint (`php2shell_scanner_v4.py`) and package (`p2s/`). You can run both
side by side while you compare results.

## 1. Why a new entrypoint

v3 mixed inventory, crash probes, session/handler checks and exploit chains in
one run, then reported a single "confidence" for the target. v4 separates:

- **inventory** — build/package/SAPI/patch facts;
- **probe** — low-impact reachability;
- **prove** — explicit bounded scenario execution;
- **exploit** — explicit destructive chain with out-of-band callback verification;
- **report** — offline reconstruction from evidence;
- **verify** — artefact hash verification.

This makes it impossible for a banner, a 502, an OOM, or a reflected marker to
silently become "VULNERABLE" or "CLEAN".

## 2. Flag mapping

| v3 | v4 | Notes |
|---|---|---|
| `python php2shell_scanner.py URL` | `python php2shell_scanner_v4.py inventory URL` | Inventory is GET-only. |
| `--all` | `inventory --all` or `probe --all` | `--all` never enables prove. |
| `--json` | `--json` | Machine-readable stdout summary. |
| `--targets FILE` | no direct equivalent | Loop over targets in your shell; each run has its own evidence directory. |
| `--sapi auto\|mod_php\|fpm` | `--sapi auto\|mod_php\|fpm\|frankenphp\|lsapi\|cli-server\|cgi-fcgi\|unknown` | Declared SAPI is not verified. `auto` stays unknown without a verified source. |
| `--timeout N` | `--timeout N` | Per-request timeout; TLS verification on by default. |
| `--probe-timeout N` | `--probe-timeout N` | Probe/health timeout. |
| `--lab-mode` | `--environment-kind lab` | A label, not relaxed proof rules. |
| `--oom` | `prove --scenario 618-S2` (or `618-S1`, `618-S3`) | Requires `--ack-authorised`; bounded. |
| `--fpm-stale` | `prove --scenario 619-S2` (or `619-S3`) | Requires same-worker telemetry for any correlation claim. |
| `--fpm-producer`, `--fpm-consumer` | `--producer-url`, `--consumer-url` | Lab harness endpoints. |
| `--handler-write`, `--handler-read` | no direct equivalent | v4 does not run handler-mismatch chains. Use a lab harness and provide telemetry. |
| `--lfi` | `exploit --chain A --lfi-path PATH` | Needs `--ack-authorised`. LFI is only a delivery vector; RCE needs a verified callback. |
| `--session-path` | `exploit --session-path` | Same guess-the-`session.save_path` caveat as v3. |
| `--exploit-lfi`, `--exploit-mismatch` | `exploit --chain A\|B\|C` | `A` = session+LFI, `B` = deserialization gadget, `C` = direct callback. Mismatch chains are still not ported. |
| `--pollute-path`, `--trigger-path`, `--inject-path` | `exploit --trigger-path`, `--inject-path` | `--pollute-path` has no equivalent; the producer step uses `/`. |
| `--command` | `exploit --command` | Passed through `shell_exec`; CR/LF/NUL are rejected. |
| `--gadget` | `exploit --gadget` | Chain B only, and it is required. The scanner ships no POP chain. Pair it with `--canary-nonce` so the callback can be correlated. |
| `--canary-nonce` | `exploit --canary-nonce` | Chain B only. Operator-supplied nonce embedded in the gadget's callback URL; requires `--callback-port`. |
| `--cleanup-race` | no direct equivalent | Exploit mode does not delete session files; clean up manually. |
| `--exploit-attempts` | `exploit --attempts` | 1..20; also bounded by `--max-requests`. |

## 3. New flags that matter

```text
--status-url URL          nonce/request-bound lab status endpoint (upgrades build/SAPI trust)
--health-url URL          health check before/after a prove scenario or exploit chain
--inventory-json FILE     operator package/build/backport evidence
--php-binary PATH         local PHP binary probe (host match checked)
--telemetry FILE          imported log/trace (repeatable)
--telemetry-source NAME   force the telemetry source label
--scenario ID             explicit prove scenario (repeatable)
--ack-authorised          required for prove and exploit
--chain A|B|C             exploit chain (exploit mode only)
--cve CVE-...             CVE label for an exploit run
--lfi-path PATH           LFI/include vector (exploit chains A/C)
--session-path PREFIX     PHP session file prefix (default /tmp/sessions/sess_)
--race-delay SECONDS      chain A upload-progress stall (0 disables; skipped on cli-server)
--inject-path PATH        session injection endpoint (default /index.php)
--trigger-path PATH       gadget trigger endpoint (exploit chain B)
--command CMD             command to run (exploit mode; default id)
--gadget PAYLOAD          serialised gadget (exploit chain B)
--canary-nonce NONCE      chain B nonce to embed in the gadget's callback URL
--callback-port N         out-of-band callback listener port (0 = auto)
--callback-bind ADDR      callback listener bind address
--callback-ip ADDR        address the target should call back to
--callback-expect ADDR    expected callback source IP (repeatable)
--attempts N              exploit attempts, 1..20
--allow-remote            permit exploit payloads against a public host
--max-requests N          request budget (prove run or exploit chain)
--max-bytes N             total byte budget
--max-request-bytes N     per-request byte cap
--max-seconds N           elapsed time cap
--concurrency N           must be 1 in prove
--allow-rerun             allow a duplicate scenario id in the same evidence set
--allow-non-advisory-sapi run a diagnostic OOM test on a SAPI the advisory did not evaluate
--synthetic-fixture       mark all evidence synthetic; confirmed statuses are refused
--insecure                disable TLS verification (explicit opt-in)
--ca-file PATH            custom CA bundle
--proxy URL               HTTP proxy
--host-header VALUE       override Host
--no-redirects            do not follow redirects
```

## 4. Output differences

v3 printed colourised check results and a single confidence. v4 writes a run
directory and prints per-CVE statuses:

```text
target : http://127.0.0.1:8099
run    : lab-618-s2-v3
  CVE-2026-109618  OOM_OBSERVED     OOM was observed in PHP ...
  CVE-2026-109619  EXPOSED_BUILD    Build/package evidence indicates ...
files  : runs/lab-618-s2-v3
```

The run directory contains `evidence.jsonl`, `artifacts/`, `case.json`,
`findings.json`, and `report/`. Every finding has `evidence_refs`,
`proof_method`, `proof_limitations`, `alternative_explanations`,
`missing_evidence`, `patch_evidence`, `remediation` and
`reproduction_context`.

Exit codes changed:

| Code | Meaning |
|---|---|
| 0 | no proof-level status and no verified exploit callback |
| 1 | a proof-level status was reached (`AFFECTED_PATH_CONFIRMED`, `PRODUCER_CONSUMER_CORRELATED`, `STALE_STATE_CONFIRMED`, `CODE_EXECUTION_CONFIRMED`), or an exploit callback was independently verified |
| 2 | validation/integrity error or bad invocation |
| 3 | matrix runner only: Docker unavailable |
| 130 | interrupted; partial evidence persisted where possible |

## 5. Behaviour changes to expect

1. **No combined verdict.** 109618 and 109619 are reported separately.
2. **`PATCH_CONFIRMED` is build/package-only.** A patched `X-Powered-By` is
   low trust and yields `INCONCLUSIVE`.
3. **Per-CVE backports.** A Debian/Ubuntu backport for 109618 does not patch
   109619 in the model.
4. **No automatic OOM in scan mode.** `inventory` and `probe` never send an OOM
   payload. `prove` requires explicit selection and authorisation.
5. **Exploit chains are opt-in and destructive.** `inventory`, `probe` and
   `prove` still do not execute commands. `exploit` does, but only with
   `--ack-authorised`, one explicit chain, a non-public target (or
   `--allow-remote`), enforced budgets, and an out-of-band callback. It refuses
   `--proxy` because it uses raw sockets. A verified callback is reported in a
   separate `exploit` section with `attribution: not_established`; it never
   promotes either CVE ladder. `CODE_EXECUTION_CONFIRMED` still requires an
   independent canary, not a reflected marker.
6. **TLS on by default.** `--insecure` is required for self-signed labs.
7. **Frontends are not crashes.** 502/503/504, 413/431, timeouts and resets are
   classified and excluded from crash/OOM conclusions.
8. **Evidence is required.** A finding cannot claim a proof status without
   evidence refs; the validator rejects it.
9. **Offline report.** `report` rebuilds findings from saved evidence with no
   network access.
10. **Batch targets are external.** v4 has no `--targets`; run one directory per
    target so evidence and hashes stay isolated.

## 6. Suggested migration steps

1. Keep the old scanner for reference; do not delete it.
2. Run `inventory` against each target and archive the run directory.
3. Run `probe` only where low-impact requests are authorised.
4. For a prepared lab, add `--status-url`, `--health-url` and `--telemetry`,
   then run one explicit scenario at a time.
5. Only in a lab you own, and only after `inventory`/`probe` show reach, use
   `exploit --chain A --ack-authorised --lfi-path ... --callback-port 0` with
   budgets. Treat a verified callback as "payload executed", not as CVE proof.
6. Use `report` to re-check conclusions from evidence; use `verify` before
   sharing a run.
7. Replace any v3 "confidence" gate in CI with an explicit allow-list of
   statuses. Do not treat `OOM_OBSERVED` or `EXPOSED_BUILD` as exploitation.

## 7. Compatibility notes

- Python 3.11+; no third-party dependencies.
- The v4 code does not import, call or parse output from
  `php2shell_scanner.py`.
- The original file's exploit functions are not part of the v4 package and are
  never fed into findings. `p2s/exploit.py` is a separate, bounded
  implementation with no import from the legacy file.
- Existing v3 JSON output is not read by v4. Re-run inventory/probe to create
  v4 evidence, or import logs with `--telemetry` and an inventory JSON file.
- Old run directories without a `canary` exploit record still rebuild: `report`
  prints `exploit NOT CONFIRMED (attribution: not_established)`.
