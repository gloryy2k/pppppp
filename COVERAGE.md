# Coverage: what is proven, what is only observable, what is unverified

This file is deliberately conservative. "Lab-proven" means the scenario was
executed against a real PHP process in this repository, evidence was persisted,
and `verify` passed. It does **not** mean the CVE was exploited unless the
status says so.

## 1. Executed in this environment

| Area | Environment | Result | Evidence |
|---|---|---|---|
| Build inventory | real PHP 8.2.12, `cli-server`, nonce/request-bound status endpoint | both CVEs `EXPOSED_BUILD` | `runs/lab-618-s2-v3` |
| Reachability probe | same lab | `REACHED`; status endpoint verified | `runs/lab-618-s2-v3` |
| 618-S2 OOM observation | same lab, `memory_limit=16M` | real PHP OOM, server process died; **`OOM_OBSERVED`** | `EV-0009`, `EV-0010`, `EV-0011` in `runs/lab-618-s2-v3` |
| 619 producer/consumer correlation | synthetic fixture only | **`PRODUCER_CONSUMER_CORRELATED`** | `fixtures/619-correlated` |
| Offline report rebuild | both runs | `report` reproduced the same verdicts without network | `report/` in each run |
| Hash verification | both runs | PASS | `verify` output |
| Exploit chain C | real PHP 8.2.12 `cli-server`, `session.upload_progress.cleanup=0`, local LFI | **RCE observed via out-of-band callback**; CVE attribution `not_established` | `runs/lab-exploit-c4` |
| Exploit chain A | same lab, upload-progress injection + LFI | **RCE observed via out-of-band callback**; CVE attribution `not_established` | `runs/lab-exploit-a2` |
| Chain D helpers | unit tests only (no live target) | heap leak parser, ASLR candidate generation, blind spray body builder, offset profile loader all tested | `tests/test_chain_d.py` (33 tests) |
| Auto mode orchestrator | not executed against live target | unit/integration coverage pending | — |

The real run's exact verdicts:

```text
CVE-2026-109618  OOM_OBSERVED      OOM was observed in PHP and correlated to the scenario request,
                                  but the advisory-specific invalid-state path is not proven.
CVE-2026-109619  EXPOSED_BUILD     Build/package evidence indicates an affected PHP version (8.2.12);
                                  exposure only, not proof.
```

`cli-server` is **not evaluated** by either advisory. The observed OOM is
therefore an OOM observation, not `AFFECTED_PATH_CONFIRMED`.

## 2. Scenario coverage

| Scenario | CVE | Advisory SAPI | Executed here? | Highest status reached | Why it stops there |
|---|---|---|---|---|---|
| `618-S1` | 109618 | mod_php, FPM, FrankenPHP, LSAPI | no | — | Requires an advisory-compatible SAPI and telemetry/trace. |
| `618-S2` | 109618 | mod_php, FPM, FrankenPHP, LSAPI | yes, on `cli-server` | `OOM_OBSERVED` | OOM is real; no lab trace of invalid-state shutdown; SAPI not covered. |
| `618-S3` | 109618 | mod_php, FPM, FrankenPHP, LSAPI | no | — | Same trace requirement as 618-S2. |
| `618-S4` | 109618 | mod_php, FPM, FrankenPHP, LSAPI | no | — | Needs `--app-oom-endpoint`/`--app-oom-field`; application OOM never proves the parser path. |
| `619-S1` | 109619 | mod_php | no | — | Lab-only; needs a harness that emits fatal backtrace state and a later INI diagnostic. |
| `619-S2` | 109619 | mod_php | no (only a synthetic fixture) | `PRODUCER_CONSUMER_CORRELATED` (fixture) | Real same-worker evidence is absent; fixture cannot claim stale state. |
| `619-S3` | 109619 | FPM, FrankenPHP, LSAPI | no | — | Lab-only; needs an application producer and consumer harness. |

The fixture is **not** a lab run. It is explicitly `environment.kind=fixture`
and `synthetic=true`, and the assessors refuse to promote it beyond
`PRODUCER_CONSUMER_CORRELATED`.

## 3. SAPI coverage

| SAPI | Advisory position | Verified here |
|---|---|---|
| Apache mod_php | 618 startup path confirmed; 619 fatal-backtrace and upload-progress paths confirmed | **no** — no mod_php runtime was available |
| PHP-FPM | 618 post-startup only (startup OOM exits the child); 619 application path confirmed | **no** — no FPM runtime was available |
| FrankenPHP | 618 source-analysis only; 619 not established | **no** |
| LSAPI | 618 source-analysis only; 619 conditional | **no** |
| `cli-server` | not evaluated by either advisory | **yes**, but cannot support `AFFECTED_PATH_CONFIRMED` |
| `cgi-fcgi` | not evaluated | **no** |
| unknown | no verified source | treated as unknown; headers are not SAPI evidence |

## 4. Status coverage

| Status | Reached here? | Notes |
|---|---|---|
| `NOT_TESTED` | yes (ordinary inventory cases) | No build and no scenario. |
| `INCONCLUSIVE` | yes | Low-trust banner, no verified SAPI, or no path evidence. |
| `PREREQUISITE_OBSERVED` | yes | Reach + advisory SAPI verified, build/path missing. |
| `EXPOSED_BUILD` | yes | High-trust affected build; never proof. |
| `OOM_OBSERVED` | yes | Real 618-S2 OOM on `cli-server`. |
| `AFFECTED_PATH_CONFIRMED` | **no** | Needs non-synthetic lab trace plus patched baseline. |
| `PRODUCER_OBSERVED` | no (fixture goes further) | Real producer telemetry without a consumer. |
| `PRODUCER_CONSUMER_CORRELATED` | yes, **fixture only** | Same-worker fixture telemetry; not real. |
| `STALE_STATE_CONFIRMED` | **no** | Needs non-synthetic pointer/UAF/freed-memory identity trace. |
| `CODE_EXECUTION_CONFIRMED` | **no** | Needs a verified independent canary bound to request/worker. |
| `PATCH_CONFIRMED` | **no** | Needs a real patched build/package with high trust. |

## 5. Exploit chain coverage

| Chain | Technique | CVE | Lab-proven RCE? | Unit tests |
|---|---|---|---|---|
| **A** | Session `upload_progress` injection + LFI | 109618 | yes (`runs/lab-exploit-a2`) | 34 tests in `test_exploit.py` |
| **B** | Session deserialization gadget | 109619 | no (needs operator POP chain + multi-worker SAPI) | 34 tests in `test_exploit.py` |
| **C** | Direct callback via upload_progress filename | 109618 | yes (`runs/lab-exploit-c4`) | 34 tests in `test_exploit.py` |
| **D** | Pure OOM mod_php (no LFI) | 109618 | no (no mod_php lab available) | 33 tests in `test_chain_d.py` |
| **WRAPPER** | php:// stream wrapper injection | 109618 | no (discovery + auto mode only) | — |
| **LOG_POISON** | Error log poisoning + LFI | 109618 | no (discovery + auto mode only) | — |

Chain D uses a 4-strategy cascade (cookie_leak → error_leak → blind_spray →
aslr_brute) with 37 offset profiles (28 verified Debian + 9 estimated
Ubuntu/RHEL). All helper functions are unit-tested; the end-to-end orchestrator
(`_try_chain_d_rce`) has not been executed against a live mod_php target.

WRAPPER and LOG_POISON chains are integrated into the auto mode discovery
pipeline. They have no standalone exploit subcommand and no dedicated test
coverage yet.

## 6. Auto mode coverage

Auto mode (`auto` subcommand) runs a 6-step pipeline:

1. **Inventory** — collect target profile
2. **Probe** — test multipart upload reachability
3. **Discovery** — 7-phase attack surface enumeration (phpinfo → spider → LFI →
   wrappers → session upload_progress → log poisoning → OOM probe)
4. **Exploit chains** — tried in priority order: WRAPPER → LOG_POISON → A → C → D → B
5. **Assess** — aggregate findings
6. **Report** — generate structured output

**Not executed** against a live target in this environment. The orchestrator
(`_run_auto`, ~400 lines in `cli.py`) has no unit tests. Discovery phases
(`discover.py`, 1,507 lines) have no tests.

## 7. Remote-only observations

Against a real remote target, the scanner can honestly produce:

- `NOT_TESTED` / `INCONCLUSIVE` / `PREREQUISITE_OBSERVED`;
- `EXPOSED_BUILD` only when a high/medium-trust build or package source is
  supplied (`--inventory-json`, `--php-binary` with a host match, or a verified
  lab status endpoint);
- `PATCH_CONFIRMED` only from a high-trust package/build source;
- `OOM_OBSERVED` only if PHP OOM text is visible in an HTTP response or in
  imported telemetry that correlates to the request.

Remote black-box HTTP cannot produce `AFFECTED_PATH_CONFIRMED`,
`STALE_STATE_CONFIRMED` or `CODE_EXECUTION_CONFIRMED`. Those require
worker-internal telemetry/trace, and the scanner will name the missing evidence
instead of guessing.

`exploit` mode is different in kind, not in rigour. It may observe an
out-of-band callback that proves the payload executed, but it reports that in a
separate `exploit` block with `attribution: not_established`. It does not turn
the callback into `CODE_EXECUTION_CONFIRMED`, and it does not promote either
CVE ladder. The local lab run (`runs/lab-exploit-a2`, `runs/lab-exploit-c4`)
proves that chain A/C can execute a payload on a deliberately LFI-vulnerable
`cli-server` harness; it does not show that the advisory's OOM/stale-state
primitive delivered it.

## 8. Patched/unpatched matrix: unexecuted

`lab/matrix/` contains pinned compose services for:

- Apache mod_php 8.2.34 (affected) and 8.2.35 (fixed);
- nginx + PHP-FPM 8.2.34 (affected) and 8.2.35 (fixed).

**The matrix has not been executed in this environment.** Docker CLI exists but
the daemon pipe `dockerDesktopLinuxEngine` is absent:

```text
Docker daemon unavailable; the matrix was NOT executed.
reason: error during connect: ... open //./pipe/dockerDesktopLinuxEngine: The system cannot find the file specified.
```

`lab/matrix/run_matrix.py --ack-authorised` exits `3` in this state. That is an
unverified environment, not a pass. When Docker is available, run:

```bash
python lab/matrix/run_matrix.py --ack-authorised
```

It will still not claim `AFFECTED_PATH_CONFIRMED` without the trace events the
assessors require. The matrix is for observing OOM, patch skipping, worker
behaviour and report integrity across builds; it is not a substitute for the
lab trace.

## 9. What the evidence in this repository does not show

- No patched PHP 8.2.35+ build was executed.
- No Apache mod_php or PHP-FPM process was exercised.
- No real worker PID correlation was collected for CVE-2026-109619.
- No lab trace contains `invalid_state_processed`, `patched_baseline`,
  `address_reuse` or `use_after_free`.
- No canary readback was verified against a real target.
- Chain B was not completed against the lab: it needs an operator-supplied POP
  chain, and its ~2 MiB part-header bomb terminates single-process `cli-server`
  (observed: connection reset, server process exited) before the gadget step.
  A serialised gadget is also static, so chain B needs `--canary-nonce` to make
  its callback correlatable.
- The exploit lab used `session.upload_progress.cleanup=0`. With the PHP default
  (`cleanup=1`), chain A/C needs a concurrent server or a working upload race;
  single-threaded `cli-server` cannot provide that race.
- No code execution, shell, file write or command output from a real target is
  present in any evidence set outside the local lab runs.
- Chain D was not executed against a real mod_php target. Its 4-strategy cascade
  and 37 offset profiles are tested only at the unit level.
- 9 offset profiles (Ubuntu/RHEL) are estimated from nearest Debian build and
  have not been verified in a lab.
- Auto mode's 7-phase discovery pipeline and chain priority orchestrator were
  not executed end-to-end against a live target.
- WRAPPER and LOG_POISON chains have no test coverage and have not been
  executed outside of the auto mode code path.
