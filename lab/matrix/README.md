# Patched/unpatched Docker matrix

**Status in this repository: UNEXECUTED.** The Docker daemon was unavailable
(`dockerDesktopLinuxEngine` pipe missing). `run_matrix.py --ack-authorised`
exits `3` and says so. Do not record this matrix as a pass.

## What it contains

| Service | PHP | SAPI | Port |
|---|---|---|---|
| `apache-affected` | 8.2.34 | Apache mod_php | 18180 |
| `apache-patched` | 8.2.35 | Apache mod_php | 18181 |
| `fpm-affected` | 8.2.34 | nginx + PHP-FPM | 18182 |
| `fpm-patched` | 8.2.35 | nginx + PHP-FPM | 18183 |

`php-matrix.ini` sets `memory_limit=16M` so the bounded 618-S2 header bomb can
reach an OOM on a lab box. That is a lab control, not a production claim.
`lab/v4/www` is mounted read-only, including the nonce/request-bound
`status.php`.

## Run

```bash
python lab/matrix/run_matrix.py --ack-authorised
```

The runner:

1. refuses to run without `--ack-authorised`;
2. checks `docker info` and exits `3` if unavailable;
3. starts compose and waits for `/status.php`;
4. runs `inventory`, `probe`, `prove 618-S2` and `prove 619-S2` against each
   target;
5. captures compose logs to `runs/<target>/compose.log` and passes that file as
   `--telemetry` while prove runs;
6. leaves evidence under `lab/matrix/runs/<target>/`;
7. shuts compose down unless `--keep-up` is given.

## What it can and cannot establish

It can show:

- real OOM observations on affected builds;
- that a high-trust patched build skips the OOM payload;
- worker behaviour and health degradation across builds;
- evidence/report integrity across runs.

It cannot, by itself, establish:

- `AFFECTED_PATH_CONFIRMED` (needs the invalid-state trace and patched
  baseline);
- `STALE_STATE_CONFIRMED` (needs same-worker memory identity);
- `CODE_EXECUTION_CONFIRMED` (needs a verified canary).

The assessors enforce these limits even if the matrix runs. See
`../../PROOF_MODEL.md` and `../../COVERAGE.md`.
