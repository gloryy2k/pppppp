# Changelog

All notable changes to php2shell v4 are documented here.

## [4.0.0] — 2026-10-31

### Added

- **7 operating modes**: inventory, probe, prove, exploit, auto, report, verify
- **Auto mode** — end-to-end 6-step pipeline: inventory → probe → 7-phase
  discovery → exploit chains → assess → report
- **6 exploit chains** in priority order: WRAPPER → LOG_POISON → A → C → D → B
- **Chain D** — pure OOM mod_php exploitation without LFI:
  - 4-strategy cascade: cookie_leak → error_leak → blind_spray → aslr_brute
  - 37 offset profiles (28 verified Debian + 9 estimated Ubuntu/RHEL)
  - Covers PHP 8.0–8.4 on x86_64 and aarch64
  - Hard 200-request budget with timing jitter (50–200ms)
  - Custom offset profiles via `--chain-d-offsets`
- **WRAPPER chain** — php:// stream wrapper injection via auto mode discovery
- **LOG_POISON chain** — error log poisoning + LFI via auto mode discovery
- **Discovery engine** — 7-phase attack surface enumeration: phpinfo extraction,
  spider, LFI vectors, php:// wrappers, session upload_progress, log poisoning
  paths, OOM probe (chunked TE)
- **Evidence-first proof model** — per-CVE status ladders with mandatory evidence
  refs; no status inferred from HTTP codes, banners, or crashes
- **Out-of-band callback verification** — RCE confirmed only by callback with
  matching nonce and verified source IP
- **192 tests** across 7 test files covering schema, exploit chains A/B/C/D,
  assessment, classification, parsing, and HTTP client
- **Lab Docker setup** — Apache mod_php + nginx/FPM containers for local testing
- **Patched/unpatched matrix** — `lab/matrix/` for differential testing
- CLI options: `--chain-d-offsets`, `--callback-ip`, `--exec-func`,
  `--max-discover-requests`, `--max-exploit-requests`, `--skip-discovery`

### Safety

- `inventory` and `probe` are read-only — no OOM payloads
- `prove`/`exploit`/`auto` require `--ack-authorised`
- Public targets refused by default (`--allow-remote` to override)
- Chain D enforces 200-request budget and timing jitter
- SAPI inference from Server header marked unverified with warning
- Chunked TE stripping detected — Chain D aborts on WAF/proxy interference
- TLS verification on by default
- Response markers never accepted as code execution proof

### Documentation

- PROOF_MODEL.md — evidence requirements per status level
- COVERAGE.md — what is lab-proven vs. unverified
- SCHEMA.md — evidence/report/finding data formats
- LIMITATIONS.md — known limits and non-claims
- MIGRATION.md — mapping from v3 to v4
