"""Tool metadata and advisory facts.

The facts below are transcribed from the two official php-src advisories.
Keep this file boring: it is the single source of truth for version ranges
and SAPI notes used by every assessor.
"""

VERSION = "4.0.0"
TOOL_NAME = "php2shell-evidence-scanner"

CVE_618 = "CVE-2026-109618"
CVE_619 = "CVE-2026-109619"
CVES = (CVE_618, CVE_619)

ADVISORIES = {
    CVE_618: {
        "ghsa": "GHSA-w8hw-w9fx-j79w",
        "url": "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
        "title": "RCE via OOM corruption",
        "severity": "critical",
        "cwe": ["CWE-416", "CWE-755", "CWE-824", "CWE-1325", "CWE-1419"],
        "fixed": {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12},
        "affected_text": "< 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12",
        "summary": (
            "PHP uses longjmp() for OOM. In some contexts request memory is "
            "temporarily reachable before it is fully initialised; an allocation "
            "failure there leaves request memory invalid. Request shutdown may "
            "then read or branch on it. Multiple multipart OOM strategies reach "
            "this state. Confirmed RCE on Apache mod_php; FPM is supported as "
            "susceptible by source analysis but no complete FPM exploit was "
            "demonstrated for the startup path (FPM exits the child on startup "
            "failure)."
        ),
    },
    CVE_619: {
        "ghsa": "GHSA-6wmf-4rv5-p3rp",
        "url": "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
        "title": "RCE via stale global state",
        "severity": "critical",
        "cwe": ["CWE-416", "CWE-755", "CWE-824", "CWE-1325", "CWE-1419"],
        "fixed": {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12},
        "affected_text": "< 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12",
        "summary": (
            "Worker-persistent global state can point at request-owned memory. "
            "If a producer request publishes such state and is interrupted "
            "(fatal/OOM) before its matching reset, a consumer operation in a "
            "later request handled by the same worker may use the stale state. "
            "Confirmed consumers include pre-initialisation INI diagnostics and "
            "session upload progress. Producer and consumer must hit the same "
            "worker; request/worker correlation is mandatory evidence."
        ),
    },
}

# Fixed versions keyed by (major, minor).  These are the only branches for
# which the advisory publishes fixed releases.
FIXED_VERSIONS = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

# SAPI classification, straight from the advisories.  "confirmed" means the
# advisory reports a validated exploit path, "source-analysis" means the
# advisory only supports susceptibility from source review.
SAPI_NOTES = {
    "mod_php": {
        "618": "confirmed-startup-path",
        "619": "confirmed",
        "note": "Apache mod_php invokes request shutdown even when request "
                "startup failed. 618 startup OOM and 619 fatal-backtrace / "
                "upload-progress paths were validated here.",
    },
    "fpm": {
        "618": "post-startup-only",
        "619": "confirmed-application-path",
        "note": "FPM exits the child when request startup fails, so the "
                "mod_php startup sequence does not carry over. Post-startup "
                "OOM remains supported by source analysis; 619 upload-progress "
                "RCE was validated with an application producer.",
    },
    "frankenphp": {
        "618": "source-analysis-only",
        "619": "not-established",
        "note": "Advisory: analogous to mod_php, likely susceptible; no "
                "validated exploit.",
    },
    "lsapi": {
        "618": "source-analysis-only",
        "619": "conditional",
        "note": "Advisory: models FPM; application-specific exploits likely "
                "but unvalidated.",
    },
    "cli-server": {
        "618": "not-covered",
        "619": "not-covered",
        "note": "The advisory does not evaluate the PHP built-in CLI server. "
                "OOM can be observed here, but it is not evidence for the "
                "advisory's affected path.",
    },
    "cgi-fcgi": {
        "618": "not-covered",
        "619": "not-covered",
        "note": "Not evaluated by either advisory.",
    },
    "unknown": {
        "618": "unknown",
        "619": "unknown",
        "note": "No verified SAPI source. Server/X-Powered-By headers are not "
                "accepted as SAPI evidence.",
    },
}

SUSCEPTIBLE_SAPI_618 = {"mod_php", "fpm", "frankenphp", "lsapi"}
SUSCEPTIBLE_SAPI_619 = {"mod_php", "fpm", "frankenphp", "lsapi"}

# Advisory workaround scope.  These are configuration risk reductions, not
# complete mitigations, and they are attached to the CVE they actually cover.
REMEDIATION = {
    CVE_618: [
        "Upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later "
        "(the only complete mitigation).",
        "If upgrading is impossible, administratively set memory_limit=-1 and "
        "restart every worker; this removes the predictable control point but "
        "is not complete (mmap/underlying allocation failure can still longjmp).",
        "Keep post_max_size conservative and enforce the decoded request size "
        "independently at the frontend.",
        "Bound multipart parts, headers per part, input nesting and uploads; "
        "reject multipart bodies entirely if the application does not use them.",
        "Do not use RLIMIT_AS/RLIMIT_DATA as a mitigation: they make mmap fail "
        "and can re-enter the vulnerable longjmp path.",
        "Disabling session.upload_progress is NOT a mitigation for 109618.",
    ],
    CVE_619: [
        "Upgrade to PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later "
        "(the only reliable mitigation; there is no complete generic config fix).",
        "PHP 8.5 only: set fatal_error_backtraces=0 administratively and restart "
        "every worker to remove the confirmed backtrace producer.",
        "Session lifecycle path only: set session.upload_progress.enabled=0 "
        "administratively and restart every worker. This does not cover other "
        "state families.",
        "Remove attacker-reachable fatal errors (including request timeouts) and "
        "diagnostics emitted before request initialisation or during cleanup.",
        "Prefer startup php.ini / FPM pool configuration over per-request INI "
        "overrides; remove obsolete or invalid directives.",
        "Consider pm.max_requests=1 to shorten worker state lifetime.",
    ],
}
