"""Response classification.

This module deliberately refuses to infer a vulnerability from a status code.
It answers narrower questions:

  * did a frontend reject the request before PHP?
  * is the response a PHP-generated fatal / warning?
  * if it was OOM, where did PHP say it happened?
  * is the body merely reflecting our nonce?
  * is there any evidence the web worker died?

The answers feed assessors; they are not conclusions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .http import HttpExchange
from .util import header_lookup

KIND_OK = "OK"
KIND_REDIRECT = "REDIRECT"
KIND_FRONTEND_REJECT = "FRONTEND_REJECT"
KIND_PROXY_ERROR = "PROXY_ERROR"
KIND_ORIGIN_ERROR = "ORIGIN_ERROR"
KIND_PHP_OOM = "PHP_OOM"
KIND_PHP_FATAL = "PHP_FATAL"
KIND_PHP_WARNING = "PHP_WARNING"
KIND_PHP_NOTICE = "PHP_NOTICE"
KIND_EMPTY_BODY = "EMPTY_BODY"
KIND_TIMEOUT = "NETWORK_TIMEOUT"
KIND_RESET = "CONNECTION_RESET"
KIND_TLS = "TLS_ERROR"
KIND_DNS = "DNS_ERROR"
KIND_NETWORK = "NETWORK_ERROR"
KIND_AUTH = "AUTH_REQUIRED"
KIND_NOT_FOUND = "NOT_FOUND"
KIND_UNKNOWN = "UNKNOWN"

OOM_RE = re.compile(
    r"Allowed memory size of\s+(\d+)\s+bytes exhausted\s*"
    r"(?:\(tried to allocate\s+(\d+)\s+bytes\))?"
    r"(?:\s+in\s+(.+?)\s+on line\s+(\d+))?",
    re.IGNORECASE,
)
FATAL_RE = re.compile(r"\bPHP\s+(Fatal error|Parse error|Core error)\s*:\s*(.*)", re.IGNORECASE)
WARNING_RE = re.compile(r"\bPHP\s+(Warning|Notice|Deprecated)\s*:\s*(.*)", re.IGNORECASE)
EXEC_TIME_RE = re.compile(r"Maximum execution time of\s+\d+\s+seconds exceeded", re.IGNORECASE)
STARTUP_RE = re.compile(r"(PHP Request Startup|PHP Startup|Unable to start PHP)", re.IGNORECASE)

PROXY_HEADERS = (
    "via",
    "x-cache",
    "x-served-by",
    "cf-ray",
    "cf-cache-status",
    "x-varnish",
    "x-fastly-request-id",
    "x-akamai-transformed",
    "x-amz-cf-id",
    "x-proxy-id",
    "x-bluecoat-via",
)
PROXY_SERVER_MARKERS = (
    "nginx",
    "cloudflare",
    "akamai",
    "varnish",
    "fastly",
    "squid",
    "haproxy",
    "envoy",
    "traefik",
    "imperva",
    "incapsula",
    "big-ip",
    "f5",
)
WAF_BODY_MARKERS = (
    "request blocked",
    "web application firewall",
    "modsecurity",
    "access denied",
    "the requested url was rejected",
    "attention required",
    "request rejected",
    "security policy",
    "incapsula incident id",
    "cloudflare ray id",
    "not acceptable",
    "request entity too large",
    "request header or cookie too large",
)


@dataclass
class Classification:
    kind: str = KIND_UNKNOWN
    detail: str = ""
    status: int = 0
    oom: bool = False
    oom_context: str = "none"  # startup_like | script | unknown | none
    oom_limit_bytes: Optional[int] = None
    oom_location: Optional[str] = None
    oom_line: Optional[int] = None
    php_generated: bool = False
    php_marker: bool = False
    display_errors: bool = False
    frontend_reject: bool = False
    proxy: bool = False
    gateway_error: bool = False
    origin_error: bool = False
    worker_crash_suspected: bool = False
    empty_body: bool = False
    reflection: bool = False
    execution_timeout: bool = False
    startup_error: bool = False
    markers: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "status": self.status,
            "oom": self.oom,
            "oom_context": self.oom_context,
            "oom_limit_bytes": self.oom_limit_bytes,
            "oom_location": self.oom_location,
            "oom_line": self.oom_line,
            "php_generated": self.php_generated,
            "php_marker": self.php_marker,
            "display_errors": self.display_errors,
            "frontend_reject": self.frontend_reject,
            "proxy": self.proxy,
            "gateway_error": self.gateway_error,
            "origin_error": self.origin_error,
            "worker_crash_suspected": self.worker_crash_suspected,
            "empty_body": self.empty_body,
            "reflection": self.reflection,
            "execution_timeout": self.execution_timeout,
            "startup_error": self.startup_error,
            "markers": list(self.markers),
            "limitations": list(self.limitations),
        }


def detect_frontend(headers: Dict[str, str]) -> Dict[str, Any]:
    """Return frontend hints.  Never identifies the PHP SAPI."""
    hints: List[str] = []
    server = header_lookup(headers, "Server").lower()
    for marker in PROXY_SERVER_MARKERS:
        if marker in server:
            hints.append(f"Server contains {marker}")
    for name in PROXY_HEADERS:
        if header_lookup(headers, name):
            hints.append(f"header {name}")
    return {
        "proxy_or_cdn_hints": hints,
        "server": header_lookup(headers, "Server"),
        "is_proxy_likely": bool(hints),
    }


def classify(exchange: HttpExchange, nonce: Optional[str] = None) -> Classification:
    c = Classification(status=exchange.status)
    body = exchange.body_preview or ""
    low = body.lower()
    headers = exchange.response_headers or {}

    if exchange.error_kind:
        mapping = {
            "timeout": (KIND_TIMEOUT, "request timed out"),
            "reset": (KIND_RESET, "connection reset without a complete response"),
            "tls_verification": (KIND_TLS, "TLS certificate verification failed"),
            "tls": (KIND_TLS, "TLS handshake failed"),
            "dns": (KIND_DNS, "DNS resolution failed"),
            "redirect_loop": (KIND_REDIRECT, "redirect limit exceeded"),
            "network": (KIND_NETWORK, "network error"),
        }
        c.kind, c.detail = mapping.get(exchange.error_kind, (KIND_NETWORK, exchange.error_kind))
        c.limitations.append("A network error is not a PHP crash observation.")
        return c

    frontend = detect_frontend(headers)
    c.proxy = frontend["is_proxy_likely"]
    c.php_marker = bool(header_lookup(headers, "X-Powered-By")) or "phpsessid" in header_lookup(
        headers, "Set-Cookie"
    ).lower()

    oom = OOM_RE.search(body)
    if oom:
        c.oom = True
        c.kind = KIND_PHP_OOM
        c.oom_limit_bytes = int(oom.group(1))
        location = (oom.group(3) or "").strip()
        c.oom_location = location or None
        try:
            c.oom_line = int(oom.group(4)) if oom.group(4) else None
        except ValueError:
            c.oom_line = None
        if location.lower() in ("unknown", ""):
            c.oom_context = "startup_like"
            c.detail = "PHP OOM reported in Unknown/0 (startup-like context, not proof)"
        else:
            c.oom_context = "script"
            c.detail = f"PHP OOM reported in {location} (may be application code)"
        c.display_errors = True
        c.php_generated = True
        c.php_marker = True
        c.markers.append("php_oom_text")
        c.limitations.append(
            "An OOM message proves an allocation failed; it does not prove the "
            "CVE-2026-109618 invalid-state path or its root cause."
        )
        return c

    if EXEC_TIME_RE.search(body):
        c.execution_timeout = True
        c.kind = KIND_PHP_FATAL
        c.detail = "Maximum execution time exceeded (fatal interruption)"
        c.php_generated = True
        c.display_errors = True
        c.markers.append("php_execution_timeout")
        c.limitations.append(
            "A timeout fatal can be a 109619 producer interruption but is not proof "
            "of stale state."
        )
        return c

    fatal = FATAL_RE.search(body)
    if fatal:
        c.kind = KIND_PHP_FATAL
        c.detail = f"PHP {fatal.group(1)}: {fatal.group(2)[:300]}"
        c.php_generated = True
        c.php_marker = True
        c.display_errors = True
        c.markers.append("php_fatal_text")
        c.startup_error = bool(STARTUP_RE.search(body))
        return c

    warn = WARNING_RE.search(body)
    if warn:
        c.kind = KIND_PHP_WARNING
        c.detail = f"PHP {warn.group(1)}: {warn.group(2)[:300]}"
        c.php_generated = True
        c.php_marker = True
        c.display_errors = True
        c.markers.append("php_diagnostic_text")
        c.limitations.append(
            "A PHP warning/notice is a code-path observation. It is not proof of "
            "CVE-2026-109618 or CVE-2026-109619."
        )
        return c

    if nonce and nonce in body:
        c.reflection = True
        c.markers.append("nonce_reflected_in_body")

    if exchange.status in (301, 302, 303, 307, 308):
        c.kind = KIND_REDIRECT
        c.detail = f"HTTP {exchange.status} redirect to {header_lookup(headers, 'Location')[:200]}"
        return c

    if exchange.status in (413, 431):
        c.kind = KIND_FRONTEND_REJECT
        c.frontend_reject = True
        c.detail = f"HTTP {exchange.status} (request rejected before/at the frontend)"
        c.markers.append(f"http_{exchange.status}")
        c.limitations.append(
            "413/431 is a size/header rejection and must not be reported as a crash "
            "or as evidence the vulnerable path was reached."
        )
        return c

    if exchange.status in (502, 503, 504):
        c.kind = KIND_PROXY_ERROR if c.proxy else KIND_ORIGIN_ERROR
        c.gateway_error = True
        c.origin_error = exchange.status == 503 and not c.proxy
        c.detail = f"HTTP {exchange.status} from a gateway/origin; cause unknown"
        c.markers.append(f"http_{exchange.status}")
        c.limitations.append(
            "A 502/503/504 is not proof of a PHP worker crash, an OOM, or either CVE. "
            "It can be generated by a proxy, WAF, upstream timeout or maintenance."
        )
        return c

    if exchange.status == 500:
        c.kind = KIND_ORIGIN_ERROR
        c.origin_error = True
        c.detail = "HTTP 500 without a PHP diagnostic in the visible body"
        c.limitations.append(
            "An opaque HTTP 500 is not evidence of OOM, worker failure or either CVE."
        )
        return c

    if exchange.status in (401, 403):
        if exchange.status == 403 and any(marker in low for marker in WAF_BODY_MARKERS):
            c.kind = KIND_FRONTEND_REJECT
            c.frontend_reject = True
            c.detail = "HTTP 403 with a WAF/block page body"
            c.markers.append("waf_body")
        else:
            c.kind = KIND_AUTH
            c.detail = f"HTTP {exchange.status} (access control)"
        return c

    if exchange.status == 404:
        c.kind = KIND_NOT_FOUND
        c.detail = "HTTP 404"
        return c

    if exchange.status == 429:
        c.kind = KIND_FRONTEND_REJECT
        c.frontend_reject = True
        c.detail = "HTTP 429 rate limit"
        c.markers.append("rate_limited")
        return c

    if 200 <= exchange.status < 400:
        if exchange.body_bytes == 0 and exchange.method != "HEAD":
            c.kind = KIND_EMPTY_BODY
            c.empty_body = True
            c.detail = f"HTTP {exchange.status} with an empty body"
            c.limitations.append(
                "An empty body is ambiguous: application output, proxy suppression, "
                "or a crashed request can all produce it."
            )
            return c
        c.kind = KIND_OK
        c.detail = f"HTTP {exchange.status}"
        c.php_generated = c.php_marker
        return c

    c.kind = KIND_UNKNOWN
    c.detail = f"HTTP {exchange.status} ({exchange.reason})"
    return c


def proxy_evidence(exchange: HttpExchange) -> Dict[str, Any]:
    return detect_frontend(exchange.response_headers or {})
