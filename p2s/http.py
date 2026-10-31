"""Bounded HTTP client with honest error classification.

* TLS verification is ON by default (``--insecure`` is an explicit opt-in).
* Redirects are followed manually and recorded.
* Bodies are truncated at a configured byte limit and hashed.
* A proxy / WAF response is never turned into a crash signal.
* The client never retries a mutating request implicitly.
"""

from __future__ import annotations

import http.client
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

_log = logging.getLogger(__name__)

from .util import (
    header_lookup,
    new_id,
    new_nonce,
    preview,
    redact_headers,
    redact_url,
    sha256_bytes,
    truncate_bytes,
    utcnow,
)

DEFAULT_MAX_BODY = 262144
DEFAULT_PREVIEW = 32768


class NetworkFailure(Exception):
    def __init__(self, kind: str, message: str, sent_at: Optional[str] = None):
        super().__init__(message)
        self.kind = kind
        self.message = message
        # The time the request was actually written to the socket.  Without it
        # a slow timeout/reset would be recorded at the time the exception was
        # observed, which destroys time-window log correlation.
        self.sent_at = sent_at


@dataclass
class HttpExchange:
    request_id: str
    method: str
    url: str
    sent_at: str
    received_at: str
    duration_ms: float
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body_bytes: int = 0
    request_body_sha256: str = ""
    status: int = 0
    reason: str = ""
    protocol: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    body_bytes: int = 0
    body_sha256: str = ""
    body_preview: str = ""
    body_truncated: bool = False
    error_kind: Optional[str] = None
    error_message: Optional[str] = None
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    nonce: Optional[str] = None
    peer: Optional[str] = None
    tls_verified: Optional[bool] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "method": self.method,
            "url": redact_url(self.url),
            "sent_at": self.sent_at,
            "received_at": self.received_at,
            "duration_ms": round(self.duration_ms, 3),
            "request_headers": dict(self.request_headers),
            "request_body_bytes": self.request_body_bytes,
            "request_body_sha256": self.request_body_sha256,
            "status": self.status,
            "reason": self.reason,
            "protocol": self.protocol,
            "response_headers": dict(self.response_headers),
            "body_bytes": self.body_bytes,
            "body_sha256": self.body_sha256,
            "body_preview": preview(self.body_preview.encode("utf-8", "replace"), DEFAULT_PREVIEW),
            "body_truncated": self.body_truncated,
            "error_kind": self.error_kind,
            "error_message": self.error_message,
            "redirect_chain": list(self.redirect_chain),
            "nonce": self.nonce,
            "peer": self.peer,
            "tls_verified": self.tls_verified,
            "notes": list(self.notes),
        }


class HttpClient:
    def __init__(
        self,
        base_url: str,
        timeout: float = 10.0,
        insecure: bool = False,
        max_body: int = DEFAULT_MAX_BODY,
        ca_file: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        user_agent: str = "php2shell-evidence-scanner/4.0",
        follow_redirects: bool = True,
        max_redirects: int = 5,
        host_header: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.insecure = insecure
        self.max_body = max_body
        self.ca_file = ca_file
        self.extra_headers = dict(extra_headers or {})
        self.proxy = proxy
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.host_header = host_header
        self._cached_ssl_ctx: Optional[ssl.SSLContext] = None

    # -- TLS ---------------------------------------------------------------

    def _ssl_context(self) -> ssl.SSLContext:
        if self._cached_ssl_ctx is not None:
            return self._cached_ssl_ctx
        if self.insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif self.ca_file:
            ctx = ssl.create_default_context(cafile=self.ca_file)
        else:
            ctx = ssl.create_default_context()
        self._cached_ssl_ctx = ctx
        return ctx

    # -- request plumbing --------------------------------------------------

    def _resolve(self, url_or_path: str) -> str:
        if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
            return url_or_path
        return urljoin(self.base_url, url_or_path)

    def _single_request(
        self,
        method: str,
        url: str,
        body: Optional[bytes],
        headers: Dict[str, str],
        chunked: bool,
        request_id: str,
        nonce: Optional[str],
        timeout: Optional[float] = None,
    ) -> Tuple[Dict[str, Any], int, str, str, Dict[str, str], bytes, bool, Optional[str], Optional[str]]:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        sent_at = utcnow()

        def fail(kind: str, message: str) -> NetworkFailure:
            return NetworkFailure(kind, message, sent_at=sent_at)

        if not host:
            raise fail("dns", f"URL has no host: {redact_url(url)}")

        conn = None
        start = None
        raw_headers = dict(self.extra_headers)
        raw_headers.update(headers or {})
        raw_headers["User-Agent"] = self.user_agent
        raw_headers.setdefault("Accept", "*/*")
        raw_headers.setdefault("Accept-Encoding", "identity")
        raw_headers.setdefault("Connection", "close")
        raw_headers["Host"] = self.host_header or raw_headers.get("Host") or parts.netloc.split("@")[-1]
        raw_headers["X-P2S-Request-ID"] = request_id
        if nonce:
            raw_headers["X-P2S-Nonce"] = nonce
        if body is not None:
            raw_headers["Content-Length"] = str(len(body))
            if chunked:
                raw_headers.pop("Content-Length", None)
                raw_headers["Transfer-Encoding"] = "chunked"

        proxy = urlsplit(self.proxy) if self.proxy else None
        tmo = timeout if timeout is not None else self.timeout
        try:
            if proxy:
                proxy_host = proxy.hostname
                proxy_port = proxy.port or (443 if proxy.scheme == "https" else 80)
                if parts.scheme == "https":
                    conn = http.client.HTTPSConnection(
                        proxy_host, proxy_port, timeout=tmo, context=self._ssl_context()
                    )
                    conn.set_tunnel(host, port)
                else:
                    conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=tmo)
            elif parts.scheme == "https":
                conn = http.client.HTTPSConnection(
                    host, port, timeout=tmo, context=self._ssl_context()
                )
            else:
                conn = http.client.HTTPConnection(host, port, timeout=tmo)

            _log.debug("%s %s (timeout=%.1fs)", method, redact_url(url), tmo)
            start = time.monotonic()
            request_target = url if (proxy and parts.scheme == "http") else path
            conn.putrequest(method, request_target, skip_host=True, skip_accept_encoding=True)
            for key, value in raw_headers.items():
                conn.putheader(key, value)
            if body is not None:
                conn.endheaders(body, encode_chunked=chunked)
            else:
                conn.endheaders()

            resp = conn.getresponse()
            protocol = "HTTP/1.1" if resp.version == 11 else f"HTTP/{resp.version // 10}.{resp.version % 10}"
            reason = resp.reason or ""
            status = int(resp.status)
            response_headers: Dict[str, str] = {}
            set_cookies: List[str] = []
            for key, value in resp.getheaders():
                lk = key.lower()
                if lk == "set-cookie":
                    set_cookies.append(value)
                else:
                    response_headers[key] = value
            if set_cookies:
                response_headers["Set-Cookie"] = "\n".join(set_cookies)
            raw_body = resp.read(self.max_body + 1)
            truncated = len(raw_body) > self.max_body
            if truncated:
                raw_body = raw_body[: self.max_body]
            received_at = utcnow()
            duration = (time.monotonic() - start) * 1000.0
            peer = None
            try:
                peer = str(conn.sock.getpeername()) if conn.sock else None
            except OSError:
                peer = None
            return (
                {
                    "status": status,
                    "reason": reason,
                    "protocol": protocol,
                    "headers": response_headers,
                    "body": raw_body,
                    "truncated": truncated,
                    "peer": peer,
                    "sent_at": sent_at,
                    "received_at": received_at,
                    "duration_ms": duration,
                    "request_headers": redact_headers(raw_headers),
                },
                status,
                reason,
                protocol,
                response_headers,
                raw_body,
                truncated,
                peer,
                None,
            )
        except ssl.SSLCertVerificationError as exc:
            _log.debug("TLS verification failed: %s", exc)
            raise fail("tls_verification", str(exc))
        except ssl.SSLError as exc:
            raise fail("tls", str(exc))
        except socket.gaierror as exc:
            raise fail("dns", str(exc))
        except (socket.timeout, TimeoutError) as exc:
            _log.debug("timeout: %s %s", method, redact_url(url))
            raise fail("timeout", str(exc) or "request timed out")
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as exc:
            raise fail("reset", str(exc) or "connection reset")
        except http.client.RemoteDisconnected as exc:
            raise fail("reset", "remote closed connection without a response")
        except (http.client.HTTPException, OSError) as exc:
            raise fail("network", str(exc))
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def request(
        self,
        method: str,
        path_or_url: str,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        chunked: bool = False,
        request_id: Optional[str] = None,
        nonce: Optional[str] = None,
        follow_redirects: Optional[bool] = None,
        timeout: Optional[float] = None,
    ) -> HttpExchange:
        method = method.upper()
        request_id = request_id or new_id("req")
        url = self._resolve(path_or_url)
        original_url = url
        redirects: List[Dict[str, Any]] = []
        follow = self.follow_redirects if follow_redirects is None else follow_redirects
        body_sha = sha256_bytes(body or b"")
        current_url = url
        current_method = method
        current_body = body
        current_chunked = chunked

        for hop in range(self.max_redirects + 1):
            try:
                raw = self._single_request(
                    current_method,
                    current_url,
                    current_body,
                    headers or {},
                    current_chunked,
                    request_id,
                    nonce,
                    timeout=timeout,
                )
            except NetworkFailure as exc:
                return HttpExchange(
                    request_id=request_id,
                    method=current_method,
                    url=current_url,
                    sent_at=exc.sent_at or utcnow(),
                    received_at=utcnow(),
                    duration_ms=0.0,
                    request_headers=redact_headers(dict(self.extra_headers, **(headers or {}))),
                    request_body_bytes=len(current_body or b""),
                    request_body_sha256=body_sha,
                    error_kind=exc.kind,
                    error_message=exc.message,
                    redirect_chain=redirects,
                    nonce=nonce,
                )

            meta = raw[0]
            status = meta["status"]
            response_headers = meta["headers"]
            raw_body = meta["body"]
            if (
                follow
                and status in (301, 302, 303, 307, 308)
                and header_lookup(response_headers, "Location")
                and hop < self.max_redirects
            ):
                location = header_lookup(response_headers, "Location")
                next_url = urljoin(current_url, location)
                redirects.append(
                    {
                        "from": redact_url(current_url),
                        "status": status,
                        "location": redact_url(next_url),
                        "method": current_method,
                    }
                )
                if status == 303 or (status in (301, 302) and current_method == "POST"):
                    current_method = "GET"
                    current_body = None
                    current_chunked = False
                    body_sha = sha256_bytes(b"")
                current_url = next_url
                continue

            return HttpExchange(
                request_id=request_id,
                method=current_method,
                url=current_url,
                sent_at=meta["sent_at"],
                received_at=meta["received_at"],
                duration_ms=meta["duration_ms"],
                request_headers=meta["request_headers"],
                request_body_bytes=len(current_body or b""),
                request_body_sha256=body_sha,
                status=status,
                reason=meta["reason"],
                protocol=meta["protocol"],
                response_headers=redact_headers(response_headers),
                body_bytes=len(raw_body),
                body_sha256=sha256_bytes(raw_body),
                body_preview=preview(raw_body, DEFAULT_PREVIEW),
                body_truncated=meta["truncated"],
                redirect_chain=redirects,
                nonce=nonce,
                peer=meta["peer"],
                tls_verified=(
                    None
                    if urlsplit(current_url).scheme != "https"
                    else (False if self.insecure else True)
                ),
                notes=[f"original_url={redact_url(original_url)}"] if redirects else [],
            )

        # Loop exhausted (defensive; normally returned above).
        return HttpExchange(
            request_id=request_id,
            method=current_method,
            url=current_url,
            sent_at=utcnow(),
            received_at=utcnow(),
            duration_ms=0.0,
            error_kind="redirect_loop",
            error_message=f"more than {self.max_redirects} redirects",
            redirect_chain=redirects,
            nonce=nonce,
        )
