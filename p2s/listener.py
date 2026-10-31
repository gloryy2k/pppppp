"""Lightweight HTTP callback listener for out-of-band RCE verification.

Runs a minimal HTTP server that records incoming callbacks from exploit
payloads.  The canary nonce in the callback URL path is necessary but not
sufficient: the caller must also check that the callback came from the target
(see ``p2s.exploit``), otherwise any host that learns the URL could fake it.

Thread-safe: the server runs in a daemon thread and can be queried from the
main thread at any time.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional
from base64 import b64decode
from urllib.parse import unquote_plus, urlparse, parse_qs

from .util import utcnow

_log = logging.getLogger(__name__)

# Bound what an unauthenticated internet-facing listener will read/store.
MAX_CALLBACK_BODY = 65536


@dataclass
class Callback:
    timestamp: str
    remote_addr: str
    remote_port: int
    method: str
    path: str
    headers: Dict[str, str]
    body: str
    nonce: Optional[str] = None
    command_output: Optional[str] = None


@dataclass
class ListenerState:
    callbacks: List[Callback] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, cb: Callback) -> None:
        with self.lock:
            self.callbacks.append(cb)

    def find_by_nonce(self, nonce: str) -> Optional[Callback]:
        with self.lock:
            for cb in self.callbacks:
                if cb.nonce == nonce:
                    return cb
        return None

    def all(self) -> List[Callback]:
        with self.lock:
            return list(self.callbacks)


def _make_handler(state: ListenerState):
    class CallbackHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _handle(self):
            try:
                declared = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                declared = 0
            content_length = max(0, min(declared, MAX_CALLBACK_BODY))
            body = (
                self.rfile.read(content_length).decode("utf-8", "replace")
                if content_length > 0
                else ""
            )

            parsed = urlparse(self.path)
            parts = parsed.path.strip("/").split("/")

            nonce = None
            command_output = None
            if len(parts) >= 2 and parts[0] == "cb":
                nonce = parts[1]
                if len(parts) >= 3:
                    command_output = "/".join(parts[2:])
            elif len(parts) >= 1 and parts[0].startswith("P2S"):
                nonce = parts[0]

            qs = parse_qs(parsed.query)
            if not command_output and "out" in qs:
                raw_out = qs["out"][0]
                try:
                    command_output = b64decode(raw_out).decode("utf-8", "replace")
                except Exception:
                    command_output = unquote_plus(raw_out)
            if not command_output and body:
                body_qs = parse_qs(body.strip())
                if "out" in body_qs:
                    raw_out = body_qs["out"][0]
                    try:
                        command_output = b64decode(raw_out).decode("utf-8", "replace")
                    except Exception:
                        command_output = unquote_plus(raw_out)
                else:
                    command_output = body.strip()
            if command_output:
                command_output = unquote_plus(command_output)

            cb = Callback(
                timestamp=utcnow(),
                remote_addr=self.client_address[0],
                remote_port=self.client_address[1],
                method=self.command,
                path=self.path,
                headers={k: v for k, v in self.headers.items()},
                body=body,
                nonce=nonce,
                command_output=command_output,
            )
            state.add(cb)
            _log.info("callback received: nonce=%s remote=%s:%d",
                      nonce, self.client_address[0], self.client_address[1])

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")

        do_GET = _handle
        do_POST = _handle
        do_PUT = _handle
        do_HEAD = _handle

    return CallbackHandler


def _get_local_ip(target_host: Optional[str] = None, target_port: int = 80) -> str:
    """Best-effort local address that can reach ``target_host``.

    No external service is contacted.  A UDP connect only selects a route, so
    the function also works in an offline lab.  ``127.0.0.1`` is used when the
    target is unknown; that is correct for a local lab and useless for a remote
    target, which is why the CLI exposes ``--callback-ip``.
    """
    probe_host = target_host or "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        try:
            s.connect((probe_host, target_port or 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"


class CallbackListener:
    def __init__(
        self,
        port: int = 0,
        bind: str = "0.0.0.0",
        target_host: Optional[str] = None,
        target_port: int = 80,
    ):
        self.state = ListenerState()
        self.bind = bind
        self._server = HTTPServer((bind, port), _make_handler(self.state))
        self.port = self._server.server_address[1]
        self.local_ip = _get_local_ip(target_host, target_port)
        self._thread: Optional[threading.Thread] = None

    @property
    def base_url(self) -> str:
        return f"http://{self.local_ip}:{self.port}"

    def callback_url(self, nonce: str) -> str:
        return f"{self.base_url}/cb/{nonce}"

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="p2s-callback-listener",
        )
        self._thread.start()
        _log.info("callback listener started on %s:%d", self.bind, self.port)

    def stop(self) -> None:
        _log.debug("shutting down callback listener")
        self._server.shutdown()
        if self._thread:
            self._thread.join(timeout=5)
        self._server.server_close()
        _log.info("callback listener stopped")

    def wait_for_callback(self, nonce: str, timeout: float = 30.0) -> Optional[Callback]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            cb = self.state.find_by_nonce(nonce)
            if cb is not None:
                return cb
            time.sleep(0.3)
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bind": self.bind,
            "port": self.port,
            "local_ip": self.local_ip,
            "base_url": self.base_url,
            "callbacks_received": len(self.state.all()),
        }
