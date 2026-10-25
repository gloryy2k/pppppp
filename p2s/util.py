"""Small helpers shared by the scanner.

No third-party dependencies.  Everything here must be safe to use in tests
and in evidence artefacts (deterministic serialisation, bounded strings,
secret redaction).
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import re
import secrets
import string
import unicodedata
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

UTC = _dt.timezone.utc


def utcnow() -> str:
    """ISO-8601 UTC with millisecond precision and a trailing Z."""
    return _dt.datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str) -> Optional[_dt.datetime]:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def iso(dt: _dt.datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=_json_default
    ).encode("utf-8")


def _json_default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, _dt.datetime):
        return iso(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return str(value)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", "replace"))


def new_nonce(prefix: str = "P2S") -> str:
    """A request-scoped, unguessable nonce used for correlation and canaries."""
    alphabet = string.ascii_uppercase + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(24))
    return f"{prefix}-{body}"


def new_id(prefix: str = "req") -> str:
    return f"{prefix}-{secrets.token_hex(12)}"


def slugify(value: str, limit: int = 60) -> str:
    text = unicodedata.normalize("NFKD", value)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-._")
    return (text or "target")[:limit]


def truncate_bytes(data: bytes, limit: int) -> "tuple[bytes, bool]":
    if limit < 0:
        limit = 0
    if len(data) <= limit:
        return data, False
    return data[:limit], True


def preview(data: bytes, limit: int = 8192) -> str:
    sample, _ = truncate_bytes(data, limit)
    return sample.decode("utf-8", "replace")


_SECRET_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}

_SECRET_QUERY_KEYS = {
    "token",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "passwd",
    "sig",
    "signature",
    "session",
    "sessionid",
}

_TEXT_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(PHPSESSID=)([^;\s\"']+)"),
    re.compile(r"(?i)\b(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})"),
    re.compile(r"(?i)([?&](?:token|api_key|apikey|password|passwd|secret|sig)=)([^&\s\"']+)"),
    re.compile(r"(?i)(\"(?:password|passwd|secret|token|api_key)\"\s*:\s*\")([^\"]+)(\")"),
]


def redact_text(value: str) -> str:
    text = value or ""
    for pattern in _TEXT_SECRET_PATTERNS:
        if pattern.groups >= 3:
            text = pattern.sub(lambda m: m.group(1) + "***" + m.group(3), text)
        else:
            text = pattern.sub(lambda m: m.group(1) + "***", text)
    return text


def redact_header_value(name: str, value: str) -> str:
    lname = name.lower().strip()
    if lname in _SECRET_HEADERS:
        return "***redacted***"
    if lname in ("x-p2s-request-id", "x-p2s-nonce", "x-request-id"):
        return value
    return redact_text(value)


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in (headers or {}).items():
        out[str(key)] = redact_header_value(str(key), str(value))
    return out


def redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return redact_text(url)
    if not parts.query:
        return redact_text(url)
    pairs = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in _SECRET_QUERY_KEYS:
            pairs.append((key, "***"))
        else:
            pairs.append((key, redact_text(value)))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def header_lookup(headers: Dict[str, str], name: str) -> str:
    if not headers:
        return ""
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return ""


def clamp_int(value: Any, low: int, high: int, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def dedupe(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def human_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB"]
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"
        amount /= 1024
    return f"{value} B"


def safe_filename(value: str, limit: int = 80) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", value or "artifact").strip("-.")
    return (text or "artifact")[:limit]
