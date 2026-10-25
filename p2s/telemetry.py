"""Telemetry ingestion: PHP logs, web-server logs, worker telemetry, lab traces.

The scanner does not require login access to the target.  Operators can import
logs/traces collected on the server.  Every imported line becomes an evidence
item with a hash; parsing mistakes are reported rather than silently dropped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .util import parse_iso, utcnow

TIMESTAMP_PATTERNS = [
    re.compile(
        r"\[(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?"
        r"(?: [A-Za-z_/+-]{2,}|[+-]\d{4})?)\]"
    ),
    re.compile(r"\[(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\]"),
    re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"),
    re.compile(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"),
    re.compile(r"\[([A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\]"),
]
REQUEST_ID_RE = re.compile(
    r"(?:req(?:uest)?[_-]?id|correlation[_-]?id|x-p2s-request-id)[=:\s\"]+([A-Za-z0-9][A-Za-z0-9._:-]{3,})",
    re.IGNORECASE,
)
PID_RE = re.compile(
    r"(?:\[pid\s+|\[client[^\]]*\]\s*\[pid\s+|worker[_ ]pid[=:\s\"]+|pid[=:\s\"]+|child\s+|worker process\s+)(\d{2,10})",
    re.IGNORECASE,
)
NONCE_RE = re.compile(r"\b(P2S-[A-Z0-9]{16,})\b")
SAPI_RE = re.compile(r"(?:sapi|php_sapi)[=:\s\"]+(mod_php|php-fpm|fpm|frankenphp|lsapi|cli-server|cgi-fcgi|apache2handler)",
                    re.IGNORECASE)

OOM_RE = re.compile(r"Allowed memory size of\s+\d+\s+bytes exhausted", re.IGNORECASE)
FATAL_RE = re.compile(r"\bPHP\s+(Fatal error|Parse error|Core error)\b", re.IGNORECASE)
DIAG_RE = re.compile(r"\bPHP\s+(Warning|Notice|Deprecated)\b", re.IGNORECASE)
EXEC_TIME_RE = re.compile(r"Maximum execution time of\s+\d+\s+seconds exceeded", re.IGNORECASE)
WORKER_EXIT_RE = re.compile(
    r"(exited on signal|SIGSEGV|SIGBUS|SIGABRT|worker process \d+ exited|child \d+ exited|segfault)",
    re.IGNORECASE,
)
WORKER_START_RE = re.compile(r"(worker process \d+ started|child \d+ started|fpm is running)", re.IGNORECASE)

LAB_EVENT_HINTS = {
    "request_start": ("request_start", "request start"),
    "request_end": ("request_end", "request end"),
    "script_entry": ("script_entry", "script entered", "bootstrap_executed"),
    "request_startup": ("request_startup", "request startup"),
    "request_shutdown": ("request_shutdown", "request shutdown"),
    "startup_failed": ("startup_failed", "request_startup_failed", "startup failure"),
    "shutdown_after_failed_startup": (
        "shutdown_after_failed_startup",
        "shutdown invoked after failed startup",
        "shutdown_invoked_after_failed_startup",
    ),
    "longjmp_from_oom": ("longjmp_from_oom", "longjmp from oom", "longjmp triggered"),
    "invalid_state_processed": (
        "invalid_state_processed",
        "processed invalid state",
        "request memory invalid",
    ),
    "request_memory_freed": ("request_memory_freed", "request heap freed", "heap released"),
    "state_publish": ("state_publish", "state_published", "state producer", "published request-owned"),
    "state_consume": ("state_consume", "state_consumed", "state consumer", "consumed stale"),
    "stale_global_referenced": ("stale_global_referenced", "stale global referenced"),
    "stale_global_consumed": ("stale_global_consumed", "stale global consumed"),
    "use_after_free": ("use_after_free", "use-after-free", "uaf detected"),
    "address_reuse": ("address_reuse", "address reused", "pointer_reused"),
    "ini_diagnostic": ("ini_diagnostic", "ini diagnostic", "config diagnostic"),
    "upload_progress_consumer": ("upload_progress_consumer", "upload progress consumer"),
    "canary_write": ("canary_write", "canary write"),
    "canary_read": ("canary_read", "canary read"),
    "patched_baseline": ("patched_baseline", "patched baseline", "fixed build control"),
    "worker_recycle": ("worker_recycle", "worker recycled"),
}

SEVERITY_MAP = {
    "oom": "fatal",
    "fatal": "fatal",
    "diagnostic": "warning",
    "ini_diagnostic": "warning",
    "worker_exit": "error",
    "worker_start": "info",
}


@dataclass
class TelemetryEvent:
    source: str
    timestamp: str
    message: str
    event_type: str
    severity: str = "info"
    request_id: Optional[str] = None
    worker_id: Optional[str] = None
    pid: Optional[int] = None
    nonce: Optional[str] = None
    sapi: Optional[str] = None
    phase: Optional[str] = None
    raw: str = ""
    line_no: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)
    parse_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "timestamp": self.timestamp,
            "message": self.message,
            "event_type": self.event_type,
            "severity": self.severity,
            "request_id": self.request_id,
            "worker_id": self.worker_id,
            "pid": self.pid,
            "nonce": self.nonce,
            "sapi": self.sapi,
            "phase": self.phase,
            "raw": self.raw[:4096],
            "line_no": self.line_no,
            "extra": self.extra,
            "parse_error": self.parse_error,
        }


def _normalise_timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    parsed = parse_iso(text)
    if parsed:
        return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    import datetime as _dt

    # PHP's common log format carries a named timezone:
    #   [23-Oct-2026 19:43:18 Europe/Berlin]
    named = re.search(
        r"(\d{2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s+([A-Za-z_/+-]+)",
        text,
    )
    if named:
        day, month, year, hour, minute, second, frac, zone = named.groups()
        try:
            dt = _dt.datetime.strptime(
                f"{day}-{month}-{year} {hour}:{minute}:{second}",
                "%d-%b-%Y %H:%M:%S",
            )
            tzinfo = _dt.timezone.utc
            if zone.upper() not in ("UTC", "GMT", "Z"):
                try:
                    from zoneinfo import ZoneInfo

                    tzinfo = ZoneInfo(zone)
                except Exception:
                    tzinfo = _dt.timezone.utc
            if frac:
                dt = dt.replace(microsecond=int((frac + "000000")[:6]))
            dt = dt.replace(tzinfo=tzinfo)
            return dt.astimezone(_dt.timezone.utc).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z")
        except ValueError:
            pass

    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(text)
        if match:
            candidate = match.group(1)
            try:
                for fmt in (
                    "%d-%b-%Y %H:%M:%S %Z",
                    "%d-%b-%Y %H:%M:%S",
                    "%Y/%m/%d %H:%M:%S",
                    "%a %b %d %H:%M:%S.%f %Y",
                    "%a %b %d %H:%M:%S %Y",
                ):
                    try:
                        dt = _dt.datetime.strptime(candidate, fmt)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=_dt.timezone.utc)
                        return dt.astimezone(_dt.timezone.utc).isoformat(
                            timespec="milliseconds"
                        ).replace("+00:00", "Z")
                    except ValueError:
                        continue
            except Exception:
                pass
    return None


def _event_type_from_message(message: str) -> str:
    low = message.lower()
    if OOM_RE.search(message):
        return "oom"
    if EXEC_TIME_RE.search(message):
        return "fatal"
    if FATAL_RE.search(message):
        return "fatal"
    if DIAG_RE.search(message):
        return "diagnostic"
    if WORKER_EXIT_RE.search(message):
        return "worker_exit"
    if WORKER_START_RE.search(message):
        return "worker_start"
    for name, hints in LAB_EVENT_HINTS.items():
        for hint in hints:
            if hint in low:
                return name
    return "log"


def _extract_pid(message: str) -> Optional[int]:
    match = PID_RE.search(message)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _phase_from(value: Dict[str, Any], message: str) -> Optional[str]:
    explicit = value.get("phase")
    if explicit in ("startup", "startup_like", "post_startup", "shutdown"):
        return explicit
    low = message.lower()
    if "phase=startup" in low or "request startup" in low:
        return "startup"
    if "phase=post_startup" in low:
        return "post_startup"
    if "unknown on line 0" in low:
        return "startup_like"
    if "request shutdown" in low:
        return "shutdown"
    return None


def parse_json_event(value: Dict[str, Any], source: str, line_no: int) -> TelemetryEvent:
    message = str(
        value.get("message")
        or value.get("msg")
        or value.get("line")
        or value.get("raw")
        or value.get("event")
        or ""
    )
    event_type = str(value.get("event_type") or value.get("event") or value.get("type") or "")
    if not event_type or event_type in ("log", "message"):
        event_type = _event_type_from_message(message)
    pid = value.get("worker_pid") or value.get("pid") or value.get("child_pid") or value.get("worker")
    try:
        pid_int = int(pid) if pid is not None else None
    except (TypeError, ValueError):
        pid_int = _extract_pid(message)
    ts = _normalise_timestamp(
        value.get("timestamp") or value.get("@timestamp") or value.get("time") or value.get("ts")
    ) or utcnow()
    request_id = (
        value.get("request_id")
        or value.get("req_id")
        or value.get("requestId")
        or value.get("correlation_id")
    )
    if not request_id:
        match = REQUEST_ID_RE.search(message)
        if match:
            request_id = match.group(1)
    nonce = value.get("nonce") or (NONCE_RE.search(message).group(1) if NONCE_RE.search(message) else None)
    sapi = value.get("sapi") or value.get("php_sapi")
    if not sapi:
        match = SAPI_RE.search(message)
        if match:
            sapi = match.group(1)
    severity = str(value.get("severity") or value.get("level") or SEVERITY_MAP.get(event_type, "info"))
    return TelemetryEvent(
        source=str(value.get("source") or source),
        timestamp=ts,
        message=message[:8192],
        event_type=event_type,
        severity=severity,
        request_id=str(request_id) if request_id else None,
        worker_id=str(pid_int) if pid_int is not None else None,
        pid=pid_int,
        nonce=nonce,
        sapi=str(sapi) if sapi else None,
        phase=_phase_from(value, message),
        raw=json.dumps(value, ensure_ascii=False)[:8192],
        line_no=line_no,
        extra={k: v for k, v in value.items() if k not in {
            "message", "msg", "line", "raw", "event", "event_type", "type",
            "timestamp", "time", "ts", "request_id", "req_id", "worker_pid",
            "pid", "nonce", "sapi", "severity", "level",
        }},
    )


def parse_text_event(line: str, source: str, line_no: int) -> TelemetryEvent:
    message = line.rstrip("\r\n")
    match_ts = None
    for pattern in TIMESTAMP_PATTERNS:
        match_ts = pattern.search(message)
        if match_ts:
            break
    ts = _normalise_timestamp(match_ts.group(0)) if match_ts else utcnow()
    pid = _extract_pid(message)
    request_match = REQUEST_ID_RE.search(message)
    nonce_match = NONCE_RE.search(message)
    sapi_match = SAPI_RE.search(message)
    event_type = _event_type_from_message(message)
    severity = SEVERITY_MAP.get(event_type, "error" if event_type in ("fatal", "oom") else "info")
    return TelemetryEvent(
        source=source,
        timestamp=ts or utcnow(),
        message=message[:8192],
        event_type=event_type,
        severity=severity,
        request_id=request_match.group(1) if request_match else None,
        worker_id=str(pid) if pid is not None else None,
        pid=pid,
        nonce=nonce_match.group(1) if nonce_match else None,
        sapi=sapi_match.group(1) if sapi_match else None,
        phase=_phase_from({}, message),
        raw=message[:8192],
        line_no=line_no,
    )


def parse_telemetry_file(path: str, default_source: str = "php_log") -> Tuple[List[TelemetryEvent], List[str]]:
    events: List[TelemetryEvent] = []
    errors: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line_no, line in enumerate(handle, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith("{"):
                    try:
                        value = json.loads(stripped)
                    except json.JSONDecodeError as exc:
                        errors.append(f"{path}:{line_no}: invalid JSON: {exc}")
                        continue
                    if isinstance(value, dict):
                        if isinstance(value.get("events"), list):
                            for item in value["events"]:
                                if isinstance(item, dict):
                                    events.append(parse_json_event(item, default_source, line_no))
                                else:
                                    errors.append(f"{path}:{line_no}: event item is not an object")
                        else:
                            events.append(parse_json_event(value, default_source, line_no))
                    else:
                        errors.append(f"{path}:{line_no}: JSON value is not an object")
                elif stripped.startswith("["):
                    # PHP's default error log starts each line with a bracketed
                    # timestamp ("[23-Oct-2026 19:43:18 Europe/Berlin] ...").
                    # Only treat a bracketed line as JSON when it really parses;
                    # otherwise fall back to the text parser instead of losing
                    # the log line as a JSON error.
                    try:
                        value = json.loads(stripped)
                    except json.JSONDecodeError:
                        if any(pattern.search(stripped) for pattern in TIMESTAMP_PATTERNS):
                            events.append(parse_text_event(stripped, default_source, line_no))
                        else:
                            errors.append(
                                f"{path}:{line_no}: bracketed line is neither valid JSON "
                                "nor a timestamped log line"
                            )
                        continue
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                events.append(parse_json_event(item, default_source, line_no))
                            else:
                                errors.append(f"{path}:{line_no}: array item is not an object")
                    elif isinstance(value, dict):
                        events.append(parse_json_event(value, default_source, line_no))
                    else:
                        errors.append(f"{path}:{line_no}: JSON value is not an object")
                else:
                    events.append(parse_text_event(stripped, default_source, line_no))
    except OSError as exc:
        errors.append(f"{path}: {exc}")
    return events, errors


def source_for_path(path: str) -> str:
    low = path.lower()
    if "fpm" in low or "worker" in low:
        return "worker_telemetry"
    if "nginx" in low or "apache" in low or "access" in low:
        return "web_server_log"
    if "trace" in low:
        return "lab_trace"
    if "canary" in low:
        return "canary"
    return "php_log"


def merge_events(*collections: Iterable[TelemetryEvent]) -> List[TelemetryEvent]:
    out: List[TelemetryEvent] = []
    seen = set()
    for collection in collections:
        for event in collection:
            key = (event.source, event.timestamp, event.message, event.line_no, event.request_id)
            if key in seen:
                continue
            seen.add(key)
            out.append(event)
    out.sort(key=lambda e: (e.timestamp or "", e.line_no))
    return out
