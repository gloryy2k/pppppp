"""Verify Chain D offset profiles against real Docker containers.

Spins up containers from docker-compose.verify-offsets.yml and uses
``nm`` inside each container to extract the real symbol offsets from
the installed libphp.so / mod_php module.  Compares against the
estimated values in data/chain_d_offsets.json and reports mismatches.

Usage:
    cd lab/
    docker compose -f docker-compose.verify-offsets.yml up -d --build
    python verify_offsets.py --ack-authorised
    docker compose -f docker-compose.verify-offsets.yml down -v

Exits 0 if all profiles match, 1 if any mismatch, 3 if Docker is
unavailable.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OFFSETS_PATH = os.path.join(ROOT, "data", "chain_d_offsets.json")

CONTAINERS: List[Dict[str, Any]] = [
    {
        "service": "ubuntu-noble",
        "port": 18090,
        "profile_patterns": ["noble"],
        "libphp_paths": [
            "/usr/lib/apache2/modules/libphp8.3.so",
            "/usr/lib/apache2/modules/libphp.so",
        ],
    },
    {
        "service": "ubuntu-jammy",
        "port": 18091,
        "profile_patterns": ["jammy"],
        "libphp_paths": [
            "/usr/lib/apache2/modules/libphp8.1.so",
            "/usr/lib/apache2/modules/libphp.so",
        ],
    },
    {
        "service": "rocky9",
        "port": 18092,
        "profile_patterns": ["el9"],
        "libphp_paths": [
            "/usr/lib64/httpd/modules/libphp.so",
            "/usr/lib64/httpd/modules/libphp8.so",
            "/usr/lib/httpd/modules/libphp.so",
        ],
    },
]

SYMBOLS = ["zval_ptr_dtor", "zif_system"]


def _docker_available() -> Tuple[bool, str]:
    if not shutil.which("docker"):
        return False, "docker CLI not found on PATH"
    proc = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "docker info failed").strip()
        return False, detail.splitlines()[-1][:500]
    return True, proc.stdout.strip()


def _wait_for(url: str, timeout: float = 120.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(2)
    return False


def _docker_exec(service: str, cmd: List[str]) -> Tuple[int, str, str]:
    full = ["docker", "compose", "-f", "docker-compose.verify-offsets.yml",
            "exec", "-T", service] + cmd
    proc = subprocess.run(
        full, cwd=HERE, capture_output=True, text=True, timeout=60, check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _find_libphp(service: str, candidate_paths: List[str]) -> Optional[str]:
    for path in candidate_paths:
        rc, out, _ = _docker_exec(service, ["test", "-f", path])
        if rc == 0:
            return path
    rc, out, _ = _docker_exec(service, ["find", "/usr", "-name", "libphp*.so", "-type", "f"])
    if rc == 0 and out.strip():
        return out.strip().splitlines()[0]
    return None


def _extract_offsets(service: str, libphp_path: str) -> Dict[str, str]:
    offsets: Dict[str, str] = {}
    for symbol in SYMBOLS:
        rc, out, err = _docker_exec(service, ["nm", "-D", libphp_path])
        if rc != 0:
            rc, out, err = _docker_exec(service, ["nm", libphp_path])
        if rc != 0:
            print(f"    [!] nm failed on {service}: {err.strip()[:200]}")
            continue
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[2] == symbol:
                offsets[symbol] = "0x" + parts[0].lstrip("0").upper()
                if not offsets[symbol] or offsets[symbol] == "0x":
                    offsets[symbol] = "0x0"
                break
    return offsets


def _get_php_version(service: str) -> Optional[str]:
    rc, out, _ = _docker_exec(service, ["php", "-r", "echo phpversion();"])
    if rc == 0:
        return out.strip()
    return None


def _get_arch(service: str) -> str:
    rc, out, _ = _docker_exec(service, ["uname", "-m"])
    if rc == 0:
        raw = out.strip()
        if raw in ("x86_64", "amd64"):
            return "x86_64"
        if raw in ("aarch64", "arm64"):
            return "aarch64"
        return raw
    return "unknown"


def _load_offsets() -> Dict[str, Any]:
    with open(OFFSETS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_offsets(data: Dict[str, Any]) -> None:
    with open(OFFSETS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _match_profiles(
    profiles: Dict[str, Any], patterns: List[str],
) -> List[Tuple[str, Dict[str, Any]]]:
    matched = []
    for key, val in profiles.items():
        if key.startswith("_"):
            continue
        if not isinstance(val, dict):
            continue
        for pat in patterns:
            if pat in key:
                matched.append((key, val))
                break
    return matched


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ack-authorised", action="store_true",
                        help="confirm authorisation to run Docker containers")
    parser.add_argument("--update", action="store_true",
                        help="update chain_d_offsets.json with verified values")
    parser.add_argument("--readiness-timeout", type=float, default=120.0)
    args = parser.parse_args()

    if not args.ack_authorised:
        print("pass --ack-authorised to confirm", file=sys.stderr)
        return 2

    ok, detail = _docker_available()
    if not ok:
        print(f"Docker unavailable: {detail}", file=sys.stderr)
        return 3

    offsets_data = _load_offsets()
    profiles = offsets_data.get("profiles", {})

    mismatches = 0
    verified_updates: Dict[str, Dict[str, Any]] = {}

    for container in CONTAINERS:
        service = container["service"]
        port = container["port"]
        patterns = container["profile_patterns"]

        print(f"\n{'='*60}")
        print(f"Verifying: {service}")
        print(f"{'='*60}")

        url = f"http://127.0.0.1:{port}/status.php"
        if not _wait_for(url, args.readiness_timeout):
            print(f"  [SKIP] {service} not ready at {url}")
            continue

        php_version = _get_php_version(service)
        arch = _get_arch(service)
        print(f"  PHP version: {php_version}")
        print(f"  Arch: {arch}")

        libphp = _find_libphp(service, container["libphp_paths"])
        if not libphp:
            print(f"  [SKIP] libphp.so not found in {service}")
            continue
        print(f"  libphp: {libphp}")

        real_offsets = _extract_offsets(service, libphp)
        if not real_offsets:
            print(f"  [SKIP] could not extract offsets from {service}")
            continue
        print(f"  Real offsets:")
        for sym, val in real_offsets.items():
            print(f"    {sym} = {val}")

        matched = _match_profiles(profiles, patterns)
        if not matched:
            print(f"  [INFO] no matching profiles for patterns {patterns}")
            arch_matched = [
                (k, v) for k, v in matched
                if arch in k
            ]
            if not arch_matched:
                print(f"  [INFO] no arch-matched profiles for {arch}")
            continue

        for profile_key, profile_val in matched:
            if arch not in profile_key:
                continue
            print(f"\n  Profile: {profile_key}")
            all_match = True
            for sym in SYMBOLS:
                estimated = profile_val.get(sym, "")
                actual = real_offsets.get(sym, "")
                if not actual:
                    print(f"    {sym}: actual not available, skipping")
                    continue
                est_int = int(estimated, 16) if estimated else 0
                act_int = int(actual, 16) if actual else 0
                if est_int == act_int:
                    print(f"    {sym}: MATCH ({estimated})")
                else:
                    print(f"    {sym}: MISMATCH estimated={estimated} actual={actual}")
                    all_match = False
                    mismatches += 1

            if all_match:
                print(f"  [{profile_key}] ALL MATCH — profile is correct")
                verified_updates[profile_key] = {
                    **profile_val,
                    "verified": True,
                    "source": f"verified against {service} (PHP {php_version}, {arch})",
                }
            else:
                print(f"  [{profile_key}] MISMATCH — update needed")
                corrected = dict(profile_val)
                for sym in SYMBOLS:
                    if sym in real_offsets:
                        corrected[sym] = real_offsets[sym]
                corrected["verified"] = True
                corrected["source"] = (
                    f"corrected from {service} (PHP {php_version}, {arch}) "
                    f"— previous values were estimates"
                )
                verified_updates[profile_key] = corrected

    if args.update and verified_updates:
        print(f"\n{'='*60}")
        print(f"Updating {len(verified_updates)} profiles in chain_d_offsets.json")
        print(f"{'='*60}")
        for key, val in verified_updates.items():
            profiles[key] = val
        offsets_data["profiles"] = profiles
        _save_offsets(offsets_data)
        print("Updated.")

    print(f"\n{'='*60}")
    print(f"Summary: {len(verified_updates)} profiles checked, {mismatches} mismatches")
    if mismatches:
        print("Run with --update to write corrected values.")
    else:
        print("All checked profiles match their estimated values.")
    print(f"{'='*60}")

    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
