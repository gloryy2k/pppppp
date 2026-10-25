"""Run the patched-vs-unpatched Docker matrix.

This runner is intentionally conservative:

* it refuses to run without ``--ack-authorised``;
* it only targets the local compose services on 127.0.0.1;
* it records every scanner run under ``lab/matrix/runs/``;
* if Docker is unavailable it exits 3 and says so instead of inventing a result.

It does not add exploit code and it does not interpret an OOM as either CVE.
Read ``../../COVERAGE.md`` for what this matrix can and cannot establish.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SCANNER = os.path.join(ROOT, "php2shell_scanner_v4.py")

TARGETS = [
    ("apache-affected", "http://127.0.0.1:18180", "mod_php", "8.2.34"),
    ("apache-patched", "http://127.0.0.1:18181", "mod_php", "8.2.35"),
    ("fpm-affected", "http://127.0.0.1:18182", "fpm", "8.2.34"),
    ("fpm-patched", "http://127.0.0.1:18183", "fpm", "8.2.35"),
]


def _run(command: List[str], *, timeout: int = 600, check: bool = False) -> subprocess.CompletedProcess:
    print("+ " + " ".join(command))
    proc = subprocess.run(
        command,
        cwd=HERE,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.stdout.strip():
        print(proc.stdout.rstrip())
    if proc.stderr.strip():
        print(proc.stderr.rstrip(), file=sys.stderr)
    if check and proc.returncode != 0:
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(command)}")
    return proc


def _docker_available() -> tuple[bool, str]:
    if not shutil.which("docker"):
        return False, "docker CLI not found on PATH"
    proc = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "docker info failed").strip()
        return False, detail.splitlines()[-1][:500]
    return True, proc.stdout.strip()


def _wait_for(url: str, timeout: float = 120.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        request = urllib.request.Request(
            url,
            headers={"X-P2S-Request-ID": "matrix-readiness", "X-P2S-Nonce": "MATRIXREADY"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(2)
    return False


class LogCapture:
    """Capture compose logs to a file so prove mode can import live telemetry."""

    def __init__(self, path: str):
        self.path = path
        self.proc: Optional[subprocess.Popen] = None
        self.handle = None

    def __enter__(self) -> "LogCapture":
        self.handle = open(self.path, "w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(
            ["docker", "compose", "logs", "-f", "--no-color", "--no-log-prefix"],
            cwd=HERE,
            stdout=self.handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
        )
        time.sleep(2)
        return self

    def __exit__(self, *exc: object) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.handle is not None:
            self.handle.flush()
            self.handle.close()


def _scanner(args: List[str]) -> int:
    return _run([sys.executable, SCANNER] + args, timeout=900).returncode


def _statuses(run_dir: str) -> Dict[str, str]:
    path = os.path.join(run_dir, "findings.json")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return {item["cve"]: item["status"] for item in payload.get("findings", [])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ack-authorised", action="store_true",
                        help="confirm authorisation to send bounded OOM payloads to localhost")
    parser.add_argument("--out", default=os.path.join(HERE, "runs"))
    parser.add_argument("--keep-up", action="store_true", help="leave compose services running")
    parser.add_argument("--readiness-timeout", type=float, default=180.0)
    args = parser.parse_args()

    if not args.ack_authorised:
        print("refusing to run: pass --ack-authorised after confirming authorisation", file=sys.stderr)
        return 2

    ok, detail = _docker_available()
    if not ok:
        print("Docker daemon unavailable; the matrix was NOT executed.", file=sys.stderr)
        print(f"reason: {detail}", file=sys.stderr)
        print(
            "This is an unverified environment, not a pass.  Record it as "
            "'matrix unexecuted' in COVERAGE.md.",
            file=sys.stderr,
        )
        return 3

    os.makedirs(args.out, exist_ok=True)
    print(f"docker server {detail}")
    _run(["docker", "compose", "up", "-d", "--build"], check=True)

    try:
        for name, base, sapi, expected in TARGETS:
            if not _wait_for(base + "/status.php", args.readiness_timeout):
                print(f"{name}: readiness failed; skipping", file=sys.stderr)
                continue
            run_root = os.path.join(args.out, name)
            os.makedirs(run_root, exist_ok=True)
            log_path = os.path.join(run_root, "compose.log")
            common = [
                base,
                "--status-url", base + "/status.php",
                "--health-url", base + "/status.php",
                "--sapi", sapi,
                "--environment-kind", "lab",
            ]
            _scanner(["inventory"] + common + ["--out", os.path.join(run_root, "inventory")])
            _scanner(["probe"] + common + ["--out", os.path.join(run_root, "probe")])
            for scenario in ("618-S2", "619-S2"):
                with LogCapture(log_path):
                    _scanner(
                        ["prove"] + common
                        + ["--scenario", scenario, "--ack-authorised",
                           "--telemetry", log_path,
                           "--out", os.path.join(run_root, scenario)]
                    )
                statuses = _statuses(os.path.join(run_root, scenario))
                print(f"{name} / {scenario}: {statuses}")
    finally:
        if not args.keep_up:
            _run(["docker", "compose", "down", "-v"])

    print("\nMatrix finished.  Statuses are evidence observations, not automatic CVE proof.")
    print(f"Runs: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
