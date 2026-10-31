"""Tests for p2s.inventory pure helpers."""

from __future__ import annotations
import ipaddress
import json
import os
import socket
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from p2s.inventory import (
    SAPI_ALIASES,
    normalise_sapi,
    parse_powered_by,
    load_inventory_file,
    _trust_from_inventory,
    _inventory_evidence_data,
    _apply_inventory,
    patch_evidence,
)
from p2s.cli import _public_host


# ---------------------------------------------------------------------------
# normalise_sapi
# ---------------------------------------------------------------------------

class TestNormaliseSapi(unittest.TestCase):
    def test_exact_match(self):
        self.assertEqual(normalise_sapi("apache2handler"), "mod_php")
        self.assertEqual(normalise_sapi("fpm-fcgi"), "fpm")
        self.assertEqual(normalise_sapi("cli"), "cli")

    def test_case_insensitive(self):
        self.assertEqual(normalise_sapi("Apache2Handler"), "mod_php")
        self.assertEqual(normalise_sapi("FPM-FCGI"), "fpm")

    def test_substring_match(self):
        self.assertEqual(normalise_sapi("apache2handler (mod_php) extra"), "mod_php")

    def test_fallback_apache(self):
        self.assertEqual(normalise_sapi("apache-unknown"), "mod_php")

    def test_fallback_fpm(self):
        self.assertEqual(normalise_sapi("some-fpm-thing"), "fpm")

    def test_unknown_passthrough(self):
        self.assertEqual(normalise_sapi("exotic-sapi"), "exotic-sapi")

    def test_none(self):
        self.assertEqual(normalise_sapi(None), "unknown")

    def test_empty(self):
        self.assertEqual(normalise_sapi(""), "unknown")

    def test_all_aliases_covered(self):
        for alias, expected in SAPI_ALIASES.items():
            self.assertEqual(normalise_sapi(alias), expected)


# ---------------------------------------------------------------------------
# parse_powered_by
# ---------------------------------------------------------------------------

class TestParsePoweredBy(unittest.TestCase):
    def test_extracts_version(self):
        ver, raw = parse_powered_by({"X-Powered-By": "PHP/8.2.15"})
        self.assertEqual(ver, "8.2.15")
        self.assertIn("PHP/8.2.15", raw)

    def test_version_with_extras(self):
        ver, _ = parse_powered_by({"X-Powered-By": "PHP/8.1.2-1ubuntu2.14"})
        self.assertEqual(ver, "8.1.2-1ubuntu2.14")

    def test_no_header(self):
        ver, raw = parse_powered_by({})
        self.assertIsNone(ver)
        self.assertEqual(raw, "")

    def test_non_php_header(self):
        ver, _ = parse_powered_by({"X-Powered-By": "Express"})
        self.assertIsNone(ver)

    def test_case_insensitive_header_lookup(self):
        ver, _ = parse_powered_by({"x-powered-by": "PHP/7.4.33"})
        self.assertEqual(ver, "7.4.33")


# ---------------------------------------------------------------------------
# load_inventory_file
# ---------------------------------------------------------------------------

class TestLoadInventoryFile(unittest.TestCase):
    def test_loads_valid_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"php_version": "8.2.0", "sapi": "mod_php"}, f)
            f.flush()
            path = f.name
        try:
            data = load_inventory_file(path)
            self.assertEqual(data["php_version"], "8.2.0")
        finally:
            os.unlink(path)

    def test_rejects_non_object(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([1, 2, 3], f)
            f.flush()
            path = f.name
        try:
            with self.assertRaises(ValueError):
                load_inventory_file(path)
        finally:
            os.unlink(path)

    def test_missing_file(self):
        with self.assertRaises(OSError):
            load_inventory_file("/nonexistent/inventory.json")


# ---------------------------------------------------------------------------
# _trust_from_inventory
# ---------------------------------------------------------------------------

class TestTrustFromInventory(unittest.TestCase):
    def test_explicit_high(self):
        self.assertEqual(_trust_from_inventory({"trust": "high"}), "high")

    def test_explicit_low(self):
        self.assertEqual(_trust_from_inventory({"trust": "low"}), "low")

    def test_source_trust(self):
        self.assertEqual(_trust_from_inventory({"source_trust": "medium"}), "medium")

    def test_package_source_infers_high(self):
        self.assertEqual(_trust_from_inventory({"source": "package-manager"}), "high")
        self.assertEqual(_trust_from_inventory({"source": "distro-repo"}), "high")
        self.assertEqual(_trust_from_inventory({"source": "php-binary"}), "high")

    def test_unknown_source_defaults_medium(self):
        self.assertEqual(_trust_from_inventory({"source": "manual"}), "medium")

    def test_empty_defaults_medium(self):
        self.assertEqual(_trust_from_inventory({}), "medium")


# ---------------------------------------------------------------------------
# _inventory_evidence_data
# ---------------------------------------------------------------------------

class TestInventoryEvidenceData(unittest.TestCase):
    def test_keeps_relevant_keys(self):
        inv = {
            "php_version": "8.2.0",
            "sapi": "mod_php",
            "source": "package",
            "irrelevant_key": "dropped",
        }
        filtered = _inventory_evidence_data(inv)
        self.assertIn("php_version", filtered)
        self.assertIn("sapi", filtered)
        self.assertNotIn("irrelevant_key", filtered)

    def test_empty_inventory(self):
        self.assertEqual(_inventory_evidence_data({}), {})


# ---------------------------------------------------------------------------
# _apply_inventory
# ---------------------------------------------------------------------------

class TestApplyInventory(unittest.TestCase):
    def _make_profile(self):
        from p2s.models import TargetProfile
        return TargetProfile(
            target="http://localhost/",
            base_url="http://localhost/",
            host="localhost",
            port=80,
            tls=False,
        )

    def test_sets_version(self):
        profile = self._make_profile()
        _apply_inventory(profile, {"php_version": "8.2.15", "trust": "high"})
        self.assertEqual(profile.php_version, "8.2.15")
        self.assertEqual(profile.version_trust, "high")

    def test_strips_php_prefix(self):
        profile = self._make_profile()
        _apply_inventory(profile, {"php_version": "PHP/8.1.0"})
        self.assertEqual(profile.php_version, "8.1.0")

    def test_sets_sapi(self):
        profile = self._make_profile()
        _apply_inventory(profile, {"sapi": "apache2handler", "trust": "high"})
        self.assertEqual(profile.sapi, "mod_php")
        self.assertTrue(profile.sapi_verified)

    def test_target_match_false_downgrades_trust(self):
        profile = self._make_profile()
        _apply_inventory(profile, {
            "php_version": "8.2.0",
            "trust": "high",
            "target_match": False,
        })
        self.assertEqual(profile.version_trust, "medium")
        self.assertTrue(any("downgraded" in n for n in profile.notes))

    def test_sets_config(self):
        profile = self._make_profile()
        _apply_inventory(profile, {"config": {"memory_limit": "256M"}})
        self.assertEqual(profile.config["memory_limit"], "256M")

    def test_sets_packaging(self):
        profile = self._make_profile()
        _apply_inventory(profile, {"packaging": "deb"})
        self.assertEqual(profile.packaging, "deb")

    def test_backports_list(self):
        profile = self._make_profile()
        _apply_inventory(profile, {"backports": ["CVE-2026-109618"]})
        self.assertEqual(profile.patch.backports, ["CVE-2026-109618"])

    def test_version_from_version_key(self):
        profile = self._make_profile()
        _apply_inventory(profile, {"version": "7.4.33"})
        self.assertEqual(profile.php_version, "7.4.33")


# ---------------------------------------------------------------------------
# _public_host
# ---------------------------------------------------------------------------

class TestPublicHost(unittest.TestCase):
    def test_localhost_is_not_public(self):
        self.assertFalse(_public_host("localhost"))

    def test_loopback_is_not_public(self):
        self.assertFalse(_public_host("127.0.0.1"))

    def test_private_rfc1918_not_public(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),
            ]
            self.assertFalse(_public_host("internal.corp"))

    def test_public_ip_is_public(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
            ]
            self.assertTrue(_public_host("example.com"))

    def test_dns_failure_returns_false(self):
        with patch("socket.getaddrinfo", side_effect=OSError("dns fail")):
            self.assertFalse(_public_host("nonexistent.invalid"))

    def test_ipv6_mapped_v4_private(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::ffff:192.168.1.1", 0, 0, 0)),
            ]
            self.assertFalse(_public_host("mapped-private.test"))

    def test_ipv6_mapped_v4_public(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::ffff:93.184.216.34", 0, 0, 0)),
            ]
            self.assertTrue(_public_host("mapped-public.test"))

    def test_mixed_private_and_public(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
            ]
            self.assertTrue(_public_host("mixed.test"))

    def test_link_local_not_public(self):
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.1.1", 0)),
            ]
            self.assertFalse(_public_host("linklocal.test"))


# ---------------------------------------------------------------------------
# patch_evidence
# ---------------------------------------------------------------------------

class TestPatchEvidence(unittest.TestCase):
    def test_returns_dict_with_version_info(self):
        from p2s.models import TargetProfile
        profile = TargetProfile(
            target="http://x.com/",
            base_url="http://x.com/",
            host="x.com",
            port=80,
            tls=False,
        )
        profile.version_source = "x-powered-by"
        profile.version_trust = "low"
        result = patch_evidence(profile)
        self.assertEqual(result["version_source"], "x-powered-by")
        self.assertEqual(result["version_trust"], "low")
        self.assertIn("state", result)


if __name__ == "__main__":
    unittest.main()
