"""Tests for p2s.discover pure helpers and dataclasses."""

from __future__ import annotations
import unittest
from unittest.mock import MagicMock
from p2s.discover import (
    DiscoverBudget,
    DiscoverResult,
    LfiEndpoint,
    PhpInfoResult,
    _body_text,
    _extract_all_links,
    _extract_links,
    _full_url,
    _is_lfi_hit,
    _nest_name,
    _parse_phpinfo,
    _request_path,
    build_oom_lite_body,
    build_oom_probe_body,
    detect_framework,
    _FRAMEWORK_SIGNATURES,
)
from p2s.http import HttpExchange


# ---------------------------------------------------------------------------
# DiscoverBudget
# ---------------------------------------------------------------------------

class TestDiscoverBudget(unittest.TestCase):
    def test_initial_remaining(self):
        b = DiscoverBudget(10)
        self.assertEqual(b.remaining, 10)
        self.assertTrue(b.can_spend(1))

    def test_spend_decrements(self):
        b = DiscoverBudget(3)
        b.spend()
        self.assertEqual(b.used, 1)
        self.assertEqual(b.remaining, 2)

    def test_cannot_overspend(self):
        b = DiscoverBudget(2)
        b.spend()
        b.spend()
        self.assertFalse(b.can_spend())
        self.assertEqual(b.remaining, 0)

    def test_can_spend_n(self):
        b = DiscoverBudget(5)
        b.spend()
        self.assertTrue(b.can_spend(4))
        self.assertFalse(b.can_spend(5))

    def test_remaining_never_negative(self):
        b = DiscoverBudget(1)
        b.spend()
        b.spend()  # over-spend
        self.assertEqual(b.remaining, 0)


# ---------------------------------------------------------------------------
# _parse_phpinfo
# ---------------------------------------------------------------------------

class TestParsePhpinfo(unittest.TestCase):
    PHPINFO_SNIPPET = (
        '<tr><td class="e">memory_limit</td><td class="v">128M</td></tr>'
        '<tr><td class="e">session.save_path</td><td class="v">/tmp</td></tr>'
        '<tr><td class="e">disable_functions</td><td class="v">exec,system</td></tr>'
        '<tr><td class="e">empty_val</td><td class="v"><i>no value</i></td></tr>'
    )

    def test_extracts_directives(self):
        d = _parse_phpinfo(self.PHPINFO_SNIPPET)
        self.assertEqual(d["memory_limit"], "128M")
        self.assertEqual(d["session.save_path"], "/tmp")
        self.assertEqual(d["disable_functions"], "exec,system")

    def test_skips_no_value(self):
        d = _parse_phpinfo(self.PHPINFO_SNIPPET)
        self.assertNotIn("empty_val", d)

    def test_empty_html(self):
        self.assertEqual(_parse_phpinfo(""), {})

    def test_multiline_rows(self):
        html = '<tr>\n  <td class="e">\n    open_basedir\n  </td>\n  <td class="v">\n    /var/www\n  </td>\n</tr>'
        d = _parse_phpinfo(html)
        self.assertEqual(d["open_basedir"], "/var/www")


# ---------------------------------------------------------------------------
# PhpInfoResult
# ---------------------------------------------------------------------------

class TestPhpInfoResult(unittest.TestCase):
    def test_memory_limit_bytes_megabytes(self):
        r = PhpInfoResult(memory_limit="128M")
        self.assertEqual(r.memory_limit_bytes(), 128 * 1024 * 1024)

    def test_memory_limit_bytes_kilobytes(self):
        r = PhpInfoResult(memory_limit="512K")
        self.assertEqual(r.memory_limit_bytes(), 512 * 1024)

    def test_memory_limit_bytes_gigabytes(self):
        r = PhpInfoResult(memory_limit="2G")
        self.assertEqual(r.memory_limit_bytes(), 2 * 1024 * 1024 * 1024)

    def test_memory_limit_unlimited(self):
        r = PhpInfoResult(memory_limit="-1")
        self.assertEqual(r.memory_limit_bytes(), -1)

    def test_memory_limit_plain_number(self):
        r = PhpInfoResult(memory_limit="1048576")
        self.assertEqual(r.memory_limit_bytes(), 1048576)

    def test_memory_limit_none(self):
        r = PhpInfoResult()
        self.assertIsNone(r.memory_limit_bytes())

    def test_memory_limit_garbage(self):
        r = PhpInfoResult(memory_limit="lots")
        self.assertIsNone(r.memory_limit_bytes())

    def test_to_dict_keys(self):
        r = PhpInfoResult(found=True, url="http://x/info.php")
        d = r.to_dict()
        self.assertTrue(d["found"])
        self.assertEqual(d["url"], "http://x/info.php")
        self.assertIn("memory_limit_bytes", d)


# ---------------------------------------------------------------------------
# _extract_links
# ---------------------------------------------------------------------------

class TestExtractLinks(unittest.TestCase):
    def test_extracts_local_links_with_params(self):
        html = '<a href="page.php?id=5&cat=x">link</a>'
        results = _extract_links("http://example.com/", html)
        self.assertEqual(len(results), 1)
        path, params = results[0]
        self.assertEqual(path, "page.php")
        self.assertIn("id", params)

    def test_skips_external_links(self):
        html = '<a href="http://other.com/page.php?id=1">ext</a>'
        results = _extract_links("http://example.com/", html)
        self.assertEqual(len(results), 0)

    def test_skips_links_without_query(self):
        html = '<a href="/about.php">about</a>'
        results = _extract_links("http://example.com/", html)
        self.assertEqual(len(results), 0)

    def test_deduplicates_same_path_params(self):
        html = (
            '<a href="page.php?id=1">a</a>'
            '<a href="page.php?id=2">b</a>'
        )
        results = _extract_links("http://example.com/", html)
        self.assertEqual(len(results), 1)

    def test_same_origin_absolute_url(self):
        html = '<a href="http://example.com/view.php?doc=x">a</a>'
        results = _extract_links("http://example.com/", html)
        self.assertEqual(len(results), 1)


# ---------------------------------------------------------------------------
# _is_lfi_hit
# ---------------------------------------------------------------------------

class TestIsLfiHit(unittest.TestCase):
    def test_linux_hit(self):
        self.assertTrue(
            _is_lfi_hit("normal page", "root:x:0:0:root:/root:/bin/bash", "linux")
        )

    def test_linux_no_hit_baseline_contains(self):
        baseline = "root:x:0:0:root:/root:/bin/bash"
        self.assertFalse(_is_lfi_hit(baseline, baseline, "linux"))

    def test_linux_no_hit(self):
        self.assertFalse(_is_lfi_hit("page", "page with stuff", "linux"))

    def test_windows_hit(self):
        self.assertTrue(
            _is_lfi_hit("normal page", "[fonts]\nfoo=bar", "windows")
        )

    def test_windows_no_hit(self):
        self.assertFalse(_is_lfi_hit("page", "page", "windows"))

    def test_unknown_os_always_false(self):
        self.assertFalse(
            _is_lfi_hit("", "root:x:0:0:", "bsd")
        )


# ---------------------------------------------------------------------------
# _request_path / _full_url
# ---------------------------------------------------------------------------

class TestRequestPath(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(_request_path("http://x.com/app/", "/phpinfo.php"), "/app/phpinfo.php")

    def test_root_base(self):
        self.assertEqual(_request_path("http://x.com/", "/info.php"), "/info.php")

    def test_no_leading_slash(self):
        self.assertEqual(_request_path("http://x.com/app/", "test.php"), "/app/test.php")

    def test_path_already_contains_base(self):
        self.assertEqual(_request_path("http://x.com/app/", "/app/info.php"), "/app/info.php")


class TestFullUrl(unittest.TestCase):
    def test_full_url(self):
        self.assertEqual(
            _full_url("http://x.com/app/", "/phpinfo.php"),
            "http://x.com/app/phpinfo.php",
        )

    def test_full_url_root(self):
        self.assertEqual(
            _full_url("http://x.com/", "/info.php"),
            "http://x.com/info.php",
        )


# ---------------------------------------------------------------------------
# _body_text
# ---------------------------------------------------------------------------

class TestBodyText(unittest.TestCase):
    def test_returns_body_preview(self):
        ex = MagicMock(spec=HttpExchange)
        ex.body_preview = "hello"
        self.assertEqual(_body_text(ex), "hello")

    def test_returns_empty_for_none(self):
        ex = MagicMock(spec=HttpExchange)
        ex.body_preview = None
        self.assertEqual(_body_text(ex), "")

    def test_returns_empty_for_no_attr(self):
        obj = object()
        self.assertEqual(_body_text(obj), "")


# ---------------------------------------------------------------------------
# _nest_name
# ---------------------------------------------------------------------------

class TestNestName(unittest.TestCase):
    def test_basic_shape(self):
        name = _nest_name(0, 4, key_pad=10)
        self.assertIn(b"files[R00000", name)
        self.assertTrue(name.endswith(b"[a][a]"))

    def test_depth_1_no_nesting(self):
        name = _nest_name(1, 2, key_pad=5)
        self.assertNotIn(b"[a][a]", name)

    def test_index_formatting(self):
        name = _nest_name(42, 3, key_pad=5)
        self.assertIn(b"R00042", name)


# ---------------------------------------------------------------------------
# build_oom_probe_body / build_oom_lite_body
# ---------------------------------------------------------------------------

class TestBuildOomBodies(unittest.TestCase):
    def test_probe_body_is_multipart(self):
        body = build_oom_probe_body(parts=10, depth=4, big=2, big_len=100, burners=2, burner_len=100, progress_len=100)
        self.assertIn(b"--CCCCCCCCCC", body)
        self.assertIn(b"Content-Disposition: form-data", body)

    def test_probe_body_ends_with_terminator(self):
        body = build_oom_probe_body(parts=5, depth=3, big=1, big_len=50, burners=1, burner_len=50, progress_len=50)
        self.assertTrue(body.rstrip().endswith(b"--"))

    def test_lite_body_is_multipart(self):
        body = build_oom_lite_body(parts=10, depth=4)
        self.assertIn(b"--CCCCCCCCCC", body)
        self.assertIn(b"PHPSESSID", body)

    def test_lite_body_custom_boundary(self):
        body = build_oom_lite_body(parts=5, depth=3, boundary="XBND")
        self.assertIn(b"--XBND", body)

    def test_probe_body_nonzero(self):
        body = build_oom_probe_body()
        self.assertGreater(len(body), 1000)


# ---------------------------------------------------------------------------
# _extract_all_links
# ---------------------------------------------------------------------------

class TestExtractAllLinks(unittest.TestCase):
    def test_extracts_php_links(self):
        html = '<a href="view.php?id=1">a</a> <a href="style.css">b</a>'
        links = _extract_all_links("http://x.com/", html)
        php_links = [l for l in links if l.endswith(".php") or ".php?" in l]
        self.assertGreaterEqual(len(php_links), 1)

    def test_skips_external(self):
        html = '<a href="http://other.com/page.php">ext</a>'
        links = _extract_all_links("http://x.com/", html)
        self.assertEqual(len(links), 0)

    def test_skips_javascript(self):
        html = '<a href="javascript:void(0)">js</a>'
        links = _extract_all_links("http://x.com/", html)
        self.assertEqual(len(links), 0)

    def test_deduplicates(self):
        html = '<a href="page.php">a</a><a href="page.php">b</a>'
        links = _extract_all_links("http://x.com/", html)
        self.assertEqual(len(links), 1)

    def test_extracts_from_action_and_src(self):
        html = '<form action="submit.php"><img src="thumb.php"></form>'
        links = _extract_all_links("http://x.com/", html)
        self.assertGreaterEqual(len(links), 2)


# ---------------------------------------------------------------------------
# detect_framework
# ---------------------------------------------------------------------------

class TestDetectFramework(unittest.TestCase):
    def _make_exchange(self, headers=None, body=""):
        ex = HttpExchange(
            request_id="r1", method="GET", url="http://x.com/",
            sent_at="t", received_at="t", duration_ms=1.0,
            response_headers=headers or {},
            body_preview=body,
        )
        return ex

    def test_laravel_cookie(self):
        ex = self._make_exchange(headers={"Set-Cookie": "laravel_session=abc123"})
        from p2s.models import TargetProfile
        profile = TargetProfile(target="http://x.com/", base_url="http://x.com/", host="x.com", port=80, tls=False)
        fw, ver = detect_framework(profile, homepage_exchange=ex)
        self.assertEqual(fw, "Laravel")

    def test_wordpress_body(self):
        ex = self._make_exchange(body='<link href="/wp-content/themes/x/style.css">')
        from p2s.models import TargetProfile
        profile = TargetProfile(target="http://x.com/", base_url="http://x.com/", host="x.com", port=80, tls=False)
        fw, ver = detect_framework(profile, homepage_exchange=ex)
        self.assertEqual(fw, "WordPress")

    def test_no_framework(self):
        ex = self._make_exchange(body="<html>plain</html>")
        from p2s.models import TargetProfile
        profile = TargetProfile(target="http://x.com/", base_url="http://x.com/", host="x.com", port=80, tls=False)
        fw, ver = detect_framework(profile, homepage_exchange=ex)
        self.assertIsNone(fw)

    def test_no_exchange(self):
        from p2s.models import TargetProfile
        profile = TargetProfile(target="http://x.com/", base_url="http://x.com/", host="x.com", port=80, tls=False)
        fw, ver = detect_framework(profile, homepage_exchange=None)
        self.assertIsNone(fw)


# ---------------------------------------------------------------------------
# LfiEndpoint
# ---------------------------------------------------------------------------

class TestLfiEndpoint(unittest.TestCase):
    def test_build_include_url_traversal(self):
        ep = LfiEndpoint(url="http://x.com/page.php", param="file", method="traversal", traversal_depth="../../../../")
        url = ep.build_include_url("/etc/passwd")
        self.assertIn("etc%2Fpasswd", url)
        self.assertIn("file=", url)

    def test_build_include_url_direct(self):
        ep = LfiEndpoint(url="http://x.com/page.php", param="f", method="direct")
        url = ep.build_include_url("/tmp/sess_abc")
        self.assertIn("f=", url)
        self.assertIn("tmp", url)

    def test_to_dict(self):
        ep = LfiEndpoint(url="http://x.com/page.php", param="file")
        d = ep.to_dict()
        self.assertEqual(d["param"], "file")
        self.assertIn("method", d)


# ---------------------------------------------------------------------------
# DiscoverResult properties
# ---------------------------------------------------------------------------

class TestDiscoverResult(unittest.TestCase):
    def test_has_lfi_false(self):
        r = DiscoverResult()
        self.assertFalse(r.has_lfi)

    def test_has_lfi_true(self):
        r = DiscoverResult(lfi_endpoints=[LfiEndpoint(url="http://x.com/", param="f")])
        self.assertTrue(r.has_lfi)

    def test_chain_a_ready(self):
        r = DiscoverResult(
            lfi_endpoints=[LfiEndpoint(url="http://x.com/", param="f")],
            session_path="/tmp/sess_",
        )
        self.assertTrue(r.chain_a_ready)

    def test_chain_a_not_ready_no_session(self):
        r = DiscoverResult(lfi_endpoints=[LfiEndpoint(url="http://x.com/", param="f")])
        self.assertFalse(r.chain_a_ready)

    def test_chain_d_ready(self):
        r = DiscoverResult(oom_vulnerable=True, oom_sapi_is_mod_php=True)
        self.assertTrue(r.chain_d_ready)

    def test_chain_d_not_ready(self):
        r = DiscoverResult(oom_vulnerable=True, oom_sapi_is_mod_php=False)
        self.assertFalse(r.chain_d_ready)

    def test_wrapper_ready(self):
        r = DiscoverResult(wrapper_works="data://")
        self.assertTrue(r.wrapper_ready)

    def test_log_poison_ready(self):
        r = DiscoverResult(
            lfi_endpoints=[LfiEndpoint(url="http://x.com/", param="f")],
            log_poisoning_path="/var/log/apache2/access.log",
        )
        self.assertTrue(r.log_poison_ready)

    def test_best_lfi_prefers_data(self):
        ep1 = LfiEndpoint(url="http://x.com/", param="f", method="traversal")
        ep2 = LfiEndpoint(url="http://x.com/", param="f", method="data")
        r = DiscoverResult(lfi_endpoints=[ep1, ep2])
        self.assertEqual(r.best_lfi().method, "data")

    def test_best_lfi_fallback_first(self):
        ep1 = LfiEndpoint(url="http://x.com/", param="f", method="traversal")
        r = DiscoverResult(lfi_endpoints=[ep1])
        self.assertEqual(r.best_lfi().method, "traversal")

    def test_best_lfi_none(self):
        r = DiscoverResult()
        self.assertIsNone(r.best_lfi())

    def test_to_dict(self):
        r = DiscoverResult(oom_vulnerable=True, requests_used=42)
        d = r.to_dict()
        self.assertTrue(d["oom_vulnerable"])
        self.assertEqual(d["requests_used"], 42)


if __name__ == "__main__":
    unittest.main()
