"""Inventory: build, package, SAPI, configuration and patch state.

Trust rules:

* ``X-Powered-By`` and ``Server`` are LOW trust and can be spoofed/stripped.
* A user-supplied inventory file is only as good as its declared provenance.
* A local ``php -v``-style probe describes the host it ran on; if the target is
  not that host, the match is explicitly marked unverified.
* ``--sapi auto`` never guesses from the ``Server`` header.  It stays UNKNOWN
  unless a verified source (inventory file, local binary, lab status endpoint)
  supplies it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .classifier import KIND_FRONTEND_REJECT, KIND_PROXY_ERROR, classify, detect_frontend
from .http import HttpClient, HttpExchange
from .models import PatchAssessment, ReachAssessment, TargetProfile
from .patch import assess_patch, branch_of, is_packaged_version
from .util import (
    header_lookup,
    new_nonce,
    parse_iso,
    redact_url,
    utcnow,
)

VERSION_RE = re.compile(r"PHP/(\d+\.\d+\.\d+[^\s;)]*)")

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

SAPI_ALIASES = {
    "apache2handler": "mod_php",
    "apache2handler (mod_php)": "mod_php",
    "mod_php": "mod_php",
    "fpm-fcgi": "fpm",
    "php-fpm": "fpm",
    "fpm": "fpm",
    "frankenphp": "frankenphp",
    "litespeed": "lsapi",
    "lsapi": "lsapi",
    "cli-server": "cli-server",
    "cli": "cli",
    "cgi-fcgi": "cgi-fcgi",
}


@dataclass
class InventoryOptions:
    inventory_json: Optional[str] = None
    php_binary: Optional[str] = None
    status_url: Optional[str] = None
    sapi: str = "auto"
    environment_kind: str = "remote"
    synthetic: bool = False
    insecure: bool = False
    timeout: float = 10.0
    extra_headers: Dict[str, str] = field(default_factory=dict)
    ca_file: Optional[str] = None
    proxy: Optional[str] = None


def normalise_sapi(value: Optional[str]) -> str:
    if not value:
        return "unknown"
    text = str(value).strip().lower()
    if text in SAPI_ALIASES:
        return SAPI_ALIASES[text]
    for key, sapi in SAPI_ALIASES.items():
        if key in text:
            return sapi
    if "apache" in text:
        return "mod_php"
    if "fpm" in text:
        return "fpm"
    return text


def parse_powered_by(headers: Dict[str, str]) -> Tuple[Optional[str], str]:
    raw = header_lookup(headers, "X-Powered-By")
    match = VERSION_RE.search(raw or "")
    if not match:
        return None, ""
    return match.group(1), raw


def probe_local_php(binary: str, timeout: float = 10.0) -> Dict[str, Any]:
    code = (
        "echo json_encode(["
        "'version'=>PHP_VERSION,"
        "'sapi'=>PHP_SAPI,"
        "'build'=>PHP_BUILD_DATE ?? null,"
        "'os'=>PHP_OS,"
        "'zts'=>defined('PHP_ZTS')?PHP_ZTS:null,"
        "'config'=>php_ini_loaded_file(),"
        "'memory_limit'=>ini_get('memory_limit'),"
        "'post_max_size'=>ini_get('post_max_size'),"
        "'upload_progress'=>ini_get('session.upload_progress.enabled'),"
        "'fatal_error_backtraces'=>ini_get('fatal_error_backtraces')"
        "]);"
    )
    proc = subprocess.run(
        [binary, "-r", code],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        return {"error": (proc.stderr or proc.stdout or "php probe failed").strip()[:2000]}
    text = (proc.stdout or "").strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {"error": f"unparseable php probe output: {text[:500]}"}
    value["binary"] = binary
    value["probe"] = "local-php-binary"
    return value


def load_inventory_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("inventory JSON must be an object")
    return value


def _trust_from_inventory(value: Dict[str, Any]) -> str:
    trust = str(value.get("trust") or value.get("source_trust") or "").lower()
    if trust in ("high", "medium", "low"):
        return trust
    source = str(value.get("source") or "").lower()
    if any(word in source for word in ("package", "attestation", "build", "distro", "php-binary")):
        return "high"
    return "medium"


def _inventory_evidence_data(value: Dict[str, Any]) -> Dict[str, Any]:
    keep = {
        "source",
        "source_trust",
        "trust",
        "php_version",
        "version",
        "sapi",
        "packaging",
        "package",
        "backports",
        "build",
        "build_metadata",
        "config",
        "target_match",
        "reference",
        "collected_at",
        "notes",
    }
    return {key: value[key] for key in value if key in keep}


def _status_endpoint(
    client: HttpClient, status_url: Optional[str], timeout: float
) -> Optional[Tuple[HttpExchange, Dict[str, Any], bool]]:
    if not status_url:
        return None
    nonce = new_nonce("P2SSTATUS")
    exchange = client.request(
        "GET",
        status_url,
        headers={"Accept": "application/json", "X-P2S-Nonce": nonce},
        nonce=nonce,
        timeout=timeout,
    )
    verified = False
    payload: Dict[str, Any] = {}
    if exchange.status == 200 and exchange.body_preview:
        try:
            payload = json.loads(exchange.body_preview)
        except json.JSONDecodeError:
            payload = {}
    if payload:
        echoed = str(payload.get("nonce") or payload.get("request_nonce") or "")
        header_nonce = header_lookup(exchange.response_headers, "X-P2S-Nonce")
        request_id = str(payload.get("request_id") or header_lookup(exchange.response_headers, "X-P2S-Request-ID"))
        verified = bool(
            (echoed == nonce or header_nonce == nonce)
            and request_id
            and exchange.request_id in (request_id, header_lookup(exchange.response_headers, "X-P2S-Request-ID"))
        )
    return exchange, payload, verified


def collect(
    target: str,
    client: HttpClient,
    options: InventoryOptions,
    store: Any = None,
    run_id: str = "",
) -> TargetProfile:
    """Collect inventory.  Sends GET requests only; never OOM payloads."""
    from urllib.parse import urlsplit

    parts = urlsplit(target)
    profile = TargetProfile(
        target=target,
        base_url=target.rstrip("/") + "/",
        host=parts.hostname or "",
        port=parts.port or (443 if parts.scheme == "https" else 80),
        tls=parts.scheme == "https",
        environment_kind=options.environment_kind,
        collected_at=utcnow(),
    )

    exchange = client.request("GET", target, headers={"Accept": "text/html,application/json;q=0.9,*/*;q=0.8"})
    classification = classify(exchange)
    profile.frontend = detect_frontend(exchange.response_headers or {})
    if store is not None:
        item = store.add_http(
            exchange,
            classification,
            scenario_id="inventory",
            trust="high",
            notes="inventory control GET",
            synthetic=options.synthetic,
        )
        profile.build_metadata.setdefault("evidence_refs", []).append(item.id)

    if exchange.error_kind:
        profile.notes.append(f"control GET failed: {exchange.error_kind}: {exchange.error_message}")
    elif classification.frontend_reject or classification.kind == KIND_PROXY_ERROR:
        profile.notes.append(
            f"control GET was answered by a frontend/error page: {classification.detail}"
        )

    version, banner = parse_powered_by(exchange.response_headers or {})
    if version:
        profile.php_version = version
        profile.version_source = "x-powered-by"
        profile.version_trust = "low"
        profile.build_metadata["x_powered_by"] = banner
        profile.notes.append(
            "X-Powered-By reports PHP but is LOW trust (spoofable, strippable, may "
            "describe a different layer). It is not patch evidence."
        )
    else:
        profile.notes.append("X-Powered-By did not expose a PHP version (may be hidden).")

    # Verified lab status endpoint (explicit opt-in).
    status = _status_endpoint(client, options.status_url, options.timeout)
    if status is not None:
        status_exchange, payload, verified = status
        if store is not None:
            item = store.add_http(
                status_exchange,
                classify(status_exchange),
                scenario_id="inventory-status",
                trust="high" if verified else "low",
                notes="lab status endpoint; verified" if verified else "status endpoint did not prove nonce/request binding",
                synthetic=options.synthetic,
            )
            profile.build_metadata.setdefault("evidence_refs", []).append(item.id)
        if verified:
            sapi = normalise_sapi(payload.get("sapi"))
            if sapi != "unknown":
                profile.sapi = sapi
                profile.sapi_source = "lab-status-endpoint"
                profile.sapi_verified = True
            if payload.get("php_version"):
                # A nonce/request-bound lab status response is a verified build
                # source; it upgrades (never downgrades) the low-trust banner.
                profile.php_version = str(payload["php_version"])
                profile.version_source = "lab-status-endpoint"
                profile.version_trust = "high"
                profile.build_metadata["lab_status_version"] = payload.get("php_version")
            worker = payload.get("worker_pid")
            request_id = payload.get("request_id") or header_lookup(
                status_exchange.response_headers, "X-P2S-Request-ID"
            )
            profile.reach = ReachAssessment(
                state="REACHED",
                basis=["lab status endpoint echoed the per-request nonce and request id"],
                request_id=str(request_id) if request_id else None,
                worker_id=str(worker) if worker is not None else None,
                frontend=profile.frontend,
                evidence_refs=[item.id] if store is not None else [],
                limitations=["Verified only for the status endpoint path"],
            )
            profile.build_metadata["config"] = {
                key: payload.get(key)
                for key in (
                    "memory_limit",
                    "post_max_size",
                    "upload_max_filesize",
                    "session_upload_progress",
                    "fatal_error_backtraces",
                )
                if key in payload
            }
        else:
            profile.notes.append(
                "Status endpoint response did not prove nonce/request binding; its "
                "sapi/build claims were not trusted."
            )

    # Operator-provided inventory file.
    inventory: Dict[str, Any] = {}
    if options.inventory_json:
        try:
            inventory = load_inventory_file(options.inventory_json)
            if store is not None:
                item = store.add(
                    "host_inventory",
                    {"inventory": _inventory_evidence_data(inventory)},
                    trust=_trust_from_inventory(inventory),
                    scenario_id="inventory-file",
                    notes=f"operator inventory file {os.path.basename(options.inventory_json)}",
                    synthetic=options.synthetic,
                )
        except (OSError, ValueError) as exc:
            profile.notes.append(f"inventory file could not be loaded: {exc}")

    # Local php binary probe.
    if options.php_binary:
        try:
            probe = probe_local_php(options.php_binary)
            if store is not None:
                store.add(
                    "host_inventory",
                    {"php_probe": probe},
                    trust="high" if profile.host in LOCAL_HOSTS else "medium",
                    scenario_id="inventory-php-binary",
                    notes="local php binary probe; target match must be checked",
                    synthetic=options.synthetic,
                )
            if "error" not in probe:
                inventory.setdefault("php_version", probe.get("version"))
                inventory.setdefault("sapi", probe.get("sapi"))
                inventory.setdefault("build", probe.get("build"))
                inventory.setdefault("source", "php-binary-local")
                inventory.setdefault("trust", "high" if profile.host in LOCAL_HOSTS else "medium")
                inventory.setdefault(
                    "target_match",
                    profile.host in LOCAL_HOSTS,
                )
                inventory.setdefault(
                    "config",
                    {
                        "memory_limit": probe.get("memory_limit"),
                        "post_max_size": probe.get("post_max_size"),
                        "session.upload_progress.enabled": probe.get("upload_progress"),
                        "fatal_error_backtraces": probe.get("fatal_error_backtraces"),
                    },
                )
            else:
                profile.notes.append(f"local php probe failed: {probe['error']}")
        except (OSError, subprocess.SubprocessError) as exc:
            profile.notes.append(f"local php probe failed: {exc}")

    if inventory:
        _apply_inventory(profile, inventory)

    # Declared SAPI (operator), never auto-guessed.
    declared = normalise_sapi(options.sapi)
    if declared != "auto" and declared != "unknown" and not profile.sapi_verified:
        profile.sapi = declared
        profile.sapi_source = "operator-declared"
        profile.sapi_verified = False
        profile.notes.append(
            f"SAPI {declared} was declared by the operator; it is not verified and "
            "cannot support AFFECTED_PATH_CONFIRMED on its own."
        )

    if profile.reach.state == "UNKNOWN":
        if exchange.error_kind:
            profile.reach = ReachAssessment(
                state="UNKNOWN",
                basis=[f"control request failed: {exchange.error_kind}"],
                frontend=profile.frontend,
                limitations=[exchange.error_message or ""],
            )
        elif classification.kind == KIND_FRONTEND_REJECT:
            profile.reach = ReachAssessment(
                state="BLOCKED",
                basis=[classification.detail],
                frontend=profile.frontend,
                blocked_by="frontend/WAF",
                limitations=["Request did not reach PHP; no CVE conclusion is possible."],
            )
        elif classification.php_marker:
            profile.reach = ReachAssessment(
                state="PROBABLE",
                basis=["control response contains a PHP-generated header/cookie"],
                frontend=profile.frontend,
                limitations=[
                    "A PHP header/cookie makes reach probable but does not prove this "
                    "specific request traversed the PHP request lifecycle."
                ],
            )
        else:
            profile.reach = ReachAssessment(
                state="UNKNOWN",
                basis=["no PHP-specific response evidence"],
                frontend=profile.frontend,
                limitations=["Frontend may have served a static/cached response."],
            )

    profile.patch = assess_patch(
        profile.php_version,
        source=profile.version_source,
        trust=profile.version_trust,
        packaging=profile.packaging,
        backports=profile.patch.backports if profile.patch else [],
    )
    return profile


def _apply_inventory(profile: TargetProfile, inventory: Dict[str, Any]) -> None:
    trust = _trust_from_inventory(inventory)
    target_match = inventory.get("target_match")
    if target_match is False and trust == "high":
        trust = "medium"
        profile.notes.append(
            "Inventory was collected on a different host than the target; trust "
            "downgraded to medium."
        )

    version = inventory.get("php_version") or inventory.get("version")
    if version:
        text = str(version).strip()
        text = text.replace("PHP/", "")
        profile.php_version = text
        profile.version_source = str(inventory.get("source") or "inventory-file")
        profile.version_trust = trust
        profile.build_metadata["inventory"] = _inventory_evidence_data(inventory)
    sapi = inventory.get("sapi")
    if sapi:
        normal = normalise_sapi(sapi)
        profile.sapi = normal
        profile.sapi_source = str(inventory.get("source") or "inventory-file")
        profile.sapi_verified = trust in ("high", "medium") and normal != "unknown"
    profile.packaging = inventory.get("packaging") or inventory.get("package")
    if inventory.get("build_metadata") or inventory.get("build"):
        profile.build_metadata["build"] = inventory.get("build_metadata") or inventory.get("build")
    if inventory.get("config"):
        profile.config = dict(inventory["config"])
    backports = inventory.get("backports") or []
    if isinstance(backports, list):
        profile.patch.backports = backports
    profile.patch = assess_patch(
        profile.php_version,
        source=str(inventory.get("source") or "inventory-file"),
        trust=trust,
        packaging=profile.packaging,
        backports=backports,
        build_metadata=profile.build_metadata.get("build") if isinstance(profile.build_metadata.get("build"), dict) else {},
        notes=list(profile.notes),
    )
    profile.patch.packaging = profile.packaging
    if is_packaged_version(profile.php_version) and profile.patch.state == "AFFECTED":
        profile.notes.append(
            "Packaged version below fixed upstream release: backport evidence required."
        )
    if profile.php_version:
        profile.notes.append(f"build branch: {branch_of(profile.php_version)}")


def patch_evidence(profile: TargetProfile) -> Dict[str, Any]:
    payload = profile.patch.to_dict()
    payload["version_source"] = profile.version_source
    payload["version_trust"] = profile.version_trust
    return payload
