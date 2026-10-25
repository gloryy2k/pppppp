"""Build/package patch assessment.

Version comparison is only one input.  A distro package version such as
``8.2.29-1+deb12u6`` may contain a backport even though the upstream version
number is below the fixed release; therefore packaged builds are UNKNOWN
unless backport evidence is supplied.  Conversely a patched banner alone
(``X-Powered-By``) never yields PATCH_CONFIRMED because that source is low
trust.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .models import PatchAssessment
from .version import CVE_618, CVE_619, FIXED_VERSIONS

_VERSION_RE = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)(.*)$")
_PACKAGED_RE = re.compile(
    r"(-|~|\+|\.?ubuntu|\.?deb|\.?el\d|\.?fc\d|\.?rhel|\.?suse|\.?amzn|\.?alpine)",
    re.IGNORECASE,
)

# Sources that are strong enough to confirm a patch when they explicitly
# describe the artifact that serves the target.
HIGH_TRUST_SOURCES = {
    "php-binary-local",
    "target-php-binary",
    "package-manifest",
    "distro-advisory",
    "vendor-attestation",
    "build-metadata",
    "lab-inventory",
}


def parse_version(version: Optional[str]) -> Optional[Tuple[int, int, int, str]]:
    if not version:
        return None
    match = _VERSION_RE.match(str(version))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), match.group(4) or ""


def branch_of(version: Optional[str]) -> Optional[str]:
    parsed = parse_version(version)
    if not parsed:
        return None
    return f"{parsed[0]}.{parsed[1]}"


def fixed_version(version: Optional[str]) -> Optional[str]:
    parsed = parse_version(version)
    if not parsed:
        return None
    major, minor, _, _ = parsed
    patch = FIXED_VERSIONS.get((major, minor))
    if patch is None:
        return None
    return f"{major}.{minor}.{patch}"


def is_packaged_version(version: Optional[str]) -> bool:
    if not version:
        return False
    parsed = parse_version(version)
    suffix = parsed[3] if parsed else str(version)
    # A bare -RC1/-dev suffix is not distro packaging.
    if re.match(r"^-?(RC|rc|dev|beta|alpha)", suffix):
        return False
    return bool(_PACKAGED_RE.search(str(version)))


def _backport_for(backports: List[Dict[str, Any]], cve: str) -> Optional[Dict[str, Any]]:
    for item in backports or []:
        cves = item.get("cves") or item.get("cve") or ""
        if isinstance(cves, str):
            cves = [cves]
        if cve in cves:
            return item
        if item.get("all_cves") and item.get("status") in ("fixed", "not_fixed", "affected", "patched"):
            return item
    return None


def _backport_trust(item: Dict[str, Any]) -> str:
    source = str(item.get("source") or "").lower()
    reference = str(item.get("reference") or "").strip()
    if not reference:
        return "low"
    for known in (
        "debian",
        "ubuntu",
        "redhat",
        "rhel",
        "suse",
        "alpine",
        "php.net",
        "github.com/php",
        "vendor",
    ):
        if known in source:
            return "high"
    return "medium"


def assess_patch(
    version: Optional[str],
    source: str = "none",
    trust: str = "none",
    packaging: Optional[str] = None,
    backports: Optional[List[Dict[str, Any]]] = None,
    build_metadata: Optional[Dict[str, Any]] = None,
    notes: Optional[List[str]] = None,
) -> PatchAssessment:
    """Assess patch state for both CVEs from build/package facts."""
    backports = list(backports or [])
    notes = list(notes or [])
    build_metadata = dict(build_metadata or {})
    parsed = parse_version(version)

    result = PatchAssessment(
        state="UNKNOWN",
        source=source,
        trust=trust if trust in ("high", "medium", "low", "none") else "none",
        version=version,
        packaging=packaging,
        backports=backports,
        notes=notes,
    )

    if not parsed:
        result.details = "No parseable PHP version/build was supplied."
        result.notes.append("Version/banner alone is not patch evidence.")
        return result

    major, minor, patch, suffix = parsed
    result.branch = f"{major}.{minor}"
    result.fixed_version = fixed_version(version)
    packaged = is_packaged_version(version) or bool(packaging and packaging != "source")
    if packaged:
        result.packaging = packaging or suffix.strip("-+") or "packaged"

    fixed_patch = FIXED_VERSIONS.get((major, minor))
    if fixed_patch is None:
        result.state = "UNKNOWN"
        result.details = (
            f"PHP {version} is on branch {major}.{minor}, which is not covered by "
            f"the advisory's published fixed releases ({', '.join(f'{k[0]}.{k[1]}' for k in FIXED_VERSIONS)})."
        )
        result.notes.append(
            "Do not extrapolate the advisory range to unsupported/EOL branches; "
            "no fixed release or backport status is known."
        )
        result.per_cve = {
            cve: {"state": "UNKNOWN", "trust": result.trust, "details": result.details}
            for cve in (CVE_618, CVE_619)
        }
        return result

    upstream_patched = patch > fixed_patch or (
        patch == fixed_patch and not re.match(r"^-?(RC|rc|dev|beta|alpha)", suffix)
    )

    per_cve: Dict[str, Dict[str, Any]] = {}
    for cve in (CVE_618, CVE_619):
        backport = _backport_for(backports, cve)
        if backport:
            btrust = _backport_trust(backport)
            status = str(backport.get("status") or "").lower()
            result.notes.append(
                f"Backport evidence for {cve}: {backport.get('source', 'unknown')} "
                f"{backport.get('reference', '(no reference)')} -> {status or 'unknown'}"
            )
            if status in ("fixed", "patched", "not_affected") and btrust in ("high", "medium"):
                per_cve[cve] = {
                    "state": "PATCHED",
                    "trust": "high" if btrust == "high" else "medium",
                    "details": f"Packaged PHP {version} carries an explicit backport for {cve}.",
                }
            elif status in ("not_fixed", "affected", "vulnerable"):
                per_cve[cve] = {
                    "state": "AFFECTED",
                    "trust": "high" if btrust == "high" else "medium",
                    "details": (
                        f"Backport evidence for PHP {version} reports the package as not "
                        f"fixed for {cve}."
                    ),
                }
            else:
                per_cve[cve] = {
                    "state": "UNKNOWN",
                    "trust": "low",
                    "details": (
                        f"Backport evidence for PHP {version} is incomplete or untrusted "
                        f"for {cve}."
                    ),
                }
            continue

        if packaged:
            if upstream_patched:
                per_cve[cve] = {
                    "state": "PATCHED",
                    "trust": result.trust,
                    "details": (
                        f"Upstream version {version} is at/above {result.fixed_version}; "
                        "no backport downgrade is indicated."
                    ),
                }
            else:
                per_cve[cve] = {
                    "state": "UNKNOWN",
                    "trust": result.trust,
                    "details": (
                        f"PHP {version} is a packaged build below upstream {result.fixed_version}. "
                        "The distribution may have backported the fix; no backport evidence "
                        f"was supplied for {cve}."
                    ),
                }
                result.notes.append(
                    "Package suffix detected. Do not report AFFECTED or PATCHED from the "
                    "upstream version number alone; collect distro security-tracker evidence."
                )
            continue

        if upstream_patched:
            per_cve[cve] = {
                "state": "PATCHED",
                "trust": result.trust,
                "details": f"PHP {version} is at/above fixed release {result.fixed_version}.",
            }
        else:
            per_cve[cve] = {
                "state": "AFFECTED",
                "trust": result.trust,
                "details": f"PHP {version} is below fixed release {result.fixed_version}.",
            }

    result.per_cve = per_cve
    states = {cve: per_cve[cve]["state"] for cve in per_cve}
    if all(state == "PATCHED" for state in states.values()):
        result.state = "PATCHED"
    elif any(state == "AFFECTED" for state in states.values()):
        result.state = "AFFECTED"
    else:
        result.state = "UNKNOWN"
    trust_order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    result.trust = max(
        (per_cve[cve]["trust"] for cve in per_cve),
        key=lambda value: trust_order.get(value, 0),
        default=result.trust,
    )
    result.details = "; ".join(
        f"{cve}: {per_cve[cve]['details']}" for cve in (CVE_618, CVE_619)
    )
    return result


def merge_backports(*collections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()
    for collection in collections:
        for item in collection or []:
            key = (
                str(item.get("cve") or item.get("cves")),
                str(item.get("status")),
                str(item.get("package_version")),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(dict(item))
    return merged
