"""Data model for findings, evidence and scenario runs.

The model is deliberately explicit.  A finding cannot be constructed without
the fields the report contract requires, and a status outside the CVE-specific
enum is rejected.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .util import parse_iso, sha256_bytes, canonical_json, utcnow
from .version import CVE_618, CVE_619, CVES

# ---------------------------------------------------------------------------
# Statuses
# ---------------------------------------------------------------------------

ST_NOT_TESTED = "NOT_TESTED"
ST_INCONCLUSIVE = "INCONCLUSIVE"
ST_PREREQUISITE_OBSERVED = "PREREQUISITE_OBSERVED"
ST_EXPOSED_BUILD = "EXPOSED_BUILD"
ST_PATCH_CONFIRMED = "PATCH_CONFIRMED"

ST_OOM_OBSERVED = "OOM_OBSERVED"
ST_AFFECTED_PATH_CONFIRMED = "AFFECTED_PATH_CONFIRMED"

ST_PRODUCER_OBSERVED = "PRODUCER_OBSERVED"
ST_PRODUCER_CONSUMER_CORRELATED = "PRODUCER_CONSUMER_CORRELATED"
ST_STALE_STATE_CONFIRMED = "STALE_STATE_CONFIRMED"

ST_CODE_EXECUTION_CONFIRMED = "CODE_EXECUTION_CONFIRMED"

STATUSES_618 = [
    ST_NOT_TESTED,
    ST_INCONCLUSIVE,
    ST_PREREQUISITE_OBSERVED,
    ST_EXPOSED_BUILD,
    ST_OOM_OBSERVED,
    ST_AFFECTED_PATH_CONFIRMED,
    ST_CODE_EXECUTION_CONFIRMED,
    ST_PATCH_CONFIRMED,
]

STATUSES_619 = [
    ST_NOT_TESTED,
    ST_INCONCLUSIVE,
    ST_PREREQUISITE_OBSERVED,
    ST_EXPOSED_BUILD,
    ST_PRODUCER_OBSERVED,
    ST_PRODUCER_CONSUMER_CORRELATED,
    ST_STALE_STATE_CONFIRMED,
    ST_CODE_EXECUTION_CONFIRMED,
    ST_PATCH_CONFIRMED,
]

STATUS_BY_CVE = {CVE_618: STATUSES_618, CVE_619: STATUSES_619}

# Display order only.  PATCH_CONFIRMED is intentionally outside the proof
# ladder: it must come from build/package evidence, never from a probe.
STATUS_RANK = {
    ST_NOT_TESTED: 0,
    ST_INCONCLUSIVE: 1,
    ST_PREREQUISITE_OBSERVED: 2,
    ST_EXPOSED_BUILD: 3,
    ST_OOM_OBSERVED: 4,
    ST_PRODUCER_OBSERVED: 4,
    ST_AFFECTED_PATH_CONFIRMED: 5,
    ST_PRODUCER_CONSUMER_CORRELATED: 5,
    ST_STALE_STATE_CONFIRMED: 6,
    ST_CODE_EXECUTION_CONFIRMED: 7,
    ST_PATCH_CONFIRMED: 99,
}

NON_PROOF_STATUSES = {
    ST_NOT_TESTED,
    ST_INCONCLUSIVE,
    ST_PREREQUISITE_OBSERVED,
    ST_EXPOSED_BUILD,
    ST_OOM_OBSERVED,
    ST_PRODUCER_OBSERVED,
}

PROOF_STATUSES = {
    ST_AFFECTED_PATH_CONFIRMED,
    ST_PRODUCER_CONSUMER_CORRELATED,
    ST_STALE_STATE_CONFIRMED,
    ST_CODE_EXECUTION_CONFIRMED,
}

# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

EVIDENCE_SOURCES = {
    "http",
    "php_log",
    "web_server_log",
    "worker_telemetry",
    "host_inventory",
    "lab_trace",
    "canary",
    "operator",
}

EVIDENCE_TRUST = {"high", "medium", "low", "none"}


@dataclass
class Evidence:
    id: str
    source: str
    timestamp: str
    data: Dict[str, Any]
    sha256: str
    correlation_id: Optional[str] = None
    request_id: Optional[str] = None
    worker_id: Optional[str] = None
    artifact_path: Optional[str] = None
    scenario_id: Optional[str] = None
    trust: str = "medium"
    redacted: bool = True
    truncated: bool = False
    notes: str = ""
    synthetic: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "request_id": self.request_id,
            "worker_id": self.worker_id,
            "data": self.data,
            "sha256": self.sha256,
            "artifact_path": self.artifact_path,
            "scenario_id": self.scenario_id,
            "trust": self.trust,
            "redacted": self.redacted,
            "truncated": self.truncated,
            "notes": self.notes,
            "synthetic": self.synthetic,
        }

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "Evidence":
        return cls(
            id=str(value["id"]),
            source=str(value["source"]),
            timestamp=str(value["timestamp"]),
            data=dict(value.get("data") or {}),
            sha256=str(value["sha256"]),
            correlation_id=value.get("correlation_id"),
            request_id=value.get("request_id"),
            worker_id=value.get("worker_id"),
            artifact_path=value.get("artifact_path"),
            scenario_id=value.get("scenario_id"),
            trust=value.get("trust", "medium"),
            redacted=bool(value.get("redacted", True)),
            truncated=bool(value.get("truncated", False)),
            notes=value.get("notes", ""),
            synthetic=bool(value.get("synthetic", False)),
        )

    def validate(self) -> List[str]:
        errors: List[str] = []
        if not self.id:
            errors.append("evidence id is empty")
        if self.source not in EVIDENCE_SOURCES:
            errors.append(f"evidence {self.id}: invalid source {self.source!r}")
        if parse_iso(self.timestamp) is None:
            errors.append(f"evidence {self.id}: invalid timestamp {self.timestamp!r}")
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256 or ""):
            errors.append(f"evidence {self.id}: invalid sha256")
        if self.trust not in EVIDENCE_TRUST:
            errors.append(f"evidence {self.id}: invalid trust {self.trust!r}")
        if not isinstance(self.data, dict):
            errors.append(f"evidence {self.id}: data must be an object")
        return errors

    def recompute_sha256(self) -> str:
        return sha256_bytes(canonical_json(self.data))


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

FINDING_REQUIRED = (
    "cve",
    "status",
    "scenario_id",
    "evidence_refs",
    "proof_method",
    "proof_limitations",
    "alternative_explanations",
    "missing_evidence",
    "patch_evidence",
    "remediation",
    "reproduction_context",
)


@dataclass
class Finding:
    cve: str
    status: str
    scenario_id: str
    evidence_refs: List[str] = field(default_factory=list)
    proof_method: str = ""
    proof_limitations: List[str] = field(default_factory=list)
    alternative_explanations: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    patch_evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: List[str] = field(default_factory=list)
    reproduction_context: Dict[str, Any] = field(default_factory=dict)
    status_reason: str = ""
    observations: List[Dict[str, Any]] = field(default_factory=list)
    advisory: Dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve": self.cve,
            "status": self.status,
            "scenario_id": self.scenario_id,
            "evidence_refs": list(self.evidence_refs),
            "proof_method": self.proof_method,
            "proof_limitations": list(self.proof_limitations),
            "alternative_explanations": list(self.alternative_explanations),
            "missing_evidence": list(self.missing_evidence),
            "patch_evidence": dict(self.patch_evidence),
            "remediation": list(self.remediation),
            "reproduction_context": dict(self.reproduction_context),
            "status_reason": self.status_reason,
            "observations": list(self.observations),
            "advisory": dict(self.advisory),
            "generated_at": self.generated_at,
        }

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "Finding":
        return cls(
            cve=value["cve"],
            status=value["status"],
            scenario_id=value.get("scenario_id", ""),
            evidence_refs=list(value.get("evidence_refs") or []),
            proof_method=value.get("proof_method", ""),
            proof_limitations=list(value.get("proof_limitations") or []),
            alternative_explanations=list(value.get("alternative_explanations") or []),
            missing_evidence=list(value.get("missing_evidence") or []),
            patch_evidence=dict(value.get("patch_evidence") or {}),
            remediation=list(value.get("remediation") or []),
            reproduction_context=dict(value.get("reproduction_context") or {}),
            status_reason=value.get("status_reason", ""),
            observations=list(value.get("observations") or []),
            advisory=dict(value.get("advisory") or {}),
            generated_at=value.get("generated_at", utcnow()),
        )

    def validate(self) -> List[str]:
        errors: List[str] = []
        if self.cve not in CVES:
            errors.append(f"invalid cve {self.cve!r}")
        elif self.status not in STATUS_BY_CVE[self.cve]:
            errors.append(f"{self.cve}: invalid status {self.status!r}")
        for key in FINDING_REQUIRED:
            if key not in self.to_dict():
                errors.append(f"{self.cve}: missing required field {key}")
        if not self.scenario_id:
            errors.append(f"{self.cve}: scenario_id is required")
        if self.status in PROOF_STATUSES and not self.evidence_refs:
            errors.append(f"{self.cve}: proof status {self.status} without evidence_refs")
        if self.status == ST_CODE_EXECUTION_CONFIRMED:
            if not self.reproduction_context.get("canary_verified"):
                errors.append(f"{self.cve}: CODE_EXECUTION_CONFIRMED without canary_verified")
        if self.status == ST_PATCH_CONFIRMED:
            per_cve = (self.patch_evidence.get("per_cve") or {}).get(self.cve) or {}
            if (
                self.patch_evidence.get("state") != "PATCHED"
                and per_cve.get("state") != "PATCHED"
            ):
                errors.append(f"{self.cve}: PATCH_CONFIRMED without patched build evidence")
        return errors


# ---------------------------------------------------------------------------
# Patch / target profile
# ---------------------------------------------------------------------------


@dataclass
class PatchAssessment:
    state: str = "UNKNOWN"  # PATCHED | AFFECTED | UNKNOWN
    source: str = "none"
    trust: str = "none"  # high | medium | low | none
    details: str = ""
    version: Optional[str] = None
    branch: Optional[str] = None
    fixed_version: Optional[str] = None
    packaging: Optional[str] = None
    backports: List[Dict[str, Any]] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    # Per-CVE state so a distro backport for one advisory is never silently
    # applied to the other.  Keys are the CVE ids; values contain
    # state/trust/details.
    per_cve: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "PatchAssessment":
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in (value or {}).items() if k in known})


@dataclass
class ReachAssessment:
    state: str = "UNKNOWN"  # REACHED | PROBABLE | BLOCKED | UNKNOWN
    basis: List[str] = field(default_factory=list)
    request_id: Optional[str] = None
    worker_id: Optional[str] = None
    frontend: Dict[str, Any] = field(default_factory=dict)
    blocked_by: Optional[str] = None
    evidence_refs: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "ReachAssessment":
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in (value or {}).items() if k in known})


@dataclass
class TargetProfile:
    target: str
    base_url: str
    host: str
    port: int
    tls: bool
    php_version: Optional[str] = None
    version_source: str = "none"
    version_trust: str = "none"
    sapi: str = "unknown"
    sapi_source: str = "none"
    sapi_verified: bool = False
    patch: PatchAssessment = field(default_factory=PatchAssessment)
    reach: ReachAssessment = field(default_factory=ReachAssessment)
    environment_kind: str = "remote"  # remote | lab | fixture
    packaging: Optional[str] = None
    build_metadata: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    frontend: Dict[str, Any] = field(default_factory=dict)
    collected_at: str = field(default_factory=utcnow)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "base_url": self.base_url,
            "host": self.host,
            "port": self.port,
            "tls": self.tls,
            "php_version": self.php_version,
            "version_source": self.version_source,
            "version_trust": self.version_trust,
            "sapi": self.sapi,
            "sapi_source": self.sapi_source,
            "sapi_verified": self.sapi_verified,
            "patch": self.patch.to_dict(),
            "reach": self.reach.to_dict(),
            "environment_kind": self.environment_kind,
            "packaging": self.packaging,
            "build_metadata": dict(self.build_metadata),
            "config": dict(self.config),
            "frontend": dict(self.frontend),
            "collected_at": self.collected_at,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "TargetProfile":
        return cls(
            target=value["target"],
            base_url=value["base_url"],
            host=value["host"],
            port=int(value["port"]),
            tls=bool(value["tls"]),
            php_version=value.get("php_version"),
            version_source=value.get("version_source", "none"),
            version_trust=value.get("version_trust", "none"),
            sapi=value.get("sapi", "unknown"),
            sapi_source=value.get("sapi_source", "none"),
            sapi_verified=bool(value.get("sapi_verified", False)),
            patch=PatchAssessment.from_dict(value.get("patch") or {}),
            reach=ReachAssessment.from_dict(value.get("reach") or {}),
            environment_kind=value.get("environment_kind", "remote"),
            packaging=value.get("packaging"),
            build_metadata=dict(value.get("build_metadata") or {}),
            config=dict(value.get("config") or {}),
            frontend=dict(value.get("frontend") or {}),
            collected_at=value.get("collected_at", utcnow()),
            notes=list(value.get("notes") or []),
        )


# ---------------------------------------------------------------------------
# Scenario model
# ---------------------------------------------------------------------------


@dataclass
class ScenarioDefinition:
    id: str
    cve: str
    title: str
    sapi_applicability: List[str]
    producer: str
    consumer: str
    description: str
    impact: str
    requires: List[str] = field(default_factory=list)
    lab_only: bool = False
    default_enabled: bool = True
    max_requests: int = 2
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class ScenarioRun:
    scenario_id: str
    cve: str
    executed: bool = False
    skipped_reason: str = ""
    started_at: str = ""
    finished_at: str = ""
    request_refs: List[str] = field(default_factory=list)
    control_refs: List[str] = field(default_factory=list)
    health_refs: List[str] = field(default_factory=list)
    telemetry_refs: List[str] = field(default_factory=list)
    trace_refs: List[str] = field(default_factory=list)
    canary_refs: List[str] = field(default_factory=list)
    producer_request_id: Optional[str] = None
    consumer_request_id: Optional[str] = None
    producer_worker_id: Optional[str] = None
    consumer_worker_id: Optional[str] = None
    oom_refs: List[str] = field(default_factory=list)
    state_publish_refs: List[str] = field(default_factory=list)
    state_consume_refs: List[str] = field(default_factory=list)
    correlation: Dict[str, Any] = field(default_factory=dict)
    canary: Dict[str, Any] = field(default_factory=dict)
    interrupted: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "ScenarioRun":
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in (value or {}).items() if k in known})


@dataclass
class CaseFile:
    profile: TargetProfile
    evidence: List[Evidence] = field(default_factory=list)
    scenario_runs: List[ScenarioRun] = field(default_factory=list)
    run_id: str = ""
    tool_version: str = ""
    mode: str = ""
    started_at: str = ""
    finished_at: str = ""
    environment: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def evidence_index(self) -> Dict[str, Evidence]:
        return {item.id: item for item in self.evidence}

    def by_scenario(self, scenario_id: str) -> List[ScenarioRun]:
        return [run for run in self.scenario_runs if run.scenario_id == scenario_id]

    def validate(self) -> List[str]:
        errors: List[str] = []
        seen = set()
        for item in self.evidence:
            if item.id in seen:
                errors.append(f"duplicate evidence id {item.id}")
            seen.add(item.id)
            errors.extend(item.validate())
        for run in self.scenario_runs:
            for ref in (
                run.request_refs
                + run.control_refs
                + run.health_refs
                + run.telemetry_refs
                + run.trace_refs
                + run.canary_refs
                + run.oom_refs
                + run.state_publish_refs
                + run.state_consume_refs
            ):
                if ref not in seen:
                    errors.append(f"{run.scenario_id}: dangling evidence ref {ref}")
        return errors
