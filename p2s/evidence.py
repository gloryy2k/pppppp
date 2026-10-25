"""Append-only evidence store and case persistence.

Each evidence item is written twice:

  * as a canonical JSON artifact under ``artifacts/`` whose SHA-256 is stored
    in the evidence record;
  * as one line in ``evidence.jsonl``.

``report`` mode reads these files and re-runs the assessors without sending a
single HTTP request.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Any, Dict, Iterable, List, Optional

from .models import CaseFile, Evidence, ScenarioRun, TargetProfile, Finding
from .util import (
    canonical_json,
    redact_text,
    redact_url,
    safe_filename,
    sha256_bytes,
    utcnow,
)

MAX_STRING = 16384
MAX_LIST = 200


def _sanitize(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return "<max-depth>"
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, item in value.items():
            lkey = str(key).lower()
            if lkey in ("authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"):
                out[str(key)] = "***redacted***"
            elif lkey in ("password", "passwd", "secret", "api_key", "token") and isinstance(item, str):
                out[str(key)] = "***redacted***"
            elif lkey == "url" and isinstance(item, str):
                out[str(key)] = redact_url(item)
            else:
                out[str(key)] = _sanitize(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        items = [_sanitize(item, depth + 1) for item in value[:MAX_LIST]]
        if len(value) > MAX_LIST:
            items.append(f"<truncated {len(value) - MAX_LIST} items>")
        return items
    if isinstance(value, str):
        return redact_text(value[:MAX_STRING])
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    return value


class RunStore:
    def __init__(
        self,
        root: str,
        run_id: str,
        target: str,
        mode: str,
        tool_version: str,
        create: bool = True,
    ):
        self.root = os.path.abspath(root)
        self.run_id = run_id
        self.target = target
        self.mode = mode
        self.tool_version = tool_version
        self.evidence_dir = self.root
        self.artifacts_dir = os.path.join(self.root, "artifacts")
        self.evidence_path = os.path.join(self.root, "evidence.jsonl")
        self.case_path = os.path.join(self.root, "case.json")
        self.findings_path = os.path.join(self.root, "findings.json")
        self.manifest_path = os.path.join(self.root, "manifest.json")
        self._evidence: List[Evidence] = []
        self._next = 1
        if not create:
            return
        os.makedirs(self.artifacts_dir, exist_ok=True)
        if not os.path.exists(self.evidence_path):
            with open(self.evidence_path, "w", encoding="utf-8") as handle:
                handle.write("")
        else:
            # Reusing a run directory must not restart ids at EV-0001 and append
            # duplicates.  Evidence is append-only across modes in that case.
            self._evidence = self.load_evidence()
            numeric = []
            for item in self._evidence:
                try:
                    numeric.append(int(item.id.split("-", 1)[1]))
                except (IndexError, ValueError):
                    continue
            self._next = (max(numeric) if numeric else len(self._evidence)) + 1
        self._write_manifest()

    @classmethod
    def open(cls, root: str) -> "RunStore":
        """Open an existing evidence directory without creating or rewriting it."""
        root = os.path.abspath(root)
        manifest_path = os.path.join(root, "manifest.json")
        payload: Dict[str, Any] = {}
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        store = cls(
            root=root,
            run_id=str(payload.get("run_id") or os.path.basename(root)),
            target=str(payload.get("target") or ""),
            mode=str(payload.get("mode") or "report"),
            tool_version=str(payload.get("tool_version") or ""),
            create=False,
        )
        if not os.path.exists(store.evidence_path):
            raise FileNotFoundError(f"missing evidence file: {store.evidence_path}")
        store._evidence = store.load_evidence()
        store._next = len(store._evidence) + 1
        return store

    # -- manifest ----------------------------------------------------------

    def _write_manifest(self) -> None:
        payload = {
            "tool": "php2shell-evidence-scanner",
            "tool_version": self.tool_version,
            "run_id": self.run_id,
            "target": redact_url(self.target),
            "mode": self.mode,
            "created_at": utcnow(),
            "format": "evidence-v1",
            "artifacts": "artifacts/<evidence-id>-<name>.json",
            "hash": "sha256(canonical-json(data))",
        }
        with open(self.manifest_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)

    # -- write -------------------------------------------------------------

    def add(
        self,
        source: str,
        data: Dict[str, Any],
        timestamp: Optional[str] = None,
        request_id: Optional[str] = None,
        worker_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        scenario_id: Optional[str] = None,
        trust: str = "medium",
        notes: str = "",
        synthetic: bool = False,
        truncated: bool = False,
    ) -> Evidence:
        evidence_id = f"EV-{self._next:04d}"
        self._next += 1
        clean = _sanitize(data)
        artifact = canonical_json(clean)
        digest = sha256_bytes(artifact)
        name = safe_filename(f"{evidence_id}-{scenario_id or source}.json")
        relative = os.path.join("artifacts", name)
        with open(os.path.join(self.root, relative), "wb") as handle:
            handle.write(artifact)
        evidence = Evidence(
            id=evidence_id,
            source=source,
            timestamp=timestamp or utcnow(),
            correlation_id=correlation_id or request_id,
            request_id=request_id,
            worker_id=worker_id,
            data=clean,
            sha256=digest,
            artifact_path=relative.replace(os.sep, "/"),
            scenario_id=scenario_id,
            trust=trust,
            redacted=True,
            truncated=truncated,
            notes=notes,
            synthetic=synthetic,
        )
        self._evidence.append(evidence)
        with open(self.evidence_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(evidence.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return evidence

    def add_http(self, exchange: Any, classification: Any, **kwargs: Any) -> Evidence:
        data = {
            "exchange": exchange.to_dict(),
            "classification": classification.to_dict(),
        }
        kwargs.setdefault("request_id", exchange.request_id)
        kwargs.setdefault("correlation_id", exchange.request_id)
        kwargs.setdefault("timestamp", exchange.received_at or exchange.sent_at)
        return self.add("http", data, **kwargs)

    def add_telemetry(self, event: Any, **kwargs: Any) -> Evidence:
        data = {"event": event.to_dict()}
        kwargs.setdefault("request_id", event.request_id)
        kwargs.setdefault("worker_id", event.worker_id)
        kwargs.setdefault("correlation_id", event.request_id)
        kwargs.setdefault("timestamp", event.timestamp)
        kwargs.setdefault("trust", "medium")
        return self.add(event.source, data, **kwargs)

    # -- read / verify -----------------------------------------------------

    def load_evidence(self) -> List[Evidence]:
        evidence: List[Evidence] = []
        with open(self.evidence_path, "r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                text = line.strip()
                if not text:
                    continue
                try:
                    evidence.append(Evidence.from_dict(json.loads(text)))
                except (json.JSONDecodeError, KeyError) as exc:
                    raise ValueError(f"{self.evidence_path}:{line_no}: {exc}") from exc
        return evidence

    def verify(self) -> List[str]:
        errors: List[str] = []
        loaded = self.load_evidence()
        for item in loaded:
            errors.extend(item.validate())
            # The inline data in evidence.jsonl must match the recorded hash even
            # when a separate artefact exists.  Checking only the artefact would
            # miss a tampered JSONL record whose artefact was left untouched.
            if item.recompute_sha256() != item.sha256:
                errors.append(f"{item.id}: inline data hash mismatch")
            if item.artifact_path:
                path = os.path.join(self.root, item.artifact_path.replace("/", os.sep))
                if not os.path.exists(path):
                    errors.append(f"{item.id}: artifact missing: {item.artifact_path}")
                    continue
                with open(path, "rb") as handle:
                    digest = sha256_bytes(handle.read())
                if digest != item.sha256:
                    errors.append(f"{item.id}: artifact hash mismatch")
        return errors

    # -- case / findings ---------------------------------------------------

    def write_case(self, case: CaseFile) -> None:
        payload = {
            "run_id": case.run_id,
            "tool_version": case.tool_version,
            "mode": case.mode,
            "started_at": case.started_at,
            "finished_at": case.finished_at or utcnow(),
            "profile": case.profile.to_dict(),
            "scenario_runs": [run.to_dict() for run in case.scenario_runs],
            "environment": case.environment,
            "notes": case.notes,
        }
        with open(self.case_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=True)

    def read_case(self) -> CaseFile:
        with open(self.case_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return CaseFile(
            profile=TargetProfile.from_dict(payload["profile"]),
            evidence=self.load_evidence(),
            scenario_runs=[ScenarioRun.from_dict(item) for item in payload.get("scenario_runs", [])],
            run_id=payload.get("run_id", self.run_id),
            tool_version=payload.get("tool_version", self.tool_version),
            mode=payload.get("mode", self.mode),
            started_at=payload.get("started_at", ""),
            finished_at=payload.get("finished_at", ""),
            environment=dict(payload.get("environment") or {}),
            notes=list(payload.get("notes") or []),
        )

    def write_findings(self, findings: Iterable[Finding]) -> None:
        payload = {"run_id": self.run_id, "target": redact_url(self.target), "findings": [f.to_dict() for f in findings]}
        with open(self.findings_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False, sort_keys=True)

    def read_findings(self) -> Dict[str, Any]:
        with open(self.findings_path, "r", encoding="utf-8") as handle:
            return json.load(handle)
