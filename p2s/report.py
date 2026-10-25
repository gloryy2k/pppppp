"""Report rendering: JSON, JSONL, Markdown and a dependency-free HTML view.

The report never merges the two CVEs into a single verdict.  Every status is
printed with its reason, evidence references, limitations and missing evidence.
"""

from __future__ import annotations

import html
import json
import os
from typing import Any, Dict, Iterable, List, Optional

from .assess import assess_exploit
from .models import CaseFile, Evidence, Finding
from .util import dedupe, human_bytes, utcnow

SCHEMA_VERSION = "php2shell-report/1"


def _evidence_summary(item: Evidence) -> Dict[str, Any]:
    data = item.data or {}
    summary = ""
    phase = "other"
    if item.source == "http":
        exchange = data.get("exchange") or {}
        classification = data.get("classification") or {}
        summary = (
            f"{exchange.get('method', '?')} {exchange.get('url', '?')} -> "
            f"{exchange.get('status', 'ERR')} ({classification.get('kind', 'unknown')})"
        )
        phase = "http"
    elif item.source in ("php_log", "web_server_log", "worker_telemetry", "lab_trace"):
        event = data.get("event") or {}
        summary = f"{event.get('event_type', 'log')}: {str(event.get('message', ''))[:300]}"
        phase = "telemetry"
    elif item.source == "canary":
        assessment = data.get("assessment") or {}
        summary = f"canary verified={assessment.get('verified')} nonce={assessment.get('nonce')}"
        phase = "canary"
    elif item.source == "host_inventory":
        inventory = data.get("inventory") or {}
        probe = data.get("php_probe") or {}
        summary = (
            f"inventory: version={inventory.get('php_version') or probe.get('version')} "
            f"sapi={inventory.get('sapi') or probe.get('sapi')}"
        )
        phase = "inventory"
    elif item.source == "operator":
        summary = f"operator note: {data.get('parse_error', '')[:300]}"
        phase = "operator"
    return {
        "id": item.id,
        "timestamp": item.timestamp,
        "phase": phase,
        "source": item.source,
        "scenario_id": item.scenario_id,
        "request_id": item.request_id,
        "worker_id": item.worker_id,
        "correlation_id": item.correlation_id,
        "summary": summary,
        "sha256": item.sha256,
        "artifact_path": item.artifact_path,
        "trust": item.trust,
        "synthetic": item.synthetic,
    }


def build_document(
    case: CaseFile,
    findings: List[Finding],
    verification_errors: Optional[List[str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    profile = case.profile
    evidence_index = [_evidence_summary(item) for item in case.evidence]
    evidence_index.sort(key=lambda row: (row["timestamp"], row["id"]))
    timeline = list(evidence_index)

    verdicts = {
        finding.cve: {
            "status": finding.status,
            "reason": finding.status_reason,
            "scenario_id": finding.scenario_id,
            "evidence_refs": finding.evidence_refs,
            "missing_evidence": finding.missing_evidence,
        }
        for finding in findings
    }
    exploit = assess_exploit(case)

    oom_phase = None
    oom_worker = None
    oom_refs: List[str] = []
    for finding in findings:
        context = finding.reproduction_context or {}
        if context.get("oom_phase"):
            oom_phase = context["oom_phase"]
            oom_worker = context.get("oom_worker")
            oom_refs.extend(finding.evidence_refs)
            break

    patched_baseline_observed = False
    evidence_index_by_id = {item.id: item for item in case.evidence}
    for run in case.scenario_runs:
        if "patched_baseline" in (run.correlation or {}):
            patched_baseline_observed = True
        if "patched_baseline" in " ".join(run.notes):
            patched_baseline_observed = True
        for ref in run.trace_refs:
            item = evidence_index_by_id.get(ref)
            event = ((item.data or {}).get("event") if item is not None else {}) or {}
            if event.get("event_type") == "patched_baseline":
                patched_baseline_observed = True

    answers = {
        "did_test_request_reach_php": {
            "answer": profile.reach.state,
            "basis": profile.reach.basis,
            "limitations": profile.reach.limitations,
        },
        "did_oom_occur_in_php": {
            "answer": "YES" if oom_phase else "NO/NOT PROVEN",
            "phase": oom_phase or "n/a",
            "evidence_refs": dedupe(oom_refs) if oom_phase else [],
            "note": "An OOM observation is not proof of either CVE.",
        },
        "oom_stage": oom_phase or "n/a",
        "which_worker": {
            "worker_ids": dedupe(
                [run.producer_worker_id for run in case.scenario_runs if run.producer_worker_id]
                + [run.consumer_worker_id for run in case.scenario_runs if run.consumer_worker_id]
            ),
            "note": "Worker identity comes from telemetry, not HTTP keep-alive.",
        },
        "what_links_observation_to_cve": {
            finding.cve: finding.proof_method for finding in findings
        },
        "code_execution_observed": {
            "confirmed": exploit["confirmed"],
            "attribution": exploit["attribution"],
            "chains": [entry["chain"] for entry in exploit["chains"]],
            "evidence_refs": exploit["evidence_refs"],
            "note": (
                "Out-of-band exploit callback. It proves payload execution, not "
                "which CVE path delivered it; the CVE verdicts above are "
                "independent."
            ),
        },
        "patched_vs_unpatched_control": {
            "patch_state": profile.patch.state,
            "patch_trust": profile.patch.trust,
            "patched_baseline_observed": patched_baseline_observed,
            "note": "A 502-vs-200 difference alone is not a root-cause proof.",
        },
        "highest_conclusion_supported": verdicts,
    }

    doc: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utcnow(),
        "tool_version": case.tool_version,
        "run_id": case.run_id,
        "mode": case.mode,
        "target": profile.target,
        "environment": {
            "kind": case.environment.get("kind", profile.environment_kind),
            "synthetic": bool(case.environment.get("synthetic")),
            "php_version": profile.php_version,
            "version_source": profile.version_source,
            "version_trust": profile.version_trust,
            "sapi": profile.sapi,
            "sapi_source": profile.sapi_source,
            "sapi_verified": profile.sapi_verified,
            "packaging": profile.packaging,
            "patch": profile.patch.to_dict(),
            "reach": profile.reach.to_dict(),
            "config": profile.config,
            "build_metadata": profile.build_metadata,
            "frontend": profile.frontend,
            "notes": profile.notes,
            "collected_at": profile.collected_at,
            "telemetry_files": case.environment.get("telemetry_files", []),
            "limits": case.environment.get("limits", {}),
        },
        "executive_summary": {
            "verdicts": verdicts,
            "note": (
                "The two CVE verdicts are independent. No combined confidence is "
                "computed and PATCH_CONFIRMED comes only from build/package evidence."
            ),
        },
        "findings": [finding.to_dict() for finding in findings],
        "scenarios": [run.to_dict() for run in case.scenario_runs],
        "exploit": exploit,
        "timeline": timeline,
        "evidence_index": evidence_index,
        "proof": {
            "canaries": [
                run.canary for run in case.scenario_runs if run.canary
            ],
            "controls": [
                {
                    "scenario_id": run.scenario_id,
                    "refs": run.control_refs,
                }
                for run in case.scenario_runs
                if run.control_refs
            ],
            "artifacts": [
                {
                    "id": item["id"],
                    "source": item["source"],
                    "scenario_id": item.get("scenario_id"),
                    "sha256": item["sha256"],
                    "artifact_path": item["artifact_path"],
                    "synthetic": item["synthetic"],
                }
                for item in evidence_index
            ],
        },
        "answers": answers,
        "limitations": _global_limitations(case, findings),
        "remediation": {
            finding.cve: finding.remediation for finding in findings
        },
        "integrity": {
            "evidence_count": len(case.evidence),
            "verified": not verification_errors,
            "errors": verification_errors or [],
            "hash_algorithm": "sha256",
            "hash_covers": "canonical JSON of the bounded, redacted evidence data",
        },
    }
    if extra:
        doc.update(extra)
    return doc


def _global_limitations(case: CaseFile, findings: List[Finding]) -> List[str]:
    items = [
        "Remote black-box HTTP cannot observe PHP request memory, shutdown ordering "
        "or worker-internal state.",
        "A negative result does not prove absence of either vulnerability.",
        "HTTP status codes (500/502/503/504), timeouts, empty bodies and connection "
        "resets are not crash or CVE evidence.",
        "X-Powered-By is low trust and is never used for PATCH_CONFIRMED.",
        "OOM proves an allocation failure, not the CVE-2026-109618 invalid-state path.",
        "A worker crash is a worker failure, not automatically either CVE.",
        "HTTP keep-alive is not evidence that two requests used the same PHP worker.",
        "Evidence hashes cover the stored, bounded/redacted artefact, not the full "
        "unbounded wire body.",
        "Timing correlation alone cannot establish same-worker identity.",
    ]
    if case.environment.get("synthetic") or case.environment.get("kind") == "fixture":
        items.insert(
            0,
            "THIS IS A FIXTURE/SYNTHETIC REPORT. It exercises the evidence and report "
            "pipeline; it is not proof about a real deployment.",
        )
    for finding in findings:
        for limitation in finding.proof_limitations:
            items.append(f"{finding.cve}: {limitation}")
    return dedupe(items)


def render_markdown(doc: Dict[str, Any]) -> str:
    lines: List[str] = []
    add = lines.append
    env = doc["environment"]
    add(f"# php2shell exposure and proof report — {doc['target']}")
    add("")
    add(f"- Run: `{doc['run_id']}`")
    add(f"- Tool: `php2shell-evidence-scanner {doc['tool_version']}`")
    add(f"- Mode: `{doc['mode']}`")
    add(f"- Generated: `{doc['generated_at']}`")
    add(f"- Environment: `{env['kind']}`" + (" **(SYNTHETIC/FIXTURE)**" if env.get("synthetic") else ""))
    add("")

    add("## 1. Executive summary")
    add("")
    add("| CVE | Status | Why | Scenario |")
    add("|---|---|---|---|")
    for cve, verdict in doc["executive_summary"]["verdicts"].items():
        add(f"| {cve} | **{verdict['status']}** | {_md(verdict['reason'])} | `{verdict['scenario_id']}` |")
    add("")
    add(doc["executive_summary"]["note"])
    add("")
    if env.get("synthetic"):
        add("> **Warning:** this report was built from fixture/synthetic evidence. "
            "It demonstrates the reporting pipeline and must not be used as proof "
            "that a real target is vulnerable or patched.")
        add("")

    add("## 2. Environment")
    add("")
    add(f"- Target: `{doc['target']}`")
    add(f"- PHP build: `{env.get('php_version') or 'UNKNOWN'}` "
        f"(source: {env.get('version_source')}, trust: {env.get('version_trust')})")
    add(f"- SAPI: `{env.get('sapi')}` (source: {env.get('sapi_source')}, "
        f"verified: {env.get('sapi_verified')})")
    patch = env.get("patch") or {}
    add(f"- Patch: `{patch.get('state')}` (trust: {patch.get('trust')}); {patch.get('details', '')}")
    if patch.get("backports"):
        add(f"- Backport evidence: `{json.dumps(patch['backports'], ensure_ascii=False)}`")
    add(f"- Reachability: `{(env.get('reach') or {}).get('state')}`")
    for basis in (env.get("reach") or {}).get("basis") or []:
        add(f"  - {basis}")
    if env.get("config"):
        add(f"- Relevant configuration: `{json.dumps(env['config'], ensure_ascii=False)}`")
    add(f"- Frontend hints: `{json.dumps(env.get('frontend') or {}, ensure_ascii=False)}`")
    add(f"- Telemetry imported: {', '.join(env.get('telemetry_files') or []) or 'none'}")
    add("")

    add("## 3. Scenarios run / not run")
    add("")
    add("| Scenario | CVE | Executed | Producer | Consumer | Reason / conclusion |")
    add("|---|---|---|---|---|---|")
    for run in doc.get("scenarios") or []:
        reason = run.get("skipped_reason") or "; ".join(run.get("notes") or [])[:500]
        add(
            f"| `{run.get('scenario_id')}` | {run.get('cve')} | "
            f"{'yes' if run.get('executed') else 'no'} | "
            f"`{run.get('producer_request_id') or '-'}` | "
            f"`{run.get('consumer_request_id') or '-'}` | {_md(reason)} |"
        )
    add("")

    add("## 4. Timeline: request → PHP → worker → log/trace → conclusion")
    add("")
    add("| Time (UTC) | Phase | Source | Scenario | Request | Worker | Observation | Evidence |")
    add("|---|---|---|---|---|---|---|---|")
    for row in doc.get("timeline") or []:
        add(
            f"| {row['timestamp']} | {row['phase']} | {row['source']} | "
            f"`{row.get('scenario_id') or '-'}` | `{row.get('request_id') or '-'}` | "
            f"`{row.get('worker_id') or '-'}` | {_md(row['summary'])} | `{row['id']}` |"
        )
    add("")

    add("## 5. Proof, controls and false-positive exclusion")
    add("")
    add("### Evidence artefacts")
    add("")
    add("| ID | Source | Scenario | SHA-256 | Synthetic |")
    add("|---|---|---|---|---|")
    for row in doc["proof"]["artifacts"]:
        add(
            f"| `{row['id']}` | {row['source']} | `{row.get('scenario_id') or '-'}` | "
            f"`{row['sha256'][:16]}…` | {row['synthetic']} |"
        )
    add("")
    canaries = doc["proof"].get("canaries") or []
    if canaries:
        add("### Canary")
        add("")
        for canary in canaries:
            add(f"- nonce `{canary.get('nonce')}`: verified={canary.get('verified')}; "
                f"before={canary.get('before_present')}, after={canary.get('after_present')}, "
                f"reflected={canary.get('reflected_in_test_responses')}, "
                f"telemetry_write={canary.get('telemetry_write')}, "
                f"worker_match={canary.get('telemetry_worker_match')}")
            for reason in canary.get("reasons") or []:
                add(f"  - {reason}")
            for missing in canary.get("missing") or []:
                add(f"  - missing: {missing}")
    else:
        add("### Canary")
        add("")
        add("No canary was configured/verified. `CODE_EXECUTION_CONFIRMED` was therefore not claimed.")
    add("")
    add("### Controls")
    add("")
    controls = doc["proof"].get("controls") or []
    if not controls:
        add("No control request was recorded for this run.")
    for control in controls:
        add(f"- `{control['scenario_id']}`: {', '.join(f'`{ref}`' for ref in control['refs'])}")
    add("")
    add("A control request must reach PHP and be stable before a test result can be "
        "compared. A 502-vs-200 difference alone is not a root-cause proof.")
    add("")

    exploit = doc.get("exploit") or {}
    add("### Exploit callback (out-of-band)")
    add("")
    if exploit.get("confirmed"):
        add(f"**RCE observed:** yes (`{len(exploit.get('chains') or [])}` accepted "
            "out-of-band callback(s)).")
        add("")
        for entry in exploit.get("chains") or []:
            add(f"- chain `{entry.get('chain')}` via `{entry.get('scenario_id')}`: "
                f"callback from `{entry.get('remote_addr')}`, evidence "
                f"`{entry.get('evidence_ref')}`"
                + (f", output `{_md(entry.get('command_output'))[:200]}`"
                   if entry.get("command_output") else ""))
        add("")
        add(f"- CVE attribution: `{exploit.get('attribution')}` — a callback proves "
            "the payload executed; it does not prove which advisory path delivered it.")
    else:
        add("No accepted out-of-band exploit callback is stored in this evidence set. "
            "Response markers and deserialization diagnostics are not proof of code "
            "execution.")
        for reason in exploit.get("reasons") or []:
            add(f"- {reason}")
    add("")

    add("## 6. Limits: what is not proven")
    add("")
    for item in doc.get("limitations") or []:
        add(f"- {item}")
    add("")

    add("## 7. Recommendations")
    add("")
    for cve, items in doc.get("remediation", {}).items():
        add(f"### {cve}")
        add("")
        for item in items:
            add(f"- {item}")
        add("")

    add("## Questions the report answers")
    add("")
    answers = doc["answers"]
    add(f"- **Did the test request reach PHP?** `{answers['did_test_request_reach_php']['answer']}` — "
        + "; ".join(answers["did_test_request_reach_php"].get("basis") or []))
    add(f"- **Did OOM actually occur in PHP?** `{answers['did_oom_occur_in_php']['answer']}`")
    add(f"- **At what stage?** `{answers['oom_stage']}`")
    add(f"- **Which worker?** `{', '.join(answers['which_worker']['worker_ids']) or 'UNKNOWN'}`")
    add("- **What links the observation to the CVE?** "
        + "; ".join(f"{cve}: {method}" for cve, method in answers["what_links_observation_to_cve"].items()))
    add(f"- **Is there a patched/unpatched control?** patch=`{answers['patched_vs_unpatched_control']['patch_state']}`; "
        f"baseline observed={answers['patched_vs_unpatched_control']['patched_baseline_observed']}")
    executed = answers.get("code_execution_observed") or {}
    add(f"- **Was code execution observed?** `{'YES' if executed.get('confirmed') else 'NO/NOT PROVEN'}`; "
        f"attribution=`{executed.get('attribution', 'not_established')}`")
    add("- **Highest conclusion actually supported?** "
        + "; ".join(f"{cve}: {v['status']}" for cve, v in answers["highest_conclusion_supported"].items()))
    add("")

    add("## Integrity and reproduction")
    add("")
    add(f"- Evidence items: {doc['integrity']['evidence_count']}")
    add(f"- Hash verification: {'PASS' if doc['integrity']['verified'] else 'FAIL'}")
    if doc["integrity"].get("errors"):
        for error in doc["integrity"]["errors"]:
            add(f"  - {error}")
    add(f"- Hash covers: {doc['integrity']['hash_covers']}")
    add("")
    add("Re-run the report without sending requests:")
    add("")
    add("```\npython php2shell_scanner_v4.py report <evidence-dir> --out <report-dir>\n```")
    add("")
    add(
        f"`<evidence-dir>` is the directory containing this run's `evidence.jsonl` "
        f"and `case.json` (run id `{doc['run_id']}`)."
    )
    add("")
    add("Verify the stored artefact hashes without network access:")
    add("")
    add("```\npython php2shell_scanner_v4.py verify <evidence-dir>\n```")
    add("")
    return "\n".join(lines) + "\n"


def _md(value: Any) -> str:
    text = str(value or "")
    return text.replace("|", "\\|").replace("\n", " ")


def render_html(doc: Dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""))

    parts: List[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<title>php2shell report</title>")
    parts.append(
        "<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:1200px;"
        "margin:2rem auto;padding:0 1rem;line-height:1.45;color:#1b1f24}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.9rem}"
        "th,td{border:1px solid #d0d7de;padding:.4rem;text-align:left;vertical-align:top}"
        "th{background:#f6f8fa}code{background:#f6f8fa;padding:.1rem .25rem;border-radius:4px}"
        ".warn{background:#fff4e5;border-left:4px solid #d97706;padding:.75rem}"
        ".status{font-weight:700}</style></head><body>"
    )
    parts.append(f"<h1>php2shell exposure and proof report</h1><p><code>{esc(doc['target'])}</code></p>")
    if doc["environment"].get("synthetic"):
        parts.append("<div class='warn'><strong>Fixture/synthetic report.</strong> "
                     "It exercises the pipeline and is not proof about a real deployment.</div>")
    parts.append("<h2>1. Executive summary</h2><table><tr><th>CVE</th><th>Status</th><th>Why</th></tr>")
    for cve, verdict in doc["executive_summary"]["verdicts"].items():
        parts.append(
            f"<tr><td>{esc(cve)}</td><td class='status'>{esc(verdict['status'])}</td>"
            f"<td>{esc(verdict['reason'])}</td></tr>"
        )
    parts.append("</table>")

    env = doc["environment"]
    parts.append("<h2>2. Environment</h2><ul>")
    for label, value in (
        ("PHP build", env.get("php_version") or "UNKNOWN"),
        ("Build source/trust", f"{env.get('version_source')} / {env.get('version_trust')}"),
        ("SAPI", f"{env.get('sapi')} ({env.get('sapi_source')}, verified={env.get('sapi_verified')})"),
        ("Patch", f"{(env.get('patch') or {}).get('state')} / {(env.get('patch') or {}).get('trust')}"),
        ("Reachability", (env.get("reach") or {}).get("state")),
    ):
        parts.append(f"<li><strong>{esc(label)}:</strong> {esc(value)}</li>")
    parts.append("</ul>")

    parts.append("<h2>3. Scenarios</h2><table><tr><th>Scenario</th><th>CVE</th><th>Executed</th>"
                 "<th>Producer</th><th>Consumer</th><th>Reason</th></tr>")
    for run in doc.get("scenarios") or []:
        reason = run.get("skipped_reason") or "; ".join(run.get("notes") or [])[:400]
        parts.append(
            f"<tr><td>{esc(run.get('scenario_id'))}</td><td>{esc(run.get('cve'))}</td>"
            f"<td>{'yes' if run.get('executed') else 'no'}</td>"
            f"<td>{esc(run.get('producer_request_id') or '-')}</td>"
            f"<td>{esc(run.get('consumer_request_id') or '-')}</td><td>{esc(reason)}</td></tr>"
        )
    parts.append("</table>")

    parts.append("<h2>4. Timeline</h2><table><tr><th>Time</th><th>Source</th><th>Request</th>"
                 "<th>Worker</th><th>Observation</th><th>Evidence</th></tr>")
    for row in doc.get("timeline") or []:
        parts.append(
            f"<tr><td>{esc(row['timestamp'])}</td><td>{esc(row['source'])}</td>"
            f"<td>{esc(row.get('request_id') or '-')}</td><td>{esc(row.get('worker_id') or '-')}</td>"
            f"<td>{esc(row['summary'])}</td><td>{esc(row['id'])}</td></tr>"
        )
    parts.append("</table>")

    parts.append("<h2>5. Proof and integrity</h2><table><tr><th>ID</th><th>Source</th>"
                 "<th>SHA-256</th><th>Synthetic</th></tr>")
    for row in doc["proof"]["artifacts"]:
        parts.append(
            f"<tr><td>{esc(row['id'])}</td><td>{esc(row['source'])}</td>"
            f"<td><code>{esc(row['sha256'])}</code></td><td>{esc(row['synthetic'])}</td></tr>"
        )
    parts.append("</table>")
    for canary in doc["proof"].get("canaries") or []:
        parts.append(f"<p><strong>Canary</strong> <code>{esc(canary.get('nonce'))}</code>: "
                     f"verified={esc(canary.get('verified'))}, reflected={esc(canary.get('reflected_in_test_responses'))}, "
                     f"worker_match={esc(canary.get('telemetry_worker_match'))}</p>")

    exploit = doc.get("exploit") or {}
    parts.append("<h2>Exploit callback (out-of-band)</h2>")
    if exploit.get("confirmed"):
        parts.append(
            "<p><strong>RCE observed:</strong> yes. Attribution: "
            f"<code>{esc(exploit.get('attribution'))}</code> (a callback proves the "
            "payload executed, not which CVE path delivered it).</p><ul>"
        )
        for entry in exploit.get("chains") or []:
            parts.append(
                f"<li>chain <code>{esc(entry.get('chain'))}</code> via "
                f"<code>{esc(entry.get('scenario_id'))}</code>; callback from "
                f"<code>{esc(entry.get('remote_addr'))}</code>; evidence "
                f"<code>{esc(entry.get('evidence_ref'))}</code></li>"
            )
        parts.append("</ul>")
    else:
        parts.append(
            "<p>No accepted out-of-band exploit callback is stored. Response "
            "markers and deserialization diagnostics are not proof of code "
            "execution.</p>"
        )

    parts.append("<h2>6. Limits</h2><ul>")
    for item in doc.get("limitations") or []:
        parts.append(f"<li>{esc(item)}</li>")
    parts.append("</ul>")

    parts.append("<h2>7. Recommendations</h2>")
    for cve, items in doc.get("remediation", {}).items():
        parts.append(f"<h3>{esc(cve)}</h3><ul>")
        for item in items:
            parts.append(f"<li>{esc(item)}</li>")
        parts.append("</ul>")

    parts.append("<h2>Questions the report answers</h2><ul>")
    answers = doc["answers"]
    parts.append(f"<li>Reached PHP: <code>{esc(answers['did_test_request_reach_php']['answer'])}</code></li>")
    parts.append(f"<li>OOM in PHP: <code>{esc(answers['did_oom_occur_in_php']['answer'])}</code> "
                 f"(stage: <code>{esc(answers['oom_stage'])}</code>)</li>")
    parts.append(f"<li>Workers: <code>{esc(', '.join(answers['which_worker']['worker_ids']) or 'UNKNOWN')}</code></li>")
    parts.append(f"<li>Integrity: {'PASS' if doc['integrity']['verified'] else 'FAIL'} "
                 f"({esc(doc['integrity']['evidence_count'])} items)</li>")
    parts.append("</ul>")
    parts.append("</body></html>")
    return "".join(parts)


def write_reports(outdir: str, doc: Dict[str, Any], findings: List[Finding]) -> Dict[str, str]:
    os.makedirs(outdir, exist_ok=True)
    paths = {
        "json": os.path.join(outdir, "report.json"),
        "jsonl": os.path.join(outdir, "findings.jsonl"),
        "markdown": os.path.join(outdir, "report.md"),
        "html": os.path.join(outdir, "report.html"),
    }
    with open(paths["json"], "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2, ensure_ascii=False, sort_keys=True)
    with open(paths["jsonl"], "w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(finding.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
    with open(paths["markdown"], "w", encoding="utf-8") as handle:
        handle.write(render_markdown(doc))
    with open(paths["html"], "w", encoding="utf-8") as handle:
        handle.write(render_html(doc))
    return paths
