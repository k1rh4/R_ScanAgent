from __future__ import annotations

import os
import subprocess
import sys
import uuid
from collections import defaultdict
from typing import Any, Dict, List

from .candidates import Candidate, discover_candidates_prioritized
from .config import load_env
from .http_parser import parse_burp_json
from .llm import LLMClient
from .llm_flow import LLMJudge, LLMPlanner
from .policies import Policy
from .probing import (
    build_unauth_exploit,
    build_python_exploit,
    default_payloads,
    probe_candidate,
    shell_join,
    sqlmap_command,
    write_raw_request,
)
from .scan_logger import ScanLogger
from .tool_validators import run_commix, run_ffuf


class RedScanAgent:
    def __init__(self, policy_path: str = "custom_policy.txt", scan_logger: ScanLogger | None = None):
        load_env()
        self.policy = Policy.load(policy_path)
        self.llm = LLMClient()
        self.planner = LLMPlanner(self.llm)
        self.judge = LLMJudge(self.llm)
        self.scan_logger = scan_logger

        self.enable_commix = self._env_bool("REDSCAN_ENABLE_COMMIX", "1")
        self.enable_ffuf = self._env_bool("REDSCAN_ENABLE_FFUF", "1")
        self.tool_timeout = int(os.getenv("REDSCAN_TOOL_TIMEOUT", "45"))
        self.max_candidates = max(1, min(int(os.getenv("REDSCAN_MAX_LLM_CANDIDATES", "9")), 9))
        self.max_probe_rounds = max(1, min(int(os.getenv("REDSCAN_MAX_PROBE_ROUNDS", "10")), 20))
        self.max_payloads_per_round = max(1, min(int(os.getenv("REDSCAN_MAX_PAYLOADS_PER_ROUND", "2")), 5))

    def _env_bool(self, key: str, default: str = "0") -> bool:
        value = os.getenv(key, default)
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _system_message(self) -> str:
        base = (
            "You are an autonomous red-team agent. Focus only on critical vulnerabilities: "
            "SQL Injection, Command Injection, Path Traversal, Unrestricted File Upload/Download, IDOR, Unauthenticated API Access."
        )
        if self.policy.text:
            return base + "\nCustom policy:\n" + self.policy.text
        return base

    def _finding_key(self, finding: Dict[str, Any]) -> tuple[str, str]:
        return str(finding.get("type", "")), str(finding.get("vector", ""))

    def _request_context(self, req) -> Dict[str, Any]:
        auth_headers = {"authorization", "proxy-authorization", "x-api-key", "x-auth-token"}
        header_names = [k.lower() for k in req.headers.keys()]
        has_auth_header = any(h in header_names for h in auth_headers)
        has_cookie = bool(req.headers.get("Cookie"))
        return {
            "method": req.method,
            "url": req.url,
            "path": req.url.split("?", 1)[0],
            "query_keys": sorted(list(req.query.keys())),
            "header_names": sorted(header_names),
            "has_cookie": has_cookie,
            "has_auth_header": has_auth_header,
        }

    def triage(self, data: dict, path: str | None = None) -> Dict[str, Any]:
        req, res = parse_burp_json(data)
        scan_path = path or req.url.split("?", 1)[0]
        candidates = discover_candidates_prioritized(req, self.llm, max_candidates=self.max_candidates, res=res)
        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="triage",
                event="phase_start",
                message=f"candidate discovery started (count={len(candidates)})",
            )

        findings = []
        for c in candidates:
            findings.append(
                {
                    "id": str(uuid.uuid4()),
                    "type": c.vuln_type,
                    "vector": f"{c.param}/{c.location}",
                    "reasoning": c.reason,
                    "action": {"tool": "pending", "payload": ""},
                    "verification_evidence": "",
                }
            )
            if self.scan_logger:
                self.scan_logger.log(
                    path=scan_path,
                    phase="triage",
                    event="candidate_selected",
                    vuln_type=c.vuln_type,
                    vector=f"{c.param}/{c.location}",
                    reason=c.reason,
                    message="candidate selected for probing",
                )

        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="triage",
                event="phase_end",
                message=f"candidate discovery finished (count={len(candidates)})",
            )
        return {"analysis_status": "PROBING", "findings": findings}

    def probe(self, data: dict, active: bool = False, path: str | None = None) -> Dict[str, Any]:
        req, res = parse_burp_json(data)
        scan_path = path or req.url.split("?", 1)[0]
        candidates = discover_candidates_prioritized(req, self.llm, max_candidates=self.max_candidates, res=res)
        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="probe",
                event="phase_start",
                message=f"probing started (active={active}, candidates={len(candidates)})",
            )

        findings: List[Dict[str, Any]] = []
        req_context = self._request_context(req)

        for c in candidates:
            history: List[str] = []
            attempted_payloads: set[str] = set()
            round_results = []
            rounds = 1 if not active else self.max_probe_rounds

            for _ in range(rounds):
                fallback = [p for p in default_payloads(c.vuln_type, self.policy, max_payloads=6) if p not in attempted_payloads]
                if not fallback and active:
                    break

                finding_for_plan = {
                    "type": c.vuln_type,
                    "vector": f"{c.param}/{c.location}",
                    "reasoning": c.reason,
                }
                plan = self.planner.propose_payloads(
                    finding=finding_for_plan,
                    evidence_history=history,
                    fallback_payloads=fallback,
                    max_payloads=self.max_payloads_per_round,
                )

                payloads = [p for p in plan.payloads if p and p not in attempted_payloads]
                if plan.stop and not payloads:
                    break
                if not payloads:
                    payloads = fallback[: self.max_payloads_per_round]
                if not payloads:
                    break

                for p in payloads:
                    attempted_payloads.add(p)

                chunk = probe_candidate(req, c, self.policy, active=active, payloads=payloads)
                round_results.extend(chunk)
                for r in chunk:
                    if r.evidence:
                        history.append(r.evidence)

                # Early break when LLM judge sees enough evidence.
                if finding_for_plan.get("type") == "Unauthenticated API Access":
                    verdict = self.judge.judge(
                        finding=finding_for_plan,
                        evidence_history=history,
                        request_context=req_context,
                    )
                else:
                    verdict = self.judge.judge(finding=finding_for_plan, evidence_history=history)
                if verdict.status in {"VERIFIED", "DISCARDED"} and verdict.next_action == "STOP":
                    break

            # Fallback for empty result edge case.
            if not round_results:
                chunk = probe_candidate(req, c, self.policy, active=active)
                round_results.extend(chunk)

            for r in round_results:
                finding = {
                    "id": r.id,
                    "type": r.vuln_type,
                    "vector": r.vector,
                    "reasoning": r.reasoning,
                    "action": {"tool": r.tool, "payload": r.payload},
                    "verification_evidence": r.evidence,
                }
                findings.append(finding)
                if self.scan_logger:
                    self.scan_logger.log(
                        path=scan_path,
                        phase="probe",
                        event="candidate_probed",
                        vuln_type=r.vuln_type,
                        vector=r.vector,
                        reason=r.reasoning,
                        evidence=r.evidence,
                        message=f"probe executed with tool={r.tool}",
                    )

        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="probe",
                event="phase_end",
                message=f"probing finished (results={len(findings)})",
            )
        return {"analysis_status": "PROBING", "findings": findings}

    def _tool_eligible_by_llm(self, finding: Dict[str, Any], evidence: str) -> bool:
        if not self.llm.available():
            return True
        system = "You decide if expensive external verification tool should run. Return only HIGH or LOW."
        user = (
            f"type={finding.get('type')}\n"
            f"vector={finding.get('vector')}\n"
            f"reasoning={finding.get('reasoning')}\n"
            f"evidence={evidence}\n"
        )
        try:
            out = self.llm.chat(system, user).strip().upper()
            return "HIGH" in out
        except Exception:
            return True

    def _preverify_with_tool(self, req, finding: Dict[str, Any], evidence: str) -> tuple[str, str, str, str]:
        vtype = finding.get("type", "")
        vector = finding.get("vector", "")
        if not vector or "/" not in vector:
            return "SKIPPED", "", "", ""
        if vtype not in {"Command Injection", "Path Traversal", "Unrestricted File Download"}:
            return "SKIPPED", "", "", ""
        if not self._tool_eligible_by_llm(finding, evidence):
            return "SKIPPED", "tool_gate=low", "", ""

        if vtype == "Command Injection" and self.enable_commix:
            result = run_commix(req, vector, timeout_sec=self.tool_timeout)
            status = "VERIFIED" if result.confirmed else "PROBING"
            return status, result.evidence, result.tool, result.command

        if vtype in {"Path Traversal", "Unrestricted File Download"} and self.enable_ffuf:
            result = run_ffuf(req, vector, timeout_sec=self.tool_timeout)
            status = "VERIFIED" if result.confirmed else "PROBING"
            return status, result.evidence, result.tool, result.command

        return "SKIPPED", "tool_disabled", "", ""

    def deep_analysis(
        self,
        data: dict,
        probe_results: Dict[str, Any],
        path: str | None = None,
        active: bool = False,
    ) -> Dict[str, Any]:
        req, _ = parse_burp_json(data)
        scan_path = path or req.url.split("?", 1)[0]

        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="deep",
                event="phase_start",
                message=f"deep analysis started (findings={len(probe_results.get('findings', []))})",
            )

        grouped: dict[tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        for f in probe_results.get("findings", []):
            grouped[self._finding_key(f)].append(f)

        findings: List[Dict[str, Any]] = []
        req_context = self._request_context(req)
        for _, group in grouped.items():
            base = group[-1]
            evidence_history = [str(g.get("verification_evidence", "")).strip() for g in group if g.get("verification_evidence")]
            if base.get("type") == "Unauthenticated API Access":
                verdict = self.judge.judge(
                    finding=base,
                    evidence_history=evidence_history,
                    request_context=req_context,
                )
            else:
                verdict = self.judge.judge(finding=base, evidence_history=evidence_history)
            status = verdict.status

            merged_evidence = " || ".join(evidence_history[-5:]).strip()
            if verdict.reason:
                merged_evidence = (merged_evidence + f" judge_reason={verdict.reason} conf={verdict.confidence:.2f}").strip()

            if active and status != "VERIFIED":
                tool_status, tool_evidence, tool_name, tool_cmd = self._preverify_with_tool(req, base, merged_evidence)
                if tool_evidence:
                    merged_evidence = (merged_evidence + " " + tool_evidence).strip()
                if tool_status == "VERIFIED":
                    status = "VERIFIED"
                if self.scan_logger and tool_name:
                    self.scan_logger.log(
                        path=scan_path,
                        phase="deep",
                        event="tool_preverify",
                        vuln_type=base.get("type"),
                        vector=base.get("vector"),
                        reason=base.get("reasoning"),
                        evidence=merged_evidence,
                        message=f"tool={tool_name} status={tool_status} cmd={tool_cmd}",
                    )

            if status == "PROBING":
                status = "DISCARDED"

            finding_out = {
                **base,
                "analysis_status": status,
                "verification_evidence": merged_evidence,
            }
            findings.append(finding_out)

            if self.scan_logger:
                self.scan_logger.log(
                    path=scan_path,
                    phase="deep",
                    event="analysis_verdict",
                    vuln_type=base.get("type"),
                    vector=base.get("vector"),
                    reason=base.get("reasoning"),
                    evidence=merged_evidence,
                    message=f"verdict={status}",
                )

        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="deep",
                event="phase_end",
                message=f"deep analysis finished (findings={len(findings)})",
            )

        final_status = "VERIFIED" if any(f.get("analysis_status") == "VERIFIED" for f in findings) else "DISCARDED"
        return {"analysis_status": final_status, "findings": findings}

    def final_exploit(self, data: dict, analysis: Dict[str, Any], path: str | None = None) -> Dict[str, Any]:
        req, _ = parse_burp_json(data)
        scan_path = path or req.url.split("?", 1)[0]
        raw_path = write_raw_request(req.raw)
        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="final",
                event="phase_start",
                message=f"final exploit started (findings={len(analysis.get('findings', []))})",
            )
        findings = []
        try:
            for f in analysis.get("findings", []):
                if f.get("analysis_status") != "VERIFIED":
                    if self.scan_logger:
                        self.scan_logger.log(
                            path=scan_path,
                            phase="final",
                            event="finding_skipped",
                            vuln_type=f.get("type"),
                            vector=f.get("vector"),
                            reason=f.get("reasoning"),
                            evidence=f.get("verification_evidence"),
                            message="final exploit skipped due to non-VERIFIED status",
                        )
                    continue
                vtype = f["type"]
                vector = f["vector"]
                param, location = vector.split("/", 1)
                c = Candidate(vtype, location, param, f.get("reasoning", ""))

                if vtype == "SQL Injection":
                    cmd = sqlmap_command(req, c, raw_path)
                    sqlmap_out = self.run_sqlmap(cmd)
                    if self._sqlmap_verified(sqlmap_out):
                        f["analysis_status"] = "VERIFIED"
                        f["verification_evidence"] = (f.get("verification_evidence", "") + " sqlmap=confirmed").strip()
                    else:
                        f["analysis_status"] = "DISCARDED"
                        f["verification_evidence"] = (f.get("verification_evidence", "") + " sqlmap=not_confirmed").strip()
                    if self.scan_logger:
                        self.scan_logger.log(
                            path=scan_path,
                            phase="final",
                            event="sqlmap_executed",
                            vuln_type=f.get("type"),
                            vector=f.get("vector"),
                            reason=f.get("reasoning"),
                            evidence=f.get("verification_evidence"),
                            message=f"sqlmap executed, verdict={f.get('analysis_status')}",
                        )
                    findings.append({**f, "action": {"tool": "sqlmap", "payload": shell_join(cmd)}})
                elif vtype == "Unauthenticated API Access":
                    script = build_unauth_exploit(req)
                    if self.scan_logger:
                        self.scan_logger.log(
                            path=scan_path,
                            phase="final",
                            event="exploit_script_built",
                            vuln_type=f.get("type"),
                            vector=f.get("vector"),
                            reason=f.get("reasoning"),
                            evidence=f.get("verification_evidence"),
                            message="unauthenticated-api exploit script generated",
                        )
                    findings.append({**f, "action": {"tool": "python_script", "payload": script}})
                else:
                    payload = f["action"].get("payload", "")
                    script = build_python_exploit(req, c, payload)
                    if self.scan_logger:
                        self.scan_logger.log(
                            path=scan_path,
                            phase="final",
                            event="exploit_script_built",
                            vuln_type=f.get("type"),
                            vector=f.get("vector"),
                            reason=f.get("reasoning"),
                            evidence=f.get("verification_evidence"),
                            message="python exploit script generated",
                        )
                    findings.append({**f, "action": {"tool": "python_script", "payload": script}})
        finally:
            try:
                os.remove(raw_path)
            except Exception:
                pass

        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="final",
                event="phase_end",
                message=f"final exploit finished (findings={len(findings)})",
            )
        final_status = "VERIFIED" if any(f.get("analysis_status") == "VERIFIED" for f in findings) else "DISCARDED"
        return {"analysis_status": final_status, "findings": findings}

    def run_sqlmap(self, cmd: List[str]) -> str:
        print("[progress] tool 실행중... tool=sqlmap", file=sys.stderr, flush=True)
        result = subprocess.run(cmd, shell=False, capture_output=True, text=True)
        print(f"[progress] tool 실행완료... tool=sqlmap exit={result.returncode}", file=sys.stderr, flush=True)
        return result.stdout + result.stderr

    def _sqlmap_verified(self, output: str) -> bool:
        out = output.lower()
        return "sql injection" in out and "is vulnerable" in out
