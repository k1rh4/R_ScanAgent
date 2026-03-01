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
        self.scan_logger = scan_logger
        self.llm = LLMClient(trace_logger=self._log_llm_trace)
        self.planner = LLMPlanner(self.llm)
        self.judge = LLMJudge(self.llm)

        self.enable_commix = self._env_bool("REDSCAN_ENABLE_COMMIX", "1")
        self.enable_ffuf = self._env_bool("REDSCAN_ENABLE_FFUF", "1")
        self.tool_timeout = int(os.getenv("REDSCAN_TOOL_TIMEOUT", "45"))
        self.max_candidates = max(1, min(int(os.getenv("REDSCAN_MAX_LLM_CANDIDATES", "9")), 9))
        self.max_probe_rounds = max(1, min(int(os.getenv("REDSCAN_MAX_PROBE_ROUNDS", "10")), 20))
        self.max_payloads_per_round = max(1, min(int(os.getenv("REDSCAN_MAX_PAYLOADS_PER_ROUND", "2")), 5))

    def _log_llm_trace(self, event: Dict[str, Any]) -> None:
        if not self.scan_logger:
            return
        try:
            phase = str(event.get("phase", "")).strip() or "llm"
            path = str(event.get("path", "")).strip() or "-"
            name = str(event.get("event", "")).strip() or "llm_event"
            provider = str(event.get("provider", "")).strip()
            model = str(event.get("model", "")).strip()
            purpose = str(event.get("purpose", "")).strip()
            msg_parts = [f"provider={provider}", f"model={model}", f"purpose={purpose}"]
            if "duration_sec" in event:
                msg_parts.append(f"duration_sec={event.get('duration_sec')}")
            if "error" in event:
                msg_parts.append(f"error={event.get('error')}")
            message = " ".join([p for p in msg_parts if p]).strip() or "llm trace"

            evidence_parts: List[str] = []
            system_prompt = event.get("system_prompt")
            user_prompt = event.get("user_prompt")
            response = event.get("response")
            if isinstance(system_prompt, str) and system_prompt:
                evidence_parts.append(f"system_prompt={system_prompt}")
            if isinstance(user_prompt, str) and user_prompt:
                evidence_parts.append(f"user_prompt={user_prompt}")
            if isinstance(response, str) and response:
                evidence_parts.append(f"response={response}")
            evidence = "\n\n".join(evidence_parts) if evidence_parts else None

            self.scan_logger.log(
                path=path,
                phase=phase,
                event=name,
                message=message,
                evidence=evidence,
            )
        except Exception:
            return

    def _env_bool(self, key: str, default: str = "0") -> bool:
        value = os.getenv(key, default)
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _log(
        self,
        *,
        path: str,
        phase: str,
        event: str,
        message: str,
        vuln_type: str | None = None,
        vector: str | None = None,
        reason: str | None = None,
        evidence: str | None = None,
    ) -> None:
        if not self.scan_logger:
            return
        self.scan_logger.log(
            path=path,
            phase=phase,
            event=event,
            message=message,
            vuln_type=vuln_type,
            vector=vector,
            reason=reason,
            evidence=evidence,
        )

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

    def _is_unauth_finding(self, finding: Dict[str, Any]) -> bool:
        return str(finding.get("type", "")) == "Unauthenticated API Access"

    def _judge_finding(
        self,
        *,
        finding: Dict[str, Any],
        evidence_history: List[str],
        scan_path: str,
        phase: str,
        req_context: Dict[str, Any] | None = None,
    ):
        kwargs: Dict[str, Any] = {
            "finding": finding,
            "evidence_history": evidence_history,
            "trace_context": {"path": scan_path, "phase": phase},
        }
        if self._is_unauth_finding(finding):
            kwargs["request_context"] = req_context or {}
        return self.judge.judge(**kwargs)

    def _final_status(self, findings: List[Dict[str, Any]]) -> str:
        return "VERIFIED" if any(f.get("analysis_status") == "VERIFIED" for f in findings) else "DISCARDED"

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
        candidates = discover_candidates_prioritized(
            req,
            self.llm,
            max_candidates=self.max_candidates,
            res=res,
            trace_context={"path": scan_path, "phase": "triage"},
        )
        self._log(
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
            self._log(
                path=scan_path,
                phase="triage",
                event="candidate_selected",
                vuln_type=c.vuln_type,
                vector=f"{c.param}/{c.location}",
                reason=c.reason,
                message="candidate selected for probing",
            )

        self._log(
            path=scan_path,
            phase="triage",
            event="phase_end",
            message=f"candidate discovery finished (count={len(candidates)})",
        )
        return {"analysis_status": "PROBING", "findings": findings}

    def probe(self, data: dict, active: bool = False, path: str | None = None) -> Dict[str, Any]:
        req, res = parse_burp_json(data)
        scan_path = path or req.url.split("?", 1)[0]
        candidates = discover_candidates_prioritized(
            req,
            self.llm,
            max_candidates=self.max_candidates,
            res=res,
            trace_context={"path": scan_path, "phase": "probe"},
        )
        self._log(
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
                    trace_context={"path": scan_path, "phase": "probe"},
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
                verdict = self._judge_finding(
                    finding=finding_for_plan,
                    evidence_history=history,
                    scan_path=scan_path,
                    phase="probe",
                    req_context=req_context,
                )
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
                self._log(
                    path=scan_path,
                    phase="probe",
                    event="candidate_probed",
                    vuln_type=r.vuln_type,
                    vector=r.vector,
                    reason=r.reasoning,
                    evidence=r.evidence,
                    message=f"probe executed with tool={r.tool}",
                )

        self._log(
            path=scan_path,
            phase="probe",
            event="phase_end",
            message=f"probing finished (results={len(findings)})",
        )
        return {"analysis_status": "PROBING", "findings": findings}

    def _tool_eligible_by_llm(self, finding: Dict[str, Any], evidence: str, scan_path: str, phase: str) -> bool:
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
            out = self.llm.chat(
                system,
                user,
                trace={"path": scan_path, "phase": phase, "purpose": "tool_preverify_gate"},
            ).strip().upper()
            return "HIGH" in out
        except Exception:
            return True

    def _preverify_with_tool(self, req, finding: Dict[str, Any], evidence: str, scan_path: str, phase: str) -> tuple[str, str, str, str]:
        vtype = finding.get("type", "")
        vector = finding.get("vector", "")
        if not vector or "/" not in vector:
            return "SKIPPED", "", "", ""
        if vtype not in {"Command Injection", "Path Traversal", "Unrestricted File Download"}:
            return "SKIPPED", "", "", ""
        if not self._tool_eligible_by_llm(finding, evidence, scan_path, phase):
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

        self._log(
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
            verdict = self._judge_finding(
                finding=base,
                evidence_history=evidence_history,
                scan_path=scan_path,
                phase="deep",
                req_context=req_context,
            )
            status = verdict.status

            merged_evidence = " || ".join(evidence_history[-5:]).strip()
            if verdict.reason:
                merged_evidence = (merged_evidence + f" judge_reason={verdict.reason} conf={verdict.confidence:.2f}").strip()

            if active and status != "VERIFIED":
                tool_status, tool_evidence, tool_name, tool_cmd = self._preverify_with_tool(
                    req,
                    base,
                    merged_evidence,
                    scan_path,
                    "deep",
                )
                if tool_evidence:
                    merged_evidence = (merged_evidence + " " + tool_evidence).strip()
                if tool_status == "VERIFIED":
                    status = "VERIFIED"
                if tool_name:
                    self._log(
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

            self._log(
                path=scan_path,
                phase="deep",
                event="analysis_verdict",
                vuln_type=base.get("type"),
                vector=base.get("vector"),
                reason=base.get("reasoning"),
                evidence=merged_evidence,
                message=f"verdict={status}",
            )

        self._log(
            path=scan_path,
            phase="deep",
            event="phase_end",
            message=f"deep analysis finished (findings={len(findings)})",
        )

        return {"analysis_status": self._final_status(findings), "findings": findings}

    def final_exploit(self, data: dict, analysis: Dict[str, Any], path: str | None = None) -> Dict[str, Any]:
        req, _ = parse_burp_json(data)
        scan_path = path or req.url.split("?", 1)[0]
        raw_path = write_raw_request(req.raw)
        self._log(
            path=scan_path,
            phase="final",
            event="phase_start",
            message=f"final exploit started (findings={len(analysis.get('findings', []))})",
        )
        findings = []
        try:
            for f in analysis.get("findings", []):
                if f.get("analysis_status") != "VERIFIED":
                    self._log(
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
                original_payload = ((f.get("action") or {}).get("payload", "") if isinstance(f, dict) else "") or ""

                if vtype == "SQL Injection":
                    cmd = sqlmap_command(req, c, raw_path)
                    sqlmap_out = self.run_sqlmap(cmd)
                    if self._sqlmap_verified(sqlmap_out):
                        f["analysis_status"] = "VERIFIED"
                        f["verification_evidence"] = (f.get("verification_evidence", "") + " sqlmap=confirmed").strip()
                    else:
                        f["analysis_status"] = "DISCARDED"
                        f["verification_evidence"] = (f.get("verification_evidence", "") + " sqlmap=not_confirmed").strip()
                    self._log(
                        path=scan_path,
                        phase="final",
                        event="sqlmap_executed",
                        vuln_type=f.get("type"),
                        vector=f.get("vector"),
                        reason=f.get("reasoning"),
                        evidence=f.get("verification_evidence"),
                        message=f"sqlmap executed, verdict={f.get('analysis_status')}",
                    )
                    findings.append(
                        {
                            **f,
                            "action": {"tool": "sqlmap", "payload": shell_join(cmd)},
                            "attack_payload": original_payload,
                        }
                    )
                elif vtype == "Unauthenticated API Access":
                    script = build_unauth_exploit(req)
                    self._log(
                        path=scan_path,
                        phase="final",
                        event="exploit_script_built",
                        vuln_type=f.get("type"),
                        vector=f.get("vector"),
                        reason=f.get("reasoning"),
                        evidence=f.get("verification_evidence"),
                        message="unauthenticated-api exploit script generated",
                    )
                    findings.append(
                        {
                            **f,
                            "action": {"tool": "python_script", "payload": script},
                            "attack_payload": original_payload or "<STRIP_AUTH>",
                        }
                    )
                else:
                    payload = original_payload
                    script = build_python_exploit(req, c, payload)
                    self._log(
                        path=scan_path,
                        phase="final",
                        event="exploit_script_built",
                        vuln_type=f.get("type"),
                        vector=f.get("vector"),
                        reason=f.get("reasoning"),
                        evidence=f.get("verification_evidence"),
                        message="python exploit script generated",
                    )
                    findings.append(
                        {
                            **f,
                            "action": {"tool": "python_script", "payload": script},
                            "attack_payload": payload,
                        }
                    )
        finally:
            try:
                os.remove(raw_path)
            except Exception:
                pass

        self._log(
            path=scan_path,
            phase="final",
            event="phase_end",
            message=f"final exploit finished (findings={len(findings)})",
        )
        return {"analysis_status": self._final_status(findings), "findings": findings}

    def run_sqlmap(self, cmd: List[str]) -> str:
        print("[progress] tool 실행중... tool=sqlmap", file=sys.stderr, flush=True)
        result = subprocess.run(cmd, shell=False, capture_output=True, text=True)
        print(f"[progress] tool 실행완료... tool=sqlmap exit={result.returncode}", file=sys.stderr, flush=True)
        return result.stdout + result.stderr

    def _sqlmap_verified(self, output: str) -> bool:
        out = output.lower()
        return "sql injection" in out and "is vulnerable" in out
