from __future__ import annotations

import os
import subprocess
import sys
import uuid
from typing import Any, Dict, List

from .candidates import discover_candidates_prioritized, Candidate
from .http_parser import parse_burp_json
from .config import load_env
from .llm import LLMClient
from .policies import Policy
from .scan_logger import ScanLogger
from .tool_validators import run_commix, run_ffuf
from .probing import (
    probe_candidates,
    sqlmap_command,
    shell_join,
    build_python_exploit,
    run_python_script,
    write_raw_request,
)


class RedScanAgent:
    def __init__(self, policy_path: str = "custom_policy.txt", scan_logger: ScanLogger | None = None):
        load_env()
        self.policy = Policy.load(policy_path)
        self.llm = LLMClient()
        self.scan_logger = scan_logger
        self.enable_commix = self._env_bool("REDSCAN_ENABLE_COMMIX", "1")
        self.enable_ffuf = self._env_bool("REDSCAN_ENABLE_FFUF", "1")
        self.tool_timeout = int(os.getenv("REDSCAN_TOOL_TIMEOUT", "45"))
        self.max_candidates = max(1, min(int(os.getenv("REDSCAN_MAX_LLM_CANDIDATES", "9")), 9))

    def _env_bool(self, key: str, default: str = "0") -> bool:
        value = os.getenv(key, default)
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _system_message(self) -> str:
        base = (
            "You are an autonomous red-team agent. Focus only on critical vulnerabilities: "
            "SQL Injection, Command Injection, Path Traversal, Unrestricted File Upload/Download."
        )
        if self.policy.text:
            return base + "\nCustom policy:\n" + self.policy.text
        return base

    def triage(self, data: dict, path: str | None = None) -> Dict[str, Any]:
        req, _ = parse_burp_json(data)
        scan_path = path or req.url.split("?", 1)[0]
        candidates = discover_candidates_prioritized(req, self.llm, max_candidates=self.max_candidates)
        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="triage",
                event="phase_start",
                message=f"candidate discovery started (count={len(candidates)})",
            )
        findings = [
            {
                "id": str(uuid.uuid4()),
                "type": c.vuln_type,
                "vector": f"{c.param}/{c.location}",
                "reasoning": c.reason,
                "action": {"tool": "pending", "payload": ""},
                "verification_evidence": "",
            }
            for c in candidates
        ]
        if self.scan_logger:
            for c in candidates:
                vector = f"{c.param}/{c.location}"
                self.scan_logger.log(
                    path=scan_path,
                    phase="triage",
                    event="candidate_selected",
                    vuln_type=c.vuln_type,
                    vector=vector,
                    reason=c.reason,
                    message="candidate selected for probing",
                )
            self.scan_logger.log(
                path=scan_path,
                phase="triage",
                event="phase_end",
                message=f"candidate discovery finished (count={len(candidates)})",
            )
        return {"analysis_status": "PROBING", "findings": findings}

    def probe(self, data: dict, active: bool = False, path: str | None = None) -> Dict[str, Any]:
        req, _ = parse_burp_json(data)
        scan_path = path or req.url.split("?", 1)[0]
        candidates = discover_candidates_prioritized(req, self.llm, max_candidates=self.max_candidates)
        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="probe",
                event="phase_start",
                message=f"probing started (active={active}, candidates={len(candidates)})",
            )
        results = probe_candidates(req, candidates, self.policy, active=active)
        findings = []
        for r in results:
            findings.append(
                {
                    "id": r.id,
                    "type": r.vuln_type,
                    "vector": r.vector,
                    "reasoning": r.reasoning,
                    "action": {"tool": r.tool, "payload": r.payload},
                    "verification_evidence": r.evidence,
                }
            )
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
                message=f"probing finished (results={len(results)})",
            )
        return {"analysis_status": "PROBING", "findings": findings}

    def deep_analysis(
        self,
        data: dict,
        probe_results: Dict[str, Any],
        path: str | None = None,
        active: bool = False,
    ) -> Dict[str, Any]:
        # Heuristic + optional LLM verification
        req, _ = parse_burp_json(data)
        scan_path = path or req.url.split("?", 1)[0]
        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="deep",
                event="phase_start",
                message=f"deep analysis started (findings={len(probe_results.get('findings', []))})",
            )
        findings = []
        for f in probe_results.get("findings", []):
            evidence = f.get("verification_evidence", "")
            status = self._heuristic_verdict(f.get("type", ""), evidence)

            if active:
                tool_status, tool_evidence, tool_name, tool_cmd = self._preverify_with_tool(req, f, evidence)
                if tool_evidence:
                    evidence = (evidence + " " + tool_evidence).strip()
                if tool_status == "VERIFIED":
                    status = "VERIFIED"
                if self.scan_logger and tool_name:
                    self.scan_logger.log(
                        path=scan_path,
                        phase="deep",
                        event="tool_preverify",
                        vuln_type=f.get("type"),
                        vector=f.get("vector"),
                        reason=f.get("reasoning"),
                        evidence=evidence,
                        message=f"tool={tool_name} status={tool_status} cmd={tool_cmd}",
                    )

            if self.llm.available() and status == "VERIFIED":
                status = self._llm_downgrade_only(f, evidence, status)
            findings.append({**f, "analysis_status": status, "verification_evidence": evidence})
            if self.scan_logger:
                self.scan_logger.log(
                    path=scan_path,
                    phase="deep",
                    event="analysis_verdict",
                    vuln_type=f.get("type"),
                    vector=f.get("vector"),
                    reason=f.get("reasoning"),
                    evidence=evidence,
                    message=f"verdict={status}",
                )
        if self.scan_logger:
            self.scan_logger.log(
                path=scan_path,
                phase="deep",
                event="phase_end",
                message=f"deep analysis finished (findings={len(findings)})",
            )
        return {"analysis_status": "VERIFIED", "findings": findings}

    def _tool_eligible_by_llm(self, finding: Dict[str, Any], evidence: str) -> bool:
        if not self.llm.available():
            return True
        system = (
            "You are a security triage classifier. "
            "Decide if expensive external verification tool should run."
        )
        user = (
            "Return only HIGH or LOW.\n"
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
            status = "VERIFIED" if result.confirmed else "DISCARDED"
            return status, result.evidence, result.tool, result.command

        if vtype in {"Path Traversal", "Unrestricted File Download"} and self.enable_ffuf:
            result = run_ffuf(req, vector, timeout_sec=self.tool_timeout)
            status = "VERIFIED" if result.confirmed else "DISCARDED"
            return status, result.evidence, result.tool, result.command

        return "SKIPPED", "tool_disabled", "", ""

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
                    findings.append(
                        {
                            **f,
                            "action": {"tool": "sqlmap", "payload": shell_join(cmd)},
                        }
                    )
                else:
                    payload = f["action"]["payload"]
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
                    findings.append(
                        {
                            **f,
                            "action": {"tool": "python_script", "payload": script},
                        }
                    )
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
        return {"analysis_status": "VERIFIED", "findings": findings}

    def run_sqlmap(self, cmd: List[str]) -> str:
        print("[progress] tool 실행중... tool=sqlmap", file=sys.stderr, flush=True)
        result = subprocess.run(cmd, shell=False, capture_output=True, text=True)
        print(f"[progress] tool 실행완료... tool=sqlmap exit={result.returncode}", file=sys.stderr, flush=True)
        return result.stdout + result.stderr

    def run_python(self, script: str) -> str:
        print("[progress] tool 실행중... tool=python_script", file=sys.stderr, flush=True)
        path = run_python_script(script)
        try:
            result = subprocess.run(["python", path], capture_output=True, text=True)
            print(f"[progress] tool 실행완료... tool=python_script exit={result.returncode}", file=sys.stderr, flush=True)
            return result.stdout + result.stderr
        except Exception:
            print("[progress] tool 실행완료... tool=python_script result=error", file=sys.stderr, flush=True)
            raise

    def _heuristic_verdict(self, vuln_type: str, evidence: str) -> str:
        e = evidence.lower()
        is_path_like = vuln_type in {"Path Traversal", "Unrestricted File Download"}
        if "error" in e and not is_path_like:
            return "DISCARDED"
        if "time_delta" in e:
            # try to parse time_delta
            try:
                for part in e.split():
                    if part.startswith("time_delta="):
                        delta = float(part.split("=")[1].replace("s", ""))
                        if delta >= 1.5:
                            return "VERIFIED"
            except Exception:
                pass
        if any(k in e for k in ["sql", "syntax", "mysql", "postgres", "oracle", "mssql", "sqlite"]):
            return "VERIFIED"
        if vuln_type == "Command Injection" and any(k in e for k in ["uid=", "gid=", "whoami"]):
            return "VERIFIED"
        if is_path_like and any(
            k in e for k in ["/etc/hosts", "/etc/passwd", "root:x:"]
        ):
            return "VERIFIED"
        if vuln_type == "Unrestricted File Upload" and "verified=content_match" in e:
            return "VERIFIED"
        return "DISCARDED"

    def _llm_downgrade_only(self, finding: Dict[str, Any], evidence: str, current: str) -> str:
        system = self._system_message()
        user = (
            "Only downgrade if evidence is insufficient. "
            "Return only one token: DISCARDED or KEEP.\n\n"
            f"finding_type={finding.get('type')}\n"
            f"vector={finding.get('vector')}\n"
            f"evidence={evidence}\n"
        )
        try:
            resp = self.llm.chat(system, user).strip().upper()
            if "DISCARDED" in resp:
                return "DISCARDED"
        except Exception:
            return current
        return current

    def _sqlmap_verified(self, output: str) -> bool:
        out = output.lower()
        # sqlmap commonly prints when injection is found
        return "sql injection" in out and "is vulnerable" in out
