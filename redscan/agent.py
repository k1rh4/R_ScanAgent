from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import asdict
from typing import Any, Dict, List

from .candidates import discover_candidates, Candidate
from .http_parser import parse_burp_json
from .config import load_env
from .llm import LLMClient
from .policies import Policy
from .probing import (
    probe_candidates,
    sqlmap_command,
    build_python_exploit,
    run_python_script,
    write_raw_request,
)


class RedScanAgent:
    def __init__(self, policy_path: str = "custom_policy.txt"):
        load_env()
        self.policy = Policy.load(policy_path)
        self.llm = LLMClient()

    def _system_message(self) -> str:
        base = (
            "You are an autonomous red-team agent. Focus only on critical vulnerabilities: "
            "SQL Injection, Command Injection, Path Traversal, Unrestricted File Upload/Download."
        )
        if self.policy.text:
            return base + "\nCustom policy:\n" + self.policy.text
        return base

    def triage(self, data: dict) -> Dict[str, Any]:
        req, _ = parse_burp_json(data)
        candidates = discover_candidates(req)
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
        return {"analysis_status": "PROBING", "findings": findings}

    def probe(self, data: dict, active: bool = False) -> Dict[str, Any]:
        req, _ = parse_burp_json(data)
        candidates = discover_candidates(req)
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
        return {"analysis_status": "PROBING", "findings": findings}

    def deep_analysis(self, data: dict, probe_results: Dict[str, Any]) -> Dict[str, Any]:
        # Heuristic + optional LLM verification
        findings = []
        for f in probe_results.get("findings", []):
            evidence = f.get("verification_evidence", "")
            status = self._heuristic_verdict(f.get("type", ""), evidence)
            if self.llm.available() and status == "VERIFIED":
                status = self._llm_downgrade_only(f, evidence, status)
            findings.append({**f, "analysis_status": status})
        return {"analysis_status": "VERIFIED", "findings": findings}

    def final_exploit(self, data: dict, analysis: Dict[str, Any]) -> Dict[str, Any]:
        req, _ = parse_burp_json(data)
        raw_path = write_raw_request(req.raw)
        findings = []
        for f in analysis.get("findings", []):
            if f.get("analysis_status") != "VERIFIED":
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
                findings.append(
                    {
                        **f,
                        "action": {"tool": "sqlmap", "payload": cmd},
                    }
                )
            else:
                payload = f["action"]["payload"]
                script = build_python_exploit(req, c, payload)
                findings.append(
                    {
                        **f,
                        "action": {"tool": "python_script", "payload": script},
                    }
                )

        return {"analysis_status": "VERIFIED", "findings": findings}

    def run_sqlmap(self, cmd: str) -> str:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout + result.stderr

    def run_python(self, script: str) -> str:
        path = run_python_script(script)
        result = subprocess.run(["python", path], capture_output=True, text=True)
        return result.stdout + result.stderr

    def _heuristic_verdict(self, vuln_type: str, evidence: str) -> str:
        e = evidence.lower()
        if "error" in e:
            return "DISCARDED"
        if vuln_type == "SQL Injection":
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
        if vuln_type in ["Path Traversal", "Unrestricted File Download"] and "/etc/hosts" in e:
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
