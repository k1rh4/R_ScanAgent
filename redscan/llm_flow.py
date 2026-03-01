from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List

from .json_utils import extract_json_loose


@dataclass
class LLMProbePlan:
    payloads: List[str]
    stop: bool = False
    reason: str = ""


@dataclass
class LLMJudgeVerdict:
    status: str
    confidence: float
    reason: str
    next_action: str


class LLMPlanner:
    def __init__(self, llm_client):
        self.llm = llm_client

    def _extract_json(self, raw: str) -> Any:
        return extract_json_loose(raw)

    def _planner_focus_rules(self, vuln_type: str) -> str:
        if vuln_type == "SQL Injection":
            return (
                "- prioritize DB-specific variants (error/boolean/time-based)\n"
                "- avoid duplicate semantics with only quote-style differences\n"
                "- if SQL evidence already strong, set stop=true\n"
            )
        if vuln_type == "Command Injection":
            return (
                "- prioritize low-noise command separators and shell substitution variants\n"
                "- start with harmless identity/timing probes before destructive-looking commands\n"
                "- if command execution indicators already present, set stop=true\n"
            )
        if vuln_type == "IDOR":
            return (
                "- prioritize object-id mutations (numeric increment, UUID perturbation)\n"
                "- preserve request shape and auth context; mutate only target identifier\n"
                "- if deny patterns (401/403/auth denied) are consistent, consider stop=true\n"
            )
        if vuln_type in {"Path Traversal", "Unrestricted File Download"}:
            return (
                "- prioritize traversal encoding variants and platform-specific file targets\n"
                "- escalate depth gradually instead of repeating equivalent payloads\n"
                "- if sensitive file markers already observed, set stop=true\n"
            )
        if vuln_type == "Unrestricted File Upload":
            return (
                "- prioritize extension/content-type bypass variants and simple polyglot naming\n"
                "- prefer payloads that help verify upload + retrieval execution chain\n"
                "- if uploaded content match/retrieval proof exists, set stop=true\n"
            )
        if vuln_type == "Unauthenticated API Access":
            return (
                "- prioritize auth-removal verification attempts (cookie/auth header stripped)\n"
                "- infer endpoint sensitivity from path/response semantics (profile, billing, settings, admin, private data)\n"
                "- if unauthenticated response still returns protected-looking data, set stop=true\n"
            )
        return (
            "- choose payloads that increase evidence diversity\n"
            "- avoid semantically duplicate attempts\n"
        )

    def propose_payloads(
        self,
        *,
        finding: Dict[str, Any],
        evidence_history: Iterable[str],
        fallback_payloads: List[str],
        max_payloads: int = 3,
        trace_context: Dict[str, Any] | None = None,
    ) -> LLMProbePlan:
        fallback = fallback_payloads[:max_payloads] if fallback_payloads else [""]
        if not self.llm or not self.llm.available():
            return LLMProbePlan(payloads=fallback)

        history = [e for e in evidence_history if isinstance(e, str) and e.strip()]
        vuln_type = str(finding.get("type", ""))
        system = (
            "You are a web vulnerability probing planner. "
            "Generate next payload attempts for a single finding. "
            "Return strict JSON only."
        )
        user = (
            "Schema:\n"
            "{\n"
            '  "payloads": ["string"],\n'
            '  "stop": true|false,\n'
            '  "reason": "short reason"\n'
            "}\n"
            "Rules:\n"
            f"- return at most {max_payloads} payloads\n"
            "- payloads must be raw injection strings only\n"
            "- if evidence is already conclusive, set stop=true and payloads=[]\n"
            f"{self._planner_focus_rules(vuln_type)}"
            f"finding={json.dumps(finding, ensure_ascii=False)}\n"
            f"evidence_history={json.dumps(history[-5:], ensure_ascii=False)}\n"
            f"fallback_payloads={json.dumps(fallback, ensure_ascii=False)}"
        )
        try:
            trace = dict(trace_context or {})
            trace.setdefault("purpose", "probe_planning")
            raw = self.llm.chat(system, user, trace=trace)
            payload = self._extract_json(raw)
            if not isinstance(payload, dict):
                return LLMProbePlan(payloads=fallback)
            stop = bool(payload.get("stop", False))
            reason = str(payload.get("reason", "")).strip()
            items = payload.get("payloads", [])
            out: List[str] = []
            if isinstance(items, list):
                for it in items:
                    s = str(it).strip()
                    if not s:
                        continue
                    if s not in out:
                        out.append(s)
            if not out and not stop:
                out = fallback
            return LLMProbePlan(payloads=out[:max_payloads], stop=stop, reason=reason)
        except Exception:
            return LLMProbePlan(payloads=fallback)


class LLMJudge:
    def __init__(self, llm_client):
        self.llm = llm_client

    def _extract_json(self, raw: str) -> Any:
        return extract_json_loose(raw)

    def _judge_focus_rules(self, vuln_type: str) -> str:
        if vuln_type == "SQL Injection":
            return (
                "- VERIFIED when SQL engine errors, deterministic boolean diff, or strong time-based gap is present\n"
                "- DISCARDED when only generic 5xx/error with no SQL signal\n"
            )
        if vuln_type == "Command Injection":
            return (
                "- VERIFIED when command output markers (uid/gid/whoami/context) or strong OOB/tool confirmation exist\n"
                "- DISCARDED when response change is generic and lacks command-exec indicators\n"
            )
        if vuln_type == "IDOR":
            return (
                "- VERIFIED when identifier mutation keeps 2xx and content similarity/length indicate unauthorized object access\n"
                "- DISCARDED when response consistently indicates authorization denial\n"
            )
        if vuln_type in {"Path Traversal", "Unrestricted File Download"}:
            return (
                "- VERIFIED when sensitive file markers/root patterns are observed\n"
                "- DISCARDED when only cosmetic diff without file-read indicators\n"
            )
        if vuln_type == "Unrestricted File Upload":
            return (
                "- VERIFIED when upload succeeds and retrieval/content-match proof exists\n"
                "- DISCARDED when upload endpoint responds but retrieval/verification consistently fails\n"
            )
        if vuln_type == "Unauthenticated API Access":
            return (
                "- VERIFIED when auth headers/cookies are removed but endpoint still returns sensitive/business data with 2xx\n"
                "- DISCARDED when auth removal consistently yields denial or non-sensitive/public response\n"
            )
        return "- use conservative classification; ambiguous cases remain PROBING\n"

    def _heuristic(self, finding: Dict[str, Any], evidence_text: str) -> LLMJudgeVerdict:
        e = (evidence_text or "").lower()
        vtype = finding.get("type", "")
        if any(k in e for k in ["sqlmap=confirmed", "commix=confirmed", "ffuf=confirmed", "verified=content_match"]):
            return LLMJudgeVerdict("VERIFIED", 0.95, "tool confirmed", "STOP")
        if vtype in {"Path Traversal", "Unrestricted File Download"} and any(
            k in e for k in ["/etc/passwd", "/etc/hosts", "win.ini", "root:x:"]
        ):
            return LLMJudgeVerdict("VERIFIED", 0.9, "sensitive file indicators observed", "STOP")
        if "error=baseline_failed" in e:
            return LLMJudgeVerdict("DISCARDED", 0.8, "baseline request failed", "STOP")
        if vtype == "Unauthenticated API Access":
            try:
                data = {}
                text = (evidence_text or "").strip()
                if text.startswith("{"):
                    data = json.loads(text)
                s_probe = int(data.get("status_probe", 0)) if data else 0
                auth_hint = str(data.get("auth_hint", ""))
                sim = float(data.get("similarity", 0.0)) if data else 0.0
                ratio = float(data.get("len_ratio", 0.0)) if data else 0.0
                if s_probe in {401, 403} or auth_hint == "denied":
                    return LLMJudgeVerdict("DISCARDED", 0.9, "unauth request denied", "STOP")
                if s_probe in {200, 201} and sim >= 0.65 and 0.5 <= ratio <= 1.6 and auth_hint == "none":
                    return LLMJudgeVerdict("VERIFIED", 0.85, "auth removed but protected response still accessible", "STOP")
            except Exception:
                pass
        if "timeout" in e:
            return LLMJudgeVerdict("PROBING", 0.5, "timeout observed", "RETRY")
        return LLMJudgeVerdict("PROBING", 0.4, "insufficient evidence", "COLLECT_MORE")

    def judge(
        self,
        *,
        finding: Dict[str, Any],
        evidence_history: Iterable[str],
        request_context: Dict[str, Any] | None = None,
        trace_context: Dict[str, Any] | None = None,
    ) -> LLMJudgeVerdict:
        evidence = [e for e in evidence_history if isinstance(e, str) and e.strip()]
        merged = "\n".join(evidence[-8:])

        # Always keep a deterministic fallback.
        fallback = self._heuristic(finding, merged)
        if not self.llm or not self.llm.available():
            return fallback

        vuln_type = str(finding.get("type", ""))
        system = (
            "You are a strict security verification judge. "
            "Return strict JSON only. "
            "Classify finding evidence into VERIFIED, DISCARDED, or PROBING."
        )
        if vuln_type == "Unauthenticated API Access":
            system = (
                "You are a strict web security judge focused on Unauthenticated API Access. "
                "Determine if this endpoint is likely auth-required by business role and "
                "whether unauthenticated access is actually possible."
            )
            user = (
                "Return STRICT JSON only:\n"
                "{\n"
                '  "status": "VERIFIED|DISCARDED|PROBING",\n'
                '  "confidence": 0.0,\n'
                '  "auth_required_likely": 0.0,\n'
                '  "reason": "short explanation",\n'
                '  "next_action": "STOP|COLLECT_MORE|RETRY",\n'
                '  "evidence_flags": {\n'
                '    "sensitive_data_exposed": true,\n'
                '    "auth_denied_when_unauth": false,\n'
                '    "public_endpoint_likely": false,\n'
                '    "response_similarity_high": true\n'
                "  }\n"
                "}\n"
                "Decision policy:\n"
                "- infer whether endpoint SHOULD require auth from endpoint role, parameters, and response semantics\n"
                "- VERIFIED only if auth_required_likely is high and unauth access still returns protected/sensitive/business data\n"
                "- DISCARDED if unauth is consistently denied or endpoint likely public\n"
                "- uncertain cases must be PROBING\n"
                f"finding_type={finding.get('type')}\n"
                f"vector={finding.get('vector')}\n"
                f"reasoning={finding.get('reasoning')}\n"
                f"request_context_json={json.dumps(request_context or {}, ensure_ascii=False)}\n"
                f"unauth_probe_evidence_json={json.dumps(evidence[-8:], ensure_ascii=False)}"
            )
        else:
            user = (
                "Schema:\n"
                "{\n"
                '  "status": "VERIFIED|DISCARDED|PROBING",\n'
                '  "confidence": 0.0,\n'
                '  "reason": "short reason",\n'
                '  "next_action": "STOP|COLLECT_MORE|RUN_TOOL|RETRY"\n'
                "}\n"
                "Rules:\n"
                "- if any explicit deny(401/403 + auth denied) and no bypass evidence, prefer DISCARDED\n"
                "- if sensitive indicators or strong tool evidence exist, prefer VERIFIED\n"
                "- uncertain cases should be PROBING, not VERIFIED\n"
                f"{self._judge_focus_rules(vuln_type)}"
                f"finding={json.dumps(finding, ensure_ascii=False)}\n"
                f"evidence_history={json.dumps(evidence[-8:], ensure_ascii=False)}"
            )

        try:
            trace = dict(trace_context or {})
            trace.setdefault("purpose", "finding_judgement")
            raw = self.llm.chat(system, user, trace=trace)
            payload = self._extract_json(raw)
            if not isinstance(payload, dict):
                return fallback
            status = str(payload.get("status", "")).strip().upper()
            if status not in {"VERIFIED", "DISCARDED", "PROBING"}:
                return fallback
            confidence = payload.get("confidence", 0.5)
            try:
                conf = float(confidence)
            except Exception:
                conf = fallback.confidence
            conf = max(0.0, min(1.0, conf))
            reason = str(payload.get("reason", "")).strip() or fallback.reason
            default_action = "COLLECT_MORE"
            allowed_actions = {"STOP", "COLLECT_MORE", "RUN_TOOL", "RETRY"}
            if vuln_type == "Unauthenticated API Access":
                allowed_actions = {"STOP", "COLLECT_MORE", "RETRY"}
            next_action = str(payload.get("next_action", default_action)).strip().upper()
            if next_action not in allowed_actions:
                next_action = default_action
            return LLMJudgeVerdict(status, conf, reason, next_action)
        except Exception:
            return fallback
