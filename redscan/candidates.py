from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse, unquote


CRITICAL_TYPES = [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Unrestricted File Upload",
    "Unrestricted File Download",
]


@dataclass
class Candidate:
    vuln_type: str
    location: str
    param: str
    reason: str
    score: int = 0
    source: str = "rules"


def _guess_json_params(body: bytes) -> Dict[str, str]:
    try:
        obj = json.loads(body.decode("utf-8", errors="ignore"))
    except Exception:
        return {}
    if isinstance(obj, dict):
        return {k: str(v) for k, v in obj.items()}
    return {}


def _guess_form_params(body: bytes) -> Dict[str, str]:
    decoded = body.decode("utf-8", errors="ignore")
    return {k: v[0] if v else "" for k, v in parse_qs(decoded, keep_blank_values=True).items()}


def _flatten_json_paths(value: Any, prefix: str = "") -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(value, dict):
        for k, v in value.items():
            nxt = f"{prefix}.{k}" if prefix else k
            out.update(_flatten_json_paths(v, nxt))
        return out
    if isinstance(value, list):
        for i, v in enumerate(value):
            nxt = f"{prefix}.{i}" if prefix else str(i)
            out.update(_flatten_json_paths(v, nxt))
        return out
    out[prefix] = "" if value is None else str(value)
    return out


def _parse_cookie_params(cookie: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for kv in cookie.split(";"):
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _request_surface(req) -> Dict[str, Any]:
    parsed = urlparse(req.url)
    body_json = _guess_json_params(req.body)
    body_form = _guess_form_params(req.body)
    ctype = req.headers.get("Content-Type", "")
    body_paths: Dict[str, str] = {}
    if "application/json" in ctype and body_json:
        try:
            body_paths = _flatten_json_paths(json.loads(req.body.decode("utf-8", errors="ignore")))
        except Exception:
            body_paths = body_json
    elif "application/x-www-form-urlencoded" in ctype and body_form:
        body_paths = body_form
    return {
        "method": req.method,
        "url": req.url,
        "path": parsed.path or "/",
        "query_params": sorted(req.query.keys()),
        "body_fields": sorted(body_paths.keys()),
        "cookie_names": sorted(_parse_cookie_params(req.headers.get("Cookie", "")).keys()),
        "header_names": sorted(k for k in req.headers.keys() if k.lower() not in {"host", "content-length"}),
        "content_type": ctype,
    }


def _extract_json(raw: str) -> Any:
    raw = raw.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        pass
    match = re.search(r"(\{.*\}|\[.*\])", raw, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except Exception:
        return None


def _normalize_candidates(payload: Any, max_candidates: int) -> List[Candidate]:
    items = payload if isinstance(payload, list) else payload.get("candidates", []) if isinstance(payload, dict) else []
    allowed_types = set(CRITICAL_TYPES)
    allowed_locations = {"query", "body", "cookie", "header", "path"}
    out: List[Candidate] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        vuln_type = str(item.get("vuln_type", "")).strip()
        location = str(item.get("location", "")).strip().lower()
        param = str(item.get("param", "")).strip()
        reason = str(item.get("reason", "LLM selected candidate")).strip() or "LLM selected candidate"
        try:
            score = int(item.get("priority", 1))
        except Exception:
            score = 1
        if vuln_type not in allowed_types:
            continue
        if location not in allowed_locations:
            continue
        if location == "path":
            param = "__path__"
        if location != "path" and not param:
            continue
        out.append(
            Candidate(
                vuln_type=vuln_type,
                location=location,
                param=param,
                reason=reason,
                score=max(1, min(score, 10)),
                source="llm",
            )
        )
    uniq: dict[tuple[str, str, str], Candidate] = {}
    for c in out:
        key = (c.vuln_type, c.location, c.param)
        prev = uniq.get(key)
        if not prev or c.score > prev.score:
            uniq[key] = c
    ranked = sorted(uniq.values(), key=lambda c: c.score, reverse=True)
    return ranked[:max_candidates]


def discover_candidates(req) -> List[Candidate]:
    return discover_candidates_rules(req)


def discover_candidates_rules(req) -> List[Candidate]:
    candidates: List[Candidate] = []

    name_hints = {
        "SQL Injection": ["id", "user", "name", "search", "query", "filter"],
        "Command Injection": ["cmd", "exec", "command", "run", "ping", "host"],
        "Path Traversal": ["file", "path", "dir", "download", "name"],
        "Unrestricted File Upload": ["file", "upload", "image", "avatar", "document"],
        "Unrestricted File Download": ["file", "download", "path", "name"],
    }

    # Query params
    path = req.url.split("?", 1)[0].lower()
    parsed_path = (urlparse(req.url).path or "").lower()
    decoded_path = unquote(parsed_path)
    path_hints = {
        "SQL Injection": ["search", "query", "filter", "report", "export"],
        "Command Injection": ["exec", "cmd", "run", "ping"],
        "Path Traversal": ["file", "download", "export"],
        "Unrestricted File Upload": ["upload", "import"],
        "Unrestricted File Download": ["download", "export", "file"],
    }

    for k in req.query.keys():
        for vtype, hints in name_hints.items():
            if any(h in k.lower() for h in hints):
                score = 2
                if any(h in path for h in path_hints.get(vtype, [])):
                    score += 2
                candidates.append(Candidate(vtype, "query", k, "Parameter name suggests sensitive sink.", score, "rules"))

    # Path-based hints (critical for direct traversal/download style requests).
    traversal_tokens = ["../", "..\\", "%2e%2e", "%2f", "%5c"]
    sensitive_file_tokens = ["/etc/passwd", "/etc/hosts", "win.ini", "boot.ini"]
    if any(t in parsed_path for t in traversal_tokens) or any(t in decoded_path for t in ["../", "..\\"]):
        candidates.append(
            Candidate(
                "Path Traversal",
                "path",
                "__path__",
                "URL path contains traversal patterns.",
                5,
                "rules",
            )
        )
    if any(t in parsed_path for t in sensitive_file_tokens) or any(t in decoded_path for t in sensitive_file_tokens):
        candidates.append(
            Candidate(
                "Unrestricted File Download",
                "path",
                "__path__",
                "URL path targets sensitive file-like resources.",
                5,
                "rules",
            )
        )

    # Body params (form or json)
    body_params = {}
    ctype = req.headers.get("Content-Type", "")
    if "application/json" in ctype:
        try:
            parsed_body = json.loads(req.body.decode("utf-8", errors="ignore"))
            body_params = _flatten_json_paths(parsed_body)
        except Exception:
            body_params = _guess_json_params(req.body)
    elif "application/x-www-form-urlencoded" in ctype:
        body_params = _guess_form_params(req.body)

    for k in body_params.keys():
        for vtype, hints in name_hints.items():
            if any(h in k.lower() for h in hints):
                score = 2
                if any(h in path for h in path_hints.get(vtype, [])):
                    score += 2
                candidates.append(Candidate(vtype, "body", k, "Parameter name suggests sensitive sink.", score, "rules"))

    # Cookies
    cookie = req.headers.get("Cookie", "")
    for kv in cookie.split(";"):
        if "=" in kv:
            k = kv.split("=", 1)[0].strip()
            for vtype, hints in name_hints.items():
                if any(h in k.lower() for h in hints):
                    candidates.append(Candidate(vtype, "cookie", k, "Cookie name suggests sensitive sink.", 1, "rules"))

    # Headers
    for hk in req.headers.keys():
        if hk.lower() in ("x-forwarded-for", "referer"):
            candidates.append(Candidate("Command Injection", "header", hk, "Header sometimes passed to command/shell sinks.", 1, "rules"))

    # Upload hints
    if "multipart/form-data" in ctype:
        candidates.append(Candidate("Unrestricted File Upload", "body", "multipart", "Multipart upload observed.", 3, "rules"))

    return sorted(candidates, key=lambda c: c.score, reverse=True)


def discover_candidates_prioritized(req, llm_client, max_candidates: int = 9) -> List[Candidate]:
    cap = max(1, min(int(max_candidates), 9))
    fallback = discover_candidates_rules(req)
    if not llm_client or not llm_client.available():
        return fallback[:cap]

    surface = _request_surface(req)
    system = (
        "You are a web security candidate selector. "
        "Given an HTTP request attack surface, choose the highest-risk candidates for probing. "
        "Focus only on these vulnerability types: "
        "SQL Injection, Command Injection, Path Traversal, Unrestricted File Upload, Unrestricted File Download."
    )
    user = (
        "Return strict JSON only.\n"
        "Schema:\n"
        "{\n"
        '  "candidates": [\n'
        "    {\n"
        '      "vuln_type": one of the 5 allowed strings,\n'
        '      "location": "query" | "body" | "cookie" | "header" | "path",\n'
        '      "param": parameter key (for path always "__path__"),\n'
        '      "priority": integer 1..10,\n'
        '      "reason": short reason\n'
        "    }\n"
        "  ]\n"
        "}\n"
        f"Rules: return at most {cap} candidates, sorted by priority desc.\n"
        f"Attack surface:\n{json.dumps(surface, ensure_ascii=False)}"
    )
    try:
        raw = llm_client.chat(system, user)
        parsed = _extract_json(raw)
        llm_candidates = _normalize_candidates(parsed, cap)
        if llm_candidates:
            return llm_candidates
    except Exception:
        pass
    return fallback[:cap]
