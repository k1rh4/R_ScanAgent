from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import parse_qs


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


def discover_candidates(req) -> List[Candidate]:
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
                candidates.append(Candidate(vtype, "query", k, "Parameter name suggests sensitive sink.", score))

    # Body params (form or json)
    body_params = {}
    ctype = req.headers.get("Content-Type", "")
    if "application/json" in ctype:
        body_params = _guess_json_params(req.body)
    elif "application/x-www-form-urlencoded" in ctype:
        body_params = _guess_form_params(req.body)

    for k in body_params.keys():
        for vtype, hints in name_hints.items():
            if any(h in k.lower() for h in hints):
                score = 2
                if any(h in path for h in path_hints.get(vtype, [])):
                    score += 2
                candidates.append(Candidate(vtype, "body", k, "Parameter name suggests sensitive sink.", score))

    # Cookies
    cookie = req.headers.get("Cookie", "")
    for kv in cookie.split(";"):
        if "=" in kv:
            k = kv.split("=", 1)[0].strip()
            for vtype, hints in name_hints.items():
                if any(h in k.lower() for h in hints):
                    candidates.append(Candidate(vtype, "cookie", k, "Cookie name suggests sensitive sink.", 1))

    # Headers
    for hk in req.headers.keys():
        if hk.lower() in ("x-forwarded-for", "referer"):
            candidates.append(Candidate("Command Injection", "header", hk, "Header sometimes passed to command/shell sinks.", 1))

    # Upload hints
    if "multipart/form-data" in ctype:
        candidates.append(Candidate("Unrestricted File Upload", "body", "multipart", "Multipart upload observed.", 3))

    return sorted(candidates, key=lambda c: c.score, reverse=True)
