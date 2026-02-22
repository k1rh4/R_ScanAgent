from __future__ import annotations

import json
import re
import difflib
from urllib.parse import urlencode
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Tuple

import requests

from .http_parser import update_query
from .policies import Policy


@dataclass
class ProbeResult:
    id: str
    vuln_type: str
    vector: str
    reasoning: str
    tool: str
    payload: str
    status: str
    evidence: str


def _base_headers(headers: Dict[str, str]) -> Dict[str, str]:
    blocked = {"Content-Length", "Host"}
    return {k: v for k, v in headers.items() if k not in blocked}


def _apply_param(req, location: str, name: str, value: str):
    url = req.url
    headers = _base_headers(req.headers)
    body = req.body

    if location == "query":
        url = update_query(url, {name: value})
    elif location == "body":
        ctype = req.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                obj = json.loads(body.decode("utf-8", errors="ignore"))
            except Exception:
                obj = {}
            if isinstance(obj, dict):
                obj[name] = value
                body = json.dumps(obj).encode("utf-8")
        elif "application/x-www-form-urlencoded" in ctype:
            decoded = body.decode("utf-8", errors="ignore")
            parts = []
            found = False
            for pair in decoded.split("&"):
                if "=" not in pair:
                    continue
                k, v = pair.split("=", 1)
                if k == name:
                    v = value
                    found = True
                parts.append((k, v))
            if not found:
                parts.append((name, value))
            body = urlencode(parts).encode("utf-8")
    elif location == "cookie":
        cookie = headers.get("Cookie", "")
        kvs = []
        found = False
        for kv in cookie.split(";"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                if k.strip() == name:
                    v = value
                    found = True
                kvs.append(f"{k.strip()}={v.strip()}")
        if not found:
            kvs.append(f"{name}={value}")
        headers["Cookie"] = "; ".join(kvs)
    elif location == "header":
        headers[name] = value

    return url, headers, body


def _send(req, url, headers, body):
    start = time.time()
    r = requests.request(req.method, url, headers=headers, data=body, timeout=10)
    elapsed = time.time() - start
    return r, elapsed


def _cmd_probe(policy: Policy) -> str:
    cmd = policy.prefer_cmd_probe()
    return f";{cmd}"


def _sqli_probe(policy: Policy) -> str:
    mode = policy.prefer_sqli_mode()
    if mode == "error":
        return "'"
    return "' OR SLEEP(2)-- "


def _path_probe() -> str:
    return "../etc/hosts"


def _download_probe() -> str:
    return "../../../../etc/hosts"


def _payload_for(vuln_type: str, policy: Policy) -> str:
    if vuln_type == "SQL Injection":
        return _sqli_probe(policy)
    if vuln_type == "Command Injection":
        return _cmd_probe(policy)
    if vuln_type == "Path Traversal":
        return _path_probe()
    if vuln_type == "Unrestricted File Download":
        return _download_probe()
    if vuln_type == "Unrestricted File Upload":
        return "<FILE>"
    return ""


def _payloads_for(vuln_type: str, policy: Policy) -> List[str]:
    if vuln_type == "SQL Injection":
        return [
            _sqli_probe(policy),
            "\"",
            "' OR 1=1-- ",
        ]
    if vuln_type == "Command Injection":
        cmd = policy.prefer_cmd_probe()
        return [f";{cmd}", f"|{cmd}", f"$({cmd})"]
    if vuln_type == "Path Traversal":
        return ["../etc/hosts", "..%2fetc%2fhosts", "..\\etc\\hosts"]
    if vuln_type == "Unrestricted File Download":
        return ["../../../../etc/hosts", "..%2f..%2f..%2f..%2fetc%2fhosts"]
    if vuln_type == "Unrestricted File Upload":
        return ["<FILE>"]
    return [""]


def _diff_evidence(base, probe, base_time: float, probe_time: float) -> str:
    if not base or not probe:
        return "no_response"
    status_delta = f"{base.status_code}->{probe.status_code}"
    len_delta = f"{len(base.content)}->{len(probe.content)}"
    time_delta = probe_time - base_time
    hint = ""
    body_lower = probe.text.lower()
    for token in [
        "sql",
        "syntax",
        "mysql",
        "postgres",
        "oracle",
        "mssql",
        "sqlite",
        "root:x:",
        "/etc/hosts",
        "uid=",
        "gid=",
        "whoami",
    ]:
        if token in body_lower:
            hint = token
            break
    ratio = difflib.SequenceMatcher(None, base.text, probe.text).ratio()
    return f"status={status_delta} len={len_delta} time_delta={time_delta:.2f}s similarity={ratio:.2f} hint={hint}"


def _find_multipart_file_field(body: bytes) -> str | None:
    text = body.decode("utf-8", errors="ignore")
    match = re.search(r'name="([^"]+)";\\s*filename="[^"]*"', text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _extract_upload_url(text: str) -> str | None:
    match = re.search(r"https?://[^\\s'\\\"]+", text)
    if match:
        return match.group(0)
    return None


def probe_candidates(req, candidates, policy: Policy, active: bool = False) -> List[ProbeResult]:
    results: List[ProbeResult] = []
    baseline_cache: Dict[str, Tuple[requests.Response, float]] = {}

    def get_baseline() -> Tuple[requests.Response, float]:
        key = "baseline"
        if key not in baseline_cache:
            headers = _base_headers(req.headers)
            baseline_cache[key] = _send(req, req.url, headers, req.body)
        return baseline_cache[key]

    for c in candidates:
        payloads = _payloads_for(c.vuln_type, policy)
        payload = payloads[0] if payloads else _payload_for(c.vuln_type, policy)
        status = "PROBING"
        evidence = ""
        tool = "python_script"

        if c.vuln_type == "SQL Injection":
            tool = "sqlmap"

        if not active:
            results.append(ProbeResult(str(uuid.uuid4()), c.vuln_type, f"{c.param}/{c.location}", c.reason, tool, payload, status, evidence))
            continue

        # Active probing via HTTP replay (lightweight)
        if c.vuln_type != "Unrestricted File Upload":
            base_r, base_t = get_baseline()
            for p in payloads:
                pid = str(uuid.uuid4())
                url, headers, body = _apply_param(req, c.location, c.param, p)
                try:
                    r, elapsed = _send(req, url, headers, body)
                    evidence = _diff_evidence(base_r, r, base_t, elapsed)
                except Exception as e:
                    evidence = f"error={e}"
                results.append(ProbeResult(pid, c.vuln_type, f"{c.param}/{c.location}", c.reason, tool, p, status, evidence))
        else:
            field = _find_multipart_file_field(req.body)
            if not field:
                results.append(ProbeResult(str(uuid.uuid4()), c.vuln_type, f"{c.param}/{c.location}", c.reason, tool, payload, status, "upload field not found"))
                continue
            try:
                files = {field: ("redscan.txt", b"redscan", "text/plain")}
                headers = _base_headers(req.headers)
                headers.pop("Content-Type", None)
                start = time.time()
                r = requests.request(req.method, req.url, headers=headers, files=files, timeout=10)
                elapsed = time.time() - start
                hint = ""
                body_lower = r.text.lower()
                for token in ["uploaded", "success", "file", "url"]:
                    if token in body_lower:
                        hint = token
                        break
                url_hint = _extract_upload_url(r.text)
                verify = ""
                if url_hint:
                    try:
                        vr = requests.get(url_hint, timeout=10)
                        if "redscan" in vr.text:
                            verify = "verified=content_match"
                        else:
                            verify = "verified=miss"
                    except Exception:
                        verify = "verified=error"
                if url_hint:
                    hint = f"{hint}|{url_hint}" if hint else url_hint
                evidence = f"status={r.status_code} len={len(r.content)} time={elapsed:.2f}s hint={hint} {verify}".strip()
            except Exception as e:
                evidence = f"error={e}"
            results.append(ProbeResult(str(uuid.uuid4()), c.vuln_type, f"{c.param}/{c.location}", c.reason, tool, payload, status, evidence))

    return results


def write_raw_request(raw: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(raw)
        return f.name


def sqlmap_command(req, candidate, raw_request_path: str) -> str:
    param = candidate.param
    return f"sqlmap -r '{raw_request_path}' -p '{param}' --batch --flush-session --random-agent"


def build_python_exploit(req, candidate, payload) -> str:
    url, headers, body = _apply_param(req, candidate.location, candidate.param, payload)
    script = f"""
import requests
r = requests.request('{req.method}', '{url}', headers={headers!r}, data={body!r}, timeout=10)
print(r.status_code)
print(r.text[:1000])
"""
    return script.strip()


def run_python_script(code: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        path = f.name
    return path
