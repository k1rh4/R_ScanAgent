from __future__ import annotations

import json
import re
import difflib
import shlex
from urllib.parse import urlencode, urlparse
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


def _set_nested_json_value(obj, path: str, value: str) -> None:
    parts = [p for p in path.split(".") if p]
    if not parts:
        return
    cur = obj
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        next_is_index = i + 1 < len(parts) and parts[i + 1].isdigit()
        if part.isdigit():
            idx = int(part)
            if not isinstance(cur, list):
                return
            while len(cur) <= idx:
                cur.append({} if not next_is_index else [])
            if last:
                cur[idx] = value
                return
            if not isinstance(cur[idx], (dict, list)):
                cur[idx] = [] if next_is_index else {}
            cur = cur[idx]
            continue
        if not isinstance(cur, dict):
            return
        if last:
            cur[part] = value
            return
        if part not in cur or not isinstance(cur[part], (dict, list)):
            cur[part] = [] if next_is_index else {}
        cur = cur[part]


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
                _set_nested_json_value(obj, name, value)
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
    elif location == "path":
        parsed = urlparse(url)
        new_path = value if value.startswith("/") else f"/{value}"
        url = parsed._replace(path=new_path).geturl()

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
    if vuln_type == "IDOR":
        return "<ID_MUTATION>"
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
    if vuln_type == "IDOR":
        return ["<ID_MUTATION>"]
    return [""]


def _diff_evidence(base, probe, base_time: float, probe_time: float) -> str:
    if base is None or probe is None:
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


def _auth_hint(body_lower: str) -> str:
    for token in [
        "forbidden",
        "unauthorized",
        "not authorized",
        "access denied",
        "permission denied",
        "login",
        "sign in",
    ]:
        if token in body_lower:
            return "denied"
    return "none"


def _snippet(text: str, limit: int = 120) -> str:
    return " ".join(text.strip().split())[:limit]


def _idor_evidence(base, probe, base_time: float, probe_time: float, req_path: str) -> str:
    if base is None or probe is None:
        return json.dumps({"idor": "no_response"})
    base_text = base.text if hasattr(base, "text") else base.content.decode("utf-8", errors="ignore")
    probe_text = probe.text if hasattr(probe, "text") else probe.content.decode("utf-8", errors="ignore")
    ratio = difflib.SequenceMatcher(None, base_text, probe_text).ratio()
    auth = _auth_hint(probe_text.lower())
    base_len = len(base.content)
    probe_len = len(probe.content)
    len_ratio = (probe_len / base_len) if base_len else 0.0
    payload = {
        "idor": "compare",
        "status_base": base.status_code,
        "status_probe": probe.status_code,
        "len_base": base_len,
        "len_probe": probe_len,
        "len_ratio": round(len_ratio, 2),
        "similarity": round(ratio, 2),
        "auth_hint": auth,
        "base_snip": _snippet(base_text),
        "probe_snip": _snippet(probe_text),
        "path": req_path,
    }
    return json.dumps(payload, ensure_ascii=False)


def _find_multipart_file_field(body: bytes) -> str | None:
    text = body.decode("utf-8", errors="ignore")
    match = re.search(r'name="([^"]+)";\\s*filename="[^"]*"', text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def _get_nested_json_value(obj, path: str):
    parts = [p for p in path.split(".") if p]
    cur = obj
    for part in parts:
        if isinstance(cur, list) and part.isdigit():
            idx = int(part)
            if idx >= len(cur):
                return None
            cur = cur[idx]
        elif isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        else:
            return None
    return cur


def _current_value(req, location: str, name: str) -> str | None:
    if location == "query":
        values = req.query.get(name)
        if values:
            return str(values[0])
        return None
    if location == "body":
        ctype = req.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                obj = json.loads(req.body.decode("utf-8", errors="ignore"))
                val = _get_nested_json_value(obj, name)
                return None if val is None else str(val)
            except Exception:
                return None
        if "application/x-www-form-urlencoded" in ctype:
            decoded = req.body.decode("utf-8", errors="ignore")
            for pair in decoded.split("&"):
                if "=" not in pair:
                    continue
                k, v = pair.split("=", 1)
                if k == name:
                    return v
        return None
    if location == "cookie":
        cookie = req.headers.get("Cookie", "")
        for kv in cookie.split(";"):
            if "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            if k.strip() == name:
                return v.strip()
        return None
    if location == "header":
        return req.headers.get(name)
    return None


def _mutate_id(value: str) -> List[str]:
    if value is None:
        return ["2", "3"]
    if re.fullmatch(r"\d+", value):
        n = int(value)
        return [str(n + 1), str(n + 2)]
    if re.fullmatch(r"[0-9a-fA-F-]{32,36}", value):
        # flip last hex char
        last = value[-1]
        repl = "0" if last.lower() != "0" else "1"
        return [value[:-1] + repl]
    m = re.search(r"(\d+)", value)
    if m:
        n = int(m.group(1))
        return [value[: m.start(1)] + str(n + 1) + value[m.end(1) :]]
    return [value + "1"]


def _mutate_path(path: str) -> List[str]:
    segments = path.split("/")
    for i in range(len(segments) - 1, -1, -1):
        seg = segments[i]
        if re.fullmatch(r"\d+", seg) or re.fullmatch(r"[0-9a-fA-F-]{32,36}", seg):
            for v in _mutate_id(seg):
                copy = segments[:]
                copy[i] = v
                return ["/".join(copy)]
    # fallback: try replace first numeric substring
    m = re.search(r"(\d+)", path)
    if m:
        n = int(m.group(1))
        return [path[: m.start(1)] + str(n + 1) + path[m.end(1) :]]
    return []


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
        path_hint = f"path_hint={urlparse(req.url).path}" if c.location == "path" else ""

        if c.vuln_type == "SQL Injection":
            tool = "sqlmap"
        if c.vuln_type == "IDOR":
            tool = "python_script"

        if not active:
            results.append(
                ProbeResult(
                    str(uuid.uuid4()),
                    c.vuln_type,
                    f"{c.param}/{c.location}",
                    c.reason,
                    tool,
                    payload,
                    status,
                    path_hint,
                )
            )
            continue

        # Active probing via HTTP replay (lightweight)
        if c.vuln_type != "Unrestricted File Upload":
            try:
                base_r, base_t = get_baseline()
            except Exception as e:
                for p in payloads:
                    results.append(
                        ProbeResult(
                            str(uuid.uuid4()),
                            c.vuln_type,
                            f"{c.param}/{c.location}",
                            c.reason,
                            tool,
                            p,
                            status,
                            (f"error=baseline_failed:{e} {path_hint}").strip(),
                        )
                    )
                continue
            if c.vuln_type == "IDOR":
                req_path = urlparse(req.url).path or "/"
                if c.location == "path":
                    payloads = _mutate_path(req_path)
                    if not payloads:
                        results.append(
                            ProbeResult(
                                str(uuid.uuid4()),
                                c.vuln_type,
                                f"{c.param}/{c.location}",
                                c.reason,
                                tool,
                                "",
                                status,
                                "idor=skipped reason=no_mutation path_hint=" + req_path,
                            )
                        )
                        continue
                else:
                    cur = _current_value(req, c.location, c.param)
                    payloads = _mutate_id(cur)
            for p in payloads:
                pid = str(uuid.uuid4())
                if c.vuln_type == "IDOR" and c.location == "path":
                    url, headers, body = _apply_param(req, "path", c.param, p)
                else:
                    url, headers, body = _apply_param(req, c.location, c.param, p)
                try:
                    r, elapsed = _send(req, url, headers, body)
                    if c.vuln_type == "IDOR":
                        evidence = _idor_evidence(base_r, r, base_t, elapsed, urlparse(req.url).path or "/")
                    else:
                        evidence = _diff_evidence(base_r, r, base_t, elapsed)
                except Exception as e:
                    evidence = f"error={e}"
                if path_hint:
                    evidence = f"{evidence} {path_hint}".strip()
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


def sqlmap_command(req, candidate, raw_request_path: str) -> List[str]:
    param = candidate.param
    return [
        "sqlmap",
        "-r",
        raw_request_path,
        "-p",
        param,
        "--batch",
        "--flush-session",
        "--random-agent",
    ]


def shell_join(argv: List[str]) -> str:
    return shlex.join(argv)


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
