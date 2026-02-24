from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from urllib.parse import urlparse
from urllib.parse import parse_qsl, urlencode

from .http_parser import update_query


@dataclass
class ToolValidationResult:
    tool: str
    executed: bool
    confirmed: bool
    command: str
    evidence: str


def _update_form_body(body: bytes, name: str, value: str) -> bytes:
    decoded = body.decode("utf-8", errors="ignore")
    pairs = parse_qsl(decoded, keep_blank_values=True)
    updated = []
    found = False
    for k, v in pairs:
        if k == name:
            updated.append((k, value))
            found = True
        else:
            updated.append((k, v))
    if not found:
        updated.append((name, value))
    return urlencode(updated).encode("utf-8")


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


def _apply_value(req, location: str, name: str, value: str):
    url = req.url
    headers = dict(req.headers)
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
            body = _update_form_body(body, name, value)
    elif location == "cookie":
        cookie = headers.get("Cookie", "")
        parts = []
        found = False
        for kv in cookie.split(";"):
            if "=" not in kv:
                continue
            k, v = kv.split("=", 1)
            if k.strip() == name:
                parts.append(f"{k.strip()}={value}")
                found = True
            else:
                parts.append(f"{k.strip()}={v.strip()}")
        if not found:
            parts.append(f"{name}={value}")
        headers["Cookie"] = "; ".join(parts)
    elif location == "header":
        headers[name] = value
    elif location == "path":
        parsed = urlparse(url)
        new_path = value if value.startswith("/") else f"/{value}"
        url = parsed._replace(path=new_path).geturl()

    headers.pop("Content-Length", None)
    headers.pop("Host", None)
    return url, headers, body


def run_commix(req, vector: str, timeout_sec: int = 45) -> ToolValidationResult:
    param, location = vector.split("/", 1)
    url, headers, body = _apply_value(req, location, param, "INJECT_HERE")
    cmd = ["commix", "--batch", "--level", "3", "--url", url]

    body_text = body.decode("utf-8", errors="ignore")
    if req.method.upper() != "GET":
        cmd.extend(["--method", req.method.upper()])
    if body_text.strip():
        cmd.extend(["--data", body_text])
    if headers.get("Cookie"):
        cmd.extend(["--cookie", headers.get("Cookie", "")])
    extra_headers = []
    for k, v in headers.items():
        lk = k.lower()
        if lk in {"host", "content-length", "cookie"}:
            continue
        extra_headers.append(f"{k}: {v}")
    if extra_headers:
        cmd.extend(["--headers", "\n".join(extra_headers)])

    print(f"[progress] tool 실행중... tool=commix vector={vector}", file=sys.stderr, flush=True)
    try:
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, shell=False)
    except FileNotFoundError:
        print("[progress] tool 실행완료... tool=commix result=tool_not_installed", file=sys.stderr, flush=True)
        return ToolValidationResult("commix", False, False, " ".join(cmd), "tool_not_installed")
    except subprocess.TimeoutExpired:
        print("[progress] tool 실행완료... tool=commix result=timeout", file=sys.stderr, flush=True)
        return ToolValidationResult("commix", True, False, " ".join(cmd), "timeout")
    except Exception as e:
        print(f"[progress] tool 실행완료... tool=commix result=error", file=sys.stderr, flush=True)
        return ToolValidationResult("commix", True, False, " ".join(cmd), f"error={e}")

    output = (run.stdout or "") + "\n" + (run.stderr or "")
    lower = output.lower()
    confirmed = any(
        token in lower
        for token in [
            "command injection",
            "is vulnerable",
            "vulnerable parameter",
            "identified injectable",
        ]
    )
    evidence = "commix=confirmed" if confirmed else "commix=not_confirmed"
    print(f"[progress] tool 실행완료... tool=commix confirmed={confirmed}", file=sys.stderr, flush=True)
    return ToolValidationResult("commix", True, confirmed, " ".join(cmd), evidence)


def run_ffuf(req, vector: str, timeout_sec: int = 45) -> ToolValidationResult:
    param, location = vector.split("/", 1)
    fuzz_url, headers, fuzz_body = _apply_value(req, location, param, "FUZZ")
    payloads = [
        "../etc/passwd",
        "..%2fetc%2fpasswd",
        "..\\..\\windows\\win.ini",
        "..%5c..%5cwindows%5cwin.ini",
    ]

    wordlist_file = None
    output_file = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as wf:
            wf.write("\n".join(payloads) + "\n")
            wordlist_file = wf.name
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as of:
            output_file = of.name

        cmd = [
            "ffuf",
            "-u",
            fuzz_url,
            "-w",
            wordlist_file,
            "-mc",
            "200,206,301,302,401,403,500",
            "-mr",
            "root:|for 16-bit app support|\\[extensions\\]",
            "-of",
            "json",
            "-o",
            output_file,
            "-t",
            "10",
        ]

        if req.method.upper() != "GET":
            cmd.extend(["-X", req.method.upper()])
            body_text = fuzz_body.decode("utf-8", errors="ignore")
            if body_text.strip():
                cmd.extend(["-d", body_text])

        for k, v in headers.items():
            if k.lower() in {"content-length", "host"}:
                continue
            cmd.extend(["-H", f"{k}: {v}"])

        print(f"[progress] tool 실행중... tool=ffuf vector={vector}", file=sys.stderr, flush=True)
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, shell=False)
        except FileNotFoundError:
            print("[progress] tool 실행완료... tool=ffuf result=tool_not_installed", file=sys.stderr, flush=True)
            return ToolValidationResult("ffuf", False, False, " ".join(cmd), "tool_not_installed")
        except subprocess.TimeoutExpired:
            print("[progress] tool 실행완료... tool=ffuf result=timeout", file=sys.stderr, flush=True)
            return ToolValidationResult("ffuf", True, False, " ".join(cmd), "timeout")
        except Exception as e:
            print("[progress] tool 실행완료... tool=ffuf result=error", file=sys.stderr, flush=True)
            return ToolValidationResult("ffuf", True, False, " ".join(cmd), f"error={e}")

        confirmed = False
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                parsed = json.loads(f.read())
            confirmed = bool(parsed.get("results"))
        except Exception:
            confirmed = False

        evidence = "ffuf=confirmed" if confirmed else "ffuf=not_confirmed"
        print(f"[progress] tool 실행완료... tool=ffuf confirmed={confirmed}", file=sys.stderr, flush=True)
        return ToolValidationResult("ffuf", True, confirmed, " ".join(cmd), evidence)
    finally:
        for p in [wordlist_file, output_file]:
            if not p:
                continue
            try:
                os.remove(p)
            except Exception:
                pass
