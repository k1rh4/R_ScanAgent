from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
import json

from .request_mutation import apply_request_mutation


@dataclass
class ToolValidationResult:
    tool: str
    executed: bool
    confirmed: bool
    command: str
    evidence: str


def run_commix(req, vector: str, timeout_sec: int = 45) -> ToolValidationResult:
    param, location = vector.split("/", 1)
    url, headers, body = apply_request_mutation(req, location, param, "INJECT_HERE")
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
    fuzz_url, headers, fuzz_body = apply_request_mutation(req, location, param, "FUZZ")
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
