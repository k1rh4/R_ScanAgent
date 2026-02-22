from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Dict, Tuple
from urllib.parse import urlparse, parse_qs, urlencode


@dataclass
class ParsedRequest:
    method: str
    url: str
    headers: Dict[str, str]
    body: bytes
    query: Dict[str, list]
    raw: str


@dataclass
class ParsedResponse:
    status_code: int
    headers: Dict[str, str]
    body: bytes


def _maybe_b64(s: str) -> str:
    try:
        decoded = base64.b64decode(s, validate=True)
        if decoded:
            return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return s
    return s


def _parse_raw_request(raw: str, base_url: str | None = None) -> ParsedRequest:
    raw = _maybe_b64(raw)
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    request_line = lines[0]
    method, path, _ = request_line.split(" ")
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()

    host = headers.get("Host", "")
    scheme = "https" if ":443" in host else "http"
    if base_url:
        scheme = urlparse(base_url).scheme or scheme
        host = urlparse(base_url).netloc or host
    url = f"{scheme}://{host}{path}"

    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)

    return ParsedRequest(
        method=method,
        url=url,
        headers=headers,
        body=body.encode("utf-8", errors="ignore"),
        query=query,
        raw=raw,
    )


def _parse_raw_response(raw: str) -> ParsedResponse:
    raw = _maybe_b64(raw)
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status_line = lines[0]
    try:
        status_code = int(status_line.split(" ")[1])
    except Exception:
        status_code = 0
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()
    return ParsedResponse(status_code=status_code, headers=headers, body=body.encode("utf-8", errors="ignore"))


def parse_burp_json(data: dict) -> Tuple[ParsedRequest, ParsedResponse | None]:
    raw_req = data.get("request") or data.get("raw_request") or ""
    raw_res = data.get("response") or data.get("raw_response")
    base_url = data.get("base_url")
    req = _parse_raw_request(raw_req, base_url=base_url)
    res = _parse_raw_response(raw_res) if raw_res else None
    return req, res


def update_query(url: str, params: Dict[str, str]) -> str:
    parsed = urlparse(url)
    q = parse_qs(parsed.query, keep_blank_values=True)
    for k, v in params.items():
        q[k] = [v]
    new_q = urlencode(q, doseq=True)
    return parsed._replace(query=new_q).geturl()
