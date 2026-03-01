from __future__ import annotations

import json
from typing import Dict, Mapping, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse

from .http_parser import update_query


def filtered_headers(headers: Mapping[str, str], drop_host_content_length: bool = True) -> Dict[str, str]:
    out = dict(headers)
    if not drop_host_content_length:
        return out
    out.pop("Content-Length", None)
    out.pop("Host", None)
    return out


def update_form_body(body: bytes, name: str, value: str) -> bytes:
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


def set_nested_json_value(obj, path: str, value: str) -> None:
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


def apply_request_mutation(
    req,
    location: str,
    name: str,
    value: str,
    *,
    drop_host_content_length: bool = True,
) -> Tuple[str, Dict[str, str], bytes]:
    url = req.url
    headers = filtered_headers(req.headers, drop_host_content_length=drop_host_content_length)
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
                set_nested_json_value(obj, name, value)
                body = json.dumps(obj).encode("utf-8")
        elif "application/x-www-form-urlencoded" in ctype:
            body = update_form_body(body, name, value)
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

    return url, headers, body
