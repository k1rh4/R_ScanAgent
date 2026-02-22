from __future__ import annotations

from pathlib import Path
from threading import RLock
from urllib.parse import urlparse

from .http_parser import parse_burp_json


class CompletedPathTracker:
    def __init__(self, log_path: str = "complete_path.log"):
        self.log_path = Path(log_path)
        self._lock = RLock()
        self._completed = self._load()
        self._in_progress: set[str] = set()

    def _load(self) -> set[str]:
        if not self.log_path.exists():
            return set()
        entries: set[str] = set()
        for line in self.log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = line.strip()
            if value:
                entries.add(value)
        return entries

    def extract_path(self, data: dict) -> str:
        req, _ = parse_burp_json(data)
        parsed = urlparse(req.url)
        return parsed.path or "/"

    def extract_dedupe_key(self, data: dict) -> str:
        req, _ = parse_burp_json(data)
        parsed = urlparse(req.url)
        method = (req.method or "").upper()
        host = parsed.netloc or req.headers.get("Host", "")
        path = parsed.path or "/"
        return f"{method} {host}{path}"

    def is_completed(self, path: str) -> bool:
        with self._lock:
            return path in self._completed

    def try_reserve(self, path: str) -> bool:
        with self._lock:
            if path in self._completed or path in self._in_progress:
                return False
            self._in_progress.add(path)
            return True

    def mark_completed(self, path: str) -> None:
        with self._lock:
            self._in_progress.discard(path)
            if path in self._completed:
                return
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(path + "\n")
            self._completed.add(path)

    def mark_failed(self, path: str) -> None:
        with self._lock:
            self._in_progress.discard(path)

    def completed_count(self) -> int:
        with self._lock:
            return len(self._completed)
