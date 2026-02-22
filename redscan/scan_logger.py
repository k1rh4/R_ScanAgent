from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from pathlib import Path
from threading import RLock


class ScanLogger:
    def __init__(self, log_path: str = "scan.log"):
        self.log_path = Path(log_path)
        self._lock = RLock()
        self._seq_by_path: dict[str, int] = defaultdict(int)
        self._item_no: dict[tuple[str, str, str], int] = {}
        self.max_bytes = int(os.getenv("REDSCAN_SCAN_LOG_MAX_BYTES", str(10 * 1024 * 1024)))
        self.backup_count = int(os.getenv("REDSCAN_SCAN_LOG_BACKUP_COUNT", "5"))

    def _rotate_if_needed(self) -> None:
        if self.max_bytes <= 0 or self.backup_count <= 0:
            return
        if not self.log_path.exists():
            return
        try:
            size = self.log_path.stat().st_size
        except Exception:
            return
        if size < self.max_bytes:
            return

        # Remove oldest backup first.
        oldest = self.log_path.with_name(f"{self.log_path.name}.{self.backup_count}")
        try:
            if oldest.exists():
                oldest.unlink()
        except Exception:
            pass

        # Shift N-1 ... 1
        for i in range(self.backup_count - 1, 0, -1):
            src = self.log_path.with_name(f"{self.log_path.name}.{i}")
            dst = self.log_path.with_name(f"{self.log_path.name}.{i + 1}")
            try:
                if src.exists():
                    src.rename(dst)
            except Exception:
                pass

        # Current -> .1
        try:
            self.log_path.rename(self.log_path.with_name(f"{self.log_path.name}.1"))
        except Exception:
            pass

    def _next_no(self, path: str) -> int:
        self._seq_by_path[path] += 1
        return self._seq_by_path[path]

    def assign_no(self, path: str, vuln_type: str, vector: str) -> int:
        key = (path, vuln_type, vector)
        with self._lock:
            if key in self._item_no:
                return self._item_no[key]
            no = self._next_no(path)
            self._item_no[key] = no
            return no

    def log(
        self,
        *,
        path: str,
        phase: str,
        event: str,
        message: str,
        vuln_type: str | None = None,
        vector: str | None = None,
        reason: str | None = None,
        evidence: str | None = None,
        number: int | None = None,
    ) -> None:
        try:
            with self._lock:
                no = number
                if no is None and vuln_type and vector:
                    no = self.assign_no(path, vuln_type, vector)

                record = {
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                    "path": path,
                    "phase": phase,
                    "event": event,
                    "no": no,
                    "vuln_type": vuln_type,
                    "vector": vector,
                    "reason": reason,
                    "evidence": evidence,
                    "message": message,
                }
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                self._rotate_if_needed()
                with self.log_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
                    f.flush()
        except Exception:
            # Logging must never break scan pipeline.
            return
