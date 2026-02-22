from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Policy:
    text: str

    @staticmethod
    def load(path: str | Path) -> "Policy":
        p = Path(path)
        if not p.exists():
            return Policy("")
        return Policy(p.read_text(encoding="utf-8", errors="ignore"))

    def prefer_cmd_probe(self) -> str:
        lower = self.text.lower()
        if "whoami" in lower:
            return "whoami"
        if "id" in lower:
            return "id"
        return "id"

    def prefer_sqli_mode(self) -> str:
        lower = self.text.lower()
        if "error" in lower and "sql" in lower:
            return "error"
        return "time"
