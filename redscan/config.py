from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None


def load_env(path: str | None = None) -> None:
    if load_dotenv is None:
        return
    if path:
        load_dotenv(path)
        return
    # Default to .env in repo root if present
    root = Path(__file__).resolve().parents[1]
    env_path = root / ".env"
    if env_path.exists():
        load_dotenv(env_path)


def getenv(key: str, default: str | None = None) -> str | None:
    return os.getenv(key, default)
