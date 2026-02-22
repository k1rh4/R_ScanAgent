from __future__ import annotations

import json
import time
from typing import Callable, Iterable

import requests

from .config import getenv


def _parse_int_set(value: str | None) -> set[int]:
    if not value:
        return set()
    out: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.add(int(part))
        except ValueError:
            continue
    return out


class LLMClient:
    def __init__(self, provider: str | None = None, model: str | None = None):
        self.provider = (provider or getenv("LLM_PROVIDER", "gemini")).lower()
        self.model = model
        self.timeout = float(getenv("LLM_TIMEOUT", "30"))
        self.retries = int(getenv("LLM_RETRIES", "2"))
        self.backoff = float(getenv("LLM_RETRY_BACKOFF", "0.5"))
        self.backoff_mode = getenv("LLM_RETRY_MODE", "exponential")  # exponential | fixed
        self.retry_statuses = _parse_int_set(getenv("LLM_RETRY_STATUS", "429,500,502,503,504"))

    def _resolve_model(self, provider_model_key: str, provider_default: str) -> str:
        # Priority: explicit arg > provider-specific env > generic env > provider default
        return (
            self.model
            or getenv(provider_model_key)
            or getenv("LLM_MODEL")
            or provider_default
        )

    def available(self) -> bool:
        if self.provider == "openai":
            return bool(getenv("OPENAI_API_KEY"))
        if self.provider == "anthropic":
            return bool(getenv("ANTHROPIC_API_KEY"))
        if self.provider == "gemini":
            return bool(getenv("GEMINI_API_KEY"))
        return False

    def chat(self, system_message: str, user_message: str) -> str:
        if self.provider == "openai":
            return self._with_retry(lambda: self._openai_chat(system_message, user_message))
        if self.provider == "anthropic":
            return self._with_retry(lambda: self._anthropic_chat(system_message, user_message))
        if self.provider == "gemini":
            return self._with_retry(lambda: self._gemini_chat(system_message, user_message))
        raise RuntimeError(f"Unsupported provider: {self.provider}")

    def _sleep_for(self, attempt: int) -> None:
        if self.backoff_mode == "fixed":
            time.sleep(self.backoff)
        else:
            time.sleep(self.backoff * (2 ** attempt))

    def _with_retry(self, fn: Callable[[], str]) -> str:
        last_err = None
        for attempt in range(self.retries + 1):
            try:
                return fn()
            except requests.HTTPError as e:  # pragma: no cover
                last_err = e
                status = getattr(e.response, "status_code", None)
                if status not in self.retry_statuses or attempt >= self.retries:
                    break
                self._sleep_for(attempt)
            except (requests.Timeout, requests.ConnectionError) as e:  # pragma: no cover
                last_err = e
                if attempt >= self.retries:
                    break
                self._sleep_for(attempt)
            except Exception as e:  # pragma: no cover
                last_err = e
                break
        raise RuntimeError(f"LLM request failed: {last_err}")

    def _openai_chat(self, system_message: str, user_message: str) -> str:
        api_key = getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        model = self._resolve_model("OPENAI_MODEL", "gpt-4o-mini")
        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message},
            ],
            "temperature": 0.1,
        }
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            data=json.dumps(data),
            timeout=self.timeout,
        )
        r.raise_for_status()
        payload = r.json()
        return payload["choices"][0]["message"]["content"]

    def _anthropic_chat(self, system_message: str, user_message: str) -> str:
        api_key = getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        model = self._resolve_model("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        data = {
            "model": model,
            "max_tokens": 1024,
            "system": system_message,
            "messages": [
                {"role": "user", "content": user_message},
            ],
        }
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            data=json.dumps(data),
            timeout=self.timeout,
        )
        r.raise_for_status()
        payload = r.json()
        content = payload.get("content", [])
        if content and isinstance(content, list) and "text" in content[0]:
            return content[0]["text"]
        return ""

    def _gemini_chat(self, system_message: str, user_message: str) -> str:
        api_key = getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is not set")
        model = self._resolve_model("GEMINI_MODEL", "gemini-1.5-pro")
        data = {
            "contents": [
                {"role": "user", "parts": [{"text": f"{system_message}\n\n{user_message}"}]}
            ]
        }
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        r = requests.post(url, headers={"Content-Type": "application/json"}, data=json.dumps(data), timeout=self.timeout)
        r.raise_for_status()
        payload = r.json()
        candidates = payload.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            if parts and "text" in parts[0]:
                return parts[0]["text"]
        return ""
