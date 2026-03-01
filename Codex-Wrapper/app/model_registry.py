"""Utility helpers for discovering and caching Codex models."""

import logging
import os
from typing import Dict, List, Optional, Tuple

from .codex import (
    CodexError,
    apply_codex_profile_overrides,
    builtin_reasoning_aliases,
    list_codex_models,
    DEFAULT_CODEX_MODEL,
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL = DEFAULT_CODEX_MODEL
_AVAILABLE_MODELS: List[str] = [DEFAULT_MODEL]
_LAST_ERROR: Optional[str] = None
_REASONING_ALIAS_MAP: Dict[str, Tuple[str, ...]] = {}
_WARNED_LEGACY_ENV = False

REASONING_EFFORT_SUFFIXES = ("low", "medium", "high", "xhigh")


def _augment_models(models: List[str]) -> List[str]:
    """Add known aliases (e.g., strip -codex) and remove duplicates."""

    augmented: list[str] = []
    seen = set()
    for model in models:
        if model and model not in seen:
            augmented.append(model)
            seen.add(model)
        if model.endswith('-codex'):
            base = model[:-6]
            if base and base not in seen:
                augmented.append(base)
                seen.add(base)
    return augmented


def _default_reasoning_aliases_for_model(model: str) -> Optional[Tuple[str, ...]]:
    """Return default reasoning effort aliases for well-known model families."""

    if model.startswith("gpt-5"):
        return tuple(REASONING_EFFORT_SUFFIXES)
    return None


def _merge_default_reasoning_aliases(
    models: List[str], alias_map: Dict[str, Tuple[str, ...]]
) -> Dict[str, Tuple[str, ...]]:
    """Ensure models that support reasoning expose aliases even when presets omit them."""

    merged: Dict[str, Tuple[str, ...]] = {k: tuple(v) for k, v in alias_map.items() if v}
    for model in models:
        if model in merged:
            continue
        defaults = _default_reasoning_aliases_for_model(model)
        if defaults:
            merged[model] = defaults
    return merged


async def initialize_model_registry() -> List[str]:
    """Populate the available model list based on Codex CLI presets."""

    global _AVAILABLE_MODELS, _LAST_ERROR, _REASONING_ALIAS_MAP

    _warn_if_legacy_env_present()
    apply_codex_profile_overrides()

    try:
        models = await list_codex_models()
        if not models:
            raise CodexError("Codex CLI returned an empty model list")
        _AVAILABLE_MODELS = _augment_models(models)
        alias_map = _merge_default_reasoning_aliases(_AVAILABLE_MODELS, builtin_reasoning_aliases())
        _REASONING_ALIAS_MAP = {
            model: tuple(efforts)
            for model, efforts in alias_map.items()
            if efforts and model in _AVAILABLE_MODELS
        }
        if not _REASONING_ALIAS_MAP and "gpt-5" in _AVAILABLE_MODELS:
            _REASONING_ALIAS_MAP = {"gpt-5": tuple(REASONING_EFFORT_SUFFIXES)}
        _LAST_ERROR = None
        logger.info("Loaded %d Codex model(s): %s", len(models), ", ".join(models))
    except Exception as exc:  # pragma: no cover - startup failure path
        _LAST_ERROR = str(exc)
        logger.warning(
            "Falling back to default model list because Codex model discovery failed: %s",
            exc,
        )
        fallback_models = [DEFAULT_MODEL, "gpt-5.1", "gpt-5"]
        _AVAILABLE_MODELS = _augment_models(fallback_models)
        fallback_aliases = {
            "gpt-5": tuple(REASONING_EFFORT_SUFFIXES),
            DEFAULT_MODEL: tuple(REASONING_EFFORT_SUFFIXES),
        }
        _REASONING_ALIAS_MAP = _merge_default_reasoning_aliases(_AVAILABLE_MODELS, fallback_aliases)
    return list(_AVAILABLE_MODELS)


def get_available_models(include_reasoning_aliases: bool = False) -> List[str]:
    """Return a copy of the currently cached model list."""

    models = list(_AVAILABLE_MODELS)
    if include_reasoning_aliases and _AVAILABLE_MODELS:
        for base, suffixes in _REASONING_ALIAS_MAP.items():
            if base not in models:
                continue
            models.extend(f"{base} {suffix}" for suffix in suffixes)
    # Preserve ordering while removing duplicates
    return list(dict.fromkeys(models))


def get_default_model() -> str:
    """Return the default model name used when clients omit `model`."""

    return _AVAILABLE_MODELS[0] if _AVAILABLE_MODELS else DEFAULT_MODEL


def choose_model(requested: Optional[str]) -> Tuple[str, Optional[str]]:
    """Validate the requested model name and return the model plus optional reasoning effort."""

    if requested:
        base_model, effort = _split_model_and_effort(requested)
        if base_model in _AVAILABLE_MODELS:
            return base_model, effort
        available = ", ".join(get_available_models(include_reasoning_aliases=True))
        raise ValueError(
            f"Model '{requested}' is not available. Choose one of: {available or 'none'}"
        )
    return get_default_model(), None


def get_last_error() -> Optional[str]:
    """Return the most recent discovery error message (if any)."""

    return _LAST_ERROR


def _split_model_and_effort(raw: str) -> Tuple[str, Optional[str]]:
    normalized = " ".join(raw.split()) if raw else ""
    if not normalized:
        return normalized, None
    if " " in normalized:
        base, suffix = normalized.rsplit(" ", 1)
        suffix_lower = suffix.lower()
        supported_suffixes = _REASONING_ALIAS_MAP.get(base)
        if base and suffix_lower in REASONING_EFFORT_SUFFIXES:
            if supported_suffixes and suffix_lower in supported_suffixes:
                return base, suffix_lower
            defaults = _default_reasoning_aliases_for_model(base)
            if defaults and suffix_lower in defaults:
                return base, suffix_lower
    return normalized, None


def _warn_if_legacy_env_present() -> None:
    global _WARNED_LEGACY_ENV
    if _WARNED_LEGACY_ENV:
        return

    legacy_value = os.getenv("CODEX_MODEL")
    if legacy_value:
        logger.warning(
            "Environment variable CODEX_MODEL is deprecated and ignored. Detected value: %s",
            legacy_value,
        )
    _WARNED_LEGACY_ENV = True
