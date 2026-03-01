import json

from app import codex


def test_parse_model_listing_includes_codex_variants_from_json():
    payload = json.dumps(
        {
            "data": [
                {"id": "gpt-5.1-codex-max", "deployment": "codex"},
                {"id": "gpt-5.1-codex-mini", "deployments": ["codex"]},
                {"id": "gpt-5.2", "deployment": "default"},
                {"id": "o4-mini", "deployment": "default"},
            ]
        }
    )

    models = codex._parse_model_listing(payload)

    assert "gpt-5.1-codex-max" in models
    assert "gpt-5.1-codex-mini" in models
    assert "gpt-5.2" in models
    assert "o4-mini" in models
    assert "o4-mini-codex" not in models


def test_parse_model_listing_infers_codex_from_plaintext():
    raw = """
    Available models:
      gpt-5.1-codex-max codex
      gpt-5.1-codex-mini codex
      o4-mini default
    """

    models = codex._parse_model_listing(raw)

    assert "gpt-5.1-codex-max" in models
    assert "gpt-5.1-codex-mini" in models
    assert "o4-mini-codex" not in models
