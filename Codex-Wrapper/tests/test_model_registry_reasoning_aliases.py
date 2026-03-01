from app import model_registry


def test_gpt51_models_expose_reasoning_aliases(monkeypatch):
    available = ["gpt-5.1", "o4-mini"]
    monkeypatch.setattr(model_registry, "_AVAILABLE_MODELS", available)
    merged = model_registry._merge_default_reasoning_aliases(
        available, {"o4-mini": ("low",)}
    )
    monkeypatch.setattr(model_registry, "_REASONING_ALIAS_MAP", merged)

    models = model_registry.get_available_models(include_reasoning_aliases=True)

    assert "gpt-5.1 low" in models
    assert "gpt-5.1 high" in models
    assert "gpt-5.1 xhigh" in models
    assert "o4-mini low" in models


def test_choose_model_accepts_gpt51_reasoning_suffix(monkeypatch):
    available = ["gpt-5.1"]
    monkeypatch.setattr(model_registry, "_AVAILABLE_MODELS", available)
    merged = model_registry._merge_default_reasoning_aliases(available, {})
    monkeypatch.setattr(model_registry, "_REASONING_ALIAS_MAP", merged)

    model, effort = model_registry.choose_model("gpt-5.1 low")

    assert model == "gpt-5.1"
    assert effort == "low"
