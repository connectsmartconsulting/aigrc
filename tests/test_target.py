"""Unit tests for the target factory (build_target)."""

import pytest

from aigrc.core import build_target
from aigrc.core.target import MockTarget, OpenAICompatibleTarget


def test_build_target_mock_scheme():
    t = build_target("mock://strict", model="mock")
    assert isinstance(t, MockTarget)


def test_build_target_offline_forces_mock():
    t = build_target("anything", model="mock", offline=True)
    assert isinstance(t, MockTarget)


def test_build_target_openai_scheme_extracts_model():
    t = build_target("openai://gpt-4o", model="ignored-default")
    assert isinstance(t, OpenAICompatibleTarget)
    assert t.model == "gpt-4o"
    assert "openai://" not in t.url
    assert t.url.startswith("http")


def test_build_target_openai_scheme_falls_back_to_model_flag():
    t = build_target("openai://", model="gpt-4o-mini")
    assert isinstance(t, OpenAICompatibleTarget)
    assert t.model == "gpt-4o-mini"


def test_build_target_openai_scheme_requires_a_model():
    with pytest.raises(ValueError):
        build_target("openai://", model="")


def test_build_target_raw_url_passthrough():
    t = build_target("https://my-gateway.example/v1/chat/completions", model="local")
    assert isinstance(t, OpenAICompatibleTarget)
    assert t.url == "https://my-gateway.example/v1/chat/completions"
    assert t.model == "local"


def test_build_target_openai_base_url_override(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "https://proxy.internal/v1/chat/completions")
    t = build_target("openai://gpt-4o", model="x")
    assert t.url == "https://proxy.internal/v1/chat/completions"
