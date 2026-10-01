from __future__ import annotations

from splitagent.config import (
    GlobalConfig,
    LLMSettings,
    ProjectConfig,
    apply_provider_preset,
    load_global_config,
    load_project_config,
    save_global_config,
    save_project_config,
)


def test_global_roundtrip(tmp_path):
    path = tmp_path / "config.yaml"
    config = GlobalConfig(llm=LLMSettings(provider="groq", api_key="secret", model="m"))
    save_global_config(config, path)
    loaded = load_global_config(path)
    assert loaded.llm.provider == "groq"
    assert loaded.llm.api_key == "secret"
    assert loaded.llm.model == "m"


def test_redacted_hides_key():
    config = GlobalConfig(llm=LLMSettings(api_key="super-secret"))
    assert config.llm.redacted()["api_key"] == "***"


def test_apply_preset():
    llm = LLMSettings()
    apply_provider_preset(llm, "deepseek")
    assert llm.base_url == "https://api.deepseek.com/v1"
    assert llm.protocol == "openai"


def test_apply_anthropic_preset():
    llm = LLMSettings()
    apply_provider_preset(llm, "anthropic")
    assert llm.protocol == "anthropic"


def test_project_roundtrip(tmp_path):
    path = tmp_path / "splitagent.yaml"
    project = ProjectConfig()
    project.target.url = "http://localhost:3000"
    project.run.rounds = 4
    project.run.sandbox.enabled = False
    save_project_config(project, path)
    loaded = load_project_config(path)
    assert loaded.target.url == "http://localhost:3000"
    assert loaded.run.rounds == 4
    assert loaded.run.sandbox.enabled is False


def test_env_api_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "from-env")
    llm = LLMSettings(provider="openai")
    assert llm.resolved_api_key() == "from-env"
