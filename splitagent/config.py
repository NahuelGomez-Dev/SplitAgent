"""Configuration handling for SplitAgent.

Two layers of configuration exist:

* **Global** (``~/.splitagent/config.yaml`` on POSIX, ``%APPDATA%/splitagent``
  on Windows) stores the LLM provider/API credentials together with UI and
  default sandbox preferences. This is what the user edits from inside the
  program with ``splitagent config``.
* **Project** (``splitagent.yaml`` in the working directory) describes the
  target, the number of Red/Blue rounds and the report preferences.

Only the global layer holds secrets. Project files are safe to commit.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

from splitagent.errors import ConfigError

APP_NAME = "splitagent"
GLOBAL_ENV = "SPLITAGENT_HOME"


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
def config_home() -> Path:
    """Return the directory holding global SplitAgent state."""
    override = os.environ.get(GLOBAL_ENV)
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / APP_NAME
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP_NAME


def global_config_path() -> Path:
    return config_home() / "config.yaml"


def global_key_path() -> Path:
    return config_home() / "key.bin"


def sessions_dir() -> Path:
    return config_home() / "sessions"


def ensure_home() -> Path:
    home = config_home()
    home.mkdir(parents=True, exist_ok=True)
    sessions_dir().mkdir(parents=True, exist_ok=True)
    return home


def project_config_path(start: Path | None = None) -> Path:
    start = (start or Path.cwd()).resolve()
    for candidate_dir in [start, *start.parents]:
        candidate = candidate_dir / "splitagent.yaml"
        if candidate.exists():
            return candidate
        candidate = candidate_dir / "splitagent.yml"
        if candidate.exists():
            return candidate
    return start / "splitagent.yaml"


# --------------------------------------------------------------------------- #
# Provider presets
# --------------------------------------------------------------------------- #
PROVIDER_PRESETS: dict[str, dict[str, str]] = {
    "openai": {
        "protocol": "openai",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
    },
    "opencode-go": {
        "protocol": "openai",
        "base_url": "https://opencode.ai/zen/go/v1",
        "model": "deepseek-v4.1-flash",
    },
    "opencode": {
        "protocol": "openai",
        "base_url": "https://opencode.ai/zen/v1",
        "model": "deepseek-v4-flash",
    },
    "openrouter": {
        "protocol": "openai",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "anthropic/claude-3.5-sonnet",
    },
    "anthropic": {
        "protocol": "anthropic",
        "base_url": "https://api.anthropic.com/v1",
        "model": "claude-3-5-sonnet-latest",
    },
    "groq": {
        "protocol": "openai",
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
    },
    "deepseek": {
        "protocol": "openai",
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
    },
    "together": {
        "protocol": "openai",
        "base_url": "https://api.together.xyz/v1",
        "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    },
    "mistral": {
        "protocol": "openai",
        "base_url": "https://api.mistral.ai/v1",
        "model": "mistral-large-latest",
    },
    "xai": {
        "protocol": "openai",
        "base_url": "https://api.x.ai/v1",
        "model": "grok-2-latest",
    },
    "ollama": {
        "protocol": "openai",
        "base_url": "http://localhost:11434/v1",
        "model": "llama3.1",
    },
    "lmstudio": {
        "protocol": "openai",
        "base_url": "http://localhost:1234/v1",
        "model": "local-model",
    },
    "vllm": {
        "protocol": "openai",
        "base_url": "http://localhost:8000/v1",
        "model": "local-model",
    },
    "custom": {
        "protocol": "openai",
        "base_url": "http://localhost:8000/v1",
        "model": "custom-model",
    },
}

# Local / self-hosted providers that legitimately run without an API key.
KEYLESS_PROVIDERS = frozenset({"ollama", "lmstudio", "vllm", "custom"})

API_KEY_ENV = {
    "openai": ("OPENAI_API_KEY",),
    "opencode-go": ("OPENCODE_API_KEY", "OPENCODE_GO_API_KEY"),
    "opencode": ("OPENCODE_API_KEY",),
    "openrouter": ("OPENROUTER_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "groq": ("GROQ_API_KEY",),
    "deepseek": ("DEEPSEEK_API_KEY",),
    "together": ("TOGETHER_API_KEY",),
    "mistral": ("MISTRAL_API_KEY",),
    "xai": ("XAI_API_KEY",),
    "custom": ("SPLITAGENT_API_KEY",),
}


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #
@dataclass
class LLMSettings:
    """Credentials and behaviour for the model API used by both agents."""

    provider: str = "openai"
    protocol: str = "openai"  # openai | anthropic
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout: int = 120
    stream: bool = True
    # Transient-failure handling. 0 retries disables the retry loop.
    max_retries: int = 3
    retry_initial_delay: float = 1.0
    retry_max_delay: float = 30.0
    session_id: str = ""
    user_agent: str = ""
    # Prompt caching: reuse the stable prefix instead of paying for it every
    # turn. Anthropic/Bedrock/OpenRouter take an explicit marker; OpenAI and
    # OpenAI-compatible gateways cache automatically when the prefix is stable.
    prompt_cache: bool = True
    cache_system_messages: int = 2
    cache_tail_messages: int = 2
    extra_headers: dict[str, str] = field(default_factory=dict)

    def resolved_api_key(self) -> str:
        if self.api_key:
            return self.api_key
        for env_name in (
            *API_KEY_ENV.get(self.provider, ()),
            "SPLITAGENT_API_KEY",
            "LLM_API_KEY",
        ):
            value = os.environ.get(env_name)
            if value:
                return value
        return ""

    def redacted(self) -> dict[str, Any]:
        data = asdict(self)
        if data.get("api_key"):
            data["api_key"] = "***"
        return data


@dataclass
class ModelSpec:
    """Context/output limits for a model, used by the context manager."""

    context: int = 128_000
    output: int = 32_000

    def to_dict(self) -> dict[str, int]:
        return {"context": self.context, "output": self.output}


# Known limits; anything else falls back to a conservative default.
KNOWN_MODEL_LIMITS: dict[str, dict[str, int]] = {
    "deepseek-v4.1-flash": {"context": 1_000_000, "output": 384_000},
    "deepseek-v4-pro": {"context": 1_000_000, "output": 384_000},
    "deepseek-v4-flash": {"context": 1_000_000, "output": 384_000},
    "deepseek-v4-flash-vision-exp": {"context": 1_000_000, "output": 384_000},
    "deepseek-chat": {"context": 128_000, "output": 8_192},
    "gpt-4o": {"context": 128_000, "output": 16_384},
    "gpt-4o-mini": {"context": 128_000, "output": 16_384},
    "claude-3-5-sonnet-latest": {"context": 200_000, "output": 8_192},
    "llama3.1": {"context": 128_000, "output": 8_192},
    "llama-3.3-70b-versatile": {"context": 128_000, "output": 32_768},
}


def model_spec(model_id: str) -> ModelSpec:
    limits = KNOWN_MODEL_LIMITS.get(model_id)
    if limits:
        return ModelSpec(context=limits["context"], output=limits["output"])
    lowered = model_id.lower()
    if "flash" in lowered or "mini" in lowered:
        return ModelSpec(context=128_000, output=16_384)
    if "pro" in lowered or "sonnet" in lowered:
        return ModelSpec(context=200_000, output=32_000)
    return ModelSpec()


@dataclass
class ProviderConfig:
    """A configured (connected) provider and its model visibility."""

    id: str = ""
    base_url: str = ""
    protocol: str = "openai"
    api_key: str = ""
    enabled: bool = True
    models: dict[str, str] = field(default_factory=dict)  # model id -> display name
    hidden: list[str] = field(default_factory=list)  # model ids toggled off
    limits: dict[str, dict[str, int]] = field(default_factory=dict)  # model -> spec

    def display_name(self, model_id: str) -> str:
        return self.models.get(model_id, model_id)

    def spec(self, model_id: str) -> ModelSpec:
        """Context/output limits for a model served by this provider."""
        limits = self.limits.get(model_id)
        if limits:
            return ModelSpec(
                context=int(limits.get("context", 128_000)),
                output=int(limits.get("output", 32_000)),
            )
        return model_spec(model_id)

    def visible(self, model_id: str) -> bool:
        return self.enabled and model_id not in self.hidden

    def redacted(self) -> dict[str, Any]:
        data = asdict(self)
        if data.get("api_key"):
            data["api_key"] = "***"
        return data


@dataclass
class UISettings:
    theme: str = "opencode"
    show_thinking: bool = True
    refresh_per_second: int = 12
    # Counter shown on the dashboard. It no longer drives an interface
    # heuristic: there is a single interface.
    audits_completed: int = 0


@dataclass
class SandboxDefaults:
    engine: str = "docker"
    image: str = "bkimminich/juice-shop:latest"
    network: str = "splitagent-net"
    auto_remove: bool = True


@dataclass
class GlobalConfig:
    llm: LLMSettings = field(default_factory=LLMSettings)
    ui: UISettings = field(default_factory=UISettings)
    sandbox: SandboxDefaults = field(default_factory=SandboxDefaults)
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    authorized: bool = False  # the user accepted the responsible-use notice

    @property
    def configured(self) -> bool:
        has_key = bool(self.llm.resolved_api_key()) or self.llm.provider in KEYLESS_PROVIDERS
        return bool(self.llm.model and self.llm.base_url and has_key)


@dataclass
class TargetConfig:
    kind: str = "web"
    url: str = ""
    hosts: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    def effective_hosts(self) -> list[str]:
        hosts = list(self.hosts)
        if self.url:
            try:
                from urllib.parse import urlparse

                host = urlparse(self.url).hostname
                if host and host not in hosts:
                    hosts.append(host)
            except ValueError:
                pass
        return hosts


@dataclass
class SandboxConfig:
    enabled: bool = True
    engine: str = "docker"
    image: str = "bkimminich/juice-shop:latest"
    network: str = "splitagent-net"
    port_map: dict[str, int] = field(default_factory=dict)
    auto_remove: bool = True


@dataclass
class AuthConfig:
    """Optional credentials handed to the agents for authenticated testing."""

    username: str = ""
    password: str = ""
    token: str = ""
    cookies: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def as_headers(self) -> dict[str, str]:
        headers = dict(self.headers or {})
        if self.token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.cookies:
            headers["Cookie"] = self.cookies
        return headers

    def describe(self) -> str:
        parts: list[str] = []
        if self.username:
            parts.append(f"username={self.username}")
            parts.append("password=(provided)")
        if self.token:
            parts.append("bearer token (provided)")
        if self.cookies:
            parts.append("cookies (provided)")
        if self.headers:
            parts.append("custom headers: " + ", ".join(sorted(self.headers)))
        return ", ".join(parts) if parts else "(none)"

    def redacted(self) -> dict[str, Any]:
        """A copy safe to hand to the renderer: secrets are masked."""
        data = asdict(self)
        for key in ("password", "token", "cookies"):
            if data.get(key):
                data[key] = "***"
        data["headers"] = dict.fromkeys(self.headers or {}, "***")
        data["has_password"] = bool(self.password)
        data["has_token"] = bool(self.token)
        data["has_cookies"] = bool(self.cookies)
        return data


@dataclass
class ExecutionConfig:
    """Where the agents install and run their tooling.

    ``toolbox`` runs everything inside a disposable Docker container that has
    the security toolset preinstalled, so the host is never modified. ``local``
    runs on the host (the legacy behaviour). ``auto`` prefers the toolbox and
    falls back to local when Docker is unavailable.
    """

    mode: str = "auto"  # auto | toolbox | local
    edition: str = "standard"  # standard | kali
    image: str = "splitagent-toolbox:latest"
    container: str = "splitagent-toolbox"
    network: str = "splitagent-net"
    network_mode: str = "bridge"  # bridge | host
    auto_start: bool = True  # start Docker Desktop / the container silently
    installed: bool = False  # the operator approved building the image once
    allow_install: bool = True  # allow pip/apt/go installs inside the toolbox
    cpus: str = ""
    memory: str = ""
    keep_alive_minutes: int = 120


@dataclass
class CompactionConfig:
    """Context-window management, mirroring OpenCode's ``compaction`` block."""

    auto: bool = True
    prune: bool = True
    # Per-request reduction: drop settled reasoning, blank superseded snapshots.
    optimize: bool = True
    # Reasoning turns to keep in full; older ones are thought, not context.
    keep_reasoning_steps: int = 1
    reserved: int | None = None
    preserve_recent_tokens: int | None = None
    tail_turns: int | None = None


@dataclass
class RunConfig:
    rounds: int = 3
    max_steps: int = 12
    safe_mode: bool = True
    allow_network: bool = False
    # Independent tool calls inside one step run concurrently, bounded by this.
    tool_concurrency: int = 4
    # Hard ceiling for the whole session. 0 disables the deadline.
    max_duration_minutes: int = 90
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    compaction: CompactionConfig = field(default_factory=CompactionConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)


@dataclass
class AgentSettings:
    enabled: bool = True
    temperature: float | None = None
    # Steps reserved at the end of a turn for persisting findings and
    # summarising. 0 disables the forced wrap-up.
    wrap_up_at: int = 3


@dataclass
class AgentsConfig:
    red: AgentSettings = field(default_factory=AgentSettings)
    blue: AgentSettings = field(default_factory=AgentSettings)


@dataclass
class ReportSettings:
    formats: list[str] = field(default_factory=lambda: ["markdown", "html", "json"])
    output_dir: str = "reports"
    include_patches: bool = True
    include_evidence: bool = True


@dataclass
class WorkspaceConfig:
    """The agent's own working directory: tools, notes and recon data."""

    path: str = ""  # empty -> <project>/splitagent-workspace
    allow_install: bool = True  # let the agents install tooling
    allow_external_tools: bool = True  # allow tools outside the workspace
    max_install_seconds: int = 900
    instructions: str = ""  # inline operator guidance
    instruction_files: list[str] = field(default_factory=list)


@dataclass
class ProjectConfig:
    name: str = "splitagent"
    target: TargetConfig = field(default_factory=TargetConfig)
    run: RunConfig = field(default_factory=RunConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    workspace: WorkspaceConfig = field(default_factory=WorkspaceConfig)
    agents: AgentsConfig = field(default_factory=AgentsConfig)
    report: ReportSettings = field(default_factory=ReportSettings)


# --------------------------------------------------------------------------- #
# (De)serialisation helpers
# --------------------------------------------------------------------------- #
def _dataclass_from_dict(cls: type, data: dict[str, Any]) -> Any:
    if not isinstance(data, dict):
        return cls()
    kwargs: dict[str, Any] = {}
    known = {f.name: f for f in fields(cls)}
    for name, spec in known.items():
        if name not in data:
            continue
        value = data[name]
        type_name = getattr(spec.type, "__name__", str(spec.type))
        if type_name == "LLMSettings":
            kwargs[name] = _dataclass_from_dict(LLMSettings, value)
        elif type_name == "UISettings":
            kwargs[name] = _dataclass_from_dict(UISettings, value)
        elif type_name == "SandboxDefaults":
            kwargs[name] = _dataclass_from_dict(SandboxDefaults, value)
        elif type_name == "TargetConfig":
            kwargs[name] = _dataclass_from_dict(TargetConfig, value)
        elif type_name == "RunConfig":
            kwargs[name] = _dataclass_from_dict(RunConfig, value)
        elif type_name == "AuthConfig":
            kwargs[name] = _dataclass_from_dict(AuthConfig, value)
        elif type_name == "WorkspaceConfig":
            kwargs[name] = _dataclass_from_dict(WorkspaceConfig, value)
        elif type_name == "SandboxConfig":
            kwargs[name] = _dataclass_from_dict(SandboxConfig, value)
        elif type_name == "CompactionConfig":
            kwargs[name] = _dataclass_from_dict(CompactionConfig, value)
        elif type_name == "ExecutionConfig":
            kwargs[name] = _dataclass_from_dict(ExecutionConfig, value)
        elif type_name == "AgentsConfig":
            kwargs[name] = _dataclass_from_dict(AgentsConfig, value)
        elif type_name == "AgentSettings":
            kwargs[name] = _dataclass_from_dict(AgentSettings, value)
        elif type_name == "ReportSettings":
            kwargs[name] = _dataclass_from_dict(ReportSettings, value)
        else:
            kwargs[name] = value
    return cls(**kwargs)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:  # pragma: no cover - passthrough message
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"Top level of {path} must be a mapping")
    return raw


# --------------------------------------------------------------------------- #
# Global config
# --------------------------------------------------------------------------- #
def load_global_config(path: Path | None = None) -> GlobalConfig:
    path = path or global_config_path()
    data = _load_yaml(path)
    cfg = _dataclass_from_dict(GlobalConfig, data)
    if cfg.llm.provider in PROVIDER_PRESETS and not data.get("llm", {}).get("base_url"):
        preset = PROVIDER_PRESETS[cfg.llm.provider]
        cfg.llm.base_url = preset["base_url"]
        cfg.llm.protocol = preset.get("protocol", "openai")

    raw_providers = data.get("providers")
    cfg.providers = {}
    if isinstance(raw_providers, dict):
        for provider_id, payload in raw_providers.items():
            if not isinstance(payload, dict):
                continue
            provider = _dataclass_from_dict(ProviderConfig, payload)
            provider.id = provider.id or str(provider_id)
            cfg.providers[provider.id] = provider

    # Migrate a legacy single-key config into the providers map.
    if not cfg.providers and cfg.llm.api_key:
        preset = PROVIDER_PRESETS.get(cfg.llm.provider, {})
        cfg.providers[cfg.llm.provider] = ProviderConfig(
            id=cfg.llm.provider,
            base_url=cfg.llm.base_url,
            protocol=cfg.llm.protocol or preset.get("protocol", "openai"),
            api_key=cfg.llm.api_key,
            enabled=True,
        )
    return cfg


def ensure_provider(config: GlobalConfig, provider_id: str) -> ProviderConfig:
    """Return the provider config, creating a preset-based one if missing."""
    if provider_id not in config.providers:
        preset = PROVIDER_PRESETS.get(provider_id, {})
        config.providers[provider_id] = ProviderConfig(
            id=provider_id,
            base_url=preset.get("base_url", config.llm.base_url),
            protocol=preset.get("protocol", "openai"),
        )
    return config.providers[provider_id]


def provider_visible(config: GlobalConfig, provider_id: str, model_id: str) -> bool:
    provider = config.providers.get(provider_id)
    if provider is None:
        return False
    return provider.visible(model_id)


def settings_for_provider(config: GlobalConfig, provider_id: str, model: str) -> LLMSettings:
    """Build LLM settings for a specific provider/model selection."""
    settings = LLMSettings(**vars(config.llm))
    provider = config.providers.get(provider_id)
    preset = PROVIDER_PRESETS.get(provider_id, {})
    settings.provider = provider_id
    settings.model = model or settings.model
    if provider is not None:
        settings.base_url = provider.base_url or settings.base_url
        settings.protocol = provider.protocol or preset.get("protocol", "openai")
        settings.api_key = provider.api_key
    else:
        settings.base_url = preset.get("base_url", settings.base_url)
        settings.protocol = preset.get("protocol", "openai")
    return settings


def save_global_config(cfg: GlobalConfig, path: Path | None = None) -> Path:
    path = path or global_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = asdict(cfg)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - best effort on Windows
        pass
    return path


# --------------------------------------------------------------------------- #
# Project config
# --------------------------------------------------------------------------- #
def load_project_config(path: Path | None = None) -> ProjectConfig:
    path = path or project_config_path()
    data = _load_yaml(path)
    raw_project = data.get("project")
    project_block: dict[str, Any] = raw_project if isinstance(raw_project, dict) else {}
    kwargs: dict[str, Any] = {}
    if project_block.get("name"):
        kwargs["name"] = project_block["name"]
    if "target" in data:
        kwargs["target"] = _dataclass_from_dict(TargetConfig, data["target"])
    if "run" in data:
        kwargs["run"] = _dataclass_from_dict(RunConfig, data["run"])
    if "auth" in data:
        kwargs["auth"] = _dataclass_from_dict(AuthConfig, data["auth"])
    if "workspace" in data:
        kwargs["workspace"] = _dataclass_from_dict(WorkspaceConfig, data["workspace"])
    if "agents" in data:
        kwargs["agents"] = _dataclass_from_dict(AgentsConfig, data["agents"])
    if "report" in data:
        kwargs["report"] = _dataclass_from_dict(ReportSettings, data["report"])
    return ProjectConfig(**kwargs)


def save_project_config(cfg: ProjectConfig, path: Path | None = None) -> Path:
    path = path or Path.cwd() / "splitagent.yaml"
    data = {
        "project": {"name": cfg.name},
        "target": asdict(cfg.target),
        "run": asdict(cfg.run),
        "auth": asdict(cfg.auth),
        "workspace": asdict(cfg.workspace),
        "agents": asdict(cfg.agents),
        "report": asdict(cfg.report),
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def default_project_config() -> ProjectConfig:
    return ProjectConfig()


def apply_provider_preset(llm: LLMSettings, provider: str) -> LLMSettings:
    """Update the LLM settings in place from a provider preset."""
    preset = PROVIDER_PRESETS.get(provider)
    if not preset:
        raise ConfigError(f"Unknown provider '{provider}'. Known: {', '.join(PROVIDER_PRESETS)}")
    llm.provider = provider
    llm.protocol = preset.get("protocol", "openai")
    llm.base_url = preset["base_url"]
    if not llm.model or llm.model == LLMSettings().model:
        llm.model = preset["model"]
    return llm
