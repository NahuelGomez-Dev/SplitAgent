"""Textual TUI for SplitAgent, styled after the OpenCode interface."""

from __future__ import annotations

import json
from typing import Any

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Input,
    Label,
    Markdown,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from splitagent.config import (
    PROVIDER_PRESETS,
    GlobalConfig,
    ProjectConfig,
    save_global_config,
)
from splitagent.core.bus import Event, EventBus
from splitagent.core.context import SharedContext
from splitagent.core.engine import Engine
from splitagent.report.generator import build_markdown
from splitagent.ui import theme as t

MAX_BLOCKS = 500


class ConfigScreen(ModalScreen[GlobalConfig | None]):
    """Modal to configure the model API from inside the program."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel")]

    def __init__(self, config: GlobalConfig) -> None:
        super().__init__()
        self.config = config

    def compose(self) -> ComposeResult:
        provider_options = [(name, name) for name in PROVIDER_PRESETS]
        with Vertical(id="config-dialog"):
            yield Label("Model API configuration", id="config-title")
            yield Label("Provider", classes="field-label")
            yield Select(
                provider_options,
                value=self.config.llm.provider,
                allow_blank=False,
                id="provider",
            )
            yield Label("Base URL", classes="field-label")
            yield Input(value=self.config.llm.base_url, id="base_url")
            yield Label("API key", classes="field-label")
            yield Input(
                value=self.config.llm.api_key,
                password=True,
                placeholder="sk-...",
                id="api_key",
            )
            yield Label("Model", classes="field-label")
            yield Input(value=self.config.llm.model, id="model")
            yield Label("Temperature", classes="field-label")
            yield Input(value=str(self.config.llm.temperature), id="temperature")
            yield Static("", id="config-status")
            with Horizontal(id="config-buttons"):
                yield Button("Test", id="test", variant="default")
                yield Button("Save", id="save", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "provider" or not event.value:
            return
        preset = PROVIDER_PRESETS.get(str(event.value))
        if not preset:
            return
        self.query_one("#base_url", Input).value = preset["base_url"]
        self.query_one("#model", Input).value = preset["model"]

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        updated = self._collect()
        if event.button.id == "save":
            self.dismiss(updated)
            return
        if event.button.id == "test":
            status = self.query_one("#config-status", Static)
            status.update("Testing connection...")
            from splitagent.llm.client import LLMClient

            async with LLMClient(updated.llm) as client:
                ok, message = await client.test_connection()
            status.update(f"OK: {message}" if ok else f"Failed: {message}")

    def _collect(self) -> GlobalConfig:
        cfg = GlobalConfig(
            llm=type(self.config.llm)(**vars(self.config.llm)),
            ui=self.config.ui,
            sandbox=self.config.sandbox,
            authorized=self.config.authorized,
        )
        cfg.llm.provider = str(self.query_one("#provider", Select).value or "custom")
        cfg.llm.base_url = self.query_one("#base_url", Input).value.strip()
        cfg.llm.api_key = self.query_one("#api_key", Input).value.strip()
        cfg.llm.model = self.query_one("#model", Input).value.strip()
        try:
            cfg.llm.temperature = float(self.query_one("#temperature", Input).value or "0.2")
        except ValueError:
            cfg.llm.temperature = 0.2
        preset = PROVIDER_PRESETS.get(cfg.llm.provider)
        if preset:
            cfg.llm.protocol = preset.get("protocol", "openai")
        return cfg


class SplitAgentApp(App[None]):
    """The SplitAgent cockpit."""

    TITLE = "SplitAgent"
    SUB_TITLE = "autonomous dual-team security"
    CSS = f"""
    Screen {{ background: {t.BG}; color: {t.TEXT}; }}
    #topbar {{
        height: 3; padding: 0 1; background: {t.PANEL};
        border-bottom: solid {t.BORDER};
    }}
    #topbar-title {{ color: {t.PRIMARY}; text-style: bold; }}
    #topbar-meta {{ color: {t.MUTED}; }}
    #run-button {{ dock: right; margin: 0 1; min-width: 14; }}
    #body {{ height: 1fr; }}
    .agent-pane {{ width: 1fr; border: round {t.BORDER}; }}
    .agent-pane-title {{ padding: 0 1; background: {t.ELEMENT}; color: {t.TEXT}; }}
    #red-pane {{ border: round {t.RED}; }}
    #blue-pane {{ border: round {t.SECONDARY}; }}
    VerticalScroll {{ background: {t.BG}; }}
    #findings-table, #mitigations-table {{ background: {t.PANEL}; }}
    #report-view {{ background: {t.BG}; padding: 1 2; }}
    #config-dialog {{
        width: 70; height: auto; max-height: 90%;
        background: {t.PANEL}; border: thick {t.PRIMARY}; padding: 1 2;
        align: center middle;
    }}
    #config-title {{ color: {t.PRIMARY}; text-style: bold; padding-bottom: 1; }}
    .field-label {{ color: {t.MUTED}; padding-top: 1; }}
    #config-status {{ color: {t.CYAN}; padding-top: 1; min-height: 2; }}
    #config-buttons {{ height: 3; align-horizontal: right; padding-top: 1; }}
    #config-buttons Button {{ margin-left: 1; }}
    TabbedContent {{ background: {t.BG}; }}
    Tabs {{ background: {t.PANEL}; }}
    Tab {{ color: {t.MUTED}; }}
    Tab.-active {{ color: {t.PRIMARY}; text-style: bold; }}
    Footer {{ background: {t.PANEL}; color: {t.MUTED}; }}
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "run_audit", "Run"),
        Binding("c", "configure", "Configure"),
        Binding("e", "export", "Export"),
        Binding("s", "save_session", "Save"),
    ]

    def __init__(self, global_config: GlobalConfig, project: ProjectConfig) -> None:
        super().__init__()
        self.global_config = global_config
        self.project = project
        self.bus = EventBus()
        self.bus.subscribe(self._on_event)
        self.engine: Engine | None = None
        self.buffers: dict[str, list[str]] = {"red": [], "blue": []}
        self.findings: list[dict[str, Any]] = []
        self.mitigations: list[dict[str, Any]] = []
        self.logs: list[str] = []
        self.round = 0
        self.total_rounds = project.run.rounds
        self.phase = "idle"
        self.resilience = 0.0
        self.running = False
        self._session: SharedContext | None = None

    # -- layout ------------------------------------------------------------ #
    def compose(self) -> ComposeResult:
        with Horizontal(id="topbar"):
            yield Static("SPLITAGENT", id="topbar-title")
            yield Static("", id="topbar-meta")
            yield Button("> Run audit", id="run-button", variant="primary")
        with TabbedContent(id="body"):
            with TabPane("Stream", id="tab-stream"), Horizontal():
                with Vertical(id="red-pane", classes="agent-pane"):
                    yield Static("RED AGENT", classes="agent-pane-title")
                    with VerticalScroll(id="red-scroll"):
                        yield Static("", id="red-log")
                with Vertical(id="blue-pane", classes="agent-pane"):
                    yield Static("BLUE AGENT", classes="agent-pane-title")
                    with VerticalScroll(id="blue-scroll"):
                        yield Static("", id="blue-log")
            with TabPane("Findings", id="tab-findings"):
                yield DataTable(id="findings-table", zebra_stripes=True)
            with TabPane("Mitigations", id="tab-mitigations"):
                yield DataTable(id="mitigations-table", zebra_stripes=True)
            with TabPane("Report", id="tab-report"), VerticalScroll():
                yield Markdown("_Run an audit to generate the report._", id="report-view")
            with TabPane("Activity", id="tab-activity"), VerticalScroll():
                yield Static("", id="activity-log")
        yield Footer()

    def on_mount(self) -> None:
        findings = self.query_one("#findings-table", DataTable)
        findings.add_columns("ID", "Severity", "CVSS", "Title", "Status")
        mitigations = self.query_one("#mitigations-table", DataTable)
        mitigations.add_columns("ID", "Kind", "Finding", "Title", "Status")
        self._refresh_topbar()
        if not self.global_config.configured:
            self._prompt_config(first_run=True)

    # -- top bar ----------------------------------------------------------- #
    def _refresh_topbar(self) -> None:
        meta = (
            f"  target {self.project.target.url or 'n/a'}   "
            f"model {self.global_config.llm.provider}/{self.global_config.llm.model}   "
            f"round {self.round}/{self.total_rounds}   "
            f"phase {self.phase}   resilience {self.resilience}/100"
        )
        self.query_one("#topbar-meta", Static).update(meta)

    # -- actions ----------------------------------------------------------- #
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-button":
            self.action_run_audit()

    def action_run_audit(self) -> None:
        if self.running:
            self._log_line("A run is already in progress.")
            return
        if not self.global_config.configured:
            self._prompt_config(first_run=True)
            return
        self.running = True
        self._log_line("Starting audit...")
        self._run_engine()

    def action_configure(self) -> None:
        self._prompt_config()

    def _prompt_config(self, first_run: bool = False) -> None:
        def _apply(result: GlobalConfig | None) -> None:
            if result is None:
                return
            self.global_config = result
            path = save_global_config(result)
            self._log_line(f"Configuration saved to {path}")
            self._refresh_topbar()

        self.push_screen(ConfigScreen(self.global_config), _apply)

    def action_save_session(self) -> None:
        if self._session is not None:
            path = self._session.save()
            self._log_line(f"Session saved to {path}")
        else:
            self._log_line("Nothing to save yet.")

    def action_export(self) -> None:
        if self._session is None:
            self._log_line("Run an audit first.")
            return
        from pathlib import Path

        from splitagent.report.generator import write_reports

        paths = write_reports(
            self._session.state, self.project.report, Path(self.project.report.output_dir)
        )
        for path in paths:
            self._log_line(f"Report written: {path}")

    # -- engine worker ----------------------------------------------------- #
    @work(exclusive=True)
    async def _run_engine(self) -> None:
        try:
            self.engine = Engine(self.global_config, self.project, bus=self.bus)
            self._session = await self.engine.run()
            self._log_line("Audit complete.")
            markdown = build_markdown(self._session.state, self.project.report)
            self.query_one("#report-view", Markdown).update(markdown)
        except Exception as exc:
            self._log_line(f"Run failed: {type(exc).__name__}: {exc}")
        finally:
            self.running = False
            self.phase = "done"
            self._refresh_topbar()

    # -- event bus --------------------------------------------------------- #
    def _on_event(self, event: Event) -> None:
        etype = event.type
        if etype == "session.start":
            self.project.target.url = self.project.target.url or event.data.get("target", "")
            self.total_rounds = event.data.get("rounds", self.total_rounds)
            self.phase = "starting"
        elif etype == "round.start":
            self.round = event.data.get("round", self.round)
            self.phase = "round"
        elif etype == "phase.start":
            self.phase = event.data.get("phase", self.phase)
            self._append(event.agent, f"\n-- {event.agent.upper()} - {self.phase} --\n")
        elif etype == "agent.text":
            self._append(event.agent, event.data.get("text", ""))
        elif etype == "agent.tool_call":
            args = json.dumps(event.data.get("arguments", {}), ensure_ascii=False)
            self._append(event.agent, f"\n* {event.data.get('tool')}({args[:180]})\n")
        elif etype == "agent.tool_result":
            output = str(event.data.get("output", "")).replace("\n", " ")
            self._append(event.agent, f"  ~ {output[:200]}\n")
        elif etype == "finding":
            self.findings.append(event.data)
            self._add_finding_row(event.data)
        elif etype == "mitigation":
            self.mitigations.append(event.data)
            self._add_mitigation_row(event.data)
        elif etype == "round.end":
            self.resilience = float(event.data.get("resilience", self.resilience))
        elif etype == "log":
            self._log_line(event.data.get("text", ""))
        elif etype == "error":
            self._log_line(f"error: {event.data.get('text', '')}")
        elif etype == "session.end":
            self.phase = "done"
            self.resilience = float(event.data.get("resilience", self.resilience))
        self._refresh_topbar()

    # -- widget helpers ---------------------------------------------------- #
    def _append(self, agent: str, text: str) -> None:
        buffer = self.buffers.setdefault(agent, [])
        buffer.append(text)
        if len(buffer) > MAX_BLOCKS:
            del buffer[: len(buffer) - MAX_BLOCKS]
        widget_id = "#red-log" if agent == "red" else "#blue-log"
        scroll_id = "#red-scroll" if agent == "red" else "#blue-scroll"
        try:
            self.query_one(widget_id, Static).update("".join(buffer))
            self.query_one(scroll_id, VerticalScroll).scroll_end(animate=False)
        except Exception:  # pragma: no cover - widget not mounted yet
            pass

    def _log_line(self, message: str) -> None:
        self.logs.append(message)
        try:
            self.query_one("#activity-log", Static).update("\n".join(self.logs[-300:]))
        except Exception:  # pragma: no cover
            pass

    def _add_finding_row(self, data: dict[str, Any]) -> None:
        try:
            table = self.query_one("#findings-table", DataTable)
            table.add_row(
                data.get("id", ""),
                data.get("severity", "").upper(),
                f"{data.get('cvss_score', 0):.1f}",
                data.get("title", ""),
                "open",
                key=data.get("id"),
            )
        except Exception:  # pragma: no cover
            pass

    def _add_mitigation_row(self, data: dict[str, Any]) -> None:
        try:
            table = self.query_one("#mitigations-table", DataTable)
            table.add_row(
                data.get("id", ""),
                data.get("kind", ""),
                data.get("finding_id", ""),
                data.get("title", ""),
                "proposed",
                key=data.get("id"),
            )
        except Exception:  # pragma: no cover
            pass
