"""Command line interface for SplitAgent."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from splitagent import __version__
from splitagent.config import (
    PROVIDER_PRESETS,
    GlobalConfig,
    ProjectConfig,
    apply_provider_preset,
    global_config_path,
    load_global_config,
    load_project_config,
    project_config_path,
    save_global_config,
    save_project_config,
)
from splitagent.core.bus import EventBus
from splitagent.core.engine import Engine
from splitagent.core.sandbox import TARGET_PRESETS, DockerSandbox
from splitagent.errors import SplitAgentError
from splitagent.ui import theme as t
from splitagent.ui.stream import StreamRenderer

console = Console()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _banner() -> None:
    console.print(Text(t.BANNER, style=t.PRIMARY))
    console.print(
        Text(
            f"  v{__version__}  -  config: {global_config_path()}",
            style=t.MUTED,
        )
    )
    console.print()


def _prompt(label: str, default: str = "", secret: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        if secret:
            import getpass

            value = getpass.getpass(f"{label}{suffix}: ")
        else:
            value = input(f"{label}{suffix}: ")
    except (EOFError, KeyboardInterrupt):
        console.print()
        return default
    return value.strip() or default


def run_setup_wizard(config: GlobalConfig | None = None, test: bool = True) -> GlobalConfig:
    """Interactive provider/model setup, persisted to the global config."""
    config = config or load_global_config()
    console.print(Panel("Configure the model API", border_style=t.PRIMARY))
    console.print(
        Text(
            "SplitAgent talks to any model over an HTTP API. Pick a provider or "
            "choose 'custom' for a self-hosted OpenAI-compatible endpoint.",
            style=t.MUTED,
        )
    )
    names = list(PROVIDER_PRESETS)
    for index, name in enumerate(names, 1):
        preset = PROVIDER_PRESETS[name]
        console.print(f"  [{t.PRIMARY}]{index:>2}[/] {name:<12} {preset['base_url']}")
    choice = _prompt("Provider (name or number)", config.llm.provider or "openai")
    if choice.isdigit() and 1 <= int(choice) <= len(names):
        choice = names[int(choice) - 1]
    if choice not in PROVIDER_PRESETS:
        console.print(f"[{t.ORANGE}]Unknown provider; using 'custom'.[/]")
        choice = "custom"
    apply_provider_preset(config.llm, choice)

    config.llm.base_url = _prompt("Base URL", config.llm.base_url)
    config.llm.model = _prompt("Model", config.llm.model)
    key = _prompt("API key (blank to use env var)", "", secret=True)
    if key:
        config.llm.api_key = key
    temp = _prompt("Temperature", str(config.llm.temperature))
    try:
        config.llm.temperature = float(temp)
    except ValueError:
        pass
    config.authorized = True

    if test:
        console.print(Text("Testing connection...", style=t.MUTED))
        from splitagent.llm.client import LLMClient

        async def _probe() -> tuple[bool, str]:
            async with LLMClient(config.llm) as client:
                return await client.test_connection()

        try:
            ok, message = asyncio.run(_probe())
        except Exception as exc:
            ok, message = False, str(exc)
        if ok:
            console.print(f"[{t.GREEN}]Connection OK[/] - {message}")
        else:
            console.print(f"[{t.ORANGE}]Connection failed:[/] {message}")
            if not _prompt("Save anyway? (y/n)", "y").lower().startswith("y"):
                return config

    path = save_global_config(config)
    console.print(f"[{t.GREEN}]Saved[/] {path}")
    return config


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_init(args: argparse.Namespace) -> int:
    _banner()
    path = Path(args.path) if args.path else Path.cwd() / "splitagent.yaml"
    if path.exists() and not args.force:
        console.print(f"[{t.ORANGE}]{path} already exists (use --force).[/]")
        return 1

    project = ProjectConfig()
    project.name = args.name or Path.cwd().name

    if args.preset:
        if args.preset not in TARGET_PRESETS:
            console.print(
                f"[{t.RED}]Unknown preset '{args.preset}'. Known: {', '.join(TARGET_PRESETS)}[/]"
            )
            return 1
        preset = TARGET_PRESETS[args.preset]
        project.target.url = preset["url"]
        project.target.ports = [int(p) for p in preset["port_map"]]
        project.run.sandbox.image = preset["image"]
        project.run.sandbox.port_map = preset["port_map"]

    if args.url:
        project.target.url = args.url
    if args.kind:
        project.target.kind = args.kind
    if args.hosts:
        project.target.hosts = list(args.hosts)
    if args.rounds:
        project.run.rounds = args.rounds

    if not project.target.url and not project.target.hosts and not args.yes:
        project.target.kind = _prompt("Target kind (web/api/network/repo)", project.target.kind)
        project.target.url = _prompt("Target URL", project.target.url)
        hosts = _prompt("Additional hosts (comma separated)", "")
        if hosts:
            project.target.hosts = [h.strip() for h in hosts.split(",") if h.strip()]
        rounds = _prompt("Rounds", str(project.run.rounds))
        try:
            project.run.rounds = int(rounds)
        except ValueError:
            pass

    if not project.target.scope:
        project.target.scope = project.target.effective_hosts() or (
            ["localhost"] if project.target.url else []
        )

    saved = save_project_config(project, path)
    console.print(f"[{t.GREEN}]Project written to[/] {saved}")
    console.print(
        Text(
            "Next: `splitagent config setup` (once) then `splitagent run`.",
            style=t.MUTED,
        )
    )
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    action = args.action or "show"
    if action == "setup":
        run_setup_wizard(test=not args.no_test)
        return 0
    if action == "path":
        console.print(str(global_config_path()))
        return 0
    if action == "show":
        config = load_global_config()
        _banner()
        table = Table(title="Global configuration", border_style=t.BORDER)
        table.add_column("Key", style=t.PRIMARY)
        table.add_column("Value", style=t.TEXT)
        for key, value in config.llm.redacted().items():
            table.add_row(f"llm.{key}", str(value))
        table.add_row("authorized", str(config.authorized))
        console.print(table)
        console.print(Text(f"File: {global_config_path()}", style=t.MUTED))
        return 0
    if action == "set":
        config = load_global_config()
        if args.key not in config.llm.redacted():
            console.print(f"[{t.RED}]Unknown key '{args.key}'[/]")
            return 1
        value: object = args.value
        if args.key in ("temperature",):
            value = float(args.value)
        elif args.key in ("max_tokens", "timeout"):
            value = int(args.value)
        elif args.key in ("stream",):
            value = args.value.lower() in ("1", "true", "yes", "on")
        setattr(config.llm, args.key, value)
        path = save_global_config(config)
        console.print(f"[{t.GREEN}]Set llm.{args.key} - saved to {path}[/]")
        return 0
    if action == "preset":
        config = load_global_config()
        try:
            apply_provider_preset(config.llm, args.provider)
        except SplitAgentError as exc:
            console.print(f"[{t.RED}]{exc}[/]")
            return 1
        path = save_global_config(config)
        console.print(
            f"[{t.GREEN}]Provider set to {args.provider} ({config.llm.base_url}) - {path}[/]"
        )
        return 0
    console.print(f"[{t.RED}]Unknown config action '{action}'[/]")
    return 1


def _load_project_or_fail(args: argparse.Namespace) -> ProjectConfig:
    path = Path(args.config) if getattr(args, "config", None) else project_config_path()
    if not path.exists():
        raise SplitAgentError(f"No project config at {path}. Run `splitagent init` first.")
    project = load_project_config(path)
    if getattr(args, "rounds", None):
        project.run.rounds = args.rounds
    if getattr(args, "url", None):
        project.target.url = args.url
    if getattr(args, "max_steps", None):
        project.run.max_steps = args.max_steps
    if getattr(args, "no_sandbox", False):
        project.run.sandbox.enabled = False
    if getattr(args, "allow_network", False):
        project.run.allow_network = True
    return project


def _run_sync(project: ProjectConfig, args: argparse.Namespace) -> int:
    global_config = load_global_config()
    if not global_config.configured:
        console.print(f"[{t.ORANGE}]No model configured.[/] Launching the setup wizard.")
        global_config = run_setup_wizard(global_config)

    bus = EventBus()
    renderer = StreamRenderer(console=console, show_thinking=True)
    renderer.attach(bus)
    renderer.start()
    try:
        engine = Engine(global_config, project, bus=bus)
        context = asyncio.run(engine.run())
    except KeyboardInterrupt:
        console.print(f"\n[{t.ORANGE}]Interrupted.[/]")
        return 130
    finally:
        renderer.stop()

    state = context.state
    summary = Table(box=None, show_header=False)
    summary.add_column(style=t.MUTED)
    summary.add_column(style=t.TEXT)
    summary.add_row("session", state.id)
    summary.add_row("findings", str(len(state.findings)))
    summary.add_row("mitigations", str(len(state.mitigations)))
    summary.add_row("resilience", f"{state.resilience_score()}/100")
    summary.add_row("session file", str(context.path_for()))
    console.print(Panel(summary, title="[bold]Summary[/]", border_style=t.PRIMARY))

    if not args.no_report:
        from splitagent.report.generator import write_reports

        paths = write_reports(state, project.report, Path(project.report.output_dir))
        for path in paths:
            console.print(f"[{t.GREEN}]report[/] {path}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if getattr(args, "desktop", False):
        return cmd_desktop(args)
    _banner()
    if args.tui:
        return cmd_tui(args)
    try:
        project = _load_project_or_fail(args)
    except SplitAgentError as exc:
        console.print(f"[{t.RED}]{exc}[/]")
        return 1
    return _run_sync(project, args)


def cmd_tui(args: argparse.Namespace) -> int:
    from splitagent.ui.app import SplitAgentApp

    try:
        project = _load_project_or_fail(args)
    except SplitAgentError as exc:
        console.print(f"[{t.RED}]{exc}[/]")
        return 1
    global_config = load_global_config()
    app = SplitAgentApp(global_config, project)
    app.run()
    return 0


def cmd_desktop(args: argparse.Namespace) -> int:
    """Launch the native desktop application (pywebview)."""
    try:
        project = _load_project_or_fail(args)
    except SplitAgentError as exc:
        console.print(f"[{t.RED}]{exc}[/]")
        return 1
    try:
        from splitagent.desktop import DesktopApp
    except ImportError as exc:  # pragma: no cover - dependency is declared
        console.print(
            f"[{t.RED}]The desktop app requires pywebview:[/] pip install pywebview\n{exc}"
        )
        return 1
    global_config = load_global_config()
    app = DesktopApp(global_config, project)
    app.run()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from splitagent.core.context import SharedContext
    from splitagent.report.generator import write_reports

    if args.input:
        path = Path(args.input)
        if not path.exists():
            console.print(f"[{t.RED}]File not found: {path}[/]")
            return 1
        context = SharedContext.load_path(path)
    else:
        if not args.session:
            console.print(f"[{t.RED}]Provide --session <id> or --input <file>[/]")
            return 1
        context = SharedContext.load(args.session)

    project = ProjectConfig()
    if project_config_path().exists():
        project = load_project_config()
    if args.formats:
        project.report.formats = args.formats
    if args.output:
        project.report.output_dir = args.output
    paths = write_reports(context.state, project.report, Path(project.report.output_dir))
    for path in paths:
        console.print(f"[{t.GREEN}]report[/] {path}")
    console.print(
        Text(
            f"Resilience {context.state.resilience_score()}/100 - "
            f"{len(context.state.findings)} findings",
            style=t.MUTED,
        )
    )
    return 0


def cmd_sandbox(args: argparse.Namespace) -> int:
    _banner()
    project = ProjectConfig()
    if project_config_path().exists():
        project = load_project_config()
    if args.preset:
        preset = TARGET_PRESETS.get(args.preset)
        if not preset:
            console.print(f"[{t.RED}]Unknown preset '{args.preset}'[/]")
            return 1
        project.run.sandbox.image = preset["image"]
        project.run.sandbox.port_map = preset["port_map"]

    sandbox = DockerSandbox(project.run.sandbox, session_id="cli")

    async def _dispatch() -> int:
        if args.action == "up":
            status = await sandbox.up()
            console.print(
                f"[{t.GREEN if status.running else t.ORANGE}]{status.message}[/]"
                + (f" - {status.url}" if status.url else "")
            )
            return 0 if status.available else 1
        if args.action == "down":
            await sandbox.down()
            console.print(f"[{t.GREEN}]Sandbox removed.[/]")
            return 0
        if args.action == "status":
            status = await sandbox.status()
            console.print(f"available={status.available} running={status.running} {status.message}")
            return 0
        if args.action == "logs":
            console.print(await sandbox.logs(tail=args.tail))
            return 0
        return 1

    return asyncio.run(_dispatch())


def cmd_toolbox(args: argparse.Namespace) -> int:
    _banner()
    from splitagent.core.toolbox import Toolbox, build_command, estimated_size
    from splitagent.core.workspace import workspace_for

    project = ProjectConfig()
    if project_config_path().exists():
        project = load_project_config()
    if getattr(args, "edition", None):
        project.run.execution.edition = args.edition
    if getattr(args, "mode", None):
        project.run.execution.mode = args.mode

    workspace = workspace_for(project, base=Path.cwd())
    workspace.ensure()
    toolbox = Toolbox(project.run.execution, workspace.root)

    action = args.action
    if action == "status":
        status = toolbox.detect()
        table = Table(box=None, show_header=False)
        table.add_column(style=t.MUTED)
        table.add_column(style=t.TEXT)
        table.add_row("docker cli", "yes" if status.docker_cli else "no")
        table.add_row("daemon", "running" if status.daemon else "stopped")
        table.add_row("image", "built" if status.image else "missing")
        table.add_row("container", "running" if status.running else "stopped")
        table.add_row("edition", project.run.execution.edition)
        table.add_row("mode", project.run.execution.mode)
        table.add_row("message", status.message)
        if status.tools:
            present = [name for name, ok in status.tools.items() if ok]
            table.add_row("tools", ", ".join(present) or "(none)")
        console.print(Panel(table, title="Toolbox", border_style=t.PRIMARY))
        if not status.image:
            console.print(
                Text(
                    "Build with: " + " ".join(build_command(project.run.execution.edition)),
                    style=t.MUTED,
                )
            )
        return 0

    if action == "install":
        if not toolbox.detect().daemon and not toolbox.start_daemon()[0]:
            console.print(f"[{t.RED}]Docker daemon is not available.[/]")
            return 1
        project.run.execution.installed = True
        save_project_config(project, project_config_path())
        console.print(
            f"[{t.MUTED}]Building the {project.run.execution.edition} toolbox "
            f"({estimated_size(project.run.execution.edition)})…[/]"
        )
        result = toolbox.up()
        if not result.get("ok"):
            console.print(f"[{t.RED}]{result.get('error')}[/]")
            console.print(
                Text(" ".join(build_command(project.run.execution.edition)), style=t.MUTED)
            )
            return 1
        console.print(f"[{t.GREEN}]Toolbox ready[/] ({result.get('container')})")
        return 0

    if action == "up":
        result = toolbox.up()
        console.print(
            f"[{t.GREEN}]{result.get('container')} started[/]"
            if result.get("ok")
            else f"[{t.RED}]{result.get('error')}[/]"
        )
        return 0 if result.get("ok") else 1
    if action == "down":
        toolbox.down()
        console.print(f"[{t.GREEN}]Toolbox stopped.[/]")
        return 0
    if action == "reset":
        result = toolbox.reset()
        console.print(
            f"[{t.GREEN}]Toolbox recreated.[/]" if result.get("ok") else f"[{t.RED}]failed[/]"
        )
        return 0 if result.get("ok") else 1
    if action == "shell":
        console.print(
            Text(
                f"docker exec -it {project.run.execution.container} bash",
                style=t.MUTED,
            )
        )
        return 0
    console.print(f"[{t.RED}]Unknown action '{action}'[/]")
    return 1


def cmd_version(args: argparse.Namespace) -> int:
    console.print(f"splitagent {__version__}")
    console.print(f"config {global_config_path()}")
    return 0


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="splitagent",
        description="Autonomous dual-team (purple-team) security framework.",
    )
    parser.add_argument("--version", action="version", version=f"splitagent {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="Create a splitagent.yaml project file")
    p_init.add_argument("--path", help="Where to write the config")
    p_init.add_argument("--name")
    p_init.add_argument("--url", help="Target URL")
    p_init.add_argument("--kind", choices=["web", "api", "network", "repo"])
    p_init.add_argument("--hosts", nargs="*")
    p_init.add_argument("--rounds", type=int)
    p_init.add_argument("--preset", choices=list(TARGET_PRESETS))
    p_init.add_argument("--force", action="store_true")
    p_init.add_argument("--yes", "-y", action="store_true", help="No interactive prompts")
    p_init.set_defaults(func=cmd_init)

    p_config = sub.add_parser("config", help="Manage the global (API) configuration")
    p_config.add_argument(
        "action",
        nargs="?",
        default="show",
        choices=["show", "setup", "set", "path", "preset"],
    )
    p_config.add_argument("key", nargs="?")
    p_config.add_argument("value", nargs="?")
    p_config.add_argument("--provider", help="Provider name for the 'preset' action")
    p_config.add_argument("--no-test", action="store_true")
    p_config.set_defaults(func=cmd_config)

    p_run = sub.add_parser("run", help="Run a full Red vs Blue audit")
    p_run.add_argument("--config", help="Path to splitagent.yaml")
    p_run.add_argument("--url", help="Override the target URL")
    p_run.add_argument("--rounds", type=int)
    p_run.add_argument("--max-steps", type=int)
    p_run.add_argument("--no-sandbox", action="store_true")
    p_run.add_argument("--no-report", action="store_true")
    p_run.add_argument("--allow-network", action="store_true")
    p_run.add_argument("--tui", action="store_true", help="Launch the Textual interface")
    p_run.add_argument(
        "--desktop", action="store_true", help="Launch the native desktop application"
    )
    p_run.set_defaults(func=cmd_run)

    p_tui = sub.add_parser("tui", help="Launch the interactive interface")
    p_tui.add_argument("--config")
    p_tui.add_argument("--url")
    p_tui.add_argument("--rounds", type=int)
    p_tui.add_argument("--max-steps", type=int)
    p_tui.add_argument("--no-sandbox", action="store_true")
    p_tui.add_argument("--allow-network", action="store_true")
    p_tui.set_defaults(func=cmd_tui)

    p_desktop = sub.add_parser(
        "desktop", help="Launch the native desktop application (OpenCode-style UI)"
    )
    p_desktop.add_argument("--config")
    p_desktop.add_argument("--url")
    p_desktop.add_argument("--rounds", type=int)
    p_desktop.add_argument("--max-steps", type=int)
    p_desktop.add_argument("--no-sandbox", action="store_true")
    p_desktop.add_argument("--allow-network", action="store_true")
    p_desktop.set_defaults(func=cmd_desktop)

    p_report = sub.add_parser("report", help="Render a report from a session")
    p_report.add_argument("--session", help="Session id")
    p_report.add_argument("--input", help="Encrypted session file path")
    p_report.add_argument("--formats", nargs="*", choices=["markdown", "html", "json"])
    p_report.add_argument("--output", help="Output directory")
    p_report.set_defaults(func=cmd_report)

    p_sandbox = sub.add_parser("sandbox", help="Manage the Docker sandbox")
    p_sandbox.add_argument("action", choices=["up", "down", "status", "logs"])
    p_sandbox.add_argument("--preset", choices=list(TARGET_PRESETS))
    p_sandbox.add_argument("--tail", type=int, default=100)
    p_sandbox.set_defaults(func=cmd_sandbox)

    p_toolbox = sub.add_parser("toolbox", help="Manage the isolated agent execution environment")
    p_toolbox.add_argument(
        "action",
        choices=["status", "install", "up", "down", "reset", "shell"],
    )
    p_toolbox.add_argument("--edition", choices=["standard", "kali"])
    p_toolbox.add_argument("--mode", choices=["auto", "toolbox", "local"])
    p_toolbox.set_defaults(func=cmd_toolbox)

    p_version = sub.add_parser("version", help="Show version information")
    p_version.set_defaults(func=cmd_version)

    return parser


def _force_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):  # pragma: no cover
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except SplitAgentError as exc:
        console.print(f"[{t.RED}]error:[/] {exc}")
        return 1
    except KeyboardInterrupt:
        console.print()
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
