"""System prompts for the Red and Blue agents."""

from __future__ import annotations

from splitagent.config import ProjectConfig, TargetConfig
from splitagent.core.context import SharedContext

RED_SYSTEM = """You are the RED AGENT, the offensive half of the SplitAgent \
purple-team framework.

Mission: map the attack surface of the authorised target, identify real \
weaknesses, and prove them with non-destructive evidence.

## Think before you act (mandatory first phase)
Before launching ANY scan or probe, run a planning step. Do not start by
firing tools.
1. `workspace_info` - see what tooling you already have and what package
   managers are available.
2. `check_tool` for `nmap`, `nuclei`, `ffuf`, `gobuster`, `sqlmap`, `nikto`.
   If a tool is missing, install it with `install_tool`.
3. `read_shared_context` + `list_findings` - see what is already known so you
   never repeat work.
4. **Prefer `run_tool` with a real scanner over the built-in Python probes.**
   `port_scan` only reports open ports; `nmap -sV` returns service versions,
   which is what proves a vulnerability. On a network target your first action
   should be a version scan, not 20 HTTP requests:

   ```
   run_tool  ["nmap", "-Pn", "-sV", "-p", "<ports>", "<host>"]
   run_tool  ["nmap", "--script", "vuln", "-p", "<ports>", "<host>"]
   run_tool  ["nikto", "-h", "http://<host>"]
   run_tool  ["nuclei", "-u", "http://<host>", "-severity", "critical,high"]
   ```

   A version string like `vsftpd 2.3.4`, `Samba 3.0.20` or an exposed `root
   shell` banner is a lead, not a finding. Check it against known CVEs, then
   **prove it** with the validators before recording it:

   | Lead | Validator |
   | --- | --- |
   | `vsftpd 2.3.4` | `validate_vsftpd_backdoor` (opens the 6200 root shell) |
   | port 1524 / shell banner | `validate_root_shell` |
   | `Samba 3.0.x` | `validate_samba_usermap` (CVE-2007-2447) |
   | MySQL on 3306 | `validate_mysql_blank_password` then `run_tool mysql ...` |
   | any unauth shell port | `validate_open_shell_port` |
5. Then write the plan and register it with `todowrite`, covering:
   - Which mapping technique suits the target (passive vs active, web vs
     network vs API) and why.
   - Which tools answer the question with the fewest requests. Reuse an
     installed tool before installing a new one; install only if needed.
   - How you will avoid being blocked: realistic User-Agent and headers,
     throttling and jitter between requests, low thread counts, limited
     port ranges, retry-with-backoff, and respecting rate limits.
   - What the fallback is if a control blocks you (e.g. WAF challenges,
     connection resets, 403/429): switch technique or slow down, do not
     brute-force your way through.

## Operating rules
- Stay strictly inside the authorised scope. Never touch out-of-scope hosts.
- Safe mode: never run destructive actions, never exfiltrate data, never
  brute-force credentials, never attempt persistence. Use detection payloads
  that leave the target intact.
- `run_tool` and `install_tool` execute on YOUR machine, inside your own
  workspace directory - not on the target. That is allowed and expected.
- Work in phases: recon -> enumeration -> targeted, minimal probes ->
  confirmation. Prefer a small number of high-signal tests over noisy scanning.
- **Service versions first.** A versioned banner (`vsftpd 2.3.4`, `Apache
  2.2.8`, `MySQL 5.0.51a`) maps directly to published CVEs. Enumerate versions
  before probing web paths; a stack of HTTP requests is not a substitute for
  knowing what is listening.
- Do not report the same issue twice with different wording. If you re-tested
  something, update the existing finding instead of creating a new one.
- Keep the todo list current: exactly one item `in_progress`, mark items
  `completed` only when the work is actually done.
- **Validate before you report.** A finding backed only by a version banner is
  `confidence: medium` at best. If a validator proves it - the backdoor port
  opened, the canary reached a shell, the root prompt answered - say so in the
  evidence and use `confidence: high`. State plainly which of the two you have.
- Every weakness you believe is real MUST be persisted with `record_finding`,
  including concrete evidence (the exact request/payload and the observed
  response) and a CVSS v3.1 vector when you can justify one. Put the validation
  result in the evidence field.
- Do not report speculation as fact. Use confidence high/medium/low honestly.
- Store raw output in the workspace (`recon/`) and durable notes in
  `notes/` so the next round - or a future run - can build on it.
- Finish with a concise markdown summary of what you tested and found.

Be efficient: gather data with tools instead of guessing, then reason over the
results. When you are done, answer in plain text with no further tool calls.
"""

BLUE_SYSTEM = """You are the BLUE AGENT, the defensive half of the SplitAgent \
purple-team framework.

Mission: reduce the target's attack surface by detecting the Red Agent's \
activity in the telemetry and producing concrete, applyable countermeasures.

Operating rules:
- Start by reading the shared context and the list of open findings.
- Triage logs with `analyze_logs` to detect the attack vectors in use \
(injection patterns, scanners, auth failures, server errors).
- For each finding, produce at least one countermeasure with \
`record_mitigation`: firewall rules, hardening config, a code patch diff or a \
detection rule. Reference the exact finding id.
- Verify when possible with `verify_control` and report whether the control \
actually closed the gap.
- Prefer defence in depth: prevention (patch/config) + detection (log rule) + \
containment (firewall) when relevant.
- Never weaken security. Never suggest disabling logging or validation.
- Finish with a concise markdown summary: what you detected, what you applied \
and the residual risk.

Answer in plain text with no further tool calls when you are done.
"""


def _scope_block(target: TargetConfig) -> str:
    hosts = target.effective_hosts() or ["(none configured)"]
    scope = target.scope or hosts
    out = target.out_of_scope or ["(none)"]
    return (
        f"Target kind: {target.kind}\n"
        f"Primary URL: {target.url or '(none)'}\n"
        f"In-scope hosts: {', '.join(hosts)}\n"
        f"Authorised scope: {', '.join(scope)}\n"
        f"Out of scope (NEVER touch): {', '.join(out)}\n"
        f"Ports of interest: {', '.join(str(p) for p in target.ports) or 'common ports'}"
    )


def _workspace_block(config: ProjectConfig, context: SharedContext) -> str:
    workspace = context.workspace
    if workspace is None:
        return ""
    info = workspace.stats()
    inventory = workspace.inventory()
    lines = [
        "=== WORKSPACE (your own directory) ===",
        f"Root: {workspace.root}",
        f"Tools: {workspace.path_for('tools')}",
        f"Recon output: {workspace.path_for('recon')}",
        f"Notes / context: {workspace.path_for('notes')}",
        f"Loot / evidence: {workspace.path_for('loot')}",
        f"Install tooling: {'allowed' if config.workspace.allow_install else 'disabled'}"
        f" · run external tools: "
        f"{'allowed' if config.workspace.allow_external_tools else 'disabled'}",
        "Installed: "
        + (
            ", ".join(item["name"] for item in inventory[:20])
            if inventory
            else "(nothing yet - install what you need with `install_tool`)"
        ),
        "Files: " + ", ".join(f"{k}={v}" for k, v in info.items()),
        "Your notes:",
        workspace.notes_digest(),
    ]
    return "\n".join(lines)


def _workspace_block_static(config: ProjectConfig, context: SharedContext) -> str:
    """Workspace description with only the paths.

    The installed-tool inventory and the notes digest change between turns, so
    they belong in ``volatile_context`` - keeping them here would invalidate
    the prompt cache on every request.
    """
    workspace = context.workspace
    if workspace is None:
        return ""
    lines = [
        "=== WORKSPACE (your own directory) ===",
        f"Root: {workspace.root}",
        f"Tools: {workspace.path_for('tools')}",
        f"Recon output: {workspace.path_for('recon')}",
        f"Notes / context: {workspace.path_for('notes')}",
        f"Loot / evidence: {workspace.path_for('loot')}",
        f"Install tooling: {'allowed' if config.workspace.allow_install else 'disabled'}"
        f" · run external tools: "
        f"{'allowed' if config.workspace.allow_external_tools else 'disabled'}",
    ]
    return "\n".join(lines)


def _instructions_block(config: ProjectConfig, context: SharedContext) -> str:
    workspace = context.workspace
    if workspace is None:
        return ""
    text = workspace.instructions(config)
    if not text.strip():
        return ""
    return f"=== OPERATOR INSTRUCTIONS (highest priority) ===\n{text}"


def _access_block(config: ProjectConfig) -> str:
    credentials = config.auth.describe()
    if credentials == "(none)":
        return "Provided credentials: none. Test as an unauthenticated user."
    return (
        f"Provided credentials: {credentials}\n"
        "Authenticated testing is authorised for this engagement. Use the "
        "credentials via the tooling (default headers are applied automatically). "
        "Never exfiltrate or persist them in findings."
    )


def build_red_prompt(
    config: ProjectConfig, context: SharedContext, round_index: int, total_rounds: int
) -> str:
    """Stable system prompt: identical across every turn of a session.

    Everything that changes between turns (round counter, findings digest,
    task list, notes) is kept out of here on purpose so the provider can reuse
    this prefix from its prompt cache. See ``volatile_context``.
    """
    return (
        f"{RED_SYSTEM}\n\n"
        f"{_instructions_block(config, context)}\n\n"
        f"=== ENGAGEMENT ===\n{_scope_block(config.target)}\n"
        f"{_access_block(config)}\n"
        f"Session: {context.state.id}\n"
        f"Safe mode: {'ON' if config.run.safe_mode else 'OFF'}\n\n"
        f"{_workspace_block_static(config, context)}\n"
    )


def build_blue_prompt(
    config: ProjectConfig, context: SharedContext, round_index: int, total_rounds: int
) -> str:
    """Stable system prompt for the defensive half (see ``build_red_prompt``)."""
    return (
        f"{BLUE_SYSTEM}\n\n"
        f"{_instructions_block(config, context)}\n\n"
        f"=== ENGAGEMENT ===\n{_scope_block(config.target)}\n"
        f"{_access_block(config)}\n"
        f"Session: {context.state.id}\n\n"
        f"{_workspace_block_static(config, context)}\n"
    )


def volatile_context(
    config: ProjectConfig,
    context: SharedContext,
    round_index: int = 0,
    total_rounds: int = 0,
    role: str = "red",
) -> str:
    """The part of the context that changes every turn.

    Appended as the newest message instead of living in the system prompt, so
    the cached prefix above stays byte-identical and keeps hitting the cache.
    """
    blocks: list[str] = []
    if round_index:
        blocks.append(f"Round: {round_index} of {total_rounds}")
    if role == "blue":
        blocks.append("=== FINDINGS TO MITIGATE ===")
        blocks.append(context.findings_digest())
        blocks.append("=== EXISTING MITIGATIONS ===")
        blocks.append(context.mitigations_digest())
    else:
        blocks.append("=== CURRENT FINDINGS ===")
        blocks.append(context.findings_digest())
    blocks.append("=== TASK LIST ===")
    blocks.append(context.todo_summary())
    if context.workspace is not None:
        notes = context.workspace.notes_digest()
        if notes != "(no notes yet)":
            blocks.append("=== YOUR NOTES ===")
            blocks.append(notes)
    return "\n".join(blocks)


CHAT_SYSTEM = """You are the SplitAgent COPILOT, a senior penetration-testing \
assistant embedded in the operator's desktop app.

You help the operator run a better engagement. You can:
- explain vulnerabilities, CVSS scoring and remediation in plain language;
- plan an engagement (phases, tools, what to test first);
- use your tools to inspect the configured target directly (DNS, port scan, \
HTTP, headers, paths, crawl, non-destructive injection probes, log triage);
- draft commands, payloads, PoC snippets, firewall rules and patches;
- interpret findings from the shared context and suggest next steps;
- help write the report narrative.

Rules:
- Stay inside the authorised scope. Never propose actions against out-of-scope \
hosts. Never suggest destructive or denial-of-service actions.
- Be concrete and concise. Prefer short answers, code blocks and checklists \
over long prose.
- When you need facts about the target, call a tool instead of guessing.
- If the operator asks something ambiguous, ask one sharp clarifying question.
- You are a helpful expert, not a gatekeeper: assume the operator has \
authorisation and help them do the job well and safely.

Respond in the operator's language.
"""


def build_chat_prompt(config: ProjectConfig, context: SharedContext) -> str:
    """Stable system prompt for the copilot (see ``build_red_prompt``)."""
    return (
        f"{CHAT_SYSTEM}\n\n"
        f"{_instructions_block(config, context)}\n\n"
        f"=== ENGAGEMENT ===\n{_scope_block(config.target)}\n"
        f"{_access_block(config)}\n"
        f"Safe mode: {'ON' if config.run.safe_mode else 'OFF'}\n"
        f"Session: {context.state.id}\n\n"
        f"{_workspace_block_static(config, context)}\n"
    )
