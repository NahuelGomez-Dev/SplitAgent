# Changelog

All notable changes to SplitAgent are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.0.3] - 2026-10-03

An audit that plans before it runs, a full security-hardening pass, and a
cleaner audit workspace. The engagement is now scoped by a rich brief, planned
by the model for the specific environment, and only starts once you approve it.

### Added

**Engagement planner (audit brief)**

- The `New audit` wizard gained a sixth, optional **Brief** step: what matters
  most (crown jewels), engagement goal, noise profile (stealth / normal /
  aggressive), areas to exclude, window and rate constraints, an authorization
  reference and free notes.
- The plan is **written by the model** (`build_audit_plan`) so it adapts to each
  environment — phases, techniques and cautions tailored to the brief and the
  uploaded scope document. A deterministic **fallback plan** is used if the
  model fails or exceeds the 15-second timeout, so an audit always has a plan.
- Plans are shown as an **Approve & start** card. Nothing is tested until the
  operator approves; the approved scope and brief flow into the run.
- **Upload your own scope document** (`.md`, `.txt`, `.json`, `.yaml`, `.csv`).
  The planner treats it as the highest-priority source of truth for scope and
  rules of engagement.
- A **Plan chat** panel on the right lets the operator talk to the planner about
  the plan. It is conversational and tool-less: it only plans, never tests.
- The brief is persisted to `workspace.instructions`, so it actually reaches the
  Red and Blue agents (previously the objective was only stored as a name).

**Copilot**

- The copilot is now a **normal, conversational assistant first**: it talks
  about the objective and scope and calls `propose_engagement` to show a plan,
  then waits for approval before starting any testing.

**Desktop experience**

- **Resizable, collapsible panels**: drag the dividers between the sidebar,
  stream and review panel, or hide either side with the titlebar buttons /
  `Ctrl+B` (sidebar) and `Ctrl+J` (panel).
- **Boot intro animation** (canvas particles, drawn mark, boot log) with
  click-to-skip and `prefers-reduced-motion` support.
- A single **Thinking / Exploring** activity line pinned to the bottom of the
  stream, and a Grok-style **response timer** under the active message.
- The audit view is action-focused: the central stream shows only the agents'
  work; the free-text objective was replaced by an **Objective** indicator fed
  from the plan, and planning/questions live in the right-hand Plan chat.

**Security hardening**

- `out_of_scope` is now enforced (subtracted from the allowed hosts and always
  wins, even with `allow_network`).
- `run_tool` / `install_tool` obey the scope: hosts, URLs and git remotes taken
  from a command line are validated before execution.
- The isolated toolbox no longer interpolates model-supplied package names into
  `sh -lc`; they are passed as arguments with strict validation per manager.
- Report filenames are sanitised, so a crafted session name cannot escape the
  output directory.
- Auth secrets (password, token, cookies, headers) are **redacted** in every
  payload sent to the renderer.
- Session ids are validated against path traversal.

### Fixed

- **Copilot replies were duplicated** — chat events were delivered both over the
  live bridge and the polled buffer. Chat now has a single, polled channel.
- The planner chat returned raw JSON instead of prose (it reused the JSON-only
  plan prompt). It now has its own conversational prompt.
- The **Plan chat** button now un-collapses the review panel, so it always opens
  the chat even if the panel had been hidden.
- Resizable dividers no longer shifted the three-column layout, and keep working
  below 1280 px.
- Tool output is visible again (a global `.hidden !important` rule defeated the
  detail override), and the trace panel no longer freezes at 400 entries.
- The **swarm of state bugs** from the audit: first-run onboarding crash, boot
  intro showing for ~3 ms, Ctrl+Enter starting the audit twice, tool output
  invisible, workspace settings silently dropped by the wizard, and a leaked
  running-tool counter when `call_id` was missing.
- Continuous conversations no longer duplicate the injected "current state"
  block in the model history (`_clean_history`).
- The chat textarea rendered as an unstyled white box.
- Sandbox `port_map` direction was inverted (dvwa/bwapp/webgoat mapped to the
  wrong ports); it is now consistently `{host: container}`.
- HTTP redirects can no longer hop to an out-of-scope host (followed and
  re-checked manually).
- Malformed session files degrade instead of crashing the report renderer.
- Provider toggles, `allow_network`/offline divergence and several smaller
  backend issues.
- Type checking: all mypy errors resolved.

### CI / packaging

- `mypy` now runs in CI alongside ruff and the secret scan.
- `scripts/` is linted.

### Notes

- For **authorised security testing only**.
- Full test suite: **422 passing**.

## [0.0.2] - 2026-10-02

Redesign of the reporting engine and the desktop experience. Reports now follow
a fixed, professional penetration-test structure, the desktop gained a
post-audit dashboard and resizable panels, and the whole interface was unified
into a single cockpit.

### Added

**Professional report engine**

- Deterministic, code-owned report template: two sessions with the same data
  produce the same document, byte for byte. The model only fills structured
  fields — it never composes the document.
- Full penetration-test structure in Markdown and printable A4 HTML: document
  control, executive summary, scope and rules of engagement, methodology and
  standards, severity model, findings summary, detailed findings, remediation
  roadmap, retest tracking, appendices and limitations.
- Structured finding fields: `cwe`, `owasp`, `impact` and `reproduction`, added
  to `record_finding`, the Red Agent's prompt and `Finding`. Missing fields
  render as "Not provided" instead of raising.
- Severity model, remediation priorities with target SLAs (P0 24-48h → P4 best
  effort) and a retest/status table.

**Desktop**

- Post-audit **Dashboard** tab: overall risk, severity distribution, top
  findings, round timeline and resilience — rendered from live session state
  with inline CSS/SVG, no chart dependency. It focuses automatically when a run
  ends.
- **Resizable and collapsible panels**: drag the dividers to resize the sidebar
  and the review panel, or hide them with the titlebar buttons / `Ctrl+B`
  (sidebar) and `Ctrl+J` (review).
- **Continuous Copilot conversation**: replies stream into a single ongoing
  thread instead of spawning a new chat each message. Chat events are buffered
  and polled, so a reply can never be lost mid-stream.
- **Boot intro animation** (canvas particles, drawn mark, boot log) with a
  click-to-skip and `prefers-reduced-motion` support.
- A single **Thinking / Exploring** activity line pinned to the bottom of the
  stream, flipping verb based on what the agent is doing instead of stacking.
- A Grok-style **response timer** under the active message header.

### Changed

- **One interface.** The Simple/Developer experience model (`experience`,
  `experience_chosen`, `developer_mode`) was removed in favour of a single
  cockpit. Legacy configs containing those keys still load.
- Agent and user **avatars removed** from message headers; name and time remain.
- Report authenticity: the AI-assisted narrative is limited to finding fields,
  keeping every report consistent and reviewable.
- Chat input styling unified with the audit composer (dark card, accent focus).

### Fixed

- The desktop finally reflects the live config: report and dashboard read the
  current session rather than going stale.
- Continuous conversations no longer duplicate the injected "current state"
  block in the model history; `_clean_history` stores only real turns, keeping
  the prompt cache stable across turns.
- The chat textarea rendered as an unstyled white box; it now matches the rest
  of the interface.
- Resizable dividers no longer shift the three-column layout (they are
  absolute overlays, not grid tracks).

### CI / packaging

- Repository URLs corrected to `NahuelGomez-Dev/SplitAgent`; license migrated to
  SPDX (`MIT`) with `license-files`, removing the setuptools deprecation warning.
- Secret scanner runs in CI (`check_secrets.py --all`) and `scripts/` is linted.
- README badges (CI, PyPI, Python, license) and `pip install splitagent` quick
  start.

### Notes

- For **authorised security testing only**.

## [0.0.1] - 2026-10-01

First public release. An autonomous dual-team (purple-team) security
framework where a Red Agent and a Blue Agent work the same target.

### Added

**Core**

- Central orchestrator running Red -> Blue rounds with a shared, encrypted
  context (Fernet, key stored with `0600` permissions).
- Event bus driving both the console stream and the desktop UI.
- Session state with findings, mitigations, rounds, checkpoints and a full
  per-agent trace, all persisted encrypted.

**Agents**

- Red Agent: reconnaissance, controlled non-destructive exploitation, evidence
  capture and CVSS v3.1 scoring.
- Blue Agent: telemetry triage, countermeasures (firewall, hardening, patch,
  detection) and verification.
- Pentest copilot: an interactive assistant with the full toolset.
- Mandatory planning phase before any scan, including anti-blocking strategy.
- Forced wrap-up that persists findings and summarises before the step budget
  runs out, with a fallback summary built from persisted state.

**Exploitation validators**

- `validate_vsftpd_backdoor` (CVE-2011-2523), `validate_root_shell`,
  `validate_samba_usermap` (CVE-2007-2447), `validate_mysql_blank_password`,
  `validate_unrealircd_backdoor` (CVE-2010-2075), `validate_vnc_no_auth`,
  `validate_nfs_export`, `validate_proftpd`, `validate_open_shell_port`.
- Each returns `validated: true/false` with raw evidence and refuses to claim
  success when it cannot observe the effect.

**Tools**

- Recon, web, exploit and defence toolkits, plus a persistent agent workspace
  for installed tooling, reconnaissance output and notes with `AGENTS.md`
  operator instructions.
- `port_scan` with a `full` sweep of all 65535 ports.

**Interfaces**

- Native desktop application (pywebview) built on OpenCode's v2 design
  language: live Red/Blue stream, guided setup wizard, model picker and a
  command palette.
- Two experiences: **Simple** for non-technical users (plain language, one
  action) and **Developer** (full cockpit), with an automatic first-run
  heuristic.
- Rich streaming CLI and a Textual TUI.

**Isolated toolbox**

- Disposable Docker environment so tooling never touches the host, in a
  standard (Debian) and a professional (Kali) edition.

**Context efficiency**

- Prompt caching with a stable system prefix, per-request projection,
  reasoning stripping, pruning and compaction, all ported from OpenCode's
  session model.

**Resilience**

- Retries with exponential backoff on transient provider failures, a
  wall-clock deadline, and parallel tool execution for independent probes.

**Reports**

- Markdown, standalone HTML and JSON with CVSS v3.1, evidence, deduplicated
  findings and actionable mitigations.

### Notes

- The resilience score counts only findings whose mitigation was re-tested and
  confirmed. Proposed controls score zero, and the report says so explicitly.
- For **authorised security testing only**.
