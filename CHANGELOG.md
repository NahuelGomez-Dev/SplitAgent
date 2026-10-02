# Changelog

All notable changes to SplitAgent are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

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
