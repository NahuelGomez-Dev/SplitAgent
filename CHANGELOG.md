# Changelog

All notable changes to SplitAgent are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

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
