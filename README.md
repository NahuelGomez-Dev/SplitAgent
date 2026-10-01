# SplitAgent

**Autonomous dual-team (Purple Team) security framework.**

SplitAgent automates penetration testing and defensive hardening with two
teams of AI agents that operate against the same target, in real time:

- **Red Agent** — reconnaissance, attack-surface mapping and controlled,
  non-destructive exploitation with evidence.
- **Blue Agent** — log triage, detection and concrete mitigations (firewall
  rules, hardening config and code patches), plus verification.

Everything is driven by a **central orchestrator** that runs Red → Blue rounds,
keeps an **encrypted shared context** and compiles a professional report with
CVSS v3.1 scoring.

> The model is **never bundled**: SplitAgent talks to *any* model over an HTTP
> API (OpenAI-compatible or Anthropic). You choose the provider and paste the
> API key from inside the program — no local AI required.

---

## Highlights

- **Dual-agent Purple Team loop** — attack, mitigate, verify, repeat.
- **Any model, any provider** — OpenAI, OpenRouter, Anthropic, Groq, DeepSeek,
  Together, Mistral, xAI, vLLM, LM Studio, Ollama (OpenAI mode) or a custom
  endpoint.
- **In-app configuration** — `splitagent config setup` or press `c` in the TUI.
  Keys are stored with `0600` permissions in the global config directory.
- **Encrypted sessions** — findings and evidence are encrypted at rest with a
  Fernet key (`~/.splitagent/key.bin`).
- **Ephemeral Docker sandbox** — spin up a disposable vulnerable target
  (`juice-shop`, `dvwa`, `bwapp`, `webgoat`) on an isolated network.
- **Native desktop application** — a real window (pywebview + WebView2) whose
  interface is built on OpenCode's *Desktop v2* design language: near-black
  canvas, sidebar, central stream, review panel and composer. A Rich streaming
  CLI and a Textual TUI are included too.
- **Reports** — Markdown, standalone HTML and JSON, with CVSS v3.1 vectors,
  full traceability and ready-to-apply patches.

---

## Architecture

```
                    +-------------------------------+
                    |        Core Engine            |
                    |  rounds · shared context      |
                    |  event bus · sandbox control  |
                    +---------------+---------------+
                                    |
             +----------------------+----------------------+
             |                                             |
   +---------v----------+                       +----------v---------+
   |     RED AGENT      |   encrypted context   |     BLUE AGENT     |
   |  recon · probe     |<--------------------->|  triage · patch    |
   |  record findings   |                       |  firewall · verify |
   +---------+----------+                       +----------+---------+
             |                                             |
             +----------------------+----------------------+
                                    |
                    +---------------v---------------+
                    |   Target / Docker sandbox     |
                    +-------------------------------+
```

The engine emits events (`agent.text`, `agent.tool_call`, `finding`,
`mitigation`, `round.end`, …) that drive both the CLI stream renderer and the
Textual TUI.

---

## Installation

Requires **Python 3.10+**. Docker is optional (only for the sandbox).

```bash
git clone https://github.com/splitagent/splitagent
cd splitagent
python -m venv .venv
. .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
pip install -e .
```

Or simply:

```bash
pip install -r requirements.txt
pip install -e .
```

---

## Quick start

```bash
# 1. Configure the model API (once). Stored in ~/.splitagent/config.yaml
splitagent config setup

# 2. Create a project file (splitagent.yaml) for your target
splitagent init --preset juice-shop -y

# 3. Launch the desktop app (or `run --tui` / plain `run` for the terminal)
splitagent desktop

# 4. Reports land in ./reports
```

### Setup wizard

`splitagent config setup` lists the supported providers, lets you override the
base URL, model, temperature and API key, and validates the credentials with a
live round-trip before saving. You can also skip the wizard and use environment
variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `SPLITAGENT_API_KEY`, …).

Non-interactive setup:

```bash
splitagent config preset openrouter
splitagent config set api_key sk-or-...
splitagent config set model anthropic/claude-3.5-sonnet
```

---

## Commands

| Command | Description |
| --- | --- |
| `splitagent init` | Create `splitagent.yaml` (interactive or with flags). |
| `splitagent config setup` | Configure the model API and test it. |
| `splitagent config show` | Show the global config (key redacted). |
| `splitagent config set <key> <value>` | Update a single LLM setting. |
| `splitagent config preset <provider>` | Apply a provider preset. |
| `splitagent desktop` | Launch the native desktop application. |
| `splitagent toolbox` | Manage the isolated Docker execution environment. |
| `splitagent run` | Run the full audit in the terminal. |
| `splitagent tui` | Launch the interactive Textual interface. |
| `splitagent report --session <id>` | Re-render reports from a saved session. |
| `splitagent sandbox up\|down\|status\|logs` | Manage the Docker sandbox. |

### Useful `run` flags

```
--url URL            Override the target URL
--rounds N           Number of Red/Blue cycles
--max-steps N        Max tool-calling steps per agent turn
--no-sandbox         Do not use Docker
--no-report          Skip report generation
--allow-network      Disable scope enforcement (lab use only)
--tui                Launch the interactive interface
```

---

## Desktop application

```bash
splitagent desktop            # or: splitagent run --desktop
```

Two modes, switched from the titlebar:

- **Audit** — the autonomous Red vs Blue run.
- **Copilot** — a conversational assistant that helps you *do* the pentest:
  plan the engagement, explain a vulnerability, inspect the target with the
  full toolset, draft payloads, firewall rules or patches, and interpret
  findings. It keeps the conversation history and streams its reasoning.

The **guided setup** asks a few questions before running (target kind →
address and scope → sandbox or existing target → optional credentials →
depth) so you do not have to know the config format.

**Models & Providers settings** (`Ctrl+,`) copy OpenCode's own menus:

- **Models** — the full catalogue, searchable, grouped by provider with
  collapsible sections and a per-provider/per-model switch, plus "Custom
  model" to add an id the catalogue does not list.
- **Providers** — **Connected** (base URL, model count, enable switch,
  Refresh, Edit, Disconnect) and **Popular** with a Connect button. Connecting
  asks for the base URL and API key, then **fetches the provider's `/models`
  catalogue automatically** and can make it the active provider.
- **General** — temperature, max tokens, config-file shortcut and a connection
  test.

The **model picker** in the composer is also a faithful copy of OpenCode's:
a searchable popover grouped by provider with a "Manage models…" entry that
opens the settings above.

A frameless native window (pywebview + the system WebView2 runtime) rendering
an interface modelled on OpenCode's Desktop v2 design language:

```
┌──────────────────────────────────────────────────────────────────────┐
│  ◇ SplitAgent   Audit session              ⌘K  ⚙   ─  ▢  ✕          │
├───────────────┬──────────────────────────────────┬───────────────────┤
│ Engagement    │  ▸ Round 1 · offence             │ Findings    3     │
│ web localhost │  RED  analysis / tool calls …     │ Mitigations 2     │
│ scope …       │  ▸ Round 1 · defence             │ Report            │
│ Sessions …    │  BLUE triage / patches …          │ Activity          │
│               │  ┌────────────────────────────┐  │                   │
│ model chip    │  │ objective…      Run audit   │  │ Export report     │
├───────────────┴──────────────────────────────────┴───────────────────┤
│ provider/model · round 1/3 · defence · 42 events · resilience ▓▓▓░ 78 │
└──────────────────────────────────────────────────────────────────────┘
```

- **Quiet, OpenCode-style stream** — nothing floods the timeline while an agent
  works:

  ```
  Thinking   checking the login form for reflected input…            ›
  Exploring · 3 scans, 1 request                                     ›
    ✓ port_scan      {"host":"127.0.0.1"}                            ›
    ✓ http_request   {"url":"…/login"}                               ›
    ! test_xss       {"parameter":"q"}                               ›
  ```

  Reasoning collapses to **one shimmering line** that becomes `Thought` when
  done, and switches verb dynamically: `Thinking · considering next steps…`
  while the model deliberates, `Exploring · running tools…` while tools run.
  Every action lives in a **collapsible group** (the OpenCode `BasicTool`
  pattern): a single header with verb + counts, and inside it one compact row
  per call — status, title, args — with its **own chevron** that opens the full
  arguments and output. Tool cards are never appended to the timeline directly,
  so long runs stay short. The **Trace** tab always holds the complete replay.

- **Task dock** (`SessionTodoDock` port) — a collapsible bar above the composer
  reading `2 of 5 todos completed` with the active task as a preview, a chevron
  that rotates 180°, and a checklist where the in-progress item pulses
  (`pulse-scale 1.2s ease-in-out infinite`), completed items strike through
  with an animated line and cancelled items dim. It appears automatically when
  an agent calls `todowrite`.
- **Live stream** — Red and Blue messages stream in with tool calls that
  expand to show the exact arguments and output, plus inline severity cards and
  context-checkpoint cards.
- **Review panel** — Findings, Mitigations, the generated Report and an
  Activity log, all updating in real time.
- **Composer** — set the objective, pick the model, toggle the Docker sandbox
  and rounds, then **Run audit** (`Ctrl+Enter`). The **Guided** button opens
  the wizard.
- **Authenticated testing** — optional credentials (username/password, bearer
  token, cookies, custom headers) are injected into the agents' context and
  applied as default headers by the web tools.
- **In-app model configuration** — the Models/Providers settings manage every
  provider and its models, and *Test connection* validates credentials before
  saving. Nothing is pre-baked: any OpenAI-compatible or Anthropic endpoint
  works, and connected providers are stored in the global config so both the
  Audit and the Copilot modes share them.
- **Command palette** — `Ctrl+K` for run/stop, settings, export and sandbox
  presets.
- Sessions are encrypted and can be reopened from the sidebar; reports open
  directly from the review panel.

> Requirements: Windows 10/11 with the WebView2 runtime (bundled with Edge),
> macOS or Linux with GTK/Qt WebKit. On Windows, `pip install pywebview`
> pulls `pythonnet` automatically.

---

## Configuration

### Global — `~/.splitagent/config.yaml`

```yaml
llm:
  provider: openai            # any provider preset or "custom"
  protocol: openai            # openai | anthropic
  base_url: https://api.openai.com/v1
  api_key: sk-...
  model: gpt-4o-mini
  temperature: 0.2
  max_tokens: 4096
  timeout: 120
  stream: true
authorized: true              # you accepted the responsible-use notice
```

### Project — `splitagent.yaml`

```yaml
project:
  name: my-audit
target:
  kind: web                   # web | api | network | repo
  url: http://localhost:3000
  hosts: []
  ports: [80, 443, 3000]
  scope: [localhost]
  out_of_scope: []
run:
  rounds: 3
  max_steps: 12
  safe_mode: true
  allow_network: false
  sandbox:
    enabled: true
    image: bkimminich/juice-shop:latest
    network: splitagent-net
    port_map: { "3000": 3000 }
auth:                         # optional, for authenticated testing
  username: ""
  password: ""
  token: ""
  cookies: ""
  headers: {}
workspace:                    # the agents' own directory
  path: ""                    # empty -> ./splitagent-workspace
  allow_install: true
  allow_external_tools: true
  instructions: ""
run:
  execution:                  # isolated Docker environment
    mode: auto                # auto | toolbox | local
    edition: standard         # standard | kali
    auto_start: true
agents:
  red:  { enabled: true, temperature: 0.3 }
  blue: { enabled: true, temperature: 0.2 }
report:
  formats: [markdown, html, json]
  output_dir: reports
  include_patches: true
  include_evidence: true
```

---

## Context & token management

Ported from OpenCode's session model (`session/overflow.ts`,
`session/compaction.ts`, `tool/truncate.ts`):

| Concept | Where | Behaviour |
| --- | --- | --- |
| Usable budget | `core/context_manager.py:usable` | `context_window − reserved`, reserving room for the reply (buffer capped at 20 000). |
| Overflow | `is_overflow` | Compares the last turn's usage against that budget. |
| **Prompt caching** | `llm/client.py:_with_cache_points` | System prompt + the newest messages are marked as cache breakpoints, exactly as OpenCode's `applyCaching` does. Anthropic/Bedrock/OpenRouter get `cache_control: {type: "ephemeral"}`; OpenAI-compatible gateways cache automatically on a stable prefix. Measured at **79.8%** cache hit rate. |
| **Stable prefix** | `agents/prompts.py` | The system prompt is **byte-identical for the whole session**. Round counter, findings, task list, notes and tool inventory are appended to the newest user turn by `volatile_context()` instead of living in the system prompt — otherwise every request invalidates the cache. |
| Per-request projection | `optimize` | Runs before **every** request: drops the reasoning of settled steps, blanks superseded state snapshots, prunes old tool output. This is what keeps the billed prompt small even on 1M-token models. |
| Reasoning stripping | `strip_reasoning` | Reasoning is scaffolding — once a step produced tool calls it has been acted on. Only the last turn keeps it (OpenCode does the same per step). |
| Snapshot superseding | `supersede_stateful_results` | `workspace_info`, `read_shared_context`, `list_findings`… return full current state; only the newest copy is meaningful. |
| Pruning | `prune` | Walks backwards keeping the newest tool result, protects ~40 000 tokens of recent tool output, then blanks older results to `"[Old tool result content cleared]"`. Savings under 20 000 tokens are discarded. |
| Compaction | `compact` | Keeps a tail of recent turns within ~25 % of the budget (clamped to 2 000–15 000) and replaces the head with a structured checkpoint message. |
| Tool bounding | `prune_tool_output` | Any tool result entering the conversation is capped at 2 000 chars. |

Each model carries a context/output limit (`config.model_spec`, overridable per
provider in the settings) that feeds the policy. Everything is configurable in
`splitagent.yaml`:

```yaml
run:
  compaction:
    auto: true
    prune: true
    reserved: null                    # null = min(20k, max_output)
    preserve_recent_tokens: null       # null = clamp(25% of budget, 2k..15k)
    tail_turns: null                  # limit how many turns are kept
```

### Why the prefix must stay stable

Caching only works if the prefix is byte-identical between requests. The
runtime enforces that split:

```
system      -> RED_SYSTEM + engagement + scope + workspace paths   (frozen)
history     -> previous turns
user (last) -> the task + "=== CURRENT STATE ===" + findings, todo list,
               round counter, notes                                (fresh every step)
```

So findings can be recorded mid-run without invalidating a single cached
token. Disable it if you need to compare against a cold prompt:

```yaml
# global config
llm:
  prompt_cache: true
  cache_system_messages: 2   # how many leading system messages to mark
  cache_tail_messages: 2     # how many trailing messages to mark
```

Measured on a real run (OpenCode Go / DeepSeek V4.1 Flash):

```text
step 1: prompt=  4363 cached=     0
step 2: prompt=  4871 cached=  4736
step 3: prompt=  5170 cached=  4992
step 4: prompt=  5325 cached=  5120
step 5: prompt=  5623 cached=  5376
cache hit rate: 79.8%
```

### Full trace & replay

Nothing is lost when context is trimmed. Every reasoning step, tool call with
its exact arguments, the full tool output, token usage and each context event
are recorded:

- **Trace tab** — a live, colour-coded replay panel; "Dump JSON" writes the
  whole trace to `~/.splitagent/traces/`.
- **Session file** — encrypted checkpoints and per-agent traces travel with the
  session, so a finished audit can be replayed end to end.
- **Status bar** — a live context meter (`ctx 42%`) that turns amber then
  orange as the window fills.

---

## Tools

**Shared** — `todowrite`, `record_finding`, `list_findings`, `get_finding`,
`record_mitigation`, `read_shared_context`.

**Workspace** — `workspace_info`, `workspace_write`, `workspace_read`,
`workspace_list`, `install_tool`, `run_tool`.

`todowrite` is a faithful port of OpenCode's task tool: the same description
(proactive when 3+ steps, one `in_progress` at a time, `pending` /
`in_progress` / `completed` / `cancelled`, `high` / `medium` / `low`) and the
same `{content, status, priority}` item shape. The list is stored in the
session and surfaced in the UI as a collapsible **task dock**.

---

## Isolated toolbox (recommended)

The agents install and run their security tooling **inside a disposable Docker
container**, so your computer is never modified. This is the default in `auto`
mode and it is what makes a run reproducible: same tools, same versions, every
time.

```bash
splitagent toolbox status          # docker? daemon? image? container?
splitagent toolbox install         # build the image and start it
splitagent toolbox up|down|reset   # lifecycle
splitagent toolbox shell           # prints the docker exec command
```

### One-time consent, then silent

On first launch the app checks for Docker and, if the image is not built yet,
asks **once**:

```
┌ Set up the isolated environment ────────────────────────┐
│ Docker      installed                                     │
│ Engine      running                                       │
│ Image       not built                                     │
│ Workspace   …\splitagent-workspace                        │
│                                                           │
│ Edition  [ Standard — Debian + recon tools (~450 MB)  ▾ ] │
│                                                           │
│ [Continue without it]        [Later]  [Install environment]│
└───────────────────────────────────────────────────────────┘
```

After that it never asks again: if the daemon is stopped SplitAgent **starts
Docker Desktop itself** and brings the container up in the background. You
never have to touch Docker again.

### Editions

| Edition | Base | Size | Contents |
| --- | --- | --- | --- |
| `standard` *(default)* | Debian bookworm-slim | ~450 MB | nmap, masscan, nikto (pip), sqlmap, whatweb, wafw00f, gobuster, ffuf, dirb, nuclei, subfinder, httpx, dnsx, curl, git, python3 + venv |
| `kali` | kalilinux/kali-rolling | ~2.5 GB | the above via `kali-linux-headless`, plus the wider Kali toolset |

Go-based tools are compiled against a modern Go toolchain at build time (the
one in Debian's repos is too old), then the toolchain is discarded.

### How execution is routed

```yaml
run:
  execution:
    mode: auto            # auto | toolbox | local
    edition: standard     # standard | kali
    auto_start: true      # start Docker Desktop silently when needed
    network_mode: bridge  # bridge | host
    allow_install: true
    cpus: ""              # e.g. "2"
    memory: ""            # e.g. "2g"
```

| Mode | Behaviour |
| --- | --- |
| `auto` *(default)* | Use the toolbox when Docker works, otherwise fall back to local. |
| `toolbox` | Require the toolbox; the run fails with a clear message if Docker is missing. |
| `local` | Legacy: install and run on the host. |

`install_tool`, `run_tool` and `check_tool` become backend-aware: in toolbox
mode they run `docker exec` against the container, with the workspace mounted
at `/workspace`. The agent's tool output reports `"backend": "toolbox"`, and
`workspace_info` tells the model it is sandboxed and can install freely.

```text
run_tool  nmap --version  ->  backend toolbox
          Nmap version 7.93 ( x86_64-pc-linux-gnu )
```

The container is on `splitagent-net`, the same isolated network as the target
sandbox, and gets `NET_RAW`/`NET_ADMIN` (needed by `nmap -sS`). Without
`network_mode: host` it cannot reach your LAN, which keeps a mis-scoped scan
contained.

### Security properties

- The host is **never modified**: no winget, no `npm -g`, no system packages.
- Only the workspace directory is bind-mounted; no Docker socket, no home.
- The container is disposable — `toolbox reset` recreates it from scratch
  while keeping everything under `/workspace`.
- With no Docker at all, SplitAgent degrades to local mode and the native
  Python tools keep working.

---

## Agent workspace

The agents get their own persistent directory — a place to install tooling,
keep reconnaissance output, write notes and carry context between runs (the
same idea as OpenCode rooting an agent in a working directory and reading
`AGENTS.md` from it).

```
splitagent-workspace/
  AGENTS.md      operator instructions (highest priority in the system prompt)
  README.md
  tools/         virtualenvs, installed packages, cloned repos, tools/bin
  recon/         raw scans, crawls, HTTP captures
  loot/          downloaded artefacts and evidence
  notes/         the agent's own structured context (plan.md, findings.md, …)
  sessions/      per-run logs and traces
  cache/
```

Configured under `workspace` in `splitagent.yaml` (or step 4 of the guided
setup):

```yaml
workspace:
  path: ""                     # empty -> <project>/splitagent-workspace
  allow_install: true          # let the agents install tooling
  allow_external_tools: true   # let them run commands
  max_install_seconds: 900
  instructions: ""             # inline operator guidance
  instruction_files: []        # extra files to load into the prompt
```

- **Check before installing** — `check_tool` resolves a binary across `PATH`,
  the workspace `tools/bin` and Go's bin, and returns install suggestions when
  missing. `workspace_info` reports which common security tools are already
  present (`nmap`, `nuclei`, `ffuf`, `gobuster`, `sqlmap`, `nikto`,
  `subfinder`, `httpx`, `masscan`, `whatweb`).
- **Install tooling** — `install_tool` supports pip (into an isolated
  `tools/venv`), pipx, npm, go, cargo, apt, brew, **winget** and `git clone`.
  Go installs are redirected to `tools/bin` via `GOBIN` so they are immediately
  runnable. Known tools carry preferred `(manager, package)` pairs, e.g.
  `nmap` → winget `Insecure.Nmap`, `ffuf` → `go install
  github.com/ffuf/ffuf/v2@latest`.
- **Run tooling** — `run_tool` executes a command with the workspace as cwd; the
  binary is resolved across `PATH`, `tools/bin` (including Go installs) and the
  pip venv, and `SPLITAGENT_WORKSPACE`, `SPLITAGENT_TOOLS`,
  `SPLITAGENT_RECON` and `SPLITAGENT_NOTES` are exported. So `nmap -sV`,
  `nuclei`, `ffuf` and friends run straight from the workspace.

```text
run_tool  nmap -Pn -sT -p 80,443 127.0.0.1  ->  Nmap scan report, 80/tcp open
```
- **Instructions** — `AGENTS.md` plus anything in `instructions` /
  `instruction_files` is injected into every agent's system prompt under
  *OPERATOR INSTRUCTIONS (highest priority)*.
- The desktop sidebar shows a **Workspace** card with the file count; click it
  to open the directory in the file manager.

### Speed

Three changes, each measured against the real target:

| Change | Where | Measured |
| --- | --- | --- |
| **Parallel tool calls** | `agents/base.py:_execute_tools` | **19.2x** — 5 independent probes went from 3.32 s to 0.17 s |
| **Shared connection pool** | `tools/http_pool.py` | **2.07x** — 10 HTTP requests from 208 ms to 101 ms (no repeat TCP/TLS/DNS) |
| **Prompt caching** | `llm/client.py` | **62-80% cache hit rate** on real runs |

Tools declare `parallel_safe`. Read-only probes (`audit_security_headers`,
`test_cors`, `probe_paths`, `dns_lookup`…) run concurrently bounded by
`run.tool_concurrency`; anything that mutates state, installs or shells out
(`run_tool`, `install_tool`) keeps the ordered sequential path. Results are
always reassembled in the model's original call order, so the transcript is
deterministic regardless of completion order.

Live end-to-end run, same task and model:

```text
wall clock      : 81.5s for 8 steps   (10.2s/step)
tool calls      : 24 (3.0/step)
prompt tokens   : 74,387
cached tokens   : 46,720  (62.8% hit rate)
optimizer saved : 1,318 tokens
wrapped up      : True | hit limit: False
```

```yaml
run:
  tool_concurrency: 4     # bounded parallelism, polite to the target
```

### Findings are deduplicated

The Red Agent re-tests the same surface every round, so the raw output filled
with near-identical entries. Two findings are merged when they share an
endpoint **and** either the same category (other than the default `general`) or
strongly overlapping titles:

```
endpoint normalised  +  category matches        -> merge
endpoint normalised  +  decisive token matches  -> merge
endpoint normalised  +  >50% identity overlap   -> merge
```

The merge keeps the highest CVSS score and appends the new evidence, so nothing
is lost. Precision matters as much as recall here: `Missing CSP header` and
`Missing HSTS header`, or `SQL injection` and `XSS` on the same URL, stay
separate entries.

Measured on a real Metasploitable 2 run: **16 raw findings became 7 distinct
ones**, with all 7 genuinely different.

### Versioned service detection

The single biggest efficacy factor. `nmap -sV` returns `vsftpd 2.3.4` or
`Metasploitable root shell`, which map directly to CVEs. The Red Agent's prompt
now makes `check_tool` -> `run_tool <scanner>` the first move on a network
target, before any HTTP probing:

```text
run_tool  nmap -Pn -sV -p <ports> <host>
run_tool  nmap --script vuln -p <ports> <host>
run_tool  nikto -h http://<host>
run_tool  nuclei -u http://<host> -severity critical,high
```

### Validated, not guessed

A version banner is a lead; a pentest *proves* the flaw. The Red Agent has
validators that trigger the vulnerability, observe a benign side effect and
clean up:

| Validator | Proves | How |
| --- | --- | --- |
| `validate_vsftpd_backdoor` | CVE-2011-2523 | Sends the `:)` trigger and checks whether TCP/6200 opens. Runs nothing on the shell. |
| `validate_root_shell` | Unauthenticated shell | Reads the prompt (`root@host:/#`), disconnects. |
| `validate_samba_usermap` | CVE-2007-2447 | Passes an `echo` canary through the username and looks for it in the reply. |
| `validate_mysql_blank_password` | Exposed database | Parses the handshake version, returns the exact confirming command. |
| `validate_open_shell_port` | Any unauthenticated shell | Banner check with no command execution. |

Every one reports `validated: true/false` with raw evidence, and refuses to
claim success when it cannot observe the effect. Verified against a live
Metasploitable 2:

```text
1524 root shell  -> validated: True   confidence: high
                    evidence: returned a root shell prompt 'root@target:/#'
MySQL 3306       -> validated: True   version: 5.0.51a-3ubuntu5
vsftpd (port not reachable)
                 -> validated: False  "backdoor port stayed closed"
```

Findings carry `confidence: high` only when a validator confirmed them.

### Resilience

Long engagements used to die on a single provider hiccup. Now:

- **Retries with exponential backoff** on transient failures (429, 5xx,
  timeouts, resets). Permanent errors (401, 400, model not found) fail fast so
  the real cause surfaces. A stream that already produced content is never
  retried blindly.
- **Wall-clock deadline** (`run.max_duration_minutes`, default 90) so an
  engagement cannot hang forever; it stops cleanly with everything persisted.

```yaml
run:
  max_duration_minutes: 90

# global config
llm:
  max_retries: 3
  retry_initial_delay: 1.0
  retry_max_delay: 30.0
```

### Never run out of steps

Production runs used to end with `reached the step limit without a final
answer`: the agent burned its whole budget exploring and returned nothing.
The runtime now reserves the last `wrap_up_at` steps (default 3) and injects a
mandatory wrap-up instruction:

```
You are almost out of steps (3 left of 20).
STOP exploring. Do this now, in this order:
1. Persist every weakness you have already confirmed with record_finding…
2. Save your working state with workspace_write to notes/<scope>-state.md…
3. Reply with a concise markdown summary…
```

If even that turn produces no text, `_fallback_summary()` builds one from the
persisted state (findings, tool calls, remaining task list) instead of a bare
error line. The `agent.wrap_up` event drives the UI phase indicator.

Configure it under `agents`:

```yaml
agents:
  red:
    wrap_up_at: 3     # steps reserved for persisting + summarising (0 = off)
```

### Plan-before-you-scan

The Red Agent's prompt mandates a planning phase **before launching anything**:

1. `workspace_info` — what tooling and package managers exist.
2. `read_shared_context` + `list_findings` — what is already known.
3. Write `notes/<topic>.md`, then register the plan with `todowrite`, covering:
   - which mapping technique fits the target (passive vs active, web vs network
     vs API) and why;
   - which tools answer the question with the fewest requests (reuse before
     installing);
   - **how to avoid being blocked** — realistic User-Agent and headers,
     throttling and jitter, low thread counts, limited port ranges,
     retry-with-backoff, rate limits;
   - the fallback when a control blocks you (WAF, 403/429, connection resets):
     change technique or slow down rather than brute-forcing through.

**Red** — `dns_lookup`, `port_scan`, `http_request`, `audit_security_headers`,
`probe_paths`, `crawl`, `test_sql_injection`, `test_xss`,
`test_path_traversal`, `test_open_redirect`, `test_command_injection`,
`test_cors`, `test_http_methods`, `test_directory_listing`.

**Blue** — `analyze_logs`, `generate_firewall_rule`, `harden_headers`,
`suggest_patch`, `verify_control`.

All probes are non-destructive: they inject benign markers and inspect the
response. No tool deletes data, writes files on the target or opens a shell.

---

## Reports

Each session produces:

- **Markdown** — portable, versionable.
- **HTML** — a standalone dark-themed document (OpenCode palette).
- **JSON** — machine-readable, including metrics and the full session state.

Findings carry a CVSS v3.1 vector and score, evidence, confidence, the round
they were discovered in, and the mitigations that address them. A **resilience
score** (0–100) summarises how much of the discovered attack surface has been
mitigated.

---

## Responsible use

SplitAgent is for **authorised security testing only**. You must have explicit
permission to test the target. The framework enforces the configured `scope`
and refuses out-of-scope hosts; safe mode is on by default. The authors accept
no liability for misuse.

---

## Development

```bash
pip install -e ".[dev]"
pre-commit install     # lint, format and a secret scan on every commit
pytest
ruff check splitagent tests
ruff format splitagent tests
```

CI runs lint, the full test suite on Linux/Windows/macOS across Python
3.10-3.12, and builds the distribution to confirm the web assets ship in the
wheel. A pre-commit hook refuses to commit anything that looks like a real
provider key.

Tests cover CVSS scoring, configuration, encrypted context, tools (with a local
HTTP server), the full engine loop and the desktop pipeline (against a mock LLM
API) and the TUI.

---

## License

MIT © SplitAgent Contributors
