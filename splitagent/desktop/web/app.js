/* SplitAgent desktop front-end. */

const state = {
  bootstrap: null,
  config: {},
  project: {},
  findings: [],
  mitigations: [],
  running: false,
  chatting: false,
  mode: "audit",
  round: 0,
  totalRounds: 0,
  rounds: [],
  phase: "idle",
  resilience: 100,
  events: 0,
  reportPaths: [],
  currentMsg: {},
  rawText: {},
  tools: {},
  thinking: { red: "", blue: "", assistant: "" },
  runningTools: { red: 0, blue: 0, assistant: 0 },
  toolLog: { red: [], blue: [], assistant: [] },
  chatTurns: 0,
  models: [],
  modelsLoaded: false,
  palette: { items: [], index: 0, filtered: [], onPick: null },
  wizard: { step: 0, kind: "web", depth: "standard" },
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function reportJsError(message) {
  try {
    if (window.pywebview && window.pywebview.api && window.pywebview.api.log_js_error) {
      window.pywebview.api.log_js_error(String(message));
    }
  } catch (err) {
    /* ignore */
  }
}
window.addEventListener("error", (e) =>
  reportJsError(`${e.message} @ ${e.filename}:${e.lineno}:${e.colno}`)
);
window.addEventListener("unhandledrejection", (e) => reportJsError(`unhandled: ${e.reason}`));

// Drives the live response timers.
setInterval(() => {
  Object.keys(state.currentMsg || {}).forEach((agent) => {
    const wrap = state.currentMsg[agent];
    if (!wrap) return;
    const el = wrap.querySelector(".msg-timer");
    if (!el || !el.classList.contains("running")) return;
    const seconds = (Date.now() - Number(el.dataset.start || Date.now())) / 1000;
    el.textContent = `Thinking… ${seconds.toFixed(1)}s`;
  });
}, 100);

const AGENTS = {
  red: { name: "Red Agent", cls: "red" },
  blue: { name: "Blue Agent", cls: "blue" },
  assistant: { name: "Copilot", cls: "accent" },
  core: { name: "System", cls: "core" },
};

/* ── bridge ─────────────────────────────────────────────── */
function api(name, ...args) {
  return new Promise((resolve) => {
    if (!window.pywebview || !window.pywebview.api || !window.pywebview.api[name]) {
      resolve({ ok: false, error: "bridge not ready" });
      return;
    }
    try {
      Promise.resolve(window.pywebview.api[name](...args)).then(resolve, (err) =>
        resolve({ ok: false, error: String(err) })
      );
    } catch (err) {
      resolve({ ok: false, error: String(err) });
    }
  });
}

/* ── helpers ────────────────────────────────────────────── */
function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function md(src) {
  if (!src) return "";
  const blocks = [];
  let text = String(src).replace(/```[^\n]*\n?([\s\S]*?)```/g, (m, code) => {
    blocks.push(code.replace(/\n$/, ""));
    return `\u0000B${blocks.length - 1}\u0000`;
  });
  text = escapeHtml(text);
  text = text.replace(/^###\s?(.*)$/gm, "<h3>$1</h3>");
  text = text.replace(/^##\s?(.*)$/gm, "<h2>$1</h2>");
  text = text.replace(/^#\s?(.*)$/gm, "<h1>$1</h1>");
  text = text.replace(/`([^`]+)`/g, "<code>$1</code>");
  text = text.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" data-external="$2">$1</a>');
  text = text.replace(/(?:^|\n)((?:[-*]\s.+\n?)+)/g, (m, group) => {
    const items = group
      .trim()
      .split("\n")
      .map((line) => `<li>${line.replace(/^[-*]\s/, "")}</li>`)
      .join("");
    return `\n<ul>${items}</ul>`;
  });
  text = text
    .split(/\n{2,}/)
    .map((chunk) => {
      if (/^\s*<(h[1-3]|ul|pre|blockquote)/.test(chunk) || /^\u0000B\d+\u0000\s*$/.test(chunk.trim())) {
        return chunk;
      }
      return `<p>${chunk.replace(/\n/g, "<br>")}</p>`;
    })
    .join("");
  text = text.replace(/\u0000B(\d+)\u0000/g, (m, i) => `<pre><code>${escapeHtml(blocks[Number(i)])}</code></pre>`);
  return text;
}

function nowTime() {
  return new Date().toTimeString().slice(0, 8);
}

let toastTimer = null;
function toast(message, isError = false) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.toggle("err", !!isError);
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 3200);
}

/* ── mode ───────────────────────────────────────────────── */
function setMode(mode) {
  state.mode = mode;
  $$("#mode-switch .mode-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.mode === mode)
  );
  $("#view-audit").classList.toggle("hidden", mode !== "audit");
  $("#view-chat").classList.toggle("hidden", mode !== "chat");
  $("#st-mode").textContent = mode;
}

/* ── pinned activity feed ───────────────────────────────────
   The Thinking / Exploring / working hints must always sit at the bottom of
   the stream, right under the latest content, instead of scrolling away above
   a long message. We keep one sticky container per stream and park the
   activity lines in it. */
function activityHostFor(agent) {
  const stream = streamFor(agent);
  let host = stream.querySelector(".activity-host");
  if (!host) {
    host = document.createElement("div");
    host.className = "activity-host";
    stream.appendChild(host);
  }
  stream.appendChild(host); // hoist to the very end
  return host;
}

/* ── stream routing ─────────────────────────────────────── */
function streamFor(agent) {
  return agent === "assistant" ? $("#chat-stream") : $("#stream");
}
function scrollStream(agent) {
  const el = streamFor(agent);
  el.scrollTop = el.scrollHeight;
}
function clearEmptyFor(agent) {
  const id = agent === "assistant" ? "#chat-empty" : "#stream-empty";
  const el = $(id);
  if (el) el.remove();
}

function addDivider(agent, label) {
  finalize(agent);
  clearEmptyFor(agent);
  const div = document.createElement("div");
  div.className = `divider ${AGENTS[agent] ? AGENTS[agent].cls : "core"}`;
  div.innerHTML = `<span class="tag">${escapeHtml(label)}</span>`;
  streamFor(agent).appendChild(div);
  scrollStream(agent);
}

function ensureMsg(agent) {
  if (state.currentMsg[agent]) return state.currentMsg[agent];
  clearEmptyFor(agent);
  const meta = AGENTS[agent] || AGENTS.core;
  const wrap = document.createElement("div");
  wrap.className = "msg";
  wrap.innerHTML = `
    <div class="msg-head">
      <span class="msg-name ${meta.cls}">${meta.name}</span>
      <span class="msg-time">${nowTime()}</span>
    </div>
    <div class="msg-body"></div>`;
  streamFor(agent).appendChild(wrap);
  state.currentMsg[agent] = wrap;
  state.rawText[agent] = "";
  startTimer(agent);
  return wrap;
}

function appendText(agent, text) {
  const wrap = ensureMsg(agent);
  state.rawText[agent] += text;
  $(".msg-body", wrap).textContent = state.rawText[agent];
  scrollStream(agent);
}

function finalize(agent) {
  const wrap = state.currentMsg[agent];
  if (!wrap) return;
  $(".msg-body", wrap).innerHTML = md(state.rawText[agent]);
  stopTimer(agent);
  state.currentMsg[agent] = null;
  state.rawText[agent] = "";
}

/* One activity line per agent. The screen must never fill with "Thinking" and
   "Exploring" at once: a single line flips between them depending on what the
   agent is doing right now. The full reasoning stays available behind the
   chevron. */
function setActivity(agent, mode, text) {
  const host = activityHostFor(agent);
  let line = $("#thinking-" + agent, host);
  if (!line) {
    line = document.createElement("div");
    line.id = "thinking-" + agent;
    line.className = "thinking-line";
    line.innerHTML = `
      <span class="tl-label">Thinking</span>
      <span class="tl-text shimmer"></span>
      <span class="tl-chevron">\u203a</span>`;
    line.addEventListener("click", () => {
      const body = $("#thinking-body-" + agent, host);
      if (!body) return;
      const shown = body.classList.toggle("show");
      line.querySelector(".tl-chevron").textContent = shown ? "\u203e" : "\u203a";
    });
    clearEmptyFor(agent);
    host.appendChild(line);
    const body = document.createElement("div");
    body.id = "thinking-body-" + agent;
    body.className = "thinking-body";
    host.appendChild(body);
  }
  const label = $(".tl-label", line);
  const body = $(".tl-text", line);
  label.textContent = mode;
  label.classList.toggle("shimmer", true);
  body.classList.toggle("shimmer", true);
  if (text != null) body.textContent = text;
  line.classList.add("busy");
  line.dataset.mode = mode;
  scrollStream(agent);
}

function addThinking(agent, text) {
  if (!text) return;
  state.thinking[agent] = (state.thinking[agent] || "") + text;
  // Keep the freshest line as the visible excerpt, and let Exploring win while
  // tools are actually running.
  const heading = text.trim().split("\n").filter(Boolean).pop() || "Thinking";
  const running = (state.runningTools[agent] || 0) > 0;
  setActivity(agent, running ? "Exploring" : "Thinking", running ? "running tools…" : heading.slice(-150));
  const host = activityHostFor(agent);
  const body = $("#thinking-body-" + agent, host);
  if (body) body.textContent = state.thinking[agent];
}

function finalizeThinking(agent) {
  clearWorking(agent);
  const parent = streamFor(agent);
  const line = $("#thinking-" + agent, parent);
  if (!line) return;
  const host = parent.querySelector(".activity-host");
  if (!host || !host.contains(line)) return;
  line.classList.remove("busy");
  $(".tl-label", line).textContent = "Thought";
  const label = $(".tl-label", line);
  const text = $(".tl-text", line);
  if (label) label.classList.remove("shimmer");
  if (text) text.classList.remove("shimmer");
  state.thinking[agent] = "";
}

/* Grouped "Exploring · 3 reads, 1 search" surface, exactly like OpenCode:
   one collapsible header per tool group; individual calls only appear when
   the group is expanded. */
function toolVerb(name) {
  if (/(scan|recon|dns|port)/.test(name)) return { group: "Recon", noun: "scan" };
  if (/(http|audit|crawl|probe|request)/.test(name)) return { group: "Web", noun: "request" };
  if (/(test_|exploit)/.test(name)) return { group: "Probes", noun: "test" };
  if (/(log|harden|firewall|patch|verify)/.test(name)) return { group: "Defence", noun: "control" };
  if (/(finding|mitigation|context)/.test(name)) return { group: "Context", noun: "note" };
  return { group: "Tools", noun: "call" };
}

function updateRunSummary(agent) {
  clearEmptyFor(agent);
  const host = activityHostFor(agent);
  let el = $("#run-summary-" + agent, host);
  if (!el) {
    el = document.createElement("div");
    el.id = "run-summary-" + agent;
    el.className = "run-summary";
    el.innerHTML = `
      <span class="rs-title">
        <span class="rs-label"></span>
        <span class="rs-counts"></span>
      </span>
      <span class="rs-chevron">\u203a</span>`;
    el.addEventListener("click", () => {
      el.classList.toggle("open");
      const log = $("#rs-log-" + agent, host);
      if (log) log.classList.toggle("show", el.classList.contains("open"));
    });
    host.appendChild(el);
    const log = document.createElement("div");
    log.id = "rs-log-" + agent;
    log.className = "rs-log";
    host.appendChild(log);
  }

  const running = state.runningTools[agent] || 0;
  const log = state.toolLog[agent] || [];
  const counts = {};
  log.forEach((name) => {
    const { noun } = toolVerb(name);
    counts[noun] = (counts[noun] || 0) + 1;
  });
  const summary = Object.entries(counts)
    .map(([noun, n]) => `${n} ${noun}${n === 1 ? "" : "s"}`)
    .join(", ");
  const label = running > 0 ? "Exploring" : "Explored";
  // When tools finish, the same activity line flips back to Thinking.
  if (running === 0) {
    const line = $("#thinking-" + agent, activityHostFor(agent));
    if (line) {
      $(".tl-label", line).textContent = "Thinking";
      $(".tl-text", line).textContent = "considering next steps…";
    }
  }

  $(".rs-label", el).textContent = label;
  $(".rs-counts", el).textContent = summary ? " · " + summary : "";
  el.classList.toggle("busy", running > 0);

  scrollStream(agent);
}

function addTool(agent, data) {
  finalize(agent);
  clearEmptyFor(agent);
  const block = document.createElement("div");
  block.className = "tool";
  const args = JSON.stringify(data.arguments || {});
  const now = nowTime();
  block.innerHTML = `
    <div class="tool-head">
      <span class="tool-status running"></span>
      <span class="tool-name">${escapeHtml(data.tool || "tool")}</span>
      <span class="tool-args">${escapeHtml(args.length > 160 ? args.slice(0, 160) + "..." : args)}</span>
      <span class="tool-count">${escapeHtml(now)}</span>
      <span class="tool-chevron">\u203a</span>
    </div>
    <div class="tool-body"><pre class="tool-out">running...</pre></div>`;
  const callKey = data.call_id || Math.random().toString(36);
  state.tools[callKey] = block;
  // Detail lives inside the collapsed group, never directly in the timeline.
  block.classList.add("hidden");
  const groupItem = document.createElement("div");
  groupItem.className = "rs-log-item";
  groupItem.dataset.call = callKey;
  const compactArgs = compactJson(data.arguments || {});
  groupItem.innerHTML = `
    <div class="rs-log-row">
      <span class="tool-status running"></span>
      <span class="rs-log-name">${escapeHtml(data.tool || "tool")}</span>
      <span class="rs-log-args">${escapeHtml(compactArgs)}</span>
      <span class="rs-log-chevron">\u203a</span>
    </div>
    <div class="rs-log-detail"></div>`;
  $(".rs-log-row", groupItem).addEventListener("click", (e) => {
    e.stopPropagation();
    groupItem.classList.toggle("open");
    const detail = $(".rs-log-detail", groupItem);
    const card = state.tools[callKey];
    if (card) card.classList.toggle("open", groupItem.classList.contains("open"));
    if (detail.classList.contains("show")) {
      detail.classList.remove("show");
      if (card) card.remove();
    } else {
      detail.classList.add("show");
      if (card) detail.appendChild(card);
    }
  });
  getRsLog(agent).appendChild(groupItem);
  state.runningTools[agent] = (state.runningTools[agent] || 0) + 1;
  state.toolLog[agent] = [...(state.toolLog[agent] || []), data.tool || "tool"];
  updateRunSummary(agent);
  scrollStream(agent);
}

function compactJson(value) {
  const text = JSON.stringify(value || {});
  return text === "{}" ? "" : text.length > 120 ? text.slice(0, 120) + "..." : text;
}

/* The group container is created once per agent; its contents are populated
   incrementally so the timeline stays compact. */
function getRsLog(agent) {
  const parent = streamFor(agent);
  let log = $("#rs-log-" + agent, parent);
  if (!log) {
    updateRunSummary(agent);
    log = $("#rs-log-" + agent, parent);
  }
  return log;
}

function finishTool(agent, data) {
  const block = state.tools[data.call_id];
  if (!block) return;
  const status = $(".tool-status", block);
  const out = $(".tool-out", block);
  const text = String(data.output == null ? "" : data.output);
  const isError = /"error"|^\s*error|Traceback|out_of_scope/.test(text.slice(0, 120));
  status.className = "tool-status " + (isError ? "error" : "done");
  status.textContent = isError ? "!" : "\u2713";
  out.textContent = text;
  // Mirror the state on the group row.
  const row = document.querySelector(
    `.rs-log-item[data-call="${CSS.escape(String(data.call_id || ""))}"]`
  );
  if (row) {
    const rowStatus = $(".tool-status", row);
    rowStatus.className = "tool-status " + (isError ? "error" : "done");
    rowStatus.textContent = isError ? "!" : "\u2713";
    row.classList.toggle("error", isError);
  }
  state.runningTools[agent] = Math.max(0, (state.runningTools[agent] || 0) - 1);
  updateRunSummary(agent);
}

function addInlineFinding(data) {
  const parent = streamFor("red");
  clearEmptyFor("red");
  const card = document.createElement("div");
  card.className = `inline-finding ${data.severity || "info"}`;
  card.innerHTML = `
    <div class="if-head">
      <span class="sev ${data.severity || "info"}">${(data.severity || "info").toUpperCase()}</span>
      <span class="if-title">${escapeHtml(data.title || "")}</span>
    </div>
    <div class="if-meta">${escapeHtml(data.id || "")}</div>`;
  parent.appendChild(card);
  parent.scrollTop = parent.scrollHeight;
}

function addCompactionCard(data) {
  clearEmptyFor("red");
  finalize("red");
  const el = document.createElement("div");
  el.className = "compaction";
  el.innerHTML = `
    <div class="cp-head">
      <span class="cp-badge">CONTEXT CHECKPOINT</span>
      <span class="cp-meta">compacted ~${data.removed} tokens · kept ~${data.preserved}</span>
    </div>
    <pre class="cp-summary">${escapeHtml(data.summary || "")}</pre>
    <div class="cp-note">Earlier details are cleared from the model context but remain in the full trace and session file.</div>`;
  streamFor("red").appendChild(el);
  streamFor("red").scrollTop = streamFor("red").scrollHeight;
}

function addTrace(kind, data) {
  state.trace = state.trace || [];
  state.trace.push({ kind, data, ts: nowTime() });
  if (state.trace.length > 400) state.trace.shift();
  renderTrace();
}

function traceDetail(kind, data) {
  if (kind === "tool_call") {
    return `${data.tool}(${JSON.stringify(data.arguments || {})})`;
  }
  if (kind === "tool_result") {
    return String(data.output || "");
  }
  if (kind === "context") {
    return `estimated ${data.estimated} / usable ${data.usable} tokens (${data.percent}%) · messages ${data.messages}`;
  }
  if (kind === "usage") {
    return Object.entries(data)
      .map(([k, v]) => `${k}=${v}`)
      .join("  ");
  }
  if (kind === "prune") {
    return `freed ~${data.removed} tokens · protected ${data.protected}`;
  }
  if (kind === "compaction") {
    return `removed ~${data.removed} · preserved ~${data.preserved}\n${data.summary || ""}`;
  }
  return JSON.stringify(data || {});
}

function renderTrace() {
  const panel = $("#panel-trace");
  const body = panel.querySelector(".trace-list");
  const trace = state.trace || [];
  if (!trace.length) {
    if (!panel.querySelector(".trace-empty")) {
      const empty = document.createElement("div");
      empty.className = "trace-empty";
      empty.textContent = "Nothing captured yet.";
      panel.appendChild(empty);
    }
    return;
  }
  const emptyEl = panel.querySelector(".trace-empty");
  if (emptyEl) emptyEl.remove();
  let list = body;
  if (!list) {
    list = document.createElement("div");
    list.className = "trace-list";
    panel.appendChild(list);
  }
  // Append only the newest entry (keeps rendering cheap during a run).
  const entry = trace[trace.length - 1];
  if (list.childElementCount === trace.length) return;
  const el = document.createElement("div");
  el.className = `trace-item kind-${entry.kind}`;
  el.innerHTML = `
    <div class="ti-head">
      <span class="ti-kind">${escapeHtml(entry.kind)}</span>
      <span class="ti-time">${escapeHtml(entry.ts)}</span>
    </div>
    <pre>${escapeHtml(traceDetail(entry.kind, entry.data))}</pre>`;
  list.appendChild(el);
  panel.scrollTop = panel.scrollHeight;
}

async function dumpTrace() {
  const text = JSON.stringify(
    {
      session: state.sessionId || null,
      policy: state.policy || null,
      context: state.context || null,
      trace: state.trace || [],
    },
    null,
    2
  );
  const res = await api("save_trace", text);
  if (res && res.ok) {
    toast("Trace saved");
    api("reveal", res.path);
  } else {
    toast((res && res.error) || "could not save trace", true);
  }
}

/* ── Workspace ──────────────────────────────────────────── */
function renderWorkspace(data) {
  if (!data) return;
  state.workspace = data;
  const name = String(data.root || "").split(/[\\/]/).filter(Boolean).pop() || "workspace";
  $("#ws-name").textContent = name;
  const counts = data.file_counts || {};
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  $("#ws-badge").textContent = `${total} files`;
  $("#btn-workspace").title = `${data.root}\ninstallers: ${(data.installers || []).join(", ") || "none"}`;
}

async function openWorkspace() {
  const res = await api("workspace_open");
  if (!res || !res.ok) {
    toast((res && res.error) || "could not open the workspace", true);
    return;
  }
  const info = await api("workspace_info");
  if (info && info.ok) renderWorkspace(info);
  toast("Workspace opened");
}

/* ── Toolbox ────────────────────────────────────────────── */
function renderToolbox(status) {
  if (!status) return;
  state.toolbox = status;
  const container = status.container || "toolbox";
  $("#tb-name").textContent = container;
  const badge = $("#tb-badge");
  if (status.running) {
    const count = Object.values(status.tools || {}).filter(Boolean).length;
    badge.textContent = `${count} tools`;
    badge.className = "ws-badge on";
  } else if (status.usable && status.image) {
    badge.textContent = "stopped";
    badge.className = "ws-badge off";
  } else if (!status.docker_cli) {
    badge.textContent = "no docker";
    badge.className = "ws-badge off";
  } else {
    badge.textContent = "not built";
    badge.className = "ws-badge off";
  }
  $("#btn-toolbox").title =
    `mode ${status.effective_mode} · ${status.message}` +
    (status.edition ? `\nedition ${status.edition}` : "");
}

async function refreshToolbox() {
  const res = await api("toolbox_status");
  if (res && res.ok) renderToolbox(res.status);
  return res && res.status;
}

function fillToolboxDialog(status) {
  if (!status) return;
  const set = (id, text, cls = "") => {
    const el = $(id);
    if (!el) return;
    el.textContent = text;
    el.className = cls;
  };
  set("#tb-docker", status.docker_cli ? "installed" : "not found", status.docker_cli ? "ok" : "bad");
  set("#tb-daemon", status.daemon ? "running" : "stopped", status.daemon ? "ok" : "bad");
  set("#tb-image", status.image ? "built" : "not built", status.image ? "ok" : "bad");
  set("#tb-workspace", status.workspace || "—");
  $("#tb-edition").value = status.edition || "standard";
  const hint = $("#tb-hint");
  if (!status.docker_cli) {
    hint.textContent =
      "Docker was not found. Install Docker Desktop, then reopen this dialog to " +
      "enable the isolated environment. Until then the agents run in local mode.";
  } else if (!status.daemon) {
    hint.textContent =
      "Docker is installed but not running. SplitAgent will start it for you.";
  } else {
    hint.textContent =
      "The image is built once. After that the toolbox starts silently in the " +
      "background and you never have to touch Docker again.";
  }
  $("#tb-install").disabled = !status.docker_cli || !!state.toolboxBusy;
  $("#tb-install").dataset.noDocker = status.docker_cli ? "0" : "1";
}

async function openToolboxDialog() {
  closeModals();
  openModal("#modal-toolbox");
  $("#tb-progress").textContent = "";
  $("#tb-progress").className = "test-result";
  const status = await refreshToolbox();
  fillToolboxDialog(status);
}

function setToolboxBusy(busy) {
  state.toolboxBusy = busy;
  const install = $("#tb-install");
  const skip = $("#tb-skip");
  if (install) install.disabled = busy || install.dataset.noDocker === "1";
  if (skip) skip.disabled = busy;
  const badge = $("#tb-badge");
  if (badge && busy) {
    badge.textContent = "setting up…";
    badge.className = "ws-badge off";
  }
}

async function installToolbox() {
  const progress = $("#tb-progress");
  progress.textContent = "starting…";
  progress.className = "test-result";
  setToolboxBusy(true);
  const res = await api("toolbox_setup", {
    edition: $("#tb-edition").value,
    build: true,
  });
  // The work happens in a worker thread; progress arrives via events.
  if (!res || !res.ok) {
    setToolboxBusy(false);
    progress.textContent = (res && res.error) || "setup failed";
    progress.className = "test-result bad";
    toast((res && res.error) || "toolbox setup failed", true);
  }
}

async function toolboxAction(action) {
  const res = await api("toolbox_action", action);
  if (res && res.async) {
    setToolboxBusy(true);
    toast(`Toolbox ${action}…`);
    return;
  }
  await refreshToolbox();
  if (res && res.ok) toast(`Toolbox ${action} ok`);
  else if (res && res.error) toast(res.error, true);
}

function onToolboxProgress(data) {
  const progress = $("#tb-progress");
  const text = data.text || data.stage;
  if (progress) {
    progress.textContent = text;
    progress.className = "test-result";
  }
  const badge = $("#tb-badge");
  if (badge) {
    badge.textContent = data.stage === "build" ? "building…" : "starting…";
    badge.className = "ws-badge off";
  }
  addActivity(`toolbox: ${text}`);
}

function onToolboxReady(status) {
  setToolboxBusy(false);
  if (status) {
    renderToolbox(status);
    fillToolboxDialog(status);
  }
  const progress = $("#tb-progress");
  if (progress) {
    progress.textContent = "Ready — the agents now run isolated.";
    progress.className = "test-result ok";
  }
  addActivity(
    `toolbox ready (${status?.edition || "?"}, ${status?.container || "?"})`
  );
  toast("Isolated environment ready");
  setTimeout(closeModals, 1400);
}

function onToolboxFailed(data) {
  setToolboxBusy(false);
  const progress = $("#tb-progress");
  const message = (data && data.error) || "setup failed";
  if (progress) {
    progress.textContent = message;
    progress.className = "test-result bad";
  }
  addActivity(`toolbox error: ${message}`, true);
  if (data && data.output) addActivity(data.output.slice(-1200), true);
  toast(message, true);
  refreshToolbox();
}

/* ── Todo dock ──────────────────────────────────────────── */
function renderTodos(todos) {
  state.todos = todos || [];
  const dock = $("#todo-dock");
  if (!dock) return;
  if (!state.todos.length) {
    dock.classList.add("hidden");
    return;
  }
  dock.classList.remove("hidden");
  const done = state.todos.filter((t) => t.status === "completed").length;
  const total = state.todos.length;
  $("#td-done").textContent = done;
  $("#td-total").textContent = total;
  const active =
    state.todos.find((t) => t.status === "in_progress") ||
    state.todos.find((t) => t.status === "pending") ||
    [...state.todos].reverse().find((t) => t.status === "completed") ||
    state.todos[0];
  $("#td-preview").textContent = dock.classList.contains("collapsed")
    ? (active && active.content) || ""
    : "";
  $("#td-list").innerHTML = state.todos
    .map(
      (todo) => `
      <div class="todo-item" data-state="${escapeHtml(todo.status)}">
        <span class="todo-box">
          ${
            todo.status === "in_progress"
              ? '<svg class="todo-spinner" viewBox="0 0 12 12" width="10" height="10" fill="currentColor"><circle cx="6" cy="6" r="3"/></svg>'
              : '<svg class="todo-tick" viewBox="0 0 12 12" width="10" height="10"><path d="M2.5 6.2 4.6 8.3 9.5 3.6" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>'
          }
        </span>
        <span class="todo-text">${escapeHtml(todo.content)}</span>
      </div>`
    )
    .join("");
}

function toggleTodoDock() {
  const dock = $("#todo-dock");
  dock.classList.toggle("collapsed");
  renderTodos(state.todos || []);
}

/* ── Dynamic working state ──────────────────────────────── */
function setWorking(agent, step, maxSteps) {
  state.working = state.working || {};
  state.working[agent] = { step, maxSteps };
  // Reuse the single activity line; never stack a second one.
  const running = (state.runningTools[agent] || 0) > 0;
  setActivity(
    agent,
    running ? "Exploring" : "Thinking",
    running ? "running tools…" : "considering next steps…"
  );
}

function clearWorking(agent) {
  // No separate working line exists any more; kept for call-site compatibility.
  void agent;
}

/* ── response timer (Grok-style) ──────────────────────────
   A small live counter under the header of the message that is currently
   streaming: "Thinking… 3.4s" while it works, frozen to "+3.4s" when done. */
function startTimer(agent) {
  const wrap = state.currentMsg[agent];
  if (!wrap) return;
  const head = $(".msg-head", wrap);
  if (!head || $(".msg-timer", head)) return;
  const el = document.createElement("span");
  el.className = "msg-timer running";
  el.textContent = "Thinking… 0.0s";
  el.dataset.start = Date.now();
  head.appendChild(el);
}

function stopTimer(agent) {
  const wrap = state.currentMsg[agent];
  if (!wrap) return;
  const el = $(".msg-timer", wrap);
  if (!el) return;
  const seconds = Math.max(0, (Date.now() - Number(el.dataset.start || Date.now())) / 1000);
  el.classList.remove("running");
  el.textContent = `+${seconds.toFixed(1)}s`;
}

function updateContextMeter() {
  const ctx = state.context;
  const el = $("#st-context");
  if (!el) return;
  if (!ctx) {
    el.textContent = "context —";
    return;
  }
  el.textContent = `ctx ${ctx.percent}%`;
  el.className = "st " + (ctx.percent >= 90 ? "warn" : ctx.percent >= 70 ? "mid" : "");
}

/* ── Dashboard: the at-a-glance result of the engagement ────
   Rendered from live session state; no chart library, just CSS
   bars and dots. It becomes the active tab when an audit ends. */

const SEVERITY_META = {
  critical: { label: "Critical", color: "var(--red-strong)", order: 0 },
  high: { label: "High", color: "var(--orange)", order: 1 },
  medium: { label: "Medium", color: "var(--yellow)", order: 2 },
  low: { label: "Low", color: "var(--green)", order: 3 },
  info: { label: "Info", color: "var(--cyan)", order: 4 },
};

function severityMeta(severity) {
  return SEVERITY_META[(severity || "info").toLowerCase()] || SEVERITY_META.info;
}

function worstSeverity(findings) {
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    if (findings.some((f) => (f.severity || "info").toLowerCase() === sev)) return sev;
  }
  return null;
}

function renderDashboard() {
  const panel = $("#panel-dashboard");
  if (!panel) return;

  const findings = state.findings || [];
  const mitigations = state.mitigations || [];

  if (!findings.length && !(state.rounds || []).length && !state.running) {
    panel.innerHTML =
      '<div class="panel-empty">Run an audit to see the results here.</div>';
    return;
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => {
    const sev = (f.severity || "info").toLowerCase();
    counts[counts[sev] === undefined ? "info" : sev] += 1;
  });

  const total = findings.length;
  const worst = worstSeverity(findings);
  const resilience = Math.round(state.resilience);
  const riskClass = !worst
    ? "ok"
    : worst === "critical"
      ? "bad"
      : worst === "high" || worst === "medium"
        ? "warn"
        : "ok";
  const riskLabel = !worst ? "No issues found" : `${severityMeta(worst).label} risk`;

  const sevRows = Object.keys(SEVERITY_META)
    .sort((a, b) => SEVERITY_META[a].order - SEVERITY_META[b].order)
    .map((sev) => {
      const count = counts[sev] || 0;
      const pct = total ? Math.round((count / total) * 100) : 0;
      return `
        <div class="sev-row">
          <span class="sev-name"><span class="sev-dot" style="background:${SEVERITY_META[sev].color}"></span>${SEVERITY_META[sev].label}</span>
          <span class="sev-bar"><i style="width:${pct}%;background:${SEVERITY_META[sev].color}"></i></span>
          <span class="sev-count">${count}</span>
        </div>`;
    })
    .join("");

  const top = [...findings]
    .sort(
      (a, b) =>
        severityMeta(a.severity).order - severityMeta(b.severity).order ||
        (b.cvss_score || 0) - (a.cvss_score || 0)
    )
    .slice(0, 6)
    .map((f) => {
      const sev = (f.severity || "info").toLowerCase();
      return `
        <div class="dash-finding">
          <span class="sev-dot" style="background:${severityMeta(sev).color}"></span>
          <span class="df-title">${escapeHtml(f.title || "Untitled")}</span>
          <span class="df-where">${escapeHtml(f.endpoint || f.target || "")}</span>
          <span class="df-cvss">${(f.cvss_score || 0).toFixed(1)}</span>
        </div>`;
    })
    .join("") || '<div class="panel-empty">No findings yet.</div>';

  const rounds = state.rounds || [];
  const timeline = rounds
    .map(
      (r) => `
      <div class="dash-round">
        <div class="dr-head">Round ${r.index}<span>${r.findings || 0} findings · ${r.mitigations || 0} mitigations</span></div>
      </div>`
    )
    .join("") || '<div class="panel-empty">No rounds recorded.</div>';

  panel.innerHTML = `
    <div class="dash-hero ${riskClass}">
      <div class="dh-risk">${escapeHtml(riskLabel)}</div>
      <div class="dh-metrics">
        <div class="dh-metric"><b>${total}</b><span>findings</span></div>
        <div class="dh-metric"><b>${mitigations.length}</b><span>mitigations</span></div>
        <div class="dh-metric"><b>${state.round || 0}<small>/${state.totalRounds || 0}</small></b><span>rounds</span></div>
        <div class="dh-metric"><b>${resilience}<small>%</small></b><span>protected</span></div>
      </div>
    </div>
    <div class="dash-section">
      <div class="dash-title">Severity distribution</div>
      ${sevRows}
    </div>
    <div class="dash-section">
      <div class="dash-title">Top findings</div>
      ${top}
    </div>
    <div class="dash-section">
      <div class="dash-title">Rounds</div>
      ${timeline}
    </div>`;
}

function focusTab(name) {
  const tab = $(`#review-tabs .rtab[data-tab="${name}"]`);
  if (!tab) return;
  $$(".rtab").forEach((t) => t.classList.remove("active"));
  $$(".rpanel").forEach((p) => p.classList.remove("active"));
  tab.classList.add("active");
  const panel = $("#panel-" + name);
  if (panel) panel.classList.add("active");
}

/* ── panels ─────────────────────────────────────────────── */
function addFinding(data) {
  state.findings.push(data);
  $("#count-findings").textContent = state.findings.length;
  const panel = $("#panel-findings");
  if ($(".panel-empty", panel)) $(".panel-empty", panel).remove();
  const el = document.createElement("div");
  el.className = `finding ${data.severity || "info"}`;
  el.innerHTML = `
    <div class="f-top">
      <span class="f-title">${escapeHtml(data.title || "")}</span>
      <span class="sev ${data.severity || "info"}">${(data.severity || "info").toUpperCase()}</span>
    </div>
    <div class="f-sub">${escapeHtml(data.id || "")} · open</div>`;
  panel.appendChild(el);
  addInlineFinding(data);
  state.findingIndex = state.findingIndex || {};
  state.findingIndex[data.id] = data;
  renderDashboard();
}

function addMitigation(data) {
  state.mitigations.push(data);
  renderDashboard();
  $("#count-mitigations").textContent = state.mitigations.length;
  const panel = $("#panel-mitigations");
  if ($(".panel-empty", panel)) $(".panel-empty", panel).remove();
  const el = document.createElement("div");
  el.className = "mitigation";
  el.innerHTML = `
    <div class="m-top">
      <span class="badge">${escapeHtml(data.kind || "config")}</span>
      <span class="m-title">${escapeHtml(data.title || "")}</span>
    </div>
    <div class="m-sub">${escapeHtml(data.finding_id || "")}</div>`;
  panel.appendChild(el);
}

function addActivity(text, isError = false) {
  const panel = $("#panel-activity");
  const el = document.createElement("div");
  el.className = "activity-line" + (isError ? " err" : "");
  el.textContent = text;
  panel.appendChild(el);
  panel.scrollTop = panel.scrollHeight;
}

function setPhase(phase) {
  state.phase = phase;
  $("#st-phase").textContent = phase;
}

function setRunning(running) {
  state.running = running;
  $("#btn-run").classList.toggle("hidden", running);
  $("#btn-stop").classList.toggle("hidden", !running);
  $("#objective").disabled = running;
}
function setChatting(chatting) {
  state.chatting = chatting;
  $("#chat-send").classList.toggle("hidden", chatting);
  $("#chat-stop").classList.toggle("hidden", !chatting);
  $("#chat-input").disabled = chatting;
}
function setResilience(value) {
  state.resilience = value;
  $("#st-resilience").textContent = Math.round(value);
  $("#res-bar").style.width = `${Math.max(0, Math.min(100, value))}%`;
  renderDashboard();
}

/* ── event handling ─────────────────────────────────────── */
function handleEvent(event) {
  state.events += 1;
  $("#st-events").textContent = `${state.events} events`;
  const { type, agent, data } = event;

  switch (type) {
    case "audit.start":
      resetStream();
      setRunning(true);
      setPhase("starting");
      break;
    case "audit.started":
      break;
      addActivity(`audit start · target ${data.target || "?"} · ${data.provider}/${data.model}`);
      break;
    case "session.start":
      state.totalRounds = data.rounds || state.totalRounds;
      setPhase("running");
      break;
    case "round.start":
      state.round = data.round || state.round;
      $("#st-round").textContent = `round ${state.round}/${data.total || state.totalRounds}`;
      addDivider("red", `Round ${data.round} · offence`);
      break;
    case "phase.start":
      setPhase(data.phase || type);
      addDivider(agent, `${AGENTS[agent] ? AGENTS[agent].name : agent} · ${data.phase || ""}`);
      break;
    case "phase.end":
      finalize(agent);
      finalizeThinking(agent);
      addActivity(`${agent} phase end · ${data.tool_calls || 0} tool calls`);
      break;
    case "agent.text":
      appendText(agent, data.text || "");
      break;
    case "agent.thinking":
      addThinking(agent, data.text || "");
      break;
    case "agent.tool_call":
      addTool(agent, data);
      addActivity(`${agent} -> ${data.tool}`);
      break;
    case "agent.tool_result":
      finishTool(agent, data);
      break;
    case "context.usage":
      state.context = data;
      updateContextMeter();
      addActivity(
        `context ${data.estimated}/${data.usable} tokens (${data.percent}%)` +
          (data.overflow ? " · overflow" : "")
      );
      break;
    case "context.optimize":
      state.savedTokens = (state.savedTokens || 0) + Number(data.saved || 0);
      if (data.saved) {
        addActivity(
          `context optimised · saved ~${data.saved} tokens ` +
            `(reasoning ${data.reasoning}, snapshots ${data.stateful}, output ${data.pruned})`
        );
      }
      addTrace("optimize", data);
      break;
    case "agent.wrap_up":
      setPhase("wrapping up");
      addActivity(
        `agent wrap-up · ${data.remaining} steps left — persisting findings and summarising`
      );
      addTrace("wrap_up", data);
      break;
    case "context.compaction":
      addCompactionCard(data);
      addActivity(`compaction · removed ~${data.removed} tokens`);
      addTrace("compaction", data);
      break;
    case "checkpoint":
      addTrace("checkpoint", data);
      break;
    case "context.policy":
      state.policy = data;
      updateContextMeter();
      addActivity(
        `context window ${data.context_limit} · usable ${data.usable} · prune ${data.prune ? "on" : "off"}`
      );
      break;
    case "usage":
      addTrace("usage", data);
      break;
    case "todos":
      renderTodos(data.todos || []);
      addActivity(`task list updated · ${(data.todos || []).length} items`);
      break;
    case "workspace":
      state.workspace = data;
      renderWorkspace(data);
      addActivity(`workspace ${data.root}`);
      break;
    case "toolbox":
      if (data.status) renderToolbox({ ...data.status, effective_mode: data.active ? "toolbox" : data.mode });
      addActivity(
        `toolbox ${data.active ? "active" : "inactive"} · edition ${data.edition} · mode ${data.mode}` +
          (data.error ? ` · ${data.error}` : "")
      );
      break;
    case "toolbox.progress":
      onToolboxProgress(data);
      break;
    case "toolbox.ready":
      onToolboxReady(data);
      break;
    case "toolbox.failed":
      onToolboxFailed(data);
      break;
    case "agent.working":
      setWorking(agent, data.step, data.max_steps);
      break;
    case "finding":
      addFinding(data);
      addActivity(`finding ${data.id}: ${data.title} [${data.severity}]`);
      break;
    case "mitigation":
      addMitigation(data);
      addActivity(`mitigation ${data.id} (${data.kind}) for ${data.finding_id}`);
      break;
    case "round.end":
      setResilience(Number(data.resilience || state.resilience));
      state.rounds.push({
        index: data.round,
        findings: data.findings,
        mitigations: data.mitigations,
      });
      renderDashboard();
      addActivity(`round ${data.round} end · ${data.findings} findings · ${data.mitigations} mitigations`);
      break;
    case "log":
      addActivity(data.text || "");
      break;
    case "error":
      addActivity(`error: ${data.text || ""}`, true);
      toast(data.text || "error", true);
      break;
    case "session.end":
      setResilience(Number(data.resilience || state.resilience));
      finalize("red");
      finalize("blue");
      finalizeThinking("red");
      finalizeThinking("blue");
      break;
    case "audit.end":
      setRunning(false);
      setPhase(data.ok ? "done" : "failed");
      finalize("red");
      finalize("blue");
      finalizeThinking("red");
      finalizeThinking("blue");
      if (data.ok) {
        state.reportPaths = data.reports || [];
        $("#btn-open-reports").disabled = state.reportPaths.length === 0;
        addActivity(`audit complete · session ${data.session}`);
        toast("Audit complete");
        renderReport();
        focusTab("dashboard");
        renderDashboard();
      } else if (data.error !== "cancelled") {
        toast(data.error || "audit failed", true);
      }
      break;
    case "chat.start":
      setChatting(true);
      // Begin a fresh assistant bubble for this turn; it streams into the same
      // continuous conversation instead of spawning a separate chat.
      ensureMsg("assistant");
      break;
    case "chat.end":
      setChatting(false);
      finalize("assistant");
      finalizeThinking("assistant");
      state.chatTurns = (state.chatTurns || 0) + 1;
      if (data && data.ok && data.text && !state.rawText.assistant) {
        // Fallback: render the final text directly if streamed text was lost.
        appendText("assistant", data.text);
        finalize("assistant");
      }
      if (data && data.error && data.error !== "cancelled") toast(data.error, true);
      break;
    case "chat.reset":
      break;
  }
}

window.SplitAgent = {
  emit(events) {
    if (!Array.isArray(events)) events = [events];
    events.forEach(handleEvent);
  },
};

function resetStream() {
  const s = $("#stream");
  s.innerHTML = "";
  state.currentMsg = {};
  state.rawText = {};
  state.tools = {};
  state.findings = [];
  state.mitigations = [];
  state.events = 0;
  state.round = 0;
  state.runningTools = { red: 0, blue: 0, assistant: 0 };
  state.toolLog = { red: [], blue: [], assistant: [] };
  state.context = null;
  state.trace = [];
  state.thinking = { red: "", blue: "", assistant: "" };
  state.todos = [];
  state.working = {};
  $("#todo-dock").classList.add("hidden");
  updateContextMeter();
  api("workspace_info").then((info) => {
    if (info && info.ok) renderWorkspace(info);
  });
  state.findingIndex = {};
  state.rounds = [];
  $("#panel-dashboard").innerHTML =
    '<div class="panel-empty">Run an audit to see the results here.</div>';
  $("#panel-findings").innerHTML = '<div class="panel-empty">No findings yet.</div>';
  $("#panel-mitigations").innerHTML = '<div class="panel-empty">No mitigations yet.</div>';
  $("#panel-activity").innerHTML = "";
  $("#panel-report").innerHTML = '<div class="panel-empty">The report is generated at the end of a run.</div>';
  $("#count-findings").textContent = "0";
  $("#count-mitigations").textContent = "0";
  $("#st-events").textContent = "0 events";
  setResilience(100);
}

function resetChat() {
  const s = $("#chat-stream");
  s.innerHTML = `
    <div class="empty-state" id="chat-empty">
      <div class="empty-mark">
        <svg viewBox="0 0 24 24"><path d="M3.5 5.5h17v10h-9l-4.5 4v-4H3.5z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>
      </div>
      <h1>Pentest copilot</h1>
      <p>Ask anything: plan an engagement, explain a vulnerability, inspect the target with tools, draft payloads, patches or report text.</p>
    </div>`;
  delete state.currentMsg.assistant;
  delete state.rawText.assistant;
  state.tools = {};
  state.chatTurns = 0;
}

function renderReport() {
  const panel = $("#panel-report");
  const lines = [`<div class="activity-line">session complete</div>`];
  state.reportPaths.forEach((p) => {
    lines.push(
      `<div class="activity-line">report: ${escapeHtml(p)} <a href="#" data-open="${escapeHtml(p)}">open</a></div>`
    );
  });
  panel.innerHTML = lines.join("") || '<div class="panel-empty">No report.</div>';
}

/* ── bootstrap ──────────────────────────────────────────── */
function renderBootstrap(data) {
  state.bootstrap = data;
  state.config = data.config || {};
  state.project = data.project || {};
  state.totalRounds = (data.project && data.project.run && data.project.run.rounds) || 3;

  $("#brand-ver").textContent = "v" + (data.version || "");
  $("#settings-path").textContent = data.config_path || "";
  $("#project-path").textContent = data.project_path || "";

  updateModelUI();
  renderTarget();
  renderSessions(data.sessions || []);
  fillSettingsForm();
  fillProjectForm();
  setRunning(!!data.running);
  setChatting(!!data.chatting);
  renderDashboard();

  refreshToolbox().then((status) => {
    const exec = data.execution || {};
    if (status && status.docker_cli && !exec.installed && !status.image) {
      openToolboxDialog();
    }
  });

  if (!data.configured) {
    toast("Connect a provider to start", true);
    openSettings();
    openConnectProvider("");
  }
}

function updateModelUI() {
  const provider = state.config.provider || "";
  const model = state.config.model || "no model";
  const label = `${provider}/${model}`;
  const ok = !!state.config.api_key_set && !!state.config.model;
  ["#pill-model", "#chat-pill-model", "#side-model-name"].forEach((sel) => {
    const el = $(sel);
    if (el) el.textContent = label;
  });
  $("#st-provider").textContent = label;
  ["#pill-dot", "#chat-pill-dot", "#side-model-dot"].forEach((sel) => {
    const el = $(sel);
    if (el) el.className = "dot " + (ok ? "ok" : "bad");
  });
}

function renderTarget() {
  const t = (state.project && state.project.target) || {};
  const run = (state.project && state.project.run) || {};
  $("#tgt-kind").textContent = t.kind || "web";
  $("#tgt-url").textContent = t.url || (t.hosts && t.hosts[0]) || "not configured";
  const scope = (t.scope || []).join(", ") || "—";
  const sb = run.sandbox && run.sandbox.enabled ? "sandbox on" : "sandbox off";
  $("#tgt-meta").innerHTML = `scope <code>${escapeHtml(scope)}</code> · ${run.rounds || 3} rounds · ${sb}`;
  $("#opt-rounds").value = run.rounds || 3;
  $("#opt-sandbox").checked = !!(run.sandbox && run.sandbox.enabled);
}

function renderSessions(sessions) {
  const list = $("#session-list");
  if (!sessions.length) {
    list.innerHTML = '<div class="session-empty">No saved sessions.</div>';
    return;
  }
  list.innerHTML = sessions
    .map(
      (s) =>
        `<div class="session-item" data-session="${escapeHtml(s.id)}">
           <span class="sid">${escapeHtml(s.id)}</span>
           <span class="smeta">${escapeHtml((s.modified || "").replace("T", " ").replace("+00:00", ""))}</span>
         </div>`
    )
    .join("");
  $$(".session-item", list).forEach((el) =>
    el.addEventListener("click", () => loadSession(el.dataset.session))
  );
}

async function loadSession(id) {
  const res = await api("load_session", id);
  if (!res || !res.ok) {
    toast(res && res.error ? res.error : "could not load session", true);
    return;
  }
  const s = res.state || {};
  setMode("audit");
  resetStream();
  state.rounds = (s.rounds || []).map((r) => ({
    index: r.index,
    findings: (r.finding_ids || []).length,
    mitigations: (r.mitigation_ids || []).length,
  }));
  addDivider("core", `Loaded session ${s.id}`);
  (s.rounds || []).forEach((r) => {
    addDivider("red", `Round ${r.index} · offence`);
    if (r.red_summary) { appendText("red", r.red_summary); finalize("red"); }
    addDivider("blue", `Round ${r.index} · defence`);
    if (r.blue_summary) { appendText("blue", r.blue_summary); finalize("blue"); }
  });
  (s.findings || []).forEach((f) =>
    addFinding({ id: f.id, title: f.title, severity: f.severity, cvss_score: f.cvss_score })
  );
  (s.mitigations || []).forEach((m) => addMitigation(m));
  setResilience(res.summary && typeof res.summary.resilience === "number" ? res.summary.resilience : 100);
  addActivity(`session ${s.id} loaded`);
  toast("Session loaded");
}

/* ── model picker ───────────────────────────────────────── */
let mpAnchor = null;
async function openModelPicker(anchor) {
  mpAnchor = anchor;
  const pop = $("#model-popover");
  if (!state.modelsLoaded) {
    const res = await api("list_models");
    if (res && res.ok) {
      state.models = res.models || [];
      state.modelsLoaded = true;
    }
  }
  renderModelList("");
  $("#mp-input").value = "";
  $("#mp-clear").classList.add("hidden");
  positionPopover();
  pop.classList.remove("hidden");
  setTimeout(() => $("#mp-input").focus(), 20);
}

function positionPopover() {
  const pop = $("#model-popover");
  const anchor = mpAnchor;
  if (!anchor) return;
  const rect = anchor.getBoundingClientRect();
  const width = 284;
  let left = rect.left;
  if (left + width > window.innerWidth - 12) left = window.innerWidth - width - 12;
  if (left < 12) left = 12;
  pop.style.left = `${left}px`;
  const height = Math.min(300, window.innerHeight - 80);
  let bottom = window.innerHeight - rect.top + 6;
  if (window.innerHeight - bottom < 60) bottom = window.innerHeight - 60;
  pop.style.bottom = `${bottom}px`;
  pop.style.maxHeight = `${height}px`;
}

function renderModelList(query) {
  const q = (query || "").trim().toLowerCase();
  const current = `${state.config.provider}:${state.config.model}`;
  let models = state.models;
  if (q) {
    models = models.filter(
      (m) =>
        m.name.toLowerCase().includes(q) ||
        m.id.toLowerCase().includes(q) ||
        m.provider.toLowerCase().includes(q)
    );
  }
  models = [...models].sort((a, b) => a.name.localeCompare(b.name));

  // group by provider, current provider first
  const groups = new Map();
  for (const m of models) {
    if (!groups.has(m.provider)) groups.set(m.provider, []);
    groups.get(m.provider).push(m);
  }
  const ordered = Array.from(groups.entries()).sort((a, b) => {
    if (a[0] === state.config.provider) return -1;
    if (b[0] === state.config.provider) return 1;
    return a[0].localeCompare(b[0]);
  });

  const list = $("#mp-list");
  if (!ordered.length) {
    list.innerHTML = '<div class="mp-empty">No models found.</div>';
    state.mpFiltered = [];
    return;
  }
  let html = "";
  const flat = [];
  ordered.forEach(([provider, items]) => {
    html += `<div class="mp-group-label">${escapeHtml(provider)}</div>`;
    items.forEach((m) => {
      const key = `${m.provider}:${m.id}`;
      flat.push({ ...m, key });
      const selected = key === current;
      html += `<button class="mp-item${selected ? " selected" : ""}" data-key="${escapeHtml(key)}">
        <span class="mp-name">${escapeHtml(m.name)}</span>
        ${m.free ? '<span class="mp-tag free">FREE</span>' : ""}
        ${selected ? '<span class="check">✓</span>' : ""}
      </button>`;
    });
  });
  list.innerHTML = html;
  state.mpFiltered = flat;
  $$(".mp-item", list).forEach((el) =>
    el.addEventListener("click", () => pickModel(el.dataset.key))
  );
}

async function pickModel(key) {
  const [provider, ...rest] = key.split(":");
  const model = rest.join(":");
  const res = await api("activate_model", { provider, model });
  closeModelPicker();
  if (!res || !res.ok) {
    toast((res && res.error) || "could not switch model", true);
    return;
  }
  const entry = state.models.find((m) => m.provider === provider && m.id === model);
  const conn = state.connected.find((p) => p.id === provider);
  state.config = {
    ...state.config,
    provider,
    model,
    base_url: (conn && conn.base_url) || state.config.base_url,
    api_key_set: conn ? conn.has_key : true,
  };
  updateModelUI();
  if (!$("#modal-settings").classList.contains("hidden")) renderSettingsModels();
  toast(`Model: ${provider}/${model}`);
}

async function pickModelFromSettings(key) {
  await pickModel(key);
  await refreshCatalog();
}

function closeModelPicker() {
  $("#model-popover").classList.add("hidden");
}

/* ── guided wizard ──────────────────────────────────────── */
const WIZ_HINTS = [
  "What kind of target are you testing?",
  "Where is it? Scope keeps the agents safe.",
  "How should the agents run?",
  "Optional: credentials for authenticated testing.",
  "How deep should the audit go?",
];

function openWizard() {
  state.wizard.step = 0;
  state.wizard.kind = state.project.target?.kind || "web";
  state.wizard.depth = "standard";
  $$("#kind-grid .kind-card").forEach((c) =>
    c.classList.toggle("active", c.dataset.kind === state.wizard.kind)
  );
  $$("#depth-grid .depth-card").forEach((c) =>
    c.classList.toggle("active", c.dataset.depth === "standard")
  );
  // prefill from project
  const t = state.project.target || {};
  const run = state.project.run || {};
  const auth = state.project.auth || {};
  $("#wiz-url").value = t.url || "";
  $("#wiz-scope").value = (t.scope || []).join(", ");
  $("#wiz-out").value = (t.out_of_scope || []).join(", ");
  $("#wiz-ports").value = (t.ports || []).join(", ");
  $("#wiz-image").value = (run.sandbox && run.sandbox.image) || "bkimminich/juice-shop:latest";
  $("#wiz-network").checked = !!run.allow_network;
  const ws = state.project.workspace || {};
  $("#wiz-ws-path").value = ws.path || "";
  $("#wiz-ws-install").checked = ws.allow_install !== false;
  $("#wiz-ws-external").checked = ws.allow_external_tools !== false;
  $("#wiz-ws-instructions").value = ws.instructions || "";
  $("#wiz-user").value = auth.username || "";
  $("#wiz-pass").value = auth.password || "";
  $("#wiz-token").value = auth.token || "";
  $("#wiz-cookies").value = auth.cookies || "";
  $("#wiz-headers").value = Object.entries(auth.headers || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
  $$('input[name="env"]').forEach((r) => (r.checked = r.value === (run.sandbox && run.sandbox.enabled ? "sandbox" : "existing")));
  setWizardStep(0);
  openModal("#modal-wizard");
}

function setWizardStep(step) {
  state.wizard.step = Math.max(0, Math.min(4, step));
  $$(".wstep").forEach((s) => s.classList.toggle("active", Number(s.dataset.step) === state.wizard.step));
  $$("#wiz-progress .wdot").forEach((d, i) => {
    d.classList.toggle("active", i === state.wizard.step);
    d.classList.toggle("done", i < state.wizard.step);
  });
  $("#wiz-hint").textContent = WIZ_HINTS[state.wizard.step];
  $("#wiz-back").style.visibility = state.wizard.step === 0 ? "hidden" : "visible";
  $("#wiz-next").textContent = state.wizard.step === 4 ? "Start audit" : "Next";
  if (state.wizard.step === 4) renderWizardSummary();
}

function renderWizardSummary() {
  const kind = state.wizard.kind;
  const url = $("#wiz-url").value.trim() || "(none)";
  const scope = $("#wiz-scope").value.trim() || "(auto)";
  const env = document.querySelector('input[name="env"]:checked')?.value || "sandbox";
  const depth = state.wizard.depth;
  const depthMap = { quick: "1 round · 6 steps", standard: "3 rounds · 12 steps", deep: "5 rounds · 20 steps" };
  $("#wiz-summary").textContent =
    `target   ${kind} · ${url}\n` +
    `scope    ${scope}\n` +
    `env      ${env === "sandbox" ? "disposable Docker sandbox" : "existing target"}\n` +
    `workspace ${$("#wiz-ws-path").value.trim() || "splitagent-workspace"} ` +
    `(install ${$("#wiz-ws-install").checked ? "on" : "off"}, ` +
    `tools ${$("#wiz-ws-external").checked ? "on" : "off"})\n` +
    `depth    ${depth} (${depthMap[depth]})`;
}

async function wizardNext() {
  const step = state.wizard.step;
  if (step === 0) {
    setWizardStep(1);
    return;
  }
  if (step === 1) {
    const url = $("#wiz-url").value.trim();
    if (!url) {
      toast("Enter a target URL or host", true);
      return;
    }
    if (!$("#wiz-scope").value.trim()) {
      try {
        $("#wiz-scope").value = new URL(url).hostname;
      } catch {
        $("#wiz-scope").value = url.split(":")[0];
      }
    }
    setWizardStep(2);
    return;
  }
  if (step === 2) {
    setWizardStep(3);
    return;
  }
  if (step === 3) {
    setWizardStep(4);
    return;
  }
  await startWizardAudit();
}

function parseHeaders(text) {
  const headers = {};
  (text || "").split("\n").forEach((line) => {
    const idx = line.indexOf(":");
    if (idx > 0) {
      const name = line.slice(0, idx).trim();
      const value = line.slice(idx + 1).trim();
      if (name) headers[name] = value;
    }
  });
  return headers;
}

async function startWizardAudit() {
  const env = document.querySelector('input[name="env"]:checked')?.value || "sandbox";
  const depth = state.wizard.depth;
  const depthMap = { quick: { rounds: 1, steps: 6 }, standard: { rounds: 3, steps: 12 }, deep: { rounds: 5, steps: 20 } };
  const { rounds, steps } = depthMap[depth];

  const payload = {
    name: state.project.name,
    target: {
      kind: state.wizard.kind,
      url: $("#wiz-url").value.trim(),
      scope: $("#wiz-scope").value,
      out_of_scope: $("#wiz-out").value,
      ports: $("#wiz-ports").value,
    },
    run: {
      rounds,
      max_steps: steps,
      sandbox: { enabled: env === "sandbox", image: $("#wiz-image").value.trim() },
      allow_network: $("#wiz-network").checked,
    },
    auth: {
      username: $("#wiz-user").value.trim(),
      password: $("#wiz-pass").value,
      token: $("#wiz-token").value,
      cookies: $("#wiz-cookies").value.trim(),
      headers: parseHeaders($("#wiz-headers").value),
    },
  };
  const saved = await api("save_project", payload);
  if (saved && saved.ok) {
    state.project = saved.project;
    renderTarget();
    fillProjectForm();
  }
  payload.workspace = {
    path: $("#wiz-ws-path").value.trim(),
    allow_install: $("#wiz-ws-install").checked,
    allow_external_tools: $("#wiz-ws-external").checked,
    instructions: $("#wiz-ws-instructions").value.trim(),
  };
  const objective = $("#wiz-objective").value.trim();
  $("#objective").value = objective;
  closeModals();
  setMode("audit");
  const res = await api("start_audit", {
    objective,
    target: { url: payload.target.url, kind: payload.target.kind, scope: payload.target.scope },
    run: { rounds, sandbox: payload.run.sandbox.enabled, allow_network: payload.run.allow_network },
  });
  if (!res || !res.ok) {
    toast(res && res.error ? res.error : "could not start", true);
    return;
  }
  setRunning(true);
  addActivity("audit requested");
}

/* ── settings: models & providers ───────────────────────── */
const collapsedProviders = {};

async function refreshCatalog() {
  const [models, providers] = await Promise.all([
    api("list_models"),
    api("list_providers"),
  ]);
  state.models = (models && models.models) || [];
  state.connected = (providers && providers.connected) || [];
  state.popular = (providers && providers.popular) || [];
  state.modelsLoaded = true;
  renderSettingsModels();
  renderProviders();
}

function switchHtml(on, cls = "") {
  return `<span class="switch ${on ? "on" : ""} ${cls}"></span>`;
}

function renderSettingsModels() {
  const q = ($("#s-model-search").value || "").trim().toLowerCase();
  const current = `${state.config.provider}:${state.config.model}`;
  let models = state.models;
  if (q) {
    models = models.filter(
      (m) =>
        m.name.toLowerCase().includes(q) ||
        m.id.toLowerCase().includes(q) ||
        m.provider.toLowerCase().includes(q)
    );
  }
  const groups = new Map();
  for (const m of models) {
    if (!groups.has(m.provider)) groups.set(m.provider, []);
    groups.get(m.provider).push(m);
  }
  const ordered = Array.from(groups.entries()).sort((a, b) => {
    if (a[0] === state.config.provider) return -1;
    if (b[0] === state.config.provider) return 1;
    return a[0].localeCompare(b[0]);
  });

  const list = $("#s-models-list");
  if (!ordered.length) {
    list.innerHTML = `<div class="s-connected-empty">No models${q ? ` matching “${escapeHtml(q)}”` : ""}.</div>`;
    return;
  }
  let html = "";
  ordered.forEach(([provider, items]) => {
    const searching = q.length > 0;
    const expanded = searching || !collapsedProviders[provider];
    const allVisible = items.every((m) => m.visible);
    html += `<div class="s-group" data-provider="${escapeHtml(provider)}">
      <div class="s-group-header">
        <button class="s-group-trigger" data-toggle="${escapeHtml(provider)}">
          <span class="s-chev">${expanded ? "▾" : "▸"}</span>
          <span class="s-provider-dot">${escapeHtml(provider.slice(0, 2))}</span>
          <span>${escapeHtml(provider)}</span>
          <span class="s-group-count">${items.length}</span>
        </button>
        <span class="switch ${allVisible ? "on" : ""}" data-provider-toggle="${escapeHtml(provider)}" title="Toggle all models"></span>
      </div>`;
    if (expanded) {
      items
        .slice()
        .sort((a, b) => a.name.localeCompare(b.name))
        .forEach((m) => {
          const key = `${m.provider}:${m.id}`;
          const isActive = key === current;
          html += `<div class="s-row ${m.visible ? "" : "hidden-model"}" data-model-row="${escapeHtml(key)}">
            <span class="s-active-dot" style="${isActive ? "" : "visibility:hidden"}"></span>
            <span class="s-name">${escapeHtml(m.name)}</span>
            ${m.id !== m.name ? `<span class="s-sub">${escapeHtml(m.id)}</span>` : ""}
            <button class="s-remove" data-remove="${escapeHtml(key)}" title="Remove">✕</button>
            <span class="switch ${m.visible ? "on" : ""}" data-model-toggle="${escapeHtml(key)}"></span>
          </div>`;
        });
    }
    html += `</div>`;
  });
  list.innerHTML = html;

  $$("#s-models-list [data-toggle]").forEach((el) =>
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      const p = el.dataset.toggle;
      collapsedProviders[p] = !collapsedProviders[p];
      renderSettingsModels();
    })
  );
  $$("#s-models-list [data-provider-toggle]").forEach((el) =>
    el.addEventListener("click", async (e) => {
      e.stopPropagation();
      const p = el.dataset.providerToggle;
      const allVisible = state.models
        .filter((m) => m.provider === p)
        .every((m) => m.visible);
      await api("set_provider_visibility", { provider: p, visible: !allVisible });
      await refreshCatalog();
    })
  );
  $$("#s-models-list [data-model-toggle]").forEach((el) =>
    el.addEventListener("click", async (e) => {
      e.stopPropagation();
      const [provider, ...rest] = el.dataset.modelToggle.split(":");
      const model = rest.join(":");
      const entry = state.models.find((m) => m.provider === provider && m.id === model);
      await api("set_model_visibility", {
        provider,
        model,
        visible: !(entry && entry.visible),
      });
      await refreshCatalog();
    })
  );
  $$("#s-models-list [data-model-row]").forEach((el) =>
    el.addEventListener("dblclick", () => pickModelFromSettings(el.dataset.modelRow))
  );
  $$("#s-models-list [data-remove]").forEach((el) =>
    el.addEventListener("click", async (e) => {
      e.stopPropagation();
      const [provider, ...rest] = el.dataset.remove.split(":");
      await api("remove_model", { provider, model: rest.join(":") });
      await refreshCatalog();
      toast("Model removed");
    })
  );
}

function renderProviders() {
  const connectedList = $("#s-connected");
  if (!state.connected.length) {
    connectedList.innerHTML = '<div class="s-connected-empty">No providers connected yet.</div>';
  } else {
    connectedList.innerHTML = state.connected
      .map(
        (p) => `<div class="provider-row">
          <span class="s-provider-dot">${escapeHtml(p.id.slice(0, 2))}</span>
          <div class="provider-main">
            <span class="provider-name">${escapeHtml(p.name)}</span>
            <span class="tag-custom">${p.models} models</span>
            ${p.active ? '<span class="s-active-dot"></span>' : ""}
          </div>
          <span class="provider-sub">${escapeHtml(p.base_url.replace(/^https?:\/\//, ""))}</span>
          ${p.has_key ? '<span class="tag-rec">KEY</span>' : ""}
          <span class="switch ${p.enabled ? "on" : ""}" data-provider-enable="${escapeHtml(p.id)}" title="Enable"></span>
          <button class="btn ghost" data-provider-refresh="${escapeHtml(p.id)}">Refresh</button>
          <button class="btn ghost" data-provider-open="${escapeHtml(p.id)}">Edit</button>
          <button class="btn ghost" data-provider-disconnect="${escapeHtml(p.id)}">Disconnect</button>
        </div>`
      )
      .join("");
  }

  $("#s-popular").innerHTML =
    state.popular
      .map(
        (p) => `<div class="provider-row">
          <span class="s-provider-dot">${escapeHtml(p.id.slice(0, 2))}</span>
          <div class="provider-main">
            <span class="provider-name">${escapeHtml(p.name)}</span>
            ${["opencode", "opencode-go"].includes(p.id) ? '<span class="tag-rec">RECOMMENDED</span>' : ""}
          </div>
          <span class="provider-sub">${escapeHtml(p.base_url.replace(/^https?:\/\//, ""))}</span>
          <button class="btn ghost" data-provider-connect="${escapeHtml(p.id)}">Connect</button>
        </div>`
      )
      .join("") || '<div class="s-connected-empty">All providers connected.</div>';

  $$("#s-connected [data-provider-enable]").forEach((el) =>
    el.addEventListener("click", async () => {
      const id = el.dataset.providerEnable;
      const entry = state.connected.find((p) => p.id === id);
      await api("set_provider_visibility", { provider: id, visible: !(entry && entry.enabled) });
      await refreshCatalog();
    })
  );
  $$("#s-connected [data-provider-refresh]").forEach((el) =>
    el.addEventListener("click", async () => {
      toast("Refreshing catalogue…");
      const res = await api("refresh_provider", el.dataset.providerRefresh);
      if (res && res.ok) toast(`${res.models} models`);
      else toast((res && res.error) || "refresh failed", true);
      await refreshCatalog();
    })
  );
  $$("#s-connected [data-provider-open]").forEach((el) =>
    el.addEventListener("click", () => {
      const entry = state.connected.find((p) => p.id === el.dataset.providerOpen);
      openConnectProvider(entry ? entry.id : "");
    })
  );
  $$("#s-connected [data-provider-disconnect]").forEach((el) =>
    el.addEventListener("click", async () => {
      await api("disconnect_provider", el.dataset.providerDisconnect);
      await refreshCatalog();
      toast("Provider disconnected");
    })
  );
  $$("#s-popular [data-provider-connect]").forEach((el) =>
    el.addEventListener("click", () => openConnectProvider(el.dataset.providerConnect))
  );
}

function openSettings() {
  openModal("#modal-settings");
  refreshCatalog();
}

function openConnectProvider(providerId) {
  const presets = state.bootstrap.providers || {};
  const select = $("#pr-provider");
  select.innerHTML = Object.keys(presets)
    .map((name) => `<option value="${name}">${name}</option>`)
    .join("");
  const connectedIds = state.connected.map((p) => p.id);
  const known = state.connected.find((p) => p.id === providerId);
  select.value = providerId || known?.id || connectedIds[0] || "opencode-go";
  const isEdit = !!known;
  $("#provider-title").textContent = isEdit ? `Edit ${known.id}` : "Connect provider";
  const preset = presets[select.value] || {};
  $("#pr-base-url").value = known ? known.base_url : preset.base_url || "";
  $("#pr-model").value = "";
  $("#pr-api-key").value = "";
  $("#pr-api-key").placeholder = known && known.has_key ? "leave blank to keep current" : "sk-…";
  $("#pr-activate").checked = known ? known.active : true;
  openModal("#modal-provider");
}

async function connectProvider() {
  const payload = {
    provider: $("#pr-provider").value,
    base_url: $("#pr-base-url").value.trim(),
    api_key: $("#pr-api-key").value.trim(),
    activate: $("#pr-activate").checked,
  };
  const model = $("#pr-model").value.trim();
  if (model) payload.model = model;
  const status = $("#settings-status");
  status.textContent = "connecting…";
  status.className = "settings-status";
  const res = await api("connect_provider", payload);
  if (!res || !res.ok) {
    toast((res && res.error) || "could not connect", true);
    status.textContent = (res && res.error) || "failed";
    status.className = "settings-status bad";
    return;
  }
  if (model) {
    await api("add_custom_model", { provider: payload.provider, model });
  }
  closeModals();
  await refreshCatalog();
  syncActiveConfig();
  status.textContent = `${res.models} models${res.warning ? " · " + res.warning : ""}`;
  status.className = "settings-status " + (res.warning ? "bad" : "ok");
  toast(`Connected ${payload.provider} (${res.models} models)`);
}

function syncActiveConfig() {
  const active = state.connected.find((p) => p.active);
  if (!active) return;
  const models = state.models.filter((m) => m.provider === active.id);
  const current = state.config.model;
  const stillThere = models.some((m) => m.id === current);
  state.config = {
    ...state.config,
    provider: active.id,
    model: stillThere ? current : models[0]?.id || current,
    base_url: active.base_url,
    api_key_set: active.has_key,
  };
  updateModelUI();
}

/* ── forms ──────────────────────────────────────────────── */
function fillSettingsForm() {
  $("#f-temperature").value = state.config.temperature != null ? state.config.temperature : 0.2;
  $("#f-max-tokens").value = state.config.max_tokens || 4096;
}

function fillProjectForm() {
  const t = (state.project && state.project.target) || {};
  const run = (state.project && state.project.run) || {};
  $("#p-kind").value = t.kind || "web";
  $("#p-url").value = t.url || "";
  $("#p-scope").value = (t.scope || []).join(", ");
  $("#p-out").value = (t.out_of_scope || []).join(", ");
  $("#p-rounds").value = run.rounds || 3;
  $("#p-steps").value = run.max_steps || 12;
  $("#p-image").value = (run.sandbox && run.sandbox.image) || "";
  $("#p-sandbox").checked = !!(run.sandbox && run.sandbox.enabled);
}

async function saveSettings() {
  const payload = {
    temperature: $("#f-temperature").value,
    max_tokens: $("#f-max-tokens").value,
  };
  const res = await api("save_llm_config", payload);
  if (!res || !res.ok) {
    toast("could not save settings", true);
    return;
  }
  state.config = {
    ...state.config,
    temperature: Number(payload.temperature),
    max_tokens: Number(payload.max_tokens),
  };
  toast("Settings saved");
}

async function addCustomModel() {
  const provider = $("#cm-provider").value;
  const model = $("#cm-id").value.trim();
  if (!model) {
    toast("Enter a model id", true);
    return;
  }
  const res = await api("add_custom_model", {
    provider,
    model,
    name: $("#cm-name").value.trim(),
  });
  closeModals();
  if (!res || !res.ok) {
    toast((res && res.error) || "could not add model", true);
    return;
  }
  await refreshCatalog();
  toast(`Added ${model}`);
}

function openAddModel() {
  const select = $("#cm-provider");
  select.innerHTML = state.connected
    .map((p) => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.id)}</option>`)
    .join("");
  if (!select.options.length) {
    toast("Connect a provider first", true);
    return;
  }
  select.value = state.config.provider || select.options[0].value;
  $("#cm-id").value = "";
  $("#cm-name").value = "";
  openModal("#modal-model");
}

async function saveProject() {
  const payload = {
    name: state.project.name,
    target: {
      kind: $("#p-kind").value,
      url: $("#p-url").value.trim(),
      scope: $("#p-scope").value,
      out_of_scope: $("#p-out").value,
    },
    run: {
      rounds: Number($("#p-rounds").value || 3),
      max_steps: Number($("#p-steps").value || 12),
      sandbox: { enabled: $("#p-sandbox").checked, image: $("#p-image").value.trim() },
    },
  };
  const res = await api("save_project", payload);
  if (!res || !res.ok) {
    toast("could not save project", true);
    return;
  }
  state.project = res.project;
  renderTarget();
  fillProjectForm();
  closeModals();
  toast("Project saved");
}

async function startAudit() {
  if (state.running) return;
  const payload = {
    objective: $("#objective").value.trim(),
    target: { url: state.project.target ? state.project.target.url : "" },
    run: {
      rounds: Number($("#opt-rounds").value || 3),
      sandbox: $("#opt-sandbox").checked,
      allow_network: !!(state.project.run && state.project.run.allow_network),
    },
  };
  const res = await api("start_audit", payload);
  if (!res || !res.ok) {
    toast(res && res.error ? res.error : "could not start", true);
    return;
  }
  setRunning(true);
  addActivity("audit requested");
}

async function exportReport() {
  const res = await api("export_report", null);
  if (!res || !res.ok) {
    toast(res && res.error ? res.error : "nothing to export", true);
    return;
  }
  state.reportPaths = res.reports || [];
  $("#btn-open-reports").disabled = false;
  renderReport();
  toast("Report exported");
}

/* ── chat ───────────────────────────────────────────────── */
async function sendChat() {
  const input = $("#chat-input");
  const message = input.value.trim();
  if (!message || state.chatting) return;
  const empty = $("#chat-empty");
  if (empty) empty.remove();
  // Finish any assistant bubble left open, then append the user's message to the
  // same conversation. The assistant reply streams below it as the next turn.
  finalize("assistant");
  appendUserMessage(message);
  input.value = "";
  input.style.height = "auto";
  const res = await api("chat_send", message);
  if (!res || !res.ok) {
    toast(res && res.error ? res.error : "could not send", true);
    input.value = message; // give the text back so nothing is lost
    return;
  }
  // Optimistically enter the working state; chat.start confirms it. This
  // removes the window where the user could fire a second message.
  setChatting(true);
  await pollChat();
}

function appendUserMessage(message) {
  const stream = $("#chat-stream");
  const wrap = document.createElement("div");
  wrap.className = "msg user";
  wrap.innerHTML = `
    <div class="msg-head">
      <span class="msg-name core">You</span>
      <span class="msg-time">${nowTime()}</span>
    </div>
    <div class="msg-body">${md(message)}</div>`;
  stream.appendChild(wrap);
  stream.scrollTop = stream.scrollHeight;
}

/* The chat runs on a background thread and pushes events through the bridge.
   Between pushes we poll so the UI stays live even if an event is dropped. */
async function pollChat() {
  for (let i = 0; i < 2400; i += 1) {
    await new Promise((r) => setTimeout(r, 120));
    if (!state.chatting) break;
    const res = await api("chat_state");
    if (res && res.ok && res.pending && res.events && res.events.length) {
      window.SplitAgent.emit(res.events);
    }
    if (res && res.ok && !res.running && !res.pending) {
      setChatting(false);
      finalize("assistant");
      break;
    }
  }
}

async function clearChat() {
  await api("chat_reset");
  resetChat();
  setChatting(false);
  toast("Conversation cleared");
}

/* ── modals / palette ───────────────────────────────────── */
function openModal(sel) {
  closeModals();
  closeModelPicker();
  $(sel).classList.remove("hidden");
}
function closeModals() {
  $$(".overlay").forEach((el) => el.classList.add("hidden"));
}

function openPalette(title, items, onPick) {
  state.palette.items = items;
  state.palette.index = 0;
  state.palette.onPick = onPick;
  $("#command-input").value = "";
  $("#command-input").placeholder = title;
  renderPalette("");
  openModal("#modal-command");
  setTimeout(() => $("#command-input").focus(), 30);
}

function renderPalette(filter) {
  const list = $("#command-list");
  const f = filter.toLowerCase();
  const items = state.palette.items.filter((i) => !f || i.label.toLowerCase().includes(f));
  list.innerHTML =
    items
      .map(
        (i, idx) =>
          `<div class="command-item${idx === state.palette.index ? " active" : ""}" data-idx="${idx}">
             <span>${escapeHtml(i.label)}</span>
             ${i.hint ? `<span class="kbd">${escapeHtml(i.hint)}</span>` : ""}
           </div>`
      )
      .join("") || '<div class="panel-empty">No matches.</div>';
  state.palette.filtered = items;
  $$(".command-item", list).forEach((el) =>
    el.addEventListener("click", () => pickPalette(Number(el.dataset.idx)))
  );
}

function pickPalette(index) {
  const item = (state.palette.filtered || [])[index];
  if (!item) return;
  closeModals();
  state.palette.onPick(item);
}

const COMMANDS = [
  { label: "New audit (guided setup)", run: openWizard },
  { label: "Run audit", hint: "Ctrl+Enter", run: startAudit },
  { label: "Stop audit", run: () => api("stop_audit") },
  { label: "Open copilot chat", run: () => setMode("chat") },
  { label: "Choose model", run: () => openModelPicker($("#side-model-btn")) },
  { label: "Manage models & providers", hint: "Ctrl+,", run: openSettings },
  { label: "Connect a provider…", run: () => { openSettings(); openConnectProvider(""); } },
  { label: "Engagement / advanced", run: () => openModal("#modal-project") },
  { label: "Export report", run: exportReport },
  {
    label: "Open reports folder",
    run: () => {
      if (state.reportPaths[0]) api("reveal", state.reportPaths[0]);
      else toast("No report yet", true);
    },
  },
  {
    label: "Open project file…",
    run: async () => {
      const res = await api("choose_project_file");
      if (res && res.ok) {
        state.project = res.project;
        renderTarget();
        fillProjectForm();
        toast("Project loaded");
      }
    },
  },
  { label: "Clear audit stream", run: () => resetStream() },
  { label: "Clear chat", run: clearChat },
];

/* ── wiring ─────────────────────────────────────────────── */
function autoGrow(el) {
  el.style.height = "auto";
  el.style.height = Math.min(el.scrollHeight, 160) + "px";
}

function wire() {
  $$("#mode-switch .mode-btn").forEach((b) =>
    b.addEventListener("click", () => setMode(b.dataset.mode))
  );

  // audit
  $("#btn-run").addEventListener("click", startAudit);
  $("#btn-stop").addEventListener("click", () => api("stop_audit"));
  $("#btn-guided").addEventListener("click", openWizard);
  $("#btn-wizard").addEventListener("click", openWizard);
  $("#empty-start").addEventListener("click", openWizard);
  $("#btn-export").addEventListener("click", exportReport);
  $("#btn-dump-trace").addEventListener("click", dumpTrace);

  $("#btn-workspace").addEventListener("click", openWorkspace);
  $("#btn-toolbox").addEventListener("click", openToolboxDialog);
  $("#tb-install").addEventListener("click", installToolbox);
  $("#tb-edition").addEventListener("change", () => {
    const edition = $("#tb-edition").value;
    const size = edition === "kali" ? "~2.5 GB" : "~450 MB";
    $("#tb-hint").textContent =
      edition === "kali"
        ? `Kali Linux edition — everything preinstalled, ${size} download.`
        : `Standard edition — Debian with a curated toolset, ${size} download.`;
  });
  $("#tb-skip").addEventListener("click", async () => {
    await api("toolbox_action", "set_edition", "standard");
    closeModals();
    toast("Continuing in local mode");
  });
  $("#tb-autostart").addEventListener("change", async () => {
    // Persisted through the project save path on the next wizard save.
  });
  $("#td-toggle").addEventListener("click", toggleTodoDock);
  $("#td-toggle").addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      toggleTodoDock();
    }
  });
  $("#btn-open-reports").addEventListener("click", () => {
    if (state.reportPaths[0]) api("reveal", state.reportPaths[0]);
    else toast("No report yet", true);
  });
  $("#btn-project").addEventListener("click", () => openModal("#modal-project"));

  // model pickers
  ["#model-pill", "#chat-model-pill", "#side-model-btn"].forEach((sel) =>
    $(sel).addEventListener("click", (e) => {
      e.stopPropagation();
      if (!$("#model-popover").classList.contains("hidden") && mpAnchor === e.currentTarget) {
        closeModelPicker();
      } else {
        openModelPicker(e.currentTarget);
      }
    })
  );
  $("#mp-input").addEventListener("input", (e) => {
    renderModelList(e.target.value);
    $("#mp-clear").classList.toggle("hidden", !e.target.value.trim());
  });
  $("#mp-input").addEventListener("keydown", (e) => {
    const items = state.mpFiltered || [];
    if (e.key === "Escape") { closeModelPicker(); e.preventDefault(); }
    else if (e.key === "ArrowDown" && items.length) {
      state.mpIndex = Math.min((state.mpIndex || 0) + 1, items.length - 1);
      highlightMp();
      e.preventDefault();
    } else if (e.key === "ArrowUp" && items.length) {
      state.mpIndex = Math.max((state.mpIndex || 0) - 1, 0);
      highlightMp();
      e.preventDefault();
    } else if (e.key === "Enter" && items.length) {
      pickModel(items[state.mpIndex || 0].key);
      e.preventDefault();
    }
  });
  $("#mp-clear").addEventListener("click", () => {
    $("#mp-input").value = "";
    renderModelList("");
    $("#mp-clear").classList.add("hidden");
    $("#mp-input").focus();
  });
  $("#mp-manage").addEventListener("click", () => {
    closeModelPicker();
    openSettings();
  });
  document.addEventListener("click", (e) => {
    if (!$("#model-popover").classList.contains("hidden") &&
        !$("#model-popover").contains(e.target) &&
        !e.target.closest(".model-trigger") && !e.target.closest("#side-model-btn")) {
      closeModelPicker();
    }
  });
  window.addEventListener("resize", () => {
    if (!$("#model-popover").classList.contains("hidden")) positionPopover();
  });

  // chat
  $("#chat-send").addEventListener("click", sendChat);
  $("#chat-stop").addEventListener("click", () => api("chat_stop"));
  $("#chat-clear").addEventListener("click", clearChat);
  const chatInput = $("#chat-input");
  chatInput.addEventListener("input", () => autoGrow(chatInput));
  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      sendChat();
    }
  });
  document.addEventListener("click", (e) => {
    if (e.target.classList && e.target.classList.contains("suggestion")) {
      chatInput.value = e.target.textContent;
      autoGrow(chatInput);
      sendChat();
    }
  });

  // wizard
  $("#wiz-next").addEventListener("click", wizardNext);
  $("#wiz-back").addEventListener("click", () => setWizardStep(state.wizard.step - 1));
  $$("#kind-grid .kind-card").forEach((c) =>
    c.addEventListener("click", () => {
      state.wizard.kind = c.dataset.kind;
      $$("#kind-grid .kind-card").forEach((x) => x.classList.toggle("active", x === c));
    })
  );
  $$("#depth-grid .depth-card").forEach((c) =>
    c.addEventListener("click", () => {
      state.wizard.depth = c.dataset.depth;
      $$("#depth-grid .depth-card").forEach((x) => x.classList.toggle("active", x === c));
      renderWizardSummary();
    })
  );
  $$('input[name="env"]').forEach((r) =>
    r.addEventListener("change", () => {
      const sandbox = document.querySelector('input[name="env"]:checked').value === "sandbox";
      $("#wiz-image-field").style.opacity = sandbox ? "1" : "0.4";
      $("#wiz-image").disabled = !sandbox;
    })
  );
  $$("#wiz-presets .mini-btn").forEach((b) =>
    b.addEventListener("click", async () => {
      const res = await api("apply_target_preset", b.dataset.preset);
      if (res && res.ok) {
        state.project = res.project;
        const t = res.project.target || {};
        const run = res.project.run || {};
        $("#wiz-url").value = t.url || "";
        $("#wiz-scope").value = (t.scope || []).join(", ");
        $("#wiz-ports").value = (t.ports || []).join(", ");
        $("#wiz-image").value = (run.sandbox && run.sandbox.image) || "";
        toast(`Preset ${b.dataset.preset} applied`);
      }
    })
  );

  // settings
  $$("#settings-tabs .stab").forEach((tab) =>
    tab.addEventListener("click", () => {
      $$("#settings-tabs .stab").forEach((t) => t.classList.remove("active"));
      $$(".spanel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      $("#spanel-" + tab.dataset.stab).classList.add("active");
    })
  );
  $("#s-model-search").addEventListener("input", (e) => {
    renderSettingsModels();
    $("#s-model-search-clear").classList.toggle("hidden", !e.target.value.trim());
  });
  $("#s-model-search-clear").addEventListener("click", () => {
    $("#s-model-search").value = "";
    renderSettingsModels();
    $("#s-model-search-clear").classList.add("hidden");
  });
  $("#btn-add-model").addEventListener("click", openAddModel);
  $("#btn-model-add").addEventListener("click", addCustomModel);
  $("#btn-connect-provider").addEventListener("click", () => openConnectProvider(""));
  $("#btn-provider-connect").addEventListener("click", connectProvider);
  $("#pr-provider").addEventListener("change", () => {
    const preset = (state.bootstrap.providers || {})[$("#pr-provider").value];
    if (preset) {
      $("#pr-base-url").value = preset.base_url;
      $("#pr-model").value = "";
    }
  });
  $("#btn-open-config").addEventListener("click", () => {
    const path = state.bootstrap.config_path || "";
    if (path) api("reveal", path);
  });
  $("#btn-save-settings").addEventListener("click", saveSettings);
  $("#btn-test").addEventListener("click", async () => {
    const result = $("#test-result");
    result.textContent = "testing...";
    result.className = "test-result";
    const res = await api("test_connection", {});
    result.textContent = res && res.ok ? `OK · ${res.message}` : `Failed · ${(res && res.message) || "error"}`;
    result.className = "test-result " + (res && res.ok ? "ok" : "bad");
  });
  $("#btn-settings").addEventListener("click", openSettings);
  $("#btn-save-project").addEventListener("click", saveProject);
  $("#btn-load-project").addEventListener("click", async () => {
    const res = await api("choose_project_file");
    if (res && res.ok) {
      state.project = res.project;
      renderTarget();
      fillProjectForm();
      toast("Project loaded");
    }
  });
  $("#btn-command").addEventListener("click", () => openPalette("Command", COMMANDS, (i) => i.run()));

  // panel collapse + drag resize
  const body = $("#body");
  const sideW = () =>
    parseFloat(getComputedStyle(body).getPropertyValue("--side-w")) || 272;
  const reviewW = () =>
    parseFloat(getComputedStyle(body).getPropertyValue("--review-w")) || 384;
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

  const toggleSidebar = () =>
    document.body.classList.toggle("sidebar-collapsed");
  const toggleReview = () => document.body.classList.toggle("review-collapsed");
  $("#btn-toggle-sidebar").addEventListener("click", toggleSidebar);
  $("#btn-toggle-review").addEventListener("click", toggleReview);

  function installResizer(el, varName, getter, min, max, invert) {
    if (!el) return;
    let startX = 0;
    let startW = 0;
    const move = (e) => {
      const delta = (e.clientX - startX) * (invert ? -1 : 1);
      body.style.setProperty(varName, clamp(startW + delta, min, max) + "px");
    };
    const up = () => {
      el.classList.remove("dragging");
      body.classList.remove("resizing");
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
    };
    el.addEventListener("mousedown", (e) => {
      e.preventDefault();
      startX = e.clientX;
      startW = getter();
      el.classList.add("dragging");
      body.classList.add("resizing");
      window.addEventListener("mousemove", move);
      window.addEventListener("mouseup", up);
    });
  }
  installResizer($("#resize-sidebar"), "--side-w", sideW, 180, 420, false);
  installResizer($("#resize-review"), "--review-w", reviewW, 260, 640, true);

  // window controls
  $("#win-min").addEventListener("click", () => api("window_action", "minimize"));
  $("#win-max").addEventListener("click", () => api("window_action", "maximize"));
  $("#win-close").addEventListener("click", () => api("window_action", "close"));

  $$("[data-close]").forEach((el) => el.addEventListener("click", closeModals));
  $$(".overlay").forEach((el) =>
    el.addEventListener("mousedown", (e) => {
      if (e.target === el) closeModals();
    })
  );

  // review tabs
  $$(".rtab").forEach((tab) =>
    tab.addEventListener("click", () => {
      $$(".rtab").forEach((t) => t.classList.remove("active"));
      $$(".rpanel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      $("#panel-" + tab.dataset.tab).classList.add("active");
    })
  );

  // audit composer
  const objective = $("#objective");
  objective.addEventListener("input", () => autoGrow(objective));
  objective.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      startAudit();
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeModals(); closeModelPicker(); }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      openPalette("Command", COMMANDS, (i) => i.run());
    }
    if ((e.ctrlKey || e.metaKey) && e.key === ",") {
      e.preventDefault();
      openSettings();
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "b") {
      e.preventDefault();
      document.body.classList.toggle("sidebar-collapsed");
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "j") {
      e.preventDefault();
      document.body.classList.toggle("review-collapsed");
    }
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      if (state.mode === "chat") sendChat();
      else startAudit();
    }
    if (!$("#modal-command").classList.contains("hidden")) {
      const filtered = state.palette.filtered || [];
      if (e.key === "ArrowDown") {
        state.palette.index = Math.min(state.palette.index + 1, filtered.length - 1);
        renderPalette($("#command-input").value);
        e.preventDefault();
      } else if (e.key === "ArrowUp") {
        state.palette.index = Math.max(state.palette.index - 1, 0);
        renderPalette($("#command-input").value);
        e.preventDefault();
      } else if (e.key === "Enter") {
        pickPalette(state.palette.index);
        e.preventDefault();
      }
    }
  });
  $("#command-input").addEventListener("input", (e) => {
    state.palette.index = 0;
    renderPalette(e.target.value);
  });

  document.addEventListener("click", (e) => {
    const link = e.target.closest("[data-open]");
    if (link) {
      e.preventDefault();
      api("open_path", link.dataset.open);
    }
  });
}

function highlightMp() {
  $$("#mp-list .mp-item").forEach((el, i) => el.classList.toggle("active", i === (state.mpIndex || 0)));
}

/* ── Boot intro ─────────────────────────────────────────── */
function playIntro() {
  const intro = $("#intro");
  if (!intro) return;
  // Respect reduced motion: skip straight to the app.
  if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    intro.remove();
    return;
  }

  const lines = $("#intro-lines");
  const script = [
    "initialising purple-team core",
    "loading recon \u00b7 web \u00b7 exploit toolkits",
    "encrypted shared context ready",
    "red team \u00b7 blue team online",
  ];
  const canvas = $("#intro-canvas");
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const resize = () => {
    canvas.width = intro.clientWidth * dpr;
    canvas.height = intro.clientHeight * dpr;
  };
  resize();

  let raf = 0;
  const stars = Array.from({ length: 90 }, () => ({
    x: Math.random(),
    y: Math.random(),
    z: Math.random() * 0.8 + 0.2,
    r: Math.random() * 1.6 + 0.4,
    hue: Math.random() < 0.5 ? "91,118,255" : "90,210,230",
  }));
  const draw = () => {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    stars.forEach((s) => {
      s.y += 0.0004 * s.z;
      if (s.y > 1) s.y = 0;
      const x = s.x * canvas.width + Math.sin((Date.now() / 1400 + s.x * 20)) * 6 * dpr;
      const y = s.y * canvas.height;
      const r = s.r * s.z * dpr;
      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${s.hue},${0.25 + s.z * 0.55})`;
      ctx.fill();
    });
    raf = requestAnimationFrame(draw);
  };
  draw();

  script.forEach((text, i) => {
    const line = document.createElement("div");
    line.innerHTML = `<b>\u2713</b> ${escapeHtml(text)}`;
    line.style.animationDelay = `${0.9 + i * 0.4}s`;
    lines.appendChild(line);
  });

  const finish = () => {
    cancelAnimationFrame(raf);
    intro.classList.add("done");
    document.body.classList.add("ready");
    setTimeout(() => intro.remove(), 700);
  };
  setTimeout(finish, 0.9 + script.length * 0.4 + 0.7);
  intro.addEventListener("click", finish);
}

let booted = false;
let wired = false;
async function boot() {
  if (booted) return;
  if (!window.pywebview || !window.pywebview.api) {
    setTimeout(boot, 200);
    return;
  }
  if (!wired) {
    wire();
    wired = true;
  }
  const data = await api("bootstrap");
  if (data && data.version) {
    booted = true;
    renderBootstrap(data);
    playIntro();
  } else {
    setTimeout(boot, 300);
  }
}

window.addEventListener("pywebviewready", boot);
if (window.pywebview && window.pywebview.api) boot();
