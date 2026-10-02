"""Compile a session into a professional penetration-test report.

The document structure is owned by code, not by the model: the AI only fills
structured ``Finding`` fields, so two sessions with the same data produce the
same document. Output formats: Markdown, printable HTML (A4) and JSON.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from splitagent.config import ReportSettings
from splitagent.core.models import SEVERITY_ORDER, SessionState
from splitagent.report.cvss import describe

REPORT_VERSION = "1.0"
CLASSIFICATION = "Confidential"

SEVERITY_BADGE = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

# Severity model, as published in the report so the reader can reproduce a score.
SEVERITY_MODEL: list[tuple[str, str, str]] = [
    ("Critical", "9.0 - 10.0", "Direct, unauthenticated path to data or control. Fix first."),
    ("High", "7.0 - 8.9", "Serious impact, usually needs one precondition."),
    ("Medium", "4.0 - 6.9", "Real but constrained, or requires chaining."),
    ("Low", "0.1 - 3.9", "Limited impact on its own; still worth recording."),
    ("Informational", "0.0", "No direct security impact; hardening or hygiene observation."),
]

# Remediation priority and target SLA per severity.
REMEDIATION_SLA: dict[str, tuple[str, str]] = {
    "critical": ("P0", "24-48 hours"),
    "high": ("P1", "7 days"),
    "medium": ("P2", "30 days"),
    "low": ("P3", "90 days"),
    "info": ("P4", "best effort"),
}

METHODOLOGY_STANDARDS = [
    "OWASP Web Security Testing Guide (WSTG) and ASVS for web applications",
    "OWASP API Security Top 10 for APIs",
    "PTES (Penetration Testing Execution Standard) and NIST SP 800-115 for structure",
    "MITRE ATT&CK for adversary techniques",
    "CVSS v3.1 for severity scoring",
]

METHODOLOGY_PHASES = (
    "reconnaissance, enumeration, vulnerability analysis, controlled "
    "non-destructive exploitation, post-exploitation review and reporting"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sort_findings(state: SessionState) -> list:
    return sorted(
        state.findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            -(f.cvss_score or 0.0),
            f.title,
        ),
    )


def _raw_severity(finding: Any) -> str:
    severity = (finding.severity or "info").lower()
    return severity if severity in SEVERITY_ORDER else "info"


def _affected_asset(finding: Any) -> str:
    return finding.endpoint or finding.target or ""


def _status_label(state: SessionState, finding: Any) -> str:
    if finding.status == "false-positive":
        return "False positive"
    if finding.status == "accepted":
        return "Risk accepted"
    if state.finding_is_closed(finding):
        return "Fixed, verified"
    if any(m.finding_id == finding.id for m in state.mitigations):
        return "Mitigation proposed"
    return "Open"


def _overall_risk(state: SessionState) -> str:
    for severity in ("critical", "high", "medium", "low"):
        if any(
            _raw_severity(f) == severity and not state.finding_is_closed(f) for f in state.findings
        ):
            return severity.capitalize()
    return "Low" if state.findings else "Informational"


def _severity_counts(state: SessionState) -> dict[str, int]:
    counts = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
    for finding in state.findings:
        counts[_raw_severity(finding)] += 1
    return counts


def _exec_summary(state: SessionState) -> str:
    counts = _severity_counts(state)
    total = len(state.findings)
    if not total:
        return (
            f"An automated penetration test of {state.target or 'the target'} was performed "
            "within the authorised scope. No security findings were recorded during the "
            "engagement. The tested surface is reported as clean, subject to the scope and "
            "limitations stated in this document."
        )
    parts = [
        f"An automated penetration test of {state.target or 'the target'} was performed "
        f"within the authorised scope between {state.started_at} and {state.ended_at or 'now'}."
    ]
    parts.append(
        f"The assessment identified {total} finding(s): {counts['critical']} critical, "
        f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low and "
        f"{counts['info']} informational. Overall risk is rated "
        f"**{_overall_risk(state)}**."
    )
    top = _sort_findings(state)[:3]
    if top:
        named = "; ".join(f"{f.id} {f.title or 'untitled'}" for f in top)
        parts.append(f"The most significant findings are: {named}.")
    breakdown = state.resilience_breakdown()
    parts.append(
        f"Resilience score: **{state.resilience_score()}/100** "
        f"({breakdown['findings_closed']} of {breakdown['findings_total']} issues confirmed "
        "closed after re-testing)."
    )
    if breakdown["verified_is_zero"]:
        parts.append(
            "Nothing is verified yet: every mitigation below is a proposal. The score counts "
            "only issues re-tested after a control was applied, so it will not move until the "
            "fixes are deployed and the audit is re-run."
        )
    elif breakdown["mitigations_proposed"]:
        parts.append(
            f"{breakdown['mitigations_verified']} control(s) verified as applied; "
            f"{breakdown['mitigations_proposed']} still only proposed and not counted."
        )
    if breakdown["open_critical"]:
        parts.append(
            "Open critical issues requiring urgent action: "
            + ", ".join(breakdown["open_critical"])
            + "."
        )
    return " ".join(parts)


def _report_context(
    state: SessionState, settings: ReportSettings, generated_at: str | None = None
) -> dict[str, Any]:
    """The structured content shared by every renderer."""
    findings = _sort_findings(state)
    mitigations_by_finding: dict[str, list] = {}
    for mitigation in state.mitigations:
        mitigations_by_finding.setdefault(mitigation.finding_id, []).append(mitigation)
    return {
        "findings": findings,
        "mitigations_by_finding": mitigations_by_finding,
        "counts": _severity_counts(state),
        "overall_risk": _overall_risk(state),
        "exec_summary": _exec_summary(state),
        "breakdown": state.resilience_breakdown(),
        "settings": settings,
        "generated_at": generated_at or _now(),
    }


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def _md_finding_block(state: SessionState, finding: Any, settings: ReportSettings) -> list[str]:
    severity = _raw_severity(finding)
    cvss = (
        f"{finding.cvss_score:.1f} ({finding.cvss_vector})"
        if finding.cvss_vector
        else f"{finding.cvss_score:.1f}"
    )
    lines = [
        f"### {finding.id} - {finding.title or 'Untitled'} [{SEVERITY_BADGE[severity]}]",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Severity | {severity.capitalize()} |",
        f"| CVSS | {cvss} |",
        f"| CWE | {finding.cwe or 'Not provided'} |",
        f"| OWASP | {finding.owasp or 'Not provided'} |",
        f"| Affected asset | {_affected_asset(finding) or 'Not provided'} |",
        f"| Category | {finding.category} |",
        f"| Status | {_status_label(state, finding)} |",
        f"| Confidence | {finding.confidence} |",
        f"| Discovered in round | {finding.round} |",
        "",
        f"**Description.** {finding.description or 'Not provided'}",
        "",
        f"**Impact.** {finding.impact or 'Not provided'}",
        "",
    ]
    if finding.reproduction:
        lines.append("**Steps to reproduce**")
        lines.append("")
        lines.append(finding.reproduction)
        lines.append("")
    if settings.include_evidence and finding.evidence:
        lines.append("**Evidence**")
        lines.append("")
        lines.append("```")
        lines.append(finding.evidence)
        lines.append("```")
        lines.append("")
    if finding.recommendation:
        lines.append(f"**Remediation.** {finding.recommendation}")
        lines.append("")
    return lines


def build_markdown(
    state: SessionState, settings: ReportSettings, *, generated_at: str | None = None
) -> str:
    ctx = _report_context(state, settings, generated_at)
    findings = ctx["findings"]
    counts = ctx["counts"]
    lines: list[str] = []

    lines.append(f"# Penetration Test Report - {state.name}")
    lines.append("")
    lines.append("## Document control")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Report version | {REPORT_VERSION} |")
    lines.append(f"| Classification | {CLASSIFICATION} |")
    lines.append(f"| Target | {state.target or 'n/a'} ({state.target_kind}) |")
    lines.append(f"| Scope | {', '.join(state.scope) or 'n/a'} |")
    lines.append(f"| Session | `{state.id}` |")
    lines.append(f"| Model | {state.provider or 'n/a'} / {state.model or 'n/a'} |")
    lines.append(f"| Started | {state.started_at} |")
    lines.append(f"| Ended | {state.ended_at or 'in progress'} |")
    lines.append(f"| Report date | {ctx['generated_at']} |")
    lines.append("| Prepared by | SplitAgent (automated) |")
    lines.append("")

    lines.append("## 1. Executive summary")
    lines.append("")
    lines.append(ctx["exec_summary"])
    lines.append("")
    lines.append("| Severity | Count | Status |")
    lines.append("| --- | --- | --- |")
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity.capitalize()} | {counts[severity]} | see findings |")
    lines.append(f"| **Total** | **{len(findings)}** | |")
    lines.append("")

    lines.append("## 2. Scope and rules of engagement")
    lines.append("")
    lines.append(f"- **In scope:** {', '.join(state.scope) or state.target or 'n/a'}")
    lines.append("- **Out of scope:** any host not listed above.")
    lines.append(f"- **Testing window:** {state.started_at} to {state.ended_at or 'now'}.")
    lines.append(
        "- **Authorisation:** testing was performed by the asset owner or an authorised "
        "party. All activity was non-destructive."
    )
    lines.append("")

    lines.append("## 3. Methodology and standards")
    lines.append("")
    lines.append(f"The engagement followed {METHODOLOGY_PHASES}.")
    lines.append("")
    for standard in METHODOLOGY_STANDARDS:
        lines.append(f"- {standard}")
    lines.append("")

    lines.append("## 4. Severity model")
    lines.append("")
    lines.append("| Severity | CVSS v3.1 | Meaning |")
    lines.append("| --- | --- | --- |")
    for name, cvss_range, meaning in SEVERITY_MODEL:
        lines.append(f"| {name} | {cvss_range} | {meaning} |")
    lines.append("")

    lines.append("## 5. Findings summary")
    lines.append("")
    if not findings:
        lines.append("_No findings were recorded._")
        lines.append("")
    else:
        lines.append("| ID | Title | Severity | CVSS | Affected asset | Status |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for finding in findings:
            lines.append(
                f"| `{finding.id}` | {finding.title or 'Untitled'} | "
                f"{SEVERITY_BADGE[_raw_severity(finding)]} | {finding.cvss_score:.1f} | "
                f"{_affected_asset(finding) or '-'} | {_status_label(state, finding)} |"
            )
        lines.append("")

    lines.append("## 6. Detailed findings")
    lines.append("")
    if not findings:
        lines.append("_No findings were recorded._")
        lines.append("")
    for finding in findings:
        lines.extend(_md_finding_block(state, finding, settings))
        for mitigation in ctx["mitigations_by_finding"].get(finding.id, []):
            lines.append(
                f"**Mitigation {mitigation.id}** ({mitigation.kind}, {mitigation.status}) - "
                f"{mitigation.title}"
            )
            lines.append("")
            if mitigation.description:
                lines.append(mitigation.description)
                lines.append("")
            if settings.include_patches and mitigation.content:
                lines.append("```")
                lines.append(mitigation.content)
                lines.append("```")
                lines.append("")

    lines.append("## 7. Remediation roadmap")
    lines.append("")
    if not findings:
        lines.append("_No remediation required._")
        lines.append("")
    else:
        lines.append("| Priority | Finding | Severity | Target SLA |")
        lines.append("| --- | --- | --- | --- |")
        for finding in findings:
            severity = _raw_severity(finding)
            priority, sla = REMEDIATION_SLA[severity]
            lines.append(
                f"| {priority} | `{finding.id}` {finding.title or 'Untitled'} | "
                f"{severity.capitalize()} | {sla} |"
            )
        lines.append("")

    lines.append("## 8. Retest and status tracking")
    lines.append("")
    lines.append("| ID | Original severity | Status |")
    lines.append("| --- | --- | --- |")
    for finding in findings:
        lines.append(
            f"| `{finding.id}` | {SEVERITY_BADGE[_raw_severity(finding)]} | "
            f"{_status_label(state, finding)} |"
        )
    if not findings:
        lines.append("| - | - | - |")
    lines.append("")

    lines.append("## 9. Appendices")
    lines.append("")
    if state.usage:
        lines.append("**Model usage:** " + ", ".join(f"{k}={v}" for k, v in state.usage.items()))
        lines.append("")
    if state.notes:
        lines.append("**Analyst notes**")
        lines.append("")
        for note in state.notes:
            lines.append(f"- {note}")
        lines.append("")
    lines.append("**Round timeline**")
    lines.append("")
    for round_ in state.rounds:
        lines.append(f"- **Round {round_.index} - Red:** {round_.red_summary or '(none)'}")
        lines.append(f"- **Round {round_.index} - Blue:** {round_.blue_summary or '(none)'}")
    if not state.rounds:
        lines.append("- No rounds recorded.")
    lines.append("")

    lines.append("## 10. Limitations and disclaimer")
    lines.append("")
    lines.append(
        "This report reflects automated, non-destructive testing within the authorised scope. "
        "Automated tools do not replace human judgement: absence of a finding does not prove "
        "absence of a vulnerability. Evidence may contain sensitive values captured during "
        "testing and must be reviewed before distribution. The report must be reviewed by a "
        "qualified human before remediation decisions are made."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("_Generated by SplitAgent._")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HTML (printable A4)
# --------------------------------------------------------------------------- #
_HTML_CSS = """
:root {
  --ink:#1c1c22; --muted:#5c5c68; --faint:#8a8a96;
  --line:#e2e2e8; --panel:#f7f7fa; --accent:#3b4fd8;
  --critical:#c0223b; --high:#d9752a; --medium:#b8890f; --low:#2f8f4e;
  --info:#2b7fb8;
}
* { box-sizing:border-box; }
@page { size:A4; margin:18mm 16mm; }
html, body { margin:0; padding:0; background:#fff; color:var(--ink); }
body { font-family:"Segoe UI", system-ui, -apple-system, Roboto, Arial, sans-serif;
  font-size:11.5px; line-height:1.65; }
.wrap { max-width:820px; margin:0 auto; padding:28px 22px 64px; }

.cover { border-bottom:3px solid var(--accent); padding-bottom:22px; margin-bottom:26px; }
.cover .class { display:inline-block; font-size:10px; letter-spacing:0.16em;
  text-transform:uppercase; color:var(--critical); border:1px solid var(--critical);
  border-radius:999px; padding:2px 10px; margin-bottom:14px; }
.cover h1 { font-size:30px; margin:0 0 6px; letter-spacing:-0.02em; }
.cover .target { font-size:15px; color:var(--muted); margin:0 0 14px; }
.cover .line { font-size:11px; color:var(--faint); }

h2 { font-size:16px; margin:30px 0 10px; padding-bottom:6px;
  border-bottom:1px solid var(--line); letter-spacing:-0.01em; }
h3 { font-size:13px; margin:22px 0 8px; }
p { margin:0 0 10px; }
small { color:var(--faint); }
code { font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:11px; }

table { width:100%; border-collapse:collapse; margin:8px 0 14px; }
th, td { text-align:left; padding:7px 9px; border-bottom:1px solid var(--line);
  vertical-align:top; font-size:11px; }
th { color:var(--muted); font-weight:600; text-transform:uppercase; font-size:9.5px;
  letter-spacing:0.06em; background:var(--panel); }
td.field { color:var(--muted); width:150px; white-space:nowrap; }

.badge { display:inline-block; padding:1px 8px; border-radius:999px; font-size:9.5px;
  font-weight:700; letter-spacing:0.04em; color:#fff; }
.badge.critical { background:var(--critical); }
.badge.high { background:var(--high); }
.badge.medium { background:var(--medium); }
.badge.low { background:var(--low); }
.badge.info { background:var(--info); }

.cards { display:flex; gap:10px; flex-wrap:wrap; margin:12px 0 4px; }
.card { border:1px solid var(--line); border-radius:10px; padding:10px 14px; min-width:110px; }
.card .n { font-size:22px; font-weight:700; }
.card .l { font-size:9.5px; text-transform:uppercase; letter-spacing:0.06em; color:var(--muted); }

.finding { border:1px solid var(--line); border-left:4px solid var(--accent);
  border-radius:10px; padding:16px 18px; margin:14px 0; page-break-inside:avoid; }
.finding.critical { border-left-color:var(--critical); }
.finding.high { border-left-color:var(--high); }
.finding.medium { border-left-color:var(--medium); }
.finding.low { border-left-color:var(--low); }
.finding.info { border-left-color:var(--info); }
.finding h3 { margin-top:0; }
.finding .subhead { font-size:10px; text-transform:uppercase; letter-spacing:0.06em;
  color:var(--muted); margin:12px 0 4px; font-weight:700; }
pre { background:var(--panel); border:1px solid var(--line); border-radius:6px;
  padding:10px; overflow-x:auto; font-size:10.5px; white-space:pre-wrap; word-break:break-word; }
blockquote { margin:10px 0; padding:10px 14px; background:var(--panel);
  border-left:3px solid var(--accent); border-radius:6px; color:var(--muted); }
.rec { color:var(--low); font-weight:600; }
footer { margin-top:36px; padding-top:12px; border-top:1px solid var(--line);
  color:var(--faint); font-size:10px; }
@media print { .wrap { max-width:none; padding:0; } a { color:inherit; text-decoration:none; } }
"""


def build_html(
    state: SessionState, settings: ReportSettings, *, generated_at: str | None = None
) -> str:
    ctx = _report_context(state, settings, generated_at)
    findings = ctx["findings"]
    counts = ctx["counts"]

    def esc(value: Any) -> str:
        return html.escape(str(value or ""))

    def cell(value: Any) -> str:
        return esc(value) if value else "<span class='muted'>Not provided</span>"

    # Executive summary paragraphs.
    summary_html = "".join(f"<p>{esc(part)}</p>" for part in ctx["exec_summary"].split(". "))

    # Findings summary table.
    summary_rows = (
        "".join(
            f"<tr><td><code>{esc(f.id)}</code></td><td>{esc(f.title or 'Untitled')}</td>"
            f"<td><span class='badge {_raw_severity(f)}'>{SEVERITY_BADGE[_raw_severity(f)]}</span></td>"
            f"<td>{f.cvss_score:.1f}</td><td>{esc(_affected_asset(f) or '-')}</td>"
            f"<td>{esc(_status_label(state, f))}</td></tr>"
            for f in findings
        )
        or "<tr><td colspan='6'>No findings recorded.</td></tr>"
    )

    # Detailed findings.
    cards: list[str] = []
    for finding in findings:
        severity = _raw_severity(finding)
        cvss = (
            f"{finding.cvss_score:.1f} ({esc(finding.cvss_vector)})"
            if finding.cvss_vector
            else f"{finding.cvss_score:.1f}"
        )
        mitigations = ""
        for mitigation in ctx["mitigations_by_finding"].get(finding.id, []):
            content = (
                f"<pre>{esc(mitigation.content)}</pre>"
                if settings.include_patches and mitigation.content
                else ""
            )
            mitigations += (
                f"<div class='mitigation'><strong>{esc(mitigation.title)}</strong> "
                f"<em>({esc(mitigation.kind)} / {esc(mitigation.status)})</em>"
                f"<p>{esc(mitigation.description)}</p>{content}</div>"
            )
        evidence = (
            f"<div class='subhead'>Evidence</div><pre>{esc(finding.evidence)}</pre>"
            if settings.include_evidence and finding.evidence
            else ""
        )
        reproduction = (
            f"<div class='subhead'>Steps to reproduce</div><pre>{esc(finding.reproduction)}</pre>"
            if finding.reproduction
            else ""
        )
        cards.append(
            f"<section class='finding {severity}'>"
            f"<h3><code>{esc(finding.id)}</code> &middot; {esc(finding.title or 'Untitled')} "
            f"<span class='badge {severity}'>{SEVERITY_BADGE[severity]}</span></h3>"
            "<table>"
            f"<tr><td class='field'>Severity</td><td>{severity.capitalize()}</td></tr>"
            f"<tr><td class='field'>CVSS</td><td>{cvss}</td></tr>"
            f"<tr><td class='field'>CWE</td><td>{cell(finding.cwe)}</td></tr>"
            f"<tr><td class='field'>OWASP</td><td>{cell(finding.owasp)}</td></tr>"
            f"<tr><td class='field'>Affected asset</td><td>{cell(_affected_asset(finding))}</td></tr>"
            f"<tr><td class='field'>Category</td><td>{esc(finding.category)}</td></tr>"
            f"<tr><td class='field'>Status</td><td>{esc(_status_label(state, finding))}</td></tr>"
            f"<tr><td class='field'>Confidence</td><td>{esc(finding.confidence)}</td></tr>"
            f"<tr><td class='field'>Discovered in round</td><td>{finding.round}</td></tr>"
            "</table>"
            f"<div class='subhead'>Description</div><p>{cell(finding.description)}</p>"
            f"<div class='subhead'>Impact</div><p>{cell(finding.impact)}</p>"
            f"{reproduction}{evidence}"
            f"<div class='subhead'>Remediation</div><p class='rec'>{cell(finding.recommendation)}</p>"
            f"{mitigations}</section>"
        )

    # Severity model / remediation / retest.
    severity_rows = "".join(
        f"<tr><td><span class='badge {name.lower() if name != 'Informational' else 'info'}'>"
        f"{name.upper() if name != 'Informational' else 'INFO'}</span></td>"
        f"<td>{esc(cvss_range)}</td><td>{esc(meaning)}</td></tr>"
        for name, cvss_range, meaning in SEVERITY_MODEL
    )
    roadmap_rows = (
        "".join(
            f"<tr><td>{REMEDIATION_SLA[_raw_severity(f)][0]}</td>"
            f"<td><code>{esc(f.id)}</code> {esc(f.title or 'Untitled')}</td>"
            f"<td>{_raw_severity(f).capitalize()}</td>"
            f"<td>{esc(REMEDIATION_SLA[_raw_severity(f)][1])}</td></tr>"
            for f in findings
        )
        or "<tr><td colspan='4'>No remediation required.</td></tr>"
    )
    retest_rows = (
        "".join(
            f"<tr><td><code>{esc(f.id)}</code></td>"
            f"<td><span class='badge {_raw_severity(f)}'>{SEVERITY_BADGE[_raw_severity(f)]}</span></td>"
            f"<td>{esc(_status_label(state, f))}</td></tr>"
            for f in findings
        )
        or "<tr><td colspan='3'>No findings recorded.</td></tr>"
    )

    notes = "".join(f"<li>{esc(n)}</li>" for n in state.notes)
    timeline = (
        "".join(
            f"<li><strong>Round {r.index} &middot; Red:</strong> {esc(r.red_summary or '(none)')}<br>"
            f"<strong>Round {r.index} &middot; Blue:</strong> {esc(r.blue_summary or '(none)')}</li>"
            for r in state.rounds
        )
        or "<li>No rounds recorded.</li>"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Penetration Test Report - {esc(state.name)}</title>
<style>{_HTML_CSS}</style>
</head>
<body>
<div class="wrap">
  <header class="cover">
    <div class="class">{CLASSIFICATION}</div>
    <h1>Penetration Test Report</h1>
    <p class="target">{esc(state.name)} &middot; {esc(state.target or "n/a")}</p>
    <div class="line">Report version {REPORT_VERSION} &middot; session <code>{esc(state.id)}</code>
      &middot; generated {esc(ctx["generated_at"])}</div>
  </header>

  <h2>Document control</h2>
  <table>
    <tr><td class="field">Report version</td><td>{REPORT_VERSION}</td></tr>
    <tr><td class="field">Classification</td><td>{CLASSIFICATION}</td></tr>
    <tr><td class="field">Target</td><td>{esc(state.target or "n/a")} ({esc(state.target_kind)})</td></tr>
    <tr><td class="field">Scope</td><td>{esc(", ".join(state.scope) or "n/a")}</td></tr>
    <tr><td class="field">Model</td><td>{esc(state.provider or "n/a")} / {esc(state.model or "n/a")}</td></tr>
    <tr><td class="field">Started</td><td>{esc(state.started_at)}</td></tr>
    <tr><td class="field">Ended</td><td>{esc(state.ended_at or "in progress")}</td></tr>
    <tr><td class="field">Prepared by</td><td>SplitAgent (automated)</td></tr>
  </table>

  <h2>1. Executive summary</h2>
  <p><strong>Overall risk: {esc(ctx["overall_risk"])}</strong></p>
  <div class="cards">
    <div class="card"><div class="n">{len(findings)}</div><div class="l">Findings</div></div>
    <div class="card"><div class="n">{counts["critical"]}</div><div class="l">Critical</div></div>
    <div class="card"><div class="n">{counts["high"]}</div><div class="l">High</div></div>
    <div class="card"><div class="n">{counts["medium"]}</div><div class="l">Medium</div></div>
    <div class="card"><div class="n">{state.resilience_score()}</div><div class="l">Resilience</div></div>
  </div>
  {summary_html}

  <h2>2. Scope and rules of engagement</h2>
  <table>
    <tr><td class="field">In scope</td><td>{esc(", ".join(state.scope) or state.target or "n/a")}</td></tr>
    <tr><td class="field">Out of scope</td><td>Any host not listed above.</td></tr>
    <tr><td class="field">Testing window</td><td>{esc(state.started_at)} to {esc(state.ended_at or "now")}</td></tr>
    <tr><td class="field">Authorisation</td><td>Performed by the asset owner or an authorised
      party. All activity was non-destructive.</td></tr>
  </table>

  <h2>3. Methodology and standards</h2>
  <p>The engagement followed {esc(METHODOLOGY_PHASES)}.</p>
  <ul>{"".join(f"<li>{esc(s)}</li>" for s in METHODOLOGY_STANDARDS)}</ul>

  <h2>4. Severity model</h2>
  <table><thead><tr><th>Severity</th><th>CVSS v3.1</th><th>Meaning</th></tr></thead>
    <tbody>{severity_rows}</tbody></table>

  <h2>5. Findings summary</h2>
  <table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th>
    <th>Affected asset</th><th>Status</th></tr></thead><tbody>{summary_rows}</tbody></table>

  <h2>6. Detailed findings</h2>
  {"".join(cards) or "<p>No findings were recorded.</p>"}

  <h2>7. Remediation roadmap</h2>
  <table><thead><tr><th>Priority</th><th>Finding</th><th>Severity</th><th>Target SLA</th></tr></thead>
    <tbody>{roadmap_rows}</tbody></table>

  <h2>8. Retest and status tracking</h2>
  <table><thead><tr><th>ID</th><th>Original severity</th><th>Status</th></tr></thead>
    <tbody>{retest_rows}</tbody></table>

  <h2>9. Appendices</h2>
  <p><strong>Model usage:</strong> {esc(", ".join(f"{k}={v}" for k, v in state.usage.items()) or "n/a")}</p>
  <div class="subhead">Analyst notes</div>
  <ul>{notes or "<li>None.</li>"}</ul>
  <div class="subhead">Round timeline</div>
  <ul>{timeline}</ul>

  <h2>10. Limitations and disclaimer</h2>
  <blockquote>This report reflects automated, non-destructive testing within the authorised
    scope. Automated tools do not replace human judgement: absence of a finding does not prove
    absence of a vulnerability. Evidence may contain sensitive values captured during testing
    and must be reviewed before distribution. The report must be reviewed by a qualified human
    before remediation decisions are made.</blockquote>

  <footer>Generated by SplitAgent &middot; {esc(ctx["generated_at"])}</footer>
</div>
</body>
</html>
"""


def build_json(state: SessionState) -> str:
    payload: dict[str, Any] = state.to_dict()
    payload["metrics"] = {
        "resilience_score": state.resilience_score(),
        "resilience": state.resilience_breakdown(),
        "severity_counts": state.severity_counts(),
        "finding_count": len(state.findings),
        "mitigation_count": len(state.mitigations),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def write_reports(
    state: SessionState, settings: ReportSettings, output_dir: Path | None = None
) -> list[Path]:
    directory = output_dir or Path(settings.output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    stem = f"{state.name}-{state.id}-{stamp}"
    written: list[Path] = []
    for fmt in settings.formats:
        fmt = fmt.lower()
        if fmt in ("md", "markdown"):
            path = directory / f"{stem}.md"
            path.write_text(build_markdown(state, settings), encoding="utf-8")
            written.append(path)
        elif fmt == "html":
            path = directory / f"{stem}.html"
            path.write_text(build_html(state, settings), encoding="utf-8")
            written.append(path)
        elif fmt == "json":
            path = directory / f"{stem}.json"
            path.write_text(build_json(state), encoding="utf-8")
            written.append(path)
    return written


def cvss_detail(vector: str) -> dict[str, Any]:
    return describe(vector)
