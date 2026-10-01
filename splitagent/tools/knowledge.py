"""Shared tools: the agents' memory of findings, mitigations and context."""

from __future__ import annotations

from typing import Any

from splitagent.report.cvss import parse_vector
from splitagent.tools.base import Tool, ToolContext


async def _record_finding(
    ctx: ToolContext,
    title: str,
    description: str,
    severity: str = "",
    category: str = "general",
    cvss_vector: str = "",
    target: str = "",
    endpoint: str = "",
    evidence: str = "",
    recommendation: str = "",
    confidence: str = "medium",
    references: list[str] | None = None,
) -> dict[str, Any]:
    score = None
    if cvss_vector:
        score = parse_vector(cvss_vector)
    payload = {
        "title": title,
        "description": description,
        "severity": severity,
        "category": category,
        "cvss_vector": cvss_vector,
        "cvss_score": score,
        "target": target or ctx.context.state.target,
        "endpoint": endpoint,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": confidence,
        "references": references or [],
        "round": ctx.round,
    }
    finding = await ctx.context.add_finding(payload, agent="red")
    return {
        "recorded": True,
        "id": finding.id,
        "severity": finding.severity,
        "cvss_score": finding.cvss_score,
    }


async def _record_mitigation(
    ctx: ToolContext,
    finding_id: str,
    title: str,
    kind: str = "config",
    description: str = "",
    content: str = "",
    rationale: str = "",
) -> dict[str, Any]:
    mitigation = await ctx.context.add_mitigation(
        {
            "finding_id": finding_id,
            "title": title,
            "kind": kind,
            "description": description,
            "content": content,
            "rationale": rationale,
            "round": ctx.round,
        },
        agent="blue",
    )
    return {"recorded": True, "id": mitigation.id, "finding_id": finding_id}


def _list_findings(ctx: ToolContext) -> dict[str, Any]:
    findings = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "status": f.status,
            "endpoint": f.endpoint,
        }
        for f in ctx.context.state.findings
    ]
    return {"count": len(findings), "findings": findings}


def _get_finding(ctx: ToolContext, finding_id: str) -> dict[str, Any]:
    finding = ctx.context.state.get_finding(finding_id)
    if finding is None:
        return {"error": f"finding '{finding_id}' not found"}
    return finding.to_dict()


async def _write_todos(ctx: ToolContext, todos: list[dict[str, Any]]) -> dict[str, Any]:
    await ctx.context.set_todos(todos)
    remaining = [item for item in ctx.context.state.todos if item["status"] != "completed"]
    return {
        "updated": True,
        "total": len(ctx.context.state.todos),
        "remaining": len(remaining),
        "todos": ctx.context.state.todos,
    }


def _read_context(ctx: ToolContext) -> dict[str, Any]:
    return {
        "session": ctx.context.state.id,
        "target": ctx.context.state.target,
        "scope": ctx.context.state.scope,
        "findings": ctx.context.findings_digest(),
        "mitigations": ctx.context.mitigations_digest(),
        "todos": ctx.context.todo_summary(),
        "round": ctx.round,
    }


def knowledge_tools(ctx: ToolContext) -> list[Tool]:
    return [
        Tool(
            name="todowrite",
            description=(
                "Create and maintain a structured task list for the current "
                "engagement. Tracks progress, organises multi-step work and "
                "surfaces status to the operator in the UI.\n\n"
                "## When to use\n"
                "Use proactively when the task needs 3+ distinct steps, is "
                "non-trivial and benefits from planning, the operator gives "
                "several tasks, or new instructions arrive. Mark a task "
                "`in_progress` (only one at a time) before working on it and "
                "`completed` only when the work is actually done.\n\n"
                "## When NOT to use\n"
                "Skip single, straightforward tasks, purely informational "
                "requests, or when tracking adds no value.\n\n"
                "## States\n"
                "pending - not started; in_progress - actively working (exactly "
                "ONE at a time); completed - finished successfully; cancelled - "
                "no longer needed.\n\n"
                "## Rules\n"
                "- Update status in real time; do not batch completions.\n"
                "- Keep exactly one `in_progress` while work remains.\n"
                "- If blocked, keep it `in_progress` and add a follow-up item.\n"
                "- Items must be specific and actionable."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "todos": {
                        "type": "array",
                        "description": "The updated todo list",
                        "items": {
                            "type": "object",
                            "properties": {
                                "content": {
                                    "type": "string",
                                    "description": "Brief description of the task",
                                },
                                "status": {
                                    "type": "string",
                                    "description": (
                                        "Current status of the task: "
                                        "pending, in_progress, completed, cancelled"
                                    ),
                                },
                                "priority": {
                                    "type": "string",
                                    "description": (
                                        "Priority level of the task: high, medium, low"
                                    ),
                                },
                            },
                            "required": ["content", "status", "priority"],
                        },
                    }
                },
                "required": ["todos"],
            },
            func=lambda todos: _write_todos(ctx, todos),
            scope="shared",
        ),
        Tool(
            name="record_finding",
            description=(
                "Persist a verified vulnerability in the shared context. Always "
                "include concrete evidence and a CVSS v3.1 vector when possible."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "category": {"type": "string"},
                    "cvss_vector": {
                        "type": "string",
                        "description": "CVSS v3.1 vector, e.g. CVSS:3.1/AV:N/AC:L/...",
                    },
                    "target": {"type": "string"},
                    "endpoint": {"type": "string"},
                    "evidence": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                    },
                },
                "required": ["title", "description"],
            },
            func=lambda **kwargs: _record_finding(ctx, **kwargs),
            scope="shared",
        ),
        Tool(
            name="list_findings",
            description="List every finding recorded so far with its status.",
            parameters={"type": "object", "properties": {}},
            func=lambda: _list_findings(ctx),
            scope="shared",
        ),
        Tool(
            name="get_finding",
            description="Fetch the full detail of a single finding by id.",
            parameters={
                "type": "object",
                "properties": {"finding_id": {"type": "string"}},
                "required": ["finding_id"],
            },
            func=lambda finding_id: _get_finding(ctx, finding_id),
            scope="shared",
        ),
        Tool(
            name="record_mitigation",
            description=(
                "Persist a defensive countermeasure linked to a finding. The "
                "finding is marked as mitigated automatically."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "title": {"type": "string"},
                    "kind": {
                        "type": "string",
                        "enum": [
                            "firewall",
                            "patch",
                            "config",
                            "detection",
                            "process",
                        ],
                    },
                    "description": {"type": "string"},
                    "content": {
                        "type": "string",
                        "description": "The rule, patch diff or config to apply.",
                    },
                    "rationale": {"type": "string"},
                },
                "required": ["finding_id", "title"],
            },
            func=lambda **kwargs: _record_mitigation(ctx, **kwargs),
            scope="shared",
        ),
        Tool(
            name="read_shared_context",
            description=(
                "Read the shared context: target, scope and the running digest "
                "of findings and mitigations."
            ),
            parameters={"type": "object", "properties": {}},
            func=lambda: _read_context(ctx),
            scope="shared",
        ),
    ]
