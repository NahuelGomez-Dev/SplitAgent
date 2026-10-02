# ADR-0001: Deterministic, code-owned professional report template

- Status: Accepted
- Date: 2026-10-02
- Deciders: maintainer

## Context

The user asked for a "proper, well-made document" with a template "so the AI does not always
produce something different". Today `report/generator.py` emits an ad-hoc structure and the
only AI-authored content is the per-finding `description` and `recommendation` (plus round
summaries). Real pentest reports follow a stable section order (executive summary, scope,
methodology, severity model, findings summary, detailed findings, remediation roadmap,
retest, limitations) and each finding block carries CVSS/CWE/OWASP/impact/reproduction.

## Decision

The document structure and all narrative sections are produced **by code** from
`SessionState`. The AI is constrained to filling structured `Finding` fields; it never
composes the document. Missing fields render as an explicit "Not provided" cell.

## Alternatives considered

- **Jinja2 template files** — rejected: introduces a dependency and user-editable templates
  for no proven need (Rule of Three not met).
- **AI writes the whole report under a JSON schema** — rejected: the user's explicit
  complaint is variability; an LLM authoring section prose is variable, costly and
  hallucination-prone for a security deliverable.

## Consequences

- Positive: reproducible reports, snapshot-testable, no per-run cost, works offline.
- Negative: changing the layout requires a code change; less "creative" prose.
- Reversibility: two-way door — a templating layer can be added later without changing the
  data model.

## Follow-ups

- Add CWE/OWASP/impact/reproduction to `Finding` and the `record_finding` schema.
- Add a snapshot test locking the section order.
