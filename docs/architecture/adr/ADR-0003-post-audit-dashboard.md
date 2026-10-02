# ADR-0003: Post-audit Dashboard as a review-panel tab

- Status: Accepted
- Date: 2026-10-02
- Deciders: maintainer

## Context

When a run ends the operator has only the stream, the Findings list and the generated
report; there is no at-a-glance view of the engagement result. The user asked for "a
dashboard where you see everything much better" after the pentest finishes. All required
data already reaches the UI through the bootstrap payload and the live event bus
(findings, mitigations, severity, resilience, rounds, usage, todos).

## Decision

Add a **Dashboard** tab to the existing review panel, rendered from live session state with
inline SVG/CSS (severity distribution, resilience gauge, top findings, round timeline,
tool/usage stats). It becomes the active tab automatically on `session.end`. No new backend
endpoint and no chart library.

## Alternatives considered

- **Separate full-screen route** — rejected: duplicates the shell/layout and widens the
  responsive surface for no added value.
- **Chart library (e.g. Chart.js)** — rejected: a new dependency to draw two simple shapes;
  inline SVG/CSS is deterministic, offline and testable.

## Consequences

- Positive: zero new dependencies, reuses the event stream, contained to web assets.
- Negative: hand-rolled charts need manual styling/responsiveness.
- Reversibility: two-way door — the tab can be replaced by a route later.

## Follow-ups

- Define the `session.end` handling to focus the Dashboard.
- Add an empty state for sessions with no findings.
