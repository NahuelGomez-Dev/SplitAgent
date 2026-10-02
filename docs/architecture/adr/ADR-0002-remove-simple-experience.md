# ADR-0002: Remove the Simple/guided experience; single Developer cockpit

- Status: Accepted
- Date: 2026-10-02
- Deciders: maintainer

## Context

`config.UISettings` carries `experience` (`auto|guided|developer`), `experience_chosen` and a
`developer_mode` property; `desktop/api.py` exposes `set_experience`; the web UI duplicates
DOM nodes with `data-exp` and toggles them with `body[data-experience]`. The "Simple" mode is
not a distinct interface — it relabels the audit cockpit, and the user reports it is unused
and confusing. The user asked to delete Simple and keep the current (Developer) interface,
and to remove the per-agent/user avatar logos so messages show only the name.

## Decision

Delete the experience model entirely and ship one cockpit interface. Remove agent/user avatar
elements (name + timestamp remain). Keep `ui.audits_completed` as a plain counter.

## Alternatives considered

- **Keep Simple as a real chat-only interface** — offered and rejected by the user
  ("Sacar el selector").
- **Keep the picker but default to Developer** — rejected: leaves dead, confusing UI.

## Consequences

- Positive: less code, no duplicated DOM/CSS, one path to test and maintain.
- Negative: legacy global configs still contain `experience`/`experience_chosen`; they are
  ignored by `_dataclass_from_dict` and dropped on the next save (verified behavior).
- Reversibility: two-way door — the preference is a UI-only setting, not a data/schema change.

## Follow-ups

- Remove the settings "Interface" section and guided empty state from the web UI.
- Delete `set_experience` and the `ui.*` bootstrap keys for experience.
