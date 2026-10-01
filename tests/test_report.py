from __future__ import annotations

from splitagent.config import ReportSettings
from splitagent.core.models import Finding, Mitigation, SessionState
from splitagent.report.generator import (
    build_html,
    build_json,
    build_markdown,
    write_reports,
)


def _state() -> SessionState:
    state = SessionState(name="demo", target="http://localhost:3000")
    state.add_finding(
        Finding(
            title="Reflected XSS",
            severity="high",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cvss_score=6.1,
            evidence="<svg/onload=alert(1)> reflected",
            recommendation="Encode output",
        )
    )
    state.add_mitigation(
        Mitigation(
            finding_id=state.findings[0].id, title="Encode", kind="patch", content="- x\n+ y"
        )
    )
    state.findings[0].status = "mitigated"
    return state


def test_build_markdown_contains_finding():
    md = build_markdown(_state(), ReportSettings())
    assert "Reflected XSS" in md
    assert "CVSS:3.1" in md
    assert "Resilience score" in md


def test_build_html_is_standalone():
    html = build_html(_state(), ReportSettings())
    assert html.startswith("<!doctype html>")
    assert "Reflected XSS" in html


def test_build_json_metrics():
    payload = build_json(_state())
    assert '"resilience_score"' in payload
    assert '"severity_counts"' in payload


def test_write_reports(tmp_path):
    settings = ReportSettings(formats=["markdown", "html", "json"])
    paths = write_reports(_state(), settings, tmp_path)
    assert len(paths) == 3
    for path in paths:
        assert path.exists()
        assert path.stat().st_size > 0
