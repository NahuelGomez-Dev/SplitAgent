from __future__ import annotations

from splitagent.config import ReportSettings
from splitagent.core.models import Finding, Mitigation, SessionState
from splitagent.report.generator import (
    build_html,
    build_json,
    build_markdown,
    write_reports,
)

FIXED_TIME = "2026-01-01T00:00:00+00:00"


def _state() -> SessionState:
    state = SessionState(name="demo", target="http://localhost:3000")
    state.scope = ["localhost"]
    state.add_finding(
        Finding(
            title="Reflected XSS",
            severity="high",
            category="xss",
            description="The q parameter is reflected without encoding.",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cvss_score=6.1,
            evidence="<svg/onload=alert(1)> reflected",
            recommendation="Encode output",
            cwe="CWE-79: Cross-site Scripting",
            owasp="A03:2021 - Injection",
            impact="An attacker can run code in a victim's browser.",
            reproduction="1. GET /search?q=<svg/onload=alert(1)>",
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


def test_build_markdown_has_the_full_section_set():
    md = build_markdown(_state(), ReportSettings())
    for section in [
        "# Penetration Test Report",
        "## Document control",
        "## 1. Executive summary",
        "## 2. Scope and rules of engagement",
        "## 3. Methodology and standards",
        "## 4. Severity model",
        "## 5. Findings summary",
        "## 6. Detailed findings",
        "## 7. Remediation roadmap",
        "## 8. Retest and status tracking",
        "## 9. Appendices",
        "## 10. Limitations and disclaimer",
    ]:
        assert section in md, section
    assert "CWE-79" in md
    assert "A03:2021" in md
    assert "Steps to reproduce" in md


def test_build_html_is_standalone():
    html = build_html(_state(), ReportSettings())
    assert html.startswith("<!doctype html>")
    assert "Reflected XSS" in html


def test_build_html_has_the_full_section_set():
    html = build_html(_state(), ReportSettings(), generated_at=FIXED_TIME)
    for section in [
        "Document control",
        "1. Executive summary",
        "2. Scope and rules of engagement",
        "3. Methodology and standards",
        "4. Severity model",
        "5. Findings summary",
        "6. Detailed findings",
        "7. Remediation roadmap",
        "8. Retest and status tracking",
        "9. Appendices",
        "10. Limitations and disclaimer",
    ]:
        assert section in html, section
    assert "CWE-79: Cross-site Scripting" in html


def test_missing_report_fields_say_not_provided():
    state = SessionState(name="bare", target="http://x")
    state.add_finding(Finding(title="Bare", description="desc"))
    html = build_html(state, ReportSettings(), generated_at=FIXED_TIME)
    assert "Not provided" in html


def test_report_is_deterministic():
    state = _state()
    first = build_html(state, ReportSettings(), generated_at=FIXED_TIME)
    second = build_html(state, ReportSettings(), generated_at=FIXED_TIME)
    assert first == second


def test_build_json_metrics():
    payload = build_json(_state())
    assert '"resilience_score"' in payload
    assert '"severity_counts"' in payload


def test_report_filename_is_sanitised(tmp_path):
    from splitagent.report.generator import safe_stem

    assert "/" not in safe_stem("../evil/name")
    assert "\\" not in safe_stem("..\\..\\windows")
    assert safe_stem("") == "report"
    assert safe_stem("a" * 200) == "a" * 80


def test_write_reports_cannot_escape_the_directory(tmp_path):
    from splitagent.report.generator import write_reports

    state = _state()
    state.name = "../../escape"
    paths = write_reports(state, ReportSettings(formats=["json"]), tmp_path)
    assert len(paths) == 1
    assert paths[0].parent == tmp_path.resolve()
    assert "escape" not in paths[0].name or ".." not in paths[0].name


def test_malformed_session_degrades_instead_of_crashing():
    from splitagent.core.models import SessionState

    # A corrupt session: wrong types where the report expects numbers.
    state = SessionState.from_dict(
        {
            "findings": [
                {"title": "x", "cvss_score": "not-a-number", "round": "nope"},
                "this-is-not-a-dict",
            ],
            "rounds": [{"index": "bad"}, 42],
            "mitigations": [{"finding_id": "f", "round": None}],
        }
    )
    assert state.findings[0].cvss_score == 0.0
    assert state.findings[0].round == 0
    # Rendering must not raise.
    html = build_html(state, ReportSettings(), generated_at=FIXED_TIME)
    assert "<!doctype html>" in html


def test_write_reports(tmp_path):
    settings = ReportSettings(formats=["markdown", "html", "json"])
    paths = write_reports(_state(), settings, tmp_path)
    assert len(paths) == 3
    for path in paths:
        assert path.exists()
        assert path.stat().st_size > 0
