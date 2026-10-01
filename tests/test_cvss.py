from __future__ import annotations

from splitagent.report.cvss import describe, parse_vector, severity_from_score


def test_critical_vector():
    assert parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_zero_impact_vector():
    assert parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_reflected_xss_vector():
    assert parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1


def test_authenticated_vector():
    assert parse_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == 8.8


def test_invalid_vector():
    assert parse_vector("not-a-vector") is None


def test_severity_mapping():
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(8.0) == "high"
    assert severity_from_score(5.0) == "medium"
    assert severity_from_score(2.0) == "low"
    assert severity_from_score(0.0) == "info"


def test_describe():
    result = describe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result["severity"] == "critical"
    assert result["score"] == 9.8
