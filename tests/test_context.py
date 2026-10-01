from __future__ import annotations

import pytest

from splitagent.core.bus import EventBus
from splitagent.core.context import SharedContext


@pytest.fixture()
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SPLITAGENT_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


async def test_add_finding_and_mitigation(isolated_home, tmp_path):
    bus = EventBus()
    seen: list[str] = []
    bus.subscribe(lambda event: seen.append(event.type))

    ctx = SharedContext.create(
        target="http://localhost:3000",
        scope=["localhost"],
        bus=bus,
        directory=tmp_path / "sessions",
    )
    finding = await ctx.add_finding(
        {
            "title": "Reflected XSS",
            "description": "marker reflected",
            "severity": "high",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cvss_score": 6.1,
        }
    )
    assert finding.severity == "high"
    assert finding.cvss_score == 6.1

    await ctx.add_mitigation({"finding_id": finding.id, "title": "Encode output", "kind": "patch"})
    assert ctx.state.get_finding(finding.id).status == "mitigated"
    assert "finding" in seen and "mitigation" in seen


async def test_encrypted_roundtrip(isolated_home, tmp_path):
    directory = tmp_path / "sessions"
    ctx = SharedContext.create(target="http://example.test", bus=EventBus(), directory=directory)
    await ctx.add_finding({"title": "Issue", "severity": "medium"})
    path = ctx.save()
    raw = path.read_bytes()
    assert b"Issue" not in raw  # payload must be encrypted at rest

    loaded = SharedContext.load(ctx.state.id, directory=directory)
    assert loaded.state.findings[0].title == "Issue"
    assert loaded.state.target == "http://example.test"


async def test_duplicate_findings_are_merged(isolated_home, tmp_path):
    """Re-testing the same issue across rounds must not duplicate the report."""
    ctx = SharedContext.create(target="http://t", bus=EventBus(), directory=tmp_path / "sessions")
    first = await ctx.add_finding(
        {
            "title": "Reflected XSS in index.php page parameter",
            "endpoint": "/mutillidae/index.php?page=",
            "severity": "high",
            "cvss_score": 6.1,
            "evidence": "first evidence",
        }
    )
    second = await ctx.add_finding(
        {
            "title": "Reflected XSS in index.php page parameter - Blue review confirmed",
            "endpoint": "/mutillidae/index.php?page=",
            "severity": "high",
            "cvss_score": 6.1,
            "evidence": "second evidence",
        }
    )
    assert second.id == first.id
    assert len(ctx.state.findings) == 1
    assert "first evidence" in first.evidence
    assert "second evidence" in first.evidence  # evidence is enriched, not lost


async def test_duplicate_merge_keeps_the_stronger_score(isolated_home, tmp_path):
    ctx = SharedContext.create(target="http://t", bus=EventBus(), directory=tmp_path / "sessions")
    await ctx.add_finding(
        {"title": "SQLi in q", "endpoint": "/search", "severity": "medium", "cvss_score": 5.3}
    )
    merged = await ctx.add_finding(
        {
            "title": "SQLi in q",
            "endpoint": "/search",
            "severity": "critical",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_score": 9.8,
        }
    )
    assert len(ctx.state.findings) == 1
    assert merged.cvss_score == 9.8
    assert merged.severity == "critical"


async def test_distinct_findings_are_not_merged(isolated_home, tmp_path):
    ctx = SharedContext.create(target="http://t", bus=EventBus(), directory=tmp_path / "sessions")
    await ctx.add_finding({"title": "Missing CSP header", "endpoint": "/"})
    await ctx.add_finding({"title": "Missing HSTS header", "endpoint": "/"})
    await ctx.add_finding({"title": "SQL injection in q", "endpoint": "/search"})
    await ctx.add_finding({"title": "Reflected XSS in q", "endpoint": "/search"})
    assert len(ctx.state.findings) == 4


async def test_general_category_does_not_merge_everything(isolated_home, tmp_path):
    """The default category must not act as a match on its own."""
    ctx = SharedContext.create(target="http://t", bus=EventBus(), directory=tmp_path / "sessions")
    await ctx.add_finding({"title": "Alpha issue", "endpoint": "/x"})
    await ctx.add_finding({"title": "Beta problem", "endpoint": "/x"})
    assert len(ctx.state.findings) == 2


async def test_same_category_and_endpoint_merges_rewording(isolated_home, tmp_path):
    ctx = SharedContext.create(target="http://t", bus=EventBus(), directory=tmp_path / "sessions")
    first = await ctx.add_finding(
        {
            "title": "phpinfo.php still served at web root",
            "endpoint": "/phpinfo.php",
            "category": "information_disclosure",
        }
    )
    second = await ctx.add_finding(
        {
            "title": "phpinfo.php still served unauthenticated",
            "endpoint": "/phpinfo.php",
            "category": "information_disclosure",
        }
    )
    assert second.id == first.id
    assert len(ctx.state.findings) == 1


async def test_dedupe_can_be_disabled(isolated_home, tmp_path):
    ctx = SharedContext.create(target="http://t", bus=EventBus(), directory=tmp_path / "sessions")
    await ctx.add_finding({"title": "Same", "endpoint": "/x"})
    await ctx.add_finding({"title": "Same", "endpoint": "/x", "dedupe": False})
    assert len(ctx.state.findings) == 2


def test_endpoint_normalisation():
    from splitagent.core.context import _normalise_endpoint

    assert _normalise_endpoint("/") == "/"
    assert _normalise_endpoint("/dav/") == "/dav"
    assert _normalise_endpoint("/ and /dav/") == "/dav"
    assert _normalise_endpoint("port 80") == "/"
    assert _normalise_endpoint("") == "/"
    # Query strings are not part of identity.
    assert _normalise_endpoint("/a?x=1") == "/a"


def test_title_overlap_precision():
    from splitagent.core.context import _titles_overlap

    # Same issue, reworded -> merge.
    assert _titles_overlap("HTTP TRACE method enabled", "HTTP TRACE method enabled on both stacks")
    assert _titles_overlap(
        "WebDAV enabled with DELETE method", "WebDAV handler still mounted on /dav/"
    )
    assert _titles_overlap(
        "phpinfo.php still served at web root",
        "phpinfo.php still served unauthenticated",
    )
    # Different issues -> keep separate.
    assert not _titles_overlap("Missing CSP header", "Missing HSTS header")
    assert not _titles_overlap("SQL injection in login", "Cross-site scripting in search")
    assert not _titles_overlap("vsftpd 2.3.4 backdoor", "MySQL root with blank password")


async def test_todo_list(isolated_home, tmp_path):
    bus = EventBus()
    seen: list[str] = []
    bus.subscribe(lambda event: seen.append(event.type))
    ctx = SharedContext.create(target="t", bus=bus, directory=tmp_path / "sessions")
    assert ctx.todo_summary() == "(no task list yet)"

    await ctx.set_todos(
        [
            {"content": "Recon the target", "status": "completed", "priority": "high"},
            {"content": "Test injection", "status": "in_progress", "priority": "high"},
            {"content": "Bogus", "status": "nonsense", "priority": "weird"},
            {"content": "", "status": "pending", "priority": "low"},
        ]
    )
    assert len(ctx.state.todos) == 3  # empty content dropped
    assert ctx.state.todos[1]["status"] == "in_progress"
    assert ctx.state.todos[2]["status"] == "pending"  # invalid -> pending
    assert ctx.state.todos[2]["priority"] == "medium"
    assert "todos" in seen
    assert "Test injection" in ctx.todo_summary()

    path = ctx.save()
    assert path.exists()
    loaded = SharedContext.load(ctx.state.id, directory=tmp_path / "sessions")
    assert len(loaded.state.todos) == 3


async def test_resilience_score(isolated_home, tmp_path):
    ctx = SharedContext.create(target="t", bus=EventBus(), directory=tmp_path / "sessions")
    assert ctx.state.resilience_score() == 100.0
    await ctx.add_finding({"title": "a", "severity": "critical"})
    await ctx.add_finding({"title": "b", "severity": "low"})
    assert ctx.state.resilience_score() == 0.0
    finding = ctx.state.findings[0]
    await ctx.add_mitigation({"finding_id": finding.id, "title": "fix"})
    assert ctx.state.resilience_score() > 0.0
