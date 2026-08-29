"""Unit tests for scripts/agent/coderabbit_cli_report.py."""

from __future__ import annotations

from scripts.agent.coderabbit_cli_report import format_report, parse_events


def test_parse_skips_heartbeats_and_keeps_findings() -> None:
    raw = "\n".join(
        [
            '{"type":"heartbeat"}',
            '{"type":"finding","severity":"major","fileName":"scripts/x.py","comment":"null deref"}',
            '{"type":"complete","status":"ok","findings":1}',
        ]
    )
    events = parse_events(raw)
    text = format_report(events)
    assert "scripts/x.py" in text
    assert "null deref" in text
    assert "major" in text
    assert "file-level" in text
    assert "workflow_dispatch" in text


def test_review_skipped_is_success_copy() -> None:
    raw = '{"type":"complete","status":"review_skipped","findings":0,"message":"No changes detected"}'
    text = format_report(parse_events(raw))
    assert "review_skipped" in text
    assert "No changes detected" in text


def test_no_line_range_is_stated() -> None:
    text = format_report([])
    assert "no line range" in text
