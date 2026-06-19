"""Tests for scripts/redmine_to_github.py — pure helper functions.

All network/env I/O is excluded: only the pure helpers are covered here.
The test suite honours CLAUDE.md's coverage mandate:
  - Every branch of every function is exercised.
  - Transition tests assert the before-state before the flip.
  - Non-trivial idempotency logic (``missing_journals``) uses BDD specs.

Scenario: missing_journals idempotency core
  Background:
    Given a list of Redmine journals, some with notes and some without
    And a set of journal IDs already posted to GitHub

  Scenario A: nothing posted yet
    Given posted_ids is empty
    When missing_journals is called
    Then all note-journals are returned

  Scenario B: some already posted
    Given posted_ids contains a subset of the note-journal IDs
    When missing_journals is called
    Then only the un-posted note-journals are returned

  Scenario C: all already posted
    Given posted_ids contains every note-journal ID
    When missing_journals is called
    Then an empty list is returned

  Scenario D: out-of-order posted IDs still resolved correctly
    Given posted_ids contains IDs in a different order than the journals
    When missing_journals is called
    Then only the genuinely missing ones are returned, in chronological order
"""

from __future__ import annotations

import importlib.util
import sys
from datetime import date
from pathlib import Path
from typing import Any

# ── Load the script as a module (hyphened name → importlib) ───────────────────

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "redmine_to_github.py"
_spec = importlib.util.spec_from_file_location("redmine_to_github", _SCRIPT)
assert _spec is not None and _spec.loader is not None
rtg = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = rtg
_spec.loader.exec_module(rtg)


# ── Fixtures / helpers ─────────────────────────────────────────────────────────


def _issue(
    *,
    issue_id: int = 1,
    tracker: str = "Bug",
    priority: str = "Normal",
    subject: str = "Test subject",
    description: str = "",
    status: str = "New",
    category: str = "pfBlockerNG",
    author: str = "Alice",
    assignee: str | None = None,
    created_on: str = "2024-01-01T00:00:00Z",
    updated_on: str = "2024-06-01T00:00:00Z",
    journals: list[dict] | None = None,
    attachments: list[dict] | None = None,
) -> dict[str, Any]:
    """Build a minimal Redmine issue dict."""
    return {
        "id": issue_id,
        "tracker": {"name": tracker},
        "priority": {"name": priority},
        "subject": subject,
        "description": description,
        "status": {"name": status},
        "category": {"name": category},
        "author": {"name": author},
        "assigned_to": {"name": assignee} if assignee else None,
        "created_on": created_on,
        "updated_on": updated_on,
        "journals": journals or [],
        "attachments": attachments or [],
    }


def _journal(
    *,
    journal_id: int,
    notes: str = "",
    author: str = "Bob",
    created_on: str = "2024-03-01T00:00:00Z",
) -> dict[str, Any]:
    """Build a minimal Redmine journal dict."""
    return {
        "id": journal_id,
        "user": {"name": author},
        "notes": notes,
        "created_on": created_on,
    }


# ── map_labels ─────────────────────────────────────────────────────────────────


def test_map_labels_always_includes_redmine_imported() -> None:
    """redmine-imported is always in the result, even for unknown tracker/priority."""
    result = rtg.map_labels(_issue(tracker="Unknown", priority="Unknown"))
    assert "redmine-imported" in result


def test_map_labels_bug_tracker() -> None:
    result = rtg.map_labels(_issue(tracker="Bug"))
    assert "bug" in result


def test_map_labels_feature_tracker() -> None:
    result = rtg.map_labels(_issue(tracker="Feature"))
    assert "enhancement" in result


def test_map_labels_feature_request_tracker() -> None:
    result = rtg.map_labels(_issue(tracker="Feature request"))
    assert "enhancement" in result


def test_map_labels_unknown_tracker_adds_no_type_label() -> None:
    result = rtg.map_labels(_issue(tracker="Support"))
    # Neither bug nor enhancement
    assert "bug" not in result
    assert "enhancement" not in result
    # But redmine-imported still present
    assert "redmine-imported" in result


def test_map_labels_priority_normal() -> None:
    result = rtg.map_labels(_issue(priority="Normal"))
    assert "priority: normal" in result


def test_map_labels_priority_high() -> None:
    result = rtg.map_labels(_issue(priority="High"))
    assert "priority: high" in result


def test_map_labels_priority_low() -> None:
    result = rtg.map_labels(_issue(priority="Low"))
    assert "priority: low" in result


def test_map_labels_priority_urgent() -> None:
    result = rtg.map_labels(_issue(priority="Urgent"))
    assert "priority: urgent" in result


def test_map_labels_priority_immediate() -> None:
    result = rtg.map_labels(_issue(priority="Immediate"))
    assert "priority: immediate" in result


def test_map_labels_unknown_priority_adds_no_priority_label() -> None:
    result = rtg.map_labels(_issue(priority="Medium"))
    assert not any(lbl.startswith("priority:") for lbl in result)


def test_map_labels_keyword_unbound_in_subject() -> None:
    result = rtg.map_labels(_issue(subject="Unbound crashes on reload"))
    assert "unbound" in result


def test_map_labels_keyword_dnsbl_in_description() -> None:
    result = rtg.map_labels(_issue(description="DNSBL list is not loaded"))
    assert "dnsbl" in result


def test_map_labels_keyword_geoip() -> None:
    result = rtg.map_labels(_issue(subject="GeoIP table empty"))
    assert "geoip" in result


def test_map_labels_no_keyword_hit() -> None:
    result = rtg.map_labels(_issue(subject="Something unrelated", description=""))
    # Should not include topic labels
    assert "unbound" not in result
    assert "dnsbl" not in result


def test_map_labels_deduplication() -> None:
    """A tracker + keyword that would produce the same label only appears once."""
    # "bug" label from tracker; "bug" does not appear in keywords — but test dedup
    # with redmine-imported which always appears first.
    result = rtg.map_labels(_issue(tracker="Bug"))
    assert result.count("redmine-imported") == 1
    assert result.count("bug") == 1


def test_map_labels_stable_order() -> None:
    """redmine-imported is always first."""
    result = rtg.map_labels(_issue(tracker="Bug", priority="High", subject="dnsbl"))
    assert result[0] == "redmine-imported"


# ── render_issue_body ──────────────────────────────────────────────────────────


def test_render_issue_body_contains_marker() -> None:
    body = rtg.render_issue_body(_issue(issue_id=42), "https://redmine.example.com")
    assert "<!-- redmine-id: 42 -->" in body


def test_render_issue_body_marker_id_matches_issue() -> None:
    body = rtg.render_issue_body(_issue(issue_id=99), "https://redmine.example.com")
    assert "<!-- redmine-id: 99 -->" in body


def test_render_issue_body_back_link_present() -> None:
    body = rtg.render_issue_body(_issue(issue_id=7), "https://redmine.pfsense.org")
    assert "https://redmine.pfsense.org/issues/7" in body


def test_render_issue_body_description_included() -> None:
    body = rtg.render_issue_body(
        _issue(description="Detailed description here"),
        "https://redmine.example.com",
    )
    assert "Detailed description here" in body


def test_render_issue_body_missing_description_no_crash() -> None:
    iss = _issue(description="")
    iss["description"] = None  # simulate absent field
    body = rtg.render_issue_body(iss, "https://redmine.example.com")
    assert "<!-- redmine-id:" in body  # still renders


def test_render_issue_body_attachments_present() -> None:
    attachments = [{"filename": "screenshot.png", "content_url": "https://example.com/f/screenshot.png"}]
    body = rtg.render_issue_body(_issue(attachments=attachments), "https://redmine.example.com")
    assert "[screenshot.png](https://example.com/f/screenshot.png)" in body


def test_render_issue_body_no_attachments_section_when_empty() -> None:
    body = rtg.render_issue_body(_issue(attachments=[]), "https://redmine.example.com")
    assert "**Attachments:**" not in body


def test_render_issue_body_assignee_omitted_when_none() -> None:
    iss = _issue(assignee=None)
    body = rtg.render_issue_body(iss, "https://redmine.example.com")
    # Row for assignee should render the dash placeholder
    assert "| Assignee | — |" in body


def test_render_issue_body_assignee_shown_when_present() -> None:
    body = rtg.render_issue_body(_issue(assignee="Charlie"), "https://redmine.example.com")
    assert "Charlie" in body


# ── render_comment_body ────────────────────────────────────────────────────────


def test_render_comment_body_contains_journal_marker() -> None:
    j = _journal(journal_id=101, notes="Some note")
    body = rtg.render_comment_body(j)
    assert "<!-- redmine-journal-id: 101 -->" in body


def test_render_comment_body_marker_id_matches_journal() -> None:
    j = _journal(journal_id=202, notes="Another note")
    body = rtg.render_comment_body(j)
    assert "<!-- redmine-journal-id: 202 -->" in body


def test_render_comment_body_attribution_header() -> None:
    j = _journal(journal_id=1, notes="Hi", author="Dave", created_on="2024-05-10T12:00:00Z")
    body = rtg.render_comment_body(j)
    assert "**Dave**" in body
    assert "2024-05-10" in body


def test_render_comment_body_notes_included() -> None:
    j = _journal(journal_id=1, notes="This is the comment text.")
    body = rtg.render_comment_body(j)
    assert "This is the comment text." in body


def test_render_comment_body_missing_user_does_not_crash() -> None:
    j: dict[str, Any] = {"id": 5, "notes": "A note", "created_on": "2024-01-01T00:00:00Z"}
    # No 'user' key at all
    body = rtg.render_comment_body(j)
    assert "<!-- redmine-journal-id: 5 -->" in body


# ── parse_redmine_id ───────────────────────────────────────────────────────────


def test_parse_redmine_id_present() -> None:
    body = "Some text\n<!-- redmine-id: 123 -->"
    assert rtg.parse_redmine_id(body) == 123


def test_parse_redmine_id_absent_returns_none() -> None:
    assert rtg.parse_redmine_id("No marker here") is None


def test_parse_redmine_id_malformed_returns_none() -> None:
    # Marker with non-numeric id
    assert rtg.parse_redmine_id("<!-- redmine-id: abc -->") is None


def test_parse_redmine_id_whitespace_tolerant() -> None:
    assert rtg.parse_redmine_id("<!--   redmine-id:   456   -->") == 456


def test_parse_redmine_id_multiple_markers_returns_first() -> None:
    body = "<!-- redmine-id: 10 --> ... <!-- redmine-id: 20 -->"
    assert rtg.parse_redmine_id(body) == 10


# ── parse_posted_journal_ids ───────────────────────────────────────────────────


def test_parse_posted_journal_ids_empty_input() -> None:
    assert rtg.parse_posted_journal_ids([]) == set()


def test_parse_posted_journal_ids_single_comment() -> None:
    bodies = ["**Author** commented\n\nNote\n\n<!-- redmine-journal-id: 77 -->"]
    assert rtg.parse_posted_journal_ids(bodies) == {77}


def test_parse_posted_journal_ids_multiple_comments() -> None:
    bodies = [
        "<!-- redmine-journal-id: 1 -->",
        "<!-- redmine-journal-id: 2 -->",
        "<!-- redmine-journal-id: 3 -->",
    ]
    assert rtg.parse_posted_journal_ids(bodies) == {1, 2, 3}


def test_parse_posted_journal_ids_no_marker_in_comment() -> None:
    bodies = ["Regular comment with no marker"]
    assert rtg.parse_posted_journal_ids(bodies) == set()


def test_parse_posted_journal_ids_mixed_comments() -> None:
    bodies = [
        "No marker here",
        "<!-- redmine-journal-id: 42 -->",
        "Also no marker",
        "<!-- redmine-journal-id: 99 -->",
    ]
    assert rtg.parse_posted_journal_ids(bodies) == {42, 99}


def test_parse_posted_journal_ids_whitespace_tolerant() -> None:
    bodies = ["<!--  redmine-journal-id:  55  -->"]
    assert rtg.parse_posted_journal_ids(bodies) == {55}


# ── note_journals ──────────────────────────────────────────────────────────────


def test_note_journals_drops_empty_notes() -> None:
    journals = [
        _journal(journal_id=1, notes=""),
        _journal(journal_id=2, notes="Real note"),
        _journal(journal_id=3, notes="   "),  # whitespace-only
    ]
    result = rtg.note_journals(journals)
    assert [j["id"] for j in result] == [2]


def test_note_journals_keeps_all_with_notes() -> None:
    journals = [
        _journal(journal_id=1, notes="First"),
        _journal(journal_id=2, notes="Second"),
    ]
    result = rtg.note_journals(journals)
    assert len(result) == 2


def test_note_journals_sorted_chronologically() -> None:
    journals = [
        _journal(journal_id=3, notes="Third", created_on="2024-03-01T00:00:00Z"),
        _journal(journal_id=1, notes="First", created_on="2024-01-01T00:00:00Z"),
        _journal(journal_id=2, notes="Second", created_on="2024-02-01T00:00:00Z"),
    ]
    result = rtg.note_journals(journals)
    assert [j["id"] for j in result] == [1, 2, 3]


def test_note_journals_empty_input() -> None:
    assert rtg.note_journals([]) == []


def test_note_journals_all_empty_notes() -> None:
    journals = [
        _journal(journal_id=1, notes=""),
        _journal(journal_id=2, notes=""),
    ]
    assert rtg.note_journals(journals) == []


# ── missing_journals (idempotency core — BDD) ─────────────────────────────────


# Background: a shared set of journals used across all four scenarios.
_JOURNALS: list[dict[str, Any]] = [
    _journal(journal_id=10, notes="First note", created_on="2024-01-01T00:00:00Z"),
    _journal(journal_id=11, notes="", created_on="2024-01-02T00:00:00Z"),  # no notes — dropped
    _journal(journal_id=12, notes="Second note", created_on="2024-01-03T00:00:00Z"),
    _journal(journal_id=13, notes="Third note", created_on="2024-01-04T00:00:00Z"),
]


def test_missing_journals_scenario_a_nothing_posted_returns_all() -> None:
    """
    Scenario A: nothing posted yet → all note-journals returned.

    Given posted_ids is empty
    When missing_journals is called
    Then all three note-journals (ids 10, 12, 13) are returned in order
    """
    # Before state: posted_ids is empty.
    posted_before: set[int] = set()
    assert posted_before == set()

    # When
    result = rtg.missing_journals(_JOURNALS, posted_before)

    # Then
    assert [j["id"] for j in result] == [10, 12, 13]


def test_missing_journals_scenario_b_some_posted_returns_remainder() -> None:
    """
    Scenario B: some already posted → only un-posted note-journals returned.

    Given posted_ids = {10} (first note already on GitHub)
    When missing_journals is called
    Then only journals 12 and 13 are returned
    """
    # Before state: without the filter, all three would be returned.
    all_result = rtg.missing_journals(_JOURNALS, set())
    assert [j["id"] for j in all_result] == [10, 12, 13]

    # When
    posted: set[int] = {10}
    result = rtg.missing_journals(_JOURNALS, posted)

    # Then
    assert [j["id"] for j in result] == [12, 13]


def test_missing_journals_scenario_c_all_posted_returns_empty() -> None:
    """
    Scenario C: all already posted → empty list returned.

    Given posted_ids = {10, 12, 13} (every note-journal already on GitHub)
    When missing_journals is called
    Then an empty list is returned
    """
    # Before state: with an empty posted set, all three are returned.
    before = rtg.missing_journals(_JOURNALS, set())
    assert len(before) == 3

    # When
    posted: set[int] = {10, 12, 13}
    result = rtg.missing_journals(_JOURNALS, posted)

    # Then
    assert result == []


def test_missing_journals_scenario_d_out_of_order_posted_ids() -> None:
    """
    Scenario D: posted_ids in a different order than journals.

    Given posted_ids = {13, 10} (last and first posted, middle missing)
    When missing_journals is called
    Then only journal 12 is returned (correct gap-fill, chronological order)
    """
    # Before state: with only {13} posted, journals 10 and 12 would be missing.
    partial = rtg.missing_journals(_JOURNALS, {13})
    assert [j["id"] for j in partial] == [10, 12]

    # When: additionally mark 10 as posted (out-of-order set)
    posted: set[int] = {13, 10}
    result = rtg.missing_journals(_JOURNALS, posted)

    # Then
    assert [j["id"] for j in result] == [12]


def test_missing_journals_empty_journals_list() -> None:
    """No journals → always empty, regardless of posted_ids."""
    assert rtg.missing_journals([], set()) == []
    assert rtg.missing_journals([], {1, 2, 3}) == []


def test_missing_journals_journals_with_only_empty_notes() -> None:
    """Journals with empty notes are never in the missing set."""
    journals = [
        _journal(journal_id=1, notes=""),
        _journal(journal_id=2, notes="   "),
    ]
    assert rtg.missing_journals(journals, set()) == []


# ── issue_updated_after ────────────────────────────────────────────────────────


def test_issue_updated_after_strictly_after_cutoff_is_true() -> None:
    iss = _issue(updated_on="2024-06-15T10:00:00Z")
    assert rtg.issue_updated_after(iss, date(2024, 6, 14)) is True


def test_issue_updated_after_on_cutoff_day_is_false() -> None:
    """'After' is exclusive — same day as cutoff is NOT after."""
    iss = _issue(updated_on="2024-06-14T23:59:59Z")
    assert rtg.issue_updated_after(iss, date(2024, 6, 14)) is False


def test_issue_updated_after_before_cutoff_is_false() -> None:
    iss = _issue(updated_on="2024-06-01T00:00:00Z")
    assert rtg.issue_updated_after(iss, date(2024, 6, 14)) is False


def test_issue_updated_after_missing_field_is_false() -> None:
    iss = _issue()
    iss["updated_on"] = ""
    assert rtg.issue_updated_after(iss, date(2024, 1, 1)) is False


def test_issue_updated_after_none_field_is_false() -> None:
    iss = _issue()
    iss["updated_on"] = None  # type: ignore[assignment]
    assert rtg.issue_updated_after(iss, date(2024, 1, 1)) is False


def test_issue_updated_after_malformed_date_is_false() -> None:
    iss = _issue(updated_on="not-a-date")
    assert rtg.issue_updated_after(iss, date(2024, 1, 1)) is False


# ── Round-trip: render → parse (integration of pure helpers) ──────────────────


def test_round_trip_issue_marker() -> None:
    """Rendered body's marker is parsed back to the original id."""
    issue_id = 777
    body = rtg.render_issue_body(_issue(issue_id=issue_id), "https://redmine.example.com")
    assert rtg.parse_redmine_id(body) == issue_id


def test_round_trip_comment_marker() -> None:
    """Rendered comment body's marker is parsed back to the original journal id."""
    j = _journal(journal_id=55, notes="Round-trip note")
    body = rtg.render_comment_body(j)
    ids = rtg.parse_posted_journal_ids([body])
    assert ids == {55}


def test_full_idempotency_round_trip() -> None:
    """
    Full round-trip: render comments → parse posted ids → compute missing.

    Simulates one comment already posted and verifies only the other is missing.
    """
    journals = [
        _journal(journal_id=100, notes="First"),
        _journal(journal_id=101, notes="Second"),
    ]
    # Simulate: journal 100 has been posted.
    posted_body = rtg.render_comment_body(journals[0])
    posted_ids = rtg.parse_posted_journal_ids([posted_body])

    # Before: without the posted body, both would be missing.
    all_missing = rtg.missing_journals(journals, set())
    assert [j["id"] for j in all_missing] == [100, 101]

    # After: with journal 100 marked as posted, only 101 is missing.
    remaining = rtg.missing_journals(journals, posted_ids)
    assert [j["id"] for j in remaining] == [101]


# --- parse_issue_ids (the explicit --issue-ids list parser) --------------------


def test_parse_issue_ids_comma_separated() -> None:
    assert rtg.parse_issue_ids("16893,16830,16814") == [16893, 16830, 16814]


def test_parse_issue_ids_space_and_newline_separated() -> None:
    assert rtg.parse_issue_ids("16893 16830\n16814") == [16893, 16830, 16814]


def test_parse_issue_ids_mixed_separators_and_padding() -> None:
    assert rtg.parse_issue_ids("  16893, 16830 ,16814 ") == [16893, 16830, 16814]


def test_parse_issue_ids_dedupes_preserving_first_seen_order() -> None:
    # 16830 repeats; the result keeps first-seen order and drops the dup.
    assert rtg.parse_issue_ids("16893,16830,16893,16814,16830") == [16893, 16830, 16814]


def test_parse_issue_ids_drops_non_numeric_tokens() -> None:
    assert rtg.parse_issue_ids("16893, foo, 16830, 12.5, -4") == [16893, 16830]


def test_parse_issue_ids_empty_returns_empty_list() -> None:
    assert rtg.parse_issue_ids("") == []
    assert rtg.parse_issue_ids("   ,  \n ") == []


def test_parse_issue_ids_all_non_numeric_returns_empty() -> None:
    # All-junk input must parse to [] so the CLI can reject it instead of
    # silently falling back to migrating every open issue.
    assert rtg.parse_issue_ids("foo, bar, baz") == []
