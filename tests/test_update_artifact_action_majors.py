"""Tests for scripts/misc/update_artifact_action_majors.py — refresh of
``_KNOWN_ARTIFACT_MAJORS`` in tests/test_issue2231_workflow_hygiene.py.

No network: every test drives the pure parse/render/replace functions (or
main() with fetch monkeypatched) against recorded GitHub tag-ref fixtures.
The live matching-refs fetch is never exercised here.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from tests import test_issue2231_workflow_hygiene as hygiene

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "misc" / "update_artifact_action_majors.py"
_spec = importlib.util.spec_from_file_location("update_artifact_action_majors", _TOOL)
assert _spec is not None and _spec.loader is not None
uaam = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = uaam
_spec.loader.exec_module(uaam)

_HYGIENE_SNIPPET = """\
# Frozen 2026-08-26 from the GitHub API (issue #2725). upload-artifact has no v8
# tag (latest v7.0.1); download-artifact does (v8.0.1). Highest common is v7.
_KNOWN_ARTIFACT_MAJORS: dict[str, frozenset[int]] = {
    "upload": frozenset({4, 5, 6, 7}),
    "download": frozenset({3, 4, 5, 6, 7, 8}),
}
_HIGHEST_COMMON_ARTIFACT_MAJOR = max(_KNOWN_ARTIFACT_MAJORS["upload"] & _KNOWN_ARTIFACT_MAJORS["download"])
"""

_V7_LIVE_PINS = """\
on: workflow_dispatch
jobs:
  up:
    steps:
      - uses: actions/upload-artifact@v7
        with: {name: pkg}
  down:
    needs: up
    steps:
      - uses: actions/download-artifact@v7
        with: {name: pkg}
"""


def _refs(*tags: str) -> list[dict[str, str]]:
    return [{"ref": f"refs/tags/{tag}"} for tag in tags]


def _current_api_fixture() -> dict[str, list[dict[str, str]]]:
    """Recorded shape: upload has no v8; download does. Highest common is 7."""
    return {
        "upload": _refs("1.0.0", "v3-node20", "v4", "v4.3.4", "v5", "v6", "v7", "v7.0.1"),
        "download": _refs("v3", "v4", "v5", "v6", "v7", "v8", "v8.0.1"),
    }


# --------------------------------------------------------------------------- #
# parse — published major tags from the matching-refs JSON
# --------------------------------------------------------------------------- #


def test_parse_tag_refs_keeps_exact_and_semver_majors_drops_unprefixed_and_suffix() -> None:
    majors = uaam.parse_tag_refs(_refs("1.0.0", "v3-node20", "v4", "v4.3.4", "v7", "v7.0.1"))
    assert majors == frozenset({4, 7})
    assert 1 not in majors
    assert 3 not in majors


def test_parse_tag_refs_refuses_html_and_non_list_payloads() -> None:
    with pytest.raises(SystemExit, match="not a JSON list"):
        uaam.parse_tag_refs("<html>tags</html>")
    with pytest.raises(SystemExit, match="not a JSON list"):
        uaam.parse_tag_refs({"ref": "refs/tags/v7"})


def test_parse_tag_refs_refuses_missing_or_non_string_ref() -> None:
    with pytest.raises(SystemExit, match="missing string 'ref'"):
        uaam.parse_tag_refs([{"object": {"sha": "abc"}}])
    with pytest.raises(SystemExit, match="missing string 'ref'"):
        uaam.parse_tag_refs([{"ref": 7}])


def test_parse_tag_refs_accepts_json_text() -> None:
    payload = json.dumps(_refs("v7", "v7.0.1"))
    assert uaam.parse_tag_refs(payload) == frozenset({7})


# --------------------------------------------------------------------------- #
# highest common — intersection, never union (issue #2385 / #2728)
# --------------------------------------------------------------------------- #


def test_highest_common_stays_7_when_upload_has_no_v8() -> None:
    majors = {kind: uaam.parse_tag_refs(payload) for kind, payload in _current_api_fixture().items()}
    assert majors["upload"] == frozenset({4, 5, 6, 7})
    assert 8 not in majors["upload"]
    assert uaam.highest_common(majors) == 7


def test_highest_common_becomes_8_when_fixture_adds_upload_v8() -> None:
    payloads = _current_api_fixture()
    payloads["upload"] = payloads["upload"] + _refs("v8", "v8.0.0")
    majors = {kind: uaam.parse_tag_refs(payload) for kind, payload in payloads.items()}
    assert uaam.highest_common(majors) == 8


def test_one_sided_new_major_does_not_raise_highest_common() -> None:
    payloads = _current_api_fixture()
    payloads["download"] = payloads["download"] + _refs("v9")
    majors = {kind: uaam.parse_tag_refs(payload) for kind, payload in payloads.items()}
    assert 9 in majors["download"]
    assert 9 not in majors["upload"]
    assert uaam.highest_common(majors) == 7


def test_empty_intersection_is_refused() -> None:
    majors = {"upload": frozenset({4}), "download": frozenset({8})}
    with pytest.raises(SystemExit, match="empty intersection"):
        uaam.highest_common(majors)


def test_empty_action_majors_are_refused() -> None:
    with pytest.raises(SystemExit, match="no published majors"):
        uaam.require_plausible({"upload": frozenset(), "download": frozenset({3, 4})})


# --------------------------------------------------------------------------- #
# rewrite — table only; highest-common stays derived
# --------------------------------------------------------------------------- #


def test_replace_table_rewrites_known_majors_and_leaves_derivation() -> None:
    majors = {"upload": frozenset({4, 5, 6, 7, 8}), "download": frozenset({3, 4, 5, 6, 7, 8})}
    rendered = uaam.render_table(majors, synced="2026-08-27", highest=8)
    updated = uaam.replace_table(_HYGIENE_SNIPPET, rendered)
    assert "_KNOWN_ARTIFACT_MAJORS" in updated
    assert "frozenset({4, 5, 6, 7, 8})" in updated
    assert (
        '_HIGHEST_COMMON_ARTIFACT_MAJOR = max(_KNOWN_ARTIFACT_MAJORS["upload"] '
        '& _KNOWN_ARTIFACT_MAJORS["download"])' in updated
    )
    assert "issue #2728" in updated
    assert "2026-08-27" in updated
    assert "issue #2725" not in updated


def test_check_exits_1_when_table_is_stale_and_0_when_current(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "hygiene.py"
    target.write_text(_HYGIENE_SNIPPET, encoding="utf-8")
    payloads = _current_api_fixture()
    payloads["upload"] = payloads["upload"] + _refs("v8")

    def fake_fetch(kind: str, timeout: float = 15) -> Any:
        return payloads[kind]

    monkeypatch.setattr(uaam, "fetch_tag_payload", fake_fetch)
    monkeypatch.setattr(uaam, "DEFAULT_HYGIENE_FILE", target)
    assert uaam.main(["--check"]) == 1
    assert target.read_text(encoding="utf-8") == _HYGIENE_SNIPPET
    assert uaam.main([]) == 0
    rewritten = target.read_text(encoding="utf-8")
    assert "frozenset({4, 5, 6, 7, 8})" in rewritten
    assert uaam.main(["--check"]) == 0


# --------------------------------------------------------------------------- #
# live-pin gate — refresh must not weaken parse + highest-common (issue #2726)
# --------------------------------------------------------------------------- #


def test_upload_v8_fixture_reports_drift_on_remaining_v7_pins(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads = _current_api_fixture()
    payloads["upload"] = payloads["upload"] + _refs("v8")
    majors = {kind: uaam.parse_tag_refs(payload) for kind, payload in payloads.items()}
    highest = uaam.highest_common(majors)
    assert highest == 8
    monkeypatch.setattr(hygiene, "_KNOWN_ARTIFACT_MAJORS", majors)
    monkeypatch.setattr(hygiene, "_HIGHEST_COMMON_ARTIFACT_MAJOR", highest)
    offences = hygiene._live_artifact_offences({"w.yml": _V7_LIVE_PINS})
    assert any("upload-artifact" in item and "v8" in item and "not v7" in item for item in offences), offences
    assert any("download-artifact" in item and "v8" in item and "not v7" in item for item in offences), offences


def test_one_sided_major_does_not_silently_allow_a_mismatched_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    """A refresh that adds v9 to download only must not accept a v9/v9 pair:
    upload@v9 is still unpublished, so the parse-based existence gate must
    reject it. Highest common stays 7 (#2385 / #2728).
    """
    payloads = _current_api_fixture()
    payloads["download"] = payloads["download"] + _refs("v9")
    majors = {kind: uaam.parse_tag_refs(payload) for kind, payload in payloads.items()}
    highest = uaam.highest_common(majors)
    assert highest == 7
    monkeypatch.setattr(hygiene, "_KNOWN_ARTIFACT_MAJORS", majors)
    monkeypatch.setattr(hygiene, "_HIGHEST_COMMON_ARTIFACT_MAJOR", highest)
    sources = {
        "w.yml": """\
on: workflow_dispatch
jobs:
  up:
    steps:
      - uses: actions/upload-artifact@v9
        with: {name: pkg}
  down:
    needs: up
    steps:
      - uses: actions/download-artifact@v9
        with: {name: pkg}
"""
    }
    offences = hygiene._live_artifact_offences(sources)
    assert any("upload-artifact@v9" in item and "not a known" in item for item in offences), offences
    assert any("download-artifact" in item and "not v9" in item for item in offences), offences
    mismatched = {
        "w.yml": """\
on: workflow_dispatch
jobs:
  up:
    steps:
      - uses: actions/upload-artifact@v7
        with: {name: pkg}
  down:
    needs: up
    steps:
      - uses: actions/download-artifact@v9
        with: {name: pkg}
"""
    }
    chain = hygiene._artifact_chain_offences(mismatched)
    assert any("mismatches producers" in item for item in chain), chain
