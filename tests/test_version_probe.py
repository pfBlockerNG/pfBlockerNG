"""Tests for scripts/check-pfsense-versions.py.

Branch coverage rules (CLAUDE.md):
  every condition is tested in both directions; before-state is asserted
  in transition tests.

Scenario: Version probe against the Netgate docs page fixture
  Background:
    Given the fixture HTML contains Plus 26.x (supported + future),
          Plus 25.x (all EOL), CE 2.9 (future), CE 2.8 (supported)
    And the BUILD matrix represents the current ci-metadata state
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

# ── Load the hyphen-named script as a module ───────────────────────────────────

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check-pfsense-versions.py"
_spec = importlib.util.spec_from_file_location("check_pfsense_versions", _SCRIPT)
assert _spec is not None and _spec.loader is not None
cvs = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cvs
_spec.loader.exec_module(cvs)

# ── Fixture paths ─────────────────────────────────────────────────────────────

FIXTURE_HTML = Path(__file__).resolve().parent / "fixtures" / "netgate_versions_fixture.html"


def _fixture() -> str:
    return FIXTURE_HTML.read_text(encoding="utf-8")


# ── Minimal HTML helpers ──────────────────────────────────────────────────────


def _make_table(rows: list[str]) -> str:
    """Wrap row HTML strings in a minimal versions table."""
    header = (
        "<tr>"
        "<th>Version</th>"
        "<th>Support</th>"
        "<th>Released</th>"
        "<th>Config Rev</th>"
        "<th>FreeBSD Version</th>"
        "<th>Branch</th>"
        "</tr>"
    )
    body = "\n".join(rows)
    return f"<table><thead>{header}</thead><tbody>{body}</tbody></table>"


def _make_row(
    version: str,
    support_alt: str,
    released: str,
    freebsd: str,
    branch: str,
) -> str:
    """Build one <tr> matching the Netgate page format."""
    support_cell = f'<img alt="{support_alt}" src="dummy.png">' if support_alt else ""
    return (
        f"<tr>"
        f"<td>{version}</td>"
        f"<td>{support_cell}</td>"
        f"<td>{released}</td>"
        f"<td>24.0</td>"
        f"<td><a>{freebsd}</a></td>"
        f"<td>{branch}</td>"
        f"</tr>"
    )


# ── Support-cell classification ───────────────────────────────────────────────


class TestSupportFromCell:
    """Scenario: The Support cell text → support state mapping.

    Given a Support cell value
    When _support_from_cell() classifies it
    Then the result matches the icon semantics from the Netgate page
    """

    def test_fa_check_yields_supported(self) -> None:
        # Given the cell contains the 'fa-check' alt value
        assert cvs._support_from_cell("fa-check") == "supported"

    def test_fa_times_yields_eol(self) -> None:
        # Given the cell contains the 'fa-times' alt value
        assert cvs._support_from_cell("fa-times") == "eol"

    def test_fa_clock_yields_future(self) -> None:
        # Given the cell contains the 'fa-clock' alt value (TBD/unreleased row)
        assert cvs._support_from_cell("fa-clock") == "future"

    def test_empty_cell_defaults_to_future(self) -> None:
        # Given an empty Support cell (no icon) — treated conservatively as future,
        # not as missing-but-supported, so it never opens a false-positive nudge.
        assert cvs._support_from_cell("") == "future"


# ── Channel discriminator ─────────────────────────────────────────────────────


class TestChannelFromBranch:
    """Scenario: Branch column value → channel.

    Given a Branch column value from the Netgate page
    When _channel_from_branch() classifies it
    Then Plus and CE are correctly identified from the prefix
    """

    def test_plus_releng_prefix_yields_plus(self) -> None:
        # Given a branch name with 'plus-RELENG_' prefix
        assert cvs._channel_from_branch("plus-RELENG_26_03") == "Plus"

    def test_releng_prefix_yields_ce(self) -> None:
        # Given a bare 'RELENG_' prefix (no 'plus-' prefix)
        assert cvs._channel_from_branch("RELENG_2_8_0") == "CE"

    def test_unrecognised_branch_yields_none(self) -> None:
        # Given an unknown Branch value (e.g. main, HEAD)
        assert cvs._channel_from_branch("main") is None

    def test_channel_discrimination_is_case_insensitive(self) -> None:
        # Given lowercase variants of the branch prefixes
        assert cvs._channel_from_branch("plus-releng_26_03") == "Plus"
        assert cvs._channel_from_branch("releng_2_8_0") == "CE"


# ── Version normalization ─────────────────────────────────────────────────────


class TestNormalize:
    """Scenario: Raw version string → Major.Minor family key.

    Given a raw version string
    When _normalize() is called
    Then both channels collapse to their leading two dot components (CE Y.Z,
         Plus YY.MM) — every patch level of a family maps to one key, the
         floating Major.Minor form the matrix uses (no '.x' suffix).
    """

    def test_ce_patch_normalizes_to_family(self) -> None:
        # Given a CE version with a patch component → Major.Minor (no '.x')
        assert cvs._normalize("2.8.1") == "2.8"

    def test_ce_zero_patch_normalizes_to_family(self) -> None:
        # Given CE version 2.9.0 (zero patch — same rule)
        assert cvs._normalize("2.9.0") == "2.9"

    def test_ce_already_major_minor_is_idempotent(self) -> None:
        # Given a CE version already at Major.Minor: it stays '2.8' so it matches
        # the matrix key. Regression guard: the old rule emitted '2.8.x', which
        # never matched '2.8' and triggered a false 'missing from matrix' nudge.
        assert cvs._normalize("2.8") == "2.8"

    def test_plus_patch_normalizes_to_year_month(self) -> None:
        # Given a Plus version with a patch component
        assert cvs._normalize("26.03.1") == "26.03"

    def test_plus_without_patch_is_idempotent(self) -> None:
        # Given Plus version already at Year.Month level
        assert cvs._normalize("26.07") == "26.07"

    def test_single_component_version_uses_fallback_branch(self) -> None:
        # Given a raw version with no dot (len(parts) < 2): the false side of the
        # Major.Minor split returns the input unchanged.
        assert cvs._normalize("2") == "2"


# ── FreeBSD major extraction ──────────────────────────────────────────────────


class TestFreeBSDMajor:
    """Scenario: FreeBSD Version column → major number.

    Given a FreeBSD Version string from the Netgate page
    When _freebsd_major() is called
    Then only the leading major integer is returned, ignoring -CURRENT/@hash
    """

    def test_freebsd_16_current_with_hash(self) -> None:
        assert cvs._freebsd_major("16.0-CURRENT@c215eef34550") == "16"

    def test_freebsd_15_current_with_hash(self) -> None:
        assert cvs._freebsd_major("15.0-CURRENT@bf06074106cf") == "15"

    def test_freebsd_release_suffix_stripped(self) -> None:
        # Ensure -RELEASE variants are also handled (the matrix uses -RELEASE)
        assert cvs._freebsd_major("15.0-RELEASE") == "15"

    def test_empty_string_returns_empty(self) -> None:
        assert cvs._freebsd_major("") == ""


# ── Full parse + family grouping ──────────────────────────────────────────────


class TestParseFixture:
    """Scenario: Parse the real Netgate-page fixture HTML.

    Given the fixture HTML extracted from the actual Netgate page snapshot
    When parse_tables() + group_families() are called
    Then all expected families are extracted with correct status, channel,
         and FreeBSD major — proving Plus support (the old probe gap)
    """

    @pytest.fixture(autouse=True)
    def _load(self) -> None:
        p = cvs._TableParser()
        p.feed(_fixture())
        rows = cvs.parse_tables(p.tables)
        self.families = {(f.version, f.channel): f for f in cvs.group_families(rows)}

    def test_ce_2_8_is_supported(self) -> None:
        fam = self.families[("2.8", "CE")]
        assert fam.status == "supported"

    def test_ce_2_8_has_freebsd_15(self) -> None:
        fam = self.families[("2.8", "CE")]
        assert fam.freebsd_major == "15"

    def test_ce_2_9_is_future(self) -> None:
        # Before-state: 2.9 has no released row → future (not supported/EOL)
        fam = self.families[("2.9", "CE")]
        assert fam.status == "future"

    def test_ce_2_9_released_is_tbd(self) -> None:
        fam = self.families[("2.9", "CE")]
        assert fam.released == "TBD"

    def test_plus_26_03_is_supported(self) -> None:
        # Plus family presence proves the old 'CE only' gap is fixed
        fam = self.families[("26.03", "Plus")]
        assert fam.status == "supported"

    def test_plus_26_03_has_freebsd_16(self) -> None:
        # FreeBSD major for Plus 26.03 is 16, distinct from CE 2.8 (FreeBSD 15)
        fam = self.families[("26.03", "Plus")]
        assert fam.freebsd_major == "16"

    def test_plus_26_07_is_future(self) -> None:
        fam = self.families[("26.07", "Plus")]
        assert fam.status == "future"

    def test_plus_25_x_families_are_eol(self) -> None:
        eol_fams = [f for f in self.families.values() if f.channel == "Plus" and f.version.startswith("25.")]
        assert eol_fams, "expected Plus 25.x families in fixture"
        for fam in eol_fams:
            assert fam.status == "eol", f"{fam.version} should be eol"


# ── Diff: supported_missing ───────────────────────────────────────────────────


class TestDiffSupportedMissing:
    """Scenario: Supported families absent from the matrix are reported.

    Background:
      Given the fixture has CE 2.8 (supported) and Plus 26.03 (supported)

    Tests prove both the positive case (missing → reported) and the negative
    case (present → not reported), so a regression in either direction fails.
    """

    @pytest.fixture(autouse=True)
    def _parse(self) -> None:
        p = cvs._TableParser()
        p.feed(_fixture())
        rows = cvs.parse_tables(p.tables)
        self.families = cvs.group_families(rows)

    def test_ce_2_8_present_in_matrix_not_reported(self) -> None:
        # Given 2.8 IS in the matrix (the floating Major.Minor key)
        # Then it does NOT appear in supported_missing. Regression guard: the old
        # '2.8.x' normalization never matched '2.8' and falsely reported it missing.
        matrix = [{"pfsense_version": "2.8", "channel": "CE"}]
        result = cvs.diff(self.families, matrix)
        versions = [e["version"] for e in result["supported_missing"]]
        assert "2.8" not in versions

    def test_plus_26_03_absent_from_matrix_is_reported(self) -> None:
        # Given 26.03 is NOT in the matrix (matrix only has 2.8)
        # Then 26.03 DOES appear in supported_missing
        matrix = [{"pfsense_version": "2.8", "channel": "CE"}]
        result = cvs.diff(self.families, matrix)
        versions = [e["version"] for e in result["supported_missing"]]
        assert "26.03" in versions

    def test_channel_and_freebsd_major_in_missing_entry(self) -> None:
        # Given Plus 26.03 is absent
        # Then the entry carries channel=Plus and freebsd_major=16
        matrix = [{"pfsense_version": "2.8", "channel": "CE"}]
        result = cvs.diff(self.families, matrix)
        entry = next(e for e in result["supported_missing"] if e["version"] == "26.03")
        assert entry["channel"] == "Plus"
        assert entry["freebsd_major"] == "16"

    def test_eol_families_never_in_supported_missing(self) -> None:
        # Given Plus 25.x families are all EOL
        # Then they do NOT appear in supported_missing even with an empty matrix
        result = cvs.diff(self.families, [])
        versions = [e["version"] for e in result["supported_missing"]]
        assert not any(v.startswith("25.") for v in versions)


# ── Diff: future ─────────────────────────────────────────────────────────────


class TestDiffFuture:
    """Scenario: Future/TBD families land in the 'future' list, not supported_missing.

    Background:
      Given CE 2.9.0 and Plus 26.07 are TBD on the fixture page
    """

    @pytest.fixture(autouse=True)
    def _parse(self) -> None:
        p = cvs._TableParser()
        p.feed(_fixture())
        rows = cvs.parse_tables(p.tables)
        self.families = cvs.group_families(rows)

    def test_ce_2_9_in_future_not_missing(self) -> None:
        result = cvs.diff(self.families, [])
        future_versions = [e["version"] for e in result["future"]]
        missing_versions = [e["version"] for e in result["supported_missing"]]
        assert "2.9" in future_versions
        assert "2.9" not in missing_versions

    def test_plus_26_07_in_future_not_missing(self) -> None:
        result = cvs.diff(self.families, [])
        future_versions = [e["version"] for e in result["future"]]
        missing_versions = [e["version"] for e in result["supported_missing"]]
        assert "26.07" in future_versions
        assert "26.07" not in missing_versions

    def test_future_entry_has_tbd_released(self) -> None:
        result = cvs.diff(self.families, [])
        entry_29 = next(e for e in result["future"] if e["version"] == "2.9")
        assert entry_29["released"] == "TBD"

    def test_future_entry_includes_freebsd_major(self) -> None:
        result = cvs.diff(self.families, [])
        entry_29 = next(e for e in result["future"] if e["version"] == "2.9")
        assert entry_29["freebsd_major"] == "16"


# ── run() integration: graceful degradation ───────────────────────────────────


class TestGracefulDegradation:
    """Scenario: Any input failure → empty JSON result, exit 0, no exception.

    Per the 'graceful' contract: the script must NEVER crash the workflow.
    """

    def _run_capture(self, html: str | None, matrix_arg: str | None) -> dict[str, Any]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cvs.run(html, matrix_arg)
        assert rc == 0, "run() must return 0 (never fail the workflow)"
        return json.loads(buf.getvalue())

    def test_empty_html_yields_empty_result(self) -> None:
        result = self._run_capture("", None)
        assert result == {"supported_missing": [], "future": []}

    def test_html_without_tables_yields_empty_result(self) -> None:
        html = "<html><body><p>no tables here</p></body></html>"
        result = self._run_capture(html, None)
        assert result == {"supported_missing": [], "future": []}

    def test_garbage_html_yields_empty_result(self) -> None:
        # Even structurally broken HTML must not raise
        html = "<<<NOT HTML AT ALL>>>"
        result = self._run_capture(html, None)
        assert result == {"supported_missing": [], "future": []}

    def test_fixture_with_empty_matrix_returns_valid_json(self) -> None:
        # Fixture with empty matrix: all supported families appear in supported_missing
        result = self._run_capture(_fixture(), "[]")
        assert isinstance(result["supported_missing"], list)
        assert isinstance(result["future"], list)
        # At least CE 2.8 and Plus 26.03 should be missing
        missing = [e["version"] for e in result["supported_missing"]]
        assert "2.8" in missing
        assert "26.03" in missing


# ── Family status: mixed members ─────────────────────────────────────────────


class TestFamilyStatusWithMixedMembers:
    """Scenario: A family with both supported and future rows is 'supported'.

    Background:
      The 26.x family has 26.07 (future) AND 26.03/26.03.1 (supported).
    """

    def test_family_with_supported_member_is_supported(self) -> None:
        rows = [
            cvs._Row("26.03", "supported", "2026-04-01", "16.0-CURRENT@abc", "16", "Plus", "26.03"),
            cvs._Row("26.07", "future", "TBD", "16.0-CURRENT@abc", "16", "Plus", "26.07"),
        ]
        # Before: 26.03 alone = supported family
        fams = {(f.version, f.channel): f for f in cvs.group_families(rows)}
        assert fams[("26.03", "Plus")].status == "supported"
        # After: 26.07 alone = future family
        assert fams[("26.07", "Plus")].status == "future"
