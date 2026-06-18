"""Tests for upstream/external DNS block detection — issue #267 (Quad9 domain logging).

Covers:
- ``_parse_ede_options`` (pure EDE wire parser)
- ``classify_upstream_block`` (NXRA / EDE15 / EDE17 classifier)
- ``UpstreamBlock`` result type
- ``_log_upstream_block`` counter enqueue branch (sqlite3_dnsbl_con guard)

All tests are pure off-box — no Unbound API calls, no fixtures, no I/O.
"""

from __future__ import annotations

import pytest
from unboundmodule import RCODE_NOERROR, RCODE_NXDOMAIN

import pfb_unbound
from pfb_unbound import (
    EDE_BLOCKED,
    EDE_FILTERED,
    EDNS_OPT_CODE_EDE,
    UpstreamBlock,
    _log_upstream_block,
    _parse_ede_options,
    classify_upstream_block,
)

# ---------------------------------------------------------------------------
# NXRA path — NXDOMAIN + RA cleared
# ---------------------------------------------------------------------------


class TestClassifyUpstreamBlockNXRA:
    def test_nxdomain_ra_cleared_returns_nxra_block(self) -> None:
        # NXDOMAIN reply with RA bit CLEARED -> upstream block signal NXRA.
        result = classify_upstream_block(rcode=RCODE_NXDOMAIN, ra_available=False)
        assert result is not None
        assert result.signal == "NXRA"
        assert result.label == "NXRA"
        assert result.provider == ""

    def test_nxdomain_ra_set_returns_none(self) -> None:
        # BEFORE/AFTER pair: same NXDOMAIN rcode but RA SET -> natural NXDOMAIN, not blocked.
        # Proves RA=False is the discriminator, not the rcode alone.
        result = classify_upstream_block(rcode=RCODE_NXDOMAIN, ra_available=True)
        assert result is None

    def test_noerror_ra_cleared_no_ede_returns_none(self) -> None:
        # NOERROR + RA cleared (no EDE) -> not a block. Proves rcode gate.
        result = classify_upstream_block(rcode=RCODE_NOERROR, ra_available=False)
        assert result is None

    def test_nxra_with_ede_none_still_detected(self) -> None:
        # ede=None (omitted / not present in reply) -> NXRA logic fires normally.
        result = classify_upstream_block(rcode=RCODE_NXDOMAIN, ra_available=False, ede=None)
        assert result is not None
        assert result.signal == "NXRA"

    def test_nxra_with_ede_empty_list_still_detected(self) -> None:
        # ede=[] (option present but empty list) -> NXRA logic fires normally.
        result = classify_upstream_block(rcode=RCODE_NXDOMAIN, ra_available=False, ede=[])
        assert result is not None
        assert result.signal == "NXRA"


# ---------------------------------------------------------------------------
# EDE 15 (Blocked) path
# ---------------------------------------------------------------------------


class TestClassifyUpstreamBlockEDE15:
    def test_ede15_returns_ede15_block(self) -> None:
        # EDE info_code 15 -> EDE15 block, regardless of rcode/RA.
        # Tests with NOERROR + RA set to prove EDE wins independently of NXRA logic.
        result = classify_upstream_block(
            rcode=RCODE_NOERROR,
            ra_available=True,
            ede=[(EDE_BLOCKED, "Quad9")],
        )
        assert result is not None
        assert result.signal == "EDE15"
        assert result.label == "EDE15 (Blocked)"
        assert result.provider == "Quad9"

    def test_ede15_extra_text_stripped(self) -> None:
        # Extra-text with surrounding whitespace is stripped; provider is the stripped value.
        result = classify_upstream_block(
            rcode=RCODE_NOERROR,
            ra_available=True,
            ede=[(EDE_BLOCKED, "  Quad9  ")],
        )
        assert result is not None
        assert result.provider == "Quad9"

    def test_ede15_empty_extra_text_provider_is_empty_string(self) -> None:
        # Empty extra_text -> provider == "".
        result = classify_upstream_block(
            rcode=RCODE_NOERROR,
            ra_available=True,
            ede=[(EDE_BLOCKED, "")],
        )
        assert result is not None
        assert result.provider == ""

    def test_ede15_whitespace_only_extra_text_provider_is_empty_string(self) -> None:
        # Whitespace-only extra_text -> strips to "" -> provider == "".
        result = classify_upstream_block(
            rcode=RCODE_NOERROR,
            ra_available=True,
            ede=[(EDE_BLOCKED, "   ")],
        )
        assert result is not None
        assert result.provider == ""


# ---------------------------------------------------------------------------
# EDE 17 (Filtered) path
# ---------------------------------------------------------------------------


class TestClassifyUpstreamBlockEDE17:
    def test_ede17_returns_ede17_block(self) -> None:
        # EDE info_code 17 -> EDE17 block; label and provider set correctly.
        result = classify_upstream_block(
            rcode=RCODE_NOERROR,
            ra_available=True,
            ede=[(EDE_FILTERED, "CleanBrowsing")],
        )
        assert result is not None
        assert result.signal == "EDE17"
        assert result.label == "EDE17 (Filtered)"
        assert result.provider == "CleanBrowsing"

    def test_ede17_empty_provider(self) -> None:
        # EDE 17 with no extra-text -> provider == "".
        result = classify_upstream_block(
            rcode=RCODE_NOERROR,
            ra_available=True,
            ede=[(EDE_FILTERED, "")],
        )
        assert result is not None
        assert result.signal == "EDE17"
        assert result.provider == ""


# ---------------------------------------------------------------------------
# EDE 15 and 17 both present — 15 (Blocked) wins
# ---------------------------------------------------------------------------


class TestClassifyUpstreamBlockEDEPrecedence:
    def test_ede15_and_ede17_both_present_ede15_wins(self) -> None:
        # When both EDE 15 and 17 appear, EDE 15 (Blocked) takes precedence.
        result = classify_upstream_block(
            rcode=RCODE_NOERROR,
            ra_available=True,
            ede=[(EDE_FILTERED, "provB"), (EDE_BLOCKED, "provA")],
        )
        assert result is not None
        assert result.signal == "EDE15"
        assert result.provider == "provA"

    def test_ede15_before_ede17_in_list_ede15_wins(self) -> None:
        # 15 listed first -> same result; 15 always wins over 17.
        result = classify_upstream_block(
            rcode=RCODE_NOERROR,
            ra_available=True,
            ede=[(EDE_BLOCKED, "first"), (EDE_FILTERED, "second")],
        )
        assert result is not None
        assert result.signal == "EDE15"
        assert result.provider == "first"


# ---------------------------------------------------------------------------
# Unrecognised EDE info_codes — fall through to NXRA / None
# ---------------------------------------------------------------------------


class TestClassifyUpstreamBlockUnrecognisedEDE:
    def test_unrecognised_ede_plus_nxra_returns_nxra(self) -> None:
        # Unrecognised EDE (e.g. info_code 0) does not trigger a block on its own;
        # falls through to NXRA path if NXDOMAIN + RA cleared.
        result = classify_upstream_block(
            rcode=RCODE_NXDOMAIN,
            ra_available=False,
            ede=[(0, "something")],
        )
        assert result is not None
        assert result.signal == "NXRA"

    def test_unrecognised_ede_plus_noerror_returns_none(self) -> None:
        # Unrecognised EDE + NOERROR -> neither EDE path nor NXRA fires -> None.
        result = classify_upstream_block(
            rcode=RCODE_NOERROR,
            ra_available=True,
            ede=[(0, "something"), (1, "another"), (18, "")],
        )
        assert result is None

    def test_unrecognised_ede_18_ignored(self) -> None:
        # EDE 18 (Prohibited) is not a recognised upstream-block signal -> None.
        result = classify_upstream_block(
            rcode=RCODE_NOERROR,
            ra_available=True,
            ede=[(18, "")],
        )
        assert result is None


# ---------------------------------------------------------------------------
# Constants correctness
# ---------------------------------------------------------------------------


class TestUpstreamBlockConstants:
    def test_ede_blocked_constant(self) -> None:
        # RFC 8914 INFO-CODE 15 = Blocked.
        assert EDE_BLOCKED == 15

    def test_ede_filtered_constant(self) -> None:
        # RFC 8914 INFO-CODE 17 = Filtered.
        assert EDE_FILTERED == 17


# ---------------------------------------------------------------------------
# UpstreamBlock result type fields
# ---------------------------------------------------------------------------


class TestUpstreamBlockType:
    def test_upstream_block_fields_accessible(self) -> None:
        # UpstreamBlock is a frozen/immutable type with signal, label, provider fields.
        b = UpstreamBlock(signal="NXRA", label="NXRA", provider="")
        assert b.signal == "NXRA"
        assert b.label == "NXRA"
        assert b.provider == ""

    def test_upstream_block_is_immutable(self) -> None:
        # UpstreamBlock cannot be mutated (frozen dataclass / NamedTuple).
        b = UpstreamBlock(signal="EDE15", label="EDE15 (Blocked)", provider="Quad9")
        try:
            b.signal = "other"  # type: ignore[misc]
            raise AssertionError("Expected AttributeError — UpstreamBlock must be immutable")
        except (AttributeError, TypeError):
            pass  # expected: frozen dataclass raises AttributeError; NamedTuple raises TypeError


# ---------------------------------------------------------------------------
# _parse_ede_options — pure EDE wire parser
# ---------------------------------------------------------------------------


class TestParseEdeOptions:
    """Unit tests for the pure _parse_ede_options helper (issue #267, Part A).

    All inputs are (opt_code, opt_data) pairs; outputs are (info_code, extra_text).
    No Unbound API calls; no fixtures.
    """

    def test_valid_ede15_option_parses_correctly(self) -> None:
        # EDNS_OPT_CODE_EDE (15) + 2-byte info_code (15) + UTF-8 text -> (15, "Quad9").
        # info_code 15 (0x000F) in 2 big-endian bytes, followed by "Quad9".
        opt_data = (15).to_bytes(2, "big") + b"Quad9"
        result = _parse_ede_options([(EDNS_OPT_CODE_EDE, opt_data)])
        assert result == [(15, "Quad9")]

    def test_valid_ede17_option_parses_correctly(self) -> None:
        # INFO-CODE 17 (0x0011) + "CleanBrowsing" -> (17, "CleanBrowsing").
        opt_data = (17).to_bytes(2, "big") + b"CleanBrowsing"
        result = _parse_ede_options([(EDNS_OPT_CODE_EDE, opt_data)])
        assert result == [(17, "CleanBrowsing")]

    def test_ede_option_with_empty_extra_text(self) -> None:
        # 2-byte info_code only (no EXTRA-TEXT) -> extra_text == "".
        opt_data = (15).to_bytes(2, "big")
        result = _parse_ede_options([(EDNS_OPT_CODE_EDE, opt_data)])
        assert result == [(15, "")]

    def test_non_ede_opt_code_is_skipped(self) -> None:
        # opt_code 12 (NSID) is not EDE — must be skipped; empty result.
        opt_data = b"\x00\x0f" + b"ignored"
        result = _parse_ede_options([(12, opt_data)])
        assert result == []

    def test_ede_opt_data_shorter_than_2_bytes_is_skipped(self) -> None:
        # A 1-byte opt_data cannot hold a 2-byte info_code — skip it.
        # Before-state: len(opt_data) == 1 < 2 → skipped. ZERO entries returned.
        result = _parse_ede_options([(EDNS_OPT_CODE_EDE, b"\x0f")])
        assert result == []

    def test_zero_length_opt_data_is_skipped(self) -> None:
        # Empty opt_data — skip; no entry in result.
        result = _parse_ede_options([(EDNS_OPT_CODE_EDE, b"")])
        assert result == []

    def test_multiple_options_only_ede_included(self) -> None:
        # Mix of EDE and non-EDE: only the EDE one is returned.
        opt_data_ede = (15).to_bytes(2, "big") + b"Provider"
        result = _parse_ede_options([(12, b"nsid-data"), (EDNS_OPT_CODE_EDE, opt_data_ede), (10, b"other")])
        assert result == [(15, "Provider")]

    def test_multiple_ede_options_all_returned(self) -> None:
        # Two EDE options in sequence: both parsed.
        # Before-state: 1 EDE option → 1 result. After adding a second → 2 results.
        opt15 = (15).to_bytes(2, "big") + b"ProvA"
        result_one = _parse_ede_options([(EDNS_OPT_CODE_EDE, opt15)])
        assert len(result_one) == 1
        opt17 = (17).to_bytes(2, "big") + b"ProvB"
        result_two = _parse_ede_options([(EDNS_OPT_CODE_EDE, opt15), (EDNS_OPT_CODE_EDE, opt17)])
        assert result_two == [(15, "ProvA"), (17, "ProvB")]

    def test_empty_input_returns_empty(self) -> None:
        # Empty iterable -> empty result; no error.
        assert _parse_ede_options([]) == []

    def test_edns_opt_code_ede_constant_value(self) -> None:
        # EDNS option code 15 carries RFC 8914 EDE data (distinct from INFO-codes).
        assert EDNS_OPT_CODE_EDE == 15

    def test_utf8_extra_text_decoded(self) -> None:
        # Non-ASCII UTF-8 in EXTRA-TEXT is decoded correctly.
        text = "Föö"
        opt_data = (15).to_bytes(2, "big") + text.encode("utf-8")
        result = _parse_ede_options([(EDNS_OPT_CODE_EDE, opt_data)])
        assert result == [(15, "Föö")]

    def test_invalid_utf8_replaced_not_raised(self) -> None:
        # Malformed UTF-8 bytes are replaced (decode(..., "replace")), not raised.
        opt_data = (15).to_bytes(2, "big") + b"\xff\xfe"
        result = _parse_ede_options([(EDNS_OPT_CODE_EDE, opt_data)])
        assert len(result) == 1
        assert result[0][0] == 15
        # The invalid bytes are replaced with U+FFFD; just assert no exception
        # and info_code is correct.
        assert "�" in result[0][1]


# ---------------------------------------------------------------------------
# AA guard — authoritative NXDOMAIN excluded from NXRA detection
# ---------------------------------------------------------------------------


class TestClassifyUpstreamBlockAAGuard:
    def test_nxdomain_ra0_aa0_detected_as_nxra(self) -> None:
        # NXDOMAIN + RA=0 + AA=0 (Quad9 block shape) -> NXRA block.
        result = classify_upstream_block(rcode=RCODE_NXDOMAIN, ra_available=False, aa_authoritative=False)
        assert result is not None
        assert result.signal == "NXRA"

    def test_nxdomain_ra0_aa1_not_detected(self) -> None:
        # BEFORE/AFTER pair with above: same NXDOMAIN+RA=0, but AA=1 (authoritative NXDOMAIN).
        # AA=1 excludes it — must return None, not NXRA.
        result = classify_upstream_block(rcode=RCODE_NXDOMAIN, ra_available=False, aa_authoritative=True)
        assert result is None

    def test_nxdomain_ra1_aa0_not_detected(self) -> None:
        # NXDOMAIN + RA=1 + AA=0 (forwarder-natural) -> excluded by RA=1 guard.
        result = classify_upstream_block(rcode=RCODE_NXDOMAIN, ra_available=True, aa_authoritative=False)
        assert result is None

    def test_ede15_wins_regardless_of_flags(self) -> None:
        # EDE15 present + NXDOMAIN + RA=1 + AA=1 -> EDE15 block (EDE wins regardless of RA/AA).
        result = classify_upstream_block(
            rcode=RCODE_NXDOMAIN,
            ra_available=True,
            aa_authoritative=True,
            ede=[(EDE_BLOCKED, "Quad9")],
        )
        assert result is not None
        assert result.signal == "EDE15"
        assert result.provider == "Quad9"


# ---------------------------------------------------------------------------
# _log_upstream_block — sqlite3_dnsbl_con guard (counter enqueue)
# ---------------------------------------------------------------------------


class TestLogUpstreamBlockCounterEnqueue:
    """Scenario: _log_upstream_block enqueues a dnsbl counter task iff sqlite3_dnsbl_con is truthy.

    Background:
        The function writes CSV to dnsbl.log + unified.log, then — when the SQLite
        DNSBL connection is active — calls pfb_db_enqueue(("dnsbl", "Upstream")) to
        increment the aggregate Upstream row counter.  The guard ``if pfb["sqlite3_dnsbl_con"]``
        must be the discriminator: the enqueue fires when truthy and is suppressed when falsy.

    Given:
        A valid UpstreamBlock result (NXRA signal, no provider) and a monkeypatched
        pfb_db_enqueue that records calls.  pfb_log is patched to a no-op so no real
        file I/O occurs.
    """

    _RESULT = UpstreamBlock(signal="NXRA", label="NXRA", provider="")

    def test_enqueues_upstream_counter_when_connection_active(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """
        When sqlite3_dnsbl_con is truthy, _log_upstream_block enqueues ("dnsbl", "Upstream").

        Before-state (con=False): no enqueue occurs (proven in the companion test).
        After-state (con=True): exactly one ("dnsbl", "Upstream") task is enqueued.
        """
        calls: list[tuple[str, ...]] = []
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda task: calls.append(task))
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda _log, _line: None)

        # Before: connection inactive -> no enqueue (verified in companion test; establish
        # that the initial fixture state is falsy so the flip is meaningful).
        assert not pfb_unbound.pfb["sqlite3_dnsbl_con"]

        # Flip to active.
        pfb_unbound.pfb["sqlite3_dnsbl_con"] = True

        _log_upstream_block("example.com", "192.0.2.1", self._RESULT, "A")

        dnsbl_tasks = [t for t in calls if len(t) == 2 and t[0] == "dnsbl"]
        assert dnsbl_tasks == [("dnsbl", "Upstream")], f"Expected exactly one ('dnsbl', 'Upstream') task; got: {calls}"

    def test_no_enqueue_when_connection_inactive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """
        When sqlite3_dnsbl_con is falsy, _log_upstream_block does NOT enqueue any dnsbl task.

        This is the discriminating before-state: same function call, con=False -> no task.
        Proves the guard is real and the counter is not always incremented.
        """
        calls: list[tuple[str, ...]] = []
        monkeypatch.setattr(pfb_unbound, "pfb_db_enqueue", lambda task: calls.append(task))
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda _log, _line: None)

        # Fixture default: sqlite3_dnsbl_con is False (see conftest reset_pfb_globals).
        assert not pfb_unbound.pfb["sqlite3_dnsbl_con"]

        _log_upstream_block("example.com", "192.0.2.1", self._RESULT, "A")

        dnsbl_tasks = [t for t in calls if len(t) == 2 and t[0] == "dnsbl"]
        assert dnsbl_tasks == [], f"Expected no dnsbl enqueue with sqlite3_dnsbl_con=False; got: {calls}"
