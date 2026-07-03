"""Issue #767 — the Upstream dnsbl-counter parse layer must distinguish an
ABSENT row from a READ ERROR, so a transient lock/race (e.g. SQLITE_BUSY while
the chrooted Python module holds the DB open in WAL mode) is never misreported
as a regression in the Python DB-init seed (``_db_create``).

Pins ``_parse_counter_output`` (``tests/smoke/test_smoke_upstream_block.py``),
the pure parse function extracted from ``_read_upstream_counter`` so it is
unit-testable off-appliance — same precedent as ``test_smoke_diag_redaction.py``
importing from ``tests.smoke.helpers``. ``tests/smoke`` is ``--ignore``d by the
default ``python -m pytest`` run (see ``pyproject.toml``), but importing a
symbol from it works fine.

RED -> GREEN evidence: before this change, ``_parse_counter_output`` did not
exist at all (the import below would raise ``ImportError``) and the inline
parsing in ``_read_upstream_counter`` returned the single sentinel ``-1`` for
EVERY failure case (absent row, ``querySingle`` returning ``FALSE``, a thrown
exception, and missing/unparsable pfSsh.php delimiters alike) — so a caller
could never tell "no row" from "read blew up". Post-change, absence is -1,
error is -2 with a non-empty detail, and a genuine counter is >= 0.
"""

from __future__ import annotations

import subprocess
from typing import cast

import pytest

from tests.smoke import test_smoke_upstream_block as upstream_mod
from tests.smoke.conftest import SmokeVM
from tests.smoke.test_smoke_upstream_block import _CTR_CLOSE, _CTR_OPEN, _parse_counter_output


def test_valid_counter_parses_to_int_with_no_detail() -> None:
    out = f"{_CTR_OPEN}7|{_CTR_CLOSE}"
    assert _parse_counter_output(out) == (7, "")


def test_valid_counter_survives_pfssh_banner_noise_around_the_delimiters() -> None:
    out = f"pfSsh.php shell (WELCOME)\nsome banner text\n{_CTR_OPEN}42|{_CTR_CLOSE}\ntrailing noise"
    assert _parse_counter_output(out) == (42, "")


def test_absent_row_parses_to_negative_one_with_no_detail() -> None:
    """querySingle() returning NULL (no matching row) -> -1, not an error."""
    out = f"{_CTR_OPEN}-1|{_CTR_CLOSE}"
    assert _parse_counter_output(out) == (-1, "")


def test_error_sentinel_carries_its_message() -> None:
    """A thrown SQLITE_BUSY (or any Throwable) -> -2 with the exception detail."""
    out = f"{_CTR_OPEN}-2|database is locked{_CTR_CLOSE}"
    assert _parse_counter_output(out) == (-2, "database is locked")


def test_message_containing_extra_pipes_splits_on_the_first_only() -> None:
    out = f"{_CTR_OPEN}-2|SQLSTATE[HY000]: General error: 5 database is locked{_CTR_CLOSE}"
    assert _parse_counter_output(out) == (-2, "SQLSTATE[HY000]: General error: 5 database is locked")


def test_missing_delimiters_is_a_read_error_not_an_absent_row() -> None:
    """A pfSsh.php transport failure (banner only, no payload) must not collapse to -1."""
    out = "pfSsh.php shell (WELCOME)\nno counter payload here"
    value, detail = _parse_counter_output(out)
    assert value == -2
    assert detail  # must name what went wrong, not just fail silently
    assert "no counter payload here" in detail


def test_empty_output_is_a_read_error() -> None:
    value, detail = _parse_counter_output("")
    assert value == -2
    assert detail


def test_non_integer_value_is_a_read_error_with_detail() -> None:
    out = f"{_CTR_OPEN}not-a-number|garbled{_CTR_CLOSE}"
    value, detail = _parse_counter_output(out)
    assert value == -2
    assert "not-a-number" in detail


def test_php_eval_transport_failure_is_a_read_error_carrying_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A nonzero php_eval returncode (SSH/pfSsh.php transport failure) -> -2 with the
    stderr in the detail — not the generic "no delimited counter" parse message."""

    def fake_php_eval(vm: SmokeVM, snippet: str, *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=255, stdout="", stderr="ssh: connect refused")

    monkeypatch.setattr(upstream_mod.h, "php_eval", fake_php_eval)
    value, detail = upstream_mod._read_upstream_counter(cast(SmokeVM, object()))
    assert value == -2
    assert "rc=255" in detail
    assert "ssh: connect refused" in detail
