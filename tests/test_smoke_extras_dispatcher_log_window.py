"""``_log_delta``/``_log_window`` and stub-record capture/restore must survive a real
newsyslog rotation and a shared ``stub_dns`` teardown without corrupting state.

An independent local (non-appliance) probe of ``test_extras_dispatcher_deferral``'s
prior helpers found three real, reproducible defects with no VM required — the
module's fixture/helper logic is import-safe and its shell-driving methods accept
any object exposing ``.ssh()`` (precedent: ``test_smoke_unblock_egress``'s off-VM
coverage of a smoke-module helper):

1. A size-only rotation heuristic silently read the WRONG file region once a
   renamed-away backup's replacement regrew past the old byte offset — a real
   diagnostic could be lost with no signal, producing a false PASS on an absence
   assertion.
2. ``stub_dns.clear_cname()`` as blanket teardown erased an UNRELATED name's
   override, not just the fixture's own.
3. The MaxMind locale CSV fixture-teardown had no restore path at all.

This module pins (1) and (2) as permanent local regressions against the actual,
unchanged helpers (``_log_window``, `_log_delta`, `_capture_stub_records`,
`_restore_stub_records`) — real file renames/compression, real shell commands, the
real `_StubDnsServer`. (3) is exercised by the fixture's own real appliance runs
(the CSV round-trip only makes sense against the real pfSense filesystem layout the
fixture targets) and is not duplicated here.
"""

from __future__ import annotations

import bz2
import gzip
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from tests.smoke import test_extras_dispatcher_deferral as m
from tests.smoke.conftest import _StubDnsServer


class _ShellVM:
    """Runs `.ssh()`'s shell commands for real, against a real local file — the
    same shape ``SmokeVM.ssh`` presents (a single already-quoted command string in,
    a ``subprocess.CompletedProcess``-shaped result out) minus the SSH transport.

    ``_inode()`` emits FreeBSD's ``stat -f FORMAT`` (BSD's format-string flag) —
    the real pfSense guest's actual, correct syntax, exercised for real by the
    appliance-tier fixture. GNU ``stat``'s ``-f`` means something else entirely
    ("filesystem status"; it silently treats a bare ``%i`` as an extra filename
    operand instead of erroring), so running the SAME unmodified command against a
    GNU host needs this one, narrow translation — the only difference between what
    runs here and what runs on the real guest.
    """

    def ssh(self, command: str, *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
        command = command.replace("stat -f %i", "stat -c %i")
        return subprocess.run(["/bin/sh", "-c", command], capture_output=True, text=True, timeout=timeout or 10)


@pytest.fixture
def vm() -> m.SmokeVM:
    return cast("m.SmokeVM", _ShellVM())


def _write(path: Path, text: str) -> None:
    path.write_text(text)


# --------------------------------------------------------------------------- #
# _log_window / _log_delta: rotation-safe log reading.
# --------------------------------------------------------------------------- #


def test_log_delta_reads_only_content_appended_after_the_baseline(vm: m.SmokeVM, tmp_path: Path) -> None:
    """Given a log with pre-existing content and a baseline taken after it
    When one more line is appended (no rotation)
    Then the delta contains ONLY the appended line, never the pre-existing content.
    """
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))

    with log.open("a") as stream:
        stream.write("fresh diagnostic\n")

    delta = m._log_delta(vm, str(log), baseline)

    assert "fresh diagnostic" in delta
    assert "baseline line" not in delta


def test_log_delta_recovers_the_pre_rotation_tail_from_a_plain_rename(vm: m.SmokeVM, tmp_path: Path) -> None:
    """Given newsyslog rotates the log by a plain rename (`path` -> `path.0`) between
        the baseline and the read, with a diagnostic written just before rotation
    When the fresh, empty, differently-inodesed `path` is read
    Then the delta still contains the diagnostic — recovered from `path.0` by
        matching ITS inode against the baseline's, not by assuming whichever `.0`
        exists belongs to this baseline.
    """
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))

    with log.open("a") as stream:
        stream.write("diagnostic before rotation\n")
    log.rename(str(log) + ".0")
    _write(log, "new generation\n")

    delta = m._log_delta(vm, str(log), baseline)

    assert "diagnostic before rotation" in delta


def test_log_delta_recovers_when_the_fresh_file_regrows_past_the_old_byte_offset(vm: m.SmokeVM, tmp_path: Path) -> None:
    """Given the SAME rename-rotation, but the fresh file then regrows PAST the
        baseline's old byte offset with unrelated content (the exact case a
        size-only heuristic missed: current size >= baseline offset looks like "no
        rotation happened")
    When the delta is read
    Then it still contains the pre-rotation diagnostic and does NOT report the
        unrelated post-rotation content as if it were the pre-rotation region.
    """
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))
    baseline_offset, _ = baseline

    with log.open("a") as stream:
        stream.write("diagnostic before rotation\n")
    log.rename(str(log) + ".0")
    # Regrow well past the OLD offset with content that shares no text with the
    # diagnostic — a size-only "did it shrink" check would see this as large enough
    # to be the same generation and never even look at `.0`.
    _write(log, "unrelated later noise\n" * 64)
    assert log.stat().st_size > baseline_offset

    delta = m._log_delta(vm, str(log), baseline)

    assert "diagnostic before rotation" in delta


def test_log_delta_recovers_from_a_bz2_compressed_backup(vm: m.SmokeVM, tmp_path: Path) -> None:
    """Given the rotated-away backup has since been compressed to `path.0.bz2`
        (newsyslog's own later compression pass)
    When the delta is read
    Then the pre-rotation diagnostic is still recovered, decompressed via `bzcat`.
    """
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))

    with log.open("a") as stream:
        stream.write("diagnostic before compression\n")
    backup = Path(str(log) + ".0")
    log.rename(backup)
    # Create the fresh live file BEFORE removing `backup`: a `path.0` freed by
    # `unlink()` immediately ahead of a fresh file's creation at `path` is a
    # coincidental-inode-reuse trap on some filesystems' allocators (observed on
    # this very suite while building it) — never realistic for newsyslog itself,
    # which always creates the new live file before a later, separate compression
    # pass. Keeping this same order here avoids that artifact.
    _write(log, "new generation\n")
    backup.with_suffix(backup.suffix + ".bz2").write_bytes(bz2.compress(backup.read_bytes()))
    backup.unlink()

    delta = m._log_delta(vm, str(log), baseline)

    assert "diagnostic before compression" in delta


def test_log_delta_recovers_from_a_gz_compressed_backup(vm: m.SmokeVM, tmp_path: Path) -> None:
    """Same as the bz2 case, for a `.gz`-compressed backup (`zcat`)."""
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))

    with log.open("a") as stream:
        stream.write("diagnostic before compression\n")
    backup = Path(str(log) + ".0")
    log.rename(backup)
    _write(log, "new generation\n")  # see the bz2 test above for why this precedes unlink()
    with gzip.open(str(backup) + ".gz", "wb") as gz:
        gz.write(backup.read_bytes())
    backup.unlink()

    delta = m._log_delta(vm, str(log), baseline)

    assert "diagnostic before compression" in delta


def test_log_delta_raises_when_the_rotation_boundary_cannot_be_recovered(vm: m.SmokeVM, tmp_path: Path) -> None:
    """Given TWO rotations happen before the delta is ever read: the baseline's
        generation is renamed to `.0`, then a SECOND rotation shifts it to `.1`
        (newsyslog's own renumbering) to make room for the next `.0` — so neither
        the live file nor `.0`/`.0.bz2`/`.0.gz` carries the baseline's inode
        anywhere anymore (only the now-unchecked `.1` does)
    When the delta is read
    Then this raises rather than silently returning a possibly-incomplete delta —
        a narrowed window here could make an absence assertion falsely pass.
    """
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))

    gen0 = Path(str(log) + ".0")
    log.rename(gen0)  # first rotation: .0 = baseline generation
    _write(log, "intermediate generation\n")
    gen1 = Path(str(log) + ".1")
    gen0.rename(gen1)  # second rotation: baseline generation renumbered to .1
    log.rename(gen0)  # intermediate generation takes over .0
    _write(log, "final generation\n")

    with pytest.raises(RuntimeError, match="log rotation boundary lost"):
        m._log_delta(vm, str(log), baseline)


def test_log_window_on_an_absent_file_then_created_returns_only_new_content(vm: m.SmokeVM, tmp_path: Path) -> None:
    """Given the baseline is taken while the log does not exist yet
    When the file is later created with content
    Then the delta is exactly that content (the "absent" baseline is its own,
        non-rotation case — never confused with an inode collision).
    """
    log = tmp_path / "system.log"
    baseline = m._log_window(vm, str(log))
    assert baseline == (0, "")

    _write(log, "first-ever content\n")

    delta = m._log_delta(vm, str(log), baseline)

    assert delta == "first-ever content\n"


# --------------------------------------------------------------------------- #
# _capture_stub_records / _restore_stub_records: scoped, non-destructive teardown.
# --------------------------------------------------------------------------- #


@pytest.fixture
def stub() -> Iterator[_StubDnsServer]:
    server = _StubDnsServer(port=0)
    try:
        yield server
    finally:
        server.stop()


def test_restore_stub_records_preserves_an_unrelated_names_override(stub: _StubDnsServer) -> None:
    """Given an unrelated name already has its own override before this fixture runs
    When a DIFFERENT name is snapshotted, mutated, and restored
    Then the unrelated name's override is untouched — the exact regression a
        blanket `clear_cname()` teardown caused (it erases every name, not just the
        one this fixture touched).
    """
    stub.set_records("unrelated-prior-owner.com", a=("192.0.2.71",))
    unrelated_before = dict(stub._records)

    snapshot = m._capture_stub_records(stub, ("touched.example",))
    stub.register_nxdomain("touched.example")
    m._restore_stub_records(stub, snapshot)

    assert dict(stub._records) == unrelated_before


def test_restore_stub_records_reverts_a_touched_name_to_its_prior_value(stub: _StubDnsServer) -> None:
    """Given a name already had its own A record before this fixture runs
    When it is snapshotted, overwritten with NXDOMAIN, and restored
    Then it reverts to EXACTLY its prior record, not to the sentinel default.
    """
    stub.set_records("touched.example", a=("198.51.100.5",))
    before = stub._records[stub._fqdn("touched.example")]

    snapshot = m._capture_stub_records(stub, ("touched.example",))
    stub.register_nxdomain("touched.example")
    m._restore_stub_records(stub, snapshot)

    assert stub._records[stub._fqdn("touched.example")] == before


def test_restore_stub_records_removes_a_name_that_had_no_prior_record(stub: _StubDnsServer) -> None:
    """Given a name has NO override at all before this fixture runs (the sentinel
        default answers it)
    When it is snapshotted (observing "no record"), overwritten with NXDOMAIN, and
        restored
    Then it goes back to having NO override — not left as a lingering NXDOMAIN.
    """
    fqdn = stub._fqdn("never-touched-before.example")
    assert fqdn not in stub._records

    snapshot = m._capture_stub_records(stub, ("never-touched-before.example",))
    stub.register_nxdomain("never-touched-before.example")
    m._restore_stub_records(stub, snapshot)

    assert fqdn not in stub._records
