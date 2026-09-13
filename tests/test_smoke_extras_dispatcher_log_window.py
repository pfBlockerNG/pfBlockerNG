"""``_log_delta``/``_log_window`` and stub-record capture/restore must survive a real
newsyslog rotation and a shared ``stub_dns`` teardown without corrupting state.

An independent local (non-appliance) probe of ``test_extras_dispatcher_deferral``'s
prior helpers found five real, reproducible defects with no VM required -- the
module's fixture/helper logic is import-safe and its shell-driving methods accept
any object exposing ``.ssh()`` (precedent: ``test_smoke_unblock_egress``'s off-VM
coverage of a smoke-module helper):

1. A size-only rotation heuristic silently read the WRONG file region once a
   renamed-away backup's replacement regrew past the old byte offset.
2. An inode-based successor STILL false-greened after a SECOND rotation put a
   DIFFERENT generation's compressed backup at ``.0.bz2`` -- compression always
   creates a brand-new inode, so inode identity can never verify a compressed
   candidate at all, correctly or not.
3. A corrupt ``.0.bz2`` was silently accepted because its decompression failure
   was piped straight into ``tail``, whose OWN healthy exit status masked it.
4. ``stub_dns.clear_cname()`` as blanket teardown erased an UNRELATED name's
   override, not just this fixture's own.
5. The MaxMind locale CSV fixture-teardown had no restore path at all, and a
   later base64 capture/recreate fix still lost permissions and mtime.

This module pins (1)-(4) as permanent local regressions against the actual,
unchanged helpers (`_log_window`, `_log_delta`, `_capture_stub_records`,
`_restore_stub_records`) -- real file renames/compression/corruption, real shell
commands, the real `_StubDnsServer`. (5)'s CSV byte+metadata round-trip is exercised
by the fixture's own real appliance runs and a dedicated off-VM fixture-generator
replay (not a plain pytest module, since it drives `deployed_vm.__wrapped__()`
directly) and is not duplicated here.
"""

from __future__ import annotations

import base64
import bz2
import gzip
import shlex
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from tests.smoke import test_extras_dispatcher_deferral as m
from tests.smoke.conftest import _StubDnsServer


def _require_tool(name: str) -> None:
    """Fail this test's PRECONDITION -- never silently pass, never skip -- if
    `name` is missing from PATH.

    Without this, a missing decompressor makes `_log_delta` treat EVERY
    compressed candidate as unreadable and fall through to its own "boundary
    lost" RuntimeError -- the exact same outcome the corrupt-data and wrong-
    generation tests below assert on, but for an entirely different (and wrong)
    reason: environment misconfiguration, not the logic under test. Repo policy
    gates on a missing required tool rather than skipping past it, so this
    raises rather than `pytest.skip()`.
    """
    assert shutil.which(name) is not None, (
        f"{name!r} not found on PATH -- required for this test to exercise the real "
        f"decompression path it pins, not just its RuntimeError side effect"
    )


class _ShellVM:
    """Runs `.ssh()`'s shell commands for real, against a real local file -- the
    same shape ``SmokeVM.ssh`` presents (a single already-quoted command string,
    OR an argv shlex-joined the identical way `SmokeVM.ssh` itself does) minus
    the SSH transport."""

    def ssh(self, *remote: str, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
        command = remote[0] if len(remote) == 1 else shlex.join(remote)
        return subprocess.run(["/bin/sh", "-c", command], capture_output=True, text=True, timeout=timeout or 10)


@pytest.fixture
def vm() -> m.SmokeVM:
    return cast("m.SmokeVM", _ShellVM())


def _write(path: Path, text: str) -> None:
    path.write_text(text)


# --------------------------------------------------------------------------- #
# _log_window / _log_delta: content-marker rotation-safe log reading.
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
    When the fresh, empty `path` is read
    Then the delta still contains the diagnostic -- recovered from `path.0` by
        finding the baseline's own marker TEXT there, not by assuming whichever
        `.0` exists belongs to this baseline.
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


def test_log_delta_recovers_when_the_fresh_file_regrows_past_the_old_byte_offset(
    vm: m.SmokeVM,
    tmp_path: Path,
) -> None:
    """Given the SAME rename-rotation, but the fresh file then regrows to a size
        LARGER than the pre-rotation file ever was (the exact case a byte-offset
        heuristic missed: a numeric "did it shrink" check sees this as too big to
        be a fresh generation and never even looks at `.0`)
    When the delta is read
    Then it still contains the pre-rotation diagnostic and does NOT report the
        unrelated post-rotation content as if it were the pre-rotation region --
        content search has no offset to be fooled by size at all.
    """
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))
    pre_rotation_size = log.stat().st_size

    with log.open("a") as stream:
        stream.write("diagnostic before rotation\n")
    log.rename(str(log) + ".0")
    _write(log, "unrelated later noise\n" * 64)
    assert log.stat().st_size > pre_rotation_size

    delta = m._log_delta(vm, str(log), baseline)

    assert "diagnostic before rotation" in delta


def test_log_delta_recovers_from_a_bz2_compressed_backup(vm: m.SmokeVM, tmp_path: Path) -> None:
    """Given the rotated-away backup has since been compressed to `path.0.bz2`
        (newsyslog's own later compression pass) -- ONE rotation total
    When the delta is read
    Then the pre-rotation diagnostic is still recovered: the marker's TEXT survives
        `bzcat` decompression byte-for-byte, proving identity where an inode never
        could (compression always allocates a brand-new inode).
    """
    _require_tool("bzcat")
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))

    with log.open("a") as stream:
        stream.write("diagnostic before compression\n")
    backup = Path(str(log) + ".0")
    log.rename(backup)
    _write(log, "new generation\n")
    backup.with_suffix(backup.suffix + ".bz2").write_bytes(bz2.compress(backup.read_bytes()))
    backup.unlink()

    delta = m._log_delta(vm, str(log), baseline)

    assert "diagnostic before compression" in delta


def test_log_delta_recovers_from_a_gz_compressed_backup(vm: m.SmokeVM, tmp_path: Path) -> None:
    """Same as the bz2 case, for a `.gz`-compressed backup (`zcat`)."""
    _require_tool("zcat")
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))

    with log.open("a") as stream:
        stream.write("diagnostic before compression\n")
    backup = Path(str(log) + ".0")
    log.rename(backup)
    _write(log, "new generation\n")
    with gzip.open(str(backup) + ".gz", "wb") as gz:
        gz.write(backup.read_bytes())
    backup.unlink()

    delta = m._log_delta(vm, str(log), baseline)

    assert "diagnostic before compression" in delta


def test_log_delta_raises_after_a_second_rotation_compresses_a_different_generation(
    vm: m.SmokeVM,
    tmp_path: Path,
) -> None:
    """Given TWO rotations happen before the delta is ever read: the baseline's own
        generation is rotated to `.0`, a SECOND rotation then shifts THAT away to
        `.1.bz2` to make room, and an entirely different (intermediate) generation
        ends up compressed at `.0.bz2` instead -- the exact gate-found false-green:
        a `.0.bz2` exists, but it is NOT the baseline's generation, and inode
        identity cannot tell the difference (compression makes a new inode either
        way)
    When the delta is read
    Then this raises rather than silently returning the WRONG generation's content --
        the marker's own text is genuinely absent from the live file, `.0`, and the
        `.0.bz2` that does exist, and no candidate at `.1`/`.1.bz2` is ever
        consulted, so the boundary is correctly reported as lost, not guessed.
    """
    _require_tool("bzcat")
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))

    with log.open("a") as stream:
        stream.write("diagnostic before rotation\n")
    gen0 = Path(str(log) + ".0")
    log.rename(gen0)  # first rotation: .0 = baseline generation
    _write(log, "intermediate generation\n")
    gen1 = Path(str(log) + ".1")
    gen0.rename(gen1)
    Path(str(gen1) + ".bz2").write_bytes(bz2.compress(gen1.read_bytes()))
    gen1.unlink()  # baseline generation is now ONLY at .1.bz2 -- never consulted
    log.rename(gen0)  # intermediate generation takes over .0
    Path(str(gen0) + ".bz2").write_bytes(bz2.compress(gen0.read_bytes()))
    gen0.unlink()
    _write(log, "final generation\n")

    with pytest.raises(RuntimeError, match="log rotation boundary lost"):
        m._log_delta(vm, str(log), baseline)


def test_log_delta_raises_rather_than_silently_accept_a_corrupt_compressed_backup(
    vm: m.SmokeVM,
    tmp_path: Path,
) -> None:
    """Given the only reachable backup, `path.0.bz2`, is not valid bzip2 data at all
        (a truncated/corrupted rotation artifact)
    When the delta is read
    Then this raises -- `bzcat`'s own nonzero exit code is checked explicitly and
        SEPARATELY from the marker search, so a decompression failure can never be
        silently treated as "marker not present, keep going" and, worse, never
        masked by piping straight into a downstream reader whose OWN exit status
        would report success regardless.
    """
    _require_tool("bzcat")
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))

    with log.open("a") as stream:
        stream.write("diagnostic before corruption\n")
    backup = Path(str(log) + ".0")
    log.rename(backup)
    Path(str(backup) + ".bz2").write_bytes(b"not a bzip2 stream")
    backup.unlink()
    _write(log, "new generation\n")

    with pytest.raises(RuntimeError, match="log rotation boundary lost"):
        m._log_delta(vm, str(log), baseline)


def test_log_window_on_an_absent_file_creates_it_with_only_the_marker(vm: m.SmokeVM, tmp_path: Path) -> None:
    """Given the baseline is taken while the log does not exist yet
    When the file is later appended to
    Then the delta is exactly the appended content (the marker write itself
        created the file, so there is no separate "absent baseline" case to get
        wrong).
    """
    log = tmp_path / "system.log"
    baseline = m._log_window(vm, str(log))
    assert log.exists()

    with log.open("a") as stream:
        stream.write("first-ever content\n")

    delta = m._log_delta(vm, str(log), baseline)

    assert delta == "first-ever content\n"


def test_log_delta_raises_rather_than_silently_mask_a_failed_read_of_an_existing_backup(
    vm: m.SmokeVM,
    tmp_path: Path,
) -> None:
    """Given `path.0` exists (passes `test -f`) but reading it via `cat` genuinely
        fails (simulated here by intercepting the exact `cat path.0` command --
        a real permission-denied read is not portably reproducible as root)
    When the delta is read
    Then this raises loudly rather than treating the failed read as an empty or
        absent backup: a masked `[ -f ... ] && cat ... || true` shape would
        instead silently proceed with whatever partial output `cat` produced
        before failing, potentially still finding the marker in a truncated read.
    """
    log = tmp_path / "system.log"
    _write(log, "baseline line\n" * 8)
    baseline = m._log_window(vm, str(log))
    log.rename(str(log) + ".0")
    _write(log, "new generation\n")

    class FailingCatVM(_ShellVM):
        def ssh(self, *remote: str, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
            if remote == (f"cat {log}.0",):
                return subprocess.CompletedProcess(remote, 1, "", "cat: Permission denied")
            return super().ssh(*remote, timeout=timeout)

    with pytest.raises(AssertionError, match="rotated-backup read failed"):
        m._log_delta(cast("m.SmokeVM", FailingCatVM()), str(log), baseline)


def test_guest_file_exists_raises_on_an_ssh_transport_error_rather_than_report_absence() -> None:
    """Given the guest probe returns 255 (an SSH transport failure -- neither
        `test`'s own 0 NOR its own 1)
    When `_guest_file_exists` checks it
    Then this raises rather than reporting "absent" -- cleanup trusting a false
        "absent" here could remove marker files and declare a dispatcher-lock
        holder released while the real flock-holding process is still live and
        simply unreachable right now.
    """

    class TransportFailureVM(_ShellVM):
        def ssh(self, *remote: str, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(remote, 255, "", "ssh: connect to host: Connection refused")

    with pytest.raises(RuntimeError, match="likely an SSH transport failure"):
        m._guest_file_exists(cast("m.SmokeVM", TransportFailureVM()), "/tmp/whatever")


def test_pid_alive_raises_on_an_ssh_transport_error_rather_than_report_death() -> None:
    """Same failure mode as the file-exists probe, for the PID-liveness probe
    `_LockHolder.stop()` uses to decide whether the owned process has exited."""

    class TransportFailureVM(_ShellVM):
        def ssh(self, *remote: str, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(remote, 255, "", "ssh: connect to host: Connection refused")

    with pytest.raises(RuntimeError, match="likely an SSH transport failure"):
        m._pid_alive(cast("m.SmokeVM", TransportFailureVM()), "12345")


# --------------------------------------------------------------------------- #
# _restore_section: a corrupt capture blob must never silently wipe config.
# --------------------------------------------------------------------------- #


def _php_eval_local(vm: object, snippet: str, **_kwargs: object) -> subprocess.CompletedProcess[str]:
    """Runs `_restore_section`'s PHP snippet for REAL via a local `php` CLI,
    stubbing only the two pfSense-specific globals it calls (`config_set_path`,
    `write_config`) as no-ops -- `json_decode`/`base64_decode`/`is_array` are
    REAL PHP, so the validation branch is exercised genuinely, never
    re-implemented in Python."""
    stub_prelude = (
        "function config_set_path($path, $value) { echo 'CONFIG_SET_PATH:' . json_encode($value) . \"\\n\"; }\n"
        "function write_config($msg) { echo 'WRITE_CONFIG' . \"\\n\"; }\n"
    )
    result = subprocess.run(
        ["php", "-r", stub_prelude + snippet], capture_output=True, text=True, timeout=10, check=False
    )
    return subprocess.CompletedProcess(result.args, result.returncode, result.stdout, result.stderr)


def test_restore_section_refuses_a_corrupt_blob_rather_than_wipe_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given a corrupt/truncated base64 blob (`json_decode()` would return `NULL`)
    When `_restore_section` is called
    Then it raises rather than silently writing an empty array over the whole
    live config section -- exercised through the REAL PHP validation snippet
    (`is_array()` on the actually-decoded value), not a Python re-implementation.
    """
    monkeypatch.setattr(m.h, "php_eval", _php_eval_local)

    with pytest.raises(AssertionError, match="restore of config section"):
        m._restore_section(cast("m.SmokeVM", _ShellVM()), "system", "not-valid-base64-or-json!!!")


def test_restore_section_accepts_a_genuinely_empty_array_blob(monkeypatch: pytest.MonkeyPatch) -> None:
    """A genuinely empty array (`json_encode([])` -> `"[]"`, a real, valid capture
    of a section that really was empty) must NOT be confused with a decode
    failure -- `is_array([])` is true, so this must NOT raise."""
    monkeypatch.setattr(m.h, "php_eval", _php_eval_local)
    blob = base64.b64encode(b"[]").decode()

    m._restore_section(cast("m.SmokeVM", _ShellVM()), "system", blob)  # must not raise


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
    Then the unrelated name's override is untouched -- the exact regression a
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
    Then it goes back to having NO override -- not left as a lingering NXDOMAIN.
    """
    fqdn = stub._fqdn("never-touched-before.example")
    assert fqdn not in stub._records

    snapshot = m._capture_stub_records(stub, ("never-touched-before.example",))
    stub.register_nxdomain("never-touched-before.example")
    m._restore_stub_records(stub, snapshot)

    assert fqdn not in stub._records
