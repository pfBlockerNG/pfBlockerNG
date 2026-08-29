"""``reload()`` must prove the feed pass STARTED, not merely that the CLI exited 0.

Issue #2591 (follow-up to PR #2589 / issue #2505): a lock deferral now exits 0 for the
unattended request shape ``pfb_trigger scope=... force=false trigger=cron`` — exactly what
``reload(vm, "update")`` dispatches — and ``pfblockerng_sync_cron()`` does the same for the
``cron`` verb. ``reload()`` raised only on ``rc != 0``, so a pass that lost the dispatcher or
feed-pass lock race returned silently, the readiness wait was trivially satisfied, and the
failure surfaced later as a misleading assertion far from its cause.

The pinned contract: after a clean exit, ``reload()`` requires a NEW pass-start banner in
``/var/log/pfblockerng/pfblockerng.log`` for every scope that must run a pass synchronously,
and fails at the reload call site naming the missing evidence when there is none.

Off-VM (no VM I/O; ``tests.smoke.helpers`` is import-safe — precedent:
``test_smoke_unbound_ready.py``). The fake guest emulates the helper's own ``grep -Fo``
count over an in-memory log, and each dispatch appends the VERBATIM line production writes
on that path, so a row passes only if the helper's marker literals match production's.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.smoke import helpers

_SRC = Path(__file__).resolve().parents[1] / "src" / "usr" / "local" / "pkg" / "pfblockerng"

# Verbatim lines production appends to pfblockerng.log, with the pfb_logger() ISO stamp
# in front (pfb_logger() inserts it after any leading newlines — pfblockerng.inc:4884).
_STAMP = "2026-08-20 16:51:19 "
# sync_package_pfblockerng(), master switch ON and not a save-only pass (apply.inc:925).
_STARTED_ENABLED = f"{_STAMP} UPDATE PROCESS START [ 3.2.5_1 ]\n"
# sync_package_pfblockerng(), master switch OFF or save-only pass (apply.inc:929) — the
# branch test_dns_redirect.py, test_dot_doq_block.py and test_smoke_tick.py reload through
# after h.set_package_enabled(vm, False).
_STARTED_SAVING = f"\n{_STAMP}**Saving configuration**\n"
# pfblockerng_sync_cron() (cron.inc:365), written before its tail call into sync_package.
_STARTED_CRON = f"{_STAMP} CRON  PROCESS  START [ 3.2.5_1 ]\n"
# The two deferral lines that replace a pass start, both now exiting 0 for the unattended
# shape: apply.inc:746 (dispatcher lock) and pfblockerng.inc:18784 (feed-pass lock).
_DEFERRED_DISPATCHER = f"\n{_STAMP} sync aborted: dispatcher lock unavailable; pending changes retained.\n"
_DEFERRED_FEED_PASS = f"\n{_STAMP}Feed pass [ sync ] skipped -- another pfBlockerNG feed pass is running.\n"
# pfb_reload_unbound()'s zero-downtime fast-path line, for the data_path=True row.
_SWAP_LINE = f"{_STAMP} DNSBL update [ zero-downtime swap ]\n"


@dataclass
class _FakeResult:
    """Stand-in for ``subprocess.CompletedProcess[str]`` (the shape ``SmokeVM.ssh`` returns)."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class _FakeVM:
    """Fake guest: emulates the helper's ``grep -Fo … | wc -l`` count over an in-memory log.

    ``appends`` is what the dispatched CLI writes to the log — the verbatim production line
    for the path under test — and ``rc`` is the exit code it reports. Anything the helper
    runs that is neither the count pipeline nor the CLI dispatch answers rc=0 (the readiness
    poll), so a row never depends on call ordering it does not pin.
    """

    log: str = ""
    appends: str = ""
    rc: int = 0
    dispatches: list[tuple[str, ...]] = field(default_factory=list)

    def ssh(self, *remote: str, timeout: float = 60.0) -> _FakeResult:
        if len(remote) == 1 and "grep -Fo" in remote[0]:
            return _FakeResult(returncode=0, stdout=f"{self._count(remote[0])}\n")
        if remote and remote[0] == helpers.PHP_BIN:
            self.dispatches.append(remote)
            self.log += self.appends
            return _FakeResult(returncode=self.rc, stdout="", stderr="")
        return _FakeResult(returncode=0)

    def _count(self, command: str) -> int:
        """Count marker OCCURRENCES exactly as ``grep -Fo <patterns> <path> | wc -l`` does.

        Handles both shapes the helper can build — a bare single pattern and repeated
        ``-e`` patterns — so a row pins the COUNT contract, not the flag spelling.
        """
        words = [w for w in shlex.split(command.split("|")[0]) if not w.startswith("2>")]
        if "-e" in words:
            patterns = [words[i + 1] for i, word in enumerate(words) if word == "-e"]
        else:
            patterns = words[2:-1]  # /usr/bin/grep -Fo <pattern>… <path>
        return sum(self.log.count(pattern) for pattern in patterns)


def _reload(vm: _FakeVM, scope: str = "update", **kwargs: object) -> None:
    helpers.reload(vm, scope, wait_unbound=False, **kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The defect: a deferred pass exits 0 and must fail HERE
# --------------------------------------------------------------------------- #


def test_feed_pass_lock_deferral_with_rc0_fails_at_the_reload_call_site() -> None:
    """Given the feed-pass lock is held, so the unattended pfb_trigger dispatch stands the
    pass down and exits 0 with only the deferral line logged,
    When reload(vm, "update") runs,
    Then it raises at the reload call site instead of returning silently (issue #2591).
    """
    vm = _FakeVM(appends=_DEFERRED_FEED_PASS, rc=0)

    with pytest.raises(RuntimeError, match="did not start"):
        _reload(vm)


def test_dispatcher_lock_deferral_with_rc0_fails_for_the_cron_verb() -> None:
    """Given the dispatcher lock is held, so the `cron` verb stands its pass down and exits 0
        (pfblockerng_sync_cron() returns !$force_all — the same benign-deferral rc=0 shape),
    When reload(vm, "cron") runs,
    Then it raises rather than returning as if the cron pass had run.
    """
    vm = _FakeVM(appends=_DEFERRED_DISPATCHER, rc=0)

    with pytest.raises(RuntimeError, match="did not start"):
        _reload(vm, "cron")


def test_a_stale_pass_start_banner_does_not_satisfy_the_assertion() -> None:
    """Given the log ALREADY carries a pass-start banner from an earlier reload,
    When a deferred pass exits 0 and appends nothing,
    Then reload still raises — the evidence must be a NEW banner, not a present one.
    """
    vm = _FakeVM(log=_STARTED_ENABLED, appends="", rc=0)

    with pytest.raises(RuntimeError, match="did not start"):
        _reload(vm)


def test_deferral_diagnostic_names_the_missing_start_evidence() -> None:
    """The failure must be diagnosable without reading the harness: it names the scope, the
    before/after counts (expected vs actual), and every banner it searched for."""
    vm = _FakeVM(log=_STARTED_ENABLED, appends=_DEFERRED_FEED_PASS, rc=0)

    with pytest.raises(RuntimeError) as excinfo:
        _reload(vm)

    message = str(excinfo.value)
    assert "update" in message
    assert helpers.PFB_LOG in message
    for marker in helpers.PASS_START_MARKERS:
        assert marker in message, f"diagnostic omits the {marker!r} banner it searched for: {message}"
    assert "before=1" in message and "after=1" in message, (
        f"diagnostic omits the before/after banner counts (expected vs actual): {message}"
    )


# --------------------------------------------------------------------------- #
# No false failures: every started pass, on every branch that writes a banner
# --------------------------------------------------------------------------- #


def test_started_pass_with_master_switch_on_is_accepted() -> None:
    """A pass that logs ` UPDATE PROCESS START [ … ]` returns normally."""
    vm = _FakeVM(appends=_STARTED_ENABLED, rc=0)

    _reload(vm)


def test_started_pass_with_master_switch_off_is_accepted() -> None:
    """Master OFF logs `**Saving configuration**` instead of the UPDATE banner (apply.inc:929).

    Three live call sites reload in exactly this state — test_dns_redirect.py:1109,
    test_dot_doq_block.py:1261 and test_smoke_tick.py:324 all reload right after
    h.set_package_enabled(vm, False) — so a marker set covering only the enabled branch would
    red them all.
    """
    vm = _FakeVM(appends=_STARTED_SAVING, rc=0)

    _reload(vm)


def test_started_cron_pass_is_accepted() -> None:
    """The cron funnel's own ` CRON  PROCESS  START [ … ]` banner counts as a pass start."""
    vm = _FakeVM(appends=_STARTED_CRON, rc=0)

    _reload(vm, "cron")


@pytest.mark.parametrize("scope", ["updateip", "updatednsbl"])
def test_started_force_scope_pass_is_accepted(scope: str) -> None:
    """The force scopes share sync_package_pfblockerng()'s banner — no false failure there."""
    vm = _FakeVM(appends=_STARTED_ENABLED, rc=0)

    _reload(vm, scope)


def test_idle_tick_is_exempt_from_the_pass_start_assertion() -> None:
    """An IDLE scheduled tick dispatches no pass at all — that is its documented behaviour
    (pfblockerng_tick() only execs a due job), so `tick` must NOT require a pass-start
    banner or every idle-tick caller reds."""
    vm = _FakeVM(appends="", rc=0)

    _reload(vm, "tick")


def test_data_path_reload_still_waits_on_the_swap_after_proving_the_pass_started() -> None:
    """data_path=True keeps its zero-downtime-swap wait; the pass-start check rides alongside
    it without disturbing the swap baseline."""
    vm = _FakeVM(appends=_STARTED_ENABLED + _SWAP_LINE, rc=0)

    helpers.reload(vm, "update", data_path=True, timeout=30.0)  # type: ignore[arg-type]


def test_nonzero_exit_still_reports_the_exit_code_failure() -> None:
    """An operator-initiated deferral still exits 1; that path keeps its own rc diagnostic
    and must not be masked by the new pass-start check."""
    vm = _FakeVM(appends=_DEFERRED_FEED_PASS, rc=1)

    with pytest.raises(RuntimeError, match=r"reload\('updateip'\) failed|reload\(updateip\) failed"):
        _reload(vm, "updateip")


# --------------------------------------------------------------------------- #
# Non-goals: the trigger shape and the marker literals must not drift
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ("update", ("scope=both", "force=false", "trigger=cron")),
        ("updateip", ("scope=ip", "force=true", "trigger=force")),
        ("updatednsbl", ("scope=dnsbl", "force=true", "trigger=force")),
    ],
)
def test_trigger_shape_is_unchanged(scope: str, expected: tuple[str, ...]) -> None:
    """Issue #2591 explicitly does NOT remap reload("update") to trigger=manual: doing so
    would flip the hooks' PFB_TRIGGER from `cron` to `update` and break the coverage
    test_smoke_hooks.py pins. The dispatched argv stays byte-identical."""
    vm = _FakeVM(appends=_STARTED_ENABLED, rc=0)

    _reload(vm, scope)

    assert len(vm.dispatches) == 1
    assert vm.dispatches[0] == (helpers.PHP_BIN, helpers.PFB_CLI, "pfb_trigger", *expected)


def test_every_pass_start_marker_still_exists_in_production() -> None:
    """Tripwire: each banner the helper counts must still be a literal production writes.

    A rename would otherwise make every reload fail on the live box only — this catches it
    in the hermetic suite, where it costs no VM.
    """
    sources = "".join(
        (_SRC / name).read_text(encoding="utf-8")
        for name in ("pfblockerng.inc", "pfblockerng_apply.inc", "pfblockerng_cron.inc")
    )
    for marker in helpers.PASS_START_MARKERS:
        assert marker in sources, f"pass-start banner {marker!r} no longer exists in the package sources"
