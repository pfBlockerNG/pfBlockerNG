"""Prove the Tier-A oracle: a bare HTTP 200 can NEVER pass (ADR-14 Phase 2).

ADR §1 fact 3 / §2 contract: the render oracle must reject a 200 that carries a
PHP ``Warning``/``Notice``/``Fatal``, a blank/wrong body, or the login form.
This is the deliberately-broken-page proof, done as PURE LOGIC against
:func:`~tests.smoke.ui.render_oracle.evaluate_render` -- no VM, so it actually
executes (it needs no ``smoke_vm``).

Oracle condition (d) -- the sweep-level ``php_error.log`` check -- is proved here
too (issue #1218): with the guest raised to a true ``E_ALL`` the log carries
pfSense-core diagnostics that are none of our business, so the guard gates on the
*originating file*, not on the file growing. Those cases drive
:class:`~tests.smoke.ui.render_oracle.PhpErrorLogGuard` over a fake guest
filesystem, so they run off-box like the rest of this module.

It lives under ``tests/smoke/ui/`` so it is excluded from the default
``python -m pytest`` collection (``--ignore=tests/smoke`` keeps that run
byte-identical at 1019), and runs under the smoke/ui override
(``pytest tests/smoke/ui --override-ini="addopts="``) WITHOUT needing the live
VM. It carries the ``ui_render`` marker for consistency with the sweep, but
unlike the sweep it requests no VM fixture, so ``-m ui_render`` collects it and
it passes off-box.

Branch coverage (CLAUDE.md): for every oracle condition (a)-(c) the test asserts
BOTH a GOOD body that PASSES and a BAD variant that the oracle REJECTS -- so a
green proves the condition is a real, load-bearing branch, not an always-pass.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from . import render_oracle
from .render_oracle import (
    PFB_PATH_MARKER,
    PHP_ERROR_LEVELS,
    PhpErrorLogGuard,
    body_has_php_error,
    diagnostic_fingerprint,
    endemic_diagnostics,
    evaluate_render,
    gating_log_lines,
    load_baseline,
    observed_baseline_entries,
    stale_baseline_entries,
)

if TYPE_CHECKING:
    from ..conftest import SmokeVM

pytestmark = pytest.mark.ui_render


@pytest.fixture(autouse=True)
def _isolate_live_observation_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep this module's fixtures out of the LIVE sweep's reporting state.

    These tests carry ``ui_render``, so they run in the same pytest session as the live
    sweep, and ``pytest_sessionfinish`` reports on module-level sets shared with it. A
    fixture fingerprint leaking in would mark a real site "still emitting" and hide it from
    the removal report for good. ``record=True`` is restricted to the guard for the same
    reason; this is the belt to that suspenders, per testing.md's "reset per-test state
    explicitly" rule -- and it fails loudly rather than silently if the swap ever stops
    taking.
    """
    monkeypatch.setattr(render_oracle, "_observed_baseline", set())
    monkeypatch.setattr(render_oracle, "_endemic_seen", set())
    assert render_oracle.observed_baseline_entries() == frozenset(), "observation state did not reset"
    assert render_oracle.endemic_diagnostics() == frozenset(), "endemic state did not reset"


# A minimal "healthy" page body: HTTP-200-shaped, carries the page marker, is NOT
# the login form, and has no PHP diagnostic. This is the body the oracle MUST pass.
GOOD_MARKER = "General Settings"
GOOD_BODY = f"<html><head><title>pfBlockerNG</title></head><body><h2>{GOOD_MARKER}</h2></body></html>"
# The login form (logged-out) shape -- one of webui.LOGIN_MARKERS must be present.
LOGIN_BODY = (
    '<form class="login"><p class="form-title">Sign In</p><input id="usernamefld"><input id="passwordfld"></form>'
)


def test_good_body_passes() -> None:
    """The healthy body passes all of (a)-(c) -- the before-state for every reject case."""
    result = evaluate_render("/p", 200, GOOD_BODY, (GOOD_MARKER,))
    assert result.ok, f"healthy body unexpectedly failed: {result.detail}"
    assert result.reasons == ()


@pytest.mark.parametrize("level", PHP_ERROR_LEVELS)
def test_php_diagnostic_in_body_is_rejected(level: str) -> None:
    """(b): a body carrying any PHP diagnostic LEVEL (in shape) fails, though 200 + marker.

    The SAME marker-bearing 200 body passes without the diagnostic (asserted here
    as the before-state) and fails once a real ``PHP <Level>: ... on line N`` line
    is injected -- so the rejection is caused by the diagnostic, not anything else.
    """
    # Before: identical body minus the diagnostic passes.
    assert evaluate_render("/p", 200, GOOD_BODY, (GOOD_MARKER,)).ok
    # After: inject a realistic PHP diagnostic line into the otherwise-good body.
    broken = GOOD_BODY.replace("<body>", f"<body>PHP {level}: oops in pfblockerng.inc on line 1<br />")
    result = evaluate_render("/p", 200, broken, (GOOD_MARKER,))
    assert not result.ok, f"oracle passed a body containing a PHP {level!r} diagnostic"
    assert body_has_php_error(broken) is not None
    assert any(level in r for r in result.reasons)


@pytest.mark.parametrize(
    "shape",
    [
        "<br />\n<b>Notice</b>:  Undefined variable $x in <b>/usr/local/www/x.php</b> on line <b>42</b><br />",
        "Warning: Invalid argument supplied for foreach() in /usr/local/www/x.php on line 99",
        "Fatal error: Uncaught TypeError: bad in /x.php:7",
        "Stack trace:\n#0 /usr/local/www/x.php(7): foo()",
    ],
    ids=["html-bold", "plain-on-line", "uncaught", "stack-trace"],
)
def test_real_diagnostic_shapes_are_rejected(shape: str) -> None:
    """(b): each real rendered-diagnostic SHAPE (HTML wrap, plain on-line, uncaught, trace) fails."""
    assert evaluate_render("/p", 200, GOOD_BODY, (GOOD_MARKER,)).ok  # before: clean body passes
    broken = GOOD_BODY.replace("<body>", f"<body>{shape}")
    result = evaluate_render("/p", 200, broken, (GOOD_MARKER,))
    assert not result.ok, f"oracle passed a real diagnostic shape: {shape!r}"
    assert any("PHP diagnostic" in r for r in result.reasons)


@pytest.mark.parametrize(
    "copy",
    [
        # Real legit copy from pfblockerng_ip.php -- level words in prose, NOT diagnostics.
        "A pfSense Notice message will be submitted on completion.",
        "Upon completion, a pfSense Notice will be generated.",
        "Warning: When using an Action setting of 'Permit Inbound or Permit Both', ...",
        "Warning: With DoH/DoT Blocking enabled, you must select at least one List",
    ],
)
def test_level_words_in_legit_copy_are_not_rejected(copy: str) -> None:
    """(b) false-positive guard: a level WORD in page copy (no diagnostic shape) PASSES.

    This is the bug the shape-based oracle fixes: a bare-substring match flagged
    "a pfSense Notice message" / the "Warning: ..." input-error strings as PHP
    diagnostics. None of these carry the diagnostic shape, so the oracle must NOT
    reject them.
    """
    body = GOOD_BODY.replace("<body>", f"<body><p>{copy}</p>")
    assert body_has_php_error(body) is None, f"legit copy wrongly flagged as a PHP diagnostic: {copy!r}"
    assert evaluate_render("/p", 200, body, (GOOD_MARKER,)).ok, f"oracle wrongly rejected legit copy: {copy!r}"


# The chrome pfSense renders into EVERY page while a system notice is pending --
# captured from issue #1856's failing leg (release run 30424647767): the notice
# bell, the Notices modal, and the pending notice's own text. No PHP diagnostic
# anywhere in it.
NOTICES_CHROME = (
    '<i class="fa-solid fa-bell text-danger" title="Notices"></i>'
    '<h3 class="modal-title" id="myModalLabel">Notices</h3>'
    "<h4>warning</h4><ul><li><b></b>"
    "Boot verification failed for default. Netgate pfSense Plus was automatically "
    "rebooted back into default_20260729033017.<i>@ 2026-07-29 05:20:16</i></li></ul>"
)


def test_pending_system_notices_chrome_is_not_rejected() -> None:
    """(b) false-positive guard (#1856): the pending-notices chrome PASSES.

    A box with a pending pfSense system notice renders 'Notices' (bell title +
    modal heading) plus the notice text into every page. A bare-substring
    'Notice' assert trips on that chrome (how #1856 failed, with zero PHP
    diagnostics on the page); the shape oracle must accept it -- and must still
    reject a real diagnostic rendered alongside the same chrome.
    """
    # Premise pin: the chrome really carries the bare level word that tripped the
    # old substring assert -- an edit dropping it would leave this test vacuous.
    assert "Notice" in NOTICES_CHROME
    chrome_body = GOOD_BODY.replace("<body>", f"<body>{NOTICES_CHROME}")
    assert body_has_php_error(chrome_body) is None, "pending-notices chrome wrongly flagged as a PHP diagnostic"
    assert evaluate_render("/p", 200, chrome_body, (GOOD_MARKER,)).ok

    # Branch coverage: the chrome must not MASK a real diagnostic either.
    broken = chrome_body.replace(
        "<body>", "<body>Notice: Undefined variable $x in /usr/local/www/pfblockerng/x.php on line 3<br />"
    )
    result = evaluate_render("/p", 200, broken, (GOOD_MARKER,))
    assert not result.ok, "a real diagnostic next to the Notices chrome must still be rejected"
    assert any("PHP diagnostic" in r for r in result.reasons)


def test_non_200_is_rejected() -> None:
    """(a): a 500 fails even with a clean, marker-bearing body (200-vs-not is a real branch)."""
    assert evaluate_render("/p", 200, GOOD_BODY, (GOOD_MARKER,)).ok  # before: 200 passes
    result = evaluate_render("/p", 500, GOOD_BODY, (GOOD_MARKER,))
    assert not result.ok, "oracle passed a non-200 response"
    assert any("status 500" in r for r in result.reasons)


def test_missing_marker_is_rejected() -> None:
    """(c): a blank/redirected 200 with no page marker fails (a bare 200 is never a pass)."""
    assert evaluate_render("/p", 200, GOOD_BODY, (GOOD_MARKER,)).ok  # before: marker present passes
    # A 200 whose body is the WRONG page (e.g. the dashboard) -- marker absent.
    wrong = "<html><body><h2>Dashboard</h2></body></html>"
    result = evaluate_render("/p", 200, wrong, (GOOD_MARKER,))
    assert not result.ok, "oracle passed a 200 with no page marker"
    assert any("no page marker" in r for r in result.reasons)


def test_login_form_body_is_rejected() -> None:
    """(c): a logged-out 200 (login form rendered in place) fails -- it is not the page.

    pfSense renders the login form at HTTP 200 (no 302) for an unauthenticated
    protected GET; the oracle must treat that as a failure, never a pass.
    """
    assert evaluate_render("/p", 200, GOOD_BODY, (GOOD_MARKER,)).ok  # before: real page passes
    result = evaluate_render("/p", 200, LOGIN_BODY, (GOOD_MARKER,))
    assert not result.ok, "oracle passed the login form as a rendered page"
    assert any("login form" in r for r in result.reasons)


def test_multiple_failures_are_all_reported() -> None:
    """All failing conditions are surfaced together (specific diagnostics, not just the first)."""
    # 404 + a Warning in the body + no marker -> all three reasons.
    body = "<html><body>PHP Warning: bad in x on line 1</body></html>"
    result = evaluate_render("/p", 404, body, ("AbsentMarker",))
    assert not result.ok
    # All THREE conditions fail, so all three must surface -- a >= 2 check would
    # let the missing-marker reason silently drop.
    assert len(result.reasons) >= 3
    assert any("404" in r for r in result.reasons)
    assert any("Warning" in r for r in result.reasons)
    assert any("no page marker" in r for r in result.reasons)


# --------------------------------------------------------------------------- #
# (d) the sweep-level php_error.log guard -- OUR diagnostics gate, core noise
#     does not (issue #1218: the guest now runs a true E_ALL)
# --------------------------------------------------------------------------- #

_LOG = "/tmp/PHP_errors.log"
_SEEDED = "[25-Jul-2026 09:59:00 UTC] PHP Warning:  pre-existing in /etc/inc/config.inc on line 1\n"

# Real error_log line shapes, one per class the guard must tell apart.
# NOT an "Undefined array key": that class is exempt by MESSAGE regardless of file, so a
# core fixture using it would pass even with file scoping deleted -- the branch would be
# untested (proved by mutation: PFB_PATH_MARKER = "" left the whole suite green).
CORE_WARNING = (
    "[25-Jul-2026 10:00:00 UTC] PHP Warning:  Invalid argument supplied for foreach() in "
    "/etc/inc/pfsense-utils.inc on line 4211\n"
)
# The same core file emitting the ENDEMIC class -- exempt for a second, independent reason.
CORE_ENDEMIC_WARNING = (
    '[25-Jul-2026 10:00:00 UTC] PHP Warning:  Undefined array key "descr" in /etc/inc/pfsense-utils.inc on line 4211\n'
)
PFB_PAGE_WARNING = (
    "[25-Jul-2026 10:00:01 UTC] PHP Warning:  Undefined array key 0 in "
    "/usr/local/www/pfblockerng/pfblockerng_feeds.php on line 377\n"
)
PFB_INC_DEPRECATED = (
    "[25-Jul-2026 10:00:02 UTC] PHP Deprecated:  Optional parameter $x declared before required $y in "
    "/usr/local/pkg/pfblockerng/pfblockerng.inc on line 90\n"
)
# The classes that still SMELL like a defect once the endemic one is set aside: an
# undefined variable, and a null reaching a string parameter (a PHP 8.1 deprecation that
# becomes a TypeError in PHP 9 -- a forward-compat signal, not cosmetics).
# Both name a page that does not exist, so these cases assert the CLASS is gated and can
# never be quietly satisfied (or defeated) by whatever the shipped baseline happens to
# grandfather -- the baseline's own behaviour has its own cases below.
_NEW_PAGE = "/usr/local/www/pfblockerng/pfblockerng_brand_new.php"
PFB_PAGE_UNDEF_VAR = (
    f"[25-Jul-2026 10:00:05 UTC] PHP Warning:  Undefined variable $colspan in {_NEW_PAGE} on line 100\n"
)
PFB_PAGE_NULL_ARG = (
    "[25-Jul-2026 10:00:06 UTC] PHP Deprecated:  explode(): Passing null to parameter #2 ($string) of type "
    f"string is deprecated in {_NEW_PAGE} on line 44\n"
)
CORE_FATAL = (
    "[25-Jul-2026 10:00:03 UTC] PHP Fatal error:  Uncaught TypeError: bad in /etc/inc/config.lib.inc on line 9\n"
)
FPM_POOL_CHATTER = "[25-Jul-2026 10:00:04] NOTICE: [pool nginx] child 41027 started\n"


class _FakeSSHResult:
    """The ``subprocess``-shaped result :class:`PhpErrorLogGuard` reads."""

    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


class _FakeVM:
    """A guest filesystem (``{path: text}``) answering the guard's two ssh calls.

    The guard shells out only for ``stat -f %z <path>`` (byte size, rc 1 when the
    file is absent) and ``tail -c <n> <path>`` (the bytes appended since the
    snapshot), so a dict of file bodies is a faithful stand-in -- and keeps this
    proof off-box, where it can run on every push instead of only on a leased VM.
    """

    def __init__(self, files: dict[str, str]) -> None:
        self.files = files

    def ssh(self, *argv: str, timeout: float = 30.0) -> _FakeSSHResult:  # noqa: ARG002 - signature parity
        path = argv[-1]
        body = self.files.get(path)
        if argv[0] == "/usr/bin/stat":
            return _FakeSSHResult(0, str(len(body.encode()))) if body is not None else _FakeSSHResult(1, "")
        if argv[0] == "/usr/bin/tail":
            assert body is not None, f"tail on an absent guest file: {path}"
            return _FakeSSHResult(0, body.encode()[-int(argv[2]) :].decode())
        if argv[0].startswith("grep -F"):
            # The post-mortem dump the guard prints alongside a failure: a deduped view of
            # the same file. Answer it so the fake stays a faithful guest, but keep every
            # assertion on the VERDICT -- this output is diagnostics, never the oracle.
            # The probe is one shell string; the log path is its 4th word (`grep -F <marker>
            # <path> | ...`). Splitting from the END lands on a word of the sed script.
            body = self.files.get(argv[0].split()[3], "")
            matched = sorted({line for line in body.splitlines() if PFB_PATH_MARKER in line})
            return _FakeSSHResult(0, "\n".join(matched))
        raise AssertionError(f"unexpected guest command: {argv!r}")


def _guard_after_appending(appended: str) -> PhpErrorLogGuard:
    """A guard snapshotted over a seeded log, then ``appended`` written to it."""
    vm = _FakeVM({_LOG: _SEEDED})
    guard = PhpErrorLogGuard(cast("SmokeVM", vm), candidates=(_LOG,))
    guard.snapshot()
    vm.files[_LOG] = _SEEDED + appended
    return guard


def test_pfblockerng_undefined_variable_gates_the_sweep() -> None:
    """(d) on-branch: an ``Undefined variable`` from one of OUR pages fails the sweep.

    This is a class the Tier-A mandate names and #1211 could not obtain a red for (the
    harness masked ``E_WARNING`` before it reached the log). With the guest at ``E_ALL``
    the line lands in the log and the guard must fail on it, naming the offending line so
    the failure is actionable without opening the artifact.
    """
    with pytest.raises(AssertionError, match="Undefined variable"):
        _guard_after_appending(PFB_PAGE_UNDEF_VAR).assert_no_growth()


def test_pfblockerng_null_to_string_parameter_gates_the_sweep() -> None:
    """(d) on-branch: a null reaching a string parameter fails the sweep.

    Deprecated in PHP 8.1 and a TypeError in PHP 9, so this one is a forward-compat
    break in waiting, not a cosmetic notice -- exactly what a live gate should catch
    while there is still time to fix it.
    """
    with pytest.raises(AssertionError, match="Passing null"):
        _guard_after_appending(PFB_PAGE_NULL_ARG).assert_no_growth()


def test_pfblockerng_undefined_array_key_does_not_gate_the_sweep() -> None:
    """(d) the endemic class is REPORTED, not gated (#1712 owns burning it down).

    ``Undefined array key`` on an unset config read is emitted at 469 distinct sites in
    this package: freezing every one of them would buy a gate whose next new instance is
    indistinguishable from the ones already forgiven, at the cost of a list edited by every
    burn-down PR. So the class is observed and counted, and the gate spends its
    credibility on the classes that still smell like defects.

    It is NOT invisible: :func:`endemic_diagnostics` collects it for the end-of-sweep
    report, which is what keeps the burn-down honest.
    """
    _guard_after_appending(PFB_PAGE_WARNING).assert_no_growth()


def test_the_endemic_class_is_still_observed_and_reported() -> None:
    """Not gating is not the same as not seeing: the fingerprint is recorded.

    A silent skip would leave #1712 with no measurement of what is left to fix. Recorded
    through the guard, like a real sweep -- a direct call deliberately records nothing.
    """
    _guard_after_appending(PFB_PAGE_WARNING).assert_no_growth()
    assert any("pfblockerng_feeds.php" in entry for entry in endemic_diagnostics())


def test_pfblockerng_deprecated_from_the_package_dir_gates_the_sweep() -> None:
    """(d) on-branch, second owned root: ``/usr/local/pkg/pfblockerng/`` counts as ours too.

    Our code ships to two trees (the package dir and the ``www`` pages/widgets); a
    filter that only recognised one of them would silently ignore half the package.
    """
    with pytest.raises(AssertionError, match="pfblockerng.inc"):
        _guard_after_appending(PFB_INC_DEPRECATED).assert_no_growth()


def test_core_warning_does_not_gate_the_sweep() -> None:
    """(d) off-branch: a pfSense-CORE ``E_WARNING`` is noise the sweep must ignore.

    Raising the guest to ``E_ALL`` makes every core ``Undefined array key`` visible in
    the same log. Those are not our regressions and gating on them would redden every
    PR on unrelated upstream code -- the reason the harness masked the whole class
    before. The guard scopes by ORIGINATING file instead, so core noise passes.
    """
    _guard_after_appending(CORE_WARNING).assert_no_growth()


def test_core_endemic_warning_does_not_gate_either() -> None:
    """(d) the endemic class from a core file is exempt twice over -- file AND class.

    Paired with the case above, this separates the two reasons: that one is core-owned but
    a GATED class, so only file scoping can excuse it; this one would be excused by either
    rule alone. Without the pair, deleting the ownership check entirely left the suite
    green (proved by mutation) because every core fixture was endemic-class.
    """
    _guard_after_appending(CORE_ENDEMIC_WARNING).assert_no_growth()


def test_a_message_embedding_a_path_cannot_hijack_attribution() -> None:
    """Origin is the LAST ``in <file> on line N`` -- PHP appends the real one at the end.

    A message that itself quotes ``in <path> on line <N>`` (an include error, say) would
    otherwise be attributed to the path in its own text: a core-raised diagnostic could
    gate as ours, and an OUR-raised one could escape as core. The latter is the dangerous
    direction, so it is asserted here.
    """
    ours_but_message_names_core = (
        "[25-Jul-2026 10:00:00 UTC] PHP Warning:  failed to open in /etc/inc/config.inc on line 9 in "
        "/usr/local/www/pfblockerng/pfblockerng_alerts.php on line 77\n"
    )
    assert gating_log_lines(ours_but_message_names_core), "our diagnostic escaped by quoting a core path"


def test_a_failure_prints_the_whole_deduped_diagnostic_set(capsys: pytest.CaptureFixture[str]) -> None:
    """A gating failure dumps every pfBlockerNG diagnostic in the log, deduped.

    The assertion message quotes only the sweep's own appended lines, capped. This dump is
    the whole picture, printed at the one moment it exists: a module-scoped guard fails in
    TEARDOWN, which ``conftest._failure_report`` does not cover, and the guest is destroyed
    at the end of the run — so without it the full set costs another 4-minute sweep to
    recover. Asserting on the printed text is what keeps the guest-probe wiring honest;
    hand-tracing it once is not coverage.
    """
    with pytest.raises(AssertionError):
        _guard_after_appending(PFB_PAGE_UNDEF_VAR + PFB_PAGE_WARNING).assert_no_growth()
    dumped = capsys.readouterr().out
    assert "pfBlockerNG diagnostics in /tmp/PHP_errors.log" in dumped, f"no dump printed: {dumped!r}"
    assert "pfblockerng_brand_new.php" in dumped, "the gating line is missing from the dump"
    assert "pfblockerng_feeds.php" in dumped, "the endemic line is missing from the dump"


def test_a_rotated_log_does_not_disarm_the_guard() -> None:
    """A log rotated or truncated mid-sweep must not swallow the diagnostics after it.

    ``newsyslog`` can rotate a candidate between the snapshot and the check. Treating a
    SHRUNK file as "nothing appended" would skip every diagnostic written after the
    rotation -- silently, for the rest of a module-scoped sweep, since the baseline offset
    is never refreshed. The offset is meaningless once the file shrank, so the whole file
    is classified instead.
    """
    vm = _FakeVM({_LOG: "x" * 500 + "\n"})
    guard = PhpErrorLogGuard(cast("SmokeVM", vm), candidates=(_LOG,))
    guard.snapshot()
    vm.files[_LOG] = PFB_PAGE_UNDEF_VAR  # rotated: smaller, and carrying OUR diagnostic
    with pytest.raises(AssertionError, match="Undefined variable"):
        guard.assert_no_growth()


def test_core_fatal_still_gates_the_sweep() -> None:
    """(d): the file filter applies to the maskable classes ONLY -- a fatal always fails.

    ``E_ERROR``/``E_PARSE``-class diagnostics were never masked and are catastrophic
    wherever they are raised (a core fatal reached through our page is still a broken
    page), so scoping by file must never quiet them.
    """
    with pytest.raises(AssertionError, match="Fatal error"):
        _guard_after_appending(CORE_FATAL).assert_no_growth()


def test_non_diagnostic_log_growth_does_not_gate_the_sweep() -> None:
    """(d): a line that is not a PHP diagnostic at all (fpm pool chatter) does not fail.

    php-fpm writes its own lifecycle lines into the same watched candidates. The guard
    reads DIAGNOSTICS, not bytes, so a worker respawn during a sweep cannot redden a
    run that emitted no PHP error.
    """
    _guard_after_appending(FPM_POOL_CHATTER).assert_no_growth()


# --------------------------------------------------------------------------- #
# The burn-down baseline: pre-existing our-file diagnostics are grandfathered by
# FINGERPRINT (file + level + message, never a line number), so the gate is live
# on every file for NEW diagnostics while the known backlog burns down (#1712).
# --------------------------------------------------------------------------- #


def test_a_baselined_diagnostic_does_not_gate() -> None:
    """A grandfathered site stays green -- otherwise the whole suite is red on day one.

    The before-state is the case above: this exact line gates with an empty baseline.
    """
    assert gating_log_lines(PFB_PAGE_UNDEF_VAR, baseline=frozenset()), "the un-baselined line must gate"
    baseline = frozenset(diagnostic_fingerprint(line) or "" for line in [PFB_PAGE_UNDEF_VAR])
    assert gating_log_lines(PFB_PAGE_UNDEF_VAR, baseline=baseline) == ()


def test_a_baselined_diagnostic_stays_baselined_when_its_line_moves() -> None:
    """The fingerprint carries no line number, so editing the file above a known site
    does not resurrect it as a "new" diagnostic.

    This is the whole reason the baseline is not keyed by ``(file, line)``: those keys
    rot on the first unrelated edit, and a rotted baseline fails closed on innocent code.
    """
    baseline = frozenset({diagnostic_fingerprint(PFB_PAGE_UNDEF_VAR) or ""})
    moved = PFB_PAGE_UNDEF_VAR.replace("on line 100", "on line 412")
    assert gating_log_lines(moved, baseline=baseline) == ()


def test_a_new_key_in_a_baselined_file_still_gates() -> None:
    """A file with grandfathered sites is NOT excluded -- a new warning in it still fails.

    Excluding whole files would blind the pages the issue cares about most; only the
    exact known diagnostics are forgiven.
    """
    baseline = frozenset({diagnostic_fingerprint(PFB_PAGE_UNDEF_VAR) or ""})
    fresh = PFB_PAGE_UNDEF_VAR.replace("$colspan", "$brand_new_var")
    assert gating_log_lines(fresh, baseline=baseline), "a new diagnostic in a baselined file must gate"


def test_the_same_message_from_another_file_still_gates() -> None:
    """The fingerprint includes the originating file, so a baseline entry cannot
    accidentally forgive the identical warning somewhere else."""
    baseline = frozenset({diagnostic_fingerprint(PFB_PAGE_UNDEF_VAR) or ""})
    elsewhere = PFB_PAGE_UNDEF_VAR.replace("pfblockerng_brand_new.php", "pfblockerng_alerts.php")
    assert gating_log_lines(elsewhere, baseline=baseline), "a baselined message must not forgive another file"


def test_the_shipped_baseline_parses_and_is_burning_down() -> None:
    """Every shipped baseline entry is a well-formed fingerprint of one of OUR files.

    A typo'd entry would silently forgive nothing (it matches no line), so this pins the
    file's shape; the ownership check pins that nobody grandfathers pfSense core here,
    which the guard ignores anyway and which would hide the intent of the list.
    """
    entries = load_baseline()
    assert entries, "the shipped baseline is empty -- regenerate it from a sweep or delete the file"
    for entry in entries:
        origin, level, message = entry.split("|", 2)
        assert PFB_PATH_MARKER in origin.lower(), f"baseline entry is not a pfBlockerNG file: {entry!r}"
        assert level in PHP_ERROR_LEVELS, f"baseline entry has an unknown PHP level: {entry!r}"
        assert message.strip(), f"baseline entry has an empty message: {entry!r}"
        assert "on line" not in message, f"baseline entry pins a line number (it will rot): {entry!r}"


def test_stale_baseline_entries_names_what_a_full_sweep_never_saw() -> None:
    """A grandfathered site unobserved in a full sweep is a removal candidate.

    One green sweep does not prove a fix because config-dependent paths may not be reached.
    """
    baseline = frozenset({"a|Warning|gone", "b|Warning|still here"})
    assert stale_baseline_entries(frozenset({"b|Warning|still here"}), baseline=baseline) == ("a|Warning|gone",)


def test_stale_baseline_entries_is_empty_when_every_entry_was_observed() -> None:
    """The off branch: nothing to prune while the backlog is genuinely still there."""
    baseline = frozenset({"a|Warning|one", "b|Warning|two"})
    assert stale_baseline_entries(baseline, baseline=baseline) == ()


def test_a_shipped_baseline_hit_is_recorded_only_through_the_guard() -> None:
    """A live sweep records the observation the staleness check consumes -- a direct
    classification call does NOT.

    Both halves matter. Without recording, the sweep would report every entry as stale and
    demand deleting a backlog that is still very much present. Without the restriction, any
    off-box unit test that classifies a synthetic line would mark a REAL entry observed and
    permanently hide it from the removal report — the same "forgiven diagnostic nobody ever
    re-examines" blindness this whole issue exists to remove.
    """
    entry = sorted(load_baseline())[0]
    file, level, message = entry.split("|", 2)
    line = f"[25-Jul-2026 10:00:00 UTC] PHP {level}:  {message} in {file} on line 1\n"

    # Direct classification: the shipped entry is forgiven, but nothing is recorded.
    assert gating_log_lines(line) == ()
    assert entry not in observed_baseline_entries(), "a direct call must never record a live observation"

    # Through the guard (what a real sweep does): recorded.
    _guard_after_appending(line).assert_no_growth()
    assert entry in observed_baseline_entries()


def test_a_unit_test_baseline_hit_is_not_recorded_as_observed() -> None:
    """A caller-supplied baseline is a fixture, not a live sweep: its hits must not
    count as observations, or a unit run would mark real entries alive."""
    invented = "/usr/local/www/pfblockerng/never_shipped.php|Warning|Undefined variable $invented"
    file, level, message = invented.split("|", 2)
    line = f"[25-Jul-2026 10:00:00 UTC] PHP {level}:  {message} in {file} on line 1"
    gating_log_lines(line, baseline=frozenset({invented}), record=True)
    assert invented not in observed_baseline_entries()


def test_our_warning_still_gates_when_mixed_with_core_noise() -> None:
    """(d): one of OUR lines buried among core lines is still found and reported.

    A real sweep appends many lines at once; the guard must scan the whole appended
    chunk rather than classifying it by its first line.
    """
    with pytest.raises(AssertionError, match="Undefined variable"):
        _guard_after_appending(CORE_WARNING + PFB_PAGE_UNDEF_VAR + FPM_POOL_CHATTER).assert_no_growth()
