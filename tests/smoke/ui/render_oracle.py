"""The Tier-A render-smoke oracle (ADR-14 Phase 2).

ADR §1 fact 3: **the pass/fail oracle is NOT HTTP 200.** A 200 can carry a
rendered PHP ``Warning``/``Notice``, a fatal-error trace, or a blank/redirected
body. So a page PASSES Tier A only when ALL of:

* **(a)** the response is **HTTP 200**;
* **(b)** the body contains no rendered PHP diagnostic in its recognizable SHAPE
  (:data:`_PHP_DIAGNOSTIC_RE` over :data:`PHP_ERROR_LEVELS` -- the ``PHP <Level>``
  prefix, the ``<b><Level></b>`` HTML wrapper, a ``<Level>: ... on line N`` line,
  an ``Uncaught …Error/Exception``, or a ``Stack trace:``), so a page that
  rendered a PHP diagnostic fails -- WITHOUT false-positiving on the level words
  in legitimate page copy;
* **(c)** a **page-specific content marker** is present (so a blank body, a
  redirect to the dashboard, or the login form cannot false-pass a 200);
* **(d)** the on-box ``php_error.log`` gained **no pfBlockerNG diagnostic** across
  the sweep (the source-of-truth log; checked once at sweep level, not per page --
  see :class:`PhpErrorLogGuard`). The guest runs a true ``E_ALL`` (#1218), so the
  runtime ``E_WARNING``/``E_NOTICE``/``E_DEPRECATED`` class IS observable here; the
  guard scopes those to our own files so pfSense-core noise does not gate.

This module is the reusable pure-logic core: :func:`evaluate_render` decides
(a)-(c) for one fetched page and returns a structured :class:`RenderResult`;
:class:`PhpErrorLogGuard` owns the (d) sweep-level ``php_error.log`` diff over
SSH. Phases 3/4 reuse :func:`body_has_php_error` / :data:`PHP_ERROR_LEVELS`.

It imports nothing third-party and does not touch the VM at module import time
(the SSH calls live inside :class:`PhpErrorLogGuard`'s methods), so it is import-
safe during default collection (which ``--ignore``s ``tests/smoke``) and the
pure-logic half is unit-testable off-box (``test_render_oracle.py``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from .webui import looks_like_login_page

if TYPE_CHECKING:
    from ..conftest import SmokeVM

# PHP diagnostic LEVELS (exact casing PHP emits). These are matched only in a
# real diagnostic SHAPE (see _PHP_DIAGNOSTIC_RE) -- never as a bare word: pages
# carry the level words in legitimate copy ("a pfSense Notice message", the
# "Warning: ..." input-error strings on pfblockerng_ip.php), so a bare-substring
# match false-positives. NOTE: pfSense sets display_errors=off (errors are LOGGED,
# not echoed -- rc.php_ini_setup), so a diagnostic reaches the body only when app
# code or pfSense's own handler prints it; the sweep-level log guard (condition (d),
# PhpErrorLogGuard) is the source-of-truth catch for a logged-but-not-echoed error --
# exactly the regression class Tier A exists to catch.
PHP_ERROR_LEVELS: tuple[str, ...] = (
    "Fatal error",
    "Parse error",
    "Recoverable fatal error",
    "Warning",
    "Notice",
    "Deprecated",
    "Strict Standards",
)

_LEVELS_ALT = "|".join(re.escape(level) for level in PHP_ERROR_LEVELS)

# A rendered PHP diagnostic has an UNAMBIGUOUS shape; match that, not the bare
# level word. Any one of:
#   * error_log / CLI prefix      "PHP <Level>"          (prose never says this)
#   * HTML display_errors wrapper "<b><Level></b>"       (prose never has this)
#   * plain display form          "<Level>: ... on line <N>"  (the file/line trailer
#                                  disambiguates from "Warning: When using ..." copy)
#   * an uncaught throwable        "Uncaught <X>Error/Exception"
#   * an exception stack trace     "Stack trace:\n#0"
_PHP_DIAGNOSTIC_RE = re.compile(
    rf"PHP\s+(?:{_LEVELS_ALT})\b"
    rf"|<b>\s*(?:{_LEVELS_ALT})\s*</b>"
    rf"|(?:{_LEVELS_ALT}):[^\n]*?\bon line\b\s*(?:<b>\s*)?\d+"
    r"|\bUncaught\s+\w*(?:Error|Exception)\b"
    r"|\bStack trace:\s*#0"
)


def body_has_php_error(body: str) -> str | None:
    """Return the matched PHP-diagnostic text in ``body`` (its shape), else ``None``.

    Matches the SHAPE of a rendered PHP diagnostic (:data:`_PHP_DIAGNOSTIC_RE`),
    NOT the bare level word -- the level words appear in legitimate page copy, so
    a substring match false-positives (this bit ``pfblockerng_ip.php``: "a pfSense
    Notice message"). A non-``None`` return is the proof a PHP diagnostic was
    rendered into the page (oracle condition (b) fails). Reusable by later tiers.
    """
    match = _PHP_DIAGNOSTIC_RE.search(body)
    return match.group(0) if match else None


@dataclass(frozen=True)
class RenderResult:
    """The (a)-(c) verdict for one fetched page (the (d) log check is sweep-level).

    ``ok`` is the AND of all three per-page conditions; ``reasons`` lists every
    condition that failed (empty iff ``ok``) so a failure message is specific.
    """

    path: str
    status_code: int
    ok: bool
    reasons: tuple[str, ...]

    @property
    def detail(self) -> str:
        """A human-readable one-line failure summary (empty when ``ok``)."""
        return "; ".join(self.reasons)


def evaluate_render(path: str, status_code: int, body: str, markers: tuple[str, ...]) -> RenderResult:
    """Apply oracle conditions (a)-(c) to one fetched page; return a :class:`RenderResult`.

    * (a) ``status_code == 200``;
    * (b) ``body`` contains no rendered PHP diagnostic shape (:func:`body_has_php_error`);
    * (c) at least one of ``markers`` is present AND the body is not the login
      form (a logged-out 200 renders the login page, which must never pass).

    ``markers`` is the page's stable content marker set (its ``$pgtitle`` crumb /
    ``Form_Section`` title). All three are checked independently so ``reasons``
    can name every failing condition, not just the first.
    """
    reasons: list[str] = []

    # (a) HTTP 200 -- never trust a non-200 even if the body looks fine.
    if status_code != 200:
        reasons.append(f"status {status_code} != 200")

    # (b) no PHP diagnostic rendered into the body.
    token = body_has_php_error(body)
    if token is not None:
        reasons.append(f"body contains PHP diagnostic {token!r}")

    # (c) a page-specific marker present AND not the login form. The login-form
    # guard catches the logged-out 200 (pfSense renders login in place, not a
    # 302); the marker guard catches a blank/redirected/wrong-page 200.
    if looks_like_login_page(body):
        reasons.append("body is the login form (session not authenticated)")
    elif not any(marker in body for marker in markers):
        reasons.append(f"no page marker present (expected one of {list(markers)})")

    return RenderResult(path=path, status_code=status_code, ok=not reasons, reasons=tuple(reasons))


# php_error.log candidates, in pfSense preference order. rc.php_ini_setup points
# php.ini's error_log at /tmp/PHP_errors.log (CLI + php-fpm APPLICATION errors); the
# webConfigurator FPM pool and some builds also write /var/log/php_error.log /
# /var/log/php-fpm.log. We snapshot whichever EXIST so the guard is robust to the
# image's exact wiring -- and the strict-error smoke test pins that the guest's
# effective ini_get('error_log') is one of these (CLAUDE.md: don't assume a path,
# read the effective state).
PHP_ERROR_LOG_CANDIDATES: tuple[str, ...] = (
    "/tmp/PHP_errors.log",
    "/var/log/php_error.log",
    "/var/log/php-fpm.log",
)

# Issue #1218: the guest runs a TRUE E_ALL (helpers.STRICT_PHP_ERROR_REPORTING), so the
# runtime E_WARNING / E_NOTICE / E_DEPRECATED class finally reaches the log and a
# "this page no longer warns" assertion can be red before its fix. The cost is that
# pfSense CORE emits that class too, on code we do not own; gating on it would redden
# every PR on upstream noise (the reason the mask existed). So the guard gates on the
# ORIGINATING FILE: those three levels fail the sweep only when raised inside a
# pfBlockerNG-owned file. Every OTHER level (fatal / parse / recoverable / user-*)
# fails wherever it is raised -- those were never masked and a core fatal reached
# through our page is still a broken page.
_MASKABLE_LEVELS = frozenset({"Warning", "Notice", "Deprecated"})

# Every file this package ships carries "pfblockerng" in its path (the package dir
# /usr/local/pkg/pfblockerng/, the www pages, the widget, the shortcut, the wizard) --
# verified against src/, which has no shipped file without it. A substring test is
# therefore the whole ownership rule, with no path list to keep from rotting.
PFB_PATH_MARKER = "pfblockerng"

# An error_log diagnostic line: "[<ts>] PHP <Level>:  <message> in <file> on line <N>".
# The level is anchored to the "PHP " prefix PHP itself writes, so php-fpm's own
# lifecycle chatter ("NOTICE: [pool nginx] child N started") is not a diagnostic.
_LOG_DIAGNOSTIC_RE = re.compile(rf"PHP\s+(?P<level>{_LEVELS_ALT})\s*:\s*(?P<message>.*)")
_LOG_ORIGIN_RE = re.compile(r"\bin (?P<file>\S+) on line \d+")

# The burn-down baseline of diagnostics that ALREADY existed when the guest was raised
# to E_ALL (#1218 measured ~230 across 8 files; the cleanup is tracked separately). Each
# entry is "<origin file>|<level>|<message>" -- deliberately WITHOUT the line number, so
# an unrelated edit above a known site does not resurrect it as a new diagnostic and fail
# innocent code. The list may only ever SHRINK: a new diagnostic gates, and the fix is to
# fix it, not to append. A failing sweep prints the exact entries, so no generator script
# is needed to grow one.
BASELINE_FILENAME = "php_diagnostic_baseline.txt"

# Cap on distinct offending lines quoted in one failure message (the rest are counted).
_MAX_REPORTED_LINES = 20


def diagnostic_fingerprint(line: str) -> str | None:
    """The line-number-free identity of one logged diagnostic, or ``None`` if not one."""
    diagnostic = _LOG_DIAGNOSTIC_RE.search(line)
    if diagnostic is None:
        return None
    origin = _LOG_ORIGIN_RE.search(line)
    file = origin.group("file") if origin is not None else "?"
    # Drop the " in <file> on line <N>" trailer and collapse PHP's double spaces, so the
    # fingerprint is stable across line moves and formatting.
    message = " ".join(_LOG_ORIGIN_RE.sub("", diagnostic.group("message")).split())
    return f"{file}|{diagnostic.group('level')}|{message}"


@lru_cache(maxsize=None)
def load_baseline(path: Path | None = None) -> frozenset[str]:
    """The grandfathered fingerprints (blank lines and ``#`` comments ignored).

    A missing file reads as an empty baseline: nothing is forgiven, which fails LOUD
    rather than silently disabling the gate.
    """
    baseline_path = path if path is not None else Path(__file__).with_name(BASELINE_FILENAME)
    if not baseline_path.exists():
        return frozenset()
    lines = baseline_path.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#"))


# Fingerprints from the SHIPPED baseline actually seen during this session. A baseline
# entry nobody observes any more is a site that got FIXED, and leaving it in the file
# would silently forgive that diagnostic if it ever came back -- so a full sweep fails on
# unobserved entries and the fix is to delete them (see stale_baseline_entries).
_observed_baseline: set[str] = set()


def observed_baseline_entries() -> frozenset[str]:
    """Shipped-baseline fingerprints matched so far in this session."""
    return frozenset(_observed_baseline)


def stale_baseline_entries(observed: frozenset[str], baseline: frozenset[str] | None = None) -> tuple[str, ...]:
    """Baseline entries never observed -- fixed sites whose grandfathering must go.

    Only meaningful after a FULL sweep: a filtered or sharded run visits a subset of the
    pages, so almost every entry would read as stale. The caller owns that condition.
    """
    grandfathered = load_baseline() if baseline is None else baseline
    return tuple(sorted(grandfathered - observed))


def gating_log_lines(appended: str, baseline: frozenset[str] | None = None) -> tuple[str, ...]:
    """The lines of an appended ``php_error.log`` chunk that must FAIL the sweep.

    A line gates when it is a PHP diagnostic AND either its level is not one of the
    core-noisy :data:`_MASKABLE_LEVELS` or it was raised in a pfBlockerNG-owned file
    (:data:`PFB_PATH_MARKER`) -- unless its fingerprint is grandfathered by ``baseline``
    (the shipped :data:`BASELINE_FILENAME` when not given). Anything else -- core
    warnings/notices/deprecations, fpm pool chatter, stack-trace continuation lines --
    is ignored.

    ponytail: ownership is decided by the file the diagnostic was RAISED in, which is
    what ``errfile`` reports. A warning raised inside a pfSense core function that our
    page called therefore reads as core noise and does not gate; catching that class
    needs a call-stack, which no log line carries. Deliberate: it is the same scoping
    the issue's design settled on, and the body oracle (b) still catches it whenever
    the diagnostic is rendered.
    """
    grandfathered = load_baseline() if baseline is None else baseline
    patterns = tuple(entry for entry in grandfathered if "*" in entry)
    gating: list[str] = []
    for line in appended.splitlines():
        diagnostic = _LOG_DIAGNOSTIC_RE.search(line)
        if diagnostic is None:
            continue
        if diagnostic.group("level") in _MASKABLE_LEVELS:
            origin = _LOG_ORIGIN_RE.search(line)
            if origin is None or PFB_PATH_MARKER not in origin.group("file").lower():
                continue
        fingerprint = diagnostic_fingerprint(line)
        matched = fingerprint if fingerprint in grandfathered else _matching_pattern(fingerprint, patterns)
        if matched is not None:
            # Record the hit only for the SHIPPED baseline: a caller passing its own set
            # is a unit test, and its fixtures must not look like live observations.
            if baseline is None:
                _observed_baseline.add(matched)
            continue
        gating.append(line)
    return tuple(gating)


def _matching_pattern(fingerprint: str | None, patterns: tuple[str, ...]) -> str | None:
    """The wildcard baseline entry covering ``fingerprint``, if any.

    A site whose message varies by DATA rather than by defect -- the Feeds page reads
    ``$fconfig['feed_' . $alias]`` for every alias in the catalogue, so which keys are
    absent depends on which aliases exist right then -- cannot be enumerated key by key:
    each sweep would surface a different slice and the file would never converge. One
    ``*`` entry stands for that whole family. Everything else stays exact, so a wildcard
    can never quietly forgive a different defect: the file and level still match exactly,
    and only the message part globs.
    """
    if fingerprint is None:
        return None
    for pattern in patterns:
        if fnmatch(fingerprint, pattern):
            return pattern
    return None


class PhpErrorLogGuard:
    """Sweep-level ``php_error.log`` diff (oracle condition (d)), read over SSH.

    Snapshot the byte size of every existing candidate log ONCE before the
    parametrized sweep (:meth:`snapshot`), then read back everything appended and
    assert none of it is OURS ONCE after (:meth:`assert_no_growth`) -- the
    source-of-truth check that catches a PHP diagnostic logged but not echoed into
    a body (e.g. a Notice on a path that output-buffers, or an error_log() call).

    The size is the read offset, not the verdict: since #1218 the verdict comes
    from :func:`gating_log_lines` over the appended text, so a sweep that only
    stirred up pfSense-core noise or an fpm worker respawn stays green while one
    of our own warnings fails.

    Sizes are read with ``stat -f %z`` (BSD/pfSense ``stat``); a missing file
    reports size 0 (``|| echo 0``), so a log created mid-sweep also registers as
    growth (0 -> N).
    """

    def __init__(self, vm: SmokeVM, candidates: tuple[str, ...] = PHP_ERROR_LOG_CANDIDATES) -> None:
        self._vm = vm
        self._candidates = candidates
        self._baseline: dict[str, int] = {}

    def _sizes(self) -> dict[str, int]:
        """Current byte size of each candidate log (missing -> 0)."""
        sizes: dict[str, int] = {}
        for path in self._candidates:
            # Pass a DIRECT argv (no `/bin/sh -c "..."` wrapper): ssh space-joins
            # its remote args into ONE string the guest login shell re-parses, so
            # `/bin/sh -c "stat -f %z P 2>/dev/null || echo 0"` would have `-c`
            # consume only `stat` and stat would then read stdin (the classic
            # double-parse -> "(stdin)" output). `stat -f %z <path>` (BSD stat:
            # %z = size in bytes) runs cleanly as a direct argv, no shell needed.
            result = self._vm.ssh("/usr/bin/stat", "-f", "%z", path)
            if result.returncode == 0:
                text = result.stdout.strip()
                try:
                    sizes[path] = int(text)
                except ValueError as exc:
                    raise AssertionError(f"unparseable php_error.log size for {path}: {result.stdout!r}") from exc
            elif result.returncode == 255:
                # 255 is ssh's OWN failure code (transport/auth) -- a real read
                # fault, not a missing file; fail fast rather than masking oracle
                # condition (d) (a failed read before AND after shows no growth).
                raise AssertionError(
                    f"ssh failed reading php_error.log size for {path}: {(result.stderr or result.stdout).strip()!r}"
                )
            else:
                # stat exited non-zero (the log does not exist yet) -> size 0, so a
                # file created mid-sweep still registers as growth (0 -> N).
                sizes[path] = 0
        return sizes

    def snapshot(self) -> None:
        """Record the pre-sweep byte size of every candidate log."""
        self._baseline = self._sizes()

    def assert_no_growth(self) -> None:
        """Fail if any candidate ``php_error.log`` gained a pfBlockerNG diagnostic.

        Reads the bytes appended since :meth:`snapshot` and classifies them with
        :func:`gating_log_lines`: our-file ``Warning``/``Notice``/``Deprecated``
        and any non-maskable level fail; core noise and non-diagnostic lines do
        not (issue #1218 -- the guest runs a true ``E_ALL`` now, so the log carries
        upstream diagnostics we neither own nor can fix).

        Raises :class:`AssertionError` naming the file and the offending lines, so
        the diagnostic is in the failure message, not only the uploaded artifact.
        """
        after = self._sizes()
        offending: list[str] = []
        for path, before in self._baseline.items():
            now = after.get(path, 0)
            if now <= before:
                continue
            appended = self._vm.ssh("/usr/bin/tail", "-c", str(now - before), path).stdout
            gating = gating_log_lines(appended)
            if gating:
                # A raised E_ALL can append thousands of lines; report the distinct ones
                # (capped) rather than a wall of repeats -- the full log is in the
                # uploaded diagnostics snapshot either way.
                distinct = list(dict.fromkeys(gating))
                shown = distinct[:_MAX_REPORTED_LINES]
                elided = len(distinct) - len(shown)
                report = f"{path} ({before}->{now} bytes), {len(distinct)} distinct:\n" + "\n".join(shown)
                if elided:
                    report += f"\n... and {elided} more distinct line(s)"
                offending.append(report)
        if offending:
            raise AssertionError(
                "pfBlockerNG PHP diagnostics were logged during the render sweep:\n"
                + "\n".join(offending)
                + f"\n\nIf a line is a KNOWN pre-existing site, its {BASELINE_FILENAME} entry is "
                "'<file>|<level>|<message>' — but the baseline only ever shrinks: fix the site instead."
            )
