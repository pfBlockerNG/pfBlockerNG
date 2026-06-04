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
* **(d)** the on-box ``php_error.log`` gained **no new bytes** across the sweep
  (the source-of-truth log; checked once at sweep level, not per page -- see
  :class:`PhpErrorLogGuard`).

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
from typing import TYPE_CHECKING

from .webui import looks_like_login_page

if TYPE_CHECKING:
    from ..conftest import SmokeVM

# PHP diagnostic LEVELS (exact casing PHP emits). These are matched only in a
# real diagnostic SHAPE (see _PHP_DIAGNOSTIC_RE) -- never as a bare word: pages
# carry the level words in legitimate copy ("a pfSense Notice message", the
# "Warning: ..." input-error strings on pfblockerng_ip.php), so a bare-substring
# match false-positives. pfSense renders display_errors into the HTML, so a real
# Warning/Notice/Fatal still bleeds into the body in one of the shapes below --
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


# php_error.log candidates, in pfSense preference order. pfSense's webConfigurator
# FPM pool sets error_log to /var/log/php_error.log; php-fpm.log is the daemon's
# own log on some builds. We snapshot whichever exist so the guard is robust to
# the image's exact wiring (confirmed on-box at run time via stat -- CLAUDE.md:
# don't assume a path, read the effective state).
PHP_ERROR_LOG_CANDIDATES: tuple[str, ...] = (
    "/var/log/php_error.log",
    "/var/log/php-fpm.log",
)


class PhpErrorLogGuard:
    """Sweep-level ``php_error.log`` diff (oracle condition (d)), read over SSH.

    Snapshot the byte size of every existing candidate log ONCE before the
    parametrized sweep (:meth:`snapshot`), then assert no growth ONCE after
    (:meth:`assert_no_growth`). A new line written by ANY page in the sweep grows
    the file and fails -- this is the source-of-truth check that catches a PHP
    diagnostic logged but not echoed into a body (e.g. a Notice on a path that
    output-buffers, or an error_log() call).

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
        """Fail if any candidate ``php_error.log`` grew since :meth:`snapshot`.

        Raises :class:`AssertionError` naming the file and its size delta, plus
        the appended tail (best-effort) so the diagnostic is in the failure
        message, not only the uploaded artifact.
        """
        after = self._sizes()
        grew: list[str] = []
        for path, before in self._baseline.items():
            now = after.get(path, 0)
            if now > before:
                tail = self._vm.ssh("/usr/bin/tail", "-c", str(now - before), path).stdout
                grew.append(f"{path} grew {before}->{now} bytes; appended:\n{tail}")
        if grew:
            raise AssertionError("php_error.log gained new lines during the render sweep:\n" + "\n".join(grew))
