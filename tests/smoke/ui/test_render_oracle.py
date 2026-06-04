"""Prove the Tier-A oracle: a bare HTTP 200 can NEVER pass (ADR-14 Phase 2).

ADR §1 fact 3 / §2 contract: the render oracle must reject a 200 that carries a
PHP ``Warning``/``Notice``/``Fatal``, a blank/wrong body, or the login form.
This is the deliberately-broken-page proof, done as PURE LOGIC against
:func:`~tests.smoke.ui.render_oracle.evaluate_render` -- no VM, so it actually
executes (it needs no ``smoke_vm``).

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

import pytest

from .render_oracle import PHP_ERROR_LEVELS, body_has_php_error, evaluate_render

pytestmark = pytest.mark.ui_render

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
