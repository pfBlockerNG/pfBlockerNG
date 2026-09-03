"""Tier-B browser tests (issue #1732 step 3): a real lint diagnostic reaches the
CodeMirror gutter on the LIVE webConfigurator, for BOTH CM6 editors this branch wired
(``pfblockerng_lint.php``, steps 1-2).

Two lint sources feed the same ``@codemirror/lint`` gutter, and this file proves each
one independently:

* The DNSBL page's regex-list editor (``#pfb_regex_list`` -> ``#Python_regex_list
  .cm-content``) carries BOTH an INSTANT, offline Lezer bracket lint (unbalanced/
  unclosed ``(`` or ``[``, ``cm-lint.js`` ``lezerErrorLint()`` -- no network) and the
  advisory SERVER round-trip (``lang=regex`` POST, ~750ms debounce). Test 1 drives the
  offline path with an input the tolerant Lezer grammar itself flags
  (``tools/webassets/test/cm-lint.test.js`` pins the same bare ``"("`` doc). Test 2
  drives a pattern the SAME grammar accepts as well-formed (balanced braces) but
  CPython's ``re.compile`` rejects (``a{2,1}``, "min repeat greater than max repeat") --
  a marker appearing there can only be the server's diagnostic, so it proves the
  round-trip actually reaches ``pfb_lint_diagnostics()``/``pfb_dnsbl_regex_validation_errors()``,
  not just the offline half.
* The Edit Hooks page's script editor (``#pfb_hook_editor_content`` -> ``.cm-content``,
  server lint ONLY -- no bracket lint is wired for shell/python StreamLanguage modes,
  see ``cm-lint.js``'s comment on ``cm-regex.js`` vs ``cm-hooks.js``) mounts and lints
  even with NO script loaded (``pfb_hook_editor_lang_for()`` falls back to ``'sh'``).
  Test 3 types a bare ``do`` (FreeBSD ``/bin/sh -n`` syntax error, whose stderr
  ``pfb_lint_parse_sh_stderr()`` turns into a ``"Syntax error: ..."`` message), asserts
  the marker + tooltip, then replaces it with valid content and asserts the marker
  clears -- the same two-way clear-back-to-valid sequence as tests 1/2, folded into
  this test's tail rather than a separate function that would just re-run it.

DEFERRED (not built here): the Edit Hooks page's ``lang='py'`` variant. The gutter path
is client-side and language-agnostic (same ``serverLint()`` wiring regardless of which
lang string is passed, see ``cm-hooks.js``); driving the page's create-flow to mint a
real ``.py`` hook just to prove the SAME code path again buys nothing this tier needs.
The Python lint branch itself (``pfb_lint_py_diagnostics()``/``pfb_lint_parse_py_stderr()``)
is already covered by the endpoint's PHPUnit tests and the appliance-format probe
(``tests/smoke/test_smoke_lint_probe.py``).

Never mutates persisted config: neither test clicks Save or issues a POST -- the DNSBL
``#pfb_regex`` checkbox flip is the same client-side show/hide already exercised
without saving in ``test_browser_dnsbl.py``, and typing into a CM editor only updates
its own in-memory doc (+ the hidden mirror textarea's ``.value``, per ``cm-regex.js``/
``cm-hooks.js``'s ``updateListener``) -- nothing is ever submitted.

CM class names are pinned against the SHIPPED vendor bundle, not the upstream package
docs: ``grep -o 'cm-lint-marker[a-zA-Z-]*\\|cm-tooltip-lint\\|cm-gutter-lint'
src/usr/local/www/pfblockerng/vendor/codemirror/cm-regex.min.js`` (identical in
``cm-hooks.min.js``) returns ``cm-lint-marker``, ``cm-lint-marker-error``,
``cm-lint-marker-warning``, ``cm-lint-marker-info``, ``cm-tooltip-lint``,
``cm-gutter-lint`` -- matching ``@codemirror/lint``'s vendored source
(``tools/webassets/node_modules/@codemirror/lint/dist/index.js:767,213,837``).

NO fixed sleeps: every assertion is Playwright auto-waiting ``expect(...)``.
``@codemirror/lint``'s ``linter()`` wraps EVERY source (offline and server alike) in its
own ~750ms debounce (``index.js`` ``LintState`` ``delay: 750``) before the server half
even starts its POST, so ``LINT_TIMEOUT_MS`` is a generous flake ceiling for both, not a
wait knob. Per-step full-page screenshots go to ``screenshot_dir`` (artifacts, not
asserted baselines).

Playwright is imported lazily via ``pytest.importorskip`` so collecting this module
without it installed does not hard-error.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .conftest import mask_page_identity

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright not installed (Tier-B browser dep)")
expect = sync_api.expect

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.sync_api import Locator, Page

    from .webui import WebUI

pytestmark = pytest.mark.ui_browser

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
HOOKS_PAGE = "/pfblockerng/pfblockerng_edit_hooks.php"

# DOM-settle ceiling (checkbox click, section show/hide, editor mount): synchronous JS,
# not a debounce -- a flake ceiling, matching the sibling browser files' JS_TIMEOUT_MS.
JS_TIMEOUT_MS = 10_000

# Lint-result ceiling: covers @codemirror/lint's own ~750ms debounce PLUS (for the
# server-backed cases) the POST round-trip to pfblockerng_lint.php. Generous on
# purpose; the assertion itself is still event-shaped (expect auto-wait), never a sleep.
LINT_TIMEOUT_MS = 20_000


def _open(page: Page, webui: WebUI, path: str) -> None:
    """Navigate the (cookie-authenticated) page to ``path`` and settle the DOM.

    Asserts the load did NOT bounce to the login form -- proving the injected session
    cookie authenticated the browser (no second login). Waits on ``networkidle`` so the
    page's ``events`` handlers (which mount the CM6 editors) have run before any
    assertion.
    """
    page.goto(webui.url(path), wait_until="domcontentloaded", timeout=JS_TIMEOUT_MS * 3)
    page.wait_for_load_state("networkidle", timeout=JS_TIMEOUT_MS * 3)
    # The login form carries #usernamefld; its absence proves we are authed.
    assert page.locator("#usernamefld").count() == 0, f"GET {path} showed the login form -- cookie not authenticated"


def _shot(page: Page, screenshot_dir: Path, name: str) -> None:
    """Write a full-page screenshot artifact ``<screenshot_dir>/<name>.png``.

    Value-redacts the Plus VM identity from the DOM first (ADR-24 ``mask_page_identity``);
    a strict no-op on a CE leg (empty redaction set), so CE shots are unchanged.
    """
    mask_page_identity(page)
    page.screenshot(path=str(screenshot_dir / f"{name}.png"), full_page=True)


def _clear_and_type(content: Locator, text: str) -> None:
    """Replace a CM6 contenteditable ``.cm-content`` editor's whole doc with ``text``.

    ``.fill()`` targets a real form control's ``.value`` and is a no-op on CM's
    contenteditable div -- so this drives real key events instead: click to focus,
    Ctrl/Cmd+A to select the whole doc, Delete to clear, then ``press_sequentially()``
    to dispatch ``text`` as individual keystrokes so CM's own input/update pipeline (and
    therefore every wired lint extension) observes each one, same as a real user typing.
    An empty ``text`` just leaves the editor cleared.
    """
    content.click()
    content.page.keyboard.press("ControlOrMeta+a")
    content.page.keyboard.press("Delete")
    if text:
        content.press_sequentially(text, delay=20)


def _lint_markers(content: Locator) -> Locator:
    """Gutter lint markers (``.cm-gutter-lint .cm-lint-marker``) for a ``.cm-content`` editor.

    Scoped to the enclosing ``.cm-editor`` (the gutter and the content div are siblings
    under the same editor root) -- cheap insurance even on the pages this file drives,
    which each mount exactly one CM instance. Class names verified against the SHIPPED
    vendor bundle (module docstring) and the vendored ``@codemirror/lint`` source
    (``dist/index.js:767`` builds ``"cm-lint-marker cm-lint-marker-" + severity``;
    ``:837`` builds the ``cm-gutter-lint`` gutter class).
    """
    editor = content.locator("xpath=ancestor::div[contains(concat(' ', @class, ' '), ' cm-editor ')][1]")
    return editor.locator(".cm-gutter-lint .cm-lint-marker")


def _regex_editor(page: Page) -> Locator:
    """Open the DNSBL page's regex-list CM editor, normalized to a known-EMPTY doc.

    Ensures ``#pfb_regex`` is checked -- native ``el.click()`` via ``evaluate`` so the
    bound jQuery handler fires regardless of control geometry, mirroring
    ``_assert_checkbox_gates_section`` in ``test_browser_dnsbl.py`` -- so the
    ``#Python_regex_list`` section (and the CM editor inside it) is visible. Never
    saves: the checkbox flip is the same client-side show/hide those sibling tests
    already exercise without a POST. The editor itself may load with a PREVIOUSLY
    SAVED regex list (another test's leftover config) -- clearing it here, rather than
    assuming it starts empty, is what makes the "before" state deterministic.
    """
    box = page.locator("#pfb_regex")
    expect(box).to_be_attached(timeout=JS_TIMEOUT_MS)
    if not box.is_checked():
        box.evaluate("el => el.click()")
    expect(box).to_be_checked(timeout=JS_TIMEOUT_MS)

    section = page.locator("#Python_regex_list")
    expect(section).to_be_visible(timeout=JS_TIMEOUT_MS)

    # The section is COLLAPSIBLE|SEC_CLOSED (pfblockerng_dnsbl.php:3056): the checkbox
    # .show()s the panel, but its BODY renders as `<id>_panel-body.panel-body.collapse`
    # and stays collapsed (zero-size, so nothing inside is Playwright-visible) until the
    # panel-title toggle anchor is clicked — Form/Section.class.php's COLLAPSIBLE
    # markup. Expanding here is also exactly the "CM6 re-measure on first expansion of
    # the collapsed Python-regex section" concern issue #1669 left for this tier: the
    # typing + gutter assertions below fail if CM never becomes usable after expansion.
    body = page.locator("#Python_regex_list_panel-body")
    expect(body).to_be_attached(timeout=JS_TIMEOUT_MS)
    if "in" not in (body.get_attribute("class") or ""):
        page.locator('a[data-toggle="collapse"][href="#Python_regex_list_panel-body"]').click()
    expect(body).to_be_visible(timeout=JS_TIMEOUT_MS)

    content = section.locator(".cm-content")
    expect(content).to_be_visible(timeout=JS_TIMEOUT_MS)
    _clear_and_type(content, "")
    return content


def _hook_editor(page: Page) -> Locator:
    """The Edit Hooks page's CM editor, normalized to a known-EMPTY doc.

    Nothing needs to be loaded first -- ``pfb_hook_editor_lang_for()`` falls back to
    ``'sh'`` when no script is selected, and the Editor section (and its CM mount) is
    always rendered. The page hosts exactly one CM instance, so the bare ``.cm-content``
    is unambiguous. Never saves: no Save click, no POST -- Save would error with no
    script loaded, so this never touches it at all.
    """
    content = page.locator(".cm-content")
    expect(content).to_be_visible(timeout=JS_TIMEOUT_MS)
    _clear_and_type(content, "")
    return content


def test_regex_editor_offline_bracket_lint_marks_instantly(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """An unbalanced ``(`` in the regex editor gets a gutter marker with NO network.

    ``lezerErrorLint()`` (``cm-lint.js``) walks the ``pfb-regex-list`` grammar's own
    Lezer error nodes -- a bare ``"("`` parses to an error node immediately (the exact
    doc ``tools/webassets/test/cm-lint.test.js`` pins), no round-trip to
    ``pfblockerng_lint.php`` required. The server also rejects a lone ``"("``, so without
    blocking the endpoint the marker's source is ambiguous -- ``page.route(...).abort()``
    on ``pfblockerng_lint.php`` before typing is the proof the marker comes from
    ``lezerErrorLint()`` alone. Two-way: type ``(`` -> marker appears, clear back to empty
    -> marker disappears (proves the assertion is a real branch, not always-green).

    The marker's SEVERITY is asserted too (issue #3088): a save-blocking editor
    parse failure is reported as an error (red). Description-length stays a
    warning. Before #3088 this row pinned warning because yellow-that-blocks-save
    had not been introduced yet.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    content = _regex_editor(page)
    markers = _lint_markers(content)

    expect(markers).to_have_count(0, timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_regex_offline_before_empty")

    page.route("**/pfblockerng_lint.php", lambda route: route.abort())

    _clear_and_type(content, "(")
    expect(markers).to_have_count(1, timeout=LINT_TIMEOUT_MS)
    # issue #3088: the SEVERITY, not just the presence. @codemirror/lint builds the
    # class as "cm-lint-marker cm-lint-marker-" + severity (vendored dist/index.js:767),
    # so this is the live-gutter pin of save-blocking red -- the node tests assert on
    # the diagnostic object, not on what the browser renders from the bundle.
    expect(markers).to_have_class(re.compile(r"\bcm-lint-marker-error\b"), timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_regex_offline_after_marked")

    _clear_and_type(content, "")
    expect(markers).to_have_count(0, timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_regex_offline_after_cleared")


def test_regex_editor_offline_lint_accepts_quantifier_before_flag_letter(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """Python-valid ``m?ad`` must not get a Lezer error marker (issue #3059).

    Abort the lint endpoint so a marker can only come from ``lezerErrorLint()``.
    Marked-then-clean: type ``(`` until a marker appears (proves the gutter is
    live), then type the pattern and require the marker to disappear.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    content = _regex_editor(page)
    markers = _lint_markers(content)

    expect(markers).to_have_count(0, timeout=LINT_TIMEOUT_MS)
    page.route("**/pfblockerng_lint.php", lambda route: route.abort())

    _clear_and_type(content, "(")
    expect(markers).to_have_count(1, timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_regex_offline_flag_letter_control")

    _clear_and_type(content, "^(.+[-_.])??m?ad[sxv]?[0-9]*[-_.]")
    expect(markers).to_have_count(0, timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_regex_offline_flag_letter_clean")


def test_regex_editor_server_lint_reports_python_only_error(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """A pattern the tolerant Lezer grammar accepts but CPython's ``re`` rejects only
    gets a marker via the SERVER round-trip -- proving ``lang=regex`` actually reaches
    ``pfblockerng_lint.php``, not just the offline bracket lint.

    ``a{2,1}`` is syntactically well-formed to the Lezer regexp grammar (balanced
    braces, no offline error node -- confirmed above: a bracket problem is the only
    thing ``lezerErrorLint()`` flags) but CPython's ``re.compile`` rejects it, so a
    marker appearing here can ONLY be ``pfb_lint_parse_regex_errors()``'s diagnostic
    (pfblockerng_extra.inc's regex probe reports
    ``f"Python regex compile error: {error}"``). Hovering the marker opens
    ``.cm-tooltip-lint``; assert the stable substring ``"repeat"`` rather than the exact
    CPython wording (verified locally: CPython's ``re.compile('a{2,1}')`` raises
    ``"min repeat greater than max repeat at position 2"`` -- the exact position may
    shift across CPython versions, the "repeat" wording is the load-bearing, stable
    part). Then a plain literal (``example``) is a valid pattern -- marker disappears.
    """
    page = browser_page
    _open(page, webui, DNSBL_PAGE)
    content = _regex_editor(page)
    markers = _lint_markers(content)

    expect(markers).to_have_count(0, timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_regex_server_before_empty")

    _clear_and_type(content, "a{2,1}")
    expect(markers).to_have_count(1, timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_regex_server_after_marked")

    markers.first.hover()
    tooltip = page.locator(".cm-tooltip-lint")
    expect(tooltip).to_be_visible(timeout=LINT_TIMEOUT_MS)
    expect(tooltip).to_contain_text(re.compile(r"repeat", re.I), timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_regex_server_tooltip")

    _clear_and_type(content, "example")
    expect(markers).to_have_count(0, timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_regex_server_after_valid")


def test_hook_editor_server_lint_marks_sh_syntax_error(
    browser_page: Page,
    webui: WebUI,
    screenshot_dir: Path,
) -> None:
    """A bare shell keyword gets a gutter marker via the server round-trip; a valid
    replacement clears it in the same two-way sequence (a standalone function would
    only repeat this test's own tail, so it is not split out).

    ``do`` alone is a FreeBSD ``/bin/sh -n`` syntax error. ``pfb_lint_sh_diagnostics()``/
    ``pfb_lint_parse_sh_stderr()`` turn its stderr into a message literally prefixed
    ``"Syntax error: "`` (pfblockerng_extra.inc), so the marker's tooltip is asserted on
    that substring. No script is loaded on this page (fallback lang ``'sh'``), and
    neither Save nor any POST is ever touched -- only the editor's own content changes.
    """
    page = browser_page
    _open(page, webui, HOOKS_PAGE)
    content = _hook_editor(page)
    markers = _lint_markers(content)

    expect(markers).to_have_count(0, timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_hooks_before_empty")

    _clear_and_type(content, "do")
    expect(markers).to_have_count(1, timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_hooks_after_marked")

    markers.first.hover()
    tooltip = page.locator(".cm-tooltip-lint")
    expect(tooltip).to_be_visible(timeout=LINT_TIMEOUT_MS)
    expect(tooltip).to_contain_text(re.compile(r"Syntax error", re.I), timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_hooks_tooltip")

    _clear_and_type(content, "echo ok")
    expect(markers).to_have_count(0, timeout=LINT_TIMEOUT_MS)
    _shot(page, screenshot_dir, "lint_hooks_after_valid")
