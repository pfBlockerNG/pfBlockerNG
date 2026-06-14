"""Tier-B functional WebUI flows for the Update Hooks page (ADR-12 / ADR-14).

Marker ``ui_e2e`` -- daily / on-demand, NOT in the default run nor the PR gate
(the whole ``tests/smoke`` tree is ``--ignore``d in the default
``python -m pytest``; this tier runs with
``pytest tests/smoke -m ui_e2e --override-ini="addopts="``).

The RENDER and add-row browser coverage for ``pfblockerng_hooks.php`` already
landed in PR #107 (``test_render_smoke`` + ``test_browser``). THIS file is the
FUNCTIONAL (config round-trip) tier for the page's save handler: it drives the
real CSRF form POST and proves the EFFECTIVE state -- ``config.xml`` read via
:func:`tests.smoke.helpers.config_get`, NEVER the HTTP response body -- moved (or
did NOT move, on a reject).

The hook page is a SCRIPT PICKER, not a command box (ADR-12 security model): a hook
runs a VETTED on-box script file (``hook_<when>_*.{sh,py}`` in
``helpers.HOOK_SCRIPT_DIR``), authored by a shell-access admin; the GUI only selects
one. So these flows install the test scripts on the box first, then drive the form.

What the save handler does (read END TO END from
``src/usr/local/www/pfblockerng/pfblockerng_hooks.php``):

* It is a repeatable ``rowhelper``. Each hook row ``N`` carries the POST fields
  ``hook_script-N`` (select -- a basename from the hook-script dir for the row's
  Pre/Post), ``hook_when-N`` (select ``pre``/``post``), ``hook_enabled-N``
  (checkbox, value ``on`` -- absent when unchecked), ``hook_timeout-N`` (number)
  and ``hook_description-N`` (text). The empty render shows ONE placeholder row
  keyed ``0``.
* On ``isset($_POST['save'])`` it collects every ``field-rowid`` key, validates
  each, and -- only if there are NO input errors -- rebuilds the list and writes
  it to ``installedpackages/pfblockerng/config/0/hooks/row`` (the ``row`` listtag,
  so 1..N rows round-trip through config.xml). The per-entry shape is
  ``{script, when, enabled, description, timeout}``.
* An EMPTY resulting list deletes the whole node:
  ``config_del_path('installedpackages/pfblockerng/config/0/hooks')``.
* Validation rejects (config stays UNCHANGED -- no write_config) when: a
  ``hook_when`` value is not ``pre``/``post``; a ``hook_script`` is not a valid
  ``hook_<when>_*.{sh,py}`` present in the hook-script dir for the row's Pre/Post
  (empty, missing, a Pre/Post-prefix mismatch, a path/traversal); or any field
  value is a non-scalar.

Every flow is a TRUE transition test (CLAUDE.md): it asserts the BEFORE-state,
drives the form, asserts the AFTER-state via config.xml, and -- in a ``finally``
-- restores the box (``clear_update_hooks`` deletes the node) so a mid-test
failure can't poison the session-scoped VM for the sibling flows / Tier A. The
reject flows assert the seeded value is STILL present after the rejected POST, so
a green proves the validator blocked the write (not that the write happened to
land the same value).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

HOOKS_PAGE = "/pfblockerng/pfblockerng_hooks.php"

# config.xml nodes the save handler writes. Row 0 is the first (and, in these
# single-row flows, only) entry; 'row' is the listtag so a lone hook is
# row/0/<field>, never collapsed (see the page's save block + pfb_get_hooks()).
CFG_HOOKS = helpers.CFG_HOOKS  # installedpackages/pfblockerng/config/0/hooks
CFG_HOOKS_ROW = helpers.CFG_HOOKS_ROW  # .../hooks/row
ROW0 = CFG_HOOKS_ROW + "/0"
ROW0_SCRIPT = ROW0 + "/script"
ROW0_WHEN = ROW0 + "/when"
ROW0_ENABLED = ROW0 + "/enabled"
ROW0_TIMEOUT = ROW0 + "/timeout"
ROW0_DESCRIPTION = ROW0 + "/description"

# The vetted test scripts these flows pick from. A hook only validates/runs when
# its script is a hook_<when>_*.{sh,py} present in the hook-script dir, so the flows
# install these first. A no-op body is enough -- the save handler never runs them.
SCRIPT_PRE = "hook_pre_uismoke.sh"
SCRIPT_POST = "hook_post_uismoke.sh"
SCRIPT_BODY = "#!/bin/sh\nexit 0\n"

# A delimiter-fenced sentinel for reading PHP truthiness over pfSsh.php (whose
# startup banner would otherwise pollute the value). Mirrors helpers.config_get.
_OPEN = "<<<HOOKVAL>>>"
_CLOSE = "<<<HOOKEND>>>"


def _install_test_scripts(vm: helpers.SmokeVM) -> None:
    """Place the pre/post test scripts in the hook-script dir so the picker accepts them."""
    helpers.install_hook_script(vm, SCRIPT_PRE, SCRIPT_BODY)
    helpers.install_hook_script(vm, SCRIPT_POST, SCRIPT_BODY)


def _hooks_node_exists(vm: helpers.SmokeVM) -> bool:
    """True iff the ``hooks`` config node exists at all (array present).

    ``config_get`` casts to string, which is useless for "does the array node
    exist" (an empty array -> ``''`` is indistinguishable from a deleted node).
    Read the node directly and report whether it is an array, fenced so the
    pfSsh.php banner can't pollute the answer. The empty-list save path deletes
    the whole node (``config_del_path('.../hooks')``), so this is the oracle for
    that branch.
    """
    snippet = f"$h = config_get_path('{CFG_HOOKS}', null);\necho '{_OPEN}' . (is_array($h) ? '1' : '0') . '{_CLOSE}';"
    result = helpers.php_eval(vm, snippet)
    out = result.stdout
    start = out.find(_OPEN)
    end = out.find(_CLOSE)
    if start == -1 or end == -1:
        raise RuntimeError(f"_hooks_node_exists: no fenced value: rc={result.returncode} out={out!r}")
    return out[start + len(_OPEN) : end] == "1"


def _seed_one_hook(
    vm: helpers.SmokeVM,
    *,
    script: str = SCRIPT_POST,
    when: str = "post",
    enabled: str = "",
    timeout: str = "",
    description: str = "",
) -> None:
    """Persist exactly ONE hook row (and install its script) via the UI's config path.

    Uses :func:`helpers.set_update_hooks` (installs the script body, writes
    ``hooks/row`` under the listtag, and read-back-guards the count), so the seeded
    box is byte-identical to what a real save would leave -- a sound BEFORE-state for
    the reject flows and the enabled-toggle flow.
    """
    helpers.set_update_hooks(
        vm,
        [
            {
                "script": script,
                "_body": SCRIPT_BODY,
                "when": when,
                "enabled": enabled,
                "description": description,
                "timeout": timeout,
            }
        ],
    )


def test_save_one_hook_row_persists_to_config(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """POSTing one valid hook row writes {script,when,timeout} to config.xml.

    Transition: BEFORE there is NO hooks node (cleared first); the form POST must
    CREATE the row, persisting each field at ``hooks/row/0/<field>``. Oracle =
    config.xml, never the HTTP body. Restored (node deleted) in ``finally``.
    """
    vm = smoke_vm
    helpers.clear_update_hooks(vm)
    _install_test_scripts(vm)
    try:
        # BEFORE: no hooks node at all (empty-list save path deletes it).
        assert not _hooks_node_exists(vm), "hooks node present before the save flow seeded anything"

        # The empty render is a single placeholder row keyed 0; override its
        # fields. webui.post re-scrapes the form (current fields + fresh CSRF
        # token), applies overrides, adds the save button, and POSTs back.
        resp = webui.post(
            HOOKS_PAGE,
            {
                "hook_script-0": SCRIPT_POST,
                "hook_when-0": "post",
                "hook_timeout-0": "45",
                "hook_description-0": "smoke save",
                "hook_enabled-0": "on",
            },
            timeout=120.0,
        )
        assert not looks_like_login_page(resp.text), "hooks save POST returned the login form (session lost)"

        # AFTER: the row landed under the 'row' listtag at index 0.
        assert _hooks_node_exists(vm), "hooks node absent after a valid save"
        assert helpers.config_get(vm, ROW0_SCRIPT) == SCRIPT_POST, (
            f"script not persisted: got {helpers.config_get(vm, ROW0_SCRIPT)!r}"
        )
        assert helpers.config_get(vm, ROW0_WHEN) == "post", (
            f"when not persisted: got {helpers.config_get(vm, ROW0_WHEN)!r}"
        )
        assert helpers.config_get(vm, ROW0_TIMEOUT) == "45", (
            f"timeout not persisted: got {helpers.config_get(vm, ROW0_TIMEOUT)!r}"
        )
        assert helpers.config_get(vm, ROW0_DESCRIPTION) == "smoke save", (
            f"description not persisted: got {helpers.config_get(vm, ROW0_DESCRIPTION)!r}"
        )
        assert helpers.config_get(vm, ROW0_ENABLED) == "on", (
            f"enabled not persisted: got {helpers.config_get(vm, ROW0_ENABLED)!r}"
        )
    finally:
        helpers.clear_update_hooks(vm)


def test_enabled_toggle_off_then_on(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The per-row enabled checkbox round-trips both ways through the save handler.

    Branch coverage (CLAUDE.md): exercise the checkbox OFF *and* ON. The handler
    stores ``'on'`` only when ``hook_enabled-N === 'on'`` is present, else ``''``
    (an unchecked browser checkbox sends nothing). Transition: seed enabled ON,
    assert ON, POST with the box CLEARED -> assert ``''``, POST with it set ->
    assert ``'on'`` again. The script stays valid throughout so the save is never
    rejected for an unrelated reason. Restored in ``finally``.
    """
    vm = smoke_vm
    helpers.clear_update_hooks(vm)
    _install_test_scripts(vm)
    _seed_one_hook(vm, script=SCRIPT_POST, when="post", enabled="on")
    try:
        # BEFORE: enabled is ON as seeded.
        assert helpers.config_get(vm, ROW0_ENABLED) == "on", "seed did not store enabled=on"

        # OFF: clear the checkbox. scrape_form_fields drops an unchecked box, but the
        # seeded row renders it CHECKED so the scrape WOULD re-send 'on'; override to
        # '' (the handler stores '' for any value != 'on').
        resp = webui.post(HOOKS_PAGE, {"hook_enabled-0": ""}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "toggle-off POST returned the login form"
        assert helpers.config_get(vm, ROW0_ENABLED) == "", (
            f"enabled not cleared: got {helpers.config_get(vm, ROW0_ENABLED)!r}"
        )
        # The rest of the row must be intact (proves only the toggle changed).
        assert helpers.config_get(vm, ROW0_SCRIPT) == SCRIPT_POST, "script lost on the toggle-off save"

        # ON again: send the checkbox value 'on'.
        resp = webui.post(HOOKS_PAGE, {"hook_enabled-0": "on"}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "toggle-on POST returned the login form"
        assert helpers.config_get(vm, ROW0_ENABLED) == "on", (
            f"enabled not re-set: got {helpers.config_get(vm, ROW0_ENABLED)!r}"
        )
    finally:
        helpers.clear_update_hooks(vm)


def test_when_pre_vs_post_persists(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The 'When' select stores pre vs post (both branches), with the matching script.

    Branch coverage: the ``hook_when`` select has two valid options; exercise BOTH.
    Because the script is Pre/Post-specific (the file prefix), a When flip carries the
    matching script -- which also exercises the prefix-coupling the validator enforces.
    Transition: seed when=post (post script), POST when=pre + the pre script -> assert
    pre, POST when=post + the post script -> assert post. Restored in ``finally``.
    """
    vm = smoke_vm
    helpers.clear_update_hooks(vm)
    _install_test_scripts(vm)
    _seed_one_hook(vm, script=SCRIPT_POST, when="post", enabled="on")
    try:
        # BEFORE: when is post as seeded.
        assert helpers.config_get(vm, ROW0_WHEN) == "post", "seed did not store when=post"

        # Flip to pre (carry the pre script so the row stays valid).
        resp = webui.post(HOOKS_PAGE, {"hook_when-0": "pre", "hook_script-0": SCRIPT_PRE}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "when=pre POST returned the login form"
        assert helpers.config_get(vm, ROW0_WHEN) == "pre", (
            f"when not stored as pre: got {helpers.config_get(vm, ROW0_WHEN)!r}"
        )
        assert helpers.config_get(vm, ROW0_SCRIPT) == SCRIPT_PRE, "pre script not stored with when=pre"

        # Flip back to post (reverse transition).
        resp = webui.post(HOOKS_PAGE, {"hook_when-0": "post", "hook_script-0": SCRIPT_POST}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "when=post POST returned the login form"
        assert helpers.config_get(vm, ROW0_WHEN) == "post", (
            f"when not stored back as post: got {helpers.config_get(vm, ROW0_WHEN)!r}"
        )
    finally:
        helpers.clear_update_hooks(vm)


def test_remove_to_empty_deletes_node(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Clearing the only row to empty deletes the whole hooks node.

    The save handler builds the list from POST and, when it is empty, calls
    ``config_del_path('.../hooks')`` -- the node is GONE, not an empty array.

    The empty-list branch fires when no ``hook_*`` rowhelper keys survive. A browser
    hits it by deleting the row (the JS strips its inputs); over HTTP we reproduce
    that by POSTing a payload with NO ``hook_*-N`` keys at all -- so
    ``$rowhelper_exist`` is empty, ``$hooks`` is empty, and the node is deleted.
    Oracle = the node is absent. Restored (already empty) in ``finally``.
    """
    vm = smoke_vm
    helpers.clear_update_hooks(vm)
    _install_test_scripts(vm)
    _seed_one_hook(vm, script=SCRIPT_POST, when="post", enabled="on")
    try:
        # BEFORE: the node exists with the seeded row.
        assert _hooks_node_exists(vm), "seeded hooks node missing before the remove flow"
        assert helpers.config_get(vm, ROW0_SCRIPT) == SCRIPT_POST, "seed script missing before the remove flow"

        # Reproduce a row delete: GET the form for a fresh CSRF token, then POST
        # back ONLY the token + the save button (no hook_*-N fields). The handler
        # finds no rowhelper keys -> empty list -> config_del_path on the node.
        from .webui import extract_csrf_token

        form = webui.get(HOOKS_PAGE)
        assert not looks_like_login_page(form.text), "hooks GET returned the login form (session lost)"
        token = extract_csrf_token(form.text)
        resp = webui.session.post(
            webui.url(HOOKS_PAGE),
            data={"__csrf_magic": token, "save": "save"},
            verify=False,
            timeout=120.0,
        )
        assert not looks_like_login_page(resp.text), "empty-save POST returned the login form"

        # AFTER: the node is gone entirely (config_del_path), not an empty array.
        assert not _hooks_node_exists(vm), "hooks node still present after emptying the list"
    finally:
        helpers.clear_update_hooks(vm)


def test_reject_invalid_script_leaves_config_unchanged(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """An empty or Pre/Post-mismatched script is rejected; config stays unchanged.

    Validator branch (the ADR-12 allow-list gate): ``pfb_hook_script_valid()`` must
    pass for the row's Pre/Post. Two rejects, both leaving the seeded row intact:
      (a) an EMPTY ``hook_script-0`` (no selection);
      (b) a Pre/Post MISMATCH -- a ``hook_pre_*`` file with ``when=post`` (the file
          exists but not for this row's side).
    A green proves the validator blocked the write (the seeded script is STILL there),
    not that the write happened to land the same value. Restored in ``finally``.
    """
    vm = smoke_vm
    helpers.clear_update_hooks(vm)
    _install_test_scripts(vm)
    _seed_one_hook(vm, script=SCRIPT_POST, when="post", enabled="on")
    try:
        # BEFORE: the seeded post script is present.
        assert helpers.config_get(vm, ROW0_SCRIPT) == SCRIPT_POST, "seed script missing before the reject flow"

        # (a) Empty selection -> rejected.
        resp = webui.post(HOOKS_PAGE, {"hook_script-0": ""}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "empty-script POST returned the login form"
        assert _hooks_node_exists(vm), "hooks node deleted by a REJECTED empty-script save"
        assert helpers.config_get(vm, ROW0_SCRIPT) == SCRIPT_POST, (
            f"empty script was NOT rejected -- config changed to {helpers.config_get(vm, ROW0_SCRIPT)!r}"
        )

        # (b) Pre script with when=post (a real file, wrong side) -> rejected.
        resp = webui.post(HOOKS_PAGE, {"hook_script-0": SCRIPT_PRE}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "mismatched-script POST returned the login form"
        assert helpers.config_get(vm, ROW0_SCRIPT) == SCRIPT_POST, (
            f"Pre/Post-mismatched script was NOT rejected -- config changed to {helpers.config_get(vm, ROW0_SCRIPT)!r}"
        )
    finally:
        helpers.clear_update_hooks(vm)


def test_reject_bad_when_leaves_config_unchanged(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A 'When' value outside {pre,post} is rejected; config stays unchanged.

    Validator branch: ``!array_key_exists($value, $options_when)`` -> input error
    -> NO write_config. The select renders only pre/post, so this forces a crafted
    out-of-range value over HTTP. Transition: seed when=post, assert post, POST a
    bogus ``hook_when-0`` -> rejected, so when is STILL post. Restored in
    ``finally``.
    """
    vm = smoke_vm
    helpers.clear_update_hooks(vm)
    _install_test_scripts(vm)
    _seed_one_hook(vm, script=SCRIPT_POST, when="post", enabled="on")
    try:
        # BEFORE: when is post.
        assert helpers.config_get(vm, ROW0_WHEN) == "post", "seed did not store when=post"

        resp = webui.post(HOOKS_PAGE, {"hook_when-0": "sideways"}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "bad-when POST returned the login form"

        # AFTER (reject): when unchanged.
        assert helpers.config_get(vm, ROW0_WHEN) == "post", (
            f"bad 'when' was NOT rejected -- config changed to {helpers.config_get(vm, ROW0_WHEN)!r}"
        )
    finally:
        helpers.clear_update_hooks(vm)
