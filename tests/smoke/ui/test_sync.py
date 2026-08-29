"""Tier-B functional WebUI flows for the XMLRPC config-sync page (ADR-14).

Page under test: ``pfblockerng_sync.php`` (Firewall > pfBlockerNG > Sync). This
file establishes that the page's CSRF save handler -- its scalar settings, its
``repeatable`` Replication-Target rowhelper, its undefined-row prune, and its
field validators -- all change (or correctly REFUSE to change) the box's
EFFECTIVE state. As elsewhere in the Tier-B suite, the oracle is ``config.xml``
read over SSH (:func:`tests.smoke.helpers.config_get`), NEVER the HTTP response
body: a 200 / a post-redirect page does not prove the save took; re-reading the
config node does.

Save-handler facts read END TO END from ``pfblockerng_sync.php`` (the assertions
below depend on these; they are not guessed):

* The handler runs only under ``isset($_POST['save'])`` and writes the sync
  config under ``installedpackages/pfblockerngsync/config/0``: the scalars
  ``varsynconchanges`` / ``varsynctimeout`` / ``syncinterfaces`` and a per-target
  row map ``row/<index>/<field>`` (fields ``varsyncprotocol`` /
  ``varsyncipaddress`` / ``varsyncport`` / ``varsyncusername`` /
  ``varsyncpassword`` / ``varsyncdestinenable``).
* ROWHELPER NAMING (the ``.addClass('repeatable')`` rowhelper): every per-row
  control is named ``<field>-<index>`` (e.g. ``varsyncipaddress-0``). The handler
  finds rows by scanning every POST key containing ``-`` and splitting on it, so a
  row is POSTed by sending its ``<field>-<index>`` inputs; an index that appears in
  ANY ``<field>-<index>`` key is recorded as "present".
* UNDEFINED-ROW PRUNE: after the field loop, every ``row`` index in config that
  was NOT present in the POST is ``config_del_path``'d -- so omitting a row's
  fields from the POST deletes that row.
* VALIDATION + the WRITE GATE: a bad port (``!is_port``), a bad protocol, an
  invalid/too-long username, or an invalid hostname appends an ``$input_errors``
  entry. The per-row ``config_set_path`` calls run on the IN-MEMORY config
  regardless, but ``write_config()`` is called ONLY inside ``if (!$input_errors)``
  -- so on ANY validation error NOTHING is persisted to ``config.xml``. The oracle
  (a fresh ``pfSsh.php`` reading ``/conf/config.xml``) therefore sees the
  pre-POST state unchanged on a reject, which is exactly what the reject cases
  assert.

Every flow is a TRUE transition test (CLAUDE.md): it seeds + asserts the BEFORE
state, drives the CSRF POST, asserts the AFTER state via the config.xml oracle,
then RESETS the sync config node to a FIXED, deterministic baseline in
``finally`` (:func:`_seed_sync` -- disabled/150/no rows; NOT a snapshot of
whatever was there before the test) so a mid-test failure cannot poison Tier A
or the other flows. Every flow calls the same ``_seed_sync`` both before and
after, so no flow depends on -- or needs to restore -- another's leftover
CFG_SYNC state.

This page is a plain form handler gating on the ``save`` button, but its rendered
form ALWAYS includes a placeholder Target row whose empty ``varsyncipaddress-0``
would itself be rejected by the hostname validator when re-submitted -- so these
flows do NOT use the field-scraping :meth:`WebUI.post`; they POST a fully
controlled payload directly (GET the page, pull the fresh ``__csrf_magic`` token,
send exactly the fields under test) so each branch is exercised in isolation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

SYNC_PAGE = "/pfblockerng/pfblockerng_sync.php"
# The sync config root and the scalar/row paths the save handler writes.
CFG_SYNC = "installedpackages/pfblockerngsync/config/0"
CFG_SYNC_MODE = f"{CFG_SYNC}/varsynconchanges"
CFG_SYNC_TIMEOUT = f"{CFG_SYNC}/varsynctimeout"
CFG_SYNC_IFACE = f"{CFG_SYNC}/syncinterfaces"


def _row_path(index: int, field: str) -> str:
    """config.xml path of a Replication-Target row field (``row/<i>/<field>``)."""
    return f"{CFG_SYNC}/row/{index}/{field}"


def _post_sync(webui: WebUI, payload: dict[str, str], *, timeout: float = 120.0) -> str:
    """GET the Sync page, attach its fresh CSRF token + ``save``, POST ``payload``.

    The handler gates on ``isset($_POST['save'])``, so the save button is added
    here; the ``__csrf_magic`` token is re-extracted from the freshly-GET'd form
    (the csrf-magic output filter injects a new one per render -- it must never be
    cached). ``payload`` is the EXACT controlled field set under test (no field
    scraping): only keys present are seen by the handler, so omitting all
    ``<field>-<index>`` keys exercises the undefined-row prune deterministically.
    Returns the POST response body for the login-bounce sanity check (NOT the
    oracle -- the caller asserts config.xml).
    """
    form = webui.get(SYNC_PAGE)
    assert not looks_like_login_page(form.text), "GET of the Sync page returned the login form (session lost)"
    token = extract_csrf_token(form.text)
    data = {"__csrf_magic": token, "save": "save"}
    data.update(payload)
    # The WebUI client passes verify per-request, not on the session; mirror its
    # rule for a direct POST -- a self-signed HTTPS throwaway image is driven with
    # verify=False, plain HTTP needs no TLS verification. base_url is public.
    verify = not webui.base_url.startswith("https://")
    resp = webui.session.post(
        webui.url(SYNC_PAGE),
        data=data,
        verify=verify,
        timeout=timeout,
        allow_redirects=True,
    )
    assert not looks_like_login_page(resp.text), "Sync POST returned the login form (session lost)"
    return resp.text


def _seed_sync(vm: helpers.SmokeVM, *, timeout: float = 60.0) -> None:
    """Reset the sync config to a known pristine baseline (no targets, defaults).

    Writes ``varsynconchanges='disabled'``, ``varsynctimeout='150'`` and DELETES
    any ``row`` node, so each transition test starts from the same before-state
    regardless of what a sibling flow left behind.
    """
    snippet = (
        f"$c = config_get_path({helpers._php_str(CFG_SYNC)}, array());\n"
        "$c['varsynconchanges'] = 'disabled';\n"
        "$c['varsynctimeout'] = '150';\n"
        "$c['syncinterfaces'] = '';\n"
        "unset($c['row']);\n"
        f"config_set_path({helpers._php_str(CFG_SYNC)}, $c);\n"
        "write_config('pfBlockerNG smoke: seed sync baseline');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_sync failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


def _seed_row(vm: helpers.SmokeVM, index: int, row: dict[str, str], *, timeout: float = 60.0) -> None:
    """Persist a single Replication-Target ``row/<index>`` via the config API.

    Used to establish a BEFORE-state row that a subsequent POST must prune /
    leave untouched -- written through the same ``config_set_path`` path the GUI
    save handler uses, then ``write_config``'d so the config.xml oracle sees it.
    """
    # Build the row in one assoc write so a partial seed can't leave a half row.
    snippet = (
        f"config_set_path({helpers._php_str(f'{CFG_SYNC}/row/{index}')}, {helpers._php_kv_array(row)});\n"
        "write_config('pfBlockerNG smoke: seed sync target row');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=timeout)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_row failed: rc={result.returncode} {result.stderr!r} {result.stdout!r}")


# --------------------------------------------------------------------------- #
# 1) Scalar settings save -- timeout (sanitised numeric) + sync mode (select).
# --------------------------------------------------------------------------- #


def test_sync_timeout_scalar_round_trip(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A valid XMLRPC-timeout POST changes config.xml; the original is restored.

    True transition: assert the seeded baseline (150), POST 300 and assert
    config.xml holds 300, then POST 150 and assert it returned -- so the green
    proves each POST CAUSED its change. ``varsynctimeout`` is sanitised by
    ``pfb_filter(..., PFB_FILTER_NUM, 150)`` then ``min(5000, ...)``, so a clean
    in-range integer stores verbatim.
    """
    vm = smoke_vm
    _seed_sync(vm)
    try:
        assert helpers.config_get(vm, CFG_SYNC_TIMEOUT) == "150", "seeded timeout baseline not 150"

        _post_sync(webui, {"varsynconchanges": "disabled", "varsynctimeout": "300", "syncinterfaces": ""})
        assert helpers.config_get(vm, CFG_SYNC_TIMEOUT) == "300", "timeout 300 not persisted to config.xml"

        _post_sync(webui, {"varsynconchanges": "disabled", "varsynctimeout": "150", "syncinterfaces": ""})
        assert helpers.config_get(vm, CFG_SYNC_TIMEOUT) == "150", "timeout did not return to 150"
    finally:
        _seed_sync(vm)


def test_sync_timeout_clamped_to_max(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """An over-range timeout is CLAMPED to 5000 (the ``min(5000, ...)`` branch).

    Distinct from the verbatim path: BEFORE is 150, a POST of 99999 stores 5000
    (not 99999, not 150) -- proving the clamp is a real branch, not a reject. The
    value is sanitised in place, so config.xml DOES change (no input error).
    """
    vm = smoke_vm
    _seed_sync(vm)
    try:
        assert helpers.config_get(vm, CFG_SYNC_TIMEOUT) == "150", "seeded timeout baseline not 150"

        _post_sync(webui, {"varsynconchanges": "disabled", "varsynctimeout": "99999", "syncinterfaces": ""})
        assert helpers.config_get(vm, CFG_SYNC_TIMEOUT) == "5000", "over-range timeout not clamped to 5000"
    finally:
        _seed_sync(vm)


def test_sync_mode_select_valid_and_normalised(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The sync-mode SELECT stores a valid option and NORMALISES an invalid one.

    Branch coverage of the select validator
    (``array_key_exists($_POST[$opt], $options_$opt)``):

    * VALID branch -- BEFORE 'disabled', POST 'manual' -> config.xml holds
      'manual'; the reverse POST restores 'disabled'. Both directions exercised.
    * NORMALISE branch -- an option not in {disabled, auto, manual} is silently
      reset to '' (NOT an input error): BEFORE 'manual', POST 'bogus' -> config
      holds '' (proving the reset path), not 'bogus' and not 'manual'.

    ``syncinterfaces`` is sent empty and ``varsynctimeout`` at its baseline so the
    only delta is the select; no target rows are posted, so the empty-IP
    placeholder cannot trip the hostname validator.
    """
    vm = smoke_vm
    _seed_sync(vm)
    try:
        assert helpers.config_get(vm, CFG_SYNC_MODE) == "disabled", "seeded mode baseline not 'disabled'"

        # VALID: drive to 'manual'.
        _post_sync(webui, {"varsynconchanges": "manual", "varsynctimeout": "150", "syncinterfaces": ""})
        assert helpers.config_get(vm, CFG_SYNC_MODE) == "manual", "valid select value 'manual' not persisted"

        # Reverse VALID: back to 'disabled'.
        _post_sync(webui, {"varsynconchanges": "disabled", "varsynctimeout": "150", "syncinterfaces": ""})
        assert helpers.config_get(vm, CFG_SYNC_MODE) == "disabled", "select did not return to 'disabled'"

        # NORMALISE: an out-of-set value is reset to '' (re-seed to 'manual' first
        # so the change away from a NON-empty value is observable).
        _post_sync(webui, {"varsynconchanges": "manual", "varsynctimeout": "150", "syncinterfaces": ""})
        assert helpers.config_get(vm, CFG_SYNC_MODE) == "manual", "pre-normalise seed to 'manual' failed"
        _post_sync(webui, {"varsynconchanges": "bogus", "varsynctimeout": "150", "syncinterfaces": ""})
        assert helpers.config_get(vm, CFG_SYNC_MODE) == "", "invalid select value not normalised to ''"
    finally:
        _seed_sync(vm)


def test_sync_disable_interfaces_checkbox_toggle(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The 'Disable tab settings sync' checkbox stores 'on' and clears, both ways.

    ``syncinterfaces`` is a PFB_FILTER_ON_OFF checkbox: present+``on`` -> 'on',
    absent (a browser omits an unchecked box) -> ''. BEFORE '', POST with the box
    -> 'on'; POST without it -> '' again. Both branches of the toggle exercised.
    """
    vm = smoke_vm
    _seed_sync(vm)
    try:
        assert helpers.config_get(vm, CFG_SYNC_IFACE) == "", "seeded syncinterfaces baseline not empty"

        _post_sync(webui, {"varsynconchanges": "disabled", "varsynctimeout": "150", "syncinterfaces": "on"})
        assert helpers.config_get(vm, CFG_SYNC_IFACE) == "on", "checkbox 'on' not persisted"

        # Omit the field entirely -- a browser sends nothing for an unchecked box.
        _post_sync(webui, {"varsynconchanges": "disabled", "varsynctimeout": "150"})
        assert helpers.config_get(vm, CFG_SYNC_IFACE) == "", "checkbox did not clear when omitted"
    finally:
        _seed_sync(vm)


# --------------------------------------------------------------------------- #
# 2) Replication-Target rowhelper -- add a valid row, then it persists.
# --------------------------------------------------------------------------- #


def test_sync_target_row_add_persists(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Adding a valid Target row (``<field>-0`` rowhelper keys) persists it.

    True transition: BEFORE there is no ``row/0`` (seeded clean), POST a full
    valid row at index 0, then assert EACH field landed under
    ``row/0/<field>`` in config.xml. Then prune it (POST with no row keys) and
    assert the row is gone -- both the add and the remove direction.

    Field naming assumption (read from the PHP rowhelper): per-row controls are
    ``varsync<field>-<index>``; the handler splits on the LAST?... it uses
    ``explode('-', $key)`` taking element [0]=field, [1]=index, so the index must
    be an integer with no extra ``-`` in the field name (true for these names).
    The hostname must pass ``is_hostname`` and the port ``is_port``, so a plain
    label host and a 1..65535 port are used. ``varsynconchanges='manual'`` so the
    target row is the configured-target mode (not strictly required for the row
    to persist, but matches the UI path).
    """
    vm = smoke_vm
    _seed_sync(vm)
    host = helpers.unique_domain("synctarget").split(".")[0] + ".example-sync.com"
    row = {
        "varsyncprotocol-0": "https",
        "varsyncipaddress-0": host,
        "varsyncport-0": "8443",
        "varsyncusername-0": "syncuser",
        # Special characters (& " ' < >) pin issue #339: the password must persist
        # verbatim, NOT HTML-escaped. The pre-fix code stored htmlspecialchars() of
        # this (P@ss&amp;w&quot;o&#039;rd&lt;x&gt;), which broke XMLRPC auth.
        "varsyncpassword-0": "P@ss&w\"o'rd<x>",
        "varsyncdestinenable-0": "on",
    }
    try:
        assert helpers.config_get(vm, _row_path(0, "varsyncipaddress")) == "", "row/0 already present before add"

        _post_sync(webui, {"varsynconchanges": "manual", "varsynctimeout": "150", "syncinterfaces": "", **row})

        assert helpers.config_get(vm, _row_path(0, "varsyncprotocol")) == "https", "row protocol not persisted"
        assert helpers.config_get(vm, _row_path(0, "varsyncipaddress")) == host, "row hostname not persisted"
        assert helpers.config_get(vm, _row_path(0, "varsyncport")) == "8443", "row port not persisted"
        assert helpers.config_get(vm, _row_path(0, "varsyncusername")) == "syncuser", "row username not persisted"
        assert helpers.config_get(vm, _row_path(0, "varsyncpassword")) == "P@ss&w\"o'rd<x>", (
            "row password not persisted verbatim (issue #339: must not be HTML-escaped)"
        )
        assert helpers.config_get(vm, _row_path(0, "varsyncdestinenable")) == "on", "row enable flag not persisted"

        # Off-branch (CLAUDE.md branch coverage): re-post the SAME row WITHOUT the
        # enable checkbox (a browser omits an unchecked box). The per-row resolver
        # stores the canonical '' so the enable flag's OTHER state also persists --
        # the target is now disabled (never synced), not left at the stale 'on'.
        _post_sync(
            webui,
            {
                "varsynconchanges": "manual",
                "varsynctimeout": "150",
                "syncinterfaces": "",
                **{k: v for k, v in row.items() if k != "varsyncdestinenable-0"},
            },
        )
        assert helpers.config_get(vm, _row_path(0, "varsyncdestinenable")) == "", (
            "row enable flag not cleared to '' when the checkbox is omitted"
        )
        assert helpers.config_get(vm, _row_path(0, "varsyncipaddress")) == host, (
            "row hostname lost on the disable re-post"
        )

        # Reverse: omit the row keys -> the undefined-row prune deletes row/0.
        _post_sync(webui, {"varsynconchanges": "manual", "varsynctimeout": "150", "syncinterfaces": ""})
        assert helpers.config_get(vm, _row_path(0, "varsyncipaddress")) == "", "row/0 not pruned after omission"
    finally:
        _seed_sync(vm)


def test_sync_free_text_row_fields_sanitize_before_validation_and_persist(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """Free-text target columns sanitize once before validation and storage.

    The hostname and username arrive with Unicode boundary whitespace that their
    validators reject unless ingestion sanitization runs first. The password
    carries a Unicode format control plus HTML-special characters: only the
    control is removed, while the credential's remaining bytes persist verbatim.
    """
    vm = smoke_vm
    _seed_sync(vm)
    try:
        assert helpers.config_get(vm, _row_path(0, "varsyncipaddress")) == "", "row/0 already present"

        _post_sync(
            webui,
            {
                "varsynconchanges": "manual",
                "varsynctimeout": "150",
                "syncinterfaces": "",
                "varsyncprotocol-0": "https",
                "varsyncipaddress-0": " example.com ",
                "varsyncport-0": "443",
                "varsyncusername-0": "\u3000syncuser\u00a0",
                "varsyncpassword-0": "P@ss&\u200dword<>'",
                "varsyncdestinenable-0": "on",
            },
        )

        assert helpers.config_get(vm, _row_path(0, "varsyncipaddress")) == "example.com"
        assert helpers.config_get(vm, _row_path(0, "varsyncusername")) == "syncuser"
        assert helpers.config_get(vm, _row_path(0, "varsyncpassword")) == "P@ss&word<>'"
    finally:
        _seed_sync(vm)


# --------------------------------------------------------------------------- #
# 3) Undefined/empty-row prune -- a config row absent from the POST is deleted.
# --------------------------------------------------------------------------- #


def test_sync_undefined_row_pruned_on_save(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A pre-existing row NOT present in the POST is ``config_del_path``'d.

    Seed ``row/0`` directly via the config API (BEFORE-state: the row exists),
    assert it, then drive a VALID save whose payload contains NO ``<field>-0``
    keys. The handler's prune loop deletes every config row index not seen in the
    POST, so ``row/0`` must be gone afterwards while the scalar save still lands
    (proving the save ran, not that it silently no-op'd). The save carries a valid
    scalar change (timeout 250) so a green also proves write_config executed.
    """
    vm = smoke_vm
    _seed_sync(vm)
    seeded = {
        "varsyncprotocol": "https",
        "varsyncipaddress": "stale-target.example-sync.com",
        "varsyncport": "443",
        "varsyncusername": "admin",
        "varsyncpassword": "x",
        "varsyncdestinenable": "on",
    }
    _seed_row(vm, 0, seeded)
    try:
        assert helpers.config_get(vm, _row_path(0, "varsyncipaddress")) == seeded["varsyncipaddress"], (
            "seeded row/0 not present before the prune POST"
        )

        # POST with NO row keys -> prune row/0; a scalar delta proves the save ran.
        _post_sync(webui, {"varsynconchanges": "manual", "varsynctimeout": "250", "syncinterfaces": ""})

        assert helpers.config_get(vm, _row_path(0, "varsyncipaddress")) == "", "undefined row/0 not pruned"
        assert helpers.config_get(vm, CFG_SYNC_TIMEOUT) == "250", "scalar save did not run alongside the prune"
    finally:
        _seed_sync(vm)


# --------------------------------------------------------------------------- #
# 4) Validation reject -- a bad row aborts write_config; config stays unchanged.
# --------------------------------------------------------------------------- #


def test_sync_bad_port_rejected_config_unchanged(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A row with an out-of-range port is rejected; NOTHING is persisted.

    ``varsyncport`` is validated by ``is_port``; 99999 fails, so ``$input_errors``
    is set and ``write_config()`` (gated on ``!$input_errors``) never runs. The
    per-row ``config_set_path`` calls mutate only the IN-MEMORY config of that
    request, so a fresh config.xml read sees the UNCHANGED before-state.

    True transition with a paired VALID control so the reject is proven a real
    branch (CLAUDE.md): first POST the SAME row with a VALID port (8443) and
    assert it persisted (the change happens), then POST the bad-port row and
    assert the scalar AND the row are untouched from that valid state -- i.e. the
    bad POST caused NO write, rather than the expected end-state already holding.
    """
    vm = smoke_vm
    _seed_sync(vm)
    host = "valid-target.example-sync.com"
    base = {
        "varsynconchanges": "manual",
        "syncinterfaces": "",
        "varsyncprotocol-0": "https",
        "varsyncipaddress-0": host,
        "varsyncusername-0": "syncuser",
        "varsyncpassword-0": "syncsecret",
        "varsyncdestinenable-0": "on",
    }
    try:
        # Establish a known-good persisted state first (the VALID control).
        _post_sync(webui, {**base, "varsynctimeout": "200", "varsyncport-0": "8443"})
        assert helpers.config_get(vm, _row_path(0, "varsyncport")) == "8443", "valid control row not persisted"
        assert helpers.config_get(vm, CFG_SYNC_TIMEOUT) == "200", "valid control timeout not persisted"

        # REJECT: bad port + a would-be scalar change. write_config must NOT run,
        # so both the port and the timeout stay at the valid-control values.
        _post_sync(webui, {**base, "varsynctimeout": "1234", "varsyncport-0": "99999"})
        assert helpers.config_get(vm, _row_path(0, "varsyncport")) == "8443", (
            "bad-port POST altered config.xml (write_config should be gated on no input errors)"
        )
        assert helpers.config_get(vm, CFG_SYNC_TIMEOUT) == "200", (
            "bad-port POST persisted a scalar change despite the validation error"
        )
    finally:
        _seed_sync(vm)


def test_sync_bad_username_rejected_config_unchanged(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A row with an invalid-character username is rejected; nothing persists.

    Second validator branch: ``varsyncusername`` rejects on
    ``preg_match('/[^a-zA-Z0-9._-]/', $value)`` (and on length > 16). A username
    containing a space fails, so ``write_config`` is gated off and config.xml is
    unchanged. Paired with a valid control (a clean username persists) so the
    reject is a proven branch, not an always-unchanged path.
    """
    vm = smoke_vm
    _seed_sync(vm)
    host = "valid-target.example-sync.com"
    base = {
        "varsynconchanges": "manual",
        "syncinterfaces": "",
        "varsyncprotocol-0": "https",
        "varsyncipaddress-0": host,
        "varsyncport-0": "8443",
        "varsyncpassword-0": "syncsecret",
        "varsyncdestinenable-0": "on",
    }
    try:
        # VALID control: a clean username persists.
        _post_sync(webui, {**base, "varsynctimeout": "210", "varsyncusername-0": "gooduser"})
        assert helpers.config_get(vm, _row_path(0, "varsyncusername")) == "gooduser", "valid username not persisted"
        assert helpers.config_get(vm, CFG_SYNC_TIMEOUT) == "210", "valid control timeout not persisted"

        # REJECT: a space is an invalid username character -> input error -> no write.
        _post_sync(webui, {**base, "varsynctimeout": "1357", "varsyncusername-0": "bad user"})
        assert helpers.config_get(vm, _row_path(0, "varsyncusername")) == "gooduser", (
            "invalid username altered config.xml (write_config should be gated on no input errors)"
        )
        assert helpers.config_get(vm, CFG_SYNC_TIMEOUT) == "210", (
            "invalid-username POST persisted a scalar change despite the validation error"
        )
    finally:
        _seed_sync(vm)
