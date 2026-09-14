"""New DNSBL groups store the 'default' token (issue #3288: live inheritance of
the Global Logging/Blocking Mode -- superseding issue #3285's 'disabled_log'
copy-in-at-creation default). Exercise manual/catalog creation, and prove
existing groups' own choices -- both a concrete explicit mechanism AND an
already-'default' choice -- survive the new-group-default gate untouched.

Legacy-spelling VIP fallback (absent/''/'Enabled') is a two-parameter read
projection, not a single unconditional rule: core ``pfb_dnsbl_group_logging
(mixed $stored, bool $legacy = FALSE)`` maps a normalized VIP to literal
'default' ONLY when the caller passes ``$legacy = $pfb['dnsbl_policy_legacy']``.
That cache field is NOT bare ``dnsbl/global_log_mode`` absence (a genuinely
fresh, never-configured install also has the key absent but is not
"legacy") -- it is populated in ``pfb_global()`` from
``pfb_dnsbl_policy_legacy(array $dconfig, array $groups): bool``, which
additionally inspects whether the install has real pre-existing settings/
groups to distinguish "old release, never touched the override" from
"brand new, nothing configured yet". This test file never asserts that
internal computation directly -- only the OBSERVABLE contract (GET
projection, Save persistence) it produces on an install that is, in every
test below, unambiguously established (a normally-provisioned smoke VM with
real settings, plus seeded groups). Two distinct scenarios follow:

* Marker PRESENT (an ordinary, already-migrated system) with a raw legacy
  byte drifting back into ONE group (a foreign write, not a real migration
  gap): ``$legacy`` is FALSE for that read, so the byte still normalises to
  'enabled', never 'default'. Covered by
  ``test_existing_dnsbl_alias_legacy_spelling_renders_and_resaves_as_vip``.
* Marker ABSENT (a genuinely un-migrated / restored-without-reinstall
  system): ``$legacy`` is TRUE, so a raw legacy group PROJECTS as 'default'
  on GET (read-only -- it does not write). A VALID category_edit.php Save
  (per Main's integration ruling: the shared upgrade facade owns
  cross-section writes, and category_edit.php IS a call site -- Core's
  earlier "per-row Save can't touch global_log_mode so it can't run the
  facade" argument was a page-ownership objection, not a structural one, and
  does not hold: WITHOUT this, a group whose owner explicitly selects VIP
  while still legacy stays projected back to 'default' on the next GET
  (legacy flag never flipped) and a later real migration would silently
  RECONVERT that already-explicit choice, violating the "explicit VIP choice
  is never reconverted" idempotency guarantee) runs the facade FIRST
  (persisting the marker + the old no-override grandfather values) and THEN
  writes the submitted current-schema choice -- ordering that holds whether
  the submitted choice is the rendered 'default' or an explicit concrete
  mechanism. Covered by
  ``test_legacy_group_unchanged_save_migrates_marker_and_persists_default_token``
  and, for the specific counterexample (an explicit VIP choice as the FIRST
  save while still legacy, then re-verified on a fresh GET),
  ``test_legacy_group_explicit_vip_save_migrates_marker_and_survives_next_get``.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import evaluate_render
from .test_category import _php_row_literal
from .test_category_edit import (
    CFG_DNSBL,
    CFG_IPV4,
    _del_rowid,
    _dnsbl_payload,
    _free_rowid,
    _ipv4_payload,
    _post_form,
)
from .webui import looks_like_login_page, scrape_form_fields

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .webui import WebUI

CATEGORY_PAGE = "/pfblockerng/pfblockerng_category_edit.php"
GLOBAL_LOG_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/global_log"
GLOBAL_LOG_MODE_CFG = "installedpackages/pfblockerngdnsblsettings/config/0/global_log_mode"
POST_TIMEOUT = 120.0

# Real, current, shipped catalog entries (pfblockerng_feeds.json) -- the same
# 'ADs_Basic'/'StevenBlack_ADs'/'PRI1' the setup wizard defaults to.
_ADD_DNSBL_PAGE = f"{CATEGORY_PAGE}?type=dnsbl&act=add&atype=StevenBlack_ADs"
_ADDGROUP_DNSBL_PAGE = f"{CATEGORY_PAGE}?type=dnsbl&act=addgroup&atype=ADs_Basic"

# The eight valid, non-inherited-by-migration explicit choices a group's OWN
# 'logging' select can carry: the seven concrete mechanisms PLUS 'default'
# itself (a group can explicitly (re-)select Default; that choice round-trips
# exactly like any other -- it must never be coerced away on an unrelated resave).
_EXPLICIT_CHOICES = (
    "default",
    "enabled",
    "disabled_log",
    "disabled",
    "nxdomain_log",
    "nxdomain",
    "nodata_log",
    "nodata",
)


def _logging_selected(body: str, value: str) -> bool:
    return scrape_form_fields(body).get("logging") == value


def _alias_suffix_for(spelling: str) -> str:
    """A filesystem/aliasname-safe token for a parametrized legacy spelling."""
    return {"absent": "absent", "": "empty", "Enabled": "capital"}[spelling]


@contextlib.contextmanager
def _dnsbl_policy(vm: helpers.SmokeVM, *, mode: str, mechanism: str) -> Iterator[None]:
    """Pin dnsbl/global_log_mode + dnsbl/global_log for the block; restore both after.

    Rendering reads global policy state only through the derived
    $pfb['dnsbl_policy_legacy'] boolean (which pfb_dnsbl_group_logging()
    consumes for its legacy-projection dimension). Pinning global_log_mode to
    a PRESENT value here keeps dnsbl_policy_legacy FALSE, exercising the
    'already migrated' branch these tests target -- distinct from the
    marker-ABSENT scenarios _legacy_no_override_system pins below, where a
    VALID Save on THIS page also runs the upgrade facade and mutates both
    these keys (see test_legacy_group_*).
    """
    mode_state = helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG)
    mechanism_state = helpers.config_get_state(vm, GLOBAL_LOG_CFG)
    try:
        helpers.config_set(vm, GLOBAL_LOG_MODE_CFG, mode)
        helpers.config_set(vm, GLOBAL_LOG_CFG, mechanism)
        yield
    finally:
        helpers.config_restore_state(vm, GLOBAL_LOG_MODE_CFG, mode_state)
        helpers.config_restore_state(vm, GLOBAL_LOG_CFG, mechanism_state)


@contextlib.contextmanager
def _legacy_no_override_system(vm: helpers.SmokeVM) -> Iterator[None]:
    """Force the whole system into the genuinely un-migrated 'old no-global-
    override' state (Main's lifecycle contract): dnsbl/global_log_mode
    ABSENT and dnsbl/global_log at the pre-#3288 empty 'no override' byte.
    Deleting only the marker (not the surrounding real dnsbl settings/
    groups this VM already has from normal provisioning, nor the groups this
    module's own tests seed) is what makes
    ``pfb_dnsbl_policy_legacy($dconfig, $groups)`` read this as genuinely
    "legacy" rather than "freshly installed" -- both look identical at the
    bare marker-absence level, but only an established install with real
    settings/groups is legacy. Restores both keys exactly after, regardless
    of what the block's own Save calls migrate them to.
    """
    mode_state = helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG)
    mechanism_state = helpers.config_get_state(vm, GLOBAL_LOG_CFG)
    try:
        helpers.config_restore_state(vm, GLOBAL_LOG_MODE_CFG, (False, ""))
        helpers.config_set(vm, GLOBAL_LOG_CFG, "")
        yield
    finally:
        helpers.config_restore_state(vm, GLOBAL_LOG_MODE_CFG, mode_state)
        helpers.config_restore_state(vm, GLOBAL_LOG_CFG, mechanism_state)


def _seed_raw_legacy_dnsbl_group(vm: helpers.SmokeVM, rowid: int, aliasname: str) -> None:
    """Directly write ONE DNSBL group config node with NO 'logging' key at all
    (the absent-key legacy spelling) -- bypasses the app entirely so seeding
    itself can never trigger the upgrade facade (a real Save would)."""
    row = {
        "aliasname": aliasname,
        "action": "unbound",
        "cron": "Never",
        "description": "pfBlockerNG smoke #3288 legacy-system group",
    }
    feed = {
        "header": aliasname,
        "url": f"{helpers.PFB_DBDIR}/{aliasname}",
        "state": "Enabled",
        "format": "auto",
    }
    snippet = (
        f"config_set_path({helpers._php_str(f'{CFG_DNSBL}/{rowid}')}, {_php_row_literal(row, feed)});\n"
        "write_config('pfBlockerNG smoke: seed legacy-system DNSBL group');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=POST_TIMEOUT)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_raw_legacy_dnsbl_group failed: rc={result.returncode} {result.stdout!r}")


@contextlib.contextmanager
def _alias_name_parked(vm: helpers.SmokeVM, cfg_root: str, aliasname: str) -> Iterator[None]:
    """Prevent catalog adds from reusing an existing alias; restore its name afterward."""
    pre = (
        f"$c = config_get_path({helpers._php_str(cfg_root)}, array());\n"
        "$rid = null;\n"
        f"foreach ($c as $k => $row) {{ if (($row['aliasname'] ?? null) === {helpers._php_str(aliasname)}) "
        "{ $rid = $k; break; } }\n"
        "$found = ($rid === null) ? '' : (string) $rid;"
    )
    rid = helpers._php_read_scalar(vm, pre, "$found", timeout=60.0)
    parked_path = f"{cfg_root}/{rid}/aliasname" if rid else None
    try:
        if parked_path is not None:
            helpers.config_set(vm, parked_path, aliasname + "__pfb3288_parked")
        yield
    finally:
        if parked_path is not None:
            helpers.config_set(vm, parked_path, aliasname)


# --------------------------------------------------------------------------- #
# Tier A -- render-smoke: every creation route's NEW-group default
# --------------------------------------------------------------------------- #


@pytest.mark.ui_render
def test_add_new_dnsbl_alias_renders_default_selected(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A brand-new DNSBL alias via ``act=add`` (matching a real catalog feed
    header) renders 'Default' selected -- live inheritance of the global
    mechanism, not a concrete value copied in at creation (issue #3288)."""
    with _alias_name_parked(smoke_vm, CFG_DNSBL, "ADs_Basic"):
        resp = webui.get(_ADD_DNSBL_PAGE)
        result = evaluate_render(_ADD_DNSBL_PAGE, resp.status_code, resp.text, ("Override Default Schedule",))
        assert result.ok, f"Tier-A render oracle failed for act=add: {result.detail}"
        assert _logging_selected(resp.text, "default"), (
            "a brand-new DNSBL alias must render Logging/Blocking Mode = 'default' selected (issue #3288)"
        )
        assert not _logging_selected(resp.text, "enabled")
        assert not _logging_selected(resp.text, "disabled_log"), "must not linger on issue #3285's superseded default"


@pytest.mark.ui_render
def test_addgroup_new_dnsbl_alias_renders_default_selected(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A brand-new DNSBL alias via ``act=addgroup`` (Feeds tab) renders the
    same 'default' default."""
    with _alias_name_parked(smoke_vm, CFG_DNSBL, "ADs_Basic"):
        resp = webui.get(_ADDGROUP_DNSBL_PAGE)
        result = evaluate_render(_ADDGROUP_DNSBL_PAGE, resp.status_code, resp.text, ("Override Default Schedule",))
        assert result.ok, f"Tier-A render oracle failed for act=addgroup: {result.detail}"
        assert _logging_selected(resp.text, "default"), (
            "a brand-new DNSBL alias (addgroup/Feeds tab) must render 'default' selected (issue #3288)"
        )
        assert not _logging_selected(resp.text, "enabled")
        assert not _logging_selected(resp.text, "disabled_log")


@pytest.mark.ui_render
def test_manual_new_dnsbl_group_renders_default_selected(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The ORDINARY manual creation route -- the category list's plain "Add"
    button, a bare ``type=dnsbl&rowid=<free>`` GET with NO ``act`` at all
    (pfblockerng_category.php's Add link) -- must ALSO default to 'default',
    not just the Feeds-tab catalog shortcuts."""
    rowid = _free_rowid(smoke_vm, CFG_DNSBL)
    resp = webui.get(CATEGORY_PAGE, params={"type": "dnsbl", "rowid": str(rowid)})
    result = evaluate_render(CATEGORY_PAGE, resp.status_code, resp.text, ("Override Default Schedule",))
    assert result.ok, f"Tier-A render oracle failed for the manual new-group route: {result.detail}"
    assert _logging_selected(resp.text, "default"), (
        "a manually-created (no act=add/addgroup) brand-new DNSBL group must default to 'default' too"
    )
    assert not _logging_selected(resp.text, "enabled")
    assert not _logging_selected(resp.text, "disabled_log")


@pytest.mark.ui_render
def test_addgroup_ipv4_renders_no_logging_select(webui: WebUI) -> None:
    """The 'default' new-group default is confined to DNSBL: an IPv4 addgroup
    page (same mechanism, different type) must render NO logging select at all."""
    page = f"{CATEGORY_PAGE}?type=ipv4&act=addgroup&atype=PRI1"
    resp = webui.get(page)
    result = evaluate_render(page, resp.status_code, resp.text, ("Override Default Schedule",))
    assert result.ok, f"Tier-A render oracle failed for the IPv4 addgroup page: {result.detail}"
    assert 'name="logging"' not in resp.text, "an IPv4 group must never render the DNSBL-only logging select"


# --------------------------------------------------------------------------- #
# Tier B -- real POST: create -> persist, gate holds in storage, preservation
# --------------------------------------------------------------------------- #


@pytest.mark.ui_e2e
def test_add_new_dnsbl_alias_full_save_persists_default(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Save the real form's default, rather than injecting the desired mode."""
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    try:
        with _dnsbl_policy(vm, mode="default", mechanism="enabled"):
            response = webui.get(CATEGORY_PAGE, params={"type": "dnsbl", "rowid": str(rowid)})
            assert response.ok and not looks_like_login_page(response.text), "new-group GET failed"
            selected = scrape_form_fields(response.text)["logging"]
            _post_form(webui, _dnsbl_payload(rowid, "smoke3288add", logging=selected))
            assert helpers.config_get(vm, f"{base}/logging") == "default", (
                "a brand-new DNSBL alias's 'default' default must be accepted and persisted verbatim"
            )
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


@pytest.mark.ui_e2e
def test_addgroup_ipv4_feeds_tab_save_never_writes_a_logging_key(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The gtype gate must hold at the config-storage level, not merely in the
    rendered form: a real IPv4 alias must persist with NO 'logging' key at
    all -- a rendered-select check alone cannot see a stray write the IPv4
    page never displays back."""
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_IPV4)
    base = f"{CFG_IPV4}/{rowid}"
    try:
        _post_form(webui, _ipv4_payload(rowid, "smoke3288ipv4"))
        assert helpers.config_get(vm, f"{base}/aliasname") == "smoke3288ipv4", "the new IPv4 alias did not persist"
        present, _ = helpers.config_get_state(vm, f"{base}/logging")
        assert not present, "an IPv4 group must never gain a logging key, even at the config-storage level"
    finally:
        _del_rowid(vm, CFG_IPV4, rowid)


@pytest.mark.ui_e2e
@pytest.mark.parametrize("choice", _EXPLICIT_CHOICES)
def test_existing_dnsbl_alias_preserves_explicit_choice_on_get_and_resave(
    webui: WebUI, smoke_vm: helpers.SmokeVM, choice: str
) -> None:
    """An EXISTING alias's own explicit Logging/Blocking choice -- including an
    explicit re-selection of 'default' itself -- is untouched by the
    new-group default: create it with `choice`, GET renders it selected, and
    re-saving unchanged still persists exactly `choice`."""
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    try:
        with _dnsbl_policy(vm, mode="default", mechanism="enabled"):
            _post_form(webui, _dnsbl_payload(rowid, f"smoke3288{choice}", logging=choice))
            assert helpers.config_get(vm, f"{base}/logging") == choice

            reload = webui.get(CATEGORY_PAGE, params={"type": "dnsbl", "rowid": str(rowid)})
            assert not looks_like_login_page(reload.text), "reload GET returned the login form"
            assert _logging_selected(reload.text, choice), f"explicit choice {choice!r} must render selected on reload"

            _post_form(webui, _dnsbl_payload(rowid, f"smoke3288{choice}", logging=choice))
            assert helpers.config_get(vm, f"{base}/logging") == choice, (
                f"re-saving an existing alias unchanged must preserve its explicit {choice!r} choice"
            )
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


@pytest.mark.ui_e2e
@pytest.mark.parametrize("spelling", ["absent", "", "Enabled"], ids=["absent-key", "empty-string", "capital-Enabled"])
def test_existing_dnsbl_alias_legacy_spelling_renders_and_resaves_as_vip(
    webui: WebUI, smoke_vm: helpers.SmokeVM, spelling: str
) -> None:
    """Every legacy "no real choice recorded" spelling (a genuinely absent
    key, a stored empty string, or the pre-existing capitalised 'Enabled'
    literal the save fallback itself can write) must still resolve to the
    VIP webserver default on GET, and re-saving unchanged must persist the
    canonical 'enabled' -- never silently pick up the new-group 'default'
    token meant only for brand-new aliases. This runs under
    ``_dnsbl_policy``'s marker-PRESENT (already-migrated) system state --
    ``$pfb['dnsbl_policy_legacy']`` is FALSE here, so
    ``pfb_dnsbl_group_logging()`` never applies the legacy-projection
    dimension: a drifted raw byte on an already-migrated system is NOT the
    same thing as a genuinely-legacy system's group (see
    ``test_legacy_group_get_projects_default_save_persists_per_row_explicit_vip_stays_explicit``
    for that marker-ABSENT scenario)."""
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    try:
        with _dnsbl_policy(vm, mode="default", mechanism="enabled"):
            _post_form(webui, _dnsbl_payload(rowid, f"smoke3288legacy{_alias_suffix_for(spelling)}", logging="enabled"))
            if spelling == "absent":
                result = helpers.php_eval(
                    vm,
                    f"config_del_path({helpers._php_str(f'{base}/logging')}); "
                    "write_config('pfBlockerNG smoke: strip legacy logging key'); echo 'OK';",
                    timeout=POST_TIMEOUT,
                )
                if result.returncode != 0 or "OK" not in result.stdout:
                    raise RuntimeError(f"legacy-key strip failed: rc={result.returncode} {result.stdout!r}")
            else:
                helpers.config_set(vm, f"{base}/logging", spelling)

            reload = webui.get(CATEGORY_PAGE, params={"type": "dnsbl", "rowid": str(rowid)})
            assert not looks_like_login_page(reload.text), "reload GET returned the login form"
            # None of these three spellings is a valid <option value>, so pfSense's
            # Form_Select marks none of them 'selected' explicitly -- the EFFECTIVE
            # value is the select's own first-declared option (browser/page default),
            # which scrape_form_fields resolves identically (its docstring: "the
            # selected option's value, or the first option's when none is marked").
            # This reads ONE field's effective value; it is never used to build a POST.
            effective = scrape_form_fields(reload.text).get("logging")
            assert effective == "enabled", (
                f"legacy spelling {spelling!r} must resolve to the VIP webserver default, got {effective!r}"
            )

            _post_form(webui, _dnsbl_payload(rowid, f"smoke3288legacy{_alias_suffix_for(spelling)}", logging=effective))
            assert helpers.config_get(vm, f"{base}/logging") == "enabled", (
                "re-saving a legacy-spelling alias unchanged must persist the canonical 'enabled', never 'default'"
            )
    finally:
        _del_rowid(vm, CFG_DNSBL, rowid)


@pytest.mark.ui_e2e
def test_legacy_group_unchanged_save_migrates_marker_and_persists_default_token(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """Main's lifecycle contract for a genuinely un-migrated ("old no-global-
    override") system -- dnsbl/global_log_mode ABSENT so
    $pfb['dnsbl_policy_legacy'] === TRUE. A VALID category_edit.php Save runs
    the upgrade facade FIRST (persisting the marker + the old no-override
    grandfather values), THEN writes the submitted current-schema choice --
    category_edit.php IS a facade call site (Main's integration ruling), not
    just dnsbl.php's global-settings page.

    1. A raw legacy group (no 'logging' key at all) is seeded WITHOUT going
       through the app.
    2. GET is READ-ONLY (config byte-identical before/after, including the
       system-wide marker) and PROJECTS 'default' selected --
       pfb_dnsbl_group_logging($stored, legacy: TRUE) maps the normalized VIP
       to 'default' for render only.
    3. An UNCHANGED Save (re-submitting exactly what rendered) runs the
       facade: dnsbl/global_log_mode becomes 'default' and dnsbl/global_log
       becomes 'enabled' (the old no-override grandfather rule) BEFORE the
       submitted current-schema choice ('default') is written for THIS group.
    4. A LATER explicit VIP re-selection persists literally 'enabled' -- POST
       validation never applies the legacy flag, so a deliberate choice is
       never silently coerced back to 'default'.
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    aliasname = "smoke3288legacyunchanged"
    with _legacy_no_override_system(vm):
        try:
            _seed_raw_legacy_dnsbl_group(vm, rowid, aliasname)

            # (2) GET is read-only and PROJECTS 'default'.
            logging_before = helpers.config_get_state(vm, f"{base}/logging")
            mode_before = helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG)
            reload = webui.get(CATEGORY_PAGE, params={"type": "dnsbl", "rowid": str(rowid)})
            assert not looks_like_login_page(reload.text), "reload GET returned the login form"
            assert _logging_selected(reload.text, "default"), (
                "a genuinely legacy (marker-absent) VIP-equivalent group must render 'default' selected"
            )
            assert not _logging_selected(reload.text, "enabled"), (
                "a legacy system must PROJECT 'default', never still show the raw VIP normalization"
            )
            assert helpers.config_get_state(vm, f"{base}/logging") == logging_before, "a GET must never mutate config"
            assert helpers.config_get_state(vm, GLOBAL_LOG_MODE_CFG) == mode_before, "a GET must never migrate"

            # (3) An UNCHANGED Save runs the facade: marker + grandfather values persist,
            # THEN the submitted 'default' choice lands for THIS group.
            selected = scrape_form_fields(reload.text)["logging"]
            _post_form(webui, _dnsbl_payload(rowid, aliasname, logging=selected))
            assert helpers.config_get(vm, GLOBAL_LOG_MODE_CFG) == "default", (
                "a valid category_edit.php Save on a legacy no-override system must run the "
                "upgrade facade -> Default policy"
            )
            assert helpers.config_get(vm, GLOBAL_LOG_CFG) == "enabled", (
                "a valid Save on a legacy no-override system must migrate the shared mechanism to VIP ('enabled')"
            )
            assert helpers.config_get(vm, f"{base}/logging") == "default", (
                "the facade-then-write ordering must land the submitted 'default' choice for this group"
            )

            # (4) A LATER explicit VIP re-selection stays explicit -- no re-projection on POST.
            _post_form(webui, _dnsbl_payload(rowid, aliasname, logging="enabled"))
            assert helpers.config_get(vm, f"{base}/logging") == "enabled", (
                "an explicit VIP re-selection through the current-schema form must persist literally, "
                "never silently coerced back to 'default' by the (by-now-irrelevant) legacy projection"
            )
        finally:
            _del_rowid(vm, CFG_DNSBL, rowid)


@pytest.mark.ui_e2e
def test_legacy_group_explicit_vip_save_migrates_marker_and_survives_next_get(
    webui: WebUI, smoke_vm: helpers.SmokeVM
) -> None:
    """Main's counterexample, proven directly: WITHOUT the facade running on
    the group's own explicit-choice Save, the legacy flag would stay TRUE
    after the user picks VIP, so the NEXT GET would project that fresh
    explicit choice back to 'default' (as if it had never been made) and a
    later real migration would silently RECONVERT it -- violating "an
    explicit VIP choice is never reconverted". The discriminating case is the
    FIRST save on a still-legacy group being the EXPLICIT VIP choice itself
    (not preceded by an 'unchanged/default' save, unlike the sibling test).

    1. A raw legacy group is seeded WITHOUT going through the app; system
       stays legacy (marker absent) through the seed.
    2. The group's FIRST-EVER Save is an EXPLICIT 'enabled' (VIP) choice --
       skipping any 'default' round-trip entirely.
    3. Assert immediately: the facade ran (marker now 'default', shared
       mechanism now 'enabled' -- the grandfather values) AND the group's own
       'logging' is the just-submitted 'enabled', not overwritten by the
       facade's "convert legacy VIP groups to default" migration rule (the
       submitted current-schema choice is written AFTER the facade run).
    4. A FRESH, SEPARATE GET of the same group must STILL render 'enabled'
       selected -- proving the marker flip actually took effect (no residual
       legacy projection re-masking the user's explicit choice as 'Default').
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_DNSBL)
    base = f"{CFG_DNSBL}/{rowid}"
    aliasname = "smoke3288legacyexplicit"
    with _legacy_no_override_system(vm):
        try:
            _seed_raw_legacy_dnsbl_group(vm, rowid, aliasname)

            # (2) The FIRST save on this still-legacy group is the explicit VIP choice.
            _post_form(webui, _dnsbl_payload(rowid, aliasname, logging="enabled"))

            # (3) The facade ran, and the explicit choice was preserved (written AFTER it).
            assert helpers.config_get(vm, GLOBAL_LOG_MODE_CFG) == "default", (
                "an explicit VIP Save on a still-legacy group must ALSO run the upgrade facade -> Default policy "
                "(otherwise the legacy flag never flips and the next GET mis-projects this exact choice)"
            )
            assert helpers.config_get(vm, GLOBAL_LOG_CFG) == "enabled", (
                "the facade must persist the old no-override grandfather shared mechanism ('enabled')"
            )
            assert helpers.config_get(vm, f"{base}/logging") == "enabled", (
                "the group's own explicit 'enabled' choice must survive the facade run -- the facade's "
                "'convert legacy VIP groups to default' rule must not clobber the choice being submitted "
                "in this very request"
            )

            # (4) A FRESH GET still renders the explicit choice -- the marker flip stuck.
            reload = webui.get(CATEGORY_PAGE, params={"type": "dnsbl", "rowid": str(rowid)})
            assert not looks_like_login_page(reload.text), "reload GET returned the login form"
            assert _logging_selected(reload.text, "enabled"), (
                "a fresh GET after the explicit VIP save must still render 'enabled' selected -- if the marker "
                "never flipped, the (by-now-stale) legacy projection would wrongly re-render this as 'default'"
            )
            assert not _logging_selected(reload.text, "default"), (
                "the explicit VIP choice must not be visually reverted to 'default' on the next GET"
            )
        finally:
            _del_rowid(vm, CFG_DNSBL, rowid)


@pytest.mark.ui_e2e
def test_catalog_feed_append_preserves_existing_group_mode(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Adding a feed to an existing group must not apply the new-group default."""
    vm = smoke_vm
    with _alias_name_parked(vm, CFG_DNSBL, "ADs_Basic"), _dnsbl_policy(vm, mode="default", mechanism="enabled"):
        rowid = _free_rowid(vm, CFG_DNSBL)
        try:
            _post_form(webui, _dnsbl_payload(rowid, "ADs_Basic", logging="nxdomain_log"))
            response = webui.get(_ADD_DNSBL_PAGE)
            assert response.ok and not looks_like_login_page(response.text), "catalog append GET failed"
            fields = scrape_form_fields(response.text)
            assert fields["rowid"] == str(rowid), "catalog add must reuse the existing group"
            assert fields["logging"] == "nxdomain_log", "catalog add must preserve the existing group's mode"
        finally:
            _del_rowid(vm, CFG_DNSBL, rowid)
