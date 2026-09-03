"""Tests for scripts/check_toggle_registry.py (issue #2123's regrowth gate).

Both branches per dimension: every case that flags a violation is paired with the
correct form that must stay clean, because a gate that never goes green is as useless
as one that never goes red.

The load-bearing assertions are:

* a NEW `PFB_FILTER_ON_OFF` save into a registered section with no registry entry FAILS
  (RULE 1) -- this is the regrowth the sweep exists to stop;
* a registered field (toggle or plain scalar) whose page still declares its own default FAILS (RULE 2);
* the same shapes are clean once registered / routed through `PfbConfig::read()`;
* the real tree is clean, so the gate is blocking rather than pre-broken;
* a broken registry parse FAILS CLOSED rather than reporting every key unregistered.

The checker is a hyphen-free, underscore-named script under scripts/, so it is
importable directly by path via importlib.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TOOL = _REPO_ROOT / "scripts" / "check_toggle_registry.py"
_spec = importlib.util.spec_from_file_location("check_toggle_registry", _TOOL)
assert _spec is not None and _spec.loader is not None
ctr = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ctr
_spec.loader.exec_module(ctr)

IP_SECTION = "installedpackages/pfblockerngipsettings/config/0"
GLOBAL_SECTION = "installedpackages/pfblockerngglobal"

# A minimal stand-in for the parsed registry: registered (alias, bare key) pairs.
FAKE_KEYS: set[tuple[str, str]] = {
    ("ip", "enable_dup"),
    ("ip", "maxmind_locale"),
    ("global", "alertrefresh"),
}
FAKE_SECTIONS = {IP_SECTION: "ip", GLOBAL_SECTION: "global"}


def _find(text: str, source: str = "pfblockerng_ip.php") -> list[Any]:
    return ctr.find_violations(text, source, FAKE_SECTIONS, FAKE_KEYS)


def _rules(text: str, source: str = "pfblockerng_ip.php") -> list[str]:
    return [v.rule for v in _find(text, source)]


MIRROR = f"$pfb['iconfig'] = PfbConfig::readSection('{IP_SECTION}');\n"


# --------------------------------------------------------------------------- #
# RULE 1 -- an on/off save must name a registered key
# --------------------------------------------------------------------------- #


def test_unregistered_on_off_save_is_flagged() -> None:
    """The regrowth case: a brand-new checkbox save with no registry entry."""
    text = MIRROR + "$pfb['iconfig']['pfb_new_flag'] = pfb_filter($_POST['x'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';\n"
    violations = _find(text)
    assert [v.rule for v in violations] == ["unregistered-toggle"]
    assert "ip/pfb_new_flag" in violations[0].detail


def test_registered_on_off_save_is_clean() -> None:
    """The same shape, registered, must not be flagged -- the gate has a green side."""
    text = MIRROR + "$pfb['iconfig']['enable_dup'] = pfb_filter($_POST['x'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';\n"
    assert _find(text) == []


def test_unregistered_save_wrapped_across_lines_is_still_flagged() -> None:
    """Reformatting a save across lines must not smuggle it past RULE 1."""
    text = MIRROR + (
        "$pfb['iconfig']['pfb_new_flag'] = pfb_filter(\n    $_POST['x'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';\n"
    )
    assert _rules(text) == ["unregistered-toggle"]


def test_save_into_an_unregistered_section_is_out_of_scope() -> None:
    """A mirror whose section has no PFB_SECTIONS alias is foreign, not a violation."""
    text = (
        "$pfb['bconfig'] = PfbConfig::readSection('installedpackages/pfblockerngblacklist');\n"
        "$pfb['bconfig']['whatever'] = pfb_filter($_POST['x'] ?? '', PFB_FILTER_ON_OFF, 'b') ?: '';\n"
    )
    assert _find(text) == []


def test_dynamic_per_row_save_is_out_of_scope() -> None:
    """A per-row config_set_path save is not a section-mirror assignment at all."""
    text = MIRROR + (
        'config_set_path("installedpackages/{$conf_type}/config/{$rowid}/autoaddr_in",\n'
        "    pfb_filter($_POST['autoaddr_in'], PFB_FILTER_ON_OFF, 'Category_edit'));\n"
    )
    assert _find(text) == []


def test_commented_out_save_is_not_flagged() -> None:
    """A save inside a comment is documentation, not code."""
    text = MIRROR + "// $pfb['iconfig']['pfb_new_flag'] = pfb_filter($_POST['x'], PFB_FILTER_ON_OFF, 'ip');\n"
    assert _find(text) == []


# --------------------------------------------------------------------------- #
# RULE 2 -- a registered field's default belongs to the registry
# --------------------------------------------------------------------------- #


def test_page_level_default_for_a_registered_toggle_is_flagged() -> None:
    """The leftover-default case: the registry owns it, the page restates it."""
    text = MIRROR + "$pconfig['enable_dup'] = $pfb['iconfig']['enable_dup'] ?: '';\n"
    violations = _find(text)
    assert [v.rule for v in violations] == ["page-level-default"]
    assert "ip/enable_dup" in violations[0].detail


def test_isset_style_page_level_default_is_flagged() -> None:
    """The other spelling: the 3.2 `isset(...) ? ... : 'on'` fallback."""
    text = (
        f"$pfb['aglobal'] = PfbConfig::readSection('{GLOBAL_SECTION}');\n"
        "$alertrefresh = isset($pfb['aglobal']['alertrefresh']) ? $pfb['aglobal']['alertrefresh'] : 'on';\n"
    )
    assert _rules(text, "pfblockerng_alerts.php") == ["page-level-default"]


def test_gateway_read_is_clean() -> None:
    """Routing the read through PfbConfig::read() is the fixed form."""
    text = MIRROR + "$pconfig['enable_dup'] = PfbConfig::read('ip/enable_dup');\n"
    assert _find(text) == []


def test_registered_plain_scalar_page_default_is_flagged() -> None:
    """issue #2994: RULE 2 covers registered plain scalars, not just toggles.

    The six page/registry divergences were aligned first, so flagging a scalar
    page default no longer pushes a behaviour change through a lint.
    """
    text = MIRROR + "$pconfig['maxmind_locale'] = $pfb['iconfig']['maxmind_locale'] ?: 'en';\n"
    violations = _find(text)
    assert [v.rule for v in violations] == ["page-level-default"]
    assert "ip/maxmind_locale" in violations[0].detail


def test_page_default_for_an_unregistered_key_is_not_rule_twos_business() -> None:
    """Nothing owns the default yet, so restating it is not yet a duplication."""
    text = MIRROR + "$pconfig['ip_placeholder'] = $pfb['iconfig']['ip_placeholder'] ?: '127.1.7.7';\n"
    assert _find(text) == []


def test_the_save_sites_own_transport_normalisation_is_not_a_page_default() -> None:
    """`pfb_filter(...) ?: ''` on the SAVE side is transport, not a default.

    An unchecked checkbox is absent from POST; the `?: ''` there is what turns that
    into the owner-ruled empty Off token, and writeSection() re-normalises it through
    the registered adapter anyway. Flagging it would force every save site to be
    rewritten for no behavioural gain.
    """
    text = (
        MIRROR
        + "$pfb['iconfig']['enable_dup'] = pfb_filter($_POST['enable_dup'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';\n"
    )
    assert _find(text) == []


def test_exempt_entry_suppresses_rule_two(monkeypatch: pytest.MonkeyPatch) -> None:
    """A recorded exemption suppresses the finding; removing it brings it back."""
    text = MIRROR + "$pconfig['enable_dup'] = $pfb['iconfig']['enable_dup'] ?: '';\n"
    assert _rules(text) == ["page-level-default"], "before: the site is flagged"

    monkeypatch.setattr(ctr, "EXEMPT", {("pfblockerng_ip.php", "enable_dup"): "test"})
    assert _find(text) == []


# --------------------------------------------------------------------------- #
# Parsing the real registry
# --------------------------------------------------------------------------- #


def test_registry_parse_finds_every_alias_and_registered_key() -> None:
    """The parse must see all PFB_SECTIONS aliases and the registered keys."""
    text = (_REPO_ROOT / ctr.REGISTRY_FILE).read_text(encoding="utf-8")
    sections = ctr.parse_sections(text)
    keys = ctr.parse_registry_keys(text)

    assert sections[IP_SECTION] == "ip"
    assert sections[GLOBAL_SECTION] == "global"
    assert sections["installedpackages/pfblockerngsync/config/0"] == "sync"
    assert len(keys) >= ctr._MIN_REGISTRY_KEYS

    assert ("ip", "enable_dup") in keys
    assert ("global", "alertrefresh") in keys
    assert ("sync", "syncinterfaces") in keys
    assert ("dnsbl", "autoaddrnot_in") in keys
    assert ("ip", "v4suppression") in keys


def test_every_exempt_row_still_names_a_live_site(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stale exemption is dead weight that hides an already-fixed site -- fail on it."""
    text = (_REPO_ROOT / ctr.REGISTRY_FILE).read_text(encoding="utf-8")
    sections = ctr.parse_sections(text)
    keys = ctr.parse_registry_keys(text)
    recorded = dict(ctr.EXEMPT)

    # Re-scan with the exemptions disabled: what fires is what genuinely needs a row.
    monkeypatch.setattr(ctr, "EXEMPT", {})
    live: set[tuple[str, str]] = set()
    for rel in ctr._git_tracked_pages(_REPO_ROOT):
        page = _REPO_ROOT / rel
        for v in ctr.find_violations(page.read_text(encoding="utf-8"), str(page), sections, keys):
            # detail's first quoted token is '<alias>/<key>'.
            live.add((page.name, v.detail.split("'")[1].split("/", 1)[1]))

    stale = set(recorded) - live
    assert not stale, f"EXEMPT rows no longer needed (delete them): {sorted(stale)}"


def test_scanned_tree_is_clean() -> None:
    """The real sources pass -- this gate blocks, it is not pre-broken."""
    result = subprocess.run(
        [sys.executable, str(_TOOL)],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"the default scan set is not clean:\n{result.stderr}"


def test_self_test_red_canary_passes() -> None:
    """`--self-test` is the gate's own red path; it must report both rules firing."""
    result = subprocess.run(
        [sys.executable, str(_TOOL), "--self-test"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"red canary failed:\n{result.stderr}"
    assert "both rules fired" in result.stdout


def test_broken_registry_parse_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A registry the parser cannot read must exit 2, never 0.

    A gate that reports "clean" because it could not find the registry is worse than
    no gate: it would green a page full of unregistered saves.
    """
    fake_root = tmp_path
    (fake_root / Path(ctr.REGISTRY_FILE).parent).mkdir(parents=True)
    (fake_root / ctr.REGISTRY_FILE).write_text("<?php\n// no registry here\n", encoding="utf-8")
    monkeypatch.setattr(ctr, "__file__", str(fake_root / "scripts" / "check_toggle_registry.py"))

    assert ctr.main([]) == 2


def test_missing_registry_file_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An unreadable registry file must exit 2 as well."""
    monkeypatch.setattr(ctr, "__file__", str(tmp_path / "scripts" / "check_toggle_registry.py"))
    assert ctr.main([]) == 2


def test_exempt_row_does_not_suppress_rule_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exemption is a RULE 2 record, never a licence to skip registration.

    EXEMPT documents a page that still declares a registered toggle's default. Letting
    it also silence RULE 1 would mean one backlog row permanently hides every future
    unregistered save of that key name.
    """
    text = MIRROR + "$pfb['iconfig']['enable_dup'] = pfb_filter($_POST['x'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';\n"
    monkeypatch.setattr(ctr, "EXEMPT", {("pfblockerng_ip.php", "enable_dup"): "test"})
    assert ctr.find_violations(text, "pfblockerng_ip.php", FAKE_SECTIONS, {}) != [], (
        "an exempt row must not suppress the unregistered-toggle rule"
    )


def test_unreadable_explicit_path_fails_closed() -> None:
    """A named page the checker cannot read must exit 2, never 0."""
    assert ctr.main(["src/usr/local/www/pfblockerng/does_not_exist.php"]) == 2


def test_whitespace_between_brackets_does_not_evade_either_rule() -> None:
    """`$pfb ['iconfig'] ['x']` is valid PHP and must not slip past the matchers."""
    mirror = f"$pfb ['iconfig'] = PfbConfig::readSection('{IP_SECTION}');\n"
    save = (
        mirror + "$pfb ['iconfig'] ['pfb_new_flag'] = pfb_filter($_POST['x'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';\n"
    )
    assert _rules(save) == ["unregistered-toggle"]
    read = mirror + "$pconfig['enable_dup'] = $pfb ['iconfig'] ['enable_dup'] ?: '';\n"
    assert _rules(read) == ["page-level-default"]


# --------------------------------------------------------------------------- #
# Issue #2812 -- the recorded RULE 2 backlog is swept, not merely recorded
# --------------------------------------------------------------------------- #


def test_exempt_table_is_empty_after_the_2812_sweep() -> None:
    """Every #2812 residue row was swept, so the recorded backlog ends empty.

    EXEMPT records deliberate, still-live duplication. Once issue #2812 routed the
    seven pre-registered toggle sites through PfbConfig::read(), no duplication is
    deliberate any more and the table must hold no rows: a re-added row would
    re-license a page default the registry owns.
    """
    assert ctr.EXEMPT == {}, (
        "EXEMPT rows remain after issue #2812's sweep "
        f"(route them through PfbConfig::read() and delete them): {sorted(ctr.EXEMPT)}"
    )


def test_scanned_tree_is_clean_with_the_exempt_table_emptied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real sources carry no RULE 2 residue at all -- not one hidden by a row.

    Issue #2812's acceptance clause: with an empty EXEMPT table the gate still
    exits 0, so the sweep is proven against the live tree, not against the
    record of it.
    """
    monkeypatch.setattr(ctr, "EXEMPT", {})
    assert ctr.main([]) == 0, (
        "the scanned tree still carries page-level toggle defaults: issue #2812's sweep is incomplete"
    )


# --------------------------------------------------------------------------- #
# Issue #2994 -- RULE 2 widened to registered plain scalars
# --------------------------------------------------------------------------- #


def test_gateway_read_of_a_plain_scalar_is_clean() -> None:
    """The fixed form for a scalar is the same as for a toggle: PfbConfig::read()."""
    text = MIRROR + "$pconfig['maxmind_locale'] = PfbConfig::read('ip/maxmind_locale');\n"
    assert _find(text) == []


def test_widget_sentinel_after_a_gateway_read_is_not_a_page_default() -> None:
    """`$x = PfbConfig::read(...) ?: 'none'` is widget mapping, not a mirror restatement.

    pfb_dnsvip4/6 store '' and the Form_Select empty option is the token 'none'.
    That mapping must sit on the gateway result, not on `$pfb['dconfig'][...]`.
    """
    text = MIRROR + "$pconfig['maxmind_locale'] = PfbConfig::read('ip/maxmind_locale') ?: 'none';\n"
    assert _find(text) == []


# --------------------------------------------------------------------------- #
# Issue #3087 -- the scan set reaches every tree the contract applies to
# --------------------------------------------------------------------------- #

# The two files the review leg on PR #3084 named, plus the pkg source that turned out
# to carry the residue: each declares a PfbConfig::readSection() mirror, and none of
# them sat under the old `src/usr/local/www/pfblockerng` root.
OUTSIDE_THE_OLD_ROOT = (
    "src/usr/local/www/widgets/widgets/pfblockerng.widget.php",
    "src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc",
    "src/usr/local/pkg/pfblockerng/pfblockerng.inc",
)


def _tracked(*roots: str) -> set[str]:
    """Tracked paths under `roots`, straight from git -- never a memorised list."""
    out = subprocess.run(
        ["git", "ls-files", "-z", *roots],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {p for p in out.split("\0") if p}


def test_default_scan_set_reaches_outside_the_old_www_pfblockerng_root() -> None:
    """The contract is not bounded by a directory, so the scan set must not be either.

    A `PFB_FILTER_ON_OFF` save into a `PfbConfig::readSection()` mirror is written in
    the dashboard widget and in the pkg `.inc` sources exactly as it is on the settings
    pages. While the default root was `src/usr/local/www/pfblockerng`, a green run meant
    "the pages I looked at were clean", not "the contract holds" (issue #3087, the same
    defect #3075 fixed in check_noopener).
    """
    scanned = set(ctr._git_tracked_pages(_REPO_ROOT))
    missing = [p for p in OUTSIDE_THE_OLD_ROOT if p not in scanned]
    assert not missing, f"these do the gated shape but the gate never looks at them: {missing}"


def test_widening_the_scan_set_keeps_every_page_the_old_root_held() -> None:
    """Widening must be a superset: no settings page may drop out of the gate."""
    scanned = set(ctr._git_tracked_pages(_REPO_ROOT))
    old_root_pages = {p for p in _tracked("src/usr/local/www/pfblockerng") if p.endswith(".php")}
    assert old_root_pages, "the old narrow root must still enumerate pages -- the fixture is wrong, not the gate"
    assert old_root_pages <= scanned, f"pages lost from the scan set: {sorted(old_root_pages - scanned)}"


def test_the_pkg_sources_read_registered_fields_through_the_gateway() -> None:
    """RULE 2's subject is the registered field, not the page it is read on.

    `dnsbl/pfb_regex_list`, `dnsbl/pfb_noaaaa_list`, `dnsbl/pfb_gp_bypass_list` and
    `gen/pfb_log_trim_margin_pct` are all in `pfb_cfg_registry()`, and pfb_global() /
    pfb_log_mgmt() read them off the section mirror with their own `?? ''` fallback --
    a page-level default on a registered field, in a file the old root excluded.
    """
    pkg_sources = sorted(p for p in _tracked("src/usr/local/pkg") if p.endswith((".php", ".inc", ".xml")))
    assert pkg_sources, "no pkg sources enumerated -- the fixture is wrong, not the gate"
    result = subprocess.run(
        [sys.executable, str(_TOOL), *pkg_sources],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"src/usr/local/pkg restates a registered field's default:\n{result.stderr}"


def test_empty_default_scan_set_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A scan set that enumerates nothing must exit 2, never 0.

    This is the failure the widening exists to prevent, one level down: a gate that
    reports clean because it silently looked at no files is the same lie as a gate
    whose root is narrower than the surface it protects.
    """
    monkeypatch.setattr(ctr, "_git_tracked_pages", lambda _root: [])
    assert ctr.main([]) == 2


# --------------------------------------------------------------------------- #
# Issue #3087 -- adversarial rows for the widened surface
# --------------------------------------------------------------------------- #


def test_read_wrapped_across_lines_is_still_flagged() -> None:
    """Reformatting a read over two physical lines must not smuggle it past RULE 2."""
    text = MIRROR + "$pconfig['enable_dup'] =\n\t$pfb['iconfig']['enable_dup'] ?? '';\n"
    assert _rules(text) == ["page-level-default"]


def test_read_inside_a_comment_is_not_flagged() -> None:
    """A read quoted in prose is documentation, not code.

    The pkg `.inc` sources the widened set now covers are heavily commented, including
    docblock lines that quote the very shape RULE 2 forbids.
    """
    for comment in (
        "// $pconfig['enable_dup'] = $pfb['iconfig']['enable_dup'] ?? '';\n",
        "/* $pconfig['enable_dup'] = $pfb['iconfig']['enable_dup'] ?? ''; */\n",
        " * $pconfig['enable_dup'] = $pfb['iconfig']['enable_dup'] ?? '';\n",
    ):
        assert _find(MIRROR + comment) == [], f"a commented read must not flag: {comment!r}"


def test_a_key_sharing_a_registered_prefix_is_not_matched() -> None:
    """The registry lookup is on the whole key, never a substring of one.

    `enable_dup_extra` is unregistered and `enable_du` is not a key at all; matching
    either against the registered `enable_dup` would flag a site the registry does not
    own -- and, in the RULE 1 direction, would green one it does.
    """
    for key in ("enable_dup_extra", "enable_du"):
        text = MIRROR + f"$pconfig['x'] = $pfb['iconfig']['{key}'] ?? '';\n"
        assert _find(text) == [], f"{key} is not the registered enable_dup"


# --------------------------------------------------------------------------- #
# Issue #3136 -- hyphenated keys are seen; the widget-* namespace is foreign
# --------------------------------------------------------------------------- #

# The dashboard widget's own mirror: `wglobal` resolves to the registered `global`
# section, but its `widget-*` keys are a deliberately-foreign namespace (the widget
# marks each in-code: "foreign key: ... not in registry").
WGLOBAL_MIRROR = f"$pfb['wglobal'] = PfbConfig::readSection('{GLOBAL_SECTION}');\n"


def test_foreign_widget_prefix_save_is_not_flagged() -> None:
    """The widget's real shape: a `global/widget-*` PFB_FILTER_ON_OFF save is a
    foreign key-namespace inside a registered section, so RULE 1 must not flag it --
    the same out-of-scope disposition a foreign section already gets. This is red at
    the 4a-only intermediate (the widened matcher would flag it) and green once the
    foreign-prefix classification lands.
    """
    text = (
        WGLOBAL_MIRROR
        + "$pfb['wglobal']['widget-popup'] = pfb_filter($_POST['pfb_popup'] ?? '', PFB_FILTER_ON_OFF, 'widget');\n"
    )
    assert _find(text, "pfblockerng.widget.php") == []


def test_hyphenated_key_outside_the_foreign_namespace_is_still_flagged() -> None:
    """Anti-vacuity: widening the key group so hyphens are seen must NOT blanket-
    silence every hyphenated key. A hyphenated key doing the registry-governed save
    shape, in a registered section outside any foreign namespace, still fires RULE 1.
    Red until the key group is widened (the current `\\w+` group cannot see it).
    """
    text = MIRROR + "$pfb['iconfig']['pfb-new-flag'] = pfb_filter($_POST['x'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';\n"
    violations = _find(text)
    assert [v.rule for v in violations] == ["unregistered-toggle"]
    assert "ip/pfb-new-flag" in violations[0].detail


def test_foreign_prefix_is_a_boundary_not_a_substring() -> None:
    """`widgetx-foo` shares the letters but not the `widget-` prefix boundary, so the
    exemption is a prefix match, not a loose substring: it still fires RULE 1.
    """
    text = (
        WGLOBAL_MIRROR
        + "$pfb['wglobal']['widgetx-foo'] = pfb_filter($_POST['x'] ?? '', PFB_FILTER_ON_OFF, 'widget');\n"
    )
    violations = _find(text, "pfblockerng.widget.php")
    assert [v.rule for v in violations] == ["unregistered-toggle"]
    assert "global/widgetx-foo" in violations[0].detail


def test_widget_prefix_in_an_unregistered_section_is_foreign_via_missing_alias() -> None:
    """A `widget-` key in a section with no PFB_SECTIONS alias is already foreign
    through the missing-alias branch -- the prefix rule is not what saves it, so the
    two foreign dispositions do not overlap or mask each other.
    """
    text = (
        "$pfb['bconfig'] = PfbConfig::readSection('installedpackages/pfblockerngblacklist');\n"
        "$pfb['bconfig']['widget-popup'] = pfb_filter($_POST['x'] ?? '', PFB_FILTER_ON_OFF, 'b') ?: '';\n"
    )
    assert _find(text, "pfblockerng.widget.php") == []
