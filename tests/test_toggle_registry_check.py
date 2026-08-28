"""Tests for scripts/check_toggle_registry.py (issue #2123's regrowth gate).

Both branches per dimension: every case that flags a violation is paired with the
correct form that must stay clean, because a gate that never goes green is as useless
as one that never goes red.

The load-bearing assertions are:

* a NEW `PFB_FILTER_ON_OFF` save into a registered section with no registry entry FAILS
  (RULE 1) -- this is the regrowth the sweep exists to stop;
* a registered TOGGLE whose page still declares its own default FAILS (RULE 2);
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

# A minimal stand-in for the parsed registry: (alias, bare key) -> is-a-toggle.
FAKE_KEYS: dict[tuple[str, str], bool] = {
    ("ip", "enable_dup"): True,
    ("ip", "maxmind_locale"): False,
    ("global", "alertrefresh"): True,
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
# RULE 2 -- a registered toggle's default belongs to the registry
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


def test_registered_plain_scalar_page_default_is_not_rule_twos_business() -> None:
    """RULE 2 is toggle-scoped: a plain scalar's page default is issue #2812's backlog.

    Several of those page defaults genuinely disagree with their registry entry, so
    flagging them here would push a behaviour change through a lint.
    """
    text = MIRROR + "$pconfig['maxmind_locale'] = $pfb['iconfig']['maxmind_locale'] ?: 'en';\n"
    assert _find(text) == []


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


def test_registry_parse_finds_every_alias_and_the_toggle_entries() -> None:
    """The parse must see all PFB_SECTIONS aliases and mark toggles as toggles."""
    text = (_REPO_ROOT / ctr.REGISTRY_FILE).read_text(encoding="utf-8")
    sections = ctr.parse_sections(text)
    keys = ctr.parse_registry_keys(text)

    assert sections[IP_SECTION] == "ip"
    assert sections[GLOBAL_SECTION] == "global"
    assert sections["installedpackages/pfblockerngsync/config/0"] == "sync"
    assert len(keys) >= ctr._MIN_REGISTRY_KEYS

    # issue #2123's own entries, and their adapter classification.
    assert keys[("ip", "enable_dup")] is True
    assert keys[("global", "alertrefresh")] is True
    assert keys[("sync", "syncinterfaces")] is True
    assert keys[("dnsbl", "autoaddrnot_in")] is True
    # A registered plain scalar must NOT be classified as a toggle.
    assert keys[("ip", "v4suppression")] is False


def test_every_exempt_row_still_names_a_live_site(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stale exemption is dead weight that hides an already-fixed site -- fail on it."""
    text = (_REPO_ROOT / ctr.REGISTRY_FILE).read_text(encoding="utf-8")
    sections = ctr.parse_sections(text)
    keys = ctr.parse_registry_keys(text)
    recorded = dict(ctr.EXEMPT)

    # Re-scan with the exemptions disabled: what fires is what genuinely needs a row.
    monkeypatch.setattr(ctr, "EXEMPT", {})
    live: set[tuple[str, str]] = set()
    for page in sorted((_REPO_ROOT / ctr.WWW_DIR).glob("*.php")):
        for v in ctr.find_violations(page.read_text(encoding="utf-8"), str(page), sections, keys):
            # detail's first quoted token is '<alias>/<key>'.
            live.add((page.name, v.detail.split("'")[1].split("/", 1)[1]))

    stale = set(recorded) - live
    assert not stale, f"EXEMPT rows no longer needed (delete them): {sorted(stale)}"


def test_www_tree_is_clean() -> None:
    """The real pages pass -- this gate blocks, it is not pre-broken."""
    result = subprocess.run(
        [sys.executable, str(_TOOL)],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"src/usr/local/www/pfblockerng is not clean:\n{result.stderr}"


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


def test_every_2123_key_is_classified_as_a_toggle() -> None:
    """All seventeen, not a sample: a plain-scalar slip would let RULE 2 skip the key."""
    text = (_REPO_ROOT / ctr.REGISTRY_FILE).read_text(encoding="utf-8")
    keys = ctr.parse_registry_keys(text)
    expected = [
        ("ip", "enable_dup"),
        ("ip", "enable_agg"),
        ("ip", "enable_log"),
        ("ip", "enable_rdns"),
        ("ip", "database_cc"),
        ("ip", "enable_float"),
        ("ip", "killstates"),
        ("dnsbl", "autoaddrnot_in"),
        ("dnsbl", "autoports_in"),
        ("dnsbl", "autoaddr_in"),
        ("dnsbl", "autonot_in"),
        ("dnsbl", "autoaddrnot_out"),
        ("dnsbl", "autoports_out"),
        ("dnsbl", "autoaddr_out"),
        ("dnsbl", "autonot_out"),
        ("sync", "syncinterfaces"),
        ("global", "alertrefresh"),
    ]
    assert len(expected) == 17
    plain = [f"{a}/{b}" for a, b in expected if keys.get((a, b)) is not True]
    assert not plain, f"issue #2123 keys not carrying the toggle read adapter: {plain}"


def test_whitespace_between_brackets_does_not_evade_either_rule() -> None:
    """`$pfb ['iconfig'] ['x']` is valid PHP and must not slip past the matchers."""
    mirror = f"$pfb ['iconfig'] = PfbConfig::readSection('{IP_SECTION}');\n"
    save = (
        mirror + "$pfb ['iconfig'] ['pfb_new_flag'] = pfb_filter($_POST['x'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';\n"
    )
    assert _rules(save) == ["unregistered-toggle"]
    read = mirror + "$pconfig['enable_dup'] = $pfb ['iconfig'] ['enable_dup'] ?: '';\n"
    assert _rules(read) == ["page-level-default"]
