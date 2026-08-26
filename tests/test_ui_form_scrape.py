"""Unit tests for the ADR-14 WebUI form-reconstruction helpers (pure logic).

These pin the contract of :func:`tests.smoke.ui.webui.scrape_form_fields` (and
its siblings ``_has_flag`` / ``extract_csrf_token``) -- the pure HTML->dict logic
that the Tier-B functional flows rely on to mirror a browser submit. They run in
the DEFAULT ``python -m pytest`` gate (fast, every commit), NOT only in the live
UI suite: the logic is pure (no VM, no ``requests``), so a regression in it must
be caught here rather than waiting for a live-VM functional flow to mis-save.

Why this file exists (the bug it would have caught early): a Batch-2 functional
flow (Feeds alt-URL) failed on the live VM because ``scrape_form_fields`` cannot
faithfully reproduce a browser's submission of a form that has MULTIPLE controls
sharing one ``name`` (a radio group, and pfBlockerNG's "same-named hidden +
checked radio" pattern). It returns ``dict[str, str]`` -- one value per name --
so same-name controls collapse to whichever appears LAST in document order. That
is a pure, deterministic property of the function and is fully unit-testable
off-box; it never needed a live VM to surface. :func:`test_same_name_*` below pin
that limitation so (a) it is a documented, tested fact and (b) any future change
to the collision behaviour is caught immediately. Forms that depend on multi-value
same-name submission must be driven via the browser tier (Playwright clicks the
real control), not this scraper.

``webui.py`` lives under ``tests/smoke/ui/`` (the smoke tree, which the default
run ``--ignore``s for COLLECTION). Its module level imports only stdlib
(``requests`` is deferred into ``WebUI.__init__``), so this test loads the module
by file path -- no package import, no third-party dep, no perturbation of the
smoke suite's own import setup.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

# tests/test_ui_form_scrape.py -> tests/smoke/ui/webui.py
_WEBUI_PATH = Path(__file__).parent / "smoke" / "ui" / "webui.py"


def _load_webui() -> Any:
    """Load ``tests/smoke/ui/webui.py`` as a standalone module (pure, stdlib-only)."""
    spec = importlib.util.spec_from_file_location("pfb_webui_under_test", _WEBUI_PATH)
    assert spec is not None and spec.loader is not None, f"cannot load webui.py from {_WEBUI_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_webui = _load_webui()
scrape_form_fields: Callable[[str], dict[str, str]] = _webui.scrape_form_fields
extract_csrf_token: Callable[[str], str] = _webui.extract_csrf_token
has_flag: Callable[[str, str], bool] = _webui._has_flag
WebUILoginError: type[Exception] = _webui.WebUILoginError


# --------------------------------------------------------------------------- #
# scrape_form_fields — single-control reconstruction (the simple, faithful cases)
# --------------------------------------------------------------------------- #


def test_text_and_hidden_inputs_contribute_their_value() -> None:
    """A text/hidden input contributes ``name -> value`` (HTML-unescaped)."""
    html = '<input type="text" name="t" value="hello"><input type="hidden" name="h" value="hv">'
    assert scrape_form_fields(html) == {"t": "hello", "h": "hv"}


def test_input_value_is_html_unescaped() -> None:
    """A stored ``&amp;`` round-trips back to ``&`` (a browser submits the raw char)."""
    assert scrape_form_fields('<input type="text" name="t" value="a &amp; b">') == {"t": "a & b"}


def test_checkbox_contributes_only_when_checked() -> None:
    """An unchecked checkbox sends NOTHING (omitted); a checked one sends its value."""
    assert scrape_form_fields('<input type="checkbox" name="c" value="on">') == {}
    assert scrape_form_fields('<input type="checkbox" name="c" value="on" checked>') == {"c": "on"}


def test_checkbox_checked_without_value_defaults_to_on() -> None:
    """A checked checkbox with no ``value`` defaults to ``"on"`` (browser default)."""
    assert scrape_form_fields('<input type="checkbox" name="c" checked>') == {"c": "on"}


def test_submit_and_button_inputs_are_not_harvested() -> None:
    """Submit/button controls are added explicitly by the caller, never scraped."""
    assert scrape_form_fields('<input type="submit" name="save" value="Save">') == {}


def test_disabled_control_is_skipped() -> None:
    """A disabled control is not submitted by a browser, so it is skipped."""
    assert scrape_form_fields('<input type="text" name="d" value="x" disabled>') == {}


def test_select_takes_selected_option_else_first() -> None:
    """A ``<select>`` contributes the selected option's value, or the first when none is."""
    selected = "<select name='s'><option value='a'>A</option><option value='b' selected>B</option></select>"
    first = "<select name='s'><option value='a'>A</option><option value='b'>B</option></select>"
    assert scrape_form_fields(selected) == {"s": "b"}
    assert scrape_form_fields(first) == {"s": "a"}


def test_disabled_select_is_skipped() -> None:
    """A disabled ``<select>`` is not submitted."""
    assert scrape_form_fields("<select name='s' disabled><option value='a' selected>A</option></select>") == {}


def test_textarea_inner_text_is_the_value_unescaped() -> None:
    """A ``<textarea>``'s inner text is its value (HTML-unescaped)."""
    assert scrape_form_fields("<textarea name='ta'>line1\nline2</textarea>") == {"ta": "line1\nline2"}
    assert scrape_form_fields("<textarea name='ta'>a &amp; b</textarea>") == {"ta": "a & b"}


def test_csrf_hidden_input_is_included() -> None:
    """The ``__csrf_magic`` hidden input is harvested like any other hidden field."""
    html = '<input type="hidden" name="__csrf_magic" value="sid:tok,1">'
    assert scrape_form_fields(html) == {"__csrf_magic": "sid:tok,1"}


# --------------------------------------------------------------------------- #
# scrape_form_fields — the SAME-NAME class (the limitation that bit Feeds alt-URL)
#
# scrape_form_fields returns dict[str, str] -- ONE value per name -- so it cannot
# represent a form that submits MULTIPLE values for one name (a radio group, or a
# same-named hidden + checked radio). Same-name controls collapse to whichever is
# LAST in document order. These tests pin that contract so the limitation is an
# explicit, tested fact -- and so the class of bug is caught here, fast, on every
# commit, instead of in a live-VM flow whose save silently rejects.
# --------------------------------------------------------------------------- #


def test_radio_group_takes_only_the_checked_option() -> None:
    """A radio group contributes ONLY the checked option's value; unchecked are dropped."""
    html = (
        "<input type='radio' name='r' value='a'>"
        "<input type='radio' name='r' value='b' checked>"
        "<input type='radio' name='r' value='c'>"
    )
    assert scrape_form_fields(html) == {"r": "b"}


def test_radio_group_with_none_checked_contributes_nothing() -> None:
    """No checked option -> the radio name is absent (a browser submits nothing for it)."""
    html = "<input type='radio' name='r' value='a'><input type='radio' name='r' value='b'>"
    assert "r" not in scrape_form_fields(html)


def test_same_name_hidden_after_checked_radio_overwrites_it() -> None:
    """LIMITATION: a same-named hidden AFTER a checked radio wins (last in order).

    This is the exact shape that broke the Feeds alt-URL flow: pfBlockerNG emits
    ``<input type=hidden name=X value="">`` next to a checked base radio also named
    ``X``. A browser submits BOTH (and PHP's ``$_POST`` resolves the collision by
    document order), but scrape_form_fields keeps only the last -- here the empty
    hidden -- so the field reconstructs as ``""``. A handler that then requires a
    non-empty value for that name rejects the whole save. Such forms must be driven
    via the browser tier, not this scraper.
    """
    html = "<input type='radio' name='X' value='base' checked><input type='hidden' name='X' value=''>"
    assert scrape_form_fields(html)["X"] == ""


def test_same_name_hidden_before_checked_radio_is_overwritten() -> None:
    """Mirror of the above: a same-named hidden BEFORE the checked radio loses (radio wins).

    Pinned alongside its sibling so the contract is unambiguous: the result for a
    same-name collision is purely document-order-dependent (last wins), which is
    precisely why scrape_form_fields cannot faithfully reproduce a multi-value
    same-name submission regardless of which value the form actually intends.
    """
    html = "<input type='hidden' name='X' value=''><input type='radio' name='X' value='base' checked>"
    assert scrape_form_fields(html)["X"] == "base"


def test_only_overridden_field_changes_other_fields_keep_current_values() -> None:
    """A browser-faithful POST = scrape + one override; every other field unchanged.

    Models how the functional flows POST: the page's whole field set is reconstructed
    and only the target field is overridden, so the save handler sees the page's own
    state plus the intended delta.
    """
    html = (
        '<input type="hidden" name="__csrf_magic" value="sid:t,1">'
        '<input type="text" name="a" value="1">'
        '<input type="text" name="b" value="2">'
    )
    fields = scrape_form_fields(html)
    fields["b"] = "changed"
    assert fields == {"__csrf_magic": "sid:t,1", "a": "1", "b": "changed"}


# --------------------------------------------------------------------------- #
# _has_flag — a boolean attribute is matched as an attribute NAME, not a value token
# --------------------------------------------------------------------------- #


def test_has_flag_matches_bare_and_valued_attribute() -> None:
    """``checked`` / ``disabled`` match both the bare and the ``=value`` form."""
    assert has_flag("type='checkbox' name='x' checked", "checked")
    assert has_flag("type='checkbox' name='x' checked='checked'", "checked")


def test_has_flag_does_not_match_the_flag_word_inside_another_value() -> None:
    """The flag word inside ANOTHER attribute's value must NOT count as the flag.

    Guards the form-reconstruction logic: ``value="checked"`` or
    ``data-x="disabled-state"`` must not misclassify the control.
    """
    assert not has_flag('type="text" name="x" value="checked"', "checked")
    assert not has_flag('type="text" name="x" data-state="disabled-thing"', "disabled")


# --------------------------------------------------------------------------- #
# extract_csrf_token — pull the __csrf_magic value regardless of attribute order
# --------------------------------------------------------------------------- #


def test_extract_csrf_token_name_before_value() -> None:
    assert extract_csrf_token('<input type="hidden" name="__csrf_magic" value="sid:AAA,1" />') == "sid:AAA,1"


def test_extract_csrf_token_value_before_name() -> None:
    assert extract_csrf_token('<input type="hidden" value="sid:BBB,2" name="__csrf_magic" />') == "sid:BBB,2"


def test_extract_csrf_token_missing_raises() -> None:
    """A page with no ``__csrf_magic`` raises (a loud failure, not a silent empty token)."""
    with pytest.raises(WebUILoginError):
        extract_csrf_token('<input type="hidden" name="other" value="x">')
