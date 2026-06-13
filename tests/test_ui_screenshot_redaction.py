"""ADR-24 — the browser-tier DOM identity mask (value-based screenshot redaction).

The Tier-B browser screenshots are uploaded as artifacts. A Plus leg boots with a
SECRET source-VM identity (MAC + SMBIOS uuid [+ NDI]); even though the browser tier
only screenshots pfBlockerNG pages (where the identity is not expected to appear),
:func:`tests.smoke.ui.conftest.mask_page_identity` defensively blanks any DOM
occurrence of a redaction value BEFORE every Playwright screenshot. The mask is
value-based and env-gated: empty ``SMOKE_REDACT_VALUES`` (a CE leg) -> a strict
no-op, so CE screenshots stay byte-identical to today.

These pin the env→values lookup and the JS-string contract WITHOUT a browser (no
``page.evaluate`` is run here): the live DOM mutation is exercised by the live-VM
browser tier, not the unit suite.

They live under ``tests/`` (NOT ``tests/smoke/``) so they run in the default
suite; the import of the ui conftest is pure (its heavy deps — requests/playwright
— are all deferred), so collecting it here never touches a browser.
"""

from __future__ import annotations

import pytest

from tests.smoke.ui.conftest import (
    _DOM_MASK_JS,
    REDACT_VALUES_ENV,
    _redact_values_from_env,
)


class TestRedactValuesFromEnv:
    """The env→redaction-list lookup feeding the DOM mask (the CE/Plus gate)."""

    def test_unset_env_is_the_ce_no_op_empty_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Given SMOKE_REDACT_VALUES unset (a CE leg) -> the value set is empty.

        This empty list is the load-bearing CE no-op: ``mask_page_identity`` returns
        before any ``page.evaluate``, so the CE screenshot is unchanged.
        """
        monkeypatch.delenv(REDACT_VALUES_ENV, raising=False)
        assert _redact_values_from_env() == []

    def test_empty_string_env_is_also_the_no_op(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An explicitly-empty env value is still the CE no-op (empty list)."""
        monkeypatch.setenv(REDACT_VALUES_ENV, "")
        assert _redact_values_from_env() == []

    def test_set_env_parses_to_the_deduped_value_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Given a Plus identity in the env -> the parsed, de-duplicated value list.

        Newline- and comma-separated, whitespace-stripped, duplicates dropped — the
        same contract :func:`tests.smoke.helpers.parse_redact_values` pins. Proves
        the Plus side is NON-empty (vs the CE no-op above), so the mask actually runs.
        """
        raw = "AA:BB:CC:DD:EE:FF\n11112222-3333-4444-5555-666677778888,AA:BB:CC:DD:EE:FF"
        monkeypatch.setenv(REDACT_VALUES_ENV, raw)
        assert _redact_values_from_env() == [
            "AA:BB:CC:DD:EE:FF",
            "11112222-3333-4444-5555-666677778888",
        ]


class TestDomMaskJsContract:
    """Structural contract of the JS the mask runs (no browser — string assertions)."""

    def test_js_targets_text_and_each_listed_attribute(self) -> None:
        """The JS scrubs text nodes, input/textarea .value, and the listed attributes.

        A structural assertion (the JS is a module constant): it must walk text nodes
        (TreeWalker SHOW_TEXT), touch input/textarea ``.value``, and cover each of the
        attributes ADR-24 names (title, alt, value, placeholder), replacing matches
        with REDACTED. This guards against a future edit silently dropping a surface.
        """
        # Text nodes.
        assert "SHOW_TEXT" in _DOM_MASK_JS
        assert "createTreeWalker" in _DOM_MASK_JS
        # input/textarea live value.
        assert 'querySelectorAll("input, textarea")' in _DOM_MASK_JS
        assert ".value" in _DOM_MASK_JS
        # Every named attribute.
        for attr in ("title", "alt", "value", "placeholder"):
            assert f'"{attr}"' in _DOM_MASK_JS
        # Case-insensitive match + the redaction sentinel.
        assert "gi" in _DOM_MASK_JS  # the RegExp flags
        assert "REDACTED" in _DOM_MASK_JS

    def test_js_is_a_value_parameterised_function_not_a_hardcoded_literal(self) -> None:
        """The JS takes the values as an argument (no secret baked into the string).

        It must accept ``(values)`` and early-return on an empty list — so the same
        string is safe to ship in source (no Plus identity literal) and is a no-op
        when called with the CE empty set.
        """
        assert "(values)" in _DOM_MASK_JS
        assert "!values.length" in _DOM_MASK_JS
