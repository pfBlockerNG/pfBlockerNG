"""Issue #2492: a snippet calling ``pfb_global()`` must load ``pfblockerng.inc``.

``pfb_global()`` is defined in ``src/usr/local/pkg/pfblockerng/pfblockerng.inc``
(:3211). ``pfblockerng_extra.inc`` contains no ``require``/``include`` at all, so a
snippet that requires only extra.inc and then calls ``pfb_global()`` is fatal under
``pfSsh.php``::

    PHP ERROR: Uncaught Error: Call to undefined function pfb_global()

That errored every smoke test using ``pin_cron_due()`` (24 occurrences in one full
run) and every test in ``test_log_age_retention.py`` at fixture setup.

This defect has been introduced TWICE (most recently by ``074b359c``), which is why
it is pinned here rather than left to the live suite: smoke dispatch defaults to
``scope=impacted``, so a re-introduction can land without any leg that exercises it.

The rows below assert the emitted PHP, hermetically — no VM, no box.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.smoke import helpers

_MAIN_INC = "pfblockerng.inc"
_SMOKE_DIR = Path(__file__).resolve().parents[1] / "tests" / "smoke"


def _capture_snippet(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every snippet handed to ``php_eval`` instead of running it."""
    seen: list[str] = []

    def fake_php_eval(_vm: object, snippet: str, **_kw: object) -> subprocess.CompletedProcess[str]:
        seen.append(snippet)
        # Enough stdout for pin_cron_due's own success check to pass.
        return subprocess.CompletedProcess([], 0, "OK<<<HOUR>>>7<<<END>>>", "")

    monkeypatch.setattr(helpers, "php_eval", fake_php_eval)
    return seen


def test_pin_cron_due_loads_pfb_global_home_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """pin_cron_due must require pfblockerng.inc before calling pfb_global()."""
    seen = _capture_snippet(monkeypatch)

    assert helpers.pin_cron_due(object()) == 7  # type: ignore[arg-type]

    assert len(seen) == 1, f"expected exactly one php_eval, got {len(seen)}"
    snippet = seen[0]
    assert "pfb_global();" in snippet, "row is vacuous if the call was removed — rewrite it"
    call_at = snippet.index("pfb_global();")
    require_at = snippet.find(f"require_once('/usr/local/pkg/pfblockerng/{_MAIN_INC}')")
    assert require_at != -1, (
        f"pin_cron_due calls pfb_global() without requiring {_MAIN_INC}; "
        "under pfSsh.php that is 'Call to undefined function pfb_global()' (issue #2492)"
    )
    assert require_at < call_at, f"{_MAIN_INC} must be required BEFORE pfb_global() is called"


@pytest.mark.parametrize(
    "source",
    sorted(p for p in _SMOKE_DIR.rglob("*.py") if p.name != "__init__.py"),
    ids=lambda p: p.name,
)
def test_no_smoke_snippet_calls_pfb_global_without_its_home_file(source: Path) -> None:
    """No smoke module may call pfb_global() unless it also loads pfblockerng.inc.

    Sweeps every smoke source rather than the two known sites, so a third call site
    added later is caught by this row instead of by a red suite.
    """
    text = source.read_text(encoding="utf-8")
    if "pfb_global();" not in text:
        pytest.skip("does not call pfb_global()")
    assert _MAIN_INC in text, (
        f"{source.name} calls pfb_global() but never references {_MAIN_INC}. "
        f"pfblockerng_extra.inc defines neither pfb_global() nor any require, so the "
        f"call is fatal under pfSsh.php (issue #2492)."
    )
