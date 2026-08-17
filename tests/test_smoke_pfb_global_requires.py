"""Issue #2492: never call ``pfb_global()`` unguarded without loading its home file.

``pfb_global()`` is defined in ``src/usr/local/pkg/pfblockerng/pfblockerng.inc`` (:3211).
``pfblockerng_extra.inc`` contains no ``require``/``include`` at all, so a snippet that
requires only extra.inc and then calls ``pfb_global()`` is fatal under ``pfSsh.php``::

    PHP ERROR: Uncaught Error: Call to undefined function pfb_global()

That errored every smoke test using ``pin_cron_due()`` (24 occurrences in one full run)
and every test in ``test_log_age_retention.py`` at fixture setup.

A snippet is SAFE if either holds:

* it requires ``pfblockerng.inc`` (so the symbol exists), or
* it guards the call with ``function_exists('pfb_global')``.

Both are accepted deliberately. Which one is correct for a given snippet is an empirical
question, not a stylistic one — for ``pin_cron_due`` the require was measured WORSE than
the guard (19 passed/3 failed guarded, versus 12/13 with the require after extra.inc and
25 errors with it before), so that call site guards. Other snippets legitimately require
it. This row pins only the invariant both satisfy.

Pinned hermetically because the defect has been introduced TWICE (most recently by
``074b359c``) and smoke dispatch defaults to ``scope=impacted``, so a re-introduction can
land without any leg that exercises it.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from tests.smoke import helpers

_MAIN_INC = "pfblockerng.inc"
_GUARD = "function_exists('pfb_global')"
_SMOKE_DIR = Path(__file__).resolve().parents[1] / "tests" / "smoke"

# A call that is NOT preceded on the same line by the function_exists guard.
_UNGUARDED_CALL = re.compile(r"(?<!function_exists\('pfb_global'\)\) \{ )pfb_global\(\);")


def test_pin_cron_due_does_not_call_pfb_global_unguarded(monkeypatch: pytest.MonkeyPatch) -> None:
    """pin_cron_due's emitted PHP must not call pfb_global() without a guard or the require."""
    seen: list[str] = []

    def fake_php_eval(_vm: object, snippet: str, **_kw: object) -> subprocess.CompletedProcess[str]:
        seen.append(snippet)
        return subprocess.CompletedProcess([], 0, "OK<<<HOUR>>>7<<<END>>>", "")

    monkeypatch.setattr(helpers, "php_eval", fake_php_eval)

    assert helpers.pin_cron_due(object()) == 7  # type: ignore[arg-type]
    assert len(seen) == 1, f"expected exactly one php_eval, got {len(seen)}"
    snippet = seen[0]

    assert "pfb_global" in snippet, "row is vacuous if the call vanished entirely — rewrite it"
    if _MAIN_INC in snippet:
        return  # symbol is loaded; safe
    assert _GUARD in snippet, (
        "pin_cron_due calls pfb_global() with neither a require of pfblockerng.inc nor a "
        "function_exists guard; under pfSsh.php that is 'Call to undefined function "
        "pfb_global()' (issue #2492)"
    )
    assert not _UNGUARDED_CALL.search(snippet), "a second, unguarded pfb_global() call slipped in"


@pytest.mark.parametrize(
    "source",
    sorted(p for p in _SMOKE_DIR.rglob("*.py") if p.name != "__init__.py"),
    ids=lambda p: p.name,
)
def test_no_smoke_source_calls_pfb_global_unguarded(source: Path) -> None:
    """Sweep every smoke source, so a third call site is caught here, not by a red suite."""
    text = source.read_text(encoding="utf-8")
    if "pfb_global" not in text:
        pytest.skip("does not mention pfb_global")
    if _MAIN_INC in text or _GUARD in text:
        return  # loads the symbol, or guards the call
    assert not _UNGUARDED_CALL.search(text), (
        f"{source.name} calls pfb_global() with neither a require of {_MAIN_INC} nor a "
        f"function_exists guard. pfblockerng_extra.inc defines neither pfb_global() nor "
        f"any require, so the call is fatal under pfSsh.php (issue #2492)."
    )
