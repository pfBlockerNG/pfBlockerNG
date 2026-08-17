"""Issue #2492: never call ``pfb_global()`` unguarded without loading its home file.

``pfb_global()`` is defined in ``src/usr/local/pkg/pfblockerng/pfblockerng.inc`` (:3211).
``pfblockerng_extra.inc`` contains no ``require``/``include`` at all, so a snippet that
requires only extra.inc and then calls ``pfb_global()`` is fatal under ``pfSsh.php``::

    PHP ERROR: Uncaught Error: Call to undefined function pfb_global()

That errored every smoke test using ``pin_cron_due()`` (24 occurrences in one full run)
and every test in ``test_log_age_retention.py`` at fixture setup. The defect has been
introduced TWICE (most recently by ``074b359c``), and smoke dispatch defaults to
``scope=impacted``, so a re-introduction can land without any leg that exercises it.

Coverage here is TWO-TIER, honestly labelled:

* **Executable rows** for the two historical sites — ``pin_cron_due`` and
  ``_prime_idle_schedule`` — run the real helper against a monkeypatched ``php_eval``
  and assert the emitted PHP. These are the primary tier; both are mutation-verified.
  (Their snippet checks are substring-based too, so the evasions below apply to both
  tiers — "executable" means exercising the real helper, not parsing PHP.)
* **A source sweep** over ``tests/smoke/`` as a tripwire for NEW call sites. It is
  per-occurrence (a call must have a guard or a require in the PRECEDING window, so a
  later snippet's require cannot excuse an earlier bare call), but it reads Python
  source, not emitted PHP — string concatenation, negated guards
  (``!function_exists``), or exotic call shapes can evade it. It is a tripwire, not a
  proof; the executable rows are the stronger tier for the sites that have burned us.

Which remedy is correct per snippet is EMPIRICAL, not stylistic: for ``pin_cron_due``
the require was measured worse than the guard (19 passed/3 failed guarded; 12/13 with
the require after extra.inc — guest reporting "A valid config file could not be
recovered" x12; 25 errors, twice, with it before). Other snippets legitimately require
the file. Both remedies satisfy the invariant pinned here.
"""

from __future__ import annotations

import importlib
import re
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

_SMOKE_DIR = Path(__file__).resolve().parents[1] / "tests" / "smoke"
_GUARD = "function_exists('pfb_global')"

# A call-shaped occurrence in source: pfb_global ( ) ;  with optional spacing.
_CALL = re.compile(r"pfb_global\s*\(\s*\)\s*;")

# A require/include whose target is the MAIN inc. Deliberately does NOT match
# pfblockerng_extra.inc (the dot must follow "pfblockerng"), and does not match prose
# mentions in comments/docstrings ("do not require pfblockerng.inc" has no require-paren).
_REQUIRE_MAIN = re.compile(r"require(?:_once)?\s*\([^)\n]{0,200}pfblockerng\.inc")

# A Python constant holding the main-inc path (e.g. _PFB_INC = ".../pfblockerng.inc").
# Checked file-wide: a file that defines such a constant is requiring the file through
# it. Weaker than the windowed require check; accepted as tripwire slack.
_MAIN_CONST = re.compile(r"""(?m)^\s*\w+\s*=\s*["'][^"']*/pfblockerng\.inc["']""")

# How far back (in characters) a require/guard may sit from the call it licenses.
# Sized for the worst legitimate case in-tree: test_schedule_runtime.py keeps one
# r-string snippet whose require sits ~80 lines above its second call.
_WINDOW = 8000


def _live_helpers() -> ModuleType:
    # Resolve at CALL time, never at import time: tests/test_adr47_conftest_lane.py
    # deliberately EVICTS tests.smoke.helpers from sys.modules and re-imports it (to
    # test import-time env reads), orphaning any module-level binding taken during
    # collection. A patch applied to the orphan is invisible to code holding the new
    # instance — observed as this file passing standalone and failing in the full
    # suite with the REAL php_eval running ('object' has no attribute 'ssh_argv').
    return importlib.import_module("tests.smoke.helpers")


def _capture_emitted_snippet(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []

    def fake_php_eval(_vm: object, snippet: str, **_kw: object) -> subprocess.CompletedProcess[str]:
        seen.append(snippet)
        # Shaped to satisfy each helper's own success check: pin_cron_due parses the
        # sentinel pair; _prime_idle_schedule only wants "OK" in stdout. The literals
        # duplicate pin_cron_due's local sentinels on purpose — if that protocol
        # changes, the helper raises and this row fails LOUD (re-shape the fake then).
        return subprocess.CompletedProcess([], 0, "OK<<<HOUR>>>7<<<END>>>", "")

    monkeypatch.setattr(_live_helpers(), "php_eval", fake_php_eval)
    return seen


def _assert_snippet_safe(snippet: str, *, origin: str) -> None:
    """The emitted PHP must load the symbol or guard the call — checked on the SNIPPET,
    so a require elsewhere in the same file cannot excuse it (each php_eval is a fresh
    PHP process; nothing carries over between snippets)."""
    assert "pfb_global" in snippet, f"{origin}: row is vacuous if the call vanished — rewrite it"
    if _REQUIRE_MAIN.search(snippet):
        return
    assert _GUARD in snippet, (
        f"{origin} calls pfb_global() with neither a require of pfblockerng.inc nor a "
        f"function_exists guard; under pfSsh.php that is 'Call to undefined function "
        f"pfb_global()' (issue #2492)"
    )


def test_pin_cron_due_emits_safe_php(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _capture_emitted_snippet(monkeypatch)
    assert _live_helpers().pin_cron_due(object()) == 7  # type: ignore[arg-type]
    assert len(seen) == 1, f"expected exactly one php_eval, got {len(seen)}"
    _assert_snippet_safe(seen[0], origin="pin_cron_due")


def test_prime_idle_schedule_emits_safe_php(monkeypatch: pytest.MonkeyPatch) -> None:
    # The second historical site (its module fixture errored every test in the file).
    # Imported here, not exercised via the live suite, precisely so scope=impacted
    # cannot skip it.
    tlar = importlib.import_module("tests.smoke.test_log_age_retention")
    if getattr(tlar, "h", None) is not _live_helpers():
        # tlar's `h` is a stale instance from before an eviction — re-import so the
        # helper under test calls the same module object the patch lands on.
        tlar = importlib.reload(tlar)

    seen = _capture_emitted_snippet(monkeypatch)
    tlar._prime_idle_schedule(object())  # type: ignore[arg-type]
    assert len(seen) == 1, f"expected exactly one php_eval, got {len(seen)}"
    _assert_snippet_safe(seen[0], origin="_prime_idle_schedule")


def _swept_sources() -> list[Path]:
    # Collection-time filter instead of pytest.skip: the #2359 skip-allowlist gate
    # fails ANY skip not in tests/skip-allowlist.txt, so a skip-per-uninvolved-file
    # design (107 of them) reds the main CI job outright.
    out = []
    for p in sorted(_SMOKE_DIR.rglob("*.py")):
        if p.name == "__init__.py":
            continue
        if _CALL.search(p.read_text(encoding="utf-8")):
            out.append(p)
    return out


@pytest.mark.parametrize(
    "source",
    _swept_sources(),
    ids=lambda p: p.relative_to(_SMOKE_DIR).as_posix(),
)
def test_no_new_bare_pfb_global_call_site(source: Path) -> None:
    """Tripwire: every call-shaped pfb_global(); must have a guard or a main-inc
    require in the text WINDOW preceding it (or the file defines a main-inc path
    constant). Preceding-only is deliberate: a require in a LATER snippet cannot
    license an earlier call, and comment prose matches neither pattern."""
    text = source.read_text(encoding="utf-8")
    file_has_const = bool(_MAIN_CONST.search(text))
    for m in _CALL.finditer(text):
        window = text[max(0, m.start() - _WINDOW) : m.start()]
        if _GUARD in window or _REQUIRE_MAIN.search(window) or file_has_const:
            continue
        line = text.count("\n", 0, m.start()) + 1
        raise AssertionError(
            f"{source.relative_to(_SMOKE_DIR).as_posix()}:{line} calls pfb_global() with "
            f"no function_exists guard and no require of pfblockerng.inc in the preceding "
            f"{_WINDOW} chars. pfblockerng_extra.inc defines neither the symbol nor any "
            f"require, so this is fatal under pfSsh.php (issue #2492)."
        )
