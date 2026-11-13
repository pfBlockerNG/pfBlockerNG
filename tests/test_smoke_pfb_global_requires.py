"""Issue #2492: never call ``pfb_global()`` unguarded without loading its home file.

``pfb_global()`` is defined in ``src/usr/local/pkg/pfblockerng/pfblockerng.inc`` (:3211).
``pfblockerng_extra.inc`` contains no ``require``/``include`` at all, so a snippet that
requires only extra.inc and then calls ``pfb_global()`` is fatal under ``pfSsh.php``::

    PHP ERROR: Uncaught Error: Call to undefined function pfb_global()

Without it, every smoke test using the snippet errors at fixture setup. The defect has been
introduced twice, and smoke dispatch defaults to ``scope=impacted``, so a re-introduction can
land without any leg that exercises it — hence a hermetic pin here.

A snippet is SAFE if it requires ``pfblockerng.inc`` OR guards the call with
``function_exists``. Both are accepted: which one suits a given snippet is an empirical
question (a require was measured to break the loaded config — see issue #2492), not a
stylistic one.

Coverage is a source sweep over ``tests/smoke/`` as a tripwire for call sites. It is
per-occurrence (a require in a LATER snippet cannot excuse an earlier bare call), but
it reads Python source, not emitted PHP: string concatenation, negated guards, or
exotic call shapes evade it. Tripwire, not proof.
"""

from __future__ import annotations

import re
from pathlib import Path

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
# Sized for the worst legitimate case in-tree: an r-string snippet whose require sits ~80 lines above a later call.
_WINDOW = 8000


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
    if not out:
        # An empty parametrize list would emit a skip, which the #2359 allowlist gate
        # then fails as an unallowlisted skip — a confusing way to learn the sweep
        # covers nothing. Fail collection with the actual reason instead.
        raise RuntimeError(
            "pfb_global() sweep matched no files under tests/smoke — either every call "
            "site was removed (delete this sweep) or _CALL no longer matches the call "
            "shape (fix the pattern). Refusing to report vacuous coverage."
        )
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
