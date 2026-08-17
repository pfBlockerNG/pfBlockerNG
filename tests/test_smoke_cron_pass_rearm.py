"""Issue #2489: a repeated cron pass must re-arm its reservation, or it is inert.

``pin_cron_due()`` reserves a **one-shot** pending occurrence per feed group
(``pfb_schedule_state_set_pending`` — helpers.py). The first ``cron`` pass consumes it;
every later pass in the same loop returns at "No Updates required." without reaching
``pfb_update_check()``, so nothing the first pass persisted is ever read back.

That is what made the two ADR-42 Phase-3 conditional-GET cases fail: measured on a live
guest, every request the mock feed server saw was a BARE GET, and the feed was evaluated
exactly once::

    23:06:03 [ smokep3lm304 ]  Downloading update .. 200 OK.          <- Force ingest
    23:06:05 [ smokep3lm304 ] ( content unchanged ) Update not required   <- cron pass 1
    23:06:05 / :05 / :06 / :07   No Updates required.                 <- passes 2-4, no probe

The validator itself was written correctly (``dnsblorig/<header>.orig.lastmod`` held the
mock's fixed epoch), and re-arming the reservation each pass turned both cases green with
``src/`` untouched — ``If-None-Match`` earned ``304 via=etag`` and ``If-Modified-Since``
earned ``304 via=ims``. The defect was in the test loop, not in the product.

Two hermetic rows, because the live tier cannot be relied on to catch a re-introduction
(smoke dispatch defaults to ``scope=impacted``):

* **The loop rule** — any ``for`` loop that runs a ``cron`` pass must re-arm inside the
  loop body. Checked over the AST, so prose in a docstring cannot satisfy it.
* **The reason the rule exists** — ``pin_cron_due()`` must still emit a one-shot
  reservation. If it ever reserves durably, this rule can be revisited; until then the
  loop rule is load-bearing and this row says why.
"""

from __future__ import annotations

import ast
import importlib
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

_SMOKE_DIR = Path(__file__).resolve().parents[1] / "tests" / "smoke"

# The one-shot reservation API pin_cron_due() drives. Named here so the failure message can
# point at the actual coupling rather than at a helper name.
_ONE_SHOT_API = "pfb_schedule_state_set_pending"


def _live_helpers() -> ModuleType:
    # Resolve at CALL time: tests/test_adr47_conftest_lane.py evicts tests.smoke.helpers
    # from sys.modules and re-imports it, orphaning any module-level binding taken during
    # collection (issue #2492). A patch on the orphan is invisible to the code under test.
    return importlib.import_module("tests.smoke.helpers")


def _call_name(node: ast.AST) -> str:
    """``h.reload(...)`` -> ``h.reload``; ``reload(...)`` -> ``reload``; else ``''``."""
    if not isinstance(node, ast.Call):
        return ""
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _is_cron_pass(node: ast.AST) -> bool:
    """A call that runs one cron pass: ``h.reload(vm, "cron")``."""
    if not isinstance(node, ast.Call) or not _call_name(node).endswith("reload"):
        return False
    return any(isinstance(a, ast.Constant) and a.value == "cron" for a in node.args)


def _rearms(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _call_name(node).endswith("pin_cron_due")


def _loops_running_cron(source: Path) -> list[tuple[ast.For, str]]:
    tree = ast.parse(source.read_text(encoding="utf-8"))
    out: list[tuple[ast.For, str]] = []
    for enclosing in ast.walk(tree):
        if not isinstance(enclosing, ast.FunctionDef):
            continue
        for node in ast.walk(enclosing):
            if isinstance(node, ast.For) and any(_is_cron_pass(n) for n in ast.walk(node)):
                out.append((node, enclosing.name))
    return out


def _smoke_sources() -> list[Path]:
    # Collection-time filter rather than pytest.skip: the #2359 allowlist gate fails ANY
    # skip that is not allowlisted, so a skip-per-uninvolved-file design reds the job.
    return [p for p in sorted(_SMOKE_DIR.rglob("*.py")) if p.name != "__init__.py" and _loops_running_cron(p)]


def _sources_or_fail() -> list[Path]:
    found = _smoke_sources()
    if not found:
        # An empty parametrize list emits a skip, which the #2359 gate then fails as an
        # unallowlisted skip — a confusing way to learn the sweep covers nothing.
        raise RuntimeError(
            "no tests/smoke file loops over a cron pass — either every multi-pass loop was "
            "removed (delete this sweep) or _is_cron_pass() no longer matches the call shape "
            "(fix it). Refusing to report vacuous coverage."
        )
    return found


@pytest.mark.parametrize(
    "source",
    _sources_or_fail(),
    ids=lambda p: p.relative_to(_SMOKE_DIR).as_posix(),
)
def test_repeated_cron_pass_rearms_its_reservation(source: Path) -> None:
    """Every loop that runs a cron pass re-arms the reservation inside the loop body.

    Without it, passes after the first never reach the detector, so the loop silently
    exercises one pass however high its cap reads (issue #2489).
    """
    for loop, func in _loops_running_cron(source):
        if any(_rearms(n) for n in ast.walk(loop)):
            continue
        raise AssertionError(
            f"{source.relative_to(_SMOKE_DIR).as_posix()}:{loop.lineno} ({func}) runs a cron "
            f"pass in a loop without calling pin_cron_due() inside it. pin_cron_due() reserves "
            f"a ONE-SHOT pending occurrence, so pass 1 consumes it and every later pass returns "
            f"at 'No Updates required.' — the loop reads as N passes but exercises one (#2489)."
        )


def test_pin_cron_due_still_reserves_one_shot(monkeypatch: pytest.MonkeyPatch) -> None:
    """The loop rule above is load-bearing only while the reservation is one-shot.

    If ``pin_cron_due()`` ever reserves durably, this row fails and whoever changed it is
    told to revisit the rule — rather than leaving a sweep enforcing an obsolete coupling.
    """
    seen: list[str] = []

    def fake_php_eval(_vm: object, snippet: str, **_kw: object) -> subprocess.CompletedProcess[str]:
        seen.append(snippet)
        # Shaped to satisfy pin_cron_due's own sentinel parse; if that protocol changes the
        # helper raises and this row fails LOUD (re-shape the fake then).
        return subprocess.CompletedProcess([], 0, "OK<<<HOUR>>>7<<<END>>>", "")

    helpers = _live_helpers()
    monkeypatch.setattr(helpers, "php_eval", fake_php_eval)
    assert helpers.pin_cron_due(object()) == 7  # type: ignore[arg-type]

    assert len(seen) == 1, f"expected exactly one php_eval, got {len(seen)}"
    assert _ONE_SHOT_API in seen[0], (
        f"pin_cron_due() no longer drives {_ONE_SHOT_API}(); if the reservation is now durable, "
        f"test_repeated_cron_pass_rearms_its_reservation enforces an obsolete coupling and both "
        f"rows need revisiting (issue #2489)"
    )
