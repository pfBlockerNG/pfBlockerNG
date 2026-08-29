"""Issue #2489: a repeated cron pass must re-arm its reservation, or it is inert.

``pin_cron_due()`` reserves a **one-shot** pending occurrence per feed group
(``pfb_schedule_state_set_pending`` — helpers.py). The first ``cron`` pass consumes it;
every later pass in the same loop returns at "No Updates required." without reaching
``pfb_update_check()``, so nothing the first pass persisted is ever read back.

A loop that repeats a pass without re-arming therefore exercises ONE pass however high its
cap reads. The ADR-42 Phase-3 conditional-GET cases depend on the span: the detector
persists a validator on a 200 and can only send it on a later probe, so an unre-armed loop
leaves the conditional request unsent and the 304 unreachable.

Hermetic coverage, because the live tier cannot be relied on to catch a re-introduction
(smoke dispatch defaults to ``scope=impacted``), in three groups:

* **The rule**, applied to every ``tests/smoke`` file that repeats a pass: the re-arm must
  sit in the loop's body. Checked over the AST, so docstring prose cannot satisfy it.
* **What the rule can see** — crafted rows for ``for``/``while``, positional and keyword
  verbs, dotted call chains, and a verb the AST cannot read (which counts as a pass, so the
  rule fails closed rather than waving a refactor through).
* **What the rule rejects** — crafted rows that must be flagged, so the rule is not proven
  merely by what the tree happens to contain.
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


def _leaf_name(node: ast.AST) -> str:
    """Final segment of a call's dotted name: ``pkg.mod.h.reload(...)`` -> ``reload``.

    One level is enough: Python's AST puts the leaf attribute at the OUTERMOST node, so
    ``a[0].reload(...)`` and ``f().reload(...)`` resolve too. The leaf is matched EXACTLY —
    ``endswith`` counted ``preload()`` as a cron pass and ``spin_cron_due()`` as a re-arm,
    wrong in opposite directions.
    """
    if not isinstance(node, ast.Call):
        return ""
    func: ast.expr = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else ""


# helpers.reload(vm, scope, ...) — the verb rides the second positional or the `scope`
# keyword. Other keywords (`timeout=`, ...) are NOT verb candidates: treating them as such
# makes `reload(vm, "update", timeout=timeout)` undecidable and flags an ordinary call.
_VERB_KEYWORD = "scope"


def _verb_args(call: ast.Call) -> list[ast.expr]:
    """The expressions that can carry the verb, in the order the rule should weigh them."""
    positional = list(call.args[1:2])
    keyword = [kw.value for kw in call.keywords if kw.arg == _VERB_KEYWORD]
    return positional + keyword


def _cron_pass_kind(node: ast.AST) -> str:
    """``''`` (not a pass) · ``'cron'`` (a literal cron pass) · ``'unknown'`` (undecidable).

    Undecidable counts as a pass. A verb the AST cannot read — a variable, an f-string, an
    unpacked ``*args`` — is exactly how a refactor would slip a repeated pass past a
    literal-only sweep, so the rule fails CLOSED and asks for a re-arm (or a literal)
    rather than waving it through. A verb that IS readable and is not ``cron`` settles the
    question the other way, so ordinary calls with extra keywords stay out of it.
    """
    if _leaf_name(node) != "reload":
        return ""
    assert isinstance(node, ast.Call)
    # A starred positional hides both the VM and the verb: nothing can be sliced out of it.
    if any(isinstance(a, ast.Starred) for a in node.args) or any(kw.arg is None for kw in node.keywords):
        return "unknown"
    candidates = _verb_args(node)
    if any(isinstance(a, ast.Constant) and a.value == "cron" for a in candidates):
        return "cron"
    if any(isinstance(a, ast.Constant) for a in candidates):
        return ""
    return "unknown" if candidates else ""


def _runs_cron_pass(node: ast.AST) -> bool:
    return _cron_pass_kind(node) != ""


def _rearms(node: ast.AST) -> bool:
    return _leaf_name(node) == "pin_cron_due"


# Both loop forms count: `while` reads as "keep passing until the marker appears", which is
# exactly the shape this defect wore, and a for-only sweep would wave it through.
_LOOP_NODES = (ast.For, ast.While)
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)


def _scope_name(node: ast.AST) -> str:
    return getattr(node, "name", "<module>")


def _loops_running_cron_in(tree: ast.AST) -> list[tuple[ast.stmt, str]]:
    """Every loop that runs a cron pass, with the scope that holds it.

    Scopes include ``async def`` and module level, not just ``def``: a loop is no less
    repeated for sitting in one of those.
    """
    out: list[tuple[ast.stmt, str]] = []
    for scope in ast.walk(tree):
        if not isinstance(scope, _SCOPES):
            continue
        for node in ast.walk(scope):
            if isinstance(node, _LOOP_NODES) and any(_runs_cron_pass(n) for n in ast.walk(node)):
                out.append((node, _scope_name(scope)))
    # A loop nested in a function reports once per enclosing scope; keep the innermost.
    seen: dict[int, tuple[ast.stmt, str]] = {}
    for loop, name in out:
        if id(loop) not in seen or name != "<module>":
            seen[id(loop)] = (loop, name)
    return list(seen.values())


def _rule_violations_in(tree: ast.AST) -> list[str]:
    """The rule itself, as data: one message per loop that repeats a pass without re-arming.

    The re-arm must sit in the loop's BODY. ``ast.walk(loop)`` also reaches the ``else:``
    clause, which runs once after the loop finishes and therefore re-arms nothing.
    """
    out: list[str] = []
    for loop, scope in _loops_running_cron_in(tree):
        body: list[ast.stmt] = list(loop.body)  # type: ignore[attr-defined]
        if any(_rearms(n) for stmt in body for n in ast.walk(stmt)):
            continue
        out.append(f"line {loop.lineno} ({scope})")
    return out


def _loops_running_cron(source: Path) -> list[tuple[ast.stmt, str]]:
    return _loops_running_cron_in(ast.parse(source.read_text(encoding="utf-8")))


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
            "removed (delete this sweep) or _cron_pass_kind() no longer matches the call shape "
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
    violations = _rule_violations_in(ast.parse(source.read_text(encoding="utf-8")))
    assert not violations, (
        f"{source.relative_to(_SMOKE_DIR).as_posix()}: {'; '.join(violations)} runs a cron pass "
        f"in a loop without calling pin_cron_due() in the loop body. pin_cron_due() reserves a "
        f"ONE-SHOT pending occurrence, so pass 1 consumes it and every later pass returns at "
        f"'No Updates required.' — the loop reads as N passes but exercises one (#2489). A verb "
        f"the AST cannot read counts as a pass: make it a literal or re-arm."
    )


def _wrap(body: str) -> ast.AST:
    """Crafted source for the rows below (a sweep is only as good as what it detects)."""
    return ast.parse("def t(vm):\n    " + body.replace("\n", "\n    "))


@pytest.mark.parametrize(
    ("label", "body", "detected"),
    [
        ("for-positional", "for _ in range(2):\n    h.reload(vm, 'cron')", True),
        ("while-positional", "while True:\n    h.reload(vm, 'cron')", True),
        # helpers.reload names its second parameter `scope`; read by value, not by name.
        ("keyword-scope", "for _ in range(2):\n    h.reload(vm, scope='cron')", True),
        ("nested-in-with", "for _ in range(2):\n    with x():\n        h.reload(vm, 'cron')", True),
        ("dotted-chain", "for _ in range(2):\n    pkg.mod.h.reload(vm, 'cron')", True),
        # Fail-closed: an unreadable verb is treated as a pass rather than waved through.
        ("variable-verb", "for _ in range(2):\n    h.reload(vm, verb)", True),
        ("fstring-verb", "for _ in range(2):\n    h.reload(vm, f'{v}')", True),
        # A starred positional hides the verb slot itself, so it cannot be read at all.
        ("star-args-only", "for _ in range(2):\n    h.reload(*allargs)", True),
        ("kwargs-splat", "for _ in range(2):\n    h.reload(vm, **kw)", True),
        ("other-verb", "for _ in range(2):\n    h.reload(vm, 'updatednsbl')", False),
        # A readable non-cron verb settles it, whatever unrelated keywords ride along.
        ("other-verb-with-timeout", "for _ in range(2):\n    h.reload(vm, 'update', timeout=t)", False),
        ("single-pass", "h.reload(vm, 'cron')", False),
        # Exact leaf match, both directions: neither of these is the call we mean.
        ("preload-not-reload", "for _ in range(2):\n    h.preload(vm, 'cron')", False),
    ],
)
def test_detector_sees_every_repeat_shape(label: str, body: str, detected: bool) -> None:
    """The sweep only protects the shapes it can see; these rows fix that surface.

    Without them a later refactor — to ``while``, to a keyword, to a variable verb — would
    silently empty the sweep while every row still reported green (issue #2489).
    """
    assert bool(_loops_running_cron_in(_wrap(body))) is detected, label


@pytest.mark.parametrize(
    ("label", "body", "violations"),
    [
        # THE finding this file exists to prevent: a repeated pass with no re-arm.
        ("bare-loop-rejected", "for _ in range(2):\n    h.reload(vm, 'cron')", 1),
        (
            "rearmed-loop-accepted",
            "for i in range(2):\n    if i:\n        h.pin_cron_due(vm)\n    h.reload(vm, 'cron')",
            0,
        ),
        # `else:` runs once AFTER the loop, so a re-arm there re-arms nothing.
        (
            "rearm-in-else-rejected",
            "for _ in range(2):\n    h.reload(vm, 'cron')\nelse:\n    h.pin_cron_due(vm)",
            1,
        ),
        # The inner loop repeats without re-arming; the outer one's call does not cover it.
        (
            "inner-loop-unrearmed-rejected",
            "for _ in range(2):\n    h.pin_cron_due(vm)\n    for _ in range(2):\n        h.reload(vm, 'cron')",
            1,
        ),
        # Exact leaf match: a same-suffix name is not the re-arm.
        (
            "lookalike-rearm-rejected",
            "for _ in range(2):\n    x.spin_cron_due(vm)\n    h.reload(vm, 'cron')",
            1,
        ),
    ],
)
def test_rule_rejects_what_it_must(label: str, body: str, violations: int) -> None:
    """The rule's REJECTION half, pinned.

    Without these rows the rule is proven only by what the tree happens to contain: a
    re-arm detector that never says no still reports every file clean.
    """
    assert len(_rule_violations_in(_wrap(body))) == violations, label


@pytest.mark.parametrize(
    ("label", "source", "violations"),
    [
        ("top-level-async-def", "async def t(vm):\n    for _ in range(2):\n        h.reload(vm, 'cron')\n", 1),
        ("module-level-loop", "for _ in range(2):\n    h.reload(vm, 'cron')\n", 1),
        (
            "top-level-async-def-rearmed",
            "async def t(vm):\n    for _ in range(2):\n        h.pin_cron_due(vm)\n        h.reload(vm, 'cron')\n",
            0,
        ),
    ],
)
def test_rule_covers_scopes_outside_a_plain_def(label: str, source: str, violations: int) -> None:
    """Parsed RAW, not through ``_wrap()``.

    ``_wrap()`` nests its body in a ``def``, whose walk reaches the loop whatever scope
    holds it — so only raw sources exercise the ``async def`` and module-level handling.
    """
    assert len(_rule_violations_in(ast.parse(source))) == violations, label


def test_pin_cron_due_still_routes_through_the_reservation_api(monkeypatch: pytest.MonkeyPatch) -> None:
    """The loop rule is load-bearing only while the reservation is one-shot; this row covers
    one half of that — the helper still going through the reservation API.

    It deliberately does NOT claim to catch the reservation becoming durable: the one-shot
    semantics live in ``pfb_schedule_state_record_outcome()``
    (``src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc``, which unsets
    ``pending_occurrence`` once a pass completes), and dropping that unset would leave the
    emitted snippet byte-identical. What this catches is the helper being rewired away from
    the API entirely, which is the change most likely to arrive with a rename.
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
        f"pin_cron_due() no longer drives {_ONE_SHOT_API}(); if the reservation moved elsewhere, "
        f"check whether it is still one-shot before trusting "
        f"test_repeated_cron_pass_rearms_its_reservation (issue #2489)"
    )
