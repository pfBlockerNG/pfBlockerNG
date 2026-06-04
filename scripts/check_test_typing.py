#!/usr/bin/env python3
"""Fail if any function/method in the test suite is not fully type-annotated.

The test suite is fully typed and we keep it that way. mypy's own
``disallow_untyped_defs`` is the canonical rule (see the ``[[tool.mypy.overrides]]``
for ``tests.*`` in pyproject.toml), but mypy is not a CI/pre-commit gate here:
``pfb_unbound.py`` is typed incrementally, and running mypy over the suite also
surfaces unrelated errors (runtime-injected Unbound globals, Optional narrowings)
that have nothing to do with annotation coverage. This standalone AST check
enforces *exactly* the annotation-coverage invariant — no imports, no third-party
deps, version-independent — so it can run in the pre-commit hook and CI and stay
green regardless of those orthogonal mypy findings.

A def is "fully annotated" when it has a return annotation and every parameter is
annotated, except a leading ``self``/``cls`` receiver. Lambdas are not checked
(they cannot carry annotations).

Usage: ``python scripts/check_test_typing.py`` (scans ``tests/``); exits non-zero
and lists every offender if any def is missing an annotation.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent.parent / "tests"


def missing_annotations(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Return the reasons ``fn`` is not fully annotated (empty list == fully typed)."""
    reasons: list[str] = []
    if fn.returns is None:
        reasons.append("return")
    a = fn.args
    for i, arg in enumerate(a.posonlyargs + a.args):
        if i == 0 and arg.arg in ("self", "cls"):
            continue
        if arg.annotation is None:
            reasons.append(arg.arg)
    for arg in a.kwonlyargs:
        if arg.annotation is None:
            reasons.append(arg.arg)
    if a.vararg is not None and a.vararg.annotation is None:
        reasons.append("*" + a.vararg.arg)
    if a.kwarg is not None and a.kwarg.annotation is None:
        reasons.append("**" + a.kwarg.arg)
    return reasons


def main() -> int:
    offenders: list[str] = []
    for path in sorted(TESTS_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(TESTS_DIR.parent)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                reasons = missing_annotations(node)
                if reasons:
                    offenders.append(f"{rel}:{node.lineno}: {node.name} (missing: {', '.join(reasons)})")

    if offenders:
        sys.stderr.write("Untyped def(s) in the test suite — annotate every parameter and return:\n")
        for line in offenders:
            sys.stderr.write(f"  {line}\n")
        sys.stderr.write(f"\n{len(offenders)} untyped def(s). See scripts/check_test_typing.py.\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
