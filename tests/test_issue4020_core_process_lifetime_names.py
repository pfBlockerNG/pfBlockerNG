"""issue #4020: the native process-lifetime smoke runs Go tests by name on a pfSense box and requires each to PASS.

A Go test that is renamed or removed must fail here, in the hermetic suite, instead of only on the lab pool.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.smoke.test_core_process_lifetime import CASES

GO_DIR = Path(__file__).resolve().parents[1] / "go" / "pfb_core"


def _built_for_freebsd(source: str) -> bool:
    """A file counts as built for the box only without a constraint, or with a plain ``a || b`` list naming freebsd.

    The expression is not evaluated: any ``!``, ``&&`` or parenthesis reads as excluded (``!freebsd``,
    ``freebsd && linux``, and ``!windows`` too), so the guard fails loudly instead of accepting a file the FreeBSD
    build leaves out.
    """
    constraint = re.search(r"^//go:build (.*)$", source, flags=re.MULTILINE)
    if constraint is None:
        return True
    tags = [tag.strip() for tag in constraint[1].split("||")]
    return "freebsd" in tags and all(re.fullmatch(r"\w+", tag) for tag in tags)


@pytest.mark.parametrize(
    ("constraint", "built"),
    [
        (None, True),
        ("freebsd", True),
        ("linux || freebsd", True),
        ("linux", False),
        ("!freebsd", False),
        ("!(linux || freebsd)", False),
        ("!windows", False),
        ("freebsd && linux", False),
        ("!(windows || freebsd || linux)", False),
    ],
)
def test_only_a_constraint_that_plainly_names_freebsd_counts_as_built_for_the_box(
    constraint: str | None, built: bool
) -> None:
    source = "package p\n" if constraint is None else f"//go:build {constraint}\n\npackage p\n"
    assert _built_for_freebsd(source) is built, f"//go:build {constraint}: want built={built}"


def test_every_named_go_test_is_declared_in_its_package() -> None:
    assert CASES, "CASES is empty; the guard would pass vacuously"
    empty = [case for case, (_, tests) in CASES.items() if not tests]
    assert not empty, f"cases with no test names: {empty}"

    missing: list[str] = []
    for case, (package, tests) in sorted(CASES.items()):
        sources = [p.read_text(encoding="utf-8") for p in sorted((GO_DIR / package).glob("*_test.go"))]
        source = "\n".join(s for s in sources if _built_for_freebsd(s))
        declared = set(re.findall(r"^func (\w+)\(t \*testing\.T\)", source, flags=re.MULTILINE))
        missing += [f"{package} ({case}): {name}" for name in tests if name not in declared]
    assert not missing, "Go tests named by the smoke module are not declared:\n" + "\n".join(missing)
