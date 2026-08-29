"""Benchmarks CI job resolves its deps from the pyproject `bench` group (issue #1337).

The group's pins only govern CI dependency resolution if the workflow actually
installs from it; an ad-hoc `pip install <pkg>` resolves unpinned latest and silently
bypasses them.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from tests._workflow_steps import extract_after

ROOT = Path(__file__).resolve().parents[1]

# `pip` and `pip3` name the same installer, and both spellings are on a runner's PATH.
_PIP_INSTALL = re.compile(r"\bpip3?\s+install\b")


def _bench_group() -> list[str]:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return pyproject["dependency-groups"]["bench"]


def _pinned_benchmark_packages() -> set[str]:
    return {re.split(r"[=<>!~\[]", spec, maxsplit=1)[0].strip().lower() for spec in _bench_group()}


def _benchmarks_job() -> str:
    """The `benchmarks` job of test.yml, sliced at the next job key."""
    rest = extract_after((ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8"), "\n  benchmarks:\n")
    end = re.search(r"^  [A-Za-z0-9_.-]+:\s*$", rest, re.MULTILINE)
    return rest[: end.start()] if end else rest


def test_every_benchmark_dep_is_pinned_to_one_version() -> None:
    """A range would let the job resolve a different build run to run, which is the
    drift the group exists to stop -- uv.lock only freezes what the group constrains."""
    unpinned = sorted(spec for spec in _bench_group() if "==" not in spec)
    assert _bench_group(), "the `bench` dependency group must pin at least one package"
    assert unpinned == [], f"these benchmark deps are not pinned to an exact version: {unpinned}"


def test_benchmarks_job_syncs_the_locked_bench_group() -> None:
    """`--locked` is the whole point: it resolves against uv.lock, so the TRANSITIVE
    graph is pinned too. A bare `uv sync --group bench` would re-resolve and move a
    benchmark's dependencies with no diff anywhere."""
    job = _benchmarks_job()
    assert "uv sync --locked --group bench" in job, (
        "the benchmarks job must install its deps with `uv sync --locked --group bench`, "
        "or the pyproject `bench` group stops governing what CI resolves"
    )
    assert not _PIP_INSTALL.search(job), (
        "a pip install in the benchmarks job would resolve alongside the synced environment "
        "and silently re-introduce the drift the locked group removes"
    )


def _ad_hoc_installs(text: str, pinned: set[str]) -> list[str]:
    """Lines installing a pinned benchmark dep by name instead of from the group.

    `-r` requirements installs are not ad-hoc, and a trailing ` #` comment is prose.
    A shell-quoted spec (`"pympler==1.1"`) names the same package as a bare one, so
    the quotes come off before the name is read.
    """
    offenders: list[str] = []
    for line in text.splitlines():
        code = line.split(" #", 1)[0]
        if not _PIP_INSTALL.search(code) or "-r" in code.split():
            continue
        args = {re.split(r"[=<>!~\[]", arg.strip("\"'"), maxsplit=1)[0].strip("\"'").lower() for arg in code.split()}
        if pinned & args:
            offenders.append(line.strip())
    return offenders


def test_no_ad_hoc_install_of_pinned_benchmark_deps() -> None:
    pinned = _pinned_benchmark_packages()
    assert pinned, "the `bench` dependency group must pin at least one package"
    offenders = _ad_hoc_installs((ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8"), pinned)
    assert offenders == [], (
        f"these lines install a pinned benchmark dep by name, bypassing the pyproject `bench` group: {offenders}"
    )


def test_the_ad_hoc_scanner_reports_a_planted_bypass() -> None:
    """Vacuity guard: no workflow installs these by name today, so the guard above can
    only be trusted if the scanner still recognises the shape it forbids -- while a
    requirements-file install and a mention in a comment stay clean."""
    pinned = {"pympler"}
    assert _ad_hoc_installs("        run: pip install pympler==1.1\n", pinned) == ["run: pip install pympler==1.1"]
    assert _ad_hoc_installs("        run: pip3 install pympler==1.1\n", pinned) == ["run: pip3 install pympler==1.1"]
    assert _ad_hoc_installs('        run: pip install "pympler==1.1"\n', pinned) == ['run: pip install "pympler==1.1"']
    assert _ad_hoc_installs("        run: python3 -m pip install 'pympler==1.1'\n", pinned) == [
        "run: python3 -m pip install 'pympler==1.1'"
    ]
    assert _ad_hoc_installs("        run: pip install -r legacy/benchmarks/reqs.txt\n", pinned) == []
    assert _ad_hoc_installs("        # never pip install pympler here\n", pinned) == []
