"""Benchmarks CI job installs its deps from legacy/benchmarks/requirements.txt (issue #1337).

The pins in legacy/benchmarks/requirements.txt only govern CI dependency resolution if the
workflow actually installs from that file; an ad-hoc `pip install <pkg>` resolves
unpinned latest and silently bypasses them.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _pinned_benchmark_packages() -> set[str]:
    names: set[str] = set()
    for line in (ROOT / "legacy/benchmarks/requirements.txt").read_text().splitlines():
        spec = line.split("#", 1)[0].strip()
        if spec:
            names.add(re.split(r"[=<>!~\[]", spec, maxsplit=1)[0].strip().lower())
    return names


def test_benchmarks_pins_govern_ci_via_the_runner_image() -> None:
    """The job no longer installs anything: it runs inside ci-runner, which bakes these
    pins. The property is unchanged -- legacy/benchmarks/requirements.txt must govern what CI
    resolves -- but its mechanism moved from a `pip install -r` step into the image, so
    the guard follows it rather than being dropped."""
    baked = (ROOT / ".github/docker/ci-requirements.txt").read_text()
    for name in _pinned_benchmark_packages():
        assert name in baked.lower(), (
            f"the runner image must bake the benchmarks pin {name!r}, or the job resolves "
            f"whatever PyPI serves and legacy/benchmarks/requirements.txt stops governing CI"
        )

    workflow = (ROOT / ".github/workflows/test.yml").read_text()
    assert "pip install" not in workflow, (
        "a pip install in the workflow would resolve alongside the baked toolchain and "
        "silently re-introduce the drift the image removes"
    )


def test_no_ad_hoc_install_of_pinned_benchmark_deps() -> None:
    pinned = _pinned_benchmark_packages()
    assert pinned, "legacy/benchmarks/requirements.txt must pin at least one package"
    for line in (ROOT / ".github/workflows/test.yml").read_text().splitlines():
        code = line.split(" #", 1)[0]
        if "pip install" not in code or "-r" in code.split():
            continue
        args = {re.split(r"[=<>!~\[]", arg, maxsplit=1)[0].lower() for arg in code.split()}
        offending = pinned & args
        assert not offending, (
            f"ad-hoc install of pinned benchmark dep(s) {sorted(offending)} bypasses "
            f"legacy/benchmarks/requirements.txt: {line.strip()!r}"
        )
