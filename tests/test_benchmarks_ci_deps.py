"""Benchmarks CI job installs its deps from benchmarks/requirements.txt (issue #1337).

The pins in benchmarks/requirements.txt only govern CI dependency resolution if the
workflow actually installs from that file; an ad-hoc `pip install <pkg>` resolves
unpinned latest and silently bypasses them.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _pinned_benchmark_packages() -> set[str]:
    names: set[str] = set()
    for line in (ROOT / "benchmarks/requirements.txt").read_text().splitlines():
        spec = line.split("#", 1)[0].strip()
        if spec:
            names.add(re.split(r"[=<>!~\[]", spec, maxsplit=1)[0].strip().lower())
    return names


def test_benchmarks_job_installs_from_requirements_file() -> None:
    workflow = (ROOT / ".github/workflows/test.yml").read_text()
    assert "pip install -r benchmarks/requirements.txt" in workflow, (
        "benchmarks job must install via benchmarks/requirements.txt so its pins govern CI"
    )


def test_no_ad_hoc_install_of_pinned_benchmark_deps() -> None:
    pinned = _pinned_benchmark_packages()
    assert pinned, "benchmarks/requirements.txt must pin at least one package"
    for line in (ROOT / ".github/workflows/test.yml").read_text().splitlines():
        code = line.split(" #", 1)[0]
        if "pip install" not in code or "-r" in code.split():
            continue
        offending = pinned & {arg.lower() for arg in code.split()}
        assert not offending, (
            f"ad-hoc install of pinned benchmark dep(s) {sorted(offending)} bypasses "
            f"benchmarks/requirements.txt: {line.strip()!r}"
        )
