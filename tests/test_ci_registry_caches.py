"""Guard: these jobs must not re-fetch from npm or PyPI on every run (#3884).

`markdownlint-cli2` is baked into the ci image, so the markdownlint job runs the binary rather than
`npx --yes`. The jobs that still install at job time (the webassets drift guard's `npm ci`, and every
`uv sync` of the dependency-package toolchain) restore the package manager's download cache first, as
the `test-typing` job in test.yml does.

A cache step counts only when it is an `actions/cache@` step on the manager's directory, keyed on the
lock file the install reads, and it sits BEFORE the first step that fetches and runs whenever that step
does: a cache restored after the install, or skipped while the install runs, caches nothing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
_WORKFLOWS = ROOT / ".github/workflows"

Step = dict[str, Any]

_NPM_LOCK = "tools/webassets/package-lock.json"
# (workflow, job): every job that runs `uv sync` at job time
_UV_JOBS = [
    ("build-pkg-linux.yml", "build"),
    ("nightly.yml", "build"),
    ("nightly.yml", "resolve-live-stable-identity"),
    ("release.yml", "build-pkgs-portable"),
]


def _steps(workflow: str, job: str) -> list[Step]:
    document = yaml.safe_load((_WORKFLOWS / workflow).read_text(encoding="utf-8"))
    steps: list[Step] = document["jobs"][job]["steps"]
    return steps


def _first_running(steps: list[Step], pattern: str) -> int | None:
    """Index of the first step whose `run:` matches `pattern`."""
    return next((i for i, step in enumerate(steps) if re.search(pattern, step.get("run", ""))), None)


def _cache_gaps(steps: list[Step], fetching: int, path: str, lock: str) -> list[str]:
    """Why the job does not cache `path` ahead of step `fetching`; [] when it does."""
    caches = [
        i
        for i, s in enumerate(steps)
        if str(s.get("uses", "")).startswith("actions/cache@") and (s.get("with") or {}).get("path") == path
    ]
    if not caches:
        return [f"no actions/cache@ step on {path}"]
    cache = steps[caches[0]]
    gaps = []
    if caches[0] > fetching:
        gaps.append(f"the cache is step {caches[0]}, after the fetching step {fetching}")
    if f"hashFiles('{lock}')" not in cache["with"].get("key", ""):
        gaps.append(f"the key `{cache['with'].get('key')}` does not hash {lock}")
    if cache.get("if") != steps[fetching].get("if"):
        gaps.append(f"the cache runs on {cache.get('if')!r}, the fetching step on {steps[fetching].get('if')!r}")
    return gaps


def test_the_markdownlint_job_runs_the_baked_binary_not_npx() -> None:
    steps = _steps("test.yml", "markdownlint")

    assert _first_running(steps, r"\bmarkdownlint-cli2\b") is not None, (
        "the markdownlint job must run markdownlint-cli2"
    )
    assert _first_running(steps, r"\bnpx\b") is None, (
        "the markdownlint job fetches markdownlint-cli2 with npx on every run"
    )


def test_the_webassets_job_caches_the_npm_downloads_before_its_first_npm_step() -> None:
    steps = _steps("test.yml", "webassets-vendor")
    # check_webassets_vendor.py runs build-webassets.sh, which runs `npm ci`
    first_npm = _first_running(steps, r"\bnpm\b|check_webassets_vendor\.py")

    assert first_npm is not None, "webassets-vendor has no npm step, so the test guards nothing"
    gaps = _cache_gaps(steps, first_npm, "~/.npm", _NPM_LOCK)
    assert gaps == [], f"webassets-vendor must cache ~/.npm: {gaps}"


def _uv_lock_read_by(sync_run: str) -> str:
    return "trusted/uv.lock" if re.search(r"--project\s+trusted\b", sync_run) else "uv.lock"


@pytest.mark.parametrize(("workflow", "job"), _UV_JOBS, ids=[f"{w}:{j}" for w, j in _UV_JOBS])
def test_a_job_that_syncs_uv_caches_the_downloads_first(workflow: str, job: str) -> None:
    steps = _steps(workflow, job)
    sync = _first_running(steps, r"\buv sync\b")

    assert sync is not None, f"{workflow} job {job} has no `uv sync` step, so the test guards nothing"
    gaps = _cache_gaps(steps, sync, "~/.cache/uv", _uv_lock_read_by(steps[sync]["run"]))
    assert gaps == [], f"{workflow} job {job} must cache ~/.cache/uv: {gaps}"


@pytest.mark.parametrize(("workflow", "job"), _UV_JOBS, ids=[f"{w}:{j}" for w, j in _UV_JOBS])
def test_a_job_that_syncs_one_uv_group_keys_its_cache_on_that_group(workflow: str, job: str) -> None:
    """test.yml's jobs save the `dev` group under `uv-<lock hash>`. Sharing that key, a job syncing
    another group gets an exact hit holding none of its packages, and an exact hit never saves."""
    steps = _steps(workflow, job)
    sync = _first_running(steps, r"\buv sync\b")
    assert sync is not None, f"{workflow} job {job} has no `uv sync` step, so the test guards nothing"
    group = re.search(r"--only-group\s+(\S+)", steps[sync]["run"])
    assert group, f"{workflow} job {job} syncs no single group: {steps[sync]['run']!r}"
    cache = next(s for s in steps if (s.get("with") or {}).get("path") == "~/.cache/uv")
    prefix = f"uv-{group.group(1)}-"

    assert cache["with"]["key"].startswith(prefix), f"{workflow} job {job} key {cache['with']['key']!r}"
    assert cache["with"].get("restore-keys") == prefix, f"{workflow} job {job} restore-keys must be {prefix!r}"


def test_the_cache_check_rejects_each_way_a_cache_can_cache_nothing() -> None:
    """Vacuity guard: a compliant job passes; no cache, a late cache, a key on the wrong lock and a
    cache that skips when the install runs are each reported."""
    cache = {"uses": "actions/cache@v6", "with": {"path": "~/.cache/uv", "key": "uv-${{ hashFiles('uv.lock') }}"}}
    sync = {"run": "uv sync --locked", "if": "inputs.x"}

    def gaps(*steps: Step, lock: str = "uv.lock") -> list[str]:
        return _cache_gaps(list(steps), steps.index(sync), "~/.cache/uv", lock)

    assert gaps({**cache, "if": "inputs.x"}, sync) == []
    assert gaps(sync) == ["no actions/cache@ step on ~/.cache/uv"]
    assert gaps(sync, {**cache, "if": "inputs.x"}) == ["the cache is step 1, after the fetching step 0"]
    assert gaps({**cache, "if": "inputs.x"}, sync, lock="trusted/uv.lock") == [
        "the key `uv-${{ hashFiles('uv.lock') }}` does not hash trusted/uv.lock"
    ]
    assert gaps(cache, sync) == ["the cache runs on None, the fetching step on 'inputs.x'"]
