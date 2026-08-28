"""Issue #2614: a CI job that can block on a kernel lock carries a wall-clock budget.

A `flock(2)`-family acquire has no timeout of its own, so a regression that leaves the
lock held makes the waiter block rather than fail. Probed for the issue (macOS, `lockf`):
a second acquirer of a held lock never returns -- `timeout 5 sh -c 'exec 9>L; lockf -k 9'`
exits 124 -- while the same acquire against a free lock exits 0 at once. Nothing inside
the suites bounds that wait, so the only bound left is the job's own `timeout-minutes`;
without one GitHub applies its 360-minute default and a deadlock reports as a platform
timeout hours later instead of as the assertion that names the cause.

What this file gates is therefore the *relationship*, not the one job the issue named:
every workflow job that runs a suite whose sources hold a kernel-lock acquire carries a
job-level `timeout-minutes` that is a real bound. Which suites those are is read from
source by `kernel_lock_acquires` and pinned by
`test_which_suite_roots_hold_kernel_lock_acquires`, so a suite that starts or stops
locking is a visible diff rather than a silent change in what this gate demands.

Why it was needed. On `origin/devel` at the time of writing, all four lock-reachable jobs
carried a budget, but `smoke-single.yml`'s `smoke` job (45) was defended by no test at
all: deleting that line left the whole suite green (5614 passed, 2 skipped) and
`actionlint` 1.7.12 silent. `test.yml`'s `test` and `php-unit` are pinned by
`test_issue2673_xdist_ci.py` and `ui-tests.yml`'s `ui` by
`test_smoke_ui_config_digest.py`, but nothing tied any of them to lock reachability, so a
new lock-reachable job would have landed unbudgeted with the suite green.

Jobs that call a reusable workflow are excluded: GitHub allows only
name/uses/with/secrets/needs/if/permissions/strategy there -- smoke.yml states that same
allow-list in its own comment -- so such a job cannot carry a budget, and the bound that
applies is the called job's, which this gate reads at its definition site.

Slices into the non-YAML config files go through `tests/_workflow_steps.py`, so a
reworded anchor raises instead of silently widening (issue #2669). Workflow structure is
read with `yaml`, whose missing key is `None` and cannot widen at all.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

from tests._workflow_steps import extract_after, extract_between, extract_job

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

# GitHub's default when a job declares no budget. A value at or above it is the platform
# default wearing a number, which is the condition this issue exists to remove.
GITHUB_DEFAULT_TIMEOUT_MINUTES = 360

# Runner token (at command position in a `run:` body) -> the suite root it executes.
# Every root is re-derived from the configuration the runner itself reads by
# `test_suite_roots_match_the_configuration_that_declares_them`, so the table cannot
# drift away from what the runners actually load.
SUITE_ROOTS: dict[str, str] = {
    "vendor/bin/phpunit": "tests/php",
    "pytest": "tests",
    "shellspec": "tests/shell",
    "scripts/run-smoke.sh": "tests/smoke",
}

# Command prefixes that carry a runner without being one: `uv run pytest`,
# `sh scripts/run-smoke.sh`, `DASH=dash shellspec`. Stripped left to right until the
# leading word is the command itself.
_PREFIX_WORDS = frozenset({"sh", "bash", "sudo", "env", "time", "exec", "uv", "run", "xargs", "python3", "-m"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# A logical command boundary inside a `run:` body.
_SEGMENT = re.compile(r"(?:\|\||&&|[|;&\n])")

# Kernel-lock acquires, by shape. `LOCK_UN` is a release and never matches. `flock()`
# requires a `$`-prefixed first argument so a prose mention ("...and flock().") is
# skipped -- the same discrimination `tests/test_bounded_flock.py` makes for the same
# reason. `file_put_contents(..., LOCK_EX)` is included because it takes a BLOCKING
# `flock(2)` exclusive lock, which the #1780 scanner (call-syntax only) does not see.
_ACQUIRE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"flock\s*\(\s*\$[^()]*LOCK_(?:EX|SH)"),
    re.compile(r"file_put_contents\s*\(.*LOCK_EX"),
    re.compile(r"fcntl\.(?:flock|lockf)\s*\("),
    re.compile(r"(?:^|[|;&(]\s*|\b(?:sh|bash|env|sudo|exec|timeout(?:\s+\S+)?)\s+)(?:lockf|flock)\s+-"),
)


def _tracked(root: str) -> list[Path]:
    """Tracked files under ``root``. `git ls-files`, not `rglob`: untracked scratch a
    developer left in the tree must not move this gate's verdict."""
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--", root],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [ROOT / name for name in listing.split("\0") if name]


def kernel_lock_acquires(root: str) -> list[str]:
    """``path:line`` for every kernel-lock acquire under ``root``.

    Reachability is a *may*, deliberately: a suite whose sources name an acquire counts
    as able to reach one, because the discrimination that would narrow it -- does this
    embedded snippet get executed or only written? -- is not something a regex can make.
    `tests/` scores hits it can only write (`test_bounded_flock.py`'s own PHP fixtures)
    alongside hits it really runs (`tests/smoke`'s appliance snippets). Over-inclusion
    costs a job a budget it already has; under-inclusion costs a six-hour hang.
    """
    found: list[str] = []
    for path in _tracked(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary fixture or broken symlink: carries no acquire either way
        for lineno, line in enumerate(text.splitlines(), start=1):
            if any(pattern.search(line) for pattern in _ACQUIRE_PATTERNS):
                found.append(f"{path.relative_to(ROOT)}:{lineno}")
    return found


def lock_bearing_roots() -> set[str]:
    return {root for root in set(SUITE_ROOTS.values()) if kernel_lock_acquires(root)}


def _strip_comment(line: str) -> str:
    stripped = line.strip()
    return "" if stripped.startswith("#") else stripped


def runners_in_run_body(body: str) -> set[str]:
    """Runner tokens ``body`` invokes *as commands*.

    A mention is not an invocation: `echo "shellspec shell tests failed"` and
    `--suite pytest` name a runner in argument position, and a `#` line only documents
    one. Keeping both out is what keeps this gate off jobs that merely talk about a suite
    -- test.yml's `all-tests-passed` AND gate is exactly that shape.
    """
    found: set[str] = set()
    for segment in _SEGMENT.split("\n".join(_strip_comment(line) for line in body.splitlines())):
        words = segment.strip().split()
        while words and (words[0] in _PREFIX_WORDS or _ASSIGNMENT.match(words[0])):
            words = words[1:]
        if words and words[0] in SUITE_ROOTS:
            found.add(words[0])
    return found


def _composite_run_bodies(uses: str) -> list[str]:
    """`run:` bodies of a local composite action, so a suite invoked one level down is
    still attributed to the job that reaches it."""
    action = ROOT / uses.lstrip("./")
    for candidate in (action / "action.yml", action / "action.yaml", action):
        if candidate.is_file():
            document = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            steps = (document.get("runs") or {}).get("steps") or []
            return [step["run"] for step in steps if isinstance(step, dict) and step.get("run")]
    return []


def suite_running_jobs() -> dict[tuple[str, str], set[str]]:
    """``(workflow file name, job id) -> runner tokens the job executes``.

    Jobs that call a reusable workflow are skipped -- they cannot carry a budget, and the
    called job's own budget is the bound that applies.
    """
    reached: dict[tuple[str, str], set[str]] = {}
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for job_id, job in (document.get("jobs") or {}).items():
            if not isinstance(job, dict) or job.get("uses"):
                continue
            runners: set[str] = set()
            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                if step.get("run"):
                    runners |= runners_in_run_body(step["run"])
                uses = step.get("uses")
                if isinstance(uses, str) and uses.startswith("./"):
                    for body in _composite_run_bodies(uses):
                        runners |= runners_in_run_body(body)
            if runners:
                reached[(path.name, job_id)] = runners
    return reached


def lock_reachable_jobs() -> set[tuple[str, str]]:
    bearing = lock_bearing_roots()
    return {
        job for job, runners in suite_running_jobs().items() if {SUITE_ROOTS[runner] for runner in runners} & bearing
    }


def budget_offences(sources: dict[str, str], reached: dict[tuple[str, str], set[str]]) -> list[str]:
    """One line per job that runs a lock-bearing suite without a usable budget."""
    bearing = lock_bearing_roots()
    offences: list[str] = []
    for (workflow, job_id), runners in sorted(reached.items()):
        roots = sorted({SUITE_ROOTS[runner] for runner in runners} & bearing)
        if not roots:
            continue
        body = extract_job(sources[workflow], job_id)
        hit = re.search(r"^    timeout-minutes:[ \t]*(.*\S)[ \t]*$", body, re.MULTILINE)
        where = f"{workflow}: job {job_id} runs {', '.join(sorted(runners))} (lock sites under {', '.join(roots)})"
        if hit is None:
            offences.append(f"{where}: no job-level timeout-minutes, so a stuck lock burns GitHub's 360-minute default")
            continue
        raw = hit.group(1)
        if not re.fullmatch(r"[1-9][0-9]*", raw):
            offences.append(f"{where}: timeout-minutes is {raw!r}, not a plain positive integer")
        elif int(raw) >= GITHUB_DEFAULT_TIMEOUT_MINUTES:
            offences.append(
                f"{where}: timeout-minutes is {raw}, at or above GitHub's "
                f"{GITHUB_DEFAULT_TIMEOUT_MINUTES}-minute default, so it bounds nothing"
            )
    return offences


def _workflow_sources() -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8") for path in sorted(WORKFLOWS.glob("*.y*ml"))}


# --------------------------------------------------------------------------- #
# The gate.
# --------------------------------------------------------------------------- #


def test_every_job_running_a_lock_bearing_suite_pins_timeout_minutes() -> None:
    """The issue's Expected, enforced for the whole class rather than the one job it
    named: a deadlock fails at the job's own budget, not at the platform default."""
    offences = budget_offences(_workflow_sources(), suite_running_jobs())
    assert not offences, "kernel-lock job budget missing:\n  " + "\n  ".join(offences)


def test_which_suite_roots_hold_kernel_lock_acquires() -> None:
    """The gate's premise, asserted rather than assumed.

    `tests/shell` holds none, which is why the shellspec jobs are deliberately NOT
    gated here: the `lockf -k 9` / `flock 9` the issue named lived in
    `scripts/agent/work-branch.sh` and was retired with the Graphify store, and no spec
    has acquired a kernel lock since. A lock landing in (or leaving) any root changes
    which jobs this file demands a budget from, so it must be a visible diff.
    """
    bearing = {root: len(kernel_lock_acquires(root)) for root in sorted(set(SUITE_ROOTS.values()))}
    assert {root for root, count in bearing.items() if count} == {
        "tests",
        "tests/php",
        "tests/smoke",
    }, bearing


def test_the_lock_reachable_jobs_are_the_ones_the_scan_finds() -> None:
    """The enumeration the issue's scope note asks for, in one place, so a job entering
    or leaving the class is a visible diff.

    The issue named only `shell-tests`; its scope note says the exposure comes from the
    primitives plus the missing budget, not from any one test.
    """
    assert lock_reachable_jobs() == {
        ("smoke-single.yml", "smoke"),
        ("test.yml", "php-unit"),
        ("test.yml", "test"),
        ("ui-tests.yml", "ui"),
    }, sorted(lock_reachable_jobs())


def test_suite_roots_match_the_configuration_that_declares_them() -> None:
    """`SUITE_ROOTS` re-derived from the files the runners themselves read, each slice
    bounded by its anchor so a reworded config line raises instead of passing."""
    phpunit = (ROOT / "phpunit.xml").read_text(encoding="utf-8")
    assert extract_between(phpunit, "<directory>", "</directory>") == SUITE_ROOTS["vendor/bin/phpunit"]

    ini = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pytest"]["ini_options"]
    assert ini["testpaths"] == [SUITE_ROOTS["pytest"]]

    shellspec = (ROOT / ".shellspec").read_text(encoding="utf-8")
    assert extract_after(shellspec, "--default-path ").split("\n", 1)[0].strip() == SUITE_ROOTS["shellspec"]

    run_smoke = (ROOT / "scripts" / "run-smoke.sh").read_text(encoding="utf-8")
    assert extract_between(run_smoke, '_PATHS="', '"') == SUITE_ROOTS["scripts/run-smoke.sh"]


# --------------------------------------------------------------------------- #
# Vacuity guards: every rule above fires on a planted offence.
# --------------------------------------------------------------------------- #


_PLANTED_JOB = {("planted.yml", "suite"): {"vendor/bin/phpunit"}}


@pytest.mark.parametrize(
    ("budget", "expected"),
    (
        ("", "no job-level timeout-minutes"),
        ("    timeout-minutes: ${{ inputs.budget }}\n", "not a plain positive integer"),
        ("    timeout-minutes: 0\n", "not a plain positive integer"),
        ("    timeout-minutes: -5\n", "not a plain positive integer"),
        (f"    timeout-minutes: {GITHUB_DEFAULT_TIMEOUT_MINUTES}\n", "bounds nothing"),
    ),
)
def test_the_gate_reports_a_planted_budget_offence(budget: str, expected: str) -> None:
    source = "jobs:\n  suite:\n    runs-on: ubuntu-latest\n" + budget + "    steps: []\n"
    offences = budget_offences({"planted.yml": source}, _PLANTED_JOB)
    assert len(offences) == 1 and expected in offences[0], offences


def test_the_gate_accepts_a_planted_job_that_carries_a_budget() -> None:
    source = "jobs:\n  suite:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    steps: []\n"
    assert budget_offences({"planted.yml": source}, _PLANTED_JOB) == []


def test_a_budget_nested_under_a_step_is_not_a_job_budget() -> None:
    """Six-space indentation puts the key on a step, where GitHub ignores it. The
    job-level regex must not accept it."""
    source = (
        "jobs:\n  suite:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - name: run\n        timeout-minutes: 15\n        run: true\n"
    )
    offences = budget_offences({"planted.yml": source}, _PLANTED_JOB)
    assert len(offences) == 1 and "no job-level timeout-minutes" in offences[0], offences


def test_a_renamed_planted_job_raises_instead_of_widening_the_slice() -> None:
    """The #2669 shape: an absent landmark must raise, never return the whole file --
    which would let the `timeout-minutes` search match a LATER job's budget and pass."""
    source = "jobs:\n  renamed:\n    timeout-minutes: 15\n    steps: []\n"
    with pytest.raises(ValueError, match="job 'suite' not found"):
        budget_offences({"planted.yml": source}, _PLANTED_JOB)


@pytest.mark.parametrize(
    "body",
    (
        "shellspec --shell dash",
        "uv run pytest --junitxml=/tmp/x.xml",
        "sh scripts/run-smoke.sh --paths tests/smoke",
        "vendor/bin/phpunit --coverage-text",
        'DASH=dash shellspec --shell "$DASH"',
        "make build && shellspec",
    ),
)
def test_the_runner_scan_sees_real_invocations(body: str) -> None:
    assert runners_in_run_body(body), body


@pytest.mark.parametrize(
    "body",
    (
        '        echo "shellspec shell tests failed or were cancelled."',
        "        # sh scripts/run-smoke.sh shells out to the synced interpreter",
        "        python3 scripts/check_skip_allowlist.py --suite pytest report.xml",
        '        installed="$(shellspec --version)"',
    ),
)
def test_the_runner_scan_ignores_mentions_that_are_not_invocations(body: str) -> None:
    assert runners_in_run_body(body) == set(), body


@pytest.mark.parametrize(
    "line",
    (
        "\tif ($lock === FALSE || !@flock($lock, LOCK_SH | LOCK_NB)) {",
        "\t\t$this->assertTrue(flock($holder, LOCK_EX));",
        "\t@file_put_contents($path, $content, LOCK_EX);",
        "        fcntl.flock(handle, fcntl.LOCK_EX)",
        "\t\t( exec 9>lockfile; lockf -k 9; sleep 30 ) &",
        "timeout 5 sh -c 'exec 9>L; flock -w 0 9'",
    ),
)
def test_the_acquire_scan_sees_every_acquire_shape(line: str) -> None:
    assert any(pattern.search(line) for pattern in _ACQUIRE_PATTERNS), line


@pytest.mark.parametrize(
    "line",
    (
        "\t@flock($lock, LOCK_UN);",
        "\t// A waiter can be descheduled between its deadline check and flock().",
        "# The flock inside _rebuild_code still prevents pile-ups",
        "45 lockf /usr/bin/lockf -s -t 5 /tmp/pfSense-upgrade.lock",
    ),
)
def test_the_acquire_scan_ignores_releases_prose_and_fixture_text(line: str) -> None:
    assert not any(pattern.search(line) for pattern in _ACQUIRE_PATTERNS), line
