"""Issue #2614: every workflow job that can reach a kernel-lock acquire is bounded.

A `flock(2)`-family acquire takes no timeout, so the only bound above a stuck lock is the
job's own `timeout-minutes`; without one GitHub applies its 360-minute default and a
deadlock reports as a platform timeout rather than as the assertion that names the cause.

The gated contract is the relationship, not one job: a job that reaches a tree holding a
kernel-lock acquire declares a job-level `timeout-minutes` that is a plain positive
integer below that default. `SUITE_RUNNERS` maps each runner to the trees it EXECUTES, so
a lock arriving anywhere a suite drives pulls that suite's jobs into the contract.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

from tests._workflow_steps import extract_after, extract_between

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

# GitHub's default when a job declares no budget. A value at or above it is the platform
# default wearing a number, which is the condition this issue exists to remove.
GITHUB_DEFAULT_TIMEOUT_MINUTES = 360

# The pytest root is scoped to the top-level `tests/*.py` pytest can collect: `testpaths`
# is `tests`, but that pathspec subsumes `tests/php` and `tests/smoke`, which pytest never
# collects (not Python) and which other runners own. Unscoped, the premise assertion below
# could never be false.
PYTEST_ROOT = ":(glob)tests/*.py"

# Runner token (at command position in a `run:` body) -> every tree it EXECUTES.
# A suite reaches more than its own directory: shellspec drives `scripts/`, PHPUnit loads
# the real `src/` .inc, and the live-VM harness runs the installed package.
SUITE_RUNNERS: dict[str, tuple[str, ...]] = {
    "vendor/bin/phpunit": ("tests/php", "src"),
    "pytest": (PYTEST_ROOT,),
    "shellspec": ("tests/shell", "scripts"),
    "scripts/run-smoke.sh": ("tests/smoke", "src"),
}

# Production entry points -> `src`, matched as a SUBSTRING of any non-comment `run:` line.
# Substring, not command position, because these arrive through indirection no command
# matcher can chase: build-image.yml runs `tests/smoke/roundtrip.sh` (which shells
# `pfblockerng.php update`) and image-refresh.yml wraps the same entry point in
# `run_ssh '...'`. Naming either in a live run body means driving production code.
PRODUCTION_ENTRY_POINTS: dict[str, tuple[str, ...]] = {
    "pfblockerng.php": ("src",),
    "tests/smoke/roundtrip.sh": ("src",),
}

REACHED_ROOTS: dict[str, tuple[str, ...]] = {**SUITE_RUNNERS, **PRODUCTION_ENTRY_POINTS}
ALL_ROOTS: tuple[str, ...] = tuple(sorted({root for roots in REACHED_ROOTS.values() for root in roots}))

# Words that can precede a runner without being one, stripped left to right until the
# leading word is the command: `uv run pytest`, `sh scripts/run-smoke.sh`,
# `python -m pytest`, `timeout 600 vendor/bin/phpunit`, `nice -n 5 shellspec`,
# `if ! pytest`, `{ pytest; }`. `command`/`builtin` cover `command pytest`; that also
# makes `command -v shellspec` read as an invocation, which is over-inclusion in the safe
# direction.
_PREFIX_WORDS = frozenset(
    {
        "sh",
        "bash",
        "sudo",
        "env",
        "time",
        "exec",
        "uv",
        "run",
        "xargs",
        "poetry",
        "nice",
        "timeout",
        "command",
        "builtin",
        "if",
        "then",
        "elif",
        "else",
        "do",
        "while",
        "until",
        "!",
        "-m",
    }
)
_PREFIX_SHAPES = (
    re.compile(r"^python[0-9.]*$"),  # python, python3, python3.11
    re.compile(r"^-"),  # a flag of an already-stripped prefix
    # A wrapper's duration/count operand: `timeout 600`, `timeout 10m`, `timeout 1.5h`,
    # `nice 10`. GNU timeout's s/m/h/d suffixes are ordinary workflow syntax, so a
    # digits-only shape would leave the runner behind `timeout 10m` unreached.
    re.compile(r"^[0-9]+(?:\.[0-9]+)?[smhd]?$"),
    re.compile(r"^[A-Za-z_][A-Za-z0-9_]*="),  # VAR=value prefix assignment
)
_SEGMENT = re.compile(r"(?:\|\||&&|[|;&\n])")  # a logical command boundary
_STRIP_CHARS = "(){}\"'`"  # grouping punctuation, not command words

# Kernel-lock acquires, by shape. Every pattern is LINE-based and each names one of
# `_PREFILTER_TOKENS`, which is what makes the prefilter a sound superset. `LOCK_UN` is a
# release and never matches.
_ACQUIRE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # PHP flock(). A `$` must appear in the arguments so a prose mention ("...between its
    # deadline check and flock().") stays out, while `self::$fp` and `$this->fp` match.
    re.compile(r"flock\s*\(\s*[^();]*\$[^();]*LOCK_(?:EX|SH)"),
    # file_put_contents(..., LOCK_EX) takes a real BLOCKING flock(2) LOCK_EX -- probed at
    # 0.504 s against a holder releasing after 0.5 s. `[^;]` keeps a match in one
    # statement. The #1780 scanner misses this shape; it reads flock( call syntax only.
    re.compile(r"file_put_contents\s*\([^;]*LOCK_EX"),
    # The ARGUMENT line of a wrapped acquire (`flock(\n\t$fp,\n\tLOCK_EX\n);`), invisible
    # to the line-scoped patterns above. The constant must be the last thing on the line
    # apart from delimiters, which is what keeps mid-line prose out; comment markers are
    # excluded as well, so `// LOCK_EX, and the deadline` and `/* LOCK_EX */` do not match.
    re.compile(r"^[^;/*#]*LOCK_(?:EX|SH)\b[^;/*#]*[,)\s]*;?\s*$"),
    re.compile(r"fcntl\.(?:flock|lockf)\s*\("),
    # flock(1)/lockf(1) at command position, including the bare-fd form this issue names
    # (`exec 9>L; flock 9`, `lockf -k 9`, `flock $fd`). The operand may be quoted, which
    # is this repository's shell convention (`flock "$fd"`, `flock "${fd}"`).
    re.compile(r"""(?:^|[|;&(]\s*|\b(?:sh|bash|env|sudo|exec|timeout(?:\s+\S+)?)\s+)(?:lockf|flock)\s+['"]?[-\d$]"""),
)

_PREFILTER_TOKENS = ("LOCK_EX", "LOCK_SH", "flock", "lockf", "fcntl")


def _candidate_files(root: str) -> list[Path]:
    """Tracked files under ``root`` that could hold an acquire.

    `git grep -l` over the loose token list rather than reading every tracked file: a
    sound superset, and it stops re-reading ~1000 files once per root. Tracked-only, so
    untracked scratch cannot move the verdict. `git grep` exits 1 for "no match", which is
    not an error; any other status raises instead of reading as an empty scan.
    """
    argv = ["git", "grep", "-l", "-F"]
    for token in _PREFILTER_TOKENS:
        argv += ["-e", token]
    result = subprocess.run([*argv, "--", root], cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode not in (0, 1):
        raise OSError(f"git grep failed for {root!r}: {result.stderr.strip()}")
    return [ROOT / name for name in result.stdout.split("\n") if name]


def kernel_lock_acquires(root: str) -> list[str]:
    """``path:line`` for every kernel-lock acquire under ``root``.

    Reachability is a MAY, and the scan errs toward over-inclusion: whether an embedded
    snippet is executed or merely written is not something a regex can decide, so a tree
    naming an acquire counts as able to reach one. Over-inclusion costs a job a budget it
    already has; under-inclusion costs a six-hour hang.

    An unreadable candidate RAISES. `_candidate_files` only returns files `git grep`
    already matched on a lock token, so one that cannot then be read is a broken
    assumption, not a benign skip -- and swallowing it would drop a file known to name a
    lock, which is the vacuous-scan shape this gate exists to prevent.
    """
    found: list[str] = []
    for path in _candidate_files(root):
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise OSError(f"candidate {path.relative_to(ROOT)} names a lock token but cannot be read: {exc}") from exc
        # errors="replace", never a skip: an except-and-continue on UnicodeDecodeError
        # silently dropped a tracked latin-1 .inc holding a real flock($fp, LOCK_EX).
        for lineno, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
            if any(pattern.search(line) for pattern in _ACQUIRE_PATTERNS):
                found.append(f"{path.relative_to(ROOT)}:{lineno}")
    return found


def lock_bearing_roots() -> set[str]:
    return {root for root in ALL_ROOTS if kernel_lock_acquires(root)}


def _is_prefix(word: str) -> bool:
    return word in _PREFIX_WORDS or any(shape.match(word) for shape in _PREFIX_SHAPES)


def _command_word(raw: str) -> str:
    """``raw`` reduced to the command word it carries.

    Strips grouping punctuation and a command-substitution opener, so
    `"$(command -v shellspec)" --shell dash` reaches `command` (a prefix) and then
    `shellspec`. A runner buried in a NESTED shell string with its own quoting
    (`sh -c 'a && b'`) is only seen when the inner command leads; deeper nesting is
    deliberately out of scope, and stated here rather than left implicit.
    """
    return raw.strip(_STRIP_CHARS).removeprefix("$(").strip(_STRIP_CHARS)


def _runner_for(word: str) -> str | None:
    """The runner ``word`` invokes, tolerating `./` and any leading path."""
    candidate = word.removeprefix("./")
    for token in SUITE_RUNNERS:
        if candidate == token or candidate.endswith("/" + token):
            return token
    return None


def runners_in_run_body(body: str) -> set[str]:
    """Suite runners ``body`` invokes as commands, plus production entry points it names.

    A mention is not an invocation: `echo "shellspec shell tests failed"` and
    `--suite pytest` put a runner in argument position, and a `#` line only documents one.
    Keeping both out is what keeps this gate off jobs that merely talk about a suite --
    test.yml's `all-tests-passed` AND gate is exactly that shape.
    """
    found: set[str] = set()
    live = [line.strip() for line in body.splitlines() if not line.strip().startswith("#")]
    for line in live:
        found |= {entry for entry in PRODUCTION_ENTRY_POINTS if entry in line}
    for segment in _SEGMENT.split("\n".join(live)):
        words = [stripped for word in segment.split() if (stripped := _command_word(word))]
        while words:
            if (runner := _runner_for(words[0])) is not None:
                found.add(runner)
                break
            if not _is_prefix(words[0]):
                break
            was_flag = words[0].startswith("-")
            words = words[1:]
            # A wrapper option can take a VALUE (`uv run --group dev pytest`,
            # `env -u NAME pytest`): drop it too, unless it is itself a runner or another
            # prefix, so the runner behind it is still reached.
            if was_flag and words and not _is_prefix(words[0]) and _runner_for(words[0]) is None:
                words = words[1:]
    return found


def _local_action_run_bodies(uses: str, seen: frozenset[str] = frozenset()) -> list[str]:
    """Every `run:` body a LOCAL composite action reaches, following nested `uses: ./...`.

    A composite action is ordinary GitHub Actions, so a suite invoked inside one belongs
    to the job that reaches it. Recursive with cycle detection: a one-level walk would
    give false assurance, and a self- or mutually-referential action must not hang the
    gate. Docker- and node-based local actions are NOT followed -- their entry point is an
    image or a script, not a `run:` body -- and no local action in this repository uses
    either form.
    """
    reference = uses.split("@", 1)[0]
    if reference in seen:
        return []
    action = ROOT / reference.removeprefix("./")
    for candidate in (action / "action.yml", action / "action.yaml"):
        if not candidate.is_file():
            continue
        document = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
        bodies: list[str] = []
        for step in (document.get("runs") or {}).get("steps") or []:
            if not isinstance(step, dict):
                continue
            if step.get("run"):
                bodies.append(step["run"])
            nested = step.get("uses")
            if isinstance(nested, str) and nested.startswith("./"):
                bodies.extend(_local_action_run_bodies(nested, seen | {reference}))
        return bodies
    return []


def _documents() -> dict[str, dict]:
    return {
        path.name: (yaml.safe_load(path.read_text(encoding="utf-8")) or {}) for path in sorted(WORKFLOWS.glob("*.y*ml"))
    }


def suite_running_jobs(documents: dict[str, dict] | None = None) -> dict[tuple[str, str], set[str]]:
    """``(workflow file name, job id) -> the runners / entry points the job reaches``.

    Jobs that call a reusable workflow are skipped: GitHub allows only
    name/uses/with/secrets/needs/if/permissions/strategy there -- smoke.yml states that
    allow-list in its own comment -- so they cannot carry a budget, and the bound that
    applies is the called job's, which this gate reads at its definition site.
    """
    reached: dict[tuple[str, str], set[str]] = {}
    for name, document in (documents if documents is not None else _documents()).items():
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
                    for step_body in _local_action_run_bodies(uses):
                        runners |= runners_in_run_body(step_body)
            if runners:
                reached[(name, job_id)] = runners
    return reached


def _reached_bearing_roots(runners: set[str], bearing: set[str]) -> list[str]:
    return sorted({root for runner in runners for root in REACHED_ROOTS[runner]} & bearing)


def lock_reachable_jobs() -> set[tuple[str, str]]:
    bearing = lock_bearing_roots()
    return {job for job, runners in suite_running_jobs().items() if _reached_bearing_roots(runners, bearing)}


_MISSING = object()


def budget_offences(documents: dict[str, dict], reached: dict[tuple[str, str], set[str]]) -> list[str]:
    """One line per job that reaches a lock-bearing tree without a usable budget.

    Read from the parsed document, never a text slice: YAML is what GitHub reads, and a
    quoted sibling job key walks past `extract_job`'s boundary and lets a LATER job's
    budget satisfy the search.

    There is a ceiling and deliberately no floor. A budget at or above GitHub's default
    bounds nothing and is silent, which is the hazard; an absurdly tight one fails on the
    next run and is self-revealing. A floor would put a wall-clock number in an assertion.
    """
    bearing = lock_bearing_roots()
    offences: list[str] = []
    for (workflow, job_id), runners in sorted(reached.items()):
        roots = _reached_bearing_roots(runners, bearing)
        if not roots:
            continue
        job = (documents[workflow].get("jobs") or {})[job_id]
        raw = job.get("timeout-minutes", _MISSING)
        where = f"{workflow}: job {job_id} reaches {', '.join(sorted(runners))} (lock sites under {', '.join(roots)})"
        if raw is _MISSING:
            offences.append(f"{where}: no job-level timeout-minutes, so a stuck lock burns GitHub's 360-minute default")
        elif not isinstance(raw, int) or isinstance(raw, bool) or raw <= 0:
            offences.append(f"{where}: timeout-minutes is {raw!r}, not a plain positive integer")
        elif raw >= GITHUB_DEFAULT_TIMEOUT_MINUTES:
            offences.append(
                f"{where}: timeout-minutes is {raw}, at or above GitHub's "
                f"{GITHUB_DEFAULT_TIMEOUT_MINUTES}-minute default, so it bounds nothing"
            )
    return offences


# --------------------------------------------------------------------------- #
# The gate.
# --------------------------------------------------------------------------- #


def test_every_job_reaching_a_lock_bearing_tree_pins_timeout_minutes() -> None:
    """The issue's Expected, enforced for the whole class rather than the one job it
    named: a deadlock fails at the job's own budget, not at the platform default."""
    documents = _documents()
    offences = budget_offences(documents, suite_running_jobs(documents))
    assert not offences, "kernel-lock job budget missing:\n  " + "\n  ".join(offences)


def test_which_roots_hold_kernel_lock_acquires() -> None:
    """The gate's premise, asserted rather than assumed, and falsifiable in both
    directions.

    `scripts` and `tests/shell` hold none today: the `lockf -k 9` / `flock 9` this issue
    names lived in `scripts/agent/work-branch.sh` and was retired with the Graphify store.
    Reintroducing a lock there flips `scripts` to bearing and pulls the shellspec jobs
    into the gate -- which is the regression class the issue is about, so it must be a
    visible diff either way.
    """
    counts = {root: len(kernel_lock_acquires(root)) for root in ALL_ROOTS}
    assert {root for root, count in counts.items() if count} == {
        "src",
        PYTEST_ROOT,
        "tests/php",
        "tests/smoke",
    }, counts


def test_the_lock_reachable_jobs_are_the_ones_the_scan_finds() -> None:
    """The enumeration the issue's scope note asks for, in one place, so a job entering or
    leaving the class is a visible diff. The issue named only `shell-tests`; its scope note
    says the exposure comes from the primitives plus the missing budget, not one test."""
    found = lock_reachable_jobs()
    assert found == {
        ("build-image.yml", "verify-image"),
        ("image-refresh.yml", "refresh"),
        ("smoke-single.yml", "smoke"),
        ("test.yml", "php-unit"),
        ("test.yml", "test"),
        ("ui-tests.yml", "ui"),
    }, sorted(found)


def test_suite_roots_match_the_configuration_that_declares_them() -> None:
    """Each root re-derived from the config the runner itself reads, every slice bounded by
    its anchor so a reworded config line raises instead of passing."""
    phpunit = (ROOT / "phpunit.xml").read_text(encoding="utf-8")
    assert extract_between(phpunit, "<directory>", "</directory>") in SUITE_RUNNERS["vendor/bin/phpunit"]

    ini = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["pytest"]["ini_options"]
    assert ini["testpaths"] == ["tests"]
    assert "--ignore=tests/smoke" in ini["addopts"].split()
    assert PYTEST_ROOT.endswith("tests/*.py")

    shellspec = (ROOT / ".shellspec").read_text(encoding="utf-8")
    assert extract_after(shellspec, "--default-path ").split("\n", 1)[0].strip() in SUITE_RUNNERS["shellspec"]

    run_smoke = (ROOT / "scripts" / "run-smoke.sh").read_text(encoding="utf-8")
    assert extract_between(run_smoke, '_PATHS="', '"') in SUITE_RUNNERS["scripts/run-smoke.sh"]

    # roundtrip.sh maps to `src` because it drives the production reload entry point.
    roundtrip = (ROOT / "tests" / "smoke" / "roundtrip.sh").read_text(encoding="utf-8")
    assert extract_between(roundtrip, 'PHP_CLI="', '"').endswith("pfblockerng.php")
    assert PRODUCTION_ENTRY_POINTS["tests/smoke/roundtrip.sh"] == ("src",)


# --------------------------------------------------------------------------- #
# Vacuity guards: every rule above fires on a planted offence.
# --------------------------------------------------------------------------- #


_PLANTED_JOB = {("planted.yml", "suite"): {"vendor/bin/phpunit"}}


def _planted(budget: object) -> dict[str, dict]:
    job: dict[str, object] = {"runs-on": "ubuntu-latest", "steps": []}
    if budget is not _MISSING:
        job["timeout-minutes"] = budget
    return {"planted.yml": {"jobs": {"suite": job}}}


@pytest.mark.parametrize(
    ("budget", "expected"),
    (
        (_MISSING, "no job-level timeout-minutes"),
        ("${{ inputs.budget }}", "not a plain positive integer"),
        ("20", "not a plain positive integer"),
        (0, "not a plain positive integer"),
        (-5, "not a plain positive integer"),
        (20.0, "not a plain positive integer"),
        (True, "not a plain positive integer"),
        (GITHUB_DEFAULT_TIMEOUT_MINUTES, "bounds nothing"),
        (100000, "bounds nothing"),
    ),
)
def test_the_gate_reports_a_planted_budget_offence(budget: object, expected: str) -> None:
    offences = budget_offences(_planted(budget), _PLANTED_JOB)
    assert len(offences) == 1 and expected in offences[0], offences


def test_the_gate_accepts_a_planted_job_that_carries_a_budget() -> None:
    assert budget_offences(_planted(15), _PLANTED_JOB) == []


@pytest.mark.parametrize(
    ("label", "source"),
    (
        (
            "quoted sibling job key",
            'jobs:\n  suite:\n    steps: []\n  "other":\n    timeout-minutes: 5\n    steps: []\n',
        ),
        (
            "budget nested under a step",
            "jobs:\n  suite:\n    steps:\n      - name: run\n        timeout-minutes: 15\n        run: 'true'\n",
        ),
    ),
)
def test_a_budget_that_is_not_the_job_s_own_does_not_satisfy_the_gate(label: str, source: str) -> None:
    """Two false-pass shapes a text slice allows. `extract_job`'s sibling boundary does not
    recognise a QUOTED job key, so a slice runs into the next job and its budget satisfies
    the search; and GitHub ignores a step-level key as a job bound. Reading the parsed
    document cannot be fooled by either."""
    offences = budget_offences({"planted.yml": yaml.safe_load(source)}, _PLANTED_JOB)
    assert len(offences) == 1 and "no job-level timeout-minutes" in offences[0], (label, offences)


@pytest.mark.parametrize(
    ("body", "expected"),
    (
        ("shellspec --shell dash", {"shellspec"}),
        ("uv run pytest --junitxml=/tmp/x.xml", {"pytest"}),
        ("python -m pytest -q", {"pytest"}),
        ("python3.11 -m pytest", {"pytest"}),
        ("uv run python -m pytest", {"pytest"}),
        ("sh scripts/run-smoke.sh --paths tests/smoke", {"scripts/run-smoke.sh"}),
        ("./scripts/run-smoke.sh --paths tests/smoke", {"scripts/run-smoke.sh"}),
        ('"$GITHUB_WORKSPACE"/scripts/run-smoke.sh -m smoke', {"scripts/run-smoke.sh"}),
        ("vendor/bin/phpunit --coverage-text", {"vendor/bin/phpunit"}),
        ("./vendor/bin/phpunit", {"vendor/bin/phpunit"}),
        ('DASH=dash shellspec --shell "$DASH"', {"shellspec"}),
        ("make build && shellspec", {"shellspec"}),
        ("timeout 600 vendor/bin/phpunit", {"vendor/bin/phpunit"}),
        ("timeout 60 sh scripts/run-smoke.sh", {"scripts/run-smoke.sh"}),
        ("timeout --foreground 60 sh scripts/run-smoke.sh", {"scripts/run-smoke.sh"}),
        ("nice -n 5 shellspec", {"shellspec"}),
        ("if ! pytest -q; then echo no; fi", {"pytest"}),
        ("(pytest)", {"pytest"}),
        ("{ pytest; }", {"pytest"}),
        ("command pytest", {"pytest"}),
        ("tests/smoke/roundtrip.sh smoke_key a b", {"tests/smoke/roundtrip.sh"}),
        ("run_ssh '/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php update'", {"pfblockerng.php"}),
        ('"$(command -v shellspec)" --shell dash', {"shellspec"}),
        ("poetry run pytest", {"pytest"}),
        ('"$HOME/shellspec/shellspec" --shell dash', {"shellspec"}),
        ("if command -v pytest; then pytest; fi", {"pytest"}),
        ("for v in a b; do shellspec; done", {"shellspec"}),
        ("bash -c 'shellspec'", {"shellspec"}),
        # A wrapper option that takes a VALUE must not hide the runner behind it.
        ("uv run --group dev pytest", {"pytest"}),
        ("env -u PYTHONPATH pytest", {"pytest"}),
        ("uv run --python 3.11 pytest -q", {"pytest"}),
        ("timeout 10m vendor/bin/phpunit", {"vendor/bin/phpunit"}),
        ("timeout 600s sh scripts/run-smoke.sh", {"scripts/run-smoke.sh"}),
        ("timeout 1.5h shellspec", {"shellspec"}),
        ("nice -n +5 shellspec", {"shellspec"}),
        ('        echo "shellspec shell tests failed or were cancelled."', set()),
        ("        # sh scripts/run-smoke.sh shells out to the synced interpreter", set()),
        ("        # pfblockerng.php update is the production reload entry point", set()),
        ("        python3 scripts/check_skip_allowlist.py --suite pytest report.xml", set()),
        ('        installed="$(shellspec --version)"', set()),
        ("        grep -n pytest pyproject.toml", set()),
    ),
)
def test_the_runner_scan_reads_invocations_and_not_mentions(body: str, expected: set[str]) -> None:
    assert runners_in_run_body(body) == expected, body


def test_a_suite_invoked_through_nested_composite_actions_is_attributed_to_the_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A composite action is ordinary GitHub Actions, so a suite invoked one -- or two --
    levels down still belongs to the job that reaches it. A self-referential action must
    terminate rather than hang."""
    actions = tmp_path / "actions"
    for name, body in (
        ("l1", "runs:\n  using: composite\n  steps:\n    - uses: ./actions/l2\n"),
        ("l2", "runs:\n  using: composite\n  steps:\n    - shell: sh\n      run: uv run pytest -q\n"),
        ("loop", "runs:\n  using: composite\n  steps:\n    - uses: ./actions/loop\n"),
    ):
        (actions / name).mkdir(parents=True)
        (actions / name / "action.yaml").write_text(body, encoding="utf-8")
    monkeypatch.setattr("tests.test_issue2614_lock_job_budgets.ROOT", tmp_path)

    assert _local_action_run_bodies("./actions/l1") == ["uv run pytest -q"]
    assert _local_action_run_bodies("./actions/loop") == []  # cycle, not a hang

    workflows = tmp_path / "wf"
    workflows.mkdir()
    (workflows / "planted.yml").write_text(
        "jobs:\n  suite:\n    steps:\n      - uses: ./actions/l1\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("tests.test_issue2614_lock_job_budgets.WORKFLOWS", workflows)
    assert suite_running_jobs() == {("planted.yml", "suite"): {"pytest"}}


_ACQUIRE_CASES: tuple[tuple[bool, str], ...] = (
    (True, "\tif ($lock === FALSE || !@flock($lock, LOCK_SH | LOCK_NB)) {"),
    (True, "\t\t$this->assertTrue(flock($holder, LOCK_EX));"),
    (True, "\t\tflock($this->fp, LOCK_EX);"),
    (True, "\t\tflock(self::$fp, LOCK_EX);"),
    (True, "\t@file_put_contents($path, $content, LOCK_EX);"),
    # A call wrapped across lines puts the constant on its own line, with and without a
    # trailing delimiter -- both are the shape the line-scoped patterns cannot see.
    (True, "\t\t\tLOCK_EX"),
    (True, "\t\t\t$fp, LOCK_EX);"),
    (True, "\t\t\tLOCK_EX | LOCK_NB,"),
    (True, "        fcntl.flock(handle, fcntl.LOCK_EX)"),
    (True, "\t\t( exec 9>lockfile; lockf -k 9; sleep 30 ) &"),
    (True, "\t\t( exec 9>lockfile; flock 9; sleep 30 ) &"),
    (True, "sh -c 'exec 9>L; flock $fd'"),
    (True, "timeout 5 sh -c 'exec 9>L; flock -w 0 9'"),
    # SplFileObject::flock has no `$` argument at all; the wrapped-argument pattern is
    # what catches it. `exec {fd}>` names the descriptor in a brace, not a digit.
    (True, "\t\t$file->flock(LOCK_EX);"),
    (True, "exec {fd}>file; flock $fd"),
    # A quoted expansion is this repository's shell convention, so the operand must be
    # allowed to start with a quote.
    (True, 'exec {fd}>file; flock "$fd"'),
    (True, 'exec {fd}>file; flock "${fd}"'),
    (True, 'exec 9>file; flock "9"'),
    (False, "\t@flock($lock, LOCK_UN);"),
    (False, "\t// A waiter can be descheduled between its deadline check and flock()."),
    (False, "\t// LOCK_EX, and the deadline, are documented above."),
    (False, "\t/* LOCK_EX */"),
    (False, "# The flock inside _rebuild_code still prevents pile-ups"),
    (False, "45 lockf /usr/bin/lockf -s -t 5 /tmp/pfSense-upgrade.lock"),
)


@pytest.mark.parametrize(("acquires", "line"), _ACQUIRE_CASES)
def test_the_acquire_scan_separates_acquires_from_releases_and_prose(acquires: bool, line: str) -> None:
    assert any(pattern.search(line) for pattern in _ACQUIRE_PATTERNS) is acquires, line


def test_the_acquire_scan_finds_the_real_production_and_fixture_lock_sites() -> None:
    """A production oracle, not a restatement of the regexes: the scan must actually find
    the acquires that make `php-unit` and the live-VM jobs lock-reachable."""
    src_files = {hit.rsplit(":", 1)[0] for hit in kernel_lock_acquires("src")}
    assert "src/usr/local/pkg/pfblockerng/pfblockerng.inc" in src_files
    # Wrapped across lines, so this one only appears once the argument-line pattern works.
    assert "src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc" in src_files, sorted(src_files)

    php_files = {hit.rsplit(":", 1)[0] for hit in kernel_lock_acquires("tests/php")}
    # The forked pair that both append under LOCK_EX to the SAME paths: a genuine blocking
    # waiter, which is what makes the php-unit budget load-bearing rather than decorative.
    assert "tests/php/TickSafeSearchReservationTest.php" in php_files
    assert "tests/php/FeedPassLockTest.php" in php_files

    assert kernel_lock_acquires("tests/smoke"), "tests/smoke must keep its appliance LOCK_EX writes"


def test_a_latin1_encoded_source_is_scanned_rather_than_skipped() -> None:
    """An except-and-continue on UnicodeDecodeError dropped a tracked latin-1 `.inc`
    holding a real `flock($fp, LOCK_EX)` -- a silent false negative."""
    decoded = b"<?php\nflock($fp, LOCK_EX); // latin-1: \xff\n".decode("utf-8", errors="replace")
    assert any(pattern.search(line) for line in decoded.splitlines() for pattern in _ACQUIRE_PATTERNS)


def test_the_prefilter_is_a_superset_of_every_acquire_pattern() -> None:
    """`_candidate_files` only reads files naming a `_PREFILTER_TOKENS` entry, so a line a
    pattern matches WITHOUT one of those tokens would be invisible to the scan even though
    the regex would have caught it -- a silent hole. Checked against the real matching
    lines above rather than against the pattern sources, which spell the constants as
    alternations (`LOCK_(?:EX|SH)`) and would make a source-text check vacuous."""
    matching = [line for acquires, line in _ACQUIRE_CASES if acquires]
    assert matching, "no positive acquire cases to check the prefilter against"
    for line in matching:
        assert any(token in line for token in _PREFILTER_TOKENS), line
