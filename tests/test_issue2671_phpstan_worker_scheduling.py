"""Issue #2671: PHPStan's job scheduling, not the corpus, sets this repo's memory ceiling.

PHPStan cuts jobs from the analysed-file list and derives its worker count from the job
count, so the default `parallel.jobSize` of 20 turns 34 files into 2 jobs and 2 jobs into
ONE worker — the whole tree accumulates in one allocator, whatever the core count. On the
CI PHP builds that one worker needs 576M; two or more need 448M, the floor
`pfblockerng.inc` sets alone. The crash that opened the issue hit a 1G limit 1.78x above
a 576M requirement, and no other factor moved that requirement.
"""

import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# PHPStan 2.2.5, src/Parallel/Scheduler.php. `jobSize` is the only one of these
# this repo sets; the rest are upstream defaults (conf/config.neon).
PHPSTAN_DEFAULT_JOB_SIZE = 20
PHPSTAN_MIN_JOBS_PER_PROCESS = 2
PHPSTAN_MAX_PROCESSES = 8

# The smallest core count a supported runner offers. GitHub's ubuntu-latest has
# four; asserting against two keeps the verdict true on the leanest of them.
LEANEST_RUNNER_CORES = 2

# `--memory-limit` is PHPStan's flag and nothing else's (PHPCS spells it
# `-d memory_limit=`), so the flag alone identifies the invocation — no need to find the
# word `phpstan` on the same line, which a `\`-continued command would not carry. Only a
# literal ceiling counts: a probe sweeping `--memory-limit="$2"` is measuring, not
# documenting.
_MEMORY_LIMIT = re.compile(r"--memory-limit=(-1|\d+[KMG])\b")


def _neon() -> str:
    return (ROOT / "phpstan.neon").read_text(encoding="utf-8")


def _neon_list(neon: str, key: str) -> list[str]:
    """The `- value` entries of a phpstan.neon list, e.g. `paths` or `fileExtensions`."""
    block = re.search(rf"^(\s*){key}:\s*$((?:\n\1\s+-[^\n]*)+)", neon, re.MULTILINE)
    assert block is not None, f"phpstan.neon declares no `{key}:` list"
    return re.findall(r"-\s*(\S+)", block.group(2))


def _neon_job_size(neon: str) -> int:
    """`parameters.parallel.jobSize`, or PHPStan's default when unset."""
    match = re.search(r"^\s*jobSize:\s*(\d+)\s*$", neon, re.MULTILINE)
    return int(match.group(1)) if match else PHPSTAN_DEFAULT_JOB_SIZE


def _analysed_file_count() -> int:
    """How many files `phpstan analyse` will cut into jobs: everything under the
    configured `paths` carrying a configured `fileExtensions` suffix. `scanDirectories`
    is deliberately absent — those symbols are read, never analysed."""
    neon = _neon()
    suffixes = {f".{extension}" for extension in _neon_list(neon, "fileExtensions")}
    files = [
        path
        for root in _neon_list(neon, "paths")
        for path in (ROOT / root).rglob("*")
        if path.suffix in suffixes and path.is_file()
    ]
    assert files, "phpstan.neon's paths matched nothing — the scan is broken, not the config"
    return len(files)


def _worker_processes(file_count: int, job_size: int, cpu_cores: int) -> int:
    """PHPStan 2.2.5 Scheduler::scheduleWork, transcribed.

    The striping that decides WHICH files share a job is irrelevant here; only the
    count is, because a process holds every file of every job it is handed.
    """
    jobs = math.ceil(file_count / job_size)
    return min(max(jobs // PHPSTAN_MIN_JOBS_PER_PROCESS, 1), cpu_cores, PHPSTAN_MAX_PROCESSES)


def test_phpstan_spreads_the_tree_over_more_than_one_worker() -> None:
    """One worker holds the whole tree and needs 576M; two or more need 448M.

    `--debug`, which drops the worker and analyses in the main process, measures the same
    576M — so the cost is accumulation in one process, and the ceiling and the wall clock
    move together because they have one cause.
    """
    file_count = _analysed_file_count()
    job_size = _neon_job_size(_neon())
    processes = _worker_processes(file_count, job_size, LEANEST_RUNNER_CORES)

    largest_that_works = max(
        size for size in range(1, file_count + 1) if _worker_processes(file_count, size, LEANEST_RUNNER_CORES) >= 2
    )
    assert processes >= 2, (
        f"phpstan.neon's parallel.jobSize={job_size} cuts {file_count} analysed files into "
        f"{math.ceil(file_count / job_size)} job(s), which PHPStan runs on {processes} worker "
        f"process(es). One worker accumulates the whole tree and pushes the run to its measured "
        f"576M worst case; jobSize <= {largest_that_works} keeps it on the 448M per-file floor "
        f"(issue #2671)."
    )


def test_the_scheduling_model_reproduces_phpstans_single_worker_default() -> None:
    """Vacuity guard: the assertion above is only worth something if this model can report
    the failure it checks for. 34 files at PHPStan's default jobSize is one worker, four
    idle cores or not."""
    assert _worker_processes(34, PHPSTAN_DEFAULT_JOB_SIZE, 4) == 1
    assert _worker_processes(34, 10, 4) == 2
    assert _worker_processes(34, 3, 4) == 4


def _sources_quoting_a_phpstan_limit() -> list[tuple[str, str]]:
    """(where, text) for every tracked surface that tells someone how to run PHPStan
    over the whole tree. `tests/php/NoEmptyOnStringRuleTest.php` is not one of them:
    it analyses a three-file fixture directory and carries its own limit."""
    skip = {"node_modules", ".venv", "vendor", "plugins", ".git", "graphify-out"}
    worktrees = ROOT / ".claude" / "worktrees"
    candidates = [
        *ROOT.rglob("*.md"),
        ROOT / "phpstan.neon",
        *(ROOT / ".github/workflows").glob("*.yml"),
    ]
    return [
        (str(path.relative_to(ROOT)), path.read_text(encoding="utf-8"))
        for path in candidates
        if not skip & set(path.parts) and worktrees not in path.parents
    ]


def _limits_disagreeing_with(expected: str, where: str, text: str) -> list[str]:
    """`where:line says X` for every literal PHPStan ceiling in `text` that is not `expected`."""
    return [
        f"{where}:{line_no} says {found.group(1)}"
        for line_no, line in enumerate(text.splitlines(), 1)
        if (found := _MEMORY_LIMIT.search(line + " "))
        if found.group(1) != expected
    ]


def test_every_phpstan_instruction_quotes_the_limit_composer_actually_carries() -> None:
    """composer.json is the invocation; a doc quoting a different limit sends a contributor
    at a ceiling CI does not use."""
    composer = json.loads((ROOT / "composer.json").read_text(encoding="utf-8"))
    canonical = _MEMORY_LIMIT.search(composer["scripts"]["phpstan"] + " ")
    assert canonical is not None, "composer.json's phpstan script carries no --memory-limit"
    expected = canonical.group(1)

    disagreeing = [
        entry
        for where, text in _sources_quoting_a_phpstan_limit()
        for entry in _limits_disagreeing_with(expected, where, text)
    ]

    assert not disagreeing, f"composer phpstan runs at {expected}; these disagree: " + "; ".join(disagreeing)


def test_the_limit_scan_catches_a_backslash_continued_command() -> None:
    """The fixture a same-line scan misses: a continued invocation puts `phpstan` and its
    ceiling on different lines, and only the ceiling line carries the flag."""
    split = "vendor/bin/phpstan analyse --no-progress \\\n  --memory-limit=1G\n"
    assert _limits_disagreeing_with("2G", "doc.md", split) == ["doc.md:2 says 1G"]
    assert _limits_disagreeing_with("1G", "doc.md", split) == []
