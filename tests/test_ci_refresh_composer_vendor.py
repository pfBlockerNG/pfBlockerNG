"""Guard: a job that commits a PHP file under the git hooks has a vendor tree first.

Issue #1793: tld-refresh.yml activates the repository git hooks on purpose
("automated commits must hit the same local gates as a human commit"), then
stages src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php and commits. Staging
a PHP-family file sets `staged_php=1` in .githooks/pre-commit, which runs the
fail-closed `composer vendor` gate and, behind it, PHPStan and PHPCS out of
vendor/bin. Without `composer install` on the runner there is no vendor tree,
the gate fails closed, and the whole refresh -- commit, push, PR, CI dispatch --
is aborted. The gate is right to fail; the workflow was missing its half of the
contract.

The invariant is stated over every workflow rather than over tld-refresh alone:
the next automation that opts into the hooks and touches a PHP file inherits the
same requirement, and the same latent break (tld-refresh only failed the week
IANA actually drifted -- a no-change week never reaches the commit).

Scoped per JOB, not per file: two jobs are two runners with no shared
filesystem, so `composer install` in one does nothing for a commit in the other.
Staging detection is fail-closed -- a broad pathspec (`-A`, `.`, a directory)
counts as PHP-staging, because it can sweep one in.

Text-parsed rather than PyYAML, following the house idiom in
tests/test_ci_tool_pins.py and tests/test_ci_checkout_persist_credentials.py:
this guard reasons about shell and comments that a YAML object model discards.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
_WORKFLOW_GLOBS = ("*.yml", "*.yaml")

# `staged_php` in .githooks/pre-commit is set from these two suffixes.
_PHP_SUFFIXES = (".php", ".inc")

# Pathspecs that can sweep in a PHP file without naming one.
_BROAD_PATHSPECS = frozenset({"-A", "--all", ".", "-u", "--update", "*", ":/"})

# Both ways a workflow can put .githooks in front of its own commit.
_HOOKS_RE = re.compile(r"scripts/setup-hooks\.sh|core\.hooksPath")
# Pathspecs end at the first shell separator: a `.php` in the message of a
# chained `git commit` is not a staged path.
_GIT_ADD_RE = re.compile(r"\bgit add\b(?P<paths>[^\n#;|&]*)")
_GIT_COMMIT_RE = re.compile(r"\bgit commit\b")
# The one way a job ends up with a vendor tree: Composer resolving it in that job.
_VENDOR_TREE_RE = re.compile(r"\bcomposer install\b")

# The hook's php -l / PHPStan / PHPCS gates must run on a supported PHP, which
# means setup-php fed from read-version-matrix rather than the runner default.
_SETUP_PHP_RE = re.compile(r"uses:\s*shivammathur/setup-php@")
_PHP_VERSION_RE = re.compile(r"php-version:\s*(?P<value>\S.*?)\s*$")
_MATRIX_OUTPUT_RE = re.compile(r"outputs\.php_versions")

# A job key: exactly two spaces of indent under the top-level `jobs:` mapping.
_JOB_KEY_RE = re.compile(r"^ {2}(?P<name>[A-Za-z0-9_.-]+):\s*(#.*)?$")
_JOBS_ROOT_RE = re.compile(r"^jobs:\s*(#.*)?$")


def _workflow_files() -> list[Path]:
    """Every workflow file under WORKFLOWS_DIR, `.yml` and `.yaml` alike.

    GitHub Actions loads either extension, so globbing only `*.yml` would be a
    silent bypass. Keyed by filename so the two globs cannot double-count.
    """
    by_name: dict[str, Path] = {}
    for pattern in _WORKFLOW_GLOBS:
        for path in WORKFLOWS_DIR.glob(pattern):
            by_name.setdefault(path.name, path)
    return [by_name[name] for name in sorted(by_name)]


def _code_lines(text: str) -> list[str]:
    """The file's lines with whole-line comments blanked out.

    A commented-out or documented `git add src/foo.php` is prose, not an
    invocation, and must not be read as one. Blanked rather than dropped so
    line numbers stay usable in failure messages.
    """
    return ["" if line.lstrip().startswith("#") else line for line in text.splitlines()]


def _jobs(lines: list[str]) -> list[tuple[str, int, list[str]]]:
    """Every job as (name, 1-based first line, its own lines).

    Two jobs are two runners with no shared filesystem, so the Composer/commit
    ordering only means anything within one job.
    """
    starts: list[tuple[str, int]] = []
    in_jobs = False
    for index, line in enumerate(lines):
        if _JOBS_ROOT_RE.match(line):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        # A non-blank line at column 0 ends the `jobs:` mapping.
        if line.strip() and not line.startswith(" "):
            break
        match = _JOB_KEY_RE.match(line)
        if match:
            starts.append((match.group("name"), index))

    jobs: list[tuple[str, int, list[str]]] = []
    for position, (name, start) in enumerate(starts):
        end = starts[position + 1][1] if position + 1 < len(starts) else len(lines)
        jobs.append((name, start + 1, lines[start:end]))
    return jobs


def _stages_php(lines: list[str]) -> bool:
    """True if these lines stage something the pre-commit PHP block reacts to.

    Fail-closed: a pathspec that merely *can* contain a PHP file -- `-A`, `.`,
    a directory -- counts, since the gate fires on what the pathspec resolved
    to, not on what the workflow spelled out.
    """
    for line in lines:
        for match in _GIT_ADD_RE.finditer(line):
            for raw in match.group("paths").split():
                token = raw.strip("\"'")
                if not token:
                    continue
                if token in _BROAD_PATHSPECS or token.endswith(_PHP_SUFFIXES):
                    return True
                # An absolute pathspec points outside this checkout, so it can
                # only be judged as broad -- never resolved against ROOT.
                if token.startswith("/") or token.endswith("/"):
                    return True
                if (ROOT / token).is_dir():
                    return True
    return False


def _first_line_matching(lines: list[str], pattern: re.Pattern[str]) -> int | None:
    """1-based offset within `lines` of the first match, or None."""
    for number, line in enumerate(lines, start=1):
        if pattern.search(line):
            return number
    return None


def _hook_php_jobs(text: str) -> list[tuple[str, int, list[str]]]:
    """Every job in this workflow that stages PHP with .githooks active."""
    lines = _code_lines(text)
    if not _HOOKS_RE.search("\n".join(lines)):
        return []
    return [job for job in _jobs(lines) if _stages_php(job[2])]


def _offenders(name: str, text: str) -> tuple[list[str], list[str]]:
    """(offending job descriptions, inspected job labels) for one workflow."""
    offenders: list[str] = []
    inspected: list[str] = []
    for job, job_start, job_lines in _hook_php_jobs(text):
        inspected.append(f"{name}:{job}")

        install_offset = _first_line_matching(job_lines, _VENDOR_TREE_RE)
        commit_offset = _first_line_matching(job_lines, _GIT_COMMIT_RE)
        if install_offset is None:
            offenders.append(
                f"{name}: job `{job}` stages PHP under the git hooks but never materialises a Composer vendor tree"
            )
        elif commit_offset is not None and install_offset > commit_offset:
            offenders.append(
                f"{name}: job `{job}` materialises its vendor tree at line {job_start + install_offset - 1}, "
                f"after `git commit` at line {job_start + commit_offset - 1}"
            )
    return offenders, inspected


def test_php_staging_jobs_install_composer_before_committing() -> None:
    """A hook-running job that stages PHP has a vendor tree by commit time.

    Scenario: the pre-commit `composer vendor` gate is fail-closed.
    Given a job that activates .githooks and stages a .php/.inc file,
    when it reaches `git commit`, then `composer install` must already have run
    in that same job -- otherwise the gate aborts the commit and every step
    that follows it.
    """
    offenders: list[str] = []
    inspected: list[str] = []
    for path in _workflow_files():
        found, seen = _offenders(path.name, path.read_text(encoding="utf-8"))
        offenders.extend(found)
        inspected.extend(seen)

    assert inspected, (
        "no job both activates .githooks and stages a PHP file. Either the shapes this guard "
        "looks for (`git add` pathspecs, setup-hooks.sh / core.hooksPath) stopped matching and "
        "it now protects nothing, or no workflow runs the hooks any more -- in which case delete "
        "this guard rather than leaving it vacuous"
    )
    assert not offenders, "expected every PHP-staging job to install Composer before committing; got:\n" + "\n".join(
        offenders
    )


def test_php_staging_jobs_pin_php_from_the_version_matrix() -> None:
    """The hook's PHP gates run on a supported PHP, not on whatever the runner ships.

    Scenario: .githooks/pre-commit runs php -l and PHPCS.
    Given a job that puts those gates in front of its own commit,
    when the runner image changes its default PHP,
    then the gates must still run on a version supported-versions.json ships --
    so the PHP version comes from read-version-matrix, never from the ambient
    runner default and never from a literal restating the matrix.
    """
    offenders: list[str] = []
    for path in _workflow_files():
        text = path.read_text(encoding="utf-8")
        for job, _, job_lines in _hook_php_jobs(text):
            if _first_line_matching(job_lines, _SETUP_PHP_RE) is None:
                offenders.append(f"{path.name}: job `{job}` runs the hook PHP gates on the runner's ambient PHP")
                continue
            pinned = [
                match.group("value")
                for line in job_lines
                if (match := _PHP_VERSION_RE.search(line))
                if not _MATRIX_OUTPUT_RE.search(match.group("value"))
            ]
            if pinned:
                offenders.append(
                    f"{path.name}: job `{job}` pins php-version to {', '.join(pinned)} "
                    "instead of a read-version-matrix output"
                )

    assert not offenders, "expected every PHP-staging job to take its PHP version from the matrix; got:\n" + "\n".join(
        offenders
    )


def test_guard_flags_a_job_that_stages_php_without_installing_composer() -> None:
    """The guard's own red path: the exact shape of issue #1793."""
    offenders, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        "      - run: sh scripts/setup-hooks.sh\n"
        "      - run: |\n"
        "          git add src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php\n"
        "          git commit -m 'refresh'\n",
    )
    assert inspected == ["synthetic.yml:refresh"]
    assert offenders == [
        "synthetic.yml: job `refresh` stages PHP under the git hooks but never materialises a Composer vendor tree"
    ]


def test_guard_flags_composer_installed_in_a_different_job() -> None:
    """Two jobs are two runners: an install in job A leaves job B without vendor/."""
    offenders, _ = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  prepare:\n"
        "    steps:\n"
        "      - run: composer install\n"
        "  refresh:\n"
        "    steps:\n"
        "      - run: sh scripts/setup-hooks.sh\n"
        "      - run: |\n"
        "          git add src/foo.php\n"
        "          git commit -m 'x'\n",
    )
    assert offenders == [
        "synthetic.yml: job `refresh` stages PHP under the git hooks but never materialises a Composer vendor tree"
    ]


def test_guard_flags_composer_installed_after_the_commit() -> None:
    """Ordering matters: a vendor tree built after the commit is built too late."""
    offenders, _ = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        "      - run: git config core.hooksPath .githooks\n"
        "      - run: |\n"
        "          git add src/foo.inc\n"
        "          git commit -m 'x'\n"
        "      - run: composer install\n",
    )
    assert offenders == [
        "synthetic.yml: job `refresh` materialises its vendor tree at line 8, after `git commit` at line 7"
    ]


def test_guard_treats_a_broad_pathspec_as_php_staging() -> None:
    """`git add -A` can sweep in a PHP file, so it is judged as if it did."""
    offenders, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        "      - run: sh scripts/setup-hooks.sh\n"
        "      - run: |\n"
        "          git add -A\n"
        "          git commit -m 'x'\n",
    )
    assert inspected == ["synthetic.yml:refresh"]
    assert offenders


def test_guard_ignores_a_git_add_that_is_only_a_comment() -> None:
    """A documented `git add` is prose; only real invocations are judged."""
    offenders, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        "      # e.g. git add src/foo.php\n"
        "      - run: sh scripts/setup-hooks.sh\n"
        "      - run: git add docs/notes.md\n",
    )
    assert inspected == []
    assert offenders == []


def test_guard_sees_through_a_quoted_pathspec() -> None:
    """Quoting a path does not hide it from the gate, so it does not hide it here."""
    _, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        "      - run: sh scripts/setup-hooks.sh\n"
        "      - run: composer install\n"
        '      - run: git add "src/foo.php"\n'
        "      - run: git commit -m 'x'\n",
    )
    assert inspected == ["synthetic.yml:refresh"]


def test_guard_passes_a_job_that_installs_composer_first() -> None:
    """The fixed shape: install, then stage, then commit -- no finding."""
    offenders, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        "      - run: sh scripts/setup-hooks.sh\n"
        "      - run: composer install --no-interaction\n"
        "      - run: |\n"
        "          git add src/foo.php\n"
        "          git commit -m 'x'\n",
    )
    assert inspected == ["synthetic.yml:refresh"]
    assert offenders == []


def test_guard_stops_reading_pathspecs_at_a_shell_separator() -> None:
    """A `.php` mentioned in a chained commit message is not a staged path."""
    offenders, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        "      - run: sh scripts/setup-hooks.sh\n"
        '      - run: git add docs/notes.md && git commit -m "mention foo.php in the notes"\n',
    )
    assert inspected == []
    assert offenders == []


def test_guard_treats_an_absolute_pathspec_as_broad() -> None:
    """An absolute pathspec is judged on its own terms, not against this checkout."""
    offenders, inspected = _offenders(
        "synthetic.yml",
        "jobs:\n"
        "  refresh:\n"
        "    steps:\n"
        "      - run: sh scripts/setup-hooks.sh\n"
        "      - run: |\n"
        "          git add /home/runner/work/pfBlockerNG/pfBlockerNG/src\n"
        "          git commit -m 'x'\n",
    )
    assert inspected == ["synthetic.yml:refresh"]
    assert offenders
