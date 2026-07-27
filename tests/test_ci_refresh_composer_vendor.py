"""Guard: a workflow that commits a PHP file under the git hooks installs Composer first.

Issue #1793: tld-refresh.yml activates the repository git hooks on purpose
("automated commits must hit the same local gates as a human commit"), then
stages src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php and commits. Staging
a PHP-family file sets `staged_php=1` in .githooks/pre-commit, which runs the
fail-closed `composer vendor` gate and, behind it, PHPStan and PHPCS out of
vendor/bin. With no `composer install` on the runner there is no vendor tree,
the gate fails closed, and the whole refresh -- commit, push, PR, CI dispatch --
is aborted. The gate is right to fail; the workflow was missing its half of the
contract.

The invariant is stated over every workflow rather than over tld-refresh alone:
the next automation that opts into the hooks and touches a PHP file inherits the
same requirement, and the same latent break (tld-refresh only failed the week
IANA actually drifted -- a no-change week never reaches the commit).

Text-parsed rather than PyYAML, following the house idiom in
tests/test_ci_tool_pins.py and tests/test_ci_checkout_persist_credentials.py:
test.yml's "Install test dependencies" step installs no YAML parser.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
_WORKFLOW_GLOBS = ("*.yml", "*.yaml")

# `staged_php` in .githooks/pre-commit is set from these two suffixes.
_PHP_SUFFIXES = (".php", ".inc")

_HOOKS_RE = re.compile(r"scripts/setup-hooks\.sh")
_GIT_ADD_RE = re.compile(r"\bgit add\b(?P<paths>[^\n#]*)")
_GIT_COMMIT_RE = re.compile(r"\bgit commit\b")
_COMPOSER_INSTALL_RE = re.compile(r"\bcomposer install\b")


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


def _stages_php(text: str) -> bool:
    """True if the workflow stages a path the pre-commit PHP block reacts to."""
    for match in _GIT_ADD_RE.finditer(text):
        for token in match.group("paths").split():
            if token.endswith(_PHP_SUFFIXES):
                return True
    return False


def _first_line_matching(lines: list[str], pattern: re.Pattern[str]) -> int | None:
    """1-based line number of the first match, or None."""
    for number, line in enumerate(lines, start=1):
        if pattern.search(line):
            return number
    return None


def test_php_staging_workflows_install_composer_before_committing() -> None:
    """A hook-running workflow that stages PHP has a vendor tree by commit time.

    Scenario: the pre-commit `composer vendor` gate is fail-closed.
    Given a workflow that activates .githooks and stages a .php/.inc file,
    when it reaches `git commit`, then `composer install` must already have run
    -- otherwise the gate aborts the commit and every step that follows it.
    """
    offenders: list[str] = []
    inspected: list[str] = []

    for path in _workflow_files():
        text = path.read_text(encoding="utf-8")
        if not _HOOKS_RE.search(text) or not _stages_php(text):
            continue
        inspected.append(path.name)

        lines = text.splitlines()
        install_line = _first_line_matching(lines, _COMPOSER_INSTALL_RE)
        commit_line = _first_line_matching(lines, _GIT_COMMIT_RE)

        if install_line is None:
            offenders.append(f"{path.name}: stages PHP under the git hooks but never runs `composer install`")
        elif commit_line is not None and install_line > commit_line:
            offenders.append(
                f"{path.name}: `composer install` at line {install_line} runs after `git commit` at line {commit_line}"
            )

    assert inspected, (
        "no workflow both activates .githooks and stages a PHP file -- the guard has "
        "nothing to protect, which means it silently stopped matching (check the "
        "`git add` / setup-hooks.sh shapes it looks for)"
    )
    assert not offenders, (
        "expected every PHP-staging workflow to install Composer before committing; got:\n" + "\n".join(offenders)
    )
