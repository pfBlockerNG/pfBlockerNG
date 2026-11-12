"""Guard the setup a container job must do itself once the ci image has started (#3852).

The image cannot prevent two failure modes:

- A PHP matrix leg that never selects its version runs the image default (the lowest supported
  PHP), so the 8.4 and 8.5 legs report green for a version they never ran.
- The runner creates the workspace directory as its own uid, while the job runs as root. The PHP
  suite and the portable builder's ``--build-record`` probe drop every ``GIT_*`` variable and
  the system/global git config, so no ``safe.directory`` reaches them, and git refuses a
  workspace-root checkout as "dubious ownership" unless the job first takes ownership of it.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = ROOT / ".github" / "workflows"

MATRIX_PHP = "${{ matrix.php-version }}"
SELECT_PHP = f'update-alternatives --set php "/usr/bin/php{MATRIX_PHP}"'
SELECT_PHP_CGI = f'update-alternatives --set php-cgi "/usr/bin/php-cgi{MATRIX_PHP}"'
OWN_WORKSPACE = 'chown "$(id -u):$(id -g)" "$GITHUB_WORKSPACE"'

_USES_PHP = re.compile(r"\bphp\b|\bcomposer\b|vendor/bin/")
_DROPS_GIT_CONFIG = re.compile(r"vendor/bin/phpunit|--build-record\b")
# The ownership command as an executed line, never inside a comment or a string.
_OWNS_WORKSPACE = re.compile(rf"^[ \t]*{re.escape(OWN_WORKSPACE)}[ \t]*$", re.MULTILINE)


def _before(run: str, needle: str) -> str:
    """The part of ``run`` that executes before ``needle`` (all of it when ``needle`` is absent)."""
    return run.split(needle, 1)[0]


def _jobs(workflows: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for name, document in sorted(workflows.items()):
        jobs = document.get("jobs") if isinstance(document, dict) else None
        for job_id, job in (jobs or {}).items():
            if isinstance(job, dict):
                yield name, job_id, job


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [step for step in job.get("steps") or [] if isinstance(step, dict)]


def _run(step: dict[str, Any]) -> str:
    run = step.get("run")
    return run if isinstance(run, str) else ""


def _first(runs: list[tuple[str, bool]], match: Callable[[str], object]) -> int | None:
    """Index of the first run matching ``match``; ``runs`` pairs each run with whether it always executes."""
    return next((i for i, (run, _) in enumerate(runs) if match(run)), None)


def _first_unconditional(runs: list[tuple[str, bool]], needle: str) -> int | None:
    # A step behind `if:` may not run, so it cannot be the one that selects or takes ownership.
    return next((i for i, (run, always) in enumerate(runs) if always and needle in run), None)


def php_leg_violations(workflows: dict[str, Any]) -> list[str]:
    """Every php-version matrix job that does not select its leg's PHP before first using PHP."""
    violations: list[str] = []
    for name, job_id, job in _jobs(workflows):
        matrix = (job.get("strategy") or {}).get("matrix")
        if not isinstance(matrix, dict) or "php-version" not in matrix:
            continue
        runs = [(_run(step), "if" not in step) for step in _steps(job)]
        selected = _first_unconditional(runs, SELECT_PHP)
        first_use = _first(runs, lambda run: _USES_PHP.search(_before(run, SELECT_PHP)))
        where = f"{name}:{job_id}"
        if selected is None:
            violations.append(f"{where} — never selects php {MATRIX_PHP}; the leg runs the image default")
        elif first_use is not None and first_use <= selected:
            violations.append(f"{where} — uses PHP before selecting php {MATRIX_PHP}")
        phpunit = _first(runs, lambda run: "vendor/bin/phpunit" in _before(run, SELECT_PHP_CGI))
        cgi = _first_unconditional(runs, SELECT_PHP_CGI)
        if phpunit is not None and (cgi is None or cgi >= phpunit):
            violations.append(f"{where} — runs PHPUnit without first selecting php-cgi {MATRIX_PHP}")
    return violations


def workspace_owner_violations(workflows: dict[str, Any]) -> list[str]:
    """Every container job that checks out at the workspace root and then runs a tool that drops
    the git config before taking ownership of the workspace."""
    violations: list[str] = []
    for name, job_id, job in _jobs(workflows):
        steps = _steps(job)
        root_checkout = any(
            str(step.get("uses", "")).startswith("actions/checkout@")
            and (step.get("with") or {}).get("path") in (None, "", ".", "./")
            for step in steps
        )
        if "container" not in job or not root_checkout:
            continue
        for index, step in enumerate(steps):
            run = _run(step)
            owned = _OWNS_WORKSPACE.search(run)
            if _DROPS_GIT_CONFIG.search(run[: owned.start()] if owned else run):
                violations.append(
                    f"{name}:{job_id}:{step.get('name', index)} — drops the git config on a workspace root does not own"
                )
                break
            if owned and "if" not in step:
                break
    return violations


def _real_workflows() -> dict[str, Any]:
    found = {path.name: yaml.safe_load(path.read_text(encoding="utf-8")) for path in WORKFLOWS_DIR.glob("*.y*ml")}
    assert found, f"no workflow files under {WORKFLOWS_DIR}"
    return found


def test_every_php_matrix_leg_runs_the_php_it_is_named_for() -> None:
    violations = php_leg_violations(_real_workflows())
    assert violations == [], "\n".join(violations)


def test_every_git_config_dropping_tool_runs_on_a_workspace_root_owns() -> None:
    violations = workspace_owner_violations(_real_workflows())
    assert violations == [], "\n".join(violations)


def test_deleting_a_real_php_selection_is_caught() -> None:
    workflows = _real_workflows()
    job = workflows["test.yml"]["jobs"]["php-syntax"]
    job["steps"] = [step for step in job["steps"] if SELECT_PHP not in _run(step)]
    assert php_leg_violations(workflows) == [
        f"test.yml:php-syntax — never selects php {MATRIX_PHP}; the leg runs the image default"
    ]


@pytest.mark.parametrize(("workflow", "job_id"), [("release.yml", "build-pkgs-portable"), ("test.yml", "php-unit")])
def test_deleting_a_real_workspace_chown_is_caught(workflow: str, job_id: str) -> None:
    workflows = _real_workflows()
    job = workflows[workflow]["jobs"][job_id]
    job["steps"] = [step for step in job["steps"] if OWN_WORKSPACE not in _run(step)]
    violations = workspace_owner_violations(workflows)
    assert any(violation.startswith(f"{workflow}:{job_id}:") for violation in violations), violations


def _php_leg(*steps: str | dict[str, Any]) -> dict[str, Any]:
    body = [{"uses": "actions/checkout@v7"}, *(step if isinstance(step, dict) else {"run": step} for step in steps)]
    job = {"strategy": {"matrix": {"php-version": ["8.3"]}}, "container": {"image": "x"}, "steps": body}
    return {"w.yml": {"jobs": {"leg": job}}}


def test_a_php_leg_that_selects_first_passes() -> None:
    assert php_leg_violations(_php_leg(SELECT_PHP, SELECT_PHP_CGI, "php -l x.php", "vendor/bin/phpunit")) == []


@pytest.mark.parametrize(
    ("steps", "expected"),
    [
        (("php -l x.php",), "never selects php"),
        (('update-alternatives --set php "/usr/bin/php8.3"', "php -l x.php"), "never selects php"),
        (({"if": "false", "run": SELECT_PHP}, "php -l x.php"), "never selects php"),
        (("composer install", SELECT_PHP), "uses PHP before selecting"),
        ((SELECT_PHP, "vendor/bin/phpunit"), "runs PHPUnit without first selecting php-cgi"),
        ((SELECT_PHP, "vendor/bin/phpunit", SELECT_PHP_CGI), "runs PHPUnit without first selecting php-cgi"),
        ((SELECT_PHP, {"if": "false", "run": SELECT_PHP_CGI}, "vendor/bin/phpunit"), "without first selecting php-cgi"),
        ((f"php -v\n{SELECT_PHP}",), "uses PHP before selecting"),
        ((SELECT_PHP, f"vendor/bin/phpunit\n{SELECT_PHP_CGI}"), "without first selecting php-cgi"),
    ],
    ids=[
        "no-selection",
        "literal-version",
        "conditional-selection",
        "selected-too-late",
        "phpunit-without-cgi",
        "cgi-selected-too-late",
        "conditional-cgi-selection",
        "php-used-before-selection-in-the-same-step",
        "phpunit-before-cgi-selection-in-the-same-step",
    ],
)
def test_a_php_leg_on_the_image_default_is_rejected(steps: tuple[str | dict[str, Any], ...], expected: str) -> None:
    violations = php_leg_violations(_php_leg(*steps))
    assert len(violations) == 1 and expected in violations[0], violations


def test_a_job_without_a_php_matrix_is_not_a_php_leg() -> None:
    workflows = _php_leg("php -l x.php")
    del workflows["w.yml"]["jobs"]["leg"]["strategy"]
    assert php_leg_violations(workflows) == []


def _builder(*steps: dict[str, Any], container: bool = True) -> dict[str, Any]:
    job: dict[str, Any] = {"steps": list(steps)}
    if container:
        job["container"] = {"image": "x"}
    return {"w.yml": {"jobs": {"build": job}}}


_CHECKOUT = {"uses": "actions/checkout@v7"}
_BUILD = {"name": "build", "run": "sh scripts/build-leg.sh --build-record rec.json"}
_OWN = {"run": OWN_WORKSPACE}


@pytest.mark.parametrize(
    ("workflows", "flagged"),
    [
        (_builder(_CHECKOUT, _BUILD), True),
        (_builder(_CHECKOUT, _BUILD, _OWN), True),
        (_builder(_CHECKOUT, {"if": "false", "run": OWN_WORKSPACE}, _BUILD), True),
        (_builder({"uses": "actions/checkout@v7", "with": {"path": "."}}, _BUILD), True),
        (_builder(_CHECKOUT, {"run": "vendor/bin/phpunit"}), True),
        (_builder(_CHECKOUT, _OWN, _BUILD), False),
        (_builder({"uses": "actions/checkout@v7", "with": {"path": "source"}}, _BUILD), False),
        (_builder(_CHECKOUT, _BUILD, container=False), False),
        (_builder(_CHECKOUT, {"run": "sh scripts/build-leg.sh"}), False),
        (_builder(_CHECKOUT, {"run": f"# {OWN_WORKSPACE}"}, _BUILD), True),
        (_builder(_CHECKOUT, {"run": f"echo '{OWN_WORKSPACE}'"}, _BUILD), True),
        (_builder(_CHECKOUT, {"run": f"{_BUILD['run']}\n{OWN_WORKSPACE}"}), True),
        (_builder(_CHECKOUT, {"run": f"{OWN_WORKSPACE}\n{_BUILD['run']}"}), False),
    ],
    ids=[
        "no-chown",
        "chown-too-late",
        "conditional-chown",
        "checkout-at-dot-is-the-root",
        "phpunit-no-chown",
        "chown-first",
        "checkout-in-subdirectory",
        "bare-runner",
        "no-git-config-dropping-tool",
        "commented-out-chown",
        "chown-only-echoed",
        "chown-after-the-build-in-the-same-step",
        "chown-before-the-build-in-the-same-step",
    ],
)
def test_workspace_ownership_is_required_exactly_where_git_config_is_dropped(
    workflows: dict[str, Any], flagged: bool
) -> None:
    violations = workspace_owner_violations(workflows)
    assert bool(violations) is flagged, violations
