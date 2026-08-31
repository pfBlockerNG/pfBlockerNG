"""Issue #2713: every CI Git mutation installs the Graphify merge driver first."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests._workflow_steps import extract_job

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
_SETUP_UV = "uses: astral-sh/setup-uv@v7"
_DRIVER = "ensure-graphify-merge-driver.sh"
_STEP_RE = re.compile(r"^      - [A-Za-z_][A-Za-z0-9_-]*:", re.MULTILINE)
_JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$", re.MULTILINE)
_SHELL_ARG = r"(?:\"[^\"]*\"|'[^']*'|\S+)"
_GIT_MUTATION_RE = re.compile(
    r"^(?:(?:if|until|while)\s+|!\s+)*"
    r"(?:env(?:\s+[A-Za-z_][A-Za-z0-9_]*=\S+)*\s+)?git"
    rf"(?:\s+(?:-C|-c)\s+{_SHELL_ARG})*"
    r"\s+(?:push|pull|merge|rebase|cherry-pick)(?:\s|$)"
)
_GH_MUTATION_RE = re.compile(r"^gh\s+pr\s+merge(?:\s|$)")
_WRAPPER_MUTATION_RE = re.compile(r"^sh\s+\S*scripts/(?:publish-pkg-repo|render-pkg-site)\.sh(?:\s|$)")
_TAG_ONLY_PUSH_RE = re.compile(
    r"""^git\s+push\s+origin\s+(?:"refs/tags/[^"\s:]+"|'refs/tags/[^'\s:]+'|refs/tags/[^\s:]+)$"""
)


@dataclass(frozen=True)
class PushJob:
    workflow: str
    job: str
    ensure_command: str
    first_mutation: str
    checkout_groups: tuple[tuple[str, ...], ...] = ()


PUSH_JOBS = (
    PushJob(
        "hsts-refresh.yml",
        "refresh",
        "sh scripts/agent/ensure-graphify-merge-driver.sh .",
        'git push --force origin "$BRANCH"',
        checkout_groups=(("uses: actions/checkout@v6", "ref: devel"),),
    ),
    PushJob(
        "psl-refresh.yml",
        "refresh",
        "sh scripts/agent/ensure-graphify-merge-driver.sh .",
        'git push --force origin "$BRANCH"',
        checkout_groups=(("uses: actions/checkout@v6", "ref: devel"),),
    ),
    PushJob(
        "tld-refresh.yml",
        "refresh",
        "sh scripts/agent/ensure-graphify-merge-driver.sh .",
        'git push --force origin "$BRANCH"',
        checkout_groups=(("uses: actions/checkout@v6", "ref: devel"),),
    ),
    PushJob(
        "image-refresh.yml",
        "refresh",
        "sh scripts/agent/ensure-graphify-merge-driver.sh .",
        'git -C "$WT" push --force origin "$BR"',
        checkout_groups=(("name: Checkout (for scripts/ + tests/smoke/)", "uses: actions/checkout@v6"),),
    ),
    PushJob(
        "module-durations.yml",
        "refresh",
        "sh scripts/agent/ensure-graphify-merge-driver.sh .",
        "until git push origin HEAD:devel; do",
        checkout_groups=(("uses: actions/checkout@v6", "ref: devel"),),
    ),
    PushJob(
        "version-tracker.yml",
        "reconcile",
        "sh scripts/agent/ensure-graphify-merge-driver.sh .",
        'git push --force origin "$1"',
        checkout_groups=(("uses: actions/checkout@v6",),),
    ),
    PushJob(
        "release-published.yml",
        "sync-ports-fork",
        'sh "${GITHUB_WORKSPACE}/pfblockerng-src/scripts/agent/ensure-graphify-merge-driver.sh" .',
        "until git push origin HEAD:pfblockerng/use-github; do",
        checkout_groups=(
            (
                "name: Checkout the FreeBSD-ports fork (use-github branch)",
                "uses: actions/checkout@v6",
                "repository: pfBlockerNG/FreeBSD-ports",
                "ref: pfblockerng/use-github",
            ),
            (
                "uses: actions/checkout@v6",
                "repository: pfBlockerNG/pfBlockerNG",
                "ref: ${{ github.workflow_sha }}",
                "path: pfblockerng-src",
            ),
        ),
    ),
)


def _steps(job: str) -> list[str]:
    starts = [match.start() for match in _STEP_RE.finditer(job)]
    return [job[start:end].rstrip() for start, end in zip(starts, [*starts[1:], len(job)])]


def _run_commands(step: str) -> list[str]:
    lines = step.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^(?P<indent> +)run:\s*(?P<value>.*)$", line)
        if match is None:
            continue
        value = match.group("value").strip()
        if value not in {"", "|", ">", "|-", ">-"}:
            return [value]

        indent = len(match.group("indent"))
        commands: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate.strip() and len(candidate) - len(candidate.lstrip(" ")) <= indent:
                break
            command = candidate.strip()
            if command and not command.startswith("#"):
                commands.append(command.split(" #", 1)[0].rstrip())
        return commands
    return []


def _has_step_line(step: str, marker: str) -> bool:
    expected = {marker, f"- {marker}"}
    return any(line.strip() in expected for line in step.splitlines())


def _command_step(steps: list[str], command: str, label: str) -> int:
    matches = [index for index, step in enumerate(steps) if command in _run_commands(step)]
    assert len(matches) == 1, f"{label}: expected one executable command {command!r}, found {len(matches)}"
    return matches[0]


def _first_mutation(steps: list[str]) -> tuple[int, str] | None:
    for index, step in enumerate(steps):
        for command in _run_commands(step):
            if _TAG_ONLY_PUSH_RE.match(command):
                continue
            if _GIT_MUTATION_RE.match(command) or _GH_MUTATION_RE.match(command) or _WRAPPER_MUTATION_RE.match(command):
                return index, command
    return None


def _assert_job_contract(job: str, spec: PushJob) -> None:
    label = f"{spec.workflow}:{spec.job}"
    steps = _steps(job)
    checkout_steps: list[int] = []
    for group in spec.checkout_groups:
        matches = [index for index, step in enumerate(steps) if all(_has_step_line(step, marker) for marker in group)]
        assert len(matches) == 1, f"{label}: expected one checkout step containing {group!r}, found {len(matches)}"
        checkout = steps[matches[0]]
        lines = {line.strip() for line in checkout.splitlines()}
        for prefix in ("repository:", "ref:", "path:"):
            expected_fields = {marker for marker in group if marker.startswith(prefix)}
            actual_fields = {line for line in lines if line.startswith(prefix)}
            assert actual_fields == expected_fields, (
                f"{label}: checkout {prefix} fields changed: "
                f"expected {sorted(expected_fields)!r}, got {sorted(actual_fields)!r}"
            )
        checkout_steps.append(matches[0])
    setup_uv_steps = [index for index, step in enumerate(steps) if _has_step_line(step, _SETUP_UV)]
    assert len(setup_uv_steps) == 1, (
        f"{label}: expected exactly one setup-uv step pinned to v7, found {len(setup_uv_steps)}"
    )
    setup_uv = setup_uv_steps[0]
    assert _SETUP_UV in steps[setup_uv], f"{label}: setup-uv must be pinned to v7"

    ensure = _command_step(steps, spec.ensure_command, label)
    assert _DRIVER in steps[ensure]
    mutation = _first_mutation(steps)
    assert mutation is not None, f"{label}: no qualifying push/pull-rebase command found"
    mutation_step, mutation_command = mutation
    assert mutation_command == spec.first_mutation, f"{label}: first qualifying mutation changed: {mutation_command!r}"
    assert max(checkout_steps) < setup_uv, f"{label}: setup-uv must run after every relevant checkout"
    assert setup_uv < ensure, f"{label}: setup-uv v7 must run before merge-driver setup"
    assert ensure < mutation_step, f"{label}: merge-driver setup must run before {mutation_command!r}"


def _workflow_jobs(path: Path) -> list[tuple[str, str]]:
    workflow = path.read_text(encoding="utf-8")
    jobs_match = re.search(r"^jobs:\s*$", workflow, re.MULTILINE)
    assert jobs_match is not None, f"{path.name}: workflow has no jobs mapping"
    return [(name, extract_job(workflow, name)) for name in _JOB_RE.findall(workflow[jobs_match.end() :])]


def _discovered_mutation_jobs() -> set[tuple[str, str]]:
    discovered: set[tuple[str, str]] = set()
    paths = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
    for path in paths:
        for job_name, job in _workflow_jobs(path):
            if _first_mutation(_steps(job)) is not None:
                discovered.add((path.name, job_name))
    return discovered


def _job_has_driver(job: str) -> bool:
    return any(_DRIVER in command for step in _steps(job) for command in _run_commands(step))


def _discovered_driver_jobs() -> set[tuple[str, str]]:
    discovered: set[tuple[str, str]] = set()
    paths = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
    for path in paths:
        for job_name, job in _workflow_jobs(path):
            if _job_has_driver(job):
                discovered.add((path.name, job_name))
    return discovered


def test_exhaustive_push_matrix_has_graphify_driver_before_each_mutation() -> None:
    expected = {(spec.workflow, spec.job) for spec in PUSH_JOBS}
    assert len(PUSH_JOBS) == len(expected) == 7, "issue #2713 defines 7 branch/content mutation jobs"
    assert _discovered_mutation_jobs() == expected, (
        "the workflow branch/content push/pull/merge inventory changed; update the issue #2713 matrix"
    )
    assert _discovered_driver_jobs() == expected, (
        "Graphify merge-driver setup exists outside the 7 branch/content mutation jobs"
    )

    failures: list[str] = []
    for spec in PUSH_JOBS:
        workflow = (WORKFLOWS / spec.workflow).read_text(encoding="utf-8")
        try:
            _assert_job_contract(extract_job(workflow, spec.job), spec)
        except (AssertionError, ValueError) as error:
            failures.append(str(error))
    assert not failures, "\n" + "\n".join(failures)


_GOOD_FIXTURE = """\
      - name: Checkout tools
        uses: actions/checkout@v6
      - name: Checkout target
        uses: actions/checkout@v6
        with:
          path: pkg-repo
      - name: Set up uv
        uses: astral-sh/setup-uv@v7
      - name: Install Graphify merge driver
        run: sh scripts/agent/ensure-graphify-merge-driver.sh pkg-repo
      - name: Publish
        run: sh scripts/publish-pkg-repo.sh
"""
_SETUP_FIXTURE = """\
      - name: Set up uv
        uses: astral-sh/setup-uv@v7
"""
_PUBLISH_FIXTURE = """\
      - name: Publish
        run: sh scripts/publish-pkg-repo.sh
"""
_FIXTURE_SPEC = PushJob(
    "fixture.yml",
    "publish",
    "sh scripts/agent/ensure-graphify-merge-driver.sh pkg-repo",
    "sh scripts/publish-pkg-repo.sh",
    checkout_groups=(
        ("name: Checkout tools", "uses: actions/checkout@v6"),
        ("name: Checkout target", "uses: actions/checkout@v6", "path: pkg-repo"),
    ),
)


@pytest.mark.parametrize(
    "broken",
    (
        _GOOD_FIXTURE.replace(_SETUP_FIXTURE, "", 1),
        _GOOD_FIXTURE.replace(_SETUP_FIXTURE, "", 1).replace(
            _PUBLISH_FIXTURE,
            _PUBLISH_FIXTURE + _SETUP_FIXTURE,
            1,
        ),
    ),
    ids=("missing-setup", "late-setup"),
)
def test_guard_rejects_planted_missing_or_late_setup(broken: str) -> None:
    _assert_job_contract(_GOOD_FIXTURE, _FIXTURE_SPEC)
    with pytest.raises(AssertionError, match="setup-uv"):
        _assert_job_contract(broken, _FIXTURE_SPEC)


def test_comments_cannot_spoof_tool_pins_or_checkout_paths() -> None:
    wrong_uv = _GOOD_FIXTURE.replace(
        "        uses: astral-sh/setup-uv@v7",
        "        uses: astral-sh/setup-uv@v6\n        # uses: astral-sh/setup-uv@v7",
    )
    with pytest.raises(AssertionError, match="setup-uv"):
        _assert_job_contract(wrong_uv, _FIXTURE_SPEC)

    wrong_path = _GOOD_FIXTURE.replace(
        "          path: pkg-repo",
        "          path: wrong-repo\n          # path: pkg-repo",
    )
    with pytest.raises(AssertionError, match="checkout step"):
        _assert_job_contract(wrong_path, _FIXTURE_SPEC)


@pytest.mark.parametrize(
    "command",
    (
        "git merge topic",
        "git pull origin devel",
        "git rebase origin/devel",
        "git cherry-pick deadbeef",
        "env GIT_TERMINAL_PROMPT=0 git push origin main",
        "git -C repo -c user.name=bot push origin main",
        "gh pr merge 42",
    ),
)
def test_mutation_scanner_recognizes_every_guarded_command_class(command: str) -> None:
    job = f"      - name: Mutate\n        run: {command}\n"
    assert _first_mutation(_steps(job)) == (0, command)


def test_tag_ref_push_does_not_require_a_content_merge_driver() -> None:
    command = 'git push origin "refs/tags/${TAG}"'
    job = f"      - name: Push tag\n        run: {command}\n"
    assert _first_mutation(_steps(job)) is None


@pytest.mark.parametrize(
    "command",
    (
        "git push origin refs/tags/v1 refs/heads/main",
        "git push origin refs/tags/",
        "git push origin refs/tags/v1:refs/heads/main",
        'git push origin "refs/tags/v1" "HEAD:refs/heads/main"',
        "git push origin refs/tags/v1 && git push origin main",
        "git push --atomic origin refs/tags/v1",
        "env TOKEN=x git push origin refs/tags/v1",
        "git push origin HEAD:refs/heads/refs/tags/main",
    ),
)
def test_tag_ref_exemption_rejects_non_tag_only_pushes(command: str) -> None:
    job = f"      - name: Push\n        run: {command}\n"
    assert _first_mutation(_steps(job)) == (0, command)


def test_driver_scanner_distinguishes_a_nonmutating_job() -> None:
    job = """\
      - name: Install Graphify merge driver
        run: sh scripts/agent/ensure-graphify-merge-driver.sh .
      - name: Read only
        run: git status --short
"""
    assert _job_has_driver(job)
    assert _first_mutation(_steps(job)) is None
