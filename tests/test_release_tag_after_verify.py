"""Pin issue #1855: the release pipeline builds and VERIFIES before it tags.

Three parts compose into one code path in `.github/workflows/release.yml`:

* Part 1 -- ordering. Nothing irreversible reaches GitHub until the artifacts are
  built and the verification phase is green: the release SHA is pinned on the
  channel-branch tip (after the docs-only notes commit), every `.pkg` is built from
  that pinned SHA, the suites run, and only then does `tag-release` create+push the
  tag on the SAME pinned SHA -- followed by the draft Release, the assets, the
  healthcheck, the publish flip, the pkg-repo dispatch and the ports-fork sync.
  Two stranded tag+draft pairs in one day (runs 30419586338 / 30424647767) came
  from the old order; this file is the graph proof that it cannot come back.
* Part 2 -- only a RELEASED pfSense version may veto (see
  `tests/shell/resolve_legs_spec.sh` for the status predicate itself).
* Part 3 -- our own alpha/beta tags skip the live suites (`run_suites`), with a
  `force_suites` dispatch input as the manual escape hatch.

The reachability tests walk the real `needs:` graph rather than asserting on one
job's text, so ANY re-ordering that puts a mutation ahead of the build or ahead of
the suite AND-gates fails here.
"""

from __future__ import annotations

import re
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z][A-Za-z0-9_-]*):[ \t]*$")
_JOB_KEY_RE = re.compile(r"^    [A-Za-z_-]+:")
_STEP_HEADER_RE = re.compile(r"^      - ")

# Every job that changes something outside this workflow run: the tag, the Release,
# its assets, the published flip, the pkg repo, the ports fork. Each MUST be
# downstream of the build and (when they run) of both live suites.
IRREVERSIBLE_JOBS = (
    "tag-release",
    "release",
    "attach-pkgs",
    "publish-release",
    "repo-publish",
    "sync-ports-fork",
)


# --------------------------------------------------------------------------- #
# workflow parsing (line-based, same technique as the sibling release tests)
# --------------------------------------------------------------------------- #


def _jobs(workflow: Path = RELEASE_WORKFLOW) -> dict[str, list[str]]:
    lines = workflow.read_text(encoding="utf-8").splitlines()
    body = lines[lines.index("jobs:") + 1 :]
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    buffer: list[str] = []
    for line in body:
        match = _JOB_HEADER_RE.match(line)
        if match is not None:
            if current is not None:
                jobs[current] = buffer
            current = match.group(1)
            buffer = []
        elif current is not None:
            buffer.append(line)
    if current is not None:
        jobs[current] = buffer
    return jobs


def _steps(job_lines: list[str]) -> list[list[str]]:
    steps: list[list[str]] = []
    for line in job_lines:
        if _STEP_HEADER_RE.match(line):
            steps.append([])
        if steps:
            steps[-1].append(line)
    return steps


def _step(job_lines: list[str], needle: str) -> list[str]:
    matches = [s for s in _steps(job_lines) if any(needle in line for line in s)]
    assert len(matches) == 1, f"expected exactly one step containing {needle!r}, got {len(matches)}"
    return matches[0]


def _step_run_script(step_lines: list[str]) -> str:
    text = "\n".join(step_lines)
    marker = "run: |\n"
    idx = text.index(marker) + len(marker)
    return textwrap.dedent(text[idx:])


def _job_if_block(job_lines: list[str]) -> str:
    """The whole job-level `if:` value, folded (`if: >-`) multi-line forms included."""
    collected: list[str] = []
    for line in job_lines:
        if collected:
            if _JOB_KEY_RE.match(line):
                break
            collected.append(line)
        elif line.startswith("    if:"):
            collected.append(line)
    assert collected, f"job carries no job-level if:\n{chr(10).join(job_lines)}"
    return "\n".join(collected)


def _needs(job_lines: list[str]) -> set[str]:
    """The job's direct `needs:` set (inline-list and bare-scalar forms alike)."""
    line = next((ln for ln in job_lines if ln.startswith("    needs:")), None)
    if line is None:
        return set()
    value = line.split("needs:", 1)[1].strip().strip("[]")
    return {token.strip().strip("\"'") for token in value.split(",") if token.strip()}


def _graph() -> dict[str, set[str]]:
    return {name: _needs(lines) for name, lines in _jobs().items()}


def _upstream(job: str, graph: dict[str, set[str]]) -> set[str]:
    """Every job `job` is transitively downstream of."""
    seen: set[str] = set()
    stack = list(graph[job])
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(graph.get(node, set()))
    return seen


# --------------------------------------------------------------------------- #
# graph sanity: the edges we walk actually exist
# --------------------------------------------------------------------------- #


def test_every_needs_edge_points_at_a_real_job() -> None:
    graph = _graph()
    dangling = {job: sorted(deps - graph.keys()) for job, deps in graph.items() if deps - graph.keys()}
    assert not dangling, f"needs: edge(s) pointing at a non-existent job: {dangling}"


def test_the_needs_graph_is_acyclic() -> None:
    """A cycle would make GitHub refuse the whole workflow; catch it here instead."""
    graph = _graph()
    for job in graph:
        assert job not in _upstream(job, graph), f"job {job} is (transitively) its own dependency"


# --------------------------------------------------------------------------- #
# Part 1 reachability: nothing irreversible before the build or the suites
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("job", IRREVERSIBLE_JOBS)
def test_every_irreversible_job_is_downstream_of_the_build(job: str) -> None:
    """The tag/draft/assets/publish must describe artifacts that already exist.

    Runs 30419586338 + 30424647767 tagged and drafted first and built/verified
    afterwards; both had to be deleted unpublished.
    """
    graph = _graph()
    assert "build-pkgs-portable" in _upstream(job, graph), (
        f"{job} is not (transitively) downstream of build-pkgs-portable: upstream={sorted(_upstream(job, graph))}"
    )


@pytest.mark.parametrize("job", IRREVERSIBLE_JOBS)
@pytest.mark.parametrize("suite", ["ui-suite", "smoke-suite"])
def test_every_irreversible_job_is_downstream_of_both_suite_gates(job: str, suite: str) -> None:
    """Both live AND-gates sit upstream of every irreversible job.

    Whether they actually RUN is Part 3's `run_suites` decision; the ORDER is
    unconditional -- when they run, they run before anything is tagged or published.
    """
    graph = _graph()
    assert suite in _upstream(job, graph), (
        f"{job} is not (transitively) downstream of {suite}: upstream={sorted(_upstream(job, graph))}"
    )


def test_the_suites_are_downstream_of_the_build_and_upstream_of_the_tag() -> None:
    """The verification phase consumes the built artifacts and gates the tag."""
    graph = _graph()
    for suite in ("ui-suite", "smoke-suite"):
        assert "build-pkgs-portable" in _upstream(suite, graph), f"{suite} must consume the built .pkg artifacts"
        assert suite in graph["tag-release"], (
            f"tag-release must need {suite} DIRECTLY, got: {sorted(graph['tag-release'])}"
        )


def test_the_draft_release_is_downstream_of_the_tag() -> None:
    """softprops/action-gh-release CREATES a missing tag itself, so the draft job must
    never run before tag-release -- that is exactly how a failed run stranded a tag."""
    graph = _graph()
    assert "tag-release" in _upstream("release", graph)


# --------------------------------------------------------------------------- #
# Part 1: the tag is created in tag-release, on the pinned SHA -- not earlier
# --------------------------------------------------------------------------- #


def test_prepare_release_no_longer_creates_the_tag() -> None:
    """prepare-release only pins the release SHA (and pushes the docs-only notes
    commit). Creating or pushing the tag there is the pre-#1855 order that stranded
    two tag+draft pairs. (Reading tags -- `git tag --sort=...` for the compare base --
    is fine; only creation and push are forbidden.)"""
    body = "\n".join(_jobs()["prepare-release"])
    assert "git tag -a" not in body, body
    assert "refs/tags/" not in body, body
    assert "git push origin" in body, "prepare-release still pushes the notes commit to the channel branch"


def test_prepare_release_pins_a_sha_output() -> None:
    jobs = _jobs()
    outputs = "\n".join(jobs["prepare-release"])
    assert re.search(r"^\s+sha:\s+\$\{\{ steps\.pin\.outputs\.sha \}\}", outputs, re.MULTILINE), (
        f"prepare-release must expose the pinned release SHA as an output:\n{outputs}"
    )


def test_tag_release_creates_the_tag_on_the_pinned_sha() -> None:
    jobs = _jobs()
    script = _step_run_script(_step(jobs["tag-release"], "Create + push the tag on the verified commit"))
    assert 'git tag -a "$TAG" -m "$TAG" "$SHA"' in script, (
        f"the tag must be created ON the pinned SHA (the channel branch may have moved), got:\n{script}"
    )


@pytest.mark.parametrize("job", ["resolve-stamp", "build-pkgs-portable", "release"])
def test_artifact_jobs_check_out_the_pinned_sha_not_the_tag(job: str) -> None:
    """Everything downstream of prepare-release builds from the PINNED SHA: at build
    time the tag does not exist yet, and by publish time the branch may have moved."""
    body = "\n".join(_jobs()[job])
    ref_line = next(line for line in _jobs()[job] if line.strip().startswith("ref:"))
    assert "needs.prepare-release.outputs.sha" in ref_line, (
        f"{job}'s checkout ref must be the pinned SHA, got: {ref_line}"
    )
    assert "github.event.inputs.tag" not in ref_line, (
        f"{job} must not check out the tag -- it does not exist until tag-release runs, got: {ref_line}"
    )
    assert body  # the job body is non-empty (parser sanity)


# --------------------------------------------------------------------------- #
# Part 3: which channels run the live suites (read-matrix's run_suites decision)
# --------------------------------------------------------------------------- #


def _run_suites_decision(tmp_path: Path, tag: str, force_suites: str) -> dict[str, str]:
    """Execute read-matrix's REAL channel/run_suites step body under sh."""
    script = _step_run_script(_step(_jobs()["read-matrix"], "Detect pkg channel from tag"))
    output_file = tmp_path / f"github_output_{tag}_{force_suites or 'unset'}"
    output_file.write_text("")
    completed = subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "INPUT_TAG": tag,
            "FORCE_SUITES": force_suites,
            "GITHUB_OUTPUT": str(output_file),
        },
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    outputs: dict[str, str] = {}
    for line in output_file.read_text().splitlines():
        key, _, value = line.partition("=")
        outputs[key] = value
    return outputs


@pytest.mark.parametrize(
    ("tag", "expected_run_suites"),
    [
        ("v4.0.0.alpha.1", "false"),  # alpha: verify-checks (CI green) is the mandatory gate
        ("v4.0.0.beta.1", "false"),  # beta: same
        ("v4.0.0.rc.1", "true"),  # rc: full live verification before the tag
        ("v4.0.0", "true"),  # stable: full live verification before the tag
    ],
)
def test_run_suites_per_channel(tmp_path: Path, tag: str, expected_run_suites: str) -> None:
    outputs = _run_suites_decision(tmp_path, tag, "false")
    assert outputs["run_suites"] == expected_run_suites, outputs


@pytest.mark.parametrize("tag", ["v4.0.0.alpha.1", "v4.0.0.beta.1"])
def test_force_suites_turns_the_live_suites_back_on_for_an_alpha_or_beta(tmp_path: Path, tag: str) -> None:
    """The manual escape hatch: default off for alpha/beta, forceable per dispatch."""
    assert _run_suites_decision(tmp_path, tag, "false")["run_suites"] == "false"
    assert _run_suites_decision(tmp_path, tag, "true")["run_suites"] == "true"


@pytest.mark.parametrize("tag", ["v4.0.0.rc.1", "v4.0.0"])
def test_force_suites_cannot_turn_the_live_suites_off(tmp_path: Path, tag: str) -> None:
    """rc/stable always verify; the input only ever ADDS verification."""
    assert _run_suites_decision(tmp_path, tag, "false")["run_suites"] == "true"


def test_force_suites_input_is_declared_boolean_and_defaults_off() -> None:
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    dispatch = text.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
    assert "force_suites:" in dispatch, "release.yml must offer a force_suites dispatch input"
    block = dispatch.split("      force_suites:\n", 1)[1].split("\n\n", 1)[0]
    assert re.search(r"^\s+type:\s*boolean\s*$", block, re.MULTILINE), block
    assert re.search(r"^\s+default:\s*false\s*$", block, re.MULTILINE), block


@pytest.mark.parametrize("job_name", ["ui-suite", "smoke-suite"])
def test_the_suites_are_gated_on_the_run_suites_decision(job_name: str) -> None:
    if_block = _job_if_block(_jobs()[job_name])
    assert "needs.read-matrix.outputs.run_suites == 'true'" in if_block, if_block


def test_tag_release_tolerates_skipped_suites_only_when_they_were_not_required() -> None:
    """One code path: for alpha/beta the verification phase is EMPTY, not bypassed.

    The tolerance is a positive `run_suites == 'false'` comparison guarded by
    read-matrix having genuinely succeeded, so a crashed read-matrix (empty output)
    can never read as "the suites were not required".
    """
    if_block = _job_if_block(_jobs()["tag-release"])
    assert "needs.read-matrix.result == 'success'" in if_block, if_block
    assert "needs.read-matrix.outputs.run_suites == 'false'" in if_block, if_block
    assert "run_suites != 'true'" not in if_block, f"fail-open tolerance shape: {if_block}"


# --------------------------------------------------------------------------- #
# Part 1: tag_state narrows to the crash-after-tag window
#
# The real tag step, lifted verbatim and executed against a throwaway repo with a
# local `origin`. The only legitimate reason for the tag to pre-exist is a prior
# run that crashed AFTER tagging the same pinned SHA.
# --------------------------------------------------------------------------- #


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _tag_repo(tmp_path: Path) -> tuple[Path, str, str]:
    """A work repo with a bare `origin`, two commits; returns (repo, head_sha, older_sha)."""
    origin = tmp_path / "origin.git"
    repo = tmp_path / "work"
    subprocess.run(["git", "init", "--bare", "-q", str(origin)], check=True)  # noqa: S603
    subprocess.run(["git", "init", "-q", "-b", "devel", str(repo)], check=True)  # noqa: S603
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "a.txt").write_text("one\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-qm", "one")
    older = _git(repo, "rev-parse", "HEAD")
    (repo / "a.txt").write_text("two\n")
    _git(repo, "commit", "-qam", "two")
    head = _git(repo, "rev-parse", "HEAD")
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "devel")
    return repo, head, older


def _run_tag_step(repo: Path, tag: str, sha: str) -> subprocess.CompletedProcess[str]:
    script = _step_run_script(_step(_jobs()["tag-release"], "Create + push the tag on the verified commit"))
    return subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        cwd=repo,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": str(repo),
            "TAG": tag,
            "SHA": sha,
            "GITHUB_OUTPUT": str(repo / "gh_output"),
        },
        capture_output=True,
        text=True,
    )


def test_tag_step_creates_and_pushes_the_tag_on_the_pinned_sha(tmp_path: Path) -> None:
    repo, head, _older = _tag_repo(tmp_path)
    result = _run_tag_step(repo, "v9.9.9.rc.1", head)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _git(repo, "rev-list", "-n", "1", "refs/tags/v9.9.9.rc.1") == head
    assert "v9.9.9.rc.1" in _git(repo, "ls-remote", "--tags", "origin")
    assert f"sha={head}" in (repo / "gh_output").read_text()


def test_tag_step_resumes_a_tag_that_already_points_at_the_verified_sha(tmp_path: Path) -> None:
    """Scenario: a prior run crashed after tagging. Given the tag already exists on the
    SAME pinned SHA, when the step re-runs, then it reuses the tag and still succeeds."""
    repo, head, _older = _tag_repo(tmp_path)
    _git(repo, "tag", "-a", "v9.9.9.rc.1", "-m", "v9.9.9.rc.1", head)
    _git(repo, "push", "-q", "origin", "refs/tags/v9.9.9.rc.1")
    result = _run_tag_step(repo, "v9.9.9.rc.1", head)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _git(repo, "rev-list", "-n", "1", "refs/tags/v9.9.9.rc.1") == head


def test_tag_step_refuses_a_stale_tag_pointing_at_other_code(tmp_path: Path) -> None:
    """Given the tag exists on a DIFFERENT commit than the one this run verified,
    when the step runs, then it fails loudly and never moves the tag -- the verified
    artifacts belong to the pinned SHA, so silently reusing the old tag would publish
    assets that do not match their tag."""
    repo, head, older = _tag_repo(tmp_path)
    _git(repo, "tag", "-a", "v9.9.9.rc.1", "-m", "v9.9.9.rc.1", older)
    _git(repo, "push", "-q", "origin", "refs/tags/v9.9.9.rc.1")
    result = _run_tag_step(repo, "v9.9.9.rc.1", head)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "::error::" in (result.stdout + result.stderr)
    assert _git(repo, "rev-list", "-n", "1", "refs/tags/v9.9.9.rc.1") == older, "the stale tag must not be moved"
