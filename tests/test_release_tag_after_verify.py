"""Pin issue #1855: the release pipeline builds and VERIFIES before it tags, and
stops at a DRAFT.

`.github/workflows/release.yml` runs, in order: pin the channel-branch tip; mint
the tag locally on it (nothing pushed); build every `.pkg` from that SHA; run the
verification suites against those artifacts AND that same source tree; push the
tag; create the Release as a DRAFT with the deterministic placeholder body,
attach the packages, health-check the draft -- and STOP.

Publishing is a separate, human/Claude step: the notes and the title are authored
onto the draft and the draft is published by hand. Release notes are therefore not
files in this repository at all -- nothing here reads, writes or commits a
`docs/release-notes/<tag>.md`, and the pipeline pushes NOTHING to the channel
branch. The downstream effects that used to run after the in-pipeline publish flip
(pkg-repo republish, ports-fork bump) now fire from `release-published.yml` on the
real `release: published` event.

Two other parts ride along:

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
PUBLISHED_WORKFLOW = ROOT / ".github/workflows/release-published.yml"

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z][A-Za-z0-9_-]*):[ \t]*$")
_JOB_KEY_RE = re.compile(r"^    [A-Za-z_-]+:")
_STEP_HEADER_RE = re.compile(r"^      - ")

# Every job in release.yml that changes something outside this workflow run: the
# tag, the Release, its assets. Each MUST be downstream of the build and (when they
# run) of both live suites. The pkg-repo republish and the ports-fork bump are no
# longer here at all -- they hang off the real `release: published` event.
IRREVERSIBLE_JOBS = (
    "tag-release",
    "release",
    "attach-pkgs",
    "draft-healthcheck",
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


def test_prepare_release_mints_the_tag_locally_and_pushes_nothing() -> None:
    """Scenario: the tag is minted before the build so a conflicting tag is caught in
    seconds instead of after an hour of live suites -- but it stays LOCAL. Given a
    dispatch, when prepare-release runs, then it creates the annotated tag on the
    pinned SHA and pushes nothing at all: not the tag, and (notes are no longer files)
    not the channel branch either."""
    body = "\n".join(_jobs()["prepare-release"])
    assert 'git tag -a "$TAG" -m "$TAG" "$SHA"' in body, body
    assert "git push" not in body, f"prepare-release must push NOTHING; got:\n{body}"


def test_no_release_job_touches_a_notes_file() -> None:
    """Release notes are authored onto the GitHub Release, never committed to the repo.

    A committed changelog forces a changelog commit, which forces a push to the channel
    branch and a re-generation whenever devel moves; the released source tree should not
    carry its own changelog.
    """
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert "release-notes/" not in text, "release.yml must not read, write or commit a notes file"
    assert "NOTES_FILE" not in text, "release.yml must not read, write or commit a notes file"
    assert "<!-- SUMMARY:" not in text, "there is no notes file, so no `<!-- SUMMARY: … -->` title marker to parse"


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
# The run STOPS at a complete draft; publishing is a separate human/Claude step
# --------------------------------------------------------------------------- #


def test_the_release_is_created_as_a_draft() -> None:
    draft_step = _step(_jobs()["release"], "softprops/action-gh-release")
    assert "draft: true" in "\n".join(draft_step), "\n".join(draft_step)


def test_nothing_in_the_release_run_un_drafts_the_release() -> None:
    """The pipeline must never publish: the notes are authored onto the draft first,
    and only then does a human (or Claude) publish it."""
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert "--draft=false" not in text, "release.yml must not flip the draft to published"
    assert "draft: false" not in text, "release.yml must not flip the draft to published"
    assert "publish-release" not in _jobs(), "the in-pipeline publish job is gone; the draft is the end state"


def test_the_draft_healthcheck_is_the_terminal_job() -> None:
    """Completeness is still asserted -- a human must never be handed a draft that is
    missing the source archive or a .pkg -- it just no longer publishes anything."""
    jobs = _jobs()
    assert "draft-healthcheck" in jobs, "release.yml must health-check the finished draft"
    downstream = [name for name, lines in jobs.items() if "draft-healthcheck" in _needs(lines)]
    assert not downstream, f"nothing may run after the draft healthcheck, got: {downstream}"


@pytest.mark.parametrize("job", IRREVERSIBLE_JOBS)
def test_a_dry_run_stops_after_the_suites(job: str) -> None:
    """dry_run=true does steps 1-4 only: pin, build, verify -- then stop. Nothing that
    touches GitHub may be reachable without an explicit `dry_run == 'false'`."""
    if_block = _job_if_block(_jobs()[job])
    assert "dry_run == 'false'" in if_block, f"{job} is reachable in a dry run: {if_block}"


def test_the_draft_job_never_runs_without_the_tag() -> None:
    """Pre-rework the draft job tolerated a SKIPPED tag-release so a dry run could still
    render the body. That tolerance is gone: a real run whose tag-release was skipped
    must not reach softprops (which would create the missing tag itself)."""
    if_block = _job_if_block(_jobs()["release"])
    assert "needs.tag-release.result == 'success'" in if_block, if_block
    assert "needs.prepare-release.result == 'skipped'" not in if_block, (
        f"the draft job must not run when prepare-release was skipped: {if_block}"
    )


# --------------------------------------------------------------------------- #
# Downstream effects fire on the REAL published event, not inside the release run
# --------------------------------------------------------------------------- #


def test_downstream_jobs_left_the_release_workflow() -> None:
    jobs = _jobs()
    assert "repo-publish" not in jobs, "the pkg-repo dispatch must not run before the release is published"
    assert "sync-ports-fork" not in jobs, "the ports bump must not run before the release is published"


def test_the_published_workflow_triggers_on_a_published_release() -> None:
    text = PUBLISHED_WORKFLOW.read_text(encoding="utf-8")
    on_block = text.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
    assert "release:" in on_block, on_block
    assert "types: [published]" in on_block, on_block


def test_the_published_workflow_carries_both_downstream_effects() -> None:
    """Publishing a release must still refresh the pkg repo and bump the ports fork."""
    jobs = _jobs(PUBLISHED_WORKFLOW)
    assert "sync-ports-fork" in jobs, sorted(jobs)
    assert "repo-publish" in jobs, sorted(jobs)


def test_the_pkg_repo_dispatch_still_waits_for_the_ports_bump() -> None:
    """pfBlockerNG/pkg derives the NIGHTLY version from the -nightly port's PORTVERSION,
    so racing the bump ships a stale-versioned nightly (e.g. 4.0.0.alpha.3.* on the
    alpha.4 commit)."""
    graph = {name: _needs(lines) for name, lines in _jobs(PUBLISHED_WORKFLOW).items()}
    assert "sync-ports-fork" in _upstream("repo-publish", graph), graph


def test_the_published_workflow_reads_the_tag_from_the_release_payload() -> None:
    text = PUBLISHED_WORKFLOW.read_text(encoding="utf-8")
    assert "github.event.release.tag_name" in text, "the tag must come from the release that was published"


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
