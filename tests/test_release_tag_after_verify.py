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
branch.


Two other parts ride along:

* Part 2 -- only a RELEASED pfSense version may veto (see
  `tests/shell/resolve_legs_spec.sh` for the status predicate itself).
* Part 3 -- our own alpha/beta tags skip the live suites (`run_suites`), with a
  `force_suites` escape hatch only for release lines that carry a live corpus.

The reachability tests walk the real `needs:` graph rather than asserting on one
job's text, so ANY re-ordering that puts a mutation ahead of the build or ahead of
the suite AND-gates fails here.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from tests._workflow_steps import extract_after, extract_between
from tests.gitenv import scrubbed_git_env

ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"
PUBLISHED_WORKFLOW = ROOT / ".github/workflows/release-published.yml"

_JOB_HEADER_RE = re.compile(r"^  ([A-Za-z][A-Za-z0-9_-]*):[ \t]*$")
_JOB_KEY_RE = re.compile(r"^    [A-Za-z_-]+:")
_STEP_HEADER_RE = re.compile(r"^      - ")

# Draft-workflow jobs that change state outside the workflow run.
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
    raw = text[idx:].splitlines()
    first = next((line for line in raw if line.strip()), "")
    base = len(first) - len(first.lstrip())
    end = len(raw)
    for i, line in enumerate(raw):
        if line.strip() and len(line) - len(line.lstrip()) < base:
            end = i
            break
    return textwrap.dedent("\n".join(raw[:end])) + "\n"


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


def _job_outputs(job_lines: list[str]) -> list[str]:
    """The job's declared `outputs:` keys."""
    names: list[str] = []
    inside = False
    for line in job_lines:
        if line.startswith("    outputs:"):
            inside = True
            continue
        if inside:
            if _JOB_KEY_RE.match(line):
                break
            match = re.match(r"^      ([A-Za-z_][A-Za-z0-9_-]*):", line)
            if match is not None:
                names.append(match.group(1))
    return names


def _job_contents_scope(job_lines: list[str]) -> str:
    """The job's own `contents:` permission scope ('' when it declares none)."""
    line = next((ln for ln in job_lines if ln.strip().split("#", 1)[0].strip().startswith("contents:")), None)
    if line is None:
        return ""
    return line.split("contents:", 1)[1].split("#", 1)[0].strip()


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


def test_every_job_that_touches_a_release_can_actually_see_a_draft() -> None:
    """A DRAFT Release is invisible to a `contents: read` GITHUB_TOKEN, so a job that
    reads one must hold `contents: write` or it 404s on every real cut.

    PROBED in-session (2026-07-29, run 30442759084, two jobs differing only in scope):
    `GET /releases/tags/<tag>` returns 404 for a draft under BOTH scopes, so `gh release
    view` falls back to LISTING releases -- and that listing only returns drafts to a
    token with push access. Under `contents: read` the call printed "release not found"
    and exited 1 and the list showed 0 drafts; under `contents: write` it returned
    `{"assets":[],"isDraft":true,...}` and the list showed 1. This run never publishes,
    so every draft-reading job is write-scoped for VISIBILITY, not to mutate.
    """
    offenders = {}
    for name, lines in _jobs().items():
        body = "\n".join(lines)
        if "gh release " not in body and "action-gh-release" not in body:
            continue
        scope = _job_contents_scope(lines)
        if scope != "write":
            offenders[name] = scope or "<none: inherits the read-only workflow default>"
    assert not offenders, f"job(s) that read or write a Release without the scope a DRAFT read needs: {offenders}"


def test_the_complete_draft_is_the_last_thing_the_release_run_produces() -> None:
    jobs = _jobs()
    assert "draft-healthcheck" in jobs, "release.yml must health-check the finished draft"
    assert "sync-ports-fork" not in jobs, "the ports bump must wait for release: published"
    downstream = [name for name, lines in jobs.items() if "draft-healthcheck" in _needs(lines)]
    assert not downstream, f"the complete draft must be terminal, got: {downstream}"


@pytest.mark.parametrize("job", IRREVERSIBLE_JOBS)
def test_a_cancelled_run_never_tags_or_drafts(job: str) -> None:
    """Cancellation must prevent every external mutation in release.yml."""
    if_block = _job_if_block(_jobs()[job])
    assert "always()" not in if_block, f"{job} would still start on a CANCELLED run -- use !cancelled(): {if_block}"
    assert "!cancelled()" in if_block, f"{job} lost its skip tolerance: {if_block}"


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


def test_downstream_publish_effects_do_not_run_in_the_draft_workflow() -> None:
    jobs = _jobs()
    release_text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert "publish-pkg" not in jobs, "the pkg catalogue publish must wait for release: published"
    assert "sync-ports-fork" not in jobs, "the ports bump must wait for release: published"
    for marker in ("publish-pkg-repo.sh", "publish_release.py"):
        assert marker not in release_text, f"{marker} must not run inside the release workflow"


def test_the_published_workflow_triggers_on_a_published_release() -> None:
    text = PUBLISHED_WORKFLOW.read_text(encoding="utf-8")
    on_block = extract_between(text, "\non:\n", "\npermissions:\n")
    assert "release:" in on_block, on_block
    assert "types: [published]" in on_block, on_block


def test_the_published_workflow_carries_both_downstream_effects() -> None:
    jobs = _jobs(PUBLISHED_WORKFLOW)
    assert "publish-pkg" in jobs, sorted(jobs)
    assert "sync-ports-fork" in jobs, sorted(jobs)


@pytest.mark.parametrize("workflow", [RELEASE_WORKFLOW, PUBLISHED_WORKFLOW], ids=lambda p: p.name)
def test_no_job_declares_an_output_nobody_reads(workflow: Path) -> None:
    """Every declared job output must have a dotted ``needs`` or ``jobs`` consumer."""
    text = workflow.read_text(encoding="utf-8")
    unconsumed = sorted(
        f"{job}.{out}"
        for job, lines in _jobs(workflow).items()
        for out in _job_outputs(lines)
        if f"needs.{job}.outputs.{out}" not in text and f"jobs.{job}.outputs.{out}" not in text
    )
    assert not unconsumed, f"{workflow.name}: job output(s) nobody consumes: {unconsumed}"


@pytest.mark.parametrize("workflow", [RELEASE_WORKFLOW, PUBLISHED_WORKFLOW], ids=lambda p: p.name)
def test_no_job_output_is_read_through_index_syntax(workflow: Path) -> None:
    """Reject indexed output references that the dead-output scan cannot detect."""
    expressions = re.findall(r"\$\{\{(.*?)\}\}", workflow.read_text(encoding="utf-8"), re.DOTALL)
    indexed = [expr.strip() for expr in expressions if re.search(r"\b(?:needs|jobs)\s*\[", expr)]
    assert not indexed, f"{workflow.name}: index-syntax job reference(s) the dead-output scan cannot see: {indexed}"


def test_published_downstream_effects_resolve_the_release_independently() -> None:
    graph = {name: _needs(lines) for name, lines in _jobs(PUBLISHED_WORKFLOW).items()}
    assert graph["sync-ports-fork"] == {"resolve"}, graph
    assert graph["publish-pkg"] == {"resolve"}, graph


# Jobs that hold a credential worth stealing AND execute a repository script as shell.
_TRUSTED_HELPER_ROOT = "${GITHUB_WORKSPACE}/pfblockerng-src/scripts/"
CREDENTIALLED_JOBS = (
    (RELEASE_WORKFLOW, "prepare-release", _TRUSTED_HELPER_ROOT),
    (RELEASE_WORKFLOW, "release", _TRUSTED_HELPER_ROOT),
    (PUBLISHED_WORKFLOW, "sync-ports-fork", _TRUSTED_HELPER_ROOT),
)

_HELPER_CALL_RE = re.compile(r"\bsh\s+(\S*scripts/[A-Za-z0-9._-]+)")


@pytest.mark.parametrize(
    ("workflow", "job", "helper_root"),
    CREDENTIALLED_JOBS,
    ids=lambda item: item.name if isinstance(item, Path) else item,
)
def test_a_credentialled_job_runs_every_helper_from_a_trusted_checkout(
    workflow: Path, job: str, helper_root: str
) -> None:
    lines = _jobs(workflow)[job]
    checkout = _step(lines, "ref: ${{ github.workflow_sha }}")
    ref_line = next(line for line in checkout if line.strip().startswith("ref:"))
    assert "github.workflow_sha" in ref_line, f"{job}: the helper checkout must pin the trusted ref, got: {ref_line}"
    for untrusted in ("needs.release.outputs.tag", "needs.resolve.outputs.release_tag", "github.event"):
        assert untrusted not in ref_line, f"{job}: the helper must not come from the released tree, got: {ref_line}"

    calls = _HELPER_CALL_RE.findall("\n".join(lines))
    assert calls, f"{job} executes no repository helper at all -- has the job shape changed?"
    untrusted_calls = [call for call in calls if not call.lstrip('"').startswith(helper_root)]
    assert not untrusted_calls, f"{job} executes helpers outside its trusted checkout: {untrusted_calls}"


@pytest.mark.parametrize(
    ("workflow", "job", "_helper_root"),
    CREDENTIALLED_JOBS,
    ids=lambda item: item.name if isinstance(item, Path) else item,
)
def test_the_helper_checkout_never_persists_credentials(workflow: Path, job: str, _helper_root: str) -> None:
    checkout = _step(_jobs(workflow)[job], "ref: ${{ github.workflow_sha }}")
    assert any("persist-credentials: false" in line for line in checkout), "\n".join(checkout)


# --------------------------------------------------------------------------- #
# release-published.yml: trusted execution, and an off-scheme tag must say WHY
# --------------------------------------------------------------------------- #


def test_the_tag_classifier_runs_from_a_trusted_ref() -> None:
    """Workflow-text assertion (a checkout's `ref:` cannot be executed): the last
    untrusted-execution site in the pipeline.

    `release-version.sh` is executed as shell in this job, and a `release` event
    defaults the checkout to the RELEASED tag's tree — a tree the workflow does not
    control. The blast radius is small *today* (no App token, read-scoped
    GITHUB_TOKEN, pushes nowhere), but that is a property of the current job body, not
    of the design: the next credential this job grows would silently inherit the hole.
    Pin the trusted ref instead, so nobody has to re-derive "is this one safe?".
    """
    checkout = _step(_jobs(PUBLISHED_WORKFLOW)["resolve"], "uses: actions/checkout")
    ref_line = next(line for line in checkout if line.strip().startswith("ref:"))
    assert "github.workflow_sha" in ref_line, f"the classifier checkout must pin the trusted ref, got: {ref_line}"
    for untrusted in ("github.event.release", "github.ref", "tag_name"):
        assert untrusted not in ref_line, f"the classifier must not run from the released tree, got: {ref_line}"


def _published_tag_fixture(
    tmp_path: Path,
    tag: str,
    trailer: str | tuple[str, ...] | None = "edge",
    source_line: str = "release/4.0",
) -> Path:
    """Create a fetched tag object for the published-workflow step."""
    origin = tmp_path / "origin.git"
    repo = tmp_path / "published"
    subprocess.run(  # noqa: S603
        ["git", "init", "--bare", "-q", str(origin)], check=True, env=scrubbed_git_env(drop_git_vars=True)
    )
    subprocess.run(  # noqa: S603
        ["git", "init", "-q", "-b", "devel", str(repo)], check=True, env=scrubbed_git_env(drop_git_vars=True)
    )
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "a.txt").write_text("one\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-qm", "one")
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "devel")
    _git(repo, "push", "-q", "origin", f"HEAD:refs/heads/{source_line}")
    if trailer is None:
        _git(repo, "tag", tag)
    else:
        trailers = (trailer,) if isinstance(trailer, str) else trailer
        args = ["tag", "-a", tag, "-m", tag]
        args.extend(("-m", "\n".join(f"pfBlockerNG-Release-Channel: {value}" for value in trailers)))
        _git(repo, *args)
    _git(repo, "push", "-q", "origin", f"refs/tags/{tag}")
    (repo / "scripts").mkdir()
    for helper in ("release-version.sh", "release_version.py"):
        shutil.copy2(ROOT / "scripts" / helper, repo / "scripts" / helper)
    return repo


def _run_classify_step(
    tmp_path: Path,
    tag: str,
    trailer: str | tuple[str, ...] | None = "edge",
    release_prerelease: str = "true",
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    """Execute the REAL tag-classification step body under sh."""
    script = _step_run_script(_step(_jobs(PUBLISHED_WORKFLOW)["resolve"], "Classify the tag"))
    repo = _published_tag_fixture(tmp_path, tag, trailer)
    output_file = tmp_path / "gh_output"
    output_file.write_text("")
    completed = subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        cwd=repo,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "TAG": tag,
            "RELEASE_PRERELEASE": release_prerelease,
            "GITHUB_OUTPUT": str(output_file),
        },
        capture_output=True,
        text=True,
    )
    outputs: dict[str, str] = {}
    for line in output_file.read_text().splitlines():
        key, _, value = line.partition("=")
        outputs[key] = value
    return completed, outputs


def _run_classify_with_source_line(tmp_path: Path, tag: str, source_line: str) -> subprocess.CompletedProcess[str]:
    """Run the published classifier against an explicitly chosen remote release line."""
    script = _step_run_script(_step(_jobs(PUBLISHED_WORKFLOW)["resolve"], "Classify the tag"))
    repo = _published_tag_fixture(tmp_path, tag, "edge", source_line)
    output_file = tmp_path / "gh_output_route"
    output_file.write_text("")
    return subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        cwd=repo,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "TAG": tag,
            "RELEASE_PRERELEASE": "true",
            "GITHUB_OUTPUT": str(output_file),
        },
        capture_output=True,
        text=True,
    )


def _run_port_sync_validation(portversion: str) -> subprocess.CompletedProcess[str]:
    script = _step_run_script(_step(_jobs(PUBLISHED_WORKFLOW)["sync-ports-fork"], "Bump PORTVERSION and push"))
    marker = 'case "$CHANNEL" in'
    validation, _after = script.split(marker, 1)
    return subprocess.run(  # noqa: S603
        ["sh", "-c", "set -eu\n" + validation],
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "SOURCE": "release/4.0",
            "CHANNEL": "edge",
            "TAG": "v4.0.0.a1",
            "PORTVERSION": portversion,
        },
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("stage", ["a", "b", "r"])
def test_sync_ports_accepts_short_prerelease_versions(stage: str) -> None:
    result = _run_port_sync_validation(f"4.0.0.{stage}1")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("stage", ["alpha", "beta", "rc"])
def test_sync_ports_rejects_long_prerelease_versions(stage: str) -> None:
    result = _run_port_sync_validation(f"4.0.0.{stage}.1")
    assert result.returncode != 0, result.stdout + result.stderr


def test_sync_ports_preserves_rebuild_and_push_retry_contract() -> None:
    script = _step_run_script(_step(_jobs(PUBLISHED_WORKFLOW)["sync-ports-fork"], "Bump PORTVERSION and push"))
    assert 'OLD_PORTVERSION="$(grep -m1 \'^PORTVERSION=\' "$MAKEFILE"' in script
    assert 'OLD_PORTREVISION="$(grep -m1 \'^PORTREVISION=\' "$MAKEFILE"' in script

    assert '"${OLD_PORTVERSION}" "${OLD_PORTREVISION}" "${PORTVERSION}"' in script
    assert 'if [ "${NEW_PORTREVISION}" -gt 0 ]; then' in script
    assert "n=0" in script
    assert "n=$((n + 1))" in script
    assert "until git push origin HEAD:pfblockerng/use-github; do" in script
    assert 'if [ "$n" -ge 3 ]; then' in script
    assert "git pull --rebase origin pfblockerng/use-github" in script


def test_published_classifier_rejects_tag_outside_derived_release_line(tmp_path: Path) -> None:
    result = _run_classify_with_source_line(tmp_path, "v4.0.0.a1", "release/5.0")
    assert result.returncode != 0, result.stdout + result.stderr


def test_published_classifier_accepts_tag_on_derived_release_line(tmp_path: Path) -> None:
    result = _run_classify_with_source_line(tmp_path, "v4.0.0.a1", "release/4.0")
    assert result.returncode == 0, result.stdout + result.stderr


def test_an_off_scheme_published_tag_reports_the_real_reason(tmp_path: Path) -> None:
    """release-version.sh writes its diagnostics to stderr, so capturing only stdout
    annotated an empty line and buried the reason in the raw log.

    Asserted on the ANNOTATION LINE alone: the workflow's own wording deliberately does
    not restate the reason, so "is not a valid release tag" can only have come from the
    captured stderr. Drop the capture and this test goes red.
    """
    completed, _outputs = _run_classify_step(tmp_path, "v4.0.0.gamma.1")
    combined = completed.stdout + completed.stderr
    assert completed.returncode != 0, combined
    annotations = [ln for ln in combined.splitlines() if ln.startswith("::error::")]
    assert len(annotations) == 1, combined
    assert "v4.0.0.gamma.1" in annotations[0], annotations[0]
    assert "is not a valid release tag" in annotations[0], annotations[0]


def test_a_scheme_tag_classifies_cleanly(tmp_path: Path) -> None:
    completed, outputs = _run_classify_step(tmp_path, "v4.0.0.a7")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert outputs["channel"] == "edge", outputs
    assert outputs["source"] == "release/4.0", outputs
    assert outputs["portversion"] == "4.0.0.a7", outputs


def test_the_published_workflow_reads_the_tag_from_the_release_payload() -> None:
    text = PUBLISHED_WORKFLOW.read_text(encoding="utf-8")
    assert "github.event.release.tag_name" in text, "the tag must come from the release that was published"


def test_release_dispatch_requires_explicit_channel_and_source() -> None:
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    dispatch = extract_between(text, "\non:\n", "\npermissions:\n")
    channel = extract_between(dispatch, "      channel:\n", "\n\n")
    assert re.search(r"^\s+type:\s*choice\s*$", channel, re.MULTILINE), channel
    assert re.search(r"^\s+options:\s*\[stable, testing, edge\]\s*$", channel, re.MULTILINE), channel
    source = extract_between(dispatch, "      source:\n", "\n\n")
    assert re.search(r"^\s+required:\s*true\s*$", source, re.MULTILINE), source
    assert "release/X.Y" in source, source


def test_release_uses_explicit_channel_and_exact_source_line() -> None:
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert 'release-version.sh "$TAG" "$CHANNEL" "$SOURCE"' in text, text
    assert 'release-version.sh "$TAG")' not in text, text
    assert 'git checkout "$SOURCE"' in text, text
    assert 'if [ "$channel" = "devel" ]' not in text, text


def test_tag_step_writes_and_validates_the_release_channel_trailer() -> None:
    jobs = _jobs()
    prepare = "\n".join(_jobs()["prepare-release"])
    tag = _step_run_script(_step(jobs["tag-release"], "Create + push the tag on the verified commit"))
    combined = prepare + "\n" + tag
    assert "git interpret-trailers" in combined, combined
    assert "pfBlockerNG-Release-Channel" in combined, combined
    assert combined.count("grep -Eic '^pfBlockerNG-Release-Channel:'") == 2, combined
    assert 'git cat-file -t "refs/tags/${TAG}"' in tag, tag
    assert 'git rev-parse "refs/tags/${TAG}^{commit}"' in tag, tag


@pytest.mark.parametrize(
    "trailer",
    [
        None,
        (),
        ("edge", "edge"),
        ("edge", "testing"),
        ("edge\npfblockerng-release-channel: testing",),
        ("edge\npfblockerng-release-channel:testing",),
        ("edge\nPFBLOCKERNG-RELEASE-CHANNEL:\ttesting",),
        ("bogus",),
    ],
    ids=[
        "lightweight",
        "missing",
        "duplicate",
        "conflicting",
        "case-conflicting",
        "no-space-conflicting",
        "tab-conflicting",
        "unknown",
    ],
)
def test_published_workflow_rejects_invalid_channel_trailers(tmp_path: Path, trailer: object) -> None:
    values = trailer if isinstance(trailer, tuple) else trailer
    completed, _outputs = _run_classify_step(tmp_path, "v4.0.0.a7", values)  # type: ignore[arg-type]
    assert completed.returncode != 0, completed.stdout + completed.stderr


def test_published_workflow_passes_the_validated_channel_to_classifier(tmp_path: Path) -> None:
    completed, outputs = _run_classify_step(tmp_path, "v4.0.0.a7", "edge")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert outputs["channel"] == "edge", outputs
    assert outputs["source"] == "release/4.0", outputs


@pytest.mark.parametrize(
    ("tag", "trailer", "release_prerelease"),
    [("v4.0.0", "stable", "true"), ("v4.0.0.a7", "edge", "false")],
)
def test_published_workflow_rejects_release_flag_mismatch(
    tmp_path: Path, tag: str, trailer: str, release_prerelease: str
) -> None:
    step = "\n".join(_step(_jobs(PUBLISHED_WORKFLOW)["resolve"], "Classify the tag"))
    assert "github.event.release.prerelease" in step, step
    completed, _outputs = _run_classify_step(tmp_path, tag, trailer, release_prerelease)
    assert completed.returncode != 0, completed.stdout + completed.stderr


# --------------------------------------------------------------------------- #
# Part 3: which channels run the live suites (read-matrix's run_suites decision)
# --------------------------------------------------------------------------- #


def _run_suites_decision(
    tmp_path: Path,
    tag: str,
    force_suites: str,
    *,
    source: str = "release/4.0",
) -> dict[str, str]:
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
            "INPUT_CHANNEL": "stable"
            if tag in {"v4.0.0", "v3.3.3"}
            else ("testing" if tag.startswith("v3.3.3.") else "edge"),
            "INPUT_SOURCE": source,
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
        ("v4.0.0.a1", "false"),  # alpha: verify-checks (CI green) is the mandatory gate
        ("v4.0.0.b1", "false"),  # beta: same
        ("v4.0.0.r1", "true"),  # rc: full live verification before the tag
        ("v4.0.0", "true"),  # stable: full live verification before the tag
    ],
)
def test_run_suites_per_channel(tmp_path: Path, tag: str, expected_run_suites: str) -> None:
    outputs = _run_suites_decision(tmp_path, tag, "false")
    assert outputs["run_suites"] == expected_run_suites, outputs


@pytest.mark.parametrize("tag", ["v4.0.0.a1", "v4.0.0.b1"])
def test_force_suites_turns_the_live_suites_back_on_for_an_alpha_or_beta(tmp_path: Path, tag: str) -> None:
    """The manual escape hatch for release lines that carry live suites."""
    assert _run_suites_decision(tmp_path, tag, "false")["run_suites"] == "false"
    assert _run_suites_decision(tmp_path, tag, "true")["run_suites"] == "true"


@pytest.mark.parametrize("tag", ["v4.0.0.r1", "v4.0.0"])
def test_force_suites_cannot_turn_the_live_suites_off(tmp_path: Path, tag: str) -> None:
    """rc/stable always verify; the input only ever ADDS verification."""
    assert _run_suites_decision(tmp_path, tag, "false")["run_suites"] == "true"


@pytest.mark.parametrize("tag", ["v3.3.3.a1", "v3.3.3"])
@pytest.mark.parametrize("force_suites", ["false", "true"])
def test_release_33_never_runs_live_suites(tmp_path: Path, tag: str, force_suites: str) -> None:
    outputs = _run_suites_decision(tmp_path, tag, force_suites, source="release/3.3")
    assert outputs["run_suites"] == "false", outputs


def _parse_github_outputs(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    outputs: dict[str, str] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if "<<" in line.partition("=")[0]:
            key, delimiter = line.split("<<", 1)
            assert key and delimiter, f"invalid GitHub output record: {line!r}"
            value_lines: list[str] = []
            index += 1
            while index < len(lines) and lines[index] != delimiter:
                value_lines.append(lines[index])
                index += 1
            assert index < len(lines), f"unterminated GitHub output record for {key!r}"
            outputs[key] = "\n".join(value_lines)
        else:
            key, separator, value = line.partition("=")
            assert key and separator, f"invalid GitHub output record: {line!r}"
            outputs[key] = value
        index += 1
    return outputs


def _run_extra_pkgs_decision(tmp_path: Path, source: str, extra_pkgs: str) -> str:
    script = _step_run_script(_step(_jobs()["build-pkgs-portable"], "Resolve release-line extras"))
    output_file = tmp_path / "extra_pkgs_output"
    output_file.write_text("")
    completed = subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "SOURCE": source,
            "MATRIX_EXTRA_PKGS": extra_pkgs,
            "GITHUB_OUTPUT": str(output_file),
        },
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    outputs = _parse_github_outputs(output_file)
    assert set(outputs) == {"extra_pkgs"}, outputs
    return outputs["extra_pkgs"]


def test_release_33_suppresses_matrix_extra_packages(tmp_path: Path) -> None:
    assert _run_extra_pkgs_decision(tmp_path, "release/3.3", '["textproc/py-charset-normalizer"]') == "[]"


@pytest.mark.parametrize(
    "extra_pkgs",
    [
        [],
        ["textproc/py-charset-normalizer"],
        ["textproc/py-charset-normalizer", "security/ca_root_nss"],
        ["category/line\nbreak", "__EXTRA_PKGS__", "category/name<<__EXTRA_PKGS__", 'category/quote"and\\slash'],
    ],
)
def test_other_release_lines_keep_matrix_extra_packages(tmp_path: Path, extra_pkgs: list[str]) -> None:
    rendered = json.dumps(extra_pkgs, indent=2)
    assert json.loads(_run_extra_pkgs_decision(tmp_path, "release/4.0", rendered)) == extra_pkgs


def _run_build_record(
    tmp_path: Path,
    *,
    source: str,
    matrix_extra_pkgs: list[str],
    effective_extra_pkgs: list[str],
) -> dict[str, object]:
    script = _step_run_script(_step(_jobs()["build-pkgs-portable"], "Write the destination-bound build record"))
    row = {
        "variant": "CE",
        "pfsense_version": "2.8",
        "freebsd_major": "15",
        "extra_pkgs": matrix_extra_pkgs,
    }
    completed = subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "TAG": "v3.3.5",
            "CHANNEL": "stable",
            "SOURCE": source,
            "PORTVERSION": "3.3.5",
            "CLASSIFICATION": "final",
            "COMMIT": "b" * 40,
            "CREATED": "1",
            "MATRIX_ROW": json.dumps(row),
            "EXTRA_PKGS": json.dumps(effective_extra_pkgs),
            "PORTS_SHA": "a" * 40,
            "DEPENDENCY_BUILDER": json.dumps(
                {
                    "python": "3.11.15",
                    "pip": "26.2.1",
                    "setuptools": "75.6.0",
                    "wheel": "0.45.1",
                    "zstandard": "0.25.0",
                    "uv": "0.12.6",
                    "uv_lock_sha256": "d" * 64,
                }
            ),
            "RUNNER_TEMP": str(tmp_path),
        },
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads((tmp_path / "build-record.json").read_text())


def test_release_33_build_record_uses_effective_empty_extras(tmp_path: Path) -> None:
    record = _run_build_record(
        tmp_path,
        source="release/3.3",
        matrix_extra_pkgs=["textproc/py-charset-normalizer"],
        effective_extra_pkgs=[],
    )

    matrix_row = record["matrix_row"]
    assert isinstance(matrix_row, dict)
    assert matrix_row["extra_pkgs"] == []
    assert "dependency_builder" not in record


@pytest.mark.parametrize(
    ("extra_pkgs", "has_dependency_builder"),
    [([], False), (["textproc/py-charset-normalizer"], True)],
)
def test_build_record_only_records_dependency_builder_for_extra_packages(
    tmp_path: Path,
    extra_pkgs: list[str],
    has_dependency_builder: bool,
) -> None:
    record = _run_build_record(
        tmp_path,
        source="release/4.0",
        matrix_extra_pkgs=extra_pkgs,
        effective_extra_pkgs=extra_pkgs,
    )

    assert ("dependency_builder" in record) is has_dependency_builder


def test_release_33_decision_and_matrix_bindings_are_not_bypassed() -> None:
    job = _jobs()["build-pkgs-portable"]
    decision = "\n".join(_step(_jobs()["read-matrix"], "Detect pkg channel from tag"))
    extras = "\n".join(_step(job, "Resolve release-line extras"))
    record = "\n".join(_step(job, "Write the destination-bound build record"))
    build = "\n".join(_step(job, "Build the .pkg via build-leg.sh"))

    assert "INPUT_SOURCE:  ${{ github.event.inputs.source }}" in decision
    assert "MATRIX_EXTRA_PKGS: ${{ toJson(matrix.extra_pkgs) }}" in extras
    assert "MATRIX_ROW:    ${{ toJson(matrix) }}" in record
    assert "EXTRA_PKGS:   ${{ steps.extras.outputs.extra_pkgs }}" in build


def test_force_suites_input_is_declared_boolean_and_defaults_off() -> None:
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    dispatch = extract_between(text, "\non:\n", "\npermissions:\n")
    assert "force_suites:" in dispatch, "release.yml must offer a force_suites dispatch input"
    block = extract_between(dispatch, "      force_suites:\n", "\n\n")
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
        env=scrubbed_git_env(drop_git_vars=True),
    ).stdout.strip()


def _tag_repo(tmp_path: Path) -> tuple[Path, str, str]:
    """A work repo with a bare `origin`, two commits; returns (repo, head_sha, older_sha)."""
    origin = tmp_path / "origin.git"
    repo = tmp_path / "work"
    subprocess.run(  # noqa: S603
        ["git", "init", "--bare", "-q", str(origin)], check=True, env=scrubbed_git_env(drop_git_vars=True)
    )
    subprocess.run(  # noqa: S603
        ["git", "init", "-q", "-b", "devel", str(repo)], check=True, env=scrubbed_git_env(drop_git_vars=True)
    )
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
            "CHANNEL": "testing",
            "SOURCE": "release/9.9",
            "GITHUB_OUTPUT": str(repo / "gh_output"),
        },
        capture_output=True,
        text=True,
    )


def test_tag_step_creates_and_pushes_the_tag_on_the_pinned_sha(tmp_path: Path) -> None:
    repo, head, _older = _tag_repo(tmp_path)
    result = _run_tag_step(repo, "v9.9.9.r1", head)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _git(repo, "rev-list", "-n", "1", "refs/tags/v9.9.9.r1") == head
    assert "v9.9.9.r1" in _git(repo, "ls-remote", "--tags", "origin")
    assert f"sha={head}" in (repo / "gh_output").read_text()


def test_tag_step_resumes_a_tag_that_already_points_at_the_verified_sha(tmp_path: Path) -> None:
    """Reuse an existing annotated tag only when it points to the pinned SHA."""
    repo, head, _older = _tag_repo(tmp_path)
    _git(repo, "tag", "-a", "v9.9.9.r1", "-m", "v9.9.9.r1", "-m", "pfBlockerNG-Release-Channel: testing", head)
    _git(repo, "push", "-q", "origin", "refs/tags/v9.9.9.r1")
    result = _run_tag_step(repo, "v9.9.9.r1", head)
    assert result.returncode == 0, result.stdout + result.stderr
    assert _git(repo, "rev-list", "-n", "1", "refs/tags/v9.9.9.r1") == head


def test_tag_step_refuses_a_stale_tag_pointing_at_other_code(tmp_path: Path) -> None:
    """Given the tag exists on a DIFFERENT commit than the one this run verified,
    when the step runs, then it fails loudly and never moves the tag -- the verified
    artifacts belong to the pinned SHA, so silently reusing the old tag would publish
    assets that do not match their tag."""
    repo, head, older = _tag_repo(tmp_path)
    _git(repo, "tag", "-a", "v9.9.9.r1", "-m", "v9.9.9.r1", "-m", "pfBlockerNG-Release-Channel: testing", older)
    _git(repo, "push", "-q", "origin", "refs/tags/v9.9.9.r1")
    result = _run_tag_step(repo, "v9.9.9.r1", head)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "::error::" in (result.stdout + result.stderr)
    assert _git(repo, "rev-list", "-n", "1", "refs/tags/v9.9.9.r1") == older, "the stale tag must not be moved"


@pytest.mark.parametrize(
    "trailers",
    [
        None,
        (),
        ("testing", "testing"),
        ("testing", "edge"),
        ("testing\npfblockerng-release-channel: edge",),
        ("testing\npfblockerng-release-channel:edge",),
        ("testing\nPFBLOCKERNG-RELEASE-CHANNEL:\tedge",),
        ("bogus",),
    ],
    ids=[
        "lightweight",
        "missing",
        "duplicate",
        "conflicting",
        "case-conflicting",
        "no-space-conflicting",
        "tab-conflicting",
        "unknown",
    ],
)
def test_tag_step_refuses_existing_tags_without_exact_channel_metadata(tmp_path: Path, trailers: object) -> None:
    repo, head, _older = _tag_repo(tmp_path)
    tag = "v9.9.9.r1"
    if trailers is None:
        _git(repo, "tag", tag, head)
    else:
        args = ["tag", "-a", tag, "-m", tag]
        assert isinstance(trailers, tuple)
        args.extend(("-m", "\n".join(f"pfBlockerNG-Release-Channel: {value}" for value in trailers)))
        _git(repo, *args, head)
    _git(repo, "push", "-q", "origin", f"refs/tags/{tag}")
    result = _run_tag_step(repo, tag, head)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "::error::" in result.stdout + result.stderr


# --------------------------------------------------------------------------- #
# `retag`: the operator states the intent, the workflow never guesses it
#
# The pin is the channel-branch tip. If the branch moved after a run pushed its
# tag, re-dispatching the same tag pins a NEW commit and then rejects its own
# already-pushed tag as stale -- unrecoverable without deleting the tag by hand.
# `retag=true` says "start clean on the current tip", and the workflow only obeys
# when that is provably safe.
# --------------------------------------------------------------------------- #


def test_retag_input_is_declared_boolean_and_defaults_off() -> None:
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    dispatch = extract_between(text, "\non:\n", "\npermissions:\n")
    assert "retag:" in dispatch, "release.yml must offer a retag dispatch input"
    block = extract_between(dispatch, "      retag:\n", "\n\n")
    assert re.search(r"^\s+type:\s*boolean\s*$", block, re.MULTILINE), block
    assert re.search(r"^\s+default:\s*false\s*$", block, re.MULTILINE), block


def test_the_retag_step_is_opt_in_and_runs_before_the_pin() -> None:
    """Workflow-text assertion (a step's own `if:` cannot be executed): the deletion
    is reachable ONLY with retag=true, and it happens before the SHA is pinned so the
    re-cut lands on the freshly pinned commit."""
    steps = _steps(_jobs()["prepare-release"])
    names = ["\n".join(s) for s in steps]
    retag_idx = next(i for i, s in enumerate(names) if "Delete the existing tag" in s)
    pin_idx = next(i for i, s in enumerate(names) if "id: pin" in s)
    assert retag_idx < pin_idx, "the retag deletion must run BEFORE the SHA is pinned"
    if_line = next(line for line in steps[retag_idx] if line.strip().startswith("if:"))
    assert "github.event.inputs.retag == 'true'" in if_line, if_line


def test_only_the_pin_job_may_delete_and_it_says_why() -> None:
    """Workflow-text assertion: this is the one place the pipeline REMOVES something
    from GitHub. GitHub scopes permissions per job, not per step, so the write scope
    must be justified in place rather than silently widened."""
    body = "\n".join(_jobs()["prepare-release"])
    assert "contents: write" in body, body
    assert "retag" in extract_after(body, "contents: write")[:300], (
        "the write scope must name the retag deletion as its reason"
    )
    deleting_jobs = {name for name, lines in _jobs().items() if "gh release delete" in "\n".join(lines)}
    assert deleting_jobs == {"prepare-release"}, f"only prepare-release may delete: {deleting_jobs}"


def _run_retag_step(
    tmp_path: Path,
    tag: str,
    release_json: str | None,
    dry_run: str = "false",
    make_tag: bool = True,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Execute the REAL retag step body against a throwaway repo and a `gh` stub.

    `release_json` is what `gh release view` returns (None = no release at all, i.e.
    gh exits non-zero). Returns the completed process plus every gh invocation.
    """
    repo = tmp_path / "work"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "devel")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "a.txt").write_text("one\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-qm", "one")
    if make_tag:
        _git(repo, "tag", "-a", tag, "-m", tag)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh_log = tmp_path / "gh.log"
    meta = tmp_path / "meta.json"
    meta.write_text(release_json or "")
    (bin_dir / "gh").write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{gh_log}"\n'
        'if [ "$1 $2" = "release view" ]; then\n'
        f'  [ -s "{meta}" ] || exit 1\n'
        f'  cat "{meta}"\n'
        "fi\n"
        "exit 0\n"
    )
    (bin_dir / "gh").chmod(0o755)

    script = _step_run_script(_step(_jobs()["prepare-release"], "Delete the existing tag"))
    completed = subprocess.run(  # noqa: S603
        ["sh", "-c", script],
        cwd=repo,
        env={
            "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
            "HOME": str(repo),
            "TAG": tag,
            "REPO": "owner/repo",
            "DRY_RUN": dry_run,
            "GH_TOKEN": "stub",
        },
        capture_output=True,
        text=True,
    )
    calls = gh_log.read_text().splitlines() if gh_log.exists() else []
    return completed, calls


def _tag_still_there(tmp_path: Path, tag: str) -> bool:
    return (
        subprocess.run(  # noqa: S603
            ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"],
            cwd=tmp_path / "work",
            capture_output=True,
            env=scrubbed_git_env(drop_git_vars=True),
        ).returncode
        == 0
    )


def test_retag_refuses_a_published_release(tmp_path: Path) -> None:
    """Given the tag already carries a PUBLISHED Release, when retag runs, then it
    refuses: a published release is immutable, so retagging cannot rescue it and the
    only way forward is the next .N."""
    completed, calls = _run_retag_step(tmp_path, "v9.9.9.r1", '{"isDraft":false,"assets":[]}')
    assert completed.returncode != 0, completed.stdout + completed.stderr
    assert "::error::" in completed.stdout + completed.stderr
    assert "PUBLISHED" in completed.stdout + completed.stderr
    assert not [c for c in calls if "delete" in c or "DELETE" in c], calls
    assert _tag_still_there(tmp_path, "v9.9.9.r1")


def test_retag_refuses_a_draft_that_already_has_assets(tmp_path: Path) -> None:
    """Given a DRAFT with assets attached, when retag runs, then it refuses and names
    BOTH ways forward.

    The state machine is right, but "that draft is a finished cut waiting for its notes,
    author them and publish it" is not: the `release` job attaches the source archive
    before `attach-pkgs` runs, so a crash in between leaves a draft WITH an asset and
    NOT ONE `.pkg`. Publishing that ships an empty release. The refusal cannot tell the
    two apart -- which is exactly why it refuses instead of deleting -- so it must offer
    the operator both routes rather than pick one for them: re-dispatch the same tag
    with `retag=false` to finish the draft, or delete it by hand to start over.
    """
    completed, calls = _run_retag_step(tmp_path, "v9.9.9.r1", '{"isDraft":true,"assets":[{"name":"x.pkg"}]}')
    message = completed.stdout + completed.stderr
    assert completed.returncode != 0, message
    assert "::error::" in message
    assert not [c for c in calls if "delete" in c or "DELETE" in c], calls
    assert _tag_still_there(tmp_path, "v9.9.9.r1")
    assert "retag=false" in message, f"the refusal must name the way to FINISH that draft: {message}"
    assert "by hand" in message, f"the refusal must name the way to START OVER: {message}"


def test_retag_deletes_an_assetless_draft_together_with_the_tag(tmp_path: Path) -> None:
    """An assetless draft is the debris of a crashed run. Leaving it while deleting its
    tag would orphan it and produce two drafts for the same tag, so both go."""
    completed, calls = _run_retag_step(tmp_path, "v9.9.9.r1", '{"isDraft":true,"assets":[]}')
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert any(c.startswith("release delete v9.9.9.r1") for c in calls), calls
    assert any("git/refs/tags/v9.9.9.r1" in c for c in calls), calls
    assert not _tag_still_there(tmp_path, "v9.9.9.r1"), "the local ref must go too, or the pin re-finds it"


def test_retag_with_no_release_deletes_only_the_tag(tmp_path: Path) -> None:
    completed, calls = _run_retag_step(tmp_path, "v9.9.9.r1", None)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not [c for c in calls if c.startswith("release delete")], calls
    assert any("git/refs/tags/v9.9.9.r1" in c for c in calls), calls
    assert not _tag_still_there(tmp_path, "v9.9.9.r1")


def test_retag_is_a_silent_no_op_when_no_tag_exists(tmp_path: Path) -> None:
    completed, calls = _run_retag_step(tmp_path, "v9.9.9.r1", None, make_tag=False)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not [c for c in calls if "delete" in c or "DELETE" in c], calls


@pytest.mark.parametrize("release_json", [None, '{"isDraft":true,"assets":[]}'])
def test_a_dry_run_never_deletes_anything(tmp_path: Path, release_json: str | None) -> None:
    """Defence in depth: the job is real-publish only, so this step cannot run in a dry
    run at all -- but if that gate is ever relaxed, the step still refuses to delete and
    only reports what it would have removed."""
    completed, calls = _run_retag_step(tmp_path, "v9.9.9.r1", release_json, dry_run="true")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not [c for c in calls if "delete" in c or "DELETE" in c], calls
    assert _tag_still_there(tmp_path, "v9.9.9.r1")
    assert "would delete" in completed.stdout.lower(), completed.stdout
