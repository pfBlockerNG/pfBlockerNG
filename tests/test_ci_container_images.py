"""Guard: every installing CI job runs on a pre-baked ci-image container (issue #3852).

Toolchains are baked into two Debian images (`ci`, `ci-vm`) that the reusable
`.github/workflows/ci-image.yml` builds once; a job then runs INSIDE one via `container:`
instead of installing its toolchain at job time. This guard fails the moment a job drifts
back to installing, and the three rules are pure functions over parsed YAML so synthetic
workflows prove each one rejects a violation and accepts a compliant job:

1. Container rule -- every job is a reusable `uses:` call, is listed in BARE (installs
   nothing, so needs no image) or in DOCKER_WRAPPED (test.yml's two jobs, whose every
   `run:` step `docker run`s the image itself), or declares `container.image` = a ci-image
   output, `--init`, and (ci_vm) `--device /dev/kvm` + `--cap-add NET_ADMIN`. Each needs the
   `ci-image` job, and a workflow's `ci-image` job must be the reusable call.
2. Banned-step rule -- no setup-* action, `apt-get`, `udevadm` or
   `playwright install --with-deps` in any workflow job or `.github/actions/*` composite step.
3. Stale-entry rule -- BARE and DOCKER_WRAPPED name only jobs that exist, so the lists
   cannot rot into permanent exemptions for jobs that were renamed away.

Run bodies are matched as plain text: `apt-get` inside a shell comment still counts, on
purpose -- a guard that had to parse shell would have holes.

Both `.yml` and `.yaml` are scanned: GitHub Actions loads either extension.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
_KNOWN_ACTION = ".github/actions/read-version-matrix/action.yml"  # a scan that misses it scanned the wrong place
_EXTENSIONS = ("yml", "yaml")

CI_IMAGE_JOB = "ci-image"
CI_IMAGE_USES = "./.github/workflows/ci-image.yml"
_CI_IMAGE = "${{ needs.ci-image.outputs.ci }}"
_CI_VM_IMAGE = "${{ needs.ci-image.outputs.ci_vm }}"

# filename (workflows) or repo-relative path (composite actions) -> parsed document
Docs = dict[str, Any]
JobKey = tuple[str, str]

_STOCK = "orchestration on the runner's stock git/gh/python3/sh; installs nothing"
_SHELL_ONLY = "shell-only gate or aggregator; no checkout, installs nothing"

# Jobs that install nothing and so run on a bare runner. Adding a job here is an owner-visible
# decision: it exempts the job from the container rule. Banned steps (rule 2) still apply.
BARE: dict[JobKey, str] = {
    ("agent-config.yml", "agent-config"): _STOCK,
    ("build-image.yml", "resolve-version"): _STOCK,
    ("ci-image.yml", "build"): "builds the images, so it cannot run inside them",
    ("coderabbit-cli.yml", "cli-review"): "dispatch-only review tooling, not CI; tracks the vendor's latest CLI",
    ("context-budget.yml", "context-budget"): _STOCK,
    ("image-refresh.yml", "plan"): _STOCK,
    ("nightly-failure-alert.yml", "alert"): _SHELL_ONLY,
    ("nightly-failure-alert.yml", "recovery"): _SHELL_ONLY,
    ("nightly.yml", "cleanup-nightly-oci"): _STOCK,
    ("nightly.yml", "handoff"): _STOCK,
    ("nightly.yml", "ingest-pkg"): _STOCK,
    ("nightly.yml", "prepare"): _STOCK,
    ("pkg-republish.yml", "resolve"): _STOCK,
    ("pkg-tagged-ingest.yml", "finalize-pkg"): _STOCK,
    ("pkg-tagged-ingest.yml", "prepare-live-gate"): _STOCK,
    ("pkg-tagged-ingest.yml", "stage-pkg"): _STOCK,
    ("release-published.yml", "resolve"): _STOCK,
    ("release-published.yml", "sync-ports-fork"): _STOCK,
    ("release.yml", "attach-pkgs"): _STOCK,
    ("release.yml", "draft-healthcheck"): _SHELL_ONLY,
    ("release.yml", "prepare-release"): _STOCK,
    ("release.yml", "read-matrix"): _STOCK,
    ("release.yml", "resolve-stamp"): _STOCK,
    ("release.yml", "tag-release"): _STOCK,
    ("repo-install.yml", "all-repo-install-passed"): _SHELL_ONLY,
    ("repo-install.yml", "gate"): _SHELL_ONLY,
    ("repo-install.yml", "prepare"): _STOCK,
    ("smoke.yml", "all-smoke-passed"): _SHELL_ONLY,
    ("smoke.yml", "prepare"): _STOCK,
    ("test-version-matrix.yml", "test-reader"): _STOCK,
    ("test.yml", "all-tests-passed"): _SHELL_ONLY,
    ("test.yml", "comment-narration"): _STOCK,
    ("test.yml", "coverage-pairing"): _STOCK,
    ("test.yml", "read-matrix"): _STOCK,
    ("top1m-healthcheck.yml", "alert"): _SHELL_ONLY,
    ("top1m-healthcheck.yml", "check"): _STOCK,
    ("top1m-healthcheck.yml", "discover"): _STOCK,
    ("top1m-healthcheck.yml", "recovery"): _SHELL_ONLY,
    ("ui-tests.yml", "all-ui-passed"): _SHELL_ONLY,
    ("ui-tests.yml", "prepare"): _STOCK,
    ("version-tracker.yml", "react"): _STOCK,
    ("version-tracker.yml", "read-matrix"): _STOCK,
}

# Owner decision A (#3852): these two run each tool step as `docker run <ci image> ...` on a
# bare runner instead of a `container:` job, so their tests can start sibling containers.
DOCKER_WRAPPED: frozenset[JobKey] = frozenset({("test.yml", "test"), ("test.yml", "go-quality")})

BANNED_ACTIONS = frozenset(
    {
        "shivammathur/setup-php",
        "actions/setup-go",
        "actions/setup-node",
        "astral-sh/setup-uv",
        "actions/setup-python",
        "oras-project/setup-oras",
    }
)

# (label, pattern): every run step of a docker-wrapped job, env references substituted, must match all.
_DOCKER_TOKENS = (
    ("docker run", re.compile(r"\bdocker run\b")),
    ("--init", re.compile(r"--init(?!\S)")),
    ("--network host", re.compile(r"--network[ =]host(?!\S)")),
    ("/var/run/docker.sock:/var/run/docker.sock", re.compile(r"/var/run/docker\.sock:/var/run/docker\.sock")),
    ("/tmp:/tmp", re.compile(r"(?<![\w/.-])/tmp:/tmp(?![\w/])")),
    (
        "a $GITHUB_WORKSPACE bind mount",
        re.compile(
            r"(?:-v|--volume)[ =][\"']?(?:\$GITHUB_WORKSPACE|\$\{GITHUB_WORKSPACE\}|\$\{\{\s*github\.workspace\s*\}\})"
        ),
    ),
    ("needs.ci-image.outputs.ci", re.compile(r"needs\.ci-image\.outputs\.ci\b")),  # \b: ci_vm is NOT the ci image
)

_BANNED_RUN = (
    ("apt-get", re.compile(r"\bapt-get\b")),
    ("udevadm", re.compile(r"\budevadm\b")),
    # `--with-deps` may sit before or after the browser name, or on a continuation line.
    ("playwright install --with-deps", re.compile(r"\bplaywright\s+install\b(?:[^\n]|\\\n)*?--with-deps")),
)

_EXPR_RE = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
_ENV_REF_RE = re.compile(r"\$(?:\{(\w+)\}|(\w+))")


def _normalise(expr: str) -> str:
    """`${{needs.ci-image.outputs.ci}}` and `${{ needs.ci-image.outputs.ci }}` are one expression."""
    return _EXPR_RE.sub(r"${{ \1 }}", expr.strip())


def _jobs(doc: Any) -> dict[str, Any]:
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    return jobs if isinstance(jobs, dict) else {}


def _steps(holder: Any) -> list[tuple[str, dict[str, Any]]]:
    """(label, step) for each mapping step of a job or a composite action's `runs`; the label
    is the step name, else its index."""
    steps = holder.get("steps") if isinstance(holder, dict) else None
    if not isinstance(steps, list):
        return []
    return [(str(step.get("name") or i), step) for i, step in enumerate(steps) if isinstance(step, dict)]


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs")
    return [needs] if isinstance(needs, str) else needs if isinstance(needs, list) else []


def _has_option(tokens: list[str], flag: str, value: str) -> bool:
    """`flag value` or `flag=value` as whole tokens, so `/dev/kvm2` never satisfies `/dev/kvm`."""
    return f"{flag}={value}" in tokens or any(a == flag and b == value for a, b in zip(tokens, tokens[1:]))


def _container_problems(job: dict[str, Any]) -> list[str]:
    container = job.get("container")
    if container is None:
        return ["no container: and not listed in BARE or DOCKER_WRAPPED"]
    if not isinstance(container, dict):
        return [f"container must be a mapping with image and options, got {type(container).__name__}"]
    problems = []
    image = container.get("image")
    image = _normalise(image) if isinstance(image, str) else image
    if image not in (_CI_IMAGE, _CI_VM_IMAGE):
        problems.append(f"container.image must be {_CI_IMAGE} or {_CI_VM_IMAGE}, got {image!r}")
    options = container.get("options")
    tokens = options.split() if isinstance(options, str) else []
    if "--init" not in tokens:
        problems.append("container.options lacks --init")
    if image == _CI_VM_IMAGE:
        for flag, value in (("--device", "/dev/kvm"), ("--cap-add", "NET_ADMIN")):
            if not _has_option(tokens, flag, value):
                problems.append(f"ci_vm container.options lacks {flag} {value}")
    return problems


def _wrapped_violations(where: str, job: dict[str, Any]) -> list[str]:
    """Rule 1b: every `run:` step of a docker-wrapped job runs the ci image itself. `$NAME` and
    `${NAME}` take their value from the job and step `env:` (single pass, unknown names kept), so a
    step may carry the `docker run ...` prefix in an env var; `uses:` steps are exempt."""
    out = []
    if "container" in job:
        out.append(f"{where} — docker-wrapped job must not declare container:")
    job_env: dict[str, Any] = job["env"] if isinstance(job.get("env"), dict) else {}
    run_steps = 0
    for label, step in _steps(job):
        run = step.get("run")
        if not isinstance(run, str):
            continue
        run_steps += 1
        env = job_env | (step["env"] if isinstance(step.get("env"), dict) else {})
        text = _ENV_REF_RE.sub(lambda m: str(env.get(m.group(1) or m.group(2), m.group(0))), run)
        out += [f"{where}:{label} — docker-wrapped step lacks {t}" for t, rx in _DOCKER_TOKENS if not rx.search(text)]
    if not run_steps:
        out.append(f"{where} — docker-wrapped job has no run: step to wrap")
    return out


def container_violations(
    workflows: Docs,
    bare: Mapping[JobKey, str] = BARE,
    wrapped: Collection[JobKey] = DOCKER_WRAPPED,
) -> list[str]:
    """Rule 1 and 1b: sorted `<file>:<job> — <reason>` for every job off the container contract."""
    out: list[str] = []
    for fname in sorted(workflows):
        jobs = _jobs(workflows[fname])
        needing_image = []
        for name, job in jobs.items():
            where = f"{fname}:{name}"
            if not isinstance(job, dict):
                out.append(f"{where} — job must be a mapping, got {type(job).__name__}")
            elif name == CI_IMAGE_JOB:
                if job.get("uses") != CI_IMAGE_USES:
                    out.append(f"{where} — must be the reusable call `uses: {CI_IMAGE_USES}`")
            elif "uses" not in job and (fname, name) not in bare:
                needing_image.append(name)
                is_wrapped = (fname, name) in wrapped
                problems: list[str] = [] if is_wrapped else _container_problems(job)
                if CI_IMAGE_JOB not in _needs(job):
                    problems.append(f"needs must include {CI_IMAGE_JOB}")
                out += [f"{where} — {p}" for p in problems]
                if is_wrapped:
                    out += _wrapped_violations(where, job)
        if needing_image and CI_IMAGE_JOB not in jobs:
            out.append(f"{fname}:{CI_IMAGE_JOB} — missing; needed by {', '.join(needing_image)}")
    return sorted(out)


def _banned_step_violations(where: str, steps: list[tuple[str, dict[str, Any]]]) -> list[str]:
    out = []
    for label, step in steps:
        uses = step.get("uses")
        if isinstance(uses, str) and (action := uses.split("@")[0].strip().lower()) in BANNED_ACTIONS:
            out.append(f"{where}:{label} — banned action {action}; bake the tool into the ci image")
        run = step.get("run")
        if isinstance(run, str):
            out += [
                f"{where}:{label} — banned `{name}` in run; bake it into the ci image"
                for name, rx in _BANNED_RUN
                if rx.search(run)
            ]
    return out


def banned_step_violations(workflows: Docs, actions: Docs) -> list[str]:
    """Rule 2: every step of every workflow job and every composite action (`runs.steps`)."""
    out: list[str] = []
    for fname, doc in workflows.items():
        for name, job in _jobs(doc).items():
            out += _banned_step_violations(f"{fname}:{name}", _steps(job))
    for path, doc in actions.items():
        out += _banned_step_violations(path, _steps(doc.get("runs") if isinstance(doc, dict) else None))
    return sorted(out)


def stale_entry_violations(
    workflows: Docs,
    bare: Mapping[JobKey, str] = BARE,
    wrapped: Collection[JobKey] = DOCKER_WRAPPED,
) -> list[str]:
    """Rule 3: every exemption-list key names a job that exists in that workflow file."""
    listed = [("BARE", key) for key in bare] + [("DOCKER_WRAPPED", key) for key in wrapped]
    return sorted(
        f"{fname}:{job} — listed in {source} but no such job exists (stale entry)"
        for source, (fname, job) in listed
        if job not in _jobs(workflows.get(fname))
    )


def reasonless_bare_entries(bare: Mapping[JobKey, str]) -> list[str]:
    """Every BARE exemption must say why the job needs no image: a blank reason is a silent exemption."""
    return sorted(
        f"{fname}:{job} — BARE entry states no reason" for (fname, job), reason in bare.items() if not reason.strip()
    )


def _real_workflows() -> Docs:
    docs = {
        path.name: yaml.safe_load(path.read_text(encoding="utf-8"))
        for ext in _EXTENSIONS
        for path in WORKFLOWS_DIR.glob(f"*.{ext}")
    }
    assert docs, f"no workflows found under {WORKFLOWS_DIR}; the guard would pass vacuously"
    return docs


def _real_actions(root: Path = ROOT) -> Docs:
    docs = {
        path.relative_to(root).as_posix(): yaml.safe_load(path.read_text(encoding="utf-8"))
        for ext in _EXTENSIONS
        for path in (root / ".github" / "actions").glob(f"*/action.{ext}")
    }
    assert docs, f"no composite actions found under {root / '.github' / 'actions'}; the scan would pass vacuously"
    assert _KNOWN_ACTION in docs, f"composite action scan missed {_KNOWN_ACTION}; found {sorted(docs)}"
    return docs


def test_every_job_runs_in_a_ci_image_container_or_is_explicitly_exempt() -> None:
    violations = container_violations(_real_workflows())
    assert violations == [], "jobs off the ci-image container contract:\n" + "\n".join(violations)


def test_no_workflow_or_composite_action_installs_tooling_at_job_time() -> None:
    violations = banned_step_violations(_real_workflows(), _real_actions())
    assert violations == [], "steps that install tooling at job time:\n" + "\n".join(violations)


def test_exemption_lists_name_only_jobs_that_exist() -> None:
    violations = stale_entry_violations(_real_workflows())
    assert violations == [], "stale BARE / DOCKER_WRAPPED entries:\n" + "\n".join(violations)


def test_every_bare_exemption_states_a_reason() -> None:
    reasonless = reasonless_bare_entries(BARE)
    assert reasonless == [], "BARE entries without a reason:\n" + "\n".join(reasonless)


_DOCKER_RUN = (
    "docker run --rm --init --network host -v /var/run/docker.sock:/var/run/docker.sock "
    '-v "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE" -v /tmp:/tmp -w "$GITHUB_WORKSPACE" '
    "${{ needs.ci-image.outputs.ci }} ruff check ."
)
_VM_OPTIONS = "--init --device /dev/kvm --cap-add NET_ADMIN"


def _ci_job(**override: Any) -> dict[str, Any]:
    job: dict[str, Any] = {
        "needs": ["ci-image"],
        "runs-on": "ubuntu-latest",
        "container": {"image": _CI_IMAGE, "options": "--init"},
        "steps": [{"run": "true"}],
    }
    return job | override


def _ci_vm_job(options: str | None = _VM_OPTIONS, **override: Any) -> dict[str, Any]:
    container = {"image": _CI_VM_IMAGE} | ({"options": options} if options is not None else {})
    return _ci_job(container=container, **override)


def _wrapped_job(run: str = _DOCKER_RUN, **override: Any) -> dict[str, Any]:
    job: dict[str, Any] = {"needs": ["ci-image"], "runs-on": "ubuntu-latest", "steps": [{"run": run}]}
    return job | override


def _workflow(jobs: dict[str, Any]) -> Docs:
    """One workflow `w.yml` whose first job is the reusable ci-image call."""
    return {"w.yml": {"jobs": {"ci-image": {"uses": CI_IMAGE_USES}, **jobs}}}


def _check(job: Any, **lists: Any) -> list[str]:
    """Rule 1 on a single job named `build`; the exemption lists default to empty."""
    return container_violations(_workflow({"build": job}), lists.get("bare", {}), lists.get("wrapped", frozenset()))


def _assert_one_violation(violations: list[str], fragment: str) -> None:
    assert len(violations) == 1 and fragment in violations[0], (
        f"expected exactly one violation containing {fragment!r}; got {violations!r}"
    )


def test_compliant_ci_job_is_accepted() -> None:
    assert _check(_ci_job()) == []


def test_compliant_ci_vm_job_is_accepted() -> None:
    assert _check(_ci_vm_job()) == []


def test_image_expression_without_inner_spaces_is_accepted() -> None:
    job = _ci_job(container={"image": "${{needs.ci-image.outputs.ci}}", "options": "--init"})
    assert _check(job) == []


def test_equals_form_of_kvm_and_cap_add_is_accepted() -> None:
    assert _check(_ci_vm_job("--init --device=/dev/kvm --cap-add=NET_ADMIN")) == []


def test_needs_given_as_a_string_or_a_list_is_accepted() -> None:
    assert _check(_ci_job(needs="ci-image")) == []
    assert _check(_ci_job(needs=["read-matrix", "ci-image"])) == []


def test_reusable_call_job_is_exempt() -> None:
    assert _check({"uses": "./.github/workflows/smoke-single.yml", "needs": ["ci-image"]}) == []


def test_bare_listed_job_is_exempt_and_the_same_job_unlisted_is_rejected() -> None:
    bare_job = {"runs-on": "ubuntu-latest", "steps": [{"run": "gh issue list"}]}
    assert _check(bare_job, bare={("w.yml", "build"): "reads issues"}) == []
    violations = _check(bare_job)
    expected = "w.yml:build — no container: and not listed in BARE or DOCKER_WRAPPED"
    assert expected in violations, f"expected {expected!r} among {violations!r}"


def test_job_with_no_steps_key_is_judged_on_its_container_alone() -> None:
    job = _ci_job()
    del job["steps"]
    assert _check(job) == []


@pytest.mark.parametrize(
    "image",
    [
        pytest.param("ghcr.io/x/y:1", id="literal-tag"),
        pytest.param("${{ needs.ci-image.outputs.other }}", id="other-output"),
        pytest.param("${{ needs.ci-image.outputs.ci_vmx }}", id="near-miss-output"),
        pytest.param(None, id="no-image"),
    ],
)
def test_image_other_than_a_ci_image_output_is_rejected(image: str | None) -> None:
    violations = _check(_ci_job(container={"image": image, "options": "--init"}))
    _assert_one_violation(violations, "w.yml:build — container.image must be")


def test_container_given_as_a_plain_string_is_rejected_not_a_crash() -> None:
    violations = _check(_ci_job(container="ghcr.io/x/y:1"))
    _assert_one_violation(violations, "container must be a mapping with image and options, got str")


@pytest.mark.parametrize("options", [None, "", "--privileged", "--init-path /x"], ids=repr)
def test_container_without_init_is_rejected(options: str | None) -> None:
    container = {"image": _CI_IMAGE} | ({"options": options} if options is not None else {})
    _assert_one_violation(_check(_ci_job(container=container)), "container.options lacks --init")


@pytest.mark.parametrize(
    ("options", "missing"),
    [
        pytest.param("--init --cap-add NET_ADMIN", "--device /dev/kvm", id="no-kvm"),
        pytest.param("--init --device /dev/kvm2 --cap-add NET_ADMIN", "--device /dev/kvm", id="kvm-prefix-only"),
        pytest.param("--init --device /dev/kvm", "--cap-add NET_ADMIN", id="no-net-admin"),
        pytest.param(
            "--init --device /dev/kvm --cap-add NET_ADMINX", "--cap-add NET_ADMIN", id="net-admin-prefix-only"
        ),
        pytest.param("--init --device /dev/kvm --cap-add NET_RAW", "--cap-add NET_ADMIN", id="wrong-capability"),
    ],
)
def test_ci_vm_job_missing_a_vm_option_is_rejected(options: str, missing: str) -> None:
    _assert_one_violation(_check(_ci_vm_job(options)), f"ci_vm container.options lacks {missing}")


def test_plain_ci_job_is_not_asked_for_vm_options() -> None:
    assert _check(_ci_job(container={"image": _CI_IMAGE, "options": "--init"})) == []


def test_ci_vm_job_without_init_is_rejected() -> None:
    _assert_one_violation(_check(_ci_vm_job("--device /dev/kvm --cap-add NET_ADMIN")), "container.options lacks --init")


@pytest.mark.parametrize("needs", [None, "read-matrix", ["read-matrix"], []], ids=repr)
def test_job_whose_needs_lack_ci_image_is_rejected(needs: Any) -> None:
    job = _ci_job()
    job["needs"] = needs
    _assert_one_violation(_check(job), "needs must include ci-image")


def test_workflow_with_image_jobs_but_no_ci_image_job_is_rejected() -> None:
    workflows = {"w.yml": {"jobs": {"build": _ci_job()}}}
    _assert_one_violation(container_violations(workflows, {}, frozenset()), "w.yml:ci-image — missing; needed by build")


@pytest.mark.parametrize(
    "ci_image_job",
    [
        pytest.param({"runs-on": "ubuntu-latest", "steps": [{"run": "docker build ."}]}, id="inline-steps"),
        pytest.param({"uses": "./.github/workflows/other.yml"}, id="other-reusable-workflow"),
    ],
)
def test_ci_image_job_that_is_not_the_reusable_call_is_rejected(ci_image_job: dict[str, Any]) -> None:
    workflows = {"w.yml": {"jobs": {"ci-image": ci_image_job, "build": _ci_job()}}}
    _assert_one_violation(
        container_violations(workflows, {}, frozenset()),
        f"w.yml:ci-image — must be the reusable call `uses: {CI_IMAGE_USES}`",
    )


def test_job_that_is_not_a_mapping_is_rejected_not_a_crash() -> None:
    _assert_one_violation(_check(None), "w.yml:build — job must be a mapping, got NoneType")


def test_empty_workflow_document_is_ignored() -> None:
    assert container_violations({"empty.yml": None}, {}, frozenset()) == []


def test_compliant_docker_wrapped_job_is_accepted() -> None:
    assert _check(_wrapped_job(), wrapped={("w.yml", "build")}) == []


def test_docker_wrapped_job_may_take_the_image_from_env() -> None:
    run = _DOCKER_RUN.replace("${{ needs.ci-image.outputs.ci }}", '"$CI_IMAGE"')
    job = _wrapped_job(run, env={"CI_IMAGE": "${{ needs.ci-image.outputs.ci }}"})
    assert _check(job, wrapped={("w.yml", "build")}) == []


def test_docker_wrapped_job_tolerates_a_null_run_step() -> None:
    job = _wrapped_job(steps=[{"run": None}, {"run": _DOCKER_RUN}])
    assert _check(job, wrapped={("w.yml", "build")}) == []


@pytest.mark.parametrize(
    "steps",
    [
        pytest.param(None, id="no-steps-key"),
        pytest.param([], id="no-steps"),
        pytest.param([{"run": None}, {"uses": "actions/checkout@v7"}], id="no-run-step"),
    ],
)
def test_docker_wrapped_job_with_no_run_step_is_rejected_not_vacuously_accepted(steps: Any) -> None:
    job = _wrapped_job()
    del job["steps"]
    if steps is not None:
        job["steps"] = steps
    _assert_one_violation(
        _check(job, wrapped={("w.yml", "build")}), "w.yml:build — docker-wrapped job has no run: step"
    )


def test_docker_wrapped_job_with_a_container_is_rejected() -> None:
    job = _wrapped_job(container={"image": _CI_IMAGE, "options": "--init"})
    _assert_one_violation(_check(job, wrapped={("w.yml", "build")}), "docker-wrapped job must not declare container:")


def test_docker_wrapped_job_whose_needs_lack_ci_image_is_rejected() -> None:
    _assert_one_violation(
        _check(_wrapped_job(needs=["read-matrix"]), wrapped={("w.yml", "build")}),
        "needs must include ci-image",
    )


@pytest.mark.parametrize(
    ("label", "removed"),
    [
        pytest.param("docker run", "docker run ", id="docker-run"),
        pytest.param("--init", " --init", id="init"),
        pytest.param("--network host", " --network host", id="network-host"),
        pytest.param(
            "/var/run/docker.sock:/var/run/docker.sock",
            " -v /var/run/docker.sock:/var/run/docker.sock",
            id="docker-sock",
        ),
        pytest.param("/tmp:/tmp", " -v /tmp:/tmp", id="tmp-mount"),
        pytest.param(
            "a $GITHUB_WORKSPACE bind mount", ' -v "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE"', id="workspace-mount"
        ),
        pytest.param("needs.ci-image.outputs.ci", "${{ needs.ci-image.outputs.ci }}", id="ci-image-output"),
    ],
)
def test_docker_wrapped_job_missing_a_required_token_is_rejected(label: str, removed: str) -> None:
    run = _DOCKER_RUN.replace(removed, "")
    assert run != _DOCKER_RUN, "fixture precondition: the token must actually be removed"
    _assert_one_violation(_check(_wrapped_job(run), wrapped={("w.yml", "build")}), f"docker-wrapped step lacks {label}")


def test_docker_wrapped_job_accepts_the_equals_form_of_network_host() -> None:
    run = _DOCKER_RUN.replace("--network host", "--network=host")
    assert run != _DOCKER_RUN, "fixture precondition: the flag must actually change"
    assert _check(_wrapped_job(run), wrapped={("w.yml", "build")}) == []


def test_docker_wrapped_init_must_be_the_flag_itself_not_a_longer_flag() -> None:
    run = _DOCKER_RUN.replace(" --init", " --init-path /x")
    assert run != _DOCKER_RUN, "fixture precondition: the flag must actually change"
    _assert_one_violation(_check(_wrapped_job(run), wrapped={("w.yml", "build")}), "docker-wrapped step lacks --init")


def test_docker_wrapped_tmp_mount_must_bind_the_host_tmp_itself() -> None:
    run = _DOCKER_RUN.replace(" -v /tmp:/tmp", " -v /var/tmp:/tmp")
    assert run != _DOCKER_RUN, "fixture precondition: the mount must actually change"
    _assert_one_violation(
        _check(_wrapped_job(run), wrapped={("w.yml", "build")}), "docker-wrapped step lacks /tmp:/tmp"
    )


def test_docker_wrapped_job_running_the_ci_vm_image_is_rejected() -> None:
    run = _DOCKER_RUN.replace("outputs.ci }}", "outputs.ci_vm }}")
    _assert_one_violation(
        _check(_wrapped_job(run), wrapped={("w.yml", "build")}), "docker-wrapped step lacks needs.ci-image.outputs.ci"
    )


_WRAPPED = {("w.yml", "build")}
_ALL_TOKENS = [token for token, _ in _DOCKER_TOKENS]


@pytest.mark.parametrize(
    ("bare_step", "label"),
    [
        pytest.param({"name": "types", "run": "mypy tests/"}, "types", id="named"),
        pytest.param({"run": "ruff check ."}, "1", id="unnamed-by-index"),
    ],
)
def test_docker_wrapped_job_with_one_bare_run_step_is_flagged_naming_that_step(
    bare_step: dict[str, Any], label: str
) -> None:
    job = _wrapped_job(steps=[{"name": "lint", "run": _DOCKER_RUN}, bare_step])
    expected = sorted(f"w.yml:build:{label} — docker-wrapped step lacks {token}" for token in _ALL_TOKENS)
    assert _check(job, wrapped=_WRAPPED) == expected


def test_docker_wrapped_job_exempts_uses_steps_but_not_a_bare_run_beside_them() -> None:
    job = _wrapped_job(steps=[{"uses": "actions/checkout@v7"}, {"run": _DOCKER_RUN}])
    assert _check(job, wrapped=_WRAPPED) == []


@pytest.mark.parametrize("reference", ["$CI_RUN", "${CI_RUN}"])
def test_docker_wrapped_step_may_take_its_docker_run_prefix_from_job_env(reference: str) -> None:
    job = _wrapped_job(env={"CI_RUN": _DOCKER_RUN}, steps=[{"run": f"{reference} --extra"}])
    assert _check(job, wrapped=_WRAPPED) == []


def test_docker_wrapped_step_env_overrides_job_env() -> None:
    good_step = {"name": "lint", "run": "$CI_RUN", "env": {"CI_RUN": _DOCKER_RUN}}
    assert _check(_wrapped_job(env={"CI_RUN": "true"}, steps=[good_step]), wrapped=_WRAPPED) == []
    bad_step = {"name": "lint", "run": "$CI_RUN", "env": {"CI_RUN": "true"}}
    expected = sorted(f"w.yml:build:lint — docker-wrapped step lacks {token}" for token in _ALL_TOKENS)
    assert _check(_wrapped_job(env={"CI_RUN": _DOCKER_RUN}, steps=[bad_step]), wrapped=_WRAPPED) == expected


@pytest.mark.parametrize("reference", ["$CI_RUN", "${CI_RUN}"])
def test_docker_wrapped_step_whose_env_var_lacks_a_token_is_flagged(reference: str) -> None:
    env = {"CI_RUN": _DOCKER_RUN.replace(" --network host", "")}
    job = _wrapped_job(env=env, steps=[{"name": "lint", "run": f"{reference} --extra"}])
    _assert_one_violation(_check(job, wrapped=_WRAPPED), "w.yml:build:lint — docker-wrapped step lacks --network host")


@pytest.mark.parametrize(
    ("env", "run"),
    [
        pytest.param({"CI_RUN": _DOCKER_RUN}, "$CI_RUNN", id="reference-is-a-longer-name"),
        pytest.param({"CI_RUN": _DOCKER_RUN}, "$OTHER", id="reference-is-undefined"),
        pytest.param({"A": "$B", "B": _DOCKER_RUN}, "$A", id="substitution-is-single-pass"),
    ],
)
def test_docker_wrapped_step_with_an_unresolved_env_reference_is_flagged(env: dict[str, str], run: str) -> None:
    job = _wrapped_job(env=env, steps=[{"name": "lint", "run": run}])
    expected = sorted(f"w.yml:build:lint — docker-wrapped step lacks {token}" for token in _ALL_TOKENS)
    assert _check(job, wrapped=_WRAPPED) == expected


def _banned(step: dict[str, Any]) -> list[str]:
    return banned_step_violations({"w.yml": {"jobs": {"build": {"steps": [step]}}}}, {})


@pytest.mark.parametrize("action", sorted(BANNED_ACTIONS))
def test_each_banned_setup_action_is_rejected(action: str) -> None:
    _assert_one_violation(
        _banned({"name": "setup", "uses": f"{action}@v1", "with": {"x": 1}}),
        f"w.yml:build:setup — banned action {action}",
    )


def test_banned_action_is_matched_case_insensitively_and_without_a_version() -> None:
    _assert_one_violation(_banned({"uses": "Actions/Setup-Go"}), "banned action actions/setup-go")


@pytest.mark.parametrize(
    ("run", "name"),
    [
        pytest.param("sudo apt-get install -y jq", "apt-get", id="apt-get"),
        pytest.param("echo ok\n# apt-get update was here\n", "apt-get", id="apt-get-in-a-comment-still-counts"),
        pytest.param("sudo udevadm trigger --name-match=kvm", "udevadm", id="udevadm"),
        pytest.param(
            "playwright install --with-deps chromium", "playwright install --with-deps", id="flag-before-browser"
        ),
        pytest.param(
            "playwright install chromium --with-deps", "playwright install --with-deps", id="flag-after-browser"
        ),
        pytest.param(
            "uv run playwright install chromium \\\n  --with-deps",
            "playwright install --with-deps",
            id="flag-on-continuation",
        ),
    ],
)
def test_each_banned_run_pattern_is_rejected(run: str, name: str) -> None:
    _assert_one_violation(_banned({"name": "install", "run": run}), f"w.yml:build:install — banned `{name}` in run")


@pytest.mark.parametrize(
    "step",
    [
        pytest.param({"run": "playwright install chromium"}, id="playwright-without-with-deps"),
        pytest.param({"run": "playwright install chromium\necho --with-deps"}, id="with-deps-on-another-command"),
        pytest.param({"run": "echo apt-getter udevadmin"}, id="near-miss-words"),
        pytest.param({"uses": "actions/checkout@v7"}, id="allowed-action"),
        pytest.param({"uses": "./.github/actions/read-version-matrix"}, id="local-action"),
        pytest.param({"uses": "actions/setup-go-extra@v1"}, id="near-miss-action"),
        pytest.param({"run": None}, id="null-run"),
        pytest.param({"name": "empty"}, id="no-run-no-uses"),
    ],
)
def test_steps_that_install_nothing_are_not_flagged(step: dict[str, Any]) -> None:
    assert _banned(step) == []


def test_unnamed_step_is_reported_by_its_index() -> None:
    workflows = {"w.yml": {"jobs": {"build": {"steps": [{"run": "true"}, {"run": "apt-get update"}]}}}}
    _assert_one_violation(banned_step_violations(workflows, {}), "w.yml:build:1 — banned `apt-get` in run")


def test_job_without_steps_and_reusable_call_job_have_nothing_to_flag() -> None:
    workflows = {"w.yml": {"jobs": {"a": {"runs-on": "x"}, "b": {"uses": "./.github/workflows/c.yml"}, "c": None}}}
    assert banned_step_violations(workflows, {}) == []


def test_banned_step_inside_a_composite_action_is_rejected() -> None:
    action = {
        "runs": {"using": "composite", "steps": [{"name": "deps", "run": "apt-get install -y jq", "shell": "bash"}]}
    }
    path = ".github/actions/x/action.yml"
    _assert_one_violation(banned_step_violations({}, {path: action}), f"{path}:deps — banned `apt-get` in run")


def test_clean_composite_action_and_node_action_are_accepted() -> None:
    actions = {
        "a/action.yml": {"runs": {"using": "composite", "steps": [{"run": "true", "shell": "bash"}]}},
        "b/action.yml": {"runs": {"using": "node24", "main": "index.js"}},
        "c/action.yml": None,
    }
    assert banned_step_violations({}, actions) == []


def test_stale_bare_entry_is_reported() -> None:
    workflows = _workflow({"build": _ci_job()})
    violations = stale_entry_violations(workflows, {("w.yml", "gone"): "reads issues"}, frozenset())
    _assert_one_violation(violations, "w.yml:gone — listed in BARE but no such job exists (stale entry)")


def test_stale_docker_wrapped_entry_is_reported() -> None:
    workflows = _workflow({"build": _wrapped_job()})
    violations = stale_entry_violations(workflows, {}, frozenset({("w.yml", "gone")}))
    _assert_one_violation(violations, "w.yml:gone — listed in DOCKER_WRAPPED but no such job exists (stale entry)")


def test_entry_for_a_missing_workflow_file_is_reported() -> None:
    violations = stale_entry_violations(_workflow({}), {("nope.yml", "build"): "reads issues"}, frozenset())
    _assert_one_violation(violations, "nope.yml:build — listed in BARE")


def test_entries_naming_existing_jobs_are_accepted() -> None:
    workflows = _workflow({"build": _ci_job(), "wrapped": _wrapped_job()})
    assert stale_entry_violations(workflows, {("w.yml", "build"): "x"}, frozenset({("w.yml", "wrapped")})) == []


@pytest.mark.parametrize("reason", ["", "   "], ids=["empty", "whitespace"])
def test_bare_entry_without_a_reason_is_flagged(reason: str) -> None:
    assert reasonless_bare_entries({("w.yml", "build"): reason}) == ["w.yml:build — BARE entry states no reason"]


def test_bare_entry_with_a_reason_is_accepted() -> None:
    assert reasonless_bare_entries({("w.yml", "build"): "reads issues"}) == []


def _write_action(root: Path, name: str, ext: str) -> None:
    action = root / ".github" / "actions" / name / f"action.{ext}"
    action.parent.mkdir(parents=True)
    action.write_text("runs:\n  using: composite\n  steps: []\n", encoding="utf-8")


def test_composite_action_scan_refuses_to_pass_over_an_empty_directory(tmp_path: Path) -> None:
    with pytest.raises(AssertionError, match="no composite actions found"):
        _real_actions(tmp_path)


def test_composite_action_scan_refuses_to_pass_when_the_known_action_is_missing(tmp_path: Path) -> None:
    _write_action(tmp_path, "other", "yml")
    with pytest.raises(AssertionError, match="read-version-matrix/action.yml"):
        _real_actions(tmp_path)


def test_composite_action_scan_discovers_both_yml_and_yaml_actions(tmp_path: Path) -> None:
    _write_action(tmp_path, "read-version-matrix", "yml")
    _write_action(tmp_path, "other", "yaml")
    assert sorted(_real_actions(tmp_path)) == sorted([_KNOWN_ACTION, ".github/actions/other/action.yaml"])
