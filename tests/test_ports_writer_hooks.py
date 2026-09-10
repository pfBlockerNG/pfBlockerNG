"""Ports writer hooks reject invalid commits in the actual sparse checkout context."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from tests._workflow_steps import extract_step
from tests.gitenv import scrubbed_git_env

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release-published.yml"
JOB_NAME = "sync-ports-fork"
CHECKOUT_STEP = "Checkout pfBlockerNG (the release helper — TRUSTED ref, sparse)"
ACTIVATE_STEP = "Activate git hooks"

PORT_MAKEFILES = {
    "stable": "net/pfSense-pkg-pfBlockerNG/Makefile",
    "testing": "net/pfSense-pkg-pfBlockerNG-testing/Makefile",
    "edge": "net/pfSense-pkg-pfBlockerNG-edge/Makefile",
}

BOT_NAME = "pfblockerng-bot"
BOT_EMAIL = "293667935+pfblockerng-bot@users.noreply.github.com"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _job(text: str) -> dict:
    jobs = yaml.safe_load(text)["jobs"]
    assert JOB_NAME in jobs, f"release-published.yml has no `{JOB_NAME}` job"
    return jobs[JOB_NAME]


def _step_named(job: dict, name: str) -> dict:
    for step in job.get("steps", []):
        if step.get("name") == name:
            return step
    raise AssertionError(f"`{JOB_NAME}` has no step named {name!r}")


def _declared_sparse_paths(job: dict) -> list[str]:
    step = _step_named(job, CHECKOUT_STEP)
    raw = step.get("with", {}).get("sparse-checkout", "")
    return [line.strip() for line in raw.splitlines() if line.strip()]


def _helper_path(job: dict) -> str:
    step = _step_named(job, CHECKOUT_STEP)
    path = step.get("with", {}).get("path")
    assert path, f"{CHECKOUT_STEP!r} step has no with.path"
    return path


def _activation_command(text: str) -> str:
    """Execute the workflow's actual activation command."""
    step_body = extract_step(text, ACTIVATE_STEP)
    match = re.search(r"run:\s*(.+)", step_body)
    assert match, f"{ACTIVATE_STEP!r} step has no run: command"
    return match.group(1).strip()


def _run(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    merged = scrubbed_git_env(drop_git_vars=True)
    if env:
        merged.update(env)
    return subprocess.run(args, cwd=cwd, env=merged, check=check, capture_output=True, text=True)


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["git", *args], cwd=repo, check=check)


def _head(repo: Path) -> str:
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


def _attempt_commit(repo: Path, message: str) -> subprocess.CompletedProcess[str]:
    return _git(repo, "commit", "-qm", message, check=False)


def _seed_makefile(channel_path: str) -> str:
    return f"PORTNAME=\tpfBlockerNG\nPORTVERSION=\t1.0.0\nCATEGORIES=\tnet\n# fixture: {channel_path}\n"


def _materialize_helper_checkout(dest: Path, sparse_paths: list[str]) -> None:
    """Materialize the helper using the workflow's declared sparse paths."""
    for rel in sparse_paths:
        rel = rel.rstrip("/")
        src = ROOT / rel
        if not src.exists():
            continue
        target = dest / rel
        if src.is_dir():
            shutil.copytree(src, target)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)


@dataclass
class Scenario:
    foreign_root: Path
    helper_root: Path
    runner_temp: Path
    seed_sha: str
    activate: subprocess.CompletedProcess[str]


def _build_scenario(tmp_path: Path, *, sparse_paths: list[str] | None = None) -> Scenario:
    """Seed the foreign root, materialize the helper, and activate workflow hooks."""
    text = _workflow_text()
    job = _job(text)
    helper_rel = _helper_path(job)
    paths = sparse_paths if sparse_paths is not None else _declared_sparse_paths(job)

    foreign_root = tmp_path / "workspace"
    foreign_root.mkdir()
    _git(foreign_root, "init", "-q", "-b", "pfblockerng/use-github")
    _git(foreign_root, "config", "pfblockerng.allowprimarycommit", "true")
    for rel_path in PORT_MAKEFILES.values():
        full = foreign_root / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(_seed_makefile(rel_path), encoding="utf-8")
    _git(foreign_root, "add", "-A")
    _git(
        foreign_root,
        "-c",
        "user.name=fixture-seed",
        "-c",
        "user.email=fixture-seed@pfblockerng.test",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "seed",
    )
    seed_sha = _head(foreign_root)

    helper_root = foreign_root / helper_rel
    helper_root.mkdir(parents=True, exist_ok=True)
    _materialize_helper_checkout(helper_root, paths)

    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()

    activate = _run(
        ["sh", "-c", _activation_command(text)],
        cwd=foreign_root,
        env={"GITHUB_WORKSPACE": str(foreign_root), "RUNNER_TEMP": str(runner_temp)},
        check=False,
    )
    return Scenario(
        foreign_root=foreign_root,
        helper_root=helper_root,
        runner_temp=runner_temp,
        seed_sha=seed_sha,
        activate=activate,
    )


def _configure_good_identity(scenario: Scenario, signing_key: Path) -> None:
    """Configure the writer's bot identity with a real SSH signing key."""
    _git(scenario.foreign_root, "config", "user.name", BOT_NAME)
    _git(scenario.foreign_root, "config", "user.email", BOT_EMAIL)
    _git(scenario.foreign_root, "config", "gpg.format", "ssh")
    _git(scenario.foreign_root, "config", "user.signingkey", str(signing_key))
    _git(scenario.foreign_root, "config", "commit.gpgsign", "true")


@pytest.fixture
def signing_key(tmp_path: Path) -> Path:
    """Generate a real, isolated SSH signing key."""
    key = tmp_path / "writer-signing-key"
    _run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], cwd=tmp_path)
    return key


@pytest.mark.parametrize("channel", sorted(PORT_MAKEFILES))
def test_good_intended_commit_is_accepted_on_each_allowed_makefile(
    tmp_path: Path, signing_key: Path, channel: str
) -> None:
    """Intended Makefile commits succeed without a project graph."""
    scenario = _build_scenario(tmp_path)
    _configure_good_identity(scenario, signing_key)
    rel_path = PORT_MAKEFILES[channel]
    makefile = scenario.foreign_root / rel_path
    makefile.write_text(makefile.read_text(encoding="utf-8") + "PORTREVISION=\t1\n", encoding="utf-8")
    _git(scenario.foreign_root, "add", rel_path)

    result = _attempt_commit(scenario.foreign_root, f"{rel_path}: bump")

    assert result.returncode == 0, (
        f"a well-formed writer commit touching only {rel_path} with the configured bot "
        f"identity must be accepted by the activated writer hooks; stderr={result.stderr!r}"
    )
    assert _head(scenario.foreign_root) != scenario.seed_sha
    assert not (scenario.foreign_root / "graphify-out").exists(), (
        "a ports writer commit must never require or produce root-graph output (issue #3240: "
        "no Graphify in the writer profile)"
    )


def test_bad_identity_commit_is_rejected(tmp_path: Path, signing_key: Path) -> None:
    """A rejected placeholder identity proves the pre-commit checker runs."""
    scenario = _build_scenario(tmp_path)
    _configure_good_identity(scenario, signing_key)
    _git(scenario.foreign_root, "config", "user.name", "root")
    rel_path = PORT_MAKEFILES["stable"]
    makefile = scenario.foreign_root / rel_path
    makefile.write_text(makefile.read_text(encoding="utf-8") + "PORTREVISION=\t1\n", encoding="utf-8")
    _git(scenario.foreign_root, "add", rel_path)

    result = _attempt_commit(scenario.foreign_root, "stable: bump")

    assert result.returncode != 0, (
        "a commit carrying the generic placeholder identity 'root' must be rejected by the "
        "activated writer pre-commit hook (issue #2982's check-commit-identity.sh); it was "
        "accepted instead, proving no compatible hook ever ran for this writer"
    )
    assert _head(scenario.foreign_root) == scenario.seed_sha, "a rejected commit must not advance HEAD"
    assert "placeholder" in result.stderr.lower(), result.stderr


@pytest.mark.parametrize(
    "extra_paths",
    [
        ["net/pfSense-pkg-pfBlockerNG/distinfo"],
        ["net/pfSense-pkg-pfBlockerNG/Makefile", "net/pfSense-pkg-pfBlockerNG/distinfo"],
    ],
    ids=["out-of-scope-alone", "allowed-plus-out-of-scope"],
)
def test_unexpected_staged_path_is_rejected(tmp_path: Path, signing_key: Path, extra_paths: list[str]) -> None:
    """Unrelated changes cannot use the writer's graph exemption."""
    scenario = _build_scenario(tmp_path)
    _configure_good_identity(scenario, signing_key)
    for rel in extra_paths:
        target = scenario.foreign_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.write_text(target.read_text(encoding="utf-8") + "PORTREVISION=\t1\n", encoding="utf-8")
        else:
            target.write_text("unexpected\n", encoding="utf-8")
        _git(scenario.foreign_root, "add", rel)

    result = _attempt_commit(scenario.foreign_root, "unexpected path")

    assert result.returncode != 0, (
        f"staging {extra_paths} outside the ports writer's allowed Makefile pathspec must be "
        f"rejected by the activated writer pre-commit hook; it was accepted instead"
    )
    assert _head(scenario.foreign_root) == scenario.seed_sha, "a rejected commit must not advance HEAD"


def test_activation_fails_closed_when_writer_hook_corpus_is_missing(tmp_path: Path) -> None:
    """Missing sparse hook files must fail setup, not silently disable checks."""
    scenario = _build_scenario(tmp_path, sparse_paths=["scripts/"])
    assert scenario.activate.returncode != 0, (
        "activation must fail closed when the helper checkout carries no `.githooks/` writer "
        f"corpus; it exited 0 instead (stdout={scenario.activate.stdout!r}, "
        f"stderr={scenario.activate.stderr!r})"
    )
