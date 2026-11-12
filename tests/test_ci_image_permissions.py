"""Guard: callers of an image-building workflow grant `packages: write` (issue #3852).

Every `ci-image` job pushes to GHCR, so it needs `packages: write`. A reusable workflow's jobs
can only receive the GITHUB_TOKEN permissions their caller job grants, so every job that calls --
directly or through other reusable workflows -- a workflow containing a `ci-image` job must grant
`packages: write` itself. GitHub rejects a missing grant only when the run starts, which for rare
workflows (release-published, pkg-republish) means at release time; this guard fails at PR time.

The check is a pure function over `{filename: parsed_yaml}` returning violation strings, like the
guards in test_ci_container_images.py, so synthetic workflows prove each branch.

Effective permission of a calling job: its own `permissions` if present (a job block REPLACES the
workflow block, it does not merge, so a missing `packages` key there means none), else the
workflow's top-level block. An absent block is a violation: the repo default is not pinned here.
`write-all` / `read-all` are honoured.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
_LOCAL = "./.github/workflows/"
CI_IMAGE = "ci-image.yml"

Docs = dict[str, Any]


def _jobs(doc: Any) -> dict[str, Any]:
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    return jobs if isinstance(jobs, dict) else {}


def _callee(job: Any) -> str | None:
    """Filename of the local reusable workflow a job calls, else None."""
    uses = job.get("uses") if isinstance(job, dict) else None
    return uses.removeprefix(_LOCAL) if isinstance(uses, str) and uses.startswith(_LOCAL) else None


def _needs_packages_write(workflows: Docs) -> set[str]:
    """Workflows that need `packages: write` from their caller: ci-image.yml and, transitively,
    every workflow with a job calling one of them. Fixpoint iteration, so a cycle terminates."""
    needing = {CI_IMAGE}
    grew = True
    while grew:
        grew = False
        for fname, doc in workflows.items():
            if fname not in needing and any(_callee(job) in needing for job in _jobs(doc).values()):
                needing.add(fname)
                grew = True
    return needing


def _effective_packages(workflow_doc: Any, job: dict[str, Any]) -> str:
    block = job["permissions"] if "permissions" in job else workflow_doc.get("permissions")
    if block == "write-all":
        return "write"
    if isinstance(block, dict):
        return str(block.get("packages", "none"))
    return "none"  # read-all, absent, or malformed: no write grant


def packages_write_violations(workflows: Docs) -> list[str]:
    needing = _needs_packages_write(workflows)
    violations = []
    builder = workflows.get(CI_IMAGE)
    for job_id, job in _jobs(builder).items():
        if not isinstance(job, dict) or _callee(job) is not None:
            continue
        granted = _effective_packages(builder, job)
        if granted != "write":
            violations.append(f"{CI_IMAGE}:{job_id} — pushes the ci images but grants packages: {granted}")
    for fname, doc in sorted(workflows.items()):
        for job_id, job in _jobs(doc).items():
            callee = _callee(job)
            if callee not in needing:
                continue
            granted = _effective_packages(doc, job)
            if granted != "write":
                violations.append(
                    f"{fname}:{job_id} — calls {callee} (builds ci images) but grants packages: {granted}"
                )
    return violations


def _real_workflows() -> Docs:
    docs = {
        path.name: yaml.safe_load(path.read_text(encoding="utf-8"))
        for ext in ("yml", "yaml")
        for path in WORKFLOWS_DIR.glob(f"*.{ext}")
    }
    assert CI_IMAGE in docs, f"workflow scan missed {CI_IMAGE}; the guard would pass vacuously"
    return docs


def test_every_caller_of_an_image_building_workflow_grants_packages_write() -> None:
    violations = packages_write_violations(_real_workflows())
    assert violations == [], "callers lacking packages: write:\n" + "\n".join(violations)


def _call(callee: str, **permissions: Any) -> dict[str, Any]:
    job: dict[str, Any] = {"uses": _LOCAL + callee}
    if permissions:
        job["permissions"] = permissions
    return job


def _docs(**workflows: Any) -> Docs:
    """`name_yml=...` keyword -> `name.yml` filename; each value is the whole workflow document."""
    return {name.replace("_yml", ".yml"): doc for name, doc in workflows.items()}


def test_direct_caller_with_packages_read_is_flagged() -> None:
    docs = _docs(a_yml={"jobs": {"img": _call(CI_IMAGE, contents="read", packages="read")}})
    assert packages_write_violations(docs) == [
        "a.yml:img — calls ci-image.yml (builds ci images) but grants packages: read"
    ]


def test_transitive_caller_lacking_the_grant_is_flagged() -> None:
    docs = _docs(
        a_yml={"jobs": {"mid": _call("b.yml", contents="read")}},
        b_yml={"jobs": {"img": _call(CI_IMAGE, packages="write")}},
    )
    assert packages_write_violations(docs) == ["a.yml:mid — calls b.yml (builds ci images) but grants packages: none"]


def test_transitive_caller_with_the_grant_is_accepted() -> None:
    docs = _docs(
        a_yml={"jobs": {"mid": _call("b.yml", packages="write")}},
        b_yml={"jobs": {"img": _call(CI_IMAGE, packages="write")}},
    )
    assert packages_write_violations(docs) == []


def test_job_level_grant_overrides_a_read_only_workflow_block() -> None:
    docs = _docs(a_yml={"permissions": {"packages": "read"}, "jobs": {"img": _call(CI_IMAGE, packages="write")}})
    assert packages_write_violations(docs) == []


def test_workflow_level_write_with_no_job_block_is_accepted() -> None:
    docs = _docs(a_yml={"permissions": {"packages": "write"}, "jobs": {"img": _call(CI_IMAGE)}})
    assert packages_write_violations(docs) == []


def test_write_all_is_accepted_at_workflow_and_job_level() -> None:
    docs = _docs(
        a_yml={"permissions": "write-all", "jobs": {"img": _call(CI_IMAGE)}},
        b_yml={"jobs": {"img": {"uses": _LOCAL + CI_IMAGE, "permissions": "write-all"}}},
    )
    assert packages_write_violations(docs) == []


def test_read_all_is_flagged() -> None:
    docs = _docs(a_yml={"permissions": "read-all", "jobs": {"img": _call(CI_IMAGE)}})
    assert packages_write_violations(docs) == [
        "a.yml:img — calls ci-image.yml (builds ci images) but grants packages: none"
    ]


def test_absent_permissions_everywhere_is_flagged() -> None:
    docs = _docs(a_yml={"jobs": {"img": _call(CI_IMAGE)}})
    assert len(packages_write_violations(docs)) == 1


def test_job_block_without_packages_replaces_the_workflow_grant() -> None:
    docs = _docs(
        a_yml={"permissions": {"packages": "write"}, "jobs": {"img": _call(CI_IMAGE, contents="read")}},
    )
    assert packages_write_violations(docs) == [
        "a.yml:img — calls ci-image.yml (builds ci images) but grants packages: none"
    ]


def test_call_to_a_workflow_that_builds_no_image_is_not_flagged() -> None:
    docs = _docs(
        a_yml={"jobs": {"lint": _call("b.yml", contents="read")}},
        b_yml={"jobs": {"run": {"runs-on": "ubuntu-latest", "steps": [{"run": "true"}]}}},
    )
    assert packages_write_violations(docs) == []


def test_cycle_terminates() -> None:
    docs = _docs(
        a_yml={"jobs": {"to-b": _call("b.yml", packages="write")}},
        b_yml={"jobs": {"to-a": _call("a.yml", packages="write"), "img": _call(CI_IMAGE, packages="write")}},
    )
    assert packages_write_violations(docs) == []
    bad = _docs(
        a_yml={"jobs": {"to-b": _call("b.yml")}},
        b_yml={"jobs": {"to-a": _call("a.yml"), "img": _call(CI_IMAGE, packages="write")}},
    )
    assert len(packages_write_violations(bad)) == 2


def test_non_mapping_job_and_empty_document_are_ignored() -> None:
    docs = _docs(a_yml={"jobs": {"odd": None}}, b_yml=None)
    assert packages_write_violations(docs) == []


_BUILD_JOB = {"runs-on": "ubuntu-latest", "steps": [{"run": "docker buildx build --push ."}]}


def test_the_image_builder_without_packages_write_is_flagged() -> None:
    docs = {CI_IMAGE: {"permissions": {"contents": "read"}, "jobs": {"build": dict(_BUILD_JOB)}}}
    assert packages_write_violations(docs) == ["ci-image.yml:build — pushes the ci images but grants packages: none"]


def test_the_image_builder_with_packages_write_is_accepted() -> None:
    docs = {CI_IMAGE: {"permissions": {"contents": "read", "packages": "write"}, "jobs": {"build": dict(_BUILD_JOB)}}}
    assert packages_write_violations(docs) == []
