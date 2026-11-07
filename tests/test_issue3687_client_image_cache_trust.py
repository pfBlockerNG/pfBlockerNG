"""#3687: only a job that never checks out a caller-named ref may write the client image cache.

An Actions cache entry belongs to the scope of the TRIGGERING ref. ``ui`` checks out
``inputs.checkout_ref`` and runs that ref's scripts (``scripts/resolve-legs.sh`` builds the
cache key and fills the directory) before any of its own steps could save. CodeQL's
``actions/cache-poisoning/direct-cache`` rule models exactly that shape -- a job that checks
out a ref the caller names AND declares a cache save -- and does not credit a step ``if:``
guard, so a guard alone is the wrong boundary. The client (civm) image is therefore saved by
the ``client-image`` job, whose checkout names no ref: it executes only the code of the ref
whose scope it writes. ``ui`` keeps restoring the entry and pulling by digest on a miss.

This isolates the workflow's DECLARED cache steps. It is not a capability boundary: a named-ref
``ui`` job still holds the runner's cache credentials.

The execution cases evaluate the workflow's own ``if:`` text, so they fail if a guard is dropped
or inverted, not merely if a string moves. They exist because hit/miss/failed-pull/named-ref
combinations are what a static read of each ``if:`` cannot pin. uv's cache is out of scope here:
``test_issue3489_cache_save_guard`` pins its ``save-cache`` input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ui-tests.yml"
CLIENT_DIR = "client-image"
WRITER = "client-image"
APT_DIR = "${{ steps.aptkey.outputs.dir }}"
NAMED_REF_CLAUSE = "inputs.checkout_ref == ''"
CLIENT_KEY = "civm-img-${{ steps.civm.outputs.k }}"


def _jobs() -> dict[str, dict[str, Any]]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def _uses(step: dict[str, Any], prefix: str) -> bool:
    return str(step.get("uses", "")).startswith(prefix)


def _saves(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in job.get("steps", []) if _uses(s, "actions/cache/save@")]


def _step(job_id: str, label: str) -> dict[str, Any]:
    matches = [s for s in _jobs()[job_id]["steps"] if s.get("id") == label or str(s.get("name", "")).startswith(label)]
    assert len(matches) == 1, f"{job_id}: expected one step {label!r}, got {[s.get('name') for s in matches]}"
    return matches[0]


# --- a GitHub `if:` evaluated over the operators this workflow uses; anything else fails loudly ---

_TOKEN = re.compile(r"'[^']*'|[A-Za-z_][\w.-]*(?:\(\))?")


class _Context(dict[str, str]):
    def __missing__(self, key: str) -> str:
        if key.startswith("steps.") and ".outputs." in key:
            return ""  # an output a step never wrote reads as the empty string, as on GitHub
        raise KeyError(f"the scenario defines no value for the context {key!r}")


def _holds(condition: object, context: _Context, failed: bool) -> bool:
    """Evaluate ``condition`` (&&, ||, !, ==, !=, status functions) as GitHub does for a step or job.

    Translated to a Python expression over the repo's own workflow text with builtins removed;
    a function, operator or context outside that set raises KeyError/SyntaxError, never passes.
    """
    text = "success()" if condition is None else str(condition)
    status = {"success()": not failed, "failure()": failed, "always()": True, "cancelled()": False}

    def token(match: re.Match[str]) -> str:
        found = match.group()
        if found.startswith("'"):
            return found
        return str(status[found]) if found.endswith("()") else f"context[{found!r}]"

    expression = _TOKEN.sub(token, text).replace("&&", " and ").replace("||", " or ")
    expression = re.sub(r"!(?!=)", " not ", expression)
    value = bool(eval(expression, {"__builtins__": {}}, {"context": context}))  # noqa: S307
    # With no status function GitHub implies success(): a step after a failure is skipped.
    return value and (any(name in text for name in status) or not failed)


@dataclass(frozen=True)
class Scenario:
    event: str
    ref: str
    checkout_ref: str


TRUSTED = {
    "schedule on the default branch": Scenario("schedule", "refs/heads/devel", ""),
    "dispatch on a feature branch": Scenario("workflow_dispatch", "refs/heads/feature", ""),
}
NAMED = {
    "dispatch on devel naming a feature branch": Scenario(
        "workflow_dispatch", "refs/heads/devel", "refs/heads/feature"
    ),
    "release naming its pinned sha": Scenario(
        "workflow_dispatch", "refs/heads/devel", "0123456789abcdef" * 2 + "01234567"
    ),
    "dispatch naming a pull request head": Scenario("workflow_dispatch", "refs/heads/devel", "refs/pull/1/head"),
    "whitespace-only ref is still a named ref": Scenario("workflow_dispatch", "refs/heads/devel", " "),
}

# step-name prefix that may fail -> the cache path that must then stay unpublished
PULLS = {"Pull civm image": CLIENT_DIR, "Pull pfSense image": "image", "Install host tools": APT_DIR}


def _saved(job_id: str, scenario: Scenario, restore: str, fail: str | None = None) -> list[str] | None:
    """Cache paths ``job_id`` saves under ``scenario``; None when the job is skipped."""
    job = _jobs()[job_id]
    context = _Context(
        {
            "github.event_name": scenario.event,
            "github.ref": scenario.ref,
            "inputs.checkout_ref": scenario.checkout_ref,
            "inputs.pkg_artifact_prefix": "",
            "needs.prepare.result": "success",
            "needs.prepare.outputs.run": "true",
            "needs.build-pkg.result": "success",
            "matrix.tier": "render",
        }
    )
    if not _holds(job.get("if"), context, failed=False):
        return None
    saved: list[str] = []
    failed = False
    for step in job.get("steps", []):
        if not _holds(step.get("if"), context, failed):
            continue
        if _uses(step, "actions/cache/restore@"):
            context[f"steps.{step['id']}.outputs.cache-hit"] = "true" if restore == "hit" else "false"
        elif _uses(step, "actions/cache/save@"):
            saved.append(step["with"]["path"])
        failed = failed or bool(fail and str(step.get("name", "")).startswith(fail))
    return saved


def _all_saved(scenario: Scenario, restore: str, fail: str | None = None) -> dict[str, list[str] | None]:
    return {job_id: _saved(job_id, scenario, restore, fail) for job_id, job in _jobs().items() if job.get("steps")}


# --- static trust boundary ---


def test_the_client_image_is_saved_only_by_a_job_that_names_no_ref() -> None:
    writers = {
        job_id: job for job_id, job in _jobs().items() if any(s["with"]["path"] == CLIENT_DIR for s in _saves(job))
    }
    assert list(writers) == [WRITER], f"jobs saving {CLIENT_DIR!r}: {list(writers)}"

    checkouts = [s for s in writers[WRITER]["steps"] if _uses(s, "actions/checkout@")]
    assert checkouts, f"{WRITER} must check out the code it executes"
    for step in checkouts:
        assert not {"ref", "repository"} & set(step.get("with", {})), (
            f"{WRITER} checkout must name no ref or repository, got {step.get('with')}"
        )


def test_ui_restores_the_client_image_after_the_writer_and_pulls_on_a_miss() -> None:
    ui = _jobs()["ui"]
    assert WRITER in ui["needs"], f"ui needs {ui['needs']}: it must wait for {WRITER} to publish the entry"
    assert "needs.client-image" not in WORKFLOW.read_text(), "nothing may depend on the optional writer's result"

    restore = _step("ui", "civmcache")
    assert "if" not in restore, "a caller-named ref must still READ the cache"
    assert restore["with"]["path"] == CLIENT_DIR
    # lookup-only would report a hit without downloading: the VM would boot on an empty directory.
    assert "lookup-only" not in restore["with"], "ui must download the entry it boots from"
    assert _step("ui", "Pull civm image")["if"] == "steps.civmcache.outputs.cache-hit != 'true'"


def test_a_failed_writer_does_not_fail_the_called_workflow() -> None:
    # A caller reads the whole call's result; ui pulls by digest itself when the writer is absent.
    assert _jobs()[WRITER].get("continue-on-error") is True


def test_the_writer_only_checks_that_the_entry_exists() -> None:
    restore = _step(WRITER, "civmcache")
    assert str(restore["with"].get("lookup-only")).lower() == "true", "ui downloads the entry; the writer must not"


def test_both_jobs_agree_on_the_immutable_digest_key() -> None:
    keys = {
        (job_id, step.get("uses", "").split("@")[0]): step["with"]["key"]
        for job_id in ("ui", WRITER)
        for step in _jobs()[job_id]["steps"]
        if step.get("with", {}).get("path") == CLIENT_DIR
    }
    assert keys == {
        ("ui", "actions/cache/restore"): CLIENT_KEY,
        (WRITER, "actions/cache/restore"): CLIENT_KEY,
        (WRITER, "actions/cache/save"): CLIENT_KEY,
    }


@pytest.mark.parametrize("label", ["Install oras", "civm", "Pull civm image"])
def test_writer_provisions_exactly_as_ui_does(label: str) -> None:
    """The executed provisioning tests drive ui's steps; identical text means they cover the writer too."""
    ui, writer = _step("ui", label), _step(WRITER, label)
    assert {k: writer.get(k) for k in ("env", "run", "if")} == {k: ui.get(k) for k in ("env", "run", "if")}


def test_writer_reads_only_the_registry_credentials_and_the_named_ref() -> None:
    text = yaml.safe_dump(_jobs()[WRITER])
    # Any other spelling (secrets['X'], toJSON(secrets), inputs[...]) is a bare context word that fails here.
    assert re.findall(r"\bsecrets\b(?!\.(?:SMOKE_GHCR_USER|SMOKE_GHCR_TOKEN|GITHUB_TOKEN)\b)", text) == []
    assert re.findall(r"\binputs\b(?!\.checkout_ref\b)", text) == []


# --- guards, executed ---


@pytest.mark.parametrize("scenario", NAMED.values(), ids=NAMED)
@pytest.mark.parametrize("restore", ["hit", "miss"])
@pytest.mark.parametrize("fail", [None, *PULLS])
def test_a_run_naming_a_checkout_ref_never_runs_the_writer_and_saves_no_cache(
    scenario: Scenario, restore: str, fail: str | None
) -> None:
    saved = _all_saved(scenario, restore, fail)

    assert saved[WRITER] is None, (
        f"checkout_ref={scenario.checkout_ref!r} must skip {WRITER}, which ran: {saved[WRITER]}"
    )
    assert {job_id: paths for job_id, paths in saved.items() if paths} == {}


@pytest.mark.parametrize("scenario", TRUSTED.values(), ids=TRUSTED)
def test_a_trusted_run_saves_the_client_image_once_from_the_writer_on_a_miss(scenario: Scenario) -> None:
    saved = _all_saved(scenario, "miss")

    assert [job_id for job_id, paths in saved.items() if CLIENT_DIR in (paths or [])] == [WRITER]
    assert {"image", APT_DIR} <= {path for paths in saved.values() for path in paths or []}, (
        "the other caches keep priming"
    )


@pytest.mark.parametrize("scenario", TRUSTED.values(), ids=TRUSTED)
def test_a_cache_hit_saves_nothing(scenario: Scenario) -> None:
    saved = _all_saved(scenario, "hit")

    assert {job_id: paths for job_id, paths in saved.items() if paths} == {}


@pytest.mark.parametrize("scenario", TRUSTED.values(), ids=TRUSTED)
@pytest.mark.parametrize("fail", list(PULLS))
def test_a_failed_pull_publishes_nothing_for_that_cache(scenario: Scenario, fail: str) -> None:
    written = {path for paths in _all_saved(scenario, "miss", fail).values() for path in paths or []}

    assert PULLS[fail] not in written, f"{fail!r} failed but {PULLS[fail]!r} was still saved"


def test_every_cache_save_in_the_workflow_still_carries_the_named_ref_clause() -> None:
    for job_id, job in _jobs().items():
        for step in _saves(job):
            condition = str(step.get("if", "")).strip()
            assert condition.endswith(f"&& {NAMED_REF_CLAUSE}"), f"{job_id}: {step['name']!r} if: {condition!r}"
