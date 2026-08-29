"""Fail-closed tagged release mutation preconditions."""

from __future__ import annotations

from dataclasses import fields, replace
from typing import Any

import pytest

from scripts import release_mutation as rm
from scripts import release_version as rv

API: Any = rm
VERSIONS: Any = rv
STABLE = VERSIONS.parse_release_tag("v4.0.0", "stable")
SOURCE_SHA = "a" * 40
OTHER_SOURCE_SHA = "b" * 40
PORTS_SHA = "c" * 40
OTHER_PORTS_SHA = "d" * 40
INPUT_DIGEST = "e" * 64
OTHER_INPUT_DIGEST = "f" * 64
ARTIFACT_SHA = "1" * 64
OTHER_ARTIFACT_SHA = "2" * 64


def _request(
    result: Any = STABLE,
    selected_release_line: str | None = STABLE.release_line,
    source_sha: str = SOURCE_SHA,
    ports_sha: str = PORTS_SHA,
    input_digest: str = INPUT_DIGEST,
    artifact_sha256: str = ARTIFACT_SHA,
) -> Any:
    return API.MutationRequest(result, selected_release_line, source_sha, ports_sha, input_digest, artifact_sha256)


def _observed(**changes: Any) -> Any:
    return API.ObservedMutationState(source_reachable=True, **changes)


def _run(request: Any | None = None, observed: Any | None = None) -> tuple[str, list[str]]:
    calls: list[str] = []
    outcome = API.apply_release_mutation(request or _request(), observed or _observed(), lambda: calls.append("mutate"))
    return outcome, calls


def test_public_mutation_dataclasses_are_frozen_and_explicit() -> None:
    assert [field.name for field in fields(API.MutationRequest)] == [
        "result",
        "selected_release_line",
        "source_sha",
        "ports_sha",
        "input_digest",
        "artifact_sha256",
    ]
    assert [field.name for field in fields(API.ObservedMutationState)] == [
        "source_reachable",
        "tag",
        "tag_source_sha",
        "release_state",
        "latest_pkg_version",
        "candidate_vs_latest",
        "existing_pkg_version",
        "existing_artifact_sha256",
        "existing_source_sha",
        "existing_ports_sha",
        "existing_input_digest",
    ]
    assert API.MutationRequest.__dataclass_params__.frozen  # type: ignore[attr-defined]
    assert API.ObservedMutationState.__dataclass_params__.frozen  # type: ignore[attr-defined]


def test_fresh_tagged_mutation_calls_callback_once() -> None:
    assert _run() == ("mutated", ["mutate"])


def test_exact_existing_artifact_and_build_input_are_unchanged() -> None:
    observed = _observed(
        existing_pkg_version=STABLE.pkg_version,
        existing_artifact_sha256=ARTIFACT_SHA,
        existing_source_sha=SOURCE_SHA,
        existing_ports_sha=PORTS_SHA,
        existing_input_digest=INPUT_DIGEST,
    )
    assert _run(observed=observed) == ("unchanged", [])


@pytest.mark.parametrize(
    "changes",
    [
        {"existing_artifact_sha256": OTHER_ARTIFACT_SHA},
        {"existing_source_sha": OTHER_SOURCE_SHA},
        {"existing_ports_sha": OTHER_PORTS_SHA},
        {"existing_input_digest": OTHER_INPUT_DIGEST},
    ],
)
def test_same_package_different_artifact_or_input_fails_before_callback(changes: dict[str, str]) -> None:
    observed_values = {
        "existing_pkg_version": STABLE.pkg_version,
        "existing_artifact_sha256": ARTIFACT_SHA,
        "existing_source_sha": SOURCE_SHA,
        "existing_ports_sha": PORTS_SHA,
        "existing_input_digest": INPUT_DIGEST,
        **changes,
    }
    observed = _observed(**observed_values)
    calls: list[str] = []
    with pytest.raises(ValueError, match="collision"):
        API.apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
    assert calls == []


def test_assetless_tagged_recovery_keeps_tag_and_source_safety() -> None:
    observed = _observed(
        tag=STABLE.tag,
        tag_source_sha=SOURCE_SHA,
        release_state="draft_assetless",
        latest_pkg_version="opaque-latest",
        candidate_vs_latest="=",
    )
    assert _run(observed=observed) == ("mutated", ["mutate"])
    for invalid in (
        _observed(tag=STABLE.tag, release_state="draft_assetless"),
        _observed(tag="v4.0.1", tag_source_sha=SOURCE_SHA, release_state="draft_assetless"),
        _observed(tag=STABLE.tag, tag_source_sha=OTHER_SOURCE_SHA, release_state="draft_assetless"),
    ):
        calls: list[str] = []
        with pytest.raises((TypeError, ValueError)):
            API.apply_release_mutation(_request(), invalid, lambda: calls.append("mutate"))
        assert calls == []


@pytest.mark.parametrize("release_state", ["draft_with_assets", "published"])
def test_immutable_release_state_wins_over_identical_noop(release_state: str) -> None:
    observed = _observed(
        release_state=release_state,
        existing_pkg_version=STABLE.pkg_version,
        existing_artifact_sha256=ARTIFACT_SHA,
        existing_source_sha=SOURCE_SHA,
        existing_ports_sha=PORTS_SHA,
        existing_input_digest=INPUT_DIGEST,
    )
    with pytest.raises(ValueError):
        API.apply_release_mutation(_request(), observed, lambda: None)


def test_stale_catalogue_candidate_rejects_before_callback() -> None:
    observed = _observed(latest_pkg_version="opaque-latest", candidate_vs_latest="<")
    calls: list[str] = []
    with pytest.raises(ValueError, match="stale"):
        API.apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
    assert calls == []


@pytest.mark.parametrize(
    "tag",
    ["", "v" + "x" * 128, "v4.0.0\n", "v4.0.0é"],
)
def test_observed_hostile_tag_fails_closed(tag: str) -> None:
    calls: list[str] = []
    with pytest.raises((TypeError, ValueError)):
        API.apply_release_mutation(_request(), _observed(tag=tag), lambda: calls.append("mutate"))
    assert calls == []


@pytest.mark.parametrize(
    "observation",
    [
        {"latest_pkg_version": "opaque"},
        {"candidate_vs_latest": ">"},
        {"existing_pkg_version": "opaque"},
        {"existing_artifact_sha256": ARTIFACT_SHA},
        {"existing_source_sha": SOURCE_SHA},
        {"existing_ports_sha": PORTS_SHA},
        {"existing_input_digest": INPUT_DIGEST},
        {"latest_pkg_version": "line\nbreak", "candidate_vs_latest": "="},
        {"existing_pkg_version": "line\nbreak", "existing_artifact_sha256": ARTIFACT_SHA},
        {"release_state": "ABSENT"},
        {"candidate_vs_latest": "=="},
    ],
)
def test_malformed_observations_never_call_mutator(observation: dict[str, object]) -> None:
    observed = _observed(**observation)
    calls: list[str] = []
    with pytest.raises((TypeError, ValueError)):
        API.apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
    assert calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        ("source_sha", "A" * 40),
        ("source_sha", "a" * 39),
        ("ports_sha", "A" * 40),
        ("input_digest", "A" * 64),
        ("artifact_sha256", "A" * 64),
        ("selected_release_line", "release/4.1"),
        ("result", replace(STABLE, package="wrong")),
    ],
)
def test_malformed_requests_fail_closed_before_callback(mutation: tuple[str, object]) -> None:
    field, value = mutation
    request = _request(**{field: value})  # type: ignore[arg-type]
    calls: list[str] = []
    with pytest.raises((TypeError, ValueError)):
        API.apply_release_mutation(request, _observed(), lambda: calls.append("mutate"))
    assert calls == []


def test_exact_dataclass_types_and_callable_mutator_are_required() -> None:
    with pytest.raises(TypeError):
        API.apply_release_mutation(object(), _observed(), lambda: None)
    with pytest.raises(TypeError):
        API.apply_release_mutation(_request(), object(), lambda: None)
    with pytest.raises(TypeError):
        API.apply_release_mutation(_request(), _observed(), None)
