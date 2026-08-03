"""Fail-closed release mutation preconditions."""

from __future__ import annotations

from dataclasses import fields, replace
from datetime import date
from typing import Any

import pytest

from scripts.release_mutation import (
    MutationRequest,
    ObservedMutationState,
    apply_release_mutation,
)
from scripts.release_version import PACKAGE, generate_snapshot, parse_release_tag

STABLE = parse_release_tag("v4.0.0")
NIGHTLY = generate_snapshot(
    channel="nightly",
    target_final="4.0.0",
    release_line="devel",
    source_sha="a" * 40,
    build_date=date(2026, 8, 4),
)
SOURCE_SHA = "a" * 40
OTHER_SOURCE_SHA = "b" * 40
ARTIFACT_SHA = "c" * 64
OTHER_ARTIFACT_SHA = "d" * 64


def _request(
    result: Any = STABLE, source_sha: str = SOURCE_SHA, artifact_sha256: str = ARTIFACT_SHA
) -> MutationRequest:
    return MutationRequest(result, result.release_line, source_sha, artifact_sha256)


def _observed(**changes: Any) -> ObservedMutationState:
    return ObservedMutationState(**{"source_reachable": True, **changes})


def _observed_with_tag(tag: str | None, **changes: Any) -> ObservedMutationState:
    return ObservedMutationState(source_reachable=True, tag=tag, **changes)


def _run(
    request: MutationRequest | None = None, observed: ObservedMutationState | None = None
) -> tuple[str, list[str]]:
    calls: list[str] = []

    def mutate() -> object:
        calls.append("mutate")
        return object()

    outcome = apply_release_mutation(
        request or _request(),
        observed or _observed(),
        mutate,
    )
    return outcome, calls


def test_public_dataclasses_have_exact_frozen_shapes() -> None:
    assert [field.name for field in fields(MutationRequest)] == [
        "result",
        "selected_release_line",
        "source_sha",
        "artifact_sha256",
    ]
    assert [field.name for field in fields(ObservedMutationState)] == [
        "source_reachable",
        "tag",
        "tag_source_sha",
        "release_state",
        "latest_pkg_version",
        "candidate_vs_latest",
        "existing_pkg_version",
        "existing_artifact_sha256",
    ]
    assert MutationRequest.__dataclass_params__.frozen  # type: ignore[attr-defined]
    assert ObservedMutationState.__dataclass_params__.frozen  # type: ignore[attr-defined]


def test_fresh_tagged_release_mutates_once_and_ignores_callback_return() -> None:
    outcome, calls = _run()
    assert outcome == "mutated"
    assert calls == ["mutate"]


def test_fresh_nightly_release_mutates_once() -> None:
    outcome, calls = _run(_request(NIGHTLY), _observed())
    assert outcome == "mutated"
    assert calls == ["mutate"]


def test_exact_existing_artifact_is_unchanged_without_callback() -> None:
    observed = _observed(existing_pkg_version=STABLE.pkg_version, existing_artifact_sha256=ARTIFACT_SHA)
    calls: list[str] = []
    outcome = apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
    assert outcome == "unchanged"
    assert calls == []


def test_assetless_draft_same_tag_and_source_recovers_equal_candidate() -> None:
    observed = _observed_with_tag(
        STABLE.tag,
        tag_source_sha=SOURCE_SHA,
        release_state="draft_assetless",
        latest_pkg_version="opaque-latest",
        candidate_vs_latest="=",
    )
    outcome, calls = _run(observed=observed)
    assert outcome == "mutated"
    assert calls == ["mutate"]


def test_assetless_recovery_requires_exact_observed_tag_and_source() -> None:
    invalid = [
        _observed_with_tag(STABLE.tag, tag_source_sha=SOURCE_SHA),
        _observed_with_tag(None, tag_source_sha=SOURCE_SHA, release_state="draft_assetless"),
        _observed_with_tag(STABLE.tag, release_state="draft_assetless"),
        _observed_with_tag("v4.0.1", tag_source_sha=SOURCE_SHA, release_state="draft_assetless"),
        _observed_with_tag(STABLE.tag, tag_source_sha=OTHER_SOURCE_SHA, release_state="draft_assetless"),
    ]
    for observed in invalid:
        calls = []
        with pytest.raises((TypeError, ValueError)):
            apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
        assert calls == []


def test_fresh_and_nightly_mutations_require_absent_observed_tag_identity() -> None:
    for request, observed in (
        (_request(), _observed_with_tag(STABLE.tag)),
        (_request(), _observed_with_tag(STABLE.tag, tag_source_sha=SOURCE_SHA)),
        (_request(NIGHTLY), _observed_with_tag("v4.0.0")),
    ):
        calls: list[str] = []
        with pytest.raises((TypeError, ValueError)):
            apply_release_mutation(request, observed, lambda: calls.append("mutate"))
        assert calls == []


@pytest.mark.parametrize("tag", ["", "v" + "x" * 128, "v4.0.0\n", "v4.0.0é"])
def test_observed_tag_must_be_printable_ascii_release_tag_sized(tag: str) -> None:
    observed = _observed_with_tag(tag)
    calls: list[str] = []
    with pytest.raises((TypeError, ValueError)):
        apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
    assert calls == []


def test_assetless_recovery_still_rejects_stale_or_artifact_collision() -> None:
    cases = [
        _observed(
            tag_source_sha=SOURCE_SHA,
            release_state="draft_assetless",
            latest_pkg_version="opaque-latest",
            candidate_vs_latest="<",
        ),
        _observed(
            tag_source_sha=SOURCE_SHA,
            release_state="draft_assetless",
            existing_pkg_version=STABLE.pkg_version,
            existing_artifact_sha256=OTHER_ARTIFACT_SHA,
        ),
    ]
    for observed in cases:
        calls: list[str] = []
        with pytest.raises(ValueError):
            apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
        assert calls == []


def test_callback_exception_propagates_after_valid_preconditions() -> None:
    error = RuntimeError("mutation failed")
    calls: list[str] = []

    def mutate() -> object:
        calls.append("mutate")
        raise error

    with pytest.raises(RuntimeError, match="mutation failed"):
        apply_release_mutation(_request(), _observed(), mutate)
    assert calls == ["mutate"]


@pytest.mark.parametrize(
    "result,selected_release_line",
    [
        (replace(STABLE, version="4.0.99"), STABLE.release_line),
        (replace(STABLE, target_final="4.0.99"), STABLE.release_line),
        (replace(STABLE, release_line="release/4.1"), "release/4.1"),
        (replace(STABLE, pkg_version="4.0.99"), STABLE.release_line),
        (replace(STABLE, sequence="1"), STABLE.release_line),
        (replace(STABLE, tag="vgarbage"), STABLE.release_line),
    ],
)
def test_tagged_canonical_field_tampering_never_calls_mutator(result: Any, selected_release_line: str) -> None:
    calls: list[str] = []
    request = MutationRequest(result, selected_release_line, SOURCE_SHA, ARTIFACT_SHA)
    with pytest.raises((TypeError, ValueError)):
        apply_release_mutation(request, _observed(), lambda: calls.append("mutate"))
    assert calls == []


@pytest.mark.parametrize(
    "result,selected_release_line",
    [
        (replace(NIGHTLY, version="4.0.0.nightly.20260804.2"), NIGHTLY.release_line),
        (replace(NIGHTLY, target_final="4.0.1"), NIGHTLY.release_line),
        (replace(NIGHTLY, release_line="devel/forged"), "devel/forged"),
        (replace(NIGHTLY, pkg_version="4.0.0.snapshot.2.20260804.2"), NIGHTLY.release_line),
        (replace(NIGHTLY, sequence="20260804.2"), NIGHTLY.release_line),
        (replace(NIGHTLY, package="wrong"), NIGHTLY.release_line),
        (replace(NIGHTLY, prerelease=False), NIGHTLY.release_line),
        (replace(NIGHTLY, final=True), NIGHTLY.release_line),
        (replace(NIGHTLY, notes_required=True), NIGHTLY.release_line),
        (replace(NIGHTLY, github_release="prerelease"), NIGHTLY.release_line),
        (replace(NIGHTLY, stage="edge"), NIGHTLY.release_line),
        (replace(NIGHTLY, channel="edge"), NIGHTLY.release_line),
    ],
)
def test_nightly_canonical_field_tampering_never_calls_mutator(result: Any, selected_release_line: str) -> None:
    calls: list[str] = []
    request = MutationRequest(result, selected_release_line, SOURCE_SHA, ARTIFACT_SHA)
    with pytest.raises((TypeError, ValueError)):
        apply_release_mutation(request, _observed(), lambda: calls.append("mutate"))
    assert calls == []


@pytest.mark.parametrize(
    "mutation_request,observed",
    [
        (replace(_request(), result=replace(STABLE, package="wrong")), _observed()),
        (replace(_request(), selected_release_line="release/4.1"), _observed()),
        (replace(_request(), source_sha="A" * 40), _observed()),
        (replace(_request(), source_sha="a" * 39), _observed()),
        (replace(_request(), artifact_sha256="A" * 64), _observed()),
        (replace(_request(), artifact_sha256="c" * 63), _observed()),
        (replace(_request(), source_sha=OTHER_SOURCE_SHA), _observed(source_reachable=False)),
        (replace(_request(), source_sha=OTHER_SOURCE_SHA), _observed(source_reachable=1)),
        (_request(), _observed(tag_source_sha="A" * 40)),
        (_request(), _observed(tag_source_sha="a" * 39)),
        (_request(), _observed(tag_source_sha=1)),
    ],
)
def test_invalid_request_or_reachability_never_calls_mutator(
    mutation_request: MutationRequest, observed: ObservedMutationState
) -> None:
    calls: list[str] = []
    with pytest.raises((TypeError, ValueError)):
        apply_release_mutation(mutation_request, observed, lambda: calls.append("mutate"))
    assert calls == []


@pytest.mark.parametrize(
    "observed",
    [
        _observed(latest_pkg_version="opaque"),
        _observed(candidate_vs_latest=">"),
        _observed(existing_pkg_version="opaque"),
        _observed(existing_artifact_sha256=ARTIFACT_SHA),
        _observed(latest_pkg_version="", candidate_vs_latest="="),
        _observed(latest_pkg_version="é", candidate_vs_latest="="),
        _observed(latest_pkg_version="x" * 129, candidate_vs_latest="="),
        _observed(latest_pkg_version="line\nbreak", candidate_vs_latest="="),
        _observed(latest_pkg_version="nul\x00byte", candidate_vs_latest="="),
        _observed(existing_pkg_version="line\nbreak", existing_artifact_sha256=ARTIFACT_SHA),
        _observed(existing_pkg_version="opaque", existing_artifact_sha256="D" * 64),
        _observed(release_state="ABSENT"),
        _observed(candidate_vs_latest="=="),
    ],
)
def test_malformed_observations_fail_closed_before_callback(observed: ObservedMutationState) -> None:
    calls: list[str] = []
    with pytest.raises((TypeError, ValueError)):
        apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
    assert calls == []


def test_exact_dataclass_types_and_callable_mutator_are_required() -> None:
    calls: list[str] = []
    for request, observed in (
        (object(), _observed()),
        (MutationRequest(object(), "release/4.0", SOURCE_SHA, ARTIFACT_SHA), _observed()),  # type: ignore[arg-type]
        (_request(), object()),
    ):
        with pytest.raises((TypeError, ValueError)):
            apply_release_mutation(request, observed, lambda: calls.append("mutate"))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        apply_release_mutation(_request(), _observed(), None)  # type: ignore[arg-type]
    assert calls == []


def test_moved_tag_repeated_tag_and_immutable_release_states_reject() -> None:
    cases = [
        _observed(tag_source_sha=OTHER_SOURCE_SHA),
        _observed(tag_source_sha=SOURCE_SHA),
        _observed(tag_source_sha=SOURCE_SHA, release_state="draft_with_assets"),
        _observed(tag_source_sha=SOURCE_SHA, release_state="published"),
        _observed(release_state="draft_assetless"),
        _observed(tag_source_sha=OTHER_SOURCE_SHA, release_state="draft_assetless"),
    ]
    for observed in cases:
        calls: list[str] = []
        with pytest.raises(ValueError):
            apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
        assert calls == []


def test_nightly_requires_unpublished_unassociated_tag_state() -> None:
    for observed in (
        _observed(tag_source_sha=SOURCE_SHA),
        _observed(release_state="draft_assetless"),
        _observed(release_state="draft_with_assets"),
        _observed(release_state="published"),
    ):
        calls: list[str] = []
        with pytest.raises(ValueError):
            apply_release_mutation(_request(NIGHTLY), observed, lambda: calls.append("mutate"))
        assert calls == []


def test_nightly_malformed_stage_or_channel_rejects_without_parsing_tag() -> None:
    for result in (replace(NIGHTLY, stage="edge"), replace(NIGHTLY, channel="testing")):
        calls: list[str] = []
        with pytest.raises(ValueError):
            apply_release_mutation(_request(result), _observed(), lambda: calls.append("mutate"))
        assert calls == []


@pytest.mark.parametrize(
    "result",
    [replace(STABLE, tag=None), replace(NIGHTLY, tag="v4.0.0.nightly.20260804.1")],
)
def test_inconsistent_tagged_and_nightly_shapes_reject(result: Any) -> None:
    calls: list[str] = []
    with pytest.raises(ValueError):
        apply_release_mutation(_request(result), _observed(), lambda: calls.append("mutate"))
    assert calls == []


def test_pkg_collision_with_different_artifact_rejects() -> None:
    observed = _observed(existing_pkg_version=STABLE.pkg_version, existing_artifact_sha256=OTHER_ARTIFACT_SHA)
    calls: list[str] = []
    with pytest.raises(ValueError, match="collision"):
        apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
    assert calls == []


@pytest.mark.parametrize("release_state", ["draft_with_assets", "published"])
def test_immutable_release_state_wins_over_identical_artifact_noop(release_state: str) -> None:
    observed = _observed(
        release_state=release_state,
        existing_pkg_version=STABLE.pkg_version,
        existing_artifact_sha256=ARTIFACT_SHA,
    )
    calls: list[str] = []
    with pytest.raises(ValueError):
        apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
    assert calls == []


@pytest.mark.parametrize("comparison", ["<", "="])
def test_stale_or_repeated_catalogue_candidate_rejects(comparison: str) -> None:
    observed = _observed(latest_pkg_version="opaque-latest", candidate_vs_latest=comparison)
    calls: list[str] = []
    with pytest.raises(ValueError):
        apply_release_mutation(_request(), observed, lambda: calls.append("mutate"))
    assert calls == []


def test_greater_and_empty_catalogue_candidates_mutate_without_package_parsing() -> None:
    request = _request()
    for observed in (_observed(), _observed(latest_pkg_version="opaque latest !", candidate_vs_latest=">")):
        outcome, calls = _run(request=request, observed=observed)
        assert outcome == "mutated"
        assert calls == ["mutate"]


def test_mutation_request_and_observation_are_not_modified() -> None:
    request = _request()
    observed = _observed()
    before_request = request
    before_observed = observed
    outcome, _ = _run(request, observed)
    assert outcome == "mutated"
    assert request == before_request
    assert observed == before_observed


def test_wrong_package_constant_is_rejected_even_for_nightly() -> None:
    assert STABLE.package == PACKAGE
    request = _request(replace(NIGHTLY, package="other"))
    calls: list[str] = []
    with pytest.raises(ValueError):
        apply_release_mutation(request, _observed(), lambda: calls.append("mutate"))
    assert calls == []
