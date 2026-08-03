"""Fail-closed preconditions for release artifact mutation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Literal

from scripts.release_version import ReleaseInfo, validate_release_info

ReleaseState = Literal["absent", "draft_assetless", "draft_with_assets", "published"]
Comparison = Literal["<", "=", ">"]
MutationOutcome = Literal["mutated", "unchanged"]

_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ARTIFACT_RE = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_STATES = ("absent", "draft_assetless", "draft_with_assets", "published")
_COMPARISONS = ("<", "=", ">")


@dataclass(frozen=True)
class MutationRequest:
    result: ReleaseInfo
    selected_release_line: str
    source_sha: str
    artifact_sha256: str


@dataclass(frozen=True)
class ObservedMutationState:
    source_reachable: bool
    tag: str | None = None
    tag_source_sha: str | None = None
    release_state: ReleaseState = "absent"
    latest_pkg_version: str | None = None
    candidate_vs_latest: Comparison | None = None
    existing_pkg_version: str | None = None
    existing_artifact_sha256: str | None = None


def _validate_sha(value: object, *, name: str) -> None:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise ValueError(f"{name} must be lowercase 40- or 64-character hex")


def _validate_artifact_sha(value: object) -> None:
    if not isinstance(value, str) or not _ARTIFACT_RE.fullmatch(value):
        raise ValueError("artifact_sha256 must be lowercase 64-character hex")


def _validate_pkg_observation(value: object, *, name: str) -> None:
    if value is None:
        return
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or not all(0x20 <= ord(char) <= 0x7E for char in value)
    ):
        raise ValueError(f"{name} must be nonempty ASCII of at most 128 characters")


def _validate_observed_tag(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or not value.startswith("v")
        or not all(0x20 <= ord(char) <= 0x7E for char in value)
    ):
        raise ValueError("tag must be a printable ASCII release tag of at most 128 characters")


def _validate_result(result: object) -> ReleaseInfo:
    if type(result) is not ReleaseInfo:
        raise TypeError("request.result must be ReleaseInfo")
    validate_release_info(result)
    return result


def _validate_observed(observed: object) -> ObservedMutationState:
    if type(observed) is not ObservedMutationState:
        raise TypeError("observed must be ObservedMutationState")
    if observed.source_reachable is not True:
        raise ValueError("source must be reachable")
    if not isinstance(observed.release_state, str) or observed.release_state not in _RELEASE_STATES:
        raise ValueError("invalid release state")
    if observed.tag is not None:
        _validate_observed_tag(observed.tag)
    if observed.candidate_vs_latest is not None and (
        not isinstance(observed.candidate_vs_latest, str) or observed.candidate_vs_latest not in _COMPARISONS
    ):
        raise ValueError("invalid package comparison")
    if (observed.latest_pkg_version is None) != (observed.candidate_vs_latest is None):
        raise ValueError("latest package version and comparison must be paired")
    if (observed.existing_pkg_version is None) != (observed.existing_artifact_sha256 is None):
        raise ValueError("existing package version and artifact digest must be paired")
    _validate_pkg_observation(observed.latest_pkg_version, name="latest_pkg_version")
    _validate_pkg_observation(observed.existing_pkg_version, name="existing_pkg_version")
    if observed.existing_artifact_sha256 is not None:
        _validate_artifact_sha(observed.existing_artifact_sha256)
    if observed.tag_source_sha is not None:
        _validate_sha(observed.tag_source_sha, name="tag_source_sha")
    if (observed.tag is None) != (observed.tag_source_sha is None):
        raise ValueError("observed tag and tag source must be paired")
    return observed


def _validate_tag_state(result: ReleaseInfo, request: MutationRequest, observed: ObservedMutationState) -> bool:
    """Validate tag/release identity; return whether assetless recovery is allowed."""
    nightly = result.tag is None
    if observed.release_state in {"draft_with_assets", "published"}:
        raise ValueError("existing release is immutable")
    if nightly:
        if observed.tag is not None or observed.tag_source_sha is not None or observed.release_state != "absent":
            raise ValueError("Nightly mutation requires an absent untagged release")
        return False

    if observed.release_state == "absent":
        if observed.tag is None and observed.tag_source_sha is None:
            return False
        if observed.tag == result.tag and observed.tag_source_sha == request.source_sha:
            return True
        raise ValueError("existing tag is already present or moved")
    if observed.release_state == "draft_assetless":
        if observed.tag != result.tag:
            raise ValueError("assetless draft has a different tag")
        if observed.tag_source_sha != request.source_sha:
            raise ValueError("tag moved to a different source")
        return True
    raise ValueError("invalid tagged release state")


def apply_release_mutation(
    request: MutationRequest,
    observed: ObservedMutationState,
    mutate: Callable[[], object],
) -> MutationOutcome:
    """Apply mutation only after all release identity and artifact preconditions pass."""
    if type(request) is not MutationRequest:
        raise TypeError("request must be MutationRequest")
    if not callable(mutate):
        raise TypeError("mutate must be callable")
    result = _validate_result(request.result)
    if not isinstance(request.selected_release_line, str) or request.selected_release_line != result.release_line:
        raise ValueError("selected release line does not match result")
    _validate_sha(request.source_sha, name="source_sha")
    _validate_artifact_sha(request.artifact_sha256)
    state = _validate_observed(observed)
    recovery = _validate_tag_state(result, request, state)
    comparison = state.candidate_vs_latest
    if comparison == "<":
        raise ValueError("candidate package is stale")

    if state.existing_pkg_version == result.pkg_version:
        if state.existing_artifact_sha256 != request.artifact_sha256:
            raise ValueError("artifact collision for existing package version")
        if recovery:
            mutate()
            return "mutated"
        return "unchanged"

    if comparison == "=" and not recovery:
        raise ValueError("candidate package already exists")

    mutate()
    return "mutated"
