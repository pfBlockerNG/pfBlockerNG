"""Fail-closed preconditions for tagged release mutation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Literal

from scripts import release_version as rv

ReleaseInfo = rv.ReleaseInfo
ReleaseState = Literal["absent", "draft_assetless", "draft_with_assets", "published"]
Comparison = Literal["<", "=", ">"]
MutationOutcome = Literal["mutated", "unchanged"]

_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_RE = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_STATES = ("absent", "draft_assetless", "draft_with_assets", "published")
_COMPARISONS = ("<", "=", ">")


@dataclass(frozen=True)
class MutationRequest:
    result: ReleaseInfo
    selected_release_line: str
    source_sha: str
    ports_sha: str
    input_digest: str
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
    existing_source_sha: str | None = None
    existing_ports_sha: str | None = None
    existing_input_digest: str | None = None


def _validate_sha(value: object, *, name: str) -> None:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise ValueError(f"{name} must be lowercase 40- or 64-character hex")


def _validate_digest(value: object, *, name: str) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{name} must be lowercase 64-character hex")


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


def _validate_result(result: object) -> str:
    if type(result) is ReleaseInfo:
        rv.validate_release_info(result)
        if result.tag is None:
            raise ValueError("tagged mutation requires a release tag")
        return result.pkg_version
    raise TypeError("request.result must be ReleaseInfo")


def _validate_observed(observed: object) -> ObservedMutationState:
    if type(observed) is not ObservedMutationState:
        raise TypeError("observed must be ObservedMutationState")
    if observed.source_reachable is not True:
        raise ValueError("source must be reachable")
    if observed.release_state not in _RELEASE_STATES:
        raise ValueError("invalid release state")
    if observed.tag is not None:
        _validate_observed_tag(observed.tag)
    if observed.candidate_vs_latest is not None and observed.candidate_vs_latest not in _COMPARISONS:
        raise ValueError("invalid package comparison")
    if (observed.latest_pkg_version is None) != (observed.candidate_vs_latest is None):
        raise ValueError("latest package version and comparison must be paired")
    existing_values = (
        observed.existing_pkg_version,
        observed.existing_artifact_sha256,
        observed.existing_source_sha,
        observed.existing_ports_sha,
        observed.existing_input_digest,
    )
    if any(value is None for value in existing_values) and any(value is not None for value in existing_values):
        raise ValueError("existing package and provenance observations must be paired")
    _validate_pkg_observation(observed.latest_pkg_version, name="latest_pkg_version")
    _validate_pkg_observation(observed.existing_pkg_version, name="existing_pkg_version")
    if observed.existing_artifact_sha256 is not None:
        _validate_artifact_sha(observed.existing_artifact_sha256)
    if observed.existing_source_sha is not None:
        _validate_sha(observed.existing_source_sha, name="existing_source_sha")
    if observed.existing_ports_sha is not None:
        _validate_sha(observed.existing_ports_sha, name="existing_ports_sha")
    if observed.existing_input_digest is not None:
        _validate_digest(observed.existing_input_digest, name="existing_input_digest")
    if observed.tag_source_sha is not None:
        _validate_sha(observed.tag_source_sha, name="tag_source_sha")
    if (observed.tag is None) != (observed.tag_source_sha is None):
        raise ValueError("observed tag and tag source must be paired")
    return observed


def _validate_tag_state(result: ReleaseInfo, request: MutationRequest, observed: ObservedMutationState) -> bool:
    """Validate tag/release identity; return whether assetless recovery is allowed."""
    if observed.release_state in {"draft_with_assets", "published"}:
        raise ValueError("existing release is immutable")
    if request.selected_release_line != result.release_line:
        raise ValueError("selected release line does not match result")
    if observed.release_state == "absent":
        if observed.tag is None and observed.tag_source_sha is None:
            return False
        if observed.tag == result.tag and observed.tag_source_sha == request.source_sha:
            return True
        raise ValueError("existing tag is already present or moved")
    if observed.release_state == "draft_assetless":
        if observed.tag != result.tag or observed.tag_source_sha != request.source_sha:
            raise ValueError("assetless draft tag/source mismatch")
        return True
    raise ValueError("invalid tagged release state")


def apply_release_mutation(
    request: MutationRequest,
    observed: ObservedMutationState,
    mutate: Callable[[], object],
) -> MutationOutcome:
    """Apply mutation only after release, artifact, and input provenance checks pass."""
    if type(request) is not MutationRequest:
        raise TypeError("request must be MutationRequest")
    if not callable(mutate):
        raise TypeError("mutate must be callable")
    pkg_version = _validate_result(request.result)
    if not isinstance(request.selected_release_line, str):
        raise TypeError("selected_release_line must be str")
    _validate_sha(request.source_sha, name="source_sha")
    _validate_sha(request.ports_sha, name="ports_sha")
    _validate_digest(request.input_digest, name="input_digest")
    _validate_artifact_sha(request.artifact_sha256)
    state = _validate_observed(observed)
    recovery = _validate_tag_state(request.result, request, state)
    if state.existing_pkg_version == pkg_version:
        if state.existing_artifact_sha256 != request.artifact_sha256:
            raise ValueError("artifact collision for existing package version")
        if (
            state.existing_source_sha,
            state.existing_ports_sha,
            state.existing_input_digest,
        ) != (request.source_sha, request.ports_sha, request.input_digest):
            raise ValueError("build input collision for existing package version")
        if recovery:
            mutate()
            return "mutated"
        return "unchanged"

    if state.candidate_vs_latest == "<":
        raise ValueError("candidate package is stale")

    if state.candidate_vs_latest == "=" and not recovery:
        raise ValueError("candidate package already exists")
    mutate()
    return "mutated"
