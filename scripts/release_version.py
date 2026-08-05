"""Parse pfBlockerNG release tags and derive their canonical release metadata."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal, Mapping, Sequence

PACKAGE = "pfSense-pkg-pfBlockerNG"

Stage = Literal["final", "alpha", "beta", "rc"]
Channel = Literal["stable", "testing", "edge"]
GithubRelease = Literal["final", "prerelease"]

_CORE = r"(0|[1-9][0-9]*)"
_FINAL_RE = re.compile(rf"^v(?P<major>{_CORE})\.(?P<minor>{_CORE})\.(?P<patch>{_CORE})$")
_PREVIEW_RE = re.compile(
    rf"^v(?P<major>{_CORE})\.(?P<minor>{_CORE})\.(?P<patch>{_CORE})\."
    r"(?P<stage>[abr])(?P<sequence>[1-9][0-9]*)$"
)
_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_NIGHTLY_RE = re.compile(r"^(?P<date>[0-9]{8})$")
_NIGHTLY_PKG_RE = re.compile(r"^(?P<date>[0-9]{8})(?:_(?P<revision>[1-9][0-9]*))?$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_RELEASE_TEXT = 128


def _tag_shape(tag: str) -> tuple[str, str, str, str | None, str | None]:
    """Return strict tag components without inferring a destination channel."""
    if not isinstance(tag, str) or not tag or len(tag) > _MAX_RELEASE_TEXT or not tag.isascii():
        raise _invalid(tag)
    match = _FINAL_RE.fullmatch(tag)
    if match:
        return (match.group("major"), match.group("minor"), match.group("patch"), None, None)
    match = _PREVIEW_RE.fullmatch(tag)
    if match:
        return tuple(match.group(name) for name in ("major", "minor", "patch", "stage", "sequence"))  # type: ignore[return-value]
    raise _invalid(tag)


@dataclass(frozen=True)
class ReleaseInfo:
    tag: str | None
    version: str
    stage: Stage
    sequence: str | None
    target_final: str
    release_line: str
    channel: Channel
    prerelease: bool
    final: bool
    notes_required: bool
    github_release: GithubRelease
    pkg_version: str
    package: str


NightlyOutcome = Literal["build", "unchanged"]


@dataclass(frozen=True)
class NightlyAllocation:
    outcome: NightlyOutcome
    portversion: str
    portrevision: int
    pkg_version: str
    source_sha: str
    ports_sha: str
    input_digest: str


def _invalid(tag: str) -> ValueError:
    return ValueError(f"invalid release tag: {tag!r}")


def get_tag(
    major: str | int,
    minor: str | int,
    patch: str | int,
    tags: Sequence[str] = (),
    *,
    branch: str | None = None,
    tag_branches: Mapping[str, str] | None = None,
) -> str | None:
    """Return an exact valid tag, optionally restricted to one release line."""
    expected = (str(major), str(minor), str(patch))
    branches = tag_branches or {}
    for candidate in tags:
        try:
            shape = _tag_shape(candidate)
        except ValueError:
            continue
        if shape[:3] == expected and shape[3] is None and (branch is None or branches.get(candidate) == branch):
            return candidate
    return None


def get_tags_zero_after(
    tag_for_zero: str | None,
    tags: Sequence[str] = (),
    *,
    tag_branches: Mapping[str, str] | None = None,
) -> list[str]:
    """Return higher-family patch-zero prereleases on their own release lines."""
    if tag_for_zero is None:
        return []
    ordered = list(tags)
    try:
        anchor_major, anchor_minor, _anchor_patch, _anchor_stage, _anchor_sequence = _tag_shape(tag_for_zero)
    except ValueError:
        return []
    branches = tag_branches or {}
    result: list[str] = []
    for candidate in ordered:
        try:
            major, minor, patch, stage, _sequence = _tag_shape(candidate)
        except ValueError:
            continue
        if (
            patch == "0"
            and stage is not None
            and (int(major), int(minor)) > (int(anchor_major), int(anchor_minor))
            and branches.get(candidate) == f"release/{major}.{minor}"
        ):
            result.append(candidate)
    return result


def derive_destinations(
    tag: str,
    *,
    branch: str,
    ordered_tags: Sequence[str] = (),
    tag_branches: Mapping[str, str] | None = None,
) -> tuple[Channel, ...]:
    """Derive the ordered catalogue tuple for one release tag."""
    major, minor, patch, stage, _sequence = _tag_shape(tag)
    release_line = f"release/{major}.{minor}"
    if branch != release_line:
        raise ValueError(f"current tag {tag!r} is not on {release_line!r}")
    branches = tag_branches or {}
    if tag in branches and branches[tag] != release_line:
        raise ValueError(f"current tag {tag!r} is not on {release_line!r}")
    if stage is not None and patch == "0":
        return ("edge",)
    anchor = get_tag(major, minor, 0, ordered_tags, branch=release_line, tag_branches=branches)
    has_later_zero = bool(get_tags_zero_after(anchor, ordered_tags, tag_branches=branches))
    if stage is not None:
        return ("testing",) if has_later_zero else ("testing", "edge")
    return ("stable", "testing") if has_later_zero else ("stable", "testing", "edge")


def derive_destinations_from_git(
    tag: str,
    branch: str,
    repo: str | Path = ".",
    *,
    current_commit: str | None = None,
) -> tuple[Channel, ...]:
    """Derive destinations from tag chronology and release-line ancestry."""
    repo_path = str(repo)
    major, minor, patch, stage, _sequence = _tag_shape(tag)
    expected_branch = f"release/{major}.{minor}"
    if branch != expected_branch:
        raise ValueError(f"current tag {tag!r} is not on {expected_branch!r}")

    def git(*args: str) -> str:
        result = subprocess.run(["git", "-C", repo_path, *args], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed")
        return result.stdout.strip()

    def git_optional(*args: str) -> str:
        result = subprocess.run(["git", "-C", repo_path, *args], capture_output=True, text=True, check=False)
        return result.stdout.strip() if result.returncode == 0 else ""

    def has_exact_channel_trailer(candidate: str, expected: str) -> bool:
        if git_optional("cat-file", "-t", f"refs/tags/{candidate}") != "tag":
            return False
        contents = git("for-each-ref", "--format=%(contents)", f"refs/tags/{candidate}")
        trailer_result = subprocess.run(
            ["git", "-C", repo_path, "interpret-trailers", "--parse"],
            input=contents,
            capture_output=True,
            text=True,
            check=False,
        )
        if trailer_result.returncode != 0:
            raise RuntimeError(f"git interpret-trailers failed for {candidate}")
        trailers = [
            line for line in trailer_result.stdout.splitlines() if line.startswith("pfBlockerNG-Release-Channel:")
        ]
        return trailers == [f"pfBlockerNG-Release-Channel: {expected}"]

    def is_edge_tag(candidate: str) -> bool:
        return has_exact_channel_trailer(candidate, "edge")

    tags = git("for-each-ref", "--sort=creatordate", "--format=%(refname:strip=2)", "refs/tags/").splitlines()
    tag_commit = git_optional("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    if current_commit and tag_commit and current_commit != tag_commit:
        raise ValueError(f"current tag {tag!r} does not match the selected source commit")
    if tag_commit:
        tag_type = git_optional("cat-file", "-t", f"refs/tags/{tag}")
        expected_channel = "stable" if stage is None else ("edge" if patch == "0" else "testing")
        if tag_type != "tag":
            raise ValueError(f"current tag {tag!r} must be an annotated tag")
        if not has_exact_channel_trailer(tag, expected_channel):
            raise ValueError(f"current tag {tag!r} lacks the exact {expected_channel} release trailer")
    selected_commit = current_commit or tag_commit
    if selected_commit:
        branch_ref = f"refs/remotes/origin/{branch}"
        if not git_optional("show-ref", "--verify", branch_ref):
            branch_ref = branch
        result = subprocess.run(
            ["git", "-C", repo_path, "merge-base", "--is-ancestor", selected_commit, branch_ref], check=False
        )
        if result.returncode != 0:
            raise ValueError(f"current tag {tag!r} is not reachable from {branch!r}")

    branch_map: dict[str, str] = {}
    for candidate in tags:
        try:
            major, minor, patch, stage, _sequence = _tag_shape(candidate)
        except ValueError:
            continue
        line = f"release/{major}.{minor}"
        if patch == "0" and stage is not None and not is_edge_tag(candidate):
            if candidate == tag:
                raise ValueError(f"current tag {tag!r} lacks the exact Edge release trailer")
            continue
        commit = git("rev-parse", "--verify", f"refs/tags/{candidate}^{{commit}}")
        ref = f"refs/remotes/origin/{line}"
        if not git_optional("show-ref", "--verify", ref):
            ref = line
        result = subprocess.run(["git", "-C", repo_path, "merge-base", "--is-ancestor", commit, ref], check=False)
        if result.returncode == 0:
            branch_map[candidate] = line
    return derive_destinations(tag, branch=branch, ordered_tags=tags, tag_branches=branch_map)


def primary_channel_for_tag(tag: str) -> Channel:
    """Return the channel required by a tag's primary release trailer."""
    _major, _minor, patch, stage, _sequence = _tag_shape(tag)
    if stage is None:
        return "stable"
    return "edge" if patch == "0" else "testing"


def parse_release_tag(tag: str, channel: Channel | None = None) -> ReleaseInfo:
    """Parse one strict release tag and validate its channel context."""
    if not isinstance(tag, str) or not tag or len(tag) > 128 or not tag.isascii():
        raise _invalid(tag)

    if not isinstance(channel, str) or channel not in ("stable", "testing", "edge"):
        raise ValueError(f"invalid release channel: {channel!r}")

    match = _FINAL_RE.fullmatch(tag)
    if match:
        if channel != "stable":
            raise ValueError("final tag requires stable channel")
        major, minor, patch = (match.group(name) for name in ("major", "minor", "patch"))
        version = f"{major}.{minor}.{patch}"
        return ReleaseInfo(
            tag=tag,
            version=version,
            stage="final",
            sequence=None,
            target_final=version,
            release_line=f"release/{major}.{minor}",
            channel="stable",
            prerelease=False,
            final=True,
            notes_required=True,
            github_release="final",
            pkg_version=version,
            package=PACKAGE,
        )

    match = _PREVIEW_RE.fullmatch(tag)
    if match:
        if channel == "stable":
            raise ValueError("preview tag requires testing or edge channel")
        major, minor, patch = (match.group(name) for name in ("major", "minor", "patch"))
        expected_channel = "edge" if patch == "0" else "testing"
        if channel != expected_channel:
            raise ValueError(f"preview tag patch {patch} requires {expected_channel} channel")
        stage_code = match.group("stage")
        stage = {"a": "alpha", "b": "beta", "r": "rc"}[stage_code]
        sequence = match.group("sequence")
        version = f"{major}.{minor}.{patch}"
        return ReleaseInfo(
            tag=tag,
            version=f"{version}.{stage_code}{sequence}",
            stage=stage,  # type: ignore[arg-type]
            sequence=sequence,
            target_final=version,
            release_line=f"release/{major}.{minor}",
            channel=channel,
            prerelease=True,
            final=False,
            notes_required=True,
            github_release="prerelease",
            pkg_version=f"{version}.{stage_code}{sequence}",
            package=PACKAGE,
        )

    raise _invalid(tag)


def _validate_source_sha(source_sha: str, *, name: str = "source_sha") -> None:
    if not isinstance(source_sha, str) or not _SHA_RE.fullmatch(source_sha):
        raise ValueError(f"{name} must be lowercase 40- or 64-character hex")


def validate_release_info(info: ReleaseInfo) -> None:
    """Require a ReleaseInfo value to be exactly one canonical release identity."""
    if type(info) is not ReleaseInfo:
        raise TypeError("release info must be ReleaseInfo")
    if info.tag is None:
        raise ValueError("Nightly uses NightlyAllocation, not ReleaseInfo")
    if parse_release_tag(info.tag, info.channel) != info:
        raise ValueError("release info does not match its release tag")
    if len(info.version) > _MAX_RELEASE_TEXT or len(info.pkg_version) > _MAX_RELEASE_TEXT:
        raise ValueError(f"release identity exceeds {_MAX_RELEASE_TEXT} characters")


def _validate_digest(value: object, *, name: str = "input_digest") -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{name} must be lowercase 64-character hex")


def _nightly_date(value: object) -> date:
    if not isinstance(value, str) or not _NIGHTLY_RE.fullmatch(value):
        raise ValueError("portversion must be YYYYMMDD")
    try:
        return date(int(value[:4]), int(value[4:6]), int(value[6:]))
    except ValueError as exc:
        raise ValueError(f"invalid Nightly calendar date: {value}") from exc


def _validate_nightly_allocation(value: object) -> NightlyAllocation:
    if type(value) is not NightlyAllocation:
        raise TypeError("allocation must be NightlyAllocation")
    if value.outcome not in ("build", "unchanged"):
        raise ValueError("invalid Nightly outcome")
    _nightly_date(value.portversion)
    if type(value.portrevision) is not int or value.portrevision < 0:
        raise ValueError("portrevision must be a non-negative integer")
    expected_pkg = value.portversion if value.portrevision == 0 else f"{value.portversion}_{value.portrevision}"
    if len(value.pkg_version) > _MAX_RELEASE_TEXT:
        raise ValueError(f"Nightly package identity exceeds {_MAX_RELEASE_TEXT} characters")
    if value.pkg_version != expected_pkg or not _NIGHTLY_PKG_RE.fullmatch(value.pkg_version):
        raise ValueError("invalid Nightly package version")
    _validate_source_sha(value.source_sha)
    _validate_source_sha(value.ports_sha, name="ports_sha")
    _validate_digest(value.input_digest)
    return value


def validate_nightly_allocation(value: NightlyAllocation) -> None:
    """Require one Nightly allocation to match the date/revision contract."""
    _validate_nightly_allocation(value)


def combined_nightly_input_digest(source_sha: str, ports_sha: str, input_digest: str) -> str:
    """Return deterministic provenance digest for downstream build annotations."""
    _validate_source_sha(source_sha)
    _validate_source_sha(ports_sha, name="ports_sha")
    _validate_digest(input_digest)
    payload = "\0".join((source_sha, ports_sha, input_digest)).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def allocate_nightly(
    build_date: date,
    source_sha: str,
    ports_sha: str,
    input_digest: str,
    existing: Sequence[NightlyAllocation] = (),
) -> NightlyAllocation:
    """Allocate a monotonic date/revision Nightly identity for one full input."""
    if type(build_date) is not date:
        raise TypeError("build_date must be datetime.date")
    _validate_source_sha(source_sha)
    _validate_source_sha(ports_sha, name="ports_sha")
    _validate_digest(input_digest)
    try:
        records = tuple(existing)
    except TypeError as exc:
        raise ValueError("existing must be a sequence of NightlyAllocation") from exc

    identity = (source_sha, ports_sha, input_digest)
    by_identity: dict[tuple[str, str, str], NightlyAllocation] = {}
    by_version: dict[str, tuple[str, str, str]] = {}
    parsed: list[tuple[NightlyAllocation, date]] = []
    for record in records:
        allocation = _validate_nightly_allocation(record)
        record_identity = (allocation.source_sha, allocation.ports_sha, allocation.input_digest)
        previous = by_identity.get(record_identity)
        if previous is not None and (
            previous.portversion,
            previous.portrevision,
            previous.pkg_version,
        ) != (
            allocation.portversion,
            allocation.portrevision,
            allocation.pkg_version,
        ):
            raise ValueError("conflicting Nightly results for one input")
        version_identity = by_version.get(allocation.pkg_version)
        if version_identity is not None and version_identity != record_identity:
            raise ValueError("Nightly version collision for different inputs")
        by_identity[record_identity] = allocation
        by_version[allocation.pkg_version] = record_identity
        parsed.append((allocation, _nightly_date(allocation.portversion)))

    repeated = by_identity.get(identity)
    if repeated is not None:
        return NightlyAllocation(
            "unchanged",
            repeated.portversion,
            repeated.portrevision,
            repeated.pkg_version,
            repeated.source_sha,
            repeated.ports_sha,
            repeated.input_digest,
        )

    latest_date = max((record_date for _, record_date in parsed), default=None)
    if latest_date is not None and build_date < latest_date:
        raise ValueError("Nightly date is older than the latest allocation")
    revision = 0
    if latest_date == build_date:
        revision = max(allocation.portrevision for allocation, record_date in parsed if record_date == build_date) + 1
    portversion = f"{build_date.year:04d}{build_date.month:02d}{build_date.day:02d}"
    pkg_version = portversion if revision == 0 else f"{portversion}_{revision}"
    if pkg_version in by_version:
        raise ValueError("Nightly version collision for different inputs")
    allocation = NightlyAllocation("build", portversion, revision, pkg_version, source_sha, ports_sha, input_digest)
    return _validate_nightly_allocation(allocation)


def validate_branch(info: ReleaseInfo, branch: str) -> None:
    """Require the exact maintained release line for a tagged release."""
    if not isinstance(branch, str):
        raise ValueError(f"branch {branch!r} is unknown")
    if branch == info.release_line:
        return
    raise ValueError(f"branch {branch!r} points at {info.release_line!r}, not this release")


def _emit(info: ReleaseInfo) -> None:
    """Print eval-safe release fields for shell callers."""
    fields = (
        ("version", info.version),
        ("channel", info.channel),
        ("prerelease", str(info.prerelease).lower()),
        ("prekind", "" if info.final else info.stage),
        ("portversion", info.pkg_version),
        ("release_channel", info.channel),
        ("tag", info.tag or ""),
        ("stage", info.stage),
        ("sequence", info.sequence or ""),
        ("target_final", info.target_final or ""),
        ("release_line", info.release_line),
        ("final", str(info.final).lower()),
        ("notes_required", str(info.notes_required).lower()),
        ("github_release", info.github_release),
        ("package", info.package),
    )
    for key, value in fields:
        print(f"{key}={value}")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 2 or len(args) > 3 or not args[0] or not args[1]:
        print("error: usage: release-version.sh <tag> <channel> [branch]", file=sys.stderr)
        return 1

    tag, channel = args[:2]
    try:
        info = parse_release_tag(tag, channel)  # type: ignore[arg-type]
        if len(args) == 3:
            validate_branch(info, args[2])
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("invalid release tag"):
            print(f"error: {tag!r} is not a valid release tag", file=sys.stderr)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    _emit(info)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
