"""Parse pfBlockerNG release tags and derive their canonical release metadata."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
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
_NIGHTLY_VERSION_RE = re.compile(r"^(?P<timestamp>[0-9]{14})\.(?P<source_sha>[0-9a-f]{7})$")
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


@dataclass(frozen=True)
class ReleaseTagCandidate:
    """A validated tag and the ancestry facts needed for base selection."""

    tag: str
    info: ReleaseInfo
    primary: Channel
    on_source_line: bool
    ancestor_of_current: bool


def _invalid(tag: str) -> ValueError:
    return ValueError(f"invalid release tag: {tag!r}")


def derive_destinations(
    tag: str,
    *,
    branch: str,
    ordered_tags: Sequence[str] = (),
    tag_branches: Mapping[str, str] | None = None,
) -> tuple[Channel, ...]:
    """Derive the ordered catalogue tuple for one release tag.

    Unconditional fan-out (issue #2251): every channel catalogue strictly contains
    its slower channels' files (edge >= testing >= stable), so the destination tuple
    depends only on the current tag's own shape, never on sibling tags. `ordered_tags`
    stays in the signature for caller stability; it is no longer consulted.
    """
    major, minor, patch, stage, _sequence = _tag_shape(tag)
    release_line = f"release/{major}.{minor}"
    if branch != release_line:
        raise ValueError(f"current tag {tag!r} is not on {release_line!r}")
    branches = tag_branches or {}
    if tag in branches and branches[tag] != release_line:
        raise ValueError(f"current tag {tag!r} is not on {release_line!r}")
    if stage is not None and patch == "0":
        return ("edge",)
    if stage is not None:
        return ("testing", "edge")
    return ("stable", "testing", "edge")


def derive_destinations_from_git(
    tag: str,
    branch: str,
    repo: str | Path = ".",
    *,
    current_commit: str | None = None,
) -> tuple[Channel, ...]:
    """Validate the current tag against git state, then derive its unconditional destinations."""
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

    def has_exact_channel_trailer(candidate: str, expected: Channel) -> bool:
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

    tag_commit = git_optional("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    if current_commit and tag_commit and current_commit != tag_commit:
        raise ValueError(f"current tag {tag!r} does not match the selected source commit")
    # Gate on the ref existing, not on the peel: an annotated tag may point at a
    # non-commit object, and skipping these checks then accepts a mistagged release.
    tag_type = git_optional("cat-file", "-t", f"refs/tags/{tag}")
    if tag_type:
        expected_channel: Channel = primary_channel_for_tag(tag)
        if tag_type != "tag":
            raise ValueError(f"current tag {tag!r} must be an annotated tag")
        if not tag_commit:
            raise ValueError(f"current tag {tag!r} does not point at a commit")
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

    # Unconditional fan-out (issue #2251): destinations depend only on the current
    # tag's own shape, validated above (branch, annotation, trailer, ancestry).
    # No other tag in the repository can change the outcome, so there is nothing
    # left to scan for.
    return derive_destinations(tag, branch=branch)


def primary_channel_for_tag(tag: str) -> Channel:
    """Return the channel required by a tag's primary release trailer."""
    _major, _minor, patch, stage, _sequence = _tag_shape(tag)
    if stage is None:
        return "stable"
    return "edge" if patch == "0" else "testing"


def _release_order(info: ReleaseInfo) -> tuple[int, int, int, int, int]:
    major, minor, patch = (int(part) for part in info.target_final.split("."))
    stage_rank = {"alpha": 0, "beta": 1, "rc": 2, "final": 3}[info.stage]
    return (major, minor, patch, stage_rank, int(info.sequence or 0))


def _release_family(info: ReleaseInfo) -> tuple[int, int]:
    major, minor = info.release_line.removeprefix("release/").split(".")
    return int(major), int(minor)


def select_previous_release_tag(
    current_tag: str,
    channel: Channel,
    candidates: Sequence[ReleaseTagCandidate],
) -> str | None:
    """Select a family-scoped notes base from validated tag/ancestry facts."""
    current = parse_release_tag(current_tag, channel)
    primary = primary_channel_for_tag(current_tag)
    allowed = {
        "stable": {"stable"},
        "testing": {"stable", "testing"},
        "edge": {"stable", "edge"},
    }[primary]
    current_family = _release_family(current)
    current_order = _release_order(current)

    same_family = [
        candidate
        for candidate in candidates
        if candidate.tag != current_tag
        and candidate.info.release_line == current.release_line
        and candidate.primary in allowed
        and candidate.on_source_line
        and candidate.ancestor_of_current
        and _release_order(candidate.info) < current_order
    ]
    if same_family:
        return max(same_family, key=lambda candidate: _release_order(candidate.info)).tag

    if primary not in {"stable", "edge"}:
        return None
    previous_family_stables = [
        candidate
        for candidate in candidates
        if candidate.primary == "stable"
        and candidate.on_source_line
        and candidate.ancestor_of_current
        and _release_family(candidate.info) < current_family
    ]
    if not previous_family_stables:
        return None
    return max(
        previous_family_stables,
        key=lambda candidate: (_release_family(candidate.info), _release_order(candidate.info)),
    ).tag


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
        expected_channel: Channel = "edge" if patch == "0" else "testing"
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
        raise ValueError("Nightly does not use ReleaseInfo")
    if parse_release_tag(info.tag, info.channel) != info:
        raise ValueError("release info does not match its release tag")
    if len(info.version) > _MAX_RELEASE_TEXT or len(info.pkg_version) > _MAX_RELEASE_TEXT:
        raise ValueError(f"release identity exceeds {_MAX_RELEASE_TEXT} characters")


def _validate_digest(value: object, *, name: str = "input_digest") -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{name} must be lowercase 64-character hex")


def validate_nightly_version(value: object, *, source_sha: str | None = None) -> str:
    """Validate one stateless UTC-timestamp and source-commit identity."""
    if not isinstance(value, str) or len(value) > _MAX_RELEASE_TEXT:
        raise ValueError("Nightly version must be YYYYMMDDHHMMSS.<7-character source SHA>")
    match = _NIGHTLY_VERSION_RE.fullmatch(value)
    if match is None:
        raise ValueError("Nightly version must be YYYYMMDDHHMMSS.<7-character source SHA>")
    try:
        datetime.strptime(match.group("timestamp"), "%Y%m%d%H%M%S")
    except ValueError as exc:
        raise ValueError(f"invalid Nightly UTC timestamp: {match.group('timestamp')}") from exc
    version_sha = match.group("source_sha")
    if source_sha is not None:
        _validate_source_sha(source_sha)
        if version_sha != source_sha[:7]:
            raise ValueError("Nightly version source SHA does not match pinned source SHA")
    return value


def combined_nightly_input_digest(source_sha: str, ports_sha: str, input_digest: str) -> str:
    """Return deterministic provenance digest for downstream build annotations."""
    _validate_source_sha(source_sha)
    _validate_source_sha(ports_sha, name="ports_sha")
    _validate_digest(input_digest)
    payload = "\0".join((source_sha, ports_sha, input_digest)).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


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
