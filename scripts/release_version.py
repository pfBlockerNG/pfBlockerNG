"""Parse pfBlockerNG release tags and derive their canonical release metadata."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import date
from typing import Literal, Sequence

PACKAGE = "pfSense-pkg-pfBlockerNG"

Stage = Literal["final", "alpha", "beta", "rc", "edge", "nightly"]
Channel = Literal["stable", "testing", "edge", "nightly"]
GithubRelease = Literal["final", "prerelease", "none"]

_CORE = r"(0|[1-9][0-9]*)"
_FINAL_RE = re.compile(rf"^v(?P<major>{_CORE})\.(?P<minor>{_CORE})\.(?P<patch>{_CORE})$")
_PREVIEW_RE = re.compile(
    rf"^v(?P<major>{_CORE})\.(?P<minor>{_CORE})\.(?P<patch>{_CORE})\."
    r"(?P<stage>[abr])(?P<sequence>[1-9][0-9]*)$"
)
_BARE_VERSION_RE = re.compile(rf"^(?P<major>{_CORE})\.(?P<minor>{_CORE})\.(?P<patch>{_CORE})$")
_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SEQUENCE_RE = re.compile(r"^(?P<date>[0-9]{8})\.(?P<count>[1-9][0-9]*)$")
_MAX_RELEASE_TEXT = 128


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
class SnapshotRecord:
    source_sha: str
    result: ReleaseInfo


def _invalid(tag: str) -> ValueError:
    return ValueError(f"invalid release tag: {tag!r}")


def parse_release_tag(tag: str, channel: Channel | None = None) -> ReleaseInfo:
    """Parse one strict release tag using explicit channel context."""
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


def _parse_bare_version(final_version: str) -> tuple[str, str, str]:
    if not isinstance(final_version, str):
        raise TypeError("target_final must be str")
    if not final_version or len(final_version) > 128:
        raise ValueError(f"invalid final version: {final_version!r}")
    match = _BARE_VERSION_RE.fullmatch(final_version)
    if not match:
        raise ValueError(f"invalid final version: {final_version!r}")
    return tuple(match.group(name) for name in ("major", "minor", "patch"))  # type: ignore[return-value]


def next_patch_target(final_version: str) -> str:
    """Return the next patch target for a strict bare X.Y.Z final version."""
    major, minor, patch = _parse_bare_version(final_version)
    return f"{major}.{minor}.{int(patch) + 1}"


def _validate_source_sha(source_sha: str) -> None:
    if not isinstance(source_sha, str) or not _SHA_RE.fullmatch(source_sha):
        raise ValueError("source_sha must be lowercase 40- or 64-character hex")


def _sequence_parts(sequence: str) -> tuple[date, int]:
    if not isinstance(sequence, str):
        raise ValueError("snapshot sequence must be YYYYMMDD.N")
    match = _SEQUENCE_RE.fullmatch(sequence)
    if not match:
        raise ValueError("snapshot sequence must be YYYYMMDD.N")
    raw_date = match.group("date")
    try:
        build_date = date(int(raw_date[:4]), int(raw_date[4:6]), int(raw_date[6:]))
    except ValueError as exc:
        raise ValueError(f"invalid snapshot calendar date: {raw_date}") from exc
    return build_date, int(match.group("count"))


def _date_text(build_date: date) -> str:
    return f"{build_date.year:04d}{build_date.month:02d}{build_date.day:02d}"


def _validate_nightly_result(result: ReleaseInfo) -> None:
    major, minor, patch = _parse_bare_version(result.target_final)
    build_date, count = _sequence_parts(result.sequence or "")
    date_text = _date_text(build_date)
    expected_version = f"{result.target_final}.nightly.{date_text}.{count}"
    expected_pkg = f"{result.target_final}.snapshot.2.{date_text}.{count}"
    if result.tag is not None or result.stage != "nightly" or result.channel != "nightly":
        raise ValueError("invalid Nightly snapshot result")
    if result.release_line != "devel" or result.version != expected_version or result.pkg_version != expected_pkg:
        raise ValueError("invalid Nightly snapshot result")
    if result.target_final != f"{major}.{minor}.{patch}" or result.prerelease is not True or result.final is not False:
        raise ValueError("invalid Nightly snapshot result")
    if result.notes_required is not False or result.github_release != "none" or result.package != PACKAGE:
        raise ValueError("invalid Nightly snapshot result")


def validate_release_info(info: ReleaseInfo) -> None:
    """Require a ReleaseInfo value to be exactly one canonical release identity."""
    if type(info) is not ReleaseInfo:
        raise TypeError("release info must be ReleaseInfo")
    if info.tag is None:
        _validate_nightly_result(info)
    elif parse_release_tag(info.tag, info.channel) != info:
        raise ValueError("release info does not match its release tag")
    if len(info.version) > _MAX_RELEASE_TEXT or len(info.pkg_version) > _MAX_RELEASE_TEXT:
        raise ValueError(f"release identity exceeds {_MAX_RELEASE_TEXT} characters")


def _validate_snapshot_result(result: ReleaseInfo) -> tuple[date, int]:
    validate_release_info(result)
    if result.channel == "edge":
        return _sequence_parts(result.sequence or "")
    if result.channel == "nightly":
        return _sequence_parts(result.sequence or "")
    raise ValueError("existing records must contain Edge or Nightly snapshots")


def _snapshot_info(
    channel: Literal["edge", "nightly"],
    target_final: str,
    release_line: str,
    build_date: date,
    count: int,
) -> ReleaseInfo:
    date_text = _date_text(build_date)
    sequence = f"{date_text}.{count}"
    if channel == "edge":
        version = f"{target_final}.edge.{sequence}"
        return ReleaseInfo(
            tag=f"v{version}",
            version=version,
            stage="edge",
            sequence=sequence,
            target_final=target_final,
            release_line=release_line,
            channel="edge",
            prerelease=True,
            final=False,
            notes_required=True,
            github_release="prerelease",
            pkg_version=f"{target_final}.snapshot.1.{sequence}",
            package=PACKAGE,
        )
    return ReleaseInfo(
        tag=None,
        version=f"{target_final}.nightly.{sequence}",
        stage="nightly",
        sequence=sequence,
        target_final=target_final,
        release_line=release_line,
        channel="nightly",
        prerelease=True,
        final=False,
        notes_required=False,
        github_release="none",
        pkg_version=f"{target_final}.snapshot.2.{sequence}",
        package=PACKAGE,
    )


def generate_snapshot(
    *,
    channel: Literal["edge", "nightly"],
    target_final: str,
    release_line: str,
    source_sha: str,
    build_date: date,
    existing: Sequence[SnapshotRecord] = (),
) -> ReleaseInfo:
    """Generate a deterministic Edge or Nightly snapshot identity."""
    if channel not in ("edge", "nightly"):
        raise ValueError(f"unknown snapshot channel: {channel!r}")
    major, minor, patch = _parse_bare_version(target_final)
    expected_line = f"release/{major}.{minor}" if channel == "edge" else "devel"
    if not isinstance(release_line, str) or release_line != expected_line:
        raise ValueError(f"release line must be {expected_line!r}")
    if type(build_date) is not date:
        raise TypeError("build_date must be datetime.date")
    _validate_source_sha(source_sha)

    try:
        records = tuple(existing)
    except TypeError as exc:
        raise ValueError("existing must be a sequence of SnapshotRecord") from exc
    validated: list[tuple[SnapshotRecord, date, int]] = []
    for record in records:
        if not isinstance(record, SnapshotRecord):
            raise ValueError("existing must contain SnapshotRecord values")
        _validate_source_sha(record.source_sha)
        build_date_existing, count_existing = _validate_snapshot_result(record.result)
        validated.append((record, build_date_existing, count_existing))

    scope = (channel, target_final, release_line)
    scoped = [
        item
        for item in validated
        if (item[0].result.channel, item[0].result.target_final, item[0].result.release_line) == scope
    ]
    seen_emitted: dict[tuple[str, str], str] = {}
    for record, _, _ in validated:
        key = (record.result.version, record.result.pkg_version)
        previous_source = seen_emitted.get(key)
        if previous_source is not None and previous_source != record.source_sha:
            raise ValueError("snapshot version collision for different sources")
        seen_emitted[key] = record.source_sha

    same_source = [item for item in scoped if item[0].source_sha == source_sha]
    if same_source:
        first = same_source[0][0].result
        if any(item[0].result != first for item in same_source[1:]):
            raise ValueError("conflicting snapshot results for source")

    latest = max((item[1] for item in scoped), default=None)
    if latest is not None and build_date < latest:
        raise ValueError("snapshot date is older than latest relevant snapshot")
    if same_source:
        return same_source[0][0].result
    count = 1
    if latest == build_date:
        count = max(item[2] for item in scoped if item[1] == build_date) + 1
    candidate = _snapshot_info(channel, target_final, release_line, build_date, count)
    validate_release_info(candidate)
    return candidate


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
