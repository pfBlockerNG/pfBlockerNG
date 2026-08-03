"""Parse pfBlockerNG release tags and derive their canonical release metadata."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import date
from typing import Literal

PACKAGE = "pfSense-pkg-pfBlockerNG"

Stage = Literal["final", "alpha", "beta", "rc", "edge"]
Channel = Literal["stable", "testing", "edge"]
GithubRelease = Literal["final", "prerelease"]

_CORE = r"(0|[1-9][0-9]*)"
_FINAL_RE = re.compile(rf"^v(?P<major>{_CORE})\.(?P<minor>{_CORE})\.(?P<patch>{_CORE})$")
_TESTING_RE = re.compile(
    rf"^v(?P<major>{_CORE})\.(?P<minor>{_CORE})\.(?P<patch>{_CORE})\."
    r"(?P<stage>alpha|beta|rc)\.(?P<sequence>[1-9][0-9]*)$"
)
_EDGE_RE = re.compile(
    rf"^v(?P<major>{_CORE})\.(?P<minor>{_CORE})\.(?P<patch>{_CORE})\.edge\."
    r"(?P<date>[0-9]{8})\.(?P<count>[1-9][0-9]*)$"
)


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


def _invalid(tag: str) -> ValueError:
    return ValueError(f"invalid release tag: {tag!r}")


def _check_edge_date(raw: str) -> None:
    try:
        date(int(raw[:4]), int(raw[4:6]), int(raw[6:]))
    except ValueError as exc:
        raise ValueError(f"invalid Edge calendar date: {raw}") from exc


def parse_release_tag(tag: str) -> ReleaseInfo:
    """Parse one strict release tag into canonical release metadata."""
    if not isinstance(tag, str) or not tag or len(tag) > 128 or not tag.isascii():
        raise _invalid(tag)

    match = _FINAL_RE.fullmatch(tag)
    if match:
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

    match = _TESTING_RE.fullmatch(tag)
    if match:
        major, minor, patch = (match.group(name) for name in ("major", "minor", "patch"))
        stage = match.group("stage")
        sequence = match.group("sequence")
        version = f"{major}.{minor}.{patch}"
        return ReleaseInfo(
            tag=tag,
            version=f"{version}.{stage}.{sequence}",
            stage=stage,  # type: ignore[arg-type]
            sequence=sequence,
            target_final=version,
            release_line=f"release/{major}.{minor}",
            channel="testing",
            prerelease=True,
            final=False,
            notes_required=True,
            github_release="prerelease",
            pkg_version=f"{version}.{stage}.{sequence}",
            package=PACKAGE,
        )

    match = _EDGE_RE.fullmatch(tag)
    if match:
        major, minor, patch = (match.group(name) for name in ("major", "minor", "patch"))
        edge_date = match.group("date")
        count = match.group("count")
        _check_edge_date(edge_date)
        version = f"{major}.{minor}.{patch}"
        return ReleaseInfo(
            tag=tag,
            version=f"{version}.edge.{edge_date}.{count}",
            stage="edge",
            sequence=f"{edge_date}.{count}",
            target_final=version,
            release_line=f"release/{major}.{minor}",
            channel="edge",
            prerelease=True,
            final=False,
            notes_required=True,
            github_release="prerelease",
            pkg_version=f"{version}.snapshot.1.{edge_date}.{count}",
            package=PACKAGE,
        )

    raise _invalid(tag)


def validate_branch(info: ReleaseInfo, branch: str, legacy: bool = False) -> None:
    """Require a canonical release line, with optional legacy branch aliases."""
    if not isinstance(branch, str):
        raise ValueError(f"branch {branch!r} is unknown")
    if branch == info.release_line:
        return
    if legacy and info.stage == "final" and branch == "main":
        return
    if legacy and info.channel == "testing" and branch == "devel":
        return
    raise ValueError(f"branch {branch!r} points at {info.release_line!r}, not this release")


def _emit(info: ReleaseInfo) -> None:
    """Print legacy fields first, followed by canonical fields for shell callers."""
    fields = (
        ("version", info.version),
        ("channel", "stable" if info.channel == "stable" else "devel" if info.channel == "testing" else "edge"),
        ("prerelease", str(info.prerelease).lower()),
        ("prekind", "" if info.final else info.stage),
        ("portversion", info.pkg_version),
        ("release_channel", info.channel),
        ("tag", info.tag or ""),
        ("stage", info.stage),
        ("sequence", info.sequence or ""),
        ("target_final", info.target_final),
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
    if not args or not args[0]:
        print("error: no tag given", file=sys.stderr)
        print("usage: release-version.sh <tag> [branch]", file=sys.stderr)
        return 1
    if len(args) > 2:
        print("error: usage: release-version.sh <tag> [branch]", file=sys.stderr)
        return 1

    tag = args[0]
    try:
        info = parse_release_tag(tag)
        if len(args) == 2:
            validate_branch(info, args[1], legacy=True)
    except ValueError as exc:
        if str(exc).startswith("invalid release tag") or "calendar date" in str(exc):
            print(f"error: {tag!r} is not a valid release tag", file=sys.stderr)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    _emit(info)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
