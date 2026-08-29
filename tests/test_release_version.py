"""Contextual release tag and channel contract for issue #2140."""

from __future__ import annotations

import subprocess
from dataclasses import fields, replace
from pathlib import Path
from typing import cast

import pytest

from scripts.release_version import (
    PACKAGE,
    GithubRelease,
    ReleaseInfo,
    parse_release_tag,
    validate_branch,
    validate_release_info,
)

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "release-version.sh"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["sh", str(_SCRIPT), *args], capture_output=True, text=True, check=False)


def _fields(stdout: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in stdout.splitlines() if "=" in line)


@pytest.mark.parametrize(
    ("tag", "channel", "expected"),
    [
        ("v3.2.15", "stable", ("3.2.15", "final", None, "stable", False, True, "3.2.15")),
        ("v3.2.16.a1", "testing", ("3.2.16.a1", "alpha", "1", "testing", True, False, "3.2.16.a1")),
        ("v3.2.16.b1", "testing", ("3.2.16.b1", "beta", "1", "testing", True, False, "3.2.16.b1")),
        ("v3.2.16.r1", "testing", ("3.2.16.r1", "rc", "1", "testing", True, False, "3.2.16.r1")),
        ("v4.0.0.a1", "edge", ("4.0.0.a1", "alpha", "1", "edge", True, False, "4.0.0.a1")),
    ],
)
def test_context_classifies_shared_tag_grammar(
    tag: str, channel: str, expected: tuple[str, str, str | None, str, bool, bool, str]
) -> None:
    info = parse_release_tag(tag, channel)  # type: ignore[arg-type,call-arg]
    version, _stage, _sequence, _expected_channel, _prerelease, final, _pkg_version = expected
    assert (
        info.version,
        info.stage,
        info.sequence,
        info.channel,
        info.prerelease,
        info.final,
        info.pkg_version,
    ) == expected
    assert info.tag == tag
    assert info.target_final == ".".join(version.split(".")[:3])
    assert info.release_line == f"release/{info.target_final.rsplit('.', 1)[0]}"
    assert info.package == PACKAGE
    assert info.notes_required is True
    assert info.github_release == ("final" if final else "prerelease")


@pytest.mark.parametrize(
    ("tag", "channel"),
    [
        ("v3.2.15.a1", "stable"),
        ("v3.2.15", "testing"),
        ("v4.0.0.a1", "stable"),
        ("v4.0.0.a1", "testing"),
        ("v4.0.0.b1", "testing"),
        ("v4.0.0.r1", "testing"),
        ("v3.2.16.a1", "edge"),
        ("v3.2.16.b1", "edge"),
        ("v3.2.16.r1", "edge"),
        ("v4.0.0", "edge"),
        ("v4.0.0.alpha.1", "testing"),
        ("v4.0.0.edge.20260804.1", "edge"),
        ("v4.0.0.a0", "testing"),
    ],
)
def test_context_rejects_contradictory_or_superseded_tag_shapes(tag: str, channel: str) -> None:
    with pytest.raises(ValueError):
        parse_release_tag(tag, channel)  # type: ignore[arg-type,call-arg]


@pytest.mark.parametrize(
    ("tag", "channel"),
    [
        ("v4.0.0-devel", "stable"),
        ("v4.0.0.rc1", "testing"),
        ("v4.0.0-rc.1", "testing"),
        ("v4.0.0.alpha1", "testing"),
        ("v4.0.0.alpha", "testing"),
        ("v4.0.a.1", "testing"),
        ("v4.0.0.gamma.1", "testing"),
        ("v4.0.0.pre.1", "testing"),
        ("4.0.0.a1", "testing"),
        ("v4.0.0.a1.extra", "testing"),
        ("v01.2.3", "stable"),
        ("v1.02.3", "stable"),
        ("v1.2.03", "stable"),
        ("v4.0.0.a0", "testing"),
        ("v4.0.0.a01", "testing"),
        ("v4.0.0.b00", "edge"),
        ("v4.0.0.r0", "edge"),
    ],
)
def test_strict_version_and_preview_sequence_validation(tag: str, channel: str) -> None:
    with pytest.raises(ValueError):
        parse_release_tag(tag, channel)  # type: ignore[arg-type,call-arg]


@pytest.mark.parametrize("channel", ["", "main", "devel", "nightly", "Testing", None])
def test_channel_context_is_required_and_strict(channel: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        parse_release_tag("v3.2.15", channel)  # type: ignore[arg-type,call-arg]


@pytest.mark.parametrize("tag", ["", "3.2.15", "v3.2.15\n", "v3.2.15;echo pwned", "v3.2.15.é", "v" + "1" * 129])
def test_parser_and_wrapper_fail_closed_without_assignments(tag: str) -> None:
    with pytest.raises(ValueError):
        parse_release_tag(tag, "stable")  # type: ignore[arg-type,call-arg]
    result = _run(tag, "stable")
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize(
    ("tag", "channel"),
    [
        ("v4.0.0\t", "stable"),
        ("v4.0.0;echo pwned", "stable"),
        ("v4.0.0.é", "testing"),
        ("v4.0.0.a1\n", "testing"),
        ("v" + "1" * 129, "stable"),
    ],
)
def test_hostile_wrapper_inputs_emit_no_assignments(tag: str, channel: str) -> None:
    with pytest.raises(ValueError):
        parse_release_tag(tag, channel)  # type: ignore[arg-type,call-arg]
    result = _run(tag, channel)
    assert result.returncode != 0
    assert result.stdout == ""


def test_matching_release_line_is_required_for_tagged_context() -> None:
    info = parse_release_tag("v3.2.15", "stable")  # type: ignore[arg-type,call-arg]
    validate_branch(info, "release/3.2")
    validate_branch(parse_release_tag("v3.2.16.a1", "testing"), "release/3.2")  # type: ignore[arg-type,call-arg]


@pytest.mark.parametrize("branch", ["main", "devel", "release/3.3", "feature/release", ""])
def test_wrong_or_legacy_branch_is_rejected(branch: str) -> None:
    with pytest.raises(ValueError):
        validate_branch(parse_release_tag("v3.2.15", "stable"), branch)  # type: ignore[arg-type,call-arg]


def test_wrapper_requires_explicit_channel_and_emits_contextual_fields() -> None:
    missing = _run("v3.2.15")
    assert missing.returncode != 0
    assert missing.stdout == ""

    result = _run("v3.2.16.a1", "testing", "release/3.2")
    assert result.returncode == 0, result.stderr
    assert _fields(result.stdout) == {
        "version": "3.2.16.a1",
        "channel": "testing",
        "prerelease": "true",
        "prekind": "alpha",
        "portversion": "3.2.16.a1",
        "release_channel": "testing",
        "tag": "v3.2.16.a1",
        "stage": "alpha",
        "sequence": "1",
        "target_final": "3.2.16",
        "release_line": "release/3.2",
        "final": "false",
        "notes_required": "true",
        "github_release": "prerelease",
        "package": PACKAGE,
    }


def test_wrapper_rejects_wrong_line_without_assignments() -> None:
    result = _run("v3.2.15", "stable", "release/3.3")
    assert result.returncode != 0
    assert result.stdout == ""


def test_release_info_is_frozen_and_tamper_evident() -> None:
    assert [field.name for field in fields(ReleaseInfo)] == [
        "tag",
        "version",
        "stage",
        "sequence",
        "target_final",
        "release_line",
        "channel",
        "prerelease",
        "final",
        "notes_required",
        "github_release",
        "pkg_version",
        "package",
    ]
    assert ReleaseInfo.__dataclass_params__.frozen  # type: ignore[attr-defined]
    info = parse_release_tag("v3.2.16.a1", "testing")  # type: ignore[arg-type,call-arg]
    validate_release_info(info)
    for forged in (
        replace(info, version="3.2.16.b1"),
        replace(info, channel="stable"),
        replace(info, pkg_version="3.2.16.b1"),
    ):
        with pytest.raises(ValueError):
            validate_release_info(forged)
    with pytest.raises(TypeError):
        validate_release_info(object())  # type: ignore[arg-type]


@pytest.mark.parametrize("tag,channel", [("v3.2.15", "stable"), ("v3.2.16.a1", "testing"), ("v4.0.0.r1", "edge")])
def test_every_canonical_field_tampering_is_rejected(tag: str, channel: str) -> None:
    info = parse_release_tag(tag, channel)  # type: ignore[arg-type,call-arg]
    tampered = [
        replace(info, version=info.version + ".forged"),
        replace(info, target_final="4.0.99"),
        replace(info, release_line="release/9.9"),
        replace(info, pkg_version=info.pkg_version + ".forged"),
        replace(info, sequence="2"),
        replace(info, stage="beta"),
        replace(info, final=not info.final),
        replace(info, prerelease=not info.prerelease),
        replace(info, notes_required=not info.notes_required),
        replace(info, github_release=cast(GithubRelease, "none")),
        replace(info, package="wrong"),
    ]
    for forged in tampered:
        with pytest.raises(ValueError):
            validate_release_info(forged)


def test_tagged_release_requires_exact_release_line_without_legacy_aliases() -> None:
    info = parse_release_tag("v4.0.0", "stable")  # type: ignore[arg-type,call-arg]
    validate_branch(info, "release/4.0")
    for branch in ("main", "devel", "release/4.1", "feature/release", ""):
        with pytest.raises(ValueError):
            validate_branch(info, branch)
