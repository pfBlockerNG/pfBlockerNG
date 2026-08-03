"""Behaviour guard for the release tag/version scheme (scripts/release-version.sh).

This is the single source of truth that `release.yml` (publish gating, PORTVERSION
bump) and `.githooks/pre-push` (client-side tag enforcement) both consume, so it
is pinned here directly rather than re-deriving the regex in each consumer.

Scheme:
  * vX.Y.Z                          -> STABLE release, cut from `main` only
  * vX.Y.Z.alpha.N/.beta.N/.rc.N    -> ALPHA/BETA/RC prerelease, cut from `devel` only

The script classifies a tag into version/channel/prerelease/prekind/portversion,
rejects malformed tags, and (when a branch is supplied) enforces branch<->channel.
"""

from __future__ import annotations

import subprocess
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "release-version.sh"


def _api() -> tuple[Any, Any, Any, Any]:
    """Load the public Python API only in tests that exercise it directly."""
    from scripts.release_version import PACKAGE, ReleaseInfo, parse_release_tag, validate_branch

    return PACKAGE, ReleaseInfo, parse_release_tag, validate_branch


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    """Invoke the classifier script with the given args, capturing stdout/stderr/exit."""
    return subprocess.run(
        ["sh", str(_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _fields(stdout: str) -> dict[str, str]:
    """Parse the script's ``KEY=VALUE`` stdout lines into a dict."""
    return dict(line.split("=", 1) for line in stdout.splitlines() if "=" in line)


# (tag, branch, expected channel/prerelease/prekind/portversion)
_VALID = [
    ("v4.0.0.alpha.1", "devel", "devel", "true", "alpha", "4.0.0.alpha.1"),
    ("v4.0.0.alpha.2", "devel", "devel", "true", "alpha", "4.0.0.alpha.2"),
    ("v4.0.0.beta.1", "devel", "devel", "true", "beta", "4.0.0.beta.1"),
    ("v4.0.0.rc.1", "devel", "devel", "true", "rc", "4.0.0.rc.1"),
    ("v4.0.0.rc.12", "devel", "devel", "true", "rc", "4.0.0.rc.12"),
    ("v4.0.0", "main", "stable", "false", "", "4.0.0"),
    ("v10.20.30", "main", "stable", "false", "", "10.20.30"),
    # No branch context (dry-run): channel inferred from the tag shape, no branch check.
    ("v4.1.0.alpha.3", "", "devel", "true", "alpha", "4.1.0.alpha.3"),
    ("v4.1.0", "", "stable", "false", "", "4.1.0"),
]


@pytest.mark.parametrize("tag,branch,channel,prerelease,prekind,portversion", _VALID)
def test_valid_tag_classification(
    tag: str, branch: str, channel: str, prerelease: str, prekind: str, portversion: str
) -> None:
    """A well-formed tag classifies into the expected channel/prerelease/PORTVERSION."""
    args = [tag, branch] if branch else [tag]
    res = _run(*args)
    assert res.returncode == 0, res.stderr
    f = _fields(res.stdout)
    assert f["version"] == tag[1:]
    assert f["channel"] == channel
    assert f["prerelease"] == prerelease
    assert f["prekind"] == prekind
    # PORTVERSION must be pkg-safe (no '-', the pkg name/version separator) and == version.
    assert f["portversion"] == portversion
    assert "-" not in f["portversion"]


_MALFORMED = [
    "v4.0.0-devel",  # legacy suffix scheme — no longer valid
    "v4.0.0.a1",  # legacy short stage form — no longer valid
    "v4.0.0.b1",  # legacy short stage form — no longer valid
    "v4.0.0.rc1",  # legacy short stage form (rc without the dot+seq) — no longer valid
    "v4.0.0-rc.1",  # dash, not the dotted .rc.N form
    "v4.0.0.alpha1",  # stage word not dot-separated from the sequence
    "v4.0.0.alpha",  # stage word without a sequence number
    "v4.0.a.1",  # only two numeric components
    "v4.0.0.gamma.1",  # unknown stage word (not alpha|beta|rc)
    "v4.0.0.pre.1",  # 'pre' is pkg-recognized but not part of our scheme
    "4.0.0.alpha.1",  # missing leading v
    "v4.0.0.alpha.1.1",  # trailing junk after the sequence
    "v01.2.3",  # leading zero in a version component (not strict semver)
    "v1.02.3",  # leading zero in the minor component
    "v1.2.03",  # leading zero in the patch component
    "v4.0.0.alpha.0",  # prerelease sequence must be >= 1
    "v4.0.0.alpha.01",  # leading zero in the prerelease sequence
]


@pytest.mark.parametrize("tag", _MALFORMED)
def test_malformed_tag_rejected(tag: str) -> None:
    """A tag that does not match either form is rejected with a non-zero exit."""
    res = _run(tag)
    assert res.returncode != 0
    assert "not a valid release tag" in res.stderr


def test_empty_tag_rejected() -> None:
    """No tag argument is a usage error."""
    res = _run()
    assert res.returncode != 0
    assert "no tag given" in res.stderr


# Branch<->channel mismatches: a prerelease may only come from devel, a stable
# only from main. The opposite pairing must fail (the before/after of the gate).
@pytest.mark.parametrize(
    "tag,good_branch,bad_branch",
    [
        ("v4.0.0.alpha.1", "devel", "main"),  # prerelease belongs on devel, not main
        ("v4.0.0", "main", "devel"),  # stable belongs on main, not devel
    ],
)
def test_branch_channel_enforcement(tag: str, good_branch: str, bad_branch: str) -> None:
    """The SAME tag passes on its correct branch and is rejected on the wrong one."""
    ok = _run(tag, good_branch)
    assert ok.returncode == 0, ok.stderr

    bad = _run(tag, bad_branch)
    assert bad.returncode != 0
    assert "points at" in bad.stderr or "points to" in bad.stderr


def test_ordering_documented_matches_pkg_semantics() -> None:
    """Sanity: the stage forms classify so their PORTVERSIONs order alpha<beta<rc<stable.

    FreeBSD pkg orders 4.0.0.alpha.1 < 4.0.0.beta.1 < 4.0.0.rc.1 < 4.0.0 natively
    (a component starting with a letter gets an implicit leading -1, so any
    .alpha/.beta/.rc sorts below the bare release; the keyword weight alpha<beta<rc
    breaks ties). This only asserts the script emits those exact PORTVERSION strings;
    the ordering itself is a pkg property, validated live by the repo-install smoke.
    """
    versions = [
        _fields(_run(t).stdout)["portversion"] for t in ("v4.0.0.alpha.1", "v4.0.0.beta.1", "v4.0.0.rc.1", "v4.0.0")
    ]
    assert versions == ["4.0.0.alpha.1", "4.0.0.beta.1", "4.0.0.rc.1", "4.0.0"]


def test_release_info_public_shape_is_frozen() -> None:
    """The parser result exposes the canonical release contract, immutably."""
    PACKAGE, ReleaseInfo, _, _ = _api()
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
    assert PACKAGE == "pfSense-pkg-pfBlockerNG"


@pytest.mark.parametrize(
    "tag,expected",
    [
        (
            "v4.0.0",
            {
                "stage": "final",
                "sequence": None,
                "target_final": "4.0.0",
                "release_line": "release/4.0",
                "channel": "stable",
                "prerelease": False,
                "final": True,
                "notes_required": True,
                "github_release": "final",
                "pkg_version": "4.0.0",
            },
        ),
        (
            "v4.0.0.alpha.1",
            {
                "stage": "alpha",
                "sequence": "1",
                "target_final": "4.0.0",
                "release_line": "release/4.0",
                "channel": "testing",
                "prerelease": True,
                "final": False,
                "notes_required": True,
                "github_release": "prerelease",
                "pkg_version": "4.0.0.alpha.1",
            },
        ),
        (
            "v4.0.0.beta.12",
            {
                "stage": "beta",
                "sequence": "12",
                "target_final": "4.0.0",
                "release_line": "release/4.0",
                "channel": "testing",
                "prerelease": True,
                "final": False,
                "notes_required": True,
                "github_release": "prerelease",
                "pkg_version": "4.0.0.beta.12",
            },
        ),
        (
            "v4.0.0.rc.1",
            {
                "stage": "rc",
                "sequence": "1",
                "target_final": "4.0.0",
                "release_line": "release/4.0",
                "channel": "testing",
                "prerelease": True,
                "final": False,
                "notes_required": True,
                "github_release": "prerelease",
                "pkg_version": "4.0.0.rc.1",
            },
        ),
        (
            "v4.0.0.edge.20240229.3",
            {
                "stage": "edge",
                "sequence": "20240229.3",
                "target_final": "4.0.0",
                "release_line": "release/4.0",
                "channel": "edge",
                "prerelease": True,
                "final": False,
                "notes_required": True,
                "github_release": "prerelease",
                "pkg_version": "4.0.0.snapshot.1.20240229.3",
            },
        ),
    ],
)
def test_parse_release_tag_derives_canonical_release_info(tag: str, expected: dict[str, object]) -> None:
    """Stable, Testing, and Edge tags map to one canonical result shape."""
    PACKAGE, _, parse_release_tag, _ = _api()
    info = parse_release_tag(tag)
    assert info.tag == tag
    assert info.version == tag[1:]
    for field, value in expected.items():
        assert getattr(info, field) == value, f"{field}: expected {value!r}, got {getattr(info, field)!r}"
    assert info.package == PACKAGE


@pytest.mark.parametrize(
    "tag,branch,legacy",
    [
        ("v4.0.0", "release/4.0", False),
        ("v4.0.0.alpha.1", "release/4.0", False),
        ("v4.0.0.edge.20240229.3", "release/4.0", False),
        ("v4.0.0", "main", True),
        ("v4.0.0.alpha.1", "devel", True),
    ],
)
def test_validate_branch_accepts_canonical_and_legacy_contexts(tag: str, branch: str, legacy: bool) -> None:
    """Canonical release lines admit every channel; legacy aliases are opt-in."""
    _, _, parse_release_tag, validate_branch = _api()
    validate_branch(parse_release_tag(tag), branch, legacy=legacy)


@pytest.mark.parametrize(
    "tag,branch,legacy",
    [
        ("v4.0.0", "release/4.1", False),
        ("v4.0.0", "main", False),
        ("v4.0.0.alpha.1", "devel", False),
        ("v4.0.0.alpha.1", "main", True),
        ("v4.0.0", "devel", True),
        ("v4.0.0.edge.20240229.3", "main", True),
        ("v4.0.0", "feature/release", True),
    ],
)
def test_validate_branch_rejects_wrong_unknown_and_cross_legacy_contexts(tag: str, branch: str, legacy: bool) -> None:
    """Branch admission fails closed for wrong, unknown, and Edge legacy branches."""
    _, _, parse_release_tag, validate_branch = _api()
    with pytest.raises(ValueError):
        validate_branch(parse_release_tag(tag), branch, legacy=legacy)


@pytest.mark.parametrize(
    "tag",
    [
        "",
        "4.0.0",
        "v4.0.0.alpha.0",
        "v4.0.0.alpha.01",
        "v4.0.0.beta.00",
        "v4.0.0.rc.0",
        "v4.0.0.edge.20230229.1",
        "v4.0.0.edge.20240229.0",
        "v4.0.0.edge.20240229.01",
        "v4.0.0.edge.2024022.1",
        "v4.0.0.pre.1",
        "v4.0.0.gamma.1",
        "v4.0.0.alpha.1.extra",
        "v4.0.0\t",
        "v4.0.0;echo pwned",
        "v4.0.0.é",
        "v" + "1" * 129,
    ],
)
def test_parser_and_wrapper_reject_hostile_tags_without_assignments(tag: str) -> None:
    """Malformed, unsafe, non-ASCII, and oversized input produces no shell assignments."""
    _, _, parse_release_tag, _ = _api()
    with pytest.raises(ValueError):
        parse_release_tag(tag)
    result = _run(tag)
    assert result.returncode != 0
    assert result.stdout == ""


def test_wrapper_emits_canonical_keys_and_accepts_release_branch() -> None:
    """The shell facade preserves legacy keys and appends canonical parser fields."""
    result = _run("v4.0.0.edge.20240229.3", "release/4.0")
    assert result.returncode == 0, result.stderr
    fields_out = _fields(result.stdout)
    assert fields_out == {
        "version": "4.0.0.edge.20240229.3",
        "channel": "edge",
        "prerelease": "true",
        "prekind": "edge",
        "portversion": "4.0.0.snapshot.1.20240229.3",
        "release_channel": "edge",
        "tag": "v4.0.0.edge.20240229.3",
        "stage": "edge",
        "sequence": "20240229.3",
        "target_final": "4.0.0",
        "release_line": "release/4.0",
        "final": "false",
        "notes_required": "true",
        "github_release": "prerelease",
        "package": "pfSense-pkg-pfBlockerNG",
    }


@pytest.mark.parametrize(
    "tag,branch",
    [("v4.0.0", "release/4.1"), ("v4.0.0", "feature/release"), ("v4.0.0.edge.20240229.3", "main")],
)
def test_wrapper_rejects_wrong_or_unknown_branches_without_assignments(tag: str, branch: str) -> None:
    """Wrapper branch validation uses legacy compatibility only where explicitly allowed."""
    result = _run(tag, branch)
    assert result.returncode != 0
    assert result.stdout == ""
