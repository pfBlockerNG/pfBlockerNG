"""scripts/update-vendored-skills.py -- vendoring refresh for the mode skills.

Managed/cloud sessions load only committed .claude/skills/, never marketplace
plugins, so the ponytail/caveman skills (and their hook scripts) are vendored
and refreshed by this script. These tests pin the refresh contract against
LOCAL fixture upstreams (file:// fetches -- no network):

  - an enabled GitHub-sourced plugin's skills/<plugin>/ dir + LICENSE (+ any
    EXTRA_VENDOR_GLOBS hook scripts, upstream-relative paths preserved) are
    copied byte-identical, with an UPSTREAM provenance line naming the exact
    upstream commit and ref;
  - --ref targets ANY ref -- a tag or a commit sha (one fetch code path);
    the default for GitHub-slug repos is the latest release's tag (file://
    fixtures never touch the release API);
  - a refresh REPLACES the target dir; re-running is idempotent;
  - every skipped plugin is skipped VISIBLY (disabled, malformed key,
    non-GitHub source), hostile plugin names ('@bogus' empty segment,
    '../'-traversal) fail loudly BEFORE any path is built, symlinked upstream
    content is refused, and GIT_* env poisoning cannot redirect the fetch.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import urllib.error
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "update-vendored-skills.py"
_spec = importlib.util.spec_from_file_location("update_vendored_skills", _SCRIPT)
assert _spec is not None and _spec.loader is not None
uvs = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = uvs
_spec.loader.exec_module(uvs)


@pytest.fixture(autouse=True)
def _scrub_git_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip GIT_* vars so the fixture repos are the sole git context.

    Same rationale as test_read_version_matrix._clean_git_env(): under a git
    hook, exported GIT_DIR/GIT_WORK_TREE would point the fixtures' `git init`
    at the real repository. The script scrubs its own subprocesses (pinned by
    test_git_env_poisoning_cannot_redirect_the_fetch below).
    """
    for key in list(os.environ):
        if key.startswith("GIT_"):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture(autouse=True)
def _no_release_api(monkeypatch: pytest.MonkeyPatch) -> None:
    """file:// fixtures must never consult the GitHub release API.

    Any test that needs latest_release_tag() re-monkeypatches it explicitly;
    for everything else an unexpected call is a hard failure, pinning the
    'default resolves the release tag only for GitHub-slug repos' rule.
    """

    def _boom(repo: str) -> str:
        raise AssertionError(f"latest_release_tag unexpectedly called for {repo}")

    monkeypatch.setattr(uvs, "latest_release_tag", _boom)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _make_upstream(
    root: Path,
    plugin: str,
    *,
    skill_files: dict[str, str] | None = None,
    extra_files: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Create a one-commit fixture upstream repo; return (file:// url, HEAD sha)."""
    repo = root / f"{plugin}-upstream"
    skill_dir = repo / "skills" / plugin
    skill_dir.mkdir(parents=True)
    files = skill_files if skill_files is not None else {"SKILL.md": f"---\nname: {plugin}\n---\n\n# {plugin}\n"}
    for name, content in files.items():
        (skill_dir / name).write_text(content, encoding="utf-8")
    for rel, content in (extra_files or {}).items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (repo / "LICENSE").write_text(f"MIT License\n\nCopyright (c) 2026 {plugin} upstream\n", encoding="utf-8")

    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "test")
    _git(repo, "config", "commit.gpgsign", "false")
    # Lets the script's fetch-by-sha path work against a file:// remote, as it
    # does against GitHub (which enables allow-any-sha server-side).
    _git(repo, "config", "uploadpack.allowAnySHA1InWant", "true")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fixture upstream")
    return f"file://{repo}", _git(repo, "rev-parse", "HEAD")


def _settings_file(root: Path, plugins: dict[str, dict], enabled: dict[str, bool]) -> Path:
    settings = root / "settings.json"
    settings.write_text(json.dumps({"enabledPlugins": enabled, "extraKnownMarketplaces": plugins}), encoding="utf-8")
    return settings


def _run(settings: Path, skills: Path, *extra: str) -> int:
    return uvs.main(["--settings", str(settings), "--skills-dir", str(skills), *extra])


def test_vendors_enabled_plugin_byte_identical_with_provenance(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    url, sha = _make_upstream(tmp_path, "myplugin")
    settings = _settings_file(
        tmp_path,
        {"myplugin": {"source": {"source": "github", "repo": url}}},
        {"myplugin@myplugin": True},
    )
    skills = tmp_path / "skills"

    rc = _run(settings, skills)

    assert rc == 0, f"expected exit 0, got {rc}; output: {capsys.readouterr().out}"
    copied = (skills / "myplugin" / "SKILL.md").read_text(encoding="utf-8")
    assert copied == "---\nname: myplugin\n---\n\n# myplugin\n", f"SKILL.md not byte-identical: {copied!r}"
    licence = (skills / "myplugin" / "LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in licence, f"LICENSE not copied: {licence!r}"
    upstream = (skills / "myplugin" / "UPSTREAM").read_text(encoding="utf-8")
    assert sha in upstream and url in upstream, f"expected {url} and {sha} in provenance, got {upstream!r}"
    assert "(ref HEAD" in upstream, f"expected the fetched ref in provenance, got {upstream!r}"


def test_ref_targets_a_tag(tmp_path: Path) -> None:
    url, _ = _make_upstream(tmp_path, "myplugin", skill_files={"SKILL.md": "tagged content\n"})
    repo = tmp_path / "myplugin-upstream"
    _git(repo, "tag", "v1.0.0")
    (repo / "skills" / "myplugin" / "SKILL.md").write_text("newer content\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "post-release drift")
    tagged_sha = _git(repo, "rev-parse", "v1.0.0^{commit}")
    settings = _settings_file(
        tmp_path,
        {"myplugin": {"source": {"source": "github", "repo": url}}},
        {"myplugin@myplugin": True},
    )
    skills = tmp_path / "skills"

    assert _run(settings, skills, "--ref", "myplugin=v1.0.0") == 0

    copied = (skills / "myplugin" / "SKILL.md").read_text(encoding="utf-8")
    assert copied == "tagged content\n", f"--ref must vendor the TAGGED commit, got: {copied!r}"
    upstream = (skills / "myplugin" / "UPSTREAM").read_text(encoding="utf-8")
    assert tagged_sha in upstream and "(ref v1.0.0" in upstream, f"provenance must pin tag + sha, got {upstream!r}"


def test_ref_targets_a_commit_sha(tmp_path: Path) -> None:
    url, first_sha = _make_upstream(tmp_path, "myplugin", skill_files={"SKILL.md": "first\n"})
    repo = tmp_path / "myplugin-upstream"
    (repo / "skills" / "myplugin" / "SKILL.md").write_text("second\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "second")
    settings = _settings_file(
        tmp_path,
        {"myplugin": {"source": {"source": "github", "repo": url}}},
        {"myplugin@myplugin": True},
    )
    skills = tmp_path / "skills"

    assert _run(settings, skills, "--ref", f"myplugin={first_sha}") == 0

    copied = (skills / "myplugin" / "SKILL.md").read_text(encoding="utf-8")
    assert copied == "first\n", f"--ref must vendor the exact sha, got: {copied!r}"
    assert first_sha in (skills / "myplugin" / "UPSTREAM").read_text(encoding="utf-8")


def test_extra_vendor_globs_copy_hook_scripts_with_relative_paths(tmp_path: Path) -> None:
    url, _ = _make_upstream(
        tmp_path,
        "myplugin",
        extra_files={"hooks/a.js": "// hook a\n", "hooks/b.js": "// hook b\n", "hooks/skipme.sh": "#!/bin/sh\n"},
    )
    skills = tmp_path / "skills"

    uvs.vendor_one("myplugin", url, skills, None, ("hooks/*.js",))

    assert (skills / "myplugin" / "hooks" / "a.js").read_text(encoding="utf-8") == "// hook a\n"
    assert (skills / "myplugin" / "hooks" / "b.js").is_file()
    assert not (skills / "myplugin" / "hooks" / "skipme.sh").exists(), "only the glob's matches may be vendored"


def test_missing_extra_glob_fails_loudly(tmp_path: Path) -> None:
    url, _ = _make_upstream(tmp_path, "myplugin")

    with pytest.raises(FileNotFoundError, match="src/hooks"):
        uvs.vendor_one("myplugin", url, tmp_path / "skills", None, ("src/hooks/*.js",))


def test_latest_release_tag_parses_the_github_response(monkeypatch: pytest.MonkeyPatch) -> None:
    # Direct unit test of the resolver on a FRESH module instance (the autouse
    # fixture stubs the shared module's attribute).
    captured: dict[str, Any] = {}

    class _FakeResponse(io.BytesIO):
        def __enter__(self) -> _FakeResponse:
            return self

        def __exit__(self, *exc: object) -> None:
            self.close()

    def fake_urlopen(request: Any, timeout: float = 0) -> _FakeResponse:
        captured["url"] = request.full_url
        return _FakeResponse(b'{"tag_name": "v9.9.9"}')

    fresh = _real_latest_release_tag()
    monkeypatch.setattr(sys.modules[fresh.__module__].urllib.request, "urlopen", fake_urlopen)

    result = fresh("owner/name")

    assert result == "v9.9.9", f"expected the release tag_name, got {result!r}"
    assert captured["url"] == "https://api.github.com/repos/owner/name/releases/latest"


def _real_latest_release_tag() -> Any:
    """The un-stubbed latest_release_tag (the autouse fixture replaces the module attr)."""
    fresh_spec = importlib.util.spec_from_file_location("uvs_fresh", _SCRIPT)
    assert fresh_spec is not None and fresh_spec.loader is not None
    fresh = importlib.util.module_from_spec(fresh_spec)
    sys.modules[fresh_spec.name] = fresh
    fresh_spec.loader.exec_module(fresh)
    return fresh.latest_release_tag


def test_latest_release_tag_missing_release_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: Any, timeout: float = 0) -> Any:
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", None, None)  # type: ignore[arg-type]

    fresh = _real_latest_release_tag()
    monkeypatch.setattr(sys.modules[fresh.__module__].urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match=r"--ref"):
        fresh("owner/name")


def test_refresh_replaces_target_removing_stale_files(tmp_path: Path) -> None:
    url, _ = _make_upstream(tmp_path, "myplugin")
    settings = _settings_file(
        tmp_path,
        {"myplugin": {"source": {"source": "github", "repo": url}}},
        {"myplugin@myplugin": True},
    )
    skills = tmp_path / "skills"
    stale = skills / "myplugin" / "OBSOLETE.md"
    stale.parent.mkdir(parents=True)
    stale.write_text("left over from an older upstream layout\n", encoding="utf-8")

    assert _run(settings, skills) == 0
    assert not stale.exists(), "refresh must REPLACE the target dir -- stale files may not survive"
    assert (skills / "myplugin" / "SKILL.md").is_file()


def test_rerun_against_unchanged_upstream_is_idempotent(tmp_path: Path) -> None:
    url, _ = _make_upstream(tmp_path, "myplugin")
    settings = _settings_file(
        tmp_path,
        {"myplugin": {"source": {"source": "github", "repo": url}}},
        {"myplugin@myplugin": True},
    )
    skills = tmp_path / "skills"

    assert _run(settings, skills) == 0
    first = {p.relative_to(skills): p.read_bytes() for p in sorted(skills.rglob("*")) if p.is_file()}
    assert _run(settings, skills) == 0
    second = {p.relative_to(skills): p.read_bytes() for p in sorted(skills.rglob("*")) if p.is_file()}

    assert first == second, f"re-run must be a byte-identical no-op; diff keys: {set(first) ^ set(second)}"


def test_every_skipped_plugin_is_skipped_visibly(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    url, _ = _make_upstream(tmp_path, "myplugin")
    settings = _settings_file(
        tmp_path,
        {
            "myplugin": {"source": {"source": "github", "repo": url}},
            "disabledone": {"source": {"source": "github", "repo": url}},
            "dirsourced": {"source": {"source": "directory", "path": "/somewhere"}},
        },
        {
            "myplugin@myplugin": True,
            "disabledone@disabledone": False,
            "dirsourced@dirsourced": True,
            "notakey": True,
        },
    )
    skills = tmp_path / "skills"

    rc = _run(settings, skills)

    assert rc == 0
    assert (skills / "myplugin").is_dir()
    assert not (skills / "disabledone").exists(), "a disabled plugin must not be vendored"
    assert not (skills / "dirsourced").exists(), "a directory-source marketplace has no upstream to vendor"
    out = capsys.readouterr().out
    assert "SKIP disabledone: disabled" in out, f"a disabled plugin must be skipped VISIBLY, got: {out!r}"
    assert "SKIP dirsourced" in out, f"directory-source skip must be visible, got: {out!r}"
    assert "SKIP 'notakey'" in out, f"a malformed enabledPlugins key must be skipped visibly, got: {out!r}"


@pytest.mark.parametrize("hostile_key", ["@bogus", "../escape@mp", "a/b@mp"])
def test_hostile_plugin_names_fail_loudly_before_any_path_is_built(tmp_path: Path, hostile_key: str) -> None:
    # '@bogus' yields an EMPTY plugin segment -- skills_dir / '' resolves to the
    # skills dir itself, which a refresh would rmtree; '../'-shaped names escape
    # it. Both must die in validation, never reach the filesystem (#931 review).
    settings = _settings_file(
        tmp_path,
        {"mp": {"source": {"source": "github", "repo": "owner/repo"}}},
        {hostile_key: True},
    )

    with pytest.raises(ValueError, match="unsafe plugin name"):
        _run(settings, tmp_path / "skills")


def test_symlinked_upstream_content_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside-secret"
    outside.write_text("must never be vendored\n", encoding="utf-8")
    url, _ = _make_upstream(tmp_path, "myplugin")
    repo = tmp_path / "myplugin-upstream"
    (repo / "skills" / "myplugin" / "evil.md").symlink_to(outside)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add symlink")

    with pytest.raises(ValueError, match="symlink"):
        uvs.vendor_one("myplugin", url, tmp_path / "skills", None)

    assert not (tmp_path / "skills" / "myplugin").exists(), "refusal must happen before any copy"


def test_git_env_poisoning_cannot_redirect_the_fetch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    url, sha = _make_upstream(tmp_path, "myplugin")
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    _git(decoy, "init", "-q", "-b", "main")
    monkeypatch.setenv("GIT_DIR", str(decoy / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(decoy))
    skills = tmp_path / "skills"

    uvs.vendor_one("myplugin", url, skills, None)

    upstream = (skills / "myplugin" / "UPSTREAM").read_text(encoding="utf-8")
    assert sha in upstream, f"GIT_DIR poisoning must not redirect the fetch; provenance: {upstream!r}"


def test_unknown_ref_plugin_is_a_nonzero_exit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    url, _ = _make_upstream(tmp_path, "myplugin")
    settings = _settings_file(
        tmp_path,
        {"myplugin": {"source": {"source": "github", "repo": url}}},
        {"myplugin@myplugin": True},
    )

    rc = _run(settings, tmp_path / "skills", "--ref", "nosuch=v1.0.0")

    assert rc == 1, "--ref for an unknown plugin must fail loudly"
    assert "nosuch" in capsys.readouterr().err


def test_bad_ref_spec_is_a_nonzero_exit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    settings = _settings_file(tmp_path, {}, {})

    rc = _run(settings, tmp_path / "skills", "--ref", "justaword")

    assert rc == 1
    assert "PLUGIN=REF" in capsys.readouterr().err


def test_no_enabled_github_plugins_is_a_nonzero_exit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    settings = _settings_file(tmp_path, {}, {})

    rc = _run(settings, tmp_path / "skills")

    assert rc == 1, "an empty plugin set must fail loudly, never silently vendor nothing"
    assert "found none" in capsys.readouterr().err
