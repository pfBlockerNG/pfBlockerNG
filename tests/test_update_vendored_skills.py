"""scripts/update-vendored-skills.py -- vendoring refresh for the mode skills.

Managed/cloud sessions load only committed .claude/skills/, never marketplace
plugins, so the ponytail/caveman skills are vendored and refreshed by this
script. These tests pin the refresh contract against LOCAL fixture upstreams
(file:// clones -- no network):

  - an enabled GitHub-sourced plugin's skills/<plugin>/ dir + LICENSE are
    copied byte-identical, with an UPSTREAM provenance line naming the exact
    upstream commit;
  - a refresh REPLACES the target dir (stale files from an older upstream
    layout do not survive);
  - re-running against an unchanged upstream is idempotent;
  - a disabled plugin and a non-GitHub (directory-source) marketplace are
    skipped, an upstream without skills/<plugin>/ fails loudly, and an empty
    plugin set is a non-zero exit (never a silent no-op).
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

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
    hook, exported GIT_DIR/GIT_WORK_TREE would point the script's `git clone`
    and the fixtures' `git init` at the real repository.
    """
    for key in list(os.environ):
        if key.startswith("GIT_"):
            monkeypatch.delenv(key, raising=False)


def _make_upstream(root: Path, plugin: str, *, skill_files: dict[str, str] | None = None) -> tuple[str, str]:
    """Create a one-commit fixture upstream repo; return (file:// url, HEAD sha)."""
    repo = root / f"{plugin}-upstream"
    skill_dir = repo / "skills" / plugin
    skill_dir.mkdir(parents=True)
    files = skill_files if skill_files is not None else {"SKILL.md": f"---\nname: {plugin}\n---\n\n# {plugin}\n"}
    for name, content in files.items():
        (skill_dir / name).write_text(content, encoding="utf-8")
    (repo / "LICENSE").write_text(f"MIT License\n\nCopyright (c) 2026 {plugin} upstream\n", encoding="utf-8")

    def _git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()

    _git("init", "-q", "-b", "main")
    _git("config", "user.email", "test@example.com")
    _git("config", "user.name", "test")
    _git("config", "commit.gpgsign", "false")
    _git("add", "-A")
    _git("commit", "-q", "-m", "fixture upstream")
    return f"file://{repo}", _git("rev-parse", "HEAD")


def _settings_file(root: Path, plugins: dict[str, dict], enabled: dict[str, bool]) -> Path:
    settings = root / "settings.json"
    settings.write_text(json.dumps({"enabledPlugins": enabled, "extraKnownMarketplaces": plugins}), encoding="utf-8")
    return settings


def test_vendors_enabled_plugin_byte_identical_with_provenance(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    url, sha = _make_upstream(tmp_path, "ponytail")
    settings = _settings_file(
        tmp_path,
        {"ponytail": {"source": {"source": "github", "repo": url}}},
        {"ponytail@ponytail": True},
    )
    skills = tmp_path / "skills"

    rc = uvs.main(["--settings", str(settings), "--skills-dir", str(skills)])

    assert rc == 0, f"expected exit 0, got {rc}; output: {capsys.readouterr().out}"
    copied = (skills / "ponytail" / "SKILL.md").read_text(encoding="utf-8")
    assert copied == "---\nname: ponytail\n---\n\n# ponytail\n", f"SKILL.md not byte-identical: {copied!r}"
    licence = (skills / "ponytail" / "LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in licence, f"LICENSE not copied: {licence!r}"
    upstream = (skills / "ponytail" / "UPSTREAM").read_text(encoding="utf-8")
    assert sha in upstream and url in upstream, f"expected {url} and {sha} in provenance, got {upstream!r}"


def test_refresh_replaces_target_removing_stale_files(tmp_path: Path) -> None:
    url, _ = _make_upstream(tmp_path, "caveman")
    settings = _settings_file(
        tmp_path,
        {"caveman": {"source": {"source": "github", "repo": url}}},
        {"caveman@caveman": True},
    )
    skills = tmp_path / "skills"
    stale = skills / "caveman" / "OBSOLETE.md"
    stale.parent.mkdir(parents=True)
    stale.write_text("left over from an older upstream layout\n", encoding="utf-8")

    rc = uvs.main(["--settings", str(settings), "--skills-dir", str(skills)])

    assert rc == 0
    assert not stale.exists(), "refresh must REPLACE the target dir -- stale files may not survive"
    assert (skills / "caveman" / "SKILL.md").is_file()


def test_rerun_against_unchanged_upstream_is_idempotent(tmp_path: Path) -> None:
    url, _ = _make_upstream(tmp_path, "ponytail")
    settings = _settings_file(
        tmp_path,
        {"ponytail": {"source": {"source": "github", "repo": url}}},
        {"ponytail@ponytail": True},
    )
    skills = tmp_path / "skills"

    assert uvs.main(["--settings", str(settings), "--skills-dir", str(skills)]) == 0
    first = {p.relative_to(skills): p.read_bytes() for p in sorted(skills.rglob("*")) if p.is_file()}
    assert uvs.main(["--settings", str(settings), "--skills-dir", str(skills)]) == 0
    second = {p.relative_to(skills): p.read_bytes() for p in sorted(skills.rglob("*")) if p.is_file()}

    assert first == second, f"re-run must be a byte-identical no-op; diff keys: {set(first) ^ set(second)}"


def test_disabled_plugin_and_directory_source_are_skipped(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    url, _ = _make_upstream(tmp_path, "ponytail")
    settings = _settings_file(
        tmp_path,
        {
            "ponytail": {"source": {"source": "github", "repo": url}},
            "disabledone": {"source": {"source": "github", "repo": url}},
            "dirsourced": {"source": {"source": "directory", "path": "/somewhere"}},
        },
        {"ponytail@ponytail": True, "disabledone@disabledone": False, "dirsourced@dirsourced": True},
    )
    skills = tmp_path / "skills"

    rc = uvs.main(["--settings", str(settings), "--skills-dir", str(skills)])

    assert rc == 0
    assert (skills / "ponytail").is_dir()
    assert not (skills / "disabledone").exists(), "a disabled plugin must not be vendored"
    assert not (skills / "dirsourced").exists(), "a directory-source marketplace has no upstream to vendor"
    out = capsys.readouterr().out
    assert "SKIP dirsourced" in out, f"directory-source skip must be visible, got: {out!r}"


def test_upstream_without_the_skill_dir_fails_loudly(tmp_path: Path) -> None:
    url, _ = _make_upstream(tmp_path, "renamedplugin", skill_files={"SKILL.md": "x\n"})
    settings = _settings_file(
        tmp_path,
        {"ponytail": {"source": {"source": "github", "repo": url}}},
        {"ponytail@ponytail": True},
    )

    with pytest.raises(FileNotFoundError, match="skills/ponytail"):
        uvs.main(["--settings", str(settings), "--skills-dir", str(tmp_path / "skills")])


def test_no_enabled_github_plugins_is_a_nonzero_exit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    settings = _settings_file(tmp_path, {}, {})

    rc = uvs.main(["--settings", str(settings), "--skills-dir", str(tmp_path / "skills")])

    assert rc == 1, "an empty plugin set must fail loudly, never silently vendor nothing"
    err = capsys.readouterr().err
    assert "found none" in err, f"expected the reason on stderr, got: {err!r}"
