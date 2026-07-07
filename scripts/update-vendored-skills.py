#!/usr/bin/env python3
"""update-vendored-skills.py -- refresh the vendored plugin skills in .claude/skills/.

Managed/cloud Claude sessions never load marketplace plugins (their slash
commands and the /plugin diagnostics are both unavailable there), so the mode
skills this repo relies on (ponytail, caveman) are vendored byte-identical
into committed .claude/skills/, which cloud sessions do load. This script
automates the refresh so the vendored copies can track their upstreams:

  python3 scripts/update-vendored-skills.py                 # latest RELEASES
  python3 scripts/update-vendored-skills.py --ref ponytail=v4.8.3
  git diff                                                  # inspect, then commit

For each plugin that is BOTH enabled in .claude/settings.json's
`enabledPlugins` AND declared in its `extraKnownMarketplaces` with a GitHub
source, it fetches the upstream repo at one ref -- `--ref PLUGIN=REF` (a tag,
branch, or commit sha), defaulting to the tag of the upstream's LATEST GitHub
RELEASE -- and copies:

  - `skills/<plugin>/` (the plugin's core mode skill) -> `.claude/skills/<plugin>/`
  - the repo-root LICENSE
  - the plugin's hook scripts (EXTRA_VENDOR_GLOBS below, upstream-relative
    paths preserved) so `.claude/hooks/vendored-plugin-hook.sh` can run them
    with CLAUDE_PLUGIN_ROOT pointed at the vendored root
  - an UPSTREAM provenance line (repo @ commit sha, ref, date) so drift stays
    visible

Deliberately NOT run in managed environments -- it needs network + git and
its output is committed; cloud sessions just consume the committed copies.

Dev-host tooling (scripts/): bare `python3` is fine here, this never runs on
the pfSense appliance (CLAUDE.md's appliance-python carve-out).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SETTINGS_FILE = REPO_ROOT / ".claude/settings.json"
SKILLS_DIR = REPO_ROOT / ".claude/skills"

GITHUB_RELEASE_API = "https://api.github.com/repos/{repo}/releases/latest"

# The plugin name becomes a path segment under --skills-dir (and the rmtree
# target of a refresh), so it must be a plain single-segment name -- an empty
# segment ('@bogus' typo) would resolve to the skills dir itself and a '../'
# name would escape it (#931 review).
_PLUGIN_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")

# Per-plugin upstream paths vendored IN ADDITION to skills/<plugin>/ + LICENSE,
# copied with their upstream-relative paths preserved under the vendored root
# (matching each plugin's own ${CLAUDE_PLUGIN_ROOT}-relative hook manifest).
EXTRA_VENDOR_GLOBS: dict[str, tuple[str, ...]] = {
    "ponytail": ("hooks/*.js", "hooks/ponytail-statusline.*"),
    "caveman": ("src/hooks/*.js", "src/hooks/caveman-statusline.*"),
}


def _git_env() -> dict[str, str]:
    """os.environ minus every GIT_* var.

    Under a git hook, exported GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE would point
    this script's `git fetch`/`git rev-parse` at the WRONG repository (#931
    review); scrub them so the temp clone is the sole git context.
    """
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def enabled_github_plugins(settings: dict) -> dict[str, str]:
    """Map plugin name -> GitHub `owner/repo` for every enabled marketplace plugin.

    `enabledPlugins` keys are `plugin@marketplace`; only marketplaces with a
    GitHub source are vendorable (a `directory` source has no canonical
    upstream to refresh from). Every skipped key is reported -- a silent skip
    reads as "vendored" when it wasn't (#931 review).
    """
    marketplaces = settings.get("extraKnownMarketplaces", {})
    plugins: dict[str, str] = {}
    for key, enabled in settings.get("enabledPlugins", {}).items():
        if "@" not in key:
            print(f"SKIP {key!r}: not a plugin@marketplace key")
            continue
        plugin, marketplace = key.split("@", 1)
        if not enabled:
            print(f"SKIP {plugin}: disabled")
            continue
        if not _PLUGIN_NAME_RE.match(plugin):
            raise ValueError(f"unsafe plugin name {plugin!r} in enabledPlugins -- must match {_PLUGIN_NAME_RE.pattern}")
        source = marketplaces.get(marketplace, {}).get("source", {})
        if source.get("source") == "github" and source.get("repo"):
            plugins[plugin] = source["repo"]
        else:
            print(f"SKIP {plugin}: marketplace {marketplace!r} has no GitHub source")
    return plugins


def latest_release_tag(repo: str) -> str:
    """Tag name of `repo`'s latest GitHub release; loud failure if there is none."""
    request = urllib.request.Request(
        GITHUB_RELEASE_API.format(repo=repo),
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "pfBlockerNG-update-vendored-skills",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            tag = json.load(resp).get("tag_name", "")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"no latest GitHub release for {repo} (HTTP {exc.code}) -- pass --ref <plugin>=<ref> explicitly"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"failed to query the latest release of {repo} ({exc.reason}) -- pass --ref <plugin>=<ref> explicitly"
        ) from exc
    if not tag:
        raise RuntimeError(f"latest release of {repo} carries no tag_name -- pass --ref <plugin>=<ref> explicitly")
    return tag


def _refuse_symlinks(paths: list[Path], clone: Path, repo: str) -> None:
    """Refuse to vendor symlinks -- copying would dereference them (#931 review).

    A hostile/compromised upstream could point a symlink outside the clone
    (same escape class scripts/build-pkg-portable.py's _safe_extract guards);
    vendored trees must be regular files only. Every COMPONENT between each
    path and the clone root is checked too: a symlinked skills/<plugin>/ (or
    hooks/) directory would otherwise smuggle its target's files through as
    regular-looking descendants (#931 delta review).
    """
    for path in paths:
        p = path
        while p != clone:
            if p.is_symlink():
                raise ValueError(f"{repo}: refusing to vendor symlink {p.relative_to(clone)}")
            if p == p.parent:  # filesystem root -- path was never under the clone
                raise ValueError(f"{repo}: {path} escapes the clone")
            p = p.parent


def vendor_one(plugin: str, repo: str, skills_dir: Path, ref: str | None, extra_globs: tuple[str, ...] = ()) -> None:
    """Fetch `repo` at `ref` (tag/branch/sha; None = remote HEAD) and vendor `plugin`."""
    with tempfile.TemporaryDirectory(prefix=f"vendor-{plugin}-") as tmp:
        clone = Path(tmp) / "clone"
        clone.mkdir()
        url = repo if repo.startswith("file://") else f"https://github.com/{repo}.git"

        def _git(*args: str) -> str:
            return subprocess.run(
                ["git", "-C", str(clone), *args],
                check=True,
                capture_output=True,
                text=True,
                env=_git_env(),
            ).stdout.strip()

        # init + fetch-by-ref + detach handles tags, branches, AND commit shas
        # with one code path (clone --branch cannot take a sha).
        _git("init", "-q")
        _git("remote", "add", "origin", url)
        _git("fetch", "-q", "--depth", "1", "origin", ref or "HEAD")
        _git("checkout", "-q", "--detach", "FETCH_HEAD")
        sha = _git("rev-parse", "HEAD")

        upstream_skill = clone / "skills" / plugin
        if not upstream_skill.is_dir():
            raise FileNotFoundError(f"{repo} has no skills/{plugin}/ directory -- upstream layout changed?")

        licence = clone / "LICENSE"
        extra_files: list[Path] = []
        for pattern in extra_globs:
            matched = sorted(clone.glob(pattern))
            if not matched:
                raise FileNotFoundError(f"{repo} has no files matching {pattern!r} -- upstream layout changed?")
            extra_files.extend(matched)
        _refuse_symlinks([upstream_skill, *upstream_skill.rglob("*"), licence, *extra_files], clone, repo)

        target = skills_dir / plugin
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(upstream_skill, target)
        if licence.is_file():
            shutil.copy2(licence, target / "LICENSE")
        for src in extra_files:
            dest = target / src.relative_to(clone)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)

        # Compatibility shim (#931 delta review): the vendored hook scripts were
        # written for the upstream PLUGIN-ROOT layout and resolve the skill text
        # via __dirname math at <plugin-root>/skills/<plugin>/SKILL.md. Our
        # vendored root IS upstream's skills/<plugin>/, so re-copy the skill dir
        # at its upstream-relative path too -- without it every managed-session
        # activation silently emits the js's frozen built-in fallback ruleset
        # instead of the real, current SKILL.md.
        shutil.copytree(upstream_skill, target / "skills" / plugin)

        date = datetime.now(timezone.utc).date().isoformat()
        (target / "UPSTREAM").write_text(f"{repo} @ {sha} (ref {ref or 'HEAD'}, {date})\n", encoding="utf-8")
        shown = target.relative_to(REPO_ROOT) if target.is_relative_to(REPO_ROOT) else target
        print(f"OK  {plugin}: {repo} @ {sha[:12]} (ref {ref or 'HEAD'}) -> {shown}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--settings",
        type=Path,
        default=SETTINGS_FILE,
        help="settings.json declaring enabledPlugins + extraKnownMarketplaces",
    )
    parser.add_argument(
        "--skills-dir",
        type=Path,
        default=SKILLS_DIR,
        help="destination .claude/skills directory",
    )
    parser.add_argument(
        "--ref",
        action="append",
        default=[],
        metavar="PLUGIN=REF",
        help="vendor PLUGIN at REF (tag, branch, or commit sha); repeatable. "
        "Default: the tag of the plugin's latest GitHub release",
    )
    args = parser.parse_args(argv)

    refs: dict[str, str] = {}
    for spec in args.ref:
        plugin, sep, ref = spec.partition("=")
        if not sep or not plugin or not ref:
            print(f"bad --ref {spec!r}: expected PLUGIN=REF", file=sys.stderr)
            return 1
        if plugin in refs:
            print(f"duplicate --ref for {plugin!r} ({refs[plugin]!r} then {ref!r}) -- pass it once", file=sys.stderr)
            return 1
        refs[plugin] = ref

    settings = json.loads(args.settings.read_text(encoding="utf-8"))
    plugins = enabled_github_plugins(settings)
    if not plugins:
        print(f"expected at least one enabled GitHub-sourced plugin in {args.settings}, found none", file=sys.stderr)
        return 1
    unknown = sorted(set(refs) - set(plugins))
    if unknown:
        print(f"--ref names unknown plugin(s) {unknown} -- enabled: {sorted(plugins)}", file=sys.stderr)
        return 1

    args.skills_dir.mkdir(parents=True, exist_ok=True)
    for plugin, repo in sorted(plugins.items()):
        ref = refs.get(plugin)
        if ref is None and not repo.startswith("file://"):
            ref = latest_release_tag(repo)
            print(f"    {plugin}: latest release of {repo} is {ref}")
        vendor_one(plugin, repo, args.skills_dir, ref, EXTRA_VENDOR_GLOBS.get(plugin, ()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
