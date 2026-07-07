#!/usr/bin/env python3
"""update-vendored-skills.py -- refresh the vendored plugin skills in .claude/skills/.

Managed/cloud Claude sessions never load marketplace plugins (their slash
commands and the /plugin diagnostics are both unavailable there), so the mode
skills this repo relies on (ponytail, caveman) are vendored byte-identical
into committed .claude/skills/, which cloud sessions do load. This script
automates the refresh so the vendored copies can track their upstreams:

  python3 scripts/update-vendored-skills.py          # refresh all
  git diff                                           # inspect, then commit

For each plugin that is BOTH enabled in .claude/settings.json's
`enabledPlugins` AND declared in its `extraKnownMarketplaces` with a GitHub
source, it shallow-clones the upstream repo, copies `skills/<plugin>/`
(the plugin's core mode skill) plus the repo-root LICENSE into
`.claude/skills/<plugin>/`, and writes an UPSTREAM provenance line
(repo @ commit sha, clone date) so drift stays visible.

Deliberately NOT run in managed environments -- it needs network + git and
its output is committed; cloud sessions just consume the committed copies.

Dev-host tooling (scripts/): bare `python3` is fine here, this never runs on
the pfSense appliance (CLAUDE.md's appliance-python carve-out).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SETTINGS_FILE = REPO_ROOT / ".claude/settings.json"
SKILLS_DIR = REPO_ROOT / ".claude/skills"

# ponytail: default clone base swapped only by tests (file:// fixtures) or a
# GitHub Enterprise mirror; not a user-facing knob.
DEFAULT_CLONE_BASE = "https://github.com/"


def enabled_github_plugins(settings: dict) -> dict[str, str]:
    """Map plugin name -> GitHub `owner/repo` for every enabled marketplace plugin.

    `enabledPlugins` keys are `plugin@marketplace`; only marketplaces with a
    GitHub source are vendorable (a `directory` source has no canonical
    upstream to refresh from -- skipped with a notice, not an error).
    """
    marketplaces = settings.get("extraKnownMarketplaces", {})
    plugins: dict[str, str] = {}
    for key, enabled in settings.get("enabledPlugins", {}).items():
        if not enabled or "@" not in key:
            continue
        plugin, marketplace = key.split("@", 1)
        source = marketplaces.get(marketplace, {}).get("source", {})
        if source.get("source") == "github" and source.get("repo"):
            plugins[plugin] = source["repo"]
        else:
            print(f"SKIP {plugin}: marketplace {marketplace!r} has no GitHub source")
    return plugins


def vendor_one(plugin: str, repo: str, clone_base: str, skills_dir: Path) -> None:
    """Clone `repo` shallow and copy its `skills/<plugin>/` + LICENSE into skills_dir."""
    with tempfile.TemporaryDirectory(prefix=f"vendor-{plugin}-") as tmp:
        clone = Path(tmp) / "clone"
        url = f"{clone_base}{repo}.git" if not repo.startswith("file://") else repo
        subprocess.run(
            ["git", "clone", "--quiet", "--depth", "1", url, str(clone)],
            check=True,
        )
        sha = subprocess.run(
            ["git", "-C", str(clone), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        upstream_skill = clone / "skills" / plugin
        if not upstream_skill.is_dir():
            raise FileNotFoundError(f"{repo} has no skills/{plugin}/ directory -- upstream layout changed?")

        target = skills_dir / plugin
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(upstream_skill, target)

        licence = clone / "LICENSE"
        if licence.is_file():
            shutil.copy2(licence, target / "LICENSE")

        date = datetime.now(timezone.utc).date().isoformat()
        (target / "UPSTREAM").write_text(f"{repo} @ {sha} ({date})\n", encoding="utf-8")
        shown = target.relative_to(REPO_ROOT) if target.is_relative_to(REPO_ROOT) else target
        print(f"OK  {plugin}: {repo} @ {sha[:12]} -> {shown}")


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
        "--clone-base",
        default=DEFAULT_CLONE_BASE,
        help="prefix for `owner/repo` clone URLs (default: GitHub)",
    )
    args = parser.parse_args(argv)

    settings = json.loads(args.settings.read_text(encoding="utf-8"))
    plugins = enabled_github_plugins(settings)
    if not plugins:
        print(f"expected at least one enabled GitHub-sourced plugin in {args.settings}, found none", file=sys.stderr)
        return 1

    args.skills_dir.mkdir(parents=True, exist_ok=True)
    for plugin, repo in sorted(plugins.items()):
        vendor_one(plugin, repo, args.clone_base, args.skills_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
