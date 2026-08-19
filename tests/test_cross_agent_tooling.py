"""Cross-agent modes, repo-owned skills, and external plugin bridges."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODES = ("PONYTAIL", "CAVEMAN")
REPO_SKILLS = {
    "coderabbit",
    "debug",
    "new-terminal",
    "release",
    "release-with-changelog",
    "subsystem-sweep",
}


def _commands(path: str, event: str) -> str:
    config = json.loads((ROOT / path).read_text(encoding="utf-8"))
    return "\n".join(
        hook["command"] for group in config["hooks"][event] for hook in group["hooks"] if "command" in hook
    )


def _write_plugin_manifest(config_dir: Path, plugins: dict[str, list[dict[str, str]]]) -> None:
    manifest = config_dir / "plugins/installed_plugins.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({"version": 2, "plugins": plugins}), encoding="utf-8")


def test_repo_contains_only_owned_skills_and_symlink_adapters() -> None:
    assert not (ROOT / "plugins").exists(), "third-party plugin trees must not be vendored"
    assert not (ROOT / "skills-lock.json").exists(), "third-party skill lock must not be vendored"
    assert not (ROOT / ".agents/plugins").exists(), "local plugin marketplace must not be vendored"

    canonical = {path.name for path in (ROOT / ".agents/skills").iterdir() if path.is_dir()}
    adapters = {path.name for path in (ROOT / ".claude/skills").iterdir()}
    assert canonical == adapters == REPO_SKILLS
    for name in REPO_SKILLS:
        adapter = ROOT / ".claude/skills" / name
        assert adapter.is_symlink(), f"{adapter.relative_to(ROOT)} must stay a bridge"
        assert adapter.resolve() == ROOT / ".agents/skills" / name


def test_statusline_loads_ponytail_from_external_plugin_cache(tmp_path: Path) -> None:
    user_dir = tmp_path / "plugins/cache/ponytail/ponytail/0.9"
    project_dir = tmp_path / "plugins/cache/ponytail/ponytail/1.0"
    for install_dir, output in ((user_dir, "USER"), (project_dir, "PONYTAIL")):
        hook_dir = install_dir / "hooks"
        hook_dir.mkdir(parents=True)
        (hook_dir / "ponytail-statusline.sh").write_text(f"#!/bin/sh\nprintf {output}", encoding="utf-8")
    (tmp_path / "plugins/cache/ponytail/ponytail/2.0").mkdir(parents=True)
    _write_plugin_manifest(
        tmp_path,
        {
            "ponytail@ponytail": [
                {"scope": "user", "installPath": str(user_dir)},
                {"scope": "project", "projectPath": str(ROOT), "installPath": str(project_dir)},
            ]
        },
    )
    env = os.environ | {
        "CLAUDE_CONFIG_DIR": str(tmp_path),
        "CLAUDE_PROJECT_DIR": str(ROOT),
        "HOME": str(tmp_path),
    }

    result = subprocess.run(
        ["sh", ROOT / ".claude/hooks/statusline.sh"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "PONYTAIL "


def test_caveman_stats_loads_script_from_external_plugin_cache(tmp_path: Path) -> None:
    install_dir = tmp_path / "plugins/cache/caveman/caveman/1.0"
    plugin_script = install_dir / "src/hooks/caveman-stats.js"
    plugin_script.parent.mkdir(parents=True)
    plugin_script.touch()
    (tmp_path / "plugins/cache/caveman/caveman/2.0").mkdir(parents=True)
    _write_plugin_manifest(tmp_path, {"caveman@caveman": [{"scope": "user", "installPath": str(install_dir)}]})
    node_log = tmp_path / "node.log"
    fake_node = tmp_path / "bin/node"
    fake_node.parent.mkdir()
    fake_node.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >"$NODE_LOG"\n', encoding="utf-8")
    fake_node.chmod(0o755)
    env = os.environ | {
        "CLAUDE_CONFIG_DIR": str(tmp_path),
        "CLAUDE_PROJECT_DIR": str(ROOT),
        "HOME": str(tmp_path),
        "NODE_LOG": str(node_log),
        "PATH": f"{fake_node.parent}:{os.environ['PATH']}",
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
    }

    result = subprocess.run(
        ["sh", ROOT / ".claude/hooks/caveman-stats-refresh.sh"],
        input='{"transcript_path":"/tmp/session.jsonl"}',
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert node_log.read_text(encoding="utf-8") == f"{plugin_script} --session-file /tmp/session.jsonl\n"


def test_caveman_stats_skips_when_plugin_is_not_cached(tmp_path: Path) -> None:
    node_log = tmp_path / "node.log"
    fake_node = tmp_path / "bin/node"
    fake_node.parent.mkdir(parents=True)
    fake_node.write_text('#!/bin/sh\nprintf invoked >"$NODE_LOG"\nexit 99\n', encoding="utf-8")
    fake_node.chmod(0o755)
    missing_dir = tmp_path / "plugins/cache/caveman/caveman/missing"
    missing_dir.mkdir(parents=True)
    _write_plugin_manifest(tmp_path, {"caveman@caveman": [{"scope": "user", "installPath": str(missing_dir)}]})
    env = os.environ | {
        "CLAUDE_CONFIG_DIR": str(tmp_path),
        "HOME": str(tmp_path),
        "NODE_LOG": str(node_log),
        "PATH": f"{fake_node.parent}:{os.environ['PATH']}",
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
    }

    result = subprocess.run(
        ["sh", ROOT / ".claude/hooks/caveman-stats-refresh.sh"],
        input="{}",
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert not node_log.exists()


def test_project_plugin_bridges_use_external_sources_only() -> None:
    config = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
    assert set(config["enabledPlugins"]) == {"ponytail@ponytail", "caveman@caveman"}
    assert set(config["extraKnownMarketplaces"]) == {"ponytail", "caveman"}
    assert all(marketplace["source"]["source"] == "github" for marketplace in config["extraKnownMarketplaces"].values())


def test_modes_reach_every_agent_start() -> None:
    for path in (".claude/settings.json", ".codex/hooks.json"):
        for event in ("SessionStart", "SubagentStart"):
            commands = _commands(path, event)
            missing = [mode for mode in MODES if mode not in commands]
            assert not missing, f"{path} {event} missing {missing}"


def test_codex_repository_hook_integrity_pins_match() -> None:
    config = json.loads((ROOT / ".codex/hooks.json").read_text(encoding="utf-8"))
    commands = [
        hook["command"]
        for groups in config["hooks"].values()
        for group in groups
        for hook in group["hooks"]
        if "command" in hook
    ]
    for relative in (".claude/hooks/session-branch-sync.sh", "scripts/claude-bash-guard.sh"):
        digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        matches = [command for command in commands if relative in command]
        assert len(matches) == 1, f"expected one Codex hook command for {relative}"
        assert digest in matches[0], f"stale Codex hook hash for {relative}"


def test_copilot_client_detection_needs_nothing_installed() -> None:
    # Copilot CLI exports COPILOT_CLI into every shell it spawns, so detection is
    # one variable like the other two clients. Nothing may reappear under
    # ~/.copilot or .github/hooks: a global hook running repo-relative scripts is
    # how the first attempt at this grew an arbitrary-code-execution surface.
    assert not (ROOT / ".github/hooks").exists(), "repo-level Copilot hooks are not wired"
    for name in ("copilot-session-marker.sh", "copilot-session-hook.sh", "install-copilot-hooks.sh"):
        assert not (ROOT / "scripts/agent" / name).exists(), f"{name} was superseded by COPILOT_CLI"

    for hook in (".githooks/prepare-commit-msg", ".githooks/pre-push"):
        body = (ROOT / hook).read_text(encoding="utf-8")
        assert "COPILOT_CLI" in body, f"{hook} lost Copilot detection"
        assert "COPILOT_AGENT_PROMPT" in body, f"{hook} lost cloud-agent detection"

    # Every client present is credited from its OWN key, and the legacy key —
    # which holds Claude's identity here — is gated on no client being present.
    trailer = (ROOT / ".githooks/prepare-commit-msg").read_text(encoding="utf-8")
    assert "for pfb_provider in claude codex copilot grok" in trailer, "attribution is no longer per-client"
    assert "coauthor.${pfb_provider}.email" in trailer, "identities no longer come from per-client keys"
    assert "any_client" in trailer, "the legacy coauthor key is no longer gated on a client marker"


def test_copilot_instructions_route_at_the_canonical_bootstrap() -> None:
    instructions = (ROOT / ".github/copilot-instructions.md").read_text(encoding="utf-8")
    assert "AGENTS.md" in instructions, "Copilot is never sent to the canonical bootstrap"
    assert ".agents/context/copilot-adapter.md" in instructions
    for mode in ("PONYTAIL", "CAVEMAN"):
        assert mode in instructions

    adapter = ROOT / ".agents/context/copilot-adapter.md"
    assert adapter.exists()
    bootstrap = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert ".agents/context/copilot-adapter.md" in bootstrap, "AGENTS.md never names the Copilot adapter"


def test_grok_client_detection_needs_nothing_installed() -> None:
    # Grok CLI exports GROK_AGENT and GROK_SESSION_ID into every shell it
    # spawns, so detection is two variables like the other clients. Nothing
    # may appear under scripts/agent as a Grok session installer.
    for name in ("grok-session-marker.sh", "grok-session-hook.sh", "install-grok-hooks.sh"):
        assert not (ROOT / "scripts/agent" / name).exists(), f"{name} is not how Grok is detected"

    for hook in (".githooks/prepare-commit-msg", ".githooks/pre-push"):
        body = (ROOT / hook).read_text(encoding="utf-8")
        assert "GROK_SESSION_ID" in body, f"{hook} lost Grok session detection"
        assert "GROK_AGENT" in body, f"{hook} lost Grok agent detection"
        assert "grok_session" in body, f"{hook} lost grok_session helper"

    trailer = (ROOT / ".githooks/prepare-commit-msg").read_text(encoding="utf-8")
    assert "for pfb_provider in claude codex copilot grok" in trailer, "Grok is missing from per-client attribution"
    assert "grok) grok_session || continue" in trailer, "Grok is no longer a trailer provider"


def test_grok_adapter_routes_at_the_canonical_bootstrap() -> None:
    adapter_md = (ROOT / "GROK.md").read_text(encoding="utf-8")
    assert "AGENTS.md" in adapter_md, "Grok is never sent to the canonical bootstrap"
    assert ".agents/context/grok-adapter.md" in adapter_md
    for mode in ("PONYTAIL", "CAVEMAN"):
        assert mode in adapter_md

    adapter = ROOT / ".agents/context/grok-adapter.md"
    assert adapter.exists()
    bootstrap = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert ".agents/context/grok-adapter.md" in bootstrap, "AGENTS.md never names the Grok adapter"
    assert "GROK.md" in bootstrap, "AGENTS.md never names the Grok thin adapter"

    harness = ROOT / ".grok/rules/harness.md"
    assert harness.is_file(), "Grok rules dir must auto-inject the adapter pointer"
    pointer = harness.read_text(encoding="utf-8")
    assert "GROK.md" in pointer
    assert ".agents/context/grok-adapter.md" in pointer


def test_copilot_roles_are_pinned_and_defined() -> None:
    tiers = dict(
        line.split("=", 1)
        for line in (ROOT / ".agents/model-tiers.conf").read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.startswith("#")
    )
    for tier in ("TOP_COPILOT", "MID_COPILOT", "SMALL_COPILOT"):
        assert tiers.get(tier), f"{tier} is unpinned"

    agents = {path.name for path in (ROOT / ".github/agents").glob("*.agent.md")}
    codex_agents = {path.stem for path in (ROOT / ".codex/agents").glob("*.toml")}
    assert {f"{name}.agent.md" for name in codex_agents} == agents, "Copilot role coverage diverges from Codex"
