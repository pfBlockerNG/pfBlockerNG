"""Cross-agent mode, Token Savior, and skill-plugin wiring."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODES = ("PONYTAIL", "CAVEMAN", "TOKEN-SAVIOR")


def _commands(path: str, event: str) -> str:
    config = json.loads((ROOT / path).read_text(encoding="utf-8"))
    return "\n".join(
        hook["command"] for group in config["hooks"][event] for hook in group["hooks"] if "command" in hook
    )


def test_modes_and_token_savior_reach_every_agent_start() -> None:
    for path in (".claude/settings.json", ".codex/hooks.json"):
        for event in ("SessionStart", "SubagentStart"):
            commands = _commands(path, event)
            missing = [mode for mode in MODES if mode not in commands]
            assert not missing, f"{path} {event} missing {missing}"


def test_token_savior_hooks_preserve_upstream_opt_in_defaults() -> None:
    for path in (".claude/settings.json", ".codex/hooks.json"):
        config = json.loads((ROOT / path).read_text(encoding="utf-8"))
        commands = json.dumps(config.get("hooks", {}).get("PostToolUse", []))
        assert "tool_capture_hook" in commands, f"{path} lost Token Savior lifecycle wiring"

        serialized = json.dumps(config)
        for variable in ("TS_BASH_COMPACT", "TS_BASH_REWRITE", "TS_CAPTURE_DISABLED"):
            assert variable not in serialized, f"{path} overrides opt-in {variable}"


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
    assert "for pfb_provider in claude codex copilot" in trailer, "attribution is no longer per-client"
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


def test_mattpocock_plugin_is_installable_by_copilot() -> None:
    plugin_root = ROOT / "plugins/mattpocock-skills"
    manifest = json.loads((plugin_root / ".github/plugin/plugin.json").read_text(encoding="utf-8"))
    assert manifest["name"] == "mattpocock-skills"

    claude = json.loads((plugin_root / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
    assert manifest["version"] == claude["version"], "the Copilot manifest drifted from the plugin version"

    # Points at the existing vendor-neutral tree: no third copy of every skill.
    skills = manifest["skills"]
    assert skills == "codex/skills/"
    assert (plugin_root / skills).is_dir()

    marketplace = json.loads((plugin_root / ".github/plugin/marketplace.json").read_text(encoding="utf-8"))
    assert [entry["name"] for entry in marketplace["plugins"]] == ["mattpocock-skills"]


def test_mattpocock_skills_are_project_enabled_for_claude_and_listed_for_codex() -> None:
    claude = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
    assert claude["enabledPlugins"]["mattpocock-skills@mattpocock"] is True
    assert claude["extraKnownMarketplaces"]["mattpocock"]["source"] == {
        "source": "directory",
        "path": "./plugins/mattpocock-skills",
    }

    codex = json.loads((ROOT / ".agents/plugins/marketplace.json").read_text(encoding="utf-8"))
    entries = {plugin["name"] for plugin in codex["plugins"]}
    assert {"mattpocock-skills", "ponytail"} <= entries
