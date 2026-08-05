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


def test_copilot_session_start_carries_the_modes_and_the_session_marker() -> None:
    # Copilot's own schema: repo hooks live in .github/hooks/*.json, events are
    # camelCase, and only sessionStart output is processed for additionalContext.
    config = json.loads((ROOT / ".github/hooks/pfblockerng.json").read_text(encoding="utf-8"))
    assert config["version"] == 1

    # The ACTION matters, not just the script name: a sessionEnd wired to `start`
    # would leave every session recorded forever.
    for event, action in (("sessionStart", "start"), ("sessionEnd", "end")):
        commands = [entry["bash"] for entry in config["hooks"][event] if "bash" in entry]
        assert any(command.endswith(f'copilot-session-hook.sh" {action}') for command in commands), (
            f"copilot {event} does not dispatch `{action}`"
        )

    # subagentStart carries its own capsule, exactly as the other two vendors pin
    # SessionStart AND SubagentStart.
    commands = [entry["bash"] for entry in config["hooks"]["subagentStart"] if "bash" in entry]
    assert any(command.endswith('copilot-session-hook.sh" subagent') for command in commands)

    # Both capsules live in the dispatcher, because the same script backs the
    # user-level install (repo-level hooks did not fire in CLI 1.0.78).
    dispatcher = (ROOT / "scripts/agent/copilot-session-hook.sh").read_text(encoding="utf-8")
    capsules = [line for line in dispatcher.splitlines() if line.startswith('{"additionalContext"')]
    assert len(capsules) == 2, "expected a session capsule and a subagent capsule"
    for capsule in capsules:
        missing = [mode for mode in MODES if mode not in capsule]
        assert not missing, f"copilot capsule missing {missing}"

    marker_script = ROOT / "scripts/agent/copilot-session-marker.sh"
    assert marker_script.exists()
    body = marker_script.read_text(encoding="utf-8")
    assert "pfb-copilot-session" in body
    assert "--git-common-dir" in body, "the marker must be shared across worktrees"

    installer = (ROOT / "scripts/agent/install-copilot-hooks.sh").read_text(encoding="utf-8")
    assert "copilot-session-hook.sh" in installer


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
