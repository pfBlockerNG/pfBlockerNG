"""Cross-agent policy, repo-owned skills, and client detection."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO_SKILLS = {
    "coderabbit",
    "debug",
    "release",
    "release-with-changelog",
    "subsystem-sweep",
}


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
    assert "for pfb_provider in claude codex copilot grok omp" in trailer, "attribution is no longer per-client"
    assert "coauthor.${pfb_provider}.email" in trailer, "identities no longer come from per-client keys"
    assert "any_client" in trailer, "the legacy coauthor key is no longer gated on a client marker"


def test_copilot_instructions_route_at_the_canonical_bootstrap() -> None:
    instructions = (ROOT / ".github/copilot-instructions.md").read_text(encoding="utf-8")
    assert "AGENTS.md" in instructions, "Copilot is never sent to the canonical bootstrap"
    assert ".agents/context/copilot-adapter.md" in instructions

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
    assert "for pfb_provider in claude codex copilot grok omp" in trailer, "Grok is missing from per-client attribution"
    assert "grok) grok_session || continue" in trailer, "Grok is no longer a trailer provider"


def test_grok_adapter_routes_at_the_canonical_bootstrap() -> None:
    adapter_md = (ROOT / "GROK.md").read_text(encoding="utf-8")
    assert "AGENTS.md" in adapter_md, "Grok is never sent to the canonical bootstrap"
    assert ".agents/context/grok-adapter.md" in adapter_md

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


def test_omp_adapter_and_client_detection() -> None:
    for hook in (".githooks/prepare-commit-msg", ".githooks/pre-push"):
        body = (ROOT / hook).read_text(encoding="utf-8")
        assert "OMP_CLI" in body, f"{hook} lost OMP detection"
        assert "PI_CLI" in body, f"{hook} lost Pi-compatible detection"
        assert "omp_session" in body, f"{hook} lost omp_session helper"

    trailer = (ROOT / ".githooks/prepare-commit-msg").read_text(encoding="utf-8")
    assert "for pfb_provider in claude codex copilot grok omp" in trailer
    assert "omp) omp_session || continue" in trailer

    adapter = (ROOT / ".agents/context/omp-adapter.md").read_text(encoding="utf-8")
    for contract in (".omp/AGENTS.md", ".omp/RULES.md", "OMP_CLI=1", "PI_CLI=1", "coauthor.omp"):
        assert contract in adapter, f"OMP adapter lost {contract}"
    bootstrap = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert ".agents/context/omp-adapter.md" in bootstrap

    native = (ROOT / ".omp/AGENTS.md").read_text(encoding="utf-8")
    assert "@../AGENTS.md" in native
    assert "@../.agents/context/omp-adapter.md" in native

    rules = (ROOT / ".omp/RULES.md").read_text(encoding="utf-8")
    discipline = (
        "Never assume: read the source of truth, investigate live state, and confirm a genuine fork before building. "
        "A claim without a run artifact is ASSUMED. Environmental claims written into artifacts are probed "
        "in-session first. Before any fix edit, list at least two hypotheses and run a discriminating probe. "
        "No self-exemption from a MUST without quoted user authorization. Every behavior change requires an "
        "unchanged test executed red before the production edit and green afterward. Every change ships with tests "
        "whose assertions fail on regression; no coverage theater. Substantial coding work is planned and gated by "
        "the top tier, implemented by small-tier sub-agents, and every step is gated by an independent small-tier "
        "verifier through the brief → handoff → gate contract. Read an entire GitHub issue, including comments, "
        "before working it."
    )
    expected_rules = f"# pfBlockerNG session invariants\n\n{discipline} See `.agents/policy/delegation.md`.\n"
    assert rules == expected_rules


def test_repository_intelligence_routing_is_canonical_for_every_client() -> None:
    bootstrap = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    heading = "## Repository intelligence routing"
    assert heading in bootstrap, "repository-intelligence routing must be vendor-neutral"
    routing = bootstrap.split(heading, 1)[1].split("\n## ", 1)[0]
    for contract in (
        "scripts/agent/ensure-codegraph.sh",
        "codegraph_explore",
        "codegraph serve --mcp",
        "Serena",
        "Graphify",
    ):
        assert contract in routing, f"canonical routing lost {contract}"

    for entrypoint in (
        "CLAUDE.md",
        ".agents/context/codex-adapter.md",
        ".github/copilot-instructions.md",
        "GROK.md",
    ):
        body = (ROOT / entrypoint).read_text(encoding="utf-8")
        assert "AGENTS.md" in body, f"{entrypoint} does not load canonical routing"

    codex = (ROOT / ".agents/context/codex-adapter.md").read_text(encoding="utf-8")
    assert heading not in codex, "Codex must not own a second routing policy"


def test_repository_intelligence_initializes_each_worktree_directly() -> None:
    routing = (ROOT / ".agents/context/repository-intelligence.md").read_text(encoding="utf-8")
    assert routing.strip(), "repository-intelligence routing must not be empty"
    for contract in (
        "work-branch.sh --worktree",
        "scripts/agent/init-worktree-tools.sh",
        "scripts/agent/ensure-codegraph.sh",
        "graphify update",
        "graphify extract",
        "serena project index",
        "OMP_CLI",
        "PI_CLI",
        "graphify-out/graph.json",
        "source_file",
        "src/` is production",
        "tests/` is",
        "harness/test",
        "stubs/` is shim/support",
        "ignored and untracked",
    ):
        assert contract in routing, f"direct worktree initialization routing lost {contract}"

    folded_routing = routing.casefold()
    for obsolete in (
        "graphify-refresh-required",
        "graphify-store.py",
        ".git/graphify-store.lock",
        "temporary detached builder",
        "graphify cluster-only",
        "cluster-only",
    ):
        assert obsolete not in folded_routing, f"obsolete Graphify store/refresh recipe remains: {obsolete}"
    assert "graphify-out/views" not in routing
    assert "update_graphify_views.py" not in routing

    attrs_text = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert attrs_text.strip(), ".gitattributes must not be empty"
    attrs = attrs_text.splitlines()
    graphify_attribute = "graphify-out/graph.json merge=graphify"
    assert attrs.count(graphify_attribute) == 1, f"expected exact .gitattributes row: {graphify_attribute}"
    assert (
        subprocess.run(["git", "ls-files", "graphify-out"], cwd=ROOT, check=True, text=True, capture_output=True).stdout
        == ""
    )
    root_ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "graphify-out/" in root_ignore, "generated Graphify output must remain ignored"
    for obsolete_path in ("scripts/agent/graphify-store.py", "tests/test_graphify_store.py"):
        assert not (ROOT / obsolete_path).exists(), f"obsolete Graphify store path returned: {obsolete_path}"


def test_markdownlint_excludes_generated_graphify_reports() -> None:
    config = (ROOT / ".markdownlint-cli2.jsonc").read_text(encoding="utf-8")
    assert '"!graphify-out/**"' in config


def test_codegraph_generated_state_is_ignored_by_its_own_tracked_contract() -> None:
    local_ignore = (ROOT / ".codegraph/.gitignore").read_text(encoding="utf-8").splitlines()
    assert "*" in local_ignore
    assert "!.gitignore" in local_ignore
    root_ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".codegraph/" not in root_ignore, "root ignore would hide CodeGraph's own tracked contract"


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
