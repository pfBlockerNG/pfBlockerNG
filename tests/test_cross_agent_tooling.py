"""Cross-agent policy, repo-owned skills, and client detection."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests._workflow_steps import extract_between

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


def test_landing_policy_pins_both_signed_linear_paths() -> None:
    landing = (ROOT / ".agents/policy/landing.md").read_text(encoding="utf-8")
    merge = extract_between(landing, "## Merge step", "## Post-merge")
    head_binding = merge.index("reviewed_sha=$(git rev-parse HEAD)")
    base_binding = merge.index("reviewed_base=$(git rev-parse origin/devel)")
    hosted = merge.index("**GitHub-hosted path:**")
    local_start = merge.index("**Maintainer-local path:**")
    assert head_binding < base_binding < hosted
    hosted_policy = merge[hosted:local_start]
    assert 'gh pr merge N --squash --match-head-commit "$reviewed_sha"' in hosted_policy
    assert "only with an atomic strict-base gate; otherwise use local" in hosted_policy
    assert "--delete-branch" not in hosted_policy
    assert "require the exact landed squash commit OID to be GitHub-signed" in hosted_policy

    for checkpoint in (
        "git fetch origin",
        'git fetch origin "pull/N/head"',
        'remote_pr_head="$(git rev-parse FETCH_HEAD)"',
        'local_head="$(git rev-parse HEAD)"',
        'test "$remote_pr_head" = "$reviewed_sha"',
        'test "$local_head" = "$reviewed_sha"',
        "origin/devel == reviewed_base",
    ):
        assert checkpoint in merge
    pr_fetch = merge.index('git fetch origin "pull/N/head"')
    resolve = merge.index('remote_pr_head="$(git rev-parse FETCH_HEAD)"')
    remote_guard = merge.index('test "$remote_pr_head" = "$reviewed_sha"')
    local_guard = merge.index('test "$local_head" = "$reviewed_sha"')
    base_fetch = merge.index("Before either path run `git fetch origin`")
    fence_call = merge.index("run the fence", base_fetch)
    base_guard = merge.index("origin/devel == reviewed_base")
    assert base_binding < pr_fetch < resolve < remote_guard < local_guard < base_fetch
    assert base_fetch < fence_call < base_guard < hosted

    local = extract_between(merge, "**Maintainer-local path:**", "From OUTSIDE")
    assert 'git merge-base --is-ancestor "$reviewed_sha" origin/devel' in local
    assert "A non-descendant `origin/devel` stops" in local
    pre_push_fence = local.index("Immediately before push, run the PR head fence")
    push = local.index("git push origin HEAD:devel")
    post_push_fence = local.index("After push, fetch `origin`, run the PR head fence again")
    mismatch_marker = "**Post-push PR head fence mismatch:**"
    match_marker = "**Post-push PR head fence match:**"
    assert mismatch_marker in local, "post-push fresh-fence mismatch needs an explicit state machine"
    assert match_marker in local, "evidence and terminal synchronization need a fresh-fence success gate"

    mismatch = extract_between(local, mismatch_marker, match_marker)
    assert "After `reviewed_sha` is confirmed landed but the fetched PR head differs" in mismatch
    assert "retain the remote head branch and worktree; stop" in mismatch
    mismatch_state = mismatch.index("read the PR state")
    assert mismatch_state < mismatch.index("`MERGED` keeps terminal state")
    assert "`MERGED` keeps terminal state and routes newer head commits to a new PR" in mismatch
    assert "`OPEN` stays open and restarts affected review plus exact-head CI for the current head" in mismatch
    assert (
        "`CLOSED` reopens the PR and issue and restarts affected review plus exact-head CI for the current head"
        in mismatch
    )
    assert "post landed evidence" not in mismatch
    assert "close the PR and issue" not in mismatch
    assert "--force-with-lease=refs/heads/<head>:<reviewed_sha>" not in mismatch

    matched = extract_between(local, match_marker, "**On lease failure:**")
    evidence = matched.index("post landed evidence")
    state_read = matched.index("read the PR state")
    merged_state = matched.index("If it is `MERGED`")
    open_state = matched.index("If it is `OPEN`")
    close = matched.index("close the PR and issue")
    terminal = matched.index("verify both terminal states")
    assert "If it is `MERGED`, verify the linked issue completed" in matched
    assert "Any other state stops" in matched
    assert "verify both terminal states and retain the worktree" in matched
    delete = matched.index("--force-with-lease=refs/heads/<head>:<reviewed_sha>")
    assert pre_push_fence < push < post_push_fence < local.index(mismatch_marker) < local.index(match_marker)
    assert evidence < state_read < merged_state < open_state < close < terminal < delete

    lease_failure = extract_between(local, "**On lease failure:**", "Only after leased deletion succeeds")
    assert "retain the remote head branch and worktree; stop; do not clean up" in lease_failure
    assert "`CLOSED` reopens the PR and issue and restarts review" in lease_failure
    assert "`MERGED` keeps terminal state and routes newer head commits to a new PR" in lease_failure
    success_cleanup = merge.index("Only after leased deletion succeeds")
    outside_cleanup = merge.index("From OUTSIDE")
    assert local.index("**On lease failure:**") < success_cleanup < outside_cleanup
    assert "restart affected review plus exact-head CI" in merge
    assert "every landed commit is locally signed and verified" in landing

    issues = (ROOT / ".agents/policy/issues.md").read_text(encoding="utf-8")
    assert "GitHub squash or indirect local fast-forward" in issues
    assert "Local fast-forward not inferred as `MERGED`" in issues
    assert "commit and issue auto-closure (`state_reason: completed`)" in issues
    assert "close the issue `--reason completed`, and verify both terminal states" in issues

    git_policy = (ROOT / ".agents/policy/git.md").read_text(encoding="utf-8")
    assert "git push origin --delete <branch>" not in git_policy
    assert "--force-with-lease=refs/heads/<head>:<reviewed_sha>" in git_policy


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

    adapter = (ROOT / ".agents/context/omp-adapter.md").read_text(encoding="utf-8")
    for contract in (
        ".omp/AGENTS.md",
        ".omp/RULES.md",
        "OMP_CLI=1",
        "PI_CLI=1",
        "OMP adds no attribution to commits or public bodies.",
    ):
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
        "whose assertions fail on regression; no coverage theater. Read an entire GitHub issue, including comments, "
        "before working it."
    )
    expected_rules = f"# pfBlockerNG session invariants\n\n{discipline}\n"
    assert rules == expected_rules


def test_repository_intelligence_initializes_each_worktree_directly() -> None:
    routing = (ROOT / ".agents/context/repository-intelligence.md").read_text(encoding="utf-8")
    assert routing.strip(), "repository-intelligence routing must not be empty"
    # issue #3120: wrapping a Markdown paragraph must not drop a pin or hide a retired recipe.
    flat = " ".join(routing.split())
    for contract in (
        "work-branch.sh --worktree",
        "scripts/agent/init-worktree-tools.sh",
        "scripts/agent/ensure-codegraph.sh",
        "serena project index",
        "OMP_CLI",
        "PI_CLI",
        # CodeGraph's first call is for code structure ONLY; grep first for the rest.
        "grep first",
        "reference counts",
        "tool wiring",
        # Every agent tool installs the same way: one command that installs on a
        # fresh host and upgrades an outdated one, a floor at most, never a pin --
        # including the install added when a setup script hits a missing dependency.
        "an exact `==` pin is never the answer",
        "installed the same way, never pinned",
    ):
        assert contract in flat, f"direct worktree initialization routing lost {contract}"


def test_codegraph_generated_state_is_ignored_by_its_own_tracked_contract() -> None:
    local_ignore = (ROOT / ".codegraph/.gitignore").read_text(encoding="utf-8").splitlines()
    assert "*" in local_ignore
    assert "!.gitignore" in local_ignore
    root_ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".codegraph/" not in root_ignore, "root ignore would hide CodeGraph's own tracked contract"


def test_omp_language_servers_route_php_include_files() -> None:
    # pfSense ships PHP include files as .inc, and OMP's built-in intelephense entry
    # claims only .php/.phtml -- so without this override every .inc file, including
    # the largest production file in the package, is invisible to lsp
    # definition/references/rename/diagnostics (issue #2802). Only the fields that
    # differ from the built-in entry are overridden: OMP merges the built-in config
    # under the override, so omitted top-level fields are inherited, while a field
    # the override does supply replaces the built-in value whole.
    server = json.loads((ROOT / ".omp/lsp.json").read_text(encoding="utf-8"))["servers"]["intelephense"]
    assert set(server["fileTypes"]) == {".php", ".phtml", ".inc"}
    assert server["languageId"] == "php", "an inferred language id follows the extension, not PHP"

    # Routing didOpen is not enough: intelephense's own workspace scan is driven by
    # files.associations, and cross-file references come from that index. The array
    # replaces intelephense's own default, so dropping *.php or *.phtml here would
    # unindex ordinary PHP files.
    settings = server["settings"]["intelephense"]
    assert {"*.php", "*.phtml", "*.inc"} <= set(settings["files"]["associations"])

    # The editor already carries the same association and PHP version; the two agent
    # surfaces must not drift apart.
    vscode = (ROOT / ".vscode/settings.json").read_text(encoding="utf-8")
    assert '"*.inc": "php"' in vscode
    php_version = settings["environment"]["phpVersion"]
    assert f'"intelephense.environment.phpVersion": "{php_version}"' in vscode


def test_copilot_roles_mirror_codex_roles() -> None:
    agents = {path.name for path in (ROOT / ".github/agents").glob("*.agent.md")}
    codex_agents = {path.stem for path in (ROOT / ".codex/agents").glob("*.toml")}
    assert {f"{name}.agent.md" for name in codex_agents} == agents, "Copilot role coverage diverges from Codex"


# A real production include, so the probes prove the tools read this package's own PHP.
PHP_INCLUDE_PROBE = "src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"


def test_php_inc_files_are_declared_php_to_extension_driven_tools() -> None:
    # issue #2807: an unmapped `.inc` is skipped, and the result is indistinguishable
    # from a clean no-match on a file the tool did read.
    config = yaml.safe_load((ROOT / "sgconfig.yml").read_text(encoding="utf-8"))
    assert config == {"languageGlobs": {"php": ["*.inc"]}}, "ast-grep rejects a scalar glob"

    routing = (ROOT / ".agents/context/repository-intelligence.md").read_text(encoding="utf-8")
    assert "--scan-unknown-extensions" in routing, "semgrep's only surface is the documented flag"


@pytest.mark.skipif(shutil.which("ast-grep") is None, reason="agent-host tool, absent from CI")
def test_ast_grep_parses_a_php_inc_file_as_php() -> None:
    # The reported language, not a match count: any language ast-grep assigns matches
    # `return $$$X;`, so a count alone passes under a decoy mapping.
    stream = subprocess.run(
        ["ast-grep", "run", "--pattern", "return $$$X;", "--json=stream", PHP_INCLUDE_PROBE],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    languages = {json.loads(line)["language"] for line in stream}
    assert languages == {"Php"}, f"ast-grep read {PHP_INCLUDE_PROBE} as {languages or 'no language'}"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="agent-host tool, absent from CI")
def test_semgrep_scans_a_php_inc_file_only_with_the_documented_flag() -> None:
    def findings(*flags: str) -> int:
        scan = subprocess.run(
            ["semgrep", "scan", "--quiet", "--json", "-e", "return $X;", "-l", "php", *flags, PHP_INCLUDE_PROBE],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert scan.returncode == 0, f"semgrep exited {scan.returncode}: {scan.stdout}{scan.stderr}"
        report = json.loads(scan.stdout)
        assert report["errors"] == [], f"semgrep errored: {report['errors']}"
        return len(report["results"])

    assert findings() == 0, "semgrep gained .inc support; the documented flag is now misleading"
    assert findings("--scan-unknown-extensions") > 0, "the documented semgrep flag does not work"
