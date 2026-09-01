"""Cross-agent policy, repo-owned skills, and client detection."""

from __future__ import annotations

import collections
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
    assert head_binding < base_binding < hosted
    assert 'gh pr merge N --squash --match-head-commit "$reviewed_sha"' in merge
    assert "atomic strict-base gate" in merge

    steps = merge
    for checkpoint in (
        "git fetch origin",
        'git fetch origin "pull/N/head"',
        'remote_pr_head="$(git rev-parse FETCH_HEAD)"',
        'test "$remote_pr_head" = "$reviewed_sha"',
        'test "$local_head" = "$reviewed_sha"',
    ):
        assert checkpoint in steps
    base_fetch = steps.index("git fetch origin")
    pr_fetch = steps.index('git fetch origin "pull/N/head"')
    resolve = steps.index('remote_pr_head="$(git rev-parse FETCH_HEAD)"')
    remote_guard = steps.index('test "$remote_pr_head" = "$reviewed_sha"')
    local_guard = steps.index('test "$local_head" = "$reviewed_sha"')
    recheck = steps.index("recheck the three-way")
    push = steps.index("git push origin HEAD:devel")
    close = steps.index("close the PR")
    delete = steps.index("--force-with-lease=refs/heads/<head>:<reviewed_sha>")
    assert base_fetch < pr_fetch < resolve < remote_guard
    assert local_guard < hosted < recheck < push < close < delete
    assert "before push and before terminal PR/issue synchronization" in steps
    assert "restart affected review plus exact-head CI" in steps
    assert "every landed commit is locally signed and verified" in landing


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
    routing = extract_between(bootstrap, heading, "\n## ")
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
        # The initializer no longer builds the first graph: the routing document
        # must direct that judgement call to a `/graphify` run instead.
        "prints a notice and builds nothing",
        "`/graphify` run",
        "serena project index",
        "OMP_CLI",
        "PI_CLI",
        "graphify-out/graph.json",
        "source_file",
        "src/` is production",
        "tests/` is",
        "harness/test",
        "stubs/` is shim/support",
        "graph.json` is tracked",
        "records under `graphify-out/memory/` are tracked",
        # The query-outcome feedback loop (issue #2823).
        "graphify save-result",
        "graphify reflect",
        "--outcome useful|dead_end|corrected",
        "`useful` when the returned subgraph answered",
        "`dead_end` when another surface answered it",
        "`corrected` when the graph answered and was wrong",
        "A dead end MUST carry `--correction`",
        "reflections/LESSONS.md",
        # Graphify-first holds for code structure ONLY.
        "grep first",
        "reference counts",
        "tool wiring",
        # Every agent tool installs the same way: one command that installs on a
        # fresh host and upgrades an outdated one, a floor at most, never a pin --
        # including the install added when a setup script hits a missing dependency.
        "an exact `==` pin is never the answer",
        "installed the same way, never pinned",
    ):
        assert contract in routing, f"direct worktree initialization routing lost {contract}"

    folded_routing = routing.casefold()
    for obsolete in (
        "ignored and untracked",
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
    # linguist-generated collapses the whole-file rewrites in pull-request diffs and
    # keeps them out of the language stats; merge=graphify still resolves parallel
    # updates, so both attributes must ride on the row.
    graphify_attribute = "graphify-out/graph.json merge=graphify linguist-generated=true"
    assert attrs.count(graphify_attribute) == 1, f"expected exact .gitattributes row: {graphify_attribute}"
    # The root graph plus the query-outcome records are tracked (issue #2823). Records are
    # named per query and accumulate, so the durable contract is the SET of allowed
    # prefixes: it fails on a dropped graph and on a newly tracked generated artifact.
    tracked = subprocess.run(
        ["git", "ls-files", "graphify-out"], cwd=ROOT, check=True, text=True, capture_output=True
    ).stdout.split()
    assert "graphify-out/graph.json" in tracked, "the root graph must stay tracked"
    strays = [
        path for path in tracked if path != "graphify-out/graph.json" and not path.startswith("graphify-out/memory/")
    ]
    assert strays == [], f"generated Graphify output must stay ignored: {strays}"
    root_ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    # The pair, in order: ignore the directory's contents, then re-include only the
    # tracked graph. Either line alone gets the tracking wrong, and so does a later
    # duplicate of the ignore -- git takes the LAST matching rule, while index()
    # reports the first, so the count is asserted before the order.
    assert root_ignore.count("graphify-out/*") == 1, "generated Graphify output must remain ignored, once"
    assert root_ignore.count("!graphify-out/graph.json") == 1, "the tracked root graph must be re-included, once"
    assert root_ignore.index("graphify-out/*") < root_ignore.index("!graphify-out/graph.json"), (
        "the re-include must follow the ignore, or the graph is not tracked"
    )
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


def test_graphify_memory_records_are_tracked_by_a_directory_reinclude() -> None:
    # issue #2823: `!graphify-out/memory/**` silently fails. `graphify-out/*` matches the
    # memory directory itself and git never descends into it, so every record stays
    # ignored while the ignore file reads as though they are tracked.
    lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert lines.count("!graphify-out/memory/") == 1, "re-include the directory, exactly once"
    assert "!graphify-out/memory/**" not in lines, "a contents glob leaves every record ignored"
    # gitignore takes the LAST matching rule, so the re-include must follow the ignore.
    assert lines.index("graphify-out/*") < lines.index("!graphify-out/memory/")

    def ignored(path: str) -> bool:
        # Only 0 and 1 are verdicts; a symlinked memory/ exits 128.
        probe = subprocess.run(
            ["git", "check-ignore", "-q", path], cwd=ROOT, capture_output=True, text=True, check=False
        )
        assert probe.returncode in (0, 1), f"git could not classify {path}: {probe.stderr.strip()}"
        return probe.returncode == 0

    assert not ignored("graphify-out/memory/query_20260101_000000_probe.md"), "records must be trackable"
    assert ignored("graphify-out/GRAPH_REPORT.md"), "the re-include must not un-ignore the rest"
    assert ignored("graphify-out/reflections/LESSONS.md"), "the aggregate is derivable, so it stays local"

    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert "graphify-out/memory/** linguist-documentation" in attributes, "records are prose, not code"


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


def test_graphify_inc_language_override_rides_as_a_local_patch() -> None:
    # Graphify's suffix map sends .inc to the Pascal extractor, so this repository's
    # PHP includes extract as a handful of incidental nodes (issue #2810). The fix is
    # upstream in Graphify-Labs/graphify#3075 and unreleased, so it rides as a patch
    # applied to the installed package after every install.
    patch = (ROOT / ".agents/patches/graphify-3075-language-overrides.patch").read_text(encoding="utf-8")
    assert "Graphify-Labs/graphify#3075" in patch, "the vendored patch must name its upstream PR"
    assert "+++ b/graphify/rcfile.py" in patch, "the vendored patch must carry the .graphifyrc parser"

    installer_path = "scripts/agent/ensure-graphify.sh"
    installer = (ROOT / installer_path).read_text(encoding="utf-8")
    install_command = "uv tool install --upgrade 'graphifyy>=0.9.51'"
    assert install_command in installer, "the shared Graphify installer lost its install/upgrade floor"
    assert 'sh "$patch_graphify"' in installer, "the shared Graphify installer does not apply the patch"

    resolver = (ROOT / "scripts/agent/resolve-graphify.sh").read_text(encoding="utf-8")
    quote_probe = (
        '"$_graphify_interpreter" -I -c \'import shlex, sys; print(shlex.quote(sys.argv[1]))\' "$_graphify_interpreter"'
    )
    assert quote_probe in resolver, "uv trampoline validation lost isolated POSIX quoting by its owning interpreter"
    assert "eval" not in resolver, "Graphify launcher validation must not evaluate launcher text"

    callers = {
        "scripts/setup-hooks.sh": 'sh "$script_dir/agent/ensure-graphify.sh" "$root"',
        ".githooks/pre-commit": "sh scripts/agent/patch-graphify.sh || failed 'Graphify .inc language override'",
        "scripts/agent/init-worktree-tools.sh": 'sh "$(dirname "$0")/patch-graphify.sh" || exit $?',
        "scripts/agent/ensure-graphify-merge-driver.sh": 'sh "$(dirname "$0")/ensure-graphify.sh" "$root"',
        "scripts/agent/setup-agent-tools.sh": '(cd "$root" && sh "$setup_hooks")',
    }
    for caller, invocation in callers.items():
        source = (ROOT / caller).read_text(encoding="utf-8")
        assert invocation in source, f"{caller} lost mandatory Graphify install/patch reachability"
        assert install_command not in source, f"{caller} duplicates the shared Graphify installation convention"

    agent_setup = (ROOT / "scripts/agent/setup-agent-tools.sh").read_text(encoding="utf-8")
    assert 'sh "$ensure_graphify" "$root"' not in agent_setup, "agent setup duplicates canonical Graphify setup"

    rc = (ROOT / ".graphifyrc").read_text(encoding="utf-8").splitlines()
    assert "language.inc=php" in rc, ".graphifyrc must declare the PHP include override"

    routing = (ROOT / ".agents/context/repository-intelligence.md").read_text(encoding="utf-8")
    for contract in (
        "scripts/agent/ensure-graphify.sh",
        "scripts/agent/patch-graphify.sh",
        "scripts/setup-hooks.sh",
        ".githooks/pre-commit",
        "Graphify-Labs/graphify#3075",
        "language.inc=php",
        "include-node floor",
    ):
        assert contract in routing, f"repository-intelligence routing lost: {contract}"


def test_tracked_graph_carries_the_php_include_corpus() -> None:
    # A Graphify without the vendored override parses all 21 .inc files with the Pascal
    # extractor: extraction still succeeds, so the only visible symptom is a collapsed
    # node count -- 30 across the corpus instead of roughly 755 (issue #2810). Nothing
    # else catches an unattended `uv tool upgrade graphifyy` followed by a Graphify
    # post-commit rebuild, which silently replaces site-packages and drops the patch.
    graph = json.loads((ROOT / "graphify-out/graph.json").read_text(encoding="utf-8"))
    include_files = collections.Counter(
        str(node["source_file"]) for node in graph["nodes"] if str(node.get("source_file", "")).endswith(".inc")
    )
    total = sum(include_files.values())
    # Size alone is satisfied by ONE large include: pfblockerng.inc carries 482 of the
    # 767 nodes, so a graph holding only that file clears any total-node floor. Breadth
    # is the discriminating half -- a file parsed as Pascal still contributes its own
    # file node, so the honest signal is how many includes contribute symbols BESIDES
    # that node: 9 of 21 with the override, 3 without it.
    with_symbols = sorted(path for path, nodes in include_files.items() if nodes > 1)
    assert total > 400 and len(with_symbols) >= 6, (
        f"{total} graph nodes from {len(include_files)} .inc files, and only "
        f"{len(with_symbols)} of them contribute symbols beyond their own file node "
        f"({', '.join(with_symbols) or 'none'}): the tracked graph is missing the PHP "
        "include corpus that .agents/patches/graphify-3075-language-overrides.patch "
        "restores"
    )
