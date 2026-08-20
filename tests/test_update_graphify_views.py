"""Tests for the declarative Graphify ownership and reference views."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "agent" / "update_graphify_views.py"
_SPEC = importlib.util.spec_from_file_location("update_graphify_views", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
views = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(views)


def _config() -> dict:
    return views.load_config()


def _raw_graph(*, duplicate_fixture: bool = False, structural: bool = False) -> dict:
    nodes = [
        {
            "id": "runtime-use",
            "label": "pfb_alias_autocomplete_lists",
            "source_file": "src/app.py",
        },
        {
            "id": "standin-use",
            "label": "config_get_path",
            "source_file": "tests/standins/firewall_standin.py",
        },
        {"id": "test", "label": "test_app", "source_file": "tests/test_app.py"},
        {"id": "fixture", "label": "fixture.json", "source_file": "tests/fixtures/fixture.json"},
    ]
    if duplicate_fixture:
        nodes.append({"id": "fixture-two", "label": "fixture.json", "source_file": "tests/fixtures/other/fixture.json"})
    links = [{"source": "runtime-use", "target": "standin-use", "relation": "calls"}] if structural else []
    return {"directed": False, "nodes": nodes, "links": links}


def _paths(duplicate_fixture: bool = False) -> list[str]:
    paths = [
        "src/app.py",
        "tests/standins/firewall_standin.py",
        "tests/test_app.py",
        "tests/fixtures/fixture.json",
    ]
    if duplicate_fixture:
        paths.append("tests/fixtures/other/fixture.json")
    return paths


def _texts(duplicate_fixture: bool = False) -> dict[str, str]:
    texts = {
        "src/app.py": "config_get_path('aliases/alias')\n",
        "tests/standins/firewall_standin.py": "def config_get_path(path): pass\n",
        "tests/test_app.py": "open('fixture.json')\n",
    }
    if duplicate_fixture:
        texts["tests/fixtures/other/fixture.json"] = "{}\n"
    return texts


def test_first_match_partition_and_future_standin_convention() -> None:
    config = _config()
    partition = views.partition_paths(
        [
            "src/vendor/codemirror.js",
            "src/app.py",
            "tests/standins/new_standin.py",
            "tests/test_app.py",
            "tools/webassets/patches/local.patch",
        ],
        config,
    )

    assert partition["vendor"] == ["src/vendor/codemirror.js", "tools/webassets/patches/local.patch"]
    assert partition["runtime"] == ["src/app.py"]
    assert partition["test-support"] == ["tests/standins/new_standin.py"]
    assert partition["test-code"] == ["tests/test_app.py"]
    assert views.classify_path("tools/webassets/test/cm-hooks-source.test.js", config) == "test-code"
    assert views.classify_path("tools/webassets/lezer-regexp/test/parse.test.js", config) == "test-code"
    assert views.classify_path("tools/webassets/lezer-regexp/test/cases.txt", config) == "test-support"
    assert views.classify_path("composer.json", config) == "vendor"
    assert views.classify_path("composer.lock", config) == "vendor"
    assert views.classify_path("pyproject.toml", config) == "vendor"
    assert views.classify_path("uv.lock", config) == "vendor"
    assert views.classify_path("LICENSE", config) is None
    assert views.classify_path("AGENTS.md", config) == "agent-context"
    assert views.classify_path(".agents/new-policy.md", config) == "agent-context"
    assert views.classify_path("scripts/agent/new-workflow.py", config) == "agent-context"
    assert views.classify_path("support/fixtures/not-a-test-fixture.json", config) is None


def test_source_view_order_and_ambiguous_prefixes_fail_closed() -> None:
    config = _config()
    reordered = json.loads(json.dumps(config))
    reordered["views"][0], reordered["views"][1] = reordered["views"][1], reordered["views"][0]
    with pytest.raises(views.GraphifyViewsError):
        views.validate_config(reordered)
    raw = {
        "nodes": [
            {"id": "src_foo_bar_alpha", "label": "alpha", "source_file": "src/foo-bar.py"},
            {"id": "src_foo_bar_beta", "label": "beta", "source_file": "src/foo_bar.py"},
            {"id": "src_foo_bar_gamma", "label": "gamma", "source_file": "src/foo.bar.py"},
            {"id": "src_foo_bar_unowned", "label": "unowned", "source_file": ""},
        ],
        "links": [],
    }
    built = views.build_views(
        raw,
        config,
        tracked_paths=["src/foo-bar.py", "src/foo_bar.py", "src/foo.bar.py"],
    )
    assert not any(node["id"].endswith("unowned") for node in built["runtime"]["nodes"])


def test_partition_excludes_unclassified_files_and_keeps_artifact_nodes() -> None:
    config = _config()
    accepted = [
        "src/app.py",
        "tests/fixtures/data.bin",
        "tools/webassets/patches/upstream.patch",
        "composer.json",
        "composer.lock",
        "uv.lock",
    ]
    unclassified = "misc/unclassified_code.py"
    partition = views.partition_paths(accepted, config)
    assert sorted(path for paths in partition.values() for path in paths) == sorted(accepted)
    assert views.classify_path(unclassified, config) is None
    built = views.build_views({}, config, tracked_paths=accepted)
    assert all(unclassified not in node.get("source_file", "") for node in built["whole-repository"]["nodes"])
    assert {node["source_file"] for node in built["whole-repository"]["nodes"]} >= set(accepted)


def test_agent_context_headings_and_exact_path_references_are_dynamic() -> None:
    config = _config()
    tracked = ["AGENTS.md", ".agents/new-policy.md", "src/app.py", "scripts/agent/new-workflow.py"]
    built = views.build_views(
        {},
        config,
        tracked_paths=tracked,
        source_texts={
            "AGENTS.md": "# Policy\nUse src/app.py.\n\n## Next\nKeep this section bounded.\n",
            ".agents/new-policy.md": "# New policy\nUse scripts/agent/new-workflow.py.\n",
        },
    )
    context = built["agent-context"]
    sections = [node for node in context["nodes"] if node["file_type"] == "document-section"]
    assert {node["label"] for node in sections} == {"Policy", "Next", "New policy"}
    assert all(node["source_location"].startswith("L") and len(node["description"]) <= 500 for node in sections)
    refs = [edge for edge in context["links"] if edge["relation"] == "path-reference"]
    assert {edge["target_file"] for edge in refs} == {"src/app.py", "scripts/agent/new-workflow.py"}
    assert all(edge["evidence"] == "exact-path-literal" for edge in refs)


def test_agent_context_is_deterministic_for_reordered_inputs() -> None:
    config = _config()
    tracked = ["AGENTS.md", ".agents/new-policy.md", "src/app.py", "scripts/agent/new-workflow.py"]
    source_texts = {
        "AGENTS.md": "# Policy\nUse src/app.py.\n\n## Next\nKeep this section bounded.\n",
        ".agents/new-policy.md": "# New policy\nUse scripts/agent/new-workflow.py.\n",
    }
    first = views._augment_agent_context_graph({}, tracked, source_texts, config)
    second = views._augment_agent_context_graph({}, list(reversed(tracked)), source_texts, config)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_agent_context_ignores_fenced_headings_and_suffix_path_matches() -> None:
    config = _config()
    built = views.build_views(
        {},
        config,
        tracked_paths=["AGENTS.md", "src/app.py", "src/app.py.bak"],
        source_texts={
            "AGENTS.md": "# Visible heading\nUse src/app.py.bak.\n\n```text\n# Hidden heading\nsrc/app.py\n```\n",
        },
    )
    context = built["agent-context"]
    sections = [node for node in context["nodes"] if node["file_type"] == "document-section"]
    assert {node["label"] for node in sections} == {"Visible heading"}
    refs = [edge for edge in context["links"] if edge["relation"] == "path-reference"]
    assert {edge["target_file"] for edge in refs} == {"src/app.py.bak"}


def test_agent_context_sections_stay_owned_but_references_cross_views() -> None:
    config = _config()
    tracked = ["AGENTS.md", "tests/README.md", "src/vendor/README.md", "src/app.py"]
    built = views.build_views(
        {},
        config,
        tracked_paths=tracked,
        source_texts={
            "AGENTS.md": "# Agent policy\nSee tests/README.md and src/vendor/README.md.\n",
            "tests/README.md": "# Test documentation\nThis belongs to test-code.\n",
            "src/vendor/README.md": "# Vendor documentation\nThis belongs to vendor.\n",
        },
    )
    sections = [node for node in built["agent-context"]["nodes"] if node["file_type"] == "document-section"]
    assert {(node["source_file"], node["label"]) for node in sections} == {("AGENTS.md", "Agent policy")}
    refs = [edge for edge in built["agent-context"]["links"] if edge["relation"] == "path-reference"]
    assert {edge["target_file"] for edge in refs} == {"tests/README.md", "src/vendor/README.md"}


def test_agent_context_collapses_adapter_aliases_and_reuses_reference_nodes() -> None:
    duplicate_id = "claude_skills_example_skill"
    raw = {
        "nodes": [
            {
                "id": duplicate_id,
                "label": "Example skill",
                "source_file": ".agents/skills/example/SKILL.md",
            },
            {
                "id": duplicate_id,
                "label": "Example skill",
                "source_file": ".claude/skills/example/SKILL.md",
            },
        ],
        "links": [],
    }
    tracked = [
        ".agents/skills/example/SKILL.md",
        ".claude/skills/example/SKILL.md",
        "AGENTS.md",
        "src/app.py",
    ]
    built = views.build_views(
        raw,
        _config(),
        tracked_paths=tracked,
        source_texts={"AGENTS.md": "# One\nUse src/app.py.\n\n## Two\nRecheck src/app.py.\n"},
    )
    context = built["agent-context"]
    ids = [node["id"] for node in context["nodes"]]
    assert len(ids) == len(set(ids))
    skill = next(node for node in context["nodes"] if node["id"].endswith(duplicate_id))
    assert skill["source_aliases"] == [
        ".agents/skills/example/SKILL.md",
        ".claude/skills/example/SKILL.md",
    ]
    references = [node for node in context["nodes"] if node["id"].endswith("reference:src/app.py")]
    assert len(references) == 1


def test_synthetic_build_bridges_runtime_to_standin_and_namespaces_union() -> None:
    config = _config()
    built = views.build_views(
        _raw_graph(structural=True), config, tracked_paths=_paths(), source_texts=_texts(), built_at_commit="abc123"
    )

    runtime = built["runtime"]
    support = built["test-support"]
    bridge = built["bridge"]
    investigation = built["investigation"]
    whole = built["whole-repository"]
    assert {node["view"] for node in runtime["nodes"]} == {"runtime"}
    assert any(node["source_file"] == "tests/fixtures/fixture.json" for node in support["nodes"])
    structural = [edge for edge in bridge["links"] if edge["evidence"] == "structural-edge"]
    assert len(structural) == 1
    assert structural[0]["target"] == "test-support::standin-use"
    assert structural[0]["target_view"] == "test-support"
    assert structural[0]["source_file"] == "src/app.py"
    assert all(edge["source"] in {node["id"] for node in whole["nodes"]} for edge in bridge["links"])
    assert all(edge["target"] in {node["id"] for node in whole["nodes"]} for edge in bridge["links"])
    assert any(node.get("reference") and node["target_view"] == "test-support" for node in investigation["nodes"])
    ids = [node["id"] for node in whole["nodes"]]
    assert len(ids) == len(set(ids))
    assert all(graph.get("built_at_commit") == "abc123" for graph in built.values())


def test_new_standin_node_and_edge_are_discovered_without_config_changes() -> None:
    raw = _raw_graph(structural=True)
    raw["nodes"].append(
        {"id": "future-standin", "label": "new_dependency", "source_file": "tests/standins/new_standin.py"}
    )
    raw["links"].append({"source": "runtime-use", "target": "future-standin", "relation": "imports"})
    paths = [*_paths(), "tests/standins/new_standin.py"]
    built = views.build_views(raw, _config(), tracked_paths=paths, source_texts=_texts())
    assert views.classify_path("tests/standins/new_standin.py", _config()) == "test-support"
    assert any(
        edge["target_file"] == "tests/standins/new_standin.py" and edge["evidence"] == "structural-edge"
        for edge in built["bridge"]["links"]
    )
    assert any(
        node.get("source_file") == "tests/standins/new_standin.py" and node.get("reference")
        for node in built["investigation"]["nodes"]
    )


def test_structural_edge_is_evidence_backed_and_has_valid_bridge_endpoints() -> None:
    built = views.build_views(_raw_graph(structural=True), _config(), tracked_paths=_paths(), source_texts=_texts())
    structural = [edge for edge in built["bridge"]["links"] if edge["evidence"] == "structural-edge"]
    assert len(structural) == 1
    assert structural[0]["evidence_detail"] == "calls"
    bridge_ids = {node["id"] for node in built["bridge"]["nodes"]}
    assert structural[0]["source"] in bridge_ids
    assert structural[0]["target"] in bridge_ids
    assert set(built) == {
        "runtime",
        "tooling",
        "test-code",
        "test-support",
        "vendor",
        "agent-context",
        "bridge",
        "investigation",
        "whole-repository",
    }
    for graph in built.values():
        ids = [node["id"] for node in graph["nodes"]]
        assert len(ids) == len(set(ids))
        endpoints = set(ids)
        assert all(edge["source"] in endpoints and edge["target"] in endpoints for edge in graph["links"])


def test_duplicate_fixture_basename_has_no_literal_bridge() -> None:
    built = views.build_views(
        _raw_graph(duplicate_fixture=True),
        _config(),
        tracked_paths=_paths(duplicate_fixture=True),
        source_texts=_texts(duplicate_fixture=True),
    )
    assert not [edge for edge in built["bridge"]["links"] if edge["evidence"] == "literal-fixture"]


def test_fixture_nodes_from_one_source_file_share_one_literal_bridge() -> None:
    raw = _raw_graph()
    raw["nodes"].append(
        {"id": "fixture-symbol", "label": "fixture_loader", "source_file": "tests/fixtures/fixture.json"}
    )
    built = views.build_views(
        raw,
        _config(),
        tracked_paths=_paths(),
        source_texts=_texts(),
    )
    literal = [edge for edge in built["bridge"]["links"] if edge["evidence"] == "literal-fixture"]
    assert len(literal) == 1
    assert literal[0]["target_file"] == "tests/fixtures/fixture.json"


def test_python_literal_evidence_ignores_comments_docstrings_and_prose() -> None:
    raw = _raw_graph()
    for identifier, path in (
        ("doc-only", "tests/fixtures/doc-only.json"),
        ("comment-only", "tests/fixtures/comment-only.json"),
        ("prose-only", "tests/fixtures/prose-only.json"),
    ):
        raw["nodes"].append({"id": identifier, "label": path, "source_file": path})
    tracked = [
        *_paths(),
        "tests/fixtures/doc-only.json",
        "tests/fixtures/comment-only.json",
        "tests/fixtures/prose-only.json",
    ]
    built = views.build_views(
        raw,
        _config(),
        tracked_paths=tracked,
        source_texts={
            "tests/test_app.py": """\
\"\"\"doc-only.json\"\"\"
# comment-only.json
prose = \"prose-only.json\"
open(\"fixture.json\")
""",
        },
    )
    literal = [edge for edge in built["bridge"]["links"] if edge["evidence"] == "literal-fixture"]
    assert len(literal) == 1
    assert literal[0]["source_file"] == "tests/test_app.py"
    assert literal[0]["target_file"] == "tests/fixtures/fixture.json"


def test_support_definitions_group_by_file_and_investigation_filters_unrelated_hops() -> None:
    raw = {
        "nodes": [
            {"id": "runtime", "label": "pfb_alias_autocomplete_lists", "source_file": "src/app.py"},
            {"id": "double", "label": "config_get_path", "source_file": "tests/standins/firewall_standin.py"},
            {
                "id": "double-duplicate",
                "label": "config_get_path",
                "source_file": "tests/standins/firewall_standin.py",
                "source_location": "L20",
            },
            {"id": "stub", "label": "config_get_path", "source_file": "stubs/pfsense/config.php"},
            {"id": "test-reached", "label": "test_app", "source_file": "tests/test_app.py"},
            {"id": "test-unrelated", "label": "test_other", "source_file": "tests/test_other.py"},
            {"id": "fixture", "label": "fixture.json", "source_file": "tests/fixtures/fixture.json"},
            {"id": "other-fixture", "label": "other.json", "source_file": "tests/fixtures/other.json"},
        ],
        "links": [
            {"source": "runtime", "target": "test-reached", "relation": "covers"},
            {"source": "runtime", "target": "test-reached", "relation": "covers"},
            {"source": "runtime", "target": "double", "relation": "calls"},
            {"source": "runtime", "target": "stub", "relation": "calls"},
        ],
    }
    paths = [node["source_file"] for node in raw["nodes"]]
    built = views.build_views(
        raw,
        _config(),
        tracked_paths=paths,
        source_texts={
            "src/app.py": "config_get_path('aliases/alias')\n",
            "tests/test_app.py": "open('fixture.json')\n",
            "tests/test_other.py": "open('other.json')\n",
        },
    )
    bridge = built["bridge"]
    structural = [edge for edge in bridge["links"] if edge["evidence"] == "structural-edge"]
    assert {edge["target_file"] for edge in structural} >= {
        "tests/standins/firewall_standin.py",
        "stubs/pfsense/config.php",
    }
    assert len(structural) == 3
    keys = [(edge["source"], edge["target"], edge["evidence"], edge["evidence_detail"]) for edge in bridge["links"]]
    assert len(keys) == len(set(keys))
    literal = [edge for edge in bridge["links"] if edge["evidence"] == "literal-fixture"]
    assert {edge["source_file"] for edge in literal} == {"tests/test_app.py", "tests/test_other.py"}
    investigation = built["investigation"]
    investigation_keys = {
        (edge["source"], edge["target"], edge["evidence"], edge["evidence_detail"])
        for edge in investigation["links"]
        if edge.get("evidence")
    }
    assert any(edge["source_file"] == "tests/test_app.py" for edge in investigation["links"])
    assert not any(edge["source_file"] == "tests/test_other.py" for edge in investigation["links"])
    assert len(investigation["links"]) < len(bridge["links"])
    assert investigation_keys <= set(keys)


def _current_output_paths(root: Path) -> list[Path]:
    current = root / "current"
    return [
        current / "graph.json",
        current / "VIEW.json",
        *(
            current / name / filename
            for name in (
                "runtime",
                "tooling",
                "test-code",
                "test-support",
                "vendor",
                "agent-context",
                "bridge",
                "whole-repository",
            )
            for filename in ("graph.json", "VIEW.json")
        ),
    ]


def _generation_paths(root: Path) -> set[str]:
    generations = root / "generations"
    if not generations.exists():
        return set()
    return {path.name for path in generations.iterdir() if path.is_dir() and not path.name.startswith(".stage-")}


def _semantic_repo(tmp_path: Path, graph: dict | None = None) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "src").mkdir()
    (repo / "src/app.py").write_text("print('runtime')\n", encoding="utf-8")
    graph_root = repo / "graphify-out"
    graph_root.mkdir()
    (graph_root / "manifest.json").write_bytes(b"semantic-manifest\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Graphify test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "graphify-test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "add", "src/app.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "seed"], cwd=repo, check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    semantic_graph = dict(graph or {"nodes": [], "links": []})
    semantic_graph["built_at_commit"] = commit
    (graph_root / "graph.json").write_bytes((json.dumps(semantic_graph, sort_keys=True) + "\n").encode())
    return repo, commit


def _view_output_names() -> set[str]:
    return set(views.SOURCE_VIEWS + views.DERIVED_VIEWS)


def test_main_uses_semantic_root_and_publishes_views_without_mutating_semantic_state(tmp_path: Path) -> None:
    repo, commit = _semantic_repo(
        tmp_path,
        {"nodes": [{"id": "runtime", "label": "runtime", "source_file": "src/app.py"}], "links": []},
    )
    graph_path = repo / "graphify-out/graph.json"
    manifest_path = repo / "graphify-out/manifest.json"
    semantic_before = (graph_path.read_bytes(), manifest_path.read_bytes())

    assert views.main(["--repo-root", str(repo)]) == 0

    assert (graph_path.read_bytes(), manifest_path.read_bytes()) == semantic_before
    output = repo / "graphify-out/views"
    assert (output / "current/graph.json").is_file()
    assert (output / "current/VIEW.json").is_file()
    assert {path.name for path in (output / "current").iterdir()} >= _view_output_names() - {"investigation"}
    assert json.loads((output / "current/graph.json").read_text())["built_at_commit"] == commit
    assert not (repo / "graphify-out/current").exists()


def test_main_explicit_input_and_output_override_defaults(tmp_path: Path) -> None:
    repo, commit = _semantic_repo(tmp_path)
    explicit_input = tmp_path / "input.json"
    explicit_graph = {
        "nodes": [{"id": "runtime", "label": "explicit-input", "source_file": "src/app.py"}],
        "links": [],
        "built_at_commit": commit,
    }
    explicit_input.write_text(json.dumps(explicit_graph), encoding="utf-8")
    output = tmp_path / "explicit-output"

    assert views.main(["--repo-root", str(repo), "--input", str(explicit_input), "--output", str(output)]) == 0

    assert (output / "current/graph.json").is_file()
    assert json.loads((output / "current/graph.json").read_text())["built_at_commit"] == commit
    assert any(
        node.get("label") == "explicit-input"
        for node in json.loads((output / "current/runtime/graph.json").read_text())["nodes"]
    )
    assert not (repo / "graphify-out/views").exists()


def test_main_missing_default_semantic_graph_fails_before_output(tmp_path: Path) -> None:
    repo, _ = _semantic_repo(tmp_path)
    (repo / "graphify-out/graph.json").unlink()

    with pytest.raises(views.GraphifyViewsError, match="run the full Graphify skill"):
        views.main(["--repo-root", str(repo)])

    assert not (repo / "graphify-out/views").exists()


@pytest.mark.parametrize("symlink_default", [False, True])
def test_main_rejects_output_that_aliases_semantic_graph(tmp_path: Path, symlink_default: bool) -> None:
    repo, _ = _semantic_repo(tmp_path)
    semantic_graph = repo / "graphify-out/graph.json"
    manifest = repo / "graphify-out/manifest.json"
    before = (semantic_graph.read_bytes(), manifest.read_bytes())
    if symlink_default:
        (repo / "graphify-out/views").symlink_to(".")
        args = ["--repo-root", str(repo)]
    else:
        args = ["--repo-root", str(repo), "--output", str(repo / "graphify-out")]

    with pytest.raises(views.GraphifyViewsError, match="overlaps semantic graph"):
        views.main(args)

    assert (semantic_graph.read_bytes(), manifest.read_bytes()) == before
    assert not (repo / "graphify-out/current").exists()
    assert not (repo / "graphify-out/views/current").exists()


def test_main_rejects_canonical_output_alias_with_external_input(tmp_path: Path) -> None:
    repo, commit = _semantic_repo(tmp_path)
    canonical_graph = repo / "graphify-out/graph.json"
    manifest = repo / "graphify-out/manifest.json"
    explicit_input = tmp_path / "semantic-input.json"
    explicit_graph = {
        "nodes": [{"id": "runtime", "source_file": "src/app.py"}],
        "links": [],
        "built_at_commit": commit,
    }
    explicit_input.write_text(json.dumps(explicit_graph), encoding="utf-8")
    before = (canonical_graph.read_bytes(), manifest.read_bytes(), explicit_input.read_bytes())

    with pytest.raises(views.GraphifyViewsError, match="overlaps semantic graph"):
        views.main(["--repo-root", str(repo), "--input", str(explicit_input), "--output", str(repo / "graphify-out")])

    assert (canonical_graph.read_bytes(), manifest.read_bytes(), explicit_input.read_bytes()) == before
    assert not (repo / "graphify-out/current").exists()
    assert not (repo / "graphify-out/views").exists()


@pytest.mark.parametrize("staged", [False, True])
def test_main_rejects_dirty_tracked_tree_before_publication(tmp_path: Path, staged: bool) -> None:
    repo, _ = _semantic_repo(tmp_path)
    canonical_graph = repo / "graphify-out/graph.json"
    manifest = repo / "graphify-out/manifest.json"
    before = (canonical_graph.read_bytes(), manifest.read_bytes())
    source = repo / "src/app.py"
    source.write_text("print('dirty')\n", encoding="utf-8")
    if staged:
        subprocess.run(["git", "add", "src/app.py"], cwd=repo, check=True)

    with pytest.raises(views.GraphifyViewsError, match="tracked Git tree is dirty"):
        views.main(["--repo-root", str(repo)])

    assert (canonical_graph.read_bytes(), manifest.read_bytes()) == before
    assert not (repo / "graphify-out/views").exists()


@pytest.mark.parametrize("provenance", [None, "stale"])
def test_main_rejects_missing_or_stale_semantic_provenance(tmp_path: Path, provenance: str | None) -> None:
    repo, commit = _semantic_repo(tmp_path)
    graph_path = repo / "graphify-out/graph.json"
    graph = json.loads(graph_path.read_text())
    if provenance is None:
        graph.pop("built_at_commit")
    else:
        graph["built_at_commit"] = provenance
    graph_path.write_text(json.dumps(graph), encoding="utf-8")

    with pytest.raises(views.GraphifyViewsError, match="run the full Graphify skill"):
        views.main(["--repo-root", str(repo)])

    assert graph_path.is_file()
    assert not (repo / "graphify-out/views").exists()


@pytest.mark.parametrize(
    "graph",
    [
        {"built_at_commit": "current", "manifest": {}},
        {"built_at_commit": "current", "nodes": {}, "links": []},
        {"built_at_commit": "current", "nodes": [None], "links": []},
        {"built_at_commit": "current", "nodes": [{"id": "node"}], "links": [None]},
        {"built_at_commit": "current", "nodes": [{"id": ""}], "links": []},
        {"built_at_commit": "current", "nodes": [{"id": "node"}], "links": [{"source": "node"}]},
        {"built_at_commit": "current", "nodes": [{"id": "node"}], "links": [{"from": "node"}]},
        {"built_at_commit": "current", "nodes": [{"id": "node"}], "links": [{"source": "node", "to": "node"}]},
        {"built_at_commit": "current", "nodes": [{"id": "node"}], "links": [{"from": "node", "target": "node"}]},
    ],
)
def test_main_rejects_non_graph_semantic_inputs(tmp_path: Path, graph: dict) -> None:
    repo, commit = _semantic_repo(tmp_path)
    graph["built_at_commit"] = commit
    graph_path = repo / "graphify-out/graph.json"
    graph_path.write_text(json.dumps(graph), encoding="utf-8")

    with pytest.raises(views.GraphifyViewsError, match="semantic graph"):
        views.main(["--repo-root", str(repo)])

    assert not (repo / "graphify-out/views").exists()


def test_main_accepts_from_to_semantic_edges(tmp_path: Path) -> None:
    repo, _ = _semantic_repo(
        tmp_path,
        {
            "nodes": [
                {"id": "runtime", "source_file": "src/app.py"},
                {"id": "support", "source_file": "tests/standins/support.py"},
            ],
            "links": [{"from": "runtime", "to": "support"}],
        },
    )

    assert views.main(["--repo-root", str(repo)]) == 0
    assert (repo / "graphify-out/views/current/graph.json").is_file()


def test_write_outputs_switches_one_generation_and_malformed_config_preserves_it(tmp_path: Path) -> None:
    config = _config()
    built = views.build_views(_raw_graph(), config, tracked_paths=_paths(), source_texts=_texts())
    views.write_outputs(tmp_path, built, config)
    output_paths = _current_output_paths(tmp_path)
    before = {path: path.read_bytes() for path in output_paths}
    assert all(path.exists() for path in output_paths)
    assert (tmp_path / "current").is_symlink()
    assert (tmp_path / "graph.json").is_symlink()
    assert (tmp_path / "VIEW.json").is_symlink()
    assert json.loads((tmp_path / "VIEW.json").read_text())["view"] == "investigation"
    for name in (
        "runtime",
        "tooling",
        "test-code",
        "test-support",
        "vendor",
        "agent-context",
        "bridge",
        "whole-repository",
    ):
        metadata = json.loads((tmp_path / "current" / name / "VIEW.json").read_text())
        assert metadata["view"] == name
        assert metadata["purpose"]
        assert metadata["related_views"]
    malformed_kind = json.loads(json.dumps(config))
    next(row for row in malformed_kind["views"] if row["name"] == "runtime")["kind"] = "derived"
    malformed_support = json.loads(json.dumps(config))
    malformed_support["bridge"]["support_views"] = ["runtime"]
    malformed_missing_purpose = json.loads(json.dumps(config))
    next(row for row in malformed_missing_purpose["views"] if row["name"] == "runtime").pop("purpose")
    malformed_non_string_purpose = json.loads(json.dumps(config))
    next(row for row in malformed_non_string_purpose["views"] if row["name"] == "runtime")["purpose"] = 123
    malformed_blank_purpose = json.loads(json.dumps(config))
    next(row for row in malformed_blank_purpose["views"] if row["name"] == "runtime")["purpose"] = "  "
    malformed_missing_view = json.loads(json.dumps(config))
    malformed_missing_view["views"] = malformed_missing_view["views"][:-1]
    malformed_unknown_view = json.loads(json.dumps(config))
    next(row for row in malformed_unknown_view["views"] if row["name"] == "runtime")["name"] = "unknown"
    for malformed in (
        malformed_kind,
        malformed_support,
        malformed_missing_purpose,
        malformed_non_string_purpose,
        malformed_blank_purpose,
        malformed_missing_view,
        malformed_unknown_view,
    ):
        with pytest.raises(views.GraphifyViewsError):
            views.write_outputs(tmp_path, built, malformed)
        assert {path: path.read_bytes() for path in output_paths} == before


def test_generation_staging_and_pointer_failures_leave_current_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config()
    first = views.build_views(
        _raw_graph(), config, tracked_paths=_paths(), source_texts=_texts(), built_at_commit="old"
    )
    second = views.build_views(
        _raw_graph(), config, tracked_paths=_paths(), source_texts=_texts(), built_at_commit="new"
    )
    views.write_outputs(tmp_path, first, config)
    current = tmp_path / "current"
    old_target = current.readlink()
    output_paths = _current_output_paths(tmp_path)
    before = {path: path.read_bytes() for path in output_paths}
    generations_before = _generation_paths(tmp_path)

    original_write_text = Path.write_text
    writes = 0

    def fail_third_stage_write(
        path: Path,
        text: str,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> int:
        nonlocal writes
        if ".stage-" in path.as_posix():
            writes += 1
            if writes == 3:
                raise OSError("injected staging failure")
        return original_write_text(path, text, encoding=encoding, errors=errors, newline=newline)

    monkeypatch.setattr(Path, "write_text", fail_third_stage_write)
    with pytest.raises(OSError, match="staging failure"):
        views.write_outputs(tmp_path, second, config)
    assert current.readlink() == old_target
    assert {path: path.read_bytes() for path in output_paths} == before
    assert _generation_paths(tmp_path) == generations_before

    monkeypatch.setattr(Path, "write_text", original_write_text)
    original_replace_symlink = views._replace_symlink

    def fail_current_switch(link: Path, target: str) -> None:
        if link.name == "current":
            raise OSError("injected pointer failure")
        original_replace_symlink(link, target)

    monkeypatch.setattr(views, "_replace_symlink", fail_current_switch)
    with pytest.raises(OSError, match="pointer failure"):
        views.write_outputs(tmp_path, second, config)
    assert current.readlink() == old_target
    assert {path: path.read_bytes() for path in output_paths} == before
    assert _generation_paths(tmp_path) == generations_before


def test_malformed_compatibility_failure_does_not_publish_generation(tmp_path: Path) -> None:
    config = _config()
    first = views.build_views(_raw_graph(), config, tracked_paths=_paths(), source_texts=_texts())
    second = views.build_views(
        _raw_graph(), config, tracked_paths=_paths(), source_texts=_texts(), built_at_commit="new"
    )
    views.write_outputs(tmp_path, first, config)
    old_target = (tmp_path / "current").readlink()
    generations_before = _generation_paths(tmp_path)
    (tmp_path / "VIEW.json").unlink()
    (tmp_path / "VIEW.json").write_bytes(b"malformed compatibility")

    with pytest.raises(views.GraphifyViewsError, match="compatibility links"):
        views.write_outputs(tmp_path, second, config)

    assert (tmp_path / "current").readlink() == old_target
    assert (tmp_path / "VIEW.json").read_bytes() == b"malformed compatibility"
    assert _generation_paths(tmp_path) == generations_before


def test_successful_updates_keep_current_and_one_rollback_generation(tmp_path: Path) -> None:
    config = _config()
    for commit in ("one", "two", "three"):
        built = views.build_views(
            _raw_graph(), config, tracked_paths=_paths(), source_texts=_texts(), built_at_commit=commit
        )
        views.write_outputs(tmp_path, built, config)
    generations = [path for path in (tmp_path / "generations").iterdir() if path.is_dir()]
    assert len(generations) == 2
    assert (tmp_path / "current").resolve() in {path.resolve() for path in generations}


def test_legacy_output_migration_rolls_back_compatibility_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_graph = b'{"generation":"old"}\n'
    old_view = b'{"view":"legacy"}\n'
    (tmp_path / "graph.json").write_bytes(old_graph)
    (tmp_path / "VIEW.json").write_bytes(old_view)
    built = views.build_views(_raw_graph(), _config(), tracked_paths=_paths(), source_texts=_texts())
    generations_before = _generation_paths(tmp_path)
    original_replace_symlink = views._replace_symlink
    failed = False

    def fail_view_link_once(link: Path, target: str) -> None:
        nonlocal failed
        if link.name == "VIEW.json" and not failed:
            failed = True
            raise OSError("injected compatibility failure")
        original_replace_symlink(link, target)

    monkeypatch.setattr(views, "_replace_symlink", fail_view_link_once)
    with pytest.raises(OSError, match="compatibility failure"):
        views.write_outputs(tmp_path, built, _config())
    assert (tmp_path / "graph.json").read_bytes() == old_graph
    assert (tmp_path / "VIEW.json").read_bytes() == old_view
    assert _generation_paths(tmp_path) == generations_before
    assert not list((tmp_path / "generations").glob("legacy-*"))

    monkeypatch.setattr(views, "_replace_symlink", original_replace_symlink)
    views.write_outputs(tmp_path, built, _config())
    assert (tmp_path / "current").is_symlink()
    assert json.loads((tmp_path / "graph.json").read_text())["nodes"]
