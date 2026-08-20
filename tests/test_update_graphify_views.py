"""Tests for the declarative Graphify ownership and reference views."""

from __future__ import annotations

import importlib.util
import json
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
    assert views.classify_path("support/fixtures/not-a-test-fixture.json", config) is None


def test_extraction_input_excludes_unclassified_files_and_keeps_artifact_nodes(tmp_path: Path) -> None:
    config = _config()
    accepted = [
        "src/app.py",
        "tests/fixtures/data.bin",
        "tools/webassets/patches/upstream.patch",
    ]
    unclassified = ".claude/hooks/session-branch-sync.sh"
    for relative in (*accepted, unclassified):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("placeholder", encoding="utf-8")
    calls: list[Path] = []

    def collect(target: Path, *, root: Path) -> list[Path]:
        calls.append(target)
        return [target]

    extracted = views._collect_graphify_paths(tmp_path, [*accepted, unclassified], config, collector=collect)
    assert extracted == [tmp_path / relative for relative in accepted]
    assert unclassified not in {path.relative_to(tmp_path).as_posix() for path in calls}
    built = views.build_views({}, config, tracked_paths=accepted)
    assert all(unclassified not in node.get("source_file", "") for node in built["whole-repository"]["nodes"])
    assert {node["source_file"] for node in built["whole-repository"]["nodes"]} >= set(accepted)


def test_synthetic_build_bridges_runtime_to_standin_and_namespaces_union() -> None:
    config = _config()
    built = views.build_views(
        _raw_graph(), config, tracked_paths=_paths(), source_texts=_texts(), built_at_commit="abc123"
    )

    runtime = built["runtime"]
    support = built["test-support"]
    bridge = built["bridge"]
    investigation = built["investigation"]
    whole = built["whole-repository"]
    assert {node["view"] for node in runtime["nodes"]} == {"runtime"}
    assert any(node["source_file"] == "tests/fixtures/fixture.json" for node in support["nodes"])
    exact = [edge for edge in bridge["links"] if edge["evidence"] == "exact-symbol"]
    assert len(exact) == 1
    assert exact[0]["evidence_detail"] == "config_get_path"
    assert exact[0]["source"] == "runtime::runtime-use"
    assert exact[0]["target_view"] == "test-support"
    assert exact[0]["source_file"] == "src/app.py"
    assert all(edge["source"] in {node["id"] for node in whole["nodes"]} for edge in bridge["links"])
    assert all(edge["target"] in {node["id"] for node in whole["nodes"]} for edge in bridge["links"])
    assert any(node.get("reference") and node["target_view"] == "test-support" for node in investigation["nodes"])
    ids = [node["id"] for node in whole["nodes"]]
    assert len(ids) == len(set(ids))
    assert all(graph.get("built_at_commit") == "abc123" for graph in built.values())


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
    exact = [edge for edge in bridge["links"] if edge["evidence"] == "exact-symbol"]
    assert {edge["target_file"] for edge in exact} == {
        "tests/standins/firewall_standin.py",
        "stubs/pfsense/config.php",
    }
    assert len(exact) == 2
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


def test_common_and_short_identifiers_do_not_fan_out() -> None:
    raw = {
        "nodes": [
            {"id": "r", "label": "run", "source_file": "src/app.py"},
            {"id": "s", "label": "run", "source_file": "tests/doubles/app_double.py"},
            {"id": "r2", "label": "tiny", "source_file": "src/tiny.py"},
            {"id": "s2", "label": "tiny", "source_file": "tests/doubles/tiny_double.py"},
        ],
        "links": [],
    }
    built = views.build_views(
        raw,
        _config(),
        tracked_paths=["src/app.py", "tests/doubles/app_double.py", "src/tiny.py", "tests/doubles/tiny_double.py"],
        source_texts={"src/app.py": "run()", "src/tiny.py": "tiny()"},
    )
    assert not [edge for edge in built["bridge"]["links"] if edge["evidence"] == "exact-symbol"]


def test_write_outputs_replaces_graphs_and_malformed_config_preserves_them(tmp_path: Path) -> None:
    config = _config()
    built = views.build_views(_raw_graph(), config, tracked_paths=_paths(), source_texts=_texts())
    views.write_outputs(tmp_path, built, config)
    output_paths = [
        tmp_path / "graph.json",
        tmp_path / "VIEW.json",
        *(
            tmp_path / name / filename
            for name in ("runtime", "tooling", "test-code", "test-support", "vendor", "bridge", "whole-repository")
            for filename in ("graph.json", "VIEW.json")
        ),
    ]
    before = {path: path.read_bytes() for path in output_paths}
    assert all(path.exists() for path in output_paths)
    assert json.loads((tmp_path / "VIEW.json").read_text())["view"] == "investigation"
    for name in ("runtime", "tooling", "test-code", "test-support", "vendor", "bridge", "whole-repository"):
        metadata = json.loads((tmp_path / name / "VIEW.json").read_text())
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
