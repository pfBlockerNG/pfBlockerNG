#!/usr/bin/env python3
"""Build Graphify's ownership-separated views from one extraction.

The ownership map is deliberately data, not Python.  Classification is first-match
ordered, while bridge and investigation graphs are derived from the same namespaced
source graphs on every run.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import fnmatch
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = Path(__file__).with_name("graphify-views.json")
SOURCE_VIEWS = ("runtime", "tooling", "test-code", "test-support", "vendor", "agent-context")
DERIVED_VIEWS = ("bridge", "investigation", "whole-repository")
ALL_VIEWS = SOURCE_VIEWS + ("unclassified",) + DERIVED_VIEWS


class GraphifyViewsError(ValueError):
    """Invalid ownership input or graph data."""


class BootstrapError(RuntimeError):
    """Graphify is not available for extraction."""


def _path(value: str | Path) -> str:
    text = str(value).replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/") if not Path(text).is_absolute() else text


def load_config(path: str | Path = CONFIG_PATH) -> dict[str, Any]:
    """Read and validate the declarative ownership map before any output writes."""

    try:
        config = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GraphifyViewsError(f"cannot read ownership config {path}: {exc}") from exc
    validate_config(config)
    return config


def validate_config(config: Mapping[str, Any]) -> None:
    """Reject malformed maps and ambiguous view definitions."""

    if not isinstance(config, Mapping) or config.get("schema_version") != 1:
        raise GraphifyViewsError("ownership config requires schema_version 1")
    rows = config.get("views")
    if not isinstance(rows, list):
        raise GraphifyViewsError("ownership config views must be a list")
    names: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise GraphifyViewsError("each ownership view must be an object")
        name = row.get("name")
        kind = row.get("kind")
        if not isinstance(name, str) or name not in ALL_VIEWS:
            raise GraphifyViewsError(f"unknown ownership view: {name!r}")
        if name in names:
            raise GraphifyViewsError(f"duplicate ownership view: {name}")
        if kind not in ("source", "derived"):
            raise GraphifyViewsError(f"invalid kind for view {name}: {kind!r}")
        if not isinstance(row.get("purpose"), str) or not row["purpose"].strip():
            raise GraphifyViewsError(f"view {name} requires a non-empty purpose")
        if name in SOURCE_VIEWS and kind != "source":
            raise GraphifyViewsError(f"source view {name} must have kind source")
        if name in DERIVED_VIEWS and kind != "derived":
            raise GraphifyViewsError(f"derived view {name} must have kind derived")
        if name == "unclassified" and (kind != "source" or row.get("fail_closed") is not True):
            raise GraphifyViewsError("unclassified must be a fail-closed source view")
        names.append(name)
        rules = row.get("rules")
        if not isinstance(rules, Mapping):
            raise GraphifyViewsError(f"view {name} rules must be an object")
        for key in rules:
            if key not in ("path_globs", "file_globs"):
                raise GraphifyViewsError(f"unknown rule key for {name}: {key}")
            values = rules[key]
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                raise GraphifyViewsError(f"view {name} {key} must be a string list")
        if (
            kind == "source"
            and name in SOURCE_VIEWS
            and not rules.get("path_globs")
            and not rules.get("file_globs")
            and name != "unclassified"
        ):
            raise GraphifyViewsError(f"source view {name} has no rules")
        if kind == "derived" and name in DERIVED_VIEWS and (rules.get("path_globs") or rules.get("file_globs")):
            raise GraphifyViewsError(f"derived view {name} cannot classify paths")
    missing = set(ALL_VIEWS) - set(names)
    if missing:
        raise GraphifyViewsError(f"ownership config is missing views: {', '.join(sorted(missing))}")
    source_order = [row["name"] for row in rows if row["kind"] == "source"]
    if source_order != ["vendor", "test-support", "test-code", "agent-context", "tooling", "runtime", "unclassified"]:
        raise GraphifyViewsError("source ownership views must retain canonical first-match order")
    bridge = config.get("bridge")
    if not isinstance(bridge, Mapping):
        raise GraphifyViewsError("ownership config bridge must be an object")
    support_views = bridge.get("support_views")
    if (
        not isinstance(support_views, list)
        or not all(isinstance(item, str) for item in support_views)
        or len(support_views) != len(set(support_views))
    ):
        raise GraphifyViewsError("bridge support_views must be a unique string list")
    allowed_support = set(SOURCE_VIEWS) - {"runtime", "test-code"}
    if not all(isinstance(item, str) and item in allowed_support for item in support_views) or not {
        "test-support",
        "vendor",
        "tooling",
    }.issubset(support_views):
        raise GraphifyViewsError("bridge support_views must include only configured support source views")
    if bridge.get("runtime_view") != "runtime" or bridge.get("test_view") != "test-code":
        raise GraphifyViewsError("bridge runtime_view/test_view must be runtime/test-code")


def _matches(path: str, rules: Mapping[str, Any]) -> bool:
    for pattern in rules.get("path_globs", []):
        if fnmatch.fnmatchcase(path, pattern):
            return True
    for pattern in rules.get("file_globs", []):
        if fnmatch.fnmatchcase(path, pattern):
            return True
    return False


def _classify_path_unchecked(path: str | Path, config: Mapping[str, Any]) -> str | None:
    normalized = _path(path)
    for row in config["views"]:
        if row["kind"] == "source" and _matches(normalized, row["rules"]):
            return str(row["name"])
    return None


def classify_path(path: str | Path, config: Mapping[str, Any]) -> str | None:
    """Return the first matching source view; ``None`` is fail-closed."""

    validate_config(config)
    return _classify_path_unchecked(path, config)


def partition_paths(paths: Iterable[str | Path], config: Mapping[str, Any]) -> dict[str, list[str]]:
    """Partition paths using config order and reject every unknown path."""

    validate_config(config)
    result: dict[str, list[str]] = {name: [] for name in SOURCE_VIEWS}
    for raw in paths:
        path = _path(raw)
        owner = _classify_path_unchecked(path, config)
        if owner not in result:
            raise GraphifyViewsError(f"unclassified tracked path: {path}")
        result[owner].append(path)
    for paths_for_view in result.values():
        paths_for_view.sort()
    return result


def _links(graph: Mapping[str, Any]) -> list[dict[str, Any]]:
    value = graph.get("links", graph.get("edges", []))
    if not isinstance(value, list):
        raise GraphifyViewsError("graph links must be a list")
    return [dict(link) for link in value if isinstance(link, Mapping)]


def _nodes(graph: Mapping[str, Any]) -> list[dict[str, Any]]:
    value = graph.get("nodes", [])
    if not isinstance(value, list):
        raise GraphifyViewsError("graph nodes must be a list")
    return [dict(node) for node in value if isinstance(node, Mapping) and node.get("id") is not None]


def _endpoint(edge: Mapping[str, Any], side: str) -> str | None:
    value = edge.get(side)
    if value is None:
        value = edge.get("from" if side == "source" else "to")
    return str(value) if value is not None else None


def _graph(
    nodes: Iterable[Mapping[str, Any]],
    links: Iterable[Mapping[str, Any]],
    *,
    directed: bool = False,
) -> dict[str, Any]:
    return {
        "directed": directed,
        "multigraph": True,
        "graph": {},
        "hyperedges": [],
        "nodes": [dict(node) for node in nodes],
        "links": [dict(link) for link in links],
    }


def _file_node_id(path: str) -> str:
    return "file:" + path


def _owner_nodes(
    raw_graph: Mapping[str, Any], config: Mapping[str, Any]
) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    owners: dict[str, str] = {}
    nodes: dict[str, dict[str, Any]] = {}
    prefixes, ambiguous = _source_prefixes(raw_graph, config)
    for node in _nodes(raw_graph):
        node_id = str(node["id"])
        owner = _node_owner(node, config, prefixes, ambiguous)
        if owner not in SOURCE_VIEWS:
            continue
        owners[node_id] = str(owner)
        nodes[node_id] = node
    return owners, nodes


def _namespace(view: str, node_id: str) -> str:
    return f"{view}::{node_id}"


def _graphify_id_prefix(source_file: str) -> str:
    stem = str(Path(source_file).with_suffix(""))
    return re.sub(r"\W+", "_", stem).strip("_").casefold()


def _source_prefixes(
    raw_graph: Mapping[str, Any], config: Mapping[str, Any]
) -> tuple[dict[str, tuple[str, str]], set[str]]:
    prefixes: dict[str, tuple[str, str]] = {}
    ambiguous: set[str] = set()
    for node in _nodes(raw_graph):
        source = str(node.get("source_file", ""))
        owner = _classify_path_unchecked(source, config) if source else None
        if owner in SOURCE_VIEWS:
            prefix = _graphify_id_prefix(source)
            if prefix in ambiguous:
                continue
            existing = prefixes.get(prefix)
            if existing is None:
                prefixes[prefix] = (owner, source)
            elif existing[0] != owner or existing[1] != source:
                prefixes.pop(prefix, None)
                ambiguous.add(prefix)
    return prefixes, ambiguous


def _node_owner(
    node: Mapping[str, Any],
    config: Mapping[str, Any],
    prefixes: Mapping[str, tuple[str, str]],
    ambiguous: set[str],
) -> str | None:
    source = str(node.get("source_file", ""))
    if source:
        owner = _classify_path_unchecked(source, config)
        return owner if owner in SOURCE_VIEWS else None
    owner = node.get("view") or node.get("ownership")
    if owner in SOURCE_VIEWS:
        return str(owner)
    node_id = str(node.get("id", ""))
    matches = [prefix for prefix in prefixes if node_id == prefix or node_id.startswith(prefix + "_")]
    if any(prefix in ambiguous for prefix in matches):
        return None
    if not matches:
        return None
    return prefixes[max(matches, key=len)][0]


def namespace_graph(graph: Mapping[str, Any], view: str) -> dict[str, Any]:
    """Namespace every node and edge so equal labels remain distinct by view."""

    nodes_by_id: dict[str, dict[str, Any]] = {}
    ids: set[str] = set()
    for node in _nodes(graph):
        old = str(node["id"])
        if old in nodes_by_id:
            existing = nodes_by_id[old]
            if existing.get("label") != node.get("label"):
                raise GraphifyViewsError(f"conflicting duplicate node id: {old}")
            aliases = {
                str(source)
                for source in (
                    existing.get("source_file"),
                    node.get("source_file"),
                    *existing.get("source_aliases", []),
                )
                if source
            }
            existing["source_aliases"] = sorted(aliases)
            if str(node.get("source_file", "")) < str(existing.get("source_file", "")):
                existing["source_file"] = node.get("source_file")
            continue
        new = dict(node)
        new["id"] = _namespace(view, old)
        new["view"] = view
        new["ownership"] = view
        nodes_by_id[old] = new
        ids.add(old)
    links: list[dict[str, Any]] = []
    for edge in _links(graph):
        source = _endpoint(edge, "source")
        target = _endpoint(edge, "target")
        if source not in ids or target not in ids:
            continue
        new_edge = dict(edge)
        new_edge["source"] = _namespace(view, str(source))
        new_edge["target"] = _namespace(view, str(target))
        new_edge.pop("from", None)
        new_edge.pop("to", None)
        links.append(new_edge)
    return _graph(nodes_by_id.values(), links, directed=bool(graph.get("directed", False)))


def _select_source_graph(
    raw_graph: Mapping[str, Any], view: str, config: Mapping[str, Any], tracked: Sequence[str]
) -> dict[str, Any]:
    selected: list[dict[str, Any]] = []
    prefixes, ambiguous = _source_prefixes(raw_graph, config)
    for node in _nodes(raw_graph):
        owner = _node_owner(node, config, prefixes, ambiguous)
        if owner == view:
            selected.append(node)
    ids = {str(node["id"]) for node in selected}
    selected_links = []
    for edge in _links(raw_graph):
        source = _endpoint(edge, "source")
        target = _endpoint(edge, "target")
        if source in ids and target in ids:
            selected_links.append(edge)
    known = {_path(str(node["source_file"])) for node in selected if node.get("source_file")}
    for path in tracked:
        if path not in known:
            selected.append(
                {
                    "id": _file_node_id(path),
                    "label": path,
                    "file_type": "file",
                    "source_file": path,
                    "source_location": None,
                    "ownership": view,
                    "view": view,
                }
            )
    return _graph(selected, selected_links, directed=bool(raw_graph.get("directed", False)))


def _augment_agent_context_graph(
    graph: dict[str, Any],
    tracked: Sequence[str],
    source_texts: Mapping[str, str],
    config: Mapping[str, Any],
) -> dict[str, Any]:
    tracked_paths = sorted(set(tracked))
    nodes = _nodes(graph)
    links = _links(graph)
    by_source = _representatives_by_source(nodes)
    node_ids = {str(node["id"]) for node in nodes}
    for path in tracked_paths:
        if _classify_path_unchecked(path, config) != "agent-context":
            continue
        if Path(path).suffix.lower() not in (".md", ".mdx"):
            continue
        text = source_texts.get(path, "")
        if not text:
            continue
        headings: list[tuple[int, str, str]] = []
        visible_lines: list[tuple[int, str]] = []
        fence: str | None = None
        for line_number, line in enumerate(text.splitlines(), 1):
            fence_match = re.match(r"^\s*(`{3,}|~{3,})", line)
            if fence_match:
                marker = fence_match.group(1)[0]
                if fence is None:
                    fence = marker
                elif marker == fence:
                    fence = None
                continue
            if fence is None:
                visible_lines.append((line_number, line))
        for line_number, line in visible_lines:
            match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
            if match:
                headings.append((line_number, match.group(2), match.group(1)))
        for index, (line_number, title, marks) in enumerate(headings):
            end = headings[index + 1][0] if index + 1 < len(headings) else None
            description = " ".join(
                line.strip()
                for visible_number, line in visible_lines
                if visible_number > line_number and (end is None or visible_number < end) and line.strip()
            )[:500]
            node_id = f"section:{path}:L{line_number}"
            nodes.append(
                {
                    "id": node_id,
                    "label": title,
                    "file_type": "document-section",
                    "source_file": path,
                    "source_location": f"L{line_number}",
                    "section_level": len(marks),
                    "description": description,
                    "view": "agent-context",
                    "ownership": "agent-context",
                }
            )
            node_ids.add(node_id)
        section_for_line = [(line, f"section:{path}:L{line}") for line, _, _ in headings]
        for target in tracked_paths:
            if target == path:
                continue
            target_owner = _classify_path_unchecked(target, config)
            if target_owner is None:
                continue
            target_pattern = re.compile(rf"(?<![A-Za-z0-9_/-]){re.escape(target)}(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_/-])")
            occurrence_line = next(
                (line_number for line_number, line in visible_lines if target_pattern.search(line)),
                None,
            )
            if occurrence_line is None:
                continue
            target_node = by_source.get(target)
            if target_node is None:
                target_id = f"reference:{target}"
                target_node = {
                    "id": target_id,
                    "label": target,
                    "file_type": "file-reference",
                    "source_file": target,
                    "source_location": None,
                    "view": "agent-context",
                    "ownership": "agent-context",
                    "target_view": target_owner,
                    "reference": True,
                }
                nodes.append(target_node)
                node_ids.add(target_id)
                by_source[target] = target_node
            else:
                target_id = str(target_node["id"])
            section_id = next(
                (node_id for line, node_id in reversed(section_for_line) if line <= occurrence_line),
                str(by_source.get(path, {}).get("id", _file_node_id(path))),
            )
            edge = {
                "source": section_id,
                "target": target_id,
                "relation": "path-reference",
                "evidence": "exact-path-literal",
                "source_file": path,
                "target_file": target,
                "target_view": target_owner,
                "ownership": "agent-context",
            }
            if (
                section_id in node_ids
                and target_id in node_ids
                and not any(
                    existing.get("source") == section_id
                    and existing.get("target") == target_id
                    and existing.get("relation") == "path-reference"
                    for existing in links
                )
            ):
                links.append(edge)
    return _graph(nodes, links, directed=True)


def _source_line(node: Mapping[str, Any]) -> int:
    value = str(node.get("source_location", ""))
    match = re.search(r"\d+", value)
    return int(match.group()) if match else 0


def _representative(nodes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Choose one stable node for a source file, preferring file nodes."""
    return min(
        (dict(node) for node in nodes),
        key=lambda node: (
            0 if node.get("file_type") == "file" else 1,
            _source_line(node),
            str(node.get("id", "")),
        ),
    )


def _representatives_by_source(
    nodes: Iterable[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for node in nodes:
        source = _path(str(node.get("source_file", "")))
        if source:
            grouped.setdefault(source, []).append(node)
    return {source: _representative(items) for source, items in grouped.items()}


def _python_call_string_literals(text: str) -> list[str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    literals: list[str] = []
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        arguments = [*call.args, *(keyword.value for keyword in call.keywords)]
        literals.extend(
            str(argument.value)
            for argument in arguments
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str)
        )
    return literals


def _bridge_edge(
    source: Mapping[str, Any],
    target: Mapping[str, Any],
    *,
    evidence: str,
    confidence: str,
    detail: str,
) -> dict[str, Any]:
    source_view = str(source["view"])
    target_view = str(target["view"])
    return {
        "source": _namespace(source_view, str(source["id"])),
        "target": _namespace(target_view, str(target["id"])),
        "relation": "reference",
        "ownership": source_view,
        "target_view": target_view,
        "source_file": str(source.get("source_file", "")),
        "target_file": str(target.get("source_file", "")),
        "evidence": evidence,
        "evidence_detail": detail,
        "confidence": confidence,
    }


def derive_bridges(
    raw_graph: Mapping[str, Any],
    source_graphs: Mapping[str, Mapping[str, Any]],
    config: Mapping[str, Any],
    source_texts: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Derive only structural and syntactic literal evidence."""

    validate_config(config)
    source_texts = {_path(key): value for key, value in (source_texts or {}).items()}
    owners, raw_nodes = _owner_nodes(raw_graph, config)
    nodes_by_view: dict[str, list[dict[str, Any]]] = {view: [] for view in SOURCE_VIEWS}
    for view, graph in source_graphs.items():
        for node in _nodes(graph):
            item = dict(node)
            item["view"] = view
            item["ownership"] = view
            nodes_by_view.setdefault(view, []).append(item)
    bridge_links: list[dict[str, Any]] = []
    bridge_nodes: dict[str, dict[str, Any]] = {}
    bridge_keys: set[tuple[str, str, str, str]] = set()

    def add(
        source: Mapping[str, Any],
        target: Mapping[str, Any],
        *,
        evidence: str,
        confidence: str,
        detail: str,
    ) -> None:
        edge = _bridge_edge(source, target, evidence=evidence, confidence=confidence, detail=detail)
        key = (edge["source"], edge["target"], evidence, detail)
        if key in bridge_keys:
            return
        bridge_keys.add(key)
        bridge_links.append(edge)
        for item in (source, target):
            view = str(item["view"])
            node = dict(item)
            node["id"] = _namespace(view, str(item["id"]))
            node["view"] = view
            node["ownership"] = view
            bridge_nodes[node["id"]] = node

    raw_by_id = raw_nodes
    for edge in _links(raw_graph):
        source_id = _endpoint(edge, "source")
        target_id = _endpoint(edge, "target")
        if source_id not in owners or target_id not in owners or owners[source_id] == owners[target_id]:
            continue
        source = dict(raw_by_id[source_id])
        target = dict(raw_by_id[target_id])
        source["view"] = owners[source_id]
        target["view"] = owners[target_id]
        add(source, target, evidence="structural-edge", confidence="high", detail=str(edge.get("relation", "edge")))

    support_files: dict[str, dict[str, dict[str, Any]]] = {}
    for support_source, node in _representatives_by_source(nodes_by_view.get("test-support", [])).items():
        support_files.setdefault(Path(support_source).name, {})[support_source] = node
    test_files = _representatives_by_source(nodes_by_view.get("test-code", []))
    support_by_path = {source: node for candidates in support_files.values() for source, node in candidates.items()}
    for test_file, test in test_files.items():
        if Path(test_file).suffix.lower() != ".py":
            continue
        text = source_texts.get(test_file, "")
        if not text:
            continue
        for literal in _python_call_string_literals(text):
            literal_path = _path(literal)
            candidate_sources = support_files.get(Path(literal_path).name, {})
            if literal_path in support_by_path:
                candidate_sources = {literal_path: support_by_path[literal_path]}
            if len(candidate_sources) != 1:
                continue
            basename = next(iter(candidate_sources))
            add(
                test,
                next(iter(candidate_sources.values())),
                evidence="literal-fixture",
                confidence="medium",
                detail=basename,
            )
    return _graph(bridge_nodes.values(), bridge_links, directed=True)


def _union_graphs(graphs: Iterable[Mapping[str, Any]], links: Iterable[Mapping[str, Any]] = ()) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    all_links: list[dict[str, Any]] = []
    for graph in graphs:
        for node in _nodes(graph):
            nodes[str(node["id"])] = dict(node)
        all_links.extend(_links(graph))
    all_links.extend(dict(link) for link in links)
    valid = set(nodes)
    all_links = [
        link for link in all_links if _endpoint(link, "source") in valid and _endpoint(link, "target") in valid
    ]
    return _graph(nodes.values(), all_links, directed=True)


def build_views(
    raw_graph: Mapping[str, Any],
    config: Mapping[str, Any],
    *,
    tracked_paths: Iterable[str | Path] = (),
    source_texts: Mapping[str, str] | None = None,
    built_at_commit: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Build every graph fully in memory; no output is touched by this function."""

    validate_config(config)
    paths = partition_paths(tracked_paths, config)
    all_tracked = [path for view_paths in paths.values() for path in view_paths]
    source_graphs: dict[str, dict[str, Any]] = {}
    for view in SOURCE_VIEWS:
        selected = _select_source_graph(raw_graph, view, config, paths[view])
        if view == "agent-context":
            selected = _augment_agent_context_graph(selected, all_tracked, source_texts or {}, config)
        source_graphs[view] = namespace_graph(selected, view)
    # Bridge derivation needs unnamespaced source IDs and ownership annotations.
    raw_sources: dict[str, dict[str, Any]] = {}
    for view in SOURCE_VIEWS:
        raw_sources[view] = _select_source_graph(raw_graph, view, config, paths[view])
    bridge = derive_bridges(raw_graph, raw_sources, config, source_texts)
    whole = _union_graphs(source_graphs.values(), _links(bridge))
    investigation_nodes = list(_nodes(source_graphs["runtime"]))
    investigation_ids = {str(node["id"]) for node in investigation_nodes}
    bridge_nodes_by_id = {str(node["id"]): node for node in _nodes(bridge)}
    bridge_links = _links(bridge)
    runtime_bridge_links = [
        edge
        for edge in bridge_links
        if _endpoint(edge, "source") in investigation_ids or _endpoint(edge, "target") in investigation_ids
    ]
    reached_ids = set(investigation_ids)
    reached_ids.update(
        endpoint
        for edge in runtime_bridge_links
        for endpoint in (_endpoint(edge, "source"), _endpoint(edge, "target"))
        if endpoint is not None
    )
    literal_hops = [
        edge
        for edge in bridge_links
        if edge.get("evidence") == "literal-fixture"
        and (
            (
                _endpoint(edge, "source") in reached_ids
                and bridge_nodes_by_id.get(str(_endpoint(edge, "source")), {}).get("view") == "test-code"
            )
            or (
                _endpoint(edge, "target") in reached_ids
                and bridge_nodes_by_id.get(str(_endpoint(edge, "target")), {}).get("view") == "test-code"
            )
        )
    ]
    selected_bridge_links = runtime_bridge_links + literal_hops
    selected_ids = {
        endpoint
        for edge in selected_bridge_links
        for endpoint in (_endpoint(edge, "source"), _endpoint(edge, "target"))
        if endpoint is not None
    }
    for node_id in selected_ids:
        if node_id not in investigation_ids and node_id in bridge_nodes_by_id:
            item = dict(bridge_nodes_by_id[node_id])
            item["reference"] = True
            item["target_view"] = item.get("view")
            investigation_nodes.append(item)
            investigation_ids.add(node_id)
    investigation_links = list(_links(source_graphs["runtime"])) + selected_bridge_links
    investigation = _graph(investigation_nodes, investigation_links, directed=True)
    views: dict[str, dict[str, Any]] = {
        **source_graphs,
        "bridge": bridge,
        "investigation": investigation,
        "whole-repository": whole,
    }
    if built_at_commit:
        for graph in views.values():
            graph["built_at_commit"] = built_at_commit
    return views


def _view_row(config: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    return next(row for row in config["views"] if row["name"] == name)


def _view_metadata(config: Mapping[str, Any], name: str, graph: Mapping[str, Any]) -> dict[str, Any]:
    row = _view_row(config, name)
    if row["kind"] == "source":
        includes = list(row["rules"].get("path_globs", [])) + list(row["rules"].get("file_globs", []))
        excludes = [f"{other}/**" for other in SOURCE_VIEWS if other != name]
    else:
        includes = list(row["rules"].get("path_globs", []))
        excludes = []
    related = [view for view in ALL_VIEWS if view != name and view != "unclassified"]
    return {
        "view": name,
        "purpose": row["purpose"],
        "includes": includes,
        "excludes": excludes,
        "related_views": related,
        "built_at_commit": graph.get("built_at_commit"),
        "nodes": len(_nodes(graph)),
        "edges": len(_links(graph)),
    }


def _replace_symlink(link: Path, target: str) -> None:
    """Atomically replace one relative symlink."""

    temporary = link.with_name(f".{link.name}.{uuid.uuid4().hex}.tmp")
    temporary.unlink(missing_ok=True)
    os.symlink(target, temporary)
    try:
        os.replace(temporary, link)
    finally:
        temporary.unlink(missing_ok=True)


def _restore_regular_file(path: Path, source: Path) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    shutil.copy2(source, temporary)
    os.replace(temporary, path)


def _prune_generations(generations: Path, current: Path) -> None:
    """Keep the published generation and one rollback generation."""

    active = current.resolve()
    candidates = sorted(
        (path for path in generations.iterdir() if path.is_dir() and not path.name.startswith(".stage-")),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    keep = {active}
    keep.update(path.resolve() for path in candidates if path.resolve() != active and len(keep) < 2)
    for path in candidates:
        if path.resolve() not in keep:
            with contextlib.suppress(OSError):
                shutil.rmtree(path)


def write_outputs(
    output_root: str | Path,
    views: Mapping[str, Mapping[str, Any]],
    config: Mapping[str, Any],
) -> None:
    """Stage one generation, then publish it with one ``current`` switch."""

    validate_config(config)
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    payloads: dict[Path, str] = {}
    for name, graph in views.items():
        if name not in SOURCE_VIEWS + DERIVED_VIEWS:
            raise GraphifyViewsError(f"unexpected output view: {name}")
        graph_text = json.dumps(dict(graph), indent=2, sort_keys=True) + "\n"
        view_text = json.dumps(_view_metadata(config, name, graph), indent=2, sort_keys=True) + "\n"
        directory = Path() if name == "investigation" else Path(name)
        payloads[directory / "graph.json"] = graph_text
        payloads[directory / "VIEW.json"] = view_text
    generations = root / "generations"
    generations.mkdir(exist_ok=True)
    stage: Path | None = None
    generation = generations / f"generation-{uuid.uuid4().hex}"
    legacy: Path | None = None
    current = root / "current"
    compatibility = {
        root / "graph.json": "current/graph.json",
        root / "VIEW.json": "current/VIEW.json",
    }
    previous_current: str | None = None
    installed_compatibility: list[Path] = []
    publication_started = False

    def published(path: Path) -> bool:
        return current.is_symlink() and current.resolve() == path.resolve()

    try:
        stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=generations))
        for relative, text in payloads.items():
            staged_path = stage / relative
            staged_path.parent.mkdir(parents=True, exist_ok=True)
            staged_path.write_text(text, encoding="utf-8")
        os.replace(stage, generation)

        if os.path.lexists(current) and not current.is_symlink():
            raise GraphifyViewsError(f"managed pointer is not a symlink: {current}")
        previous_current = os.readlink(current) if current.is_symlink() else None
        managed_compatibility = all(
            path.is_symlink() and os.readlink(path) == target for path, target in compatibility.items()
        )
        if previous_current is not None and not managed_compatibility:
            raise GraphifyViewsError("current exists but compatibility links are missing or unmanaged")

        if previous_current is None and any(os.path.lexists(path) for path in compatibility):
            if any(path.is_symlink() for path in compatibility if os.path.lexists(path)):
                raise GraphifyViewsError("legacy compatibility paths must be regular files")
            legacy = generations / f"legacy-{uuid.uuid4().hex}"
            legacy.mkdir()
            for relative in payloads:
                existing = root / relative
                if existing.is_file() and not existing.is_symlink():
                    destination = legacy / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(existing, destination)
            if not (legacy / "graph.json").exists():
                raise GraphifyViewsError("legacy output has no graph.json")
            publication_started = True
            _replace_symlink(current, str(legacy.relative_to(root)))

        installed_compatibility = []
        publication_started = True
        for path, target in compatibility.items():
            if path.is_symlink() and os.readlink(path) == target:
                continue
            _replace_symlink(path, target)
            installed_compatibility.append(path)
        _replace_symlink(current, str(generation.relative_to(root)))
    except Exception:
        if publication_started:
            if previous_current is not None:
                _replace_symlink(current, previous_current)
            else:
                current.unlink(missing_ok=True)
            if legacy is not None:
                for path in installed_compatibility:
                    relative = Path(path.name)
                    source = legacy / relative
                    if source.exists():
                        _restore_regular_file(path, source)
                    else:
                        path.unlink(missing_ok=True)
            else:
                for path in installed_compatibility:
                    path.unlink(missing_ok=True)
        raise
    finally:
        if stage is not None and stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        if generation.exists() and not published(generation):
            shutil.rmtree(generation, ignore_errors=True)
        if legacy is not None and legacy.exists() and not published(legacy):
            shutil.rmtree(legacy, ignore_errors=True)
    _prune_generations(generations, current)


def _tracked_paths(root: Path, config: Mapping[str, Any]) -> list[str]:
    completed = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True)
    paths = [item for item in completed.stdout.decode().split("\0") if item]
    known: list[str] = []
    for path in paths:
        if _classify_path_unchecked(path, config) in SOURCE_VIEWS:
            known.append(path)
    return known


def _read_sources(root: Path, paths: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in paths:
        try:
            result[path] = (root / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return result


def _reexec_graphify_python() -> None:
    """Use the per-graph virtualenv when the host interpreter lacks Graphify."""

    if os.environ.get("PFB_GRAPHIFY_REEXEC") == "1":
        return
    if importlib.util.find_spec("graphify") is not None:
        return
    pointer = ROOT / "graphify-out" / ".graphify_python"
    if pointer.exists():
        executable = pointer.read_text(encoding="utf-8").strip()
        if executable and Path(executable).is_file():
            environment = dict(os.environ, PFB_GRAPHIFY_REEXEC="1")
            os.execve(executable, [executable, str(Path(__file__).resolve()), *sys.argv[1:]], environment)
    raise BootstrapError(
        "Graphify is unavailable. Bootstrap graphify-out/.graphify_python or install Graphify, then rerun "
        "scripts/agent/update_graphify_views.py"
    )


def _collect_graphify_paths(
    root: Path,
    tracked_paths: Iterable[str],
    config: Mapping[str, Any],
    collector: Callable[..., list[Path]] | None = None,
) -> list[Path]:
    """Collect only already-classified tracked files for one Graphify pass."""

    if collector is None:
        from graphify import collect_files

        collector = collect_files
    collected: set[Path] = set()
    accepted = (path for path in tracked_paths if _classify_path_unchecked(path, config) in SOURCE_VIEWS)
    for relative in accepted:
        target = root / relative
        collected.update(collector(target, root=root))
    return sorted(collected)


def _extract_graph(
    root: Path,
    tracked_paths: Sequence[str],
    config: Mapping[str, Any],
    cache_root: Path,
) -> dict[str, Any]:
    _reexec_graphify_python()
    from graphify.extract import extract

    paths = _collect_graphify_paths(root, tracked_paths, config)
    return extract(paths, root=root, cache_root=cache_root, parallel=False)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--input", type=Path, help="use an existing Graphify JSON extraction")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    root = args.repo_root.resolve()
    tracked = _tracked_paths(root, config)
    output_root = args.output or root / "graphify-out"
    cache_root = output_root / "cache"
    graph = (
        json.loads(args.input.read_text(encoding="utf-8"))
        if args.input
        else _extract_graph(root, tracked, config, cache_root)
    )
    source_texts = _read_sources(root, tracked)
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    views = build_views(graph, config, tracked_paths=tracked, source_texts=source_texts, built_at_commit=commit)
    write_outputs(output_root, views, config)
    print(f"updated {len(views)} Graphify views under {output_root}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BootstrapError, GraphifyViewsError, OSError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
