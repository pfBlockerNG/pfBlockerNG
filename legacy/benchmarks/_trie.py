"""Frozen domain-trie implementation — the rejected ADR-01 structure.

Verbatim snapshot of the trie matcher (TrieNode + insert/lookup API + the
Phase-7 fused ``trie_lookup_all``) as it stood in production before the ADR-01
roll-back. Kept here, isolated, solely so the benchmark can keep comparing the
trie against the flat dicts (``_baseline.py``) and reproduce the numbers that
justified rejecting ADR-01. It is no longer in the shipped ``pfb_unbound.py``.

Do not "improve" or re-import this into production — it exists only to preserve
the rejected design for the benchmark of record. Pure stdlib; no Unbound deps.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class TrieNode:
    """Reversed-label trie node (TLD-first insertion)."""

    __slots__ = ("children", "data", "zone", "white", "white_wild", "noaaaa", "noaaaa_wild", "hsts")

    def __init__(self) -> None:
        self.children: dict[str, TrieNode] | None = None
        self.data: dict[str, Any] | None = None
        self.zone: dict[str, Any] | None = None
        self.white: bool = False
        self.white_wild: bool = False
        self.noaaaa: bool | None = None
        self.noaaaa_wild: bool = False
        self.hsts: bool = False


def trie_split_labels(name: str) -> list[str]:
    """Return labels in reverse order (TLD-first).

    'ads.example.com' -> ['com', 'example', 'ads']
    """
    if not name:
        return []
    labels = name.split(".")
    labels.reverse()
    return labels


def _trie_walk_or_create(root: TrieNode, labels: list[str]) -> TrieNode:
    """Walk the trie creating nodes as needed; return terminal node."""
    node = root
    for label in labels:
        if not label:
            continue
        if node.children is None:
            node.children = {}
        child = node.children.get(label)
        if child is None:
            child = TrieNode()
            node.children[label] = child
        node = child
    return node


def _trie_walk(root: TrieNode, labels: list[str]) -> TrieNode | None:
    """Walk the trie without creating nodes; return terminal node or None."""
    node = root
    for label in labels:
        if not label:
            continue
        if node.children is None:
            return None
        child = node.children.get(label)
        if child is None:
            return None
        node = child
    return node


def _trie_get_terminal(root: TrieNode, domain: str) -> TrieNode | None:
    """Return (creating nodes as needed) the terminal node for domain; None if domain is empty."""
    labels = trie_split_labels(domain)
    if not labels:
        return None
    return _trie_walk_or_create(root, labels)


def trie_insert_data(root: TrieNode, domain: str, payload: dict[str, Any]) -> None:
    """Insert exact-match (data) payload into trie."""
    node = _trie_get_terminal(root, domain)
    if node is None:
        return
    node.data = payload


def trie_insert_zone(root: TrieNode, domain: str, payload: dict[str, Any]) -> None:
    """Insert wildcard-incl-self zone payload into trie."""
    node = _trie_get_terminal(root, domain)
    if node is None:
        return
    node.zone = payload


def trie_insert_white(root: TrieNode, domain: str, wildcard: bool) -> None:
    """Insert whitelist entry (exact or wildcard-suffix) into trie."""
    node = _trie_get_terminal(root, domain)
    if node is None:
        return
    if wildcard:
        node.white_wild = True
    else:
        node.white = True


def trie_insert_noaaaa(root: TrieNode, domain: str, wildcard: bool) -> None:
    """Insert noAAAA entry (exact presence or wildcard-parent) into trie."""
    node = _trie_get_terminal(root, domain)
    if node is None:
        return
    node.noaaaa = wildcard
    if wildcard:
        node.noaaaa_wild = True


def trie_insert_hsts(root: TrieNode, domain: str) -> None:
    """Insert HSTS domain into trie."""
    node = _trie_get_terminal(root, domain)
    if node is None:
        return
    node.hsts = True


def trie_lookup_exact(root: TrieNode, name: str) -> dict[str, Any] | None:
    """Return terminal node's .data (exact-match payload), or None if not found."""
    labels = trie_split_labels(name)
    if not labels:
        return None
    node = _trie_walk(root, labels)
    if node is None:
        return None
    return node.data


def trie_lookup_zone(root: TrieNode, name: str) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    """Return (matched_domain, payload) for deepest ancestor (incl self) with .zone set."""
    labels = trie_split_labels(name)
    if not labels:
        return None, None

    node = root
    best: tuple[int, dict[str, Any]] | None = None
    accumulated: list[str] = []

    for label in labels:
        if not label:
            continue
        if node.children is None:
            break
        child = node.children.get(label)
        if child is None:
            break
        node = child
        accumulated.append(label)
        if node.zone is not None:
            best = (len(accumulated), node.zone)

    if best is None:
        return None, None
    depth, payload = best
    return ".".join(reversed(accumulated[:depth])), payload


def trie_lookup_white(root: TrieNode, name: str, tld_seg: int) -> bool:
    """Whitelist match via trie (exact, www.-strip, and tld_seg-gated suffix walk)."""
    labels = trie_split_labels(name)
    if not labels:
        return False

    path_nodes: list[TrieNode] = []
    node = root
    for label in labels:
        if not label:
            continue
        if node.children is None:
            break
        child = node.children.get(label)
        if child is None:
            break
        node = child
        path_nodes.append(node)

    n = len(path_nodes)
    full_depth = len([lb for lb in labels if lb])

    if n == full_depth and (path_nodes[-1].white or path_nodes[-1].white_wild):
        return True

    if name.startswith("www."):
        stripped_depth = full_depth - 1
        if stripped_depth > 0 and stripped_depth <= n:
            snode = path_nodes[stripped_depth - 1]
            if snode.white or snode.white_wild:
                return True

    for d in range(full_depth - 1, tld_seg - 1, -1):
        if d <= n and path_nodes[d - 1].white_wild:
            return True

    return False


def trie_lookup_noaaaa(root: TrieNode, name: str) -> bool:
    """noAAAA match via trie (exact presence OR wildcard-parent)."""
    labels = trie_split_labels(name)
    if not labels:
        return False

    path_nodes: list[TrieNode] = []
    node = root
    for label in labels:
        if not label:
            continue
        if node.children is None:
            break
        child = node.children.get(label)
        if child is None:
            break
        node = child
        path_nodes.append(node)

    n = len(path_nodes)
    full_depth = len([lb for lb in labels if lb])

    if n == full_depth and path_nodes[-1].noaaaa is not None:
        return True

    for d in range(full_depth - 1, 1, -1):
        if d <= n and path_nodes[d - 1].noaaaa_wild:
            return True

    return False


def trie_lookup_hsts(
    root: TrieNode,
    name: str,
    hsts_tlds: tuple[str, ...] | list[str],
    tld: str,
) -> tuple[bool, str]:
    """HSTS match via trie, including the original -2 stride."""
    if tld in hsts_tlds:
        return True, "HSTS_TLD"

    labels = trie_split_labels(name)
    if not labels:
        return False, "Python"

    path_nodes: list[TrieNode] = []
    node = root
    for label in labels:
        if not label:
            continue
        if node.children is None:
            break
        child = node.children.get(label)
        if child is None:
            break
        node = child
        path_nodes.append(node)

    dot_count = name.count(".")
    full_depth = dot_count + 1
    n_iters = (full_depth + 1) // 2
    for i in range(n_iters):
        path_idx = full_depth - 1 - i
        if path_idx >= 0 and path_idx < len(path_nodes) and path_nodes[path_idx].hsts:
            return True, "HSTS"

    return False, "Python"


@dataclass
class TrieLookupResult:
    """Per-category results from a single fused trie descent."""

    data: dict[str, Any] | None
    zone: tuple[str, dict[str, Any]] | tuple[None, None]
    white: bool
    noaaaa: bool
    hsts: tuple[bool, str]


def trie_lookup_all(
    root: TrieNode,
    name: str,
    tld_seg: int,
    hsts_tlds: tuple[str, ...] | list[str],
    tld: str,
) -> TrieLookupResult:
    """Resolve every domain category in a SINGLE trie descent (Phase-7 fused path)."""
    labels = trie_split_labels(name)

    path_nodes: list[TrieNode] = []
    node = root
    for label in labels:
        if not label:
            continue
        if node.children is None:
            break
        child = node.children.get(label)
        if child is None:
            break
        node = child
        path_nodes.append(node)

    n = len(path_nodes)
    full_depth = len([lb for lb in labels if lb])

    data_payload: dict[str, Any] | None = None
    if n == full_depth and n > 0:
        data_payload = path_nodes[-1].data

    zone_result: tuple[str, dict[str, Any]] | tuple[None, None] = (None, None)
    nonempty_labels = [lb for lb in labels if lb]
    best_zone_depth = 0
    best_zone_payload: dict[str, Any] | None = None
    for depth in range(1, n + 1):
        zp = path_nodes[depth - 1].zone
        if zp is not None:
            best_zone_depth = depth
            best_zone_payload = zp
    if best_zone_payload is not None:
        matched = ".".join(reversed(nonempty_labels[:best_zone_depth]))
        zone_result = (matched, best_zone_payload)

    white_hit = False
    if n > 0:
        if n == full_depth and (path_nodes[-1].white or path_nodes[-1].white_wild):
            white_hit = True
        if not white_hit and name.startswith("www."):
            stripped_depth = full_depth - 1
            if 0 < stripped_depth <= n:
                snode = path_nodes[stripped_depth - 1]
                if snode.white or snode.white_wild:
                    white_hit = True
        if not white_hit:
            for d in range(full_depth - 1, tld_seg - 1, -1):
                if d <= n and path_nodes[d - 1].white_wild:
                    white_hit = True
                    break

    noaaaa_hit = False
    if n > 0:
        if n == full_depth and path_nodes[-1].noaaaa is not None:
            noaaaa_hit = True
        if not noaaaa_hit:
            for d in range(full_depth - 1, 1, -1):
                if d <= n and path_nodes[d - 1].noaaaa_wild:
                    noaaaa_hit = True
                    break

    if tld in hsts_tlds:
        hsts_result: tuple[bool, str] = (True, "HSTS_TLD")
    else:
        hsts_result = (False, "Python")
        dot_count = name.count(".")
        hsts_full_depth = dot_count + 1
        n_iters = (hsts_full_depth + 1) // 2
        for i in range(n_iters):
            path_idx = hsts_full_depth - 1 - i
            if 0 <= path_idx < n and path_nodes[path_idx].hsts:
                hsts_result = (True, "HSTS")
                break

    return TrieLookupResult(
        data=data_payload,
        zone=zone_result,
        white=white_hit,
        noaaaa=noaaaa_hit,
        hsts=hsts_result,
    )
