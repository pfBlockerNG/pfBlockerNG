#!/usr/bin/env python3
"""Validate the shared agent role registry against every vendor's role definitions.

`.agents/policy/agent-roles.md` is the shared, vendor-neutral role-family
contract (issue #1387). Its machine-readable registry table binds every role to
Claude surfaces (`.claude/agents/*.md`, skills, policy docs, the session),
Codex surfaces (`.codex/agents/*.toml`, skills, policy docs, the session), and
Copilot surfaces (`.github/agents/*.agent.md`, skills, policy docs, the
session — issue #2177). This
checker validates the SEMANTIC fields — mutation boundaries, binding targets,
contract-section completeness — never textual identity, so vendor-native wording
may differ freely while capability drift (a sandbox/mutation mismatch, a missing
or orphaned vendor role, a missing contract field) fails loudly.

CONDITIONAL: in --staged / --diff mode the full validation runs IF AND ONLY IF
the change touches a role surface (.agents/policy/, .codex/agents/,
.github/agents/, .claude/agents/, .agents/skills/, or this checker); otherwise
it reports the skip and exits 0. --all validates unconditionally.

Usage:
    check_agent_roles.py --staged            # pre-commit: staged diff decides
    check_agent_roles.py --diff <base>       # CI PR gate: base...HEAD decides
    check_agent_roles.py --all               # unconditional full validation
    [--root PATH]                            # repo root (default: script's repo)

Exit status: 0 = clean or skipped, 1 = violations (printed), 2 = usage/git error.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NamedTuple

from _git_paths import nul_listing

_ROLES_DOC = ".agents/policy/agent-roles.md"
_CODEX_AGENTS = ".codex/agents"
_COPILOT_AGENTS = ".github/agents"
_CLAUDE_AGENTS = ".claude/agents"
_SKILLS = ".agents/skills"
_POLICY = ".agents/policy"
# Role surfaces: full validation triggers iff a changed path is one of these
# files or sits under one of these directories.
_TRIGGER_FILES = (_ROLES_DOC, "scripts/check_agent_roles.py")
_TRIGGER_DIRS = (
    f"{_CODEX_AGENTS}/",
    f"{_COPILOT_AGENTS}/",
    f"{_CLAUDE_AGENTS}/",
    f"{_SKILLS}/",
    f"{_POLICY}/",
)

_BEGIN = "<!-- role-registry:begin -->"
_END = "<!-- role-registry:end -->"
_HEADER = (
    "Role",
    "Mutation",
    "Independent",
    "Claude bindings",
    "Codex bindings",
    "Copilot bindings",
)
_MUTATIONS = ("read-only", "workspace-write")
_CLAUDE_KINDS = ("agent", "skill", "policy")
_CODEX_KINDS = ("agent", "skill", "policy")
_COPILOT_KINDS = ("agent", "skill", "policy")
_ROLE_ID = re.compile(r"[a-z][a-z0-9-]*")
_MUTATION_MARKER = re.compile(r"<!--\s*mutation:\s*([a-z-]+)\s*-->")
# The seven semantic fields every role's contract section must carry.
_SECTION_FIELDS = (
    "Purpose & routing",
    "Inputs & task packet",
    "Outputs & evidence",
    "Permissions & mutation",
    "Context & skills",
    "Stop & escalation",
    "Independence",
)


class Role(NamedTuple):
    name: str
    mutation: str
    independent: str
    claude: tuple[tuple[str, str], ...]  # (kind, target); ("session", "")
    codex: tuple[tuple[str, str], ...]
    copilot: tuple[tuple[str, str], ...]


def _split_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _parse_bindings(
    cell: str, kinds: tuple[str, ...], column: str, role: str, problems: list[str]
) -> tuple[tuple[str, str], ...]:
    bindings: list[tuple[str, str]] = []
    for part in (p.strip() for p in cell.split(",")):
        if not part:
            problems.append(f"{_ROLES_DOC}: role '{role}': empty {column} binding")
            continue
        if part == "session":
            bindings.append(("session", ""))
            continue
        kind, sep, target = part.partition(":")
        if not sep or not target or kind not in kinds:
            problems.append(
                f"{_ROLES_DOC}: role '{role}': {column} binding '{part}' is not 'session' or "
                f"kind:name with kind in {'/'.join(kinds)}"
            )
            continue
        bindings.append((kind, target))
    return tuple(bindings)


def _parse_registry(doc: str, problems: list[str]) -> list[Role]:
    begin, end = doc.find(_BEGIN), doc.find(_END)
    if begin < 0 or end < begin:
        problems.append(f"{_ROLES_DOC}: registry markers missing ({_BEGIN} ... {_END})")
        return []
    rows = [line for line in doc[begin + len(_BEGIN) : end].splitlines() if line.strip().startswith("|")]
    if not rows:
        problems.append(f"{_ROLES_DOC}: registry table is empty")
        return []
    header = _split_row(rows[0])
    if header != list(_HEADER):
        problems.append(f"{_ROLES_DOC}: registry header must be {list(_HEADER)}, got {header}")
        return []
    roles: list[Role] = []
    seen: set[str] = set()
    for line in rows[1:]:
        cells = _split_row(line)
        if all(cell and set(cell) <= set("-: ") for cell in cells):
            continue  # the |----| separator row (all-empty cells are NOT a separator)
        if len(cells) != len(_HEADER):
            problems.append(f"{_ROLES_DOC}: registry row needs {len(_HEADER)} columns: {line.strip()}")
            continue
        name, mutation, independent, claude_cell, codex_cell, copilot_cell = cells
        ok = True
        if not _ROLE_ID.fullmatch(name):
            problems.append(f"{_ROLES_DOC}: invalid role id: {name!r}")
            ok = False
        if name in seen:
            problems.append(f"{_ROLES_DOC}: duplicate role: {name}")
            ok = False
        seen.add(name)
        if mutation not in _MUTATIONS:
            problems.append(f"{_ROLES_DOC}: role '{name}': Mutation must be one of {_MUTATIONS}, got {mutation!r}")
            ok = False
        if independent not in ("yes", "no"):
            problems.append(f"{_ROLES_DOC}: role '{name}': Independent must be yes/no, got {independent!r}")
            ok = False
        claude = _parse_bindings(claude_cell, _CLAUDE_KINDS, "Claude", name, problems)
        codex = _parse_bindings(codex_cell, _CODEX_KINDS, "Codex", name, problems)
        copilot = _parse_bindings(copilot_cell, _COPILOT_KINDS, "Copilot", name, problems)
        if ok:
            roles.append(Role(name, mutation, independent, claude, codex, copilot))
    return roles


def _check_sections(doc: str, roles: list[Role], problems: list[str]) -> None:
    for role in roles:
        match = re.search(rf"^### {re.escape(role.name)}$", doc, re.MULTILINE)
        if not match:
            problems.append(f"{_ROLES_DOC}: missing contract section '### {role.name}'")
            continue
        rest = doc[match.end() :]
        next_heading = re.search(r"^#{2,3} ", rest, re.MULTILINE)
        section = rest[: next_heading.start()] if next_heading else rest
        for field in _SECTION_FIELDS:
            if f"**{field}:**" not in section:
                problems.append(f"{_ROLES_DOC}: section '### {role.name}' missing field '**{field}:**'")


def _check_codex_agents(root: Path, agent_roles: dict[str, list[Role]], problems: list[str]) -> None:
    for target, bound in sorted(agent_roles.items()):
        path = root / _CODEX_AGENTS / f"{target}.toml"
        names = "/".join(sorted(role.name for role in bound))
        if not path.is_file():
            problems.append(f"role(s) {names}: missing Codex agent {_CODEX_AGENTS}/{target}.toml")
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            problems.append(f"{_CODEX_AGENTS}/{target}.toml: unparsable TOML: {exc}")
            continue
        sandbox = data.get("sandbox_mode")
        mutations = {role.mutation for role in bound}
        if len(mutations) > 1:
            problems.append(f"{_CODEX_AGENTS}/{target}.toml is bound by roles with conflicting Mutation: {names}")
        elif sandbox != next(iter(mutations)):
            problems.append(
                f"{_CODEX_AGENTS}/{target}.toml sandbox_mode {sandbox!r} != role Mutation "
                f"'{next(iter(mutations))}' ({names})"
            )


def _agent_md_front_matter(text: str) -> dict[str, str]:
    """Read the flat scalar fields of a `.agent.md` YAML front matter.

    Deliberately tiny: the only field this checker reads there is `description`,
    so a full YAML parser would add a dependency for one string.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    if not any(line.strip() == "---" for line in lines[1:]):
        return {}  # unterminated front matter is malformed, not an open block
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if not line.strip() or line.lstrip().startswith("#") or line[:1].isspace():
            continue
        key, sep, value = (part.strip() for part in line.partition(":"))
        if sep and value:
            if len(value) >= 2 and (
                (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'"))
            ):
                value = value[1:-1]
            fields[key] = value
    return fields


def _agent_md_mutation(text: str) -> str | None:
    """Read the `<!-- mutation: ... -->` marker.

    Copilot CLI 1.0.78 warns `unknown field ignored` for any front-matter key
    outside its own schema, so the mutation boundary rides an HTML comment that
    the CLI passes through untouched.
    """
    found = _MUTATION_MARKER.search(text)
    return found.group(1) if found else None


def _check_md_agents(
    root: Path, agent_roles: dict[str, list[Role]], directory: str, suffix: str, side: str, problems: list[str]
) -> None:
    """Claude `.md` and Copilot `.agent.md` definitions share one shape."""
    for target, bound in sorted(agent_roles.items()):
        rel = f"{directory}/{target}{suffix}"
        names = "/".join(sorted(role.name for role in bound))
        path = root / rel
        if not path.is_file():
            problems.append(f"role(s) {names}: missing {side} agent {rel}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        fields = _agent_md_front_matter(text)
        if not fields:
            problems.append(f"{rel}: missing YAML front matter")
            continue
        if not fields.get("description"):
            problems.append(f"{rel}: front matter has no description")
        mutations = {role.mutation for role in bound}
        mutation = _agent_md_mutation(text)
        if len(mutations) > 1:
            problems.append(f"{rel} is bound by roles with conflicting Mutation: {names}")
        elif mutation != next(iter(mutations)):
            problems.append(f"{rel} mutation marker {mutation!r} != role Mutation '{next(iter(mutations))}' ({names})")


def _check_file_bindings(root: Path, roles: list[Role], problems: list[str]) -> None:
    for role in roles:
        for kind, target in role.claude + role.codex + role.copilot:
            if kind == "skill" and not (root / _SKILLS / target / "SKILL.md").is_file():
                problems.append(f"role '{role.name}': skill binding '{target}' has no {_SKILLS}/{target}/SKILL.md")
            elif kind == "policy" and not (root / _POLICY / target).is_file():
                problems.append(f"role '{role.name}': policy binding '{target}' has no {_POLICY}/{target}")


def _check_orphans(root: Path, roles: list[Role], problems: list[str]) -> None:
    claimed_agents = {target for role in roles for kind, target in role.codex if kind == "agent"}
    claimed_copilot = {target for role in roles for kind, target in role.copilot if kind == "agent"}
    claimed_claude = {target for role in roles for kind, target in role.claude if kind == "agent"}
    for directory, suffix, claimed, side in (
        (root / _CODEX_AGENTS, ".toml", claimed_agents, "Codex role"),
        (root / _COPILOT_AGENTS, ".agent.md", claimed_copilot, "Copilot role"),
        (root / _CLAUDE_AGENTS, ".md", claimed_claude, "Claude agent"),
    ):
        if not directory.is_dir():
            if claimed:
                problems.append(f"missing directory: {directory.relative_to(root)}")
            continue
        for path in sorted(directory.glob(f"*{suffix}")):
            # Path.stem strips ONE suffix, so a Copilot `<name>.agent.md` keeps
            # its `.agent` half — take the target off the full name instead.
            if path.name[: -len(suffix)] not in claimed:
                problems.append(f"{path.relative_to(root)}: {side} not claimed by any registry row")


def validate(root: Path) -> tuple[int, list[str]]:
    """Full semantic validation; returns (role count, problems)."""
    doc_path = root / _ROLES_DOC
    if not doc_path.is_file():
        return 0, [f"missing role contract: {_ROLES_DOC}"]
    problems: list[str] = []
    doc = doc_path.read_text(encoding="utf-8", errors="replace")
    roles = _parse_registry(doc, problems)
    if not roles and not problems:
        problems.append(f"{_ROLES_DOC}: registry has no roles")
    _check_sections(doc, roles, problems)
    _check_file_bindings(root, roles, problems)
    claude_agent_roles: dict[str, list[Role]] = {}
    agent_roles: dict[str, list[Role]] = {}
    copilot_roles: dict[str, list[Role]] = {}
    for role in roles:
        for kind, target in role.claude:
            if kind == "agent":
                claude_agent_roles.setdefault(target, []).append(role)
        for kind, target in role.codex:
            if kind == "agent":
                agent_roles.setdefault(target, []).append(role)
        for kind, target in role.copilot:
            if kind == "agent":
                copilot_roles.setdefault(target, []).append(role)
    _check_md_agents(root, claude_agent_roles, _CLAUDE_AGENTS, ".md", "Claude", problems)
    _check_codex_agents(root, agent_roles, problems)
    _check_md_agents(root, copilot_roles, _COPILOT_AGENTS, ".agent.md", "Copilot", problems)
    _check_orphans(root, roles, problems)
    return len(roles), problems


def _changed_paths(root: Path, git_args: list[str]) -> list[str]:
    # -z: the newline form C-quotes any path holding a quote, backslash, control
    # byte or non-ASCII byte, and a quoted path matches no role surface.
    return nul_listing(root, "diff", "--name-only", "-z", "--no-color", *git_args)


def touches_role_surface(paths: list[str]) -> bool:
    return any(path in _TRIGGER_FILES or any(path.startswith(prefix) for prefix in _TRIGGER_DIRS) for path in paths)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").partition("\n")[0], prog="check_agent_roles.py")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="validate iff the staged diff touches a role surface")
    mode.add_argument("--diff", metavar="BASE", help="validate iff BASE...HEAD touches a role surface")
    mode.add_argument("--all", action="store_true", help="unconditional full validation")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (default: this script's repository)",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not args.all:
        try:
            changed = _changed_paths(root, ["--cached"] if args.staged else [f"{args.diff}...HEAD"])
        except (subprocess.CalledProcessError, OSError) as exc:
            stderr = getattr(exc, "stderr", "") or str(exc)
            print(f"agent-roles: git diff failed: {stderr.strip()}", file=sys.stderr)
            return 2
        if not touches_role_surface(changed):
            print("agent-roles: no role surface changed; skipped")
            return 0
    count, problems = validate(root)
    if problems:
        print("Agent role-family drift detected:\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            f"\nThe shared role contract ({_ROLES_DOC}) and the vendor role definitions"
            "\nmust stay semantically aligned: fix the drifted side, or update the"
            "\nregistry row and its contract section together.",
            file=sys.stderr,
        )
        return 1
    print(f"agent-roles: registry and vendor role definitions consistent ({count} roles)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
