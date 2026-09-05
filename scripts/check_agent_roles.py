#!/usr/bin/env python3
"""Validate the shared agent role registry against every vendor's role definitions.

`.agents/policy/agent-roles.md` is the shared, vendor-neutral role-family
contract (issue #1387). Its machine-readable registry table binds every role to
Claude surfaces (`.claude/workflows/*.js`, skills, policy docs, the session),
Codex surfaces (`.codex/agents/*.toml`, skills, policy docs, the session), and
Copilot surfaces (`.github/agents/*.agent.md`, skills, policy docs, the
session — issue #2177). This
checker validates the SEMANTIC fields — tier vocabulary, mutation boundaries,
binding targets, model-tier pins, Codex review-effort pins, contract-section
completeness — never textual identity, so vendor-native wording may differ freely
while capability drift (a retiered model pin, a sandbox/mutation mismatch, an
orphaned vendor role, a missing contract field) fails loudly.

CONDITIONAL: in --staged / --diff mode the full validation runs IF AND ONLY IF
the change touches a role surface (.agents/policy/, .agents/model-tiers.conf,
.codex/agents/, .github/agents/, .claude/workflows/, .agents/skills/, or this
checker); otherwise
it reports the skip and exits 0. --all validates unconditionally.

Usage:
    check_agent_roles.py --staged            # pre-commit: staged diff decides
    check_agent_roles.py --diff <base>       # CI PR gate: base...HEAD decides
    check_agent_roles.py --all               # unconditional full validation
    [--root PATH]                            # repo root (default: script's repo)

A model pin is exempt only when its line carries standalone, case-sensitive
`roles-ok:` followed by a same-line non-whitespace reason.

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
_TIERS_CONF = ".agents/model-tiers.conf"
_CODEX_AGENTS = ".codex/agents"
_COPILOT_AGENTS = ".github/agents"
_CLAUDE_AGENTS = ".claude/agents"
_CLAUDE_WORKFLOWS = ".claude/workflows"
_SKILLS = ".agents/skills"
_POLICY = ".agents/policy"
# Role surfaces: full validation triggers iff a changed path is one of these
# files or sits under one of these directories.
_TRIGGER_FILES = (_ROLES_DOC, _TIERS_CONF, "scripts/check_agent_roles.py")
_TRIGGER_DIRS = (
    f"{_CODEX_AGENTS}/",
    f"{_COPILOT_AGENTS}/",
    f"{_CLAUDE_AGENTS}/",
    f"{_CLAUDE_WORKFLOWS}/",
    f"{_SKILLS}/",
    f"{_POLICY}/",
)

_BEGIN = "<!-- role-registry:begin -->"
_END = "<!-- role-registry:end -->"
_HEADER = (
    "Role",
    "Tiers",
    "Mutation",
    "Independent",
    "Claude bindings",
    "Codex bindings",
    "Copilot bindings",
)
_TIERS = ("top", "mid", "small")
_MUTATIONS = ("read-only", "workspace-write")
_CLAUDE_KINDS = ("agent", "workflow", "skill", "policy")
_CODEX_KINDS = ("agent", "skill", "policy")
_COPILOT_KINDS = ("agent", "skill", "policy")
_TIER_KEYS = tuple(f"{tier.upper()}_{vendor}" for tier in _TIERS for vendor in ("CLAUDE", "CODEX", "COPILOT"))
_ROLE_ID = re.compile(r"[a-z][a-z0-9-]*")
# A DIRECTLY QUOTED model id is a pin; a mid-prose mention inside a longer
# string is not — that tolerance is what "no textual identity" means here.
_CLAUDE_MODEL_PIN = re.compile(r"""['"](claude-[a-z0-9.-]+)['"]""")
_ESCAPE = re.compile(r"(?<![\w-])roles-ok:[^\S\r\n]*\S")
_MUTATION_MARKER = re.compile(r"<!--\s*mutation:\s*([a-z-]+)\s*-->")
# The eight semantic fields every role's contract section must carry.
_SECTION_FIELDS = (
    "Purpose & routing",
    "Inputs & task packet",
    "Outputs & evidence",
    "Permissions & mutation",
    "Context & skills",
    "Stop & escalation",
    "Independence",
    "Tier intent",
)


class Role(NamedTuple):
    name: str
    tiers: tuple[str, ...]  # primary first
    mutation: str
    independent: str
    claude: tuple[tuple[str, str], ...]  # (kind, target); ("session", "")
    codex: tuple[tuple[str, str], ...]
    copilot: tuple[tuple[str, str], ...]


def _common_tiers(bound: list[Role]) -> set[str]:
    return set(bound[0].tiers).intersection(*(role.tiers for role in bound[1:]))


def _parse_tiers_conf(text: str, problems: list[str]) -> dict[str, str]:
    """Parse KEY=VALUE tier lines; require exactly the six known keys, once each."""
    values: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = (part.strip() for part in line.partition("="))
        if not sep or not key or not value:
            problems.append(f"{_TIERS_CONF}:{lineno}: invalid tier assignment: {line}")
        elif key not in _TIER_KEYS:
            problems.append(f"{_TIERS_CONF}:{lineno}: unknown tier key: {key}")
        elif key in values:
            problems.append(f"{_TIERS_CONF}:{lineno}: duplicate tier key: {key}")
        else:
            values[key] = value
    for key in _TIER_KEYS:
        if key not in values:
            problems.append(f"{_TIERS_CONF}: missing tier key: {key}")
    return values


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
        name, tiers_cell, mutation, independent, claude_cell, codex_cell, copilot_cell = cells
        ok = True
        if not _ROLE_ID.fullmatch(name):
            problems.append(f"{_ROLES_DOC}: invalid role id: {name!r}")
            ok = False
        if name in seen:
            problems.append(f"{_ROLES_DOC}: duplicate role: {name}")
            ok = False
        seen.add(name)
        tiers = tuple(tier.strip() for tier in tiers_cell.split("+"))
        if any(tier not in _TIERS for tier in tiers) or len(set(tiers)) != len(tiers):
            problems.append(
                f"{_ROLES_DOC}: role '{name}': Tiers must be distinct {'/'.join(_TIERS)} tokens "
                f"joined by '+', primary first; got {tiers_cell!r}"
            )
            ok = False
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
            roles.append(Role(name, tiers, mutation, independent, claude, codex, copilot))
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


def _scan_model_pins(path: Path) -> list[str]:
    pins: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if _ESCAPE.search(line):
            continue
        pins.extend(_CLAUDE_MODEL_PIN.findall(line))
    return pins


def _check_claude_workflows(
    root: Path, workflow_roles: dict[str, list[Role]], tiers_conf: dict[str, str], problems: list[str]
) -> None:
    model_tier = {model: key.split("_")[0].lower() for key, model in tiers_conf.items() if key.endswith("_CLAUDE")}
    for target, bound in sorted(workflow_roles.items()):
        path = root / _CLAUDE_WORKFLOWS / f"{target}.js"
        names = "/".join(sorted(role.name for role in bound))
        if not path.is_file():
            problems.append(f"role(s) {names}: missing Claude workflow {_CLAUDE_WORKFLOWS}/{target}.js")
            continue
        pins = _scan_model_pins(path)
        allowed = _common_tiers(bound)
        for pin in sorted(set(pins)):
            tier = model_tier.get(pin)
            if tier is None:
                problems.append(f"{_CLAUDE_WORKFLOWS}/{target}.js pins '{pin}', which is not in {_TIERS_CONF}")
            elif tier not in allowed:
                problems.append(
                    f"{_CLAUDE_WORKFLOWS}/{target}.js pins '{pin}' ({tier} tier), outside "
                    f"tier(s) {'+'.join(sorted(allowed))} of role(s) {names}"
                )
        for role in bound:
            primary = tiers_conf.get(f"{role.tiers[0].upper()}_CLAUDE")
            if primary is not None and primary not in pins:
                problems.append(
                    f"{_CLAUDE_WORKFLOWS}/{target}.js never pins role '{role.name}' "
                    f"primary tier '{role.tiers[0]}' ({primary})"
                )


def _check_claude_agents(
    root: Path, agent_roles: dict[str, list[Role]], tiers_conf: dict[str, str], problems: list[str]
) -> None:
    agent_model: dict[str, str | None] = {}
    for target, bound in sorted(agent_roles.items()):
        path = root / _CLAUDE_AGENTS / f"{target}.md"
        names = "/".join(sorted(role.name for role in bound))
        agent_model[target] = None
        if not path.is_file():
            problems.append(f"role(s) {names}: missing Claude agent {_CLAUDE_AGENTS}/{target}.md")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        fields = _agent_md_front_matter(text)
        if not fields:
            problems.append(f"{_CLAUDE_AGENTS}/{target}.md: missing YAML front matter")
            continue
        if not fields.get("description"):
            problems.append(f"{_CLAUDE_AGENTS}/{target}.md: front matter has no description")
        model = fields.get("model")
        allowed = {tiers_conf.get(f"{tier.upper()}_CLAUDE") for tier in _common_tiers(bound)} - {None}
        if model is not None:
            agent_model[target] = model
        if model is None or model not in allowed:
            problems.append(
                f"{_CLAUDE_AGENTS}/{target}.md model {model!r} is not a Claude model of "
                f"the tier(s) declared for role(s) {names}"
            )
        review_roles = sorted({role.name for role in bound} & {"reviewer", "verifier"})
        if review_roles:
            required_effort = "medium"
            effort = fields.get("effort")
            if effort != required_effort:
                problems.append(
                    f"{_CLAUDE_AGENTS}/{target}.md effort {effort!r} != required "
                    f"{required_effort!r} for Claude reviewer/verifier role(s) {'/'.join(review_roles)}"
                )
        mutations = {role.mutation for role in bound}
        mutation = _agent_md_mutation(text)
        if len(mutations) > 1:
            problems.append(f"{_CLAUDE_AGENTS}/{target}.md is bound by roles with conflicting Mutation: {names}")
        elif mutation != next(iter(mutations)):
            problems.append(
                f"{_CLAUDE_AGENTS}/{target}.md mutation marker {mutation!r} != role Mutation "
                f"'{next(iter(mutations))}' ({names})"
            )
    for role in {role.name: role for bound in agent_roles.values() for role in bound}.values():
        bound_agents = [target for kind, target in role.claude if kind == "agent"]
        primary = tiers_conf.get(f"{role.tiers[0].upper()}_CLAUDE")
        if primary is not None and not any(agent_model.get(target) == primary for target in bound_agents):
            problems.append(
                f"role '{role.name}': no Claude agent binding runs its primary tier '{role.tiers[0]}' ({primary})"
            )


def _check_codex_agents(
    root: Path, agent_roles: dict[str, list[Role]], tiers_conf: dict[str, str], problems: list[str]
) -> None:
    agent_model: dict[str, str | None] = {}
    for target, bound in sorted(agent_roles.items()):
        path = root / _CODEX_AGENTS / f"{target}.toml"
        names = "/".join(sorted(role.name for role in bound))
        agent_model[target] = None
        if not path.is_file():
            problems.append(f"role(s) {names}: missing Codex agent {_CODEX_AGENTS}/{target}.toml")
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            problems.append(f"{_CODEX_AGENTS}/{target}.toml: unparsable TOML: {exc}")
            continue
        model, sandbox = data.get("model"), data.get("sandbox_mode")
        allowed = {tiers_conf.get(f"{tier.upper()}_CODEX") for tier in _common_tiers(bound)} - {None}
        if isinstance(model, str):
            agent_model[target] = model
        if not isinstance(model, str) or model not in allowed:
            problems.append(
                f"{_CODEX_AGENTS}/{target}.toml model {model!r} is not a Codex model of "
                f"the tier(s) declared for role(s) {names}"
            )
        review_roles = sorted({role.name for role in bound} & {"reviewer", "verifier"})
        if review_roles and isinstance(model, str):
            required_effort = "high" if model == tiers_conf.get("SMALL_CODEX") else "medium"
            effort = data.get("model_reasoning_effort")
            if effort != required_effort:
                problems.append(
                    f"{_CODEX_AGENTS}/{target}.toml model_reasoning_effort {effort!r} != required "
                    f"{required_effort!r} for Codex reviewer/verifier role(s) {'/'.join(review_roles)}"
                )
        mutations = {role.mutation for role in bound}
        if len(mutations) > 1:
            problems.append(f"{_CODEX_AGENTS}/{target}.toml is bound by roles with conflicting Mutation: {names}")
        elif sandbox != next(iter(mutations)):
            problems.append(
                f"{_CODEX_AGENTS}/{target}.toml sandbox_mode {sandbox!r} != role Mutation "
                f"'{next(iter(mutations))}' ({names})"
            )
    for role in {role.name: role for bound in agent_roles.values() for role in bound}.values():
        bound_agents = [target for kind, target in role.codex if kind == "agent"]
        primary = tiers_conf.get(f"{role.tiers[0].upper()}_CODEX")
        if primary is not None and not any(agent_model.get(target) == primary for target in bound_agents):
            problems.append(
                f"role '{role.name}': no Codex agent binding runs its primary tier '{role.tiers[0]}' ({primary})"
            )


def _agent_md_front_matter(text: str) -> dict[str, str]:
    """Read the flat scalar fields of a `.agent.md` YAML front matter.

    Deliberately tiny: the only field this checker reads there is `model`, so a
    full YAML parser would add a dependency for one string.
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


def _check_copilot_agents(
    root: Path, agent_roles: dict[str, list[Role]], tiers_conf: dict[str, str], problems: list[str]
) -> None:
    agent_model: dict[str, str | None] = {}
    for target, bound in sorted(agent_roles.items()):
        path = root / _COPILOT_AGENTS / f"{target}.agent.md"
        names = "/".join(sorted(role.name for role in bound))
        agent_model[target] = None
        if not path.is_file():
            problems.append(f"role(s) {names}: missing Copilot agent {_COPILOT_AGENTS}/{target}.agent.md")
            continue
        fields = _agent_md_front_matter(path.read_text(encoding="utf-8", errors="replace"))
        if not fields:
            problems.append(f"{_COPILOT_AGENTS}/{target}.agent.md: missing YAML front matter")
            continue
        if not fields.get("description"):
            problems.append(f"{_COPILOT_AGENTS}/{target}.agent.md: front matter has no description")
        model = fields.get("model")
        allowed = {tiers_conf.get(f"{tier.upper()}_COPILOT") for tier in _common_tiers(bound)} - {None}
        if model is not None:
            agent_model[target] = model
        if model is None or model not in allowed:
            problems.append(
                f"{_COPILOT_AGENTS}/{target}.agent.md model {model!r} is not a Copilot model of "
                f"the tier(s) declared for role(s) {names}"
            )
        mutations = {role.mutation for role in bound}
        mutation = _agent_md_mutation(path.read_text(encoding="utf-8", errors="replace"))
        if len(mutations) > 1:
            problems.append(f"{_COPILOT_AGENTS}/{target}.agent.md is bound by roles with conflicting Mutation: {names}")
        elif mutation != next(iter(mutations)):
            problems.append(
                f"{_COPILOT_AGENTS}/{target}.agent.md mutation marker {mutation!r} != role Mutation "
                f"'{next(iter(mutations))}' ({names})"
            )
    for role in {role.name: role for bound in agent_roles.values() for role in bound}.values():
        bound_agents = [target for kind, target in role.copilot if kind == "agent"]
        primary = tiers_conf.get(f"{role.tiers[0].upper()}_COPILOT")
        if primary is not None and not any(agent_model.get(target) == primary for target in bound_agents):
            problems.append(
                f"role '{role.name}': no Copilot agent binding runs its primary tier '{role.tiers[0]}' ({primary})"
            )


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
    claimed_workflows = {target for role in roles for kind, target in role.claude if kind == "workflow"}
    for directory, suffix, claimed, side in (
        (root / _CODEX_AGENTS, ".toml", claimed_agents, "Codex role"),
        (root / _COPILOT_AGENTS, ".agent.md", claimed_copilot, "Copilot role"),
        (root / _CLAUDE_AGENTS, ".md", claimed_claude, "Claude agent"),
        (root / _CLAUDE_WORKFLOWS, ".js", claimed_workflows, "Claude workflow"),
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
    tiers_path = root / _TIERS_CONF
    if tiers_path.is_file():
        tiers_conf = _parse_tiers_conf(tiers_path.read_text(encoding="utf-8", errors="replace"), problems)
    else:
        tiers_conf = {}
        problems.append(f"missing tier vocabulary: {_TIERS_CONF}")
    roles = _parse_registry(doc, problems)
    if not roles and not problems:
        problems.append(f"{_ROLES_DOC}: registry has no roles")
    _check_sections(doc, roles, problems)
    _check_file_bindings(root, roles, problems)
    workflow_roles: dict[str, list[Role]] = {}
    claude_agent_roles: dict[str, list[Role]] = {}
    agent_roles: dict[str, list[Role]] = {}
    copilot_roles: dict[str, list[Role]] = {}
    for role in roles:
        for kind, target in role.claude:
            if kind == "workflow":
                workflow_roles.setdefault(target, []).append(role)
            elif kind == "agent":
                claude_agent_roles.setdefault(target, []).append(role)
        for kind, target in role.codex:
            if kind == "agent":
                agent_roles.setdefault(target, []).append(role)
        for kind, target in role.copilot:
            if kind == "agent":
                copilot_roles.setdefault(target, []).append(role)
    _check_claude_workflows(root, workflow_roles, tiers_conf, problems)
    _check_claude_agents(root, claude_agent_roles, tiers_conf, problems)
    _check_codex_agents(root, agent_roles, tiers_conf, problems)
    _check_copilot_agents(root, copilot_roles, tiers_conf, problems)
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
            "\nregistry row and its contract section together. A deliberate model pin"
            "\non an exempt line carries `roles-ok: <reason>`.",
            file=sys.stderr,
        )
        return 1
    print(f"agent-roles: registry and vendor role definitions consistent ({count} roles)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
