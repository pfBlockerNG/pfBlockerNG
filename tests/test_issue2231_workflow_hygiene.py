"""Workflow-file hygiene gates (issue #2231).

For WORKFLOW files, duplicate-key/schema/expression validation is actionlint's
job (the `actionlint` job in test.yml; #2232).
actionlint speaks only the workflow schema, so `.github/actions/*/action.yml`
has no duplicate-key gate — tolerable because a malformed action manifest
fails its referencing job LOUDLY at use, unlike a workflow file, which GitHub
disables silently. These gates cover what actionlint cannot:

1. No bare ``$GITHUB_*``/``$RUNNER_*`` in ``env:`` map values: GitHub Actions
   substitutes only ``${{ }}`` expressions there, never shell variables — such
   a value reaches the job as a literal dollar-string (schema-legal, so
   actionlint accepts it). Paths derived from runner variables belong in
   ``run:`` bodies.
2. Every workflow arming the hermetic egress gate installs ``iptables`` and
   proves it usable before the suite runs (issue #2261).
3. The ``actionlint`` job keeps its embedded ShellCheck pass over ``run:``
   bodies, and no config filters that pass's findings away (issue #2241).
4. Dispatchable workflows own top-level concurrency; artifact chains keep one
   upload/download action major at the highest major both actions publish
   (issue #2725); container invocations pass ``--init``; and downstream jobs
   consume prepared SHA pins (issue #2413).
"""

from __future__ import annotations

import ast
import re
import shlex
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple, cast

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow_files() -> list[Path]:
    workflows = ROOT / ".github/workflows"
    files = sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])
    actions = ROOT / ".github/actions"
    files += sorted([*actions.glob("*/action.yml"), *actions.glob("*/action.yaml")])
    assert files, "no workflow files found — wrong ROOT?"
    return files


# --------------------------------------------------------------------------- #
# 1. env: map values are never shell-expanded.
# --------------------------------------------------------------------------- #

# $GITHUB_FOO and ${GITHUB_FOO} alike; ${{ github.foo }} never matches (lowercase).
_BARE_RUNNER_VAR = re.compile(r"\$\{?(?:GITHUB|RUNNER)_[A-Z]")
_ENV_KEY = re.compile(r"^(\s*)env:\s*(?:#.*)?$")
_MAP_ENTRY = re.compile(r"^(\s*)([A-Za-z_][\w.-]*):\s*(.*)$")
# `key: |` / `key: >` open a block scalar (a run body, a folded step name).
# The `- ` list-item form puts SIBLING keys two columns deeper than the dash,
# so the scalar's effective indent is the KEY's, not the dash's.
_BLOCK_SCALAR = re.compile(r"^(\s*)(- )?[\w.-]+:\s*[|>][+-]?\d*\s*(?:#.*)?$")


def _env_map_offences(text: str, where: str) -> list[str]:
    """Line scanner: report env-map entries whose value carries a bare runner
    variable. Tracks block scalars so ``run:`` bodies (plain text to YAML) are
    never scanned — EXCEPT a scalar that is itself an env entry's value, whose
    body is exactly the unexpanded string the job receives — and tracks the
    current ``env:`` block by indentation."""
    offences: list[str] = []
    scalar_indent: int | None = None  # inside a block scalar deeper than this
    scalar_env_key: str | None = None  # ...which is an env VALUE under this key
    env_indent: int | None = None  # inside an env: map opened at this indent
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or (scalar_indent is None and line.lstrip().startswith("#")):
            continue
        indent = len(line) - len(line.lstrip())
        if scalar_indent is not None:
            if indent > scalar_indent:
                if scalar_env_key is not None and _BARE_RUNNER_VAR.search(line):
                    offences.append(f"{where}:{line_no}: env {scalar_env_key}: {line.strip()!r}")
                continue
            scalar_indent = None
            scalar_env_key = None
        if env_indent is not None and indent <= env_indent:
            env_indent = None
        scalar = _BLOCK_SCALAR.match(line)
        if scalar:
            scalar_indent = indent + (2 if scalar.group(2) else 0)
            if env_indent is not None:
                scalar_env_key = line.strip().split(":", 1)[0]
            continue
        env_open = _ENV_KEY.match(line)
        if env_open:
            env_indent = len(env_open.group(1))
            continue
        if env_indent is None:
            continue
        entry = _MAP_ENTRY.match(line)
        if entry and _BARE_RUNNER_VAR.search(entry.group(3)):
            offences.append(f"{where}:{line_no}: env {entry.group(2)}: {entry.group(3)!r}")
    return offences


def test_env_map_values_never_carry_bare_runner_path_variables() -> None:
    offenders: list[str] = []
    for path in _workflow_files():
        offenders.extend(_env_map_offences(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT))))
    assert not offenders, (
        "GitHub Actions performs no shell expansion inside env: map values — these reach "
        "the job as literal dollar-strings. Export the path inside the run: body instead:\n  " + "\n  ".join(offenders)
    )


def test_env_map_scanner_catches_a_planted_offence() -> None:
    """Vacuity guard for the scanner itself: a planted env-map literal is
    reported, and the same variable inside a run: block scalar is not."""
    fixture = (
        "jobs:\n"
        "  x:\n"
        "    env:\n"
        "      GOOD: ${{ github.workspace }}/out\n"
        "      BAD: $GITHUB_WORKSPACE/out\n"
        "      WORSE: ${RUNNER_TEMP}/assets\n"
        "    steps:\n"
        "      - run: |\n"
        '          export FINE="$GITHUB_WORKSPACE/out"\n'
        "      - name: >-\n"
        "          a folded step name must not swallow its sibling keys\n"
        "        env:\n"
        "          AFTER_FOLD: $RUNNER_TEMP/x\n"
        "          MULTILINE: >-\n"
        "            an env VALUE spelled as a block scalar is still\n"
        "            unexpanded $GITHUB_WORKSPACE text\n"
    )
    offences = _env_map_offences(fixture, "fixture.yml")
    assert [o.split(" env ")[1] for o in offences] == [
        "BAD: '$GITHUB_WORKSPACE/out'",
        "WORSE: '${RUNNER_TEMP}/assets'",
        "AFTER_FOLD: '$RUNNER_TEMP/x'",
        "MULTILINE: 'unexpanded $GITHUB_WORKSPACE text'",
    ], offences


# --------------------------------------------------------------------------- #
# 2. The hermetic egress gate has a usable iptables.
# --------------------------------------------------------------------------- #


# The arming match accepts ANY non-empty value because helpers.py arms on any non-empty
# string (a workflow arming with "true" must not escape the gate), and the proof must be
# an iptables INVOCATION rather than a substring — the gate's own diagnostic echo names
# iptables in its error text. Both rules come from review mutations on PR #2262.
_ARMING = re.compile(r"^\s*SMOKE_BLOCK_EGRESS:\s*['\"]?[^'\"\s#]")
_IPTABLES_SETUP = (
    ("installs iptables", re.compile(r"\bapt-get install\b.*\biptables\b")),
    ("proves iptables usable", re.compile(r"\biptables\b.*-S\s+OUTPUT")),
)
_JOB_KEY = re.compile(r"^  ([A-Za-z0-9_.-]+):\s*$", re.MULTILINE)


def _jobs(text: str) -> list[tuple[str, str]]:
    """``(name, body)`` per job, sliced at the next job key. A file with no ``jobs:``
    map is a composite action manifest, whose steps all run inside ONE caller job —
    the whole file is that single unit."""
    top = re.search(r"^jobs:\s*$", text, re.MULTILINE)
    if top is None:
        return [("<action steps>", text)]
    body = text[top.end() :]
    keys = list(_JOB_KEY.finditer(body))
    return [
        (key.group(1), body[key.end() : keys[i + 1].start() if i + 1 < len(keys) else len(body)])
        for i, key in enumerate(keys)
    ]


def _egress_arming_jobs(text: str) -> list[tuple[str, list[str]]]:
    """``(job, what that job never sets up)`` for every job arming the egress gate."""
    return [
        (name, [what for what, pattern in _IPTABLES_SETUP if not pattern.search(body)])
        for name, body in _jobs(text)
        if any(_ARMING.match(line) for line in body.splitlines())
    ]


def test_egress_gating_workflows_install_and_prove_iptables() -> None:
    """Any job that arms the hermetic egress gate (sets SMOKE_BLOCK_EGRESS) runs
    `sudo iptables` from tests/smoke/helpers.py, so the runner needs the binary AND
    the privilege to use it (issue #2261). A runner missing either fails every
    hermetic case halfway through the suite instead of at setup, so the arming job
    must install iptables and prove it usable up front.

    Scoped per JOB, not per file: Actions jobs get their own runner and share no
    state, so a sibling setup job installing iptables leaves the armed job exactly
    as unprotected as no install at all."""
    armed: list[tuple[str, list[str]]] = []
    for path in _workflow_files():
        armed += [
            (f"{path.relative_to(ROOT)}:{job}", missing)
            for job, missing in _egress_arming_jobs(path.read_text(encoding="utf-8"))
        ]
    assert armed, (
        "no workflow job sets SMOKE_BLOCK_EGRESS any more — either the egress gate "
        "moved (update this test) or it was silently dropped (that is a bug)"
    )
    offenders = [f"{where}: {', '.join(missing)}" for where, missing in armed if missing]
    assert not offenders, (
        "a job arming SMOKE_BLOCK_EGRESS must install iptables and prove it usable "
        "in that same job, or block_egress fails every hermetic case mid-run:\n  " + "\n  ".join(offenders)
    )


def test_the_egress_scan_reads_only_the_arming_job() -> None:
    """Vacuity guard: the setup has to sit in the armed job itself. A two-job
    workflow whose OTHER job installs and probes iptables is reported, and moving
    the same two steps into the armed job clears it."""
    setup = "      - run: sudo apt-get install -y iptables\n      - run: sudo iptables -w -S OUTPUT\n"
    armed = '    steps:\n      - run: pytest\n        env:\n          SMOKE_BLOCK_EGRESS: "1"\n'
    elsewhere = f"jobs:\n  setup:\n    steps:\n{setup}  smoke:\n{armed}"
    assert _egress_arming_jobs(elsewhere) == [("smoke", ["installs iptables", "proves iptables usable"])]
    assert _egress_arming_jobs(f"jobs:\n  setup:\n    steps:\n      - run: true\n  smoke:\n{armed}{setup}") == [
        ("smoke", [])
    ]


# --------------------------------------------------------------------------- #
# 3. The actionlint job keeps its embedded shellcheck pass.
# --------------------------------------------------------------------------- #


# Two flags silence the pass. `-shellcheck` with ANY value: actionlint skips the
# pass in silence for every value it cannot resolve to a binary — `-shellcheck=`,
# `-shellcheck ''`, a typo'd path, and `-shellcheck -color` (Go's flag package
# binds `-color` as the value) all exit 0 with run bodies ungraded. `-ignore`:
# a regex that filters matched messages out of the report, so `-ignore
# 'shellcheck reported'` grades the tree and discards every finding. The job
# resolves shellcheck from PATH and its canary proves the resolution, so neither
# flag has a legitimate use here; keeping `-shellcheck` out also keeps the
# canary's argv equivalent to the tree-grading argv.
#
# The left boundary matters: unanchored, the pattern matches the tail of any
# hyphenated token, so the `paths-ignore:` keys and a `canary-shellcheck.yml`
# filename would trip the gate. Comment lines are skipped for the same reason —
# they document the flags, they cannot pass them.
_PASS_SILENCER = re.compile(r"(?<![\w-])--?(?:shellcheck|ignore)\b")


def _pass_silencers(text: str) -> list[str]:
    """Every non-comment line of ``text`` handing actionlint a flag that switches
    its embedded shellcheck pass off or filters the pass's findings away, located
    for the failure message. Line-agnostic by construction, so a flag split from
    its invocation across a `\\` + newline continuation is still its own line."""
    return [
        f"test.yml:{n}: {line.strip()}"
        for n, line in enumerate(text.splitlines(), 1)
        if not line.lstrip().startswith("#") and _PASS_SILENCER.search(line)
    ]


def test_actionlint_job_keeps_the_embedded_shellcheck_pass() -> None:
    """`run:` bodies are shell that no other gate reads — the ShellCheck job
    scans `src scripts .claude/hooks`, never `.github/workflows` (issue #2241).
    An unresolvable `-shellcheck` value turns the pass off silently and `-ignore`
    discards its findings, either way letting a quoting or word-splitting bug in
    a workflow body reach `devel` ungated. The job's own canary catches the
    runtime half (a binary missing from the image); this catches the source
    half."""
    text = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
    assert '"$AL"' in text, "the actionlint job no longer invokes $AL — update this gate"
    assert "echo $CANARY" in text, (
        "the actionlint job lost its shellcheck canary — the fixture whose unquoted expansion "
        "must fail actionlint is what proves the embedded pass ran at all, so without it a "
        "runner whose shellcheck install regressed turns run-body coverage off silently"
    )
    silencers = _pass_silencers(text)
    assert not silencers, (
        "the actionlint job must pass neither -shellcheck (every value actionlint cannot "
        "resolve disables the embedded pass over run: bodies, silently) nor -ignore (which "
        "filters the pass's findings out of the report):\n  " + "\n  ".join(silencers)
    )


def test_no_actionlint_config_filters_the_shellcheck_pass() -> None:
    """`.github/actionlint.yaml` can drop messages per path (`paths: {glob:
    {ignore: [regex]}}`, the skeleton `actionlint -init-config` writes). That
    silences the tree while BOTH canaries stay green: they are graded from
    `$RUNNER_TEMP`, outside the repo project, where no config applies."""
    for name in ("actionlint.yaml", "actionlint.yml"):
        config = ROOT / ".github" / name
        if not config.exists():
            continue
        assert "shellcheck" not in config.read_text(encoding="utf-8").lower(), (
            f".github/{name} filters shellcheck messages out of actionlint's report — run "
            "bodies would go ungraded while the job's canaries, graded outside the project, "
            "stay green"
        )


def test_pass_silencer_scanner_catches_every_spelling() -> None:
    """Vacuity guard: every spelling that silences the pass is reported —
    including the three that look harmless on their own line (an explicit path,
    `-color` swallowed as the value, and an `-ignore` regex) — while prose and
    hyphenated tokens are not."""
    assert _pass_silencers('xargs -0 "$AL" -shellcheck= -color') == ['test.yml:1: xargs -0 "$AL" -shellcheck= -color']
    assert _pass_silencers("\"$AL\" -shellcheck '' f.yml") == ["test.yml:1: \"$AL\" -shellcheck '' f.yml"]
    assert _pass_silencers('"$AL" \\\n  -shellcheck=  -color') == ["test.yml:2: -shellcheck=  -color"]
    assert _pass_silencers('xargs -0 "$AL" -shellcheck -color') == ['test.yml:1: xargs -0 "$AL" -shellcheck -color']
    assert _pass_silencers('"$AL" -shellcheck=/usr/local/bin/shellcheck f.yml') == [
        'test.yml:1: "$AL" -shellcheck=/usr/local/bin/shellcheck f.yml'
    ]
    assert _pass_silencers('"$AL" --shellcheck=/usr/bin/shellcheckk f.yml') == [
        'test.yml:1: "$AL" --shellcheck=/usr/bin/shellcheckk f.yml'
    ]
    assert _pass_silencers("xargs -0 \"$AL\" -color -ignore 'shellcheck reported issue'") == [
        "test.yml:1: xargs -0 \"$AL\" -color -ignore 'shellcheck reported issue'"
    ]
    assert _pass_silencers('"$AL" -color f.yml') == []
    # Prose must not trip it: a comment cannot pass a flag, `paths-ignore:` and a
    # `canary-shellcheck.yml` filename are not flags, and `--norc` is not one either.
    assert _pass_silencers("          # never pass -shellcheck here, nor -ignore") == []
    assert _pass_silencers("# actionlint runs shellcheck --norc; see .shellcheckrc") == []
    assert _pass_silencers("      paths-ignore:\n        - '**.md'") == []
    assert _pass_silencers('> "$RUNNER_TEMP/canary-shellcheck.yml"') == []


# --------------------------------------------------------------------------- #
# 4. Dispatchable workflows own top-level concurrency.
# --------------------------------------------------------------------------- #


_EXTERNAL_TRIGGERS = {"workflow_dispatch", "push", "schedule", "release"}


def _workflow_sources() -> dict[str, str]:
    directory = ROOT / ".github/workflows"
    paths = {path.name: path for pattern in ("*.yml", "*.yaml") for path in directory.glob(pattern)}
    assert paths, f"no workflow files discovered under {directory}"
    return {name: paths[name].read_text(encoding="utf-8") for name in sorted(paths)}


def _workflow_document(source: str, where: str) -> dict[object, object]:
    try:
        document: object = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise AssertionError(f"{where}: rule=yaml: invalid workflow YAML: {exc}") from exc
    assert isinstance(document, dict), f"{where}: rule=yaml: workflow must be a non-empty YAML mapping"
    return document


def _trigger_names(document: dict[object, object]) -> set[str]:
    triggers = document.get(True, document.get("on"))  # PyYAML 1.1 resolves a plain `on` key to True.
    if isinstance(triggers, str):
        return {triggers}
    if isinstance(triggers, list):
        return {trigger for trigger in triggers if isinstance(trigger, str)}
    if isinstance(triggers, dict):
        return {trigger for trigger in triggers if isinstance(trigger, str)}
    return set()


def _concurrency_scan(sources: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    classifications: dict[str, str] = {}
    offences: list[str] = []
    for where, source in sources.items():
        document = _workflow_document(source, where)
        triggers = _trigger_names(document)
        if triggers & _EXTERNAL_TRIGGERS:
            classifications[where] = "dispatchable"
            concurrency = document.get("concurrency")
            valid = (
                isinstance(concurrency, dict)
                and isinstance(concurrency.get("group"), str)
                and bool(concurrency["group"].strip())
            )
            if not valid:
                offences.append(
                    f"{where}: rule=concurrency: dispatchable triggers {sorted(triggers & _EXTERNAL_TRIGGERS)!r} "
                    "require top-level concurrency"
                )
        elif triggers == {"workflow_call"}:
            classifications[where] = "reusable-only"
        else:
            classifications[where] = "internal-only"
    return classifications, offences


def test_dispatchable_workflows_have_top_level_concurrency() -> None:
    sources = _workflow_sources()
    classifications, offences = _concurrency_scan(sources)
    assert set(classifications) == set(sources)
    assert not offences, "workflow concurrency hygiene failed:\n  " + "\n  ".join(offences)


def test_concurrency_scanner_handles_yaml_trigger_shapes_and_planted_offences() -> None:
    sources = {
        "quoted.yaml": (
            '"on":\n  "workflow_dispatch":\n'
            "concurrency:\n  group: >-\n    quoted-${{ github.ref }} # parsed as data\n"
            "jobs: {}\n"
        ),
        "mixed.yml": (
            "on:\n  workflow_call:\n  schedule:\n    - cron: '0 1 * * *'\n"
            "concurrency:\n  group: mixed-${{ github.ref }} # inline comment\njobs: {}\n"
        ),
        "internal.yml": "on:\n  workflow_run:\n  pull_request:\njobs: {}\n",
        "missing.yml": "on:\n  push:\njobs: {}\n",
        "empty.yaml": "on:\n  release:\nconcurrency:\n  group: '' # empty after YAML decoding\njobs: {}\n",
        "scalar.yml": "on:\n  workflow_dispatch:\nconcurrency: text-decoy\njobs: {}\n",
        "nested-only.yml": (
            "# concurrency: comments cannot satisfy the rule\n"
            "on:\n  push:\njobs:\n  test:\n    concurrency:\n      group: nested\n"
        ),
    }
    classifications, offences = _concurrency_scan(sources)
    assert classifications == {
        "quoted.yaml": "dispatchable",
        "mixed.yml": "dispatchable",
        "internal.yml": "internal-only",
        "missing.yml": "dispatchable",
        "empty.yaml": "dispatchable",
        "scalar.yml": "dispatchable",
        "nested-only.yml": "dispatchable",
    }
    assert offences == [
        "missing.yml: rule=concurrency: dispatchable triggers ['push'] require top-level concurrency",
        "empty.yaml: rule=concurrency: dispatchable triggers ['release'] require top-level concurrency",
        "scalar.yml: rule=concurrency: dispatchable triggers ['workflow_dispatch'] require top-level concurrency",
        "nested-only.yml: rule=concurrency: dispatchable triggers ['push'] require top-level concurrency",
    ]


@pytest.mark.parametrize(("where", "source"), (("empty.yaml", ""), ("invalid.yml", "on: [\n")))
def test_workflow_parser_fails_closed_with_file_and_rule_diagnostics(where: str, source: str) -> None:
    with pytest.raises(AssertionError, match=rf"^{re.escape(where)}: rule=yaml:"):
        _workflow_document(source, where)


@pytest.mark.parametrize("workflow", ("image-refresh.yml", "nightly-failure-alert.yml"))
def test_lossless_operational_workflows_keep_every_pending_event(workflow: str) -> None:
    concurrency = _workflow_document(_workflow_sources()[workflow], workflow)["concurrency"]
    assert isinstance(concurrency, dict)
    assert concurrency.get("queue") == "max"
    assert concurrency.get("cancel-in-progress") is False


# --------------------------------------------------------------------------- #
# 5. Artifact producer/consumer chains keep one action major.
# --------------------------------------------------------------------------- #


class _Artifact(NamedTuple):
    workflow: str
    job: str
    name: str
    major: int


class _ArtifactJob(NamedTuple):
    produced: tuple[_Artifact, ...]
    outputs: Mapping[str, frozenset[str]]


_DownloadKey = tuple[str, str, int, int, tuple[tuple[str, str], ...], tuple[str, ...]]


_ARTIFACT_ACTION_REF = re.compile(r"^actions/(?P<kind>upload|download)-artifact@.+$")
_ARTIFACT_ACTION = re.compile(r"^actions/(?P<kind>upload|download)-artifact@v(?P<major>[0-9]+)(?:\.[0-9]+){0,2}$")
# Frozen 2026-08-27 from the GitHub API (issue #2728). Highest common is v7.
_KNOWN_ARTIFACT_MAJORS: dict[str, frozenset[int]] = {
    "upload": frozenset({1, 2, 3, 4, 5, 6, 7}),
    "download": frozenset({1, 2, 3, 4, 5, 6, 7, 8}),
}
_HIGHEST_COMMON_ARTIFACT_MAJOR = max(_KNOWN_ARTIFACT_MAJORS["upload"] & _KNOWN_ARTIFACT_MAJORS["download"])
_GH_EXPRESSION = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
_UNRESOLVED_EXPRESSION = re.compile(r"<unresolved:(?P<expression>[^>]+)>")


def _artifact_action_match(uses: object, where: str) -> re.Match[str] | None:
    if not isinstance(uses, str):
        return None
    match = _ARTIFACT_ACTION.fullmatch(uses)
    if _ARTIFACT_ACTION_REF.fullmatch(uses) and match is None:
        raise AssertionError(f"{where}: rule=artifact-major: unclassified action ref {uses!r}")
    return match


def _expression_parts(source: str, separator: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote = ""
    index = 0
    while index < len(source):
        char = source[index]
        if quote:
            if char == quote and (index == 0 or source[index - 1] != "\\"):
                quote = ""
        elif char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and source.startswith(separator, index):
            parts.append(source[start:index].strip())
            start = index + len(separator)
            index += len(separator) - 1
        index += 1
    parts.append(source[start:].strip())
    return parts


def _expression_values(expression: str, context: Mapping[str, frozenset[str]]) -> frozenset[str]:
    expression = expression.strip()
    alternatives = _expression_parts(expression, "||")
    if len(alternatives) > 1:
        return frozenset().union(*(_expression_values(part, context) for part in alternatives))
    conditions = _expression_parts(expression, "&&")
    if len(conditions) > 1:
        return _expression_values(conditions[-1], context)
    if expression.startswith("format(") and expression.endswith(")"):
        arguments = _expression_parts(expression[7:-1], ",")
        try:
            template = ast.literal_eval(arguments[0])
        except (SyntaxError, ValueError):
            template = None
        if isinstance(template, str):
            values = [_expression_values(argument, context) for argument in arguments[1:]]
            rendered = {template}
            for position, candidates in enumerate(values):
                rendered = {
                    value.replace(f"{{{position}}}", candidate) for value in rendered for candidate in candidates
                }
            return frozenset(rendered)
    if expression in context:
        return context[expression]
    step_output = re.fullmatch(r"steps\.[A-Za-z0-9_-]+\.outputs\.([A-Za-z0-9_-]+)", expression)
    if step_output is not None and f"inputs.{step_output.group(1)}" in context:
        return context[f"inputs.{step_output.group(1)}"]
    if expression.startswith(("needs.", "jobs.")):
        return frozenset({f"<unresolved:{expression}>"})
    try:
        literal = ast.literal_eval(expression)
    except (SyntaxError, ValueError):
        literal = None
    if isinstance(literal, (str, int, bool)):
        return frozenset({str(literal)})
    return frozenset({f"${{{{ {expression} }}}}"})


def _scalar_values(value: object, context: Mapping[str, frozenset[str]]) -> frozenset[str]:
    if not isinstance(value, str):
        return frozenset()
    matches = list(_GH_EXPRESSION.finditer(value))
    if not matches:
        return frozenset({value})
    if len(matches) == 1 and matches[0].span() == (0, len(value)):
        return _expression_values(matches[0].group(1), context)
    rendered = {value}
    for match in matches:
        token = match.group(0)
        rendered = {
            candidate.replace(token, replacement, 1)
            for candidate in rendered
            for replacement in _expression_values(match.group(1), context)
        }
    return frozenset(rendered)


def _trigger_config(document: Mapping[object, object], trigger: str) -> Mapping[object, object]:
    triggers = document.get(True, document.get("on"))
    if not isinstance(triggers, dict):
        return {}
    config = triggers.get(trigger)
    return config if isinstance(config, dict) else {}


def _default_inputs(document: Mapping[object, object]) -> dict[str, frozenset[str]]:
    result: dict[str, frozenset[str]] = {}
    for trigger in ("workflow_call", "workflow_dispatch"):
        inputs = _trigger_config(document, trigger).get("inputs", {})
        if not isinstance(inputs, dict):
            continue
        for name, config in inputs.items():
            if not isinstance(name, str) or name in result:
                continue
            default = config.get("default", "") if isinstance(config, dict) else ""
            result[name] = frozenset({str(default)})
    return result


def _needs(job: Mapping[object, object]) -> tuple[str, ...]:
    value = job.get("needs", ())
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _workflow_call_path(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"\./\.github/workflows/(?P<name>[^/]+\.ya?ml)", value)
    return match.group("name") if match else None


def _glob_patterns_overlap(left: str, right: str) -> bool:
    pending = {(0, 0)}
    seen: set[tuple[int, int]] = set()
    while pending:
        left_index, right_index = pending.pop()
        if (left_index, right_index) in seen:
            continue
        seen.add((left_index, right_index))
        if left_index == len(left) and right_index == len(right):
            return True
        if left_index < len(left) and left[left_index] == "*":
            pending.add((left_index + 1, right_index))
        if right_index < len(right) and right[right_index] == "*":
            pending.add((left_index, right_index + 1))
        if left_index == len(left) or right_index == len(right):
            continue
        left_token = left[left_index]
        right_token = right[right_index]
        if left_token == "*" and right_token == "*":
            continue
        if left_token not in "*?" and right_token not in "*?" and left_token != right_token:
            continue
        pending.add(
            (
                left_index if left_token == "*" else left_index + 1,
                right_index if right_token == "*" else right_index + 1,
            )
        )
    return False


def _selectors_match(name: str, selector: str) -> bool:
    import fnmatch

    if fnmatch.fnmatchcase(name, selector):
        return True
    dynamic_name = _GH_EXPRESSION.sub("*", name)
    dynamic_selector = _GH_EXPRESSION.sub("*", selector)
    return _glob_patterns_overlap(dynamic_name, dynamic_selector)


def _artifact_chain_offences(sources: dict[str, str]) -> list[str]:
    documents = {name: _workflow_document(source, name) for name, source in sources.items()}
    offences: set[str] = set()
    download_matches: dict[_DownloadKey, bool] = {}
    download_selectors: dict[_DownloadKey, set[str]] = {}
    major_mismatches: dict[_DownloadKey, set[tuple[str, str, int]]] = {}
    required_downloads: set[_DownloadKey] = set()

    def scan_instance(
        workflow: str,
        supplied_inputs: Mapping[str, frozenset[str]],
        inherited: tuple[_Artifact, ...],
        stack: tuple[tuple[str, str], ...],
        require_matches: bool,
    ) -> tuple[tuple[_Artifact, ...], Mapping[str, frozenset[str]]]:
        assert workflow not in {caller for caller, _ in stack}, (
            f"{workflow}: rule=artifact-major: recursive reusable workflow"
        )
        document = documents[workflow]
        inputs = _default_inputs(document)
        inputs.update(supplied_inputs)
        base_context = {f"inputs.{name}": values for name, values in inputs.items()}
        jobs = document.get("jobs")
        assert isinstance(jobs, dict), f"{workflow}: rule=artifact-major: jobs must be a mapping"
        states: dict[str, _ArtifactJob] = {}
        pending = {name for name, job in jobs.items() if isinstance(name, str) and isinstance(job, dict)}
        while pending:
            ready = [
                name
                for name in sorted(pending)
                if all(dependency in states for dependency in _needs(cast(Mapping[object, object], jobs[name])))
            ]
            assert ready, f"{workflow}: rule=artifact-major: cyclic or missing needs {sorted(pending)!r}"
            for job_name in ready:
                job = cast(Mapping[object, object], jobs[job_name])
                dependencies = _needs(job)
                upstream = tuple(
                    [*inherited, *(artifact for dependency in dependencies for artifact in states[dependency].produced)]
                )
                context = dict(base_context)
                for dependency in dependencies:
                    for output, values in states[dependency].outputs.items():
                        context[f"needs.{dependency}.outputs.{output}"] = values
                call_path = _workflow_call_path(job.get("uses"))
                if call_path is not None:
                    assert call_path in documents, (
                        f"{workflow}:{job_name}: rule=artifact-major: local workflow {call_path!r} does not exist"
                    )
                    with_values = job.get("with", {})
                    assert isinstance(with_values, dict), (
                        f"{workflow}:{job_name}: rule=artifact-major: reusable with: must be a mapping"
                    )
                    called_inputs = {
                        name: _scalar_values(value, context)
                        for name, value in with_values.items()
                        if isinstance(name, str)
                    }
                    called_produced, called_outputs = scan_instance(
                        call_path, called_inputs, upstream, (*stack, (workflow, job_name)), require_matches
                    )
                    lineage = tuple(
                        dict.fromkeys(
                            [
                                *(artifact for dependency in dependencies for artifact in states[dependency].produced),
                                *called_produced,
                            ]
                        )
                    )
                    states[job_name] = _ArtifactJob(lineage, called_outputs)
                    pending.remove(job_name)
                    continue

                produced: list[_Artifact] = []
                steps = job.get("steps", [])
                assert isinstance(steps, list), f"{workflow}:{job_name}: rule=artifact-major: steps must be a list"
                for step_index, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue
                    match = _artifact_action_match(step.get("uses"), f"{workflow}:{job_name}:step-{step_index}")
                    if match is None:
                        continue
                    action_inputs = step.get("with", {})
                    assert isinstance(action_inputs, dict), (
                        f"{workflow}:{job_name}: rule=artifact-major: artifact action with: must be a mapping"
                    )
                    selector_value = action_inputs.get("name", action_inputs.get("pattern", "*"))
                    selectors = _scalar_values(selector_value, context)
                    assert selectors, f"{workflow}:{job_name}: rule=artifact-major: empty artifact selector"
                    unresolved = sorted(
                        {
                            match.group("expression")
                            for selector in selectors
                            for match in _UNRESOLVED_EXPRESSION.finditer(selector)
                        }
                    )
                    if unresolved:
                        offences.add(
                            f"{workflow}:{job_name}:step-{step_index}: rule=artifact-major: "
                            f"unresolved artifact selector {unresolved!r}"
                        )
                        continue
                    major = int(match.group("major"))
                    if match.group("kind") == "upload":
                        produced.extend(_Artifact(workflow, job_name, selector, major) for selector in selectors)
                        continue
                    key = (workflow, job_name, step_index, major, stack, tuple(sorted(selectors)))
                    download_selectors.setdefault(key, set()).update(selectors)
                    download_matches.setdefault(key, False)
                    if require_matches:
                        required_downloads.add(key)
                    available = (*upstream, *produced)
                    matched = {
                        artifact
                        for selector in selectors
                        for artifact in available
                        if _selectors_match(artifact.name, selector)
                    }
                    if not matched:
                        continue
                    download_matches[key] = True
                    by_name: dict[str, set[tuple[str, str]]] = {}
                    for artifact in matched:
                        by_name.setdefault(artifact.name, set()).add((artifact.workflow, artifact.job))
                        if artifact.major != major:
                            major_mismatches.setdefault(key, set()).add(
                                (artifact.workflow, artifact.job, artifact.major)
                            )
                    for name, owners in by_name.items():
                        if len(owners) > 1:
                            offences.add(
                                f"{workflow}:{job_name}:step-{step_index}: rule=artifact-major: "
                                f"ambiguous producers for {name!r}: {sorted(owners)!r}"
                            )
                job_outputs: dict[str, frozenset[str]] = {}
                configured_outputs = job.get("outputs", {})
                if isinstance(configured_outputs, dict):
                    job_outputs = {
                        name: _scalar_values(value, context)
                        for name, value in configured_outputs.items()
                        if isinstance(name, str)
                    }
                lineage = tuple(
                    dict.fromkeys(
                        [
                            *(artifact for dependency in dependencies for artifact in states[dependency].produced),
                            *produced,
                        ]
                    )
                )
                states[job_name] = _ArtifactJob(lineage, job_outputs)
                pending.remove(job_name)

        all_produced = tuple(dict.fromkeys(artifact for state in states.values() for artifact in state.produced))
        output_context = dict(base_context)
        for job_name, state in states.items():
            for output, values in state.outputs.items():
                output_context[f"jobs.{job_name}.outputs.{output}"] = values
        call_outputs = _trigger_config(document, "workflow_call").get("outputs", {})
        workflow_outputs: dict[str, frozenset[str]] = {}
        if isinstance(call_outputs, dict):
            for name, config in call_outputs.items():
                if isinstance(name, str) and isinstance(config, dict):
                    workflow_outputs[name] = _scalar_values(config.get("value"), output_context)
        return all_produced, workflow_outputs

    direct_names: dict[str, tuple[_Artifact, ...]] = {}
    workflow_run_roots: list[str] = []
    for workflow, document in documents.items():
        triggers = _trigger_names(document)
        if "workflow_run" in triggers:
            workflow_run_roots.append(workflow)
        if triggers != {"workflow_run"}:
            root_produced, _ = scan_instance(
                workflow,
                {},
                (),
                (("<direct>", workflow),),
                "workflow_run" not in triggers and triggers != {"workflow_call"},
            )
            name = document.get("name")
            if isinstance(name, str) and triggers != {"workflow_call"}:
                direct_names[name] = tuple(dict.fromkeys((*direct_names.get(name, ()), *root_produced)))
    for workflow in workflow_run_roots:
        names = _trigger_config(documents[workflow], "workflow_run").get("workflows", [])
        assert isinstance(names, list), f"{workflow}: rule=artifact-major: workflow_run.workflows must be a list"
        inherited = tuple(
            artifact for name in names if isinstance(name, str) for artifact in direct_names.get(name, ())
        )
        missing = [name for name in names if isinstance(name, str) and name not in direct_names]
        if missing:
            offences.add(f"{workflow}: rule=artifact-major: workflow_run names missing producers {missing!r}")
        scan_instance(workflow, {}, inherited, (("<workflow_run>", workflow),), True)
    for key, matched in sorted(download_matches.items()):
        workflow, job, step, major, _, _ = key
        if not matched and key in required_downloads:
            offences.add(
                f"{workflow}:{job}:step-{step}: rule=artifact-major: no producer matches "
                f"{sorted(download_selectors[key])!r}"
            )
    for key, producers in sorted(major_mismatches.items()):
        workflow, job, step, major, _, _ = key
        offences.add(
            f"{workflow}:{job}:step-{step}: rule=artifact-major: download v{major} "
            f"mismatches producers {sorted(producers)!r}"
        )
    return sorted(offences)


def test_artifact_action_majors_match_per_producer_consumer_chain() -> None:
    offences = _artifact_chain_offences(_workflow_sources())
    assert not offences, "artifact chain hygiene failed:\n  " + "\n  ".join(offences)


def _live_yaml_sources() -> dict[str, str]:
    return {str(path.relative_to(ROOT)): path.read_text(encoding="utf-8") for path in _workflow_files()}


def _iter_step_uses(document: Mapping[object, object], where: str) -> list[tuple[str, object]]:
    """Step ``uses:`` from a workflow ``jobs.*.steps`` or a composite ``runs.steps``."""
    found: list[tuple[str, object]] = []
    jobs = document.get("jobs")
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for index, step in enumerate(steps):
                if isinstance(step, dict) and "uses" in step:
                    found.append((f"{where}:{job_name}:step-{index}", step.get("uses")))
    runs = document.get("runs")
    if isinstance(runs, dict):
        steps = runs.get("steps")
        if isinstance(steps, list):
            for index, step in enumerate(steps):
                if isinstance(step, dict) and "uses" in step:
                    found.append((f"{where}:runs:step-{index}", step.get("uses")))
    return found


def _live_artifact_offences(sources: dict[str, str]) -> list[str]:
    """issue #2725: every live upload/download-artifact pin must exist upstream
    and sit at the highest major both actions publish.

    Walks parsed YAML so quoted ``uses:``, folded scalars, and composite-action
    steps are visible; comment lines are not pins.
    """
    offences: list[str] = []
    for name, text in sources.items():
        document = _workflow_document(text, name)
        for location, uses in _iter_step_uses(document, name):
            match = _artifact_action_match(uses, location)
            if match is None:
                continue
            kind = match.group("kind")
            major = int(match.group("major"))
            known = _KNOWN_ARTIFACT_MAJORS[kind]
            if major not in known:
                offences.append(
                    f"{location}: actions/{kind}-artifact@v{major} is not a known "
                    f"upstream major (known: {sorted(known)})"
                )
            elif major != _HIGHEST_COMMON_ARTIFACT_MAJOR:
                offences.append(
                    f"{location}: pin actions/{kind}-artifact to "
                    f"v{_HIGHEST_COMMON_ARTIFACT_MAJOR} (highest common existing major), "
                    f"not v{major}"
                )
    return offences


def test_live_artifact_actions_use_highest_common_existing_major() -> None:
    """issue #2725: producer/consumer major matching does not prove the pin
    exists upstream. ``upload-artifact@v8`` matched ``download-artifact@v8``
    and passed every gate, then failed at Set up job.

    Live workflow pins must be a known upstream major for that action and use
    the highest major both actions publish, so the pair stays matched at a
    resolvable ref. Fixture YAML in this file is out of scope — those literals
    exercise the scanner, not GitHub's tag namespace.
    """
    offences = _live_artifact_offences(_live_yaml_sources())
    assert not offences, "live artifact pins failed:\n  " + "\n  ".join(offences)


def test_live_artifact_gate_sees_quoted_uses_refs() -> None:
    """Quoted ``uses:`` is a real workflow shape (this file's own fixtures) and
    is the original #2725 incident with quotes added. A line regex that requires
    an unquoted value misses it; a comment line is not a pin.
    """
    sources = {
        "quoted.yml": """\
on: workflow_dispatch
jobs:
  up:
    steps:
      - uses: "actions/upload-artifact@v8"
        with: {name: pkg}
  down:
    needs: up
    steps:
      - uses: 'actions/download-artifact@v8'
        with: {name: pkg}
""",
        "comment.yml": """\
on: workflow_dispatch
jobs:
  x:
    steps:
      - run: "true"
#      - uses: actions/upload-artifact@v8
""",
        ".github/actions/example/action.yml": """\
runs:
  using: composite
  steps:
    - uses: actions/upload-artifact@v8
      with: {name: pkg}
""",
    }
    offences = _live_artifact_offences(sources)
    assert any("quoted.yml" in item and "upload-artifact@v8" in item and "not a known" in item for item in offences), (
        offences
    )
    assert any("quoted.yml" in item and "download-artifact" in item and "not v8" in item for item in offences), offences
    assert any("action.yml" in item and "upload-artifact@v8" in item and "not a known" in item for item in offences), (
        offences
    )
    assert not any("comment.yml" in item for item in offences), offences


def test_artifact_scanner_follows_needs_reusable_inputs_outputs_and_workflow_run() -> None:
    sources = {
        "producer.yml": """\
name: Producer
on:
  workflow_call:
    inputs:
      artifact: {type: string, default: pkg}
    outputs:
      artifact:
        value: ${{ inputs.artifact }}
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@v7
        with: {name: "${{ inputs.artifact }}"}
""",
        "root.yaml": """\
name: Root
"on": workflow_dispatch
jobs:
  make:
    uses: ./.github/workflows/producer.yml
    with: {artifact: pkg}
  bridge:
    needs: make
    steps:
      - run: "true"
  consume-output:
    needs: make
    steps:
      - uses: actions/download-artifact@v7
        with: {name: "${{ needs.make.outputs.artifact }}"}
  consume:
    needs: bridge
    steps:
      - uses: actions/download-artifact@v7
        with: {name: pkg}
      - uses: actions/upload-artifact@v8
        with: {name: status-v8}
  consume-v8:
    needs: consume
    steps:
      - uses: actions/download-artifact@v8
        with: {name: status-v8}
""",
        "callback.yml": """\
on:
  workflow_run:
    workflows: [Root]
jobs:
  consume:
    steps:
      - uses: actions/download-artifact@v7
        with: {pattern: "p*"}
""",
    }
    assert _artifact_chain_offences(sources) == []


def test_artifact_scanner_reports_direct_ambiguous_wrong_output_and_pattern_majors() -> None:
    sources = {
        "producer.yml": """\
on:
  workflow_call:
    outputs:
      artifact: {value: pkg}
jobs:
  first:
    steps:
      - uses: actions/upload-artifact@v7
        with: {name: pkg}
      - uses: actions/upload-artifact@v7
        with: {name: family-one}
  duplicate:
    steps:
      - uses: actions/upload-artifact@v7
        with: {name: pkg}
      - uses: actions/upload-artifact@v8
        with: {name: family-two}
""",
        "root.yaml": """\

on: workflow_dispatch
jobs:
  make:
    uses: ./.github/workflows/producer.yml
  ambiguous:
    needs: make
    steps:
      - uses: actions/download-artifact@v7
        with: {name: pkg}
  wrong-output:
    needs: make
    steps:
      - uses: actions/download-artifact@v7
        with: {name: "${{ needs.make.outputs.missing }}"}
  pattern:
    needs: make
    steps:
      - uses: actions/download-artifact@v7
        with: {pattern: "family-*"}
""",
    }
    offences = _artifact_chain_offences(sources)
    assert any(
        "root.yaml:ambiguous:step-0: rule=artifact-major: ambiguous producers for 'pkg'" in item for item in offences
    )
    assert any(
        "root.yaml:wrong-output:step-0: rule=artifact-major: "
        "unresolved artifact selector ['needs.make.outputs.missing']" in item
        for item in offences
    )
    assert any(
        "root.yaml:pattern:step-0: rule=artifact-major: download v7 mismatches producers" in item
        and "('producer.yml', 'duplicate', 8)" in item
        for item in offences
    )


def test_artifact_scanner_rejects_unmatched_workflow_run_selector() -> None:
    sources = {
        "root.yml": """\
name: Root
on: workflow_dispatch
jobs:
  upload:
    steps:
      - uses: "actions/upload-artifact@v8"
        with: {name: expected}
""",
        "callback.yaml": """\
on:
  workflow_run:
    workflows: [Root, Missing]
jobs:
  consume:
    steps:
      - uses: "actions/download-artifact@v8"
        with: {name: typo}
""",
    }
    assert _artifact_chain_offences(sources) == [
        "callback.yaml: rule=artifact-major: workflow_run names missing producers ['Missing']",
        "callback.yaml:consume:step-0: rule=artifact-major: no producer matches ['typo']",
    ]


def test_artifact_scanner_fails_closed_on_broken_job_and_reusable_graphs() -> None:
    with pytest.raises(AssertionError, match=r"missing-needs.yml: rule=artifact-major: cyclic or missing needs"):
        _artifact_chain_offences(
            {
                "missing-needs.yml": """\
on: workflow_dispatch
jobs:
  consume:
    needs: absent
    steps: []
"""
            }
        )
    with pytest.raises(AssertionError, match=r"local workflow 'missing.yml' does not exist"):
        _artifact_chain_offences(
            {
                "missing-local.yml": """\
on: workflow_dispatch
jobs:
  call:
    uses: ./.github/workflows/missing.yml
"""
            }
        )
    with pytest.raises(AssertionError, match=r"recursive reusable workflow"):
        _artifact_chain_offences(
            {
                "a.yml": """\
on: workflow_dispatch
jobs:
  call:
    uses: ./.github/workflows/b.yml
""",
                "b.yml": """\
on: workflow_call
jobs:
  call:
    uses: ./.github/workflows/a.yml
""",
            }
        )


def test_artifact_scanner_accumulates_duplicate_workflow_display_names() -> None:
    sources = {
        "one.yml": """\
name: Producer
on: workflow_dispatch
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@v7
        with: {name: pkg}
""",
        "two.yml": """\
name: Producer
on: workflow_dispatch
jobs:
  upload:
    steps:
      - uses: actions/upload-artifact@v8
        with: {name: pkg}
""",
        "callback.yml": """\
on:
  workflow_run:
    workflows: [Producer]
jobs:
  consume:
    steps:
      - uses: actions/download-artifact@v8
        with: {name: pkg}
""",
    }
    assert _artifact_chain_offences(sources) == [
        "callback.yml:consume:step-0: rule=artifact-major: ambiguous producers for 'pkg': "
        "[('one.yml', 'upload'), ('two.yml', 'upload')]",
        "callback.yml:consume:step-0: rule=artifact-major: download v8 mismatches producers [('one.yml', 'upload', 7)]",
    ]


# --------------------------------------------------------------------------- #
# 6. Every container invocation passes --init.
# --------------------------------------------------------------------------- #


def _option_words(options: str, where: str, rule: str) -> list[str]:
    try:
        return shlex.split(options, comments=False, posix=True)
    except ValueError as exc:
        raise AssertionError(f"{where}: rule={rule}: invalid option quoting: {exc}") from exc


def _container_offences(sources: dict[str, str]) -> list[str]:
    offences: list[str] = []
    for workflow, source in sources.items():
        jobs = _workflow_document(source, workflow).get("jobs")
        assert isinstance(jobs, dict), f"{workflow}: rule=container-init: jobs must be a mapping"
        for job_name, job in jobs.items():
            if not isinstance(job_name, str) or not isinstance(job, dict) or "container" not in job:
                continue
            container = job["container"]
            options = container.get("options") if isinstance(container, dict) else None
            if not isinstance(options, str) or "--init" not in _option_words(
                options, f"{workflow}:{job_name}", "container-init"
            ):
                offences.append(
                    f"{workflow}:{job_name}: rule=container-init: container.options must include exact token --init"
                )
    return offences


def test_workflow_container_blocks_pass_init_in_block_local_options() -> None:
    offences = _container_offences(_workflow_sources())
    assert not offences, "workflow container hygiene failed:\n  " + "\n  ".join(offences)


def test_container_scanner_decodes_only_job_container_options() -> None:
    source = """\
on: workflow_dispatch
jobs:
  quoted:
    container:
      image: example/valid
      options: '--label "odd=a & b"   --init' # inline comment
  folded:
    container:
      image: example/folded
      options: >-
        --rm
        --init
  scalar:
    container: example/scalar
  null-options:
    container: {image: example/null, options: null}
  empty-options:
    container: {image: example/empty, options: ""}
  expression-only:
    container:
      image: example/expression
      options: ${{ inputs.options }}
  comment-only:
    container:
      image: example/comment
      options: --rm # --init
    steps:
      - run: echo --init
  decoy:
    strategy:
      matrix:
        options: [--init]
    steps:
      - run: |
          printf '%s\\n' 'container: {options: --init}'
"""
    assert _container_offences({"containers.yaml": source}) == [
        "containers.yaml:scalar: rule=container-init: container.options must include exact token --init",
        "containers.yaml:null-options: rule=container-init: container.options must include exact token --init",
        "containers.yaml:empty-options: rule=container-init: container.options must include exact token --init",
        "containers.yaml:expression-only: rule=container-init: container.options must include exact token --init",
        "containers.yaml:comment-only: rule=container-init: container.options must include exact token --init",
    ]


_SHELL_OPERATORS = {";", ";;", "&", "&&", "|", "||", "(", ")"}


def _tracked_text_sources() -> dict[str, str]:
    tracked = subprocess.run(
        ["git", "ls-files", "scripts", "tests/smoke"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    sources: dict[str, str] = {}
    for name in tracked:
        path = ROOT / name
        if not path.is_file():
            continue
        try:
            sources[name] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
    return sources


def _logical_shell_lines(source: str) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    start = 1
    parts: list[str] = []
    heredoc: str | None = None
    for line_no, line in enumerate(source.splitlines(), 1):
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        if not parts:
            start = line_no
        if line.endswith("\\"):
            parts.append(line[:-1])
            continue
        parts.append(line)
        command = " ".join(parts)
        logical.append((start, command))
        match = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", command)
        if match is not None:
            heredoc = match.group(2)
        parts = []
    if parts:
        logical.append((start, " ".join(parts)))
    return logical


def _shell_words(source: str, where: str) -> list[tuple[int, list[str]]]:
    commands: list[tuple[int, list[str]]] = []
    bindings: dict[str, str] = {}
    command_v = re.compile(r'(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*["\']?\$\(\s*command\s+-v\s+docker\s*\)["\']?')
    for line_no, logical in _logical_shell_lines(source):
        for match in command_v.finditer(logical):
            bindings[match.group("name")] = "docker"
        bound_reference = any(
            re.search(rf"\$(?:{re.escape(name)}\b|\{{{re.escape(name)}\}})", logical) for name in bindings
        )
        if "docker" not in logical.lower() and not ("run" in logical and bound_reference):
            continue
        lexer = shlex.shlex(logical, posix=True, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        try:
            words = list(lexer)
        except ValueError as exc:
            raise AssertionError(f"{where}:{line_no}: rule=docker-init: invalid shell quoting: {exc}") from exc
        segment: list[str] = []
        for word in [*words, ";"]:
            if word in _SHELL_OPERATORS:
                if segment:
                    for candidate in segment:
                        assignment = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", candidate)
                        if assignment is not None and Path(assignment.group(2)).name == "docker":
                            bindings[assignment.group(1)] = assignment.group(2)
                    resolved: list[str] = []
                    for candidate in segment:
                        variable = re.fullmatch(
                            r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})",
                            candidate,
                        )
                        name = next((group for group in variable.groups() if group), "") if variable else ""
                        resolved.append(bindings.get(name, candidate))
                    commands.append((line_no, resolved))
                    segment = []
            else:
                segment.append(word)
    return commands


_DOCKER_GLOBAL_VALUE_OPTIONS = {
    "--config",
    "--context",
    "--host",
    "--log-level",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
    "-H",
    "-c",
    "-l",
}


def _docker_argv(words: list[str]) -> list[str] | None:
    index = 0
    while index < len(words) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[index]):
        index += 1
    while index < len(words) and words[index] in {"command", "exec", "sudo"}:
        wrapper = words[index]
        index += 1
        if wrapper == "sudo":
            while index < len(words) and words[index].startswith("-"):
                option = words[index]
                index += 1
                if option in {"-C", "-g", "-h", "-p", "-u"} and index < len(words):
                    index += 1
    if index < len(words) and words[index] == "env":
        index += 1
        while index < len(words) and (
            words[index].startswith("-") or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[index])
        ):
            option = words[index]
            index += 1
            if option in {"-C", "--chdir", "-S", "--split-string", "-u", "--unset"} and index < len(words):
                index += 1
    docker = words[index] if index < len(words) else ""
    if Path(docker).name != "docker" and "DOCKER" not in docker:
        return None
    index += 1
    while index < len(words) and words[index] != "run":
        option = words[index]
        if not option.startswith("-"):
            return None
        index += 1
        if option in _DOCKER_GLOBAL_VALUE_OPTIONS and "=" not in option and index < len(words):
            index += 1
    if index >= len(words):
        return None
    return words[index + 1 :]


_DOCKER_VALUE_OPTIONS = {
    "--add-host",
    "--annotation",
    "--attach",
    "--blkio-weight",
    "--blkio-weight-device",
    "--cap-add",
    "--cap-drop",
    "--cgroup-parent",
    "--cgroupns",
    "--cidfile",
    "--cpu-count",
    "--cpu-percent",
    "--cpu-period",
    "--cpu-quota",
    "--cpu-rt-period",
    "--cpu-rt-runtime",
    "--cpu-shares",
    "--cpus",
    "--cpuset-cpus",
    "--cpuset-mems",
    "--device",
    "--device-cgroup-rule",
    "--device-read-bps",
    "--device-read-iops",
    "--device-write-bps",
    "--device-write-iops",
    "--dns",
    "--dns-option",
    "--dns-search",
    "--domainname",
    "--entrypoint",
    "--env",
    "--env-file",
    "--expose",
    "--gpus",
    "--group-add",
    "--health-cmd",
    "--health-interval",
    "--health-retries",
    "--health-start-interval",
    "--health-start-period",
    "--health-timeout",
    "--hostname",
    "--ip",
    "--ip6",
    "--ipc",
    "--isolation",
    "--kernel-memory",
    "--label",
    "--label-file",
    "--link",
    "--link-local-ip",
    "--log-driver",
    "--log-opt",
    "--mac-address",
    "--memory",
    "--memory-reservation",
    "--memory-swap",
    "--memory-swappiness",
    "--mount",
    "--name",
    "--network",
    "--network-alias",
    "--oom-score-adj",
    "--pid",
    "--pids-limit",
    "--platform",
    "--publish",
    "--pull",
    "--restart",
    "--runtime",
    "--security-opt",
    "--shm-size",
    "--stop-signal",
    "--stop-timeout",
    "--storage-opt",
    "--sysctl",
    "--tmpfs",
    "--ulimit",
    "--user",
    "--userns",
    "--uts",
    "--volume",
    "--volume-driver",
    "--volumes-from",
    "--workdir",
    "-a",
    "-c",
    "-e",
    "-h",
    "-l",
    "-m",
    "-p",
    "-u",
    "-v",
    "-w",
}


def _docker_has_init_before_image(argv: list[str]) -> bool:
    index = 0
    while index < len(argv):
        word = argv[index]
        if word == "--init":
            return True
        if word == "--" or not word.startswith("-"):
            return False
        index += 2 if word in _DOCKER_VALUE_OPTIONS and "=" not in word else 1
    return False


def _python_docker_runs(source: str, where: str) -> list[tuple[int, list[str]]]:
    try:
        tree = ast.parse(source, filename=where)
    except SyntaxError as exc:
        raise AssertionError(f"{where}:{exc.lineno}: rule=docker-init: invalid Python: {exc.msg}") from exc
    imported_calls: dict[ast.AST, set[str]] = {}
    subprocess_modules: dict[ast.AST, set[str]] = {}
    scope_types = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def scope_chain(node: ast.AST) -> list[ast.AST]:
        scopes: list[ast.AST] = []
        current = node
        while not isinstance(current, ast.Module):
            current = parents[current]
            if isinstance(current, scope_types):
                scopes.append(current)
        if not scopes or not isinstance(scopes[-1], ast.Module):
            scopes.append(tree)
        return scopes

    bound_argv: dict[ast.AST, dict[str, list[tuple[int, ast.expr]]]] = {}
    functions: dict[ast.AST, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for node in ast.walk(tree):
        scope = scope_chain(node)[0] if not isinstance(node, ast.Module) else tree
        if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            imported_calls.setdefault(scope, set()).update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name in {"call", "check_call", "check_output", "Popen", "run"}
            )
        elif isinstance(node, ast.Import):
            subprocess_modules.setdefault(scope, set()).update(
                alias.asname or alias.name for alias in node.names if alias.name == "subprocess"
            )
        elif isinstance(node, ast.Assign) and isinstance(node.value, (ast.List, ast.Tuple)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bound_argv.setdefault(scope, {}).setdefault(target.id, []).append((node.lineno, node.value))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parent_scope = scope_chain(node)[0]
            functions.setdefault(parent_scope, {})[node.name] = node

    def resolve_factory(argument: ast.expr, seen: frozenset[int] = frozenset()) -> ast.expr:
        if not (
            isinstance(argument, ast.Call)
            and isinstance(argument.func, ast.Name)
            and not argument.args
            and not argument.keywords
        ):
            return argument
        for scope in scope_chain(argument):
            function = functions.get(scope, {}).get(argument.func.id)
            if function is None:
                continue
            if id(function) in seen:
                return argument
            returns = [
                statement
                for statement in function.body
                if isinstance(statement, ast.Return) and statement.value is not None
            ]
            if len(returns) != 1:
                return argument
            result = cast(ast.expr, returns[0].value)
            if isinstance(result, ast.Name):
                bindings = bound_argv.get(function, {}).get(result.id, [])
                candidates = [(line, value) for line, value in bindings if line < returns[0].lineno]
                if candidates:
                    result = max(candidates, key=lambda candidate: candidate[0])[1]
            return resolve_factory(result, seen | {id(function)})
        return argument

    def resolve_argument(argument: ast.expr, call: ast.Call) -> ast.expr:
        if isinstance(argument, ast.Name):
            for scope in scope_chain(call):
                bindings = bound_argv.get(scope, {}).get(argument.id)
                if bindings is None:
                    continue
                candidates = [(line, value) for line, value in bindings if line < call.lineno]
                return max(candidates, key=lambda candidate: candidate[0])[1] if candidates else argument
        if isinstance(argument, ast.Call):
            return resolve_factory(argument)
        return argument

    invocations: list[tuple[int, list[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        is_subprocess = (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and any(function.value.id in subprocess_modules.get(scope, set()) for scope in scope_chain(node))
            and function.attr in {"call", "check_call", "check_output", "Popen", "run"}
        )
        is_os_system = (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id == "os"
            and function.attr == "system"
        )
        is_imported_subprocess = isinstance(function, ast.Name) and any(
            function.id in imported_calls.get(scope, set()) for scope in scope_chain(node)
        )
        if not (is_subprocess or is_imported_subprocess or is_os_system):
            continue
        keyword_arguments = [keyword.value for keyword in node.keywords if keyword.arg == "args"]
        assert len(keyword_arguments) <= 1 and not (node.args and keyword_arguments), (
            f"{where}:{node.lineno}: rule=docker-init: subprocess argv must have one source"
        )
        if node.args:
            argument = node.args[0]
        elif keyword_arguments and not is_os_system:
            argument = keyword_arguments[0]
        else:
            continue
        argument = resolve_argument(argument, node)
        words: list[str] | None = None
        if isinstance(argument, (ast.List, ast.Tuple)):
            words = [
                cast(str, item.value) if isinstance(item, ast.Constant) and isinstance(item.value, str) else "<dynamic>"
                for item in argument.elts
            ]
        elif isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            words = _option_words(argument.value, f"{where}:{node.lineno}", "docker-init")
        if words is not None and _docker_argv(words) is not None:
            invocations.append((node.lineno, words))
    return invocations


_PHP_STRING_ASSIGN = re.compile(
    r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<quote>['\"])(?P<body>.*?)(?P=quote)\s*;",
    re.DOTALL,
)
_PHP_CONCAT_ASSIGN = re.compile(
    r"\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<body>(?:'[^']*'|\"[^\"]*\")(?:\s*\.\s*(?:'[^']*'|\"[^\"]*\"))+)\s*;",
    re.DOTALL,
)
_PHP_STRING_LITERAL = re.compile(r"'([^']*)'|\"([^\"]*)\"")
_PHP_SHELL_CALL = re.compile(
    r"\b(?:exec|passthru|shell_exec|system)\s*\(\s*"
    r"(?:(?P<quote>['\"])(?P<body>.*?)(?P=quote)|\$(?P<variable>[A-Za-z_][A-Za-z0-9_]*))",
    re.DOTALL,
)


def _php_docker_runs(source: str, where: str) -> list[tuple[int, list[str]]]:
    variables: dict[str, str] = {}
    for match in _PHP_STRING_ASSIGN.finditer(source):
        line_start = source.rfind("\n", 0, match.start()) + 1
        if not source[line_start : match.start()].lstrip().startswith(("//", "#", "*")):
            variables[match.group("name")] = match.group("body")
    for match in _PHP_CONCAT_ASSIGN.finditer(source):
        variables[match.group("name")] = "".join(
            next((value for value in literal if value), "")
            for literal in _PHP_STRING_LITERAL.findall(match.group("body"))
        )
    invocations: list[tuple[int, list[str]]] = []
    for match in _PHP_SHELL_CALL.finditer(source):
        line_start = source.rfind("\n", 0, match.start()) + 1
        if source[line_start : match.start()].lstrip().startswith(("//", "#", "*")):
            continue
        body = match.group("body")
        if body is None:
            body = variables.get(match.group("variable"))
        if body is None:
            continue
        line_no = source.count("\n", 0, match.start()) + 1
        words = _option_words(body, f"{where}:{line_no}", "docker-init")
        if _docker_argv(words) is not None:
            invocations.append((line_no, words))
    return invocations


def _docker_run_offences(sources: dict[str, str]) -> list[str]:
    offences: list[str] = []
    for where, source in sources.items():
        suffix = Path(where).suffix
        if suffix == ".py":
            invocations = _python_docker_runs(source, where)
        elif suffix == ".php":
            invocations = _php_docker_runs(source, where)
        else:
            invocations = _shell_words(source, where)
        for line_no, words in invocations:
            argv = _docker_argv(words)
            if argv is not None and not _docker_has_init_before_image(argv):
                offences.append(f"{where}:{line_no}: rule=docker-init: docker run must include exact token --init")
    return offences


def test_tracked_docker_run_invocations_pass_init() -> None:
    sources = _tracked_text_sources()
    assert sources, "no tracked text files found under scripts/ or tests/smoke/"
    offences = _docker_run_offences(sources)
    assert not offences, "docker invocation hygiene failed:\n  " + "\n  ".join(offences)


def test_docker_scanner_handles_commands_continuations_comments_and_metacharacters() -> None:
    sources = {
        "scripts/case.sh": """\
# docker run --rm -- misleading comment
echo "docker run --rm"
exec /usr/bin/docker   run --label 'odd=a&b' '--init'
"docker" \\
  "run" --rm # --init in a comment is not an option
docker run --rm; echo --init
docker run --rm | cat --init
printf '%s\\n' docker run --rm
cat <<'TEXT'
docker run --rm
TEXT
command docker run --rm --init && echo done
""",
        "tests/smoke/case.py": """\
import subprocess
TEXT = "docker run --rm"
# subprocess.run(["docker", "run", "--rm"])
subprocess.run(["docker", "run", "--rm", "--init"], check=True)
subprocess.run(["/usr/bin/docker", "run", "--rm"], check=True)
""",
        "scripts/case.php": """\
<?php
$text = 'docker run --rm';
// system('docker run --rm');
exec('/usr/bin/docker run --rm --init');
system('docker run --rm');
""",
        "scripts/case.txt": "env MODE=test docker run --rm --init || echo failed\n",
    }
    assert _docker_run_offences(sources) == [
        "scripts/case.sh:4: rule=docker-init: docker run must include exact token --init",
        "scripts/case.sh:6: rule=docker-init: docker run must include exact token --init",
        "scripts/case.sh:7: rule=docker-init: docker run must include exact token --init",
        "tests/smoke/case.py:5: rule=docker-init: docker run must include exact token --init",
        "scripts/case.php:5: rule=docker-init: docker run must include exact token --init",
    ]


def test_docker_scanner_rejects_wrappers_dynamic_argv_and_late_init() -> None:
    sources = {
        "scripts/wrappers.sh": """\
sudo docker run alpine
sudo -u root docker run alpine
docker run alpine --init
DOCKER=docker
"$DOCKER" run --rm alpine
env -u HOME docker run alpine
""",
        "tests/smoke/imported.py": """\
import subprocess as sp
from subprocess import run

opts = ["--rm", "alpine"]
command = ["docker", "run", "alpine"]
run(["docker", "run", "alpine"])
run(["docker", "run", *opts])
run(command)
sp.run(command)
""",
    }
    assert _docker_run_offences(sources) == [
        "scripts/wrappers.sh:1: rule=docker-init: docker run must include exact token --init",
        "scripts/wrappers.sh:2: rule=docker-init: docker run must include exact token --init",
        "scripts/wrappers.sh:3: rule=docker-init: docker run must include exact token --init",
        "scripts/wrappers.sh:5: rule=docker-init: docker run must include exact token --init",
        "scripts/wrappers.sh:6: rule=docker-init: docker run must include exact token --init",
        "tests/smoke/imported.py:6: rule=docker-init: docker run must include exact token --init",
        "tests/smoke/imported.py:7: rule=docker-init: docker run must include exact token --init",
        "tests/smoke/imported.py:8: rule=docker-init: docker run must include exact token --init",
        "tests/smoke/imported.py:9: rule=docker-init: docker run must include exact token --init",
    ]


# --------------------------------------------------------------------------- #
# 7. Prepared SHA pins are the exact values consumed downstream.
# --------------------------------------------------------------------------- #


class _ShaPin(NamedTuple):
    workflow: str
    job: str
    output: str


_PIN_JOB = re.compile(r"(?:^|-)(?:prepare|read|resolve)(?:-|$)")
_PIN_OUTPUT = re.compile(r"(?:^|_)sha$")
_PIN_BRIDGE = re.compile(r"^\$\{\{\s*steps\.(?P<step>[A-Za-z0-9_-]+)\.outputs\.(?P<output>[A-Za-z0-9_-]+)\s*\}\}$")
_NEEDS_OUTPUT = re.compile(
    r"(?<![A-Za-z0-9_-])needs\.(?P<job>[A-Za-z0-9_-]+)\.outputs\."
    r"(?P<output>[A-Za-z0-9_-]+)(?![A-Za-z0-9_-])"
)


def _walk_scalars(node: object, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], str]]:
    scalars: list[tuple[tuple[str, ...], str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str):
                scalars.extend(_walk_scalars(value, (*path, key)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            scalars.extend(_walk_scalars(value, (*path, str(index))))
    elif isinstance(node, str):
        scalars.append((path, node))
    return scalars


def _job_descendants(document: Mapping[object, object], producer: str) -> set[str]:
    jobs = document.get("jobs")
    assert isinstance(jobs, dict)
    descendants: set[str] = set()
    while True:
        discovered = {
            name
            for name, job in jobs.items()
            if isinstance(name, str)
            and isinstance(job, dict)
            and name not in descendants
            and any(need == producer or need in descendants for need in _needs(job))
        }
        if not discovered:
            return descendants
        descendants.update(discovered)


def _sha_inventory(
    documents: Mapping[str, Mapping[object, object]],
) -> tuple[list[_ShaPin], list[str]]:
    pins: list[_ShaPin] = []
    offences: list[str] = []
    for workflow, document in documents.items():
        jobs = document.get("jobs")
        assert isinstance(jobs, dict), f"{workflow}: rule=pin-consumer: jobs must be a mapping"
        for job_name, job in jobs.items():
            if not isinstance(job_name, str) or not isinstance(job, dict) or _PIN_JOB.search(job_name) is None:
                continue
            outputs = job.get("outputs", {})
            if not isinstance(outputs, dict):
                continue
            steps = job.get("steps", [])
            step_ids = (
                {step["id"] for step in steps if isinstance(step, dict) and isinstance(step.get("id"), str)}
                if isinstance(steps, list)
                else set()
            )
            for output, value in outputs.items():
                if not isinstance(output, str) or _PIN_OUTPUT.search(output) is None:
                    continue
                match = _PIN_BRIDGE.fullmatch(value) if isinstance(value, str) else None
                if match is None or match.group("output") != output or match.group("step") not in step_ids:
                    offences.append(
                        f"{workflow}:{job_name}.{output}: rule=pin-consumer: output must bridge "
                        f"steps.<real-id>.outputs.{output}"
                    )
                    continue
                pins.append(_ShaPin(workflow, job_name, output))
    return pins, offences


def _shell_commands(source: str) -> list[list[str]]:
    commands: list[list[str]] = []
    for _, logical in _logical_shell_lines(source):
        lexer = shlex.shlex(logical, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        try:
            words = list(lexer)
        except ValueError:
            continue
        segment: list[str] = []
        for word in [*words, ";"]:
            if word in _SHELL_OPERATORS:
                if segment:
                    commands.append(segment)
                    segment = []
            else:
                segment.append(word)
    return commands


def _pin_base(output: str) -> str:
    return output.removesuffix("_sha").replace("_", "-")


def _pin_expression_members(value: str) -> frozenset[tuple[str, str]]:
    expression = _GH_EXPRESSION.fullmatch(value.strip())
    if expression is None:
        return frozenset()
    members: set[tuple[str, str]] = set()
    for alternative in _expression_parts(expression.group(1), "||"):
        member = _NEEDS_OUTPUT.fullmatch(alternative)
        if member is None:
            return frozenset()
        members.add((member.group("job"), member.group("output")))
    return frozenset(members)


_GIT_IDENTITY_COMMANDS = {"show", "checkout", "switch", "reset"}
_GIT_GLOBAL_VALUE_OPTIONS = {
    "-C",
    "-c",
    "--config-env",
    "--exec-path",
    "--git-dir",
    "--namespace",
    "--super-prefix",
    "--work-tree",
}


def _git_identity_command(words: list[str]) -> tuple[str, list[str]] | None:
    if not words or words[0] != "git":
        return None
    index = 1
    while index < len(words) and words[index].startswith("-"):
        option = words[index]
        index += 1
        if option in _GIT_GLOBAL_VALUE_OPTIONS and "=" not in option and index < len(words):
            index += 1
    if index >= len(words) or words[index] not in _GIT_IDENTITY_COMMANDS:
        return None
    return words[index], words[index + 1 :]


def _ref_binding(path: tuple[str, ...]) -> bool:
    if not path or "env" in path or "outputs" in path:
        return False
    return path[-1].lower() in {
        "ref",
        "checkout_ref",
        "source_ref",
        "source_sha",
        "ports_ref",
        "smoke_nightly_expected_source_sha",
        "smoke_repo_expected_source_sha",
    }


_SHELL_VARIABLE = re.compile(r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)(?:[^}]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))")
_SHELL_EXACT_VARIABLE = re.compile(r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))")


def _shell_assignments(words: list[str]) -> list[tuple[str, str]]:
    declarations = bool(words) and words[0] in {"export", "readonly"}
    assignments: list[tuple[str, str]] = []
    index = 1 if declarations else 0
    while index < len(words):
        assignment = re.fullmatch(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)", words[index])
        if assignment is None:
            if not declarations:
                break
            index += 1
            continue
        value = assignment.group("value")
        depth = value.count("$(") - value.count(")")
        while depth > 0 and index + 1 < len(words):
            index += 1
            value += f" {words[index]}"
            depth += words[index].count("$(") - words[index].count(")")
        assignments.append((assignment.group("name"), value))
        index += 1
    return assignments


def _shell_alias_provenance(value: str, aliases: Mapping[str, str]) -> str | None:
    if re.search(r"\$\(\s*git\s+ls-remote\b", value):
        return "live"
    variables = [match.group("braced") or match.group("plain") for match in _SHELL_VARIABLE.finditer(value)]
    inherited = [aliases[name] for name in variables if name in aliases]
    if not inherited:
        return None
    if "live" in inherited:
        return "live"
    exact = _SHELL_EXACT_VARIABLE.fullmatch(value)
    if exact is not None and aliases[exact.group("braced") or exact.group("plain")] == "exact":
        return "exact"
    return "derived"


def _pin_flag_arguments(words: list[str], base: str) -> list[tuple[str, str]]:
    arguments: list[tuple[str, str]] = []
    for index, word in enumerate(words):
        match = re.fullmatch(
            r"(?P<flag>--[A-Za-z0-9][A-Za-z0-9_-]*-(?:ref|sha))(?:=(?P<argument>.*))?",
            word,
        )
        if match is None:
            continue
        flag = match.group("flag")
        if base and not flag.removeprefix("--").startswith(base):
            continue
        argument = match.group("argument")
        if argument is None:
            if index + 1 >= len(words):
                continue
            argument = words[index + 1]
        arguments.append((flag, argument))
    return arguments


def _pin_offences(sources: dict[str, str]) -> list[str]:
    documents = {workflow: _workflow_document(source, workflow) for workflow, source in sources.items()}
    pins, offences = _sha_inventory(documents)
    for pin in pins:
        document = documents[pin.workflow]
        jobs = document["jobs"]
        assert isinstance(jobs, dict)
        descendants = _job_descendants(document, pin.job)
        reference = f"needs.{pin.job}.outputs.{pin.output}"
        consumers: list[tuple[str, tuple[str, ...], str]] = []
        for job_name in sorted(descendants):
            job = jobs[job_name]
            if not isinstance(job, dict):
                continue
            for path, value in _walk_scalars(job):
                members = {(match.group("job"), match.group("output")) for match in _NEEDS_OUTPUT.finditer(value)}
                if (pin.job, pin.output) in members:
                    consumers.append((job_name, path, value))
        if not consumers:
            offences.append(
                f"{pin.workflow}:{pin.job}.{pin.output}: rule=pin-consumer: "
                "no dependent consumer references the exact output"
            )
            continue

        workflow_pins = {(candidate.job, candidate.output) for candidate in pins if candidate.workflow == pin.workflow}
        identity = False
        invalid_alias_sinks: set[tuple[str, str, str]] = set()
        derived_alias_sinks: set[tuple[str, str, str]] = set()
        invalid_ref_jobs: set[str] = set()
        for job_name, path, value in consumers:
            if not _ref_binding(path):
                continue
            expression_members = _pin_expression_members(value)
            if (pin.job, pin.output) in expression_members and expression_members <= workflow_pins:
                identity = True
            else:
                invalid_ref_jobs.add(job_name)
        if identity:
            for job_name in invalid_ref_jobs:
                offences.append(
                    f"{pin.workflow}:{job_name}: rule=pin-consumer: derived or untrusted ref sink "
                    f"references {pin.job}.{pin.output}"
                )
        exact_member = frozenset({(pin.job, pin.output)})
        for job_name in sorted(descendants):
            job = jobs[job_name]
            if not isinstance(job, dict):
                continue
            job_env = job.get("env", {})
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                effective_env: dict[object, object] = {}
                if isinstance(job_env, dict):
                    effective_env.update(job_env)
                env = step.get("env", {})
                if isinstance(env, dict):
                    effective_env.update(env)
                pin_aliases = {
                    name
                    for name, value in effective_env.items()
                    if isinstance(name, str)
                    and isinstance(value, str)
                    and any(
                        (member.group("job"), member.group("output")) == (pin.job, pin.output)
                        for member in _NEEDS_OUTPUT.finditer(value)
                    )
                }
                step_aliases = {
                    name
                    for name in pin_aliases
                    if _pin_expression_members(cast(str, effective_env[name])) == exact_member
                }
                prepared_aliases = {
                    name
                    for name, value in effective_env.items()
                    if isinstance(name, str)
                    and isinstance(value, str)
                    and bool(_pin_expression_members(value))
                    and _pin_expression_members(value) <= workflow_pins
                }
                invalid_aliases = pin_aliases - step_aliases
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                aliases = {name: "prepared" for name in prepared_aliases}
                aliases.update({name: "exact" for name in step_aliases})
                aliases.update({name: "derived" for name in invalid_aliases})
                normalized_run = re.sub(
                    r"\$\((.*?)\)",
                    lambda match: "$(" + " ".join(match.group(1).split()) + ")",
                    run,
                    flags=re.DOTALL,
                )
                commands = _shell_commands(normalized_run)
                base = _pin_base(pin.output)
                for words in commands:
                    for name, value in _shell_assignments(words):
                        provenance = _shell_alias_provenance(value, aliases)
                        if provenance is not None or name in aliases:
                            aliases[name] = provenance or "overwritten"

                    flag_arguments: list[tuple[str, str, str | None, str | None, frozenset[tuple[str, str]]]] = []
                    for flag, argument in _pin_flag_arguments(words, base):
                        argument_match = _SHELL_EXACT_VARIABLE.fullmatch(argument)
                        argument_var = (
                            argument_match.group("braced") or argument_match.group("plain")
                            if argument_match is not None
                            else None
                        )
                        flag_arguments.append(
                            (
                                flag,
                                argument,
                                argument_var,
                                aliases.get(argument_var or ""),
                                _pin_expression_members(argument),
                            )
                        )
                    has_exact_sha_argument = any(
                        flag.endswith("-sha")
                        and (reference == argument or argument_members == exact_member or provenance == "exact")
                        for flag, argument, _, provenance, argument_members in flag_arguments
                    )
                    for flag, argument, argument_var, provenance, argument_members in flag_arguments:
                        if provenance == "derived":
                            sinks = invalid_alias_sinks if argument_var in invalid_aliases else derived_alias_sinks
                            sinks.add((job_name, cast(str, argument_var), flag))
                        elif provenance == "live":
                            offences.append(
                                f"{pin.workflow}:{job_name}: rule=pin-consumer: live git ls-remote "
                                f"replaces {pin.job}.{pin.output} at identity sink {flag}"
                            )
                        elif reference == argument or argument_members == exact_member or provenance == "exact":
                            identity = True
                        elif provenance == "prepared" or bool(argument_members) and argument_members <= workflow_pins:
                            continue
                        elif provenance == "overwritten":
                            offences.append(
                                f"{pin.workflow}:{job_name}: rule=pin-consumer: alias overwrites "
                                f"{pin.job}.{pin.output} at identity sink {flag}"
                            )
                        elif not (flag.endswith("-ref") and has_exact_sha_argument):
                            offences.append(
                                f"{pin.workflow}:{job_name}: rule=pin-consumer: identity flag {flag} uses "
                                f"a derived, untrusted, or unknown value instead of {pin.job}.{pin.output}"
                            )

                    identity_command = _git_identity_command(words)
                    if identity_command is None:
                        continue
                    command, arguments = identity_command
                    used_git = {
                        name
                        for argument in arguments
                        for name in aliases
                        if argument == f"${name}"
                        or argument == f"${{{name}}}"
                        or argument.startswith(f"${name}:")
                        or argument.startswith(f"${{{name}}}:")
                    }
                    exact_git = {name for name in used_git if aliases[name] == "exact"}
                    live_git = {name for name in used_git if aliases[name] == "live"}
                    derived_git = {name for name in used_git if aliases[name] == "derived"}
                    overwritten_git = {name for name in used_git if aliases[name] == "overwritten"}
                    for name in derived_git:
                        sinks = invalid_alias_sinks if name in invalid_aliases else derived_alias_sinks
                        sinks.add((job_name, name, f"git {command}"))
                    direct_live = any(re.search(r"\$\(\s*git\s+ls-remote\b", argument) for argument in arguments)
                    if (live_git or direct_live) and step_aliases:
                        offences.append(
                            f"{pin.workflow}:{job_name}: rule=pin-consumer: live git ls-remote "
                            f"replaces {pin.job}.{pin.output} at identity sink git {command}"
                        )
                    elif overwritten_git:
                        offences.append(
                            f"{pin.workflow}:{job_name}: rule=pin-consumer: alias overwrites "
                            f"{pin.job}.{pin.output} at identity sink git {command}"
                        )
                    elif exact_git:
                        identity = True
        if identity:
            offences.extend(
                f"{pin.workflow}:{job_name}: rule=pin-consumer: derived or untrusted env alias "
                f"{name} references {pin.job}.{pin.output} at identity sink {sink}"
                for job_name, name, sink in invalid_alias_sinks
            )
            offences.extend(
                f"{pin.workflow}:{job_name}: rule=pin-consumer: derived shell alias {name} references "
                f"{pin.job}.{pin.output} at identity sink {sink}"
                for job_name, name, sink in derived_alias_sinks
            )
        else:
            offences.append(
                f"{pin.workflow}:{pin.job}.{pin.output}: rule=pin-consumer: pin is not consumed by a ref/identity sink"
            )
    return sorted(set(offences))


def test_prepare_read_resolve_sha_pins_feed_exact_downstream_consumers() -> None:
    offences = _pin_offences(_workflow_sources())
    assert not offences, "SHA pin hygiene failed:\n  " + "\n  ".join(offences)


def test_pin_scanner_supports_fallbacks_aliases_exact_reads_and_both_extensions() -> None:
    sources = {
        "first.yml": """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
        run: echo "ports_sha=$VALUE" >> "$GITHUB_OUTPUT"
  build:
    needs: prepare
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          git fetch origin main
          git show "$PORTS_SHA:Makefile"
          build-leg.sh --ports-ref "$PORTS_SHA"
""",
        "second.yaml": """\
"on": workflow_dispatch
jobs:
  resolve:
    outputs:
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
        run: echo "source_sha=$VALUE" >> "$GITHUB_OUTPUT"
  prepare-release:
    outputs:
      sha: ${{ steps.pin.outputs.sha }}
    steps:
      - id: pin
        run: echo "sha=$VALUE" >> "$GITHUB_OUTPUT"
  consume:
    needs: [resolve, prepare-release]
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${{ needs.prepare-release.outputs.sha || needs.resolve.outputs.source_sha }}
""",
    }
    assert _pin_offences(sources) == []


def test_pin_scanner_reports_wrong_bridges_boundaries_moving_refs_and_live_reresolution() -> None:
    sources = {
        "wrong.yaml": """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.wrong_sha }}
    steps:
      - id: pin
  read-matrix:
    outputs:
      matrix_sha: ${{ steps.matrix.outputs.matrix_sha }}
    steps:
      - id: matrix
  build:
    needs: [prepare, read-matrix]
    env:
      WRONG: ${{ needs.read-matrix.outputs.matrix_sha_extra }}
    steps:
      - run: echo "$WRONG"
""",
        "moving-ref.yml": """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
          PORTS_REF: pfblockerng/use-github
        run: |
          test "$ACTUAL_PORTS_SHA" = "$PORTS_SHA"
          build-leg.sh --ports-ref "$PORTS_REF"
""",
        "live.yml": """\
on: workflow_dispatch
jobs:
  resolve:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
    steps:
      - id: pin
  consume:
    needs: resolve
    steps:
      - env:
          PORTS_SHA: ${{ needs.resolve.outputs.ports_sha }}
        run: |
          PORTS_SHA="$(git ls-remote origin main)"
          build-leg.sh --ports-ref "$PORTS_SHA"
""",
        "unrelated.yaml": """\
on: workflow_dispatch
env:
  WORKFLOW_SHA: ${{ github.workflow_sha }}
  HEAD_SHA: mutable
  DIGEST: sha256:abcdef
jobs:
  build:
    steps:
      - run: |
          git fetch origin main
          git tag --contains HEAD
          printf '%s\\n' metadata-only-ref
""",
    }
    offences = _pin_offences(sources)
    assert any(
        item
        == ("wrong.yaml:prepare.ports_sha: rule=pin-consumer: output must bridge steps.<real-id>.outputs.ports_sha")
        for item in offences
    )
    assert any(
        item
        == ("wrong.yaml:read-matrix.matrix_sha: rule=pin-consumer: no dependent consumer references the exact output")
        for item in offences
    )
    assert any(
        item == ("moving-ref.yml:prepare.ports_sha: rule=pin-consumer: pin is not consumed by a ref/identity sink")
        for item in offences
    )
    assert any(
        "live git ls-remote replaces resolve.ports_sha at identity sink --ports-ref" in item for item in offences
    )
    assert not any("unrelated.yaml" in item for item in offences)


def test_pin_scanner_rejects_decorated_refs_alias_overwrites_and_indirect_live_refs() -> None:
    sources = {
        "hostile.yml": """\
on: workflow_dispatch
jobs:
  prepare:
    outputs:
      ports_sha: ${{ steps.pin.outputs.ports_sha }}
      source_sha: ${{ steps.pin.outputs.source_sha }}
    steps:
      - id: pin
  build:
    needs: prepare
    with:
      ref: refs/heads/${{ needs.prepare.outputs.source_sha }}-attacker
      arbitrary_sha: ${{ needs.prepare.outputs.source_sha }}
    steps:
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          git show \"$PORTS_SHA:Makefile\"
          FRESH=\"$(git ls-remote origin main)\"
          build-leg.sh --ports-ref \"$FRESH\"
      - env:
          PORTS_SHA: ${{ needs.prepare.outputs.ports_sha }}
        run: |
          PORTS_SHA=main
          build-leg.sh --ports-ref \"$PORTS_SHA\"
""",
    }
    offences = _pin_offences(sources)
    assert any("prepare.source_sha: rule=pin-consumer: pin is not consumed" in item for item in offences)
    assert any("live git ls-remote replaces prepare.ports_sha" in item for item in offences)
    assert any("overwrites prepare.ports_sha" in item for item in offences)
