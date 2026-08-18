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
"""

from __future__ import annotations

import re
from pathlib import Path

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
