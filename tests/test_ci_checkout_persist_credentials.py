"""Guard: every actions/checkout site declares persist-credentials explicitly.

Issue #1691 (CWE-522): actions/checkout defaults to persisting GITHUB_TOKEN in
.git/config for the rest of the job. A job that runs no git-authenticated
operation afterwards (no push, no cross-repo git fetch requiring auth) should
disable that persistence; a job that DOES need it (a git push/tag) must say so
explicitly with a comment naming the operation -- the house convention set by
release.yml's prepare-release checkout (`persist-credentials: true   # need to
push branch + tag via GITHUB_TOKEN`). This guard enumerates every checkout site
straight out of .github/workflows/*.yml itself -- never a hardcoded
line-number list, which rots on the first edit -- and fails, naming the
offending sites, the moment one regresses to the implicit (persisting)
default.

Text-parsed because this security guard must preserve comments, which PyYAML
discards. Parsing follows the house idiom in tests/test_ci_tool_pins.py,
generalised to walk every step block instead of anchoring on one named job.

Both `.yml` and `.yaml` are scanned: GitHub Actions loads either extension
from .github/workflows/, so a guard that only globbed `*.yml` would be a
silent bypass the moment a workflow ships as `.yaml` -- exactly the kind of
gap a security check must not have.
"""

import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = ROOT / ".github" / "workflows"
_WORKFLOW_GLOBS = ("*.yml", "*.yaml")

_STEP_ITEM_RE = re.compile(r"^(?P<indent>[ ]*)-\s")
_STEP_MARKER_RE = re.compile(r"^[ ]*-[ ]+")  # the sequence marker only, never the key that follows
_CHECKOUT_RE = re.compile(r"uses:\s*actions/checkout@")
_EXPECTED_ACTION_VERSIONS = {"actions/checkout": "v7", "astral-sh/setup-uv": "v10.0.1"}
_ACTION_USES_RE = re.compile(
    r"""^(?:-\s+)?uses:\s*(?P<quote>["']?)(?P<action>actions/checkout|astral-sh/setup-uv)@"""
    r"""(?P<version>[^\s"']+)(?P=quote)(?:\s+#.*)?$"""
)
_PERSIST_RE = re.compile(r"^[ ]*persist-credentials:\s*(?P<value>true|false)\b(?P<comment>.*)$")
_JOB_KEY_RE = re.compile(r"^ {2}[A-Za-z0-9_.-]+:\s*(#.*)?$")
_WITH_KEY_RE = re.compile(r"^(?P<indent>[ ]*)with:\s*(#.*)?$")


def _is_comment_line(line: str) -> bool:
    return line.lstrip().startswith("#")


def _workflow_files() -> list[Path]:
    """Every workflow file under WORKFLOWS_DIR, `.yml` and `.yaml` alike.
    Keyed by filename (a directory cannot hold two entries of the same name)
    so a file can never be double-counted even if the glob patterns were to
    overlap."""
    by_name: dict[str, Path] = {}
    for pattern in _WORKFLOW_GLOBS:
        for path in WORKFLOWS_DIR.glob(pattern):
            by_name.setdefault(path.name, path)
    return [by_name[name] for name in sorted(by_name)]


@dataclass(frozen=True)
class CheckoutSite:
    file: str
    line: int  # 1-based line number of the `uses: actions/checkout@...` line
    job: str
    persist_declared: bool
    persist_value: str | None  # "true" / "false" / None (undeclared)
    comment: str


def _step_block_end(lines: list[str], start_idx: int, indent: int) -> int:
    """Index (exclusive) where the step block starting at `start_idx` (a list-item
    line at `indent`) ends: the next non-blank line at indent <= `indent`."""
    for j in range(start_idx + 1, len(lines)):
        stripped = lines[j].strip()
        if not stripped:
            continue
        line_indent = len(lines[j]) - len(lines[j].lstrip(" "))
        if line_indent <= indent:
            return j
    return len(lines)


def _with_inputs(block: list[str]) -> list[str]:
    """The direct children of the step's `with:` mapping -- the only lines
    actions/checkout ever reads as inputs. Scoping matters for a security
    guard: a scan of the whole step block also matches `persist-credentials:`
    inside ANOTHER key's block scalar (a `ref: |` whose content happens to
    read `persist-credentials: false`), which the action never sees, so the
    site would score compliant while the token stays persisted. A flow-style
    `with: {...}` yields nothing here and the site reads as undeclared --
    over-strict, which for this guard is the safe direction.

    The `with:` line itself is anchored at the step's own key indent for the
    same reason one level up: a whole `with:` mapping can be quoted inside
    another key's block scalar, and a block scalar's content is always
    indented deeper than the key owning it, so it can never sit at the step's
    key indent."""
    marker = _STEP_MARKER_RE.match(block[0])
    assert marker is not None  # block[0] is a step item by construction
    key_indent = len(marker.group())
    for i, line in enumerate(block):
        with_match = _WITH_KEY_RE.match(line)
        if not with_match or len(with_match.group("indent")) != key_indent:
            continue
        inputs: list[str] = []
        input_indent: int | None = None
        for candidate in block[i + 1 :]:
            if not candidate.strip():
                continue
            indent = len(candidate) - len(candidate.lstrip(" "))
            if indent <= key_indent:
                break
            if input_indent is None:
                input_indent = indent
            if indent == input_indent:
                inputs.append(candidate)
        return inputs
    return []


def _enclosing_job(lines: list[str], idx: int) -> str:
    for j in range(idx, -1, -1):
        if _JOB_KEY_RE.match(lines[j]):
            return lines[j].strip().rstrip(":")
    return "?"


def _find_checkout_sites(path: Path) -> list[CheckoutSite]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    sites: list[CheckoutSite] = []

    item_indices = [i for i, line in enumerate(lines) if _STEP_ITEM_RE.match(line)]
    for i in item_indices:
        match = _STEP_ITEM_RE.match(lines[i])
        assert match is not None
        indent = len(match.group("indent"))
        end = _step_block_end(lines, i, indent)
        block = lines[i:end]

        checkout_offset = None
        for offset, block_line in enumerate(block):
            if _CHECKOUT_RE.search(block_line) and not _is_comment_line(block_line):
                checkout_offset = offset
                break
        if checkout_offset is None:
            continue

        persist_declared = False
        persist_value: str | None = None
        comment = ""
        for block_line in _with_inputs(block):
            persist_match = _PERSIST_RE.match(block_line)
            if persist_match:
                persist_declared = True
                persist_value = persist_match.group("value")
                comment = persist_match.group("comment").strip().lstrip("#").strip()
                break

        sites.append(
            CheckoutSite(
                file=path.name,
                line=i + checkout_offset + 1,
                job=_enclosing_job(lines, i),
                persist_declared=persist_declared,
                persist_value=persist_value,
                comment=comment,
            )
        )
    return sites


def _all_sites() -> list[CheckoutSite]:
    sites: list[CheckoutSite] = []
    for path in _workflow_files():
        sites.extend(_find_checkout_sites(path))
    return sites


def _raw_checkout_line_count() -> int:
    """Dumb, independent count of real (non-comment) `uses: actions/checkout@`
    lines over the SAME file set _all_sites() scans. Deliberately does not
    reuse the step-block walker: it exists to catch that walker drifting from
    reality in EITHER direction (missing a site the regex plainly sees, or
    inventing one the regex doesn't). Comment lines are excluded here -- the
    same predicate _find_checkout_sites applies when picking a block's
    checkout line -- so a documentation example like `# uses:
    actions/checkout@v7` can never make the two sides disagree; a REAL
    duplicate `uses:` key inside one step is invalid YAML and out of scope."""
    count = 0
    for path in _workflow_files():
        for line in path.read_text(encoding="utf-8").splitlines():
            if _CHECKOUT_RE.search(line) and not _is_comment_line(line):
                count += 1
    return count


def _format(sites: list[CheckoutSite]) -> str:
    return "\n".join(f"  {s.file}:{s.line} job={s.job}" for s in sites)


def test_enumeration_is_non_vacuous() -> None:
    """Floor of 1, not a magic count: an empty/misconfigured workflow
    directory (e.g. a broken glob) must not silently pass as "nothing to
    check". The real completeness guarantee is the parity check below."""
    sites = _all_sites()
    assert len(sites) >= 1, (
        f"found zero actions/checkout sites under {WORKFLOWS_DIR} (globs: {_WORKFLOW_GLOBS}) -- "
        f"a broken enumeration must never silently pass by finding nothing."
    )


def _action_version_offenders() -> tuple[set[str], list[str]]:
    seen: set[str] = set()
    offenders: list[str] = []
    for path in _workflow_files():
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = _ACTION_USES_RE.fullmatch(line.strip())
            if match is None:
                continue
            action = match.group("action")
            seen.add(action)
            if match.group("version") != _EXPECTED_ACTION_VERSIONS[action]:
                offenders.append(f"{path.name}:{line_number}: {line.strip()}")
    return seen, offenders


def test_checkout_and_setup_uv_versions_are_current() -> None:
    seen, offenders = _action_version_offenders()
    assert seen == _EXPECTED_ACTION_VERSIONS.keys(), (
        f"expected action pins not found: {sorted(_EXPECTED_ACTION_VERSIONS.keys() - seen)}"
    )
    assert not offenders, "outdated GitHub Action pins:\n  " + "\n  ".join(offenders)


def test_walker_count_matches_raw_checkout_line_count() -> None:
    """Anti-magic-number companion to test_enumeration_is_non_vacuous: rather
    than a hardcoded site-count floor (which rots the moment a workflow is
    added or deleted -- the exact rot this guard's docstring warns against),
    assert the structural per-step walker agrees with a dumb regex count over
    the identical file set. Self-updating, survives workflow churn, and
    catches drift in BOTH directions."""
    sites = _all_sites()
    raw_count = _raw_checkout_line_count()
    assert len(sites) == raw_count, (
        f"structural walker found {len(sites)} checkout site(s) but the raw "
        f"(non-comment) line count found {raw_count} -- symmetric difference "
        f"{abs(len(sites) - raw_count)}. A mismatch means the walker either missed a "
        f"real `uses: actions/checkout@` line (undercount) or invented a site the raw "
        f"scan doesn't see, e.g. from a mis-parsed step block (overcount).\n"
        f"Walker-found sites:\n{_format(sites)}"
    )


def test_every_site_declares_persist_credentials() -> None:
    sites = _all_sites()
    offenders = [s for s in sites if not s.persist_declared]
    assert not offenders, (
        "these actions/checkout sites rely on the implicit (persisting) default instead of "
        "declaring persist-credentials explicitly (issue #1691, CWE-522):\n" + _format(offenders)
    )


def test_every_needs_auth_site_has_a_justifying_comment() -> None:
    sites = _all_sites()
    offenders = [s for s in sites if s.persist_value == "true" and not s.comment]
    assert not offenders, (
        "these sites declare persist-credentials: true with no comment naming the git "
        "operation that needs it (house convention: release.yml prepare-release's "
        "`persist-credentials: true   # need to push branch + tag via GITHUB_TOKEN`):\n" + _format(offenders)
    )


def test_only_a_direct_child_of_the_with_block_counts_as_a_declaration(tmp_path: Path) -> None:
    """A guard that scans the whole step block for the text
    `persist-credentials:` also matches it inside SOME OTHER key's block
    scalar, where Actions never reads it as an input -- the site would score
    compliant while the token stays persisted. Only a line at the `with:`
    mapping's own key indent is a real declaration. The compliant fixture
    rides along so the negative case cannot pass by the parser simply
    finding nothing."""
    smuggled = tmp_path / "smuggled.yml"
    smuggled.write_text(
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - name: Checkout\n"
        "        uses: actions/checkout@v7\n"
        "        with:\n"
        "          ref: |\n"
        "            persist-credentials: false\n",
        encoding="utf-8",
    )
    (site,) = _find_checkout_sites(smuggled)
    assert not site.persist_declared, (
        "`persist-credentials: false` sitting inside another key's block scalar is not an "
        "input to actions/checkout -- the action still persists GITHUB_TOKEN, so the guard "
        "must not read it as a declaration."
    )

    declared = tmp_path / "declared.yml"
    declared.write_text(
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - name: Checkout\n"
        "        uses: actions/checkout@v7\n"
        "        with:\n"
        "          ref: main\n"
        "          persist-credentials: false\n",
        encoding="utf-8",
    )
    (real_site,) = _find_checkout_sites(declared)
    assert real_site.persist_declared and real_site.persist_value == "false"


def test_a_decoy_with_block_inside_another_keys_scalar_is_not_the_input_mapping(tmp_path: Path) -> None:
    """The companion to the vector above, one level up: a whole `with:` mapping
    can be smuggled inside another key's block scalar. `env:` values legitimately
    hold block scalars, so this is runnable YAML, and here the step has no real
    `with:` at all -- actions/checkout takes every default, GITHUB_TOKEN included.
    Only a `with:` at the step's own key indent is the input mapping; a block
    scalar's content is always indented deeper than the key that owns it."""
    decoy = tmp_path / "decoy.yml"
    decoy.write_text(
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - name: Checkout\n"
        "        uses: actions/checkout@v7\n"
        "        env:\n"
        "          NOTES: |\n"
        "            with:\n"
        "              persist-credentials: false\n",
        encoding="utf-8",
    )
    (site,) = _find_checkout_sites(decoy)
    assert not site.persist_declared, (
        "a `with:` mapping quoted inside another key's block scalar is not the step's input "
        "mapping -- this step declares nothing and actions/checkout persists GITHUB_TOKEN."
    )

    # Same decoy, but the step's first key itself starts with a dash. The step
    # key indent has to be measured off the sequence marker alone; a dash-eating
    # scan mistakes the key's own dash for part of the marker, shifts the indent
    # by one, and the decoy lands exactly on it.
    dash_key = tmp_path / "dash-key.yml"
    dash_key.write_text(
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - -weird: x\n"
        "        uses: actions/checkout@v7\n"
        "        env: |\n"
        "         with:\n"
        "           persist-credentials: false\n",
        encoding="utf-8",
    )
    (dash_site,) = _find_checkout_sites(dash_key)
    assert not dash_site.persist_declared, (
        "the step key indent is measured off the sequence marker, never off a key name that "
        "happens to start with a dash."
    )
