"""Guard: every actions/checkout site declares persist-credentials explicitly.

Issue #1691 (CWE-522): actions/checkout defaults to persisting GITHUB_TOKEN in
.git/config for the rest of the job. A job that runs no git-authenticated
operation afterwards (no push, no cross-repo git fetch requiring auth) should
disable that persistence; a job that DOES need it (a git push/tag) must say so
explicitly with a comment naming the operation -- the house convention set by
release.yml:78 (`persist-credentials: true   # need to push branch + tag via
GITHUB_TOKEN`). This guard enumerates every checkout site straight out of
.github/workflows/*.yml itself -- never a hardcoded line-number list, which
rots on the first edit -- and fails, naming the offending sites, the moment
one regresses to the implicit (persisting) default.

Text-parsed rather than PyYAML: the `test` job's "Install test dependencies"
step (test.yml) installs only pytest/pytest-cov/dnspython -- no PyYAML -- and
adding it would be a workflow change outside this guard's scope (issue #1691
touches credential persistence only). Parsing follows the house idiom in
tests/test_ci_tool_pins.py (plain text, no YAML parser), generalised to walk
every step block instead of anchoring on one named job.

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

# PENDING: files intentionally left non-compliant by issue #1691's fix. Both
# are owned by a parallel lane out of this change's reach (release.yml: the
# tag/publish pushes; ui-tests.yml: a UI-only lane). Anti-rot:
# test_pending_set_is_still_noncompliant re-asserts each file still has an
# undeclared site every run, so fixing them elsewhere trips this test and
# forces the entry's removal -- a pending list must never silently outlive
# its reason.
# Tracking issue: #1700
PENDING_FILES = frozenset({"release.yml", "ui-tests.yml"})

_STEP_ITEM_RE = re.compile(r"^(?P<indent>[ ]*)-\s")
_CHECKOUT_RE = re.compile(r"uses:\s*actions/checkout@")
_PERSIST_RE = re.compile(r"^[ ]*persist-credentials:\s*(?P<value>true|false)\b(?P<comment>.*)$")
_JOB_KEY_RE = re.compile(r"^ {2}[A-Za-z0-9_.-]+:\s*(#.*)?$")


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
        for block_line in block:
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
    actions/checkout@v6` can never make the two sides disagree; a REAL
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


def test_every_non_pending_site_declares_persist_credentials() -> None:
    sites = _all_sites()
    offenders = [s for s in sites if s.file not in PENDING_FILES and not s.persist_declared]
    assert not offenders, (
        "these actions/checkout sites rely on the implicit (persisting) default instead of "
        "declaring persist-credentials explicitly (issue #1691, CWE-522):\n" + _format(offenders)
    )


def test_every_needs_auth_site_has_a_justifying_comment() -> None:
    sites = _all_sites()
    offenders = [s for s in sites if s.file not in PENDING_FILES and s.persist_value == "true" and not s.comment]
    assert not offenders, (
        "these sites declare persist-credentials: true with no comment naming the git "
        "operation that needs it (house convention: release.yml:78's "
        "`persist-credentials: true   # need to push branch + tag via GITHUB_TOKEN`):\n" + _format(offenders)
    )


def test_pending_set_is_still_noncompliant() -> None:
    """Anti-rot: PENDING_FILES exists only because release.yml and ui-tests.yml are
    owned by a parallel lane outside this change's reach. If either is fixed later,
    this assertion goes red -- a pending list must never silently outlive its reason."""
    sites = _all_sites()
    for pending_file in PENDING_FILES:
        file_sites = [s for s in sites if s.file == pending_file]
        assert file_sites, f"PENDING file {pending_file} has zero checkout sites -- update PENDING_FILES"
        assert any(not s.persist_declared for s in file_sites), (
            f"PENDING file {pending_file} now declares persist-credentials at every "
            f"checkout site -- it is compliant. Remove it from PENDING_FILES "
            f"(tracking issue #1700)."
        )
