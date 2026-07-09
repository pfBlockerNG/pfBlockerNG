#!/usr/bin/env python3
"""Lint ADR phase prompts for the delegation-contract blocks.

PROBLEM
-------
An `/adr-phase` implementer executes a phase prompt verbatim, so a weak prompt
ships weak work: the 2026-07 audit (issues #900-#909) traced several shipped
defects to specs missing an executable verification plan, a declared test mode,
or the instruction to distrust the prompt's own stale claims. CLAUDE.md's
delegation contract now mandates those blocks; this check is the mechanical
floor that keeps a new ADR's prompts from silently omitting them (the depth of
each block stays the orchestrator gate's job — this only proves presence).

CHECKS (per post-contract phase prompt)
---------------------------------------
* ``verification-section`` — a line starting with ``VERIFICATION`` exists.
* ``handoff-results``      — a line starting with ``HANDOFF`` exists and the
  prompt names its ``RESULTS/`` handoff file.
* ``mode-declared``        — the prompt declares its test mode: a red-first
  token (``red-run`` / ``red->green`` / ``red→green``) or a behaviour-preserving
  one (``behaviour-preserving`` / ``oracle``), case-insensitive.
* ``reality-override``     — the standing line telling the implementer the live
  tree and prior RESULTS "override this prompt" on any conflict is present.
* ``blast-radius``         — (ADR >= :data:`_BLAST_RADIUS_MIN_ADR` only) a
  blast-radius line exists: what production behaviour can change when this
  phase lands alone ("NONE" / "PRODUCTION-DORMANT until Phase N" count).

SCOPE
-----
* Phase prompts only: tracked ``.ADRs/ADR_{NN}_*/{MM}_*.txt``. ``RESULTS/``
  handoffs and non-numeric ``.txt`` notes are not prompts and are skipped.
* **Grandfather cutoff:** ADRs numbered below :data:`_CONTRACT_MIN_ADR` predate
  the delegation contract and are never flagged (retrofitting finished ADRs
  would be noise, not safety) — EXCEPT the :data:`_RETROFITTED_ADRS` set: those
  are still unimplemented, their prompts drive future implementer runs, and they
  were brought up to the contract, so they are gated. The cutoff applies in
  file-argument mode too, so a typo fix in a legacy prompt is never blocked.

Exit status: 0 = clean, 1 = one or more violations (printed with file + check).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# First ADR authored under the delegation contract (CLAUDE.md, landed 2026-07).
# Everything older is grandfathered — except the retrofitted set below.
_CONTRACT_MIN_ADR = 60

# Pre-contract ADRs whose prompts still drive FUTURE implementer runs (every ADR
# still Proposed/unimplemented at retrofit time — existing prompts brought up to
# the contract in 2821b9df/9b21b75e; 51/56/57 have no prompts yet, but any they
# gain are gated). An ADR implemented before the contract stays grandfathered;
# an ADR added here must comply. Keep in sync with the Proposed set (positive
# Status grep — a negative grep ate ADR-52's "Not yet implemented" once).
_RETROFITTED_ADRS = frozenset({25, 32, 33, 34, 51, 52, 54, 55, 56, 57})

# First ADR whose prompts must carry a blast-radius line. ADR-62's phases were
# re-split pre-implementation because one phase silently bundled five concerns;
# a stated blast radius is what makes an overloaded phase visible to the gate.
# Implemented ADRs below this stay grandfathered (their prompts never run again).
_BLAST_RADIUS_MIN_ADR = 62

_BLAST_RE = re.compile(r"blast[- ]radius", re.IGNORECASE)

# .ADRs/ADR_{NN}_{Name}/{MM}_{Name}.txt — capture the ADR number for the cutoff.
_PROMPT_RE = re.compile(r"(?:^|/)\.ADRs/ADR_(\d+)_[^/]+/\d+_[^/]+\.txt$")

# Mode tokens (matched case-insensitively, word-bounded so e.g. "coracle" never
# satisfies "oracle"). One must appear.
_MODE_RE = re.compile(r"(?<!\w)(red-run|red->green|red→green|behaviour-preserving|oracle)(?!\w)")


def _prompt_adr_number(path: Path) -> int | None:
    """The ADR number when ``path`` is a phase prompt, else ``None``."""
    m = _PROMPT_RE.search(path.as_posix())
    if m is None or "/RESULTS/" in path.as_posix():
        return None
    return int(m.group(1))


# Resolve the repo root from this file's location so the tracked scan is
# cwd-independent — `git ls-files .ADRs` from a subdirectory silently matches
# nothing and would defeat the CI gate (PR #927 review finding).
_REPO_ROOT = Path(__file__).resolve().parent.parent


def tracked_phase_prompts() -> list[Path]:
    """Every git-tracked phase prompt under ``.ADRs/`` (all ADR numbers)."""
    out = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "ls-files", "-z", ".ADRs"],
        capture_output=True,
        text=True,
        check=True,
    )
    paths = [_REPO_ROOT / p for p in out.stdout.split("\0") if p]
    return [p for p in paths if _prompt_adr_number(p) is not None]


def _handoff_names_results(text: str) -> bool:
    """True iff a HANDOFF block names a ``RESULTS/`` file within its own span
    (the ``HANDOFF`` line and its continuation, up to the next all-caps section
    header). A ``RESULTS/`` mention elsewhere — e.g. REQUIRED READING citing the
    PRIOR phase's handoff — must not satisfy the check."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith("HANDOFF"):
            continue
        if "RESULTS/" in line:
            return True
        for nxt in lines[i + 1 :]:
            if "RESULTS/" in nxt:
                return True
            if re.match(r"^[A-Z][A-Z0-9 -]{3,}", nxt):
                break
    return False


def _check_prompt(text: str, adr: int) -> list[tuple[str, str]]:
    """Return ``(check_id, message)`` for each contract block missing in ``text``."""
    lower = text.lower()
    missing: list[tuple[str, str]] = []
    if not re.search(r"^VERIFICATION", text, flags=re.MULTILINE):
        missing.append(("verification-section", "no VERIFICATION section"))
    if not _handoff_names_results(text):
        missing.append(("handoff-results", "no HANDOFF block naming its RESULTS/ file"))
    if not _MODE_RE.search(lower):
        missing.append(("mode-declared", "no test mode declared (red-run/red->green vs behaviour-preserving/oracle)"))
    if "override this prompt" not in lower:
        missing.append(("reality-override", 'no "prior RESULTS + live tree override this prompt" line'))
    if adr >= _BLAST_RADIUS_MIN_ADR and not _BLAST_RE.search(text):
        missing.append(("blast-radius", "no blast-radius line (what may change when this phase lands alone)"))
    return missing


def find_violations(paths: list[Path]) -> list[tuple[Path, str, str]]:
    """``(path, check_id, message)`` for every contract block missing from a
    post-contract phase prompt in ``paths``. Non-prompt and grandfathered files
    are skipped."""
    violations: list[tuple[Path, str, str]] = []
    for path in paths:
        adr = _prompt_adr_number(path)
        if adr is None or (adr < _CONTRACT_MIN_ADR and adr not in _RETROFITTED_ADRS):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            violations.append((path, "unreadable", f"cannot read prompt: {exc}"))
            continue
        violations.extend((path, check, msg) for check, msg in _check_prompt(text, adr))
    return violations


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] if argv else tracked_phase_prompts()
    violations = find_violations(paths)
    if not violations:
        return 0
    print("Phase prompt missing delegation-contract blocks:\n", file=sys.stderr)
    for path, check, msg in violations:
        try:
            shown = path.relative_to(_REPO_ROOT)
        except ValueError:
            shown = path
        print(f"  {shown}: {check}: {msg}", file=sys.stderr)
    print(
        "\nEvery post-contract phase prompt (ADR >= "
        f"{_CONTRACT_MIN_ADR}) must carry the CLAUDE.md delegation-contract blocks: "
        "a VERIFICATION section, a HANDOFF block naming its RESULTS/ file, a declared "
        "test mode (red-run vs behaviour-preserving/oracle), and the reality-override "
        f"line; from ADR >= {_BLAST_RADIUS_MIN_ADR} also a blast-radius line. "
        'Template: /adr-create Step 4; law: CLAUDE.md "The delegation contract".',
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
