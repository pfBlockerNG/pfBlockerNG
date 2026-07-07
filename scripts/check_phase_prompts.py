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

SCOPE
-----
* Phase prompts only: tracked ``.ADRs/ADR_{NN}_*/{MM}_*.txt``. ``RESULTS/``
  handoffs and non-numeric ``.txt`` notes are not prompts and are skipped.
* **Grandfather cutoff:** ADRs numbered below :data:`_CONTRACT_MIN_ADR` predate
  the delegation contract and are never flagged (retrofitting 59 finished ADRs
  would be noise, not safety). The cutoff applies in file-argument mode too, so
  a typo fix in a legacy prompt is never blocked.

Exit status: 0 = clean, 1 = one or more violations (printed with file + check).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# First ADR authored under the delegation contract (CLAUDE.md, landed 2026-07).
# Everything older is grandfathered.
_CONTRACT_MIN_ADR = 60

# .ADRs/ADR_{NN}_{Name}/{MM}_{Name}.txt — capture the ADR number for the cutoff.
_PROMPT_RE = re.compile(r"(?:^|/)\.ADRs/ADR_(\d+)_[^/]+/\d+_[^/]+\.txt$")

# Mode tokens (lowercase; matched case-insensitively). One must appear.
_MODE_TOKENS = ("red-run", "red->green", "red→green", "behaviour-preserving", "oracle")


def _prompt_adr_number(path: Path) -> int | None:
    """The ADR number when ``path`` is a phase prompt, else ``None``."""
    m = _PROMPT_RE.search(path.as_posix())
    if m is None or "/RESULTS/" in path.as_posix():
        return None
    return int(m.group(1))


def tracked_phase_prompts() -> list[Path]:
    """Every git-tracked phase prompt under ``.ADRs/`` (all ADR numbers)."""
    out = subprocess.run(
        ["git", "ls-files", "-z", ".ADRs"],
        capture_output=True,
        text=True,
        check=True,
    )
    paths = [Path(p) for p in out.stdout.split("\0") if p]
    return [p for p in paths if _prompt_adr_number(p) is not None]


def _check_prompt(text: str) -> list[tuple[str, str]]:
    """Return ``(check_id, message)`` for each contract block missing in ``text``."""
    lower = text.lower()
    missing: list[tuple[str, str]] = []
    if not re.search(r"^VERIFICATION", text, flags=re.MULTILINE):
        missing.append(("verification-section", "no VERIFICATION section"))
    if not (re.search(r"^HANDOFF", text, flags=re.MULTILINE) and "RESULTS/" in text):
        missing.append(("handoff-results", "no HANDOFF block naming its RESULTS/ file"))
    if not any(token in lower for token in _MODE_TOKENS):
        missing.append(("mode-declared", "no test mode declared (red-run/red->green vs behaviour-preserving/oracle)"))
    if "override this prompt" not in lower:
        missing.append(("reality-override", 'no "prior RESULTS + live tree override this prompt" line'))
    return missing


def find_violations(paths: list[Path]) -> list[tuple[Path, str, str]]:
    """``(path, check_id, message)`` for every contract block missing from a
    post-contract phase prompt in ``paths``. Non-prompt and grandfathered files
    are skipped."""
    violations: list[tuple[Path, str, str]] = []
    for path in paths:
        adr = _prompt_adr_number(path)
        if adr is None or adr < _CONTRACT_MIN_ADR:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        violations.extend((path, check, msg) for check, msg in _check_prompt(text))
    return violations


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] if argv else tracked_phase_prompts()
    violations = find_violations(paths)
    if not violations:
        return 0
    print("Phase prompt missing delegation-contract blocks:\n", file=sys.stderr)
    for path, check, msg in violations:
        print(f"  {path}: {check}: {msg}", file=sys.stderr)
    print(
        "\nEvery post-contract phase prompt (ADR >= "
        f"{_CONTRACT_MIN_ADR}) must carry the CLAUDE.md delegation-contract blocks: "
        "a VERIFICATION section, a HANDOFF block naming its RESULTS/ file, a declared "
        "test mode (red-run vs behaviour-preserving/oracle), and the reality-override "
        'line. Template: /adr-create Step 4; law: CLAUDE.md "The delegation contract".',
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
