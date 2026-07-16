---
name: spec-lint
description: >
  Lint ADR phase prompts for the delegation-contract blocks (VERIFICATION,
  HANDOFF naming its RESULTS file, declared test mode, reality-override line,
  blast-radius line from ADR-62 on) via scripts/check_phase_prompts.py — the
  mechanical floor beneath /adr-create.
  Args: [ADR number or prompt file paths] (default: every tracked post-contract
  prompt). Use when the user says "lint the ADR prompts", "spec-lint ADR N",
  "check the phase prompts", or invokes /spec-lint. /adr-create runs this
  before reporting a new ADR done.
---

Run the phase-prompt checker and report. The checker enforces **presence** of the
CLAUDE.md delegation-contract blocks; judging their **depth** stays your job.

Args: `{{ args }}`

## Step 1 — Resolve targets and run

- No args → `python3 scripts/check_phase_prompts.py` (scans every tracked prompt; ADRs
  below the grandfather cutoff in the script are skipped by design).
- An ADR number `N` → pass that ADR's prompt files:
  `python3 scripts/check_phase_prompts.py .ADRs/ADR_{NN}_*/[0-9]*.txt`.
- Explicit paths → pass them through verbatim.

## Step 2 — Report

- Clean → say so, one line, and note anything the checker cannot see that you noticed
  anyway (a vague ACTION PLAN, a missing coverage matrix where the ADR says "all X", a
  new transformer — parser/regex/scrub/formatter — whose prompt carries no hostile-input
  rows — the checker's known blind spots; the transformer check is judgment, not
  mechanical: those words pepper ordinary ADR prose, so a word-trigger lint would be
  mostly false positives).
- Violations → list them file-by-file with the missing block, and fix the prompts (prompt
  text is the ADR-text dev-only class — direct-to-`devel` landing per CLAUDE.md
  "Worktrees") or hand the list back to the author, per what the user asked.

Do not weaken the checker to make a prompt pass (CLAUDE.md never-weaken rule); a prompt that
genuinely cannot satisfy a block states why in the prompt itself and the ADR documents the
exemption.
