---
name: adr-phase
description: >
  Implement a specific phase of an ADR (Architecture Decision Record).
  Args: <ADR-number> [phase-number]
  If phase is omitted, defaults to the first phase that has a prompt file
  but no corresponding result document. Use when the user says
  "implement phase N of ADR-M", "run adr phase", or invokes /adr-phase.
---

You are implementing a phase of an ADR in this repository.

## Step 1 — Parse args

Args string: `{{ args }}`

- First token = ADR number (required). Accept bare digits: "1", "01", "1".
- Second token = phase number (optional). Bare digits.

## Step 2 — Locate the ADR directory

ADR directories live under `.ADRs/` and follow the pattern `ADR_{NN}_{Name}/`
where `NN` is the zero-padded two-digit ADR number.

Run:
```
ls .ADRs/
```
Find the directory whose name starts with `ADR_` followed by the zero-padded
ADR number (e.g. `ADR_01_` for ADR 1). If none found, stop and tell the user.

## Step 3 — Determine the phase number

Phase prompt files inside the ADR directory follow the pattern `{NN}_*.txt`
(e.g. `01_Extract_A1_A3_and_B.txt`, `03_Oracle_Tests.txt`).

Result documents (handoffs) live in `RESULTS/` inside the ADR directory and
follow `{NN}_Results.txt` (plain text, e.g. `RESULTS/02_Results.txt`).

**If the user supplied a phase number**, use it directly.

**If no phase was supplied**, scan all `NN_*.txt` files in the ADR directory
sorted numerically by their `NN` prefix. The default phase is the **first** one
whose corresponding `RESULTS/NN_Results.txt` does NOT exist. If all phases have
results, stop and tell the user that all phases are done.

## Step 4 — Read the phase prompt

Read the file `{ADR_DIR}/{NN}_{Name}.txt` for the resolved phase. This file
contains the full instructions for the phase, including required reading,
action plan, constraints, verification steps, and commit message.

Also read any result documents referenced as prerequisites (the prompt's
"Prereq" or "REQUIRED READING" sections often name them). They are in
`{ADR_DIR}/RESULTS/`.

## Step 5 — Implement the phase inline on the feature branch

Do **not** spawn a worktree-isolated agent. ADR phases run **inline on the
feature branch**, one commit per phase, in this session — so each phase builds
on the previous phase's committed work in the same tree.

1. **Confirm the branch.** The phase prompt / `ADR.md` names the feature branch
   (e.g. `adr/03`). Run `git branch --show-current` and verify you are on it. If
   you are on `devel`/`main` or a different branch, **stop and ask** rather than
   committing the phase to the wrong place.
2. **Follow the phase prompt exactly**, in order: do its REQUIRED READING
   (including the prior phase's `RESULTS/{N-1}_Results.txt` handoff — if that
   gate is in the prompt and the file is missing, STOP and report), then work
   through its ACTION PLAN under its CONSTRAINTS. Make the edits directly.
3. **Run the VERIFICATION gates** the prompt lists and that CLAUDE.md requires —
   typically `python -m pytest`, `ruff check .`, `ruff format .`, and `php -l` /
   ShellCheck for any PHP/shell touched. All must pass before committing. If a
   gate fails, fix it within the phase's scope; do not commit red.
4. **Commit** as a single commit using the message from the prompt's COMMIT
   block. Then **push directly to the feature branch**; open a PR only if the
   direct push is rejected by branch protection.
5. **Write the handoff** `RESULTS/{NN}_Results.txt` (plain text) as directed by
   the prompt's HANDOFF section — state after this phase, decisions/values
   chosen, watch-outs, verification numbers, and the go-ahead for the next
   phase. Include it in the phase commit (or a clearly-labelled follow-up).

## Step 6 — Report back

After the phase is committed, summarize:
- Which ADR and phase was implemented, and on which branch.
- Whether `python -m pytest`, `ruff check .`, `ruff format .` (and `php -l` /
  ShellCheck if relevant) passed.
- The commit hash and whether it was pushed.
- The path to the new `RESULTS/{NN}_Results.txt`.
- Any blockers or deviations from the phase prompt.
