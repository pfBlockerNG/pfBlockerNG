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

Result documents live in `RESULTS/` inside the ADR directory and follow
`{NN}_Results.md` (e.g. `RESULTS/02_Results.md`).

**If the user supplied a phase number**, use it directly.

**If no phase was supplied**, scan all `NN_*.txt` files in the ADR directory
sorted numerically by their `NN` prefix. The default phase is the **first** one
whose corresponding `RESULTS/NN_Results.md` does NOT exist. If all phases have
results, stop and tell the user that all phases are done.

## Step 4 — Read the phase prompt

Read the file `{ADR_DIR}/{NN}_{Name}.txt` for the resolved phase. This file
contains the full instructions for the phase, including required reading,
action plan, constraints, verification steps, and commit message.

Also read any result documents referenced as prerequisites (the prompt's
"Prereq" or "REQUIRED READING" sections often name them). They are in
`{ADR_DIR}/RESULTS/`.

## Step 5 — Spawn an implementation agent

Spawn an Agent (general-purpose) with `isolation: "worktree"` and pass it:
- The full text of the phase prompt as the task description.
- The content of any prerequisite result documents.
- An explicit instruction to write a `RESULTS/{NN}_Results.md` handoff document
  upon completion (as directed by the phase prompt's HANDOFF section).

The agent brief must be self-contained: include the ADR directory path, all
relevant file paths, and exactly what needs to be verified (tests, linters).

## Step 6 — Report back

After the agent completes, summarize:
- Which ADR and phase was implemented.
- Whether `python -m pytest`, `ruff check .`, and `ruff format .` passed.
- The path to the new `RESULTS/{NN}_Results.md` if created.
- Any blockers or deviations from the phase prompt.
