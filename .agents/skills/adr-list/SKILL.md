---
name: adr-list
description: >
  List the ADRs that are still open work — NOT yet implemented and NOT already in
  flight — as a table of `ADR-NN | Name | Status`, so you can pick what to build
  next. "Not implemented" = the ADR's code has NOT landed on `devel` AND it has NO
  open PR. Excludes Rejected ADRs, anything already Accepted/landed, and anything
  with an open PR. Read-only; writes nothing. Args: none. Use when the user says
  "list ADRs", "what ADRs are left", "which ADRs can I work on next", "adr-list",
  or invokes /adr-list.
---

You list the ADRs that are **candidates for AI to work on next** — the ones whose
code has **not** reached `devel` and which have **no open PR**. The output is a
single Markdown table; you write nothing to the repo.

A candidate is an ADR that is **none** of: Rejected, already implemented (landed on
`devel`), or in flight (has an open PR). Everything else is a candidate.

## Step 1 — Collect the ADRs

- **Public ADRs** live one-per-directory under `.ADRs/ADR_{NN}_{Name}/ADR.md`. For each:
  - **Code** = `ADR-{NN}` from the directory (`ADR_07_ABP_DNSBL_Support` → `ADR-07`).
  - **Name** = the directory's `{Name}`, de-slugged (`ABP_DNSBL_Support` → "ABP DNSBL
    Support"), or the `ADR.md` H1 title if clearer.
  - **Status** = the value on the `**Status:**` line — take the **leading status word**
    (`Proposed` / `Accepted` / `Rejected` / …); ignore the trailing prose/dates.
- **Private ADRs** (if the companion `pfBlockerNG/private` checkout is present): scan its
  `.ADRs/PFBL_{NN}_{Name}/ADR.md` the same way (code `PFBL-{NN}`). **Disclosure rule —
  the resulting rows are LOCAL OUTPUT ONLY:** never copy a `PFBL-NN` code, name, or status
  into any public artifact (commit message, PR/issue/comment, pushed file). If the private
  repo isn't checked out, just list the public ADRs.

## Step 2 — Drop the non-candidates

Remove an ADR when **any** of these holds:

- **Rejected** — the leading status word starts with `reject` (case-insensitive). Excluded
  by definition (`REJECTED` and `Rejected` both count).
- **Implemented (code reached `devel`)** — the repo flips an ADR to **Accepted** only once
  it has landed on `devel` with green coverage (see `CLAUDE.md` → "ADR acceptance"), so a
  leading **`Accepted`** status ⇒ in `devel` ⇒ drop. Also treat an explicit
  "landed/shipped to `devel`" / "all phases on `devel`" / "implemented on `devel`" note in
  the Status line as implemented.
- **In flight (has an open PR)** — there is an **open** PR belonging to this ADR. Detect it by
  either signal:
  - a head branch matching the `/adr-phase` convention `adr/{NN}-*` (or bare `adr/{NN}`), or
  - a PR **title or body** referencing `ADR-{NN}` (e.g. "implement ADR-25", "ADR-27 phase 3").

  List open PRs with `gh pr list --state open --json number,title,headRefName,body` where the
  `gh` CLI is available, otherwise `mcp__github__list_pull_requests` (state `open`) or
  `mcp__github__search_pull_requests` (`is:pr is:open ADR-{NN}`). A match ⇒ drop (it is
  already being worked).

What remains is the candidate set.

## Step 3 — Output the table

Print a Markdown table, sorted by ADR number, with exactly these columns:

```text
| ADR    | Name                | Status   |
| ------ | ------------------- | -------- |
| ADR-25 | Group Policy DNSBL  | Proposed |
```

- The **Status** column is the ADR's own recorded status (almost always `Proposed` — its
  context for picking). Do **not** emit Rejected or Accepted rows.
- If the candidate set is **empty**, say so plainly: "No non-implemented ADRs — every ADR is
  Accepted/landed, Rejected, or has an open PR."
- Keep any private `PFBL-NN` rows in this local table only (Step 1 disclosure rule).

## Notes

- **Read-only.** This skill inspects `.ADRs/` and open PRs; it never edits, commits, or pushes.
- Don't infer a status you can't read — if an ADR's `**Status:**` line is missing or unusual
  and it has no open PR, include it as a candidate and show its raw status verbatim.
- To then build one, hand its code to `/adr-phase {NN}` (single phase) or `/adr-all {NN}`
  (end-to-end).
