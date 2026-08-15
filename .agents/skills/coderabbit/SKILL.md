---
name: coderabbit
description: >
  CodeRabbit Fair Usage and CLI review. Run immediately before opening a
  GitHub PR, when a quota / "Review limit reached" notice appears, or when
  dispatching the CLI-in-CI workflow. Loads `.agents/policy/coderabbit.md`.
  Triggers: "open a PR", "Fair Usage", "rate limit", "coderabbit",
  "@coderabbitai", "/coderabbit".
---

Canonical contract: [`.agents/policy/coderabbit.md`](../../policy/coderabbit.md).
Read that file; do not invent mute labels or post `@coderabbitai rate limit`.

## Before `gh pr create`

```sh
scripts/agent/before-pr-create.sh --repo OWNER/REPO
```

- Exit 0 → open the PR.
- Exit 3 → wait until the printed `next slot`, unless the owner overrode in this conversation.
- Exit 2 → tool/auth error; stop.

The printed block is the full picture (plan hourly columns, 7-day band, remaining slots). Do not re-derive it.

## Quota notice on an open PR

A quota notice is not a review. Do not nudge while the countdown is live. Pause first, then one `@coderabbitai review` after the window. Details in the policy.

## CLI review (separate hourly budget)

Dispatch-only: Actions → **CodeRabbit CLI review** → PR number.
Needs secret `CODERABBIT_API_KEY` (Agentic key). Findings are file-level.
Do not enable per-push until a burst test says the 7-day PR taper is independent (#2436).
