---
name: coderabbit
description: >
  Asking CodeRabbit for a review, handling its Fair Usage quota notices, and
  dispatching the CLI-in-CI workflow. Run when a PR is ready to merge, when a
  quota / "Review limit reached" notice appears, or before dispatching the CLI
  workflow. Loads `.agents/policy/coderabbit.md`. Triggers: "ready to merge",
  "Fair Usage", "rate limit", "coderabbit", "@coderabbitai", "/coderabbit".
---

Canonical contract: [`.agents/policy/coderabbit.md`](../../policy/coderabbit.md).
Read that file; do not invent mute labels or post `@coderabbitai rate limit`.

## Automatic review is off

Opening or pushing a PR triggers no CodeRabbit review. Nothing to wait on until
you ask. Do not arm a reviewer wait at PR-open time.

## Asking for the review

Post exactly one top-level `@coderabbitai review` comment, and only once all of
these hold:

- development is finished;
- the adversarial review of `landing.md` is complete and its findings resolved;
- CI is green on the head SHA;
- you judge the code ready to merge.

Then arm the bounded wait:

```sh
scripts/agent/wait-reviewer.sh --repo OWNER/REPO --pr N \
  --handle coderabbitai --until finished --since "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

FINISHED → triage every finding. QUOTA → wait the stated window, then one more
ask; a second quota notice ends it with a recorded miss. Never nudge while a
countdown is live.

## Do not re-ask

Not for format-only, comment-only, lint, or mechanical APPLY of CodeRabbit's own
suggestions. Only a material behaviour change after the review earns a second
ask, and only one.

## CLI review (separate hourly budget)

Dispatch-only: Actions → **CodeRabbit CLI review** → PR number.
Needs secret `CODERABBIT_API_KEY` (Agentic key). Findings are file-level.
Do not enable per-push until a burst test says the 7-day PR taper is independent (#2436).
