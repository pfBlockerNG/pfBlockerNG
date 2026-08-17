# CodeRabbit missed reviews

Append-only. One line per merged SHA whose only CodeRabbit engagement
was a quota notice (or none) and that never got a later finished
review of that SHA.

Format: `` `SHA`  title  (#PR) ``

Newest first.

- `de69f67b`  wait-checks.sh: resolve an abbreviated `--sha` at arm time  (#2482) — CodeRabbit never reviewed this PR: quota notice on the first ACK (58 min), then after the window a `pause` + `review` returned another notice (46 min), and one final `review` after that window returned a third (12 min). Path stopped there per coderabbit.md; three-leg carried the review.
- `de69f67b`  wait-checks.sh: resolve an abbreviated `--sha` at arm time  (#2482) — CodeRabbit never reviewed this PR: quota notice on the first ACK (58 min), then after the window a `pause` + `review` returned another notice (46 min), and one final `review` after that window returned a third (12 min). Path stopped there per coderabbit.md; three-leg carried the review.
- `aaf8019d`  pkg Pages: one install-`<ch>`.sh per channel that converges the box from any starting state  (#2444) — CodeRabbit finished only on `ed359c69`; the fix-round heads (`91d33b35`, `aaf8019d`) got no finished review (one nudge already spent on a quota window; not re-spent).
