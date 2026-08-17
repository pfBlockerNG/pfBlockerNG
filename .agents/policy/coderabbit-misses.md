# CodeRabbit missed reviews

Append-only. One line per merged SHA whose only CodeRabbit engagement
was a quota notice (or none) and that never got a later finished
review of that SHA.

Format: `` `SHA`  title  (#PR) ``

Newest first.

- `1e735e38`  smoke: keep polling when the post-boot metadata job has not started  (#2485) — CodeRabbit finished a real review at `09:41Z` (two quota windows first: 34 min, then 13 min) and its two actionable comments were both answered. The later review-fix heads `f2fa506a` and `1e735e38` got no finished review: the bot was paused and still quota-limited, and per coderabbit.md a slot is not re-spent on mechanical review-fix rounds. Three-leg carried those rounds (four rounds total, converging clean).
- `de69f67b`  wait-checks.sh: resolve an abbreviated `--sha` at arm time  (#2482) — CodeRabbit never reviewed this PR: quota notice on the first ACK (58 min), then after the window a `pause` + `review` returned another notice (46 min), and one final `review` after that window returned a third (12 min). Path stopped there per coderabbit.md; three-leg carried the review.
- `de69f67b`  wait-checks.sh: resolve an abbreviated `--sha` at arm time  (#2482) — CodeRabbit never reviewed this PR: quota notice on the first ACK (58 min), then after the window a `pause` + `review` returned another notice (46 min), and one final `review` after that window returned a third (12 min). Path stopped there per coderabbit.md; three-leg carried the review.
- `aaf8019d`  pkg Pages: one install-`<ch>`.sh per channel that converges the box from any starting state  (#2444) — CodeRabbit finished only on `ed359c69`; the fix-round heads (`91d33b35`, `aaf8019d`) got no finished review (one nudge already spent on a quota window; not re-spent).
