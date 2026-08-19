# CodeRabbit missed reviews

Append-only. One line per merged SHA whose only CodeRabbit engagement
was a quota notice (or none) and that never got a later finished
review of that SHA.

Format: `` `SHA`  title  (#PR) ``

Newest first.

- `1f348346b`  Consented pkg.conf PKG_ENV patch so GUI and CLI pkg operations work on Plus boxes  (#2523) — CodeRabbit finished its first review at `58b25ec25`; every finding was resolved. The material review-fix head received a 15-minute quota notice, and the single elapsed-window retry received a second quota notice (3 minutes), so the final merged SHA has no finished CodeRabbit review. Three clean adversarial legs, exact-head CI, canonical local gates, and final Tier-A/Tier-B live smoke carried the merge.
- `f0dddeb6`  pfblockerng: carry the box's CA locations on the Software catalog reads  (#2520) — CodeRabbit was never asked on this PR at all: the ack window was never armed and no `@coderabbitai review` was posted, then the PR was merged at owner instruction before the review step closed. Not a quota case — an orchestrator miss. Three-leg was also incomplete (contract-conformance lens never run round 1; run post-merge instead), and the round-2 test-honesty leg was still in flight at merge.
- `b2df9957`  install: export SSL_CA_CERT_PATH for every pkg call  (#2515) — same orchestrator miss: no CodeRabbit ack window, no `@coderabbitai review`, merged after three review rounds carried by adversarial legs only. The contract-conformance lens was likewise not run before merge (a security lens was run in its place, which is not one of the three required lenses).
- `1e735e38`  smoke: keep polling when the post-boot metadata job has not started  (#2485) — CodeRabbit finished a real review at `09:41Z` (two quota windows first: 34 min, then 13 min) and its two actionable comments were both answered. The later review-fix heads `f2fa506a` and `1e735e38` got no finished review: the bot was paused and still quota-limited, and per coderabbit.md a slot is not re-spent on mechanical review-fix rounds. Three-leg carried those rounds (four rounds total, converging clean).
- `de69f67b`  wait-checks.sh: resolve an abbreviated `--sha` at arm time  (#2482) — CodeRabbit never reviewed this PR: quota notice on the first ACK (58 min), then after the window a `pause` + `review` returned another notice (46 min), and one final `review` after that window returned a third (12 min). Path stopped there per coderabbit.md; three-leg carried the review.
- `de69f67b`  wait-checks.sh: resolve an abbreviated `--sha` at arm time  (#2482) — CodeRabbit never reviewed this PR: quota notice on the first ACK (58 min), then after the window a `pause` + `review` returned another notice (46 min), and one final `review` after that window returned a third (12 min). Path stopped there per coderabbit.md; three-leg carried the review.
- `aaf8019d`  pkg Pages: one install-`<ch>`.sh per channel that converges the box from any starting state  (#2444) — CodeRabbit finished only on `ed359c69`; the fix-round heads (`91d33b35`, `aaf8019d`) got no finished review (one nudge already spent on a quota window; not re-spent).
