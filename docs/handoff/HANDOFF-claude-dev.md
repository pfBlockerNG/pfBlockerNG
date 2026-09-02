# Handoff — claude-dev

Written at 86% context (864k/1M). Nothing below is in flight; every item is
either landed, blocked on someone else, or not started.

## Landed this session

| item | result |
|---|---|
| #3046 / PR #3047 | merged. PSL index off the lru_cache key path. **93.17s -> 44.14s** on the owner's production 25.11 box (1,219,390 entries) |
| #3051 | closed with it. The throughput guard now asserts structurally, not on a clock |
| #3058 / PR #3067 | merged. Build duration + per-structure counts on the `init_standard` log line |

Nine issues filed: #3055, #3056, #3057, #3059, #3060 (claude2-dev), #3061, #3062, #3063 and #3075. Of those, andrebrait has since implemented #3063
(`f36c2a9a8`) and #3061 (PR #3080).

## Open, mine

### PR #3072 (#3059) — regex lint severity, waiting on owner's instruction

Code complete, CI green, four legs reported, ledger posted. andrebrait's
CHANGES_REQUESTED was about a regex101 link, now removed; he has since said
"just switch to Warning, or keep Error but don't block the save button", so the
core is accepted.

**Two things it still needs:**

1. **A vacuous test.** `tests/webassets/cm-lint.test.js` asserts "a valid
   real-world rule that trips the grammar is a warning, not an error" using the
   owner's rule `^(.+[-_.])?m?ad[sxv]?[0-9]*[-_.]`. Since #3063 landed, that rule
   parses cleanly and produces **0 diagnostics**, so the `for (const d of diags)`
   loop body never runs and the test passes while asserting nothing. Verified
   against origin/devel: 0 diags for all three of the owner's rules, 1 for a bare
   `(`. Review leg 3 predicted this exact failure four hours before it happened.
   Fix: use a pattern that still trips the current grammar, or restructure so it
   cannot pass on an empty list.
2. **A Tier-B run**, which no seat can currently produce — see below.
   `tests/smoke/ui/test_browser_lint.py::test_regex_editor_offline_bracket_lint_marks_instantly`
   RED at `0d8610b22^` (marker carries `cm-lint-marker-error`),
   GREEN at `cb08b3292` (`cm-lint-marker-warning`).
   **The red half is the one that matters** — if it passes on the parent, the
   assertion is not seeing severity and the row is theatre.

## Not started, ranked by user harm

### #3055 — unbound double-bind on restart: highest harm, root cause found

The owner hit this twice on production: `bind: address already in use`, requiring
`kill -9` and regenerating the unbound PEM files.

**My original filed mechanism was wrong** and I corrected it on the issue.
Python *does* service SIGTERM during a pure-Python CPU loop (measured: 305ms).
The real cause is in our own PHP, `pfblockerng.inc:11417-11429`:

```php
define('PFB_UNBOUND_STOP_WAIT', 30);
...
for ($i=1; $i <= PFB_UNBOUND_STOP_WAIT; $i++) {
    if (is_process_running('unbound')) { sleep(1); } else { break; }
}
// then unconditionally:
pfb_logger("\nStarting Unbound Resolver", 1);
```

The wait is bounded but **the timeout is not handled** — no branch for "still
running after 30s". Execution falls through and starts a second instance.

**Still live after #3046**: stop wait is 30s, the owner's init is 42.44s even
after #3046 + #3050. Anyone past ~800k entries on that hardware remains exposed.

Fix direction: check `is_process_running` after the loop; escalate (TERM -> KILL
-> re-verify) or abort loudly. Also verify the port, not just the process --
`bind` is about `:53` and a socket can outlive a pid.

**Unit-testable off-appliance** — `is_process_running` is stubbed at
`stubs/pfsense/util.php:26`, so this needs no Tier-B seat. That makes it the best
next piece of work available.

### #3056 — charset scans, measured and ready

`frozenset.issuperset` for the two per-character label scans plus a plain `or`
for the `*!` scan. **44.14s -> 37.75s on the owner's box (14.5%)**, 16.4% on a
dev box against the owner's corpus, byte-identical output both. Now unblocked
(#3067 is off `pfb_unbound.py`). Owner's 1.2M-entry corpus is staged at
`/var/tmp/agents/pfb3046` as a reproduction fixture — **that path is on disk, not
tmpfs, and will survive**.

### Owner's bypass-checkbox design — not yet filed

Owner proposed: when the editor's checker flags a pattern, block the save with a
checkbox to override. Agreed shape, with one boundary:

- checker flags + **Python rejects** -> **no override**. A non-compiling regex
  saved is a rule that silently never matches; blocking is correct.
- checker flags + **Python accepts** -> override allowed. This is our grammar
  being incomplete and the user is right.

Per-save, never persisted. Name the flagged lines. **Record the bypassed
patterns** — each is a false-positive report with a reproduction attached, and
counting them gives a measured false-positive rate for a grammar we wrote
ourselves. Awaiting andrebrait's response before filing.

### Others

- **#3062** — blocked on the owner's logs (`grep -i pfblockerng /var/log/system.log`, 13:01-13:10).
- **#3057**, **#3075** — offered to claude2-dev.
- **#3061** — andrebrait is on it (PR #3080).

## Lab state a successor needs

**Tier-B capacity is one seat.** `pfb-msg who` lists mailboxes, not agents.
Sends, in the last 200 bus lines: claude-smoke **75**, grok-smoke **0**,
claude2-smoke **0**. Only claude-smoke is live, and they are at 89% with
`handoff_due`. grok-smoke is limited; claude2-smoke has never transmitted.

**I got this wrong once**: claude-smoke declined, I concluded the lab had no
capacity, escalated it to the owner as a design question, then saw three seats in
`who` and *retracted a correct escalation*. The owner corrected me back. The
discriminator is sends, not unread count or serve uptime.

**Traps that cost real time tonight** (some now in `/srv/docs/TRAPS.md`):

- `/tmp` is a 3.9G tmpfs shared by every seat. Session dirs are never reaped — four stale ones held 1.7G. Sandboxes belong in `/var/tmp/agents`. Verify staleness by mtime **and** zero `/proc/*/cwd` refs before deleting.
- node tests need the Lezer parsers generated first, or `ERR_MODULE_NOT_FOUND` reports as `# pass 0 # fail 1` — reads as a red, means zero tests ran.
- PHP suite carries ~61 errors / 15 failures on devel off-appliance. Reproduce on base before attributing anything to a PR.
- A worktree needs `composer install` or the pre-commit `composer vendor` gate blocks the commit — and `git log -1` then shows the *base* commit, which reads as success.

## Review-leg template notes

Four legs per PR, models per `.agents/model-tiers.conf`. Post each leg's audit
**before** any fix commit derived from it. Give each leg its required reading as
`file:line` refs — `delegation.md:76` mandates it and sub-agents load nothing
automatically. Tell them in capitals to sandbox under `/var/tmp/agents` and
delete it when done.
