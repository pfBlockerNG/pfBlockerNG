# Session history — claude-dev, 2026-09-01

Written at 86% context, for a successor (probably a cleared version of this seat)
picking up the open work. Companion to `HANDOFF-claude-dev.md`, which is the
terse state; this is the reasoning behind it.

Read the section on your task, then "Corrections" and "Traps" before touching
anything. Several conclusions here cost multiple rounds to reach and one of them
reverses something stated confidently earlier in the day.

## What landed

| item | result |
|---|---|
| #3046 / PR #3047 | PSL index off the `lru_cache` key path |
| #3051 | closed with it — the guard that let #3046 through now asserts structurally |
| #3058 / PR #3067 | build duration and per-structure counts on the `init_standard` log line |
| #3059 / PR #3072 | regex lint reports a warning, not a syntax error |

Nine issues filed: #3055, #3056, #3057, #3059, #3060, #3061, #3062, #3063, #3075,
plus #3088. andrebrait implemented #3061 (PR #3080), #3062 (PR #3086) and #3063
(merged) the same night.

## The #3046 story, because its numbers anchor everything else

`_psl_index()` was `@lru_cache`d on the frozen `PslRules` dataclass. Computing
that cache key hashes six tuples holding every PSL rule, and CPython does not
cache tuple hashes, so every call walked all ~10k shipped rules before the O(1)
lookup. The fix holds the sets on the instance.

Measured on the maintainer's production pfSense Plus 25.11 box, 1,219,390 DNSBL
entries across 29 feeds, `build()` timed in isolation, medians of three:

```text
shipped baseline (0a31b83…)   93.17 s
#3046                         44.14 s      -49.0 s
#3046 + #3050                 42.44 s      -1.7 s
+ charset change (unmerged)   37.75 s      -6.4 s
```

**The 49 s figure originally in the issue was never the defect's cost.** It was
measured with an undocumented `eq=False` diagnostic edit still present on the
reporting box, which gives `PslRules` identity hashing and so removes the same
cost by a different, unshippable mechanism. That is why the fix appeared to do
nothing there at first, and it took most of the evening to find. Five hypotheses
died before it: PSL gate off, feeds are ABP, long TLD blacklist, entries rejected
before the classifier, stale bytecode cache. All refuted with evidence.

The lesson that generalises: **the reporting box carried a modification nobody
had recorded.** Before trusting any "before" number, verify what the before
actually is.

## Next task: #3055, and everything already established about it

Highest user harm of anything open. The maintainer hit it twice on production:
`bind: address already in use`, requiring `kill -9` and regenerating the unbound
PEM files.

**The mechanism I originally filed was wrong and I corrected it on the issue.**
Python *does* service SIGTERM during a pure-Python CPU loop — measured 305 ms
latency, both for a busy loop and for a GIL-releasing call. Do not rebuild an
argument on "Python does not service signals".

The real cause is in our own PHP, `pfblockerng.inc:11417-11429`:

```php
define('PFB_UNBOUND_STOP_WAIT', 30);
...
sigkillbypid("{$g['varrun_path']}/unbound.pid", 'TERM');
for ($i=1; $i <= PFB_UNBOUND_STOP_WAIT; $i++) {
    if (is_process_running('unbound')) { pfb_logger('.', 1); sleep(1); }
    else { pfb_logger("\nUnbound stopped in {$i} sec.", 1); break; }
}
// then unconditionally:
pfb_logger("\nStarting Unbound Resolver", 1);
```

The wait is bounded but **the timeout is not handled** — no branch for "still
running after 30 s". Execution falls through and starts a second instance on top
of the first.

The signal half still matters, but as duration: unbound cannot act on a queued
shutdown until it returns from the pythonmod init call, so a stop issued mid-init
takes as long as the remaining init.

**Still live after #3046.** Stop wait is 30 s; the maintainer's init is 42.44 s
even after #3046 and #3050. Roughly 800k+ entries on that hardware is enough to
stay exposed. Merging #3046 did not fix this, and the issue says so explicitly.

Fix direction, from the issue comment:

1. Check `is_process_running` after the loop — the predicate already exists.
2. Escalate rather than fall through: second TERM, then KILL, then re-verify. Or
   abort with a loud ledger entry. Starting a second instance is the one branch
   that produces an unrecoverable state.
3. Verify the port, not just the process. `bind` is about `:53`, and a socket can
   outlive a pid — `sockstat -46l | grep ':53'`.

**Unit-testable off-appliance.** `is_process_running` is stubbed at
`stubs/pfsense/util.php:26`, so the timeout branch needs no live daemon and no
Tier-B seat. That is what makes this the best available work — everything else
blocking tonight needed a smoke seat.

Related, do not conflate: #3086 (andrebrait) serialises package installs against
an in-flight feed pass. That addresses a *trigger*; #3055 is the fall-through
itself.

## Other open work

### #3056 — charset scans, measured and ready

Three sites: two per-character label charset scans and one `*!` scan. Replace
with `frozenset.issuperset` and a plain `or`. Measured 44.14 s → 37.75 s on the
maintainer's box (14.5%), 16.4% on a dev box against their corpus, byte-identical
output both times (`data=183880 zone=918971`).

Their 1.2M-entry corpus is staged at `/var/tmp/agents/pfb3046` as a reproduction
fixture — **on disk, not tmpfs, so it survives**. `run3046.py` and the probes are
at `~/pfb-diagnostics/`.

### #3088 — save-time notice with an override

The maintainer's design, and the strongest idea of the evening. When the editor's
checker flags a pattern, block the save and offer an explicit override checkbox.
One boundary: checker-flags + **Python-rejects** must stay unbypassable, because a
non-compiling regex saved is a rule that silently never matches. The override
exists only for checker-flags + Python-accepts, where our grammar is incomplete
and the user is right.

Every use of the override is a false-positive report on a real pattern — which
gives a measured false-positive rate for a grammar we wrote ourselves, and a bug
report with a reproduction attached. Per-save, never persisted.

### #3057, #3075 — offered to claude2-dev

### #3062 — needs the maintainer's logs

`grep -i pfblockerng /var/log/system.log` around 13:01-13:10. andrebrait opened
PR #3086 for it anyway.

## Corrections — things stated confidently and then reversed

Record these; a fresh context will otherwise repeat them.

**Smoke capacity.** claude-smoke declined a Tier-B run at 89% context and framed
it as a lab-wide single-point-of-failure. I escalated that to the owner, then saw
three smoke seats in `pfb-msg who`, concluded the lab had capacity, and
**retracted a correct escalation**. The owner corrected me back. `who` lists
mailboxes, not agents.

**Send counts, three times wrong.** First mine (200-line window), then
claude2-dev's (globbed `new/` and `cur/`, missing `read/`). The correct form:

```sh
grep -h '^From:' */new/*.md */read/*.md | sort | uniq -c | sort -rn
```

```text
claude-smoke   556      grok-smoke  534      grok  350
claude-dev     296      grok-dev    286      claude2-dev  98
claude2-smoke    8   <- all 2026-08-30, then silence
```

grok-smoke is **live** but limited; claude2-smoke is dead.

**Cross-box facts.** I relayed `id claude2` output from smoke-1 as though it
described pfb-dev. It does not — claude2 is not in group `pfb` there, and
`/srv/Smoke` does not exist on pfb-dev at all. **Name the box when quoting a
figure.**

**A workaround that fixed nothing.** I told the maintainer to change `??` to `?`
in two regexes to clear a lint marker. It did not clear it — the trigger was a
single `?` before a flag letter, not the double. Nearly walked them into editing
working rules to satisfy a broken checker, which is the exact harm #3059 exists
to prevent.

## Traps that cost real time

- **A red result that arrives too fast is not a red result.** 391 test "failures"
  in 12 s where 5849 passes take 65 s — all `ENOSPC` from a full tmpfs. Check
  `df -h /tmp` before debugging the diff.
- **`/tmp` is a 3.9 GB tmpfs shared by every seat.** Session directories are never
  reaped; four stale ones held 1.7 GB. Sandboxes belong in `/var/tmp/agents`.
  Verify staleness by mtime **and** zero `/proc/*/cwd` refs before deleting.
- **node tests need the Lezer parsers generated first**, or `ERR_MODULE_NOT_FOUND`
  reports as `# pass 0 # fail 1` — reads as a red, means zero tests ran.
- **A worktree needs `composer install`** or the `composer vendor` pre-commit gate
  blocks the commit — and `git log -1` then shows the *base* commit, which reads
  as success.
- **The PHP suite carries ~61 errors / 15 failures on devel off-appliance.**
  Reproduce on base before attributing anything to a PR.
- **`unbound-checkconf` must run from `/var/unbound`.** `python-script:` is a
  relative path and checkconf does not chroot; from elsewhere it dies in 0.02 s,
  which reads as a spectacular result.
- **Both copies of `pfb_unbound.py` matter.** checkconf reads the chroot copy;
  the package copy is what survives a feed pass. Patch one and you measure the
  other.
- **`cp -a` of a worktree keeps its `.git` pointer file** and operates on the
  original's index — andrebrait's #3089. `git archive HEAD | tar -x` has no `.git`
  at all and is safe for read-only scratch.

The shape common to most of these: **a listing proves a thing exists, not that it
works.** A mailbox is not an agent; a `.git` pointer is not isolation; a passing
test file is not an executed test.

## Review-leg practice that worked

Four legs per PR, models per `.agents/model-tiers.conf`. What mattered:

- **Post each leg's audit before any fix commit derived from it.** Owner's
  instruction; keeps the PR chronological.
- **Give each leg its required reading as `file:line` refs.** `delegation.md:76`
  mandates it — sub-agents start fresh and load nothing.
- **Tell them in capitals to sandbox under `/var/tmp/agents`** and delete it.
- Legs disagreeing is useful. On #3067, leg 3 found the count formula unpinned and
  proposed a fix that would not have worked; leg 1 had independently established
  why (`init_standard` rebinds the DBs). The working fix came from combining them.

## Environment

```text
maintainer's box   pfSense Plus 25.11, 1,219,390 DNSBL entries, 29 feeds
Plus test clone    10.30.41.108, 26.07-RELEASE — see BOXES-AND-BUS.md for access
pytest             /home/claude/pfBlockerNG/.venv/bin/pytest
phpunit            vendor/bin/phpunit (needs composer install per worktree)
corpus fixture     /var/tmp/agents/pfb3046
probes             ~/pfb-diagnostics/
```
