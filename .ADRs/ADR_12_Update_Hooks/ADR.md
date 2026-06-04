# ADR-12: Generic pre/post update command hooks

- **Status:** **Proposed** (2026-06-02)
- **Date:** 2026-06-02
- **Branch:** `adr/12` (off **`devel`** — update-flow/PHP side, no Python/DNSBL coupling; independent of the ADR-07/10 chain. Pairs with ADR-11 (`devel`) but does not require it to land first) / **Component(s):** `src/usr/local/pkg/pfblockerng/pfblockerng.inc` (a `pfb_run_hooks()` runner + the pre/post fire points in `sync_package_pfblockerng`, config read), `src/usr/local/www/pfblockerng/*` + the settings schema (the hooks table UI), `README.md`/`CLAUDE.md` (docs + the HAProxy recipe).
- **Target runtime:** PHP 8.3 + POSIX `sh` (pfSense CE 2.8). **No Python** — the Unbound plugin is untouched.
- **Test suite:** **No `pytest` oracle** (PHP/shell; no unit harness in-repo, same reality as ADR-11). Validation = `php -l` + PHPStan + ShellCheck (the automated gate) + a **manual smoke checklist** (hooks fire with correct context; failure/timeout handled; HA sync; the HAProxy recipe end-to-end on a live box).

---

## 1. Context

### Today

pfBlockerNG runs its feed/DNSBL update through one entry point, with **no way for an admin to run their own command before or after it**:

1. **The update entry is `sync_package_pfblockerng($cron='')`** (`pfblockerng.inc:6556`). It is invoked by the cron job `pfblockerng.php cron` (`:10149`) and by the manual *Update* / *Force Update* / *Force Reload* actions — all funnel here. `$cron` distinguishes the trigger.
2. **"What changed" is already tracked.** The pass sets `$pfb['filter_configure'] = FALSE` and flips it when a firewall reload is needed (`:6561`); per-area `$pfbupdate`/`$pfbpython` flags track whether IP / DNSBL data changed (`:1924`, `:2059`, `:8488`, …). DNSBL reload goes through `pfb_update_unbound`/`pfb_reload_unbound` (`:3193`/`:3095`); IP tables through `pfb_aliastables` + `filter_configure`; the pass ends near a `closing` step (`:10293`). → A **post**-hook can be handed an accurate change summary for free; the **pre**/**post** fire points are the function's start and that closing tail.
3. **No generic user-command hook exists.** Every `exec("{$pfb['script']} …")` in the pass calls pfBlockerNG's **own** shell helper (`pfblockerng.sh`: `whoisconvert`, `et`, `cidr_aggregate`, `suppress`, …). The selectable per-list `ip_pre_*.sh` scripts (e.g. `ip_pre_AWS_*.sh`, CLAUDE.md) are **per-feed fetch/transform pre-scripts**, not an update-level hook — a different feature, and a **naming-collision risk** to avoid.
4. **pfBlockerNG already manipulates pfSense `shellcmd`/`earlyshellcmd`** for the boot-time aliastable restore (`:4406-4468`) — precedent for the package writing command config, but that is boot-only, not per-update.
5. **Config syncs to a CARP/HA secondary** via `pfblockerng_sync_on_changes()` (`:10425`). Anything stored in the pfBlockerNG config is replicated to the secondary.

### The need (motivating use case — ADR-11/HAProxy)

After an IP update, downstream consumers need a nudge. The concrete driver: ADR-11's aggregate alias (`pfB_Aggregate_*`) is consumed by **HAProxy** to block CF-fronted real-client IPs — but HAProxy only re-reads its `-f` ACL files **at reload**, and the pfSense runtime socket can't inject the data (see `[[haproxy-integration-findings]]`; socket = stats + hitless-reload only, `haproxy.inc:1562`). So freshness = **trigger a graceful HAProxy reload after the pfBlockerNG update** (the package then re-emits the `ipalias_*.lst` via its `source_ip` emission, `haproxy.inc:1085`). That is just *"run a command after the update finishes."*

### Decision driver (project PoV, user-confirmed)

Rather than hardcode HAProxy (coupling pfBlockerNG to another package's churny internals), make the mechanism **generic** — "run anything before/after a pfBlockerNG update" — and ship **HAProxy as a documented recipe**. The same hooks serve service restarts, a Cloudflare-API push, downstream sync, notifications, etc.

### Load-bearing facts

1. **Feature, not a premise.** No perf/memory claim to falsify (unlike ADR-01); the risk is *operational safety* (a user command running as root from the update pass must not hang, break, or destabilise updates).
2. **No PHP/shell test harness** (same as ADR-11) → validation is lint + manual smoke + the HAProxy recipe end-to-end. No oracle.
3. **The trust model already allows admin root commands** — pfSense `shellcmd`/cron store admin-authored commands run as root; the pfBlockerNG GUI is admin-only. A hook command is the same trust class.
4. **Change context is available without new tracking** (fact 2) — so conditional hooks need no extra machinery.

---

## 2. Decision

Add **admin-configurable pre/post update command hooks**: a list of hook entries, run as root with a timeout at the start and end of every pfBlockerNG update pass, fed rich context, with failures logged and **never** allowed to break or block the update.

| Area | Decision |
| --- | --- |
| **Hook model** | A **list of hook entries** in the pfBlockerNG config: `{ command, when: pre\|post, enabled: bool, description, timeout? }`. Mirrors pfSense `shellcmd`'s `{cmd, cmdtype}` shape; supports multiple hooks, ordering (list order), and enable/disable. |
| **Fire points (whole-cycle)** | **`pre`** runs at the **top** of `sync_package_pfblockerng` (before any feed processing); **`post`** runs at the **end** (after IP/DNSBL reloads + `filter_configure`, at the closing tail `:10293`). **Two points only** — granularity beyond this is out of scope (the context flags make per-type points unnecessary). Fire on **every** trigger (cron, manual Update, Force Update/Reload); `PFB_TRIGGER` distinguishes them. |
| **Context (env vars)** | Hooks receive env vars. **pre:** `PFB_TRIGGER` (cron\|update\|force-update\|force-reload), `PFB_WHEN=pre`. **post:** the above plus `PFB_IP_CHANGED`, `PFB_DNSBL_CHANGED` (0\|1, from `$pfbupdate`/`$pfbpython`), `PFB_STATUS` (ok\|partial\|error), and `PFB_CHANGED_ALIASES` (space-separated). Documented + stable. (pre can't know what changed yet — nothing downloaded.) |
| **Execution** | Run as **root** via `mwexec` **synchronously with a per-hook timeout** (sane default, e.g. 60 s, overridable); stdout/stderr captured to the pfBlockerNG log with a clear header. Synchronous + timeout (not detached) so failures are logged in order and a quick reload completes before the pass returns. |
| **Failure semantics** | A hook's **non-zero exit or timeout is logged and the update CONTINUES** — pre **and** post. A bad/hung/typo'd hook can **never** brick or stall updates. (No "abort on failure"; if a hook is a hard precondition, that's the user's script's problem to signal — we still don't abort.) |
| **Security / UI** | An **admin-only** settings table (add/edit/enable/reorder/delete; command, when, description, timeout) with help text documenting the env vars. Same root-command trust class as pfSense `shellcmd`; the field is clearly labelled as running as root. |
| **HA sync** | Hooks live in config → replicate to the CARP/HA secondary (`:10425`) and **run there too** when the secondary updates. This is **correct** for the HAProxy case (the secondary's HAProxy needs its own reload) and documented as a behaviour. |
| **HAProxy = recipe, not code** | No HAProxy-specific code/UI. The docs ship a **worked recipe**: a `post` hook guarded on `[ "$PFB_IP_CHANGED" = "1" ]` whose command triggers a **graceful HAProxy reload** (the package's reload — `haproxy_check_run`/`haproxy_configure`, `haproxy.inc:2491`/`:1349`), plus the HAProxy config pattern (one `source_ip` ACL referencing `pfB_Aggregate_v4` → package emits `ipalias_pfB_Aggregate_v4.lst`; a header ACL referencing that file; ADR-11's never-empty file removes the dummy-IP hack). |

### Semantics that MUST be preserved (the contract)

- **Additive.** With **no enabled hooks**, the update pass is **byte-identical** to today (the runner is a no-op).
- **A hook can never break or block an update.** Non-zero exit, crash, or hang → logged, timed out, update continues. Pre and post alike.
- **Hooks run as root, admin-only** — same trust class as pfSense `shellcmd`; no privilege escalation surface beyond what an admin already has.
- **Context env vars are stable + documented** — a hook can rely on `PFB_TRIGGER`/`PFB_IP_CHANGED`/… being present with the documented values.
- **Ordering** — hooks run in listed order; all `pre` before any processing, all `post` after everything.
- **No interference with the existing pass** — the runner only reads the change flags; it changes no update logic.

### Explicitly kept / out of scope

- **HAProxy-specific code or UI** — out; HAProxy is a documented recipe driven by a generic hook.
- **Per-feed / per-list hooks** — out; those are the existing `ip_pre_*.sh` pre-scripts (different feature).
- **Per-type (post-IP/post-DNSBL) or per-reload fire points** — out for v1; the post context flags cover the need. Extensible later.
- **A full event/plugin system, hook return-value protocols, "abort on failure"** — out; this is a thin, safe command runner.
- **Detached/async hook execution** — out for v1 (synchronous + timeout is simpler and sufficient; a quick reload fits the budget).

---

## 3. Consequences

**Positive**

- Closes the loop ADR-11 opened: a post-update hook gives HAProxy (and anything else) a fresh-data nudge with **zero new coupling** — the reload is a documented one-liner, not pfBlockerNG code.
- Broadly useful: service restarts, Cloudflare-API push, downstream sync, monitoring pings, custom logging — all via the same mechanism.
- Idiomatic + low-risk: mirrors pfSense `shellcmd`; reuses existing change-tracking; additive and safe-by-default (failures never break updates).
- HA-aware for free (hooks run on whichever node updates).

**Negative / risks**

- **Arbitrary root commands.** Mitigated: admin-only (same trust as `shellcmd`/cron), clearly labelled, timeout-bounded, never escalating beyond existing admin power.
- **A hook adds pass latency / could hang.** Mitigated: synchronous **timeout** + log-and-continue; a hung hook is killed, the update proceeds.
- **HA double-run surprise.** A hook runs on the secondary too. Mitigated by documenting it (and it's the desired behaviour for the HAProxy case).
- **No automated oracle** (PHP/shell). Mitigated: thin runner, lint-clean, tight manual smoke, and the HAProxy recipe proven end-to-end.
- **Log noise** from chatty hooks. Mitigated by a clear per-hook log header + capturing output under the existing logger.

---

## 4. Requirements (acceptance)

1. **Additive:** no enabled hooks ⇒ byte-identical update pass.
2. **Fires correctly:** `pre` at the start, `post` at the end, on cron + manual + force triggers; correct `PFB_TRIGGER`.
3. **Context:** `post` hooks receive accurate `PFB_IP_CHANGED`/`PFB_DNSBL_CHANGED`/`PFB_STATUS`/`PFB_CHANGED_ALIASES`; `pre` receives `PFB_TRIGGER`/`PFB_WHEN`.
4. **Safe:** a failing hook (non-zero) is logged and the update continues; a hanging hook is killed at its timeout and the update continues — pre and post.
5. **Admin-only UI:** the hooks table adds/edits/enables/reorders/deletes entries; help documents the env vars + the run-as-root caveat.
6. **HAProxy recipe works end-to-end** (manual smoke): an IP update → post hook → graceful HAProxy reload → fresh `ipalias_*.lst` → a header ACL blocks a listed IP.
7. **Lint-clean:** `php -l` + PHPStan + ShellCheck clean; `python -m pytest` untouched/green.

---

## 5. Constraints (from `CLAUDE.md`)

- **PHP:** tabs, 8.3, no `die()`/`exit()` in library code; pfSense fns via stubs (add to `stubs/pfsense/` if a new one is used; PHPStan is the gate). Use `mwexec`/`mwexec_bg` semantics correctly for the timeout.
- **Shell:** any helper is POSIX `sh`, quoted, absolute binary paths, ShellCheck-clean. The documented HAProxy-recipe hook command must be POSIX-sh-safe.
- **No shipped Python change**; the Unbound plugin and `pytest` suite are untouched.
- Commit style `<scope>: <imperative summary>`; **work inline on `adr/12`, one commit per phase, push directly** (PR only if rejected); promote `devel → next` by rebase + `--force-with-lease`. PR bodies via `--body-file`.
- **Docs:** README/CLAUDE.md + the settings help updated when the feature lands (final phase), including the HAProxy recipe.

---

## 6. Action plan

Each phase = one commit, leaves the tree lint-clean (`php -l`/PHPStan/ShellCheck) and `python -m pytest` **untouched/green**. The **runner lands first, unwired (Phase 1)** — a behaviour-preserving building block — before the fire points are wired into the pass.

### Phase 1 — PREP (behaviour-preserving): the hook runner + config schema (unwired)

Prompt: `01_Hook_Runner_Prep.txt`

- Define the config schema (a list of `{command, when, enabled, description, timeout}` under the pfBlockerNG config). Implement `pfb_run_hooks(string $when, array $ctx)`: read enabled hooks matching `$when` in list order, build the env from `$ctx`, run each via `mwexec` with a per-hook timeout, capture output to the pfBlockerNG log with a header, **non-zero/timeout → log + continue**. **Not called from the pass yet.** Add a tiny CLI/manual invocation path for testing. PHPStan/ShellCheck clean; no behaviour change.

### Phase 2 — Wire pre + post fire points + context builder

Prompt: `02_Wire_Fire_Points.txt`

- In `sync_package_pfblockerng`: call `pfb_run_hooks('pre', $ctx)` at the **top** (ctx = trigger), and `pfb_run_hooks('post', $ctx)` at the **closing tail** (`:10293`) with ctx built from `$pfbupdate`/`$pfbpython`/`$pfb['filter_configure']`/`$cron` → `PFB_IP_CHANGED`/`PFB_DNSBL_CHANGED`/`PFB_STATUS`/`PFB_CHANGED_ALIASES`. **Additive:** no enabled hooks ⇒ no-op ⇒ byte-identical. Fires on cron + manual + force.

### Phase 3 — Settings UI (hooks table, admin-only)

Prompt: `03_Settings_UI.txt`

- An admin-only settings table: add/edit/enable/reorder/delete hook entries (command, when, description, timeout) with validation + help text documenting the env vars and the run-as-root caveat. Disambiguate the naming from the per-list `ip_pre_*.sh` pre-scripts (e.g. "Update Hooks" / "Pre/Post Update Commands").

### Phase 4 — HAProxy recipe + docs + manual smoke + DoD

Prompt: `04_Recipe_Docs_Smoke_DoD.txt`

- Document the worked **HAProxy recipe** (a `post` hook guarded on `PFB_IP_CHANGED`, the exact graceful-reload command, the `source_ip`-ACL + header-ACL config consuming the ADR-11 aggregate + never-empty file) in README/CLAUDE.md. Note the HA-sync behaviour. Finalise §7 manual smoke + reject criteria.

---

## 7. Definition of done

**Implementation status (2026-06-04): code + docs complete (Phases 1-4 landed on
`adr/12`); Status stays Proposed pending the maintainer live smoke below.**

- No enabled hooks ⇒ byte-identical update pass; with hooks, `pre`/`post` fire on all triggers with correct context; a failing/hanging hook is logged + timed out and the update continues. **(Done — `pfb_run_hooks` early-returns with no enabled hooks; `/usr/bin/timeout -s TERM -k 5 <to> /bin/sh -c …` kills a hung hook as a process group, non-zero/timeout log-and-continue. Phase 1.)**
- `php -l` + PHPStan + ShellCheck clean; `python -m pytest` untouched/green. **(Done — green every phase; ShellCheck N/A, no shell file shipped.)**
- The admin-only hooks UI works; help documents the env vars + run-as-root caveat; the HAProxy recipe is documented. **(Done — `pfblockerng_hooks.php` "Update Hooks" tab, Phase 3; env vars + recipe in `README.md`/`CLAUDE.md`, Phase 4.)**
- Status → **Accepted** only after the maintainer confirms the manual smoke below on a live pfSense box (including the HAProxy recipe end-to-end).

**Shipped context contract (what the code actually emits — the docs match this, not the §2 nominal):**

- `PFB_WHEN` = `pre` | `post` (always). `PFB_TRIGGER` ∈ **`cron` | `update` | `force-reload`** — the §2-nominal `force-update` **collapses to `cron`** (GUI Force Update and scheduled cron arrive with an identical `$cron` and are indistinguishable). `update` = a settings save; `force-reload` = a GUI IP-only / DNSBL-only Force Reload.
- post adds `PFB_IP_CHANGED` / `PFB_DNSBL_CHANGED` (`0`|`1`, **accurate** — derived from `$pfb['filter_configure']` and `$pfbupdate`/`$pfbpython`; these are the flags a recipe guards on).
- `PFB_STATUS` = `ok` and `PFB_CHANGED_ALIASES` = `''` are **stable reserved placeholders** today: no pass-wide error/partial accumulator or changed-alias list exists, and the ADR forbids inventing tracking machinery. The env-var **names** are stable and always present; **do not branch a recipe on their value**. A future phase may add real accumulation without changing the names.

### Reject / pivot criteria (decided)

- **Can't run hooks safely from the pass → NOT triggered.** The synchronous timed hook is safe: FreeBSD `/usr/bin/timeout` (no `--foreground`) signals the command **as a process group** and SIGKILLs after the `-k` grace, so a hung grandchild (e.g. `sleep 30`) is reaped at the deadline, the stdout pipe closes, `exec()` returns rc 124, and the runner logs "timed out … continuing". Output is captured via the file's established `exec("… 2>&1", …)` idiom (no log corruption). **No detached-exec pivot needed** (Phase 1 verdict). The `pre`/`post` points are unchanged.
- **HAProxy recipe can't be made hack-free → NOT triggered.** With ADR-11's never-empty `pfB_Aggregate_*` consumer file, the documented recipe validates and reloads with **no `/../../` path trick and no dummy-IP hack**: a `source_ip` ACL referencing the `pfB_Aggregate_v4` alias makes the HAProxy package emit/maintain `ipalias_pfB_Aggregate_v4.lst` (`haproxy.inc:1084-1092`), and `haproxy_check_run(1)` re-emits it on every reload even when the aggregate is empty. No residual to revisit. *(To be confirmed by the live smoke.)*

### Documented HAProxy reload command (the recipe's `post` hook)

```sh
[ "$PFB_IP_CHANGED" = "1" ] && echo 'require_once("haproxy/haproxy.inc"); haproxy_check_run(1);' | /usr/local/sbin/pfSsh.php
```

- **Graceful, not a hard restart.** `haproxy_check_run(1)` (`haproxy.inc:2491`; wrapped by `haproxy_configure()` `:1347-1350`) re-writes the config — re-emitting the `-f` ACL files including `ipalias_pfB_Aggregate_v4.lst` — and restarts with `-sf` (finish existing connections; hitless). The runtime socket is stats + hitless-reload only and cannot inject ACL data (`haproxy.inc:1562`), so a reload is the only way to refresh the list.
- **Why `pfSsh.php`, not `php -r`.** `haproxy.inc` opens with bare `require_once("functions.inc")` etc. that resolve via pfSense's PHP `include_path`; a plain `php -r` lacks that path. `/usr/local/sbin/pfSsh.php` bootstraps the pfSense env (`globals.inc`/`functions.inc`/`config.inc`/`util.inc`) and `eval`s PHP piped on stdin, so `require_once("haproxy/haproxy.inc")` and its dependency chain load. POSIX-sh-safe (single-quoted PHP, no shell metacharacter expansion). Runs on the node performing the update.

### Manual smoke (owner: maintainer) — required before Accept

> CI cannot run the update pass against pf/HAProxy. Run on a live pfSense CE box
> (the package's own validation is `php -l`/PHPStan/ShellCheck — there is no pytest
> oracle for this PHP/shell feature). Inspect results in the pfBlockerNG log
> (Status > System Logs, or `/var/log/pfblockerng`).
>
> **Now partly automated.** A live-VM smoke module — `tests/smoke/test_smoke_hooks.py`
> (ADR-04 harness; deploys the branch `.pkg` on a real pfSense CE VM, fires the hooks
> via the same `pfblockerng.php <verb>` CLI the GUI/cron use, and reads each hook's
> `/usr/bin/env` dump back from a `/tmp` marker on the guest) — now automates the
> no-op, pre/post fire+context, trigger values, IP/DNSBL-changed, and both safety
> (non-zero / timeout) items below. **HA sync** and the **HAProxy recipe end-to-end**
> stay maintainer-manual: the smoke image has neither a CARP pair nor the HAProxy
> package. The `PFB_TRIGGER=update` (`$cron=''`, settings-save) value is not reachable
> via any smoke `reload()` verb (GUI Force Update / a settings save map to `update` →
> `cron`), so it remains a manual-only check.

- [x] **No-op.** With no enabled hooks, an update behaves exactly as before (no hook-runner log lines; pass output unchanged). *(automated: `tests/smoke/test_smoke_hooks.py::test_hooks_noop_no_marker`; plus the enabled-flag branch in `test_hooks_disabled_entry_not_run_then_enabled_runs`.)*
- [x] **Pre/post fire + context.** Add a `pre` hook `command='env | grep ^PFB_'` and a `post` hook the same; run an update. `pre` logs `PFB_WHEN=pre` + `PFB_TRIGGER`; `post` logs `PFB_WHEN=post` + `PFB_TRIGGER` + `PFB_IP_CHANGED`/`PFB_DNSBL_CHANGED` (0|1) + `PFB_STATUS=ok` + `PFB_CHANGED_ALIASES=` (empty). Repeat across **scheduled cron** (`PFB_TRIGGER=cron`), **a settings save** (`update`), **GUI Force Update / Force Reload All** (also `cron`), and **GUI Force Reload of IP-only or DNSBL-only** (`force-reload`); confirm `PFB_IP_CHANGED`/`PFB_DNSBL_CHANGED` track what actually changed (e.g. an IP-only Force Reload that changes a table ⇒ `PFB_IP_CHANGED=1`). *(automated: `test_hooks_pre_and_post_fire_with_context` (pre-vs-post ctx + full env), `test_hooks_trigger_values` (`update`→`cron`, `updatednsbl`→`force-reload`), `test_hooks_ip_changed_reflects_pass` (IP pass ⇒ `PFB_IP_CHANGED=1`; DNSBL-only reload ⇒ `0` + `PFB_DNSBL_CHANGED=1`). Manual-only: the settings-save `PFB_TRIGGER=update` value, not reachable via a smoke verb.)*
- [x] **Safety — non-zero.** A `post` hook `command='exit 7'` is logged with its non-zero exit and the update **completes** (test the same as a `pre` hook). *(automated: `test_hooks_failing_hook_does_not_abort_update` — a non-zero `pre` hook runs but does not abort; the later `post` hook still fires.)*
- [x] **Safety — timeout.** A hook `command='sleep 30'` with `timeout=2` is killed (logged "timed out … continuing") and the update **completes** — verify both `pre` and `post`. *(automated: `test_hooks_timeout_killed_update_continues` — a `pre` hook is killed mid-run (marker has `START`, not `DONE`) and the `post` hook still fires.)*
- [ ] **HA sync** (maintainer-manual; no CARP pair on the smoke image). On a CARP pair, the hooks replicate to the secondary's config and run on whichever node performs the update (a hook with an external side effect runs once per updating node — expected).
- [ ] **HAProxy recipe end-to-end** (maintainer-manual; no HAProxy package on the smoke image). With ADR-11's `pfB_Aggregate_v4`, the recipe HAProxy config (a `source_ip` ACL on `pfB_Aggregate_v4` + a `req.hdr_ip(CF-Connecting-IP) -f …/ipalias_pfB_Aggregate_v4.lst` deny ACL, gated on a Cloudflare-range source ACL), and the documented `post` hook above: an IP update with `PFB_IP_CHANGED=1` fires the hook → graceful HAProxy reload → fresh `ipalias_pfB_Aggregate_v4.lst`; a request whose `CF-Connecting-IP` is in the aggregate is **denied** at HAProxy (and one not in it is **allowed** — assert both, before and after listing). An **empty** aggregate still validates and reloads (never-empty file). Confirm **no `/../../` path trick and no dummy-IP hack** is needed.
