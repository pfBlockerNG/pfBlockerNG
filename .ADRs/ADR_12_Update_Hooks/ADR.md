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

- No enabled hooks ⇒ byte-identical update pass; with hooks, `pre`/`post` fire on all triggers with correct context; a failing/hanging hook is logged + timed out and the update continues.
- `php -l` + PHPStan + ShellCheck clean; `python -m pytest` untouched/green.
- The admin-only hooks UI works; help documents the env vars + run-as-root caveat; the HAProxy recipe is documented.
- Status → **Accepted** only after the maintainer confirms the manual smoke below on a live pfSense box.

### Reject / pivot criteria (decide cheaply)

- **Can't run hooks safely from the pass:** if a synchronous timed hook can still hang or destabilise the update (e.g. `mwexec` timeout doesn't reliably kill a child, or output handling corrupts the log) → pivot to **detached** execution (fire-and-forget with output to a side log) or reconsider the post fire point. Settle in Phase 1/2 before the UI.
- **HAProxy recipe can't be made hack-free:** if, given ADR-11's never-empty file, the documented recipe still needs the `/../../` + dummy-IP hacks to validate/reload → record the residual and (optionally) revisit the upstream HAProxy-package contribution; the generic hook still ships.

### Manual smoke (owner: maintainer) — required before Accept

> CI cannot run the update pass against pf/HAProxy. Run on a live pfSense CE box.

- [ ] **No-op.** With no enabled hooks, an update behaves exactly as before.
- [ ] **Pre/post fire + context.** A `pre` hook logging its env shows `PFB_TRIGGER`; a `post` hook shows correct `PFB_IP_CHANGED`/`PFB_DNSBL_CHANGED`/`PFB_STATUS`/`PFB_CHANGED_ALIASES` across cron, manual Update, and Force Reload.
- [ ] **Safety.** A hook that exits non-zero is logged and the update completes; a hook that sleeps past its timeout is killed and the update completes — pre and post.
- [ ] **HA sync.** On a CARP pair, the hooks replicate and run on whichever node performs the update.
- [ ] **HAProxy recipe end-to-end.** With ADR-11's `pfB_Aggregate_v4` and the recipe config, an IP update fires the `post` hook → graceful HAProxy reload → fresh `ipalias_pfB_Aggregate_v4.lst`; a request whose CF-forwarded client IP is in the aggregate is denied at HAProxy; an empty aggregate still validates (never-empty file). No `/../../`/dummy-IP hack needed.
