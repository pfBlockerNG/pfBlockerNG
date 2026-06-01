# ADR-02: Drop the non-Python (native Unbound) DNSBL mode

- **Status:** **IMPLEMENTED (pending smoke test)** (2026-05-31) — Phases 1–5 complete on branch `edge`; code is Python-only DNSBL with auto-migration. Acceptance is blocked on the manual smoke test (§7 / `RESULTS/05_Results.txt`), which cannot be automated (no live Unbound in CI).
- **Date:** 2026-05-31
- **Component:** DNSBL subsystem — PHP glue (`pfblockerng.inc`, `pfblockerng_install.inc`), Web UI (`pfblockerng_dnsbl.php`, `pfblockerng_alerts.php`, `pfblockerng.widget.php`), shell (`pfblockerng.sh`); the Python plugin (`pfb_unbound.py`) is barely touched.
- **Target runtime:** pfSense CE 2.8 (PHP 8.3, FreeBSD 15), Unbound `pythonmod` + embedded Python 3.11+.

---

## 1. Context

DNSBL blocking has shipped in two implementations:

1. **Native Unbound mode** — domains are written into Unbound as `local-zone` / `local-data` entries (`pfb_dnsbl.conf`); Unbound itself answers blocked queries with the DNSBL VIP, and a separate PHP **`queries` daemon** tails the Unbound query log to produce DNSBL alerts.
2. **Unbound Python mode** — `pfb_unbound.py` (loaded via `python_enable` in the resolver config) performs matching per query and returns the DNSBL VIP (→ lighttpd block page + logging) or a null/NXDOMAIN answer. This is the modern path; ADR-01 work pinned its matcher semantics with tests.

### The mode isn't one flag — it's two keys collapsing into one boolean

Config keys (`installedpackages/pfblockerngdnsblsettings/config/0`):

- `dnsbl_mode` ∈ { `dnsbl_unbound`, `dnsbl_python` }
- `pfb_py_block` ∈ { `on`, off }

Resolved in `pfblockerng.inc` (~L844–863):

```php
$pfb['dnsbl_py_blacklist'] = ($pfb['dnsbl_mode'] == 'dnsbl_python' && $pfb['dnsbl_py_block'] == 'on');
```

`dnsbl_py_blacklist` is the **real switch**: TRUE ⇒ Python does the blocking; FALSE ⇒ Unbound-native blocking. There are therefore **three** states today, not two:

| State | `dnsbl_mode` | `pfb_py_block` | `dnsbl_py_blacklist` | Who blocks |
| --- | --- | --- | --- | --- |
| 1 | `dnsbl_unbound` | n/a | FALSE | Unbound (native) |
| 2 | `dnsbl_python` | off | FALSE | Unbound (native); py loaded only for DNS-reply logging |
| 3 | `dnsbl_python` | on | TRUE | **Python** ← the only state we keep |

States 1 and 2 share **all** native-blocking code, gated throughout by `!$pfb['dnsbl_py_blacklist']` (~50 sites in `pfblockerng.inc`, more in `pfblockerng_alerts.php`).

### Motivation

Python mode is now fast and correct (ADR-01 hardened and benchmarked the matcher). Maintaining the native path doubles the surface of nearly every DNSBL code site, keeps a second blocklist file format (`local-zone`/`local-data`) and a log-tailing daemon alive, and forces every UI/alert site to branch on mode. The native path no longer earns its keep.

---

## 2. Decision

**If DNSBL is enabled, the only implementation is the Unbound Python integration.** Remove the native Unbound DNSBL mechanism entirely, remove the mode selector and the `pfb_py_block` sub-toggle, and auto-migrate existing installs. After this ADR, `dnsbl_py_blacklist` is effectively a constant TRUE and is removed as a variable.

### The safe deletion rule (load-bearing — apply literally)

> Delete **only**: (a) code reachable solely on the FALSE side of `$pfb['dnsbl_py_blacklist']`, and (b) the pure-native artifacts — the `local-zone`/`local-data` conf format, its shell builder, and the `queries` log-tailing daemon. Keep everything that is unconditional or on the TRUE side.

Concretely:

- `dnsbl_py_blacklist` becomes always-true ⇒ every `if (!$pfb['dnsbl_py_blacklist']) { … }` block is **dead** (delete it); every `if ($pfb['dnsbl_py_blacklist'])` becomes **unconditional** (unwrap it); every ternary `X ? py : native` collapses to `py`.

### What is removed

| File | Removed |
| --- | --- |
| `pfblockerng_dnsbl.php` | `dnsbl_mode` `Form_Select` + `$options_dnsbl_mode`; `pfb_py_block` `Form_Checkbox`; `.dnsbl_unbound_tld` infoblocks + their JS show/hide; the TLD **Whitelist** UI; `dnsbl_mode => 'dnsbl_unbound'` validation default; POST handling for both removed fields. |
| `pfblockerng.inc` | the `dnsbl_mode`/`pfb_py_block`/`dnsbl_py_blacklist` reads (replace with constant true at the keystone); all `!$pfb['dnsbl_py_blacklist']` branches; `pfb_dnsbl.conf` (`.conf`) `local-zone`/`local-data` generation; unbound-mode `safesearch`/`youtube`/`doh` `.conf` writes (the py path writes its own data); the `queries` daemon launch in `pfb_dnsbl_service()` (~L1038) and the `pfb_dnsbl_parse('daemon', …)` log-tailing path; live-update-without-reload (`dnsbl_sync` / `dnsbl_livesync`, FALSE-side only). |
| `pfblockerng.sh` | `domaintld()` (native `local-zone`/`local-data` builder) and any native-only TLD-remove plumbing it owns; **keep** `domaintldpy()`. |
| `pfblockerng_alerts.php` | every `dnsbl_mode == 'dnsbl_python'` guard becomes unconditional; every `!$pfb['dnsbl_py_blacklist']` branch/ternary collapses to the py side (column titles, "DNSBL Webserver/VIP" labels, suppression handling, agent vs blocking-type, etc.). |
| `pfblockerng.widget.php` | `dnsbl_mode == 'dnsbl_python'` guards become unconditional. |
| `pfblockerng_install.inc` | **add** the config migration (see §6). |
| `pfb_unbound.py` | near-zero — see "kept" note below. |

### What is explicitly KEPT (do NOT delete — common traps)

- **lighttpd webserver, DNSBL VIP, NAT rules, `pfb_dnsbl` service** — these are **not** native-only. Python blocking returns the DNSBL VIP, so the browser still hits lighttpd for the block page and for event logging (unless null-blocking or `pfb_py_nolog`). `pfb_create_lighttpd()` stays.
- **`pfb_tld` / `$pfb['dnsbl_tld']` (Wildcard Blocking TLD)** — used in **both** modes (e.g. `pfblockerng.inc` ~L8895 sits inside the `dnsbl_py_blacklist` TRUE branch). Only the TLD **Whitelist** (the `tld_seg` / `dnsbl_tld_remove` consolidation surfaced by `.dnsbl_unbound_tld`) is native-specific. Keep the wildcard-blocking feature; remove only the whitelist UI/plumbing tied to the native consolidation.
- **`pfb_py_reply` (DNS-reply logging), `pfb_py_nolog`, `pfb_noaaaa`, `pfb_pytld`, `pfb_hsts`, `pfb_cname`, `pfb_gp`, `pfb_regex`, `pfb_control`** — Python-mode features; keep.
- **`python_blocking` `.ini` key** — `pfb_unbound.py` reads it (default `False`, L306). PHP must keep emitting `python_blocking = on` unconditionally, or the plugin would block nothing. (Alternatively flip the py default to True and drop the option — a larger py change; default to the minimal "always emit on".)

---

## 3. Consequences

**Positive**

- One DNSBL code path. ~50 `!dnsbl_py_blacklist` branches and a parallel blocklist file format disappear; the `queries` log-tailing daemon and its parser disappear.
- UI/alerts stop branching on mode → simpler pages, fewer states to reason about and test.
- Removes a class of "works in one mode, broken in the other" bugs.

**Negative / risks**

- **No automated PHP tests** in this repo. Correctness of the deletion is verified by `intelephense`/lint and **manual smoke on a live pfSense box** (`scripts/deploy.sh`). The smoke checklist (§7) is therefore non-negotiable.
- **Config migration must be idempotent and safe** for the population currently on `dnsbl_unbound` (or `dnsbl_python` + `pfb_py_block=off`). A botched migration silently changes blocking behavior on upgrade.
- Risk of over-deletion: removing something on the TRUE side or an unconditional dependency (lighttpd/VIP, `pfb_tld`). Mitigated by the §2 deletion rule and the "kept" list.
- Large multi-file diff; review in phases.

---

## 4. Action plan (recommended order)

Each phase is an independent commit that leaves the package installable and `python -m pytest` green (the py suite barely moves). **Phase 1 is the keystone**: pin the switch to TRUE first, so the package becomes Python-only behaviorally while the native branches go dead-but-present. Phases 2–5 are then mechanical dead-code deletion that can be reviewed in isolation.

### Phase 1 — Keystone: force Python + migrate config

Prompt: `01_Keystone_Force_Python.txt`

- `pfblockerng_install.inc`: add migration — rewrite `dnsbl_unbound` → `dnsbl_python`, set `pfb_py_block = on`, drop the now-meaningless keys; idempotent; follows the existing VIP-migration precedent (`pfblockerng_install.inc` L35–106).
- `pfblockerng.inc`: at the keystone read (~L844–863), hard-set `$pfb['dnsbl_mode'] = 'dnsbl_python'` and `$pfb['dnsbl_py_blacklist'] = TRUE` (still emit `python_blocking = on`). No branch deletion yet.
- Result: every install behaves as state 3; native branches are unreachable but still in the tree.

### Phase 2 — Web UI: remove the selector + native-only controls

Prompt: `02_UI_Remove_Toggle.txt`

- `pfblockerng_dnsbl.php`: remove `dnsbl_mode` select, `$options_dnsbl_mode`, `pfb_py_block` checkbox, `.dnsbl_unbound_tld` infoblocks + JS, TLD-Whitelist UI, validation default, and POST handling for the removed fields.

### Phase 3 — Core: delete native blocking + the queries daemon

Prompt: `03_Core_Remove_Native.txt`

- `pfblockerng.inc`: collapse all `dnsbl_py_blacklist` branches per the §2 rule; delete `pfb_dnsbl.conf` `local-zone`/`local-data` generation, native safesearch/youtube/doh `.conf` writes, the `queries` daemon launch and `pfb_dnsbl_parse('daemon',…)`, and native-only `dnsbl_sync`/`dnsbl_livesync`. Keep lighttpd/VIP/NAT and `pfb_tld`. Remove the `dnsbl_py_blacklist` variable itself.

### Phase 4 — Shell: drop the native conf builder

Prompt: `04_Shell_Remove_domaintld.txt`

- `pfblockerng.sh`: delete `domaintld()` and native-only TLD-remove plumbing; keep `domaintldpy()`. Update any PHP call sites/arguments that selected the native builder. ShellCheck clean (POSIX sh).

### Phase 5 — Alerts/widget + finalize

Prompt: `05_Alerts_Widget_Finalize.txt`

- `pfblockerng_alerts.php` + `pfblockerng.widget.php`: collapse mode guards to unconditional. Ensure PHP still emits `python_blocking = on`. Update `README.md` if any workflow/min-version text references the modes; sweep for stray `dnsbl_unbound` / `pfb_py_block` references package-wide. `python -m pytest`, `ruff`, ShellCheck, and intelephense clean.

---

## 5. Constraints (from `CLAUDE.md`)

- **PHP**: tabs; PHP 8.3; no `die()`/`exit()` in library code; pfSense functions come from `stubs/pfsense/` — add new ones there rather than expanding suppressions.
- **Shell**: POSIX `sh` only (no bash-isms); quote all expansions; absolute binary paths; ShellCheck clean (`.shellcheckrc` covers SC1091/SC2154 only).
- **Python**: 4-space; stdlib only; run `python -m pytest` + `ruff check .` / `ruff format .` after any `pfb_unbound.py`/`tests/` change.
- **Commits**: `<scope>: <imperative summary>`, no trailing period; land on `devel`. Push directly to `devel`; open a PR only if the push is rejected by branch protection. PR bodies via `--body-file`.
- **Docs**: update `README.md` only if a workflow/min-version/tooling fact changes.

---

## 6. Config migration (Phase 1 detail)

Existing installs may hold:

- `dnsbl_mode = dnsbl_unbound` (state 1), or
- `dnsbl_mode = dnsbl_python` + `pfb_py_block` ≠ `on` (state 2).

On package upgrade, in `pfblockerng_install.inc` (idempotent, guarded so it no-ops on already-migrated configs):

- set `dnsbl_mode = dnsbl_python`;
- set `pfb_py_block = on`;
- optionally drop keys that only ever fed the native path (TLD-Whitelist settings), leaving the wildcard-blocking `pfb_tld` intact;
- `write_config('pfBlockerNG: migrated DNSBL to Python-only mode')` and trigger the standard DNSBL rebuild so the resolver config and python data files regenerate.

A force-reload is required after migration (the resolver config flips from `local-zone` blocking to `python_enable` blocking).

---

## 7. Definition of done

- Mode selector and `pfb_py_block` toggle gone from the UI; no `dnsbl_unbound` / `pfb_py_block` / `dnsbl_py_blacklist` references remain package-wide (grep clean).
- Native `pfb_dnsbl.conf` generation, `domaintld()`, and the `queries` daemon removed; lighttpd/VIP/NAT and `pfb_tld` retained.
- Migration converts both legacy states to Python-only and no-ops on re-run.
- `python -m pytest` green; `ruff` / ShellCheck / intelephense clean.
- Status moved to **Accepted** after the manual smoke below passes on a live box.

### Manual smoke test (owner: **maintainer** — no live Unbound in CI)

Deploy via `scripts/deploy.sh`, then on a clean install **and** on a box upgraded from `dnsbl_unbound`:

- [ ] **Upgrade migration:** box previously on `dnsbl_unbound` → after upgrade, DNSBL is enabled, Python integration is active (`python_enable` in resolver config), and blocking still works without manual intervention.
- [ ] **Exact block:** query a domain that is an exact DNSBL entry → blocked (DNSBL VIP response) and logged via the webserver.
- [ ] **Wildcard block:** query a subdomain of a wildcard/zone entry → blocked.
- [ ] **Whitelist:** a whitelisted domain (and a `www.` case) resolves normally.
- [ ] **TLD wildcard blocking (`pfb_tld` on):** still consolidates/blocks correctly in Python mode (confirms we kept the right TLD code).
- [ ] **DNS-reply logging (`pfb_py_reply` on) and `pfb_py_nolog`:** both still log as expected.
- [ ] **Alerts UI + widget:** DNSBL alerts render (blocking-type column, VIP labels) with no PHP notices; unblock/whitelist actions work.

Once all pass, set **Status: Accepted** and record results in `RESULTS/`.
