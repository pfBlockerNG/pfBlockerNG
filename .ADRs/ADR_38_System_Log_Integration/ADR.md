# ADR-38: Integrated syslog export of pfBlockerNG security events

- **Status:** **Proposed** (2026-06-20)
- **Date:** 2026-06-20
- **Branch:** `adr/38-system-log-integration` (off `devel`; `{slug}` per CLAUDE.md "Branch naming")
- **Component(s):**
  - `src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc` — pure key=value formatter (IP side); the PHP syslog-emit helper; `PfbConfig` registry entries for the new fields
  - `src/usr/local/pkg/pfblockerng/pfblockerng.inc` — the filterlog daemon write site (`:9319-9324`) where IP Block/Permit/Match events are emitted
  - `src/usr/local/pkg/pfblockerng/pfb_unbound.py` — the DNSBL event write site; a stdlib `SysLogHandler` emitter (chroot-aware)
  - `src/usr/local/pkg/pfblockerng/pfblockerng.xml` (+ install/sync) — the pfSense package `<logging>` registration (facility, dedicated file, chroot log socket)
  - `src/usr/local/www/pfblockerng/pfblockerng_general.php` — the **Log Settings** UI section (enable + facility + severity controls)
  - `tests/php/`, `tests/` (pytest), `tests/smoke/` — formatter unit tests + live-VM behaviour
- **Target runtime:** PHP 8.3 (pfSense CE 2.8) for the IP side + package wiring; Python 3.11+ stdlib-only inside Unbound's chrooted python loader for the DNSBL side.
- **Test surface:** `vendor/bin/phpunit` + `vendor/bin/phpcs` + `vendor/bin/phpstan` + `python -m pytest` (PR gate); `tests/smoke` (ADR-04 live VM); `ui_render` (Tier A PR gate).

Originates from **issue #337** (Redmine #14878, *"Integrated syslog support"*) with **#380**
(Redmine #12097, *"Add dnsbl and geoip logs to system log … like Snort has a setting to enable
syslog"*) folded in as a duplicate. Organisations running a SIEM need pfBlockerNG's block/permit
events delivered to syslog, not only to local CSV files they must tail.

---

## 1. Context (today)

### 1.1 How pfBlockerNG logs now (measured, not assumed)

- **Security events are written to flat CSV files.** The PHP filterlog daemon
  (`pfb_daemon_filterlog()` in `pfblockerng.inc`) builds each IP Block/Permit/Match line and
  appends it (`pfblockerng.inc:9319-9324`):

  ```php
  @file_put_contents("{$iplog}", "{$log},{$details},{$dup_entry}\n", FILE_APPEND | LOCK_EX);
  // …and, for non-duplicates, the same line prefixed with the L_type to the unified log:
  @file_put_contents("{$pfb['unilog']}", "{$l_type},{$log},{$details},{$dup_entry}\n", …);
  ```

  The CSV fields are: timestamp, tracker ID, rule number, interface, action, IP version, then
  `dir,geoip,alias,ip_evaluated,feed,resolved_host,client_host,asn` and the protocol/addr/port
  group (built at `:9289-9317`), plus the `+`/`-` duplicate marker. **DNSBL** block events are
  written by the chrooted Unbound python module `pfb_unbound.py` as an 11-field CSV line
  (`DNSBL-python,timestamp,q_name,q_ip,p_type,b_type,group,b_eval,feed,dup,q_type`).
- **`logger()` already exists** (`pfblockerng_extra.inc:1424-1448`) wrapping PHP `syslog()` with a
  severity→prefix map and an optional facility OR-mask — but it is used **only for operational
  notices** (daemon start/stop, sync, errors), never for per-event export. There is no
  config-driven event export, no facility/server option.
- **Log rotation is already inode-stable** (#264 / ADR-30): `pfb_log_mgmt()` truncates in place
  (`tail -n N > tmp; cat tmp > file`) so the inode is preserved and a `(inode, offset)`-keyed
  shipper resumes rather than re-sending. So the reporter's *secondary* complaint (rotation replay
  duplicates) is **already fixed on `devel`**; the *primary* ask (export to syslog) is not.
- **Config access** for registered scalar fields is mediated by **`PfbConfig`** (ADR-29); new
  registered keys read via `PfbConfig::read()` / write via `PfbConfig::write()`, enforced by the
  `RequireConfigGateway` sniff. Log-related fields live in the **Log Settings** section of
  `pfblockerng_general.php` (`log_max_*`, `log_rotate_*`, `log_reset_keep_*` siblings).

### 1.2 How pfSense syslog works (the load-bearing platform facts — verified against core)

Verified against `pfSense/src/etc/inc/syslog.inc` (master) and Netgate docs:

1. **syslogd runs in secure mode (`syslogd -s`) — it does NOT listen on UDP.** A local sender
   therefore **cannot** ship via UDP to `127.0.0.1:514`; it must use a **unix datagram socket**.
2. **The default unix log socket is `/var/run/log`.** A **chrooted** process (Unbound →
   `/var/unbound`) resolves that to `/var/unbound/var/run/log`, which does **not** exist by
   default. pfSense adds extra sockets **only** via `-l <path>`, built from the hardcoded dhcpd
   chroot socket **plus** each package's declared `installedpackages/package/{k}/logging/logsocket`.
   So the **only** supported way to give the Unbound chroot a reachable log socket is the package
   `<logging><logsocket>` element.
3. **`/var/etc/syslog.d/*.conf` is auto-included** (`include /var/etc/syslog.d`). A package that
   declares a `<logging>` block (`facilityname` + `logfilename` [+ `logsocket`]) makes pfSense
   create `/var/log/<logfilename>`, write a `/var/etc/syslog.d/<logfilename>.conf` drop-in routing
   `!<facilityname>` (a **program/tag** filter) to that file, and add the tag to
   `$separatelogfacilities` so it is **excluded from the `system.log` catch-all** (no local dup).
4. **Remote forwarding of a package facility is NOT automatic for the granular categories.**
   pfSense's *Remote Logging* "Remote Log Contents" is a **fixed list** (Firewall, DNS, Auth, …);
   a package facility is not in it. **But the "Everything" (`*.*`) option forwards every facility,
   ours included** — appended in the main config before the `syslog.d` include, so our messages
   match both the remote `*.*` line and our local `!tag` file line.
5. **Facility map (verified):** core uses **`local3` (VPN)** and **`local5` (nginx/webGUI)**, and
   reserves **`local0`/`local4`/`local7`** (present in the `system.log` `local*.none` exclusion).
   That leaves **`local1`, `local2`, `local6`** genuinely free. RFC-3164 / UDP-514 is the only wire
   format core syslogd forwards (no RFC-5424, no TCP/TLS — that is syslog-ng-package territory).

### 1.3 How Snort/Suricata do it — and why only the UI shape ports

Snort's *"Send Alerts to System Log"* (`alertsystemlog` + `alertsystemlog_facility` +
`alertsystemlog_priority`, default `LOG_AUTH LOG_ALERT`) and Suricata's `suricata.yaml` `syslog`
output both rely on the **IDS engine's own native syslog output plugin**. **pfBlockerNG has no
engine/plugin host** — its events come from PHP, Python, and shell writing flat files — so the
Snort *mechanism* does not port. Only the **UI shape** ports (checkbox + facility select + severity
select). Snort's `LOG_AUTH` default is a known anti-pattern (it dumps IDS alerts into pfSense's
*Authentication* log); we deliberately avoid it.

### 1.4 Premise check (this is NOT an ADR-01-style bet)

No performance premise. The justification is **functional**: deliver security events to a SIEM via
the platform's own syslog. The risks to weigh are (a) the **chroot syslog reachability** for the
DNSBL/Python leg (§1.2.2) and (b) keeping the change **genuinely opt-in / zero default impact**.
Both are contained by the phasing (§6) and the pinned contract (§2.2). The §7 reject path covers
the case where the chroot leg cannot be made reachable without invasive change.

## 2. Decision

Add an **opt-in "Send security events to System Log"** feature: a single master toggle plus a
**facility** and **severity** selector, in the **Log Settings** section. When enabled, every
**security event** that is written to a local CSV file is **also emitted once to syslog** at
write-time — IP **Block / Permit / Match** events from the PHP filterlog daemon, and **DNSBL block**
events from the chrooted python module — tagged `pfblockerng`, in a **structured `key=value`**
message body. Local routing + `system.log` de-dup + the chroot log socket are provided by the
pfSense package **`<logging>`** registration; **remote** delivery is left entirely to pfSense's
existing *Remote Logging → Everything*, documented. The existing CSV files and the Reports/Alerts
UI are **unchanged** — syslog export is purely additive.

### 2.1 Per-area decision table

| Area | Decision |
| --- | --- |
| **Master toggle** | One registered key **`log_syslog`** (`'on'`/`''`, `PfbToggle` adapter, default `''`/off). Gates **all** event emission across PHP + Python. |
| **Facility** | Registered key **`log_syslog_facility`** (plain-string identity adapter), default **`log_local6`** (a free `localN` — §1.2.5). Full Snort-style vocabulary (`log_local0..7`, `log_daemon`, `log_user`, `log_auth`, …) so a SIEM admin can move us off a slot they already use. |
| **Severity** | Registered key **`log_syslog_priority`** (plain-string identity), default **`log_notice`**. Snort-style vocabulary (`log_emerg`…`log_debug`). Single configurable severity for all events (matches Snort). |
| **Message format** | **Structured `key=value`**, space-separated, stable keys (e.g. `act=block dir=in if=em0 proto=TCP src=… dst=… sport=… dport=… ipver=4 geoip=US alias=pfB_… feed=… host=… asn=…` for IP; `act=dnsbl qname=… qip=… qtype=A group=… feed=… btype=VIP eval=…` for DNSBL). Built by **pure formatters** from the same fields the CSV line is built from, so the two cannot drift. Values with spaces/`=` are quoted/escaped; never multi-line. |
| **Tag / ident** | `openlog()` ident **`pfblockerng`** (PHP) and `SysLogHandler` ident **`pfblockerng`** (Python) — the real on-box identity the `<logging>` `!pfblockerng` filter keys on. |
| **PHP emit** | A small helper `pfb_syslog_event(string $msg)` in `pfblockerng_extra.inc` — `openlog('pfblockerng', LOG_PID, <facility>)` (facility/severity resolved once from `PfbConfig`) then `syslog(<severity>, $msg)`. Called at the filterlog write site (`pfblockerng.inc:9319-9324`) **only when `log_syslog` is on**, once per event line. |
| **Python emit** | A module-level `logging.handlers.SysLogHandler(address='/var/run/log', facility=<n>)` (resolves inside the chroot to the package log socket from §1.2.2), created once, gated by a new `py_unbound.ini` boolean + facility/severity values written by the PHP side at config-build time. Emitted at the DNSBL CSV write site. Persistent socket ⇒ one `sendto()` per event (hot-path safe). |
| **Local routing + chroot socket** | A pfSense package **`<logging>`** block in `pfblockerng.xml`: `<facilityname>pfblockerng</facilityname>`, `<logfilename>pfblockerng_syslog.log</logfilename>`, `<logsocket>/var/unbound/var/run/log</logsocket>`. Gives the dedicated local file, the `system.log` de-dup, and (critically) the `-l` chroot socket the python leg needs. Install/sync ensures `/var/unbound/var/run` exists before syslogd (re)starts. |
| **Remote delivery** | **None in-package.** Rely on pfSense *Status → System Logs → Settings → Remote Logging → "Everything"*, which forwards our facility automatically (§1.2.4). Documented in help text + the manual checklist. (A self-managed `@server` drop-in for granular setups is **out of scope** — §2.3.) |
| **Existing CSV files / Reports** | **Unchanged.** Export is additive; nothing about the flat files, `pfb_log_mgmt()`, or Reports/Alerts parsing changes. |

### 2.2 Semantics that MUST be preserved (the contract — pin with tests before wiring)

1. **Default off ⇒ no event export, no behaviour change to existing logging.** With `log_syslog`
   off, **zero** syslog event records are emitted by PHP or Python; the CSV files, `pfb_logger()`,
   the existing operational `logger()` notices, and `system.log` are byte-for-byte as today. (The
   inert `<logging>` registration footprint — an empty `pfblockerng_syslog.log`, an unused log
   socket, and a `!pfblockerng` exclusion that matches nothing while off — is the single, explicitly
   accepted exception; see §3 / §2.4.)
2. **On ⇒ exactly one syslog record per exported event line, no drop / no duplicate**, carrying the
   configured facility + severity, tag `pfblockerng`, and the `key=value` body.
3. **CSV ↔ key=value cannot drift:** both are produced from the same source fields; a formatter test
   pins the mapping for every event class (Block/Permit/Match, IPv4/IPv6, DNSBL VIP/NULL).
4. **No regression on the DNSBL hot path:** the python emitter uses a persistent socket; a failed/
   unavailable socket must **degrade silently** (never raise into Unbound, never block resolution).
5. **Config round-trips through `PfbConfig`** (`write(read(v)) == v` for every vocabulary value;
   absent ⇒ documented default), and emits only legacy-safe stored tokens (ADR-29 rollback).

### 2.3 Explicitly kept / out of scope

- **Operational logs** (`pfblockerng.log`, error/extras, parse-error, dns_reply) — **not** exported.
  Scope is *security events* only (Block/Permit/Match + DNSBL blocks), matching Snort's "alerts".
- **A pfBlockerNG-owned remote-server config** (host/port/protocol) and a **self-managed `@server`
  syslog.d drop-in** for non-"Everything" setups — out of scope; remote is delegated to pfSense.
- **RFC-5424 / TCP / TLS** transport — not offered by core syslogd; out of scope (syslog-ng package
  territory).
- **JSON-in-message** / per-event severity mapping — deferred; `key=value` + one severity chosen for
  SIEM-parseability at the lowest maintenance cost across the PHP+Python emitters.
- **Shell-side events** — `pfblockerng.sh` produces no per-event security records; nothing to export.
- The **CSV files, rotation, and Reports/Alerts** — untouched.

### 2.4 Alternatives considered (and why rejected)

- **Native engine plugin (the Snort/Suricata mechanism):** impossible — pfBlockerNG has no engine
  with a syslog output plugin (§1.3). Only the UI shape is borrowed.
- **Tail the existing CSV files into syslog via a syslog.d drop-in (the reporter's mental model):**
  syslogd does **not** ingest arbitrary flat files — a drop-in only routes *emitted* syslog
  messages. Tailing would require a separate shipper (syslog-ng/Telegraf) — exactly the fragile
  workaround the reporters want to avoid. Emit-at-write-time is the only first-class path.
- **UDP to `127.0.0.1:514` from python:** impossible — `syslogd -s` (secure mode) does not listen on
  UDP (§1.2.1). The chroot unix socket via `<logging><logsocket>` is the supported route.
- **A pfBlockerNG-owned remote-server option:** duplicates pfSense's Remote Logging config and
  re-implements server/IPv6 handling for no benefit over "Everything"; rejected for v1 (§2.3).
- **Strictly zero footprint when off (no static `<logging>`):** would deny the python leg its chroot
  socket (only the static element installs the `-l` socket). Accepted the small inert footprint
  instead (§2.2.1).

## 3. Consequences

**Positive**

- The #337/#380 ask is delivered through the platform's own syslog: events reach a SIEM via pfSense
  *Remote Logging → Everything* with no per-app server config and no file-tailing.
- Opt-in + default-off ⇒ no surprise for existing installs.
- A dedicated `local6`/`pfblockerng` stream keeps events out of `auth`/`system.log` — no Snort-style
  Auth-log pollution; a clean, isolatable SIEM bucket.
- `key=value` is SIEM-parseable and stable across the heterogeneous CSV layouts; the pure formatters
  are fully unit-tested and shared with the CSV source fields (no drift).
- Rotation duplicate concern is already neutralised (#264/ADR-30); emit-at-write-time sidesteps
  file-tailing entirely.

**Negative / risks**

- **Inert-when-off footprint:** the static `<logging>` registration creates an empty
  `pfblockerng_syslog.log`, a log socket under `/var/unbound/var/run`, and a `system.log` exclusion
  for the `pfblockerng` tag even when the toggle is off. Judged negligible and idiomatic (every
  pfSense package that logs registers this way); called out in §2.2.1 and the smoke contract.
- **Chroot socket dependency:** the python leg only works if syslogd was (re)started after the
  `<logging><logsocket>` was registered and `/var/unbound/var/run` exists. Install/sync must order
  this; the live-VM smoke proves it. Fallback if unreachable: degrade silently (contract §2.2.4) and,
  if ultimately intractable, ship IP-events-only in v1 (reject path §7).
- **Remote requires "Everything":** an admin forwarding only granular categories will not get our
  facility. Documented; the granular self-forward is a deferred enhancement (§2.3).
- A modest config + UI surface (3 keys, 3 controls) — contained by the existing Log Settings pattern.

## 4. Requirements (acceptance)

- A **"Send security events to System Log"** toggle + **Facility** + **Severity** selectors in
  **Firewall → pfBlockerNG → General → Log Settings**, default **off / `local6` / `notice`**,
  persisted across upgrade (round-trips through `PfbConfig`).
- With it **on**: each IP Block/Permit/Match event and each DNSBL block event emits exactly one
  syslog record (tag `pfblockerng`, configured facility/severity, `key=value` body), landing in the
  dedicated local log and — when pfSense Remote Logging "Everything" is set — at the remote server.
- With it **off**: no event records are emitted; existing logging is unchanged.
- The CSV files + Reports/Alerts are unchanged in both states.
- All gates green; the §2.2 contract pinned by tests; live-VM smoke green (CE + Plus) for on/off
  branch coverage of both the IP and DNSBL legs.

## 5. Constraints (from CLAUDE.md)

- **PHP** 8.3, tabs, uppercase `TRUE`/`FALSE`, no `die()/exit()` in library code; new registered
  fields go through **`PfbConfig`** (ADR-29) — registry entry + `since` + sniff `$registeredPaths` +
  `CfgGatewayTest`/`RollbackContractTest`/inventory.
- **Python** 4-space, 3.11+, `from __future__ import annotations`, **stdlib only** inside Unbound's
  loader, no bare `except`; injected Unbound symbols stay in `stubs/python/`.
- **Naming** follows the Log Settings neighbours (`log_*` prefix).
- **Test-coverage mandate:** every branch (toggle on/off, each event class, IPv4/IPv6, DNSBL
  VIP/NULL), assert before-and-after, no coverage theater.
- ADR implementation uses the **full worktree + rebase-only-PR flow** (touches `src/` + `tests/`).
  ADR text/prompts are committed on this branch directly (managed-remote: the pinned session branch
  replaces the canonical `adr/38-…` name; see the §6 note).

## 6. Action plan

> Each phase is one commit, leaves `python -m pytest` + `vendor/bin/phpunit` green, and is
> behaviour-preserving until the wiring phases flip the (default-off) feature on. The early phases
> are the preparatory, test-first, dormant-code groundwork; the risky chroot/python wiring lands only
> after the pure formatters and the config field are pinned and the (chroot-free) PHP leg is proven.
>
> **Managed-remote branch note:** under a hard-pinned push policy the implementation lands on the
> session's `claude/*` branch, which **replaces** the canonical `adr/38-system-log-integration` name;
> record the `ADR-RESUME:` sentinel in `RESULTS/01_Results.txt` per CLAUDE.md. Where the push policy
> allows the canonical branch, `/adr-phase` uses `adr/38-system-log-integration` as normal.

### Phase 1 — Pure key=value formatters + unit tests (dormant)

- Prompt: `01_Formatters.txt`
- Add `pfb_syslog_format_ip(...)` to `pfblockerng_extra.inc` (PHP) and `syslog_format_dnsbl(...)` to
  `pfb_unbound.py` (Python) — pure functions mapping the existing event source fields to the stable
  `key=value` string (quote/escape values with spaces/`=`; never multi-line). No emission yet.
- Tests: PHPUnit `tests/php/SyslogFormatTest.php` + pytest `tests/test_syslog_format.py` — every
  event class (Block/Permit/Match, IPv4/IPv6, DNSBL VIP/NULL), empty/odd fields, escaping. Functions
  dormant (uncalled) ⇒ behaviour-preserving.

### Phase 2 — Register the config fields (dormant)

- Prompt: `02_Config_Fields.txt`
- Register `log_syslog` (toggle, default `''`), `log_syslog_facility` (plain, default `'log_local6'`),
  `log_syslog_priority` (plain, default `'log_notice'`) in `pfb_cfg_registry()` (Log Settings
  section, `since` = current devel series); add their paths to the sniff `$registeredPaths`; extend
  `CfgGatewayTest` (round-trip + default-absent), `RollbackContractTest` (vocabulary), and the
  inventory test. Add a pure facility/severity token→constant map helper (e.g. `log_local6` →
  `LOG_LOCAL6`) with its own unit test. Dormant — no reader/writer wired.

### Phase 3 — Package `<logging>` registration + PHP IP-leg emit (flips IP export on, default-off)

- Prompt: `03_Php_Leg_And_Logging.txt`
- Add the `<logging>` block (facility/logfile/logsocket) to `pfblockerng.xml`; ensure
  `/var/unbound/var/run` exists and syslogd is (re)started on install/sync (idempotent).
- Add `pfb_syslog_event()` (openlog ident `pfblockerng` + facility/severity from `PfbConfig`) and
  call it at `pfblockerng.inc:9319-9324`, gated by `PfbConfig::read('log_syslog')`, once per event
  line, using the Phase-1 formatter. Keep PFBL-01 + `RequireConfigGateway` sniffs green.
- Tests: extend the PHP suite to assert the emit helper is invoked iff the toggle is on (mock
  `syslog`/`openlog` via the doubles), with the formatted body. **This flips the IP leg on
  (default-off).**

### Phase 4 — DNSBL/python leg over the chroot socket (flips DNSBL export on, default-off)

- Prompt: `04_Python_Leg.txt`
- Write the new syslog ini keys (enable/facility/severity) into `py_unbound.ini` at config-build
  time (PHP side). In `pfb_unbound.py`, create a module-level `SysLogHandler(address='/var/run/log',
  facility=<n>)` once when enabled, emit the Phase-1 `key=value` body at the DNSBL CSV write site,
  and **degrade silently** on any socket error (contract §2.2.4). Resolve + document the chroot
  socket reachability; add the injected-symbol/stub note if needed.
- Tests: pytest asserts the emitter fires iff enabled and is a no-op (no raise) when the socket is
  absent; the body matches the formatter. **This flips the DNSBL leg on (default-off).**

### Phase 5 — Log Settings UI controls

- Prompt: `05_Ui.txt`
- Add the **enable** checkbox + **Facility** select + **Severity** select to the Log Settings section
  of `pfblockerng_general.php`, loaded/saved through `PfbConfig`, with brief help text (note: remote
  delivery uses pfSense *Remote Logging → Everything*; default facility `local6`). `ui_render` proof
  (200, no PHP error, controls present).

### Phase 6 — Smoke + docs + acceptance

- Prompt: `06_Smoke_And_Docs.txt`
- Live-VM smoke (ADR-04): enable the toggle, trigger an IP block **and** a DNSBL block, assert one
  `pfblockerng`-tagged `key=value` record per event in the dedicated local log with expected fields;
  assert **off ⇒ no records** (before/after branch coverage); assert the existing CSV files still get
  their lines in both states. Add the §7 manual checklist (real remote SIEM via "Everything"); update
  user-facing help/docs. Flip Status → Accepted on green.

## 7. Definition of done

- All six phases landed; `vendor/bin/phpunit` + `phpcs` + `phpstan` + `python -m pytest` +
  `ui_render` green; the §2.2 contract pinned by tests.
- Live-VM smoke (CE + Plus fan-out) green for: on ⇒ IP event exported, on ⇒ DNSBL event exported,
  off ⇒ neither exported, CSV files unchanged in both states.
- **Manual smoke checklist (owner: maintainer — out-of-CI, real SIEM):**
  1. Enable the feature (facility `local6`); on a receiver (rsyslog/syslog-ng) filtering `local6.*`,
     confirm IP Block/Permit/Match + DNSBL block events arrive as `pfblockerng` `key=value` records.
  2. Set pfSense *Remote Logging → Everything* to a remote syslog server; confirm the same records
     arrive remotely; confirm they do **not** pollute the *Authentication* log.
  3. Toggle off; confirm export stops and local CSV logging continues unchanged.
  4. Change the facility to another `localN`; confirm the receiver-side filter follows.

**Reject criteria.** Abandon/redesign if: (a) the chrooted python leg cannot reach syslogd via the
`<logging><logsocket>` socket without invasive pfSense changes **and** no acceptable in-chroot
fallback exists — then ship **IP-events-only** in v1 and track the DNSBL leg separately; or (b) the
feature cannot be made genuinely opt-in / zero-default-impact beyond the accepted inert `<logging>`
footprint; or (c) emit-at-write-time measurably regresses DNS resolution latency on the DNSBL path.

### Maintainer acceptance steps (live-VM fan-out — dispatched via `smoke-fanout.yml`)

Phase 6 lands `tests/smoke/test_syslog_export.py` (`pytest.mark.smoke`). Status flips to **Accepted**
when `smoke-fanout.yml` runs green on the merged `devel` tip across the full CE + Plus matrix. The §7
manual checklist covers the real remote-SIEM path CI cannot fully simulate — run it post-accept.
