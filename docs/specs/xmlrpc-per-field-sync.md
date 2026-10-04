# Per-field pfBlockerNG XMLRPC sync

This specification resolves wayfinder map
[Map: per-field XMLRPC sync with policy and node-local scopes (4.0)](https://github.com/pfBlockerNG/pfBlockerNG/issues/3443),
which carries option D of [#3441](https://github.com/pfBlockerNG/pfBlockerNG/issues/3441) to `devel`.
`release/3.3` keeps option B ([#3442](https://github.com/pfBlockerNG/pfBlockerNG/issues/3442)).
Package references are to `devel` at `ac5abbed`; pfSense references are to `pfsense/pfsense`
`master` at `9363ac5b`.

## Goal

Synchronize pfBlockerNG policy from the sending firewall to its peers while every peer keeps its
own interfaces, VIPs, listener ports, gateways, scripts, credentials, runtime markers, and
presentation settings. A policy change, including a deletion, takes effect on the receiver after
one receive. A repeated receive changes nothing. An older peer never receives a partial section.
Both nodes report when their policy, or the `pfB_*` objects pfSense HA copies between them,
disagree.

## Fixed constraints

- `devel`/4.0 only. The per-field scope is used only between peers that both support it; the
  legacy whole-section scopes keep their current wire format and receive behaviour unchanged
  (andrebrait, 2026-10-04).
- Upgrade migrates the "Disable General/IP/DNSBL tab settings sync" checkbox
  (`sync/syncinterfaces`) without behaviour change: checked selects the legacy lists-only scope;
  unchecked or absent selects the legacy all-settings scope.
- Authority: the node where pfBlockerNG Sync is enabled with targets is the sender. A receiving
  node never originates a sync, including from the apply its receive triggers (BBcan177,
  2026-10-04).
- No pfSense core change. Transport uses existing pfSense XMLRPC methods and their
  authentication: valid credentials plus the `system-xmlrpc-ha-sync` privilege or uid 0
  (`xmlrpc.php:48-93`).
- Registered fields use `PfbConfig`. Forward migration is one-time, idempotent, and
  behaviour-preserving; package downgrade is unsupported (`docs/misc/config-gateway.md`).
- Appliance code is PHP or POSIX shell.
- pfSense behaviour the design relies on:
  - `restore_config_section` removes `installedpackages` from the payload before its own merge,
    writes only the path/value pairs returned by package `plugin_xmlrpc_recv` hooks, then runs
    `filter_configure()` and calls `plugin_xmlrpc_recv_done` (`xmlrpc.php:433-435`, `:574-597`,
    `:712-716`).
  - `merge_installedpackages_section` replaces each sent `installedpackages/<name>` wholesale and
    calls no package hook (`xmlrpc.php:726-743`).
  - Both methods return `true` for every outcome, including a refused CARP loop
    (`xmlrpc.php:190-193`, `:730-733`), so a receiver cannot report through their return value.
  - Automatic sync runs only when a core HA section is ticked and both nodes have the same config
    version (`rc.filter_synchronize:73-97`, `:337-346`). It sends only config paths named by
    `plugin_xmlrpc_send`, and a named path absent on the sender is sent as an empty array
    (`rc.filter_synchronize:201`, `:349-356`).
  - `xmlrpc_client` retries a failed call up to four times (`xmlrpc_client.inc:95-150`).
  - pfSense HA replaces `filter`, `nat`, and `aliases` wholesale on the receiver
    (`xmlrpc.php:199-233`); the sender strips only entries flagged `nosync`
    (`rc.filter_synchronize:110-129`).

## Decisions

### Scopes and migration

The checkbox becomes a select stored as the registered field `sync/syncscope`
(`installedpackages/pfblockerngsync/config/0/syncscope`):

| Token | Meaning | Sections sent | Receive |
| --- | --- | --- | --- |
| `policy` | Policy and lists; this node's local settings stay local | the 19 sections of `pfblockerng_sync_sections(TRUE)` | per-field merge (below) |
| `all` | All settings (legacy) | the same 19 sections, whole | legacy whole-section merge |
| `lists` | Lists and global settings only (legacy) | the 16 always-synced sections | legacy whole-section merge |

- `all` and `lists` reproduce today's unchecked and checked behaviour exactly: same sections, the
  `varsynconchanges` gate path, `merge_installedpackages_section` for manual targets, and the
  existing receive merge (`pfblockerng.inc:21494-21597`).
- Migration is a one-time `pfb_migration_registry()` entry. It runs only when the sync section
  exists and has no `syncscope`, reads `sync/syncinterfaces` with its toggle semantics
  (`PfbToggle::On` → `lists`; every other stored value or absence → `all`), writes `syncscope`,
  then deletes the old key. The old registry entry is removed with no dual read. A registry
  `grandfather` map is not used: it matches raw tokens exactly, while the toggle
  read is case-insensitive. `sync/syncscope` declares `no_grandfather` because the migration runs
  before the registry pass.
- New installs, and existing installs that have never saved the Sync page (no sync section, so
  sync is disabled), get the registry default `policy`.
- The #3441 warning (`pfblockerng_sync_dnsblip_mismatch()`, `pfblockerng_sync.php:198-201`) applies
  to `lists` only; its first term becomes `syncscope === lists`. `all` and `policy` both carry DNSBL
  policy to the peer.

### Ownership classification

- Every `pfb_cfg_registry()` entry declares exactly one `'sync' => 'policy'|'local'`. A gate test,
  shaped like `CfgRegistryGrandfatherGateTest`, fails the suite for an entry with no value. There
  is no default, so a new field cannot inherit a scope silently.
- The 20 unregistered scalars written in the settings sections are registered with every existing
  registry obligation: IP `ip_placeholder`, `maxmind_locale`, `maxmind_account`, `maxmind_key`,
  `asn_reporting`, `asn_token`, `inbound_interface`, `inbound_deny_action`, `outbound_interface`,
  `outbound_deny_action`, `pass_order`, `autorule_suffix`; DNSBL `agateway_in`, `agateway_out`,
  `aliasaddr_in`, `aliasaddr_out`, `aliasports_in`, `aliasports_out`, `autoproto_in`,
  `autoproto_out`. `dnsbl_webpage` stays foreign (ADR-29 §2.5).
- Rule: **local** is an interface, VIP, listener port, gateway, filesystem or script reference,
  credential, runtime or one-shot marker, log, display, or per-node performance tuning value.
  **Policy** is what is blocked, permitted, logged, or transformed, and the shape of generated
  objects.
- Settings sections (`gen`, `ip`, `dnsbl`) use an allowlist: a key syncs if and only if its
  registry entry says `policy`. Unregistered keys there (`dnsbl_webpage`, the retired markers
  `dnsbl_mode`, `pfb_py_block`, `pfb_control_legacy_seeded`, and the `hooks` subtree) never sync.
- All other synced sections use a deny list, `pfb_sync_local_paths()`, kept beside the registry:
  row leaves `srcint`, `script_pre`, `script_post`, `agateway_in`, `agateway_out` in any section;
  in `pfblockerngglobal` every key except `feed_*` and `feed_alt_*`. Everything else is policy.
- Local registered and newly registered keys (every other key in these sections is policy):

| Section | Local keys |
| --- | --- |
| `gen` | `settings_family`, every `log_max_*` and `log_max_days_*`, `pfb_log_trim_margin_pct`, `pfb_reentry_timeout`, `pfb_software_check`, `pfb_reuse`, `pfb_alias_delta_mode`, `pfb_alias_delta_batch`, `pfb_syntax_highlight`, `log_syslog` |
| `ip` | `enable_rdns`, `maxmind_locale`, `asn_reporting`, `inbound_interface`, `outbound_interface`, `maxmind_account`†, `maxmind_key`†, `asn_token`† |
| `dnsbl` | `pfb_dnsvip_auto`, `dnsbl_interface`, `pfb_dnsvip4`, `pfb_dnsvip6`, `pfb_dnsport`, `pfb_dnsport_ssl`, `pfb_cache`, `pfb_cache_flush`, `pfb_py_reply`, `pfb_py_nolog`, `pfb_control`, `pfb_control_legacy`, `pfb_py_cache_max`, `dnsbl_allow_int`, `dnsbl_redir_int`, `dnsbl_dot_block_int`, `agateway_in`, `agateway_out`, `top1m_token`† |
| `rep`, `ss` | none |
| `global` | `alertrefresh` |
| `sync` | `syncscope` (the section is never sent) |

  † Credential; [fork 5](#5-credentials) may move these to policy.

- Feature toggles are policy even when their companion is local: `dnsbl_redir` and
  `dnsbl_dot_block` sync, while their interface lists stay local. Their exception lists
  (`dnsbl_redir_exclude`, `dnsbl_dot_block_exclude`) and `killstates` are enforcement behaviour and
  therefore policy.
- Each node applies its own classification. The sender's classification never decides what the
  receiver keeps.

### Wire contract and transports

- A policy payload is an `installedpackages` subtree holding the gate leaf
  `pfblockerngsync/config/0/syncscope = policy` and each of the 19 sections the sender has, whole
  and raw. It never contains `varsynconchanges`, so every released receive hook (`devel`, `main`,
  `release/3.3`) returns `[]` for it (`pfblockerng.inc:21566-21569`).
- Automatic: in `policy` scope, `pfblockerng_plugin_xmlrpc_send()` returns the gate path and the
  section paths after the capability check passes; pfSense sends them through
  `restore_config_section`.
- Manual: in `policy` scope, each enabled target is sent the same subtree through
  `restore_config_section`, not `merge_installedpackages_section`, with the configured
  `varsynctimeout`. That method writes package configuration only from hook results, so the same
  receive hook handles both transports.
- An unknown `syncscope` token is refused on receive. A future incompatible wire change introduces
  a new token.
- The sender's local values travel inside the authenticated channel, as they do in today's default
  scope. The receiver never stores or applies them.

### Receive merge

`pfblockerng_plugin_xmlrpc_recv()` dispatches on the incoming gate: `syncscope === policy` → per-field
merge; otherwise `varsynconchanges === auto` → the legacy merge, unchanged; otherwise `[]`.

1. **Validate before computing.** Each present section is an array; each scalar leaf is a string.
   Rows in `pfblockernglistsv4`, `pfblockernglistsv6`, and `pfblockerngdnsbl` are arrays; an empty
   row is ignored, as `pfblockerng_category.php:144-152` already removes it. Every other row has a
   non-empty `aliasname` that passes the editor rule (no `\W`, `pfblockerng_category_edit.php:586-592`)
   and is unique within its section, on both the sender's and the receiver's side. Any failure
   returns `[]` and records the refusal. No pfBlockerNG path changes.
2. **Complete snapshot.** In `policy` scope all 19 sections are always in scope. A section missing
   or empty in the payload means the sender has no policy content there. No omitted-versus-empty
   distinction exists, so the merge never depends on how XMLRPC or the config parser encodes an
   empty element.
3. **Map sections** (each settings `config/0`, the continent, Top Spammers and Proxy/Satellite
   `config/0`, `pfblockerngreputation/config/0`, `pfblockerngsafesearch`, `pfblockerngblacklist`,
   `pfblockerngglobal`): policy keys come from the sender exactly. A present value is copied
   verbatim, including `''`, and an absent key stays absent. Local keys come from the receiver
   exactly. Stored `''` therefore keeps its #2120 meaning on both nodes.
4. **Row sections** (`pfblockernglistsv4`, `pfblockernglistsv6`, `pfblockerngdnsbl` `config`): rows
   take the sender's order. They are matched to receiver rows by `aliasname`, the identity the
   package's ledgers already use. A matched row keeps the receiver's local leaves. A row new to the
   receiver gets the editor's select defaults for its local leaves (`pfblockerng_category_edit.php:563-571`),
   never the sender's values. A receiver row absent from the payload is deleted with its local
   leaves, after the same ledger close a local delete performs
   (`pfb_sync_status_close_removed_alias()`, `pfblockerng_category.php:163`). A sender rename is a
   delete plus an add, matching the editor (`pfblockerng_category_edit.php:845-850`).
5. **Raw values.** The merge copies stored values without an adapter round trip, so the receiver's
   stored policy is byte-identical to the sender's. Runtime reads still pass through `PfbConfig`.
   Section-level access follows the existing hook; registered keys get no per-key direct access.
6. **Return only changes.** The hook returns path → merged section for changed sections only; an
   unchanged receive returns `[]`. It never returns the `xmlrpc_recv_result` key, because cores
   without pfSense `7a9b52632297` write every returned key as a config path. The receiver does not
   depend on that commit, so no pfSense minimum beyond the supported matrix is needed.
7. **Idempotence.** The merge is a pure function of the payload and the receiver's configuration,
   so a client retry or a repeated sync is a no-op.
8. **Concurrent saves.** A receive and a page save on the receiver are last-writer-wins, like every
   pfSense configuration write. Drift detection reports the loser, and the next send restores
   policy. No new lock is added.

### Peer capability and mixed versions

- The sender sends a policy payload to a peer only after the peer's status (primitive:
  [fork 2](#2-capability-and-status-primitive)) lists `policy` as a supported token. Otherwise
  pfBlockerNG sends nothing to that peer and logs, raises a notice, and records the reason. In
  automatic mode, `plugin_xmlrpc_send()` returns `[]`, and pfSense still syncs its own sections.
  Manual targets are checked independently.
- There is no automatic fallback to a legacy scope. `all` would overwrite the local fields the
  operator chose to keep, and `lists` would restore the #3441 hazard.
- Without the check, an older receiver still ignores the payload because its gate fails. Old
  sender → new receiver uses the legacy gate and the unchanged legacy merge.
- Package versions may differ. Compatibility means support for the same scope token.
  Classification differences between versions appear as a policy-digest mismatch.

### Apply on receive and authority

- Register `plugin_xmlrpc_recv_done` (`pfblockerng.xml:73-80`). It acts only when this request's
  policy receive changed configuration (a request-local flag set by the receive hook; the hook
  argument is ignored). It marks pending changes with `pfb_mark_pending_changes()`, the page-save
  path, and starts the direct `pfblockerng.php tick` verb in the background.
- The tick applies pending changes through its manual-apply branch inside the apply window
  (`pfblockerng_extra.inc:6449`, `:6595-6611`). Without a `pfb_quiet_hours` window, the change
  takes effect right after the receive instead of at the next `*/15` cron tick
  (`pfblockerng.inc:8819`). Inside a window, it waits as a local page save does. A failed apply
  keeps the pending marker, as it does today.
- Legacy-scope receives trigger no apply, so their behaviour is unchanged.
- A node never sends a policy payload whose policy digest equals the last policy digest it
  received. This covers `pfblockerng_sync_on_changes()` after an apply
  (`pfblockerng_apply.inc:5169-5171`) and `plugin_xmlrpc_send()` after the apply's filter reload.
  A receive-triggered apply therefore never originates a sync, while a later local policy edit on
  a node also configured as a sender still syncs. Saving the Sync page lifts this suppression
  until the next receive, so a deliberate role flip can push unchanged policy. Losing that state,
  such as `dbdir` on a RAM disk, permits at most one redundant send, which the peer treats as a
  no-op.

### Disagreement detection and reporting

The **policy digest** is SHA-256 over a canonical serialization of a node's policy projection: the
19 sections without that node's local leaves, with map keys sorted and row order preserved.

1. **Policy agreement.** The sender compares its digest with the peer's reported digest before each
   policy send, which reveals the previous sync's outcome, and after each manual send. A
   **Check peers** action on the Sync page refreshes per-peer state on demand. A mismatch is logged
   and raises one notice per state change.
2. **Receiver drift.** The receiver keeps the last received digest. When its current digest
   differs because of a local edit or a lost update, its status shows drift.
3. **Effective policy.** After a receive-triggered apply, the receiver records received policy that
   cannot take effect locally. Examples are DNSBL forced off by VIP validation
   (`pfblockerng.inc:3563-3585`) and the existing missing-credential notices.
4. **Copied `pfB_*` objects** (with [fork 1](#1-ownership-of-copied-pfb-objects) option A). Each
   apply records a digest of the pfB-managed aliases, filter rules, and NAT rules it leaves in config
   (`pfblockerng_apply.inc:4716-4734`, `:4858-4883`, `:3231`, `:3361`; DNSBL NAT
   `pfblockerng.inc:9317`). On the next apply, an object is reported if the existing managed set
   differs from the recorded set because of an external writer, such as pfSense HA or a manual edit,
   and also differs from the newly generated set. The report names each object and the attribute
   keys that differ, such as `interface`, `gateway`, or `address`. Identical copies stay silent, and
   whole rulesets are never byte-compared. The check runs in every scope and does not change what
   the apply writes.

Receiver findings raise a pfSense notice and appear on its Sync page. Sender findings appear per peer
on its Sync page and in its log. Status and digest state live in root-only files under
`{$pfb['dbdir']}`, never in `config.xml`. A peer's status contains no secret and no local value.

## Acceptance criteria

Off-box suites; each behaviour test runs RED before its production change, per
`.agents/policy/testing.md`:

1. The classification gate fails for a registry entry without `sync`. `pfb_sync_local_paths()` and
   the local table above are pinned. Each newly registered field meets the existing registry
   obligations: round trip, grandfather decision, sniff path, and inventory.
2. Migration maps stored `on` and `ON` → `lists`, and `''`, `off`, junk, and absent → `all`. A
   second run is a no-op. The old key and its registry entry are gone. A fresh install seeds
   `policy`.
3. In `all` and `lists`, `plugin_xmlrpc_send()` paths, the manual method and payload, and receive
   results equal the pre-change output for the same fixtures.
4. The per-field merge table covers each section shape: policy change; `''` versus absent; untouched
   local keys; policy deletion; row add, reorder, rename, and delete; new-row local defaults; and
   an identical second receive returning `[]`. Hostile inputs return no paths: non-array sections,
   non-string leaves, nested arrays in scalar leaves, empty or `\W` `aliasname`, duplicate
   `aliasname` on either side, and an unknown `syncscope` token.
5. A policy payload never contains `varsynconchanges`, and the released receive hook returns `[]`
   for it.
6. Capability responses of `true`, a non-array, a fault, and a timeout send no policy payload to
   that peer and record status. Other manual targets proceed.
7. `plugin_xmlrpc_recv_done` marks pending changes and dispatches exactly once for a changed policy
   receive, never for legacy or unchanged receives, and ignores its argument.
8. The send path skips a payload whose digest equals the last received digest, sends a different
   digest, and sends after a Sync-page save clears the stored digest.
9. The digest ignores key order and local leaves and changes with row order. The copied-object
   detector stays silent for its own writes and identical copies and reports attribute names for
   differing external copies.
10. The Sync page passes Tier A render for each scope and Tier B coverage for the scope select, the
    peer status, and Check peers.

Two-node HA smoke: node A sends and node B receives. Both use the minimum CE leg and the branch
package unless a row says otherwise. A's System > High Availability syncs Firewall Rules, NAT, and
Aliases to B. `.pfb_cron_disable` stays on both nodes. Each assertion waits on a completion record,
never elapsed time.

1. **Automatic transport.** A policy change on A, such as a DNSBL whitelist entry or an IP deny
   action, makes B's stored policy equal A's. B's interfaces, VIPs, ports, gateways, scripts,
   credentials, alert preferences, and hooks remain byte-identical.
2. **Manual transport.** The automatic transport row passes with "Sync to host(s) defined below".
3. **Apply within one receive.** With no apply window, B enforces the change after the receive,
   proven by B's record of a receive-triggered apply and an on-box probe, without any cron tick.
4. **Deletion.** Deleting a scalar policy setting, one list group, and every group in a section on A
   is reflected on B. Surviving groups keep B's local leaves.
5. **Idempotent repeat.** Resending, including a forced client retry through a short timeout, leaves
   B's `config.xml` unchanged after the first receive, with one apply.
6. **Legacy migration.** Upgrading both nodes from the previous `devel` build, once with the checkbox
   checked and once unchecked, preserves the sync payload and receive result.
7. **Mixed-version fallback.** A new sender in `policy` scope leaves the previous-build B
   byte-identical and reports the peer as unsupported. A previous-build A to a new B keeps legacy
   behaviour.
8. **No partial mutation on failure.** An injected invalid payload, such as a duplicate `aliasname`,
   leaves B's `installedpackages` byte-identical and shows the refusal on both nodes.
9. **Copied `pfB_*` rule detection.** With a different `inbound_interface` on B, B reports the
   affected `pfB_*` rules and the `interface` attribute. With equal values, it reports nothing.
10. **Authority.** CARP demotion of A makes B originate nothing. If B lists A as a manual target, a
    receive from A causes no send back. With two manual targets and one unreachable, the reachable
    target updates and status is recorded per target.

## Out of scope

- pfSense core changes, including what pfSense HA copies or how it authenticates.
- Backporting to `release/3.3`.
- Per-field operator selection, chained relays (A → B → C), multi-master merging, and conflict
  resolution.
- Synchronizing `pfblockerngsync` itself (targets, credentials, scope), runtime data, databases,
  downloads, or logs.
- Atomicity across targets; each target succeeds or fails independently.
- Separating secrets embedded in feed URLs from list policy.
- Changing legacy-scope behaviour, including the legacy hook's existing `xmlrpc_recv_result` return.
- Implementation tickets before every fork below is closed.

## Open forks

Each fork's ticket is filed after the owner reviews this draft.

### 1. Ownership of copied pfB objects

pfSense HA copies `filter`, `nat`, and `aliases` wholesale, so local interface, gateway, VIP, and
port values embedded in `pfB_*` objects reach the receiver.

- **A (recommended):** pfSense keeps ownership of what it copies. Embedded fields stay local in
  pfBlockerNG, and detection 4 reports differing copies. This needs no package-side change to
  copied objects and leaves no enforcement gap. The flap stays visible until the operator aligns
  the values.
- **B:** pfBlockerNG re-owns its objects. It flags generated objects `nosync`, and the receiver
  re-inserts its own objects in `plugin_xmlrpc_recv_done`. Each HA receive still replaces the three
  sections, so the receiver runs without `pfB_*` objects between pfSense's `filter_configure()` and
  the hook. User rules that reference `pfB_*` aliases fail to load in that gap, and every sync
  reloads the filter twice. Detection 4 would become a re-insert check.

### 2. Capability and status primitive

- **A (recommended):** The sender calls pfSense's `exec_php` through `xmlrpc_exec_php()`
  (`xmlrpc_client.inc:155-158`). A fixed code string without interpolated data calls
  `pfblockerng_sync_status()`, which returns supported tokens, package version, policy digest, last
  receive, and findings. It uses the same authentication and privilege as `restore_config_section`
  and returns no secret. An older peer lacks the function and returns `true`
  (`xmlrpc.php:138-147`), so the sender reads it as unsupported.
- **B:** The receiver publishes its status as a top-level `config.xml` element that the sender reads
  with `backup_config_section`. That method returns whole top-level sections
  (`xmlrpc.php:170-173`), so the element must sit outside `installedpackages`; reading
  `installedpackages` returns every package's secrets. Every receive and apply also writes
  configuration.

### 3. Receiver opt-in

- **A (recommended):** The sender is authoritative. The receiver's own scope affects only its own
  sends, matching pfSense HA and today's hook.
- **B:** The receiver accepts `policy` only when its own `syncscope` is `policy`. This needs per-node
  setup before the first sync, and the sender sees a refusal only through status.

### 4. Lists-only scope lifetime

- **A (recommended):** Keep `lists` indefinitely with the #3441 warning. Plan any deprecation
  separately, based on usage evidence.
- **B:** Deprecate `lists` in 4.0, add an upgrade notice, and remove it in a named later release.

### 5. Credentials

- **A (recommended):** MaxMind account and key, IPinfo ASN token, and Cloudflare TOP1M token stay
  local, as marked †. A receiver without one reports it through the existing credential notices
  and status. Feed URLs with embedded keys remain list policy, as a documented limitation.
- **B:** Credentials are policy, as in today's default all-settings sync, and are stored on every
  receiver.
