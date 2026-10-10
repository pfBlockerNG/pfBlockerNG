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
presentation settings. The sender separates policy from node-local values before transmission, so
local values and credentials never leave the sending node. A policy change, including a deletion,
takes effect on the receiver after one receive. A repeated receive changes nothing. An older peer
applies no policy mutation.

The node that can observe a disagreement reports it. The receiver reports drift in its policy,
refused or partly ignored payloads, policy that cannot take effect locally, and incompatible
`pfB_*` objects that pfSense HA copied to it. The sender reports only what it did: what it handed
to or sent over the transport and any transport error that transport itself detected. The sender
never claims that a peer supports, accepted, or applied a payload.

## Fixed constraints

- `devel`/4.0 only. The legacy whole-section scopes keep their current wire format and receive
  behaviour exactly, and the lists-only scope is retained indefinitely with the #3441 warning
  (andrebrait, 2026-10-04 and 2026-10-05). Their send behaviour is unchanged too, with one stated
  exception: a node that holds an accepted policy digest, which exists only after a policy
  receive, originates nothing while its policy is unchanged (see
  [Apply on receive and authority](#apply-on-receive-and-authority)). A legacy-only workflow never
  creates that digest.
- Upgrade migrates the "Disable General/IP/DNSBL tab settings sync" checkbox
  (`sync/syncinterfaces`) without behaviour change: checked selects the legacy lists-only scope;
  unchecked or absent selects the legacy all-settings scope.
- Authority: the node where pfBlockerNG Sync is enabled with targets is the sender, and its scope
  is authoritative. The receiver's own scope controls only what the receiver itself sends, never
  whether it accepts a payload. A receiving node never originates a sync, including from the apply
  its receive triggers and whatever its own scope is (BBcan177, 2026-10-04; andrebrait, 2026-10-05).
- No pfSense core change, and no new endpoint, privilege, or reachability prerequisite. The package
  adds no call to a peer beyond the HA sync transport itself:
  - automatic: `plugin_xmlrpc_send()` returns config paths and pfSense core transmits them;
  - manual: one `restore_config_section` call per enabled target, over the connection
    `pfblockerng_do_xmlrpc_sync()` already opens with that target's configured address, port,
    protocol, username, and password.

  There is no capability or status probe, no `exec_php`, `exec_shell`, `host_firmware_version`, or
  `backup_config_section` call, and no read of a peer's configuration. Authentication stays what
  pfSense already requires: valid credentials plus the `system-xmlrpc-ha-sync` privilege or uid 0
  (`xmlrpc.php:48-93`).
- Registered fields use `PfbConfig`. Forward migration is one-time, idempotent, and
  behaviour-preserving; package downgrade is unsupported (`docs/misc/config-gateway.md`).
- No temporary configuration storage and no top-level `config.xml` status record. The only
  configuration this design adds is the registered field `sync/syncscope`; node-local status lives
  in root-only files under `{$pfb['dbdir']}`.
- Appliance code is PHP or POSIX shell.
- pfSense behaviour the design relies on:
  - `restore_config_section` removes `installedpackages` from the payload before its own merge,
    writes only the path/value pairs returned by package `plugin_xmlrpc_recv` hooks, then runs
    `filter_configure()` and calls `plugin_xmlrpc_recv_done` (`xmlrpc.php:434`, `:574-597`,
    `:712-715`). It does so for every payload, including one whose hooks all return `[]`, so a
    peer that ignores a payload still records a config-history entry and reloads its filter.
  - `merge_installedpackages_section` replaces each sent `installedpackages/<name>` wholesale and
    calls no package hook (`xmlrpc.php:726-743`).
  - Both methods return `true` for every outcome, including a refused CARP loop
    (`xmlrpc.php:190-193`, `:730-733`), so neither node can learn acceptance from the return value.
  - Automatic sync runs only when a core HA section is ticked and both nodes have the same config
    version (`rc.filter_synchronize:73-97`, `:337-346`). The package contributes only config paths
    named by `plugin_xmlrpc_send`, and for each path the default branch of `carp_sync_xml` stores
    `array_get_path($config_copy, $path, [])` at that path (`rc.filter_synchronize:201`,
    `:349-356`).
  - `rc.filter_synchronize` is a standalone script that requires `config.inc` (`:32`), which parses
    `config.xml` from disk (`config.inc:131`). The automatic hook and `carp_sync_xml` therefore read
    freshly parsed values: every stored leaf is already its persisted string, and no `false` leaf
    exists.
  - `array_get_path` returns its default for an absent path and for a stored empty string
    (`util.inc:4645-4664`). An empty-string leaf therefore travels as an empty array, and path
    presence in the payload is what separates it from an absent leaf. Core itself relies on an
    empty array keeping its key in transit (`xmlrpc.php:224-228`).
  - A config element written empty reparses as `''`, and an empty array is written as an empty
    element (`xmlparse.inc:105-111`, `:293-295`, `:305-307`), so `''` and `[]` are indistinguishable
    once stored.
  - `xmlrpc_client` retries a failed call up to four times (`xmlrpc_client.inc:95-150`).
  - pfSense HA replaces `filter`, `nat`, and `aliases` wholesale on the receiver
    (`xmlrpc.php:199-233`); the sender strips only entries flagged `nosync`
    (`rc.filter_synchronize:110-129`).

## Decisions

### Scopes and migration

The checkbox becomes a select stored as the registered field `sync/syncscope`
(`installedpackages/pfblockerngsync/config/0/syncscope`):

| Token | Meaning | Sent | Receive |
| --- | --- | --- | --- |
| `policy` | Policy and lists; this node's local settings stay local | the gate leaf plus the policy projection of the 19 sections of `pfblockerng_sync_sections(TRUE)` | per-field merge (below) |
| `all` | All settings (legacy) | the same 19 sections, whole | legacy whole-section merge |
| `lists` | Lists and global settings only (legacy) | the 16 always-synced sections, whole | legacy whole-section merge |

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
  in `pfblockerngblacklist` the provider credentials `item/*/username` and `item/*/password`; in
  `pfblockerngglobal` every key except `feed_*` (which includes `feed_alt_*`). Everything else is
  policy.
- The 19 synced sections, with the classification mode that applies to each:

| Section | Shape | Written by | Mode |
| --- | --- | --- | --- |
| `pfblockerng` | `config/0` map; `hooks/row` list | General tab, Hooks tab | allowlist (43 registered) |
| `pfblockerngipsettings` | `config/0` map | IP tab | allowlist (11 registered + 12 newly registered) |
| `pfblockerngdnsblsettings` | `config/0` map | DNSBL tab | allowlist (69 registered + 8 newly registered) |
| `pfblockernglistsv4`, `pfblockernglistsv6`, `pfblockerngdnsbl` | rows `config/N`, each with a `row/M` feed list | category editor | deny list |
| `pfblockerngreputation` | `config/0` map | Reputation tab | deny list |
| `pfblockerngtopspammers`, `pfblockerngafrica`, `pfblockerngantarctica`, `pfblockerngasia`, `pfblockerngeurope`, `pfblockerngnorthamerica`, `pfblockerngoceania`, `pfblockerngsouthamerica`, `pfblockerngproxyandsatellite` | `config/0` map | GeoIP tabs | deny list |
| `pfblockerngblacklist` | flat settings keys plus an `item` list of per-provider rows, each identified by its `xml` leaf | Blacklist tab | deny list; `item` rows matched by `xml` |
| `pfblockerngglobal` | flat map | Feeds page (`feed_*`), dashboard widget (`widget-*`), Alerts page (`alertrefresh`) | deny list |
| `pfblockerngsafesearch` | flat map | SafeSearch tab | deny list |

- Local keys (every other key in these sections is policy):

| Section | Local keys |
| --- | --- |
| `gen` | `settings_family`, every `log_max_*` and `log_max_days_*`, `pfb_log_trim_margin_pct`, `pfb_reentry_timeout`, `pfb_software_check`, `pfb_reuse`, `pfb_alias_delta_mode`, `pfb_alias_delta_batch`, `pfb_syntax_highlight`, `log_syslog` |
| `ip` | `enable_rdns`, `maxmind_locale`, `asn_reporting`, `inbound_interface`, `outbound_interface`, `maxmind_account`, `maxmind_key`, `asn_token` |
| `dnsbl` | `pfb_dnsvip_auto`, `dnsbl_interface`, `pfb_dnsvip4`, `pfb_dnsvip6`, `pfb_dnsport`, `pfb_dnsport_ssl`, `pfb_cache`, `pfb_cache_flush`, `pfb_py_reply`, `pfb_py_nolog`, `pfb_control`, `pfb_control_legacy`, `pfb_py_cache_max`, `dnsbl_allow_int`, `dnsbl_redir_int`, `dnsbl_dot_block_int`, `agateway_in`, `agateway_out`, `top1m_token` |
| `rep`, `ss` | none |
| `global` | every key except `feed_*`: `alertrefresh`, every `widget-*` |
| `pfblockerngblacklist` | `item/*/username`, `item/*/password` (the `item` list is matched by its `xml` leaf) |
| `sync` | `syncscope` (the section is never sent) |

- Credentials are local. The MaxMind account and key (`maxmind_account`, `maxmind_key`), the IPinfo
  ASN token (`asn_token`), the Cloudflare TOP1M token (`top1m_token`), and the Blacklist provider
  account of each `item` row (`username`, `password`) are not policy: they never enter a policy
  payload, so they never leave the sending node in `policy` scope, and a receiver keeps its own,
  matched by the row's `xml` leaf and not by its index. A provider row new to the receiver gets
  `''` for both. The legacy scopes are unchanged. Feed URLs that embed a key stay list policy and
  travel with their row; that is a documented exception and is not separated.
- Feature toggles are policy even when their companion is local: `dnsbl_redir` and
  `dnsbl_dot_block` sync, while their interface lists stay local. Their exception lists
  (`dnsbl_redir_exclude`, `dnsbl_dot_block_exclude`) and `killstates` are enforcement behaviour and
  therefore policy.
- Each node applies its own classification. The sender's classification never decides what the
  receiver keeps.

> **Amendment 2026-10-10 (#3451 review).** `infolists` is a row-local key: `pfb_sync_local_paths()['row']`
> lists it beside `srcint`, `script_pre`, `script_post`, `agateway_in` and `agateway_out`, and its whole
> subtree stays local. It is the legacy v1 tag the category editor deletes on save
> (`pfblockerng_category_edit.php:960`, "Remove unused xml tag"); without this entry a sender's
> never-re-saved group would make every receiver refuse the snapshot. Separately, a payload key outside
> `[a-z0-9_.-]` is unclassifiable (core lower-cases element names on reload) and is ignored at every depth
> under the step 3 rule for a leaf the receiver cannot classify.

### Policy projection

A node's **policy projection** is the ordered list of its stored policy leaves in the 19 sections,
produced by its own classification before anything is transmitted. Local and unknown settings
leaves, credentials, `pfblockerngsync` content, and `varsynconchanges` are not in it.

- A **leaf** is a stored scalar, or a stored empty array (persisted as an empty element, which
  reparses as `''`). A stored non-string scalar is normalized as `write_config` persists it: `true`
  and `''` become `''`, `false` is omitted, any other scalar is cast to a string. Sender memory
  state therefore never yields a payload the receiver refuses.
- The automatic transport reads `rc.filter_synchronize`'s own freshly parsed configuration, where
  that normalization is the identity. Only the manual builder runs on the sender's in-memory
  configuration, so only it normalizes, before it builds the payload.
- A leaf's path is `installedpackages/<section>/<key path>`, in stored order. Row indices and row
  order are preserved by the path.
- The projection lists only leaves that exist. An absent key has no path; a stored `''` has one.
- Both transports are derived from one path list: the gate path
  `installedpackages/pfblockerngsync/config/0/syncscope` once, followed by the projection paths.
  Every path already starts at the `installedpackages` root, so a payload built from the list has
  `installedpackages` as its single top-level key. Both transports require the stored `syncscope`
  leaf to read `policy`; the registry default alone never sends. Core copies the stored leaf
  verbatim, and a manual payload built from an unstored leaf would carry `[]` in the gate, which a
  receiver refuses while the sender shows sent. A node with a Sync section always has the leaf,
  because the Sync page save and the migration both store it.
  - Automatic: while `varsynconchanges` is `auto`, as today, `plugin_xmlrpc_send()` returns the
    path list. Core then builds the payload from those paths, storing a listed `''` leaf as `[]`.
  - Manual: the builder first copies each projected leaf, normalized as above and with the gate
    leaf included, into `$normalized`. It then starts from `$payload = []` and, for each path in
    list order, runs the expression core uses:
    `array_set_path($payload, $path, array_get_path($normalized, $path, []))`. It sends `$payload`
    itself as the `restore_config_section` argument and never wraps it in
    `['installedpackages' => …]` again. Both transports therefore put the same array on the wire.
- The payload is a **complete snapshot**: all 19 sections are always in scope. A section with no
  policy leaf contributes no path, which means the sender has no policy content there. No
  per-leaf deletion record exists or is needed.

### Wire contract and transports

- A policy payload is an `installedpackages` subtree holding the gate leaf
  `pfblockerngsync/config/0/syncscope = policy` and the nested leaves of the sender's policy
  projection. It never contains `varsynconchanges`, a local leaf, a credential, or an unknown
  settings leaf. Every released receive hook returns `[]` for it: `devel` before this change,
  `main`, `release/3.3`, and every tag from `v3.2.15` to `v3.3.10` share the same
  `varsynconchanges` gate (`pfblockerng.inc:21566-21569` at `devel`).
- Automatic: in `policy` scope, `pfblockerng_plugin_xmlrpc_send()` returns the gate path and the
  projection paths; pfSense sends them through `restore_config_section`.
- Manual: in `policy` scope, each enabled target is sent the payload through
  `restore_config_section`, not `merge_installedpackages_section`, with the configured
  `varsynctimeout`. That method writes package configuration only from hook results, so the same
  receive hook handles both transports. Unlike the legacy manual merge, it also makes the receiver
  run `filter_configure()` (`xmlrpc.php:712`).
- Any `syncscope` value other than `policy`, including `[]`, is refused on receive and never falls
  through to the legacy merge. A future incompatible wire change introduces a new token.

### Receive merge

`pfblockerng_plugin_xmlrpc_recv()` dispatches on whether the incoming payload carries the gate leaf
`installedpackages/pfblockerngsync/config/0/syncscope`:

- Leaf present: the value `policy` → per-field merge; every other value, including `[]` → refuse:
  return `[]` and record the reason. A `varsynconchanges = auto` leaf supplied alongside changes
  nothing, because legacy payloads never carry `syncscope`: `pfblockerng_sync_sections()` has no
  `pfblockerngsync` section (`pfblockerng.inc:21447-21474`).
- Leaf absent: `varsynconchanges === auto` → the legacy merge, unchanged; otherwise `[]`.

The receiver's own `syncscope` is not consulted.

1. **Validate before computing.** Each present section is an array. Each leaf is a string or an
   empty array; a non-empty array where the receiver's schema has a scalar, or a scalar where it
   has a container, fails. Rows in `pfblockernglistsv4`, `pfblockernglistsv6`, and `pfblockerngdnsbl`
   are arrays; an empty row is ignored, as `pfblockerng_category.php:144-152` already removes it.
   Every other row has a non-empty `aliasname` that passes the editor rule (no `\W`,
   `pfblockerng_category_edit.php:586-592`) and is unique within its section, on both the sender's
   and the receiver's side. Every feed `row` `header` is unchanged by `pfb_normalize_row_header()`, the
   `\W` strip that the apply persists (`pfblockerng_apply.inc:1425-1435`) and the editor already
   enforces (`pfblockerng_category_edit.php:629`); an empty header, which a Disabled feed may have,
   passes. A received header therefore cannot change under the apply after the accepted digest is
   taken. Each Blacklist `item` row is an array with a non-empty string `xml`, unique within `item`
   on both sides. Any failure returns `[]` and records the refusal locally. No pfBlockerNG path
   changes. Sections outside the 19, and content of `pfblockerngsync` other than the gate leaf, are
   ignored.
2. **Complete snapshot.** In `policy` scope all 19 sections are always in scope. A section missing
   or empty in the payload means the sender has no policy content there. A listed leaf holding
   `''` or `[]` is a present, empty value and never a deletion. The merge therefore does not depend
   on how XMLRPC or the config parser encodes an empty element.
3. **Map sections** (each settings `config/0`, the continent, Top Spammers and Proxy/Satellite
   `config/0`, `pfblockerngreputation/config/0`, `pfblockerngsafesearch`, `pfblockerngglobal`, and
   the flat keys of `pfblockerngblacklist`, which are all keys except `item`): the receiver's
   policy keys come from the payload exactly. A present value is copied verbatim, `[]` becomes `''`,
   and a policy key absent from the payload is deleted. A payload leaf that the receiver classifies
   local, or in a settings section does not register, is ignored. The receiver's local and unknown
   keys are kept exactly. Stored `''` therefore keeps its #2120 meaning on both nodes.
4. **Row sections** (`pfblockernglistsv4`, `pfblockernglistsv6`, `pfblockerngdnsbl` `config`): rows
   take the payload's order. They are matched to receiver rows by `aliasname`, the identity the
   package's ledgers already use. A matched row keeps the receiver's local leaves and ignores any
   local leaf in the payload. A row new to the receiver gets the editor's select defaults for its
   local leaves (`pfblockerng_category_edit.php:563-571`), never the sender's values. A receiver
   row absent from the payload is deleted with its local leaves, after the same ledger close a local
   delete performs (`pfb_sync_status_close_removed_alias()`, `pfblockerng_category.php:163`), once
   per deleted alias and only after step 1 has accepted the whole payload, so a refused or
   repeated receive closes nothing. A sender rename is a delete plus an add, matching the editor
   (`pfblockerng_category_edit.php:845-850`). Rows are stored under the payload's keys in the
   payload's order. At rest both nodes' lists are dense, because the parser numbers list entries by
   position and `write_config` writes lists in order (`xmlparse.inc:80-88`, `:266-292`).
   The Blacklist `item` list has the same shape with the identity `xml` in place of `aliasname`:
   payload order; a matched row keeps the receiver's `username` and `password`, matched by `xml`
   and never by index; a row new to the receiver gets `''` for both; a receiver row whose `xml` the
   payload lacks is deleted. That deletion has no ledger to close.
5. **Raw values.** The merge copies stored values without an adapter round trip, so the receiver's
   stored policy is byte-identical to the sender's: whitespace, leading zeros, and case are kept,
   and the only transformation is `[]` becoming `''`. Runtime reads still pass through `PfbConfig`.
   Section-level access follows the existing hook; registered keys get no per-key direct access.
6. **Return only changes.** The hook returns path → merged section for changed sections only; an
   unchanged receive returns `[]`. Its keys are only `installedpackages/<section>` paths: it carries
   no control or status key and never returns the `xmlrpc_recv_result` key, because cores
   without pfSense `7a9b52632297` write every returned key as a config path. The receiver does not
   depend on that commit, so no pfSense minimum beyond the supported matrix is needed.
7. **Idempotence.** The merge is a pure function of the payload and the receiver's configuration,
   so a client retry or a repeated sync is a no-op.
8. **Concurrent saves.** A receive and a page save on the receiver are last-writer-wins, like every
   pfSense configuration write. Drift detection reports the loser, and the next send restores
   policy. No new lock is added.
9. **Local record.** The hook records the receive in the receiver's own status files (see
   [Reporting](#reporting)): the outcome, the incoming and accepted digests, and the ignored leaf
   paths, or the refusal reason. Nothing is returned to or read from the sender.

### Mixed versions and unsupported peers

- There is no probe. A sender in `policy` scope always transmits the policy payload, subject only
  to the [received-digest suppression](#apply-on-receive-and-authority). It does not ask a peer
  whether the peer supports the scope, before or after sending.
- Safety is by construction on the receiving side. An unsupported receiver's hook returns `[]` for
  a payload without `varsynconchanges`, and a policy payload never carries it, so an unsupported
  peer applies no policy mutation and its pfBlockerNG sections are not written.
- That guarantee covers policy mutation only. The request still reaches the peer: core writes a
  config-history entry and reloads the filter (`xmlrpc.php:595-597`, `:712`), and any pfSense HA
  section ticked on the sender still syncs normally. The design does not promise that no request,
  config revision, or filter reload occurs, or that a peer's `config.xml` is byte-identical when
  pfSense HA updates other sections.
- The sender cannot tell an unsupported peer from a supporting one: the transport returns `true`
  for a payload an older hook ignored, so the sender shows acceptance as **unconfirmed**. An
  unsupported peer is visible only on that peer, where it shows none of the new receiver records;
  the sender never reads a peer's state, so that absence is not a detector it can use. An
  unreachable or refusing peer is different: the sender observes the transport failure itself.
  Manual: the client's error (connection, TLS, authentication, or timeout), recorded per target
  after the client's retries. Automatic: pfSense HA sync's own report, which the package does not
  duplicate.
- There is no automatic fallback to a legacy scope. `all` would overwrite the local fields the
  operator chose to keep, and `lists` would restore the #3441 hazard.
- Old sender → new receiver uses the legacy gate and the unchanged legacy merge.
- Two supporting builds may differ. Compatibility means support for the same scope token. A
  receiver cannot tell a policy key the sender deleted from one the sender's build does not send,
  so a key that the receiver's build classifies as policy and the sender's build does not know is
  deleted from the receiver at every receive. Peers should run the same package build. The
  opposite skew is visible on the receiver as ignored leaf paths.

### Apply on receive and authority

- Register `plugin_xmlrpc_recv_done` (`pfblockerng.xml:73-80`). It acts only when this request's
  policy receive changed configuration (a request-local flag set by the receive hook; the hook
  argument is ignored). It marks pending changes with `pfb_mark_pending_changes()`, the page-save
  path, and starts the direct `pfblockerng.php tick` verb in the background.
- The tick applies pending changes through its manual-apply branch inside the apply window
  (`pfblockerng_extra.inc:6449`, `:6595-6611`). Without a `pfb_quiet_hours` window, the change
  takes effect right after the receive instead of at the next `*/15` cron tick
  (`pfblockerng.inc:8819`). Inside a window, it waits as a local page save does. A failed apply
  keeps the pending marker, as it does today. The receive record states only that the
  configuration was accepted; the apply has its own record (see [Reporting](#reporting), item 4).
- Legacy-scope receives trigger no apply, so their behaviour is unchanged.
- **Received-digest suppression, in any scope.** After every accepted policy receive the node
  records the **accepted digest** (see [Reporting](#reporting)). While its current policy digest
  still equals that record, the node originates no pfBlockerNG sync, whatever its own scope
  (`policy`, `all`, or `lists`) and whichever targets it lists: `pfblockerng_sync_on_changes()`,
  which runs after every apply (`pfblockerng_apply.inc:5169-5171`), returns before its target
  loop, and `plugin_xmlrpc_send()` returns no pfBlockerNG path, while pfSense still syncs its own
  sections. A receive-triggered apply therefore never originates a sync. The sender's authority
  holds even when the receiver is itself configured as a sender or lists the original sender as a
  target, and the receiver's scope plays no part.
- **Lifting it.** A local policy edit changes the digest, so a node also configured as a sender
  syncs that edit as before. Saving the Sync page, a deliberate role flip, clears the stored
  accepted digest until the next receive. Losing the state file, such as `dbdir` on a RAM disk,
  ends the suppression until the next receive, so the node sends as it did before this change; a
  peer treats a repeated policy payload as a no-op.
- **Legacy behaviour otherwise unchanged.** The accepted digest exists only after a policy
  receive, and legacy receives record none. A node that has never accepted a policy payload, or
  whose workflow is legacy only, sends exactly as it did before this change. A node that holds an
  accepted digest and sends in `all` or `lists` scope is a chained relay, which is out of scope, or
  a role flip. While its policy digest is unchanged, an edit of its local-only settings does not
  trigger a send until a policy edit or a Sync-page save.

### Reporting

Each node reports only what it can observe itself. No node reads another node's state, and no
digest is exchanged or compared across nodes. State lives in root-only files under
`{$pfb['dbdir']}`, never in `config.xml`, and contains no secret and no node-local value: findings
name leaf paths, never values.

A node's **policy digest** is SHA-256 over a canonical serialization of its policy projection: the
19 sections in `pfblockerng_sync_sections(TRUE)` order, string-keyed maps sorted by key, and row
lists, Blacklist `item` included, kept in order and renumbered by position. It depends on that
node's own classification.

**Receiver** (Sync page panel and a pfSense notice per state change):

1. **Last receive.** Time and receive outcome (accepted with changes, accepted unchanged, or
   refused with its reason), the **incoming digest** over every leaf the payload carried in the 19
   sections, counting an empty array as `''`, and the **accepted digest** over this node's policy
   projection immediately after the merge. The outcome says only that the configuration was stored
   or refused; it makes no claim about runtime.
2. **Incoming versus accepted.** When the two digests differ after an accepted receive, the payload
   carried leaves this node classifies local or unknown: injected local fields, or a classification
   difference between builds. The record lists their paths.
3. **Drift.** The current digest, recomputed on demand, differs from the accepted digest: a local
   edit, a restore, or a lost update since the last receive.
4. **Apply outcome and effective policy.** The receive outcome in item 1 never claims that the
   policy is running. The apply that a changed receive triggers has its own record: waiting for the
   quiet-hours window, applied, or failed with its reason (a failed apply keeps the pending
   marker). Once an apply has completed, received policy that cannot take effect locally is
   listed. Examples are DNSBL forced off by VIP validation (`pfblockerng.inc:3563-3585`), the
   existing MaxMind and ASN missing-credential notices (`pfb_maxmind_credential_notice()`,
   `pfblockerng_apply.inc:3797-3803`), a missing TOP1M token while `top1m_enable` is on and the
   selected provider requires one (`pfb_top1m_auth_headers()`; TOP1M has no notice today), and a
   feed row whose header collides with a package-reserved name, which the apply skips with its
   existing notice (`pfblockerng_apply.inc:1426-1429`, `:1472-1477`).
5. **Copied `pfB_*` objects.** pfSense keeps copying `filter`, `nat`, and `aliases`, and
   pfBlockerNG neither flags its objects `nosync` nor re-inserts them. Each apply records a digest
   of the pfB-managed aliases, filter rules, and NAT rules it leaves in config
   (`pfblockerng_apply.inc:4716-4734`, `:4858-4883`, `:3231`, `:3361`; DNSBL NAT
   `pfblockerng.inc:9317`). On the next apply, an object is reported if the existing managed set
   differs from the recorded set because of an external writer, such as pfSense HA or a manual edit,
   and also differs from the newly generated set. The report names each object and the attribute
   keys that differ, such as `interface`, `gateway`, or `address`. Identical copies stay silent, and
   whole rulesets are never byte-compared. The check runs in every scope and does not change what
   the apply writes.

**Sender** (Sync page panel and log):

- Manual target: the time and digest of the payload, and either **sent, acceptance unconfirmed**
  (the call returned; the words "acceptance unconfirmed" are required) or the transport error the
  client reported (connection, TLS, authentication fault, or timeout after its retries). One
  unreachable target does not stop the others and is recorded per target.
- Automatic: the time and digest of the paths handed to pfSense HA sync, labelled as handed over.
  The hook returns before core transmits and never learns the outcome, so the package records no
  delivery result and raises no reachability failure of its own; pfSense reports the transport
  errors it detects.
- The sender never shows a peer as supported, accepted, applied, in sync, or drifting.

## Acceptance criteria

Off-box suites; each behaviour test runs RED before its production change, per
`.agents/policy/testing.md`:

1. The classification gate fails for a registry entry without `sync`. `pfb_sync_local_paths()` and
   the local table above are pinned, including the six credential leaves as `local`: the MaxMind
   account and key, the ASN token, the TOP1M token, and Blacklist `item/*/username` and
   `item/*/password`. Each newly registered field meets the existing registry obligations: round
   trip, grandfather decision, sniff path, and inventory.
2. Migration maps stored `on` and `ON` → `lists`, and `''`, `off`, junk, and absent → `all`. A
   second run is a no-op. The old key and its registry entry are gone. A fresh install seeds
   `policy`. `pfblockerng_sync_dnsblip_mismatch()`, whose first term is now `syncscope === lists`,
   is true for `lists` only, with its remaining guards unchanged, and false for `all` and `policy`
   when those guards hold (`tests/php/SyncDnsblipMismatchTest.php`).
3. In `all` and `lists`, `plugin_xmlrpc_send()` paths, the manual method and payload, and receive
   results equal the pre-change output for the same fixtures, on a node with no accepted digest.
4. Projection, from a fixture holding every local key in the table, all six credential leaves with
   sentinel values, an unknown settings key, a `hooks` subtree, a Blacklist `item` list, and
   `pfblockerngsync` content:
   - neither the projection paths nor any serialized payload contains those keys or their sentinel
     values; a feed URL with an embedded key is present;
   - on a disk-shaped fixture (every leaf a string, as `rc.filter_synchronize` parses it), the
     automatic path list, fed through core's default-branch expression, builds an array equal to
     the manual payload. That array has `installedpackages` as its only top-level key, no nested
     `installedpackages/installedpackages`, and the gate leaf once. The test doubles of
     `array_get_path` and `array_set_path` are verbatim copies of the pinned `util.inc` bodies,
     including the empty-string rule at `:4659`, because a double without it would pass vacuously;
   - a separate in-memory fixture holding `true`, `false`, integer, and `''` leaves exercises the
     manual builder's normalization alone: its payload equals the payload of the same fixture after
     persistence and reparse;
   - a stored `''` is listed and arrives as `[]`, and an absent key has no path;
   - a non-string scalar is normalized as persisted; row order and indices are preserved;
   - both transports produce a policy payload only when the stored `syncscope` leaf reads `policy`;
     an unstored leaf, `all`, and `lists` produce none from either;
   - `varsynconchanges` is never present.
5. The per-field merge table covers each section shape: policy change; `''` and `[]` versus
   absent; untouched local keys; policy deletion; row add, reorder, rename, and delete; new-row
   local defaults; Blacklist `item` add, reorder, and delete, matched by `xml` so that the
   receiver's `username` and `password` stay with their provider when the order differs, and `''`
   for a new provider row; and an identical second receive returning `[]`. Each case asserts the
   stored result, not only the return value:
   - the stored policy equals the sender's value byte for byte (whitespace, leading zeros, case),
     and `[]` is stored as `''`;
   - the returned keys are exactly the changed `installedpackages/<section>` paths, with no
     `xmlrpc_recv_result`, control, or status key;
   - `pfb_sync_status_close_removed_alias()` runs once per deleted alias and only after the whole
     payload has passed validation; a refused payload and a repeated receive close none.

   Hostile inputs return no paths and leave configuration byte-identical: non-array sections,
   non-string leaves, non-empty arrays at scalar keys, empty or `\W` `aliasname`, duplicate
   `aliasname` on either side, a feed `header` that `pfb_normalize_row_header()` would change (an
   empty header and one of word characters are accepted), a Blacklist `item` row with an empty or
   duplicate `xml`, and a `syncscope` leaf of any value other than `policy`, including `[]`. The
   last case also runs with `varsynconchanges = auto` injected alongside: it still returns `[]` and
   records a refusal, and never reaches the legacy merge. A payload without `syncscope` and with
   `varsynconchanges = auto` still takes the legacy merge unchanged.
6. A payload that injects local or unknown leaves (`inbound_interface`, `dnsbl_interface`,
   `maxmind_key`, `asn_token`, `top1m_token`, a Blacklist `item` `username` and `password`,
   `srcint`, `script_pre`, `agateway_in`, a `hooks` row, `widget-*`) changes none of the receiver's
   values for them. The receive record lists their paths and its incoming and accepted digests
   differ.
7. A policy payload never contains `varsynconchanges`, and the released receive hook returns `[]`
   for it; the test carries a verbatim copy of the released hook.
8. No probe: a recording double of the XMLRPC client shows a manual `policy` sync calls exactly
   `restore_config_section` once per enabled target, with the payload itself (`installedpackages`
   is its only top-level key) and the configured `varsynctimeout`, and never `exec_php`,
   `exec_shell`, `backup_config_section`, `host_firmware_version`, or
   `merge_installedpackages_section`. `plugin_xmlrpc_send()` makes no client call. The double
   records what a real client would be asked to send; the assertions compare that record with the
   expected method, payload, and timeout, so the test is red if the builder wraps the payload
   again, drops the timeout, or calls another method.
9. Sender state is truthful. In the sender panel only, a `true` return records "sent, acceptance
   unconfirmed", and none of the whole words `supported`, `accepted`, `applied`, or `drifting`, nor
   the phrase `in sync`, appears there. The receiver panel on the same page is excluded because it
   necessarily says accepted and applied, and a whole-word match leaves `unsupported` and
   `acceptance` alone. A null return records the client's error; the automatic path records only
   "handed to pfSense HA sync"; an unreachable target leaves the other targets sent and recorded
   separately.
10. `plugin_xmlrpc_recv_done` marks pending changes and dispatches exactly once for a changed
    policy receive, never for legacy or unchanged receives, and ignores its argument. The receive
    record reads accepted in every case, while the apply record is separate: waiting inside a
    quiet-hours window, failed with the pending marker kept after a failed apply, and applied
    after a completed one.
11. Received-digest suppression holds in every scope. With an accepted digest equal to the current
    policy digest, `pfblockerng_sync_on_changes()` returns before its target loop, so a recording
    client double sees no call, and `plugin_xmlrpc_send()` returns no pfBlockerNG path. Both hold
    for a node whose own scope is `policy`, `all`, or `lists`, whatever scope the sender used, with
    the original sender listed as a manual target and again in automatic mode. Both send after a
    local policy edit changes the digest and after a Sync-page save clears the stored digest. A
    node with no accepted digest produces the pre-change output (criterion 3).
12. The digest ignores key order and local leaves and changes with row order. The receiver records
    drift after a local edit, refusal reasons without touching configuration, and effective-policy
    findings. The copied-object detector stays silent for its own writes and identical copies and
    reports attribute names for differing external copies. With the detector on, the apply writes
    byte-identical aliases, filter rules, and NAT rules compared with the detector off.
13. A receiver whose own scope is `policy`, `all`, or `lists` accepts the same policy payload with
    the same result and, per criterion 11, sends nothing back.
14. The Sync page passes Tier A render for each scope and Tier B coverage for the scope select, the
    receiver panel, and the sender panel; it offers no peer check control.

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
4. **Deletion and empty values.** Deleting a scalar policy setting, one list group, and every group
   in a section on A is reflected on B. A policy leaf stored `''` on A is stored `''` on B. Surviving
   groups keep B's local leaves.
5. **Idempotent repeat.** Resending, including a forced client retry through a short timeout, leaves
   B's `config.xml` unchanged after the first receive, with one apply.
6. **Legacy migration.** Upgrading both nodes from the previous `devel` build, once with the checkbox
   checked and once unchecked, preserves the sync payload and receive result.
7. **Local values and credentials stay local.** With sentinel values in A's six credential leaves,
   Blacklist provider `username` and `password` included, and in every local key, B keeps its own
   after the sync, and B's incoming and accepted digests are equal, which shows A carried none of
   them.
8. **Injected local field.** A request built by the harness with B's credentials and extra
   `inbound_interface` and Blacklist `item` `password` leaves does not change B's values, and B's
   receive record lists those paths.
9. **Mixed versions without a probe.** A new sender in `policy` scope to a B on the previous
   `devel` build leaves B's pfBlockerNG sections byte-identical, sends no call other than
   `restore_config_section`, and shows the target as sent, acceptance unconfirmed. B's other
   sections follow pfSense HA. A previous-build A to a new B keeps legacy behaviour.
10. **No partial mutation on failure.** An injected invalid payload, such as a duplicate `aliasname`,
    leaves B's `installedpackages` byte-identical. B shows the refusal and A shows only sent,
    acceptance unconfirmed.
11. **Copied `pfB_*` rule detection.** With a different `inbound_interface` on B, B reports the
    affected `pfB_*` rules and the `interface` attribute. With equal values, it reports nothing.
12. **Authority.** CARP demotion of A makes B originate nothing. If B lists A as a manual target, a
    receive from A causes no send back, whether B's own scope is `policy`, `all`, or `lists`, and
    A's receive records show none from B. Saving B's Sync page afterwards (a deliberate role flip)
    lets B's next send reach A, and so does a later local policy edit on B. With two manual
    targets and one unreachable, the reachable target updates and status is recorded per target.
13. **Reachability.** With B unreachable, the manual target records the client's transport error on
    A; in automatic mode A's package records only that paths were handed to pfSense HA sync, and
    pfSense reports the failure.
14. **Receiver scope.** B with its own scope set to `lists` still accepts A's `policy` payload.

## Out of scope

- pfSense core changes, including what pfSense HA copies, how it authenticates, and any `nosync`
  flag or re-ownership of copied `pfB_*` objects.
- Backporting to `release/3.3`.
- Any probe, status call, or readback of a peer (`exec_php`, `backup_config_section`), any display
  of a peer's state on the sender, and any digest comparison across nodes.
- Per-field operator selection, chained relays (A → B → C), multi-master merging, and conflict
  resolution.
- Synchronizing `pfblockerngsync` itself (targets, credentials, scope), runtime data, databases,
  downloads, or logs.
- Atomicity across targets; each target succeeds or fails independently.
- Separating secrets embedded in feed URLs from list policy.
- Changing legacy-scope behaviour, including the legacy hook's existing `xmlrpc_recv_result`
  return, other than the stated received-digest suppression on a node that holds an accepted
  digest.

## Open forks

None.

### Decision provenance

Each fork was resolved by the owner (andrebrait) on
[#3443](https://github.com/pfBlockerNG/pfBlockerNG/issues/3443):

| Fork | Resolution | Source |
| --- | --- | --- |
| 1. Copied `pfB_*` objects | pfSense keeps copying; pfBlockerNG reports incompatible copies and re-owns nothing | [comment, 2026-10-05](https://github.com/pfBlockerNG/pfBlockerNG/issues/3443#issuecomment-5985989968) |
| 2. Capability and status | No probe; peer status, drift, and findings are receiver-reported | [comment, 2026-10-04](https://github.com/pfBlockerNG/pfBlockerNG/issues/3443#issuecomment-5985714324) |
| 3. Receiver opt-in | The sender's scope is authoritative; the receiver's scope controls only its own sends | [comment, 2026-10-05](https://github.com/pfBlockerNG/pfBlockerNG/issues/3443#issuecomment-5985989968) |
| 4. Lists-only scope | Kept indefinitely with the #3441 warning | [comment, 2026-10-05](https://github.com/pfBlockerNG/pfBlockerNG/issues/3443#issuecomment-5985989968) |
| 5. Credentials | Provider credentials stay local and never travel in a policy payload | [comment, 2026-10-04](https://github.com/pfBlockerNG/pfBlockerNG/issues/3443#issuecomment-5985787784) |

Fail-closed mixed-version behaviour is the 2026-10-04 owner
[decision](https://github.com/pfBlockerNG/pfBlockerNG/issues/3443#issuecomment-5984708704), as
clarified for the probe-free design in the map's Decisions so far. Sender authority and the facts
behind the blocking list are in
[BBcan177's review](https://github.com/pfBlockerNG/pfBlockerNG/issues/3443#issuecomment-5981971807).
