# Reversible pfBlockerNG settings transitions between v3.2 and v4

This specification resolves wayfinder map
[Specify reversible pfBlockerNG settings transitions between v3.2 and v4](https://github.com/pfBlockerNG/pfBlockerNG/issues/1596)
and its decision tickets. Later resolution addenda and the map's lifecycle-ordering
correction supersede earlier compatibility-release recommendations.

## Goal

Make pfBlockerNG settings transitions between schema families `3.2` and `4.0`
reversible without losing settings, credentials, unrelated pfSense configuration, or the
ability to recover from an interrupted package operation.

The result protects the first upgrade from genuine, unmodified Stable `v3.2.15` and Devel
`v3.2.16`, supports a v4-owned downgrade to either frozen target, restores the saved v4
settings on re-upgrade, and leaves existing package migrations and resync as the only
forward-transformation and runtime-reconstruction mechanisms.

## Fixed constraints

- The initial supported boundary is settings schema family `3.2` ↔ `4.0`. Major-version
  transitions are protected. A minor-version transition is protected only when explicitly
  declared schema-incompatible.
- Stable and Devel package names share a settings schema family. Channel and package name
  are provenance and package-selection facts, not restore identity.
- There is no v3 bridge/compatibility release and no transition, restore, or Software-page
  code backported into v3.x. Frozen targets use the original Stable `v3.2.15` and Devel
  `v3.2.16` payloads and lifecycle behavior.
- Every supported build-matrix architecture remains supported, including ARM64
  (`aarch64` in package ABIs). Architecture never gates or changes downgrade behavior.
- A settings snapshot is lossless and appliance-local. It includes credentials and every
  direct child of `<installedpackages>` whose element name starts with `pfblockerng`.
  Package-registration metadata, wizard scratch state, unrelated pfSense settings,
  generated aliases/rules, databases, logs, downloads, and runtime files are excluded.
- Snapshot and journal storage is root-only under `/cf/conf/pfblockerng/`. It is never HA
  synchronized, sanitized, or exposed as a downloadable diagnostic artifact.
- Existing package install migrations remain the sole forward transformers. Existing
  install/resync code remains the sole builder of VIPs, aliases, rules, DNSBL state, and
  other generated/runtime state.
- Package lifecycle scripts and transition helpers are noninteractive. They never prompt,
  read, or wait on stdin. Missing, corrupt, incompatible, or contradictory identity fails
  closed with Package Manager output, logs, and a pfSense notification.
- A matching-family pfSense restore-driven reinstall preserves active settings and runs
  normal idempotent migrations/resync without confirmation.
- Exact environment value `PFB_BYPASS_UPGRADE_VERSION_CHECKS=1` bypasses only legacy source
  eligibility. Every snapshot, read-back, integrity, target, and journal check remains
  mandatory. No other value authorizes the transition.
- v4 and later packages protect every normal scripted package path. Explicit pkg script
  bypasses such as `--no-scripts` or `--script-no-exec` are unsupported.
- The one package-path exception is v4 → unmodified legacy v3.2: it is supported only
  through the v4 Maintenance page or shipped transition runner. Direct Package Manager or
  raw `pkg` downgrade into v3.2 is unsupported.
- No transition merges independently changed settings. Leaving a family saves its current
  state; entering a previously activated family restores only that family's verified head.
- Registered configuration fields use `PfbConfig`. Whole owned-subtree capture and
  replacement is a structural transition operation; it must not create a second scalar
  configuration gateway.
- Implementation obeys the appliance language boundary: PHP or POSIX shell only; no new
  appliance Python.

## Decisions

### Settings identity and snapshot format

- An explicit settings schema-family marker such as `3.2` or `4.0` travels with the
  pfBlockerNG-owned settings. It is distinct from package release, channel, and name.
- A fresh install with no owned settings is valid. Owned settings without a marker are
  legacy input and fail before mutation unless the exact legacy-bootstrap bypass is set.
- A snapshot is a gzip-compressed XML wrapper containing:
  - snapshot-format version;
  - settings schema family;
  - exact source package name and version;
  - UTC creation time;
  - SHA-256 of the owned-settings payload; and
  - unchanged copies of the complete owned-section set.
- Snapshots live under
  `/cf/conf/pfblockerng/settings-snapshots/<schema-family>/`, with `0700` directories and
  `0600` files.
- Creation uses the transition lock, a same-directory temporary file, durable flush,
  gzip validation, decompression/XML parse, payload checksum comparison, exact read-back,
  and atomic publication. Failure leaves active configuration and existing snapshots
  unchanged.
- Restore validates compression, XML, snapshot format, checksum, requested schema family,
  package/target identity, and the complete owned-section set before mutation. It
  atomically replaces all current owned sections through pfSense configuration APIs,
  rereads them, and verifies exact parsed equality. It never falls back to an older
  snapshot or an empty configuration.
- Identical payloads deduplicate by SHA-256. Every distinct snapshot in a retained family
  remains recovery history; only the verified family head is selected automatically.

### First genuine v3.2 upgrade ordering

The v4 package adds protection at the earliest ordering-compatible package boundary:

1. v4 `PRE-INSTALL` runs before the frozen v3 package's cleanup.
2. With unversioned owned settings and no exact bypass, it rejects the attempt before
   settings, schema, journal, or package-payload mutation and prints the exact retry
   command.
3. On the authorized retry, it locks the transition, losslessly snapshots and read-back
   verifies the legacy owned settings, publishes the durable journal, records schema family
   `3.2`, and seeds an absent legacy `pfb_keep='on'`.
4. An existing `pfb_keep='on'` or explicit `pfb_keep='off'` is not rewritten. The verified
   snapshot and journal protect the explicit-off case even if frozen v3 cleanup removes
   the active owned sections.
5. Only after the verified snapshot and journal are durable may `PRE-INSTALL` succeed and
   frozen v3 cleanup/package replacement proceed.
6. v4 `POST-INSTALL` restores or verifies the journal-selected settings before any current
   migration or resync runs.
7. Existing v4 migrations then perform the forward transformation, resync reconstructs
   runtime state, final settings are verified, and the journal completes.

This is the supported first-transition mechanism. A v3 bridge release, an external
downloaded preflight, and the current post-install-only `pfb_keep` migration are not
substitutes.

### Durable journal and recovery

The write-ahead journal binds source and target package identities, schema families,
snapshot hashes, action, exact target artifact/checksum, and any one-shot authorization.
It is durable before `PRE-INSTALL` or the legacy runner crosses its mutation boundary.

| Phase | Durable meaning | Recovery |
| --- | --- | --- |
| `prepared` | Source snapshot and target action are verified. | If source remains installed, retry or abandon safely. If target is present, continue. |
| `settings-applying` | Target is present and owned-settings replacement/clear is about to run. | Source-equal live state may apply the target; target-equal live state may continue; any third state requires manual recovery. |
| `settings-applied` | Target settings input is exact and verified. | Rerun idempotent target migrations/resync; never restore again. |
| `complete` | Settings read-back, migrations, and resync succeeded. | Record target activation baseline, prune eligible history, clear the journal, and publish recovered live status without changing prior notices. |

- Snapshot publication/read-back, journal publication, configuration replacement/read-back,
  package execution, and migration/resync dispatch are separate durable boundaries.
- Failure before settings mutation aborts the package operation without changing active
  settings.
- Failure after package commit retains the journal, skips unsafe later settings writes and
  resync, preserves last generated runtime state where possible, and resumes from the
  recorded phase.
- Unknown journal versions/phases, identity or hash contradictions, or live settings equal
  to neither journaled endpoint require administrator-directed recovery.

### Transition behavior

- **First v3.2 → v4:** snapshot genuine v3.2, preserve or restore it as v4 migration input,
  run existing migrations, and record the migrated v4 activation baseline. No v4 snapshot
  is expected; this is not divergence.
- **Same-family reinstall or channel replacement:** preserve active matching-family
  settings, perform no restore/clear, require no confirmation, and run normal
  migrations/resync. Cross-name package failure preserves settings and snapshots.
- **First fresh-v4 → v3.2:** snapshot v4, require explicit one-shot authorization bound to
  the exact target package/version/checksum, clear only active pfBlockerNG-owned settings,
  and start v3.2 unconfigured. Confirmation occurs before native package execution.
- **Previously activated target family:** snapshot and verify the family being left, then
  restore only the verified head of the target family. Missing, corrupt, or wrong-family
  head state is fatal.
- **v4 → legacy v3.2:** the shipped v4 runner prepares the snapshot/journal, restores the
  v3.2 head or performs the authorized clear, verifies active state, and only then installs
  the exact frozen package. It owns recovery because frozen v3 has no restore consumer.
- **Repeated v3.2 → v4:** snapshot current v3.2, restore the saved v4 head before current
  migrations/resync, and never merge the two families.
- Exact package selection uses a validated normal-catalog artifact and forced
  version-qualified install. The runner rejects any artifact whose embedded package name,
  version, ABI, source identity, or checksum differs from the selected frozen target.

### Divergence, retention, and uninstall

- Entering a family records the final post-migration settings hash as its activation
  baseline.
- Leaving a family whose live hash changed creates a new verified source snapshot, restores
  the target head without merging, and sends a notification. Producer-owned transition
  state records the exact source and target snapshot hashes.
- That transition state suppresses only the exact hash pair and survives reboot. A later
  pair sends a new notification. Recovery updates live transition status only and sends no
  recovery notification. Emission is a one-way handoff; transition code never queries,
  mutates, dismisses, or otherwise uses the notification as storage.
- Keep all distinct snapshots for the active family and the three most recent prior schema
  families. Prune a whole oldest family only after the new family's settings,
  migrations, and resync have completed successfully.
- Genuine uninstall with Keep Settings enabled retains `/cf/conf/pfblockerng/`, including
  snapshots, journal/recovery state, and acknowledgements.
- Genuine uninstall with Keep Settings disabled deletes that entire owned state tree with
  the existing settings/data wipe. Merely saving Keep Settings as disabled while installed
  does not delete transition state.

### Frozen packages and catalog retention

- Build genuine Stable `v3.2.15` and Devel `v3.2.16` packages from the original tagged
  payloads for every active build-matrix ABI/catalog path. Packaging may wrap the historical
  payload for a current ABI, but must not alter its shipped v3 settings or lifecycle logic.
- Artifact identity includes source tag/commit, package name/version, ABI, catalog path,
  and checksum. Publication rejects missing, duplicate, mismatched, or silently rebuilt
  identities.
- Each normal catalog retains the newest 10 Stable and newest 10 Devel releases, plus the
  newest package from every pfBlockerNG major/minor line for each package channel. The
  per-line pins keep `v3.2.15` Stable and `v3.2.16` Devel available after they age out of
  the rolling windows.
- A route-only/EOL pfSense family freezes its final compatible catalog: current
  Stable/Devel, rolling rollback window, and every per-pfBlockerNG-line pin. It is served
  from immutable Release assets and is not regenerated from newer builds.
- No isolated compatibility repository, v3 source line, global release-tag classifier
  change, or branch-independent release system is introduced.

### Maintenance and Downgrade UI

- The existing Software surface becomes a Maintenance workspace. Existing general software
  operations remain under Operations; sanitized diagnostic-export implementation remains
  separate.
- Downgrade offers exactly:
  - Stable `pfSense-pkg-pfBlockerNG-3.2.15`; and
  - Devel `pfSense-pkg-pfBlockerNG-devel-3.2.16`.
- The selected target defaults to the installed package's current channel. One Downgrade
  action is enabled only after the administrator types the exact selected package
  name/version.
- The page explains whether it will restore a verified v3.2 head or preserve v4 and start
  v3.2 unconfigured. Confirmation and exact-target binding complete before package
  execution begins.
- Downgrade shows current journal/recovery status, verified family heads, older recovery
  history, and divergence state without exposing snapshot contents or credentials.
  Contradictory identity/hash state locks the action and points to manual recovery.
- The Downgrade tab and every downgrade render/dispatch path require both normal
  pfBlockerNG Software-page authorization and pfSense Package Manager Installed-page
  authorization. Both checks are server-side. The Maintenance shell, Operations, and other
  maintenance actions do not inherit the Package Manager gate.
- “Diagnostic export” means a downloadable sanitized support artifact.
  “Settings snapshots” means lossless, internal, credential-bearing transition artifacts.
  The UI never calls a settings snapshot a sanitized backup or offers it for download.
- The page invokes the shipped runner, which delegates package execution to the native
  package flow so progress and output survive pfBlockerNG package replacement.

### Verification model

- PHPUnit exhaustively verifies settings, snapshot, journal, restore, retention,
  divergence, uninstall, and recovery behavior off-box with pfSense API doubles.
- PHPUnit fixtures are minimal temporary `config.xml` documents containing representative
  owned sections, unrelated pfSense sections, unknown future fields, credentials, and empty
  nodes.
- The oracle is exact parsed owned-subtree equality—element names, ordering, values, unknown
  fields, credentials, and empty nodes—and structural equality of every unrelated pfSense
  subtree. Whole-file byte equality is not required because pfSense may reserialize XML.
- ShellSpec verifies only lifecycle/runner orchestration, noninteractive behavior, exact
  command arguments, durable-boundary ordering, and exit propagation. It does not duplicate
  the PHP state machine.
- Configuration coverage uses one canonical `3.2 → 4.0 → 3.2 → 4.0` round trip plus focused
  state/failure cases. Stable/Devel, CE/Plus, and CPU architecture do not form a
  configuration cross-product.
- Failure is injected at every durable boundary and recovery starts from every journal
  phase. There is no live failure-injection matrix.
- Live fan-out is derived dynamically from every version-matrix entry with `ci:true`,
  `arch: amd64`, and CE or Plus identity. No version literals or “one CE/one Plus”
  assumptions are hardcoded.
- Every selected live leg runs one focused genuine-package
  `v3.2 → v4 → v3.2 → v4` sequence. Across that sequence it installs both original v3.2
  channel packages, crosses the frozen-v3 cleanup boundary, exercises a supported
  cross-channel destination, and proves the saved v4 head returns.
- The live fixture triggers the four registered migrations together:
  `adr02-dnsbl-python-mode`, `pfbl03-control-legacy-seed`,
  `adr22-dnsbl-lenient`, and `issue281-pfb-keep-seed`. It also carries preserved canaries
  and credentials.
- Every live leg asserts migration results, exact owned-settings restoration, unchanged
  unrelated pfSense subtrees, schema markers, verified family heads, cleared/completed
  journal state, package identity, and representative runtime behavior.
- Tier-A `ui_render` and the Tier-B downgrade interaction run on every selected live leg.
- The existing smoke test that re-versions one current package remains a current-hook
  regression test only. It is never cited as evidence for the genuine v3.2 boundary.

## Acceptance criteria

1. A first unversioned genuine `v3.2.15` or `v3.2.16` upgrade without the exact bypass
   fails before frozen-v3 cleanup and prints the exact retry command.
2. On the authorized retry, v4 `PRE-INSTALL` snapshots and verifies every owned setting,
   publishes the journal, and seeds only an absent legacy `pfb_keep='on'` before frozen-v3
   cleanup. `POST-INSTALL` restores/verifies before migrations and resync.
3. Off-box tests prove the first upgrade for `pfb_keep` absent, explicitly `on`, and
   explicitly `off`, using genuine historical lifecycle/package inputs rather than a
   re-versioned current payload.
4. Minimal temporary `config.xml` fixtures prove exact parsed equality of the complete
   owned subtree, including credentials, unknown fields, order, and empty nodes; unrelated
   pfSense subtrees remain structurally unchanged.
5. Snapshot creation and restore fail closed on bad compression, XML, checksum, schema
   family, package identity, target identity, permissions, publication, or read-back.
   Secrets never appear in output, notices, logs, or test diagnostics.
6. PHPUnit covers the canonical round trip and each focused state: fresh v4; legacy reject
   and exact-bypass bootstrap; same-family/channel replacement; first unconfigured
   downgrade; repeated transition; divergence/acknowledgement; missing/corrupt/wrong-family
   or contradictory state; restore-driven reinstall; retention; and both Keep Settings
   uninstall outcomes.
7. Failure injection covers snapshot publication/read-back, journal publication,
   configuration replacement/read-back, package execution, and migration/resync dispatch;
   recovery succeeds or fails as specified from `prepared`, `settings-applying`,
   `settings-applied`, and `complete`.
8. ShellSpec proves PRE-INSTALL-before-old-cleanup and POST-INSTALL-before-migration/resync
   ordering, exact target command construction, noninteractive execution, lock handling,
   signal/exit propagation, and resumable runner behavior.
9. Frozen original Stable `v3.2.15` and Devel `v3.2.16` artifacts exist and validate for
   every active build-matrix ABI/catalog path, including `aarch64`; source identity,
   package metadata, ABI, and checksums match the declared matrix.
10. Catalog tests prove newest-10 Stable, newest-10 Devel, per-major/minor channel pins, and
    route-only final-catalog freezing, including the two permanent v3.2 targets.
11. The Downgrade UI exposes only the two exact targets, defaults to current channel,
    requires exact typed confirmation, enforces both authorizations before render and
    dispatch, and never exposes snapshot contents or secrets.
12. Every dynamically selected `ci:true` amd64 CE/Plus leg completes one focused genuine
    `v3.2 → v4 → v3.2 → v4` sequence, proves all four representative migrations and
    restoration invariants, exercises Tier A and Tier B, and leaves no active journal.
13. Direct legacy downgrade through Package Manager/raw `pkg`, target tampering, and
    unauthorized/CSRF dispatch fail without changing settings or starting package
    execution. Supported matching-family restore-driven reinstall remains noninteractive.
14. All canonical code, test, package, catalog, UI, and live gates named by the three
    implementation tickets pass. No acceptance claim relies on a synthetic package that
    merely re-versions the current payload.

## Out of scope

- Implementing, building, publishing, or releasing packages while authoring this
  specification.
- A v3 bridge release, v3 transition/restore consumer, or v3 Software-page backport.
- Arbitrary-version rollback or schema-family support beyond the declared `3.2` ↔ `4.0`
  boundary.
- Automatic merging of settings changed independently in two families.
- Backing up/restoring unrelated pfSense settings or pfBlockerNG generated/runtime data.
- Sanitized diagnostic-export implementation or reconciliation of its separate privilege
  specification.
- A live failure-injection cross-product, ARM live-VM gate, or channel/edition/architecture
  configuration cross-product.
- Changing global release-tag classification, making release behavior branch-independent,
  or restoring the former release-with-changelog skill.
- General package-manager hardening against administrators who explicitly disable package
  scripts.

## Open forks

None.
