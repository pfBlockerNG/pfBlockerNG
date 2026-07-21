# Package lifecycle and exact-version downgrade mechanics

## Outcome

The settings protection belongs in package lifecycle scripts, not only in the Software page.
The package's `+INSTALL` script is run by libpkg for `PRE-INSTALL` and `POST-INSTALL` on an
install, upgrade, downgrade, or forced reinstall. A non-zero `PRE-INSTALL` result aborts before
payload extraction and before the old same-name package's pre-deinstall hook, so this is the
load-bearing fail-closed backup point. The current pfSense port script deliberately ignores every
phase except `POST-INSTALL`; both the v3.2 compatibility packages and v4 packages must extend that
script.

The exact repository-backed downgrade command is:

```sh
pkg install -y -f pfSense-pkg-pfBlockerNG-<exact-version>
pkg install -y -f pfSense-pkg-pfBlockerNG-devel-<exact-version>
```

`-f` is required. `pkg install <name>-<older-version>` resolves the exact catalogue row, but the
solver otherwise rejects it because it is not an upgrade. The pfSense Package Manager already
accepts the version-qualified string and its `reinstallpkg` mode supplies `-f`; therefore the v4
Software page can remain a thin link to:

```text
/pkg_mgr_install.php?mode=reinstallpkg&pkg=<urlencoded-name-version>
```

The selected v3.2 package must remain in the active repository catalogue. Stable and devel are
different package names in the same repository. Existing live-VM coverage proves installing one
file-overlapping package replaces the other in both directions without `-f`, so adding `-f` for an
exact target also supports stable ↔ devel transitions.

Store snapshots under a private pfBlockerNG directory in pfSense's persistent configuration
filesystem, e.g. `/cf/conf/pfblockerng/`, not `/var`, `/tmp`, the package payload, or the rotating
whole-config backup directory. Use pfSense's `safe_write_file()` for temp-file + fsync + rename +
directory-fsync publication, plus a named `lock()` around snapshot read/compare/write. Validate a
freshly written snapshot by reading and parsing it before returning success; only then may the
pre-install hook exit zero. Use mode `0700` for the directory and `0600` for files because the
captured settings include credentials.

## Verified lifecycle ordering

### libpkg same-name install, upgrade, downgrade, and forced reinstall

For an already installed same-name package, libpkg routes the candidate through `pkg_add_upgrade()`.
The order in `pkg_add_common()` is:

1. Open and validate the new package archive.
2. Begin/register the new package in the database transaction.
3. Run the new package's `PRE-INSTALL` script. `PKG_UPGRADE=true` is present whenever a local
   same-name package exists, including downgrade and forced reinstall.
4. Extract new payload files into libpkg's staged/temp paths.
5. Run the old package's `DEINSTALL` (pre-deinstall) script.
6. Remove files absent from the new package.
7. Finalize extracted files and package database registration.
8. Run the new package's `POST-INSTALL` script.

The script runner supplies `$1` as `<new-name>-<new-version>` and `$2` as `PRE-INSTALL`,
`POST-INSTALL`, `DEINSTALL`, or `POST-DEINSTALL`. It also exports `PKG_NAME`, `PKG_PREFIX`, and
`PKG_ROOTDIR`. `PKG_UPGRADE` only says that a local same-name package exists; it does not distinguish
upgrade, downgrade, and reinstall. Direction must be derived from the installed source identity and
the target identity, not from `PKG_UPGRADE` alone.

Sources:

- [libpkg add/upgrade ordering](https://github.com/freebsd/pkg/blob/a8f08f97943305c778ee863e4c7db8d0832e7504/libpkg/pkg_add.c#L1688-L1790)
- [legacy lifecycle argument and environment mapping](https://github.com/freebsd/pkg/blob/a8f08f97943305c778ee863e4c7db8d0832e7504/libpkg/scripts.c#L74-L142)
- [script exit-status handling](https://github.com/freebsd/pkg/blob/a8f08f97943305c778ee863e4c7db8d0832e7504/libpkg/scripts.c#L252-L310)

### Delete and cross-package replacement

A standalone delete runs the old package's `DEINSTALL`, removes files, then runs
`POST-DEINSTALL`. In normal mode, libpkg logs but ignores non-zero deinstall-script results; only
developer/no-exec modes propagate them. Therefore a deinstall hook is useful as a redundant backup
attempt, but it is not a reliable fail-closed gate.

Stable/devel switching is a solver transaction between different package names. File conflicts can
schedule removal of the installed name and installation of the target name as separate actions.
This means the target package's `PRE-INSTALL` remains the authoritative backup gate for the active
settings, but on a cross-name failure the old package may already have been removed. Settings remain
available because current pfBlockerNG detects the ancestor operation as `install` and skips its
destructive uninstall path. The Software page should perform the same backup preflight before
dispatch for cleaner UX, while lifecycle `PRE-INSTALL` repeats and verifies it for native Package
Manager and CLI paths.

Sources:

- [libpkg delete ordering and ignored normal-mode hook failures](https://github.com/freebsd/pkg/blob/a8f08f97943305c778ee863e4c7db8d0832e7504/libpkg/pkg_delete.c#L67-L141)
- [job execution order](https://github.com/freebsd/pkg/blob/a8f08f97943305c778ee863e4c7db8d0832e7504/libpkg/pkg_jobs.c#L2069-L2167)
- [pfBlockerNG operation detection and teardown decision](https://github.com/pfBlockerNG/pfBlockerNG/blob/0146ecbb7645d3673dd51a24a4561b026b50f210/src/usr/local/pkg/pfblockerng/pfblockerng.inc#L4614-L4647)
- [pfBlockerNG pre-deinstall skip on install/upgrade/reinstall](https://github.com/pfBlockerNG/pfBlockerNG/blob/0146ecbb7645d3673dd51a24a4561b026b50f210/src/usr/local/pkg/pfblockerng/pfblockerng.inc#L16663-L16681)
- [live-VM stable-name/nightly-name replacement oracle](https://github.com/pfBlockerNG/pfBlockerNG/blob/0146ecbb7645d3673dd51a24a4561b026b50f210/tests/smoke/test_nightly_install.py#L247-L277)

### pfSense package bridge

The standard pfSense `pkg-install` script currently invokes `/etc/rc.packages` only for
`POST-INSTALL`; the standard deinstall script forwards both deinstall phases. `rc.packages` maps
`POST-INSTALL` to `install_package_xml()`, and maps `DEINSTALL`/`POST-DEINSTALL` to
`delete_package_xml()`.

`install_package_xml()` then performs pfSense package registration, the XML
`custom_php_install_command`, `custom_php_resync_config_command`, menu/service/plugin registration,
and a final `write_config()`. For pfBlockerNG the custom install command includes
`pfblockerng_install.inc`, whose first migration call can mutate v3 settings. Restore must therefore
happen in the package `POST-INSTALL` script **before** it calls `rc.packages`; restoring from within
the current custom install hook would be too late.

`rc.packages` exits without work when PHP-FPM is not running. Backup/restore cannot depend solely on
that bridge: the lifecycle script must invoke a small direct PHP helper for `PRE-INSTALL` and for
restore at the beginning of `POST-INSTALL`, then call the existing `rc.packages` bridge. The v3.2
compatibility package's new helper is thus available after extraction when its `POST-INSTALL` runs;
the v4 `PRE-INSTALL` logic must be self-contained in package metadata or invoke a helper guaranteed
to exist in the compatibility source package.

Sources:

- [standard pfBlockerNG install script](https://github.com/pfsense/FreeBSD-ports/blob/a621624266b19a7f48b1f94a60821d2c2fc6ee4c/net/pfSense-pkg-pfBlockerNG-devel/files/pkg-install.in)
- [standard pfBlockerNG deinstall script](https://github.com/pfsense/FreeBSD-ports/blob/a621624266b19a7f48b1f94a60821d2c2fc6ee4c/net/pfSense-pkg-pfBlockerNG-devel/files/pkg-deinstall.in)
- [pfSense lifecycle dispatch](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/rc.packages#L27-L78)
- [pfSense package XML install ordering](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/pkg-utils.inc#L795-L981)
- [pfBlockerNG install command and resync registration](https://github.com/pfBlockerNG/pfBlockerNG/blob/0146ecbb7645d3673dd51a24a4561b026b50f210/src/usr/local/pkg/pfblockerng.xml#L81-L100)

## Safe and unsafe abort points

| Point | Non-zero honored? | State when it runs | Use |
| --- | --- | --- | --- |
| New `PRE-INSTALL` | Yes | Before payload extraction and old same-name pre-deinstall | Mandatory fail-closed snapshot creation and verification |
| Old `DEINSTALL` during same-name replacement | No in normal mode | After new payload staging, before old-only file removal/finalization | Redundant snapshot/logging only; never sole gate |
| New `POST-INSTALL` | No in normal mode | New payload and database already finalized | Restore, divergence notice, and setup; failure is recoverable but package transaction is already committed |
| pfSense XML custom install/resync | PHP failure can interrupt wrapper, but after pkg commit | Package files installed; pfSense registration/config work in progress | Must consume already restored settings, not perform first restore |

The backup failure requirement is enforceable at `PRE-INSTALL`. Restore failure cannot roll back the
already committed package replacement; it must leave the active settings and every snapshot intact,
emit a hard error, and skip migration/resync where possible. A recovery command or next package run
can retry the idempotent restore.

## Exact version and channel invocation

The official `pkg-install(8)` syntax accepts `pkg-name-version` and `-r reponame`. Its exact query
matches either `name` or `name || '-' || version`. However, the solver only selects a lower exact
version when force is set: without force, `pkg_jobs_need_upgrade()` rejects `local > remote`; with
force, all matching candidates enter the universe.

- [pkg-install syntax and repository selector](https://github.com/freebsd/pkg/blob/a8f08f97943305c778ee863e4c7db8d0832e7504/docs/pkg-install.8#L21-L35)
- [exact name-version database predicate](https://github.com/freebsd/pkg/blob/a8f08f97943305c778ee863e4c7db8d0832e7504/libpkg/pkgdb_query.c#L45-L112)
- [exact version candidate filtering](https://github.com/freebsd/pkg/blob/a8f08f97943305c778ee863e4c7db8d0832e7504/libpkg/pkg_jobs.c#L784-L817)
- [force versus downgrade rejection](https://github.com/freebsd/pkg/blob/a8f08f97943305c778ee863e4c7db8d0832e7504/libpkg/pkg_jobs_universe.c#L1054-L1124)

pfSense validates package arguments with `^pfSense-pkg-[a-zA-Z0-9._-]+$`, so an exact
name-version is accepted. `reinstallpkg` builds `-i <argument> -f` for `pfSense-upgrade`, exactly the
force needed for downgrade. The page also creates a whole-config restore point before dispatch, but
that is not a substitute for the version-keyed pfBlockerNG-only snapshot.

- [Package Manager validation](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/pkg-utils.inc#L54-L60)
- [Package Manager modes and dispatcher arguments](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/usr/local/www/pkg_mgr_install.php#L591-L682)
- [current Software-page delegation pattern](https://github.com/pfBlockerNG/pfBlockerNG/blob/0146ecbb7645d3673dd51a24a4561b026b50f210/src/usr/local/www/pfblockerng/pfblockerng_software.php#L191-L227)

Do not add `-r` for normal stable/devel selection: both live in the shared `pfblockerng` repository,
and the exact package name chooses the channel. Pin and display the target `name`, `version`, repo,
and checksum before confirmation so a catalogue refresh cannot silently change the requested
downgrade. The implementation must verify the exact target still resolves immediately before
dispatch.

## Durable storage and atomicity

pfSense declares `/conf` and `/cf/conf` as configuration storage. Core writes `config.xml` and its
rotating backups under `/cf/conf`, while `/var` and `/tmp` are runtime paths. Existing pfBlockerNG
also documents `/usr/local/etc` as reboot-persistent, but that tree is within the package/software
prefix and is a weaker ownership boundary than `/cf/conf` for snapshots that must outlive package
replacement.

`safe_write_file()` provides the needed atomic publication sequence: same-directory PID temp file,
full write, file `fsync`, rename, then directory `fsync`. It does not lock callers or apply private
permissions. Use a dedicated named `lock()` and explicitly set permissions. Do not put snapshots in
`/cf/conf/backup`: core rotates and indexes that directory as whole-configuration restore points.

Restoring the settings must mutate only `installedpackages` keys whose names start with
`pfblockerng`, under the core `config` exclusive lock, then call `write_config()` once. The current
package already defines full removal by dynamically enumerating exactly that prefix, confirming the
ownership boundary.

- [pfSense persistent/runtime path definitions](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/globals.inc#L58-L78)
- [atomic `safe_write_file()`](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/config.lib.inc#L476-L540)
- [locked atomic config write](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/config.lib.inc#L1240-L1273)
- [core backup directory ownership](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/config.lib.inc#L959-L982)
- [dynamic pfBlockerNG settings boundary](https://github.com/pfBlockerNG/pfBlockerNG/blob/0146ecbb7645d3673dd51a24a4561b026b50f210/src/usr/local/pkg/pfblockerng/pfblockerng.inc#L16877-L16894)

## Notifications and observable failures

Use `file_notice('pfBlockerNG', ..., 'pfBlockerNG',
'/pfblockerng/pfblockerng_software.php', 2)` for divergence or restore failure, plus stdout/stderr and
syslog. `file_notice()` queues a dismissible pfSense notice and fans out to configured remote
notification transports. Its queue is under `/tmp/notices`, so the notice itself is not durable
across reboot. Durable snapshot metadata must retain the unresolved divergence/failure marker and
re-file the notice from post-install or the Software page until acknowledged.

- [pfSense `file_notice()` behavior](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/notices.inc#L88-L149)
- [temporary notice queue path](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/notices.inc#L25-L34)

## Coverage boundary for every package path

Lifecycle scripts are embedded in the package and therefore run for the Software-page shortcut,
native pfSense Package Manager, direct `pkg install`, `pkg upgrade`, exact downgrade, and forced
reinstall. This is the only common seam.

Two explicit bypasses cannot be prevented by package code:

1. `pkg install -I` / `pkg upgrade -I` (`--no-scripts`) suppresses install and deinstall scripts.
2. `pkg add -I` or `--script-no-exec` likewise suppresses execution.

These are administrator override/debug paths and must be documented as unsupported for protected
v3.2 ↔ v4 transitions. The supported UI/CLI commands must never use these flags. A raw manual file
replacement is outside pkg lifecycle entirely.

The current standard `rc.packages` bridge has another gap: it exits when PHP-FPM is down. Direct PHP
backup/restore calls in the package lifecycle script close that gap for normal pkg transactions;
the existing `rc.packages` call may continue handling pfSense package registration when available.

- [pkg `--no-scripts` semantics](https://github.com/freebsd/pkg/blob/a8f08f97943305c778ee863e4c7db8d0832e7504/docs/pkg-install.8#L148-L158)
- [pkg-add script suppression](https://github.com/freebsd/pkg/blob/a8f08f97943305c778ee863e4c7db8d0832e7504/docs/pkg-add.8#L75-L107)

## Required implementation probes

Before implementation locks the protocol, execute these on the CE and Plus smoke variants with
forged v3/v4 packages:

1. Same-name `v3 → v4`, `v4 → v3`, and forced same-version reinstall; capture lifecycle marker order
   and prove a failing `PRE-INSTALL` leaves source package/config untouched.
2. Cross-name stable ↔ devel in both directions; capture whether solver removal precedes target
   `PRE-INSTALL`, then prove backup failure leaves all settings and snapshots intact even if no
   package remains installed.
3. Invoke each transition through Software page, native Package Manager, `pkg install -f
   name-version`, and `pkg upgrade`; prove one backup/restore protocol and identical effective state.
4. Stop PHP-FPM and run the exact transition; prove direct lifecycle backup/restore still occurs and
   document how pfSense package registration is reconciled on boot.
5. Force disk-full, unwritable directory, corrupt snapshot, truncated snapshot, checksum mismatch,
   and interrupted publication; verify no migration begins after a failed backup and no partial
   restore reaches `config.xml`.

## Evidence commands run

The investigation used immutable source revisions and local history:

```text
git -C /private/tmp/pkg-1597 rev-parse HEAD
=> a8f08f97943305c778ee863e4c7db8d0832e7504

gh api repos/pfsense/pfsense/commits/master --jq .sha
=> 9363ac5b8651a1c7a333180425ce7719070f95f9

gh api repos/pfsense/FreeBSD-ports/commits/devel --jq .sha
=> a621624266b19a7f48b1f94a60821d2c2fc6ee4c

git rev-parse HEAD
=> 0146ecbb7645d3673dd51a24a4561b026b50f210
```

Source inspection commands included `rg`/`sed` over `libpkg/pkg_add.c`, `pkg_delete.c`,
`pkg_jobs.c`, `pkg_jobs_universe.c`, `scripts.c`, `pkgdb_query.c`, official pfSense
`pkg_mgr_install.php`, `pkg-utils.inc`, `rc.packages`, `config.lib.inc`, `globals.inc`, and
`notices.inc`, plus the official FreeBSD-ports stable/devel pfBlockerNG port files and this
repository's lifecycle smoke tests.

## Newly surfaced decisions

1. Specify the self-contained pre-extraction helper strategy. A new package's payload is unavailable
   at `PRE-INSTALL`; direct upgrades from pre-compatibility v3.2 need either embedded package-script
   logic or an explicit prerequisite that users first install the v3.2 compatibility build.
2. Specify durable divergence acknowledgement. `file_notice()` is dismissible but reboot-volatile;
   snapshot metadata needs an acknowledgement/re-notification rule.
3. Specify cross-name backup-failure recovery. libpkg may remove the source package before the
   target `PRE-INSTALL`; the required state and one-click retry behavior need a precise contract.
4. Specify repository retention and immutable target identity. Exact v3.2 stable/devel versions and
   checksums must remain in every supported ABI catalogue while v4 offers downgrade.
