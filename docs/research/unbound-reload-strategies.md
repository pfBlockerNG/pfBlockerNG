# Unbound reload behavior in pfBlockerNG

Last verified: 2026-07-22

This note explains how pfBlockerNG applies DNSBL changes today, how Unbound's three reload
commands differ, and how resolver caches affect a future reload strategy. It records current
behavior separately from proposed changes.

## What pfBlockerNG does today

Saving DNSBL settings does not immediately touch Unbound. The page writes the settings and
marks them pending for the next pfBlockerNG Update
([source](../../src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php#L913-L944)).

During that Update, pfBlockerNG chooses between two apply paths:

| Change | Current apply path |
| --- | --- |
| DNSBL data only | Publish a new manifest/raw generation, notify the running Python module, and atomically swap its in-memory snapshot |
| Python module inclusion or removal | Stop and start Unbound |
| Python INI, SafeSearch, generated `unbound.conf`, or mount change | Stop and start Unbound |
| Data-swap eligibility or application failure | Stop and start Unbound |

The stop/start path sends `SIGTERM`, waits up to 30 seconds, adjusts chroot mounts while Unbound
is down, then starts `/usr/local/sbin/unbound` again
([source](../../src/usr/local/pkg/pfblockerng/pfblockerng.inc#L9240-L9277)). It can optionally
dump and restore the resolver cache around that restart
([source](../../src/usr/local/pkg/pfblockerng/pfblockerng.inc#L9558-L9608)).

pfBlockerNG does **not** currently call `unbound-control reload`, `reload_keep_cache`, or
`fast_reload`.

## The current zero-downtime DNSBL path

For a data-only update, the running Python module remains loaded:

1. PHP atomically publishes the complete manifest/raw generation.
2. PHP advances `/var/unbound/pfb_py_reload`.
3. A Python watcher builds a new immutable snapshot while queries continue using the old one.
4. Python atomically replaces the live snapshot and clears its `decisionDB` memo.
5. Python publishes an applied-generation marker.
6. PHP waits for that marker before returning.
7. When the default-off **Clear Resolver Cache** option is enabled, a bulk update clears
   Unbound's full message and RRset caches. Exact Alerts allow→block edits instead flush only
   their validated domain and `www.` sibling regardless of that option.

The implementation and fallback gates are in
[`pfb_reload_unbound()`](../../src/usr/local/pkg/pfblockerng/pfblockerng.inc#L9465-L9554).
The snapshot swap and `decisionDB.clear()` are in
[`rebuild_and_swap()`](../../src/usr/local/pkg/pfblockerng/pfb_unbound.py#L5605-L5675).

This path is already better than any Unbound configuration reload for DNSBL data: it does not
pause or reinitialize the resolver.

## Unbound reload commands

| Property | `fast_reload` | `reload_keep_cache` | `reload` |
| --- | --- | --- | --- |
| Availability | Added in Unbound 1.23; still experimental | Available in Unbound 1.22 | Available in Unbound 1.22 |
| Mechanism | Builds supported configuration in a background thread, then briefly swaps it into running workers | Traditional internal restart | Traditional internal restart |
| Worker/module lifecycle | Existing workers and Python module remain running | Workers recreated; modules run `deinit()` then `init()` | Workers recreated; modules run `deinit()` then `init()` |
| In-flight queries | Retained | Interrupted | Interrupted |
| Native cache | Retained | Retained only when configuration permits | Cleared |
| Module inclusion/removal | Not supported | Supported | Supported |
| Configuration coverage | Selected options only | Broad | Broad |
| Temporary memory | Approximately twice the configuration memory | No equivalent prepared-config overlap | No equivalent prepared-config overlap |
| Failure before apply | Old configuration keeps serving | Not fail-safe by itself | Not fail-safe by itself |

Primary references:

- [Unbound control manual](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound-control.html)
- [Unbound 1.23 release announcement](https://nlnetlabs.nl/news/2025/Apr/24/unbound-1.23.0-released/)
- [Unbound module lifecycle API](https://nlnetlabs.nl/documentation/unbound/doxygen/structmodule__func__block.html)
- [pfSense CE 2.8 release notes: Unbound 1.22](https://docs.netgate.com/pfsense/en/latest/releases/2-8-0.html)

Consequently, `fast_reload` is unavailable on the current pfSense CE 2.8 baseline. Trying it
may still be a reasonable future capability probe if an unsupported-command error cleanly
falls through to another apply path.

## What traditional `reload` actually does

`reload` is not an external service restart or process `exec`. The daemon keeps its PID, but
internally it stops workers, tears down modules, rereads configuration, and rebuilds the runtime.
It is therefore functionally an in-process restart.

The control command replies `ok` before the new configuration is parsed. The source sets the
reload flags, exits the worker event loop, and sends the response immediately
([source](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/daemon/remote.c#L672-L680)).
The daemon only then rereads configuration and starts the runtime again
([source](https://github.com/NLnetLabs/unbound/blob/release-1.22.0/daemon/unbound.c#L695-L745)).

An invalid configuration or runtime initialization failure can therefore terminate Unbound
after `unbound-control` already returned success. A safe caller needs all of the following:

1. Back up the last-known-good configuration.
2. Run `unbound-checkconf` before requesting reload.
3. Verify resolver readiness and the expected Python state after reload.
4. Restore the backup and perform a full external restart if verification fails.

`unbound-checkconf` reduces configuration-parse risk. It cannot prove that Python initialization,
mount access, memory allocation, or every other runtime action will succeed.

## Python module inclusion and removal

Normal `reload` and `reload_keep_cache` are designed to run module `deinit()` before reload and
module `init()` afterward. At the Unbound layer, adding or removing `python` from `module-config`
does not inherently require a new daemon process.

pfBlockerNG also manages chroot mounts. Today it creates mounts before the external restart and
removes them while Unbound is stopped
([source](../../src/usr/local/pkg/pfblockerng/pfblockerng.inc#L8842-L9175)). A reload-based
transition would need this ordering:

- Inclusion: establish required mounts, publish valid configuration, then reload.
- Removal: publish configuration without Python, reload and confirm `deinit()`, then unmount.

That mount choreography has not yet been proven on a live pfSense box. Until it is, treating it
as verified behavior would be guessing.

## Cache behavior

Two different caches matter:

- **Python `decisionDB`:** pfBlockerNG's per-domain decision memo. Every successful snapshot
  swap clears it.
- **Unbound native C caches:** message and RRset caches containing resolved DNS answers. Python
  does not globally clear these caches.

Synthetic DNSBL block replies set `qstate.no_cache_store = 1`, so Unbound never puts them in its
native message cache
([source](../../src/usr/local/pkg/pfblockerng/pfb_unbound.py#L6948-L7001)). This makes staleness
one-directional:

- Block to allow is immediate after `decisionDB` is cleared because no cached block exists.
- Allow to block may keep serving the previously resolved real answer until its TTL expires.

Bulk feed updates do not have a cheap exact effective delta because wildcard rules, regular
expressions, ABP priority, TLD/IDN policy, and allow rules can all change the result. The
default-off **Clear Resolver Cache** option therefore lets the operator choose between retaining
cached PASS answers until TTL expiry and immediate allow→block enforcement. When enabled, the
bulk caller runs `unbound-control flush_zone +c .` after the Python applied-generation handshake
succeeds, clearing the full message and RRset caches without pausing or restarting Unbound. A
data-path restart fallback does not restore the pre-update cache; normal settings-page whitelist
changes remain config-class updates and restart Unbound.

Alerts cache treatment follows transition direction after `pfb_reload_unbound()` returns.
Custom_List add, exact whitelist deletion, and Lock flush the validated domain and its `www.`
sibling. Wildcard whitelist deletion clears the full cache because it can re-block an unknown set
of subdomains. Whitelist add and Unlock need no flush because blocked answers are not cached.
Targeted commands retain domain validation plus shell escaping.

## Candidate future routing

This is a proposal, not current behavior:

```text
DNSBL data only
    -> existing Python snapshot swap

Unbound config changed
    -> back up config
    -> unbound-checkconf
    -> try fast_reload when supported and compatible
    -> otherwise reload or reload_keep_cache
    -> verify resolver and Python state
    -> on failure: restore backup and perform full external restart
```

Cache choice depends on semantics:

| Change class | Suggested cache treatment |
| --- | --- |
| Logging, telemetry, or other answer-neutral setting | Keep cache |
| Exact Alerts allow→block edit | Keep cache and flush the validated single-domain set after the snapshot is confirmed applied |
| Alerts wildcard-whitelist removal | Clear the full message and RRset caches after the snapshot is confirmed applied |
| Bulk generation load | User-selected: retain caches by default, or clear the full message and RRset caches after the snapshot is confirmed applied |
| Regex, TLD, IDN, SafeSearch, response-shape, or other broad DNS-policy change | Clear the native cache |
| Python module inclusion/removal | Clear the native cache unless live testing proves retained entries cannot violate the new policy |

Thus `fast_reload` fits answer-neutral supported configuration changes. A broad policy change may
still require plain `reload`, or an explicit full cache flush after a successful fast reload.

## Live-box checks still required

Before changing production behavior, verify on every supported pfSense/Unbound line:

1. Unsupported `fast_reload` returns a reliable nonzero status without disturbing service.
2. Incompatible `fast_reload` leaves old configuration and queries intact.
3. Python inclusion works with mounts established before `reload`.
4. Python removal completes `deinit()` before mounts are removed.
5. `reload_keep_cache` reinitializes `pfb_unbound.py` and preserves only compatible caches.
6. Post-reload probes detect Python initialization failure even though the control command said
   `ok`.
7. Backup restoration plus external restart reliably recovers every failed reload case.
