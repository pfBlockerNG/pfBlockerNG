# HAProxy: local package patch via pfSense System Patches (worked example)

A real, applied-in-production example of carrying local modifications to a pfSense
package (`pfSense-pkg-haproxy-devel`) with the **System Patches** package, until the
upstream change is merged. Use it as the template when someone asks how to run a
patched HAProxy package (or any pfSense package) without forking the installation.

- Patch file: [`haproxy-devel-modernize.patch`](haproxy-devel-modernize.patch)
- Upstream submission: <https://github.com/pfsense/FreeBSD-ports/pull/1450>
- Verified on: pfSense Plus 26.03.1, `pfSense-pkg-haproxy` 0.65.7 / `-devel` 0.66.7
  (both ship byte-identical PHP for the touched files), haproxy 3.2.10

## What the patch does

1. **Threads auto-detection** — `nbthread` GUI field becomes numeric with default 0;
   0 (or blank) emits no `nbthread` line so haproxy auto-detects the thread count.
   Removes the "haproxy 1.8 threads are experimental" era help text.
2. **No DH parameters in Modern SSL/TLS mode** — TLS 1.3 has no DHE key exchange, so
   `tune.ssl.default-dh-param` is omitted from the generated config and the GUI field
   hides itself when Modern is selected.
3. **Alias autocomplete** — ACL value fields on the frontend/backend edit pages suggest
   firewall alias names. Also fixes the package's `get_alias_list(array(...))` calls:
   current pfSense accepts only a comma-separated string and silently returns `[]` for
   an array, which had left the pre-existing address/port autocomplete empty.
4. **New ACL type "Header IP matches IP or Alias"** — matches a request header (for
   example `X-Forwarded-For` or `CF-Connecting-IP`; the name is user-supplied) against
   an IP, network or alias via `req.hdr_ip()`. Aliases materialize into the same
   `ipalias_*.lst` files the Source IP ACL uses. `req.hdr_ip()` yields an IP-typed
   sample, so CIDR entries in the list match correctly — a hand-written
   `req.hdr(...) -f` custom ACL does string matching and never matches CIDRs.
5. **Reload-time fixes** (measured on a config with a 642k-entry pfBlockerNG aggregated
   alias referenced by three ACLs plus a 20k-entry IPv6 list):
   - PHP config generation 9.8 s → 0.2 s: each alias list file is written once per
     generated config, and urltable aliases are copied from the already-expanded
     `/var/db/aliastables/<name>.txt` instead of being re-expanded in PHP.
   - haproxy config parse 14 s → 1.1 s: haproxy's ip pattern parser attempts a DNS
     lookup for every IPv6 entry of an `-f` list before parsing it as IPv6 (two
     blocking round trips per entry). Pure IP/CIDR lists now pass the `-n` matching
     flag, which forbids that resolution; lists that may contain hostnames keep it.

## Applying with System Patches

1. Install the **System Patches** package, then *System → Patches → Add New Patch*.
2. **Paste** the patch file's contents into *Patch Contents*. Do not use the file
   upload: the form validates the browser-supplied MIME type (`text/x-patch`), not the
   content, so a correct unified diff is often rejected depending on the browser.
3. Settings that matter (the paths in the diff look like `a/usr/local/pkg/...`):
   - **Path Strip Count**: `1` (the default `2` is for pfSense mainline `a/src/...`
     diffs; with the wrong value every hunk reports "No file to patch")
   - **Base Directory**: `/`
4. Save, then use the test/apply view. Interpreting it:
   - *Apply-check OK* — stock files present; click **Apply**.
   - *Apply-check fails, revert-check OK* — the changes are already on disk (already
     applied, or hand-deployed); nothing to do.
   - *Both checks fail* — the package version has diverged from the patch base; the
     patch needs regenerating against the new package source.
5. After applying, do a Save/Apply cycle in the HAProxy GUI once so the configuration
   regenerates through the patched code.

The entry persists across package upgrades: an upgrade overwrites the package files
with stock ones, after which the patch shows apply-ready again — reapply and redo the
HAProxy Save/Apply. Retire the entry once the upstream PR ships in the package.

## Regenerating the patch after a package update

The patch was produced from the `pfBlockerNG/FreeBSD-ports` fork, branch
`haproxy-devel-modernize`, with filesystem-relative paths:

```sh
git diff --relative=net/pfSense-pkg-haproxy-devel/files \
    origin/devel...haproxy-devel-modernize -- net/pfSense-pkg-haproxy-devel/files
```

Rebase that branch onto the new package source and re-run the command. The
`--relative=<dir>` is what turns port-tree paths into `a/usr/local/...` filesystem
paths that System Patches can apply at `/` with strip count 1.
