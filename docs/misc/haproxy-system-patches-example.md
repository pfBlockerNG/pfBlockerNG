# HAProxy: local package patch via pfSense System Patches (worked example)

Real production example: carry local mods to pfSense package (`pfSense-pkg-haproxy-devel`) with **System Patches** package until upstream merge. Template for running patched HAProxy package (or any pfSense package) without forking install.

- Patch file: [`haproxy-devel-modernize.patch`](haproxy-devel-modernize.patch)
- Upstream submission: <https://github.com/pfsense/FreeBSD-ports/pull/1450>
- Verified on: pfSense Plus 26.03.1, `pfSense-pkg-haproxy` 0.65.7 / `-devel` 0.66.7
  (both ship byte-identical PHP for touched files), haproxy 3.2.10

## What the patch does

1. **Threads auto-detection** — `nbthread` GUI field now numeric, default 0. 0 (or blank) emits no `nbthread` line, so haproxy auto-detects thread count. Drops "haproxy 1.8 threads are experimental" era help text.
2. **No DH parameters in Modern SSL/TLS mode** — TLS 1.3 has no DHE key exchange, so `tune.ssl.default-dh-param` omitted from generated config and GUI field hides when Modern selected.
3. **Alias autocomplete** — ACL value fields on frontend/backend edit pages suggest firewall alias names. Also fixes package's `get_alias_list(array(...))` calls: current pfSense accepts only comma-separated string, silently returns `[]` for array — that left pre-existing address/port autocomplete empty.
4. **New ACL type "Header IP matches IP or Alias"** — matches request header (example `X-Forwarded-For` or `CF-Connecting-IP`; name user-supplied) against IP, network or alias via `req.hdr_ip()`. Aliases materialize into same `ipalias_*.lst` files Source IP ACL uses. `req.hdr_ip()` yields IP-typed sample, so CIDR entries in list match correctly — hand-written `req.hdr(...) -f` custom ACL does string matching, never matches CIDRs.
5. **Reload-time fixes** (measured on config with 642k-entry pfBlockerNG aggregated alias referenced by three ACLs plus 20k-entry IPv6 list):
   - PHP config generation 9.8 s → 0.2 s: each alias list file written once per generated config, and urltable aliases copied from already-expanded `/var/db/aliastables/<name>.txt` instead of re-expanded in PHP.
   - haproxy config parse 14 s → 1.1 s: haproxy ip pattern parser attempts DNS lookup for every IPv6 entry of `-f` list before parsing as IPv6 (two blocking round trips per entry). Pure IP/CIDR lists now pass `-n` matching flag, which forbids that resolution; lists that may contain hostnames keep it.

## Applying with System Patches

1. Install **System Patches** package, then *System → Patches → Add New Patch*.
2. **Paste** patch file contents into *Patch Contents*. Do not use file upload: form validates browser-supplied MIME type (`text/x-patch`), not content, so correct unified diff often rejected depending on browser.
3. Settings that matter (paths in diff look like `a/usr/local/pkg/...`):
   - **Path Strip Count**: `1` (default `2` is for pfSense mainline `a/src/...` diffs; wrong value makes every hunk report "No file to patch")
   - **Base Directory**: `/`
4. Save, then use test/apply view. Reading it:
   - *Apply-check OK* — stock files present; click **Apply**.
   - *Apply-check fails, revert-check OK* — changes already on disk (already applied, or hand-deployed); nothing to do.
   - *Both checks fail* — package version diverged from patch base; regenerate patch against new package source.
5. After applying, do one Save/Apply cycle in HAProxy GUI so config regenerates through patched code.

Entry persists across package upgrades: upgrade overwrites package files with stock ones, after which patch shows apply-ready again — reapply and redo HAProxy Save/Apply. Retire entry once upstream PR ships in package.

## Regenerating the patch after a package update

Patch produced from `pfBlockerNG/FreeBSD-ports` fork, branch `haproxy-devel-modernize`, with filesystem-relative paths:

```sh
git diff --relative=net/pfSense-pkg-haproxy-devel/files \
    origin/devel...haproxy-devel-modernize -- net/pfSense-pkg-haproxy-devel/files
```

Rebase that branch onto new package source, re-run command. `--relative=<dir>` turns port-tree paths into `a/usr/local/...` filesystem paths System Patches can apply at `/` with strip count 1.
