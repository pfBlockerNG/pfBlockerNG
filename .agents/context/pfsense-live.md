# pfSense live-system investigation gotchas

Scope: investigating a live pfSense/FreeBSD box or reasoning about on-appliance behaviour.
Load when: touching a live system, a generated artifact, or an appliance service (Unbound,
pf, HAProxy, pkg).

Each of these cost a real misdiagnosis:

- **Follow file inclusions.** *NIX config splits across `include:` directives and `*.d/`
  drop-ins — grep the whole tree, then follow the chain. Unbound's DNS-Resolver ACLs live not
  in `/var/unbound/unbound.conf` but in the included `/var/unbound/access_lists.conf` (with
  `host_entries.conf`, `domainoverrides.conf`, `remotecontrol.conf`).
- **Some pfSense services run CHROOTED** — a chrooted process resolves absolute paths against
  its chroot root. **Unbound** → `/var/unbound` (`pfb_unbound.py` runs there: host-absolute
  `/var/unbound/pfb_py_raw/x` becomes `/var/unbound/var/unbound/pfb_py_raw/x` inside and 404s —
  use in-chroot paths; files like `/usr/local/pkg/...` are unreachable). **HAProxy** →
  `/tmp/haproxy`. A host file can be unreadable purely from the chroot — caused a real DNSBL
  feed-loading bug (manifest stored host-absolute paths the chrooted module couldn't open).
- **Ask the tool for its effective state via its own CLI** (resolves includes, shows what's
  loaded): **pf** → `pfctl` (`-sr`/`-sn`/`-sTables`/`-t <t> -T show`/`-ss`); **Unbound** →
  `unbound-control` (`get_option <opt>`, `list_local_zones`, `status`), `unbound-checkconf`
  validates. In general prefer the CLI/`pfSsh.php` over generated files.
- **Turn on debug/verbose when unsure what a tool does** (URLs/files hit, cache/304). E.g.
  `pkg -d update` traces the underlying `curl` (catalogue `meta.conf`/`data.pkg`, the
  `If-Modified-Since` → "Simulate an HTTP 304" → "repository is up to date" path; local DB
  under `/var/db/pkg/repos/<repo>/db`); `curl -v` for raw HTTP. Gotcha: pfSense pkg uses the
  **`pkg+https`** scheme (mirror indirection) — `pkg.pfsense.org` doesn't resolve directly (a
  plain `dig` looks "broken") but pkg resolves it to a Netgate mirror (e.g.
  `pkg00-atx.netgate.com`). The smoke harness keeps egress OPEN during the `deploy()`/reload
  phase for the **resolver + feed-update path** (the DNSBL update needs a working resolver);
  `pkg add` itself is **OFFLINE** — pfBlockerNG's RUN_DEPENDS are baked into the smoke image
  (`scripts/misc/install_deps_CE_2.8.sh`), so it resolves them from the local pkg db with no
  mirror round-trip.
- **Confirm what's installed with `pkg`.** `pkg info` / `pkg info <pkg>` / `pkg info -l <pkg>`
  (files) / `pkg which <path>` (owner); available: `pkg search` / `pkg rquery`. The smoke
  image ships `ldns` (→ `drill`), `bind-tools` (→ `dig`/`host`/`nslookup`), `python311`,
  `unbound`, `php83`, `qemu-guest-agent` — check before adding a dep or coding a fallback.
- **`/conf/config.xml` is the source of truth** for pfSense settings; `/var/…` is generated
  from it. To check a setting, open the relevant `config.xml` section (e.g. `<unbound><acls>`)
  — don't assume.
- **"Everything is files" cuts both ways:** read the actual files (diff before/after) and
  confirm a set/empty value on the box, not from recollection.
