# pfSense live-system investigation gotchas

Scope: investigating live pfSense/FreeBSD box or reasoning about on-appliance behaviour.
Load when: touching live system, generated artifact, or appliance service (Unbound,
pf, HAProxy, pkg).

Each cost real misdiagnosis:

- **Follow file inclusions.** *NIX config splits across `include:` directives and `*.d/`
  drop-ins — grep whole tree, then follow chain. Unbound DNS-Resolver ACLs live not
  in `/var/unbound/unbound.conf` but in included `/var/unbound/access_lists.conf` (with
  `host_entries.conf`, `domainoverrides.conf`, `remotecontrol.conf`).
- **Some pfSense services run CHROOTED** — chrooted process resolves absolute paths against
  its chroot root. **Unbound** → `/var/unbound` (`pfb_unbound.py` runs there: host-absolute
  `/var/unbound/pfb_py_raw/x` becomes `/var/unbound/var/unbound/pfb_py_raw/x` inside and 404s —
  use in-chroot paths; files like `/usr/local/pkg/...` unreachable). **HAProxy** →
  `/tmp/haproxy`. Host file can be unreadable purely from chroot — caused real DNSBL
  feed-loading bug (manifest stored host-absolute paths chrooted module couldn't open).
- **Ask tool for effective state via its own CLI** (resolves includes, shows what
  loaded): **pf** → `pfctl` (`-sr`/`-sn`/`-sTables`/`-t <t> -T show`/`-ss`); **Unbound** →
  `unbound-control` (`get_option <opt>`, `list_local_zones`, `status`), `unbound-checkconf`
  validates. Prefer CLI/`pfSsh.php` over generated files.
- **Turn on debug/verbose when unsure what tool does** (URLs/files hit, cache/304). E.g.
  `pkg -d update` traces underlying `curl` (catalogue `meta.conf`/`data.pkg`, the
  `If-Modified-Since` → "Simulate an HTTP 304" → "repository is up to date" path; local DB
  under `/var/db/pkg/repos/<repo>/db`); `curl -v` for raw HTTP. Gotcha: pfSense pkg uses
  **`pkg+https`** scheme (mirror indirection) — `pkg.pfsense.org` doesn't resolve directly (plain
  `dig` looks "broken") but pkg resolves it to Netgate mirror (e.g.
  `pkg00-atx.netgate.com`). Smoke harness keeps egress OPEN during `deploy()`/reload
  phase for **resolver + feed-update path** (DNSBL update needs working resolver);
  `pkg add` itself **OFFLINE** — pfBlockerNG RUN_DEPENDS baked into smoke image
  (`scripts/misc/install_deps_CE_2.8.sh`), so resolves them from local pkg db, no
  mirror round-trip.
- **Confirm what installed with `pkg`.** `pkg info` / `pkg info <pkg>` / `pkg info -l <pkg>`
  (files) / `pkg which <path>` (owner); available: `pkg search` / `pkg rquery`. Smoke
  image ships `ldns` (→ `drill`), `bind-tools` (→ `dig`/`host`/`nslookup`), `python311`,
  `unbound`, `php83`, `qemu-guest-agent` — check before adding dep or coding fallback.
- **`/conf/config.xml` is the source of truth** for pfSense settings; `/var/…` generated
  from it. To check setting, open relevant `config.xml` section (e.g. `<unbound><acls>`)
  — don't assume.
- **"Everything is files" cuts both ways:** read actual files (diff before/after) and
  confirm set/empty value on box, not from recollection.
