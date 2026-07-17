# Smoke tests (ADR-04 — live pfSense VM)

Scope: `tests/smoke/` and the live-VM harness. Load when: touching `tests/smoke/**` or
running the smoke/UI suites — READ BEFORE TOUCHING `tests/smoke/`.

`tests/smoke/` installs the branch `.pkg` on a REAL pfSense CE VM in CI and asserts
pfBlockerNG end-to-end. **Run it locally first** (no workflow spent):
[`docs/misc/local-smoke-debian.md`](../../docs/misc/local-smoke-debian.md), wrapped by
`scripts/local-smoke.sh` — it already exists; reach for it before asking.

**The live-VM smoke ALWAYS runs locally — never claim it "needs CI" or "cannot run on this
host".** `scripts/local-smoke.sh` leases a box from the **`PFB_BOXES`** pool (ADR-47) and runs
the whole leg — images, build, pytest — **on that box** over ssh, so the dev machine needs
nothing but `ssh` (macOS included). `PFB_BOXES` is the owner's ssh-target list and is the one
input the repo cannot supply: get it from the owner (or your session memory) and export it —
the addresses in the doc are illustrative, not a live inventory. A red→green proof for
`tests/smoke/**` is EXECUTED on a leased box (`--marker`/`--filter` to scope it), never
dispatched to CI and never reasoned through.

Non-obvious truths, each costly to relearn:

- **Probe ON-BOX** (`drill @127.0.0.1` over SSH), never the runner-side SLIRP hostfwd.
  Python-mode DNSBL has no localhost exemption. After `reload()` → `wait_unbound_ready`, the
  **first** DNS response is authoritative — assert it, never loop for the expected value.
- **Test domains MUST be `helpers.unique_domain()`** (`uuid-*.com`): never RFC 6761 TLDs
  (Unbound's built-in `local-zone`s shadow them before DNSBL) and never HSTS-preload names
  (`pfb_hsts` default ON forces a would-be VIP block to NULL). Sole carve-out: byte-identity
  harnesses use fixed inert literals (same two prohibitions apply).
- **Block shapes (python mode):** NOERROR + VIP (`dnsbl_ipv4`) or NULL (`0.0.0.0`/`::`);
  NEVER NXDOMAIN for a feed match (SafeSearch-only). Per-list `logging` selects VIP vs NULL
  and is a LIST-level field, not per-row. Compare IPs by value (`::` == `::0`).
- **Unbound is chrooted at `/var/unbound`** — module-read files must be chroot-relative; a
  host-absolute path silently fails to load.
- **pfSense root's login shell is `tcsh` — always drive the guest via `/bin/sh`.** tcsh
  silently mangles POSIX syntax (`2>&1`, here-docs, `grep -E` with `()`/`|`/`$`) — it once
  produced a false `rules.debug:0` read. `SmokeVM.ssh` already wraps commands in `/bin/sh -c`;
  do the same for anything new or by hand. (`pfSsh.php` snippets are a separate
  stdin/`exec`/`exit` contract.)
- **Enable chain:** DNSBL `mode=='enabled'` needs `enable_cb=on` + `pfb_dnsbl=on` + the DNS
  Resolver enabled (`unbound_state`). On `devel`, `dnsbl_mode`/`pfb_py_block` are dead keys;
  on `main` they're still required.
- **The image bakes only deps + qemu-guest-agent** — the harness injects the DNSBL VIP
  (`ensure_dnsbl_vip`) and all per-case config; `pkg add` runs offline (RUN_DEPENDS baked via
  `scripts/misc/install_deps_CE_2.8.sh`); `pfb_dnsvip_auto` defaults OFF, so
  `ensure_dnsbl_vip` stays the fixture. The smoke qcow2 cache is content-keyed by GHCR
  digest.
- **The branch `.pkg` is built on a plain Linux runner** (`build-pkg-linux.yml` →
  `scripts/build-pkg-portable.py`) — pfBlockerNG is a `NO_BUILD` port; this is the **sole**
  builder for CI and releases.
- **Every run uploads a full guest snapshot** (`smoke-diagnostics`: `/var/log`, `dmesg`,
  `pfctl -sa`, unbound + pfBlockerNG state, scrubbed `config.xml`). On any failure, read it
  first.

Web-UI tiers (ADR-14, `tests/smoke/ui/`) + the mock-feed load smoke (ADR-16 Part C) are
documented in architecture-notes. Operative facts:

- **Tier A `ui_render` is the PR gate**: GET each page → 200, body free of PHP
  errors/warnings, a page-specific marker present, AND no new on-box `php_error.log` line —
  never HTTP 200 alone. Tiers B are schedule/dispatch-only. Run:
  `python3 -m pytest tests/smoke/ui -m ui_render --override-ini="addopts="`
  (`SMOKE_ADMIN_PASSWORD` must be set — the UI fixtures FAIL without it; a skip is not a
  pass).
- **Selective dispatch:** a bare `gh workflow run smoke.yml`/`ui-tests.yml` defaults to
  `scope=impacted` (min-CE leg + test modules changed vs `origin/devel`); pass
  `-f pytest_filter="a or b"` to add tests covering changed non-test code; `-f scope=full` =
  every leg, whole marker. Nightly/`workflow_call` gates stay full. Locally pass `-k`/`-m` to
  `scripts/local-smoke.sh`. Full reference: architecture-notes "Selective dispatch".
- Fixtures live in `tests/smoke/fixtures/` (inert data — RFC 5737/3849 IPs, `uuid-*.com`;
  never RFC 6761 TLDs or HSTS-preload names). Add one: the file + `fixtures/README.md` + a
  `test_smoke_feeds.py` case via `mock_feeds.feed_url("<name>")`.
