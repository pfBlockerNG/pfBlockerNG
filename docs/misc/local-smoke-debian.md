# Running live-VM smoke suite locally on Debian

Dev-only notes for running `tests/smoke/` (ADR-04) on Debian/KVM LXC box, outside
GitHub Actions. These cost real time to relearn; CI workflow
(`.github/workflows/smoke-single.yml`) is source of truth for canonical invocation.

## Prerequisites

### On the orchestrator (your laptop/workstation)

- `ssh` reach to LXC pool (`PFB_BOXES`).
- Git worktree of branch under test checked out locally (orchestrator reads
  HEAD to derive default `--ref`).

### On each LXC box (pre-provisioned once)

- `/dev/kvm` present + writable (hardware virtualisation). Everything need KVM.
- `docker` and `git`. **Nothing else**: qemu, oras, dig, Playwright browser now
  live in `ghcr.io/pfblockerng/ci-runner-vm`, which leg runs inside (issue #2223).
  Image public — box need no registry credentials.
- Guest SSH key (baked into smoke images) at `/root/smoke-ssh-key`.
- FreeBSD-ports checkout under `/root/FreeBSD-ports` (auto-cloned/updated by `smoke-on-box.sh`).

Image storage is not a box prerequisite. Each `docker run --rm` workload pulls its selected
pfSense image (and civm image unless `--no-two-vm`) into container-local
`/root/images/{pfsense,civm}`; Docker removes that writable layer when the workload exits.
Set `PFB_LAN_REGISTRY` on the box to use the durable LAN zot cache; without it, pulls use
GHCR and `SMOKE_GHCR_TOKEN` may authenticate the pull.

## Running (new: via lease + on-box execution)

Orchestrator leases box, runs EVERYTHING on it — images, build, pytest:

`PFB_BOXES` is pool of ssh targets to lease from. **Current pool is `10.0.0.31`
through `10.0.0.34` (four boxes, ssh as `root`)** — copy line below verbatim. Do not infer
pool from anywhere else in tree: `tests/shell/select_box_spec.sh` uses `10.0.0.23` and
`10.0.0.24` as *fake* boxes for lease-token assertions, and run pointed at those fails with
`No route to host` and reads like harness broken.

```sh
export PFB_BOXES="root@10.0.0.31 root@10.0.0.32 root@10.0.0.33 root@10.0.0.34"

# Full smoke (marker=smoke, current HEAD):
scripts/local-smoke.sh

# Specific --filter (pytest -k expression rides as one quoted arg, no word-split):
scripts/local-smoke.sh --filter "test_dns_redirect or test_killstates"

# Different marker (e.g. the reboot-persistence tier):
scripts/local-smoke.sh --marker reboot

# Skip civm (two-VM LAN-client tests will SKIP):
scripts/local-smoke.sh --no-two-vm

# The ADR-14 Web-UI tiers (ui_render / ui_e2e / ui_browser):
scripts/local-smoke.sh --marker ui_render

# A different pkg channel (stable|testing|edge|nightly; default edge):
scripts/local-smoke.sh --channel testing
```

`--channel` decides which port `.pkg` built from, and port NAMES package
(`pfSense-pkg-pfBlockerNG-<channel>`), so it decides which artifact suite installs. Default
is channel `devel` branch's `4.0.0.a*` line belongs to — one
`build-pkg-linux.yml` builds (issue #2166) — because run on any other channel
verifies differently-named package than CI ships (issue #2206). Two defaults kept
in step by hand: `tests/test_issue2166_workflow_channel_inputs.py` pins workflows and
`tests/smoke`, never this script's own default. Pass `--channel` explicit if verifying
specific artifact. Unknown channel refused before box leased,
because `build-pkg-portable.py` would otherwise reject it on box after
lease and ports clone.

UI-tier marker auto-scopes run to `tests/smoke/ui` with 300s per-test ceiling
(matching `ui-tests.yml`); `ui_browser` also installs headless Chromium binary on
box. **webConfigurator admin password must be on box** — UI fixtures log in over
CSRF form, so unset `SMOKE_ADMIN_PASSWORD` FAILS whole tier (never skips — skipped
tier = false green). Put it (and optional `SMOKE_ADMIN_USER`, default `admin`) in box's
`~/.ssh/environment` (needs `PermitUserEnvironment yes`) so on-box pytest inherits it; it
must match password baked into pfSense image box pulls.

```sh
# Explicit ref:
scripts/local-smoke.sh --ref origin/devel
```

EXIT trap in `scripts/select-box.sh` releases lease automatically (Ctrl-C included).
All images, ports, build, sysctl, pytest run ON box — orchestrator only provides
bootstrap command string.

### Sharded runs (issue #797)

```sh
# Lease 3 boxes concurrently, each running one module-level shard of the smoke suite:
scripts/local-smoke.sh --shards 3
```

`--shards N` (default 1) leases N boxes at once, one `select-box.sh` invocation per shard,
each forwarding `--shard I --shard-total N` down to `run-smoke.sh` (module round-robin via
`scripts/shard-modules.sh` — same splitter CI's `smoke.yml` uses, so local and CI sharding
same mechanism). Logs land one-per-shard under kept `mktemp` dir (path printed at
start and end); run exits non-zero iff any shard failed, and prints summary plus each
failed shard's last 25 log lines.

Constraints: `--shards N>1` refuses `--filter` and any `--marker` other than default
`smoke` — narrowed run can collect zero tests for given shard, and pytest's exit 5 (no
tests collected) would fail that shard spuriously. `N` should stay at or under free
`PFB_BOXES` pool; oversized `N` just makes excess shards fail loudly on
`select-box.sh`'s own pool-exhaustion path rather than pre-counting pool.

### How it works

1. `local-smoke.sh` leases one box from `PFB_BOXES` via `select-box.sh -- <bootstrap>`.
2. On box, `smoke-on-box.sh` (invoked by bootstrap) runs in order:
   - `git sparse-checkout` (only `src`, `scripts`, `stubs/python`, `tests/smoke`, `pkg-site` —
     13 MB of a 34 MB tree),
     then `git fetch` + `git checkout FETCH_HEAD`. Ref resolved HERE; container
     runs already-resolved tree and never fetches.
   - `sparse-clone-ports.sh` to bring `/root/FreeBSD-ports` to `pfblockerng/use-github`.
   - `docker run --rm` leg inside `ci-runner-vm`, with `--device /dev/kvm` and
     `--sysctl net.ipv4.ip_unprivileged_port_start=53`. Inside it, `oras` pulls pfSense
     civm images directly into disposable `/root/images/{pfsense,civm}` directories.
     The LAN zot registry remains the durable fleet cache when `PFB_LAN_REGISTRY` is set;
     no qcow2 store is shared between boxes.
   - `pkill -9 -f qemu-system-x86_64`. Port floor set by caller's `--sysctl`
     flag, not in-script: `smoke-on-box.sh` now treats it as precondition and refuses
     to run when above 53, naming missing flag.
   - `build-leg.sh` → `SMOKE_PKG`.
   - `run-smoke.sh --paths <P> --marker <M> --timeout <T> [--filter <K>]` — `<P>`/`<T>` derive
     from marker (`scripts/lib/smoke-tier.sh`): UI tier → `tests/smoke/ui` + 300s, else
     `tests/smoke` + 30s; `ui_browser` marker also installs Chromium first.
3. `run-smoke.sh` is ONE canonical pytest argv — same script CI uses.

CI `scope=impacted` / min-CE / auto-derived-`-k` defaulting (see
[architecture-notes.md](architecture-notes.md) "Selective dispatch") is **CI-only** — locally
you pick target and `-k` yourself.

All step logic (`select-box.sh`, `smoke-on-box.sh`, `build-leg.sh`, `run-smoke.sh`) lives in
`scripts/` and runs identically on local box and in CI — workflows are thin dispatch
wrappers. Shared `scripts/lib/git-env-scrub.sh` scrubs six GIT_\* vars that
pre-commit hook exports; every script sources it at entry so git fixture repos never
corrupted by inherited GIT_DIR.

## The two-VM topology

Many cases (`test_dns_redirect.py`, anything depending on `lan_interface`) need
**civm** Debian client connected to pfSense LAN, or they SKIP. `smoke-on-box.sh` pulls
civm image automatically (unless `--no-two-vm` passed).

civm OCI image at `ghcr.io/pfblockerng/civm:v1` (~600 MB). qcow2 named
`pfSense-CE-v1.qcow2` and its OCI annotation says "pfSense CE" — **that label is templated
lie**; image is Debian client, not pfSense.

Each `SMOKE_*_IMAGE_DIR` must hold **exactly one** `*.qcow2` after its direct pull. The
directories disappear with the container after the workload exits.

## Building the `.pkg` off-FreeBSD (CI reference)

Portable Linux builder reproduces `make package` for this `NO_BUILD` port. For CE 2.8
(values from CE 2.8 entry in ci-metadata matrix):

```sh
python3 scripts/build-pkg-portable.py \
  --ports /path/to/FreeBSD-ports --channel edge --local-src . \
  --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --out out/
```

`--ports` is FreeBSD-ports checkout containing `net/pfSense-pkg-pfBlockerNG-edge`
(channel devel branch builds; `--channel` accepts stable, testing, edge, nightly).
`pkg add` checks dep is PRESENT, not its version, so this `.pkg` installs on
baked-deps image.

`scripts/build-leg.sh` wraps above with run-keyed defaults (ports-dir, out-dir, channel).
On box, `smoke-on-box.sh` calls it automatically.

## Driving the pfSense guest — tcsh vs `/bin/sh`

**pfSense `root`'s login shell is `tcsh`, not POSIX `sh`.** Command sent to bare
login shell over SSH is therefore parsed by **tcsh**, and tcsh is *not* sh-compatible — so
script that works in your terminal can silently mis-parse on guest, producing wrong output
rather than error. This bit real investigation: `grep -E` probe returned false
`rules.debug:0` (rule "absent") purely because tcsh mangled command.

**Rule: always wrap guest commands in `/bin/sh -c`.** Never assume login shell is POSIX.

```sh
# WRONG — runs under tcsh:
ssh root@pf "/usr/bin/grep -nE 'rdr|\\(self\\)|port (53|853)' /tmp/rules.debug"
# RIGHT — force /bin/sh:
ssh root@pf /bin/sh -c "'/usr/bin/grep -nE \"rdr|\\(self\\)|port (53|853)\" /tmp/rules.debug'"
```

tcsh specifically mishandles, vs `sh`:

- redirection — `2>&1` is syntax error in tcsh (it wants `>&`); stray `2>&1` mis-parses;
- here-documents and `$(...)` command substitution differ;
- `grep -E` / `awk` pattern containing `(`, `)`, `|`, `$`, `{` `}` — tcsh's history/glob/var
  parsing can eat them before program sees them;
- quoting rules and `!` (history expansion) differ.

In harness this already handled — `SmokeVM.ssh` routes **every** guest command through
`/bin/sh -c` (remote argv re-quoted into one POSIX-sh command line; see
`tests/smoke/conftest.py`). When you add new on-box command (in harness or by hand),
keep that contract. One exception is **`pfSsh.php`** snippet, which is piped on **stdin**
and ends with `exec` then `exit` (pfSense developer-shell contract) — that is not tcsh
command line at all (see `pfSsh.php` gotcha below).

## Gotchas that cost time

- **Background VM boots get killed.** Plain `nohup boot_vm.sh ... &` from tool/CI
  shell dies when shell returns. Fully detach with `setsid` + stdin from `/dev/null`:
  `QMP_SOCK=/tmp/x.sock setsid sh tests/smoke/boot_vm.sh --role pfsense IMG OVERLAY > log 2>&1 </dev/null &`.
  Setting `QMP_SOCK` also switches `boot_vm.sh` to `-serial stdio` (clean for redirection)
  instead of `-serial mon:stdio`.
- **`pfSsh.php` contract.** Pipe PHP on **stdin**, and last two lines fed to it
  MUST be line `exec` then `exit`, or it hangs and is Killed. When wrapping in shell
  heredoc, QUOTE inner delimiter (`<<'PHP'`) so shell does not expand PHP
  `$variables` before pfSsh sees them.
- **Some pfSense functions are not callable from `pfSsh.php` eval.** `interface_vip_configure`,
  `filter_configure_sync`, etc. need full rc environment (`shaper.inc`/`interfaces.inc`
  globals); bare call throws "undefined function" or builds degraded result. Use
  `/etc/rc.*` entrypoints (e.g. `/etc/rc.filter_configure_sync`) over SSH instead.
- **SSH hangs on `php ... | tail`.** pfBlockerNG `update` restarts daemons that inherit
  command's stdout fd, so piped reader never sees EOF and SSH blocks to its timeout.
  Redirect to file in background and poll: `nohup php ... pfblockerng.php update >/tmp/up.log 2>&1 </dev/null &`,
  or follow with `tail -F`.
- **`pfctl -sn` rendering.** Loaded rdr rule shows **physical device** (`vtnet2`),
  never config name (`lan`), and renders **port 53 as `domain`**. Resolve config to
  device with `get_real_interface()` and match `domain`/numeric — do not grep for
  config name or literal `53`.
- **Wait on signals, not timing.** After config change, force deterministic apply
  (e.g. blocking `/etc/rc.filter_configure_sync`) and read once, rather than polling for
  async effect against fixed timeout (async `filter_configure()` apply can lag).
- **Free ports between runs.** `pkill -9 -f qemu-system-x86_64` releases host
  forwards (pfSense ssh 2222 / web 8080, civm ssh 2223) and LAN crossover socket.
- Published CE image reports `2.8.1-RELEASE` even though its tag is `2.8`.
