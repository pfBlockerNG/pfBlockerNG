# Running the live-VM smoke suite locally on Debian

Dev-only notes for running `tests/smoke/` (ADR-04) on a Debian/KVM LXC box, outside
GitHub Actions. These are the things that cost real time to (re)learn; the CI workflow
(`.github/workflows/smoke-single.yml`) is the source of truth for the canonical invocation.

## Prerequisites

### On the orchestrator (your laptop/workstation)

- `ssh` reachability to the LXC pool (`PFB_BOXES`).
- A git worktree of the branch under test checked out locally (the orchestrator reads
  HEAD to derive the default `--ref`).

### On each LXC box (pre-provisioned once)

- `/dev/kvm` present and writable (hardware virtualisation). Everything needs KVM.
- `qemu-system-x86_64`, `qemu-img`, `ssh`, `oras`, `python3` (3.11+), `python3-venv`, `git`.
- The guest SSH key (baked into the smoke images) at `/root/smoke-ssh-key`.
- A pfSense CE qcow2 under `/root/images/pfsense/` (auto-pulled by `smoke-on-box.sh` if absent
  or stale vs the GHCR digest; set `SMOKE_GHCR_TOKEN` to authenticate the pull).
- A FreeBSD-ports checkout under `/root/FreeBSD-ports` (auto-cloned/updated by `smoke-on-box.sh`).

## Running (new: via lease + on-box execution)

The orchestrator leases a box and runs EVERYTHING on it — images, build, pytest:

```sh
export PFB_BOXES="root@10.0.0.23 root@10.0.0.24"   # space-separated SSH targets

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
```

A UI-tier marker auto-scopes the run to `tests/smoke/ui` with the 300s per-test ceiling
(matching `ui-tests.yml`); `ui_browser` additionally installs the headless Chromium binary on
the box. **The webConfigurator admin password must be on the box** — the UI fixtures log in over
the CSRF form, so an unset `SMOKE_ADMIN_PASSWORD` SKIPS the whole tier off-CI (a false-green of
all-skips). Put it (and an optional `SMOKE_ADMIN_USER`, default `admin`) in the box's
`~/.ssh/environment` (needs `PermitUserEnvironment yes`) so the on-box pytest inherits it; it
must match the password baked into the pfSense image the box pulls.

```sh
# Explicit ref:
scripts/local-smoke.sh --ref origin/devel
```

The EXIT trap in `scripts/select-box.sh` releases the lease automatically (Ctrl-C included).
All images, ports, build, sysctl, and pytest run ON the box — the orchestrator only provides
the bootstrap command string.

### Sharded runs (issue #797)

```sh
# Lease 3 boxes concurrently, each running one module-level shard of the smoke suite:
scripts/local-smoke.sh --shards 3
```

`--shards N` (default 1) leases N boxes at once, one `select-box.sh` invocation per shard,
each forwarding `--shard I --shard-total N` down to `run-smoke.sh` (module round-robin via
`scripts/shard-modules.sh` — the same splitter CI's `smoke.yml` uses, so local and CI sharding
are the same mechanism). Logs land one-per-shard under a kept `mktemp` dir (path printed at
start and end); the run exits non-zero iff any shard failed, and prints the summary plus each
failed shard's last 25 log lines.

Constraints: `--shards N>1` refuses `--filter` and any `--marker` other than the default
`smoke` — a narrowed run can collect zero tests for a given shard, and pytest's exit 5 (no
tests collected) would fail that shard spuriously. `N` should stay at or under the free
`PFB_BOXES` pool; an oversized `N` just makes the excess shards fail loudly on
`select-box.sh`'s own pool-exhaustion path rather than pre-counting the pool.

### How it works

1. `local-smoke.sh` leases one box from `PFB_BOXES` via `select-box.sh -- <bootstrap>`.
2. On the box, `smoke-on-box.sh` (invoked by the bootstrap) runs in order:
   - `git fetch` + `git checkout <REF>` (ref-stable bootstrap; re-execs itself at the new ref).
   - `sparse-clone-ports.sh` to bring `/root/FreeBSD-ports` to `pfblockerng/use-github`.
   - `oras` digest-compare → pull pfSense + civm images to `/root/images/{pfsense,civm}` if stale.
   - `sysctl net.ipv4.ip_unprivileged_port_start=53` + `pkill -9 -f qemu-system-x86_64`.
   - `build-leg.sh` → `SMOKE_PKG`.
   - `run-smoke.sh --paths <P> --marker <M> --timeout <T> [--filter <K>]` — `<P>`/`<T>` derive
     from the marker (`scripts/lib/smoke-tier.sh`): a UI tier → `tests/smoke/ui` + 300s, else
     `tests/smoke` + 30s; a `ui_browser` marker also installs Chromium first.
3. `run-smoke.sh` is the ONE canonical pytest argv — same script CI uses.

The CI `scope=impacted` / min-CE / auto-derived-`-k` defaulting (see
[architecture-notes.md](architecture-notes.md) "Selective dispatch") is **CI-only** — locally
you pick the target and `-k` yourself.

All step logic (`select-box.sh`, `smoke-on-box.sh`, `build-leg.sh`, `run-smoke.sh`) lives in
`scripts/` and runs identically on the local box and in CI — the workflows are thin dispatch
wrappers. The shared `scripts/lib/git-env-scrub.sh` scrubs the six GIT_\* vars that the
pre-commit hook exports; every script sources it at entry so git fixture repos are never
corrupted by an inherited GIT_DIR.

## Manual run (advanced: on-box directly, no orchestrator)

If you are already on the box or want to iterate without the lease overhead:

```sh
# On the box:
cd /root/pfBlockerNG
git fetch && git checkout <REF>

# Set required env (normally provided by smoke-on-box.sh):
export SMOKE_SSH_KEY=/root/smoke-ssh-key
export SMOKE_PKG="$(sh scripts/build-leg.sh --ports-dir /root/FreeBSD-ports)"
export SMOKE_IMAGE_DIR=/root/images/pfsense
export SMOKE_CLIENT_IMAGE_DIR=/root/images/civm
export SMOKE_STUB_DNS_ADDR=127.0.0.1
export SMOKE_STUB_DNS_PORT=53

sudo sysctl -w net.ipv4.ip_unprivileged_port_start=53
pkill -9 -f qemu-system-x86_64 2>/dev/null || true

# Run (same argv as CI):
sh scripts/run-smoke.sh --paths tests/smoke -m smoke --timeout 30 --filter "test_dns_redirect"
```

## The two-VM topology

Many cases (`test_dns_redirect.py`, anything depending on `lan_interface`) need the
**civm** Debian client connected to the pfSense LAN, or they SKIP. `smoke-on-box.sh` pulls the
civm image automatically (unless `--no-two-vm` is passed).

The civm OCI image is at `ghcr.io/pfblockerng/civm:v1` (~600 MB). The qcow2 is named
`pfSense-CE-v1.qcow2` and its OCI annotation says "pfSense CE" — **that label is a templated
lie**; the image is the Debian client, not pfSense.

`SMOKE_CLIENT_IMAGE_DIR` must hold **exactly one** `*.qcow2`, so keep it in its own directory
separate from `SMOKE_IMAGE_DIR`.

## Building the `.pkg` off-FreeBSD (CI reference)

The portable Linux builder reproduces `make package` for this `NO_BUILD` port. For CE 2.8
(values from the CE 2.8 entry in the ci-metadata matrix):

```sh
python3 scripts/build-pkg-portable.py \
  --ports /path/to/FreeBSD-ports --channel devel --local-src . \
  --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --out out/
```

`--ports` is a FreeBSD-ports checkout containing `net/pfSense-pkg-pfBlockerNG-devel`.
`pkg add` checks a dep is PRESENT, not its version, so this `.pkg` installs on the
baked-deps image.

`scripts/build-leg.sh` wraps the above with run-keyed defaults (ports-dir, out-dir, channel).
On the box, `smoke-on-box.sh` calls it automatically.

## Driving the pfSense guest — tcsh vs `/bin/sh`

**pfSense `root`'s login shell is `tcsh`, not a POSIX `sh`.** A command sent to the bare
login shell over SSH is therefore parsed by **tcsh**, and tcsh is *not* sh-compatible — so a
script that works in your terminal can silently mis-parse on the guest, producing wrong output
rather than an error. This bit a real investigation: a `grep -E` probe returned a false
`rules.debug:0` (rule "absent") purely because tcsh mangled the command.

**Rule: always wrap guest commands in `/bin/sh -c`.** Never assume the login shell is POSIX.

```sh
# WRONG — runs under tcsh:
ssh root@pf "/usr/bin/grep -nE 'rdr|\\(self\\)|port (53|853)' /tmp/rules.debug"
# RIGHT — force /bin/sh:
ssh root@pf /bin/sh -c "'/usr/bin/grep -nE \"rdr|\\(self\\)|port (53|853)\" /tmp/rules.debug'"
```

tcsh specifically mishandles, vs `sh`:

- redirection — `2>&1` is a syntax error in tcsh (it wants `>&`); a stray `2>&1` mis-parses;
- here-documents and `$(...)` command substitution differ;
- a `grep -E` / `awk` pattern containing `(`, `)`, `|`, `$`, `{` `}` — tcsh's history/glob/var
  parsing can eat them before the program sees them;
- quoting rules and `!` (history expansion) differ.

In the harness this is already handled — `SmokeVM.ssh` routes **every** guest command through
`/bin/sh -c` (the remote argv is re-quoted into one POSIX-sh command line; see
`tests/smoke/conftest.py`). When you add a new on-box command (in the harness or by hand),
keep that contract. The one exception is a **`pfSsh.php`** snippet, which is piped on **stdin**
and ends with `exec` then `exit` (the pfSense developer-shell contract) — that is not a tcsh
command line at all (see the `pfSsh.php` gotcha below).

## Gotchas that cost time

- **Background VM boots get killed.** A plain `nohup boot_vm.sh ... &` from a tool/CI
  shell dies when the shell returns. Fully detach with `setsid` + stdin from `/dev/null`:
  `QMP_SOCK=/tmp/x.sock setsid sh tests/smoke/boot_vm.sh --role pfsense IMG OVERLAY > log 2>&1 </dev/null &`.
  Setting `QMP_SOCK` also switches `boot_vm.sh` to `-serial stdio` (clean for redirection)
  instead of `-serial mon:stdio`.
- **`pfSsh.php` contract.** Pipe the PHP on **stdin**, and the last two lines fed to it
  MUST be a line `exec` then `exit`, or it hangs and is Killed. When wrapping in a shell
  heredoc, QUOTE the inner delimiter (`<<'PHP'`) so the shell does not expand the PHP
  `$variables` before pfSsh sees them.
- **Some pfSense functions are not callable from `pfSsh.php` eval.** `interface_vip_configure`,
  `filter_configure_sync`, etc. need the full rc environment (`shaper.inc`/`interfaces.inc`
  globals); a bare call throws "undefined function" or builds a degraded result. Use the
  `/etc/rc.*` entrypoints (e.g. `/etc/rc.filter_configure_sync`) over SSH instead.
- **SSH hangs on `php ... | tail`.** A pfBlockerNG `update` restarts daemons that inherit
  the command's stdout fd, so a piped reader never sees EOF and SSH blocks to its timeout.
  Redirect to a file in the background and poll: `nohup php ... pfblockerng.php update >/tmp/up.log 2>&1 </dev/null &`,
  or follow with `tail -F`.
- **`pfctl -sn` rendering.** A loaded rdr rule shows the **physical device** (`vtnet2`),
  never the config name (`lan`), and renders **port 53 as `domain`**. Resolve config →
  device with `get_real_interface()` and match `domain`/numeric — do not grep for the
  config name or the literal `53`.
- **Wait on signals, not timing.** After a config change, force a deterministic apply
  (e.g. blocking `/etc/rc.filter_configure_sync`) and read once, rather than polling for an
  async effect against a fixed timeout (the async `filter_configure()` apply can lag).
- **Free the ports between runs.** `pkill -9 -f qemu-system-x86_64` releases the host
  forwards (pfSense ssh 2222 / web 8080, civm ssh 2223) and the LAN crossover socket.
- The published CE image reports `2.8.1-RELEASE` even though its tag is `2.8`.
