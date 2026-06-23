# Running the live-VM smoke suite locally on Debian

Dev-only notes for running `tests/smoke/` (ADR-04) on a plain Debian/KVM box, outside
GitHub Actions. These are the things that cost real time to (re)learn; the CI workflow
(`.github/workflows/smoke.yml`) is the source of truth for the canonical invocation.

## Prerequisites

- `/dev/kvm` present and writable (hardware virtualisation). Everything needs KVM.
- `qemu-system-x86_64`, `qemu-img`, `ssh`, `oras`, `python3` (3.11+), `python3-venv`.
- The guest SSH key (the smoke image bakes a fixed key); export it as `SMOKE_SSH_KEY`.
- A pfSense CE qcow2 (`SMOKE_IMAGE_DIR` — a directory holding exactly one `*.qcow2`).
- A built branch `.pkg` (`SMOKE_PKG`) — see "Building the .pkg".

```sh
python3 -m venv .venv
.venv/bin/pip install -r tests/smoke/requirements.txt
# ruff is NOT in requirements (it is a lint tool, not a harness dep):
.venv/bin/pip install ruff   # only if you want to lint here
```

## The two-VM topology (required for the DNS-redirect / LAN-client cases)

Many cases (`test_dns_redirect.py`, anything depending on `lan_interface`) need the
**civm** Debian client connected to the pfSense LAN, or they SKIP. Two extra pieces:

### 1. The civm client image

```sh
mkdir -p /path/to/civm
cd /path/to/civm && oras pull ghcr.io/pfblockerng/civm:v1   # ~600 MB
# Point the harness at the DIRECTORY (it globs for exactly one *.qcow2):
export SMOKE_CLIENT_IMAGE_DIR=/path/to/civm
```

- The qcow2 is named `pfSense-CE-v1.qcow2` and its OCI annotation says "pfSense CE" —
  **that label is a templated lie**; the image is the Debian client, not pfSense.
- `SMOKE_CLIENT_IMAGE_DIR` must hold **exactly one** `*.qcow2`, so do **not** drop it
  next to the pfSense qcow2 in `SMOKE_IMAGE_DIR` — use a separate directory.

### 2. The stub-DNS-on-:53 relay

The harness mock DNS must bind the runner's `127.0.0.1:53` so libslirp can NAT the guest's
`10.10.0.2:53` (WAN host alias) to it, port-preserving:

```sh
# Let a non-root process bind :53 (systemd-resolved sits on .53/.54, so :53 on 127.0.0.1 is free):
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=53
export SMOKE_STUB_DNS_ADDR=127.0.0.1
export SMOKE_STUB_DNS_PORT=53
```

Without these the DNSBL-upstream self-check (`use_system_dns_upstream`) times out and the
`deployed_vm` fixture errors during setup (the symptom is a `drill @127.0.0.1` SSH timeout).

## Running

```sh
SMOKE_SSH_KEY=/path/to/key \
SMOKE_PKG=/path/to/pfSense-pkg-pfBlockerNG-devel-X.Y.Z.pkg \
SMOKE_IMAGE_DIR=/path/to/images \
SMOKE_CLIENT_IMAGE_DIR=/path/to/civm \
SMOKE_STUB_DNS_ADDR=127.0.0.1 SMOKE_STUB_DNS_PORT=53 \
.venv/bin/python -m pytest tests/smoke/test_dns_redirect.py \
  -m smoke --override-ini="addopts=" -rA
```

`-m smoke --override-ini="addopts="` is mandatory: the default `addopts` has
`--ignore=tests/smoke`, so a plain `pytest` collects nothing here.

`scripts/local-smoke.sh` wraps the env setup (sysctl, civm pull, defaults) — see its
`--help`.

## Building the `.pkg` off-FreeBSD

The portable Linux builder reproduces `make package` for this `NO_BUILD` port. For CE 2.8
(FreeBSD 15):

```sh
python3 scripts/build-pkg-portable.py \
  --ports /path/to/FreeBSD-ports --channel devel --local-src . \
  --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --out out/
```

`--ports` is a FreeBSD-ports checkout containing `net/pfSense-pkg-pfBlockerNG-devel`.
`pkg add` checks a dep is PRESENT, not its version, so this `.pkg` installs on the
baked-deps image.

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
