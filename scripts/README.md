# Dev scripts

Helper scripts for developing, deploying, and building pfBlockerNG. **Dev-only** —
none of this ships in the release archive (which contains only `src/`).

## Deploy / install onto a pfSense box

| Script | Use |
| --- | --- |
| [`install-from-repo.sh`](install-from-repo.sh) | **First-time install** onto a clean pfSense from `src/` — no Netgate pkg. |
| [`deploy.sh`](deploy.sh) | Fast code update of an **already-installed** pfBlockerNG: rsync `src/` + restart unbound/nginx. |
| [`setup-hooks.sh`](setup-hooks.sh) | Point git at `.githooks` (run once after cloning). |
| [`update-pfsense-stubs.py`](update-pfsense-stubs.py) | Regenerate `stubs/pfsense/` after a CE bump. |

`install-from-repo.sh` syncs the files then runs the port's real install hook —
`php -f /etc/rc.packages pfSense-pkg-pfBlockerNG-devel POST-INSTALL` (exactly what
`pkg` runs) — which registers the menu/services and runs `pfblockerng_install.inc`.
It is **all local: no internet, no Netgate pkg**, so it works even with egress blocked
(and is also handy for installing onto a local dev VM).

## Image pipeline (ADR-04 smoke base)

The CI smoke harness — see [`../.ADRs/ADR_04_VM_Smoke_Tests/`](../.ADRs/ADR_04_VM_Smoke_Tests/) —
boots a real pfSense CE VM. **No Packer**: pfBlockerNG compiles nothing.

| Script | Use |
| --- | --- |
| [`image-publish.sh`](image-publish.sh) | Export a powered-off VM's ZFS zvol → compressed (zstd) qcow2 → `oras push` to GHCR by CE version. Old tags kept. |
| [`image-upgrade.sh`](image-upgrade.sh) | Pull a tag → boot a **copy** → `pfSense-upgrade` → power off → publish a new version tag. Source image untouched. |

### Driving from your machine

Both scripts run **from your laptop** against a remote Proxmox/KVM host — pass
`--proxmox [user@]host` (+ `--proxmox-port` / `--proxmox-ssh-key`, or the
`PROXMOX_SSH_HOST`/`USER`/`PORT`/`KEY` env vars). The **native** steps
(`qm`/`pvesm`/`qemu-img`/`qemu-system` — all shipped with Proxmox VE) run there
over SSH; **`oras` runs locally**, so no GHCR creds and nothing extra need
installing on Proxmox. The image is converted/compressed on Proxmox and
**streamed** over SSH. For `image-upgrade.sh` the guest is reached by **jumping
through Proxmox** (`ProxyCommand -W`), so the guest SSH key never leaves your
machine. Omit `--proxmox` to run directly on the host, as before.

```sh
# publish the seed image (driving a remote Proxmox host)
./scripts/image-publish.sh 2.8.1 --proxmox root@pve.lan

# bump a published image to a newer CE release
./scripts/image-upgrade.sh --from 2.8.1 --proxmox pve.lan --ssh-key ~/.ssh/smoke_key

# or set the host once and call bare
export PROXMOX_SSH_HOST=pve.lan PROXMOX_SSH_USER=root
./scripts/image-publish.sh 2.8.1
```

## Two install paths: CI/local vs release

| | `install-from-repo.sh` (rsync + hook) | Real `.pkg` (`pkg add`) |
| --- | --- | --- |
| Use | CI smoke + local dev | GitHub Release artifact |
| Deps | none (no VM, no internet) | FreeBSD build VM |
| Tests | runtime behaviour | the shipping artifact + the real `pkg` path |
| Catches pkg-plist drift | no (rsync copies everything) | **yes** |

For the smoke matrix, `install-from-repo.sh` is enough and faster. Build the real
`.pkg` for the GitHub Release artifact and as a higher-fidelity packaging gate.

## ABI: what actually matters for the `.pkg`

pfBlockerNG ships no compiled files, but the port (`net/pfSense-pkg-pfBlockerNG-devel`)
**run-depends on `net/libmaxminddb`** (a compiled C lib, `mmdblookup`) and does **not**
set `NO_ARCH`, so the package is ABI-tagged `FreeBSD:<major>:<arch>` (e.g.
`FreeBSD:15:amd64`).

- `pkg` gates installs on the **OS major**. A `FreeBSD:15` package on a `FreeBSD:16`
  system is **refused by default**; `pkg add -f` forces it — functionally safe here
  (no binaries of ours; the smoke image bakes pfBlockerNG's run-deps incl.
  `libmaxminddb`, so `pkg add` resolves them locally/offline).
- So **build one `.pkg` per distinct FreeBSD major**, on a FreeBSD VM pinned to that
  major. One build covers every pfSense version on that major. Rebuild only on a
  **FreeBSD-major jump** (rare; coincides with raising the minimum supported version).
- `NO_ARCH` would wildcard the **arch**, not the OS major — it does not make the
  package cross-major.
- pfSense **Plus** artifacts build fine without a Plus license (you only need the
  right FreeBSD-major build env); Plus is **build-only** — it can't be tested in CI
  (no licensed image).

### Support matrix → builds

| Target | FreeBSD major | `.pkg` build | CI smoke |
| --- | --- | --- | --- |
| Previous CE major (e.g. 2.7.x) | 14 | yes | yes |
| Current CE major (e.g. 2.8.x) | 15 | yes | yes |
| Current Plus major | 15 (today) | only if its major diverges | no (licensing) |

Artifacts = **one per distinct FreeBSD major**; CI = one image per CE minor, never Plus.
The scheduled version-tracking + release-automation design is its own ADR.
