# ADR-04 — pfSense CE smoke-base image RUNBOOK (maintainer)

How the version-tagged pfSense CE qcow2 in PRIVATE GHCR is produced, exactly
what is baked into it, and how it is published + verified. This is the
"build-method-agnostic seam" of ADR-04 §2: everything downstream consumes only
the published qcow2 (`oras pull`), so the OS install/provisioning can be done by
hand once per CE version without touching the harness.

**No Packer.** pfBlockerNG compiles nothing and pfSense ships only installer
media; a hand-baked wholesale qcow2 is the accepted path (ADR-04 §7 — a
non-automatable installer is NOT a reject). The PUBLISH and VERIFY steps are
automated; the one clean install is manual.

---

## 1. Output contract

```text
ghcr.io/<org>/pfsense-ce:<PFSENSE_CE_VERSION>     # e.g. :2.8.1
```

- OCI artifact (one qcow2 layer), `artifact-type application/vnd.netgate.pfsense-ce.disk.v1`,
  layer media type `application/vnd.qemu.qcow2`.
- **PRIVATE to the org** (ADR-04 §3 redistribution risk — the image carries
  Netgate binaries/trademarks; never make the package public).
- **CE only, no Plus** (Plus is license-encumbered, out of scope).
- **Immutable, never overwritten.** Each version is its own tag; the seed and
  every upgrade snapshot are retained (recoverable chain + audit trail). The
  scripts refuse to clobber an existing tag without `--force`.

Pull / pin:

```sh
oras pull ghcr.io/<org>/pfsense-ce:2.8.1 -o ./image
oras manifest fetch --descriptor ghcr.io/<org>/pfsense-ce:2.8.1   # digest to pin in CI
```

---

## 2. Base-OS strategy — "seed once, upgrade in place"

ADR-04 §2. Two layers, one output contract.

### 2a. SEED (one clean manual install — done once, archived)

1. On the maintainer's Proxmox host, do **one clean manual pfSense CE install**
   into a VM whose hardware matches the profile in §4 (this is the load-bearing
   part — pfSense keys interface assignment to NIC type/MAC/count).
2. Provision it per §3 (SSH key, base `config.xml`, Unbound `local-data`, serial
   console). **Do NOT install pfBlockerNG** — the harness installs the
   branch-under-test after every boot.
3. Power the VM OFF (a live-disk export is inconsistent).
4. Publish the seed tag from your workstation:

   ```sh
   export SMOKE_GHCR_USER=<user> SMOKE_GHCR_TOKEN=<write:packages token>
   ./scripts/image-publish.sh 2.8.1 --proxmox root@pve.lan --vmid 103
   ```

   `image-publish.sh` exports the powered-off VM's disk
   (`qm config` → `pvesm path` → `qemu-img convert -c` zstd) on the Proxmox host
   over SSH, streams the compressed qcow2 back, and `oras push`es it. `oras` runs
   locally — no GHCR creds on Proxmox.

This export reads a host disk over SSH, so it **cannot run on a GH runner** (no
Proxmox, no LAN). The seed is therefore always maintainer-driven.

### 2b. UPGRADE IN PLACE (every subsequent CE release, incl. major)

The seed is minimal/plain, so the upgrade chain accumulates little cruft.

- **Maintainer / local:**

  ```sh
  ./scripts/image-upgrade.sh --from 2.8.1 --to 2.8.2 \
      --proxmox pve.lan --ssh-key ~/.ssh/smoke_ed25519
  ```

- **CI (canonical):** `.github/workflows/build-image.yml`, `base_source=upgrade`.
  It runs `scripts/image-upgrade.sh` **locally** (the runner is the KVM host, so
  no `--proxmox`): pull `from_version` (local `oras`) → boot a writable copy
  under the runner's KVM → `pfSense-upgrade` over SSH → wait for the new version
  → power off → compress → push the new tag. The source tag is untouched.

The upgrade command (`scripts/image-upgrade.sh`):

```sh
yes | /usr/local/sbin/pfSense-upgrade -d
```

- `-d` = non-interactive/batch. `yes |` hedges against any residual prompt.
- **Readiness/completion is detected by polling `/etc/version` over SSH**, not by
  a fixed sleep: the script records the pre-upgrade version, waits out the
  reboot, and treats "version changed" as done (hard timeout `--upgrade-timeout`,
  default 1800 s). The target tag defaults to the upgraded box's reported version
  (`-RELEASE` stripped) unless `--to` is given.
- **Exact flags should be re-confirmed per CE release** (ADR-04 §6 flags this);
  the version-poll detects completion regardless of how the box reboots.

### 2c. SANITY GATE — publish only on pass, fail closed

The post-upgrade guard is the **smoke round-trip itself**: `build-image.yml`'s
`verify-image` job pulls the freshly published tag, installs the branch `.pkg`,
and runs the Phase-1 round-trip (`tests/smoke/{boot_vm,wait_ready,roundtrip}.sh`).
A red round-trip fails the workflow. A fresh manual re-seed is the fallback only
when the gate fails on a bad upgrade. *(ADR-09 automates the scheduled refresh +
this gate across the version matrix.)*

---

## 3. EXACTLY what is baked (provisioning)

All of this MUST be baked at image-build time: a single-NIC WAN install is
default-deny with no anti-lockout and Unbound refuses WAN-side recursion, so SSH
/ WebUI / DNS are unreachable until the config exists — it cannot be added later
over SSH. `PFSENSE_CE_VERSION`-parameterised. The pfBlockerNG **package** is NOT
baked (the harness `pkg add`s the branch `.pkg`), but its **dependencies ARE**
(see below) so that install runs offline.

| Baked item | Detail / source |
| --- | --- |
| Root SSH pubkey | `SMOKE_SSH_PUB_KEY` → root `authorized_keys`; root SSH enabled. Matching private half is the `SMOKE_SSH_PRIV_KEY` secret the workflows use. |
| pfBlockerNG RUN_DEPENDS | **Convention (do not skip):** bake pfBlockerNG's runtime deps so the harness `pkg add` of the branch `.pkg` resolves them from the local pkg db **offline** (stable deploy; no repo round-trip). **Run [`scripts/misc/install_deps_CE_2.8.sh`](../../scripts/misc/install_deps_CE_2.8.sh) on the box** when preparing the image (one per supported CE version). Full per-version list + purpose: [`docs/misc/pfSense_versions.md`](../../docs/misc/pfSense_versions.md). CE 2.8.x set (9, = the port `RUN_DEPENDS`): `libmaxminddb`, `py311-maxminddb`, `py311-sqlite3`, `lighttpd`, `jq`, `rsync`, `grepcidr`, `iprange`, `gnugrep` (`py311-*` track the base Python — `py312-*` on a 3.12 base; `rsync` is a real run-dep — rsync-format feeds). Authoritative = the port Makefile `RUN_DEPENDS` / `pkg info -d <pkg>`. A missing dep → `pkg add` "Missing dependency" → bad image, re-bake. |
| Admin password | `SMOKE_ADMIN_PASSWORD` (bcrypt) in `config.xml`. Not exercised by the round-trip (SSH = key, WebUI = reachability) — available if scope grows. |
| WAN pass rules | host → **22 (SSH), 80 (WebUI HTTP), 53 (DNS)**. Required — SSH unreachable otherwise. |
| Unbound access-control | `access-control: 10.0.2.0/24 allow` (the SLIRP subnet) — Unbound refuses WAN-side recursion by default (`REFUSED`). |
| Block-private / Block-bogons | DISABLED **if present** (the `10.0.2.2` SLIRP source is RFC1918). On a single-interface install pfSense does not auto-add these — disable only if present. |
| Unbound `local-data` | At least one control name for the deterministic `dig` probe. Spike default `smoke-control.pfb.test` → `192.0.2.123` (workflow inputs `local_data_name` / `local_data_ip`). Per-case control records are injected over SSH by Phase 4, not baked. |
| DNS Resolver | Forwarding mode → Cloudflare `1.1.1.1` / `1.0.0.1`, DNSSEC off. Mode is immaterial to the smoke cases; a fixed external upstream is fail-closed under the egress block. Do NOT forward to the SLIRP `10.0.2.3`. |
| WAN addressing | **DHCP** (SLIRP leases `10.0.2.15`, gw `10.0.2.2`). NEVER bake a static WAN IP — it breaks SLIRP. |
| Serial console | Retained (`-serial`); readiness is gauged by SSH (`wait_ready.sh`), serial is for post-mortem. |

---

## 4. Source-VM HARDWARE PROFILE (do NOT change without re-baking)

pfSense keys interface assignment to NIC type/MAC/count; change any and a clean
boot drops to the console interface-reassignment prompt. `tests/smoke/boot_vm.sh`
mirrors this profile exactly (derived from `qm showcmd 103 --pretty` on the
source Proxmox host, Proxmox host-glue dropped, net backend + disk swapped for
CI). `scripts/image-upgrade.sh` boots with the same MAC.

```text
machine    : pc (i440fx; Proxmox pc+pve0)
cpu        : host  (re-probed by FreeBSD at boot; keeps AES-NI; not a fingerprint axis)
smp / mem  : 2 vCPU (sockets=1,cores=2) / 4096 MB
disk bus   : VirtIO-SCSI (virtio-scsi-pci + scsi-hd); guest sees da0
NIC        : single virtio-net-pci, MAC pinned BC:24:11:37:9C:AC
             (the source VM's MAC; a MAC is not sensitive, so hardcoded — no secret)
smbios     : type=1,uuid=58fd7964-c40c-4f47-bf02-3fdad18f8b00
```

**Disk export:** the qcow2 is the source VM's disk exported wholesale —
`qemu-img convert -O qcow2 -c -o compression_type=zstd <zvol> out.qcow2` (zstd,
zlib fallback) on the Proxmox host (`image-publish.sh`). The published base is
**read-only and never booted directly**: `boot_vm.sh` creates an ephemeral
copy-on-write overlay (`qemu-img create -b base -F qcow2`) and boots that, so
concurrent/repeat runs never mutate the base.

### Host ↔ guest exposure (QEMU user-net / SLIRP)

```text
host 127.0.0.1:2222/tcp -> guest 22   (SSH)
host 127.0.0.1:8080/tcp -> guest 80   (WebUI, HTTP)
host 127.0.0.1:5353/tcp -> guest 53   (DNS, TCP)
host 127.0.0.1:5353/udp -> guest 53   (DNS, UDP)
guest -> runner via the SLIRP alias 10.0.2.2 (mock feeds, later phases)
```

---

## 5. The build-image workflow (publish + verify)

`.github/workflows/build-image.yml` — `workflow_dispatch` (a `schedule` hook is
left commented for ADR-09).

- **Inputs:** `pfsense_ce_version` (target tag), `base_source` (`upgrade` | `seed`),
  `from_version` (upgrade source), `compression`, `upgrade_timeout`, plus verify
  knobs (`verify_boot_timeout`, `local_data_name`, `local_data_ip`).
- **`publish-image` job:** KVM-perms fix (`99-kvm4all.rules`) → install qemu +
  oras → write the guest key from `SMOKE_SSH_PRIV_KEY` → run
  `scripts/image-upgrade.sh` locally (upgrade) or assert the seed tag exists
  (seed; creation is off-runner). `GITHUB_TOKEN: packages: write`; package PRIVATE.
- **`build-pkg` job:** reuses `.github/workflows/build-pkg.yml` to build the
  branch `.pkg` on a FreeBSD 15 VM (matches the CE 2.8.1 base ABI).
- **`verify-image` job:** pulls the freshly published `:version` tag, installs the
  branch `.pkg` (`scripts/install-pkg.sh`), and runs the Phase-1 round-trip
  (`tests/smoke/{boot_vm,wait_ready,roundtrip}.sh`). This is the sanity gate.

### Required Actions config (never commit secrets)

| Name | Kind | Use |
| --- | --- | --- |
| `SMOKE_GHCR_USER` | secret | `oras login ghcr.io` |
| `SMOKE_GHCR_TOKEN` | secret | `write:packages` (publish) / `read:packages` (verify pull) |
| `SMOKE_SSH_PRIV_KEY` | secret | guest SSH private key (public half baked into the image) |
| `SMOKE_IMAGE` | var or secret | GHCR image ref WITHOUT tag (default `ghcr.io/<owner>/pfsense-ce`) |
| `SMOKE_IMAGE_REF` | var or secret | optional: a base OCI ref by digest for verify-only |

`SMOKE_SSH_PUB_KEY` / `SMOKE_ADMIN_PASSWORD` are baked at image-build time, not
consumed by the workflow.

---

## 6. CE-version bump checklist

When the minimum/target supported CE version changes:

1. `build-image.yml` `base_source=upgrade`, `from_version=<prior>`,
   `pfsense_ce_version=<new>` → publishes + verifies the new tag.
2. If the upgrade gate fails, re-seed manually (§2a) and re-run verify.
3. Update `tests/smoke` / boot defaults if the hardware profile or baked
   `local-data` changed (it should not for a routine CE bump).
4. Regenerate `stubs/pfsense/` per `CLAUDE.md` if the bump is a real base change.

This image-rebuild step is wired into the CE-version-bump docs in Phase 6.
