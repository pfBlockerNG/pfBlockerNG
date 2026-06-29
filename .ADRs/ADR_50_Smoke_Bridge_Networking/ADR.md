# ADR-50: Bridge networking for the smoke VMs (SLIRP → tap+bridge)

- **Status:** **Rejected** (2026-06-29) — P1–P4 were implemented and the P5 live A/B ran, but
  bridge mode showed **no wall-clock win** (per-step parity with slirp; the smoke run is
  guest-compute-bound, not transport-bound) and exposed a hermetic-egress WAN-path gap. The
  `SMOKE_NET_MODE` machinery is being **removed in full**; `slirp` remains the sole backend. Full
  outcome in **§9**. (History: P1 `SMOKE_NET_MODE` toggle, PR #615; P2–P4 setup/conftest/CI, PR #616.)
- **Date:** 2026-06-29
- **Branch:** ADR text authored directly on `devel` (ADR-text carve-out); implementation on `smoke/bridge-networking` via the normal PR flow / **Component(s):** `tests/smoke/boot_vm.sh`, `tests/smoke/conftest.py`, the box-setup/lease path (ADR-47), `.github/workflows/{smoke-single,ui-tests}.yml`
- **Target runtime:** GitHub Actions runners (CI) + developer LXC/KVM boxes (local) — POSIX sh + Python 3.11
- **Test suite:** `shellspec` (`tests/shell/boot_vm_spec.sh`), the live-VM smoke fan-out (ADR-04), and an A/B timing comparison (slirp vs bridge)

---

## 1. Context

The ADR-04 smoke suite is slow on GitHub-hosted runners. Two levers already landed on `devel`:

- **#611 / PR #612** — `CaseContext` collapses an IP case's enter from two heavy reloads to one.
- **#613** — QEMU boot tuning (`iothread` + `aio=io_uring` + `+kvm_pv_*`).

The remaining lever is the **network backend**. The smoke VMs use QEMU **SLIRP** user-net
(`-netdev user,…,hostfwd=…`): a userspace NAT whose packets are copied through QEMU's main thread,
with non-trivial per-connection setup latency. The harness drives the guest over SSH almost
entirely — *hundreds* of round-trips per run (every reload, `snap_state`, probe, plus the bulk
`collect_host_diagnostics` log pull). SLIRP's latency × that round-trip count, plus the main-loop
CPU it burns, is real wall-clock.

**Hypothesis:** moving WAN/MGMT to **tap devices on host Linux bridges** (kernel datapath) cuts
total wall-clock + QEMU main-loop CPU. **Honest scope:** it will *not* dent the ~30s *guest-internal*
reload compute (PHP feed-parse + `filter_configure`), which reproduces even on a bare-metal box —
that is #611 territory. This ADR targets the harness/transport overhead, not guest compute.

SLIRP gives DHCP + DNS + NAT + a host alias (`192.168.89.2`) and host→guest `hostfwd` for free; a
bare bridge gives none of that, so the design must reproduce each piece. Two facts make it tractable:

- **The smoke flow is hermetic / runner-local.** The mock-feed HTTP server + sinkhole bind
  `0.0.0.0:<port>` on the runner; the stub DNS binds the runner; the guest reaches all of it via the
  single SLIRP host alias `192.168.89.2` (and `192.168.89.2:53` → runner `127.0.0.1:53` for DNS).
- **`pkg add` is OFFLINE** — pfBlockerNG's RUN_DEPENDS are baked into the smoke image
  (`scripts/misc/install_deps_CE_2.8.sh`); the install never hits the network.

So a bridge needs **no internet NAT** — it only has to reproduce `192.168.89.2` as a real runner IP
and supply DHCP. This composes with **ADR-47** (local/CI execution parity): the per-box bridge
setup is an ADR-47-style per-box concern (box-setup/lease path), and the per-leg test surface
(`run-smoke.sh` / pytest) stays identical across CI and local.

## 2. Decision

Add a **`SMOKE_NET_MODE` toggle** (`slirp` | `bridge`), **default `slirp`** (byte-identical to
today). `bridge` is opt-in until an A/B proves it faster, at which point the default flips. The
toggle *is* the A/B mechanism: run the same commit under each mode and compare.

`bridge` mode:

- **Two bridges, separate subnets** — `br-wan` `192.168.89.2/24` (WAN), `br-mgmt` `192.168.43.2/24`
  (MGMT). The runner holds `.2` on each; the guest reaches the runner-local servers at the SAME
  `192.168.89.2` the SLIRP path used.
- **`dnsmasq` per bridge** for DHCP (SLIRP's built-in DHCP is gone), auto-announcing itself as
  gateway + DNS per subnet; a **static MGMT lease** (`→192.168.43.15`) gives a deterministic SSH
  target.
- **No internet NAT** (hermetic; `pkg add` offline). The stub DNS moves its bind from
  `127.0.0.1:53` to the bridge IP `192.168.89.2:53`; the harness SSHes the guest's **MGMT bridge IP**
  instead of the SLIRP `hostfwd` (`127.0.0.1:2222`).
- The **LAN crossover socket** (net2 / civm net1) and the unassigned **net3-7** are unchanged in
  both modes — only WAN + MGMT switch backend. The NIC backend swap (`user` → `tap`) is transparent
  to the guest (same `virtio-net-pci` device + MAC), so there is **no interface-reassignment** risk.

## 3. Consequences

**Positive:** lower per-round-trip SSH latency + less QEMU main-loop CPU → expected lower wall-clock,
especially on the diagnostics pull; production-like networking; the toggle keeps SLIRP as a safe
default + a one-flag rollback.

**Negative / costs:** a per-box bridge+dnsmasq setup to author + maintain; `dnsmasq` baked into the
box image; on **LXC** dev boxes a one-time host change to expose `/dev/net/tun` (see §7); a second
moving part (the bridge/dnsmasq) that can fail independently of QEMU.

## 4. Alternatives considered

- **Keep SLIRP.** The baseline. Rejected only if the A/B shows a real win; if it does not, this ADR
  ships the toggle but leaves the default `slirp`.
- **vhost-net without a bridge.** Still needs a tap; the bridge is what gives the runner-local
  server reachability. No simpler.
- **Pass real internet NAT (MASQUERADE).** Unneeded — the flow is hermetic + `pkg add` is offline.
  Adding NAT would only widen the blast radius. Rejected.
- **One bridge for WAN+MGMT.** Rejected — two NICs on one subnet break pfSense routing/anti-spoof
  (proven in the derisk; the guest's outbound to `.2` failed). Separate subnets, mirroring SLIRP.

## 5. Resolved design

### 5.1 The toggle (LANDED — P1)

`tests/smoke/boot_vm.sh` reads `SMOKE_NET_MODE` (default `slirp`). In `bridge` mode the WAN/MGMT
NICs become `-netdev tap,ifname=$TAP,script=no,downscript=no` where the tap names are passed in
(`SMOKE_WAN_TAP`, `SMOKE_MGMT_TAP` for the pfsense role; `SMOKE_CLIENT_MGMT_TAP` for civm) by the
per-box setup (§5.2). The qemu binaries are env-overridable (`SMOKE_QEMU_BIN` / `SMOKE_QEMU_IMG_BIN`)
so the shellspec is hermetic. `slirp` mode emits the exact pre-toggle argv.

### 5.2 Per-box bridge + dnsmasq setup (P2 — the keystone remaining)

A setup step, run **once per box in the box-setup/lease path** (ADR-47: `smoke-on-box.sh` /
`select-box.sh`, **not** the per-leg `run-smoke.sh`), does:

- create `br-wan` (`192.168.89.2/24`) + `br-mgmt` (`192.168.43.2/24`) via `ip link add … type bridge`;
- create **per-lane** taps (unique names, keyed off `SMOKE_LANE` so parallel lanes don't collide),
  attach to the right bridge, bring up;
- run `dnsmasq` bound to the two bridges (`port=0` = DHCP only; one `dhcp-range` per subnet; it
  auto-announces itself as gw+DNS), with a **static MGMT lease** (`dhcp-host=<mgmt-mac>,192.168.43.15`)
  so the SSH target is deterministic;
- export `SMOKE_WAN_TAP` / `SMOKE_MGMT_TAP` / `SMOKE_CLIENT_MGMT_TAP` for `boot_vm.sh`, and the MGMT
  IP for `conftest`.

`dnsmasq` must be **baked into the box image** (it is not installed on the current boxes). Teardown
removes taps/bridges + stops the dnsmasq instance. Lane isolation + idempotency follow the ADR-47
lease model.

### 5.3 conftest + stub DNS (P3)

`tests/smoke/conftest.py`: when `SMOKE_NET_MODE=bridge`, `SmokeVM.ssh` targets the guest's MGMT
bridge IP (`192.168.43.15` static lease) instead of `127.0.0.1:<hostfwd>`. The stub DNS binds the
bridge IP (`192.168.89.2:53`) rather than `127.0.0.1:53` (systemd-resolved sits on `127.0.0.53:53`,
so the bridge IP `:53` is free — no conflict). The mock-feed/sinkhole already bind `0.0.0.0`. All of
this is guarded by `SMOKE_NET_MODE` so `slirp` is untouched.

### 5.4 CI wiring (P4)

`smoke-single.yml` + `ui-tests.yml` gain a bridge-setup step (productionize the derisk's
create-bridges+dnsmasq) before pytest, active when `SMOKE_NET_MODE=bridge`. GH runners have
`/dev/net/tun` natively (no host change); the KVM-perms udev step already present is unrelated and stays.

### 5.5 A/B + flip (P5)

Run the SAME commit under `slirp` (default) and `SMOKE_NET_MODE=bridge` — dispatch the smoke
fan-out twice, or `local-smoke.sh` with each mode — and compare the `PFB_TIMING` per-step log +
total wall-clock (the #605 instrumentation makes this a direct read). Flip the default to `bridge`
**iff** it is a clear win on the CE+Plus fan-out; otherwise keep `slirp` and leave the toggle opt-in.

## 6. Phases

- **P1 — `SMOKE_NET_MODE` toggle (DONE; PR #615, branch `smoke/bridge-networking`).** `boot_vm.sh`
  gains the toggle (slirp byte-identical; bridge consumes `SMOKE_*_TAP`). Pinned by
  `tests/shell/boot_vm_spec.sh` (both modes × both roles + fatal guards). Also fixed a **latent bug**
  the spec exposed: `cleanup()` (the `EXIT` trap) ended with status 0, masking **every** error-path
  exit as success — now preserves `$?` (and uses explicit `exit 1` guards, since bash 3.2 reports
  `$?`=0 for `${VAR:?}` under an EXIT trap). Behaviour-preserving; bridge mode dormant until P2/P3.
- **P2 — per-box bridge+dnsmasq setup (§5.2) (DONE; PR #616).** New `scripts/bridge-net.sh up|down`
  (br-wan/br-mgmt, per-lane taps, DHCP-only dnsmasq with static MGMT leases keyed off the real
  net1/civm MACs, fail-closed input validation, no-`eval` `KEY=value` emit). Wired into the ADR-47
  box-setup path (`smoke-on-box.sh` Step 4 + `--net-mode` through `local-smoke.sh`). Pinned by
  `tests/shell/bridge_net_spec.sh`. **Out-of-CI items (documented, not blockers):** baking `dnsmasq`
  into the box image + the LXC `/dev/net/tun` host passthrough (§7.1) live in
  `docs/misc/local-smoke-debian.md`; GH runners have `tun` natively.
- **P3 — conftest SSH→MGMT-IP + stub-DNS rebind (§5.3) (DONE; PR #616).** `SMOKE_NET_MODE`-guarded;
  bridge mode targets the guest MGMT bridge IPs (pfSense `.15` / civm `.16`) on :22 and binds the
  stub DNS at `192.168.89.2:53`. Off-box unit test `tests/test_smoke_net_mode.py` (both modes +
  overrides + invalid-mode), slirp byte-identical.
- **P4 — CI bridge-setup step (§5.4) (DONE; PR #616)** in `smoke-single.yml` + `ui-tests.yml` (gated
  `net_mode == 'bridge'`, default slirp = byte-identical), `net_mode` forwarded through the `smoke.yml`
  fan-out so P5's A/B is dispatchable across CE+Plus.
- **P5 — A/B (§5.5) (REMAINING).** Run the live-VM fan-out under both modes, record bridge timing,
  and (conditionally) flip the default. Also finalizes the live-only details the shellspec/actionlint
  can't assert: tap ownership vs non-root QEMU (may need a `user` on the tap), and that dnsmasq serves
  DHCP + auto-announces option 3/6 (§7.3).

**Out of scope:** the ~30s guest-internal reload cost (#611); provisioning the LXC pool / the host
tun passthrough (user-owned infra, §7); vhost-net micro-tuning (revisit only if the A/B is marginal).

## 7. Adversarial verification (de-risk findings — both environments PASS)

The design was de-risked end-to-end before this ADR. A standalone harness booted the real pfSense
smoke image on a bridge and asserted boot + DHCP + SSH + guest→runner HTTP.

- **Local LXC box (10.0.0.31): PASS** — WAN `192.168.89.37`, MGMT `192.168.43.45`, `SSH_OK`,
  guest→runner HTTP OK. Harness: `bridge-derisk.sh` (kept in the session scratchpad).
- **GH-hosted runner: PASS (~1 min)** — run `28352290881`; same checks green. (The throwaway
  `bridge-derisk.yml` that drove it was removed from the branch after; evidence is in run history.)

Gotchas found + resolved (each folded into §5):

1. **LXC has no `/dev/net/tun`.** The dev boxes are LXC containers; SLIRP never needed tun, so the
   cgroup device policy denied it (`ip tuntap add` → "Operation not permitted"). **Host-side fix**
   (run on the Proxmox host, per container `.conf`, then restart): `lxc.cgroup2.devices.allow: c
   10:200 rwm` + `lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file 0 0`. Applied to
   the pool 2026-06-29. **GH runners are VMs with tun present — unaffected.**
2. **WAN + MGMT must be on SEPARATE subnets/bridges.** Both on one subnet → pfSense
   routing/anti-spoof ambiguity → the guest's outbound to `.2` fails (`fetch: Permission denied`)
   while runner→guest replies still work. Mirror SLIRP's split (89.x / 43.x).
3. **`dnsmasq` is required** (SLIRP's DHCP is gone) and is NOT on the boxes — bake it into the image
   or have the setup install it. `port=0` (DHCP only) + one `dhcp-range` per bridge; it auto-sets
   option 3/6 to its own per-subnet address.
4. **Stub-DNS bind.** Move `127.0.0.1:53` → the bridge IP (`192.168.89.2:53`); systemd-resolved on
   `127.0.0.53:53` (loopback) does not conflict.
5. **qcow2 relative backing path.** A qcow2 overlay resolves a relative `-b` backing path against
   the OVERLAY's dir (`/tmp`), not cwd — pass the base image as an **absolute** path. `boot_vm.sh`
   already does this (its absolute-base block); keep any new harness consistent.
6. **EXIT-trap exit-status masking** (fixed in P1) — see §6.
7. **`workflow_dispatch` only registers on the default branch.** A branch-only workflow must trigger
   `on: push` to fire (this is why the GHA derisk used `on: push`). Relevant if a future throwaway
   validation workflow is added on a feature branch.

## 8. Acceptance

Per the CLAUDE.md ADR-acceptance rule (green automated coverage, no manual sign-off): P1's shellspec
is green; P2–P4 each ship with their tests; **P5's A/B** runs the live-VM smoke fan-out (CE + Plus)
under both `slirp` and `bridge` and they are both green, with the bridge timing recorded. The ADR is
**Accepted** when bridge mode is green on the fan-out AND the A/B is captured; the default flips to
`bridge` only if it is a clear win (else the toggle ships opt-in, which is still a complete,
documented outcome). The host-side LXC tun passthrough (§7.1) is a documented out-of-CI prerequisite
for the local path, not an acceptance blocker for CI.

---

## 9. Outcome — Rejected (2026-06-29)

P1–P4 were implemented (PR #615 + #616) and the **P5 live A/B** ran the full CE+Plus smoke fan-out
on the same commit under both modes ([slirp run 28360739642](https://github.com/pfBlockerNG/pfBlockerNG/actions/runs/28360739642),
[bridge run 28360747842](https://github.com/pfBlockerNG/pfBlockerNG/actions/runs/28360747842)). The result rejects the hypothesis:

- **Bridge transport works.** The guest booted, took the static MGMT lease (`192.168.43.15`), and the
  harness drove it over the bridge (`sshd … 192.168.43.15:22`); DNS probes + most feed tests ran. The
  feared tap-ownership / non-root-QEMU issue (§7) was a **non-issue** on the GH runner.
- **No wall-clock win.** For every step both legs ran, `PFB_TIMING` medians are within noise
  (`reload:cron` 35.72 s vs 35.84 s; `php_eval` 1.57 vs 1.55; `pfb_trigger` 3.35 vs 3.02; ssh: means
  equal). The smoke run is **guest-compute-bound** (PHP feed-parse + `filter_configure`), exactly the
  ADR's §1 "honest scope" caveat — SLIRP's transport latency was never the bottleneck, so removing it
  buys ≈ nothing.
- **WAN-path gap.** The hermetic egress block (`helpers.block_egress`, CI smoke only) opens only
  loopback (`-o lo`). slirp's feed path is NAT'd to `127.0.0.1` so it survives; bridge reaches the
  mock feed server at the runner's `br-wan` IP (`192.168.89.2`) — a non-loopback interface the block
  severs → 255 `cURL Error: 7` → feed-test errors + the 45-min job timeout. It passed locally / in the
  §7 de-risk because `SMOKE_BLOCK_EGRESS` is set **only** by the CI smoke matrix (not `local-smoke.sh`,
  not the de-risk harness), so the egress-blocked feed path over a bridge had never run anywhere else.

**Decision:** since fixing the egress carve-out would yield a *passing* but still not *faster* bridge
(the timing parity is independent of the WAN bug), bridge mode is **not worth carrying even as opt-in**.
The `SMOKE_NET_MODE` machinery (P1–P4) is **removed in full** — `boot_vm.sh` toggle, `scripts/bridge-net.sh`,
the conftest targeting, the box-setup/CI wiring, and the docs — restoring slirp-only. The independent
`cleanup()` exit-status fix from P1 (§6) is a genuine bug fix and is **kept**. Removal PR tracked
separately; this ADR stands as the record of why bridge was tried and dropped.
