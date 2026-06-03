# ADR-04: End-to-end smoke tests against a real pfSense VM in CI

- **Status:** **Implemented — pending maintainer live-smoke** (2026-06-02; proposed 2026-05-31). All six phases are built and merged on `adr/04`; the automated harness is code-complete. Flips to **Accepted** only after (a) the `smoke.yml` matrix is green on a `gh`-dispatched CI run and (b) the maintainer confirms the §7 manual checklist on a live box.
- **Date:** 2026-05-31
- **Branch:** `adr/04` (off `devel`) / **Component(s):** new dev-only tooling — `packer/`, `tests/smoke/`, `.github/workflows/` (a build workflow + a smoke workflow); reuses `scripts/deploy.sh`. **No shipped (`src/`) code changes.**
- **Target runtime:** the harness runs on a GitHub-hosted `ubuntu-latest` runner (Python 3.11+, **dev-only third-party deps allowed** — see §5). The system under test is **pfSense CE (latest stable, CE only)** in a QEMU/KVM VM, driving the real `pfb_unbound.py` (Python in Unbound's `pythonmod`) and the real PHP/`pfctl` IP path.
- **Test suite:** new `tests/smoke/` (pytest, marker `smoke`, **deselected from the default run**); existing `tests/test_pfb_unbound.py` is untouched.

---

## 1. Context

### Today

Every prior ADR (01 §3, 02, 03 §3/§7) records the same hole: **there is no live Unbound — and no live pfSense — in CI.** Correctness of the DNSBL hot path and the IP/firewall path is verified only by:

- `tests/test_pfb_unbound.py` — a pytest **oracle** that imports `pfb_unbound.py` with Unbound's API symbols stubbed (`stubs/python/unboundmodule.py`, copied onto `builtins` by `tests/conftest.py`). It pins *matcher logic*, not the running resolver.
- A **manual smoke checklist owned by the maintainer** (ADR-01 §7, ADR-03 §7 / `RESULTS/03_Results.txt`) — run by hand on a physical/VM pfSense box via `scripts/deploy.sh`, never automated.

So a regression that only manifests inside a running Unbound, or in the `pfctl` alias-table / firewall-rule path, or in the PHP↔Python sqlite coexistence, is **invisible to CI** and caught only if a human remembers to run the checklist. ADR-03 shipped "IMPLEMENTED (pending smoke test)" precisely because of this.

### Load-bearing facts (verified)

1. **Deploy already exists.** `scripts/deploy.sh <ssh-target>` rsyncs `src/usr/` and `src/etc/` to a live box, then `pfSsh.php playback svc restart unbound` + `... svc restart nginx`. It is the deploy mechanism the harness reuses unchanged — only an SSH-reachable target is needed.
2. **pfBlockerNG has a first-class PHP CLI** (the cron entry point), in `src/usr/local/www/pfblockerng/pfblockerng.php`:
   - `:66` `clearip`, `:72` `cleardnsbl` — reset state.
   - `:173` gate → `:179` switch: `:188` **`update`** → `sync_package_pfblockerng('cron')` (Force update, IP **and** DNSBL); `:184` **`updateip`** / `:185` **`updatednsbl`** (targeted, faster per matrix case); `:180` `cron`.
   - Invoked as **`/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php update`** — the *exact* production entry point: the cron job is `… pfblockerng.php cron` (`pfblockerng.inc:10610`, installed `:10631`) and the package self-invokes the same way (`inc:7961/8086/9000`). The harness uses it for **fidelity** (drives the real path, no wrapper) — *not* because `pfSsh.php playback` is worse. Note there is **no `pfblockerng` playback script** shipped (the `pfSsh.php playback pfblockerng update` at `deploy.sh:93` is only an echoed tip, unverified); the `svc restart` playbacks deploy.sh runs are real pfSense built-ins.
3. **The IP path is observable over SSH.** `pfblockerng.sh` drives `pathpfctl=/sbin/pfctl`; pfBlockerNG materialises each list into a pf alias table. `pfctl -t <alias> -T show` dumps a table's members and `pfctl -sr` dumps the ruleset — enough to assert the IP side without a UI.
4. **The DNSBL response set is small and enumerable.** `pfb_unbound.py` returns one of a few shapes: `NXDOMAIN` (9 refs), a null IP (`0.0.0.0`/configured null-block VIP), or a DNSBL-webserver/VIP answer (`set_return_msg`, 24 refs). A `dig`-level assertion (rcode + record) distinguishes them.
5. **Existing CI shape to mirror.** `.github/workflows/test.yml` runs on `push` (main/devel) + `pull_request`, on `ubuntu-latest`, a `python-version` matrix (3.11–3.13), `pip install pytest` → `python -m pytest`. The smoke workflow is a **separate** workflow (different cost/runtime profile), not a new job in `test.yml`.
6. **Dev-only third-party deps are already precedent.** Shipped code (`pfb_unbound.py`) is stdlib-only because it runs in Unbound's loader; **dev tooling is not** — ADR-01's `benchmarks/requirements.txt` pulled in `pytest-benchmark`/`pympler`. The smoke harness (in `tests/smoke/`, never shipped in the release archive) may therefore depend on `dnspython`/`paramiko`/`oras`.
7. **No pfSense cloud image exists to borrow; the OS install is the only hard part.** pfSense CE ships only as installer media; there is no free, redistributable cloud image. Fully unattended install **is possible but unofficial and fragile** — it needs media surgery (an `etc/installerconfig` script + `rc.local` edits: `TERM=vt100`, comment out the console-type dialog) or brittle `boot_command` keystrokes; Netgate doesn't support it (uses `pfi.conf`, not clean FreeBSD `installerconfig`), reports say it doesn't fully automate, and it is version-fragile. **Key seam:** everything downstream consumes only the published qcow2 (`oras pull`), so it is **install-method-agnostic** — the OS install can be automated *or* done by hand once per CE version without affecting the harness. pfSense **Plus** is license-encumbered and **out of scope** (CE only).

---

## 2. Decision

Build a CI smoke harness that boots a **real pfSense CE VM**, deploys the branch-under-test with the existing `scripts/deploy.sh`, drives pfBlockerNG via its PHP CLI, feeds it lists from **mock HTTP servers on the runner**, and asserts both the IP path (`pfctl`) and the DNS path (`dig`) with **pytest**. Image **build** and per-PR **test** are two separate workflows; the image is cached in GHCR.

**The premise is unproven and is falsified first (Phase 1), before any Packer investment** — exactly the discipline ADR-01 lacked (built 8 phases, then rejected on evidence).

| Area | Decision |
| --- | --- |
| **Runner** | GitHub-hosted `ubuntu-latest` with `/dev/kvm` (nested virt). **Spike-gated** (Phase 1): if boot-time/flakiness misses the kill-threshold (§7), pivot to a self-hosted runner — recorded in the ADR, not shipped flaky. |
| **VM** | QEMU `x86_64` + KVM accel, headless, serial console. One **pfSense CE** guest (version-parameterised — ADR-04 validates one CE version; ADR-09 fans the harness across versions), **one NIC = WAN only** (no LAN — single-interface pfSense; the harness drives everything over WAN). **VirtIO throughout** (virtio-net NIC + VirtIO-SCSI disk), `-cpu host`, **2 vCPU / 4 GB RAM / 4 GB disk**. Booted in the test job with plain `qemu-system-x86_64` whose hardware **mirrors the source Proxmox VM** (machine type, `scsihw`, NIC model + MAC — derive via `qm showcmd <vmid> --pretty`) so the one published qcow2 boots without pfSense re-detecting hardware — **Packer is not invoked at test time**. (`-cpu host` is safe across runners: FreeBSD re-probes the CPU at boot, so CPU model is **not** a hardware-fingerprint axis like NIC type/MAC/count, and `host` passes AES-NI for Unbound crypto.) |
| **Networking** | QEMU **user-net (SLIRP)** on the single WAN NIC — no bridge/tap/sudo, runs as-is on GH-hosted `ubuntu-latest` (bridge-to-physical is a non-starter there: cloud-fabric MAC/IP anti-spoofing drops a guest MAC). WAN stays **DHCP** — SLIRP leases `10.0.2.15` / gw `10.0.2.2`; never bake a **static** WAN IP (a lab static breaks SLIRP networking — a fixed lab IP belongs in a parent DHCP reservation on the pinned MAC, not a pfSense static). Host→guest via `hostfwd` (host `2222`→22 SSH, `8080`→80 WebUI (HTTP), `5353`→udp/tcp 53 DNS); guest→runner mock-feed server via the SLIRP alias `10.0.2.2:<port>`. Guest egress (SLIRP NAT) is used **only at image-build time** (package install, `pfSense-upgrade`); the **test job blocks egress** (§4 #4) — block the runner's outbound at the firewall **after** the GHCR pull (SLIRP-internal `10.0.2.2` feeds + `hostfwd` survive on loopback; real internet and the SLIRP DNS upstream `10.0.2.3` go dark), or use SLIRP `restrict=on` + a `guestfwd` for the feed port; sequence is **pull → block → boot/deploy/run**. Through `hostfwd` the guest sees every probe sourced from `10.0.2.2`. The NIC is a **single VirtIO device with its MAC pinned to the source VM's MAC**: pfSense keys interface assignment to the `vtnet0` device and is sensitive to NIC type/MAC/count — change any and it drops to a console interface-reassignment prompt, breaking the unattended boot. The pinned MAC is the source VM's (`BC:24:11:37:9C:AC`), hardcoded in the boot helper — a MAC is not sensitive, so no secret/variable is needed. |
| **Image immutability / concurrency** | The published base qcow2 is **read-only and never booted directly** — each run boots an ephemeral copy-on-write overlay (`-drive …,snapshot=on`, discarded on qemu exit; or an explicit `qemu-img create -b base -F qcow2` overlay kept on failure for post-mortem), so a run never mutates the base. **Concurrent instances are safe**: every user-net VM has its own isolated SLIRP NAT (no shared L2), so the **same hardcoded MAC never collides** — the only contention is `hostfwd` host ports, fixed across GH jobs (each job = its own runner) and allocated per-instance only if several VMs share one runner. Pull the base by **digest** (`…@sha256:…`), not a mutable tag. |
| **Image build (split: base OS vs provisioning)** | Two layers, **one output contract** (a versioned qcow2 in GHCR), so the fragile part is isolated. **(a) Base OS — canonical mode is "seed once, upgrade in place":** a maintainer does **one clean manual install**, archived as the seed; each subsequent CE release is produced by **booting the prior image and running pfSense's own upgrader** (`pfSense-upgrade`, the CLI behind System → Update) → re-snapshot → publish. **Upgrade-in-place for *all* bumps (incl. major)** — the seed is minimal/plain so the chain accumulates little cruft, and a **post-upgrade sanity gate** (the smoke suite itself) is the publish guard: publish only on pass, fail closed. A fresh manual re-seed is a **fallback** only when the gate fails. *(The image refresh + sanity gate are automated in **ADR-09**.)* *(Packer-from-ISO via installerconfig/keystrokes stays an optional, spike-gated automation of the clean install — not required.)* **(b) Provisioning — automated with Packer (`qemu` builder booting the base via `disk_image = true`) or a script WHERE FEASIBLE, else hand-baked by the maintainer per a documented runbook** (and if Packer can't drive the build at all, a **ready-made qcow2 is provided wholesale** — §7): bakes in a **test SSH key** (root SSH), a known base `config.xml` **that opens WAN for the harness** (single-NIC WAN is default-deny with no anti-lockout, so bake **WAN pass rules host→22/80/53** — WebUI is HTTP on `:80` here — **and an Unbound `access-control: 10.0.2.0/24 allow`**, since Unbound refuses WAN-side recursion by default (returns `REFUSED`; the stock ACL is LAN-only). On a **single-interface install pfSense does not auto-add the WAN Block-private/Block-bogons rules**, so disable them only if present — the `10.0.2.2` source is RFC1918. SSH is unreachable until the pass rule exists, so all of this must be **baked**, not added later over SSH), serial console, the DNS Resolver in **forwarding mode → Cloudflare `1.1.1.1`/`1.0.0.1`, DNSSEC off** (mode is immaterial to the test; a fixed external upstream is fail-closed under the egress block and survives a :53-hijacking build LAN), and Unbound `local-data` for the hermetic control domains. Parameterised by `PFSENSE_CE_VERSION`. **pfBlockerNG is NOT baked** — the image is clean pfSense CE + config; the harness installs the branch under test from `src/` after every boot via `scripts/install-from-repo.sh` (the port's `php -f /etc/rc.packages … POST-INSTALL` hook), which is **all local → needs no internet** and runs even after the egress block. So the image is pfBlockerNG-version-agnostic and reusable across branches. The build method lives **behind the published-qcow2 seam** (build-method-agnostic, like the install method): Packer keeps it scripted where it can, but a fully hand-made image is equally valid — reproducibility then rests on **an archived qcow2 + a runbook of exactly what is baked**, **provided the seed + each snapshot are archived** (see versioning). |
| **Image store / versioning** | Built `qcow2` pushed to **GHCR as an OCI artifact** via `oras`, tagged by `PFSENSE_CE_VERSION`, **CE only, no Plus**. ADR-04 builds a **version-parameterised** harness and validates **one** CE version (the thin slice, §6); the **per-minor matrix, smoke fan-out, and automated image-refresh are ADR-09** (which reads the supported-version matrix and supplies the tags). The image tag/digest is a **parameter** everywhere (boot helper, fixture, workflow) so ADR-09 fans out without reworking ADR-04. The hand-rolled image scripts (`image-publish.sh` from a Proxmox seed, `image-upgrade.sh` to bump a tag) produce the per-version tags — no Packer. **Retain the archived clean-install seed AND every published version snapshot** (don't overwrite) — this is what makes the upgrade-in-place chain recoverable (rebuild from the last good clean base) and auditable (how each tag was produced), restoring the reproducibility a long upgrade chain would otherwise erode. The GHCR package is **private to the org** (see §3 redistribution risk). |
| **Deploy** | Reuse **`scripts/deploy.sh <ssh-target>`** unchanged (rsync `src/` + restart unbound/nginx). The harness only provides the SSH target (port-forwarded, `127.0.0.1:2222`) and the key: the runner authenticates with the **private key from secret `SMOKE_SSH_PRIV_KEY`** (written to a mode-600 temp file, `ssh -i`), matching the **public key (`SMOKE_SSH_PUB_KEY`) baked into root's `authorized_keys`** at image-build time. The pfSense `admin` password is in **`SMOKE_ADMIN_PASSWORD`**, baked into `config.xml` to match (bcrypt hash); since SSH uses the key and the WebUI is reachability-only, this password is **not exercised by the current scope** — it's available for an authenticated WebUI/console check if the scope grows. |
| **Config injection** | Per matrix case, set the pfBlockerNG config over SSH via a **`php -r` snippet** using pfSense's config API (`parse_config` / `config_set_path` / `write_config`) — set the feed URL(s), DNSBL response mode, whitelist, wildcard/exact, **and the case's control-domain `local-data`/`local-zone`** (Unbound Host Overrides / Custom Options) so passthrough cases resolve hermetically. Same channel → control domains live with the fixtures, not the image. |
| **Reload / update** | `ssh <vm> /usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php <verb>` — `updatednsbl` / `updateip` for targeted (fast) per-case reloads, `update` for full; `clearip` / `cleardnsbl` to reset between cases. (Fact 2.) |
| **Mock feeds** | A small **stdlib `http.server`** on the runner serving fixture IP + DNSBL lists; the guest fetches them at `http://10.0.2.2:<port>/...` (QEMU user-net host alias) over **plain `http` with an IP-literal URL** — no TLS cert to trust, no DNS lookup on the feed host, fully self-contained. No external network needed for feeds. pfBlockerNG caches downloaded lists, so an edited fixture only takes effect after a **forced `update`** (see "Reset between cases"). |
| **DNS probe** | `dig`/`dnspython` from the runner against the guest's **real Unbound** (port 53 via QEMU `hostfwd` udp/tcp, e.g. host `5353`) — the resolver is the SUT, not a mock. The full path is CI → pfSense → Unbound → `pfb_unbound.py` → Unbound → pfSense → CI. Assert **rcode + record** vs the expected block shape (fact 4). |
| **IP probe** | `ssh <vm> /sbin/pfctl -t <alias> -T show` (table members) and `pfctl -sr` (rules) vs the IPs the mock feed served. |
| **Hermetic DNS** | **No separate DNS-server mock is needed.** `pfb_unbound.py` synthesises blocked answers locally (never recurses); non-blocked "control"/whitelist domains resolve from **Unbound `local-data`/`local-zone`** — which *is* the upstream mock. These control records are **not baked into the image**: the harness **injects them per case over SSH** via the pfSense config API (Unbound Host Overrides / Custom Options), the same channel as the per-case pfBlockerNG config, so the control set lives with the test fixtures and a new passthrough case needs **no image rebuild**. Inject them **before** the feed `update` so they persist into the regenerated `unbound.conf` (records added live via `unbound-control` would be wiped by a pfBlockerNG reload). **Unbound mode is immaterial** to the smoke cases — the plugin and `local-data` short-circuit every case before any upstream is consulted — so hermeticity rests on **blocked egress + mock feeds + `local-data`**, not the resolver/forwarder choice. The image ships **forwarding mode → Cloudflare `1.1.1.1`/`1.0.0.1`, DNSSEC off**: a fixed *external* upstream is fail-closed under the egress block (a non-`local-data` name SERVFAILs), and forwarding (RD=1) also survives a build-network that hijacks plaintext :53. Do **not** forward to the DHCP/SLIRP `10.0.2.3`, which can survive the block. (Phase 1's single baked `local-data` name is a spike convenience only.) |
| **Test driver / isolation** | **pytest** in `tests/smoke/`, every VM test under marker **`smoke`**, **deselected from the default `python -m pytest`** (config in `pyproject.toml`). Only the smoke workflow runs `pytest -m smoke` (it needs KVM + the GHCR image). Deps (`dnspython`, `paramiko`, `oras`) live in `tests/smoke/requirements.txt`. |

### Semantics that MUST be preserved (the contract — pin before relying on it)

This ADR adds tooling, not behaviour; the "contract" is **the probe→expectation invariants the harness encodes**, each pinned by a passing case in the thin slice (Phase 5) before the matrix is trusted/expanded:

- **The harness must distinguish a true block from a true pass.** A blocked domain returns the configured block shape (NXDOMAIN / null-IP / VIP per fact 4); a whitelisted or unlisted control domain returns its `local-data` answer — and a *failure to inject/reload* must make the assertion **fail**, not silently pass (guard: a deliberately-wrong expectation must go red).
- **IP path:** an IP present in the served feed appears in the named pf alias table (`pfctl -T show`); an IP not in the feed does not. A rule referencing the alias exists (`pfctl -sr`).
- **DNSBL-IP is dual-stack:** with the DNSBL-IP firewall feature enabled and a feed carrying both families, the IPs embedded in the DNSBL list must populate **two distinct** pf alias tables — `pfB_DNSBLIP_v4` *and* `pfB_DNSBLIP_v6` — never collide on one. The hardcoded `DNSBLIP` base name is suffixed per address family downstream (`pfB_{aliasname}{vtype}`, `inc:8680`/`inc:9260`), so `pfctl -sTables | grep pfB_DNSBLIP` must list **both**, each table holding only its own family's addresses. A run that produced only one table (or merged the families) must go red.
- **Determinism without internet:** every assertion resolves from mock feeds + `local-data`; a run with the runner's egress blocked must still pass (no hidden dependency on real upstreams/feeds).
- **Reset between cases:** `clearip`/`cleardnsbl` + a **forced `update`** (not just a reload — pfBlockerNG caches feeds, so an edited mock fixture is re-fetched only on a force) returns the VM to a known state so cases don't leak into each other (or each case gets a fresh boot/snapshot — Phase 3 decides).

### Explicitly kept / out of scope

- **Web-UI browsing / Selenium** — out (per the request; UI is exercised only via the PHP CLI + SSH).
- **pfSense Plus** — out (licensing). The **per-minor matrix, smoke fan-out, and automated image-refresh are ADR-09** (out of scope here); ADR-04 validates **one** CE version on a **version-parameterised** harness that ADR-09 fans out. An **exhaustive per-patch matrix** stays out.
- **Testing the in-place upgrade path** (pfSense OS, or pfBlockerNG itself) — **future work**; CI tests **clean boots** of each version image, not the upgrade transition. `scripts/image-upgrade.sh` is build tooling that *produces* per-version tags, not a tested path.
- **GeoIP/MaxMind/ASN feeds** (`dc`/`bu`/`asn` verbs) — out (license-encumbered downloads); the mock feeds cover plain IP + DNSBL lists only.
- **Stable channel** — the harness deploys `devel` only initially (`deploy.sh` default).
- **Broad DNSBL matrix** (SafeSearch, regex, HSTS, TLD, full noAAAA/AAAA) — deferred; Phase 5 lands a **thin vertical slice** and §7 documents how to extend it.
- **`src/` code** — unchanged. If a smoke test reveals a bug, the fix is a **separate** change with its own unit test; this ADR only builds the harness.

---

## 3. Consequences

**Positive**

- Closes the "no live Unbound/pfSense in CI" gap that every prior ADR deferred to a human — the manual smoke checklist (ADR-01 §7, ADR-03 §7) becomes (partly) automated and regression-guarded.
- Exercises the **real** integrated system: Unbound + `pfb_unbound.py`, the PHP reload/cron path, `pfctl` tables/rules, and the PHP↔Python sqlite coexistence (ADR-03) — none of which the unit oracle can reach.
- A parametrised pytest matrix makes "test all combinations of DNSBL settings" a tractable, growable target instead of a manual ritual.
- The "seed once, upgrade in place" image strategy tests an **upgraded** box — what most production pfSense installs actually are — so it exercises upgrade-path effects (config migration, package re-add) a pristine install never would.

**Negative / risks**

- **Premise risk (highest):** unattended pfSense CE install may not be cleanly automatable/reproducible; GH-hosted KVM may be too slow or flaky for a FreeBSD guest. **Mitigated by the Phase 1 spike + explicit kill-threshold (§7) before any Packer work.**
- **Redistribution risk:** a built pfSense image carries Netgate binaries/trademarks; publishing it could violate Netgate's terms. **Mitigated:** GHCR package **private to the org**; ADR requires reviewing Netgate's distribution terms before any public image, and building from CE installer media we are licensed to use.
- **Maintenance cost:** the image must be rebuilt when CE bumps (tied into the CLAUDE.md "minimum supported CE version changes" checklist); the matrix and fixtures need upkeep as pfBlockerNG evolves.
- **CI cost/time:** booting a VM per PR is far heavier than the unit suite — hence build/test split, image caching, targeted (`updatednsbl`) reloads, and a thin slice. If per-PR time is unacceptable, the smoke workflow can be gated (label / `workflow_dispatch` / nightly) rather than every-PR — decided in Phase 6.
- **Flake surface:** networking (`hostfwd`), boot races, and reload timing are classic CI flake sources; the harness must wait on readiness signals, not sleeps, and retry the SSH/DNS round-trip with bounded backoff.
- **Image drift (upgrade-in-place):** an image walked across many CE releases could accumulate cruft. Mitigated by a **minimal/plain seed** (little to drift), a **post-upgrade sanity gate** that fails closed (a bad upgrade is never published — **ADR-09** automates this), and **archiving the seed + every snapshot** (rebuild from the last clean base; audit trail). A fresh manual re-seed is a fallback only when the gate fails.

---

## 4. Requirements (acceptance)

1. **Boots & controls in CI:** the GH-hosted smoke workflow pulls the GHCR image, boots the pfSense VM, SSHes in, and runs `pfctl` + `dig` — green, within the time/stability budget (§7).
2. **Deploys the branch-under-test:** `scripts/deploy.sh` lands the working-tree `src/` onto the VM and the reload (`pfblockerng.php update`) succeeds.
3. **Asserts both paths (thin slice):** at least one IP alias-table+rule case and the DNSBL cases (exact→NXDOMAIN/null, one wildcard, one whitelist passthrough) pass — and a deliberately-wrong expectation goes red (no false-green).
4. **Hermetic:** the whole matrix passes with the runner's external egress blocked (mock feeds + `local-data` only).
5. **Default suite unaffected:** `python -m pytest` (no `-m smoke`) runs exactly as today — no new deps, no VM, no failures.

---

## 5. Constraints (from `CLAUDE.md`)

- **Shipped code is untouched.** The stdlib-only rule applies to `pfb_unbound.py` (runs in Unbound); it does **not** bind the dev harness. `tests/smoke/` may use third-party deps (`dnspython`, `paramiko`, `oras`) pinned in `tests/smoke/requirements.txt` — precedent: `benchmarks/requirements.txt`. None of this ships in the release archive (which contains only `src/`).
- **Python harness:** 3.11+; 4-space indent; type hints on new fns; no bare `except`. Run `python -m pytest` after any `tests/` change; it must stay green **and** the `smoke` marker must be deselected by default (`pyproject.toml` `addopts`/`markers`).
- **Shell:** any new shell (boot helper, install hooks) is **POSIX `sh`**, quoted expansions, absolute binary paths; ShellCheck clean (`.shellcheckrc` rules).
- **Packer/HCL & YAML:** match `.editorconfig`; keep workflows lint-clean.
- `ruff check .` / `ruff format .` clean before each commit; keep `.flake8` in sync if Ruff config changes.
- Commit style `<scope>: <imperative summary>` (e.g. `ci:`, `dev:`, `test:`); **work inline on `adr/04`, one commit per phase, push directly** (PR only if the push is rejected). PR bodies via `--body-file`.
- **Docs:** updating the supported CE version (and thus rebuilding the image) is added to the CLAUDE.md / README version-bump checklist (Phase 6).

---

## 6. Action plan

Each phase is one commit, leaves `python -m pytest` (default, no `-m smoke`) green, and pushes to `adr/04`. The **de-risking spike is front-loaded** (Phase 1) so the expensive Packer/matrix work is never built on an unproven premise.

### Phase 1 — Spike & kill-gate: prove KVM boot + control round-trip

Prompt: `01_Spike_Boot_Roundtrip.txt`

- On `ubuntu-latest`: confirm `/dev/kvm`; boot a **hand-built** pfSense+pfBlockerNG `qcow2` (maintainer-provided, stored privately for the spike) headless via `qemu-system-x86_64` with the `hostfwd` map (SSH + DNS).
- SSH in (baked key) → `pfctl -sr`; `dig @<vm>` a baked `local-data` name; run `pfblockerng.php update`.
- **Measure** boot-to-ready time and pass/fail over N≥5 runs; **record vs the kill-threshold (§7)**. Lands a minimal `.github/workflows/smoke-spike.yml` + boot helper + the recorded numbers in `RESULTS/01_Results.txt`.
- **Gate:** miss the threshold → STOP; record the pivot (self-hosted) before Phase 2.

### Phase 2 — Image → publish to GHCR (Packer where feasible, else maintainer-provided)

Prompt: `02_Packer_Image_GHCR.txt`

- Image build sits behind the published-qcow2 seam: where Packer is feasible, a `packer/` QEMU template (provisioning via `disk_image = true`; ISO install optional) bakes the test SSH key (root SSH), pfBlockerNG-devel, base `config.xml` (WAN open), Unbound `local-data`; **else the maintainer provides a ready-made qcow2 wholesale**, built by hand per a documented runbook (§7).
- `.github/workflows/build-image.yml` (`workflow_dispatch` + scheduled): build *or* accept a maintainer-supplied qcow2, then `oras push` to **private GHCR** tagged by CE version.
- Deliverables: the publish pipeline + a runbook of exactly what is baked + verification that the published image boots and passes the Phase 1 round-trip — not necessarily a working Packer template.

### Phase 3 — pytest smoke scaffolding: VM fixture + marker + mock feeds

Prompt: `03_Pytest_Smoke_Scaffolding.txt`

- `tests/smoke/` with `requirements.txt` (`dnspython`, `paramiko`, `oras`); `pyproject.toml`: register marker `smoke`, **deselect by default**.
- Session-scoped fixture: `oras pull` the GHCR image → boot VM → wait on readiness (SSH+DNS reachable, not a sleep) → yield connection info → teardown. Decide per-case isolation (fresh boot vs snapshot-revert vs `clear*`+reload).
- Stdlib mock HTTP feed server fixture (serves fixture IP/DNSBL lists at `10.0.2.2:<port>`).
- A trivial `pytest -m smoke` test (boot + SSH `pfctl -sr` + `dig` a `local-data` name) proves the scaffolding; the **default** `python -m pytest` still ignores everything `smoke`.

### Phase 4 — Config-injection + deploy + reload helpers

Prompt: `04_Config_Inject_Deploy_Reload.txt`

- Helper to `scripts/deploy.sh` the working tree onto the VM (SSH target from the fixture).
- `php -r` config-injection helper: set feed URL(s), DNSBL response mode, whitelist, wildcard/exact for a case via the pfSense config API; reload via `pfblockerng.php updatednsbl`/`updateip`/`update`; reset via `clearip`/`cleardnsbl`.
- DNS-probe and pfctl-probe helpers (rcode+record; table members + rule presence). Pin them with a self-test: a wrong expectation must fail.

### Phase 5 — Thin vertical-slice matrix

Prompt: `05_Thin_Slice_Matrix.txt`

- IP: feed N IPs → assert alias table membership + rule presence; assert a non-fed IP is absent.
- IP (DNSBL-embedded, dual-stack): a DNSBL feed carrying both IPv4 and IPv6 entries → assert **both** `pfB_DNSBLIP_v4` and `pfB_DNSBLIP_v6` tables exist, are partitioned by family (no collision from the shared `DNSBLIP` base name), and that the inet/inet6 rules reference the matching table.
- DNSBL (parametrised): exact block → NXDOMAIN **and** null-IP modes; one wildcard (`*.example.com` blocks `a.b.example.com`, self); one whitelist passthrough (resolves via `local-data`).
- Hermetic check: passes with egress blocked. False-green guard: a deliberately-wrong case is xfail/asserted-red.

### Phase 6 — Per-PR workflow wiring + docs + DoD

Prompt: `06_Workflow_Docs_DoD.txt`

- `.github/workflows/smoke.yml`: pull GHCR image → `pytest -m smoke`; decide the trigger (every-PR vs label/`workflow_dispatch`/nightly) on the Phase 1 timing.
- README: how to run smoke locally, how to rebuild the image on a CE bump, how to **extend the matrix**; add the image-rebuild step to the CE-version-bump checklist (CLAUDE.md/README).
- Fold the spike workflow into the final one; finalise §7 manual checklist + reject criteria.

---

## 7. Definition of done

- `python -m pytest` (default) green and **unchanged** — no new deps pulled, `smoke` deselected.
- `pytest -m smoke` green in the smoke workflow on GH-hosted KVM: VM boots from the GHCR image, branch deploys via `scripts/deploy.sh`, the thin-slice IP + DNSBL cases pass, the run is **hermetic** (egress blocked), and a deliberately-wrong expectation goes **red**.
- The Packer image builds reproducibly and is published (private GHCR) tagged by CE version; rebuild-on-bump documented in the CE-version checklist.
- `ruff` clean; ShellCheck clean on any new `sh`; workflows lint-clean.
- README documents run/rebuild/extend.
- Status → **Accepted** only after the smoke workflow is green on `adr/04`'s CI **and** the maintainer confirms the manual items below on a live box.

### DoD outcome (Phase 6 — code-complete)

The harness is built and the workflow is wired. Status of each DoD item:

- **Default suite unaffected** — **MET (verified locally).** `python -m pytest`
  collects/passes exactly **169**, byte-for-byte unchanged; `smoke` is
  `--ignore`'d, no new deps pulled.
- **`pytest -m smoke` green, hermetic, false-green guarded** — **WIRED, pending
  CI.** `smoke.yml` runs `pytest -m smoke` over the build-pkg → artifact →
  `pkg add` → boot-fixture flow with the egress block (pull → block → run) and
  the strict-xfail false-green guard (`test_false_green_guard_vm`). The actual
  green/red + wall-time come from the orchestrator's `gh workflow run smoke.yml`
  dispatch — **NOT** run or measured in this environment (no `/dev/kvm`, image,
  or secrets); not fabricated.
- **Image builds reproducibly + published private GHCR, rebuild-on-bump
  documented** — **MET** (Phase 2: `build-image.yml` + `IMAGE_RUNBOOK.md`); the
  CE-bump checklist now carries the image-rebuild step (CLAUDE.md + README).
- **`ruff` / ShellCheck / workflow lint clean** — **MET (verified locally).**
- **README documents run/rebuild/extend** — **MET** ("Smoke tests" section).
- **Status → Accepted** — **NOT yet**: gated on the CI dispatch above **and** the
  maintainer's live-box checklist below (deliberately left to the maintainer).

The Phase-1 spike measured GH-hosted KVM as viable (GO); no reject criterion
fired. Because the per-run wall-time is still unmeasured, the trigger is **gated**
(`workflow_dispatch` + `workflow_call`, nightly `schedule` commented) rather than
every-PR — move it to `pull_request` once a dispatched run confirms it fits the
~20 min/job budget.

### Reject criteria (what kills this ADR — decide cheaply, in Phase 1, before Packer)

- **Packer can't build the image (install and/or provisioning):** this is **NOT a reject** — it is the accepted fallback. If Packer can't headlessly install CE, the maintainer hand-installs the base once per CE version; if Packer can't drive provisioning either, the maintainer **provides a ready-made qcow2 wholesale** (built by hand per a documented runbook). Either way `oras push` + the verification round-trip proceed unchanged — the published qcow2 is the **build-method-agnostic seam** (§2 "Image build"). It becomes a reject **only** if *no bootable, round-trip-passing qcow2 can be produced at all* — which the Phase-1 spike (which boots a hand-built image) already disproves before any Packer work.
- **GH-hosted KVM unfit:** if boot-to-ready + thin-slice run cannot complete reliably within the budget — proposed kill-threshold **≤ ~20 min per job and ≥ 4/5 clean runs** in Phase 1 (tune with the maintainer) — → do **not** ship flaky every-PR CI; pivot to self-hosted or a gated (nightly/label) trigger, recorded in the ADR.
- **Redistribution blocked:** if Netgate's terms forbid storing the built image even in private GHCR → reject the GHCR-caching approach; fall back to build-in-job or maintainer-hosted storage.

### Manual smoke (owner: maintainer) — required before Accept

The automated matrix is a thin slice; before flipping to Accepted, the maintainer confirms on a live box that the harness's expectations match real behaviour for at least:

- [ ] An exact DNSBL block returns the configured response (NXDOMAIN / null-IP / VIP) and is logged.
- [ ] A wildcard `zone` block catches a deep subdomain and the parent.
- [ ] A whitelisted domain resolves normally.
- [ ] An IP feed populates the expected pf alias table and a rule references it.
- [ ] The DNSBL-IP feature, fed a list with both IPv4 and IPv6 addresses, creates **both** `pfB_DNSBLIP_v4` and `pfB_DNSBLIP_v6` pf tables (distinct, each holding only its own family) and the inet/inet6 rules reference the matching table — v4 and v6 do not overwrite each other.
- [ ] The smoke workflow's pass/fail matches these observations (no false-green / false-red).
