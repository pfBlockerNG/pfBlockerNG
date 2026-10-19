# Real-pkg removal oracle (issue #3515)

Dev-only; not collected by pytest or PHPUnit and not a CI gate (it needs Docker and the network once, to build).

What it answers: when a package removal **aborts** (the hook exits 3) after pfSense has already stopped and deregistered the
package's services, does pfB-DNS keep serving, and can the operator then remove the package? Everything between pkg's
DEINSTALL step and the shipped hook is real:

| Layer | What runs |
| --- | --- |
| package manager | FreeBSD `pkg` 2.1.0 built from source (`PINS`), `pkg delete`, real `+DEINSTALL` / `+POST-DEINSTALL` scripts |
| pfSense core | `delete_package_xml()`, `start_service()`, `stop_service()`, `write_rcfile()`, `isvalidpid()`, `parse_xml_config_pkg()` extracted **by name from the real files** at the pinned commits (`core.php`) |
| package | the repo's `pfblockerng.inc` and the shipped `pfblockerng.xml` hook text, evaluated by core's `eval_once()` |
| DNS | real Unbound, the real DNS proxy hosting the real `pfb_unbound.py` (module mode: a listed name is answered with the DNSBL VIP) |
| locks / config | real `flock`-based `try_lock()`; a file-backed config.xml written whole by `write_config()` |

Stand-ins (listed in `core.php`): `update_status`, `logger`, `gettext`, `init_config_arr` and `platform_booting` (RELENG_2_7_2
only), `is_process_running`, `daemon(8)`, `lockf(1)` (over `flock`), `uname -p`, `read_xml_tag.sh` and `pgrep -qnF` (`shims/`:
procps-ng 4.0.4's `pgrep` takes `-F` but rejects `-q` (exit 2), and the r272 core's `isvalidpid()` makes that call, so every pid read as
dead without it), and the pfb-dns
payload of the Go gateway (below). The shared PHPUnit bootstrap loads `pfblockerng.inc`
before core does, so core's load-time rewrite of `pfb_filter.sh` / `pfb_dnsbl.sh` is not reproduced (the PHPUnit worker models it);
the recovery writes all three rc scripts itself.

## The Go gateway on this Linux oracle: what is and is not proven

Since #3515 the proxy the package starts is the Go gateway: `pfb_dns.sh` execs `dns_proxy/bin/<target>/pfb-dns`, with `<target>`
chosen by `uname -p`, and that binary runs the Python decision service. The oracle reproduces that path with container-local stand-ins:

| Piece | What the oracle does |
| --- | --- |
| `pfb-dns` | `run.sh` builds it from the product's own `go/pfb_dns_gateway` (the same revision as the product tree) with the pinned Go toolchain (`GO_VERSION` in `scripts/go_toolchain.py`), `CGO_ENABLED=0`, `GOOS=linux GOARCH=amd64` and the hermetic flags of `scripts/build-pfb-dns.py`. It is placed at `bin/freebsd-amd64/pfb-dns`, the path `pfb_dns.sh` selects for `amd64`. `results/pfb-dns.txt` records the Go version, size, sha256 and ELF header. |
| `uname -p` | `shims/uname` answers `amd64` for that one call (the Debian image says `unknown`, which `pfb_dns.sh` rejects); every other call is the real `uname`. |
| `/usr/bin/lockf` | `shims/lockf` (over `flock`), as before: the proxy start runs under `lockf -k -t 10`. |
| `POSIX_EPERM` | Not a stand-in: `core.php` takes the `define` statement from the pinned `util.inc` (`ORACLE_CORE_CONSTANTS`) and evaluates it as written. |

What this proves: the package-removal lifecycle through the real Go gateway's code, the real decision service, real Unbound and the real
package manager. What it does **not** prove: that the FreeBSD `pfb-dns` payloads (built by `build-pkg-portable.py`) behave the same on
an appliance. The staged binary is a Linux ELF under a FreeBSD path name, so this is not FreeBSD-native binary evidence; the appliance
proof is the live smoke (`test_an_aborted_removal_*`).

`run.sh` runs against a staged copy of the working tree (`OUT/stage`: no `.git`, `.codegraph` or `graphify-out`); REPO is only read.
`PFB_ORACLE_IMAGE` (default `pfb-pkg-oracle:2`) names the image that `build.sh` builds and `run.sh` runs, so a scratch run does not
replace a shared tag.

pfSense CE 2.8.x cannot be pinned (the public repo has no `RELENG_2_8_*` ref; Plus is closed). master and RELENG_2_7_2 agree on
the logic that matters; the live 2.8.1 case is `test_an_aborted_removal_*` in `tests/smoke/test_smoke_dns_proxy.py`.

```sh
sh tests/pkg_oracle/build.sh  OUT                    # fetch + sha256-verify core files, build pkg 2.1.0, build image $PFB_ORACLE_IMAGE
sh tests/pkg_oracle/run.sh    OUT REPO recovered master   # the fixed code against core master (9363ac5b): exit 0 iff it held
sh tests/pkg_oracle/run.sh    OUT REPO recovered r272     # ... against RELENG_2_7_2 (ec956d34)
sh tests/pkg_oracle/run.sh    OUT BASE broken   master    # the base commit: exit 0 iff the defect reproduces (on the fixed code: FAIL at once)
```

Scenario: pfB-DNS serving in module mode; `pkg delete` while another save holds the config lock until the removal's Resolver restore
gives up (the lock double leaves `pfb_dns_config.refused`, and the holder lets go on it); then the aborted removal's leftovers are
probed; then the retry with the lock free. Every wait observes an event (Unbound's start line, the holder's ready marker, the proxy's
first answer, the proxy's port refusing once it is stopped) and gives up at a 60 s monotonic deadline (`AWAIT_CAP`, read from
/proc/uptime, checked between probes; a silent port's 2 s probe timeout can add to it). Expiry is `STUCK/ENVIRONMENT`. Each `pkg delete`
runs under a cap, 180 s by default; `ORACLE_DELETE_CAP=S` can only shorten it (1 to 180 s), and expiry kills the process group and is
also `STUCK/ENVIRONMENT`. After the first removal probe.php's state is read once: the three services registered and the proxy running,
or the run FAILs before any readiness wait. Broken mode reads the probe once after the removal: an answer FAILs at once ("defect did
not reproduce"), and only silence waits for the refusal that shows the stop. In this scenario the proxy's stop is synchronous (the broken
branch in scenario.sh cites the source lines), so a live answer after `pkg delete` returns is not a stop still in flight; the recovery's
own restart waits for READY first. The pgrep stand-in is self-checked before the removal; a failed self-check is a harness fault. The
EXIT trap stops the proxy the scenario started (its recorded pids, supervisor first) and the scenario's Unbound, so a STUCK before the
removal leaves no proxy behind.

Exit status: 0 PASS; 1 product FAIL (a check failed, or in broken mode the defect did not reproduce); 8 STUCK/ENVIRONMENT (a deadline
expired, so the run decided nothing about the product); 9 harness fault: run.sh's own staging (the Go toolchain is not the pinned one,
the gateway build or its ELF check failed, or any other failure before the container starts: run.sh's EXIT trap turns it into 9), or the
scenario's (the pgrep stand-in's self-check, the package build). 2 is usage. 125, 126 and 127 are docker's own failures (daemon, container
command cannot run, not found): harness errors, returned unchanged. Only exit 1 is a verdict on the product.
Container only: nothing is installed on or changed on the host.
