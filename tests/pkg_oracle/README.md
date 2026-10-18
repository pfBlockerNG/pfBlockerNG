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
only), `is_process_running`, `daemon(8)`, `lockf(1)` (over `flock`) and `read_xml_tag.sh` (`shims/`). The shared PHPUnit bootstrap loads `pfblockerng.inc`
before core does, so core's load-time rewrite of `pfb_filter.sh` / `pfb_dnsbl.sh` is not reproduced (the PHPUnit worker models it);
the recovery writes all three rc scripts itself.

pfSense CE 2.8.x cannot be pinned (the public repo has no `RELENG_2_8_*` ref; Plus is closed). master and RELENG_2_7_2 agree on
the logic that matters; the live 2.8.1 case is `test_an_aborted_removal_*` in `tests/smoke/test_smoke_dns_proxy.py`.

```sh
sh tests/pkg_oracle/build.sh  OUT                    # fetch + sha256-verify core files, build pkg 2.1.0, build image pfb-pkg-oracle:2
sh tests/pkg_oracle/run.sh    OUT REPO recovered master   # the fixed code against core master (9363ac5b): exit 0 iff it held
sh tests/pkg_oracle/run.sh    OUT REPO recovered r272     # ... against RELENG_2_7_2 (ec956d34)
sh tests/pkg_oracle/run.sh    OUT BASE broken   master    # the base commit: exit 0 iff the defect reproduces
```

Scenario: pfB-DNS serving in module mode; `pkg delete` while another save holds the config lock for 15 s (the hook's Resolver
restore gives up); then the aborted removal's leftovers are probed; then the retry with the lock free. Container only: nothing is
installed on or changed on the host.
