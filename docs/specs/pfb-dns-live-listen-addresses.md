# pfB-DNS: live listen-address changes

## Goal

The running pfB-DNS gateway (`go/pfb_dns_gateway`) gains and loses listen addresses without a restart
([#3599](https://github.com/pfBlockerNG/pfBlockerNG/issues/3599)). When an address on one interface and IP version
appears or disappears, only that address's listeners change; the gateway, its decider and every other listener keep
serving. This replaces the whole-pair restart that [#3598](https://github.com/pfBlockerNG/pfBlockerNG/issues/3598)
makes once an address the gateway's start could not bind becomes bindable.

## Fixed constraints

- One gateway process, as today. The decider stays the gateway's child on fd 3.
- The gateway binds only before it drops root (`start()` in `go/pfb_dns_gateway/main.go`). A listener added later is
  bound by root PHP and handed over on the control socket (`/var/run/pfb_dns/ctl.sock`, `ctl.go`) with `SCM_RIGHTS`.
  The control socket stays uid-0-only, judged by the kernel's peer credential before a byte is read.
- The gateway log stays the record of what is served: `pfb_dns_proxy_listeners()`, the startup check
  (`pfb_dns_proxy_startup_check()`) and the status panel (`pfb_dns_status()`) read it. An added listener logs
  `listening <kind> <host:port>`, the same line a start logs.

> **Amendment 2026-10-31 (#3625).** The gateway is asked, not read: `pfb_dns_proxy_listener_list()` sends `FF FF FF FC` (nothing after it) on the control socket and reads `listening <kind> <host:port>` and `refused <kind> <host:port> <reason>` lines, then `ok`. Unknown (NULL: no socket, no reply within `PFB_DNS_PROXY_CTL_TIMEOUT`, an `error:` line, a malformed reply, or one over 64 KiB): the startup check judges no listener, the status panel shows `configured_unconfirmed`, the sync changes nothing, and the update pass restarts an address-only change. The log lines stay for people reading them.

- Port changes and TLS, DDR or module setting changes keep restarting the whole pair.
- Under a package operation (`pfb_dns_proxy_restart_deferred()`) a live proxy is not restarted.
- The cron tick never calls `pfb_dns_proxy_ensure_running()` (#3598 owner decision); rc-script rewrites stay with the
  update pass.
- No unbounded wait: every control-socket step is bounded by `PFB_DNS_PROXY_CTL_TIMEOUT` and every log wait by
  `PFB_DNS_PROXY_LOG_WAIT` (`docs/misc/external-process-waits.md`).

> **Amendment 2026-10-31 (#3625).** `PFB_DNS_PROXY_LOG_WAIT` is deleted: no caller waits on the log for a listener. The one wait left is the list probe, one control-socket exchange (`FF FF FF FC`, `listening`/`refused` lines, then `ok`) bounded by `PFB_DNS_PROXY_CTL_TIMEOUT`. Unknown (no socket, no reply in time, an `error:` line, a malformed reply, or one over 64 KiB): the startup check judges no listener, the status panel shows `configured_unconfirmed`, the sync changes nothing, and the update pass restarts an address-only change.

- Test-first red→green per `.agents/policy/testing.md`; PHPUnit through the real `.inc`; Go tests through the real
  control socket.

## Decisions

### D1. Address-only rc change (the issue's open fork)

`pfb_dns_proxy_ensure_running()` already reads the rc script before `pfb_dns_proxy_service()` rewrites it. It masks
every listen-address argument out of both texts: every `--listen '<addr>'`, `--dot-listen '<addr>'`,
`--doh-listen '<addr>'` and `--doq-listen '<addr>'` with the space before it (the form `escapeshellarg()` gives them in
`pfb_dns_proxy_service()` and `pfb_dns_proxy_tls_flags()`). Equal remainders with different full texts are an
address-only change. Any other difference (a port, `--tls-pem`, a TLS group turned on or off, `--doh-trusted`, DDR,
`--no-module`/`--observer`/`--reply-log`, the rc shell text) restarts the whole pair as today.

Why: the rc script is the only record of what the running gateway was started with, and the addresses are its only
per-interface part. Turning a TLS group on or off adds or removes its `--<kind>-port`, so a group change never masks
equal. Each TLS group always lists loopback, so a group that is on never has an empty address list.

An address-only change is reconciled live (D4) when the proxy is READY and its log holds a complete start. Otherwise
(not READY, or no complete start to compare with) it restarts the whole pair as today.

> **Amendment 2026-10-31 (#3625).** "Its log holds a complete start" now means the list probe answers. A known reply is the comparison; a NULL is the "no complete start" case, so the pass restarts the whole pair as today. The probe is `FF FF FF FC`, read as `listening`/`refused` lines then `ok`. Unknown (no socket, no reply within `PFB_DNS_PROXY_CTL_TIMEOUT`, an `error:` line, a malformed reply, or one over 64 KiB): the startup check judges no listener, the status panel shows `configured_unconfirmed`, the sync changes nothing, and the update pass restarts an address-only change.

### D2. Control-socket verbs

The existing framing is kept: 4 bytes first. Two new values that no certificate length can take:

| First 4 bytes | Verb |
| --- | --- |
| `FF FF FF FE` | add a listener |
| `FF FF FF FD` | remove a listener |

> **Amendment 2026-10-31 (#3625).** A third value, `FF FF FF FC` with nothing after it, lists what the gateway serves: one
> `listening <kind> <host:port>` line per served listener, one `refused <kind> <host:port> <reason>` line per start-time bind
> failure not served now, then `ok`.

Then a 4-byte big-endian length `L` (1 to 256) and `L` bytes of ASCII `<kind> <host:port>`: `kind` is `udp+tcp`,
`dot`, `doh` or `doq`; `host:port` is Go's `netip.AddrPort` spelling (IPv6 bracketed and compressed; no zone; no
IPv4-mapped IPv6), which `pfb_dns_proxy_host_port()` produces. One reply line, `ok` or `error: <reason>`, as for the
other verbs.

An add carries its sockets as `SCM_RIGHTS` in the same `sendmsg()` as the frame: `udp+tcp` exactly two, the UDP socket
then the TCP listening socket; `dot` and `doh` exactly one TCP listening socket; `doq` exactly one UDP socket. The
gateway takes it only when all of these hold; otherwise it replies `error: <reason>` and closes every descriptor it
received:

- the kind is one this gateway serves: `udp+tcp` always; a TLS kind only when its `--<kind>-listen` was given at start;
- the port is the kind's configured port (`--port`, `--dot-port`, `--doh-port`, `--doq-port`);
- that kind is not served on that host:port already;
- the descriptor count is the kind's, and the kernel truncated nothing (`MSG_CTRUNC`);
- each descriptor is a socket of the expected type (`SO_TYPE`), a stream socket is listening (`SO_ACCEPTCONN`), and its
  bound address (`getsockname()`) is the host:port of the frame, family included;
- the gateway is not stopping.

A taken add is served exactly as a start serves its own listener of that kind (DoT, DoH and DoQ with the certificate
store's configs, DoH with the start's `--doh-trusted` prefixes), logs `listening <kind> <host:port>`, and replies `ok`.

With `--ddr`, the DoT, DoH and DoQ listeners that DDR designates follow adds and removes: an added one is designated, a
removed one (bound at start or added) no longer is.

A remove names one served listener (bound at start or added): it is closed (both sockets for `udp+tcp`), logs
`stopped listening <kind> <host:port>`, and replies `ok`; one that is not served is `error: <kind> <host:port> is not
served`. Plain TCP and DoT connections a removed listener already accepted run to their own end; DoH and DoQ
connections end with their listener (the HTTP server and the QUIC transport own them).

Descriptors that arrive with any other frame (decider restart, certificate push, remove) are closed, and the frame is
handled as without them. A peer that is not uid 0 is closed on unread, as today: the kernel disposes of descriptors
still queued. The gateway's shutdown closes every listener it serves, added ones included; a removed listener is not
closed twice.

A gateway older than these verbs reads `FF FF FF FE` as a certificate length and answers
`error: a message of 4294967294 bytes is not between 1 and 65536`.

### D3. Where a start begins in the log

`start()` logs `starting pid <pid>` as its first line. `pfb_dns_proxy_listeners()` then reads:

- the **latest complete start**: the lines after the last `starting pid` line before the last `ready upstream` line, up
  to that `ready upstream` line. A log with no such marker in that range (a gateway older than this change) is read as
  today, from the second-to-last `ready upstream` line;
- **then, in log order**, the lines after that `ready upstream` line up to the next `starting pid` line (a start in
  progress) or the log's end: `listening <kind> <host:port>` adds to `listening`, `stopped listening <kind> <host:port>`
  removes from it. `refused` keeps the start's reasons.

Why the marker: without it, the lines a running gateway logs after its `ready upstream` line (its live changes) fall
inside the next start's range, and a listener added to the old process would be credited to a new one that never bound
it. The startup check and the status panel read `pfb_dns_proxy_listeners()`, so both see live changes with no change
of their own.

> **Amendment 2026-10-31 (#3625).** This section is superseded. `pfb_dns_proxy_listeners()` and its log folding (the `starting pid` marker, the lines after `ready upstream`) are deleted. The gateway is asked instead, with `FF FF FF FC` (`listening`/`refused` lines, then `ok`), so a listener is served only if the process answering the control socket now lists it. The log lines stay human-readable. Unknown (no socket, no reply within `PFB_DNS_PROXY_CTL_TIMEOUT`, an `error:` line, a malformed reply, or one over 64 KiB): the startup check judges no listener, the status panel shows `configured_unconfirmed`, the sync changes nothing, and the update pass restarts an address-only change.

### D4. The reconcile (`pfb_dns_proxy_listeners_sync()`)

One helper, used by `pfb_dns_proxy_ensure_running()` and by the cron tick, replaces `pfb_dns_proxy_refusal_cleared()`.
It compares `pfb_dns_proxy_command_listeners()` (what the rc script asks for) with `pfb_dns_proxy_listeners()`
`listening` (what is served), per kind:

1. Each served listener the command does not name is removed (D2), then each one the command names and nothing serves
   is added. One frame per listener.
2. An add binds first, as root, in this process: `stream_socket_server()` on `tcp://<host:port>` (listening, backlog
   65535, which the kernel caps at its own maximum as it does the gateway's) and `udp://<host:port>`, TCP before UDP for
   `udp+tcp`. Only a host `inet_pton()` takes is bound (a name would be resolved). PHP closes its copies once the frame
   is sent, whatever the reply.
3. A bind that fails with `can't assign requested address` / `cannot assign requested address` (the address is not
   there yet) is skipped with nothing logged: the next pass tries again. Any other bind failure is logged on
   `pfblockerng.log` and skipped. Neither restarts anything: the gateway could not bind it either.
4. A change the gateway does not take — no reply, an `error:` reply (including an older gateway's), no control socket,
   or no `socket_sendmsg()` in this PHP — stops the reconcile and returns why, and the caller restarts the whole pair
   once, as before this change. The restart's start binds every address the box can bind, so a later pass finds
   nothing missing that it could bind: no restart loop.
5. After a change the gateway took, it waits (bounded by `PFB_DNS_PROXY_LOG_WAIT`, polled every 100 ms) until the log
   shows it, so the startup check that follows judges what is served.

   > **Amendment 2026-10-31 (#3625).** The log wait after a change is deleted. The gateway applies an add or remove before it answers `ok`, so the next probe (the startup check that follows) already sees it. The probe is `FF FF FF FC`, read as `listening`/`refused` lines then `ok`. Unknown (no socket, no reply within `PFB_DNS_PROXY_CTL_TIMEOUT`, an `error:` line, a malformed reply, or one over 64 KiB): the sync changes nothing, the startup check judges no listener, the status panel shows `configured_unconfirmed`, and the update pass restarts an address-only change.

6. Each change taken is logged on `pfblockerng.log`.
7. While a restart is pending (`/var/run/pfb_dns_proxy_restart_pending`), the rc script may differ from the running
   gateway in more than addresses, so nothing is changed live: a missing listener that binds now returns why (the
   whole-pair restart #3598 makes, which leaves the marker to the update pass), and served listeners the command does
   not name are kept.
8. The reconcile reads the record of the gateway that published the ready marker: `pfb_dns_proxy_ready_listeners()` is
   `pfb_dns_proxy_listeners()` for the marker's pid, as the status panel reads it. A log with no complete start of that
   gateway (NULL: no `ready upstream` line, or the latest one ends with another pid) changes nothing; the caller decides
   (D1). After a (re)start the marker is published before the gateway's log lines are relayed, so until they arrive the
   latest complete start is the previous gateway's: acting on it could remove a listener the new gateway never served.

> **Amendment 2026-10-31 (#3625).** The marker's pid selects no log record any more: `pfb_dns_proxy_ready_listeners()` is deleted, and the reconcile asks the gateway that answers the control socket now, with `FF FF FF FC` (`listening`/`refused` lines, then `ok`). A previous gateway's log lines are not read at all. Unknown (no socket, no reply within `PFB_DNS_PROXY_CTL_TIMEOUT`, an `error:` line, a malformed reply, or one over 64 KiB): the reconcile changes nothing and the caller decides (D1); the startup check judges no listener, the status panel shows `configured_unconfirmed`, and the update pass restarts an address-only change.

### D5. Answers to the packet's questions

- **(a) Version skew.** A running gateway that predates the verbs answers `error:` (D2), which D4.4 turns into the
  whole-pair restart. The same holds for any other control-socket failure.
- **(b) Package operation.** No live change under `pfb_dns_proxy_restart_deferred()`: a changed rc script is recorded
  as a pending restart as today, and the tick does not reconcile under it. A live add is no restart, but its failure
  path is one, and the gateway that runs during a package operation is the one most likely to predate the verbs.
- **(c) Folding.** D3.

> **Amendment 2026-10-31 (#3625).** Folding is gone with D3, so no post-ready line can be credited to another start. The probe is `FF FF FF FC` (`listening`/`refused` lines, then `ok`). Unknown (no socket, no reply within `PFB_DNS_PROXY_CTL_TIMEOUT`, an `error:` line, a malformed reply, or one over 64 KiB): the startup check judges no listener, the status panel shows `configured_unconfirmed`, the sync changes nothing, and the update pass restarts an address-only change.

- **(d) The tick.** `pfblockerng_tick()`'s pfB-DNS branch calls `pfb_dns_proxy_listeners_sync()` where it called
  `pfb_dns_proxy_refusal_cleared()`, under the same guards (no update pass running, READY, no package operation). A
  returned why restarts the pair and passes its `$since` to `pfb_dns_proxy_confirm_ready()`, as #3598 does.
- **(e) A failed live add.** A bind that fails is logged (unless the address is just not there yet) and named by the
  startup check's notice as not served; nothing restarts. A send or reply that fails restarts once (D4.4).

## Acceptance criteria

- WHEN the rc script changes only in listen addresses and the proxy is READY THEN no restart, the new addresses are
  added and the gone ones removed live, and the log shows `listening`/`stopped listening` lines for them.
- WHEN the rc script changes in a port or a TLS, DDR or module flag THEN the whole pair restarts, as today.
- WHEN an address the start could not assign becomes bindable THEN the next tick or update pass adds it live, with no
  restart, and the standing startup notice closes.
- WHEN the gateway does not take a change (older gateway, error, no socket) THEN the whole pair restarts once.
- WHEN a hostile add frame arrives (D2 rows) THEN `error:`, nothing served, and no descriptor leaks in the gateway.
- WHEN `scripts/agent/run-gates.sh --diff origin/devel` runs THEN every touched gate passes.
- WHEN a smoke seat adds and removes an address with `ifconfig … alias` on a live box and runs the tick THEN
  `listening`/`stopped listening` lines appear with no gateway restart. Pending until a smoke seat runs it.

### Coverage matrix

Kinds from `pfb_dns_proxy_command_listeners()` (`udp+tcp`, `dot`, `doh`, `doq`); families IPv4 and IPv6; operations add
and remove.

| Row | Expected |
| --- | --- |
| G1 add `udp+tcp`, IPv4 and IPv6 | served on UDP and TCP; `listening udp+tcp` line; `ok` |
| G2 add `dot`, `doh`, `doq` | served with the store's certificate (DoH with the trusted prefixes); line; `ok` |
| G3 remove each kind, bound at start and added | closed; `stopped listening` line; other listeners keep serving |
| G4 remove a listener not served | `error:` |
| G5 add a listener already served | `error:`; descriptors closed |
| G6 descriptor count wrong (0, 1 or 3 for `udp+tcp`; 2 for `dot`), or `MSG_CTRUNC` | `error:`; descriptors closed |
| G7 wrong socket type, `udp+tcp` order swapped, family mismatch, unbound socket, TCP not listening, bound elsewhere, not a socket | `error:`; descriptors closed |
| G8 port not the kind's configured port; TLS kind not served by this gateway | `error:`; descriptors closed |
| G9 descriptors on a restart, certificate or remove frame | closed; frame handled as without them |
| G10 peer not uid 0 sends an add with descriptors | closed unread; nothing served; no descriptor left in the gateway |
| G11 shutdown with added listeners; remove then shutdown | every listener closed once |
| G12 `starting pid <pid>` is the start's first line | asserted |
| P1 address-only rc change, READY | no restart; adds and removes sent; rc rewritten |
| P2 rc change in a port, a TLS group, DDR or a module flag | whole restart |
| P3 address-only change, not READY or no complete start | whole restart |
| P4 package operation | nothing live; pending restart recorded as today |
| P5 gateway answers `error:` (older gateway's text), hangs up, or has no socket | whole restart, once |
| P6 bind fails EADDRNOTAVAIL (IPv4 and IPv6) | nothing sent, nothing logged, no restart |
| P7 bind fails otherwise (address in use) | logged, nothing sent, no restart |
| P8 tick: refused address now bindable | added live; no restart; notice closes |
| P9 tick: still unbindable; update pass running | nothing; confirmation as today |
| P10 tick with a pending restart and a bindable missing listener | whole restart; marker kept |
| P11 tick: served listener the command does not name, no marker | removed live |
| P12 host `inet_pton()` rejects (`127.1`) | never bound |
| P13 frames for each kind and family | `<kind> <host:port>`, descriptor count and types as D2 |
| P14 several changes; first one refused | one restart; later changes not sent |
| P15 `pfb_dns_proxy_listeners()` folding | post-ready add/remove applied in order; previous start's post-ready lines not credited to the next start; a start in progress ignored; legacy log read as before |
| P16 startup check and status panel after a live add and a remove | add counted as served, notice closed; removed not shown as listening |
| P17 PHP closes its socket copies after the send | no descriptor left in the PHP process |
| E1 real PHP to real gateway (root-only CI step) | add over `SCM_RIGHTS` served and logged; remove stops it |

> **Amendment 2026-10-31 (#3625).** Row P15 is superseded: the startup check and the status panel read the list probe, not the log, so there is no folding to pin. The probe is `FF FF FF FC` (`listening`/`refused` lines, then `ok`); row E1 asserts it after each step with the real PHP and the real gateway. Unknown (no socket, no reply within `PFB_DNS_PROXY_CTL_TIMEOUT`, an `error:` line, a malformed reply, or one over 64 KiB): the startup check judges no listener, the status panel shows `configured_unconfirmed`, the sync changes nothing, and the update pass restarts an address-only change.

### Hostile-input rows

| Input | Expected |
| --- | --- |
| Length 0, length over 256, body shorter than its length | `error:`; descriptors closed |
| Unknown kind, empty kind, kind in another case (`UDP+TCP`) | `error:` |
| `host:port` with no port, unbracketed IPv6, a name, a zone (`[fe80::1%em0]:53`), IPv4-mapped IPv6, non-canonical IPv6 spelling, port 0 or over 65535 | `error:` |
| Trailing space or newline, two spaces, a tab, a NUL byte, non-ASCII bytes | `error:` |
| Log line `stopped listening` for a listener never served; trailing spaces on log lines; decider lines between them | no effect beyond D3 |
| rc text where a non-address flag changes next to an address change | not address-only |

> **Amendment 2026-10-31 (#3625).** The log row above is superseded by the reply's own rows: the reply is read as exactly `listening` and `refused` lines then `ok`, each kind and address spelled as the gateway spells it and named once. Any other reply (an `error:` line, a control byte, a malformed or repeated line, or one over 64 KiB) is unknown: the startup check judges no listener, the status panel shows `configured_unconfirmed`, the sync changes nothing, and the update pass restarts an address-only change.

## Out of scope

- A faster trigger than the tick (for example a pfSense new-address event hook).
- Port changes and TLS, DDR or module setting changes: they keep restarting the whole pair.
- Asking the gateway what it serves: the log stays the record.

> **Amendment 2026-10-31 (#3625).** "Asking the gateway what it serves" is done: `pfb_dns_proxy_listener_list()` sends `FF FF FF FC` on the control socket and reads `listening`/`refused` lines, then `ok`. Unknown (no socket, no reply within `PFB_DNS_PROXY_CTL_TIMEOUT`, an `error:` line, a malformed reply, or one over 64 KiB): the startup check judges no listener, the status panel shows `configured_unconfirmed`, the sync changes nothing, and the update pass restarts an address-only change. The log is read by people, never for listener state.

## Open forks

None.
