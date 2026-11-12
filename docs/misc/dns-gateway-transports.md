# DNS gateway encrypted transports

Scope: DoT, DoH and DoQ of the Go connectivity layer (`go/pfb_dns_gateway`, issue #3513), the certificate they serve,
how a client address is decided on each, and what a front end such as HAProxy can and cannot do for them. Load when:
changing `tlsconfig.go`, `dot.go`, `doh.go`, `doq.go`, `pfb_doq_probe`, or putting a front end in front of the gateway.

Every query is attributed to the accepted listener as TCP, UDP, DoT, DoH or DoQ, independently of the upstream
UDP exchange or TCP fallback. DoH client attribution still follows the trusted-proxy rules below; a proxy header
does not change the listener transport. Only UDP clients have the decider's UDP answer-size limit.

## Certificate

DoT, DoH and DoQ serve the certificate selected on **DNS > General** (`dns/pfb_dns_sslcertref`): the certificate, the CAs after it nearest first, then its private key,
as one PEM text. The gateway does not read `config.xml`. It has the certificate from two places, and nowhere else:

1. **At start, from `--tls-pem`** (`/var/etc/pfb_dns/tls.pem` in pfBlockerNG's rc script). pfBlockerNG writes the file
   (`pfb_dns_proxy_certificate_export()`, see `architecture-notes.md`): mode 0600 in a directory of mode 0700, both root's, outside
   the Unbound chroot, with the `dns/pfb_dns_sslcertref` certificate, the chain its `caref` leads to (a missing CA or a loop ends it), and a
   key that is neither encrypted nor another certificate's; it replaces the file by rename, when the certificate changed, at every
   apply, at every cron tick (15 minutes) and at a start that finds no file. The gateway reads it once, as root, before the privilege
   drop, and not at all unless an ordinary or fixed-port DoT/DoH/DoQ listen flag is given. It never looks at the file again: what is in
   it after the start is none of the running gateway's business. The DoT port is `--dot-port`, from `dns_shared/pfb_dns_dot_port`
   (853 by default). PKCS#8, PKCS#1 and SEC1 keys load; an encrypted key is refused (a daemon cannot be asked for a
   passphrase).
2. **While it runs, as a push on the control socket** (`--ctl-socket`, `/var/run/pfb_dns/ctl.sock`), from root. The gateway is
   `unbound` by then and cannot read a file only root can read, which is the point: the key of the pfB-DNS certificate is not
   readable by the user of a network-facing daemon (nor by Unbound's user, which is why the file is no longer in the chroot).

When a TLS transport is requested and the file is unusable or absent at start, the reason is logged once
(`TLS certificate not loaded: <reason>; DoT, DoH and DoQ handshakes fail until one is pushed`), the TLS listeners are bound
with no certificate (a handshake fails with `no TLS certificate is loaded`), plain UDP and TCP keep serving (under `daemon -r` a
broken certificate must not crash-loop the only :53 listener), and the first certificate pushed is served by the listeners that were
there all along, with no restart: the next apply or cron tick pushes it (the start has PHP write a missing file first). Until
then the status lists `tls_certificate` in `degraded`.

### The control socket

- **Made** before the privilege drop in every mode, TLS transport or not, and reported as `control socket <path>` before
  `ready upstream`. Its directory is created mode 0700 (or
  must already be a real directory, not a symlink, owned by the user running the gateway, and is chmod'ed 0700 if it was left
  open); the socket is mode 0600; a stale file at the path is replaced. A socket that cannot be made is logged once
  (`control socket: <reason>; the certificate cannot be renewed without a restart`) and the
  gateway serves the certificate it read at start: a renewal then needs a restart, which pfBlockerNG reports as a notice.
- **Who may push.** One credential, read from the kernel for every connection: the peer's uid must be 0. Linux:
  `getsockopt(SO_PEERCRED)` (`unix.GetsockoptUcred`, the `uid` field). FreeBSD (pfSense): `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)`
  (`unix.GetsockoptXucred`, `cr_uid`, `cr_version` must be 0). Any other OS reads no credential, so every connection is
  refused. A connection from another user, or whose credential cannot be read, is closed without being read and logged once per
  burst (`control socket: refused a connection from uid N: only uid 0 may push`; the next accepted root connection re-arms the
  line). The mode 0600 on the socket is a second wall, not the one relied on.
- **Frame.** One message per connection, starting with 4 bytes. `FF FF FF FE` and `FF FF FF FD` add and remove a listener,
  `FF FF FF FB` replaces the address tables, and `FF FF FF FA` reads applied status (below).
  `FF FF FF FC`, with nothing after it, remains the explicit listener-list diagnostic: `listening <kind> <host:port>`
  for each served listener, then `refused <kind> <host:port> <reason>` for each outstanding start-time bind refusal,
  then `ok`. A live add clears the refusal of the same kind and address.
  Anything else is the length of the PEM, big-endian (1 to 65536; judged before the body is read), then the PEM
  (the chain, then the key). Reads and writes have separate 5 s deadlines. Replies end with `ok` or `error: <reason>`.
  A certificate push that does not parse, or whose key is not the certificate's, changes nothing and logs
  `TLS certificate not replaced: <reason>; keeping the previous one`; one that does logs `TLS certificate replaced by a push`
  and is served from the next handshake on. A push without TLS listeners answers
  `error: no TLS transport is served, so there is no certificate to replace`.
- **Add and remove a listener** (issue #3599). The gateway binds only before it drops root; root PHP binds the socket and hands
  it over here with `SCM_RIGHTS`, in the same `sendmsg()` as the frame. `FF FF FF FE` (add) or `FF FF FF FD` (remove), a 4-byte
  big-endian length 1 to 256 (judged before the body is read), then `<kind> <host:port>` in ASCII: `kind` is `udp+tcp`, `dot`,
  `doh` or `doq`, exactly; `host:port` is Go's `netip.AddrPort` spelling and must equal its own `String()` (IPv6 bracketed and
  compressed; no zone, no IPv4-mapped form, no port 0; no space, tab, NUL or non-ASCII byte anywhere else). An add carries
  `udp+tcp` the UDP socket then the listening TCP socket, `dot` and `doh` one listening TCP socket, `doq` one UDP socket. It is
  taken only when the kind is served by this gateway (`udp+tcp` always; a TLS kind when its ordinary or fixed listen list was given),
  the port is its configured family port or its own standard port (plain DNS 53, DoT/DoQ 853, DoH 443; #3699), and
  `<kind> <host:port>` is not served
  already, the descriptor count is the kind's and nothing was truncated (`MSG_CTRUNC`; room for 8 descriptors), each descriptor
  is a socket of the type expected (`SO_TYPE`), a stream socket is listening (`SO_ACCEPTCONN`) and every one is bound
  (`getsockname()`) to the frame's address in its family, and the gateway is not stopping; otherwise the reply is
  `error: <reason>` and every descriptor is closed. A taken add is served as a start-bound listener of its kind (certificate
  from the store, DoH with the start's `--doh-trusted` prefixes), logs `listening <kind> <host:port>` (the line a start logs) and
  replies `ok`. With `--ddr`, a DoT, DoH or DoQ listener is designated from its add on and not after its remove (see DDR).
  A remove closes a served listener (bound at start or added; both sockets of `udp+tcp`), logs
  `stopped listening <kind> <host:port>` and replies `ok`; one that is not served is
  `error: <kind> <host:port> is not served`. Connections the removed listener had accepted: plain TCP and DoT connections
  keep running to their own end (or the shutdown's); DoH connections (the HTTP server is closed) and DoQ connections (closed
  with `DOQ_NO_ERROR`) end with the listener. A descriptor that comes with any other frame (restart, certificate, remove) is closed and the frame is handled as
  without it; descriptors may ride with any byte of the frame. The shutdown closes every listener, added ones included, and a
  removed one is not closed again. A gateway older than the verbs answers `FF FF FF FE` with
  `error: a message of 4294967294 bytes is not between 1 and 65536`.
- **Address tables** (issues #3694, #3757). `FF FF FF FB`, a 4-byte big-endian length 0 to 65536, then lines joined by
  `\n` with no trailing newline or empty line. Rows are `dns-name-answer LOCAL=ADDR[,ADDR]`, `ddr-doh-443 ADDR`,
  or `listener-interface IP=BASE64UTF8`; the first two retain their corresponding flag formats.
  `dns-name-answer LOCAL=` explicitly owns the Name without either address family. A `listener-interface` entry (a row, or
  a `--listener-interface` flag) is valid when its IP is canonical, unscoped and not unspecified, and its label is canonical
  standard base64 of at most 65535 bytes of valid UTF-8 with no control, format, line-separator or paragraph-separator
  character (so `Län` and `日本` are valid, a zero-width joiner or U+2028 is not; an empty label is valid). An entry that is
  not valid is logged (`listener-interface "<entry>" skipped: <reason>`) and skipped, and the first of two entries for one
  address wins; the others apply, in a push and at startup alike, and neither refuses the push nor stops the gateway. Name
  and DDR rows and the framing of the body (no empty line, no trailing newline, a known first word) are still validated as a
  whole before any table changes, and a body that fails them leaves the previous tables intact.
  Ownership-only or empty updates work without `--dns-name` or DDR; name rows still require `--dns-name` and DoH 443
  rows still require DDR. An empty body empties all tables. The gateway replaces each immutable table snapshot, logs
  only a changed table as `address table: <N> name answers, <N> DoH 443 addresses, <N> listener interfaces` (an
  ownership-only change too; the count is the entries applied), and replies `ok`.
  Repeatable `--listener-interface IP=BASE64UTF8` flags initialize the owner snapshot at startup. PHP uses the existing
  address-table push after listener synchronization to refresh ownership as well as name/DDR rows; in-flight queries
  retain their captured description. A gateway older than the verb answers
  `error: a message of 4294967291 bytes is not between 1 and 65536`.
- **Applied status** (issue #3845). `FF FF FF FA`, with no body, returns one compact JSON line, then `ok`, then EOF.
  The complete response is at most 65536 bytes; an oversized snapshot returns an error, never partial status.
  Version 1 includes:
  - `version`, `pid`, `executable` and `ready`: runtime identity and frontend readiness. `executable` is the path the
    gateway started from, read at start: a package upgrade replaces that file under a running gateway, and FreeBSD then
    reports no path for the process (issue #3857).
  - Optional `upstream`: the canonical numeric applied endpoint. Supported forms are package-generated loopback endpoints
    and the prior readiness check's unscoped numeric IP forms (including bracketed IPv4), with a raw port of one to five
    ASCII digits in the range 1–65535. Leading zeros normalize. Hostnames, scoped IPv6 and unsupported port spellings omit
    this field without invalidating the rest of the snapshot. PHP upstream readiness is then false; no name resolution,
    text passthrough or configuration fallback is attempted.
  - `dns_name` and `name_answers`: the applied name and each local address's `a`/`aaaa` arrays. An owned empty pair means
    NODATA; an address missing from the map is forwarded.
  - `listeners`: each `kind`, `address`, `state` (`listening` or `refused`) and `reason`.
  - `ddr` and `advertisements`: applied DDR enablement and each local address's `records` and `additional` addresses.
    Records carry `priority`, `target`, `alpn`, `port`, `hint` and `path`, converted from the same designation builder
    that answers DNS queries, including its certificate and actual-listener checks.
  - `degraded` (issue #3848): always present, `[]` when nothing is lost (a gateway older than the field sends none). A row is
    `part` and `reason` (one line, no control characters, at most 300 bytes). The parts, in the order the rows come, each at
    most once:
    - `dnsbl`: the DNSBL does not block. The decider could not boot (an error, or no boot within 300 s), so it was booted again
      with no module and every query is forwarded; or it booted with no DNSBL build (manifest absent, unreadable or unbuildable).
      A zero-downtime reload that builds the DNSBL ends the second case; a reload that fails after a good build keeps the last
      good lists and lists nothing.
    - `dnsbl_settings`: `pfb_unbound.ini` could not be parsed; the DNSBL runs with what was read.
    - `dns_name`: `--dns-name` or `--dns-name-answer` cannot be used: no DNS name answers, and no DDR (see DNS name).
    - `ddr`: DDR is off although it was asked for (see DDR).
    - `tls_certificate`: no usable certificate; DoT, DoH and DoQ handshakes fail until one is pushed.
    - `acl`: Unbound's config cannot be loaded for the ACL, so every client is forwarded (Unbound still applies its own ACL).
    - `statistics`: a DNSBL statistics database could not be opened; nothing is counted in it.
    - `observer`: the upstream observer's socket could not be bound; upstream blocks are not detected.

  The existing serial control handler builds the snapshot between mutations, off the DNS query path. No certificate,
  private key or configuration blob is returned. The same root peer credential and filesystem permissions apply.
  PHP validates the version, complete response and runtime identity against the live gateway's ready marker.
  Unknown, malformed, oversized or unavailable status is unavailable, never a saved-setting fallback.
  One response supplies the page or widget refresh; readiness still independently requires the live Unbound PID to
  own TCP and UDP sockets on the reported upstream. Advertised state does not prove client reachability or TLS trust.
  The update pass and cron tick confirm their own starts/restarts. An existing gateway stays running when status
  reads fail or the Resolver backend is down; existing startup diagnostics still run. A foreign holder of the applied
  upstream port changes nothing either: no pass gives the Resolver back (owner decision, 2026-11-11).
  A dead or foreign-held backend makes **Service** say `Resolver backend not answering: <why>` and is a problem of the startup notice
  ([#3848](https://github.com/pfBlockerNG/pfBlockerNG/issues/3848)), which also tracks moving Unbound off a foreign holder's port to a free loopback port pair.
  No port migration, fallback, new restart or retry is added here. An actual start/restart still waits for serving
  readiness, also under a package operation, and reports a start that does not serve without restoring the Resolver.
  Rare IPv4-compatible (`::/96`), mapped and equivalent-spelling normalization is deferred to
  [#3849](https://github.com/pfBlockerNG/pfBlockerNG/issues/3849). Existing exact-spelling acceptance/refusal is retained;
  this status change does not introduce a new address codec.

A renewal needs no restart. Every TLS config of the three transports takes its certificate from `GetCertificate`, an atomic
pointer the push replaces: no handshake fails and no connection is touched: an open DoT, DoH or DoQ connection keeps the
certificate it was set up with and goes on answering, and a gateway that nobody connects to does nothing at all.

pfBlockerNG's side (`pfb_dns_proxy_certificate_refresh()`, called by every `pfb_dns_proxy_service()` and by the cron tick):
once the gateway is READY and the content of the file differs from what it was last given (a SHA-256 in `tls.pushed` beside the
file, written after a push that got `ok`, and removed by the rc start of a new process), PHP connects to the socket in its own
process (3 s per step: connect, send, reply; no external process, so no `timeout(1)`), sends the frame and reads the reply. A
refusal, a gateway that does not answer, a missing socket: one notice per distinct reason (`pfBlockerNG DNS Proxy certificate`), the
gateway keeps the certificate it has, and the next apply or tick tries again, because nothing records a push that failed.

Pinned by `ctl_test.go`, `ctl_wiring_test.go` and `restart_test.go` (peer credentials with a real unprivileged process, frame limits, directory and
socket modes, bound before the drop and kept after a real one), `live_listen_linux_test.go`, `live_listen_refused_linux_test.go`
and `starting_pid_test.go` (add and remove over real sockets and descriptors: served on every kind and family, refused rows,
hostile frames, descriptors closed, shutdown closes each listener once, `starting pid` first), `live_listen_list_linux_test.go`
(the `list` reply: every kind listening and refused, refusals cleared by a live add), `tls_reload_test.go` (a gateway process serving all three
transports through a rotation, a refused push and a rotation under load: no failed handshake, no unanswered query),
`tlsconfig_test.go`, `tests/dns_proxy/test_gateway_e2e.py` (the real binary, a pushed certificate, the modes of the socket and its
directory, and row E1: the real PHP `list` probe against the real gateway) and, for the PHP side, `DnsProxyCertificateExportTest`,
`DnsProxyCertificatePushTest` (a stand-in gateway on a real
Unix socket records the bytes it was sent) and `DnsProxyCertificateStartTest`.

**Not done, tracked as follow-up #3525: the chroot.** The gateway does not `chroot(2)` after the privilege drop. What keeps the
key from the unprivileged gateway here is that the file is root's alone and a renewal is pushed; confining the daemon to a
directory is a separate hardening and is not part of this change.

## Listeners

| Transport | Flags | Socket | TLS | Cap |
|---|---|---|---|---|
| DoT | `--dot-listen`, `--dot-listen-853` (repeatable), `--dot-port` (853) | TCP | 1.2+ | 128 connections, shared with plain TCP, checked at accept before the handshake; handshake 10 s; 4 queries in flight per connection |
| DoH | `--doh-listen` (repeatable), `--doh-listen-443` (repeatable), `--doh-port` (4443), `--doh-trusted` (repeatable) | TCP, HTTP/1.1 and HTTP/2 (ALPN `h2`, `http/1.1`) | 1.2+ | 128 connections of their own, closed at accept; read-header 10 s, idle 30 s, 100 streams per connection; 512 queries in flight, shared with DoQ and apart from UDP's (over it: 503 with `Retry-After: 1`) |
| DoQ | `--doq-listen`, `--doq-listen-853` (repeatable), `--doq-port` (853) | UDP, ALPN `doq` | 1.3 | 128 connections of their own, admitted before the handshake (the 129th, and an address the ACL denies, are refused with `CONNECTION_REFUSED`); 100 streams, idle `max(30 s, 2*timeout+grace)` (the query budget, so an in-flight query is not cut off) and no keepalive; receive window one message (65535 bytes) per stream and 100 messages per connection; 512 queries in flight, shared with DoH (over it: SERVFAIL on the stream) |

A listener that cannot be bound is logged and skipped. Every start logs `starting pid <pid>` first (before any bind error), so
that a reader of the log finds where a start begins; then, before `ready upstream`, the readiness lines in the order udp+tcp,
dot, doh, doq: `listening dot|doh|doq <host>:<port>`; an IPv6 address is bracketed (`[::1]:853`). A listener added or removed
while the gateway serves logs `listening <kind> <host>:<port>` or `stopped listening <kind> <host>:<port>` after `ready upstream`.
These lines are for people reading the log: nothing parses them for listener state, which applied status answers.

The repeatable fixed-port flags `--listen-53 ADDR`, `--dot-listen-853 ADDR`, `--doh-listen-443 ADDR` and
`--doq-listen-853 ADDR` bind only their named kind on the named standard port (#3699). ADDR is an IP address without a zone;
mapped IPv4 forms follow existing normalization. A fixed list may be the only list enabling its transport. Ordinary and fixed
lists that resolve to the same endpoint bind it once. Bind failures retain the existing per-kind refusal reporting.
pfBlockerNG uses these flags for automatically created Resolver VIPs and excludes those VIPs from ordinary configured-port lists:
they do not also serve custom ports. Administrator-managed VIPs remain ordinary configured-port addresses. DDR follows actual
bound listeners, so a managed DoH VIP advertises 443 without an explicit advertisement override.

pfBlockerNG's rc script always adds `127.0.0.1` and `::1` to
`--dot-listen`, `--doh-listen` and `--doq-listen`, next to the interfaces' addresses, so a local HAProxy has a stable backend; the DoT,
DoH and DoQ ports are their own, so nothing collides with the plain DNS listeners there.

## Fairness: what one address may hold

The caps in the table are global. On top of them one client address may hold at most half of each shared budget, so that
one host cannot fill it: 256 of the 512 UDP queries in flight, 256 of the 512 DoH and DoQ queries in flight (one share for
both transports together), 64 of the 128 TCP and DoT connections (plain TCP and DoT count together), 64 of the 128 DoH
connections and 64 of the 128 DoQ connections. The share is counted per full address, never per prefix: a pfSense LAN is
normally one /64, and prefix keying would make every IPv6 host on it share one share. For DoH behind a trusted front end the
address of a query is the client the front end names, not the front end; the front end's own connections, which carry many
clients, hold no connection share (a peer in `--doh-trusted` is exempt, an address that is not in it is not, whatever
header it sends). DoQ has no front end: its client is the QUIC peer, so it has no exemption.

A query over its address's share is refused as one over the global cap is (UDP: dropped; DoH: 503 with `Retry-After: 1`;
DoQ: SERVFAIL on the stream); a connection over it is refused as one over the global cap is (TCP, DoT and DoH: closed at
accept; DoQ: `CONNECTION_REFUSED` before the handshake). Nothing already accepted is ever evicted to
make room: a newcomer is refused, queries that were accepted are answered. The first refusal of a burst is logged
(`client address limit of N <what> reached`, without the address) and the log re-arms once nothing is held.

Known limit: a client that rotates its source address (many /128s of one /64, spoofed UDP sources) is held to the global
cap only, because each address has a share of its own; the cap then bounds the gateway, and since nothing is evicted the
others' accepted queries are not displaced, but new ones from everyone are refused until the flood drains.

## TCP and DoT connections

One connection carries up to 4 queries at once (RFC 7766 6.2.1.1: a server SHOULD process them concurrently and MAY
answer out of order). Each is decided and forwarded on its own and its reply is written when it is ready, so replies
can come in another order than the queries. At 4 the connection is not read until one query is answered: TCP's flow
control pushes back, and nothing already accepted is dropped.

Unbound is asked over UDP first, as for a DoH or DoQ client: a PROXYv2 header for UDP naming the client, one datagram
exchange. Unbound counts every TCP connection against its few TCP slots (`incoming-num-tcp`, 10 per thread by default
in pfSense), so clients that ask small names open none. Only a reply with TC set is asked again over TCP, on one of the
connection's own Unbound TCP connections: opened behind a TCP PROXYv2 header naming the same client, kept for that
client's next truncated answer, used for one exchange at a time; a connection that fails or times out is closed and
never reused. The client gets the whole TCP answer. The one consequence: a client that a custom `allow_cookie` ACL
covers (the pfSense GUI does not offer it) is refused over UDP, where a native Unbound would answer it over TCP. DoH and
DoQ clients already behave this way.

A client that closes its sending side between two frames (a FIN, or a TLS close_notify) is still owed every answer: the
queries it sent are decided and answered, then the connection is closed. A read that hits the idle timeout does the same:
a query still in flight runs to its own budget and is answered, then the connection is closed; with nothing in flight the
connection is closed at once. Any other end of the client's stream (a reset, an end inside a frame) and a reply that
cannot be written abandon what is in flight and free the slot. A connection at its 4 queries is not read, so it learns of
such an end when one of them finishes (at most one whole-query limit).

A DoT connection ends with a TLS close_notify (RFC 8446 6.1) whatever ends it: the idle timeout, a failed write, or
the gateway stopping. A client that does not take it is cut off at the TCP level after 250 ms.

## Stopping

SIGTERM, SIGINT and SIGHUP stop the gateway the same way: the ready file is removed, the listeners are closed and
what is in flight is cancelled. A query still being decided is answered SERVFAIL, built by the gateway; the reply Unbound
sends later is never relayed, because the decider did not approve it. TCP and DoT clients get that answer and then the
close; DoH connections are closed with their listener. DoQ connections, accepted or still handshaking, are ended on the
wire before the UDP socket goes: an accepted one with a CONNECTION_CLOSE and `DOQ_NO_ERROR`, one still handshaking with
`CONNECTION_REFUSED` (quic-go's `Transport.Close` and `Listener.Close` send neither for an accepted connection, which
would stay open at the client until its 30 s idle timeout); that wait is bounded by 500 ms. The gateway waits for its
goroutines, DoH requests being served included, for 500 ms; the client connections still open then are closed, and
after another 500 ms the gateway stops waiting. The decider is then closed, in the time left of the shutdown's 4 s budget, also
when a query is still running in it (Close stops its watchers and removes its observer socket, and that query writes no row
after it; this is logged), and one that does not close in time is
left to the exit (each is logged), so the gateway exits at the end of the budget whatever the decider does, inside the 5 s the
rc stop allows before its KILL.

Every transport goes through the same path as plain DNS: the Resolver ACL, then the decider, then PROXYv2 to Unbound
with the client in the header. The ACL is Unbound's own, read from `--unbound-conf` (`/var/unbound/unbound.conf`) and
every file it includes, globs too: the `access-control` rows of `access_lists.conf`, of pfBlockerNG's marked clause and
of the admin's Custom Options. The most specific prefix matches and, of identical prefixes, the row read last wins; deny:
nothing is answered; refuse, and a client no row names (Unbound's default): REFUSED built by the gateway. Supported
rows accept a netblock immediately after the colon, as Unbound 1.26.1 does: `access-control:10.0.0.0/8 deny` counts.
Include-loading failures (a missing or unreadable include, a glob directory it cannot list, an include cycle, a brace
pattern) are logged once and retried when a file or glob match changes (a chmod counts, and so does a glob directory
that can be listed again). A glob whose directory is absent, is not a directory, is a symlink loop or has no match is an
empty include, as in glob(3), and so is an entry a wildcard directory component matches that is a plain file or a symlink
loop; a wildcard in a directory component is expanded and each directory it names is listed, so an unreadable one (a
permission or I/O error) fails the load like any other glob directory. Any other error opening a file, which can be
transient, is retried and logged every second. After a good load the gateway keeps its last good rules through such a
failure; before the first good load it forwards everything. Any file or glob match that changes is picked up within a
second.

Two Unbound rules the gateway follows too. A netblock named only by `access-control-view`, `access-control-tag`,
`access-control-tag-action` or `access-control-tag-data` is allowed, unless an identical `access-control` row names it.
The gateway forwards `deny_non_local`, `refuse_non_local` and `allow_cookie` clients, so the decider can still answer a
listed name for them; Unbound's own refusal or drop for a non-local name is not reproduced. Unbound refuses a UDP query
without a valid DNS cookie, and the client retries over TCP. Known divergence: two statements on one line (`access-control:
… allow access-control: …`) and a `server:` on a row's line are not split. The gateway ignores that row where Unbound
applies it. Splitting them needs a tokenizer rewrite; pfSense and pfBlockerNG never write them.
Scoped netblocks (`fe80::1%em0`) and prefixes with trailing text (`10.1.0.0/16x`) are also ignored locally even though
Unbound accepts them. This reader is not a configuration validator: an implicit row missing its required view/tag
argument can match locally although Unbound refuses to load that configuration.

## Who is the client

| Transport | Client address |
|---|---|
| DoT | the TCP peer |
| DoQ | the QUIC peer, whose address a Retry has validated |
| DoH, peer not in `--doh-trusted` | the TCP peer. PROXY bytes are not parsed (the TLS handshake fails) and `X-Forwarded-For` is ignored |
| DoH, peer in `--doh-trusted` | the source of its PROXY header when that header names one (a non-LOCAL header with an IP address; a source at the peer's own IP counts); otherwise the TCP peer, and then, if the request has `X-Forwarded-For`, the rightmost entry of the **last** such header when it parses as an IP address, else unchanged |

A `--doh-trusted` value is a prefix (host bits masked) or a bare address (/32, /128). One that is neither is logged and
ignored; it never stops the gateway.

PROXY header library behaviour (go-proxyproto v0.15.0), pinned by tests: version 1 and version 2 headers from a trusted
peer are accepted; a LOCAL command and an AF_UNIX source leave the client as the TCP peer; a malformed header, or a
PROXY command with an unspecified address family, ends the connection. The header sent on to Unbound names the
resolved client; a cross-family destination is normalized for PROXYv2 independently of the actual receiving IP
carried to the decider. Neither a proxy header nor HTTP Host can supply the receiving endpoint or its interface.

## Hostile messages and fuzzing

The same messages get the same result on every listener (`hostile_transports_test.go`, UDP, TCP, DoT, DoH and DoQ). The
gateway judges only a runt (under 12 bytes) and a message that is already a response: neither is answered or sent to
Unbound (DoH: 400; DoQ: the stream is reset with `DOQ_PROTOCOL_ERROR`). Everything else, malformed or not (another opcode,
QDCOUNT 0 or 2, oversized counts, TC set, a bad OPT), goes through the decider to Unbound as the client sent it, and Unbound
owns the answer; the client gets it back unchanged. A DoQ message differs only in the Message ID the gateway picks (RFC 9250
4.2.1). The parsers of what comes from outside have fuzz targets with a committed seed corpus (`testdata/fuzz/`): Unbound
config rows (`FuzzACLRow`) and the DoH GET parameter and POST body
(`FuzzDoHGet`, `FuzzDoHPost`). `go test` runs the corpus as ordinary tests, as the Go step of `scripts/agent/run-gates.sh`
does; `go test -fuzz=FuzzACLRow -fuzztime=30s` (and the others) explores from it, and what it finds is minimised into the
same directory.

## DoQ details (RFC 9250)

- ALPN `doq`; any other ALPN is refused in the handshake. No 0-RTT. The server grants no unidirectional streams.
- One query per bidirectional stream: a 2-byte length, the message, the client's FIN. The reply is a 2-byte length and
  the message, then the server's FIN. The buffer grows with the data that arrives, not with the length claimed.
- Message ID. RFC 9250 4.2.1: "When forwarding a DNS message from DoQ over another transport, a DNS Message ID MUST
  be generated according to the rules of the protocol that is in use." The decider and Unbound see a non-zero ID the
  gateway picked; the client gets its reply with ID 0.
- A query with a non-zero Message ID: RFC 9250 4.3.3 lists it as a protocol error ("It SHOULD forcibly abort the
  connection using QUIC's CONNECTION_CLOSE mechanism and SHOULD use the DoQ error code DOQ_PROTOCOL_ERROR"). The
  connection is closed with `DOQ_PROTOCOL_ERROR`. A denied current address gets `DOQ_REQUEST_CANCELLED` instead: see the
  deny bullet below.
- A query that carries the edns-tcp-keepalive option (code 11, RFC 7828): RFC 9250 4.3.3 lists receiving it as a
  protocol error and 5.5.2 forbids sending it on DoQ ("because it is specific to the use of TCP/TLS as a transport").
  The connection is closed with `DOQ_PROTOCOL_ERROR`, as for a non-zero Message ID, and a denied current address gets
  `DOQ_REQUEST_CANCELLED` instead. Other options, padding for one, pass.
- Other malformed streams (FIN before the announced length, more bytes than announced, a second query, no FIN after
  a complete message, fewer bytes than a DNS header, a response instead of a query) are reset with `DOQ_PROTOCOL_ERROR`
  and the connection goes on. RFC 9250 4.3.3 lists most of these as connection-fatal with the same SHOULD; the gateway
  resets the stream only, so one bad stream cannot cancel the other queries of the connection. A denied current address
  is different: its connection closes on any stream (see the deny bullet below).
  A stream whose length or body is not complete within the query timeout is reset with `DOQ_REQUEST_CANCELLED`, not
  `DOQ_PROTOCOL_ERROR`: the client was slow, the message was not wrong. A complete message that never gets its FIN
  stays `DOQ_PROTOCOL_ERROR`.
- A stream is read for at most the query timeout (`--timeout`, default 5 s), not the 30 s TCP idle timeout: a client
  sends its query and the FIN at once, and a stream has no idle wait between queries as a TCP connection has.
- Admission happens before the handshake (quic-go `ConnContext`). An address the ACL denies, and a connection over the
  cap of 128, are refused with the QUIC transport error `CONNECTION_REFUSED`; the cap log line appears once per burst.
  The slot is freed when the connection ends or its handshake fails. Because a slot is taken at the first Initial
  packet, every new client first proves its address with a Retry (one extra round trip), so a spoofed source cannot
  hold slots. ACL refuse still needs the handshake: REFUSED is a DNS answer on a stream.
- An ACL deny of a connection's current address closes the connection with `DOQ_REQUEST_CANCELLED`, whatever the stream
  holds (a query, a non-zero Message ID, edns-tcp-keepalive, a malformed or partial frame, a response), and frees its
  admission slot. The address is checked before a stream's read and again when the read ends, before the stream is
  parsed. A path that moves onto a denied address is judged the same way. A stream already being read when the deny
  arrives is judged when its read ends, which the read deadline bounds (the shorter of `--timeout` and the handshake
  budget). A decider DROP cancels only its stream, with the same code.
- Over the 512 queries in flight that DoQ shares with DoH, a stream is answered with a SERVFAIL (Message ID 0) built by
  the gateway, without asking the decider or Unbound; one log line per flood. DoQ has no status code to use instead.
- A query is resolved on a context that ends with its connection or its stream (the client's STOP_SENDING), so a
  connection that drops, or a stream the client abandons, while the query waits for the decider or
  Unbound frees its in-flight slot at once instead of holding it for the whole wait.

## DoH details (RFC 8484)

`/dns-query` only (else 404). GET: `dns` is base64url, padding tolerated, the standard alphabet is a 400. POST:
`Content-Type: application/dns-message` (else 415). 405 for other methods, 413 above 65535 bytes (a POST from its
Content-Length, before the body is read), 400 for a query that cannot be decoded or is shorter than a DNS header or is
a response. Answers are 200 `application/dns-message` with `Cache-Control: max-age=0`. RFC 8484 5.1 does not require
it: it says that a server that "customizes a response based on the client's identity" "would not want to allow global
reuse of that response" and names a `max-age` of 0 as one way; the DNSBL answer does depend on the client.
ACL deny, and a decider DROP, abort the request (the client sees a reset). A reply with TC set by Unbound's UDP
answer is asked for again over TCP. Over the 512 queries in flight that DoH shares with DoQ, a request gets 503 with
`Retry-After: 1` and one log line per flood. RFC 8484 4.2.1 has 2xx for any valid DNS response, SERVFAIL included, and
has a client treat other statuses like any HTTP client (retry later, or ask another server); an overloaded gateway is
that second case, so it is not a SERVFAIL body.

## Front ends: what HAProxy can do (verified against the HAProxy 3.4.7 manual, 2026-10-17)

The same statements are in the 3.2 and 3.3 manuals.

| Claim | Source |
|---|---|
| `send-proxy-v2` is a server option usable in `tcp` and `http` mode: HAProxy then puts a PROXYv2 header at the start of every connection to the server, carrying the client's addresses (and ALPN when negotiated). | [Configuration manual, `send-proxy-v2`](https://docs.haproxy.org/3.4/configuration.html#5.2-send-proxy-v2) |
| The PROXY header is "the block of connection information the connection initiator prepends at the beginning of a connection", and "the receiver MUST NOT start processing the connection before it receives a complete and valid PROXY protocol header". On a re-encrypting server line the header therefore comes first and the TLS handshake follows, which is the order the gateway expects (PROXY, then TLS, then HTTP). | [PROXY protocol specification](https://www.haproxy.org/download/3.4/doc/proxy-protocol.txt), section 2 |
| A receiver "MUST not try to guess whether the protocol header is present or not" and "SHOULD ensure proper access filtering so that only trusted proxies are allowed to use this protocol": hence `--doh-trusted`. | PROXY protocol specification, section 2 |
| For HTTP, a proxy that "do have a complete understanding of the transported protocol" "MUST use the facilities provided by this protocol to present the client's address" (here HTTP, so `X-Forwarded-For`) and "MUST NOT implement [the PROXY] protocol on multiplexed connections". HAProxy reuses an idle backend connection only for requests with the same source and destination addresses and proxy protocol, so the connection-level PROXY source stays one client's. The gateway takes the per-request header only where that source is absent. | PROXY protocol specification, section 2; [`http-reuse`](https://docs.haproxy.org/3.4/configuration.html#4.2-http-reuse) |
| `option forwardfor` appends `X-Forwarded-For` "at the end of the existing header list" as its own header line, and "the server must be configured to always use the last occurrence of this header only", because the client may have sent one. This is why the gateway takes the last header, and its rightmost entry (a proxy such as nginx that appends to one list is read the same way). | [`option forwardfor`](https://docs.haproxy.org/3.4/configuration.html#4.2-option%20forwardfor) |
| `option forwardfor if-none` states that "the header will only be added if it is not present", and the manual warns that it "should only be used in perfectly trusted environment, as this might cause a security issue if headers reaching HAProxy are under the control of the end-user". `option forwardfor except <network>` adds nothing for sources in that network ("any source IP matching the network will not cause an addition of this header"). With either, the last `X-Forwarded-For` line that reaches the gateway can be the end user's own; where the connection's PROXY header named no client, the gateway takes it from HAProxy's trusted address and believes it, so the user chooses the client address that the ACL, the decider and the logs see. | [`option forwardfor`](https://docs.haproxy.org/3.4/configuration.html#4.2-option%20forwardfor) |
| DoQ cannot go through HAProxy. HAProxy is not "a packet-based load balancer : it will not see IP packets nor UDP datagrams"; its QUIC listeners and servers speak HTTP/3 only ("QUIC supports only h3 and hq-interop as ALPN"), and connection migration is unsupported. DoQ (`doq`, UDP 853) is reached directly, or through a layer 3/4 forwarder that keeps the client's source address: the gateway has no PROXY support on QUIC. | [Introduction, "What HAProxy is and is not"](https://docs.haproxy.org/3.4/intro.html), [`alpn`](https://docs.haproxy.org/3.4/configuration.html#5.1-alpn), [Configuration manual, HTTP/3](https://docs.haproxy.org/3.4/configuration.html) |
| An HAProxy HTTP/3 frontend can serve DoH clients and reach this gateway over HTTP/2 or HTTP/1.1; the gateway itself serves no HTTP/3. [INFERENCE] from the QUIC frontend being an HTTP frontend; not run. | same |

A gateway behind HAProxy, TLS terminated on the gateway (client sees the pfB-DNS certificate):

```text
frontend doh
    mode tcp
    bind :443
    default_backend gateway_doh
backend gateway_doh
    mode tcp
    server gw 192.0.2.10:4443 send-proxy-v2
```

HAProxy terminating TLS itself and re-encrypting to the gateway:

```text
backend gateway_doh
    mode http
    option forwardfor
    server gw 192.0.2.10:4443 ssl verify required ca-file /etc/haproxy/resolver-ca.pem send-proxy-v2
```

with `--doh-trusted 192.0.2.1/32` (HAProxy's address) on the gateway.

Keep `option forwardfor` plain on a backend that points at the gateway: no `if-none`, no `except` (see the table).

Not verified by a run: the interplay with a live HAProxy. The PROXY-before-TLS order on an `ssl` server line rests on
the specification text above, and the gateway's side of it (PROXY header, then TLS, then HTTP, per request) is
exercised with hand-built headers in `doh_test.go`.

## DDR

Discovery of Designated Resolvers ([RFC 9462](https://www.rfc-editor.org/rfc/rfc9462.html), issue #3583), off unless asked for.
Its target name is the DNS name (below): there is no predefined name, and DDR with no DNS name answers nothing.

| Flag | Meaning |
|---|---|
| `--ddr` | DDR on; every record names the DNS name. Needs a usable `--dns-name`: without one the gateway still starts, with DDR off, and lists `ddr` in `degraded` (`--ddr needs --dns-name`, or `--ddr needs a --dns-name that can be served`). |
| `--ddr-doh-443 ADDR` | Repeatable (issue #3694). On the address ADDR the DoH record carries no `port` parameter, whatever port DoH listens on there, so clients reach DoH on 443 (a reverse proxy in front). ADDR is a valid IP address with no zone (an IPv4-mapped one is unmapped; a duplicate is harmless). Needs `--ddr`, and a value that is not valid has no use: either way the gateway still starts, with DDR off, and lists `ddr` in `degraded` (`--ddr-doh-443 needs --ddr`, or the bad value). |

With `--ddr`, after the Resolver ACL (a refused client still gets REFUSED, a denied one nothing) and before the decider, the
gateway answers every query for a name at or under `resolver.arpa.` itself, on every transport; the decider never sees it
and nothing is written to the reply log. Names match case-insensitively (ASCII) and the question is echoed as received.

- `_dns.resolver.arpa. SVCB` over plain UDP or TCP, received on address L: one ServiceMode record (TTL 300) per transport
  listening on L, while a certificate is loaded: DoH priority 1 (`alpn=h2`, `dohpath=/dns-query{?dns}`), DoT priority 2
  (`alpn=dot`), DoQ priority 3 (`alpn=doq`). `port` only when the listener's port is not 443 (DoH) or 853 (DoT, DoQ), and
  never on the DoH record of an address that has a DoH listener on port 443 or is among the `--ddr-doh-443` addresses (so exactly one DoH
  record per address, with the port of its DoH listener otherwise). Each record has `TargetName` = the DNS name and an `ipv4hint` or `ipv6hint` = L;
  the Additional section has the A or AAAA record for the DNS name = L.
- `resolver.arpa.` SOA and NS: `resolver.arpa. 300 IN SOA localhost. nobody.invalid. 1 3600 1200 604800 300` and
  `resolver.arpa. 300 IN NS localhost.`.
- Everything else at or under the zone, the SVCB query over DoT, DoH or DoQ, and a plain query on an address no
  qualifying transport listens on: NOERROR, no data, that SOA in Authority.
- Over UDP a reply over 512 bytes (the client's OPT size, clamped to 512 to 1232, when it sent one) is replaced by
  header, question and OPT with TC set; a reply to a query with an OPT carries an OPT advertising 1232.

L is the address a client queried, which only an explicit listener address gives. A DoT, DoH or DoQ listener bound to a
wildcard address is never matched to L. A plain socket bound to a wildcard address gives L over TCP (the connection's own
address) but not over UDP (the socket's address is the wildcard), so over UDP that query gets no data, and no record ever
carries `0.0.0.0` or `::` as a hint. Without `--ddr`, or with pfB-DNS off, the gateway does not touch `resolver.arpa.` and
the client gets Unbound's own answer unchanged.

The listeners DDR designates are the ones the gateway serves now: a DoT, DoH or DoQ listener added over the control socket
is designated from then on, and one that is removed (bound at start or added) no longer is, with no restart.

DDR designates on plain DNS only: a query that reaches a DoT, DoH or DoQ listener is never a DDR query (see DNS name for what those
transports do answer).

## DNS name

The DNS name (issue #3694) is entered on **DNS > General** beside the certificate (`dns/pfb_dns_name`, per node like the certificate, which
must list it as a DNS SAN) and is both DDR's target name and the one name pfB-DNS answers `A` and `AAAA` for itself.
An active pfB-DNS configuration requires this name for any of DoT, DoH, DoQ or DDR, even when DDR is off.
Save validation rejects a missing name; runtime command generation also leaves unnamed/invalid-name encrypted groups out with
a diagnostic, preserving plain DNS. Plain-only operation and disabling pfB-DNS may leave the name empty. This is pfBlockerNG's
configuration policy, not a new restriction on the standalone gateway's generic CLI.

| Flag | Meaning |
|---|---|
| `--dns-name NAME` | The DNS name, with or without one trailing dot: labels of 1 to 63 characters, at most 253 in all. Empty or absent: no name, so no DDR and no name answers. A NAME that is not valid leaves the gateway starting without the name, and so without DDR, with `dns_name` in `degraded`. The Save DNS settings save also refuses an IP literal, a wildcard, a single label and `resolver.arpa.` or a name under it. |
| `--dns-name-answer LOCAL=ADDR[,ADDR]` | Repeatable. A query for the name that arrives on LOCAL is answered with the ADDR of the family it asked for, or local NOERROR/NODATA when that family is absent. `LOCAL=` owns the Name without any addresses. LOCAL and every ADDR are IP addresses without a zone (an IPv4-mapped one is read as its IPv4 address); at most one ADDR per family. A LOCAL named twice, a value that is not valid, and any of these flags without `--dns-name` (`--dns-name-answer needs --dns-name`) are not usage errors: the gateway starts, serves plain DNS, answers no name and no DDR, and lists `dns_name` in `degraded`. LOCAL need not be one of its ADDRs. |

After the Resolver ACL (a refused client still gets REFUSED, a denied one nothing) and after DDR, before the decider, the gateway
answers a query for exactly the DNS name itself, on every transport, when LOCAL is in the table: the question is one `IN` `QUERY` of type `A` or
`AAAA`, its name equals the DNS name (ASCII case-insensitive; `sub.<name>` and every other type, MX, TXT and HTTPS included, go on to
Unbound). When the requested family is available, the reply is NOERROR with AA, RA and the query's RD, one
record of TTL 300 owned by the name as asked (its case kept), and an EDNS OPT echoed as DDR's replies do.
When that family is absent, the local reply is NOERROR/NODATA with an SOA for negative caching, not a public/upstream answer.
In either case the decider never sees the query and nothing is written to the reply log.
An address without a table entry still delegates to the decider and Unbound. On DoT, DoH and DoQ LOCAL is the address the connection reached
(after any PROXY header); DDR still sees only plain DNS.

The table is what PHP derives for each address the gateway listens on (`pfb_dns_proxy_name_answers()`): an active Resolver VIP is
answered with the VIP and the other family's active VIP, if any; any other address with the IPv4 and IPv6 addresses of the interface that
carries it, never a VIP, so a client that queries `10.0.0.1` is sent to `10.0.0.1` whether or not a VIP is active; an address no interface
carries, and loopback, get no entry. The table is given at start by the flags and replaced while running by the name-answer verb (see
the control socket), so an interface that gains or loses an address changes the answers with no restart.

The explicit VIP-only policy (`gen/pfb_dns_listen_vip_only`, off by default) instead gives the selected active VIP pair to every
served address, including internal loopback. Missing VIP families never fall back to an interface or public address: they return
local NODATA. If every VIP becomes unavailable, explicit owned-empty loopback entries preserve that behavior for both families.
The policy applies only while pfB-DNS is enabled; standalone Unbound restoration is unchanged.
Enabling it does not enable DNS redirect or delete leases: clients with old resolver addresses need DHCP renewal, RA DNS refresh
or manual reconfiguration.
This is a listener policy, not a guarantee that every DHCP/RA configuration advertises only VIPs. Existing Resolver VIP
advertisement handling remains; administrators must configure native defaults, overrides and static clients for the VIPs.
Custom DHCP/RA lists do not block activation.

## RFCs read for this step

- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) sections 4.1, 4.2, 5.1.
- [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html) sections 4.1 to 4.3.
- [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html) sections 4.3.3 and 5.5.2 for the keepalive option.
- [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html) section 6.2.1.1 (query pipelining over TCP) and
  [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) section 6.1 (close_notify).
