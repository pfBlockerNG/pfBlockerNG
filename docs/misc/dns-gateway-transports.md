# DNS gateway encrypted transports

Scope: DoT, DoH and DoQ of the Go connectivity layer (`go/pfb_dns_gateway`, issue #3513), the certificate they serve,
how a client address is decided on each, and what a front end such as HAProxy can and cannot do for them. Load when:
changing `tlsconfig.go`, `dot.go`, `doh.go`, `doq.go`, `pfb_doq_probe`, or putting a front end in front of the gateway.
The decision protocol with the Python decider is in [dns-gateway-protocol.md](dns-gateway-protocol.md).

## Certificate

DoT, DoH and DoQ serve the DNS Resolver's certificate: the certificate, the CAs after it nearest first, then its private key,
as one PEM text. The gateway does not read `config.xml`. It has the certificate from two places, and nowhere else:

1. **At start, from `--tls-pem`** (`/var/etc/pfb_dns/tls.pem` in pfBlockerNG's rc script). pfBlockerNG writes the file
   (`pfb_dns_proxy_certificate_export()`, see `architecture-notes.md`): mode 0600 in a directory of mode 0700, both root's, outside
   the Unbound chroot, with `unbound/sslcertref`'s certificate, the chain its `caref` leads to (a missing CA or a loop ends it), and a
   key that is neither encrypted nor another certificate's; it replaces the file by rename, when the certificate changed, at every
   apply, at every cron tick (15 minutes) and at a start that finds no file. The gateway reads it once, as root, before the privilege
   drop, and not at all unless `--dot`, `--doh-listen` or `--doq-listen` is given. It never looks at the file again: what is in
   it after the start is none of the running gateway's business. The DoT port is `--dot-port` (the Resolver's `unbound/tlsport`
   when it is a port, else 853). PKCS#8, PKCS#1 and SEC1 keys load; an encrypted key is refused (a daemon cannot be asked for a
   passphrase).
2. **While it runs, as a push on the control socket** (`--ctl-socket`, `/var/run/pfb_dns/ctl.sock`), from root. The gateway is
   `unbound` by then and cannot read a file only root can read, which is the point: the key of the Resolver's certificate is not
   readable by the user of a network-facing daemon (nor by Unbound's user, which is why the file is no longer in the chroot).

When a TLS transport is requested and the file is unusable or absent at start, the reason is logged once
(`TLS certificate not loaded: <reason>; DoT, DoH and DoQ handshakes fail until one is pushed`), the TLS listeners are bound
with no certificate (a handshake fails with `no TLS certificate is loaded`), plain UDP and TCP keep serving (under `daemon -r` a
broken certificate must not crash-loop the only :53 listener), and the first certificate pushed is served by the listeners that were
there all along, with no restart: the next apply or cron tick pushes it (the start has PHP write a missing file first).

### The control socket

- **Made** with the other TLS sockets, before the privilege drop, only when a TLS transport is requested (`--dot`, `--doh-listen`
  or `--doq-listen`), and reported as `control socket <path>` before `ready upstream`. Its directory is created mode 0700 (or
  must already be a real directory, not a symlink, owned by the user running the gateway, and is chmod'ed 0700 if it was left
  open); the socket is mode 0600; a stale file at the path is replaced. A socket that cannot be made is logged once
  (`control socket: <reason>; the certificate cannot be renewed without a restart`) and the gateway serves the certificate it
  read at start: a renewal then needs a restart, which pfBlockerNG reports as a notice.
- **Who may push.** One credential, read from the kernel for every connection: the peer's uid must be 0. Linux:
  `getsockopt(SO_PEERCRED)` (`unix.GetsockoptUcred`, the `uid` field). FreeBSD (pfSense): `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)`
  (`unix.GetsockoptXucred`, `cr_uid`, `cr_version` must be 0). Any other OS reads no credential, so every connection is
  refused. A connection from another user, or whose credential cannot be read, is closed without being read and logged once per
  burst (`control socket: refused a connection from uid N: only uid 0 may push`; the next accepted root connection re-arms the
  line). The mode 0600 on the socket is a second wall, not the one relied on.
- **Frame.** One message per connection: the length of the PEM as 4 bytes big-endian (1 to 65536; judged before the body is read),
  then the PEM (the chain, then the key). Reads have a 5 s deadline. The one reply line is `ok` or `error: <reason>`. A push that does
  not parse, or whose key is not the certificate's, changes nothing and logs
  `TLS certificate not replaced: <reason>; keeping the previous one`; one that does logs `TLS certificate replaced by a push` and
  is served from the next handshake on.

A renewal needs no restart. Every TLS config of the three transports takes its certificate from `GetCertificate`, an atomic
pointer the push replaces: no handshake fails and no connection is touched: an open DoT, DoH or DoQ connection keeps the
certificate it was set up with and goes on answering, and a gateway that nobody connects to does nothing at all.

pfBlockerNG's side (`pfb_dns_proxy_certificate_refresh()`, called by every `pfb_dns_proxy_service()` and by the cron tick):
once the gateway is READY and the content of the file differs from what it was last given (a SHA-256 in `tls.pushed` beside the
file, written after a push that got `ok`, and removed by the rc start of a new process), PHP connects to the socket in its own
process (3 s per step: connect, send, reply; no external process, so no `timeout(1)`), sends the frame and reads the reply. A
refusal, a gateway that does not answer, a missing socket: one notice per distinct reason (`pfBlockerNG DNS Proxy certificate`), the
gateway keeps the certificate it has, and the next apply or tick tries again, because nothing records a push that failed.

Pinned by `ctl_test.go` and `ctl_wiring_test.go` (peer credentials with a real unprivileged process, frame limits, directory and
socket modes, bound before the drop and kept after a real one), `tls_reload_test.go` (a gateway process serving all three
transports through a rotation, a refused push and a rotation under load: no failed handshake, no unanswered query),
`tlsconfig_test.go`, `tests/dns_proxy/test_gateway_e2e.py` (the real binary, a pushed certificate, the modes of the socket and its
directory) and, for the PHP side, `DnsProxyCertificateExportTest`, `DnsProxyCertificatePushTest` (a stand-in gateway on a real
Unix socket records the bytes it was sent) and `DnsProxyCertificateStartTest`.

**Not done, tracked as follow-up #3525: the chroot.** The gateway does not `chroot(2)` after the privilege drop. What keeps the
key from the unprivileged gateway here is that the file is root's alone and a renewal is pushed; confining the daemon to a
directory is a separate hardening and is not part of this change.

## Listeners

| Transport | Flags | Socket | TLS | Cap |
|---|---|---|---|---|
| DoT | `--dot`, on every `--listen` address at `--dot-port` (853) | TCP | 1.2+ | 128 connections, shared with plain TCP, checked at accept before the handshake; handshake 10 s; 4 queries in flight per connection |
| DoH | `--doh-listen` (repeatable), `--doh-port` (4443), `--doh-trusted` (repeatable) | TCP, HTTP/1.1 and HTTP/2 (ALPN `h2`, `http/1.1`) | 1.2+ | 128 connections of their own, closed at accept; read-header 10 s, idle 30 s, 100 streams per connection; 512 queries in flight, shared with DoQ and apart from UDP's (over it: 503 with `Retry-After: 1`) |
| DoQ | `--doq-listen` (repeatable), `--doq-port` (853) | UDP, ALPN `doq` | 1.3 | 128 connections of their own, admitted before the handshake (the 129th, and an address the ACL denies, are refused with `CONNECTION_REFUSED`); 100 streams, idle 30 s; 512 queries in flight, shared with DoH (over it: SERVFAIL on the stream) |

A listener that cannot be bound is logged and skipped. Readiness lines, before `ready upstream`, in the order udp+tcp,
dot, doh, doq: `listening dot|doh|doq <host>:<port>`; an IPv6 address is bracketed (`[::1]:853`).

pfBlockerNG's rc script always adds `127.0.0.1` and `::1` to
`--doh-listen` and `--doq-listen`, next to the interfaces' addresses, so a local HAProxy has a stable backend; the DoH and
DoQ ports are their own, so nothing collides with the plain DNS listeners there.

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
queries it sent are decided and answered, then the connection is closed. Any other end of the client's stream (a reset,
an end inside a frame, the idle timeout) and a reply that cannot be written abandon what is in flight and free the slot.
A connection at its 4 queries is not read, so it learns of such an end when one of them finishes (at most one
whole-query limit).

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
after another 500 ms the gateway stops waiting. The decider gets EOF with the transports' stop, and then the time
left of the shutdown's 4 s budget, less an eighth of it, to exit; after that it is killed (a kill that is refused is
logged) and the gateway exits at the end of the budget whatever the decider does, inside the 5 s the rc stop allows
before its KILL.

Every transport goes through the same path as plain DNS: the Resolver ACL, then the decider, then PROXYv2 to Unbound
with the client in the header. The ACL is Unbound's own, read from `--unbound-conf` (`/var/unbound/unbound.conf`) and
every file it includes, globs too: the `access-control` rows of `access_lists.conf`, of pfBlockerNG's marked clause and
of the admin's Custom Options. The most specific prefix matches and, of identical prefixes, the row read last wins; deny:
nothing is answered; refuse, and a client no row names (Unbound's default): REFUSED built by the gateway. A config
Unbound could not load (a missing include, an include cycle, a brace pattern) is logged once and the gateway forwards
everything; any file or glob match that changes is picked up within a second.

Two Unbound rules the gateway follows too. A netblock named only by `access-control-view`, `access-control-tag`,
`access-control-tag-action` or `access-control-tag-data` is allowed, unless an identical `access-control` row names it.
The gateway forwards `deny_non_local`, `refuse_non_local` and `allow_cookie` clients, so the decider can still answer a
listed name for them; Unbound's own refusal or drop for a non-local name is not reproduced. Unbound refuses a UDP query
without a valid DNS cookie, and the client retries over TCP. Known divergence: two statements on one line (`access-control:
… allow access-control: …`) and a `server:` on a row's line are not split. The gateway ignores that row where Unbound
applies it. Splitting them needs a tokenizer rewrite; pfSense and pfBlockerNG never write them.

## Who is the client

| Transport | Client address |
|---|---|
| DoT | the TCP peer |
| DoQ | the QUIC peer, whose address a Retry has validated |
| DoH, peer not in `--doh-trusted` | the TCP peer. PROXY bytes are not parsed (the TLS handshake fails) and `X-Forwarded-For` is ignored |
| DoH, peer in `--doh-trusted` | the source of its PROXY header if it sent one, else the TCP peer; then, if the request has `X-Forwarded-For`, the rightmost entry of the **last** such header when it parses as an IP address, else unchanged |

A `--doh-trusted` value is a prefix (host bits masked) or a bare address (/32, /128). One that is neither is logged and
ignored; it never stops the gateway.

PROXY header library behaviour (go-proxyproto v0.15.0), pinned by tests: version 1 and version 2 headers from a trusted
peer are accepted; a LOCAL command and an AF_UNIX source leave the client as the TCP peer; a malformed header, or a
PROXY command with an unspecified address family, ends the connection. The header sent on to Unbound always names the
resolved client and the local listener, never the front end's own addresses.

## Hostile messages and fuzzing

The same messages get the same result on every listener (`hostile_transports_test.go`, UDP, TCP, DoT, DoH and DoQ). The
gateway judges only a runt (under 12 bytes) and a message that is already a response: neither is answered or sent to
Unbound (DoH: 400; DoQ: the stream is reset with `DOQ_PROTOCOL_ERROR`). Everything else, malformed or not (another opcode,
QDCOUNT 0 or 2, oversized counts, TC set, a bad OPT), goes through the decider to Unbound as the client sent it, and Unbound
owns the answer; the client gets it back unchanged. A DoQ message differs only in the Message ID the gateway picks (RFC 9250
4.2.1). The parsers of what comes from outside have fuzz targets with a committed seed corpus (`testdata/fuzz/`): the
decider's frames (`FuzzReadFrame`), Unbound config rows (`FuzzACLRow`) and the DoH GET parameter and POST body
(`FuzzDoHGet`, `FuzzDoHPost`). `go test` runs the corpus as ordinary tests, as the Go step of `scripts/agent/run-gates.sh`
does; `go test -fuzz=FuzzReadFrame -fuzztime=30s` (and the others) explores from it, and what it finds is minimised into the
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
  connection is closed with `DOQ_PROTOCOL_ERROR`.
- A query that carries the edns-tcp-keepalive option (code 11, RFC 7828): RFC 9250 4.3.3 lists receiving it as a
  protocol error and 5.5.2 forbids sending it on DoQ ("because it is specific to the use of TCP/TLS as a transport").
  The connection is closed with `DOQ_PROTOCOL_ERROR`, as for a non-zero Message ID. Other options, padding for one, pass.
- Other malformed streams (FIN before the announced length, more bytes than announced, a second query, no FIN within
  the query timeout, fewer bytes than a DNS header, a response instead of a query) are reset with `DOQ_PROTOCOL_ERROR`
  and the connection goes on. RFC 9250 4.3.3 lists most of these as connection-fatal with the same SHOULD; the gateway
  resets the stream only, so one bad stream cannot cancel the other queries of the connection.
- A stream is read for at most the query timeout (`--timeout`, default 5 s), not the 30 s TCP idle timeout: a client
  sends its query and the FIN at once, and a stream has no idle wait between queries as a TCP connection has.
- Admission happens before the handshake (quic-go `ConnContext`). An address the ACL denies, and a connection over the
  cap of 128, are refused with the QUIC transport error `CONNECTION_REFUSED`; the cap log line appears once per burst.
  The slot is freed when the connection ends or its handshake fails. Because a slot is taken at the first Initial
  packet, every new client first proves its address with a Retry (one extra round trip), so a spoofed source cannot
  hold slots. ACL refuse still needs the handshake: REFUSED is a DNS answer on a stream.
- A deny rule that appears while a connection is open, and a decider DROP, cancel the stream with
  `DOQ_REQUEST_CANCELLED`.
- Over the 512 queries in flight that DoQ shares with DoH, a stream is answered with a SERVFAIL (Message ID 0) built by
  the gateway, without asking the decider or Unbound; one log line per flood. DoQ has no status code to use instead.

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
| For HTTP, a proxy that "do have a complete understanding of the transported protocol" "MUST use the facilities provided by this protocol to present the client's address" (here HTTP, so `X-Forwarded-For`) and "MUST NOT implement [the PROXY] protocol on multiplexed connections". HAProxy reuses an idle backend connection only for requests with the same source and destination addresses and proxy protocol, so the connection-level PROXY source stays one client's; the per-request header refines it. [INFERENCE] for the last clause. | PROXY protocol specification, section 2; [`http-reuse`](https://docs.haproxy.org/3.4/configuration.html#4.2-http-reuse) |
| `option forwardfor` appends `X-Forwarded-For` "at the end of the existing header list" as its own header line, and "the server must be configured to always use the last occurrence of this header only", because the client may have sent one. This is why the gateway takes the last header, and its rightmost entry (a proxy such as nginx that appends to one list is read the same way). | [`option forwardfor`](https://docs.haproxy.org/3.4/configuration.html#4.2-option%20forwardfor) |
| `option forwardfor if-none` states that "the header will only be added if it is not present", and the manual warns that it "should only be used in perfectly trusted environment, as this might cause a security issue if headers reaching HAProxy are under the control of the end-user". `option forwardfor except <network>` adds nothing for sources in that network ("any source IP matching the network will not cause an addition of this header"). With either, the last `X-Forwarded-For` line that reaches the gateway can be the end user's own; the gateway takes it from HAProxy's trusted address and believes it, so the user chooses the client address that the ACL, the decider and the logs see. | [`option forwardfor`](https://docs.haproxy.org/3.4/configuration.html#4.2-option%20forwardfor) |
| DoQ cannot go through HAProxy. HAProxy is not "a packet-based load balancer : it will not see IP packets nor UDP datagrams"; its QUIC listeners and servers speak HTTP/3 only ("QUIC supports only h3 and hq-interop as ALPN"), and connection migration is unsupported. DoQ (`doq`, UDP 853) is reached directly, or through a layer 3/4 forwarder that keeps the client's source address: the gateway has no PROXY support on QUIC. | [Introduction, "What HAProxy is and is not"](https://docs.haproxy.org/3.4/intro.html), [`alpn`](https://docs.haproxy.org/3.4/configuration.html#5.1-alpn), [Configuration manual, HTTP/3](https://docs.haproxy.org/3.4/configuration.html) |
| An HAProxy HTTP/3 frontend can serve DoH clients and reach this gateway over HTTP/2 or HTTP/1.1; the gateway itself serves no HTTP/3. [INFERENCE] from the QUIC frontend being an HTTP frontend; not run. | same |

A gateway behind HAProxy, TLS terminated on the gateway (client sees the Resolver's certificate):

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

## RFCs read for this step

- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) sections 4.1, 4.2, 5.1.
- [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html) sections 4.1 to 4.3.
- [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html) sections 4.3.3 and 5.5.2 for the keepalive option.
- [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html) section 6.2.1.1 (query pipelining over TCP) and
  [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) section 6.1 (close_notify).
