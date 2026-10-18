# DNS gateway encrypted transports

Scope: DoT, DoH and DoQ of the Go connectivity layer (`go/pfb_dns_gateway`, issue #3513), the certificate they serve,
how a client address is decided on each, and what a front end such as HAProxy can and cannot do for them. Load when:
changing `tlsconfig.go`, `dot.go`, `doh.go`, `doq.go`, `pfb_doq_probe`, or putting a front end in front of the gateway.
The decision protocol with the Python decider is in [dns-gateway-protocol.md](dns-gateway-protocol.md).

## Certificate

DoT, DoH and DoQ serve the DNS Resolver's certificate, read from `config.xml` exactly as
`dns_proxy/pfsense_dot.py` reads it: `unbound/sslcertref` names a top-level `<cert>`; its `crt` and `prv` are
base64 PEM; the CAs its `caref` leads to follow the certificate, nearest first, and a missing CA or a loop ends the
chain. `unbound/tlsport` is the DoT port when it is a port (1 to 65535), else 853. `unbound/enablessl` is not read:
the gateway flags decide. PKCS#8, PKCS#1 and SEC1 keys load; an encrypted key is refused (a daemon cannot be asked
for a passphrase).

`config.xml` is root-only, so it is read, and every TLS socket bound, before the privilege drop. It is not read at all
unless `--dot`, `--doh-listen` or `--doq-listen` is given. When one is given and the certificate is unusable the reason
is logged once (`TLS transports disabled: <file>: <reason>`), no TLS listener is bound and plain UDP and TCP keep
serving. This differs on purpose from the Python `--dot`, which exits 1: under `daemon -r` a broken certificate must
not crash-loop the only :53 listener.

## Listeners

| Transport | Flags | Socket | TLS | Cap |
|---|---|---|---|---|
| DoT | `--dot`, on every `--listen` address at the config's tlsport | TCP | 1.2+ | 128 connections, shared with plain TCP, checked at accept before the handshake; handshake 10 s |
| DoH | `--doh-listen` (repeatable), `--doh-port` (4443), `--doh-trusted` (repeatable) | TCP, HTTP/1.1 and HTTP/2 (ALPN `h2`, `http/1.1`) | 1.2+ | 128 connections of their own, closed at accept; read-header 10 s, idle 30 s, 100 streams per connection |
| DoQ | `--doq-listen` (repeatable), `--doq-port` (853) | UDP, ALPN `doq` | 1.3 | 128 connections of their own (excess closed with `DOQ_EXCESSIVE_LOAD`), 100 streams, idle 30 s |

A listener that cannot be bound is logged and skipped. Readiness lines, before `ready upstream`, in the order udp+tcp,
dot, doh, doq: `listening dot|doh|doq <host>:<port>`; an IPv6 address is bracketed (`[::1]:853`).

Every transport goes through the same path as plain DNS: Resolver ACL (deny: nothing is answered; refuse: REFUSED built
by the gateway), then the decider, then PROXYv2 to Unbound with the client in the header.

## Who is the client

| Transport | Client address |
|---|---|
| DoT | the TCP peer |
| DoQ | the QUIC peer (after the handshake) |
| DoH, peer not in `--doh-trusted` | the TCP peer. PROXY bytes are not parsed (the TLS handshake fails) and `X-Forwarded-For` is ignored |
| DoH, peer in `--doh-trusted` | the source of its PROXY header if it sent one, else the TCP peer; then, if the request has `X-Forwarded-For`, the rightmost entry of the **last** such header when it parses as an IP address, else unchanged |

A `--doh-trusted` value is a prefix (host bits masked) or a bare address (/32, /128). One that is neither is logged and
ignored; it never stops the gateway.

PROXY header library behaviour (go-proxyproto v0.15.0), pinned by tests: version 1 and version 2 headers from a trusted
peer are accepted; a LOCAL command and an AF_UNIX source leave the client as the TCP peer; a malformed header, or a
PROXY command with an unspecified address family, ends the connection. The header sent on to Unbound always names the
resolved client and the local listener, never the front end's own addresses.

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
- Other malformed streams (FIN before the announced length, more bytes than announced, a second query, no FIN within
  the idle timeout, fewer bytes than a DNS header, a response instead of a query) are reset with `DOQ_PROTOCOL_ERROR`
  and the connection goes on. RFC 9250 4.3.3 lists most of these as connection-fatal with the same SHOULD; the gateway
  resets the stream only, so one bad stream cannot cancel the other queries of the connection.
- ACL deny or a decider DROP: the stream is cancelled with `DOQ_REQUEST_CANCELLED`.

## DoH details (RFC 8484)

`/dns-query` only (else 404). GET: `dns` is base64url, padding tolerated, the standard alphabet is a 400. POST:
`Content-Type: application/dns-message` (else 415). 405 for other methods, 413 above 65535 bytes (a POST from its
Content-Length, before the body is read), 400 for a query that cannot be decoded or is shorter than a DNS header or is
a response. Answers are 200 `application/dns-message` with `Cache-Control: max-age=0`: RFC 8484 5.1 says a server that
"customizes a response based on the client's identity" must not allow global reuse, and the DNSBL answer does.
ACL deny, and a decider DROP, abort the request (the client sees a reset). A reply with TC set by Unbound's UDP
answer is asked for again over TCP.

## Front ends: what HAProxy can do (verified against the HAProxy 3.4.7 manual, 2026-10-17)

The same statements are in the 3.2 and 3.3 manuals.

| Claim | Source |
|---|---|
| `send-proxy-v2` is a server option usable in `tcp` and `http` mode: HAProxy then puts a PROXYv2 header at the start of every connection to the server, carrying the client's addresses (and ALPN when negotiated). | [Configuration manual, `send-proxy-v2`](https://docs.haproxy.org/3.4/configuration.html#5.2-send-proxy-v2) |
| The PROXY header is "the block of connection information the connection initiator prepends at the beginning of a connection", and "the receiver MUST NOT start processing the connection before it receives a complete and valid PROXY protocol header". On a re-encrypting server line the header therefore comes first and the TLS handshake follows, which is the order the gateway expects (PROXY, then TLS, then HTTP). | [PROXY protocol specification](https://www.haproxy.org/download/3.4/doc/proxy-protocol.txt), section 2 |
| A receiver "MUST not try to guess whether the protocol header is present or not" and "SHOULD ensure proper access filtering so that only trusted proxies are allowed to use this protocol": hence `--doh-trusted`. | PROXY protocol specification, section 2 |
| For HTTP, a proxy that "do have a complete understanding of the transported protocol" "MUST use the facilities provided by this protocol to present the client's address" (here HTTP, so `X-Forwarded-For`) and "MUST NOT implement [the PROXY] protocol on multiplexed connections". HAProxy reuses an idle backend connection only for requests with the same source and destination addresses and proxy protocol, so the connection-level PROXY source stays one client's; the per-request header refines it. [INFERENCE] for the last clause. | PROXY protocol specification, section 2; [`http-reuse`](https://docs.haproxy.org/3.4/configuration.html#4.2-http-reuse) |
| `option forwardfor` appends `X-Forwarded-For` "at the end of the existing header list" as its own header line, and "the server must be configured to always use the last occurrence of this header only", because the client may have sent one. This is why the gateway takes the last header, and its rightmost entry (a proxy such as nginx that appends to one list is read the same way). | [`option forwardfor`](https://docs.haproxy.org/3.4/configuration.html#4.2-option%20forwardfor) |
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

Not verified by a run: the interplay with a live HAProxy. The PROXY-before-TLS order on an `ssl` server line rests on
the specification text above, and the gateway's side of it (PROXY header, then TLS, then HTTP, per request) is
exercised with hand-built headers in `doh_test.go`.

## RFCs read for this step

- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) sections 4.1, 4.2, 5.1.
- [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html) sections 4.1 to 4.3.
