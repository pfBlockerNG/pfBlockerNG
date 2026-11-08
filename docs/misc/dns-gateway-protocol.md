# DNS gateway decision protocol

Scope: the wire protocol between the Go connectivity layer (`pfb-dns`, the *gateway*) and the Python DNSBL
decider (`dns_proxy/pfb_dns_proxy.py --decision-fd N`, the *decider*): the only process besides the gateway that
pfB-DNS runs. Load when: changing either side or the frame format. Normative: where code and this page disagree, one
of them is a bug. Issues #3513, #3517, #3751.

The gateway owns every client-facing and Unbound-facing socket. The decider owns the DNSBL decision: for each client
query it either answers itself (block answer, FORMERR, SafeSearch rewrite) or asks the gateway to put a wire on the
way to Unbound and hand the reply back, so reply handling (CNAME validation, reply logging, the SafeSearch chase)
stays in the decider. The gateway never unpacks a DNS message, except with `--ddr` or `--dns-name`: it then parses the question of
each query and answers the ones at or under `resolver.arpa.` (DDR), and the `A` and `AAAA` queries for the DNS name (issue #3694), itself,
before the decider (see the `## DDR` and `## DNS name` sections of [dns-gateway-transports.md](dns-gateway-transports.md));
every other query goes to the decider as above.

## Transport

One `AF_UNIX`, `SOCK_STREAM` socketpair, created by the gateway. The gateway starts the decider as a child with the
other end inherited as file descriptor N (the gateway uses 3) and passes `--decision-fd N`, which is required: the decider
binds no DNS socket and has no flag for one. Its flags are `--decision-fd`, `--module-dir`, `--user` and the three mode flags
the gateway appends from its own flags of the same names: with `--no-module` (pfB-DNS with DNSBL off) it boots no module and
forwards every query, with `--no-module --reply-log` it also writes the DNS Reply log row of each reply. Otherwise it hosts
the module, and with `--observer` it makes the observer socket `pfb_upstream.sock` in `--module-dir`: Unbound's upstream
observer (`pfb_upstream_observer.py`) reports each raw upstream response there and the module logs an upstream block (mode
0600; a socket that cannot be made is one error line, and the decider serves without upstream-block detection).

## Frame

All integers are big-endian. The stream is a sequence of frames, in both directions, with no other framing:

| field | size | meaning |
|---|---|---|
| `len` | `u32` | bytes that follow: 5 + payload length |
| `type` | `u8` | see below |
| `id` | `u32` | the gateway's id for one client query; 0 for READY |
| payload | `len - 5` bytes | per type |

`len` is at least 5 and at most 131590 (5 + 1 + 1 + 255 + 1 + 255 + 2 + 65535 + 65535).

## Frame types

| type | direction | name | payload |
|---|---|---|---|
| `0x01` | gateway to decider | QUERY | `u8 transport` (TCP=0, UDP=1, DoT=2, DoH=3, DoQ=4), `u8 n` and `n` client-IP bytes, `u8 m` and `m` listener-IP bytes, `u16 k` and `k` interface UTF-8 bytes, then the client's DNS wire (may be empty) |
| `0x02` | decider to gateway | FORWARD | DNS wire to send to Unbound on behalf of that client |
| `0x03` | gateway to decider | REPLY | Unbound's reply wire for the last FORWARD of that id; empty = no reply (timeout, error) |
| `0x04` | decider to gateway | ANSWER | the final DNS wire to send to the client |
| `0x05` | decider to gateway | DROP | empty; send nothing to the client |
| `0x06` | decider to gateway | READY | empty, id 0; see below |

Types `0x00` and `0x07` to `0xFF` are unknown.

## One query

The gateway picks an id that is not in flight and sends QUERY. The decider then sends zero or more FORWARD frames,
each answered by exactly one REPLY before the next FORWARD of that id, and finally exactly one ANSWER or DROP.

```text
plain:       G: QUERY 7                                       (allowed name)
             P: FORWARD 7 <client wire>
             G: REPLY 7 <Unbound reply>
             P: ANSWER 7 <reply, relayed unchanged unless the module rewrote it>

decided:     G: QUERY 8                                       (blocked name)
             P: ANSWER 8 <block answer>                       (no FORWARD)

SafeSearch:  G: QUERY 9
             P: FORWARD 9 <client wire>
             G: REPLY 9 <Unbound reply>
             P: FORWARD 9 <chase query for the planted CNAME target>
             G: REPLY 9 <Unbound reply for the target>
             P: ANSWER 9 <CNAME + target records>

dropped:     G: QUERY 10                                      (a response packet, or fewer than 12 bytes)
             P: DROP 10
```

The first FORWARD of a query carries the client's own bytes; a later FORWARD is a query the decider built (the
SafeSearch chase: fresh DNS id, RD set, EDNS as the client's). The gateway forwards each as given, to Unbound, as that
client, and answers with Unbound's reply bytes, or an empty REPLY when there is none.

For a plain-UDP client the first FORWARD goes to Unbound over UDP only and its reply, truncated or not, is the REPLY as it
is (Unbound saw the client's own UDP size). Every FORWARD after the first within one QUERY goes over UDP and, when Unbound's
reply has TC set, again over TCP behind a stream PROXYv2 header for the same client; the REPLY is the TCP reply, or empty when
that failed. Only the SafeSearch chase issues a second FORWARD today: it must read the target's addresses whole, and a
truncated reply says nothing about them. For a stream client (TCP, DoT, DoH, DoQ) every FORWARD goes over UDP and, when
Unbound's reply has TC set, again over TCP behind a stream PROXYv2 header for the same client, so the client gets the
whole answer; a TCP or DoT client keeps one pool of upstream TCP connections for those retries, DoH and DoQ open one per
retry.

Over UDP the gateway keeps the first datagram that is Unbound's reply to the FORWARD and ignores every other one, such as a
late reply to an earlier query on a reused local port. A reply is a whole 12-byte DNS header with the query's id and QR set,
and the query's question: the same label boundaries and octets (ASCII name content case-insensitively), type and class.
Labels may contain any octet, including a literal dot; names are not flattened to dotted text. Compression pointers are
expanded with backward-only targets outside the header, a 127-pointer bound, and the 63-octet label/255-octet name limits.
A reply with no question counts only when its rcode is an error or it has TC set. Unbound sends bare FORMERR or NOTIMP for
some early refusals, including TC-set queries and IQUERY, STATUS and UPDATE; NOTIFY instead carries a question and REFUSED.
A reply with TC set counts even when it has lost all or part of its question, but a readable different question is rejected.
Other unreadable questions count only when the bytes after the header exactly echo the query's; parsing limitations of a
text-name library do not make a legal binary label unreadable.

The transport byte identifies the original client-facing listener, not the gateway-to-Unbound connection. Only UDP
has a size limit: an answer the decider builds itself is held to the client's advertised UDP size (512 without EDNS,
at most the 1232 the decider advertises; over it the answer is the question alone with TC set). Other transports are
sent whole up to 65535 bytes, the most one DNS message can carry; a longer one is the bare SERVFAIL, since the gateway
cannot frame it. A relayed reply is never cut: it is Unbound's own. A SafeSearch chase longer than 65535 bytes (the
client's EDNS options with a longer target name) is never forwarded: the client gets that same SERVFAIL.

Frames of different ids interleave freely and complete in any order; the decider never waits for one query before
reading the next. An id is in flight from the gateway's QUERY until the gateway has read the decider's ANSWER or DROP
for it. A gateway that stops waiting earlier (its own deadline, a client that went away) keeps the id reserved until
then; the late ANSWER or DROP is read and discarded. A late FORWARD for such an id is answered at once with an
empty REPLY and no exchange with Unbound takes place.

The gateway keeps at most 4096 ids reserved, in flight or abandoned. Live queries never reach that many (512 UDP,
512 DoH and DoQ, and 4 for each of 128 TCP and DoT connections), so the rest is room for abandoned ones; a decider that
never sends a final frame fills it. At the cap a new query is answered SERVFAIL by the gateway, with no QUERY sent,
nothing reserved is evicted, and one log line per burst says so; a final frame frees a place.

An unknown or finished id is not an error: a REPLY the decider is not waiting for (finished query, never-seen id,
or an id with no FORWARD outstanding) is ignored, and so is any frame the gateway receives for an id it no longer
tracks.

## READY and lifecycle

READY is the first frame the decider sends, once the module has booted (if there is one) and the observer socket is made (if asked for) (and, with
`--user`, after the privilege drop). The gateway starts serving clients on READY and not before; a QUERY sent earlier is read after it.

EOF from the gateway, including a frame cut half way through its header or payload, ends the session: the decider
cancels what is in flight (no ANSWER or DROP is sent), shuts the module down and exits 0. A peer that resets the
connection ends it the same way. EOF from the decider means it exited; the gateway treats that as failure.

## Protocol errors

These are fatal. The receiver logs the reason, closes the socket and stops; the decider exits 1 (its log line starts
`decision protocol error:`), the gateway exits non-zero:

- `len` below 5 or above 131590 (detected on the 4 length bytes, before any payload is read);
- an unknown type;
- a type that is only valid in the other direction: FORWARD, ANSWER, DROP or READY from the gateway; QUERY or
  REPLY from the decider;
- a QUERY with a transport byte outside 0..4, an empty client IP, or a missing/truncated client, listener or interface length/body;
- a QUERY whose id is already in flight;
- READY more than once, or with an id other than 0 or a payload;
- an ANSWER with an empty payload (a decider with nothing to send uses DROP);
- a FORWARD or ANSWER whose DNS wire is longer than 65535 bytes.

These are not, and the session goes on: a QUERY with invalid endpoint metadata is answered with DROP for that id.
This includes non-ASCII or invalid IP text, a prefix, zone, brackets, port or unspecified address; invalid UTF-8 or
control characters in the interface; and a nonempty interface without a listener IP. An empty listener and interface
mean unavailable. A QUERY whose DNS wire is empty or shorter than a header gets DROP too, as a response or a packet
that short is never answered; a FORWARD that arrives while the previous FORWARD of its id is still unanswered is ignored.

## Endpoint metadata

Client and listener IPs are independent canonical addresses: dotted-quad IPv4 or RFC 5952 IPv6, with mapped IPv4
unmapped, no zone, port, brackets or prefix. The decider validates and canonicalizes each with `ipaddress.ip_address`.
The client address retains the existing Group Policy and DNSBL logging meaning, including trusted DoH attribution.

The listener is the gateway's actual kernel receiving address, captured before PROXYv2 family normalization.
TCP/DoT use the accepted socket, DoH uses the underlying connection rather than a proxy destination or HTTP Host,
and DoQ uses QUIC's local address. Wildcard UDP sockets use destination ancillary data; unavailable destination
metadata stays empty, never `0.0.0.0` or `::`. Upstream sockets and DNS answer addresses are not receiving endpoints.

The interface is the description of the address owner, not packet ingress. Each query captures its label from an
immutable gateway address-map snapshot; later VIP moves or interface renames cannot reinterpret that event.
The root-owned configuration/control path supplies that map, including `Localhost` for loopback-owned VIPs.

## Logged transport

The decider passes the canonical name (`TCP`, `UDP`, `DoT`, `DoH`, `DoQ`) through the shim's `qstate.pfb_transport`.
The existing DNSBL writers append it at index 11 (after qtype at 10), and DNS Reply appends it at index 10 (after ISO
at 9). No prior column changes position. Readers accept historical rows without the column as `Unknown`; malformed
metadata is also `Unknown`, never arbitrary CSV text. Helpers without original listener metadata default to `Unknown`.
Consecutive DNSBL duplicate detection includes client, transport and receiving metadata, so different endpoints remain visible.

Standalone native Unbound uses `Unknown`: the supported
[`pythonmod/interface.i`](https://github.com/NLnetLabs/unbound/blob/master/pythonmod/interface.i) SWIG surface exposes
`module_qstate.reply` and `mesh_info.reply_list.query_reply`, but `comm_reply` exports only client address/family/port,
not `comm_point`, socket type, TLS or HTTP metadata. Neither client ports nor upstream connections prove the original
listener. The upstream observer report likewise lacks original listener metadata and logs `Unknown`. No query
correlation or port-based inference is performed.

Receiving IP/interface metadata follows transport without moving prior columns: DNSBL indexes 12/13 and DNS Reply
indexes 11/12. Unavailable values are empty in CSV and display **—** in Reports. Native Unbound and upstream observer
paths also leave these fields unavailable: their supported APIs do not prove the original receiving endpoint.

## Timeouts

- Unbound: the gateway's. It waits `--timeout` (default 5 s; the rc script never changes it) per exchange with Unbound and
  turns silence or an error into an empty REPLY.
- REPLY: the decider's guard against a gateway that never answers. A FORWARD with no REPLY within 10 s (twice the gateway's
  default `--timeout`; `UNBOUND_TIMEOUT` in `pfb_dns_proxy.py`) is treated as an empty REPLY, and a REPLY that arrives after
  that is ignored.
- A query as a whole: the gateway's. It sends SERVFAIL to the client if it has no decision within twice the timeout
  plus one second; the decider enforces no overall deadline.

## Limits

- Frames: 131590 bytes at most (above); DNS wire at most 65535 bytes, each IP text at most 255 bytes, interface UTF-8 at most 65535 bytes.
- In flight: the protocol sets no cap. The gateway bounds it through its own client limits; the decider starts one
  task per QUERY and keeps no queue.

Implementation: decider side `dns_proxy/decision_service.py` (framing and loop) and `serve_decisions()` in
`dns_proxy/pfb_dns_proxy.py`, tests `tests/dns_proxy/test_decision_service.py` and `test_decision_transport.py`; gateway side
`go/pfb_dns_gateway/decider.go` (the frames) and `plain.go` (the FORWARD rule), tests `decider_test.go`, `gateway_test.go`,
`client_transport_test.go` and `process_test.go` in that directory.

The client-facing transports beyond plain UDP and TCP (DoT, DoH, DoQ), the certificate they serve and how a client
address is decided on each are in [dns-gateway-transports.md](dns-gateway-transports.md).
