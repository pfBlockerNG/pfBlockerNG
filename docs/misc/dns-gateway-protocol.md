# DNS gateway decision protocol

Scope: the wire protocol between the Go connectivity layer (`pfb_dns_gateway`, the *gateway*) and the Python DNSBL
decider (`dns_proxy/pfb_dns_proxy.py --decision-fd N`, the *decider*). Load when: changing either side or the frame
format. Normative: where code and this page disagree, one of them is a bug. Issue #3513.

The gateway owns every client-facing and Unbound-facing socket. The decider owns the DNSBL decision: for each client
query it either answers itself (block answer, FORMERR, SafeSearch rewrite) or asks the gateway to put a wire on the
way to Unbound and hand the reply back, so reply handling (CNAME validation, reply logging, the SafeSearch chase)
runs exactly as in the Python-only proxy.

## Transport

One `AF_UNIX`, `SOCK_STREAM` socketpair, created by the gateway. The gateway starts the decider as a child with the
other end inherited as file descriptor N (the gateway uses 3) and passes `--decision-fd N`. In that mode the decider
binds no DNS socket; `--listen`, `--port` and `--dot` are rejected (exit 2). It takes the Python proxy's mode flags: with
`--no-module` (pfB-DNS with DNSBL off) it boots no module and forwards every query, with `--no-module --reply-log` it also
writes the DNS Reply log row of each reply. Otherwise it hosts the module, and with `--observer` it makes the
observer socket `pfb_upstream.sock` in `--module-dir` exactly as the Python-only proxy does: Unbound's upstream observer
(`pfb_upstream_observer.py`) reports each raw upstream response there and the module logs an upstream block (mode 0600;
a socket that cannot be made is one error line, and the decider serves without upstream-block detection).

## Frame

All integers are big-endian. The stream is a sequence of frames, in both directions, with no other framing:

| field | size | meaning |
|---|---|---|
| `len` | `u32` | bytes that follow: 5 + payload length |
| `type` | `u8` | see below |
| `id` | `u32` | the gateway's id for one client query; 0 for READY |
| payload | `len - 5` bytes | per type |

`len` is at least 5 and at most 65796 (5 + 1 + 255 + 65535).

## Frame types

| type | direction | name | payload |
|---|---|---|---|
| `0x01` | gateway to decider | QUERY | `u8 n`, then `n` bytes of client IP text, then the client's DNS wire (may be empty) |
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

Frames of different ids interleave freely and complete in any order; the decider never waits for one query before
reading the next. An id is in flight from the gateway's QUERY until the gateway has read the decider's ANSWER or DROP
for it. A gateway that stops waiting earlier (its own deadline, a client that went away) keeps the id reserved until
then; the late ANSWER or DROP is read and discarded. A late FORWARD for such an id is answered at once with an
empty REPLY and no exchange with Unbound takes place.

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

- `len` below 5 or above 65796 (detected on the 4 length bytes, before any payload is read);
- an unknown type;
- a type that is only valid in the other direction: FORWARD, ANSWER, DROP or READY from the gateway; QUERY or
  REPLY from the decider;
- a QUERY whose payload is empty, has `n = 0`, or has fewer than `n` bytes after the `n` byte;
- a QUERY whose id is already in flight;
- READY more than once, or with an id other than 0 or a payload;
- an ANSWER with an empty payload (a decider with nothing to send uses DROP);
- a FORWARD or ANSWER whose DNS wire is longer than 65535 bytes.

These are not, and the session goes on: a QUERY whose IP text is not a valid IP address (not ASCII, `999.1.1.1`,
`192.0.2.10/24`) is answered with DROP for that id; a QUERY whose DNS wire is empty or shorter than a header gets
DROP too, as the Python-only proxy never answers a packet that short; a FORWARD that arrives while the previous
FORWARD of its id is still unanswered is ignored.

## Client IP text

The `n` bytes are the canonical text of the address the gateway puts in the PROXYv2 header: dotted-quad IPv4 or
RFC 5952 IPv6, an IPv4-mapped IPv6 address already unmapped to IPv4, no zone id, no port, no brackets, no prefix.
The decider checks it with Python's `ipaddress.ip_address` and hands the text, unchanged, to the module as the
client address (Group Policy bypass and DNSBL logging key on it).

## Timeouts

- Unbound: the gateway's. It waits `--timeout` per exchange with Unbound and turns silence or an error into an empty
  REPLY.
- REPLY: the decider's guard against a gateway that never answers. A FORWARD with no REPLY within twice the decider's
  own `--timeout` is treated as an empty REPLY, and a REPLY that arrives after that is ignored.
- A query as a whole: the gateway's. It sends SERVFAIL to the client if it has no decision within twice the timeout
  plus one second; the decider enforces no overall deadline.

## Limits

- Frames: 65796 bytes at most (above); the DNS wire in QUERY, FORWARD, REPLY and ANSWER is at most 65535 bytes, the
  client IP text at most 255.
- In flight: the protocol sets no cap. The gateway bounds it through its own client limits; the decider starts one
  task per QUERY and keeps no queue.

Implementation: decider side `dns_proxy/decision_service.py` (framing and loop) and `serve_decisions()` in
`dns_proxy/pfb_dns_proxy.py`, tests `tests/dns_proxy/test_decision_service.py`; gateway side
`go/pfb_dns_gateway/decider.go`, tests `decider_test.go`, `gateway_test.go` and `process_test.go` in that directory.

The client-facing transports beyond plain UDP and TCP (DoT, DoH, DoQ), the certificate they serve and how a client
address is decided on each are in [dns-gateway-transports.md](dns-gateway-transports.md).
