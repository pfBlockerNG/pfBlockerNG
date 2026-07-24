# Recipient-local DNSBL reply isolation in Unbound

Issue: [#1557](https://github.com/pfBlockerNG/pfBlockerNG/issues/1557)

## Verdict

Unbound 1.24.2 on pfSense CE 2.8.1 exposes recipient identity to resolved- and
cache-reply callbacks, and both callbacks can change encoded RR TTLs. It does
not expose a supported recipient-local way to replace RR payload bytes, RRset
references, or the complete `reply_info`.

The recipient-local replacement gate therefore fails: the current Unbound
Python API cannot replace an existing positive answer with a
recipient-specific DNSBL answer without modifying the shared reply object.
ADR-25 does not necessarily fail with it. A separate supported design can
avoid mixed-policy qstates instead of repairing their replies: partition mesh
states by policy-equivalence class, and prevent globally cached answers when
they could bypass an effective ACL stack's result for that name.

`DNSMessage.set_return_msg()` remains usable from `operate()` while a qstate
exists. That replaces the qstate-wide answer, which is suitable only when the
entire grouped request receives the same result. It does not solve a mixed
recipient decision. The cache callback has `qstate == NULL`, so it cannot use
that mechanism at all.

The result does not depend on observed mesh timing. Unbound's contract permits
multiple recipients on one mesh state; no experiment attempted to prove that
late attachment happens rarely or within a particular timing window.

## Scope

The live proof ran on:

| Component | Value |
| --- | --- |
| Appliance | pfSense CE at `192.168.57.10` |
| pfSense | 2.8.1 |
| Unbound | 1.24.2 |
| Python runtime | `python311-3.11.11` |
| pfBlockerNG | not installed |
| Probe date | 2026-07-22 |

The original task requested CE and Plus. A Plus run was attempted at
`192.168.57.11`, but SSH timed out. The user then explicitly accepted CE as
sufficient for this gate. No Plus conclusion is claimed.

## How the live proof was wired

The probe used the appliance's real resolver, cache, and upstream DNS. It did
not run a second resolver, replace the upstream, create a synthetic answer, or
use synthetic client identities.

The runner:

1. copied a temporary module to
   `/var/unbound/adr25_system_probe.py`;
2. copied `/var/unbound/unbound.conf` to a uniquely named backup;
3. changed `module-config: "iterator"` to
   `module-config: "python iterator"`;
4. appended:

   ```yaml
   python:
   python-script: adr25_system_probe.py
   ```

5. validated the result from `/var/unbound` with `unbound-checkconf`;
6. stopped the configured resolver with
   `unbound-control -c /var/unbound/unbound.conf stop`;
7. waited for its old PID to exit, then started
   `unbound -c /var/unbound/unbound.conf`;
8. queried ordinary names through `127.0.0.1:53` with bounded `dig` calls;
9. printed the module's event log; and
10. restored the original configuration byte-for-byte, removed the module and
    log, restarted normal Unbound, and verified DNS in an unconditional trap.

Because pfBlockerNG was not installed, its normal Unbound chroot runtime mounts
were absent. Embedded Python initially failed before module import with:

```text
python exception in Py_InitializeFromConfig: init_fs_encoding:
failed to get the Python codec of the filesystem encoding
```

The final runner temporarily reproduced only pfBlockerNG's canonical read-only
runtime mounts:

```text
/lib             -> /var/unbound/lib
/usr/local/bin   -> /var/unbound/usr/local/bin
/usr/local/lib   -> /var/unbound/usr/local/lib
```

It removed those mounts during cleanup. The host Python package was already
installed; no package was installed or upgraded.

After every run, these checks passed:

```text
no /var/unbound/unbound.conf.adr25-probe-backup
no /var/unbound/adr25_system_probe.py
no /var/unbound/adr25_probe_events.log
module-config: "iterator"
no temporary chroot runtime mounts
ordinary DNS query through 127.0.0.1 succeeds
```

## Callback coverage

The module inventoried the live binding and registered every callback family
available to `pfb_unbound.py` or potentially useful to this investigation:

```text
register_inplace_cb_query
register_inplace_cb_query_response
register_inplace_cb_edns_back_parsed_call
register_inplace_cb_reply
register_inplace_cb_reply_cache
register_inplace_cb_reply_local
register_inplace_cb_reply_servfail
```

`register_edns_option` was also present in the binding inventory. It registers
an EDNS option code; it is not a callback family.

The temporary module also logged `init_standard()`, `operate()`,
`inform_super()`, and `deinit()`. Every callback logged its inputs before any
change and its return state afterward.

## Ordinary-query traces

### Cold positive answer

The first `post.nl A` query produced:

```text
operate(MODULE_EVENT_NEW)
  -> inplace_query, one or more times as iterator recursed
  -> inplace_edns_back_parsed
  -> inplace_query_response
  -> operate(MODULE_EVENT_MODDONE)
  -> inplace_reply, recipient=127.0.0.1, qstate non-null
```

The wire answer was `NOERROR` with ordinary upstream A records.

### Warm positive cache answer

The immediately repeated `post.nl A` query produced only:

```text
inplace_reply_cache, recipient=127.0.0.1, qstate=none
```

The answer remained `NOERROR` with the cached A records. This confirms that
the positive-cache enforcement point has recipient identity but no qstate.

The cache is not client-specific. A controlled cross-client run first queried
`example.com A` from CE loopback, then queried the same name 17 seconds later
from CIVM2, whose address behind CE is `192.168.1.100`. The first request ran
the full chain:

```text
operate(MODULE_EVENT_NEW)
  -> inplace_query
  -> inplace_query_response
  -> operate(MODULE_EVENT_MODDONE)
  -> inplace_reply, recipient=127.0.0.1
```

The CIVM2 request produced only:

```text
inplace_reply_cache, recipient=192.168.1.100, qstate=none
```

It received the cached answer with 207 seconds remaining. A different client
address therefore does not cause `operate()` to run again.

### Early `no_cache_store`

A second A/B probe set `qstate.no_cache_store = 1` during
`MODULE_EVENT_NEW` for `iana.org`. Both consecutive queries then ran
`operate(MODULE_EVENT_NEW)` and `operate(MODULE_EVENT_MODDONE)`; both also ran
the outbound-query and query-response callbacks. On this path the flag
prevented storage of both the message answer and its RRsets, so the second
request resolved through the iterator again.

This matches the iterator contract: it calls `iter_dns_store()` only when
`qstate->no_cache_store` is false.

- [Unbound 1.24.2 iterator cache-store guard](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/iterator/iterator.c#L3308-L3315)

Setting the flag on the first resolution guarantees that later requests for
that name reach `operate()`. It does so at the cost of repeated
iterator/upstream work; an upstream forwarder may still answer from its own
cache. ADR-25 therefore needs the flag only when evaluation across the current
effective ACL stacks proves that caching the answer would be unsafe.

### Local answer

`localhost A` produced only `inplace_reply_local`, with recipient
`127.0.0.1` and `qstate=none`. The wire answer remained the normal
authoritative `127.0.0.1` response.

The SERVFAIL callback was registered but a SERVFAIL was not manufactured for
the final run. A deliberately broken-domain attempt created noisy iterator
traffic without adding evidence and was removed.

## Mutation experiments

### Correcting the flag vocabulary

An initial flag experiment used runtime `PKT_AA`, whose live value is `2`,
against `reply_info.flags`. That field contains wire-format DNS header bits.
The invalid experiment therefore changed the wire RCODE to SERVFAIL and was
discarded.

The corrected experiment changed the wire AA bit directly:

```text
reply_info.flags: 0x8180 -> 0x8580
```

The callback observed the new value, but the client still received
`qr rd ra`, without AA. The encoder did not re-read that header field after
the callback.

### Resolved-reply RR TTL

For a cold `example.com A` answer, `inplace_reply` changed all of:

```text
reply_info.ttl
reply_info.prefetch_ttl
packed_rrset_data.ttl
packed_rrset_data.rr_ttl[i]
```

to 42 seconds. The event log recorded the modified values before callback
return, and `dig` received:

```text
status: NOERROR
example.com.  42  IN  A  172.66.147.243
example.com.  42  IN  A  104.20.23.154
```

Therefore resolved-reply RR TTL mutation is consumed by the encoder.

### Positive-cache RR TTL

The first `iana.org A` query populated the cache without mutation. On the
second query, `inplace_reply_cache` received absolute cache TTL timestamps.
The probe set the reply, RRset, and per-RR timestamps to current time plus 42
seconds. `dig` received:

```text
status: NOERROR
iana.org.  42  IN  A  192.0.43.8
```

Therefore positive-cache RR TTL mutation is also consumed by the encoder.
This proves mutability, not ownership: the callback still holds Unbound's
borrowed cache-path object.

## Binding contract

The installed 1.24.2 SWIG binding exposes setters for metadata and per-RR TTL:

```python
packed_rrset_data.ttl = property(getter, setter)
RRSetData_RRTTL.__setitem__ = _set_data_rr_ttl
reply_info.ttl = property(getter, setter)
```

It exposes no supported setter for RR payload bytes or RRset references:

```python
class RRSetData_RRData:
    def __getitem__(self, index): ...

    # no __setitem__


class ReplyInfo_RRSet:
    def __getitem__(self, index): ...

    # no __setitem__
```

There is likewise no `_set_data_rr_data()` or `_rrset_rrsets_set()` function.
This is decisive for DNSBL replacement: changing an A/AAAA address, producing
NXDOMAIN, or installing a different RRset is not supported through these
in-place Python callback objects.

The C/Python bridge reinforces that boundary. It wraps callback arguments as
borrowed SWIG pointers and consumes the callback return only as a boolean; no
return position accepts a new `reply_info *` or encoded packet.

- [Unbound 1.24.2 Python callback bridge](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/pythonmod/interface.i#L1586-L1644)
- [Unbound 1.24.2 `DNSMessage.set_return_msg()`](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/pythonmod/interface.i#L1315-L1405)

## Shared-object and cache implications

For resolved answers, Unbound calls the reply callback once per recipient and
then encodes the supplied `reply_info *`. The surrounding mesh fan-out may use
that same reply for other recipients; callback registration disables encoded
packet reuse but does not allocate a private reply object.

- [Unbound 1.24.2 mesh reply fan-out](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L1425-L1554)

For positive-cache answers, Unbound passes `qstate == NULL` and the cache-path
reply object, then encodes it. A partial CNAME path may create an internal
copy, but the callback API does not grant ownership or accept a replacement.

- [Unbound 1.24.2 cache callback and encoder](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/daemon/worker.c#L723-L914)

Consequently, temporary mutation followed by restoration would rely on
undocumented sequencing and shared-state discipline. It is not an acceptable
recipient-isolation contract.

## Consequence for ADR-25

The supported paths are:

| Path | Can identify recipient? | Can replace full answer? | Scope |
| --- | --- | --- | --- |
| `operate()` with `set_return_msg()` | mesh/qstate view | yes | entire qstate |
| query-response callback | no final recipient-local output | no RR payload setter | shared resolution |
| resolved-reply callback | yes | no RR payload/RRset setter | borrowed mesh reply |
| cache-reply callback | yes | no qstate and no RR payload/RRset setter | borrowed cache reply |
| local/SERVFAIL reply callbacks | yes | no supported replacement | existing reply path |

ADR-25 may retain qstate-wide synthetic blocking only when the decision is
valid for every recipient attached to that state. If a mixed-policy qstate is
possible, the Python module must allow the original query to resolve; current
in-place callbacks cannot safely substitute different DNSBL answers per
recipient.

A complete mixed-recipient implementation would therefore require an upstream
Unbound capability that provides either an owned per-recipient reply/packet
replacement or a supported way to split recipients into independently
answered states. Current Python callback ABI provides neither. Preventing
incompatible recipients from sharing a state avoids that requirement.

## Follow-up: preventing incompatible mesh attachment

[The query-coalescing follow-up](1557-unbound-query-coalescing-settings.md)
found a supported native partitioning seam that narrows the resolved-answer
problem without disabling safe concurrency.

Unbound includes response-policy client information in its mesh-state key. It
compares tag lists, tag actions/data, and views before allowing two otherwise
identical requests to share a state. Distinct `access-control-tag` or
`access-control-view` assignments can therefore keep different DNS Policy
Layer equivalence classes out of the same mesh state while still allowing
requests within one class to coalesce. This is an explicit source contract,
not a timing observation.

- [Unbound 1.24.2 client-policy mesh comparison](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L94-L152)
- [Unbound 1.24.2 mesh-state key](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L160-L195)

Views/tags do not partition the global positive message cache. The live
cross-client test confirmed that a warm answer bypasses `operate()` even when
the second client address differs. ADR-25 must therefore combine mesh-key
partitioning with early `no_cache_store` whenever the current policy classes
can produce different cache-visible results for the queried name. Whether a
permit is redundant is evaluated through the requesting ACL's remaining active
layers; merely mentioning an already-permitted name does not disable caching.
Because the positive cache is shared, the final storage decision must also keep
one ACL's cached pass from bypassing another ACL's effective block.

That combination uses only supported contracts:

1. distinct effective policy classes cannot share a top-level mesh state;
2. recipients within one class necessarily receive the same decision;
3. answers that differ across current policy classes cannot enter the global
   Unbound cache; and
4. `operate()` can safely install one qstate-wide synthetic answer.

It preserves coalescing inside a policy-equivalence class. Its remaining cost
is repeated iterator/upstream work only for names with class-dependent
results.

## Agreed ADR-25 integration boundary

The owner accepted the following design boundary after this proof:

- Unbound configuration assigns one opaque ACL tag to each complete
  policy-equivalence class and maps client IP ranges to that tag. The class
  encodes the complete ordered stack, including parallel policies at one
  level; tag-list ordering is not used to encode policy order.
- Python receives the tag-to-stack mapping and policy manifest. It keeps
  matcher data segmented by Feed Group and evaluates an explicit, always-active
  Baseline layer using the same evaluator as user Group Policies.
- PHP remains the authority for native pfSense Schedules. A schedule transition
  produces a new Group Policy generation containing the complete set of active
  Group Policy instance IDs. Python intersects that set with each tag's static
  ordered/parallel topology and atomically replaces its effective-policy map
  without rebuilding unchanged policy definitions or feed matcher data.
- A Group Policy instance owns its User Group audience, one optional Schedule
  reference, Feed Group selection, DNS rules, and global level/order. The static
  tag topology is PHP's compiled representation of User Group/IP applicability.
  If identical policy content applies to different audiences under different
  Schedules, those are distinct Group Policy instances with distinct IDs.
- After Python acknowledges the new generation, PHP flushes Unbound's complete
  message and RRset cache with `unbound-control flush_zone +c .`. Configuration
  saves that change client-to-class mappings retain the existing full Unbound
  configuration reload path. Targeted Lock/Unlock continues to flush only the
  affected domain. The general zero-downtime cache-flush correction is tracked
  by [issue #1615](https://github.com/pfBlockerNG/pfBlockerNG/issues/1615).
- Cache flushing is live resolver maintenance: no resolver restart, processing
  pause, or request-list flush is required. The small generation-swap-to-flush
  interval remains, but stale policy answers are no longer retained for an
  arbitrary upstream TTL.

This architecture does not require recipient-local reply replacement or
global `unique_mesh`. It also does not require Python to evaluate pfSense
Schedules or maintain a replacement DNS cache.
