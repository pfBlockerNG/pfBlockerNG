# Unbound mesh partitioning by pfBlockerNG Group Policy

## Outcome

Unbound has a native pre-resolution policy seam, but its Python module cannot control it.
`mesh_state_compare()` includes native client response-IP tags, tag actions/data, and view
identity. Those values are selected before `mesh_new_client()` finds or creates a mesh state
and before Python `operate()` runs. pfBlockerNG therefore cannot add its effective Group
Policy to mesh identity from `pfb_unbound.py` alone.

The selected fallback is a hybrid:

1. Keep the existing qstate-wide synthetic block when every requester visible at the
   decision point is blocked.
2. Resolve normally when at least one requester is allowed.
3. At every per-recipient reply callback, classify the callback's actual sender and replace
   only a blocked recipient's reply.
4. Apply the same recipient classification and replacement in the C message-cache callback,
   where `qstate` is absent.

This preserves one normal resolution for allowed recipients while preventing another
recipient's policy from choosing their reply. A mandatory implementation kill gate remains:
prove the previously tested recipient-local reply replacement mechanism without mutating the
shared mesh reply or the cached base reply.

A reply-only design was considered and rejected as the default. It is mechanically simpler,
but it forces Unbound to resolve every blocked name upstream unless a positive answer is
already cached. The hybrid retains today's cheap early finish for uniformly blocked states and
uses reply transformation only when normal resolution is necessary for an allowed recipient.
This ticket does not move SafeSearch: its current CNAME chase semantics are not equivalent to a
final reply rewrite. SafeSearch is nevertheless a required future Group Policy action and must
be designed into that implementation rather than kept permanently global.

## Evidence

### Native mesh identity is selected before Python

For Unbound 1.24.2, `mesh_state_compare()` compares uniqueness, priming and validation flags,
RD/CD, query name/type/class, and `respip_client_info`. The client comparison includes tag
lists, tag actions, tag-data identity, and view name. Unbound 1.22.0 has the same relevant
tag/action/data partition, with version-specific representation differences.

- [Unbound 1.24.2 mesh identity](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L94-L196)
- [Unbound 1.22.0 mesh identity](https://github.com/NLnetLabs/unbound/blob/0076736fc40298eb6252705e6e158462c6b24d06/services/mesh.c#L80-L180)
- [Query comparison and hashing](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/util/data/msgreply.c#L666-L731)

`mesh_new_client()` uses the query and native client information to find or create a state,
then attaches the requester. Python module execution happens inside that already-selected
state. Changing Python state cannot retroactively split it.

- [Client-to-mesh attachment](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L424-L530)
- [Mesh lookup and reply attachment](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L1870-L1970)
- [Mesh-state invariants](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.h#L173-L191)

The Python interface exposes `qstate.mesh_info.reply_list`, each reply's communication point,
and callback `repinfo`; it does not expose `module_qstate.client_info` or a trusted callback
before mesh attachment.

- [Python mesh/reply exposure](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/pythonmod/interface.i#L614-L642)
- [Exported `module_qstate` fields](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/pythonmod/interface.i#L776-L817)
- [Python callback bridge](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/pythonmod/interface.i#L1586-L1644)

### Reply callbacks are per recipient, but the reply is shared

Unbound walks the mesh reply list, invokes the in-place reply callback for that recipient,
encodes its packet, and sends it. Registering callbacks disables encoded-packet reuse, so the
callback timing and sender correlation fit recipient-specific policy.

The callback still receives the shared `reply_info *`; it does not automatically receive a
private deep copy. Any replacement adapter must prove that a blocked recipient cannot alter a
later allowed recipient's answer.

- [Per-recipient mesh fan-out](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L1425-L1554)

A requester can attach after Python first sees a state. Initial requester enumeration is
therefore an optimization, not an authorization snapshot. Callback-time classification of
`repinfo.addr` is authoritative.

### C message-cache hits bypass `operate()`

Unbound checks the C message cache before mesh attachment. On a hit, Python `operate()` does
not decide policy. The cache callback still receives `qinfo`, the cached reply, and `repinfo`,
but `qstate` is `None`.

- [Worker cache and mesh order](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/daemon/worker.c#L1891-L2009)
- [Cache callback and encoding](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/daemon/worker.c#L723-L914)
- [Official Python callback example](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/pythonmod/examples/inplace_callbacks.py#L77-L152)

`DNSMessage.set_return_msg()` requires a qstate, so its current use does not prove reply
construction in a cache callback.

- [Python response construction](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/pythonmod/interface.i#L1315-L1405)

Current qstate-wide NXDOMAIN and null/VIP blocks set `qstate.no_cache_store = 1`; synthetic
blocks therefore do not contaminate the C message cache. A future cache callback must likewise
leave the cached positive base answer unchanged.

### Client-controlled EDNS is not a policy identity

Unbound can mark registered EDNS options as non-aggregating, but the client supplies the
option before cache lookup and mesh attachment. Python cannot inject a trusted effective
policy at that point. Making every request unique would also discard safe same-policy sharing.

- [EDNS registration](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/util/module.c#L261-L292)
- [Unique-state decision](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/util/module.c#L362-L385)

## Selected fallback

### State entry

At each relevant `operate()` event, capture one immutable matcher/policy snapshot and inspect
all requesters currently attached:

- all blocked: build today's qstate-wide synthetic response and finish with
  `no_cache_store = 1`;
- any allowed: preserve or obtain the normal resolver response;
- mixed: never replace the shared qstate response.

An all-allowed observation is not frozen. A blocked requester may attach while recursion is
pending and must still be blocked by its eventual reply callback.

In the common uncached case, the first requester is the only attached requester when Python
first runs. If it blocks, the existing immediate synthetic response avoids upstream work. If it
allows, normal recursion is necessary for that recipient; any blocked requester that attaches
later is handled safely at fan-out.

### Recipient decisions across atomic swaps

Use one typed, generation-stamped recipient-decision cache. Its logical key is the queried
domain plus effective-policy identity; its value is explicit `allow` or the complete block
decision. An entry also carries the matcher/policy snapshot generation and any time-bound
validity needed by scheduled policy.

At reply time:

1. Derive the actual client from callback `repinfo` using existing `pfb_addr` precedence.
2. Resolve the client's effective-policy identity.
3. Use a matching, still-valid generation entry when present.
4. If the entry is missing or stale, capture the current immutable snapshot once, recompute
   the recipient decision entirely against it, and cache the result with that generation.
5. Preserve the base reply for `allow`; invoke the recipient-local replacement adapter for a
   block decision.

This makes absence mean “recompute,” not “allow.” An atomic data-structure replacement cannot
mix old policy membership with a new domain matcher in one decision.

The existing domain-only `decisionDB` may continue memoizing client-independent DNSBL matching
facts. The effective Group Policy action is a separate recipient decision; it must not turn the
domain-only memo into a first-client-wins cache.

### Required callbacks

| Reply source | Authoritative identity | Required behavior |
| --- | --- | --- |
| Resolved mesh reply | callback `repinfo` | Preserve allowed base; replace blocked recipient only |
| C message-cache hit | callback `repinfo`, `qstate=None` | Recompute/use recipient decision; never mutate cached base |
| Local reply | callback `repinfo` | Apply only policy semantics specified for local answers |
| SERVFAIL | callback `repinfo` | Preserve existing failure semantics; do not invent a block |

## Mandatory reply-isolation kill gate

Before production behavior changes, locate and execute the repository's previously tested
reply-copy/replacement mechanism, or prove an equivalent supported adapter. It must:

- construct exact NXDOMAIN, null, IPv4/IPv6 VIP, and ANY block shapes;
- work in resolved reply callbacks and cache callbacks with `qstate=None`;
- leave the shared mesh reply unchanged for a later allowed recipient;
- leave the cached base reply unchanged for a later cache consumer;
- preserve encoder metadata and set security status correctly for a synthetic answer;
- keep existing logging and feed/group attribution tied to the actual callback sender.

The owner reports that cache callback modification has already been implemented and tested.
No matching current-tree adapter was found during this research, so that environmental/history
claim remains **ASSUMED** until its executable artifact is located. Failure of this kill gate
routes back to native generated tags/views or an upstream/core pre-mesh hook; shared-object
mutation is not an acceptable fallback.

## Alternatives rejected for this ticket

### Generated access-control tags or views

Native tags/views can partition in-flight mesh states by effective policy before Python.
They require generated Unbound configuration, ownership/lifecycle work, module-order and
CE/Plus probes, and translation from native response-IP behavior to pfBlockerNG's qname DNSBL
semantics. They also do not remove the need to handle C-cache hits in a policy-aware callback.
This is larger and shallower than the selected Python reply seam.

### Unbound core hook

A trusted pre-cache/pre-mesh policy callback would provide the cleanest direct identity seam,
but requires an Unbound patch or upstream feature. It remains the escalation if recipient-local
reply replacement cannot be proven.

### Reply-only policy

Evaluating every recipient exclusively on the reply path would avoid mesh-list reasoning, but
would also resolve uniformly blocked names upstream. The selected hybrid gains the same
recipient correctness while preserving the existing early-block performance and privacy
property. The future Group Policy implementation must separately specify mixed-policy
SafeSearch because its CNAME redirect deliberately participates in resolution rather than
merely replacing the final packet.

## Platform assumptions and live probes

Netgate release documentation maps CE 2.8.0 to Unbound 1.22.0 and Plus 25.11 to Unbound
1.24.2. Netgate currently lists CE 2.8.1 and Plus 26.03.1 as supported releases. Exact packaged
versions, downstream patches, Python exposure, and generated configuration remain **ASSUMED**
until probed on both live appliances.

- [pfSense CE 2.8.0 release notes](https://docs.netgate.com/pfsense/en/latest/releases/2-8-0.html)
- [pfSense Plus 25.11 release notes](https://docs.netgate.com/pfsense/en/latest/releases/rn-plus-25-11.html)
- [Current pfSense versions](https://docs.netgate.com/pfsense/en/latest/releases/versions.html)

Required inventory:

```sh
pkg info unbound
unbound -V
unbound-checkconf /var/unbound/unbound.conf
grep -nE 'module-config|python-script|respip|response-ip|access-control-tag|access-control-view|view:' /var/unbound/unbound.conf
```

Required live matrix:

- allowed-first and blocked-late attachment to one in-flight query;
- mixed requesters sharing one normal resolution;
- positive C-cache hit with `qstate=None` for allowed and blocked clients in both orders;
- proof that a blocked callback cannot contaminate a later allowed reply;
- direct and CNAME-discovered matches;
- NXDOMAIN, null, IPv4/IPv6 VIP, and ANY block shapes;
- snapshot replacement between lookup and callback, proving stale/missing recipient decisions
  recompute against one current snapshot.

## Consequence for implementation

[pfb_unbound.py: make requester identity policy-partition aware](https://github.com/pfBlockerNG/pfBlockerNG/issues/1406)
should implement the selected hybrid reply seam, not attempt Python mesh partitioning. Its first
checkpoint is the reply-isolation kill gate above. Only after that proof may production and
test-first implementation proceed. SafeSearch policy behavior remains future feature scope, but
the recipient-policy interface must not encode an invariant that SafeSearch is always global.
