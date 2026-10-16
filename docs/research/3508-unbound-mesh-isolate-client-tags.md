# Unbound patch: isolate in-flight queries by client tag

Issue: [DNSBL python group policy CIDR](https://github.com/pfBlockerNG/pfBlockerNG/issues/3508)

## Problem

Unbound coalesces identical in-flight client queries onto one mesh state. A
state is keyed on query name, type, class, the RD and CD flags, the
priming/validation flags, the ECS `unique` marker, and the client info
(tags, tag actions, tag data, view)
([`mesh_state_compare()` and `client_info_compare()`](https://github.com/NLnetLabs/unbound/blob/d648eac68d7765440207f68077f96675f5bb36cc/services/mesh.c#L94-L196)).
Only the client that creates the state reaches `pfb_unbound.py` `operate()`.
Every client that attaches while the state is in flight receives the same
answer.

pfBlockerNG's Group Policy bypass decides per client IP. When a bypassed
client and a blocked client ask the same question at the same moment, the
first one decides for both: a blocked client can receive the real answer, and
a bypassed client can receive a block.

The client info that would separate them is built only when response-ip or
RPZ is configured, and only for A, AAAA and ANY queries
([`worker_handle_request()`](https://github.com/NLnetLabs/unbound/blob/d648eac68d7765440207f68077f96675f5bb36cc/daemon/worker.c#L1956-L1972)).
HTTPS, SVCB, TXT, MX, SRV, CNAME, PTR and NS queries, all of which
`pfb_unbound.py` blocks, are never separated by any configuration.

| Mechanism | Separates in-flight queries | Limitation |
|---|---|---|
| `access-control-tag` / `access-control-view` | A, AAAA, ANY only | Needs `respip` or RPZ active |
| `subnetcache` (`unique_mesh`) | All types | Not compiled into pfSense's Unbound (`SUBNET` port option off) |
| EDNS option with `no_aggregation` | All types | Only when the client itself sends the option |
| `module_env.unique_mesh` | All types | Not exposed to Python |

The pfSense CE build used for the evidence reports
`Linked modules: dns64 python dynlib respip validator iterator`.

## Patch

A new `server:` option, off by default:

```text
mesh-isolate-client-tags: <yes or no>
```

When enabled, `worker_handle_request()` also builds the client info when the
matched access-control element carries tags or a view, for every query type
and whether or not response-ip or RPZ is configured. Clients whose elements
carry different tags or views then never share a mesh state. Clients with the
same tags and view still coalesce.

The full diff, against Unbound `master` at `d648eac`, is in
[`3508-unbound-mesh-isolate-client-tags.patch`](3508-unbound-mesh-isolate-client-tags.patch).
The core change:

```c
if(((worker->daemon->use_response_ip || worker->daemon->use_rpz) &&
    (qinfo.qtype == LDNS_RR_TYPE_A ||
    qinfo.qtype == LDNS_RR_TYPE_AAAA ||
    qinfo.qtype == LDNS_RR_TYPE_ANY)) ||
    (worker->env.cfg->mesh_isolate_client_tags && acladdr &&
    (acladdr->taglist || acladdr->view))) {
```

The rest is option plumbing in the usual places: `config_file.h` field,
`config_file.c` default plus `S_YNO`/`O_YNO`, lexer token, parser rule,
fast-reload `COPY_VAR_int`, `unbound.conf.rst`, and `example.conf.in`.

### Why a client-info change and not a new key field

The mesh key already compares client info, `mesh_copy_client_info()` already
copies it into each state, and fast reload already handles it. The only gap
is that the worker does not build it. Building it covers every query type
with one condition and no new comparison code.

### Side effects with the option enabled

- **Respip.** Unchanged. `apply_respip_action()` in the worker and the mesh,
  and `respip_operate()`, all return early for types other than A, AAAA and
  ANY.
- **RPZ.** Tag-filtered RPZ NSDNAME and NSIP triggers (`rpz.c`, the iterator
  callbacks) now see the client tags for every query type. They previously
  treated non-address queries as untagged. This applies the RPZ zone's tag
  filter as configured, so it is a correction, but it is a behavior change
  and belongs in the release notes.
- **DNS64.** Its sub-queries inherit the parent's client info through
  `attach_sub`, so they are separated by class as well.
- **Cost.** Untagged clients: one extra branch per query. Tagged clients: one
  regional copy of the tag list, tag actions and view name per mesh state
  (`mesh_copy_client_info()`), and no coalescing across different tag sets.
  Same-class coalescing, cache lookups, and outbound query deduplication are
  unchanged; the proof below shows one upstream query for two isolated states.
- **Caches.** Not partitioned. A module that produces client-specific answers
  must still keep them out of the shared message and RRset caches.

## Proof

The harness is
[`3508-mesh-harness.py`](3508-mesh-harness.py).
It builds a throwaway configuration with a Python module that bypasses
`127.0.0.2` (tagged `bypass`) and answers NXDOMAIN to every other client.
A forwarder stub answers after one second, so the queries overlap in flight.
Each upstream answer carries a sequence number. Clients send A, TXT and HTTPS
queries for the same name 50 ms apart.

Build: Unbound `master` `d648eac` plus the patch, with `--with-pythonmodule
--with-libevent`. `make unittest && ./unittest` reports `1317093 checks ok.`;
`unbound-checkconf -o mesh-isolate-client-tags` prints `yes`; the value
`maybe` fails with `expected yes or no.`.

`BYPASS_NO_CACHE=1` makes the module set `qstate.no_cache_store = 1` for
bypassed queries. A cell lists the result for the blocked client `127.0.0.3`;
the bypassed client `127.0.0.2` received the real answer in every run.

| Case | isolate=no | isolate=yes | isolate=no + no-cache | isolate=yes + no-cache |
|---|---|---|---|---|
| Bypass first, blocked attaches | **leak** (real answer) | NXDOMAIN | **leak** | NXDOMAIN |
| Blocked first, bypass attaches | NXDOMAIN | NXDOMAIN | NXDOMAIN | NXDOMAIN |
| Two blocked clients | one state, NXDOMAIN | one state, NXDOMAIN | one state, NXDOMAIN | one state, NXDOMAIN |
| Bypass resolves, blocked asks later | **leak** (cache) | **leak** (cache) | NXDOMAIN | NXDOMAIN |

Each row held for A, TXT and HTTPS. Only the last column is leak-free. The
blocked-first row cannot show the opposite failure here because the module
finishes immediately; `pfb_unbound.py` also blocks at `MODULE_EVENT_MODDONE`
on a CNAME target, where an attached bypassed client would be blocked, and
isolation removes that case the same way.

## pfBlockerNG integration (after Unbound ships the option)

1. **Capability.** Emit the option only when the installed Unbound accepts
   it (`unbound-checkconf -o mesh-isolate-client-tags` succeeds). An
   unknown option is a fatal configuration error.
2. **Tags.** One `define-tag` per policy class. For bypass: one tag on every
   bypass IP or CIDR via `access-control-tag`.
3. **ACL action.** A tag on a netblock with no `access-control` creates an
   `allow` element (`acl_list.c`, `acl_find_or_create_str2addr()`). Each
   tagged netblock must also get an explicit `access-control` that repeats
   the action pfSense would otherwise apply to it, so tagging never widens
   access.
4. **Nested ACLs.** Any pfSense ACL element more specific than a bypass
   netblock must carry the same tag, or its clients fall back to the
   untagged class.
5. **Cache.** `pfb_unbound.py` sets `qstate.no_cache_store = 1` at
   `MODULE_EVENT_NEW` for every bypassed query. The iterator skips all
   message and RRset stores for that state (`iterator.c`, every
   `iter_dns_store()` call is guarded), so a bypassed answer, including
   its CNAME chain, never reaches a blocked client through the cache.
   Bypassed clients still read answers cached by blocked clients, which are
   always safe for them because synthetic blocks are never cached.
6. **Decision.** Python cannot read the tags (`client_info` is not exposed
   in `interface.i`), but it does not need to: with isolation every client
   on a state is in the same class, so the existing client-IP match on the
   first reply-list entry is correct.

## Upstream route

Submit the patch to
[NLnetLabs/unbound](https://github.com/NLnetLabs/unbound) with a `tdir`
test modelled on the harness (Python module plus a delaying upstream).
pfSense picks it up through the `dns/unbound` port once a release carries
it.
