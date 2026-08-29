# Unbound 1.24.2 query-coalescing controls

## Question

Can a supported Unbound setting stop simultaneous client requests from being
aggregated onto one mesh state?

## Conclusion

Upstream Unbound 1.24.2 has one indirect all-request mechanism: load the
supported `subnetcache` module. In Unbound 1.24.2,
initializing that module sets the process environment's `unique_mesh` flag for
all queries. The incoming-client path then skips lookup of an existing mesh
state, creates a new one, and marks it unique. Consequently, two client
requests do not share their top-level mesh state, even when their name, type,
class, and relevant flags are identical.

That mechanism is unavailable in the tested pfSense CE binary: its live
`unbound -V` linked-module list does not contain `subnetcache`. Upstream builds
expose that module only when compiled with `CLIENT_SUBNET`
([`modstack.c` lines 151-177](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/modstack.c#L151-L177)).
Therefore **the tested CE 1.24.2 binary has no supported configuration setting
that disables top-level client mesh aggregation globally**.

There is no documented `unique-mesh:` configuration directive in 1.24.2.
`unique_mesh` is an internal module-environment field. The supported
configuration surface that enables it is `module-config` with `subnetcache`
immediately before `iterator`, for example:

```text
server:
    module-config: "subnetcache validator iterator"
```

This is not a free switch. It enables the EDNS Client Subnet module and its
specialized cache behavior. NLnet Labs explicitly warns that ECS segregation
impacts resolution and cache-response performance, recommends enabling it only
where ECS is required, and states that subnet-cache data does not interact with
`serve-expired` or `prefetch`. Using it solely to obtain unique mesh states
would therefore be a supported mechanism used for a purpose broader than its
documented operational intent.

The history confirms that intent. `unique_mesh` entered upstream in commit
[`b0fd814`](https://github.com/NLnetLabs/unbound/commit/b0fd8149755ea159cd37be0ba6d2547a5092f818),
whose subject is “Merge EDNS Client subnet implementation.” The same commit
added the field, CLIENT_SUBNET build/configuration machinery, the mesh lookup
branch, and the subnet module assignment. It was infrastructure for ECS, not
a hidden general-purpose configuration directive.

## 1. Default and version availability

The finding is against the exact source commit tagged
[`release-1.24.2`](https://github.com/NLnetLabs/unbound/tree/f6269baa605d31859f28770e01a24e3677e5f82c).
The default module stack is `validator iterator`, so `subnetcache` and unique
client mesh states are not enabled by default
([`config_file.c` lines 321-333](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/util/config_file.c#L321-L333)).
The 1.24.2 manual documents `subnetcache` as a valid module that must appear
immediately before `iterator`; it gives `validator iterator` as the default
stack
([`unbound.conf.5.in` lines 2297-2335](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/doc/unbound.conf.5.in#L2297-L2335)).
It also says that ECS support must be compiled into the daemon
([lines 4700-4715](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/doc/unbound.conf.5.in#L4700-L4715)).

There is no separate configuration-file setting for `unique_mesh` in this
release. The field exists in the C `module_env`
([`module.h` lines 535-556](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/util/module.h#L535-L556));
the 1.24.2 configuration parser and documented directives do not expose it.
The Python binding exposes an explicit subset of `module_env` fields and omits
`unique_mesh`
([`interface.i` lines 714-761](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/pythonmod/interface.i#L714-L761)),
so `pfb_unbound.py` cannot simply assign the internal flag either.

## 2. Exact semantics

During `subnetcache` initialization, Unbound states "Create new mesh state for
all queries", sets `env->unique_mesh = 1`, and registers ECS with
`no_aggregation = 1`
([`subnetmod.c` lines 270-283](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/edns-subnet/subnetmod.c#L270-L283)).

The generic uniqueness test returns true whenever `env->unique_mesh` is set.
Without that global flag, it returns true only when the incoming request
contains a registered EDNS option marked `no_aggregation`
([`module.c` lines 362-385](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/util/module.c#L362-L385)).

For each incoming client request, `mesh_new_client()`:

1. computes `unique` with that test;
2. calls `mesh_area_find()` only when `unique` is false;
3. creates a new state when no existing state was selected; and
4. marks the new state unique.

See
[`mesh.c` lines 424-493](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L424-L493).
The unique marker points at the state itself
([lines 1041-1045](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L1041-L1045)),
and mesh comparison considers that marker before query identity
([lines 160-195](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L160-L195)).

Therefore, on a build containing `subnetcache`, this fully prevents multiple
front-end client requests from sharing one top-level mesh state. It does
**not** make Unbound's caches private, stop parallel/concurrent processing, or
promise that internal dependency/subquery states and lower-level work cannot
be shared. Those forms of concurrency are harmless for the recipient-list
problem being investigated.
The conclusion needed by ADR-25 is limited to client reply attachment: a
top-level client qstate no longer holds a reply list for multiple client
requests.

## 3. Runtime and performance caveats

The manual says ECS answers use a specialized cache while authorities that do
not support ECS fall back to the regular cache
([`unbound.conf.5.in` lines 4724-4729](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/doc/unbound.conf.5.in#L4724-L4729)).
It then warns that ECS client-space segregation impacts both resolution and
cache-response performance, recommends the module only when that behavior is
required, and says the module does not interact with `serve-expired` or
`prefetch`
([lines 4740-4757](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/doc/unbound.conf.5.in#L4740-L4757)).
The implementation emits corresponding warnings when either feature is enabled
([`subnetmod.c` lines 236-246](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/edns-subnet/subnetmod.c#L236-L246)).

Independent inference from the client-path source: disabling top-level
aggregation increases concurrent mesh-state count and removes the normal
deduplication of identical in-flight client work. Capacity and upstream-query
impact should be measured under expected concurrency before treating this as a
production architecture.

ECS exposure is separately controlled. Without a matching
`send-client-subnet` address or `client-subnet-zone`, the manual says other
authorities do not receive client subnet information
([`unbound.conf.5.in` lines 4760-4776](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/doc/unbound.conf.5.in#L4760-L4776)).
That limits accidental disclosure, but it does not remove the module's unique
mesh and cache/runtime consequences.

## 4. Related settings and mechanisms that do not solve it

- `client-subnet-always-forward: yes` is not the uniqueness switch. It changes
  ECS address checking and skips regular-cache lookup; default is `no`
  ([`unbound.conf.5.in` lines 4780-4790](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/doc/unbound.conf.5.in#L4780-L4790)).
  Loading `subnetcache` sets `unique_mesh` regardless of this value.
- `num-threads` and `so-reuseport` do not guarantee isolation. A mesh is
  thread-specific
  ([`mesh.c` lines 36-43](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L36-L43));
  more threads create more such partitions, while `so-reuseport` only *may*
  distribute incoming queries more evenly
  ([`unbound.conf.5.in` lines 655-672](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/doc/unbound.conf.5.in#L655-L672)).
  Requests landing on the same worker may still aggregate.
- Views, response-IP tags, RD/CD flags, and query identity can prevent sharing
  when their mesh keys differ, but identical keys still share. The comparison
  logic documents and implements those distinctions
  ([`mesh.c` lines 94-109](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L94-L109),
  [`mesh.c` lines 160-195](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/services/mesh.c#L160-L195)).
  `access-control-tag` and `access-control-view` are supported ways to assign
  those distinctions by client netblock
  ([`unbound.conf.5.in` lines 1525-1559](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/doc/unbound.conf.5.in#L1525-L1559)).
  A unique view or tag set per policy-equivalence class would prevent clients
  in different classes from attaching to one state without ECS. It would not
  stop two requests in the same class from sharing, so it is partitioning, not
  a global no-aggregation switch. That may still be sufficient when all
  clients in a class must receive the same DNS policy decision.
- Cache TTL, cache sizing, `prefetch`, and `serve-expired` govern answer-cache
  behavior, not whether two outstanding client requests attach to one mesh
  state. The live CE probe also confirmed that the positive message cache is
  shared across clients: after loopback populated `example.com`, CIVM2 at
  `192.168.1.100` received `inplace_reply_cache` only and did not enter
  `operate()`. Setting `qstate.no_cache_store` during the first
  `MODULE_EVENT_NEW` prevented that path on repeated queries, but also caused
  repeated iterator/upstream work.
- A module can register an EDNS option with `no_aggregation=True`; the Python
  binding exposes that flag
  ([`interface.i` lines 1546-1558](https://github.com/NLnetLabs/unbound/blob/f6269baa605d31859f28770e01a24e3677e5f82c/pythonmod/interface.i#L1546-L1558)).
  However, uniqueness then applies only when the client request actually
  carries that EDNS option, because `unique_mesh_state()` scans the incoming
  option list. It is not a configuration-only, all-client solution.

## Recommendation for ADR-25

Do not design CE around `subnetcache`-driven unique mesh: the tested binary did
not compile that module. The only no-ECS supported configuration seam found is
mesh-key partitioning with distinct ACL tags or views. Assign one opaque tag to
each complete DNS Policy Layer equivalence class and map client IP ranges to
that tag. This keeps different classes in different qstates while preserving
safe same-class aggregation; parallelism and lower-level resolver sharing stay
enabled.

Tags do not partition Unbound's global positive cache. During `operate()`, the
policy evaluator first determines whether a permit changes the result of the
requesting ACL's complete active stack. It must suppress cache storage whenever
the resulting answer could bypass any effective ACL stack; otherwise it may
retain caching. After PHP changes the active policy generation, it must wait
for Python's applied-generation acknowledgement and then clear the global
message and RRset cache with
`unbound-control flush_zone +c .`.

This removes any need for strict one-request-per-top-level-qstate, ECS,
`unique_mesh`, an Unbound patch, or a Python-owned DNS cache.
