# ADR-25 recipient-safe DNSBL enforcement

Issue: [Finalize ADR-25 recipient-safe enforcement specification](https://github.com/pfBlockerNG/pfBlockerNG/issues/1616)

## Goal

Enforce the complete DNS Policy Layer graph compiled by ADR-55 for each DNS
recipient without allowing one effective policy, cache entry, query state, or
generation to determine another recipient's answer. Preserve zero-downtime
DNSBL data publication and same-policy query coalescing on supported pfSense CE
and Plus systems.

This specification supersedes the unimplemented phase plan in ADR-25. ADR-54
still owns normalized Feeds and Feed Groups. ADR-55 still owns User Groups,
ordered DNS Policy Layers, Baseline, validation, migration, and UI. ADR-25 owns
the compiled handoff from that graph into Unbound and `pfb_unbound.py`.

## Fixed constraints

- DNSBL Group Policy v1 is DNS-only. DNSBLIP, IP rules, DNS redirect, DoT/DoQ,
  DoH-IP, and IP Group Policy never enter the recipient-policy vector.
- Recipient identity is the actual callback recipient, never the first or head
  reply-list node.
- Recipient-local reply replacement is unavailable in supported Unbound 1.24.2
  Python callbacks. Resolved and positive-cache callbacks expose borrowed reply
  state and no supported payload/RRset replacement; cache callbacks also have
  no qstate. Shared-reply mutation and restore is forbidden.
- Different static policy topologies must not share a top-level mesh state.
  Identical topologies may coalesce; distinct topologies that currently filter
  to the same effective vector may remain conservatively separated.
- Unbound's positive message and RRset caches are global. An answer that could
  let one active class bypass another class's result for the same policy-
  relevant name must not be stored.
- PHP owns native pfSense Schedule evaluation, selector/alias resolution,
  configuration validation, migration, Unbound configuration, and cache flush.
  Python does not parse pfSense Schedules or `config.xml`.
- One query observes one immutable static policy/content snapshot and one
  acknowledged active-ID generation. Publication never exposes a mixed graph.
- Baseline is explicit, always active, always last, and evaluated by the same
  layer evaluator as an upper Group Policy.
- There is one global order of upper Group Policies. Multiple matching User
  Groups are ORed and a Policy is deduplicated by immutable ID. “Parallel”
  combination means all decision producers inside one Policy layer contribute
  to that layer's fixed precedence; v1 has no equal-rank cross-Policy union.
- Configuration fields remain behind registered `PfbConfig` structural roots.
  No direct config-path access is introduced.
- Configuration saves that change recipient-to-class mappings use the existing
  full Unbound configuration-reload path. Feed/content-only and Schedule-boundary
  changes remain zero-downtime data/generation swaps.
- All waits are bounded. A failed candidate never replaces the last coherent
  live generation.
- Package downgrade is unsupported. Recovery uses the pre-upgrade native
  pfSense configuration backup; no inverse converter or legacy mirror exists.
- Compatibility is capability-tested, not selected by CE/Plus version branches.

## Decisions

### 1. Compiled inputs and ownership

ADR-55 publishes one validated candidate from the `feed_model` and
`group_policy` structural roots. ADR-25 consumes two atomic files under the
existing DNSBL publication lock.

The **static policy manifest** contains:

- schema version and immutable configuration/content generation;
- every opaque ACL-tag class and its complete ordered upper-Policy ID vector,
  followed by Baseline;
- complete immutable Policy definitions and typed provenance;
- Feed-Group-segmented matcher inputs and policy-scoped compiled views for
  domain/regex/TLD/TOP1M/IDN/CNAME/No-AAAA/SafeSearch/DoH-hostname decisions;
- response and logging settings; and
- the manifest/raw-generation references needed to rebuild one frozen Python
  snapshot.

The **active generation** contains only its schema version, a monotonically
advancing generation, the complete set of active upper-Policy instance IDs,
and the static-manifest generation it targets. Omission means inactive. Baseline
is implicit and cannot be disabled.

Both formats are strict JSON with exact field types, duplicate rejection,
bounded collections/strings, unknown-version rejection, and no credentials.
Writers stage, flush, fsync, rename, then signal. Python parses and builds off
the live snapshot, swaps one reference atomically, and acknowledges only the
generation it actually installed.

Static policy/content changes publish a new static manifest through the
existing DNSBL reload sentinel and applied marker. A Schedule boundary may
publish only a new active generation when the static generation is unchanged.
An active generation targeting an unknown static generation is rejected and
never acknowledged.

### 2. Deterministic policy-equivalence classes

PHP resolves every valid v1 selector against one coherent native alias-table
snapshot. It partitions IPv4 and IPv6 address space at every selector boundary,
derives each segment's complete ordered static Policy topology before
enabled/Schedule filtering, appends Baseline, then minimizes
adjacent/equivalent segments to non-overlapping CIDRs. Unmatched recipients map
to the Baseline-only topology.

Every distinct complete topology receives one opaque Unbound ACL tag. The tag
is deterministically derived from the canonical ordered Policy-ID topology,
uses only Unbound-safe characters, exposes no Policy/User Group names, and is
collision-checked before publication. Equal topologies share a tag. Tags stay
stable across content and Schedule generations that do not change topology;
they are compiler artifacts, not public configuration identity.

Generated Unbound configuration declares the tags and maps the complete,
non-overlapping client CIDRs to them. Tag list order never encodes Policy order.
Overlapping User Groups therefore combine before ACL emission; Unbound never
resolves policy precedence from access-control line order. A recipient outside
all explicit selectors still receives the Baseline-only tag.

Changes to User Groups, selectors, native alias membership, Policy audiences,
Policy order, or any other vector-defining field rebuild the classes and use a
full Unbound configuration reload. Empty live alias expansion is a valid
no-match. Transient alias read failure retains the last coherent class map;
confirmed deletion invalidates affected upper Policies as ADR-55 specifies.

### 3. Effective generation derivation

PHP evaluates optional native Schedules using pfSense local-time semantics,
including start-inclusive/end-exclusive boundaries. It publishes the complete
active upper-Policy ID set at startup, after relevant saves, and at every next
native Schedule boundary. Missed boundaries collapse to the current complete
state; they are not replayed.

Python validates that every active ID exists in the targeted static manifest.
For each ACL class it filters the static ordered vector by the active set and
appends Baseline, interns equal resulting vectors, builds all derived indexes
off to the side, then swaps the complete effective map once. Query threads see
the old map or new map, never partial activation.

After the exact generation is acknowledged, PHP executes
`unbound-control flush_zone +c .` once to clear both message and RRset caches.
The flush is live resolver maintenance: no Unbound restart, DNSBL processing
pause, or request-list flush. A later generation supersedes queued older work;
acknowledgement and cache flush remain monotonic and idempotent.

On publish, parse, derivation, or acknowledgement failure, the last coherent
effective map stays live, a typed durable error is opened, and the operation
returns failure. A bounded acknowledgement timeout never claims the new state
is active. If the matcher swap is acknowledged but cache flushing fails, the
new map stays live while convergence remains failed and bounded retry continues;
success is never reported. Restart/reload reconstructs current static and
active state before acknowledging it.

### 4. Layer evaluation

For the ACL tag attached to the current qstate, Python evaluates its current
effective vector in global Policy order:

1. Evaluate every matching producer in the current layer under ADR-55's fixed
   intra-layer precedence.
2. A winning Permit, Deny, synthetic response, No-AAAA action, or reached
   `Bypass all` is terminal for the complete stack.
3. A complete non-match advances to the next layer.
4. Baseline is always evaluated last by the same evaluator.

Feed/ABP, TOP1M, SafeSearch/DoH, user domain/regex, TLD, IDN, CNAME, No-AAAA,
response, logging, and HSTS behavior remain exactly as fixed by ADR-55. A
Policy disabling a feature does not suppress Baseline; only an earlier terminal
opposite decision does. CNAME targets are evaluated only by layers with CNAME
Validation enabled. The winning Policy/Group/Feed/rule attribution is retained.

The evaluator is pure over one frozen snapshot, effective vector, normalized
query name/type, observed CNAME chain, and transient override state. The same
entry point serves `operate()`, the decision-query channel, and focused tests;
callbacks do not carry a second policy implementation.

### 5. Mesh and positive-cache safety

Distinct ACL-tag state participates in Unbound's top-level mesh key. Because
one tag represents one complete static topology, `operate()` may install one
qstate-wide synthetic answer: global active-ID filtering gives every recipient
attached to that state the same current effective vector.

Before resolution, Python determines whether storing the base answer could
bypass any currently active ACL class for the policy-relevant name/query shape.
If classes can produce different cache-visible outcomes, it sets
`qstate.no_cache_store = 1` during `MODULE_EVENT_NEW`. This suppresses message
and RRset storage. If every active class produces the same cache-safe outcome,
normal Unbound caching remains enabled. Permit evaluation includes the
requesting class's remaining layers; merely matching an early Permit does not
prove the final base answer is globally safe.

Resolved, cache, local, and SERVFAIL callbacks may attribute/log the actual
recipient but never replace or temporarily mutate reply payloads. A positive
cache hit is valid only when the storage invariant proves the base reply safe
for all active classes. Observing a violating cache hit is an invariant breach:
the callback leaves borrowed reply state untouched, records a critical typed
event, and requests a full cache flush. The individual query is allowed rather
than corrupting shared state or crashing the resolver.

Every acknowledged static/content/Schedule generation that can change a
terminal result receives the full `flush_zone +c .` invalidation. Targeted
Lock/Unlock keeps its existing validated single-domain plus `www` sibling
flush when no generation-wide change occurred.

### 6. Transient controls

The legacy configured `pfb_gp` bypass list migrates atomically under ADR-55 to
`Migrated DNSBL Bypass` plus one upper `DNSBL: Bypass all` Policy. Enabled and
disabled legacy state is preserved; empty legacy configuration creates neither
record. Successful migration retires legacy config/runtime reads. Malformed or
conflicting legacy data aborts the whole candidate.

`python_control addbypass` and `removebypass` remain transient runtime
operations, not configuration or migration input. They become a generation-
safe recipient override keyed by canonical IP, with the current bounded expiry
semantics. A matching active override acts as a terminal Permit-all before the
compiled vector. Control publication and acknowledgement are atomic and
monotonic; restart discards transient overrides as today. Add/remove/expiry
flushes affected cache state before acknowledgement can report convergence.
Global `disable`/`enable` retains its current control meaning and cannot publish
a half-applied Policy generation.

### 7. Failure, rollback, and observability

- Strict validation failure, unknown IDs, generation mismatch, unreadable
  alias state, or build failure leaves the last coherent snapshot active.
- A missing/corrupt static manifest at cold start leaves policy enforcement
  unavailable but does not crash Unbound; the failure is loud and durable.
- A missing/corrupt active generation at cold start activates Baseline only
  after validating the static manifest, opens a durable error, and never guesses
  Schedule state.
- Config reload failure keeps the previous running Unbound configuration.
- Cache-flush failure keeps the new acknowledged matcher state but marks
  convergence failed and retries boundedly; operators see that stale cache may
  remain. It never falsely records success.
- Rollback republishes a previously validated immutable static generation plus
  a fresh monotonic active generation; generation numbers never move backward.
- Runtime events record action, Policy ID/name snapshot or Baseline, matched
  origin/Group/Feed/rule, response reason, recipient class, and static/active
  generations. Secrets and raw credentials are forbidden.
- Notification producers keep their own domain state and delivery cursor when
  needed to suppress unchanged repeats. Emission is a one-way handoff: producers
  never query, mutate, dismiss, or otherwise use the notification as storage.
  Live generation, pending generation, last acknowledgement, cache-flush status,
  alias expansion, and recovery remain producer-owned status.

### 8. Compatibility and release boundary

Fresh configurations with only Baseline preserve current DNSBL decisions,
except ADR-55's explicitly approved TOP1M precedence correction. Existing
Feed/ABP matching and response shapes remain byte/semantically equivalent when
the effective Policy vector is equivalent.

Migration is one native backup, one validated candidate graph, and one atomic
config commit. No legacy and normalized runtime union exists. Package downgrade
is unsupported and receives release warning plus backup-recovery guidance.

The design uses supported ACL-tag mesh partitioning and `no_cache_store`. It
does not require Unbound core patches, ECS/subnetcache solely for
`unique_mesh`, views, recipient-local reply mutation, a Python-owned Schedule
engine, or a Python-owned DNS cache.

### 9. Implementation graph

Implementation is delivered through the linked execution tickets below. Each
ticket owns one coherent seam, includes test-first red-to-green evidence, and
is blocked by every prerequisite named in its issue relationship.

1. [**Compile ADR-55 User Groups and DNS Policy Layers**](https://github.com/pfBlockerNG/pfBlockerNG/issues/1621) — configuration,
   migration, UI, selector/Schedule compiler, policy-scoped content, and the
   validated static/dynamic ADR-25 handoff.
2. [**Load and evaluate compiled DNS Policy Layers**](https://github.com/pfBlockerNG/pfBlockerNG/issues/1617) — strict Python manifest
   model, frozen policy snapshot, one shared layer evaluator, and query-channel
   behavior.
3. [**Partition Unbound by recipient policy class**](https://github.com/pfBlockerNG/pfBlockerNG/issues/1620) — deterministic ACL tags,
   non-overlapping client mappings, configuration reload boundaries, and
   actual-recipient class lookup.
4. [**Enforce recipient-safe DNSBL cache behavior**](https://github.com/pfBlockerNG/pfBlockerNG/issues/1618) — qstate-wide enforcement
   inside a class, cross-class `no_cache_store` analysis, callback invariants,
   and cache-hit safety.
5. [**Apply policy generations and transient recipient overrides**](https://github.com/pfBlockerNG/pfBlockerNG/issues/1619) — native
   Schedule transitions, atomic active-ID swap/acknowledgement, full cache
   invalidation, control compatibility, provenance, and CE/Plus live gates.

The first ticket depends on the landed normalized registry foundation. The
second depends on the first. The third may proceed after the first and joins
the second before enforcement. The fourth depends on the second and third. The
fifth depends on the fourth. The final ticket owns integrated acceptance, not
another implementation of earlier seams, and also depends on
[Flush Unbound cache after zero-downtime DNSBL generations](https://github.com/pfBlockerNG/pfBlockerNG/issues/1615).

## Acceptance criteria

- Static/dynamic schemas reject malformed, hostile, duplicate, oversized,
  secret-bearing, unknown-version, unknown-ID, and cross-generation inputs
  without changing the live snapshot.
- Address/network/alias selectors across IPv4 and IPv6 compile into complete,
  non-overlapping ACL mappings. Overlaps, multiple audiences, deduplication,
  order, Baseline-only recipients, empty aliases, and confirmed deletion are
  pinned. Content and Schedule-only changes preserve ACL tags/configuration.
- Every ADR-55 intra-layer precedence collision and every cross-layer terminal/
  fallthrough case has a non-vacuous test. Baseline equivalence is frozen before
  behavior edits and passes unchanged afterward.
- Two recipients with different static topologies never share a top-level
  qstate or one terminal decision; recipients with equal topologies may
  coalesce. Distinct topologies that filter to the same effective vector may
  remain separated.
- Cold/warm, first-requester order, late attachment, positive-cache, local,
  SERVFAIL, NXDOMAIN, null, IPv4 VIP, IPv6 VIP, AAAA/NODATA, ANY, CNAME, DNSSEC,
  and encoder-metadata paths preserve reply ownership and recipient attribution.
- Unsafe cross-class answers set `no_cache_store` before storage; safe common
  answers remain cacheable. A cache-hit invariant breach never mutates borrowed
  reply state.
- Startup, configuration reload, Feed-content change, selector/alias change,
  Schedule boundary, active-ID mismatch, rapid successive generations, timeout,
  failed flush, rollback, and restart recovery preserve atomic old-or-new state.
- `addbypass`/`removebypass`/expiry and global enable/disable remain bounded,
  acknowledged, restart-safe, and cache-coherent.
- Migration covers absent, enabled, disabled, duplicate, malformed base64,
  invalid IP, conflict, injected write failure, idempotent re-entry, and native
  backup recovery. No partial config or legacy/normalized runtime union appears.
- Runtime logs/notices contain complete typed provenance and generation data but
  no secret canary. Every negative assertion has a canary-shaped fixture.
- Focused PHP, Python, integration, UI Tier-A/Tier-B, and smoke suites pass.
  Representative current CE and Plus systems prove ACL-tag partitioning,
  Schedule boundaries, callback-time multiple recipients, positive-cache safety,
  zero-downtime generation swap, and full cache invalidation.
- Canonical repository gates and independent review pass for every execution
  ticket; final integrated smoke runs only after rebase onto current `devel`.

## Out of scope

- Feed/Feed Group normalization, catalog work, external-content scheduling, or
  Category Blocking internals owned by ADR-54.
- Redesigning ADR-55's User Group, Policy, Baseline, UI, precedence, validation,
  or migration contracts.
- IP Group Policy, policy-scoped firewall rules, IP bypass, or policy-aware
  DNSBLIP in v1.
- DHCP/static-hostname/MAC/DUID selectors before their separate CE/Plus and
  ISC/Kea gate.
- GeoIP policy axes, a warning/click-through page, or new client identity.
- Unbound patches, shared-reply mutation, ECS solely for `unique_mesh`, a custom
  scheduler, or a replacement DNS cache.
- Persisting the full traversed Policy stack per query; the generation/vector
  and provenance shape must permit the Triangulator to add it later.
- Supported package downgrade or inverse conversion.

## Open forks

None.
