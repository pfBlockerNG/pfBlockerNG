# CrowdSec pfSense bouncer enforcement mechanics

## Outcome

The proposed dedicated CrowdSec path is on the right track and closely matches the official
pfSense integration. CrowdSec does not feed decisions through a general list-processing
pipeline. It owns two dedicated pf tables, installs hidden bidirectional block rules once, and
applies each decision delta directly with `pfctl -T add` and `pfctl -T delete`.

For pfBlockerNG, the smallest compatible architecture is therefore:

1. own dedicated IPv4 and IPv6 CrowdSec aliases/tables and firewall rules;
2. obtain an initial full decision snapshot, then periodic REST deltas;
3. apply validated additions/deletions directly to the live tables, outside normal feed
   download, parsing, suppression, reputation, and deduplication;
4. kill matching live states when a new ban must affect established connections;
5. fire a separate CrowdSec-only post-change hook after a successful delta; and
6. reconcile after process start and every pfSense filter reload.

This does **not** require gRPC or protobuf. The current official bouncer uses a long-running Go
process, but its "stream" is a timed sequence of HTTP REST requests, not a server-pushed or gRPC
stream. A persistent HTTP client may reuse its underlying connection; each response body is
still completed and closed before the next poll.

## Official pfSense ownership model

The current pfSense package creates two empty, persistent config aliases:
`crowdsec_blacklists` and `crowdsec6_blacklists`. Both are `host` aliases marked "DO NOT EDIT".
It writes them to `config.xml`, points the firewall bouncer's `blacklists_ipv4` and
`blacklists_ipv6` settings at them, and calls `filter_configure()` when installing or removing
the integration.

- [Alias definitions and installation wiring](https://github.com/crowdsecurity/pfSense-pkg-crowdsec/blob/649fc12ea7f6ef68b16be0851b6fa3c470e6a40d/security/pfSense-pkg-crowdsec/files/usr/local/pkg/crowdsec.inc)
- [Current pfSense package configuration UI](https://github.com/crowdsecurity/pfSense-pkg-crowdsec/blob/649fc12ea7f6ef68b16be0851b6fa3c470e6a40d/security/pfSense-pkg-crowdsec/files/usr/local/pkg/crowdsec.xml)

`crowdsec_generate_rules()` is registered through pfSense's `filter_rules_needed` hook. It
emits hidden `block drop ... quick` rules, optionally limited to selected interfaces:

| Family | Direction | Match |
| --- | --- | --- |
| IPv4 | inbound | `from <crowdsec_blacklists> to any` |
| IPv4 | outbound | `from any to <crowdsec_blacklists>` |
| IPv6 | inbound | `from <crowdsec6_blacklists> to any` |
| IPv6 | outbound | `from any to <crowdsec6_blacklists>` |

Logging, a PF tag, interface selection, and each address family are independently configurable.
The rules are intentionally separate from ordinary GUI rules.

### Surviving a pfSense filter reload

A pfSense filter reload empties alias-backed live tables. The current package handles this in
its `pfearly` callback by reading each CrowdSec table with `pfctl -T show`, registering a PHP
shutdown callback, then restoring the captured entries after the reload with batched
`pfctl -T add` calls through `xargs`. It avoids restarting the bouncer and avoids a file-based
time-of-check/time-of-use window.

That recent upstream mechanism is strong evidence that direct table ownership is correct, but
also that filter-reload survival is mandatory. A pfBlockerNG implementation must integrate with
the same reload lifecycle or provide an equivalent bounded reconciliation.

## Official decision transport

The current pfSense package ships firewall bouncer `v0.0.34`. That bouncer constructs
`go-cs-bouncer`'s `StreamBouncer`, starts it as a long-running process, and consumes the
`New`/`Deleted` arrays it emits.

- [Firewall bouncer v0.0.34 orchestration](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/4144555453620958398aee64253dfd90bbc1f698/cmd/root.go)
- [Stream client v0.0.16](https://github.com/crowdsecurity/go-cs-bouncer/blob/7f9da7f0265d77f216dc9c1952918ade8b634950/stream_bouncer.go)
- [Official remediation-component stream specification](https://docs.crowdsec.net/docs/v1.6/contributing/specs/bouncer_appsec_specs/#stream-mode-by-default)

The sequence is:

1. call `GET /v1/decisions/stream` with `startup=true` for the full current decision set;
2. switch to `startup=false`;
3. call the same endpoint on `update_frequency` ticks, 10 seconds by default;
4. close every response body after reading it; and
5. deliver the returned `new` and `deleted` arrays to the firewall backend.

Failed initial connection ends the bouncer unless `retry_initial_connect` is enabled. Later
poll failures are logged and the loop continues. TLS CA, client certificate/key, API-key auth,
and `insecure_skip_verify` are supported by the HTTP client.

No gRPC import, service definition, protobuf decision model, SSE endpoint, or long-held response
body exists in the inspected bouncer/API client. The supported interface is HTTP REST with JSON
models. gRPC/protobuf would require a new upstream-compatible protocol or a translating sidecar;
it is not a current LAPI optimization knob.

## Official PF delta application

The PF backend separates IPv4 from IPv6, defaulting to batches of 2,000 decisions. A commit
applies deleted decisions first, then additions:

- delete: `pfctl -t <table> -T delete <values...>`;
- add: `pfctl -t <table> -T add <values...>`; and
- startup/shutdown: flush each table.

- [PF backend batching and commit order](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/4144555453620958398aee64253dfd90bbc1f698/pkg/pf/pf.go)
- [PF table operations and state killing](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/4144555453620958398aee64253dfd90bbc1f698/pkg/pf/pf_context.go)

After adding decisions, the backend reads the PF state table. For a newly banned IP with an
existing state, it executes both incoming and outgoing `pfctl -k` forms. Updating only table
membership would otherwise leave established stateful connections alive.

The backend accepts only configured decision types (`ban` by default). It does no pfBlockerNG
canonicalization, suppression, reputation pass, or cross-list deduplication.

### Failure caveat

In bouncer `v0.0.34`, an individual failed PF batch is logged and processing continues. A normal
delta call does not itself prove that the live table reached the desired end state. The startup
full snapshot repairs state after a process restart, while the pfSense package separately
preserves tables across filter reloads.

A native implementation should keep the direct fast path but specify a cheap reconciliation
rule. It must not silently acknowledge a delta whose PF mutation failed. This is reliability
bookkeeping, not admission into pfBlockerNG's list pipeline.

## Log path

CrowdSec's official pfSense package offers a local compiled Log Processor. Its own documentation
also supports remediation-only pfSense connected to a remote Security Engine. For this effort,
the lighter boundary remains native pfSense/HAProxy/nginx syslog export to the remote collector;
parsing and scenarios run remotely.

- [Official pfSense deployment sizes and remote LAPI support](https://docs.crowdsec.net/docs/next/getting_started/install_crowdsec_pfsense/)

The LAPI bouncer endpoint is for retrieving decisions, not ingesting raw firewall/access logs.
Log acquisition transport and the exact remote CrowdSec acquisition configuration need their
own decision ticket.

## Coverage matrix

| Axis | Verified behavior |
| --- | --- |
| IPv4 / IPv6 | Separate aliases, tables, rules, and PF contexts |
| Initial state | `startup=true` full REST response; PF backend starts from flushed tables |
| Incremental state | Periodic `startup=false` response with `new` and `deleted` arrays |
| Addition / deletion | Direct batched `pfctl -T add` / `pfctl -T delete` |
| Existing connections | Newly banned matching states killed in both directions |
| Inbound / outbound | Four hidden quick block rules, two per family |
| Filter reload | Snapshot live tables before reload; restore afterward |
| Process restart | Flush, verify tables, then repopulate from startup full response |
| API failure | Initial failure optionally retries; later failures log and next tick continues |
| Protocol | HTTP REST/JSON; no official gRPC/protobuf decision stream found |
| Credentials | API key or mutual TLS; certificate verification on by default |
| Normal pfBlockerNG updates | No relationship in upstream; keep CrowdSec lifecycle separate |
| Log shipping | Not a LAPI decision operation; use a separate acquisition/syslog path |

## Consequences for the Wayfinder map

Lock these as fixed constraints:

- CrowdSec enforcement owns dedicated IPv4/IPv6 tables and rules.
- Decision changes bypass normal pfBlockerNG feed processing and deduplication.
- A successful delta is reflected immediately with direct PF operations.
- Existing matching PF states are handled explicitly.
- CrowdSec change hooks are a separate lifecycle and never fire for ordinary pfBlockerNG
  updates.
- Filter reload and process restart have explicit reconciliation paths.

Keep these as open decisions:

- short-lived polling versus a small resident worker, and the minimum supported cadence;
- whether HTTP connection reuse provides enough benefit to justify residency;
- exact behavior on partial PF mutation failure;
- same-IP multiple-decision deletion semantics from LAPI;
- CrowdSec-only hook payload, ordering, timeout, and failure behavior; and
- remote syslog/acquisition topology for pfSense, HAProxy, nginx, and pfBlockerNG events.
