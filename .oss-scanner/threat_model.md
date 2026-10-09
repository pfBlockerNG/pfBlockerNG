# Threat model

## What this project does

pfBlockerNG is a package for the pfSense firewall. It downloads IP and domain blocklists
(feeds), normalizes them, and enforces them through `pf` aliases and firewall rules (IP) and
through the Unbound DNS resolver (DNSBL). It runs as root on FreeBSD; there is no
unprivileged split. Only `src/` ships. Everything else (`tests/`, `scripts/`, `stubs/`,
`legacy/`, `.github/`) is development tooling.

## Where untrusted input enters

Ranked by exposure:

1. **DNS queries from LAN clients.** `src/usr/local/pkg/pfblockerng/pfb_unbound.py` runs
   inside Unbound as a Python module and sees every query name, type and client address.
   Any client that can reach the resolver is untrusted.
2. **The DNSBL block page.** `src/usr/local/www/pfblockerng/www/index.php` and
   `dnsbl_default.php` are served without authentication by a dedicated lighttpd instance on
   the DNSBL VIP. The Host header, URI, Referer and User-Agent are attacker-controlled.
3. **Feed contents.** Feeds are downloaded from third parties, often over plain HTTP, and
   may be compressed (gzip, zip, 7z, tar). Treat every byte as hostile: parsing, archive
   extraction, normalization (`pfb_feed_normalize.py`, `pfblockerng.inc`, `pfblockerng.sh`,
   `list_scripts/`) and anything later built from feed data (aliases, Unbound zone data,
   regex rules, shell command lines).
4. **Data rendered in the web UI.** Log lines, alert data and feed entries that originate
   from items 1 to 3 are displayed on the Alerts, Reports and Log pages. Stored XSS through
   these paths is in scope.
5. **The authenticated web UI** (`src/usr/local/www/pfblockerng/*.php`, widgets, wizards).
   Assume an attacker who can make a logged-in administrator's browser send requests
   (CSRF, reflected XSS), or a pfSense user with only some pfBlockerNG page privileges trying
   to escalate.
6. **XMLRPC HA sync** (`pfblockerng_sync.php` and the sync code in `pfblockerng.inc`), which
   pushes configuration to a peer firewall.

## Out of scope / by design

- An administrator with full pfBlockerNG access running code as root. Custom hooks
  (`pfblockerng_hooks.php`, `pfblockerng_edit_hooks.php`), custom feed URLs and list
  scripts are administrator features; executing them is intended. Injection is still in
  scope when a value an administrator would reasonably treat as data (a feed name, a
  description, a domain) breaks out into a shell, PHP, or Python context.
- A feed provider choosing to block or allow arbitrary domains or IPs. Feeds are trusted
  to decide *what* is listed, not trusted to be well-formed.
- pfSense itself, Unbound, lighttpd, and PHP, except where pfBlockerNG misuses them.
- Linux-only behaviour of the test container. Production is FreeBSD: `/bin/sh` is ash,
  `tar` and `unzip` are libarchive, and tools live under `/usr/local/bin`.
- Code under `tests/`, `scripts/`, `stubs/`, `legacy/`, `docs/`, and `.github/`.

## How to exercise it

- `pytest` runs the Python suite, including `pfb_unbound.py` with a stubbed `unboundmodule`.
- `vendor/bin/phpunit` loads the real `pfblockerng.inc` with pfSense doubles from
  `tests/php/bootstrap.php`.
- `shellspec --shell /usr/bin/dash` runs the POSIX shell specs under `tests/shell/`.
- `tests/smoke/` needs a live pfSense appliance and does not run in this image.

## Severity

- **Critical:** unauthenticated remote code execution as root; for example a crafted DNS
  query, block-page request, or feed entry that reaches a shell, `eval`, or a file write
  in an executable location.
- **High:** unauthenticated persistent denial of service of DNS resolution or the
  firewall (crash or hang of Unbound through `pfb_unbound.py`, or a feed that wedges the
  update cron); arbitrary file write or read as root from feed data; stored XSS that
  reaches an administrator from LAN or feed input; silently disabling enforcement (a
  crafted feed or query that bypasses blocking for entries that should match).
- **Medium:** CSRF or reflected XSS against an administrator; privilege escalation between
  pfSense user privilege levels; information disclosure on the block page; resource
  exhaustion that recovers on its own.
- **Low:** issues that require full administrator access, or that only affect
  defense in depth.

## Reports and patches

- Include a minimal reproducer: a DNS query, HTTP request, or feed snippet, plus the
  code path it takes.
- Proposed patches should be minimal and follow the existing style. PHP must not use
  constructs newer than 8.3; shell must be strict POSIX (it runs under FreeBSD ash).
- Group findings by root cause: one report per distinct sink, even when it is reached
  from several pages or feeds.
