# The Core Updater's end-to-end corpus (issue #4038, sub-slice 9j)

`corpus.json` holds cases of whole Updates. Today's PHP Update on a pfSense box is the oracle:
`tests/smoke/test_smoke_update_loop_corpus.py` runs each case there and records what each Update left.
`../../e2e_replay_test.go` runs the same cases through the Core Updater's loop and compares.

## A case

| Key | Meaning |
|---|---|
| `id`, `description` | The case's name and what it pins |
| `ordering` | The ordering rule of #4038 the case holds, when it holds one |
| `groups` | Feed groups: `kind` (`ipv4`, `ipv6`, `dnsbl`), `name` (the alias name), `action` (IP groups), `feeds` (`header`, and `serve`, the name the feed server serves it under) |
| `dnsbl_ip` | The DNSBL IP action (DNSBLIP), when on |
| `serve` | The bodies the feed server serves at the start: name to `text` and `etag` |
| `steps` | The Updates, in order: `request` (the version 1 request: `trigger`, `scope`, `force`, `feeds`), and `serve`, bodies changed before it |
| `expect` | One record per step, frozen from the box |

A feed whose `serve` name is not served gets 404. The server answers a served name with 200, its ETag and a fixed
`Last-Modified`, or 304 to a matching `If-None-Match`, as the smoke harness's mock feed server does.

Each feed header is used by one case only, so no case finds another's downloads.

## A step's record

| Key | What today's Update left |
|---|---|
| `exit` | The Update program's exit status |
| `outcomes`, `attempted` | The result lines on fd 3, added up |
| `sets` | Every `pfB_*` mirror under `/var/db/aliastables`, its lines in file order |
| `dnsbl` | The manifest `pfb_py_sources.json` (`config`, and each feed row with the lines of its raw file as `rows`), or null without one |
| `issues` | The open entries of the ADR-61 ledgers, without their times (the harness clears the ledger before each case) |
| `stages` | The transcript's stage headers in the order they first appear, named as the loop names its stages |
| `snapshot` | The settings adapter's read before the Update, the feed server's address written as `{{FEEDS}}`: the replay's settings, never compared |

## What the replay compares, and the departures it applies

| Output | Loop side | Departures applied to today's record |
|---|---|---|
| Sets | Every `ip-set` and `ip-aggregate` the store holds, by `apply.Alias` | No placeholder row (owner question 1); one spelling per network and the address guard (`apply.Member`); a sorted set |
| DNSBL data | `dnsbl/manifest` and its feed bodies | A feed's rows are a sorted, de-duplicated set (#4036 owner question 2); a feed without today's permit mode is a deny feed |
| Outcomes | The worker's `Result` | none |
| Issues | The version 2 request's issues, by table (an `ip-set` id read as its alias) and stage | Messages are not compared |
| Stage order | The stage boundaries the worker reaches | Today's stages keep their order among them |

The settings snapshot is replayed with the mock network `192.168.89.0/24` in the feed-host allowlist replaced by
`127.0.0.0/8`, where the replay's feed server listens.

## The Loop the replay gives

The replay builds the `Loop` from JSON. Besides today's `settingsCmd`, `resourceDir` and `mainLog`, it names the folders of
a pfSense box under a sandbox root, created as an installed package has them:

| Key | Today's path |
|---|---|
| `dbDir` | `$pfb['dbdir']`, `/var/db/pfblockerng`, with `deny`, `permit`, `match/generated`, `native`, `original`, `snapshot`, `dnsbl`, `dnsblorig` and `ET` |
| `geoipShareDir` | `$pfb['geoipshare']`, `/usr/local/share/GeoIP` |
| `ccDir` | `$pfb['ccdir']`, `/usr/local/share/GeoIP/cc` (not created) |
| `pkgDir` | `/usr/local/pkg/pfblockerng`: the SafeSearch lists `pfb_dnsbl.*.conf` and `dnsbl_psl` (the repository's `src` copy) |

The apply program is the test binary standing in for it: it records each version 2 request and answers one result line
that applies every resource and removal the request names.

## Freezing

Run the smoke module on a box (`scripts/local-smoke.sh --filter test_smoke_update_loop_corpus`). Each run writes
`update_loop_corpus_actual.json` in its diagnostics folder: per case, the records and the full transcripts. Copy a case's
records into its `expect`. Cases here hold no SafeSearch: its table resolves names through the box's resolver, a
host-dependent input that stays out of the shared corpus.
