# Shell — language context

Scope: writing or changing POSIX shell. Load when: any touched `*.sh` file.

- POSIX sh only (`#!/bin/sh`); no bash-isms (`[[`, arrays, `$RANDOM`). Quote all expansions.
  **POSIX-compliant means correct under strict-POSIX SEMANTICS (ash/dash), not merely free of
  bashisms** — e.g. a redirection error on a special built-in (`:`, `exec`, `set`) exits a
  non-interactive ash/dash shell entirely while bash continues. bash-as-sh acceptance is not
  evidence; the shellspec gate executes under dash for exactly this reason.
- Absolute paths for add-on/privileged binaries (`iprange`/`grepcidr`/`mmdblookup`/`jq`/
  `pfctl`) as `path*` vars (see `pfblockerng.sh`); base utilities may be bare.
- AWS region pre-scripts: 25 thin wrappers over the shared
  `list_scripts/aws_region_prefixes.sh` — change that one, not 25.
- **Locale (ADR-26):** never `export LC_ALL`/`LANG` script-wide; every `sort -u`/`uniq`/
  `comm`/`join` over machine data (IPs, punycode) carries inline **`LC_ALL=C`** — a language
  collation can merge distinct strings and silently drop a blocklist entry. Full policy:
  architecture-notes "Locale policy".
