# Shell — language context

Scope: writing or changing POSIX shell. Load when: any touched `*.sh` file.

- POSIX sh only (`#!/bin/sh`); no bash-isms (`[[`, arrays, `$RANDOM`). Quote all expansions.
  **POSIX-compliant mean correct under strict-POSIX SEMANTICS (ash/dash), not just
  free of bashisms** — example: redirection error on special built-in (`:`, `exec`, `set`) kill
  non-interactive ash/dash shell entirely while bash keep going. bash-as-sh acceptance no
  evidence; shellspec gate run under dash for this reason.
- Absolute paths for add-on/privileged binaries (`iprange`/`grepcidr`/`mmdblookup`/`jq`/
  `pfctl`) as `path*` vars (see `pfblockerng.sh`); base utilities may be bare.
- AWS region pre-scripts: 25 thin wrappers over shared
  `list_scripts/aws_region_prefixes.sh` — change that one, not 25.
- **Locale (ADR-26):** never `export LC_ALL`/`LANG` script-wide; every `sort -u`/`uniq`/
  `comm`/`join` over machine data (IPs, punycode) carry inline **`LC_ALL=C`** — language
  collation can merge distinct strings and silently drop blocklist entry. Full policy:
  architecture-notes "Locale policy".
