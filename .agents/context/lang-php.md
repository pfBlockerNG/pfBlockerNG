# PHP — language context

Scope: writing or changing PHP (`*.php`/`*.inc`). Load when: any touched PHP file.

- Indent **tabs** (`.editorconfig`); target PHP 8.3 (pfSense CE 2.8).
- pfSense-injected functions are declared in `stubs/pfsense/` — don't `require_once` pfSense
  files in tests.
- No `die()`/`exit()` in library code; return or throw.
- Web UI help text: brief yet clear — match neighbouring help texts' wording/length/style.

## Resolving pfSense-provided PHP functions from upstream

When a pfSense-provided PHP function is missing, ambiguous, or possibly implicated in a bug
and isn't stubbed yet, do NOT guess a workaround. It's open source:
<https://github.com/pfsense/pfSense>. Behaviour differs across releases, so check it in the
full source tree at each relevant ref:

1. **Minimum supported CE** — youngest commit ≤ our min CE launch date (currently **2.8.0**).
2. **Each CE release** since the oldest supported — youngest commit ≤ its launch date.
3. **Each pfSense Plus release** since our oldest supported CE — youngest commit ≤ its date.
4. **`master`** — current tip.

Resolve refs at investigation time (don't hardcode hashes): take the youngest commit
at/before the release date (`git log --before="<date>" -1 <branch>`, or the dated GitHub
commits view). The public mirror may lack release branches/tags (no `RELENG_2_8_0`), so dated
commits are the reliable handle. **Prefer stubbing the real function over an exception** (a
`phpstan-baseline.neon` suppression, an `undefinedFunctions` entry, or a code workaround) —
stubs encode reality and keep PHPStan/Intelephense honest. By-hand counterpart to the bulk
generator in `scripts/update-pfsense-stubs.py`.
