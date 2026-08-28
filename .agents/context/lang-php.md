# PHP — language context

Scope: writing or changing PHP (`*.php`/`*.inc`). Load when: any touched PHP file.

- Indent **tabs** (`.editorconfig`); target PHP 8.3 (pfSense CE 2.8).
- pfSense-injected functions declared in `stubs/pfsense/` — no `require_once` pfSense files in tests.
- No `die()`/`exit()` in library code; return or throw.
- Web UI help text: brief yet clear — match neighbouring help texts' wording/length/style.

## Resolving pfSense-provided PHP functions from upstream

pfSense function missing, ambiguous, or maybe implicated in bug and not stubbed yet? No guess workaround. Open source: <https://github.com/pfsense/pfSense>. Behaviour differ across releases, so check full source tree at each relevant ref:

1. **Minimum supported CE** — youngest commit ≤ our min CE launch date (currently **2.8.0**).
2. **Each CE release** since oldest supported — youngest commit ≤ its launch date.
3. **Each pfSense Plus release** since our oldest supported CE — youngest commit ≤ its date.
4. **`master`** — current tip.

Resolve refs at investigation time (no hardcode hashes): take youngest commit at/before release date (`git log --before="<date>" -1 <branch>`, or dated GitHub commits view). Public mirror may lack release branches/tags (no `RELENG_2_8_0`), so dated commits are reliable handle. **Prefer stubbing real function over exception** (a `phpstan-baseline.neon` suppression, an `undefinedFunctions` entry, or code workaround) — stubs encode reality, keep PHPStan/Intelephense honest. By-hand counterpart to bulk generator in `scripts/update-pfsense-stubs.py`.
