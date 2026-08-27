# ADR-26: Locale Policy and Cross-Platform Shell Portability

- **Status:** **Accepted** (2026-06-16)
- **Date:** 2026-06-15
- **Branch:** `adr/26-locale-policy-and-shell-po` (off `devel`)
- **Component(s):**
  `src/usr/local/pkg/pfblockerng/pfblockerng.sh` (collation sinks; `ls`-column parse; `jot`),
  `src/usr/local/pkg/pfblockerng/list_scripts/*.sh` (future surface),
  `CLAUDE.md` + `docs/misc/architecture-notes.md` (the policy of record)
- **Target runtime:** POSIX `/bin/sh` — FreeBSD (pfSense CE 2.8 / FreeBSD 15) today; GNU/musl
  Linux + macOS as cross-platform ambitions land
- **Test surface:** `shellcheck` + `sh -n` (pre-commit/CI), `tests/smoke` (ADR-04 live VM),
  `tests/` (pytest) for any extractable helper

## 1. Context

pfBlockerNG's heavy lifting lives in `pfblockerng.sh` — feed parsing, dedup, aggregation,
reputation, suppression — a POSIX `sh` script that has only ever run on FreeBSD under
pfSense's controlled environment. As the project takes on **cross-platform ambitions**
(running parts of this tooling on Linux/containers, and validating it off-appliance), the
script's reliance on the **ambient C library locale** becomes a correctness and portability
hazard. This ADR fixes the **locale policy** as the project's rule of record, and folds in the
two adjacent FreeBSD-only shell constructs surfaced alongside it.

### 1.1 What the locale controls (and why it bites)

The `LC_*` environment governs how `sort`, `uniq`, `comm`, `join`, `grep`, `tr`, `awk`, and
`sed` interpret bytes:

- **`LC_COLLATE`** — sort/compare order **and** the notion of "equal". Under a UTF-8 or
  language locale, distinct strings can share a collation weight, so `sort -u` / `uniq` treat
  them as **duplicates and silently drop one**. For a blocklist that is data corruption: a
  dropped IP/CIDR or domain is a hole in the block set, with no error.
- **`LC_CTYPE`** — character classification + multibyte decoding: `[[:alpha:]]`, `[[:space:]]`,
  case-fold (`tr a-z A-Z`, `grep -i`), and `awk` `length()`/`substr()`. Under the `C` (POSIX)
  locale these are **ASCII-only and byte-oriented**; under a UTF-8 locale they are
  Unicode-aware.

These two knobs pull in **opposite directions**: byte-exact dedup wants `C`; Unicode-aware
text handling wants UTF-8. They are separable.

### 1.2 The data is already ASCII at the shell boundary

pfBlockerNG's machine data reaching the shell is **IPv4/IPv6 addresses and punycode
(ASCII) domains** — the ADR-08 IDN/homoglyph work is done in Python (`unicodedata`) and
domains are punycode-encoded before the shell processes them. So at today's collation sinks
there is **nothing for UTF-8 ctype to add** — byte semantics are exactly right, and `C` is
the most universally available locale.

### 1.3 Audit — collation sinks in `pfblockerng.sh`

`sort -u` / `uniq` over machine data where byte-exact uniqueness is load-bearing (line
numbers as of current `devel`; pair each with its command to stay findable as the file
drifts):

| Line | Construct | Class | Risk if locale-collated |
| ---- | --------- | ----- | ----------------------- |
| 479  | `LC_ALL=C sort -u "${tempfile}"` (aggregate dedup) | **already correct** | — (reference pattern) |
| 282  | `data="$(sort -u "${pfbsuppression}")"` | HIGH | suppression entry dropped |
| 531  | `cut -d ' ' -f1 "${masterfile}" \| sort -u` | HIGH | alias-list compare skewed |
| 543  | `sort -u "${pfbdeny}${alias}.txt"` (in-place) | HIGH | deny IP dropped |
| 759  | `sort -u "${pfbdeny}${alias}.txt"` | HIGH | deny IP dropped |
| 853  | `sort -u "${pfbdeny}${alias}.txt"` (in-place) | HIGH | deny IP dropped |
| 1158 | `grep -aoEw '<ipv4>' \| sort -u > …orig` | HIGH | extracted IP dropped |
| 1180 | `sort -o "${masterfile}" "${masterfile}"` | MEDIUM | order feeds later compares/diffs |

Numeric (`sort -n…`) and display-only sinks (`wc -l … | sort -n -r` at 1197/1201/1205/1209/
1222/1255; `sort -nu` at 725; `sort -t . -k 1,1n…` at 1181) are **collation-insensitive** —
`-n` parses numbers, and `.`-keyed octet sort is numeric. They are out of scope (adding the
prefix is harmless but noise).

`pfblockerng.inc`'s `sort($members)` / `sort($sch)` are **PHP in-process array sorts**, not
shell collation — out of scope for this ADR.

### 1.4 Adjacent FreeBSD-only constructs (cross-platform, surfaced with the locale work)

- **`ls`-column parse** — lines 1226 and 1230:
  `ls -lahtr "${pfb…orig}"*.orig | sed … | awk -v OFS='\t' '{print $6" "$7,$8,$9}'`. Parsing
  `ls -l` by column position is the classic anti-pattern: the field layout shifts with
  **locale** (date formatting/field count) and across **BSD vs GNU `ls`** (`-h` spacing,
  timestamp format). This is a **diagnostic dump** (no shipped decision depends on it), so the
  blast radius is cosmetic, but it is both locale- and platform-fragile.
- **`jot`** — line 327: `for i in $(/usr/bin/jot 255)`. `jot(1)` is BSD-only and hardcoded to
  `/usr/bin/jot`; Linux ships `seq(1)` instead. (The `jot` mention at line 18 is a comment
  about temp-dir entropy, not a call.)

The other `ls -A "${dir}"` usages (1090, 1174, 1195, 1203, 1207, 1211, 1220, 1224, 1228) are
**emptiness checks** (`[ "$(ls -A dir)" ]`) — portable, out of scope.

### 1.5 Availability of a "fixed but Unicode-aware" locale

The natural middle ground for *future* Unicode-aware shell text is **`C.UTF-8`**:
locale-independent like `C` (deterministic **codepoint** collation, no language dictionary
rules, no equal-weight merging) **plus** a UTF-8 codeset (Unicode-aware `LC_CTYPE`). ASCII
stays single-byte with identical values, so it is nearly as cheap as `C`. The catch is
**availability, not behaviour**:

- **FreeBSD / pfSense** (FreeBSD 15) — present.
- **glibc Linux** — built-in since glibc 2.35 (2022); older/minimal images may lack it.
- **musl / Alpine** — the `C` locale is already UTF-8; fine.
- **macOS (BSD libc)** — **no `C.UTF-8`**; only `en_US.UTF-8` and friends. This is the main
  portability hole for off-appliance dev/CI on Macs.

So `LC_ALL=C.UTF-8` **cannot be assumed** to exist everywhere; it must be resolved at runtime
with a fallback chain, never hardcoded.

## 2. Decision

**Locale is set explicitly and per-command at the points that need it; it is never exported
process-wide.** Three rules:

### 2.1 Byte-exact machine-data sinks → inline `LC_ALL=C`

Every `sort -u` / `uniq` / `comm` / `join` (and any plain `sort` whose **order** feeds a
downstream compare/diff) over machine data (IPs, punycode domains) carries an **inline**
`LC_ALL=C` prefix on **that command** — matching the existing reference at line 479. Apply to
the HIGH + MEDIUM sinks in §1.3. This guarantees byte-exact uniqueness and identical results
on FreeBSD and Linux regardless of the host's default locale.

### 2.2 Never `export LC_ALL=C` (nor `LANG=C`) script-wide

A global export poisons **every child process** the script spawns — `php`, `host`/`drill`,
`mmdblookup`, list pre-/post-scripts — ASCII-crippling any legitimately UTF-8-aware tool and
changing error-message language, date, and number formatting. It also creates a **partial-
adoption hazard**: `comm`/`join`/`diff`/`uniq` require **all** inputs in the **same**
collation, so a global default silently mismatches any pipeline that mixes a `C`-sorted file
with a locale-sorted one. Keep locale **surgical and inline**.

### 2.3 Future Unicode-aware shell text → split the knobs, resolve at runtime

If/when a shell path must classify or case-fold **raw Unicode** (un-punycode'd) text, it does
**not** use bare `C` (which would silently miss non-ASCII). Instead it **splits the two
concerns**:

- **`LC_COLLATE=C`** on any sort/set operation in that path — keeps order deterministic and
  uniqueness byte-exact.
- **`LC_CTYPE=<UTF-8 locale>`** for the classification/case-fold step, where the UTF-8 locale
  is **resolved at runtime** (prefer `C.UTF-8`, fall back to a `*.UTF-8` such as
  `en_US.UTF-8`, last-resort `C`) — never assume `C.UTF-8` exists (macOS / minimal images).

The resolution is centralised in one helper (a `pfb_*` locale resolver, naming per the
established `pfB_*`/`pfb_*` convention) so call sites stay one-liners and the fallback logic
lives in exactly one place.

**Deferred — no caller today (Phase 2 decision).** Since no raw-Unicode shell path exists yet,
shipping the resolver now would land an **unused** function in `pfblockerng.sh` — dead code in
the user-facing release archive (which carries `src/`) and an "unused" lint risk — that buys
nothing the byte-exact sinks of §2.1 don't already have. So the resolver is recorded as a
**copy-ready snippet** in `docs/misc/architecture-notes.md` ("Locale policy (ADR-26)"), and is
promoted to a real `pfb_*` helper in `pfblockerng.sh` the day the **first `LC_CTYPE` caller**
lands. The policy itself (when/how to split the knobs) is in force now; only the function body is
deferred. Note the two knobs pull opposite ways at a collation sink — the sinks of §2.1 want byte
ctype too, so they keep `LC_ALL=C` and never adopt this resolver.

### 2.4 Adjacent portability fixes (same cross-platform driver)

- Replace both `ls -lahtr … | sed | awk` column-parses with a metadata API that is neither
  locale- nor `ls`-layout-dependent — `find … -printf '%T@ %p\n' | LC_ALL=C sort -n | …`
  (GNU) or a `stat`-based equivalent, behind a tiny portability wrapper if both BSD and GNU
  must be supported (`find -printf` is GNU-only; BSD `stat -f '%m %N'` vs GNU `stat
  --format='%Y %n'` differ — the wrapper or `find` choice is decided in implementation).
- Replace the `jot 255` range with a portable sequence (`seq`, or a small `jot`/`seq`
  compatibility shim) and drop the hardcoded `/usr/bin/jot` path.

## 3. Consequences

**Positive**

- Byte-exact dedup at every set-operation sink — no silently dropped IP/domain on any host
  locale; identical output on FreeBSD and Linux.
- No child-process pollution; UTF-8-aware tools the script invokes keep working.
- A single documented rule ("inline `LC_ALL=C` on machine-data set ops; split knobs for
  Unicode text; never export") that future shell additions can follow mechanically.
- Removes two FreeBSD-only / locale-fragile constructs (the `ls` parse and `jot`).

**Negative**

- A handful of call sites grow an `LC_ALL=C` prefix (minor verbosity; the line-479 precedent
  already establishes the idiom).
- The `ls`→`find`/`stat` rewrite must keep the existing diagnostic **output format** stable
  (column order/labels) to avoid surprising anyone reading the logs.

**Neutral**

- Numeric/display-only sinks are left unprefixed by design (collation-insensitive); a future
  reviewer may mistake this for an omission — §1.3 records why.
- `C.UTF-8` is not adopted now (no raw-Unicode shell path exists today); §2.3 is the policy
  for **when** one appears, not a present change.

## 4. Alternatives considered

- **Global `export LC_ALL=C`** (Grok's first suggestion, and the simplest). Rejected:
  child-process pollution and the partial-adoption/mixed-collation hazard (§2.2) outweigh the
  "one line, covers everything" convenience. The data doesn't need a global default; the
  sinks that matter are enumerable.
- **Global `LC_ALL=C.UTF-8`.** Rejected for now: not universally available (macOS, old glibc,
  minimal images), still a global export, and buys nothing for today's ASCII data.
- **Use `LANG=C` instead of `LC_ALL=C` at the sinks.** Rejected — `LANG=C` is both weaker and
  redundant here, never a substitute. The locale precedence is **`LC_ALL` > each `LC_*` (e.g.
  `LC_COLLATE`) > `LANG`**: `LC_ALL`, when set, forces **every** category and overrides all
  `LC_*` and `LANG`; `LANG` is only the **fallback default** consulted for a category that no
  `LC_ALL`/specific `LC_*` set. So:
  - **`LANG=C` alone is unsafe.** An inherited `LC_COLLATE` (or `LC_ALL`) in the caller's
    environment outranks `LANG` — `sort -u` would still collate UTF-8 and silently drop a
    blocklist entry, the exact bug this ADR closes. `LC_ALL=C` cannot be defeated that way.
  - **`LANG=C` *added alongside* `LC_ALL=C` is pure noise.** `LC_ALL` already pins all
    categories, so `LANG` is never consulted; it only bloats the diff and breaks the
    line-479 reference idiom's uniformity.
  - The two are equivalent only in the degenerate case where no `LC_*` is set anywhere — a
    fragile assumption that `LC_ALL=C` removes outright. Hence the inline prefix is `LC_ALL=C`,
    and the "never export" rule in §2.2 covers **both** `LC_ALL` and `LANG` (exporting `LANG=C`
    process-wide would, symmetrically, weakly-and-globally pollute children while still losing
    to any child's own `LC_*`).
- **Do nothing (rely on pfSense's ambient locale).** Rejected: works only because pfSense
  happens to run an effectively byte-collating default; the moment any of this runs on a
  Linux host with a UTF-8 default, `sort -u` can drop entries with no diagnostic.

## 5. Scope / phases

1. **Inline `LC_ALL=C` on the dedup/order sinks** (§2.1) — the HIGH + MEDIUM sinks in §1.3.
2. **Locale policy of record + deferred resolver** (§2.2, §2.3) — the documented rule in
   `CLAUDE.md` / `architecture-notes.md`, plus the runtime UTF-8 resolver kept as a copy-ready doc
   snippet (no caller today → not shipped as a function; promoted to a `pfb_*` helper when the
   first `LC_CTYPE` site lands).
3. **Adjacent portability fixes** (§2.4) — the `ls`-column parses and `jot`.
4. **Definition of Done** — shellcheck/`sh -n` clean, smoke green, docs landed, diff minimal.

See the ordered `NN_*.txt` phase prompts in this directory.
