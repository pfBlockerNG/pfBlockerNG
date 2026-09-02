#!/usr/bin/env python3
"""Keep the on/off toggle contract in the configuration registry, not in the page.

issue #2123 moved seventeen `PFB_FILTER_ON_OFF` toggle keys off the 3.2 arrangement --
default declared at the top of the page, stored vocabulary decided at the save site,
comparison written inline at the render -- and onto `pfb_cfg_registry()`. Without a
mechanical gate that sweep is a one-off: the next settings checkbox someone adds gets
its own page-level `?: ''` and the drift is back.

Two rules, both scoped to a SECTION-MIRROR save (`$pfb['<mirror>']['<key>'] = ...`),
which is the shape a registered scalar takes:

  RULE 1 -- REGISTERED. A `PFB_FILTER_ON_OFF` save into a section mirror must name a key
  that `pfb_cfg_registry()` knows, under the alias the mirror's own section resolves to.

  RULE 2 -- NO PAGE DEFAULT. Once a key IS registered (toggle or plain scalar), the page
  must not restate its default: a READ of `$pfb['<mirror>']['<key>']` may not carry a
  `?:` fallback or sit inside an `isset(...) ? ... : <literal>`. The default belongs
  to the registry entry. issue #2994 widened this off toggles after aligning the six
  page/registry divergences. Reads are distinguished from saves by side: a save has
  the mirror expression on the LEFT of `=`, a read has it on the right. The save
  site's own `?: ''` is left alone on purpose -- it is transport normalisation of an
  absent checkbox, not a default, and `PfbConfig::writeSection()` re-normalises it
  through the registered adapter anyway.

The mirror -> section mapping is DERIVED, never listed: each page declares it itself
with `$pfb['<mirror>'] = PfbConfig::readSection('<section path>')`, and the section path
is resolved to a registry alias through `PFB_SECTIONS`. So a page that introduces a new
mirror is covered the moment it is written, with nothing to keep in sync here.

Exemptions live in `EXEMPT` below and each carries a reason. An unregisterable key --
a genuinely dynamic per-row or per-continent path -- never reaches these rules in the
first place: it is not a section-mirror save.

Usage:
    check_toggle_registry.py [PATH ...]
    check_toggle_registry.py --self-test

With no PATH, scans every tracked `src/usr/local/www/pfblockerng/*.php`. Exit 0 clean,
1 on violations, 2 when the scan set or the registry could not be established (fail
closed -- a gate that cannot read the registry must not report "clean").

`--self-test` is the red canary the testing policy requires for a newly wired blocking
gate: it feeds a known-violating synthetic page through the same matchers and exits 0
only if BOTH rules fire. It does not touch the repository.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

REGISTRY_FILE = "src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"
WWW_DIR = "src/usr/local/www/pfblockerng"

# A registry entry: its path key plus enough of the entry body to bound the match
# to the entry's own closing `],`.
_REGISTRY_ENTRY_RE = re.compile(
    r"^\s*'([a-z]+)/([A-Za-z0-9_]+)'\s*=>\s*\[(.*?)^\t\t\],",
    re.DOTALL | re.MULTILINE,
)

# One `PFB_SECTIONS` row: `'ip' => 'installedpackages/pfblockerngipsettings/config/0',`.
_SECTIONS_BLOCK_RE = re.compile(r"const PFB_SECTIONS\s*=\s*\[(.*?)^\];", re.DOTALL | re.MULTILINE)
_SECTIONS_ROW_RE = re.compile(r"'([a-z]+)'\s*=>\s*'([^']+)'")

# A page's own mirror declaration: `$pfb['iconfig'] = PfbConfig::readSection('...');`.
_MIRROR_RE = re.compile(r"\$pfb\s*\[\s*'(\w+)'\s*\]\s*=\s*PfbConfig::readSection\(\s*'([^']+)'")

# A save into a section mirror through the on/off form filter. Matched over the whole
# file, not line by line: `[^;]*?` cannot cross a statement terminator, so a save
# wrapped across lines is still one match and cannot slip past the gate by being
# reformatted.
_SAVE_RE = re.compile(
    r"\$pfb\s*\[\s*'(\w+)'\s*\]\s*\[\s*'(\w+)'\s*\]\s*=[^;]*?\bPFB_FILTER_ON_OFF\b",
    re.DOTALL,
)

# A read of a section mirror carrying its own default. Two spellings:
#   $x = $pfb['iconfig']['enable_dup'] ?: '';
#   $x = isset($pfb['aglobal']['alertrefresh']) ? $pfb['aglobal']['alertrefresh'] : 'on';
_READ_COALESCE_RE = re.compile(r"=\s*\$pfb\s*\[\s*'(\w+)'\s*\]\s*\[\s*'(\w+)'\s*\]\s*\?[:?]")
_READ_ISSET_RE = re.compile(r"isset\(\s*\$pfb\s*\[\s*'(\w+)'\s*\]\s*\[\s*'(\w+)'\s*\]\s*\)\s*\?[^?:]*:")

# Sanity floor: the registry has had >100 entries since issue #1920's audit. A parse
# that finds fewer has broken, and a broken parse must fail the gate rather than
# declare every save site unregistered (or, worse, every key registered).
_MIN_REGISTRY_KEYS = 100

# (page basename, bare key) -> reason. Every entry is a deliberate, recorded decision.
#
# Empty since issue #2812: the last seven pre-#2123 toggle sites it recorded were routed
# through PfbConfig::read() and their rows deleted. The table stays as the shape for a
# DELIBERATE exemption -- a future row must name the decision that makes the duplication
# acceptable, and a row whose site is gone is dead weight -- delete it.
EXEMPT: dict[tuple[str, str], str] = {}


class Violation(NamedTuple):
    """One page site that keeps a toggle contract the registry should own."""

    source: str
    line: int
    rule: str
    detail: str
    snippet: str


def parse_sections(registry_text: str) -> dict[str, str]:
    """Map config.xml section path -> registry alias, from `PFB_SECTIONS`."""
    block = _SECTIONS_BLOCK_RE.search(registry_text)
    if block is None:
        return {}
    return {path: alias for alias, path in _SECTIONS_ROW_RE.findall(block.group(1))}


def parse_registry_keys(registry_text: str) -> set[tuple[str, str]]:
    """Every `(alias, bare key)` pair `pfb_cfg_registry()` declares literally."""
    return {(alias, key) for alias, key, _body in _REGISTRY_ENTRY_RE.findall(registry_text)}


def find_violations(
    text: str,
    source: str,
    sections_by_path: dict[str, str],
    registry_keys: set[tuple[str, str]] | dict[tuple[str, str], object],
) -> list[Violation]:
    """Apply both rules to one page's source."""
    basename = Path(source).name
    lines = text.splitlines()
    # The page's own mirror -> alias map, derived from its readSection() calls.
    alias_by_mirror: dict[str, str] = {}
    for mirror, path in _MIRROR_RE.findall(text):
        alias = sections_by_path.get(path)
        if alias is not None:
            alias_by_mirror[mirror] = alias

    def site(offset: int) -> tuple[int, str]:
        """(1-based line, trimmed line) for a match offset."""
        lineno = text.count("\n", 0, offset) + 1
        return lineno, lines[lineno - 1].strip() if lineno <= len(lines) else ""

    violations: list[Violation] = []

    # RULE 1 -- every on/off save into a registered section must name a registered key.
    for match in _SAVE_RE.finditer(text):
        mirror, key = match.group(1), match.group(2)
        alias = alias_by_mirror.get(mirror)
        if alias is None:
            # The mirror is not a registered section at all (no PFB_SECTIONS alias):
            # a foreign section, outside the registry's scope.
            continue
        # EXEMPT is a RULE 2 record only: one backlog row must never license an
        # unregistered save of that key name forever.
        if (alias, key) in registry_keys:
            continue
        lineno, snippet = site(match.start())
        if snippet.startswith(("//", "*", "/*", "#")):
            continue
        violations.append(
            Violation(
                source,
                lineno,
                "unregistered-toggle",
                f"PFB_FILTER_ON_OFF save of '{alias}/{key}' has no pfb_cfg_registry() entry",
                snippet,
            )
        )

    # RULE 2 -- every registered key. issue #2994 aligned the six page/registry
    # scalar divergences, so the toggle-only scope #2123 kept (and #2812 left as
    # work item 2) can widen: a registered plain scalar may not restate its
    # default on a section-mirror read either.
    seen: set[int] = set()
    for matcher in (_READ_COALESCE_RE, _READ_ISSET_RE):
        for match in matcher.finditer(text):
            mirror, key = match.group(1), match.group(2)
            alias = alias_by_mirror.get(mirror)
            if alias is None or (alias, key) not in registry_keys:
                continue
            if (basename, key) in EXEMPT:
                continue
            lineno, snippet = site(match.start())
            if lineno in seen or snippet.startswith(("//", "*", "/*", "#")):
                continue
            seen.add(lineno)
            violations.append(
                Violation(
                    source,
                    lineno,
                    "page-level-default",
                    f"'{alias}/{key}' is a registered field, so its default belongs to "
                    "the registry entry -- read it with PfbConfig::read()",
                    snippet,
                )
            )

    return sorted(violations, key=lambda v: (v.line, v.rule))


def _git_tracked_pages(root: Path) -> list[str]:
    """Tracked `src/usr/local/www/pfblockerng/*.php` paths (sorted)."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", WWW_DIR],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    return sorted(p for p in out.split("\0") if p.endswith(".php"))


_SELF_TEST_PAGE = """<?php
$pfb['iconfig'] = PfbConfig::readSection('installedpackages/pfblockerngipsettings/config/0');
$pconfig['suppression'] = $pfb['iconfig']['suppression'] ?: 'on';
if ($_POST) {
    $pfb['iconfig']['pfb_brand_new_toggle'] = pfb_filter(
        $_POST['pfb_brand_new_toggle'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';
    $pfb['iconfig']['suppression'] = pfb_filter($_POST['suppression'] ?? '', PFB_FILTER_ON_OFF, 'ip') ?: '';
}
"""


def _self_test(sections_by_path: dict[str, str], registry_keys: dict[tuple[str, str], bool]) -> int:
    """Red canary: prove both rules fire on a known-violating synthetic page."""
    found = find_violations(_SELF_TEST_PAGE, "self-test/pfblockerng_ip.php", sections_by_path, registry_keys)
    rules = {v.rule for v in found}
    missing = {"unregistered-toggle", "page-level-default"} - rules
    if missing:
        print(
            f"check_toggle_registry --self-test: rule(s) did not fire: {sorted(missing)}. "
            "The gate cannot detect the drift it exists to detect.",
            file=sys.stderr,
        )
        for v in found:
            print(f"    fired: {v.rule} at line {v.line}", file=sys.stderr)
        return 1
    print(
        "check_toggle_registry --self-test: both rules fired on the violating page "
        f"({len(found)} finding(s)) -- gate wiring proven.",
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. 0 clean, 1 violations, 2 fail-closed."""
    args = list(sys.argv[1:] if argv is None else argv)
    root = Path(__file__).resolve().parent.parent

    try:
        registry_text = (root / REGISTRY_FILE).read_text(encoding="utf-8")
    except OSError as exc:
        print(
            f"check_toggle_registry: cannot read {REGISTRY_FILE} ({exc}) -- failing "
            "closed rather than reporting clean.",
            file=sys.stderr,
        )
        return 2

    sections_by_path = parse_sections(registry_text)
    registry_keys = parse_registry_keys(registry_text)
    if not sections_by_path or len(registry_keys) < _MIN_REGISTRY_KEYS:
        print(
            f"check_toggle_registry: parsed {len(sections_by_path)} section alias(es) and "
            f"{len(registry_keys)} registry key(s) from {REGISTRY_FILE} -- below the "
            f"{_MIN_REGISTRY_KEYS}-key floor, so the parse is broken. Failing closed.",
            file=sys.stderr,
        )
        return 2

    if args == ["--self-test"]:
        return _self_test(sections_by_path, registry_keys)

    if args:
        paths = args
    else:
        paths = _git_tracked_pages(root)
        if not paths:
            print(
                f"check_toggle_registry: `git ls-files {WWW_DIR}` returned nothing "
                "(git unavailable or not a checkout) -- failing closed rather than "
                "skipping the gate.",
                file=sys.stderr,
            )
            return 2

    violations: list[Violation] = []
    for path in paths:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = root / path
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # Fail CLOSED: a page the gate cannot read is not a clean page.
            print(
                f"check_toggle_registry: cannot read {path} ({exc}) -- failing closed rather than reporting clean.",
                file=sys.stderr,
            )
            return 2
        violations.extend(find_violations(text, path, sections_by_path, registry_keys))

    for v in violations:
        print(f"{v.source}:{v.line}: [{v.rule}] {v.detail}", file=sys.stderr)
        print(f"    {v.snippet}", file=sys.stderr)

    if violations:
        print(
            f"\n{len(violations)} toggle-contract violation(s). Add the key to "
            "pfb_cfg_registry() (see docs/misc/config-gateway.md -> 'Adding a new "
            "registered field'), read it through PfbConfig::read(), or record a "
            "reasoned exemption in scripts/check_toggle_registry.py's EXEMPT table.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
