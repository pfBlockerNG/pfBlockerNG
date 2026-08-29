"""Contract tests for the nested pfblockerng.php re-entry bounds checker.

Each blocking shape is paired with its routed/backgrounded form so the matcher
must discriminate in both directions. Every path-and-needle exemption is pinned
as load-bearing and unable to exempt another line or same-named file. Hostile
rows cover malformed text and token-boundary cases.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, NamedTuple

import pytest

# --------------------------------------------------------------------------- #
# Load the script as a module.
# --------------------------------------------------------------------------- #

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TOOL = _REPO_ROOT / "scripts" / "check_reentry_bounds.py"
_spec = importlib.util.spec_from_file_location("check_reentry_bounds", _TOOL)
assert _spec is not None and _spec.loader is not None
crb = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = crb
_spec.loader.exec_module(crb)

# The production paths the checker's allowlist is keyed on.
_PKG = "src/usr/local/pkg/pfblockerng"
_INC = f"{_PKG}/pfblockerng.inc"
_APPLY = f"{_PKG}/pfblockerng_apply.inc"
_EXTRA = f"{_PKG}/pfblockerng_extra.inc"
_INSTALL = f"{_PKG}/pfblockerng_install.inc"
_SH = f"{_PKG}/pfblockerng.sh"
_UPDATE = "src/usr/local/www/pfblockerng/pfblockerng_update.php"
_IP_PAGE = "src/usr/local/www/pfblockerng/pfblockerng_ip.php"
_WIDGET = "src/usr/local/www/widgets/widgets/pfblockerng.widget.php"

# The two token halves a re-entry composition needs: an interpreter and the target.
_PHP_BIN = "/usr/local/bin/php"
_TARGET = "/usr/local/www/pfblockerng/pfblockerng.php"
_SPAWN = f"{_PHP_BIN} {_TARGET}"

# Wall-clock ceiling for the pathological-input row. Not a duration assertion: it exists
# only so a catastrophically backtracking matcher reports as stuck instead of hanging.
_SALVAGE_CAP_S = 10.0


def _find(text: str, source: str = _EXTRA) -> list[Any]:
    """Scan `text` as `source`. Default source carries no allowlist entry."""
    return crb.find_violations(text, source)


# --------------------------------------------------------------------------- #
# The 8 blocking shapes (the brief's enumeration), each paired with the routed
# form that replaces it. Coverage matrix: "each of the 8 blocking shapes flags".
# --------------------------------------------------------------------------- #


class _Shape(NamedTuple):
    """One real-world re-entry site: the unbounded form and its bounded replacement."""

    name: str
    source: str
    blocking: str
    routed: str


_BLOCKING_SHAPES: tuple[_Shape, ...] = (
    _Shape(
        "site1-php-exec-al",
        _APPLY,
        "exec('" + _SPAWN + " al scheduled');",
        "pfb_reentry_exec('al', ['scheduled']);",
    ),
    _Shape(
        "site2-php-exec-bls-capture",
        _APPLY,
        'exec("' + _SPAWN + ' bls scheduled {$bl_string} 2>&1", $pfb_return);',
        "pfb_reentry_exec('bls', ['scheduled', $bl_string], NULL, $pfb_return);",
    ),
    _Shape(
        "site3-php-exec-dc-append-status",
        _APPLY,
        'exec("' + _SPAWN + " dc scheduled >> {$pfb['log']} 2>&1\", $maxmind_output, $maxmind_status);",
        "$maxmind_status = pfb_reentry_exec('dc', ['scheduled'], $pfb['log']);",
    ),
    _Shape(
        "site4-php-interpolated-extras",
        _EXTRA,
        "$command = \"{$pfb['php']} " + _TARGET + ' {$job}";',
        "$status = pfb_reentry_exec($job, $args, $pfb['extraslog']);",
    ),
    _Shape(
        "site5-sh-whoisconvert-asn-shell",
        _SH,
        _SPAWN + " asn_shell scheduled",
        "pfb_reentry asn_shell scheduled",
    ),
    _Shape(
        "site6-sh-iptoasn-asn",
        _SH,
        _SPAWN + " asn",
        "pfb_reentry asn",
    ),
    _Shape(
        "site7-sh-reputation-depends-bu",
        _SH,
        _SPAWN + " bu scheduled",
        "pfb_reentry bu scheduled",
    ),
    _Shape(
        "site8-sh-dnsbl-control",
        _SH,
        _SPAWN + ' dnsbl-control "$@"',
        'pfb_reentry dnsbl-control "$@"',
    ),
    _Shape(
        "sh-variable-token-form",
        _SH,
        '"${pathphp}" "${pathpfbphp}" bls scheduled',
        "pfb_reentry bls scheduled",
    ),
    _Shape(
        "php-constant-target-form",
        _INC,
        "exec(escapeshellarg($pfb['php']) . ' ' . escapeshellarg(PFB_REENTRY_SCRIPT) . ' dc scheduled');",
        "pfb_reentry_exec('dc', ['scheduled']);",
    ),
)

_SHAPE_IDS = [shape.name for shape in _BLOCKING_SHAPES]


@pytest.mark.parametrize("shape", _BLOCKING_SHAPES, ids=_SHAPE_IDS)
def test_blocking_reentry_shape_is_flagged(shape: _Shape) -> None:
    """Each enumerated blocking site flags, reporting its own source, line and snippet."""
    violations = _find(shape.blocking, shape.source)
    assert len(violations) == 1, f"{shape.name}: expected one violation, got {violations!r}"
    assert violations[0].source == shape.source
    assert violations[0].line == 1
    assert violations[0].snippet == shape.blocking.strip()


@pytest.mark.parametrize("shape", _BLOCKING_SHAPES, ids=_SHAPE_IDS)
def test_routed_reentry_shape_is_clean(shape: _Shape) -> None:
    """The seam-routed replacement composes no command, so it must not flag."""
    assert _find(shape.routed, shape.source) == [], f"{shape.name}: the fixed form was flagged"


# --------------------------------------------------------------------------- #
# Backgrounded compositions are out of the defect class (they cannot hold the
# pass open). Each clean marker is paired with the SAME line minus the marker,
# which must flag -- otherwise "clean" would be proving nothing.
# --------------------------------------------------------------------------- #


class _BgRow(NamedTuple):
    """A backgrounded composition and the identical line with the marker removed."""

    name: str
    source: str
    clean: str
    flagged: str


_TRIGGER = " pfb_trigger scope=dnsbl force=false trigger=cron"
_DAEMON = "/usr/sbin/daemon -p " + "escapeshellarg($pidfile)"

_BACKGROUNDED_ROWS: tuple[_BgRow, ...] = (
    _BgRow(
        "trailing-ampersand-inside-the-command-string",
        "src/usr/local/www/pfblockerng/pfblockerng.php",
        "exec(\"{$pfb['php']} " + _TARGET + _TRIGGER + " >> {$pfb['runlog']} 2>&1 &\");",
        "exec(\"{$pfb['php']} " + _TARGET + _TRIGGER + " >> {$pfb['runlog']} 2>&1\");",
    ),
    _BgRow(
        "mwexec_bg-on-the-same-line",
        _IP_PAGE,
        'mwexec_bg("' + _SPAWN + " ugc {$maxmind_esc} >> {$pfb['extraslog']} 2>&1\");",
        'exec("' + _SPAWN + " ugc {$maxmind_esc} >> {$pfb['extraslog']} 2>&1\");",
    ),
    _BgRow(
        "daemon-p-on-the-same-line",
        _UPDATE,
        'mwexec("' + _DAEMON + " " + _SPAWN + ' pfb_trigger");',
        'mwexec("' + _SPAWN + ' pfb_trigger");',
    ),
    _BgRow(
        "mwexec_bg-one-physical-line-above",
        _UPDATE,
        'mwexec_bg("' + _DAEMON + '" .\n\t" ' + _SPAWN + ' forcecheck scope={$scope_esc}");',
        '$cmd = ("" .\n\t" ' + _SPAWN + ' forcecheck scope={$scope_esc}");',
    ),
    _BgRow(
        "mwexec_bg-two-physical-lines-above",
        _UPDATE,
        'mwexec_bg(\n\t"' + _DAEMON + '" .\n\t" ' + _SPAWN + ' pfb_trigger scope={$scope_esc}");',
        '$cmd = (\n\t"" .\n\t" ' + _SPAWN + ' pfb_trigger scope={$scope_esc}");',
    ),
)

_BG_IDS = [row.name for row in _BACKGROUNDED_ROWS]


@pytest.mark.parametrize("row", _BACKGROUNDED_ROWS, ids=_BG_IDS)
def test_backgrounded_composition_is_clean(row: _BgRow) -> None:
    """A backgrounded spawn cannot block the pass, so it is not in the defect class."""
    assert _find(row.clean, row.source) == [], f"{row.name}: a backgrounded composition was flagged"


@pytest.mark.parametrize("row", _BACKGROUNDED_ROWS, ids=_BG_IDS)
def test_same_composition_without_the_backgrounding_marker_is_flagged(row: _BgRow) -> None:
    """Remove only the backgrounding marker and the same line must flag."""
    violations = _find(row.flagged, row.source)
    assert len(violations) == 1, f"{row.name}: expected one violation, got {violations!r}"


def test_mwexec_bg_three_physical_lines_above_does_not_reach_the_composition() -> None:
    """The lookback window is exactly two preceding physical lines, not "somewhere above".

    Paired with the two-lines-above row (clean): a marker further up belongs to a
    different statement and must not exempt an unrelated blocking composition.
    """
    text = 'mwexec_bg("' + _DAEMON + '");\n$a = 1;\n$b = 2;\nexec("' + _SPAWN + ' al scheduled");'
    violations = _find(text, _UPDATE)
    assert len(violations) == 1
    assert violations[0].line == 4


# --------------------------------------------------------------------------- #
# The allowlist: seven entries, each load-bearing. Every one gets three rows --
# the real line is clean, a near-miss in the SAME file still flags (needle-
# scoped, not file-scoped), and emptying `_ALLOWLIST` brings the real line back
# (so a dead entry cannot rot unnoticed).
# --------------------------------------------------------------------------- #


class _AllowRow(NamedTuple):
    """One `_ALLOWLIST` entry: its real line, and a near-miss that must still flag."""

    entry: str
    source: str
    clean: str
    variant: str


_ALLOWLIST_ROWS: tuple[_AllowRow, ...] = (
    _AllowRow(
        # The bounded shell seam: interpreter AND target token on one line, so the
        # allowlist entry is the only thing keeping it clean.
        "pfblockerng.sh/pfb_reentry",
        _SH,
        '\t"${pathtimeout}" -s TERM -k 5 "${_pfbre_tmo}" "${pathphp}" "${pathpfbphp}" "$@"',
        '\t"${pathphp}" "${pathpfbphp}" "$@"',
    ),
    _AllowRow(
        "pfblockerng.inc/$pfb_tick_cmd",
        _INC,
        '\t$pfb_tick_cmd = "' + _SPAWN + ' cron-tick >> {$log} 2>&1";',
        '\t$tick_command = "' + _SPAWN + ' cron-tick >> {$log} 2>&1";',
    ),
    _AllowRow(
        "pfblockerng_apply.inc/$pfb_cmd",
        _APPLY,
        '\t\t$pfb_cmd = "' + _SPAWN + ' {$type} >/dev/null 2>&1";',
        '\t\t$widget_cmd = "' + _SPAWN + ' {$type} >/dev/null 2>&1";',
    ),
    _AllowRow(
        "pfblockerng_install.inc/$pfb_cmd_esc",
        _INSTALL,
        '\t\t$pfb_cmd_esc = "' + _SPAWN + " '{$type}' >/dev/null 2>&1\";",
        '\t\t$stale_needle = "' + _SPAWN + " '{$type}' >/dev/null 2>&1\";",
    ),
    _AllowRow(
        "pfblockerng_install.inc/$pfb_cmd",
        _INSTALL,
        '\t\t\t$pfb_cmd = "' + _SPAWN + ' {$type} >/dev/null 2>&1";',
        '\t\t\t$widget_cmd = "' + _SPAWN + ' {$type} >/dev/null 2>&1";',
    ),
    _AllowRow(
        "pfblockerng_update.php/$pfb_cmd",
        _UPDATE,
        '$pfb_cmd = "' + _SPAWN + " cron-tick >> {$pfb['log']} 2>&1\";",
        '$cron_needle = "' + _SPAWN + " cron-tick >> {$pfb['log']} 2>&1\";",
    ),
    _AllowRow(
        "pfblockerng.widget.php/$pfb_cmd",
        _WIDGET,
        '\t\t\t$pfb_cmd = "' + _SPAWN + ' {$type} >/dev/null 2>&1";',
        '\t\t\t$widget_clear_cmd = "' + _SPAWN + ' {$type} >/dev/null 2>&1";',
    ),
)

_ALLOW_IDS = [row.entry for row in _ALLOWLIST_ROWS]


def test_allowlist_holds_exactly_the_seven_recorded_entries() -> None:
    """Seven entries, no more: a new one is a decision, never a convenience."""
    assert len(crb._ALLOWLIST) == 7


@pytest.mark.parametrize("row", _ALLOWLIST_ROWS, ids=_ALLOW_IDS)
def test_allowlisted_line_is_clean(row: _AllowRow) -> None:
    """Each recorded entry's real line scans clean."""
    assert _find(row.clean, row.source) == [], f"{row.entry}: the allowlisted line was flagged"


@pytest.mark.parametrize("row", _ALLOWLIST_ROWS, ids=_ALLOW_IDS)
def test_allowlist_entry_does_not_exempt_the_whole_file(row: _AllowRow) -> None:
    """A near-miss in the same file still flags: entries are needle-scoped, not file-scoped."""
    violations = _find(row.variant, row.source)
    assert len(violations) == 1, f"{row.entry}: the near-miss variant was not flagged ({violations!r})"


@pytest.mark.parametrize("row", _ALLOWLIST_ROWS, ids=_ALLOW_IDS)
def test_allowlist_entry_does_not_exempt_same_basename_elsewhere(row: _AllowRow) -> None:
    """An exemption owns one repository-relative path, not every matching basename."""
    collision = f"src/same-basename/{Path(row.source).name}"
    violations = _find(row.clean, collision)
    assert len(violations) == 1, f"{row.entry}: exemption leaked into {collision} ({violations!r})"


@pytest.mark.parametrize("row", _ALLOWLIST_ROWS, ids=_ALLOW_IDS)
def test_allowlist_entry_is_load_bearing(row: _AllowRow, monkeypatch: pytest.MonkeyPatch) -> None:
    """Emptying `_ALLOWLIST` brings the line back -- the entry, not the token rule, exempts it."""
    monkeypatch.setattr(crb, "_ALLOWLIST", type(crb._ALLOWLIST)())
    violations = _find(row.clean, row.source)
    assert len(violations) == 1, f"{row.entry}: the entry is inert, delete it or fix the needle"


class _InertRow(NamedTuple):
    """A single-token line that needs no entry, and the composition an entry would hide."""

    name: str
    source: str
    single_token: str
    inlined: str


_NO_ENTRY_ROWS: tuple[_InertRow, ...] = (
    _InertRow(
        "pfblockerng.inc/PFB_REENTRY_SCRIPT",
        _INC,
        "\tdefine('PFB_REENTRY_SCRIPT', '" + _TARGET + "');",
        '\t$cmd = "' + _SPAWN + ' {$verb}";',
    ),
    _InertRow(
        "pfblockerng.sh/pathpfbphp",
        _SH,
        "\tpathpfbphp=" + _TARGET,
        '\t"${pathphp}" ' + _TARGET + " asn",
    ),
)

_NO_ENTRY_IDS = [row.name for row in _NO_ENTRY_ROWS]


@pytest.mark.parametrize("row", _NO_ENTRY_ROWS, ids=_NO_ENTRY_IDS)
def test_single_token_line_needs_no_allowlist_entry(row: _InertRow, monkeypatch: pytest.MonkeyPatch) -> None:
    """Definition lines name only the target half, so listing them would be a hazard.

    Each is clean with NO allowlist at all (first assertion), so an entry for it would
    never be load-bearing. It would, however, keep matching if someone later inlined the
    interpreter into that same line -- silently exempting exactly the composition this
    checker exists to catch. The second assertion pins that inlined form as a violation
    under the REAL allowlist, which only holds while no entry covers it.
    """
    monkeypatch.setattr(crb, "_ALLOWLIST", type(crb._ALLOWLIST)())
    assert _find(row.single_token, row.source) == [], f"{row.name}: a target-only line was flagged"
    monkeypatch.undo()
    violations = _find(row.inlined, row.source)
    assert len(violations) == 1, f"{row.name}: the inlined-literal form was not flagged ({violations!r})"


def test_allowlist_needle_on_a_different_line_leaves_that_line_flagged() -> None:
    """Hostile row: the needle exempts ITS line, never every line of the file."""
    text = '\t\t\t$pfb_cmd = "' + _SPAWN + ' {$type} >/dev/null 2>&1";\n\t\texec("' + _SPAWN + ' dc scheduled");'
    violations = _find(text, _WIDGET)
    assert len(violations) == 1
    assert violations[0].line == 2


# --------------------------------------------------------------------------- #
# Hostile inputs (the checker is a new parser -- every row has an expected
# outcome). Each clean expectation is paired with the input that must flag.
# --------------------------------------------------------------------------- #


def test_hostile_empty_text_is_clean() -> None:
    assert _find("") == []


def test_hostile_interpreter_token_alone_is_clean() -> None:
    """No target token, no composition -- paired with the same token plus the target."""
    assert _find("$pfb['php'] = '" + _PHP_BIN + "';") == []
    assert _find("\tpathphp=" + _PHP_BIN, _SH) == []
    assert len(_find("exec(\"{$pfb['php']} " + _TARGET + ' al");')) == 1


def test_hostile_target_token_alone_is_clean() -> None:
    """No interpreter token, no composition -- paired with the composed form."""
    assert _find("install_cron_job('pfblockerng.php cron ', FALSE);", _INC) == []
    assert _find("\tpathpfbphp=" + _TARGET, _SH) == []
    assert len(_find(_SPAWN + " asn", _SH)) == 1


def test_hostile_commented_out_composition_is_still_flagged() -> None:
    """A comment is not an exemption -- the allowlist is.

    A commented-out spawn is a copy-paste source for the next unbounded caller, and
    silencing it would let any violation be laundered through a `//`. Paired with the
    commented ROUTED form, which stays clean because it composes no command at all.
    """
    assert len(_find("// exec('" + _SPAWN + " al scheduled');", _APPLY)) == 1
    assert len(_find("# " + _SPAWN + " asn", _SH)) == 1
    assert _find("// pfb_reentry_exec('al', ['scheduled']);", _APPLY) == []


def test_hostile_longer_name_is_not_the_target_token() -> None:
    """`pathpfbphpx` is a different variable; only the exact token counts."""
    assert _find('\t"${pathphp}" "${pathpfbphpx}" bls', _SH) == []
    assert len(_find('\t"${pathphp}" "${pathpfbphp}" bls', _SH)) == 1


def test_hostile_crlf_line_endings_keep_line_numbers_and_matching() -> None:
    """CRLF must not shift the reported line nor ride along in the snippet."""
    text = "<?php\r\n\texec('" + _SPAWN + " al scheduled');\r\n"
    violations = _find(text, _APPLY)
    assert len(violations) == 1
    assert violations[0].line == 2
    assert not violations[0].snippet.endswith("\r")


def test_hostile_hundred_kilobyte_single_line_completes_promptly() -> None:
    """A pathological line must not backtrack catastrophically.

    The wall-clock bound is a salvage cap, not a performance assertion: the matchers are
    substring/simple-regex with no nesting, so a run that overshoots it is stuck rather
    than slow.
    """
    line = "exec('" + _SPAWN + " al scheduled " + ("a" * 100_000) + "');"
    start = time.monotonic()
    violations = _find(line, _APPLY)
    elapsed = time.monotonic() - start
    assert len(violations) == 1
    assert elapsed < _SALVAGE_CAP_S, (
        f"salvage cap expired / stuck or environment: scanning one {len(line)}-byte line took "
        f"{elapsed:.2f}s against a {_SALVAGE_CAP_S:.0f}s cap -- the matcher is backtracking, "
        "or the run is stuck / the environment is broken, not a behavioural failure"
    )


def test_hostile_non_utf8_bytes_do_not_crash_the_scan(tmp_path: Path) -> None:
    """Undecodable bytes are replaced, never fatal -- paired with a clean undecodable file."""
    bad = tmp_path / "bad.inc"
    bad.write_bytes(b"\xff\xfe not utf-8\nexec('" + _SPAWN.encode() + b" al scheduled');\n")
    assert crb.main([str(bad)]) == 1

    clean = tmp_path / "clean.inc"
    clean.write_bytes(b"\xff\xfe not utf-8\npfb_reentry_exec('al', ['scheduled']);\n")
    assert crb.main([str(clean)]) == 0


def test_hostile_tabs_do_not_defeat_needle_or_token_matching() -> None:
    """Tabs around `=` and inside the command change nothing on either side."""
    clean = '\t\t\t$pfb_cmd\t=\t"' + _PHP_BIN + "\t" + _TARGET + '\t{$type}";'
    assert _find(clean, _WIDGET) == []
    flagged = '\t\t\t$widget_cmd\t=\t"' + _PHP_BIN + "\t" + _TARGET + '\t{$type}";'
    assert len(_find(flagged, _WIDGET)) == 1
    assert len(_find("\t" + _PHP_BIN + "\t" + _TARGET + "\tasn", _SH)) == 1


# --------------------------------------------------------------------------- #
# CLI: exit codes both ways, the red canary, and fail-closed.
# --------------------------------------------------------------------------- #


def test_main_returns_1_on_a_violating_file_and_names_the_seam(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "x.inc"
    f.write_text("exec('" + _SPAWN + " al scheduled');\n")
    assert crb.main([str(f)]) == 1
    err = capsys.readouterr().err
    assert f"{f}:1:" in err
    assert "not bounded" in err
    assert "pfb_reentry_exec" in err
    assert "pfb_reentry()" in err


def test_main_returns_0_on_a_clean_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "x.inc"
    f.write_text("pfb_reentry_exec('al', ['scheduled']);\n")
    assert crb.main([str(f)]) == 0
    assert capsys.readouterr().err == ""


def test_main_returns_0_on_an_empty_file(tmp_path: Path) -> None:
    f = tmp_path / "empty.sh"
    f.write_text("")
    assert crb.main([str(f)]) == 0


def test_self_test_red_canary_exits_zero() -> None:
    """`--self-test` proves the matcher still fires before the real scan is believed."""
    assert crb.main(["--self-test"]) == 0


def test_self_test_exits_1_when_the_matcher_is_defeated(monkeypatch: pytest.MonkeyPatch) -> None:
    """A canary that cannot go red is decoration: a matcher that finds nothing must fail it."""
    monkeypatch.setattr(crb, "find_violations", lambda text, source: [])
    assert crb.main(["--self-test"]) == 1


def test_self_test_exits_zero_as_a_process() -> None:
    """The gate runs the script, not the function -- pin the process exit code too."""
    result = subprocess.run(
        [sys.executable, str(_TOOL), "--self-test"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"


def test_main_fails_closed_when_the_default_scan_set_is_unenumerable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A policy gate must FAIL CLOSED: an empty default scan set is exit 2, never 0.

    Reproduced the way `tests/test_noopener_check.py` does it -- argless `main()` from a
    directory that is not a checkout, so `git ls-files` enumerates nothing.
    """
    monkeypatch.chdir(tmp_path)
    assert crb.main([]) == 2
    assert "failing closed" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Tree scan -- issue #2016's red->green proof. RED: the 8 blocking sites the
# brief enumerates. GREEN: 0, once every site routes through its seam.
# --------------------------------------------------------------------------- #


def _tracked_src_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "src"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return sorted(p for p in out.split("\0") if p and p.endswith((".php", ".inc", ".sh")))


def test_src_tree_is_bounded() -> None:
    """Every tracked src/ .php/.inc/.sh file composes no unbounded pfblockerng.php re-entry.

    The definitive post-fix expectation. RED before the seams land (the 8 sites in
    pfblockerng_apply.inc, pfblockerng_extra.inc and pfblockerng.sh); GREEN after. The
    assertion names the offending FILES, never their line numbers, so an unrelated edit
    to one of them cannot rot this row.
    """
    files = _tracked_src_files()
    assert len(files) >= 10  # sanity: the package tree must be present

    violations: list[Any] = []
    for rel_path in files:
        text = (_REPO_ROOT / rel_path).read_text(encoding="utf-8", errors="replace")
        violations.extend(crb.find_violations(text, rel_path))

    assert violations == [], (
        f"{len(violations)} unbounded nested pfblockerng.php re-entry site(s) in "
        + ", ".join(sorted({v.source for v in violations}))
        + " -- route each through pfb_reentry_exec() (PHP) or pfb_reentry() (shell)"
    )


def test_main_over_the_default_scan_set_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate's own argless invocation -- what the hook, CI and run-gates.sh run."""
    monkeypatch.chdir(_REPO_ROOT)
    assert crb.main([]) == 0
