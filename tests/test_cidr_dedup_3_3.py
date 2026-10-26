"""Release/3.3: cross-list IP de-duplication keeps rows that earlier lists only partly cover.

``duplicate()`` in ``pfblockerng.sh`` strips from each list the rows an earlier list
already blocks. grepcidr 2.0, the build pfSense ships, judges a row by its address
alone and ignores the row's own prefix length, so ``grepcidr -vf`` removed a whole
``185.192.100.0/23`` because an earlier list held ``185.192.100.0/24``, and the other
half of the /23 was then blocked by nothing (pfBlockerNG issue #3606). A row may go
only when a single earlier row at least as wide contains it.

The shipped shell functions run under ``sh`` against a grepcidr 2.0 stand-in, since
CI installs no grepcidr, and against the real binary wherever one is installed.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "src" / "usr" / "local" / "pkg" / "pfblockerng" / "pfblockerng.sh"

# Every top-level function body, and every /tmp scratch path the script declares.
_FUNCTION = re.compile(r"^\w+\(\) ?\{\n.*?^\}\n", re.MULTILINE | re.DOTALL)
_SCRATCH = re.compile(r"^(\w+)=/tmp/(pfbtemp\d+_\$rvar)$", re.MULTILINE)

_PLACEHOLDER = "127.1.7.7"

# grepcidr 2.0 for `-vf PATTERNS FILE`, as probed on Debian's grepcidr 2.0-2 (the same
# code as pfSense's grepcidr-2.0_1): a row is judged by its address only, its /prefix
# ignored; a row of an address family absent from the patterns is treated as holding
# no address and is omitted, as is every row when no pattern is valid; an unmatched
# row is echoed byte for byte; exit 0 when anything was printed, else 1.
_GREPCIDR_20 = f"""#!{sys.executable}
import ipaddress
import sys

_, flag, patterns, rows = sys.argv
assert flag == "-vf", flag
nets = []
with open(patterns, "rb") as fh:
    for raw in fh:
        text = raw.decode("latin-1").strip()
        if text:
            try:
                nets.append(ipaddress.ip_network(text, strict=False))
            except ValueError:
                print("grepcidr: Not a valid pattern:", text, file=sys.stderr)
families = {{net.version for net in nets}}
printed = False
with open(rows, "rb") as fh:
    for raw in fh:
        try:
            address = ipaddress.ip_address(raw.decode("latin-1").rstrip("\\r\\n").split("/")[0])
        except ValueError:
            continue
        if address.version in families and not any(address in net for net in nets):
            sys.stdout.buffer.write(raw)
            printed = True
sys.exit(0 if printed else 1)
"""


@pytest.fixture(params=["stand-in", "installed"])
def grepcidr(request: pytest.FixtureRequest, tmp_path: Path) -> str:
    """The grepcidr every case runs against: the 2.0 stand-in, then the real binary."""
    if request.param == "installed":
        installed = shutil.which("grepcidr")
        if installed is None:
            pytest.skip("grepcidr is not installed on this host")
        return installed
    stand_in = tmp_path / "grepcidr"
    stand_in.write_text(_GREPCIDR_20, encoding="utf-8")
    stand_in.chmod(0o755)
    return str(stand_in)


def _prelude(work: Path, grepcidr: str) -> str:
    """Shell text defining the script's functions over paths inside ``work``."""
    script = _SCRIPT.read_text(encoding="utf-8")
    scratch = work / "scratch"
    scratch.mkdir()
    lines = ["rvar=test"]
    lines += [f"{name}={shlex.quote(str(scratch))}/{base}" for name, base in _SCRATCH.findall(script)]
    lines += [
        f"pathgrepcidr={shlex.quote(grepcidr)}",
        f"errorlog={shlex.quote(str(work / 'error.log'))}",
        f"masterfile={shlex.quote(str(work / 'masterfile'))}",
        f"mastercat={shlex.quote(str(work / 'mastercat'))}",
        f"pfbdeny={shlex.quote(str(work / 'deny'))}/",
        f"pfborig={shlex.quote(str(work / 'original'))}/",
        f"ip_placeholder={_PLACEHOLDER}",
    ]
    return "\n".join(lines) + "\n" + "".join(_FUNCTION.findall(script))


def _sh(work: Path, grepcidr: str, command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", "-c", _prelude(work, grepcidr) + command],
        env={**os.environ, "LC_ALL": "C"},
        capture_output=True,
        text=True,
        check=False,
    )


@dataclass
class _Outcome:
    deny: str
    masterfile: str
    errorlog: str
    scratch_left: list[str]
    stderr: str


def _duplicate(tmp_path: Path, grepcidr: str, earlier: list[str], later: list[str]) -> _Outcome:
    """Run ``duplicate()`` for list ``Later_v4`` after list ``Earlier_v4`` was processed."""
    work = tmp_path / "box"
    (work / "deny").mkdir(parents=True)
    (work / "original").mkdir()
    rows = "".join(f"{row}\n" for row in later)
    (work / "masterfile").write_text("".join(f"Earlier_v4 {row}\n" for row in earlier), encoding="utf-8")
    (work / "mastercat").write_text("".join(f"{row}\n" for row in earlier), encoding="utf-8")
    (work / "deny" / "Later_v4.txt").write_text(rows, encoding="utf-8")
    (work / "original" / "Later_v4.orig").write_text(rows, encoding="utf-8")

    proc = _sh(work, grepcidr, "alias=Later_v4\nduplicate\n")
    assert proc.returncode == 0, proc.stderr
    errorlog = work / "error.log"
    return _Outcome(
        deny=(work / "deny" / "Later_v4.txt").read_text(encoding="utf-8"),
        masterfile=(work / "masterfile").read_text(encoding="utf-8"),
        errorlog=errorlog.read_text(encoding="utf-8") if errorlog.exists() else "",
        scratch_left=sorted(p.name for p in (work / "scratch").iterdir()),
        stderr=proc.stderr,
    )


def _expect(outcome: _Outcome, earlier: list[str], kept: list[str]) -> None:
    deny = "".join(f"{row}\n" for row in kept) or f"{_PLACEHOLDER}\n"
    master = "".join(f"Earlier_v4 {row}\n" for row in earlier) + "".join(f"Later_v4 {row}\n" for row in kept)
    assert outcome.deny == deny, f"deny file: expected {deny!r}, got {outcome.deny!r}\n{outcome.stderr}"
    assert outcome.masterfile == master, f"masterfile: expected {master!r}, got {outcome.masterfile!r}"
    assert outcome.errorlog == "", f"unexpected error log: {outcome.errorlog!r}"
    assert outcome.scratch_left == [], f"scratch files left behind: {outcome.scratch_left}"


@pytest.mark.parametrize(
    ("earlier", "later", "kept"),
    [
        pytest.param(["185.192.100.0/24"], ["185.192.100.0/23"], ["185.192.100.0/23"], id="v4-cidr-wider-than-earlier"),
        pytest.param(["10.0.0.0"], ["10.0.0.0/8"], ["10.0.0.0/8"], id="v4-cidr-over-earlier-host"),
        pytest.param(
            ["192.0.2.0/24", "2001:db8::/48"], ["2001:db8::/32"], ["2001:db8::/32"], id="v6-cidr-wider-than-earlier"
        ),
        pytest.param(
            ["185.192.100.0/24", "10.0.0.0"],
            ["185.192.100.7", "10.0.0.0/8", "198.51.100.0/24", "185.192.100.0/23"],
            ["10.0.0.0/8", "185.192.100.0/23", "198.51.100.0/24"],
            id="partial-and-full-cover-in-one-list",
        ),
    ],
)
def test_a_row_only_partly_covered_by_earlier_lists_is_kept(
    tmp_path: Path, grepcidr: str, earlier: list[str], later: list[str], kept: list[str]
) -> None:
    """An earlier, narrower row leaves the rest of a wider row unblocked: the wide row stays."""
    _expect(_duplicate(tmp_path, grepcidr, earlier, later), earlier, kept)


@pytest.mark.parametrize(
    ("earlier", "later", "kept"),
    [
        pytest.param(["185.192.100.0/23"], ["185.192.101.0/24", "198.51.100.0/24"], ["198.51.100.0/24"], id="v4-cidr"),
        pytest.param(["192.0.2.0/24"], ["192.0.2.55", "203.0.113.9"], ["203.0.113.9"], id="v4-host"),
        pytest.param(["192.0.2.0/24"], ["192.0.2.0/24"], [], id="v4-equal-row"),
        pytest.param(["2001:db8::/32"], ["2001:db8:1::/48", "2001:db8::1"], [], id="v6-cidr-and-host"),
    ],
)
def test_a_row_fully_inside_one_earlier_row_is_removed(
    tmp_path: Path, grepcidr: str, earlier: list[str], later: list[str], kept: list[str]
) -> None:
    """Full containment by one earlier row at least as wide still de-duplicates; an emptied
    list carries the placeholder."""
    _expect(_duplicate(tmp_path, grepcidr, earlier, later), earlier, kept)


def test_a_row_wider_than_every_earlier_row_passes_through(tmp_path: Path, grepcidr: str) -> None:
    """No earlier row is wide enough to cover the /16, so nothing may judge it -- in particular
    not a grepcidr run over an empty pattern set, which prints nothing at all -- while the host
    inside the earlier /24 in the same list is still removed."""
    earlier = ["10.0.5.0/24"]
    _expect(_duplicate(tmp_path, grepcidr, earlier, ["10.0.0.0/16", "10.0.5.7"]), earlier, ["10.0.0.0/16"])


_ROWS = (
    b"203.0.113.0/24\n192.0.2.9\n# no address\n10.0.0.0\n2001:db8:5::/48\n203.0.113.0/24\n"
    b"2001:db8::1\n8.8.4.4\r\n198.51.100.77\n10.1.0.0/16\n2001:db8::/32\n2001:db9::/48\n9.9.9.9"
)


@pytest.mark.parametrize(
    ("patterns", "expected"),
    [
        pytest.param(
            b"192.0.2.0/24\n2001:db8::/32\n10.0.0.0\n\n   \n198.51.100.0/24\r\n",
            b"203.0.113.0/24\n203.0.113.0/24\n8.8.4.4\r\n10.1.0.0/16\n2001:db9::/48\n9.9.9.9",
            id="both-families",
        ),
        pytest.param(
            b"192.0.2.0/24\n10.0.0.0\n\n   \n198.51.100.0/24\r\n",
            b"203.0.113.0/24\n203.0.113.0/24\n8.8.4.4\r\n10.1.0.0/16\n9.9.9.9",
            id="v4-patterns-only",
        ),
    ],
)
def test_without_partial_overlap_the_output_is_byte_identical_to_grepcidr(
    tmp_path: Path, grepcidr: str, patterns: bytes, expected: bytes
) -> None:
    """Order, duplicates, CR line ends, address-less lines, rows of a family the patterns
    lack and an unterminated last line all come out exactly as the plain ``grepcidr -vf``
    call left them."""
    work = tmp_path / "box"
    work.mkdir()
    (work / "patterns").write_bytes(patterns)
    (work / "rows").write_bytes(_ROWS)

    old = subprocess.run(
        [grepcidr, "-vf", str(work / "patterns"), str(work / "rows")], capture_output=True, check=False
    )
    assert old.stdout == expected, f"plain grepcidr: expected {expected!r}, got {old.stdout!r}"

    args = " ".join(shlex.quote(str(work / name)) for name in ("patterns", "rows", "out"))
    proc = _sh(work, grepcidr, f"pfb_cidr_dedup {args}\n")
    assert proc.returncode == 0, proc.stderr
    out = (work / "out").read_bytes()
    assert out == expected, f"pfb_cidr_dedup: expected {expected!r}, got {out!r}"
    leftovers = sorted(p.name for p in work.iterdir())
    assert leftovers == ["out", "patterns", "rows", "scratch"], f"files left behind: {leftovers}"


@pytest.mark.parametrize(
    "later",
    [
        pytest.param(["203.0.113.0/24", "192.0.2.9"], id="cidr-and-host"),
        pytest.param(["203.0.113.9", "192.0.2.9"], id="hosts-only"),
    ],
)
def test_a_grepcidr_failure_keeps_the_list_whole_and_logs_it(tmp_path: Path, later: list[str]) -> None:
    """grepcidr exiting 2 is an error, not a verdict: the list keeps every row rather than
    being emptied down to the placeholder, and the error log names the list."""
    failing = tmp_path / "grepcidr"
    failing.write_text("#!/bin/sh\necho 'grepcidr: Out of memory' >&2\nexit 2\n", encoding="utf-8")
    failing.chmod(0o755)
    earlier = ["192.0.2.0/24"]

    outcome = _duplicate(tmp_path, str(failing), earlier, later)

    kept = sorted(later)
    assert outcome.deny == "".join(f"{row}\n" for row in kept), outcome.stderr
    assert outcome.masterfile == "Earlier_v4 192.0.2.0/24\n" + "".join(f"Later_v4 {row}\n" for row in kept)
    assert "Later_v4" in outcome.errorlog, f"error log does not name the list: {outcome.errorlog!r}"
    assert outcome.scratch_left == [], f"scratch files left behind: {outcome.scratch_left}"


def test_a_grepcidr_failure_midway_keeps_the_list_whole(tmp_path: Path, grepcidr: str) -> None:
    """One failed grepcidr run is not outvoted by a later run that succeeds: the list is kept
    whole and the failure logged, whichever group of rows the failing run was judging."""
    marker = tmp_path / "failed-once"
    flaky = tmp_path / "grepcidr-flaky"
    flaky.write_text(
        f"#!/bin/sh\nif [ ! -e {shlex.quote(str(marker))} ]; then\n"
        f"\t: > {shlex.quote(str(marker))}; echo 'grepcidr: Out of memory' >&2; exit 2\nfi\n"
        f'exec {shlex.quote(grepcidr)} "$@"\n',
        encoding="utf-8",
    )
    flaky.chmod(0o755)
    earlier = ["192.0.2.0/24", "10.0.0.0/7"]

    # Two groups, two grepcidr runs: the /8 against the /7, the host against both patterns.
    outcome = _duplicate(tmp_path, str(flaky), earlier, ["203.0.113.9", "10.0.0.0/8"])

    assert marker.exists(), "the injected failure never ran"
    assert outcome.deny == "10.0.0.0/8\n203.0.113.9\n", outcome.stderr
    assert outcome.masterfile == (
        "Earlier_v4 192.0.2.0/24\nEarlier_v4 10.0.0.0/7\nLater_v4 10.0.0.0/8\nLater_v4 203.0.113.9\n"
    )
    assert "Later_v4" in outcome.errorlog, f"error log does not name the list: {outcome.errorlog!r}"
    assert outcome.scratch_left == [], f"scratch files left behind: {outcome.scratch_left}"


@pytest.mark.parametrize(
    "patterns",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\n   \n\t\n", id="blank-lines"),
        pytest.param(b"\r\n", id="cr-only-line"),
    ],
)
@pytest.mark.parametrize(
    "rows",
    [
        pytest.param(b"10.0.0.0/8\n192.0.2.9\n2001:db8::/32\n", id="cidr-and-host-rows"),
        pytest.param(b"192.0.2.9\n2001:db8::1\n", id="host-rows-only"),
    ],
)
def test_a_pattern_file_without_patterns_keeps_every_row(
    tmp_path: Path, grepcidr: str, patterns: bytes, rows: bytes
) -> None:
    """grepcidr given no usable pattern prints nothing at all (issue #1279), so with nothing to
    judge against, every row, CIDR or host, either family, comes back untouched."""
    work = tmp_path / "box"
    work.mkdir()
    (work / "patterns").write_bytes(patterns)
    (work / "rows").write_bytes(rows)

    args = " ".join(shlex.quote(str(work / name)) for name in ("patterns", "rows", "out"))
    proc = _sh(work, grepcidr, f"pfb_cidr_dedup {args}\n")

    assert proc.returncode == 0, proc.stderr
    out = (work / "out").read_bytes()
    assert out == rows, f"pfb_cidr_dedup: expected {rows!r}, got {out!r}"
    leftovers = sorted(p.name for p in work.iterdir())
    assert leftovers == ["out", "patterns", "rows", "scratch"], f"files left behind: {leftovers}"


@pytest.mark.parametrize(
    ("pattern", "dropped", "control"),
    [
        pytest.param("185.192.100.0/24", "185.192.100.0/23", "198.51.100.1", id="v4-row-prefix-ignored"),
        pytest.param("10.0.0.0", "10.0.0.0/8", "198.51.100.1", id="v4-row-prefix-ignored-by-host"),
        pytest.param("2001:db8::/48", "2001:db8::/32", "2001:db9::1", id="v6-row-prefix-ignored"),
        pytest.param("192.0.2.0/24", "2001:db8::1", "198.51.100.1", id="row-family-absent-from-patterns"),
    ],
)
def test_grepcidr_drops_these_rows_outright(
    tmp_path: Path, grepcidr: str, pattern: str, dropped: str, control: str
) -> None:
    """The grepcidr 2.0 behaviour the de-duplication works around, pinned for the stand-in
    and, where installed, the real binary: the row goes although the pattern does not
    cover it, while an unrelated row of the pattern's family survives."""
    (tmp_path / "patterns").write_text(f"{pattern}\n", encoding="utf-8")
    (tmp_path / "rows").write_text(f"{dropped}\n{control}\n", encoding="utf-8")
    proc = subprocess.run(
        [grepcidr, "-vf", str(tmp_path / "patterns"), str(tmp_path / "rows")], capture_output=True, text=True, check=False
    )
    assert (proc.stdout, proc.returncode) == (f"{control}\n", 0)
