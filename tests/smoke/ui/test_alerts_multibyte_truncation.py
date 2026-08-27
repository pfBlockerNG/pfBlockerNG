"""Tier-A ``ui_render`` coverage for issues #1815, #2007, and #2009: Alerts
row-cell truncation uses the Unified widths and matching UTF-8 character units.
Four values straddle their character cuts and remain valid; a fifth value is
long in bytes but short in characters and renders complete without an ellipsis.

Scenario (self-encapsulated: log truncated back to its exact pre-test byte
size in teardown, loud assertion that the restore took):
  Given four ``unified.log`` rows -- one ``Block,``-prefixed IP row, one
        ``DNSBL_CNAME`` row carrying blocked-domain and CNAME values, one
        verbatim DNS-reply row with a truncating value, and one DNS-reply row
        whose multibyte domain reaches the old byte gate but stays below the
        character gate -- with each truncating value shaped
        ``<marker><'a' padding><'é'><tail>`` so its multibyte character's lead
        byte lands exactly on that value's truncation cut
        (see ``pfblockerng_alerts.php``'s ``convert_ip_log`` /
        ``convert_dnsbl_log`` / ``convert_dns_reply_log``)
  When  GET ``pfblockerng_alerts.php?view=unified``
  Then  the Tier-A render oracle passes
  And   all five markers locate their rows
  And   the four long values render exact truncated prefixes and ellipses
  And   the code-point-short value renders complete without an ellipsis
  And   each truncated value's multibyte character survives whole

``?view=unified`` needs no config precondition (no ``pfb_dnsbl`` toggle, no
sinkhole VIP): the Unified loop reads only ``unified.log``, and its
``$pfbunicnt`` render cap defaults to 200 (pfblockerng_alerts.php, `case
'unified'`). The IP row's logged Feed Name (site 9, ``$fields[15]``) is
written into the row UNCONDITIONALLY from the raw CSV value regardless of
whether the underlying feed/alias re-attribution lookup hits or misses
(pfblockerng_alerts.php, `$fields[15] = $attribution['field15'];`) -- so no
on-disk feed-file fixture is needed for this row to exercise its truncation
site; the row renders a delisted/"Not listed!" state harmlessly either way.

The IP row deliberately targets the logged Feed Name (``$fields[15]``) rather
than the ``rhost`` (gethostbyaddr-resolved hostname) cell, which is the more
obvious candidate: the former discarded ``$fields[16]`` default/truncation
block was removed by issue #2008, and the row's actually-rendered
resolved-hostname cell comes from ``$hostname['src']`` / ``$hostname['dst']``,
a SEPARATE copy captured earlier, straight from the untruncated original.
Asserting on ``rhost`` here would be a vacuous check, and this module cannot be
executed locally to catch that.

HONESTY NOTE (no local smoke VM in this environment, precedent: commit
9fd4bfce, issue #1814): this module has NOT been executed against a live
smoke VM. It is proven ``--collect-only`` clean and ruff/mypy clean only. Do
not read a green run into this report -- there isn't one yet.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import pytest

from .render_oracle import PhpErrorLogGuard, evaluate_render
from .webui import row_containing

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

PFB_LOGDIR = "/var/log/pfblockerng"
UNIFIED_LOG = f"{PFB_LOGDIR}/unified.log"
ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"
UNIFIED_VIEW = f"{ALERTS_PAGE}?view=unified"

FIXED_TS = "2030-06-01 00:00:00"


def _mb_straddle(cut: int, marker: str, tail: str, mb_char: str = "é") -> str:
    """A string whose CUT-th byte (index CUT-1) is the LEAD byte of ``mb_char``.

    A byte-based ``substr($v, 0, cut)`` keeps that lead byte alone (a dangling,
    invalid sequence); a character-based ``mb_substr($v, 0, cut, 'UTF-8')``
    keeps ``mb_char`` whole. ``marker`` is a short ASCII prefix that survives
    inside the retained text, so :func:`row_containing` can locate the row.
    """
    return marker + "a" * (cut - 1 - len(marker)) + mb_char + tail


# Site 9 (convert_ip_log, logged Feed Name $fields[15]): cut=16, gate >=17.
IP_MARKER = "SMKIP09"
IP_FEED = _mb_straddle(16, IP_MARKER, "trailingfeed")

# Site 2 (convert_dnsbl_log, blocked domain $f2): Unified cut=39; below wide gate 60.
DNSBL_MARKER = "SMKDNSBL02"
DNSBL_DOMAIN = _mb_straddle(39, DNSBL_MARKER, "tail")

# Site 3 (convert_dnsbl_log, CNAME evaluated domain $f7): Unified cut=31; below wide gate 52.
CNAME_MARKER = "SMKDNSBL03"
CNAME_DOMAIN = _mb_straddle(31, CNAME_MARKER, "tail")

# Site 7 (convert_dns_reply_log, replied domain $fields[6]): Unified cut=29; below wide gate 45.
REPLY_MARKER = "SMKREPLY07"
REPLY_DOMAIN = _mb_straddle(29, REPLY_MARKER, "tail")

# unified.log row shapes (test_alerts_render_verify.py's _ip_line/_dnsbl_line/
# _dns_reply_line document the exact CSV layouts these mirror):
#   IP:         Block,ts,rule,real_iface,friendly_iface,action,ipv,proto_id,proto,
#               src_ip,dst_ip,src_port,dst_port,dir,geoip,alias,ip_eval,feed,
#               rhost,chost,asn,asn_domain,asn_name,dup
#   DNSBL:      DNSBL-python,ts,domain,src_ip,agent,block_mode,group,final_domain,feed,dup,qtype
#   DNS-reply:  DNS-reply,ts,reply_type,orig_record,final_record,ttl,domain,src_ip,dst,geoip
_IP_LINE = (
    f"Block,{FIXED_TS},100,em0,WAN,block,4,6,TCP,"
    f"192.0.2.201,10.0.0.5,12345,443,in,US,RVMbAlias,192.0.2.201,{IP_FEED},"
    "Unknown,Unknown,Unknown,,,+\n"
)
_DNSBL_LINE = "DNSBL-python,{},{},127.0.0.1,Python,DNSBL_CNAME,RVMbGroup,{},RVMbFeed,+,A\n".format(
    FIXED_TS, DNSBL_DOMAIN, CNAME_DOMAIN
)
_DNS_REPLY_LINE = f"DNS-reply,{FIXED_TS},A,A,A,300,{REPLY_DOMAIN},127.0.0.1,203.0.113.9,US\n"
CJK_REPLY_MARKER = "SMKREPLYCG"
CJK_REPLY_DOMAIN = CJK_REPLY_MARKER + "界" * 7
_DNS_REPLY_CHARACTER_GATE_LINE = f"DNS-reply,{FIXED_TS},A,A,A,300,{CJK_REPLY_DOMAIN},127.0.0.1,203.0.113.10,US\n"

_ALL_LINES = _IP_LINE + _DNSBL_LINE + _DNS_REPLY_LINE + _DNS_REPLY_CHARACTER_GATE_LINE


@pytest.fixture
def seeded_unified_rows(smoke_vm: SmokeVM) -> Iterator[tuple[tuple[str, str, int | None], ...]]:
    """Append four rows carrying five values; restore log size after.

    Yields the markers it actually seeded, so the test iterates over the
    fixture's own output rather than module constants -- the assertions cannot
    run against data this fixture did not write.

    Self-encapsulated (this module is ``ui_render``-only, so the shared
    ``_ui_pfb_isolation`` restore fixture does not run for it): the log
    truncates back to its exact pre-test size, failing loudly if the restore
    did not take.
    """
    vm = smoke_vm

    ensure = vm.ssh(f"mkdir -p {PFB_LOGDIR} && touch {UNIFIED_LOG}", timeout=15)
    assert ensure.returncode == 0, f"failed to ensure {UNIFIED_LOG} exists: {ensure.stderr!r}"

    size_before = vm.ssh("stat", "-f", "%z", UNIFIED_LOG, timeout=15)
    assert size_before.returncode == 0, f"failed to stat {UNIFIED_LOG}: stderr={size_before.stderr!r}"
    original_size = size_before.stdout.strip()

    append = subprocess.run(
        vm.ssh_argv("tee", "-a", UNIFIED_LOG),
        input=_ALL_LINES,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert append.returncode == 0, f"failed to append the fixture rows to {UNIFIED_LOG}: stderr={append.stderr!r}"

    yield (
        (IP_MARKER, IP_FEED, 16),
        (DNSBL_MARKER, DNSBL_DOMAIN, 39),
        (CNAME_MARKER, CNAME_DOMAIN, 31),
        (REPLY_MARKER, REPLY_DOMAIN, 29),
        (CJK_REPLY_MARKER, CJK_REPLY_DOMAIN, None),
    )

    restore = vm.ssh(f"truncate -s {original_size} {UNIFIED_LOG}", timeout=15)
    assert restore.returncode == 0, f"failed to restore {UNIFIED_LOG} size: stderr={restore.stderr!r}"
    size_after = vm.ssh("stat", "-f", "%z", UNIFIED_LOG, timeout=15)
    assert size_after.returncode == 0 and size_after.stdout.strip() == original_size, (
        f"{UNIFIED_LOG} restore did not take (before={original_size!r}, after={size_after.stdout.strip()!r})"
    )


def test_unified_rows_keep_straddling_multibyte_char_whole(
    smoke_vm: SmokeVM, webui: WebUI, seeded_unified_rows: tuple[tuple[str, str, int | None], ...]
) -> None:
    """Every seeded value's straddling character survives whole; none renders U+FFFD."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(UNIFIED_VIEW)
    result = evaluate_render(UNIFIED_VIEW, resp.status_code, resp.text, ("Alert Settings",))
    assert result.ok, f"Tier-A render oracle failed for the Alerts Unified view: {result.detail}"

    body = resp.text
    assert seeded_unified_rows, "the seeding fixture yielded no markers -- nothing would be asserted"
    truncation_rows = tuple(case for case in seeded_unified_rows if case[2] is not None)
    assert len(truncation_rows) == 4, f"fixture must yield four truncation cases, got {truncation_rows!r}"
    for marker, value, cut in truncation_rows:
        assert cut is not None
        row = row_containing(body, marker)
        expected = value[:cut] + "<small>...</small>"
        assert expected in row, (
            f"row for marker {marker!r} did not show exact cut {cut} with ellipsis; "
            f"expected fragment {expected!r}:\n{row}"
        )
        unexpected = expected + value[cut:]
        assert unexpected not in row, (
            f"row for marker {marker!r} rendered the seeded tail after its ellipsis "
            f"(unexpected fragment {unexpected!r}):\n{row}"
        )
        assert "�" not in row, (
            f"row for marker {marker!r} rendered U+FFFD -- a byte-based cut dangled the "
            f"straddling multibyte character's lead byte instead of keeping it whole:\n{row}"
        )
        assert "é" in row, f"row for marker {marker!r} lost its straddling multibyte character entirely:\n{row}"
        assert "<small>...</small>" in row, (
            f"row for marker {marker!r} did not truncate at all -- fixture broken, not a #1815 signal:\n{row}"
        )

    guard.assert_no_growth()


def test_unified_character_gate_domain_renders_complete_without_lying_ellipsis(
    smoke_vm: SmokeVM, webui: WebUI, seeded_unified_rows: tuple[tuple[str, str, int | None], ...]
) -> None:
    """A byte-long/CJK-short DNS reply domain must render complete in Unified view."""
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(UNIFIED_VIEW)
    result = evaluate_render(UNIFIED_VIEW, resp.status_code, resp.text, ("Alert Settings",))
    assert result.ok, f"Tier-A render oracle failed for the Alerts Unified view: {result.detail}"

    character_gate_rows = tuple(case for case in seeded_unified_rows if case[2] is None)
    assert len(character_gate_rows) == 1, f"fixture must yield one character-gate case, got {character_gate_rows!r}"
    marker, value, _ = character_gate_rows[0]
    row = row_containing(resp.text, marker)
    assert f'<td title="">{value}</td>' in row, f"complete value missing from marker row {marker!r}:\n{row}"
    assert value + "<small>...</small>" not in row, f"marker-local value received a lying ellipsis:\n{row}"

    guard.assert_no_growth()
