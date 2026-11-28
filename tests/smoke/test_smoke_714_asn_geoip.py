"""Live-VM smoke coverage for the #714 audit fixes: GeoIP single-IP overwrite (c8) and
the IP-side parse-fail counter (b2, b3). The ASN extras cases (c1 and #1906) went with the
PHP ASN extras path (issue #3977).

* **c8** (GeoIP continent build) — ``if ($file_chk <= 1)`` treated a continent file
  with exactly ONE genuine IP the same as an EMPTY one, overwriting it with the
  empty-file placeholder. Fixed to ``if ($file_chk == 0)``.
* **b2** (the IP feed line-parser loop) — the "Check for parse failures" block sat
  OUTSIDE the ``while (fgets...)`` loop, so it evaluated only the LAST line read
  instead of running once per unparseable line. Moved inside the loop.

**b2 is CI-runnable**: a local feed + a Force IP reload
(``test_714_b2_parse_fail_counts_every_bad_line``) reproduces deterministically with no
external credentials needed.

**c8 is OUT-OF-CI / dispatch-only**: it needs a real MaxMind GeoIP account
(``SMOKE_GEOIP_KEY``/``SMOKE_GEOIP_ACCOUNT``), an external, licensed data source
absent from CI (see ``test_smoke_aggregate.py``'s "WHAT STAYS MAINTAINER-MANUAL" for
the sibling GeoIP-download limitation). It SKIPS cleanly without its env vars;
authored faithfully for a maintainer to validate live per ADR-04 §7.

DESELECTED from the default ``python -m pytest`` (``--ignore=tests/smoke`` in
pyproject.toml). Run via the smoke workflow or locally::

    python -m pytest tests/smoke/test_smoke_714_asn_geoip.py -m smoke --override-ini="addopts="

Requires the booted ``smoke_vm`` fixture and the branch ``.pkg`` (``SMOKE_PKG``);
without it the module fixture skips cleanly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import cast

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM) -> Iterator[SmokeVM]:
    """Deploy the branch .pkg once for the #714 ASN/GeoIP/parse-fail module.

    None of the three cases needs the DNSBL VIP or a special network allowlist — all
    three exercise the IP-side download/parse/continent-build path only.
    """
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


# --------------------------------------------------------------------------- #
# c8 — a GeoIP continent file with exactly ONE genuine IP must survive, not be
# overwritten by the empty-file placeholder.
# --------------------------------------------------------------------------- #

GEOIP_KEY_ENV = "SMOKE_GEOIP_KEY"
GEOIP_ACCOUNT_ENV = "SMOKE_GEOIP_ACCOUNT"
_GEOIP_ISO = "AQ"  # Antarctica — no real-world continent config exists by default
_GEOIP_CRAFTED_IP = "203.0.113.77"  # RFC 5737 TEST-NET-3: inert, single crafted member
_GEOIP_CCDIR = "/usr/local/share/GeoIP/cc"
_GEOIP_ALIAS = "pfB_Antarctica_v4"
_GEOIP_ALIAS_FILE = f"/var/db/aliastables/{_GEOIP_ALIAS}.txt"
_GEOIP_PLACEHOLDER = "127.1.7.7"  # $pfb['ip_ph'] default (pfblockerng.inc:13034)


@pytest.mark.timeout(900)
def test_714_c8_geoip_single_ip_preserved(deployed_vm: SmokeVM) -> None:
    """#714 c8 (pfblockerng.inc:15613): a genuine 1-IP GeoIP continent file must be
    preserved, not overwritten by the "no unique IPs" empty-file placeholder.

    OUT-OF-CI / dispatch-only: the GeoIP continent build needs a real, licensed
    MaxMind account (external data source, absent from CI) — SKIPS unless both
    SMOKE_GEOIP_KEY and SMOKE_GEOIP_ACCOUNT are set. Authored faithfully for a
    maintainer to validate live per ADR-04 §7.

    Real-world MaxMind continent data is not something this test can control (no
    continent reliably has exactly one CIDR block release to release), so the
    Antarctica continent's IPv4 source is a CONTROLLED, crafted single-IP file — the
    real code path under test (continent aggregation → $file_chk → alias write) is
    exercised exactly as production does; only the country data is pinned so the
    "exactly one IP" precondition is deterministic. A first bootstrap update lets the
    real MaxMind auto-download populate its "if not found" gate files so a second
    update does not regenerate (and clobber) the crafted single-IP source.

    Given (before) the Antarctica continent has never been configured (no alias file),
    When  Antarctica is configured to source ONLY a controlled ISO file containing
      exactly one crafted IP, and a real update pass builds the continent,
    Then  the resulting alias table contains that ONE crafted IP — NOT the empty-file
      placeholder (pre-fix: `$file_chk <= 1` conflated "exactly one real IP" with
      "empty").
    """
    key = os.environ.get(GEOIP_KEY_ENV)
    account = os.environ.get(GEOIP_ACCOUNT_ENV)
    if not (key and account):
        pytest.skip(
            f"{GEOIP_KEY_ENV}/{GEOIP_ACCOUNT_ENV} not set — the GeoIP continent build needs a real, "
            "licensed MaxMind account (absent from CI); dispatch-only, validate live (ADR-04 §7)"
        )
    key = cast(str, key)
    account = cast(str, account)

    try:
        snippet_creds = (
            f"$c = config_get_path({h._php_str(h.CFG_IP_SETTINGS)}, array());\n"  # noqa: SLF001
            f"$c['maxmind_key'] = {h._php_str(key)};\n"  # noqa: SLF001
            f"$c['maxmind_account'] = {h._php_str(account)};\n"  # noqa: SLF001
            f"config_set_path({h._php_str(h.CFG_IP_SETTINGS)}, $c);\n"  # noqa: SLF001
            f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"  # noqa: SLF001
            "$g['enable_cb'] = 'on';\n"
            f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"  # noqa: SLF001
            "write_config('pfBlockerNG smoke #714 c8: MaxMind credentials');\n"
            "echo 'OK';"
        )
        res = h.php_eval(deployed_vm, snippet_creds)
        assert "OK" in res.stdout, f"could not stage MaxMind credentials: {res.stdout!r} {res.stderr!r}"

        # Bootstrap: let the real MaxMind auto-download populate its "if not found" gate
        # files once, so it SKIPS on the run under test — otherwise it would regenerate
        # ccdir/AQ_v4.txt from real data and clobber the crafted fixture below.
        h.reload(deployed_vm, "update")

        # GIVEN: a controlled, deterministic single-member Antarctica ISO source.
        write_iso = (
            f"@mkdir({h._php_str(_GEOIP_CCDIR)}, 0755, TRUE);\n"  # noqa: SLF001
            f"file_put_contents({h._php_str(f'{_GEOIP_CCDIR}/{_GEOIP_ISO}_v4.txt')}, "  # noqa: SLF001
            f"{h._php_str(f'{_GEOIP_CRAFTED_IP}/32' + chr(10))});\n"  # noqa: SLF001
            "echo 'OK';"
        )
        res = h.php_eval(deployed_vm, write_iso)
        assert "OK" in res.stdout, f"could not stage the crafted ISO file: {res.stdout!r} {res.stderr!r}"

        snippet_continent = (
            "$cfg = array('action' => 'Deny_Both', 'countries4' => "
            f"{h._php_str(_GEOIP_ISO)}, 'countries6' => '');\n"  # noqa: SLF001
            "config_set_path('installedpackages/pfblockerngantarctica/config', array($cfg));\n"
            "write_config('pfBlockerNG smoke #714 c8: single-IP Antarctica continent');\n"
            "echo 'OK';"
        )
        res = h.php_eval(deployed_vm, snippet_continent)
        assert "OK" in res.stdout, f"could not stage the continent config: {res.stdout!r} {res.stderr!r}"

        # BEFORE: the alias file does not exist yet (Antarctica was never configured).
        before = h.read_log_file(deployed_vm, _GEOIP_ALIAS_FILE)
        assert before == "", f"{_GEOIP_ALIAS_FILE} already present before the continent was ever built: {before!r}"

        # WHEN: a real update pass builds the continent from the crafted single-IP source.
        h.reload(deployed_vm, "update")

        # THEN: the crafted IP survives — NOT overwritten by the empty-file placeholder.
        after = h.read_log_file(deployed_vm, _GEOIP_ALIAS_FILE)
        assert _GEOIP_CRAFTED_IP in after, (
            f"expected {_GEOIP_ALIAS_FILE} to contain the single crafted member {_GEOIP_CRAFTED_IP}, got: {after!r}"
        )
        assert _GEOIP_PLACEHOLDER not in after, (
            f"{_GEOIP_ALIAS_FILE} was overwritten with the empty-file placeholder {_GEOIP_PLACEHOLDER} despite "
            f"a genuine 1-IP source (pre-fix `$file_chk <= 1` bug): {after!r}"
        )
    finally:
        h.reset(deployed_vm)


# --------------------------------------------------------------------------- #
# b2 — the IP-side per-line parse-fail counter must count EVERY bad line, not just
# the last one read. CI-RUNNABLE: no external credentials needed.
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_714_b2_parse_fail_counts_every_bad_line(deployed_vm: SmokeVM) -> None:
    """#714 b2 (sync_package_pfblockerng, the IP feed line-parser loop): the
    ``$parse_fail`` counter must count EVERY unparseable line, not only the last one.

    RED before / GREEN after (no external credentials needed): pre-fix, the "Check for
    parse failures" block sat OUTSIDE the ``while (fgets...)`` loop, so it ran exactly
    ONCE using whatever ``$line`` the loop last left behind — the LAST line read, our
    single VALID trailing IP (non-empty, letter-free) — so the log would show a count of
    1 even though 3 lines actually failed to parse. Post-fix the block is the last
    statement INSIDE the loop, evaluating every line that fell through without a
    ``continue`` (every failed parse); the trailing valid IP ``continue``s before
    reaching it — so the counter reaches 3. The counter is reported once per feed, after
    the loop, as ``[!] Parse Errors [ <header> ]: <count>`` (naming the feed matters: this
    line is logtype 2, also written to the error log, which has no surrounding
    "[ header ] Reload..." context of its own).

    NOTE: this is the IP-side ``$parse_fail`` counter in the MAIN pfBlockerNG log —
    distinct from the DNSBL per-line parse-error CSV (``pfb_parse_fail_log()`` →
    ``DNSBL_PARSE_ERR_LOG``).

    Given a v4 feed with three non-empty, letter-free lines that all fail IPv4 parsing
      (each has only two dots — too few octets, and no "-" or >=3 dots — so the regex
      fallback cannot silently ``continue`` past the check) followed by ONE valid
      RFC 5737 IP as the LAST line,
    When a Force IP reload parses the feed,
    Then the pfBlockerNG log gains a ``[!] Parse Errors [ smoke714b2_v4 ]: 3`` line —
      the counter reached the number of bad lines, not merely "1" (the pre-fix
      last-line-only count). The feed HEADER in that line carries the family
      suffix (``pfblockerng.inc``'s ``$header = "{$row['header']}{$list['vtype']}"``),
      same gotcha ``force_ip_refetch()`` already documents for the on-disk feed
      filename — it is NOT the bare ``IpCase.header`` value.
    """
    # Each has only TWO dots, so it fails IPv4 parsing AND is skipped by the regex
    # fallback (which requires >=3 dots) — guaranteeing it falls through to the
    # parse-fail check. (A 3-dot line like "999.1.2.3" must NOT be used: the regex
    # fallback matches the valid substring "99.1.2.3" and `continue`s past the check.)
    bad_lines = ["10.0.0", "192.168.1", "203.0.113"]  # non-empty, letter-free, all fail IPv4 parsing
    good_line = "198.51.100.7"  # RFC 5737 TEST-NET-2 — the trailing VALID line (must not count)
    body = "\n".join([*bad_lines, good_line]) + "\n"
    feed_url = h.write_local_feed(deployed_vm, "smoke_714_b2_parsefail.txt", body)
    spec = h.IpCase(aliasname="smoke714b2", feed_url=feed_url, header="smoke714b2", family="v4")
    # $header at the print site is "{row.header}{vtype}", e.g. "smoke714b2_v4" -- NOT
    # the bare IpCase.header (see docstring).
    marker = f"[!] Parse Errors [ {spec.header}_{spec.family} ]: 3"

    try:
        # BEFORE: this exact marker has never appeared (a fresh aliasname/header pair).
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

        h.inject(deployed_vm, spec)
        h.reload(deployed_vm, "update")

        # THEN: the counter reached 3 (every bad line), not 1 (pre-fix last-line-only).
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        assert after > before, (
            f"expected a new {marker!r} line in {h.PFB_LOG} after parsing 3 bad lines "
            f"(before={before}, after={after}) — the counter must count every failed "
            f"line, not just the last one read"
        )
    finally:
        h.reset(deployed_vm)
        deployed_vm.ssh("/bin/rm", "-f", feed_url)


# --------------------------------------------------------------------------- #
# b3 — a hex-letter-free, syntactically valid IPv6 address in a '_v6' list running
# in REGEX mode must NOT be double-counted as a parse failure once it has already
# been collected. CI-RUNNABLE: no external credentials needed.
# --------------------------------------------------------------------------- #


@pytest.mark.timeout(300)
def test_714_b3_v6_regex_parser_success_not_double_counted(deployed_vm: SmokeVM) -> None:
    """sync_package_pfblockerng's IPv6 "regex fallback" parser must ``continue`` after
    successfully collecting an address, mirroring its IPv4 sibling block — else a line
    it already matched and validated still falls through to the parse-fail heuristic
    and gets counted as an error.

    RED before / GREEN after: confirmed live against a real feed (qfeeds_ip_list_v6,
    format=auto but a query-string-only URL with no path extension resolves to
    $pftype='regex' via the extension-fallback rule) — 97 syntactically valid,
    hex-letter-free IPv6 addresses were all successfully extracted by
    ``preg_match_all($pfb['ipv6'], ...)`` and collected into ``$ip_data``, yet the
    "IPv6 Regex parser" block never ``continue``s (unlike the IPv4 regex-parser
    sibling, which already does), so every one of them ALSO fell through to
    "Check for parse failures" and was double-counted.

    A hex-letter-free address is required to reproduce this: the parse-fail
    heuristic itself only considers a-zA-Z-free lines, so an address with any
    hex letter (a-f) never reaches the heuristic regardless of this bug.

    Given a v6 feed with two syntactically valid, hex-letter-free IPv6 addresses
      (2000::1 / 2000::2 — outside the RFC 3849 documentation range specifically
      because that range's 'db8' hextet contains hex letters), via a URL with no
      path extension (forces $pftype='regex', matching the live qfeeds_ip_list_v6
      case),
    When a Force IP reload parses the feed,
    Then the pfBlockerNG log gains NO "[!] Parse Errors" line for this feed — both
      addresses were collected, not flagged.
    """
    good_lines = ["2000::1", "2000::2"]
    body = "\n".join(good_lines) + "\n"
    # No '.' in the name -> pathinfo() finds no extension -> $pftype='regex',
    # reproducing the live qfeeds_ip_list_v6 (query-string-only URL) case.
    feed_url = h.write_local_feed(deployed_vm, "smoke_714_b3_v6regex_ok", body)
    spec = h.IpCase(aliasname="smoke714b3", feed_url=feed_url, header="smoke714b3", family="v6")
    marker = f"[!] Parse Errors [ {spec.header}_{spec.family} ]"

    try:
        before = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)

        h.inject(deployed_vm, spec)
        h.reload(deployed_vm, "update")
        h.apply_filter_sync(deployed_vm)

        # THEN: both addresses reached the pf table (proves they were actually parsed
        # and collected, not silently dropped by some other mechanism). By-VALUE
        # comparison (h.ip_in): pf/pfBlockerNG may render a compressed literal
        # differently (e.g. an equivalent expanded form), which a substring check
        # would miss.
        members = h.pfctl_table_members(deployed_vm, spec.alias)
        for ip in good_lines:
            assert h.ip_in(ip, members), f"expected valid IPv6 {ip} in pf table {spec.alias}: {members}"

        # AND: no parse-error line was emitted for this feed.
        after = h.count_log_marker(deployed_vm, h.PFB_LOG, marker)
        assert after == before, (
            f"expected NO new {marker!r} line in {h.PFB_LOG} (before={before}, "
            f"after={after}) — both lines were valid IPv6 addresses that got "
            f"collected; the regex-parser success path must not also count them "
            f"as parse failures"
        )
    finally:
        h.reset(deployed_vm)
        deployed_vm.ssh("/bin/rm", "-f", feed_url)
