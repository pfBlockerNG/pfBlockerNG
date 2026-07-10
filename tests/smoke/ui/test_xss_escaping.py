"""Tier-A ``ui_render`` coverage for the XSS-escaping fixes (issue #1069).

Three unescaped sinks echoed attacker-influenceable log/feed data straight into
HTML/JS: the DNSBL stats table ``<td>``/filter-button attrs + the stats pie
chart's inline ``<script>`` JSON (both in ``pfblockerng_alerts.php``), and the
Feeds page's Custom Feeds URL column (``pfblockerng_feeds.php``). Each is fixed
by encoding the raw value once at its ingress -- ``pfb_hsc``/``htmlspecialchars``
for HTML context, ``pfb_js_string()`` (JSON_HEX_* + JSON_INVALID_UTF8_SUBSTITUTE)
for the inline-script JS-string context -- never double-escaping the pre-existing
intentional markup already on these pages (the ``&emsp;`` date-bucket label, the
static tags around it). The Feeds URL column also gains an http(s):// scheme
gate so a ``javascript:`` URL renders as inert text, not a clickable link.

This module is LIVE-VM/CI-only (no local smoke VM in this environment): the
red-before/green-after proof for these fixtures runs only in CI's smoke leg.
Locally it is proven collect-clean + lint-clean; the off-box evidence that
each sink actually encodes the hostile input is the manual ``php -r`` proof
pasted in this change's handoff.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

# --------------------------------------------------------------------------- #
# DNSBL Block Stats: the "Top Blocked Domain" table <td> + the pie chart's
# inline <script> JSON both echo the raw domain (issue #1069 defects #2 + #3).
# --------------------------------------------------------------------------- #

DNSBL_LOG = "/var/log/pfblockerng/dnsbl.log"
ALERTS_DNSBL_STAT_PAGE = "/pfblockerng/pfblockerng_alerts.php?view=dnsbl_stat"

# Hostile-input fixture: <, >, ", ', and a literal </script>. No comma (the
# dnsbl.log stat pipeline is comma-delimited via `cut -d ','`) and no space
# (the count/value split is `explode(' ', trim($line), 2)`, which assumes no
# space before the first token). Fixed synthetic content (never the wall clock,
# never a real domain). ".evil.example" is a unique, metachar-free marker that
# survives both HTML- and JS-encoding verbatim -- asserting it proves THIS
# seeded domain actually rendered (not some incidental `&lt;script&gt;`).
XSS_DOMAIN = "<script>alert(1)</script>\"'.evil.example"
XSS_DOMAIN_MARKER = ".evil.example"
_XSS_LOG_LINE = f"DNSBL-python,2030-02-20 10:00:00,{XSS_DOMAIN},203.0.113.50,Python,DNSBL,XSSGroup,Match,XSSFeed,+,A\n"

# The DNSBL stats view ranks domains by hit count and renders only the Top-N
# (table + pie). One row could be pushed out by existing log noise, making the
# assertions vacuous. Seed many identical rows so the hostile domain is a
# guaranteed top entry in both the table and the pie chart.
_XSS_LOG_ROW_COUNT = 25
_XSS_LOG_LINES = _XSS_LOG_LINE * _XSS_LOG_ROW_COUNT


@pytest.fixture
def _seeded_xss_dnsbl_log(smoke_vm: SmokeVM) -> Iterator[None]:
    """Append many identical hostile dnsbl.log rows; restore the pre-test size after.

    Mirrors ``test_alerts_stat_render.py``'s ``_seeded_dnsbl_log`` fixture:
    self-encapsulated teardown truncates the log back to its exact pre-test
    byte size and FAILS LOUDLY if that didn't take, so the XSS fixture rows
    never leak to a sibling test. Seeds ``_XSS_LOG_ROW_COUNT`` copies so the
    hostile domain outranks pre-existing log noise into the Top-N.
    """
    vm = smoke_vm
    log_dir = DNSBL_LOG.rsplit("/", 1)[0]
    ensure = vm.ssh(f"mkdir -p {log_dir} && touch {DNSBL_LOG}", timeout=15)
    assert ensure.returncode == 0, f"failed to ensure {DNSBL_LOG} exists: {ensure.stderr!r}"

    size_before = vm.ssh("stat", "-f", "%z", DNSBL_LOG, timeout=15)
    assert size_before.returncode == 0, f"failed to stat {DNSBL_LOG}: stderr={size_before.stderr!r}"
    original_size = size_before.stdout.strip()

    append = subprocess.run(
        vm.ssh_argv("tee", "-a", DNSBL_LOG),
        input=_XSS_LOG_LINES,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert append.returncode == 0, f"failed to append the XSS fixture rows to {DNSBL_LOG}: stderr={append.stderr!r}"

    yield

    restore = vm.ssh(f"truncate -s {original_size} {DNSBL_LOG}", timeout=15)
    assert restore.returncode == 0, f"failed to restore {DNSBL_LOG} size: stderr={restore.stderr!r}"
    size_after = vm.ssh("stat", "-f", "%z", DNSBL_LOG, timeout=15)
    assert size_after.returncode == 0 and size_after.stdout.strip() == original_size, (
        f"{DNSBL_LOG} restore did not take (before={original_size!r}, after={size_after.stdout.strip()!r}) "
        "-- the XSS fixture row leaked to sibling tests"
    )


def test_alerts_dnsbl_stat_escapes_hostile_domain(smoke_vm: SmokeVM, webui: WebUI, _seeded_xss_dnsbl_log: None) -> None:
    """A ``<script>``-carrying blocked domain renders HTML/JS-encoded, never verbatim.

    Scenario:
      Given many identical dnsbl.log rows whose blocked domain is
            ``<script>alert(1)</script>"'.evil.example`` (seeded to outrank
            noise into the Top Blocked Domain table + pie chart).
      When  GET the DNSBL Block Stats view (renders both the stats table
            ``<td>`` and the per-stat pie chart's inline ``<script>`` JSON).
      Then  the Tier-A render oracle passes AND the seeded marker
            (``.evil.example``) is present AND the domain appears HTML-encoded
            in the table (``&lt;script&gt;alert(1)&lt;/script&gt;``, ``&quot;``,
            ``&#039;``) AND JS-string-encoded in the pie chart
            (``\\u003Cscript\\u003E``) AND the verbatim
            ``<script>alert(1)</script>`` string never appears anywhere in the
            body (issue #1069 -- pre-fix, both sinks printed it raw).
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(ALERTS_DNSBL_STAT_PAGE)
    result = evaluate_render(ALERTS_DNSBL_STAT_PAGE, resp.status_code, resp.text, ("DNSBL Block Stats",))
    assert result.ok, f"Tier-A render oracle failed for the DNSBL stats page: {result.detail}"

    body = resp.text
    # Non-vacuity: the unique marker proves THE SEEDED domain rendered (in both
    # the HTML table and the inline-JS pie label, where ".evil.example" survives
    # encoding verbatim). Without it, the encoded-form checks below could pass on
    # unrelated content.
    assert XSS_DOMAIN_MARKER in body, (
        f"the seeded hostile domain never rendered ({XSS_DOMAIN_MARKER!r} absent) -- "
        "the escaping assertions would be vacuous"
    )
    assert "<script>alert(1)</script>" not in body, (
        "the raw <script> payload rendered verbatim in the DNSBL stats page -- an XSS sink regressed"
    )
    # HTML context (stats table <td>/button attrs): the full domain encodes to
    # &lt;script&gt;alert(1)&lt;/script&gt;&quot;&#039;.evil.example
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body, (
        "the stats table <td>/button attrs did not HTML-encode the hostile domain's <script> markup"
    )
    assert "&quot;" in body or "&#34;" in body, "the hostile domain's double-quote did not render encoded"
    assert "&#039;" in body, "the hostile domain's single-quote did not render encoded"
    # Inline-<script> JS context (pie chart label): JSON_HEX_* hex-escapes the tags.
    assert "\\u003Cscript\\u003E" in body, (
        "the pie chart's inline <script> JSON did not JS-string-encode the hostile domain"
    )

    guard.assert_no_growth()


# --------------------------------------------------------------------------- #
# Feeds page: the Custom Feeds table URL column echoes the raw feed URL
# (issue #1069 defect #4). Seeded directly via the config API -- a row need
# not match a real predefined feed URL to appear in the Custom Feeds table
# (``url_compare`` only marks a row ``found`` on an exact URL match).
# --------------------------------------------------------------------------- #

CFG_IPV4_FEEDS = "installedpackages/pfblockernglistsv4/config"
FEEDS_PAGE_IPV4 = "/pfblockerng/pfblockerng_feeds.php?type=ipv4"
FEEDS_PAGE_MARKERS = ("Pre-defined Alias/Group/Feeds", "IPv4 Alias name(s):")

# Hostile-input fixture: an "http" URL (hits the <a href> render branch) that
# breaks out of the href attribute and opens a <script> tag.
XSS_FEED_URL = 'http://a"><script>xss</script>.evil.example/list.txt'
# Its exact htmlspecialchars(ENT_QUOTES, UTF-8) form -- asserting the WHOLE
# encoded URL (not a fragment) proves the seeded row rendered, encoded.
XSS_FEED_URL_ENCODED = "http://a&quot;&gt;&lt;script&gt;xss&lt;/script&gt;.evil.example/list.txt"
XSS_FEED_URL_MARKER = "evil.example/list.txt"

# A "javascript:" scheme URL that still contains "http": the pre-fix
# strpos('http') gate would have wrapped it in <a href="javascript:...">, and
# htmlspecialchars does NOT neutralise the scheme, so it would execute on click.
# The scheme gate must instead render it as inert (non-linked) text.
XSS_FEED_JS_URL = "javascript:alert(1)//http://js.evil.example/list.txt"
XSS_FEED_JS_MARKER = "js.evil.example/list.txt"


def _free_rowid(vm: helpers.SmokeVM, cfg_root: str) -> int:
    """Return a config rowid under ``cfg_root`` that does not clobber an existing alias."""
    pre = (
        f"$c = config_get_path({helpers._php_str(cfg_root)}, array());\n"
        "$max = -1;\n"
        "foreach (array_keys($c) as $k) { if (is_numeric($k) && (int)$k > $max) { $max = (int)$k; } }\n"
        "$free = $max + 1;"
    )
    return int(helpers._php_read_scalar(vm, pre, "$free", timeout=60.0))


def _seed_custom_feed_row(vm: helpers.SmokeVM, cfg_root: str, rowid: int, aliasname: str, url: str) -> None:
    """Write one custom-feed alias (unmatched by the predefined catalog) via the config API.

    Direct ``config_set_path`` + ``write_config`` (not the save form) -- a pure
    render-path seed, mirroring ``test_category_edit.py``'s config-injection
    idiom (``_mk_alias``).
    """
    row = {"state": "Enabled", "url": url, "header": "xss-header"}
    snippet = (
        f"config_set_path({helpers._php_str(f'{cfg_root}/{rowid}/aliasname')}, {helpers._php_str(aliasname)});\n"
        f"config_set_path({helpers._php_str(f'{cfg_root}/{rowid}/action')}, {helpers._php_str('Deny_Both')});\n"
        f"config_set_path({helpers._php_str(f'{cfg_root}/{rowid}/row/0')}, {helpers._php_kv_array(row)});\n"
        "write_config('pfBlockerNG smoke: seed XSS feed row');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_seed_custom_feed_row failed: rc={result.returncode} {result.stdout!r} {result.stderr!r}")


def _del_rowid(vm: helpers.SmokeVM, cfg_root: str, rowid: int) -> None:
    """Delete ``{cfg_root}/{rowid}`` (cleanup of the alias slot this test created)."""
    snippet = (
        f"config_del_path({helpers._php_str(f'{cfg_root}/{rowid}')});\n"
        "write_config('pfBlockerNG smoke: drop XSS feed row');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_del_rowid failed: rc={result.returncode} {result.stdout!r}")


def test_feeds_custom_url_escapes_hostile_input(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A Custom Feed URL carrying an href-breakout payload renders HTML-encoded.

    Scenario:
      Given a custom (non-predefined) IPv4 feed alias whose source URL is
            ``http://a"><script>xss</script>.evil.example/list.txt``.
      When  GET the Feeds page (IPv4 tab), which lists it in the "Custom
            Feeds" table (its URL matches no predefined feed, so
            ``url_compare`` never marks it ``found``).
      Then  the Tier-A render oracle passes AND the FULLY-encoded URL
            (``http://a&quot;&gt;&lt;script&gt;xss&lt;/script&gt;.evil.example/list.txt``)
            appears in the body AND the raw breakout (``a"><script>``) never
            appears anywhere (issue #1069 -- pre-fix, the URL printed raw in
            both the href attribute and the link text).
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_IPV4_FEEDS)
    try:
        _seed_custom_feed_row(vm, CFG_IPV4_FEEDS, rowid, "xsstestalias", XSS_FEED_URL)

        resp = webui.get(FEEDS_PAGE_IPV4)
        result = evaluate_render(FEEDS_PAGE_IPV4, resp.status_code, resp.text, FEEDS_PAGE_MARKERS)
        assert result.ok, f"Tier-A render oracle failed for the Feeds page: {result.detail}"

        body = resp.text
        assert not looks_like_login_page(body), "Feeds GET returned the login form (session lost)"
        # Non-vacuity: the unique marker proves THE SEEDED row rendered.
        assert XSS_FEED_URL_MARKER in body, (
            f"the seeded custom feed never rendered ({XSS_FEED_URL_MARKER!r} absent) -- assertion would be vacuous"
        )
        assert 'a"><script>' not in body, (
            "the raw URL breakout rendered verbatim in the Feeds page -- an XSS sink regressed"
        )
        assert XSS_FEED_URL_ENCODED in body, (
            f"the Custom Feeds URL column did not HTML-encode the whole hostile URL (expected {XSS_FEED_URL_ENCODED!r})"
        )
    finally:
        _del_rowid(vm, CFG_IPV4_FEEDS, rowid)


def test_feeds_custom_url_javascript_scheme_not_linked(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A ``javascript:`` Custom Feed URL renders as inert text, never a clickable link.

    Scenario:
      Given a custom IPv4 feed alias whose source URL is
            ``javascript:alert(1)//http://js.evil.example/list.txt`` (contains
            "http", so the pre-fix ``strpos('http')`` gate would have linked it).
      When  GET the Feeds page (IPv4 tab).
      Then  the URL text still renders (HTML-encoded) BUT never inside an
            ``<a href="javascript:...">`` -- the scheme gate downgrades any
            non-http(s):// URL to plain text, so it cannot execute on click
            (issue #1069 -- htmlspecialchars does not neutralise the scheme).
    """
    vm = smoke_vm
    rowid = _free_rowid(vm, CFG_IPV4_FEEDS)
    try:
        _seed_custom_feed_row(vm, CFG_IPV4_FEEDS, rowid, "xssjsalias", XSS_FEED_JS_URL)

        resp = webui.get(FEEDS_PAGE_IPV4)
        result = evaluate_render(FEEDS_PAGE_IPV4, resp.status_code, resp.text, FEEDS_PAGE_MARKERS)
        assert result.ok, f"Tier-A render oracle failed for the Feeds page: {result.detail}"

        body = resp.text
        assert not looks_like_login_page(body), "Feeds GET returned the login form (session lost)"
        # Non-vacuity: the seeded row rendered (as encoded text).
        assert XSS_FEED_JS_MARKER in body, (
            f"the seeded javascript: feed never rendered ({XSS_FEED_JS_MARKER!r} absent) -- assertion would be vacuous"
        )
        assert 'href="javascript:' not in body, (
            "a javascript: feed URL was rendered as a clickable <a href> -- the scheme gate regressed"
        )
    finally:
        _del_rowid(vm, CFG_IPV4_FEEDS, rowid)
