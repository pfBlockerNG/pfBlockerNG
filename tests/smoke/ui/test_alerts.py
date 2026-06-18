"""Tier-B functional flows for the Reports/Alerts page (ADR-14 Phase 3).

The Alerts page (``pfblockerng_alerts.php``) is the heaviest page in the package
and its mutating actions are NOT a single ``save`` form -- they are JS-driven
``act``-style POSTs, each dispatched by an ``isset($_POST['<action>'])`` branch
in the ``if (isset($_POST) && !empty($_POST))`` block at the top of the file. So
these flows do NOT use :meth:`WebUI.post` (which scrapes the whole form and adds a
``save`` button); they GET the page, harvest the freshly-injected ``__csrf_magic``
token, and POST the exact ``{action: ..., domain/ip/table: ...}`` set the page's
JS would send (mirroring ``test_log.py``'s manual-POST pattern).

What this file establishes -- the same oracle discipline as ``test_functional.py``:
the oracle is the box's EFFECTIVE state, NEVER the HTTP response body. For the
config-store actions (whitelist / TLD-exclusion / IP suppression) that is the
``config.xml`` node the handler writes (read via :func:`helpers.config_get`,
base64-decoded -- these are pfBlockerNG textarea fields). For the marquee
Lock/Unlock action -- whose store is ``/tmp/dnsbl_unlock`` (not config.xml) and
whose effect is a query-time whiteDB allow -- the oracle is the on-box DNS answer
shape (``drill @127.0.0.1``), since the only observable truth of an unlock is that
the resolver stops sinkholing the name.

Every flow is a TRUE transition test (CLAUDE.md transition-test rule): it asserts
the ORIGINAL/before state FIRST, drives the action, asserts the changed state, then
RESTORES the box (asserting the reverse where it applies). A green therefore proves
the POST CAUSED the change rather than a pre-existing end-state happening to hold,
and the restore -- always in a ``finally`` so a mid-test failure cannot poison the
session-scoped VM for the sibling flows -- exercises the reverse branch too.
"""

from __future__ import annotations

import base64
import subprocess
import time
from typing import TYPE_CHECKING, Any

import pytest

from .. import helpers
from .webui import extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    import requests

    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"

# config.xml nodes the alerts handlers write (all base64 textarea fields).
CFG_SUPPRESSION = "installedpackages/pfblockerngdnsblsettings/config/0/suppression"
CFG_TLDEXCLUSION = "installedpackages/pfblockerngdnsblsettings/config/0/tldexclusion"
CFG_V4SUPPRESSION = "installedpackages/pfblockerngipsettings/config/0/v4suppression"


def _csrf(webui: WebUI) -> str:
    """GET the alerts page and return its freshly-injected ``__csrf_magic`` token.

    csrf-magic rewrites the token per render, so it must be re-harvested for each
    manual POST. Asserts the GET is authenticated so a dropped session fails loudly
    here, not as an opaque CSRF rejection inside the handler.
    """
    resp = webui.get(ALERTS_PAGE)
    assert not looks_like_login_page(resp.text), "alerts page GET returned the login form (session lost)"
    return extract_csrf_token(resp.text)


def _post_action(webui: WebUI, data: dict[str, str], *, timeout: float = 300.0) -> requests.Response:
    """POST one alerts ``act``-style action with a fresh CSRF token.

    Re-harvests the token (per-render), merges it into ``data``, and POSTs to the
    alerts page exactly as the page's JS would -- no ``save`` button (these handlers
    gate on ``isset($_POST['<action>'])``, not on ``save``). The caller asserts
    EFFECTIVE state (config.xml / DNS), never this response.
    """
    payload: dict[str, Any] = {"__csrf_magic": _csrf(webui)}
    payload.update(data)
    return webui.session.post(
        webui.url(ALERTS_PAGE),
        data=payload,
        verify=webui._verify,  # noqa: SLF001 -- mirror the client's configured cert handling
        timeout=timeout,
    )


def _suppression_entries(vm: helpers.SmokeVM, cfg_path: str) -> set[str]:
    """Return the ENTRY TOKENS of a pfBlockerNG textarea config node.

    The alerts handlers store the whitelist / TLD-exclusion / IP-suppression lists
    base64-encoded (``base64_encode`` in the handler; ``pfbng_text_area_decode``
    base64-decodes on read), one entry per CRLF line as ``<token> [# comment]``. The
    handler keys its in-memory store by the FIRST whitespace-delimited token of each
    line (``$clists[...]['data'][$line[0]]``), so an exact-token set is the faithful
    membership oracle -- a substring check would wrongly match ``example.com`` inside
    the ``www.example.com`` entry the whitelist add also writes (and which
    ``entry_delete=delete_domain`` deliberately leaves behind). An empty/absent node
    is an empty set.
    """
    raw = helpers.config_get(vm, cfg_path)
    if not raw:
        return set()
    try:
        text = base64.b64decode(raw).decode("utf-8", "replace")
    except (ValueError, UnicodeError):
        return set()
    return {line.split()[0] for line in text.splitlines() if line.strip()}


# --------------------------------------------------------------------------- #
# Marquee flow: the DNSBL temporary Lock/Unlock lifecycle (the ``dnsbl_remove``
# handler, alerts.php:1371). A feed-blocked domain "unlocked" via the alerts web
# handler must STOP being sinkholed; re-locking restores the block. Oracle = the
# on-box DNS answer SHAPE (the unlock store is /tmp/dnsbl_unlock, not config.xml).
#
# Block shape is deterministic LOCALLY (VIP / 0.0.0.0), computed by the python
# module every query (blocks are not C-cached, #43). An UNLOCK lifts the sinkhole:
# the module passes the name through and Unbound forwards it upstream. Under the UI
# fixtures there is NO controlled stub upstream, so the forwarded answer is whatever
# the real upstream returns for a random .com (NXDOMAIN) -- but that is irrelevant:
# the discriminator is "no longer a block shape" (`not is_vip and not is_null_ip`),
# which is True for NXDOMAIN/SERVFAIL/any real answer and False ONLY for a block.
# That isolates the toggle without depending on a positive upstream resolve.
# --------------------------------------------------------------------------- #


def _not_blocked(answer: helpers.DnsAnswer) -> bool:
    """True iff the answer is NOT a DNSBL block shape (neither the VIP nor null-IP).

    The upstream-independent "unlocked" oracle: an unlocked name is forwarded, so it
    is no longer sinkholed -- whatever it resolves to (or NXDOMAIN/SERVFAIL with no
    upstream), it is not the VIP and not 0.0.0.0/::.
    """
    return not helpers.is_vip(answer) and not helpers.is_null_ip(answer)


def test_dnsbl_lock_unlock_lifecycle_via_alerts(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Unlock/Lock a feed-blocked domain via the alerts ``dnsbl_remove`` web handler.

    True transition lifecycle (CLAUDE.md before/after + the lock/unlock example):

    * SETUP: a local DNSBL feed lists ``domain`` (VIP mode) with DNSBL enabled and a
      valid sinkhole VIP, then a full Force Update mounts it.
    * BEFORE: ``domain`` is VIP-BLOCKED (the deterministic local block shape, the
      authoritative first answer after the restart-class reload).
    * UNLOCK via the form (``dnsbl_remove=unlock``): the handler toggles the unlock
      store, patches the manifest's ``user_unlock`` and reloads -> the name stops
      being sinkholed. Poll until it is no longer a block shape (the swap is async).
    * RE-LOCK via the form (``dnsbl_remove=lock``): the temporary allow is removed ->
      the name is VIP-blocked again. Poll until the block shape returns.

    Oracle = the on-box DNS answer shape, never the HTTP body. ``reset(vm)`` in
    ``finally`` drops the test feed/alias and rebuilds the baseline so the session VM
    is clean for the sibling flows.
    """
    vm = smoke_vm
    domain = helpers.unique_domain("uilock")
    feed_path = helpers.write_local_feed(vm, "ui_lock.txt", f"{domain}\n")
    spec = helpers.DnsblCase(aliasname="uilock", feed_url=feed_path, header="uilock", mode=helpers.DnsblMode.VIP)

    helpers.ensure_dnsbl_vip(vm)
    helpers.set_dnsbl_enabled(vm, True)
    helpers.inject(vm, spec)
    helpers.reload(vm, "update")
    try:
        # BEFORE: the feed-listed name is VIP-blocked (authoritative first answer
        # after the restart-class Force Update).
        blocked = helpers.dns_probe(vm, domain, "A")
        assert helpers.is_vip(blocked), f"{domain} expected VIP block before unlock, got {blocked}"

        # UNLOCK via the real alerts handler -> the sinkhole is lifted. dnsbl_type is
        # PFB_FILTER_WORD and must be non-empty (handler rejects empty); 'python' is
        # the value the production helper sends.
        resp = _post_action(webui, {"dnsbl_remove": "unlock", "domain": domain, "dnsbl_type": "python"})
        assert not looks_like_login_page(resp.text), "unlock POST returned the login form (session lost)"
        # The swap is async -> poll until the name is no longer a block shape.
        unlocked = helpers.dns_probe_until(vm, domain, _not_blocked)
        assert not helpers.is_vip(unlocked), f"unlocked {domain} still VIP-blocked via the alerts handler: {unlocked}"

        # RE-LOCK via the handler -> blocked again (allow->block; the handler's
        # targeted delta-flush clears the prior resolved answer).
        resp = _post_action(webui, {"dnsbl_remove": "lock", "domain": domain, "dnsbl_type": "python"})
        assert not looks_like_login_page(resp.text), "re-lock POST returned the login form (session lost)"
        relocked = helpers.dns_probe_until(vm, domain, helpers.is_vip)
        assert helpers.is_vip(relocked), f"re-locked {domain} not VIP-blocked again: {relocked}"
    finally:
        # Drop the test feed/alias and rebuild from baseline so the unlock store and
        # the session VM are clean for the sibling flows.
        helpers.reset(vm)


def test_dnsbl_remove_rejects_missing_type(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """The ``dnsbl_remove`` handler rejects an empty ``dnsbl_type`` -> no store change.

    Branch coverage for the validator's REJECT side (the accept side is the marquee
    lifecycle above): the handler exits with a savemsg and never toggles the unlock
    store when ``dnsbl_type`` is empty (alerts.php:1380). The transition oracle is the
    DNS shape: a feed-blocked domain stays VIP-blocked across the rejected POST (the
    block is the before-state AND the after-state -- proving the POST did NOT unlock).
    """
    vm = smoke_vm
    domain = helpers.unique_domain("uireject")
    feed_path = helpers.write_local_feed(vm, "ui_reject.txt", f"{domain}\n")
    spec = helpers.DnsblCase(aliasname="uireject", feed_url=feed_path, header="uireject", mode=helpers.DnsblMode.VIP)

    helpers.ensure_dnsbl_vip(vm)
    helpers.set_dnsbl_enabled(vm, True)
    helpers.inject(vm, spec)
    helpers.reload(vm, "update")
    try:
        # BEFORE: VIP-blocked.
        before = helpers.dns_probe(vm, domain, "A")
        assert helpers.is_vip(before), f"{domain} expected VIP block before the rejected POST, got {before}"

        # Reject: empty dnsbl_type. The handler must exit before toggling the store.
        resp = _post_action(webui, {"dnsbl_remove": "unlock", "domain": domain, "dnsbl_type": ""})
        assert not looks_like_login_page(resp.text), "rejected POST returned the login form (session lost)"

        # AFTER: still VIP-blocked -- the rejected unlock did not lift the sinkhole.
        after = helpers.dns_probe(vm, domain, "A")
        assert helpers.is_vip(after), f"{domain} no longer VIP-blocked after a REJECTED unlock POST: {after}"
    finally:
        helpers.reset(vm)


# --------------------------------------------------------------------------- #
# addwhitelistdom (alerts.php:947): adds a domain to the DNSBL Whitelist
# (``suppression`` node) when ``dnsbl_exclude != 'true'``, OR to the TLD Exclusion
# list (``tldexclusion`` node) when ``dnsbl_exclude == 'true'`` -- two distinct
# config branches off the SAME action. The reverse is the ``entry_delete`` handler
# (alerts.php:1178): ``delete_domain`` removes from ``suppression``,
# ``delete_exclusion`` removes from ``tldexclusion`` -- so the restore exercises
# that handler too. Oracle = the base64-decoded config node membership.
# --------------------------------------------------------------------------- #


def test_addwhitelistdom_writes_whitelist_and_entry_delete_removes_it(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """addwhitelistdom (no exclude) writes the DNSBL Whitelist; entry_delete removes it.

    True transition with the ``suppression`` config node as oracle:

    * BEFORE: ``domain`` is absent from the decoded ``suppression`` node.
    * ADD via the form (``addwhitelistdom`` + ``dnsbl_exclude`` not 'true'): the
      handler appends ``domain`` (and ``www.domain``) and writes the base64 node.
    * AFTER: ``domain`` is present in the decoded node.
    * RESTORE via ``entry_delete=delete_domain``: the handler removes it; the decoded
      node no longer contains ``domain`` (the reverse transition AND entry_delete
      coverage). Belt-and-suspenders config reset in ``finally``.
    """
    vm = smoke_vm
    domain = helpers.unique_domain("uiwl")
    original = helpers.config_get(vm, CFG_SUPPRESSION)
    try:
        # BEFORE: the unique domain is not in the whitelist.
        assert domain not in _suppression_entries(vm, CFG_SUPPRESSION), (
            f"{domain} already in the DNSBL Whitelist before the add"
        )

        # ADD: addwhitelistdom into the DNSBL Whitelist (dnsbl_exclude false). 'table'
        # is PFB_FILTER_WORD and only checked non-empty for this branch.
        resp = _post_action(
            webui,
            {
                "addwhitelistdom": "Add",
                "domain": domain,
                "table": "DNSBL",
                "dnsbl_wildcard": "false",
                "dnsbl_exclude": "false",
            },
        )
        assert not looks_like_login_page(resp.text), "addwhitelistdom POST returned the login form (session lost)"
        assert domain in _suppression_entries(vm, CFG_SUPPRESSION), (
            f"{domain} not written to the DNSBL Whitelist (suppression) config node after addwhitelistdom"
        )

        # RESTORE via entry_delete=delete_domain (reverse transition + entry_delete coverage).
        resp = _post_action(webui, {"entry_delete": "delete_domain", "domain": domain, "table": "DNSBL"})
        assert not looks_like_login_page(resp.text), "entry_delete POST returned the login form (session lost)"
        assert domain not in _suppression_entries(vm, CFG_SUPPRESSION), (
            f"{domain} still in the DNSBL Whitelist after entry_delete=delete_domain"
        )
    finally:
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_SUPPRESSION}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore suppression');\n"
            "echo 'OK';",
        )


def test_addwhitelistdom_exclude_writes_tld_exclusion_and_entry_delete_removes_it(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """addwhitelistdom with ``dnsbl_exclude='true'`` writes the TLD Exclusion node.

    The OTHER branch of the same action (CLAUDE.md branch coverage: the exclude flag
    OFF case is the whitelist test above; this is the ON case). True transition with
    the ``tldexclusion`` config node as oracle: absent before, present after the add,
    absent again after ``entry_delete=delete_exclusion`` (the reverse + that delete
    branch). Config reset in ``finally``.
    """
    vm = smoke_vm
    domain = helpers.unique_domain("uitld")
    original = helpers.config_get(vm, CFG_TLDEXCLUSION)
    try:
        # BEFORE: not in the TLD Exclusion list.
        assert domain not in _suppression_entries(vm, CFG_TLDEXCLUSION), (
            f"{domain} already in the TLD Exclusion list before the add"
        )

        # ADD: addwhitelistdom with dnsbl_exclude=true -> the TLD Exclusion branch.
        resp = _post_action(
            webui,
            {
                "addwhitelistdom": "Add",
                "domain": domain,
                "table": "DNSBL",
                "dnsbl_wildcard": "false",
                "dnsbl_exclude": "true",
            },
        )
        assert not looks_like_login_page(resp.text), "addwhitelistdom (exclude) POST returned the login form"
        assert domain in _suppression_entries(vm, CFG_TLDEXCLUSION), (
            f"{domain} not written to the TLD Exclusion config node after addwhitelistdom exclude=true"
        )

        # RESTORE via entry_delete=delete_exclusion (reverse + delete_exclusion coverage).
        resp = _post_action(webui, {"entry_delete": "delete_exclusion", "domain": domain, "table": "DNSBL"})
        assert not looks_like_login_page(resp.text), "entry_delete (exclusion) POST returned the login form"
        assert domain not in _suppression_entries(vm, CFG_TLDEXCLUSION), (
            f"{domain} still in the TLD Exclusion list after entry_delete=delete_exclusion"
        )
    finally:
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_TLDEXCLUSION}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore tldexclusion');\n"
            "echo 'OK';",
        )


# --------------------------------------------------------------------------- #
# addsuppress (alerts.php:741): add an IPv4 /32 or /24 to the IPv4 Suppression
# customlist (``v4suppression`` node). Validator: a valid IPv4 + cidr in {32,24} +
# a non-empty table word, else it exits with a savemsg and writes NOTHING.
#
# We cover the cidr=24 ACCEPT (which writes the network entry to v4suppression even
# without a live blocked IP -- the /24 branch never takes the /32 "blocked by a
# CIDR other than /24" early exit) and an invalid-IP REJECT (config unchanged). The
# /32 ACCEPT is NOT covered: it needs a real blocked IP in a live pf table to pass.
# --------------------------------------------------------------------------- #


def test_addsuppress_cidr24_writes_and_invalid_ip_rejected(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """addsuppress accepts a valid /24 (writes config) and rejects an invalid IP.

    Branch coverage for the IPv4-suppression validator, both with the ``v4suppression``
    config node as oracle:

    * REJECT first (proves the node's before-value): an invalid IPv4 makes the handler
      exit before any write -- the node is UNCHANGED.
    * ACCEPT (cidr=24): a valid IPv4 + cidr '24' + table word writes the /24 network
      entry (``a.b.c.0/24``) to ``v4suppression`` -- the node now contains it.

    The accept asserts the network entry is PRESENT where it was ABSENT, so the green
    proves the POST caused the write. Config is restored to its original base64 value
    in ``finally`` (the handler's pfctl calls against a non-resident table are no-ops,
    so nothing on pf is left to clean up).
    """
    vm = smoke_vm
    # A documentation-range (RFC 5737) IPv4; its /24 network is 198.51.100.0/24.
    valid_ip = "198.51.100.7"
    network24 = "198.51.100.0/24"
    table = "pfBlockerNGsmoke"
    original = helpers.config_get(vm, CFG_V4SUPPRESSION)
    try:
        # REJECT: an invalid IPv4 -> handler exits, no write. This also pins the
        # before-state of the config node (the network must be absent).
        assert network24 not in _suppression_entries(vm, CFG_V4SUPPRESSION), (
            f"{network24} already in v4suppression before the test"
        )
        resp = _post_action(
            webui,
            {"addsuppress": "Suppress", "ip": "999.999.999.999", "cidr": "32", "table": table},
        )
        assert not looks_like_login_page(resp.text), "addsuppress (invalid) POST returned the login form"
        assert helpers.config_get(vm, CFG_V4SUPPRESSION) == original, (
            "v4suppression config node changed after a REJECTED (invalid IP) addsuppress POST"
        )

        # ACCEPT: a valid IPv4 with cidr 24 -> writes the /24 network entry.
        resp = _post_action(
            webui,
            {"addsuppress": "Suppress", "ip": valid_ip, "cidr": "24", "table": table},
        )
        assert not looks_like_login_page(resp.text), "addsuppress (valid /24) POST returned the login form"
        assert network24 in _suppression_entries(vm, CFG_V4SUPPRESSION), (
            f"{network24} not written to v4suppression after a valid cidr=24 addsuppress POST"
        )
    finally:
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_V4SUPPRESSION}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore v4suppression');\n"
            "echo 'OK';",
        )


# --------------------------------------------------------------------------- #
# Upstream block rendering (issue #285): a synthetic Upstream_Block CSV line
# appended to dnsbl.log must render with the cloud icon ($pfb_python override)
# and the Group column must show "Upstream", NOT "Unknown".
#
# "Unknown" is what the stale-entry correction block (pfb_dnsbl_parse) would
# produce for a domain that is not in any local feed.  The $isUpstream guard
# skips that correction; these two assertions discriminate the branches:
#
#   fa-cloud   present  → Edit D step 9 (icon override) ran
#   Upstream   present  → Edit D step 8 (skip stale-correction) kept the group
#   Unknown    absent   → the old code path is NOT taken
# --------------------------------------------------------------------------- #


def test_upstream_block_renders_cloud_icon_and_correct_group(
    webui: "WebUI",
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Upstream_Block CSV line renders the cloud icon and preserves group 'Upstream'.

    Scenario: stale-correction skip + icon override for upstream DNS blocks.

    Background:
        pfblockerng_alerts.php ``convert_dnsbl_log`` has two paths for upstream
        blocks: (a) skip the ``pfb_dnsbl_parse`` stale-entry correction that would
        rewrite group/feed to 'Unknown', and (b) replace the bolt icon with a cloud.
        Both are tested by injecting a synthetic ``Upstream_Block`` CSV line directly
        into ``dnsbl.log`` and asserting the rendered HTML.

    Given: DNSBL is enabled (required for the DNSBL Python tab to appear); a
        synthetic ``Upstream_Block`` line for a unique domain is appended to
        ``/var/log/pfblockerng/dnsbl.log``.

    When: the Reports/Alerts page is GET-ted (default ``alert`` view, which renders
        the ``DNSBL Python`` tab from ``dnsbl.log``).

    Then:
        (a) ``fa-cloud`` is present in the rendered HTML for that domain's row —
            proving the bolt-icon override fired (Edit D step 9).
        (b) the text ``Upstream`` appears near the domain and the text ``Unknown``
            does NOT appear near it — proving the stale-entry correction was skipped
            (Edit D step 8); without the skip, pfb_dnsbl_parse would rewrite the
            group to 'Unknown'.

    Cleanup: the appended log line is removed in ``finally`` (truncate the file back
        to its original size) so the session VM is clean for sibling tests.
    """
    vm = smoke_vm
    domain = helpers.unique_domain("upstrmui")

    # The synthetic log line exactly mirrors _log_upstream_block's CSV output.
    # 11 fields (indices 0-10), comma-separated, with '+' as the dup-entry token.
    ts = time.strftime("%b %d %H:%M:%S")  # e.g. "Jun 18 12:00:00"
    csv_line = f"DNSBL-python,{ts},{domain},127.0.0.1,Python,Upstream_Block,Upstream,NXRA,Quad9,+,A\n"

    dnsbl_log = "/var/log/pfblockerng/dnsbl.log"

    # Capture the original byte size so we can truncate back to it on cleanup.
    size_result = vm.ssh("stat", "-f", "%z", dnsbl_log, timeout=15)
    original_size = size_result.stdout.strip() if size_result.returncode == 0 else "0"

    helpers.set_dnsbl_enabled(vm, True)

    try:
        # GIVEN: append the synthetic upstream-block line via SSH tee -a.
        subprocess.run(
            vm.ssh_argv("tee", "-a", dnsbl_log),
            input=csv_line,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        # WHEN: GET the Alerts page (default alert view → DNSBL Python tab).
        resp = webui.get(ALERTS_PAGE)
        assert not looks_like_login_page(resp.text), (
            "alerts page GET returned login form (session lost before upstream-block render test)"
        )
        html_body = resp.text

        # THEN (a): the cloud icon class is present in the page (Edit D step 9).
        assert "fa-cloud" in html_body, (
            f"fa-cloud icon class absent from the rendered Alerts page — "
            f"the upstream-block icon override (Edit D step 9) did not fire for {domain!r}"
        )

        # THEN (b): the domain appears and its row shows group 'Upstream', not 'Unknown'.
        # We find the domain in the rendered HTML and inspect a window around it.
        dom_idx = html_body.find(domain)
        assert dom_idx != -1, f"synthetic upstream-block domain {domain!r} not found in the rendered Alerts page HTML"
        # Look in a 2 kB window around the domain occurrence for the Group value.
        window = html_body[max(0, dom_idx - 1024) : dom_idx + 1024]
        assert "Upstream" in window, (
            f"Group 'Upstream' not found near domain {domain!r} in rendered HTML — "
            f"stale-entry correction may have overwritten it (Edit D step 8 check failed)"
        )
        assert "Unknown" not in window, (
            f"Group 'Unknown' found near domain {domain!r} in rendered HTML — "
            f"pfb_dnsbl_parse rewrote the group, meaning $isUpstream guard did not fire "
            f"(Edit D step 8 regression)"
        )
    finally:
        # Truncate dnsbl.log back to its pre-test size to remove the appended line.
        subprocess.run(
            vm.ssh_argv("/usr/bin/truncate", "-s", original_size, dnsbl_log),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
