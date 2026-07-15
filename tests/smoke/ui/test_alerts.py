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
from .webui import extract_csrf_token, looks_like_login_page, row_containing

if TYPE_CHECKING:
    import requests

    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"

# config.xml nodes the alerts handlers write (all base64 textarea fields).
CFG_SUPPRESSION = "installedpackages/pfblockerngdnsblsettings/config/0/suppression"
CFG_TLDEXCLUSION = "installedpackages/pfblockerngdnsblsettings/config/0/tldexclusion"
CFG_V4SUPPRESSION = "installedpackages/pfblockerngipsettings/config/0/v4suppression"
CFG_V6SUPPRESSION = "installedpackages/pfblockerngipsettings/config/0/v6suppression"

# The dynamic per-row IPv4 alias list the alerts `$clists['ipwhitelist4']`
# collection reads Permit aliases from (alerts.php:170-251).
CFG_IPV4_LISTS = "installedpackages/pfblockernglistsv4/config"

# The temporary Lock/Unlock state store ($pfb['dnsbl_unlock'], pfblockerng.inc:150).
# Written SYNCHRONOUSLY by pfb_unlock() -- unlike the DNS-visible effect (an async
# manifest patch + Unbound reload), so it is the reliable oracle for "this POST did
# NOT touch the unlock state" (no swap-timing race to poll around).
DNSBL_UNLOCK_STORE = "/tmp/dnsbl_unlock"


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
    ``finally`` drops the derived state (tables/sqlite + a filter sync) so the session VM
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
    store when ``dnsbl_type`` is empty (alerts.php:1444-1448 -- BEFORE the
    ``pfb_unlock()`` call at :1468). The primary oracle is the unlock store itself
    (``$pfb['dnsbl_unlock']``, pfblockerng.inc:150): it is written SYNCHRONOUSLY by
    ``pfb_unlock()``, so comparing its content before/after proves the handler did
    NOT run that far -- a single un-polled DNS probe right after the POST cannot
    rule out the async swap simply not having landed yet (a false pass). The DNS
    shape is kept as a corroborating check (still VIP-blocked).
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
        # BEFORE: VIP-blocked, and the (synchronous) unlock store at its pre-POST content.
        before = helpers.dns_probe(vm, domain, "A")
        assert helpers.is_vip(before), f"{domain} expected VIP block before the rejected POST, got {before}"
        store_before = helpers.read_log_file(vm, DNSBL_UNLOCK_STORE)

        # Reject: empty dnsbl_type. The handler must exit before toggling the store.
        resp = _post_action(webui, {"dnsbl_remove": "unlock", "domain": domain, "dnsbl_type": ""})
        assert not looks_like_login_page(resp.text), "rejected POST returned the login form (session lost)"

        # AFTER (real oracle): the synchronous unlock store is byte-for-byte unchanged --
        # no swap-timing race, unlike a bare DNS probe right after the POST.
        store_after = helpers.read_log_file(vm, DNSBL_UNLOCK_STORE)
        assert store_after == store_before, (
            f"dnsbl_unlock store changed after a REJECTED unlock POST: before={store_before!r} after={store_after!r}"
        )

        # Corroborating: still VIP-blocked.
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
# addsuppress (alerts.php addsuppress branch): carve a host (v4 or v6, ANY
# containing mask) out of whichever live pf table entry blocks it, and add the
# EXACT host to the correct-family Suppression customlist (ADR-53 §2.1 fork 3 --
# full rework). Validator: a valid IP (either family) + a non-empty table word,
# else it exits with a savemsg and writes NOTHING. The retired mechanism only
# understood a bare host or an EXACT /24 network and refused every other
# containing mask ("blocked by a CIDR other than /24"); it also had no v6 path
# at all and wrote the CHOSEN mask's network line (not the exact host) into the
# customlist.
#
# We cover: an invalid-IP REJECT (config unchanged); a valid IP with NO live
# table match, which still writes the exact host (the customlist add is a
# standing exemption for FUTURE loads, not contingent on today's live snapshot
# -- ADR-53 §2.1); and, as the headline multi-step scenario, a REAL containing-
# range carve for both families below.
# --------------------------------------------------------------------------- #


def test_addsuppress_writes_exact_host_and_invalid_ip_rejected(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """addsuppress writes the EXACT host (never a network line) and rejects a bad IP.

    Branch coverage for the any-mask/v4+v6 suppression validator, with
    ``v4suppression`` as oracle:

    * REJECT first (proves the node's before-value): an invalid IPv4 makes the
      handler exit before any write -- the node is UNCHANGED.
    * ACCEPT with no live table match: a valid IPv4 against a table with no
      matching entry still writes the ``ip/32`` line -- the retired mechanism's
      "blocked by a CIDR other than /24" refusal is gone, and the ADR-53
      rework always writes the EXACT host (never the old ``{ip}/24`` network
      line the pre-rework code wrote for its cidr=24 choice).

    Config is restored to its original base64 value in ``finally`` (a
    non-resident table's pfctl calls are no-ops, so nothing on pf needs cleanup).
    """
    vm = smoke_vm
    # A documentation-range (RFC 5737) IPv4.
    valid_ip = "198.51.100.7"
    host_entry = f"{valid_ip}/32"
    table = "pfBlockerNGsmoke"
    original = helpers.config_get(vm, CFG_V4SUPPRESSION)
    try:
        # REJECT: an invalid IPv4 -> handler exits, no write. This also pins the
        # before-state of the config node (the host entry must be absent).
        assert host_entry not in _suppression_entries(vm, CFG_V4SUPPRESSION), (
            f"{host_entry} already in v4suppression before the test"
        )
        resp = _post_action(webui, {"addsuppress": "true", "ip": "999.999.999.999", "table": table})
        assert not looks_like_login_page(resp.text), "addsuppress (invalid) POST returned the login form"
        assert helpers.config_get(vm, CFG_V4SUPPRESSION) == original, (
            "v4suppression config node changed after a REJECTED (invalid IP) addsuppress POST"
        )

        # ACCEPT: a valid IPv4 against a table with no live match -> still writes
        # the exact host (no mask choice exists any more; no refusal either).
        resp = _post_action(webui, {"addsuppress": "true", "ip": valid_ip, "table": table})
        assert not looks_like_login_page(resp.text), "addsuppress (valid, no live match) POST returned the login form"
        assert host_entry in _suppression_entries(vm, CFG_V4SUPPRESSION), (
            f"{host_entry} not written to v4suppression after a valid addsuppress POST"
        )
    finally:
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_V4SUPPRESSION}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore v4suppression');\n"
            "echo 'OK';",
        )
        helpers.reset(vm)


def test_addsuppress_v4_carves_containing_range_and_spares_sibling(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """The "+" carves a host out of a containing /16 (ADR-53 §2.1 fork 3, headline case).

    True multi-step transition (CLAUDE.md before/after rule): a local IPv4 feed
    lists an RFC 2544 benchmarking ``/16`` (``198.18.0.0/16`` -- the retired
    mechanism could only ever express an exact ``/24`` or a bare host, so this
    mask was UNSUPPRESSIBLE before this phase) plus a separate sibling entry
    outside it.

    * SETUP: inject the feed as a Deny alias; a force IP update settles it.
    * BEFORE: the target host AND the sibling both match the live pf table
      (``pfctl -T test``); the target's exact-host entry is absent from
      ``v4suppression``.
    * WHEN: the "+" (``addsuppress``) is driven for the target host only.
    * THEN: the target no longer matches the table (the containing ``/16`` was
      carved into covering CIDRs and re-added minus the hole -- never a
      254-host explosion, never the old refusal); the sibling -- a distinct
      feed entry entirely outside the hole -- still matches; ``v4suppression``
      gained the EXACT ``ip/32`` host line.

    Teardown drops the injected list + derived pf state (``helpers.reset``) and
    restores ``v4suppression`` to its original value.
    """
    vm = smoke_vm
    target = "198.18.5.9"  # inside 198.18.0.0/16
    sibling = "198.19.50.5"  # a SEPARATE feed entry, RFC 2544 space, outside the /16 hole
    host_entry = f"{target}/32"

    feed_url = helpers.write_local_feed(vm, "ui_punch4.txt", f"198.18.0.0/16\n{sibling}\n")
    spec = helpers.IpCase(aliasname="uipunch4", feed_url=feed_url, header="uipunch4")
    table = spec.alias
    original = helpers.config_get(vm, CFG_V4SUPPRESSION)

    helpers.inject(vm, spec)
    helpers.reload(vm, "updateip")
    try:
        # BEFORE: the table is populated (filter_configure lands async after the
        # CLI returns, hence the poll) and both addresses match it live.
        members = helpers.wait_pfctl_table(vm, table)
        assert members, f"pf table {table} never populated after the settling update"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, f"{target} expected to match pf table {table} before suppression; pfctl said: {raw!r}"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, sibling)
        assert matched, f"{sibling} expected to match pf table {table} before suppression; pfctl said: {raw!r}"
        assert host_entry not in _suppression_entries(vm, CFG_V4SUPPRESSION), (
            f"{host_entry} already in v4suppression before the test"
        )

        # WHEN: drive the "+" for the target host against the containing-/16 table.
        resp = _post_action(webui, {"addsuppress": "true", "ip": target, "table": table})
        assert not looks_like_login_page(resp.text), "addsuppress POST returned the login form (session lost)"

        # THEN: the target no longer matches (carved out of the /16); the
        # sibling -- a separate feed entry entirely outside the hole -- is untouched.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert not matched, (
            f"{target} still matches pf table {table} after addsuppress -- the live punch did not take "
            f"effect; pfctl said: {raw!r}"
        )
        matched, raw = helpers.pfctl_table_test_raw(vm, table, sibling)
        assert matched, (
            f"{sibling} no longer matches pf table {table} after addsuppress -- an unrelated entry was "
            f"punched; pfctl said: {raw!r}"
        )

        # THEN: v4suppression gained the EXACT host -- never a 254-host
        # explosion or the retired {ip}/24 shape, any containing mask.
        assert host_entry in _suppression_entries(vm, CFG_V4SUPPRESSION), (
            f"{host_entry} not written to v4suppression after addsuppress"
        )
    finally:
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_V4SUPPRESSION}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore v4suppression');\n"
            "echo 'OK';",
        )
        helpers.reset(vm)


def test_addsuppress_v6_carves_containing_range_and_spares_sibling(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """The "+" carves a v6 host out of a containing /64 -- v6 was NEVER punchable before.

    Same multi-step shape as the v4 case above, over the ``v6suppression``
    node: an RFC 3849 documentation ``/64`` (``2001:db8:18:1::/64``) feed plus a
    sibling entry in a SEPARATE ``/64``. Before Phase 8, ``v6suppression`` had
    no live-punch path at all (the retired mechanism was v4-only). BEFORE both
    addresses match the live table; the "+" carves ONLY the target out (the
    sibling, a distinct feed entry, is untouched); ``v6suppression`` gains the
    exact ``ip/128`` host line. Teardown mirrors the v4 case.
    """
    vm = smoke_vm
    target = "2001:db8:18:1::42"  # inside 2001:db8:18:1::/64
    sibling = "2001:db8:18:2::9"  # a SEPARATE feed entry, a different /64, outside the hole
    host_entry = f"{target}/128"

    feed_url = helpers.write_local_feed(vm, "ui_punch6.txt", f"2001:db8:18:1::/64\n{sibling}\n")
    spec = helpers.IpCase(aliasname="uipunch6", feed_url=feed_url, header="uipunch6", family="v6")
    table = spec.alias
    original = helpers.config_get(vm, CFG_V6SUPPRESSION)

    helpers.inject(vm, spec)
    helpers.reload(vm, "updateip")
    try:
        members = helpers.wait_pfctl_table(vm, table)
        assert members, f"pf table {table} never populated after the settling update"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, f"{target} expected to match pf table {table} before suppression; pfctl said: {raw!r}"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, sibling)
        assert matched, f"{sibling} expected to match pf table {table} before suppression; pfctl said: {raw!r}"
        assert host_entry not in _suppression_entries(vm, CFG_V6SUPPRESSION), (
            f"{host_entry} already in v6suppression before the test"
        )

        resp = _post_action(webui, {"addsuppress": "true", "ip": target, "table": table})
        assert not looks_like_login_page(resp.text), "addsuppress POST returned the login form (session lost)"

        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert not matched, (
            f"{target} still matches pf table {table} after addsuppress -- the live punch did not take "
            f"effect; pfctl said: {raw!r}"
        )
        matched, raw = helpers.pfctl_table_test_raw(vm, table, sibling)
        assert matched, (
            f"{sibling} no longer matches pf table {table} after addsuppress -- an unrelated entry was "
            f"punched; pfctl said: {raw!r}"
        )
        assert host_entry in _suppression_entries(vm, CFG_V6SUPPRESSION), (
            f"{host_entry} not written to v6suppression after addsuppress"
        )
    finally:
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_V6SUPPRESSION}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore v6suppression');\n"
            "echo 'OK';",
        )
        helpers.reset(vm)


def test_addsuppress_v4_already_covered_by_broader_entry_skips_duplicate(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """The "+" recognises a host already covered by a BROADER manual entry (ADR-53 review H6).

    Before this fix, the addsuppress dedup only matched an EXACT host_line --
    a host already covered by a wider existing entry (e.g. a /20 added earlier
    by hand) still got its own redundant '/32' appended. Given a broader
    v4suppression entry already covering the target (seeded directly, as a
    prior manual "+"/edit would leave it -- NOT the exact host, so an
    exact-match-only dedup would miss it): clicking "+" must (1) leave
    v4suppression WITHOUT a new exact host_line for the target -- only the
    pre-existing broader entry remains; (2) surface the "already covered by an
    existing ... Suppression entry" savemsg; (3) still perform the live
    pf-table punch (unconditional, unaffected by this dedup check).
    """
    vm = smoke_vm
    target = "198.18.9.20"  # inside the broader /20 below
    broader_entry = "198.18.0.0/20"
    sibling = "198.19.60.6"  # a SEPARATE feed entry, outside the /20

    feed_url = helpers.write_local_feed(vm, "ui_punch4_covered.txt", f"198.18.0.0/16\n{sibling}\n")
    spec = helpers.IpCase(aliasname="uipunch4cov", feed_url=feed_url, header="uipunch4cov")
    table = spec.alias
    original = helpers.config_get(vm, CFG_V4SUPPRESSION)

    helpers.inject(vm, spec)
    helpers.reload(vm, "updateip")
    try:
        # GIVEN: a broader manual suppression entry already covers the target
        # -- seeded directly via config (mirroring a prior manual "+"/edit),
        # NOT the exact host, so an exact-match-only dedup would miss it.
        broader_b64 = base64.b64encode(f"{broader_entry}\r\n".encode()).decode()
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_V4SUPPRESSION}', '{broader_b64}');\n"
            "write_config('pfBlockerNG smoke: seed broader v4suppression entry');\n"
            "echo 'OK';",
        )

        # BEFORE: the target still matches the live table (the broader
        # suppression entry is config-only until this point -- no reload ran
        # since it was seeded).
        members = helpers.wait_pfctl_table(vm, table)
        assert members, f"pf table {table} never populated after the settling update"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, (
            f"{target} expected to match pf table {table} before the covered-host addsuppress; pfctl said: {raw!r}"
        )

        # WHEN: click "+" on the target -- already covered by the broader /20.
        resp = _post_action(webui, {"addsuppress": "true", "ip": target, "table": table})
        assert not looks_like_login_page(resp.text), "addsuppress POST returned the login form (session lost)"

        # THEN: no redundant exact-host entry was appended -- only the
        # pre-existing broader entry remains in v4suppression.
        entries = _suppression_entries(vm, CFG_V4SUPPRESSION)
        assert entries == {broader_entry}, (
            f"expected v4suppression to still hold ONLY the broader entry {broader_entry!r} (no redundant "
            f"{target}/32 appended); got {entries}"
        )

        # THEN: the savemsg names the "already covered" case, not "added".
        assert "already covered by an existing" in resp.text, (
            "expected the 'already covered by an existing ... Suppression entry' savemsg after a "
            "covered-host addsuppress POST; response body did not contain it"
        )
    finally:
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_V4SUPPRESSION}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore v4suppression');\n"
            "echo 'OK';",
        )
        helpers.reset(vm)


# --------------------------------------------------------------------------- #
# entry_delete=delete_ip (alerts.php:1330 -- issue #422, ADR-53 parity follow-up):
# un-suppress a customlist entry and restore the live block. Before this fix the
# handler only recognised an exact '/32' customlist key or a containing '/24' --
# any OTHER mask (e.g. a manually-added /28) made the lookup miss entirely (the
# handler replied "not found", touching neither the customlist nor the pf table),
# and the entry_delete VALIDATION GATE itself was PFB_FILTER_IPV4, so an IPv6
# domain was rejected before ever reaching the handler. pfb_ip_suppressed_match()
# (longest-prefix, any mask, either family) fixes both: it resolves the ALERTED
# HOST to its covering customlist entry, removes that entry, and re-adds it to
# the live pf table -- restoring exactly the coverage it had carved out.
# --------------------------------------------------------------------------- #


def test_delete_ip_v4_unsuppresses_broader_entry_and_restores_block(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """entry_delete=delete_ip un-suppresses a BROADER (/28) v4 entry, restoring the block.

    Before #422 the handler only understood an exact '/32' or a containing '/24'
    customlist key -- a manually-added /28 (or any other mask) made the lookup
    MISS entirely: "not found", customlist and pf table both left untouched. The
    longest-prefix pfb_ip_suppressed_match() fixes the lookup for any mask.

    Given: a live Deny v4 pf table (built exactly like the addsuppress carve
    tests -- inject a feed + Force IP Update) whose feed does NOT cover the
    suppressed /28 hole, plus a manually-seeded v4suppression entry
    '198.51.100.0/28' covering the host that will be "deleted".
    When: entry_delete=delete_ip is posted for the ALERTED HOST (not the
    customlist entry itself -- the handler must resolve host -> covering /28).
    Then: the /28 entry is gone from v4suppression, and the host now matches the
    pf table (the removed entry was re-added, restoring the block it carved out).
    """
    vm = smoke_vm
    target = "198.51.100.5"  # inside the /28 hole below (RFC 5737 TEST-NET-2)
    supp_entry = "198.51.100.0/28"  # broader than the retired /32|/24-only lookup
    sibling = "198.51.100.200"  # outside the /28 -- feeds the table so it EXISTS

    feed_url = helpers.write_local_feed(vm, "ui_unsupp4.txt", f"{sibling}/32\n")
    spec = helpers.IpCase(aliasname="uiunsupp4", feed_url=feed_url, header="uiunsupp4")
    table = spec.alias
    original = helpers.config_get(vm, CFG_V4SUPPRESSION)

    helpers.inject(vm, spec)
    helpers.reload(vm, "updateip")
    try:
        # GIVEN: seed the broader manual suppression entry directly (mirrors a
        # prior manual customlist edit, not one produced by addsuppress here).
        supp_b64 = base64.b64encode(f"{supp_entry} # smoke-unsuppress\r\n".encode()).decode()
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_V4SUPPRESSION}', '{supp_b64}');\n"
            "write_config('pfBlockerNG smoke: seed v4suppression /28 for unsuppress');\n"
            "echo 'OK';",
        )

        # BEFORE: the table exists (the sibling populated it) and does NOT cover
        # the suppressed hole; the /28 entry is present in v4suppression.
        members = helpers.wait_pfctl_table(vm, table)
        assert members, f"pf table {table} never populated after the settling update"
        assert supp_entry in _suppression_entries(vm, CFG_V4SUPPRESSION), (
            f"{supp_entry} not present in v4suppression before the un-suppress POST"
        )
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert not matched, (
            f"{target} unexpectedly matches pf table {table} before the un-suppress; pfctl said: {raw!r}"
        )

        # WHEN: entry_delete=delete_ip for the ALERTED HOST -- the handler must
        # resolve host -> covering /28 itself via pfb_ip_suppressed_match().
        resp = _post_action(webui, {"entry_delete": "delete_ip", "domain": target, "table": table})
        assert not looks_like_login_page(resp.text), "delete_ip POST returned the login form (session lost)"

        # THEN: the /28 entry is gone from v4suppression ...
        entries = _suppression_entries(vm, CFG_V4SUPPRESSION)
        assert supp_entry not in entries, (
            f"{supp_entry} still present in v4suppression after entry_delete=delete_ip; entries={entries}"
        )
        # ... and the host now matches the pf table again -- the removed entry
        # was re-added, restoring exactly the block it had carved out.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, (
            f"{target} does not match pf table {table} after un-suppressing the covering /28 -- "
            f"the block was not restored; pfctl said: {raw!r}"
        )
    finally:
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_V4SUPPRESSION}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore v4suppression');\n"
            "echo 'OK';",
        )
        helpers.reset(vm)


def test_delete_ip_v6_unsuppresses_entry_and_restores_block(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """entry_delete=delete_ip un-suppresses a v6 entry -- IPv6 was REJECTED before #422.

    Before #422 the entry_delete VALIDATION GATE was PFB_FILTER_IPV4, so ANY IPv6
    domain was rejected outright (a savemsg, no config write) before ever reaching
    the delete_ip handler -- there was no v6 branch at all. The gate is now
    PFB_FILTER_IP (both families), and the handler routes an IPv6 host through
    v6suppression + ``pfctl -t <table> -T add``.

    Given: a live Deny v6 pf table, plus a manually-seeded v6suppression entry
    '2001:db8:aa::/64' covering the host that will be "deleted".
    When: entry_delete=delete_ip is posted for the host.
    Then: the /64 entry is gone from v6suppression, and the host now matches the
    pf table again (the block is restored).
    """
    vm = smoke_vm
    target = "2001:db8:aa::5"  # inside the suppressed /64 (RFC 3849)
    supp_entry = "2001:db8:aa::/64"
    sibling = "2001:db8:bb::1"  # a SEPARATE /64 -- feeds the table so it EXISTS

    feed_url = helpers.write_local_feed(vm, "ui_unsupp6.txt", f"{sibling}/128\n")
    spec = helpers.IpCase(aliasname="uiunsupp6", feed_url=feed_url, header="uiunsupp6", family="v6")
    table = spec.alias
    original = helpers.config_get(vm, CFG_V6SUPPRESSION)

    helpers.inject(vm, spec)
    helpers.reload(vm, "updateip")
    try:
        supp_b64 = base64.b64encode(f"{supp_entry} # smoke-unsuppress\r\n".encode()).decode()
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_V6SUPPRESSION}', '{supp_b64}');\n"
            "write_config('pfBlockerNG smoke: seed v6suppression /64 for unsuppress');\n"
            "echo 'OK';",
        )

        # BEFORE: the table exists (the sibling populated it) and does NOT cover
        # the suppressed hole; the /64 entry is present in v6suppression.
        members = helpers.wait_pfctl_table(vm, table)
        assert members, f"pf table {table} never populated after the settling update"
        assert supp_entry in _suppression_entries(vm, CFG_V6SUPPRESSION), (
            f"{supp_entry} not present in v6suppression before the un-suppress POST"
        )
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert not matched, (
            f"{target} unexpectedly matches pf table {table} before the un-suppress; pfctl said: {raw!r}"
        )

        # WHEN: entry_delete=delete_ip for the IPv6 host -- REJECTED outright
        # before #422 (PFB_FILTER_IPV4 gate), so this POST alone is part of the
        # regression this test pins.
        resp = _post_action(webui, {"entry_delete": "delete_ip", "domain": target, "table": table})
        assert not looks_like_login_page(resp.text), "delete_ip POST returned the login form (session lost)"

        # THEN: the /64 entry is gone from v6suppression ...
        entries = _suppression_entries(vm, CFG_V6SUPPRESSION)
        assert supp_entry not in entries, (
            f"{supp_entry} still present in v6suppression after entry_delete=delete_ip; entries={entries}"
        )
        # ... and the host now matches the pf table again.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, (
            f"{target} does not match pf table {table} after un-suppressing the covering /64 -- "
            f"the block was not restored; pfctl said: {raw!r}"
        )
    finally:
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_V6SUPPRESSION}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore v6suppression');\n"
            "echo 'OK';",
        )
        helpers.reset(vm)


# --------------------------------------------------------------------------- #
# Suppression-icon render eligibility (convert_ip_log, alerts.php:3057 -- issue
# #422, ADR-53 follow-up). Before this fix the gate was
# ``$pfb_ipv4 && !$pfb_geoip && $mask_suppression`` -- TRUE only for a v4 host
# evaluated against an exact /32 or /24 mask. A v6 Block row, or a v4 row
# evaluated against any OTHER mask, got NEITHER the "+" (add) nor the trash-can
# (un-suppress) icon at all. The gate is now family/mask-agnostic
# (``$rtype == 'Block' && !$pfb_geoip``), and the covered-vs-not lookup itself
# is prefix-aware (pfb_ip_suppressed_match()), so a host covered by a BROADER
# manual entry (not just an exact /32 or /24 key) now gets the trash-can too.
# --------------------------------------------------------------------------- #


def test_alerts_rows_render_suppress_icons_for_v6_and_broad_v4(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Alerts render the Suppression icon for a v6 row and a broad-mask v4 row.

    Scenario: suppress-icon render eligibility, any family/mask.

    Background: three synthetic Block rows are appended directly to
    ip_block.log (the same CSV-injection technique as issue #361's rendering
    test), each exercising one branch the retired v4-only /32|/24 gate could
    not reach: (a) a v6 host, (b) a v4 host evaluated against a broad /16 mask,
    (c) a v4 host covered by a manually-seeded BROADER (/28) v4suppression
    entry, with the master Suppression toggle forced ON.

    Given: DNSBL is untouched; the three rows above are appended to
        ip_block.log, none of their icon markers rendered beforehand.
    When: the Alerts page is GET-ted (default view, which renders ip_block.log).
    Then:
        (a) and (b) render the "+" (``PFBIPSUP|add|<host>``) icon -- both rows
            would have rendered NEITHER icon under the retired v4-only/32|/24 gate.
        (c) renders the trash-can (``DNSBLWT|delete_ip|<host>``) icon -- the
            prefix-aware match finds the covering /28, which an exact-/32|/24-only
            lookup would have missed (the row would have gotten the "+" instead).

    Cleanup: the appended log lines are truncated back off in ``finally``, the
    master Suppression toggle + v4suppression are restored to their original
    values, and the seeded deny-folder feed files are removed.

    NB: each row's evaluated IP must exist (line-start match) in a deny-folder
    feed file named after the row's feed column -- convert_ip_log() re-validates
    every row against the on-disk feeds and STRIPS the suppression icon from a
    "Not listed!" row (alerts.php, "Remove Suppression Icon for 'Not Listed'
    events"), so without the seeded feed files every assert here fails for the
    wrong reason.
    """
    vm = smoke_vm

    v6_host = helpers.IPV6_FOREIGN  # 2001:db8:dead:beef::1
    v6_local = helpers.IPV6_LOCAL_HOST
    v4_broad_host = "198.51.100.77"  # RFC 5737 TEST-NET-2, evaluated against a /16
    v4_supp_host = "203.0.113.9"  # RFC 5737 TEST-NET-3, covered by the seeded /28
    supp_entry = "203.0.113.0/28"

    ts = time.strftime("%b %d %H:%M:%S")  # e.g. "Jun 18 12:00:00"
    # ip_block.log CSV format (21 fields, see the issue #361 test above):
    # ts,rule,real_iface,friendly_iface,action,ipv,proto_id,proto,
    # src_ip,dst_ip,src_port,dst_port,dir,geoip,alias,ip_eval,feed,rhost,chost,asn,dup
    csv_lines = (
        # (a) v6, inbound -> $host = SRC = the foreign v6 address; ip_eval /48.
        f"{ts},100,em0,WAN,block,6,58,ICMPV6,"
        f"{v6_host},{v6_local},,"
        f",in,US,pfB_Deny_v6,"
        "2001:db8:dead::/48,pfB_TestFeed_v6,Unknown,Unknown,Unknown,+\n"
        # (b) v4, inbound -> $host = SRC = the broad-mask host; ip_eval mask /16.
        f"{ts},100,em0,WAN,block,4,6,TCP,"
        f"{v4_broad_host},10.0.0.5,12345,443,"
        "in,US,pfB_Deny_v4,"
        "198.51.0.0/16,pfB_TestFeed_v4,Unknown,Unknown,Unknown,+\n"
        # (c) v4, inbound -> $host covered by the seeded v4suppression /28.
        f"{ts},100,em0,WAN,block,4,6,TCP,"
        f"{v4_supp_host},10.0.0.6,12345,443,"
        "in,US,pfB_Deny_v4,"
        "203.0.113.0/28,pfB_TestFeed_v4,Unknown,Unknown,Unknown,+\n"
    )

    ip_block_log = helpers.IP_BLOCK_LOG
    supp_master_path = "installedpackages/pfblockerngipsettings/config/0/suppression"
    original_supp = helpers.config_get(vm, CFG_V4SUPPRESSION)
    original_master = helpers.config_get(vm, supp_master_path)

    # The deny-folder feed files that make the three rows "listed" (see the
    # docstring NB): file name = the CSV feed column + .txt, line-start match
    # on the evaluated IP.
    deny_feed_v4 = "/var/db/pfblockerng/deny/pfB_TestFeed_v4.txt"
    deny_feed_v6 = "/var/db/pfblockerng/deny/pfB_TestFeed_v6.txt"

    # ip_block.log is created lazily -- guarantee it (and its dir) exist idempotently
    # before appending (mirrors the issue #361 test's precondition handling).
    log_dir = ip_block_log.rsplit("/", 1)[0]
    ensure_result = vm.ssh(f"mkdir -p {log_dir} && touch {ip_block_log}", timeout=15)
    assert ensure_result.returncode == 0, (
        f"Failed to ensure {ip_block_log!r} exists before mutation: "
        f"rc={ensure_result.returncode}, stderr={ensure_result.stderr!r}"
    )
    size_result = vm.ssh("stat", "-f", "%z", ip_block_log, timeout=15)
    assert size_result.returncode == 0, (
        f"Failed to stat {ip_block_log!r} before mutation: rc={size_result.returncode}, stderr={size_result.stderr!r}"
    )
    original_size = size_result.stdout.strip()

    try:
        # GIVEN: master Suppression forced ON + a /28 v4suppression entry covering (c).
        supp_b64 = base64.b64encode(f"{supp_entry} # smoke-icon\r\n".encode()).decode()
        helpers.php_eval(
            vm,
            f"config_set_path('{supp_master_path}', 'on');\n"
            f"config_set_path('{CFG_V4SUPPRESSION}', '{supp_b64}');\n"
            "write_config('pfBlockerNG smoke: seed suppression for icon test');\n"
            "echo 'OK';",
        )

        # GIVEN: the rows' evaluated IPs exist in their deny-folder feed files,
        # so convert_ip_log()'s feed re-validation keeps the icons (docstring NB).
        seed_result = vm.ssh(
            f"printf '198.51.0.0/16\\n203.0.113.0/28\\n' > {deny_feed_v4} && "
            f"printf '2001:db8:dead::/48\\n' > {deny_feed_v6}",
            timeout=15,
        )
        assert seed_result.returncode == 0, (
            f"Failed to seed deny-folder feed files: rc={seed_result.returncode}, stderr={seed_result.stderr!r}"
        )

        # BEFORE (no false pass): none of the three icon markers are present yet.
        pre = webui.get(ALERTS_PAGE)
        assert not looks_like_login_page(pre.text), "alerts page GET returned login form before mutation (session lost)"
        for marker in (
            f"PFBIPSUP|add|{v6_host}",
            f"PFBIPSUP|add|{v4_broad_host}",
            f"DNSBLWT|delete_ip|{v4_supp_host}",
        ):
            assert marker not in pre.text, f"Precondition failed: {marker!r} already present before the synthetic rows"

        # WHEN: append the synthetic rows and GET the Alerts page (default view).
        append_result = subprocess.run(
            vm.ssh_argv("tee", "-a", ip_block_log),
            input=csv_lines,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert append_result.returncode == 0, (
            f"Failed to append synthetic lines to {ip_block_log!r}: "
            f"rc={append_result.returncode}, stderr={append_result.stderr!r}"
        )

        resp = webui.get(ALERTS_PAGE)
        assert not looks_like_login_page(resp.text), (
            "alerts page GET returned login form (session lost before icon render test)"
        )
        html_body = resp.text

        # THEN (a): v6 Block row -> "+" icon (never rendered under the v4-only gate).
        assert f"PFBIPSUP|add|{v6_host}" in html_body, (
            f"'+' suppression icon missing for v6 host {v6_host!r} -- the retired v4-only gate "
            "would have skipped this row entirely"
        )
        # THEN (b): v4 row evaluated against a broad /16 -> "+" icon (the retired
        # gate required an exact /32 or /24 mask).
        assert f"PFBIPSUP|add|{v4_broad_host}" in html_body, (
            f"'+' suppression icon missing for v4 host {v4_broad_host!r} evaluated against a /16 "
            "mask -- the retired mask_suppression gate only accepted /32 or /24"
        )
        # THEN (c): v4 row covered by a manual /28 -> trash-can icon (prefix-aware match).
        assert f"DNSBLWT|delete_ip|{v4_supp_host}" in html_body, (
            f"trash-can (un-suppress) icon missing for v4 host {v4_supp_host!r} covered by the "
            f"broader {supp_entry!r} entry -- an exact-/32|/24-only lookup would have missed it"
        )
    finally:
        truncate_result = subprocess.run(
            vm.ssh_argv("/usr/bin/truncate", "-s", original_size, ip_block_log),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert truncate_result.returncode == 0, (
            f"Failed to restore {ip_block_log!r} to size={original_size!r}: "
            f"rc={truncate_result.returncode}, stderr={truncate_result.stderr!r}"
        )
        vm.ssh(f"rm -f {deny_feed_v4} {deny_feed_v6}", timeout=15)
        helpers.php_eval(
            vm,
            f"config_set_path('{supp_master_path}', '{original_master}');\n"
            f"config_set_path('{CFG_V4SUPPRESSION}', '{original_supp}');\n"
            "write_config('pfBlockerNG smoke: restore suppression for icon test');\n"
            "echo 'OK';",
        )


# --------------------------------------------------------------------------- #
# Issue #798 dedup oracle: convert_ip_log() rendered the "Permit Whitelist
# icon" via TWO byte-for-byte duplicated blocks -- the Suppression-icon gate's
# whitelist sub-path ("Check if host is in a Permit Whitelist Alias", reached
# only for a Block row not covered by any Suppression entry) and the
# standalone "IP Whitelist Icon" fallback block below it (reached by every
# OTHER row -- Permit, Match, GeoIP -- since a Block/non-GeoIP row is excluded
# from it per its own gate comment). Issue #798 extracts the shared "is $host
# in a Permit alias -> trash-can" logic into pfb_whitelist_trash_icon(); THIS
# test is the behaviour-preserving ORACLE (CLAUDE.md test-mandate exception:
# pins the CURRENT rendering, deliberately not red->green, and must stay green
# both before and after the extraction).
# --------------------------------------------------------------------------- #


def _free_list_rowid(vm: helpers.SmokeVM, cfg_root: str) -> int:
    """Return a free numeric index under a pfblockernglistsv{4,6}/config root.

    Mirrors ``test_category_edit.py``'s ``_free_rowid``: ``max(existing numeric
    keys) + 1`` via the config API, so the seeded alias slot never clobbers a
    row another suite (or an earlier case) left behind.
    """
    pre = (
        f"$c = config_get_path({helpers._php_str(cfg_root)}, array());\n"
        "$max = -1;\n"
        "foreach (array_keys($c) as $k) { if (is_numeric($k) && (int)$k > $max) { $max = (int)$k; } }\n"
        "$free = $max + 1;"
    )
    return int(helpers._php_read_scalar(vm, pre, "$free"))


def _del_list_row(vm: helpers.SmokeVM, cfg_root: str, rowid: int) -> None:
    """Delete ``{cfg_root}/{rowid}`` -- cleanup of the alias slot this test created."""
    snippet = (
        f"config_del_path({helpers._php_str(f'{cfg_root}/{rowid}')});\n"
        "write_config('pfBlockerNG smoke: drop #798 whitelist-icon oracle alias row');\n"
        "echo 'OK';"
    )
    result = helpers.php_eval(vm, snippet)
    if result.returncode != 0 or "OK" not in result.stdout:
        raise RuntimeError(f"_del_list_row({cfg_root}/{rowid}) failed: rc={result.returncode} {result.stdout!r}")


def test_alerts_rows_render_whitelist_icons_oracle(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Pin both duplicated Permit-Whitelist icon paths in convert_ip_log() (issue #798).

    Scenario: refactor oracle for the #798 dedup -- both duplicated blocks must
    keep rendering identically across the extraction.

    Background: a Permit v4 alias (``Wlorc798``, action containing ``Permit``) has
    one customlist host, ``203.0.113.77``. Master IP Suppression is ON and
    ``203.0.113.77`` is in no Suppression list, so the Suppression-icon gate falls
    into its whitelist sub-path. A second host, ``203.0.113.88``, is NOT in the
    alias's customlist.

    The fallback block's ``$supp_ip`` is only ever PRINTED for ``$rtype ==
    'Block'`` rows (convert_ip_log()'s icon assembly drops it for
    Permit/Match rows), so the only row class whose icons the fallback gate
    (``!(Block && !geoip) && !$mask_suppression``) visibly renders is a
    **GeoIP Block row** with an eval mask outside {/32, /24, /25-/31} -- that
    is what pins path (b).

    Given: neither icon marker is rendered before the synthetic rows exist.
    When:
        (a) a synthetic Block ``ip_block.log`` row for ``203.0.113.77`` (listed in
            a deny-folder feed file, so it is never "Not listed!") is appended,
            with master Suppression ON and the host in no Suppression list.
        (b) a synthetic GeoIP Block ``ip_block.log`` row (alias ``pfB_Europe_v4``
            -- the continent prefix makes ``$pfb_geoip`` TRUE, which excludes the
            row from the Suppression-icon gate) for ``203.0.113.88``, evaluated
            against a ``/23`` (so ``$mask_suppression``/``$mask_unlock`` are both
            FALSE and the row reaches the FALLBACK gate), listed in a GeoIP
            continent-folder feed file, is appended.
    Then:
        (a) the trash-can un-whitelist icon renders for ``203.0.113.77`` --
            ``DNSBLWT|delete_ipwhitelist|203.0.113.77`` (the Suppression gate's
            whitelist sub-path, via ``pfb_whitelist_trash_icon()``).
        (b) the "+" whitelist icon renders for ``203.0.113.88`` --
            ``PFBIPWHITE|203.0.113.88`` (the fallback block's else-branch).

    Both id strings, and the condition each path needs (host present vs. absent
    in a Permit alias's customlist), are exactly what step 2's helper extraction
    must preserve for this test to stay green.

    Cleanup (``finally``, order-independent): the log is truncated back to its
    original size, the seeded deny/GeoIP feed files are removed, the seeded
    Permit alias config row is deleted, and Suppression (master + v4 list) is
    restored to its original value.
    """
    vm = smoke_vm

    trash_host = "203.0.113.77"  # RFC 5737 TEST-NET-3 -- IN the seeded Permit alias
    plus_host = "203.0.113.88"  # same block, NOT in the seeded Permit alias

    ts = time.strftime("%b %d %H:%M:%S")  # e.g. "Jun 18 12:00:00"
    # ip_block.log CSV format (21 fields, see the suppress-icon
    # test above): ts,rule,real_iface,friendly_iface,action,ipv,proto_id,proto,
    # src_ip,dst_ip,src_port,dst_port,dir,geoip,alias,ip_eval,feed,rhost,chost,asn,dup
    block_csv = (
        f"{ts},100,em0,WAN,block,4,6,TCP,"
        f"{trash_host},10.0.0.10,12345,443,"
        "in,US,pfB_798AliasDeny_v4,"
        f"{trash_host}/32,pfB_798BlockFeed_v4,Unknown,Unknown,Unknown,+\n"
    )
    geo_csv = (
        f"{ts},100,em0,WAN,block,4,6,TCP,"
        f"{plus_host},10.0.0.11,12345,443,"
        "in,US,pfB_Europe_v4,"
        "203.0.113.0/23,798GeoFeed,Unknown,Unknown,Unknown,+\n"
    )

    ip_block_log = helpers.IP_BLOCK_LOG
    deny_feed = "/var/db/pfblockerng/deny/pfB_798BlockFeed_v4.txt"
    # GeoIP rows re-validate against $pfb['ccdir'] (alerts.php: $folder for
    # $pfb_geoip), filtered by the row's feed column + '.txt'.
    geo_feed = "/usr/local/share/GeoIP/cc/798GeoFeed.txt"
    supp_master_path = "installedpackages/pfblockerngipsettings/config/0/suppression"

    original_master = helpers.config_get(vm, supp_master_path)
    original_v4supp = helpers.config_get(vm, CFG_V4SUPPRESSION)

    rowid = _free_list_rowid(vm, CFG_IPV4_LISTS)
    base = f"{CFG_IPV4_LISTS}/{rowid}"
    permit_row = {
        "aliasname": "Wlorc798",
        "action": "Permit",
        "custom": helpers._b64_textarea([trash_host]),
    }

    # ip_block.log is created lazily -- guarantee it (and its dir) exists
    # idempotently before appending.
    ensure_result = vm.ssh(f"mkdir -p {ip_block_log.rsplit('/', 1)[0]} && touch {ip_block_log}", timeout=15)
    assert ensure_result.returncode == 0, (
        f"Failed to ensure {ip_block_log!r} exists before mutation: "
        f"rc={ensure_result.returncode}, stderr={ensure_result.stderr!r}"
    )
    block_size_result = vm.ssh("stat", "-f", "%z", ip_block_log, timeout=15)
    assert block_size_result.returncode == 0, (
        f"Failed to stat {ip_block_log!r} before mutation: rc={block_size_result.returncode}, "
        f"stderr={block_size_result.stderr!r}"
    )
    original_block_size = block_size_result.stdout.strip()

    try:
        # GIVEN: master Suppression ON, host NOT in any Suppression list
        # (v4suppression blanked so pfb_ip_suppressed_match() cannot accidentally
        # cover trash_host), and one Permit alias whose ONLY customlist entry is
        # trash_host.
        setup_result = helpers.php_eval(
            vm,
            f"config_set_path('{supp_master_path}', 'on');\n"
            f"config_set_path('{CFG_V4SUPPRESSION}', '');\n"
            f"config_set_path({helpers._php_str(base)}, {helpers._php_kv_array(permit_row)});\n"
            "write_config('pfBlockerNG smoke: seed #798 whitelist-icon oracle');\n"
            "echo 'OK';",
        )
        assert setup_result.returncode == 0 and "OK" in setup_result.stdout, (
            f"Failed to seed the #798 whitelist-icon oracle: rc={setup_result.returncode}, "
            f"stdout={setup_result.stdout!r}"
        )

        # GIVEN: both rows' evaluated IPs exist in their folder feed files (the
        # suppress-icon test's docstring NB applies here too: convert_ip_log()
        # re-validates every row against the on-disk feeds and strips the icon
        # from a "Not listed!" row; the GeoIP row validates against ccdir).
        seed_result = vm.ssh(
            f"mkdir -p /var/db/pfblockerng/deny /usr/local/share/GeoIP/cc && "
            f"printf '{trash_host}/32\\n' > {deny_feed} && "
            f"printf '203.0.113.0/23\\n' > {geo_feed}",
            timeout=15,
        )
        assert seed_result.returncode == 0, (
            f"Failed to seed deny/GeoIP feed files: rc={seed_result.returncode}, stderr={seed_result.stderr!r}"
        )

        # BEFORE (no false pass): neither icon marker is present yet.
        pre = webui.get(ALERTS_PAGE)
        assert not looks_like_login_page(pre.text), "alerts page GET returned login form before mutation (session lost)"
        for marker in (f"DNSBLWT|delete_ipwhitelist|{trash_host}", f"PFBIPWHITE|{plus_host}"):
            assert marker not in pre.text, f"Precondition failed: {marker!r} already present before the synthetic rows"

        # WHEN: append the synthetic Block + GeoIP-Block rows and GET the
        # Alerts page (both ride ip_block.log; the GeoIP row's alias prefix is
        # what routes it to the fallback gate).
        append_result = subprocess.run(
            vm.ssh_argv("tee", "-a", ip_block_log),
            input=block_csv + geo_csv,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert append_result.returncode == 0, (
            f"Failed to append synthetic lines to {ip_block_log!r}: "
            f"rc={append_result.returncode}, stderr={append_result.stderr!r}"
        )

        resp = webui.get(ALERTS_PAGE)
        assert not looks_like_login_page(resp.text), (
            "alerts page GET returned login form (session lost before whitelist-icon oracle)"
        )
        html_body = resp.text

        # THEN (a): the Suppression-icon gate's whitelist sub-path -- trash_host
        # is covered by the Permit alias -> trash-can un-whitelist icon.
        assert f"DNSBLWT|delete_ipwhitelist|{trash_host}" in html_body, (
            f"trash-can un-whitelist icon missing for {trash_host!r} -- the Suppression-icon "
            "gate's whitelist sub-path (pfb_whitelist_trash_icon()) did not render; "
            f"nearby body excerpt: {html_body[:200]!r}"
        )
        # THEN (b): the standalone 'IP Whitelist Icon' fallback block --
        # plus_host is NOT covered by any Permit alias -> "+" whitelist icon.
        assert f"PFBIPWHITE|{plus_host}" in html_body, (
            f"'+' whitelist icon missing for {plus_host!r} -- the IP Whitelist Icon fallback "
            f"block did not render; nearby body excerpt: {html_body[:200]!r}"
        )
    finally:
        truncate_block = subprocess.run(
            vm.ssh_argv("/usr/bin/truncate", "-s", original_block_size, ip_block_log),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert truncate_block.returncode == 0, (
            f"Failed to restore {ip_block_log!r} to size={original_block_size!r}: "
            f"rc={truncate_block.returncode}, stderr={truncate_block.stderr!r}"
        )
        vm.ssh(f"rm -f {deny_feed} {geo_feed}", timeout=15)
        _del_list_row(vm, CFG_IPV4_LISTS, rowid)
        helpers.php_eval(
            vm,
            f"config_set_path('{supp_master_path}', '{original_master}');\n"
            f"config_set_path('{CFG_V4SUPPRESSION}', '{original_v4supp}');\n"
            "write_config('pfBlockerNG smoke: restore suppression for #798 whitelist-icon oracle');\n"
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

    Given: DNSBL is enabled (required for the DNSBL Python tab to appear); the
        Alerts page GET BEFORE the seed shows neither the fresh domain nor the
        cloud icon (before-state -- no false pass); a synthetic ``Upstream_Block``
        line for a unique domain is appended to ``/var/log/pfblockerng/dnsbl.log``.

    When: the Reports/Alerts page is GET-ted again (default ``alert`` view, which
        renders the ``DNSBL Python`` tab from ``dnsbl.log``).

    Then, all scoped to the domain's OWN ``<tr>`` row (never a byte-distance
    window, which can straddle a neighbouring row):
        (a) ``fa-cloud`` is present in that row — proving the bolt-icon override
            fired (Edit D step 9).
        (b) the text ``Upstream`` appears in that row and the text ``Unknown``
            does NOT — proving the stale-entry correction was skipped (Edit D
            step 8); without the skip, pfb_dnsbl_parse would rewrite the group to
            'Unknown'.

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

    # Capture the original byte size so we can truncate back to it on cleanup. Fail
    # fast if stat fails: falling back to "0" would make the cleanup truncate wipe
    # the whole log.
    size_result = vm.ssh("stat", "-f", "%z", dnsbl_log, timeout=15)
    assert size_result.returncode == 0, (
        f"Failed to stat {dnsbl_log!r} before mutation: rc={size_result.returncode}, stderr={size_result.stderr!r}"
    )
    original_size = size_result.stdout.strip()

    helpers.set_dnsbl_enabled(vm, True)

    # GIVEN (before-state): the fresh, never-before-seen domain is absent before
    # the seed, so a later "present" assertion proves THIS row caused it.
    pre = webui.get(ALERTS_PAGE)
    assert not looks_like_login_page(pre.text), "alerts page GET returned login form before mutation (session lost)"
    assert domain not in pre.text, (
        f"Precondition failed: synthetic domain {domain!r} already present before the "
        f"synthetic row was seeded — cannot prove causation."
    )

    try:
        # WHEN: append the synthetic upstream-block line via SSH tee -a.
        append_result = subprocess.run(
            vm.ssh_argv("tee", "-a", dnsbl_log),
            input=csv_line,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert append_result.returncode == 0, (
            f"Failed to append synthetic line to {dnsbl_log!r}: "
            f"rc={append_result.returncode}, stderr={append_result.stderr!r}"
        )

        # WHEN: GET the Alerts page (default alert view → DNSBL Python tab).
        resp = webui.get(ALERTS_PAGE)
        assert not looks_like_login_page(resp.text), (
            "alerts page GET returned login form (session lost before upstream-block render test)"
        )
        html_body = resp.text

        # Row-isolate: the domain's OWN <tr>, not a byte-distance window that can
        # straddle a neighbouring row.
        row = row_containing(html_body, domain)

        # THEN (a): the cloud icon class is present in the domain's OWN row (Edit D step 9).
        assert "fa-cloud" in row, (
            f"fa-cloud icon class absent from {domain!r}'s row — "
            f"the upstream-block icon override (Edit D step 9) did not fire: {row!r}"
        )

        # THEN (b): the row shows group 'Upstream', not 'Unknown'.
        assert "Upstream" in row, (
            f"Group 'Upstream' not found in {domain!r}'s row — "
            f"stale-entry correction may have overwritten it (Edit D step 8 check failed): {row!r}"
        )
        assert "Unknown" not in row, (
            f"Group 'Unknown' found in {domain!r}'s row — "
            f"pfb_dnsbl_parse rewrote the group, meaning $isUpstream guard did not fire "
            f"(Edit D step 8 regression): {row!r}"
        )
    finally:
        # Truncate dnsbl.log back to its pre-test size to remove the appended line.
        truncate_result = subprocess.run(
            vm.ssh_argv("/usr/bin/truncate", "-s", original_size, dnsbl_log),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert truncate_result.returncode == 0, (
            f"Failed to restore {dnsbl_log!r} to size={original_size!r}: "
            f"rc={truncate_result.returncode}, stderr={truncate_result.stderr!r}"
        )


# --------------------------------------------------------------------------- #
# IPv6 alert external-host attribution (issue #361): a synthetic ip_block.log
# row with a FOREIGN IPv6 as SRC and a LOCAL IPv6 as DST must render the
# foreign address as the blocked host (with GeoIP) and must NOT render the
# local address as an external/blocked host.
#
# The display logic in convert_ip_log() is:
#   inbound ($fields[11] == 'in') → $host = $fields[7] (SRC = external/blocked)
#                                   $client = $fields[8] (DST = local)
# The fix for issue #361 ensures pfb_daemon_filterlog() correctly identifies
# local IPv6 before writing the log row, so the stored SRC/DST are authoritative.
# We verify the RENDERING layer honours the stored values — a complementary check
# to the smoke test that drives the PHP logic directly.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("direction", "src_ip", "dst_ip"),
    [
        # Inbound: foreign is the SRC, local is the DST. convert_ip_log() picks
        # $fields[7] (SRC) as the external host for dir == 'in'.
        ("in", helpers.IPV6_FOREIGN, helpers.IPV6_LOCAL_HOST),
        # Outbound: roles swap — local is the SRC, foreign is the DST. The else
        # branch picks $fields[8] (DST) as the external host for dir != 'in'.
        ("out", helpers.IPV6_LOCAL_HOST, helpers.IPV6_FOREIGN),
    ],
)
def test_ipv6_alert_external_host_attribution(
    webui: "WebUI",
    smoke_vm: helpers.SmokeVM,
    direction: str,
    src_ip: str,
    dst_ip: str,
) -> None:
    """The foreign IPv6 renders as the blocked host; the local IPv6 never does.

    Scenario: ip_block.log rendering attributes the external host by direction.

    Background:
        ``pfblockerng_alerts.php`` ``convert_ip_log()`` chooses the external host
        by direction: for ``dir == 'in'`` the host is the SRC IP (``$fields[7]``),
        for ``dir == 'out'`` it is the DST IP (``$fields[8]``).  The fix for issue
        #361 makes ``pfb_daemon_filterlog()`` classify local IPv6 correctly so the
        FOREIGN endpoint is always the host and the LOCAL endpoint is the client.

        This test seeds a synthetic IPv6 row for BOTH directions (parametrized),
        keeping the foreign address (``2001:db8:dead:beef::1``) as the external
        endpoint in each case — SRC for inbound, DST for outbound — and the local
        address (``2001:db8:51:1::1234``) as the internal endpoint, GeoIP "US".
        Covering both ``dir`` branches proves the page keys on direction rather
        than always rendering one column.

    Given: the foreign threat-lookup link is ABSENT from the Alerts page before
        the synthetic row is appended (before-state — no false pass).

    When: the row is appended to ip_block.log and the Alerts page is GET-ted.

    Then (rendering-layer attribution — complements, does not duplicate, the live
    ``pfb_collect_localip`` smoke test; ``dir`` is seeded here, so this guards
    ``convert_ip_log()``'s host selection + IPv6 rendering, not collect_localip):
        (a) The foreign IPv6 is rendered as the attributed external/blocked host —
            it appears verbatim in the threat-lookup href
            ``pfblockerng_threats.php?host=<foreign>``, with GeoIP "US" in the row.
        (b) The local IPv6 is NEVER rendered as the attributed host: its address
            must not appear as a threat-lookup ``host=`` — that exact
            misattribution (local shown as the blocked host) is the issue #361
            regression. NB: the SRC/DST table cells wrap IPv6 in ``[...]`` and
            insert a zero-width space after every colon, so the cells must not be
            substring-matched; the threat href carries the raw address and can be.

    Cleanup: ip_block.log is truncated back to its pre-seed size in finally.
    """
    vm = smoke_vm
    ts = time.strftime("%b %e %H:%M:%S")  # e.g. "Jun  8 12:00:00"

    # RFC 3849 addresses — inert, non-routable, never HSTS-preloaded. The foreign
    # address is the external host in BOTH directions; only its column moves.
    foreign = helpers.IPV6_FOREIGN  # 2001:db8:dead:beef::1 — outside the /64
    local = helpers.IPV6_LOCAL_HOST  # 2001:db8:51:1::1234   — inside the /64

    # ip_block.log IPv6 CSV format (21 fields):
    # ts,rule,real_iface,friendly_iface,action,ipv,proto_id,proto,
    # src_ip,dst_ip,src_port,dst_port,
    # dir,geoip,alias,ip_eval,feed,rhost,chost,asn,dup
    # ip_eval is the evaluated (blocked) host = the foreign address in both cases.
    csv_line = (
        f"{ts},100,em0,WAN,block,6,58,ICMPV6,"
        f"{src_ip},{dst_ip},,"
        f",{direction},US,pfB_Deny_v6,"
        f"{foreign},pfB_TestFeed_v6,Unknown,Unknown,Unknown,+\n"
    )

    ip_block_log = helpers.IP_BLOCK_LOG

    # convert_ip_log() renders the attributed external host's IP verbatim in the
    # threat-lookup icon href ($alert_ip): /pfblockerng/pfblockerng_threats.php?host=<host>
    # ($host = SRC for inbound, DST for outbound). This href carries the RAW
    # address (colons intact) — unlike the SRC/DST cells, which wrap IPv6 in [...]
    # and insert a zero-width space (&#8203;) after every colon. Match the href,
    # never the mangled cell text.
    threat_foreign = f"/pfblockerng/pfblockerng_threats.php?host={foreign}"
    threat_local = f"/pfblockerng/pfblockerng_threats.php?host={local}"

    # ip_block.log is created lazily by the package — only after the first real
    # IP-block event — so on a clean VM (or before any IP has been blocked) it may
    # not exist yet, while the sibling dnsbl.log test passes because DNSBL activity
    # creates its log. This test only needs the file PRESENT to append a synthetic
    # row and check the rendering; it does not need a real block event. Guarantee
    # the file (and its directory) exist idempotently before the stat below so the
    # precondition cannot fail on a missing log. mkdir -p / touch are no-ops when
    # the dir/file already exist, and touch preserves an existing log's content and
    # size — a freshly created file is empty, so original_size == "0" and the
    # finally truncate-back still restores it cleanly.
    log_dir = ip_block_log.rsplit("/", 1)[0]
    ensure_result = vm.ssh(f"mkdir -p {log_dir} && touch {ip_block_log}", timeout=15)
    assert ensure_result.returncode == 0, (
        f"Failed to ensure {ip_block_log!r} exists before mutation: "
        f"rc={ensure_result.returncode}, stderr={ensure_result.stderr!r}"
    )

    # Capture the original byte size — fail fast so cleanup cannot wipe the log.
    size_result = vm.ssh("stat", "-f", "%z", ip_block_log, timeout=15)
    assert size_result.returncode == 0, (
        f"Failed to stat {ip_block_log!r} before mutation: rc={size_result.returncode}, stderr={size_result.stderr!r}"
    )
    original_size = size_result.stdout.strip()

    # GIVEN (before-state): the foreign threat link is absent before the seed, so a
    # later 'present' assertion proves THIS row caused it (no false pass).
    pre = webui.get(ALERTS_PAGE)
    assert not looks_like_login_page(pre.text), "alerts page GET returned login form before mutation (session lost)"
    assert threat_foreign not in pre.text, (
        f"Precondition failed: foreign threat link {threat_foreign!r} already "
        f"present before the synthetic row was seeded — cannot prove causation."
    )

    try:
        # WHEN: append the synthetic IPv6 block line via SSH tee -a.
        append_result = subprocess.run(
            vm.ssh_argv("tee", "-a", ip_block_log),
            input=csv_line,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert append_result.returncode == 0, (
            f"Failed to append synthetic line to {ip_block_log!r}: "
            f"rc={append_result.returncode}, stderr={append_result.stderr!r}"
        )

        # WHEN: GET the Alerts page (default view renders the ip_block.log table).
        resp = webui.get(ALERTS_PAGE)
        assert not looks_like_login_page(resp.text), (
            "alerts page GET returned login form (session lost before IPv6 attribution render test)"
        )
        html_body = resp.text

        # THEN (a): the foreign IPv6 is the attributed external/blocked host.
        idx = html_body.find(threat_foreign)
        assert idx != -1, (
            f"Foreign IPv6 {foreign!r} is not rendered as the threat-lookup host "
            f"({threat_foreign!r} absent) for dir={direction!r} — the IPv6 row did "
            f"not render, or the foreign address was not attributed as the host."
        )
        # Its GeoIP code renders in the same row (the GeoIP cell follows the host
        # icons), proving geo attribution went to the foreign host.
        window = html_body[idx : idx + 2048]
        assert "US" in window, (
            f"GeoIP code 'US' not found in the rendered row for {foreign!r} — "
            f"the row may have rendered without GeoIP attribution."
        )

        # THEN (b): the LOCAL IPv6 is NEVER the attributed external host — its
        # address must not appear as a threat-lookup host. That misattribution
        # (local rendered as the blocked host) is exactly the issue #361 regression.
        assert threat_local not in html_body, (
            f"Local IPv6 {local!r} is rendered as a threat-lookup host "
            f"({threat_local!r} present) for dir={direction!r} — the page attributed "
            f"the LOCAL address as the external blocked host (issue #361 regression)."
        )

    finally:
        # Truncate ip_block.log back to its pre-test size to remove the appended line.
        truncate_result = subprocess.run(
            vm.ssh_argv("/usr/bin/truncate", "-s", original_size, ip_block_log),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert truncate_result.returncode == 0, (
            f"Failed to restore {ip_block_log!r} to size={original_size!r}: "
            f"rc={truncate_result.returncode}, stderr={truncate_result.stderr!r}"
        )
