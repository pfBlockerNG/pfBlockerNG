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
the behavioral oracle is the box's EFFECTIVE state, never the HTTP response body;
the response may prove only authenticated rendering and reachability. For the
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
from .conftest import UI_CONFIG_SNAPSHOT
from .webui import extract_csrf_token, looks_like_login_page, row_containing

if TYPE_CHECKING:
    import requests

    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

ALERTS_PAGE = "/pfblockerng/pfblockerng_alerts.php"

# config.xml nodes the alerts handlers write (all base64 textarea fields).
CFG_WHITELIST = "installedpackages/pfblockerngdnsblsettings/config/0/whitelist"
CFG_TLD_WILDCARD_EXCLUSION = "installedpackages/pfblockerngdnsblsettings/config/0/tld_wildcard_exclusion"
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

# The IP sibling of DNSBL_UNLOCK_STORE ($pfb['ip_unlock'], pfblockerng.inc:149).
# Same synchronous-write contract (pfb_unlock()), keyed by the EXACT alerted
# host since issue #1412 (never a feed CIDR) -- see _ip_unlock_hosts() below.
IP_UNLOCK_STORE = "/tmp/ip_unlock"

DERIVED_WHITELIST_FILES = (
    "/var/unbound/pfb_py_whitelist.txt",
    "/var/unbound/pfb_py_sources.json",
)


def _snapshot_guest_files(vm: helpers.SmokeVM) -> dict[str, str | None]:
    snapshot: dict[str, str | None] = {}
    for path in DERIVED_WHITELIST_FILES:
        result = vm.ssh("cat", path)
        if result.returncode == 0:
            snapshot[path] = result.stdout
        elif vm.ssh("test", "!", "-e", path).returncode == 0:
            snapshot[path] = None
        else:
            raise RuntimeError(f"failed to read existing {path}: {result.stderr!r}")
    return snapshot


def _restore_guest_files(vm: helpers.SmokeVM, snapshot: dict[str, str | None]) -> None:
    for path, content in snapshot.items():
        if content is None:
            result = vm.ssh("rm", "-f", path)
        else:
            result = subprocess.run(
                vm.ssh_argv("tee", path),
                input=content,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        if result.returncode != 0:
            raise RuntimeError(f"failed to restore {path}: {result.stderr!r}")


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
    EFFECTIVE state (config.xml / DNS); the response may only establish authenticated
    rendering and reachability.
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
    base64-encoded (``base64_encode`` in the handler; ``pfb_text_area_decode``
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


def _ip_unlock_hosts(vm: helpers.SmokeVM) -> dict[str, str]:
    """Return IP_UNLOCK_STORE's content as {exact host: table}.

    pfb_unlock() (pfblockerng.inc) writes one ``host,table`` CSV line per
    unlocked entry -- since issue #1412 ``host`` is the EXACT alerted host the
    ip_remove handler validated (never a feed CIDR), so this is the faithful
    oracle for "did the handler unlock/re-lock the RIGHT token". An
    absent/empty store is an empty dict.
    """
    raw = helpers.read_log_file(vm, IP_UNLOCK_STORE)
    entries: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split(",", 1)
        if len(parts) == 2:
            entries[parts[0]] = parts[1]
    return entries


def _config_sha256(vm: helpers.SmokeVM) -> str:
    """Return the guest config.xml byte digest, failing loudly on a bad read."""
    result = vm.ssh("/sbin/sha256", "-q", "/conf/config.xml")
    digest = result.stdout.strip()
    assert result.returncode == 0 and digest, (
        f"sha256 /conf/config.xml failed: rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    return digest


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


@pytest.mark.ui_render
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
      store, patches the manifest's ``user_unlock``, and applies the generation; blocked
      answers are not cached, so the name stops being sinkholed without a native flush.
    * RE-LOCK via the form (``dnsbl_remove=lock``): the temporary allow is removed,
      the applied generation is targeted-flushed, and the name is VIP-blocked again.

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
        unlock_lines = set(helpers.read_log_file(vm, DNSBL_UNLOCK_STORE).splitlines())
        assert f"{domain},python" in unlock_lines, (
            f"unlock store must record {domain!r} with type 'python', got {sorted(unlock_lines)!r}"
        )
        # The handler returns only after the applied-generation handshake. Blocked
        # answers are not cached, so Unlock needs no native-cache flush.
        unlocked = helpers.dns_probe(vm, domain, "A")
        assert _not_blocked(unlocked), f"unlocked {domain} still VIP-blocked via the alerts handler: {unlocked}"

        # RE-LOCK via the handler -> blocked again (allow->block; the handler's
        # targeted delta-flush clears the prior resolved answer).
        resp = _post_action(webui, {"dnsbl_remove": "lock", "domain": domain, "dnsbl_type": "python"})
        assert not looks_like_login_page(resp.text), "re-lock POST returned the login form (session lost)"
        relock_lines = set(helpers.read_log_file(vm, DNSBL_UNLOCK_STORE).splitlines())
        assert not any(line.startswith(f"{domain},") for line in relock_lines), (
            f"re-lock must remove {domain!r} from the unlock store, got {sorted(relock_lines)!r}"
        )
        # Lock likewise returns after the applied-generation handshake and targeted
        # domain/www cache flush.
        relocked = helpers.dns_probe(vm, domain, "A")
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
# list (``tld_wildcard_exclusion`` node) when ``dnsbl_exclude == 'true'`` -- two distinct
# config branches off the SAME action. The reverse is the ``entry_delete`` handler
# (alerts.php:1178): ``delete_domain`` removes from ``suppression``,
# ``delete_exclusion`` removes from ``tld_wildcard_exclusion`` -- so the restore exercises
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
    * RESTORE via ``entry_delete=delete_domain``: the handler removes it.
    * Repeat with a wildcard entry and ``entry_delete=delete_domainwildcard`` so the
      broad allow→block cache-policy branch executes. Belt-and-suspenders config reset
      in ``finally``.
    """
    vm = smoke_vm
    domain = helpers.unique_domain("uiwl")
    original = helpers.config_get(vm, CFG_WHITELIST)
    original_derived = _snapshot_guest_files(vm)
    try:
        # BEFORE: the unique domain is not in the whitelist.
        assert domain not in _suppression_entries(vm, CFG_WHITELIST), (
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
        assert "Alert Settings" in resp.text, "addwhitelistdom redirect did not render the Alerts page"
        assert domain in _suppression_entries(vm, CFG_WHITELIST), (
            f"{domain} not written to the DNSBL whitelist config node after addwhitelistdom"
        )

        # RESTORE via entry_delete=delete_domain (reverse transition + entry_delete coverage).
        resp = _post_action(webui, {"entry_delete": "delete_domain", "domain": domain, "table": "DNSBL"})
        assert not looks_like_login_page(resp.text), "entry_delete POST returned the login form (session lost)"
        assert domain not in _suppression_entries(vm, CFG_WHITELIST), (
            f"{domain} still in the DNSBL Whitelist after entry_delete=delete_domain"
        )

        # Repeat through the wildcard branch. Removing this entry can re-block any
        # cached subdomain, so production performs its full post-swap cache flush.
        resp = _post_action(
            webui,
            {
                "addwhitelistdom": "Add",
                "domain": domain,
                "table": "DNSBL",
                "dnsbl_wildcard": "true",
                "dnsbl_exclude": "false",
            },
        )
        assert not looks_like_login_page(resp.text), "wildcard whitelist POST returned the login form"
        assert f".{domain}" in _suppression_entries(vm, CFG_WHITELIST), (
            f".{domain} not written to the DNSBL Whitelist after wildcard add"
        )

        resp = _post_action(webui, {"entry_delete": "delete_domainwildcard", "domain": domain, "table": "DNSBL"})
        assert not looks_like_login_page(resp.text), "wildcard whitelist delete returned the login form"
        assert f".{domain}" not in _suppression_entries(vm, CFG_WHITELIST), (
            f".{domain} still in the DNSBL Whitelist after entry_delete=delete_domainwildcard"
        )
    finally:
        try:
            cleanup = helpers.php_eval(
                vm,
                "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
                "$had_manifest = file_exists($pfb['unbound_py_sources']);\n"
                f"config_set_path('{CFG_WHITELIST}', '{original}');\n"
                "write_config('pfBlockerNG smoke: restore suppression');\n"
                "pfb_unbound_python_whitelist('alerts');\n"
                "$patched = pfb_unbound_python_sources_whitelist();\n"
                "if ($had_manifest && !$patched) { exit(1); }\n"
                "$was_active = pfb_unbound_py_mode_active();\n"
                "pfb_reload_unbound('enabled', FALSE, FALSE, TRUE);\n"
                "if ($was_active && !pfb_dnsbl_converged()) { exit(1); }\n"
                "echo 'OK';",
            )
            if cleanup.returncode != 0 or "OK" not in cleanup.stdout:
                raise RuntimeError(
                    f"Alerts whitelist cleanup failed: rc={cleanup.returncode} "
                    f"stderr={cleanup.stderr!r} stdout={cleanup.stdout!r}"
                )
        except Exception:
            try:
                _restore_guest_files(vm, original_derived)
            finally:
                helpers.restore_pfb_config_baseline(vm, snapshot_path=UI_CONFIG_SNAPSHOT)
            raise


def test_addwhitelistdom_exclude_writes_tld_exclusion_and_entry_delete_removes_it(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """addwhitelistdom with ``dnsbl_exclude='true'`` writes the TLD Exclusion node.

    The OTHER branch of the same action (CLAUDE.md branch coverage: the exclude flag
    OFF case is the whitelist test above; this is the ON case). True transition with
    the ``tld_wildcard_exclusion`` config node as oracle: absent before, present after the add,
    absent again after ``entry_delete=delete_exclusion`` (the reverse + that delete
    branch). Config reset in ``finally``.
    """
    vm = smoke_vm
    domain = helpers.unique_domain("uitld")
    original = helpers.config_get(vm, CFG_TLD_WILDCARD_EXCLUSION)
    try:
        # BEFORE: not in the TLD Exclusion list.
        assert domain not in _suppression_entries(vm, CFG_TLD_WILDCARD_EXCLUSION), (
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
        assert domain in _suppression_entries(vm, CFG_TLD_WILDCARD_EXCLUSION), (
            f"{domain} not written to the TLD Exclusion config node after addwhitelistdom exclude=true"
        )

        # RESTORE via entry_delete=delete_exclusion (reverse + delete_exclusion coverage).
        resp = _post_action(webui, {"entry_delete": "delete_exclusion", "domain": domain, "table": "DNSBL"})
        assert not looks_like_login_page(resp.text), "entry_delete (exclusion) POST returned the login form"
        assert domain not in _suppression_entries(vm, CFG_TLD_WILDCARD_EXCLUSION), (
            f"{domain} still in the TLD Exclusion list after entry_delete=delete_exclusion"
        )
    finally:
        helpers.php_eval(
            vm,
            f"config_set_path('{CFG_TLD_WILDCARD_EXCLUSION}', '{original}');\n"
            "write_config('pfBlockerNG smoke: restore tld_wildcard_exclusion');\n"
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


@pytest.mark.ui_render
def test_alerts_invalid_actions_leave_state_unchanged_and_addsuppress_writes_exact_host(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Reject hostile action values, then add the EXACT host (never a network line).

    Branch coverage for strict Alerts action dispatch and the any-mask/v4+v6
    suppression validator, with config, pf, and IP unlock state as oracles:

    * REJECT first (proves the node's before-value): an invalid IPv4 makes the
      handler exit before any write -- the node is UNCHANGED.
    * REJECT a hostile valid-word action: ``ip_remove=ip_white`` with a valid
      IP/table must not reach another action seam or change any effective state.
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

        # REJECT: a valid IP/table paired with another action word must stay
        # inert; page-owned strict dispatch must never pass ``ip_white`` to the
        # package seam used by ip_remove. The Permit row and live table make a
        # raw-forward regression observable through both config and pf state.
        feed_host = "198.51.100.47"
        hostile_ip = "198.51.100.46"
        feed_path = helpers.write_local_feed(vm, "ui_hostile_ip.txt", f"{feed_host}\n")
        spec = helpers.IpCase(
            aliasname="uihostile",
            feed_url=feed_path,
            header="uihostile",
        )
        hostile_table = spec.alias
        custom_path = f"{CFG_IPV4_LISTS}/0/custom"
        helpers.inject(vm, spec)
        helpers.reload(vm, "updateip")
        helpers.apply_filter_sync(vm)
        table_before = sorted(helpers.pfctl_table_members(vm, hostile_table))
        assert table_before, f"{hostile_table} did not populate before hostile action"
        # Build the live table under Deny_Both first, then change only the
        # persisted row classification. Permit_Inbound with the harness's
        # default protocol does not declare a live table, while Alerts derives
        # whitelist metadata from the current config row. The blocking filter
        # apply above settles the table before this write. Avoiding a second reload then
        # leaves one real table plus matching Permit metadata: exactly the two
        # preconditions raw ip_white forwarding needs to mutate state.
        classify_result = helpers.php_eval(
            vm,
            f"config_set_path({helpers._php_str(f'{CFG_IPV4_LISTS}/0/action')}, 'Permit_Inbound');\n"
            "write_config('pfBlockerNG smoke: classify hostile-dispatch alias as Permit');\n"
            "echo 'OK';",
        )
        assert classify_result.returncode == 0 and "OK" in classify_result.stdout, (
            "failed to classify hostile-dispatch alias as Permit: "
            f"rc={classify_result.returncode} stdout={classify_result.stdout!r}"
        )
        assert sorted(helpers.pfctl_table_members(vm, hostile_table)) == table_before, (
            "config-only Permit classification unexpectedly changed live table state"
        )
        assert not helpers.pfctl_table_test(vm, hostile_table, hostile_ip), (
            f"{hostile_ip} unexpectedly matched {hostile_table} before hostile action"
        )
        config_before = _config_sha256(vm)
        custom_before = helpers.config_get(vm, custom_path)
        unlock_before = _ip_unlock_hosts(vm)
        resp = _post_action(webui, {"ip_remove": "ip_white", "ip": hostile_ip, "table": hostile_table})
        assert not looks_like_login_page(resp.text), "hostile ip_remove POST returned the login form"
        assert _config_sha256(vm) == config_before, "hostile ip_remove action changed config.xml"
        assert helpers.config_get(vm, custom_path) == custom_before, (
            "hostile ip_remove action changed the Permit customlist"
        )
        assert sorted(helpers.pfctl_table_members(vm, hostile_table)) == table_before, (
            "hostile ip_remove action changed pf state"
        )
        assert _ip_unlock_hosts(vm) == unlock_before, "hostile ip_remove action changed IP unlock state"
        helpers.reset(vm)

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
    helpers.apply_filter_sync(vm)
    try:
        # BEFORE: the table is populated after the blocking filter apply and both
        # addresses match it live.
        members = helpers.pfctl_table_members(vm, table)
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
    helpers.apply_filter_sync(vm)
    try:
        members = helpers.pfctl_table_members(vm, table)
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
    helpers.apply_filter_sync(vm)
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
        members = helpers.pfctl_table_members(vm, table)
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
    helpers.apply_filter_sync(vm)
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
        members = helpers.pfctl_table_members(vm, table)
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
    helpers.apply_filter_sync(vm)
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
        members = helpers.pfctl_table_members(vm, table)
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
# entry_delete=delete_ipwhitelist: failed or missing Permit deletes must not
# mutate persisted state.
# --------------------------------------------------------------------------- #


def test_delete_ipwhitelist_noop_paths_skip_config_write(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Failed and missing Permit deletes must not persist a config change.

    Scenario: fail-closed store/table consistency for entry_delete=delete_ipwhitelist.

    Given: a Permit v4 alias (``Wl1505``) whose only customlist host is
    ``192.0.2.150``, and NO update/reload has ever run for it -- so its pf
    table ``pfB_Wl1505_v4`` genuinely does not exist on the box, and
    ``pfctl -t pfB_Wl1505_v4 -T delete`` fails with "Table does not exist"
    (the non-kill-op failure class ``pfb_pfctl_op_failed()`` documents).
    When: ``entry_delete=delete_ipwhitelist`` is posted for that host.
    Then: (1) the failure savemsg is surfaced, (2) the alias's customlist
    STILL holds the host -- the config write never ran, (3) no
    ``Wl1505_custom_v4.update`` cron flag was touched -- the write-gate never
    fired, and (4) deleting a different host absent from the customlist leaves
    the raw config.xml unchanged.
    """
    vm = smoke_vm
    host = "192.0.2.150"  # RFC 5737 TEST-NET-1 -- unused elsewhere in this module
    aliasname = "Wl1505"
    table = f"pfB_{aliasname}_v4"

    rowid = _free_list_rowid(vm, CFG_IPV4_LISTS)
    base = f"{CFG_IPV4_LISTS}/{rowid}"
    custom_path = f"{base}/custom"
    permit_row = {
        "aliasname": aliasname,
        "action": "Permit_Inbound",
        "custom": helpers._b64_textarea([host]),
    }
    update_flag = f"{helpers.PFB_DBDIR}/permit/{aliasname}_custom_v4.update"

    try:
        setup_result = helpers.php_eval(
            vm,
            f"config_set_path({helpers._php_str(base)}, {helpers._php_kv_array(permit_row)});\n"
            "write_config('pfBlockerNG smoke: seed #1505 delete_ipwhitelist pfctl-failure Permit alias');\n"
            "echo 'OK';",
        )
        assert setup_result.returncode == 0 and "OK" in setup_result.stdout, (
            f"Failed to seed the Permit alias row: rc={setup_result.returncode}, stdout={setup_result.stdout!r}"
        )

        # GIVEN: the seeded customlist already holds the host ...
        entries = _suppression_entries(vm, custom_path)
        assert host in entries, f"{host} not present in the seeded {table} customlist before the delete POST: {entries}"
        # ... and the pf table genuinely does not exist (no update/reload ever ran for it).
        tables = helpers.pfctl_tables(vm)
        assert table not in tables, f"{table} unexpectedly already exists on the box before the delete POST: {tables}"

        # WHEN: entry_delete=delete_ipwhitelist for the host -- the checked
        # pfctl delete must fail against the never-built table.
        resp = _post_action(webui, {"entry_delete": "delete_ipwhitelist", "domain": host, "table": table})
        assert not looks_like_login_page(resp.text), "delete_ipwhitelist POST returned the login form (session lost)"

        # THEN (1): the failure savemsg is surfaced (pfblockerng_alerts.php:1430).
        for marker in ("failed [", "customlist entry was kept"):
            assert marker in resp.text, (
                f"expected the pfctl-failure savemsg fragment {marker!r} after a failed delete_ipwhitelist POST; "
                f"response body did not contain it"
            )

        # THEN (2): the customlist entry was KEPT -- no config_set_path ran.
        entries_after = _suppression_entries(vm, custom_path)
        assert host in entries_after, (
            f"{host} was dropped from the {table} customlist despite the pfctl delete failing; entries={entries_after}"
        )

        # THEN (3): no cron '.update' flag was touched -- the write-gate never fired.
        flag_present = (
            helpers._php_read_scalar(
                vm,
                f"$e = file_exists({helpers._php_str(update_flag)}) ? 'YES' : 'NO';",
                "$e",
            )
            == "YES"
        )
        assert not flag_present, f"{update_flag} unexpectedly exists after a failed delete_ipwhitelist POST"

        # THEN (4): a missing entry is also a no-op -- no write_config revision.
        missing_host = "192.0.2.151"
        config_before = _config_sha256(vm)
        resp = _post_action(webui, {"entry_delete": "delete_ipwhitelist", "domain": missing_host, "table": table})
        assert not looks_like_login_page(resp.text), "missing delete_ipwhitelist POST returned the login form"
        assert "was not found" in resp.text, f"missing-entry savemsg absent from response: {resp.text!r}"
        config_after = _config_sha256(vm)
        assert config_after == config_before, "missing Permit entry unexpectedly created a config.xml revision"
    finally:
        _del_list_row(vm, CFG_IPV4_LISTS, rowid)
        helpers.php_eval(vm, f"@unlink({helpers._php_str(update_flag)}); echo 'OK';")


# --------------------------------------------------------------------------- #
# ip_remove (alerts.php:1490 -- ADR-53 parity, issue #1412): the temporary IP
# Unlock/Re-Lock action. The retired handler deleted/added a SINGLE token
# directly via pfctl -- for a bare-host table entry that matched (the ONE
# shape it fully supported), but a containing entry BROADER than the token
# posted (e.g. a manual-mask /16, or -- the ONLY shape its split-capture regex
# admitted -- a /24-/32 CIDR the client posted itself) either unblocked the
# WHOLE entry (every sibling with it) or silently missed (no exact-token match
# in the table at all). This flow now shares pfb_live_punch_plan() with the
# Suppression "+" (addsuppress) -- same covering-CIDR carve, any mask, either
# family -- so only the alerted host is affected, siblings are spared.
# --------------------------------------------------------------------------- #


def test_ip_unlock_v4_carves_containing_range_relock_restores_and_spares_sibling(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """ip_remove=unlock carves a host out of a containing /16; relock restores it.

    True multi-step transition test: a local IPv4
    feed lists an RFC 2544 benchmarking /16 (unblockable via a single-token
    pfctl delete -- no such exact entry exists in the table) plus a separate
    sibling entry outside it.

    Given: the target AND the sibling both match the live pf table; the
        target is absent from IP_UNLOCK_STORE.
    When: ip_remove=unlock is posted for the target host only.
    Then: the target no longer matches the table (carved out of the /16,
        never the whole entry deleted); the sibling -- a distinct feed entry
        entirely outside the hole -- still matches; IP_UNLOCK_STORE records
        the EXACT host (never the /16).
    When: ip_remove=lock (re-lock) is posted for the same host.
    Then: the target matches the table again; IP_UNLOCK_STORE no longer lists it.
    """
    vm = smoke_vm
    target = "198.18.6.9"  # inside 198.18.0.0/16
    sibling = "198.19.51.6"  # a SEPARATE feed entry, RFC 2544 space, outside the /16 hole
    inside_sibling = "198.18.200.7"  # inside the SAME /16, covered only by the re-added remainder

    feed_url = helpers.write_local_feed(vm, "ui_ipunlock4.txt", f"198.18.0.0/16\n{sibling}\n")
    spec = helpers.IpCase(aliasname="uiipunlock4", feed_url=feed_url, header="uiipunlock4")
    table = spec.alias

    helpers.inject(vm, spec)
    helpers.reload(vm, "updateip")
    helpers.apply_filter_sync(vm)
    try:
        # BEFORE: the table is populated and both addresses match it live.
        members = helpers.pfctl_table_members(vm, table)
        assert members, f"pf table {table} never populated after the settling update"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, f"{target} expected to match pf table {table} before unlock; pfctl said: {raw!r}"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, sibling)
        assert matched, f"{sibling} expected to match pf table {table} before unlock; pfctl said: {raw!r}"
        assert target not in _ip_unlock_hosts(vm), f"{target} already in {IP_UNLOCK_STORE} before the test"

        # WHEN: unlock the target -- the ADR-53 live punch carves it out of the /16.
        resp = _post_action(webui, {"ip_remove": "unlock", "ip": target, "table": table})
        assert not looks_like_login_page(resp.text), "ip_remove=unlock POST returned the login form (session lost)"

        # THEN: the target no longer matches (carved out); the sibling -- a
        # separate feed entry entirely outside the hole -- is untouched.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert not matched, (
            f"{target} still matches pf table {table} after ip_remove=unlock -- the live punch did not "
            f"take effect (or the whole /16 was deleted+never re-carved); pfctl said: {raw!r}"
        )
        matched, raw = helpers.pfctl_table_test_raw(vm, table, sibling)
        assert matched, (
            f"{sibling} no longer matches pf table {table} after ip_remove=unlock -- an unrelated sibling "
            f"was punched (the whole containing entry was deleted, not just the target); pfctl said: {raw!r}"
        )
        # THEN: an address INSIDE the carved /16 (not the target) still matches --
        # only the re-added remainder CIDRs can cover it, so this discriminates a
        # delete-only regression the outside-hole sibling above cannot see.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, inside_sibling)
        assert matched, (
            f"{inside_sibling} no longer matches pf table {table} after ip_remove=unlock -- the "
            f"covering-CIDR remainder was not re-added (delete-only punch); pfctl said: {raw!r}"
        )

        # THEN: IP_UNLOCK_STORE records the EXACT host -- never the /16.
        unlocked = _ip_unlock_hosts(vm)
        assert unlocked.get(target) == table, (
            f"expected {IP_UNLOCK_STORE} to record the exact host {target!r} -> {table!r}, got {unlocked!r}"
        )

        # WHEN: a scheduled feed pass owns the serialization lock, a re-lock POST
        # must refuse the mutation and leave both live state and durable truth alone.
        holder = "/tmp/pfb_alerts_relock_holder.php"
        ready = "/tmp/pfb_alerts_relock_ready"
        stop = "/tmp/pfb_alerts_relock_stop"
        holder_php = f"""<?php
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');
pfb_global();
if (!pfb_feed_pass_acquire()) {{
    exit(2);
}}
touch('{ready}');
for ($i = 0; $i < 1200 && !file_exists('{stop}'); $i++) {{
    usleep(100000);
}}
@unlink('{ready}');
"""
        launch = vm.ssh(f"rm -f {ready} {stop}; cat > {holder} << 'PFBEOF'\n{holder_php}\nPFBEOF")
        assert launch.returncode == 0, f"failed to write feed-pass holder: {launch.stderr!r}"
        launch = vm.ssh(f"nohup /usr/local/bin/php {holder} >/dev/null 2>&1 &")
        assert launch.returncode == 0, f"failed to launch feed-pass holder: {launch.stderr!r}"
        assert helpers.wait_until(lambda: vm.ssh("test", "-f", ready).returncode == 0, timeout=30.0), (
            "feed-pass holder never acquired the lock"
        )
        try:
            resp = _post_action(webui, {"ip_remove": "lock", "ip": target, "table": table})
            assert not looks_like_login_page(resp.text), "busy ip_remove=lock POST returned the login form"
            assert "mid-update" in resp.text, f"busy re-lock feedback missing from Alerts response: {resp.text[:500]!r}"
            matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
            assert not matched, f"{target} was re-locked while the feed-pass lock was busy; pfctl said: {raw!r}"
            assert _ip_unlock_hosts(vm).get(target) == table, (
                f"busy re-lock removed {target!r} from {IP_UNLOCK_STORE}: {_ip_unlock_hosts(vm)!r}"
            )
        finally:
            vm.ssh("touch", stop)
            assert helpers.wait_until(lambda: vm.ssh("test", "!", "-f", ready).returncode == 0, timeout=30.0), (
                "feed-pass holder did not release after the stop signal"
            )

        # WHEN: the lock is free, re-lock the same host.
        resp = _post_action(webui, {"ip_remove": "lock", "ip": target, "table": table})
        assert not looks_like_login_page(resp.text), "ip_remove=lock POST returned the login form (session lost)"

        # THEN: the target is blocked again; the store no longer lists it.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, (
            f"{target} does not match pf table {table} after ip_remove=lock -- the re-lock did not "
            f"restore the block; pfctl said: {raw!r}"
        )
        assert target not in _ip_unlock_hosts(vm), f"{target} still present in {IP_UNLOCK_STORE} after ip_remove=lock"
    finally:
        helpers.reset(vm)


def test_ip_relock_acquisition_error_names_failure_and_keeps_live_and_store_state(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A real feed-pass lock acquisition error refuses a re-lock without claiming contention.

    Given: a v4 feed host was unlocked through the Alerts POST, so it no longer
        matches its live table and the unlock store records the host.
    When: the feed-pass lock path is temporarily a directory and re-lock is posted.
    Then: the rendered response names lock acquisition failure, never ``mid-update``,
        and both the live table and unlock store remain unchanged.
    """
    vm = smoke_vm
    target = "198.18.7.9"
    sibling = "198.19.52.7"
    lock_path = "/var/db/pfblockerng/pfb_feed_pass.lock"
    feed_url = helpers.write_local_feed(vm, "ui_ip_relock_error.txt", f"{target}\n{sibling}\n")
    spec = helpers.IpCase(aliasname="uiiprelockerr", feed_url=feed_url, header="uiiprelockerr")
    table = spec.alias

    helpers.inject(vm, spec)
    helpers.reload(vm, "updateip")
    helpers.apply_filter_sync(vm)
    try:
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, f"{target} expected to match pf table {table} before unlock; pfctl said: {raw!r}"
        assert target not in _ip_unlock_hosts(vm), f"{target} already in {IP_UNLOCK_STORE} before the test"

        resp = _post_action(webui, {"ip_remove": "unlock", "ip": target, "table": table})
        assert not looks_like_login_page(resp.text), "ip_remove=unlock POST returned the login form (session lost)"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert not matched, f"{target} still matches pf table {table} after unlock; pfctl said: {raw!r}"
        assert _ip_unlock_hosts(vm).get(target) == table, (
            f"expected {IP_UNLOCK_STORE} to record {target!r} -> {table!r}, got {_ip_unlock_hosts(vm)!r}"
        )
        table_before = sorted(helpers.pfctl_table_members(vm, table))
        store_before = _ip_unlock_hosts(vm)

        helpers.wait_no_active_pfb_task(vm)
        try:
            replace = vm.ssh(f"rm -f {lock_path} && mkdir {lock_path}")
            assert replace.returncode == 0, (
                f"failed to replace feed-pass lock file with a directory: "
                f"rc={replace.returncode} stderr={replace.stderr!r}"
            )
            resp = _post_action(webui, {"ip_remove": "lock", "ip": target, "table": table})
            assert not looks_like_login_page(resp.text), "lock-error ip_remove=lock POST returned the login form"
            assert "feed-pass lock could not be acquired" in resp.text, (
                f"acquisition-error feedback missing from Alerts response: {resp.text[:500]!r}"
            )
            assert "mid-update" not in resp.text, (
                f"acquisition error was misreported as contention: {resp.text[:500]!r}"
            )
            assert sorted(helpers.pfctl_table_members(vm, table)) == table_before, (
                "acquisition-error re-lock changed the live table"
            )
            assert _ip_unlock_hosts(vm) == store_before, f"acquisition-error re-lock changed {IP_UNLOCK_STORE}"
        finally:
            restore = vm.ssh(f"if [ -d {lock_path} ]; then rmdir {lock_path}; fi && touch {lock_path}")
            assert restore.returncode == 0, (
                f"failed to restore feed-pass lock path: rc={restore.returncode} stderr={restore.stderr!r}"
            )
    finally:
        helpers.reset(vm)


def test_ip_unlock_v6_carves_containing_range_relock_restores_and_spares_sibling(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """ip_remove=unlock/lock over IPv6 -- same carve+restore shape as the v4 case above.

    The retired handler's split-capture regex silently mishandled a v6 shape
    (a defined-but-unread capture group, issue #1412's fourth defect) --
    this drives the SAME server round-trip a bare v6 host now takes, over an
    RFC 3849 documentation /64 plus a separate sibling /64.
    """
    vm = smoke_vm
    target = "2001:db8:19:1::42"  # inside 2001:db8:19:1::/64
    sibling = "2001:db8:19:2::9"  # a SEPARATE feed entry, a different /64, outside the hole
    inside_sibling = "2001:db8:19:1::43"  # inside the SAME /64, covered only by the re-added remainder

    feed_url = helpers.write_local_feed(vm, "ui_ipunlock6.txt", f"2001:db8:19:1::/64\n{sibling}\n")
    spec = helpers.IpCase(aliasname="uiipunlock6", feed_url=feed_url, header="uiipunlock6", family="v6")
    table = spec.alias

    helpers.inject(vm, spec)
    helpers.reload(vm, "updateip")
    helpers.apply_filter_sync(vm)
    try:
        members = helpers.pfctl_table_members(vm, table)
        assert members, f"pf table {table} never populated after the settling update"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, f"{target} expected to match pf table {table} before unlock; pfctl said: {raw!r}"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, sibling)
        assert matched, f"{sibling} expected to match pf table {table} before unlock; pfctl said: {raw!r}"
        assert target not in _ip_unlock_hosts(vm), f"{target} already in {IP_UNLOCK_STORE} before the test"

        resp = _post_action(webui, {"ip_remove": "unlock", "ip": target, "table": table})
        assert not looks_like_login_page(resp.text), "ip_remove=unlock POST returned the login form (session lost)"

        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert not matched, (
            f"{target} still matches pf table {table} after ip_remove=unlock -- the live punch did not "
            f"take effect; pfctl said: {raw!r}"
        )
        matched, raw = helpers.pfctl_table_test_raw(vm, table, sibling)
        assert matched, (
            f"{sibling} no longer matches pf table {table} after ip_remove=unlock -- an unrelated sibling "
            f"was punched; pfctl said: {raw!r}"
        )
        # THEN: an address INSIDE the carved /64 (not the target) still matches --
        # only the re-added remainder CIDRs can cover it, so this discriminates a
        # delete-only regression the outside-hole sibling above cannot see.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, inside_sibling)
        assert matched, (
            f"{inside_sibling} no longer matches pf table {table} after ip_remove=unlock -- the "
            f"covering-CIDR remainder was not re-added (delete-only punch); pfctl said: {raw!r}"
        )
        unlocked = _ip_unlock_hosts(vm)
        assert unlocked.get(target) == table, (
            f"expected {IP_UNLOCK_STORE} to record the exact host {target!r} -> {table!r}, got {unlocked!r}"
        )

        resp = _post_action(webui, {"ip_remove": "lock", "ip": target, "table": table})
        assert not looks_like_login_page(resp.text), "ip_remove=lock POST returned the login form (session lost)"

        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, (
            f"{target} does not match pf table {table} after ip_remove=lock -- the re-lock did not "
            f"restore the block; pfctl said: {raw!r}"
        )
        assert target not in _ip_unlock_hosts(vm), f"{target} still present in {IP_UNLOCK_STORE} after ip_remove=lock"
    finally:
        helpers.reset(vm)


def test_ip_unlock_rejects_invalid_ip_no_mutation(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """ip_remove=unlock rejects a malformed/CIDR-shaped ip -- no pf or store mutation.

    Branch/hostile-input coverage for the retired split-capture regex's
    replacement (a single PFB_FILTER_IP call, #1412): a CIDR-shaped POST --
    the ONE shape the old regex partially parsed -- is now rejected exactly
    like any other malformed address, for both families (is_ipaddr() rejects
    a '/' outright); an empty ip/table is unchanged. Oracle = the pf table
    (must stay untouched -- no delete/add exec may run) and IP_UNLOCK_STORE
    (must stay unchanged).
    """
    vm = smoke_vm
    target = "198.18.7.10"
    sibling = "198.19.52.7"

    feed_url = helpers.write_local_feed(vm, "ui_ipunlock_reject.txt", f"198.18.0.0/16\n{sibling}\n")
    spec = helpers.IpCase(aliasname="uiipunlockrej", feed_url=feed_url, header="uiipunlockrej")
    table = spec.alias

    helpers.inject(vm, spec)
    helpers.reload(vm, "updateip")
    helpers.apply_filter_sync(vm)
    try:
        members = helpers.pfctl_table_members(vm, table)
        assert members, f"pf table {table} never populated after the settling update"

        store_before = _ip_unlock_hosts(vm)
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, f"{target} expected to match pf table {table} before the rejected POSTs; pfctl said: {raw!r}"

        for bad_ip in (
            "999.999.999.999",  # malformed v4
            f"{target}/16",  # v4 CIDR shape -- the ONE shape the old split-capture regex admitted
            "2001:db8::dead:beef:9/64",  # v6 CIDR shape -- the old regex's unread v6 capture group
        ):
            resp = _post_action(webui, {"ip_remove": "unlock", "ip": bad_ip, "table": table})
            assert not looks_like_login_page(resp.text), f"rejected ip={bad_ip!r} POST returned the login form"

        # THEN: the table is untouched (the target still blocked) and the
        # unlock store gained no entries -- every rejected POST is a true no-op.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, (
            f"{target} no longer matches pf table {table} after REJECTED ip_remove POSTs -- a rejected "
            f"input must never mutate the live table; pfctl said: {raw!r}"
        )
        assert _ip_unlock_hosts(vm) == store_before, (
            f"{IP_UNLOCK_STORE} changed after REJECTED ip_remove POSTs: before={store_before!r} "
            f"after={_ip_unlock_hosts(vm)!r}"
        )

        # Empty ip AND empty table are also rejected (separate guard, same invariants).
        resp = _post_action(webui, {"ip_remove": "unlock", "ip": "", "table": table})
        assert not looks_like_login_page(resp.text), "empty-ip POST returned the login form"
        resp = _post_action(webui, {"ip_remove": "unlock", "ip": target, "table": ""})
        assert not looks_like_login_page(resp.text), "empty-table POST returned the login form"

        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert matched, (
            f"{target} no longer matches pf table {table} after empty-field REJECTED POSTs; pfctl said: {raw!r}"
        )
        assert _ip_unlock_hosts(vm) == store_before, (
            f"{IP_UNLOCK_STORE} changed after empty-field REJECTED POSTs: before={store_before!r} "
            f"after={_ip_unlock_hosts(vm)!r}"
        )
    finally:
        helpers.reset(vm)


# --------------------------------------------------------------------------- #
# Live-punch redesign (issues #1467/#1470/#1471): pfb_live_table_snapshot() now
# reads live ``pfctl -T show`` as its SOLE source (the stale ADR-40 mirror file
# is never consulted), so a SECOND punch inside the same containing entry sees
# the FIRST punch's already-applied result instead of silently reverting it;
# and pfb_live_punch_apply() (#1470) computes the punch PLAN before writing the
# unlock store, so an unlock of a host nothing live blocks records NOTHING and
# says so, instead of claiming success it never performed.
# --------------------------------------------------------------------------- #


def test_ip_unlock_double_punch_v4_second_punch_keeps_first_carved(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A second unlock in the same containing /16 must not silently re-lock the first (issue #1467).

    Before this fix, ``pfb_live_table_snapshot()`` preferred the stale ADR-40
    mirror file over a live ``pfctl -T show`` capture. A live punch never
    rewrites that mirror, so a SECOND unlock inside the same containing entry
    read the mirror's PRE-first-punch membership, recomputed the covering-CIDR
    remainder from scratch, and re-added CIDRs that re-covered the FIRST
    unlocked host -- silently re-locking it without ever touching
    ``ip_remove=lock``. The fix makes live ``pfctl -T show`` the sole snapshot
    source, so the second punch's plan is always computed against the table as
    it stands AFTER the first punch.

    Given: a local IPv4 feed lists an RFC 2544 /16 (``198.18.0.0/16``) plus a
        separate sibling entry outside it; both punch targets, a third inside
        host, and the sibling all match the live pf table.
    When: the FIRST host is unlocked -- asserted carved before continuing (the
        before-state gate for the second punch). Then, WITHOUT any reload in
        between, the SECOND host (same /16) is unlocked too.
    Then: the second host no longer matches (its own punch worked); the FIRST
        host STILL does not match -- pre-fix this is exactly where the second
        punch's stale-mirror remainder re-covers it (the regression trap); a
        third, untouched host inside the /16 still matches (remainder
        integrity -- discriminates a delete-only regression the outside
        sibling below cannot see); the outside sibling is untouched; the
        unlock store records BOTH exact hosts mapped to the table.
    """
    vm = smoke_vm
    first = "198.18.6.9"  # inside 198.18.0.0/16 -- unlocked FIRST
    second = "198.18.200.7"  # inside the SAME /16 -- unlocked SECOND, no reload between
    third_inside = "198.18.90.1"  # inside the SAME /16, never unlocked -- remainder integrity
    sibling = "198.19.51.6"  # a SEPARATE feed entry, RFC 2544 space, outside the /16 hole

    feed_url = helpers.write_local_feed(vm, "ui_ipunlock4dp.txt", f"198.18.0.0/16\n{sibling}\n")
    spec = helpers.IpCase(aliasname="uiipunlock4dp", feed_url=feed_url, header="uiipunlock4dp")
    table = spec.alias

    try:
        # Inject/reload live INSIDE the try -- a failed setup
        # must still hit `finally: helpers.reset(vm)`.
        helpers.inject(vm, spec)
        helpers.reload(vm, "updateip")
        helpers.apply_filter_sync(vm)
        # BEFORE: the table is populated and every address matches it live.
        members = helpers.pfctl_table_members(vm, table)
        assert members, f"pf table {table} never populated after the settling update"
        for host in (first, second, third_inside, sibling):
            matched, raw = helpers.pfctl_table_test_raw(vm, table, host)
            assert matched, f"{host} expected to match pf table {table} before any unlock; pfctl said: {raw!r}"
        assert first not in _ip_unlock_hosts(vm), f"{first} already in {IP_UNLOCK_STORE} before the test"
        assert second not in _ip_unlock_hosts(vm), f"{second} already in {IP_UNLOCK_STORE} before the test"

        # WHEN: unlock the FIRST host -- carved out of the /16.
        resp = _post_action(webui, {"ip_remove": "unlock", "ip": first, "table": table})
        assert not looks_like_login_page(resp.text), (
            "first ip_remove=unlock POST returned the login form (session lost)"
        )
        # THEN (before-state gate for the second punch): the first host is carved.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, first)
        assert not matched, (
            f"{first} still matches pf table {table} after the FIRST unlock -- the live punch did not "
            f"take effect; pfctl said: {raw!r}"
        )

        # WHEN: WITHOUT any reload, unlock the SECOND host -- same containing /16.
        resp = _post_action(webui, {"ip_remove": "unlock", "ip": second, "table": table})
        assert not looks_like_login_page(resp.text), (
            "second ip_remove=unlock POST returned the login form (session lost)"
        )

        # THEN (issue #1467's oracle set):
        matched, raw = helpers.pfctl_table_test_raw(vm, table, second)
        assert not matched, (
            f"{second} still matches pf table {table} after the SECOND unlock -- the live punch did not "
            f"take effect; pfctl said: {raw!r}"
        )
        # The FIRST host must STILL be carved -- pre-fix, the second punch's
        # stale-mirror snapshot re-added covering CIDRs that silently re-locked it.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, first)
        assert not matched, (
            f"{first} matches pf table {table} again after the SECOND unlock -- the second punch's plan "
            f"was computed against a stale snapshot and re-covered the first carve (issue #1467 regression); "
            f"pfctl said: {raw!r}"
        )
        # A third, untouched host inside the /16 still matches -- only the
        # re-added remainder CIDRs can cover it, discriminating a delete-only punch.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, third_inside)
        assert matched, (
            f"{third_inside} no longer matches pf table {table} after the double unlock -- the "
            f"covering-CIDR remainder was not re-added (delete-only punch); pfctl said: {raw!r}"
        )
        # The outside sibling -- a distinct feed entry entirely outside the hole -- is untouched.
        matched, raw = helpers.pfctl_table_test_raw(vm, table, sibling)
        assert matched, (
            f"{sibling} no longer matches pf table {table} after the double unlock -- an unrelated "
            f"sibling was punched; pfctl said: {raw!r}"
        )
        # The unlock store records BOTH exact hosts mapped to the table.
        unlocked = _ip_unlock_hosts(vm)
        assert unlocked.get(first) == table, (
            f"expected {IP_UNLOCK_STORE} to record the exact host {first!r} -> {table!r}, got {unlocked!r}"
        )
        assert unlocked.get(second) == table, (
            f"expected {IP_UNLOCK_STORE} to record the exact host {second!r} -> {table!r}, got {unlocked!r}"
        )
    finally:
        helpers.reset(vm)


def test_ip_unlock_double_punch_v6_second_punch_keeps_first_carved(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A second v6 unlock in the same containing /64 must not silently re-lock the first (issue #1467).

    Same regression shape as the v4 case above, over the same RFC 3849 v6
    geometry the sibling carve/relock test (``test_ip_unlock_v6_carves_...``)
    uses: ``2001:db8:19:1::/64`` as the containing entry, with the earlier
    test's ``target`` (``::42``) and ``inside_sibling`` (``::43``) reused here
    as the first and second punch targets respectively, plus a third,
    never-unlocked host in the same /64 and the earlier test's outside
    sibling /64 (``2001:db8:19:2::/64``, host ``::9``).

    Given/When/Then mirror the v4 double-punch exactly, over v6 addresses.
    """
    vm = smoke_vm
    first = "2001:db8:19:1::42"  # inside 2001:db8:19:1::/64 -- unlocked FIRST
    second = "2001:db8:19:1::43"  # inside the SAME /64 -- unlocked SECOND, no reload between
    third_inside = "2001:db8:19:1::90"  # inside the SAME /64, never unlocked -- remainder integrity
    sibling = "2001:db8:19:2::9"  # a SEPARATE feed entry, a different /64, outside the hole

    feed_url = helpers.write_local_feed(vm, "ui_ipunlock6dp.txt", f"2001:db8:19:1::/64\n{sibling}\n")
    spec = helpers.IpCase(aliasname="uiipunlock6dp", feed_url=feed_url, header="uiipunlock6dp", family="v6")
    table = spec.alias

    try:
        # Inject/reload live INSIDE the try -- a failed setup
        # must still hit `finally: helpers.reset(vm)`.
        helpers.inject(vm, spec)
        helpers.reload(vm, "updateip")
        helpers.apply_filter_sync(vm)
        members = helpers.pfctl_table_members(vm, table)
        assert members, f"pf table {table} never populated after the settling update"
        for host in (first, second, third_inside, sibling):
            matched, raw = helpers.pfctl_table_test_raw(vm, table, host)
            assert matched, f"{host} expected to match pf table {table} before any unlock; pfctl said: {raw!r}"
        assert first not in _ip_unlock_hosts(vm), f"{first} already in {IP_UNLOCK_STORE} before the test"
        assert second not in _ip_unlock_hosts(vm), f"{second} already in {IP_UNLOCK_STORE} before the test"

        resp = _post_action(webui, {"ip_remove": "unlock", "ip": first, "table": table})
        assert not looks_like_login_page(resp.text), (
            "first ip_remove=unlock POST returned the login form (session lost)"
        )
        matched, raw = helpers.pfctl_table_test_raw(vm, table, first)
        assert not matched, (
            f"{first} still matches pf table {table} after the FIRST unlock -- the live punch did not "
            f"take effect; pfctl said: {raw!r}"
        )

        resp = _post_action(webui, {"ip_remove": "unlock", "ip": second, "table": table})
        assert not looks_like_login_page(resp.text), (
            "second ip_remove=unlock POST returned the login form (session lost)"
        )

        matched, raw = helpers.pfctl_table_test_raw(vm, table, second)
        assert not matched, (
            f"{second} still matches pf table {table} after the SECOND unlock -- the live punch did not "
            f"take effect; pfctl said: {raw!r}"
        )
        matched, raw = helpers.pfctl_table_test_raw(vm, table, first)
        assert not matched, (
            f"{first} matches pf table {table} again after the SECOND unlock -- the second punch's plan "
            f"was computed against a stale snapshot and re-covered the first carve (issue #1467 regression); "
            f"pfctl said: {raw!r}"
        )
        matched, raw = helpers.pfctl_table_test_raw(vm, table, third_inside)
        assert matched, (
            f"{third_inside} no longer matches pf table {table} after the double unlock -- the "
            f"covering-CIDR remainder was not re-added (delete-only punch); pfctl said: {raw!r}"
        )
        matched, raw = helpers.pfctl_table_test_raw(vm, table, sibling)
        assert matched, (
            f"{sibling} no longer matches pf table {table} after the double unlock -- an unrelated "
            f"sibling was punched; pfctl said: {raw!r}"
        )
        unlocked = _ip_unlock_hosts(vm)
        assert unlocked.get(first) == table, (
            f"expected {IP_UNLOCK_STORE} to record the exact host {first!r} -> {table!r}, got {unlocked!r}"
        )
        assert unlocked.get(second) == table, (
            f"expected {IP_UNLOCK_STORE} to record the exact host {second!r} -> {table!r}, got {unlocked!r}"
        )
    finally:
        helpers.reset(vm)


def test_ip_unlock_not_currently_blocked_records_nothing(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """ip_remove=unlock on a host nothing live blocks records NO unlock (issue #1470).

    Before this fix, an unlock POST for a host the table does not cover still
    called ``pfb_unlock()`` and claimed success. The handler now computes the
    live punch PLAN first (``pfb_live_punch_plan()``); an empty ``delete`` set
    means nothing live blocks the host, so NO store write happens and the
    savemsg says so instead of claiming an unlock that never occurred.

    Given: a local IPv4 feed populates a live pf table (``198.18.0.0/16``,
        represented by an in-range host, ``member``); the target host
        (RFC 5737 TEST-NET-3 -- in NO feed entry, never RFC 1918) does not
        match the table.
    When: ip_remove=unlock is posted for that host.
    Then: the unlock store gains no entry for it and is otherwise BYTE-FOR-BYTE
        unchanged (the primary oracle -- pre-fix it gains an entry); the
        table's actual member is unchanged (still matches); the response is
        not the login page and its savemsg names the "not currently blocked"
        case (the same resp.text savemsg idiom the covered-host addsuppress
        test above uses).
    """
    vm = smoke_vm
    member = "198.18.1.1"  # inside 198.18.0.0/16 -- proves the table itself is untouched
    target = "203.0.113.5"  # RFC 5737 TEST-NET-3 -- in NO feed entry, never currently blocked

    feed_url = helpers.write_local_feed(vm, "ui_ipunlock_notblocked.txt", "198.18.0.0/16\n")
    spec = helpers.IpCase(aliasname="uiipunlocknb", feed_url=feed_url, header="uiipunlocknb")
    table = spec.alias

    try:
        # Inject/reload live INSIDE the try -- a failed setup
        # must still hit `finally: helpers.reset(vm)`.
        helpers.inject(vm, spec)
        helpers.reload(vm, "updateip")
        helpers.apply_filter_sync(vm)
        # BEFORE: the table is populated; the member matches, the target does not
        # (the before-state gate -- "not currently blocked" must be genuinely true).
        members = helpers.pfctl_table_members(vm, table)
        assert members, f"pf table {table} never populated after the settling update"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, member)
        assert matched, f"{member} expected to match pf table {table} before the test; pfctl said: {raw!r}"
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert not matched, (
            f"{target} unexpectedly matches pf table {table} before the test -- it must be genuinely "
            f"unblocked for this to be a true not-currently-blocked case; pfctl said: {raw!r}"
        )
        store_before = _ip_unlock_hosts(vm)
        assert target not in store_before, f"{target} already in {IP_UNLOCK_STORE} before the test"

        # WHEN: unlock is posted for a host nothing live blocks.
        resp = _post_action(webui, {"ip_remove": "unlock", "ip": target, "table": table})
        assert not looks_like_login_page(resp.text), "ip_remove=unlock POST returned the login form (session lost)"

        # THEN: no unlock was recorded -- the store is BYTE-FOR-BYTE unchanged,
        # not merely missing the target (pre-fix it gains a "target,table" line).
        after = _ip_unlock_hosts(vm)
        assert target not in after, f"{target} recorded in {IP_UNLOCK_STORE} after an unlock of an unblocked host"
        assert after == store_before, (
            f"{IP_UNLOCK_STORE} changed after an unlock POST for a not-currently-blocked host: "
            f"before={store_before!r} after={after!r}"
        )
        # THEN: the table is unchanged (the member still matches; the target still doesn't).
        matched, raw = helpers.pfctl_table_test_raw(vm, table, member)
        assert matched, (
            f"{member} no longer matches pf table {table} after the not-currently-blocked unlock POST -- "
            f"the live table was unexpectedly mutated; pfctl said: {raw!r}"
        )
        matched, raw = helpers.pfctl_table_test_raw(vm, table, target)
        assert not matched, (
            f"{target} unexpectedly matches pf table {table} after the not-currently-blocked unlock POST; "
            f"pfctl said: {raw!r}"
        )
        # THEN: the savemsg names the "not currently blocked" case, not a claimed unlock.
        assert "is not currently blocked" in resp.text, (
            "expected the 'is not currently blocked' savemsg after an unlock POST for a host nothing live "
            "blocks; response body did not contain it"
        )
    finally:
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
    # ip_block.log CSV format (23 fields, see the issue #361 test above):
    # ts,rule,real_iface,friendly_iface,action,ipv,proto_id,proto,
    # src_ip,dst_ip,src_port,dst_port,dir,geoip,alias,ip_eval,feed,rhost,chost,asn,asn_domain,asn_name,dup
    csv_lines = (
        # (a) v6, inbound -> $host = SRC = the foreign v6 address; ip_eval /48.
        f"{ts},100,em0,WAN,block,6,58,ICMPV6,"
        f"{v6_host},{v6_local},,"
        f",in,US,pfB_Deny_v6,"
        "2001:db8:dead::/48,pfB_TestFeed_v6,Unknown,Unknown,Unknown,,,+\n"
        # (b) v4, inbound -> $host = SRC = the broad-mask host; ip_eval mask /16.
        f"{ts},100,em0,WAN,block,4,6,TCP,"
        f"{v4_broad_host},10.0.0.5,12345,443,"
        "in,US,pfB_Deny_v4,"
        "198.51.0.0/16,pfB_TestFeed_v4,Unknown,Unknown,Unknown,,,+\n"
        # (c) v4, inbound -> $host covered by the seeded v4suppression /28.
        f"{ts},100,em0,WAN,block,4,6,TCP,"
        f"{v4_supp_host},10.0.0.6,12345,443,"
        "in,US,pfB_Deny_v4,"
        "203.0.113.0/28,pfB_TestFeed_v4,Unknown,Unknown,Unknown,,,+\n"
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
    # ip_block.log CSV format (23 fields, see the suppress-icon
    # test above): ts,rule,real_iface,friendly_iface,action,ipv,proto_id,proto,
    # src_ip,dst_ip,src_port,dst_port,dir,geoip,alias,ip_eval,feed,rhost,chost,asn,asn_domain,asn_name,dup
    block_csv = (
        f"{ts},100,em0,WAN,block,4,6,TCP,"
        f"{trash_host},10.0.0.10,12345,443,"
        "in,US,pfB_798AliasDeny_v4,"
        f"{trash_host}/32,pfB_798BlockFeed_v4,Unknown,Unknown,Unknown,,,+\n"
    )
    geo_csv = (
        f"{ts},100,em0,WAN,block,4,6,TCP,"
        f"{plus_host},10.0.0.11,12345,443,"
        "in,US,pfB_Europe_v4,"
        "203.0.113.0/23,798GeoFeed,Unknown,Unknown,Unknown,,,+\n"
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
        "action": "Permit_Inbound",
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

    # ip_block.log IPv6 CSV format (23 fields):
    # ts,rule,real_iface,friendly_iface,action,ipv,proto_id,proto,
    # src_ip,dst_ip,src_port,dst_port,
    # dir,geoip,alias,ip_eval,feed,rhost,chost,asn,asn_domain,asn_name,dup
    # ip_eval is the evaluated (blocked) host = the foreign address in both cases.
    csv_line = (
        f"{ts},100,em0,WAN,block,6,58,ICMPV6,"
        f"{src_ip},{dst_ip},,"
        f",{direction},US,pfB_Deny_v6,"
        f"{foreign},pfB_TestFeed_v6,Unknown,Unknown,Unknown,,,+\n"
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


def _read_guest_file(vm: helpers.SmokeVM, path: str) -> str | None:
    result = vm.ssh("cat", path)
    if result.returncode == 0:
        return result.stdout
    if vm.ssh("test", "!", "-e", path).returncode == 0:
        return None
    raise RuntimeError(f"failed to read {path}: {result.stderr!r}")


def _write_or_remove_guest_file(vm: helpers.SmokeVM, path: str, content: str | None) -> None:
    if content is None:
        result = vm.ssh("rm", "-f", path)
        if result.returncode != 0:
            raise RuntimeError(f"failed to remove {path}: {result.stderr!r}")
        return
    result = subprocess.run(
        vm.ssh_argv("tee", path),
        input=content,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"failed to write {path}: {result.stderr!r}")


def _unlocked_panel_html(page_html: str) -> str:
    """Slice the Unlocked IP(s) & Domain(s) panel out of an Alerts GET body.

    The panel is the page-template print() this PR changed; helper-only PHPUnit
    does not execute it. Missing heading means the panel did not render.
    """
    marker = "Unlocked IP(s) & Domain(s)"
    idx = page_html.find(marker)
    assert idx != -1, "Unlocked panel heading missing from Alerts GET"
    return page_html[idx : idx + 8000]


@pytest.mark.ui_render
def test_unlocked_panel_renders_whitelist_plus_next_to_relock(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """issue #1526: Unlocked panel rows show suppression/whitelist plus beside re-lock.

    The panel reads only the unlock stores. Seed both stores (the state after a
    successful unlock POST), GET Alerts so the page-template print() runs, isolate
    that panel, and assert plus + re-lock ids for one IP and one domain.

    Given: unlock stores do not list the test host/domain.
    When: the stores record them and Alerts is GET-ted.
    Then: the Unlocked panel HTML contains IPLCK + PFBIPSUP for the host and
        DNSBL_LCK + DNSBLWT|add for the domain.
    """
    vm = smoke_vm
    host = "203.0.113.77"
    table = "pfB_Exact_v4"
    domain = "ui1526panel.example.com"
    dnsbl_type = "python"

    ip_before = _read_guest_file(vm, IP_UNLOCK_STORE)
    dnsbl_before = _read_guest_file(vm, DNSBL_UNLOCK_STORE)
    try:
        pre = webui.get(ALERTS_PAGE)
        assert not looks_like_login_page(pre.text), "alerts GET returned login form before seeding (session lost)"
        assert f"PFBIPSUP|add|{host}|{table}" not in pre.text, (
            f"Precondition failed: panel plus for {host} already present"
        )
        assert f"DNSBLWT|add|{domain}" not in pre.text, f"Precondition failed: panel plus for {domain} already present"

        _write_or_remove_guest_file(vm, IP_UNLOCK_STORE, f"{host},{table}\n")
        _write_or_remove_guest_file(vm, DNSBL_UNLOCK_STORE, f"{domain},{dnsbl_type}\n")

        resp = webui.get(ALERTS_PAGE)
        assert not looks_like_login_page(resp.text), "alerts GET returned login form after seeding (session lost)"
        panel = _unlocked_panel_html(resp.text)

        assert f"IPLCK|{host}|{table}" in panel, f"Unlocked panel missing Re-Lock for {host}: {panel!r}"
        assert f"PFBIPSUP|add|{host}|{table}" in panel, (
            f"issue #1526: Unlocked panel missing suppression plus for {host}: {panel!r}"
        )
        assert f"DNSBL_LCK|{domain}|{dnsbl_type}" in panel, f"Unlocked panel missing Re-Lock for {domain}: {panel!r}"
        assert f"DNSBLWT|add|{domain}|{dnsbl_type}" in panel, (
            f"issue #1526: Unlocked panel missing whitelist plus for {domain}: {panel!r}"
        )
    finally:
        _write_or_remove_guest_file(vm, IP_UNLOCK_STORE, ip_before)
        _write_or_remove_guest_file(vm, DNSBL_UNLOCK_STORE, dnsbl_before)


@pytest.mark.ui_render
def test_addwhitelistdom_clears_unlock_store_and_drops_unlocked_panel_row(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """issue #2670: whitelisting an unlocked domain must drop the unlock-store row.

    Given: the DNSBL unlock store lists a unique domain (Unlocked-panel state).
    When: addwhitelistdom POSTs that same domain (the panel plus click).
    Then: the domain is in the DNSBL whitelist, gone from the unlock store, and
        absent from the Unlocked panel on the next GET.
    """
    vm = smoke_vm
    domain = helpers.unique_domain("ui2670")
    dnsbl_type = "python"
    original = helpers.config_get(vm, CFG_WHITELIST)
    dnsbl_before = _read_guest_file(vm, DNSBL_UNLOCK_STORE)
    try:
        assert domain not in _suppression_entries(vm, CFG_WHITELIST), (
            f"Precondition failed: {domain} already in the DNSBL whitelist"
        )
        _write_or_remove_guest_file(vm, DNSBL_UNLOCK_STORE, f"{domain},{dnsbl_type}\n")

        pre = webui.get(ALERTS_PAGE)
        assert not looks_like_login_page(pre.text), "alerts GET returned login form before whitelist (session lost)"
        panel = _unlocked_panel_html(pre.text)
        assert f"DNSBLWT|add|{domain}|{dnsbl_type}" in panel, (
            f"Precondition failed: Unlocked panel missing plus for {domain}: {panel!r}"
        )

        resp = _post_action(
            webui,
            {
                "addwhitelistdom": "true",
                "domain": domain,
                "table": dnsbl_type,
                "dnsbl_wildcard": "false",
                "dnsbl_exclude": "false",
            },
        )
        assert not looks_like_login_page(resp.text), "addwhitelistdom POST returned the login form (session lost)"
        assert domain in _suppression_entries(vm, CFG_WHITELIST), (
            f"{domain} not written to the DNSBL whitelist after addwhitelistdom"
        )

        store_after = _read_guest_file(vm, DNSBL_UNLOCK_STORE) or ""
        assert domain not in store_after, (
            f"issue #2670: {domain} still in dnsbl_unlock after whitelist: {store_after!r}"
        )

        after = webui.get(ALERTS_PAGE)
        assert not looks_like_login_page(after.text), "alerts GET returned login form after whitelist (session lost)"
        assert f"DNSBL_LCK|{domain}" not in after.text, (
            f"issue #2670: Unlocked panel still shows {domain} after whitelist"
        )
    finally:
        helpers.config_set(vm, CFG_WHITELIST, original if original is not None else "")
        _write_or_remove_guest_file(vm, DNSBL_UNLOCK_STORE, dnsbl_before)
