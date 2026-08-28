"""Tier-B live pins for the persist-boundary text sanitizers (issue #1723).

Marker ``ui_e2e`` -- see :mod:`tests.smoke.ui.test_functional` for the tier's
general shape. Every test here drives a real CSRF POST (``requests``, never a
browser) and asserts the box's EFFECTIVE persisted state -- ``config.xml`` (via
:func:`tests.smoke.helpers.config_get`) for the config-backed fields, or the
on-disk artifact for the hook editor, whose script content never enters
``config.xml`` by design -- never the HTTP response body --
``requests``' ``session.post(data=...)`` sends the Python string's bytes
UNCHANGED (no browser-side CRLF canonicalization of textarea content), so a
raw payload mixing LF/CR-only/control chars reaches the server byte-for-byte.

Tests 1-5 pin the persist-boundary sanitizers wired in commit 2 of #1723
(``pfb_text_area_encode()`` for multi-line textarea fields,
``pfb_sanitize_text()`` for single-line fields) -- RED before that commit
(raw bytes/control chars persist, or the field is dropped entirely by an
unrelated pre-existing control-char gate), GREEN after. Test 6 is a LIVE PIN
of step 1 (the pfb_filter IDN/Unicode commit, same branch): the DNSBL
custom-list IDN acceptance is already GREEN at red time -- it never touches
the encode wiring, it is here so the whole #1723 story has one CI-visible
regression guard for the IDN half too.
"""

from __future__ import annotations

import base64
import uuid
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from . import test_category_edit as tce
from . import test_hooks as th
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
IP_PAGE = "/pfblockerng/pfblockerng_ip.php"
GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
EDIT_HOOKS_PAGE = "/pfblockerng/pfblockerng_edit_hooks.php"
PFB_INC_PATH = "/usr/local/pkg/pfblockerng/pfblockerng.inc"

# Generous POST timeouts: DNSBL/IP saves only write_config() (fast); General's
# save additionally runs sync_package_pfblockerng() (a full config-rebuild
# pass) AFTER write_config, mirroring test_functional.ToggleFlow's default.
SETTINGS_SAVE_TIMEOUT = 120.0
GENERAL_SAVE_TIMEOUT = 300.0


@pytest.fixture(scope="module")
def dnsbl_vip_ready(smoke_vm: helpers.SmokeVM) -> None:
    """Ensure the DNSBL sinkhole VIP exists so a DNSBL settings save validates.

    Mirrors :func:`tests.smoke.ui.test_functional.dnsbl_vip_ready` -- the DNSBL
    save runs ``pfb_validate_vips`` (manual mode) on every save; without a
    valid VIP the save always aborts with an input error before any of the
    fields under test here are even reached. Idempotent on the fixed uniqid.
    """
    helpers.ensure_dnsbl_vip(smoke_vm)


def _decoded(b64_value: str) -> str:
    """UTF-8-decode a base64 config blob (empty string decodes to '')."""
    return base64.b64decode(b64_value).decode("utf-8") if b64_value else ""


def _dnsbl_folder(vm: helpers.SmokeVM) -> str:
    """The DNSBL feed folder (``$pfb['dnsdir']``) the box resolves at runtime.

    Mirrors ``pfb_determine_list_detail('unbound', ...)``'s folder mapping
    (pfblockerng.inc ~5257) -- read live rather than hardcoded so this test
    stays correct across ``$g['vardb_path']`` layouts.
    """
    pre = f"require_once({helpers._php_str(PFB_INC_PATH)});\nglobal $pfb; pfb_global();\n$e = $pfb['dnsdir'];"
    return helpers._php_read_scalar(vm, pre, "$e", timeout=120.0)


def _flag_exists(vm: helpers.SmokeVM, path: str) -> bool:
    pre = f"$e = file_exists({helpers._php_str(path)}) ? 'YES' : 'NO';"
    return helpers._php_read_scalar(vm, pre, "$e", timeout=120.0) == "YES"


def _hook_script_bytes(vm: helpers.SmokeVM, path: str) -> str:
    """Return an on-box hook script's EXACT content, control characters intact.

    Read base64-encoded over the pfSsh.php channel rather than ``cat``: the
    payload under test deliberately carries a vertical tab and CR bytes, and a
    plain SSH text read would let the transport (or a shell) rewrite exactly
    the bytes the assertion is about.
    """
    pre = f"$e = base64_encode((string) @file_get_contents({helpers._php_str(path)}));"
    return base64.b64decode(helpers._php_read_scalar(vm, pre, "$e", timeout=120.0)).decode("utf-8")


def test_dnsbl_textarea_save_normalizes_line_endings_and_controls(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,  # noqa: ARG001
) -> None:
    """``pfb_regex_list`` save normalizes line endings and strips control chars.

    Raw payload mixes: a LF-terminated row with trailing space+tab, and a row
    separated from the next by a BARE CR (old-Mac line ending, no LF) with an
    embedded ``\\x0B`` (vertical tab).

    Design notes (two independent, pre-existing gates this field carries that
    the other multi-line fields do not -- neither is touched by this fix, and
    the payload is shaped to survive both so the ENCODE-time sanitizer stays
    the sole variable under test):

    * pfBlockerNG's separate Python regex-syntax validator
      (``pfb_dnsbl_regex_validation_errors``, gated on a usable interpreter)
      reads its stdin line-by-line splitting ONLY on ``\\n`` -- unlike PHP's
      sanitizer, it does NOT treat a bare ``\\r`` as a line break, so a raw
      ``\\r`` stays embedded INSIDE whatever Python "line" it falls in; a
      non-comment line containing an embedded control byte then trips its
      "contains ASCII control character" rejection and aborts the WHOLE
      DNSBL settings save (confirmed empirically: an early draft without the
      leading ``#`` failed with both before/after reading '', i.e. no save
      at all). Prefixing the CR/VT-bearing row with ``#`` sidesteps it: the
      validator skips a line outright once it starts with ``#``, without
      ever inspecting its characters.
    * ``pfblockerng_dnsbl.php`` ALSO gates the whole field on
      ``mb_detect_encoding($_POST['pfb_regex_list'], 'ASCII', TRUE)``
      ("DNSBL Regex list contains non-ascii characters") -- so, unlike every
      other field this issue touches, this one cannot carry an NBSP-only-row
      (or any non-ASCII byte) at all; that Unicode-aware-strip property is
      pinned on ``whitelist`` instead (next test below), which has no such
      gate and already needs Unicode content for its own assertion.

    RED (before commit 2): ``base64_encode($_POST['pfb_regex_list'])`` stores
    the raw bytes verbatim -- the CR-only row boundary, the trailing
    whitespace, and the VT all survive undecoded.

    GREEN (after): ``pfb_text_area_encode()`` runs ``pfb_sanitize_text_area()``
    first -- CR/CRLF normalize to LF, every control char (incl. ``\\x0B``) is
    stripped, and each line is right-stripped.
    """
    vm = smoke_vm
    domain = helpers.unique_domain("pfbregex")
    raw = f"{domain}  \t\n#plainrow2\rvtrow3\x0b\nfinalrow4"
    expected = f"{domain}\n#plainrow2\nvtrow3\nfinalrow4"
    cfg = "installedpackages/pfblockerngdnsblsettings/config/0/pfb_regex_list"

    before = helpers.config_get(vm, cfg)
    resp = webui.post(DNSBL_PAGE, {"pfb_regex_list": raw}, timeout=SETTINGS_SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "DNSBL POST returned the login form (session lost)"

    after = helpers.config_get(vm, cfg)
    assert after != before, "pfb_regex_list did not change -- the save did not take (POST must CAUSE the change)"
    assert _decoded(after) == expected, f"pfb_regex_list not normalized: expected {expected!r}, got {_decoded(after)!r}"


def test_dnsbl_whitelist_comment_control_char_stripped(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,  # noqa: ARG001
) -> None:
    """DNSBL ``whitelist`` save strips a control char from a comment, keeps Unicode.

    Also carries the NBSP-only-row property originally planned for the
    ``pfb_regex_list`` test (test 1): that field has its OWN, unrelated
    ``mb_detect_encoding($_POST['pfb_regex_list'], 'ASCII', TRUE)`` save-time
    gate ("DNSBL Regex list contains non-ascii characters") that rejects ANY
    non-ASCII byte outright -- NBSP included -- so it structurally cannot
    carry this property; ``whitelist`` has no such gate and already needs
    Unicode content for the control-char/comment assertion above, so it is
    the natural home for it. The two-line raw body stays validation-inert:
    pfBlockerNG's customlist validator here also splits on the LITERAL
    ``"\\r\\n"`` substring (absent from a bare ``\\n``-joined body), so the
    whole two-line payload is handled as ONE "line" containing a ``#`` --
    only the text BEFORE the first ``#`` (our clean ASCII domain) is
    validated; everything after, including the second line, is comment tail.

    RED (before commit 2): the raw ``\\x07`` (BEL) survives in the persisted
    base64 blob, and the NBSP-only second row survives as literal NBSP
    (not an empty line).

    GREEN (after): ``pfb_text_area_encode()`` strips the ``\\x07`` while
    leaving the Unicode comment text (``é``, ``☕``) byte-identical, and
    right-strips the NBSP-only row to an EMPTY line (Unicode-aware, not
    ASCII-only whitespace).
    """
    vm = smoke_vm
    domain = helpers.unique_domain("pfbsupp")
    raw = f"{domain} # caf\x07é ☕\n\xa0"
    expected = f"{domain} # café ☕\n"
    cfg = "installedpackages/pfblockerngdnsblsettings/config/0/whitelist"

    before = helpers.config_get(vm, cfg)
    resp = webui.post(DNSBL_PAGE, {"whitelist": raw}, timeout=SETTINGS_SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "DNSBL POST returned the login form (session lost)"

    after = helpers.config_get(vm, cfg)
    assert after != before, "whitelist did not change -- the save did not take (POST must CAUSE the change)"
    assert _decoded(after) == expected, f"whitelist control-char not stripped: got {_decoded(after)!r}"


def test_ip_suppression_cr_only_rows_persist_as_lf(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``v4suppression`` save normalizes bare-CR row separators to LF.

    Design note: the save-time validator (``pfblockerng_ip.php``) still splits
    on the LITERAL substring ``"\\r\\n"`` (a separate, pre-existing quirk this
    issue does not touch), so a genuinely CR-only multi-row body would be
    handed to ``pfb_validate_suppression_line`` as ONE dirty multi-address
    string and rejected outright -- confounding this test with an unrelated
    abort. A leading ``#`` comment sidesteps it: ``pfb_validate_suppression_line``
    returns early (no validation at all) whenever the line it is given starts
    with ``#`` -- exactly the shape of a real suppression list with a header
    comment -- so the encode-time sanitizer is the sole variable under test.

    RED (before commit 2): ``base64_encode($_POST['v4suppression'])`` stores
    the bare ``\\r`` separators verbatim.

    GREEN (after): ``pfb_text_area_encode()`` normalizes them to ``\\n``.

    The header comment carries a per-run UUID token (not just the fixed
    RFC 5737 addresses) so the computed ``expected`` value is unique across
    re-runs on an unreset box -- the persisted value is asserted EQUAL to
    that computed expectation (not merely "changed from before"), and a
    before-state read still guards against a stale box already holding this
    run's exact expected value.
    """
    vm = smoke_vm
    token = uuid.uuid4().hex[:12]
    addr1, addr2, addr3 = "198.51.100.1/32", "198.51.100.2/32", "198.51.100.3/32"
    raw = f"# smoke cr-only header {token}\r{addr1}\r{addr2}\r{addr3}"
    expected = f"# smoke cr-only header {token}\n{addr1}\n{addr2}\n{addr3}"
    cfg = "installedpackages/pfblockerngipsettings/config/0/v4suppression"

    before = helpers.config_get(vm, cfg)
    assert _decoded(before) != expected, (
        f"v4suppression already holds this run's expected value (stale/colliding state): {expected!r}"
    )
    resp = webui.post(IP_PAGE, {"v4suppression": raw}, timeout=SETTINGS_SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "IP POST returned the login form (session lost)"

    after = helpers.config_get(vm, cfg)
    assert _decoded(after) == expected, f"v4suppression CR rows not normalized to LF: got {_decoded(after)!r}"


def test_general_allowlist_control_chars_stripped(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """``pfb_feed_internal_allowlist`` save strips an embedded control char.

    The field is already CRLF-normalized and trimmed by the EXISTING save code
    (``base64_encode(str_replace("\\r\\n", "\\n", trim(...)))``) -- the
    control-strip is the RED differentiator this test pins, not the
    normalization (already covered elsewhere). The allowlist textarea is
    rendered ``disabled`` while ``pfb_feed_internal_filter`` is off (a
    disabled control submits nothing), so the override explicitly turns the
    filter on -- otherwise the save silently preserves the old stored value
    and the field under test is never reached.

    RED (before commit 2): the raw ``\\x07`` survives.
    GREEN (after): ``pfb_text_area_encode()`` strips it, Unicode intact.
    """
    vm = smoke_vm
    domain = helpers.unique_domain("pfballow")
    raw = f"caf\x07é-{domain}"
    expected = f"café-{domain}"
    cfg = "installedpackages/pfblockerng/config/0/pfb_feed_internal_allowlist"

    before = helpers.config_get(vm, cfg)
    resp = webui.post(
        GENERAL_PAGE,
        {"pfb_feed_internal_filter": "on", "pfb_feed_internal_allowlist": raw},
        timeout=GENERAL_SAVE_TIMEOUT,
    )
    assert not looks_like_login_page(resp.text), "General POST returned the login form (session lost)"

    after = helpers.config_get(vm, cfg)
    assert after != before, "pfb_feed_internal_allowlist did not change -- the save did not take"
    assert _decoded(after) == expected, f"allowlist control-char not stripped: got {_decoded(after)!r}"


def test_category_edit_description_sanitized(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """DNSBL alias ``description`` save trims, strips controls, keeps Unicode.

    RED (before commit 2): ``pfb_filter($_POST['description'], PFB_FILTER_HTML,
    ...)`` has its OWN, unrelated universal control-character gate (every
    ``pfb_filter()`` call rejects input containing ``\\p{Cc}``) -- so a
    raw ``\\x07`` in the posted description does not survive mangled, it makes
    ``pfb_filter()`` reject the WHOLE value and fall back to its default
    (``''``): the persisted description is EMPTY, not ``'café'``. Either way
    the assertion below (`== 'café'`) fails for the reason this change
    addresses -- the field was never sanitized before reaching that gate.

    GREEN (after): ``pfb_sanitize_text()`` runs BEFORE ``pfb_filter()`` --
    the control char is gone before the gate ever sees the value, so
    ``pfb_filter()`` passes it through (``htmlspecialchars(trim('café'))``
    is a no-op here) and the persisted description is ``'café'``.
    """
    vm = smoke_vm
    rowid = tce._free_rowid(vm, tce.CFG_DNSBL)
    base = f"{tce.CFG_DNSBL}/{rowid}"
    aliasname = "smokedescsan"
    try:
        assert helpers.config_get(vm, f"{base}/description") == "", f"rowid {rowid} not free (description already set)"

        tce._post_form(
            webui,
            tce._dnsbl_payload(rowid, aliasname, description="  caf\x07é  "),
        )

        assert helpers.config_get(vm, f"{base}/description") == "café", (
            "description not sanitized (trim + control-strip + Unicode-intact)"
        )
    finally:
        tce._del_rowid(vm, tce.CFG_DNSBL, rowid)


def test_category_edit_custom_list_accepts_idn_row(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A Unicode-label custom-list row saves cleanly (live pin of step 1's IDN change).

    NOT a persist-boundary sanitization test -- step 1 (the pfb_filter
    IDN/Unicode commit, same branch) already widened ``pfb_filter()``/the
    category-edit custom-list
    validator to accept IDN/Unicode domains; this is already GREEN at red
    time and stays green through commit 2 (the encode wiring never touches
    this validator). It exists so #1723 pins BOTH halves of the "standardize
    text fields" story with one live CI guard each.

    Given a free DNSBL rowid, saving a custom-list row whose label is a
    Unicode string (``"bü" + unique_domain()`` -- never an RFC 6761 TLD) must
    NOT abort the whole save (the DNSBL custom-list validator idn_to_ascii()s
    a non-ctype_print row before validating it as a domain) -- proven by the
    aliasname (written in the SAME ``if (!$input_errors)`` block as the custom
    row) landing, and the custom field itself being non-empty afterward.
    """
    vm = smoke_vm
    rowid = tce._free_rowid(vm, tce.CFG_DNSBL)
    base = f"{tce.CFG_DNSBL}/{rowid}"
    aliasname = "smokeidnrow"
    custom_row = "bü" + helpers.unique_domain("pfbidn")
    try:
        assert helpers.config_get(vm, f"{base}/aliasname") == "", f"rowid {rowid} not free (aliasname already set)"

        tce._post_form(
            webui,
            tce._dnsbl_payload(rowid, aliasname, custom=custom_row),
        )

        assert helpers.config_get(vm, f"{base}/aliasname") == aliasname, (
            "IDN custom-list row aborted the whole save (aliasname did not persist) -- "
            "the custom-list validator rejected the Unicode label"
        )
        # The single-line row carries no CR/LF/control chars/trailing whitespace, so
        # pfb_text_area_encode()'s pfb_sanitize_text_area() pass is a no-op -- the
        # decoded persisted value must equal the typed row exactly, not merely be
        # non-empty.
        assert _decoded(helpers.config_get(vm, f"{base}/custom")) == custom_row, (
            f"IDN custom-list row: 'custom' field does not match the typed row, "
            f"got {_decoded(helpers.config_get(vm, f'{base}/custom'))!r}"
        )
    finally:
        tce._del_rowid(vm, tce.CFG_DNSBL, rowid)


def test_category_edit_noop_resave_does_not_touch_update_flag(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A no-op custom-list resave must not touch the list's ``.update`` flag (#1729 review).

    The change detector at ``pfblockerng_category_edit.php`` ~829 compared the
    RAW ``$_POST['custom']`` (CRLF, exactly as a browser submits a textarea)
    against the STORED blob -- which ``pfb_text_area_encode()`` persists
    LF-only. An unchanged custom list therefore always compared unequal, so
    every no-op save touched
    ``{$pfbarr['folder']}/{$aname}_custom{$suffix}.update``, forcing a
    spurious custom-list reprocess/WHOIS re-query on the next cron pass.

    Given a DNSBL alias (``action='unbound'`` -> ``pfb_determine_list_detail``
    resolves a real folder, mirroring a normal DNSBL group) saved once with a
    CRLF-joined custom list, its ``.update`` flag then removed,
    When the IDENTICAL (CRLF) form is re-POSTed unchanged,
    Then the persisted ``custom`` value must be unchanged AND the flag file
    must NOT reappear.

    RED (before the fix): the second save's raw-vs-sanitized compare is
    always unequal -> the flag is touched every time.
    GREEN (after): compare sanitized-vs-sanitized -> a no-op resave never
    touches the flag.
    """
    vm = smoke_vm
    rowid = tce._free_rowid(vm, tce.CFG_DNSBL)
    base = f"{tce.CFG_DNSBL}/{rowid}"
    aliasname = "smokenoopresave"
    folder = _dnsbl_folder(vm)
    flag = f"{folder}/{aliasname}_custom.update"
    raw_custom = "\r\n".join([helpers.unique_domain("pfbnoopa"), helpers.unique_domain("pfbnoopb")])
    try:
        assert helpers.config_get(vm, f"{base}/aliasname") == "", f"rowid {rowid} not free (aliasname already set)"

        tce._post_form(webui, tce._dnsbl_payload(rowid, aliasname, custom=raw_custom))
        assert helpers.config_get(vm, f"{base}/aliasname") == aliasname, "first save did not persist the alias"
        first_custom = helpers.config_get(vm, f"{base}/custom")
        assert first_custom, "first save did not persist a custom list"

        # Sweep the flag the first (necessarily change-detected) save touched, and
        # confirm its absence before the no-op resave under test.
        helpers.php_eval(vm, f"@unlink({helpers._php_str(flag)}); echo 'OK';", timeout=120.0)
        assert not _flag_exists(vm, flag), f"precondition: {flag} must be absent before the no-op resave"

        tce._post_form(webui, tce._dnsbl_payload(rowid, aliasname, custom=raw_custom))

        assert helpers.config_get(vm, f"{base}/custom") == first_custom, (
            "an identical (CRLF) resave must not change the persisted custom list"
        )
        assert not _flag_exists(vm, flag), (
            f"a no-op custom-list resave must not touch {flag} (raw-vs-sanitized compare bug)"
        )
    finally:
        helpers.php_eval(vm, f"@unlink({helpers._php_str(flag)}); echo 'OK';", timeout=120.0)
        tce._del_rowid(vm, tce.CFG_DNSBL, rowid)


def test_category_edit_custom_list_accepts_wildcard_idn_row(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """A leading-dot (wildcard) Unicode custom-list row saves cleanly (issue #1740).

    ``.example.com`` is pfBlockerNG's wildcard form. The custom-list validator
    punycode-converts a non-ASCII row BEFORE handing it to ``pfb_filter()``,
    and ``idn_to_ascii()`` rejects a leading dot outright -- so the wildcard
    IDN row was emptied and then reported as ``Invalid Domain name entry``,
    while its ASCII twin and the read path both accept it.

    Live counterpart of ``tests/php/CategoryEditIdnWildcardTest.php``: the
    aliasname is written in the SAME ``if (!$input_errors)`` block as the
    custom row, so its landing proves the row did not abort the save, and the
    row itself must persist byte-for-byte (no CR/LF/control chars in it, so
    the encode-time sanitizer is a no-op).
    """
    vm = smoke_vm
    rowid = tce._free_rowid(vm, tce.CFG_DNSBL)
    base = f"{tce.CFG_DNSBL}/{rowid}"
    aliasname = "smokeidnwildcard"
    custom_row = ".bü" + helpers.unique_domain("pfbidnw")
    try:
        assert helpers.config_get(vm, f"{base}/aliasname") == "", f"rowid {rowid} not free (aliasname already set)"

        tce._post_form(
            webui,
            tce._dnsbl_payload(rowid, aliasname, custom=custom_row),
        )

        assert helpers.config_get(vm, f"{base}/aliasname") == aliasname, (
            "wildcard IDN custom-list row aborted the whole save (aliasname did not persist) -- "
            "the custom-list validator rejected the leading-dot Unicode label"
        )
        assert _decoded(helpers.config_get(vm, f"{base}/custom")) == custom_row, (
            f"wildcard IDN custom-list row: 'custom' field does not match the typed row, "
            f"got {_decoded(helpers.config_get(vm, f'{base}/custom'))!r}"
        )
    finally:
        tce._del_rowid(vm, tce.CFG_DNSBL, rowid)


def test_category_edit_rowhelper_header_sanitized(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """DNSBL alias rowhelper ``header-0`` sanitizes BOM/NBSP at ingestion (#1737).

    Companion to ``CategoryEditPostGuardTest`` (PHPUnit oracle, off-appliance):
    ``pfblockerng_category_edit.php``'s rowhelper ``header-N``/``url-N`` fields
    used to sanitize only in the PERSIST loop, after the validation loop had
    already evaluated the raw (unsanitized) bytes. A new ingestion-prologue
    loop now runs ``pfb_sanitize_text()`` on every ``header-N``/``url-N`` POST
    key right before validation, so both loops see the same bytes. The row is
    kept ``state-0='Disabled'`` -- the header check is non-empty-, not state-,
    gated (issue #1270), and an empty ``url-0`` on a Disabled row skips every
    url-N check, so the header sanitizer is the sole variable under test.

    RED (before the fix): the NBSP/BOM survive into the validation loop's own
    ``\\W`` header check unchanged -- a NBSP is ``\\W``, so the whole save is
    REJECTED and the seeded (empty) header is left unchanged.
    GREEN (after): the ingestion prologue strips the NBSP/BOM before the
    validation loop ever runs, so the row validates and persists as ``'hdr'``.
    """
    vm = smoke_vm
    rowid = tce._free_rowid(vm, tce.CFG_DNSBL)
    base = f"{tce.CFG_DNSBL}/{rowid}"
    aliasname = "smokehdrsan"
    try:
        assert helpers.config_get(vm, f"{base}/aliasname") == "", f"rowid {rowid} not free (aliasname already set)"
        assert helpers.config_get(vm, f"{base}/row/0/header") == "", f"rowid {rowid} not free (header already set)"

        raw = "\u00a0hdr\ufeff"
        expected = "hdr"
        tce._post_form(
            webui,
            tce._dnsbl_payload(rowid, aliasname, **{"header-0": raw}),
        )

        assert helpers.config_get(vm, f"{base}/aliasname") == aliasname, (
            "the save aborted (aliasname did not persist) -- the header guard rejected the sanitized value"
        )
        assert helpers.config_get(vm, f"{base}/row/0/header") == expected, (
            f"header not sanitized at ingestion: expected {expected!r}, got "
            f"{helpers.config_get(vm, f'{base}/row/0/header')!r}"
        )
    finally:
        tce._del_rowid(vm, tce.CFG_DNSBL, rowid)


def test_category_edit_rowhelper_url_sanitized(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """DNSBL alias rowhelper ``url-0`` sanitizes BOM/NBSP at ingestion (#1737).

    Companion to ``test_category_edit_rowhelper_header_sanitized`` above -- the
    #1737 contract update sanitizes BOTH ``header-N`` and ``url-N`` at
    ingestion, but that test keeps the row ``state-0='Disabled'`` so the
    empty ``url-0`` skips every state-gated url check entirely -- it never
    proves the ingestion sanitizer runs ahead of THOSE. This test keeps
    ``state-0='Enabled'``/``format-0='geoip'`` instead (the deterministic,
    no-network-fetch shape ``test_dnsbl_url_geoip_value_persists_byte_identical``
    in ``test_category_edit.py`` already uses -- 'auto'/'regex'/'rsync' would
    need a real resolvable feed host) so the row actually persists through
    BOTH the non-empty-gated control-char guard AND the state-gated geoip
    ``PFB_FILTER_ALNUM`` prefix check, not just the former.

    RED (before the fix): the raw BOM (category Cf) is itself inside the
    row's own ``\\p{C}`` url-N guard (issue #1104), run on the RAW value
    before any sanitize -- the save is REJECTED outright and the seeded
    (empty) url is left unchanged (mirrors
    ``test_category_edit_rowhelper_header_sanitized``'s RED story).
    GREEN (after): ``pfb_sanitize_text()`` strips the BOM + Unicode-trims the
    leading NBSP BEFORE the validation loop runs, so the row validates
    (geoip's prefix check sees a clean ``'US'``) and persists as ``'US CA'``.
    """
    vm = smoke_vm
    rowid = tce._free_rowid(vm, tce.CFG_DNSBL)
    base = f"{tce.CFG_DNSBL}/{rowid}"
    aliasname = "smokeurlsan"
    orig_key, orig_account = tce._capture_maxmind_creds(vm)
    try:
        tce._seed_maxmind_test_creds(vm)
        assert helpers.config_get(vm, f"{base}/aliasname") == "", f"rowid {rowid} not free (aliasname already set)"
        assert helpers.config_get(vm, f"{base}/row/0/url") == "", f"rowid {rowid} not free (url already set)"

        raw = "\u00a0US CA\ufeff"
        expected = "US CA"
        tce._post_form(
            webui,
            tce._dnsbl_payload(
                rowid,
                aliasname,
                **{"state-0": "Enabled", "header-0": "hdr", "format-0": "geoip", "url-0": raw},
            ),
        )

        assert helpers.config_get(vm, f"{base}/aliasname") == aliasname, (
            "the save aborted (aliasname did not persist) -- the url guard rejected the sanitized value"
        )
        assert helpers.config_get(vm, f"{base}/row/0/url") == expected, (
            f"url not sanitized at ingestion: expected {expected!r}, got "
            f"{helpers.config_get(vm, f'{base}/row/0/url')!r}"
        )
    finally:
        tce._del_rowid(vm, tce.CFG_DNSBL, rowid)
        tce._restore_maxmind_creds(vm, orig_key, orig_account)


def test_dnsbl_whitelist_accepts_single_dot_wildcard_row(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,  # noqa: ARG001
) -> None:
    """The Whitelist list keeps taking the single-dot wildcard row (issue #1741).

    The before-state half of the pair below: ``.example.com`` is the legal
    wildcard form and must still save, so the rejection of ``..example.com``
    is proven to be about the SECOND dot and not about leading dots at all.
    """
    vm = smoke_vm
    domain = helpers.unique_domain("pfbwild")
    cfg = "installedpackages/pfblockerngdnsblsettings/config/0/whitelist"

    before = helpers.config_get(vm, cfg)
    resp = webui.post(DNSBL_PAGE, {"whitelist": f".{domain}"}, timeout=SETTINGS_SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "DNSBL POST returned the login form (session lost)"

    after = helpers.config_get(vm, cfg)
    assert after != before, "whitelist did not change -- the save did not take (POST must CAUSE the change)"
    assert _decoded(after) == f".{domain}", (
        f"the single-dot wildcard row must persist verbatim, got {_decoded(after)!r}"
    )


def test_dnsbl_whitelist_rejects_double_dot_row(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,  # noqa: ARG001
) -> None:
    """The Whitelist list refuses a multi-dot row (issue #1741).

    ``..example.com`` is not a wildcard row. The page validated a
    ``trim($value[0], '.')`` copy, which drops EVERY leading dot, so the row
    validated as the bare domain and was saved -- and the build path then
    ltrim'd it into ``example.com,1``, a whitelist entry covering the whole
    domain and every subdomain the operator never wrote.

    Live counterpart of ``tests/php/DnsblCustomListWildcardValidationTest.php``:
    the save must abort, leaving the persisted field untouched.
    """
    vm = smoke_vm
    domain = helpers.unique_domain("pfbdotdot")
    cfg = "installedpackages/pfblockerngdnsblsettings/config/0/whitelist"

    before = helpers.config_get(vm, cfg)
    resp = webui.post(DNSBL_PAGE, {"whitelist": f"..{domain}"}, timeout=SETTINGS_SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "DNSBL POST returned the login form (session lost)"

    # The rejection must be THIS row's, not an unrelated save-wide abort: assert the
    # page's own per-row message before asserting that nothing persisted.
    expected_error = f"Customlist whitelist: Invalid Domain name entry: [ ..{domain} ]"
    assert expected_error in resp.text, (
        f"the page did not report the multi-dot row as invalid (expected {expected_error!r}) -- "
        "an unrelated validation failure would abort the save too"
    )

    after = helpers.config_get(vm, cfg)
    assert after == before, (
        f"the multi-dot row was saved -- whitelist changed from {_decoded(before)!r} "
        f"to {_decoded(after)!r}; the validator must refuse it"
    )


def test_dnsbl_tld_exclusion_accepts_idn_row(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,  # noqa: ARG001
) -> None:
    """TLD Exclusion (hostname-typed) keeps taking a Unicode/IDN row (issue #1731).

    TLD Exclusion (``tld_wildcard_exclusion``, PFB_FILTER_HOSTNAME) used to reject
    any non-ASCII row outright -- bare ``is_hostname()``, no IDN branch -- while
    the adjacent TLD Blacklist (``tld_wildcard_blacklist``, PFB_FILTER_TLD, issue #1723)
    already accepted a punycode-convertible Unicode row. pfb_filter()'s
    PFB_FILTER_HOSTNAME case now converts a non-ASCII input to its punycode
    candidate before ``is_hostname()`` runs, matching PFB_FILTER_TLD.
    """
    vm = smoke_vm
    idn_row = "bü" + helpers.unique_domain("pfbtldxidn")
    cfg = "installedpackages/pfblockerngdnsblsettings/config/0/tld_wildcard_exclusion"

    before = helpers.config_get(vm, cfg)
    resp = webui.post(DNSBL_PAGE, {"tld_wildcard_exclusion": idn_row}, timeout=SETTINGS_SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "DNSBL POST returned the login form (session lost)"
    assert "Invalid  Hostname entry" not in resp.text, f"the IDN row was rejected as an invalid hostname: {idn_row!r}"

    after = helpers.config_get(vm, cfg)
    assert after != before, (
        "tld_wildcard_exclusion did not change -- the save did not take (POST must CAUSE the change)"
    )
    assert _decoded(after) == idn_row, f"the IDN row must persist verbatim, got {_decoded(after)!r}"


def test_edit_hooks_save_sanitizes_the_written_script(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """The Edit Hooks save writes the shared-sanitizer form of the typed script (issue #1734).

    Scenario: the gated hook-script editor is the one persist boundary that was
    deliberately left narrower than the #1723 standard -- it only collapsed line
    endings. The #1728 owner decision routes it through the shared
    ``pfb_sanitize_text_area()`` instead, so a saved script picks up the same
    control-character strip and per-line right-strip every other multi-line field
    already gets.

    Given an existing, picker-vetted hook script on the box,
    When the editor saves a body that mixes CRLF, a bare CR row separator,
    trailing space+tab, an embedded vertical tab, and a blank line,
    Then the file on disk holds bare-LF rows with the trailing whitespace and
    the vertical tab gone, and the blank line still there.

    The line-ending half is asserted alongside the new behaviour on purpose: it
    is the regression the retired ``pfb_hook_editor_normalize_content()`` existed
    to prevent (a saved ``"#!/bin/sh\\r"`` shebang execs a nonexistent
    ``/bin/sh\\r`` and the hook silently stops firing), and the replacement must
    keep it fixed.

    RED (before the change): the narrower helper only folds CR/CRLF to LF, so the
    trailing ``"   \\t"`` and the ``\\x0b`` persist into the executable script.
    GREEN (after): ``pfb_sanitize_text_area()`` folds the line endings first, then
    strips the control character and right-strips each line, preserving the blank
    line so script formatting survives.
    """
    vm = smoke_vm
    script = f"hook_pre_smoke{uuid.uuid4().hex[:12]}.sh"
    path = f"{helpers.HOOK_SCRIPT_DIR}/{script}"
    seed = "#!/bin/sh\necho seed\n"
    raw = "#!/bin/sh\r\necho 'edited'   \t\rprintf '\x0bvt'\n\nexit 0\n"
    expected = "#!/bin/sh\necho 'edited'\nprintf 'vt'\n\nexit 0\n"

    helpers.install_hook_script(vm, script, seed)
    try:
        before = _hook_script_bytes(vm, path)
        assert before == seed, f"seed script not installed verbatim, got {before!r}"

        resp = webui.post(
            EDIT_HOOKS_PAGE,
            {
                "pfb_eh_cur_when": "pre",
                "pfb_eh_cur_script": script,
                "pfb_eh_content": raw,
            },
            submit=("pfb_eh_save", "Save"),
            timeout=SETTINGS_SAVE_TIMEOUT,
        )
        assert not looks_like_login_page(resp.text), "Edit Hooks POST returned the login form (session lost)"

        after = _hook_script_bytes(vm, path)
        assert after != before, "the hook script did not change -- the save did not take (POST must CAUSE the change)"
        assert after == expected, f"hook script not sanitized on save: expected {expected!r}, got {after!r}"
    finally:
        vm.ssh("/bin/rm", "-f", path, timeout=60.0)


def test_hooks_row_description_sanitized(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
) -> None:
    """Hooks tab row ``description`` sanitizes BOM/control/trailing-NBSP at ingestion (#1761).

    Companion to ``HooksSanitizeIngestionTest`` (PHPUnit oracle, off-appliance):
    ``pfblockerng_hooks.php``'s rowhelper validation loop used a bare ``trim()``
    at persist, so a BOM/control byte survived and a trailing Unicode (NBSP)
    space did not. Routing ``hook_description-N`` through ``pfb_sanitize_text()``
    at ingestion -- before the row's own ``\\p{C}`` control-char validator runs --
    fixes both, and (per the PHPUnit oracle) the validator still gates a genuine
    Cf/Cc character; this live pin proves the happy-path save persists the clean
    string end to end through the real page/config.xml round trip.

    RED (before the fix): the BOM (category Cf) is itself inside the row's own
    ``\\p{C}`` description validator -- run on the RAW value, before any
    sanitize -- so the save is REJECTED outright and the seeded description is
    left unchanged (mirrors ``test_category_edit_description_sanitized``
    above: "either way the assertion fails for the reason this change
    addresses").
    GREEN (after): ``pfb_sanitize_text()`` strips the BOM + control char and
    Unicode-trims the trailing NBSP BEFORE the validator runs, so the row
    validates and persists as ``"smokedesc"``.
    """
    vm = smoke_vm
    helpers.clear_update_hooks(vm)
    th._install_test_scripts(vm)
    seed_description = "smoke-1761-seed"
    th._seed_one_hook(vm, script=th.SCRIPT_POST, when="post", enabled="on", description=seed_description)
    try:
        assert helpers.config_get(vm, th.ROW0_DESCRIPTION) == seed_description, (
            f"seed description missing before the save flow: got {helpers.config_get(vm, th.ROW0_DESCRIPTION)!r}"
        )

        raw = "\ufeffsmokedesc\x07\u00a0"
        expected = "smokedesc"
        resp = webui.post(th.HOOKS_PAGE, {"hook_description-0": raw}, timeout=120.0)
        assert not looks_like_login_page(resp.text), "hooks description POST returned the login form (session lost)"

        after = helpers.config_get(vm, th.ROW0_DESCRIPTION)
        assert after == expected, f"description not sanitized at ingestion: expected {expected!r}, got {after!r}"
    finally:
        helpers.clear_update_hooks(vm)
