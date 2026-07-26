"""Tier-B live pins for the persist-boundary text sanitizers (issue #1723).

Marker ``ui_e2e`` -- see :mod:`tests.smoke.ui.test_functional` for the tier's
general shape. Every test here drives a real CSRF POST (``requests``, never a
browser) and asserts the box's EFFECTIVE ``config.xml`` state (via
:func:`tests.smoke.helpers.config_get`), never the HTTP response body --
``requests``' ``session.post(data=...)`` sends the Python string's bytes
UNCHANGED (no browser-side CRLF canonicalization of textarea content), so a
raw payload mixing LF/CR-only/control chars reaches the server byte-for-byte.

Tests 1-5 pin the persist-boundary sanitizers wired in commit 2 of #1723
(``pfb_text_area_encode()`` for multi-line textarea fields,
``pfb_sanitize_text()`` for single-line fields) -- RED before that commit
(raw bytes/control chars persist, or the field is dropped entirely by an
unrelated pre-existing control-char gate), GREEN after. Test 6 is a LIVE PIN
of step 1 (commit 57aa96e1, same branch): the DNSBL custom-list IDN
acceptance is already GREEN at red time -- it never touches the encode
wiring, it is here so the whole #1723 story has one CI-visible regression
guard for the IDN half too.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from . import test_category_edit as tce
from .webui import looks_like_login_page

if TYPE_CHECKING:
    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

DNSBL_PAGE = "/pfblockerng/pfblockerng_dnsbl.php"
IP_PAGE = "/pfblockerng/pfblockerng_ip.php"
GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"

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
      pinned on ``suppression`` instead (next test below), which has no such
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


def test_dnsbl_suppression_comment_control_char_stripped(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    dnsbl_vip_ready: None,  # noqa: ARG001
) -> None:
    """DNSBL ``suppression`` save strips a control char from a comment, keeps Unicode.

    Also carries the NBSP-only-row property originally planned for the
    ``pfb_regex_list`` test (test 1): that field has its OWN, unrelated
    ``mb_detect_encoding($_POST['pfb_regex_list'], 'ASCII', TRUE)`` save-time
    gate ("DNSBL Regex list contains non-ascii characters") that rejects ANY
    non-ASCII byte outright -- NBSP included -- so it structurally cannot
    carry this property; ``suppression`` has no such gate and already needs
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
    cfg = "installedpackages/pfblockerngdnsblsettings/config/0/suppression"

    before = helpers.config_get(vm, cfg)
    resp = webui.post(DNSBL_PAGE, {"suppression": raw}, timeout=SETTINGS_SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "DNSBL POST returned the login form (session lost)"

    after = helpers.config_get(vm, cfg)
    assert after != before, "suppression did not change -- the save did not take (POST must CAUSE the change)"
    assert _decoded(after) == expected, f"suppression control-char not stripped: got {_decoded(after)!r}"


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
    """
    vm = smoke_vm
    addr1, addr2, addr3 = "198.51.100.1/32", "198.51.100.2/32", "198.51.100.3/32"
    raw = f"# smoke cr-only header\r{addr1}\r{addr2}\r{addr3}"
    expected = f"# smoke cr-only header\n{addr1}\n{addr2}\n{addr3}"
    cfg = "installedpackages/pfblockerngipsettings/config/0/v4suppression"

    before = helpers.config_get(vm, cfg)
    resp = webui.post(IP_PAGE, {"v4suppression": raw}, timeout=SETTINGS_SAVE_TIMEOUT)
    assert not looks_like_login_page(resp.text), "IP POST returned the login form (session lost)"

    after = helpers.config_get(vm, cfg)
    assert after != before, "v4suppression did not change -- the save did not take (POST must CAUSE the change)"
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

    NOT a persist-boundary sanitization test -- step 1 (commit 57aa96e1, same
    branch) already widened ``pfb_filter()``/the category-edit custom-list
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
        assert base64.b64decode(helpers.config_get(vm, f"{base}/custom")) != b"", (
            "IDN custom-list row: 'custom' field is empty after a supposedly successful save"
        )
    finally:
        tce._del_rowid(vm, tce.CFG_DNSBL, rowid)
