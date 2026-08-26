"""issue #1070 -- array-valued $_POST fields must not 500 the settings saves.

The shared ``pfb_filter()`` rejects an array as invalid up front, so every
``ON_OFF``/``WORD``/``NUM``-filtered field in the matrix is covered in one
place. Scope includes issue #1070's filter-routed fields and issue #1106's
``pfblockerng_category_edit.php`` cluster of direct-string sinks that bypass
``pfb_filter`` (an ingress guard blanks any non-scalar POST field; ``atype``
and ``$_REQUEST[savemsg]`` get their own ``is_string()`` guard since they run
outside the save block, reachable via a plain GET query).

Each save/GET must respond like any validation failure: HTTP 200, no login
bounce, and NOT ONE new byte in any candidate ``php_error.log``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard
from .webui import looks_like_login_page, scrape_form_fields

if TYPE_CHECKING:
    from .webui import WebUI

# Tier B: mutating POST flows whose failure mode (a logged fatal + HTTP 500)
# is observable only end-to-end against the live php_error.log. Tier A render
# coverage of the touched pages already exists (test_render_smoke.py).
pytestmark = pytest.mark.ui_e2e

_POST_TIMEOUT = 120.0
_GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
_GENERAL_CONFIG = "installedpackages/pfblockerng/config/0"
_GENERAL_ARRAY_ERRORS = {
    "pfb_scheduled_feed_updates": "Scheduled Feed Updates is invalid.",
    "pfb_schedule_weekday": "Schedule weekday is invalid.",
    "pfb_schedule_hour": "Schedule hour is invalid.",
    "pfb_schedule_minute": "Schedule minute is invalid.",
    "pfb_quiet_hours_enabled": "Automatic Apply Window is invalid.",
    "pfb_quiet_hours_start": "Automatic Apply Window endpoints must be quarter-hour times.",
    "pfb_quiet_hours_end": "Automatic Apply Window endpoints must be quarter-hour times.",
}


def _general_config_token(smoke_vm: helpers.SmokeVM) -> str:
    result = helpers.php_eval(
        smoke_vm,
        "echo '__PFB_GENERAL_CONFIG_BEGIN__'"
        f" . hash('sha256', serialize(config_get_path({helpers._php_str(_GENERAL_CONFIG)}, array())))"
        " . '__PFB_GENERAL_CONFIG_END__';",
    )
    assert result.returncode == 0, f"General config snapshot failed: {result.stderr!r}"
    match = re.search(
        r"__PFB_GENERAL_CONFIG_BEGIN__([0-9a-f]{64})__PFB_GENERAL_CONFIG_END__",
        result.stdout,
    )
    assert match is not None, (
        f"General config snapshot sentinel missing: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    return match.group(1)


def _post_with_array_field(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    page: str,
    array_field: str,
    extra_fields: dict[str, str] | None = None,
) -> None:
    """Scrape the page's own form, replace one field with an array value, POST.

    Scenario: an authenticated save whose ``{array_field}[]`` carries an array.
      Given the page's own scraped field set (valid CSRF token included),
      When the field is re-sent in PHP array syntax and the save is POSTed
        (``extra_fields``, if given, overrides sibling scalar fields so the
        crafted field's own validation line is actually reached -- e.g. a
        rowhelper ``state-N`` must be non-``Disabled`` before its sibling
        ``url-N``/``header-N`` are read),
      Then the handler answers HTTP 200 (a normal validation reject, never a
        TypeError-driven 500), the session survives, and no candidate
        ``php_error.log`` gained a gated-class diagnostic during the request. Every crafted
        aliasname/custom/url-0 case here is rejected by validation before
        ``write_config()`` (an empty/invalid aliasname at rowid 0), so the
        box is never mutated.
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    general_before = _general_config_token(smoke_vm) if array_field in _GENERAL_ARRAY_ERRORS else None

    got = webui.get(page)
    assert got.status_code == 200, f"GET {page} -> HTTP {got.status_code}"
    assert not looks_like_login_page(got.text), f"GET {page} bounced to the login form"

    payload = scrape_form_fields(got.text)
    payload.pop(array_field, None)
    payload[f"{array_field}[]"] = "crafted"
    if extra_fields:
        payload.update(extra_fields)
    payload["save"] = "Save"

    resp = webui.session.post(webui.url(page), data=payload, verify=webui._verify, timeout=_POST_TIMEOUT)

    assert resp.status_code == 200, (
        f"POST {page} with {array_field}[]=crafted -> HTTP {resp.status_code} "
        "(expected a graceful validation reject, not a TypeError 500)"
    )
    assert not looks_like_login_page(resp.text), f"POST {page} bounced to the login form"
    if general_before is not None:
        expected_error = _GENERAL_ARRAY_ERRORS[array_field]
        assert expected_error in resp.text, (
            f"POST {page} with {array_field}[]=crafted did not render {expected_error!r}"
        )
        general_after = _general_config_token(smoke_vm)
        assert general_after == general_before, (
            f"POST {page} with {array_field}[]=crafted changed the General config section"
        )
    guard.assert_no_growth()


# (page, field, extra_fields) covering every array-TypeError class the theme spans
# (issue #1070): representatives of the pfb_filter-routed classes -- ON_OFF,
# WORD, and NUM -- plus (issue #1106) the category_edit ingress-guard cluster.
# All resolve to the same graceful-reject assertion. extra_fields is None except
# for the url-0 case, which needs a
# non-Disabled sibling state-N before its own validation line is reached.
_ARRAY_FIELD_CASES: list[tuple[str, str, dict[str, str] | None]] = [
    ("/pfblockerng/pfblockerng_sync.php", "varsynctimeout", None),  # pfb_filter NUM (pre-loop)
    ("/pfblockerng/pfblockerng_ip.php", "enable_dup", None),  # pfb_filter ON_OFF
    ("/pfblockerng/pfblockerng_ip.php", "asn_token", None),  # pfb_filter WORD
    # issue #1777: ip.php's own ingress guard, on the two ADR-40 fields whose
    # sinks sit below the #1723 sanitize loops -- array_key_exists() (a fatal
    # TypeError on an array) and a (string) cast.
    ("/pfblockerng/pfblockerng_ip.php", "pfb_alias_delta_mode", None),
    ("/pfblockerng/pfblockerng_ip.php", "pfb_alias_delta_batch", None),
    ("/pfblockerng/pfblockerng_general.php", "enable_cb", None),  # pfb_filter ON_OFF
    ("/pfblockerng/pfblockerng_general.php", "pfb_log_trim_margin_pct", None),  # is_array/ctype_digit
    ("/pfblockerng/pfblockerng_general.php", "pfb_scheduled_feed_updates", None),
    ("/pfblockerng/pfblockerng_general.php", "pfb_schedule_weekday", None),
    ("/pfblockerng/pfblockerng_general.php", "pfb_schedule_hour", None),
    ("/pfblockerng/pfblockerng_general.php", "pfb_schedule_minute", None),
    ("/pfblockerng/pfblockerng_general.php", "pfb_quiet_hours_enabled", None),
    ("/pfblockerng/pfblockerng_general.php", "pfb_quiet_hours_start", {"pfb_quiet_hours_enabled": "on"}),
    ("/pfblockerng/pfblockerng_general.php", "pfb_quiet_hours_end", {"pfb_quiet_hours_enabled": "on"}),
    # issue #1106: category_edit's own ingress guard (bypasses pfb_filter entirely).
    ("/pfblockerng/pfblockerng_category_edit.php?type=dnsbl", "aliasname", None),  # preg_match/strlen
    ("/pfblockerng/pfblockerng_category_edit.php?type=dnsbl", "custom", None),  # explode
    ("/pfblockerng/pfblockerng_category_edit.php?type=dnsbl", "atype", None),  # str_starts_with
    (
        "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl",
        "url-0",  # strpos/pfb_filter(URL) in the rowhelper state-loop
        {"state-0": "Enabled", "header-0": "hdr", "format-0": "auto"},
    ),
]


@pytest.mark.parametrize(("page", "field", "extra_fields"), _ARRAY_FIELD_CASES)
def test_array_valued_field_rejected_gracefully(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    page: str,
    field: str,
    extra_fields: dict[str, str] | None,
) -> None:
    _post_with_array_field(webui, smoke_vm, page, field, extra_fields)


def test_unknown_scalar_logtype_rejected_gracefully(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """issue #1198: a scalar but UNKNOWN 'logtype' must fall back silently.

    Given pfblockerng_log.php's own scraped form (valid CSRF token),
    When 'logtype' is resubmitted as the plain scalar 'zzz', which has no
      entry in $pfb_logtypes,
    Then the page still answers HTTP 200, the session survives, and no
      candidate php_error.log gains a gated-class diagnostic (#1218: the
      pre-fix fault here emitted 6 E_WARNINGs of the `Undefined array key`
      class, which the guard now REPORTS rather than gates — so the HTTP,
      session and body assertions are what this test rests on, not the log).
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    page = "/pfblockerng/pfblockerng_log.php"
    got = webui.get(page)
    assert got.status_code == 200, f"GET {page} -> HTTP {got.status_code}"
    assert not looks_like_login_page(got.text), f"GET {page} bounced to the login form"

    payload = scrape_form_fields(got.text)
    payload["logtype"] = "zzz"
    payload["save"] = "Save"

    resp = webui.session.post(webui.url(page), data=payload, verify=webui._verify, timeout=_POST_TIMEOUT)

    assert resp.status_code == 200, f"POST {page} with logtype=zzz -> HTTP {resp.status_code}"
    assert not looks_like_login_page(resp.text), f"POST {page} with logtype=zzz bounced to the login form"
    guard.assert_no_growth()


# issue #1106: 'atype' (GET) and '$_REQUEST[savemsg]' are read outside the save
# block via a plain query string -- unreachable through _post_with_array_field's
# scraped-form POST, so exercised directly as GET queries.
_GET_ARRAY_QUERY_CASES = [
    "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl&savemsg[]=crafted",
    "/pfblockerng/pfblockerng_category_edit.php?type=dnsbl&atype[]=crafted",
]


@pytest.mark.parametrize("page", _GET_ARRAY_QUERY_CASES)
def test_get_query_array_value_rejected_gracefully(webui: WebUI, smoke_vm: helpers.SmokeVM, page: str) -> None:
    """Scenario: a crafted GET query carries an array-valued scalar param.

    Given a page normally read with a scalar 'savemsg'/'atype' query value,
    When the param is sent in PHP array syntax ('param[]=x'),
    Then the page still answers HTTP 200 (never a TypeError 500), the session
      survives, and no candidate ``php_error.log`` gained a gated-class diagnostic.
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()

    resp = webui.get(page)

    assert resp.status_code == 200, f"GET {page} -> HTTP {resp.status_code}"
    assert not looks_like_login_page(resp.text), f"GET {page} bounced to the login form"
    guard.assert_no_growth()
