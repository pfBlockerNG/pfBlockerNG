"""issue #999 -- Tier-B coverage for the dashboard widget's "Clear Failed Downloads" icon.

``pfBlockerNG_clearfailed()`` (widget.php's ``pfblockerngack`` POST handler) closes
every open PHP-owned sync-status ledger entry; the pre-existing (untouched)
``sed -i 's/FAIL/Fail/g' error.log`` call still runs alongside it, feeding the
separate ``pfb_failures()`` skip-download-threshold mechanism. This module proves
BOTH survive the single POST handler, end to end over real HTTP against the ledger
writers, complementing ``test_render_widget_ledger.py``'s render-only coverage
(that module never POSTs; this one drives the actual dismiss action).

Ledger seeding reuses ``test_render_widget_ledger.py``'s own conventions
(``_ledger_open``/``_ledger_close`` over the REAL ``pfb_sync_status_open()``/
``pfb_sync_status_close()``, ``clean_ledger`` for backup/restore) rather than
hand-rolling a JSON blob -- the KILL-GATE mandate that render/behaviour tests
reflect a manually-seeded entry via the production writer, not a fixture that
merely resembles one.
"""

from __future__ import annotations

import subprocess
import uuid
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard
from .test_render_widget_ledger import (  # noqa: F401 -- clean_ledger used as a fixture arg
    _LEDGER_DIR,
    _ledger_close,
    _ledger_open,
    clean_ledger,
)
from .webui import looks_like_login_page, scrape_form_fields

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .webui import WebUI

# Tier B: this module POSTs a dismiss action (a mutating, multi-step flow), which
# is observable only end-to-end -- Tier A's plain-GET render coverage of this same
# page already exists (test_render_smoke.py ~187-189).
pytestmark = pytest.mark.ui_e2e

WIDGET_PAGE = "/widgets/widgets/pfblockerng.widget.php"
_GET_FAILED_URL = f"{WIDGET_PAGE}?getNewFailed=1"
_ERROR_LOG_PATH = "/var/log/pfblockerng/error.log"


@pytest.fixture(scope="module")
def php_error_log_guard(smoke_vm: helpers.SmokeVM, webui: WebUI) -> Iterator[PhpErrorLogGuard]:  # noqa: ARG001
    """Snapshot ``php_error.log`` once before this module's tests, assert no growth after.

    Mirrors ``test_render_widget_ledger.py``'s own fixture -- the dismiss POST
    touches two writers (the ledger close loop, the untouched sed) that could log
    a diagnostic without changing the redirect response at all.
    """
    guard = PhpErrorLogGuard(smoke_vm)
    guard.snapshot()
    yield guard
    guard.assert_no_growth()


def _get_failed_body(webui: WebUI) -> str:
    resp = webui.get(_GET_FAILED_URL)
    assert resp.status_code == 200, f"GET {_GET_FAILED_URL} -> HTTP {resp.status_code} (expected 200)"
    return resp.text


def _dismiss(webui: WebUI, headers: dict[str, str] | None = None) -> None:
    """POST the widget's dismiss action -- the exact payload the hidden 'formicons'
    form's JS-driven submit sends (``pfblockerngack=1``); the handler redirects to
    ``/`` on success (widget.php ~184-186).

    Can't use ``WebUI.post()`` (it hard-requires a scraped ``__csrf_magic`` token):
    ``$nocsrf = TRUE`` at the top of this page means csrf-magic's output filter
    never injects one here at all (confirmed live -- the rendered form has no
    hidden CSRF input), so this replicates ``post()``'s field-scrape-then-POST
    shape without that requirement.

    ``headers`` (issue #1050): extra request headers, e.g. a synthetic
    ``Sec-Fetch-Site`` to drive ``pfb_widget_post_allowed()``'s gate -- the response
    is still a normal 200 either way (blocked = the mutation is skipped and the
    page falls through to its normal render, never a login bounce or a 4xx).
    """
    page = webui.get(WIDGET_PAGE)
    assert page.status_code == 200, f"GET {WIDGET_PAGE} -> HTTP {page.status_code} (expected 200)"
    assert not looks_like_login_page(page.text), "pre-dismiss GET bounced to the login page -- not authenticated"
    payload = scrape_form_fields(page.text)
    payload["pfblockerngack"] = "1"
    resp = webui.session.post(webui.url(WIDGET_PAGE), data=payload, headers=headers, timeout=30)
    assert resp.status_code == 200, f"POST {WIDGET_PAGE} pfblockerngack=1 -> HTTP {resp.status_code} (expected 200)"
    assert not looks_like_login_page(resp.text), "dismiss POST bounced to the login page -- session not authenticated"


def _write_error_log(vm: helpers.SmokeVM, contents: str) -> None:
    """Overwrite ``error.log`` verbatim via ``tee`` over SSH (mirrors
    ``test_render_widget_ledger.py``'s ``_write_remote_file``)."""
    result = subprocess.run(
        vm.ssh_argv("tee", _ERROR_LOG_PATH),
        input=contents,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, f"writing {_ERROR_LOG_PATH} failed: rc={result.returncode} {result.stderr!r}"


def _seed_error_log_fail_line(vm: helpers.SmokeVM, alias: str) -> str:
    """Append one ISO-8601-stamped 'Download FAIL' line, matching pfb_logger()'s stamp
    (pfblockerng.inc:3005) and pfb_failures()'s expected shape (pfblockerng.inc:10706),
    dated TODAY on the guest (never the runner's clock -- avoids a skew false-negative)."""
    today = vm.ssh("date", "+%Y-%m-%d %H:%M:%S")
    assert today.returncode == 0, f"reading guest date failed: rc={today.returncode} {today.stderr!r}"
    stamp = today.stdout.strip()
    line = f"{stamp} [ {alias} - smoke-header ] Download FAIL\n"
    existing = helpers.read_log_file(vm, _ERROR_LOG_PATH)
    _write_error_log(vm, existing + line)
    return line


@pytest.fixture
def clean_error_log(smoke_vm: helpers.SmokeVM) -> Iterator[None]:
    """Snapshot + restore ``error.log`` around a test, mirroring ``clean_ledger``'s
    discipline for the OTHER file the dismiss handler touches."""
    original = helpers.read_log_file(smoke_vm, _ERROR_LOG_PATH)
    try:
        yield
    finally:
        if original:
            _write_error_log(smoke_vm, original)
        else:
            smoke_vm.ssh("rm", "-f", _ERROR_LOG_PATH, timeout=15)


def test_dismiss_closes_single_open_ip_entry(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """One open facility='ip' entry: dismiss closes it, both via the AJAX reporting
    list AND a direct ledger read -- proving the close loop, not just a stale render."""
    vm = smoke_vm
    item = f"pfB_SmokeDismiss_{uuid.uuid4().hex[:8]}_v4"
    message = f"smoke: synthetic apply failure {uuid.uuid4().hex[:8]}"
    _ledger_open(vm, "ip", item, "apply", message)

    # BEFORE: the open entry's message is in the reporting-list fragment.
    before = _get_failed_body(webui)
    assert message in before, "seeded ledger entry's message missing from ?getNewFailed=1 before dismiss"

    _dismiss(webui)

    # AFTER (AJAX fragment): the message is gone.
    after = _get_failed_body(webui)
    assert message not in after, "dismiss POST did not remove the entry from ?getNewFailed=1"

    # AFTER (direct ledger read): the raw JSON no longer names the item at all.
    raw = helpers.read_log_file(vm, f"{_LEDGER_DIR}/pfb_sync_status.json")
    assert item not in raw, f"dismiss POST left {item!r} in the raw ledger file"

    # Idempotent cleanup: closing an already-closed key is a documented no-op.
    _ledger_close(vm, "ip", item, "apply")


def test_dismiss_closes_multiple_entries_across_facilities_in_one_post(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """Two open entries (one ip, one dnsbl) dismissed in ONE POST: BOTH close --
    proves pfBlockerNG_clearfailed() loops every open entry, not just the first."""
    vm = smoke_vm
    ip_item = f"pfB_SmokeMulti_{uuid.uuid4().hex[:8]}_v4"
    ip_message = f"smoke: synthetic ip apply failure {uuid.uuid4().hex[:8]}"
    dnsbl_message = f"smoke: synthetic dnsbl apply failure {uuid.uuid4().hex[:8]}"
    _ledger_open(vm, "ip", ip_item, "apply", ip_message)
    _ledger_open(vm, "dnsbl", "dnsbl", "apply", dnsbl_message)

    before = _get_failed_body(webui)
    assert ip_message in before, "seeded ip entry's message missing before dismiss"
    assert dnsbl_message in before, "seeded dnsbl entry's message missing before dismiss"

    _dismiss(webui)

    after = _get_failed_body(webui)
    assert ip_message not in after, "dismiss POST left the ip-facility entry open"
    assert dnsbl_message not in after, "dismiss POST left the dnsbl-facility entry open"

    raw = helpers.read_log_file(vm, f"{_LEDGER_DIR}/pfb_sync_status.json")
    assert ip_item not in raw, f"dismiss POST left {ip_item!r} in the raw ledger file"
    assert "dnsbl" not in raw or dnsbl_message not in raw, "dismiss POST left the dnsbl message in the raw ledger file"

    _ledger_close(vm, "ip", ip_item, "apply")
    _ledger_close(vm, "dnsbl", "dnsbl", "apply")


def test_dismiss_still_flips_legacy_error_log_fail_marker(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
    clean_error_log: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """Regression guard: the pre-existing, UNTOUCHED
    ``sed -i 's/FAIL/Fail/g' error.log`` (feeds pfb_failures()'s separate
    skip-download-threshold mechanism) still fires alongside the new ledger close,
    on the SAME dismiss POST."""
    vm = smoke_vm
    alias = f"SmokeSedRegress{uuid.uuid4().hex[:8]}"
    line = _seed_error_log_fail_line(vm, alias)
    assert "FAIL" in line

    before = helpers.read_log_file(vm, _ERROR_LOG_PATH)
    assert "FAIL" in before, "seeded error.log line missing its FAIL marker before dismiss"

    _dismiss(webui)

    after = helpers.read_log_file(vm, _ERROR_LOG_PATH)
    assert alias in after, "seeded error.log line disappeared after dismiss (sed must edit in place, not truncate)"
    assert "FAIL" not in after, "dismiss POST did not flip FAIL -> Fail (the untouched sed regressed)"
    assert "Fail" in after, "dismiss POST did not produce the expected lowercase 'Fail' marker"


def test_dismiss_with_no_open_entries_is_a_safe_noop(
    webui: WebUI,
    clean_ledger: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """An empty ledger: dismiss is a safe no-op at the HTTP layer -- normal redirect
    response, no error, no login-page bounce."""
    before = _get_failed_body(webui)
    assert "MaxMind:" in before, "empty ledger must fall back to the MaxMind version line before dismiss"

    _dismiss(webui)

    after = _get_failed_body(webui)
    assert "MaxMind:" in after, "empty ledger must still fall back to the MaxMind version line after a no-op dismiss"


def test_dismiss_cross_site_post_does_not_clear_ledger(
    webui: WebUI,
    smoke_vm: helpers.SmokeVM,
    clean_ledger: None,
    php_error_log_guard: PhpErrorLogGuard,  # noqa: ARG001
) -> None:
    """issue #1050 (security, red case): a cross-site-shaped POST must NOT clear
    the ledger.

    ``$nocsrf=TRUE`` means csrf-magic never runs on this endpoint, so before this
    fix ANY POST (session-authenticated or auto-submitted from a completely
    unrelated site in the admin's browser) cleared every open ledger entry --
    ``pfb_widget_post_allowed()`` now rejects a POST carrying
    ``Sec-Fetch-Site: cross-site``. Reuses ``test_dismiss_closes_single_open_ip_entry``'s
    seed/assert shape, with the opposite outcome: the entry SURVIVES.
    """
    vm = smoke_vm
    item = f"pfB_SmokeCrossSite_{uuid.uuid4().hex[:8]}_v4"
    message = f"smoke: synthetic cross-site-blocked failure {uuid.uuid4().hex[:8]}"
    _ledger_open(vm, "ip", item, "apply", message)

    # BEFORE: the seeded open entry is visible, same as any other dismiss test.
    before = _get_failed_body(webui)
    assert message in before, "seeded ledger entry's message missing before the blocked dismiss"

    _dismiss(webui, headers={"Sec-Fetch-Site": "cross-site"})

    # AFTER: the entry must SURVIVE -- proving the gate, not just "dismiss is a no-op".
    after = _get_failed_body(webui)
    assert message in after, "cross-site POST cleared the ledger entry -- pfb_widget_post_allowed() gate failed"

    raw = helpers.read_log_file(vm, f"{_LEDGER_DIR}/pfb_sync_status.json")
    assert item in raw, f"cross-site POST removed {item!r} from the raw ledger file"

    _ledger_close(vm, "ip", item, "apply")
