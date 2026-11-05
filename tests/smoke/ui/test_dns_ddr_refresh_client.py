"""Hermetic execution of the real page script; backend/wire proof belongs to live DDR tests."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

PAGE = Path(__file__).resolve().parents[3] / "src/usr/local/www/pfblockerng/pfblockerng_dns.php"
BODY = "pfb-dns-status-ddr_panel-body"


@pytest.mark.parametrize("failure", ["timeout", "http", "redirect", "json", "missing", "duplicate"])
def test_periodic_ddr_refresh_replaces_only_results_and_recovers(failure: str) -> None:
    """Given a dirty collapsed form, refresh succeeds, invalidates failures and later recovers."""
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", PAGE.read_text(), re.DOTALL))
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        try:
            page.clock.install()
            page.set_content(
                '<input id="dirty" value="saved"><div id="pfb-dns-status-ddr">'
                f'<div id="{BODY}" class="panel-body collapse"><b class="text-success">old green</b></div></div>'
            )
            page.evaluate(
                """() => {
                    window.events = [];
                    window.calls = [];
                    window.mode = 'success';
                    window.fetch = (url, options) => {
                        calls.push({url, cache: options.cache, credentials: options.credentials,
                            signal: options.signal});
                        if (mode === 'timeout') return new Promise((resolve, reject) => {
                            window.finishPending = reject;
                        });
                        const body = '<div id="pfb-dns-status-ddr"><div id="pfb-dns-status-ddr_panel-body">'
                            + '<b class="text-success">new green</b></div></div>';
                        return Promise.resolve({ok: mode !== 'http', redirected: mode === 'redirect',
                            headers: new Headers({'Content-Type': 'application/json'}),
                            json: () => mode === 'json' ? Promise.reject(new Error('invalid JSON'))
                                : Promise.resolve({html: mode === 'missing' ? '<form>login</form>'
                                    : mode === 'duplicate' ? body + body : body})});
                    };
                }"""
            )
            page.add_script_tag(content=scripts + "\n;")
            page.evaluate(
                "() => { events.forEach(fn => fn()); document.querySelector('#dirty').value = 'unsaved'; "
                "window.originalBody = document.getElementById('pfb-dns-status-ddr_panel-body'); }"
            )
            page.clock.run_for(30000)
            assert page.locator(f"#{BODY}").inner_text() == "new green", "30s timer did not refresh DDR results"
            assert page.evaluate("calls.length") == 1
            assert page.evaluate("calls[0].url") == "pfblockerng_dns.php?ajax=ddr"
            assert page.evaluate("calls[0].cache") == "no-store"
            assert page.evaluate("calls[0].credentials") == "same-origin"
            page.evaluate("mode = " + repr(failure))
            page.clock.run_for(30000)
            if failure == "timeout":
                page.clock.run_for(15000)
                assert page.evaluate("calls[1].signal.aborted"), "request was not aborted after 15s"
                page.clock.run_for(45000)
                assert page.evaluate("calls.length") == 2, "overlapping request while fetch remains pending"
                page.evaluate("finishPending(new Error('aborted'))")
            page.wait_for_function("document.querySelector('[role=status]') !== null")
            assert "unavailable" in page.locator(f"#{BODY}").inner_text().lower()
            assert page.locator(f"#{BODY} .text-success").count() == 0, "failed refresh retained stale green"
            assert page.locator("form").count() == 0, "login/malformed HTML was injected"
            page.evaluate("mode = 'success'")
            page.clock.run_for(30000)
            assert page.locator(f"#{BODY}").inner_text() == "new green"
            assert page.locator("#dirty").input_value() == "unsaved"
            assert page.evaluate("originalBody === document.getElementById('pfb-dns-status-ddr_panel-body')")
            assert page.locator(f"#{BODY}").get_attribute("class") == "panel-body collapse"
            count = page.evaluate("calls.length")
            page.evaluate("window.dispatchEvent(new Event('pagehide'))")
            page.clock.run_for(60000)
            assert page.evaluate("calls.length") == count, "timer continued after page unload"
        finally:
            browser.close()


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_ddr_ajax_dispatch_exits_before_seeding_and_releases_session(method: str) -> None:
    """Execute the actual startup block with sentinel backend functions, not a simulated handler."""
    startup = PAGE.read_text().partition("$pconfig = array();")[0]
    startup = re.sub(r"require_once\([^\n]+\);", "", startup).removeprefix("<?php")
    support = r"""<?php
session_start();
function pfb_global() {}
function pfb_dns_ddr_status() {
    if (func_num_args() !== 0) throw new Exception('refresh argument');
    return ['sentinel' => 1];
}
function pfb_dns_ddr_status_panel($status) { return session_status() === PHP_SESSION_ACTIVE ? 'locked' : 'released'; }
function pfb_dns_proxy_seed_values() { echo 'SEED_WRITE_PATH'; return []; }
$_GET = ['ajax' => 'ddr'];
$_SERVER['REQUEST_METHOD'] = __METHOD__;
register_shutdown_function(function() { fwrite(STDERR, 'HTTP=' . http_response_code()); });
""".replace("__METHOD__", repr(method))
    result = subprocess.run(["php"], input=support + startup, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    if method == "GET":
        assert result.stdout == '{"html":"released"}', result.stdout
    else:
        assert result.stdout == "", result.stdout
        assert "HTTP=405" in result.stderr, result.stderr
    assert "SEED_WRITE_PATH" not in result.stdout, result.stdout
