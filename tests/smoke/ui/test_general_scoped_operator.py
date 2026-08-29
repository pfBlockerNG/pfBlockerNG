"""Live-VM Tier B pins for the #1895 write-authorization model (issue #1904).

Follow-up to #1895 / PR #1903. The write-authorization model itself is pinned by
hermetic PHPUnit tests (``tests/php``), but the PR #1903 blocking finding was a
*composition* break only a real box exhibits end-to-end: real ``priv.inc`` /
``cmp_page_matches()`` / a real webConfigurator session for a scoped operator, and
the real CLI include chain where ``isAllowedPage()`` is undefined. Neither is
reachable from a PHPUnit shim/double (see ``docs/misc/config-gateway.md``).

Two independent regressions are pinned here:

1. **Scoped-operator General-page save** (the PR #1903 persona): a webConfigurator
   user holding ONLY ``page-firewall-pfblockerng`` (no Package Manager privilege)
   saves the General settings page, changing one UNRELATED field, while a
   different registered field (``pfb_software_check``, ``write_priv`` =
   ``pkg_mgr_installed.php``) sits at a seeded NON-DEFAULT value. The save must
   succeed and must NOT touch ``pfb_software_check`` -- ``PfbConfig::writeSection()``'s
   delta-aware pass-through carve-out (the #1895 addendum) is what makes that true;
   a regression that made the gate re-strict (present-key = authorization event,
   the pre-addendum shape) would 500 this exact save. The companion GET of the
   Software page proves the SAME operator has no supported UI path to CHANGE that
   field (issue #485's secondary ``isAllowedPage('pkg_mgr_installed.php')`` gate) --
   forced through :func:`tests.smoke.ui.test_render_smoke.software_panel_forced`
   so the page's FIRST gate (build provenance, default-hidden on this offline
   sideload deploy) does not mask the SECOND (privilege) gate this test exists to
   pin; probed live -- see the scoped-user creation mechanics below.

2. **CLI/no-session gateway contract**: on the REAL include chain
   ``pfblockerng.php``'s CLI verbs use (read from ``pfblockerng.sh``'s
   invocations: ``util.inc``, ``functions.inc``, ``pkg-utils.inc``,
   ``globals.inc``, ``services.inc``, then the two pfBlockerNG includes -- no
   ``priv.inc``/``auth.inc`` anywhere in it), ``PfbConfig::write()`` on a
   registered key throws ``RuntimeException`` fail-closed (confirmed live:
   ``function_exists('isAllowedPage')`` is FALSE on this chain, the same as the
   bare ``pfSsh.php`` bootstrap -- both arms of the CAUTION in the issue collapse
   to "undefined", not "defined-but-false"), while ``PfbConfig::writeSystem()``,
   the explicit system-caller escape hatch, persists the canonical token.

Scoped-user creation mechanics were confirmed against a live pfSense box before
writing the assertions below (never guessed): ``/etc/inc/auth.inc``
(``local_user_set_password()`` / ``local_user_set()``), ``/etc/inc/priv.inc``
(``isAllowedPage()`` / ``getAllowedPages()`` / ``getPrivPages()`` reading
``$priv_list[$priv]['match']``), ``/etc/inc/authgui.inc`` (the framework-level
``isAllowedPage($_SERVER['REQUEST_URI'])`` gate), and a real
``system/user`` config.xml block (the password field is ``<bcrypt-hash>``, not
``<password>``). A user created this way and logged in over the real CSRF form
was independently confirmed to authenticate and to be denied a core admin page
(``system_usermanager.php``) with the framework's "No page assigned" refusal,
and allowed onto every page ``page-firewall-pfblockerng`` matches (e.g.
``wizard.php?xml=pfblockerng_wizard.xml``) -- i.e. the priv-routing mechanism
:func:`_create_scoped_user` relies on is real, not assumed.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render
from .test_render_smoke import software_panel_forced
from .webui import WebUI, looks_like_login_page

if TYPE_CHECKING:
    import requests

pytestmark = pytest.mark.ui_e2e

GENERAL_PAGE = "/pfblockerng/pfblockerng_general.php"
SOFTWARE_PAGE = "/pfblockerng/pfblockerng_software.php"
GENERAL_MARKERS = ("General Settings",)
# Mirrors test_render_smoke.py's _SOFTWARE_PANEL_MARKER: the page's positive-render
# marker, used here to confirm the provenance sentinel is really ON before trusting
# that the scoped operator's refusal is the PRIVILEGE gate, not the provenance gate.
SOFTWARE_PANEL_MARKER = "pfb-software-panel"
GENERAL_SAVE_TIMEOUT = 300.0

GEN_CFG_SECTION = "installedpackages/pfblockerng/config/0"
SOFTWARE_CHECK_CFG = f"{GEN_CFG_SECTION}/pfb_software_check"
MARGIN_CFG = f"{GEN_CFG_SECTION}/pfb_log_trim_margin_pct"
PFB_KEEP_CFG = f"{GEN_CFG_SECTION}/pfb_keep"

# --------------------------------------------------------------------------- #
# Scoped-user creation/deletion via pfSense's OWN auth.inc functions (confirmed
# live against /etc/inc/auth.inc + /usr/local/www/system_usermanager.php -- see
# the module docstring). __USERNAME__/__PASSWORD__ are substituted with
# helpers._php_str()-quoted literals (never raw-interpolated) before use.
# --------------------------------------------------------------------------- #

_CREATE_USER_PHP = """
require_once('auth.inc');
$uid = (int) config_get_path('system/nextuid', 2000);
config_set_path('system/nextuid', $uid + 1);
$user = array(
    'name' => __USERNAME__,
    'descr' => 'pfBlockerNG issue #1904 scoped operator (smoke, ephemeral)',
    'scope' => 'user',
    'uid' => $uid,
    'authorizedkeys' => '',
    'ipsecpsk' => '',
    'priv' => array('page-firewall-pfblockerng'),
);
config_set_path('system/user/', $user);
$users = config_get_path('system/user', array());
$idx = null;
foreach ($users as $i => $u) {
    if ($u['name'] === __USERNAME__) {
        $idx = $i;
        break;
    }
}
if ($idx === null) {
    echo 'PFB1904:CREATE:ERR:NOTFOUND';
} else {
    $item = array('idx' => $idx, 'item' => $users[$idx]);
    local_user_set_password($item, __PASSWORD__);
    $stored = config_get_path('system/user/' . $idx);
    local_user_set($stored);
    write_config('[pfBlockerNG] smoke #1904: add scoped operator');
    echo 'PFB1904:CREATE:OK';
}
"""

_DELETE_USER_PHP = """
require_once('auth.inc');
$users = config_get_path('system/user', array());
$found = false;
foreach ($users as $i => $u) {
    if ($u['name'] === __USERNAME__) {
        local_user_del($u);
        unset($users[$i]);
        $found = true;
        break;
    }
}
if ($found) {
    config_set_path('system/user', array_values($users));
}
// Restore system/nextuid to its pre-test value regardless of $found -- _create_scoped_user
// always incremented it, so the whole-config digest (_ui_pfb_isolation) must see it back at
// baseline too, or every run pays that fixture's ~15-30s full restore for a single stray counter.
config_set_path('system/nextuid', (int) __NEXTUID__);
write_config('[pfBlockerNG] smoke #1904: remove scoped operator');
echo $found ? 'PFB1904:DELETE:OK' : 'PFB1904:DELETE:MISSING';
"""

# The real CLI-verb include chain (read from pfblockerng.sh's `php ... pfblockerng.php
# <verb>` invocations, then confirmed against pfblockerng.php's own top-of-file
# require_once list): util.inc, functions.inc, pkg-utils.inc, globals.inc,
# services.inc, then the two pfBlockerNG includes. Notably absent: priv.inc / auth.inc --
# isAllowedPage() is genuinely undefined on this chain (probed live, see docstring).
_CLI_GATEWAY_PHP = """
require_once('util.inc');
require_once('functions.inc');
require_once('pkg-utils.inc');
require_once('globals.inc');
require_once('services.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');
require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');

$defined = function_exists('isAllowedPage') ? 'YES' : 'NO';
echo "PFB1904:ISALLOWEDPAGE_DEFINED:{$defined}\\n";

$before = config_get_path('installedpackages/pfblockerng/config/0/pfb_keep', NULL);

$caught = 'NO_EXCEPTION';
try {
    PfbConfig::write('gen/pfb_keep', 'off');
} catch (\\RuntimeException $e) {
    $caught = 'RuntimeException';
} catch (\\Throwable $e) {
    $caught = 'OTHER:' . get_class($e);
}
echo "PFB1904:WRITE_CAUGHT:{$caught}\\n";

$afterWrite = config_get_path('installedpackages/pfblockerng/config/0/pfb_keep', NULL);
echo 'PFB1904:AFTER_WRITE_UNCHANGED:' . (($afterWrite === $before) ? 'YES' : 'NO') . "\\n";

PfbConfig::writeSystem('gen/pfb_keep', 'off');
write_config('[pfBlockerNG] smoke #1904: CLI gateway probe writeSystem off');
$stored = (string) config_get_path('installedpackages/pfblockerng/config/0/pfb_keep', '');
echo "PFB1904:WRITESYSTEM_STORED:{$stored}\\n";

PfbConfig::writeSystem('gen/pfb_keep', $before);
write_config('[pfBlockerNG] smoke #1904: CLI gateway probe writeSystem restore');
echo 'PFB1904:RESTORED:OK';
"""


def _extract_sentinel(out: str, prefix: str) -> str:
    """Return the text after ``prefix`` on the (first) line starting with it.

    pfSsh.php always exits 0 (see :func:`tests.smoke.helpers.php_eval`'s docstring),
    so a sentinel actually being present in stdout is the only proof a snippet ran
    to completion -- a bare non-zero-returncode check is not enough.
    """
    for line in out.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    raise AssertionError(f"sentinel {prefix!r} not found in pfSsh.php output: {out!r}")


def _create_scoped_user(vm: helpers.SmokeVM, username: str, password: str) -> None:
    """Create a webConfigurator user holding ONLY ``page-firewall-pfblockerng``.

    Mirrors ``system_usermanager.php``'s own save path (``local_user_set_password()``
    then ``local_user_set()``), confirmed against ``/etc/inc/auth.inc`` on a live box
    (see the module docstring) -- not the raw ``config_set_path`` shortcut alone,
    since ``local_user_set()`` is what actually provisions the OS-level account
    (``pw useradd``) real login exercises, mirroring a real admin-created user.
    """
    snippet = _CREATE_USER_PHP.replace("__USERNAME__", helpers._php_str(username)).replace(
        "__PASSWORD__", helpers._php_str(password)
    )
    result = helpers.php_eval(vm, snippet, timeout=90.0)
    out = result.stdout
    if result.returncode != 0 or "PFB1904:CREATE:OK" not in out:
        raise RuntimeError(
            f"_create_scoped_user({username!r}) failed: rc={result.returncode} stdout={out!r} stderr={result.stderr!r}"
        )


def _delete_scoped_user(vm: helpers.SmokeVM, username: str, orig_nextuid: str) -> None:
    """Remove a user created by :func:`_create_scoped_user` -- config AND the OS account.

    ``local_user_del()`` is the ``pw userdel`` counterpart to ``local_user_set()``;
    restoring ``/conf/config.xml`` alone (the session isolation fixture's generic
    safety net) never touches the OS-level account, so this is the ONLY thing that
    actually removes it. ``orig_nextuid`` is the pre-test ``system/nextuid`` value
    (captured by the caller before :func:`_create_scoped_user` ran) -- restoring it
    keeps the whole-config digest clean so ``_ui_pfb_isolation`` doesn't pay its
    ~15-30s full restore for a single stray counter increment.
    """
    snippet = _DELETE_USER_PHP.replace("__USERNAME__", helpers._php_str(username)).replace(
        "__NEXTUID__", helpers._php_str(orig_nextuid)
    )
    result = helpers.php_eval(vm, snippet, timeout=90.0)
    out = result.stdout
    if result.returncode != 0 or ("PFB1904:DELETE:OK" not in out and "PFB1904:DELETE:MISSING" not in out):
        raise RuntimeError(
            f"_delete_scoped_user({username!r}) failed: rc={result.returncode} stdout={out!r} stderr={result.stderr!r}"
        )


def _set_config_value(vm: helpers.SmokeVM, path: str, value: str) -> None:
    """Directly write one scalar config.xml value + persist (bypasses PfbConfig).

    Used for setup/teardown ONLY (seeding ``pfb_software_check`` and restoring the
    fields this test touches) -- a raw ``config_set_path`` is the correct tool
    here precisely because it is NOT the gated path under test (PfbConfig's own
    write gate is what the test body exercises through the real HTTP save).
    """
    snippet = (
        f"config_set_path({helpers._php_str(path)}, {helpers._php_str(value)});\n"
        "write_config('[pfBlockerNG] smoke #1904: seed/restore config value');\n"
        "echo 'PFB1904:SET:OK';"
    )
    result = helpers.php_eval(vm, snippet, timeout=60.0)
    if result.returncode != 0 or "PFB1904:SET:OK" not in result.stdout:
        raise RuntimeError(
            f"_set_config_value({path!r}, {value!r}) failed: rc={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def test_scoped_operator_general_save_pass_through_and_software_refused(
    smoke_vm: helpers.SmokeVM,
    deployed_vm: helpers.SmokeVM,
    webgui_protocol: str,
    webui: WebUI,
) -> None:
    """A scoped operator's General save leaves the Package-Manager-gated field untouched.

    Scenario: the #1903 blocking-bug persona saves an unrelated General field while
    ``pfb_software_check`` sits at a seeded non-default value.

      Given a webConfigurator user holding ONLY ``page-firewall-pfblockerng`` (no
        Package Manager privilege), and ``pfb_software_check`` stored as legacy ``'off'``
        (the pass-through cell; non-default so a "reset to default" bug would also
        be visible),

      When that operator logs in, GETs the General page (200 + the "General
        Settings" marker -- proves the priv routes), then POSTs a save changing
        ONLY ``pfb_log_trim_margin_pct`` (an unrelated page-owned field),

      Then the save succeeds (200, still authenticated, no new gated PHP
        diagnostic), the changed field persists, and ``pfb_software_check`` is
        canonical ``''`` -- the delta-aware pass-through carve-out treated the
        unchanged field as a non-event rather than asserting a privilege this
        operator does not hold.

      And, with the page's FIRST/provenance gate forced open, an ADMIN GET of the
        Software page first confirms the sentinel actually took (200 + the
        ``pfb-software-panel`` marker) -- the provenance gate
        (``pfblockerng_software.php:44``) and the #485 privilege gate (``:59``)
        share the exact same 302-to-``/index.php`` refusal shape, so without this
        admin check a provenance-gate false-refusal would look identical to the
        privilege refusal this test exists to pin. THEN, as the SAME scoped
        operator, GETting the Software page is refused with the page's own shape:
        a 302 to ``/index.php`` (issue #485's
        ``isAllowedPage('pkg_mgr_installed.php')`` secondary gate) -- this operator
        has no supported UI path to CHANGE ``pfb_software_check``.

    Failability (each assertion names the regression that flips it):
      * render-oracle GET assertion -- a presence-based (not delta-aware) gate
        regression makes ``isAllowedPage()`` even get CALLED for a page-scoped
        priv this operator holds, which would still pass; the real regression
        this pins is caught by the SAVE assertions below, not this GET.
      * save status/session assertions -- a delta-aware-gate regression (the
        pre-#1895-addendum shape) makes ``writeSection()`` assert
        ``pkg_mgr_installed.php`` for the PRESENT-but-unchanged
        ``pfb_software_check`` key -> ``PfbConfig`` throws ``RuntimeException`` ->
        the save 500s -> ``post_resp.status_code == 200`` fails.
      * ``pfb_log_trim_margin_pct`` persisted -- a regression that made the save silently
        no-op (e.g. an over-broad early return) leaves the stored value at its
        PRE-save baseline -> the equality assertion fails.
      * PhpErrorLogGuard -- a regression that let an uncaught exception reach the
        page (rather than a clean redirect) logs a PHP Fatal/Uncaught line ->
        ``assert_no_growth()`` fails.
      * admin Software-page render-oracle assertion -- if the provenance sentinel
        did not actually take, this GET fails (or lacks the ``pfb-software-panel``
        marker), which would otherwise let a provenance-gate false-refusal masquerade
        as the privilege refusal below.
      * Software-page refusal shape -- removing/loosening the #485 secondary
        ``isAllowedPage('pkg_mgr_installed.php')`` check makes this GET return 200
        (or a different redirect target) instead of a 302 to ``/index.php``.
    """
    vm = smoke_vm
    username = f"pfbop{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex

    orig_software_state = helpers.config_get_state(vm, SOFTWARE_CHECK_CFG)
    orig_margin_state = helpers.config_get_state(vm, MARGIN_CFG)
    orig_margin = orig_margin_state[1] if orig_margin_state[0] else ""
    orig_nextuid = helpers.config_get(vm, "system/nextuid")

    user_created = False
    try:
        _create_scoped_user(vm, username, password)
        user_created = True

        # Seed the pass-through cell to a deliberately NON-DEFAULT value (the
        # registry default is 'on').
        _set_config_value(vm, SOFTWARE_CHECK_CFG, "off")
        assert helpers.config_get(vm, SOFTWARE_CHECK_CFG) == "off", "setup: pfb_software_check seed did not take"

        https = webgui_protocol == "https"
        scoped = WebUI(
            host=deployed_vm.host,
            port=deployed_vm.web_port,
            username=username,
            password=password,
            scheme="https" if https else "http",
            verify=not https,
        )
        scoped.login()

        guard = PhpErrorLogGuard(vm)
        guard.snapshot()

        get_resp = scoped.get(GENERAL_PAGE)
        render = evaluate_render(GENERAL_PAGE, get_resp.status_code, get_resp.text, GENERAL_MARKERS)
        assert render.ok, f"scoped operator GET {GENERAL_PAGE} failed the render oracle: {render.detail}"

        # Flip an unrelated General-page field the operator is allowed to write.
        new_margin = "25" if orig_margin != "25" else "20"
        post_resp = scoped.post(GENERAL_PAGE, {"pfb_log_trim_margin_pct": new_margin}, timeout=GENERAL_SAVE_TIMEOUT)
        assert post_resp.status_code == 200, (
            f"scoped operator General save -> HTTP {post_resp.status_code} (expected 200 after the "
            "post-save redirect back to the General page)"
        )
        assert not looks_like_login_page(post_resp.text), (
            "General POST bounced to the login form -- the scoped-operator session was lost"
        )

        guard.assert_no_growth()

        assert helpers.config_get(vm, MARGIN_CFG) == new_margin, (
            "the scoped operator's save of the unrelated log-trim margin did not persist"
        )
        assert helpers.config_get(vm, SOFTWARE_CHECK_CFG) == "", (
            "pfb_software_check did not canonicalise legacy 'off' during an unrelated General save -- "
            "the writeSection() adapter round-trip or delta-aware privilege carve-out regressed"
        )

        # Companion: force the page's FIRST (provenance) gate open so its SECOND
        # (privilege) gate is what the scoped-operator GET below actually exercises.
        # The provenance gate (pfblockerng_software.php:44) and the #485 privilege
        # gate (:59) share the identical 302-to-/index.php refusal shape, so first
        # confirm -- as the ADMIN -- that the sentinel really took (200 + the
        # 'pfb-software-panel' marker): only then does the scoped operator's 302
        # unambiguously prove the PRIVILEGE gate, not a still-hidden page.
        with software_panel_forced(vm, "on"):
            admin_resp = webui.get(SOFTWARE_PAGE)
            admin_render = evaluate_render(
                SOFTWARE_PAGE, admin_resp.status_code, admin_resp.text, (SOFTWARE_PANEL_MARKER,)
            )
            assert admin_render.ok, (
                f"admin GET {SOFTWARE_PAGE} with provenance forced ON failed the render oracle: "
                f"{admin_render.detail} -- can't trust the scoped operator's refusal below is the "
                "PRIVILEGE gate unless the provenance sentinel is confirmed ON first"
            )

            sw_resp: requests.Response = scoped.get(SOFTWARE_PAGE, allow_redirects=False)
        assert sw_resp.status_code == 302, (
            f"scoped operator GET {SOFTWARE_PAGE} -> HTTP {sw_resp.status_code} (expected the #485 "
            "secondary isAllowedPage('pkg_mgr_installed.php') gate's 302 refusal)"
        )
        assert sw_resp.headers.get("Location") == "/index.php", (
            f"unexpected Software-page refusal redirect target: {sw_resp.headers.get('Location')!r}"
        )
    finally:
        # Field restores run BEFORE the user delete: a raised delete must never skip
        # putting the box's config back the way it was.
        helpers.config_restore_state(vm, SOFTWARE_CHECK_CFG, orig_software_state)
        helpers.config_restore_state(vm, MARGIN_CFG, orig_margin_state)
        if user_created:
            _delete_scoped_user(vm, username, orig_nextuid)


def test_cli_gateway_write_fails_closed_writesystem_succeeds(
    smoke_vm: helpers.SmokeVM,
    deployed_vm: helpers.SmokeVM,  # noqa: ARG001 -- forces pfBlockerNG installed on-box
) -> None:
    """The real CLI include chain fails PfbConfig::write() closed; writeSystem() succeeds.

    Scenario: the #1895 CLI-trap acceptance, executed on the REAL include chain
    ``pfblockerng.php`` CLI verbs use (not a stand-in).

      Given that chain loaded via ``pfSsh.php`` (probed live: ``isAllowedPage()``
        is genuinely UNDEFINED there, matching the bare pfSsh.php bootstrap --
        see the module docstring for which CAUTION arm this box exercises),

      When ``PfbConfig::write('gen/pfb_keep', 'off')`` is called,

      Then it throws ``RuntimeException`` (fail-closed) and the stored value is
        UNCHANGED; and ``PfbConfig::writeSystem('gen/pfb_keep', 'off')`` -- the
        explicit system-caller escape hatch -- succeeds and persists the
        canonical empty token.

    Failability:
      * ``ISALLOWEDPAGE_DEFINED`` -- documents which CAUTION arm this box hits;
        not itself a regression pin (the RuntimeException assertion below holds
        under EITHER arm), but a change here means the test's own docstring
        claim about the probed fact would go stale.
      * ``WRITE_CAUGHT == 'RuntimeException'`` -- a regression that made
        ``assertWriteAllowed()`` pass when ``isAllowedPage`` is undefined (e.g.
        inverting the ``!function_exists(...) || !isAllowedPage(...)`` guard)
        flips this to ``'NO_EXCEPTION'``.
      * ``WRITESYSTEM_STORED == ''`` -- a regression that made
        ``writeSystem()`` ALSO gate on ``isAllowedPage()`` (collapsing the
        escape hatch into ``write()``) makes this call throw instead of storing,
        and the sentinel is never reached / the snippet aborts.
    """
    vm = smoke_vm
    orig_state = helpers.config_get_state(vm, PFB_KEEP_CFG)
    try:
        result = helpers.php_eval(vm, _CLI_GATEWAY_PHP, timeout=90.0)
        assert result.returncode == 0, (
            f"pfSsh.php CLI-gateway probe failed: rc={result.returncode} stderr={result.stderr!r} "
            f"stdout={result.stdout!r}"
        )
        out = result.stdout

        defined = _extract_sentinel(out, "PFB1904:ISALLOWEDPAGE_DEFINED:")
        assert defined == "NO", (
            f"isAllowedPage() is unexpectedly DEFINED on the real CLI include chain ({defined!r}) -- "
            "PfbConfig::write() still fails closed either way (defined-but-FALSE also throws), but "
            "record which arm this box actually hits (see module docstring)"
        )

        caught = _extract_sentinel(out, "PFB1904:WRITE_CAUGHT:")
        assert caught == "RuntimeException", (
            f"PfbConfig::write() on the CLI include chain did not fail closed (caught: {caught!r})"
        )

        unchanged = _extract_sentinel(out, "PFB1904:AFTER_WRITE_UNCHANGED:")
        assert unchanged == "YES", "PfbConfig::write() mutated pfb_keep despite throwing RuntimeException"

        stored = _extract_sentinel(out, "PFB1904:WRITESYSTEM_STORED:")
        assert stored == "", f"PfbConfig::writeSystem() did not persist canonical empty storage: {stored!r}"

        # Confirms writeSystem() restored the exact pre-test value, including absence.
        _extract_sentinel(out, "PFB1904:RESTORED:")
    finally:
        # Safety net: guarantee pfb_keep is back to its pre-test raw value even if
        # the snippet above raised before reaching its own writeSystem() restore.
        helpers.config_restore_state(vm, PFB_KEEP_CFG, orig_state)
