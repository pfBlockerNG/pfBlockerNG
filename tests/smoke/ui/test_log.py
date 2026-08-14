"""Tier-B functional flows for the Log/File browser (pfblockerng_log.php).

Marker ``ui_e2e`` runs on demand. The handler's load/download requests use the
inactive listed ``wizard.log`` as test-owned scratch; every scratch file is
removed in ``finally``. Clear-shape coverage for ``py_error.log`` and
``dnsbl.log`` is hermetic in ``LogValidateFilepathTest.php`` so active logs are
never modified by this live suite. Security rejects remain read-only checks for
package files, ``/etc/passwd``, and the legitimate ``dnsbl_psl`` download.
"""

from __future__ import annotations

import base64
import os
import subprocess
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    import requests

    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

# ``defaultlogs`` authorizes exact listed basenames; wizard.log is inactive and
# reserved as this suite's only test-owned scratch file.
LOG_PAGE = "/pfblockerng/pfblockerng_log.php"
LOG_DIR = "/var/log/pfblockerng"

# A path outside every logtype tuple; the handler must refuse it.
EVIL_PATH = "/etc/passwd"

# The validator binds the pkg-dir logtypes to exact extension patterns and their
# capability flags, so package source must reject while dnsbl_psl still downloads.
PKG_DIR = "/usr/local/pkg/pfblockerng"
PKG_SOURCE = f"{PKG_DIR}/pfblockerng.inc"
DNSBL_PSL_FILE = f"{PKG_DIR}/dnsbl_psl"


def _csrf(webui: WebUI) -> str:
    """GET the log page and return its freshly-injected ``__csrf_magic`` token.

    csrf-magic rewrites the token per render, so it must be re-harvested for each
    manual POST (cf. webui.post's re-GET). Asserts the GET is authenticated so a
    dropped session fails loudly here, not as an opaque CSRF rejection later.
    """
    resp = webui.get(LOG_PAGE)
    assert not looks_like_login_page(resp.text), "log page GET returned the login form (session lost)"
    return extract_csrf_token(resp.text)


def _post_load(webui: WebUI, token: str, file_path: str, *, timeout: float = 60.0) -> requests.Response:
    """POST the page's ``act=load`` AJAX exactly as its JS does (+ the CSRF token).

    The handler keys on ``$_REQUEST['ajax']`` being set and ``action == 'load'``,
    reading the target from ``$_REQUEST['file']`` (NOT ``logFile``). Returns the
    raw response so the caller can parse the ``|code|info|base64|`` envelope.
    """
    return webui.session.post(
        webui.url(LOG_PAGE),
        data={"__csrf_magic": token, "ajax": "ajax", "action": "load", "file": file_path},
        verify=webui._verify,
        timeout=timeout,
    )


def _post_clear(webui: WebUI, token: str, log_file: str, *, timeout: float = 120.0) -> requests.Response:
    """POST the download/clear handler in CLEAR mode (``logFile`` + ``clear``).

    The handler gates on ``logFile`` non-empty AND (isset(download) || isset(clear)),
    then takes the clear branch on a TRUTHY ``clear`` -- so the value must be a
    non-empty string (the page's JS sends ``'clear'``).
    """
    return webui.session.post(
        webui.url(LOG_PAGE),
        data={"__csrf_magic": token, "logFile": log_file, "clear": "clear"},
        verify=webui._verify,
        timeout=timeout,
    )


def _post_download(webui: WebUI, token: str, log_file: str, *, timeout: float = 60.0) -> requests.Response:
    """POST the download/clear handler in DOWNLOAD mode (``logFile`` + ``download``).

    ``clear`` is sent EMPTY so the ``if ($pconfig['clear'])`` branch is falsy and
    control reaches the ``elseif ($pconfig['download'])`` download branch.
    """
    return webui.session.post(
        webui.url(LOG_PAGE),
        data={"__csrf_magic": token, "logFile": log_file, "download": "download", "clear": ""},
        verify=webui._verify,
        timeout=timeout,
    )


def _seed_file(vm: helpers.SmokeVM, path: str, contents: str) -> None:
    """Write ``contents`` to ``path`` on the guest via a direct ``tee`` argv.

    Direct argv (never ``ssh sh -c``, which double-parses under the root tcsh
    login shell). The log dir is created by a pfBlockerNG reload, but POST-INSTALL
    may not have run one yet, so ``mkdir -p`` it first.
    """
    mk = vm.ssh("/bin/mkdir", "-p", LOG_DIR)
    assert mk.returncode == 0, f"mkdir {LOG_DIR} failed: {mk.stderr!r}"
    res = subprocess.run(
        vm.ssh_argv("tee", path),
        input=contents,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert res.returncode == 0, f"seed {path} failed: {res.stderr!r}"


def _cat(vm: helpers.SmokeVM, path: str) -> str:
    """Return the on-box file contents (the load/download oracle), '' if absent."""
    res = vm.ssh("/bin/cat", path)
    return res.stdout if res.returncode == 0 else ""


def _exists(vm: helpers.SmokeVM, path: str) -> bool:
    """True iff ``path`` exists on the guest (stat rc; the clear oracle)."""
    return vm.ssh("/usr/bin/stat", "-f", "%z", path).returncode == 0


def _size(vm: helpers.SmokeVM, path: str) -> int:
    """Byte size of ``path`` on the guest via ``stat -f %z`` (assumes it exists)."""
    res = vm.ssh("/usr/bin/stat", "-f", "%z", path)
    assert res.returncode == 0, f"stat {path} failed (absent?): {res.stderr!r}"
    return int(res.stdout.strip())


def _rm(vm: helpers.SmokeVM, path: str) -> None:
    """Best-effort delete (teardown); never raises so a finally can't mask a fault."""
    vm.ssh("/bin/rm", "-f", path)


def _scratch_log(vm: helpers.SmokeVM) -> str:
    """Return the inactive listed wizard.log path, starting absent."""
    path = f"{LOG_DIR}/wizard.log"
    _rm(vm, path)
    return path


def _decode_load_body(body: str) -> tuple[str, str]:
    """Parse the ``|code|info|base64|`` AJAX envelope -> ``(code, decoded_text)``.

    The handler prints ``|<code>|<info>|<base64-of-content>|``; on the load path
    code '0' is success and the third field is base64 of the file's raw bytes
    (verbatim, no HTML-escaping). Mirrors the page's JS (``responseText.split('|')``
    then ``atob``).
    """
    parts = body.split("|")
    # parts[0] is the leading '' before the first '|'; [1]=code, [2]=info, [3]=b64.
    code = parts[1] if len(parts) > 1 else ""
    b64 = parts[3] if len(parts) > 3 else ""
    try:
        decoded = base64.b64decode(b64).decode("utf-8", "replace")
    except (ValueError, IndexError):
        decoded = ""
    return code, decoded


# --------------------------------------------------------------------------- #
# act=load
# --------------------------------------------------------------------------- #


def test_load_returns_real_file_content(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """``act=load`` returns the exact content of listed inactive wizard.log."""
    vm = smoke_vm
    target = _scratch_log(vm)
    marker = f"pfb-ui-load-{helpers.unique_domain('load')}"
    expected = f"{marker}\n"
    _seed_file(vm, target, expected)
    try:
        # BEFORE: the seed is the file's content on the box.
        assert _cat(vm, target) == expected, "seed line not present on the box before load"

        token = _csrf(webui)
        resp = _post_load(webui, token, target)
        assert not looks_like_login_page(resp.text), "load POST returned the login form (session lost)"
        code, decoded = _decode_load_body(resp.text)
        assert code == "0", f"load did not report success: envelope={resp.text!r}"
        # AFTER (oracle): the returned content equals the file's actual content.
        assert decoded == _cat(vm, target), (
            f"load body content {decoded!r} != on-box file {_cat(vm, target)!r} (handler must return the real file)"
        )
        assert marker in decoded, f"seeded marker missing from the loaded content: {decoded!r}"
    finally:
        _rm(vm, target)


def test_load_does_not_html_escape_content(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """``act=load`` preserves characters that need HTML escaping in markup."""
    vm = smoke_vm
    target = _scratch_log(vm)
    marker = helpers.unique_domain("esc")
    expected = f"<{marker}> & \"quoted\" 'single'\n"
    _seed_file(vm, target, expected)
    try:
        assert _cat(vm, target) == expected, "seed line not present on the box before load"

        token = _csrf(webui)
        resp = _post_load(webui, token, target)
        assert not looks_like_login_page(resp.text), "load POST returned the login form (session lost)"
        code, decoded = _decode_load_body(resp.text)
        assert code == "0", f"load did not report success: envelope={resp.text!r}"
        assert decoded == expected, (
            f"load body {decoded!r} != raw seeded content {expected!r} "
            "(handler must not HTML-escape -- the textarea sink never decodes entities)"
        )
        assert "&lt;" not in decoded and "&gt;" not in decoded and "&amp;" not in decoded, (
            f"load body still HTML-escaped: {decoded!r}"
        )
    finally:
        _rm(vm, target)


def test_load_does_not_double_escape_write_time_escaped_lines(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """``act=load`` does not add an escape layer to already escaped-looking text."""
    vm = smoke_vm
    target = _scratch_log(vm)
    marker = helpers.unique_domain("dblesc")
    expected = f"pfb_validate: REJECT feed=x stage=y reason=z detected=&lt;{marker}&gt; &amp; done\n"
    _seed_file(vm, target, expected)
    try:
        assert _cat(vm, target) == expected, "seed line not present on the box before load"

        token = _csrf(webui)
        resp = _post_load(webui, token, target)
        assert not looks_like_login_page(resp.text), "load POST returned the login form (session lost)"
        code, decoded = _decode_load_body(resp.text)
        assert code == "0", f"load did not report success: envelope={resp.text!r}"
        assert decoded == expected, (
            f"load body {decoded!r} != raw seeded content {expected!r} "
            "(handler re-escaped an already-escaped line -- double escape regression)"
        )
        assert "&amp;lt;" not in decoded and "&amp;amp;" not in decoded, (
            f"load body double-escaped the write-time-escaped line: {decoded!r}"
        )
    finally:
        _rm(vm, target)


def test_load_rejects_path_outside_allowed_dirs(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """``act=load`` rejects a path outside every logtype's authorized tuple."""
    vm = smoke_vm
    before = _cat(vm, EVIL_PATH)
    assert before, "could not read /etc/passwd before the rejected load"

    token = _csrf(webui)
    resp = _post_load(webui, token, EVIL_PATH)
    assert not looks_like_login_page(resp.text), "load POST returned the login form (session lost)"
    assert resp.text.startswith("|3|"), f"rejected path did not return the |3| envelope: {resp.text!r}"
    assert "Invalid filename/path" in resp.text, f"reject envelope missing the message: {resp.text!r}"
    assert _cat(vm, EVIL_PATH) == before, "/etc/passwd changed after a rejected load (must be untouched)"


def test_load_reports_failure_for_nonexistent_file(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A listed but absent wizard.log reports failure rather than success."""
    vm = smoke_vm
    target = _scratch_log(vm)
    try:
        assert not _exists(vm, target), "listed target unexpectedly present after clear (precondition)"

        token = _csrf(webui)
        resp = _post_load(webui, token, target)
        assert not looks_like_login_page(resp.text), "load POST returned the login form (session lost)"
        code, _ = _decode_load_body(resp.text)
        assert code != "0", f"missing-file load reported success: envelope={resp.text!r}"
        assert "Log file does not exist" in resp.text, f"reject envelope missing the message: {resp.text!r}"
    finally:
        _rm(vm, target)


def test_load_reports_failure_for_unopenable_socket_node(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A listed UNIX socket node reports a read failure rather than success."""
    vm = smoke_vm
    target = _scratch_log(vm)
    launch = vm.ssh(f"nohup /usr/bin/nc -lU {target} >/dev/null 2>&1 </dev/null & echo $!")
    assert launch.returncode == 0, f"failed to launch the nc -lU listener: {launch.stderr!r}"
    pid = launch.stdout.strip()
    assert pid.isdigit(), f"did not capture a PID for the nc -lU listener: {launch.stdout!r}"
    try:
        assert _exists(vm, target), "socket node was not created by nc -lU before load"

        token = _csrf(webui)
        resp = _post_load(webui, token, target)
        assert not looks_like_login_page(resp.text), "load POST returned the login form (session lost)"
        code, _ = _decode_load_body(resp.text)
        assert code != "0", f"socket-node load reported success: envelope={resp.text!r}"
        assert "Failed to read log file" in resp.text, f"reject envelope missing the message: {resp.text!r}"
    finally:
        vm.ssh("kill", pid)
        _rm(vm, target)


def test_load_reports_correct_line_count_for_literal_zero_content(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """A one-character ``0`` file reports one loaded line."""
    vm = smoke_vm
    target = _scratch_log(vm)
    _seed_file(vm, target, "0")
    try:
        assert _cat(vm, target) == "0", "seed content not present on the box before load"

        token = _csrf(webui)
        resp = _post_load(webui, token, target)
        assert not looks_like_login_page(resp.text), "load POST returned the login form (session lost)"
        code, decoded = _decode_load_body(resp.text)
        assert code == "0", f"load of literal-zero content did not report success: envelope={resp.text!r}"
        assert decoded == "0", f"load body {decoded!r} != raw seeded content '0'"
        assert "Total Lines: 1" in resp.text, f"expected 'Total Lines: 1', got: {resp.text!r}"
    finally:
        _rm(vm, target)


def test_load_reports_zero_lines_for_empty_file(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """An empty listed file reports zero loaded lines."""
    vm = smoke_vm
    target = _scratch_log(vm)
    _seed_file(vm, target, "")
    try:
        assert _cat(vm, target) == "", "seed content not empty on the box before load"

        token = _csrf(webui)
        resp = _post_load(webui, token, target)
        assert not looks_like_login_page(resp.text), "load POST returned the login form (session lost)"
        code, _ = _decode_load_body(resp.text)
        assert code == "0", f"load of empty file did not report success: envelope={resp.text!r}"
        assert "Total Lines: 0" in resp.text, f"expected 'Total Lines: 0', got: {resp.text!r}"
    finally:
        _rm(vm, target)


# --------------------------------------------------------------------------- #
# act=download
# --------------------------------------------------------------------------- #


def test_download_streams_file_with_attachment_header(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Download of listed inactive wizard.log streams bytes with its basename."""
    vm = smoke_vm
    target = _scratch_log(vm)
    payload = f"pfb-ui-download-{helpers.unique_domain('dl')}\n"
    _seed_file(vm, target, payload)
    try:
        assert _cat(vm, target) == payload, "seed not present on the box before download"

        token = _csrf(webui)
        resp = _post_download(webui, token, target)
        assert not looks_like_login_page(resp.text), "download POST returned the login form (session lost)"
        # AFTER (oracle): the streamed body equals the on-box file content.
        assert resp.text == _cat(vm, target), f"download body {resp.text!r} != on-box file {_cat(vm, target)!r}"
        # The attachment header names the file's OWN basename (source: header() call).
        disp = resp.headers.get("Content-Disposition", "")
        expected_name = os.path.basename(target)
        assert f'attachment; filename="{expected_name}"' in disp, f"unexpected Content-Disposition: {disp!r}"
        # The file is read-only on download -- it must remain on the box, unchanged.
        assert _cat(vm, target) == payload, "download altered the source file (must be read-only)"
    finally:
        _rm(vm, target)


def test_download_rejects_package_source_in_whitelisted_dir(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Package source is rejected even though its directory has listed downloads."""
    vm = smoke_vm
    before = _cat(vm, PKG_SOURCE)
    assert before, "could not read pfblockerng.inc before the rejected download"

    token = _csrf(webui)
    resp = _post_download(webui, token, PKG_SOURCE)
    assert not looks_like_login_page(resp.text), "download POST returned the login form (session lost)"
    assert "Invalid filename/path" in resp.text, f"reject envelope missing the message: {resp.text!r}"
    code, _ = _decode_load_body(resp.text)
    assert code == "3", f"package source download was not rejected with code 3: {resp.text!r}"
    # The source itself must not have leaked into the response body.
    assert "<?php" not in resp.text, f"download leaked pfblockerng.inc source: {resp.text[:200]!r}"
    assert _cat(vm, PKG_SOURCE) == before, "pfblockerng.inc changed after a rejected download (must be untouched)"


def test_clear_rejects_package_source_in_whitelisted_dir(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Package source cannot be cleared by a logtype that does not list it."""
    vm = smoke_vm
    before = _cat(vm, PKG_SOURCE)
    assert before, "could not read pfblockerng.inc before the rejected clear"
    before_size = _size(vm, PKG_SOURCE)
    assert before_size > 0, "pfblockerng.inc unexpectedly empty before the rejected clear"

    token = _csrf(webui)
    resp = _post_clear(webui, token, PKG_SOURCE)
    assert not looks_like_login_page(resp.text), "clear POST returned the login form (session lost)"
    assert "Invalid filename/path" in resp.text, f"reject envelope missing the message: {resp.text!r}"
    code, _ = _decode_load_body(resp.text)
    assert code == "3", f"package source clear was not rejected with code 3: {resp.text!r}"
    # AFTER (oracle): the package source is wholly intact -- not unlinked, not truncated.
    assert _exists(vm, PKG_SOURCE), "pfblockerng.inc was removed by a rejected clear (validator failed!)"
    assert _size(vm, PKG_SOURCE) == before_size, "pfblockerng.inc was truncated by a rejected clear (validator failed!)"
    assert _cat(vm, PKG_SOURCE) == before, "pfblockerng.inc content changed after a rejected clear"


def test_clear_rejects_dnsbl_psl_whose_logtype_forbids_clear(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The listed dnsbl_psl file remains read-only because its type forbids clear."""
    vm = smoke_vm
    before = _cat(vm, DNSBL_PSL_FILE)
    assert before, "could not read the dnsbl_psl file before the rejected clear"
    before_size = _size(vm, DNSBL_PSL_FILE)

    token = _csrf(webui)
    resp = _post_clear(webui, token, DNSBL_PSL_FILE)
    assert not looks_like_login_page(resp.text), "clear POST returned the login form (session lost)"
    assert "Invalid filename/path" in resp.text, f"reject envelope missing the message: {resp.text!r}"
    code, _ = _decode_load_body(resp.text)
    assert code == "3", f"dnsbl_psl clear was not rejected with code 3: {resp.text!r}"
    assert _exists(vm, DNSBL_PSL_FILE), "dnsbl_psl file removed by a clear its logtype forbids (validator failed!)"
    assert _size(vm, DNSBL_PSL_FILE) == before_size, "dnsbl_psl file truncated by a forbidden clear (validator failed!)"
    assert _cat(vm, DNSBL_PSL_FILE) == before, "dnsbl_psl file content changed after a clear its logtype forbids"


def test_download_allows_dnsbl_psl_file_its_logtype_owns(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """The listed dnsbl_psl file remains available through its own download type."""
    vm = smoke_vm
    before = _cat(vm, DNSBL_PSL_FILE)
    assert before, "could not read the dnsbl_psl file before download"

    token = _csrf(webui)
    resp = _post_download(webui, token, DNSBL_PSL_FILE)
    assert not looks_like_login_page(resp.text), "download POST returned the login form (session lost)"
    assert "Invalid filename/path" not in resp.text, f"legit dnsbl_psl download was rejected: {resp.text!r}"
    assert resp.text == _cat(vm, DNSBL_PSL_FILE), (
        "download body != on-box dnsbl_psl file (handler must stream the real file)"
    )
    disp = resp.headers.get("Content-Disposition", "")
    assert 'attachment; filename="dnsbl_psl"' in disp, f"unexpected Content-Disposition: {disp!r}"
    assert _cat(vm, DNSBL_PSL_FILE) == before, "download altered the dnsbl_psl file (must be read-only)"


def test_download_rejects_path_outside_allowed_dirs(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Download rejects a path outside every logtype tuple and leaves it unchanged."""
    vm = smoke_vm
    before = _cat(vm, EVIL_PATH)
    assert before, "could not read /etc/passwd before the rejected download"

    token = _csrf(webui)
    resp = _post_download(webui, token, EVIL_PATH)
    assert not looks_like_login_page(resp.text), "download POST returned the login form (session lost)"
    assert "Invalid filename/path" in resp.text, f"reject envelope missing the message: {resp.text!r}"
    assert "root:" not in resp.text, f"download leaked /etc/passwd content: {resp.text!r}"
    code, _ = _decode_load_body(resp.text)
    assert code == "3", f"reject envelope reused a non-reject code (issue #991): {resp.text!r}"
    assert _cat(vm, EVIL_PATH) == before, "/etc/passwd changed after a rejected download (must be untouched)"


# --------------------------------------------------------------------------- #
# act=clear -- plain inactive scratch file; other shapes are hermetic PHPUnit
# --------------------------------------------------------------------------- #


def test_clear_plain_log_unlinks_file(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Clearing inactive listed wizard.log removes the file."""
    vm = smoke_vm
    target = _scratch_log(vm)
    _seed_file(vm, target, f"pfb-ui-clear-plain-{helpers.unique_domain('clr')}\n")
    try:
        assert _exists(vm, target), "seeded file missing before clear"
        assert _size(vm, target) > 0, "seeded file unexpectedly empty before clear"

        token = _csrf(webui)
        resp = _post_clear(webui, token, target)
        assert not looks_like_login_page(resp.text), "clear POST returned the login form (session lost)"
        assert not _exists(vm, target), "plain log still present after clear (expected unlink)"
    finally:
        _rm(vm, target)


def test_clear_absent_scratch_log_is_noop(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Clearing absent inactive wizard.log returns without creating it."""
    vm = smoke_vm
    target = _scratch_log(vm)
    try:
        assert not _exists(vm, target), "wizard.log unexpectedly present before absent clear"

        token = _csrf(webui)
        resp = _post_clear(webui, token, target)
        assert not looks_like_login_page(resp.text), "clear POST returned the login form (session lost)"
        assert resp.status_code == 200, f"clear of absent wizard.log did not return 200: {resp.status_code}"
        assert not _exists(vm, target), "clearing absent wizard.log unexpectedly created the file"
    finally:
        _rm(vm, target)


def test_clear_rejects_path_outside_allowed_dirs(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Clear rejects a path outside every logtype tuple and leaves it unchanged."""
    vm = smoke_vm
    before = _cat(vm, EVIL_PATH)
    assert before, "could not read /etc/passwd before the rejected clear"
    before_size = _size(vm, EVIL_PATH)
    assert before_size > 0, "/etc/passwd unexpectedly empty before the rejected clear"

    token = _csrf(webui)
    resp = _post_clear(webui, token, EVIL_PATH)
    assert not looks_like_login_page(resp.text), "clear POST returned the login form (session lost)"
    assert "Invalid filename/path" in resp.text, f"reject envelope missing the message: {resp.text!r}"
    code, _ = _decode_load_body(resp.text)
    assert code == "3", f"reject envelope reused a non-reject code (issue #991): {resp.text!r}"
    assert _exists(vm, EVIL_PATH), "/etc/passwd was removed by a rejected clear (validator failed!)"
    assert _size(vm, EVIL_PATH) == before_size, "/etc/passwd was truncated by a rejected clear (validator failed!)"
    assert _cat(vm, EVIL_PATH) == before, "/etc/passwd content changed after a rejected clear"
