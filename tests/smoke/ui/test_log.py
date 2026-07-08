"""Tier-B functional flows for the Log/File browser (pfblockerng_log.php).

Marker ``ui_e2e`` -- daily / on-demand, NOT in the default run nor the PR gate
(the whole ``tests/smoke`` tree is ``--ignore``d in the default
``python -m pytest``; this tier is run with
``pytest tests/smoke -m ui_e2e --override-ini="addopts="``).

What this file establishes: pfblockerng_log.php's three AJAX/POST actions act on
REAL files on the box, and its path validator (``pfb_validate_filepath``) is a
true gate. The oracle is therefore the on-box file state read over SSH (cat /
stat), NEVER the HTTP response body -- a 200 (or a ``|0|...|`` AJAX envelope) does
not prove the file was read/cleared; re-reading the file does.

The handler is NOT a Form save (no ``isset($_POST['save'])`` gate), so these POSTs
are crafted by hand exactly as the page's own JavaScript does: GET the page to
harvest the freshly-injected ``__csrf_magic`` token, then ``session.post`` the
minimal field set (``ajax``/``action``/``file`` for load; ``logFile``+``clear`` /
``logFile``+``download`` for the file actions). webui.post()'s form-scrape helper
is deliberately avoided -- it would re-submit the whole rendered form and append a
phantom ``save`` button, neither of which this handler reads.

Every flow is a TRUE transition test (CLAUDE.md transition-test rule):

* load -- seed a KNOWN line into the target log first (BEFORE-state asserted over
  SSH), then prove the AJAX body returns exactly that content; a rejecting path
  is proven by the ``|3|Invalid filename/path|`` envelope AND the unrelated file
  staying untouched.
* download -- seed a file, prove the download body + ``Content-Disposition`` carry
  it; the rejecting path is proven by the reject envelope and no body bytes.
* clear (the destructive branch worth the page) -- SEED non-empty content and
  assert it is non-empty (BEFORE), POST clear, then assert the AFTER on-box state
  for EACH of the handler's three distinct clear shapes:
    - a plain default log (``ip_block.log``)        -> ``unlink_if_exists``  -> ABSENT
    - ``py_error.log``                              -> ``ftruncate(0)``      -> EXISTS, size 0
    - ``dnsbl.log`` (the unbound re-touch special)  -> unlink + re-``touch`` -> EXISTS, size 0
  An invalid path is rejected with config/files untouched.

Each flow RESTORES the box (removes the seeded file / leaves the cleared file
gone) in a ``finally`` so a mid-test failure cannot poison the session-scoped VM
for the sibling flows.

THROWAWAY filenames, never the real production logs: ``pfb_validate_filepath()``
(pfblockerng_log.php:207-222) validates only the DIRECTORY (``pathinfo(...,
PATHINFO_DIRNAME)``), never the basename -- so ANY file directly under
``/var/log/pfblockerng`` passes. These flows used to seed/clear the box's REAL
``pfblockerng.log`` / ``error.log`` / ``ip_block.log`` / ``py_error.log`` /
``dnsbl.log`` directly, clobbering real content a live box would have
accumulated. Every target is now a unique, uuid-prefixed basename under the same
allowed directory instead (:func:`_throwaway_log`). The clear handler's
py_error.log/dnsbl.log special cases are themselves SUBSTRING matches
(``strpos($s_logfile, 'py_error.log')`` etc., :308,315-317), so a suffix-preserving
throwaway name (e.g. ``<uuid>-py_error.log``) still exercises the exact same
branch without ever touching the real file.
"""

from __future__ import annotations

import base64
import os
import subprocess
import uuid
from typing import TYPE_CHECKING

import pytest

from .. import helpers
from .webui import extract_csrf_token, looks_like_login_page

if TYPE_CHECKING:
    import requests

    from .webui import WebUI

pytestmark = pytest.mark.ui_e2e

# The page path and the absolute directory whose files the validator allows for
# the ``defaultlogs`` type. ``$pfb['logdir']`` == ``$g['varlog_path']/pfblockerng``
# == ``/var/log/pfblockerng`` (pfblockerng.inc:45, globals varlog_path=/var/log);
# the validator's allow-set is the set of every logtype's ``logdir`` (each with a
# trailing '/'), and ``pfb_validate_filepath`` matches a file iff its dirname '/'
# is in that set. ``defaultlogs`` is the only type whose files we both control and
# can clear, so every flow targets a file directly under this dir.
LOG_PAGE = "/pfblockerng/pfblockerng_log.php"
LOG_DIR = "/var/log/pfblockerng"

# A path the validator REJECTS: its dirname is not any logtype's logdir (no
# traversal escapes the allow-set). ``/etc/passwd`` is the canonical "would be a
# disaster if it leaked / got truncated" target -- the handler must refuse it.
EVIL_PATH = "/etc/passwd"


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


def _throwaway_log(basename_suffix: str) -> str:
    """A collision-proof ``LOG_DIR`` path that still ends in ``basename_suffix``.

    ``pfb_validate_filepath`` admits every file under ``LOG_DIR`` regardless of
    basename, and the clear handler's special-case branches key on a SUBSTRING
    match of the basename (``strpos($s_logfile, 'py_error.log')`` / ``'dnsbl.log'``
    / ...). Keeping the interesting suffix means a throwaway name still hits the
    SAME branch as the real production log -- without ever touching it.
    """
    return f"{LOG_DIR}/{uuid.uuid4().hex[:12]}-{basename_suffix}"


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
    """``act=load`` returns the actual on-box content of a validated log file.

    Transition: seed a known line (assert it landed on the box -- BEFORE), then
    prove the AJAX body decodes to exactly that content (code '0'), i.e. the
    handler read the real file. Oracle pairs the decoded envelope WITH an SSH cat
    so the body is proven to equal the file, not merely "some 200". Restored by
    removing the seed file in finally.
    """
    vm = smoke_vm
    target = _throwaway_log("pfblockerng.log")
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
    """``act=load`` returns bytes verbatim -- no HTML-entity substitution.

    Regression pin: the handler used to htmlspecialchars() each line before
    base64-encoding it, even though the only consumer is the #fileContent
    <textarea>'s JS ``.val()`` -- a plain-text sink that never decodes entities, so
    the escape only ever produced literal "&lt;"/"&gt;" text on screen. Seeds a
    line carrying every char htmlspecialchars would touch and asserts the decoded
    body is byte-identical to the on-box file, not an escaped variant.
    """
    vm = smoke_vm
    target = _throwaway_log("pfblockerng.log")
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
    """``act=load`` must not add a SECOND escape layer atop already-escaped-looking text.

    Regression pin for a defect that existed when ``pfb_validate_log_line()`` (ADR-48,
    pfblockerng.inc) still htmlspecialchars()'d reject-line fields at WRITE time: load()'s
    OWN htmlspecialchars() ran a SECOND time over that already-escaped text, turning "&lt;"
    into "&amp;lt;". pfb_validate_log_line() no longer escapes (a later follow-up dropped
    that call for the same reason load() dropped its own -- the sole renderer is a textarea
    that never parses HTML), so this fixture is now synthetic rather than something the
    current write path actually produces; it's kept as a general invariant pin: load() must
    never re-escape text that merely LOOKS pre-escaped, regardless of its source.
    """
    vm = smoke_vm
    target = _throwaway_log("error.log")
    marker = helpers.unique_domain("dblesc")
    # Synthetic: shaped like pfb_validate_log_line's OLD write-time-escaped output (a REJECT
    # line whose detail field originally contained '<' '>' '&') -- see docstring above.
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
    """``act=load`` of a path outside every logtype dir is refused (no traversal).

    The validator (`pfb_validate_filepath`) only admits files whose dirname is one
    of the logtype logdirs, so ``/etc/passwd`` is rejected with the ``|3|`` envelope.
    Transition rigor: snapshot ``/etc/passwd`` BEFORE and assert it is byte-for-byte
    UNCHANGED after -- a load is read-only, but proving the file is untouched also
    proves the reject path never opened it.
    """
    vm = smoke_vm
    before = _cat(vm, EVIL_PATH)
    assert before, "could not read /etc/passwd to snapshot the before-state"

    token = _csrf(webui)
    resp = _post_load(webui, token, EVIL_PATH)
    assert not looks_like_login_page(resp.text), "load POST returned the login form (session lost)"
    # Oracle for a reject: the |3| invalid-path envelope, NOT a |0| success.
    assert resp.text.startswith("|3|"), f"rejected path did not return the |3| envelope: {resp.text!r}"
    assert "Invalid filename/path" in resp.text, f"reject envelope missing the message: {resp.text!r}"
    # The protected file is untouched by the refused read.
    assert _cat(vm, EVIL_PATH) == before, "/etc/passwd changed after a rejected load (must be untouched)"


def test_load_reports_failure_for_nonexistent_file(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """``act=load`` of a validator-admitted path that has no file must NOT report success.

    Regression pin (issue #978): the ``file_exists`` false branch used to print
    code ``"0"`` -- the same code the page JS (``loadComplete()``) treats as
    success -- even though the info text says the file is missing. Picks a
    throwaway path under the allowed dir and never creates it.
    """
    vm = smoke_vm
    target = _throwaway_log("missing.log")
    assert not _exists(vm, target), "throwaway target unexpectedly exists before the test"

    token = _csrf(webui)
    resp = _post_load(webui, token, target)
    assert not looks_like_login_page(resp.text), "load POST returned the login form (session lost)"
    code, _ = _decode_load_body(resp.text)
    assert code != "0", f"missing-file load reported success: envelope={resp.text!r}"
    assert "Log file does not exist" in resp.text, f"reject envelope missing the message: {resp.text!r}"


def test_load_reports_failure_for_unopenable_socket_node(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """``act=load`` of a validator-admitted UNIX-domain socket node must NOT report success.

    Regression pin (issue #978, defect B -- final-else ``fopen()``-failure branch,
    code ``|0|`` -> ``|2|``): ``file_exists()`` is TRUE for a socket special file, so
    control reaches the ``fopen()`` branch. Opening a socket node via the generic
    file-open API is refused by the VFS (a directory target does NOT discriminate
    this on this platform -- FreeBSD's ``fopen($dir, 'r')`` succeeds, unlike Linux --
    but a socket node is refused everywhere, POSIX-wide, independent of that
    divergence). This lands in the final ``else``, which used to print code "0"
    (success) despite the message saying the read failed.
    """
    vm = smoke_vm
    target = _throwaway_log("asock")
    # Bind+listen a UNIX-domain socket at `target` via FreeBSD base nc(1) (`-lU`),
    # detached exactly like the update-hook launcher (test_smoke_hooks.py): all
    # three std streams redirected away from the SSH channel so the call returns
    # at once, `echo $!` captures the PID for teardown.
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
    """``act=load`` of a file whose entire content is the single char ``"0"`` reports 1 line.

    Regression pin (issue #978): PHP's ``empty("0") === TRUE`` quirk made the
    handler treat a one-line file containing only ``"0"`` as if it had read no
    data, reporting "Total Lines: 0" even though ``$linecnt`` (already computed
    by the read loop) was 1. No trailing newline -- that is the exact byte
    sequence the quirk requires.
    """
    vm = smoke_vm
    target = _throwaway_log("zero-content.log")
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
    """``act=load`` of a genuinely empty (0-byte) file still reports "Total Lines: 0".

    Regression GUARD (issue #978): pins the branch the fix must NOT disturb --
    a real empty file (``$linecnt == 0``, no lines read at all) is a distinct
    case from the literal-``"0"``-content file above (``$linecnt == 1``), and
    must still land in the "Total Lines: 0" branch after the fix. This is the
    behaviour-preserving side of the ``if ($linecnt > 0)`` condition, so unlike
    its siblings above it is expected to pass on both pre-fix and post-fix code.
    """
    vm = smoke_vm
    target = _throwaway_log("empty.log")
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
    """Download of a validated file streams its bytes with an attachment header.

    Transition: seed a known file (assert on-box BEFORE), then prove the download
    response body equals the file content and the ``Content-Disposition`` names the
    basename as an attachment. Restored in finally.
    """
    vm = smoke_vm
    target = _throwaway_log("error.log")
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


def test_download_rejects_path_outside_allowed_dirs(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Download of a path outside the allowed dirs is refused, source untouched.

    The same validator gates download. ``/etc/passwd`` -> the ``|3|Invalid
    filename/path|IA==|`` reject envelope (NOT the file's bytes) -- code '3' is the
    handler's dedicated reject code (issue #991: this branch used to reuse '0', the
    success code, for the rejection). Transition rigor: snapshot before and assert
    the file is byte-for-byte unchanged after.
    """
    vm = smoke_vm
    before = _cat(vm, EVIL_PATH)
    assert before, "could not read /etc/passwd to snapshot the before-state"

    token = _csrf(webui)
    resp = _post_download(webui, token, EVIL_PATH)
    assert not looks_like_login_page(resp.text), "download POST returned the login form (session lost)"
    # The reject envelope -- emphatically NOT the file's contents (no root: line).
    assert "Invalid filename/path" in resp.text, f"reject envelope missing the message: {resp.text!r}"
    assert "root:" not in resp.text, f"download leaked /etc/passwd content: {resp.text!r}"
    code = resp.text.split("|")[1] if resp.text.startswith("|") else ""
    assert code == "3", f"reject envelope reused a non-reject code (issue #991): {resp.text!r}"
    assert _cat(vm, EVIL_PATH) == before, "/etc/passwd changed after a rejected download (must be untouched)"


# --------------------------------------------------------------------------- #
# act=clear -- the destructive branch (three distinct shapes from source)
# --------------------------------------------------------------------------- #


def test_clear_plain_log_unlinks_file(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Clearing a plain default log UNLINKS it (``unlink_if_exists``) -> ABSENT.

    Source: the clear branch's ``else`` calls ``unlink_if_exists($s_logfile)`` for
    any file that is not py_error.log; ip_block.log is not one of the unbound
    re-touch special cases, so it is simply removed.

    Transition: seed non-empty content and assert it EXISTS + non-empty (BEFORE),
    POST clear, assert the file is now ABSENT (AFTER). Restore: ensure it's gone.
    """
    vm = smoke_vm
    target = _throwaway_log("ip_block.log")
    _seed_file(vm, target, f"pfb-ui-clear-plain-{helpers.unique_domain('clr')}\n")
    try:
        # BEFORE: present and non-empty.
        assert _exists(vm, target), "seeded file missing before clear"
        assert _size(vm, target) > 0, "seeded file unexpectedly empty before clear"

        token = _csrf(webui)
        resp = _post_clear(webui, token, target)
        assert not looks_like_login_page(resp.text), "clear POST returned the login form (session lost)"
        # AFTER (oracle): unlink_if_exists removed it.
        assert not _exists(vm, target), "plain log still present after clear (expected unlink)"
    finally:
        _rm(vm, target)


def test_clear_py_error_truncates_in_place(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Clearing py_error.log TRUNCATES it (keeps the file) -> EXISTS, size 0.

    Source: ``strpos($s_logfile, 'py_error.log') !== FALSE`` takes the
    fopen('r+')+ftruncate(0) branch (the comment: the python file pointer must not
    be lost), so the file must REMAIN, emptied -- NOT be unlinked. This is the
    branch that distinguishes py_error.log from every other log.

    Transition: seed non-empty (BEFORE), clear, assert it STILL EXISTS and is now
    size 0 (AFTER) -- proving truncate, not unlink. Restore: remove the file.
    """
    vm = smoke_vm
    target = _throwaway_log("py_error.log")
    _seed_file(vm, target, f"pfb-ui-clear-py-{helpers.unique_domain('py')}\n")
    try:
        assert _exists(vm, target), "seeded py_error.log missing before clear"
        assert _size(vm, target) > 0, "seeded py_error.log unexpectedly empty before clear"

        token = _csrf(webui)
        resp = _post_clear(webui, token, target)
        assert not looks_like_login_page(resp.text), "clear POST returned the login form (session lost)"
        # AFTER (oracle): truncated in place -- still exists, now empty.
        assert _exists(vm, target), "py_error.log was unlinked (expected ftruncate -> file kept)"
        assert _size(vm, target) == 0, f"py_error.log not truncated to 0 after clear (size={_size(vm, target)})"
    finally:
        _rm(vm, target)


def test_clear_dnsbl_log_unlinks_then_retouches_empty(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Clearing dnsbl.log unlinks THEN re-touches it -> EXISTS, size 0.

    Source: the non-py_error branch unlinks, then for dnsbl.log / unified.log /
    dns_reply.log it ``touch``es the file and chowns it to ``unbound`` (these logs
    are written by the chrooted unbound python module, so the file must exist with
    unbound ownership). Net observable: file present and EMPTY after clear (unlike
    a plain log, which stays absent).

    Transition: seed non-empty (BEFORE), clear, assert it EXISTS and size 0
    (AFTER) -- distinguishing this special case from the plain-unlink case.
    Restore: remove the file.
    """
    vm = smoke_vm
    target = _throwaway_log("dnsbl.log")
    _seed_file(vm, target, f"pfb-ui-clear-dnsbl-{helpers.unique_domain('dns')}\n")
    try:
        assert _exists(vm, target), "seeded dnsbl.log missing before clear"
        assert _size(vm, target) > 0, "seeded dnsbl.log unexpectedly empty before clear"

        token = _csrf(webui)
        resp = _post_clear(webui, token, target)
        assert not looks_like_login_page(resp.text), "clear POST returned the login form (session lost)"
        # AFTER (oracle): unlinked then re-touched -- present and empty.
        assert _exists(vm, target), "dnsbl.log absent after clear (expected re-touch)"
        assert _size(vm, target) == 0, f"dnsbl.log not empty after clear (size={_size(vm, target)})"
    finally:
        _rm(vm, target)


def test_clear_rejects_path_outside_allowed_dirs(webui: WebUI, smoke_vm: helpers.SmokeVM) -> None:
    """Clear of a path outside the allowed dirs is refused -- the file is UNTOUCHED.

    The most safety-critical branch: an unvalidated clear would unlink/truncate an
    arbitrary file. The validator must refuse ``/etc/passwd`` with the
    ``|3|Invalid filename/path|IA==|`` envelope and NOT remove or empty it -- code
    '3' is the handler's dedicated reject code (issue #991: this branch used to
    reuse '0', the success code, for the rejection).

    Transition rigor: snapshot the file's content + size BEFORE, POST the rejected
    clear, then assert it still EXISTS, is the SAME size, and the SAME bytes.
    """
    vm = smoke_vm
    before = _cat(vm, EVIL_PATH)
    assert before, "could not read /etc/passwd to snapshot the before-state"
    before_size = _size(vm, EVIL_PATH)
    assert before_size > 0, "/etc/passwd unexpectedly empty before the rejected clear"

    token = _csrf(webui)
    resp = _post_clear(webui, token, EVIL_PATH)
    assert not looks_like_login_page(resp.text), "clear POST returned the login form (session lost)"
    assert "Invalid filename/path" in resp.text, f"reject envelope missing the message: {resp.text!r}"
    code = resp.text.split("|")[1] if resp.text.startswith("|") else ""
    assert code == "3", f"reject envelope reused a non-reject code (issue #991): {resp.text!r}"
    # AFTER (oracle): the protected file is wholly intact -- not unlinked, not truncated.
    assert _exists(vm, EVIL_PATH), "/etc/passwd was removed by a rejected clear (validator failed!)"
    assert _size(vm, EVIL_PATH) == before_size, "/etc/passwd was truncated by a rejected clear (validator failed!)"
    assert _cat(vm, EVIL_PATH) == before, "/etc/passwd content changed after a rejected clear"
