"""Tier-A ``ui_render`` coverage for #3453's Sync page receiver and sender panels.

Both panels are built from this node's own state files (root-only JSON under the package db dir), so each test
writes the record it needs on the guest, reads the page through the real web session and puts the guest's own files
back. Hostile text is stored on purpose: the page must escape it, and it must never turn a refusal, an unknown
outcome or a returned call into "accepted" wording.

  Scenario: a changed receive whose apply failed, with ignored paths and findings (each of the three scopes)
    Then  the receiver panel says "accepted with changes", the apply row says "failed: <reason>" on its own row,
          and every stored value is on the page escaped and nowhere raw

  Scenario: sender attempts of every kind
    Then  the sender panel says "sent, acceptance unconfirmed" / "failed: <error>" / "handed to pfSense HA sync",
          and none of supported/accepted/applied/drifting/"in sync" -- while the receiver panel on the same page
          does say accepted, so the absence is not a blind regex

  Scenario: a refused receive, no receive record, a record of the wrong types, no usable attempts
    Then  refused is never accepted wording, an old peer shows no receiver panel, wrong types render clean

The page offers no peer check control.
"""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import contextmanager
from html import unescape
from html.parser import HTMLParser
from typing import TYPE_CHECKING, Any

import pytest

from .. import helpers
from .render_oracle import PhpErrorLogGuard, evaluate_render

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ..conftest import SmokeVM
    from .webui import WebUI

pytestmark = pytest.mark.ui_render

SYNC_PAGE = "/pfblockerng/pfblockerng_sync.php"
PAGE_MARKER = "XMLRPC Sync Settings"
SCOPE_PATH = "installedpackages/pfblockerngsync/config/0/syncscope"

RECEIVE, FINDINGS, SEND = "pfb_sync_receive.json", "pfb_sync_findings.json", "pfb_sync_send.json"
STATE_FILES = (RECEIVE, FINDINGS, SEND)

# Hostile text a stored value may carry; the page must show each only escaped.
SCRIPT = '<script>alert("pfb3453")</script>'
ATTR = '"onmouseover="x'
AMP = "x&amp;y"
LONG = "L" * 300
HOSTILE = f"{SCRIPT} {ATTR} {AMP}"

T = 1_700_000_000
INCOMING = hashlib.sha256(b"pfb3453 incoming").hexdigest()
ACCEPTED = hashlib.sha256(b"pfb3453 accepted").hexdigest()

TIME = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"
DASH = "(?:—|&mdash;|&#8212;)"
# The packet rule for the sender panel: whole words, case-insensitive; "unsupported" and "acceptance" stay legal.
BANNED = re.compile(r"\b(?:supported|accepted|applied|drifting)\b|\bin\s+sync\b", re.IGNORECASE)
ACCEPTED_WORD = re.compile(r"\baccepted\b", re.IGNORECASE)
SENDER_FOOTER = (
    "A returned call does not show what the peer did with it; the receiving firewall's own Sync page shows its receive."
)

IGNORED_PATH = f"installedpackages/a/{SCRIPT}"
APPLY_REASON = f"apply broke: {HOSTILE}"
FINDING_SCRIPT = f"DNSBL forced off {SCRIPT}"
FINDING_LONG = f"{AMP} {LONG}"
SEND_ERROR = f"connect failed {HOSTILE}"

CHANGED: dict[str, Any] = {
    "accepted_digest": ACCEPTED,
    "last": {
        "time": T,
        "outcome": "changed",
        "incoming_digest": INCOMING,
        "accepted_digest": ACCEPTED,
        "ignored": [IGNORED_PATH, "installedpackages/b/plain", 7],
        "ignored_count": 3,
    },
    "apply": {"time": T + 60, "opened": T, "outcome": "failed", "reason": APPLY_REASON},
}
FINDINGS_DOC: dict[str, Any] = {"time": T, "findings": [FINDING_SCRIPT, FINDING_LONG, ["not", "a", "string"]]}
# Three attempts that must render, then four the reader must drop (each carries its own marker).
VALID_ATTEMPTS: list[dict[str, Any]] = [
    {"target": "192.0.2.10:443", "time": T, "outcome": "sent", "digest": INCOMING},
    {"target": f"192.0.2.11{ATTR}:443", "time": T, "outcome": "failed", "error": SEND_ERROR, "digest": ["x"]},
    {"target": "pfSense HA sync", "time": T, "outcome": "handed"},
]
DROPPED_ATTEMPTS: list[dict[str, Any]] = [
    {"target": "DROPPED-accepted", "time": T, "outcome": "accepted"},
    {"target": "DROPPED-markup", "time": T, "outcome": "<b>x</b>"},
    {"target": "DROPPED-time", "time": "soon", "outcome": "sent"},
    {"target": ["DROPPED-array"], "time": T, "outcome": "sent"},
]
DROPPED_MARKERS = ("DROPPED-accepted", "DROPPED-markup", "DROPPED-time", "DROPPED-array")
SEND_DOC: dict[str, Any] = {"time": T, "attempts": VALID_ATTEMPTS + DROPPED_ATTEMPTS}


def php_escape(text: str) -> str:
    """``htmlspecialchars($text, ENT_QUOTES)`` as PHP renders it (``'`` becomes ``&#039;``)."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def plain(markup: str) -> str:
    """Visible text of a fragment: tags dropped, whitespace collapsed, entities left as sent."""
    return " ".join(re.sub(r"<[^>]*>", " ", markup).split())


_DIV_TAG = re.compile(r"<(/?)div\b[^>]*>", re.IGNORECASE)


def panel(html: str, panel_id: str) -> str | None:
    """The panel's own markup, from its opening ``div`` to the matching close; ``None`` when it is absent."""
    at = html.find(f'id="{panel_id}"')
    if at == -1:
        return None
    start = html.rfind("<div", 0, at)
    depth = 0
    for tag in _DIV_TAG.finditer(html, start):
        depth += -1 if tag.group(1) else 1
        if depth == 0:
            return html[start : tag.end()]
    raise AssertionError(f"panel {panel_id!r} never closes")


def receiver_cell(receiver: str, key: str) -> str:
    """The value cell of the receiver panel's ``pfb-sync-receiver-<key>`` row, as sent."""
    row = re.search(rf'<tr id="pfb-sync-receiver-{key}"[^>]*>(?:(?!</tr>).)*?<td[^>]*>(.*?)</td>', receiver, re.DOTALL)
    assert row, f"receiver panel has no row {key!r}"
    return row.group(1)


def assert_row(receiver: str, key: str, pattern: str) -> str:
    """The receiver row's visible text fully matches the regex ``pattern``; returns that text."""
    text = plain(receiver_cell(receiver, key))
    assert re.fullmatch(pattern, text), f"receiver row {key!r}: expected /{pattern}/, got {text!r}"
    return text


def sender_rows(sender: str) -> list[list[str]]:
    """Visible text of each attempt row's cells in the sender panel (the header row has no ``td``)."""
    rows = []
    for row in re.findall(r"<tr\b.*?</tr>", sender, re.DOTALL):
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", row, re.DOTALL)
        if cells:
            rows.append([plain(cell) for cell in cells])
    return rows


class _Controls(HTMLParser):
    """Visible text of every button and link, plus the value of every submit/button input."""

    def __init__(self) -> None:
        super().__init__()
        self.found: list[str] = []
        self._open: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("a", "button"):
            self._open.append("")
        elif tag == "input" and (dict(attrs).get("type") or "").lower() in ("submit", "button", "reset"):
            self.found.append(dict(attrs).get("value") or "")

    def handle_data(self, data: str) -> None:
        if self._open:
            self._open[-1] += data

    def handle_endtag(self, tag: str) -> None:
        if tag in ("a", "button") and self._open:
            self.found.append(self._open.pop().strip())


def assert_no_peer_check(html: str) -> None:
    """No button, link or submit input offers a peer check or probe; the scan itself sees the Save button."""
    controls = _Controls()
    controls.feed(html)
    controls.close()
    assert any("save" in text.lower() for text in controls.found), (
        f"control scan saw no Save button: {controls.found!r}"
    )
    probes = [text for text in controls.found if re.search(r"check\s*peers?|probe", text, re.IGNORECASE)]
    assert probes == [], f"expected no peer check control, found {probes!r}"


def read_state(vm: SmokeVM, name: str) -> str | None:
    """The guest state file's text; ``None`` while the file does not exist."""
    path = f"{helpers.PFB_DBDIR}/{name}"
    if vm.ssh("/bin/test", "-e", path).returncode != 0:
        return None
    result = vm.ssh("/bin/cat", path)
    assert result.returncode == 0, f"cat {path}: rc={result.returncode} stderr={result.stderr!r}"
    return result.stdout


def read_mode(vm: SmokeVM, name: str) -> str | None:
    """The guest state file's octal permission bits (FreeBSD ``stat -f %Lp``); ``None`` while it does not exist."""
    path = f"{helpers.PFB_DBDIR}/{name}"
    if vm.ssh("/bin/test", "-e", path).returncode != 0:
        return None
    result = vm.ssh("/usr/bin/stat", "-f", "%Lp", path)
    assert result.returncode == 0, f"stat {path}: rc={result.returncode} stderr={result.stderr!r}"
    return result.stdout.strip()


def _chmod(vm: SmokeVM, name: str, mode: str) -> None:
    path = f"{helpers.PFB_DBDIR}/{name}"
    done = vm.ssh("/bin/chmod", mode, path)
    assert done.returncode == 0, f"chmod {mode} {path}: rc={done.returncode} stderr={done.stderr!r}"


def seed(vm: SmokeVM, *, receive: str | None, findings: str | None, send: str | None) -> None:
    """Write each state file's text on the guest, root-only (0600) like the package's own; ``None`` removes it."""
    for name, text in ((RECEIVE, receive), (FINDINGS, findings), (SEND, send)):
        if text is None:
            removed = vm.ssh("/bin/rm", "-f", f"{helpers.PFB_DBDIR}/{name}")
            assert removed.returncode == 0, f"rm {name}: rc={removed.returncode} stderr={removed.stderr!r}"
        else:
            helpers.write_local_feed(vm, name, text)
            _chmod(vm, name, "600")


@contextmanager
def preserved_state(vm: SmokeVM) -> Iterator[None]:
    """Keep the guest's own receive, findings and send records across a test, byte for byte and mode for mode."""
    saved = {name: (read_state(vm, name), read_mode(vm, name)) for name in STATE_FILES}
    try:
        yield
    finally:
        seed(vm, receive=saved[RECEIVE][0], findings=saved[FINDINGS][0], send=saved[SEND][0])
        for name, (text, mode) in saved.items():
            if text is not None and mode is not None:
                _chmod(vm, name, mode)
        restored = {name: (read_state(vm, name), read_mode(vm, name)) for name in STATE_FILES}
        assert restored == saved, f"restore failed: expected {saved!r}, found {restored!r}"


def render_sync_page(vm: SmokeVM, webui: WebUI) -> str:
    """GET the Sync page: render oracle (200, marker, no PHP diagnostic) plus no new pfBlockerNG php_error.log line."""
    guard = PhpErrorLogGuard(vm)
    guard.snapshot()
    resp = webui.get(SYNC_PAGE)
    html = resp.content.decode("utf-8", errors="replace")
    result = evaluate_render(SYNC_PAGE, resp.status_code, html, (PAGE_MARKER,))
    assert result.ok, f"Tier-A render oracle failed for {SYNC_PAGE}: {result.detail}"
    guard.assert_no_growth()
    return html


def _receiver(html: str) -> str:
    receiver = panel(html, "pfb-sync-receiver")
    assert receiver is not None, "expected the receiver panel (id=pfb-sync-receiver), found none"
    return receiver


def _sender(html: str) -> str:
    sender = panel(html, "pfb-sync-sender")
    assert sender is not None, "expected the sender panel (id=pfb-sync-sender), found none"
    return sender


def _assert_nothing_raw(html: str) -> None:
    assert SCRIPT not in html, f"stored markup is on the page raw: {SCRIPT!r}"
    assert ATTR not in html, f"stored attribute breakout is on the page raw: {ATTR!r}"


@pytest.fixture
def state_files(smoke_vm: SmokeVM) -> Iterator[None]:
    """The guest's own state files come back after the test."""
    with preserved_state(smoke_vm):
        yield


@pytest.fixture(params=("policy", "all", "lists"))
def sync_scope(request: pytest.FixtureRequest, smoke_vm: SmokeVM) -> Iterator[str]:
    """Store one of the three Sync scopes, then restore the exact stored state."""
    saved = helpers.config_get_state(smoke_vm, SCOPE_PATH)
    helpers.config_set(smoke_vm, SCOPE_PATH, request.param)

    yield str(request.param)

    helpers.config_restore_state(smoke_vm, SCOPE_PATH, saved)
    restored = helpers.config_get_state(smoke_vm, SCOPE_PATH)
    assert restored == saved, f"restore failed for {SCOPE_PATH}: expected {saved!r}, found {restored!r}"


def test_receiver_panel_shows_the_record_escaped_in_every_scope(
    smoke_vm: SmokeVM, webui: WebUI, state_files: None, sync_scope: str
) -> None:
    """A changed receive with a failed apply renders as a receipt plus a separate apply row, every value escaped.

    Red when: the receive row stops saying "accepted with changes"; the apply outcome folds into the receive row
    (or is absent); a digest, ignored path, finding or apply reason is not escaped (raw sentinel on the page) or
    is truncated (the 300-char finding); the non-string ignored entry or finding entry is rendered; the drift row
    is missing.
    """
    seed(smoke_vm, receive=json.dumps(CHANGED), findings=json.dumps(FINDINGS_DOC), send=json.dumps(SEND_DOC))
    html = render_sync_page(smoke_vm, webui)
    receiver = _receiver(html)

    assert_row(receiver, "receive", f"{TIME} {DASH} accepted with changes")
    assert_row(receiver, "incoming", INCOMING)
    assert_row(receiver, "accepted", ACCEPTED)
    assert_row(
        receiver, "ignored", rf"3 ignored path\(s\) {re.escape(php_escape(IGNORED_PATH))} installedpackages/b/plain"
    )
    assert_row(receiver, "apply", rf"failed: {re.escape(php_escape(APPLY_REASON))} \({TIME}\)")
    # The stored accepted digest is made up, so this node's policy has "moved off" it.
    assert_row(receiver, "drift", "policy changed locally since the last accepted receive")
    assert_row(receiver, "findings", f"{re.escape(php_escape(FINDING_SCRIPT))} {re.escape(php_escape(FINDING_LONG))}")
    assert_row(receiver, "copied", "none")
    _assert_nothing_raw(html)


def test_sender_panel_never_claims_more_than_a_returned_call_shows(
    smoke_vm: SmokeVM, webui: WebUI, state_files: None
) -> None:
    """The sender panel reports sent/failed/handed attempts in its own words and drops invalid entries.

    Red when: a result's wording changes (sent, acceptance unconfirmed / failed: <error> / handed to pfSense HA
    sync); the error or a target is not escaped; any whole word supported/accepted/applied/drifting or the phrase
    "in sync" enters the sender panel's text; an entry with an unknown outcome (``accepted``, markup), a non-int
    time or a non-string target is shown; the footer note is lost. The receiver panel on the same page must match
    the banned regex (it says accepted), so the sender check reads a real slice, not a regex that cannot fire.
    """
    seed(smoke_vm, receive=json.dumps(CHANGED), findings=None, send=json.dumps(SEND_DOC))
    html = render_sync_page(smoke_vm, webui)
    sender, receiver = _sender(html), _receiver(html)

    rows = sender_rows(sender)
    assert [len(row) for row in rows] == [4, 4, 4], f"expected 3 rows of Target|Time|Digest|Result, got {rows!r}"
    sent, failed, handed = rows
    assert sent[0] == "192.0.2.10:443", f"sent target: got {sent[0]!r}"
    assert re.fullmatch(TIME, sent[1]), f"sent time: expected a date, got {sent[1]!r}"
    assert sent[2:] == [INCOMING, "sent, acceptance unconfirmed"], f"sent row: got {sent!r}"
    assert failed[0] == php_escape(f"192.0.2.11{ATTR}:443"), f"failed target: got {failed[0]!r}"
    assert failed[2:] == ["n/a", f"failed: {php_escape(SEND_ERROR)}"], f"failed row: got {failed!r}"
    assert handed[2:] == ["n/a", "handed to pfSense HA sync"], f"handed row: got {handed!r}"

    for marker in DROPPED_MARKERS:
        assert marker not in html, f"expected the invalid attempt {marker!r} dropped, found it on the page"
    banned = BANNED.search(sender)
    assert banned is None, f"the sender panel must not say {banned and banned.group(0)!r}"
    assert ACCEPTED_WORD.search(receiver), "non-vacuity: the receiver panel on the same page must say accepted"
    assert SENDER_FOOTER in unescape(plain(sender)), f"sender footer note missing: got {plain(sender)!r}"
    _assert_nothing_raw(html)


def test_refused_receive_is_never_accepted_wording(smoke_vm: SmokeVM, webui: WebUI, state_files: None) -> None:
    """A refusal shows its escaped reason and claims no digest of its own, though an older accepted digest is stored.

    Red when: the receive row says accepted for a refusal (the stored top-level accepted digest tempts exactly
    that); the reason is not escaped; the accepted or incoming row shows the old receive's digest; the apply row
    says anything but "no apply record".
    """
    reason = f"duplicate aliasname {HOSTILE}"
    refused = {"accepted_digest": ACCEPTED, "last": {"time": T, "outcome": "refused", "reason": reason}}
    seed(smoke_vm, receive=json.dumps(refused), findings=None, send=None)
    html = render_sync_page(smoke_vm, webui)
    receiver = _receiver(html)

    assert_row(receiver, "receive", f"{TIME} {DASH} refused: {re.escape(php_escape(reason))}")
    assert_row(receiver, "incoming", DASH)
    assert_row(receiver, "accepted", DASH)
    assert_row(receiver, "ignored", "none")
    assert_row(receiver, "apply", "no apply record")
    _assert_nothing_raw(html)


@pytest.mark.parametrize(
    "record",
    [None, '{"accepted_digest": null, "last": null}', "{not json"],
    ids=["absent", "null-last", "corrupt"],
)
def test_no_receive_record_shows_no_receiver_panel(
    smoke_vm: SmokeVM, webui: WebUI, state_files: None, record: str | None
) -> None:
    """A node with no usable receive record (an old or unsupported peer) shows nothing new, findings or not.

    Red when: the receiver panel renders without a ``last`` record, whatever else (findings, a sender record) is
    stored. The first render proves the panel exists for a real record, so the later absence is a transition.
    """
    seed(smoke_vm, receive=json.dumps(CHANGED), findings=None, send=json.dumps(SEND_DOC))
    _receiver(render_sync_page(smoke_vm, webui))

    seed(smoke_vm, receive=record, findings=json.dumps(FINDINGS_DOC), send=json.dumps(SEND_DOC))
    html = render_sync_page(smoke_vm, webui)
    assert 'id="pfb-sync-receiver' not in html, "expected no receiver panel without a receive record, found one"
    assert "Receiver: last policy receive" not in html, "expected no receiver heading without a receive record"
    _sender(html)


@pytest.mark.parametrize(
    "record",
    [None, json.dumps({"time": T, "attempts": []}), json.dumps({"time": T, "attempts": DROPPED_ATTEMPTS}), "{not json"],
    ids=["absent", "empty", "all-invalid", "corrupt"],
)
def test_no_usable_attempts_show_no_sender_panel(
    smoke_vm: SmokeVM, webui: WebUI, state_files: None, record: str | None
) -> None:
    """Without a usable attempt the sender panel is absent while the receiver panel still renders.

    Red when: an empty or all-invalid attempt list still renders a sender panel (a heading claiming a sync pass
    that never happened). The first render proves the panel exists for real attempts.
    """
    seed(smoke_vm, receive=json.dumps(CHANGED), findings=None, send=json.dumps(SEND_DOC))
    _sender(render_sync_page(smoke_vm, webui))

    seed(smoke_vm, receive=json.dumps(CHANGED), findings=None, send=record)
    html = render_sync_page(smoke_vm, webui)
    assert 'id="pfb-sync-sender' not in html, "expected no sender panel without a usable attempt, found one"
    assert "Sender: last sync attempts" not in html, "expected no sender heading without a usable attempt"
    _receiver(html)


@pytest.mark.parametrize(
    ("outcome", "wording"),
    [
        ("accepted", "unknown outcome"),
        ("<b>x</b>", "unknown outcome"),
        (5, "unknown outcome"),
        (None, "unknown outcome"),
        ("refused", "refused"),
    ],
    ids=["accepted", "markup", "int", "null", "refused-without-reason"],
)
def test_wrong_types_render_clean_and_unknown_outcome_is_not_accepted(
    smoke_vm: SmokeVM, webui: WebUI, state_files: None, outcome: object, wording: str
) -> None:
    """A record of the wrong types renders without a PHP diagnostic, never reading as accepted.

    Red when: an unknown outcome (the word ``accepted`` included) renders as accepted or echoes raw markup; an
    array or int in a string field prints ``Array``/the int or raises a diagnostic (the oracle and the
    php_error.log guard fail); a non-int time prints a date; a non-list ignored/findings/attempts field breaks
    the panel.
    """
    receive = {
        "accepted_digest": 5,
        "last": {
            "time": "soon",
            "outcome": outcome,
            "reason": ["x"],
            "incoming_digest": ["x"],
            "accepted_digest": 7,
            "ignored": "no",
            "ignored_count": "NaN",
        },
        "apply": {"outcome": ["x"], "time": "later", "reason": {"a": 1}},
    }
    findings = {"time": "x", "findings": [1, ["a"], "keep-me"]}
    seed(smoke_vm, receive=json.dumps(receive), findings=json.dumps(findings), send=json.dumps({"attempts": "nope"}))
    html = render_sync_page(smoke_vm, webui)
    receiver = _receiver(html)

    assert_row(receiver, "receive", f"unknown time {DASH} {wording}")
    assert_row(receiver, "incoming", DASH)
    assert_row(receiver, "accepted", DASH)
    assert_row(receiver, "ignored", "none")
    assert_row(receiver, "apply", "unknown apply state")
    assert_row(receiver, "drift", "no accepted digest to compare")
    assert_row(receiver, "findings", "none")  # a wrong-typed accepted digest is no accepted digest: no findings
    assert "keep-me" not in receiver, "findings listed for a node that holds no accepted digest"
    assert "Array" not in receiver, "a non-string value was printed as 'Array'"
    assert "<b>x</b>" not in receiver, "the stored outcome markup is in the panel raw"
    assert 'id="pfb-sync-sender' not in html, "a non-list attempts field must show no sender panel"


def test_page_offers_no_peer_check_control(smoke_vm: SmokeVM, webui: WebUI, state_files: None) -> None:
    """With both panels on the page, no button, link or submit input offers a peer check or a probe.

    Red when: any control whose text or value matches /check\\s*peers?|probe/i is added; the scan is not blind
    because it must find the form's own Save button.
    """
    seed(smoke_vm, receive=json.dumps(CHANGED), findings=json.dumps(FINDINGS_DOC), send=json.dumps(SEND_DOC))
    html = render_sync_page(smoke_vm, webui)
    _receiver(html)
    _sender(html)
    assert_no_peer_check(html)
