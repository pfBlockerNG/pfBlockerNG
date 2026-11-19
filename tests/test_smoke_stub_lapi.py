"""The smoke suite's stub CrowdSec LAPI answers as the LAPI does (issue #4074) — off-box, no VM.

``tests/smoke/stub_lapi.py`` is what the CrowdSec smoke module's bouncer talks to, so its stream semantics decide what
those tests prove: a startup pull is the full set, a delta is what changed since the previous stream reply (the
cursor moves when a reply is written, #4077), a refused request moves nothing. Driven over real HTTP on loopback.
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest

from tests.smoke.stub_lapi import StubLapi

KEY = "stub-test-key"


@pytest.fixture
def stub() -> Iterator[StubLapi]:
    lapi = StubLapi(KEY, guest_host="192.168.89.2")
    lapi.start()
    try:
        yield lapi
    finally:
        lapi.stop()


def _call(stub: StubLapi, path: str, *, key: str | None = KEY, body: bytes | None = None) -> tuple[int, Any]:
    request = urllib.request.Request(f"http://127.0.0.1:{stub.port}{path}", data=body)
    if key is not None:
        request.add_header("X-Api-Key", key)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _pull(stub: StubLapi, *, startup: bool = False) -> dict[str, Any]:
    status, reply = _call(stub, "/v1/decisions/stream?scopes=ip%2Crange" + ("&startup=true" if startup else ""))
    assert status == 200, reply
    return reply


def _values(decisions: list[dict[str, Any]] | None) -> list[str]:
    return [d["value"] for d in decisions or []]


def test_the_url_is_the_guest_alias_and_the_bound_port(stub: StubLapi) -> None:
    assert stub.url == f"http://192.168.89.2:{stub.port}"
    assert stub.port > 0


def test_a_startup_pull_is_every_active_decision_of_the_asked_scopes(stub: StubLapi) -> None:
    kept = stub.add("192.0.2.1")
    stub.add("198.51.100.0/24", scope="Range", origin="CAPI")
    stub.add("FR", scope="Country")
    gone = stub.add("192.0.2.2")
    stub.delete(gone)

    reply = _pull(stub, startup=True)

    assert _values(reply["new"]) == ["192.0.2.1", "198.51.100.0/24"], "active ip and range decisions, no country"
    assert reply["deleted"] is None, "an empty list is null, as the LAPI sends it"
    first = reply["new"][0]
    assert first == {
        "id": kept,
        "origin": "crowdsec",
        "type": "ban",
        "scope": "Ip",
        "value": "192.0.2.1",
        "duration": "4h",
        "scenario": "crowdsecurity/ssh-bf",
        "simulated": False,
    }


def test_a_delta_is_what_changed_since_the_previous_stream_reply(stub: StubLapi) -> None:
    old = stub.add("192.0.2.1")
    assert _values(_pull(stub, startup=True)["new"]) == ["192.0.2.1"]

    fresh = stub.add("2001:db8::1")
    stub.delete(old)
    delta = _pull(stub)

    assert _values(delta["new"]) == ["2001:db8::1"], "only the decision added since the startup reply"
    assert _values(delta["deleted"]) == ["192.0.2.1"]
    assert _pull(stub) == {"new": None, "deleted": None}, "the reply moved the cursor: nothing changed since"

    requests = [r for r in stub.requests() if r.is_stream]
    assert [(r.startup, r.new, r.deleted) for r in requests] == [
        (True, (old,), ()),
        (False, (fresh,), (old,)),
        (False, (), ()),
    ]


def test_a_decision_added_and_deleted_between_pulls_is_only_deleted(stub: StubLapi) -> None:
    _pull(stub, startup=True)
    brief = stub.add("192.0.2.9")
    stub.delete(brief)

    delta = _pull(stub)

    assert delta["new"] is None
    assert _values(delta["deleted"]) == ["192.0.2.9"]


def test_two_decisions_on_one_value_are_separate_ids(stub: StubLapi) -> None:
    first = stub.add("192.0.2.5")
    second = stub.add("192.0.2.5", origin="cscli")
    _pull(stub, startup=True)

    stub.delete(first)

    assert first != second
    assert _values(_pull(stub)["deleted"]) == ["192.0.2.5"]
    assert [d["id"] for d in stub.active()] == [second], "the other decision on the value is still active"


def test_a_refused_key_is_recorded_and_moves_no_cursor(stub: StubLapi) -> None:
    _pull(stub, startup=True)
    stub.add("192.0.2.7")

    assert _call(stub, "/v1/decisions/stream", key="wrong") == (403, {"message": "access forbidden"})
    assert _call(stub, "/v1/decisions/stream", key=None)[0] == 403

    assert _values(_pull(stub)["new"]) == ["192.0.2.7"], "the refused requests consumed no change"
    refused = [r for r in stub.requests() if r.status == 403]
    assert [r.api_key for r in refused] == ["wrong", None]
    assert not any(r.is_stream for r in refused)


def test_the_decisions_lookup_matches_an_address_and_the_ranges_holding_it(stub: StubLapi) -> None:
    stub.add("192.0.2.77")
    stub.add("192.0.2.0/24", scope="Range")
    stub.add("2001:db8::77")
    gone = stub.add("198.51.100.1")
    stub.delete(gone)

    status, hits = _call(stub, "/v1/decisions?ip=192.0.2.77")
    assert status == 200 and _values(hits) == ["192.0.2.77", "192.0.2.0/24"]
    assert _values(_call(stub, "/v1/decisions?ip=2001:db8::77")[1]) == ["2001:db8::77"]
    assert _call(stub, "/v1/decisions?ip=198.51.100.1") == (200, None), "a deleted decision matches nothing: null"
    assert _call(stub, "/v1/decisions?ip=not-an-ip")[0] == 400


def test_usage_metrics_are_recorded_and_accepted(stub: StubLapi) -> None:
    payload = {"remediation_components": [{"type": "pfb_crowdsec", "metrics": []}]}

    status, reply = _call(stub, "/v1/usage-metrics", body=json.dumps(payload).encode())
    refused, _ = _call(stub, "/v1/usage-metrics", key="wrong", body=b"{}")

    assert (status, reply, refused) == (201, {}, 403)
    assert stub.usage_posts() == [payload], "only the post carrying the bouncer key counts"


def test_any_other_path_is_404_and_recorded_with_its_body(stub: StubLapi) -> None:
    status, _ = _call(stub, "/xmlrpc.php", key=None, body=b"<methodCall/>")

    assert status == 404
    (request,) = stub.requests()
    assert (request.method, request.path, request.body) == ("POST", "/xmlrpc.php", b"<methodCall/>")


def test_an_outage_refuses_connections_and_the_same_port_answers_after(stub: StubLapi) -> None:
    stub.add("192.0.2.1")
    port = stub.port

    with stub.outage():
        with pytest.raises(OSError), socket.create_connection(("127.0.0.1", port), timeout=5):
            pass
        stub.add("192.0.2.2")

    assert stub.port == port
    assert _values(_pull(stub, startup=True)["new"]) == ["192.0.2.1", "192.0.2.2"], "the engine kept its decisions"


def test_wait_for_returns_the_request_once_it_arrives(stub: StubLapi) -> None:
    after = stub.mark()
    caller = threading.Thread(target=_pull, args=(stub,), kwargs={"startup": True})
    caller.start()
    try:
        seen = stub.wait_for(lambda r: r.is_stream and r.startup, after=after, timeout=30, what="startup pull")
    finally:
        caller.join(timeout=30)

    assert (seen.seq, seen.startup) == (after, True)


def test_wait_for_names_what_it_saw_when_the_cap_expires(stub: StubLapi) -> None:
    _pull(stub, startup=True)

    with pytest.raises(RuntimeError, match=r"stuck/environment: no delta pull .*#0 GET /v1/decisions/stream"):
        stub.wait_for(lambda r: r.is_stream and not r.startup, timeout=0.2, what="delta pull")


def test_deleting_a_decision_that_is_not_active_is_an_error(stub: StubLapi) -> None:
    gone = stub.add("192.0.2.1")
    stub.delete(gone)

    with pytest.raises(KeyError):
        stub.delete(gone)
