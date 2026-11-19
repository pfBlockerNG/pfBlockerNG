"""A stub CrowdSec Local API (LAPI) for the live-VM smoke suite (issue #4074; docs/specs/crowdsec-integration.md).

A stdlib HTTP server on the runner, reached by the guest at ``http://192.168.89.2:<port>`` through the WAN SLIRP host
alias, the same path ``mock_feeds`` rides (it survives the egress block). It plays the engine one bouncer talks to:

* ``GET /v1/decisions/stream?startup=true`` answers every active decision. Without ``startup`` it answers the
  decisions added and deleted since this bouncer's previous stream reply: the LAPI moves a bouncer's cursor as soon
  as it has written a reply (#4077). ``scopes`` keeps the decisions of those scopes, case-insensitively, and an empty
  list is ``null``, as the LAPI sends them.
* ``GET /v1/decisions?ip=<addr>`` answers the active decisions whose value is that address, or a range holding it;
  ``null`` when there is none.
* ``POST /v1/usage-metrics`` is recorded and answered ``201``.
* Every ``/v1/`` request without the bouncer's key in ``X-Api-Key`` gets ``403``. Any other path gets ``404``.

Every request, on any path, is recorded with its key and body, and each stream reply with the decision ids it
carried. A test adds and deletes decisions (:meth:`StubLapi.add`, :meth:`StubLapi.delete`), reads the requests and
the posted usage metrics, waits for a request with :meth:`StubLapi.wait_for`, and takes the LAPI away with
:meth:`StubLapi.outage` (connections are refused until it ends, then it answers again on the same port).
"""

from __future__ import annotations

import contextlib
import ipaddress
import itertools
import json
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

STREAM = "/v1/decisions/stream"
DECISIONS = "/v1/decisions"
USAGE = "/v1/usage-metrics"


@dataclass(frozen=True)
class LapiRequest:
    """One request the stub answered: ``seq`` counts from 0 in arrival order; ``new`` and ``deleted`` are the decision
    ids a stream reply carried."""

    seq: int
    method: str
    path: str
    query: dict[str, list[str]]
    api_key: str | None
    body: bytes
    status: int
    new: tuple[int, ...] = ()
    deleted: tuple[int, ...] = ()

    @property
    def is_stream(self) -> bool:
        return self.method == "GET" and self.path == STREAM and self.status == 200

    @property
    def startup(self) -> bool:
        return self.query.get("startup") == ["true"]

    def __str__(self) -> str:
        query = "&".join(f"{k}={v}" for k, values in self.query.items() for v in values)
        served = f" new={list(self.new)} deleted={list(self.deleted)}" if self.is_stream else ""
        return f"#{self.seq} {self.method} {self.path}{'?' + query if query else ''} -> {self.status}{served}"


@dataclass
class _Decision:
    id: int
    value: str
    scope: str
    type: str
    origin: str
    scenario: str
    duration: str
    added: int  # the stub's event clock when it was added, and deleted
    deleted: int | None = None

    def wire(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "origin": self.origin,
            "type": self.type,
            "scope": self.scope,
            "value": self.value,
            "duration": self.duration,
            "scenario": self.scenario,
            "simulated": False,
        }

    def holds(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        try:
            return ip in ipaddress.ip_network(self.value, strict=False)
        except ValueError:
            return False


@dataclass
class _State:
    key: str
    decisions: list[_Decision] = field(default_factory=list)
    requests: list[LapiRequest] = field(default_factory=list)
    clock: int = 0  # bumped by every add and delete
    cursor: int = 0  # the clock when the last stream reply was written
    ids: Iterator[int] = field(default_factory=lambda: itertools.count(1))


class StubLapi:
    """The stub LAPI; ``key`` is the bouncer key it accepts, ``guest_host`` the address the guest reaches it at."""

    def __init__(self, key: str, *, guest_host: str) -> None:
        self.key = key
        self._guest_host = guest_host
        self._state = _State(key)
        self._cond = threading.Condition()
        self._port = 0
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- serving -------------------------------------------------------------------------------------------------

    @property
    def port(self) -> int:
        return self._port

    @property
    def url(self) -> str:
        """The LAPI URL the guest uses (the bouncer's ``api_url``)."""
        return f"http://{self._guest_host}:{self._port}"

    def start(self) -> None:
        # Bound to all interfaces so the SLIRP host alias reaches it; port 0 picks a free one, kept across outage().
        self._httpd = ThreadingHTTPServer(("0.0.0.0", self._port), self._handler())
        self._port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="stub-lapi", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None

    @contextlib.contextmanager
    def outage(self) -> Iterator[None]:
        """The LAPI is unreachable (connections refused) inside the block, and answers again on the same port after."""
        self.stop()
        try:
            yield
        finally:
            self.start()

    # -- the engine's decisions ----------------------------------------------------------------------------------

    def add(
        self,
        value: str,
        *,
        scope: str = "Ip",
        type: str = "ban",  # noqa: A002 -- the LAPI's own field name
        origin: str = "crowdsec",
        scenario: str = "crowdsecurity/ssh-bf",
        duration: str = "4h",
    ) -> int:
        """Add a decision and return its id."""
        with self._cond:
            state = self._state
            state.clock += 1
            decision = _Decision(next(state.ids), value, scope, type, origin, scenario, duration, added=state.clock)
            state.decisions.append(decision)
            return decision.id

    def delete(self, *ids: int) -> None:
        """Delete active decisions by id (what ``cscli decisions delete`` does on the engine)."""
        with self._cond:
            state = self._state
            active = {d.id: d for d in state.decisions if d.deleted is None}
            missing = [i for i in ids if i not in active]
            if missing:
                raise KeyError(f"no active decision with id {missing}")
            for i in ids:
                state.clock += 1
                active[i].deleted = state.clock

    def active(self) -> list[dict[str, Any]]:
        """The active decisions, as the LAPI sends them."""
        with self._cond:
            return [d.wire() for d in self._state.decisions if d.deleted is None]

    # -- what the bouncer sent -----------------------------------------------------------------------------------

    def requests(self) -> list[LapiRequest]:
        with self._cond:
            return list(self._state.requests)

    def mark(self) -> int:
        """The seq the next request will get: pass it as ``after`` to wait for requests from now on."""
        with self._cond:
            return len(self._state.requests)

    def usage_posts(self) -> list[Any]:
        """The bodies posted to ``/v1/usage-metrics`` with the bouncer key, decoded."""
        return [
            json.loads(r.body) for r in self.requests() if r.method == "POST" and r.path == USAGE and r.status == 201
        ]

    def wait_for(
        self, match: Callable[[LapiRequest], bool], *, after: int = 0, timeout: float, what: str
    ) -> LapiRequest:
        """The first request from seq ``after`` on that ``match`` accepts, as soon as it arrives. ``timeout`` is a
        salvage cap: when it expires, the error lists the requests seen since ``after``."""
        with self._cond:
            found = self._cond.wait_for(
                lambda: next((r for r in self._state.requests[after:] if match(r)), None), timeout=timeout
            )
            if found is not None:
                return found
            seen = [str(r) for r in self._state.requests[after:]][-20:]
        raise RuntimeError(
            f"stuck/environment: no {what} within the {timeout:.0f} s cap; requests since #{after}: {seen}"
        )

    # -- the HTTP side -------------------------------------------------------------------------------------------

    def _answer(self, method: str, target: str, api_key: str | None, body: bytes) -> tuple[int, Any]:
        """Record one request and return (status, JSON body)."""
        parts = urlsplit(target)
        query = parse_qs(parts.query, keep_blank_values=True)
        with self._cond:
            state = self._state
            status, reply, new, deleted = self._route(method, parts.path, query, api_key)
            if status == 200 and method == "GET" and parts.path == STREAM:
                state.cursor = state.clock
            state.requests.append(
                LapiRequest(len(state.requests), method, parts.path, query, api_key, body, status, new, deleted)
            )
            self._cond.notify_all()
        return status, reply

    def _route(
        self, method: str, path: str, query: dict[str, list[str]], api_key: str | None
    ) -> tuple[int, Any, tuple[int, ...], tuple[int, ...]]:
        """Answer one request under the lock: (status, JSON body, new ids, deleted ids)."""
        state = self._state
        if not path.startswith("/v1/"):
            return 404, {"message": "not found"}, (), ()
        if api_key != state.key:
            return 403, {"message": "access forbidden"}, (), ()
        if method == "GET" and path == STREAM:
            scopes = {s.strip().casefold() for v in query.get("scopes", []) for s in v.split(",") if s.strip()}
            pick = [d for d in state.decisions if not scopes or d.scope.casefold() in scopes]
            if query.get("startup") == ["true"]:
                new = [d for d in pick if d.deleted is None]
                deleted: list[_Decision] = []
            else:
                new = [d for d in pick if d.deleted is None and d.added > state.cursor]
                deleted = [d for d in pick if d.deleted is not None and d.deleted > state.cursor]
            reply = {"new": [d.wire() for d in new] or None, "deleted": [d.wire() for d in deleted] or None}
            return 200, reply, tuple(d.id for d in new), tuple(d.id for d in deleted)
        if method == "GET" and path == DECISIONS:
            try:
                ip = ipaddress.ip_address(query.get("ip", [""])[0])
            except ValueError:
                return 400, {"message": "ip: not a valid IP address"}, (), ()
            hits = [d.wire() for d in state.decisions if d.deleted is None and d.holds(ip)]
            return 200, hits or None, (), ()
        if method == "POST" and path == USAGE:
            return 201, {}, (), ()
        return 404, {"message": "not found"}, (), ()

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        stub = self

        class Handler(BaseHTTPRequestHandler):
            # HTTP/1.0: one request per connection, so an outage() never leaves a kept-alive connection answering
            protocol_version = "HTTP/1.0"

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length > 0 else b""
                status, reply = stub._answer(self.command, self.path, self.headers.get("X-Api-Key"), body)
                payload = json.dumps(reply).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self) -> None:  # noqa: N802 (stdlib name)
                self._serve()

            def do_POST(self) -> None:  # noqa: N802 (stdlib name)
                self._serve()

            def do_DELETE(self) -> None:  # noqa: N802 (stdlib name)
                self._serve()

            def log_message(self, fmt: str, *args: object) -> None:
                return  # quiet: the recorded requests are the log

        return Handler
