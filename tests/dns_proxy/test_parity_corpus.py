"""Decision parity corpus (issue #3772): language-neutral JSON scenarios that the REAL shipped Python decider passes
and a Go decider can run unchanged. A scenario is one module directory (the files PHP writes for the decider) plus
ordered query cases, each with the decision as it appears on the decision protocol (docs/misc/dns-gateway-protocol.md,
"One query"): which FORWARDs the decider sent, and the final ANSWER.

The expectations in fixtures/parity/ are frozen literals derived from the source branch each family names in
families.json, never captured from a run. A fixture the loader refuses is an error naming file, case and field.

Schema 2, the contract a Go runner implements too (every key is required unless marked optional; any other key, a
duplicate JSON key, NaN/Infinity, a wrong JSON type or an unknown value is a refusal, never a skip; every file in
fixtures/parity/ is a .json document the runner loads):

  families.json  {"schema": 2, "families": {"<family>": "<source branch>", ...}}: the closed family list. Every family
                 pins pfb_unbound.py except `frontend`, which pins Frontend.resolve in pfb_dns_proxy.py.
  <scenario>.json  {"schema": 2, "description", "module", "upstream", "cases"}
    module.ini       {section: {key: value}}, every value a string, written as pfb_unbound.ini in file order; no line
                     break anywhere, no bracket in a section name, no "=" or ":" in a key.
    module.manifest  written verbatim as pfb_py_sources.json.
    module.files     {relative path: [lines]}, written joined by newlines plus a trailing one; no "..", NUL or absolute
                     path, no path listed twice ("./x" is "x"), no file that is also another one's directory, and
                     nothing at or under the names the runner writes (the shipped pfb_unbound.py and
                     pfb_dnsbl_regex_rules.py are linked in by the runner, never by a fixture).
    upstream         {"<lower-case absolute name> <TYPE>": [RR texts] or null}, Unbound's stand-in (FakeUnbound): a
                     listed question gets NOERROR with those records (an empty list: none at all; null: no reply, which
                     the runner gives as an empty REPLY), any other NXDOMAIN; one question is listed once, whichever
                     spelling of its type.
    cases            non-empty list, run IN FILE ORDER against one booted decider (its per-name memo carries over).
      id, description   non-empty strings; id unique within the file.
      family            a families.json key.
      query             {"name": absolute name, "type": mnemonic or TYPE<n> (n <= 65535)}: one question, class IN, RD
                        set, no EDNS; or {"wire_hex": lower-case hex of at most 65535 bytes}: the QUERY frame's DNS wire
                        verbatim; never both, never half of the first. Either has "client": IP (optional, 192.0.2.10)
                        and "transport": TCP|UDP|DoT|DoH|DoQ (optional, UDP).
      expect            {"decision": answer|relay|rewrite|drop, "forwards": ["<name> <TYPE>", ...], "rcode": NOERROR|
                        FORMERR|SERVFAIL|NXDOMAIN|NOTIMP|REFUSED, "answer": [RR texts], "authority": [RR texts], "tc":
                        true|false (optional, false)}. A drop is exactly {"decision": "drop", "forwards": []}.
  RR texts are "name ttl IN TYPE rdata" for A, AAAA, CNAME, TXT and SOA (dnswire.rr_from_text).

Decisions: answer = no FORWARD, the decider built the ANSWER; relay = one FORWARD carrying the client's own wire and
an ANSWER byte-identical to Unbound's reply; rewrite = FORWARDs, then an ANSWER that is none of Unbound's replies (the
SERVFAIL the decider builds for Unbound's silence is one); drop = no FORWARD and a DROP in place of the ANSWER. forwards
lists every FORWARD's question in order. answer/authority compare in order as (owner, type, class, ttl, rdata) with the
owner exactly as on the wire: the encoder compresses an owner equal to the question, case-blind, into the question, so
a mixed-case query's answer carries the client's spelling. Flags other than the rcode and TC, and the additional
section, are not compared; TC (the ANSWER's) is compared for every non-drop case. A drop has no ANSWER: only decision
and forwards are compared.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import re
import socket
from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

import decision_service
import dnswire
import pfb_dns_proxy
import pytest
from frontend_constants import SHIPPED_DIR, Booted
from frontend_helpers import (
    ANSWER,
    FORWARD,
    QUERY,
    READY,
    REPLY,
    WATCHDOG,
    DecisionGateway,
    FakeUnbound,
    build_query,
    watchdog,
)

FIXTURES = Path(__file__).parent / "fixtures" / "parity"
DEFAULT_CLIENT = "192.0.2.10"
SHIPPED_MODULES = ("pfb_unbound.py", "pfb_dnsbl_regex_rules.py")  # linked into every scenario's module directory
RUNNER_WRITES = (*SHIPPED_MODULES, "pfb_unbound.ini", "pfb_py_sources.json")
TRANSPORTS = ("TCP", "UDP", "DoT", "DoH", "DoQ")  # the QUERY frame's transport byte is this index
DECISIONS = ("answer", "relay", "rewrite", "drop")
RCODES = {"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5}
QTYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "SIG": 24,
    "AAAA": 28,
    "SRV": 33,
    "DNAME": 39,
    "SVCB": 64,
    "HTTPS": 65,
    "ANY": 255,
}


class FixtureError(ValueError):
    """A parity fixture the loader refuses; the message names the file, the case (when there is one) and the field."""


@dataclass(frozen=True)
class Query:
    wire: bytes  # the QUERY frame's DNS wire
    client: str
    transport: str


@dataclass(frozen=True)
class Expect:
    decision: str
    forwards: tuple[str, ...]
    rcode: str = ""  # the rest only for a non-drop decision: a drop has no ANSWER
    answer: tuple[dnswire.RR, ...] = ()
    authority: tuple[dnswire.RR, ...] = ()
    tc: bool = False


@dataclass(frozen=True)
class Case:
    id: str
    family: str
    description: str
    query: Query
    expect: Expect


@dataclass(frozen=True)
class Module:
    ini: dict[str, dict[str, str]]
    manifest: dict[str, Any]
    files: dict[str, list[str]]


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    module: Module
    upstream: dict[tuple[str, int], list[str] | None]  # (lower-case name, qtype) -> RR texts; None: no reply
    cases: tuple[Case, ...]


# --- the loader: every defect is one FixtureError ---------------------------------------------------------------


def _fail(where: str, field: str, why: str) -> NoReturn:
    raise FixtureError(f"{where}: {field}: {why}")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"duplicate JSON key {key!r}")
        seen.add(key)
    return dict(pairs)


def _no_constant(name: str) -> NoReturn:
    raise ValueError(f"{name} is not JSON")  # Python's json reads NaN/Infinity; other languages do not


def _read_json(path: Path) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
    except (ValueError, RecursionError) as exc:  # JSONDecodeError, a duplicate key, NaN, bad UTF-8, absurd nesting
        raise FixtureError(f"{path.name}: not a readable JSON document: {exc}") from exc


def _object(
    value: object, where: str, field: str, required: tuple[str, ...], optional: tuple[str, ...] = ()
) -> dict[str, Any]:
    """`value` as a JSON object with exactly the `required` keys plus any of the `optional` ones."""
    if not isinstance(value, dict):
        _fail(where, field or "document", "must be a JSON object")
    prefix = f"{field}." if field else ""
    for key in value:
        if key not in required and key not in optional:
            _fail(where, f"{prefix}{key}", "unknown key")
    for key in required:
        if key not in value:
            _fail(where, f"{prefix}{key}", "missing")
    return value


def _string(value: object, where: str, field: str) -> str:
    if not isinstance(value, str):
        _fail(where, field, f"must be a string, got {value!r}")
    return value


def _strings(value: object, where: str, field: str) -> list[str]:
    if not isinstance(value, list):
        _fail(where, field, f"must be a list, got {value!r}")
    return [_string(item, where, f"{field}[{index}]") for index, item in enumerate(value)]


def _choice(value: object, where: str, field: str, allowed: Collection[str]) -> str:
    text = _string(value, where, field)
    if text not in allowed:
        _fail(where, field, f"unknown value {text!r}, expected one of {' '.join(sorted(allowed))}")
    return text


def _ini_text(text: str, where: str, field: str, forbidden: str) -> str:
    if any(char in text for char in forbidden):
        _fail(where, field, f"{text!r} must not contain any of {forbidden!r}")
    return text


def _schema(doc: dict[str, Any], where: str) -> None:
    if type(doc["schema"]) is not int or doc["schema"] != 2:  # a bool or 2.0 is not the integer 2
        _fail(where, "schema", f"must be the integer 2, got {doc['schema']!r}")


def _qtype(text: str, where: str, field: str) -> int:
    if text in QTYPES:
        return QTYPES[text]
    numbered = re.fullmatch(r"TYPE([0-9]{1,5})", text)
    if numbered and int(numbered[1]) <= 0xFFFF:
        return int(numbered[1])
    return _fail(where, field, f"unknown query type {text!r}")


def _type_text(qtype: int) -> str:
    return next((name for name, number in QTYPES.items() if number == qtype), f"TYPE{qtype}")


def _wire_name(name: str, where: str, field: str) -> str:
    try:
        dnswire.name_to_labels(name)
    except ValueError as exc:
        _fail(where, field, f"name {name!r} cannot go on the wire: {exc}")
    if not name.endswith("."):
        _fail(where, field, f"name {name!r} must be absolute (end with a dot)")
    return name


def _question(text: str, where: str, field: str) -> tuple[str, int]:
    """`"<name> <TYPE>"` as the name and the numeric type."""
    name, space, kind = text.partition(" ")
    if not space:
        _fail(where, field, f"expected '<name> <TYPE>', got {text!r}")
    return _wire_name(name, where, field), _qtype(kind, where, field)


def _rrs(value: object, where: str, field: str) -> tuple[dnswire.RR, ...]:
    out = []
    for index, text in enumerate(_strings(value, where, field)):
        try:
            out.append(dnswire.rr_from_text(text))
        except ValueError as exc:
            _fail(where, f"{field}[{index}]", f"rr_from_text rejects {text!r}: {exc}")
    return tuple(out)


def load_families(path: Path) -> dict[str, str]:
    where = path.name
    doc = _object(_read_json(path), where, "", ("schema", "families"))
    _schema(doc, where)
    families = doc["families"]
    if not isinstance(families, dict) or not families:
        _fail(where, "families", "must be a non-empty JSON object of family -> source branch")
    return {name: _string(source, where, f"families.{name}") for name, source in families.items()}


def _module(value: object, where: str) -> Module:
    obj = _object(value, where, "module", ("ini", "manifest", "files"))
    if not isinstance(obj["ini"], dict):
        _fail(where, "module.ini", "must be a JSON object of sections")
    ini: dict[str, dict[str, str]] = {}
    for section, rows in obj["ini"].items():
        field = f"module.ini.{section}"
        if not isinstance(rows, dict):
            _fail(where, field, "must be a JSON object of key/value strings")
        # A line break, or a bracket/separator in the wrong place, would write a different ini than the fixture says.
        _ini_text(section, where, field, "\r\n[]")
        ini[section] = {
            _ini_text(key, where, f"{field}.{key}", "\r\n=:"): _ini_text(
                _string(text, where, f"{field}.{key}"), where, f"{field}.{key}", "\r\n"
            )
            for key, text in rows.items()
        }
    if not isinstance(obj["manifest"], dict):
        _fail(where, "module.manifest", "must be a JSON object")
    if not isinstance(obj["files"], dict):
        _fail(where, "module.files", "must be a JSON object of path -> lines")
    files: dict[str, list[str]] = {}
    for rel, lines in obj["files"].items():
        path = PurePosixPath(rel)
        if not path.parts or path.is_absolute() or ".." in path.parts or "\0" in rel:
            _fail(where, "module.files", f"unsafe path {rel!r}: must be relative and stay inside the module directory")
        if path.parts[0] in RUNNER_WRITES:  # a write would follow the shipped-code link into src/
            _fail(where, "module.files", f"{rel!r} is written by the runner, never by a fixture")
        if path.as_posix() in files:
            _fail(where, "module.files", f"{rel!r} names a file already listed")
        files[path.as_posix()] = _strings(lines, where, f"module.files[{rel!r}]")
    folders = {parent.as_posix() for name in files for parent in PurePosixPath(name).parents}
    for name in files:
        if name in folders:
            _fail(where, "module.files", f"{name!r} is both a file and the directory of another listed file")
    return Module(ini, obj["manifest"], files)


def _upstream(value: object, where: str) -> dict[tuple[str, int], list[str] | None]:
    if not isinstance(value, dict):
        _fail(where, "upstream", "must be a JSON object of '<name> <TYPE>' -> RR texts")
    zone: dict[tuple[str, int], list[str] | None] = {}
    for key, texts in value.items():
        name, qtype = _question(key, where, f"upstream[{key!r}]")
        if name != name.lower():
            _fail(where, f"upstream[{key!r}]", "the name must be lower case")
        if texts is not None:  # null: Unbound gives no reply
            _rrs(texts, where, f"upstream[{key!r}]")  # rr_from_text must accept every record
        if (name, qtype) in zone:
            _fail(where, f"upstream[{key!r}]", "the same question is already listed under another spelling")
        zone[(name, qtype)] = None if texts is None else list(texts)
    return zone


def _wire_hex(text: str, where: str, field: str) -> bytes:
    if not re.fullmatch(r"(?:[0-9a-f]{2})*", text):  # bytes.fromhex alone takes spaces and upper case
        _fail(where, field, f"{text!r} must be lower-case hex of whole bytes")
    if len(text) > 2 * 0xFFFF:
        _fail(where, field, f"{len(text) // 2} bytes: a DNS message has at most 65535")
    return bytes.fromhex(text)


def _query(value: object, where: str) -> Query:
    obj = _object(value, where, "query", (), ("name", "type", "wire_hex", "client", "transport"))
    if "wire_hex" in obj:
        if "name" in obj or "type" in obj:
            _fail(where, "query.wire_hex", "excludes query.name and query.type")
        wire = _wire_hex(_string(obj["wire_hex"], where, "query.wire_hex"), where, "query.wire_hex")
    else:
        for key in ("name", "type"):
            if key not in obj:
                _fail(where, f"query.{key}", "missing: a query is a name and a type, or wire_hex")
        name = _wire_name(_string(obj["name"], where, "query.name"), where, "query.name")
        wire = build_query(name, _qtype(_string(obj["type"], where, "query.type"), where, "query.type"))
    client = _string(obj.get("client", DEFAULT_CLIENT), where, "query.client")
    try:
        ipaddress.ip_address(client)
    except ValueError:
        _fail(where, "query.client", f"not an IP address: {client!r}")
    return Query(wire, client, _choice(obj.get("transport", "UDP"), where, "query.transport", TRANSPORTS))


def _expect(value: object, where: str) -> Expect:
    obj = _object(value, where, "expect", ("decision", "forwards"), ("rcode", "answer", "authority", "tc"))
    decision = _choice(obj["decision"], where, "expect.decision", DECISIONS)
    forwards = _strings(obj["forwards"], where, "expect.forwards")
    for position, text in enumerate(forwards):
        _question(text, where, f"expect.forwards[{position}]")
    if decision == "drop":
        for key in ("rcode", "answer", "authority", "tc"):
            if key in obj:
                _fail(where, f"expect.{key}", "unknown key: a drop has no ANSWER")
        if forwards:
            _fail(where, "expect.forwards", "must be empty for a drop")
        return Expect(decision, ())
    for key in ("rcode", "answer", "authority"):
        if key not in obj:
            _fail(where, f"expect.{key}", "missing")
    tc = obj.get("tc", False)
    if not isinstance(tc, bool):
        _fail(where, "expect.tc", f"must be true or false, got {tc!r}")
    return Expect(
        decision,
        tuple(forwards),
        _choice(obj["rcode"], where, "expect.rcode", RCODES),
        _rrs(obj["answer"], where, "expect.answer"),
        _rrs(obj["authority"], where, "expect.authority"),
        tc,
    )


def _case(item: object, index: int, where: str, families: Collection[str], seen: set[str]) -> Case:
    where_case = f"{where}: cases[{index}]"
    if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]:
        where_case = f"{where}: case {item['id']!r}"  # every later error names the case
    obj = _object(item, where_case, "", ("id", "family", "description", "query", "expect"))
    case_id = _string(obj["id"], where_case, "id")
    if not case_id:
        _fail(where_case, "id", "must not be empty")
    if case_id in seen:
        _fail(where_case, "id", "duplicate within the file")
    seen.add(case_id)
    family = _choice(obj["family"], where_case, "family", families)
    description = _string(obj["description"], where_case, "description")
    if not description:
        _fail(where_case, "description", "must say what behaviour is pinned")

    return Case(
        case_id,
        family,
        description,
        _query(obj["query"], where_case),
        _expect(obj["expect"], where_case),
    )


def load_scenario(path: Path, families: Collection[str]) -> Scenario:
    where = path.name
    doc = _object(_read_json(path), where, "", ("schema", "description", "module", "upstream", "cases"))
    _schema(doc, where)
    description = _string(doc["description"], where, "description")
    module = _module(doc["module"], where)
    upstream = _upstream(doc["upstream"], where)
    if not isinstance(doc["cases"], list) or not doc["cases"]:
        _fail(where, "cases", "must be a non-empty list")
    seen: set[str] = set()
    cases = tuple(_case(item, index, where, families, seen) for index, item in enumerate(doc["cases"]))
    return Scenario(where, description, module, upstream, cases)


FAMILIES = load_families(FIXTURES / "families.json")
SCENARIO_FILES = sorted(path for path in FIXTURES.glob("*.json") if path.name != "families.json")


# --- the runner: the shipped decider, driven over the decision protocol -----------------------------------------


def write_module(root: Path, module: Module) -> None:
    """The scenario's module directory: the shipped decider code linked in, then what PHP would write."""
    for name in SHIPPED_MODULES:
        (root / name).symlink_to(SHIPPED_DIR / name)
    ini = "".join(
        f"[{section}]\n" + "".join(f"{key} = {text}\n" for key, text in rows.items()) + "\n"
        for section, rows in module.ini.items()
    )
    (root / "pfb_unbound.ini").write_text(ini, encoding="utf-8")
    (root / "pfb_py_sources.json").write_text(json.dumps(module.manifest), encoding="utf-8")
    for rel, lines in module.files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")


class RecordingUnbound(FakeUnbound):
    """FakeUnbound that keeps each reply it gave, so a relayed answer can be told from a rewritten one by its bytes.
    A question the zone lists as None is silent: it is recorded and answered with b"", the empty REPLY."""

    def __init__(self, zone: dict[tuple[str, int], list[str] | None]) -> None:
        super().__init__({key: texts for key, texts in zone.items() if texts is not None})
        self.silent = {key for key, texts in zone.items() if texts is None}
        self.replies: list[bytes] = []

    def answer(self, wire: bytes) -> bytes:
        question = dnswire.parse(wire).questions[0]
        if (question.name.lower(), question.qtype) in self.silent:
            self.queries.append(wire)
            reply = b""
        else:
            reply = super().answer(wire)
        self.replies.append(reply)
        return reply


def _decision(wire: bytes, upstream: RecordingUnbound, answer: bytes | None) -> str:
    """How the exchange went, by the contract's definitions of answer, relay, rewrite and drop."""
    if answer is None:
        return "drop"
    if not upstream.queries:
        return "answer"
    if upstream.queries == [wire] and answer == upstream.replies[0]:
        return "relay"
    if answer not in upstream.replies:
        return "rewrite"
    return "unclassified: the ANSWER is an Unbound reply but not the one relayed FORWARD"


def _rr_text(rr: dnswire.RR) -> str:
    return f"{rr.name} {rr.ttl} class{rr.rclass} {dnswire.type_str(rr.rtype)} {rr.rdata.hex()}"


def _mismatches(
    scenario: Scenario, case: Case, wire: bytes, upstream: RecordingUnbound, answer: bytes | None
) -> list[str]:
    """One line per way the exchange differs from what `case` expects; [] when it is the expected decision."""
    expect = case.expect
    forwards = [
        f"{question.name} {_type_text(question.qtype)}"
        for query in upstream.queries
        for question in dnswire.parse(query).questions
    ]
    compared: list[tuple[str, object, object]] = [
        ("decision", expect.decision, _decision(wire, upstream, answer)),
        ("forwards", list(expect.forwards), forwards),
    ]
    if answer is not None and expect.decision != "drop":  # a drop/non-drop disagreement is the decision's line
        reply = dnswire.parse(answer)
        rcode = next((name for name, number in RCODES.items() if number == reply.rcode), f"RCODE{reply.rcode}")
        compared += [
            ("rcode", expect.rcode, rcode),
            ("answer", [_rr_text(rr) for rr in expect.answer], [_rr_text(rr) for rr in reply.answers]),
            ("authority", [_rr_text(rr) for rr in expect.authority], [_rr_text(rr) for rr in reply.authority]),
            ("tc", expect.tc, bool(reply.flags & dnswire.TC)),
        ]
    return [
        f"{scenario.name}: case {case.id!r}: {field}: expected {want!r}, got {got!r}"
        for field, want, got in compared
        if want != got
    ]


async def _exchange(gateway: DecisionGateway, query: Query, upstream: RecordingUnbound, frame_id: int) -> bytes | None:
    """One QUERY as the gateway sends it, each FORWARD answered from `upstream`: the ANSWER's wire, None for a DROP."""
    client = query.client.encode("ascii")
    transport = TRANSPORTS.index(query.transport)
    await gateway.send(QUERY, frame_id, bytes([transport, len(client)]) + client + b"\x00\x00\x00" + query.wire)
    while True:
        ftype, got, payload = await gateway.recv()
        assert got == frame_id
        if ftype == ANSWER:
            return payload
        if ftype == decision_service.DROP:
            return None
        assert ftype == FORWARD, f"frame type {ftype}: want FORWARD, ANSWER or DROP"
        await gateway.send(REPLY, frame_id, upstream.answer(payload))


async def _drive(booted: Booted, scenario: Scenario) -> tuple[list[str], list[str]]:
    """Every case in file order against the ONE booted decider, over a socketpair, as the Go gateway would: returns the
    mismatches and the problems the decision service logged."""
    gateway_end, decider_end = socket.socketpair()
    problems: list[str] = []
    resolve = pfb_dns_proxy.Frontend(booted.module).resolve
    service = asyncio.ensure_future(decision_service.serve(decider_end, resolve, WATCHDOG, problems.append))
    reader, writer = await asyncio.open_connection(sock=gateway_end)
    gateway = DecisionGateway(reader, writer)
    mismatches: list[str] = []
    try:
        assert await gateway.recv() == (READY, 0, b"")
        for frame_id, case in enumerate(scenario.cases, start=1):
            upstream = RecordingUnbound(scenario.upstream)
            query = case.query
            answer = await _exchange(gateway, query, upstream, frame_id)
            mismatches += _mismatches(scenario, case, query.wire, upstream, answer)
    finally:
        writer.close()
        await watchdog(service, "the decision service to end")
    return mismatches, problems


@pytest.fixture(params=SCENARIO_FILES, ids=lambda path: path.stem)
def scenario(request: pytest.FixtureRequest) -> Scenario:
    return load_scenario(request.param, FAMILIES)


@pytest.fixture
def module_dir(tmp_path: Path, scenario: Scenario) -> Path:
    """The scenario's module directory, in place of conftest's default one (`booted` boots whatever this holds)."""
    write_module(tmp_path, scenario.module)
    return tmp_path


def test_the_decider_makes_every_decision_the_scenario_expects(scenario: Scenario, booted: Booted) -> None:
    mismatches, problems = asyncio.run(_drive(booted, scenario))
    assert problems == []
    assert not mismatches, "\n".join(mismatches)


# --- the loader refuses a bad fixture, loudly --------------------------------------------------------------------


def _good() -> dict[str, Any]:
    """The smallest valid scenario; each hostile row below breaks one thing in a copy of it."""
    return {
        "schema": 2,
        "description": "one unlisted name",
        "module": {
            "ini": {"MAIN": {"python_enable": "true"}},
            "manifest": {"version": 1, "config": {}, "feeds": []},
            "files": {"pfb_py_raw/feed.txt": ["listed.example"]},
        },
        "upstream": {"allowed.example. A": ["allowed.example. 300 IN A 192.0.2.77"]},
        "cases": [
            {
                "id": "good",
                "family": "relay",
                "description": "an unlisted name is relayed unchanged",
                "query": {"name": "allowed.example.", "type": "A"},
                "expect": {
                    "decision": "relay",
                    "forwards": ["allowed.example. A"],
                    "rcode": "NOERROR",
                    "answer": ["allowed.example. 300 IN A 192.0.2.77"],
                    "authority": [],
                },
            }
        ],
    }


def _bad(tmp_path: Path, mutate: Callable[[dict[str, Any]], object]) -> str:
    """The loader's refusal of `_good()` after `mutate`d: its message."""
    doc = _good()
    mutate(doc)
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(FixtureError) as refusal:
        load_scenario(path, FAMILIES)
    return str(refusal.value)


def _load(tmp_path: Path, mutate: Callable[[dict[str, Any]], object]) -> Scenario:
    """The loader's reading of `_good()` after `mutate`d."""
    doc = _good()
    mutate(doc)
    path = tmp_path / "good.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return load_scenario(path, FAMILIES)


def test_a_minimal_valid_scenario_loads_with_the_defaults_filled_in(tmp_path: Path) -> None:
    [case] = _load(tmp_path, lambda doc: None).cases
    assert (case.id, case.family, case.query) == (
        "good",
        "relay",
        Query(build_query("allowed.example.", 1), DEFAULT_CLIENT, "UDP"),
    )
    assert case.expect.rcode == "NOERROR"
    assert case.expect.tc is False


def test_a_wire_hex_query_loads_as_exactly_those_bytes_with_the_defaults(tmp_path: Path) -> None:
    [case] = _load(tmp_path, lambda doc: doc["cases"][0].update(query={"wire_hex": "00ff10"})).cases
    assert case.query == Query(b"\x00\xff\x10", DEFAULT_CLIENT, "UDP")


def test_a_wire_hex_query_takes_a_client_and_a_transport_too(tmp_path: Path) -> None:
    query = {"wire_hex": "", "client": "2001:db8::1", "transport": "DoT"}
    [case] = _load(tmp_path, lambda doc: doc["cases"][0].update(query=query)).cases
    assert case.query == Query(b"", "2001:db8::1", "DoT")


def test_a_wire_hex_query_of_the_largest_dns_message_loads(tmp_path: Path) -> None:
    [case] = _load(tmp_path, lambda doc: doc["cases"][0].update(query={"wire_hex": "00" * 0xFFFF})).cases
    assert len(case.query.wire) == 0xFFFF


def test_a_drop_expectation_loads(tmp_path: Path) -> None:
    expect = {"decision": "drop", "forwards": []}
    [case] = _load(tmp_path, lambda doc: doc["cases"][0].update(expect=expect)).cases
    assert case.expect == Expect("drop", ())


def test_an_upstream_null_loads_as_unbound_giving_no_reply(tmp_path: Path) -> None:
    scenario = _load(tmp_path, lambda doc: doc["upstream"].update({"silent.example. A": None}))
    assert scenario.upstream[("silent.example.", 1)] is None


# (what is wrong, how the valid scenario is broken, what the message must name)
HOSTILE: list[tuple[str, Callable[[dict[str, Any]], object], tuple[str, ...]]] = [
    ("schema 1, the old version", lambda d: d.update(schema=1), ("bad.json", "schema")),
    ("schema 3", lambda d: d.update(schema=3), ("bad.json", "schema")),
    ("schema as a string", lambda d: d.update(schema="2"), ("bad.json", "schema")),
    ("schema missing", lambda d: d.pop("schema"), ("bad.json", "schema")),
    ("schema true", lambda d: d.update(schema=True), ("bad.json", "schema")),
    ("schema 2.0", lambda d: d.update(schema=2.0), ("bad.json", "schema")),
    ("NaN, which only Python reads", lambda d: d["module"]["manifest"].update(x=float("nan")), ("bad.json", "NaN")),
    ("no cases", lambda d: d.update(cases=[]), ("bad.json", "cases")),
    ("empty case id", lambda d: d["cases"][0].update(id=""), ("bad.json", "cases[0]", "id")),
    ("empty case description", lambda d: d["cases"][0].update(description=""), ("bad.json", "'good'", "description")),
    ("client not an IP", lambda d: d["cases"][0]["query"].update(client="host.example"), ("'good'", "query.client")),
    ("unknown transport", lambda d: d["cases"][0]["query"].update(transport="QUIC"), ("'good'", "query.transport")),
    ("TYPE65536", lambda d: d["cases"][0]["query"].update(type="TYPE65536"), ("'good'", "query.type")),
    ("TYPE with 5000 digits", lambda d: d["cases"][0]["query"].update(type="TYPE" + "9" * 5000), ("query.type",)),
    ("unknown rcode", lambda d: d["cases"][0]["expect"].update(rcode="NOPE"), ("'good'", "expect.rcode")),
    (
        "upstream name without the trailing dot",
        lambda d: d.update(upstream={"allowed.example A": []}),
        ("bad.json", "upstream['allowed.example A']"),
    ),
    (
        "upstream name in upper case",
        lambda d: d.update(upstream={"Allowed.example. A": []}),
        ("bad.json", "upstream['Allowed.example. A']", "lower case"),
    ),
    (
        "one upstream question under two spellings",
        lambda d: d["upstream"].update({"allowed.example. TYPE1": []}),
        ("bad.json", "upstream['allowed.example. TYPE1']", "already listed"),
    ),
    (
        "ini value carrying a new section",
        lambda d: d["module"]["ini"]["MAIN"].update(python_enable="true\n[X]"),
        ("bad.json", "module.ini.MAIN.python_enable"),
    ),
    (
        "ini section name closing early",
        lambda d: d["module"]["ini"].update({"A]\nB": {}}),
        ("bad.json", "module.ini.A]"),
    ),
    (
        "ini key carrying its own value",
        lambda d: d["module"]["ini"]["MAIN"].update({"a=b": "c"}),
        ("bad.json", "module.ini.MAIN.a=b"),
    ),
    (
        "files under the shipped decider's link",
        lambda d: d["module"]["files"].update({"pfb_unbound.py/x": ["x"]}),
        ("bad.json", "module.files", "runner"),
    ),
    (
        "files naming one file twice",
        lambda d: d["module"]["files"].update({"./pfb_py_raw/feed.txt": ["x"]}),
        ("bad.json", "module.files", "already listed"),
    ),
    (
        "files using a file as a directory",
        lambda d: d["module"]["files"].update({"pfb_py_raw/feed.txt/x": ["x"]}),
        ("bad.json", "module.files", "directory"),
    ),
    ("files path with a NUL", lambda d: d["module"]["files"].update({"a\0b": ["x"]}), ("bad.json", "module.files")),
    ("unknown family", lambda d: d["cases"][0].update(family="nonesuch"), ("bad.json", "'good'", "family")),
    ("unknown top-level key", lambda d: d.update(extra=1), ("bad.json", "extra")),
    ("unknown key in a case", lambda d: d["cases"][0].update(extra=1), ("bad.json", "'good'", "extra")),
    (
        "missing expect.decision",
        lambda d: d["cases"][0]["expect"].pop("decision"),
        ("bad.json", "'good'", "expect.decision"),
    ),
    (
        "decision 'block'",
        lambda d: d["cases"][0]["expect"].update(decision="block"),
        ("bad.json", "'good'", "expect.decision"),
    ),
    ("query type BOGUS", lambda d: d["cases"][0]["query"].update(type="BOGUS"), ("bad.json", "'good'", "query.type")),
    (
        "files path climbing out",
        lambda d: d["module"]["files"].update({"../x": ["x"]}),
        ("bad.json", "module.files", "../x"),
    ),
    (
        "files absolute path",
        lambda d: d["module"]["files"].update({"/etc/x": ["x"]}),
        ("bad.json", "module.files", "/etc/x"),
    ),
    (
        "files overwriting the shipped decider",
        lambda d: d["module"]["files"].update({"pfb_unbound.py": ["x"]}),
        ("bad.json", "module.files", "pfb_unbound.py", "runner"),
    ),
    (
        "files overwriting the manifest through a dot path",
        lambda d: d["module"]["files"].update({"./pfb_py_sources.json": ["x"]}),
        ("bad.json", "module.files", "pfb_py_sources.json", "runner"),
    ),
    (
        "ini value that is not a string",
        lambda d: d["module"]["ini"]["MAIN"].update(python_enable=True),
        ("bad.json", "module.ini.MAIN.python_enable"),
    ),
    (
        "duplicate case id",
        lambda d: d["cases"].append(copy.deepcopy(d["cases"][0])),
        ("bad.json", "'good'", "id", "duplicate"),
    ),
    (
        "answer text rr_from_text rejects",
        lambda d: d["cases"][0]["expect"].update(answer=["allowed.example. 300 IN A not-an-address"]),
        ("bad.json", "'good'", "expect.answer[0]"),
    ),
    (
        "upstream text rr_from_text rejects",
        lambda d: d["upstream"].update({"allowed.example. A": ["allowed.example. 300 IN MX 10 mail.example."]}),
        ("bad.json", "upstream['allowed.example. A']"),
    ),
    (
        "forward that is not '<name> <TYPE>'",
        lambda d: d["cases"][0]["expect"].update(forwards=["allowed.example."]),
        ("bad.json", "'good'", "expect.forwards[0]"),
    ),
    (
        "wire_hex with a name too",
        lambda d: d["cases"][0]["query"].update(wire_hex="00"),
        ("bad.json", "'good'", "query.wire_hex"),
    ),
    (
        "neither name nor wire_hex",
        lambda d: d["cases"][0].update(query={}),
        ("bad.json", "'good'", "query", "wire_hex"),
    ),
    ("name without type", lambda d: d["cases"][0]["query"].pop("type"), ("bad.json", "'good'", "query.type")),
    ("type without name", lambda d: d["cases"][0]["query"].pop("name"), ("bad.json", "'good'", "query.name")),
    (
        "wire_hex in upper case",
        lambda d: d["cases"][0].update(query={"wire_hex": "AB"}),
        ("bad.json", "'good'", "query.wire_hex"),
    ),
    (
        "wire_hex of odd length",
        lambda d: d["cases"][0].update(query={"wire_hex": "abc"}),
        ("bad.json", "'good'", "query.wire_hex"),
    ),
    (
        "wire_hex that is not hex",
        lambda d: d["cases"][0].update(query={"wire_hex": "zz"}),
        ("bad.json", "'good'", "query.wire_hex"),
    ),
    (
        "wire_hex with a space",
        lambda d: d["cases"][0].update(query={"wire_hex": "ab cd"}),
        ("bad.json", "'good'", "query.wire_hex"),
    ),
    (
        "wire_hex as a number",
        lambda d: d["cases"][0].update(query={"wire_hex": 12}),
        ("bad.json", "'good'", "query.wire_hex"),
    ),
    (
        "wire_hex of 65536 bytes",
        lambda d: d["cases"][0].update(query={"wire_hex": "00" * 65536}),
        ("bad.json", "'good'", "query.wire_hex", "65536"),
    ),
    (
        "drop with an rcode",
        lambda d: d["cases"][0].update(expect={"decision": "drop", "forwards": [], "rcode": "NOERROR"}),
        ("bad.json", "'good'", "expect.rcode"),
    ),
    *[
        (
            f"drop with {key}",
            lambda d, key=key, value=value: d["cases"][0].update(
                expect={"decision": "drop", "forwards": [], key: value}
            ),
            ("bad.json", "'good'", f"expect.{key}"),
        )
        for key, value in (("answer", []), ("authority", []), ("tc", False))
    ],
    (
        "drop with a forward",
        lambda d: d["cases"][0].update(expect={"decision": "drop", "forwards": ["allowed.example. A"]}),
        ("bad.json", "'good'", "expect.forwards"),
    ),
    (
        "non-drop without an rcode",
        lambda d: d["cases"][0]["expect"].pop("rcode"),
        ("bad.json", "'good'", "expect.rcode"),
    ),
    ("tc as a number", lambda d: d["cases"][0]["expect"].update(tc=1), ("bad.json", "'good'", "expect.tc")),
    ("tc as a string", lambda d: d["cases"][0]["expect"].update(tc="true"), ("bad.json", "'good'", "expect.tc")),
    (
        "upstream value a string",
        lambda d: d.update(upstream={"allowed.example. A": "allowed.example. 300 IN A 192.0.2.77"}),
        ("bad.json", "upstream['allowed.example. A']"),
    ),
    (
        "upstream value an object",
        lambda d: d.update(upstream={"allowed.example. A": {}}),
        ("bad.json", "upstream['allowed.example. A']"),
    ),
]


@pytest.mark.parametrize(("mutate", "names"), [row[1:] for row in HOSTILE], ids=[row[0] for row in HOSTILE])
def test_the_loader_refuses_a_bad_scenario_naming_file_case_and_field(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], object], names: tuple[str, ...]
) -> None:
    message = _bad(tmp_path, mutate)
    assert all(name in message for name in names), f"{message!r} must name {names}"


@pytest.mark.parametrize(
    ("document", "reason"),
    [('{"schema": 1, "schema": 2}', "duplicate JSON key 'schema'"), ("[" * 100_000, "recursion")],
    ids=["key written twice", "nesting too deep to read"],
)
def test_the_loader_refuses_an_unreadable_document_as_a_fixture_error(
    tmp_path: Path, document: str, reason: str
) -> None:
    path = tmp_path / "bad.json"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(FixtureError, match=rf"bad\.json: not a readable JSON document: .*{reason}"):
        load_scenario(path, FAMILIES)


@pytest.mark.parametrize(
    "document",
    ['{"schema": 1, "families": {"relay": "x"}}', '{"schema": 2, "families": {"relay": 7}}'],
    ids=["schema", "source"],
)
def test_the_loader_refuses_a_bad_families_index(tmp_path: Path, document: str) -> None:
    path = tmp_path / "families.json"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(FixtureError, match=r"families\.json"):
        load_families(path)


# --- the corpus covers every family -------------------------------------------------------------------------------


def _family_counts() -> tuple[dict[str, int], list[str]]:
    """Cases per family over every scenario the loader accepts, and the refused ones (each fails its own test too)."""
    counts = dict.fromkeys(FAMILIES, 0)
    refused = []
    for path in SCENARIO_FILES:
        try:
            cases = load_scenario(path, FAMILIES).cases
        except FixtureError as refusal:
            refused.append(str(refusal))
            continue
        for case in cases:
            counts[case.family] += 1
    return counts, refused


FAMILY_COUNTS, REFUSED_SCENARIOS = _family_counts()


# The count is in the test id, so the default verbose run lists the cases per family.
@pytest.mark.parametrize("family", list(FAMILY_COUNTS), ids=[f"{name}={n}" for name, n in FAMILY_COUNTS.items()])
def test_every_family_has_cases(family: str) -> None:
    assert FAMILY_COUNTS[family], f"family {family} has no case; refused scenarios not counted: {REFUSED_SCENARIOS}"


def test_every_file_in_the_corpus_is_a_json_document_the_runner_loads() -> None:
    strays = sorted(path.name for path in FIXTURES.iterdir() if path.suffix != ".json")
    assert not strays, f"never loaded, so never run: {strays}"
