"""Decision parity corpus (issue #3772): language-neutral JSON scenarios that the REAL shipped Python decider passes
and a Go decider can run unchanged. A scenario is one module directory (the files PHP writes for the decider) plus
ordered query cases, each with the decision as it appears on the decision protocol (docs/misc/dns-gateway-protocol.md,
"One query"): which FORWARDs the decider sent, and the final ANSWER.

The expectations in fixtures/parity/ are frozen literals derived from the source branch each family names in
families.json, never captured from a run. A fixture the loader refuses is an error naming file, case and field.
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
from frontend_helpers import READY, WATCHDOG, DecisionGateway, FakeUnbound, build_query, watchdog

FIXTURES = Path(__file__).parent / "fixtures" / "parity"
DEFAULT_CLIENT = "192.0.2.10"
TRANSPORTS = ("TCP", "UDP", "DoT", "DoH", "DoQ")  # the QUERY frame's transport byte is this index
DECISIONS = ("answer", "relay", "rewrite")
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
    name: str
    qtype: int
    client: str
    transport: str


@dataclass(frozen=True)
class Expect:
    decision: str
    forwards: tuple[str, ...]
    rcode: str
    answer: tuple[dnswire.RR, ...]
    authority: tuple[dnswire.RR, ...]


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
    upstream: dict[tuple[str, int], list[str]]  # FakeUnbound's zone: (lower-case name, qtype) -> RR texts
    cases: tuple[Case, ...]


# --- the loader: every defect is one FixtureError ---------------------------------------------------------------


def _fail(where: str, field: str, why: str) -> NoReturn:
    raise FixtureError(f"{where}: {field}: {why}")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    for key in keys:
        if keys.count(key) > 1:
            raise ValueError(f"duplicate JSON key {key!r}")
    return dict(pairs)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
    except ValueError as exc:  # JSONDecodeError, a duplicate key, bad UTF-8
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


def _schema(doc: dict[str, Any], where: str) -> None:
    if type(doc["schema"]) is not int or doc["schema"] != 1:  # a bool or 1.0 is not the integer 1
        _fail(where, "schema", f"must be the integer 1, got {doc['schema']!r}")


def _qtype(text: str, where: str, field: str) -> int:
    if text in QTYPES:
        return QTYPES[text]
    numbered = re.fullmatch(r"TYPE([0-9]+)", text)
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
        if not isinstance(rows, dict):
            _fail(where, f"module.ini.{section}", "must be a JSON object of key/value strings")
        ini[section] = {key: _string(text, where, f"module.ini.{section}.{key}") for key, text in rows.items()}
    if not isinstance(obj["manifest"], dict):
        _fail(where, "module.manifest", "must be a JSON object")
    if not isinstance(obj["files"], dict):
        _fail(where, "module.files", "must be a JSON object of path -> lines")
    files: dict[str, list[str]] = {}
    for rel, lines in obj["files"].items():
        parts = PurePosixPath(rel).parts
        if not parts or PurePosixPath(rel).is_absolute() or ".." in parts:
            _fail(where, "module.files", f"unsafe path {rel!r}: must be relative and stay inside the module directory")
        files[rel] = _strings(lines, where, f"module.files[{rel!r}]")
    return Module(ini, obj["manifest"], files)


def _upstream(value: object, where: str) -> dict[tuple[str, int], list[str]]:
    if not isinstance(value, dict):
        _fail(where, "upstream", "must be a JSON object of '<name> <TYPE>' -> RR texts")
    zone: dict[tuple[str, int], list[str]] = {}
    for key, texts in value.items():
        name, qtype = _question(key, where, f"upstream[{key!r}]")
        if name != name.lower():
            _fail(where, f"upstream[{key!r}]", "the name must be lower case")
        _rrs(texts, where, f"upstream[{key!r}]")  # rr_from_text must accept every record
        zone[(name, qtype)] = list(texts)
    return zone


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

    query = _object(obj["query"], where_case, "query", ("name", "type"), ("client", "transport"))
    name = _wire_name(_string(query["name"], where_case, "query.name"), where_case, "query.name")
    qtype = _qtype(_string(query["type"], where_case, "query.type"), where_case, "query.type")
    client = _string(query.get("client", DEFAULT_CLIENT), where_case, "query.client")
    try:
        ipaddress.ip_address(client)
    except ValueError:
        _fail(where_case, "query.client", f"not an IP address: {client!r}")
    transport = _choice(query.get("transport", "UDP"), where_case, "query.transport", TRANSPORTS)

    expect = _object(obj["expect"], where_case, "expect", ("decision", "forwards", "rcode", "answer", "authority"))
    forwards = _strings(expect["forwards"], where_case, "expect.forwards")
    for position, text in enumerate(forwards):
        _question(text, where_case, f"expect.forwards[{position}]")
    return Case(
        case_id,
        family,
        description,
        Query(name, qtype, client, transport),
        Expect(
            _choice(expect["decision"], where_case, "expect.decision", DECISIONS),
            tuple(forwards),
            _choice(expect["rcode"], where_case, "expect.rcode", RCODES),
            _rrs(expect["answer"], where_case, "expect.answer"),
            _rrs(expect["authority"], where_case, "expect.authority"),
        ),
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
    for name in ("pfb_unbound.py", "pfb_dnsbl_regex_rules.py"):
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
    """FakeUnbound that keeps each reply it gave, so a relayed answer can be told from a rewritten one by its bytes."""

    def __init__(self, zone: dict[tuple[str, int], list[str]]) -> None:
        super().__init__(zone)
        self.replies: list[bytes] = []

    def answer(self, wire: bytes) -> bytes:
        reply = super().answer(wire)
        self.replies.append(reply)
        return reply


def _decision(wire: bytes, upstream: RecordingUnbound, answer: bytes) -> str:
    """How the exchange went, by the contract's definitions of answer, relay and rewrite."""
    if not upstream.queries:
        return "answer"
    if upstream.queries == [wire] and answer == upstream.replies[0]:
        return "relay"
    if answer not in upstream.replies:
        return "rewrite"
    return "unclassified: the ANSWER is an Unbound reply but not the one relayed FORWARD"


def _rr_text(rr: dnswire.RR) -> str:
    return f"{rr.name} {rr.ttl} class{rr.rclass} {dnswire.type_str(rr.rtype)} {rr.rdata.hex()}"


def _mismatches(scenario: Scenario, case: Case, wire: bytes, upstream: RecordingUnbound, answer: bytes) -> list[str]:
    """One line per way the exchange differs from what `case` expects; [] when it is the expected decision."""
    reply = dnswire.parse(answer)
    expect = case.expect
    forwards = [
        f"{question.name} {_type_text(question.qtype)}"
        for query in upstream.queries
        for question in dnswire.parse(query).questions
    ]
    rcode = next((name for name, number in RCODES.items() if number == reply.rcode), f"RCODE{reply.rcode}")
    compared = [
        ("decision", expect.decision, _decision(wire, upstream, answer)),
        ("forwards", list(expect.forwards), forwards),
        ("rcode", expect.rcode, rcode),
        ("answer", [_rr_text(rr) for rr in expect.answer], [_rr_text(rr) for rr in reply.answers]),
        ("authority", [_rr_text(rr) for rr in expect.authority], [_rr_text(rr) for rr in reply.authority]),
    ]
    return [
        f"{scenario.name}: case {case.id!r}: {field}: expected {want!r}, got {got!r}"
        for field, want, got in compared
        if want != got
    ]


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
            wire = build_query(case.query.name, case.query.qtype)
            query = case.query
            answer = await gateway.ask(wire, upstream, client=query.client, transport=query.transport, fid=frame_id)
            mismatches += _mismatches(scenario, case, wire, upstream, answer)
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
        "schema": 1,
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


def test_a_minimal_valid_scenario_loads_with_the_defaults_filled_in(tmp_path: Path) -> None:
    path = tmp_path / "good.json"
    path.write_text(json.dumps(_good()), encoding="utf-8")
    [case] = load_scenario(path, FAMILIES).cases
    assert (case.id, case.family, case.query) == ("good", "relay", Query("allowed.example.", 1, DEFAULT_CLIENT, "UDP"))
    assert case.expect.rcode == "NOERROR"


# (what is wrong, how the valid scenario is broken, what the message must name)
HOSTILE: list[tuple[str, Callable[[dict[str, Any]], object], tuple[str, ...]]] = [
    ("schema 2", lambda d: d.update(schema=2), ("bad.json", "schema")),
    ("schema as a string", lambda d: d.update(schema="1"), ("bad.json", "schema")),
    ("schema missing", lambda d: d.pop("schema"), ("bad.json", "schema")),
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
]


@pytest.mark.parametrize(("mutate", "names"), [row[1:] for row in HOSTILE], ids=[row[0] for row in HOSTILE])
def test_the_loader_refuses_a_bad_scenario_naming_file_case_and_field(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], object], names: tuple[str, ...]
) -> None:
    message = _bad(tmp_path, mutate)
    assert all(name in message for name in names), f"{message!r} must name {names}"


def test_the_loader_refuses_a_json_key_written_twice_rather_than_keeping_the_last(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"schema": 1, "schema": 2}', encoding="utf-8")
    with pytest.raises(FixtureError, match=r"bad\.json.*duplicate JSON key 'schema'"):
        load_scenario(path, FAMILIES)


@pytest.mark.parametrize(
    "document",
    ['{"schema": 2, "families": {"relay": "x"}}', '{"schema": 1, "families": {"relay": 7}}'],
    ids=["schema", "source"],
)
def test_the_loader_refuses_a_bad_families_index(tmp_path: Path, document: str) -> None:
    path = tmp_path / "families.json"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(FixtureError, match=r"families\.json"):
        load_families(path)


# --- the corpus covers every family -------------------------------------------------------------------------------


def test_every_family_has_at_least_one_case() -> None:
    counts = dict.fromkeys(FAMILIES, 0)
    for path in SCENARIO_FILES:
        for case in load_scenario(path, FAMILIES).cases:
            counts[case.family] += 1
    print("family  count")
    for family, count in counts.items():
        print(f"{family}  {count}")
    print(f"total  {sum(counts.values())}")
    missing = sorted(family for family, count in counts.items() if count == 0)
    assert not missing, f"families with no case: {' '.join(missing)}"
