"""The winning rule owns new counts even when public group names collide."""

from __future__ import annotations

import json
import queue
import sqlite3
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from unboundmodule import MODULE_EVENT_NEW, MODULE_FINISHED

import pfb_unbound as P
from tests.test_dns_metric_lifecycle import drain, publish, rows
from tests.test_pfb_unbound import _make_cfg, _make_containers, make_qstate

ROOT = Path(__file__).resolve().parents[1]
BUILTINS = ("DNSBL_IDN", "DNSBL_Homoglyph", "DNSBL_Homoglyph_Suspect", "DNSBL_TLD_Allow", "DNSBL_Regex", "DNSBL_TLD")


def membership(path: Path, groups: list[str], disabled: bool = False) -> None:
    program = r"""
$args = $argv;
require $args[1] . '/tests/php/bootstrap.php';
$GLOBALS['pfb']['dnsbl_info'] = $args[2];
$GLOBALS['pfb']['sqlite_timeout'] = 2000;
$GLOBALS['pfb']['log'] = dirname($args[2]) . '/php.log';
$GLOBALS['pfb']['errlog'] = dirname($args[2]) . '/php.err';
$groups = json_decode($args[3], true);
$GLOBALS['pfb']['alias_dnsbl_configured'] = $groups;
$GLOBALS['pfb']['alias_dnsbl_all'] = $groups;
$GLOBALS['pfb']['dnsbl_info_stats'] = [];
foreach ($groups as $group) {
 $GLOBALS['pfb']['dnsbl_info_stats'][] = [
  'groupname'=>$group, 'timestamp'=>'now', 'entries'=>$args[4] === 'yes' ? 'disabled' : 1];
}
if (!dnsbl_save_stats()) { exit(3); }
"""
    proc = subprocess.run(
        ["php", "-r", program, str(ROOT), str(path), json.dumps(groups), "yes" if disabled else "no"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def epochs(path: Path) -> dict[tuple[str, str], str]:
    return {
        (owner, origin): epoch
        for owner, origin, epoch in rows(path, "SELECT owner,origin,epoch FROM dnsbl_group_epochs")
    }


@pytest.fixture
def owned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "dnsbl.sqlite"
    P.pfb.update(
        pfb_py_dnsbl=str(path),
        pfb_py_resolver=str(tmp_path / "resolver.sqlite"),
        sqlite3_dnsbl_con=True,
        sqlite3_resolver_con=True,
        db_worker=True,
        python_blocking=True,
        python_blacklist=True,
    )
    monkeypatch.setattr(P, "pfb_db_queue", queue.Queue(), raising=False)
    assert P.pfb_db_validate(P.DB_DNSBL)
    assert P.pfb_db_validate(P.DB_RESOLVER)
    assert [r[1] for r in rows(path, "PRAGMA table_info(dnsbl_group_epochs)")] == ["owner", "origin", "epoch"]
    membership(path, ["DNSBL_Regex", "DNSBL_Other"])
    (tmp_path / "regex.raw").write_text("/^feed[0-9]+\\.example$/\n/^both[0-9]+\\.example$/\n")
    (tmp_path / "other.raw").write_text("/^other[0-9]+\\.example$/\n/^both[0-9]+\\.example$/$important\n")
    source = tmp_path / "sources.json"
    source.write_text(
        json.dumps(
            {
                "version": 1,
                "config": {},
                "feeds": [
                    {"raw": "regex.raw", "feed": "R", "group": "DNSBL_Regex", "log_flag": "2", "provenance": "feed"},
                    {"raw": "other.raw", "feed": "O", "group": "DNSBL_Other", "log_flag": "2", "provenance": "feed"},
                ],
            }
        )
    )
    ini = tmp_path / "unbound.ini"
    import base64

    encoded = base64.b64encode(b"^builtin[0-9]+\\.example$#global").decode()
    ini.write_text("[MAIN]\nregex_list = " + encoded + "\n")
    P.pfb.update(pfb_py_sources=str(source), **{"pfb_unbound.ini": str(ini)})
    yield path
    P.pfb["db_worker"] = False
    P._db_close(P.DB_DNSBL)
    P._db_close(P.DB_RESOLVER)


def block(name: str) -> None:
    state = make_qstate(name + ".example.", q_ip="192.0.2.10")
    state.qinfo.qtype_str = "A"
    state.pfb_transport = "DoH"
    assert P.operate(0, MODULE_EVENT_NEW, state, None)
    assert state.ext_state[0] == MODULE_FINISHED


def totals(path: Path) -> list[tuple[Any, ...]]:
    return rows(path, "SELECT owner,origin,groupname,count FROM dns_metric_totals ORDER BY 1,2")


def test_build_evaluate_operate_regex_owners_and_priority(owned: Path) -> None:
    snap = publish()
    for name, owner, origin in [
        ("feed1", "DNSBL_Regex", "custom"),
        ("builtin1", "DNSBL_Regex", "builtin"),
        ("other1", "DNSBL_Other", "custom"),
        ("both1", "DNSBL_Other", "custom"),
    ]:
        reply = P.dnsbl_query_answer(name + ".example", "A")
        assert (
            reply["blocked"],
            reply["group"],
            reply["group_owner"],
            reply["group_origin"],
            reply["group_epoch"],
        ) == (True, "DNSBL_Regex", owner, origin, snap.group_epochs[(owner, origin)])
        block(name)
    drain()
    assert totals(owned) == [
        ("DNSBL_Other", "custom", "DNSBL_Regex", 2),
        ("DNSBL_Regex", "builtin", "DNSBL_Regex", 1),
        ("DNSBL_Regex", "custom", "DNSBL_Regex", 1),
    ]
    assert rows(owned, "SELECT counter FROM dnsbl WHERE groupname='DNSBL_Regex'") == [(4,)]
    assert rows(owned, "SELECT owner,origin,groupname,qtype,transport,count FROM dns_metric_blocks ORDER BY 1,2") == [
        ("DNSBL_Other", "custom", "DNSBL_Regex", "A", "DoH", 2),
        ("DNSBL_Regex", "builtin", "DNSBL_Regex", "A", "DoH", 1),
        ("DNSBL_Regex", "custom", "DNSBL_Regex", "A", "DoH", 1),
    ]
    allowed = P.dnsbl_query_answer("allowed.example", "A")
    assert (allowed["group_owner"], allowed["group_origin"], allowed["group_epoch"]) == ("", "", "")


def test_delete_inflight_mixed_batch_retry_and_history(owned: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    old = publish()
    old_token = old.group_epochs[("DNSBL_Regex", "custom")]
    # This is official pre-upgrade, inseparable report history, not an owned counter seed.
    with sqlite3.connect(owned) as con:
        con.execute("UPDATE dnsbl SET counter=17 WHERE groupname='DNSBL_Regex'")
    block("feed1")
    block("builtin1")
    block("other1")
    drain()
    entered, resume = threading.Event(), threading.Event()
    original = P.evaluate_domain
    errors: list[BaseException] = []

    def held(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        entered.set()
        assert resume.wait(10)
        return result

    def query() -> None:
        try:
            block("feed2")
        except BaseException as error:
            errors.append(error)

    P.decisionDB.clear()
    monkeypatch.setattr(P, "evaluate_domain", held)
    thread = threading.Thread(target=query)
    thread.start()
    try:
        assert entered.wait(10)
        membership(owned, ["DNSBL_Other"])
        membership(owned, ["DNSBL_Regex", "DNSBL_Other"])
        fresh = publish()
        assert fresh.group_epochs[("DNSBL_Regex", "custom")] != old_token
    finally:
        monkeypatch.setattr(P, "evaluate_domain", original)
        resume.set()
        thread.join(10)
    assert not thread.is_alive() and not errors, errors
    block("builtin2")
    block("feed3")
    # Drain genuine events into the same retained maps used by the worker.
    delta: dict[tuple[str, str, str, str], int] = {}
    detail: dict[tuple, int] = {}
    while not P.pfb_db_queue.empty():
        event = P.pfb_db_queue.get_nowait()
        P.pfb_db_queue.task_done()
        if event[0] == "dnsbl":
            key = event[1:5]
            delta[key] = delta.get(key, 0) + 1
            detail_key = event[1:]
            detail[detail_key] = detail.get(detail_key, 0) + 1
    assert len(delta) == 3
    with sqlite3.connect(owned) as con:
        con.execute(
            "CREATE TRIGGER fail_detail BEFORE INSERT ON dns_metric_blocks BEGIN SELECT RAISE(ABORT,'owned retry'); END"
        )
    monkeypatch.setattr(P.time, "sleep", lambda _: None)
    before = totals(owned)
    assert not P._db_flush_dnsbl(delta, detail)
    assert totals(owned) == before
    assert rows(owned, "SELECT counter FROM dnsbl WHERE groupname='DNSBL_Regex'") == [(19,)]
    with sqlite3.connect(owned) as con:
        con.execute("DROP TRIGGER fail_detail")
    assert P._db_flush_dnsbl(delta, detail)
    assert totals(owned) == [
        ("DNSBL_Other", "custom", "DNSBL_Regex", 1),
        ("DNSBL_Regex", "builtin", "DNSBL_Regex", 2),
        ("DNSBL_Regex", "custom", "DNSBL_Regex", 1),
    ]
    assert rows(owned, "SELECT counter FROM dnsbl WHERE groupname='DNSBL_Regex'") == [(21,)]
    assert old.group_epochs[("DNSBL_Regex", "custom")] == old_token
    tokens = epochs(owned)
    membership(owned, ["DNSBL_Regex", "DNSBL_Other"], disabled=True)
    P._db_close(P.DB_DNSBL)
    assert P.pfb_db_validate(P.DB_DNSBL)
    assert epochs(owned) == tokens
    assert totals(owned)[-1][-1] == 1
    assert rows(owned, "SELECT counter FROM dnsbl WHERE groupname='DNSBL_Regex'") == [(21,)]


def test_official_migration_never_infers_colliding_custom_authority(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(path) as con:
        con.execute("CREATE TABLE dnsbl(groupname TEXT,timestamp TEXT,entries INTEGER,counter INTEGER)")
        con.executemany('INSERT INTO dnsbl VALUES (?,"",1,17)', [(g,) for g in (*BUILTINS, "DNSBL_Normal")])
    P.pfb.update(pfb_py_dnsbl=str(path), sqlite3_dnsbl_con=True)
    try:
        assert P.pfb_db_validate(P.DB_DNSBL)
        assert [row[1] for row in rows(path, "PRAGMA table_info(dnsbl_group_epochs)")] == ["owner", "origin", "epoch"]
        tokens = epochs(path)
        assert all((g, "builtin") in tokens and (g, "custom") not in tokens for g in BUILTINS)
        assert ("DNSBL_Normal", "custom") in tokens
        assert totals(path) == []
        assert rows(path, "SELECT DISTINCT counter FROM dnsbl WHERE groupname LIKE 'DNSBL_%'") == [(17,)]
    finally:
        P._db_close(P.DB_DNSBL)


@pytest.mark.parametrize(
    "group,name,overrides",
    [
        ("DNSBL_IDN", "xn--evil.com", {"python_idn": True}),
        ("DNSBL_Homoglyph", "xn--pple-43d.com", {"idn_mode": P.IDN_MODE_CONFUSABLE}),
        (
            "DNSBL_Homoglyph_Suspect",
            "xn--bnk-1ce.com",
            {"idn_mode": P.IDN_MODE_CONFUSABLE, "python_idn_escalate_suspicious": True},
        ),
        ("DNSBL_TLD_Allow", "blocked.net", {"tld_allow": True, "tld_allow_list": ["com"]}),
        ("DNSBL_Regex", "builtin1.example", {}),
        ("DNSBL_TLD", "blocked.bad", {}),
    ],
)
def test_six_builtin_names_and_same_named_custom_keep_distinct_owners(
    group: str, name: str, overrides: dict[str, Any]
) -> None:
    manifest = {
        "version": 1,
        "feeds": [{"raw": "custom", "feed": "C", "group": group, "log_flag": "2", "provenance": "feed"}],
    }
    result = P.build(manifest, {"tld_wildcard_blacklist": ["bad"]}, line_reader=lambda _: ["custom.example"])
    containers = _make_containers(
        dataDB=result.data_db,
        zoneDB=result.zone_db,
        feedGroupIndexDB=result.feed_group_index_db,
        userRegexDB=P._dnsbl_compile_user_regex([("global", r"^builtin[0-9]+\.example$")], False),
    )
    cfg = _make_cfg(dataDB=True, zoneDB=True, userRegexDB=True, **overrides)
    builtin = P.evaluate_domain(name, name, name.rsplit(".", 1)[-1], False, cfg, containers)
    assert builtin.is_found and not builtin.in_whitelist
    assert getattr(builtin, "group_owner", None) == group
    assert (builtin.group, builtin.group_owner, builtin.group_origin) == (group, group, "builtin")
    custom = P.evaluate_domain("custom.example", "custom.example", "example", False, cfg, containers)
    assert (custom.group, custom.group_owner, custom.group_origin) == (group, group, "custom")


def test_custom_list_regex_is_custom_even_with_user_priority() -> None:
    manifest = {
        "version": 1,
        "feeds": [
            {"raw": "custom", "feed": "Custom_List", "group": "DNSBL_Regex", "log_flag": "2", "provenance": "user"}
        ],
    }
    result = P.build(manifest, {}, line_reader=lambda _: [r"/^custom[0-9]+\.example$/"])
    cfg = _make_cfg(userRegexDB=True, important_rules=True)
    containers = _make_containers(userRegexDB=result.user_regex_db)
    decision = P.evaluate_domain("custom1.example", "custom1.example", "example", False, cfg, containers)
    assert decision.is_found
    assert getattr(decision, "group_owner", None) == "DNSBL_Regex"
    assert (decision.group_owner, decision.group_origin) == ("DNSBL_Regex", "custom")


def test_query_reply_keeps_evaluated_owner_token(owned: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    old = publish()
    entered, resume = threading.Event(), threading.Event()
    original = P.evaluate_domain
    replies: list[dict[str, Any]] = []

    def held(*args: Any, **kwargs: Any) -> Any:
        decision = original(*args, **kwargs)
        entered.set()
        assert resume.wait(10)
        return decision

    monkeypatch.setattr(P, "evaluate_domain", held)
    thread = threading.Thread(target=lambda: replies.append(P.dnsbl_query_answer("feed1.example", "A")))
    thread.start()
    try:
        assert entered.wait(10)
        membership(owned, ["DNSBL_Other"])
        membership(owned, ["DNSBL_Regex", "DNSBL_Other"])
        fresh = publish()
        assert fresh.group_epochs[("DNSBL_Regex", "custom")] != old.group_epochs[("DNSBL_Regex", "custom")]
    finally:
        resume.set()
        thread.join(10)
    assert not thread.is_alive()
    assert (replies[0]["group_owner"], replies[0]["group_origin"], replies[0]["group_epoch"]) == (
        "DNSBL_Regex",
        "custom",
        old.group_epochs[("DNSBL_Regex", "custom")],
    )
