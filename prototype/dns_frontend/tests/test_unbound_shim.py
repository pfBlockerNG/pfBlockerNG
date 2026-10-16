"""unbound_shim: real implementations of the names Unbound's pythonmod injects into pfb_unbound.py."""

from __future__ import annotations

import ast
import builtins
import importlib.util
import io
import struct
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import dnswire
import pytest
import unbound_shim as shim

REPO_ROOT = Path(__file__).resolve().parents[3]
PFB_UNBOUND = REPO_ROOT / "src" / "usr" / "local" / "pkg" / "pfblockerng" / "pfb_unbound.py"
STUB = REPO_ROOT / "stubs" / "python" / "unboundmodule.py"


def _names_pfb_unbound_expects_injected() -> list[str]:
    """The `if TYPE_CHECKING: from unboundmodule import (...)` block: pythonmod's injected names."""
    for node in ast.parse(PFB_UNBOUND.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
            for stmt in node.body:
                if isinstance(stmt, ast.ImportFrom) and stmt.module == "unboundmodule":
                    return [alias.name for alias in stmt.names]
    raise AssertionError("pfb_unbound.py no longer declares its injected names under TYPE_CHECKING")


def _load_stub() -> Any:
    spec = importlib.util.spec_from_file_location("stub_unboundmodule", STUB)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    shim.callbacks.clear()
    shim.cache_calls.clear()
    yield
    shim.callbacks.clear()
    shim.cache_calls.clear()


def _qstate(name: str = "blocked.example.", qtype: int = shim.RR_TYPE_A, ip: str = "192.0.2.10") -> Any:
    return shim.module_qstate(shim.query_info(name, qtype), ip, 40000, 0x0100)


# --- the injected surface ------------------------------------------------------------------------


def test_every_name_pfb_unbound_expects_is_provided() -> None:
    expected = _names_pfb_unbound_expects_injected()
    assert [name for name in expected if not hasattr(shim, name)] == []
    assert [name for name in expected if name not in shim.__all__] == []


def test_constants_carry_the_values_of_the_repo_stub() -> None:
    stub = _load_stub()
    mismatched = {
        name: (getattr(shim, name), getattr(stub, name))
        for name in _names_pfb_unbound_expects_injected()
        if isinstance(getattr(stub, name), int) and getattr(shim, name) != getattr(stub, name)
    }
    assert mismatched == {}


def test_log_functions_write_to_the_real_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = io.StringIO()
    monkeypatch.setattr(sys, "__stderr__", captured)
    shim.log_info("alpha")
    shim.log_warn("beta")
    shim.log_err("gamma")
    lines = captured.getvalue().splitlines()
    assert [("info" in line, "alpha" in line) for line in lines[:1]] == [(True, True)]
    assert ("warn" in lines[1], "beta" in lines[1]) == (True, True)
    assert ("error" in lines[2], "gamma" in lines[2]) == (True, True)


def test_register_inplace_callbacks_store_the_callable_per_kind() -> None:
    def callback(*_args: Any, **_kwargs: Any) -> bool:
        return True

    env = shim.module_env()
    results = [
        shim.register_inplace_cb_reply(callback, env, 0),
        shim.register_inplace_cb_reply_cache(callback, env, 0),
        shim.register_inplace_cb_reply_local(callback, env, 0),
        shim.register_inplace_cb_reply_servfail(callback, env, 0),
        shim.register_inplace_cb_query_response(callback, env, 0),
    ]
    assert results == [True] * 5
    assert shim.callbacks == {
        "reply": callback,
        "reply_cache": callback,
        "reply_local": callback,
        "reply_servfail": callback,
        "query_response": callback,
    }


def test_cache_calls_are_recorded_and_do_nothing_else() -> None:
    qstate = _qstate()
    assert shim.storeQueryInCache(qstate, qstate.qinfo, None, 1) is True
    assert shim.invalidateQueryInCache(qstate, qstate.qinfo) is None
    assert shim.cache_calls == [("store", "blocked.example.", 1), ("invalidate", "blocked.example.")]


def test_reply_callback_gets_the_client_address_in_repinfo() -> None:
    seen: dict[str, Any] = {}

    def callback(
        qinfo: Any, qstate: Any, rep: Any, rcode: int, edns: Any, opts: Any, region: Any, **kwargs: Any
    ) -> bool:
        seen.update(qinfo=qinfo, rep=rep, rcode=rcode, kwargs=kwargs)
        return True

    shim.register_inplace_cb_reply(callback, shim.module_env(), 0)
    qstate = _qstate()
    shim.fire_reply_callback("reply", qstate, "REP", 0)
    assert (seen["qinfo"], seen["rep"], seen["rcode"]) == (qstate.qinfo, "REP", 0)
    assert (seen["kwargs"]["repinfo"].addr, seen["kwargs"]["repinfo"].port) == ("192.0.2.10", 40000)


def test_a_raising_reply_callback_is_logged_not_propagated(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = io.StringIO()
    monkeypatch.setattr(sys, "__stderr__", captured)

    def boom(*_args: Any, **_kwargs: Any) -> bool:
        raise RuntimeError("callback exploded")

    shim.register_inplace_cb_reply(boom, shim.module_env(), 0)
    shim.fire_reply_callback("reply", _qstate(), None, 0)
    assert "callback exploded" in captured.getvalue()


def test_firing_a_kind_nobody_registered_is_a_no_op() -> None:
    shim.fire_reply_callback("reply_cache", _qstate(), None, 0)


# --- qstate / query_info -------------------------------------------------------------------------


def test_query_info_exposes_what_the_module_reads() -> None:
    qinfo = shim.query_info("Sub.Blocked.Example.", shim.RR_TYPE_AAAA)
    assert qinfo.qname_str == "Sub.Blocked.Example."  # client case preserved (dns0x20)
    assert qinfo.qname_list == ["Sub", "Blocked", "Example", ""]  # root label included: the TLD is [-2]
    assert qinfo.qname == b"\x03Sub\x07Blocked\x07Example\x00"
    assert (qinfo.qtype, qinfo.qclass, qinfo.qtype_str, qinfo.qclass_str) == (28, 1, "AAAA", "IN")
    assert shim.query_info("x.", 65280).qtype_str == "TYPE65280"


def test_qstate_exposes_client_address_through_the_mesh_reply_list() -> None:
    qstate = _qstate(ip="2001:db8::7")
    reply_list = qstate.mesh_info.reply_list
    assert reply_list.query_reply.addr == "2001:db8::7"
    assert reply_list.next is None


def test_qstate_starts_unfinished_and_ext_state_is_indexable_per_module() -> None:
    qstate = _qstate()
    assert (qstate.return_msg, qstate.return_rcode, qstate.no_cache_store) == (None, shim.RCODE_NOERROR, 0)
    assert list(qstate.edns_opts_back_in_iter) == []
    assert qstate.ext_state[0] == 0
    qstate.ext_state[0] = shim.MODULE_WAIT_MODULE
    assert (qstate.ext_state[0], qstate.ext_state[1]) == (shim.MODULE_WAIT_MODULE, 0)


# --- DNSMessage / reply_info ---------------------------------------------------------------------


def test_dnsmessage_builds_rrsets_in_unbounds_rr_data_layout() -> None:
    qstate = _qstate()
    old = qstate.return_msg
    msg = shim.DNSMessage("blocked.example.", shim.RR_TYPE_A, shim.RR_CLASS_IN, shim.PKT_QR | shim.PKT_RA)
    msg.answer.append("blocked.example. 3600 IN A 10.10.10.1")
    assert msg.set_return_msg(qstate) is True
    assert qstate.return_msg is not old
    rep = qstate.return_msg.rep
    assert (rep.an_numrrsets, rep.flags, rep.security, rep.ttl) == (1, 0x8080, shim.sec_status_unchecked, 3600)
    rrset = rep.rrsets[0]
    assert rrset.rk.type_str == "A"
    assert (rrset.entry.data.count, rrset.entry.data.rrsig_count) == (1, 0)
    assert rrset.entry.data.rr_data[0] == b"\x00\x04\x0a\x0a\x0a\x01"  # 2-byte rdlength + rdata
    assert qstate.return_msg.qinfo.qname_str == "blocked.example."


def test_rrsets_past_the_end_read_as_none_like_the_swig_wrapper() -> None:
    qstate = _qstate()
    msg = shim.DNSMessage("blocked.example.", shim.RR_TYPE_A, shim.RR_CLASS_IN, shim.PKT_QR)
    msg.authority.append("blocked.example. 3600 IN SOA pfb.invalid. nobody.invalid. 1 3600 1200 604800 3600")
    assert msg.set_return_msg(qstate) is True
    rep = qstate.return_msg.rep
    assert (rep.an_numrrsets, rep.ns_numrrsets, rep.rrset_count) == (0, 1, 1)
    assert rep.rrsets[0].rk.type_str == "SOA"
    assert rep.rrsets[1] is None


def test_dnsmessage_with_an_unencodable_rr_fails_without_touching_return_msg() -> None:
    qstate = _qstate()
    msg = shim.DNSMessage("blocked.example.", shim.RR_TYPE_A, shim.RR_CLASS_IN, shim.PKT_QR)
    msg.answer.append("blocked.example. 3600 IN A not-an-address")
    assert msg.set_return_msg(qstate) is False
    assert qstate.return_msg is None


def test_dnsmessage_aa_flag_marks_the_reply_authoritative() -> None:
    qstate = _qstate()
    msg = shim.DNSMessage("blocked.example.", shim.RR_TYPE_A, shim.RR_CLASS_IN, shim.PKT_QR | shim.PKT_AA)
    msg.answer.append("blocked.example. 60 IN A 10.10.10.1")
    assert msg.set_return_msg(qstate) is True
    assert (qstate.return_msg.rep.authoritative, qstate.return_msg.rep.flags & 0x0400) == (1, 0x0400)


def test_upstream_reply_becomes_return_msg_with_uncompressed_cname_rdata() -> None:
    upstream = dnswire.Message(
        7,
        dnswire.QR | dnswire.RD | dnswire.RA,
        [dnswire.Question("alias.example.", dnswire.TYPE_A)],
        answers=[
            dnswire.rr_from_text("alias.example. 300 IN CNAME blocked.example."),
            dnswire.rr_from_text("blocked.example. 300 IN A 192.0.2.99"),
        ],
        additional=[dnswire.make_opt()],
    )
    msg = shim.DnsMsg.from_message(dnswire.parse(dnswire.encode(upstream)))
    rep = msg.rep
    assert (rep.an_numrrsets, rep.ns_numrrsets, rep.ar_numrrsets) == (
        2,
        0,
        0,
    )  # EDNS is dropped, as createResponse does
    assert [rrset.rk.type_str for rrset in rep.rrsets] == ["CNAME", "A"]
    assert rep.rrsets[0].entry.data.rr_data[0] == b"\x00\x11\x07blocked\x07example\x00"
    assert msg.qinfo.qname_str == "alias.example."


def test_rrsig_is_attached_to_the_rrset_it_covers() -> None:
    rrsig = dnswire.RR("a.example.", 46, 1, 60, struct.pack("!H", dnswire.TYPE_A) + bytes(18))
    a_rr = dnswire.rr_from_text("a.example. 60 IN A 192.0.2.1")
    other = dnswire.rr_from_text("b.example. 60 IN A 192.0.2.2")
    upstream = dnswire.Message(1, dnswire.QR, [dnswire.Question("a.example.", 1)], answers=[a_rr, rrsig, other])
    rep = shim.DnsMsg.from_message(dnswire.parse(dnswire.encode(upstream))).rep
    assert rep.an_numrrsets == 2  # the RRSIG is not an rrset of its own
    data = rep.rrsets[0].entry.data
    assert (data.count, data.rrsig_count, len(data.rr_data)) == (1, 1, 2)
    assert rep.rrsets[1].entry.data.rrsig_count == 0


def test_replacement_message_keeps_the_sections_the_front_end_will_encode() -> None:
    qstate = _qstate()
    msg = shim.DNSMessage("blocked.example.", shim.RR_TYPE_A, shim.RR_CLASS_IN, shim.PKT_QR | shim.PKT_RA)
    msg.answer.append("blocked.example. 3600 IN A 10.10.10.1")
    assert msg.set_return_msg(qstate)
    assert [rr.rdata for rr in qstate.return_msg.answer] == [bytes([10, 10, 10, 1])]
    assert qstate.return_msg.authority == [] and qstate.return_msg.additional == []


# --- install / uninstall -------------------------------------------------------------------------


def test_install_injects_names_before_import_and_uninstall_restores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pfb_unbound.py").write_text(
        "import builtins, os\nSEEN = (log_info is builtins.log_info, MODULE_FINISHED, PKT_QR)\nCWD = os.getcwd()\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    previous = object()
    monkeypatch.setattr(builtins, "log_info", previous, raising=False)  # e.g. the pytest stub's value
    monkeypatch.delattr(builtins, "PKT_AD", raising=False)  # a name nobody had set
    monkeypatch.setattr(sys, "path", list(sys.path))

    module = shim.install(str(tmp_path))
    try:
        assert module.SEEN == (True, 6, 1)
        assert module.CWD == str(tmp_path)
        assert sys.modules["pfb_unbound"] is module
        assert builtins.log_info is shim.log_info
        assert builtins.PKT_AD == 64
    finally:
        shim.uninstall()

    assert builtins.log_info is previous
    assert not hasattr(builtins, "PKT_AD")
    assert sys.modules.get("pfb_unbound") is not module


def test_install_failure_leaves_nothing_behind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "pfb_unbound.py").write_text("raise RuntimeError('boom')\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delattr(builtins, "MODULE_FINISHED", raising=False)
    monkeypatch.setattr(sys, "path", list(sys.path))
    with pytest.raises(RuntimeError, match="boom"):
        shim.install(str(tmp_path))
    assert not hasattr(builtins, "MODULE_FINISHED")
    assert str(tmp_path) not in sys.path
