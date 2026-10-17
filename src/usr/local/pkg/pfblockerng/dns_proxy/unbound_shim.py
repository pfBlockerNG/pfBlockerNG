"""Real implementations of the names Unbound's pythonmod injects into pfb_unbound.py (`TYPE_CHECKING` block there).

install() exposes them on `builtins` (the technique the repo's test suite uses with the stub) and imports the
shipped pfb_unbound.py UNCHANGED from a module dir. Behaviour mirrors Unbound 1.2x: pythonmod/interface.i
(DNSMessage, rrsets, rr_data), pythonmod_utils.c (createResponse) and services/mesh.c (how a finished query is sent).

Not modelled: the message cache (storeQueryInCache/invalidateQueryInCache are recorded no-ops) and the cache,
local and query_response callbacks, which fire only inside Unbound.
"""

from __future__ import annotations

import builtins
import importlib.util
import os
import struct
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from types import ModuleType
from typing import Any

import dnswire

MODULE_ID = 0

RR_TYPE_A = 1
RR_TYPE_NS = 2
RR_TYPE_CNAME = 5
RR_TYPE_PTR = 12
RR_TYPE_MX = 15
RR_TYPE_TXT = 16
RR_TYPE_SIG = 24
RR_TYPE_AAAA = 28
RR_TYPE_SRV = 33
RR_TYPE_DNAME = 39
RR_TYPE_ANY = 255
RR_CLASS_IN = 1

# pythonmod's runtime constants (interface.i), NOT wire header bits.
PKT_QR = 1
PKT_AA = 2
PKT_TC = 4
PKT_RD = 8
PKT_CD = 16
PKT_RA = 32
PKT_AD = 64
_PKT_WIRE = ((PKT_QR, dnswire.QR), (PKT_AA, dnswire.AA), (PKT_TC, dnswire.TC), (PKT_RD, dnswire.RD),
             (PKT_CD, dnswire.CD), (PKT_RA, dnswire.RA), (PKT_AD, 0x0020))  # fmt: skip

RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3

# util/module.h enum positions
MODULE_EVENT_NEW = 0
MODULE_EVENT_PASS = 1
MODULE_EVENT_MODDONE = 5
MODULE_WAIT_MODULE = 2
MODULE_RESTART_NEXT = 3
MODULE_WAIT_SUBQUERY = 4
MODULE_ERROR = 5
MODULE_FINISHED = 6

sec_status_unchecked = 0
sec_status_bogus = 1
sec_status_indeterminate = 2
sec_status_insecure = 3
sec_status_secure = 4

_MODULE_COUNT = 16

# Registered inplace callbacks by kind ("reply", "reply_cache", "reply_local", "reply_servfail", "query_response").
callbacks: dict[str, Callable[..., Any]] = {}
# storeQueryInCache / invalidateQueryInCache calls, in order: ("store", qname, is_referral) / ("invalidate", qname).
cache_calls: list[tuple[Any, ...]] = []


def _log(level: str, msg: object) -> None:
    # sys.__stderr__, not sys.stderr: init_standard() replaces sys.stderr with a logger.
    print(f"pfb_dns_proxy {level}: {msg}", file=sys.__stderr__, flush=True)


def log_info(msg: object) -> None:
    _log("info", msg)


def log_warn(msg: object) -> None:
    _log("warning", msg)


def log_err(msg: object) -> None:
    _log("error", msg)


def _registrar(kind: str) -> Callable[[Callable[..., Any], Any, int], bool]:
    def register(callback: Callable[..., Any], env: Any, id: int) -> bool:
        callbacks[kind] = callback
        return True

    return register


register_inplace_cb_reply = _registrar("reply")
register_inplace_cb_reply_cache = _registrar("reply_cache")
register_inplace_cb_reply_local = _registrar("reply_local")
register_inplace_cb_reply_servfail = _registrar("reply_servfail")
register_inplace_cb_query_response = _registrar("query_response")


def storeQueryInCache(qstate: Any, qinfo: Any, msgrep: Any, is_referral: int) -> bool:
    cache_calls.append(("store", qinfo.qname_str, is_referral))
    return True


def invalidateQueryInCache(qstate: Any, qinfo: Any) -> None:
    cache_calls.append(("invalidate", qinfo.qname_str))


# --- reply objects -------------------------------------------------------------------------------


@dataclass
class RRSetKey:
    type_str: str


@dataclass
class RRSetData:
    count: int  # RRs, RRSIGs excluded
    rrsig_count: int
    rr_data: list[bytes]  # 2-byte rdlength + uncompressed rdata, the RRs first, then their RRSIGs
    rr_ttl: list[int]


@dataclass
class RRSetEntry:
    data: RRSetData


@dataclass
class RRSet:
    rk: RRSetKey
    entry: RRSetEntry


class RRSets(list[RRSet]):
    """reply_info.rrsets: like pythonmod's wrapper, an index past the end reads as None instead of raising."""

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, int):
            return super().__getitem__(index) if 0 <= index < len(self) else None
        return super().__getitem__(index)


class reply_info:
    def __init__(self, flags: int, rrsets: RRSets, counts: tuple[int, int, int], ttl: int) -> None:
        self.flags = flags  # wire header flags (rcode in the low 4 bits)
        self.ttl = ttl
        self.security = sec_status_unchecked  # createResponse never stamps it; the module does
        self.an_numrrsets, self.ns_numrrsets, self.ar_numrrsets = counts
        self.rrsets = rrsets
        self.authoritative = 0

    @property
    def rrset_count(self) -> int:
        return len(self.rrsets)


class query_info:
    def __init__(self, qname_str: str, qtype: int, qclass: int = RR_CLASS_IN) -> None:
        self.qname_str = qname_str
        self.qtype = qtype
        self.qclass = qclass

    @property
    def qname(self) -> bytes:
        return dnswire.encode_name(self.qname_str)

    @property
    def qname_list(self) -> list[str]:
        """Labels INCLUDING the root label, so the TLD is [-2]; raises on a non-UTF-8 label like the real property."""
        return [label.decode("utf-8") for label in dnswire.name_to_labels(self.qname_str)] + [""]

    @property
    def qtype_str(self) -> str:
        return dnswire.type_str(self.qtype)

    @property
    def qclass_str(self) -> str:
        return "IN" if self.qclass == RR_CLASS_IN else f"CLASS{self.qclass}"


def _rr_data(rdata: bytes) -> bytes:
    return struct.pack("!H", len(rdata)) + rdata


def _build_rrsets(sections: Sequence[Sequence[dnswire.RR]]) -> tuple[RRSets, tuple[int, int, int], int]:
    """Group each section's RRs into rrsets the way parse_create_msg does: one per (owner, type, class), RRSIGs
    attached to the set they cover, EDNS dropped. Returns (rrsets, per-section rrset counts, minimum TTL)."""
    rrsets = RRSets()
    counts = []
    ttls: list[int] = []
    for section in sections:
        before = len(rrsets)
        by_key: dict[tuple[str, int, int], RRSet] = {}
        for rr in section:
            if rr.rtype == dnswire.TYPE_OPT:
                continue
            ttls.append(rr.ttl)
            owner = rr.name.lower()
            if rr.rtype == dnswire.TYPE_RRSIG and len(rr.rdata) >= 2:
                covered = by_key.get((owner, struct.unpack("!H", rr.rdata[:2])[0], rr.rclass))
                if covered is not None:
                    covered.entry.data.rr_data.append(_rr_data(rr.rdata))
                    covered.entry.data.rr_ttl.append(rr.ttl)
                    covered.entry.data.rrsig_count += 1
                    continue
            rrset = by_key.get((owner, rr.rtype, rr.rclass))
            if rrset is None:
                rrset = RRSet(RRSetKey(dnswire.type_str(rr.rtype)), RRSetEntry(RRSetData(0, 0, [], [])))
                by_key[(owner, rr.rtype, rr.rclass)] = rrset
                rrsets.append(rrset)
            data = rrset.entry.data
            data.rr_data.insert(data.count, _rr_data(rr.rdata))
            data.rr_ttl.insert(data.count, rr.ttl)
            data.count += 1
        counts.append(len(rrsets) - before)
    return rrsets, (counts[0], counts[1], counts[2]), min(ttls, default=0)


class DnsMsg:
    """Unbound's dns_msg (`qinfo`, `rep`) plus the RR sections the proxy serialises when it answers itself."""

    def __init__(
        self,
        qinfo: query_info,
        flags: int,
        answer: list[dnswire.RR],
        authority: list[dnswire.RR],
        additional: list[dnswire.RR],
    ) -> None:
        self.qinfo = qinfo
        self.answer, self.authority, self.additional = answer, authority, additional
        rrsets, counts, ttl = _build_rrsets((answer, authority, additional))
        self.rep = reply_info(flags, rrsets, counts, ttl)
        self.rep.authoritative = 1 if flags & dnswire.AA else 0

    @classmethod
    def from_message(cls, message: dnswire.Message, fallback: dnswire.Question | None = None) -> DnsMsg:
        """What createResponse makes of a reply from Unbound: EDNS removed, CD cleared. `fallback` stands in for a
        question section the reply lacks (Unbound's access-control REFUSED has none)."""
        question = message.questions[0] if message.questions else fallback
        if question is None:
            raise ValueError("reply carries no question")
        qinfo = query_info(question.name, question.qtype, question.qclass)
        additional = [rr for rr in message.additional if rr.rtype != dnswire.TYPE_OPT]
        return cls(qinfo, message.flags & ~dnswire.CD, message.answers, message.authority, additional)


class DNSMessage:
    def __init__(
        self, rr_name: str, rr_type: int, rr_class: int = RR_CLASS_IN, query_flags: int = 0, default_ttl: int = 0
    ) -> None:
        self.rr_name = rr_name
        self.rr_type = rr_type
        self.rr_class = rr_class
        self.query_flags = query_flags
        self.default_ttl = default_ttl
        self.question: list[str] = []
        self.answer: list[str] = []
        self.authority: list[str] = []
        self.additional: list[str] = []

    def set_return_msg(self, qstate: Any) -> bool:
        """Replace qstate.return_msg with a fresh message built from the text RRs; False if one cannot be encoded."""
        try:
            dnswire.name_to_labels(self.rr_name)
            sections = [
                [dnswire.rr_from_text(text) for text in section]
                for section in (self.answer, self.authority, self.additional)
            ]
        except ValueError:
            return False
        flags = sum(wire for pkt, wire in _PKT_WIRE if self.query_flags & pkt)
        qstate.return_msg = DnsMsg(query_info(self.rr_name, self.rr_type, self.rr_class), flags, *sections)
        return True


# --- query state ---------------------------------------------------------------------------------


@dataclass
class ReplyAddr:
    addr: str
    port: int = 0


@dataclass
class MeshReply:
    query_reply: ReplyAddr
    next: MeshReply | None = None


@dataclass
class MeshInfo:
    reply_list: MeshReply | None


class ExtState:
    def __init__(self) -> None:
        self._states = [0] * _MODULE_COUNT

    def __getitem__(self, module_id: int) -> int:
        return self._states[module_id]

    def __setitem__(self, module_id: int, state: int) -> None:
        self._states[module_id] = state


class module_env:
    """pythonmod hands init() the real struct; the module only forwards it to register_inplace_cb_*."""

    cfg: Any = None
    worker: Any = None


class module_qstate:
    def __init__(self, qinfo: query_info, client_ip: str, client_port: int = 0, query_flags: int = 0) -> None:
        self.qinfo = qinfo
        self.query_flags = query_flags
        self.return_msg: DnsMsg | None = None
        self.return_rcode = RCODE_NOERROR
        self.ext_state = ExtState()
        self.no_cache_store = 0
        self.edns_opts_back_in_iter: list[Any] = []
        self.mesh_info = MeshInfo(MeshReply(ReplyAddr(client_ip, client_port)))


def fire_reply_callback(kind: str, qstate: module_qstate, rep: reply_info | None, rcode: int) -> None:
    """Invoke the registered inplace callback the way pythonmod does, with the client in `repinfo`."""
    callback = callbacks.get(kind)
    if callback is None:
        return
    assert qstate.mesh_info.reply_list is not None
    try:
        callback(qstate.qinfo, qstate, rep, rcode, None, None, None, repinfo=qstate.mesh_info.reply_list.query_reply)
    except Exception as exc:  # pythonmod logs a failing callback and still sends the reply
        log_err(f"inplace callback {kind} failed: {exc!r}")


# --- install -------------------------------------------------------------------------------------

__all__ = [
    "DNSMessage",
    "MODULE_ERROR",
    "MODULE_EVENT_MODDONE",
    "MODULE_EVENT_NEW",
    "MODULE_EVENT_PASS",
    "MODULE_FINISHED",
    "MODULE_RESTART_NEXT",
    "MODULE_WAIT_MODULE",
    "MODULE_WAIT_SUBQUERY",
    "PKT_AA",
    "PKT_AD",
    "PKT_CD",
    "PKT_QR",
    "PKT_RA",
    "PKT_RD",
    "PKT_TC",
    "RCODE_NOERROR",
    "RCODE_NXDOMAIN",
    "RR_CLASS_IN",
    "RR_TYPE_A",
    "RR_TYPE_AAAA",
    "RR_TYPE_ANY",
    "RR_TYPE_CNAME",
    "RR_TYPE_DNAME",
    "RR_TYPE_MX",
    "RR_TYPE_NS",
    "RR_TYPE_PTR",
    "RR_TYPE_SIG",
    "RR_TYPE_SRV",
    "RR_TYPE_TXT",
    "invalidateQueryInCache",
    "log_err",
    "log_info",
    "log_warn",
    "module_env",
    "module_qstate",
    "query_info",
    "register_inplace_cb_query_response",
    "register_inplace_cb_reply",
    "register_inplace_cb_reply_cache",
    "register_inplace_cb_reply_local",
    "register_inplace_cb_reply_servfail",
    "reply_info",
    "sec_status_bogus",
    "sec_status_indeterminate",
    "sec_status_insecure",
    "sec_status_secure",
    "sec_status_unchecked",
    "storeQueryInCache",
]

_MISSING = object()


@dataclass
class _Saved:
    builtins: dict[str, Any]
    module: ModuleType | None
    module_dir: str


_saved: _Saved | None = None


def install(module_dir: str) -> ModuleType:
    """Inject the names, chdir to `module_dir` (pfb_unbound.ini lives there) and import its pfb_unbound.py."""
    global _saved
    if _saved is not None:
        raise RuntimeError("shim already installed; uninstall() first")
    module_dir = os.path.abspath(module_dir)
    _saved = _Saved(
        {name: getattr(builtins, name, _MISSING) for name in __all__}, sys.modules.get("pfb_unbound"), module_dir
    )
    for name in __all__:
        setattr(builtins, name, globals()[name])
    sys.path.insert(0, module_dir)
    os.chdir(module_dir)
    try:
        spec = importlib.util.spec_from_file_location("pfb_unbound", os.path.join(module_dir, "pfb_unbound.py"))
        if spec is None or spec.loader is None:
            raise ImportError(f"no pfb_unbound.py in {module_dir}")
        module = importlib.util.module_from_spec(spec)
        sys.modules["pfb_unbound"] = module
        spec.loader.exec_module(module)
    except BaseException:
        uninstall()
        raise
    return module


def uninstall() -> None:
    """Undo install(): builtins, sys.modules and sys.path as they were (the CWD stays where it is)."""
    global _saved
    saved, _saved = _saved, None
    if saved is None:
        return
    for name, value in saved.builtins.items():
        if value is _MISSING:
            if hasattr(builtins, name):
                delattr(builtins, name)
        else:
            setattr(builtins, name, value)
    if saved.module is None:
        sys.modules.pop("pfb_unbound", None)
    else:
        sys.modules["pfb_unbound"] = saved.module
    if saved.module_dir in sys.path:
        sys.path.remove(saved.module_dir)
    callbacks.clear()
