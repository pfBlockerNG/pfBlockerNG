# Development/test stand-in for Unbound's embedded ``unboundmodule``.
#
# Unbound's pythonmod injects these symbols directly into pfb_unbound.py's
# module globals at runtime; pfb_unbound.py never imports this module in
# production (release archives ship only ``src/``). This stub exists so that:
#
#   * static type checkers (Pylance, mypy) can resolve the
#     ``if TYPE_CHECKING: from unboundmodule import ...`` block in pfb_unbound.py;
#   * the pytest suite has a single source of truth for the injected symbols,
#     which tests/conftest.py copies onto ``builtins`` before importing the
#     module under test.
#
# The struct classes are intentionally permissive (``__getattr__`` returns
# ``Any``) because the real Unbound objects are SWIG wrappers with a large,
# dynamic attribute surface that is not worth enumerating here.
from __future__ import annotations

import types
from typing import Any

__all__ = [
    # Logging
    "log_info",
    "log_err",
    "log_warn",
    # Inplace reply callback registration
    "register_inplace_cb_reply",
    "register_inplace_cb_reply_cache",
    "register_inplace_cb_reply_local",
    "register_inplace_cb_reply_servfail",
    # Reply-message helper
    "DNSMessage",
    # RR types / class
    "RR_TYPE_A",
    "RR_TYPE_AAAA",
    "RR_TYPE_ANY",
    "RR_TYPE_CNAME",
    "RR_TYPE_DNAME",
    "RR_TYPE_SIG",
    "RR_TYPE_MX",
    "RR_TYPE_NS",
    "RR_TYPE_PTR",
    "RR_TYPE_SRV",
    "RR_TYPE_TXT",
    "RR_CLASS_IN",
    # Packet flags
    "PKT_QR",
    "PKT_RA",
    "PKT_RD",
    # Response codes
    "RCODE_NOERROR",
    "RCODE_NXDOMAIN",
    # Module events / return states
    "MODULE_EVENT_NEW",
    "MODULE_EVENT_PASS",
    "MODULE_EVENT_MODDONE",
    "MODULE_FINISHED",
    "MODULE_WAIT_MODULE",
    "MODULE_ERROR",
]

# ---------------------------------------------------------------------------
# RR types (IANA DNS resource-record type numbers)
# ---------------------------------------------------------------------------
RR_TYPE_A = 1  # IPv4 host address
RR_TYPE_NS = 2  # Authoritative name server
RR_TYPE_CNAME = 5  # Canonical name (alias)
RR_TYPE_SIG = 24  # DNSSEC signature (legacy; superseded by RRSIG type 46)
RR_TYPE_MX = 15  # Mail exchange
RR_TYPE_PTR = 12  # Domain name pointer (reverse DNS)
RR_TYPE_TXT = 16  # Text record
RR_TYPE_AAAA = 28  # IPv6 host address
RR_TYPE_SRV = 33  # Service locator
RR_TYPE_DNAME = 39  # Non-terminal name redirection (subtree alias)
RR_TYPE_ANY = 255  # Wildcard match — any RR type (query only)

# RR class: Internet (the only class used in practice)
RR_CLASS_IN = 1

# ---------------------------------------------------------------------------
# Packet flags (DNS header bitmask positions)
# ---------------------------------------------------------------------------
PKT_QR = 0x8000  # QR bit: set -> response, clear -> query
PKT_RD = 0x0100  # RD bit: recursion desired (client requests recursive lookup)
PKT_RA = 0x0080  # RA bit: recursion available (server supports recursion)

# ---------------------------------------------------------------------------
# Response codes (RCODE field in DNS header)
# ---------------------------------------------------------------------------
RCODE_NOERROR = 0  # No error; query answered successfully
RCODE_NXDOMAIN = 3  # Non-existent domain; name does not exist

# ---------------------------------------------------------------------------
# Module events — passed as the ``event`` argument to operate()
# ---------------------------------------------------------------------------
MODULE_EVENT_NEW = 0  # New query arrived; first module to handle it
MODULE_EVENT_PASS = 1  # Query passed from a previous module for further processing
MODULE_EVENT_MODDONE = 3  # Downstream module finished; resume this module

# ---------------------------------------------------------------------------
# Module external states — set on qstate.ext_state[id] inside operate()
# ---------------------------------------------------------------------------
MODULE_FINISHED = 4  # Module completed successfully; pass to next module
MODULE_WAIT_MODULE = 2  # Module is waiting for another module to finish
MODULE_ERROR = 5  # Module encountered an error; abort query processing


def log_info(msg: object) -> None:
    """Log an informational message to Unbound's log at level INFO.

    Args:
        msg: Message to log. Converted to str via Unbound's SWIG wrapper.
    """
    ...


def log_err(msg: object) -> None:
    """Log an error message to Unbound's log at level ERROR.

    Args:
        msg: Message to log. Converted to str via Unbound's SWIG wrapper.
    """
    ...


def log_warn(msg: object) -> None:
    """Log a warning message to Unbound's log at level WARN.

    Args:
        msg: Message to log. Converted to str via Unbound's SWIG wrapper.
    """
    ...


def register_inplace_cb_reply(*_: Any) -> bool:
    """Register a callback invoked just before sending any resolved reply.

    The callback is called for every reply regardless of its origin
    (recursive resolution, cache, local data, or SERVFAIL).

    Args:
        cb  (positional 0): Callable with the signature below.
        env (positional 1): Module environment (``env`` parameter of ``init()``).
        id  (positional 2): Module index (``id`` parameter of ``init()``).

    Callback signature::

        def cb(qinfo, qstate, rep, rcode, edns, opt_list_out, region, **kwargs):
            ...

    Returns:
        True on success, False on failure.
    """
    return True


def register_inplace_cb_reply_cache(*_: Any) -> bool:
    """Register a callback invoked just before sending a reply served from cache.

    Same args and callback signature as :func:`register_inplace_cb_reply`.
    The callback's ``qstate`` argument is ``None`` for cache hits (no module
    state was created).

    Returns:
        True on success, False on failure.
    """
    return True


def register_inplace_cb_reply_local(*_: Any) -> bool:
    """Register a callback invoked just before sending a local-data or CHAOS reply.

    Same args and callback signature as :func:`register_inplace_cb_reply`.

    Returns:
        True on success, False on failure.
    """
    return True


def register_inplace_cb_reply_servfail(*_: Any) -> bool:
    """Register a callback invoked just before sending a SERVFAIL reply.

    Same args and callback signature as :func:`register_inplace_cb_reply`.
    The callback's ``rep`` argument is ``None`` (no reply was constructed).

    Returns:
        True on success, False on failure.
    """
    return True


class _Struct:
    """Base for SWIG-like Unbound structs with a dynamic attribute surface."""

    def __getattr__(self, name: str) -> Any: ...

    def __setattr__(self, name: str, value: Any) -> None: ...

    def __getitem__(self, item: Any) -> Any: ...

    def __setitem__(self, key: Any, value: Any) -> None: ...


class module_env(_Struct):
    """Shared services and configuration available to all modules.

    Passed as ``env`` to ``init(id, cfg)`` and accessible as ``qstate.env``
    during ``operate()``. Key attributes (dynamic SWIG surface):

    - ``cfg``    : Unbound configuration object (mirrors ``unbound.conf`` settings).
    - ``worker`` : Per-thread worker reference.
    - ``edns_known_options`` : Registered EDNS option codes.
    """


class module_qstate(_Struct):
    """Per-query state passed to ``operate(id, event, qstate, qdata)``.

    Key attributes (dynamic SWIG surface):

    - ``qinfo``        : :class:`query_info` — the question being resolved.
    - ``return_msg``   : DNS response message to return to the client; set via
                         :meth:`DNSMessage.set_return_msg`.
    - ``return_rcode`` : RCODE to return (e.g. ``RCODE_NOERROR``, ``RCODE_NXDOMAIN``).
    - ``ext_state``    : Indexable by module id; set to one of the
                         ``MODULE_*`` return-state constants before returning
                         from ``operate()``.
    - ``query_flags``  : DNS query flags bitmask (e.g. ``PKT_RD``).
    - ``curmod``       : Index of the module currently processing the query.
    - ``env``          : :class:`module_env` — shared services.
    - ``reply``        : :class:`reply_info` — reply structure (may be None).
    """


class query_info(_Struct):
    """DNS question section data, available as ``qstate.qinfo``.

    Key attributes (dynamic SWIG surface):

    - ``qname``       : Wire-format question name (bytes).
    - ``qname_str``   : Human-readable FQDN string, e.g. ``"example.com."``.
    - ``qname_list``  : Labels as a list of strings (root label excluded),
                        e.g. ``["example", "com"]``.
    - ``qtype``       : Numeric RR type (e.g. ``RR_TYPE_A``).
    - ``qclass``      : Numeric RR class (e.g. ``RR_CLASS_IN``).
    - ``local_alias`` : Local alias chain if the name matched a local-data alias.
    """


class reply_info(_Struct):
    """DNS reply / answer data, available as ``qstate.reply``.

    Key attributes (dynamic SWIG surface):

    - ``flags``       : DNS header flags bitmask (``PKT_QR | PKT_RA | …``).
    - ``an_numrrsets``: Number of RRsets in the answer section.
    - ``rrsets``      : List of RRset objects in the reply.
    - ``security``    : DNSSEC security status integer (2 = secure).
    """


class DNSMessage:
    """Reply-message builder.

    Records every instance on the class so tests can inspect the answer section
    of the reply that operate() constructed before it was discarded.

    Usage in ``operate()``::

        msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN,
                         PKT_QR | PKT_RD | PKT_RA)
        msg.answer.append("example.com. 3600 IN A 0.0.0.0")
        if msg.set_return_msg(qstate):
            qstate.return_rcode = RCODE_NOERROR
    """

    instances: list[DNSMessage] = []

    def __init__(self, qname: str, qtype: int, qclass: int, flags: int) -> None:
        """Create a DNS reply message.

        Args:
            qname:  Question name string, e.g. ``"example.com."``.
            qtype:  RR type constant, e.g. ``RR_TYPE_A``.
            qclass: RR class constant, e.g. ``RR_CLASS_IN``.
            flags:  DNS header flags bitmask, e.g. ``PKT_QR | PKT_RD | PKT_RA``.
        """
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass
        self.flags = flags
        self.answer: list[str] = []  # RR strings to include in the answer section
        self._qstate: Any = None
        DNSMessage.instances.append(self)

    def set_return_msg(self, qstate: Any) -> bool:
        """Attach this message as the response on ``qstate.return_msg``.

        Initialises ``qstate.return_msg`` if not already set, then marks the
        reply as DNSSEC-secure (security = 2) so Unbound accepts it.

        Args:
            qstate: The :class:`module_qstate` whose ``return_msg`` to populate.

        Returns:
            True on success.
        """
        self._qstate = qstate
        if getattr(qstate, "return_msg", None) is None:
            qstate.return_msg = types.SimpleNamespace(
                rep=types.SimpleNamespace(security=0, an_numrrsets=0, rrsets=[]),
                qinfo=types.SimpleNamespace(qname_str=self.qname, qname_list=[]),
            )
        qstate.return_msg.rep.security = 2
        return True
