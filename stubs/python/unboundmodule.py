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
    "register_inplace_cb_query_response",
    "register_inplace_cb_edns_back_parsed_call",
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
    "PKT_AA",
    # Response codes
    "RCODE_NOERROR",
    "RCODE_NXDOMAIN",
    # Module events / return states
    "MODULE_EVENT_NEW",
    "MODULE_EVENT_PASS",
    "MODULE_EVENT_MODDONE",
    "MODULE_FINISHED",
    "MODULE_WAIT_MODULE",
    "MODULE_WAIT_SUBQUERY",
    "MODULE_RESTART_NEXT",
    "MODULE_ERROR",
    # DNSSEC security status (rep.security)
    "sec_status_unchecked",
    "sec_status_bogus",
    "sec_status_indeterminate",
    "sec_status_insecure",
    "sec_status_secure",
    # Message-cache helpers
    "storeQueryInCache",
    "invalidateQueryInCache",
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
# Packet flags — pythonmod's injected runtime constants (interface.i
# ``%constant uint16_t PKT_QR = 1`` etc.). These are NOT the wire-format
# header bits: ``set_return_msg``/``createResponse`` maps them onto the wire
# internally, and ``reply_info.flags`` carries the WIRE bits (mask those with
# hex literals, e.g. 0x0080 for RA — see pfb_unbound.py's upstream-block
# classifier), never these constants.
# ---------------------------------------------------------------------------
PKT_QR = 1  # QR: set -> response, clear -> query
PKT_AA = 2  # AA: authoritative answer
PKT_RD = 8  # RD: recursion desired (client requests recursive lookup)
PKT_RA = 32  # RA: recursion available (server supports recursion)

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
MODULE_WAIT_SUBQUERY = 4  # Module is waiting for a sub-query it attached to finish
MODULE_RESTART_NEXT = 3  # Restart the module chain at the next module (re-run iterator)
MODULE_ERROR = 5  # Module encountered an error; abort query processing

# ---------------------------------------------------------------------------
# DNSSEC security status — values for ``qstate.return_msg.rep.security``.
# Mirrors the Python-visible SWIG enum (pythonmod/interface.i), which omits the
# C-only ``sec_status_secure_sentinel_fail`` — so ``secure`` is 4 here, not 5.
# A synthesized/injected answer (e.g. a SafeSearch CNAME redirect) must overwrite
# ``security`` to a non-bogus value, else the validator marks the unsigned hop
# bogus -> SERVFAIL.
# ---------------------------------------------------------------------------
sec_status_unchecked = 0  # Not yet validated
sec_status_bogus = 1  # Validation failed (signatures/chain broken)
sec_status_indeterminate = 2  # Insecure, but not authoritatively so
sec_status_insecure = 3  # Authoritatively known to be insecure
sec_status_secure = 4  # Validated secure


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


def register_inplace_cb_query_response(*_: Any) -> bool:
    """Register a callback invoked after a query RESPONSE is received from an
    upstream/authoritative server, BEFORE Unbound finalises the client reply.

    Callback signature::

        def cb(qstate, response, **kwargs):
            ...

    ``response`` is the upstream ``dns_msg`` (``response.rep`` is its
    :class:`reply_info`, whose ``flags`` still carry the upstream header).

    Returns:
        True on success, False on failure.
    """
    return True


def register_inplace_cb_edns_back_parsed_call(*_: Any) -> bool:
    """Register a callback invoked once Unbound has parsed the EDNS of an
    upstream (back-end) response.

    Callback signature::

        def cb(qstate, **kwargs):
            ...

    The upstream's EDNS options are available on ``qstate.edns_opts_back_in``
    (a linked list of options with ``opt_code`` / ``opt_data``).

    Returns:
        True on success, False on failure.
    """
    return True


def storeQueryInCache(qstate: Any, qinfo: Any, msgrep: Any, is_referral: int) -> bool:
    """Insert a query's reply into Unbound's message cache.

    Used by the SafeSearch CNAME redirect to plant a synthesized
    ``orig -> CNAME -> target`` referral so the iterator (re-run via
    :data:`MODULE_RESTART_NEXT`) chases the target itself — working around
    NLnetLabs/unbound #976 (a module-injected CNAME is not chased).

    Args:
        qstate:      The :class:`module_qstate`.
        qinfo:       The :class:`query_info` to key the cache entry on.
        msgrep:      The reply (``qstate.return_msg.rep``) to store.
        is_referral: 1 to store as a referral (lets the iterator continue the
                     chase), 0 to store as a final answer.

    Returns:
        True on success.
    """
    return True


def invalidateQueryInCache(qstate: Any, qinfo: Any) -> None:
    """Evict a query's entry from Unbound's message cache.

    Paired with :func:`storeQueryInCache` so a stale entry never shadows the
    freshly synthesized one.

    Args:
        qstate: The :class:`module_qstate`.
        qinfo:  The :class:`query_info` whose cache entry to invalidate.
    """
    ...


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
    - ``qname_list``  : Labels as a list of strings, **including the empty
                        root label**, e.g. ``["example", "com", ""]`` — this
                        mirrors Unbound's ``GetNameAsLabelList`` (the wire name
                        ends with the zero-length root label). So the real TLD
                        is ``qname_list[-2]``, not ``qname_list[-1]``.
    - ``qtype``       : Numeric RR type (e.g. ``RR_TYPE_A``).
    - ``qclass``      : Numeric RR class (e.g. ``RR_CLASS_IN``).
    - ``local_alias`` : Local alias chain if the name matched a local-data alias.
    """


class reply_info(_Struct):
    """DNS reply / answer data, available as ``qstate.reply``.

    Key attributes (dynamic SWIG surface):

    - ``flags``       : WIRE-format DNS header flags word — mask with hex
                        literals (e.g. ``0x0080`` for RA, ``0x0400`` for AA),
                        NOT the runtime ``PKT_*`` constants above (a different
                        vocabulary; see the packet-flags comment).
    - ``an_numrrsets``: Number of RRsets in the answer section.
    - ``rrsets``      : List of RRset objects in the reply.
    - ``security``    : DNSSEC security status integer -- one of the
                        ``sec_status_*`` constants above (0 = unchecked,
                        4 = secure; NOT 2, which is ``indeterminate``).
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

        Mirrors real Unbound's ``createResponse`` (pythonmod/pythonmod_utils.c):
        it REPLACES any existing ``qstate.return_msg`` wholesale with a fresh
        reply -- it never mutates one in place. On the real box the message's
        RR sections are parsed INTO that fresh reply (``rep.rrsets`` carries
        the answer); this stub deliberately leaves ``rep`` empty as a
        simplification -- tests inspect ``DNSMessage.instances[-1].answer``
        instead. The fresh reply's ``rep.security`` is left at
        :data:`sec_status_unchecked` (0); ``createResponse`` never stamps
        security, so a caller that wants a trusted synthesized reply must
        stamp ``rep.security`` itself, exactly as on the real box -- else the
        validator treats it as unchecked and SERVFAILs it (issue #149 class).

        Also mirrors the Python wrapper's post-success step: sets
        ``rep.authoritative = 1`` iff ``PKT_AA`` is set in this message's
        ``flags``.

        Args:
            qstate: The :class:`module_qstate` whose ``return_msg`` to populate.

        Returns:
            True on success.
        """
        self._qstate = qstate
        qstate.return_msg = types.SimpleNamespace(
            rep=types.SimpleNamespace(security=0, an_numrrsets=0, rrsets=[], authoritative=0),
            qinfo=types.SimpleNamespace(qname_str=self.qname, qname_list=[]),
        )
        if self.flags & PKT_AA:
            qstate.return_msg.rep.authoritative = 1
        return True
