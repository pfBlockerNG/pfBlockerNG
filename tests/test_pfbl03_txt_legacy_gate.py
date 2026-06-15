"""PFBL-03 Phase 3 -- the deprecated DNS-TXT control transport is OFF by default.

WHY THIS FILE EXISTS
--------------------
DNSBL control moved onto the local privileged command file + CLI (pinned in
``test_pfbl03_control_channel.py``). The old DNS-TXT transport (``drill TXT
python_control.*``) is retained for ONE release behind a new, separate, opt-in
sub-toggle ``python_control_legacy`` -- OFF by default. These tests pin that gate:

  * legacy OFF (the DEFAULT): a ``python_control.`` DNS TXT query is NOT honoured --
    the DNS-TXT path performs no DNSBL control action;
  * legacy ON: the same query IS honoured -- proving the gate is a REAL branch, not an
    always-off path.

Per the repo coverage rules each transition test asserts the BEFORE state first, so a
green proves the gate value CAUSED the outcome. The shared handler
``pfb_apply_control_command`` is exercised transport-agnostically in the sibling file;
here we drive it through the real ``operate()`` DNS-TXT branch.
"""

from __future__ import annotations

import types

from unboundmodule import DNSMessage

import pfb_unbound as P

RR_TXT = 16
MODULE_EVENT_NEW = 0


def _txt_control_qstate(qname: str, q_ip: str = "127.0.0.1") -> types.SimpleNamespace:
    """A localhost DNS TXT query carrying a python_control command (the legacy transport).

    Mirrors the operate() inputs: a numeric TXT qtype, a localhost reply IP, and a
    ``python_control.<cmd>`` qname (trailing dot, as Unbound presents it)."""
    reply_list = types.SimpleNamespace(query_reply=types.SimpleNamespace(addr=q_ip), next=None)
    qinfo = types.SimpleNamespace(
        qname_str=qname,
        qtype=RR_TXT,
        qtype_str="",
        qname_list=qname.rstrip(".").split("."),
    )
    return types.SimpleNamespace(
        qinfo=qinfo,
        mesh_info=types.SimpleNamespace(reply_list=reply_list),
        return_msg=None,
        return_rcode=0,
        ext_state={},
        no_cache_store=0,
    )


class TestLegacyTxtControlGate:
    """Scenario: the DNS-TXT control transport is honoured ONLY when the deprecated
    legacy sub-toggle is explicitly enabled.

    Background:
      * DNSBL Control is enabled (``python_control`` True) -- the parent toggle.
      * A localhost ``python_control.disable`` DNS TXT query is the command under test.
    """

    def test_txt_control_not_honoured_when_legacy_off_default(self) -> None:
        # Given: the legacy DNS-TXT transport is OFF (the DEFAULT) and DNSBL blocking is ON.
        P.pfb["python_control"] = True
        P.pfb["python_control_legacy"] = False
        P.pfb["python_blacklist"] = True
        assert P.pfb["python_blacklist"] is True  # BEFORE: blocking on.

        # When: a localhost python_control.disable DNS TXT query is processed.
        qstate = _txt_control_qstate("python_control.disable.")
        P.operate(0, MODULE_EVENT_NEW, qstate, None)

        # Then: the DNS-TXT path did NOT honour it -- blocking is UNCHANGED (still on), and
        # the control branch produced no TXT reply (it never ran).
        assert P.pfb["python_blacklist"] is True
        assert not any(
            "python_control" in (getattr(ans, "answer", [""]) or [""])[0]
            for ans in DNSMessage.instances
            if getattr(ans, "answer", None)
        )

    def test_txt_control_honoured_when_legacy_on(self) -> None:
        # Given: the legacy DNS-TXT transport is explicitly ON and DNSBL blocking is ON.
        P.pfb["python_control"] = True
        P.pfb["python_control_legacy"] = True
        P.pfb["python_blacklist"] = True
        assert P.pfb["python_blacklist"] is True  # BEFORE: blocking on.

        # When: the SAME localhost python_control.disable DNS TXT query is processed.
        qstate = _txt_control_qstate("python_control.disable.")
        rcd = P.operate(0, MODULE_EVENT_NEW, qstate, None)

        # Then: the DNS-TXT path honoured it -- blocking is now OFF (the disable applied),
        # proving the gate is a real branch rather than an always-off path.
        assert rcd is True
        assert P.pfb["python_blacklist"] is False

    def test_txt_control_inert_when_legacy_on_but_parent_disabled(self) -> None:
        # The deprecated branch still requires the parent DNSBL Control toggle + localhost:
        # with python_control OFF the existing in-branch guard refuses the command even
        # when the legacy transport gate is open.
        P.pfb["python_control"] = False
        P.pfb["python_control_legacy"] = True
        P.pfb["python_blacklist"] = True

        qstate = _txt_control_qstate("python_control.disable.")
        P.operate(0, MODULE_EVENT_NEW, qstate, None)

        # The command was not authorized -> blocking unchanged.
        assert P.pfb["python_blacklist"] is True

    def test_txt_control_inert_when_legacy_on_but_not_localhost(self) -> None:
        # The legacy branch's 127.0.0.1 guard still applies: a non-localhost source is
        # refused even with the legacy gate open and the parent toggle on.
        P.pfb["python_control"] = True
        P.pfb["python_control_legacy"] = True
        P.pfb["python_blacklist"] = True

        qstate = _txt_control_qstate("python_control.disable.", q_ip="192.0.2.50")
        P.operate(0, MODULE_EVENT_NEW, qstate, None)

        assert P.pfb["python_blacklist"] is True
