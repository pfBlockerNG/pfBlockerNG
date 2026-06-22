"""ADR-38 Phase 4 — DNSBL syslog emitter: gate and silent-degrade tests.

Pins the behaviour of _emit_dnsbl_syslog() and its integration at the
get_details_dnsbl() CSV write site.

Coverage mandate (CLAUDE.md test-coverage):
  (a) Toggle branch: syslog_enable=False => no emit; then True => emit.
      The before-state is asserted first so the test proves the flag caused
      the change (not an always-emit path).
  (b) Socket-absent / raising: the handler constructor raises => _syslog_failed
      is latched True, no exception propagates, the DNSBL CSV write and
      resolution path still complete (return value is True, CSV line written).
  (c) Emit-once: a single DNSBL block event fires exactly one syslog emit.
  (d) Body contents: the emitted message includes the pfblockerng ident prefix
      and the syslog_format_dnsbl() key=value body.
"""

from __future__ import annotations

import types
from typing import Any
from unittest.mock import MagicMock

import pfb_unbound

# ---------------------------------------------------------------------------
# Helpers shared by the test classes below.
# ---------------------------------------------------------------------------


def _block_decision(**kw: Any) -> Any:
    """A composed Decision whose DNSBL axis is a block; kw overrides fields."""
    fields: dict[str, Any] = {
        "is_found": True,
        "in_whitelist": False,
        "in_hsts": False,
        "null_blocking": False,
        "nxdomain": False,
        "log_type": "1",
        "b_type": "VIP",
        "p_type": "Python",
        "feed": "TestFeed",
        "group": "TestGroup",
        "b_eval": "bad.example.com",
    }
    fields.update(kw)
    return pfb_unbound.Decision(dnsbl=pfb_unbound.DnsblDecision(**fields))


def _qstate(name: str = "bad.example.com.", qtype: str = "A") -> Any:
    return types.SimpleNamespace(
        qinfo=types.SimpleNamespace(qname_str=name, qtype_str=qtype),
        return_msg=None,
    )


def _run_dnsbl(monkeypatch: Any, name: str = "bad.example.com.") -> list[tuple[str, str]]:
    """Set up and call get_details_dnsbl(); return captured pfb_log calls."""
    key = name.rstrip(".")
    monkeypatch.setitem(pfb_unbound.pfb, "python_nolog", False)
    monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
    monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)
    monkeypatch.setattr(pfb_unbound, "decisionDB", {key: _block_decision()})
    lines: list[tuple[str, str]] = []
    monkeypatch.setattr(pfb_unbound, "pfb_log", lambda path, line: lines.append((path, line)))
    pfb_unbound.get_details_dnsbl("dnsbl", None, _qstate(name), None, {"pfb_addr": "1.2.3.4"})
    return lines


# ---------------------------------------------------------------------------
# (a) Toggle branch: disabled => no emit, then enabled => emit.
# ---------------------------------------------------------------------------


class TestSyslogEmitToggleBranch:
    """Prove the syslog_enable gate is a real branch (not an always-emit path).

    Scenario:
      Given syslog_enable=False (default off).
      When  get_details_dnsbl() processes a DNSBL block event.
      Then  _emit_dnsbl_syslog is NOT called and _syslog_handler stays None.
      ──
      Given syslog_enable=True (enabled).
      When  get_details_dnsbl() processes a DNSBL block event.
      Then  _emit_dnsbl_syslog IS called, the message body is correct, and the
            CSV line is still written (syslog is additive, not a replacement).
    """

    def test_disabled_no_syslog_emit_before_enabled(self, monkeypatch: Any) -> None:
        """BEFORE: syslog_enable=False => no handler created, no emit.

        This is the before-state assertion required by the coverage mandate.
        """
        # Given: syslog off (conftest default)
        assert pfb_unbound.pfb["syslog_enable"] is False

        emitted: list[str] = []

        def _fake_emit(msg: str) -> None:
            emitted.append(msg)

        monkeypatch.setattr(pfb_unbound, "_emit_dnsbl_syslog", _fake_emit)

        _run_dnsbl(monkeypatch)

        # Then: no syslog emit
        assert emitted == [], "disabled: _emit_dnsbl_syslog must NOT be called"
        assert pfb_unbound._syslog_handler is None, "disabled: handler stays None"

    def test_enabled_emits_exactly_once_with_correct_body(self, monkeypatch: Any) -> None:
        """AFTER: syslog_enable=True => exactly one emit with correct body.

        Also asserts the CSV log line is still written (additive, not replacing).
        """
        # Given: syslog enabled
        monkeypatch.setitem(pfb_unbound.pfb, "syslog_enable", True)
        assert pfb_unbound.pfb["syslog_enable"] is True

        emitted: list[str] = []

        def _fake_emit(msg: str) -> None:
            emitted.append(msg)

        monkeypatch.setattr(pfb_unbound, "_emit_dnsbl_syslog", _fake_emit)

        lines = _run_dnsbl(monkeypatch)

        # Then: exactly one syslog emit
        assert len(emitted) == 1, "enabled: _emit_dnsbl_syslog must be called exactly once"

        body = emitted[0]
        # Body must contain all expected DNSBL key=value pairs
        assert "act=dnsbl" in body, "body must contain act=dnsbl"
        assert "qname=bad.example.com" in body, "body must contain qname"
        assert "qip=1.2.3.4" in body, "body must contain qip"
        assert "btype=VIP" in body, "body must contain btype"
        assert "eval=bad.example.com" in body, "body must contain eval"

        # CSV file write still happened (additive, not replacing)
        dnsbl_lines = [line for path, line in lines if path.endswith("dnsbl.log")]
        assert len(dnsbl_lines) == 1, "CSV write must still occur when syslog is enabled"

    def test_toggle_flip_off_then_on_proves_real_branch(self, monkeypatch: Any) -> None:
        """Toggle off => no emit; then toggle on => emit. Before AND after asserted.

        This is the canonical before/after transition test required by CLAUDE.md:
        assert off-state, flip toggle, assert on-state — proving the flag caused it.
        """
        emitted: list[str] = []

        def _fake_emit(msg: str) -> None:
            emitted.append(msg)

        monkeypatch.setattr(pfb_unbound, "_emit_dnsbl_syslog", _fake_emit)

        # --- BEFORE: disabled ---
        assert pfb_unbound.pfb["syslog_enable"] is False
        _run_dnsbl(monkeypatch)
        assert emitted == [], "before (off): no emit"

        # --- AFTER: enabled ---
        monkeypatch.setitem(pfb_unbound.pfb, "syslog_enable", True)
        _run_dnsbl(monkeypatch)
        assert len(emitted) == 1, "after (on): exactly one emit"


# ---------------------------------------------------------------------------
# (b) Silent-degrade: socket absent / constructor raises => no propagation.
# ---------------------------------------------------------------------------


class TestSyslogEmitSilentDegrade:
    """Prove the silent-degrade contract (ADR §2.2.4).

    Scenario:
      Given syslog_enable=True AND the SysLogHandler constructor raises
            (simulating an absent/unreachable socket).
      When  get_details_dnsbl() processes a DNSBL block event.
      Then  no exception propagates (resolution path safe), the DNSBL CSV
            line is still written, get_details_dnsbl returns True, and
            _syslog_failed is latched True (no retry-storm).
    """

    def test_socket_absent_raises_no_exception_and_csv_still_written(self, monkeypatch: Any) -> None:
        """Constructor raises => CSV write completes, no exception, latch set.

        Given: syslog_enable=True, SysLogHandler constructor raises OSError.
        When:  get_details_dnsbl() processes a block.
        Then:  returns True, CSV written, _syslog_failed latched.
        """
        # Given: syslog enabled, handler constructor will raise
        monkeypatch.setitem(pfb_unbound.pfb, "syslog_enable", True)
        assert pfb_unbound._syslog_handler is None
        assert pfb_unbound._syslog_failed is False

        # Patch _PfbSysLogHandler to raise in the constructor
        class _RaisingHandler:
            def __init__(self, **kw: Any) -> None:
                raise OSError("no such socket /var/run/log")

        monkeypatch.setattr(pfb_unbound, "_PfbSysLogHandler", _RaisingHandler)

        lines = _run_dnsbl(monkeypatch)

        # Then: no exception propagated (we reached here); CSV still written
        dnsbl_lines = [line for path, line in lines if path.endswith("dnsbl.log")]
        assert len(dnsbl_lines) == 1, "CSV write must succeed even when syslog raises"

        # Failure latch must be set (no retry-storm)
        assert pfb_unbound._syslog_failed is True, "_syslog_failed must be latched on error"
        assert pfb_unbound._syslog_handler is None, "handler must not be set after constructor failure"

    def test_socket_absent_subsequent_calls_are_no_ops(self, monkeypatch: Any) -> None:
        """After _syslog_failed is latched, further calls skip the handler entirely.

        Given: _syslog_failed already latched from a prior error.
        When:  _emit_dnsbl_syslog is called again (enabled).
        Then:  no handler construction attempted, no exception.
        """
        # Given: latch already set
        monkeypatch.setitem(pfb_unbound.pfb, "syslog_enable", True)
        monkeypatch.setattr(pfb_unbound, "_syslog_failed", True)

        constructor_calls: list[Any] = []

        class _TrackingHandler:
            def __init__(self, **kw: Any) -> None:
                constructor_calls.append(kw)

        monkeypatch.setattr(pfb_unbound, "_PfbSysLogHandler", _TrackingHandler)

        # Call the emitter directly (no exception expected)
        pfb_unbound._emit_dnsbl_syslog("act=dnsbl qname=x.com qip=1.2.3.4 qtype=A btype=VIP eval=x.com")

        assert constructor_calls == [], "constructor must NOT be called when latch is set"

    def test_emit_exception_latches_failure_and_does_not_propagate(self, monkeypatch: Any) -> None:
        """emit() raising latches _syslog_failed and does not propagate.

        Given: syslog_enable=True, handler constructed OK but emit() raises.
        When:  _emit_dnsbl_syslog is called.
        Then:  _syslog_failed becomes True, no exception raised.
        """
        monkeypatch.setitem(pfb_unbound.pfb, "syslog_enable", True)
        assert pfb_unbound._syslog_failed is False

        mock_handler = MagicMock()
        mock_handler.emit.side_effect = OSError("broken pipe")

        class _SuccessHandler:
            def __init__(self, **kw: Any) -> None:
                pass

        monkeypatch.setattr(pfb_unbound, "_PfbSysLogHandler", _SuccessHandler)
        # Pre-wire a mock handler so emit() is what raises
        monkeypatch.setattr(pfb_unbound, "_syslog_handler", mock_handler)

        # Must not raise
        pfb_unbound._emit_dnsbl_syslog("act=dnsbl qname=x.com qip=1.2.3.4 qtype=A btype=VIP eval=x.com")

        assert pfb_unbound._syslog_failed is True, "emit error must latch _syslog_failed"

    def test_get_details_dnsbl_returns_true_when_syslog_raises(self, monkeypatch: Any) -> None:
        """get_details_dnsbl() returns True (resolution continues) even when syslog fails.

        Given: syslog_enable=True, SysLogHandler constructor raises.
        When:  get_details_dnsbl() is called with a block decision.
        Then:  returns True (the DNSBL path completes normally).
        """
        monkeypatch.setitem(pfb_unbound.pfb, "syslog_enable", True)
        monkeypatch.setitem(pfb_unbound.pfb, "python_nolog", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_resolver_con", False)
        monkeypatch.setitem(pfb_unbound.pfb, "sqlite3_dnsbl_con", False)

        class _RaisingHandler:
            def __init__(self, **kw: Any) -> None:
                raise OSError("socket error")

        monkeypatch.setattr(pfb_unbound, "_PfbSysLogHandler", _RaisingHandler)
        monkeypatch.setattr(pfb_unbound, "decisionDB", {"bad.example.com": _block_decision()})
        monkeypatch.setattr(pfb_unbound, "pfb_log", lambda *a: None)

        result = pfb_unbound.get_details_dnsbl("dnsbl", None, _qstate(), None, {"pfb_addr": "1.2.3.4"})

        assert result is True, "get_details_dnsbl must return True even when syslog raises"


# ---------------------------------------------------------------------------
# (c)+(d) Emit body contents and ident prefix.
# ---------------------------------------------------------------------------


class TestSyslogEmitBody:
    """Verify the message body and ident prefix from _emit_dnsbl_syslog directly."""

    def test_message_has_pfblockerng_ident_prefix(self, monkeypatch: Any) -> None:
        """The emitted message begins with 'pfblockerng: ' for syslogd tag routing.

        Scenario:
          Given syslog_enable=True and a functioning handler mock.
          When  _emit_dnsbl_syslog('act=dnsbl qname=...') is called.
          Then  the LogRecord.msg starts with 'pfblockerng: '.
        """
        monkeypatch.setitem(pfb_unbound.pfb, "syslog_enable", True)

        recorded_records: list[Any] = []
        mock_handler = MagicMock()
        mock_handler.emit.side_effect = lambda rec: recorded_records.append(rec)

        monkeypatch.setattr(pfb_unbound, "_syslog_handler", mock_handler)

        body = "act=dnsbl qname=bad.com qip=10.0.0.1 qtype=A btype=VIP eval=bad.com"
        pfb_unbound._emit_dnsbl_syslog(body)

        assert len(recorded_records) == 1
        record = recorded_records[0]
        assert record.msg.startswith("pfblockerng: "), "emitted LogRecord.msg must start with 'pfblockerng: '"
        assert body in record.msg, "body must appear after the ident prefix"

    def test_disabled_emit_is_zero_cost_no_handler_creation(self, monkeypatch: Any) -> None:
        """When syslog_enable=False, _emit_dnsbl_syslog returns immediately (no handler).

        Gate checked before any formatting — zero overhead on the common path.
        """
        assert pfb_unbound.pfb["syslog_enable"] is False
        assert pfb_unbound._syslog_handler is None

        constructor_calls: list[Any] = []

        class _TrackingHandler:
            def __init__(self, **kw: Any) -> None:
                constructor_calls.append(kw)

        monkeypatch.setattr(pfb_unbound, "_PfbSysLogHandler", _TrackingHandler)

        pfb_unbound._emit_dnsbl_syslog("act=dnsbl qname=x.com qip=1.2.3.4 qtype=A btype=VIP eval=x.com")

        assert constructor_calls == [], "disabled: no handler construction"
        assert pfb_unbound._syslog_handler is None, "disabled: _syslog_handler stays None"
