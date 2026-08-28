"""ADR-10 Phase 3 -- the fail-closed ``rebuild_and_swap()`` build -> atomic-swap step.

WHY THIS FILE EXISTS
--------------------
Phase 3 factors the build->install step into ONE reusable, fail-closed
``rebuild_and_swap(build_snapshot)`` that, ON SUCCESS only: atomically rebinds the
single ``_snapshot`` ref to a freshly-built Snapshot, clears the unified ``decisionDB``
query memo, and re-emits the UI counts; ON FAILURE (the builder returns ``None`` or
raises) keeps the OLD snapshot and memo intact (fail-closed). It is still called
synchronously at init this
phase, so net init behaviour is unchanged; Phase 4's background watcher reuses it.

Following the repo test-coverage rules, every transition test asserts the BEFORE-state
first (the old snapshot is live and a decisionDB entry is present),
THEN flips (calls rebuild_and_swap), THEN asserts the AFTER-state -- so a green proves
the swap CAUSED the change rather than the end-state happening to hold already. Both
branches of the success/failure toggle are covered (success path AND each failure
shape -- None and raising builder).
"""

from __future__ import annotations

import re
import sys
from typing import Any

import pytest

import pfb_unbound as P
from pfb_unbound import _db_flush_dnsbl, _dnsbl_stats_wanted

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _snapshot(
    *,
    data: dict[str, Any] | None = None,
    counts: int = 0,
    regex_count: int = 0,
    rejects: P.RejectTally | None = None,
) -> P.Snapshot:
    """A populated Snapshot with distinct identity + counts so the swap is observable."""
    return P.Snapshot(
        data_db=data if data is not None else {},
        zone_db={},
        white_db={},
        regex_db={},
        allow_regex_db={},
        feed_group_index_db={},
        hsts_db={},
        important_rules=False,
        counts=counts,
        regex_count=regex_count,
        rejects=rejects if rejects is not None else {},
    )


def _seed_decision(name: str) -> P.Decision:
    """Put a STALE verdict on the live decisionDB (the unified LRU query memo)."""
    dec = P.Decision()
    dec.dnsbl = P.DnsblDecision(
        is_found=True,
        in_whitelist=False,
        in_hsts=False,
        null_blocking=False,
        nxdomain=False,
        log_type="1",
        b_type="DNSBL",
        p_type="DNSBL",
        feed="staleFeed",
        group="staleGroup",
        b_eval="data",
    )
    P.decisionDB[name] = dec
    return dec


def _set_count_paths(tmp_path: Any) -> None:
    """init_standard sets these UI-count path keys; the autouse reset fixture does not,
    so a test exercising the count re-emit must set them itself."""
    P.pfb["pfb_py_count"] = str(tmp_path / "pfb_py_count")
    P.pfb["pfb_py_regex_count"] = str(tmp_path / "pfb_py_regex_count")


class _RaisingStderr:
    def write(self, text: str) -> int:
        raise OSError(text)


class _ValueErrorStderr:
    def write(self, text: str) -> int:
        raise ValueError(text)


def test_each_snapshot_gets_a_fresh_generation() -> None:
    # issue #1074: the decisionDB memo stamp needs every built Snapshot to carry a
    # unique, advancing generation -- two builds must never share one (id() reuse is
    # exactly the trap this replaces).
    a, b = _snapshot(), _snapshot()
    assert b.gen > a.gen > 0


# --------------------------------------------------------------------------- #
# Success path: rebind + clear decisionDB + recount
# --------------------------------------------------------------------------- #


class TestRebuildAndSwapSuccess:
    def test_swaps_ref_clears_decisiondb_and_recounts(self, tmp_path: Any, monkeypatch: Any) -> None:
        # ---- arrange: a live OLD snapshot + a STALE decisionDB entry.
        old = _snapshot(data={"old.example.com": {"log": "1", "index": 0, "important": False}}, counts=1)
        P._snapshot = old
        _seed_decision("stale.example.com")
        _set_count_paths(tmp_path)

        emitted: dict[str, int] = {}
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda path, count: emitted.update({path: count}) or True)

        # ---- BEFORE-state (must hold so a green proves the swap caused the change).
        assert P._snapshot is old
        assert "stale.example.com" in P.decisionDB
        assert P.decisionDB.get("stale.example.com") is not None

        new = _snapshot(
            data={"new.example.com": {"log": "1", "index": 0, "important": False}},
            counts=42,
            regex_count=7,
        )

        # ---- act: swap.
        result = P.rebuild_and_swap(lambda: new)

        # ---- AFTER-state.
        assert result is True
        # (a) the single ref now points at the NEW snapshot (atomic rebind).
        assert P._snapshot is new
        assert P._snapshot is not old
        # (b) the unified decisionDB query memo was CLEARED (stale verdict gone).
        assert "stale.example.com" not in P.decisionDB
        assert P.decisionDB.get("stale.example.com") is None
        assert len(P.decisionDB) == 0
        # (c) the UI counts were re-emitted from the NEW snapshot.
        assert emitted[P.pfb["pfb_py_count"]] == 42
        assert emitted[P.pfb["pfb_py_regex_count"]] == 7

    def test_swap_clears_regex_warn_and_perf_strike_state(self, tmp_path: Any, monkeypatch: Any) -> None:
        # #714 FIX #2: a swap installs a BRAND-NEW regex_db/allow_regex_db, so the
        # runtime warn-suppression + perf-fallback strike bookkeeping (keyed on
        # pattern NAME, ADR-07 P7) must not survive it -- a name reused across
        # reloads (a re-added or edited rule) would otherwise inherit stale
        # strikes/suppression from the OLD pattern object. init_standard already
        # clears both on a restart; rebuild_and_swap must mirror it for a
        # no-restart swap (pre-fix it left this state dangling).
        _set_count_paths(tmp_path)
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)
        P._snapshot = _snapshot(counts=0)

        # ---- BEFORE-state: stale bookkeeping left by a PRIOR pattern set.
        P._regex_warned.add("stale-pattern")
        P._regex_perf_strikes["stale-pattern"] = 3
        assert "stale-pattern" in P._regex_warned
        assert P._regex_perf_strikes["stale-pattern"] == 3

        # ---- act: a successful swap.
        assert P.rebuild_and_swap(lambda: _snapshot(counts=1)) is True

        # ---- AFTER-state: both runtime dicts are cleared, in parity with init.
        assert P._regex_warned == set()
        assert P._regex_perf_strikes == {}

    def test_swap_enables_master_dnsbl_gate_when_new_lists_load(self, tmp_path: Any, monkeypatch: Any) -> None:
        # ADR-10: operate() gates ALL DNSBL evaluation on pfb["python_blacklist"], which
        # is otherwise written only at init. A swap that loads lists into a previously-
        # empty/disabled module (e.g. a regex-ONLY feed when the last init had no lists)
        # MUST flip it True, or the newly-swapped lists never block (the live abp_regex
        # smoke failure: snap_regex=1 but pyblacklist=False -> the regex was skipped).
        # Cover BOTH branches (CLAUDE.md): a list-bearing swap enables it; an EMPTY swap
        # leaves it untouched (no spurious enable).
        _set_count_paths(tmp_path)
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)

        # ---- regex-only NEW snapshot (no data/zone) over an empty live one.
        P._snapshot = _snapshot(counts=0)
        P.pfb["python_blacklist"] = False  # BEFORE: master gate OFF (last init had no lists)
        regex_only = P.Snapshot(
            data_db={},
            zone_db={},
            white_db={},
            regex_db={"feed#0": {"re": re.compile("badword"), "important": False, "band": 1}},
            allow_regex_db={},
            feed_group_index_db={},
            hsts_db={},
            important_rules=True,
            counts=0,
            regex_count=1,
        )
        assert P.pfb["python_blacklist"] is False
        assert P.rebuild_and_swap(lambda: regex_only) is True
        assert P.pfb["python_blacklist"] is True, "a regex-only swap must enable the master DNSBL gate"

        # ---- an EMPTY swap must NOT spuriously enable the gate (other-branch coverage).
        P._snapshot = regex_only
        P.pfb["python_blacklist"] = False
        empty = _snapshot(counts=0)
        assert P.pfb["python_blacklist"] is False
        assert P.rebuild_and_swap(lambda: empty) is True
        assert P.pfb["python_blacklist"] is False, "an empty swap must leave the master gate untouched"


# --------------------------------------------------------------------------- #
# Failure paths: keep the old snapshot and decision memo intact (fail-closed)
# --------------------------------------------------------------------------- #


class TestRebuildAndSwapFailClosed:
    def test_builder_returns_none_keeps_everything(self, tmp_path: Any, monkeypatch: Any) -> None:
        old = _snapshot(data={"old.example.com": {"log": "1", "index": 0, "important": False}}, counts=1)
        P._snapshot = old
        _seed_decision("stale.example.com")

        emitted: dict[str, int] = {}
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda path, count: emitted.update({path: count}) or True)

        # BEFORE: old snapshot live and stale memo present.
        assert P._snapshot is old
        assert "stale.example.com" in P.decisionDB

        # act: a None build (absent/unparseable manifest, build error).
        result = P.rebuild_and_swap(lambda: None)

        # AFTER (fail-closed): NOTHING changed.
        assert result is False
        assert P._snapshot is old  # old snapshot kept.
        assert "stale.example.com" in P.decisionDB  # STALE memo SURVIVES a failed build.
        assert P.decisionDB.get("stale.example.com") is not None
        assert emitted == {}  # no recount on failure.

    def test_builder_raises_keeps_everything(self, tmp_path: Any, monkeypatch: Any, capsys: Any) -> None:
        old = _snapshot(data={"old.example.com": {"log": "1", "index": 0, "important": False}}, counts=1)
        P._snapshot = old
        _seed_decision("stale.example.com")

        emitted: dict[str, int] = {}
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda path, count: emitted.update({path: count}) or True)

        def _boom() -> P.Snapshot:
            raise RuntimeError("build blew up")

        # BEFORE.
        assert P._snapshot is old
        assert "stale.example.com" in P.decisionDB

        # act: a raising build must be caught (no bare except leak) and fail-closed.
        result = P.rebuild_and_swap(_boom)

        # AFTER (fail-closed): identical to the None case -- nothing touched.
        assert result is False
        assert P._snapshot is old
        assert "stale.example.com" in P.decisionDB  # STALE memo SURVIVES a raising build.
        assert emitted == {}
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "[pfBlockerNG]: DNSBL rebuild failed, keeping current snapshot: build blew up"

    @pytest.mark.parametrize("emit_counts", [True, False])
    @pytest.mark.parametrize(
        "hostile_stderr",
        [
            pytest.param(None, id="stderr-none"),
            pytest.param(_RaisingStderr(), id="stderr-write-raises"),
        ],
    )
    def test_builder_raises_with_hostile_stderr_keeps_everything(
        self, monkeypatch: Any, hostile_stderr: Any, emit_counts: bool
    ) -> None:
        old = _snapshot(data={"old.example.com": {"log": "1", "index": 0, "important": False}}, counts=1)
        P._snapshot = old
        _seed_decision("stale.example.com")
        monkeypatch.setattr(sys, "stderr", hostile_stderr)

        def _boom() -> P.Snapshot:
            raise RuntimeError("build blew up")

        assert P._snapshot is old
        assert "stale.example.com" in P.decisionDB
        assert P.rebuild_and_swap(_boom, emit_counts=emit_counts) is False
        assert P._snapshot is old
        assert "stale.example.com" in P.decisionDB

    def test_builder_error_diagnostic_propagates_non_oserror(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(sys, "stderr", _ValueErrorStderr())

        def _boom() -> P.Snapshot:
            raise RuntimeError("build blew up")

        with pytest.raises(ValueError, match="DNSBL rebuild failed.*build blew up"):
            P.rebuild_and_swap(_boom)


# --------------------------------------------------------------------------- #
# emit_counts toggle (init opts out to stay byte-identical; Phase 4 default emits)
# --------------------------------------------------------------------------- #


class TestEmitCountsToggle:
    def test_emit_counts_false_skips_recount(self, tmp_path: Any, monkeypatch: Any) -> None:
        # init calls with emit_counts=False (keeps its own inline path-specific emits).
        P._snapshot = _snapshot(counts=1)
        emitted: dict[str, int] = {}
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda path, count: emitted.update({path: count}) or True)

        new = _snapshot(counts=99, regex_count=5)
        assert P.rebuild_and_swap(lambda: new, emit_counts=False) is True

        # The swap happened, but counts were NOT re-emitted.
        assert P._snapshot is new
        assert emitted == {}

    def test_emit_counts_true_recounts(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Branch pair: with the default (Phase 4 caller) the counts ARE re-emitted.
        P._snapshot = _snapshot(counts=1)
        _set_count_paths(tmp_path)
        emitted: dict[str, int] = {}
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda path, count: emitted.update({path: count}) or True)

        new = _snapshot(counts=99, regex_count=5)
        assert P.rebuild_and_swap(lambda: new) is True
        assert emitted[P.pfb["pfb_py_count"]] == 99
        assert emitted[P.pfb["pfb_py_regex_count"]] == 5

    def test_emit_counts_true_also_reemits_reject_stats_when_path_set(self, tmp_path: Any, monkeypatch: Any) -> None:
        # ADR-48 Phase 4 (#789): a no-restart swap re-emits the reject-stats
        # artifact from the FRESH snapshot too, exactly like the UI counts above.
        # init_standard() sets the path (needs the live Unbound env, can't run
        # here), so this test seeds it directly on the bare pfb dict.
        P._snapshot = _snapshot(counts=1)
        _set_count_paths(tmp_path)
        P.pfb["pfb_py_reject_stats"] = str(tmp_path / "pfb_py_reject_stats.json")
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)
        emitted_stats: dict[str, P.RejectTally] = {}
        monkeypatch.setattr(
            P,
            "dnsbl_emit_reject_stats",
            lambda path, rejects: emitted_stats.update({path: rejects}) or True,
        )

        new = _snapshot(counts=99, rejects={("F", "G"): {"shape": 1, "wire_cap": 2}})
        assert P.rebuild_and_swap(lambda: new) is True

        assert emitted_stats[P.pfb["pfb_py_reject_stats"]] == {("F", "G"): {"shape": 1, "wire_cap": 2}}

    def test_emit_counts_true_skips_reject_stats_when_path_absent(self, tmp_path: Any, monkeypatch: Any) -> None:
        # Contrast: a bare pfb dict without the key (every OTHER test in this
        # module never seeds it) must NOT KeyError -- the caller guards with
        # ``pfb.get(...)`` precisely because unit tests build a minimal pfb dict.
        P._snapshot = _snapshot(counts=1)
        _set_count_paths(tmp_path)
        assert "pfb_py_reject_stats" not in P.pfb
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)
        called: list[Any] = []

        def _spy_emit_reject_stats(*a: Any, **k: Any) -> bool:
            called.append((a, k))
            return True

        monkeypatch.setattr(P, "dnsbl_emit_reject_stats", _spy_emit_reject_stats)

        new = _snapshot(counts=99, rejects={("F", "G"): {"shape": 1, "wire_cap": 0}})
        assert P.rebuild_and_swap(lambda: new) is True

        assert called == []


# --------------------------------------------------------------------------- #
# Single-rebind invariant: rebuild_and_swap is the only place _snapshot is bound
# --------------------------------------------------------------------------- #


class TestSingleRebindPoint:
    def test_only_rebuild_and_swap_rebinds_snapshot(self) -> None:
        # Static guard: ``_snapshot = `` (a rebind) appears in the module source ONLY
        # inside rebuild_and_swap, never in init_standard or operate (operate reads
        # ``snap = _snapshot``; init now installs via rebuild_and_swap).
        import inspect

        src = inspect.getsource(P)
        rebind_lines = [
            ln.strip() for ln in src.splitlines() if ln.strip().startswith("_snapshot =") and "==" not in ln
        ]
        assert rebind_lines == ["_snapshot = new_snapshot"], rebind_lines


# --------------------------------------------------------------------------- #
# ADR-10 swap-visibility guard: operate()'s per-stratum presence gates + the
# important_rules fast-path flag MUST be derived from the captured snapshot (which
# a background swap replaces), NOT from the pfb[...] booleans (written only at
# init_standard and never refreshed by a swap). Reading them from pfb froze the
# gate at the last restart's state, so a zero-downtime swap that introduced a NEW
# stratum (feed/user regex, or data/zone when the prior init had none) left its gate
# False and evaluate_domain skipped it -- the newly-swapped block never applied (the
# live regex/important/custom-list smoke failures). Pinned at source level because
# operate() needs a full live qstate to exercise end-to-end (covered by the live smoke).
# --------------------------------------------------------------------------- #


class TestSwapGatesFromSnapshot:
    def test_operate_cfg_gates_read_snapshot_not_pfb(self) -> None:
        import inspect

        # ADR-65: the cfg-assembly dict operate() builds per query was extracted
        # into _evaluate_cfg(snap) (shared with the read-only query channel) -- the
        # snap-not-pfb invariant below now lives there; operate() only delegates.
        assert "cfg = _evaluate_cfg(snap)" in inspect.getsource(P.operate)
        src = inspect.getsource(P._evaluate_cfg)
        # The cfg dict each query builds must source the list-presence gates + the
        # important_rules flag from ``snap`` (the swapped snapshot), not ``pfb``.
        for key, field in (
            ("dataDB", "snap.data_db"),
            ("zoneDB", "snap.zone_db"),
            ("regexDB", "snap.regex_db"),
            ("whiteDB", "snap.white_db"),
            ("allowRegexDB", "snap.allow_regex_db"),
            ("important_rules", "snap.important_rules"),
            ("hstsDB", "snap.hsts_db"),
        ):
            assert f'"{key}": bool({field})' in src, (
                f'operate() cfg["{key}"] must be derived from {field} (the swapped snapshot), '
                f"not from the stale pfb[...] flag"
            )
        # And must NOT regress to reading these gates back off pfb[...]. Strip comment
        # lines first (the rationale comment legitimately names the pfb[...] keys).
        code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
        for stale in (
            'pfb["dataDB"]',
            'pfb["zoneDB"]',
            'pfb["regexDB"]',
            'pfb["whiteDB"]',
            'pfb["allowRegexDB"]',
            'pfb["important_rules"]',
            'pfb["hstsDB"]',
        ):
            assert stale not in code, f"operate() must not read the stale {stale} gate (swap-invisible)"


# --------------------------------------------------------------------------- #
# Issue #862 (sibling of #860): a swap that NEWLY wants DNSBL stats opens the
# stats DB init skipped at boot -- else per-feed/Upstream counters no-op forever.
# --------------------------------------------------------------------------- #


class TestSwapOpensDnsblStatsDb:
    """Scenario: an ADR-10 swap that newly satisfies ``_dnsbl_stats_wanted()`` opens the
    dnsbl stats DB that init left closed at boot, so a subsequent counter flush lands.

    Background:
        init_standard opens ``sqlite3_dnsbl_con`` only when ``_dnsbl_stats_wanted()``
        (python_blacklist OR forwarding -- issue #860) holds AT INIT. A forwarding-off /
        no-feeds boot leaves it False. A later zero-downtime swap raises
        ``python_blacklist`` (feeds added post-boot, no Unbound restart), but pre-fix
        rebuild_and_swap never re-opened the DB -- so ``_db_flush_dnsbl``'s
        ``sqlite3_dnsbl_con`` guard (and ``_log_upstream_block``'s enqueue) silently
        dropped every increment until a full restart. Same silent-loss class #860 fixed
        for the forwarding-only init; this pins the swap path.

    Every test asserts the BEFORE-state (DB closed) first, then swaps, so a green proves
    the swap CAUSED the open. All three branches of the ``_dnsbl_stats_wanted()`` guard
    inside the new open are covered: blacklist-flip opens it, forwarding-only opens it,
    neither leaves it closed.
    """

    def test_swap_enabling_blacklist_opens_db_and_flush_lands_counter(self, tmp_path: Any, monkeypatch: Any) -> None:
        """A swap that loads feeds (flips python_blacklist True) opens the stats DB and a
        counter flush then lands -- the exact effect the bug silently lost.

        RED pre-fix: rebuild_and_swap raised python_blacklist but left sqlite3_dnsbl_con
        False, so the ``assert ... sqlite3_dnsbl_con`` below fails.
        """
        _set_count_paths(tmp_path)
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)
        P.pfb["mod_sqlite3"] = True  # pin every guard input so "closed" is provably the predicate, not sqlite off
        P.pfb["pfb_py_dnsbl"] = str(tmp_path / "dnsbl.sqlite")

        # ---- BEFORE: boot state where stats were NOT wanted -> init left the DB closed.
        P.pfb["python_blacklist"] = False
        P.pfb["forwarding"] = False
        P._snapshot = _snapshot(counts=0)
        assert not P.pfb["sqlite3_dnsbl_con"]
        assert not _dnsbl_stats_wanted()

        # ---- act: a swap loads a data-stratum feed -> flips the master gate True.
        new = _snapshot(data={"blocked.example.com": {"log": "1", "index": 0, "important": False}}, counts=5)
        assert P.rebuild_and_swap(lambda: new) is True

        # ---- AFTER: the gate flipped AND the stats DB is now open.
        assert P.pfb["python_blacklist"] is True
        assert P.pfb["sqlite3_dnsbl_con"], "a swap that newly wants stats must open the dnsbl DB (issue #862)"

        # ---- and a counter flush actually lands now (pre-fix: guarded no-op).
        assert _db_flush_dnsbl({"Upstream": 1})
        con = P._db_conns[P.DB_DNSBL]
        row = con.execute("SELECT counter FROM dnsbl WHERE groupname = 'Upstream'").fetchone()
        assert row == (1,), f"Upstream counter not incremented after the swap opened the DB: {row!r}"

    def test_forwarding_only_swap_opens_db_even_with_empty_snapshot(self, tmp_path: Any, monkeypatch: Any) -> None:
        """Other truthy branch of the guard: forwarding alone (no blacklist) wants stats
        too (#860 predicate), so a swap opens the DB even when the snapshot has no lists --
        the Upstream-counter path -- WITHOUT spuriously flipping python_blacklist.

        RED pre-fix: sqlite3_dnsbl_con stays False across the swap.
        """
        _set_count_paths(tmp_path)
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)
        P.pfb["mod_sqlite3"] = True  # pin every guard input so "closed" is provably the predicate, not sqlite off
        P.pfb["pfb_py_dnsbl"] = str(tmp_path / "dnsbl.sqlite")

        # ---- BEFORE: forwarding on, but the DB somehow closed (DB never opened).
        P.pfb["python_blacklist"] = False
        P.pfb["forwarding"] = True
        P._snapshot = _snapshot(counts=0)
        assert not P.pfb["sqlite3_dnsbl_con"]

        assert P.rebuild_and_swap(lambda: _snapshot(counts=0)) is True

        # ---- AFTER: an empty snapshot leaves python_blacklist False, but forwarding still
        # wants stats -> the DB opens.
        assert P.pfb["python_blacklist"] is False
        assert P.pfb["sqlite3_dnsbl_con"], "forwarding-only swap must open the dnsbl stats DB (issue #862/#860)"

    def test_empty_swap_no_forwarding_leaves_db_closed(self, tmp_path: Any, monkeypatch: Any) -> None:
        """Guard-intact branch: a swap that does NOT newly want stats (empty snapshot, no
        forwarding, gate stays False) must NOT open the DB -- proving the open is scoped to
        a swap that actually enables stats, not a blanket open-on-every-swap."""
        _set_count_paths(tmp_path)
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)
        P.pfb["mod_sqlite3"] = True  # pin every guard input so "closed" is provably the predicate, not sqlite off
        P.pfb["pfb_py_dnsbl"] = str(tmp_path / "dnsbl.sqlite")
        P.pfb["python_blacklist"] = False
        P.pfb["forwarding"] = False
        P._snapshot = _snapshot(counts=0)

        assert P.rebuild_and_swap(lambda: _snapshot(counts=0)) is True

        assert P.pfb["python_blacklist"] is False
        assert not P.pfb["sqlite3_dnsbl_con"]
        assert P.DB_DNSBL not in P._db_conns, "an empty swap that does not want stats must not open the dnsbl DB"

    def test_swap_does_not_open_db_when_mod_sqlite3_unavailable(self, tmp_path: Any, monkeypatch: Any) -> None:
        """Third input of the AND guard (mod_sqlite3): with the sqlite3 module unavailable,
        a swap that WOULD otherwise want stats (python_blacklist flips True) must still NOT
        open the DB -- the mod_sqlite3 conjunct gates it, matching init's own mod_sqlite3
        gate. Completes branch coverage of the guard's three inputs.

        Failable guard: drop the `mod_sqlite3 and` conjunct and this fails -- sqlite3 is
        importable in the test env, so the open would succeed and sqlite3_dnsbl_con flip True.
        """
        _set_count_paths(tmp_path)
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)
        P.pfb["mod_sqlite3"] = False  # sqlite3 module unavailable on this install
        P.pfb["pfb_py_dnsbl"] = str(tmp_path / "dnsbl.sqlite")
        P.pfb["python_blacklist"] = False
        P.pfb["forwarding"] = False
        P._snapshot = _snapshot(counts=0)
        assert not P.pfb["sqlite3_dnsbl_con"]

        # ---- act: a swap loads a feed -> flips python_blacklist True (stats WOULD be wanted).
        new = _snapshot(data={"blocked.example.com": {"log": "1", "index": 0, "important": False}}, counts=5)
        assert P.rebuild_and_swap(lambda: new) is True

        # ---- the master gate flips and stats ARE wanted, but mod_sqlite3=False keeps the DB closed.
        assert P.pfb["python_blacklist"] is True
        assert _dnsbl_stats_wanted()
        assert not P.pfb["sqlite3_dnsbl_con"], "mod_sqlite3=False must gate the swap-side DB open"
        assert P.DB_DNSBL not in P._db_conns, "no connection may open when the sqlite3 module is unavailable"

    def test_swap_does_not_reopen_an_already_open_db(self, tmp_path: Any, monkeypatch: Any) -> None:
        """Idempotency: when the stats DB is already open (init opened it), a later swap
        must NOT reconnect -- the not-sqlite3_dnsbl_con guard makes the open a no-op, so
        the existing connection (and its accumulated counter) is preserved."""
        _set_count_paths(tmp_path)
        monkeypatch.setattr(P, "dnsbl_emit_count", lambda *a, **k: True)
        P.pfb["mod_sqlite3"] = True  # pin every guard input so "closed" is provably the predicate, not sqlite off
        P.pfb["pfb_py_dnsbl"] = str(tmp_path / "dnsbl.sqlite")

        # ---- BEFORE: the DB is already open with an accumulated Upstream counter.
        P.pfb["python_blacklist"] = True
        P.pfb["sqlite3_dnsbl_con"] = True
        assert _db_flush_dnsbl({"Upstream": 7})
        first_con = P._db_conns[P.DB_DNSBL]
        assert first_con.execute("SELECT counter FROM dnsbl WHERE groupname = 'Upstream'").fetchone() == (7,)
        P._snapshot = _snapshot(counts=0)
        new = _snapshot(data={"blocked.example.com": {"log": "1", "index": 0, "important": False}}, counts=5)
        assert P.rebuild_and_swap(lambda: new) is True

        # ---- AFTER: same connection object (no reconnect), counter preserved.
        assert P.pfb["sqlite3_dnsbl_con"]
        assert P._db_conns[P.DB_DNSBL] is first_con, "an already-open stats DB must not be reconnected by the swap"
        assert first_con.execute("SELECT counter FROM dnsbl WHERE groupname = 'Upstream'").fetchone() == (7,)
