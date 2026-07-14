"""ADR-65 -- the read-only DNSBL decision query channel.

WHY THIS FILE EXISTS
--------------------
ADR-65 adds an always-on, read-only file channel to ``pfb_unbound.py``: a local
consumer writes a JSON request to ``pfb_py_query``, and the query watcher answers
into ``pfb_py_query.reply`` with the LIVE matcher's verdict -- the exact
attribution fields ``dnsbl.log`` carries -- with NONE of a real query's side
effects except the decisionDB LRU memo. PRODUCTION-DORMANT: nothing writes the
request file until the consumers are rewired (ADR-65 SS2.2), so this suite is
the only thing exercising it.

Three things must be pinned:
  * DECISION EQUALITY (Axis 1): ``dnsbl_query_answer`` must match an INDEPENDENTLY
    computed ``evaluate_domain`` verdict, over one arm per the frozen
    ``tests/test_adr65_decision_oracle.py`` catalogue (A1-A19) -- reusing its
    ``_containers``/``_containers_from_result``/``_cfg`` helpers (read-only import;
    that module is FROZEN, never edited here).
  * SIDE-EFFECT FREEDOM (Axis 2): a channel query reaches none of operate()'s
    counter/log/cache sinks; the decisionDB LRU memo is the one allowed write. A
    vacuity guard proves the same spies WOULD catch a real sink call.
  * THE WATCHER (Axis 4) + HOSTILE INPUT (section 5): the request parser is a new
    local trust boundary -- every malformed/adversarial input must never crash the
    daemon and never write a reply it cannot correlate.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import types
from typing import Any

import pytest

import pfb_unbound as P
from pfb_unbound import (
    IDN_FEED_MALICIOUS,
    IDN_GROUP_MALICIOUS,
    IDN_MODE_ALL,
    IDN_MODE_CONFUSABLE,
    PRIO_FEED_ALLOW,
    PRIO_FEED_BLOCK,
    PRIO_FEED_BLOCK_IMPORTANT,
    REGEX_EVICT_MS_DEFAULT,
    REGEX_WARN_MS_DEFAULT,
)
from tests.test_adr06_init_from_raw import _build_from_manifest
from tests.test_adr08_confusable_matcher import MALICIOUS_NAME, SUSPICIOUS_NAME
from tests.test_adr65_decision_oracle import _build_manifest_off, _cfg, _containers, _containers_from_result
from tests.test_issue1083_dnsbl_interchange_semantic_oracle import _run_corpus_build

_FGI = {0: {"feed": "TestFeed", "group": "TestGroup"}}

# The cfg keys _evaluate_cfg reads verbatim from pfb[...] (never container
# presence) -- pfb_unbound.py's cfg dict literal (moved into _evaluate_cfg).
_PFB_CFG_KEYS = (
    "python_blocking",
    "tld_allow",
    "tld_allow_list",
    "dnsbl_ipv4",
    "dnsbl_ipv6",
    "python_idn",
    "python_tld_seg",
    "hsts_tlds",
)


# --------------------------------------------------------------------------- #
# Decision-equality harness: drive the CHANNEL (dnsbl_query_answer) and an
# INDEPENDENT oracle call (evaluate_domain, given the SAME containers/cfg) side by
# side, so the comparison proves decision-equality without circularity.
# --------------------------------------------------------------------------- #


def _snapshot_from_containers(containers: dict[str, Any], *, important_rules: bool) -> P.Snapshot:
    return P.Snapshot(
        data_db=containers["dataDB"],
        zone_db=containers["zoneDB"],
        white_db=containers["whiteDB"],
        regex_db=containers["regexDB"],
        allow_regex_db=containers.get("allowRegexDB", {}),
        feed_group_index_db=containers["feedGroupIndexDB"],
        hsts_db=containers["hstsDB"],
        important_rules=important_rules,
    )


def _seed_pfb_from_cfg(cfg: dict[str, Any]) -> None:
    for k in _PFB_CFG_KEYS:
        P.pfb[k] = cfg[k]
    P.pfb["idn_mode"] = cfg.get("idn_mode")
    P.pfb["python_idn_block_malicious"] = cfg.get("python_idn_block_malicious", True)
    P.pfb["python_idn_escalate_suspicious"] = cfg.get("python_idn_escalate_suspicious", False)
    P.pfb["regex_warn_ms"] = cfg.get("regex_warn_ms", REGEX_WARN_MS_DEFAULT)
    P.pfb["regex_evict_ms"] = cfg.get("regex_evict_ms", REGEX_EVICT_MS_DEFAULT)


def _channel_and_oracle(
    monkeypatch: Any,
    *,
    containers: dict[str, Any],
    q_name: str,
    tld: str,
    **cfg_overrides: Any,
) -> tuple[dict[str, Any], Any]:
    cfg = _cfg(**cfg_overrides)
    snap = _snapshot_from_containers(containers, important_rules=cfg["important_rules"])
    _seed_pfb_from_cfg(cfg)
    monkeypatch.setattr(P, "_snapshot", snap)
    reply = P.dnsbl_query_answer(q_name, "A")
    oracle = P.evaluate_domain(q_name, q_name, tld, False, cfg, containers)
    return reply, oracle


def _assert_reply_matches_oracle(reply: dict[str, Any], oracle: Any) -> None:
    blocked = oracle.is_found and not oracle.in_whitelist
    assert reply["blocked"] == blocked
    if blocked:
        assert reply["b_type"] == "{}".format(oracle.b_type)
        assert reply["group"] == "{}".format(oracle.group)
        assert reply["b_eval"] == "{}".format(oracle.b_eval)
        assert reply["feed"] == "{}".format(oracle.feed)
        assert reply["p_type"] == "{}".format(oracle.p_type)
    else:
        assert reply["b_type"] == ""
        assert reply["group"] == ""
        assert reply["b_eval"] == ""
        assert reply["feed"] == ""
        assert reply["p_type"] == ""


# --------------------------------------------------------------------------- #
# Axis 1 -- decision equality, direct container construction (A1-A3, A5, A6, A8-A16).
# --------------------------------------------------------------------------- #


class TestDecisionEqualityDirectContainers:
    def test_a1_data_db_exact_hit(self, monkeypatch: Any) -> None:
        q = "exact-hit.uuid1001.com"
        data = {q: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        containers = _containers(data=data, feed_group_index=_FGI)
        reply, oracle = _channel_and_oracle(monkeypatch, containers=containers, q_name=q, tld="com")
        assert reply["blocked"] is True
        _assert_reply_matches_oracle(reply, oracle)

    def test_a2_zone_db_suffix_hit(self, monkeypatch: Any) -> None:
        parent = "zone-parent.uuid1002.net"
        child = "deep.sub." + parent
        zone = {parent: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        containers = _containers(zone=zone, feed_group_index=_FGI)
        reply, oracle = _channel_and_oracle(monkeypatch, containers=containers, q_name=child, tld="net")
        assert reply["blocked"] is True
        _assert_reply_matches_oracle(reply, oracle)

    def test_a3_feed_block_regex_hit(self, monkeypatch: Any) -> None:
        pattern = re.compile(r"^regex-hit-\d+\.uuid1003\.org$")
        regex_db = {"MyBlockRegex": {"re": pattern, "important": False, "band": PRIO_FEED_BLOCK}}
        q = "regex-hit-42.uuid1003.org"
        containers = _containers(regex=regex_db)
        reply, oracle = _channel_and_oracle(monkeypatch, containers=containers, q_name=q, tld="org")
        assert reply["blocked"] is True
        _assert_reply_matches_oracle(reply, oracle)

    def test_a6_fast_path_whitelist_overrides_block(self, monkeypatch: Any) -> None:
        q = "fastpath-allow.uuid1006.net"
        data = {q: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        white = {q: True}
        containers = _containers(data=data, white=white, feed_group_index=_FGI)
        reply, oracle = _channel_and_oracle(
            monkeypatch, containers=containers, q_name=q, tld="net", important_rules=False
        )
        assert reply["blocked"] is False  # whitelisted overrides the block
        _assert_reply_matches_oracle(reply, oracle)

    def test_a5_abp_allow_overrides_block_via_numeric_band(self, monkeypatch: Any) -> None:
        q = "allow-wins.uuid1005.com"
        data = {q: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        white = {q: {"wildcard": False, "important": False, "band": PRIO_FEED_ALLOW}}
        containers = _containers(data=data, white=white, feed_group_index=_FGI)
        reply, oracle = _channel_and_oracle(
            monkeypatch, containers=containers, q_name=q, tld="com", important_rules=True
        )
        assert reply["blocked"] is False
        _assert_reply_matches_oracle(reply, oracle)

    def test_a8_important_block_beats_plain_allow(self, monkeypatch: Any) -> None:
        q = "important-wins.uuid1008.org"
        data = {q: {"log": "1", "index": 0, "important": True, "band": PRIO_FEED_BLOCK_IMPORTANT}}
        white = {q: {"wildcard": False, "important": False, "band": PRIO_FEED_ALLOW}}
        containers = _containers(data=data, white=white, feed_group_index=_FGI)
        reply, oracle = _channel_and_oracle(
            monkeypatch, containers=containers, q_name=q, tld="org", important_rules=True
        )
        assert reply["blocked"] is True
        _assert_reply_matches_oracle(reply, oracle)

    def test_a9_hsts_listed_name_resolves_real(self, monkeypatch: Any) -> None:
        q = "hsts-listed.uuid1009.com"
        data = {q: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        hsts = {q: 0}
        containers = _containers(data=data, hsts=hsts, feed_group_index=_FGI)
        reply, oracle = _channel_and_oracle(monkeypatch, containers=containers, q_name=q, tld="com")
        assert oracle.in_hsts is True  # HSTS still resolves real, but IS attributed
        _assert_reply_matches_oracle(reply, oracle)

    def test_a10_confusable_block_dual_form(self, monkeypatch: Any) -> None:
        containers = _containers()
        reply, oracle = _channel_and_oracle(
            monkeypatch,
            containers=containers,
            q_name=MALICIOUS_NAME,
            tld="com",
            idn_mode=IDN_MODE_CONFUSABLE,
            python_idn_block_malicious=True,
        )
        assert reply["blocked"] is True
        assert (reply["feed"], reply["group"]) == (IDN_FEED_MALICIOUS, IDN_GROUP_MALICIOUS)
        _assert_reply_matches_oracle(reply, oracle)

    def test_a11_all_idn_blocks_any_xn_dash_dash(self, monkeypatch: Any) -> None:
        q = "xn--any1234.uuid1011.com"
        containers = _containers()
        reply, oracle = _channel_and_oracle(
            monkeypatch, containers=containers, q_name=q, tld="com", idn_mode=IDN_MODE_ALL
        )
        assert reply["blocked"] is True
        _assert_reply_matches_oracle(reply, oracle)

    def test_a12_confusable_alert_does_not_block(self, monkeypatch: Any) -> None:
        containers = _containers()
        reply, oracle = _channel_and_oracle(
            monkeypatch,
            containers=containers,
            q_name=SUSPICIOUS_NAME,
            tld="com",
            idn_mode=IDN_MODE_CONFUSABLE,
            python_idn_escalate_suspicious=False,
        )
        assert oracle.idn_alert is not None  # ALERT fired ...
        assert reply["blocked"] is False  # ... but the reply never blocks for it
        _assert_reply_matches_oracle(reply, oracle)

    def test_a13_disallowed_tld_blocks_via_tld_allow(self, monkeypatch: Any) -> None:
        q = "anything.uuid1013.org"
        containers = _containers()
        reply, oracle = _channel_and_oracle(
            monkeypatch, containers=containers, q_name=q, tld="org", tld_allow=True, tld_allow_list=["com", "net"]
        )
        assert reply["blocked"] is True
        assert (reply["feed"], reply["group"]) == ("TLD_Allow", "DNSBL_TLD_Allow")
        _assert_reply_matches_oracle(reply, oracle)

    def test_a14_nxdomain_shape_still_blocked_in_reply(self, monkeypatch: Any) -> None:
        q = "nx-listed.uuid1014.com"
        data = {q: {"log": "3", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        hsts = {q: 0}  # even HSTS-listed, NXDOMAIN wins (evaluate_domain's own contract)
        containers = _containers(data=data, hsts=hsts, feed_group_index=_FGI)
        reply, oracle = _channel_and_oracle(monkeypatch, containers=containers, q_name=q, tld="com")
        assert oracle.nxdomain is True
        assert reply["blocked"] is True  # found+not-whitelisted; the channel never returns a DNS rcode
        _assert_reply_matches_oracle(reply, oracle)

    def test_a15_channel_never_applies_the_cname_suffix(self, monkeypatch: Any) -> None:
        # The channel always passes is_cname=False (no CNAME chain on this transport):
        # its answer must equal evaluate_domain's OWN is_cname=False verdict, never the
        # CNAME-suffixed one that same containers/cfg would give a chained query.
        q = "cname-target.uuid1015.net"
        data = {q: {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}}
        containers = _containers(data=data, feed_group_index=_FGI)
        reply, oracle = _channel_and_oracle(monkeypatch, containers=containers, q_name=q, tld="net")
        assert reply["b_type"] == "DNSBL"
        _assert_reply_matches_oracle(reply, oracle)
        # Sanity: the CNAME arm DOES suffix for the exact same containers/cfg --
        # proving the b_type match above is a real is_cname=False verdict, not a
        # coincidence of the axis being absent from evaluate_domain entirely.
        cname_oracle = P.evaluate_domain(q, q, "net", True, _cfg(), containers)
        assert cname_oracle.b_type == "DNSBL_CNAME"
        assert reply["b_type"] != cname_oracle.b_type

    def test_a16_unlisted_name_resolves(self, monkeypatch: Any) -> None:
        q = "totally-clean.uuid1016.com"
        containers = _containers()
        reply, oracle = _channel_and_oracle(monkeypatch, containers=containers, q_name=q, tld="com")
        assert oracle.is_found is False
        assert reply == {"blocked": False, "b_type": "", "group": "", "b_eval": "", "feed": "", "p_type": ""}


# --------------------------------------------------------------------------- #
# Axis 1 -- decision equality, manifest-driven arms (A4, A7, A17-A19): build the
# Snapshot from _containers_from_result over the REAL build, as the oracle does.
# --------------------------------------------------------------------------- #


class TestDecisionEqualityManifestDriven:
    def test_a4_abp_anchor_zone_class(self, monkeypatch: Any) -> None:
        result = _run_corpus_build()
        containers = _containers_from_result(result)
        reply, oracle = _channel_and_oracle(
            monkeypatch,
            containers=containers,
            q_name="anchor.abp.example",
            tld="example",
            important_rules=result.important_rules,
        )
        assert reply["blocked"] is True
        assert reply["b_type"] == "TLD"
        _assert_reply_matches_oracle(reply, oracle)

    def test_a4_abp_exact_regex_fold_data_class(self, monkeypatch: Any) -> None:
        result = _run_corpus_build()
        containers = _containers_from_result(result)
        reply, oracle = _channel_and_oracle(
            monkeypatch,
            containers=containers,
            q_name="regexblock.abp.example",
            tld="example",
            important_rules=result.important_rules,
        )
        assert reply["blocked"] is True
        assert reply["b_type"] == "DNSBL"
        _assert_reply_matches_oracle(reply, oracle)

    def test_a7_top1m_enabled_unblocks(self, monkeypatch: Any, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=True)
        containers = _containers_from_result(result)
        reply, oracle = _channel_and_oracle(
            monkeypatch,
            containers=containers,
            q_name="popularcdn.com",
            tld="com",
            important_rules=result.important_rules,
        )
        assert reply["blocked"] is False
        _assert_reply_matches_oracle(reply, oracle)

    def test_a7_top1m_disabled_blocks_same_domain(self, monkeypatch: Any, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        containers = _containers_from_result(result)
        reply, oracle = _channel_and_oracle(
            monkeypatch,
            containers=containers,
            q_name="popularcdn.com",
            tld="com",
            important_rules=result.important_rules,
        )
        assert reply["blocked"] is True
        _assert_reply_matches_oracle(reply, oracle)

    def test_a17_two_label_domain_zone_when_on(self, monkeypatch: Any, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=False)  # always TLD ON
        containers = _containers_from_result(result)
        reply, oracle = _channel_and_oracle(
            monkeypatch, containers=containers, q_name="malware.com", tld="com", important_rules=result.important_rules
        )
        assert reply["b_type"] == "TLD"
        _assert_reply_matches_oracle(reply, oracle)

    def test_a18_same_two_label_domain_data_when_off(self, monkeypatch: Any, tmp_path: Any) -> None:
        result = _build_manifest_off(tmp_path)
        containers = _containers_from_result(result)
        reply, oracle = _channel_and_oracle(
            monkeypatch, containers=containers, q_name="malware.com", tld="com", important_rules=result.important_rules
        )
        assert reply["b_type"] == "DNSBL"
        _assert_reply_matches_oracle(reply, oracle)

    def test_a19_multilabel_public_suffix_zone_when_on(self, monkeypatch: Any, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        containers = _containers_from_result(result)
        reply, oracle = _channel_and_oracle(
            monkeypatch, containers=containers, q_name="shop.co.uk", tld="uk", important_rules=result.important_rules
        )
        assert reply["b_type"] == "TLD"
        _assert_reply_matches_oracle(reply, oracle)

    def test_a19_multilabel_public_suffix_data_when_off(self, monkeypatch: Any, tmp_path: Any) -> None:
        result = _build_manifest_off(tmp_path)
        containers = _containers_from_result(result)
        reply, oracle = _channel_and_oracle(
            monkeypatch, containers=containers, q_name="shop.co.uk", tld="uk", important_rules=result.important_rules
        )
        assert reply["b_type"] == "DNSBL"
        _assert_reply_matches_oracle(reply, oracle)

    def test_a19_deep_subdomain_unmatched_parent_stays_data_when_on(self, monkeypatch: Any, tmp_path: Any) -> None:
        result = _build_from_manifest(tmp_path, top1m_enabled=False)
        containers = _containers_from_result(result)
        reply, oracle = _channel_and_oracle(
            monkeypatch,
            containers=containers,
            q_name="deep.path.cleanmal.com",
            tld="com",
            important_rules=result.important_rules,
        )
        assert reply["b_type"] == "DNSBL"
        _assert_reply_matches_oracle(reply, oracle)


# --------------------------------------------------------------------------- #
# Watcher harness -- mirrors tests/test_pfbl03_control_channel.py's _ControlHarness/
# control_harness, minus the seq/baseline logic (the query channel is stateless).
# --------------------------------------------------------------------------- #

_ABSENT: object = object()


class _QueryHarness:
    """Run pfb_query_watcher on a real daemon thread against a temp channel file."""

    def __init__(self, tmp_path: Any, monkeypatch: Any) -> None:
        self.channel = str(tmp_path / "pfb_py_query")
        self.reply_path = str(tmp_path / "pfb_py_query.reply")
        P.pfb["pfb_py_query"] = self.channel
        P.pfb["pfb_py_query_reply"] = self.reply_path
        # Short cadence so the poll/kqueue timeout is prompt.
        monkeypatch.setattr(P, "RELOAD_POLL_INTERVAL", 0.05)
        P.pfb_query_stop = threading.Event()
        self.thread: Any = None

    def publish(self, record: dict[str, Any]) -> None:
        tmp = self.channel + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(record))
        os.replace(tmp, self.channel)

    def write_raw(self, raw: str) -> None:
        """Write RAW (possibly non-JSON) content straight to the channel -- for the
        hostile-input rows (malformed JSON, non-dict, empty, oversized junk)."""
        tmp = self.channel + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(raw)
        os.replace(tmp, self.channel)

    def read_reply(self) -> dict[str, Any] | None:
        try:
            with open(self.reply_path, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError:
            return None
        if not raw.strip():
            return None
        try:
            parsed = json.loads(raw)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def start(self) -> None:
        self.thread = threading.Thread(name="pfb_query_watcher_test", target=P.pfb_query_watcher, daemon=True)
        self.thread.start()

    def wait_reply(self, req_id: str, timeout: float = 3.0) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rec = self.read_reply()
            if rec is not None and rec.get("id") == req_id:
                return rec
            time.sleep(0.01)
        return None

    def stop_join(self) -> bool:
        """Bounded, sliced join (mirrors _ControlHarness.stop_join) so CPU contention
        cannot make one long join return prematurely."""
        P.pfb_query_stop.set()
        if self.thread is None:
            return True
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            self.thread.join(timeout=0.5)
            if not self.thread.is_alive():
                return True
        return False


@pytest.fixture
def query_harness(tmp_path: Any, monkeypatch: Any) -> Any:
    """Isolated, guaranteed-teardown fixture (mirrors control_harness)."""
    live_before = [t for t in threading.enumerate() if t.name == "pfb_query_watcher_test"]
    assert not live_before, (
        f"query_harness setup: a pfb_query_watcher_test thread from a PREVIOUS test is still alive: {live_before!r}."
    )

    _pfb_keys = ("pfb_py_query", "pfb_py_query_reply")
    snapshot_pfb: dict[str, Any] = {k: P.pfb.get(k, _ABSENT) for k in _pfb_keys}
    snapshot_stop: Any = getattr(P, "pfb_query_stop", _ABSENT)
    snapshot_thread: Any = getattr(P, "pfb_query_watcher_thread", _ABSENT)

    h = _QueryHarness(tmp_path, monkeypatch)
    try:
        yield h
    finally:
        teardown_errors: list[str] = []
        try:
            died = h.stop_join()
            if not died:
                teardown_errors.append(f"query_harness teardown: watcher thread {h.thread!r} did not exit in 10s.")
            live_after = [t for t in threading.enumerate() if t.name == "pfb_query_watcher_test"]
            if live_after:
                teardown_errors.append(f"query_harness teardown: leaked watcher thread(s): {live_after!r}")
        finally:
            for k, v in snapshot_pfb.items():
                if v is _ABSENT:
                    P.pfb.pop(k, None)
                else:
                    P.pfb[k] = v
            if snapshot_stop is _ABSENT:
                try:
                    del P.pfb_query_stop  # type: ignore[attr-defined]
                except AttributeError:
                    pass
            else:
                P.pfb_query_stop = snapshot_stop
            if snapshot_thread is _ABSENT:
                try:
                    del P.pfb_query_watcher_thread  # type: ignore[attr-defined]
                except AttributeError:
                    pass
            else:
                P.pfb_query_watcher_thread = snapshot_thread
        assert not teardown_errors, "\n".join(teardown_errors)


def _seed_blocked_domain(q: str) -> None:
    """Populate the LIVE module globals (the default _snapshot wraps these -- see
    conftest.reset_pfb_globals) with one feed-block entry, for watcher-thread tests
    that must exercise the real global state, not a monkeypatched Snapshot."""
    P.pfb["python_blocking"] = True
    P.dataDB[q] = {"log": "1", "index": 0, "important": False, "band": PRIO_FEED_BLOCK}
    P.feedGroupIndexDB[0] = {"feed": "TestFeed", "group": "TestGroup"}


# --------------------------------------------------------------------------- #
# Axis 4 -- watcher lifecycle.
# --------------------------------------------------------------------------- #


class TestQueryWatcherLoop:
    def test_request_answered_by_id(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        q = "watcher-basic.uuidquery2001.com"
        _seed_blocked_domain(q)
        h.start()
        h.publish({"id": "req1", "domain": q, "qtype": "A"})
        reply = h.wait_reply("req1")
        assert reply is not None
        assert reply["blocked"] is True
        assert reply["b_type"] == "DNSBL"

    def test_reply_file_mode_is_0640(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        q = "watcher-mode.uuidquery2002.com"
        _seed_blocked_domain(q)
        h.start()
        h.publish({"id": "req2", "domain": q, "qtype": "A"})
        assert h.wait_reply("req2") is not None
        assert (os.stat(h.reply_path).st_mode & 0o777) == 0o640

    def test_reply_written_atomically_no_tmp_residue(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        q = "watcher-atomic.uuidquery2003.com"
        _seed_blocked_domain(q)
        h.start()
        h.publish({"id": "req3", "domain": q, "qtype": "A"})
        assert h.wait_reply("req3") is not None
        assert not os.path.exists(h.reply_path + ".tmp")

    def test_identical_record_answered_once_changed_record_reanswered(
        self, query_harness: _QueryHarness, monkeypatch: Any
    ) -> None:
        h = query_harness
        q1 = "watcher-settle-a.uuidquery2004.com"
        q2 = "watcher-settle-b.uuidquery2004.com"
        _seed_blocked_domain(q1)
        calls: list[dict[str, Any]] = []
        orig = P._pfb_write_query_reply

        def spy(reply: dict[str, Any]) -> None:
            calls.append(dict(reply))
            orig(reply)

        monkeypatch.setattr(P, "_pfb_write_query_reply", spy)
        h.start()

        h.publish({"id": "dup1", "domain": q1, "qtype": "A"})
        assert h.wait_reply("dup1") is not None
        time.sleep(0.2)
        assert len(calls) == 1  # answered once

        h.publish({"id": "dup1", "domain": q1, "qtype": "A"})  # byte-identical redelivery
        time.sleep(0.3)
        assert len(calls) == 1  # settle: NOT re-answered

        h.publish({"id": "dup1", "domain": q2, "qtype": "A"})  # same id, NEW domain
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and len(calls) < 2:
            time.sleep(0.01)
        assert len(calls) == 2  # a changed record IS re-answered

    def test_preexisting_request_answered_at_startup(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        q = "watcher-preexisting.uuidquery2005.com"
        _seed_blocked_domain(q)
        h.publish({"id": "pre1", "domain": q, "qtype": "A"})  # published BEFORE start()
        h.start()
        reply = h.wait_reply("pre1")
        assert reply is not None  # stateless: no baseline-adopt-without-answering
        assert reply["blocked"] is True

    def test_watcher_never_writes_or_deletes_the_request_file(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        q = "watcher-readonly.uuidquery2006.com"
        _seed_blocked_domain(q)
        h.publish({"id": "ro1", "domain": q, "qtype": "A"})
        before_bytes = open(h.channel, "rb").read()
        before_mtime = os.stat(h.channel).st_mtime
        h.start()
        assert h.wait_reply("ro1") is not None
        time.sleep(0.2)
        assert os.path.exists(h.channel)  # never deleted
        assert open(h.channel, "rb").read() == before_bytes  # never rewritten
        assert os.stat(h.channel).st_mtime == before_mtime

    def test_stop_event_terminates_the_thread(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        h.start()
        assert h.stop_join() is True


# --------------------------------------------------------------------------- #
# Axis 2 -- side-effect freedom (+ vacuity guard).
# --------------------------------------------------------------------------- #


class TestSideEffectFree:
    def test_channel_query_is_side_effect_free_except_decisiondb_memo(
        self, query_harness: _QueryHarness, monkeypatch: Any
    ) -> None:
        h = query_harness
        q = "side-effect.uuidquery2010.com"
        _seed_blocked_domain(q)
        P.pfb["sqlite3_resolver_con"] = True
        P.pfb["sqlite3_dnsbl_con"] = True

        enqueue_calls: list[Any] = []
        log_calls: list[Any] = []
        monkeypatch.setattr(P, "pfb_db_enqueue", lambda task: enqueue_calls.append(task))
        monkeypatch.setattr(P, "pfb_log", lambda path, line: log_calls.append((path, line)))
        before_last_event = P._dnsbl_last_event
        before_decision = P.decisionDB.get(q)
        assert before_decision is None  # BEFORE: no memo yet

        h.start()
        h.publish({"id": "se1", "domain": q, "qtype": "A"})
        reply = h.wait_reply("se1")
        assert reply is not None
        assert reply["blocked"] is True

        # No sink reached except the ALLOWED decisionDB LRU memo.
        assert enqueue_calls == []
        assert log_calls == []
        assert P._dnsbl_last_event == before_last_event
        dec = P.decisionDB.get(q)
        assert dec is not None
        assert dec.dnsbl.is_found is True
        assert dec.snap_gen == P._snapshot.gen

        # VACUITY GUARD: the SAME spies DO capture a real sink call -- proving they
        # would catch a violation, not merely that nothing happened to fire them.
        qstate = types.SimpleNamespace(qinfo=types.SimpleNamespace(qname_str=q + ".", qtype_str="A"), return_msg=None)
        P.get_details_dnsbl("dnsbl", None, qstate, {"pfb_addr": "127.0.0.1"}, dec.dnsbl)
        assert enqueue_calls != []
        assert log_calls != []


# --------------------------------------------------------------------------- #
# Section 5 -- hostile-input rows. The request parser is a new local trust
# boundary: every row must never crash the watcher and never write an
# uncorrelatable reply.
# --------------------------------------------------------------------------- #


class TestHostileInputRows:
    def test_row1_malformed_json_no_reply_watcher_alive(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        h.write_raw('{"id":"x",')
        h.start()
        time.sleep(0.3)
        assert h.read_reply() is None
        assert h.thread is not None and h.thread.is_alive()

    def test_row2_non_dict_json_top_level_no_reply(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        h.write_raw("[1, 2]")
        h.start()
        time.sleep(0.3)
        assert h.read_reply() is None
        assert h.thread is not None and h.thread.is_alive()
        # A bare JSON string top-level is also non-dict.
        h.write_raw('"just a string"')
        time.sleep(0.3)
        assert h.read_reply() is None
        assert h.thread.is_alive()

    def test_row3_empty_or_whitespace_request_no_reply(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        h.write_raw("   \n  ")
        h.start()
        time.sleep(0.3)
        assert h.read_reply() is None
        assert h.thread is not None and h.thread.is_alive()

    def test_row4_missing_id_no_reply(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        q = "hostile-missing-id.uuidquery3004.com"
        h.start()
        h.publish({"domain": q, "qtype": "A"})
        time.sleep(0.3)
        assert h.read_reply() is None
        assert h.thread is not None and h.thread.is_alive()

    def test_row5_non_string_or_empty_id_no_reply(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        q = "hostile-bad-id.uuidquery3005.com"
        h.start()
        h.publish({"id": "", "domain": q, "qtype": "A"})
        time.sleep(0.2)
        assert h.read_reply() is None
        h.publish({"id": 123, "domain": q, "qtype": "A"})
        time.sleep(0.2)
        assert h.read_reply() is None
        assert h.thread is not None and h.thread.is_alive()

    def test_row6_missing_empty_non_string_domain_gets_miss_shaped_reply(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        h.start()
        h.publish({"id": "m1"})  # missing domain
        reply = h.wait_reply("m1")
        assert reply == {
            "id": "m1",
            "blocked": False,
            "b_type": "",
            "group": "",
            "b_eval": "",
            "feed": "",
            "p_type": "",
        }

        h.publish({"id": "m2", "domain": ""})
        reply = h.wait_reply("m2")
        assert reply is not None and reply["blocked"] is False

        h.publish({"id": "m3", "domain": 123})
        reply = h.wait_reply("m3")
        assert reply is not None and reply["blocked"] is False
        assert h.thread is not None and h.thread.is_alive()

    def test_row7_punycode_and_raw_non_ascii_domain(self, query_harness: _QueryHarness, monkeypatch: Any) -> None:
        h = query_harness
        h.start()
        for req_id, domain in (("p1", "xn--bcher-kva.zzexample"), ("p2", "bücher.zzexample")):
            h.publish({"id": req_id, "domain": domain, "qtype": "A"})
            reply = h.wait_reply(req_id)
            assert reply is not None
            expected = P.evaluate_domain(
                domain.rstrip(".").lower(),
                domain.rstrip(".").lower(),
                P.get_tld_from_name(domain.rstrip(".").lower()),
                False,
                P._evaluate_cfg(P._snapshot),
                P._snapshot.containers(),
            )
            assert reply["blocked"] == (expected.is_found and not expected.in_whitelist)
        assert h.thread is not None and h.thread.is_alive()

    def test_row8_oversized_domain_no_crash_blocked_false(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        h.start()
        oversized = "a" * 300 + ".com"
        h.publish({"id": "big1", "domain": oversized, "qtype": "A"})
        reply = h.wait_reply("big1")
        assert reply is not None
        assert reply["blocked"] is False
        assert h.thread is not None and h.thread.is_alive()

    def test_row9_unknown_qtype_no_crash(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        q = "hostile-qtype.uuidquery3009.com"
        _seed_blocked_domain(q)
        h.start()
        for req_id, qtype in (("qt1", "FOO"), ("qt2", 42), ("qt3", None)):
            h.publish({"id": req_id, "domain": q, "qtype": qtype})
            reply = h.wait_reply(req_id)
            assert reply is not None
            assert reply["blocked"] is True  # decision is qtype-independent
        assert h.thread is not None and h.thread.is_alive()

    def test_row10_domain_with_embedded_metacharacters_no_crash(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        h.start()
        h.publish({"id": "meta1", "domain": "evil\ndomain,foo;bar", "qtype": "A"})
        reply = h.wait_reply("meta1")
        assert reply is not None
        assert reply["blocked"] is False
        assert h.thread is not None and h.thread.is_alive()

    def test_row11_one_mb_of_junk_no_crash_no_reply(self, query_harness: _QueryHarness) -> None:
        h = query_harness
        h.start()
        h.write_raw("x" * (1024 * 1024))
        time.sleep(0.3)
        assert h.read_reply() is None
        assert h.thread is not None and h.thread.is_alive()

    def test_row12_settle_semantics(self, query_harness: _QueryHarness) -> None:
        # Covered end-to-end by TestQueryWatcherLoop.test_identical_record_answered_once_
        # changed_record_reanswered -- this row restates it as its own hostile-input entry
        # per the coverage matrix.
        h = query_harness
        q = "row12-settle.uuidquery3012.com"
        _seed_blocked_domain(q)
        h.start()
        h.publish({"id": "r12", "domain": q, "qtype": "A"})
        assert h.wait_reply("r12") is not None
        assert h.thread is not None and h.thread.is_alive()

    def test_row13_reply_write_oserror_survives(self, monkeypatch: Any) -> None:
        # A reply path whose directory does not exist raises OSError inside the
        # write helper -- it must be swallowed (stderr-logged), never crash the caller.
        P.pfb["pfb_py_query_reply"] = "/nonexistent-dir-xyz-adr65/reply"
        P._pfb_write_query_reply({"id": "e1", "blocked": False})  # must not raise
