"""ADR-08 Phase 5 -- the Confusable tier wired into the PRODUCTION matcher.

Phase 3 pinned Off/All-IDN (``test_adr08_mode_baseline.py``); Phase 4 shipped the pure
analyzer graded against the Phase-2 oracle (``test_adr08_analyzer.py``). This file is the
Phase-5 gate: it drives the PRODUCTION ``evaluate_domain`` / ``idn_confusable_action`` in
IDN_MODE_CONFUSABLE over the corpus and asserts the matcher's verdict matches the Phase-2
decision oracle (``test_adr08_decision_spec.action``) across EVERY severity tier and BOTH
states of the two sub-toggles:

  * MALICIOUS (Latin+Cyrillic/Greek, Cyrillic+Greek) -> BLOCK by default; -> ALERT when the
    block-malicious sub-toggle is disabled.
  * SUSPICIOUS (Latin+Armenian/Cherokee/Coptic) -> ALERT by default; -> BLOCK when the
    escalate-suspicious sub-toggle is enabled.
  * FLAGGED (scriptless / undecodable -- the decode NEVER raises into the matcher) -> ALERT
    by default; -> BLOCK on escalation; never block-by-default, never crash.
  * LEGIT (single-script, Latin+CJK, IDN-ccTLD per-label) -> RESOLVE (no IDN action).

Plus the two cross-cutting contracts: a non-xn-- query pays nothing (no analysis, resolves),
and WHITELIST WINS -- a user-whitelisted malicious homoglyph is un-blocked by the existing
whiteDB override (the analyzer feeds is_found like any block source; the override is NOT
special-cased). Off/All-IDN are NOT re-tested here -- their no-regression golden is
``test_adr08_mode_baseline.py`` and stays byte-identical.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import types
from collections import defaultdict
from typing import Any

import pytest

_HERE = os.path.dirname(__file__)


def _import_oracle() -> types.ModuleType:
    """Import the Phase-2 oracle as a plain module (same pattern as test_adr08_analyzer).

    ``test_adr08_decision_spec`` is pure (no Unbound symbol); loading it by path avoids
    any pytest import-mode coupling and gives us its ``action`` policy + ACT_* constants
    to grade the PRODUCTION matcher against -- not a re-derived rule.
    """
    spec = importlib.util.spec_from_file_location("adr08_oracle", os.path.join(_HERE, "test_adr08_decision_spec.py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["adr08_oracle"] = module  # so its dataclasses resolve __module__.
    spec.loader.exec_module(module)
    return module


_ORACLE = _import_oracle()
ACT_NONE = _ORACLE.ACT_NONE
ACT_ALERT = _ORACLE.ACT_ALERT
ACT_BLOCK = _ORACLE.ACT_BLOCK
action = _ORACLE.action

from pfb_unbound import (
    IDN_ACT_ALERT,
    IDN_ACT_BLOCK,
    IDN_ACT_NONE,
    IDN_FEED_MALICIOUS,
    IDN_FEED_SUSPECT,
    IDN_GROUP_MALICIOUS,
    IDN_GROUP_SUSPECT,
    IDN_MODE_CONFUSABLE,
    evaluate_domain,
    idn_confusable_action,
)

_CORPUS_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "adr08_corpus", "corpus.json")
with open(_CORPUS_PATH, encoding="utf-8") as _fh:
    _CORPUS = json.load(_fh)

# Map the oracle's ACT_* to the matcher's IDN_ACT_* (same vocabulary, asserted equal so a
# future divergence is caught) -- used to grade idn_confusable_action against action().
_ACT_TO_IDN_ACT = {ACT_NONE: IDN_ACT_NONE, ACT_ALERT: IDN_ACT_ALERT, ACT_BLOCK: IDN_ACT_BLOCK}


# --------------------------------------------------------------------------- #
# Representative names per tier (a real label + a real TLD label) drawn from the corpus.
# evaluate_domain analyses PER LABEL; appending ".com" keeps the offending label intact.
# --------------------------------------------------------------------------- #


def _label(section: str, index: int = 0) -> str:
    return _CORPUS[section][index]["a_label"]


# One concrete name per severity, each a corpus entry whose decoded form is documented above.
MALICIOUS_NAME = _label("homograph_single_label", 0) + ".com"  # xn--pple-43d = аpple (Latin+Cyrillic)
MALICIOUS_NAME_2 = _label("homograph_single_label", 4) + ".com"  # xn--mxa00ab = сαр (Cyrillic+Greek)
SUSPICIOUS_NAME = _label("suspicious_single_label", 0) + ".com"  # xn--bnk-1ce = bաnk (Latin+Armenian)
FLAGGED_SCRIPTLESS_NAME = _CORPUS["edge_decode"][4]["a_label"] + ".com"  # xn--ls8h = 💩 (no letter-script)
FLAGGED_DECODE_ERR_NAME = _CORPUS["edge_decode"][2]["a_label"] + ".com"  # xn--zz -> UnicodeDecodeError
LEGIT_CJK_NAME = _label("legit_single_label", 5) + ".com"  # xn--wgv71a119e = 日本語 (single-script Han)
LEGIT_ACCENTED_NAME = _label("legit_single_label", 0) + ".com"  # xn--mnchen-3ya = münchen (single Latin)
# A legit ASCII/Latin SLD under an IDN ccTLD -- per-label, must NOT union across the dot.
LEGIT_IDN_CCTLD_NAME = _CORPUS["legit_multi_label"][0]["a_name"]  # example.xn--p1ai (example.рф)
NON_IDN_NAME = "plain-ascii.example.com"  # no xn-- label anywhere


# --------------------------------------------------------------------------- #
# Matcher cfg/containers: only the IDN feed is enabled, so a block can ONLY be the IDN
# branch (isolates exactly the Confusable tier). whiteDB toggled per the whitelist case.
# --------------------------------------------------------------------------- #


def _make_cfg(**overrides: Any) -> dict:
    base = {
        "python_blocking": True,
        "dataDB": False,
        "zoneDB": False,
        "python_tld": False,
        "python_tlds": [],
        "dnsbl_ipv4": "10.10.10.1",
        "dnsbl_ipv6": "::1",
        "regexDB": False,
        "whiteDB": False,
        "python_tld_seg": 2,
        "hstsDB": False,
        "hsts_tlds": (),
        "idn_mode": IDN_MODE_CONFUSABLE,
        # Defaults under test: malicious blocks, suspicious only alerts.
        "python_idn_block_malicious": True,
        "python_idn_escalate_suspicious": False,
    }
    base.update(overrides)
    return base


def _make_containers(white: dict[str, Any] | None = None) -> dict:
    return {
        "dataDB": {},
        "zoneDB": {},
        "whiteDB": white or {},
        "hstsDB": {},
        "regexDB": defaultdict(str),
        "feedGroupIndexDB": defaultdict(list),
    }


def _evaluate(q_name: str, *, white: dict[str, Any] | None = None, **cfg_overrides: Any) -> Any:
    cfg = _make_cfg(whiteDB=bool(white), **cfg_overrides)
    return evaluate_domain(q_name, q_name, "com", False, cfg, _make_containers(white))


# --------------------------------------------------------------------------- #
# 1. idn_confusable_action reproduces the Phase-2 oracle action() across all tiers + toggles.
#    (The policy seam -- the matcher branch below consumes this.)
# --------------------------------------------------------------------------- #


class TestConfusableActionMatchesOracle:
    """``idn_confusable_action`` == the oracle's ``action(severity, *toggles)`` per tier.

    Scenario: the matcher's severity->action policy under the two sub-toggles.
      Background: a representative xn-- name per severity drawn from the corpus.
    """

    @pytest.mark.parametrize(
        "name,severity",
        [
            (MALICIOUS_NAME, "malicious"),
            (MALICIOUS_NAME_2, "malicious"),
            (SUSPICIOUS_NAME, "suspicious"),
            (FLAGGED_SCRIPTLESS_NAME, "flagged"),
            (FLAGGED_DECODE_ERR_NAME, "flagged"),
            (LEGIT_CJK_NAME, "legit"),
            (LEGIT_ACCENTED_NAME, "legit"),
            (LEGIT_IDN_CCTLD_NAME, "legit"),
        ],
    )
    @pytest.mark.parametrize("block_malicious", [True, False])
    @pytest.mark.parametrize("escalate_suspicious", [True, False])
    def test_action_equals_oracle_for_every_tier_and_toggle(
        self, name: str, severity: str, block_malicious: bool, escalate_suspicious: bool
    ) -> None:
        # When the production policy classifies the name under these toggles; Then its action
        # equals the oracle's action() for the (known) severity -- every tier x both toggles.
        act, verdict = idn_confusable_action(
            name, block_malicious=block_malicious, escalate_suspicious=escalate_suspicious
        )
        assert verdict is not None  # an xn-- name always yields a verdict
        assert verdict.severity == severity, (name, verdict.severity)
        oracle_act = action(severity, block_malicious=block_malicious, escalate_suspicious=escalate_suspicious)
        assert act == _ACT_TO_IDN_ACT[oracle_act], (name, severity, block_malicious, escalate_suspicious)

    def test_non_idn_query_pays_nothing(self) -> None:
        # A name with no xn-- label is NEVER classified (no decode/script work) -> NONE, no
        # verdict. This is the bounded-cost contract (analysis gated behind is_idn_domain).
        act, verdict = idn_confusable_action(NON_IDN_NAME, block_malicious=True, escalate_suspicious=False)
        assert act == IDN_ACT_NONE
        assert verdict is None

    def test_malformed_label_never_raises(self) -> None:
        # The decode-error FLAGGED case must come back as a verdict (FLAGGED) -- proving the
        # decode is caught, NOT propagated into the matcher (would crash the resolver).
        act, verdict = idn_confusable_action(FLAGGED_DECODE_ERR_NAME, block_malicious=True, escalate_suspicious=False)
        assert verdict is not None and verdict.severity == "flagged"
        assert act == IDN_ACT_ALERT  # flagged alerts by default


# --------------------------------------------------------------------------- #
# 2. PRODUCTION evaluate_domain: the wired matcher block/alert/resolve per tier.
# --------------------------------------------------------------------------- #


class TestConfusableMatcherDefaults:
    """evaluate_domain in Confusable mode with DEFAULT toggles (block malicious, alert rest).

    Scenario: the shipped default policy at the matcher.
      Background: only the IDN feed enabled, so any block is the homoglyph tier.
    """

    def test_malicious_blocks_as_homoglyph_feed(self) -> None:
        # Given a Latin+Cyrillic homograph; Then it BLOCKS, attributed to the distinct
        # Homoglyph feed/group (NOT the blunt "IDN"/"DNSBL_IDN") with a dual-form b_eval.
        for name in (MALICIOUS_NAME, MALICIOUS_NAME_2):
            dec = _evaluate(name)
            assert dec.is_found is True, name
            assert dec.feed == IDN_FEED_MALICIOUS, name
            assert dec.group == IDN_GROUP_MALICIOUS, name
            assert dec.idn_alert is None, name  # a block, not an alert
            # Dual form: the A-label + the decoded Unicode in brackets, actionable in the log.
            assert name.split(".", 1)[0] in dec.b_eval, name
            assert "[" in dec.b_eval and "]" in dec.b_eval, name

    def test_suspicious_alerts_but_resolves(self) -> None:
        # Given a Latin+Armenian suspicious mix; Then it does NOT block (resolves) but records
        # an alert under the Suspect feed/group -- the alert-not-block default.
        dec = _evaluate(SUSPICIOUS_NAME)
        assert dec.is_found is False
        assert dec.idn_alert is not None
        feed, group, b_eval = dec.idn_alert
        assert feed == IDN_FEED_SUSPECT
        assert group == IDN_GROUP_SUSPECT
        assert SUSPICIOUS_NAME.split(".", 1)[0] in b_eval

    def test_flagged_scriptless_alerts_but_resolves(self) -> None:
        # A scriptless label (💩) -> FLAGGED -> alert (not block), surfaced under Suspect.
        dec = _evaluate(FLAGGED_SCRIPTLESS_NAME)
        assert dec.is_found is False
        assert dec.idn_alert is not None
        assert dec.idn_alert[1] == IDN_GROUP_SUSPECT

    def test_flagged_decode_error_alerts_and_never_crashes(self) -> None:
        # An undecodable label -> FLAGGED -> alert; evaluate_domain returns normally (the
        # decode error is caught inside classify_idn, never raised into the matcher).
        dec = _evaluate(FLAGGED_DECODE_ERR_NAME)
        assert dec.is_found is False
        assert dec.idn_alert is not None
        assert dec.idn_alert[1] == IDN_GROUP_SUSPECT

    def test_legit_idn_resolves_untouched(self) -> None:
        # Single-script Han, single Latin, and an ASCII SLD under an IDN ccTLD all RESOLVE --
        # no block, no alert (the per-label rule keeps example.рф legit, no cross-dot union).
        for name in (LEGIT_CJK_NAME, LEGIT_ACCENTED_NAME, LEGIT_IDN_CCTLD_NAME):
            dec = _evaluate(name)
            assert dec.is_found is False, name
            assert dec.idn_alert is None, name

    def test_non_idn_resolves_untouched(self) -> None:
        dec = _evaluate(NON_IDN_NAME)
        assert dec.is_found is False
        assert dec.idn_alert is None


class TestConfusableMatcherSubToggles:
    """The two sub-toggles flip the matcher action -- before/after each transition pinned."""

    def test_disabling_block_malicious_downgrades_block_to_alert(self) -> None:
        # Given the default (block-malicious ON) a homograph BLOCKS (before-state);
        # When the operator disables block-malicious; Then the SAME homograph only ALERTS
        # (resolves) under the malicious feed -- green proves the toggle (not the input) flips it.
        before = _evaluate(MALICIOUS_NAME)  # default: block_malicious True
        assert before.is_found is True and before.idn_alert is None
        after = _evaluate(MALICIOUS_NAME, python_idn_block_malicious=False)
        assert after.is_found is False  # no longer blocked
        assert after.idn_alert is not None
        assert after.idn_alert[1] == IDN_GROUP_MALICIOUS  # still attributed malicious, just alerted

    def test_enabling_escalate_suspicious_promotes_alert_to_block(self) -> None:
        # Given the default (escalate OFF) a suspicious mix only ALERTS (before-state);
        # When the operator escalates; Then the SAME name BLOCKS under the Suspect feed.
        before = _evaluate(SUSPICIOUS_NAME)  # default: escalate False
        assert before.is_found is False and before.idn_alert is not None
        after = _evaluate(SUSPICIOUS_NAME, python_idn_escalate_suspicious=True)
        assert after.is_found is True
        assert after.feed == IDN_FEED_SUSPECT
        assert after.group == IDN_GROUP_SUSPECT
        assert after.idn_alert is None  # a block now, not an alert

    def test_escalate_promotes_flagged_to_block(self) -> None:
        # FLAGGED is escalatable like suspicious: alert by default, block when escalated.
        before = _evaluate(FLAGGED_SCRIPTLESS_NAME)
        assert before.is_found is False and before.idn_alert is not None
        after = _evaluate(FLAGGED_SCRIPTLESS_NAME, python_idn_escalate_suspicious=True)
        assert after.is_found is True
        assert after.group == IDN_GROUP_SUSPECT


class TestConfusableWhitelistWins:
    """A user-whitelisted homoglyph is un-blocked by the existing whiteDB override (NOT
    special-cased -- the analyzer feeds is_found, the override applies after)."""

    def test_whitelisted_malicious_homoglyph_is_unblocked(self) -> None:
        # Given a malicious homograph that BLOCKS without a whitelist (before-state);
        # When the user whitelists that exact name; Then evaluate_domain still finds it
        # (is_found True) but in_whitelist flips True -> operate() lets it resolve. The
        # whiteDB override runs AFTER the IDN block, exactly as for any other block source.
        blocked = _evaluate(MALICIOUS_NAME)
        assert blocked.is_found is True and blocked.in_whitelist is False  # before-state

        white = {MALICIOUS_NAME: True}  # a user whitelist entry (bare-bool legacy shape)
        allowed = _evaluate(MALICIOUS_NAME, white=white)
        assert allowed.is_found is True  # the IDN block STILL fires (analyzer feeds is_found)
        assert allowed.in_whitelist is True  # ...but the whiteDB override un-blocks it


class TestConfusableBlockBandUnderImportantRules:
    """Regression (PR #136 review): a Confusable (and All-IDN) BLOCK must carry a
    non-zero block_band so the ABP numeric resolution (``important_rules``) does not
    read it as already overridden. ``_resolve_numeric_allow`` returns ``allow_band >=
    block_band``; with ``block_band == 0`` a no-allow ``allow_band == 0`` makes ``0 >=
    0`` true, silently resolving every IDN block the instant any ABP $important / feed
    @@ / feed-regex forces the numeric path."""

    def test_malicious_homograph_stays_blocked_under_important_rules(self) -> None:
        # Given a malicious homograph that blocks on the fast path (before-state)...
        before = _evaluate(MALICIOUS_NAME)
        assert before.is_found is True and before.in_whitelist is False
        # When important_rules forces the numeric 6-band resolution with NO allow match...
        after = _evaluate(MALICIOUS_NAME, important_rules=True)
        # Then the block is honoured (a real feed-band block, not auto-overridden).
        assert after.is_found is True
        assert after.in_whitelist is False
