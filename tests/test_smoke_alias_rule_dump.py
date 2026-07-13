"""``alias_rule_dump`` must name WHICH layer lost a pfB alias's auto-rule.

Issue #1239 filed a ``rule_references`` smoke flake with a fabricated cause ("the check
does not poll" — it has polled since PR #133). The real cause is still unknown, and the two
candidates demand opposite responses: the rule was never written to config.xml (a PRODUCT
bug — a populated block table with nothing enforcing it) versus the rule was written and
emitted but pf had not loaded it yet (a genuine reload lag, i.e. a test-only flake).

Only the layer that still holds the rule tells them apart, so the on-failure dump reports a
``[STAGE LOST]`` verdict across CONFIG -> RULES.DEBUG -> LIVE PF. This module pins that
verdict for every layer combination off-VM (``tests.smoke.helpers`` is import-safe —
precedent: ``test_smoke_unbound_ready.py``), so the next live occurrence localises itself
instead of being re-guessed.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

import pytest

from tests.smoke import helpers

ALIAS = "pfB_DNSBLIP_v4"
CFG_ROW = "pfB_DNSBLIP_v4 auto rule|block|if=wan|inet|src=pfB_DNSBLIP_v4|dst=any|disabled=0"
DEBUG_ROW = "412:block drop in quick on em0 from <pfB_DNSBLIP_v4> to any"
LIVE_ROW = "block drop in quick on em0 from <pfB_DNSBLIP_v4> to any"


@dataclass
class _FakeResult:
    """Stand-in for ``subprocess.CompletedProcess[str]`` (the shape ``SmokeVM.ssh`` returns)."""

    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


@dataclass
class _FakeVM:
    """Fake ``vm.ssh(*remote, ...)`` dispatching on the command, not on call order.

    Order-independent by construction: the dump may reorder its probes without silently
    turning these fixtures into the wrong layer's answer.
    """

    rules_debug: str = ""
    live_rules: str = ""
    tables: str = ""
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def ssh(self, *remote: str, timeout: float = 60.0) -> _FakeResult:
        self.calls.append(remote)
        if remote[0] == "/usr/bin/grep":
            # grep exits 1 on no match — the dump must treat that as "absent", not as an error.
            return _FakeResult(returncode=0 if self.rules_debug else 1, stdout=self.rules_debug)
        if remote[:2] == (helpers.PFCTL, "-sr"):
            return _FakeResult(stdout=self.live_rules)
        if remote[:2] == (helpers.PFCTL, "-sTables"):
            return _FakeResult(stdout=self.tables)
        raise AssertionError(f"unexpected ssh command: {remote}")


def _fake_php_eval(rows: str) -> object:
    """Return a php_eval stand-in emitting the dump's ``<<CFG>>``-delimited config rows."""

    def _run(_vm: object, _snippet: str, *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=f"banner\n<<CFG>>{rows}<<END>>\n", stderr="")

    return _run


@pytest.mark.parametrize(
    ("cfg_rows", "rules_debug", "live_rules", "expected_stage"),
    [
        # Scenario: the rule never reached config.xml -> pfBlockerNG never generated it.
        # This is the PRODUCT-bug verdict: the block table can be populated with no rule
        # enforcing it, which no amount of extra polling would ever fix.
        ("", "", "", "CONFIG"),
        # Scenario: written to config.xml, but filter_configure never emitted it into the
        # generated ruleset -> the pfSense rule generator dropped it (a rule-shape problem).
        (CFG_ROW, "", "", "RULES.DEBUG"),
        # Scenario: emitted into rules.debug but not yet loaded into pf -> the genuine
        # reload-lag verdict (or a pfctl load rejection), i.e. a test-only flake.
        (CFG_ROW, DEBUG_ROW, "", "LIVE PF"),
        # Scenario: present at all three layers -> rule_references' poll read stale state;
        # the rule IS there, so the assertion, not the product, is what to look at.
        (CFG_ROW, DEBUG_ROW, LIVE_ROW, "NONE"),
    ],
    ids=["never-generated", "generator-dropped-it", "emitted-not-loaded", "present-everywhere"],
)
def test_stage_lost_names_the_layer_that_lost_the_rule(
    monkeypatch: pytest.MonkeyPatch,
    cfg_rows: str,
    rules_debug: str,
    live_rules: str,
    expected_stage: str,
) -> None:
    """Given a box where the alias's rule survives only up to a given layer
    When alias_rule_dump runs
    Then its [STAGE LOST] verdict names THAT layer — the one discriminator that decides
    whether the flake is a product bug (rule never generated) or a reload lag.
    """
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(cfg_rows))
    vm = _FakeVM(rules_debug=rules_debug, live_rules=live_rules, tables=f"{ALIAS}\npfB_DNSBLIP_v6\n")

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    stage_line = next(ln for ln in dump.splitlines() if ln.startswith("[STAGE LOST]"))
    assert expected_stage in stage_line, f"expected stage {expected_stage!r} in: {stage_line!r}"
    # The verdict must be unambiguous — exactly one layer named, never two.
    others = {"CONFIG", "RULES.DEBUG", "LIVE PF", "NONE"} - {expected_stage}
    # "CONFIG" is a substring of nothing else here, but "LIVE PF"/"RULES.DEBUG" could co-occur
    # in a sloppy verdict string; assert the others are absent so a catch-all message fails.
    assert not [o for o in others if o in stage_line.split("—")[0]], f"verdict is ambiguous: {stage_line!r}"


def test_dump_carries_the_underlying_evidence_not_just_the_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given a box holding the rule at every layer
    When alias_rule_dump runs
    Then the raw per-layer evidence is printed too — a verdict with no evidence behind it
    cannot be audited when the verdict itself is what turns out to be wrong (issue #1239).
    """
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(CFG_ROW))
    vm = _FakeVM(rules_debug=DEBUG_ROW, live_rules=LIVE_ROW, tables=f"{ALIAS}\n")

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    assert CFG_ROW in dump, f"config row missing from dump:\n{dump}"
    assert DEBUG_ROW in dump, f"rules.debug row missing from dump:\n{dump}"
    assert LIVE_ROW in dump, f"live pf row missing from dump:\n{dump}"
    assert "[pf table pfB_DNSBLIP_v4 exists] True" in dump, f"table existence missing from dump:\n{dump}"


def test_missing_pf_table_is_reported_rather_than_assumed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given a box where the pf table itself does not exist
    When alias_rule_dump runs
    Then it reports the table as absent — a rule referencing a table that was never loaded
    is a different failure from a table that exists but is unreferenced.
    """
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(""))
    vm = _FakeVM(tables="pfB_Something_Else_v4\n")

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    assert "[pf table pfB_DNSBLIP_v4 exists] False" in dump, f"absent table not reported:\n{dump}"


@pytest.mark.parametrize(
    "hostile",
    ["pfB_x'; system('id'); $z='", "pfB_x\nfoo", "pfB-x", "", "pfB_x; rm -rf /", "pfB_x'", "../etc/passwd"],
    ids=["php-quote-break", "newline", "dash", "empty", "shell-metachars", "bare-quote", "path-traversal"],
)
def test_alias_is_validated_before_it_reaches_the_php_snippet(hostile: str) -> None:
    """Given an alias carrying quotes, newlines, shell metacharacters or path separators
    When alias_rule_dump is called with it
    Then it raises ValueError instead of interpolating it into the pfSsh.php snippet — the
    alias crosses into a PHP string literal, so the bare-table-name shape is a trust boundary.
    """
    with pytest.raises(ValueError, match="bare pf table name"):
        helpers.alias_rule_dump(_FakeVM(), hostile)  # type: ignore[arg-type]
