"""Pin the layered alias-rule diagnostic and forbid retired pfctl polls."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

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
    grep_rc: int | None = None
    sr_rc: int = 0
    tables_rc: int = 0
    # issue #1252: probe keys ("grep"/"sr"/"tables") whose ssh call stalls the transport
    # instead of returning — TimeoutExpired, not a returncode.
    timeout_on: frozenset[str] = field(default_factory=frozenset)
    # What the stalled probe had already written before it hung. CPython attaches this to
    # TimeoutExpired UNDECODED (bytes) even under text=True, so bytes is the realistic value.
    timeout_output: dict[str, bytes | str] = field(default_factory=dict)
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def _stall(self, key: str, remote: tuple[str, ...], timeout: float) -> None:
        raise subprocess.TimeoutExpired(cmd=list(remote), timeout=timeout, output=self.timeout_output.get(key))

    def ssh(self, *remote: str, timeout: float = 60.0) -> _FakeResult:
        self.calls.append(remote)
        if remote[0] == "/usr/bin/grep":
            if "grep" in self.timeout_on:
                self._stall("grep", remote, timeout)
            # grep exits 1 on no match — the dump must treat that as "absent", not as an error.
            rc = self.grep_rc if self.grep_rc is not None else (0 if self.rules_debug else 1)
            return _FakeResult(returncode=rc, stdout=self.rules_debug)
        if remote[:2] == (helpers.PFCTL, "-sr"):
            if "sr" in self.timeout_on:
                self._stall("sr", remote, timeout)
            return _FakeResult(returncode=self.sr_rc, stdout=self.live_rules)
        if remote[:2] == (helpers.PFCTL, "-sTables"):
            if "tables" in self.timeout_on:
                self._stall("tables", remote, timeout)
            return _FakeResult(returncode=self.tables_rc, stdout=self.tables)
        raise AssertionError(f"unexpected ssh command: {remote}")


def _fake_php_eval(rows: str, *, returncode: int = 0, raw: str | None = None, raises_timeout: bool = False) -> object:
    """Return a php_eval stand-in emitting the dump's ``<<CFG>>``-delimited config rows.

    ``raw`` replaces the whole stdout, so a test can simulate pfSsh.php fatalling before it
    printed the sentinels (it still exits 0 — the sentinels are the only completion proof).
    ``raises_timeout`` (issue #1252) simulates the transport stalling instead.
    """

    def _run(_vm: object, _snippet: str, *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        if raises_timeout:
            raise subprocess.TimeoutExpired(cmd=["/usr/local/sbin/pfSsh.php"], timeout=timeout)
        stdout = raw if raw is not None else f"banner\n<<CFG>>{rows}<<END>>\n"
        return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")

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
        # Scenario: present at all three layers -> the read saw stale state;
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
    ("kwargs", "vm_kwargs", "broken"),
    [
        # pfSsh.php exits 0 even when the PHP inside it fatals, so a missing sentinel — not
        # the return code — is what proves the config read never completed.
        ({"raw": "banner\nPHP Fatal error: something\n"}, {}, "CONFIG(pfSsh)"),
        ({"returncode": 1}, {}, "CONFIG(pfSsh)"),
        # grep rc>=2 = the grep itself failed (e.g. /tmp/rules.debug missing); rc 1 is a real
        # "no match" answer and must NOT be treated as a broken probe (covered elsewhere).
        ({}, {"grep_rc": 2}, "RULES.DEBUG(grep)"),
        ({}, {"sr_rc": 1}, "LIVE PF(pfctl -sr)"),
    ],
    ids=["pfssh-fatal", "pfssh-nonzero-rc", "grep-error", "pfctl-error"],
)
def test_a_failed_probe_is_unproven_never_an_accusation(
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, object],
    vm_kwargs: dict[str, object],
    broken: str,
) -> None:
    """Given a probe that ERRORS rather than returning an answer
    When alias_rule_dump runs
    Then the verdict is UNPROVEN and names the broken probe — it must NEVER read a failed
    probe's empty output as "the rule was never generated". Blaming the product for a
    pfSsh.php error is precisely the misdiagnosis this helper exists to prevent, so the
    accusing CONFIG verdict must be absent.
    """
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(CFG_ROW, **kwargs))  # type: ignore[arg-type]
    vm = _FakeVM(rules_debug=DEBUG_ROW, live_rules=LIVE_ROW, tables=ALIAS, **vm_kwargs)  # type: ignore[arg-type]

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    stage_line = next(ln for ln in dump.splitlines() if ln.startswith("[STAGE LOST]"))
    assert "UNPROVEN" in stage_line, f"a failed probe did not yield UNPROVEN: {stage_line!r}"
    assert broken in stage_line, f"the broken probe {broken!r} is not named: {stage_line!r}"
    assert "NEVER generated" not in stage_line, f"a failed probe accused the product: {stage_line!r}"


def test_config_probe_timeout_is_unproven_not_a_raw_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given the pfSsh.php transport stalling (subprocess.TimeoutExpired)
    When alias_rule_dump runs
    Then the verdict is UNPROVEN naming CONFIG(pfSsh) — the exception must NOT escape and
    wreck the other three layers' diagnostic output (issue #1252).
    """
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(CFG_ROW, raises_timeout=True))
    vm = _FakeVM(rules_debug=DEBUG_ROW, live_rules=LIVE_ROW, tables=ALIAS)

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    stage_line = next(ln for ln in dump.splitlines() if ln.startswith("[STAGE LOST]"))
    assert "UNPROVEN" in stage_line, f"a stalled probe did not yield UNPROVEN: {stage_line!r}"
    assert "CONFIG(pfSsh)" in stage_line, f"the stalled probe is not named: {stage_line!r}"
    assert "pfSsh=124" in stage_line, f"the timeout rc is not reported as 124: {stage_line!r}"


def test_rules_debug_probe_timeout_is_unproven_not_a_raw_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given the rules.debug grep stalling
    When alias_rule_dump runs
    Then the verdict is UNPROVEN naming RULES.DEBUG(grep) (issue #1252).
    """
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(CFG_ROW))
    vm = _FakeVM(live_rules=LIVE_ROW, tables=ALIAS, timeout_on=frozenset({"grep"}))

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    stage_line = next(ln for ln in dump.splitlines() if ln.startswith("[STAGE LOST]"))
    assert "UNPROVEN" in stage_line, f"a stalled probe did not yield UNPROVEN: {stage_line!r}"
    assert "RULES.DEBUG(grep)" in stage_line, f"the stalled probe is not named: {stage_line!r}"
    assert "grep=124" in stage_line, f"the timeout rc is not reported as 124: {stage_line!r}"


def test_live_pf_probe_timeout_is_unproven_not_a_raw_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given the ``pfctl -sr`` read stalling
    When alias_rule_dump runs
    Then the verdict is UNPROVEN naming LIVE PF(pfctl -sr) (issue #1252).
    """
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(CFG_ROW))
    vm = _FakeVM(rules_debug=DEBUG_ROW, tables=ALIAS, timeout_on=frozenset({"sr"}))

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    stage_line = next(ln for ln in dump.splitlines() if ln.startswith("[STAGE LOST]"))
    assert "UNPROVEN" in stage_line, f"a stalled probe did not yield UNPROVEN: {stage_line!r}"
    assert "LIVE PF(pfctl -sr)" in stage_line, f"the stalled probe is not named: {stage_line!r}"
    assert "pfctl-sr=124" in stage_line, f"the timeout rc is not reported as 124: {stage_line!r}"


def test_table_existence_probe_timeout_does_not_flip_the_verdict_to_unproven(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Given ONLY the ``pfctl -sTables`` read stalling, with the rule present at all 3 layers
    When alias_rule_dump runs
    Then the verdict stays the normal layer verdict (NONE here) — table existence is not one
    of the three UNPROVEN causes today, and a stalled table read must not change that. A naive
    "catch every TimeoutExpired into broken" implementation fails this (issue #1252).
    """
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(CFG_ROW))
    vm = _FakeVM(rules_debug=DEBUG_ROW, live_rules=LIVE_ROW, timeout_on=frozenset({"tables"}))

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    stage_line = next(ln for ln in dump.splitlines() if ln.startswith("[STAGE LOST]"))
    assert "UNPROVEN" not in stage_line, f"a stalled table read wrongly flipped the verdict: {stage_line!r}"
    assert "NONE" in stage_line, f"expected the normal NONE verdict: {stage_line!r}"
    assert "[pf table pfB_DNSBLIP_v4 exists] UNKNOWN (pfctl -sTables failed)" in dump, (
        f"the stalled table read is not reported as UNKNOWN:\n{dump}"
    )


def test_all_three_verdict_probes_stalling_names_all_three(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given CONFIG, RULES.DEBUG and LIVE PF all stalling at once
    When alias_rule_dump runs
    Then the single UNPROVEN verdict names all three — mirrors today's multi-rc-failure
    behaviour (issue #1252).
    """
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(CFG_ROW, raises_timeout=True))
    vm = _FakeVM(tables=ALIAS, timeout_on=frozenset({"grep", "sr"}))

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    stage_line = next(ln for ln in dump.splitlines() if ln.startswith("[STAGE LOST]"))
    assert "UNPROVEN" in stage_line, f"stalled probes did not yield UNPROVEN: {stage_line!r}"
    for name in ("CONFIG(pfSsh)", "RULES.DEBUG(grep)", "LIVE PF(pfctl -sr)"):
        assert name in stage_line, f"{name!r} missing from: {stage_line!r}"
    assert "pfSsh=124" in stage_line and "grep=124" in stage_line and "pfctl-sr=124" in stage_line, (
        f"not all rc fields report 124: {stage_line!r}"
    )


def test_output_written_before_a_stall_still_reaches_the_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given a probe that printed part of its answer and THEN hung
    When alias_rule_dump runs
    Then the partial output still appears in its layer — a stalled probe is unusable as
    PROOF (the verdict stays UNPROVEN), but what it did manage to say is exactly the
    diagnostic this helper exists to surface, so it must not be thrown away (issue #1252).
    """
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(CFG_ROW))
    vm = _FakeVM(
        live_rules=LIVE_ROW,
        tables=ALIAS,
        timeout_on=frozenset({"grep"}),
        # CPython hands back the pre-stall buffer as raw BYTES even under text=True.
        timeout_output={"grep": DEBUG_ROW.encode()},
    )

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    stage_line = next(ln for ln in dump.splitlines() if ln.startswith("[STAGE LOST]"))
    assert "UNPROVEN" in stage_line, f"a stalled probe did not yield UNPROVEN: {stage_line!r}"
    assert f"[RULES.DEBUG {ALIAS}: 1] {DEBUG_ROW}" in dump, (
        f"the output the probe managed to write before stalling was discarded:\n{dump}"
    )


def test_a_stall_mid_utf8_sequence_does_not_crash_the_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    """Given a probe that hung mid-way through a multi-byte character
    When alias_rule_dump runs
    Then the dump still renders — a transport stall truncates at an arbitrary BYTE, so the
    pre-stall buffer routinely ends inside a UTF-8 sequence and must never raise (issue #1252).
    """
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(CFG_ROW))
    vm = _FakeVM(
        rules_debug=DEBUG_ROW,
        tables=ALIAS,
        timeout_on=frozenset({"sr"}),
        timeout_output={"sr": LIVE_ROW.encode() + "é".encode()[:1]},  # dangling lead byte
    )

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    stage_line = next(ln for ln in dump.splitlines() if ln.startswith("[STAGE LOST]"))
    assert "UNPROVEN" in stage_line, f"a stalled probe did not yield UNPROVEN: {stage_line!r}"
    assert f"[LIVE PF -sr {ALIAS}: 1] {LIVE_ROW}" in dump, (
        f"the decodable part of the pre-stall buffer was lost:\n{dump}"
    )


def test_a_rule_naming_the_alias_only_in_its_descr_does_not_count_as_a_reference() -> None:
    """The CONFIG layer must match the source/destination ADDRESS, never the descr label.

    A rule whose descr merely mentions the table enforces nothing. Counting it would report
    the rule as generated while no traffic is actually filtered — the exact false-negative
    that would have hidden #1239's real defect. Pinned on the emitted PHP, which is where
    the matching happens.
    """
    php = _php_snippet_for(ALIAS)

    assert "$s===$a||$d===$a" in php, f"CONFIG no longer matches on the address fields:\n{php}"
    assert "strpos" not in php, f"CONFIG still admits a descr substring match:\n{php}"


def _php_snippet_for(alias: str) -> str:
    """Capture the PHP the dump feeds pfSsh.php (the snippet is built inline, not exported)."""
    captured: list[str] = []

    def _capture(_vm: object, snippet: str, *, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        captured.append(snippet)
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="<<CFG>><<END>>", stderr="")

    original = helpers.php_eval
    helpers.php_eval = _capture  # type: ignore[assignment]
    try:
        helpers.alias_rule_dump(_FakeVM(), alias)  # type: ignore[arg-type]
    finally:
        helpers.php_eval = original  # type: ignore[assignment]
    return captured[0]


def test_public_dump_uses_exact_alias_match(monkeypatch: pytest.MonkeyPatch) -> None:
    """The public dump includes only rules that reference the requested table."""
    monkeypatch.setattr(helpers, "php_eval", _fake_php_eval(CFG_ROW))
    foreign = "block drop in quick from <pfB_Other_v4> to any"
    generic = "block drop in quick on em0 # mentions harness"
    vm = _FakeVM(
        rules_debug=f"{DEBUG_ROW}\n{foreign}\n{generic}\n",
        live_rules=f"{LIVE_ROW}\n{foreign}\n{generic}\n",
        tables=f"{ALIAS}\npfB_Other_v4\n",
    )

    dump = helpers.alias_rule_dump(vm, ALIAS)  # type: ignore[arg-type]

    assert f"[RULES.DEBUG {ALIAS}: 1] {DEBUG_ROW}" in dump
    assert f"[LIVE PF -sr {ALIAS}: 1] {LIVE_ROW}" in dump
    assert foreign not in dump
    assert generic not in dump


@pytest.mark.parametrize(
    ("live_rules", "alias", "expected"),
    [
        ("block drop in quick from <pfB_Foo_v4> to any", "pfB_Foo_v4", True),
        ("block drop in quick from <pfB_Foo_v4_other_v4> to any", "pfB_Foo_v4", False),
        ("block drop in quick from <pfB_Other_v4> to any", "pfB_Foo_v4", False),
        ("block drop in quick from pfB_Foo_v4, to any", "pfB_Foo_v4", True),
        ("block drop in quick from pfB_Foo_v4_other_v4 to any", "pfB_Foo_v4", False),
        ("block drop in quick from harness to any", "harness", False),
        ("block drop in quick from <harness> to any", "harness", True),
        # Bare-token matching must quote an unvalidated alias before compiling it as regex.
        ("block drop in quick from pfB_FooXv4 to any", "pfB_Foo.v4", False),
    ],
    ids=[
        "exact-angle-token",
        "longer-angle-token",
        "foreign-angle-token",
        "bare-token-punctuation-boundary",
        "longer-bare-token",
        "generic-bare-word",
        "generic-angle-token",
        "metacharacter-is-literal",
    ],
)
def test_pfctl_rule_has_alias_matches_complete_tokens(live_rules: str, alias: str, expected: bool) -> None:
    """Match only the complete requested table token in an authoritative pfctl snapshot."""
    actual = helpers.pfctl_rule_has_alias(_FakeVM(live_rules=live_rules), alias)  # type: ignore[arg-type]

    assert actual == expected, f"alias={alias!r} live_rules={live_rules!r}: expected {expected}, got {actual}"


def test_no_retired_pf_poll_names_remain() -> None:
    """Every Python smoke file must use sync boundaries plus one-shot reads."""
    retired = ["_".join(("wait", "pfctl", "table")), "_".join(("rule", "references"))]
    root = Path(__file__).parent
    hits = [
        (str(path), token)
        for path in sorted(root.rglob("*.py"))
        for token in retired
        if token in path.read_text(encoding="utf-8")
    ]
    assert not hits, "retired pf poll names found:\n" + "\n".join(f"{path}: {token}" for path, token in hits)


@pytest.mark.parametrize(
    "hostile",
    [
        "pfB_x'; system('id'); $z='",
        "pfB_x\nfoo",
        # A TRAILING newline is the shape a `$`-anchored re.match() silently admits (it matches
        # just before a final \n) — the guard must use fullmatch, so this rejects too.
        "pfB_x\n",
        "pfB-x",
        "",
        "pfB_x; rm -rf /",
        "pfB_x'",
        "../etc/passwd",
        "pfB_$var",
        "pfB_x\\",
        "pfB_ünïcode",
    ],
    ids=[
        "php-quote-break",
        "embedded-newline",
        "trailing-newline",
        "dash",
        "empty",
        "shell-metachars",
        "bare-quote",
        "path-traversal",
        "php-var-interpolation",
        "backslash",
        "unicode",
    ],
)
def test_alias_is_validated_before_it_reaches_the_php_snippet(hostile: str) -> None:
    """Given an alias carrying quotes, newlines, shell metacharacters or path separators
    When alias_rule_dump is called with it
    Then it raises ValueError instead of interpolating it into the pfSsh.php snippet — the
    alias crosses into a PHP string literal, so the bare-table-name shape is a trust boundary.
    """
    with pytest.raises(ValueError, match="bare pf table name"):
        helpers.alias_rule_dump(_FakeVM(), hostile)  # type: ignore[arg-type]
