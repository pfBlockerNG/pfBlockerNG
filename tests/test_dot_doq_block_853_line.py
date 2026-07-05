"""Issues #813 + #849 — anchor ``_is_block_853_line`` on the pfB DoT-block descr prefix.

Pins the pure, off-VM predicate ``_is_block_853_line`` from
``tests/smoke/test_dot_doq_block.py`` across BOTH pf label renders:

- **#813 (ownership anchor).** Before #813 the matcher was
  ``"block" in line and ("853" in line or "domain-s" in line)`` — unanchored, so ANY
  block/reject rule mentioning port 853 (a foreign rule baked onto the smoke image,
  unrelated firewall policy, etc.) false-matched the positive gate
  (``_pfctl_sr_has_block_853``), and the ABSENT gate (``_pfctl_sr_block_853_absent``)
  could false-fail on a rule pfBlockerNG never created.
- **#849 (edition-portable anchor).** The #813 fix anchored on the composed CE label
  ``USER_RULE: pfB_DoT_Block_`` — but that is the **CE 2.8** render only. Plus 26.03
  renders split labels with no ``USER_RULE:`` prefix —
  ``label "id=<N>" label "tags=user_rule" label "descr=<descr>"`` (live Plus leg of run
  28733176915: all four loaded rules missed, every dot_doq live-pf gate failed). The one
  token present in both renders is the descr itself, so the matcher anchors on the bare
  ``pfB_DoT_Block_`` prefix.

Render evidence: CE 2.8 prints ``label "USER_RULE: <descr>"`` in PLAIN ``pfctl -sr``
output — no ``-v`` needed, pf labels are rule TEXT emitted by ``print_rule()`` regardless
of verbosity (live CE smoke-diagnostics guest, run 28704593724). Plus 26.03 prints the
split-label form above (live Plus leg, run 28733176915).

Importing ``tests.smoke.test_dot_doq_block`` here is import-safe off-VM — established
pattern: ``tests/test_bench_pfctl_parse.py`` pulls pure functions out of
``tests/smoke/`` the same way.
"""

from __future__ import annotations

from tests.smoke.test_dot_doq_block import _is_block_853_line


def _rendered_line_ce(*, action: str, port_token: str, label: str | None) -> str:
    """Build a realistic **CE 2.8** ``pfctl -sr`` line.

    Mirrors the evidence from a live CE 2.8 guest (run 28704593724): plain ``pfctl -sr``
    prints ``label "USER_RULE: <descr>"`` (plus an internal ``id:N`` label) for every
    config filter/rule row that carries a ``descr``.
    """
    label_clause = f' label "USER_RULE: {label}"' if label is not None else ""
    return (
        f"{action} out on em0 inet46 proto tcp from any to ! (self) "
        f"port = {port_token} flags S/SA keep state{label_clause} "
        'label "id:1782416890" ridentifier 1782416890'
    )


def _rendered_line_plus(*, action: str, port_token: str, descr: str | None) -> str:
    """Build a realistic **Plus 26.03** ``pfctl -sr`` line.

    Mirrors the evidence from the live Plus leg of run 28733176915: Plus renders split
    labels — ``label "id=<N>" label "tags=user_rule" label "descr=<descr>"`` — with no
    ``USER_RULE:`` prefix anywhere on the line.
    """
    descr_clause = f' label "descr={descr}"' if descr is not None else ""
    return (
        f"{action} in quick on vtnet2 inet proto tcp from any to ! (self) "
        f'port = {port_token} label "id=1760001634" label "tags=user_rule"{descr_clause} '
        "ridentifier 1760001634"
    )


def test_pfb_owned_reject_default_ce_rendering_matches() -> None:
    """(a) The genuine pfB DoT-block CE-rendered line (Reject default, domain-s) matches.

    Given the reject-default rule's pfctl -sr line (pfSense renders 'reject' as
      'block return' — PR #562) carrying the CE label "USER_RULE: pfB_DoT_Block_wan",
    Then _is_block_853_line returns True.
    """
    line = _rendered_line_ce(action="block return", port_token="domain-s", label="pfB_DoT_Block_wan")
    assert _is_block_853_line(line), f"expected a match for the genuine pfB CE-rendered line, got False:\n  {line!r}"


def test_pfb_owned_plus_split_label_rendering_matches() -> None:
    """(a') The genuine pfB DoT-block PLUS-rendered line (split labels) matches (#849).

    Given the same rule as rendered by Plus 26.03 — split labels, the descr carried as
      label "descr=pfB_DoT_Block_lan", no USER_RULE: prefix anywhere,
    Then _is_block_853_line returns True.

    RED on the #813 matcher (anchored on the composed CE label "USER_RULE: pfB_DoT_Block_"):
    that anchor never appears in the Plus render, so every loaded rule read as absent —
    the exact live failure of run 28733176915 (all five dot_doq live-pf gates, Plus leg).
    """
    line = _rendered_line_plus(action="block return", port_token="domain-s", descr="pfB_DoT_Block_lan")
    assert _is_block_853_line(line), f"expected a match for the genuine pfB Plus-rendered line, got False:\n  {line!r}"


def test_foreign_853_block_ce_line_without_pfb_descr_does_not_match() -> None:
    """(b) A foreign CE-rendered block rule on port 853 with NO pfB descr must NOT match (#813).

    Given a baked harness-style block rule that also targets port 853 (some other
      firewall policy on the smoke image, unrelated to pfBlockerNG),
    Then _is_block_853_line returns False — the descr-prefix anchor rejects it.

    RED on the pre-#813 matcher (``"block" in line and ("853" in line or "domain-s" in
    line)``, no ownership check): that older matcher returns True here, false-matching the
    positive gate and making the ABSENT gate false-fail on a rule pfBlockerNG never
    created.
    """
    line = _rendered_line_ce(action="block drop", port_token="853", label="Deny inbound DoT probe")
    assert not _is_block_853_line(line), (
        f"expected NO match for a foreign (non-pfB) port-853 CE block line, got True:\n  {line!r}"
    )


def test_foreign_853_block_plus_line_without_pfb_descr_does_not_match() -> None:
    """(b') A foreign PLUS-rendered block rule on port 853 with NO pfB descr must NOT match.

    Given a Plus split-label block rule targeting port 853 whose descr is not
      pfBlockerNG's (label "descr=Deny inbound DoT probe"),
    Then _is_block_853_line returns False — ownership still filters on the Plus render;
      the bare "tags=user_rule" label alone never qualifies a line.
    """
    line = _rendered_line_plus(action="block drop", port_token="853", descr="Deny inbound DoT probe")
    assert not _is_block_853_line(line), (
        f"expected NO match for a foreign (non-pfB) port-853 Plus block line, got True:\n  {line!r}"
    )


def test_pfb_labeled_non_853_line_does_not_match() -> None:
    """(c) A pfB-labeled block rule that is NOT about port 853 must not match.

    Given a pfctl -sr line carrying the pfB_DoT_Block_ descr but a different port,
    Then _is_block_853_line returns False — the descr alone is not sufficient without
      the 853/domain-s port token.
    """
    line = _rendered_line_ce(action="block return", port_token="http", label="pfB_DoT_Block_wan")
    assert not _is_block_853_line(line), f"expected NO match (wrong port), got True:\n  {line!r}"


def test_block_action_rendering_also_matches() -> None:
    """(d) The explicit Block-action rendering ('block drop') matches too.

    Given the rule Action selector set to 'block' instead of the Reject default,
    Then pfSense renders 'block drop' (not 'block return') and _is_block_853_line
      still returns True — the matcher checks for the substring 'block', covering both
      dispositions.
    """
    line = _rendered_line_ce(action="block drop", port_token="domain-s", label="pfB_DoT_Block_wan")
    assert _is_block_853_line(line), f"expected a match for the Block-action rendering, got False:\n  {line!r}"


def test_floating_variant_descr_still_matches() -> None:
    """The floating opt-in variant (descr pfB_DoT_Block_Floating) still matches.

    Given the floating rule's rendered line — same descr PREFIX, different suffix,
    Then _is_block_853_line returns True: the anchor matches the descr PREFIX, not the
      full per-interface descr, so the floating variant is covered too.
    """
    line = _rendered_line_ce(action="block return", port_token="domain-s", label="pfB_DoT_Block_Floating")
    assert _is_block_853_line(line), f"expected a match for the floating pfB rendered line, got False:\n  {line!r}"
