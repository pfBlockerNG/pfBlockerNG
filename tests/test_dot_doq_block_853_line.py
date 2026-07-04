"""Issue #813 — anchor ``_is_block_853_line`` on the rendered pfB DoT-block label.

Pins the pure, off-VM predicate ``_is_block_853_line`` from
``tests/smoke/test_dot_doq_block.py``: before the fix it was
``"block" in line and ("853" in line or "domain-s" in line)`` — unanchored, so ANY
block/reject rule mentioning port 853 (a foreign rule baked onto the smoke image,
unrelated firewall policy, etc.) false-matched the positive gate
(``_pfctl_sr_has_block_853``), and the ABSENT gate (``_pfctl_sr_block_853_absent``)
could false-fail on a rule pfBlockerNG never created.

Real pfSense renders every config ``filter/rule`` row that carries a ``descr`` as
``label "USER_RULE: <descr>"`` in PLAIN ``pfctl -sr`` output — no ``-v`` needed, pf
labels are rule TEXT emitted by ``print_rule()`` regardless of verbosity (confirmed on
a live CE 2.8 smoke-diagnostics guest, run 28704593724). pfBlockerNG's DoT/DoQ block
rows carry descr ``pfB_DoT_Block_<iface>`` (or the floating variant
``pfB_DoT_Block_Floating``) — anchoring on that rendered label PREFIX lets the matcher
tell a pfB-owned 853 block from any other.

Importing ``tests.smoke.test_dot_doq_block`` here is import-safe off-VM — established
pattern: ``tests/test_bench_pfctl_parse.py`` pulls pure functions out of
``tests/smoke/`` the same way.
"""

from __future__ import annotations

from tests.smoke.test_dot_doq_block import _is_block_853_line


def _rendered_line(*, action: str, port_token: str, label: str | None) -> str:
    """Build a realistic ``pfctl -sr`` line in the shape pfSense actually renders.

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


def test_pfb_owned_reject_default_rendering_matches() -> None:
    """(a) The genuine pfB DoT-block rendered line (Reject default, domain-s) matches.

    Given the reject-default rule's pfctl -sr line (pfSense renders 'reject' as
      'block return' — PR #562) carrying the pfB_DoT_Block_wan label,
    Then _is_block_853_line returns True.
    """
    line = _rendered_line(action="block return", port_token="domain-s", label="pfB_DoT_Block_wan")
    assert _is_block_853_line(line), f"expected a match for the genuine pfB rendered line, got False:\n  {line!r}"


def test_foreign_853_block_line_without_pfb_label_does_not_match() -> None:
    """(b) A foreign block rule on port 853 with NO pfB label must NOT match (#813).

    Given a baked harness-style block rule that also targets port 853 (some other
      firewall policy on the smoke image, unrelated to pfBlockerNG),
    Then _is_block_853_line returns False — the label anchor rejects it.

    RED on the pre-#813 matcher (``"block" in line and ("853" in line or "domain-s" in
    line)``, no label check): that older matcher returns True here, false-matching the
    positive gate and making the ABSENT gate false-fail on a rule pfBlockerNG never
    created.
    """
    line = _rendered_line(action="block drop", port_token="853", label="Deny inbound DoT probe")
    assert not _is_block_853_line(line), (
        f"expected NO match for a foreign (non-pfB) port-853 block line, got True:\n  {line!r}"
    )


def test_pfb_labeled_non_853_line_does_not_match() -> None:
    """(c) A pfB-labeled block rule that is NOT about port 853 must not match.

    Given a pfctl -sr line carrying the pfB_DoT_Block_ label but a different port,
    Then _is_block_853_line returns False — the label alone is not sufficient without
      the 853/domain-s port token.
    """
    line = _rendered_line(action="block return", port_token="http", label="pfB_DoT_Block_wan")
    assert not _is_block_853_line(line), f"expected NO match (wrong port), got True:\n  {line!r}"


def test_block_action_rendering_also_matches() -> None:
    """(d) The explicit Block-action rendering ('block drop') matches too.

    Given the rule Action selector set to 'block' instead of the Reject default,
    Then pfSense renders 'block drop' (not 'block return') and _is_block_853_line
      still returns True — the matcher checks for the substring 'block', covering both
      dispositions.
    """
    line = _rendered_line(action="block drop", port_token="domain-s", label="pfB_DoT_Block_wan")
    assert _is_block_853_line(line), f"expected a match for the Block-action rendering, got False:\n  {line!r}"


def test_floating_variant_label_still_matches() -> None:
    """The floating opt-in variant (descr pfB_DoT_Block_Floating) still matches.

    Given the floating rule's rendered line — same label PREFIX, different suffix,
    Then _is_block_853_line returns True: the anchor matches the label PREFIX, not the
      full per-interface descr, so the floating variant is covered too.
    """
    line = _rendered_line(action="block return", port_token="domain-s", label="pfB_DoT_Block_Floating")
    assert _is_block_853_line(line), f"expected a match for the floating pfB rendered line, got False:\n  {line!r}"
