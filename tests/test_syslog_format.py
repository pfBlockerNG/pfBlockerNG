"""ADR-38 Phase 1 — Pure DNSBL syslog event formatter.

Pins the behaviour of:
    syslog_format_dnsbl(q_name, q_ip, q_type, group, feed, b_type, b_eval) -> str

The function is PURE (no I/O, no globals, stdlib-only) and DORMANT this phase
(uncalled from production code).  These tests are the only callers.

Coverage mandate (CLAUDE.md):
  - DNSBL VIP block type vs NULL block type.
  - CNAME q_type (non-A/AAAA).
  - Empty group and/or feed omitted from output.
  - Value containing space, '=', or '"' is double-quoted.
  - Newline in value is stripped (single-line guarantee).
  - Fixed key order: act qname qip qtype [group] [feed] btype eval.
  - Exact golden strings for every case.
"""

from __future__ import annotations

from pfb_unbound import syslog_format_dnsbl

# ---------------------------------------------------------------------------
# DNSBL VIP block — all fields populated
# ---------------------------------------------------------------------------


def test_dnsbl_vip_block_all_fields_exact_string() -> None:
    """VIP block with group and feed present produces the exact golden string.

    Scenario:
      Given q_name='malware.example.com', q_ip='192.168.1.5', q_type='A',
            group='EasyList', feed='EasyList_Adult', b_type='VIP',
            b_eval='malware.example.com'.
      When  syslog_format_dnsbl(...).
      Then  returns the exact key=value string with act=dnsbl and all fields.
    """
    result = syslog_format_dnsbl(
        q_name="malware.example.com",
        q_ip="192.168.1.5",
        q_type="A",
        group="EasyList",
        feed="EasyList_Adult",
        b_type="VIP",
        b_eval="malware.example.com",
    )
    assert result == (
        "act=dnsbl qname=malware.example.com qip=192.168.1.5 qtype=A "
        "group=EasyList feed=EasyList_Adult btype=VIP eval=malware.example.com"
    ), "VIP block: all fields in documented order"


# ---------------------------------------------------------------------------
# DNSBL NULL block — all fields populated
# ---------------------------------------------------------------------------


def test_dnsbl_null_block_all_fields_exact_string() -> None:
    """NULL block with all fields present: btype=NULL.

    Scenario:
      Given b_type='NULL', q_type='AAAA', all other fields non-empty.
      When  syslog_format_dnsbl(...).
      Then  returns exact string with btype=NULL.
    """
    result = syslog_format_dnsbl(
        q_name="tracking.example.net",
        q_ip="10.0.0.1",
        q_type="AAAA",
        group="BlockGroup",
        feed="TrackingFeed",
        b_type="NULL",
        b_eval="tracking.example.net",
    )
    assert result == (
        "act=dnsbl qname=tracking.example.net qip=10.0.0.1 qtype=AAAA "
        "group=BlockGroup feed=TrackingFeed btype=NULL eval=tracking.example.net"
    ), "NULL block: all fields"


# ---------------------------------------------------------------------------
# VIP vs NULL are different outputs (before-and-after)
# ---------------------------------------------------------------------------


def test_dnsbl_vip_vs_null_differ() -> None:
    """VIP and NULL b_type produce different btype= values — before/after.

    Scenario:
      Given identical inputs except b_type.
      Before: b_type='VIP'  -> btype=VIP in output.
      After:  b_type='NULL' -> btype=NULL in output.
      Then    the two outputs differ exactly at the btype field.
    """
    vip = syslog_format_dnsbl("ex.com", "1.2.3.4", "A", "G", "F", "VIP", "ex.com")
    null_ = syslog_format_dnsbl("ex.com", "1.2.3.4", "A", "G", "F", "NULL", "ex.com")

    # Before: VIP -> btype=VIP.
    assert "btype=VIP" in vip, "VIP: btype=VIP must appear"
    assert "btype=NULL" not in vip, "VIP: btype=NULL must NOT appear"

    # After: NULL -> btype=NULL.
    assert "btype=NULL" in null_, "NULL: btype=NULL must appear"
    assert "btype=VIP" not in null_, "NULL: btype=VIP must NOT appear"


# ---------------------------------------------------------------------------
# CNAME q_type
# ---------------------------------------------------------------------------


def test_dnsbl_cname_qtype_exact_string() -> None:
    """CNAME q_type appears verbatim in the output.

    Scenario:
      Given q_type='CNAME'.
      When  syslog_format_dnsbl(...).
      Then  qtype=CNAME appears in output at the correct position.
    """
    result = syslog_format_dnsbl(
        q_name="cdn.malware.example.com",
        q_ip="172.16.0.1",
        q_type="CNAME",
        group="CDNBlock",
        feed="MalwareFeed",
        b_type="TLD",
        b_eval="malware.example.com",
    )
    assert result == (
        "act=dnsbl qname=cdn.malware.example.com qip=172.16.0.1 qtype=CNAME "
        "group=CDNBlock feed=MalwareFeed btype=TLD eval=malware.example.com"
    ), "CNAME q_type: exact string"


# ---------------------------------------------------------------------------
# Empty group — omitted from output
# ---------------------------------------------------------------------------


def test_dnsbl_empty_group_omitted() -> None:
    """Empty group is omitted; non-empty group is included — before/after.

    Scenario:
      Before: group='' -> 'group=' absent from output.
      After:  group='RealGroup' -> 'group=RealGroup' present in output.
    """
    # Before: empty group -> absent.
    before = syslog_format_dnsbl("a.com", "1.1.1.1", "A", "", "SomeFeed", "VIP", "a.com")
    assert "group=" not in before, "empty group must be omitted"

    # After: real group -> present.
    after = syslog_format_dnsbl("a.com", "1.1.1.1", "A", "RealGroup", "SomeFeed", "VIP", "a.com")
    assert "group=RealGroup" in after, "non-empty group must appear"


def test_dnsbl_empty_group_exact_string() -> None:
    """Empty group omitted: exact golden string without group key.

    Scenario:
      Given group='', feed='SomeFeed'.
      When  syslog_format_dnsbl(...).
      Then  output skips group= and goes straight to feed= after qtype=.
    """
    result = syslog_format_dnsbl(
        q_name="b.com",
        q_ip="2.2.2.2",
        q_type="A",
        group="",
        feed="SomeFeed",
        b_type="DNSBL",
        b_eval="b.com",
    )
    assert result == ("act=dnsbl qname=b.com qip=2.2.2.2 qtype=A feed=SomeFeed btype=DNSBL eval=b.com"), (
        "empty group: exact string without group key"
    )


# ---------------------------------------------------------------------------
# Empty feed — omitted from output
# ---------------------------------------------------------------------------


def test_dnsbl_empty_feed_omitted() -> None:
    """Empty feed is omitted; non-empty feed is included — before/after.

    Scenario:
      Before: feed='' -> 'feed=' absent from output.
      After:  feed='RealFeed' -> 'feed=RealFeed' present.
    """
    # Before: empty feed -> absent.
    before = syslog_format_dnsbl("c.com", "3.3.3.3", "A", "Grp", "", "VIP", "c.com")
    assert "feed=" not in before, "empty feed must be omitted"

    # After: real feed -> present.
    after = syslog_format_dnsbl("c.com", "3.3.3.3", "A", "Grp", "RealFeed", "VIP", "c.com")
    assert "feed=RealFeed" in after, "non-empty feed must appear"


def test_dnsbl_empty_group_and_feed_exact_string() -> None:
    """Both group and feed empty: exact string with just required fields.

    Scenario:
      Given group='', feed=''.
      When  syslog_format_dnsbl(...).
      Then  output has act qname qip qtype btype eval only.
    """
    result = syslog_format_dnsbl(
        q_name="d.com",
        q_ip="4.4.4.4",
        q_type="AAAA",
        group="",
        feed="",
        b_type="Python",
        b_eval="d.com",
    )
    assert result == ("act=dnsbl qname=d.com qip=4.4.4.4 qtype=AAAA btype=Python eval=d.com"), (
        "both group and feed empty: exact minimal string"
    )


# ---------------------------------------------------------------------------
# Escaping — space, '=', '"' in values
# ---------------------------------------------------------------------------


def test_dnsbl_value_with_space_is_quoted() -> None:
    """A value containing a space is double-quoted.

    Scenario:
      Given b_eval = 'TLD match.example.com' (contains space).
      When  syslog_format_dnsbl(...).
      Then  eval="TLD match.example.com" appears quoted in output.
    """
    result = syslog_format_dnsbl(
        q_name="e.com",
        q_ip="5.5.5.5",
        q_type="A",
        group="G",
        feed="F",
        b_type="TLD",
        b_eval="TLD match.example.com",
    )
    assert 'eval="TLD match.example.com"' in result, "b_eval with space must be quoted"


def test_dnsbl_value_with_equals_is_quoted() -> None:
    """A value containing '=' is double-quoted.

    Scenario:
      Given q_name = 'host=bad.example.com' (contains '=').
      When  syslog_format_dnsbl(...).
      Then  qname="host=bad.example.com" appears quoted.
    """
    result = syslog_format_dnsbl(
        q_name="host=bad.example.com",
        q_ip="6.6.6.6",
        q_type="A",
        group="G",
        feed="F",
        b_type="DNSBL",
        b_eval="host=bad.example.com",
    )
    assert 'qname="host=bad.example.com"' in result, "qname with = must be quoted"


def test_dnsbl_value_with_double_quote_is_escaped() -> None:
    """A value containing '"' is double-quoted with inner quote escaped.

    Scenario:
      Given b_eval = 'bad"eval' (contains '"').
      When  syslog_format_dnsbl(...).
      Then  eval="bad\\"eval" appears in output.
    """
    result = syslog_format_dnsbl(
        q_name="f.com",
        q_ip="7.7.7.7",
        q_type="A",
        group="G",
        feed="F",
        b_type="DNSBL",
        b_eval='bad"eval',
    )
    assert 'eval="bad\\"eval"' in result, 'inner " must be \\"-escaped'


def test_dnsbl_newline_in_value_is_stripped() -> None:
    """Newlines embedded in a value are replaced with a space (single-line output).

    Scenario:
      Given q_name = 'multi\\nline.com' (contains \\n).
      When  syslog_format_dnsbl(...).
      Then  the output contains no newline character.
      And   the embedded newline is replaced with a space.
    """
    result = syslog_format_dnsbl(
        q_name="multi\nline.com",
        q_ip="8.8.8.8",
        q_type="A",
        group="G",
        feed="F",
        b_type="VIP",
        b_eval="multi\nline.com",
    )
    assert "\n" not in result, "output must be single-line"
    assert 'qname="multi line.com"' in result, "newline replaced with space, then quoted"


# ---------------------------------------------------------------------------
# Fixed key order
# ---------------------------------------------------------------------------


def test_dnsbl_key_order_required_fields() -> None:
    """act qname qip qtype btype eval appear in the documented order.

    Scenario:
      Given all required fields and no optional fields.
      When  syslog_format_dnsbl(...).
      Then  keys appear in order: act < qname < qip < qtype < btype < eval.
    """
    result = syslog_format_dnsbl(
        q_name="order.example.com",
        q_ip="9.9.9.9",
        q_type="A",
        group="",
        feed="",
        b_type="VIP",
        b_eval="order.example.com",
    )
    pos_act = result.index("act=")
    pos_qname = result.index("qname=")
    pos_qip = result.index("qip=")
    pos_qtype = result.index("qtype=")
    pos_btype = result.index("btype=")
    pos_eval = result.index("eval=")

    assert pos_act < pos_qname, "act before qname"
    assert pos_qname < pos_qip, "qname before qip"
    assert pos_qip < pos_qtype, "qip before qtype"
    assert pos_qtype < pos_btype, "qtype before btype"
    assert pos_btype < pos_eval, "btype before eval"


def test_dnsbl_key_order_with_optional_fields() -> None:
    """group and feed appear between qtype and btype when present.

    Scenario:
      Given all fields including group and feed.
      When  syslog_format_dnsbl(...).
      Then  qtype < group < feed < btype < eval.
    """
    result = syslog_format_dnsbl(
        q_name="full.example.com",
        q_ip="10.10.10.10",
        q_type="A",
        group="MyGroup",
        feed="MyFeed",
        b_type="DNSBL",
        b_eval="full.example.com",
    )
    pos_qtype = result.index("qtype=")
    pos_group = result.index("group=")
    pos_feed = result.index("feed=")
    pos_btype = result.index("btype=")
    pos_eval = result.index("eval=")

    assert pos_qtype < pos_group, "qtype before group"
    assert pos_group < pos_feed, "group before feed"
    assert pos_feed < pos_btype, "feed before btype"
    assert pos_btype < pos_eval, "btype before eval"
