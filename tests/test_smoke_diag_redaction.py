"""ADR-24 — redaction of the smoke diagnostics: the Spring-Boot-Actuator-style
sensitive-TAG scrub of config.xml AND the value-based scrub of the pfSense Plus
secret VM identity.

These pin the PURE, off-VM seams shared by ``collect_host_diagnostics``:

* **Sensitive-TAG scrub** (``sensitive_tag_sed_program()`` appended to the
  credential ``sed``): scrub the inner text of any config.xml element whose TAG
  NAME looks sensitive (Spring Boot Actuator default keys-to-sanitize:
  password / secret / key / token / *credential* / …), auto-catching unknown
  token/secret-named tags by name without enumerating them. The live box's
  ``<ipsecpsk>`` is the motivating catch.
* **Value-based scrub** (``parse_redact_values`` / ``redact_values`` /
  ``_sed_escape_literal``): the Plus source-VM identity (MAC + SMBIOS uuid [+ NDI]
  + live serial) is a license/NDI-keyed SECRET supplied via SMOKE_REDACT_VALUES on
  the Plus leg only; the bundle is value-redacted before upload so a live Plus run
  cannot leak it. A CE leg sets no value -> the set is empty -> the redactor is a
  strict no-op (the CE artifact stays byte-identical). The Python redactor and the
  in-guest BSD-``sed`` program must agree, so a literal-escape parity test pins them.

They live under ``tests/`` (NOT ``tests/smoke/``) so they run in the default suite
without a VM. The behaviour is non-trivial (per-word-class branches, plurals,
prefix/text near-misses, cross-language Python-vs-`sed` parity, the empty CE no-op
vs the populated Plus path) -> BDD-style Given/When/Then specs below. Branch
coverage requires BOTH a positive (sensitive tag / secret value scrubbed) AND the
load-bearing negative (a non-sensitive tag / the empty no-op left intact).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from tests.smoke.helpers import (
    REDACTED,
    _sed_escape_literal,
    parse_redact_values,
    redact_sensitive_xml_tags,
    redact_values,
    sensitive_tag_sed_program,
)

# --------------------------------------------------------------------------- #
# redact_sensitive_xml_tags — Actuator-style sensitive-KEY (tag-name) redaction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("element", "expected"),
    [
        # One case per Actuator-inspired word class — each MUST be scrubbed.
        ("<password>hunter2</password>", f"<password>{REDACTED}</password>"),
        ("<passwd>hunter2</passwd>", f"<passwd>{REDACTED}</passwd>"),
        ("<secret>s3kr3t</secret>", f"<secret>{REDACTED}</secret>"),
        ("<api_token>abc123</api_token>", f"<api_token>{REDACTED}</api_token>"),
        ("<authkey>k</authkey>", f"<authkey>{REDACTED}</authkey>"),
        ("<wg_privatekey>Qk==</wg_privatekey>", f"<wg_privatekey>{REDACTED}</wg_privatekey>"),
        ("<passphrase>open</passphrase>", f"<passphrase>{REDACTED}</passphrase>"),
        ("<presharedkey>P</presharedkey>", f"<presharedkey>{REDACTED}</presharedkey>"),
        ("<psk>xyz</psk>", f"<psk>{REDACTED}</psk>"),
        ("<some_credential>c</some_credential>", f"<some_credential>{REDACTED}</some_credential>"),
        ("<apikey>AK</apikey>", f"<apikey>{REDACTED}</apikey>"),
        # The bare `key` suffix (deliberately broad, Actuator-style).
        ("<key>KK</key>", f"<key>{REDACTED}</key>"),
    ],
)
def test_redact_sensitive_xml_tags_scrubs_each_sensitive_word_class(element: str, expected: str) -> None:
    """Given a config.xml element whose tag name ends in a sensitive Actuator word
    When redact_sensitive_xml_tags runs
    Then the inner text is replaced with REDACTED and the opening tag is preserved
         verbatim — proving each word class is a real, covered branch.
    """
    assert redact_sensitive_xml_tags(element) == expected


def test_redact_sensitive_xml_tags_scrubs_plural_tag() -> None:
    """Given a sensitive tag in its plural form (`<tokens>`)
    When redact_sensitive_xml_tags runs
    Then it is scrubbed too — the optional trailing `s` is matched.
    """
    assert redact_sensitive_xml_tags("<tokens>a b c</tokens>") == f"<tokens>{REDACTED}</tokens>"


@pytest.mark.parametrize(
    "element",
    [
        "<hostname>fw1</hostname>",
        "<descr>my token list</descr>",  # 'token' in TEXT, not the tag name -> untouched
        "<ipaddr>192.0.2.1</ipaddr>",
        "<keyword>geo</keyword>",  # 'key' is a PREFIX here, not the suffix -> untouched
        "<version>2.8.0</version>",
    ],
)
def test_redact_sensitive_xml_tags_leaves_non_sensitive_tags_intact(element: str) -> None:
    """LOAD-BEARING NEGATIVE: a non-sensitive tag must be left byte-for-byte intact.

    Given an element whose tag name does NOT end in a sensitive word (incl. a tag
          where a sensitive word appears only as a prefix or in the text)
    When redact_sensitive_xml_tags runs
    Then the element is unchanged — this is what fails if the pattern over-matches.
    """
    assert redact_sensitive_xml_tags(element) == element


def test_redact_sensitive_xml_tags_does_not_touch_closing_tags_or_structure() -> None:
    """Given a multiline config.xml fragment with sensitive AND non-sensitive
          elements, nesting, and closing tags
    When redact_sensitive_xml_tags runs
    Then only the inner text of sensitive OPENING tags is scrubbed; closing tags,
         nesting, and non-sensitive content are preserved (structure not corrupted).
    """
    fragment = (
        "<system>\n"
        "  <hostname>fw1</hostname>\n"
        "  <secret>topsecret</secret>\n"
        "  <user>\n"
        "    <name>admin</name>\n"
        "    <api_token>abc.def</api_token>\n"
        "  </user>\n"
        "</system>\n"
    )
    expected = (
        "<system>\n"
        "  <hostname>fw1</hostname>\n"
        f"  <secret>{REDACTED}</secret>\n"
        "  <user>\n"
        "    <name>admin</name>\n"
        f"    <api_token>{REDACTED}</api_token>\n"
        "  </user>\n"
        "</system>\n"
    )
    assert redact_sensitive_xml_tags(fragment) == expected


def test_redact_sensitive_xml_tags_empty_element_is_safe() -> None:
    """Given an empty sensitive element (`<token></token>`)
    When redact_sensitive_xml_tags runs
    Then it does not crash and does not corrupt the element structure: the opening
         and closing tags are preserved (the harmless REDACTED placeholder inserted
         into the empty body is acceptable over-redaction — never under-redaction).
    """
    out = redact_sensitive_xml_tags("<token></token>")
    assert out == f"<token>{REDACTED}</token>"
    # Structure intact: opening + closing tags survive verbatim.
    assert out.startswith("<token>")
    assert out.endswith("</token>")


@pytest.mark.skipif(shutil.which("sed") is None, reason="sed not available")
def test_sensitive_tag_sed_program_agrees_with_python() -> None:
    """Scenario: the in-guest BSD-`sed` sensitive-tag scrub == the Python redactor.

    Given the sed PROGRAM from sensitive_tag_sed_program() (the exact program the
          in-guest config.xml scrub appends) and a sample XML exercising every word
          class, plurals, nesting, closing tags, an empty element, and non-sensitive
          tags (incl. prefix/text near-misses)
    When that program is run via `sed -E` over the sample
    Then the output equals redact_sensitive_xml_tags(sample) — the anti-coverage-
         theater gate: it FAILS if the shell and Python patterns drift.
    """
    sample = (
        "<system>\n"
        "  <hostname>fw1</hostname>\n"
        "  <descr>contains token word in text</descr>\n"
        "  <keyword>prefix-not-suffix</keyword>\n"
        "  <password>hunter2</password>\n"
        "  <secret>s3kr3t</secret>\n"
        "  <api_token>abc.def</api_token>\n"
        "  <tokens>a b c</tokens>\n"
        "  <wg_privatekey>Qk==</wg_privatekey>\n"
        "  <psk>p</psk>\n"
        "  <some_credential>c</some_credential>\n"
        "  <key>KK</key>\n"
        "  <token></token>\n"
        "</system>\n"
    )

    # Pre-state — the fixture starts UNREDACTED: raw secrets present, no REDACTED yet,
    # so a green result proves the scrub CAUSED their removal (not that they were absent).
    assert "hunter2" in sample and "s3kr3t" in sample and "abc.def" in sample
    assert REDACTED not in sample

    result = subprocess.run(
        ["sed", "-E", sensitive_tag_sed_program()],
        input=sample,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout == redact_sensitive_xml_tags(sample)
    # Post-state — raw secrets gone, placeholder present, a non-sensitive tag untouched.
    assert "hunter2" not in result.stdout
    assert "abc.def" not in result.stdout
    assert REDACTED in result.stdout
    assert "<hostname>fw1</hostname>" in result.stdout


# --------------------------------------------------------------------------- #
# redact_values — literal value redaction of the Plus secret identity
# --------------------------------------------------------------------------- #
# Documentation/test-only fake values — NEVER a real Plus MAC/uuid (those are the
# SMOKE_PLUS_* secrets and must not appear in the repo, ADR-24).
_FAKE_MAC = "02:00:00:00:00:01"
_FAKE_UUID = "00000000-0000-0000-0000-000000000000"


def test_redact_values_empty_set_is_identity_ce_no_op() -> None:
    """LOAD-BEARING CE NO-OP: an empty value set leaves the text byte-identical.

    Given the diagnostics text and an EMPTY redaction set (the CE leg — no
          SMOKE_REDACT_VALUES secret)
    When redact_values runs
    Then the text is returned unchanged — this is what guarantees the CE artifact
         is byte-identical to pre-ADR-24 (it fails if redaction ever fires on CE).
    """
    text = f"link#1: {_FAKE_MAC}\nsmbios uuid {_FAKE_UUID}\n"
    assert redact_values(text, []) == text


def test_redact_values_present_value_is_replaced() -> None:
    """Given text containing a secret value and a redaction set containing it
    When redact_values runs
    Then every occurrence of the value is replaced with REDACTED and the value is gone.

    Pre-state asserted first (value present, REDACTED absent) so green proves the
    redaction CAUSED the removal, not that the value was never there.
    """
    text = f"nic0 ether {_FAKE_MAC} (active); peer {_FAKE_MAC}"
    assert _FAKE_MAC in text and REDACTED not in text
    out = redact_values(text, [_FAKE_MAC])
    assert _FAKE_MAC not in out
    assert out.count(REDACTED) == 2  # both occurrences scrubbed
    assert out == f"nic0 ether {REDACTED} (active); peer {REDACTED}"


def test_redact_values_is_case_insensitive() -> None:
    """LOAD-BEARING: a secret stored UPPER-case must scrub its lower-case rendering.

    Given an upper-case MAC in the redaction set but the lower-case form in the text
         (ifconfig/dmesg/logs emit lower-case)
    When redact_values runs
    Then the lower-case rendering is gone — without this, an upper-case secret would
         leak through. Mirrors the `s###REDACTED###gI` sed flag the shell paths use.
    """
    upper = "02:AB:CD:EF:12:34"  # fake doc MAC; letters differ by case
    text = f"nic0 ether {upper.lower()} (active)"
    assert upper not in text and upper.lower() in text and REDACTED not in text
    out = redact_values(text, [upper])
    assert upper.lower() not in out
    assert out == f"nic0 ether {REDACTED} (active)"


@pytest.mark.skipif(shutil.which("sed") is None, reason="sed not on PATH")
def test_value_sed_program_gI_flag_is_case_insensitive() -> None:
    """The in-guest `s###REDACTED###gI` program scrubs a case-mismatched value.

    Given the sed program built from an upper-case secret (as the in-guest scrub
         emits it, with the `I` flag) and a sample carrying the lower-case rendering
    When run through `sed`
    Then the value is scrubbed — proving the `I` (case-insensitive) flag the harness
         relies on actually works on the available sed (GNU here; FreeBSD in-guest).
    """
    upper = "02:AB:CD:EF:12:34"
    sample = f"ether {upper.lower()}"
    sed_prog = f"s#{_sed_escape_literal(upper)}#{REDACTED}#gI;"
    out = subprocess.run(["sed", sed_prog], input=sample, capture_output=True, text=True, check=True).stdout
    assert upper.lower() not in out
    assert out == f"ether {REDACTED}"


def test_redact_values_regex_special_value_matched_literally() -> None:
    """Given a value packed with regex/BRE metacharacters (`. * [ ] ^ $ #` + `\\`)
    When redact_values runs
    Then it is matched LITERALLY (not as a regex) and replaced, while a string that
         the metachars WOULD match as a regex is left untouched — proving literal,
         not pattern, matching.
    """
    needle = r"a.b*c[d]e^f$g#h\i"
    text = f"value={needle}; decoy=aXbYYcde_f_g_h_i"
    assert needle in text and REDACTED not in text
    out = redact_values(text, [needle])
    assert needle not in out
    assert out == f"value={REDACTED}; decoy=aXbYYcde_f_g_h_i"  # decoy survives (literal match)


def test_redact_values_ignores_blank_needles() -> None:
    """Given a redaction set with empty/whitespace-only entries among real ones
    When redact_values runs
    Then the blanks are ignored (an empty needle would otherwise match everywhere)
         and only the real value is scrubbed.
    """
    text = f"mac {_FAKE_MAC} end"
    out = redact_values(text, ["", "   ", _FAKE_MAC])
    assert out == f"mac {REDACTED} end"


# --------------------------------------------------------------------------- #
# parse_redact_values — newline/comma split, trim, placeholder drop, dedup
# --------------------------------------------------------------------------- #


def test_parse_redact_values_none_and_empty_yield_empty_list() -> None:
    """Given a None or empty SMOKE_REDACT_VALUES (the CE leg)
    When parse_redact_values runs
    Then the result is [] — the empty set that makes redact_values a no-op.
    """
    assert parse_redact_values(None) == []
    assert parse_redact_values("") == []
    assert parse_redact_values("\n  \n") == []


def test_parse_redact_values_splits_newline_and_comma_and_trims() -> None:
    """Given a mixed newline- and comma-separated raw value with surrounding space
    When parse_redact_values runs
    Then each token is split and trimmed, preserving order.
    """
    raw = f"  {_FAKE_MAC} \n{_FAKE_UUID},deadbeef  "
    assert parse_redact_values(raw) == [_FAKE_MAC, _FAKE_UUID, "deadbeef"]


def test_parse_redact_values_drops_generic_smbios_placeholders() -> None:
    """Given raw values that include generic SMBIOS placeholders (case-insensitive)
    When parse_redact_values runs
    Then the placeholders are dropped (they are not secrets and redacting them would
         mangle unrelated diagnostics), keeping only the real value.
    """
    raw = f"Not Specified\nTo Be Filled By O.E.M.\n0\nNONE\nDefault String\n{_FAKE_MAC}"
    assert parse_redact_values(raw) == [_FAKE_MAC]


def test_parse_redact_values_dedups_preserving_first_occurrence() -> None:
    """Given a raw value with a duplicate token
    When parse_redact_values runs
    Then duplicates collapse to a single entry (first occurrence order kept).
    """
    raw = f"{_FAKE_MAC}\n{_FAKE_UUID}\n{_FAKE_MAC}"
    assert parse_redact_values(raw) == [_FAKE_MAC, _FAKE_UUID]


# --------------------------------------------------------------------------- #
# Python ⇄ BSD-sed parity for the VALUE redactor (anti-coverage-theater gate)
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(shutil.which("sed") is None, reason="sed not available")
def test_value_redactor_python_matches_sed() -> None:
    """Scenario: the in-guest BSD-`sed` value scrub == the Python redact_values.

    Given a set of secret-shaped values (incl. one packed with BRE metacharacters)
          and a sample of diagnostics text containing each
    When the values are escaped via _sed_escape_literal into a `s#…#REDACTED#g`
         program and run through `sed`, AND redact_values runs over the same text
    Then the two outputs are identical — the gate that FAILS if the shell and Python
         value redactors drift (e.g. a metachar escaped on one side only).
    """
    values = [_FAKE_MAC, _FAKE_UUID, r"x.y*z[q]^w$v#u\t"]
    sample = f"ether {_FAKE_MAC}\nsmbios.system.uuid: {_FAKE_UUID}\nweird={values[2]}\nuntouched: plain text line\n"
    # Pre-state — the secrets are present and unredacted, so a green result proves
    # the scrub CAUSED their removal.
    for v in values:
        assert v in sample
    assert REDACTED not in sample

    sed_prog = "".join(f"s#{_sed_escape_literal(v)}#{REDACTED}#g;" for v in values)
    result = subprocess.run(
        ["sed", sed_prog],
        input=sample,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout == redact_values(sample, values)
    # Post-state — every secret gone, the non-secret line intact.
    for v in values:
        assert v not in result.stdout
    assert "untouched: plain text line" in result.stdout
