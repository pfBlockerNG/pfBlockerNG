"""ADR-24 — Spring-Boot-Actuator-style sensitive-TAG redaction of the smoke
config.xml scrub.

These pin the PURE, off-VM seam shared by the in-guest config.xml scrub
(``collect_host_diagnostics`` appends ``sensitive_tag_sed_program()`` to the
credential ``sed``): scrub the inner text of any config.xml element whose TAG NAME
looks sensitive (Spring Boot Actuator default keys-to-sanitize:
password / secret / key / token / *credential* / …), auto-catching unknown
token/secret-named tags by name without enumerating them. The live box's
``<ipsecpsk>`` is the motivating catch.

(Value-based NDI/serial redaction was dropped: the Netgate Device ID is a
non-reversible hash of the already-public MAC, so scrubbing it while the MAC ships
in the repo is not meaningful.)

They live under ``tests/`` (NOT ``tests/smoke/``) so they run in the default suite
without a VM. The behaviour is non-trivial (per-word-class branches, plurals,
prefix/text near-misses, cross-language Python-vs-`sed` parity) -> BDD-style
Given/When/Then specs below. Branch coverage requires BOTH a positive (sensitive
tag scrubbed) for each word class AND the load-bearing negative (a non-sensitive
tag left intact).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from tests.smoke.helpers import (
    REDACTED,
    redact_sensitive_xml_tags,
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
