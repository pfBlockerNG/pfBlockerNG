<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_filter_whitelist_atype() — validates the Reports-tab whitelist composite
 * parameter 'Whitelist|<ip>|<description>' field-by-field (IP via PFB_FILTER_IP,
 * description via PFB_FILTER_HTML) and returns the sanitised composite.
 *
 * Bug pinned (issue #353): the old gate ran the entire composite through
 * PFB_FILTER_ATYPE whose regex /^[a-zA-Z0-9\.|_]+$/ rejects spaces and most
 * special characters, so any description containing a space caused the filter to
 * return '' → the prefill block was skipped → the page rendered blank.
 *
 * Fix: the helper splits on '|' (limit 3) and filters each field separately,
 * so spaces and HTML-special characters in the description are preserved (escaped).
 *
 * Branches covered:
 *   1. Space in description — passes through (the bug case).
 *   2. No-space description — passes through unchanged.
 *   3. HTML-special chars in description — escaped exactly once.
 *   4. Invalid IP — IP slot is emptied; description is still passed.
 *   5. Missing description — third slot defaults to empty string.
 *   6. Old gate proof — PFB_FILTER_ATYPE returns '' for a spaced description.
 */
#[CoversFunction('pfb_filter_whitelist_atype')]
final class PfbFilterWhitelistAtypeTest extends TestCase
{
	/**
	 * Pins the bug: a description WITH a space must survive the helper.
	 *
	 * Scenario: Reports-tab whitelist wizard with a multi-word description.
	 *
	 * Given: the composite 'Whitelist|89.248.168.42|chickens are here'.
	 * When:  the OLD gate (PFB_FILTER_ATYPE) processes it.
	 * Then:  the result is '' (empty) — the gate rejects the space.
	 *
	 * Given: the same composite.
	 * When:  pfb_filter_whitelist_atype() processes it.
	 * Then:  the result preserves the IP and the spaced description.
	 */
	public function testSpacedDescriptionSurvivesHelperButFailsOldGate(): void
	{
		$composite = 'Whitelist|89.248.168.42|chickens are here';

		// Before state: the old gate rejects the whole composite because of the space.
		$oldResult = pfb_filter($composite, PFB_FILTER_ATYPE, 'PfbFilterWhitelistAtypeTest');
		$this->assertSame('', $oldResult, 'old PFB_FILTER_ATYPE gate must return empty for a spaced description');

		// After state: the helper validates each field separately, preserving the space.
		$newResult = pfb_filter_whitelist_atype($composite);
		$this->assertSame('Whitelist|89.248.168.42|chickens are here', $newResult,
			'helper must preserve a spaced description');

		// Cross-check: the two results are different — proves the fix caused the change.
		$this->assertNotSame($oldResult, $newResult, 'helper result must differ from old gate result');
	}

	/**
	 * A description with no spaces passes through unchanged.
	 * Proves single-word descriptions still work after the fix.
	 */
	public function testNoSpaceDescriptionPassesThroughUnchanged(): void
	{
		$composite = 'Whitelist|89.248.168.42|chickens';

		$result = pfb_filter_whitelist_atype($composite);

		$this->assertSame('Whitelist|89.248.168.42|chickens', $result);
	}

	/**
	 * HTML-special characters in the description are kept as RAW text (NOT
	 * HTML-encoded at ingestion). Storage is base64 (the custom list), and each
	 * display sink escapes on output — so the stored/edited description shows the
	 * value the user typed ('a & b'), not 'a &amp; b'.
	 */
	public function testHtmlSpecialCharsInDescriptionArePreservedRaw(): void
	{
		$result = pfb_filter_whitelist_atype('Whitelist|89.248.168.42|a & b');

		$this->assertSame('Whitelist|89.248.168.42|a & b', $result,
			'the ampersand must be preserved raw, not HTML-encoded at ingestion');
		$this->assertStringNotContainsString('&amp;', $result, 'no HTML entity may be introduced');
	}

	/**
	 * Angle brackets and quotes in the description are likewise preserved raw; the
	 * output sinks (json_encode for JS, Form_Input/Form_Textarea for HTML) escape
	 * them, so ingestion keeps the user's literal text.
	 */
	public function testAngleBracketsAndQuotesInDescriptionArePreservedRaw(): void
	{
		$result = pfb_filter_whitelist_atype('Whitelist|89.248.168.42|<b>"x"</b>');

		$this->assertSame('Whitelist|89.248.168.42|<b>"x"</b>', $result,
			'tags and quotes must be preserved raw (escaping is an output concern)');
	}

	/**
	 * A description with control characters or newlines is collapsed to a single
	 * space, so it cannot inject extra lines into the (newline-delimited, base64
	 * stored) custom list. Pins the anti-injection contract.
	 */
	public function testControlCharsAndNewlinesAreNormalisedToSingleLine(): void
	{
		$result = pfb_filter_whitelist_atype("Whitelist|89.248.168.42|foo\nbar\tbaz");

		$this->assertSame('Whitelist|89.248.168.42|foo bar baz', $result,
			'newlines/tabs must collapse to a single space (no extra custom-list lines)');
		$this->assertStringNotContainsString("\n", $result, 'no newline may survive');
		$this->assertStringNotContainsString("\t", $result, 'no tab may survive');
	}

	/**
	 * The category-edit page emits $atype into its JS-string site with
	 * json_encode(..., JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT).
	 * This pins that contract: even a raw description containing quotes, a
	 * backslash, '<', '>' and '&' yields a JS string literal that round-trips and
	 * cannot break out of the surrounding <script> block.
	 */
	public function testRawDescriptionIsJsSafeViaJsonEncodeHexFlags(): void
	{
		$atype = pfb_filter_whitelist_atype('Whitelist|89.248.168.42|x"\\</script><b>&y');

		$jsLiteral = json_encode($atype, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

		$this->assertIsString($jsLiteral);
		$this->assertSame($atype, json_decode($jsLiteral), 'json_encode must round-trip the value');
		// Inside the literal (between the delimiting quotes) none of these may appear
		// raw — the HEX flags escape them, so the string cannot break out of <script>.
		$inner = substr($jsLiteral, 1, -1);
		foreach (['<', '>', '&', '"', "'"] as $dangerous) {
			$this->assertStringNotContainsString($dangerous, $inner,
				"'{$dangerous}' must be hex-escaped, never literal, in the JS literal");
		}
	}

	/**
	 * A composite whose first token is not exactly 'Whitelist' is rejected (returns
	 * '') — the helper never normalises a foreign prefix into a whitelist payload.
	 */
	public function testNonWhitelistPrefixReturnsEmpty(): void
	{
		$this->assertSame('', pfb_filter_whitelist_atype('Feed|89.248.168.42|x'),
			'a non-Whitelist first token must be rejected');
		$this->assertSame('', pfb_filter_whitelist_atype('WhitelistFoo|89.248.168.42|x'),
			'a token merely starting with Whitelist must be rejected');
	}

	/**
	 * An invalid IP produces an empty IP slot; the description is still passed.
	 * The empty slot causes the downstream invalid-IP branch to show
	 * "Cannot create new IP Whitelist! Invalid data!" — correct UX preserved.
	 */
	public function testInvalidIpEmptiesIpSlotButPreservesDescription(): void
	{
		$composite = 'Whitelist|not_an_ip|some description';

		$result = pfb_filter_whitelist_atype($composite);

		$this->assertSame('Whitelist||some description', $result,
			'invalid IP must produce empty IP slot, not the raw invalid value');
	}

	/**
	 * When the description field is absent the third slot defaults to empty string.
	 * Proves the helper does not crash on a two-part composite.
	 */
	public function testMissingDescriptionDefaultsToEmpty(): void
	{
		$composite = 'Whitelist|192.0.2.1';

		$result = pfb_filter_whitelist_atype($composite);

		$this->assertSame('Whitelist|192.0.2.1|', $result,
			'missing description must produce an empty third slot, not an error');
	}

	/**
	 * A description containing a pipe character ('|') is preserved intact because
	 * explode() is called with a limit of 3, so only the first two pipes split.
	 */
	public function testPipeInDescriptionIsPreserved(): void
	{
		$composite = 'Whitelist|10.0.0.1|foo|bar';

		$result = pfb_filter_whitelist_atype($composite);

		$this->assertSame('Whitelist|10.0.0.1|foo|bar', $result,
			'a pipe inside the description must be preserved (limit-3 split)');
	}

	/**
	 * An IPv6 address is accepted — PFB_FILTER_IP covers both address families.
	 */
	public function testValidIPv6AddressPassesIpFilter(): void
	{
		$composite = 'Whitelist|2001:db8::1|test description';

		$result = pfb_filter_whitelist_atype($composite);

		$this->assertSame('Whitelist|2001:db8::1|test description', $result,
			'a valid IPv6 address must pass the IP filter');
	}
}
