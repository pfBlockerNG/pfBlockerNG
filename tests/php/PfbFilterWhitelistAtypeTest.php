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
	 * HTML-special characters in the description are escaped exactly once.
	 *
	 * Given: a description containing '&'.
	 * When:  the helper processes the composite.
	 * Then:  '&' is encoded as '&amp;' (single escape, NOT '&amp;amp;').
	 *
	 * Proves that the downstream addgroup block must NOT re-filter the description
	 * (which would double-escape '&amp;' → '&amp;amp;').
	 */
	public function testHtmlSpecialCharsInDescriptionAreEscapedOnce(): void
	{
		$composite = 'Whitelist|89.248.168.42|a & b';

		$result = pfb_filter_whitelist_atype($composite);

		$this->assertStringContainsString('a &amp; b', $result,
			'ampersand must be HTML-escaped exactly once');
		$this->assertStringNotContainsString('&amp;amp;', $result,
			'must not double-escape: &amp;amp; is a double-escape of &');
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
	public function testIPv6AddressIsAccepted(): void
	{
		$composite = 'Whitelist|2001:db8::1|test description';

		$result = pfb_filter_whitelist_atype($composite);

		$this->assertSame('Whitelist|2001:db8::1|test description', $result,
			'a valid IPv6 address must pass the IP filter');
	}
}
