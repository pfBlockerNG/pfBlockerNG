<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_feed_manifest_row() — ADR-31 P3 extracted helper. Builds a single per-feed
 * manifest row for $pfb_py_feeds[]; reusable by both the deny (DNSBL) and permit
 * (DNSWL, Phase 4) download loops.
 *
 * Pins the deny contract (mode='deny' default):
 *   - the 'mode' key is OMITTED for deny rows — byte-identical with pre-ADR-31
 *     entries (Phase 2: absent == deny in Python).
 *   - all four fields (header, group, log, provenance) are faithfully forwarded.
 *     ('format' retired #1083 P4 -- every live caller tagged 'plain' unconditionally,
 *     making the parameter dead; see the ADR-62 amendment.)
 *
 * Also pins the permit contract (mode='permit'):
 *   - 'mode' => 'permit' appears in the row.
 *   - all four base fields remain unchanged.
 */
#[CoversFunction('pfb_feed_manifest_row')]
final class FeedManifestRowTest extends TestCase
{
	// --- Deny path (default) — byte-identical with pre-ADR-31 entries ---------------

	public function testDenyRowOmitsModeKey(): void
	{
		// GIVEN a plain feed row with the default mode (deny)
		$row = pfb_feed_manifest_row('MyFeed', 'DNSBL_MyGroup', '1', 'feed');

		// THEN 'mode' must be absent — pre-ADR-31 consumers expect no such key
		$this->assertArrayNotHasKey('mode', $row,
			'deny rows must omit the mode key to stay byte-identical with existing manifests');
	}

	public function testExplicitDenyRowOmitsModeKey(): void
	{
		// GIVEN the same row with mode='deny' passed explicitly
		$row = pfb_feed_manifest_row('MyFeed', 'DNSBL_MyGroup', '1', 'feed', 'deny');

		// THEN 'mode' is still absent — explicit 'deny' == absent
		$this->assertArrayNotHasKey('mode', $row,
			'explicit mode=deny must also omit the mode key');
	}

	public function testDenyRowFieldsAreForwardedExactly(): void
	{
		// GIVEN representative deny row inputs (feed-sourced)
		$row = pfb_feed_manifest_row('EasyList', 'DNSBL_Ads', '1', 'feed');

		// THEN all four manifest fields carry the exact input values
		$this->assertSame('EasyList',     $row['header']);
		$this->assertSame('DNSBL_Ads',   $row['group']);
		$this->assertSame('1',            $row['log']);
		$this->assertSame('feed',         $row['provenance']);
	}

	public function testDenyRowNoFormatKeyEmitted(): void
	{
		// GIVEN any deny row (#1083 P4: the 'format' key is retired end-to-end)
		$row = pfb_feed_manifest_row('EasyListABP', 'DNSBL_Ads', '0', 'feed');

		// THEN the row carries no 'format' key at all
		$this->assertArrayNotHasKey('format', $row);
	}

	public function testDenyRowUserProvenanceIsForwarded(): void
	{
		// GIVEN a custom-list row (provenance='user', the sovereign block band)
		$row = pfb_feed_manifest_row('MyAlias_custom', 'DNSBL_MyGroup', '1', 'user');

		// THEN provenance='user' is preserved and mode is absent
		$this->assertSame('user', $row['provenance']);
		$this->assertArrayNotHasKey('mode', $row);
	}

	public function testDenyRowNullBlockingLogFlagIsForwarded(): void
	{
		// GIVEN a null-blocking deny row (log_flag='2')
		$row = pfb_feed_manifest_row('SomeList', 'DNSBL_Null', '2', 'feed');

		// THEN log flag is preserved verbatim
		$this->assertSame('2', $row['log']);
	}

	// --- Permit path (mode='permit') — Phase 4 DNSWL contract ----------------------

	public function testPermitRowIncludesModePermit(): void
	{
		// GIVEN a permit-mode row (DNSWL feed, Phase 4)
		// BEFORE state: a deny row for the same header omits 'mode'
		$deny = pfb_feed_manifest_row('SafeList', 'DNSWL_Safe', '1', 'feed', 'deny');
		$this->assertArrayNotHasKey('mode', $deny, 'before: deny row has no mode key');

		// WHEN mode='permit' is passed
		$row = pfb_feed_manifest_row('SafeList', 'DNSWL_Safe', '1', 'feed', 'permit');

		// THEN 'mode' => 'permit' appears in the row
		$this->assertArrayHasKey('mode', $row, 'permit row must carry the mode key');
		$this->assertSame('permit', $row['mode'],
			'mode value must be exactly the lowercase string permit (Phase 2 contract)');
	}

	public function testPermitRowBaseFieldsAreUnchanged(): void
	{
		// GIVEN a permit row
		$row = pfb_feed_manifest_row('DNSWL_Org', 'DNSWL_Allow', '1', 'feed', 'permit');

		// THEN all four base fields are forwarded exactly, in addition to mode
		$this->assertSame('DNSWL_Org',    $row['header']);
		$this->assertSame('DNSWL_Allow',  $row['group']);
		$this->assertSame('1',             $row['log']);
		$this->assertSame('feed',          $row['provenance']);
		$this->assertSame('permit',        $row['mode']);
	}
}
