<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-31 P4 — per-row 'action' field → manifest mode routing.
 *
 * Pins the call-site logic added in Phase 4: each pfblockerngdnsbl/config
 * row's 'action' key (dynamic per-row, read directly — foreign-key exclusion,
 * like 'custom') selects the manifest mode passed to pfb_feed_manifest_row():
 *
 *   'Permit' → 'permit'  (mode='permit' key present in row — P2 allow path)
 *   'Deny'   → 'deny'    (mode key omitted — byte-identical with pre-ADR-31)
 *   absent   → 'deny'    (same — default/missing key treated as Deny)
 *
 * Stored vocabulary: 'Permit' | 'Deny' (mirrors the IP-side Deny/Permit/Match
 * action convention; stored in pfblockerngdnsbl/config/{group}/row/{idx}/action).
 */
final class DnsblRowActionModeTest extends TestCase
{
	// Derive the manifest mode from a row's 'action' field exactly as the
	// DNSBL download loop does (ADR-31 P4 call-site pattern).
	private function deriveMode(array $row): string
	{
		return (($row['action'] ?? '') === 'Permit') ? 'permit' : 'deny';
	}

	// --- Permit branch -----------------------------------------------------------

	public function testPermitActionRowYieldsModePermitInManifestEntry(): void
	{
		// GIVEN a row with action='Permit' (the new Permit value)
		$row = ['url' => 'https://safelist.example.com/list.txt',
		        'header' => 'SafeList', 'state' => 'Enabled', 'action' => 'Permit'];

		// BEFORE: a Deny row for the same header carries no mode key
		$deny = pfb_feed_manifest_row('SafeList', 'DNSBL_Safe', '1', 'plain', 'feed', 'deny');
		$this->assertArrayNotHasKey('mode', $deny,
			'before: a Deny-action row must produce no mode key (byte-identical)');

		// WHEN the mode is derived from the Permit action and the manifest row is built
		$mode = $this->deriveMode($row);
		$entry = pfb_feed_manifest_row('SafeList', 'DNSBL_Safe', '1', 'plain', 'feed', $mode);

		// THEN the manifest entry carries mode='permit'
		$this->assertSame('permit', $mode,
			'Permit action must derive mode=permit');
		$this->assertArrayHasKey('mode', $entry,
			'manifest entry for Permit-action row must carry the mode key');
		$this->assertSame('permit', $entry['mode'],
			'mode value must be exactly the lowercase string permit (Phase 2 contract)');
	}

	public function testPermitActionRowBaseFieldsAreUnchanged(): void
	{
		// GIVEN a Permit-action row
		$row = ['url' => 'https://safelist.example.com/list.txt',
		        'header' => 'DNSWL_Test', 'state' => 'Enabled', 'action' => 'Permit'];

		// WHEN the manifest entry is built with the derived mode
		$mode  = $this->deriveMode($row);
		$entry = pfb_feed_manifest_row('DNSWL_Test', 'DNSBL_Allow', '1', 'plain', 'feed', $mode);

		// THEN all five base fields and mode are present and correct
		$this->assertSame('DNSWL_Test',   $entry['header']);
		$this->assertSame('DNSBL_Allow',  $entry['group']);
		$this->assertSame('1',             $entry['log']);
		$this->assertSame('plain',         $entry['format']);
		$this->assertSame('feed',          $entry['provenance']);
		$this->assertSame('permit',        $entry['mode']);
	}

	// --- Deny branch (both stored 'Deny' and absent/missing key) -----------------

	public function testDenyActionRowYieldsNoModeKeyByteIdentical(): void
	{
		// GIVEN a row with action='Deny' (the default stored value)
		$row = ['url' => 'https://blocklist.example.com/list.txt',
		        'header' => 'BlockList', 'state' => 'Enabled', 'action' => 'Deny'];

		// WHEN the mode is derived and the manifest entry is built
		$mode  = $this->deriveMode($row);
		$entry = pfb_feed_manifest_row('BlockList', 'DNSBL_Block', '1', 'plain', 'feed', $mode);

		// THEN mode='deny' and the mode key is OMITTED (byte-identical with pre-ADR-31)
		$this->assertSame('deny', $mode,
			'Deny action must derive mode=deny');
		$this->assertArrayNotHasKey('mode', $entry,
			'deny-action manifest entry must omit the mode key (byte-identical with existing)');
	}

	public function testAbsentActionFieldDefaultsToDenyByteIdentical(): void
	{
		// GIVEN a row with no 'action' key (existing rows before Phase 4 / Phase 5 UI)
		$row = ['url' => 'https://blocklist.example.com/list.txt',
		        'header' => 'LegacyFeed', 'state' => 'Enabled'];

		// WHEN the mode is derived from an absent action key
		$mode  = $this->deriveMode($row);
		$entry = pfb_feed_manifest_row('LegacyFeed', 'DNSBL_Legacy', '1', 'plain', 'feed', $mode);

		// THEN absent 'action' defaults to deny — mode key absent, byte-identical
		$this->assertSame('deny', $mode,
			'absent action key must default to deny — no regression on existing rows');
		$this->assertArrayNotHasKey('mode', $entry,
			'absent-action manifest entry must omit the mode key');
	}
}
